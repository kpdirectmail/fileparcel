package mdns

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	pmdns "github.com/pion/mdns/v2"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"

	"fileparcel/internal/core"
)

// Builtin responder tunables.
const (
	mdnsPort        = 5353
	probeTimeout    = 1500 * time.Millisecond
	probeInterval   = 250 * time.Millisecond
	builtinResponse = 120 // record TTL (s), RFC 6762 recommendation
)

// builtinBackend runs a pion/mdns/v2 responder in-process (DESIGN §10.5,
// "auto" fallback when neither Avahi nor macOS dns-sd is available). It
// listens on UDP 5353 with SO_REUSEADDR|SO_REUSEPORT (so it can share the
// port), probes the host name and the service instance first and reports a
// host collision when another host answers for the name, or an instance
// collision when another responder (typically a second FileParcel on this
// machine) answers for the same instance.
type builtinBackend struct {
	log   *slog.Logger
	emit  func(backendEvent)
	probe bool

	mu   sync.Mutex
	conn *pmdns.Conn
}

func newBuiltinBackend(log *slog.Logger, emit func(backendEvent)) *builtinBackend {
	return &builtinBackend{log: log, emit: emit, probe: true}
}

func (b *builtinBackend) kind() string { return BackendBuiltin }

// listenMulticast opens the IPv4 and IPv6 mDNS sockets (either may fail;
// at least one is required).
func listenMulticast(ctx context.Context) (*ipv4.PacketConn, *ipv6.PacketConn, error) {
	lc := net.ListenConfig{Control: reusePort}
	var (
		p4   *ipv4.PacketConn
		p6   *ipv6.PacketConn
		errs []error
	)
	if c, err := lc.ListenPacket(ctx, "udp4", fmt.Sprintf("0.0.0.0:%d", mdnsPort)); err == nil {
		p4 = ipv4.NewPacketConn(c)
	} else {
		errs = append(errs, err)
	}
	if c, err := lc.ListenPacket(ctx, "udp6", fmt.Sprintf("[::]:%d", mdnsPort)); err == nil {
		p6 = ipv6.NewPacketConn(c)
	} else {
		errs = append(errs, err)
	}
	if p4 == nil && p6 == nil {
		return nil, nil, fmt.Errorf("listening on UDP %d: %w", mdnsPort, errors.Join(errs...))
	}
	return p4, p6, nil
}

func closePC(p4 *ipv4.PacketConn, p6 *ipv6.PacketConn) {
	if p4 != nil {
		_ = p4.Close()
	}
	if p6 != nil {
		_ = p6.Close()
	}
}

// netInterfaces resolves the publication's interfaces to net.Interface values.
func netInterfaces(p publication) []net.Interface {
	var out []net.Interface
	for _, ia := range p.Ifaces {
		ifc, err := net.InterfaceByName(ia.Name)
		if err != nil {
			continue
		}
		out = append(out, *ifc)
	}
	return out
}

func (b *builtinBackend) publish(ctx context.Context, gen uint64, p publication) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.closeLocked()
	ifaces := netInterfaces(p)
	if len(ifaces) == 0 {
		return errors.New("none of the selected interfaces exists")
	}
	logf := slogOption(pmdns.WithLoggerFactory, b.log)
	if b.probe {
		hostTaken, instTaken, err := b.probeNames(ctx, p, ifaces, logf)
		if err != nil {
			b.log.Debug("mdns: probe failed", "err", err)
		}
		switch {
		case hostTaken: // checked first: a real host conflict wins
			return errCollision
		case instTaken:
			return errInstanceCollision
		}
	}
	p4, p6, err := listenMulticast(ctx)
	if err != nil {
		return err
	}
	var txt []pmdns.TXTEntry
	for _, t := range p.TXT {
		k, v, _ := strings.Cut(t, "=")
		txt = append(txt, pmdns.NewTXTString(k, v))
	}
	opts := []pmdns.ServerOption{
		pmdns.WithName("fileparcel"),
		logf,
		pmdns.WithLocalNames(p.FQDN()),
		pmdns.WithInterfaces(ifaces...),
		pmdns.WithIncludeLoopback(p.Loopback),
		pmdns.WithResponseTTL(builtinResponse),
		pmdns.WithService(pmdns.ServiceInstance{
			Instance: p.Instance, Service: ServiceType, Domain: "local", Host: p.FQDN() + ".",
			Port: uint16(p.Port), Text: txt,
		}),
	}
	// With exactly one address, pin it (the automatic choice could pick an
	// address that is not being published).
	if addrs := p.allAddrs(); len(addrs) == 1 {
		opts = append(opts, pmdns.WithLocalAddress(net.IP(addrs[0].AsSlice())))
	}
	conn, err := pmdns.NewServer(p4, p6, opts...)
	if err != nil {
		closePC(p4, p6)
		return fmt.Errorf("starting the mDNS responder: %w", err)
	}
	b.conn = conn
	// The responder answers immediately; there is no asynchronous
	// registration phase to wait for.
	go b.emit(backendEvent{gen: gen, state: core.MDNSPublished})
	return nil
}

// probeNames asks the network whether another responder already answers for
// p.FQDN() or for p's service instance (RFC 6762 §8.1, simplified), both
// within one probeTimeout.
//
// The host name is taken when an answer carries an address that is not one
// of ours. The instance is taken when "<instance>._https._tcp.local" resolves
// to another port or target host — a second FileParcel on this machine
// publishes the same "FileParcel on <computer name>" with our addresses, so
// the host probe cannot see it. The same port and target is our own stale
// record: no other process holds our port here, and another host using our
// target name is caught by the host probe.
func (b *builtinBackend) probeNames(ctx context.Context, p publication, ifaces []net.Interface, logf pmdns.ServerOption) (hostTaken, instTaken bool, err error) {
	p4, p6, err := listenMulticast(ctx)
	if err != nil {
		return false, false, err
	}
	q, err := pmdns.NewServer(p4, p6, pmdns.WithName("fileparcel-probe"), logf,
		pmdns.WithInterfaces(ifaces...), pmdns.WithIncludeLoopback(p.Loopback), pmdns.WithCacheRefresh(false),
		pmdns.WithQueryInterval(probeInterval))
	if err != nil {
		closePC(p4, p6)
		return false, false, err
	}
	defer q.Close()
	pctx, cancel := context.WithTimeout(ctx, probeTimeout)
	defer cancel()
	var inst atomic.Bool
	q.OnServiceDiscovered(func(ev pmdns.ServiceEvent) {
		si := ev.Instance
		if !strings.EqualFold(si.Instance, p.Instance) {
			return
		}
		if int(si.Port) != p.Port || !strings.EqualFold(strings.TrimSuffix(si.Host, "."), p.FQDN()) {
			inst.Store(true)
		}
	})
	if err := q.Browse(pctx, ServiceType); err != nil {
		b.log.Debug("mdns: service instance probe failed", "err", err)
	}
	ours := p.allAddrs()
	for {
		_, addr, err := q.QueryAddr(pctx, p.FQDN())
		if err != nil {
			break // no answer: the name is free
		}
		addr = addr.Unmap().WithZone("")
		if !slices.Contains(ours, addr) && !addr.IsLoopback() && !addr.IsLinkLocalUnicast() {
			b.log.Info("mdns: name already answered by another host", "name", p.FQDN(), "addr", addr)
			return true, false, nil
		}
		// Our own (stale) record: keep listening until the probe ends.
		select {
		case <-pctx.Done():
		case <-time.After(probeInterval):
		}
		if pctx.Err() != nil {
			break
		}
	}
	if inst.Load() {
		b.log.Info("mdns: service instance already answered by another responder", "instance", p.Instance)
		return false, true, nil
	}
	return false, false, nil
}

func (b *builtinBackend) closeLocked() {
	if b.conn != nil {
		if err := b.conn.Close(); err != nil {
			b.log.Debug("mdns: closing responder", "err", err)
		}
		b.conn = nil
	}
}

func (b *builtinBackend) unpublish() {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.closeLocked()
}

func (b *builtinBackend) close() error {
	b.unpublish()
	return nil
}

// slogOption returns pion's logger-factory option wired to slog.
//
// pion's logger interfaces live in github.com/pion/logging, which go.mod
// lists as an indirect dependency; importing it here would promote it to a
// direct one (a go.mod change). Instead the factory is generic over the
// logger type L and the method-based type inference of Go 1.21+ binds
// F = logging.LoggerFactory and L = logging.LeveledLogger from the
// signature of pmdns.WithLoggerFactory, passed in as with.
func slogOption[F interface{ NewLogger(string) L }, L any, R any](with func(F) R, log *slog.Logger) R {
	f, ok := any(slogFactory[L]{log: log}).(F)
	if !ok {
		panic("mdns: slog adapter does not implement pion's LoggerFactory")
	}
	return with(f)
}

// slogFactory adapts pion's logger to slog. pion is chatty (per-interface
// send failures on down links), so everything below Error goes to Debug.
type slogFactory[L any] struct{ log *slog.Logger }

// NewLogger implements pion's logging.LoggerFactory (L = logging.LeveledLogger).
func (f slogFactory[L]) NewLogger(scope string) L {
	l, ok := any(&slogLogger{log: f.log.With("component", "pion-"+scope)}).(L)
	if !ok {
		panic("mdns: slog adapter does not implement pion's LeveledLogger")
	}
	return l
}

// slogLogger implements pion's logging.LeveledLogger.
type slogLogger struct{ log *slog.Logger }

func (l *slogLogger) Trace(msg string)                  {}
func (l *slogLogger) Tracef(format string, args ...any) {}
func (l *slogLogger) Debug(msg string)                  { l.log.Debug(msg) }
func (l *slogLogger) Debugf(format string, args ...any) { l.log.Debug(fmt.Sprintf(format, args...)) }
func (l *slogLogger) Info(msg string)                   { l.log.Debug(msg) }
func (l *slogLogger) Infof(format string, args ...any)  { l.log.Debug(fmt.Sprintf(format, args...)) }
func (l *slogLogger) Warn(msg string)                   { l.log.Debug(msg) }
func (l *slogLogger) Warnf(format string, args ...any)  { l.log.Debug(fmt.Sprintf(format, args...)) }
func (l *slogLogger) Error(msg string)                  { l.log.Warn(msg) }
func (l *slogLogger) Errorf(format string, args ...any) { l.log.Warn(fmt.Sprintf(format, args...)) }
