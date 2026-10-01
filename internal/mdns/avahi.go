package mdns

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/godbus/dbus/v5"

	"fileparcel/internal/core"
)

// Avahi D-Bus API (avahi-daemon/org.freedesktop.Avahi.*.xml, avahi-common/defs.h).
const (
	avahiName           = "org.freedesktop.Avahi"
	avahiServerIface    = "org.freedesktop.Avahi.Server"
	avahiGroupIface     = "org.freedesktop.Avahi.EntryGroup"
	avahiIfUnspec       = int32(-1)
	avahiProtoUnspec    = int32(-1)
	avahiPublishNoRev   = uint32(16) // AVAHI_PUBLISH_NO_REVERSE
	avahiServerRunning  = int32(2)   // AVAHI_SERVER_RUNNING
	avahiGroupRegister  = int32(1)   // AVAHI_ENTRY_GROUP_REGISTERING
	avahiGroupEstablish = int32(2)   // AVAHI_ENTRY_GROUP_ESTABLISHED
	avahiGroupCollision = int32(3)   // AVAHI_ENTRY_GROUP_COLLISION
	avahiGroupFailure   = int32(4)   // AVAHI_ENTRY_GROUP_FAILURE
	avahiCallTimeout    = 5 * time.Second
)

// avahiAvailable reports whether the system bus has an owner for
// org.freedesktop.Avahi (DESIGN §10.5: "auto" picks Avahi then).
func avahiAvailable(ctx context.Context) bool {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	conn, err := dbus.ConnectSystemBus(dbus.WithContext(ctx))
	if err != nil {
		return false
	}
	defer conn.Close()
	var owned bool
	err = conn.BusObject().CallWithContext(ctx, "org.freedesktop.DBus.NameHasOwner", 0, avahiName).Store(&owned)
	return err == nil && owned
}

// avahiBackend publishes through avahi-daemon's D-Bus API: an A/AAAA record
// per address (NO_REVERSE, so the daemon's own reverse records stay intact)
// in one EntryGroup and the _https._tcp service in a second one. The two
// record sets are kept apart on purpose: avahi withdraws a whole entry group
// on COLLISION, so sharing one would make an asynchronous conflict
// unattributable and a mere service-instance clash (another FileParcel on
// this machine publishes the same "FileParcel on <computer name>") would
// rename <name>.local. It never binds UDP 5353 (coexistence, DESIGN §18.3).
type avahiBackend struct {
	log  *slog.Logger
	emit func(backendEvent)
	// dial opens the system bus (tests may point it elsewhere).
	dial func(ctx context.Context) (*dbus.Conn, error)

	mu        sync.Mutex // serialises D-Bus operations
	conn      *dbus.Conn
	addrGroup dbus.ObjectPath // entry group of the address records ("" = none)
	svcGroup  dbus.ObjectPath // entry group of the DNS-SD service ("" = none)
	sigs      chan *dbus.Signal
	wg        sync.WaitGroup
	// cur is read lock-free by the signal watcher: the groups whose state
	// changes are forwarded, and their publication generation.
	cur atomic.Pointer[avahiGroupRef]
}

// avahiGroupRef identifies the entry groups of one publication.
type avahiGroupRef struct {
	gen  uint64
	addr dbus.ObjectPath // "" when avahi-daemon owns the host records
	svc  dbus.ObjectPath
	// addrOK/svcOK record which groups reached ESTABLISHED; the publication
	// counts as published once every committed group has.
	addrOK atomic.Bool
	svcOK  atomic.Bool
}

// owns reports whether path is one of the groups of this publication.
func (r *avahiGroupRef) owns(path dbus.ObjectPath) bool {
	return path != "" && (path == r.svc || path == r.addr)
}

// established marks path as established and reports whether the whole
// publication is now established.
func (r *avahiGroupRef) established(path dbus.ObjectPath) bool {
	if path == r.svc {
		r.svcOK.Store(true)
	} else if path == r.addr {
		r.addrOK.Store(true)
	}
	return r.svcOK.Load() && (r.addr == "" || r.addrOK.Load())
}

func newAvahiBackend(log *slog.Logger, emit func(backendEvent)) *avahiBackend {
	return &avahiBackend{log: log, emit: emit, dial: func(ctx context.Context) (*dbus.Conn, error) {
		return dbus.ConnectSystemBus(dbus.WithContext(context.WithoutCancel(ctx)))
	}}
}

func (b *avahiBackend) kind() string { return BackendAvahi }

// connectLocked (re)opens the D-Bus connection and subscribes to the
// EntryGroup state and Avahi owner changes. b.mu must be held.
func (b *avahiBackend) connectLocked(ctx context.Context) error {
	if b.conn != nil && b.conn.Connected() {
		return nil
	}
	b.dropConnLocked()
	conn, err := b.dial(ctx)
	if err != nil {
		return fmt.Errorf("connecting to the system D-Bus: %w", err)
	}
	var owned bool
	if err := conn.BusObject().CallWithContext(ctx, "org.freedesktop.DBus.NameHasOwner", 0, avahiName).Store(&owned); err != nil {
		conn.Close()
		return fmt.Errorf("D-Bus: %w", err)
	}
	if !owned {
		conn.Close()
		return errors.New("avahi-daemon is not running")
	}
	for _, opts := range [][]dbus.MatchOption{
		{dbus.WithMatchSender(avahiName), dbus.WithMatchInterface(avahiGroupIface), dbus.WithMatchMember("StateChanged")},
		{dbus.WithMatchSender("org.freedesktop.DBus"), dbus.WithMatchInterface("org.freedesktop.DBus"),
			dbus.WithMatchMember("NameOwnerChanged"), dbus.WithMatchArg(0, avahiName)},
	} {
		if err := conn.AddMatchSignalContext(ctx, opts...); err != nil {
			conn.Close()
			return fmt.Errorf("D-Bus match: %w", err)
		}
	}
	sigs := make(chan *dbus.Signal, 64)
	conn.Signal(sigs)
	b.conn, b.sigs = conn, sigs
	b.wg.Add(1)
	go b.watch(sigs)
	return nil
}

// dropConnLocked closes the connection (the entry groups die with it).
func (b *avahiBackend) dropConnLocked() {
	if b.conn != nil {
		_ = b.conn.Close() // closes b.sigs → watch returns
		b.conn = nil
	}
	b.addrGroup, b.svcGroup = "", ""
	b.cur.Store(nil)
}

// watch forwards EntryGroup state changes of the current groups and reports
// avahi-daemon restarts (which drop every entry group).
func (b *avahiBackend) watch(sigs chan *dbus.Signal) {
	defer b.wg.Done()
	for sig := range sigs {
		switch sig.Name {
		case avahiGroupIface + ".StateChanged":
			if len(sig.Body) < 1 {
				continue
			}
			state, _ := sig.Body[0].(int32)
			msg := ""
			if len(sig.Body) > 1 {
				msg, _ = sig.Body[1].(string)
			}
			ref := b.cur.Load()
			if ref == nil || !ref.owns(sig.Path) {
				continue
			}
			gen := ref.gen
			switch state {
			case avahiGroupRegister:
				b.emit(backendEvent{gen: gen, state: core.MDNSPublishing})
			case avahiGroupEstablish:
				// Published once every committed group is established.
				if ref.established(sig.Path) {
					b.emit(backendEvent{gen: gen, state: core.MDNSPublished})
				}
			case avahiGroupCollision:
				// The service entry lives in its own group, so a conflict
				// there is a service-instance clash and leaves the host
				// name (and with it the certificate) alone.
				st := core.MDNSCollision
				if sig.Path == ref.svc {
					st = stateInstanceCollision
				}
				b.emit(backendEvent{gen: gen, state: st})
			case avahiGroupFailure:
				if msg == "" {
					msg = "avahi reported a failure"
				}
				b.emit(backendEvent{gen: gen, state: core.MDNSError, err: errors.New("avahi: " + msg)})
			}
		case "org.freedesktop.DBus.NameOwnerChanged":
			if len(sig.Body) < 3 {
				continue
			}
			if name, _ := sig.Body[0].(string); name != avahiName {
				continue
			}
			// The daemon's objects (our entry group) are gone.
			if ref := b.cur.Swap(nil); ref != nil {
				b.emit(backendEvent{gen: ref.gen, state: core.MDNSError, err: errors.New("avahi-daemon restarted")})
			}
		}
	}
}

// dbusErrName returns the D-Bus error name of err ("" if none).
func dbusErrName(err error) string {
	var de dbus.Error
	if errors.As(err, &de) {
		return de.Name
	}
	var dp *dbus.Error
	if errors.As(err, &dp) && dp != nil {
		return dp.Name
	}
	return ""
}

func isAvahiCollision(err error) bool {
	n := dbusErrName(err)
	return strings.HasSuffix(n, ".CollisionError") || strings.HasSuffix(n, ".LocalCollisionError")
}

func (b *avahiBackend) publish(ctx context.Context, gen uint64, p publication) error {
	ctx, cancel := context.WithTimeout(ctx, avahiCallTimeout)
	defer cancel()
	b.mu.Lock()
	defer b.mu.Unlock()
	if err := b.connectLocked(ctx); err != nil {
		return err
	}
	err := b.publishLocked(ctx, gen, p, true)
	if errors.Is(err, errPerIface) {
		// Some interface refused the service entry: one entry on all
		// interfaces instead.
		err = b.publishLocked(ctx, gen, p, false)
	}
	return err
}

// errPerIface asks publish to retry with a single all-interface service entry.
var errPerIface = errors.New("per-interface service entry refused")

// publishLocked builds and commits fresh entry groups for p — one for the
// address records, one for the DNS-SD service. b.mu is held.
func (b *avahiBackend) publishLocked(ctx context.Context, gen uint64, p publication, perIface bool) error {
	server := b.conn.Object(avahiName, "/")
	var state int32
	if err := server.CallWithContext(ctx, avahiServerIface+".GetState", 0).Store(&state); err != nil {
		b.dropConnLocked()
		return fmt.Errorf("avahi: %w", err)
	}
	if state != avahiServerRunning {
		return fmt.Errorf("avahi-daemon is not ready (server state %d)", state)
	}
	var hostName string
	_ = server.CallWithContext(ctx, avahiServerIface+".GetHostName", 0).Store(&hostName)

	// Withdraw the previous publication first: fresh groups per publish
	// keep the state signals unambiguous.
	b.freeGroupsLocked(ctx)
	newGroup := func() (dbus.BusObject, error) {
		var path dbus.ObjectPath
		if err := server.CallWithContext(ctx, avahiServerIface+".EntryGroupNew", 0).Store(&path); err != nil {
			b.dropConnLocked()
			return nil, fmt.Errorf("avahi EntryGroupNew: %w", err)
		}
		return b.conn.Object(avahiName, path), nil
	}
	call := func(g dbus.BusObject, method string, args ...any) error {
		return g.CallWithContext(ctx, avahiGroupIface+"."+method, 0, args...).Err
	}
	// fail maps a failure of the ADDRESS records: a collision means
	// <name>.local itself is taken, so the host label has to change.
	fail := func(err error) error {
		b.freeGroupsLocked(ctx)
		if isAvahiCollision(err) {
			return errCollision
		}
		return err
	}
	// failInstance maps a failure of the SERVICE entry: a collision means
	// only the DNS-SD instance name is taken (another FileParcel on this
	// machine publishes the same "FileParcel on <computer name>"), which
	// says nothing about <name>.local.
	failInstance := func(err error) error {
		b.freeGroupsLocked(ctx)
		if isAvahiCollision(err) {
			return errInstanceCollision
		}
		return err
	}

	host := p.FQDN()
	// When the name equals the daemon's own host name, Avahi already
	// publishes the address records; only the service is added.
	ownHost := strings.EqualFold(p.Host, hostName)
	if ownHost {
		host = strings.ToLower(hostName) + ".local"
		_ = server.CallWithContext(ctx, avahiServerIface+".GetHostNameFqdn", 0).Store(&host)
		perIface = false
	} else {
		g, err := newGroup()
		if err != nil {
			return err
		}
		b.addrGroup = g.Path()
		var errs []error
		added := 0
		for _, ifc := range p.Ifaces {
			for _, a := range ifc.Addrs {
				idx := int32(ifc.Index)
				if idx <= 0 {
					idx = avahiIfUnspec
				}
				err := call(g, "AddAddress", idx, avahiProtoUnspec, avahiPublishNoRev, host, a.String())
				if err != nil && idx != avahiIfUnspec && strings.HasSuffix(dbusErrName(err), ".InvalidInterfaceError") {
					err = call(g, "AddAddress", avahiIfUnspec, avahiProtoUnspec, avahiPublishNoRev, host, a.String())
				}
				switch {
				case err == nil:
					added++
				case isAvahiCollision(err):
					return fail(err)
				default:
					b.log.Debug("mdns: avahi AddAddress", "addr", a.String(), "iface", ifc.Name, "err", err)
					errs = append(errs, fmt.Errorf("%s: %w", a, err))
				}
			}
		}
		if added == 0 {
			return fail(fmt.Errorf("avahi could not publish any address: %w", errors.Join(errs...)))
		}
	}

	svc, err := newGroup()
	if err != nil {
		b.freeGroupsLocked(ctx)
		return err
	}
	b.svcGroup = svc.Path()
	txt := make([][]byte, len(p.TXT))
	for i, t := range p.TXT {
		txt[i] = []byte(t)
	}
	addService := func(idx int32) error {
		return call(svc, "AddService", idx, avahiProtoUnspec, uint32(0), p.Instance, ServiceType, "", host, uint16(p.Port), txt)
	}
	// One service entry per interface keeps the SRV target and its
	// addresses on the same links.
	for _, ifc := range p.Ifaces {
		if ifc.Index <= 0 {
			perIface = false
		}
	}
	if perIface {
		for _, ifc := range p.Ifaces {
			if err := addService(int32(ifc.Index)); err != nil {
				if isAvahiCollision(err) {
					return failInstance(err)
				}
				b.log.Debug("mdns: avahi per-interface AddService", "iface", ifc.Name, "err", err)
				b.freeGroupsLocked(ctx)
				return errPerIface
			}
		}
	} else if err := addService(avahiIfUnspec); err != nil {
		return failInstance(fmt.Errorf("avahi AddService: %w", err))
	}
	// Publish the reference before committing: the daemon's state signals
	// may arrive as soon as Commit returns.
	b.cur.Store(&avahiGroupRef{gen: gen, addr: b.addrGroup, svc: b.svcGroup})
	if b.addrGroup != "" {
		if err := call(b.conn.Object(avahiName, b.addrGroup), "Commit"); err != nil {
			return fail(fmt.Errorf("avahi Commit: %w", err))
		}
	}
	if err := call(svc, "Commit"); err != nil {
		return failInstance(fmt.Errorf("avahi Commit: %w", err))
	}
	return nil
}

// freeGroupsLocked frees the current entry groups (withdrawing their
// records). The service goes first so it never outlives its SRV target.
func (b *avahiBackend) freeGroupsLocked(ctx context.Context) {
	b.cur.Store(nil)
	groups := [2]dbus.ObjectPath{b.svcGroup, b.addrGroup}
	b.svcGroup, b.addrGroup = "", ""
	if b.conn == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 2*time.Second)
	defer cancel()
	for _, path := range groups {
		if path == "" {
			continue
		}
		if err := b.conn.Object(avahiName, path).CallWithContext(ctx, avahiGroupIface+".Free", 0).Err; err != nil {
			b.log.Debug("mdns: avahi Free", "err", err)
		}
	}
}

func (b *avahiBackend) unpublish() {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.freeGroupsLocked(context.Background())
}

func (b *avahiBackend) close() error {
	b.mu.Lock()
	b.freeGroupsLocked(context.Background())
	b.dropConnLocked()
	b.mu.Unlock()
	b.wg.Wait()
	return nil
}
