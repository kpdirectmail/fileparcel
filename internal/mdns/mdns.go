// Package mdns publishes <name>.local and the _https._tcp DNS-SD service via
// Avahi (D-Bus), macOS dns-sd, or a builtin pion/mdns responder (DESIGN §10.5).
// Owned by unit G.
//
// A supervisor goroutine (Start) owns the backend. It computes the desired
// publication from the settings (mdns.mode, mdns.name/server.name,
// mdns.interfaces, mdns.zerotier) and the classified interfaces of
// core.Network, publishes it, renames the host on a host-name collision
// ("<name>-2.local", …) and only the service on a DNS-SD instance collision
// ("FileParcel on nas (2)", keeping <name>.local),
// retries failures with backoff and re-publishes on network.changed and on
// settings.changed for mdns.* / server.name. Every state change is
// published as mdns.changed with the core.MDNSStatus payload.
package mdns

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"os"
	"runtime"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"fileparcel/internal/core"
	"fileparcel/internal/events"
)

// Tunables.
const (
	debounceDelay = 500 * time.Millisecond // coalesces bursts of change events
	retryMin      = 2 * time.Second
	retryMax      = 2 * time.Minute
	maxAttempts   = 32 // collision renames before giving up
	// avahiRecheck is how often mode "auto" looks for Avahi again while it
	// runs the builtin responder.
	avahiRecheck = 30 * time.Second
)

// Service implements core.MDNS.
type Service struct {
	env     *core.Env
	net     core.Network
	log     *slog.Logger
	goos    string
	port    int
	cfgName string // server.name read at construction (fallback)

	// Injectable collaborators (tests).
	hostname   func() (string, error)
	detect     func(ctx context.Context) string // auto: avahi | dnssd | builtin
	newBackend func(kind string, emit func(backendEvent)) (backend, error)
	loopback   bool // publish on loopback interfaces too (tests)
	debounce   time.Duration
	retryMin   time.Duration
	retryMax   time.Duration
	recheck    time.Duration // avahiRecheck

	status atomic.Pointer[core.MDNSStatus]

	mu      sync.Mutex // guards cancel/done/reqs
	started bool
	cancel  context.CancelFunc
	done    chan struct{}
	reqs    chan chan error
	bevents chan backendEvent
}

var _ core.MDNS = (*Service)(nil)

// New creates the service (constructor signature fixed by DESIGN §5.2). It
// does no I/O; Start begins publishing.
func New(env *core.Env, net core.Network) (*Service, error) {
	s := &Service{
		env:      env,
		net:      net,
		log:      slog.Default(),
		goos:     runtime.GOOS,
		port:     8443,
		hostname: os.Hostname,
		debounce: debounceDelay,
		retryMin: retryMin,
		retryMax: retryMax,
		recheck:  avahiRecheck,
		bevents:  make(chan backendEvent, 64),
	}
	s.detect = s.detectBackend
	s.newBackend = s.systemBackend
	if env != nil {
		if env.Log != nil {
			s.log = env.Log
		}
		if env.Config != nil {
			if env.Config.Server.HTTPSPort > 0 {
				s.port = env.Config.Server.HTTPSPort
			}
			s.cfgName = env.Config.Server.Name
		}
	}
	return s, nil
}

// ---------- core.MDNS ----------

// Status returns the current publishing status (a copy).
func (s *Service) Status() core.MDNSStatus {
	if st := s.status.Load(); st != nil {
		c := *st
		c.Interfaces = slices.Clone(st.Interfaces)
		return c
	}
	mode := s.mode()
	name := s.baseName() + ".local"
	return core.MDNSStatus{Mode: mode, Backend: BackendNone, Name: name, Configured: name, State: core.MDNSOff,
		Interfaces: []string{}}
}

// Name returns the effective FQDN ("fileparcel.local", or "fileparcel-2.local"
// after a collision); before Start the configured name.
func (s *Service) Name() string {
	if st := s.status.Load(); st != nil && st.Name != "" {
		return st.Name
	}
	return s.baseName() + ".local"
}

// Republish forces a new publication (after resolving collisions afresh)
// and waits for the backend to accept it. 409 conflict when publishing is
// not running (offline mode, or before Start).
func (s *Service) Republish(ctx context.Context) error {
	s.mu.Lock()
	reqs, done := s.reqs, s.done
	s.mu.Unlock()
	if reqs == nil {
		return core.Errorf(core.ErrConflict, "mDNS publishing is not running")
	}
	reply := make(chan error, 1)
	select {
	case reqs <- reply:
	case <-done:
		return core.Errorf(core.ErrConflict, "mDNS publishing is not running")
	case <-ctx.Done():
		return ctx.Err()
	}
	select {
	case err := <-reply:
		return err
	case <-done:
		return core.Errorf(core.ErrConflict, "mDNS publishing stopped")
	case <-ctx.Done():
		return ctx.Err()
	}
}

// Start begins publishing in the background (errors surface in Status and
// mdns.changed, never here). Calling it again is a no-op.
func (s *Service) Start(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.started {
		return nil
	}
	s.started = true
	lctx, cancel := context.WithCancel(ctx)
	s.cancel, s.done, s.reqs = cancel, make(chan struct{}), make(chan chan error)
	var ch <-chan events.Event
	unsub := func() {}
	if s.env != nil && s.env.Bus != nil {
		ch, unsub = s.env.Bus.Subscribe(events.TopicNetworkChanged, events.TopicSettingsChanged)
	}
	go func() {
		defer close(s.done)
		defer unsub()
		s.run(lctx, ch)
	}()
	return nil
}

// Stop withdraws the publication and stops the supervisor. Safe to call
// without Start and more than once.
func (s *Service) Stop() error {
	s.mu.Lock()
	cancel, done := s.cancel, s.done
	s.mu.Unlock()
	if cancel == nil {
		return nil
	}
	cancel()
	<-done
	return nil
}

// ---------- supervisor ----------

// supervisor is the state owned by the run goroutine.
//
// The host label and the DNS-SD instance name have independent attempt
// counters: the instance ("FileParcel on <computer name>") is the same for
// every FileParcel process on one machine, so an instance clash says nothing
// about <name>.local — renaming the host for it would silently move the
// advertised URL, the leaf certificate SANs and the WebAuthn RP ID.
type supervisor struct {
	s           *Service
	ctx         context.Context
	b           backend
	bquit       chan struct{}
	gen         uint64
	base        string // base label of the current host attempt series
	attempt     int
	instBase    string // base instance name of the current instance series
	instAttempt int
	current     *publication // last publication handed to the backend
	backoff     time.Duration
	retry       *time.Timer
	debounce    *time.Timer
}

func (s *Service) run(ctx context.Context, ch <-chan events.Event) {
	sv := &supervisor{s: s, ctx: ctx, attempt: 1, instAttempt: 1}
	sv.retry = stoppedTimer()
	sv.debounce = stoppedTimer()
	defer sv.teardown()
	recheck := time.NewTicker(max(s.recheck, time.Millisecond))
	defer recheck.Stop()
	sv.apply(true)
	for {
		select {
		case <-ctx.Done():
			return
		case reply := <-s.reqs:
			sv.attempt, sv.instAttempt = 1, 1
			reply <- sv.apply(true)
		case <-recheck.C:
			// Mode "auto" fell back to the builtin responder because Avahi
			// was absent (restarting, or not started yet at boot). Nothing
			// else reports its return, so look again: apply detects the
			// backend afresh and moves the publication to Avahi once it owns
			// its bus name — never two responders on UDP 5353 (DESIGN §18.3).
			if sv.b != nil && sv.b.kind() == BackendBuiltin && s.mode() == ModeAuto {
				sv.apply(false)
			}
		case e, ok := <-ch:
			if !ok {
				ch = nil
				continue
			}
			if relevant(e) {
				sv.debounce.Reset(s.debounce)
			}
		case <-sv.debounce.C:
			sv.apply(false)
		case <-sv.retry.C:
			sv.apply(true)
		case ev := <-s.bevents:
			sv.handle(ev)
		}
	}
}

func stoppedTimer() *time.Timer {
	t := time.NewTimer(time.Hour)
	t.Stop()
	return t
}

// relevant reports whether an event may change the desired publication.
func relevant(e events.Event) bool {
	if e.Topic == events.TopicNetworkChanged {
		return true
	}
	var keys []string
	switch v := e.Data.(type) {
	case core.SettingsChangedEvent:
		keys = v.Keys
	case *core.SettingsChangedEvent:
		if v != nil {
			keys = v.Keys
		}
	}
	if len(keys) == 0 {
		return true
	}
	return slices.ContainsFunc(keys, func(k string) bool { return strings.HasPrefix(k, "mdns.") || k == "server.name" })
}

// apply converges the backend on the desired publication. With force it
// republishes even when nothing changed. It returns the publish error (for
// Republish).
func (sv *supervisor) apply(force bool) error {
	s := sv.s
	for {
		if sv.ctx.Err() != nil {
			return sv.ctx.Err()
		}
		d, err := s.desired(sv.ctx)
		mode := s.mode()
		if mode == ModeOff {
			sv.closeBackend()
			sv.current = nil
			s.setStatus(core.MDNSStatus{Mode: mode, Backend: BackendNone, Name: s.baseName() + ".local", State: core.MDNSOff})
			return nil
		}
		kind := mode
		if mode == ModeAuto {
			kind = s.detect(sv.ctx)
		}
		if err != nil {
			sv.fail(mode, kind, d.Host, err)
			return err
		}
		if d.Host != sv.base {
			sv.base, sv.attempt = d.Host, 1
		}
		if d.Instance != sv.instBase {
			sv.instBase, sv.instAttempt = d.Instance, 1
		}
		pub := d
		pub.Host = hostLabel(d.Host, sv.attempt)
		pub.Instance = instanceName(d.Instance, sv.instAttempt)
		if sv.b != nil && sv.b.kind() != kind {
			sv.closeBackend()
		}
		if !force && sv.b != nil && sv.current != nil && sv.current.equal(pub) {
			if st := s.status.Load(); st != nil && st.State != core.MDNSError {
				return nil // already published (or publishing) exactly this
			}
		}
		if len(pub.Ifaces) == 0 {
			if sv.b != nil {
				sv.b.unpublish()
			}
			sv.current = nil
			err := errors.New("no LAN or Wi-Fi interface with an address to publish on")
			sv.fail(mode, kind, pub.Host, err)
			sv.retry.Stop() // network.changed will bring us back
			return err
		}
		if sv.b == nil {
			sv.bquit = make(chan struct{})
			quit := sv.bquit
			emit := func(ev backendEvent) {
				select {
				case s.bevents <- ev:
				case <-quit:
				case <-sv.ctx.Done():
				}
			}
			b, err := s.newBackend(kind, emit)
			if err != nil {
				close(quit)
				sv.fail(mode, kind, pub.Host, err)
				return err
			}
			sv.b = b
		}
		sv.gen++
		sv.current = &pub
		s.setStatus(statusFor(mode, kind, pub, core.MDNSPublishing, ""))
		err = sv.b.publish(sv.ctx, sv.gen, pub)
		switch {
		case errors.Is(err, errInstanceCollision):
			if !sv.instanceCollided(mode, kind, pub) {
				return err
			}
			continue // try the next instance name right away
		case errors.Is(err, errCollision):
			if !sv.collided(mode, kind, pub) {
				return err
			}
			continue // try the next name right away
		case err != nil:
			sv.current = nil
			sv.fail(mode, kind, pub.Host, err)
			return err
		}
		return nil
	}
}

// collided records a collision and advances to the next name. It returns
// false when the attempts are exhausted.
func (sv *supervisor) collided(mode, kind string, pub publication) bool {
	s := sv.s
	s.setStatus(statusFor(mode, kind, pub, core.MDNSCollision, pub.FQDN()+" is already in use on the network"))
	s.log.Info("mdns: name collision, renaming", "name", pub.FQDN())
	sv.attempt++
	if sv.attempt > maxAttempts {
		sv.attempt = 1
		sv.fail(mode, kind, pub.Host, fmt.Errorf("no free name found after %d attempts", maxAttempts))
		return false
	}
	return true
}

// instanceCollided advances to the next DNS-SD instance name. The host label
// is left alone: another FileParcel on this machine publishes the same
// "FileParcel on <computer name>", which says nothing about <name>.local.
// It deliberately does not set core.MDNSCollision either — the published
// name does not change, and a collision state would make the certificate
// and the doctor check flap. It returns false when the attempts are
// exhausted.
func (sv *supervisor) instanceCollided(mode, kind string, pub publication) bool {
	s := sv.s
	s.log.Info("mdns: service instance name in use, renaming the service (keeping the host name)",
		"instance", pub.Instance, "name", pub.FQDN())
	sv.instAttempt++
	if sv.instAttempt > maxAttempts {
		sv.instAttempt = 1
		sv.fail(mode, kind, pub.Host, fmt.Errorf("no free service instance name found after %d attempts", maxAttempts))
		return false
	}
	return true
}

// fail reports an error state and schedules a retry with backoff.
func (sv *supervisor) fail(mode, kind, host string, err error) {
	s := sv.s
	st := core.MDNSStatus{Mode: mode, Backend: kind, Name: host + ".local", State: core.MDNSError, Error: err.Error()}
	if prev := s.status.Load(); prev == nil || prev.State != core.MDNSError || prev.Error != st.Error {
		s.log.Warn("mdns: publishing failed", "backend", kind, "err", err)
	}
	s.setStatus(st)
	if sv.backoff == 0 {
		sv.backoff = s.retryMin
	} else {
		sv.backoff = min(sv.backoff*2, s.retryMax)
	}
	sv.retry.Reset(sv.backoff)
}

// handle processes a backend state report.
func (sv *supervisor) handle(ev backendEvent) {
	if ev.gen != sv.gen || sv.current == nil {
		return // stale
	}
	s := sv.s
	mode, kind, pub := s.mode(), BackendNone, *sv.current
	if sv.b != nil {
		kind = sv.b.kind()
	}
	switch ev.state {
	case core.MDNSPublished:
		sv.backoff = 0
		sv.retry.Stop()
		s.setStatus(statusFor(mode, kind, pub, core.MDNSPublished, ""))
		s.log.Info("mdns: published", "name", pub.FQDN(), "backend", kind, "interfaces", pub.ifaceNames())
		if sv.base != "" && pub.Host != sv.base {
			s.log.Warn("mdns: published under a renamed host name; the configured name does not resolve",
				"configured", sv.base+".local", "published", pub.FQDN())
		}
	case core.MDNSPublishing:
		s.setStatus(statusFor(mode, kind, pub, core.MDNSPublishing, ""))
	case core.MDNSCollision:
		if sv.collided(mode, kind, pub) {
			sv.apply(true)
		}
	case stateInstanceCollision:
		if sv.instanceCollided(mode, kind, pub) {
			sv.apply(true)
		}
	default:
		err := ev.err
		if err == nil {
			err = errors.New("publishing failed")
		}
		sv.current = nil
		sv.fail(mode, kind, pub.Host, err)
	}
}

func (sv *supervisor) closeBackend() {
	if sv.b == nil {
		return
	}
	close(sv.bquit)
	if err := sv.b.close(); err != nil {
		sv.s.log.Debug("mdns: closing backend", "err", err)
	}
	sv.b, sv.bquit = nil, nil
}

func (sv *supervisor) teardown() {
	sv.retry.Stop()
	sv.debounce.Stop()
	sv.closeBackend()
	st := sv.s.Status()
	st.State, st.Error, st.Interfaces = core.MDNSOff, "", []string{}
	sv.s.setStatus(st)
}

func statusFor(mode, kind string, p publication, state, errMsg string) core.MDNSStatus {
	return core.MDNSStatus{Mode: mode, Backend: kind, Name: p.FQDN(), State: state, Error: errMsg, Interfaces: p.ifaceNames()}
}

// setStatus stores st and publishes mdns.changed when it differs.
func (s *Service) setStatus(st core.MDNSStatus) {
	if st.Interfaces == nil {
		st.Interfaces = []string{}
	}
	if st.Configured == "" {
		st.Configured = s.baseName() + ".local"
	}
	prev := s.status.Load()
	s.status.Store(&st)
	if prev != nil && prev.Mode == st.Mode && prev.Backend == st.Backend && prev.Name == st.Name &&
		prev.Configured == st.Configured &&
		prev.State == st.State && prev.Error == st.Error && slices.Equal(prev.Interfaces, st.Interfaces) {
		return
	}
	if s.env != nil && s.env.Bus != nil {
		c := st
		c.Interfaces = slices.Clone(st.Interfaces)
		s.env.Bus.Publish(events.Event{Topic: events.TopicMDNSChanged, Data: c})
	}
}

// ---------- desired state ----------

func (s *Service) setting(key string) string {
	if s.env == nil || s.env.Settings == nil {
		return ""
	}
	return s.env.Settings.String(key)
}

// mode returns mdns.mode ("auto" when unset or unknown).
func (s *Service) mode() string {
	switch m := s.setting(KeyMode); m {
	case ModeAuto, ModeOff, BackendAvahi, BackendDNSSD, BackendBuiltin:
		return m
	}
	return ModeAuto
}

// baseName returns the configured label: mdns.name, else server.name, else
// "fileparcel".
func (s *Service) baseName() string {
	for _, n := range []string{s.setting(KeyName), s.setting("server.name"), s.cfgName, "fileparcel"} {
		n = strings.ToLower(strings.TrimSpace(n))
		if validLabel(n) {
			return n
		}
	}
	return "fileparcel"
}

// instanceBase returns "FileParcel on <host>" (DESIGN §10.5).
func (s *Service) instanceBase() string {
	h, err := s.hostname()
	if err != nil {
		return "FileParcel"
	}
	h, _, _ = strings.Cut(strings.TrimSpace(h), ".")
	if h == "" {
		return "FileParcel"
	}
	return "FileParcel on " + h
}

// desired computes the publication for attempt 1 from the settings and the
// current interfaces.
func (s *Service) desired(ctx context.Context) (publication, error) {
	p := publication{Host: s.baseName(), Instance: s.instanceBase(), Port: s.port, TXT: []string{"path=/", "fp=1"},
		Loopback: s.loopback}
	if s.net == nil {
		return p, errors.New("network information unavailable")
	}
	ifs, err := s.net.Interfaces(ctx)
	if err != nil {
		return p, fmt.Errorf("listing interfaces: %w", err)
	}
	p.Ifaces = selectInterfaces(ifs, s.setting(KeyInterfaces), s.env != nil && s.env.Settings != nil && s.env.Settings.Bool(KeyZeroTier),
		s.loopback, indexOf)
	return p, nil
}

// selectInterfaces picks the interfaces and addresses to publish on. spec is
// a comma/space separated list of interface names, where the keyword "lan"
// (the default, also for an empty spec) stands for every up interface of
// role local — LAN and Wi-Fi, or one an administrator set to local with
// network.iface_roles (DESIGN §10.1, §10.5) — plus ZeroTier when zerotier:
// "lan" alone, "eth0, wlan0", or "lan, br0" to add an interface to the LAN
// set. Exit VPNs, unknown tunnels and containers are never in the LAN set;
// a container interface is used only when it was set to local. Loopback
// only when loopback is set. Per interface: IPv4 addresses (link-local only
// if nothing else) and global/ULA IPv6 addresses.
func selectInterfaces(ifs []core.NetInterface, spec string, zerotier, loopback bool, index func(string) int) []ifaceAddrs {
	names := strings.FieldsFunc(strings.ToLower(spec), func(r rune) bool { return r == ',' || r == ' ' || r == '\t' })
	lan := len(names) == 0 || slices.Contains(names, "lan")
	var out []ifaceAddrs
	for _, ni := range ifs {
		role := roleOf(ni)
		if !ni.Up || (ni.Kind == core.IfContainer && role != core.VPNRoleLocal) {
			continue
		}
		switch {
		case ni.Kind == core.IfLoopback:
			if !loopback {
				continue
			}
		case slices.Contains(names, strings.ToLower(ni.Name)):
		case lan && role == core.VPNRoleLocal:
		case lan && ni.Kind == core.IfZeroTier && zerotier:
		default:
			continue
		}
		addrs := publishAddrs(ni.Addrs, ni.Kind == core.IfLoopback)
		if len(addrs) == 0 {
			continue
		}
		out = append(out, ifaceAddrs{Name: ni.Name, Index: index(ni.Name), Addrs: addrs})
	}
	return out
}

// roleOf is the interface's role; a value without one (an older network
// service, a test fake) counts as local when it is LAN or Wi-Fi.
func roleOf(ni core.NetInterface) string {
	if ni.Role != "" {
		return ni.Role
	}
	if ni.Kind == core.IfLAN || ni.Kind == core.IfWiFi {
		return core.VPNRoleLocal
	}
	return ""
}

// publishAddrs selects the addresses of one interface (see selectInterfaces).
func publishAddrs(prefixes []netip.Prefix, loopback bool) []netip.Addr {
	var v4, v4ll, v6 []netip.Addr
	for _, p := range prefixes {
		a := p.Addr().Unmap().WithZone("")
		switch {
		case !a.IsValid() || a.IsUnspecified() || a.IsMulticast():
		case a.IsLoopback():
			if loopback && a.Is4() {
				v4 = append(v4, a)
			}
		case a.Is4() && a.IsLinkLocalUnicast():
			v4ll = append(v4ll, a)
		case a.Is4():
			v4 = append(v4, a)
		case a.IsGlobalUnicast() || a.IsPrivate():
			if !a.IsLinkLocalUnicast() {
				v6 = append(v6, a)
			}
		}
	}
	if len(v4) == 0 {
		v4 = v4ll
	}
	out := append(v4, v6...)
	slices.SortStableFunc(out, func(a, b netip.Addr) int {
		if a.Is4() != b.Is4() {
			if a.Is4() {
				return -1
			}
			return 1
		}
		return 0
	})
	return slices.Compact(out)
}
