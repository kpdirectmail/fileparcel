// Package tsingress publishes FileParcel through Tailscale Funnel (the
// internet) and Tailscale Serve (the tailnet) and implements core.Ingress
// (DESIGN §10.6). Owned by unit G.
//
// tailscaled terminates TLS for <node>.<tailnet>.ts.net and proxies HTTP/1.1
// to a dedicated ingress listener per kind, which package server opens
// through core.IngressListeners: the private Unix socket
// <HOME>/run/ts-{funnel,serve}.sock, or 127.0.0.1:<funnel.backend_port>
// (+1 for Serve) where tailscaled refuses Unix-socket targets. This package
// owns the desired state (the funnel.* settings and the marker file
// <HOME>/service/tailscale.json), the prerequisite checks, the reconcile of
// FileParcel's own serve-config entries (a surgical merge: everything else
// is written back unchanged, always with If-Match), the status, the
// lock-free policy snapshot the request path reads, and a self-probe over
// the tailnet.
//
// Reconcile runs on a change (SetFunnel, SetServe, Reapply), when the
// server attaches its listeners (Attach), on settings.changed for funnel.*
// and the server ports, and on network.changed when the node's name or ID
// changed. It never runs on a timer: an entry an admin removed with
// `tailscale serve reset` is reported as drift, not fought. Enabling
// applies first and stores the settings only on success. While the server
// is stopped (the offline CLI) only removals reach tailscaled: an enable is
// recorded in the marker as pending and written when the server starts, so
// tailscaled never points at a backend nobody listens on, and a home
// without a marker (a restored backup, a copied home) publishes nothing by
// itself.
package tsingress

import (
	"context"
	"crypto/x509"
	"errors"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"os/user"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"fileparcel/internal/core"
	"fileparcel/internal/events"
	"fileparcel/internal/home"
	"fileparcel/internal/tslocal"
)

// kinds are the two ingress kinds, in the order of the per-kind arrays.
var kinds = [2]string{core.IngressFunnel, core.IngressServe}

// kindIndex returns the array index of kind (-1 for an unknown kind).
func kindIndex(kind string) int {
	switch kind {
	case core.IngressFunnel:
		return 0
	case core.IngressServe:
		return 1
	}
	return -1
}

// timing holds the tunables (tests shorten them).
type timing struct {
	statusTTL    time.Duration // cached tailscaled read of Status
	reconcileTTL time.Duration // cached status/prefs read of a reconcile
	probeDelay   time.Duration // self-probe after an apply
	probeTimeout time.Duration // one self-probe (a first certificate issuance is slow)
	probeRetry   time.Duration // re-probe while the last one failed
	probeWait    time.Duration // how long Status(refresh) waits for a probe
	nonceTTL     time.Duration // lifetime of a probe nonce
	debounce     time.Duration // coalesces bursts of change events
	retryMin     time.Duration // start retries while tailscaled is not up yet
	retryMax     time.Duration
	detach       time.Duration // removal of TCP-backend entries on shutdown
	eventGap     time.Duration // ingress.changed for "last public request" at most this often
	fixTTL       time.Duration // query-feature answer cache
}

var defaultTiming = timing{
	statusTTL:    30 * time.Second,
	reconcileTTL: 5 * time.Second,
	probeDelay:   5 * time.Second,
	probeTimeout: 60 * time.Second,
	probeRetry:   10 * time.Minute,
	probeWait:    15 * time.Second,
	nonceTTL:     2 * time.Minute,
	debounce:     500 * time.Millisecond,
	retryMin:     5 * time.Second,
	retryMax:     5 * time.Minute,
	detach:       5 * time.Second,
	eventGap:     time.Minute,
	fixTTL:       10 * time.Minute,
}

// Service implements core.Ingress.
type Service struct {
	env  *core.Env
	net  core.Network // nil in some tests
	log  *slog.Logger
	ts   *tslocal.Client
	goos string
	t    timing

	// Injectable collaborators (tests).
	inContainer  func() bool
	listening    func(port int) (addrs []netip.AddrPort, known bool) // LISTEN sockets on a port (port.shadow)
	portFree     func(port int) bool                                 // 127.0.0.1:port can be bound (TCP backend)
	localAddr    func(ip netip.Addr) bool                            // a local interface carries ip (self-probe)
	mayConfigure func(p *tslocal.Prefs) bool                         // tailscaled's PermitWrite for this process
	serviceUser  func() string
	probeDial    func(ctx context.Context, network, addr string) (net.Conn, error)
	probeRoots   *x509.CertPool // nil = the system roots

	// probeMu serializes the self-probes of one kind (one nonce in flight).
	probeMu [2]sync.Mutex

	// mu serializes every change (reconcile, Set*, Reapply, RemoveAll,
	// Attach, Detach). It is held during tailscaled I/O, whose context
	// Detach cancels (opCtx), and Detach waits for it only within its own
	// context.
	mu opLock

	// stMu guards the fields below. It is never held during I/O.
	stMu          sync.Mutex
	lis           core.IngressListeners  // nil while not attached (server stopped, offline CLI)
	attachCtx     context.Context        // cancelled by Detach
	attachStop    context.CancelFunc     //
	open          map[string]backendSpec // kind → open ingress listener
	prev          map[string]backendSpec // kind → the previous TCP listener, bound while tailscaled may still route to it
	kst           [2]kindState
	view          *tsView
	unixRefused   bool // tailscaled refused the Unix backend: auto uses TCP from now on
	configLocked  bool // tailscaled runs from a config file
	foreignLogged bool // the marker of the home this one was copied from was reported
	fix           *fixURL
	probeTimers   [2]*time.Timer
	retryTimer    *time.Timer
	retryDelay    time.Duration
	lastName      string // HostPort name and node ID of the last reconcile (network.changed filter)
	lastNode      string
	started       bool
	stop          context.CancelFunc
	done          chan struct{}
	kick          chan string

	// Lock-free state of the request path.
	policy      [2]atomic.Pointer[core.IngressPolicy]
	base        atomic.Pointer[string]
	urls        atomic.Pointer[[]core.AccessURL]
	lastReq     [2]atomic.Int64 // unix nanoseconds
	lastPublic  [2]atomic.Int64
	serveFunnel atomic.Bool // a Funnel request reached the serve listener since the last reconcile
	nonce       [2]atomic.Pointer[probeNonce]
}

var _ core.Ingress = (*Service)(nil)

// kindState is what the last reconcile and self-probe found for one kind.
type kindState struct {
	state    string // core.IngressState*; "" before the first reconcile of this process
	message  string
	hostPort string
	port     int
	proxy    string // target of FileParcel's entry
	backend  string // unix|tcp
	tcpWarn  bool   // auto fell back to the TCP backend
	// backendErr: the error of state is the backend's (listener, socket
	// path, TCP port).
	backendErr bool
	appliedAt  *time.Time
	reachable  *core.IngressCheck // last self-probe
	probedAt   *time.Time
}

// New creates the service (constructor signature fixed by DESIGN §5.2). It
// does no I/O: Start subscribes to the bus, Attach (the running server)
// runs the first reconcile. network may be nil.
func New(env *core.Env, network core.Network) (*Service, error) {
	if env == nil {
		env = &core.Env{}
	}
	s := &Service{
		env:         env,
		net:         network,
		log:         slog.Default(),
		ts:          tslocal.Default(),
		goos:        runtime.GOOS,
		t:           defaultTiming,
		inContainer: inContainer,
		listening:   listeningOn,
		portFree:    portFree,
		localAddr:   hasLocalAddr,
		serviceUser: currentUserName,
		kick:        make(chan string, 8),
		open:        map[string]backendSpec{},
		prev:        map[string]backendSpec{},
		attachCtx:   context.Background(),
		attachStop:  func() {},
	}
	s.mayConfigure = func(p *tslocal.Prefs) bool { return s.ts.MayConfigure(p) }
	s.probeDial = (&net.Dialer{}).DialContext
	if env.Log != nil {
		s.log = env.Log
	}
	for i := range kinds {
		s.policy[i].Store(&core.IngressPolicy{Mode: core.FunnelOff})
	}
	empty := ""
	s.base.Store(&empty)
	s.urls.Store(&[]core.AccessURL{})
	return s, nil
}

func (s *Service) now() time.Time { return s.env.Now() }

func (s *Service) home() *home.Home { return s.env.Home }

// sockPath returns the Unix socket of kind's ingress listener.
func (s *Service) sockPath(kind string) string {
	if s.env.Home == nil {
		return ""
	}
	return filepath.Join(s.env.Home.RunDir(), "ts-"+kind+".sock")
}

// adminSocket returns the admin socket path ("" without a home).
func (s *Service) adminSocket() string {
	if s.env.Home == nil {
		return ""
	}
	return s.env.Home.Socket()
}

// ---------- lifecycle ----------

// Start subscribes to settings.changed and network.changed (DESIGN §5.2:
// after certs, ModeNetwork only). It loads nothing into tailscaled and opens
// no listener; the first reconcile runs from Attach. Calling it again is a
// no-op.
func (s *Service) Start(ctx context.Context) error {
	s.stMu.Lock()
	defer s.stMu.Unlock()
	if s.started {
		return nil
	}
	s.started = true
	lctx, cancel := context.WithCancel(ctx)
	s.stop, s.done = cancel, make(chan struct{})
	var ch <-chan events.Event
	unsub := func() {}
	if s.env.Bus != nil {
		ch, unsub = s.env.Bus.Subscribe(events.TopicSettingsChanged, events.TopicNetworkChanged)
	}
	go func() {
		defer close(s.done)
		defer unsub()
		s.run(lctx, ch)
	}()
	return nil
}

// Close stops the event loop and the timers (io.Closer for wire's cleanup;
// idempotent).
func (s *Service) Close() error {
	s.stMu.Lock()
	stop, done := s.stop, s.done
	s.stop = nil
	s.stopTimersLocked()
	s.stMu.Unlock()
	if stop != nil {
		stop()
		<-done
	}
	return nil
}

// Attach hands the running server's listener manager to the service and
// starts the first reconcile in the background (DESIGN §10.6 start rules):
// a pending or suspended marker is applied; entries the marker lists as
// applied are only verified (missing ones are drift, never re-added); with
// no marker nothing is published.
func (s *Service) Attach(l core.IngressListeners) {
	go s.startReconcile(s.attach(l), "start")
}

// attach records the listener manager and returns the context of this
// attachment (cancelled by Detach).
func (s *Service) attach(l core.IngressListeners) context.Context {
	ctx, cancel := context.WithCancel(context.Background())
	s.stMu.Lock()
	s.attachStop()
	s.lis, s.attachCtx, s.attachStop = l, ctx, cancel
	s.open, s.prev = map[string]backendSpec{}, map[string]backendSpec{}
	s.retryDelay = 0
	s.stMu.Unlock()
	return ctx
}

// startReconcile runs the reconcile of Attach (and its retries while
// tailscaled is not up yet).
func (s *Service) startReconcile(ctx context.Context, reason string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if ctx.Err() != nil || !s.attached() {
		return
	}
	s.reconcileLocked(ctx, s.loadDesired(), recOpts{reason: reason})
}

// Detach is called on server shutdown, before the servers drain: with the
// TCP backend FileParcel's entries are removed (best effort) and the marker
// becomes "suspended", so no other local program can take the port while
// FileParcel is stopped; the next start writes them again. The Unix backend
// keeps its entries (tailscaled answers 502 while the socket is gone, and
// nobody can take a socket inside the 0700 run directory).
//
// Detach returns within ctx: it first cancels the change that may be
// running (the tailscaled I/O of every reconcile runs under opCtx), waits
// for it only as long as ctx allows, and the removal gets what is left of
// ctx, at most the detach timeout.
func (s *Service) Detach(ctx context.Context) {
	s.stMu.Lock()
	s.attachStop()
	s.stopTimersLocked()
	s.stMu.Unlock()
	if err := s.mu.LockContext(ctx); err != nil {
		s.stMu.Lock()
		s.lis, s.open, s.prev = nil, map[string]backendSpec{}, map[string]backendSpec{}
		s.stMu.Unlock()
		s.clearSnapshots()
		s.log.Warn("tsingress: shutdown did not wait for a Tailscale change that is still running; "+
			"FileParcel's entries stay in tailscaled", "err", err)
		return
	}
	defer s.mu.Unlock()
	s.stMu.Lock()
	s.stopTimersLocked() // a change that ran meanwhile may have scheduled one
	attached := s.lis != nil
	var bound []backendSpec // the 127.0.0.1 listeners (a write cancelled above may still have landed)
	for _, set := range []map[string]backendSpec{s.open, s.prev} {
		for _, spec := range set {
			if spec.backend == BackendTCP {
				bound = append(bound, spec)
			}
		}
	}
	s.lis, s.open, s.prev = nil, map[string]backendSpec{}, map[string]backendSpec{}
	s.stMu.Unlock()
	if !attached {
		return
	}
	defer s.clearSnapshots()
	m, err := s.loadMarker()
	if err != nil {
		m = nil
	}
	// FileParcel's entries that point at a 127.0.0.1 port: the marker's and
	// those of the listeners that were open.
	own := ownership{kinds: map[string]string{}}
	suspend := false
	for k, p := range s.ownership(m).kinds {
		if backendOf(k) == BackendTCP {
			own.kinds[k], suspend = p, m.State == markerApplied
		}
	}
	for _, spec := range bound {
		if _, ok := own.kinds[spec.proxy]; !ok {
			own.kinds[spec.proxy] = core.IngressFunnel // the kind is not needed for a removal
		}
	}
	if len(own.kinds) == 0 {
		return
	}
	ctx, cancel := context.WithTimeout(ctx, s.t.detach)
	defer cancel()
	sys := core.WithPrincipal(ctx, core.SystemPrincipal(core.ViaOffline))
	if err := s.removeMarked(sys, own); err != nil {
		s.log.Warn("tsingress: could not remove the TCP-backend entries from tailscaled on shutdown", "err", err)
		for _, e := range m.entries() {
			if backendOf(e.Proxy) == BackendTCP {
				s.audit(sys, e.Kind, core.OutcomeFailure, map[string]any{"reason": "suspend_failed", "port": e.Port,
					"backend": BackendTCP, "error": err.Error()})
			}
		}
		return
	}
	if suspend {
		m.State = markerSuspended
		if err := writeMarker(s.home(), m); err != nil {
			s.log.Warn("tsingress: could not update the marker", "err", err)
		}
	}
}

// opCtx returns ctx, cancelled as well when the server detaches: Detach must
// not wait for the tailscaled I/O of a person's or an automatic reconcile.
// The offline CLI is never attached (its attach context never ends).
func (s *Service) opCtx(ctx context.Context) (context.Context, context.CancelFunc) {
	s.stMu.Lock()
	actx := s.attachCtx
	s.stMu.Unlock()
	ctx, cancel := context.WithCancel(ctx)
	stop := context.AfterFunc(actx, cancel)
	return ctx, func() { stop(); cancel() }
}

// opLock is a mutex whose Lock can give up when a context ends (a one-slot
// semaphore; the zero value is unlocked).
type opLock struct {
	once sync.Once
	ch   chan struct{}
}

func (l *opLock) init() { l.once.Do(func() { l.ch = make(chan struct{}, 1) }) }

// Lock acquires the lock.
func (l *opLock) Lock() { l.init(); l.ch <- struct{}{} }

// Unlock releases the lock.
func (l *opLock) Unlock() { <-l.ch }

// LockContext acquires the lock unless ctx ends first.
func (l *opLock) LockContext(ctx context.Context) error {
	l.init()
	select {
	case l.ch <- struct{}{}:
		return nil
	default:
	}
	select {
	case l.ch <- struct{}{}:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// attached reports whether the running server's listeners are attached.
func (s *Service) attached() bool {
	s.stMu.Lock()
	defer s.stMu.Unlock()
	return s.lis != nil
}

func (s *Service) stopTimersLocked() {
	for i, t := range s.probeTimers {
		if t != nil {
			t.Stop()
			s.probeTimers[i] = nil
		}
	}
	if s.retryTimer != nil {
		s.retryTimer.Stop()
		s.retryTimer = nil
	}
}

// ---------- event loop ----------

// run reconciles after relevant settings and network changes (debounced).
func (s *Service) run(ctx context.Context, ch <-chan events.Event) {
	var (
		reasons []string
		timer   *time.Timer
		fire    <-chan time.Time
	)
	add := func(r string) {
		if r == "" {
			return
		}
		if !slices.Contains(reasons, r) {
			reasons = append(reasons, r)
		}
		if timer == nil {
			timer = time.NewTimer(s.t.debounce)
			fire = timer.C
		}
	}
	for {
		select {
		case <-ctx.Done():
			if timer != nil {
				timer.Stop()
			}
			return
		case ev, ok := <-ch:
			if !ok {
				ch = nil
				continue
			}
			add(relevant(ev))
		case r := <-s.kick:
			add(r)
		case <-fire:
			timer, fire = nil, nil
			rs := reasons
			reasons = nil
			s.autoReconcile(ctx, rs)
		}
	}
}

// relevant maps a bus event to a reconcile reason ("" = none).
func relevant(ev events.Event) string {
	switch ev.Topic {
	case events.TopicNetworkChanged:
		return "network"
	case events.TopicSettingsChanged:
		sc, _ := ev.Data.(core.SettingsChangedEvent)
		for _, k := range sc.Keys {
			if strings.HasPrefix(k, "funnel.") || k == keyHTTPSPort || k == keyHTTPPort {
				return "settings"
			}
		}
	}
	return ""
}

// kickReconcile asks the event loop for an automatic reconcile (never
// blocks; a full queue already holds one).
func (s *Service) kickReconcile(reason string) {
	select {
	case s.kick <- reason:
	default:
	}
}

// autoReconcile runs an automatic reconcile while attached. A bare
// network.changed only matters when the node's MagicDNS name or ID changed.
func (s *Service) autoReconcile(ctx context.Context, reasons []string) {
	s.stMu.Lock()
	actx := s.attachCtx
	s.stMu.Unlock()
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.attached() || actx.Err() != nil {
		return
	}
	ctx, done := s.opCtx(ctx)
	defer done()
	if slices.Equal(reasons, []string{"network"}) {
		v := s.readView(ctx, s.t.reconcileTTL)
		s.stMu.Lock()
		same := v.st != nil && v.st.HostPortName() == s.lastName && v.st.NodeID() == s.lastNode
		s.stMu.Unlock()
		if same || v.err != nil {
			return
		}
	}
	s.reconcileLocked(ctx, s.loadDesired(), recOpts{reason: strings.Join(reasons, ",")})
}

// ---------- lock-free request path ----------

// Policy returns what kind's ingress listener enforces. Mode is "off" while
// the listener should not serve (fail closed).
func (s *Service) Policy(kind string) core.IngressPolicy {
	if i := kindIndex(kind); i >= 0 {
		if p := s.policy[i].Load(); p != nil {
			return *p
		}
	}
	return core.IngressPolicy{Mode: core.FunnelOff}
}

// Note records a request on kind's listener: the time of the last request,
// of the last public (Funnel-marked) one, and a Funnel request that reached
// the serve listener (conflict: Funnel was turned on for the tailnet-only
// port; the next reconcile removes that flag).
func (s *Service) Note(kind string, public, conflict bool) {
	i := kindIndex(kind)
	if i < 0 {
		return
	}
	now := s.now().UnixNano()
	s.lastReq[i].Store(now)
	if public {
		prev := s.lastPublic[i].Swap(now)
		if now-prev >= int64(s.t.eventGap) {
			s.publish()
		}
	}
	if conflict && kind == core.IngressServe && !s.serveFunnel.Swap(true) {
		s.publish()
		s.kickReconcile("funnel_flag")
	}
}

// PublicBaseURL returns https://<name>[:port] while Funnel (shares or app)
// is active, else "". Share links use it when server.public_url is unset.
func (s *Service) PublicBaseURL() string {
	if p := s.base.Load(); p != nil {
		return *p
	}
	return ""
}

// InternetLinks reports whether share links are reachable from the internet.
func (s *Service) InternetLinks() bool { return s.PublicBaseURL() != "" }

// AccessURLs returns the addresses Funnel (app mode) and Serve add to the
// access URLs of the network page.
func (s *Service) AccessURLs() []core.AccessURL {
	if p := s.urls.Load(); p != nil {
		return slices.Clone(*p)
	}
	return []core.AccessURL{}
}

// publish announces a status change (ingress.changed, no payload).
func (s *Service) publish() {
	if s.env.Bus != nil {
		s.env.Bus.Publish(events.Event{Topic: events.TopicIngressChanged})
	}
}

// ---------- small helpers ----------

// peerUIDs are the users allowed to connect to an ingress listener: root,
// the owner of tailscaled's socket (the daemon's user) and this process's
// user.
func (s *Service) peerUIDs() []int {
	var out []int
	for _, u := range []int{0, s.ts.SocketOwnerUID(), os.Getuid()} {
		if u >= 0 && !slices.Contains(out, u) {
			out = append(out, u)
		}
	}
	return out
}

// hostURL returns https://name[:port] (no trailing slash).
func hostURL(name string, port int) string {
	if port == 443 {
		return "https://" + name
	}
	return "https://" + name + ":" + strconv.Itoa(port)
}

func inContainer() bool {
	for _, p := range []string{"/.dockerenv", "/run/.containerenv"} {
		if _, err := os.Stat(p); err == nil {
			return true
		}
	}
	return false
}

func portFree(port int) bool {
	ln, err := net.Listen("tcp4", "127.0.0.1:"+strconv.Itoa(port))
	if err != nil {
		return false
	}
	_ = ln.Close()
	return true
}

func hasLocalAddr(ip netip.Addr) bool {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return false
	}
	for _, a := range addrs {
		if p, err := netip.ParsePrefix(a.String()); err == nil && p.Addr().Unmap() == ip.Unmap() {
			return true
		}
	}
	return false
}

func currentUserName() string {
	if u, err := user.Current(); err == nil && u.Username != "" {
		return u.Username
	}
	return strconv.Itoa(os.Getuid())
}

// errNotRunning describes a reachable tailscaled that is not connected.
func errNotRunning(st *tslocal.Status) error {
	state := "not connected"
	if st != nil && st.BackendState != "" {
		state = st.BackendState
	}
	return errors.New("Tailscale is " + state)
}
