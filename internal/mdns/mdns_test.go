package mdns

import (
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"fileparcel/internal/config"
	"fileparcel/internal/core"
	"fileparcel/internal/events"
	"fileparcel/internal/settings"
)

func init() {
	// A test-only key (never a catalog key) for "unrelated setting changed".
	settings.Register(settings.Def{Key: "mdnstest.unrelated", Type: settings.TypeBool, Default: false})
}

// ---------- fakes ----------

// fakeNet implements core.Network with a mutable interface list.
type fakeNet struct {
	core.Network
	mu  sync.Mutex
	ifs []core.NetInterface
	err error
}

func (f *fakeNet) Interfaces(context.Context) ([]core.NetInterface, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.ifs), f.err
}

func (f *fakeNet) set(ifs []core.NetInterface) {
	f.mu.Lock()
	f.ifs = ifs
	f.mu.Unlock()
}

func ni(name, kind string, up bool, addrs ...string) core.NetInterface {
	var ps []netip.Prefix
	for _, a := range addrs {
		ps = append(ps, netip.MustParsePrefix(a))
	}
	return core.NetInterface{Name: name, Kind: kind, Up: up, Addrs: ps}
}

func lanIfs() []core.NetInterface {
	return []core.NetInterface{
		ni("lo", core.IfLoopback, true, "127.0.0.1/8", "::1/128"),
		ni("eth2", core.IfLAN, true, "192.168.1.10/24", "2001:db8::6/64", "fe80::1/64"),
		ni("tailscale0", core.IfTailscale, true, "100.64.0.10/32"),
		ni("docker0", core.IfContainer, true, "172.17.0.1/16"),
	}
}

// fakeBackend records publications; behaviour is scripted per host label.
type fakeBackend struct {
	k    string
	emit func(backendEvent)

	mu        sync.Mutex
	pubs      []publication
	collide   map[string]bool // host label -> synchronous collision
	asyncColl map[string]bool // host label -> asynchronous collision event
	instColl  map[string]bool // instance name -> synchronous instance collision
	asyncInst map[string]bool // instance name -> asynchronous instance collision
	fail      error           // publish error
	closed    int
	unpubs    int
}

func (b *fakeBackend) kind() string { return b.k }

func (b *fakeBackend) publish(_ context.Context, gen uint64, p publication) error {
	b.mu.Lock()
	b.pubs = append(b.pubs, p)
	coll, async, fail := b.collide[p.Host], b.asyncColl[p.Host], b.fail
	inst, asyncInst := b.instColl[p.Instance], b.asyncInst[p.Instance]
	b.mu.Unlock()
	switch {
	case fail != nil:
		return fail
	case inst:
		return errInstanceCollision
	case coll:
		return errCollision
	case asyncInst:
		go b.emit(backendEvent{gen: gen, state: stateInstanceCollision})
	case async:
		go b.emit(backendEvent{gen: gen, state: core.MDNSCollision})
	default:
		go b.emit(backendEvent{gen: gen, state: core.MDNSPublished})
	}
	return nil
}

func (b *fakeBackend) unpublish() {
	b.mu.Lock()
	b.unpubs++
	b.mu.Unlock()
}

func (b *fakeBackend) close() error {
	b.mu.Lock()
	b.closed++
	b.mu.Unlock()
	return nil
}

func (b *fakeBackend) published() []publication {
	b.mu.Lock()
	defer b.mu.Unlock()
	return slices.Clone(b.pubs)
}

type harness struct {
	t   *testing.T
	env *core.Env
	net *fakeNet
	svc *Service
	ch  <-chan events.Event

	mu       sync.Mutex
	backends []*fakeBackend
	script   func(b *fakeBackend)
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	env := &core.Env{Bus: events.New(), Clock: core.SystemClock{}}
	cfg := config.Default(config.NewInstallID())
	cfg.Server.HTTPSPort = 9443
	env.Config = cfg
	st, err := settings.New(env)
	if err != nil {
		t.Fatal(err)
	}
	env.Settings = st
	h := &harness{t: t, env: env, net: &fakeNet{ifs: lanIfs()}}
	svc, err := New(env, h.net)
	if err != nil {
		t.Fatal(err)
	}
	svc.hostname = func() (string, error) { return "nas.example.lan", nil }
	svc.detect = func(context.Context) string { return BackendBuiltin }
	svc.debounce = 20 * time.Millisecond
	svc.retryMin, svc.retryMax = 30*time.Millisecond, 60*time.Millisecond
	svc.newBackend = func(kind string, emit func(backendEvent)) (backend, error) {
		b := &fakeBackend{k: kind, emit: emit, collide: map[string]bool{}, asyncColl: map[string]bool{},
			instColl: map[string]bool{}, asyncInst: map[string]bool{}}
		h.mu.Lock()
		if h.script != nil {
			h.script(b)
		}
		h.backends = append(h.backends, b)
		h.mu.Unlock()
		return b, nil
	}
	h.svc = svc
	ch, cancel := env.Bus.Subscribe(events.TopicMDNSChanged)
	h.ch = ch
	t.Cleanup(func() {
		_ = svc.Stop()
		cancel()
		_ = st.Close()
		env.Bus.Close()
	})
	return h
}

func (h *harness) backend(i int) *fakeBackend {
	h.mu.Lock()
	defer h.mu.Unlock()
	if i >= len(h.backends) {
		return nil
	}
	return h.backends[i]
}

func (h *harness) set(key, raw string) {
	h.t.Helper()
	if _, err := h.env.Settings.Set(context.Background(), nil, map[string]json.RawMessage{key: json.RawMessage(raw)}); err != nil {
		h.t.Fatal(err)
	}
}

// waitState waits for an mdns.changed event with the given state (and name when set).
func (h *harness) waitState(state, name string) core.MDNSStatus {
	h.t.Helper()
	timeout := time.After(3 * time.Second)
	for {
		select {
		case e := <-h.ch:
			st := e.Data.(core.MDNSStatus)
			if st.State == state && (name == "" || st.Name == name) {
				return st
			}
		case <-timeout:
			h.t.Fatalf("no mdns.changed with state %s name %q (status %+v)", state, name, h.svc.Status())
		}
	}
}

func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatal("condition not reached")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// ---------- tests ----------

func TestNamesAndLabels(t *testing.T) {
	if hostLabel("fileparcel", 1) != "fileparcel" || hostLabel("fileparcel", 2) != "fileparcel-2" {
		t.Fatal("hostLabel")
	}
	long := strings.Repeat("a", 62) + "-b"
	if l := hostLabel(long, 12); len(l) > 63 || !strings.HasSuffix(l, "-12") || !validLabel(l) {
		t.Fatalf("long label %q", l)
	}
	if instanceName("FileParcel on nas", 1) != "FileParcel on nas" || instanceName("FileParcel on nas", 3) != "FileParcel on nas (3)" {
		t.Fatal("instanceName")
	}
	in := instanceName("FileParcel on "+strings.Repeat("é", 40), 2)
	if len(in) > 63 || !strings.HasSuffix(in, " (2)") || !strings.HasPrefix(in, "FileParcel on ") {
		t.Fatalf("instance %q (%d)", in, len(in))
	}
	for s, want := range map[string]bool{"fileparcel": true, "a": true, "a-b": true, "-a": false, "a-": false, "A": false,
		"a.b": false, "": false, strings.Repeat("x", 64): false} {
		if validLabel(s) != want {
			t.Errorf("validLabel(%q)", s)
		}
	}
}

func TestSelectInterfaces(t *testing.T) {
	idx := func(name string) int { return len(name) }
	ifs := []core.NetInterface{
		ni("lo", core.IfLoopback, true, "127.0.0.1/8"),
		ni("eth0", core.IfLAN, false, "10.0.0.1/8"),
		ni("eth2", core.IfLAN, true, "2001:db8::6/64", "fe80::1/64", "192.168.1.10/24", "fd00::6/64"),
		ni("wlan0", core.IfWiFi, true, "169.254.7.7/16"),
		ni("wlan1", core.IfWiFi, true, "169.254.7.8/16", "10.1.1.1/24"),
		ni("zt0", core.IfZeroTier, true, "172.22.0.5/16"),
		ni("tailscale0", core.IfTailscale, true, "100.64.0.10/32"),
		ni("docker0", core.IfContainer, true, "172.17.0.1/16"),
		ni("eth3", core.IfLAN, true, "fe80::3/64"),
	}
	got := selectInterfaces(ifs, "lan", false, false, idx)
	names := func(l []ifaceAddrs) []string {
		var out []string
		for _, i := range l {
			out = append(out, i.Name)
		}
		return out
	}
	if !slices.Equal(names(got), []string{"eth2", "wlan0", "wlan1"}) {
		t.Fatalf("lan: %v", names(got))
	}
	if a := got[0].Addrs; len(a) != 3 || a[0].String() != "192.168.1.10" || a[1].String() != "2001:db8::6" || a[2].String() != "fd00::6" || got[0].Index != 4 {
		t.Fatalf("eth2 addrs %v", got[0])
	}
	if a := got[1].Addrs; len(a) != 1 || a[0].String() != "169.254.7.7" {
		t.Fatalf("link-local only when nothing else: %v", a)
	}
	if a := got[2].Addrs; len(a) != 1 || a[0].String() != "10.1.1.1" {
		t.Fatalf("link-local dropped when a routable address exists: %v", a)
	}
	if got := names(selectInterfaces(ifs, "", true, false, idx)); !slices.Contains(got, "zt0") {
		t.Fatalf("zerotier: %v", got)
	}
	if got := names(selectInterfaces(ifs, "Tailscale0, docker0,eth0 eth2", false, false, idx)); !slices.Equal(got, []string{"eth2", "tailscale0"}) {
		t.Fatalf("named: %v", got)
	}
	if got := names(selectInterfaces(ifs, "lan", false, true, idx)); got[0] != "lo" {
		t.Fatalf("loopback: %v", got)
	}
	// "lan" inside a list adds the LAN/Wi-Fi set to the named interfaces
	// rather than being taken for an interface name.
	if got := names(selectInterfaces(ifs, "lan, tailscale0", false, false, idx)); !slices.Equal(got, []string{"eth2", "wlan0", "wlan1", "tailscale0"}) {
		t.Fatalf("lan + named: %v", got)
	}
	if got := names(selectInterfaces(ifs, "LAN,", false, false, idx)); !slices.Equal(got, []string{"eth2", "wlan0", "wlan1"}) {
		t.Fatalf("lan with a trailing comma: %v", got)
	}
	if got := names(selectInterfaces(ifs, "lan zt0", false, false, idx)); !slices.Equal(got, []string{"eth2", "wlan0", "wlan1", "zt0"}) {
		t.Fatalf("named zerotier: %v", got)
	}
}

// The LAN set is the interfaces of role local (DESIGN §10.1): NordVPN's
// nordlynx (formerly classified lan) and unknown TUN devices are no longer
// announced on; network.iface_roles can add or remove an interface.
func TestSelectInterfacesByRole(t *testing.T) {
	idx := func(name string) int { return len(name) }
	withRole := func(n core.NetInterface, role, source string) core.NetInterface {
		n.Role, n.RoleSource = role, source
		return n
	}
	ifs := []core.NetInterface{
		withRole(ni("eth2", core.IfLAN, true, "192.168.1.10/24"), core.VPNRoleLocal, core.VPNRoleSourceAuto),
		withRole(ni("eth3", core.IfLAN, true, "10.0.3.1/24"), core.VPNRoleEgress, core.VPNRoleSourceOverride),
		withRole(ni("wlan0", core.IfWiFi, true, "10.1.1.1/24"), core.VPNRoleLocal, core.VPNRoleSourceAuto),
		withRole(ni("nordlynx", core.IfExitVPN, true, "10.5.0.2/32", "100.90.1.2/32"), core.VPNRoleMesh, core.VPNRoleSourceAuto),
		withRole(ni("edge0", core.IfVPN, true, "172.30.0.2/16"), core.VPNRoleUnknown, core.VPNRoleSourceAuto),
		withRole(ni("wg0", core.IfWireGuard, true, "10.8.0.2/24"), core.VPNRoleLocal, core.VPNRoleSourceOverride),
		withRole(ni("br-lan", core.IfContainer, true, "192.168.9.1/24"), core.VPNRoleLocal, core.VPNRoleSourceOverride),
		withRole(ni("docker0", core.IfContainer, true, "172.17.0.1/16"), core.VPNRoleNone, core.VPNRoleSourceAuto),
		withRole(ni("zt0", core.IfZeroTier, true, "172.22.0.5/16"), core.VPNRoleMesh, core.VPNRoleSourceAuto),
	}
	var got []string
	for _, i := range selectInterfaces(ifs, "lan", true, false, idx) {
		got = append(got, i.Name)
	}
	if !slices.Equal(got, []string{"eth2", "wlan0", "wg0", "br-lan", "zt0"}) {
		t.Fatalf("by role: %v", got)
	}
	// A named interface is used whatever its role (the administrator asked
	// for it), but not a container that is not local.
	got = nil
	for _, i := range selectInterfaces(ifs, "edge0, docker0", false, false, idx) {
		got = append(got, i.Name)
	}
	if !slices.Equal(got, []string{"edge0"}) {
		t.Fatalf("named: %v", got)
	}
}

func TestSupervisorPublishAndCollisions(t *testing.T) {
	h := newHarness(t)
	h.script = func(b *fakeBackend) {
		b.collide["fileparcel"] = true     // taken (reported synchronously)
		b.asyncColl["fileparcel-2"] = true // taken (reported by a state change)
	}
	if st := h.svc.Status(); st.State != core.MDNSOff || st.Name != "fileparcel.local" || st.Interfaces == nil {
		t.Fatalf("before start %+v", st)
	}
	if err := h.svc.Republish(context.Background()); !errors.Is(err, core.ErrConflict) {
		t.Fatalf("republish before start: %v", err)
	}
	if err := h.svc.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := h.svc.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	h.waitState(core.MDNSCollision, "fileparcel.local")
	st := h.waitState(core.MDNSPublished, "fileparcel-3.local")
	if st.Backend != BackendBuiltin || st.Mode != ModeAuto || !slices.Equal(st.Interfaces, []string{"eth2"}) {
		t.Fatalf("status %+v", st)
	}
	if h.svc.Name() != "fileparcel-3.local" {
		t.Fatal(h.svc.Name())
	}
	pubs := h.backend(0).published()
	last := pubs[len(pubs)-1]
	// The host renames; the DNS-SD instance name has its own counter and is
	// untouched by a host collision.
	if last.Instance != "FileParcel on nas" || last.Port != 9443 || !slices.Equal(last.TXT, []string{"path=/", "fp=1"}) ||
		len(last.Ifaces) != 1 || len(last.Ifaces[0].Addrs) != 2 {
		t.Fatalf("publication %+v", last)
	}

	// Unrelated settings and unchanged interfaces do not republish.
	n := len(h.backend(0).published())
	h.set("mdnstest.unrelated", "true")
	h.env.Bus.Publish(events.Event{Topic: events.TopicNetworkChanged})
	time.Sleep(100 * time.Millisecond)
	if got := len(h.backend(0).published()); got != n {
		t.Fatalf("republished without a change (%d -> %d)", n, got)
	}

	// A new address republishes (keeping the collision-free name).
	ifs := lanIfs()
	ifs[1] = ni("eth2", core.IfLAN, true, "192.168.1.7/24")
	h.net.set(ifs)
	h.env.Bus.Publish(events.Event{Topic: events.TopicNetworkChanged})
	waitFor(t, func() bool {
		p := h.backend(0).published()
		l := p[len(p)-1]
		return len(l.Ifaces) == 1 && l.Ifaces[0].Addrs[0].String() == "192.168.1.7" && l.Host == "fileparcel-3"
	})

	// Explicit Republish resolves collisions afresh (attempt 1 again).
	if err := h.svc.Republish(context.Background()); err != nil {
		t.Fatal(err)
	}
	h.waitState(core.MDNSPublished, "fileparcel-3.local")

	// Changing the name restarts the attempt series.
	h.set(KeyName, `"myfiles"`)
	h.waitState(core.MDNSPublished, "myfiles.local")
	if h.svc.Name() != "myfiles.local" {
		t.Fatal(h.svc.Name())
	}
	// server.name is the fallback when mdns.name is empty.
	h.set(KeyName, `""`)
	h.set("server.name", `"nas2"`)
	h.waitState(core.MDNSPublished, "nas2.local")

	// Mode off withdraws everything; switching back creates a new backend.
	h.set(KeyMode, `"off"`)
	h.waitState(core.MDNSOff, "")
	if b := h.backend(0); b.closed != 1 {
		t.Fatalf("backend not closed: %d", b.closed)
	}
	if err := h.svc.Republish(context.Background()); err != nil {
		t.Fatalf("republish while off: %v", err)
	}
	h.set(KeyMode, `"avahi"`)
	st = h.waitState(core.MDNSPublished, "nas2.local")
	if st.Backend != BackendAvahi || st.Mode != BackendAvahi || h.backend(1) == nil || h.backend(1).kind() != BackendAvahi {
		t.Fatalf("mode switch %+v", st)
	}

	if err := h.svc.Stop(); err != nil {
		t.Fatal(err)
	}
	if err := h.svc.Stop(); err != nil {
		t.Fatal(err)
	}
	if st := h.svc.Status(); st.State != core.MDNSOff {
		t.Fatalf("after stop %+v", st)
	}
	if b := h.backend(1); b.closed != 1 {
		t.Fatal("backend not closed on stop")
	}
	if err := h.svc.Republish(context.Background()); !errors.Is(err, core.ErrConflict) {
		t.Fatalf("republish after stop: %v", err)
	}
}

// TestInstanceCollisionKeepsTheHostName pins the split attempt counters.
// The DNS-SD instance is "FileParcel on <computer name>", identical for
// every FileParcel process on one machine, so a clash there must rename only
// the service: renaming <name>.local as well would move the advertised URL
// on every restart, drop the configured name from the leaf certificate SANs
// and change the WebAuthn RP ID.
func TestInstanceCollisionKeepsTheHostName(t *testing.T) {
	h := newHarness(t)
	h.script = func(b *fakeBackend) {
		b.instColl["FileParcel on nas"] = true      // taken (reported synchronously)
		b.instColl["FileParcel on nas (2)"] = true  //
		b.asyncInst["FileParcel on nas (3)"] = true // taken (reported by a state change)
	}
	h.set("server.name", `"zq7unique"`)
	if err := h.svc.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	var st core.MDNSStatus
	deadline := time.After(3 * time.Second)
	for st.State != core.MDNSPublished {
		select {
		case e := <-h.ch:
			s := e.Data.(core.MDNSStatus)
			if s.State == core.MDNSCollision {
				t.Fatalf("an instance clash was reported as a name collision: %+v", s)
			}
			st = s
		case <-deadline:
			t.Fatalf("never published (%+v)", h.svc.Status())
		}
	}
	if st.Name != "zq7unique.local" {
		t.Fatalf("an instance clash renamed the host: %s", st.Name)
	}
	if h.svc.Name() != "zq7unique.local" { // feeds the cert SANs and the WebAuthn RP ID
		t.Fatalf("Name() = %s", h.svc.Name())
	}
	pubs := h.backend(0).published()
	last := pubs[len(pubs)-1]
	if last.Host != "zq7unique" || last.Instance != "FileParcel on nas (4)" {
		t.Fatalf("publication %+v", last)
	}

	// Republish starts both series afresh.
	if err := h.svc.Republish(context.Background()); err != nil {
		t.Fatal(err)
	}
	h.waitState(core.MDNSPublished, "zq7unique.local")
	pubs = h.backend(0).published()
	if first := pubs[len(pubs)-4]; first.Instance != "FileParcel on nas" {
		t.Fatalf("republish did not restart the instance series: %+v", first)
	}
}

// TestHostCollisionKeepsTheInstanceName is the other half: a real host-name
// clash renames <name>.local and leaves the service instance alone.
func TestHostCollisionKeepsTheInstanceName(t *testing.T) {
	h := newHarness(t)
	h.script = func(b *fakeBackend) {
		b.collide["fileparcel"] = true
		b.asyncColl["fileparcel-2"] = true
	}
	if err := h.svc.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	h.waitState(core.MDNSPublished, "fileparcel-3.local")
	pubs := h.backend(0).published()
	for _, p := range pubs {
		if p.Instance != "FileParcel on nas" {
			t.Fatalf("host rename also renamed the service instance: %+v", p)
		}
	}
}

func TestSupervisorFailureRetryAndNoInterfaces(t *testing.T) {
	h := newHarness(t)
	h.script = func(b *fakeBackend) { b.fail = errors.New("daemon not ready") }
	if err := h.svc.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	st := h.waitState(core.MDNSError, "")
	if !strings.Contains(st.Error, "daemon not ready") {
		t.Fatalf("%+v", st)
	}
	// Retries with backoff until the backend recovers.
	waitFor(t, func() bool { return len(h.backend(0).published()) >= 3 })
	b := h.backend(0)
	b.mu.Lock()
	b.fail = nil
	b.mu.Unlock()
	h.waitState(core.MDNSPublished, "fileparcel.local")

	// Losing every usable interface is an error state (no retry loop);
	// network.changed brings it back.
	h.net.set([]core.NetInterface{ni("lo", core.IfLoopback, true, "127.0.0.1/8")})
	h.env.Bus.Publish(events.Event{Topic: events.TopicNetworkChanged})
	st = h.waitState(core.MDNSError, "")
	if !strings.Contains(st.Error, "no LAN") {
		t.Fatalf("%+v", st)
	}
	b.mu.Lock()
	unpubs := b.unpubs
	b.mu.Unlock()
	if unpubs == 0 {
		t.Fatal("not unpublished")
	}
	h.net.set(lanIfs())
	h.env.Bus.Publish(events.Event{Topic: events.TopicNetworkChanged})
	h.waitState(core.MDNSPublished, "fileparcel.local")

	// Stale backend events (old generation) are ignored.
	b.emit(backendEvent{gen: 9999, state: core.MDNSError, err: errors.New("stale")})
	time.Sleep(50 * time.Millisecond)
	if st := h.svc.Status(); st.State != core.MDNSPublished {
		t.Fatalf("stale event applied: %+v", st)
	}
	// A current-generation failure (e.g. avahi-daemon restarted) retries.
	n := len(b.published())
	b.emit(backendEvent{gen: currentGen(h), state: core.MDNSError, err: errors.New("avahi-daemon restarted")})
	h.waitState(core.MDNSError, "")
	h.waitState(core.MDNSPublished, "fileparcel.local")
	if len(b.published()) <= n {
		t.Fatal("no retry after a backend failure")
	}
}

// currentGen returns the generation of the last publication (the fake
// backend records one publication per generation, in order).
func currentGen(h *harness) uint64 {
	var total uint64
	h.mu.Lock()
	defer h.mu.Unlock()
	for _, b := range h.backends {
		total += uint64(len(b.published()))
	}
	return total
}

func TestSupervisorNetworkError(t *testing.T) {
	h := newHarness(t)
	h.net.err = errors.New("boom")
	if err := h.svc.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	st := h.waitState(core.MDNSError, "")
	if !strings.Contains(st.Error, "boom") {
		t.Fatalf("%+v", st)
	}
	// Without a network service at all.
	s, _ := New(nil, nil)
	if s.Name() != "fileparcel.local" || s.Status().Mode != ModeAuto {
		t.Fatal("nil env")
	}
	if err := s.Stop(); err != nil {
		t.Fatal(err)
	}
}

// Mode "auto" that fell back to the builtin responder while Avahi was away
// moves back to Avahi once it returns (never two responders on 5353), and
// does not churn while Avahi stays away.
func TestAutoSwitchesBackToAvahi(t *testing.T) {
	h := newHarness(t)
	var detected atomic.Value
	detected.Store(BackendAvahi)
	h.svc.detect = func(context.Context) string { return detected.Load().(string) }
	h.svc.recheck = 30 * time.Millisecond
	if err := h.svc.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	waitBackend := func(kind string) {
		t.Helper()
		timeout := time.After(3 * time.Second)
		for {
			select {
			case e := <-h.ch:
				if st := e.Data.(core.MDNSStatus); st.State == core.MDNSPublished && st.Backend == kind {
					return
				}
			case <-timeout:
				t.Fatalf("not published on %s (status %+v)", kind, h.svc.Status())
			}
		}
	}
	waitBackend(BackendAvahi)
	// avahi-daemon goes away: the retry falls back to the builtin responder.
	detected.Store(BackendBuiltin)
	h.backend(0).emit(backendEvent{gen: currentGen(h), state: core.MDNSError, err: errors.New("avahi-daemon restarted")})
	waitBackend(BackendBuiltin)
	builtin := h.backend(1)
	// No churn while Avahi stays away.
	time.Sleep(150 * time.Millisecond)
	if n := len(builtin.published()); n != 1 || h.backend(2) != nil {
		t.Fatalf("builtin republished %d times while Avahi was away", n)
	}
	// Avahi is back: the next recheck moves the publication over.
	detected.Store(BackendAvahi)
	waitBackend(BackendAvahi)
	builtin.mu.Lock()
	closed := builtin.closed
	builtin.mu.Unlock()
	if closed != 1 {
		t.Fatalf("builtin backend closed %d times", closed)
	}
}

// An explicitly chosen backend is never switched by the recheck.
func TestExplicitBuiltinIsNotRechecked(t *testing.T) {
	h := newHarness(t)
	h.set(KeyMode, `"builtin"`)
	h.svc.detect = func(context.Context) string { return BackendAvahi }
	h.svc.recheck = 10 * time.Millisecond
	if err := h.svc.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	h.waitState(core.MDNSPublished, "fileparcel.local")
	time.Sleep(100 * time.Millisecond)
	if b := h.backend(0); b.kind() != BackendBuiltin || len(b.published()) != 1 || h.backend(1) != nil {
		t.Fatalf("explicit builtin changed: %+v", h.svc.Status())
	}
}

func TestRelevant(t *testing.T) {
	cases := []struct {
		e    events.Event
		want bool
	}{
		{events.Event{Topic: events.TopicNetworkChanged}, true},
		{events.Event{Topic: events.TopicSettingsChanged, Data: core.SettingsChangedEvent{Keys: []string{"mdns.mode"}}}, true},
		{events.Event{Topic: events.TopicSettingsChanged, Data: &core.SettingsChangedEvent{Keys: []string{"server.name"}}}, true},
		{events.Event{Topic: events.TopicSettingsChanged, Data: core.SettingsChangedEvent{Keys: []string{"network.strict_host"}}}, false},
		{events.Event{Topic: events.TopicSettingsChanged}, true},
	}
	for i, c := range cases {
		if relevant(c.e) != c.want {
			t.Errorf("case %d", i)
		}
	}
}

func TestSettingsValidation(t *testing.T) {
	for v, ok := range map[string]bool{`""`: true, `"fileparcel"`: true, `"File"`: false, `"a.b"`: false, `"-x"`: false} {
		d, _ := settings.Lookup(KeyName)
		if _, _, err := d.Decode(json.RawMessage(v)); (err == nil) != ok {
			t.Errorf("mdns.name %s: %v", v, err)
		}
	}
	for v, ok := range map[string]bool{`"lan"`: true, `"eth0, wlan0"`: true, `"eth0;rm"`: false, `""`: true, `"LAN"`: true, `"lan, eth0"`: true} {
		d, _ := settings.Lookup(KeyInterfaces)
		if _, _, err := d.Decode(json.RawMessage(v)); (err == nil) != ok {
			t.Errorf("mdns.interfaces %s: %v", v, err)
		}
	}
}
