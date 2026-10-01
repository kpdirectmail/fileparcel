package tsingress

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"net/netip"
	"path/filepath"
	"slices"
	"sync"
	"testing"
	"time"

	"fileparcel/internal/core"
	"fileparcel/internal/events"
	"fileparcel/internal/home"
	"fileparcel/internal/settings"
	"fileparcel/internal/tslocal"
	"fileparcel/internal/tslocal/tslocaltest"
)

func init() {
	// The mtls.* settings belong to package certs, which this test binary
	// does not link; the checks read them.
	if _, ok := settings.Lookup("mtls.mode"); !ok {
		settings.Register(settings.Def{Key: "mtls.mode", Section: "mtls", Order: 1, Type: settings.TypeEnum,
			Default: "off", Enum: []string{"off", "optional", "required"}})
		settings.Register(settings.Def{Key: "mtls.exempt_shares", Section: "mtls", Order: 2, Type: settings.TypeBool,
			Default: true})
	}
}

// fakeAudit records entries in memory.
type fakeAudit struct {
	mu      sync.Mutex
	entries []core.AuditEntry
}

func (a *fakeAudit) Record(ctx context.Context, e core.AuditEntry) {
	if p := core.PrincipalFrom(ctx); p != nil && e.ActorName == "" {
		e.ActorName = p.Username
	}
	a.mu.Lock()
	a.entries = append(a.entries, e)
	a.mu.Unlock()
}
func (a *fakeAudit) RecordTx(ctx context.Context, _ *sql.Tx, e core.AuditEntry) error {
	a.Record(ctx, e)
	return nil
}
func (a *fakeAudit) Query(context.Context, core.AuditQuery) (core.Page[core.AuditRecord], error) {
	return core.Page[core.AuditRecord]{}, nil
}
func (a *fakeAudit) Verify(context.Context) (*core.AuditVerify, error) { return nil, nil }
func (a *fakeAudit) Export(context.Context, core.AuditQuery, string, io.Writer) error {
	return nil
}
func (a *fakeAudit) Prune(context.Context, time.Time) (int, error) { return 0, nil }

func (a *fakeAudit) actions(action string) []core.AuditEntry {
	a.mu.Lock()
	defer a.mu.Unlock()
	var out []core.AuditEntry
	for _, e := range a.entries {
		if e.Action == action {
			out = append(out, e)
		}
	}
	return out
}

// last returns the last entry of action (fails the test when there is none).
func (a *fakeAudit) last(t *testing.T, action string) core.AuditEntry {
	t.Helper()
	es := a.actions(action)
	if len(es) == 0 {
		t.Fatalf("no %s audit entry", action)
	}
	return es[len(es)-1]
}

// withReason returns the entries of action whose details carry reason.
func (a *fakeAudit) withReason(action, reason string) []core.AuditEntry {
	var out []core.AuditEntry
	for _, e := range a.actions(action) {
		if d, ok := e.Details.(map[string]any); ok && d["reason"] == reason {
			out = append(out, e)
		}
	}
	return out
}

// seqLog records listener and tailscaled events in order.
type seqLog struct {
	mu sync.Mutex
	ev []string
}

func (l *seqLog) add(s string) { l.mu.Lock(); l.ev = append(l.ev, s); l.mu.Unlock() }

func (l *seqLog) all() []string { l.mu.Lock(); defer l.mu.Unlock(); return slices.Clone(l.ev) }

func (l *seqLog) reset() { l.mu.Lock(); l.ev = nil; l.mu.Unlock() }

// fakeListeners implements core.IngressListeners and addrListeners.
type fakeListeners struct {
	log  *seqLog
	mu   sync.Mutex
	open map[string][2]string         // kind → network, address of the current listener
	all  map[string]map[string]string // kind → address → network of every open listener
	fail error
	uids []int
}

func (l *fakeListeners) Open(kind, network, address string, peerUIDs []int) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.fail != nil {
		return l.fail
	}
	l.uids = peerUIDs
	if cur, ok := l.open[kind]; ok && cur == [2]string{network, address} && len(l.all[kind]) == 1 {
		return nil
	}
	l.open[kind] = [2]string{network, address}
	l.allOf(kind)
	l.all[kind] = map[string]string{address: network}
	l.log.add("open " + kind + " " + network + " " + address)
	return nil
}

func (l *fakeListeners) allOf(kind string) map[string]string {
	if l.all == nil {
		l.all = map[string]map[string]string{}
	}
	if l.all[kind] == nil {
		l.all[kind] = map[string]string{}
	}
	return l.all[kind]
}

func (l *fakeListeners) OpenAt(kind, network, address string, peerUIDs []int) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.fail != nil {
		return l.fail
	}
	l.uids = peerUIDs
	a := l.allOf(kind)
	if n, ok := a[address]; ok && n == network {
		l.open[kind] = [2]string{network, address}
		return nil
	}
	a[address] = network
	l.open[kind] = [2]string{network, address}
	l.log.add("open " + kind + " " + network + " " + address)
	return nil
}

func (l *fakeListeners) CloseAt(kind, network, address string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	a := l.allOf(kind)
	if _, ok := a[address]; !ok {
		return
	}
	delete(a, address)
	l.log.add("close " + kind + " " + address)
	if cur, ok := l.open[kind]; ok && cur[1] == address {
		delete(l.open, kind)
		for addr, n := range a {
			l.open[kind] = [2]string{n, addr}
		}
	}
}

func (l *fakeListeners) Close(kind string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if _, ok := l.open[kind]; ok || len(l.allOf(kind)) > 0 {
		delete(l.open, kind)
		delete(l.all, kind)
		l.log.add("close " + kind)
	}
}

func (l *fakeListeners) get(kind string) ([2]string, bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	v, ok := l.open[kind]
	return v, ok
}

// bound reports whether kind has a listener at address.
func (l *fakeListeners) bound(kind, address string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	_, ok := l.allOf(kind)[address]
	return ok
}

// failingSettings fails Set when fail returns an error.
type failingSettings struct {
	core.Settings
	fail func(changes map[string]json.RawMessage) error
}

func (f *failingSettings) Set(ctx context.Context, by *core.Principal, ch map[string]json.RawMessage) (*core.SettingsResult, error) {
	if f.fail != nil {
		if err := f.fail(ch); err != nil {
			return nil, err
		}
	}
	return f.Settings.Set(ctx, by, ch)
}

// harness is a Service on a temporary home with a fake tailscaled and fake
// listeners.
type harness struct {
	t     *testing.T
	f     *tslocaltest.Fake
	s     *Service
	env   *core.Env
	audit *fakeAudit
	lis   *fakeListeners
	log   *seqLog
	home  *home.Home
	now   time.Time
	mu    sync.Mutex
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	hm, err := home.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	h := &harness{t: t, home: hm, now: time.Date(2026, 9, 25, 12, 0, 0, 0, time.UTC)}
	env := &core.Env{Home: hm, Bus: events.New(), Clock: core.ClockFunc(h.clock)}
	st, err := settings.New(env)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close(); env.Bus.Close() })
	env.Settings = st
	h.audit = &fakeAudit{}
	env.Audit = h.audit
	h.env = env
	h.f = tslocaltest.New(t)
	h.log = &seqLog{}
	h.lis = &fakeListeners{log: h.log, open: map[string][2]string{}}
	h.f.BeforePost(func(*tslocaltest.Fake) { h.log.add("post") })
	s, err := New(env, nil)
	if err != nil {
		t.Fatal(err)
	}
	s.ts = h.f.Client()
	s.goos = "linux"
	s.inContainer = func() bool { return false }
	s.listening = func(int) ([]netip.AddrPort, bool) { return nil, true }
	s.portFree = func(int) bool { return true }
	s.localAddr = func(netip.Addr) bool { return false }
	s.mayConfigure = func(*tslocal.Prefs) bool { return true }
	s.serviceUser = func() string { return "fp" }
	s.t.statusTTL, s.t.reconcileTTL = 0, 0
	s.t.probeDelay, s.t.retryMin, s.t.retryMax = time.Hour, time.Hour, time.Hour
	s.t.debounce = 10 * time.Millisecond
	t.Cleanup(func() { _ = s.Close() })
	h.s = s
	return h
}

func (h *harness) clock() time.Time {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.now
}

func (h *harness) advance(d time.Duration) {
	h.mu.Lock()
	h.now = h.now.Add(d)
	h.mu.Unlock()
}

// attach attaches the fake listeners and runs the start reconcile
// synchronously.
func (h *harness) attach() {
	h.s.startReconcile(h.s.attach(h.lis), "start")
}

// restart simulates a server restart: a new service on the same home and
// fake tailscaled (Detach of the old one first).
func (h *harness) restart() {
	h.s.Detach(context.Background())
	old := h.s
	s, _ := New(h.env, nil)
	s.ts, s.goos, s.inContainer, s.listening = old.ts, old.goos, old.inContainer, old.listening
	s.portFree, s.localAddr, s.mayConfigure, s.serviceUser, s.t = old.portFree, old.localAddr, old.mayConfigure, old.serviceUser, old.t
	h.t.Cleanup(func() { _ = s.Close() })
	h.s = s
	h.lis = &fakeListeners{log: h.log, open: map[string][2]string{}}
}

func (h *harness) sock(kind string) string { return filepath.Join(h.home.RunDir(), "ts-"+kind+".sock") }

func (h *harness) setting(key, raw string) {
	h.t.Helper()
	if _, err := h.env.Settings.Set(context.Background(), core.SystemPrincipal(core.ViaOffline),
		map[string]json.RawMessage{key: json.RawMessage(raw)}); err != nil {
		h.t.Fatalf("set %s: %v", key, err)
	}
}

func (h *harness) marker() *marker {
	h.t.Helper()
	m, err := readMarker(h.home)
	if err != nil {
		h.t.Fatal(err)
	}
	return m
}

func (h *harness) status() *core.IngressStatus {
	h.t.Helper()
	st, err := h.s.Status(context.Background(), false)
	if err != nil {
		h.t.Fatal(err)
	}
	return st
}

func (h *harness) enable(mode string) *core.IngressStatus {
	h.t.Helper()
	st, err := h.s.SetFunnel(context.Background(), admin(), core.FunnelInput{Mode: mode, Confirm: ConfirmPublic})
	if err != nil {
		h.t.Fatalf("SetFunnel %s: %v", mode, err)
	}
	return st
}

func admin() *core.Principal {
	return &core.Principal{UserID: "usr_admin", Username: "admin", Role: core.RoleAdmin, RoleID: "admin", AuthLevel: core.AuthLevelFull}
}

// delegate holds network.manage through a custom role but is no built-in
// owner or administrator.
func delegate() *core.Principal {
	p := &core.Principal{UserID: "usr_net", Username: "netops", Role: core.RoleMember, RoleID: "rol_netops",
		AuthLevel: core.AuthLevelFull}
	p.SetCaps(core.MemberCaps.With(core.CapNetworkManage))
	return p
}

// funnelConfig is exactly the entry FileParcel writes for Funnel on hp.
func funnelConfig(hp, port, proxy string) string {
	return `{"AllowFunnel":{"` + hp + `":true},"TCP":{"` + port + `":{"HTTPS":true}},` +
		`"Web":{"` + hp + `":{"Handlers":{"/":{"Proxy":"` + proxy + `"}}}}}`
}

// fieldOf returns the core.Error field and HTTP status of err.
func fieldOf(err error) (string, int) {
	if ce := core.AsError(err); ce != nil {
		return ce.Field, ce.HTTPStatus()
	}
	return "", 0
}

func mustCode(t *testing.T, err error, base *core.Error, field string) {
	t.Helper()
	if !errors.Is(err, base) {
		t.Fatalf("error %v, want %s", err, base.Code)
	}
	if f, _ := fieldOf(err); f != field {
		t.Fatalf("field %q, want %q (%v)", f, field, err)
	}
}

func mustHome(t *testing.T, dir string) *home.Home {
	t.Helper()
	h, err := home.New(dir)
	if err != nil {
		t.Fatal(err)
	}
	return h
}
