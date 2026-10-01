package netinfo

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"fileparcel/internal/core"
	"fileparcel/internal/events"
	"fileparcel/internal/settings"
	"fileparcel/internal/tslocal"
)

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

var _ core.Audit = (*fakeAudit)(nil)

// testEnv returns an env with an in-memory settings store, a bus and a fake audit.
func testEnv(t *testing.T) (*core.Env, *fakeAudit) {
	t.Helper()
	env := &core.Env{Bus: events.New(), Clock: core.SystemClock{}}
	st, err := settings.New(env)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close(); env.Bus.Close() })
	env.Settings = st
	au := &fakeAudit{}
	env.Audit = au
	return env, au
}

func mustMatcher(t *testing.T, p core.AccessPolicy) *matcher {
	t.Helper()
	m, err := compilePolicy(p)
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func TestMatcher(t *testing.T) {
	ip := netip.MustParseAddr
	type check struct {
		ip   string
		want bool
	}
	cases := []struct {
		name   string
		policy core.AccessPolicy
		checks []check
	}{
		{"allowlist empty = loopback only", core.AccessPolicy{Mode: "allowlist"}, []check{
			{"127.0.0.1", true}, {"127.8.9.10", true}, {"::1", true}, {"::ffff:127.0.0.1", true},
			{"192.168.1.10", false}, {"fe80::1%eth0", false}, {"8.8.8.8", false},
		}},
		{"allowlist with LAN and tailnet", core.AccessPolicy{Mode: "allowlist",
			Allow: []string{"192.168.1.0/24", "100.64.0.0/10", "fd7a:115c:a1e0::/48", "2001:db8::5"}}, []check{
			{"192.168.1.77", true}, {"::ffff:192.168.1.77", true}, {"192.168.2.1", false},
			{"100.64.0.10", true}, {"fd7a:115c:a1e0::a", true}, {"2001:db8::5", true}, {"2001:db8::6", false},
			{"::ffff:10.0.0.1", false},
		}},
		{"deny wins over allow", core.AccessPolicy{Mode: "allowlist",
			Allow: []string{"192.168.0.0/16"}, Deny: []string{"192.168.1.66", "192.168.5.0/24"}}, []check{
			{"192.168.1.65", true}, {"192.168.1.66", false}, {"::ffff:192.168.1.66", false}, {"192.168.5.200", false},
		}},
		{"loopback beats deny", core.AccessPolicy{Mode: "any", Deny: []string{"0.0.0.0/0", "::/0"}}, []check{
			{"127.0.0.1", true}, {"::1", true}, {"1.2.3.4", false}, {"2001:db8::1", false},
		}},
		{"any", core.AccessPolicy{Mode: "any", Deny: []string{"203.0.113.0/24"}}, []check{
			{"8.8.8.8", true}, {"2606:4700::1111", true}, {"203.0.113.9", false}, {"::ffff:203.0.113.9", false},
		}},
		{"private", core.AccessPolicy{Mode: "private", Allow: []string{"2001:db8:f030:b300::/64"}}, []check{
			{"10.1.2.3", true}, {"172.16.0.1", true}, {"172.32.0.1", false}, {"192.168.1.10", true},
			{"169.254.1.1", true}, {"100.64.0.1", true}, {"fd00::1", true}, {"fe80::1", true},
			{"8.8.8.8", false}, {"2001:db8:f030:b300::9", true}, {"2001:db8:f030:b301::9", false},
			{"::ffff:10.1.2.3", true},
		}},
		{"mapped prefix normalised", core.AccessPolicy{Mode: "allowlist", Allow: []string{"::ffff:10.0.0.0/104"}}, []check{
			{"10.200.0.1", true}, {"::ffff:10.200.0.1", true}, {"11.0.0.1", false},
		}},
	}
	for _, c := range cases {
		m := mustMatcher(t, c.policy)
		for _, ch := range c.checks {
			if got := m.allowed(ip(ch.ip)); got != ch.want {
				t.Errorf("%s: %s -> %v, want %v", c.name, ch.ip, got, ch.want)
			}
		}
	}
	if (&matcher{any: true}).allowed(netip.Addr{}) {
		t.Fatal("invalid address allowed")
	}
	var nilM *matcher
	if !nilM.allowed(ip("127.0.0.1")) || nilM.allowed(ip("10.0.0.1")) {
		t.Fatal("nil matcher must allow loopback only")
	}
}

func TestCompilePolicyValidation(t *testing.T) {
	m := mustMatcher(t, core.AccessPolicy{Mode: " Allowlist ", Allow: []string{"192.168.1.10/24", " 10.0.0.1 ", "192.168.1.0/24", "", "::ffff:10.0.0.0/104"}})
	want := []string{"192.168.1.0/24", "10.0.0.1", "10.0.0.0/8"}
	if m.policy.Mode != "allowlist" || !slices.Equal(m.policy.Allow, want) || m.policy.Deny == nil {
		t.Fatalf("normalised: %+v", m.policy)
	}
	if m := mustMatcher(t, core.AccessPolicy{}); m.policy.Mode != core.AccessAllowlist {
		t.Fatal("empty mode must default to allowlist")
	}
	bad := []core.AccessPolicy{
		{Mode: "public"},
		{Mode: "allowlist", Allow: []string{"10.0.0.0/33"}},
		{Mode: "allowlist", Allow: []string{"example.com"}},
		{Mode: "allowlist", Deny: []string{"1.2.3.4/x"}},
		{Mode: "allowlist", Allow: []string{"::ffff:0:0/80"}},
	}
	for _, p := range bad {
		_, err := compilePolicy(p)
		if !errors.Is(err, core.ErrInvalid) {
			t.Errorf("%+v: %v", p, err)
		}
	}
	_, err := compilePolicy(core.AccessPolicy{Mode: "allowlist", Deny: []string{"bogus"}})
	if ce := core.AsError(err); ce == nil || ce.Field != "deny" {
		t.Fatalf("field: %v", err)
	}
	many := make([]string, maxPolicyEntries+1)
	for i := range many {
		many[i] = netip.AddrFrom4([4]byte{10, byte(i >> 8), byte(i), 1}).String()
	}
	if _, err := compilePolicy(core.AccessPolicy{Mode: "allowlist", Allow: many}); err == nil {
		t.Fatal("too many entries accepted")
	}
	if got := PrivateRanges(); len(got) != len(privateRanges) || got[0] != "127.0.0.0/8" {
		t.Fatalf("%v", got)
	}
}

func TestPolicyWarnings(t *testing.T) {
	has := func(w []string, sub string) bool {
		return slices.ContainsFunc(w, func(s string) bool { return strings.Contains(s, sub) })
	}
	w := policyWarnings(mustMatcher(t, core.AccessPolicy{Mode: "any"}), netip.Addr{}, false)
	if !has(w, `"any"`) {
		t.Fatalf("any: %v", w)
	}
	w = policyWarnings(mustMatcher(t, core.AccessPolicy{Mode: "allowlist"}), netip.Addr{}, false)
	if !has(w, "empty") {
		t.Fatalf("empty: %v", w)
	}
	w = policyWarnings(mustMatcher(t, core.AccessPolicy{Mode: "allowlist", Allow: []string{"0.0.0.0/0"}, Deny: []string{"127.0.0.0/8"}}),
		netip.MustParseAddr("192.168.1.9"), true)
	if !has(w, "every IPv4") || !has(w, "loopback") {
		t.Fatalf("wide/loopback: %v", w)
	}
	w = policyWarnings(mustMatcher(t, core.AccessPolicy{Mode: "allowlist", Allow: []string{"10.0.0.0/8"}}),
		netip.MustParseAddr("192.168.1.9"), true)
	if !has(w, "192.168.1.9") {
		t.Fatalf("forced lockout: %v", w)
	}
}

func TestSetPolicyLockoutGuard(t *testing.T) {
	env, au := testEnv(t)
	s, err := New(env)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	admin := &core.Principal{UserID: "usr_1", Username: "admin", Role: core.RoleAdmin, AuthLevel: 2}
	client := netip.MustParseAddr("::ffff:192.168.1.50") // IPv4-mapped, as a dual-stack listener reports it

	if p := s.Policy(); p.Mode != core.AccessAllowlist || len(p.Allow) != 0 || p.Deny == nil {
		t.Fatalf("initial policy %+v", p)
	}
	if s.Allowed(client) || !s.Allowed(netip.MustParseAddr("::1")) {
		t.Fatal("initial matcher")
	}

	// A policy that excludes the client is refused without force.
	_, err = s.SetPolicy(ctx, admin, core.AccessPolicy{Mode: "allowlist", Allow: []string{"10.0.0.0/8"}}, client, false)
	if !errors.Is(err, core.ErrConflict) {
		t.Fatalf("lockout guard: %v", err)
	}
	if env.Settings.String(KeyAccessMode) != "allowlist" || len(env.Settings.Strings(KeyAllowCIDRs)) != 0 {
		t.Fatal("refused policy was stored")
	}
	if d := au.actions(core.ActNetworkPolicy); len(d) != 1 || d[0].Outcome != core.OutcomeDenied {
		t.Fatalf("denied audit: %+v", d)
	}

	// Including the client works; the matcher changes immediately.
	warn, err := s.SetPolicy(ctx, admin, core.AccessPolicy{Mode: "allowlist", Allow: []string{"192.168.1.0/24", "100.64.0.0/10"},
		Deny: []string{"192.168.1.66"}}, client, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(warn) != 0 {
		t.Fatalf("warnings %v", warn)
	}
	if !s.Allowed(client) || s.Allowed(netip.MustParseAddr("192.168.1.66")) || !s.Allowed(netip.MustParseAddr("100.64.0.10")) {
		t.Fatal("new policy not applied")
	}
	if got := env.Settings.Strings(KeyAllowCIDRs); !slices.Equal(got, []string{"192.168.1.0/24", "100.64.0.0/10"}) {
		t.Fatalf("stored allow %v", got)
	}
	if got := env.Settings.Strings(KeyDenyCIDRs); !slices.Equal(got, []string{"192.168.1.66"}) {
		t.Fatalf("stored deny %v", got)
	}
	ok := au.actions(core.ActNetworkPolicy)
	if len(ok) != 2 || ok[1].Outcome != core.OutcomeSuccess || ok[1].ActorName != "admin" {
		t.Fatalf("success audit: %+v", ok)
	}
	if len(au.actions(core.ActSettingsChange)) != 2 { // access_mode unchanged: no entry
		t.Fatalf("settings.change audits: %d", len(au.actions(core.ActSettingsChange)))
	}

	// force overrides the guard, with a warning.
	warn, err = s.SetPolicy(ctx, admin, core.AccessPolicy{Mode: "allowlist", Allow: []string{"10.0.0.0/8"}}, client, true)
	if err != nil || len(warn) == 0 || s.Allowed(client) {
		t.Fatalf("force: %v %v", warn, err)
	}

	// In-process callers (no client address) and loopback clients are never locked out.
	if _, err := s.SetPolicy(ctx, admin, core.AccessPolicy{Mode: "allowlist"}, netip.Addr{}, false); err != nil {
		t.Fatal(err)
	}
	if _, err := s.SetPolicy(ctx, admin, core.AccessPolicy{Mode: "allowlist", Deny: []string{"::/0", "0.0.0.0/0"}}, netip.IPv6Loopback(), false); err != nil {
		t.Fatal(err)
	}
	// Invalid input.
	if _, err := s.SetPolicy(ctx, admin, core.AccessPolicy{Mode: "open"}, client, true); !errors.Is(err, core.ErrInvalid) {
		t.Fatalf("invalid: %v", err)
	}
	// CheckPolicy does not apply anything.
	allowed, err := s.CheckPolicy(core.AccessPolicy{Mode: "any"}, client)
	if err != nil || !allowed || s.Allowed(client) {
		t.Fatalf("check: %v %v", allowed, err)
	}
	if _, err := s.CheckPolicy(core.AccessPolicy{Mode: "any", Deny: []string{"x"}}, client); !errors.Is(err, core.ErrInvalid) {
		t.Fatalf("check invalid: %v", err)
	}
}

func TestPolicyReloadOnSettingsChanged(t *testing.T) {
	env, _ := testEnv(t)
	s, _ := New(env)
	s.source = func() ([]rawIface, error) { return nil, nil }
	s.ts.tl = &tslocal.Client{}
	s.sysHost.lookup = func(context.Context) string { return "" }
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := s.Start(ctx); err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	// A direct settings change (e.g. PATCH /admin/settings or `config set`)
	// reaches the matcher through settings.changed.
	_, err := env.Settings.Set(ctx, core.SystemPrincipal(core.ViaOffline), map[string]json.RawMessage{
		KeyAccessMode: json.RawMessage(`"private"`)})
	if err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(3 * time.Second)
	for !s.Allowed(netip.MustParseAddr("10.9.8.7")) {
		if time.Now().After(deadline) {
			t.Fatal("policy not reloaded")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if s.Policy().Mode != core.AccessPrivate {
		t.Fatal(s.Policy())
	}
}

func BenchmarkAllowed(b *testing.B) {
	s := newService(nil)
	m, _ := compilePolicy(core.AccessPolicy{Mode: "allowlist", Allow: []string{"192.168.1.0/24", "100.64.0.0/10", "fd7a:115c:a1e0::/48"},
		Deny: []string{"192.168.1.66"}})
	s.matcher.Store(m)
	ip := netip.MustParseAddr("::ffff:100.64.0.10")
	b.ReportAllocs()
	for b.Loop() {
		if !s.Allowed(ip) {
			b.Fatal("denied")
		}
	}
}

// Denied is the deny list alone (Tailscale Funnel: the internet reaches it
// by design, so the allow list and the mode do not apply).
func TestMatcherDenied(t *testing.T) {
	m := mustMatcher(t, core.AccessPolicy{Mode: "allowlist", Allow: []string{"192.168.1.0/24"},
		Deny: []string{"198.51.100.0/24", "2001:db8:bad::/48", "0.0.0.0/32"}})
	for ip, want := range map[string]bool{
		"198.51.100.7": true, "::ffff:198.51.100.7": true, "2001:db8:bad::1": true, "2001:db8:bad::1%eth0": true,
		"203.0.113.9": false, "192.168.1.5": false, "2001:db8::1": false, "127.0.0.1": false, "::1": false,
	} {
		if got := m.denied(netip.MustParseAddr(ip)); got != want {
			t.Errorf("denied(%s) = %v", ip, got)
		}
	}
	if m.denied(netip.Addr{}) || (*matcher)(nil).denied(netip.MustParseAddr("198.51.100.7")) {
		t.Fatal("invalid address or no matcher")
	}
	var s Service
	s.matcher.Store(m)
	if !s.Denied(netip.MustParseAddr("198.51.100.7")) || s.Denied(netip.MustParseAddr("203.0.113.9")) {
		t.Fatal("Service.Denied")
	}
}
