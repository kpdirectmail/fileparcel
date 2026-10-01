package settingsapi

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"

	"fileparcel/internal/app"
	_ "fileparcel/internal/auth" // the auth.* settings (passkeys, RP ID)
	"fileparcel/internal/config"
	"fileparcel/internal/core"
	"fileparcel/internal/events"
	_ "fileparcel/internal/mdns"   // the mdns.* settings
	"fileparcel/internal/netinfo"  // the real access-policy compiler and the network.* settings
	_ "fileparcel/internal/notify" // the smtp.* settings (section email)
	"fileparcel/internal/qr"
	"fileparcel/internal/settings"
	"fileparcel/internal/web/httpx"
	"fileparcel/internal/web/mw"
)

// Test-only settings (never catalog keys).
const (
	keyTestCount  = "sapitest.count"  // section general, restart
	keyTestFlag   = "sapitest.flag"   // section auth (sensitive)
	keyTestSecret = "sapitest.secret" // section general, secret
)

func init() {
	settings.Register(settings.Def{Key: keyTestCount, Section: "general", Order: 1, Type: settings.TypeInt,
		Default: 3, Min: 1, Max: 10, Restart: true, Label: "Test count"})
	settings.Register(settings.Def{Key: keyTestFlag, Section: "auth", Order: 1, Type: settings.TypeBool,
		Default: false, Label: "Test flag"})
	settings.Register(settings.Def{Key: keyTestSecret, Section: "general", Order: 2, Type: settings.TypeSecret,
		Default: "", Label: "Test secret"})
}

// ---------- fakes ----------

type fakeAudit struct {
	core.Audit
	mu      sync.Mutex
	entries []core.AuditEntry
}

func (f *fakeAudit) Record(_ context.Context, e core.AuditEntry) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.entries = append(f.entries, e)
}

func (f *fakeAudit) RecordTx(ctx context.Context, _ *sql.Tx, e core.AuditEntry) error {
	f.Record(ctx, e)
	return nil
}

func (f *fakeAudit) actions(action string) []core.AuditEntry {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []core.AuditEntry
	for _, e := range f.entries {
		if e.Action == action {
			out = append(out, e)
		}
	}
	return out
}

type fakeKeys struct{ core.Keys }

func (fakeKeys) State() core.KeyState { return core.KeyStateUnlocked }
func (fakeKeys) SealField(aad string, pt []byte) (string, error) {
	return "v1:test:" + aad + ":" + string(bytes.ToUpper(pt)), nil
}
func (fakeKeys) OpenField(aad, sealed string) ([]byte, error) {
	return []byte(strings.ToLower(strings.TrimPrefix(sealed, "v1:test:"+aad+":"))), nil
}

// fakeNet is the real netinfo service (policy compilation, SetPolicy with
// its lockout guard and audit) with canned interfaces, URLs and Tailscale
// status. Policy is read back from the settings so PATCHed values are
// visible without netinfo's event loop.
type fakeNet struct {
	*netinfo.Service
	st     core.Settings
	ifs    []core.NetInterface
	ifsErr error
}

func (f *fakeNet) Interfaces(context.Context) ([]core.NetInterface, error) {
	if f.ifsErr != nil {
		return nil, f.ifsErr
	}
	return f.ifs, nil
}
func (f *fakeNet) URLs(context.Context) ([]core.AccessURL, error) {
	return []core.AccessURL{{URL: "https://192.168.1.10:8443/", Kind: core.URLKindIP, Interface: "eth0", Label: "LAN (eth0)", Recommended: true}}, nil
}
func (f *fakeNet) Tailscale(context.Context) (*core.TailscaleInfo, error) {
	return &core.TailscaleInfo{Running: true, Kind: core.IfTailscale, DNSName: "node.tailnet.ts.net"}, nil
}
func (f *fakeNet) Policy() core.AccessPolicy {
	return core.AccessPolicy{Mode: f.st.String("network.access_mode"), Allow: f.st.Strings("network.allow_cidrs"),
		Deny: f.st.Strings("network.deny_cidrs")}
}

// fakeAuth reports the RP ID in use and the number of accounts whose only
// second factor is a passkey (the passkey guard's inputs).
type fakeAuth struct {
	core.Auth
	rpID string
	n    int
}

func (f *fakeAuth) RPID() string                                     { return f.rpID }
func (f *fakeAuth) PasskeyOnlyAccounts(context.Context) (int, error) { return f.n, nil }

type fakeMDNS struct {
	republished atomic.Int32
	err         error
}

func (m *fakeMDNS) Status() core.MDNSStatus {
	return core.MDNSStatus{Mode: "auto", Backend: "avahi", Name: "fileparcel.local", State: core.MDNSPublished}
}
func (m *fakeMDNS) Name() string { return "fileparcel.local" }
func (m *fakeMDNS) Republish(context.Context) error {
	m.republished.Add(1)
	return m.err
}
func (m *fakeMDNS) Start(context.Context) error { return nil }
func (m *fakeMDNS) Stop() error                 { return nil }

// ---------- harness ----------

type testEnv struct {
	d      *app.Deps
	st     *settings.Service
	audit  *fakeAudit
	mdns   *fakeMDNS
	net    *fakeNet
	bus    *events.Bus
	router http.Handler
	srv    *httptest.Server
	now    time.Time
	who    atomic.Pointer[core.Principal]
	client atomic.Pointer[netip.Addr]
}

func newTestEnv(t *testing.T) *testEnv {
	t.Helper()
	te := &testEnv{audit: &fakeAudit{}, mdns: &fakeMDNS{}, now: time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)}
	te.bus = events.New()
	env := &core.Env{
		Config: config.Default("test"), Bus: te.bus,
		Clock: core.ClockFunc(func() time.Time { return te.now }),
		Log:   slog.New(slog.NewTextHandler(io.Discard, nil)),
		Keys:  fakeKeys{}, Audit: te.audit,
	}
	st, err := settings.New(env)
	if err != nil {
		t.Fatal(err)
	}
	env.Settings = st
	te.st = st
	ns, err := netinfo.New(env)
	if err != nil {
		t.Fatal(err)
	}
	te.net = &fakeNet{Service: ns, st: st, ifs: []core.NetInterface{
		{Name: "eth0", Kind: core.IfLAN, Label: "LAN", Up: true, Addrs: []netip.Prefix{netip.MustParsePrefix("192.168.1.10/24")}, MTU: 1500},
	}}
	te.d = &app.Deps{Env: env, Network: te.net, MDNS: te.mdns}
	te.setClient(netip.MustParseAddr("192.168.1.50"))

	r := chi.NewRouter()
	r.Use(mw.Inject(te.d), middleware.GetHead, mw.SecurityHeaders)
	r.Use(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			ctx := req.Context()
			if p := te.who.Load(); p != nil {
				ctx = core.WithPrincipal(ctx, p.Clone())
			}
			if ip := te.client.Load(); ip != nil {
				ctx = httpx.WithClientIP(ctx, *ip)
			}
			next.ServeHTTP(w, req.WithContext(ctx))
		})
	})
	api := chi.NewRouter()
	Mount(api, te.d)
	r.Mount("/api/v1", api)
	te.router = r
	te.srv = httptest.NewServer(r)
	t.Cleanup(func() {
		te.srv.Close()
		_ = st.Close()
		_ = ns.Close()
		te.bus.Close()
	})
	return te
}

func (te *testEnv) setClient(ip netip.Addr) { te.client.Store(&ip) }

func (te *testEnv) principal(role core.Role, elevated bool) *core.Principal {
	p := &core.Principal{UserID: "usr_" + string(role), Username: string(role), Role: role, Via: core.ViaSession,
		AuthLevel: core.AuthLevelFull, SessionID: "ses_" + string(role)}
	if elevated {
		p.ElevatedUntil = te.now.Add(5 * time.Minute)
	}
	return p
}

func (te *testEnv) admin(elevated bool) *core.Principal {
	return te.principal(core.RoleAdmin, elevated)
}

type result struct {
	status int
	code   string
	field  string
	msg    string
	body   []byte
	header http.Header
}

// do sends a request as p through the test server and decodes JSON into out.
func (te *testEnv) do(t *testing.T, p *core.Principal, method, path string, body any, out any) result {
	t.Helper()
	te.who.Store(p)
	var rd io.Reader
	if body != nil {
		switch b := body.(type) {
		case string:
			rd = strings.NewReader(b)
		default:
			raw, _ := json.Marshal(body)
			rd = bytes.NewReader(raw)
		}
	}
	req, _ := http.NewRequest(method, te.srv.URL+path, rd)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	res := result{status: resp.StatusCode, body: raw, header: resp.Header}
	var er httpx.ErrorResponse
	if resp.StatusCode >= 400 && json.Unmarshal(raw, &er) == nil {
		res.code, res.field, res.msg = er.Error.Code, er.Error.Field, er.Error.Message
	}
	if out != nil && resp.StatusCode < 300 {
		if err := json.Unmarshal(raw, out); err != nil {
			t.Fatalf("%s %s: decode %s: %v", method, path, raw, err)
		}
	}
	return res
}

func (te *testEnv) catalog(t *testing.T) map[string]core.SettingView {
	t.Helper()
	var list []core.SettingView
	if r := te.do(t, te.admin(false), http.MethodGet, "/api/v1/admin/settings", nil, &list); r.status != http.StatusOK {
		t.Fatalf("catalog: %d %s", r.status, r.body)
	}
	return byKey(list)
}

func routes(d *app.Deps) [][2]string {
	api := chi.NewRouter()
	Mount(api, d)
	var out [][2]string
	_ = chi.Walk(api, func(method, route string, _ http.Handler, _ ...func(http.Handler) http.Handler) error {
		out = append(out, [2]string{method, route})
		return nil
	})
	return out
}

var paramRe = regexp.MustCompile(`\{[^}]+\}`)

// ---------- tests ----------

func TestRouteProtectionSweep(t *testing.T) {
	te := newTestEnv(t)
	rs := routes(te.d)
	if len(rs) != 14 {
		t.Fatalf("expected 14 routes, got %d: %v", len(rs), rs)
	}
	pending := te.admin(true)
	pending.AuthLevel = core.AuthLevelPassword
	enroll := te.admin(true)
	enroll.EnrollRequired = true
	token := te.admin(true)
	token.Via, token.Scopes = core.ViaToken, []string{core.ScopeFilesRead, core.ScopeShares}
	member := te.principal(core.RoleMember, true)
	guest := te.principal(core.RoleGuest, true)
	for _, r := range rs {
		path := "/api/v1" + paramRe.ReplaceAllString(r[1], keyTestCount)
		admin := strings.HasPrefix(r[1], "/admin/")
		t.Run(r[0]+" "+r[1], func(t *testing.T) {
			if res := te.do(t, nil, r[0], path, nil, nil); res.status != http.StatusUnauthorized {
				t.Errorf("anonymous: %d", res.status)
			}
			if res := te.do(t, pending, r[0], path, nil, nil); res.status != http.StatusUnauthorized || res.code != "mfa_required" {
				t.Errorf("mfa pending: %d %s", res.status, res.code)
			}
			if res := te.do(t, enroll, r[0], path, nil, nil); res.status != http.StatusForbidden || res.code != "mfa_enroll_required" {
				t.Errorf("enrollment pending: %d %s", res.status, res.code)
			}
			for _, p := range []*core.Principal{member, guest, token} {
				res := te.do(t, p, r[0], path, nil, nil)
				if admin && (res.status != http.StatusForbidden || res.code != "forbidden") {
					t.Errorf("%s (%s): %d %s", p.Username, p.Via, res.status, res.code)
				}
				if !admin && (res.status == http.StatusUnauthorized || res.status == http.StatusForbidden) {
					t.Errorf("%s (%s) on an F route: %d %s", p.Username, p.Via, res.status, res.code)
				}
			}
		})
	}
}

func TestSecurityHeaders(t *testing.T) {
	te := newTestEnv(t)
	for _, path := range []string{"/api/v1/admin/settings", "/api/v1/admin/network", "/api/v1/admin/mdns", "/api/v1/network/urls"} {
		res := te.do(t, te.admin(false), http.MethodGet, path, nil, nil)
		if res.status != http.StatusOK {
			t.Fatalf("%s: %d %s", path, res.status, res.body)
		}
		if err := mw.CheckSecurityHeaders(res.header, mw.HeadersAPI); err != nil {
			t.Errorf("%s: %v", path, err)
		}
	}
}

func TestListSettings(t *testing.T) {
	te := newTestEnv(t)
	cat := te.catalog(t)
	for _, k := range []string{keyTestCount, keyTestFlag, keyTestSecret, "network.access_mode", "server.https_port", "log.level"} {
		if _, ok := cat[k]; !ok {
			t.Errorf("catalog lacks %s", k)
		}
	}
	c := cat[keyTestCount]
	if string(c.Value) != "3" || string(c.Default) != "3" || c.IsSet || !c.Restart || c.Section != "general" ||
		c.Min == nil || *c.Min != 1 || c.Max == nil || *c.Max != 10 {
		t.Errorf("count view %+v", c)
	}
	s := cat[keyTestSecret]
	if !s.Secret || s.IsSet || string(s.Value) != "null" || string(s.Default) != "null" {
		t.Errorf("secret view %+v", s)
	}
	if b := cat["server.https_port"]; !b.Bootstrap || !b.Restart {
		t.Errorf("bootstrap view %+v", b)
	}

	// Section filter.
	var list []core.SettingView
	if r := te.do(t, te.admin(false), http.MethodGet, "/api/v1/admin/settings?section=network", nil, &list); r.status != http.StatusOK {
		t.Fatal(r.status)
	}
	if len(list) == 0 {
		t.Fatal("empty network section")
	}
	for _, v := range list {
		if v.Section != "network" {
			t.Errorf("section filter returned %s", v.Key)
		}
	}
}

func TestPatchSettings(t *testing.T) {
	te := newTestEnv(t)
	ch, cancel := te.bus.Subscribe(events.TopicSettingsChanged)
	defer cancel()

	// Non-sensitive section: no elevation needed.
	var res core.SettingsResult
	if r := te.do(t, te.admin(false), http.MethodPatch, "/api/v1/admin/settings", map[string]any{keyTestCount: 5}, &res); r.status != http.StatusOK {
		t.Fatalf("patch: %d %s", r.status, r.body)
	}
	if !slices.Equal(res.Applied, []string{keyTestCount}) || !slices.Equal(res.RestartRequired, []string{keyTestCount}) {
		t.Fatalf("result %+v", res)
	}
	if te.st.Int(keyTestCount) != 5 {
		t.Fatal("not applied")
	}
	select {
	case e := <-ch:
		if ev, ok := e.Data.(core.SettingsChangedEvent); !ok || !slices.Equal(ev.Keys, []string{keyTestCount}) {
			t.Fatalf("event %+v", e)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("no settings.changed")
	}
	if a := te.audit.actions(core.ActSettingsChange); len(a) != 1 || a[0].TargetID != keyTestCount {
		t.Fatalf("audit %+v", a)
	}

	// Sensitive section: elevation required; nothing applied from a mixed batch.
	r := te.do(t, te.admin(false), http.MethodPatch, "/api/v1/admin/settings", map[string]any{keyTestCount: 6, keyTestFlag: true}, nil)
	if r.status != http.StatusForbidden || r.code != "elevation_required" {
		t.Fatalf("sensitive without elevation: %d %s", r.status, r.code)
	}
	if te.st.Int(keyTestCount) != 5 || te.st.Bool(keyTestFlag) {
		t.Fatal("partially applied")
	}
	// server.name and mdns.name decide the default passkey domain; the SMTP
	// relay receives the stored smtp.password.
	for _, key := range []string{"server.https_port", "network.strict_host", "mdns.name", "smtp.host", "smtp.port", "notify.events"} {
		r := te.do(t, te.admin(false), http.MethodPatch, "/api/v1/admin/settings", map[string]any{key: json.RawMessage(`true`)}, nil)
		if r.status != http.StatusForbidden || r.code != "elevation_required" {
			t.Errorf("%s without elevation: %d %s", key, r.status, r.code)
		}
	}
	for _, key := range []string{"smtp.host", "smtp.password", "mdns.name"} {
		r := te.do(t, te.admin(false), http.MethodDelete, "/api/v1/admin/settings/"+key, nil, nil)
		if r.status != http.StatusForbidden || r.code != "elevation_required" {
			t.Errorf("reset %s without elevation: %d %s", key, r.status, r.code)
		}
	}
	if r := te.do(t, te.admin(true), http.MethodPatch, "/api/v1/admin/settings", map[string]any{"smtp.host": "mx.example.org"}, nil); r.status != http.StatusOK ||
		te.st.String("smtp.host") != "mx.example.org" {
		t.Fatalf("smtp.host elevated: %d %s", r.status, r.body)
	}
	if r := te.do(t, te.admin(true), http.MethodPatch, "/api/v1/admin/settings", map[string]any{keyTestFlag: true}, &res); r.status != http.StatusOK {
		t.Fatalf("elevated: %d %s", r.status, r.body)
	}
	if !te.st.Bool(keyTestFlag) || len(res.RestartRequired) != 0 {
		t.Fatalf("flag %v %+v", te.st.Bool(keyTestFlag), res)
	}

	// Validation errors name the key.
	for _, tc := range []struct {
		body  any
		field string
	}{
		{map[string]any{keyTestCount: 11}, keyTestCount},
		{map[string]any{keyTestCount: "x"}, keyTestCount},
		{map[string]any{keyTestCount: nil}, keyTestCount},
		{map[string]any{"sapitest.nope": 1}, "sapitest.nope"},
		{`{"sapitest.count": `, ""},
		{`[1,2]`, ""},
	} {
		r := te.do(t, te.admin(true), http.MethodPatch, "/api/v1/admin/settings", tc.body, nil)
		if r.status != http.StatusUnprocessableEntity || r.code != "invalid" || (tc.field != "" && r.field != tc.field) {
			t.Errorf("%v: %d %s %q", tc.body, r.status, r.code, r.field)
		}
	}

	// Empty change set.
	if r := te.do(t, te.admin(false), http.MethodPatch, "/api/v1/admin/settings", map[string]any{}, &res); r.status != http.StatusOK ||
		res.Applied == nil || res.RestartRequired == nil || len(res.Applied) != 0 {
		t.Fatalf("empty: %d %s", r.status, r.body)
	}

	// Oversized body.
	big := `{"sapitest.count": 1, "x": "` + strings.Repeat("a", maxSettingsBody) + `"}`
	if r := te.do(t, te.admin(true), http.MethodPatch, "/api/v1/admin/settings", big, nil); r.status != http.StatusRequestEntityTooLarge && r.status != http.StatusUnprocessableEntity {
		t.Errorf("oversized: %d %s", r.status, r.code)
	}
}

func TestPatchSecretMasked(t *testing.T) {
	te := newTestEnv(t)
	var res core.SettingsResult
	if r := te.do(t, te.admin(false), http.MethodPatch, "/api/v1/admin/settings", map[string]any{keyTestSecret: "hunter2"}, &res); r.status != http.StatusOK {
		t.Fatalf("%d %s", r.status, r.body)
	}
	if got, err := te.st.Secret(keyTestSecret); err != nil || got != "hunter2" {
		t.Fatalf("secret %q %v", got, err)
	}
	r := te.do(t, te.admin(false), http.MethodGet, "/api/v1/admin/settings", nil, nil)
	if bytes.Contains(bytes.ToLower(r.body), []byte("hunter2")) {
		t.Fatal("catalog leaks the secret")
	}
	if v := te.catalog(t)[keyTestSecret]; !v.IsSet || string(v.Value) != "null" {
		t.Fatalf("secret view %+v", v)
	}
	for _, e := range te.audit.actions(core.ActSettingsChange) {
		raw, _ := json.Marshal(e.Details)
		if bytes.Contains(bytes.ToLower(raw), []byte("hunter2")) {
			t.Fatalf("audit leaks the secret: %s", raw)
		}
	}
	// The masked value round-trips without changing the secret.
	if r := te.do(t, te.admin(false), http.MethodPatch, "/api/v1/admin/settings", map[string]any{keyTestSecret: settings.Mask}, &res); r.status != http.StatusOK {
		t.Fatal(r.status)
	}
	if got, _ := te.st.Secret(keyTestSecret); got != "hunter2" {
		t.Fatalf("mask round trip changed the secret: %q", got)
	}
	// Reset clears it.
	var v core.SettingView
	if r := te.do(t, te.admin(false), http.MethodDelete, "/api/v1/admin/settings/"+keyTestSecret, nil, &v); r.status != http.StatusOK || v.IsSet {
		t.Fatalf("reset: %d %+v", r.status, v)
	}
	if got, _ := te.st.Secret(keyTestSecret); got != "" {
		t.Fatalf("secret after reset %q", got)
	}
}

func TestResetSetting(t *testing.T) {
	te := newTestEnv(t)
	if r := te.do(t, te.admin(true), http.MethodPatch, "/api/v1/admin/settings", map[string]any{keyTestCount: 7, keyTestFlag: true}, nil); r.status != http.StatusOK {
		t.Fatal(r.status)
	}
	if r := te.do(t, te.admin(true), http.MethodDelete, "/api/v1/admin/settings/sapitest.nope", nil, nil); r.status != http.StatusNotFound {
		t.Fatalf("unknown: %d", r.status)
	}
	var v core.SettingView
	if r := te.do(t, te.admin(false), http.MethodDelete, "/api/v1/admin/settings/"+keyTestCount, nil, &v); r.status != http.StatusOK {
		t.Fatalf("reset: %d %s", r.status, r.body)
	}
	if v.Key != keyTestCount || string(v.Value) != "3" || v.IsSet || te.st.Int(keyTestCount) != 3 {
		t.Fatalf("after reset %+v", v)
	}
	if r := te.do(t, te.admin(false), http.MethodDelete, "/api/v1/admin/settings/"+keyTestFlag, nil, nil); r.status != http.StatusForbidden || r.code != "elevation_required" {
		t.Fatalf("sensitive reset without elevation: %d %s", r.status, r.code)
	}
	if r := te.do(t, te.admin(true), http.MethodDelete, "/api/v1/admin/settings/"+keyTestFlag, nil, nil); r.status != http.StatusOK || te.st.Bool(keyTestFlag) {
		t.Fatalf("sensitive reset: %d", r.status)
	}
	var resets int
	for _, e := range te.audit.actions(core.ActSettingsChange) {
		if d, ok := e.Details.(map[string]any); ok && d["reset"] == true {
			resets++
		}
	}
	if resets != 2 {
		t.Fatalf("reset audit entries: %d", resets)
	}
}

func TestPatchPolicyLockoutGuard(t *testing.T) {
	te := newTestEnv(t) // client 192.168.1.50
	patch := func(p *core.Principal, query string, body map[string]any) result {
		return te.do(t, p, http.MethodPatch, "/api/v1/admin/settings"+query, body, nil)
	}
	if r := patch(te.admin(false), "", map[string]any{"network.allow_cidrs": []string{"192.168.1.0/24"}}); r.status != http.StatusForbidden {
		t.Fatalf("network section needs elevation: %d", r.status)
	}
	if r := patch(te.admin(true), "", map[string]any{"network.allow_cidrs": []string{"192.168.1.0/24"}}); r.status != http.StatusOK {
		t.Fatalf("admitting change: %d %s", r.status, r.body)
	}
	for _, body := range []map[string]any{
		{"network.allow_cidrs": []string{"10.0.0.0/8"}},
		{"network.deny_cidrs": []string{"192.168.1.50"}},
		{"network.access_mode": "any", "network.deny_cidrs": []string{"::ffff:192.168.1.0/120"}},
		{"network.access_mode": "private", "network.deny_cidrs": []string{"192.168.0.0/16"}},
	} {
		r := patch(te.admin(true), "", body)
		if r.status != http.StatusConflict || r.code != "conflict" || !strings.HasPrefix(r.field, "network.") ||
			!strings.Contains(r.msg, "192.168.1.50") {
			t.Errorf("%v: %d %s %q %q", body, r.status, r.code, r.field, r.msg)
		}
	}
	if got := te.st.Strings("network.allow_cidrs"); !slices.Equal(got, []string{"192.168.1.0/24"}) {
		t.Fatalf("refused change applied: %v", got)
	}
	// Other clients and in-process callers.
	if r := patch(te.admin(true), "", map[string]any{"network.access_mode": "private", "network.allow_cidrs": []string{}}); r.status != http.StatusOK {
		t.Fatalf("private admits a LAN client: %d %s", r.status, r.body)
	}
	// Invalid values are left to the settings validation (422, not 409).
	if r := patch(te.admin(true), "", map[string]any{"network.allow_cidrs": []string{"not-a-cidr"}}); r.status != http.StatusUnprocessableEntity || r.field != "network.allow_cidrs" {
		t.Fatalf("invalid: %d %s %s", r.status, r.code, r.field)
	}
	// force overrides the guard.
	if r := patch(te.admin(true), "?force=1", map[string]any{"network.access_mode": "allowlist", "network.allow_cidrs": []string{"10.0.0.0/8"}}); r.status != http.StatusOK {
		t.Fatalf("forced: %d %s", r.status, r.body)
	}
	if te.st.String("network.access_mode") != "allowlist" || !slices.Equal(te.st.Strings("network.allow_cidrs"), []string{"10.0.0.0/8"}) {
		t.Fatal("forced change not applied")
	}

	// Resetting a policy key goes through the guard as well: with mode "any"
	// the client is admitted; the default mode (allowlist, 10/8 only) would
	// refuse it.
	te.setClient(netip.MustParseAddr("10.1.2.3"))
	if r := patch(te.admin(true), "", map[string]any{"network.access_mode": "any"}); r.status != http.StatusOK {
		t.Fatal(r.status)
	}
	te.setClient(netip.MustParseAddr("192.168.1.50"))
	if r := te.do(t, te.admin(true), http.MethodDelete, "/api/v1/admin/settings/network.access_mode", nil, nil); r.status != http.StatusConflict {
		t.Fatalf("reset lockout: %d %s", r.status, r.body)
	}
	if r := te.do(t, te.admin(true), http.MethodDelete, "/api/v1/admin/settings/network.access_mode?force=true", nil, nil); r.status != http.StatusOK {
		t.Fatalf("forced reset: %d %s", r.status, r.body)
	}
	if te.st.String("network.access_mode") != "allowlist" {
		t.Fatal("reset not applied")
	}
}

// Turning passkeys off, or moving the passkey domain (RP ID) credentials are
// bound to, shuts out the accounts whose only second factor is a passkey:
// 409 naming the key unless ?force=1, on PATCH and on a reset to the default.
func TestPasskeyGuard(t *testing.T) {
	te := newTestEnv(t)
	fa := &fakeAuth{rpID: "fileparcel.local", n: 2}
	te.d.Auth = fa
	patch := func(query string, body map[string]any) result {
		t.Helper()
		return te.do(t, te.admin(true), http.MethodPatch, "/api/v1/admin/settings"+query, body, nil)
	}
	refused := func(r result, field string, words ...string) {
		t.Helper()
		if r.status != http.StatusConflict || r.code != "conflict" || r.field != field || !strings.Contains(r.msg, "2 account(s)") {
			t.Fatalf("want 409 on %s: %d %s %q %q", field, r.status, r.code, r.field, r.msg)
		}
		if strings.Contains(r.msg, "?force") {
			t.Fatalf("the message names a query parameter no client shows: %q", r.msg)
		}
		for _, w := range words {
			if !strings.Contains(r.msg, w) {
				t.Fatalf("message %q lacks %q", r.msg, w)
			}
		}
	}
	ok := func(r result) {
		t.Helper()
		if r.status != http.StatusOK {
			t.Fatalf("want 200: %d %s", r.status, r.body)
		}
	}

	// auth.passkeys: only turning it off is guarded.
	refused(patch("", map[string]any{"auth.passkeys": false}), "auth.passkeys")
	if !te.st.Bool("auth.passkeys") {
		t.Fatal("refused change applied")
	}
	ok(patch("", map[string]any{"auth.passkeys": true}))

	// With auth.webauthn_rp_id empty, mdns.name (else server.name) + ".local"
	// is the passkey domain.
	refused(patch("", map[string]any{"mdns.name": "files"}), "mdns.name", "fileparcel.local", "files.local")
	if te.st.String("mdns.name") != "" {
		t.Fatal("refused rename applied")
	}
	refused(patch("", map[string]any{"server.name": "nas"}), "server.name", "nas.local")
	ok(patch("", map[string]any{"mdns.name": "fileparcel"})) // the domain stays fileparcel.local
	ok(patch("?force=1", map[string]any{"mdns.name": "files"}))
	if te.st.String("mdns.name") != "files" {
		t.Fatal("forced rename not applied")
	}
	fa.rpID = "files.local" // auth follows the rename
	// Resetting mdns.name moves the domain back to <server.name>.local.
	r := te.do(t, te.admin(true), http.MethodDelete, "/api/v1/admin/settings/mdns.name", nil, nil)
	refused(r, "mdns.name", "files.local", "fileparcel.local")
	ok(te.do(t, te.admin(true), http.MethodDelete, "/api/v1/admin/settings/mdns.name?force=1", nil, nil))
	if te.st.String("mdns.name") != "" {
		t.Fatal("forced reset not applied")
	}

	// A collision rename of the effective mDNS name (fileparcel-2.local) is
	// what the passkeys are bound to: the configured name staying is no
	// move, pinning the RP ID to the base name is one, pinning it to the
	// name in use is none — and a pinned RP ID ignores the .local name.
	fa.rpID = "fileparcel-2.local"
	ok(patch("", map[string]any{"mdns.name": "fileparcel"}))
	refused(patch("", map[string]any{"auth.webauthn_rp_id": "fileparcel.local"}), "auth.webauthn_rp_id", "fileparcel-2.local")
	ok(patch("", map[string]any{"auth.webauthn_rp_id": "fileparcel-2.local"}))
	ok(patch("", map[string]any{"mdns.name": "files"}))
	refused(patch("", map[string]any{"auth.webauthn_rp_id": "files.example.org"}), "auth.webauthn_rp_id", "files.example.org")

	// Without passkey-only accounts nothing is guarded.
	fa.n = 0
	ok(patch("", map[string]any{"auth.passkeys": false, "auth.webauthn_rp_id": "files.example.org"}))
}

func TestNetworkOverview(t *testing.T) {
	te := newTestEnv(t)
	var ov core.NetworkOverview
	if r := te.do(t, te.admin(false), http.MethodGet, "/api/v1/admin/network", nil, &ov); r.status != http.StatusOK {
		t.Fatalf("%d %s", r.status, r.body)
	}
	if len(ov.Interfaces) != 1 || ov.Interfaces[0].Name != "eth0" || len(ov.URLs) != 1 || ov.ClientIP != "192.168.1.50" ||
		ov.Tailscale == nil || ov.Tailscale.DNSName != "node.tailnet.ts.net" || ov.Policy.Mode != core.AccessAllowlist {
		t.Fatalf("overview %+v", ov)
	}
	// Lists are [] rather than null.
	r := te.do(t, te.admin(false), http.MethodGet, "/api/v1/admin/network", nil, nil)
	if !bytes.Contains(r.body, []byte(`"allow":[]`)) || !bytes.Contains(r.body, []byte(`"deny":[]`)) {
		t.Fatalf("policy lists: %s", r.body)
	}
	// An IPv4-mapped client address is reported unmapped.
	te.setClient(netip.MustParseAddr("::ffff:192.168.1.77"))
	if r := te.do(t, te.admin(false), http.MethodGet, "/api/v1/admin/network", nil, &ov); r.status != http.StatusOK || ov.ClientIP != "192.168.1.77" {
		t.Fatalf("mapped client: %s", ov.ClientIP)
	}
	// Interfaces that cannot be listed leave the page usable (policy, URLs).
	te.net.ifsErr = errors.New("netlinkrib: permission denied")
	ov = core.NetworkOverview{}
	if r := te.do(t, te.admin(false), http.MethodGet, "/api/v1/admin/network", nil, &ov); r.status != http.StatusOK ||
		ov.Interfaces == nil || len(ov.Interfaces) != 0 || len(ov.URLs) != 1 || ov.Policy.Mode != core.AccessAllowlist {
		t.Fatalf("interfaces error: %d %+v", r.status, ov)
	}
}

func TestPutPolicy(t *testing.T) {
	te := newTestEnv(t) // client 192.168.1.50 (peer: loopback)
	put := func(p *core.Principal, body any) (result, core.PolicyResult) {
		var out core.PolicyResult
		r := te.do(t, p, http.MethodPut, "/api/v1/admin/network/policy", body, &out)
		return r, out
	}
	if r, _ := put(te.admin(false), core.PolicyInput{Mode: "private"}); r.status != http.StatusForbidden || r.code != "elevation_required" {
		t.Fatalf("not elevated: %d %s", r.status, r.code)
	}
	for _, tc := range []struct {
		body  any
		field string
	}{
		{core.PolicyInput{Allow: []string{"192.168.1.0/24"}}, "mode"},
		{core.PolicyInput{Mode: "public"}, "mode"},
		{core.PolicyInput{Mode: "allowlist", Allow: []string{"192.168.1.0/33"}}, "allow"},
		{core.PolicyInput{Mode: "allowlist", Allow: []string{"192.168.1.0/24"}, Deny: []string{"x"}}, "deny"},
		{`{"mode":"any","extra":1}`, ""},
	} {
		if r, _ := put(te.admin(true), tc.body); r.status != http.StatusUnprocessableEntity || (tc.field != "" && r.field != tc.field) {
			t.Errorf("%v: %d %s %q", tc.body, r.status, r.code, r.field)
		}
	}
	r, _ := put(te.admin(true), core.PolicyInput{Mode: "allowlist", Allow: []string{"10.0.0.0/8"}})
	if r.status != http.StatusConflict || r.code != "conflict" {
		t.Fatalf("lockout: %d %s", r.status, r.body)
	}
	r, out := put(te.admin(true), core.PolicyInput{Mode: "allowlist", Allow: []string{"192.168.1.7", "192.168.1.0/24", "fd7a:115c:a1e0::/48"}})
	if r.status != http.StatusOK {
		t.Fatalf("admitting: %d %s", r.status, r.body)
	}
	if out.Policy.Mode != "allowlist" || !slices.Equal(out.Policy.Allow, []string{"192.168.1.7", "192.168.1.0/24", "fd7a:115c:a1e0::/48"}) ||
		out.Policy.Deny == nil || out.Warnings == nil {
		t.Fatalf("result %+v", out)
	}
	if !te.net.Allowed(netip.MustParseAddr("::ffff:192.168.1.99")) || te.net.Allowed(netip.MustParseAddr("10.0.0.1")) ||
		!te.net.Allowed(netip.MustParseAddr("127.0.0.1")) {
		t.Fatal("matcher not applied")
	}
	if got := te.st.Strings("network.allow_cidrs"); len(got) != 3 {
		t.Fatalf("settings not written: %v", got)
	}
	r, out = put(te.admin(true), core.PolicyInput{Mode: "any", Deny: []string{"192.168.1.50"}, Force: true})
	if r.status != http.StatusOK || !slices.ContainsFunc(out.Warnings, func(w string) bool { return strings.Contains(w, "192.168.1.50") }) ||
		!slices.ContainsFunc(out.Warnings, func(w string) bool { return strings.Contains(w, `"any"`) }) {
		t.Fatalf("forced: %d %+v", r.status, out)
	}
	var ok, denied int
	for _, e := range te.audit.actions(core.ActNetworkPolicy) {
		switch e.Outcome {
		case core.OutcomeSuccess:
			ok++
		case core.OutcomeDenied:
			denied++
		}
	}
	if ok != 2 || denied != 1 {
		t.Fatalf("network.policy audit: %d ok, %d denied", ok, denied)
	}
}

// TestPutPolicyReverseProxy checks the guard on the direct peer (a trusted
// proxy): the listener's allowlist sees the proxy's address, not the client's.
func TestPutPolicyReverseProxy(t *testing.T) {
	te := newTestEnv(t)
	te.who.Store(te.admin(true))
	send := func(body core.PolicyInput) *httptest.ResponseRecorder {
		raw, _ := json.Marshal(body)
		req := httptest.NewRequest(http.MethodPut, "/api/v1/admin/network/policy", bytes.NewReader(raw))
		req.RemoteAddr = "10.9.9.9:40000" // the proxy
		rec := httptest.NewRecorder()
		te.router.ServeHTTP(rec, req)
		return rec
	}
	rec := send(core.PolicyInput{Mode: "allowlist", Allow: []string{"192.168.1.0/24"}})
	if rec.Code != http.StatusConflict || !strings.Contains(rec.Body.String(), "10.9.9.9") {
		t.Fatalf("proxy lockout: %d %s", rec.Code, rec.Body)
	}
	rec = send(core.PolicyInput{Mode: "allowlist", Allow: []string{"192.168.1.0/24"}, Force: true})
	var out core.PolicyResult
	if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &out) != nil ||
		!slices.ContainsFunc(out.Warnings, func(w string) bool { return strings.Contains(w, "reverse proxy address 10.9.9.9") }) {
		t.Fatalf("forced: %d %s", rec.Code, rec.Body)
	}
	rec = send(core.PolicyInput{Mode: "allowlist", Allow: []string{"192.168.1.0/24", "10.9.9.9"}})
	if rec.Code != http.StatusOK {
		t.Fatalf("admitting: %d %s", rec.Code, rec.Body)
	}
}

func TestMDNSRoutes(t *testing.T) {
	te := newTestEnv(t)
	var st core.MDNSStatus
	if r := te.do(t, te.admin(false), http.MethodGet, "/api/v1/admin/mdns", nil, &st); r.status != http.StatusOK || st.Name != "fileparcel.local" ||
		st.Interfaces == nil {
		t.Fatalf("status: %d %+v", r.status, st)
	}
	if r := te.do(t, te.admin(false), http.MethodPost, "/api/v1/admin/mdns/republish", map[string]any{}, &st); r.status != http.StatusOK ||
		te.mdns.republished.Load() != 1 || st.State != core.MDNSPublished {
		t.Fatalf("republish: %d %+v", r.status, st)
	}
	te.mdns.err = core.Errorf(core.ErrConflict, "mDNS publishing is not running")
	if r := te.do(t, te.admin(false), http.MethodPost, "/api/v1/admin/mdns/republish", nil, nil); r.status != http.StatusConflict {
		t.Fatalf("not running: %d", r.status)
	}
	te.mdns.err = errors.New("avahi: dbus exploded")
	if r := te.do(t, te.admin(false), http.MethodPost, "/api/v1/admin/mdns/republish", nil, nil); r.status != http.StatusServiceUnavailable ||
		!strings.Contains(r.msg, "dbus exploded") {
		t.Fatalf("backend failure: %d %q", r.status, r.msg)
	}
}

func TestNetworkURLs(t *testing.T) {
	te := newTestEnv(t)
	var urls []core.AccessURL
	if r := te.do(t, te.principal(core.RoleMember, false), http.MethodGet, "/api/v1/network/urls", nil, &urls); r.status != http.StatusOK ||
		len(urls) != 1 || !urls[0].Recommended {
		t.Fatalf("%d %+v", r.status, urls)
	}
}

func TestQRSVG(t *testing.T) {
	te := newTestEnv(t)
	member := te.principal(core.RoleMember, false)
	get := func(method, rawQuery string) result {
		return te.do(t, member, method, "/api/v1/qr.svg?"+rawQuery, nil, nil)
	}
	const text = "https://fileparcel.local:8443/s/SeCrEtToKeN"
	r := get(http.MethodGet, "data="+url.QueryEscape(text))
	if r.status != http.StatusOK || r.header.Get("Content-Type") != "image/svg+xml" ||
		r.header.Get("Content-Security-Policy") != httpx.CSPContent || r.header.Get("Cache-Control") != "private, no-store" ||
		r.header.Get("X-Content-Type-Options") != "nosniff" {
		t.Fatalf("%d %v", r.status, r.header)
	}
	want, _ := qr.SVG(text, qr.Options{Title: "QR code"})
	if !bytes.Equal(r.body, want) || !bytes.HasPrefix(r.body, []byte("<svg")) {
		t.Fatalf("body %.80s", r.body)
	}
	if bytes.Contains(r.body, []byte("SeCrEtToKeN")) || bytes.Contains(r.body, []byte("<script")) {
		t.Fatal("svg embeds the text")
	}
	if r := get(http.MethodHead, "data=hello"); r.status != http.StatusOK || len(r.body) != 0 {
		t.Fatalf("HEAD: %d %d bytes", r.status, len(r.body))
	}
	if r := get(http.MethodGet, "data="+strings.Repeat("a", qr.MaxLen)); r.status != http.StatusOK {
		t.Fatalf("max length: %d %s", r.status, r.body)
	}
	for _, q := range []string{"", "data=", "data=" + strings.Repeat("a", qr.MaxLen+1), "data=%ff%fe", "data=a&data=b"} {
		if r := get(http.MethodGet, q); r.status != http.StatusUnprocessableEntity || r.field != "data" {
			t.Errorf("%q: %d %s %q", q, r.status, r.code, r.field)
		}
	}
}

func TestMissingServices(t *testing.T) {
	d := &app.Deps{Env: &core.Env{Clock: core.SystemClock{}}}
	r := chi.NewRouter()
	r.Use(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			p := &core.Principal{UserID: "usr_a", Username: "a", Role: core.RoleAdmin, Via: core.ViaSession,
				AuthLevel: core.AuthLevelFull, ElevatedUntil: time.Now().Add(time.Hour)}
			next.ServeHTTP(w, req.WithContext(core.WithPrincipal(req.Context(), p)))
		})
	})
	Mount(r, d)
	for _, rt := range [][2]string{
		{http.MethodGet, "/admin/settings"}, {http.MethodPatch, "/admin/settings"}, {http.MethodDelete, "/admin/settings/x.y"},
		{http.MethodGet, "/admin/network"}, {http.MethodPut, "/admin/network/policy"}, {http.MethodGet, "/admin/mdns"},
		{http.MethodPost, "/admin/mdns/republish"}, {http.MethodGet, "/network/urls"},
	} {
		req := httptest.NewRequest(rt[0], rt[1], strings.NewReader(`{}`))
		rec := httptest.NewRecorder()
		r.ServeHTTP(rec, req)
		if rec.Code != http.StatusServiceUnavailable {
			t.Errorf("%s %s: %d %s", rt[0], rt[1], rec.Code, rec.Body)
		}
	}
}

func TestSensitive(t *testing.T) {
	for _, s := range []string{"auth", "network", "tls", "acme", "mtls", "keys", "backup", "server", "mdns", "email", "tailscale", "funnel"} {
		if !Sensitive(s) {
			t.Errorf("%s should be sensitive", s)
		}
	}
	for _, s := range []string{"general", "storage", "sharing", "audit", "ratelimit", ""} {
		if Sensitive(s) {
			t.Errorf("%s should not be sensitive", s)
		}
	}
}

// fakeNotify records Test calls and returns a canned error.
type fakeNotify struct {
	enabled bool
	to      []string
	err     error
}

func (n *fakeNotify) Enabled() bool                                     { return n.enabled }
func (n *fakeNotify) Send(context.Context, []string, string, any) error { return nil }
func (n *fakeNotify) Test(_ context.Context, to string) error           { n.to = append(n.to, to); return n.err }

func TestEmailTest(t *testing.T) {
	te := newTestEnv(t)
	admin := te.admin(false)

	// No notify service wired at all: 503, nothing sent.
	if res := te.do(t, admin, http.MethodPost, "/api/v1/admin/settings/email/test",
		core.EmailTestInput{To: "a@example.com"}, nil); res.status != http.StatusServiceUnavailable {
		t.Fatalf("without a notify service: %d %s", res.status, res.body)
	}

	n := &fakeNotify{enabled: true}
	te.d.Notify = n

	// Missing address: 422 on the "to" field, and Test is not called.
	for _, body := range []any{core.EmailTestInput{}, core.EmailTestInput{To: "   "}} {
		res := te.do(t, admin, http.MethodPost, "/api/v1/admin/settings/email/test", body, nil)
		if res.status != http.StatusUnprocessableEntity || res.field != "to" {
			t.Fatalf("empty address: %d %s %s", res.status, res.code, res.field)
		}
	}
	if len(n.to) != 0 {
		t.Fatalf("Test called for an empty address: %v", n.to)
	}

	// Success: 204 and the address is passed through unchanged.
	if res := te.do(t, admin, http.MethodPost, "/api/v1/admin/settings/email/test",
		core.EmailTestInput{To: "Admin@Example.com"}, nil); res.status != http.StatusNoContent || len(res.body) != 0 {
		t.Fatalf("send: %d %s", res.status, res.body)
	}
	if len(n.to) != 1 || n.to[0] != "Admin@Example.com" {
		t.Fatalf("recipients %v", n.to)
	}

	// The service's error reaches the client unchanged (SMTP failure → 503).
	n.err = core.Errorf(core.ErrUnavailable, "sending the test e-mail failed: dial tcp: refused")
	res := te.do(t, admin, http.MethodPost, "/api/v1/admin/settings/email/test",
		core.EmailTestInput{To: "a@example.com"}, nil)
	if res.status != http.StatusServiceUnavailable || !strings.Contains(res.msg, "dial tcp") {
		t.Fatalf("smtp failure: %d %q", res.status, res.msg)
	}

	// A bad address is the service's 422.
	n.err = core.Invalid("to", "not an e-mail address")
	if res := te.do(t, admin, http.MethodPost, "/api/v1/admin/settings/email/test",
		core.EmailTestInput{To: "nope"}, nil); res.status != http.StatusUnprocessableEntity {
		t.Fatalf("bad address: %d", res.status)
	}
}

// fakeCertsWithConstraints answers the optional interface the settings API
// uses to warn about names the local CA may not sign.
type fakeCertsWithConstraints struct {
	core.Certs
	unsignable []string
}

func (f *fakeCertsWithConstraints) UnsignableNames(names []string) []string {
	var out []string
	for _, n := range names {
		if slices.Contains(f.unsignable, n) {
			out = append(out, n)
		}
	}
	return out
}

// Adding a name the local CA may not sign to tls.extra_sans (or
// network.extra_hosts) is accepted and applied, but the leaf silently drops
// it: nothing is reissued, no error is raised, and the access URLs and the
// strict Host check keep advertising a name HTTPS does not cover. The PATCH
// response says so.
func TestPatchSettingsWarnsAboutUncoveredNames(t *testing.T) {
	te := newTestEnv(t)
	te.d.Certs = &fakeCertsWithConstraints{unsignable: []string{"files.example.org"}}

	var res core.SettingsResult
	body := map[string]any{"network.extra_hosts": []string{"files.example.org", "nas.local"}}
	if r := te.do(t, te.admin(true), http.MethodPatch, "/api/v1/admin/settings", body, &res); r.status != http.StatusOK {
		t.Fatalf("patch: %d %s", r.status, r.body)
	}
	if !slices.Equal(res.Applied, []string{"network.extra_hosts"}) {
		t.Fatalf("applied %v", res.Applied)
	}
	if len(res.Warnings) != 1 || !strings.Contains(res.Warnings[0], "files.example.org") {
		t.Fatalf("warnings %v", res.Warnings)
	}
	if strings.Contains(res.Warnings[0], "nas.local") {
		t.Fatalf("a covered name was reported: %v", res.Warnings)
	}

	// A change the certificate can follow warns about nothing.
	res.Warnings = nil
	body = map[string]any{"network.extra_hosts": []string{"nas.local"}}
	if r := te.do(t, te.admin(true), http.MethodPatch, "/api/v1/admin/settings", body, &res); r.status != http.StatusOK {
		t.Fatalf("patch: %d %s", r.status, r.body)
	}
	if len(res.Warnings) != 0 {
		t.Fatalf("unexpected warnings %v", res.Warnings)
	}
}
