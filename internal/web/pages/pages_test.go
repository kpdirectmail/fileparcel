package pages

import (
	"context"
	"encoding/json"
	"html"
	"io"
	"log/slog"
	"math"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"testing/fstest"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"

	"fileparcel/internal/app"
	"fileparcel/internal/buildinfo"
	"fileparcel/internal/config"
	"fileparcel/internal/core"
	"fileparcel/internal/db"
	"fileparcel/internal/web/mw"
	"fileparcel/internal/web/static"
)

// ---------- fakes (embed the interface; unimplemented methods panic) ----------

type fakeSettings struct {
	core.Settings
	mu   sync.Mutex
	vals map[string]any
}

func (s *fakeSettings) get(k string) (any, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	v, ok := s.vals[k]
	return v, ok
}
func (s *fakeSettings) set(k string, v any) { s.mu.Lock(); s.vals[k] = v; s.mu.Unlock() }
func (s *fakeSettings) Raw(k string) (json.RawMessage, error) {
	v, ok := s.get(k)
	if !ok {
		return nil, core.ErrNotFound
	}
	b, _ := json.Marshal(v)
	return b, nil
}
func (s *fakeSettings) Bool(k string) bool     { v, _ := s.get(k); b, _ := v.(bool); return b }
func (s *fakeSettings) String(k string) string { v, _ := s.get(k); x, _ := v.(string); return x }
func (s *fakeSettings) Int(k string) int64 {
	switch v, _ := s.get(k); x := v.(type) {
	case int:
		return int64(x)
	case int64:
		return x
	}
	return 0
}
func (s *fakeSettings) Strings(k string) []string {
	v, _ := s.get(k)
	x, _ := v.([]string)
	return x
}

type fakeUsers struct {
	core.Users
	count int
	users map[string]*core.User
}

func (u *fakeUsers) Count(ctx context.Context) (int, error) { return u.count, nil }
func (u *fakeUsers) Get(ctx context.Context, id string) (*core.User, error) {
	if x, ok := u.users[id]; ok {
		return x, nil
	}
	return nil, core.ErrNotFound
}

// fakeAuth builds session principals the way package auth does: the role
// and its permissions come from the stored account (usr_1), with
// sharing.allow_guests_share folded in for built-in guests.
type fakeAuth struct {
	core.Auth
	users *fakeUsers
	s     *fakeSettings
}

// Authenticate: cookie "s" = "full" | "mfa" | "mfa-guest" | "enroll" →
// session principals of usr_1 ("mfa-guest": as a guest, whatever is stored).
func (a fakeAuth) Authenticate(r *http.Request) (*core.Principal, error) {
	c, err := r.Cookie("s")
	if err != nil {
		if r.Header.Get("Authorization") != "" {
			return nil, core.ErrUnauthorized
		}
		return nil, nil
	}
	u := a.users.users["usr_1"]
	p := &core.Principal{UserID: u.ID, Username: u.Username, Role: u.Role, RoleID: u.RoleID, RoleName: u.RoleName,
		Via: core.ViaSession, AuthLevel: core.AuthLevelFull}
	switch c.Value {
	case "mfa":
		p.AuthLevel = core.AuthLevelPassword
	case "mfa-guest":
		p.AuthLevel, p.Role, p.RoleID, p.RoleName = core.AuthLevelPassword, core.RoleGuest, "", ""
	case "enroll":
		p.EnrollRequired = true
	case "full":
	default:
		return nil, nil
	}
	if p.RoleID == "" {
		p.RoleID, p.RoleName = string(p.Role), core.BuiltinRoleName(p.Role)
	}
	p.SetCaps(core.EffectiveRoleCaps(p.Role, p.RoleID, u.Permissions, a.s.Bool("sharing.allow_guests_share")))
	return p, nil
}
func (fakeAuth) CSRFToken(p *core.Principal) string { return "csrf-" + p.UserID }

type fakeKeys struct {
	core.Keys
	state core.KeyState
}

func (k *fakeKeys) State() core.KeyState { return k.state }

type fakeCerts struct{ core.Certs }

func (fakeCerts) Fingerprint() string { return "AB:CD:EF" }

type fakeNet struct{ core.Network }

// Hostnames and IPs back knownHost (routes.go), which decides whether the
// request's Host header may be echoed into a QR code or security.txt.
func (fakeNet) Hostnames() []string { return []string{"fileparcel.local", "box.local", "example.test"} }

func (fakeNet) IPs() []netip.Addr { return []netip.Addr{netip.MustParseAddr("192.168.1.10")} }

func (fakeNet) URLs(ctx context.Context) ([]core.AccessURL, error) {
	return []core.AccessURL{
		{URL: "https://192.168.1.10:8443/", Kind: core.URLKindIP, Recommended: true},
		{URL: "https://fileparcel.local:8443/", Kind: core.URLKindMDNS, Recommended: true},
	}, nil
}

type fakeMDNS struct{ core.MDNS }

func (fakeMDNS) Name() string { return "box.local" }

type env struct {
	d     *app.Deps
	s     *fakeSettings
	users *fakeUsers
	keys  *fakeKeys
	h     http.Handler
}

func newEnv(t *testing.T) *env {
	t.Helper()
	s := &fakeSettings{vals: map[string]any{}}
	users := &fakeUsers{count: 1, users: map[string]*core.User{
		"usr_1": {ID: "usr_1", Username: "alice", DisplayName: "Alice", Role: core.RoleMember,
			Prefs: json.RawMessage(`{"theme":"dark"}`)},
	}}
	keys := &fakeKeys{state: core.KeyStateUnlocked}
	e := &core.Env{Clock: core.SystemClock{}, Log: slog.New(slog.NewTextHandler(io.Discard, nil)),
		Config: config.Default("0123456789abcdef0123456789abcdef"), Settings: s, Keys: keys,
		Build: buildinfo.Info{Version: "v42"}}
	d := &app.Deps{Env: e, Users: users, Auth: fakeAuth{users: users, s: s}, Certs: fakeCerts{}, Network: fakeNet{}, MDNS: fakeMDNS{}}
	r := chi.NewRouter()
	r.Use(mw.Inject(d), middleware.GetHead, mw.RequestID, mw.ResolveClientIP, mw.SecurityHeaders, mw.SealedGate)
	MountRoot(r, d)
	static.MountRoot(r, d)
	return &env{d: d, s: s, users: users, keys: keys, h: r}
}

func (e *env) do(t *testing.T, method, target string, hdr map[string]string, cookie string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, target, nil)
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	if cookie != "" {
		req.AddCookie(&http.Cookie{Name: "s", Value: cookie})
	}
	rec := httptest.NewRecorder()
	e.h.ServeHTTP(rec, req)
	return rec
}

var bootRe = regexp.MustCompile(`(?s)<script type="application/json" id="fp-boot">(.*?)</script>`)

// bootOf extracts and decodes the #fp-boot JSON of a rendered page.
func bootOf(t *testing.T, body string) map[string]any {
	t.Helper()
	m := bootRe.FindStringSubmatch(body)
	if m == nil {
		t.Fatalf("no fp-boot in %q", body[:min(len(body), 300)])
	}
	var v map[string]any
	if err := json.Unmarshal([]byte(m[1]), &v); err != nil {
		t.Fatalf("boot JSON %q: %v", m[1], err)
	}
	return v
}

// ---------- tests ----------

func TestRedirects(t *testing.T) {
	e := newEnv(t)
	cases := []struct {
		name, path, cookie string
		setup              func()
		want               string
	}{
		{"root anonymous", "/", "", nil, "/login"},
		{"root signed in", "/", "full", nil, "/files"},
		{"root mfa pending", "/", "mfa", nil, "/login"},
		{"root no users", "/", "", func() { e.users.count = 0 }, "/setup"},
		{"root locked", "/", "full", func() { e.keys.state = core.KeyStateLocked }, "/unlock"},
		{"spa anonymous", "/files/abc?x=1", "", nil, "/login?next=%2Ffiles%2Fabc%3Fx%3D1"},
		{"spa mfa pending", "/admin/users", "mfa", nil, "/login?next=%2Fadmin%2Fusers"},
		{"spa no users", "/files", "", func() { e.users.count = 0 }, "/setup"},
		{"spa locked", "/files", "full", func() { e.keys.state = core.KeyStateLocked }, "/unlock?next=%2Ffiles"},
		{"login signed in", "/login?next=/shared", "full", nil, "/shared"},
		{"login signed in evil next", "/login?next=//evil.example/", "full", nil, "/files"},
		{"login no users", "/login", "", func() { e.users.count = 0 }, "/setup"},
		{"setup with users", "/setup", "", nil, "/login"},
		{"unlock while unlocked", "/unlock?next=/files/x", "", nil, "/files/x"},
		{"unlock while unlocked evil", "/unlock?next=https://evil.example", "", nil, "/"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			e.users.count, e.keys.state = 1, core.KeyStateUnlocked
			if c.setup != nil {
				c.setup()
			}
			rec := e.do(t, "GET", c.path, nil, c.cookie)
			if rec.Code != http.StatusSeeOther {
				t.Fatalf("status %d, body %q", rec.Code, rec.Body.String())
			}
			if got := rec.Header().Get("Location"); got != c.want {
				t.Fatalf("Location %q, want %q", got, c.want)
			}
		})
	}
}

func TestPagesRender(t *testing.T) {
	e := newEnv(t)
	for _, c := range []struct {
		path, cookie, page string
		setup              func()
	}{
		{"/files", "full", "app", nil},
		{"/files/nod_x/y", "full", "app", nil},
		{"/settings/security", "enroll", "app", nil},
		{"/admin", "full", "app", nil},
		{"/login", "", "login", nil},
		{"/login", "mfa", "login", nil},
		{"/setup", "", "setup", func() { e.users.count = 0 }},
		{"/unlock", "", "unlock", func() { e.keys.state = core.KeyStateLocked }},
		{"/trust", "", "trust", nil},
		{"/invite/abcdefgh12345678", "", "invite", nil},
	} {
		e.users.count, e.keys.state = 1, core.KeyStateUnlocked
		if c.setup != nil {
			c.setup()
		}
		rec := e.do(t, "GET", c.path, nil, c.cookie)
		if rec.Code != 200 {
			t.Fatalf("%s: %d %q", c.path, rec.Code, rec.Header().Get("Location"))
		}
		if err := mw.CheckSecurityHeaders(rec.Header(), mw.HeadersPage); err != nil {
			t.Errorf("%s: %v", c.path, err)
		}
		if ct := rec.Header().Get("Content-Type"); ct != "text/html; charset=utf-8" {
			t.Errorf("%s: content type %q", c.path, ct)
		}
		b := bootOf(t, rec.Body.String())
		if b["page"] != c.page || b["asset_base"] != static.AssetBase() || b["version"] != "v42" ||
			b["instance"] != DefaultInstanceName || b["rp_id"] != "box.local" {
			t.Errorf("%s: boot %v", c.path, b)
		}
		if !strings.Contains(rec.Body.String(), `data-page="`+c.page+`"`) {
			t.Errorf("%s: data-page missing", c.path)
		}
	}
	// HEAD reaches the GET handler (net/http drops the body).
	if rec := e.do(t, "HEAD", "/login", nil, ""); rec.Code != 200 {
		t.Fatalf("HEAD /login: %d", rec.Code)
	}
}

// boot.rp_id must be normalised like everywhere else: the browser compares it
// against location.hostname, which is always lower case, so a mixed-case
// auth.webauthn_rp_id would switch the whole passkey UI off at an address
// that actually matches.
func TestBootRPIDNormalized(t *testing.T) {
	cases := map[string]string{"LocalHost": "localhost", "Box.Local.": "box.local", " box.local ": "box.local"}
	for set, want := range cases {
		e := newEnv(t)
		e.s.set("auth.webauthn_rp_id", set)
		if got := bootOf(t, e.do(t, "GET", "/login", nil, "").Body.String())["rp_id"]; got != want {
			t.Errorf("rp_id for %q: got %v, want %q", set, got, want)
		}
	}
	// No setting: the mDNS name and the configured name are normalised too.
	e := newEnv(t)
	e.d.Config.Server.Name = "Box"
	e.d.MDNS = nil
	if got := bootOf(t, e.do(t, "GET", "/login", nil, "").Body.String())["rp_id"]; got != "box.local" {
		t.Errorf("rp_id from server.name: got %v", got)
	}
}

func TestBootData(t *testing.T) {
	e := newEnv(t)
	e.s.set(KeyInstanceName, "Home Box")
	e.s.set(KeyDefaultView, "grid")
	e.s.set("sharing.links_enabled", false)
	rec := e.do(t, "GET", "/files", nil, "full")
	b := bootOf(t, rec.Body.String())
	if b["csrf"] != "csrf-usr_1" || b["instance"] != "Home Box" || b["keys_state"] != "unlocked" {
		t.Fatalf("boot %v", b)
	}
	u, _ := b["user"].(map[string]any)
	if u["username"] != "alice" || u["display_name"] != "Alice" || u["role"] != "member" {
		t.Fatalf("user %v", u)
	}
	f, _ := b["features"].(map[string]any)
	if f["links"] != false || f["requests"] != true || f["passkeys"] != true {
		t.Fatalf("features %v", f)
	}
	ui, _ := b["ui"].(map[string]any)
	if ui["default_view"] != "grid" || ui["default_theme"] != "system" {
		t.Fatalf("ui %v", ui)
	}
	// The user's theme preference wins over the default, and the browser bar
	// (theme-color) follows it whatever the OS scheme.
	if !strings.Contains(rec.Body.String(), `data-theme="dark"`) {
		t.Fatal("prefs theme not applied")
	}
	themeColors := func(body, light, dark string) {
		t.Helper()
		for _, want := range []string{
			`<meta name="theme-color" content="` + light + `" media="(prefers-color-scheme: light)">`,
			`<meta name="theme-color" content="` + dark + `" media="(prefers-color-scheme: dark)">`,
		} {
			if !strings.Contains(body, want) {
				t.Errorf("missing %s", want)
			}
		}
	}
	themeColors(rec.Body.String(), "#101419", "#101419")
	themeColors(e.do(t, "GET", "/login", nil, "").Body.String(), "#fbf9f5", "#101419") // system
	e.s.set(KeyDefaultTheme, "light")
	themeColors(e.do(t, "GET", "/login", nil, "").Body.String(), "#fbf9f5", "#fbf9f5")
	e.s.set(KeyDefaultTheme, "system")
	if !strings.Contains(rec.Body.String(), "<title>Home Box</title>") {
		t.Fatal("instance name missing from title")
	}
	// Anonymous: no user, no CSRF.
	b = bootOf(t, e.do(t, "GET", "/login", nil, "").Body.String())
	if b["user"] != nil || b["csrf"] != "" {
		t.Fatalf("anonymous boot %v", b)
	}
	// MFA pending: user flagged, CSRF present (the login page needs it for /auth/totp).
	b = bootOf(t, e.do(t, "GET", "/login", nil, "mfa").Body.String())
	u, _ = b["user"].(map[string]any)
	if u["mfa_pending"] != true || b["csrf"] == "" {
		t.Fatalf("mfa boot %v", b)
	}
	// ... but no role, permissions, address or prefs before the second
	// factor (as GET /me).
	for _, k := range []string{"role", "role_id", "role_name", "permissions", "staff", "space_id", "email", "prefs",
		"display_name"} {
		if _, ok := u[k]; ok {
			t.Fatalf("mfa boot user has %q: %v", k, u)
		}
	}
	// Guests get no links/requests unless allowed.
	e.users.users["usr_1"].Role = core.RoleGuest
	e.s.set("sharing.links_enabled", true)
	f = bootOf(t, e.do(t, "GET", "/files", nil, "full").Body.String())["features"].(map[string]any)
	if f["links"] != false || f["requests"] != false {
		t.Fatalf("guest features %v", f)
	}
	// The permission flags do not reveal a guest before the second factor:
	// they are off for every pending session.
	for _, cookie := range []string{"mfa-guest", "mfa"} {
		b = bootOf(t, e.do(t, "GET", "/login", nil, cookie).Body.String())
		if f, _ := b["features"].(map[string]any); f["links"] != false || f["requests"] != false ||
			f["directory"] != false || f["tokens"] != false || f["passkeys"] != true {
			t.Fatalf("%s features %v", cookie, b["features"])
		}
	}
	e.s.set("sharing.allow_guests_share", true)
	f = bootOf(t, e.do(t, "GET", "/files", nil, "full").Body.String())["features"].(map[string]any)
	if f["links"] != true {
		t.Fatalf("guest features allowed %v", f)
	}
	// An invalid instance name falls back to the default.
	e.s.set(KeyInstanceName, "bad\x00name")
	if b := bootOf(t, e.do(t, "GET", "/login", nil, "").Body.String()); b["instance"] != DefaultInstanceName {
		t.Fatalf("instance %v", b["instance"])
	}
}

func TestBootEscaping(t *testing.T) {
	e := newEnv(t)
	evil := "</script><script>alert(1)</script>\u2028<!--&\"'"
	e.users.users["usr_1"].DisplayName = evil
	e.s.set(KeyInstanceName, "Box <b>")
	rec := e.do(t, "GET", "/files", nil, "full")
	body := rec.Body.String()
	if strings.Contains(body, "<script>alert(1)") || strings.Contains(body, "</script><script>alert") {
		t.Fatalf("script injection in page: %s", body)
	}
	if strings.Contains(body, "<b>") {
		t.Fatal("instance name not escaped")
	}
	if strings.Contains(body, "\u2028") {
		t.Fatal("U+2028 not escaped")
	}
	b := bootOf(t, body)
	u := b["user"].(map[string]any)
	if u["display_name"] != evil {
		t.Fatalf("display name round trip: %q", u["display_name"])
	}
	// Data passed by other packages (e.g. share titles) is escaped too. The
	// unrelated context value checks that Inject does not trip over one.
	req := httptest.NewRequest("GET", "/s/x", nil)
	req = req.WithContext(context.WithValue(req.Context(), unrelatedCtxKey{}, nil))
	rr := httptest.NewRecorder()
	mw.Inject(e.d)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		RenderTitled(w, r, "share", evil, map[string]any{"title": evil})
	})).ServeHTTP(rr, req)
	if strings.Contains(rr.Body.String(), "<script>alert(1)") {
		t.Fatal("share data not escaped")
	}
	if got := bootOf(t, rr.Body.String())["data"].(map[string]any)["title"]; got != evil {
		t.Fatalf("share title %q", got)
	}
	if !strings.Contains(rr.Body.String(), html.EscapeString("</script>")) {
		t.Fatal("title not HTML-escaped")
	}
}

func TestRenderErrors(t *testing.T) {
	e := newEnv(t)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/x", nil)
	mw.Inject(e.d)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		Render(w, r, "no-such-page", nil)
	})).ServeHTTP(rec, req)
	if rec.Code != 500 || strings.Contains(rec.Body.String(), "no-such-page") {
		t.Fatalf("missing template: %d %q", rec.Code, rec.Body.String())
	}
	rec = httptest.NewRecorder()
	Render(rec, req, "../etc/passwd", nil)
	if rec.Code != 500 {
		t.Fatalf("bad name: %d", rec.Code)
	}
	// Without deps (outside the router) rendering still works with defaults.
	rec = httptest.NewRecorder()
	Render(rec, httptest.NewRequest("GET", "/login", nil), "login", nil)
	if rec.Code != 200 || bootOf(t, rec.Body.String())["instance"] != DefaultInstanceName {
		t.Fatalf("no deps: %d", rec.Code)
	}
}

// RenderStatus marks pages noindex but must not weaken a stricter value set
// by an outer middleware (the public share group adds noarchive).
func TestRobotsTag(t *testing.T) {
	newEnv(t)
	req := httptest.NewRequest("GET", "/login", nil)
	rec := httptest.NewRecorder()
	Render(rec, req, "login", nil)
	if got := rec.Header().Get("X-Robots-Tag"); got != "noindex, nofollow" {
		t.Errorf("default X-Robots-Tag = %q", got)
	}
	const strict = "noindex, nofollow, noarchive"
	rec = httptest.NewRecorder()
	rec.Header().Set("X-Robots-Tag", strict)
	Render(rec, req, "login", nil)
	if got := rec.Header().Get("X-Robots-Tag"); got != strict {
		t.Errorf("page X-Robots-Tag = %q, want the outer %q", got, strict)
	}
	// The generic 404 (an unknown share token lands here) keeps it too.
	rec = httptest.NewRecorder()
	rec.Header().Set("X-Robots-Tag", strict)
	NotFound(rec, req)
	if rec.Code != 404 {
		t.Fatalf("404: %d", rec.Code)
	}
	if got := rec.Header().Get("X-Robots-Tag"); got != strict {
		t.Errorf("404 X-Robots-Tag = %q, want the outer %q", got, strict)
	}
}

func TestNotFound(t *testing.T) {
	e := newEnv(t)
	rec := e.do(t, "GET", "/nope", nil, "")
	if rec.Code != 404 || !strings.Contains(rec.Body.String(), `data-page="error"`) {
		t.Fatalf("404 page: %d", rec.Code)
	}
	d := bootOf(t, rec.Body.String())["data"].(map[string]any)
	if d["status"] != float64(404) || d["code"] != "not_found" || d["request_id"] == "" {
		t.Fatalf("404 data %v", d)
	}
	rec = e.do(t, "GET", "/api/nope", nil, "")
	if rec.Code != 404 || !strings.Contains(rec.Body.String(), `"not_found"`) || !strings.HasPrefix(rec.Header().Get("Content-Type"), "application/json") {
		t.Fatalf("api 404: %d %q", rec.Code, rec.Body.String())
	}
	for _, p := range []string{"/invite/short", "/invite/has%20space12345", "/invite/" + strings.Repeat("a", 300)} {
		if rec := e.do(t, "GET", p, nil, ""); rec.Code != 404 {
			t.Errorf("%s: %d", p, rec.Code)
		}
	}
	b := bootOf(t, e.do(t, "GET", "/invite/Tok_en-12345678", nil, "").Body.String())
	if b["data"].(map[string]any)["token"] != "Tok_en-12345678" {
		t.Fatalf("invite token %v", b["data"])
	}
}

func TestTrustPage(t *testing.T) {
	e := newEnv(t)
	req := httptest.NewRequest("GET", "/trust", nil)
	req.RemoteAddr = "127.0.0.1:5555"
	rec := httptest.NewRecorder()
	e.h.ServeHTTP(rec, req)
	d := bootOf(t, rec.Body.String())["data"].(map[string]any)
	if d["fingerprint"] != "AB:CD:EF" || d["urls"] == nil || d["qr_target"] != "https://fileparcel.local:8443/trust" ||
		!strings.HasPrefix(d["qr"].(string), "data:image/svg+xml;base64,") {
		t.Fatalf("loopback trust data %v", d)
	}
	// Remote visitors never see the URL list; the QR points at the host they used.
	req = httptest.NewRequest("GET", "/trust", nil)
	req.RemoteAddr = "192.168.1.20:5555"
	req.Host = "192.168.1.10:8443"
	rec = httptest.NewRecorder()
	e.h.ServeHTTP(rec, req)
	d = bootOf(t, rec.Body.String())["data"].(map[string]any)
	if d["urls"] != nil || d["qr_target"] != "https://192.168.1.10:8443/trust" {
		t.Fatalf("remote trust data %v", d)
	}
	req.Host = "evil host<>"
	rec = httptest.NewRecorder()
	e.h.ServeHTTP(rec, req)
	if d = bootOf(t, rec.Body.String())["data"].(map[string]any); d["qr"] != nil {
		t.Fatalf("invalid host produced a QR: %v", d)
	}
}

func TestHealth(t *testing.T) {
	e := newEnv(t)
	rec := e.do(t, "GET", "/healthz", nil, "")
	if rec.Code != 200 || rec.Body.String() != "ok\n" {
		t.Fatalf("healthz %d %q", rec.Code, rec.Body.String())
	}
	// readyz without a DB → 503.
	if rec := e.do(t, "GET", "/readyz", nil, ""); rec.Code != 503 {
		t.Fatalf("readyz without db: %d", rec.Code)
	}
	database, err := db.Open(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	e.d.DB = database
	if rec := e.do(t, "GET", "/readyz", nil, ""); rec.Code != 200 || rec.Body.String() != "ready\n" {
		t.Fatalf("readyz: %d %q", rec.Code, rec.Body.String())
	}
	e.keys.state = core.KeyStateLocked
	// /readyz stays reachable while sealed and reports the key state.
	if rec := e.do(t, "GET", "/readyz", nil, ""); rec.Code != 503 || !strings.Contains(rec.Body.String(), "locked") {
		t.Fatalf("readyz locked: %d %q", rec.Code, rec.Body.String())
	}
	if rec := e.do(t, "GET", "/healthz", nil, ""); rec.Code != 200 {
		t.Fatalf("healthz locked: %d", rec.Code)
	}
	database.Close()
	e.keys.state = core.KeyStateUnlocked
	if rec := e.do(t, "GET", "/readyz", nil, ""); rec.Code != 503 {
		t.Fatalf("readyz closed db: %d", rec.Code)
	}
}

func TestSmallRootFiles(t *testing.T) {
	e := newEnv(t)
	rec := e.do(t, "GET", "/robots.txt", nil, "")
	if rec.Body.String() != "User-agent: *\nDisallow: /\n" {
		t.Fatalf("robots %q", rec.Body.String())
	}
	req := httptest.NewRequest("GET", "/.well-known/security.txt", nil)
	req.Host = "box.local:8443"
	rr := httptest.NewRecorder()
	e.h.ServeHTTP(rr, req)
	body := rr.Body.String()
	if !strings.Contains(body, "Contact: https://box.local:8443/\n") || !strings.Contains(body, "Expires: ") ||
		!strings.Contains(body, "Canonical: https://box.local:8443/.well-known/security.txt") {
		t.Fatalf("security.txt %q", body)
	}
	// A Host header this instance does not answer to must never be echoed back.
	req = httptest.NewRequest("GET", "/.well-known/security.txt", nil)
	req.Host = "evil.example.com"
	rr = httptest.NewRecorder()
	e.h.ServeHTTP(rr, req)
	if strings.Contains(rr.Body.String(), "evil.example.com") {
		t.Fatalf("foreign Host echoed into security.txt: %q", rr.Body.String())
	}

	m := regexp.MustCompile(`Expires: (\S+)`).FindStringSubmatch(body)
	exp, err := time.Parse(time.RFC3339, m[1])
	if err != nil || exp.Before(time.Now()) || exp.After(time.Now().AddDate(1, 0, 0)) {
		t.Fatalf("expires %q", m[1])
	}
	e.d.Config.Server.PublicURL = "https://files.example.org/sub"
	rr = httptest.NewRecorder()
	e.h.ServeHTTP(rr, req)
	if !strings.Contains(rr.Body.String(), "Contact: https://files.example.org/\n") {
		t.Fatalf("security.txt public url %q", rr.Body.String())
	}
	rec = e.do(t, "GET", "/favicon.ico", nil, "")
	if rec.Code != 200 || (rec.Header().Get("Content-Type") != "image/png" && rec.Header().Get("Content-Type") != "image/svg+xml") ||
		rec.Header().Get("Cache-Control") != cacheDay {
		t.Fatalf("favicon %d %v", rec.Code, rec.Header())
	}
	rec = e.do(t, "POST", "/share-target", nil, "")
	if rec.Code != 303 || rec.Header().Get("Location") != "/files?upload=1" {
		t.Fatalf("share-target %d", rec.Code)
	}
	rec = e.do(t, "POST", "/share-target", map[string]string{"Sec-Fetch-Site": "cross-site"}, "")
	if rec.Code != 403 {
		t.Fatalf("cross-site share-target %d", rec.Code)
	}
}

func TestServiceWorkerAndManifest(t *testing.T) {
	e := newEnv(t)
	rec := e.do(t, "GET", "/sw.js", nil, "")
	if rec.Code != 200 {
		t.Fatalf("sw.js %d", rec.Code)
	}
	if rec.Header().Get("Cache-Control") != "no-cache" || rec.Header().Get("Content-Type") != "text/javascript; charset=utf-8" ||
		rec.Header().Get("ETag") == "" || rec.Header().Get("Service-Worker-Allowed") != "/" {
		t.Fatalf("sw.js headers %v", rec.Header())
	}
	if s := rec.Body.String(); strings.Contains(s, "'"+static.PlaceholderHash+"'") || !strings.Contains(s, static.Hash()) {
		t.Fatal("sw.js placeholder not substituted")
	}
	etag := rec.Header().Get("ETag")
	if rec := e.do(t, "GET", "/sw.js", map[string]string{"If-None-Match": etag}, ""); rec.Code != 304 {
		t.Fatalf("sw.js 304: %d", rec.Code)
	}

	e.s.set(KeyInstanceName, "My Family Parcel Box")
	e.s.set(KeyAccentColor, "#0a0")
	rec = e.do(t, "GET", "/manifest.webmanifest", nil, "")
	if rec.Code != 200 || rec.Header().Get("Content-Type") != "application/manifest+json" || rec.Header().Get("Cache-Control") != "no-cache" {
		t.Fatalf("manifest %d %v", rec.Code, rec.Header())
	}
	var m map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &m); err != nil {
		t.Fatal(err)
	}
	if m["name"] != "My Family Parcel Box" || m["short_name"] != "My Family Pa" || m["theme_color"] != "#00aa00" {
		t.Fatalf("manifest %v", m)
	}
	if strings.Contains(rec.Body.String(), static.PlaceholderBase) || !strings.Contains(rec.Body.String(), static.AssetBase()+"/icons/") {
		t.Fatal("manifest asset base not substituted")
	}
	// A settings change is reflected immediately.
	e.s.set(KeyInstanceName, "Other")
	rec = e.do(t, "GET", "/manifest.webmanifest", nil, "")
	_ = json.Unmarshal(rec.Body.Bytes(), &m)
	if m["name"] != "Other" || m["short_name"] != "Other" {
		t.Fatalf("manifest after change %v", m)
	}
}

func TestBuildManifest(t *testing.T) {
	blue, _ := ParseHexColor("#123456")
	if got := BuildManifest([]byte("not json"), "X", blue, true); string(got) != "not json" {
		t.Fatalf("invalid json changed: %q", got)
	}
	out := BuildManifest([]byte(`{"name":"FileParcel","short_name":"FP","theme_color":"#fff","icons":[{"src":"a","sizes":"1x1"}],"n":1.50}`), "Ünïcödé Instance Name", blue, false)
	var m map[string]any
	if err := json.Unmarshal(out, &m); err != nil {
		t.Fatal(err)
	}
	if m["name"] != "Ünïcödé Instance Name" || m["short_name"] != "Ünïcödé Inst" || m["theme_color"] != "#fff" || m["n"] != 1.5 {
		t.Fatalf("manifest %v", m)
	}
}

func TestThemeCSS(t *testing.T) {
	e := newEnv(t)
	rec := e.do(t, "GET", "/theme.css", nil, "")
	if rec.Code != 200 || rec.Body.String() != defaultCSS || rec.Header().Get("Content-Type") != "text/css; charset=utf-8" ||
		rec.Header().Get("Cache-Control") != "no-cache" {
		t.Fatalf("default theme %d %q %v", rec.Code, rec.Body.String(), rec.Header())
	}
	e.s.set(KeyAccentColor, "#D946EF")
	rec = e.do(t, "GET", "/theme.css", nil, "")
	body := rec.Body.String()
	for _, want := range []string{"--fp-brand: #d946ef;", "--fp-primary: light-dark(#d946ef, #", "--fp-on-primary: light-dark(", "--fp-accent-dark: #"} {
		if !strings.Contains(body, want) {
			t.Fatalf("theme css missing %q:\n%s", want, body)
		}
	}
	// Browsers without light-dark() keep a usable primary: the plain values
	// come first, every light-dark() only behind @supports (an unguarded one
	// would override tokens.css's fallback with a value invalid at use), and
	// the fallback tints follow the accent.
	const guard, notGuard = "@supports (color: light-dark(#000, #fff)) {", "@supports not (color: light-dark(#000, #fff)) {"
	plain, plainOn := strings.Index(body, "--fp-primary: #d946ef;"), strings.Index(body, "--fp-on-primary: #")
	g, ld := strings.Index(body, guard), strings.Index(body, "--fp-primary: light-dark(#d946ef, #")
	ng := strings.Index(body, notGuard)
	if plain < 0 || plainOn < 0 || g < 0 || ng < 0 || plain > g || plainOn > g || ld < g || ng < ld ||
		strings.Index(body, "light-dark(") != g+len("@supports (color: ") {
		t.Fatalf("light-dark() not guarded:\n%s", body)
	}
	fallback := body[ng:]
	for _, want := range []string{"--fp-primary-hover: #", "--fp-primary-soft: rgb(217 70 239 / 0.12);", "--fp-primary-text: #", "--fp-focus-ring: #"} {
		if !strings.Contains(fallback, want) {
			t.Fatalf("fallback tints missing %q:\n%s", want, body)
		}
	}
	if strings.Contains(fallback[len(notGuard):], "light-dark(") || strings.Contains(fallback, "color-mix(") {
		t.Fatalf("fallback block uses modern colour functions:\n%s", body)
	}
	if rec := e.do(t, "GET", "/theme.css", map[string]string{"If-None-Match": rec.Header().Get("ETag")}, ""); rec.Code != 304 {
		t.Fatalf("theme 304: %d", rec.Code)
	}
	// The default is the tokens.css brand (served as the design defaults);
	// any other colour, the former default #2563eb included, is generated.
	e.s.set(KeyAccentColor, DefaultAccentColor)
	if rec := e.do(t, "GET", "/theme.css", nil, ""); rec.Body.String() != defaultCSS {
		t.Fatalf("default accent: %q", rec.Body.String())
	}
	e.s.set(KeyAccentColor, "#2563eb")
	if rec := e.do(t, "GET", "/theme.css", nil, ""); !strings.Contains(rec.Body.String(), "--fp-brand: #2563eb;") {
		t.Fatalf("#2563eb accent: %q", rec.Body.String())
	}
	// Invalid values (settings validation would reject them) fall back to the defaults.
	e.s.set(KeyAccentColor, "red; } body { display:none")
	if rec := e.do(t, "GET", "/theme.css", nil, ""); rec.Body.String() != defaultCSS {
		t.Fatalf("invalid accent: %q", rec.Body.String())
	}
	// The theme is reachable while the keys are locked (the unlock page uses it).
	e.keys.state = core.KeyStateLocked
	if rec := e.do(t, "GET", "/theme.css", nil, ""); rec.Code != 200 {
		t.Fatalf("theme while locked: %d", rec.Code)
	}
}

// TestDefaultAccentIsBrand: ui.accent_color's default is the colour the UI
// shows while the setting is unchanged (/theme.css then sends nothing), so
// it must equal the tokens.css brand, its no-light-dark() fallback and the
// static manifest's theme_color.
func TestDefaultAccentIsBrand(t *testing.T) {
	if got := fromOKLCH(0.58, 0.16, 255*math.Pi/180).Hex(); got != DefaultAccentColor {
		t.Errorf("oklch(0.58 0.16 255) = %s, default accent %s", got, DefaultAccentColor)
	}
	tokens, ok := static.File("css/tokens.css")
	if !ok {
		t.Fatal("no css/tokens.css")
	}
	for _, want := range []string{"--fp-brand: oklch(0.58 0.16 255);", "--fp-primary: " + DefaultAccentColor + ";"} {
		if !strings.Contains(string(tokens), want) {
			t.Errorf("tokens.css lacks %q", want)
		}
	}
	e, ok := static.Templated(manifestFile)
	if !ok {
		t.Fatal("no manifest")
	}
	var m map[string]any
	if err := json.Unmarshal(e.Data, &m); err != nil {
		t.Fatal(err)
	}
	if m["theme_color"] != DefaultAccentColor {
		t.Errorf("manifest theme_color %v, default accent %s", m["theme_color"], DefaultAccentColor)
	}
}

func TestColorMath(t *testing.T) {
	for _, c := range []struct {
		in   string
		want string
		ok   bool
	}{
		{"#2563eb", "#2563eb", true}, {"#ABC", "#aabbcc", true}, {" #000000 ", "#000000", true},
		{"2563eb", "", false}, {"#12345", "", false}, {"#gggggg", "", false}, {"", "", false}, {"#1234567", "", false},
	} {
		got, err := ParseHexColor(c.in)
		if (err == nil) != c.ok || (c.ok && got.Hex() != c.want) {
			t.Errorf("%q: %v %v", c.in, got.Hex(), err)
		}
	}
	// Round trip through OKLab is lossless (within rounding).
	for _, hex := range []string{"#2563eb", "#000000", "#ffffff", "#d946ef", "#00aa00", "#7f7f7f", "#ffcc00"} {
		c, _ := ParseHexColor(hex)
		L, a, b := c.oklab()
		back := fromOKLCH(L, math.Hypot(a, b), math.Atan2(b, a))
		if back != c {
			t.Errorf("%s round trip → %s", hex, back.Hex())
		}
		dark := DarkVariant(c)
		if dl, _, _ := dark.oklab(); dl < 0.715 {
			t.Errorf("%s dark variant %s too dark (L=%.3f)", hex, dark.Hex(), dl)
		}
		for _, bg := range []RGB{c, dark} {
			if on := OnColor(bg); Contrast(on, bg) < 3 && Contrast(bg, onLight) > 3 {
				t.Errorf("%s: poor on-colour %s", bg.Hex(), on.Hex())
			}
		}
	}
	if r := Contrast(RGB{0, 0, 0}, RGB{255, 255, 255}); math.Abs(r-21) > 0.01 {
		t.Fatalf("contrast %v", r)
	}
	if OnColor(RGB{255, 255, 0}) != onDark || OnColor(RGB{0, 0, 128}) != onLight {
		t.Fatal("on colour choice")
	}
	// Light accents keep their hue in the dark variant.
	y, _ := ParseHexColor("#ffcc00")
	if DarkVariant(y) != y {
		t.Fatalf("light colour changed: %s", DarkVariant(y).Hex())
	}
}

func TestSafeNext(t *testing.T) {
	cases := map[string]string{
		"":                              "/f",
		"/files":                        "/files",
		"/files/a?b=c&d=%2F":            "/files/a?b=c&d=%2F",
		"//evil.example":                "/f",
		"/\\evil.example":               "/f",
		"https://evil.example/x":        "/f",
		"files":                         "/f",
		"/login":                        "/f",
		"/unlock?next=/x":               "/f",
		"/invite/tok":                   "/f",
		"/api/v1/me":                    "/f",
		"/a\nb":                         "/f",
		"/%2F%2Fevil":                   "/%2F%2Fevil",
		"/" + strings.Repeat("a", 3000): "/f",
	}
	for in, want := range cases {
		if got := SafeNext(in, "/f"); got != want {
			t.Errorf("SafeNext(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestTemplatePartials(t *testing.T) {
	old := templatesFS
	t.Cleanup(func() { templatesFS = old; resetTemplates() })
	templatesFS = fstest.MapFS{
		"templates/x.html":             {Data: []byte(`{{template "_hdr" .}}|{{template "foot" .}}|{{asset "a.js"}}|{{.Boot}}`)},
		"templates/_hdr.html":          {Data: []byte(`H:{{.Instance}}`)},
		"templates/partials/foot.html": {Data: []byte(`F:{{.Page}}`)},
		"templates/broken.html":        {Data: []byte(`{{`)},
	}
	resetTemplates()
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/x", nil)
	Render(rec, req, "x", map[string]any{"k": 1})
	if rec.Code != 200 || !strings.HasPrefix(rec.Body.String(), "H:FileParcel|F:x|"+static.Asset("a.js")+"|") {
		t.Fatalf("partials: %d %q", rec.Code, rec.Body.String())
	}
	rec = httptest.NewRecorder()
	Render(rec, req, "broken", nil)
	if rec.Code != 500 {
		t.Fatalf("broken template: %d", rec.Code)
	}
}

func TestSettingsValidation(t *testing.T) {
	for _, c := range []struct {
		v  string
		ok bool
	}{{"FileParcel", true}, {"", false}, {" x", false}, {"a\x01", false}, {strings.Repeat("x", 64), true}, {strings.Repeat("x", 65), false}} {
		if err := validateInstanceName(c.v); (err == nil) != c.ok {
			t.Errorf("instance %q: %v", c.v, err)
		}
	}
	for _, c := range []struct {
		v  string
		ok bool
	}{{"", true}, {"Hello\nworld", true}, {"bad\x00", false}, {strings.Repeat("x", 2001), false}} {
		if err := validateLoginMessage(c.v); (err == nil) != c.ok {
			t.Errorf("login message %q: %v", c.v, err)
		}
	}
}

func TestTrustTarget(t *testing.T) {
	if got := trustTarget([]core.AccessURL{{URL: "https://10.0.0.1:8443/", Kind: core.URLKindIP}}); got != "https://10.0.0.1:8443/trust" {
		t.Fatal(got)
	}
	if got := trustTarget([]core.AccessURL{{URL: "http://x/", Kind: core.URLKindIP}}); got != "" {
		t.Fatal(got)
	}
	if got := trustTarget([]core.AccessURL{{URL: "https://[fd00::1]:8443/", Kind: core.URLKindIP, Recommended: true}}); got != "https://[fd00::1]:8443/trust" {
		t.Fatal(got)
	}
	_ = netip.Addr{}
}

// unrelatedCtxKey is a context key no package looks for.
type unrelatedCtxKey struct{}
