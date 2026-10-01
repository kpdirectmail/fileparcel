package mw

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"fileparcel/internal/app"
	"fileparcel/internal/config"
	"fileparcel/internal/core"
	"fileparcel/internal/ratelimit"
	"fileparcel/internal/web/httpx"
)

// ---------- fakes (embed the interface; unimplemented methods panic) ----------

// fakeAuth authenticates "Bearer good" as a token principal and any request
// with cookie s=1 as a session principal; CSRF token "t0k" is valid.
type fakeAuth struct{ core.Auth }

func (fakeAuth) Authenticate(r *http.Request) (*core.Principal, error) {
	if r.Header.Get("Authorization") == "Bearer good" {
		return &core.Principal{UserID: "usr_t", Username: "tok", Role: core.RoleMember, Via: core.ViaToken, AuthLevel: 2, Scopes: []string{core.ScopeFilesRead}}, nil
	}
	if r.Header.Get("Authorization") != "" {
		return nil, core.ErrUnauthorized
	}
	if c, err := r.Cookie("s"); err == nil && c.Value == "1" {
		return &core.Principal{UserID: "usr_s", Username: "sess", Role: core.RoleAdmin, Via: core.ViaSession, AuthLevel: 2}, nil
	}
	return nil, nil
}
func (fakeAuth) CheckCSRF(p *core.Principal, tok string) bool { return tok == "t0k" }

type fakeKeys struct {
	core.Keys
	state core.KeyState
}

func (k fakeKeys) State() core.KeyState { return k.state }

type fakeUsers struct{ core.Users }

func (fakeUsers) GetByUsername(ctx context.Context, name string) (*core.User, error) {
	switch name {
	case "bob":
		return &core.User{ID: "usr_bob", Username: "bob", Role: core.RoleMember, Status: core.UserActive}, nil
	case "gone":
		return &core.User{ID: "usr_gone", Username: "gone", Role: core.RoleMember, Status: core.UserDisabled}, nil
	case "locked":
		return nil, core.ErrKeysLocked
	}
	return nil, core.ErrNotFound
}

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
func (s *fakeSettings) set(k string, v any) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.vals[k] = v
}
func (s *fakeSettings) Raw(k string) (json.RawMessage, error) {
	v, ok := s.get(k)
	if !ok {
		return nil, core.ErrNotFound
	}
	b, _ := json.Marshal(v)
	return b, nil
}
func (s *fakeSettings) Bool(k string) bool { v, _ := s.get(k); b, _ := v.(bool); return b }
func (s *fakeSettings) Int(k string) int64 {
	v, _ := s.get(k)
	switch x := v.(type) {
	case int:
		return int64(x)
	case int64:
		return x
	}
	return 0
}
func (s *fakeSettings) Duration(k string) time.Duration {
	v, _ := s.get(k)
	d, _ := v.(time.Duration)
	return d
}
func (s *fakeSettings) String(k string) string { v, _ := s.get(k); x, _ := v.(string); return x }
func (s *fakeSettings) Strings(k string) []string {
	v, _ := s.get(k)
	x, _ := v.([]string)
	return x
}

type fakeCerts struct {
	core.Certs
	public map[string]bool
}

func (c fakeCerts) PubliclyTrusted(name string) bool { return c.public[name] }

type fakeNet struct{ core.Network }

func (fakeNet) IPs() []netip.Addr {
	return []netip.Addr{netip.MustParseAddr("192.168.1.10"), netip.MustParseAddr("100.64.0.10"), netip.MustParseAddr("fd7a:115c:a1e0::1")}
}
func (fakeNet) Hostnames() []string { return []string{"myhost.local", "files.tail1234.ts.net"} }
func (n fakeNet) IsLocal(ip netip.Addr) bool {
	for _, a := range n.IPs() {
		if a == ip.Unmap() {
			return true
		}
	}
	return ip.IsLoopback()
}

type fakeMDNS struct{ core.MDNS }

func (fakeMDNS) Name() string { return "fileparcel.local" }

type testEnv struct {
	d    *app.Deps
	s    *fakeSettings
	logs *syncBuf
}

type syncBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuf) Write(p []byte) (int, error) { s.mu.Lock(); defer s.mu.Unlock(); return s.b.Write(p) }
func (s *syncBuf) String() string              { s.mu.Lock(); defer s.mu.Unlock(); return s.b.String() }

func newEnv(t *testing.T) *testEnv {
	t.Helper()
	logs := &syncBuf{}
	env := &core.Env{
		Clock:  core.SystemClock{},
		Log:    slog.New(slog.NewTextHandler(logs, &slog.HandlerOptions{Level: slog.LevelDebug})),
		Config: config.Default("test"),
	}
	s := &fakeSettings{vals: map[string]any{}}
	env.Settings = s
	env.Keys = fakeKeys{state: core.KeyStateUnlocked}
	lim, _ := ratelimit.New(env)
	t.Cleanup(func() { lim.Close() })
	d := &app.Deps{Env: env, Auth: fakeAuth{}, Users: fakeUsers{}, Limiter: lim,
		Certs: fakeCerts{public: map[string]bool{"files.example.org": true}}, Network: fakeNet{}, MDNS: fakeMDNS{}}
	return &testEnv{d: d, s: s, logs: logs}
}

func ok(w http.ResponseWriter, r *http.Request) {
	p := Principal(r)
	who := "anon"
	if p != nil {
		who = p.UserID + "/" + string(p.Via)
	}
	io.WriteString(w, who)
}

func serve(d *app.Deps, h http.Handler, r *http.Request) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	Inject(d)(RequestID(h)).ServeHTTP(rec, r)
	return rec
}

func code(t *testing.T, rec *httptest.ResponseRecorder) string {
	t.Helper()
	var er struct {
		Error struct {
			Code string `json:"code"`
		} `json:"error"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &er)
	return er.Error.Code
}

func withP(r *http.Request, p *core.Principal) *http.Request {
	return r.WithContext(core.WithPrincipal(r.Context(), p))
}

// ---------- tests ----------

func TestAuthenticateAndCSRF(t *testing.T) {
	e := newEnv(t)
	d := e.d
	h := Authenticate(CSRF(http.HandlerFunc(ok)))

	rec := serve(d, h, httptest.NewRequest("GET", "/api/v1/x", nil))
	if rec.Body.String() != "anon" {
		t.Fatalf("anonymous: %q", rec.Body.String())
	}
	r := httptest.NewRequest("GET", "/api/v1/x", nil)
	r.Header.Set("Authorization", "Bearer bad")
	if rec := serve(d, h, r); rec.Code != 401 || rec.Header().Get("WWW-Authenticate") == "" {
		t.Fatalf("bad bearer: %d %v", rec.Code, rec.Header())
	}
	// AuthenticateOptional never fails.
	if rec := serve(d, AuthenticateOptional(http.HandlerFunc(ok)), r); rec.Code != 200 || rec.Body.String() != "anon" {
		t.Fatalf("optional bad bearer: %d %q", rec.Code, rec.Body.String())
	}
	// Bearer POST: CSRF exempt, even cross-site.
	r = httptest.NewRequest("POST", "/api/v1/x", nil)
	r.Header.Set("Authorization", "Bearer good")
	r.Header.Set("Sec-Fetch-Site", "cross-site")
	if rec := serve(d, h, r); rec.Code != 200 || rec.Body.String() != "usr_t/token" {
		t.Fatalf("bearer post: %d %s", rec.Code, rec.Body.String())
	}
	// Session POST without token → 403; with token → 200; cross-site → 403.
	// A bad token has its own code (the web client re-reads the token and
	// retries once); a cross-origin block stays "forbidden" and is never retried.
	r = httptest.NewRequest("POST", "/api/v1/x", nil)
	r.AddCookie(&http.Cookie{Name: "s", Value: "1"})
	if rec := serve(d, h, r); rec.Code != 403 || code(t, rec) != "csrf_invalid" {
		t.Fatalf("session no csrf: %d %s", rec.Code, rec.Body.String())
	}
	r = httptest.NewRequest("POST", "/api/v1/x", nil)
	r.AddCookie(&http.Cookie{Name: "s", Value: "1"})
	r.Header.Set(HeaderCSRF, "wrong")
	if rec := serve(d, h, r); rec.Code != 403 || code(t, rec) != "csrf_invalid" {
		t.Fatalf("session wrong csrf: %d %s", rec.Code, rec.Body.String())
	}
	r.Header.Set(HeaderCSRF, "t0k")
	if rec := serve(d, h, r); rec.Code != 200 {
		t.Fatalf("session csrf ok: %d", rec.Code)
	}
	r2 := httptest.NewRequest("POST", "/api/v1/x", nil)
	r2.AddCookie(&http.Cookie{Name: "s", Value: "1"})
	r2.Header.Set(HeaderCSRF, "t0k")
	r2.Header.Set("Sec-Fetch-Site", "cross-site")
	if rec := serve(d, h, r2); rec.Code != 403 || code(t, rec) != "forbidden" {
		t.Fatalf("cross-site session POST: %d %s", rec.Code, rec.Body.String())
	}
	// Anonymous cross-site POST (login CSRF) is blocked; same-origin passes.
	r3 := httptest.NewRequest("POST", "/api/v1/auth/login", nil)
	r3.Header.Set("Sec-Fetch-Site", "cross-site")
	if rec := serve(d, h, r3); rec.Code != 403 || code(t, rec) != "forbidden" {
		t.Fatalf("anonymous cross-site POST: %d %s", rec.Code, rec.Body.String())
	}
	if rec := serve(d, h, httptest.NewRequest("POST", "/", nil)); rec.Code != 200 {
		t.Fatalf("anonymous same-origin POST: %d", rec.Code)
	}
	// GET never needs a token.
	r4 := httptest.NewRequest("GET", "/api/v1/x", nil)
	r4.AddCookie(&http.Cookie{Name: "s", Value: "1"})
	r4.Header.Set("Sec-Fetch-Site", "cross-site")
	if rec := serve(d, h, r4); rec.Code != 200 {
		t.Fatalf("cross-site GET: %d", rec.Code)
	}

	// Trusted in-process principal is kept; X-FP-As switches user.
	r = withP(httptest.NewRequest("POST", "/api/v1/x", nil), core.SystemPrincipal(core.ViaOffline))
	r.Header.Set("Sec-Fetch-Site", "cross-site")
	if rec := serve(d, h, r); rec.Body.String() != "/offline" {
		t.Fatalf("offline: %q", rec.Body.String())
	}
	r.Header.Set(HeaderActAs, "bob")
	var got *core.Principal
	cap := Authenticate(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { got = Principal(r) }))
	serve(d, cap, r)
	if got == nil || got.UserID != "usr_bob" || got.Via != core.ViaOffline || got.AuthLevel != core.AuthLevelFull || !got.Elevated(time.Now()) {
		t.Fatalf("as bob: %+v", got)
	}
	r.Header.Set(HeaderActAs, "nobody")
	if rec := serve(d, h, r); rec.Code != 404 {
		t.Fatalf("as nobody: %d", rec.Code)
	}
	// A disabled account cannot be acted as, even from a trusted caller.
	r.Header.Set(HeaderActAs, "gone")
	if rec := serve(d, h, r); rec.Code != 403 {
		t.Fatalf("as disabled: %d %s", rec.Code, rec.Body.String())
	}
	r.Header.Set(HeaderActAs, "locked")
	if rec := serve(d, h, r); rec.Code != 503 || code(t, rec) != "keys_locked" {
		t.Fatalf("as while locked: %d %s", rec.Code, code(t, rec))
	}
	// X-FP-As from the network is ignored (no trusted principal).
	r = httptest.NewRequest("GET", "/api/v1/x", nil)
	r.Header.Set(HeaderActAs, "bob")
	if rec := serve(d, h, r); rec.Body.String() != "anon" {
		t.Fatalf("network X-FP-As: %q", rec.Body.String())
	}
	// X-FP-As with a non-trusted pre-set principal is ignored too.
	r = withP(httptest.NewRequest("GET", "/api/v1/x", nil), &core.Principal{UserID: "usr_m", Via: core.ViaSession, AuthLevel: 2})
	r.Header.Set(HeaderActAs, "bob")
	if rec := serve(d, h, r); rec.Body.String() != "usr_m/session" {
		t.Fatalf("session X-FP-As: %q", rec.Body.String())
	}
}

func TestPrincipalMetadata(t *testing.T) {
	e := newEnv(t)
	var got *core.Principal
	h := ResolveClientIP(Authenticate(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { got = Principal(r) })))
	r := httptest.NewRequest("GET", "/api/v1/x", nil)
	r.AddCookie(&http.Cookie{Name: "s", Value: "1"})
	r.RemoteAddr = "[::ffff:192.168.1.20]:5555"
	r.Header.Set("User-Agent", "ua/1")
	rec := serve(e.d, h, r)
	if got == nil || got.IP.String() != "192.168.1.20" || got.UserAgent != "ua/1" || got.RequestID != rec.Header().Get(HeaderRequestID) {
		t.Fatalf("metadata: %+v", got)
	}
}

func TestGuards(t *testing.T) {
	e := newEnv(t)
	d := e.d
	now := time.Now()
	member := &core.Principal{UserID: "u", Role: core.RoleMember, Via: core.ViaSession, AuthLevel: 2}
	pending := &core.Principal{UserID: "u", Role: core.RoleMember, Via: core.ViaSession, AuthLevel: 1}
	pendingElev := &core.Principal{UserID: "u", Role: core.RoleAdmin, Via: core.ViaSession, AuthLevel: 1, ElevatedUntil: now.Add(time.Hour)}
	enroll := &core.Principal{UserID: "u", Role: core.RoleAdmin, Via: core.ViaSession, AuthLevel: 2, EnrollRequired: true}
	enrollTok := &core.Principal{UserID: "u", Role: core.RoleMember, Via: core.ViaToken, AuthLevel: 2, EnrollRequired: true, Scopes: []string{core.ScopeFilesRead}}
	mustChange := &core.Principal{UserID: "u", Role: core.RoleAdmin, Via: core.ViaSession, AuthLevel: 2, MustChangePassword: true}
	admin := &core.Principal{UserID: "a", Role: core.RoleAdmin, Via: core.ViaSession, AuthLevel: 2, ElevatedUntil: now.Add(time.Minute)}
	adminExpired := &core.Principal{UserID: "a", Role: core.RoleAdmin, Via: core.ViaSession, AuthLevel: 2, ElevatedUntil: now.Add(-time.Second)}
	adminTok := &core.Principal{UserID: "a", Role: core.RoleAdmin, Via: core.ViaToken, AuthLevel: 2, Scopes: []string{core.ScopeFilesRead}}
	adminTokFull := &core.Principal{UserID: "a", Role: core.RoleAdmin, Via: core.ViaToken, AuthLevel: 2, Scopes: []string{core.ScopeAdmin}}
	guest := &core.Principal{UserID: "g", Role: core.RoleGuest, Via: core.ViaSession, AuthLevel: 2}
	sys := core.SystemPrincipal(core.ViaSocket)
	off := core.SystemPrincipal(core.ViaOffline)

	type tc struct {
		mw   Middleware
		p    *core.Principal
		path string
		want int
		code string
	}
	cases := []tc{
		{RequireAuth, nil, "/x", 401, "unauthorized"},
		{RequireAuth, member, "/x", 200, ""},
		// AuthLevel 1 (second factor pending): only /auth/* and GET /me, /me/mfa.
		{RequireAuth, pending, "/x", 401, "mfa_required"},
		{RequireAuth, pending, "/api/v1/auth/logout", 200, ""},
		{RequireAuth, pending, "/api/v1/auth/totp", 200, ""},
		{RequireAuth, pending, "/api/v1/me", 200, ""},
		{RequireAuth, pending, "HEAD /api/v1/me", 200, ""},
		{RequireAuth, pending, "/api/v1/me/mfa", 200, ""},
		{RequireAuth, pending, "/api/v1/me/sessions", 401, "mfa_required"},
		{RequireAuth, pending, "POST /api/v1/me/totp/begin", 401, "mfa_required"},
		{RequireAuth, pending, "POST /api/v1/me/passkeys/begin", 401, "mfa_required"},
		{RequireAuth, pending, "PATCH /api/v1/me", 401, "mfa_required"},
		{RequireFull, nil, "/x", 401, "unauthorized"},
		{RequireFull, pending, "/x", 401, "mfa_required"},
		{RequireFull, pending, "POST /api/v1/me/passkeys/begin", 401, "mfa_required"},
		// Pending 2FA enrollment: /me* and /auth/logout only, no credential minting.
		{RequireFull, enroll, "/api/v1/spaces", 403, "mfa_enroll_required"},
		{RequireFull, enroll, "/api/v1/mega", 403, "mfa_enroll_required"},
		{RequireFull, enroll, "/api/v1/menu", 403, "mfa_enroll_required"},
		{RequireFull, enroll, "POST /api/v1/me/totp/begin", 200, ""},
		{RequireFull, enroll, "POST /api/v1/me/totp/confirm", 200, ""},
		{RequireFull, enroll, "POST /api/v1/me/passkeys/finish", 200, ""},
		{RequireFull, enroll, "/api/v1/me/passkeys", 200, ""},
		{RequireFull, enroll, "/api/v1/me/sessions", 200, ""},
		{RequireFull, enroll, "POST /api/v1/me/password", 200, ""},
		{RequireFull, enroll, "POST /api/v1/auth/logout", 200, ""},
		{RequireFull, enroll, "POST /api/v1/auth/elevate", 403, "mfa_enroll_required"},
		{RequireFull, enroll, "/api/v1/me/tokens", 200, ""},
		{RequireFull, enroll, "POST /api/v1/me/tokens", 403, "mfa_enroll_required"},
		{RequireFull, enroll, "POST /api/v1/me/client-certs", 403, "mfa_enroll_required"},
		{RequireFull, enroll, "/api/v1/me/client-certs", 200, ""},
		{RequireAdmin, enroll, "/api/v1/admin/users", 403, "mfa_enroll_required"},
		// A token cannot enrol: refused on /me* too (GET /me and /me/mfa are RequireAuth).
		{RequireFull, enrollTok, "/api/v1/me/tokens", 403, "mfa_enroll_required"},
		{RequireFull, enrollTok, "/api/v1/me/usage", 403, "mfa_enroll_required"},
		{RequireAuth, enrollTok, "/api/v1/me/mfa", 200, ""},
		// Password set by an administrator: the enrolment routes' set, until it is changed.
		{RequireFull, mustChange, "/api/v1/spaces", 403, "password_change_required"},
		{RequireFull, mustChange, "POST /api/v1/me/password", 200, ""},
		{RequireFull, mustChange, "/api/v1/me/sessions", 200, ""},
		{RequireFull, mustChange, "POST /api/v1/me/tokens", 403, "password_change_required"},
		{RequireFull, mustChange, "POST /api/v1/auth/logout", 200, ""},
		{RequireAdmin, mustChange, "/api/v1/admin/users", 403, "password_change_required"},
		{RequireAuth, mustChange, "/api/v1/me", 200, ""},
		{RequireFull, member, "/x", 200, ""},
		{RequireAdmin, nil, "/x", 401, "unauthorized"},
		{RequireAdmin, member, "/x", 403, "forbidden"},
		{RequireAdmin, guest, "/x", 403, "forbidden"},
		{RequireAdmin, admin, "/x", 200, ""},
		{RequireAdmin, adminTok, "/x", 403, "forbidden"},
		{RequireAdmin, adminTokFull, "/x", 200, ""},
		{RequireAdmin, sys, "/x", 200, ""},
		{RequireAdmin, off, "/x", 200, ""},
		{RequireRole(core.RoleOwner), admin, "/x", 403, "forbidden"},
		{RequireRole(core.RoleAdmin, core.RoleOwner), admin, "/x", 200, ""},
		{RequireRole(core.RoleOwner), sys, "/x", 200, ""},
		{RequireRole(core.RoleMember), pending, "/x", 401, "mfa_required"},
		{RequireElevated, nil, "/x", 401, "unauthorized"},
		{RequireElevated, member, "/x", 403, "elevation_required"},
		{RequireElevated, adminExpired, "/x", 403, "elevation_required"},
		{RequireElevated, pendingElev, "/x", 401, "mfa_required"},
		{RequireElevated, admin, "/x", 200, ""},
		{RequireElevated, sys, "/x", 200, ""},
		{RequireScope(core.ScopeFilesWrite), nil, "/x", 401, "unauthorized"},
		{RequireScope(core.ScopeFilesWrite), adminTok, "/x", 403, "forbidden"},
		{RequireScope(core.ScopeFilesRead), adminTok, "/x", 200, ""},
		{RequireScope(core.ScopeAdmin), member, "/x", 200, ""},
		{SocketOnly, nil, "/x", 403, "forbidden"},
		{SocketOnly, admin, "/x", 403, "forbidden"},
		{SocketOnly, sys, "/x", 200, ""},
		{SocketOnly, off, "/x", 200, ""},
	}
	for i, c := range cases {
		method, path := "GET", c.path
		if m, rest, ok := strings.Cut(c.path, " "); ok {
			method, path = m, rest
		}
		r := httptest.NewRequest(method, path, nil)
		if c.p != nil {
			r = withP(r, c.p)
		}
		rec := serve(d, c.mw(http.HandlerFunc(ok)), r)
		if rec.Code != c.want || (c.code != "" && code(t, rec) != c.code) {
			t.Errorf("case %d (%s %s): got %d %s want %d %s", i, method, path, rec.Code, code(t, rec), c.want, c.code)
		}
	}
}

func TestMaxBody(t *testing.T) {
	e := newEnv(t)
	d := e.d
	var readBytes int
	read := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, err := io.ReadAll(r.Body)
		readBytes = len(b)
		if err != nil {
			w.WriteHeader(413)
			return
		}
		io.WriteString(w, "ok")
	})
	body := strings.Repeat("x", 100)
	cases := []struct {
		name  string
		h     http.Handler
		chunk bool // unknown length
		want  int
	}{
		{"outer limit", MaxBody(10)(read), false, 413},
		{"outer limit chunked", MaxBody(10)(read), true, 413},
		{"raised", MaxBody(10)(MaxBody(1000)(read)), false, 200},
		{"raised chunked", MaxBody(10)(MaxBody(1000)(read)), true, 200},
		{"lowered", MaxBody(1000)(MaxBody(10)(read)), false, 413},
		{"unlimited", MaxBody(10)(MaxBody(-1)(read)), false, 200},
		{"exact", MaxBody(100)(read), false, 200},
	}
	for _, c := range cases {
		var rd io.Reader = strings.NewReader(body)
		if c.chunk {
			rd = io.MultiReader(strings.NewReader(body)) // hides the length
		}
		r := httptest.NewRequest("POST", "/", rd)
		if c.chunk {
			r.ContentLength = -1
		}
		rec := serve(d, c.h, r)
		if rec.Code != c.want {
			t.Errorf("%s: %d want %d", c.name, rec.Code, c.want)
		}
	}
	// Declared Content-Length above the limit fails before reading anything.
	r := httptest.NewRequest("POST", "/", strings.NewReader(body))
	readBytes = -1
	if rec := serve(d, MaxBody(10)(read), r); rec.Code != 413 || readBytes != 0 {
		t.Fatalf("early reject: %d read %d", rec.Code, readBytes)
	}
	// httpx.Error maps the MaxBytesError to 413 too_large.
	h := MaxBody(10)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, err := io.ReadAll(r.Body)
		if err != nil {
			httpxError(w, r, err)
		}
	}))
	if rec := serve(d, h, httptest.NewRequest("POST", "/", strings.NewReader(body))); rec.Code != 413 || code(t, rec) != "too_large" {
		t.Fatalf("too_large mapping: %d %s", rec.Code, code(t, rec))
	}
	// Bodyless requests are untouched.
	if rec := serve(d, MaxBody(1)(read), httptest.NewRequest("GET", "/", nil)); rec.Code != 200 {
		t.Fatalf("no body: %d", rec.Code)
	}
}

func TestSealedGate(t *testing.T) {
	e := newEnv(t)
	d := e.d
	d.Keys = fakeKeys{state: core.KeyStateLocked}
	h := SecurityHeaders(SealedGate(http.HandlerFunc(ok)))
	rec := serve(d, h, httptest.NewRequest("GET", "/api/v1/spaces", nil))
	if rec.Code != 503 || code(t, rec) != "keys_locked" || rec.Header().Get("Retry-After") == "" {
		t.Fatalf("api while locked: %d %s", rec.Code, code(t, rec))
	}
	rec = serve(d, h, httptest.NewRequest("GET", "/files/abc?x=1", nil))
	if rec.Code != 303 || rec.Header().Get("Location") != "/unlock?next=%2Ffiles%2Fabc%3Fx%3D1" {
		t.Fatalf("page while locked: %d %v", rec.Code, rec.Header().Get("Location"))
	}
	if rec := serve(d, h, httptest.NewRequest("GET", "/", nil)); rec.Code != 303 || rec.Header().Get("Location") != "/unlock" {
		t.Fatalf("root while locked: %d %s", rec.Code, rec.Header().Get("Location"))
	}
	if rec := serve(d, h, httptest.NewRequest("POST", "/share-target", nil)); rec.Code != 503 {
		t.Fatalf("POST page while locked: %d", rec.Code)
	}
	for _, p := range []string{"/unlock", "/trust", "/api/v1/system/status", "/api/v1/system/unlock", "/api/v1/auth/state",
		"/static/abc/app.js", "/trust/ca.crt", "/healthz", "/readyz", "/theme.css", "/sw.js", "/manifest.webmanifest", "/favicon.ico"} {
		if rec := serve(d, h, httptest.NewRequest("GET", p, nil)); rec.Code != 200 {
			t.Errorf("%s while locked: %d", p, rec.Code)
		}
	}
	for _, p := range []string{"/api/v1/system/statusx", "/unlockx", "/api/v1/admin/keys", "/s/tok", "/login"} {
		if rec := serve(d, h, httptest.NewRequest("GET", p, nil)); rec.Code == 200 {
			t.Errorf("%s reachable while locked", p)
		}
	}
	// The public share JSON routes are API paths: fetch() must get the JSON
	// 503, not a redirect it would follow to the HTML unlock page.
	for _, p := range []string{"/s/tok/api", "/s/tok/api/list?node=x", "/s/tok/api/uploads/u1"} {
		rec := serve(d, h, httptest.NewRequest("GET", p, nil))
		if rec.Code != 503 || code(t, rec) != "keys_locked" || rec.Header().Get("Retry-After") == "" {
			t.Errorf("%s while locked: %d %q", p, rec.Code, rec.Header().Get("Location"))
		}
	}
	// The share page itself still redirects, without ?next= (the token must
	// not travel into the unlock page's URL).
	if rec := serve(d, h, httptest.NewRequest("GET", "/s/tok", nil)); rec.Code != 303 || rec.Header().Get("Location") != "/unlock" {
		t.Errorf("share page while locked: %d %q", rec.Code, rec.Header().Get("Location"))
	}
	// Trusted in-process callers pass.
	r := withP(httptest.NewRequest("GET", "/api/v1/admin/system", nil), core.SystemPrincipal(core.ViaSocket))
	if rec := serve(d, h, r); rec.Code != 200 {
		t.Fatalf("socket while locked: %d", rec.Code)
	}
	// Unlocked: everything passes.
	d.Keys = fakeKeys{state: core.KeyStateUnlocked}
	if rec := serve(d, h, httptest.NewRequest("GET", "/api/v1/spaces", nil)); rec.Code != 200 {
		t.Fatalf("unlocked: %d", rec.Code)
	}
}

func TestSecurityHeaders(t *testing.T) {
	e := newEnv(t)
	d := e.d
	h := SecurityHeaders(http.HandlerFunc(ok))
	rec := serve(d, h, httptest.NewRequest("GET", "/files", nil))
	if err := CheckSecurityHeaders(rec.Header(), HeadersPage); err != nil {
		t.Error(err)
	}
	if !strings.Contains(rec.Header().Get("Content-Security-Policy"), "trusted-types fp") {
		t.Error("page CSP lacks trusted-types fp")
	}
	rec = serve(d, h, httptest.NewRequest("GET", "/api/v1/me", nil))
	if err := CheckSecurityHeaders(rec.Header(), HeadersAPI); err != nil {
		t.Error(err)
	}
	if rec.Header().Get("Strict-Transport-Security") != "" {
		t.Error("HSTS on plain HTTP")
	}
	// The public share JSON routes are API paths too; the share page and the
	// content routes are not.
	for _, p := range []string{"/api/v1/me", "/s/abc/api", "/s/abc/api/list", "/s/abc/api/upload-batches/1/files"} {
		rec = serve(d, h, httptest.NewRequest("GET", p, nil))
		if err := CheckSecurityHeaders(rec.Header(), HeadersAPI); err != nil {
			t.Errorf("%s: %v", p, err)
		}
	}
	for _, p := range []string{"/s/abc", "/s/abc/dl/1", "/s/abc/zip", "/share", "/apidocs", "/api"} {
		rec = serve(d, h, httptest.NewRequest("GET", p, nil))
		if err := CheckSecurityHeaders(rec.Header(), HeadersPage); err != nil {
			t.Errorf("%s: %v", p, err)
		}
	}
	// Sweep detects problems.
	bad := http.Header{}
	bad.Set("Server", "x")
	if err := CheckSecurityHeaders(bad, HeadersPage); err == nil || !strings.Contains(err.Error(), "Server") || !strings.Contains(err.Error(), "nosniff") {
		t.Fatalf("sweep: %v", err)
	}

	hsts := func(mode, sni string) string {
		if mode == "" {
			delete(e.s.vals, "tls.hsts")
		} else {
			e.s.set("tls.hsts", mode)
		}
		r := httptest.NewRequest("GET", "https://x/files", nil)
		r.TLS = &tls.ConnectionState{ServerName: sni}
		return serve(d, h, r).Header().Get("Strict-Transport-Security")
	}
	cases := []struct{ mode, sni, want string }{
		{"on", "", HSTSValue},
		{"off", "files.example.org", ""},
		{"auto", "files.example.org", HSTSValue},
		{"auto", "fileparcel.local", ""},
		{"auto", "", ""},
		{"", "files.example.org", HSTSValue}, // unregistered = auto
	}
	for _, c := range cases {
		if got := hsts(c.mode, c.sni); got != c.want {
			t.Errorf("hsts %q %q: %q want %q", c.mode, c.sni, got, c.want)
		}
	}
	// Without deps nothing panics and no HSTS is sent.
	rec = httptest.NewRecorder()
	r := httptest.NewRequest("GET", "https://x/", nil)
	r.TLS = &tls.ConnectionState{}
	SecurityHeaders(http.HandlerFunc(ok)).ServeHTTP(rec, r)
	if rec.Header().Get("Strict-Transport-Security") != "" || rec.Header().Get("X-Frame-Options") != "DENY" {
		t.Fatal("nil deps headers")
	}
}

func TestHostCheck(t *testing.T) {
	e := newEnv(t)
	d := e.d
	h := HostCheck(http.HandlerFunc(ok))
	e.s.set("network.extra_hosts", []string{"files.home.arpa", "*.wild.example", "203.0.113.5"})
	e.s.set("tls.extra_sans", []string{"Nas.Example.org.", "10.8.0.1", "2001:DB8::5"})
	e.s.set("server.public_url", "https://[2001:db8::7]:8443/")
	d.Config.Server.PublicURL = "https://public.example.com:9443/"

	allowed := []string{"localhost", "localhost:8443", "127.0.0.1:8443", "[::1]:8443", "127.8.9.1", "192.168.1.10:8443",
		"[fd7a:115c:a1e0::1]:8443", "[::ffff:192.168.1.10]:8443", "fileparcel.local", "FILEPARCEL.LOCAL.:8443", "myhost.local",
		"files.tail1234.ts.net", "files.home.arpa", "a.wild.example", "nas.example.org", "public.example.com", "app.localhost",
		// IP addresses configured in the settings (NAT / port forward): not
		// the server's interface addresses, still its own.
		"203.0.113.5:8443", "10.8.0.1", "[::ffff:10.8.0.1]:8443", "[2001:db8::5]:8443", "[2001:0db8:0:0::5]", "[2001:db8::7]:8443"}
	denied := []string{"", "evil.example", "192.168.1.7", "10.0.0.1:8443", "wild.example", "a.b.wild.example",
		"fileparcel.local.evil.example", "[fe80::1%eth0]:8443", "203.0.113.6", "10.8.0.2:8443", "[2001:db8::6]"}

	// strict_host off: everything passes.
	for _, host := range denied {
		r := httptest.NewRequest("GET", "/", nil)
		r.Host = host
		if rec := serve(d, h, r); rec.Code != 200 {
			t.Errorf("strict off, %q: %d", host, rec.Code)
		}
	}
	e.s.set("network.strict_host", true)
	for _, host := range allowed {
		r := httptest.NewRequest("GET", "/", nil)
		r.Host = host
		if rec := serve(d, h, r); rec.Code != 200 {
			t.Errorf("allowed %q: %d", host, rec.Code)
		}
	}
	for _, host := range denied {
		r := httptest.NewRequest("GET", "/api/v1/me", nil)
		r.Host = host
		rec := serve(d, h, r)
		if rec.Code != 421 || code(t, rec) != "misdirected" {
			t.Errorf("denied %q: %d", host, rec.Code)
		}
		// The refusal is written before SecurityHeaders runs, so it must
		// carry the §9.2 headers itself.
		if err := CheckSecurityHeaders(rec.Header(), HeadersAPI); err != nil {
			t.Errorf("denied %q: %v", host, err)
		}
	}
	r := httptest.NewRequest("GET", "/files", nil)
	r.Host = "evil.example"
	rec := serve(d, h, r)
	if rec.Code != 421 || !strings.Contains(rec.Body.String(), "421") {
		t.Errorf("page denied: %d", rec.Code)
	}
	if err := CheckSecurityHeaders(rec.Header(), HeadersPage); err != nil {
		t.Errorf("page denied: %v", err)
	}
	// The public share JSON routes are API paths: a JSON 421.
	for _, p := range []string{"/s/tok/api", "/s/tok/api/list"} {
		r = httptest.NewRequest("GET", p, nil)
		r.Host = "evil.example"
		rec = serve(d, h, r)
		if rec.Code != 421 || code(t, rec) != "misdirected" {
			t.Errorf("%s denied: %d %q", p, rec.Code, rec.Body.String())
		}
		if err := CheckSecurityHeaders(rec.Header(), HeadersAPI); err != nil {
			t.Errorf("%s denied: %v", p, err)
		}
	}
	// Trusted callers always pass.
	r = withP(httptest.NewRequest("GET", "/api/v1/me", nil), core.SystemPrincipal(core.ViaSocket))
	r.Host = "evil.example"
	if rec := serve(d, h, r); rec.Code != 200 {
		t.Errorf("socket: %d", rec.Code)
	}
}

func TestResolveClientIP(t *testing.T) {
	e := newEnv(t)
	d := e.d
	var got string
	h := ResolveClientIP(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { got = ClientIP(r).String() }))
	try := func(remote string, xff ...string) string {
		r := httptest.NewRequest("GET", "/", nil)
		r.RemoteAddr = remote
		for _, x := range xff {
			r.Header.Add("X-Forwarded-For", x)
		}
		got = ""
		serve(d, h, r)
		return got
	}
	// No trusted proxies: XFF ignored, IPv4-mapped unmapped.
	if ip := try("10.0.0.1:1234", "203.0.113.9"); ip != "10.0.0.1" {
		t.Fatalf("untrusted proxy honoured: %s", ip)
	}
	if ip := try("[::ffff:10.0.0.1]:1234"); ip != "10.0.0.1" {
		t.Fatalf("mapped: %s", ip)
	}
	if ip := try("@"); ip != "::1" {
		t.Fatalf("unix socket: %s", ip)
	}
	d.Config.Server.TrustedProxies = []string{"10.0.0.0/8", "192.168.1.1"}
	cases := []struct {
		remote string
		xff    []string
		want   string
	}{
		{"10.0.0.1:1", []string{"203.0.113.9"}, "203.0.113.9"},
		{"10.0.0.1:1", []string{"1.1.1.1, 203.0.113.9"}, "203.0.113.9"},    // spoofed left entry ignored
		{"10.0.0.1:1", []string{"203.0.113.9, 10.0.0.2"}, "203.0.113.9"},   // chained trusted proxies
		{"10.0.0.1:1", []string{"203.0.113.9", "10.0.0.2"}, "203.0.113.9"}, // multiple header lines
		{"10.0.0.1:1", []string{"garbage, 10.0.0.2"}, "10.0.0.2"},          // malformed stops the walk
		{"10.0.0.1:1", []string{"[2001:db8::1]:443"}, "2001:db8::1"},       // bracketed with port
		{"10.0.0.1:1", []string{"::ffff:203.0.113.5"}, "203.0.113.5"},      // mapped
		{"10.0.0.1:1", nil, "10.0.0.1"},                                    // no header
		{"192.168.1.1:1", []string{"203.0.113.9"}, "203.0.113.9"},          // single-IP proxy entry
		{"192.168.1.2:1", []string{"203.0.113.9"}, "192.168.1.2"},          // not a proxy
		{"10.0.0.1:1", []string{"10.0.0.3, 10.0.0.2"}, "10.0.0.3"},         // all trusted → left-most
	}
	for _, c := range cases {
		if ip := try(c.remote, c.xff...); ip != c.want {
			t.Errorf("%s %v: %s want %s", c.remote, c.xff, ip, c.want)
		}
	}
	// The settings bridge wins over the config when registered.
	e.s.set("server.trusted_proxies", []string{"172.16.0.0/12"})
	if ip := try("172.16.0.5:1", "203.0.113.1"); ip != "203.0.113.1" {
		t.Fatalf("settings proxies: %s", ip)
	}
	if ip := try("10.0.0.1:1", "203.0.113.1"); ip != "10.0.0.1" {
		t.Fatalf("config proxies after settings: %s", ip)
	}
}

func TestParsePrefixes(t *testing.T) {
	got := parsePrefixes([]string{"10.0.0.0/8", " 192.168.1.7 ", "::ffff:172.16.0.0/108", "::1", "::ffff:0:0/80", "junk", "fe80::1%eth0"})
	var s []string
	for _, p := range got {
		s = append(s, p.String())
	}
	if strings.Join(s, ",") != "10.0.0.0/8,192.168.1.7/32,172.16.0.0/12,::1/128,fe80::1/128" {
		t.Fatalf("%v", s)
	}
}

func TestRateLimit(t *testing.T) {
	e := newEnv(t)
	d := e.d
	d.Limiter.Configure("t", 0.001, 1) // one request, then (effectively) never again
	h := RateLimit("t", PerIP)(http.HandlerFunc(ok))
	for i := 0; i < 3; i++ {
		r := withP(httptest.NewRequest("GET", "/x", nil), core.SystemPrincipal(core.ViaSocket))
		if rec := serve(d, h, r); rec.Code != 200 {
			t.Fatalf("trusted request %d limited: %d", i, rec.Code)
		}
	}
	first := serve(d, h, httptest.NewRequest("GET", "/x", nil))
	second := serve(d, h, httptest.NewRequest("GET", "/x", nil))
	if first.Code != 200 || second.Code != 429 || code(t, second) != "rate_limited" {
		t.Fatalf("limit: %d %d", first.Code, second.Code)
	}
	if ra := second.Header().Get("Retry-After"); ra == "" || ra == "0" {
		t.Fatalf("Retry-After %q", ra)
	}
}

func TestRetryAfterSeconds(t *testing.T) {
	for in, want := range map[float64]int{0: 1, 0.2: 1, 1: 1, 1.1: 2, 59.9: 60, 1e9: 86400, -3: 1} {
		if got := retryAfterSeconds(in); got != want {
			t.Errorf("%v: %d want %d", in, got, want)
		}
	}
}

func TestBucketNames(t *testing.T) {
	if BucketAPI != ratelimit.BucketAPI || BucketLogin != ratelimit.BucketLogin ||
		BucketShare != ratelimit.BucketShare || BucketUnlock != ratelimit.BucketUnlock ||
		BucketLoginNet != ratelimit.BucketLoginNet || BucketShareNet != ratelimit.BucketShareNet ||
		BucketUnlockNet != ratelimit.BucketUnlockNet {
		t.Fatal("mw.Bucket* constants drifted from ratelimit.Bucket*")
	}
	// The registry configures every aggregate RateLimit uses, at
	// ratelimit.NetFactor times its per-address bucket.
	e := newEnv(t)
	for b, nb := range netBuckets {
		if got, want := e.d.Limiter.Tokens(nb, "k"), e.d.Limiter.Tokens(b, "k")*ratelimit.NetFactor; got != want {
			t.Errorf("%s: burst %v, want %v", nb, got, want)
		}
	}
}

// ipsNet is a core.Network with the given interface addresses.
type ipsNet struct {
	core.Network
	ips []netip.Addr
}

func (n ipsNet) IPs() []netip.Addr { return n.ips }

// Rotating through the addresses of one IPv6 /64 must not escape the login,
// share and unlock limits: past the per-address limit, the /64 as a whole
// has an aggregate one. LAN (on-link), ULA/tailnet, link-local and IPv4
// clients keep per-address limits only, and the api bucket and non-IP keys
// are never aggregated.
func TestRateLimitIPv6Net(t *testing.T) {
	e := newEnv(t)
	d := e.d
	d.Network = ipsNet{ips: []netip.Addr{netip.MustParseAddr("192.168.1.10"), netip.MustParseAddr("2001:db8:aa:1::6")}}
	// Effectively no refill: 2 per address, 5 per /64.
	d.Limiter.Configure(BucketLogin, 0.001, 2)
	d.Limiter.Configure(BucketLoginNet, 0.001, 5)
	d.Limiter.Configure(BucketAPI, 0.001, 2)
	h := RateLimit(BucketLogin, PerIP)(http.HandlerFunc(ok))
	from := func(h http.Handler, addr string) int {
		r := httptest.NewRequest("POST", "/api/v1/auth/login", nil)
		r.RemoteAddr = "[" + addr + "]:1"
		if a := netip.MustParseAddr(addr); a.Is4() {
			r.RemoteAddr = addr + ":1"
		}
		return serve(d, h, r).Code
	}

	// A fresh address per request inside 2001:db8:1::/64: the 6th is refused.
	for i := 1; i <= 5; i++ {
		if c := from(h, fmt.Sprintf("2001:db8:1::%x", i)); c != 200 {
			t.Fatalf("rotation request %d: %d", i, c)
		}
	}
	if c := from(h, "2001:db8:1::99"); c != 429 {
		t.Fatalf("rotation past the /64 aggregate: %d", c)
	}
	// Another /64 is unaffected.
	if c := from(h, "2001:db8:2::1"); c != 200 {
		t.Fatalf("other /64: %d", c)
	}
	// The per-address limit still applies first.
	for i, want := range []int{200, 200, 429} {
		if c := from(h, "2001:db8:3::1"); c != want {
			t.Fatalf("per-address limit: request %d: %d, want %d", i+1, c, want)
		}
	}
	// Not aggregated: the server's own /64 (LAN), ULA (tailnet), link-local
	// and IPv4 clients.
	for _, pfx := range []string{"2001:db8:aa:1::", "fd7a:115c:a1e0::", "fe80::", "fd00::"} {
		for i := 1; i <= 8; i++ {
			if c := from(h, fmt.Sprintf("%s%x", pfx, i)); c != 200 {
				t.Fatalf("%s%x: %d", pfx, i, c)
			}
		}
	}
	for i := 1; i <= 8; i++ {
		if c := from(h, fmt.Sprintf("192.0.2.%d", i)); c != 200 {
			t.Fatalf("IPv4 %d: %d", i, c)
		}
	}
	// Neither the api bucket nor a per-user key gets an aggregate.
	api := RateLimit(BucketAPI, PerIP)(http.HandlerFunc(ok))
	user := RateLimit(BucketLogin, PerUser)(http.HandlerFunc(ok))
	for i := 1; i <= 8; i++ {
		if c := from(api, fmt.Sprintf("2001:db8:4::%x", i)); c != 200 {
			t.Fatalf("api bucket %d: %d", i, c)
		}
		if c := from(user, fmt.Sprintf("2001:db8:5::%x", i)); c != 200 {
			t.Fatalf("per-user key %d: %d", i, c)
		}
	}
}

func TestNetKey(t *testing.T) {
	e := newEnv(t)
	cases := map[string]string{
		"2001:db8:1:2::5":         "2001:db8:1:2::/64",
		"2001:db8:1:2:ffff::9":    "2001:db8:1:2::/64",
		"::ffff:192.0.2.1":        "",
		"192.0.2.1":               "",
		"::1":                     "",
		"fe80::1":                 "",
		"fd7a:115c:a1e0::1":       "",
		"fd00::2":                 "",
		"2001:db8:1:2::5%eth0":    "2001:db8:1:2::/64",
		"ff02::1":                 "",
		"2001:db8:ffff:ffff::abc": "2001:db8:ffff:ffff::/64",
	}
	for in, want := range cases {
		got, agg := netKey(e.d, netip.MustParseAddr(in))
		if got != want || agg != (want != "") {
			t.Errorf("%s: %q %v want %q", in, got, agg, want)
		}
	}
}

func TestPerKeys(t *testing.T) {
	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = "[2001:db8::5]:1"
	if PerIP(r) != "2001:db8::5" || PerUser(r) != "ip:2001:db8::5" {
		t.Fatalf("%s %s", PerIP(r), PerUser(r))
	}
	r = withP(r, &core.Principal{UserID: "usr_1"})
	if PerUser(r) != "u:usr_1" {
		t.Fatal(PerUser(r))
	}
}

func TestAccessLog(t *testing.T) {
	e := newEnv(t)
	d := e.d
	d.Config.Server.TrustedProxies = []string{"10.9.9.9"}
	// Same order as the root chain (router.go): ResolveClientIP outside, so
	// the logged ip is the resolved client, not the proxy.
	h := ResolveClientIP(AccessLog(Authenticate(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(201)
		io.WriteString(w, "abc")
	}))))
	r := httptest.NewRequest("POST", "/s/VERYSECRETTOKEN/api/password?pw=hunter2", nil)
	r.AddCookie(&http.Cookie{Name: "s", Value: "1"})
	r.RemoteAddr = "10.9.9.9:1234"
	r.Header.Set("X-Forwarded-For", "203.0.113.7")
	serve(d, h, r)
	out := e.logs.String()
	if strings.Contains(out, "VERYSECRETTOKEN") || strings.Contains(out, "hunter2") {
		t.Fatalf("credential logged: %s", out)
	}
	for _, want := range []string{"status=201", "bytes=3", "user=sess", "via=session", "method=POST", "request_id=", "ip=203.0.113.7"} {
		if !strings.Contains(out, want) {
			t.Errorf("log lacks %q: %s", want, out)
		}
	}
	// Health checks log at debug.
	e.logs.b.Reset()
	serve(d, h, httptest.NewRequest("GET", "/healthz", nil))
	if !strings.Contains(e.logs.String(), "level=DEBUG") {
		t.Errorf("healthz level: %s", e.logs.String())
	}
}

// A panicking handler must still produce an access-log line (DESIGN §20.1
// measures route coverage from it), reported as the 500 Recover writes.
func TestAccessLogPanic(t *testing.T) {
	e := newEnv(t)
	h := Recover(AccessLog(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { panic("boom") })))
	rec := serve(e.d, h, httptest.NewRequest("GET", "/api/v1/x", nil))
	if rec.Code != 500 {
		t.Fatalf("status %d, want 500", rec.Code)
	}
	out := e.logs.String()
	if !strings.Contains(out, "msg=panic") {
		t.Errorf("panic not logged: %s", out)
	}
	if !strings.Contains(out, "msg=http") || !strings.Contains(out, "status=500") {
		t.Errorf("no access-log line for the panicking request: %s", out)
	}
}

// readerFromRecorder is a ResponseWriter that implements io.ReaderFrom, like
// net/http's *response does.
type readerFromRecorder struct{ *httptest.ResponseRecorder }

func (w readerFromRecorder) ReadFrom(r io.Reader) (int64, error) { return io.Copy(w.Body, r) }

// The root chain's wrappers must not hide io.ReaderFrom from handlers, or
// every io.Copy body loses net/http's ReadFrom fast path (the same invariant
// internal/server's TestStreamWriterPassThrough pins).
func TestChainKeepsReaderFrom(t *testing.T) {
	e := newEnv(t)
	seen := false
	var chain http.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rf, ok := w.(io.ReaderFrom)
		seen = ok
		if !ok {
			t.Error("io.ReaderFrom lost")
			return
		}
		if _, err := rf.ReadFrom(strings.NewReader("hello")); err != nil {
			t.Error(err)
		}
	})
	for _, m := range []func(http.Handler) http.Handler{Recover, ResolveClientIP, AccessLog} {
		chain = m(chain)
	}
	rec := httptest.NewRecorder()
	Inject(e.d)(RequestID(chain)).ServeHTTP(readerFromRecorder{rec}, httptest.NewRequest("GET", "/x", nil))
	if !seen {
		t.Fatal("handler did not see io.ReaderFrom")
	}
	if rec.Body.String() != "hello" {
		t.Fatalf("body %q", rec.Body.String())
	}
	if !strings.Contains(e.logs.String(), "bytes=5") {
		t.Errorf("ReadFrom bytes not counted: %s", e.logs.String())
	}
}

func TestRecover(t *testing.T) {
	e := newEnv(t)
	d := e.d
	h := Recover(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { panic("secret detail") }))
	rec := serve(d, h, httptest.NewRequest("GET", "/api/v1/x", nil))
	if rec.Code != 500 || code(t, rec) != "internal" || strings.Contains(rec.Body.String(), "secret detail") {
		t.Fatalf("panic: %d %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(e.logs.String(), "secret detail") {
		t.Fatal("panic not logged")
	}
	// Panic after the response started: nothing more is written, and the
	// response is aborted (http.ErrAbortHandler) rather than ended cleanly.
	h = Recover(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(202)
		io.WriteString(w, "partial")
		panic("late")
	}))
	rec = httptest.NewRecorder()
	func() {
		defer func() {
			if v := recover(); v != http.ErrAbortHandler {
				t.Fatalf("late panic not turned into an abort: %v", v)
			}
		}()
		Inject(d)(RequestID(h)).ServeHTTP(rec, httptest.NewRequest("GET", "/", nil))
	}()
	if rec.Code != 202 || rec.Body.String() != "partial" {
		t.Fatalf("late panic: %d %q", rec.Code, rec.Body.String())
	}
	if !strings.Contains(e.logs.String(), "late") {
		t.Fatal("late panic not logged")
	}
	// http.ErrAbortHandler propagates.
	defer func() {
		if v := recover(); v != http.ErrAbortHandler {
			t.Fatalf("abort not re-panicked: %v", v)
		}
	}()
	serve(d, Recover(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { panic(http.ErrAbortHandler) })),
		httptest.NewRequest("GET", "/", nil))
}

// A panic in the middle of a streamed body must reach the client as a failed
// transfer, not as a complete 200 with a truncated body.
func TestRecoverAbortsStartedResponse(t *testing.T) {
	e := newEnv(t)
	srv := httptest.NewServer(Inject(e.d)(Recover(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/zip")
		io.WriteString(w, "PK\x03\x04partial")
		w.(http.Flusher).Flush()
		panic("archive writer failed")
	}))))
	defer srv.Close()
	resp, err := srv.Client().Get(srv.URL + "/api/v1/archives/t")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err == nil {
		t.Fatalf("truncated body delivered as complete: %d %q", resp.StatusCode, body)
	}
}

// The panic log line names the request path without its credential.
func TestRecoverRedactsPath(t *testing.T) {
	e := newEnv(t)
	h := Recover(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { panic("boom") }))
	rec := serve(e.d, h, httptest.NewRequest("GET", "/s/SECRETTOKEN123/api/list", nil))
	out := e.logs.String()
	if rec.Code != 500 || !strings.Contains(out, "msg=panic") || !strings.Contains(out, "path=/s/…/api/list") {
		t.Fatalf("panic: %d %s", rec.Code, out)
	}
	if strings.Contains(out, "SECRETTOKEN123") {
		t.Fatalf("share token logged: %s", out)
	}
}

func TestRequestID(t *testing.T) {
	e := newEnv(t)
	var ctxID string
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { ctxID = requestIDOf(r) })
	r := httptest.NewRequest("GET", "/", nil)
	r.Header.Set(HeaderRequestID, "client-chosen")
	a := serve(e.d, h, r)
	b := serve(e.d, h, httptest.NewRequest("GET", "/", nil))
	ida, idb := a.Header().Get(HeaderRequestID), b.Header().Get(HeaderRequestID)
	if ida == "" || ida == idb || ida == "client-chosen" || len(ida) < 20 || idb != ctxID {
		t.Fatalf("ids %q %q ctx %q", ida, idb, ctxID)
	}
}

func TestCrossOriginPublicURL(t *testing.T) {
	e := newEnv(t)
	d := e.d
	h := CrossOrigin(http.HandlerFunc(ok))
	r := httptest.NewRequest("POST", "http://internal:8443/s/x/api/password", nil)
	r.Header.Set("Origin", "https://files.example.org")
	if rec := serve(d, h, r); rec.Code != 403 {
		t.Fatalf("foreign origin: %d", rec.Code)
	}
	d.Config.Server.PublicURL = "https://files.example.org/"
	if rec := serve(d, h, r); rec.Code != 200 {
		t.Fatalf("public_url origin: %d", rec.Code)
	}
	d.Config.Server.PublicURL = ""
	if rec := serve(d, h, r); rec.Code != 403 {
		t.Fatalf("public_url removed: %d", rec.Code)
	}
}

func httpxError(w http.ResponseWriter, r *http.Request, err error) { httpx.Error(w, r, err) }

func requestIDOf(r *http.Request) string { return httpx.RequestID(r.Context()) }
