package usersapi

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"

	"fileparcel/internal/app"
	"fileparcel/internal/config"
	"fileparcel/internal/core"
	"fileparcel/internal/crypt"
	"fileparcel/internal/db"
	"fileparcel/internal/events"
	"fileparcel/internal/home"
	"fileparcel/internal/users"
	"fileparcel/internal/web/httpx"
	"fileparcel/internal/web/mw"
)

// ---------- fakes ----------

type fakeAuth struct {
	core.Auth
	mu       sync.Mutex
	calls    []string
	lastPW   string
	lastMust bool
	except   string
	min      int                        // auth.password_min (12 when lower)
	tokens   map[string][]core.APIToken // ListTokens by user id
}

func (a *fakeAuth) record(c string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.calls = append(a.calls, c)
}

func (a *fakeAuth) called(c string) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	for _, x := range a.calls {
		if x == c {
			return true
		}
	}
	return false
}

func (a *fakeAuth) HashPassword(pw string) (string, error) {
	return crypt.HashPasswordParams(pw, crypt.Argon2Params{MemoryKiB: 64, Time: 1, Threads: 1, SaltLen: 16, KeyLen: 32})
}

func (a *fakeAuth) CheckPasswordPolicy(pw string, u *core.User) error {
	if len(pw) < max(12, a.min) {
		return core.Invalid("password", "too short")
	}
	if u != nil && len(u.Username) >= 3 && strings.Contains(strings.ToLower(pw), strings.ToLower(u.Username)) {
		return core.Invalid("password", "the password must not contain your username")
	}
	return nil
}

func (a *fakeAuth) AdminSetPassword(ctx context.Context, by *core.Principal, userID, pw string, mustChange bool) error {
	a.mu.Lock()
	a.lastPW, a.lastMust = pw, mustChange
	a.mu.Unlock()
	a.record("AdminSetPassword:" + userID)
	return nil
}

func (a *fakeAuth) ListSessions(ctx context.Context, userID string) ([]core.Session, error) {
	a.record("ListSessions:" + userID)
	return []core.Session{{ID: "ses_a", UserID: userID}, {ID: "ses_b", UserID: userID}}, nil
}

func (a *fakeAuth) RevokeAllSessions(ctx context.Context, by *core.Principal, userID, exceptID string) error {
	a.mu.Lock()
	a.except = exceptID
	a.mu.Unlock()
	a.record("RevokeAllSessions:" + userID)
	return nil
}

func (a *fakeAuth) ResetMFA(ctx context.Context, by *core.Principal, userID string) error {
	a.record("ResetMFA:" + userID)
	return nil
}

func (a *fakeAuth) ListTokens(ctx context.Context, userID string) ([]core.APIToken, error) {
	a.record("ListTokens:" + userID)
	a.mu.Lock()
	defer a.mu.Unlock()
	return slices.Clone(a.tokens[userID]), nil
}

type fakeAudit struct {
	core.Audit
	mu      sync.Mutex
	query   *core.AuditQuery
	entries []core.AuditEntry
}

func (f *fakeAudit) Record(_ context.Context, e core.AuditEntry) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.entries = append(f.entries, e)
}

// recorded returns a copy of the entries recorded so far.
func (f *fakeAudit) recorded() []core.AuditEntry {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.entries)
}
func (f *fakeAudit) RecordTx(context.Context, *sql.Tx, core.AuditEntry) error { return nil }
func (f *fakeAudit) Query(_ context.Context, q core.AuditQuery) (core.Page[core.AuditRecord], error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.query = &q
	return core.NewPage([]core.AuditRecord{{Seq: 1, Action: core.ActAuthLogin, ActorID: q.ActorID}}, ""), nil
}

type fakeKeys struct{ core.Keys }

func (fakeKeys) State() core.KeyState { return core.KeyStateUnlocked }
func (fakeKeys) SealField(aad string, pt []byte) (string, error) {
	return "v1:k:" + string(pt), nil
}
func (fakeKeys) OpenField(aad, sealed string) ([]byte, error) {
	return []byte(strings.TrimPrefix(sealed, "v1:k:")), nil
}

type fakeSettings struct {
	core.Settings
	ints  map[string]int64
	bools map[string]bool
}

func (s fakeSettings) Int(key string) int64  { return s.ints[key] }
func (s fakeSettings) Bool(key string) bool  { return s.bools[key] }
func (fakeSettings) String(string) string    { return "" }
func (fakeSettings) Strings(string) []string { return nil }

type fakeNotify struct {
	mu   sync.Mutex
	sent []map[string]any
	on   atomic.Bool
}

func (n *fakeNotify) Enabled() bool { return n.on.Load() }
func (n *fakeNotify) Send(_ context.Context, to []string, tmpl string, data any) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	m, _ := data.(map[string]any)
	m["_to"], m["_tmpl"] = to[0], tmpl
	n.sent = append(n.sent, m)
	return nil
}
func (n *fakeNotify) Test(context.Context, string) error { return nil }

// ---------- environment ----------

type testEnv struct {
	d      *app.Deps
	auth   *fakeAuth
	audit  *fakeAudit
	notify *fakeNotify
	srv    *httptest.Server
	who    atomic.Pointer[core.Principal]
	now    time.Time

	owner, owner2, admin, member, guest *core.User
}

func newTestEnv(t *testing.T) *testEnv {
	t.Helper()
	h, err := home.New(filepath.Join(t.TempDir(), "home"))
	if err != nil {
		t.Fatal(err)
	}
	if err := h.EnsureLayout(); err != nil {
		t.Fatal(err)
	}
	database, err := db.Open(h.DB())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := database.Migrate(context.Background()); err != nil {
		t.Fatal(err)
	}
	te := &testEnv{auth: &fakeAuth{}, audit: &fakeAudit{}, notify: &fakeNotify{}, now: time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)}
	bus := events.New()
	env := &core.Env{
		Home: h, DB: database, Bus: bus, Config: config.Default("test"),
		Clock: core.ClockFunc(func() time.Time { return te.now }),
		Log:   slog.New(slog.NewTextHandler(io.Discard, nil)),
		Keys:  fakeKeys{}, Settings: fakeSettings{}, Audit: te.audit,
	}
	us, err := users.New(env)
	if err != nil {
		t.Fatal(err)
	}
	_ = us.Bind(&core.Services{Notify: te.notify})
	te.d = &app.Deps{Env: env, Users: us, Auth: te.auth, Notify: te.notify}

	r := chi.NewRouter()
	r.Use(mw.Inject(te.d))
	r.Use(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			if p := te.who.Load(); p != nil {
				req = req.WithContext(core.WithPrincipal(req.Context(), p.Clone()))
			}
			next.ServeHTTP(w, req)
		})
	})
	api := chi.NewRouter()
	Mount(api, te.d)
	r.Mount("/api/v1", api)
	te.srv = httptest.NewServer(r)
	t.Cleanup(func() {
		te.srv.Close()
		bus.Close()
		_ = database.Close()
	})

	sys := core.SystemPrincipal(core.ViaSocket)
	mk := func(name string, role core.Role, email string) *core.User {
		phc, _ := te.auth.HashPassword("correct horse battery")
		u, err := us.Create(context.Background(), sys, core.NewUser{Username: name, Role: role, Email: email, PasswordHash: phc})
		if err != nil {
			t.Fatal(err)
		}
		return u
	}
	te.owner = mk("owner", core.RoleOwner, "owner@example.com")
	te.owner2 = mk("owner2", core.RoleOwner, "")
	te.admin = mk("admin", core.RoleAdmin, "")
	te.member = mk("member", core.RoleMember, "member@example.com")
	te.guest = mk("guest", core.RoleGuest, "")
	return te
}

// principal for u; elevated opens the step-up window.
func (te *testEnv) principal(u *core.User, elevated bool) *core.Principal {
	p := &core.Principal{UserID: u.ID, Username: u.Username, Role: u.Role, Via: core.ViaSession, AuthLevel: core.AuthLevelFull,
		SessionID: "ses_" + u.Username}
	if elevated {
		p.ElevatedUntil = te.now.Add(5 * time.Minute)
	}
	return p
}

// client sends requests as one principal.
type client struct {
	te *testEnv
	p  *core.Principal
}

func (te *testEnv) as(p *core.Principal) client { return client{te: te, p: p} }

// do sends a request as c.p and decodes the JSON response into out (when non-nil).
func (c client) do(t *testing.T, method, path string, body any, out any) (int, string) {
	t.Helper()
	te := c.te
	te.who.Store(c.p)
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
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
	code := ""
	var er httpx.ErrorResponse
	if json.Unmarshal(raw, &er) == nil {
		code = er.Error.Code
	}
	if out != nil && resp.StatusCode < 300 {
		if err := json.Unmarshal(raw, out); err != nil {
			t.Fatalf("%s %s: decode %s: %v", method, path, raw, err)
		}
	}
	return resp.StatusCode, code
}

// routes lists every mounted route (method + pattern).
func routes(t *testing.T, d *app.Deps) [][2]string {
	t.Helper()
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
	rs := routes(t, te.d)
	if len(rs) != 37 {
		t.Fatalf("expected 37 routes, got %d: %v", len(rs), rs)
	}
	pending := te.principal(te.admin, true)
	pending.AuthLevel = core.AuthLevelPassword
	enroll := te.principal(te.admin, true)
	enroll.EnrollRequired = true
	token := te.principal(te.admin, true)
	token.Via, token.Scopes = core.ViaToken, []string{core.ScopeFilesRead, core.ScopeShares}
	for _, r := range rs {
		path := "/api/v1" + paramRe.ReplaceAllString(r[1], te.member.ID)
		admin := strings.HasPrefix(r[1], "/admin/")
		t.Run(r[0]+" "+r[1], func(t *testing.T) {
			if st, _ := te.as(nil).do(t, r[0], path, nil, nil); st != http.StatusUnauthorized {
				t.Errorf("anonymous: %d", st)
			}
			if st, code := te.as(pending).do(t, r[0], path, nil, nil); st != http.StatusUnauthorized || code != "mfa_required" {
				t.Errorf("mfa pending: %d %s", st, code)
			}
			if st, code := te.as(enroll).do(t, r[0], path, nil, nil); st != http.StatusForbidden || code != "mfa_enroll_required" {
				t.Errorf("enrollment pending: %d %s", st, code)
			}
			if admin {
				for _, p := range []*core.Principal{te.principal(te.member, true), te.principal(te.guest, true), token} {
					if st, code := te.as(p).do(t, r[0], path, nil, nil); st != http.StatusForbidden || code != "forbidden" {
						t.Errorf("%s (%s): %d %s", p.Username, p.Via, st, code)
					}
				}
			}
		})
	}
}

func TestElevationRequired(t *testing.T) {
	te := newTestEnv(t)
	adm := te.principal(te.admin, false)
	role := core.RoleAdmin
	cases := []struct {
		method, path string
		body         any
	}{
		{"DELETE", "/api/v1/admin/users/" + te.member.ID, nil},
		{"POST", "/api/v1/admin/users/" + te.member.ID + "/password", core.PasswordResetInput{Generate: true}},
		{"POST", "/api/v1/admin/users/" + te.member.ID + "/reset-mfa", nil},
		{"PATCH", "/api/v1/admin/users/" + te.member.ID, core.UserUpdate{Role: &role}},
		{"POST", "/api/v1/admin/users", core.NewUser{Username: "newadmin", Role: core.RoleAdmin, GeneratePassword: true}},
		{"POST", "/api/v1/admin/invites", core.InviteInput{Role: core.RoleAdmin}},
	}
	for _, c := range cases {
		if st, code := te.as(adm).do(t, c.method, c.path, c.body, nil); st != http.StatusForbidden || code != "elevation_required" {
			t.Errorf("%s %s: %d %s", c.method, c.path, st, code)
		}
	}
	if len(te.auth.calls) != 0 {
		t.Fatalf("auth called without elevation: %v", te.auth.calls)
	}
	// Non-role changes and member creation need no elevation.
	var u core.User
	if st, _ := te.as(adm).do(t, "PATCH", "/api/v1/admin/users/"+te.member.ID, core.UserUpdate{DisplayName: ptr("Mem")}, &u); st != 200 || u.DisplayName != "Mem" {
		t.Fatalf("patch name: %d %+v", st, u)
	}
	same := core.RoleMember
	if st, _ := te.as(adm).do(t, "PATCH", "/api/v1/admin/users/"+te.member.ID, core.UserUpdate{Role: &same}, nil); st != 200 {
		t.Fatalf("patch same role: %d", st)
	}
	var created core.UserCreated
	if st, _ := te.as(adm).do(t, "POST", "/api/v1/admin/users", core.NewUser{Username: "m2", GeneratePassword: true}, &created); st != 201 {
		t.Fatalf("create member: %d", st)
	}
	// Elevated: the sensitive routes work.
	el := te.principal(te.admin, true)
	for _, c := range cases {
		want := map[string]int{"DELETE": 204, "PATCH": 200, "POST": 200}[c.method]
		if strings.HasSuffix(c.path, "/reset-mfa") {
			want = 204
		}
		if c.path == "/api/v1/admin/users" || c.path == "/api/v1/admin/invites" {
			want = 201
		}
		if c.method == "DELETE" {
			continue // run last
		}
		if st, code := te.as(el).do(t, c.method, c.path, c.body, nil); st != want {
			t.Errorf("elevated %s %s: %d %s", c.method, c.path, st, code)
		}
	}
	if st, _ := te.as(el).do(t, "DELETE", cases[0].path+"?transfer_to="+te.admin.ID, nil, nil); st != 204 {
		t.Fatalf("elevated delete: %d", st)
	}
	if !te.auth.called("ResetMFA:"+te.member.ID) || !te.auth.called("AdminSetPassword:"+te.member.ID) {
		t.Fatalf("auth calls %v", te.auth.calls)
	}
}

func TestOwnerAccountsProtected(t *testing.T) {
	te := newTestEnv(t)
	adm := te.principal(te.admin, true)
	base := "/api/v1/admin/users/" + te.owner.ID
	cases := []struct {
		method, path string
		body         any
	}{
		{"POST", base + "/password", core.PasswordResetInput{Generate: true}},
		{"POST", base + "/reset-mfa", nil},
		{"GET", base + "/sessions", nil}, // the list exposes addresses and the step-up window
		{"DELETE", base + "/sessions", nil},
		{"PATCH", base, core.UserUpdate{DisplayName: ptr("x")}},
		{"POST", base + "/disable", nil},
		{"POST", base + "/unlock", nil},
		{"DELETE", base, nil},
	}
	for _, c := range cases {
		if st, code := te.as(adm).do(t, c.method, c.path, c.body, nil); st != http.StatusForbidden || code != "forbidden" {
			t.Errorf("admin %s %s: %d %s", c.method, c.path, st, code)
		}
	}
	if len(te.auth.calls) != 0 {
		t.Fatalf("auth reached: %v", te.auth.calls)
	}
	// Viewing is fine.
	if st, _ := te.as(adm).do(t, "GET", base, nil, nil); st != 200 {
		t.Fatalf("get owner: %d", st)
	}
	// Another owner may act.
	own := te.principal(te.owner2, true)
	if st, _ := te.as(own).do(t, "POST", base+"/reset-mfa", nil, nil); st != 204 {
		t.Fatalf("owner reset-mfa: %d", st)
	}
}

func TestCreateUser(t *testing.T) {
	te := newTestEnv(t)
	adm := te.as(te.principal(te.admin, false))
	var res core.UserCreated
	st, _ := adm.do(t, "POST", "/api/v1/admin/users", core.NewUser{Username: "gen", Email: "gen@example.com", GeneratePassword: true}, &res)
	if st != 201 || res.User == nil || len(res.Password) != 22 || !res.User.MustChangePassword || res.User.SpaceID == "" {
		t.Fatalf("generated: %d %+v", st, res)
	}
	if ok, _ := crypt.VerifyPassword(mustUser(t, te, res.User.ID).PasswordHash, res.Password); !ok {
		t.Fatal("stored hash does not match the generated password")
	}
	res = core.UserCreated{}
	if st, _ := adm.do(t, "POST", "/api/v1/admin/users", core.NewUser{Username: "given", Password: "a long enough password"}, &res); st != 201 || res.Password != "" {
		t.Fatalf("given: %d %+v", st, res)
	}
	for _, c := range []struct {
		body  any
		field string
	}{
		{core.NewUser{Username: "x1", Password: "short"}, "password"},
		{core.NewUser{Username: "x2"}, "password"},
		{core.NewUser{Username: "x3", Password: "a long enough password", GeneratePassword: true}, "password"},
		{core.NewUser{Username: "bad name", GeneratePassword: true}, "username"},
		{map[string]any{"username": "x4", "generate_password": true, "password_hash": "x"}, "password_hash"},
		{core.NewUser{Username: "x5", GeneratePassword: true, SetupToken: "t"}, "setup_token"},
	} {
		st, code := adm.do(t, "POST", "/api/v1/admin/users", c.body, nil)
		if st != 422 || code != "invalid" {
			t.Errorf("%+v: %d %s", c.body, st, code)
		}
	}
	if st, code := adm.do(t, "POST", "/api/v1/admin/users", core.NewUser{Username: "given", GeneratePassword: true}, nil); st != 409 || code != "conflict" {
		t.Fatalf("duplicate: %d %s", st, code)
	}
	// Admins cannot create owners even when elevated.
	if st, _ := te.as(te.principal(te.admin, true)).do(t, "POST", "/api/v1/admin/users",
		core.NewUser{Username: "boss", Role: core.RoleOwner, GeneratePassword: true}, nil); st != 403 {
		t.Fatalf("admin creates owner: %d", st)
	}
	// The JSON never carries hashes.
	req, _ := http.NewRequest("GET", te.srv.URL+"/api/v1/admin/users/"+res.User.ID, nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if strings.Contains(string(raw), "argon2") || strings.Contains(string(raw), "password_hash") {
		t.Fatalf("hash leaked: %s", raw)
	}
	if resp.Header.Get("Cache-Control") != "no-store" {
		t.Fatalf("cache-control %q", resp.Header.Get("Cache-Control"))
	}
}

// Generated passwords pass the password policy like typed ones: at least
// auth.password_min characters when that is above 22 (otherwise a generated
// reset failed with 422 on a field the admin never saw, and a generated
// account got a password below the minimum), and drawn again when one
// happens to contain the username.
func TestGeneratedPasswordsFollowThePolicy(t *testing.T) {
	te := newTestEnv(t)
	te.d.Env.Settings = fakeSettings{ints: map[string]int64{"auth.password_min": 40}}
	te.auth.min = 40
	adm := te.as(te.principal(te.admin, true))

	var res core.UserCreated
	if st, _ := adm.do(t, "POST", "/api/v1/admin/users", core.NewUser{Username: "long", GeneratePassword: true}, &res); st != 201 || len(res.Password) != 40 {
		t.Fatalf("generated account: %d %q", st, res.Password)
	}
	var reset core.PasswordReset
	if st, _ := adm.do(t, "POST", "/api/v1/admin/users/"+te.member.ID+"/password", core.PasswordResetInput{Generate: true}, &reset); st != 200 ||
		len(reset.Password) != 40 || te.auth.lastPW != reset.Password || !te.auth.lastMust {
		t.Fatalf("generated reset: %d %q", st, reset.Password)
	}

	// A draw containing the username is replaced by the next one.
	orig := randomPassword
	t.Cleanup(func() { randomPassword = orig })
	draws := 0
	randomPassword = func(n int) string {
		draws++
		if draws == 1 {
			return ("member" + orig(n))[:n]
		}
		return orig(n)
	}
	reset = core.PasswordReset{}
	if st, _ := adm.do(t, "POST", "/api/v1/admin/users/"+te.member.ID+"/password", core.PasswordResetInput{Generate: true}, &reset); st != 200 ||
		draws != 2 || strings.Contains(reset.Password, "member") || len(reset.Password) != 40 {
		t.Fatalf("redraw: %d after %d draws: %q", st, draws, reset.Password)
	}
	// A policy no draw meets ends with its error instead of looping.
	randomPassword = func(n int) string { return strings.Repeat("member2", n)[:n] }
	if st, code := adm.do(t, "POST", "/api/v1/admin/users", core.NewUser{Username: "member2", GeneratePassword: true}, nil); st != 422 || code != "invalid" {
		t.Fatalf("hopeless policy: %d %s", st, code)
	}
}

func mustUser(t *testing.T, te *testEnv, id string) *core.User {
	t.Helper()
	u, err := te.d.Users.Get(context.Background(), id)
	if err != nil {
		t.Fatal(err)
	}
	return u
}

func TestUserAdminRoutes(t *testing.T) {
	te := newTestEnv(t)
	adm := te.as(te.principal(te.admin, true))
	id := te.member.ID

	var page core.Page[core.User]
	if st, _ := adm.do(t, "GET", "/api/v1/admin/users?role=owner&limit=1", nil, &page); st != 200 || len(page.Items) != 1 || page.NextCursor == "" {
		t.Fatalf("list: %d %+v", st, page)
	}
	if st, code := adm.do(t, "GET", "/api/v1/admin/users?role=king", nil, nil); st != 422 || code != "invalid" {
		t.Fatalf("bad role filter: %d", st)
	}
	if st, _ := adm.do(t, "GET", "/api/v1/admin/users/usr_nope", nil, nil); st != 404 {
		t.Fatalf("missing user: %d", st)
	}
	if st, _ := adm.do(t, "POST", "/api/v1/admin/users/"+id+"/disable", nil, nil); st != 204 || mustUser(t, te, id).Status != core.UserDisabled {
		t.Fatalf("disable: %d", st)
	}
	if st, _ := adm.do(t, "POST", "/api/v1/admin/users/"+id+"/enable", nil, nil); st != 204 || mustUser(t, te, id).Status != core.UserActive {
		t.Fatalf("enable: %d", st)
	}
	if st, _ := adm.do(t, "POST", "/api/v1/admin/users/"+id+"/unlock", nil, nil); st != 204 {
		t.Fatalf("unlock: %d", st)
	}
	var reset core.PasswordReset
	if st, _ := adm.do(t, "POST", "/api/v1/admin/users/"+id+"/password", core.PasswordResetInput{Generate: true}, &reset); st != 200 ||
		len(reset.Password) != 22 || te.auth.lastPW != reset.Password || !te.auth.lastMust {
		t.Fatalf("generated reset: %d %+v", st, reset)
	}
	reset = core.PasswordReset{}
	if st, _ := adm.do(t, "POST", "/api/v1/admin/users/"+id+"/password", core.PasswordResetInput{Password: "new secret pass"}, &reset); st != 200 ||
		reset.Password != "" || te.auth.lastMust {
		t.Fatalf("given reset: %d %+v", st, reset)
	}
	for _, bad := range []core.PasswordResetInput{{}, {Password: "x", Generate: true}} {
		if st, _ := adm.do(t, "POST", "/api/v1/admin/users/"+id+"/password", bad, nil); st != 422 {
			t.Errorf("reset %+v: %d", bad, st)
		}
	}
	var sessions core.Page[core.Session]
	if st, _ := adm.do(t, "GET", "/api/v1/admin/users/"+id+"/sessions", nil, &sessions); st != 200 || len(sessions.Items) != 2 {
		t.Fatalf("sessions: %d %+v", st, sessions)
	}
	if st, _ := adm.do(t, "DELETE", "/api/v1/admin/users/"+id+"/sessions", nil, nil); st != 204 || te.auth.except != "" {
		t.Fatalf("revoke: %d except %q", st, te.auth.except)
	}
	// Revoking one's own sessions keeps the current one.
	if st, _ := adm.do(t, "DELETE", "/api/v1/admin/users/"+te.admin.ID+"/sessions", nil, nil); st != 204 || te.auth.except != "ses_admin" {
		t.Fatalf("revoke own: %d except %q", st, te.auth.except)
	}
	// Security alerts (password reset, MFA reset) go to users with an address.
	te.notify.on.Store(true)
	if st, _ := adm.do(t, "POST", "/api/v1/admin/users/"+id+"/reset-mfa", nil, nil); st != 204 {
		t.Fatalf("reset-mfa: %d", st)
	}
	te.notify.mu.Lock()
	sent := append([]map[string]any(nil), te.notify.sent...)
	te.notify.mu.Unlock()
	if len(sent) != 1 || sent[0]["kind"] != "mfa_reset" || sent[0]["_to"] != "member@example.com" || sent[0]["actor"] != "admin" {
		t.Fatalf("alerts %+v", sent)
	}
	if st, code := adm.do(t, "PATCH", "/api/v1/admin/users/"+id, map[string]any{"bogus": 1}, nil); st != 422 || code != "invalid" {
		t.Fatalf("unknown field: %d", st)
	}
	if st, _ := adm.do(t, "PATCH", "/api/v1/admin/users/"+id, map[string]any{"quota_bytes": nil}, nil); st != 200 {
		t.Fatalf("null quota: %d", st)
	}
	if st, _ := adm.do(t, "DELETE", "/api/v1/admin/users/"+id+"?transfer_to="+te.guest.ID, nil, nil); st != 422 {
		t.Fatalf("transfer to guest: %d", st)
	}
	if st, _ := adm.do(t, "DELETE", "/api/v1/admin/users/"+te.admin.ID, nil, nil); st != 403 {
		t.Fatalf("self delete: %d", st)
	}
}

func TestInvitesAndGroupsRoutes(t *testing.T) {
	te := newTestEnv(t)
	adm := te.as(te.principal(te.admin, false))

	var g core.Group
	if st, _ := adm.do(t, "POST", "/api/v1/admin/groups", core.GroupInput{Name: "Team"}, &g); st != 201 || g.SpaceID == "" {
		t.Fatalf("create group: %d %+v", st, g)
	}
	if st, _ := adm.do(t, "POST", "/api/v1/admin/groups", core.GroupInput{Name: "team"}, nil); st != 409 {
		t.Fatalf("dup group: %d", st)
	}
	if st, _ := adm.do(t, "PATCH", "/api/v1/admin/groups/"+g.ID, core.GroupInput{Name: "Team A"}, &g); st != 200 || g.Name != "Team A" {
		t.Fatalf("rename: %d %+v", st, g)
	}
	if st, _ := adm.do(t, "PUT", "/api/v1/admin/groups/"+g.ID+"/members/"+te.member.ID, core.RoleInput{Role: core.GroupRoleManager}, nil); st != 204 {
		t.Fatalf("set member: %d", st)
	}
	if st, _ := adm.do(t, "PUT", "/api/v1/admin/groups/"+g.ID+"/members/"+te.member.ID, core.RoleInput{Role: "boss"}, nil); st != 422 {
		t.Fatalf("bad role: %d", st)
	}
	var members core.Page[core.GroupMember]
	if st, _ := adm.do(t, "GET", "/api/v1/admin/groups/"+g.ID+"/members", nil, &members); st != 200 || len(members.Items) != 1 {
		t.Fatalf("members: %d %+v", st, members)
	}
	var mine core.Page[core.Group]
	if st, _ := te.as(te.principal(te.member, false)).do(t, "GET", "/api/v1/groups", nil, &mine); st != 200 ||
		len(mine.Items) != 1 || mine.Items[0].MyRole != core.GroupRoleManager {
		t.Fatalf("my groups: %d %+v", st, mine)
	}
	var groups core.Page[core.Group]
	if st, _ := adm.do(t, "GET", "/api/v1/admin/groups", nil, &groups); st != 200 || len(groups.Items) != 1 {
		t.Fatalf("groups: %d", st)
	}
	if st, _ := adm.do(t, "DELETE", "/api/v1/admin/groups/"+g.ID+"/members/"+te.member.ID, nil, nil); st != 204 {
		t.Fatalf("remove member: %d", st)
	}
	if st, _ := adm.do(t, "DELETE", "/api/v1/admin/groups/"+g.ID+"/members/"+te.member.ID, nil, nil); st != 404 {
		t.Fatalf("remove twice: %d", st)
	}
	if st, _ := adm.do(t, "DELETE", "/api/v1/admin/groups/"+g.ID, nil, nil); st != 204 {
		t.Fatalf("delete group: %d", st)
	}
	if st, _ := adm.do(t, "GET", "/api/v1/admin/groups/"+g.ID, nil, nil); st != 404 {
		t.Fatalf("deleted group: %d", st)
	}

	var inv core.InviteCreated
	if st, _ := adm.do(t, "POST", "/api/v1/admin/invites", core.InviteInput{Email: "n@example.com", Role: core.RoleGuest}, &inv); st != 201 ||
		inv.Invite == nil || !strings.HasPrefix(inv.URL, "/invite/") || inv.Invite.URL != inv.URL {
		t.Fatalf("invite: %d %+v", st, inv)
	}
	tok := strings.TrimPrefix(inv.URL, "/invite/")
	if got, err := te.d.Users.LookupInvite(context.Background(), tok); err != nil || got.ID != inv.Invite.ID {
		t.Fatalf("lookup: %v", err)
	}
	var list core.Page[core.Invite]
	if st, _ := adm.do(t, "GET", "/api/v1/admin/invites", nil, &list); st != 200 || len(list.Items) != 1 || list.Items[0].URL != inv.URL {
		t.Fatalf("list invites: %d %+v", st, list)
	}
	if st, _ := adm.do(t, "POST", "/api/v1/admin/invites", core.InviteInput{Role: core.RoleOwner}, nil); st != 422 {
		t.Fatalf("owner invite: %d", st)
	}
	if st, _ := adm.do(t, "DELETE", "/api/v1/admin/invites/"+inv.Invite.ID, nil, nil); st != 204 {
		t.Fatalf("revoke: %d", st)
	}
	if st, _ := adm.do(t, "DELETE", "/api/v1/admin/invites/inv_nope", nil, nil); st != 404 {
		t.Fatalf("revoke missing: %d", st)
	}
}

func TestSelfServiceRoutes(t *testing.T) {
	te := newTestEnv(t)
	mem := te.as(te.principal(te.member, false))
	var refs core.Page[core.UserRef]
	if st, _ := mem.do(t, "GET", "/api/v1/users/lookup?q=own", nil, &refs); st != 200 || len(refs.Items) != 2 || refs.Items[0].Username != "owner" {
		t.Fatalf("lookup: %d %+v", st, refs)
	}
	raw := mustGet(t, te, "/api/v1/users/lookup?q=own")
	if strings.Contains(raw, "email") || strings.Contains(raw, "role") {
		t.Fatalf("lookup leaks: %s", raw)
	}
	if st, _ := mem.do(t, "GET", "/api/v1/users/lookup?q=o", nil, nil); st != 422 {
		t.Fatalf("short lookup: %d", st)
	}
	if st, _ := te.as(te.principal(te.guest, false)).do(t, "GET", "/api/v1/users/lookup?q=own", nil, nil); st != 403 {
		t.Fatalf("guest lookup: %d", st)
	}

	var act core.Page[core.AuditRecord]
	if st, _ := te.as(te.principal(te.member, false)).do(t, "GET",
		"/api/v1/activity?action=auth.&since=2026-01-01T00:00:00Z&limit=5&cursor=abc", nil, &act); st != 200 || len(act.Items) != 1 {
		t.Fatalf("activity: %d %+v", st, act)
	}
	q := te.audit.query
	if q == nil || q.ActorID != te.member.ID || q.Action != "auth." || q.Since == nil || q.Limit != 5 || q.Cursor != "abc" {
		t.Fatalf("query %+v", q)
	}
	// The actor filter cannot be overridden by the caller.
	te.audit.query = nil
	mem.do(t, "GET", "/api/v1/activity?actor_id="+te.admin.ID, nil, nil)
	if te.audit.query.ActorID != te.member.ID {
		t.Fatalf("actor override: %+v", te.audit.query)
	}
	// The details panel's item filter runs on the server (not over the newest
	// page of everything), and still only over the caller's own events.
	te.audit.query = nil
	mem.do(t, "GET", "/api/v1/activity?target_type=node&target_id=nod_x&actor_id="+te.admin.ID, nil, nil)
	if q := te.audit.query; q == nil || q.TargetType != "node" || q.TargetID != "nod_x" || q.ActorID != te.member.ID {
		t.Fatalf("target filter: %+v", q)
	}
	if st, _ := mem.do(t, "GET", "/api/v1/activity?until=yesterday", nil, nil); st != 422 {
		t.Fatalf("bad until: %d", st)
	}
	// The system principal has no own activity (never everyone's).
	te.audit.query = nil
	act = core.Page[core.AuditRecord]{}
	if st, _ := te.as(core.SystemPrincipal(core.ViaSocket)).do(t, "GET", "/api/v1/activity", nil, &act); st != 200 || len(act.Items) != 0 || te.audit.query != nil {
		t.Fatalf("system activity: %d %+v", st, act)
	}
	var none core.Page[core.Group]
	if st, _ := mem.do(t, "GET", "/api/v1/groups", nil, &none); st != 200 || none.Items == nil {
		t.Fatalf("no groups: %d %+v", st, none)
	}
}

func mustGet(t *testing.T, te *testEnv, path string) string {
	t.Helper()
	te.who.Store(te.principal(te.member, false))
	resp, err := http.Get(te.srv.URL + path)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return string(b)
}

func ptr[T any](v T) *T { return &v }

// sweepBody is a body every route accepts (JSON object; GETs ignore it).
func sweepBody(method, route string) any {
	switch {
	case method == http.MethodGet, method == http.MethodDelete:
		return nil
	case strings.HasSuffix(route, "/members/{userId}"):
		return core.RoleInput{Role: core.GroupRoleMember}
	case route == "/admin/users/{id}/password":
		return core.PasswordResetInput{Generate: true}
	}
	return map[string]any{}
}

func TestServicesUnavailable(t *testing.T) {
	te := newTestEnv(t)
	te.d.Users, te.d.Auth, te.d.Audit = nil, nil, nil
	own := te.as(te.principal(te.owner, true))
	for _, r := range routes(t, te.d) {
		if r[1] == "/admin/capabilities" {
			continue // the catalog is compiled in: no service needed
		}
		path := "/api/v1" + paramRe.ReplaceAllString(r[1], te.member.ID)
		if r[1] == "/users/lookup" {
			path += "?q=mem"
		}
		if st, code := own.do(t, r[0], path, sweepBody(r[0], r[1]), nil); st != http.StatusServiceUnavailable || code != "unavailable" {
			t.Errorf("%s %s: %d %s", r[0], r[1], st, code)
		}
	}
}

func TestUnknownIDsAre404(t *testing.T) {
	te := newTestEnv(t)
	own := te.as(te.principal(te.owner, true))
	g, err := te.d.Users.CreateGroup(context.Background(), core.SystemPrincipal(core.ViaSocket), core.GroupInput{Name: "G"})
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, r := range routes(t, te.d) {
		if !strings.Contains(r[1], "{") {
			continue
		}
		n++
		path := strings.NewReplacer("{id}", "zzz_missing", "{userId}", "usr_missing", "{groupId}", "grp_missing").Replace(r[1])
		if st, code := own.do(t, r[0], "/api/v1"+path, sweepBody(r[0], r[1]), nil); st != http.StatusNotFound || code != "not_found" {
			t.Errorf("%s %s: %d %s", r[0], path, st, code)
		}
	}
	if n != 24 {
		t.Fatalf("swept %d parameterized routes", n)
	}
	// A known group with an unknown user.
	if st, _ := own.do(t, "PUT", "/api/v1/admin/groups/"+g.ID+"/members/usr_missing", core.RoleInput{Role: core.GroupRoleMember}, nil); st != 404 {
		t.Fatalf("unknown member: %d", st)
	}
	if st, _ := own.do(t, "DELETE", "/api/v1/admin/groups/"+g.ID+"/members/usr_missing", nil, nil); st != 404 {
		t.Fatalf("remove unknown member: %d", st)
	}
}

// An admin invite link creates an administrator whose password the holder
// picks, so GET /admin/invites leaves it out unless the caller has stepped
// up, like POST of an admin invite; other links stay visible.
func TestAdminInviteLinkNeedsElevation(t *testing.T) {
	te := newTestEnv(t)
	el := te.as(te.principal(te.admin, true))
	var admInv, memInv core.InviteCreated
	if st, code := el.do(t, "POST", "/api/v1/admin/invites", core.InviteInput{Role: core.RoleAdmin}, &admInv); st != 201 {
		t.Fatalf("admin invite: %d %s", st, code)
	}
	if st, code := el.do(t, "POST", "/api/v1/admin/invites", core.InviteInput{Role: core.RoleMember}, &memInv); st != 201 {
		t.Fatalf("member invite: %d %s", st, code)
	}
	urls := func(c client) map[string]string {
		t.Helper()
		var list core.Page[core.Invite]
		if st, code := c.do(t, "GET", "/api/v1/admin/invites", nil, &list); st != 200 || len(list.Items) != 2 {
			t.Fatalf("list: %d %s %+v", st, code, list)
		}
		m := map[string]string{}
		for _, i := range list.Items {
			m[i.ID] = i.URL
		}
		return m
	}
	got := urls(te.as(te.principal(te.admin, false)))
	if got[admInv.Invite.ID] != "" || got[memInv.Invite.ID] != memInv.URL || memInv.URL == "" {
		t.Fatalf("not elevated: %v", got)
	}
	got = urls(el)
	if got[admInv.Invite.ID] != admInv.URL || admInv.URL == "" || got[memInv.Invite.ID] != memInv.URL {
		t.Fatalf("elevated: %v", got)
	}
}
