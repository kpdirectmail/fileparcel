package meapi_test

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"

	"fileparcel/internal/app"
	"fileparcel/internal/auth"
	"fileparcel/internal/auth/authtest"
	"fileparcel/internal/core"
	"fileparcel/internal/web/authapi"
	"fileparcel/internal/web/httpx"
	"fileparcel/internal/web/meapi"
	"fileparcel/internal/web/mw"
)

func TestMain(m *testing.M) {
	restore := authtest.FastHashing()
	code := m.Run()
	restore()
	os.Exit(code)
}

const (
	pw     = "correct horse battery staple"
	newPW  = "a completely different passphrase"
	origin = "https://fileparcel.local:8443"
)

// fakeFiles implements only Files.Usage (the one method meapi calls).
type fakeFiles struct{ core.Files }

func (fakeFiles) Usage(_ context.Context, userID string) (*core.Usage, error) {
	return &core.Usage{UserID: userID, SpaceID: "spc_mine", UsedBytes: 1234, TrashBytes: 5}, nil
}

// server wires the /api/v1 chain of web/router.go around authapi and meapi
// (authapi is needed for sign-in and elevation).
func server(t *testing.T, mutate ...func(*app.Deps)) (*authtest.Env, http.Handler) {
	t.Helper()
	e := authtest.New(t)
	e.Settings.Put("ratelimit.login_per_min", 1000)
	e.Limiter.ApplySettings()
	d := &app.Deps{Env: e.Env, Auth: e.Auth, Users: e.Users, Files: fakeFiles{}, Limiter: e.Limiter}
	for _, f := range mutate {
		f(d)
	}
	r := chi.NewRouter()
	r.Use(mw.Inject(d), middleware.GetHead, mw.RequestID, mw.ResolveClientIP)
	api := chi.NewRouter()
	authapi.Mount(api, d)
	meapi.Mount(api, d)
	// an ordinary full-auth route outside /me* (the enrolment and must-change gates)
	api.With(mw.RequireFull).Get("/probe", func(w http.ResponseWriter, _ *http.Request) { httpx.NoContent(w) })
	r.With(mw.MaxBody(httpx.DefaultMaxBody), mw.RateLimit(mw.BucketAPI, mw.PerIP), mw.Authenticate, mw.CSRF).Mount("/api/v1", api)
	return e, r
}

// client is a minimal browser (session cookie + CSRF header), a Bearer
// client, or an in-process caller (principal in the request context).
type client struct {
	t         *testing.T
	h         http.Handler
	ip        string
	token     string
	csrf      string
	bearer    string
	principal *core.Principal // trusted in-process principal (admin socket)
	cookie    *http.Cookie    // last Set-Cookie of the session cookie
	header    http.Header     // extra headers for the next request
}

func newClient(t *testing.T, h http.Handler) *client { return &client{t: t, h: h, ip: "192.0.2.10"} }

func (c *client) do(method, path string, body any) *httptest.ResponseRecorder {
	c.t.Helper()
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			c.t.Fatal(err)
		}
		rd = bytes.NewReader(b)
	}
	r := httptest.NewRequest(method, "/api/v1"+path, rd)
	r.RemoteAddr = c.ip + ":41000"
	if body != nil {
		r.Header.Set("Content-Type", "application/json")
	}
	if c.token != "" {
		r.AddCookie(&http.Cookie{Name: auth.CookieName, Value: c.token})
	}
	if c.csrf != "" && method != http.MethodGet && method != http.MethodHead {
		r.Header.Set(mw.HeaderCSRF, c.csrf)
	}
	if c.bearer != "" {
		r.Header.Set("Authorization", "Bearer "+c.bearer)
	}
	if c.principal != nil {
		r = r.WithContext(core.WithPrincipal(r.Context(), c.principal.Clone()))
	}
	for k, v := range c.header {
		r.Header[http.CanonicalHeaderKey(k)] = v
	}
	c.header = nil
	w := httptest.NewRecorder()
	c.h.ServeHTTP(w, r)
	for _, ck := range w.Result().Cookies() {
		if ck.Name == auth.CookieName {
			c.cookie = ck
			if ck.MaxAge < 0 || ck.Value == "" {
				c.token = ""
			} else {
				c.token = ck.Value
			}
		}
	}
	return w
}

func decode[T any](t *testing.T, w *httptest.ResponseRecorder, status int) T {
	t.Helper()
	var v T
	if w.Code != status {
		t.Fatalf("status %d, want %d: %s", w.Code, status, w.Body.String())
	}
	if w.Body.Len() > 0 {
		if err := json.Unmarshal(w.Body.Bytes(), &v); err != nil {
			t.Fatalf("decode %T: %v (%s)", v, err, w.Body.String())
		}
	}
	return v
}

func errCode(t *testing.T, w *httptest.ResponseRecorder, status int, code string) httpx.ErrorDetail {
	t.Helper()
	er := decode[httpx.ErrorResponse](t, w, status)
	if er.Error.Code != code {
		t.Fatalf("error code %q, want %q (%s)", er.Error.Code, code, er.Error.Message)
	}
	return er.Error
}

func noContent(t *testing.T, w *httptest.ResponseRecorder) {
	t.Helper()
	if w.Code != http.StatusNoContent {
		t.Fatalf("status %d, want 204: %s", w.Code, w.Body.String())
	}
}

func totpCode(t *testing.T, secret string, at time.Time) string {
	t.Helper()
	c, err := totp.GenerateCodeCustom(secret, at, totp.ValidateOpts{Period: 30, Digits: otp.DigitsSix, Algorithm: otp.AlgorithmSHA1})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func (c *client) login(user, pass string) core.LoginResult {
	c.t.Helper()
	res := decode[core.LoginResult](c.t, c.do(http.MethodPost, "/auth/login", core.LoginInput{Username: user, Password: pass}), http.StatusOK)
	c.csrf = res.CSRF
	return res
}

func (c *client) elevate(in core.ElevateInput) core.ElevateResult {
	c.t.Helper()
	res := decode[core.ElevateResult](c.t, c.do(http.MethodPost, "/auth/elevate", in), http.StatusOK)
	if res.CSRF != "" {
		c.csrf = res.CSRF
	}
	return res
}

// enrollTOTP turns on TOTP for the signed-in client (stepping up with the
// password first, as setting up a factor needs) and returns the secret and
// the recovery codes. The clock is advanced past the used time step.
func (c *client) enrollTOTP(e *authtest.Env) (string, []string) {
	c.t.Helper()
	c.elevate(core.ElevateInput{Password: pw})
	en := decode[core.TOTPEnrollment](c.t, c.do(http.MethodPost, "/me/totp/begin", nil), http.StatusOK)
	rc := decode[core.RecoveryCodes](c.t, c.do(http.MethodPost, "/me/totp/confirm", core.CodeInput{Code: totpCode(c.t, en.Secret, e.Clock.Now())}), http.StatusOK)
	e.Clock.Advance(30 * time.Second)
	return en.Secret, rc.RecoveryCodes
}

// ---------- routes & guards ----------

// wantRoutes is the meapi part of DESIGN §9.4 (without /me/client-certs*).
var wantRoutes = []string{
	"DELETE /me/passkeys/{id}", "DELETE /me/sessions/{id}", "DELETE /me/tokens/{id}", "DELETE /me/totp",
	"GET /me", "GET /me/mfa", "GET /me/passkeys", "GET /me/sessions", "GET /me/tokens", "GET /me/usage",
	"PATCH /me/passkeys/{id}", "PATCH /me/profile",
	"POST /me/passkeys/begin", "POST /me/passkeys/finish", "POST /me/password", "POST /me/recovery-codes",
	"POST /me/sessions/revoke-others", "POST /me/tokens", "POST /me/totp/begin", "POST /me/totp/confirm",
}

func routes(t *testing.T) []string {
	t.Helper()
	r := chi.NewRouter()
	meapi.Mount(r, &app.Deps{})
	var out []string
	err := chi.Walk(r, func(method, route string, _ http.Handler, _ ...func(http.Handler) http.Handler) error {
		out = append(out, method+" "+route)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	slices.Sort(out)
	return out
}

func TestRouteTable(t *testing.T) {
	got := routes(t)
	want := slices.Clone(wantRoutes)
	slices.Sort(want)
	if !slices.Equal(got, want) {
		t.Fatalf("routes\n got %q\nwant %q", got, want)
	}
}

func TestRouteProtection(t *testing.T) {
	e, h := server(t)
	e.AddUser(t, "pam", pw, core.RoleMember)
	all := routes(t)

	// anonymous: every route is 401
	anon := newClient(t, h)
	for _, rt := range all {
		method, path, _ := strings.Cut(rt, " ")
		path = strings.ReplaceAll(path, "{id}", "x")
		errCode(t, anon.do(method, path, nil), http.StatusUnauthorized, "unauthorized")
	}

	// password verified, second factor pending: only GET /me and GET /me/mfa
	c := newClient(t, h)
	c.login("pam", pw)
	c.enrollTOTP(e)
	noContent(t, c.do(http.MethodPost, "/auth/logout", nil))
	if res := c.login("pam", pw); !res.MFARequired {
		t.Fatalf("second factor expected: %+v", res)
	}
	for _, rt := range all {
		method, path, _ := strings.Cut(rt, " ")
		path = strings.ReplaceAll(path, "{id}", "x")
		w := c.do(method, path, nil)
		if rt == "GET /me" || rt == "GET /me/mfa" {
			if w.Code != http.StatusOK {
				t.Fatalf("%s at AuthLevel 1: %d %s", rt, w.Code, w.Body)
			}
			continue
		}
		// in particular no new authenticator or passkey with a password alone
		errCode(t, w, http.StatusUnauthorized, "mfa_required")
	}

	// a cross-site request with a valid session and CSRF token is refused
	c.header = http.Header{"Sec-Fetch-Site": {"cross-site"}, "Origin": {"https://evil.example"}}
	errCode(t, c.do(http.MethodPatch, "/me/profile", map[string]any{"display_name": "x"}), http.StatusForbidden, "forbidden")
}

func TestServicesUnavailable(t *testing.T) {
	_, h := server(t, func(d *app.Deps) { d.Auth = nil })
	errCode(t, newClient(t, h).do(http.MethodGet, "/me", nil), http.StatusServiceUnavailable, "unavailable")
}

// ---------- GET /me ----------

func TestMe(t *testing.T) {
	e, h := server(t)
	u := e.AddUser(t, "mona", pw, core.RoleMember)
	c := newClient(t, h)
	res := c.login("mona", pw)
	me := decode[core.Me](t, c.do(http.MethodGet, "/me", nil), http.StatusOK)
	switch {
	case me.User == nil || me.User.ID != u.ID || me.User.Username != "mona":
		t.Fatalf("user %+v", me.User)
	case me.CSRF == "" || me.CSRF != res.CSRF:
		t.Fatalf("csrf %q vs %q", me.CSRF, res.CSRF)
	case string(me.Prefs) != "{}":
		t.Fatalf("prefs %s", me.Prefs)
	case !me.Features["passkeys"] || !me.Features["links"] || !me.Features["requests"]:
		t.Fatalf("features %v", me.Features)
	case me.MFAPending || me.MFA == nil || me.MFA.TOTPEnabled || me.MFA.Required || me.MFA.EnrollRequired:
		t.Fatalf("mfa %+v pending %v", me.MFA, me.MFAPending)
	case me.SpaceID == "" || len(me.Groups) != 1 || me.GroupSpaceIDs["grp_team"] != "spc_team":
		t.Fatalf("spaces %q %v %v", me.SpaceID, me.Groups, me.GroupSpaceIDs)
	case me.Via != core.ViaSession || me.ElevatedUntil != nil:
		t.Fatalf("via %q elevated %v", me.Via, me.ElevatedUntil)
	}
	if strings.Contains(c.do(http.MethodGet, "/me", nil).Body.String(), "password_hash") {
		t.Fatal("/me leaks the password hash")
	}
	if w := c.do(http.MethodHead, "/me", nil); w.Code != http.StatusOK {
		t.Fatalf("HEAD /me %d", w.Code)
	}
	if got := c.do(http.MethodGet, "/me", nil).Header().Get("Cache-Control"); got != "no-store" {
		t.Fatalf("Cache-Control %q", got)
	}

	el := c.elevate(core.ElevateInput{Password: pw})
	me = decode[core.Me](t, c.do(http.MethodGet, "/me", nil), http.StatusOK)
	if me.ElevatedUntil == nil || !me.ElevatedUntil.Equal(el.ElevatedUntil) {
		t.Fatalf("elevated_until %v, want %v", me.ElevatedUntil, el.ElevatedUntil)
	}

	e.Settings.Put("auth.passkeys", false)
	e.Settings.Put("sharing.links_enabled", false)
	me = decode[core.Me](t, c.do(http.MethodGet, "/me", nil), http.StatusOK)
	if me.Features["passkeys"] || me.Features["links"] || !me.Features["requests"] {
		t.Fatalf("features must follow the settings: %v", me.Features)
	}
}

// Guests only share when sharing.allow_guests_share is on (shares.Create
// refuses them otherwise). The client merges the page boot features with
// these, /me winning, so /me must apply the same rule as pages.features or a
// guest gets "My links" and "File requests" entries that end in a 403.
func TestMeGuestFeatures(t *testing.T) {
	e, h := server(t)
	e.AddUser(t, "gus", pw, core.RoleGuest)
	e.AddUser(t, "meg", pw, core.RoleMember)
	g := newClient(t, h)
	g.login("gus", pw)
	m := newClient(t, h)
	m.login("meg", pw)

	me := decode[core.Me](t, g.do(http.MethodGet, "/me", nil), http.StatusOK)
	if me.Features["links"] || me.Features["requests"] || !me.Features["passkeys"] {
		t.Fatalf("guest features without allow_guests_share: %v", me.Features)
	}
	if me = decode[core.Me](t, m.do(http.MethodGet, "/me", nil), http.StatusOK); !me.Features["links"] || !me.Features["requests"] {
		t.Fatalf("member features: %v", me.Features)
	}

	e.Settings.Put("sharing.allow_guests_share", true)
	if me = decode[core.Me](t, g.do(http.MethodGet, "/me", nil), http.StatusOK); !me.Features["links"] || !me.Features["requests"] {
		t.Fatalf("guest features with allow_guests_share: %v", me.Features)
	}
	// the global switches still win
	e.Settings.Put("sharing.requests_enabled", false)
	if me = decode[core.Me](t, g.do(http.MethodGet, "/me", nil), http.StatusOK); !me.Features["links"] || me.Features["requests"] {
		t.Fatalf("guest features with requests off: %v", me.Features)
	}
}

// GET /me has to answer at AuthLevel 1 — login.js fetches the CSRF token
// for the second-factor POST there — but a password-only session has not
// crossed the second-factor boundary yet. Somebody holding a stolen password
// alone must not learn the e-mail address that receives the security alerts,
// the role, the last-login IP or anything else from the profile.
func TestMeWithholdsTheProfileWhileTheSecondFactorIsPending(t *testing.T) {
	e, h := server(t)
	u := e.AddUser(t, "vera", pw, core.RoleAdmin)
	c := newClient(t, h)
	c.login("vera", pw)
	secret, _ := c.enrollTOTP(e)
	noContent(t, c.do(http.MethodPost, "/auth/logout", nil))
	if res := c.login("vera", pw); !res.MFARequired {
		t.Fatal("second factor expected")
	}

	var body struct {
		User  map[string]any  `json:"user"`
		CSRF  string          `json:"csrf"`
		MFA   *core.MFAStatus `json:"mfa"`
		Prefs json.RawMessage `json:"prefs"`
	}
	w := c.do(http.MethodGet, "/me", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("pending /me: %d", w.Code)
	}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	// What the login page needs stays.
	if body.CSRF == "" || body.MFA == nil || !body.MFA.TOTPEnabled {
		t.Fatalf("csrf %q mfa %+v", body.CSRF, body.MFA)
	}
	if body.User["id"] != u.ID || body.User["username"] != "vera" || body.User["mfa_enabled"] != true {
		t.Fatalf("reduced user %+v", body.User)
	}
	// Everything behind the boundary is gone.
	for _, k := range []string{"email", "last_login_ip", "last_login_at", "password_changed_at", "space_id", "created_by"} {
		if v, ok := body.User[k]; ok {
			t.Fatalf("pending /me leaks user.%s = %v", k, v)
		}
	}
	if body.User["role"] != "" {
		t.Fatalf("pending /me leaks the role: %v", body.User["role"])
	}
	if s := w.Body.String(); strings.Contains(s, "vera@example.test") || strings.Contains(s, "192.0.2.10") {
		t.Fatalf("pending /me body leaks the profile: %s", s)
	}
	if string(body.Prefs) != "{}" {
		t.Fatalf("prefs %s", body.Prefs)
	}

	// After the second factor the full profile is back.
	full := decode[core.LoginResult](t, c.do(http.MethodPost, "/auth/totp",
		core.CodeInput{Code: totpCode(t, secret, e.Clock.Now())}), http.StatusOK)
	if full.User == nil {
		t.Fatal("totp step")
	}
	c.csrf = full.CSRF
	me := decode[core.Me](t, c.do(http.MethodGet, "/me", nil), http.StatusOK)
	if me.MFAPending || me.User == nil || me.User.Email != "vera@example.test" || me.User.Role != core.RoleAdmin || me.SpaceID == "" {
		t.Fatalf("full /me %+v", me.User)
	}
}

func TestMeInProcessPrincipal(t *testing.T) {
	e, h := server(t)
	u := e.AddUser(t, "otto", pw, core.RoleAdmin)
	c := newClient(t, h)
	c.principal = core.SystemPrincipal(core.ViaSocket)

	me := decode[core.Me](t, c.do(http.MethodGet, "/me", nil), http.StatusOK)
	if me.User == nil || me.User.Role != core.RoleSystem || me.CSRF != "" || me.Via != core.ViaSocket || me.ElevatedUntil != nil {
		t.Fatalf("system /me %+v", me)
	}
	// the bare system principal has no account
	errCode(t, c.do(http.MethodGet, "/me/sessions", nil), http.StatusUnprocessableEntity, "invalid")

	// X-FP-As: act as a user
	c.header = http.Header{mw.HeaderActAs: {"otto"}}
	me = decode[core.Me](t, c.do(http.MethodGet, "/me", nil), http.StatusOK)
	if me.User == nil || me.User.ID != u.ID || me.CSRF != "" || me.Via != core.ViaSocket {
		t.Fatalf("act-as /me %+v", me)
	}
	c.header = http.Header{mw.HeaderActAs: {"otto"}}
	decode[core.Page[core.Session]](t, c.do(http.MethodGet, "/me/sessions", nil), http.StatusOK)
	// in-process callers skip CSRF and may manage credentials (elevated)
	c.header = http.Header{mw.HeaderActAs: {"otto"}}
	created := decode[core.TokenCreated](t, c.do(http.MethodPost, "/me/tokens", core.TokenInput{Name: "cli", Scopes: []string{core.ScopeAdmin}}), http.StatusCreated)
	if created.Token.UserID != u.ID || !strings.HasPrefix(created.Secret, auth.TokenPrefix) {
		t.Fatalf("token %+v", created)
	}
}

// ---------- profile ----------

func TestProfile(t *testing.T) {
	e, h := server(t)
	e.AddUser(t, "pia", pw, core.RoleMember)
	c := newClient(t, h)
	c.login("pia", pw)
	c.elevate(core.ElevateInput{Password: pw}) // a new e-mail address needs step-up
	u := decode[core.User](t, c.do(http.MethodPatch, "/me/profile",
		map[string]any{"display_name": "Pia P.", "email": "pia@example.org", "prefs": map[string]any{"theme": "dark"}}), http.StatusOK)
	if u.DisplayName != "Pia P." || u.Email != "pia@example.org" || !strings.Contains(string(u.Prefs), "dark") {
		t.Fatalf("updated %+v", u)
	}
	me := decode[core.Me](t, c.do(http.MethodGet, "/me", nil), http.StatusOK)
	if !strings.Contains(string(me.Prefs), `"theme":"dark"`) || me.User.DisplayName != "Pia P." {
		t.Fatalf("/me after update %+v prefs %s", me.User, me.Prefs)
	}
	// admin-only fields cannot be smuggled in
	for _, body := range []map[string]any{{"role": "admin"}, {"quota_bytes": 0}, {"must_change_password": false}} {
		errCode(t, c.do(http.MethodPatch, "/me/profile", body), http.StatusUnprocessableEntity, "invalid")
	}
	if got, _ := e.Users.Get(context.Background(), u.ID); got.Role != core.RoleMember {
		t.Fatalf("role changed to %s", got.Role)
	}
}

// The e-mail address receives the security alerts, so a session that
// changes (or removes) it must step up first — otherwise a hijacked session
// could redirect the alert about the passkey it adds next — and the previous
// address is told. The rest of the profile needs no step-up, and neither does
// the unchanged address the profile form always sends along.
func TestEmailChangeNeedsStepUpAndAlertsTheOldAddress(t *testing.T) {
	n := &recordingNotify{enabled: true}
	e, h := server(t, func(d *app.Deps) { d.Notify = n })
	u := e.AddUser(t, "emil", pw, core.RoleMember)
	c := newClient(t, h)
	c.login("emil", pw)

	decode[core.User](t, c.do(http.MethodPatch, "/me/profile",
		map[string]any{"display_name": "Emil", "email": "Emil@Example.test"}), http.StatusOK)
	decode[core.User](t, c.do(http.MethodPatch, "/me/profile",
		map[string]any{"prefs": map[string]any{"theme": "dark"}}), http.StatusOK)
	for _, email := range []string{"attacker@evil.example", ""} {
		errCode(t, c.do(http.MethodPatch, "/me/profile",
			map[string]any{"display_name": "Mallory", "email": email}), http.StatusForbidden, "elevation_required")
	}
	if got, _ := e.Users.Get(context.Background(), u.ID); !strings.EqualFold(got.Email, "emil@example.test") || got.DisplayName != "Emil" {
		t.Fatalf("refused change applied: %q %q", got.Email, got.DisplayName)
	}
	if got := n.sent(); len(got) != 0 {
		t.Fatalf("alerts without an address change: %+v", got)
	}

	c.elevate(core.ElevateInput{Password: pw})
	if nu := decode[core.User](t, c.do(http.MethodPatch, "/me/profile", map[string]any{"email": "emil@example.org"}), http.StatusOK); nu.Email != "emil@example.org" {
		t.Fatalf("email %q", nu.Email)
	}
	decode[core.User](t, c.do(http.MethodPatch, "/me/profile", map[string]any{"email": ""}), http.StatusOK)
	got := n.sent()
	if len(got) != 2 {
		t.Fatalf("expected two alerts, got %+v", got)
	}
	for i, want := range []struct{ to, name string }{{"emil@example.test", "e***@example.org"}, {"emil@example.org", ""}} {
		m := got[i]
		if m.tmpl != "security_alert" || len(m.to) != 1 || !strings.EqualFold(m.to[0], want.to) ||
			m.data["kind"] != "email_changed" || m.data["name"] != want.name || m.data["username"] != "emil" {
			t.Errorf("alert %d: to %v tmpl %q data %+v", i, m.to, m.tmpl, m.data)
		}
	}
}

// ---------- password ----------

func TestPasswordChange(t *testing.T) {
	e, h := server(t)
	e.AddUser(t, "quin", pw, core.RoleMember)
	c := newClient(t, h)
	c.login("quin", pw)
	other := newClient(t, h)
	other.ip = "192.0.2.77"
	other.login("quin", pw)
	before := c.token

	f := errCode(t, c.do(http.MethodPost, "/me/password", core.PasswordChangeInput{CurrentPassword: "not it", NewPassword: newPW}), http.StatusUnprocessableEntity, "invalid")
	if f.Field != "current_password" {
		t.Fatalf("field %q", f.Field)
	}
	f = errCode(t, c.do(http.MethodPost, "/me/password", core.PasswordChangeInput{CurrentPassword: pw, NewPassword: "short"}), http.StatusUnprocessableEntity, "invalid")
	if f.Field != "new_password" {
		t.Fatalf("field %q", f.Field)
	}
	errCode(t, c.do(http.MethodPost, "/me/password", core.PasswordChangeInput{CurrentPassword: pw, NewPassword: pw}), http.StatusUnprocessableEntity, "invalid")

	res := decode[core.LoginResult](t, c.do(http.MethodPost, "/me/password", core.PasswordChangeInput{CurrentPassword: pw, NewPassword: newPW}), http.StatusOK)
	if res.CSRF == "" || res.User == nil || c.token == before || c.token == "" {
		t.Fatalf("password change must rotate the session: %+v (rotated %v)", res, c.token != before)
	}
	c.csrf = res.CSRF
	// the current session continues with the new cookie, the others are gone
	decode[core.Me](t, c.do(http.MethodGet, "/me", nil), http.StatusOK)
	noContent(t, c.do(http.MethodPost, "/me/sessions/revoke-others", nil))
	errCode(t, other.do(http.MethodGet, "/me", nil), http.StatusUnauthorized, "unauthorized")
	stale := newClient(t, h)
	stale.token = before
	errCode(t, stale.do(http.MethodGet, "/me", nil), http.StatusUnauthorized, "unauthorized")

	errCode(t, newClient(t, h).do(http.MethodPost, "/auth/login", core.LoginInput{Username: "quin", Password: pw}), http.StatusUnauthorized, "unauthorized")
	newClient(t, h).login("quin", newPW)
	if n := e.Audit.Count(core.ActUserPasswordChange, core.OutcomeSuccess); n != 1 {
		t.Fatalf("user.password_change audits: %d", n)
	}
	if n := e.Audit.Count(core.ActUserPasswordChange, core.OutcomeFailure); n != 1 {
		t.Fatalf("failed password change audits: %d", n)
	}
}

func TestPasswordChangeRateLimit(t *testing.T) {
	e, h := server(t)
	e.AddUser(t, "rhea", pw, core.RoleMember)
	c := newClient(t, h)
	c.login("rhea", pw)
	e.Settings.Put("ratelimit.login_per_min", 2)
	e.Limiter.ApplySettings()
	for range 2 {
		errCode(t, c.do(http.MethodPost, "/me/password", core.PasswordChangeInput{CurrentPassword: "guess guess", NewPassword: newPW}), http.StatusUnprocessableEntity, "invalid")
	}
	w := c.do(http.MethodPost, "/me/password", core.PasswordChangeInput{CurrentPassword: pw, NewPassword: newPW})
	errCode(t, w, http.StatusTooManyRequests, "rate_limited")
	if ra := w.Header().Get("Retry-After"); ra == "" || ra == "0" {
		t.Fatalf("Retry-After %q", ra)
	}
	e.Clock.Advance(time.Minute)
	decode[core.LoginResult](t, c.do(http.MethodPost, "/me/password", core.PasswordChangeInput{CurrentPassword: pw, NewPassword: newPW}), http.StatusOK)
}

func TestTokensCannotManageCredentials(t *testing.T) {
	e, h := server(t)
	e.AddUser(t, "sven", pw, core.RoleMember)
	c := newClient(t, h)
	c.login("sven", pw)
	created := decode[core.TokenCreated](t, c.do(http.MethodPost, "/me/tokens", core.TokenInput{Name: "all", Scopes: []string{core.ScopeFilesRead, core.ScopeFilesWrite, core.ScopeShares}}), http.StatusCreated)
	b := newClient(t, h)
	b.bearer = created.Secret
	for _, rt := range []struct {
		method, path string
		body         any
	}{
		{http.MethodPost, "/me/password", core.PasswordChangeInput{CurrentPassword: pw, NewPassword: newPW}},
		{http.MethodPost, "/me/totp/begin", nil},
		{http.MethodPost, "/me/totp/confirm", core.CodeInput{Code: "123456"}},
		{http.MethodDelete, "/me/totp", nil},
		{http.MethodPost, "/me/recovery-codes", nil},
		{http.MethodGet, "/me/passkeys", nil},
		{http.MethodPost, "/me/passkeys/begin", nil},
		{http.MethodPost, "/me/passkeys/finish", nil},
		{http.MethodPatch, "/me/passkeys/pk_x", core.NameInput{Name: "x"}},
		{http.MethodDelete, "/me/passkeys/pk_x", nil},
		// browser sessions: their addresses, and signing the owner out everywhere
		{http.MethodGet, "/me/sessions", nil},
		{http.MethodDelete, "/me/sessions/ses_x", nil},
		{http.MethodPost, "/me/sessions/revoke-others", nil},
	} {
		errCode(t, b.do(rt.method, rt.path, rt.body), http.StatusForbidden, "forbidden")
	}
	decode[core.Page[core.Session]](t, c.do(http.MethodGet, "/me/sessions", nil), http.StatusOK) // still signed in
	// The e-mail address receives the security alerts (and the display name
	// is what the pickers show), so a token cannot change either — otherwise
	// a leaked read-only token could redirect the alerts about its own use.
	email := "attacker@evil.example"
	name := "Someone Else"
	for _, in := range []core.ProfileUpdate{{Email: &email}, {DisplayName: &name}} {
		errCode(t, b.do(http.MethodPatch, "/me/profile", in), http.StatusForbidden, "forbidden")
	}
	me := decode[core.Me](t, c.do(http.MethodGet, "/me", nil), http.StatusOK)
	if me.User == nil || me.User.Email == email || me.User.DisplayName == name {
		t.Fatalf("token changed the identity fields: %+v", me.User)
	}
	// preferences stay writable (script clients sync them)
	decode[core.User](t, b.do(http.MethodPatch, "/me/profile", core.ProfileUpdate{Prefs: json.RawMessage(`{"theme":"dark"}`)}), http.StatusOK)

	// but the rest of /me works without CSRF
	decode[core.Page[core.APIToken]](t, b.do(http.MethodGet, "/me/tokens", nil), http.StatusOK)
	decode[core.Usage](t, b.do(http.MethodGet, "/me/usage", nil), http.StatusOK)
}

// ---------- sessions ----------

func TestSessions(t *testing.T) {
	e, h := server(t)
	e.AddUser(t, "tess", pw, core.RoleMember)
	e.AddUser(t, "ugo", pw, core.RoleMember)
	c := newClient(t, h)
	c.login("tess", pw)
	c2 := newClient(t, h)
	c2.ip = "198.51.100.2"
	c2.header = http.Header{"User-Agent": {"second-browser"}}
	c2.login("tess", pw)
	stranger := newClient(t, h)
	stranger.login("ugo", pw)

	page := decode[core.Page[core.Session]](t, c.do(http.MethodGet, "/me/sessions", nil), http.StatusOK)
	if len(page.Items) != 2 {
		t.Fatalf("sessions %+v", page.Items)
	}
	var mine, theirs core.Session
	for _, s := range page.Items {
		if s.Current {
			mine = s
		} else {
			theirs = s
		}
	}
	if mine.ID == "" || theirs.ID == "" || theirs.IP != "198.51.100.2" || theirs.UserAgent != "second-browser" {
		t.Fatalf("sessions %+v / %+v", mine, theirs)
	}
	if strings.Contains(c.do(http.MethodGet, "/me/sessions", nil).Body.String(), "csrf_secret") {
		t.Fatal("session secrets leaked")
	}

	noContent(t, c.do(http.MethodDelete, "/me/sessions/"+theirs.ID, nil))
	errCode(t, c2.do(http.MethodGet, "/me", nil), http.StatusUnauthorized, "unauthorized")
	errCode(t, c.do(http.MethodDelete, "/me/sessions/"+theirs.ID, nil), http.StatusNotFound, "not_found")
	errCode(t, c.do(http.MethodDelete, "/me/sessions/ses_unknown", nil), http.StatusNotFound, "not_found")

	// another user's session is not found (no IDOR)
	sp := decode[core.Page[core.Session]](t, stranger.do(http.MethodGet, "/me/sessions", nil), http.StatusOK)
	errCode(t, c.do(http.MethodDelete, "/me/sessions/"+sp.Items[0].ID, nil), http.StatusNotFound, "not_found")
	decode[core.Me](t, stranger.do(http.MethodGet, "/me", nil), http.StatusOK)

	// revoking the current session signs out and deletes the cookie
	noContent(t, c.do(http.MethodDelete, "/me/sessions/"+mine.ID, nil))
	if c.cookie == nil || c.cookie.MaxAge >= 0 || c.token != "" {
		t.Fatalf("cookie not cleared: %+v", c.cookie)
	}
	if n := e.Audit.Count(core.ActSessionRevoke, core.OutcomeSuccess); n != 2 {
		t.Fatalf("session.revoke audits: %d", n)
	}
}

// ---------- MFA ----------

func TestTOTPAndRecoveryCodes(t *testing.T) {
	e, h := server(t)
	e.AddUser(t, "vic", pw, core.RoleMember)
	c := newClient(t, h)
	c.login("vic", pw)

	st := decode[core.MFAStatus](t, c.do(http.MethodGet, "/me/mfa", nil), http.StatusOK)
	if st.TOTPEnabled || st.TOTPPending || st.RecoveryCodesLeft != 0 || st.PasskeyCount != 0 {
		t.Fatalf("initial %+v", st)
	}
	// a confirmed authenticator satisfies step-up, so setting one up needs it
	errCode(t, c.do(http.MethodPost, "/me/totp/begin", nil), http.StatusForbidden, "elevation_required")
	errCode(t, c.do(http.MethodPost, "/me/totp/confirm", core.CodeInput{Code: "123456"}), http.StatusForbidden, "elevation_required")
	c.elevate(core.ElevateInput{Password: pw})
	errCode(t, c.do(http.MethodPost, "/me/totp/confirm", core.CodeInput{Code: "123456"}), http.StatusConflict, "conflict")
	en := decode[core.TOTPEnrollment](t, c.do(http.MethodPost, "/me/totp/begin", nil), http.StatusOK)
	if en.Secret == "" || !strings.HasPrefix(en.OTPAuthURI, "otpauth://totp/") || !strings.HasPrefix(en.QRDataURI, "data:image/svg+xml") {
		t.Fatalf("enrollment %+v", en)
	}
	if st = decode[core.MFAStatus](t, c.do(http.MethodGet, "/me/mfa", nil), http.StatusOK); !st.TOTPPending {
		t.Fatalf("pending %+v", st)
	}
	good := totpCode(t, en.Secret, e.Clock.Now())
	bad := "000000"
	if bad == good {
		bad = "999999"
	}
	errCode(t, c.do(http.MethodPost, "/me/totp/confirm", core.CodeInput{Code: bad}), http.StatusUnprocessableEntity, "invalid")
	rc := decode[core.RecoveryCodes](t, c.do(http.MethodPost, "/me/totp/confirm", core.CodeInput{Code: good}), http.StatusOK)
	if len(rc.RecoveryCodes) != auth.RecoveryCodeCount || len(rc.RecoveryCodes[0]) != 9 || rc.RecoveryCodes[0][4] != '-' {
		t.Fatalf("recovery codes %q", rc.RecoveryCodes)
	}
	st = decode[core.MFAStatus](t, c.do(http.MethodGet, "/me/mfa", nil), http.StatusOK)
	if !st.TOTPEnabled || st.TOTPPending || st.RecoveryCodesLeft != auth.RecoveryCodeCount {
		t.Fatalf("enabled %+v", st)
	}
	errCode(t, c.do(http.MethodPost, "/me/totp/begin", nil), http.StatusConflict, "conflict")

	// (E) routes, once the step-up window of the setup has closed
	e.Clock.Advance(11 * time.Minute)
	errCode(t, c.do(http.MethodPost, "/me/recovery-codes", nil), http.StatusForbidden, "elevation_required")
	errCode(t, c.do(http.MethodDelete, "/me/totp", nil), http.StatusForbidden, "elevation_required")
	e.Clock.Advance(30 * time.Second)
	c.elevate(core.ElevateInput{TOTP: totpCode(t, en.Secret, e.Clock.Now())})
	again := decode[core.RecoveryCodes](t, c.do(http.MethodPost, "/me/recovery-codes", nil), http.StatusOK)
	if len(again.RecoveryCodes) != auth.RecoveryCodeCount || slices.Contains(again.RecoveryCodes, rc.RecoveryCodes[0]) {
		t.Fatalf("regenerated %q", again.RecoveryCodes)
	}
	noContent(t, c.do(http.MethodDelete, "/me/totp", nil))
	st = decode[core.MFAStatus](t, c.do(http.MethodGet, "/me/mfa", nil), http.StatusOK)
	if st.TOTPEnabled || st.RecoveryCodesLeft != 0 {
		t.Fatalf("after disable %+v", st)
	}
	errCode(t, c.do(http.MethodDelete, "/me/totp", nil), http.StatusNotFound, "not_found")
	for _, act := range []string{core.ActMFATOTPEnable, core.ActMFARecoveryRegenerate, core.ActMFATOTPDisable} {
		if e.Audit.Count(act, core.OutcomeSuccess) != 1 {
			t.Errorf("%s not audited once", act)
		}
	}
}

func TestEnrollmentRequired(t *testing.T) {
	e, h := server(t)
	e.AddUser(t, "wanda", pw, core.RoleAdmin) // auth.require_2fa defaults to admins
	c := newClient(t, h)
	if res := c.login("wanda", pw); !res.EnrollRequired {
		t.Fatalf("login %+v", res)
	}
	me := decode[core.Me](t, c.do(http.MethodGet, "/me", nil), http.StatusOK)
	if me.MFA == nil || !me.MFA.Required || !me.MFA.EnrollRequired {
		t.Fatalf("mfa %+v", me.MFA)
	}
	// /me* works, minting long-lived credentials does not
	decode[core.Page[core.Session]](t, c.do(http.MethodGet, "/me/sessions", nil), http.StatusOK)
	decode[core.User](t, c.do(http.MethodPatch, "/me/profile", map[string]any{"display_name": "W"}), http.StatusOK)
	errCode(t, c.do(http.MethodPost, "/me/tokens", core.TokenInput{Name: "x", Scopes: []string{core.ScopeFilesRead}}), http.StatusForbidden, "mfa_enroll_required")

	c.enrollTOTP(e)
	me = decode[core.Me](t, c.do(http.MethodGet, "/me", nil), http.StatusOK)
	if me.MFA.EnrollRequired || !me.User.MFAEnabled {
		t.Fatalf("after enrollment %+v", me.MFA)
	}
	decode[core.TokenCreated](t, c.do(http.MethodPost, "/me/tokens", core.TokenInput{Name: "x", Scopes: []string{core.ScopeFilesRead}}), http.StatusCreated)
}

// A password set by an administrator or the installer (must_change_password)
// has to be replaced before the account is used: the server, not just the
// web UI, keeps such a session to what changing it needs (/me*, /auth/*) —
// no other route, and no new API token that would outlive the password.
// Tokens minted before the flag was set are not affected.
func TestMustChangePasswordGate(t *testing.T) {
	e, h := server(t)
	u := e.AddUser(t, "moe", pw, core.RoleMember)
	c := newClient(t, h)
	c.login("moe", pw)
	noContent(t, c.do(http.MethodGet, "/probe", nil))
	tok := decode[core.TokenCreated](t, c.do(http.MethodPost, "/me/tokens",
		core.TokenInput{Name: "ci", Scopes: []string{core.ScopeFilesRead}}), http.StatusCreated)
	if _, err := e.DB.Exec(context.Background(), `UPDATE users SET must_change_password = 1 WHERE id = ?`, u.ID); err != nil {
		t.Fatal(err) // what "fileparcel user edit moe --must-change" does
	}

	errCode(t, c.do(http.MethodGet, "/probe", nil), http.StatusForbidden, "password_change_required")
	errCode(t, c.do(http.MethodPost, "/me/tokens", core.TokenInput{Name: "x", Scopes: []string{core.ScopeFilesRead}}),
		http.StatusForbidden, "password_change_required")
	if me := decode[core.Me](t, c.do(http.MethodGet, "/me", nil), http.StatusOK); !me.User.MustChangePassword {
		t.Fatalf("/me %+v", me.User)
	}
	decode[core.Page[core.Session]](t, c.do(http.MethodGet, "/me/sessions", nil), http.StatusOK)
	decode[core.MFAStatus](t, c.do(http.MethodGet, "/me/mfa", nil), http.StatusOK)
	b := newClient(t, h)
	b.bearer = tok.Secret
	noContent(t, b.do(http.MethodGet, "/probe", nil))

	res := decode[core.LoginResult](t, c.do(http.MethodPost, "/me/password",
		core.PasswordChangeInput{CurrentPassword: pw, NewPassword: newPW}), http.StatusOK)
	c.csrf = res.CSRF
	noContent(t, c.do(http.MethodGet, "/probe", nil))

	// An administrator's reset with a generated password: the next sign-in is gated too.
	if err := e.Auth.AdminSetPassword(context.Background(), core.SystemPrincipal(core.ViaSocket), u.ID, pw, true); err != nil {
		t.Fatal(err)
	}
	n := newClient(t, h)
	if lr := n.login("moe", pw); !lr.MustChangePassword && (lr.User == nil || !lr.User.MustChangePassword) {
		t.Fatalf("login %+v", lr)
	}
	errCode(t, n.do(http.MethodGet, "/probe", nil), http.StatusForbidden, "password_change_required")
	noContent(t, n.do(http.MethodPost, "/auth/logout", nil))
}

// ---------- passkeys ----------

func TestPasskeys(t *testing.T) {
	e, h := server(t)
	e.AddUser(t, "xia", pw, core.RoleMember)
	e.AddUser(t, "yves", pw, core.RoleMember)
	a := &authtest.Authenticator{Origin: origin, UV: true}
	c := newClient(t, h)
	c.login("xia", pw)

	// a passkey signs in on its own and satisfies step-up: registering one needs step-up
	errCode(t, c.do(http.MethodPost, "/me/passkeys/begin", nil), http.StatusForbidden, "elevation_required")
	errCode(t, c.do(http.MethodPost, "/me/passkeys/finish", core.PasskeyFinishInput{FlowID: "x"}), http.StatusForbidden, "elevation_required")
	c.elevate(core.ElevateInput{Password: pw})
	begin := decode[core.PasskeyBegin](t, c.do(http.MethodPost, "/me/passkeys/begin", nil), http.StatusOK)
	if begin.FlowID == "" || !strings.Contains(string(begin.Options), `"publicKey"`) {
		t.Fatalf("begin %+v", begin)
	}
	cred, err := a.Create(begin.Options)
	if err != nil {
		t.Fatal(err)
	}
	errCode(t, c.do(http.MethodPost, "/me/passkeys/finish", core.PasskeyFinishInput{FlowID: begin.FlowID}), http.StatusUnprocessableEntity, "invalid")
	errCode(t, c.do(http.MethodPost, "/me/passkeys/finish", core.PasskeyFinishInput{FlowID: begin.FlowID, Credential: json.RawMessage(`{"id":"garbage"}`)}), http.StatusUnprocessableEntity, "invalid")
	// the flow is single-use: the failed attempt consumed it
	errCode(t, c.do(http.MethodPost, "/me/passkeys/finish", core.PasskeyFinishInput{FlowID: begin.FlowID, Credential: cred}), http.StatusUnprocessableEntity, "invalid")

	begin = decode[core.PasskeyBegin](t, c.do(http.MethodPost, "/me/passkeys/begin", nil), http.StatusOK)
	if cred, err = a.Create(begin.Options); err != nil {
		t.Fatal(err)
	}
	pk := decode[core.Passkey](t, c.do(http.MethodPost, "/me/passkeys/finish", core.PasskeyFinishInput{FlowID: begin.FlowID, Credential: cred}), http.StatusCreated)
	if pk.Name != "Passkey" || pk.RPID != "fileparcel.local" || pk.ID == "" {
		t.Fatalf("passkey %+v", pk)
	}
	list := decode[core.Page[core.Passkey]](t, c.do(http.MethodGet, "/me/passkeys", nil), http.StatusOK)
	if len(list.Items) != 1 || list.Items[0].ID != pk.ID {
		t.Fatalf("list %+v", list)
	}
	if st := decode[core.MFAStatus](t, c.do(http.MethodGet, "/me/mfa", nil), http.StatusOK); st.PasskeyCount != 1 {
		t.Fatalf("mfa %+v", st)
	}

	noContent(t, c.do(http.MethodPatch, "/me/passkeys/"+pk.ID, core.NameInput{Name: "Laptop"}))
	for _, bad := range []string{"", "   ", "tab\there", strings.Repeat("n", 65)} {
		errCode(t, c.do(http.MethodPatch, "/me/passkeys/"+pk.ID, core.NameInput{Name: bad}), http.StatusUnprocessableEntity, "invalid")
	}
	if list = decode[core.Page[core.Passkey]](t, c.do(http.MethodGet, "/me/passkeys", nil), http.StatusOK); list.Items[0].Name != "Laptop" {
		t.Fatalf("renamed %+v", list.Items[0])
	}

	// another user can neither see nor change it (404, no existence leak)
	y := newClient(t, h)
	y.login("yves", pw)
	if l := decode[core.Page[core.Passkey]](t, y.do(http.MethodGet, "/me/passkeys", nil), http.StatusOK); len(l.Items) != 0 {
		t.Fatalf("stranger sees %+v", l.Items)
	}
	errCode(t, y.do(http.MethodPatch, "/me/passkeys/"+pk.ID, core.NameInput{Name: "mine"}), http.StatusNotFound, "not_found")
	y.elevate(core.ElevateInput{Password: pw})
	errCode(t, y.do(http.MethodDelete, "/me/passkeys/"+pk.ID, nil), http.StatusNotFound, "not_found")

	// deleting needs the step-up window (the one of the registration has closed)
	e.Clock.Advance(11 * time.Minute)
	errCode(t, c.do(http.MethodDelete, "/me/passkeys/"+pk.ID, nil), http.StatusForbidden, "elevation_required")
	c.elevate(core.ElevateInput{Password: pw})
	noContent(t, c.do(http.MethodDelete, "/me/passkeys/"+pk.ID, nil))
	if l := decode[core.Page[core.Passkey]](t, c.do(http.MethodGet, "/me/passkeys", nil), http.StatusOK); len(l.Items) != 0 {
		t.Fatalf("after delete %+v", l.Items)
	}
	errCode(t, c.do(http.MethodDelete, "/me/passkeys/"+pk.ID, nil), http.StatusNotFound, "not_found")
	if e.Audit.Count(core.ActPasskeyAdd, core.OutcomeSuccess) != 1 || e.Audit.Count(core.ActPasskeyRemove, core.OutcomeSuccess) != 1 {
		t.Fatal("passkey.add / passkey.remove not audited")
	}

	e.Settings.Put("auth.passkeys", false)
	errCode(t, c.do(http.MethodPost, "/me/passkeys/begin", nil), http.StatusForbidden, "forbidden")
}

// passkeyCreated mirrors the body of POST /me/passkeys/finish.
type passkeyCreated struct {
	core.Passkey
	RecoveryCodes []string `json:"recovery_codes"`
}

// addPasskey runs a full registration ceremony for the signed-in client
// (after a password step-up, which registering needs).
func (c *client) addPasskey(a *authtest.Authenticator, name string) passkeyCreated {
	c.t.Helper()
	c.elevate(core.ElevateInput{Password: pw})
	begin := decode[core.PasskeyBegin](c.t, c.do(http.MethodPost, "/me/passkeys/begin", nil), http.StatusOK)
	cred, err := a.Create(begin.Options)
	if err != nil {
		c.t.Fatal(err)
	}
	return decode[passkeyCreated](c.t, c.do(http.MethodPost, "/me/passkeys/finish",
		core.PasskeyFinishInput{FlowID: begin.FlowID, Credential: cred, Name: name}), http.StatusCreated)
}

// A passkey is not an out-of-band factor: an account whose only second
// factor is a passkey cannot sign in at all once an administrator turns
// auth.passkeys off, and nothing short of "fileparcel user reset-mfa" over
// the admin socket brings it back. The first passkey therefore comes with
// recovery codes, shown once like POST /me/totp/confirm shows them.
func TestFirstPasskeyHandsOutRecoveryCodes(t *testing.T) {
	e, h := server(t)
	e.AddUser(t, "zoe", pw, core.RoleMember)
	c := newClient(t, h)
	c.login("zoe", pw)

	first := c.addPasskey(&authtest.Authenticator{Origin: origin, UV: true}, "Key")
	if len(first.RecoveryCodes) != auth.RecoveryCodeCount {
		t.Fatalf("first passkey handed out %d recovery codes", len(first.RecoveryCodes))
	}
	st := decode[core.MFAStatus](t, c.do(http.MethodGet, "/me/mfa", nil), http.StatusOK)
	if st.PasskeyCount != 1 || st.RecoveryCodesLeft != auth.RecoveryCodeCount {
		t.Fatalf("mfa %+v", st)
	}
	// A second passkey must not invalidate the codes the user wrote down.
	second := c.addPasskey(&authtest.Authenticator{Origin: origin, UV: true}, "Phone")
	if len(second.RecoveryCodes) != 0 {
		t.Fatalf("second passkey replaced the recovery codes: %v", second.RecoveryCodes)
	}
	if st = decode[core.MFAStatus](t, c.do(http.MethodGet, "/me/mfa", nil), http.StatusOK); st.RecoveryCodesLeft != auth.RecoveryCodeCount {
		t.Fatalf("codes left %d", st.RecoveryCodesLeft)
	}
	// With passkeys turned off the account still has a usable second factor.
	e.Settings.Put("auth.passkeys", false)
	res := newClient(t, h).login("zoe", pw)
	if !res.MFARequired || !slices.Contains(res.Methods, core.MFARecovery) {
		t.Fatalf("passkeys off: methods %v", res.Methods)
	}
}

// ---------- API tokens ----------

func TestTokens(t *testing.T) {
	e, h := server(t)
	e.AddUser(t, "zack", pw, core.RoleMember)
	e.AddUser(t, "zora", pw, core.RoleMember)
	c := newClient(t, h)
	c.login("zack", pw)

	for _, in := range []core.TokenInput{
		{Name: "", Scopes: []string{core.ScopeFilesRead}},
		{Name: "x", Scopes: nil},
		{Name: "x", Scopes: []string{"files:delete"}},
		{Name: "x", Scopes: []string{core.ScopeAdmin}}, // not an administrator
		{Name: "x", Scopes: []string{core.ScopeFilesRead}, ExpiresAt: new(e.Clock.Now().Add(-time.Hour))},
		{Name: "x", Scopes: []string{core.ScopeFilesRead}, Elevated: true},
	} {
		errCode(t, c.do(http.MethodPost, "/me/tokens", in), http.StatusUnprocessableEntity, "invalid")
	}
	// creating a token for someone else needs an administrator
	errCode(t, c.do(http.MethodPost, "/me/tokens", core.TokenInput{Name: "x", Scopes: []string{core.ScopeFilesRead}, UserID: "usr_other"}), http.StatusForbidden, "forbidden")

	exp := e.Clock.Now().Add(48 * time.Hour).Truncate(time.Millisecond)
	created := decode[core.TokenCreated](t, c.do(http.MethodPost, "/me/tokens", core.TokenInput{Name: "backup script", Scopes: []string{core.ScopeFilesWrite, core.ScopeFilesRead}, ExpiresAt: &exp}), http.StatusCreated)
	tok := created.Token
	if !strings.HasPrefix(created.Secret, auth.TokenPrefix) || tok.Name != "backup script" || !slices.Equal(tok.Scopes, []string{core.ScopeFilesRead, core.ScopeFilesWrite}) ||
		tok.ExpiresAt == nil || !tok.ExpiresAt.Equal(exp) || tok.Elevated {
		t.Fatalf("created %+v", created)
	}
	list := decode[core.Page[core.APIToken]](t, c.do(http.MethodGet, "/me/tokens", nil), http.StatusOK)
	if len(list.Items) != 1 || list.Items[0].ID != tok.ID {
		t.Fatalf("list %+v", list.Items)
	}
	if body := c.do(http.MethodGet, "/me/tokens", nil).Body.String(); strings.Contains(body, created.Secret) || strings.Contains(body, "token_hash") {
		t.Fatal("token list leaks the secret")
	}

	// the token authenticates, cannot widen its scopes, and can be revoked
	b := newClient(t, h)
	b.bearer = created.Secret
	if me := decode[core.Me](t, b.do(http.MethodGet, "/me", nil), http.StatusOK); me.Via != core.ViaToken || me.User.Username != "zack" {
		t.Fatalf("bearer /me %+v", me)
	}
	errCode(t, b.do(http.MethodPost, "/me/tokens", core.TokenInput{Name: "wider", Scopes: []string{core.ScopeShares}}), http.StatusForbidden, "forbidden")
	child := decode[core.TokenCreated](t, b.do(http.MethodPost, "/me/tokens", core.TokenInput{Name: "narrower", Scopes: []string{core.ScopeFilesRead}}), http.StatusCreated)

	// other users' tokens are invisible
	z := newClient(t, h)
	z.login("zora", pw)
	errCode(t, z.do(http.MethodDelete, "/me/tokens/"+tok.ID, nil), http.StatusNotFound, "not_found")
	if l := decode[core.Page[core.APIToken]](t, z.do(http.MethodGet, "/me/tokens", nil), http.StatusOK); len(l.Items) != 0 {
		t.Fatalf("stranger sees %+v", l.Items)
	}
	errCode(t, c.do(http.MethodDelete, "/me/tokens/tok_unknown", nil), http.StatusNotFound, "not_found")

	noContent(t, c.do(http.MethodDelete, "/me/tokens/"+tok.ID, nil))
	noContent(t, c.do(http.MethodDelete, "/me/tokens/"+tok.ID, nil)) // idempotent
	errCode(t, b.do(http.MethodGet, "/me", nil), http.StatusUnauthorized, "unauthorized")
	list = decode[core.Page[core.APIToken]](t, c.do(http.MethodGet, "/me/tokens", nil), http.StatusOK)
	if len(list.Items) != 2 {
		t.Fatalf("list %+v", list.Items)
	}
	for _, it := range list.Items {
		if (it.ID == tok.ID) != (it.RevokedAt != nil) {
			t.Fatalf("revocation state %+v", it)
		}
	}
	b.bearer = child.Secret
	decode[core.Me](t, b.do(http.MethodGet, "/me", nil), http.StatusOK)

	// expiry
	e.Clock.Advance(49 * time.Hour)
	b.bearer = created.Secret
	errCode(t, b.do(http.MethodGet, "/me", nil), http.StatusUnauthorized, "unauthorized")

	if e.Audit.Count(core.ActTokenCreate, core.OutcomeSuccess) != 2 || e.Audit.Count(core.ActTokenRevoke, core.OutcomeSuccess) != 1 {
		t.Fatal("token.create / token.revoke audits")
	}
}

// A token revokes itself and the tokens it could have minted, never a wider
// one: a leaked files:read token must not cut off the owner's other
// integrations (the remote "fileparcel token revoke" still works).
func TestTokenRevokesNoWiderToken(t *testing.T) {
	e, h := server(t)
	e.Settings.Put("auth.require_2fa", "off")
	e.AddUser(t, "ines", pw, core.RoleAdmin)
	c := newClient(t, h)
	c.login("ines", pw)
	mk := func(name string, in core.TokenInput) core.TokenCreated {
		in.Name = name
		return decode[core.TokenCreated](t, c.do(http.MethodPost, "/me/tokens", in), http.StatusCreated)
	}
	reader := mk("reader", core.TokenInput{Scopes: []string{core.ScopeFilesRead, core.ScopeShares}})
	narrow := mk("narrow", core.TokenInput{Scopes: []string{core.ScopeFilesRead}})
	wide := mk("wide", core.TokenInput{Scopes: []string{core.ScopeFilesRead, core.ScopeFilesWrite}})
	c.elevate(core.ElevateInput{Password: pw})
	admin := mk("admin", core.TokenInput{Scopes: []string{core.ScopeAdmin}})
	elevated := mk("elevated", core.TokenInput{Scopes: []string{core.ScopeAdmin}, Elevated: true, ExpiresAt: new(e.Clock.Now().Add(24 * time.Hour))})

	b := newClient(t, h)
	b.bearer = reader.Secret
	for _, tok := range []core.TokenCreated{wide, admin, elevated} {
		errCode(t, b.do(http.MethodDelete, "/me/tokens/"+tok.Token.ID, nil), http.StatusForbidden, "forbidden")
	}
	noContent(t, b.do(http.MethodDelete, "/me/tokens/"+narrow.Token.ID, nil))
	for _, tok := range []core.TokenCreated{wide, admin, elevated} {
		w := newClient(t, h)
		w.bearer = tok.Secret
		decode[core.Me](t, w.do(http.MethodGet, "/me", nil), http.StatusOK)
	}
	noContent(t, b.do(http.MethodDelete, "/me/tokens/"+reader.Token.ID, nil)) // itself
	errCode(t, b.do(http.MethodGet, "/me", nil), http.StatusUnauthorized, "unauthorized")
	// a browser session revokes any of its tokens
	noContent(t, c.do(http.MethodDelete, "/me/tokens/"+elevated.Token.ID, nil))
}

// A token of an account that still has to enrol a second factor cannot
// enrol (the enrollment routes refuse tokens), so every full route refuses
// it — /me* included — until the owner has enrolled in the web UI. GET /me
// and GET /me/mfa (RequireAuth) still answer, so the CLI can explain why.
func TestEnrollRequiredTokenIsRefused(t *testing.T) {
	e, h := server(t)
	e.Settings.Put("auth.require_2fa", "off")
	e.AddUser(t, "jan", pw, core.RoleMember)
	c := newClient(t, h)
	c.login("jan", pw)
	created := decode[core.TokenCreated](t, c.do(http.MethodPost, "/me/tokens",
		core.TokenInput{Name: "ci", Scopes: []string{core.ScopeFilesRead}}), http.StatusCreated)
	e.Settings.Put("auth.require_2fa", "all")

	b := newClient(t, h)
	b.bearer = created.Secret
	for _, rt := range []struct{ method, path string }{
		{http.MethodGet, "/me/tokens"}, {http.MethodGet, "/me/usage"}, {http.MethodDelete, "/me/tokens/" + created.Token.ID},
	} {
		errCode(t, b.do(rt.method, rt.path, nil), http.StatusForbidden, "mfa_enroll_required")
	}
	if st := decode[core.MFAStatus](t, b.do(http.MethodGet, "/me/mfa", nil), http.StatusOK); !st.EnrollRequired {
		t.Fatalf("mfa %+v", st)
	}
	// the browser session keeps /me* for enrolling
	decode[core.Page[core.APIToken]](t, c.do(http.MethodGet, "/me/tokens", nil), http.StatusOK)
}

func TestAdminTokens(t *testing.T) {
	e, h := server(t)
	e.Settings.Put("auth.require_2fa", "off")
	ada := e.AddUser(t, "ada", pw, core.RoleAdmin)
	c := newClient(t, h)
	c.login("ada", pw)
	admin := core.TokenInput{Name: "ops", Scopes: []string{core.ScopeAdmin}}
	errCode(t, c.do(http.MethodPost, "/me/tokens", admin), http.StatusForbidden, "elevation_required")
	c.elevate(core.ElevateInput{Password: pw})
	plain := decode[core.TokenCreated](t, c.do(http.MethodPost, "/me/tokens", admin), http.StatusCreated)
	if plain.Token.Elevated {
		t.Fatal("not requested elevated")
	}

	admin.Elevated = true
	errCode(t, c.do(http.MethodPost, "/me/tokens", admin), http.StatusUnprocessableEntity, "invalid") // no expiry
	admin.ExpiresAt = new(e.Clock.Now().Add(31 * 24 * time.Hour))
	errCode(t, c.do(http.MethodPost, "/me/tokens", admin), http.StatusUnprocessableEntity, "invalid") // > 30 days
	admin.ExpiresAt = new(e.Clock.Now().Add(7 * 24 * time.Hour))
	el := decode[core.TokenCreated](t, c.do(http.MethodPost, "/me/tokens", admin), http.StatusCreated)
	if !el.Token.Elevated {
		t.Fatalf("elevated token %+v", el.Token)
	}

	b := newClient(t, h)
	b.bearer = plain.Secret
	if me := decode[core.Me](t, b.do(http.MethodGet, "/me", nil), http.StatusOK); me.ElevatedUntil != nil {
		t.Fatal("plain admin token must not be elevated")
	}
	b.bearer = el.Secret
	if me := decode[core.Me](t, b.do(http.MethodGet, "/me", nil), http.StatusOK); me.ElevatedUntil == nil {
		t.Fatal("elevated token must count as elevated")
	}
	// a token cannot mint elevated tokens
	errCode(t, b.do(http.MethodPost, "/me/tokens", admin), http.StatusForbidden, "forbidden")

	// Over HTTP an elevated administrator cannot mint a token bound to
	// another account: that would hand them a credential acting as the
	// victim and bypass auth.admin_can_access_files. Creating tokens for
	// someone else is the admin socket's job (fileparcel token create
	// --user, which travels as X-FP-As).
	victim := e.AddUser(t, "vera", pw, core.RoleMember)
	errCode(t, c.do(http.MethodPost, "/me/tokens",
		core.TokenInput{Name: "impersonate", Scopes: []string{core.ScopeFilesRead}, UserID: victim.ID}),
		http.StatusForbidden, "forbidden")
	if list, err := e.Auth.ListTokens(context.Background(), victim.ID); err != nil || len(list) != 0 {
		t.Fatalf("victim tokens %+v (err %v)", list, err)
	}
	// naming your own id stays legal
	decode[core.TokenCreated](t, c.do(http.MethodPost, "/me/tokens",
		core.TokenInput{Name: "self", Scopes: []string{core.ScopeFilesRead}, UserID: ada.ID}), http.StatusCreated)

	// the trusted in-process channel (admin socket) still may: that is how
	// "fileparcel token create --user vera" works
	sock := newClient(t, h)
	sock.principal = core.SystemPrincipal(core.ViaSocket)
	sock.header = http.Header{mw.HeaderActAs: {"ada"}}
	cli := decode[core.TokenCreated](t, sock.do(http.MethodPost, "/me/tokens",
		core.TokenInput{Name: "socket", Scopes: []string{core.ScopeFilesRead}, UserID: victim.ID}), http.StatusCreated)
	if cli.Token.UserID != victim.ID {
		t.Fatalf("socket token %+v", cli.Token)
	}
}

// ---------- usage ----------

func TestUsage(t *testing.T) {
	e, h := server(t)
	u := e.AddUser(t, "ulla", pw, core.RoleMember)
	c := newClient(t, h)
	c.login("ulla", pw)
	us := decode[core.Usage](t, c.do(http.MethodGet, "/me/usage", nil), http.StatusOK)
	if us.UserID != u.ID || us.UsedBytes != 1234 {
		t.Fatalf("usage %+v", us)
	}

	e2, h2 := server(t, func(d *app.Deps) { d.Files = nil })
	e2.AddUser(t, "ulla", pw, core.RoleMember)
	c2 := newClient(t, h2)
	c2.login("ulla", pw)
	errCode(t, c2.do(http.MethodGet, "/me/usage", nil), http.StatusServiceUnavailable, "unavailable")
}

// ---------- security alerts ----------

// recordingNotify records every queued message.
type recordingNotify struct {
	mu       sync.Mutex
	enabled  bool
	messages []sentMail
}

type sentMail struct {
	to   []string
	tmpl string
	data map[string]any
}

func (n *recordingNotify) Enabled() bool { return n.enabled }

func (n *recordingNotify) Send(_ context.Context, to []string, tmpl string, data any) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	m, _ := data.(map[string]any)
	n.messages = append(n.messages, sentMail{to: slices.Clone(to), tmpl: tmpl, data: m})
	return nil
}

func (n *recordingNotify) Test(context.Context, string) error { return nil }

func (n *recordingNotify) sent() []sentMail {
	n.mu.Lock()
	defer n.mu.Unlock()
	return slices.Clone(n.messages)
}

// A new passkey, authenticator app or API token each e-mail the account
// owner (notify "security_alert"); nothing is sent while notifications are
// off.
func TestSecurityAlertOnNewCredential(t *testing.T) {
	n := &recordingNotify{}
	e, h := server(t, func(d *app.Deps) { d.Notify = n })
	e.AddUser(t, "nora", pw, core.RoleMember)
	c := newClient(t, h)
	c.login("nora", pw)

	// Notifications disabled: nothing is queued.
	decode[core.TokenCreated](t, c.do(http.MethodPost, "/me/tokens",
		core.TokenInput{Name: "quiet", Scopes: []string{core.ScopeFilesRead}}), http.StatusCreated)
	if got := n.sent(); len(got) != 0 {
		t.Fatalf("mail while notifications are off: %+v", got)
	}

	n.enabled = true
	decode[core.TokenCreated](t, c.do(http.MethodPost, "/me/tokens",
		core.TokenInput{Name: "backup script", Scopes: []string{core.ScopeFilesRead}}), http.StatusCreated)

	a := &authtest.Authenticator{Origin: origin, UV: true}
	c.elevate(core.ElevateInput{Password: pw})
	begin := decode[core.PasskeyBegin](t, c.do(http.MethodPost, "/me/passkeys/begin", nil), http.StatusOK)
	cred, err := a.Create(begin.Options)
	if err != nil {
		t.Fatal(err)
	}
	decode[core.Passkey](t, c.do(http.MethodPost, "/me/passkeys/finish",
		core.PasskeyFinishInput{FlowID: begin.FlowID, Credential: cred, Name: "YubiKey"}), http.StatusCreated)
	// an authenticator app keeps the recovery codes the passkey handed out
	if _, codes := c.enrollTOTP(e); len(codes) != 0 {
		t.Fatalf("the authenticator app replaced the recovery codes: %v", codes)
	}

	got := n.sent()
	if len(got) != 3 {
		t.Fatalf("expected three alerts, got %+v", got)
	}
	for i, want := range []struct{ kind, name string }{
		{"token_created", "backup script"},
		{"passkey_added", "YubiKey"},
		{"totp_added", ""},
	} {
		m := got[i]
		if m.tmpl != "security_alert" || len(m.to) != 1 || m.to[0] != "nora@example.test" {
			t.Errorf("alert %d: tmpl %q to %v", i, m.tmpl, m.to)
		}
		if m.data["kind"] != want.kind || m.data["name"] != want.name || m.data["username"] != "nora" {
			t.Errorf("alert %d: data %+v", i, m.data)
		}
	}
}

// A token created for another account (only the admin socket can do that)
// alerts that account, not the caller, and names the acting administrator.
func TestSecurityAlertGoesToTheTokenOwner(t *testing.T) {
	n := &recordingNotify{enabled: true}
	e, h := server(t, func(d *app.Deps) { d.Notify = n })
	e.Settings.Put("auth.require_2fa", "off")
	e.AddUser(t, "nils", pw, core.RoleAdmin)
	target := e.AddUser(t, "nina", pw, core.RoleMember)

	c := newClient(t, h)
	c.principal = core.SystemPrincipal(core.ViaSocket)
	c.header = http.Header{mw.HeaderActAs: {"nils"}}
	created := decode[core.TokenCreated](t, c.do(http.MethodPost, "/me/tokens",
		core.TokenInput{Name: "for nina", Scopes: []string{core.ScopeFilesRead}, UserID: target.ID}), http.StatusCreated)
	if created.Token.UserID != target.ID {
		t.Fatalf("token %+v", created.Token)
	}
	got := n.sent()
	if len(got) != 1 {
		t.Fatalf("expected one alert, got %+v", got)
	}
	m := got[0]
	if m.tmpl != "security_alert" || len(m.to) != 1 || m.to[0] != "nina@example.test" {
		t.Fatalf("alert went to %v (tmpl %q)", m.to, m.tmpl)
	}
	if m.data["kind"] != "token_created" || m.data["username"] != "nina" || m.data["name"] != "for nina" || m.data["actor"] != "nils" {
		t.Fatalf("alert data %+v", m.data)
	}
}

// A failing notify service never fails the request.
func TestSecurityAlertFailureIsNotFatal(t *testing.T) {
	e, h := server(t, func(d *app.Deps) { d.Notify = failingNotify{} })
	e.AddUser(t, "otto", pw, core.RoleMember)
	c := newClient(t, h)
	c.login("otto", pw)
	decode[core.TokenCreated](t, c.do(http.MethodPost, "/me/tokens",
		core.TokenInput{Name: "t", Scopes: []string{core.ScopeFilesRead}}), http.StatusCreated)
}

type failingNotify struct{}

func (failingNotify) Enabled() bool { return true }
func (failingNotify) Send(context.Context, []string, string, any) error {
	return core.Errorf(core.ErrUnavailable, "the mail queue is full")
}
func (failingNotify) Test(context.Context, string) error { return nil }
