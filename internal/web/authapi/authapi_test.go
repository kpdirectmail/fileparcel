package authapi_test

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
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

const pw = "correct horse battery staple"

// server wires the /api/v1 chain of web/router.go around authapi and meapi.
func server(t *testing.T) (*authtest.Env, http.Handler) {
	t.Helper()
	e := authtest.New(t)
	d := &app.Deps{Env: e.Env, Auth: e.Auth, Users: e.Users, Limiter: e.Limiter}
	r := chi.NewRouter()
	r.Use(mw.Inject(d), middleware.GetHead, mw.RequestID, mw.ResolveClientIP)
	api := chi.NewRouter()
	authapi.Mount(api, d)
	meapi.Mount(api, d)
	r.With(mw.MaxBody(httpx.DefaultMaxBody), mw.RateLimit(mw.BucketAPI, mw.PerIP), mw.Authenticate, mw.CSRF).Mount("/api/v1", api)
	return e, r
}

// client is a minimal browser: it keeps the session cookie and sends the
// CSRF token on unsafe requests.
type client struct {
	t      *testing.T
	h      http.Handler
	ip     string
	token  string
	csrf   string
	bearer string
	cookie *http.Cookie // last Set-Cookie of the session cookie
	header http.Header  // extra headers for the next request
}

func newClient(t *testing.T, h http.Handler) *client { return &client{t: t, h: h, ip: "192.0.2.50"} }

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
	r.RemoteAddr = c.ip + ":40000"
	if body != nil {
		r.Header.Set("Content-Type", "application/json")
	}
	if c.token != "" {
		r.AddCookie(&http.Cookie{Name: auth.CookieName, Value: c.token})
	}
	if c.csrf != "" && method != http.MethodGet {
		r.Header.Set(mw.HeaderCSRF, c.csrf)
	}
	if c.bearer != "" {
		r.Header.Set("Authorization", "Bearer "+c.bearer)
	}
	for k, v := range c.header {
		r.Header[k] = v
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

// json decodes the response into v after checking the status.
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

// stepUp opens a step-up window with the password (POST /auth/elevate),
// which enrolling a second factor or a passkey needs.
func (c *client) stepUp(pass string) {
	c.t.Helper()
	res := decode[core.ElevateResult](c.t, c.do(http.MethodPost, "/auth/elevate", core.ElevateInput{Password: pass}), http.StatusOK)
	if res.CSRF != "" {
		c.csrf = res.CSRF
	}
}

func TestState(t *testing.T) {
	e, h := server(t)
	c := newClient(t, h)
	st := decode[core.AuthState](t, c.do(http.MethodGet, "/auth/state", nil), http.StatusOK)
	if !st.SetupNeeded || st.RPID != "fileparcel.local" || !st.Passkeys || st.KeysState != core.KeyStateUnlocked || st.Instance != "FileParcel" ||
		st.PasswordMin != auth.DefaultPasswordMin {
		t.Fatalf("state %+v", st)
	}
	e.AddUser(t, "a", pw, core.RoleOwner)
	e.Settings.Put("auth.passkeys", false)
	e.Settings.Put("auth.password_min", 8) // the password forms follow the configured minimum
	st = decode[core.AuthState](t, c.do(http.MethodGet, "/auth/state", nil), http.StatusOK)
	if st.SetupNeeded || st.Passkeys || st.PasswordMin != 8 {
		t.Fatalf("state %+v", st)
	}
	if got := authapi.RPID(nil); got != "fileparcel.local" {
		t.Fatalf("RPID(nil) = %q", got)
	}
}

func TestLoginTOTPSessionCSRFLogout(t *testing.T) {
	e, h := server(t)
	e.AddUser(t, "vera", pw, core.RoleMember)
	c := newClient(t, h)

	// enroll TOTP with a full session
	c.login("vera", pw)
	if ck := c.cookie; ck == nil || !ck.Secure || !ck.HttpOnly || ck.SameSite != http.SameSiteLaxMode || ck.Path != "/" || ck.MaxAge != 0 {
		t.Fatalf("session cookie %+v", c.cookie)
	}
	c.stepUp(pw)
	en := decode[core.TOTPEnrollment](t, c.do(http.MethodPost, "/me/totp/begin", nil), http.StatusOK)
	rc := decode[core.RecoveryCodes](t, c.do(http.MethodPost, "/me/totp/confirm", core.CodeInput{Code: totpCode(t, en.Secret, e.Clock.Now())}), http.StatusOK)
	if len(rc.RecoveryCodes) != auth.RecoveryCodeCount {
		t.Fatalf("recovery codes %v", rc)
	}
	if w := c.do(http.MethodPost, "/auth/logout", nil); w.Code != http.StatusNoContent || c.token != "" {
		t.Fatalf("logout %d token %q", w.Code, c.token)
	}
	e.Clock.Advance(30 * time.Second)

	// password step
	res := c.login("vera", pw)
	if !res.MFARequired || res.User != nil || len(res.Methods) != 2 || res.CSRF == "" || c.token == "" {
		t.Fatalf("login %+v", res)
	}
	pending := c.token
	me := decode[core.Me](t, c.do(http.MethodGet, "/me", nil), http.StatusOK)
	// The pending session gets the csrf token and who is signing in, never
	// the profile behind the second-factor boundary.
	if !me.MFAPending || me.CSRF != res.CSRF || me.User == nil || me.MFA == nil || !me.MFA.TOTPEnabled {
		t.Fatalf("pending /me %+v", me)
	}
	if me.User.Email != "" || me.User.LastLoginIP != "" || me.User.SpaceID != "" || me.SpaceID != "" {
		t.Fatalf("pending /me leaks the profile: %+v", me.User)
	}
	errCode(t, c.do(http.MethodGet, "/me/sessions", nil), http.StatusUnauthorized, "mfa_required")

	// CSRF: missing token, then a cross-site request
	csrf := c.csrf
	c.csrf = ""
	errCode(t, c.do(http.MethodPost, "/auth/totp", core.CodeInput{Code: "123456"}), http.StatusForbidden, "csrf_invalid")
	c.csrf = csrf
	c.header = http.Header{"Sec-Fetch-Site": {"cross-site"}, "Origin": {"https://evil.example"}}
	errCode(t, c.do(http.MethodPost, "/auth/totp", core.CodeInput{Code: "123456"}), http.StatusForbidden, "forbidden")

	good := totpCode(t, en.Secret, e.Clock.Now())
	bad := "000000"
	if good == bad {
		bad = "111111"
	}
	errCode(t, c.do(http.MethodPost, "/auth/totp", core.CodeInput{Code: bad}), http.StatusUnprocessableEntity, "invalid")
	full := decode[core.LoginResult](t, c.do(http.MethodPost, "/auth/totp", core.CodeInput{Code: good}), http.StatusOK)
	if full.User == nil || full.CSRF == res.CSRF || c.token == pending || c.token == "" {
		t.Fatalf("second factor must rotate: %+v", full)
	}
	old := c.csrf
	c.csrf = full.CSRF
	me = decode[core.Me](t, c.do(http.MethodGet, "/me", nil), http.StatusOK)
	if me.MFAPending || me.CSRF != full.CSRF || len(me.Groups) != 1 || me.GroupSpaceIDs["grp_team"] != "spc_team" || me.SpaceID == "" {
		t.Fatalf("/me %+v", me)
	}
	// the old CSRF token no longer works
	c.csrf = old
	errCode(t, c.do(http.MethodPost, "/me/sessions/revoke-others", nil), http.StatusForbidden, "csrf_invalid")
	c.csrf = full.CSRF
	if w := c.do(http.MethodPost, "/me/sessions/revoke-others", nil); w.Code != http.StatusNoContent {
		t.Fatalf("revoke-others %d %s", w.Code, w.Body)
	}
	// the pre-MFA cookie is dead
	stale := newClient(t, h)
	stale.token = pending
	errCode(t, stale.do(http.MethodGet, "/me", nil), http.StatusUnauthorized, "unauthorized")

	if w := c.do(http.MethodPost, "/auth/logout", nil); w.Code != http.StatusNoContent || c.cookie.MaxAge >= 0 {
		t.Fatalf("logout %d %+v", w.Code, c.cookie)
	}
	c.token = full.Token // the browser would have dropped it; the server must refuse it too
	errCode(t, c.do(http.MethodGet, "/me", nil), http.StatusUnauthorized, "unauthorized")
	c.token = ""
	errCode(t, c.do(http.MethodPost, "/auth/logout", nil), http.StatusUnauthorized, "unauthorized")
}

func TestRecoveryCodeLogin(t *testing.T) {
	e, h := server(t)
	e.AddUser(t, "walt", pw, core.RoleMember)
	c := newClient(t, h)
	c.login("walt", pw)
	c.stepUp(pw)
	en := decode[core.TOTPEnrollment](t, c.do(http.MethodPost, "/me/totp/begin", nil), http.StatusOK)
	rc := decode[core.RecoveryCodes](t, c.do(http.MethodPost, "/me/totp/confirm", core.CodeInput{Code: totpCode(t, en.Secret, e.Clock.Now())}), http.StatusOK)
	c.do(http.MethodPost, "/auth/logout", nil)
	c.login("walt", pw)
	full := decode[core.LoginResult](t, c.do(http.MethodPost, "/auth/recovery", core.CodeInput{Code: rc.RecoveryCodes[3]}), http.StatusOK)
	if full.User == nil {
		t.Fatal("recovery login")
	}
	c.csrf = full.CSRF // the second factor rotated the CSRF secret
	if w := c.do(http.MethodPost, "/auth/logout", nil); w.Code != http.StatusNoContent {
		t.Fatalf("logout %d %s", w.Code, w.Body)
	}
	c.login("walt", pw)
	errCode(t, c.do(http.MethodPost, "/auth/recovery", core.CodeInput{Code: rc.RecoveryCodes[3]}), http.StatusUnprocessableEntity, "invalid")
}

func TestLoginRateLimitAndUniformErrors(t *testing.T) {
	e, h := server(t)
	e.AddUser(t, "xena", pw, core.RoleMember)
	e.Settings.Put("ratelimit.login_per_min", 3)
	e.Limiter.ApplySettings()
	c := newClient(t, h)
	errCode(t, c.do(http.MethodPost, "/auth/login", core.LoginInput{Username: "xena", Password: "nope"}), http.StatusUnauthorized, "unauthorized")
	errCode(t, c.do(http.MethodPost, "/auth/login", core.LoginInput{Username: "ghost", Password: "nope"}), http.StatusUnauthorized, "unauthorized")
	c.login("xena", pw)
	w := c.do(http.MethodPost, "/auth/login", core.LoginInput{Username: "xena", Password: pw})
	errCode(t, w, http.StatusTooManyRequests, "rate_limited")
	if ra := w.Header().Get("Retry-After"); ra == "" || ra == "0" {
		t.Fatalf("Retry-After %q", ra)
	}
	// another client IP is unaffected
	d := newClient(t, h)
	d.ip = "192.0.2.99"
	d.login("xena", pw)
	// unknown fields are rejected
	errCode(t, d.do(http.MethodPost, "/auth/login", map[string]any{"username": "x", "password": "y", "admin": true}), http.StatusUnprocessableEntity, "invalid")
}

func TestElevation(t *testing.T) {
	e, h := server(t)
	e.AddUser(t, "yuri", pw, core.RoleMember)
	c := newClient(t, h)
	c.login("yuri", pw)
	errCode(t, c.do(http.MethodPost, "/me/recovery-codes", nil), http.StatusForbidden, "elevation_required")
	errCode(t, c.do(http.MethodPost, "/auth/elevate", core.ElevateInput{Password: "wrong"}), http.StatusForbidden, "forbidden")
	before := c.token
	res := decode[core.ElevateResult](t, c.do(http.MethodPost, "/auth/elevate", core.ElevateInput{Password: pw}), http.StatusOK)
	if !res.ElevatedUntil.Equal(e.Clock.Now().Add(10*time.Minute)) || res.CSRF != c.csrf || c.token == before {
		t.Fatalf("elevate %+v (token rotated: %v)", res, c.token != before)
	}
	// elevated now: the route is reachable (no second factor yet → 409)
	errCode(t, c.do(http.MethodPost, "/me/recovery-codes", nil), http.StatusConflict, "conflict")
	me := decode[core.Me](t, c.do(http.MethodGet, "/me", nil), http.StatusOK)
	if me.ElevatedUntil == nil {
		t.Fatal("/me must report the step-up window")
	}
}

func TestPasskeyLoginHTTP(t *testing.T) {
	e, h := server(t)
	e.AddUser(t, "zoe", pw, core.RoleMember)
	a := &authtest.Authenticator{Origin: "https://fileparcel.local:8443", UV: true}
	c := newClient(t, h)
	c.login("zoe", pw)
	// a passkey signs in on its own: registering one needs step-up
	errCode(t, c.do(http.MethodPost, "/me/passkeys/begin", nil), http.StatusForbidden, "elevation_required")
	c.stepUp(pw)
	begin := decode[core.PasskeyBegin](t, c.do(http.MethodPost, "/me/passkeys/begin", nil), http.StatusOK)
	cred, err := a.Create(begin.Options)
	if err != nil {
		t.Fatal(err)
	}
	pk := decode[core.Passkey](t, c.do(http.MethodPost, "/me/passkeys/finish", core.PasskeyFinishInput{FlowID: begin.FlowID, Credential: cred, Name: "Laptop"}), http.StatusCreated)
	if pk.Name != "Laptop" {
		t.Fatalf("passkey %+v", pk)
	}
	c.do(http.MethodPost, "/auth/logout", nil)
	c.csrf = ""

	anon := newClient(t, h)
	begin = decode[core.PasskeyBegin](t, anon.do(http.MethodPost, "/auth/passkey/begin", core.PasskeyBeginInput{}), http.StatusOK)
	assertion, err := a.Get(begin.Options)
	if err != nil {
		t.Fatal(err)
	}
	res := decode[core.LoginResult](t, anon.do(http.MethodPost, "/auth/passkey/finish", core.PasskeyFinishInput{FlowID: begin.FlowID, Credential: assertion}), http.StatusOK)
	if res.User == nil || res.User.Username != "zoe" || anon.token == "" {
		t.Fatalf("passkey login %+v", res)
	}
	if anon.cookie == nil || anon.cookie.MaxAge != 0 {
		t.Fatalf("passkey sign-in without remember: cookie %+v", anon.cookie)
	}
	// "keep me signed in" applies to a passwordless sign-in too
	kept := newClient(t, h)
	begin = decode[core.PasskeyBegin](t, kept.do(http.MethodPost, "/auth/passkey/begin", core.PasskeyBeginInput{}), http.StatusOK)
	if assertion, err = a.Get(begin.Options); err != nil {
		t.Fatal(err)
	}
	decode[core.LoginResult](t, kept.do(http.MethodPost, "/auth/passkey/finish",
		core.PasskeyFinishInput{FlowID: begin.FlowID, Credential: assertion, Remember: true}), http.StatusOK)
	if ck := kept.cookie; ck == nil || ck.MaxAge < 29*24*3600 || ck.Expires.IsZero() {
		t.Fatalf("remembered passkey sign-in: cookie %+v", ck)
	}
	anon.csrf = res.CSRF
	decode[core.Me](t, anon.do(http.MethodGet, "/me", nil), http.StatusOK)
	errCode(t, anon.do(http.MethodPost, "/auth/passkey/finish", core.PasskeyFinishInput{FlowID: "x"}), http.StatusUnprocessableEntity, "invalid")

	// second factor: password, then the passkey
	c.login("zoe", pw)
	begin = decode[core.PasskeyBegin](t, c.do(http.MethodPost, "/auth/passkey/begin", core.PasskeyBeginInput{}), http.StatusOK)
	assertion, _ = a.Get(begin.Options)
	res = decode[core.LoginResult](t, c.do(http.MethodPost, "/auth/passkey/finish", core.PasskeyFinishInput{FlowID: begin.FlowID, Credential: assertion}), http.StatusOK)
	if res.User == nil || res.Session != nil {
		t.Fatalf("second factor %+v", res)
	}
	c.csrf = res.CSRF
	if me := decode[core.Me](t, c.do(http.MethodGet, "/me", nil), http.StatusOK); me.MFAPending {
		t.Fatal("still pending")
	}

	// elevation with the passkey
	begin = decode[core.PasskeyBegin](t, c.do(http.MethodPost, "/auth/passkey/begin", core.PasskeyBeginInput{Username: "zoe"}), http.StatusOK)
	assertion, _ = a.Get(begin.Options)
	el := decode[core.ElevateResult](t, c.do(http.MethodPost, "/auth/elevate", core.ElevateInput{Passkey: assertion, FlowID: begin.FlowID}), http.StatusOK)
	if el.ElevatedUntil.IsZero() {
		t.Fatal("not elevated")
	}
}

func TestSetupHTTP(t *testing.T) {
	e, h := server(t)
	tok, err := e.Auth.SetupToken(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	c := newClient(t, h)
	body := map[string]any{"setup_token": "wrong", "username": "owner", "password": pw, "email": "o@example.test"}
	w := c.do(http.MethodPost, "/auth/setup", body)
	if er := decode[httpx.ErrorResponse](t, w, http.StatusForbidden); er.Error.Field != "setup_token" {
		t.Fatalf("wrong token %+v", er)
	}
	body["setup_token"] = tok
	res := decode[core.LoginResult](t, c.do(http.MethodPost, "/auth/setup", body), http.StatusCreated)
	if res.User == nil || res.User.Role != core.RoleOwner || !res.EnrollRequired || c.token == "" {
		t.Fatalf("setup %+v", res)
	}
	c.csrf = res.CSRF
	me := decode[core.Me](t, c.do(http.MethodGet, "/me", nil), http.StatusOK)
	if me.MFA == nil || !me.MFA.EnrollRequired {
		t.Fatalf("owner must enroll: %+v", me.MFA)
	}
	// while enrollment is pending: /me* works, but no tokens
	decode[core.Page[core.Session]](t, c.do(http.MethodGet, "/me/sessions", nil), http.StatusOK)
	errCode(t, c.do(http.MethodPost, "/me/tokens", core.TokenInput{Name: "x", Scopes: []string{"files:read"}}), http.StatusForbidden, "mfa_enroll_required")
	errCode(t, newClient(t, h).do(http.MethodPost, "/auth/setup", body), http.StatusConflict, "conflict")
}

func TestInviteHTTP(t *testing.T) {
	e, h := server(t)
	e.Users.AddInvite("invtoken123", core.RoleMember, e.Clock.Now().Add(24*time.Hour)).InvitedBy = "Ada Admin"
	c := newClient(t, h)
	errCode(t, c.do(http.MethodGet, "/auth/invite/nope", nil), http.StatusNotFound, "not_found")
	inv := decode[core.Invite](t, c.do(http.MethodGet, "/auth/invite/invtoken123", nil), http.StatusOK)
	if inv.CreatedBy != "" || inv.URL != "" || len(inv.GroupIDs) != 0 || inv.Role != core.RoleMember || inv.Note != "welcome" {
		t.Fatalf("public invite leaks: %+v", inv)
	}
	if inv.InvitedBy != "Ada Admin" { // the invite page's "Invited by" line
		t.Fatalf("public invite without the inviter's name: %+v", inv)
	}
	in := core.AcceptInvite{Username: "newbie", Password: "password123", DisplayName: "New"}
	errCode(t, c.do(http.MethodPost, "/auth/invite/invtoken123/accept", in), http.StatusUnprocessableEntity, "invalid")
	in.Password = pw
	res := decode[core.LoginResult](t, c.do(http.MethodPost, "/auth/invite/invtoken123/accept", in), http.StatusCreated)
	if res.User == nil || res.User.Username != "newbie" || c.token == "" {
		t.Fatalf("accept %+v", res)
	}
	c.csrf = res.CSRF
	if me := decode[core.Me](t, c.do(http.MethodGet, "/me", nil), http.StatusOK); me.User.Username != "newbie" {
		t.Fatal("not signed in as the new user")
	}
	errCode(t, newClient(t, h).do(http.MethodPost, "/auth/invite/invtoken123/accept", core.AcceptInvite{Username: "second", Password: pw}), http.StatusNotFound, "not_found")
	errCode(t, newClient(t, h).do(http.MethodPost, "/auth/invite/x/accept", core.AcceptInvite{Password: pw}), http.StatusUnprocessableEntity, "invalid")
}

// An invitation that names an e-mail address gives the account that address
// even when the invitee leaves the field empty, so the password is checked
// against it ("must not contain your e-mail address") like every later
// password change or reset of the account would.
func TestInviteChecksPasswordAgainstTheInvitedAddress(t *testing.T) {
	e, h := server(t)
	inv := e.Users.AddInvite("invmail1234", core.RoleMember, e.Clock.Now().Add(24*time.Hour))
	inv.Email = "alice.martin@corp.example"
	c := newClient(t, h)
	if d := errCode(t, c.do(http.MethodPost, "/auth/invite/invmail1234/accept",
		core.AcceptInvite{Username: "am", Password: "alice.martin#Quartz-2026"}), http.StatusUnprocessableEntity, "invalid"); d.Field != "password" {
		t.Fatalf("refused on the wrong field: %+v", d)
	}
	res := decode[core.LoginResult](t, c.do(http.MethodPost, "/auth/invite/invmail1234/accept", core.AcceptInvite{Username: "am", Password: pw}), http.StatusCreated)
	if res.User == nil || res.User.Email != "alice.martin@corp.example" {
		t.Fatalf("accept %+v", res.User)
	}
	// an unusable token is still a plain 404, before any password check
	errCode(t, newClient(t, h).do(http.MethodPost, "/auth/invite/nope/accept", core.AcceptInvite{Username: "am2", Password: "x"}), http.StatusNotFound, "not_found")
}

func TestBearerTokens(t *testing.T) {
	e, h := server(t)
	e.AddUser(t, "amy", pw, core.RoleMember)
	c := newClient(t, h)
	c.login("amy", pw)
	created := decode[core.TokenCreated](t, c.do(http.MethodPost, "/me/tokens", core.TokenInput{Name: "ci", Scopes: []string{"files:read"}}), http.StatusCreated)
	if !strings.HasPrefix(created.Secret, "fpt_") || created.Token == nil {
		t.Fatalf("created %+v", created)
	}
	b := newClient(t, h)
	b.bearer = created.Secret
	me := decode[core.Me](t, b.do(http.MethodGet, "/me", nil), http.StatusOK)
	if me.Via != core.ViaToken || me.CSRF != "" {
		t.Fatalf("token /me %+v", me)
	}
	// Bearer requests are exempt from CSRF but not from the credential rules
	if w := b.do(http.MethodPatch, "/me/profile", core.ProfileUpdate{Prefs: json.RawMessage(`{"theme":"dark"}`)}); w.Code != http.StatusOK {
		t.Fatalf("bearer PATCH %d %s", w.Code, w.Body)
	}
	errCode(t, b.do(http.MethodPost, "/me/sessions/revoke-others", nil), http.StatusForbidden, "forbidden")
	errCode(t, b.do(http.MethodPost, "/me/password", core.PasswordChangeInput{CurrentPassword: pw, NewPassword: "x"}), http.StatusForbidden, "forbidden")
	errCode(t, b.do(http.MethodPost, "/auth/elevate", core.ElevateInput{Password: pw}), http.StatusForbidden, "forbidden")
	b.bearer = created.Secret + "tampered"
	w := b.do(http.MethodGet, "/me", nil)
	errCode(t, w, http.StatusUnauthorized, "unauthorized")
	if !strings.HasPrefix(w.Header().Get("WWW-Authenticate"), "Bearer") {
		t.Fatal("missing WWW-Authenticate")
	}
}
