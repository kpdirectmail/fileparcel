package authapi_test

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"

	"fileparcel/internal/app"
	"fileparcel/internal/auth"
	"fileparcel/internal/core"
	"fileparcel/internal/web/authapi"
	"fileparcel/internal/web/mw"
)

// TestRouteTable checks the authapi part of DESIGN §9.4.
func TestRouteTable(t *testing.T) {
	r := chi.NewRouter()
	authapi.Mount(r, &app.Deps{})
	var got []string
	_ = chi.Walk(r, func(method, route string, _ http.Handler, _ ...func(http.Handler) http.Handler) error {
		got = append(got, method+" "+route)
		return nil
	})
	want := []string{
		"GET /auth/state", "POST /auth/login", "POST /auth/totp", "POST /auth/recovery",
		"POST /auth/passkey/begin", "POST /auth/passkey/finish", "POST /auth/logout", "POST /auth/elevate",
		"POST /auth/setup", "GET /auth/invite/{token}", "POST /auth/invite/{token}/accept",
	}
	if len(got) != len(want) {
		t.Fatalf("routes %q, want %q", got, want)
	}
	for _, w := range want {
		found := false
		for _, g := range got {
			found = found || g == w
		}
		if !found {
			t.Fatalf("missing route %s (have %q)", w, got)
		}
	}
}

func TestProtectedAuthRoutes(t *testing.T) {
	_, h := server(t)
	anon := newClient(t, h)
	for _, p := range []string{"/auth/totp", "/auth/recovery", "/auth/logout", "/auth/elevate"} {
		errCode(t, anon.do(http.MethodPost, p, map[string]string{}), http.StatusUnauthorized, "unauthorized")
	}
}

func TestLockoutHTTP(t *testing.T) {
	e, h := server(t)
	e.Settings.Put("auth.lockout_threshold", 3)
	e.Settings.Put("ratelimit.login_per_min", 1000)
	e.Limiter.ApplySettings()
	e.AddUser(t, "lena", pw, core.RoleMember)
	c := newClient(t, h)
	var msgs []string
	for range 3 {
		msgs = append(msgs, errCode(t, c.do(http.MethodPost, "/auth/login", core.LoginInput{Username: "lena", Password: "wrong wrong"}), http.StatusUnauthorized, "unauthorized").Message)
	}
	// locked: the right password gets the same answer
	msgs = append(msgs, errCode(t, c.do(http.MethodPost, "/auth/login", core.LoginInput{Username: "lena", Password: pw}), http.StatusUnauthorized, "unauthorized").Message)
	msgs = append(msgs, errCode(t, c.do(http.MethodPost, "/auth/login", core.LoginInput{Username: "nobody", Password: pw}), http.StatusUnauthorized, "unauthorized").Message)
	for _, m := range msgs {
		if m != msgs[0] {
			t.Fatalf("non-uniform errors %q", msgs)
		}
	}
	if c.token != "" {
		t.Fatal("a failed login set a cookie")
	}
	if e.Audit.Count(core.ActAuthLockout, core.OutcomeDenied) != 1 {
		t.Fatalf("auth.lockout audits: %d", e.Audit.Count(core.ActAuthLockout, ""))
	}
	e.Clock.Advance(15*time.Minute + time.Second)
	if res := c.login("lena", pw); res.User == nil {
		t.Fatalf("after the lock: %+v", res)
	}
}

func TestRememberMeCookie(t *testing.T) {
	e, h := server(t)
	e.AddUser(t, "mo", pw, core.RoleMember)
	c := newClient(t, h)
	res := decode[core.LoginResult](t, c.do(http.MethodPost, "/auth/login", core.LoginInput{Username: "mo", Password: pw, Remember: true}), http.StatusOK)
	c.csrf = res.CSRF
	ck := c.cookie
	if ck == nil || ck.MaxAge < 29*24*3600 || ck.MaxAge > 30*24*3600 || ck.Expires.IsZero() {
		t.Fatalf("remember-me cookie %+v", ck)
	}
	// with a second factor the pending cookie is a browser-session cookie;
	// the persistent cookie is set when the login completes
	c.stepUp(pw)
	en := decode[core.TOTPEnrollment](t, c.do(http.MethodPost, "/me/totp/begin", nil), http.StatusOK)
	decode[core.RecoveryCodes](t, c.do(http.MethodPost, "/me/totp/confirm", core.CodeInput{Code: totpCode(t, en.Secret, e.Clock.Now())}), http.StatusOK)
	noContent(t, c.do(http.MethodPost, "/auth/logout", nil))
	e.Clock.Advance(30 * time.Second)
	res = decode[core.LoginResult](t, c.do(http.MethodPost, "/auth/login", core.LoginInput{Username: "mo", Password: pw, Remember: true}), http.StatusOK)
	c.csrf = res.CSRF
	if !res.MFARequired || c.cookie.MaxAge != 0 {
		t.Fatalf("pending cookie %+v", c.cookie)
	}
	decode[core.LoginResult](t, c.do(http.MethodPost, "/auth/totp", core.CodeInput{Code: totpCode(t, en.Secret, e.Clock.Now())}), http.StatusOK)
	if c.cookie.MaxAge < 29*24*3600 {
		t.Fatalf("completed cookie %+v", c.cookie)
	}
}

func TestLogoutPendingSession(t *testing.T) {
	e, h := server(t)
	e.AddUser(t, "nat", pw, core.RoleMember)
	c := newClient(t, h)
	c.login("nat", pw)
	c.stepUp(pw)
	en := decode[core.TOTPEnrollment](t, c.do(http.MethodPost, "/me/totp/begin", nil), http.StatusOK)
	decode[core.RecoveryCodes](t, c.do(http.MethodPost, "/me/totp/confirm", core.CodeInput{Code: totpCode(t, en.Secret, e.Clock.Now())}), http.StatusOK)
	noContent(t, c.do(http.MethodPost, "/auth/logout", nil))
	c.login("nat", pw)
	pending := c.token
	noContent(t, c.do(http.MethodPost, "/auth/logout", nil))
	if c.token != "" || c.cookie.MaxAge >= 0 {
		t.Fatalf("cookie %+v", c.cookie)
	}
	stale := newClient(t, h)
	stale.token = pending
	errCode(t, stale.do(http.MethodGet, "/me", nil), http.StatusUnauthorized, "unauthorized")
	if e.Audit.Count(core.ActAuthLogout, core.OutcomeSuccess) != 2 {
		t.Fatalf("auth.logout audits: %d", e.Audit.Count(core.ActAuthLogout, ""))
	}
}

func TestSecondFactorEdgeCases(t *testing.T) {
	e, h := server(t)
	e.AddUser(t, "ola", pw, core.RoleMember)
	c := newClient(t, h)
	c.login("ola", pw)
	// a full session has nothing pending
	errCode(t, c.do(http.MethodPost, "/auth/totp", core.CodeInput{Code: "123456"}), http.StatusConflict, "conflict")

	c.stepUp(pw)
	en := decode[core.TOTPEnrollment](t, c.do(http.MethodPost, "/me/totp/begin", nil), http.StatusOK)
	decode[core.RecoveryCodes](t, c.do(http.MethodPost, "/me/totp/confirm", core.CodeInput{Code: totpCode(t, en.Secret, e.Clock.Now())}), http.StatusOK)
	noContent(t, c.do(http.MethodPost, "/auth/logout", nil))
	// the code that confirmed the enrollment cannot be replayed to sign in
	c.login("ola", pw)
	errCode(t, c.do(http.MethodPost, "/auth/totp", core.CodeInput{Code: totpCode(t, en.Secret, e.Clock.Now())}), http.StatusUnprocessableEntity, "invalid")

	// the pending sign-in expires after 10 minutes: start over
	e.Clock.Advance(auth.PendingTTL + time.Second)
	w := c.do(http.MethodPost, "/auth/totp", core.CodeInput{Code: totpCode(t, en.Secret, e.Clock.Now())})
	errCode(t, w, http.StatusUnauthorized, "unauthorized")
}

func TestElevateWithTOTP(t *testing.T) {
	e, h := server(t)
	e.AddUser(t, "pete", pw, core.RoleMember)
	c := newClient(t, h)
	c.login("pete", pw)
	c.stepUp(pw)
	en := decode[core.TOTPEnrollment](t, c.do(http.MethodPost, "/me/totp/begin", nil), http.StatusOK)
	decode[core.RecoveryCodes](t, c.do(http.MethodPost, "/me/totp/confirm", core.CodeInput{Code: totpCode(t, en.Secret, e.Clock.Now())}), http.StatusOK)
	errCode(t, c.do(http.MethodPost, "/auth/elevate", core.ElevateInput{}), http.StatusUnprocessableEntity, "invalid")
	errCode(t, c.do(http.MethodPost, "/auth/elevate", core.ElevateInput{Password: pw, TOTP: "123456"}), http.StatusUnprocessableEntity, "invalid")
	// the confirm code's time step is used up
	errCode(t, c.do(http.MethodPost, "/auth/elevate", core.ElevateInput{TOTP: totpCode(t, en.Secret, e.Clock.Now())}), http.StatusForbidden, "forbidden")
	e.Clock.Advance(30 * time.Second)
	res := decode[core.ElevateResult](t, c.do(http.MethodPost, "/auth/elevate", core.ElevateInput{TOTP: totpCode(t, en.Secret, e.Clock.Now())}), http.StatusOK)
	if !res.ElevatedUntil.After(e.Clock.Now()) {
		t.Fatalf("elevate %+v", res)
	}
	// (the first success is the password step-up that enrolling needed)
	if e.Audit.Count(core.ActAuthElevate, core.OutcomeSuccess) != 2 || e.Audit.Count(core.ActAuthElevate, core.OutcomeFailure) != 1 {
		t.Fatal("auth.elevate audits")
	}
}

func TestPasskeysDisabledHTTP(t *testing.T) {
	e, h := server(t)
	e.Settings.Put("auth.passkeys", false)
	c := newClient(t, h)
	errCode(t, c.do(http.MethodPost, "/auth/passkey/begin", core.PasskeyBeginInput{}), http.StatusForbidden, "forbidden")
	errCode(t, c.do(http.MethodPost, "/auth/passkey/finish", core.PasskeyFinishInput{FlowID: "x", Credential: []byte(`{}`)}), http.StatusForbidden, "forbidden")
}

func TestBadRequests(t *testing.T) {
	_, h := server(t)
	for _, body := range []string{`{"username":`, `[]`, `{"username":1}`} {
		r := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", bytes.NewReader([]byte(body)))
		r.Header.Set("Content-Type", "application/json")
		r.RemoteAddr = "192.0.2.3:1234"
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		errCode(t, w, http.StatusUnprocessableEntity, "invalid")
	}
	// bodies above 1 MiB are refused
	big := `{"username":"` + strings.Repeat("a", 2<<20) + `","password":"x"}`
	r := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", strings.NewReader(big))
	r.Header.Set("Content-Type", "application/json")
	r.RemoteAddr = "192.0.2.3:1234"
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	errCode(t, w, http.StatusRequestEntityTooLarge, "too_large")
}

func TestUnavailable(t *testing.T) {
	d := &app.Deps{}
	r := chi.NewRouter()
	r.Use(mw.Inject(d))
	api := chi.NewRouter()
	authapi.Mount(api, d)
	r.Mount("/api/v1", api)
	for _, tc := range []struct{ method, path string }{
		{http.MethodPost, "/api/v1/auth/login"},
		{http.MethodPost, "/api/v1/auth/setup"},
		{http.MethodGet, "/api/v1/auth/invite/x"},
	} {
		req := httptest.NewRequest(tc.method, tc.path, strings.NewReader(`{}`)).WithContext(context.Background())
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		errCode(t, w, http.StatusServiceUnavailable, "unavailable")
	}
	// the public state works without services
	req := httptest.NewRequest(http.MethodGet, "/api/v1/auth/state", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	st := decode[core.AuthState](t, w, http.StatusOK)
	if st.Instance != "FileParcel" || st.RPID != "fileparcel.local" {
		t.Fatalf("state %+v", st)
	}
}
