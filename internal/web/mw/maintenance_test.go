package mw

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"fileparcel/internal/core"
	"fileparcel/internal/settings"
)

// notice stands in for pages.MaintenanceNotice.
func notice(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusServiceUnavailable)
	_, _ = w.Write([]byte("NOTICE:" + MaintenanceMessage(Deps(r))))
}

// TestMaintenanceGate covers DESIGN §20 gap 1: while maintenance.enabled is
// on, non-admin API requests get 503 and page navigations get the notice,
// while the health checks, the static assets, the sign-in/unlock pages, the
// auth (but not invitation) /me/system/admin API groups and the admin SPA
// stay reachable.
func TestMaintenanceGate(t *testing.T) {
	e := newEnv(t)
	d := e.d
	h := Maintenance(http.HandlerFunc(notice))(http.HandlerFunc(ok))

	// Off: everything passes.
	if rec := serve(d, h, httptest.NewRequest("GET", "/api/v1/spaces", nil)); rec.Code != 200 {
		t.Fatalf("maintenance off: %d", rec.Code)
	}

	e.s.set(KeyMaintenanceEnabled, true)

	// Anonymous API request.
	rec := serve(d, h, httptest.NewRequest("GET", "/api/v1/spaces", nil))
	if rec.Code != 503 || code(t, rec) != "unavailable" {
		t.Fatalf("api during maintenance: %d %s", rec.Code, code(t, rec))
	}
	if rec.Header().Get("Retry-After") == "" {
		t.Error("no Retry-After on the 503")
	}
	if got := rec.Body.String(); !strings.Contains(got, DefaultMaintenanceMessage) {
		t.Errorf("503 body does not carry the notice: %s", got)
	}

	// Page navigation.
	rec = serve(d, h, httptest.NewRequest("GET", "/files/abc", nil))
	if rec.Code != 503 || !strings.Contains(rec.Body.String(), "NOTICE:") {
		t.Fatalf("page during maintenance: %d %q", rec.Code, rec.Body.String())
	}

	// A configured message wins.
	e.s.set(KeyMaintenanceMessage, "Back at 09:00 UTC.")
	rec = serve(d, h, httptest.NewRequest("GET", "/files", nil))
	if !strings.Contains(rec.Body.String(), "Back at 09:00 UTC.") {
		t.Errorf("configured message not shown: %q", rec.Body.String())
	}
	rec = serve(d, h, httptest.NewRequest("GET", "/api/v1/spaces", nil))
	if !strings.Contains(rec.Body.String(), "Back at 09:00 UTC.") {
		t.Errorf("configured message not in the API error: %q", rec.Body.String())
	}

	// Public share links are closed too.
	for _, p := range []string{"/s/tok", "/s/tok/api", "/s/tok/dl/nod_1", "/api/v1/nodes/nod_1/content"} {
		if rec := serve(d, h, httptest.NewRequest("GET", p, nil)); rec.Code == 200 {
			t.Errorf("%s reachable during maintenance", p)
		}
	}
	// The share JSON routes are API paths: the share page's fetch() gets the
	// JSON 503 with the operator's message, not the HTML notice.
	for _, p := range []string{"/s/tok/api", "/s/tok/api/list"} {
		rec := serve(d, h, httptest.NewRequest("GET", p, nil))
		if rec.Code != 503 || code(t, rec) != "unavailable" || !strings.Contains(rec.Body.String(), "Back at 09:00 UTC.") {
			t.Errorf("%s during maintenance: %d %q", p, rec.Code, rec.Body.String())
		}
	}
	if rec := serve(d, h, httptest.NewRequest("GET", "/s/tok", nil)); rec.Code != 503 || !strings.Contains(rec.Body.String(), "NOTICE:") {
		t.Errorf("share page during maintenance: %d %q", rec.Code, rec.Body.String())
	}
	// Invitations cannot be accepted (that creates an account); the /invite
	// page is closed as well. Signing in still works.
	for _, r := range []*http.Request{
		httptest.NewRequest("GET", "/api/v1/auth/invite/tok", nil),
		httptest.NewRequest("POST", "/api/v1/auth/invite/tok/accept", nil),
		httptest.NewRequest("GET", "/invite/tok", nil),
	} {
		if rec := serve(d, h, r); rec.Code != 503 {
			t.Errorf("%s %s during maintenance: %d", r.Method, r.URL.Path, rec.Code)
		}
	}
	if rec := serve(d, h, httptest.NewRequest("POST", "/api/v1/auth/login", nil)); rec.Code != 200 {
		t.Errorf("sign-in during maintenance: %d", rec.Code)
	}
	// Unsafe methods too.
	if rec := serve(d, h, httptest.NewRequest("POST", "/api/v1/upload-batches", nil)); rec.Code != 503 {
		t.Errorf("POST during maintenance: %d", rec.Code)
	}

	// The allow-list stays open for everyone (DESIGN §20).
	for _, p := range []string{
		"/healthz", "/readyz", "/login", "/unlock", "/trust", "/favicon.ico", "/robots.txt",
		"/sw.js", "/manifest.webmanifest", "/theme.css", "/static/abc/js/app.js", "/trust/ca.crt",
		"/api/v1/auth/state", "/api/v1/auth/login", "/api/v1/me", "/api/v1/me/mfa",
		"/api/v1/system/status", "/api/v1/admin/settings", "/admin", "/admin/users", "/settings",
	} {
		if rec := serve(d, h, httptest.NewRequest("GET", p, nil)); rec.Code != 200 {
			t.Errorf("%s blocked during maintenance: %d", p, rec.Code)
		}
	}

	// Administrators pass everywhere (fakeAuth: cookie s=1 is an admin session).
	r := httptest.NewRequest("GET", "/api/v1/spaces", nil)
	r.AddCookie(&http.Cookie{Name: "s", Value: "1"})
	if rec := serve(d, h, r); rec.Code != 200 {
		t.Errorf("admin blocked during maintenance: %d %s", rec.Code, rec.Body.String())
	}
	// A member token does not.
	r = httptest.NewRequest("GET", "/api/v1/spaces", nil)
	r.Header.Set("Authorization", "Bearer good")
	if rec := serve(d, h, r); rec.Code != 503 {
		t.Errorf("member token passed during maintenance: %d", rec.Code)
	}
	// But members keep their own account settings (documented behaviour).
	r = httptest.NewRequest("PATCH", "/api/v1/me/profile", nil)
	r.Header.Set("Authorization", "Bearer good")
	if rec := serve(d, h, r); rec.Code != 200 {
		t.Errorf("member's own profile during maintenance: %d", rec.Code)
	}
	// Bad credentials are not an error here, just "not an administrator".
	r = httptest.NewRequest("GET", "/api/v1/spaces", nil)
	r.Header.Set("Authorization", "Bearer bad")
	if rec := serve(d, h, r); rec.Code != 503 || code(t, rec) != "unavailable" {
		t.Errorf("bad token during maintenance: %d %s", rec.Code, code(t, rec))
	}

	// An anonymous request costs no authentication lookup and is still refused.
	if rec := serve(d, h, httptest.NewRequest("GET", "/api/v1/spaces", nil)); rec.Code != 503 {
		t.Errorf("anonymous during maintenance: %d", rec.Code)
	}

	// Trusted in-process callers pass: this is how the CLI switches it off.
	r = withP(httptest.NewRequest("PATCH", "/api/v1/admin/settings", nil), core.SystemPrincipal(core.ViaSocket))
	if rec := serve(d, h, r); rec.Code != 200 {
		t.Errorf("admin socket blocked during maintenance: %d", rec.Code)
	}

	// Switching it off restores everything.
	e.s.set(KeyMaintenanceEnabled, false)
	if rec := serve(d, h, httptest.NewRequest("GET", "/api/v1/spaces", nil)); rec.Code != 200 {
		t.Fatalf("maintenance off again: %d", rec.Code)
	}
}

// A nil notice handler (or a nil Deps) must not panic.
func TestMaintenanceGateDegrades(t *testing.T) {
	h := Maintenance(nil)(http.HandlerFunc(ok))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/files", nil))
	if rec.Code != 200 {
		t.Fatalf("no deps: %d", rec.Code)
	}
	e := newEnv(t)
	e.s.set(KeyMaintenanceEnabled, true)
	if rec := serve(e.d, h, httptest.NewRequest("GET", "/files", nil)); rec.Code != 503 {
		t.Fatalf("nil notice: %d", rec.Code)
	}
}

// The two settings the CLI reads must be registered with the documented
// defaults, or `fileparcel maintenance` degrades to "no maintenance mode".
func TestMaintenanceSettingsRegistered(t *testing.T) {
	defs := map[string]settings.Def{}
	for _, d := range settings.Defs() {
		defs[d.Key] = d
	}
	en, ok := defs[KeyMaintenanceEnabled]
	if !ok {
		t.Fatalf("%s is not registered", KeyMaintenanceEnabled)
	}
	if en.Section != "general" || en.Type != settings.TypeBool || en.Default != false || en.Restart {
		t.Errorf("%s: %+v", KeyMaintenanceEnabled, en)
	}
	msg, ok := defs[KeyMaintenanceMessage]
	if !ok {
		t.Fatalf("%s is not registered", KeyMaintenanceMessage)
	}
	if msg.Section != "general" || msg.Type != settings.TypeString || msg.Default != "" {
		t.Errorf("%s: %+v", KeyMaintenanceMessage, msg)
	}
	if err := msg.Validate(string(make([]byte, 0))); err != nil {
		t.Errorf("empty message rejected: %v", err)
	}
	long := make([]rune, MaxMaintenanceMessage+1)
	for i := range long {
		long[i] = 'a'
	}
	if err := msg.Validate(string(long)); err == nil {
		t.Error("an over-long message was accepted")
	}
	if err := msg.Validate("bad\x00null"); err == nil {
		t.Error("a control character was accepted")
	}
}

func TestMaintenanceAllowed(t *testing.T) {
	for _, p := range []string{"/healthz", "/readyz", "/login", "/unlock", "/static/x/y.js",
		"/api/v1/auth/login", "/api/v1/me", "/api/v1/me/tokens", "/api/v1/system/status",
		"/api/v1/admin/users", "/admin", "/admin/users"} {
		if !MaintenanceAllowed(p) {
			t.Errorf("%s should stay reachable", p)
		}
	}
	for _, p := range []string{"/", "/files", "/files/abc", "/s/tok", "/api/v1/spaces",
		"/api/v1/nodes/n/content", "/api/v1/shares", "/api/v1/search", "/api/v1/events",
		// invitations stay closed inside the open /api/v1/auth tree
		"/api/v1/auth/invite", "/api/v1/auth/invite/tok", "/api/v1/auth/invite/tok/accept", "/invite/tok",
		// whole segments only: these are not the allow-listed trees
		"/adminish", "/settingsx", "/api/v1/meta", "/static-files", "/trusted"} {
		if MaintenanceAllowed(p) {
			t.Errorf("%s should be blocked", p)
		}
	}
	// The trust page and the CA downloads are one tree.
	for _, p := range []string{"/trust", "/trust/ca.crt", "/trust/ca.pem", "/trust/ca.mobileconfig"} {
		if !MaintenanceAllowed(p) {
			t.Errorf("%s should stay reachable", p)
		}
	}
}
