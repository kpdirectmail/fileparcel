package securityapi

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/netip"
	"net/url"
	"slices"
	"strings"
	"testing"
	"time"

	"fileparcel/internal/app"
	"fileparcel/internal/core"
	"fileparcel/internal/ids"
	"fileparcel/internal/web/mw"
)

// guard kinds of the route table (DESIGN §9.4).
const (
	gPublic = iota
	gFull
	gAdmin
	gAdminElevated
)

type route struct {
	method, path string
	body         any
	guard        int
}

var routes = []route{
	{"GET", "/api/v1/admin/certs", nil, gAdmin},
	{"POST", "/api/v1/admin/certs/renew", nil, gAdmin},
	{"POST", "/api/v1/admin/certs/tailscale/fetch", nil, gAdmin},
	{"GET", "/api/v1/admin/client-certs", nil, gAdmin},
	{"GET", "/api/v1/admin/client-certs/download?ticket=x", nil, gAdmin},
	{"DELETE", "/api/v1/admin/client-certs/ccr_missing", nil, gAdmin},
	{"GET", "/api/v1/admin/keys", nil, gAdmin},
	{"POST", "/api/v1/admin/certs/ca/regenerate", nil, gAdminElevated},
	{"PUT", "/api/v1/admin/certs/custom", CustomCertInput{CertPEM: "x", KeyPEM: "y"}, gAdminElevated},
	{"DELETE", "/api/v1/admin/certs/custom", nil, gAdminElevated},
	{"POST", "/api/v1/admin/certs/acme/apply", nil, gAdminElevated},
	{"POST", "/api/v1/admin/client-certs", core.ClientCertInput{UserID: "usr_nobody"}, gAdminElevated},
	{"POST", "/api/v1/admin/keys/lock", nil, gAdminElevated},
	{"POST", "/api/v1/admin/keys/seal", core.PassphraseInput{Passphrase: "p"}, gAdminElevated},
	{"POST", "/api/v1/admin/keys/unseal", core.PassphraseInput{Passphrase: "correct horse"}, gAdminElevated},
	{"POST", "/api/v1/admin/keys/passphrase", core.PassphraseChangeInput{CurrentPassphrase: "correct horse", NewPassphrase: "correct horse"}, gAdminElevated},
	{"POST", "/api/v1/admin/keys/rotate", core.KeysRotateInput{Target: "bogus"}, gAdminElevated},
	{"POST", "/api/v1/admin/keys/recovery", nil, gAdminElevated},
	{"GET", "/api/v1/me/client-certs", nil, gFull},
	{"POST", "/api/v1/me/client-certs", core.ClientCertInput{}, gFull},
	{"GET", "/api/v1/me/client-certs/download?ticket=x", nil, gFull},
	{"DELETE", "/api/v1/me/client-certs/ccr_missing", nil, gFull},
	{"GET", "/api/v1/system/status", nil, gPublic},
	{"POST", "/api/v1/system/unlock", core.PassphraseInput{Passphrase: "p"}, gPublic},
	{"GET", "/trust/ca.crt", nil, gPublic},
	{"GET", "/trust/ca.pem", nil, gPublic},
	{"GET", "/trust/ca.mobileconfig", nil, gPublic},
}

// guardCodes are the error codes produced by the guards themselves.
var guardCodes = []string{"unauthorized", "forbidden", "elevation_required", "mfa_required", "mfa_enroll_required"}

func TestRouteGuards(t *testing.T) {
	hs := newHarness(t)
	type expect struct {
		status int
		code   string // "" = the guard lets the request through
	}
	unauth := expect{http.StatusUnauthorized, "unauthorized"}
	forbidden := expect{http.StatusForbidden, "forbidden"}
	mfa := expect{http.StatusUnauthorized, "mfa_required"}
	elev := expect{http.StatusForbidden, "elevation_required"}
	pass := expect{}
	want := func(g int, who string) expect {
		switch g {
		case gPublic:
			return pass
		case gFull:
			switch who {
			case "":
				return unauth
			case "mfa-pending":
				return mfa
			case "enrolling":
				// an API token (the harness principals are tokens) of a user who
				// must enrol a second factor is refused everywhere, /me* too: it
				// cannot enrol (mw.RequireFull)
				return expect{http.StatusForbidden, "mfa_enroll_required"}
			}
			return pass
		case gAdmin, gAdminElevated:
			switch who {
			case "":
				return unauth
			case "mfa-pending":
				return mfa
			case "member", "bob", "enrolling":
				if who == "enrolling" {
					return expect{http.StatusForbidden, "mfa_enroll_required"}
				}
				return forbidden
			case "admin":
				if g == gAdminElevated {
					return elev
				}
			}
			return pass
		}
		return pass
	}
	for _, rt := range routes {
		for _, who := range []string{"", "member", "enrolling", "mfa-pending", "admin", "admin-elevated", "socket"} {
			t.Run(fmt.Sprintf("%s %s as %q", rt.method, rt.path, who), func(t *testing.T) {
				rec := hs.do(t, rt.method, rt.path, rt.body, as(who), from("192.168.1.20:5555"))
				exp := want(rt.guard, who)
				code := errCode(rec)
				if exp.code == "" {
					if slices.Contains(guardCodes, code) && !legitimateHandlerDenial(rt, who, code) {
						t.Fatalf("guard rejected: %d %s", rec.Code, rec.Body.String())
					}
					return
				}
				if rec.Code != exp.status || code != exp.code {
					t.Fatalf("got %d %q, want %d %q (%s)", rec.Code, code, exp.status, exp.code, rec.Body.String())
				}
			})
		}
	}
}

// legitimateHandlerDenial lists handler-level denials that are not guard
// failures: self-service disabled, unlock rules, and the enrollment-pending
// user minting credentials.
func legitimateHandlerDenial(rt route, who, code string) bool {
	switch {
	case rt.path == "/api/v1/me/client-certs" && rt.method == "POST":
		return code == "forbidden" || (who == "enrolling" && code == "mfa_enroll_required")
	case rt.path == "/api/v1/system/unlock":
		return code == "unauthorized" // wrong passphrase (the fake is unlocked → 409 normally)
	}
	return false
}

func TestEnrollingUserCannotMintClientCert(t *testing.T) {
	hs := newHarness(t)
	hs.settings.set(keyMTLSSelfService, true)
	rec := hs.do(t, "POST", "/api/v1/me/client-certs", core.ClientCertInput{Name: "x"}, as("enrolling"))
	if rec.Code != http.StatusForbidden || errCode(rec) != "mfa_enroll_required" {
		t.Fatalf("got %d %s", rec.Code, rec.Body.String())
	}
	if hs.certs.called("IssueClient") != 0 {
		t.Fatal("certificate issued")
	}
}

// ---------- certificates ----------

func TestCertEndpoints(t *testing.T) {
	hs := newHarness(t)

	rec := hs.do(t, "GET", "/api/v1/admin/certs", nil, as("admin"))
	if rec.Code != http.StatusOK || decode[core.CertStatus](t, rec).CA == nil {
		t.Fatalf("status: %d %s", rec.Code, rec.Body.String())
	}
	if cc := rec.Header().Get("Cache-Control"); !strings.Contains(cc, "no-store") {
		t.Fatalf("Cache-Control %q", cc)
	}

	tests := []struct {
		name      string
		method    string
		path      string
		body      any
		who       string
		status    int
		check     func(t *testing.T)
		wantCalls string
	}{
		{"renew", "POST", "/api/v1/admin/certs/renew", nil, "admin", 200,
			func(t *testing.T) { expectBool(t, "force", hs.certs.force, false) }, "RenewLocal"},
		{"renew force body", "POST", "/api/v1/admin/certs/renew", RenewInput{Force: true}, "admin", 200,
			func(t *testing.T) { expectBool(t, "force", hs.certs.force, true) }, "RenewLocal"},
		{"renew force query", "POST", "/api/v1/admin/certs/renew?force=true", nil, "admin", 200,
			func(t *testing.T) { expectBool(t, "force", hs.certs.force, true) }, "RenewLocal"},
		{"renew bad query", "POST", "/api/v1/admin/certs/renew?force=maybe", nil, "admin", 422, nil, ""},
		{"renew unknown field", "POST", "/api/v1/admin/certs/renew", `{"forse":true}`, "admin", 422, nil, ""},
		{"regenerate constrained", "POST", "/api/v1/admin/certs/ca/regenerate", nil, "admin-elevated", 200,
			func(t *testing.T) { expectBool(t, "constrained", hs.certs.constrained, true) }, "RegenerateCA"},
		{"regenerate unconstrained", "POST", "/api/v1/admin/certs/ca/regenerate", RegenerateCAInput{Unconstrained: true}, "admin-elevated", 200,
			func(t *testing.T) { expectBool(t, "constrained", hs.certs.constrained, false) }, "RegenerateCA"},
		{"custom set", "PUT", "/api/v1/admin/certs/custom", CustomCertInput{CertPEM: "CERT", KeyPEM: "KEY"}, "admin-elevated", 200,
			func(t *testing.T) {
				if hs.certs.certPEM != "CERT" || hs.certs.keyPEM != "KEY" {
					t.Fatalf("got %q %q", hs.certs.certPEM, hs.certs.keyPEM)
				}
			}, "SetCustom"},
		{"custom too large", "PUT", "/api/v1/admin/certs/custom",
			CustomCertInput{CertPEM: strings.Repeat("A", maxCustomBody), KeyPEM: "KEY"}, "admin-elevated", 413, nil, ""},
		{"custom clear", "DELETE", "/api/v1/admin/certs/custom", nil, "admin-elevated", 200, nil, "ClearCustom"},
		{"acme apply", "POST", "/api/v1/admin/certs/acme/apply", nil, "admin-elevated", 202, nil, "ApplyACME"},
		{"tailscale fetch", "POST", "/api/v1/admin/certs/tailscale/fetch", nil, "admin", 200, nil, "FetchTailscale"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			before := 0
			if tc.wantCalls != "" {
				before = hs.certs.called(tc.wantCalls)
			}
			rec := hs.do(t, tc.method, tc.path, tc.body, as(tc.who))
			if rec.Code != tc.status {
				t.Fatalf("status %d, want %d: %s", rec.Code, tc.status, rec.Body.String())
			}
			if tc.wantCalls != "" && hs.certs.called(tc.wantCalls) != before+1 {
				t.Fatalf("%s not called", tc.wantCalls)
			}
			if rec.Code < 300 {
				if st := decode[core.CertStatus](t, rec); st.CA == nil {
					t.Fatal("no status in the response")
				}
			}
			if tc.check != nil {
				tc.check(t)
			}
		})
	}
}

func expectBool(t *testing.T, name string, got, want bool) {
	t.Helper()
	if got != want {
		t.Fatalf("%s = %v, want %v", name, got, want)
	}
}

func TestCertErrorsPropagate(t *testing.T) {
	hs := newHarness(t)
	hs.certs.err["RenewLocal"] = core.ErrKeysLocked
	hs.certs.err["FetchTailscale"] = core.Errorf(core.ErrPrecondition, "Tailscale is not running")
	hs.certs.err["SetCustom"] = core.Invalid("key_pem", "the private key does not match the certificate")
	for _, tc := range []struct {
		method, path string
		body         any
		who          string
		status       int
		code         string
	}{
		{"POST", "/api/v1/admin/certs/renew", nil, "admin", 503, "keys_locked"},
		{"POST", "/api/v1/admin/certs/tailscale/fetch", nil, "admin", 412, "precondition_failed"},
		{"PUT", "/api/v1/admin/certs/custom", CustomCertInput{CertPEM: "a", KeyPEM: "b"}, "admin-elevated", 422, "invalid"},
	} {
		rec := hs.do(t, tc.method, tc.path, tc.body, as(tc.who))
		if rec.Code != tc.status || errCode(rec) != tc.code {
			t.Fatalf("%s %s: %d %s", tc.method, tc.path, rec.Code, rec.Body.String())
		}
	}
	// Without a certificate service every endpoint answers 503.
	hs.d.Certs = nil
	rec := hs.do(t, "GET", "/api/v1/admin/certs", nil, as("admin"))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("no certs service: %d", rec.Code)
	}
}

// ---------- client certificates ----------

func TestAdminIssueClientCertAndOneTimeDownload(t *testing.T) {
	hs := newHarness(t)
	rec := hs.do(t, "POST", "/api/v1/admin/client-certs",
		core.ClientCertInput{UserID: "alice", Name: "Alice's phone", Days: 30, Legacy: true}, as("admin-elevated"))
	if rec.Code != http.StatusCreated {
		t.Fatalf("issue: %d %s", rec.Code, rec.Body.String())
	}
	res := decode[ClientCertIssued](t, rec)
	if len(hs.certs.issued) != 1 {
		t.Fatal("IssueClient not called")
	}
	in := hs.certs.issued[0]
	if in.UserID != "usr_alice" || in.Days != 30 || !in.Legacy || in.Name != "Alice's phone" {
		t.Fatalf("input %+v", in)
	}
	if hs.certs.issuer == nil || hs.certs.issuer.UserID != "usr_admin" {
		t.Fatalf("issuer %+v", hs.certs.issuer)
	}
	if res.Password == "" || res.Password != in.Password || len(res.Password) < 20 {
		t.Fatalf("generated password %q (sent %q)", res.Password, in.Password)
	}
	if p12, err := base64.StdEncoding.DecodeString(res.P12); err != nil || string(p12) != string(hs.certs.p12) {
		t.Fatalf("p12 %q %v", res.P12, err)
	}
	if res.ClientCert == nil || res.Filename != "alice-alices-phone.p12" {
		t.Fatalf("response %+v", res)
	}
	u, err := url.Parse(res.DownloadURL)
	if err != nil || u.Path != "/api/v1/admin/client-certs/download" || u.Query().Get("ticket") == "" {
		t.Fatalf("download url %q", res.DownloadURL)
	}

	// HEAD does not consume the ticket; another principal cannot use it.
	rec = hs.do(t, "HEAD", res.DownloadURL, nil, as("admin-elevated"))
	if rec.Code != http.StatusOK || rec.Body.Len() != 0 {
		t.Fatalf("HEAD: %d %d bytes", rec.Code, rec.Body.Len())
	}
	rec = hs.do(t, "GET", res.DownloadURL, nil, as("socket"))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("other principal: %d", rec.Code)
	}
	rec = hs.do(t, "GET", res.DownloadURL, nil, as("admin"))
	if rec.Code != http.StatusOK || rec.Body.String() != string(hs.certs.p12) {
		t.Fatalf("download: %d %q", rec.Code, rec.Body.String())
	}
	h := rec.Header()
	if h.Get("Content-Type") != mimePKCS12 || h.Get("X-Content-Type-Options") != "nosniff" ||
		!strings.HasPrefix(h.Get("Content-Disposition"), "attachment") || !strings.Contains(h.Get("Content-Disposition"), "alice-alices-phone.p12") ||
		!strings.Contains(h.Get("Cache-Control"), "no-store") {
		t.Fatalf("headers %v", h)
	}
	rec = hs.do(t, "GET", res.DownloadURL, nil, as("admin"))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("second download: %d", rec.Code)
	}

	// A caller-chosen password is never echoed; user ids pass unchanged.
	uid := ids.New(ids.PrefixUser)
	rec = hs.do(t, "POST", "/api/v1/admin/client-certs",
		core.ClientCertInput{UserID: uid, Password: "hunter2hunter2"}, as("admin-elevated"))
	if rec.Code != http.StatusCreated || decode[ClientCertIssued](t, rec).Password != "" {
		t.Fatalf("chosen password: %d %s", rec.Code, rec.Body.String())
	}
	if got := hs.certs.issued[1]; got.Password != "hunter2hunter2" || got.UserID != uid {
		t.Fatalf("input %+v", got)
	}

	// Unknown usernames are 404 before anything is issued.
	n := hs.certs.called("IssueClient")
	rec = hs.do(t, "POST", "/api/v1/admin/client-certs", core.ClientCertInput{UserID: "mallory"}, as("admin-elevated"))
	if rec.Code != http.StatusNotFound || hs.certs.called("IssueClient") != n {
		t.Fatalf("unknown user: %d", rec.Code)
	}
	rec = hs.do(t, "POST", "/api/v1/admin/client-certs", core.ClientCertInput{}, as("admin-elevated"))
	if rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("missing user: %d", rec.Code)
	}
}

func TestAdminClientListAndRevoke(t *testing.T) {
	hs := newHarness(t)
	hs.certs.certs = []core.ClientCert{
		{ID: "ccr_a", UserID: "usr_alice", Name: "a"},
		{ID: "ccr_b", UserID: "usr_bob", Name: "b"},
	}
	rec := hs.do(t, "GET", "/api/v1/admin/client-certs", nil, as("admin"))
	if rec.Code != 200 || len(decode[core.Page[core.ClientCert]](t, rec).Items) != 2 {
		t.Fatalf("list all: %d %s", rec.Code, rec.Body.String())
	}
	rec = hs.do(t, "GET", "/api/v1/admin/client-certs?user_id=alice", nil, as("admin"))
	if p := decode[core.Page[core.ClientCert]](t, rec); rec.Code != 200 || len(p.Items) != 1 || p.Items[0].ID != "ccr_a" {
		t.Fatalf("list alice: %d %s", rec.Code, rec.Body.String())
	}
	rec = hs.do(t, "GET", "/api/v1/admin/client-certs?user_id=nobody", nil, as("admin"))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("unknown user filter: %d", rec.Code)
	}
	rec = hs.do(t, "DELETE", "/api/v1/admin/client-certs/ccr_b?reason=lost+phone", nil, as("admin"))
	if rec.Code != http.StatusNoContent || len(hs.certs.revoked) != 1 || hs.certs.revoked[0] != "ccr_b|lost phone" {
		t.Fatalf("revoke: %d %v", rec.Code, hs.certs.revoked)
	}
	rec = hs.do(t, "DELETE", "/api/v1/admin/client-certs/ccr_zzz", nil, as("admin"))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("revoke unknown: %d", rec.Code)
	}
}

func TestMeClientCerts(t *testing.T) {
	hs := newHarness(t)
	hs.certs.certs = []core.ClientCert{
		{ID: "ccr_alice1", UserID: "usr_alice", Name: "laptop", NotAfter: testNow.Add(time.Hour)},
		{ID: "ccr_bob1", UserID: "usr_bob", Name: "bob", NotAfter: testNow.Add(time.Hour)},
	}

	// Self-service is off by default. "socket-as-alice" issues: minting a
	// client certificate is closed to API tokens (see TestMeClientCertIssueRefusesTokens).
	rec := hs.do(t, "POST", "/api/v1/me/client-certs", core.ClientCertInput{Name: "phone"}, as("socket-as-alice"))
	if rec.Code != http.StatusForbidden || hs.certs.called("IssueClient") != 0 {
		t.Fatalf("self-service off: %d %s", rec.Code, rec.Body.String())
	}
	hs.settings.set(keyMTLSSelfService, true)

	rec = hs.do(t, "POST", "/api/v1/me/client-certs", core.ClientCertInput{Name: "phone"}, as("socket-as-alice"))
	if rec.Code != http.StatusCreated {
		t.Fatalf("self-service issue: %d %s", rec.Code, rec.Body.String())
	}
	res := decode[ClientCertIssued](t, rec)
	if hs.certs.issued[0].UserID != "usr_alice" || !strings.HasPrefix(res.DownloadURL, "/api/v1/me/client-certs/download?ticket=") {
		t.Fatalf("issued %+v %q", hs.certs.issued[0], res.DownloadURL)
	}
	// The member downloads it once.
	if rec = hs.do(t, "GET", res.DownloadURL, nil, as("member")); rec.Code != http.StatusOK {
		t.Fatalf("member download: %d", rec.Code)
	}
	if rec = hs.do(t, "GET", res.DownloadURL, nil, as("member")); rec.Code != http.StatusNotFound {
		t.Fatalf("member second download: %d", rec.Code)
	}

	for _, tc := range []struct {
		name string
		in   core.ClientCertInput
		code int
	}{
		{"for someone else", core.ClientCertInput{UserID: "usr_bob"}, 422},
		{"too long", core.ClientCertInput{Days: 366}, 422},
		{"own id explicitly", core.ClientCertInput{UserID: "usr_alice", Days: 365}, 201},
	} {
		rec := hs.do(t, "POST", "/api/v1/me/client-certs", tc.in, as("socket-as-alice"))
		if rec.Code != tc.code {
			t.Fatalf("%s: %d %s", tc.name, rec.Code, rec.Body.String())
		}
	}

	// Listing shows only the caller's certificates.
	rec = hs.do(t, "GET", "/api/v1/me/client-certs", nil, as("member"))
	page := decode[core.Page[core.ClientCert]](t, rec)
	for _, c := range page.Items {
		if c.UserID != "usr_alice" {
			t.Fatalf("foreign certificate listed: %+v", c)
		}
	}
	if len(page.Items) != 3 {
		t.Fatalf("own certificates: %d", len(page.Items))
	}

	// Revocation: own yes; someone else's is not found — also for admins
	// using the /me route.
	if rec = hs.do(t, "DELETE", "/api/v1/me/client-certs/ccr_alice1", nil, as("member")); rec.Code != http.StatusNoContent {
		t.Fatalf("own revoke: %d", rec.Code)
	}
	if rec = hs.do(t, "DELETE", "/api/v1/me/client-certs/ccr_bob1", nil, as("member")); rec.Code != http.StatusNotFound {
		t.Fatalf("foreign revoke: %d", rec.Code)
	}
	if rec = hs.do(t, "DELETE", "/api/v1/me/client-certs/ccr_bob1", nil, as("admin")); rec.Code != http.StatusNotFound {
		t.Fatalf("admin via /me: %d", rec.Code)
	}
	if by := hs.certs.revokeBy[0]; by.Role != core.RoleMember {
		t.Fatalf("revoke principal role %q", by.Role)
	}

	// The socket principal has no user: it must act as one.
	rec = hs.do(t, "GET", "/api/v1/me/client-certs", nil, as("socket"))
	if rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("socket /me: %d", rec.Code)
	}
}

// TestMeClientCertIssueRefusesTokens: an API token must not mint an mTLS
// client certificate — a network-layer credential valid for up to a year
// that no token scope implies. Listing, revoking and the one-time download
// stay open (revoking is a de-escalation).
func TestMeClientCertIssueRefusesTokens(t *testing.T) {
	hs := newHarness(t)
	hs.settings.set(keyMTLSSelfService, true)
	hs.certs.certs = []core.ClientCert{{ID: "ccr_alice1", UserID: "usr_alice", Name: "laptop", NotAfter: testNow.Add(time.Hour)}}

	rec := hs.do(t, "POST", "/api/v1/me/client-certs", core.ClientCertInput{Name: "from-token"}, as("member"))
	if rec.Code != http.StatusForbidden || errCode(rec) != "forbidden" {
		t.Fatalf("token issue: %d %s", rec.Code, rec.Body.String())
	}
	if hs.certs.called("IssueClient") != 0 {
		t.Fatal("certificate issued for an API token")
	}
	// A browser session (or the admin socket) still issues.
	if rec = hs.do(t, "POST", "/api/v1/me/client-certs", core.ClientCertInput{Name: "ok"}, as("socket-as-alice")); rec.Code != http.StatusCreated {
		t.Fatalf("session issue: %d %s", rec.Code, rec.Body.String())
	}
	// Tokens keep the read and revoke routes.
	if rec = hs.do(t, "GET", "/api/v1/me/client-certs", nil, as("member")); rec.Code != http.StatusOK {
		t.Fatalf("token list: %d %s", rec.Code, rec.Body.String())
	}
	if rec = hs.do(t, "DELETE", "/api/v1/me/client-certs/ccr_alice1", nil, as("member")); rec.Code != http.StatusNoContent {
		t.Fatalf("token revoke: %d %s", rec.Code, rec.Body.String())
	}
}

func TestMeClientCertActiveLimit(t *testing.T) {
	hs := newHarness(t)
	hs.settings.set(keyMTLSSelfService, true)
	revoked := testNow
	for i := range selfServiceMaxActive + 3 {
		c := core.ClientCert{ID: fmt.Sprintf("ccr_%d", i), UserID: "usr_alice", NotAfter: testNow.Add(time.Hour)}
		switch {
		case i < 2:
			c.RevokedAt = &revoked // does not count
		case i == 2:
			c.NotAfter = testNow.Add(-time.Hour) // expired: does not count
		}
		hs.certs.certs = append(hs.certs.certs, c)
	}
	// 25 active → refused.
	rec := hs.do(t, "POST", "/api/v1/me/client-certs", core.ClientCertInput{}, as("socket-as-alice"))
	if rec.Code != http.StatusConflict {
		t.Fatalf("limit: %d %s", rec.Code, rec.Body.String())
	}
	hs.certs.certs = hs.certs.certs[:selfServiceMaxActive+2] // 24 active
	rec = hs.do(t, "POST", "/api/v1/me/client-certs", core.ClientCertInput{}, as("socket-as-alice"))
	if rec.Code != http.StatusCreated {
		t.Fatalf("below limit: %d %s", rec.Code, rec.Body.String())
	}
}

func TestP12Store(t *testing.T) {
	s := newP12Store()
	now := testNow
	tok := s.put([]byte("data"), "a.p12", "u:1", now)
	if _, _, ok := s.take(tok, "u:2", now, true); ok {
		t.Fatal("other owner")
	}
	for _, bad := range []string{"", "not a token!", strings.Repeat("a", 65), tok + "x"} {
		if _, _, ok := s.take(bad, "u:1", now, true); ok {
			t.Fatalf("bad token %q accepted", bad)
		}
	}
	if d, name, ok := s.take(tok, "u:1", now, false); !ok || string(d) != "data" || name != "a.p12" {
		t.Fatal("peek")
	}
	if _, _, ok := s.take(tok, "u:1", now.Add(p12TTL+time.Second), true); ok {
		t.Fatal("expired entry served")
	}
	if len(s.m) != 0 {
		t.Fatal("expired entry kept")
	}
	// Bounded: the oldest entry is evicted.
	first := s.put([]byte("0"), "0.p12", "u:1", now)
	for i := 1; i <= p12MaxEntries; i++ {
		s.put([]byte("x"), "x.p12", "u:1", now.Add(time.Duration(i)*time.Millisecond))
	}
	if len(s.m) != p12MaxEntries {
		t.Fatalf("entries %d", len(s.m))
	}
	if _, _, ok := s.take(first, "u:1", now, true); ok {
		t.Fatal("oldest entry not evicted")
	}
	// Tickets are stored hashed.
	for k := range s.m {
		if strings.Contains(k, tok) {
			t.Fatal("ticket stored in clear")
		}
	}
}

func TestP12Filename(t *testing.T) {
	for _, tc := range []struct {
		user, name, want string
	}{
		{"alice", "Alice's Phone", "alice-alices-phone.p12"},
		{"alice", "", "alice.p12"},
		{"", "", "client-certificate.p12"},
		{"Bob", "../../etc/passwd", "bob-etcpasswd.p12"},
		{"a b", "c\nd", "a-b-cd.p12"},
		{"ève", "Ωmega", "ve-mega.p12"},
		{"x", strings.Repeat("n", 200), "x-" + strings.Repeat("n", 78) + ".p12"},
	} {
		if got := p12Filename(&core.ClientCert{Username: tc.user, Name: tc.name}); got != tc.want {
			t.Errorf("p12Filename(%q, %q) = %q, want %q", tc.user, tc.name, got, tc.want)
		}
	}
}

func TestOwnerKey(t *testing.T) {
	if ownerKey(nil) != "" || ownerKey(&core.Principal{UserID: "usr_1"}) != "u:usr_1" ||
		ownerKey(core.SystemPrincipal(core.ViaSocket)) != "sys:socket" {
		t.Fatal("ownerKey")
	}
}

// ---------- keys ----------

func TestKeysEndpoints(t *testing.T) {
	hs := newHarness(t)
	rec := hs.do(t, "GET", "/api/v1/admin/keys", nil, as("admin"))
	if st := decode[core.KeyStatus](t, rec); rec.Code != 200 || st.WebUnlock != "lan" || st.State != core.KeyStateUnlocked {
		t.Fatalf("status: %d %s", rec.Code, rec.Body.String())
	}
	hs.settings.set(keyWebUnlock, "off")
	if st := decode[core.KeyStatus](t, hs.do(t, "GET", "/api/v1/admin/keys", nil, as("admin"))); st.WebUnlock != "off" {
		t.Fatalf("web_unlock %q", st.WebUnlock)
	}

	for _, tc := range []struct {
		name   string
		path   string
		body   any
		status int
		call   string
	}{
		{"seal", "/api/v1/admin/keys/seal", core.PassphraseInput{Passphrase: "correct horse"}, 200, "Seal"},
		{"seal empty", "/api/v1/admin/keys/seal", core.PassphraseInput{}, 422, ""},
		{"seal unknown field", "/api/v1/admin/keys/seal", `{"pass":"x"}`, 422, ""},
		{"unseal wrong", "/api/v1/admin/keys/unseal", core.PassphraseInput{Passphrase: "nope"}, 401, ""},
		{"unseal", "/api/v1/admin/keys/unseal", core.PassphraseInput{Passphrase: "correct horse"}, 200, "Unseal"},
		{"passphrase missing current", "/api/v1/admin/keys/passphrase", core.PassphraseChangeInput{NewPassphrase: "n"}, 422, ""},
		{"passphrase missing new", "/api/v1/admin/keys/passphrase", core.PassphraseChangeInput{CurrentPassphrase: "c"}, 422, ""},
		{"passphrase wrong", "/api/v1/admin/keys/passphrase",
			core.PassphraseChangeInput{CurrentPassphrase: "nope", NewPassphrase: "new pass"}, 401, ""},
		{"passphrase", "/api/v1/admin/keys/passphrase",
			core.PassphraseChangeInput{CurrentPassphrase: "correct horse", NewPassphrase: "battery staple"}, 200, "ChangePassphrase"},
		{"lock", "/api/v1/admin/keys/lock", nil, 200, "Lock"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rec := hs.do(t, "POST", tc.path, tc.body, as("admin-elevated"))
			if rec.Code != tc.status {
				t.Fatalf("%d %s", rec.Code, rec.Body.String())
			}
			if tc.call != "" && !hs.keys.called(tc.call) {
				t.Fatalf("%s not called", tc.call)
			}
		})
	}
	if hs.keys.pass != "battery staple" {
		t.Fatal("passphrase not changed")
	}

	rec = hs.do(t, "POST", "/api/v1/admin/keys/recovery", nil, as("admin-elevated"))
	if rk := decode[core.RecoveryKey](t, rec); rec.Code != 200 || rk.RecoveryKey != "FPRK-TEST-1234" {
		t.Fatalf("recovery: %d %s", rec.Code, rec.Body.String())
	}
	if cc := rec.Header().Get("Cache-Control"); !strings.Contains(cc, "no-store") {
		t.Fatalf("recovery key cacheable: %q", cc)
	}
	hs.keys.err["Lock"] = core.Errorf(core.ErrConflict, "plain mode cannot be locked")
	if rec = hs.do(t, "POST", "/api/v1/admin/keys/lock", nil, as("admin-elevated")); rec.Code != http.StatusConflict {
		t.Fatalf("lock error: %d", rec.Code)
	}
	// The key service audits these operations itself: no duplicates here.
	if n := hs.audit.count(); n != 0 {
		t.Fatalf("handlers wrote %d audit entries: %+v", n, hs.audit.entries)
	}
}

func TestKeysRotate(t *testing.T) {
	for _, tc := range []struct {
		name       string
		in         any
		mode       app.Mode
		status     int
		wantJob    string
		wantParams string
		wantRotate string
	}{
		{"kek default purpose", core.KeysRotateInput{Target: "kek"}, app.ModeNetwork, 202, core.JobKeysRotateKEK, `{"purpose":"blob"}`, ""},
		{"kek field", core.KeysRotateInput{Target: "KEK", Purpose: "Field"}, app.ModeNetwork, 202, core.JobKeysRotateKEK, `{"purpose":"field"}`, ""},
		{"kek mac refused", core.KeysRotateInput{Target: "kek", Purpose: "mac"}, app.ModeNetwork, 422, "", "", ""},
		{"data", core.KeysRotateInput{Target: "data"}, app.ModeNetwork, 202, core.JobKeysReencrypt, `{}`, ""},
		{"master", core.KeysRotateInput{Target: "master"}, app.ModeNetwork, 200, "", "", "master"},
		{"unknown target", core.KeysRotateInput{Target: "everything"}, app.ModeNetwork, 422, "", "", ""},
		{"empty body", nil, app.ModeNetwork, 422, "", "", ""},
		{"kek offline runs now", core.KeysRotateInput{Target: "kek", Purpose: "blob"}, app.ModeOffline, 200, "", "", "kek:blob"},
		{"data offline queues", core.KeysRotateInput{Target: "data"}, app.ModeOffline, 202, core.JobKeysReencrypt, `{}`, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			hs := newHarness(t)
			hs.d.Mode = tc.mode
			rec := hs.do(t, "POST", "/api/v1/admin/keys/rotate", tc.in, as("admin-elevated"))
			if rec.Code != tc.status {
				t.Fatalf("%d %s", rec.Code, rec.Body.String())
			}
			if tc.wantJob != "" {
				if len(hs.jobs.q) != 1 || hs.jobs.q[0].kind != tc.wantJob || hs.jobs.q[0].params != tc.wantParams {
					t.Fatalf("enqueued %+v", hs.jobs.q)
				}
				if hs.jobs.q[0].by == nil || hs.jobs.q[0].by.UserID != "usr_admin" {
					t.Fatal("job not attributed to the administrator")
				}
				if ref := decode[core.JobRef](t, rec); ref.JobID == "" {
					t.Fatal("no job id")
				}
				e := hs.audit.find(core.ActKeysRotate)
				if len(e) != 1 || e[0].Outcome != "" || e[0].Details.(map[string]any)["phase"] != "queued" ||
					e[0].Details.(map[string]any)["job_id"] == nil {
					t.Fatalf("audit %+v", e)
				}
			} else if len(hs.jobs.q) != 0 {
				t.Fatalf("unexpected job %+v", hs.jobs.q)
			}
			if tc.wantRotate != "" && (len(hs.keys.rotate) != 1 || hs.keys.rotate[0] != tc.wantRotate) {
				t.Fatalf("rotations %v", hs.keys.rotate)
			}
			if tc.wantJob == "" && hs.audit.count() != 0 {
				t.Fatalf("synchronous rotations are audited by the key service: %+v", hs.audit.entries)
			}
		})
	}

	t.Run("enqueue failure", func(t *testing.T) {
		hs := newHarness(t)
		hs.jobs.err = core.Errorf(core.ErrConflict, "a key job is already running")
		rec := hs.do(t, "POST", "/api/v1/admin/keys/rotate", core.KeysRotateInput{Target: "data"}, as("admin-elevated"))
		if rec.Code != http.StatusConflict {
			t.Fatalf("%d", rec.Code)
		}
		if e := hs.audit.find(core.ActKeysRotate); len(e) != 1 || e[0].Outcome != core.OutcomeFailure {
			t.Fatalf("audit %+v", e)
		}
	})
	t.Run("no job service", func(t *testing.T) {
		hs := newHarness(t)
		hs.d.Jobs = nil
		if rec := hs.do(t, "POST", "/api/v1/admin/keys/rotate", core.KeysRotateInput{Target: "data"}, as("admin-elevated")); rec.Code != 503 {
			t.Fatalf("%d", rec.Code)
		}
		if rec := hs.do(t, "POST", "/api/v1/admin/keys/rotate", core.KeysRotateInput{Target: "kek"}, as("admin-elevated")); rec.Code != 200 {
			t.Fatalf("kek without jobs: %d", rec.Code)
		}
	})
}

// ---------- system ----------

func TestSystemStatus(t *testing.T) {
	hs := newHarness(t)
	for _, tc := range []struct {
		state core.KeyState
		users int
		setup bool
	}{
		{core.KeyStateUnlocked, 2, false},
		{core.KeyStateLocked, 1, false},
		{core.KeyStateUnlocked, 0, true},
	} {
		hs.keys.state, hs.users.count = tc.state, tc.users
		rec := hs.do(t, "GET", "/api/v1/system/status", nil)
		st := decode[core.SystemStatus](t, rec)
		if rec.Code != 200 || st.State != tc.state || st.SetupNeeded != tc.setup {
			t.Fatalf("%+v: %d %s", tc, rec.Code, rec.Body.String())
		}
	}
	hs.d.Keys, hs.d.Users = nil, nil
	if st := decode[core.SystemStatus](t, hs.do(t, "GET", "/api/v1/system/status", nil)); st.State != core.KeyStateUninitialized {
		t.Fatalf("no keys service: %+v", st)
	}
}

func TestSystemUnlockNetworkPolicy(t *testing.T) {
	for _, tc := range []struct {
		mode   string
		addr   string
		who    string
		status int
	}{
		{"", "192.168.1.5:40000", "", 200}, // default lan
		{"lan", "192.168.1.5:40000", "", 200},
		{"lan", "10.1.2.3:40000", "", 200},
		{"lan", "100.64.0.10:40000", "", 200}, // tailnet
		{"lan", "[fd7a:115c:a1e0::5]:40000", "", 200},
		{"lan", "[::ffff:192.168.1.5]:40000", "", 200}, // IPv4-mapped
		{"lan", "[fe80::1%eth0]:40000", "", 200},
		{"lan", "203.0.113.9:40000", "", 403},
		{"lan", "[2001:db8::1]:40000", "", 403},
		{"lan", "203.0.113.9:40000", "admin-elevated", 403}, // a session does not lift the rule
		{"any", "203.0.113.9:40000", "", 200},
		{"off", "192.168.1.5:40000", "", 403},
		{"off", "127.0.0.1:40000", "", 403},
		{"off", "@", "socket", 200},             // the admin socket always may
		{"off", "@", "socket-as-alice", 200},    // also acting as a user (X-FP-As)
		{"off", "@", "offline", 200},            // in-process CLI
		{"bogus", "203.0.113.9:40000", "", 403}, // unknown values fall back to lan
	} {
		t.Run(fmt.Sprintf("%s from %s as %q", tc.mode, tc.addr, tc.who), func(t *testing.T) {
			hs := newHarness(t)
			hs.keys.state = core.KeyStateLocked
			if tc.mode != "" {
				hs.settings.set(keyWebUnlock, tc.mode)
			}
			rec := hs.do(t, "POST", "/api/v1/system/unlock", core.PassphraseInput{Passphrase: "correct horse"}, from(tc.addr), as(tc.who))
			if rec.Code != tc.status {
				t.Fatalf("%d %s", rec.Code, rec.Body.String())
			}
			if tc.status == 200 {
				if st := decode[core.SystemStatus](t, rec); st.State != core.KeyStateUnlocked {
					t.Fatalf("state %q", st.State)
				}
				return
			}
			if hs.keys.called("Unlock") {
				t.Fatal("Unlock called despite the network rule")
			}
			e := hs.audit.find(core.ActKeysUnlock)
			if len(e) != 1 || e[0].Outcome != core.OutcomeDenied {
				t.Fatalf("denial not audited: %+v", e)
			}
		})
	}
}

func TestSystemUnlock(t *testing.T) {
	lan := from("192.168.1.5:40000")
	t.Run("wrong then right", func(t *testing.T) {
		hs := newHarness(t)
		hs.keys.state = core.KeyStateLocked
		rec := hs.do(t, "POST", "/api/v1/system/unlock", core.PassphraseInput{Passphrase: "wrong"}, lan,
			func(r *http.Request) { r.Header.Set("User-Agent", "unit-test") })
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("wrong: %d", rec.Code)
		}
		// Anonymous callers reach the key service with a rights-less
		// principal that carries their address for the audit log.
		p := hs.keys.ctxP
		if p == nil || p.IP != netip.MustParseAddr("192.168.1.5") || p.UserAgent != "unit-test" || p.RequestID == "" ||
			p.Role != "" || p.UserID != "" || p.IsAdmin() || p.Elevated(testNow) || p.Full() {
			t.Fatalf("context principal %+v", p)
		}
		rec = hs.do(t, "POST", "/api/v1/system/unlock", core.PassphraseInput{Passphrase: "correct horse"}, lan)
		if rec.Code != 200 {
			t.Fatalf("right: %d", rec.Code)
		}
		if n := len(hs.audit.find(core.ActKeysUnlock)); n != 0 {
			t.Fatalf("handler duplicated the key service's audit (%d)", n)
		}
	})
	for _, tc := range []struct {
		name   string
		state  core.KeyState
		body   any
		status int
	}{
		{"already unlocked", core.KeyStateUnlocked, core.PassphraseInput{Passphrase: "x"}, 409},
		{"uninitialized", core.KeyStateUninitialized, core.PassphraseInput{Passphrase: "x"}, 409},
		{"missing passphrase", core.KeyStateLocked, core.PassphraseInput{}, 422},
		{"bad json", core.KeyStateLocked, `{"passphrase":`, 422},
		{"unknown field", core.KeyStateLocked, `{"password":"x"}`, 422},
	} {
		t.Run(tc.name, func(t *testing.T) {
			hs := newHarness(t)
			hs.keys.state = tc.state
			rec := hs.do(t, "POST", "/api/v1/system/unlock", tc.body, lan)
			if rec.Code != tc.status {
				t.Fatalf("%d %s", rec.Code, rec.Body.String())
			}
			if hs.keys.called("Unlock") {
				t.Fatal("Unlock called")
			}
		})
	}
	t.Run("logged-in principal is kept", func(t *testing.T) {
		hs := newHarness(t)
		hs.keys.state = core.KeyStateLocked
		rec := hs.do(t, "POST", "/api/v1/system/unlock", core.PassphraseInput{Passphrase: "correct horse"}, lan, as("admin"))
		if rec.Code != 200 || hs.keys.ctxP == nil || hs.keys.ctxP.UserID != "usr_admin" {
			t.Fatalf("%d %+v", rec.Code, hs.keys.ctxP)
		}
	})
}

// On a dual-stack home network the LAN also has a global IPv6 /64, which the
// .local name advertises and browsers prefer: keys.web_unlock=lan admits the
// server's own on-link IPv6 subnets, not other global addresses.
func TestSystemUnlockOnLinkIPv6(t *testing.T) {
	pfx := netip.MustParsePrefix
	wifi := core.NetInterface{Name: "wlan0", Kind: core.IfWiFi, Up: true,
		Addrs: []netip.Prefix{pfx("192.168.1.10/24"), pfx("2001:db8:1::10/64"), pfx("fe80::10/64")}}
	down := core.NetInterface{Name: "eth1", Kind: core.IfLAN, Up: false, Addrs: []netip.Prefix{pfx("2001:db8:3::10/64")}}
	wg := core.NetInterface{Name: "wg0", Kind: core.IfWireGuard, Up: true, IsVPN: true,
		Addrs: []netip.Prefix{pfx("2001:db8:4::1/128"), pfx("2001:db8:5::1/64")}}
	vm := core.NetInterface{Name: "eth0", Kind: core.IfLAN, Up: true, // a cloud VM's uplink
		Addrs: []netip.Prefix{pfx("203.0.113.10/24"), pfx("2001:db8:6::10/64")}}
	wide := core.NetInterface{Name: "eth2", Kind: core.IfLAN, Up: true, Addrs: []netip.Prefix{pfx("2001:db8:7::10/48")}}
	docker := core.NetInterface{Name: "docker0", Kind: core.IfContainer, Up: true, Addrs: []netip.Prefix{pfx("2001:db8:8::1/64")}}
	// v4 interface roles: an outgoing VPN's subnet is the provider's, an
	// override to mesh makes a tunnel count again.
	exit := core.NetInterface{Name: "nordlynx", Kind: core.IfExitVPN, Up: true, IsVPN: true, Role: core.VPNRoleEgress,
		Addrs: []netip.Prefix{pfx("2001:db8:9::2/64")}}
	access := core.NetInterface{Name: "tun0", Kind: core.IfCorpVPN, Up: true, IsVPN: true, Role: core.VPNRoleAccess,
		Addrs: []netip.Prefix{pfx("2001:db8:a::2/64")}}
	meshed := core.NetInterface{Name: "wg1", Kind: core.IfWireGuard, Up: true, IsVPN: true, Role: core.VPNRoleMesh,
		RoleSource: core.VPNRoleSourceOverride, Addrs: []netip.Prefix{pfx("2001:db8:b::1/64")}}
	all := []core.NetInterface{wifi, down, wg, vm, wide, docker, exit, access, meshed}
	for _, tc := range []struct {
		name   string
		net    core.Network
		addr   string
		status int
	}{
		{"own /64", &fakeNetwork{ifs: all}, "[2001:db8:1::abcd]:40000", 200},
		{"other global prefix", &fakeNetwork{ifs: all}, "[2001:db8:2::1]:40000", 403},
		{"interface down", &fakeNetwork{ifs: all}, "[2001:db8:3::1]:40000", 403},
		{"VPN host-only /128", &fakeNetwork{ifs: all}, "[2001:db8:4::2]:40000", 403},
		{"VPN subnet", &fakeNetwork{ifs: all}, "[2001:db8:5::2]:40000", 200},
		{"next to a public IPv4", &fakeNetwork{ifs: all}, "[2001:db8:6::abcd]:40000", 403},
		{"wider than /64", &fakeNetwork{ifs: all}, "[2001:db8:7::abcd]:40000", 403},
		{"container network", &fakeNetwork{ifs: all}, "[2001:db8:8::2]:40000", 403},
		{"outgoing VPN subnet", &fakeNetwork{ifs: all}, "[2001:db8:9::abcd]:40000", 403},
		{"access VPN subnet", &fakeNetwork{ifs: all}, "[2001:db8:a::abcd]:40000", 403},
		{"VPN made mesh by an override", &fakeNetwork{ifs: all}, "[2001:db8:b::2]:40000", 200},
		{"public IPv4 in the VM's subnet", &fakeNetwork{ifs: all}, "203.0.113.20:40000", 403},
		{"private ranges without a listing", &fakeNetwork{err: core.ErrUnavailable}, "192.168.1.5:40000", 200},
		{"listing fails", &fakeNetwork{err: core.ErrUnavailable}, "[2001:db8:1::abcd]:40000", 403},
		{"no network information", nil, "[2001:db8:1::abcd]:40000", 403},
	} {
		t.Run(tc.name, func(t *testing.T) {
			hs := newHarness(t)
			hs.keys.state = core.KeyStateLocked
			if tc.net != nil {
				hs.d.Network = tc.net
			}
			rec := hs.do(t, "POST", "/api/v1/system/unlock", core.PassphraseInput{Passphrase: "correct horse"}, from(tc.addr))
			if rec.Code != tc.status {
				t.Fatalf("%d %s", rec.Code, rec.Body.String())
			}
		})
	}
}

func TestIsLAN(t *testing.T) {
	for addr, want := range map[string]bool{
		"127.0.0.1": true, "10.0.0.1": true, "172.16.5.4": true, "172.32.0.1": false, "192.168.0.1": true,
		"169.254.1.1": true, "100.64.0.1": true, "100.128.0.1": false, "::1": true, "fd00::1": true, "fe80::1": true,
		"::ffff:10.0.0.1": true, "8.8.8.8": false, "2001:4860::1": false, "::ffff:8.8.8.8": false,
	} {
		if got := isLAN(netip.MustParseAddr(addr)); got != want {
			t.Errorf("isLAN(%s) = %v", addr, got)
		}
	}
}

// ---------- trust downloads ----------

func TestTrustDownloads(t *testing.T) {
	hs := newHarness(t)
	for _, tc := range []struct {
		path, ctype, file string
	}{
		{"/trust/ca.crt", "application/x-x509-ca-cert", "fileparcel-ca.crt"},
		{"/trust/ca.pem", "application/x-pem-file", "fileparcel-ca.pem"},
		{"/trust/ca.mobileconfig", "application/x-apple-aspen-config", "fileparcel-ca.mobileconfig"},
	} {
		t.Run(tc.path, func(t *testing.T) {
			rec := hs.do(t, "GET", tc.path, nil)
			h := rec.Header()
			if rec.Code != 200 || h.Get("Content-Type") != tc.ctype || h.Get("X-Content-Type-Options") != "nosniff" ||
				!strings.HasPrefix(h.Get("Content-Disposition"), "attachment") || !strings.Contains(h.Get("Content-Disposition"), tc.file) {
				t.Fatalf("%d %v", rec.Code, h)
			}
			if rec.Body.Len() == 0 || h.Get("Content-Length") == "" {
				t.Fatal("empty body")
			}
			head := hs.do(t, "HEAD", tc.path, nil)
			if head.Code != 200 || head.Body.Len() != 0 || head.Header().Get("Content-Length") != h.Get("Content-Length") {
				t.Fatalf("HEAD: %d %d", head.Code, head.Body.Len())
			}
		})
	}
	// Works while locked (no authentication, no keys needed).
	hs.keys.state = core.KeyStateLocked
	if rec := hs.do(t, "GET", "/trust/ca.pem", nil); rec.Code != 200 {
		t.Fatalf("locked: %d", rec.Code)
	}
	hs.certs.err["CAExport"] = core.NotFoundf("the local CA does not exist yet")
	if rec := hs.do(t, "GET", "/trust/ca.pem", nil); rec.Code != 404 {
		t.Fatalf("no CA: %d", rec.Code)
	}
	if !mw.SealedAllowed("/trust/ca.crt") {
		t.Fatal("trust downloads must be reachable while sealed")
	}
}

// A name added to tls.extra_sans or network.extra_hosts that the local CA may
// not sign is dropped from the leaf — correctly, but it used to happen without
// a trace: no reissue, no error, nothing in the status, while the access URLs
// and the strict Host check kept advertising it.
func TestCertStatusReportsUncoveredNames(t *testing.T) {
	hs := newHarness(t)
	hs.certs.uncovered = []string{"files.example.org"}

	rec := hs.do(t, "GET", "/api/v1/admin/certs", nil, as("admin"))
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d", rec.Code)
	}
	var body struct {
		CA             *core.CertInfo `json:"ca"`
		UncoveredNames []string       `json:"uncovered_names"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body.CA == nil {
		t.Fatalf("the certificate status is gone: %s", rec.Body.String())
	}
	if !slices.Equal(body.UncoveredNames, []string{"files.example.org"}) {
		t.Fatalf("uncovered_names = %v, body %s", body.UncoveredNames, rec.Body.String())
	}

	hs.certs.uncovered = nil
	rec = hs.do(t, "GET", "/api/v1/admin/certs", nil, as("admin"))
	if strings.Contains(rec.Body.String(), "uncovered_names") {
		t.Fatalf("empty list must be omitted: %s", rec.Body.String())
	}
}
