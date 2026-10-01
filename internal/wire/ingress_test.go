package wire

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"

	"fileparcel/internal/app"
	"fileparcel/internal/core"
	"fileparcel/internal/tsingress"
	"fileparcel/internal/web"
	"fileparcel/internal/web/mw"
)

// policyIngress is the wired Ingress service with a fixed policy (the
// router only reads the policy; tsingress has its own tests).
type policyIngress struct {
	core.Ingress
	pol map[string]core.IngressPolicy
}

func (p *policyIngress) Policy(kind string) core.IngressPolicy { return p.pol[kind] }

// The Ingress service is wired into the services and the dependencies.
func TestIngressWired(t *testing.T) {
	d := buildForAudit(t)
	if _, ok := d.Ingress.(*tsingress.Service); !ok {
		t.Fatalf("Deps.Ingress is %T", d.Ingress)
	}
	// Not attached: nothing is published, links stay relative.
	if d.Ingress.InternetLinks() || d.Ingress.PublicBaseURL() != "" || d.Ingress.Policy(core.IngressFunnel).Mode != core.FunnelOff {
		t.Fatal("an unattached ingress service publishes something")
	}
	st, err := d.Ingress.Status(context.Background(), false)
	if err != nil || st.Funnel.State != core.IngressStateOff || st.Serve.State != core.IngressStateOff {
		t.Fatalf("status %+v %v", st, err)
	}
}

// Through the real router: over Funnel "shares" mode an app path gets
// exactly the answer of an unknown share token (HTML) or an unknown API
// endpoint (JSON) — nothing tells an internet visitor what exists.
func TestIngressRouterUniformNotFound(t *testing.T) {
	d, cleanup, err := Build(context.Background(), newTestHome(t), app.ModeOffline)
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()
	pi := &policyIngress{Ingress: d.Ingress, pol: map[string]core.IngressPolicy{
		core.IngressFunnel: {Mode: core.FunnelShares, DNSName: "node.tail.ts.net", Port: 443, Require2FA: true},
		core.IngressServe:  {Mode: core.FunnelApp, DNSName: "node.tail.ts.net", Port: 8443},
	}}
	d.Ingress = pi
	h := web.NewRouter(d)
	client := netip.MustParseAddr("203.0.113.9")
	do := func(kind, method, target string) *httptest.ResponseRecorder {
		t.Helper()
		r := httptest.NewRequest(method, target, nil)
		r.Host = "node.tail.ts.net"
		r.Header.Set("Cookie", "__Host-fp_session=0123456789abcdef0123456789abcdef0123456789a")
		if kind != "" {
			r.RemoteAddr = netip.AddrPortFrom(client, 0).String()
			r = r.WithContext(core.WithIngress(r.Context(), &core.IngressInfo{Kind: kind, ClientIP: client, Public: true,
				Host: "node.tail.ts.net"}))
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, r)
		return rec
	}
	// The request id differs per request; everything else must match.
	norm := func(rec *httptest.ResponseRecorder) string {
		return strings.ReplaceAll(rec.Body.String(), rec.Header().Get(mw.HeaderRequestID), "RID")
	}
	unknownToken := do(core.IngressFunnel, "GET", "/s/"+strings.Repeat("A", 22))
	if unknownToken.Code != http.StatusNotFound || !strings.Contains(unknownToken.Body.String(), `id="fp-boot"`) {
		t.Fatalf("unknown token: %d %s", unknownToken.Code, unknownToken.Body.String())
	}
	for _, p := range []string{"/", "/login", "/files", "/admin", "/trust", "/setup", "/unlock", "/healthz", "/sw.js",
		"/invite/abc", "/s/x/../../api/v1/me"} {
		rec := do(core.IngressFunnel, "GET", p)
		if rec.Code != http.StatusNotFound || norm(rec) != norm(unknownToken) {
			t.Errorf("GET %s over funnel: %d\n%s", p, rec.Code, rec.Body.String())
		}
		if rec.Header().Get("X-Robots-Tag") == "" || rec.Header().Get("Content-Security-Policy") != mw.CSPApp {
			t.Errorf("GET %s over funnel: headers %v", p, rec.Header())
		}
	}
	unknownAPI := do("", "GET", "/api/v1/does-not-exist")
	var ref struct {
		Error struct{ Code, Message string } `json:"error"`
	}
	if err := json.Unmarshal(unknownAPI.Body.Bytes(), &ref); err != nil || unknownAPI.Code != 404 {
		t.Fatalf("unknown endpoint: %d %s", unknownAPI.Code, unknownAPI.Body.String())
	}
	for _, p := range []string{"/api/v1/me", "/api/v1/auth/state", "/api/v1/admin/users", "/api/v1/does-not-exist"} {
		rec := do(core.IngressFunnel, "GET", p)
		if rec.Code != http.StatusNotFound || norm(rec) != norm(unknownAPI) {
			t.Errorf("GET %s over funnel: %d %s", p, rec.Code, rec.Body.String())
		}
	}
	// The public share routes are reachable (and answer as usual).
	if rec := do(core.IngressFunnel, "GET", "/s/"+strings.Repeat("A", 22)+"/api"); rec.Code != 404 ||
		!strings.Contains(rec.Body.String(), "share not found") {
		t.Fatalf("share API: %d %s", rec.Code, rec.Body.String())
	}
	if rec := do(core.IngressFunnel, "GET", "/theme.css"); rec.Code != 200 {
		t.Fatalf("theme.css: %d", rec.Code)
	}

	// "app" mode: the blocked paths get 403, the page or JSON.
	pi.pol[core.IngressFunnel] = core.IngressPolicy{Mode: core.FunnelApp, DNSName: "node.tail.ts.net", Port: 443, Require2FA: true}
	rec := do(core.IngressFunnel, "GET", "/admin/users")
	if rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), `id="fp-boot"`) ||
		!strings.Contains(rec.Body.String(), "public internet address") {
		t.Fatalf("admin page over funnel app: %d %s", rec.Code, rec.Body.String())
	}
	rec = do(core.IngressFunnel, "GET", "/api/v1/admin/users")
	if rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), "not available over the public Funnel address") {
		t.Fatalf("admin API over funnel app: %d %s", rec.Code, rec.Body.String())
	}
	if rec := do(core.IngressFunnel, "GET", "/api/v1/auth/state"); rec.Code != 200 {
		t.Fatalf("auth state over funnel app: %d", rec.Code)
	}
	// Serve applies the access policy: the default allow list is loopback
	// only, so a tailnet client is refused.
	if rec := do(core.IngressServe, "GET", "/login"); rec.Code != http.StatusForbidden || rec.Header().Get("Connection") != "close" {
		t.Fatalf("serve outside the allow list: %d", rec.Code)
	}
}
