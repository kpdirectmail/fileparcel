package pages

import (
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"

	"fileparcel/internal/core"
	"fileparcel/internal/web/mw"
)

// ingressStub is the part of core.Ingress the pages use.
type ingressStub struct {
	core.Ingress
	links bool
	mode  string
}

func (i *ingressStub) InternetLinks() bool { return i.links }
func (i *ingressStub) Policy(kind string) core.IngressPolicy {
	if kind != core.IngressFunnel {
		return core.IngressPolicy{Mode: core.FunnelApp}
	}
	return core.IngressPolicy{Mode: i.mode, DNSName: "node.tail.ts.net", Port: 443}
}

func TestIngressFeatures(t *testing.T) {
	e := newEnv(t)
	f := Features(e.d, nil)
	if f["internet_links"] || f["funnel_2fa"] {
		t.Fatalf("without Funnel: %v", f)
	}
	ing := &ingressStub{links: true, mode: core.FunnelShares}
	e.d.Ingress = ing
	if f := Features(e.d, nil); !f["internet_links"] || f["funnel_2fa"] {
		t.Fatalf("shares mode: %v", f)
	}
	// funnel_2fa follows the settings: mode app and require_2fa (default on).
	e.s.set("funnel.mode", core.FunnelApp)
	if f := Features(e.d, nil); !f["funnel_2fa"] {
		t.Fatalf("app mode: %v", f)
	}
	e.s.set("funnel.require_2fa", false)
	if f := Features(e.d, nil); f["funnel_2fa"] {
		t.Fatalf("require_2fa off: %v", f)
	}
	e.s.set("funnel.require_2fa", true)
	ing.links = false
	if f := Features(e.d, nil); f["internet_links"] || !f["funnel_2fa"] {
		t.Fatalf("funnel not active: %v", f)
	}
	// The boot carries them (the login page reads funnel_2fa and ingress).
	e.s.set("tls.hsts", "off") // the fake certificates service knows no names
	req := httptest.NewRequest("GET", "/login", nil)
	req = req.WithContext(core.WithIngress(req.Context(), &core.IngressInfo{Kind: core.IngressFunnel,
		ClientIP: netip.MustParseAddr("203.0.113.9"), Host: "node.tail.ts.net"}))
	rec := httptest.NewRecorder()
	e.h.ServeHTTP(rec, req)
	b := bootOf(t, rec.Body.String())
	feats, _ := b["features"].(map[string]any)
	if b["ingress"] != core.IngressFunnel || feats["funnel_2fa"] != true || feats["internet_links"] != false {
		t.Fatalf("boot %v %v", b["ingress"], feats)
	}
}

// The share page leads into the app only where the app is reachable.
func TestShareBrandOverFunnel(t *testing.T) {
	e := newEnv(t)
	ing := &ingressStub{mode: core.FunnelShares}
	e.d.Ingress = ing
	h := mw.Inject(e.d)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		RenderTitled(w, r, "share", "Holiday", map[string]any{"token": "x"})
	}))
	render := func(kind string) string {
		t.Helper()
		req := httptest.NewRequest("GET", "/s/x", nil)
		if kind != "" {
			req = req.WithContext(core.WithIngress(req.Context(), &core.IngressInfo{Kind: kind,
				ClientIP: netip.MustParseAddr("203.0.113.9"), Host: "node.tail.ts.net"}))
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != 200 {
			t.Fatalf("%s: %d", kind, rec.Code)
		}
		return rec.Body.String()
	}
	const link, span = `<a class="brand" href="/">`, `<span class="brand">`
	for _, tc := range []struct {
		kind, mode string
		public     bool
	}{
		{"", core.FunnelShares, false},
		{core.IngressServe, core.FunnelShares, false},
		{core.IngressFunnel, core.FunnelShares, true},
		{core.IngressFunnel, core.FunnelOff, true}, // fail closed
		{core.IngressFunnel, core.FunnelApp, false},
	} {
		ing.mode = tc.mode
		body := render(tc.kind)
		if strings.Contains(body, span) != tc.public || strings.Contains(body, link) == tc.public {
			t.Errorf("%q/%s: public=%v, body has span=%v link=%v", tc.kind, tc.mode, tc.public,
				strings.Contains(body, span), strings.Contains(body, link))
		}
		if !strings.Contains(body, `<span class="brand-name">`) {
			t.Errorf("%q/%s: brand name missing", tc.kind, tc.mode)
		}
	}
	// Without an Ingress service a Funnel-marked request still counts as
	// public.
	e.d.Ingress = nil
	if body := render(core.IngressFunnel); !strings.Contains(body, span) {
		t.Fatal("no ingress service: brand links into the app")
	}
}
