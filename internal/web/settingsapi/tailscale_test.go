package settingsapi

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"fileparcel/internal/core"
	_ "fileparcel/internal/tsingress" // the funnel.* settings (managed keys)
	"fileparcel/internal/web/httpx"
)

// fakeIngress records the calls of the Funnel/Serve routes and answers a
// canned status or error.
type fakeIngress struct {
	core.Ingress
	mu      sync.Mutex
	calls   []string
	by      []*core.Principal
	funnel  []core.FunnelInput
	serve   []core.ServeInput
	refresh []bool
	st      *core.IngressStatus
	err     error
}

func (f *fakeIngress) record(call string, by *core.Principal) (*core.IngressStatus, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, call)
	f.by = append(f.by, by)
	if f.err != nil {
		return nil, f.err
	}
	return f.st, nil
}

func (f *fakeIngress) Status(_ context.Context, refresh bool) (*core.IngressStatus, error) {
	f.mu.Lock()
	f.refresh = append(f.refresh, refresh)
	f.mu.Unlock()
	return f.record("status", nil)
}

func (f *fakeIngress) SetFunnel(_ context.Context, by *core.Principal, in core.FunnelInput) (*core.IngressStatus, error) {
	f.mu.Lock()
	f.funnel = append(f.funnel, in)
	f.mu.Unlock()
	return f.record("funnel", by)
}

func (f *fakeIngress) SetServe(_ context.Context, by *core.Principal, in core.ServeInput) (*core.IngressStatus, error) {
	f.mu.Lock()
	f.serve = append(f.serve, in)
	f.mu.Unlock()
	return f.record("serve", by)
}

func (f *fakeIngress) Reapply(_ context.Context, by *core.Principal) (*core.IngressStatus, error) {
	return f.record("reapply", by)
}

func (f *fakeIngress) callList() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.calls)
}

// testStatus is an active Funnel in shares mode with one foreign entry
// that bypasses FileParcel's access policy.
func testStatus() *core.IngressStatus {
	return &core.IngressStatus{Available: true, Transport: "localapi",
		Funnel: core.IngressEntry{Kind: core.IngressFunnel, Mode: core.FunnelShares, Port: 443, HostPort: "node.tail.ts.net:443",
			URL: "https://node.tail.ts.net/", State: core.IngressStateActive, Checks: []core.IngressCheck{}},
		Serve: core.IngressEntry{Kind: core.IngressServe, Mode: core.FunnelOff, Port: 10000, State: core.IngressStateOff,
			Checks: []core.IngressCheck{}},
		FunnelPorts: []int{443, 10000}, Require2FA: true,
		Foreign: []core.ForeignServe{
			{HostPort: "node.tail.ts.net:8443", Mount: "/", Target: "https+insecure://localhost:8443", Funnel: true, Bypass: true},
			{HostPort: "node.tail.ts.net:10000", Mount: "/", Target: "http://127.0.0.1:3000"},
		}}
}

func TestTailscaleRoutes(t *testing.T) {
	te := newTestEnv(t)
	fi := &fakeIngress{st: testStatus()}
	te.d.Ingress = fi
	member := te.principal(core.RoleMember, true)

	// Read: network.manage, no step-up; refresh is passed through.
	var st core.IngressStatus
	if r := te.do(t, te.admin(false), http.MethodGet, "/api/v1/admin/network/tailscale", nil, &st); r.status != http.StatusOK ||
		st.Funnel.State != core.IngressStateActive || r.header.Get("Cache-Control") != "no-store" {
		t.Fatalf("status: %d %s %v", r.status, r.body, r.header)
	}
	if r := te.do(t, te.admin(false), http.MethodGet, "/api/v1/admin/network/tailscale?refresh=1", nil, nil); r.status != http.StatusOK {
		t.Fatalf("refresh: %d", r.status)
	}
	if !slices.Equal(fi.refresh, []bool{false, true}) {
		t.Fatalf("refresh flags %v", fi.refresh)
	}
	if r := te.do(t, member, http.MethodGet, "/api/v1/admin/network/tailscale", nil, nil); r.status != http.StatusForbidden ||
		r.code != "forbidden" || r.msg != "this needs the “"+core.CapNetworkManage.Label()+"” permission" {
		t.Fatalf("member: %d %s %q", r.status, r.code, r.msg)
	}

	// Writes: network.manage and step-up; the service gets the principal.
	writes := []struct{ method, path, call string }{
		{http.MethodPut, "/api/v1/admin/network/funnel", "funnel"},
		{http.MethodPut, "/api/v1/admin/network/serve", "serve"},
		{http.MethodPost, "/api/v1/admin/network/tailscale/reapply", "reapply"},
	}
	for _, w := range writes {
		b := any(nil)
		switch w.call {
		case "funnel":
			b = map[string]any{"mode": "shares", "port": 443, "confirm": "public"}
		case "serve":
			b = map[string]any{"enabled": true, "port": 10000}
		}
		if r := te.do(t, member, w.method, w.path, b, nil); r.status != http.StatusForbidden || r.code != "forbidden" {
			t.Errorf("%s as member: %d %s", w.path, r.status, r.code)
		}
		if r := te.do(t, te.admin(false), w.method, w.path, b, nil); r.status != http.StatusForbidden || r.code != "elevation_required" {
			t.Errorf("%s without step-up: %d %s", w.path, r.status, r.code)
		}
		if r := te.do(t, te.admin(true), w.method, w.path, b, &st); r.status != http.StatusOK || st.Funnel.URL != "https://node.tail.ts.net/" {
			t.Errorf("%s: %d %s", w.path, r.status, r.body)
		}
	}
	if got := fi.callList(); !slices.Equal(got[len(got)-3:], []string{"funnel", "serve", "reapply"}) {
		t.Fatalf("calls %v", got)
	}
	if len(fi.funnel) != 1 || fi.funnel[0].Mode != core.FunnelShares || fi.funnel[0].Confirm != "public" ||
		len(fi.serve) != 1 || !fi.serve[0].Enabled || fi.serve[0].Port != 10000 {
		t.Fatalf("inputs %+v %+v", fi.funnel, fi.serve)
	}
	for _, by := range fi.by[len(fi.by)-3:] {
		if by == nil || by.Username != "admin" {
			t.Fatalf("principal %+v", by)
		}
	}

	// Strict decoding and the body limit.
	if r := te.do(t, te.admin(true), http.MethodPut, "/api/v1/admin/network/funnel", `{"mode":"app","extra":1}`, nil); r.status != http.StatusUnprocessableEntity {
		t.Fatalf("unknown field: %d %s", r.status, r.body)
	}
	big := `{"mode":"shares","confirm":"` + strings.Repeat("a", maxSettingsBody) + `"}`
	if r := te.do(t, te.admin(true), http.MethodPut, "/api/v1/admin/network/funnel", big, nil); r.status != http.StatusRequestEntityTooLarge &&
		r.status != http.StatusUnprocessableEntity {
		t.Fatalf("oversized: %d", r.status)
	}

	// The service's errors reach the client unchanged.
	for _, err := range []error{
		&core.Error{Code: core.ErrPrecondition.Code, Status: core.ErrPrecondition.Status, Field: "tailscale.funnel_attr", Message: "no funnel"},
		&core.Error{Code: core.ErrConflict.Code, Status: core.ErrConflict.Status, Field: "port", Message: "taken"},
		core.Invalid("confirm", `type-confirmation required: send confirm="public"`),
		core.Errorf(core.ErrForbidden, "only an owner or administrator can weaken sign-in over the public Funnel address"),
		core.Wrap(core.ErrUnavailable, "tailscaled does not answer", nil),
	} {
		fi.err = err
		want := core.AsError(err)
		if r := te.do(t, te.admin(true), http.MethodPut, "/api/v1/admin/network/funnel", map[string]any{"mode": "app"}, nil); r.status != want.Status ||
			r.code != want.Code || r.field != want.Field || r.msg != want.Message {
			t.Errorf("%v: %d %s %q %q", err, r.status, r.code, r.field, r.msg)
		}
	}
	fi.err = nil

	// Without the service: 503.
	te.d.Ingress = nil
	if r := te.do(t, te.admin(true), http.MethodGet, "/api/v1/admin/network/tailscale", nil, nil); r.status != http.StatusServiceUnavailable {
		t.Fatalf("no service: %d", r.status)
	}
}

// The funnel.* keys the Funnel/Serve routes store are refused by PATCH and
// DELETE /admin/settings with 409 naming the key (for every caller); the
// connection settings of the section are ordinary (sensitive) settings.
func TestManagedFunnelSettings(t *testing.T) {
	te := newTestEnv(t)
	cat := te.catalog(t)
	for _, k := range []string{"funnel.mode", "funnel.port", "funnel.allow_admin", "funnel.require_2fa", "funnel.serve",
		"funnel.serve_port", "funnel.node"} {
		v, ok := cat[k]
		if !ok || v.Managed == "" {
			t.Fatalf("%s: %+v", k, v)
		}
		r := te.do(t, te.admin(true), http.MethodPatch, "/api/v1/admin/settings", map[string]any{k: v.Default}, nil)
		if r.status != http.StatusConflict || r.code != "conflict" || r.field != k || !strings.Contains(r.msg, "fileparcel network ") {
			t.Errorf("PATCH %s: %d %s %q %q", k, r.status, r.code, r.field, r.msg)
		}
		r = te.do(t, te.admin(true), http.MethodDelete, "/api/v1/admin/settings/"+k, nil, nil)
		if r.status != http.StatusConflict || r.field != k {
			t.Errorf("DELETE %s: %d %s", k, r.status, r.field)
		}
	}
	// Serve's keys name the tailscale-serve command, Funnel's the funnel one.
	if r := te.do(t, te.admin(true), http.MethodPatch, "/api/v1/admin/settings", map[string]any{"funnel.serve": true}, nil); !strings.Contains(r.msg, `"fileparcel network tailscale-serve"`) {
		t.Errorf("serve message %q", r.msg)
	}
	if r := te.do(t, te.admin(true), http.MethodPatch, "/api/v1/admin/settings", map[string]any{"funnel.mode": "app"}, nil); !strings.Contains(r.msg, `"fileparcel network funnel"`) {
		t.Errorf("funnel message %q", r.msg)
	}
	// A batch with a managed key changes nothing.
	r := te.do(t, te.admin(true), http.MethodPatch, "/api/v1/admin/settings", map[string]any{"funnel.backend": "tcp", "funnel.mode": "app"}, nil)
	if r.status != http.StatusConflict || te.st.String("funnel.backend") != "auto" || te.st.String("funnel.mode") != "off" {
		t.Fatalf("mixed batch: %d, backend %s", r.status, te.st.String("funnel.backend"))
	}
	// The connection settings: sensitive (section funnel), not managed.
	if r := te.do(t, te.admin(false), http.MethodPatch, "/api/v1/admin/settings", map[string]any{"funnel.backend": "tcp"}, nil); r.status != http.StatusForbidden ||
		r.code != "elevation_required" {
		t.Fatalf("backend without step-up: %d %s", r.status, r.code)
	}
	if r := te.do(t, te.admin(true), http.MethodPatch, "/api/v1/admin/settings", map[string]any{"funnel.backend": "tcp", "funnel.backend_port": 20000}, nil); r.status != http.StatusOK ||
		te.st.String("funnel.backend") != "tcp" || te.st.Int("funnel.backend_port") != 20000 {
		t.Fatalf("backend: %d %s", r.status, r.body)
	}
	// The service itself still stores the managed keys.
	if _, err := te.st.Set(context.Background(), core.SystemPrincipal(core.ViaOffline),
		map[string]json.RawMessage{"funnel.mode": json.RawMessage(`"shares"`)}); err != nil || te.st.String("funnel.mode") != "shares" {
		t.Fatalf("service store: %v", err)
	}
}

// PATCH server.https_port/http_port onto the port of a wanted Funnel or
// Serve entry is applied with a warning (the entry is removed).
func TestIngressPortWarnings(t *testing.T) {
	te := newTestEnv(t)
	a := &api{d: te.d}
	raw := func(v any) json.RawMessage { b, _ := json.Marshal(v); return b }
	if w := a.ingressWarnings(map[string]json.RawMessage{"server.https_port": raw(443)}); len(w) != 0 {
		t.Fatalf("Funnel off: %v", w)
	}
	if _, err := te.st.Set(context.Background(), core.SystemPrincipal(core.ViaOffline), map[string]json.RawMessage{
		"funnel.mode": raw("shares"), "funnel.port": raw(443), "funnel.serve": raw(true), "funnel.serve_port": raw(10000),
	}); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		changes map[string]json.RawMessage
		want    []string
	}{
		{map[string]json.RawMessage{"server.https_port": raw(443)}, []string{"Tailscale Funnel uses port 443"}},
		{map[string]json.RawMessage{"server.http_port": raw(10000)}, []string{"Tailscale Serve uses port 10000"}},
		{map[string]json.RawMessage{"server.https_port": raw(443), "server.http_port": raw(10000)},
			[]string{"Tailscale Funnel uses port 443", "Tailscale Serve uses port 10000"}},
		{map[string]json.RawMessage{"server.https_port": raw(8443)}, nil},
		{map[string]json.RawMessage{"server.https_port": raw("x")}, nil},
		{map[string]json.RawMessage{"sapitest.count": raw(443)}, nil},
	} {
		got := a.ingressWarnings(c.changes)
		if len(got) != len(c.want) {
			t.Errorf("%s: %v", c.changes, got)
			continue
		}
		for i, w := range c.want {
			if !strings.HasPrefix(got[i], w) || !strings.Contains(got[i], "removes its") {
				t.Errorf("%s: %q, want %q…", c.changes, got[i], w)
			}
		}
	}
}

// GET /admin/network carries the cached Funnel/Serve status and the
// exposures of hand-made proxies (foreign bypass entries and the proxy
// signals of the last 24 hours).
func TestNetworkOverviewIngress(t *testing.T) {
	te := newTestEnv(t)
	// A clock of its own (the proxy signals are process wide): signals noted
	// at this time are older than 24 hours for every other test.
	te.now = time.Date(2020, 1, 1, 12, 0, 0, 0, time.UTC)
	fi := &fakeIngress{st: testStatus()}
	te.d.Ingress = fi
	var ov core.NetworkOverview
	if r := te.do(t, te.admin(false), http.MethodGet, "/api/v1/admin/network", nil, &ov); r.status != http.StatusOK {
		t.Fatalf("%d %s", r.status, r.body)
	}
	if ov.Ingress == nil || ov.Ingress.Funnel.State != core.IngressStateActive || !slices.Equal(fi.refresh, []bool{false}) {
		t.Fatalf("ingress %+v (refresh %v)", ov.Ingress, fi.refresh)
	}
	if len(ov.Exposures) != 1 || ov.Exposures[0].ID != httpx.ExposureBypass || ov.Exposures[0].Severity != "fail" ||
		!strings.Contains(ov.Exposures[0].Message, "https+insecure://localhost:8443") ||
		!strings.Contains(ov.Exposures[0].Hint, "tailscale serve --yes --https=8443 off") {
		t.Fatalf("exposures %+v", ov.Exposures)
	}
	httpx.ProxySignals.LocalProxy.Note("files.example.org", te.now.Add(-time.Hour))
	httpx.ProxySignals.FunnelToMain.Note("box.tail.ts.net:10000", te.now.Add(-2*time.Hour))
	ov = core.NetworkOverview{}
	te.do(t, te.admin(false), http.MethodGet, "/api/v1/admin/network", nil, &ov)
	ids := []string{}
	for _, e := range ov.Exposures {
		ids = append(ids, e.ID+":"+e.Severity)
	}
	if !slices.Equal(ids, []string{"tailscale.bypass:fail", "tailscale.bypass:fail", "proxy.local_unconfigured:warn"}) ||
		!strings.Contains(ov.Exposures[1].Hint, "--https=10000 --set-path=") || !strings.Contains(ov.Exposures[2].Message, "files.example.org") {
		t.Fatalf("exposures %+v", ov.Exposures)
	}
	// A day later the signals are gone again.
	te.now = te.now.Add(25 * time.Hour)
	fi.st = &core.IngressStatus{Foreign: []core.ForeignServe{}}
	ov = core.NetworkOverview{}
	te.do(t, te.admin(false), http.MethodGet, "/api/v1/admin/network", nil, &ov)
	if ov.Exposures == nil || len(ov.Exposures) != 0 {
		t.Fatalf("stale exposures %+v", ov.Exposures)
	}
}

// PUT /admin/network/policy over Tailscale Funnel: only the deny list applies
// to the requester there, so an allow list without its (public) address is
// accepted and a deny list that covers it is refused unless force. Over
// Serve the usual guard applies to the tailnet address.
func TestPutPolicyOverIngress(t *testing.T) {
	te := newTestEnv(t)
	te.who.Store(te.admin(true))
	send := func(kind string, client netip.Addr, body core.PolicyInput) (int, httpx.ErrorResponse, core.PolicyResult) {
		t.Helper()
		te.setClient(client)
		raw, _ := json.Marshal(body)
		req := httptest.NewRequest(http.MethodPut, "/api/v1/admin/network/policy", bytes.NewReader(raw))
		req.RemoteAddr = netip.AddrPortFrom(client, 0).String()
		req = req.WithContext(core.WithIngress(req.Context(), &core.IngressInfo{Kind: kind, ClientIP: client, Public: kind == core.IngressFunnel,
			Host: "node.tail.ts.net"}))
		rec := httptest.NewRecorder()
		te.router.ServeHTTP(rec, req)
		var er httpx.ErrorResponse
		var res core.PolicyResult
		if rec.Code >= 400 {
			_ = json.Unmarshal(rec.Body.Bytes(), &er)
		} else if err := json.Unmarshal(rec.Body.Bytes(), &res); err != nil {
			t.Fatalf("%v: %s", err, rec.Body)
		}
		return rec.Code, er, res
	}
	internet := netip.MustParseAddr("203.0.113.9")
	code, er, res := send(core.IngressFunnel, internet, core.PolicyInput{Mode: "allowlist", Allow: []string{"192.168.1.0/24"}})
	if code != http.StatusOK || res.Policy.Mode != "allowlist" || !slices.Equal(te.st.Strings("network.allow_cidrs"), []string{"192.168.1.0/24"}) {
		t.Fatalf("allow list over funnel: %d %+v", code, er)
	}
	for _, deny := range [][]string{{"203.0.113.9"}, {"203.0.113.0/24"}, {"::ffff:203.0.113.0/120"}} {
		code, er, _ = send(core.IngressFunnel, internet, core.PolicyInput{Mode: "allowlist", Allow: []string{"192.168.1.0/24"}, Deny: deny})
		if code != http.StatusConflict || er.Error.Code != "conflict" || er.Error.Field != "deny" || !strings.Contains(er.Error.Message, "203.0.113.9") {
			t.Errorf("deny %v over funnel: %d %+v", deny, code, er)
		}
	}
	if got := te.st.Strings("network.deny_cidrs"); len(got) != 0 {
		t.Fatalf("refused deny list stored: %v", got)
	}
	code, _, _ = send(core.IngressFunnel, internet, core.PolicyInput{Mode: "allowlist", Allow: []string{"192.168.1.0/24"},
		Deny: []string{"203.0.113.0/24"}, Force: true})
	if code != http.StatusOK || !slices.Equal(te.st.Strings("network.deny_cidrs"), []string{"203.0.113.0/24"}) {
		t.Fatalf("forced over funnel: %d", code)
	}
	// Invalid input is still the policy validation's 422.
	if code, er, _ = send(core.IngressFunnel, internet, core.PolicyInput{Mode: "allowlist", Deny: []string{"nope"}}); code != http.StatusUnprocessableEntity ||
		er.Error.Field != "deny" {
		t.Fatalf("invalid over funnel: %d %+v", code, er)
	}

	// Serve: the tailnet address must stay allowed.
	tailnet := netip.MustParseAddr("100.101.1.2")
	if code, er, _ = send(core.IngressServe, tailnet, core.PolicyInput{Mode: "allowlist", Allow: []string{"192.168.1.0/24"}}); code != http.StatusConflict ||
		!strings.Contains(er.Error.Message, "100.101.1.2") {
		t.Fatalf("serve lockout: %d %+v", code, er)
	}
	if code, _, _ = send(core.IngressServe, tailnet, core.PolicyInput{Mode: "allowlist", Allow: []string{"100.64.0.0/10"}}); code != http.StatusOK {
		t.Fatalf("serve admitting: %d", code)
	}
}
