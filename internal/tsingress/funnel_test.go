package tsingress

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"slices"
	"strings"
	"testing"

	"fileparcel/internal/core"
	"fileparcel/internal/events"
	"fileparcel/internal/tslocal"
	"fileparcel/internal/tslocal/tslocaltest"
)

const hp443 = "node.tail.ts.net:443"

// Turning Funnel on writes exactly FileParcel's entry, merged into what
// tailscaled already serves (foreign TCP, Foreground and Services kept
// byte for byte), with If-Match, after the listener is open.
func TestEnableFunnelWritesExactEntry(t *testing.T) {
	h := newHarness(t)
	h.attach()
	st := h.enable(core.FunnelShares)
	want := funnelConfig(hp443, "443", "unix:"+h.sock(core.IngressFunnel))
	if got := h.f.Config(); got != want {
		t.Fatalf("posted\n%s\nwant\n%s", got, want)
	}
	posts := h.f.Posts()
	if len(posts) != 1 || posts[0].IfMatch == "" {
		t.Fatalf("posts %+v", posts)
	}
	if ev := h.log.all(); len(ev) != 2 || !strings.HasPrefix(ev[0], "open funnel unix ") || ev[1] != "post" {
		t.Fatalf("order %v", ev)
	}
	if st.Funnel.State != core.IngressStateActive || st.Funnel.URL != "https://node.tail.ts.net/" ||
		st.Funnel.Backend != "unix:"+h.sock(core.IngressFunnel) || st.Funnel.Mode != core.FunnelShares {
		t.Fatalf("status %+v", st.Funnel)
	}
	if !st.Available || st.Transport != "localapi" || !slices.Equal(st.FunnelPorts, []int{443, 10000}) {
		t.Fatalf("status %+v", st) // 8443 is FileParcel's own port
	}
	s := h.env.Settings
	if s.String(KeyMode) != core.FunnelShares || s.String(KeyNode) != "nTESTNODE1CNTRL" || s.Int(KeyPort) != 443 {
		t.Fatalf("settings mode=%s node=%s", s.String(KeyMode), s.String(KeyNode))
	}
	m := h.marker()
	if m == nil || m.State != markerApplied || m.NodeID != "nTESTNODE1CNTRL" || m.Backend != BackendUnix ||
		len(m.Entries) != 1 || m.Entries[0].Proxy != "unix:"+h.sock(core.IngressFunnel) || !m.Entries[0].Funnel {
		t.Fatalf("marker %+v", m)
	}
	p := h.s.Policy(core.IngressFunnel)
	if p.Mode != core.FunnelShares || p.DNSName != "node.tail.ts.net" || p.Port != 443 || !p.Require2FA || p.AllowAdmin {
		t.Fatalf("policy %+v", p)
	}
	if h.s.PublicBaseURL() != "https://node.tail.ts.net" || !h.s.InternetLinks() || len(h.s.AccessURLs()) != 0 {
		t.Fatalf("base %q urls %+v", h.s.PublicBaseURL(), h.s.AccessURLs())
	}
	if e := h.audit.last(t, core.ActNetworkFunnel); e.Outcome != core.OutcomeSuccess || e.ActorName != "admin" {
		t.Fatalf("audit %+v", e)
	}
	if v, _ := h.lis.get(core.IngressFunnel); v[0] != "unix" || v[1] != h.sock(core.IngressFunnel) {
		t.Fatalf("listener %v", v)
	}
	if !slices.Contains(h.lis.uids, 0) {
		t.Fatalf("peer uids %v", h.lis.uids)
	}
}

func TestEnableFunnelKeepsForeignParts(t *testing.T) {
	h := newHarness(t)
	const foreign = `{"Foreground":{"s1":{"TCP":{"4443":{"HTTPS":true}},"Web":{"node.tail.ts.net:4443":{"Handlers":{"/":{"Proxy":"http://127.0.0.1:3000"}}}}}},` +
		`"Services":{"svc:web":{"TCP":{"443":{"HTTPS":true}}}},"TCP":{"10000":{"TCPForward":"127.0.0.1:22"}},"Zed":{"a": [1,  2]}}`
	h.f.SetConfig(foreign)
	h.attach()
	h.enable(core.FunnelShares)
	var in, got map[string]json.RawMessage
	_ = json.Unmarshal([]byte(foreign), &in)
	if err := json.Unmarshal([]byte(h.f.Config()), &got); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"Foreground", "Services", "Zed"} {
		if string(in[k]) != string(got[k]) {
			t.Errorf("%s changed:\n%s\n%s", k, in[k], got[k])
		}
	}
	if !strings.Contains(string(got["TCP"]), `"10000":{"TCPForward":"127.0.0.1:22"}`) ||
		!strings.Contains(string(got["TCP"]), `"443":{"HTTPS":true}`) {
		t.Fatalf("TCP %s", got["TCP"])
	}
	// Disabling restores the document exactly.
	if _, err := h.s.SetFunnel(context.Background(), admin(), core.FunnelInput{Mode: core.FunnelOff}); err != nil {
		t.Fatal(err)
	}
	var back tslocal.ServeConfig
	_ = back.UnmarshalJSON([]byte(h.f.Config()))
	var orig tslocal.ServeConfig
	_ = orig.UnmarshalJSON([]byte(foreign))
	if !back.Equal(&orig) {
		t.Fatalf("after disable\n%s\nwant\n%s", h.f.Config(), foreign)
	}
	// The foreign entries are listed (the service has no mount), none
	// bypasses FileParcel.
	st := h.status()
	if len(st.Foreign) != 2 {
		t.Fatalf("foreign %+v", st.Foreign)
	}
	for _, f := range st.Foreign {
		if f.Bypass {
			t.Fatalf("bypass %+v", f)
		}
	}
}

// shares → app is FileParcel's policy only; a port change moves the entry;
// disabling closes the listener before tailscaled is changed.
func TestModePortAndDisable(t *testing.T) {
	h := newHarness(t)
	h.attach()
	h.enable(core.FunnelShares)
	ctx := context.Background()
	n := len(h.f.Posts())
	// Widening needs the typed confirmation.
	_, err := h.s.SetFunnel(ctx, admin(), core.FunnelInput{Mode: core.FunnelApp})
	mustCode(t, err, core.ErrInvalid, "confirm")
	st, err := h.s.SetFunnel(ctx, admin(), core.FunnelInput{Mode: core.FunnelApp, Confirm: ConfirmPublic})
	if err != nil {
		t.Fatal(err)
	}
	if len(h.f.Posts()) != n || st.Funnel.State != core.IngressStateActive || st.Funnel.Mode != core.FunnelApp {
		t.Fatalf("shares → app touched tailscaled: %d posts, %+v", len(h.f.Posts())-n, st.Funnel)
	}
	if h.s.Policy(core.IngressFunnel).Mode != core.FunnelApp {
		t.Fatal("policy not updated")
	}
	urls := h.s.AccessURLs()
	if len(urls) != 1 || urls[0].Kind != core.URLKindFunnel || urls[0].URL != "https://node.tail.ts.net/" {
		t.Fatalf("access urls %+v", urls)
	}
	// Port change: moved, same listener.
	h.log.reset()
	if st, err = h.s.SetFunnel(ctx, admin(), core.FunnelInput{Mode: core.FunnelApp, Port: 10000}); err != nil {
		t.Fatal(err)
	}
	want := funnelConfig("node.tail.ts.net:10000", "10000", "unix:"+h.sock(core.IngressFunnel))
	if got := h.f.Config(); got != want || st.Funnel.URL != "https://node.tail.ts.net:10000/" {
		t.Fatalf("moved\n%s\nwant\n%s", got, want)
	}
	if ev := h.log.all(); !slices.Equal(ev, []string{"post"}) {
		t.Fatalf("events %v", ev)
	}
	if h.s.PublicBaseURL() != "https://node.tail.ts.net:10000" || h.marker().Entries[0].Port != 10000 {
		t.Fatalf("base %q marker %+v", h.s.PublicBaseURL(), h.marker())
	}
	// Disable: listener closed first, then the entry removed.
	h.log.reset()
	if st, err = h.s.SetFunnel(ctx, admin(), core.FunnelInput{Mode: core.FunnelOff}); err != nil {
		t.Fatal(err)
	}
	if ev := h.log.all(); !slices.Equal(ev, []string{"close funnel", "post"}) {
		t.Fatalf("disable order %v", ev)
	}
	if h.f.Config() != "null" || h.marker() != nil || st.Funnel.State != core.IngressStateOff ||
		h.s.Policy(core.IngressFunnel).Mode != core.FunnelOff || h.s.InternetLinks() || len(h.s.AccessURLs()) != 0 {
		t.Fatalf("after disable: config %s, status %+v", h.f.Config(), st.Funnel)
	}
	if h.env.Settings.String(KeyMode) != core.FunnelOff {
		t.Fatal("mode not stored")
	}
	if e := h.audit.last(t, core.ActNetworkFunnel); e.Outcome != core.OutcomeSuccess || e.Details.(map[string]any)["mode"] != "off" {
		t.Fatalf("audit %+v", e)
	}
}

// A disable whose removal fails still answers, with state error and the
// command that removes the entry by hand.
func TestDisableRemovalFailure(t *testing.T) {
	h := newHarness(t)
	h.attach()
	h.enable(core.FunnelShares)
	h.f.FailNextPost(http.StatusUnauthorized, "must be root, or be an operator and able to run 'sudo tailscale' to serve a path or Unix socket")
	st, err := h.s.SetFunnel(context.Background(), admin(), core.FunnelInput{Mode: core.FunnelOff})
	if err != nil {
		t.Fatal(err)
	}
	if st.Funnel.State != core.IngressStateError ||
		!strings.Contains(st.Funnel.Message, "sudo tailscale serve --yes --https=443 --set-path=/ off") {
		t.Fatalf("status %+v", st.Funnel)
	}
	if _, ok := h.lis.get(core.IngressFunnel); ok || h.s.Policy(core.IngressFunnel).Mode != core.FunnelOff {
		t.Fatal("the listener must be closed even though the removal failed")
	}
	if e := h.audit.last(t, core.ActNetworkFunnel); e.Outcome != core.OutcomeFailure {
		t.Fatalf("audit %+v", e)
	}
	// The marker still names the entry, so a later reconcile removes it.
	if m := h.marker(); m == nil || m.entry(core.IngressFunnel) == nil {
		t.Fatalf("marker %+v", m)
	}
	h.s.autoReconcile(context.Background(), []string{"settings"})
	if h.f.Config() != "null" || h.marker() != nil {
		t.Fatalf("not removed later: %s", h.f.Config())
	}
}

func TestConflictMatrix(t *testing.T) {
	for name, cfg := range map[string]string{
		"foreground port":     `{"Foreground":{"s1":{"TCP":{"443":{"HTTPS":true}},"Web":{"x:443":{"Handlers":{"/":{"Proxy":"http://127.0.0.1:1"}}}}}}}`,
		"foreground hostport": `{"Foreground":{"s1":{"Web":{"` + hp443 + `":{"Handlers":{"/":{"Proxy":"http://127.0.0.1:1"}}}}}}}`,
		"plain http":          `{"TCP":{"443":{"HTTP":true}}}`,
		"tcp forward":         `{"TCP":{"443":{"TCPForward":"127.0.0.1:22"}}}`,
		"terminate tls":       `{"TCP":{"443":{"TCPForward":"127.0.0.1:22","TerminateTLS":"x"}}}`,
		"foreign mount":       `{"TCP":{"443":{"HTTPS":true}},"Web":{"` + hp443 + `":{"Handlers":{"/docs":{"Path":"/srv"}}}}}`,
		"foreign root":        `{"TCP":{"443":{"HTTPS":true}},"Web":{"` + hp443 + `":{"Handlers":{"/":{"Proxy":"http://127.0.0.1:3000"}}}}}`,
	} {
		t.Run(name, func(t *testing.T) {
			h := newHarness(t)
			h.f.SetConfig(cfg)
			h.attach()
			_, err := h.s.SetFunnel(context.Background(), admin(), core.FunnelInput{Mode: core.FunnelShares, Confirm: ConfirmPublic})
			mustCode(t, err, core.ErrConflict, "port")
			if len(h.f.Posts()) != 0 || h.f.Config() != cfg {
				t.Fatalf("written: %s", h.f.Config())
			}
			if _, ok := h.lis.get(core.IngressFunnel); ok || h.env.Settings.String(KeyMode) != core.FunnelOff {
				t.Fatal("listener opened or settings stored")
			}
			if e := h.audit.last(t, core.ActNetworkFunnel); e.Outcome != core.OutcomeDenied {
				t.Fatalf("audit %+v", e)
			}
		})
	}
}

// Funnel switched on for FileParcel's tailnet-only Serve port: the flag is
// removed and audited; the conflict shows until then.
func TestServeHardening(t *testing.T) {
	h := newHarness(t)
	h.attach()
	ctx := context.Background()
	st, err := h.s.SetServe(ctx, admin(), core.ServeInput{Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	if st.Serve.State != core.IngressStateActive || h.env.Settings.Bool(KeyServe) != true {
		t.Fatalf("serve %+v", st.Serve)
	}
	proxy := "unix:" + h.sock(core.IngressServe)
	if got := h.f.Config(); got != `{"TCP":{"443":{"HTTPS":true}},"Web":{"`+hp443+`":{"Handlers":{"/":{"Proxy":"`+proxy+`"}}}}}` {
		t.Fatalf("serve config %s", got)
	}
	urls := h.s.AccessURLs()
	if len(urls) != 1 || urls[0].Kind != core.URLKindTailscaleServe || !urls[0].Recommended || h.s.InternetLinks() {
		t.Fatalf("urls %+v", urls)
	}
	// Someone runs `tailscale funnel` on the port; a public request arrives.
	h.f.SetConfig(funnelConfig(hp443, "443", proxy))
	h.s.Note(core.IngressServe, true, true)
	if st := h.status(); st.Serve.State != core.IngressStateConflict {
		t.Fatalf("conflict not shown: %+v", st.Serve)
	}
	h.s.autoReconcile(ctx, []string{"funnel_flag"})
	var sc tslocal.ServeConfig
	_ = sc.UnmarshalJSON([]byte(h.f.Config()))
	if sc.FunnelOn(hp443) {
		t.Fatalf("flag kept: %s", h.f.Config())
	}
	if len(h.audit.withReason(core.ActNetworkServe, "funnel_flag_removed")) != 1 {
		t.Fatal("not audited")
	}
	if st := h.status(); st.Serve.State != core.IngressStateActive {
		t.Fatalf("serve %+v", st.Serve)
	}
}

func TestPrerequisites412(t *testing.T) {
	node := func(mod func(*tslocaltest.Node)) func(h *harness) {
		return func(h *harness) {
			n := tslocaltest.DefaultNode()
			mod(&n)
			h.f.SetNode(n)
		}
	}
	for _, tc := range []struct {
		name  string
		setup func(h *harness)
		port  int
		field string
		text  string
	}{
		{"no https cap", node(func(n *tslocaltest.Node) { n.Caps = []string{"funnel", tslocaltest.FunnelPortsCap} }),
			0, checkHTTPS, "HTTPS certificates"},
		{"no funnel attr", node(func(n *tslocaltest.Node) { n.Caps = []string{"https", tslocaltest.FunnelPortsCap} }),
			0, checkFunnelAttr, "nodeAttrs"},
		{"port not allowed", node(func(n *tslocaltest.Node) {
			n.Caps = []string{"https", "funnel", "https://tailscale.com/cap/funnel-ports?ports=443"}
		}), 10000, checkFunnelPort, "Allowed here: 443"},
		{"shields up", func(h *harness) {
			h.f.SetPrefs(`{"ControlURL":"https://controlplane.tailscale.com","ShieldsUp":true}`)
		}, 0, checkShieldsUp, "shields-up=false"},
		{"headscale", func(h *harness) {
			h.f.SetPrefs(`{"ControlURL":"https://hs.example.org"}`)
			n := tslocaltest.DefaultNode()
			n.Caps, n.CertDomains = nil, nil
			h.f.SetNode(n)
		}, 0, checkHTTPS, "juanfont/headscale#1921"},
		{"not running", node(func(n *tslocaltest.Node) { n.BackendState = "Stopped" }), 0, checkRunning, "Tailscale is Stopped"},
		{"magicdns off", node(func(n *tslocaltest.Node) { n.MagicDNS = false }), 0, checkMagicDNS, "MagicDNS"},
		{"not operator", func(h *harness) {
			h.s.mayConfigure = func(*tslocal.Prefs) bool { return false }
			h.f.SetPrefs(`{"ControlURL":"https://controlplane.tailscale.com","OperatorUser":"alice"}`)
		}, 0, checkOperator, "--operator=fp (tailscaled has one operator per machine; it is alice now)"},
		{"mtls required", func(h *harness) {
			h.setting("mtls.mode", `"required"`)
			h.setting("mtls.exempt_shares", `false`)
		}, 0, checkMTLS, "Tailscale's TLS"},
		{"container", func(h *harness) { h.s.inContainer = func() bool { return true } }, 0, checkContainer, "container"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t)
			tc.setup(h)
			h.attach()
			_, err := h.s.SetFunnel(context.Background(), admin(), core.FunnelInput{Mode: core.FunnelShares,
				Port: tc.port, Confirm: ConfirmPublic})
			mustCode(t, err, core.ErrPrecondition, tc.field)
			if !strings.Contains(err.Error(), tc.text) {
				t.Fatalf("message %q lacks %q", err, tc.text)
			}
			if len(h.f.Posts()) != 0 || h.env.Settings.String(KeyMode) != core.FunnelOff {
				t.Fatal("applied or stored")
			}
			if e := h.audit.last(t, core.ActNetworkFunnel); e.Outcome != core.OutcomeDenied ||
				e.Details.(map[string]any)["check"] != tc.field {
				t.Fatalf("audit %+v", e)
			}
		})
	}
	// mTLS required with share links exempt allows mode shares.
	h := newHarness(t)
	h.setting("mtls.mode", `"required"`)
	h.attach()
	h.enable(core.FunnelShares)
	// The fix_url comes from query-feature when the attr is missing.
	h = newHarness(t)
	n := tslocaltest.DefaultNode()
	n.Caps = []string{"https", tslocaltest.FunnelPortsCap}
	h.f.SetNode(n)
	h.f.SetQueryFeature(`{"Complete":false,"URL":"https://login.tailscale.com/f/funnel?node=abc"}`)
	st, _ := h.s.Status(context.Background(), true)
	var attr core.IngressCheck
	for _, c := range st.Funnel.Checks {
		if c.ID == checkFunnelAttr {
			attr = c
		}
	}
	if attr.Status != statusFail || attr.FixURL != "https://login.tailscale.com/f/funnel?node=abc" {
		t.Fatalf("attr check %+v", attr)
	}
	if st.Serve.State != core.IngressStateOff || !st.Available {
		t.Fatalf("serve is still possible: %+v", st)
	}
}

// With only the tailscale command (no LocalAPI socket), Funnel on another
// port than 443 needs 443 in funnel-ports (`tailscale funnel` checks 443).
func TestCLIPortCheck(t *testing.T) {
	h := newHarness(t)
	n := tslocaltest.DefaultNode()
	n.Caps = []string{"https", "funnel", "https://tailscale.com/cap/funnel-ports?ports=8443,10000"}
	h.s.ts = fakeCLIClient(t, n, `{}`)
	_, err := h.s.SetFunnel(context.Background(), admin(), core.FunnelInput{Mode: core.FunnelShares, Port: 10000, Confirm: ConfirmPublic})
	mustCode(t, err, core.ErrPrecondition, checkCLIPort)
}

func Test422(t *testing.T) {
	h := newHarness(t)
	h.attach()
	ctx := context.Background()
	for _, tc := range []struct {
		in    core.FunnelInput
		field string
	}{
		{core.FunnelInput{Mode: "public", Confirm: ConfirmPublic}, "mode"},
		{core.FunnelInput{Mode: core.FunnelShares, Port: 8443, Confirm: ConfirmPublic}, "port"}, // server.https_port
		{core.FunnelInput{Mode: core.FunnelShares, Port: 444, Confirm: ConfirmPublic}, "port"},
		{core.FunnelInput{Mode: core.FunnelShares}, "confirm"},
		{core.FunnelInput{Mode: core.FunnelShares, AllowAdmin: ptr(true), Confirm: ConfirmPublic}, "allow_admin"},
		{core.FunnelInput{Mode: core.FunnelApp, AllowAdmin: ptr(true), Require2FA: ptr(false), Confirm: ConfirmPublic}, "allow_admin"},
	} {
		_, err := h.s.SetFunnel(ctx, admin(), tc.in)
		mustCode(t, err, core.ErrInvalid, tc.field)
	}
	// The other kind's port.
	if _, err := h.s.SetServe(ctx, admin(), core.ServeInput{Enabled: true}); err != nil {
		t.Fatal(err)
	}
	_, err := h.s.SetFunnel(ctx, admin(), core.FunnelInput{Mode: core.FunnelShares, Confirm: ConfirmPublic})
	mustCode(t, err, core.ErrInvalid, "port")
	_, err = h.s.SetServe(ctx, admin(), core.ServeInput{Enabled: true, Port: 8443})
	mustCode(t, err, core.ErrInvalid, "port")
	h.enable2(core.FunnelShares, 10000)
	_, err = h.s.SetServe(ctx, admin(), core.ServeInput{Enabled: true, Port: 10000})
	mustCode(t, err, core.ErrInvalid, "port")
	if len(h.f.Posts()) != 2 {
		t.Fatalf("%d posts", len(h.f.Posts()))
	}
}

func (h *harness) enable2(mode string, port int) {
	h.t.Helper()
	if _, err := h.s.SetFunnel(context.Background(), admin(), core.FunnelInput{Mode: mode, Port: port, Confirm: ConfirmPublic}); err != nil {
		h.t.Fatal(err)
	}
}

func ptr[T any](v T) *T { return &v }

// Weakening sign-in over Funnel is for built-in owners and administrators;
// a network.manage delegate may switch Funnel on and off and move it.
func TestRBACWeakening(t *testing.T) {
	h := newHarness(t)
	h.attach()
	ctx := context.Background()
	if _, err := h.s.SetFunnel(ctx, delegate(), core.FunnelInput{Mode: core.FunnelApp, Confirm: ConfirmPublic}); err != nil {
		t.Fatalf("delegate enable: %v", err)
	}
	for _, in := range []core.FunnelInput{
		{Mode: core.FunnelApp, Require2FA: ptr(false), Confirm: ConfirmPublic},
		{Mode: core.FunnelApp, AllowAdmin: ptr(true), Confirm: ConfirmPublic},
	} {
		n := len(h.audit.actions(core.ActNetworkFunnel))
		_, err := h.s.SetFunnel(ctx, delegate(), in)
		mustCode(t, err, core.ErrForbidden, "")
		if !strings.Contains(err.Error(), "only an owner or administrator") {
			t.Fatalf("message %v", err)
		}
		es := h.audit.actions(core.ActNetworkFunnel)
		if len(es) != n+1 || es[n].Outcome != core.OutcomeDenied || es[n].Details.(map[string]any)["reason"] != "rbac" ||
			es[n].ActorName != "netops" {
			t.Fatalf("audit %+v", es[n:])
		}
	}
	if !h.env.Settings.Bool(KeyRequire2FA) || h.env.Settings.Bool(KeyAllowAdmin) {
		t.Fatal("weakened")
	}
	if _, err := h.s.SetFunnel(ctx, delegate(), core.FunnelInput{Mode: core.FunnelApp, Port: 10000}); err != nil {
		t.Fatalf("delegate port change: %v", err)
	}
	if _, err := h.s.SetFunnel(ctx, admin(), core.FunnelInput{Mode: core.FunnelApp, AllowAdmin: ptr(true), Confirm: ConfirmPublic}); err != nil {
		t.Fatalf("admin: %v", err)
	}
	if p := h.s.Policy(core.IngressFunnel); !p.AllowAdmin || !p.Require2FA {
		t.Fatalf("policy %+v", p)
	}
	// Restoring the safe values needs no confirmation and no admin.
	if _, err := h.s.SetFunnel(ctx, delegate(), core.FunnelInput{Mode: core.FunnelApp, AllowAdmin: ptr(false)}); err != nil {
		t.Fatalf("delegate tightening: %v", err)
	}
	if _, err := h.s.SetFunnel(ctx, delegate(), core.FunnelInput{Mode: core.FunnelOff}); err != nil {
		t.Fatalf("delegate disable: %v", err)
	}
}

func TestETagRetry(t *testing.T) {
	h := newHarness(t)
	h.attach()
	once := false
	h.f.BeforePost(func(f *tslocaltest.Fake) {
		h.log.add("post")
		if !once {
			once = true
			f.SetConfig(`{"TCP":{"10000":{"TCPForward":"127.0.0.1:22"}}}`)
		}
	})
	h.enable(core.FunnelShares)
	posts := h.f.Posts()
	if len(posts) != 2 || posts[0].IfMatch == posts[1].IfMatch {
		t.Fatalf("posts %+v", posts)
	}
	got := h.f.Config()
	if !strings.Contains(got, `"10000":{"TCPForward":"127.0.0.1:22"}`) || !strings.Contains(got, "ts-funnel.sock") {
		t.Fatalf("merged %s", got)
	}
}

// tailscaled refuses the Unix socket for this user: auto switches to the
// TCP backend, stores the port and warns.
func TestUnixForbiddenFallsBackToTCP(t *testing.T) {
	h := newHarness(t)
	h.attach()
	h.f.SetUnixForbidden(true)
	st := h.enable(core.FunnelShares)
	if got, want := h.f.Config(), funnelConfig(hp443, "443", "http://127.0.0.1:18443"); got != want {
		t.Fatalf("config %s", got)
	}
	if h.env.Settings.Int(KeyBackendPort) != 18443 {
		t.Fatalf("backend port %d", h.env.Settings.Int(KeyBackendPort))
	}
	if v, _ := h.lis.get(core.IngressFunnel); v != [2]string{"tcp4", "127.0.0.1:18443"} {
		t.Fatalf("listener %v", v)
	}
	var tcp *core.IngressCheck
	for i, c := range st.Funnel.Checks {
		if c.ID == checkBackendTCP {
			tcp = &st.Funnel.Checks[i]
		}
	}
	if tcp == nil || tcp.Status != statusWarn || !strings.Contains(tcp.Message, "only allows Unix-socket targets") {
		t.Fatalf("backend.tcp check %+v", tcp)
	}
	if st.Funnel.State != core.IngressStateActive || h.marker().Backend != BackendTCP {
		t.Fatalf("state %+v", st.Funnel)
	}
	// Serve takes the next port.
	if st, _ = h.s.SetServe(context.Background(), admin(), core.ServeInput{Enabled: true, Port: 8444}); st == nil ||
		st.Serve.Backend != "http://127.0.0.1:18444" {
		t.Fatalf("serve %+v", st)
	}
}

// A foreign entry with a Unix socket makes tailscaled check every write:
// with the TCP backend the write still fails, and the hint names what
// helps: changing that entry (a "sudo fileparcel … reapply" cannot, the
// server writes as its own user).
func TestForeignUnixEntryWithTCPBackend(t *testing.T) {
	h := newHarness(t)
	h.setting(KeyBackend, `"tcp"`)
	h.setting(KeyBackendPort, `20000`)
	h.f.SetConfig(`{"TCP":{"10000":{"HTTPS":true}},"Web":{"node.tail.ts.net:10000":{"Handlers":{"/":{"Proxy":"unix:/run/other.sock"}}}}}`)
	h.f.SetUnixForbidden(true)
	h.attach()
	_, err := h.s.SetFunnel(context.Background(), admin(), core.FunnelInput{Mode: core.FunnelShares, Confirm: ConfirmPublic})
	mustCode(t, err, core.ErrPrecondition, checkBackend)
	if msg := err.Error(); !strings.Contains(msg, "remove that entry") || !strings.Contains(msg, "TCP target") ||
		strings.Contains(msg, "sudo fileparcel") {
		t.Fatalf("message %v", err)
	}
	if _, ok := h.lis.get(core.IngressFunnel); ok || h.env.Settings.String(KeyMode) != core.FunnelOff {
		t.Fatal("not reverted")
	}
	if !errors.Is(err, tslocal.ErrUnixForbidden) {
		t.Fatalf("cause lost: %v", err)
	}
}

// Apply first, store after: a failed apply stores nothing; a failed store
// puts tailscaled back.
func TestApplyThenStore(t *testing.T) {
	h := newHarness(t)
	h.attach()
	h.f.FailNextPost(http.StatusInternalServerError, `{"error":"updating config: something broke"}`)
	_, err := h.s.SetFunnel(context.Background(), admin(), core.FunnelInput{Mode: core.FunnelShares, Confirm: ConfirmPublic})
	mustCode(t, err, core.ErrUnavailable, "")
	if h.env.Settings.String(KeyMode) != core.FunnelOff || h.f.Config() != "null" {
		t.Fatal("stored after a failed apply")
	}
	if _, ok := h.lis.get(core.IngressFunnel); ok || h.s.Policy(core.IngressFunnel).Mode != core.FunnelOff {
		t.Fatal("listener left open")
	}
	if e := h.audit.last(t, core.ActNetworkFunnel); e.Outcome != core.OutcomeFailure {
		t.Fatalf("audit %+v", e)
	}

	h.env.Settings = &failingSettings{Settings: h.env.Settings, fail: func(ch map[string]json.RawMessage) error {
		if _, ok := ch[KeyMode]; ok {
			return errors.New("disk full")
		}
		return nil
	}}
	_, err = h.s.SetFunnel(context.Background(), admin(), core.FunnelInput{Mode: core.FunnelShares, Confirm: ConfirmPublic})
	if err == nil || !strings.Contains(err.Error(), "disk full") {
		t.Fatalf("store error %v", err)
	}
	if h.f.Config() != "null" || h.marker() != nil {
		t.Fatalf("tailscaled not reverted: %s", h.f.Config())
	}
	if _, ok := h.lis.get(core.IngressFunnel); ok {
		t.Fatal("listener left open")
	}
}

// A server port moved onto the Funnel port removes FileParcel's entry.
func TestPortClashRemoved(t *testing.T) {
	h := newHarness(t)
	h.attach()
	h.enable(core.FunnelShares)
	h.setting("server.https_port", `443`)
	h.s.autoReconcile(context.Background(), []string{"settings"})
	if h.f.Config() != "null" {
		t.Fatalf("entry kept: %s", h.f.Config())
	}
	if len(h.audit.withReason(core.ActNetworkFunnel, "port_clash_removed")) != 1 {
		t.Fatal("not audited")
	}
	st := h.status()
	if st.Funnel.State != core.IngressStateUnavailable || !strings.Contains(st.Funnel.Message, "FileParcel itself uses port 443") {
		t.Fatalf("status %+v", st.Funnel)
	}
	if _, ok := h.lis.get(core.IngressFunnel); ok {
		t.Fatal("listener open")
	}
}

// Note records requests and announces the first public one.
func TestNoteAndEvents(t *testing.T) {
	h := newHarness(t)
	ch, cancel := h.env.Bus.Subscribe(events.TopicIngressChanged)
	defer cancel()
	h.attach()
	h.enable(core.FunnelShares)
	for len(ch) > 0 {
		<-ch
	}
	h.s.Note(core.IngressFunnel, false, false)
	if len(ch) != 0 {
		t.Fatal("a tailnet request published an event")
	}
	h.s.Note(core.IngressFunnel, true, false)
	h.s.Note(core.IngressFunnel, true, false)
	if len(ch) != 1 {
		t.Fatalf("%d events for two public requests in a row", len(ch))
	}
	st := h.status()
	if st.Funnel.LastRequestAt == nil || st.Funnel.LastPublicRequestAt == nil || st.Serve.LastRequestAt != nil {
		t.Fatalf("times %+v", st.Funnel)
	}
	h.s.Note("bogus", true, true)
}
