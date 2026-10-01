package httpx

import (
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"

	"fileparcel/internal/core"
)

func TestProxySignal(t *testing.T) {
	var s ProxySignal
	if snap := s.Snapshot(); snap.Count != 0 || !snap.Last.IsZero() || snap.Host != "" || s.Since(time.Time{}) {
		t.Fatalf("zero signal %+v", snap)
	}
	at := time.Date(2026, 9, 29, 10, 0, 0, 0, time.UTC)
	s.Note("Node.Tail.TS.net:443", at)
	s.Note("", at.Add(time.Minute)) // no host: the last one stays
	snap := s.Snapshot()
	if snap.Count != 2 || !snap.Last.Equal(at.Add(time.Minute)) || snap.Host != "node.tail.ts.net:443" {
		t.Fatalf("snapshot %+v", snap)
	}
	if !s.Since(at) || !s.Since(at.Add(time.Minute)) || s.Since(at.Add(2*time.Minute)) {
		t.Fatal("Since")
	}
	for in, want := range map[string]string{
		"evil<script>.example":   "evilscript.example",
		"[2001:DB8::1]:8443":     "[2001:db8::1]:8443",
		"a b\r\nc":               "abc",
		strings.Repeat("a", 999): strings.Repeat("a", maxSignalHost),
		"ünïcode.example":        "ncode.example",
	} {
		if got := SanitizeHost(in); got != want {
			t.Errorf("SanitizeHost(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestMetaIngress(t *testing.T) {
	r := httptest.NewRequest("GET", "/", nil)
	if m := Meta(r); m.Ingress != "" || m.IP.String() != "192.0.2.1" {
		t.Fatalf("direct meta %+v", m)
	}
	ip := netip.MustParseAddr("203.0.113.9")
	r = r.WithContext(WithClientIP(core.WithIngress(r.Context(), &core.IngressInfo{Kind: core.IngressFunnel, ClientIP: ip}), ip))
	if m := Meta(r); m.Ingress != core.IngressFunnel || m.IP != ip {
		t.Fatalf("funnel meta %+v", m)
	}
}

// ProxyExposures: every foreign entry that reaches FileParcel directly is a
// failure with a removal hint fitting its kind (at most a few), and the
// process-wide signals count for 24 hours.
func TestProxyExposures(t *testing.T) {
	// The package-wide signals are noted by nothing else in this package.
	now := time.Date(2018, 3, 1, 12, 0, 0, 0, time.UTC)
	if got := ProxyExposures(nil, now); got == nil || len(got) != 0 {
		t.Fatalf("nothing: %+v", got)
	}
	st := &core.IngressStatus{Foreign: []core.ForeignServe{
		{HostPort: "node.tail.ts.net:8443", Mount: "/", Target: "https+insecure://localhost:8443", Funnel: true, Bypass: true},
		{HostPort: "node.tail.ts.net:443", Mount: "/admin", Target: "unix:/srv/fp/run/admin.sock", Bypass: true},
		{HostPort: "node.tail.ts.net:10000", Mount: "/", Target: "http://127.0.0.1:8443", Bypass: true},
		{HostPort: "node.tail.ts.net:443", Mount: "/", Target: "127.0.0.1:8443", Foreground: true, Bypass: true},
		{HostPort: "svc:files:443", Mount: "/", Target: "http://localhost:8443", Service: "svc:files", Bypass: true},
		{HostPort: "node.tail.ts.net:10000", Mount: "/other", Target: "http://127.0.0.1:3000"},
		{HostPort: "node.tail.ts.net:9", Mount: "/", Target: "8443", Bypass: true},
	}}
	got := ProxyExposures(st, now)
	if len(got) != maxBypassExposures {
		t.Fatalf("%d exposures: %+v", len(got), got)
	}
	for i, want := range []struct{ msg, hint string }{
		{"Tailscale Funnel forwards node.tail.ts.net:8443/ straight to FileParcel (https+insecure://localhost:8443)", "`tailscale serve --yes --https=8443 off`"},
		{"to FileParcel's admin socket (unix:/srv/fp/run/admin.sock), which refuses proxied requests", "--https=443 off"},
		{"every tailnet visitor looks like this machine", "--https=10000 off"},
		{"(127.0.0.1:8443)", "runs in the foreground"},
		{"(http://localhost:8443)", "Tailscale service svc:files"},
	} {
		e := got[i]
		if e.ID != ExposureBypass || e.Severity != "fail" || !strings.Contains(e.Message, want.msg) || !strings.Contains(e.Hint, want.hint) ||
			!strings.Contains(e.Hint, "fileparcel network funnel enable") {
			t.Errorf("exposure %d: %+v", i, e)
		}
	}

	ProxySignals.FunnelToMain.Note("Box.Tail.ts.net:8443", now.Add(-23*time.Hour))
	ProxySignals.LocalProxy.Note("", now.Add(-time.Minute))
	got = ProxyExposures(nil, now)
	if len(got) != 2 || got[0].ID != ExposureBypass || !strings.Contains(got[0].Message, "box.tail.ts.net:8443") ||
		!strings.Contains(got[0].Message, now.Add(-23*time.Hour).Format("2006-01-02 15:04 UTC")) ||
		!strings.Contains(got[0].Hint, "--https=8443 --set-path=") || got[1].ID != ExposureLocalProxy || got[1].Severity != "warn" ||
		!strings.Contains(got[1].Message, "an unknown host") || !strings.Contains(got[1].Hint, "server.trusted_proxies") {
		t.Fatalf("signals: %+v", got)
	}
	// Almost a day later: the Funnel request is older than 24 hours, the proxy's is not.
	if got := ProxyExposures(nil, now.Add(ProxySignalWindow-2*time.Minute)); len(got) != 1 || got[0].ID != ExposureLocalProxy {
		t.Fatalf("a day later: %+v", got)
	}
	if portOf("[2001:db8::1]", 443) != 443 || portOf("host:70000", 443) != 443 || portOf("host:10000", 443) != 10000 {
		t.Fatal("portOf")
	}
}
