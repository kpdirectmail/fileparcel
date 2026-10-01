package tsingress

import (
	"context"
	"net/netip"
	"slices"
	"strings"
	"testing"
	"time"

	"fileparcel/internal/core"
	"fileparcel/internal/tslocal"
	"fileparcel/internal/tslocal/tslocaltest"
)

func findings(fs []OfflineFinding, id string) []OfflineFinding {
	var out []OfflineFinding
	for _, f := range fs {
		if f.ID == id {
			out = append(out, f)
		}
	}
	return out
}

func TestOfflineFindings(t *testing.T) {
	ctx := context.Background()
	h := newHarness(t)
	// Nothing configured, nothing foreign: nil.
	if fs := OfflineFindings(ctx, h.home, h.f.Client()); fs != nil {
		t.Fatalf("%+v", fs)
	}
	// Pending (enabled while stopped).
	h.enable(core.FunnelShares)
	fs := OfflineFindings(ctx, h.home, h.f.Client())
	if f := findings(fs, FindingFunnel); len(f) != 1 || f[0].Status != "info" || !strings.Contains(f[0].Message, "when the server starts") {
		t.Fatalf("pending %+v", fs)
	}
	// Applied and present.
	h.attach()
	h.restart()
	fs = OfflineFindings(ctx, h.home, h.f.Client())
	if f := findings(fs, FindingFunnel); len(f) != 1 || f[0].Status != "info" ||
		!strings.Contains(f[0].Message, "https://node.tail.ts.net/") {
		t.Fatalf("applied %+v", fs)
	}
	// Applied but removed outside FileParcel.
	h.f.SetConfig("null")
	fs = OfflineFindings(ctx, h.home, h.f.Client())
	if f := findings(fs, FindingFunnel); len(f) != 1 || f[0].Status != "warn" || !strings.Contains(f[0].Hint, "funnel reapply") {
		t.Fatalf("drift %+v", fs)
	}
	// tailscaled unreachable: still reported from the marker.
	fs = OfflineFindings(ctx, h.home, &tslocal.Client{Sockets: []string{"/nonexistent/ts.sock"}})
	if f := findings(fs, FindingFunnel); len(f) != 1 || f[0].Status != "info" {
		t.Fatalf("unreachable %+v", fs)
	}
	// A foreign entry to FileParcel's own port, and an expiring key.
	h.f.SetConfig(`{"Foreground":{"s":{"TCP":{"443":{"HTTPS":true}},"Web":{"node.tail.ts.net:443":{"Handlers":{"/":{"Proxy":"https+insecure://localhost:8443"}}}}}}}`)
	n := tslocaltest.DefaultNode()
	exp := time.Now().Add(48 * time.Hour)
	n.KeyExpiry = &exp
	h.f.SetNode(n)
	fs = OfflineFindings(ctx, h.home, h.f.Client())
	if f := findings(fs, FindingBypass); len(f) != 1 || f[0].Status != "fail" || !strings.Contains(f[0].Hint, "network funnel enable") {
		t.Fatalf("bypass %+v", fs)
	}
	if f := findings(fs, FindingKeyExpiry); len(f) != 1 || f[0].Status != "warn" {
		t.Fatalf("key expiry %+v", fs)
	}
	// Without a marker the bypass alone is reported.
	if err := writeMarker(h.home, nil); err != nil {
		t.Fatal(err)
	}
	fs = OfflineFindings(ctx, h.home, h.f.Client())
	if len(fs) != 1 || fs[0].ID != FindingBypass {
		t.Fatalf("%+v", fs)
	}
}

// A crashed server leaves its TCP entry: the offline doctor warns.
func TestOfflineFindingsTCPResidue(t *testing.T) {
	h := newHarness(t)
	h.setting(KeyBackend, `"tcp"`)
	h.attach()
	h.enable(core.FunnelShares)
	// No Detach: a crash.
	fs := OfflineFindings(context.Background(), h.home, h.f.Client())
	if f := findings(fs, FindingFunnel); len(f) != 1 || f[0].Status != "warn" || !strings.Contains(f[0].Message, "127.0.0.1:18443") {
		t.Fatalf("%+v", fs)
	}
}

func TestBypassTarget(t *testing.T) {
	const admin = "/h/run/admin.sock"
	local := (&Service{}).localHost(&tsView{st: &tslocal.Status{Self: &tslocal.SelfStatus{DNSName: "Node.tail.ts.net.",
		HostName: "node", TailscaleIPs: []netip.Addr{netip.MustParseAddr("100.101.102.103")}}}})
	mains := []int{8443}
	for _, target := range []string{
		"https+insecure://localhost:8443", "http://127.0.0.1:8443", "8443", "localhost:8443", "tcp://[::1]:8443",
		"127.0.0.1:8443", "unix:" + admin, "https://node.tail.ts.net:8443/x", "http://100.101.102.103:8443",
		"https://node:8443", "http://[::]:8443", "unix:/h/run/../run/admin.sock",
	} {
		if !bypassTarget(target, mains, admin, local) {
			t.Errorf("%q not recognised", target)
		}
	}
	for _, target := range []string{
		"", "http://127.0.0.1:3000", "https://localhost", "8444", "tcp://example.org:8443", "unix:/h/run/ts-funnel.sock",
		"http://192.0.2.7:8443", "text", "ftp://localhost:8443", "unix:/other/admin.sock",
	} {
		if bypassTarget(target, mains, admin, local) {
			t.Errorf("%q flagged", target)
		}
	}
	if !bypassTarget("https://localhost", []int{443}, admin, local) || !bypassTarget("http://localhost", []int{80}, admin, local) {
		t.Error("default ports")
	}
}

// Foreign entries in the status carry the bypass flag, Foreground and
// Services included.
func TestStatusForeignBypass(t *testing.T) {
	h := newHarness(t)
	h.f.SetConfig(`{"TCP":{"10000":{"TCPForward":"127.0.0.1:8443"}},` +
		`"Foreground":{"s":{"Web":{"node.tail.ts.net:4443":{"Handlers":{"/":{"Proxy":"unix:` + h.home.Socket() + `"}}}}}},` +
		`"Services":{"svc:x":{"Web":{"x.tail.ts.net:443":{"Handlers":{"/":{"Proxy":"http://localhost:8443"}}}}}},` +
		`"Web":{"node.tail.ts.net:8080":{"Handlers":{"/":{"Proxy":"http://127.0.0.1:3000"}}}}}`)
	st := h.status()
	got := map[string]bool{}
	for _, f := range st.Foreign {
		got[f.Target] = f.Bypass
	}
	want := map[string]bool{"tcp:127.0.0.1:8443": true, "unix:" + h.home.Socket(): true,
		"http://localhost:8443": true, "http://127.0.0.1:3000": false}
	for k, v := range want {
		if b, ok := got[k]; !ok || b != v {
			t.Errorf("%s: %v (present %v)", k, b, ok)
		}
	}
}

func TestParseProcNetListen(t *testing.T) {
	tcp := `  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000:01BB 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 1 1 0 100 0 0 10 0
   1: 0100007F:01BB 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 2 1 0 100 0 0 10 0
   2: 0A004064:01BB 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 3 1 0 100 0 0 10 0
   3: 00000000:20FB 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 4 1 0 100 0 0 10 0
   4: 0100007F:01BB 0100007F:9C40 01 00000000:00000000 00:00000000 00000000  1000        0 5 1 0 20 4 30 10 -1
`
	got := parseProcNetListen([]byte(tcp), 443)
	want := []string{"0.0.0.0:443", "127.0.0.1:443", "100.64.0.10:443"}
	var gs []string
	for _, a := range got {
		gs = append(gs, a.String())
	}
	if !slices.Equal(gs, want) {
		t.Fatalf("%v", gs)
	}
	tcp6 := `  sl  local_address                         remote_address                        st
   0: 00000000000000000000000000000000:01BB 00000000000000000000000000000000:0000 0A
   1: 00000000000000000000000001000000:01BB 00000000000000000000000000000000:0000 0A
   2: 0000000000000000FFFF00000100007F:01BB 00000000000000000000000000000000:0000 0A
`
	gs = nil
	for _, a := range parseProcNetListen([]byte(tcp6), 443) {
		gs = append(gs, a.String())
	}
	if !slices.Equal(gs, []string{"[::]:443", "[::1]:443", "127.0.0.1:443"}) {
		t.Fatalf("%v", gs)
	}
}

// port.shadow: another program on the wildcard address or the Tailscale
// address (before FileParcel's own entry exists) is reported.
func TestPortShadow(t *testing.T) {
	h := newHarness(t)
	h.s.listening = func(port int) ([]netip.AddrPort, bool) {
		if port != 443 {
			return nil, true
		}
		return []netip.AddrPort{netip.MustParseAddrPort("127.0.0.1:443"), netip.MustParseAddrPort("0.0.0.0:443")}, true
	}
	st := h.status()
	var c core.IngressCheck
	for _, x := range st.Funnel.Checks {
		if x.ID == checkPortShadow {
			c = x
		}
	}
	if c.Status != statusWarn || !strings.Contains(c.Message, "0.0.0.0:443") || strings.Contains(c.Message, "127.0.0.1") {
		t.Fatalf("%+v", c)
	}
	h.s.listening = func(int) ([]netip.AddrPort, bool) { return nil, false }
	for _, x := range h.status().Funnel.Checks {
		if x.ID == checkPortShadow && x.Status != statusSkip {
			t.Fatalf("%+v", x)
		}
	}
}
