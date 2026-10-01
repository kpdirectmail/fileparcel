package netinfo

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"fileparcel/internal/core"
	"fileparcel/internal/tslocal"
)

const fakeStatus = `{
 "BackendState": "Running",
 "TUN": true,
 "Version": "1.102.4",
 "TailscaleIPs": ["100.64.0.10", "fd7a:115c:a1e0::a"],
 "Self": {"ID": "nExampleNode1CNTRL", "HostName": "files", "DNSName": "Files.tail1234.ts.net.", "TailscaleIPs": ["100.64.0.10"],
          "KeyExpiry": "2027-03-13T01:09:45Z",
          "CapMap": {"https": null, "funnel": null, "https://tailscale.com/cap/funnel-ports?ports=443,8443,10000": null}},
 "MagicDNSSuffix": "tail1234.ts.net",
 "CurrentTailnet": {"Name": "example.github", "MagicDNSSuffix": "tail1234.ts.net", "MagicDNSEnabled": true},
 "CertDomains": ["files.tail1234.ts.net"]
}`

// shortTempDir returns a temp dir with a short path (Unix socket paths are
// limited to ~104 bytes).
func shortTempDir(t *testing.T) string {
	t.Helper()
	d, err := os.MkdirTemp("", "fpni")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(d) })
	return d
}

func fakeLocalAPI(t *testing.T, controlURL, operator string, hits *atomic.Int32) string {
	t.Helper()
	sock := filepath.Join(shortTempDir(t), "ts.sock")
	l, err := net.Listen("unix", sock)
	if err != nil {
		t.Skipf("unix sockets unavailable: %v", err)
	}
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Host != "local-tailscaled.sock" {
			http.Error(w, "bad host", http.StatusForbidden)
			return
		}
		if hits != nil {
			hits.Add(1)
		}
		switch r.URL.Path {
		case "/localapi/v0/status":
			if r.URL.Query().Get("peers") != "false" {
				http.Error(w, "peers requested", http.StatusBadRequest)
				return
			}
			_, _ = w.Write([]byte(fakeStatus))
		case "/localapi/v0/prefs":
			_, _ = w.Write([]byte(`{"ControlURL":"` + controlURL + `","OperatorUser":"` + operator + `","ShieldsUp":true}`))
		default:
			http.NotFound(w, r)
		}
	}))
	srv.Listener = l
	srv.Start()
	t.Cleanup(srv.Close)
	return sock
}

func operatorIs(name string) func(*tslocal.Prefs) bool {
	return func(p *tslocal.Prefs) bool { return p != nil && name != "" && p.OperatorUser == name }
}

func TestTailscaleLocalAPI(t *testing.T) {
	var hits atomic.Int32
	sock := fakeLocalAPI(t, "https://controlplane.tailscale.com", "alice", &hits)
	now := time.Unix(1000, 0)
	c := &tailscaleClient{tl: &tslocal.Client{Sockets: []string{"/nonexistent/x.sock", sock}}, ttl: 30 * time.Second,
		now: func() time.Time { return now }, goos: "linux", mayConfigure: operatorIs("alice")}
	info := c.get(context.Background(), false)
	if !info.Running || info.Kind != core.IfTailscale || info.DNSName != "files.tail1234.ts.net" || info.Tailnet != "example.github" ||
		len(info.IPs) != 2 || !info.CertCapable || info.ControlURL != "https://controlplane.tailscale.com" || info.Error != "" ||
		!info.Installed {
		t.Fatalf("%+v", info)
	}
	// The v4 fields (Funnel/Serve prerequisites).
	if info.Version != "1.102.4" || info.NodeID != "nExampleNode1CNTRL" || info.Userspace || !info.ShieldsUp ||
		!info.CanConfigure || !info.FunnelCapable || len(info.FunnelPorts) != 3 || info.KeyExpiry == nil ||
		info.KeyExpiry.Format(time.RFC3339) != "2027-03-13T01:09:45Z" || info.KindGuessed {
		t.Fatalf("v4 fields %+v", info)
	}
	// Cached for 30 s.
	n := hits.Load()
	c.get(context.Background(), false)
	if hits.Load() != n {
		t.Fatal("not cached")
	}
	now = now.Add(31 * time.Second)
	c.get(context.Background(), false)
	if hits.Load() == n {
		t.Fatal("cache not expired")
	}
	// The result is a copy.
	info.IPs[0] = info.IPs[1]
	info.FunnelPorts[0] = 1
	*info.KeyExpiry = time.Time{}
	if p := c.peek(); p.IPs[0].String() != "100.64.0.10" || p.FunnelPorts[0] != 443 || p.KeyExpiry.IsZero() {
		t.Fatal("cache aliased")
	}
}

func TestTailscaleHeadscale(t *testing.T) {
	sock := fakeLocalAPI(t, "https://headscale.example.org:8080", "", nil)
	c := &tailscaleClient{tl: &tslocal.Client{Sockets: []string{sock}}, ttl: time.Minute, now: time.Now,
		mayConfigure: operatorIs("")}
	info := c.get(context.Background(), true)
	if info.Kind != core.IfHeadscale || info.CertCapable || info.KindGuessed || info.CanConfigure {
		t.Fatalf("%+v", info)
	}
}

// Without readable prefs the kind is guessed from the MagicDNS name
// (DESIGN §10.1): a name outside .ts.net/.tailscale.net means a self-hosted
// control server.
func TestTailscaleKindGuessedWithoutPrefs(t *testing.T) {
	c := &tailscaleClient{mayConfigure: operatorIs("")}
	for name, want := range map[string]bool{
		"files.tail1234.ts.net.": false, "box.example.tailscale.net.": false,
		"box.hs.example.org.": true, "": false,
	} {
		var st tslocal.Status
		if err := json.Unmarshal([]byte(fakeStatus), &st); err != nil {
			t.Fatal(err)
		}
		st.Self.DNSName, st.MagicDNSSuffix = name, ""
		info := c.build(&st, nil)
		if (info.Kind == core.IfHeadscale) != want || info.KindGuessed != want {
			t.Errorf("%q: %+v", name, info)
		}
	}
}

func TestTailscaleCLIFallback(t *testing.T) {
	dir := shortTempDir(t)
	script := filepath.Join(dir, "tailscale")
	body := "#!/bin/sh\n" +
		"if [ \"$1\" = status ]; then\n" +
		"  case \"$*\" in *peers*) echo 'flag provided but not defined: -peers' >&2; exit 2;; esac\n" +
		"  cat <<'EOF'\n" + strings.ReplaceAll(fakeStatus, `"Running"`, `"Stopped"`) + "\nEOF\n  exit 0\nfi\n" +
		"if [ \"$1\" = debug ]; then echo '{\"ControlURL\":\"https://hs.example.net\"}'; exit 0; fi\n" +
		"exit 1\n"
	if err := os.WriteFile(script, []byte(body), 0o755); err != nil {
		t.Fatal(err)
	}
	c := &tailscaleClient{tl: &tslocal.Client{Sockets: []string{filepath.Join(dir, "missing.sock")}, CLIs: []string{script}},
		ttl: time.Minute, now: time.Now, mayConfigure: func(*tslocal.Prefs) bool { return true }}
	info := c.get(context.Background(), true)
	if info.Running || info.BackendState != "Stopped" || info.Kind != core.IfHeadscale || info.CertCapable ||
		info.Error == "" || info.DNSName != "files.tail1234.ts.net" || info.CanConfigure || info.Userspace {
		t.Fatalf("%+v", info)
	}
}

func TestTailscaleMissing(t *testing.T) {
	c := &tailscaleClient{tl: &tslocal.Client{Sockets: []string{"/nonexistent/sock"}, CLIs: []string{"/nonexistent/tailscale"}},
		ttl: time.Minute, now: time.Now}
	info := c.get(context.Background(), true)
	// Neither a socket nor a CLI: not installed, which the UI shows as a
	// neutral note rather than a problem.
	if info.Running || info.Error == "" || info.Installed {
		t.Fatalf("%+v", info)
	}
	// A failing CLI reports its error (installed but broken).
	dir := shortTempDir(t)
	script := filepath.Join(dir, "tailscale")
	_ = os.WriteFile(script, []byte("#!/bin/sh\necho 'failed to connect to local tailscaled' >&2\nexit 1\n"), 0o755)
	c.tl.CLIs = []string{script}
	info = c.get(context.Background(), true)
	if info.Running || !strings.Contains(info.Error, "failed to connect") || !info.Installed {
		t.Fatalf("%+v", info)
	}
	// Under `go test` the default client reaches nothing, whatever runs on
	// the machine.
	t.Setenv(tslocal.EnvSocket, "")
	if def := newTailscaleClient(); def.tl.Installed() {
		t.Fatalf("default client under test: %+v", def.tl)
	}
}

// A failing tailscaled keeps the node's identity from its last answer for
// tsGrace (so the MagicDNS name stays in the SANs), retrying every tsRetry,
// while the failure itself is still reported.
func TestTailscaleFailureKeepsIdentity(t *testing.T) {
	var hits atomic.Int32
	sock := fakeLocalAPI(t, "https://hs.example.org", "", &hits)
	now := time.Unix(1000, 0)
	c := &tailscaleClient{tl: &tslocal.Client{Sockets: []string{sock}}, ttl: tsCacheTTL,
		now: func() time.Time { return now }, mayConfigure: operatorIs("")}
	if info := c.get(context.Background(), false); !info.Running || info.Kind != core.IfHeadscale {
		t.Fatalf("first: %+v", info)
	}
	c.tl = &tslocal.Client{Sockets: []string{filepath.Join(shortTempDir(t), "gone.sock")}}
	now = now.Add(tsCacheTTL + time.Second)
	info := c.get(context.Background(), false)
	if info.Running || info.Error == "" || info.DNSName != "files.tail1234.ts.net" || info.Kind != core.IfHeadscale ||
		len(info.IPs) != 2 || info.Tailnet != "example.github" || info.ControlURL != "https://hs.example.org" || info.CertCapable ||
		info.NodeID != "nExampleNode1CNTRL" {
		t.Fatalf("failure: %+v", info)
	}
	// Retried after tsRetry (shorter than the TTL); back to normal once
	// tailscaled answers again.
	c.tl = &tslocal.Client{Sockets: []string{sock}}
	n := hits.Load()
	now = now.Add(tsRetry - time.Second)
	c.get(context.Background(), false)
	if hits.Load() != n {
		t.Fatal("retried before tsRetry")
	}
	now = now.Add(2 * time.Second)
	if info := c.get(context.Background(), false); !info.Running || info.Error != "" || hits.Load() == n || !c.failedAt.IsZero() {
		t.Fatalf("recovered: %+v", info)
	}
	// Failing for longer than tsGrace: the identity is dropped.
	c.tl = &tslocal.Client{Sockets: []string{filepath.Join(shortTempDir(t), "gone.sock")}}
	now = now.Add(tsCacheTTL + time.Second)
	if info := c.get(context.Background(), false); info.DNSName == "" {
		t.Fatalf("within grace: %+v", info)
	}
	now = now.Add(tsGrace)
	if info := c.get(context.Background(), false); info.DNSName != "" || info.Kind != "" || len(info.IPs) != 0 || info.Running {
		t.Fatalf("after grace: %+v", info)
	}
	// ... and the bare failure is cached for the normal TTL again.
	if c.cacheTTL() != tsCacheTTL {
		t.Fatalf("ttl %v", c.cacheTTL())
	}
}

func TestTailscaleMagicDNSDisabled(t *testing.T) {
	var st tslocal.Status
	raw := strings.Replace(fakeStatus, `"MagicDNSEnabled": true`, `"MagicDNSEnabled": false`, 1)
	if err := json.Unmarshal([]byte(raw), &st); err != nil {
		t.Fatal(err)
	}
	c := &tailscaleClient{mayConfigure: func(*tslocal.Prefs) bool { return true }}
	info := c.build(&st, nil)
	if info.DNSName != "" || !info.Running || !info.CertCapable || info.Kind != core.IfTailscale {
		t.Fatalf("%+v", info)
	}
}

// A connected daemon without TUN device (userspace networking) dials tailnet
// connections to 127.0.0.1: reported for the exposure checks.
func TestTailscaleUserspace(t *testing.T) {
	var st tslocal.Status
	if err := json.Unmarshal([]byte(strings.Replace(fakeStatus, `"TUN": true`, `"TUN": false`, 1)), &st); err != nil {
		t.Fatal(err)
	}
	c := &tailscaleClient{mayConfigure: func(*tslocal.Prefs) bool { return false }, goos: "darwin"}
	info := c.build(&st, &tslocal.Prefs{ControlURL: "https://controlplane.tailscale.com"})
	if !info.Userspace || info.CanConfigure != true || info.CertCapable {
		// macOS: the write decides whether the configuration may change.
		t.Fatalf("%+v", info)
	}
}
