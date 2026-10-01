package netinfo

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"fileparcel/internal/core"
)

func readFixture(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", "cloudflared", name))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestYAMLRules(t *testing.T) {
	got := yamlRules(readFixture(t, "config.yml"))
	want := []tunnelRule{{"files.example.org", "https://localhost:8443"}, {"grafana.example.org", "http://localhost:3000"},
		{"", "https://127.0.0.1:8443/"}, {"", "http_status:404"}}
	if !slices.Equal(got, want) {
		t.Fatalf("config.yml: %+v", got)
	}
	if got := yamlRules(readFixture(t, "legacy.yml")); !slices.Equal(got, []tunnelRule{{"share.example.net", "http://[::1]:8443"}}) {
		t.Fatalf("legacy.yml: %+v", got)
	}
	if got := yamlRules(readFixture(t, "other.yml")); !slices.Equal(got, []tunnelRule{{"wiki.example.org", "http://localhost:8080"}, {"", "http_status:404"}}) {
		t.Fatalf("other.yml: %+v", got)
	}
}

func TestCloudflaredExposure(t *testing.T) {
	cfg := readFixture(t, "config.yml")
	local := func(h string) bool { return h == "192.168.1.10" || h == "fileparcel.local" }
	cases := []struct {
		name     string
		in       cloudflaredInput
		severity string
		msg      string
	}{
		{"not running", cloudflaredInput{configs: [][]byte{cfg}, port: 8443}, "", ""},
		{"config", cloudflaredInput{running: true, configs: [][]byte{cfg}, port: 8443}, "warn", "forwards files.example.org to FileParcel"},
		{"legacy url", cloudflaredInput{running: true, configs: [][]byte{readFixture(t, "legacy.yml")}, port: 8443}, "warn", "share.example.net"},
		{"other port", cloudflaredInput{running: true, configs: [][]byte{cfg}, port: 9443}, "", ""},
		{"other service", cloudflaredInput{running: true, configs: [][]byte{readFixture(t, "other.yml")}, port: 8443}, "", ""},
		{"quick tunnel", cloudflaredInput{running: true, cmdlines: [][]string{{"cloudflared", "tunnel", "--url", "https://localhost:8443"}}, port: 8443},
			"warn", "forwards a public hostname"},
		{"url=", cloudflaredInput{running: true, cmdlines: [][]string{{"/usr/bin/cloudflared", "--url=http://127.0.0.1:8443"}}, port: 8443}, "warn", "127.0.0.1"},
		{"other url", cloudflaredInput{running: true, cmdlines: [][]string{{"cloudflared", "--url", "http://localhost:8080"}}, port: 8443}, "", ""},
		{"token tunnel", cloudflaredInput{running: true, cmdlines: [][]string{{"cloudflared", "tunnel", "run", "--token", "eyJ…"}}, port: 8443},
			"info", "without a local configuration"},
		// A --config file that could not be read proves nothing: info, like a token tunnel.
		{"unread config flag", cloudflaredInput{running: true, cmdlines: [][]string{{"cloudflared", "--config", "/srv/cf.yml", "tunnel", "run"}}, port: 8443},
			"info", "without a local configuration"},
		// A read configuration without FileParcel's origin: nothing.
		{"read other config", cloudflaredInput{running: true, configs: [][]byte{readFixture(t, "other.yml")},
			cmdlines: [][]string{{"cloudflared", "tunnel", "--config", "/srv/cf.yml", "run"}}, port: 8443}, "", ""},
		// The origin is this machine's LAN address or .local name.
		{"lan origin", cloudflaredInput{running: true, local: local,
			configs: [][]byte{[]byte("ingress:\n  - hostname: files.example.org\n    service: https://192.168.1.10:8443\n  - service: http_status:404\n")},
			port:    8443}, "warn", "forwards files.example.org to FileParcel"},
		{".local origin", cloudflaredInput{running: true, local: local,
			cmdlines: [][]string{{"cloudflared", "tunnel", "--url", "https://FileParcel.local:8443/"}}, port: 8443}, "warn", "a public hostname"},
		{"another machine", cloudflaredInput{running: true, local: local,
			configs: [][]byte{[]byte("ingress:\n  - hostname: files.example.org\n    service: https://192.168.1.7:8443\n")}, port: 8443}, "", ""},
		{"default https port", cloudflaredInput{running: true, local: local,
			cmdlines: [][]string{{"cloudflared", "--url", "https://localhost"}}, port: 443}, "warn", "a public hostname"},
		{"not http", cloudflaredInput{running: true, local: local,
			cmdlines: [][]string{{"cloudflared", "--url", "tcp://localhost:8443"}}, port: 8443}, "", ""},
	}
	for _, c := range cases {
		e := cloudflaredExposure(c.in)
		switch {
		case c.severity == "" && e != nil:
			t.Errorf("%s: unexpected %+v", c.name, e)
		case c.severity != "" && (e == nil || e.Severity != c.severity || e.ID != ExposureCloudflared ||
			!strings.Contains(e.Message, c.msg) || !strings.Contains(e.Hint, "server.trusted_proxies")):
			t.Errorf("%s: %+v", c.name, e)
		}
	}
	if e := cloudflaredExposure(cloudflaredInput{running: true, configs: [][]byte{cfg, readFixture(t, "legacy.yml")}, port: 8443}); e == nil ||
		!strings.Contains(e.Message, "files.example.org, share.example.net to FileParcel") {
		t.Fatalf("two configs: %+v", e)
	}
}

func TestConfigArgs(t *testing.T) {
	got := configArgs([]string{"cloudflared", "tunnel", "--config", "/srv/a.yml", "run", "--config=/srv/b.yml", "--config"})
	if !slices.Equal(got, []string{"/srv/a.yml", "/srv/b.yml"}) {
		t.Fatalf("%v", got)
	}
}

func TestTailscaleExposures(t *testing.T) {
	if e := tailscaleExposures(nil); e == nil || len(e) != 0 {
		t.Fatal(e)
	}
	if e := tailscaleExposures(&core.TailscaleInfo{Running: false, Userspace: true, ShieldsUp: true}); len(e) != 0 {
		t.Fatal(e)
	}
	e := tailscaleExposures(&core.TailscaleInfo{Running: true, Userspace: true, ShieldsUp: true})
	if len(e) != 2 || e[0].ID != ExposureUserspace || e[0].Severity != "warn" || !strings.Contains(e[0].Hint, "network tailscale-serve enable") ||
		e[1].ID != ExposureShieldsUp || e[1].Severity != "info" {
		t.Fatalf("%+v", e)
	}
}

func TestServiceExposures(t *testing.T) {
	env, _ := testEnv(t)
	s := newTestService(t, env, &fakeSource{list: hostList()}, "")
	calls := 0
	var gotPort int
	s.cloudflared = func(_ context.Context, port int, local func(string) bool) *core.Exposure {
		if local == nil || !local("localhost") || local("192.0.2.1") {
			t.Error("local host predicate")
		}
		calls++
		gotPort = port
		return &core.Exposure{ID: ExposureCloudflared, Severity: "warn", Message: "Cloudflare Tunnel forwards x to FileParcel"}
	}
	ctx := context.Background()
	for range 3 {
		if e := s.Exposures(ctx); len(e) != 1 || e[0].ID != ExposureCloudflared {
			t.Fatalf("%+v", e)
		}
	}
	if calls != 1 || gotPort != 8443 {
		t.Fatalf("calls %d port %d", calls, gotPort)
	}
	// Loopback as a trusted proxy: the tunnel's visitors are seen, no finding.
	if _, err := env.Settings.Set(ctx, nil, map[string]json.RawMessage{"server.trusted_proxies": json.RawMessage(`["127.0.0.1","::1"]`)}); err != nil {
		t.Fatal(err)
	}
	if e := s.Exposures(ctx); len(e) != 0 {
		t.Fatalf("with trusted loopback: %+v", e)
	}
	if !loopbackTrusted([]string{"10.0.0.0/8", "::1/128"}) || loopbackTrusted([]string{"10.0.0.1"}) || loopbackTrusted(nil) {
		t.Fatal("loopbackTrusted")
	}
}

func TestProbeHelpers(t *testing.T) {
	dir := t.TempDir()
	mk := func(p, content string) {
		t.Helper()
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	tinc := filepath.Join(dir, "tinc")
	mk(filepath.Join(tinc, "home", "tinc.conf"), "Name = alpha\nConnectTo = beta\n")
	mk(filepath.Join(tinc, "office", "tinc.conf"), "Name = alpha\n  interface=tun-office\n")
	mk(filepath.Join(tinc, "broken", "hosts", "x"), "")
	if got := tincInterfaces([]string{tinc, filepath.Join(dir, "missing")}); !slices.Equal(got, []string{"home", "tun-office"}) {
		t.Fatalf("tinc %v", got)
	}
	inner := filepath.Join(dir, "innernet")
	mk(filepath.Join(inner, "corpnet.conf"), "[interface]\n")
	mk(filepath.Join(inner, "notes.txt"), "")
	if err := os.MkdirAll(filepath.Join(inner, "dir.conf"), 0o755); err != nil {
		t.Fatal(err)
	}
	if got := innernetInterfaces([]string{inner}); !slices.Equal(got, []string{"corpnet"}) {
		t.Fatalf("innernet %v", got)
	}
	if !lookBinary("sh") || lookBinary("fileparcel-no-such-binary") || lookBinary("../sh") || lookBinary("") {
		t.Fatal("lookBinary")
	}
	now := time.Unix(1000, 0)
	bc := &binaryCache{now: func() time.Time { return now }, found: map[string]binaryEntry{}}
	bc.found["twingate"] = binaryEntry{ok: true, at: now}
	if !bc.has("twingate") { // cached answer
		t.Fatal("cache")
	}
	now = now.Add(binaryTTL)
	if bc.has("twingate") { // expired: looked up again (not installed here)
		t.Fatal("expiry")
	}
	n := 0
	v := &ttlValue[int]{ttl: time.Minute, fetch: func() int { n++; return n }, now: func() time.Time { return now }}
	first := v.get()
	if second := v.get(); first != 1 || second != 1 {
		t.Fatalf("ttlValue %d %d", first, second)
	}
	now = now.Add(time.Minute)
	if v.get() != 2 {
		t.Fatal("ttlValue expiry")
	}
	big := filepath.Join(dir, "big")
	mk(big, strings.Repeat("x", 100))
	if _, ok := readSmall(big, 99); ok {
		t.Fatal("readSmall limit")
	}
	if b, ok := readSmall(big, 100); !ok || len(b) != 100 {
		t.Fatal("readSmall")
	}
	if _, ok := readSmall(dir, 100); ok {
		t.Fatal("readSmall dir")
	}
}
