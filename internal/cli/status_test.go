package cli

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"fileparcel/internal/config"
	"fileparcel/internal/core"
	"fileparcel/internal/svc"
)

func TestStatusOffline(t *testing.T) {
	lcIsolateHost(t)
	h, _ := lcInitTestHome(t)
	if err := os.WriteFile(h.VersionFile(), []byte("v7 abc1234 2026-09-19\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	r := lcRun(t, "", "--json", "status", "--home", h.Dir())
	var rep lcStatusReport
	if r.code != 0 || json.Unmarshal([]byte(r.out), &rep) != nil {
		t.Fatalf("status --json: %d %s %s", r.code, r.out, r.err)
	}
	if rep.Running || rep.Home != h.Dir() || !rep.KeysFile || rep.HTTPSPort == 0 || rep.HomeLocked ||
		rep.InstalledVersion != "v7 abc1234 2026-09-19" || rep.Service != nil || rep.System != nil {
		t.Fatalf("offline report %+v", rep)
	}

	r = lcRun(t, "", "status", "--home", h.Dir())
	for _, frag := range []string{"Server:", "not running", "Installed:", "v7 abc1234", "Ports:", "HTTPS", "Service:", "none registered", "CLI version:"} {
		if !strings.Contains(r.out, frag) {
			t.Errorf("human status lacks %q:\n%s", frag, r.out)
		}
	}

	// Lock held without a socket, a failed restore and a missing key file → notes.
	unlock, err := h.Lock()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(h.RestoreFile()+".failed", []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(h.KeysFile(), h.KeysFile()+".bak"); err != nil {
		t.Fatal(err)
	}
	r = lcRun(t, "", "--json", "status", "--home", h.Dir())
	unlock()
	rep = lcStatusReport{}
	if r.code != 0 || json.Unmarshal([]byte(r.out), &rep) != nil || !rep.HomeLocked || rep.KeysFile || !rep.RestoreFailed ||
		len(rep.Notes) != 3 {
		t.Fatalf("notes: %d %+v", r.code, rep)
	}

	r = lcRun(t, "", "status", "--home", t.TempDir())
	if r.code != ExitFailure || !strings.Contains(r.err, "not a FileParcel home") {
		t.Fatalf("non-home: %d %s", r.code, r.err)
	}
}

func TestStatusRemote(t *testing.T) {
	lcIsolateHost(t)
	sys := map[string]any{
		"version": "v9", "commit": "0123456789abcdef", "home": "/srv/fp", "pid": 42, "uptime_seconds": 3700,
		"keys_state": "unlocked", "key_mode": "plain", "db_bytes": 2048, "blobs_bytes": 1 << 20, "blob_count": 3,
		"disk_free_bytes": int64(10 << 30), "disk_size_bytes": int64(20 << 30), "restart_required": []string{"server.https_port"},
		"supervisor": "systemd", "mode": "network",
		"certs":   map[string]any{"leaf": map[string]any{"not_after": time.Date(2027, 1, 2, 0, 0, 0, 0, time.UTC)}, "ca": map[string]any{"fingerprint": "AA:BB"}},
		"mdns":    map[string]any{"state": "published", "name": "fileparcel.local"},
		"network": map[string]any{"policy": map[string]any{"mode": "allowlist"}, "urls": []map[string]any{{"url": "https://fileparcel.local:8443/", "recommended": true}}},
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/admin/system" || r.Header.Get("Authorization") != "Bearer fpt_ok" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte(`{"error":{"code":"forbidden","message":"admin only"}}`))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(sys)
	}))
	defer srv.Close()
	t.Setenv(TokenEnv, "")

	r := lcRun(t, "", "--server", srv.URL, "--token", "fpt_ok", "status")
	if r.code != 0 {
		t.Fatalf("remote status: %d %s", r.code, r.err)
	}
	for _, frag := range []string{"running (pid 42, up 1h1m", "systemd)", "v9 (0123456789ab)", "unlocked (plain master key)",
		"allowlist", "https://fileparcel.local:8443/  (recommended)", "valid until 2027-01-0", "AA:BB", "published fileparcel.local",
		"3 blobs", "free of", "server.https_port", "Server URL:"} {
		if !strings.Contains(r.out, frag) {
			t.Errorf("remote status lacks %q:\n%s", frag, r.out)
		}
	}
	r = lcRun(t, "", "--server", srv.URL, "--token", "fpt_ok", "--json", "status")
	var rep map[string]any
	if r.code != 0 || json.Unmarshal([]byte(r.out), &rep) != nil || rep["running"] != true || rep["transport"] != ModeRemote {
		t.Fatalf("remote --json: %d %s", r.code, r.out)
	}
	if s, ok := rep["system"].(map[string]any); !ok || s["blob_count"] != float64(3) {
		t.Fatalf("raw system object not passed through: %v", rep["system"])
	}
	r = lcRun(t, "", "--server", srv.URL, "--token", "bad", "status")
	if r.code != ExitFailure || !strings.Contains(r.err, "admin only") {
		t.Fatalf("remote forbidden: %d %s", r.code, r.err)
	}

	// --token-file keeps the token out of the process list: first line,
	// whitespace trimmed; a group/world-readable file is warned about.
	dir := t.TempDir()
	tokFile := filepath.Join(dir, "token")
	if err := os.WriteFile(tokFile, []byte("fpt_ok \n"), 0o600); err != nil {
		t.Fatal(err)
	}
	r = lcRun(t, "", "--server", srv.URL, "--token-file", tokFile, "status")
	if r.code != 0 || !strings.Contains(r.out, "3 blobs") || strings.Contains(r.err, "readable") {
		t.Fatalf("--token-file: %d %s", r.code, r.err)
	}
	// It wins over $FILEPARCEL_TOKEN, like --token.
	t.Setenv(TokenEnv, "bad")
	if r = lcRun(t, "", "--server", srv.URL, "--token-file", tokFile, "status"); r.code != 0 {
		t.Fatalf("--token-file with $%s set: %d %s", TokenEnv, r.code, r.err)
	}
	t.Setenv(TokenEnv, "")
	if err := os.Chmod(tokFile, 0o644); err != nil {
		t.Fatal(err)
	}
	if r = lcRun(t, "", "--server", srv.URL, "--token-file", tokFile, "status"); r.code != 0 ||
		!strings.Contains(r.err, "readable by other users") {
		t.Fatalf("--token-file 0644: %d %s", r.code, r.err)
	}
	r = lcRun(t, "", "--server", srv.URL, "--token", "fpt_ok", "--token-file", tokFile, "status")
	if r.code != ExitUsage || !strings.Contains(r.err, "only one of --token and --token-file") {
		t.Fatalf("--token with --token-file: %d %s", r.code, r.err)
	}
	empty := filepath.Join(dir, "empty")
	if err := os.WriteFile(empty, []byte(" \n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{empty, filepath.Join(dir, "missing")} {
		if r = lcRun(t, "", "--server", srv.URL, "--token-file", f, "status"); r.code != ExitUsage ||
			!strings.Contains(r.err, "--token-file") {
			t.Fatalf("--token-file %s: %d %s", f, r.code, r.err)
		}
	}
}

func TestRenderStatusService(t *testing.T) {
	NewRootCmd()
	t.Setenv("NO_COLOR", "1")
	rep := &lcStatusReport{Home: "/h", CLIVersion: "dev", KeysFile: true, RestorePending: true,
		LastCleanShutdown: ptrTime(time.Now().Add(-time.Hour)),
		Service:           &svc.Status{Kind: svc.KindSystemdUser, State: "inactive", Installed: true, Enabled: true}}
	var b bytes.Buffer
	if err := lcRenderStatus(&b, rep); err != nil {
		t.Fatal(err)
	}
	for _, frag := range []string{"not running", "pending (applied at the next start)", "Last clean stop:",
		"systemd user service: inactive, starts at boot", "Start it with: fileparcel service start"} {
		if !strings.Contains(b.String(), frag) {
			t.Errorf("lacks %q:\n%s", frag, b.String())
		}
	}
	if lcFirstLine("/nonexistent/VERSION") != "" {
		t.Fatal("lcFirstLine of a missing file")
	}
	_ = core.KeyStateLocked
}

func ptrTime(t time.Time) *time.Time { return &t }

// Extra access URLs are continuation rows: aligned under the value column,
// with no bare ":" at the start of the line.
func TestRenderStatusURLContinuation(t *testing.T) {
	NewRootCmd()
	t.Setenv("NO_COLOR", "1")
	var sys lcSystem
	raw := `{"version":"v9","home":"/srv/fp","keys_state":"unlocked","network":{"policy":{"mode":"any"},
	  "urls":[{"url":"https://a.local:8443/","recommended":true},{"url":"https://192.168.1.10:8443/"},
	          {"url":"https://[2001:db8::1]:8443/"}]}}`
	if err := json.Unmarshal([]byte(raw), &sys); err != nil {
		t.Fatal(err)
	}
	var b bytes.Buffer
	if err := lcRenderStatus(&b, &lcStatusReport{CLIVersion: "dev", sys: &sys}); err != nil {
		t.Fatal(err)
	}
	out := b.String()
	var urlLines []string
	for _, line := range strings.Split(out, "\n") {
		if strings.Contains(line, "https://") {
			urlLines = append(urlLines, line)
		}
		if strings.HasPrefix(line, ":") {
			t.Errorf("continuation row printed a bare colon:\n%s", out)
		}
	}
	if len(urlLines) != 3 {
		t.Fatalf("want 3 URL lines, got %d:\n%s", len(urlLines), out)
	}
	if !strings.HasPrefix(urlLines[0], "URLs:") {
		t.Errorf("first URL row lacks its key: %q", urlLines[0])
	}
	col := strings.Index(urlLines[0], "https://")
	for _, l := range urlLines[1:] {
		if strings.Index(l, "https://") != col || strings.TrimSpace(l[:col]) != "" {
			t.Errorf("continuation row not aligned under the value column (%d): %q", col, l)
		}
	}
}

// A server that could not read its database flags the blob figures
// (stats_unavailable): they are zeros from the failed read, so status must
// not print them as an empty store.
func TestRenderStatusStatsUnavailable(t *testing.T) {
	NewRootCmd()
	t.Setenv("NO_COLOR", "1")
	render := func(raw string) string {
		t.Helper()
		var sys lcSystem
		if err := json.Unmarshal([]byte(raw), &sys); err != nil {
			t.Fatal(err)
		}
		var b bytes.Buffer
		if err := lcRenderStatus(&b, &lcStatusReport{CLIVersion: "dev", sys: &sys}); err != nil {
			t.Fatal(err)
		}
		return b.String()
	}
	base := `{"version":"v9","home":"/srv/fp","keys_state":"unlocked","db_bytes":1048576,"blobs_bytes":0,"blob_count":0`
	out := render(base + `,"stats_unavailable":true}`)
	if !strings.Contains(out, "database 1.0 MiB; file data unknown") || strings.Contains(out, "in 0 blobs") {
		t.Errorf("stats_unavailable printed as facts:\n%s", out)
	}
	out = render(base + `}`)
	if !strings.Contains(out, "database 1.0 MiB, 0 B in 0 blobs") {
		t.Errorf("a readable empty store is not shown:\n%s", out)
	}
}

// With admin_socket.enabled = false nothing ever answers on the socket, so
// a held home lock is the running server, not a hang: status says running
// (and does not suggest starting it), and other commands say why they
// cannot reach it.
func TestStatusAdminSocketDisabled(t *testing.T) {
	lcIsolateHost(t)
	h, _ := lcInitTestHome(t)
	unlock, err := h.Lock() // stands in for the running server
	if err != nil {
		t.Fatal(err)
	}
	defer unlock()
	status := func() lcStatusReport {
		t.Helper()
		r := lcRun(t, "", "--json", "status", "--home", h.Dir())
		var rep lcStatusReport
		if r.code != 0 || json.Unmarshal([]byte(r.out), &rep) != nil {
			t.Fatalf("status --json: %d %s %s", r.code, r.out, r.err)
		}
		return rep
	}
	hangs := func(rep lcStatusReport) bool {
		return strings.Contains(strings.Join(rep.Notes, "\n"), "server hangs")
	}
	if rep := status(); rep.Running || !rep.HomeLocked || !hangs(rep) {
		t.Fatalf("socket enabled, lock held: %+v", rep)
	}

	cfg, err := config.Load(h)
	if err != nil {
		t.Fatal(err)
	}
	cfg.AdminSocket.Enabled = false
	if err := cfg.Save(); err != nil {
		t.Fatal(err)
	}
	rep := status()
	if !rep.Running || !rep.HomeLocked || hangs(rep) || !strings.Contains(strings.Join(rep.Notes, "\n"), "admin_socket.enabled = false") {
		t.Fatalf("socket disabled: %+v", rep)
	}
	var out bytes.Buffer
	rep.Service = &svc.Status{Kind: svc.KindSystemdUser, Installed: true, Active: true, State: "active"}
	if err := lcRenderStatus(&out, &rep); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "running") || strings.Contains(out.String(), "not running") ||
		strings.Contains(out.String(), "Start it with") {
		t.Fatalf("human status:\n%s", out.String())
	}
	if _, err := Connect(Options{Home: h.Dir()}); err == nil || !strings.Contains(err.Error(), "admin socket is disabled") {
		t.Fatalf("Connect: %v", err)
	}
}

// Maintenance mode is easy to forget (administrators keep working through
// it): status says it is on, and nothing while it is off.
func TestRenderStatusMaintenance(t *testing.T) {
	NewRootCmd()
	t.Setenv("NO_COLOR", "1")
	render := func(raw string) string {
		t.Helper()
		var sys lcSystem
		if err := json.Unmarshal([]byte(raw), &sys); err != nil {
			t.Fatal(err)
		}
		var b bytes.Buffer
		if err := lcRenderStatus(&b, &lcStatusReport{CLIVersion: "dev", sys: &sys}); err != nil {
			t.Fatal(err)
		}
		return b.String()
	}
	out := render(`{"version":"v9","home":"/srv/fp","keys_state":"unlocked","maintenance":true}`)
	if !strings.Contains(out, "Maintenance:") || !strings.Contains(out, "fileparcel maintenance off") {
		t.Errorf("maintenance on is not shown:\n%s", out)
	}
	if out := render(`{"version":"v9","home":"/srv/fp","keys_state":"unlocked"}`); strings.Contains(out, "Maintenance") {
		t.Errorf("maintenance shown while off:\n%s", out)
	}
}
