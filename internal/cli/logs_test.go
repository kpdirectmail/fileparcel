package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"fileparcel/internal/config"
	"fileparcel/internal/home"
	"fileparcel/internal/svc"
)

// lcBareHome creates a minimal home (layout + fileparcel.toml, no keys,
// certificates or database) for commands that only look at files.
func lcBareHome(t *testing.T) *home.Home {
	t.Helper()
	h, err := home.New(filepath.Join(t.TempDir(), "fp"))
	if err != nil {
		t.Fatal(err)
	}
	if err := h.EnsureLayout(); err != nil {
		t.Fatal(err)
	}
	cfg := config.Default(config.NewInstallID())
	cfg.Server.HTTPSPort, cfg.Server.HTTPPort = lcFreePort(t), lcFreePort(t)
	for cfg.Server.HTTPPort == cfg.Server.HTTPSPort {
		cfg.Server.HTTPPort = lcFreePort(t)
	}
	if err := cfg.SaveTo(h.Config()); err != nil {
		t.Fatal(err)
	}
	return h
}

// lcIsolateHost points $HOME (and so the svc registration paths: systemd
// user units, LaunchAgents, the default symlink) at a temp dir, so tests
// never look at or touch the real user's service registrations.
func lcIsolateHost(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	t.Setenv("XDG_CONFIG_HOME", "")
	t.Setenv("XDG_DATA_HOME", "")
	t.Setenv("FILEPARCEL_HOME", "")
	t.Setenv("NO_COLOR", "1")
	return dir
}

func lcWriteLines(t *testing.T, path string, from, to int) {
	t.Helper()
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	for i := from; i <= to; i++ {
		fmt.Fprintf(f, "line %d\n", i)
	}
}

func TestTailFile(t *testing.T) {
	p := filepath.Join(t.TempDir(), "x.log")
	if _, err := lcTailFile(p, 5); err == nil {
		t.Fatal("missing file accepted")
	}
	if err := os.WriteFile(p, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if got, err := lcTailFile(p, 5); err != nil || len(got) != 0 {
		t.Fatalf("empty file: %v %v", got, err)
	}
	lcWriteLines(t, p, 1, 10)
	cases := []struct {
		n    int
		want string
	}{
		{0, ""},
		{1, "line 10"},
		{3, "line 8|line 9|line 10"},
		{50, "line 1|line 2|line 3|line 4|line 5|line 6|line 7|line 8|line 9|line 10"},
	}
	for _, c := range cases {
		got, err := lcTailFile(p, c.n)
		if err != nil || strings.Join(got, "|") != c.want {
			t.Errorf("n=%d: %q %v", c.n, got, err)
		}
	}
}

func TestTailFileLarge(t *testing.T) {
	// Only the last lcLogScan bytes are read and the partial first line is dropped.
	p := filepath.Join(t.TempDir(), "big.log")
	line := strings.Repeat("x", 1023) + "\n"
	f, err := os.Create(p)
	if err != nil {
		t.Fatal(err)
	}
	n := lcLogScan/len(line) + 10
	for i := 0; i < n; i++ {
		if _, err := f.WriteString(line); err != nil {
			t.Fatal(err)
		}
	}
	fmt.Fprintf(f, "the end\n")
	f.Close()
	got, err := lcTailFile(p, lcMaxLogLines)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) == 0 || got[len(got)-1] != "the end" || len(got[0]) != 1023 {
		t.Fatalf("got %d lines, first %d bytes, last %q", len(got), len(got[0]), got[len(got)-1])
	}
	if len(got) > lcLogScan/len(line)+1 {
		t.Fatalf("read more than the scan window: %d lines", len(got))
	}
}

func TestCleanLogLine(t *testing.T) {
	cases := map[string]string{
		"plain":                       "plain",
		"tab\tkept":                   "tab\tkept",
		"esc \x1b[31mred\x1b[0m":      "esc [31mred[0m",
		"bell\a del\x7f c1\u009b end": "bell del c1 end",
		"ümlaut ✓":                    "ümlaut ✓",
	}
	for in, want := range cases {
		if got := lcCleanLogLine(in); got != want {
			t.Errorf("%q → %q, want %q", in, got, want)
		}
	}
}

func TestFollowRotationAndTruncation(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "fileparcel.log")
	lcWriteLines(t, p, 1, 3)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	out := &lcSyncBuffer{}
	done := make(chan error, 1)
	go func() { done <- lcFollow(ctx, p, out, lcWriteLogLine, 10*time.Millisecond) }()

	waitFor := func(want string) {
		t.Helper()
		deadline := time.Now().Add(10 * time.Second)
		for !strings.Contains(out.String(), want) {
			if time.Now().After(deadline) {
				cancel()
				t.Fatalf("timed out waiting for %q; got:\n%s", want, out.String())
			}
			time.Sleep(5 * time.Millisecond)
		}
	}
	// Wait until lcFollow has seeked to the end: append probes until one shows.
	for i := 0; !strings.Contains(out.String(), "probe"); i++ {
		if i > 500 {
			t.Fatal("lcFollow never printed an appended line")
		}
		f, _ := os.OpenFile(p, os.O_WRONLY|os.O_APPEND, 0)
		fmt.Fprintf(f, "probe %d\n", i)
		f.Close()
		time.Sleep(20 * time.Millisecond)
	}
	lcWriteLines(t, p, 4, 5)
	waitFor("line 5\n")

	// A partial line is held back until its newline arrives.
	f, _ := os.OpenFile(p, os.O_WRONLY|os.O_APPEND, 0)
	f.WriteString("part")
	f.Close()
	time.Sleep(50 * time.Millisecond)
	if strings.Contains(out.String(), "part") {
		t.Fatal("partial line printed early")
	}
	f, _ = os.OpenFile(p, os.O_WRONLY|os.O_APPEND, 0)
	f.WriteString("ial \x1b[2Jline\n")
	f.Close()
	waitFor("partial [2Jline\n")

	// Rotation: the old file is renamed, a new one appears at the path.
	lcWriteLines(t, p, 6, 6)
	if err := os.Rename(p, p+".1"); err != nil {
		t.Fatal(err)
	}
	lcWriteLines(t, p, 7, 8)
	waitFor("line 8\n")

	// Truncation: start over at the beginning.
	if err := os.WriteFile(p, []byte("fresh 1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	waitFor("fresh 1\n")

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("lcFollow did not stop")
	}
	got := out.String()
	for _, l := range []string{"line 1\n", "line 2\n", "line 3\n"} {
		if strings.Contains(got, l) {
			t.Errorf("follow printed old content %q", l)
		}
	}
	if !strings.Contains(got, "line 6\n") || strings.Count(got, "line 7\n") != 1 {
		t.Errorf("rotation lost or repeated lines:\n%s", got)
	}
	if strings.Index(got, "line 4") > strings.Index(got, "line 8") {
		t.Errorf("out of order:\n%s", got)
	}
}

func TestLogsCommand(t *testing.T) {
	h := lcBareHome(t)

	// No log file yet.
	r := lcRun(t, "", "logs", "--home", h.Dir())
	if r.code != ExitFailure || !strings.Contains(r.err, "has not written a log yet") {
		t.Fatalf("missing log: %d %s", r.code, r.err)
	}
	// File logging disabled: point at the service manager.
	cfg, err := config.Load(h)
	if err != nil {
		t.Fatal(err)
	}
	cfg.Log.File = false
	if err := cfg.Save(); err != nil {
		t.Fatal(err)
	}
	r = lcRun(t, "", "logs", "--home", h.Dir())
	if r.code != ExitFailure || !strings.Contains(r.err, "log.file = false") || !strings.Contains(r.err, "standard error") {
		t.Fatalf("log.file=false, no service: %d %s", r.code, r.err)
	}
	// A system unit's journal is not the --user one.
	if err := svc.WriteInstalled(h, &svc.Installed{Kind: svc.KindSystemdSystem, Home: h.Dir()}); err != nil {
		t.Fatal(err)
	}
	r = lcRun(t, "", "logs", "--home", h.Dir())
	if r.code != ExitFailure || !strings.Contains(r.err, "journalctl -u fileparcel") || strings.Contains(r.err, "--user") {
		t.Fatalf("log.file=false, system unit: %d %s", r.code, r.err)
	}
	if err := os.Remove(svc.InstalledPath(h)); err != nil {
		t.Fatal(err)
	}

	lcWriteLines(t, h.LogFile(), 1, 300)
	r = lcRun(t, "", "logs", "--home", h.Dir())
	if r.code != 0 || strings.Count(r.out, "\n") != 200 || !strings.HasPrefix(r.out, "line 101\n") {
		t.Fatalf("default -n 200: %d lines, starts %q", strings.Count(r.out, "\n"), r.out[:min(20, len(r.out))])
	}
	r = lcRun(t, "", "logs", "--home", h.Dir(), "-n", "2")
	if r.code != 0 || r.out != "line 299\nline 300\n" {
		t.Fatalf("-n 2: %q", r.out)
	}
	r = lcRun(t, "", "logs", "--home", h.Dir(), "-n", "0")
	if r.code != 0 || r.out != "" {
		t.Fatalf("-n 0: %q", r.out)
	}
	// Nothing to show is an empty list in JSON, not null (jq '.lines[]').
	r = lcRun(t, "", "--json", "logs", "--home", h.Dir(), "-n", "0")
	if r.code != 0 || !strings.Contains(r.out, `"lines": []`) {
		t.Fatalf("--json -n 0: %d %s", r.code, r.out)
	}
	r = lcRun(t, "", "--json", "logs", "--home", h.Dir(), "-n", "1")
	var js struct {
		File  string   `json:"file"`
		Lines []string `json:"lines"`
	}
	if r.code != 0 || json.Unmarshal([]byte(r.out), &js) != nil || js.File != h.LogFile() ||
		strings.Join(js.Lines, ",") != "line 300" {
		t.Fatalf("--json: %d %s", r.code, r.out)
	}

	// Just rotated: an empty file.
	empty := lcBareHome(t)
	if err := os.WriteFile(empty.LogFile(), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	r = lcRun(t, "", "--json", "logs", "--home", empty.Dir())
	if r.code != 0 || !strings.Contains(r.out, `"lines": []`) {
		t.Fatalf("--json on an empty log: %d %s", r.code, r.out)
	}

	// -f follows until the context ends.
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	r = lcRunCtx(t, ctx, "", "logs", "--home", h.Dir(), "-n", "1", "-f")
	if r.code != 0 || !strings.HasPrefix(r.out, "line 300\n") {
		t.Fatalf("-f: %d %q %s", r.code, r.out, r.err)
	}

	// --json with -f: one JSON object per line, so the stream stays parseable.
	jctx, jcancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer jcancel()
	r = lcRunCtx(t, jctx, "", "--json", "logs", "--home", h.Dir(), "-n", "2", "-f")
	if r.code != 0 {
		t.Fatalf("--json -f: %d %s", r.code, r.err)
	}
	var followed []string
	for _, l := range strings.Split(strings.TrimRight(r.out, "\n"), "\n") {
		var rec struct {
			Line string `json:"line"`
		}
		if err := json.Unmarshal([]byte(l), &rec); err != nil {
			t.Fatalf("--json -f line %q is not JSON: %v", l, err)
		}
		followed = append(followed, rec.Line)
	}
	if strings.Join(followed, "|") != "line 299|line 300" {
		t.Fatalf("--json -f lines: %q", followed)
	}

	// Not a home.
	r = lcRun(t, "", "logs", "--home", t.TempDir())
	if r.code != ExitFailure || !strings.Contains(r.err, "not a FileParcel home") {
		t.Fatalf("non-home: %d %s", r.code, r.err)
	}
}

func TestLogsRemote(t *testing.T) {
	var gotN string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/admin/system/logs" || r.Header.Get("Authorization") != "Bearer fpt_test" {
			http.Error(w, `{"error":{"code":"not_found","message":"nope"}}`, http.StatusNotFound)
			return
		}
		gotN = r.URL.Query().Get("n")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"file":"/srv/fp/logs/fileparcel.log","lines":["a","b \u001b[1mbold"],"truncated":false}`))
	}))
	defer srv.Close()
	t.Setenv(TokenEnv, "")
	r := lcRun(t, "", "--server", srv.URL, "--token", "fpt_test", "logs", "-n", "2")
	if r.code != 0 || gotN != "2" || r.out != "a\nb [1mbold\n" {
		t.Fatalf("remote logs: %d n=%s %q %s", r.code, gotN, r.out, r.err)
	}
	r = lcRun(t, "", "--server", srv.URL, "--token", "fpt_test", "--json", "logs", "-n", "5")
	if r.code != 0 || !strings.Contains(r.out, `"file": "/srv/fp/logs/fileparcel.log"`) {
		t.Fatalf("remote --json: %d %s", r.code, r.out)
	}
	r = lcRun(t, "", "--server", srv.URL, "--token", "fpt_test", "--json", "logs", "-n", "0")
	if r.code != 0 || !strings.Contains(r.out, `"lines": []`) || strings.Contains(r.out, "null") {
		t.Fatalf("remote --json -n 0: %d %s", r.code, r.out)
	}
	r = lcRun(t, "", "--server", srv.URL, "--token", "fpt_test", "logs", "-f")
	if r.code != ExitUsage || !strings.Contains(r.err, "-f is not available") {
		t.Fatalf("remote -f: %d %s", r.code, r.err)
	}
	r = lcRun(t, "", "--server", srv.URL, "--token", "wrong", "logs")
	if r.code != ExitFailure {
		t.Fatalf("remote error: %d %s", r.code, r.err)
	}
}

func TestServiceLogHint(t *testing.T) {
	for _, tc := range []struct {
		kind      svc.Kind
		want, not string
	}{
		{svc.KindSystemdUser, "journalctl --user -u fileparcel", ""},
		{svc.KindSystemdSystem, "journalctl -u fileparcel", "--user"},
		{svc.KindLaunchdAgent, filepath.Join("/srv/fp", "logs", "launchd.err.log"), "journalctl"},
		{svc.KindLaunchdDaemon, filepath.Join("/srv/fp", "logs", "launchd.err.log"), "journalctl"},
		{svc.KindNone, "standard error", "journalctl"},
		{"", "standard error", "journalctl"},
	} {
		got := lcServiceLogHint(tc.kind, "/srv/fp")
		if !strings.Contains(got, tc.want) || (tc.not != "" && strings.Contains(got, tc.not)) {
			t.Errorf("%q: %q", tc.kind, got)
		}
	}
}

// A missing log file or file logging turned off on the server is explained,
// as for the local log, instead of printing an empty (or stale) tail.
func TestLogsRemoteExplainsMissingLog(t *testing.T) {
	body := ""
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(body))
	}))
	defer srv.Close()
	t.Setenv(TokenEnv, "")
	run := func() lcResult {
		t.Helper()
		return lcRun(t, "", "--server", srv.URL, "--token", "fpt_test", "logs")
	}
	body = `{"file":"logs/fileparcel.log","lines":[],"truncated":false,"missing":true,"file_logging":false}`
	if r := run(); r.code != ExitFailure || !strings.Contains(r.err, "log.file = false") {
		t.Fatalf("file logging off: %d %q %s", r.code, r.out, r.err)
	}
	body = `{"file":"logs/fileparcel.log","lines":[],"truncated":false,"missing":true,"file_logging":true}`
	if r := run(); r.code != ExitFailure || !strings.Contains(r.err, "has not written a log yet") {
		t.Fatalf("no log yet: %d %q %s", r.code, r.out, r.err)
	}
	body = `{"file":"logs/fileparcel.log","lines":["old"],"truncated":false,"missing":false,"file_logging":false}`
	if r := run(); r.code != 0 || r.out != "old\n" || !strings.Contains(r.err, "from before it was turned off") {
		t.Fatalf("stale lines: %d %q %s", r.code, r.out, r.err)
	}
}
