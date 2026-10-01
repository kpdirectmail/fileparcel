package cli

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/spf13/cobra"

	"fileparcel/internal/core"
	"fileparcel/internal/home"
	"fileparcel/internal/svc"
)

// lcSyncBuffer is a goroutine-safe bytes.Buffer.
type lcSyncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *lcSyncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *lcSyncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

// lcStartServe runs `serve` for h in a goroutine (without re-parsing the
// global flags, which other calls of this test read concurrently) and
// returns a channel with its error.
func lcStartServe(t *testing.T, ctx context.Context, h *home.Home, o serveOptions) (<-chan error, *lcSyncBuffer) {
	t.Helper()
	NewRootCmd() // reset the global flags before the goroutine starts
	G.Home = h.Dir()
	cmd := newServeCmd()
	stderr := &lcSyncBuffer{}
	cmd.SetOut(stderr)
	cmd.SetErr(stderr)
	cmd.SetContext(ctx)
	done := make(chan error, 1)
	go func() { done <- runServe(cmd, o) }()
	return done, stderr
}

func lcWaitDone(t *testing.T, done <-chan error) error {
	t.Helper()
	select {
	case err := <-done:
		return err
	case <-time.After(60 * time.Second):
		t.Fatal("serve did not stop")
	}
	return nil
}

func TestServeLifecycle(t *testing.T) {
	h, _ := lcInitTestHome(t)
	t.Setenv("FILEPARCEL_SUPERVISED", "1") // exit 75 instead of re-executing the test binary
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done, stderr := lcStartServe(t, ctx, h, serveOptions{})

	if err := svc.WaitHealthy(ctx, h, 0, 30*time.Second, 100*time.Millisecond); err != nil {
		cancel()
		t.Fatalf("server not healthy: %v\n%s", err, stderr.String())
	}

	// A second server on the same home is refused (lock).
	cmd2 := newServeCmd()
	var err2 bytes.Buffer
	cmd2.SetErr(&err2)
	cmd2.SetContext(ctx)
	if err := runServe(cmd2, serveOptions{}); err == nil || !strings.Contains(err.Error(), "another FileParcel process") {
		t.Fatalf("second serve: %v", err)
	}

	// status / doctor / open through the admin socket.
	rep, err := lcCollectStatus(ctx)
	if err != nil || !rep.Running || rep.Transport != ModeSocket || rep.sys == nil ||
		rep.sys.KeysState != core.KeyStateUnlocked || rep.sys.Home != h.Dir() {
		t.Fatalf("status %+v %v", rep, err)
	}
	var buf bytes.Buffer
	if err := lcRenderStatus(&buf, rep); err != nil || !strings.Contains(buf.String(), "Server:") ||
		!strings.Contains(buf.String(), "running (pid") {
		t.Fatalf("status render %v\n%s", err, buf.String())
	}
	d := &lcDoctor{h: h, host: svc.CurrentHost(), now: time.Now()}
	drep := d.run(ctx)
	var ids []string
	for _, c := range drep.Checks {
		ids = append(ids, c.ID+"="+c.Status)
	}
	joined := strings.Join(ids, " ")
	for _, want := range []string{"server=ok", "health=ok", "home=ok", "keys.file=ok", "keys=ok"} {
		if !strings.Contains(joined, want) {
			t.Errorf("doctor lacks %s: %s", want, joined)
		}
	}
	c, err := connectSocket(h, Options{})
	if err != nil {
		t.Fatal(err)
	}
	urls, err := lcAccessURLs(ctx, c)
	if err != nil || len(urls) == 0 {
		t.Fatalf("urls %v %v", urls, err)
	}

	// Restart request → exit status 75.
	if err := c.Do(ctx, http.MethodPost, "/api/v1/admin/system/restart", nil, nil); err != nil {
		t.Fatalf("restart: %v", err)
	}
	c.Close()
	err = lcWaitDone(t, done)
	var ee *ExitCodeError
	if !errors.As(err, &ee) || ee.Code != ExitRestart {
		t.Fatalf("serve after restart request: %v\n%s", err, stderr.String())
	}

	// Start again and stop gracefully (context cancelled = SIGTERM).
	ctx2, cancel2 := context.WithCancel(context.Background())
	defer cancel2()
	done, stderr = lcStartServe(t, ctx2, h, serveOptions{})
	if err := svc.WaitHealthy(ctx2, h, 0, 30*time.Second, 100*time.Millisecond); err != nil {
		t.Fatalf("second start: %v\n%s", err, stderr.String())
	}
	cancel2()
	if err := lcWaitDone(t, done); err != nil {
		t.Fatalf("graceful stop: %v", err)
	}
	if _, err := os.Stat(h.CleanShutdownFile()); err != nil {
		t.Errorf("no clean-shutdown marker: %v", err)
	}
	// The lock is free again.
	unlock, err := h.Lock()
	if err != nil {
		t.Fatalf("lock after stop: %v", err)
	}
	unlock()
}

func TestServeSetupTokenAndSealed(t *testing.T) {
	// No account: the setup token is logged.
	h, _ := lcInitTestHome(t, "--no-admin")
	ctx, cancel := context.WithCancel(context.Background())
	done, stderr := lcStartServe(t, ctx, h, serveOptions{})
	if err := svc.WaitHealthy(ctx, h, 0, 30*time.Second, 100*time.Millisecond); err != nil {
		cancel()
		t.Fatalf("%v\n%s", err, stderr.String())
	}
	cancel()
	if err := lcWaitDone(t, done); err != nil {
		t.Fatal(err)
	}
	logb, _ := os.ReadFile(h.LogFile())
	if !strings.Contains(string(logb), "setup_token=") {
		t.Fatalf("setup token not logged:\n%s", logb)
	}

	// Sealed: a wrong passphrase file starts locked; the right one unlocks.
	pp := filepath.Join(t.TempDir(), "pp")
	if err := os.WriteFile(pp, []byte("correct horse battery staple\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	hs, _ := lcInitTestHome(t, "--sealed", "--passphrase-file", pp)
	bad := filepath.Join(t.TempDir(), "bad")
	if err := os.WriteFile(bad, []byte("wrong passphrase\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		file  string
		state core.KeyState
	}{{bad, core.KeyStateLocked}, {pp, core.KeyStateUnlocked}} {
		ctx, cancel := context.WithCancel(context.Background())
		done, stderr := lcStartServe(t, ctx, hs, serveOptions{passphraseFile: c.file})
		if err := svc.WaitHealthy(ctx, hs, 0, 30*time.Second, 100*time.Millisecond); err != nil {
			cancel()
			t.Fatalf("%v\n%s", err, stderr.String())
		}
		rep, err := lcCollectStatus(ctx)
		cancel()
		if werr := lcWaitDone(t, done); werr != nil {
			t.Fatal(werr)
		}
		if err != nil || rep.sys == nil || rep.sys.KeysState != c.state {
			t.Fatalf("%s: status %+v %v", c.file, rep, err)
		}
	}
}

func TestServeErrors(t *testing.T) {
	NewRootCmd()
	G.Home = t.TempDir()
	cmd := newServeCmd()
	cmd.SetErr(&bytes.Buffer{})
	cmd.SetContext(context.Background())
	if err := runServe(cmd, serveOptions{}); err == nil || !strings.Contains(err.Error(), "not a FileParcel home") {
		t.Fatalf("serve on a non-home: %v", err)
	}
	if os.Geteuid() == 0 {
		if err := runServe(cmd, serveOptions{}); err == nil || !strings.Contains(err.Error(), "root") {
			t.Fatalf("serve as root: %v", err)
		}
	}
}

func TestServeInitIfMissing(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "data")
	pwFile := filepath.Join(t.TempDir(), "pw")
	pw := "docker secret password 1"
	if err := os.WriteFile(pwFile, []byte(pw+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv(EnvAdminUser, "dora")
	t.Setenv(EnvAdminPasswordFile, pwFile)
	h, _ := home.New(dir)
	cmd := &cobra.Command{}
	var stderr bytes.Buffer
	cmd.SetErr(&stderr)
	if err := serveInitHome(context.Background(), cmd, h); err != nil {
		t.Fatal(err)
	}
	if !h.Exists() || !strings.Contains(stderr.String(), "owner account: dora") || strings.Contains(stderr.String(), pw) {
		t.Fatalf("init-if-missing output:\n%s", stderr.String())
	}
	if !lcVerifyPassword(t, h, "dora", pw) {
		t.Fatal("password file not used")
	}
	// A second call (another container won the race) is fine.
	if err := serveInitHome(context.Background(), cmd, h); err != nil {
		t.Fatalf("existing home: %v", err)
	}

	// Without a password file the generated password is printed once.
	t.Setenv(EnvAdminUser, "")
	t.Setenv(EnvAdminPasswordFile, "")
	h2, _ := home.New(filepath.Join(t.TempDir(), "data2"))
	stderr.Reset()
	if err := serveInitHome(context.Background(), cmd, h2); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(stderr.String(), "owner account: admin") || !strings.Contains(stderr.String(), "generated password") {
		t.Fatalf("output:\n%s", stderr.String())
	}
	t.Setenv(EnvAdminPasswordFile, filepath.Join(t.TempDir(), "missing"))
	if err := serveInitHome(context.Background(), cmd, mustNewHome(t, filepath.Join(t.TempDir(), "d3"))); err == nil {
		t.Fatal("missing password file accepted")
	}
}

func mustNewHome(t *testing.T, dir string) *home.Home {
	t.Helper()
	h, err := home.New(dir)
	if err != nil {
		t.Fatal(err)
	}
	return h
}

func TestMemoryLimit(t *testing.T) {
	const gib = int64(1) << 30
	cases := []struct {
		mb    int
		avail int64
		want  int64
	}{
		{512, 0, 512 << 20},
		{0, 0, gib},
		{0, 2 * gib, gib / 2},
		{0, 16 * gib, gib},
		{2048, 1 * gib, 2 * gib},
	}
	for _, c := range cases {
		if got, _ := lcMemoryLimit(c.mb, c.avail); got != c.want {
			t.Errorf("lcMemoryLimit(%d, %d) = %d, want %d", c.mb, c.avail, got, c.want)
		}
	}
	mi := []byte("MemFree: 10 kB\nMemTotal:       16318228 kB\n")
	if got := lcParseMemInfo(mi); got != 16318228*1024 {
		t.Fatal(got)
	}
	if lcParseMemInfo([]byte("nothing")) != 0 || lcParseMemInfo([]byte("MemTotal: x kB")) != 0 {
		t.Fatal("bad meminfo parsed")
	}
	t.Setenv("GOMEMLIMIT", "1GiB")
	if lim, how := lcApplyMemoryLimit(nil); lim != 0 || how != "GOMEMLIMIT" {
		t.Fatal(lim, how)
	}
	if lcIsTerminal(&bytes.Buffer{}) {
		t.Fatal("buffer is a terminal")
	}
}
