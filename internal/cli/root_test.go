package cli

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/spf13/cobra"
)

// lcResult is the outcome of one CLI invocation in tests.
type lcResult struct {
	out, err string
	code     int
}

// lcRun executes the CLI with args (stdin from in) and returns the output
// and exit code, like the real process.
func lcRun(t *testing.T, in string, args ...string) lcResult {
	t.Helper()
	return lcRunCtx(t, context.Background(), in, args...)
}

func lcRunCtx(t *testing.T, ctx context.Context, in string, args ...string) lcResult {
	t.Helper()
	root := NewRootCmd()
	var out, errOut bytes.Buffer
	root.SetOut(&out)
	root.SetErr(&errOut)
	root.SetIn(strings.NewReader(in))
	code := run(ctx, root, args, &errOut)
	return lcResult{out: out.String(), err: errOut.String(), code: code}
}

// lcFreePort returns a TCP port that is free right now.
func lcFreePort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	return ln.Addr().(*net.TCPAddr).Port
}

// lcFind returns the command at path (e.g. "service", "install").
func lcFind(root *cobra.Command, path ...string) *cobra.Command {
	c, _, err := root.Find(path)
	if err != nil || c == root {
		return nil
	}
	return c
}

func TestLifecycleCommandTree(t *testing.T) {
	root := NewRootCmd()
	cases := []struct {
		path  []string
		flags []string
	}{
		{[]string{"serve"}, []string{"foreground", "dev", "passphrase-file", "init-if-missing", "allow-root"}},
		{[]string{"init"}, []string{"port", "http-port", "name", "admin", "admin-password-stdin", "admin-password-file",
			"generate-password", "admin-email", "sealed", "passphrase-stdin", "passphrase-file", "access", "allow", "non-interactive", "no-admin"}},
		{[]string{"install"}, []string{"dir", "port", "http-port", "name", "service", "boot", "no-boot", "symlink", "no-symlink",
			"admin", "generate-password", "admin-password-stdin", "admin-password-file", "admin-email", "sealed", "passphrase-file",
			"access", "allow", "upgrade", "force", "dry-run", "non-interactive"}},
		{[]string{"uninstall"}, []string{"keep-data", "purge", "final-backup", "backup-to", "remove-user", "dry-run"}},
		{[]string{"upgrade"}, []string{"force", "skip-backup", "dry-run"}},
		{[]string{"service", "install"}, []string{"user", "system", "boot", "no-boot", "start"}},
		{[]string{"service", "uninstall"}, nil},
		{[]string{"service", "start"}, []string{"wait", "no-wait"}},
		{[]string{"service", "stop"}, nil},
		{[]string{"service", "restart"}, []string{"wait", "no-wait"}},
		{[]string{"service", "status"}, nil},
		{[]string{"service", "enable-boot"}, nil},
		{[]string{"service", "disable-boot"}, nil},
		{[]string{"service", "print"}, []string{"user", "system"}},
		{[]string{"status"}, nil},
		{[]string{"doctor"}, []string{"fix"}},
		{[]string{"version"}, nil},
		{[]string{"healthcheck"}, []string{"port", "timeout"}},
		{[]string{"open"}, []string{"qr", "no-browser"}},
		{[]string{"logs"}, []string{"follow", "lines"}},
	}
	for _, c := range cases {
		cmd := lcFind(root, c.path...)
		if cmd == nil || cmd.Name() != c.path[len(c.path)-1] {
			t.Errorf("command %v missing", c.path)
			continue
		}
		if cmd.Short == "" || (cmd.RunE == nil && !cmd.HasSubCommands()) {
			t.Errorf("%v: no help or no RunE", c.path)
		}
		for _, f := range c.flags {
			if cmd.Flags().Lookup(f) == nil {
				t.Errorf("%v: flag --%s missing", c.path, f)
			}
		}
	}
	// Shorthands of logs.
	logs := lcFind(root, "logs")
	if logs.Flags().ShorthandLookup("f") == nil || logs.Flags().ShorthandLookup("n") == nil {
		t.Error("logs -f/-n missing")
	}
	// Global flags documented in the root package doc.
	for _, g := range []string{"home", "json", "yes", "no-color", "offline", "server", "token", "token-file", "ca-file", "fingerprint", "as"} {
		if root.PersistentFlags().Lookup(g) == nil {
			t.Errorf("global --%s missing", g)
		}
	}
}

func TestLifecycleUsageErrors(t *testing.T) {
	dir := t.TempDir()
	h := filepath.Join(dir, "fp")
	t.Setenv("FILEPARCEL_HOME", "")
	cases := []struct {
		args []string
		in   string
		want string
	}{
		{[]string{"init"}, "", "needs --home"},
		{[]string{"init", "--home", h, "--access", "world"}, "", "--access"},
		{[]string{"init", "--home", h, "--port", "0"}, "", "--port"},
		{[]string{"init", "--home", h, "--http-port", "8443"}, "", "--http-port"},
		{[]string{"init", "--home", h, "--passphrase-file", "x"}, "", "need --sealed"},
		{[]string{"init", "--home", h, "--sealed", "-y"}, "", "--sealed needs"},
		{[]string{"init", "--home", h, "--admin-password-stdin", "--passphrase-stdin", "--sealed"}, "", "cannot both"},
		{[]string{"init", "--home", h, "--admin-password-stdin", "--admin-password-file", "f"}, "", "use only one of"},
		{[]string{"install", "--service", "cron", "-y"}, "", "--service"},
		{[]string{"install", "--boot", "--no-boot"}, "", "use only one of --boot and --no-boot"},
		{[]string{"install", "--http-port", "-5", "-y"}, "", "--http-port"},
		{[]string{"install", "--port", "70000", "-y"}, "", "--port"},
		{[]string{"install", "--access", "all", "-y"}, "", "--access"},
		{[]string{"install", "--passphrase-file", "x", "-y"}, "", "need --sealed"},
		{[]string{"uninstall", "--keep-data", "--purge"}, "", "use only one of"},
		{[]string{"upgrade"}, "", "needs <release.zip|binary>"},
		{[]string{"service", "install", "--user", "--system"}, "", "use only one of"},
		{[]string{"logs", "-n", "-1", "--home", dir}, "", "-n must be"},
		{[]string{"status", "extra"}, "", "unknown command"},
	}
	for _, c := range cases {
		r := lcRun(t, c.in, c.args...)
		if r.code != ExitUsage || !strings.Contains(r.err, c.want) {
			t.Errorf("%v: exit %d, stderr %q; want exit 2 with %q", c.args, r.code, r.err, c.want)
		}
	}
	if lcExists(h) {
		t.Error("a failed init created the home")
	}
}

func lcExists(p string) bool {
	m, _ := filepath.Glob(p)
	return len(m) > 0
}

func TestLifecycleHelpTexts(t *testing.T) {
	for _, name := range []string{"serve", "init", "install", "uninstall", "upgrade", "service", "status", "doctor",
		"healthcheck", "open", "logs"} {
		r := lcRun(t, "", name, "--help")
		if r.code != 0 || !strings.Contains(r.out, "Usage:") {
			t.Errorf("%s --help: exit %d\n%s%s", name, r.code, r.out, r.err)
		}
	}
	r := lcRun(t, "", "--help")
	for _, name := range []string{"serve", "init", "install", "doctor"} {
		if !strings.Contains(r.out, name) {
			t.Errorf("root help lacks %s", name)
		}
	}
}

// Runtime failures whose text merely contains a cobra phrase are errors
// (exit 1), not bad usage: "invalid argument" is also the text of EINVAL
// (a file name a vfat stick refuses). Real flag and argument errors still
// exit 2.
func TestFlagErrorIsMatchedByPrefix(t *testing.T) {
	for _, c := range []struct {
		err  error
		want int
	}{
		{fatalf("%v", &os.PathError{Op: "open", Path: "/media/usb/report: v2.pdf.fpart", Err: syscall.EINVAL}), ExitFailure},
		{errors.New("write x: invalid argument"), ExitFailure},
		{errors.New("upload: server says: unknown command"), ExitFailure},
	} {
		root := &cobra.Command{Use: "fileparcel", SilenceUsage: true, SilenceErrors: true}
		root.AddCommand(&cobra.Command{Use: "x", RunE: func(*cobra.Command, []string) error { return c.err }})
		var errOut bytes.Buffer
		if got := run(context.Background(), root, []string{"x"}, &errOut); got != c.want {
			t.Errorf("%v: exit %d, want %d", c.err, got, c.want)
		}
	}
	for _, args := range [][]string{
		{"x", "--port", "abc"}, // pflag: invalid argument "abc" for "--port" flag
		{"x", "--nope"},
		{"x", "---bad"},
		{"x", "a", "b"},
	} {
		root := &cobra.Command{Use: "fileparcel", SilenceUsage: true, SilenceErrors: true}
		x := &cobra.Command{Use: "x", Args: cobra.MaximumNArgs(1), RunE: func(*cobra.Command, []string) error { return nil }}
		x.Flags().Int("port", 0, "")
		root.AddCommand(x)
		var errOut bytes.Buffer
		if got := run(context.Background(), root, args, &errOut); got != ExitUsage {
			t.Errorf("%v: exit %d, want %d (%s)", args, got, ExitUsage, errOut.String())
		}
	}
}

// The first SIGINT only cancels the command context. A command blocked
// where it does not watch the context (a read of the terminal, a step
// without a context) must still end on the next Ctrl-C: the signal is not
// swallowed for the rest of the run.
func TestSecondInterruptEndsTheProcess(t *testing.T) {
	if os.Getenv("FP_TEST_SIGNAL_HELPER") == "1" {
		ctx, stop := signalContext()
		defer stop()
		fmt.Println("ready")
		<-ctx.Done()
		fmt.Println("cancelled")
		_, _ = io.ReadAll(os.Stdin) // blocks: nobody writes or closes stdin
		os.Exit(0)
	}
	if runtime.GOOS == "windows" {
		t.Skip("needs POSIX signals")
	}
	stdinR, stdinW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer stdinW.Close()
	defer stdinR.Close()
	cmd := exec.Command(os.Args[0], "-test.run=^TestSecondInterruptEndsTheProcess$")
	cmd.Env = append(os.Environ(), "FP_TEST_SIGNAL_HELPER=1")
	cmd.Stdin = stdinR
	out, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	lines := bufio.NewReader(out)
	if l, err := lines.ReadString('\n'); err != nil || l != "ready\n" {
		_ = cmd.Process.Kill()
		t.Fatalf("helper: %q %v", l, err)
	}
	if err := cmd.Process.Signal(os.Interrupt); err != nil {
		t.Fatal(err)
	}
	if l, err := lines.ReadString('\n'); err != nil || l != "cancelled\n" {
		_ = cmd.Process.Kill()
		t.Fatalf("first SIGINT did not cancel the context: %q %v", l, err)
	}
	done := make(chan error, 1)
	go func() { _, _ = io.Copy(io.Discard, lines); done <- cmd.Wait() }()
	deadline := time.After(10 * time.Second)
	tick := time.NewTicker(100 * time.Millisecond)
	defer tick.Stop()
	for {
		select {
		case err := <-done:
			if err == nil {
				t.Fatal("helper exited normally; want it ended by the second SIGINT")
			}
			return
		case <-tick.C:
			_ = cmd.Process.Signal(os.Interrupt)
		case <-deadline:
			_ = cmd.Process.Kill()
			<-done
			t.Fatal("further SIGINTs were swallowed: the process kept running")
		}
	}
}
