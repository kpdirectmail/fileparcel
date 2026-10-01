package cli

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/spf13/cobra"
)

func TestHumanDurationSubMillisecond(t *testing.T) {
	for _, c := range []struct {
		d    time.Duration
		want string
	}{
		{0, "0ms"},
		{1, "<1ms"},
		{700 * time.Microsecond, "<1ms"},
		{-700 * time.Microsecond, "-<1ms"},
		{time.Millisecond, "1ms"},
		{12 * time.Millisecond, "12ms"},
		{1500 * time.Millisecond, "1s"},
		{90 * time.Second, "1m30s"},
	} {
		if got := HumanDuration(c.d); got != c.want {
			t.Errorf("HumanDuration(%v) = %q, want %q", c.d, got, c.want)
		}
	}
}

// An unnamed column keeps a blank heading: the "-" placeholder belongs to
// empty data cells only, and a bold "-" in the header reads as a value
// (`network urls` has an unnamed recommendation column).
func TestTableBlankHeaderIsNotAPlaceholder(t *testing.T) {
	tb := NewTable("URL", "TRUSTED", "")
	tb.Add("https://one/", false, "recommended")
	tb.Add("https://two/", true, "")
	var b strings.Builder
	if err := tb.Render(&b); err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimRight(b.String(), "\n"), "\n")
	if len(lines) != 3 {
		t.Fatalf("lines: %q", lines)
	}
	if strings.Contains(lines[0], "-") {
		t.Errorf("header renders the unnamed column as a value: %q", lines[0])
	}
	if !strings.HasSuffix(lines[1], "recommended") {
		t.Errorf("row 1 %q", lines[1])
	}
	if !strings.HasSuffix(lines[2], "-") { // empty data cells still print as "-"
		t.Errorf("row 2 %q", lines[2])
	}
	// The unnamed column stays a column: the data cells line up under it.
	if strings.Index(lines[1], "recommended") != strings.Index(lines[2], "-") {
		t.Errorf("column not aligned:\n%q\n%q", lines[1], lines[2])
	}
}

func TestKVContinuationRow(t *testing.T) {
	kv := NewKV()
	kv.Add("Access", "any")
	kv.Add("URLs", "https://one/")
	kv.Add("", "https://two/")
	var b strings.Builder
	if err := kv.Render(&b); err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimRight(b.String(), "\n"), "\n")
	if len(lines) != 3 {
		t.Fatalf("lines: %q", lines)
	}
	if strings.HasPrefix(lines[2], ":") || strings.TrimSpace(lines[2]) != "https://two/" {
		t.Errorf("continuation row %q", lines[2])
	}
	if strings.Index(lines[2], "https://") != strings.Index(lines[1], "https://") {
		t.Errorf("continuation row not aligned:\n%q\n%q", lines[1], lines[2])
	}
}

// A world-readable secret file is only worth warning about when this process
// could actually chmod it. The documented Docker bootstrap (DESIGN §14.7)
// bind-mounts a 0644 secret owned by the host user into a container running as
// uid 65532; telling that container to "chmod 600 it" would make the file
// unreadable and break the setup, so ReadSecretFile stays quiet there.
func TestReadSecretFilePermissionWarning(t *testing.T) {
	warn := func(path string) string {
		cmd := &cobra.Command{}
		var stderr bytes.Buffer
		cmd.SetErr(&stderr)
		cmd.SetOut(io.Discard)
		_, _ = ReadSecretFile(cmd, path)
		return stderr.String()
	}

	own := filepath.Join(t.TempDir(), "pw")
	if err := os.WriteFile(own, []byte("hunter2\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if got := warn(own); !strings.Contains(got, "chmod 600") {
		t.Errorf("own 0644 secret: got %q, want a chmod 600 warning", got)
	}
	if err := os.Chmod(own, 0o600); err != nil {
		t.Fatal(err)
	}
	if got := warn(own); got != "" {
		t.Errorf("own 0600 secret: got %q, want no warning", got)
	}

	// A file owned by somebody else (the container-secret case): root's
	// /etc/passwd is world-readable everywhere this test runs.
	if runtime.GOOS == "windows" || os.Geteuid() == 0 {
		t.Skip("needs a non-root uid and unix file ownership")
	}
	st, err := os.Stat("/etc/passwd")
	if err != nil || st.Mode().Perm()&0o004 == 0 {
		t.Skip("/etc/passwd is not world-readable here")
	}
	if got := warn("/etc/passwd"); got != "" {
		t.Errorf("foreign-owned 0644 secret: got %q, want no warning", got)
	}
}

// With colours on, the bold header must still line up with its columns:
// tabwriter counts the ANSI codes as characters, so the header is made bold
// only after the alignment.
func TestTableBoldHeaderStaysAligned(t *testing.T) {
	render := func(color bool) string {
		t.Helper()
		old := colorOn
		colorOn = func() bool { return color }
		defer func() { colorOn = old }()
		tb := NewTable("USERNAME", "NAME", "ROLE", "STATUS")
		tb.Add("bob", "Bob Smith", "owner", "active")
		tb.Add("a", "b", "c", "d")
		var b strings.Builder
		if err := tb.Render(&b); err != nil {
			t.Fatal(err)
		}
		return b.String()
	}
	plain, colored := render(false), render(true)
	if !strings.HasPrefix(colored, "\x1b[1m") {
		t.Fatalf("header not bold: %q", colored)
	}
	stripped := strings.NewReplacer("\x1b[1m", "", "\x1b[0m", "").Replace(colored)
	if stripped != plain {
		t.Fatalf("colours change the layout:\n%s\nwant\n%s", stripped, plain)
	}
	lines := strings.Split(plain, "\n")
	if strings.Index(lines[0], "ROLE") != strings.Index(lines[1], "owner") {
		t.Fatalf("header misaligned:\n%s", plain)
	}
}

// Sub saturates beyond ~292 years; a certificate valid until 9999-12-31 is
// not "just now".
func TestAgoFarFromNow(t *testing.T) {
	now := time.Date(2026, 9, 24, 0, 0, 0, 0, time.UTC)
	for _, c := range []struct {
		t    time.Time
		want string
	}{
		{time.Date(9999, 12, 31, 23, 59, 59, 0, time.UTC), "in 7973 years"},
		{time.Date(2320, 1, 1, 0, 0, 0, 0, time.UTC), "in 293 years"},
		{time.Date(1600, 1, 1, 0, 0, 0, 0, time.UTC), "427 years ago"},
		{time.Date(2126, 1, 1, 0, 0, 0, 0, time.UTC), "in 99 years"},
		{now.Add(-10 * time.Second), "just now"},
		{now.Add(3 * time.Hour), "in 3 h"},
		{now.Add(-50 * 24 * time.Hour), "50 days ago"},
	} {
		if got := agoFrom(c.t, now); got != c.want {
			t.Errorf("agoFrom(%s) = %q, want %q", c.t.Format(time.RFC3339), got, c.want)
		}
	}
}

// A prompt returns as soon as the command context is cancelled (Ctrl-C),
// even while its read is still blocked, and is not shown at all once the
// context is done.
func TestPromptsStopOnCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	block := make(chan struct{})
	defer close(block)
	done := make(chan error, 1)
	go func() {
		_, err := ttyRead(ctx, -1, func() (string, error) { <-block; return "late", nil })
		done <- err
	}()
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("ttyRead: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("ttyRead did not return on cancel")
	}
	if s, err := ttyRead(context.Background(), -1, func() (string, error) { return "x", nil }); s != "x" || err != nil {
		t.Fatalf("uncancellable read: %q %v", s, err)
	}

	cmd := &cobra.Command{}
	cmd.SetContext(ctx) // already cancelled
	cmd.SetIn(strings.NewReader("y\n"))
	var errOut bytes.Buffer
	cmd.SetErr(&errOut)
	G = Globals{}
	if _, err := Confirm(cmd, "Delete?", false); !errors.Is(err, context.Canceled) {
		t.Fatalf("Confirm: %v", err)
	}
	if _, err := Prompt(cmd, "Name", ""); !errors.Is(err, context.Canceled) {
		t.Fatalf("Prompt: %v", err)
	}
	if _, err := PromptSecret(cmd, "Password: "); !errors.Is(err, context.Canceled) {
		t.Fatalf("PromptSecret: %v", err)
	}
	if errOut.Len() != 0 {
		t.Fatalf("a prompt was shown after the cancel: %q", errOut.String())
	}
}
