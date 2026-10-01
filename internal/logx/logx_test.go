package logx

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"fileparcel/internal/config"
)

func TestRotation(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, FileName)
	r, err := NewRotatingFile(p, 100, 2)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 10; i++ {
		fmt.Fprintf(r, "%s\n", strings.Repeat(string(rune('a'+i)), 59)) // 60 bytes per line
	}
	r.Close()
	for _, name := range []string{FileName, FileName + ".1", FileName + ".2"} {
		st, err := os.Stat(filepath.Join(dir, name))
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if st.Size() > 100 {
			t.Fatalf("%s too large: %d", name, st.Size())
		}
	}
	if _, err := os.Stat(filepath.Join(dir, FileName+".3")); !os.IsNotExist(err) {
		t.Fatal("more files kept than configured")
	}
	b, _ := os.ReadFile(p)
	if !strings.HasPrefix(string(b), "jjj") {
		t.Fatalf("newest line not in active file: %q", b)
	}
}

// TestRotateReopensAfterFailure: a rotation whose reopen fails (here: the
// directory is not writable) must not end file logging for good. Writes fail
// while the problem lasts, reopen attempts are rate-limited, and the file is
// back once the problem is gone. Only Close is permanent.
func TestRotateReopensAfterFailure(t *testing.T) {
	if os.Geteuid() == 0 || runtime.GOOS == "windows" {
		t.Skip("needs directory permissions that are enforced")
	}
	var notices bytes.Buffer
	oldReport := reportTo
	reportTo = &notices
	t.Cleanup(func() { reportTo = oldReport })

	dir := filepath.Join(t.TempDir(), "logs")
	p := filepath.Join(dir, FileName)
	r, err := NewRotatingFile(p, 100, 2)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	line := strings.Repeat("x", 59) + "\n"
	if _, err := r.Write([]byte(line)); err != nil {
		t.Fatal(err)
	}
	// The active file is gone and cannot be created again.
	if err := os.Remove(p); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })
	if _, err := r.Write([]byte(line)); err == nil { // rotates, reopen fails
		t.Fatal("write succeeded without a file")
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	// Within the retry delay nothing is attempted.
	if _, err := r.Write([]byte(line)); err == nil || errors.Is(err, os.ErrClosed) {
		t.Fatalf("write during the retry delay: %v", err)
	}
	r.mu.Lock()
	r.retryAt = time.Time{} // the delay has passed
	r.mu.Unlock()
	if _, err := r.Write([]byte("marker\n")); err != nil {
		t.Fatalf("write after the problem was fixed: %v", err)
	}
	if b, err := os.ReadFile(p); err != nil || !strings.Contains(string(b), "marker") {
		t.Fatalf("active file after recovery: %q %v", b, err)
	}
	if got := notices.String(); strings.Count(got, "file logging paused") != 1 || !strings.Contains(got, "file logging resumed") {
		t.Fatalf("notices: %q", got)
	}
	if err := r.Rotate(); err != nil {
		t.Fatalf("rotate after recovery: %v", err)
	}

	// Close is permanent.
	if err := r.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Write([]byte(line)); !errors.Is(err, os.ErrClosed) {
		t.Fatalf("write after Close: %v", err)
	}
	if err := r.Rotate(); !errors.Is(err, os.ErrClosed) {
		t.Fatalf("rotate after Close: %v", err)
	}
}

func TestNewAndSetLevel(t *testing.T) {
	var stderr bytes.Buffer
	dir := t.TempDir()
	log, closer, err := New(Options{
		Config: config.LogConfig{Level: "info", Format: "json", File: true, MaxSizeMB: 1, MaxFiles: 1},
		Dir:    dir, Stderr: &stderr,
	})
	if err != nil {
		t.Fatal(err)
	}
	log.Debug("hidden")
	log.Info("shown", "k", 1)
	if err := SetLevel("debug"); err != nil || Level() != "debug" {
		t.Fatalf("SetLevel: %v %s", err, Level())
	}
	log.Debug("now visible")
	closer.Close()
	file, _ := os.ReadFile(filepath.Join(dir, FileName))
	if strings.Contains(stderr.String(), "hidden") || !strings.Contains(stderr.String(), "shown") ||
		!strings.Contains(stderr.String(), "now visible") {
		t.Fatalf("stderr: %s", stderr.String())
	}
	if !strings.Contains(string(file), `"msg":"shown"`) || !strings.Contains(string(file), "now visible") {
		t.Fatalf("file: %s", file)
	}
	if SetLevel("loud") == nil {
		t.Fatal("bad level accepted")
	}

	// Quiet console: warnings only, whatever the global level.
	stderr.Reset()
	log, closer, _ = New(Options{Config: config.LogConfig{Level: "debug"}, Stderr: &stderr, StderrQuiet: true})
	log.Info("info-line")
	log.Warn("warn-line")
	closer.Close()
	if strings.Contains(stderr.String(), "info-line") || !strings.Contains(stderr.String(), "warn-line") {
		t.Fatalf("quiet: %s", stderr.String())
	}
	_ = SetLevel("info")
}
