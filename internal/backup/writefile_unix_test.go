//go:build unix

package backup

import (
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

// TestWriteFileAtomicTempFile: writeFileAtomic writes run/restore.key (the
// key that unseals the stored backup identity and passphrase), so a
// pre-existing <path>.tmp must never lend the new file its mode, nor be a
// symlink the secret is written through, and the mode must not depend on
// the process umask.
func TestWriteFileAtomicTempFile(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root writes through anything")
	}
	dir := t.TempDir()
	secret := []byte("restore key")

	t.Run("stale temp file", func(t *testing.T) {
		path := filepath.Join(dir, "stale.key")
		if err := os.WriteFile(path+".tmp", []byte("left by a crash"), 0o666); err != nil {
			t.Fatal(err)
		}
		if err := writeFileAtomic(path, secret, 0o600); err != nil {
			t.Fatal(err)
		}
		checkFile(t, path, secret, 0o600)
	})

	t.Run("temp file is a symlink", func(t *testing.T) {
		path := filepath.Join(dir, "linked.key")
		target := filepath.Join(dir, "elsewhere")
		if err := os.WriteFile(target, nil, 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(target, path+".tmp"); err != nil {
			t.Fatal(err)
		}
		if err := writeFileAtomic(path, secret, 0o600); err != nil {
			t.Fatal(err)
		}
		if b, err := os.ReadFile(target); err != nil || len(b) != 0 {
			t.Fatalf("the secret was written through the symlink: %q %v", b, err)
		}
		st, err := os.Lstat(path)
		if err != nil || !st.Mode().IsRegular() {
			t.Fatalf("%s is not a regular file: %v %v", path, st.Mode(), err)
		}
		checkFile(t, path, secret, 0o600)
	})

	t.Run("umask independent", func(t *testing.T) {
		old := unix.Umask(0o277)
		defer unix.Umask(old)
		path := filepath.Join(dir, "umask.key")
		if err := writeFileAtomic(path, secret, 0o600); err != nil {
			t.Fatal(err)
		}
		checkFile(t, path, secret, 0o600)
	})

	t.Run("rewrite", func(t *testing.T) {
		path := filepath.Join(dir, "rewrite.key")
		for _, data := range [][]byte{secret, []byte("a second, longer value")} {
			if err := writeFileAtomic(path, data, 0o600); err != nil {
				t.Fatal(err)
			}
			checkFile(t, path, data, 0o600)
		}
		if _, err := os.Lstat(path + ".tmp"); !os.IsNotExist(err) {
			t.Fatalf("temp file left behind: %v", err)
		}
	})
}

func checkFile(t *testing.T, path string, want []byte, mode os.FileMode) {
	t.Helper()
	st, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm() != mode {
		t.Errorf("%s has mode %s, want %s", path, st.Mode().Perm(), mode)
	}
	if b, err := os.ReadFile(path); err != nil || string(b) != string(want) {
		t.Errorf("%s holds %q (%v), want %q", path, b, err, want)
	}
}
