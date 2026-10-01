package home

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestResolvePrecedence(t *testing.T) {
	flagDir := t.TempDir()
	envDir := t.TempDir()
	t.Setenv(EnvVar, envDir)

	h, err := Resolve(flagDir)
	if err != nil || h.Dir() != flagDir {
		t.Fatalf("flag: %v %v", h, err)
	}
	h, err = Resolve("")
	if err != nil || h.Dir() != envDir {
		t.Fatalf("env: %v %v", h, err)
	}
	t.Setenv(EnvVar, "")
	// The test binary's directory has no fileparcel.toml.
	if _, err := Resolve(""); !errors.Is(err, ErrNoHome) {
		t.Fatalf("want ErrNoHome, got %v", err)
	}
	rel, err := New(".")
	if err != nil || !filepath.IsAbs(rel.Dir()) {
		t.Fatal("New must make paths absolute")
	}
}

func TestAccessors(t *testing.T) {
	h, _ := New("/srv/fp")
	cases := map[string]string{
		h.Config():            "/srv/fp/fileparcel.toml",
		h.DB():                "/srv/fp/data/fileparcel.db",
		h.BlobsDir():          "/srv/fp/data/blobs",
		h.KeysFile():          "/srv/fp/keys/master.key",
		h.CertsDir():          "/srv/fp/certs",
		h.BackupsDir():        "/srv/fp/backups",
		h.LogsDir():           "/srv/fp/logs",
		h.TmpDir(TmpUploads):  "/srv/fp/tmp/uploads",
		h.TmpDir(""):          "/srv/fp/tmp",
		h.RunDir():            "/srv/fp/run",
		h.Socket():            "/srv/fp/run/admin.sock",
		h.LockFile():          "/srv/fp/run/fileparcel.lock",
		h.ServiceDir():        "/srv/fp/service",
		h.BinDir():            "/srv/fp/bin",
		h.Binary():            "/srv/fp/bin/fileparcel",
		h.VersionFile():       "/srv/fp/VERSION",
		h.RestoreFile():       "/srv/fp/run/restore.json",
		h.Path("certs", "ca"): "/srv/fp/certs/ca",
	}
	for got, want := range cases {
		if got != want {
			t.Errorf("got %s want %s", got, want)
		}
	}
}

func TestEnsureLayoutModesAndIsHome(t *testing.T) {
	old := umask(0o022)
	defer umask(old)
	dir := filepath.Join(t.TempDir(), "home")
	h, _ := New(dir)
	if h.Exists() || IsHome(dir) {
		t.Fatal("empty dir must not be a home")
	}
	if err := h.EnsureLayout(); err != nil {
		t.Fatal(err)
	}
	// Loosen one dir; EnsureLayout must repair it.
	if err := os.Chmod(h.KeysDir(), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := h.EnsureLayout(); err != nil {
		t.Fatal(err)
	}
	want := map[string]os.FileMode{
		dir:                   0o750,
		h.DataDir():           0o700,
		h.BlobsDir():          0o700,
		h.KeysDir():           0o700,
		h.CertsDir():          0o700,
		h.Path("certs", "ca"): 0o700,
		h.BackupsDir():        0o700,
		h.LogsDir():           0o750,
		h.TmpDir(TmpZip):      0o700,
		h.RunDir():            0o700,
		h.BinDir():            0o755,
		h.ServiceDir():        0o750,
	}
	for p, mode := range want {
		st, err := os.Stat(p)
		if err != nil {
			t.Fatal(err)
		}
		if st.Mode().Perm() != mode {
			t.Errorf("%s: mode %o want %o", p, st.Mode().Perm(), mode)
		}
	}
	if err := os.WriteFile(h.Config(), []byte("x"), 0o640); err != nil {
		t.Fatal(err)
	}
	if !h.Exists() || !IsHome(dir) {
		t.Fatal("IsHome")
	}
	t.Setenv(EnvVar, "")
}

// A system install's HOME is root:<service group> 01770 (DESIGN §14.4): the
// server's EnsureLayout (running as the service account, which cannot chmod
// it) must leave it alone; any other mode is still repaired to 0750.
func TestEnsureLayoutKeepsSystemHome(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "home")
	h, _ := New(dir)
	if err := h.EnsureLayout(); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, ModeSystemHome); err != nil {
		t.Fatal(err)
	}
	if err := h.EnsureLayout(); err != nil {
		t.Fatal(err)
	}
	st, err := os.Stat(dir)
	if err != nil || !IsSystemHomeMode(st.Mode()) {
		t.Fatalf("system home mode changed to %v (%v)", st.Mode(), err)
	}
	if err := os.Chmod(dir, 0o770); err != nil { // group-writable without the sticky bit
		t.Fatal(err)
	}
	if err := h.EnsureLayout(); err != nil {
		t.Fatal(err)
	}
	if st, _ := os.Stat(dir); st.Mode()&(os.ModePerm|os.ModeSticky) != ModeHome {
		t.Fatalf("mode %v not repaired", st.Mode())
	}
}

func TestLock(t *testing.T) {
	h, _ := New(t.TempDir())
	unlock, err := h.Lock()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.Lock(); !errors.Is(err, ErrLocked) {
		t.Fatalf("second lock: %v", err)
	}
	unlock()
	unlock() // idempotent
	unlock2, err := h.Lock()
	if err != nil {
		t.Fatalf("relock: %v", err)
	}
	unlock2()
}
