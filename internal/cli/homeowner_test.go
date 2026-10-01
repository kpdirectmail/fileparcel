//go:build unix

package cli

import (
	"bytes"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"fileparcel/internal/home"
	"fileparcel/internal/svc"
)

// lcFakeRoot makes the ownership code believe it runs as root and records
// the homes it gives back; locked: check that the home lock is still held.
func lcFakeRoot(t *testing.T, fail error, locked bool) *[]homeOwner {
	t.Helper()
	var calls []homeOwner
	geteuid, give, stderr := lcGeteuid, lcGiveHome, lcOwnerStderr
	t.Cleanup(func() { lcGeteuid, lcGiveHome, lcOwnerStderr = geteuid, give, stderr })
	lcGeteuid = func() int { return 0 }
	lcGiveHome = func(h *home.Home, o homeOwner) error {
		if locked {
			if u, err := h.Lock(); err == nil {
				u()
				t.Errorf("home given back after the lock was released")
			} else if !errors.Is(err, home.ErrLocked) {
				t.Error(err)
			}
		}
		calls = append(calls, o)
		return fail
	}
	return &calls
}

func lcStatOwner(t *testing.T, p string) (uid, gid int) {
	t.Helper()
	fi, err := os.Stat(p)
	if err != nil {
		t.Fatal(err)
	}
	u, g, _, ok := fileOwner(fi)
	if !ok {
		t.Fatal("no owner")
	}
	return int(u), int(g)
}

func TestHomeOwnerFromStat(t *testing.T) {
	ids := lcAccountIDs
	t.Cleanup(func() { lcAccountIDs = ids })
	account := svc.ServiceUser(&svc.Host{GOOS: runtime.GOOS})
	var asked string
	lcAccountIDs = func(name string) (int, int, error) {
		asked = name
		return 999, 998, nil
	}
	sys := fs.ModeDir | home.ModeSystemHome

	// A user's (or a container's) home: its owner.
	if o, ok := lcOwnerFromStat(1000, 1001, fs.ModeDir|0o750); !ok || o.uid != 1000 || o.gid != 1001 || o.system {
		t.Errorf("user home: %+v %v", o, ok)
	}
	// A system install: root:<service group> 01770 → the host's service
	// account, whatever installed.json says.
	if o, ok := lcOwnerFromStat(0, 998, sys); !ok || o.uid != 999 || o.gid != 998 || !o.system || o.name != account ||
		asked != account {
		t.Errorf("system home: %+v %v (asked %q)", o, ok, asked)
	}
	// Root's own home, or a HOME whose group is not the account's: nothing.
	for _, tc := range []struct {
		gid  uint32
		mode fs.FileMode
	}{{0, fs.ModeDir | 0o750}, {0, sys}, {997, sys}} {
		if o, ok := lcOwnerFromStat(0, tc.gid, tc.mode); ok {
			t.Errorf("root home gid %d mode %v: %+v", tc.gid, tc.mode, o)
		}
	}
	lcAccountIDs = func(string) (int, int, error) { return 0, 0, errors.New("no such account") }
	if o, ok := lcOwnerFromStat(0, 998, sys); ok {
		t.Errorf("missing account: %+v", o)
	}
	lcAccountIDs = func(string) (int, int, error) { return 0, 998, nil }
	if o, ok := lcOwnerFromStat(0, 998, sys); ok {
		t.Errorf("account with uid 0: %+v", o)
	}
}

// Run as root on a home that belongs to another account (sudo on a system
// install), releasing the home lock first gives what was written back to
// that account — while the lock is still held, and once.
func TestLockHomeGivesHomeBack(t *testing.T) {
	h := lcBareHome(t)
	uid, gid := lcStatOwner(t, h.Dir())

	// Not root: nothing to give back.
	calls := lcFakeRoot(t, nil, true)
	lcGeteuid = os.Geteuid
	if os.Geteuid() == 0 {
		t.Skip("runs as root: the non-root case cannot be checked")
	}
	unlock, err := lockHome(h)
	if err != nil {
		t.Fatal(err)
	}
	unlock()
	if len(*calls) != 0 {
		t.Fatalf("not root, yet given back: %+v", *calls)
	}

	lcGeteuid = func() int { return 0 }
	unlock, err = lockHome(h)
	if err != nil {
		t.Fatal(err)
	}
	unlock()
	unlock()
	if len(*calls) != 1 || (*calls)[0].uid != uid || (*calls)[0].gid != gid || (*calls)[0].system {
		t.Fatalf("give back: %+v (home %d:%d)", *calls, uid, gid)
	}
	if u, err := h.Lock(); err != nil {
		t.Fatalf("lock not released: %v", err)
	} else {
		u()
	}

	// A failure is reported with the repair, and the lock is released anyway.
	calls = lcFakeRoot(t, errors.New("chown: operation not permitted"), true)
	var errOut bytes.Buffer
	lcOwnerStderr = &errOut
	unlock, err = lockHome(h)
	if err != nil {
		t.Fatal(err)
	}
	unlock()
	if len(*calls) != 1 || !strings.Contains(errOut.String(), "operation not permitted") ||
		!strings.Contains(errOut.String(), "sudo fileparcel doctor --fix") {
		t.Fatalf("failure: %d calls, %q", len(*calls), errOut.String())
	}
	if u, err := h.Lock(); err != nil {
		t.Fatalf("lock not released after a failure: %v", err)
	} else {
		u()
	}
}

// Offline mode (a restore, keys, certificates, uploads … with the server
// stopped) gives the home back when the client is closed, after the
// services are stopped and before the lock is released.
func TestConnectOfflineGivesHomeBack(t *testing.T) {
	lcIsolateHost(t)
	h, _ := lcInitTestHome(t)
	calls := lcFakeRoot(t, nil, true)
	c, err := Connect(Options{Home: h.Dir(), Offline: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(*calls) != 0 {
		t.Fatal("given back before the command ran")
	}
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
	_ = c.Close()
	uid, _ := lcStatOwner(t, h.Dir())
	if len(*calls) != 1 || (*calls)[0].uid != uid {
		t.Fatalf("give back on Close: %+v", *calls)
	}
}

func TestKeepOwner(t *testing.T) {
	dir := t.TempDir()
	orig, tmp := filepath.Join(dir, "fileparcel.toml"), filepath.Join(dir, ".edit")
	for _, p := range []string{orig, tmp} {
		if err := os.WriteFile(p, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	// Same owner: nothing to do.
	if err := keepOwner(tmp, orig); err != nil {
		t.Fatal(err)
	}
	if os.Geteuid() != 0 {
		// A file of root's cannot be matched by an ordinary user: the edit
		// is refused rather than saved with the wrong owner.
		if err := keepOwner(tmp, "/etc/passwd"); err == nil || !strings.Contains(err.Error(), "not saved") {
			t.Fatalf("foreign owner: %v", err)
		}
		return
	}
	// As root: the copy gets the original's owner.
	if err := os.Lchown(orig, 65534, 65534); err != nil {
		t.Skip(err)
	}
	if err := keepOwner(tmp, orig); err != nil {
		t.Fatal(err)
	}
	if u, g := lcStatOwner(t, tmp); u != 65534 || g != 65534 {
		t.Fatalf("owner not kept: %d:%d", u, g)
	}
}

// config edit saves the edited copy with the file's mode and owner.
func TestConfigEditKeepsModeAndOwner(t *testing.T) {
	lcIsolateHost(t)
	h := lcBareHome(t)
	if err := os.Chmod(h.Config(), home.ModeConfig); err != nil {
		t.Fatal(err)
	}
	uid, gid := lcStatOwner(t, h.Config())
	ed := filepath.Join(t.TempDir(), "ed.sh")
	script := "#!/bin/sh\nsed 's/^level = .*/level = \"debug\"/' \"$1\" > \"$1.new\" && cat \"$1.new\" > \"$1\" && rm \"$1.new\"\n"
	if err := os.WriteFile(ed, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("VISUAL", "")
	t.Setenv("EDITOR", ed)
	r := lcRun(t, "", "config", "edit", "--home", h.Dir())
	if r.code != 0 || !strings.Contains(r.out, "saved") {
		t.Fatalf("config edit: %d %s %s", r.code, r.out, r.err)
	}
	b, err := os.ReadFile(h.Config())
	if err != nil || !strings.Contains(string(b), `level = "debug"`) {
		t.Fatalf("not edited: %v\n%s", err, b)
	}
	fi, err := os.Stat(h.Config())
	if err != nil || fi.Mode().Perm() != home.ModeConfig {
		t.Fatalf("mode not kept: %v %v", fi.Mode(), err)
	}
	if u, g := lcStatOwner(t, h.Config()); u != uid || g != gid {
		t.Fatalf("owner changed: %d:%d, was %d:%d", u, g, uid, gid)
	}
	if left, _ := filepath.Glob(filepath.Join(h.Dir(), ".fileparcel.toml.edit-*")); len(left) != 0 {
		t.Fatalf("temporary copies left: %v", left)
	}
}

// doctor reports files the home's account does not own; --fix gives them
// back, but only as root.
func TestDoctorOwnership(t *testing.T) {
	lcIsolateHost(t)
	h := lcBareHome(t)
	rep, _ := lcDoctorJSON(t, h)
	if st := lcStatuses(rep); st["ownership"] != lcOK {
		t.Fatalf("own home: %v", st)
	}

	// Pretend the home belongs to another account.
	ownerOf := lcOwnerOf
	t.Cleanup(func() { lcOwnerOf = ownerOf })
	lcOwnerOf = func(h *home.Home) (homeOwner, bool) {
		return homeOwner{uid: os.Getuid() + 1, gid: os.Getgid(), name: "svcacct"}, true
	}
	check := func(rep lcDoctorReport) lcCheck {
		t.Helper()
		for _, c := range rep.Checks {
			if c.ID == "ownership" {
				return c
			}
		}
		t.Fatalf("no ownership check: %+v", rep.Checks)
		return lcCheck{}
	}
	calls := lcFakeRoot(t, nil, false)
	lcGeteuid = func() int { return 1000 }
	rep, _ = lcDoctorJSON(t, h, "--fix")
	c := check(rep)
	if c.Status != lcWarn || c.Fixed || !strings.Contains(c.Message, "not owned by svcacct") ||
		!strings.Contains(c.Hint, "sudo fileparcel doctor --fix") || len(*calls) != 0 {
		t.Fatalf("not root: %+v (%d calls)", c, len(*calls))
	}

	lcGeteuid = func() int { return 0 }
	rep, _ = lcDoctorJSON(t, h, "--fix")
	if c = check(rep); c.Status != lcOK || !c.Fixed || len(*calls) != 1 || (*calls)[0].name != "svcacct" {
		t.Fatalf("root --fix: %+v (%+v)", c, *calls)
	}
}

func TestForeignEntries(t *testing.T) {
	h := lcBareHome(t)
	me := homeOwner{uid: os.Getuid(), gid: os.Getgid()}
	if n, first, partial := lcForeignEntries(h, me); n != 0 || first != nil || partial {
		t.Fatalf("own home: %d %v %v", n, first, partial)
	}
	other := homeOwner{uid: os.Getuid() + 1, gid: os.Getgid(), system: true}
	n, first, _ := lcForeignEntries(h, other)
	if n == 0 || len(first) != 3 || first[0] == "./" {
		t.Fatalf("foreign: %d %v", n, first)
	}
	// bin/ and uninstall.sh stay root's on a system install; symlinks are
	// never changed; a new file counts.
	for _, p := range []string{filepath.Join(h.BinDir(), "fileparcel"), h.UninstallScript(), filepath.Join(h.DataDir(), "x")} {
		if err := os.WriteFile(p, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink("/etc/passwd", filepath.Join(h.DataDir(), "link")); err != nil {
		t.Fatal(err)
	}
	if n2, _, _ := lcForeignEntries(h, other); n2 != n+1 {
		t.Fatalf("after adding bin/, uninstall.sh, a symlink and one file: %d, want %d", n2, n+1)
	}
	// A directory this user cannot read: said, not counted as checked.
	if os.Geteuid() != 0 {
		if err := os.Chmod(h.KeysDir(), 0); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.Chmod(h.KeysDir(), 0o700) })
		if _, _, partial := lcForeignEntries(h, me); !partial {
			t.Fatal("unreadable keys/ not reported")
		}
	}
}

// As root for real: what an offline command writes ends up owned by the
// home's account.
func TestOfflineAsRootGivesFilesBack(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root")
	}
	lcIsolateHost(t)
	h, _ := lcInitTestHome(t)
	if err := svc.ChownTree(h.Dir(), 65534, 65534); err != nil {
		t.Skip(err)
	}
	c, err := Connect(Options{Home: h.Dir(), Offline: true})
	if err != nil {
		t.Fatal(err)
	}
	written := filepath.Join(h.DataDir(), "written-as-root")
	if err := os.WriteFile(written, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	_ = c.Close()
	for _, p := range []string{written, h.Config(), h.KeysFile(), h.DB()} {
		if u, g := lcStatOwner(t, p); u != 65534 || g != 65534 {
			t.Errorf("%s is %d:%d", p, u, g)
		}
	}
}
