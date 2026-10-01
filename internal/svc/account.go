package svc

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/user"
	"regexp"
	"strconv"
	"strings"

	"fileparcel/internal/home"
)

// System service accounts (DESIGN §14.4, §14.5): Linux `useradd --system`
// (or busybox `adduser -S` on Alpine), macOS a hidden role account created
// with dscl in the UID range 400–499.

var accountNameRe = regexp.MustCompile(`^_?[a-z][a-z0-9_-]{0,30}$`)

// lookupUser is user.Lookup (tests replace it).
var lookupUser = user.Lookup

// UserExists reports whether an account exists.
func UserExists(name string) bool {
	_, err := lookupUser(name)
	return err == nil
}

// AccountIDs returns the uid and gid of an account.
func AccountIDs(name string) (uid, gid int, err error) {
	u, err := lookupUser(name)
	if err != nil {
		return 0, 0, err
	}
	uid, err1 := strconv.Atoi(u.Uid)
	gid, err2 := strconv.Atoi(u.Gid)
	if err1 != nil || err2 != nil {
		return 0, 0, fmt.Errorf("svc: account %s has non-numeric ids", name)
	}
	return uid, gid, nil
}

// SystemUserCommands returns the commands that create the service account
// name with home dir home on h (without running them). On macOS uid/gid are
// chosen by FreeMacID first; pass them in id.
func SystemUserCommands(h *Host, name, homeDir string, id int) ([][]string, error) {
	if !accountNameRe.MatchString(name) {
		return nil, fmt.Errorf("svc: invalid account name %q", name)
	}
	switch h.GOOS {
	case "linux":
		shell := "/usr/sbin/nologin"
		if _, err := os.Stat(shell); err != nil {
			shell = "/sbin/nologin"
		}
		if h.Has("useradd") {
			return [][]string{{"useradd", "--system", "--home-dir", homeDir, "--no-create-home",
				"--shell", shell, "--user-group", name}}, nil
		}
		if h.Has("adduser") && h.Has("addgroup") {
			return [][]string{
				{"addgroup", "-S", name},
				{"adduser", "-S", "-D", "-H", "-h", homeDir, "-s", shell, "-G", name, name},
			}, nil
		}
		return nil, errors.New("svc: neither useradd nor adduser is available to create the service account")
	case "darwin":
		if id < 400 || id > 499 {
			return nil, fmt.Errorf("svc: role account id %d outside 400-499", id)
		}
		ids := strconv.Itoa(id)
		g, u := "/Groups/"+name, "/Users/"+name
		return [][]string{
			{"dscl", ".", "-create", g},
			{"dscl", ".", "-create", g, "PrimaryGroupID", ids},
			{"dscl", ".", "-create", g, "RealName", "FileParcel"},
			{"dscl", ".", "-create", g, "Password", "*"},
			{"dscl", ".", "-create", u},
			{"dscl", ".", "-create", u, "UniqueID", ids},
			{"dscl", ".", "-create", u, "PrimaryGroupID", ids},
			{"dscl", ".", "-create", u, "UserShell", "/usr/bin/false"},
			{"dscl", ".", "-create", u, "NFSHomeDirectory", homeDir},
			{"dscl", ".", "-create", u, "RealName", "FileParcel server"},
			{"dscl", ".", "-create", u, "Password", "*"},
			{"dscl", ".", "-create", u, "IsHidden", "1"},
		}, nil
	}
	return nil, fmt.Errorf("svc: creating service accounts is not supported on %s", h.GOOS)
}

// FreeMacID returns the lowest id in 400–499 unused as UniqueID and as
// PrimaryGroupID (from `dscl . -list /Users UniqueID` / `/Groups PrimaryGroupID`).
func FreeMacID(ctx context.Context, h *Host) (int, error) {
	used := map[int]bool{}
	for _, q := range [][]string{{".", "-list", "/Users", "UniqueID"}, {".", "-list", "/Groups", "PrimaryGroupID"}} {
		res, err := h.run(ctx, nil, "dscl", q...)
		if err != nil {
			return 0, err
		}
		sc := bufio.NewScanner(bytes.NewReader(res.Stdout))
		for sc.Scan() {
			f := strings.Fields(sc.Text())
			if len(f) >= 2 {
				if n, err := strconv.Atoi(f[len(f)-1]); err == nil {
					used[n] = true
				}
			}
		}
	}
	for id := 400; id <= 499; id++ {
		if !used[id] {
			return id, nil
		}
	}
	return 0, errors.New("svc: no free id in 400-499 for the role account")
}

// EnsureSystemUser creates the service account unless it exists. created
// reports whether it was created now (recorded in installed.json so
// `uninstall --remove-user` only deletes accounts the installer made).
func EnsureSystemUser(ctx context.Context, h *Host, name, homeDir string) (created bool, err error) {
	if UserExists(name) {
		return false, nil
	}
	if !h.Root() {
		return false, errors.New("svc: creating the service account needs root")
	}
	id := 0
	if h.GOOS == "darwin" {
		if id, err = FreeMacID(ctx, h); err != nil {
			return false, err
		}
	}
	cmds, err := SystemUserCommands(h, name, homeDir, id)
	if err != nil {
		return false, err
	}
	for _, c := range cmds {
		if _, err := h.run(ctx, nil, c[0], c[1:]...); err != nil {
			return false, err
		}
	}
	return true, nil
}

// RemoveSystemUser deletes the service account (and its group). Only the
// service accounts the installer creates (fileparcel, _fileparcel) are ever
// deleted, never an account with uid 0: the name comes from installed.json,
// which the service account itself can write on system installs.
func RemoveSystemUser(ctx context.Context, h *Host, name string) error {
	if !accountNameRe.MatchString(name) {
		return fmt.Errorf("svc: invalid account name %q", name)
	}
	if name != DefaultSystemUser && name != DefaultMacSystemUser {
		return fmt.Errorf("svc: refusing to delete %q: only the service account %s (%s on macOS) is removed", name,
			DefaultSystemUser, DefaultMacSystemUser)
	}
	if !UserExists(name) {
		return nil
	}
	if uid, _, err := AccountIDs(name); err != nil || uid == 0 {
		return fmt.Errorf("svc: refusing to delete the account %s (uid 0 or unknown)", name)
	}
	var cmds [][]string
	switch h.GOOS {
	case "linux":
		if h.Has("userdel") {
			cmds = [][]string{{"userdel", name}}
		} else {
			cmds = [][]string{{"deluser", name}, {"delgroup", name}}
		}
	case "darwin":
		cmds = [][]string{{"dscl", ".", "-delete", "/Users/" + name}, {"dscl", ".", "-delete", "/Groups/" + name}}
	default:
		return fmt.Errorf("svc: removing accounts is not supported on %s", h.GOOS)
	}
	var errs []error
	for _, c := range cmds {
		if _, err := h.run(ctx, nil, c[0], c[1:]...); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// lchown and chown are os.Lchown and os.Chown, fchown is (*os.File).Chown
// (tests replace them); chownVisit, when set, is called with each entry a
// ChownTree walk has looked at and is about to open (tests change the tree
// there).
var (
	lchown     = os.Lchown
	chown      = os.Chown
	fchown     = (*os.File).Chown
	chownVisit func(p string)
)

// ChownTree gives root and the tree below it to uid:gid, except the files
// and directories in skip (and everything below them), which are left
// alone. A symlinked root (a home moved to another disk and linked back) is
// followed; nothing below it is.
//
// Root runs this on trees the service account owns and can change while
// they are walked (`service install --system` on a live system home), so
// the walk never resolves a path again: each directory is opened relative
// to its parent's descriptor with O_NOFOLLOW, and each file is opened the
// same way and changed with fchown — an entry swapped for a symlink (to
// /etc, or to the root-owned bin/) after it was listed is left alone
// instead of followed. skip is matched by identity (device and inode), so
// no other name for bin/ reaches it either. Symlinks, sockets, FIFOs and
// devices are left alone, and so is a file with several hard links that
// uid does not own already: where hard links are not protected (macOS,
// fs.protected_hardlinks=0) the account could link a file of root's into
// the tree.
func ChownTree(root string, uid, gid int, skip ...string) error {
	return chownTree(root, true, uid, gid, skip)
}

// SecureSystemHome sets the ownership of a system install (DESIGN §14.4):
// everything in HOME belongs to the service account uid:gid except bin/ and
// uninstall.sh, which root runs (`sudo fileparcel …`, the uninstaller) and
// which stay owned by root, and HOME itself, which LockSystemHome makes
// root:gid 01770 — first, so the account cannot rename bin/ while the tree
// is walked. A symlinked HOME is followed; nothing below it is (see
// ChownTree).
func SecureSystemHome(h *home.Home, uid, gid int) error {
	if err := LockSystemHome(h, gid); err != nil {
		return err
	}
	return chownTree(h.Dir(), false, uid, gid, []string{h.BinDir(), h.UninstallScript()})
}

// LockSystemHome makes the HOME of a system install root:gid with mode
// home.ModeSystemHome (01770), and bin/ and uninstall.sh owned by root. The
// service account needs to write in HOME itself (fileparcel.toml replaced
// atomically, pre-restore-*/ and the items a restore swaps), which group
// write allows; the sticky bit keeps it from renaming or replacing what it
// does not own there. Owning HOME, it could otherwise move the root-owned
// bin/ aside (a rename within one directory needs write permission on that
// directory only) and put its own fileparcel binary — or its own
// uninstall.sh — where root runs it. The tree below is not walked (upgrades
// run this on homes the service account has been writing to).
func LockSystemHome(h *home.Home, gid int) error {
	if err := chown(h.Dir(), 0, gid); err != nil { // follows a symlinked HOME
		return err
	}
	if err := os.Chmod(h.Dir(), home.ModeSystemHome); err != nil {
		return err
	}
	// Lchown: a symlink planted in their place is never followed.
	for _, p := range []string{h.BinDir(), h.UninstallScript()} {
		if err := lchown(p, 0, 0); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return err
		}
	}
	return nil
}
