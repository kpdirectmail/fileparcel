package cli

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/user"
	"path/filepath"
	"runtime"
	"strconv"
	"sync"

	"fileparcel/internal/home"
	"fileparcel/internal/svc"
)

// Admin commands may run as root (`sudo fileparcel …`, the documented way on
// a system install), and with the server stopped they work in-process on
// the home. Files root creates there are root:root 0600/0700 (umask 077),
// which the server — running as the home's account — cannot read: a
// restore's data/, keys/, certs/ and fileparcel.toml, a new key or
// certificate, blobs, backups, a rotated log. So what such a command wrote
// is given back to that account before the home lock is released
// (lockHome), `config edit` keeps the file's owner (keepOwner), and doctor
// reports and repairs what is left (checkOwner).

// homeOwner is the account a FileParcel home belongs to (DESIGN §14.4).
type homeOwner struct {
	uid, gid int
	name     string // for messages
	system   bool   // a system install: HOME itself stays root:<gid> 01770
}

// Test hooks: the effective uid, the account lookup of a system install,
// the home owner lookup, the repair and where its failure is reported.
var (
	lcGeteuid               = os.Geteuid
	lcAccountIDs            = svc.AccountIDs
	lcOwnerOf               = lcHomeOwner
	lcGiveHome              = giveHomeBack
	lcOwnerStderr io.Writer = os.Stderr
)

// lcHomeOwner returns the account that owns h: on a system install (HOME
// root:<service group> 01770) the host's service account — never a name
// read from installed.json, which that account can write — and otherwise
// the owner of HOME when it is not root (a user install, a container's
// uid, a system home from before HOME became root's). ok is false for a
// home root owns itself, and where files carry no owner.
func lcHomeOwner(h *home.Home) (o homeOwner, ok bool) {
	fi, err := os.Stat(h.Dir()) // a symlinked HOME is followed
	if err != nil {
		return o, false
	}
	uid, gid, _, ok := fileOwner(fi)
	if !ok {
		return o, false
	}
	return lcOwnerFromStat(uid, gid, fi.Mode())
}

// lcOwnerFromStat is lcHomeOwner for a HOME owned by uid:gid with mode.
func lcOwnerFromStat(uid, gid uint32, mode fs.FileMode) (o homeOwner, ok bool) {
	switch {
	case uid != 0:
		return homeOwner{uid: int(uid), gid: int(gid), name: lcAccountName(uid)}, true
	case home.IsSystemHomeMode(mode):
		name := svc.ServiceUser(&svc.Host{GOOS: runtime.GOOS})
		u, g, err := lcAccountIDs(name)
		if err != nil || u == 0 || g != int(gid) {
			return o, false // not the account the home was given to: guess nothing
		}
		return homeOwner{uid: u, gid: g, name: name, system: true}, true
	}
	return o, false
}

// lcAccountName returns the name of uid (the number when it has none).
func lcAccountName(uid uint32) string {
	id := strconv.FormatUint(uint64(uid), 10)
	if u, err := user.LookupId(id); err == nil && u.Username != "" {
		return u.Username
	}
	return "uid " + id
}

// giveHomeBack gives everything in h but bin/ and uninstall.sh (root's on a
// system install) to o. Entries o owns already are left alone, and the walk
// never follows a symlink (svc.ChownTree, svc.SecureSystemHome).
func giveHomeBack(h *home.Home, o homeOwner) error {
	if o.system {
		return svc.SecureSystemHome(h, o.uid, o.gid)
	}
	return svc.ChownTree(h.Dir(), o.uid, o.gid, h.BinDir(), h.UninstallScript())
}

// lockHome takes the home lock (h.Lock). When root takes it on a home that
// belongs to another account, the returned unlock first gives what the
// command wrote there back to that account, still under the lock; a
// failure is reported on stderr with the repair command. The owner is
// looked up before anything is written.
func lockHome(h *home.Home) (unlock func(), err error) {
	var o homeOwner
	own := false
	if lcGeteuid() == 0 {
		o, own = lcOwnerOf(h)
	}
	release, err := h.Lock()
	if err != nil || !own {
		return release, err
	}
	var once sync.Once
	return func() {
		once.Do(func() {
			if err := lcGiveHome(h, o); err != nil {
				fmt.Fprintf(lcOwnerStderr, "%s could not give the files this command wrote in %s back to %s (%v): "+
					"the server may not be able to read them; run \"sudo fileparcel doctor --fix\"\n",
					Yellow("warning:"), h.Dir(), o.name, err)
			}
			release()
		})
	}, nil
}

// keepOwner gives tmp the owner and group of orig, which a rename of tmp is
// about to replace: written by `sudo fileparcel config edit`, the copy is
// root's, and renamed over fileparcel.toml as it is, the server (running as
// the home's account) could no longer read its configuration.
func keepOwner(tmp, orig string) error {
	ofi, err := os.Stat(orig)
	if err != nil {
		return err
	}
	tfi, err := os.Lstat(tmp)
	if err != nil {
		return err
	}
	uid, gid, _, ok := fileOwner(ofi)
	if tuid, tgid, _, _ := fileOwner(tfi); !ok || (tuid == uid && tgid == gid) {
		return nil
	}
	if err := os.Lchown(tmp, int(uid), int(gid)); err != nil {
		return fmt.Errorf("cannot give the edited copy the owner of %s (%d:%d), so it was not saved: %w", orig, uid, gid, err)
	}
	return nil
}

// lcForeignEntries walks h (bin/ and uninstall.sh aside, as giveHomeBack)
// and returns how many directories and regular files o does not own, with
// the first few (relative paths). Like svc.ChownTree it ignores symlinks,
// sockets and other special files, a file with several hard links that o
// does not own, and HOME itself on a system install (root's). Directories
// it cannot read are skipped; partial says there were some.
func lcForeignEntries(h *home.Home, o homeOwner) (n int64, first []string, partial bool) {
	root, err := filepath.EvalSymlinks(h.Dir())
	if err != nil {
		return 0, nil, true
	}
	skip := map[string]bool{
		filepath.Join(root, "bin"):          true,
		filepath.Join(root, "uninstall.sh"): true,
	}
	_ = filepath.WalkDir(root, func(p string, e fs.DirEntry, err error) error {
		if err != nil {
			partial = partial || !errors.Is(err, fs.ErrNotExist)
			return nil // unreadable (its own entry was checked), or gone
		}
		if skip[p] {
			if e.IsDir() {
				return fs.SkipDir
			}
			return nil
		}
		if p == root && o.system {
			return nil
		}
		if !e.IsDir() && !e.Type().IsRegular() {
			return nil
		}
		fi, err := e.Info()
		if err != nil {
			return nil // gone since it was listed
		}
		uid, gid, nlink, ok := fileOwner(fi)
		if !ok || (int(uid) == o.uid && int(gid) == o.gid) || (!fi.IsDir() && nlink > 1 && int(uid) != o.uid) {
			return nil
		}
		n++
		if len(first) < 3 {
			rel, _ := filepath.Rel(root, p)
			if fi.IsDir() {
				rel += "/"
			}
			first = append(first, rel)
		}
		return nil
	})
	return n, first, partial
}
