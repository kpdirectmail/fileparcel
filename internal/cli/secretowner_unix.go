//go:build unix

package cli

import (
	"io/fs"
	"os"
	"syscall"
)

// canChangeMode reports whether this process could chmod fi: it owns the file,
// or it is root. A secret bind-mounted into a container (/run/secrets/…) is
// owned by somebody else and cannot be chmod'ed here, so no permission warning
// is printed for it (the documented Docker bootstrap needs a world-readable
// secret so the container's uid 65532 can read it; see DESIGN §14.7).
func canChangeMode(fi fs.FileInfo) bool {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return true
	}
	uid := os.Geteuid()
	return uid == 0 || uint32(uid) == st.Uid
}

// fileOwner returns the owner, group and link count of fi (ok false when
// the file system reports none).
func fileOwner(fi fs.FileInfo) (uid, gid uint32, nlink uint64, ok bool) {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, 0, 0, false
	}
	return st.Uid, st.Gid, uint64(st.Nlink), true
}
