//go:build unix

package installer

import (
	"os"
	"syscall"
)

// fileOwner returns the uid owning p (not following a symlink).
func fileOwner(p string) (int, bool) {
	fi, err := os.Lstat(p)
	if err != nil {
		return 0, false
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, false
	}
	return int(st.Uid), true
}
