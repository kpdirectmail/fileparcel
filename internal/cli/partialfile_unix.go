//go:build unix

package cli

import (
	"io/fs"
	"os"
	"syscall"
)

// ownPrivateFile reports whether fi (from os.Lstat) is a regular file that
// this process's user owns and that has no other hard link: the only kind of
// partial download a later run continues. Anything else next to the
// destination — a symlink or hard link to another file, or a file somebody
// else planted in a shared directory — would receive (and could expose) the
// downloaded bytes.
func ownPrivateFile(fi fs.FileInfo) bool {
	if !fi.Mode().IsRegular() {
		return false
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return true
	}
	return int64(st.Uid) == int64(os.Geteuid()) && st.Nlink <= 1
}
