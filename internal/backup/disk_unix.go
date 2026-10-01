//go:build unix

package backup

import "golang.org/x/sys/unix"

// diskFree returns the bytes available to unprivileged users on the
// filesystem holding path (ok=false when unknown).
func diskFree(path string) (free int64, ok bool) {
	var st unix.Statfs_t
	if err := unix.Statfs(path, &st); err != nil {
		return 0, false
	}
	return int64(st.Bavail) * int64(st.Bsize), true //nolint:unconvert // field types differ per OS
}

// processAlive reports whether a process with pid exists.
func processAlive(pid int) bool {
	err := unix.Kill(pid, 0)
	return err == nil || err == unix.EPERM
}
