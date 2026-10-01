//go:build linux || darwin || freebsd

package opsapi

import "syscall"

// diskUsage returns the size and the space available to unprivileged users
// of the filesystem holding path (zeros when unknown).
func diskUsage(path string) (size, free int64) {
	var st syscall.Statfs_t
	if err := syscall.Statfs(path, &st); err != nil {
		return 0, 0
	}
	bs := int64(st.Bsize) //nolint:unconvert // the field type differs per OS
	return int64(st.Blocks) * bs, int64(st.Bavail) * bs
}
