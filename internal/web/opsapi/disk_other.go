//go:build !(linux || darwin || freebsd)

package opsapi

// diskUsage is unknown on this platform. (OpenBSD names the syscall.Statfs_t
// fields F_bsize/F_blocks/F_bavail and NetBSD has no syscall.Statfs at all,
// so disk_unix.go does not build there.)
func diskUsage(path string) (size, free int64) { return 0, 0 }
