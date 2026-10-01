//go:build unix

package keys

import "golang.org/x/sys/unix"

// sysAlloc maps n bytes of anonymous memory outside the Go heap, excludes it
// from core dumps (Linux) and tries to mlock it. It falls back to a heap
// slice when mmap fails.
func sysAlloc(n int) (mem []byte, mapped, mlocked bool) {
	mem, err := unix.Mmap(-1, 0, n, unix.PROT_READ|unix.PROT_WRITE, unix.MAP_ANON|unix.MAP_PRIVATE)
	if err != nil {
		return make([]byte, n), false, false
	}
	dontDump(mem)
	return mem, true, unix.Mlock(mem) == nil
}

// sysFree zeroes mem and unmaps it.
func sysFree(mem []byte, mapped, mlocked bool) {
	clear(mem)
	if !mapped {
		return
	}
	if mlocked {
		_ = unix.Munlock(mem)
	}
	_ = unix.Munmap(mem)
}
