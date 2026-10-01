//go:build !unix

package keys

// sysAlloc returns heap memory: mlock is not available on this platform.
func sysAlloc(n int) (mem []byte, mapped, mlocked bool) { return make([]byte, n), false, false }

// sysFree zeroes mem.
func sysFree(mem []byte, _, _ bool) { clear(mem) }
