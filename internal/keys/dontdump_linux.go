//go:build linux

package keys

import "golang.org/x/sys/unix"

// dontDump excludes mem from core dumps (best effort).
func dontDump(mem []byte) { _ = unix.Madvise(mem, unix.MADV_DONTDUMP) }
