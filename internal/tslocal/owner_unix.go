//go:build unix

package tslocal

import (
	"os"
	"syscall"
)

// fileOwner returns the uid owning path (-1 when unknown).
func fileOwner(path string) int {
	st, err := os.Stat(path)
	if err != nil {
		return -1
	}
	if sys, ok := st.Sys().(*syscall.Stat_t); ok {
		return int(sys.Uid)
	}
	return -1
}
