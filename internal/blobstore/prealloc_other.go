//go:build !linux

package blobstore

import (
	"errors"
	"os"
	"syscall"
)

// preallocate sets the file size to n (sparse on most file systems).
func preallocate(f *os.File, n int64) error { return f.Truncate(n) }

// isNoSpace reports a full disk (or an exhausted disk quota).
func isNoSpace(err error) bool {
	return errors.Is(err, syscall.ENOSPC) || errors.Is(err, syscall.EDQUOT)
}
