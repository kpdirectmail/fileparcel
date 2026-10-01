//go:build linux

package blobstore

import (
	"errors"
	"os"
	"syscall"

	"golang.org/x/sys/unix"
)

// preallocate reserves n bytes for f (fallocate; falls back to Truncate on
// file systems without support).
func preallocate(f *os.File, n int64) error {
	if n <= 0 {
		return f.Truncate(n)
	}
	return fallocFallback(unix.Fallocate(int(f.Fd()), 0, 0, n), func() error { return f.Truncate(n) })
}

// fallocFallback decides what a failed fallocate means: a full disk or an
// exhausted quota (isNoSpace) is returned, so the upload is refused up
// front, while anything else is taken for "not supported by this file
// system" and truncate sets the size instead (sparse). Truncating after an
// EDQUOT would succeed without reserving a block and skip the reservation
// exactly when it matters.
func fallocFallback(err error, truncate func() error) error {
	if err == nil {
		return nil
	}
	if isNoSpace(err) {
		return err
	}
	return truncate()
}

// isNoSpace reports a full disk (or an exhausted disk quota).
func isNoSpace(err error) bool {
	return errors.Is(err, syscall.ENOSPC) || errors.Is(err, syscall.EDQUOT)
}
