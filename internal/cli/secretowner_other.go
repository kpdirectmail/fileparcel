//go:build !unix

package cli

import "io/fs"

// canChangeMode is the non-unix stub: file modes carry no owner there, so the
// permission warning is always printed.
func canChangeMode(fs.FileInfo) bool { return true }

// fileOwner is the non-unix stub: files carry no uid/gid there.
func fileOwner(fs.FileInfo) (uid, gid uint32, nlink uint64, ok bool) { return 0, 0, 0, false }
