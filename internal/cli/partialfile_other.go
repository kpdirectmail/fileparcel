//go:build !unix

package cli

import "io/fs"

// ownPrivateFile is the non-unix variant: file modes carry no owner or link
// count there, so any regular file (never a symlink) qualifies.
func ownPrivateFile(fi fs.FileInfo) bool { return fi.Mode().IsRegular() }
