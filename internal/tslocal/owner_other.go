//go:build !unix

package tslocal

// fileOwner returns -1: file owners are not uids here.
func fileOwner(string) int { return -1 }
