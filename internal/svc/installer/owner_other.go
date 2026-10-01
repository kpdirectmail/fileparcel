//go:build !unix

package installer

// fileOwner is not known on this platform.
func fileOwner(string) (int, bool) { return 0, false }
