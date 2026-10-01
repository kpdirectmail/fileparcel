//go:build !unix

package backup

// diskFree is unknown on this platform.
func diskFree(path string) (free int64, ok bool) { return 0, false }

// processAlive is unknown on this platform (assume alive).
func processAlive(pid int) bool { return true }
