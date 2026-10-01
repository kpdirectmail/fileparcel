//go:build !linux

package backup

// lockHolders cannot determine lock owners on this platform.
func lockHolders(path string) (pids []int, ok bool) { return nil, false }
