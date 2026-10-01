//go:build unix && !linux

package keys

// dontDump is a no-op where MADV_DONTDUMP does not exist.
func dontDump([]byte) {}
