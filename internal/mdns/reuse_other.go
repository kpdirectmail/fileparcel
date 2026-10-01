//go:build !unix

package mdns

import "syscall"

// reusePort is a no-op where SO_REUSEPORT does not exist.
func reusePort(_, _ string, _ syscall.RawConn) error { return nil }
