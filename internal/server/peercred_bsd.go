//go:build darwin || freebsd

package server

import (
	"net"

	"golang.org/x/sys/unix"
)

// sunPathMax is sizeof(sockaddr_un.sun_path) on macOS and FreeBSD.
const sunPathMax = 104

// peerUID returns the uid of the process on the other end of c
// (LOCAL_PEERCRED).
func peerUID(c *net.UnixConn) (int, error) {
	raw, err := c.SyscallConn()
	if err != nil {
		return -1, err
	}
	var (
		cred *unix.Xucred
		serr error
	)
	if err := raw.Control(func(fd uintptr) {
		cred, serr = unix.GetsockoptXucred(int(fd), unix.SOL_LOCAL, unix.LOCAL_PEERCRED)
	}); err != nil {
		return -1, err
	}
	if serr != nil {
		return -1, serr
	}
	return int(cred.Uid), nil
}
