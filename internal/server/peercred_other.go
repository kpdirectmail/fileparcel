//go:build !linux && !darwin && !freebsd

package server

import (
	"errors"
	"net"
)

// sunPathMax is the portable lower bound of sockaddr_un.sun_path.
const sunPathMax = 104

// peerUID is unsupported on this platform: every admin-socket connection is
// refused (fail closed).
func peerUID(*net.UnixConn) (int, error) {
	return -1, errors.New("peer credentials are not supported on this platform")
}
