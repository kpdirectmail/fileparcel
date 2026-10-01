//go:build linux

package server

import (
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
	"os"
)

// maxProcNet bounds one read of /proc/net/tcp{,6}.
const maxProcNet = 16 << 20

// loopbackPeerUID returns the uid of the process on the other end of an
// accepted loopback TCP connection: the owner of the socket whose local
// address is c's remote address and whose remote address is c's local
// address, looked up in /proc/net/tcp and then /proc/net/tcp6 (a dual-stack
// client socket). A missing row is an error (the connection is refused).
func loopbackPeerUID(c net.Conn) (int, error) {
	peer, err1 := netip.ParseAddrPort(c.RemoteAddr().String())
	local, err2 := netip.ParseAddrPort(c.LocalAddr().String())
	if err1 != nil || err2 != nil {
		return -1, errors.New("not a TCP connection")
	}
	for _, p := range []string{"/proc/net/tcp", "/proc/net/tcp6"} {
		f, err := os.Open(p)
		if err != nil {
			continue
		}
		b, err := io.ReadAll(io.LimitReader(f, maxProcNet))
		_ = f.Close()
		if err != nil {
			continue
		}
		if uid, ok := procNetPeerUID(b, peer, local, binary.NativeEndian); ok {
			return uid, nil
		}
	}
	return -1, errors.New("the peer socket is not in /proc/net/tcp")
}
