//go:build linux

package tsingress

import (
	"io"
	"net/netip"
	"os"
)

// maxProcNet bounds one /proc/net table read.
const maxProcNet = 16 << 20

// listeningOn returns the local LISTEN sockets on port (IPv4 and IPv6).
func listeningOn(port int) ([]netip.AddrPort, bool) {
	var out []netip.AddrPort
	known := false
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
		known = true
		out = append(out, parseProcNetListen(b, port)...)
	}
	return out, known
}
