package tsingress

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"net/netip"
	"strconv"
	"strings"
)

// parseProcNetListen returns the LISTEN sockets on port of a
// /proc/net/tcp or /proc/net/tcp6 table (port.shadow). Addresses are hex
// 32-bit words in host (little-endian) order, ports big-endian hex.
func parseProcNetListen(data []byte, port int) []netip.AddrPort {
	var out []netip.AddrPort
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 0, 4096), 1<<20)
	first := true
	for sc.Scan() {
		if first { // header
			first = false
			continue
		}
		f := strings.Fields(sc.Text())
		if len(f) < 4 || f[3] != "0A" { // TCP_LISTEN
			continue
		}
		host, p, ok := strings.Cut(f[1], ":")
		if !ok {
			continue
		}
		pn, err := strconv.ParseUint(p, 16, 16)
		if err != nil || int(pn) != port {
			continue
		}
		if ip, ok := parseProcAddr(host); ok {
			out = append(out, netip.AddrPortFrom(ip.Unmap(), uint16(pn)))
		}
	}
	return out
}

// parseProcAddr decodes an address of /proc/net/tcp{,6}.
func parseProcAddr(h string) (netip.Addr, bool) {
	b, err := hex.DecodeString(h)
	if err != nil || (len(b) != 4 && len(b) != 16) {
		return netip.Addr{}, false
	}
	for i := 0; i < len(b); i += 4 {
		b[i], b[i+1], b[i+2], b[i+3] = b[i+3], b[i+2], b[i+1], b[i]
	}
	ip, ok := netip.AddrFromSlice(b)
	return ip, ok
}
