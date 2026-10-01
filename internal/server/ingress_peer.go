package server

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"net/netip"
	"strconv"
	"strings"
)

// procNetPeerUID finds, in a /proc/net/tcp or /proc/net/tcp6 table, the
// socket whose local address is peer and whose remote address is local —
// the other end of a loopback connection this process accepted — and
// returns the uid owning it. Addresses are hex 32-bit words in host byte
// order (order), ports big-endian hex; IPv4-mapped IPv6 addresses (a
// dual-stack peer socket in tcp6) match their IPv4 form.
func procNetPeerUID(table []byte, peer, local netip.AddrPort, order binary.AppendByteOrder) (int, bool) {
	peer = netip.AddrPortFrom(peer.Addr().Unmap(), peer.Port())
	local = netip.AddrPortFrom(local.Addr().Unmap(), local.Port())
	sc := bufio.NewScanner(bytes.NewReader(table))
	sc.Buffer(make([]byte, 0, 4096), 1<<20)
	for first := true; sc.Scan(); first = false {
		if first { // header
			continue
		}
		f := strings.Fields(sc.Text())
		if len(f) < 8 {
			continue
		}
		la, ok1 := parseProcNetAddrPort(f[1], order)
		ra, ok2 := parseProcNetAddrPort(f[2], order)
		if !ok1 || !ok2 || la != peer || ra != local {
			continue
		}
		uid, err := strconv.Atoi(f[7])
		if err != nil || uid < 0 {
			return -1, false
		}
		return uid, true
	}
	return -1, false
}

// parseProcNetAddrPort decodes "0100007F:1F90" (IPv4) or the 32-digit IPv6
// form; the address comes back unmapped.
func parseProcNetAddrPort(s string, order binary.AppendByteOrder) (netip.AddrPort, bool) {
	hexAddr, hexPort, ok := strings.Cut(s, ":")
	if !ok || (len(hexAddr) != 8 && len(hexAddr) != 32) || len(hexPort) != 4 {
		return netip.AddrPort{}, false
	}
	b := make([]byte, 0, 16)
	for i := 0; i < len(hexAddr); i += 8 {
		w, err := strconv.ParseUint(hexAddr[i:i+8], 16, 32)
		if err != nil {
			return netip.AddrPort{}, false
		}
		b = order.AppendUint32(b, uint32(w))
	}
	port, err := strconv.ParseUint(hexPort, 16, 16)
	if err != nil {
		return netip.AddrPort{}, false
	}
	ip, ok := netip.AddrFromSlice(b)
	if !ok {
		return netip.AddrPort{}, false
	}
	return netip.AddrPortFrom(ip.Unmap(), uint16(port)), true
}
