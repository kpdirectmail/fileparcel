package netinfo

import (
	"bufio"
	"bytes"
	"net"
	"net/netip"
	"strings"
)

// systemInterfaces enumerates the host's interfaces with their addresses
// (net.Interfaces). IPv4 addresses are unmapped and IPv6 zones dropped.
func systemInterfaces() ([]rawIface, error) {
	ifs, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	out := make([]rawIface, 0, len(ifs))
	for _, ifc := range ifs {
		r := rawIface{Name: ifc.Name, Index: ifc.Index, Flags: ifc.Flags, MTU: ifc.MTU, Wireless: isWireless(ifc.Name)}
		r.DevType, r.IsTun, r.Master = sysfsInfo(ifc.Name)
		addrs, err := ifc.Addrs()
		if err == nil {
			for _, a := range addrs {
				if p, ok := prefixOf(a); ok {
					r.Addrs = append(r.Addrs, p)
				}
			}
		}
		out = append(out, r)
	}
	return out, nil
}

// prefixOf converts a net.Addr of net.Interface.Addrs to a netip.Prefix.
func prefixOf(a net.Addr) (netip.Prefix, bool) {
	var (
		ip   net.IP
		bits int
	)
	switch v := a.(type) {
	case *net.IPNet:
		ip = v.IP
		bits, _ = v.Mask.Size()
	case *net.IPAddr:
		ip = v.IP
		bits = -1
	default:
		return netip.Prefix{}, false
	}
	addr, ok := netip.AddrFromSlice(ip)
	if !ok {
		return netip.Prefix{}, false
	}
	mapped := addr.Is4In6()
	addr = addr.Unmap().WithZone("")
	// net.IPNet masks of IPv4 addresses may be 128-bit (IPv4-in-IPv6 form).
	if addr.Is4() && bits > 32 && (mapped || len(ip) == net.IPv6len) {
		bits -= 96
	}
	if bits < 0 || bits > addr.BitLen() {
		bits = addr.BitLen()
	}
	return netip.PrefixFrom(addr, bits), true
}

// safeIfName reports whether an interface name can be used in a sysfs path.
func safeIfName(name string) bool {
	return name != "" && name != "." && name != ".." && !strings.ContainsAny(name, "/\x00")
}

// ueventDevType returns the DEVTYPE= value of a sysfs uevent file.
func ueventDevType(b []byte) string {
	sc := bufio.NewScanner(bytes.NewReader(b))
	for sc.Scan() {
		if v, ok := strings.CutPrefix(sc.Text(), "DEVTYPE="); ok {
			return strings.ToLower(strings.TrimSpace(v))
		}
	}
	return ""
}
