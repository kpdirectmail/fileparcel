package netinfo

import (
	"context"
	"net/netip"
	"syscall"

	"golang.org/x/net/route"
)

// systemDefaultRouteIfaces reads the routing table through a routing socket
// and returns the interfaces that carry the effective default route
// (DESIGN §10.1): a zero destination with a zero or missing netmask, or both
// def1 halves; routes scoped to an interface (RTF_IFSCOPE) are ignored.
func systemDefaultRouteIfaces(ctx context.Context) (map[int]bool, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	b, err := route.FetchRIB(syscall.AF_UNSPEC, route.RIBTypeRoute, 0)
	if err != nil {
		return nil, err
	}
	msgs, err := route.ParseRIB(route.RIBTypeRoute, b)
	if err != nil {
		return nil, err
	}
	var rs []bsdRoute
	for _, m := range msgs {
		rm, ok := m.(*route.RouteMessage)
		if !ok || rm.Flags&syscall.RTF_UP == 0 || len(rm.Addrs) <= syscall.RTAX_DST {
			continue
		}
		var mask route.Addr
		if len(rm.Addrs) > syscall.RTAX_NETMASK {
			mask = rm.Addrs[syscall.RTAX_NETMASK]
		}
		if dst, ok := bsdPrefix(rm.Addrs[syscall.RTAX_DST], mask); ok {
			rs = append(rs, bsdRoute{flags: rm.Flags, index: rm.Index, dst: dst})
		}
	}
	return bsdDefaultRouteIfaces(rs), nil
}

// bsdPrefix converts a routing-socket destination and netmask to a prefix
// (a missing netmask means a host route, except for the zero destination,
// which the kernel stores without one).
func bsdPrefix(dst, mask route.Addr) (netip.Prefix, bool) {
	var a netip.Addr
	var bits int
	switch d := dst.(type) {
	case *route.Inet4Addr:
		a = netip.AddrFrom4(d.IP)
		bits = 32
		if m, ok := mask.(*route.Inet4Addr); ok {
			bits = maskBits(m.IP[:])
		} else if a.IsUnspecified() {
			bits = 0
		}
	case *route.Inet6Addr:
		a = netip.AddrFrom16(d.IP)
		bits = 128
		if m, ok := mask.(*route.Inet6Addr); ok {
			bits = maskBits(m.IP[:])
		} else if a.IsUnspecified() {
			bits = 0
		}
	default:
		return netip.Prefix{}, false
	}
	p, err := a.Prefix(bits)
	return p, err == nil
}

// maskBits counts the leading one bits of a netmask.
func maskBits(m []byte) int {
	n := 0
	for _, b := range m {
		for i := 7; i >= 0; i-- {
			if b&(1<<i) == 0 {
				return n
			}
			n++
		}
	}
	return n
}
