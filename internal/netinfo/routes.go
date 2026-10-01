package netinfo

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
)

// Effective default route (DESIGN §10.1): a generic tunnel (WireGuard,
// OpenVPN, IPsec, …) that carries it is an exit VPN or an internet uplink,
// not a network other devices come in through. The parsers here are
// portable (tests run them on captured dumps everywhere); routes_linux.go
// and routes_darwin.go read the kernel tables.

// kernelRoute is one unicast route: its table (Linux; 0 elsewhere), its
// destination and the interfaces it leaves through.
type kernelRoute struct {
	table  int
	dst    netip.Prefix
	ifaces []int
}

// Linux routing tables.
const (
	rtTableMain  = 254
	rtTableLocal = 255
)

// Halves of the address space that together replace a default route
// (OpenVPN's and wg-quick's "def1"): they win over a /0 by being longer.
var (
	def1V4 = [2]netip.Prefix{netip.MustParsePrefix("0.0.0.0/1"), netip.MustParsePrefix("128.0.0.0/1")}
	def1V6 = [2]netip.Prefix{netip.MustParsePrefix("::/1"), netip.MustParsePrefix("8000::/1")}
)

// defaultRouteIfaces returns the interfaces that carry a default route in
// one of tables (nil: every table): a /0 route, or both def1 halves of one
// family on the same interface in the same table.
func defaultRouteIfaces(routes []kernelRoute, tables map[int]bool) map[int]bool {
	out := map[int]bool{}
	type half struct{ table, iface, idx int }
	halves := map[half]bool{}
	for _, r := range routes {
		if tables != nil && !tables[r.table] {
			continue
		}
		if r.dst.Bits() == 0 {
			for _, i := range r.ifaces {
				out[i] = true
			}
			continue
		}
		for fam, pair := range [][2]netip.Prefix{def1V4, def1V6} {
			for k, p := range pair {
				if r.dst != p {
					continue
				}
				for _, i := range r.ifaces {
					halves[half{r.table, i, fam*2 + k}] = true
					if halves[half{r.table, i, fam*2 + 1 - k}] {
						out[i] = true
					}
				}
			}
		}
	}
	return out
}

// ---------- Linux rtnetlink dumps ----------

// rtnetlink message types, attributes and constants (linux/rtnetlink.h,
// linux/fib_rules.h), kept here so the parser builds on every system.
const (
	nlmsgHdrLen   = 16
	nlmsgError    = 2
	nlmsgDone     = 3
	rtmNewRoute   = 24
	rtmNewRule    = 32
	rtHdrLen      = 12 // struct rtmsg and struct fib_rule_hdr
	rtnUnicast    = 1
	rtaDst        = 1
	rtaOIF        = 4
	rtaMultipath  = 9
	rtaTable      = 15
	fraIIFName    = 3
	fraTable      = 15
	fraOIFName    = 17
	fraL3MDev     = 19
	fraUIDRange   = 20
	fraIPProto    = 22
	fraSPortRange = 23
	fraDPortRange = 24
	frActToTbl    = 1
	rtnhHdrLen    = 8 // struct rtnexthop
	nlaTypeMask   = 0x3fff
	maxNLMessages = 200_000
)

// errTooManyRoutes stops a dump parse after maxNLMessages messages.
var errTooManyRoutes = errors.New("more than 200000 routing messages")

// nlAlign rounds n up to the 4-byte netlink alignment.
func nlAlign(n int) int { return (n + 3) &^ 3 }

// nlMsg is one netlink message: its type and its payload.
type nlMsg struct {
	typ  int
	data []byte
}

// nlMessages splits a netlink dump into messages, stopping at NLMSG_DONE.
// An NLMSG_ERROR message with a non-zero errno is returned as an error.
func nlMessages(b []byte, bo binary.ByteOrder) ([]nlMsg, error) {
	var out []nlMsg
	for len(b) >= nlmsgHdrLen {
		l := int(bo.Uint32(b[0:4]))
		typ := int(bo.Uint16(b[4:6]))
		if l < nlmsgHdrLen || l > len(b) {
			return nil, fmt.Errorf("netlink: bad message length %d", l)
		}
		switch typ {
		case nlmsgDone:
			return out, nil
		case nlmsgError:
			if l >= nlmsgHdrLen+4 {
				if errno := int32(bo.Uint32(b[16:20])); errno != 0 {
					return nil, fmt.Errorf("netlink: error %d", -errno)
				}
			}
		default:
			if len(out) >= maxNLMessages {
				return nil, errTooManyRoutes
			}
			out = append(out, nlMsg{typ, b[nlmsgHdrLen:l]})
		}
		b = b[min(nlAlign(l), len(b)):]
	}
	return out, nil
}

// nlAttrs walks the route attributes of b: fn gets each attribute's type
// (flags masked) and value. It is written by hand because
// syscall.ParseNetlinkRouteAttr refuses RTM_NEWRULE messages.
func nlAttrs(b []byte, bo binary.ByteOrder, fn func(typ int, v []byte)) {
	for len(b) >= 4 {
		l := int(bo.Uint16(b[0:2]))
		if l < 4 || l > len(b) {
			return
		}
		fn(int(bo.Uint16(b[2:4]))&nlaTypeMask, b[4:l])
		b = b[min(nlAlign(l), len(b)):]
	}
}

// nlRule is one policy routing rule as far as the default route cares.
type nlRule struct {
	table int
	// general: the rule applies to all locally originated traffic — no
	// source or destination prefix, tos, input or output interface, VRF,
	// uid range, IP protocol or port range, action "lookup". Rules with
	// fwmark or "not fwmark" count (wg-quick table 51820, Mullvad,
	// Tailscale's table 52): the traffic they skip is the tunnel's own. A
	// split tunnel ("to 198.51.100.0/24 lookup 100") does not.
	general bool
}

// parseRules parses an RTM_GETRULE dump (struct fib_rule_hdr: family,
// dst_len, src_len, tos, table, res1, res2, action, flags u32).
func parseRules(b []byte, bo binary.ByteOrder) ([]nlRule, error) {
	msgs, err := nlMessages(b, bo)
	if err != nil {
		return nil, err
	}
	var out []nlRule
	for _, m := range msgs {
		if m.typ != rtmNewRule {
			continue
		}
		p := m.data
		if len(p) < rtHdrLen {
			continue
		}
		r := nlRule{table: int(p[4])}
		general := p[1] == 0 && p[2] == 0 && p[3] == 0 && p[7] == frActToTbl
		nlAttrs(p[rtHdrLen:], bo, func(typ int, v []byte) {
			switch typ {
			case fraTable:
				if len(v) >= 4 {
					r.table = int(bo.Uint32(v))
				}
			case fraIIFName, fraOIFName, fraL3MDev, fraUIDRange, fraIPProto, fraSPortRange, fraDPortRange:
				general = false
			}
		})
		r.general = general
		out = append(out, r)
	}
	return out, nil
}

// defaultTables are the tables that decide the effective default route:
// main and the tables of general rules; never local.
func defaultTables(rules []nlRule) map[int]bool {
	t := map[int]bool{rtTableMain: true}
	for _, r := range rules {
		if r.general && r.table != 0 && r.table != rtTableLocal {
			t[r.table] = true
		}
	}
	return t
}

// parseRoutes parses an RTM_GETROUTE dump (struct rtmsg: family, dst_len,
// src_len, tos, table, protocol, scope, type, flags u32). Only unicast routes
// are kept, and only those without a source prefix (a route that applies
// to one source, like a rule "from …", does not carry general traffic). The
// table is RTA_TABLE when present (the header says 252 for ids above 255);
// the interfaces are RTA_OIF and every nexthop of RTA_MULTIPATH. Routes that
// only reference a nexthop object (RTA_NH_ID) have no interface and are
// dropped.
func parseRoutes(b []byte, bo binary.ByteOrder) ([]kernelRoute, error) {
	msgs, err := nlMessages(b, bo)
	if err != nil {
		return nil, err
	}
	var out []kernelRoute
	for _, m := range msgs {
		if m.typ != rtmNewRoute {
			continue
		}
		p := m.data
		if len(p) < rtHdrLen || p[7] != rtnUnicast || p[2] != 0 {
			continue
		}
		fam, dstLen := p[0], int(p[1])
		r := kernelRoute{table: int(p[4])}
		var dst netip.Addr
		nlAttrs(p[rtHdrLen:], bo, func(typ int, v []byte) {
			switch typ {
			case rtaDst:
				if a, ok := netip.AddrFromSlice(v); ok {
					dst = a
				}
			case rtaOIF:
				if len(v) >= 4 {
					r.ifaces = append(r.ifaces, int(int32(bo.Uint32(v))))
				}
			case rtaTable:
				if len(v) >= 4 {
					r.table = int(bo.Uint32(v))
				}
			case rtaMultipath:
				for len(v) >= rtnhHdrLen {
					l := int(bo.Uint16(v[0:2]))
					if l < rtnhHdrLen || l > len(v) {
						break
					}
					r.ifaces = append(r.ifaces, int(int32(bo.Uint32(v[4:8]))))
					v = v[min(nlAlign(l), len(v)):]
				}
			}
		})
		if !dst.IsValid() {
			switch fam {
			case 2: // AF_INET
				dst = netip.IPv4Unspecified()
			case 10: // AF_INET6
				dst = netip.IPv6Unspecified()
			default:
				continue
			}
		}
		pfx, err := dst.Prefix(dstLen)
		if err != nil || len(r.ifaces) == 0 {
			continue
		}
		r.dst = pfx
		out = append(out, r)
	}
	return out, nil
}

// linuxDefaultRouteIfaces combines the rule and route dumps of both
// families (rules4, routes4, rules6, routes6; a nil dump is skipped).
func linuxDefaultRouteIfaces(bo binary.ByteOrder, dumps ...[2][]byte) (map[int]bool, error) {
	out := map[int]bool{}
	for _, d := range dumps {
		if d[1] == nil {
			continue
		}
		rules, err := parseRules(d[0], bo)
		if err != nil {
			return nil, err
		}
		routes, err := parseRoutes(d[1], bo)
		if err != nil {
			return nil, err
		}
		for i := range defaultRouteIfaces(routes, defaultTables(rules)) {
			out[i] = true
		}
	}
	return out, nil
}

// ---------- BSD routing sockets (darwin) ----------

// rtfIfscope marks a route scoped to one interface (darwin RTF_IFSCOPE):
// macOS installs a scoped default per interface next to the real one.
const rtfIfscope = 0x1000000

// bsdRoute is one route of a darwin routing-socket dump.
type bsdRoute struct {
	flags int
	index int
	dst   netip.Prefix
}

// bsdDefaultRouteIfaces applies the default-route rule to a darwin dump:
// scoped routes (RTF_IFSCOPE) are ignored.
func bsdDefaultRouteIfaces(rs []bsdRoute) map[int]bool {
	routes := make([]kernelRoute, 0, len(rs))
	for _, r := range rs {
		if r.flags&rtfIfscope != 0 || r.index <= 0 || !r.dst.IsValid() {
			continue
		}
		routes = append(routes, kernelRoute{dst: r.dst, ifaces: []int{r.index}})
	}
	return defaultRouteIfaces(routes, nil)
}
