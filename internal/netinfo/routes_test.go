package netinfo

import (
	"context"
	"encoding/binary"
	"errors"
	"maps"
	"net"
	"net/netip"
	"os"
	"slices"
	"testing"
	"time"

	"fileparcel/internal/core"
)

// The testdata/netlink/*.bin files are rtnetlink dumps captured on the
// development machine (syscall.NetlinkRIB, amd64): its rules 0 local,
// 5210/5230 fwmark lookup main/default, 5250 fwmark unreachable, 5270
// lookup 52 (Tailscale), 32766 main, 32767 default; Tailscale's routes in
// table 52 (no exit node) and the LAN default route via eth2 (ifindex 4)
// in main; tailscale0 is ifindex 7.

var le = binary.LittleEndian

func readDump(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile("testdata/netlink/" + name + ".bin")
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// ---------- synthetic rtnetlink messages ----------

func u32b(v uint32) []byte { return le.AppendUint32(nil, v) }

func nlAttr(typ int, v []byte) []byte {
	b := le.AppendUint16(nil, uint16(4+len(v)))
	b = le.AppendUint16(b, uint16(typ))
	b = append(b, v...)
	for len(b)%4 != 0 {
		b = append(b, 0)
	}
	return b
}

func nlMessage(typ int, hdr []byte, attrs ...[]byte) []byte {
	body := slices.Clone(hdr)
	for _, a := range attrs {
		body = append(body, a...)
	}
	b := le.AppendUint32(nil, uint32(nlmsgHdrLen+len(body)))
	b = le.AppendUint16(b, uint16(typ))
	b = le.AppendUint16(b, 2) // NLM_F_MULTI
	b = le.AppendUint32(b, 1)
	b = le.AppendUint32(b, 0)
	return append(b, body...)
}

func nlDone() []byte { return nlMessage(nlmsgDone, u32b(0)) }

// ruleMsg: family, src_len, header table, action, flags (+ attributes).
func ruleMsg(fam, srcLen, table, action byte, flags uint32, attrs ...[]byte) []byte {
	hdr := []byte{fam, 0, srcLen, 0, table, 0, 0, action}
	hdr = le.AppendUint32(hdr, flags)
	return nlMessage(rtmNewRule, hdr, attrs...)
}

// routeMsg: family, dst_len, src_len, header table, type (+ attributes).
func routeMsg(fam, dstLen, srcLen, table, typ byte, attrs ...[]byte) []byte {
	hdr := []byte{fam, dstLen, srcLen, 0, table, 3, 0, typ}
	hdr = le.AppendUint32(hdr, 0)
	return nlMessage(rtmNewRoute, hdr, attrs...)
}

func dump(msgs ...[]byte) []byte {
	var b []byte
	for _, m := range msgs {
		b = append(b, m...)
	}
	return append(b, nlDone()...)
}

func nexthops(ifaces ...int) []byte {
	var b []byte
	for _, i := range ifaces {
		b = le.AppendUint16(b, rtnhHdrLen)
		b = append(b, 0, 0)
		b = le.AppendUint32(b, uint32(i))
	}
	return b
}

const (
	afInet  = 2
	afInet6 = 10
	rtnLoc  = 2 // RTN_LOCAL
	notFlag = 2 // FIB_RULE_INVERT ("not fwmark")
	fraSrc  = 2
	fraMark = 10
	rtaNHID = 30
)

func ip4(s string) []byte { a := netip.MustParseAddr(s).As4(); return a[:] }
func ip6(s string) []byte { a := netip.MustParseAddr(s).As16(); return a[:] }

func TestParseRulesCaptured(t *testing.T) {
	for _, f := range []string{"rules4", "rules6"} {
		rules, err := parseRules(readDump(t, f), le)
		if err != nil {
			t.Fatal(f, err)
		}
		got := slices.Sorted(maps.Keys(defaultTables(rules)))
		// main, default and Tailscale's 52 (the fwmark rules count, the
		// unreachable one does not, local never).
		if !slices.Equal(got, []int{52, 253, 254}) {
			t.Errorf("%s: tables %v (rules %+v)", f, got, rules)
		}
	}
}

func TestParseRulesSynthetic(t *testing.T) {
	b := dump(
		// wg-quick: not fwmark 0xca6c lookup 51820 (FRA_TABLE, header 252)
		ruleMsg(afInet, 0, 252, frActToTbl, notFlag, nlAttr(fraMark, u32b(0xca6c)), nlAttr(fraTable, u32b(51820))),
		// from 10.0.0.2 lookup 100 (a reply table)
		ruleMsg(afInet, 32, 100, frActToTbl, 0, nlAttr(fraSrc, ip4("10.0.0.2"))),
		// iif wg1 lookup 101
		ruleMsg(afInet, 0, 101, frActToTbl, 0, nlAttr(fraIIFName, []byte("wg1\x00"))),
		// uidrange 1000-1000 lookup 102
		ruleMsg(afInet, 0, 102, frActToTbl, 0, nlAttr(fraUIDRange, append(u32b(1000), u32b(1000)...))),
		// fwmark 0x1 blackhole (action 6)
		ruleMsg(afInet, 0, 0, 6, 0, nlAttr(fraMark, u32b(1))),
		// lookup local
		ruleMsg(afInet, 0, rtTableLocal, frActToTbl, 0),
	)
	rules, err := parseRules(b, le)
	if err != nil {
		t.Fatal(err)
	}
	want := []nlRule{{51820, true}, {100, false}, {101, false}, {102, false}, {0, false}, {rtTableLocal, true}}
	if !slices.Equal(rules, want) {
		t.Fatalf("rules %+v", rules)
	}
	if got := slices.Sorted(maps.Keys(defaultTables(rules))); !slices.Equal(got, []int{254, 51820}) {
		t.Fatalf("tables %v", got)
	}
}

func TestParseRoutesCaptured(t *testing.T) {
	got := map[int]bool{}
	for _, fam := range []string{"4", "6"} {
		rules, err := parseRules(readDump(t, "rules"+fam), le)
		if err != nil {
			t.Fatal(err)
		}
		routes, err := parseRoutes(readDump(t, "routes"+fam), le)
		if err != nil {
			t.Fatal(err)
		}
		if len(routes) == 0 {
			t.Fatalf("routes%s: none parsed", fam)
		}
		for _, r := range routes {
			if len(r.ifaces) == 0 || !r.dst.IsValid() {
				t.Errorf("routes%s: %+v", fam, r)
			}
		}
		maps.Copy(got, defaultRouteIfaces(routes, defaultTables(rules)))
	}
	// Only eth2 (4) carries the default route; Tailscale's table 52 holds
	// no default without an exit node; local/broadcast routes are skipped.
	if !maps.Equal(got, map[int]bool{4: true}) {
		t.Fatalf("default ifaces %v", got)
	}
	// Table 52's routes are there with their table id.
	routes, _ := parseRoutes(readDump(t, "routes4"), le)
	if !slices.ContainsFunc(routes, func(r kernelRoute) bool {
		return r.table == 52 && r.dst == netip.MustParsePrefix("100.100.100.100/32") && slices.Equal(r.ifaces, []int{7})
	}) {
		t.Fatalf("table 52 routes missing: %+v", routes)
	}
	m, err := linuxDefaultRouteIfaces(le, [2][]byte{readDump(t, "rules4"), readDump(t, "routes4")},
		[2][]byte{readDump(t, "rules6"), readDump(t, "routes6")}, [2][]byte{nil, nil})
	if err != nil || !maps.Equal(m, map[int]bool{4: true}) {
		t.Fatalf("combined %v %v", m, err)
	}
}

func TestParseRoutesSynthetic(t *testing.T) {
	const eth, wg, ts, tun, tun2 = 4, 9, 7, 10, 11
	rules := []nlRule{{rtTableMain, true}, {52, true}, {51820, true}, {100, false}}
	cases := []struct {
		name string
		msgs [][]byte
		want map[int]bool
	}{
		{"main default", [][]byte{routeMsg(afInet, 0, 0, rtTableMain, rtnUnicast, nlAttr(rtaOIF, u32b(eth)))}, map[int]bool{eth: true}},
		// wg-quick: default in table 51820 (header 252, RTA_TABLE) under a "not fwmark" rule
		{"table 51820", [][]byte{routeMsg(afInet, 0, 0, 252, rtnUnicast, nlAttr(rtaTable, u32b(51820)), nlAttr(rtaOIF, u32b(wg)))}, map[int]bool{wg: true}},
		// a reply table reached only by "from 10.0.0.2 lookup 100"
		{"from table", [][]byte{routeMsg(afInet, 0, 0, 100, rtnUnicast, nlAttr(rtaOIF, u32b(wg)))}, map[int]bool{}},
		// Tailscale exit node: default in table 52
		{"exit node", [][]byte{routeMsg(afInet, 0, 0, 52, rtnUnicast, nlAttr(rtaOIF, u32b(ts)))}, map[int]bool{ts: true}},
		// ECMP default over two interfaces
		{"multipath", [][]byte{routeMsg(afInet, 0, 0, rtTableMain, rtnUnicast, nlAttr(rtaMultipath, nexthops(eth, wg)))}, map[int]bool{eth: true, wg: true}},
		// OpenVPN def1 halves, both on tun0; one half alone is not a default
		{"def1", [][]byte{
			routeMsg(afInet, 1, 0, rtTableMain, rtnUnicast, nlAttr(rtaDst, ip4("0.0.0.0")), nlAttr(rtaOIF, u32b(tun))),
			routeMsg(afInet, 1, 0, rtTableMain, rtnUnicast, nlAttr(rtaDst, ip4("128.0.0.0")), nlAttr(rtaOIF, u32b(tun))),
			routeMsg(afInet, 1, 0, rtTableMain, rtnUnicast, nlAttr(rtaDst, ip4("128.0.0.0")), nlAttr(rtaOIF, u32b(tun2))),
		}, map[int]bool{tun: true}},
		{"def1 v6", [][]byte{
			routeMsg(afInet6, 1, 0, rtTableMain, rtnUnicast, nlAttr(rtaDst, ip6("::")), nlAttr(rtaOIF, u32b(tun))),
			routeMsg(afInet6, 1, 0, rtTableMain, rtnUnicast, nlAttr(rtaDst, ip6("8000::")), nlAttr(rtaOIF, u32b(tun))),
		}, map[int]bool{tun: true}},
		// halves in different tables do not combine
		{"def1 split tables", [][]byte{
			routeMsg(afInet, 1, 0, rtTableMain, rtnUnicast, nlAttr(rtaDst, ip4("0.0.0.0")), nlAttr(rtaOIF, u32b(tun))),
			routeMsg(afInet, 1, 0, 52, rtnUnicast, nlAttr(rtaDst, ip4("128.0.0.0")), nlAttr(rtaOIF, u32b(tun))),
		}, map[int]bool{}},
		// only a nexthop object: no interface, ignored
		{"nh id", [][]byte{routeMsg(afInet, 0, 0, rtTableMain, rtnUnicast, nlAttr(rtaNHID, u32b(12)))}, map[int]bool{}},
		// not unicast (local), or source-specific (from 2001:db8::/64)
		{"local", [][]byte{routeMsg(afInet, 0, 0, rtTableMain, rtnLoc, nlAttr(rtaOIF, u32b(eth)))}, map[int]bool{}},
		{"source route", [][]byte{routeMsg(afInet6, 0, 64, rtTableMain, rtnUnicast, nlAttr(rtaOIF, u32b(wg)))}, map[int]bool{}},
		{"subnet", [][]byte{routeMsg(afInet, 24, 0, rtTableMain, rtnUnicast, nlAttr(rtaDst, ip4("10.8.0.0")), nlAttr(rtaOIF, u32b(wg)))}, map[int]bool{}},
	}
	for _, c := range cases {
		routes, err := parseRoutes(dump(c.msgs...), le)
		if err != nil {
			t.Fatal(c.name, err)
		}
		if got := defaultRouteIfaces(routes, defaultTables(rules)); !maps.Equal(got, c.want) {
			t.Errorf("%s: %v want %v (routes %+v)", c.name, got, c.want, routes)
		}
	}
}

func TestNetlinkErrors(t *testing.T) {
	errMsg := nlMessage(nlmsgError, append(le.AppendUint32(nil, uint32(0xffffffff-12)), make([]byte, 16)...)) // -13 EACCES
	if _, err := parseRoutes(errMsg, le); err == nil {
		t.Fatal("NLMSG_ERROR accepted")
	}
	ack := nlMessage(nlmsgError, make([]byte, 20)) // errno 0: an ACK
	if r, err := parseRoutes(append(ack, nlDone()...), le); err != nil || len(r) != 0 {
		t.Fatal(r, err)
	}
	bad := routeMsg(afInet, 0, 0, rtTableMain, rtnUnicast)
	le.PutUint32(bad[0:4], 4096)
	if _, err := parseRoutes(bad, le); err == nil {
		t.Fatal("bad length accepted")
	}
	// A truncated attribute stops the walk without panicking.
	trunc := routeMsg(afInet, 0, 0, rtTableMain, rtnUnicast, []byte{200, 0, rtaOIF, 0})
	if r, err := parseRoutes(dump(trunc), le); err != nil || len(r) != 0 {
		t.Fatal(r, err)
	}
	// The parse stops after maxNLMessages messages.
	one := routeMsg(afInet, 24, 0, rtTableMain, rtnUnicast, nlAttr(rtaOIF, u32b(1)))
	big := make([]byte, 0, len(one)*(maxNLMessages+1))
	for range maxNLMessages + 1 {
		big = append(big, one...)
	}
	if _, err := parseRoutes(big, le); !errors.Is(err, errTooManyRoutes) {
		t.Fatalf("limit: %v", err)
	}
}

func TestBSDDefaultRoute(t *testing.T) {
	pp := netip.MustParsePrefix
	// macOS keeps a scoped default per interface (RTF_IFSCOPE): only the
	// unscoped one is the effective default route.
	if got := bsdDefaultRouteIfaces([]bsdRoute{
		{flags: rtfIfscope, index: 12, dst: pp("0.0.0.0/0")}, // utun4, scoped only
		{flags: 0, index: 4, dst: pp("0.0.0.0/0")},           // en0
		{flags: rtfIfscope, index: 4, dst: pp("0.0.0.0/0")},
		{flags: 0, index: 0, dst: pp("::/0")}, // no interface
	}); !maps.Equal(got, map[int]bool{4: true}) {
		t.Fatalf("ifscope: %v", got)
	}
	if got := bsdDefaultRouteIfaces([]bsdRoute{
		{index: 13, dst: pp("0.0.0.0/1")}, {index: 13, dst: pp("128.0.0.0/1")}, {index: 14, dst: pp("::/1")},
	}); !maps.Equal(got, map[int]bool{13: true}) {
		t.Fatalf("def1: %v", got)
	}
}

func TestRouteCache(t *testing.T) {
	var c routeCache
	calls := 0
	fetch := func(context.Context) (map[int]bool, error) { calls++; return map[int]bool{9: true}, nil }
	now := time.Unix(1000, 0)
	ctx := context.Background()
	for range 3 {
		if m := c.get(ctx, "a", now, fetch); !m[9] {
			t.Fatal(m)
		}
	}
	c.get(ctx, "a", now.Add(routeTTL-time.Second), fetch)
	if calls != 1 {
		t.Fatalf("calls %d", calls)
	}
	c.get(ctx, "b", now, fetch) // the interface set changed
	c.get(ctx, "b", now.Add(routeTTL), fetch)
	if calls != 3 {
		t.Fatalf("calls %d", calls)
	}
	// A failed probe knows no default route (nothing becomes egress) and
	// is cached; a cancelled one is not.
	failing := func(context.Context) (map[int]bool, error) { calls++; return nil, errors.New("netlink denied") }
	if m := c.get(ctx, "c", now, failing); len(m) != 0 {
		t.Fatal(m)
	}
	c.get(ctx, "c", now, failing)
	if calls != 4 {
		t.Fatalf("calls %d", calls)
	}
	// A cancelled caller gets the last answer (even a stale one, or one for
	// another interface set) and nothing is recorded.
	c.get(ctx, "c2", now, fetch) // {9: true}
	cctx, cancel := context.WithCancel(ctx)
	cancel()
	if m := c.get(cctx, "d", now.Add(2*routeTTL), func(ctx context.Context) (map[int]bool, error) { calls++; return nil, ctx.Err() }); !m[9] {
		t.Fatalf("cancelled: %v", m)
	}
	c.get(ctx, "d", now, fetch)
	if calls != 6 {
		t.Fatalf("calls %d", calls)
	}
	// Without any earlier answer a cancelled caller gets "none known".
	var empty routeCache
	if m := empty.get(cctx, "d", now, func(ctx context.Context) (map[int]bool, error) { return nil, ctx.Err() }); len(m) != 0 {
		t.Fatal(m)
	}
	if empty.m != nil {
		t.Fatal("a cancelled probe was recorded")
	}
}

// A request cancelled while the route cache is stale keeps the exit
// tunnel's role: the snapshot does not change (no network.changed, no
// certificate reissue with the tunnel's address).
func TestCancelledRefreshKeepsDefaultRoute(t *testing.T) {
	src := &fakeSource{}
	src.set([]rawIface{
		{Name: "lo", Index: 1, Flags: net.FlagUp | net.FlagLoopback, Addrs: pfx("127.0.0.1/8")},
		{Name: "eth0", Index: 2, Flags: up, Addrs: pfx("192.168.1.10/24")},
		{Name: "wg0", Index: 5, Flags: net.FlagUp | net.FlagPointToPoint, Addrs: pfx("10.66.1.2/32")},
	})
	s := newTestService(t, nil, src, "")
	s.probe = &hostProbe{defaultRouteIfaces: func(ctx context.Context) (map[int]bool, error) {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		return map[int]bool{5: true, 2: true}, nil
	}}
	role := func(ifs []core.NetInterface) string {
		for _, ni := range ifs {
			if ni.Name == "wg0" {
				return ni.Role
			}
		}
		return ""
	}
	ifs, _ := s.Interfaces(context.Background())
	if role(ifs) != core.VPNRoleEgress {
		t.Fatalf("setup: %+v", ifs)
	}
	fp := s.snap.Load().fp
	s.routes.mu.Lock()
	s.routes.at = time.Now().Add(-2 * routeTTL)
	s.routes.mu.Unlock()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	ifs, _ = s.Interfaces(ctx)
	if role(ifs) != core.VPNRoleEgress || s.snap.Load().fp != fp || slices.Contains(s.IPs(), netip.MustParseAddr("10.66.1.2")) {
		t.Fatalf("after a cancelled request: %s %v", role(ifs), s.IPs())
	}
}

// The real routing tables can be read (read only); what they hold depends
// on the machine, so only the call is checked.
func TestSystemDefaultRouteIfaces(t *testing.T) {
	m, err := systemDefaultRouteIfaces(context.Background())
	if errors.Is(err, errors.ErrUnsupported) {
		t.Skip("no routing-table reader on this system")
	}
	if err != nil {
		t.Skip("routing tables not readable here:", err)
	}
	if m == nil {
		t.Fatal("nil map")
	}
}

// nlTestMsg and nlTestAttr build rtnetlink messages for parser tests.
func nlTestMsg(bo binary.ByteOrder, typ int, payload []byte) []byte {
	b := make([]byte, 16, 16+len(payload))
	bo.PutUint32(b[0:4], uint32(16+len(payload)))
	bo.PutUint16(b[4:6], uint16(typ))
	return append(b, payload...)
}

func nlTestAttr(bo binary.ByteOrder, typ int, v []byte) []byte {
	b := make([]byte, 4, 4+len(v)+3)
	bo.PutUint16(b[0:2], uint16(4+len(v)))
	bo.PutUint16(b[2:4], uint16(typ))
	b = append(b, v...)
	for len(b)%4 != 0 {
		b = append(b, 0)
	}
	return b
}

// Only rules that select all traffic (apart from fwmark) make their table
// decide the default route: a split tunnel's "to <prefix> lookup 100", a
// tos, output-interface, protocol or port rule does not.
func TestRulesWithSelectorsAreNotGeneral(t *testing.T) {
	bo := binary.NativeEndian
	u32 := func(v uint32) []byte { b := make([]byte, 4); bo.PutUint32(b, v); return b }
	done := nlTestMsg(bo, nlmsgDone, u32(0))
	// table 100: default dev 5 (wg0); main: default dev 2 (eth0)
	routes := append(append(
		nlTestMsg(bo, rtmNewRoute, append([]byte{2, 0, 0, 0, 100, 3, 0, 1, 0, 0, 0, 0}, nlTestAttr(bo, rtaOIF, u32(5))...)),
		nlTestMsg(bo, rtmNewRoute, append([]byte{2, 0, 0, 0, 254, 3, 0, 1, 0, 0, 0, 0}, nlTestAttr(bo, rtaOIF, u32(2))...))...),
		done...)
	for name, tc := range map[string]struct {
		hdr   []byte // fib_rule_hdr: family, dst_len, src_len, tos, table, res1, res2, action, flags
		attrs []byte
		wg0   bool
	}{
		"all traffic":    {[]byte{2, 0, 0, 0, 100, 0, 0, 1, 0, 0, 0, 0}, nil, true},
		"fwmark":         {[]byte{2, 0, 0, 0, 100, 0, 0, 1, 0, 0, 0, 0}, nlTestAttr(bo, 10, u32(0xca6c)), true},
		"to a prefix":    {[]byte{2, 24, 0, 0, 100, 0, 0, 1, 0, 0, 0, 0}, nlTestAttr(bo, 1, []byte{198, 51, 100, 0}), false},
		"tos":            {[]byte{2, 0, 0, 0x10, 100, 0, 0, 1, 0, 0, 0, 0}, nil, false},
		"oif":            {[]byte{2, 0, 0, 0, 100, 0, 0, 1, 0, 0, 0, 0}, nlTestAttr(bo, fraOIFName, []byte("eth1\x00")), false},
		"ip proto":       {[]byte{2, 0, 0, 0, 100, 0, 0, 1, 0, 0, 0, 0}, nlTestAttr(bo, fraIPProto, []byte{6}), false},
		"dport range":    {[]byte{2, 0, 0, 0, 100, 0, 0, 1, 0, 0, 0, 0}, nlTestAttr(bo, fraDPortRange, u32(443|443<<16)), false},
		"sport range":    {[]byte{2, 0, 0, 0, 100, 0, 0, 1, 0, 0, 0, 0}, nlTestAttr(bo, fraSPortRange, u32(1|2<<16)), false},
		"from a prefix":  {[]byte{2, 0, 24, 0, 100, 0, 0, 1, 0, 0, 0, 0}, nlTestAttr(bo, 2, []byte{10, 0, 0, 0}), false},
		"input iface":    {[]byte{2, 0, 0, 0, 100, 0, 0, 1, 0, 0, 0, 0}, nlTestAttr(bo, fraIIFName, []byte("br0\x00")), false},
		"l3mdev (a VRF)": {[]byte{2, 0, 0, 0, 100, 0, 0, 1, 0, 0, 0, 0}, nlTestAttr(bo, fraL3MDev, []byte{1}), false},
	} {
		rules := append(nlTestMsg(bo, rtmNewRule, append(slices.Clone(tc.hdr), tc.attrs...)), done...)
		m, err := linuxDefaultRouteIfaces(bo, [2][]byte{rules, routes})
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if m[5] != tc.wg0 || !m[2] {
			t.Errorf("%s: %v", name, m)
		}
	}
}
