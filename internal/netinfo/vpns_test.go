package netinfo

import (
	"context"
	"encoding/json"
	"net"
	"net/netip"
	"slices"
	"strings"
	"testing"
	"time"

	"fileparcel/internal/core"
	"fileparcel/internal/events"
)

// vpnHost is a machine with a LAN, Tailscale as an exit node, NordVPN
// Meshnet, a WireGuard tunnel that carries the default route (wg0), a
// WireGuard network into the office (wg1), an unknown TUN, a Cisco client
// and an up interface without a usable address.
func vpnHost() []rawIface {
	return []rawIface{
		{Name: "lo", Index: 1, Flags: net.FlagUp | net.FlagLoopback, Addrs: pfx("127.0.0.1/8", "::1/128")},
		{Name: "eth2", Index: 4, Flags: up, Addrs: pfx("192.168.1.10/24", "2001:db8:f030:b300::6/64")},
		{Name: "tailscale0", Index: 7, Flags: up, IsTun: true, Addrs: pfx("100.64.0.10/32", "fd7a:115c:a1e0::a/128")},
		{Name: "nordlynx", Index: 8, Flags: up, DevType: "wireguard", Addrs: pfx("10.5.0.2/32", "100.90.1.2/32")},
		{Name: "wg0", Index: 9, Flags: up, DevType: "wireguard", Addrs: pfx("10.64.1.2/24")},
		{Name: "wg1", Index: 10, Flags: up, DevType: "wireguard", Addrs: pfx("10.8.0.2/24")},
		{Name: "edge0", Index: 11, Flags: up, IsTun: true, Addrs: pfx("172.30.0.2/16")},
		{Name: "cscotun0", Index: 12, Flags: up, IsTun: true, Addrs: pfx("10.200.0.9/24")},
		{Name: "utun0", Index: 13, Flags: up, Addrs: pfx("fe80::1/64")},
	}
}

// vpnService is a test service over vpnHost whose probe reports the default
// route on eth2 (main), tailscale0 (table 52) and wg0 (table 51820).
func vpnService(t *testing.T) (*Service, *core.Env, *int) {
	t.Helper()
	env, _ := testEnv(t)
	s := newTestService(t, env, &fakeSource{list: vpnHost()}, "")
	calls := 0
	s.probe = &hostProbe{defaultRouteIfaces: func(context.Context) (map[int]bool, error) {
		calls++
		return map[int]bool{4: true, 7: true, 9: true}, nil
	}}
	return s, env, &calls
}

func ifaceByName(ifs []core.NetInterface, name string) core.NetInterface {
	for _, ni := range ifs {
		if ni.Name == name {
			return ni
		}
	}
	return core.NetInterface{}
}

func ipStrings(ips []netip.Addr) []string {
	var out []string
	for _, a := range ips {
		out = append(out, a.String())
	}
	return out
}

func TestServiceRoles(t *testing.T) {
	s, _, calls := vpnService(t)
	ctx := context.Background()
	ifs, err := s.Interfaces(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for name, want := range map[string][2]string{
		"lo": {core.IfLoopback, "none"}, "eth2": {core.IfLAN, "local"}, "tailscale0": {core.IfTailscale, "mesh"},
		"nordlynx": {core.IfExitVPN, "mesh"}, "wg0": {core.IfWireGuard, "egress"}, "wg1": {core.IfWireGuard, "unknown"},
		"edge0": {core.IfVPN, "unknown"}, "cscotun0": {core.IfCorpVPN, "access"}, "utun0": {core.IfVPN, "unknown"},
	} {
		ni := ifaceByName(ifs, name)
		if ni.Kind != want[0] || ni.Role != want[1] || ni.RoleSource != core.VPNRoleSourceAuto {
			t.Errorf("%s: %+v", name, ni)
		}
	}
	// Tailscale as an exit node stays mesh; the route is its detail.
	if ts := ifaceByName(ifs, "tailscale0"); !ts.DefaultRoute || ts.Detail != detailDefaultRoute {
		t.Errorf("tailscale0 %+v", ts)
	}
	if wg := ifaceByName(ifs, "wg0"); !wg.DefaultRoute || wg.Detail != detailDefaultRoute {
		t.Errorf("wg0 %+v", wg)
	}
	if eth := ifaceByName(ifs, "eth2"); eth.DefaultRoute || eth.Detail != "" {
		t.Errorf("eth2 %+v", eth)
	}
	// SANs: offered interfaces only; nordlynx only with its Meshnet address;
	// local addresses first in the URLs.
	wantIPs := []string{"192.168.1.10", "2001:db8:f030:b300::6", "100.64.0.10", "fd7a:115c:a1e0::a",
		"100.90.1.2", "10.8.0.2", "172.30.0.2"}
	if got := ipStrings(s.IPs()); !slices.Equal(got, wantIPs) {
		t.Fatalf("IPs %v", got)
	}
	urls, err := s.URLs(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var ipURLs []string
	for _, u := range urls {
		if u.Kind == core.URLKindIP {
			ipURLs = append(ipURLs, u.URL)
		}
	}
	wantURLs := []string{"https://192.168.1.10:8443/", "https://[2001:db8:f030:b300::6]:8443/", "https://100.64.0.10:8443/",
		"https://100.90.1.2:8443/", "https://10.8.0.2:8443/", "https://172.30.0.2:8443/", "https://[fd7a:115c:a1e0::a]:8443/"}
	if !slices.Equal(ipURLs, wantURLs) {
		t.Fatalf("URLs %v", ipURLs)
	}
	// The routing tables are read once per interface set and minute.
	s.Interfaces(ctx)
	s.URLs(ctx)
	if *calls != 1 {
		t.Fatalf("default-route probe ran %d times", *calls)
	}
}

func TestServiceNoRouteProbeWithoutVPN(t *testing.T) {
	env, _ := testEnv(t)
	s := newTestService(t, env, &fakeSource{list: []rawIface{
		{Name: "lo", Index: 1, Flags: net.FlagUp | net.FlagLoopback, Addrs: pfx("127.0.0.1/8")},
		{Name: "eth0", Index: 2, Flags: up, Addrs: pfx("192.168.1.10/24")},
		{Name: "wg9", Index: 3, Flags: net.FlagBroadcast, Addrs: pfx("10.9.0.1/24")}, // down
	}}, "")
	s.probe = &hostProbe{defaultRouteIfaces: func(context.Context) (map[int]bool, error) {
		t.Error("routing tables read without an up VPN interface")
		return nil, nil
	}}
	if _, err := s.Interfaces(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestServiceRoleOverrides(t *testing.T) {
	s, env, _ := vpnService(t)
	s.poll = time.Hour
	ch, unsub := env.Bus.Subscribe(events.TopicNetworkChanged)
	defer unsub()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := s.Start(ctx); err != nil {
		t.Fatal(err)
	}
	set := func(v string) error {
		_, err := env.Settings.Set(ctx, nil, map[string]json.RawMessage{KeyIfaceRoles: json.RawMessage(v)})
		return err
	}
	// wg0 is really the office network; eth2 turns out to be an uplink.
	if err := set(`["wg0=mesh","eth2=local","eth2=egress"]`); err != nil {
		t.Fatal(err)
	}
	select {
	case <-ch:
	case <-time.After(2 * time.Second):
		t.Fatal("network.changed not published for network.iface_roles")
	}
	ifs, _ := s.Interfaces(ctx)
	if wg := ifaceByName(ifs, "wg0"); wg.Role != core.VPNRoleMesh || wg.RoleSource != core.VPNRoleSourceOverride || wg.Kind != core.IfWireGuard {
		t.Fatalf("wg0 %+v", wg)
	}
	if eth := ifaceByName(ifs, "eth2"); eth.Role != core.VPNRoleEgress || eth.RoleSource != core.VPNRoleSourceOverride {
		t.Fatalf("eth2 %+v", eth)
	}
	ips := ipStrings(s.IPs())
	if !slices.Contains(ips, "10.64.1.2") || slices.Contains(ips, "192.168.1.10") {
		t.Fatalf("IPs after override %v", ips)
	}
	// The VPN list follows (eth2 is listed now: an administrator gave it a
	// VPN role).
	vpns := s.VPNs(ctx)
	byID := map[string]core.VPNInfo{}
	for _, v := range vpns {
		byID[v.ID] = v
	}
	if v := byID["wg0"]; v.Role != core.VPNRoleMesh || v.RoleSource != core.VPNRoleSourceOverride || !v.CanAllow || !slices.Equal(v.Ranges, []string{"10.64.1.0/24"}) {
		t.Fatalf("wg0 vpn %+v", v)
	}
	if v := byID["eth2"]; v.Role != core.VPNRoleEgress || v.CanAllow || len(v.Ranges) != 0 {
		t.Fatalf("eth2 vpn %+v", v)
	}
	// Only the role changes (same addresses): still a new fingerprint, so
	// mDNS republishes.
	if err := set(`["eth2=mesh"]`); err != nil {
		t.Fatal(err)
	}
	select {
	case <-ch:
	case <-time.After(2 * time.Second):
		t.Fatal("network.changed not published for a role change")
	}
	// Invalid entries are refused on write.
	for _, bad := range []string{`["wg0"]`, `["wg0=vpn"]`, `["../x=mesh"]`, `["=mesh"]`, `["a b=mesh"]`} {
		if err := set(bad); err == nil {
			t.Errorf("%s accepted", bad)
		}
	}
}

func TestParseIfaceRoles(t *testing.T) {
	m, err := parseIfaceRoles([]string{" wg0 = Mesh ", "", "eth2=local", "eth2=egress", "Wi Fi=none"})
	if err == nil {
		t.Fatalf("space in a name accepted: %v", m)
	}
	m, err = parseIfaceRoles([]string{" wg0 = Mesh ", "", "eth2=local", "eth2=egress", "tun-firezone=none"})
	if err != nil || len(m) != 3 || m["wg0"] != "mesh" || m["eth2"] != "egress" || m["tun-firezone"] != "none" {
		t.Fatalf("%v %v", m, err)
	}
	for _, r := range roleNames {
		if _, err := parseIfaceRoles([]string{"x=" + r}); err != nil {
			t.Errorf("%s: %v", r, err)
		}
	}
	long := make([]string, maxIfaceRoles+1)
	for i := range long {
		long[i] = "wg0=mesh"
	}
	if _, err := parseIfaceRoles(long); err == nil {
		t.Fatal("65 entries accepted")
	}
	for _, bad := range []string{"wg0", "wg0=", "=mesh", "wg0=auto", "../etc=mesh", strings.Repeat("x", 65) + "=mesh", "a\tb=mesh"} {
		if _, err := parseIfaceRoles([]string{bad}); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
	if err := validIfaceRoles([]string{"wg0=mesh"}); err != nil {
		t.Fatal(err)
	}
}

func TestOffered(t *testing.T) {
	nord := core.NetInterface{Name: "nordlynx", Kind: core.IfExitVPN, Provider: "nordvpn", Up: true, Role: core.VPNRoleMesh,
		Addrs: pfx("10.5.0.2/32", "100.90.1.2/32")}
	a := netip.MustParseAddr
	if !offered(nord) || offeredAddr(nord, a("10.5.0.2")) || !offeredAddr(nord, a("100.90.1.2")) {
		t.Fatal("meshnet")
	}
	// Overridden to mesh without a Meshnet address: all its addresses.
	exit := nord
	exit.Addrs = pfx("10.5.0.2/32")
	exit.RoleSource = core.VPNRoleSourceOverride
	if !offeredAddr(exit, a("10.5.0.2")) {
		t.Fatal("override without meshnet")
	}
	exit.Role = core.VPNRoleEgress
	if offered(exit) {
		t.Fatal("egress offered")
	}
	for role, want := range map[string]bool{"mesh": true, "unknown": true, "local": true, "access": false, "egress": false,
		"overlay": false, "none": false} {
		if got := offered(core.NetInterface{Up: true, Role: role}); got != want {
			t.Errorf("%s: %v", role, got)
		}
	}
	if offered(core.NetInterface{Up: false, Role: "local"}) {
		t.Fatal("down offered")
	}
	// Values without a role (older servers, fakes) get their kind's role.
	for kind, want := range map[string]string{core.IfLAN: "local", core.IfWiFi: "local", core.IfContainer: "none",
		core.IfLoopback: "none", core.IfTailscale: "mesh", core.IfWireGuard: "unknown", core.IfVPN: "unknown",
		core.IfExitVPN: "egress", core.IfCorpVPN: "access", core.IfYggdrasil: "overlay", "future": "local"} {
		if got := RoleOf(core.NetInterface{Kind: kind}); got != want {
			t.Errorf("RoleOf(%s) = %s", kind, got)
		}
	}
	if RoleOf(core.NetInterface{Kind: "future", IsVPN: true}) != core.VPNRoleUnknown {
		t.Fatal("unknown VPN kind")
	}
}

func TestMatcherCovers(t *testing.T) {
	p := netip.MustParsePrefix
	cases := []struct {
		pol  core.AccessPolicy
		net  string
		want string
	}{
		{core.AccessPolicy{Mode: "any"}, "10.8.0.0/24", "yes"},
		{core.AccessPolicy{Mode: "any", Deny: []string{"10.8.0.66"}}, "10.8.0.0/24", "partly"},
		{core.AccessPolicy{Mode: "any", Deny: []string{"10.0.0.0/8"}}, "10.8.0.0/24", "no"},
		{core.AccessPolicy{Mode: "allowlist", Allow: []string{"10.8.0.0/16"}}, "10.8.0.0/24", "yes"},
		{core.AccessPolicy{Mode: "allowlist", Allow: []string{"10.8.0.0/25"}}, "10.8.0.0/24", "partly"},
		{core.AccessPolicy{Mode: "allowlist", Allow: []string{"100.64.0.10"}}, "100.64.0.0/10", "partly"},
		{core.AccessPolicy{Mode: "allowlist"}, "10.8.0.0/24", "no"},
		{core.AccessPolicy{Mode: "private"}, "100.64.0.0/10", "yes"},
		{core.AccessPolicy{Mode: "private"}, "fd7a:115c:a1e0::/48", "yes"},
		{core.AccessPolicy{Mode: "private"}, "200::/7", "no"},
		{core.AccessPolicy{Mode: "private", Deny: []string{"100.100.0.0/16"}}, "100.64.0.0/10", "partly"},
		{core.AccessPolicy{Mode: "allowlist", Allow: []string{"::ffff:10.8.0.0/120"}}, "10.8.0.0/24", "yes"},
	}
	for _, c := range cases {
		if got := mustMatcher(t, c.pol).covers(p(c.net)); got != c.want {
			t.Errorf("%+v %s: %s want %s", c.pol, c.net, got, c.want)
		}
	}
	var nilM *matcher
	if nilM.covers(p("10.0.0.0/8")) != "no" {
		t.Fatal("nil matcher")
	}
}

func TestBuildVPNs(t *testing.T) {
	up := true
	ni := func(name, kind, role string, addrs ...string) core.NetInterface {
		return core.NetInterface{Name: name, Kind: kind, Label: kindLabels[kind], Up: up, IsVPN: vpnKinds[kind], Role: role,
			RoleSource: core.VPNRoleSourceAuto, Addrs: pfx(addrs...)}
	}
	nord := ni("nordlynx", core.IfExitVPN, "mesh", "10.5.0.2/32", "100.90.1.2/32")
	nord.Provider, nord.Label = "nordvpn", "NordVPN Meshnet"
	mull := ni("wg0-mullvad", core.IfExitVPN, "egress", "10.64.1.2/32")
	mull.Provider, mull.Label = "mullvad", "Mullvad VPN"
	cisco := ni("cscotun0", core.IfCorpVPN, "access", "10.200.0.9/24")
	cisco.Provider, cisco.Label = "cisco", "Cisco Secure Client"
	warp := ni("CloudflareWARP", core.IfWARP, "egress", "100.96.0.5/32")
	warp.Provider = "cloudflare"
	fz := ni("tun-firezone", core.IfFirezone, "access", "100.66.0.3/32")
	fz.Provider = "firezone"
	down := ni("wg7", core.IfWireGuard, "unknown", "10.7.0.1/24")
	down.Up = false
	overLAN := ni("eth5", core.IfLAN, "mesh", "172.20.0.5/16")
	overLAN.RoleSource = core.VPNRoleSourceOverride
	ifaces := []core.NetInterface{
		ni("lo", core.IfLoopback, "none", "127.0.0.1/8"),
		ni("eth2", core.IfLAN, "local", "192.168.1.10/24"),
		warp, mull, cisco, fz,
		ni("tailscale0", core.IfTailscale, "mesh", "100.64.0.10/32", "fd7a:115c:a1e0::a/128"),
		nord,
		ni("hnet0", core.IfHusarnet, "mesh", "fc94:1:2::3/128"),
		ni("ygg0", core.IfYggdrasil, "overlay", "201:1:2::3/7"),
		ni("zt1", core.IfZeroTier, "mesh", "10.147.17.5/24"),
		ni("zt2", core.IfZeroTier, "mesh", "10.147.18.5/24", "fe80::1/64"),
		ni("wg1", core.IfWireGuard, "unknown", "10.8.0.2/24"),
		ni("wg2", core.IfWireGuard, "unknown", "10.9.0.2/32"),
		ni("utun0", core.IfVPN, "unknown", "fe80::1/64"),
		down, overLAN,
		ni("docker0", core.IfContainer, "none", "172.17.0.1/16"),
	}
	pol := core.AccessPolicy{Mode: "allowlist", Allow: []string{"100.64.0.10", "10.147.17.0/24", "10.147.18.0/24", "10.8.0.0/16", "10.64.1.0/24"}}
	vpns := BuildVPNs(ifaces, nil, pol)
	var ids []string
	byID := map[string]core.VPNInfo{}
	for _, v := range vpns {
		ids = append(ids, v.ID)
		byID[v.ID] = v
		if v.Interfaces == nil || v.Ranges == nil || v.RoleSource == "" || v.Label == "" {
			t.Errorf("%s: %+v", v.ID, v)
		}
	}
	wantIDs := []string{"tailscale", "nordvpn", "husarnet", "zerotier", "eth5", "wg1", "wg2", "yggdrasil", "cisco", "firezone", "warp", "mullvad"}
	if !slices.Equal(ids, wantIDs) {
		t.Fatalf("ids %v", ids)
	}
	check := func(id, label, role string, ranges []string, allowed string, canAllow, force, rec bool, note, warning string) {
		t.Helper()
		v := byID[id]
		if v.Label != label || v.Role != role || !slices.Equal(v.Ranges, ranges) || v.Allowed != allowed || v.CanAllow != canAllow ||
			v.NeedsForce != force || v.Recommended != rec || !strings.Contains(v.Note, note) || v.Warning != warning {
			t.Errorf("%s: %+v", id, v)
		}
	}
	check("tailscale", "Tailscale", "mesh", []string{"100.64.0.0/10", "fd7a:115c:a1e0::/48"}, "partly", true, false, true, "", tailnetWarning)
	check("nordvpn", "NordVPN Meshnet", "mesh", []string{"100.64.0.0/10"}, "partly", true, false, true, "", "")
	check("husarnet", "Husarnet", "mesh", []string{"fc94::/16"}, "no", true, false, true, husarnetNote, "")
	check("zerotier", "ZeroTier", "mesh", []string{"10.147.17.0/24", "10.147.18.0/24"}, "yes", true, false, true, "", "")
	check("eth5", "LAN (eth5)", "mesh", []string{"172.20.0.0/16"}, "no", true, false, true, "", "")
	check("wg1", "WireGuard (wg1)", "unknown", []string{"10.8.0.0/24"}, "yes", true, false, true, "", "")
	check("wg2", "WireGuard (wg2)", "unknown", []string{}, "no", false, false, false, hostOnlyNote, "")
	check("yggdrasil", "Yggdrasil", "overlay", []string{"200::/7"}, "no", true, true, false, "", yggdrasilWarning)
	check("cisco", "Cisco Secure Client", "access", []string{}, "no", false, false, false, "", "")
	check("firezone", "Firezone", "access", []string{}, "no", false, false, false, firezoneNote, "")
	check("warp", "Cloudflare WARP", "egress", []string{}, "no", false, false, false, warpNote, "")
	// An outgoing VPN's own subnet in the allow list shows as allowed.
	check("mullvad", "Mullvad VPN", "egress", []string{}, "yes", false, false, false, "", "")
	if z := byID["zerotier"]; !slices.Equal(z.Interfaces, []string{"zt1", "zt2"}) {
		t.Fatalf("zerotier interfaces %v", z.Interfaces)
	}

	// An override on one ZeroTier network lists both on their own.
	ifaces[11].Role, ifaces[11].RoleSource = core.VPNRoleEgress, core.VPNRoleSourceOverride
	byID = map[string]core.VPNInfo{}
	for _, v := range BuildVPNs(ifaces, nil, pol) {
		byID[v.ID] = v
	}
	if _, ok := byID["zerotier"]; ok || byID["zt1"].Role != "mesh" || byID["zt2"].Role != "egress" || byID["zt1"].Label != "ZeroTier (zt1)" {
		t.Fatalf("split: %+v", byID)
	}

	if v := BuildVPNs(nil, nil, core.AccessPolicy{}); v == nil || len(v) != 0 {
		t.Fatal(v)
	}
	// An invalid policy falls back to loopback only.
	if v := BuildVPNs(ifaces[:7], nil, core.AccessPolicy{Mode: "bogus"}); v[0].Allowed != "no" {
		t.Fatal(v[0])
	}
}

func TestBuildVPNsHeadscale(t *testing.T) {
	hs := core.NetInterface{Name: "tailscale0", Kind: core.IfHeadscale, Label: "Headscale", Up: true, IsVPN: true,
		Role: core.VPNRoleMesh, Addrs: pfx("100.64.0.3/32", "fd7a:115c:a1e0::3/128")}
	ts := &core.TailscaleInfo{Running: true, Kind: core.IfHeadscale, ControlURL: "https://hs.example.org:8080",
		IPs: []netip.Addr{netip.MustParseAddr("100.64.0.3"), netip.MustParseAddr("fd7a:115c:a1e0::3")}}
	v := BuildVPNs([]core.NetInterface{hs}, ts, core.AccessPolicy{Mode: "private"})[0]
	if v.ID != "headscale" || v.Label != "Headscale (hs.example.org)" || !slices.Equal(v.Ranges, []string{"100.64.0.0/10", "fd7a:115c:a1e0::/48"}) ||
		!v.CanAllow || !v.Recommended || v.Note != "" || v.Warning != "" || v.Allowed != "yes" || v.RoleSource != "auto" {
		t.Fatalf("default prefixes: %+v", v)
	}
	// Custom prefixes: nothing is guessed, the note says what to do.
	hs.Addrs = pfx("10.99.0.3/32", "fd00:99::3/128")
	ts.IPs = []netip.Addr{netip.MustParseAddr("10.99.0.3"), netip.MustParseAddr("fd00:99::3")}
	ts.KindGuessed = true
	v = BuildVPNs([]core.NetInterface{hs}, ts, core.AccessPolicy{Mode: "allowlist"})[0]
	if len(v.Ranges) != 0 || v.CanAllow || v.Recommended || v.Note != headscaleNote || v.Label != "Headscale (self-hosted control server?)" {
		t.Fatalf("custom prefixes: %+v", v)
	}
	// Without tailscaled's answer the interface addresses decide.
	hs.Addrs = pfx("100.64.0.3/32", "fd00:99::3/128")
	v = BuildVPNs([]core.NetInterface{hs}, nil, core.AccessPolicy{})[0]
	if !slices.Equal(v.Ranges, []string{"100.64.0.0/10"}) || v.Note != headscaleNote || !v.CanAllow || v.Label != "Headscale" {
		t.Fatalf("mixed: %+v", v)
	}
}

func TestVPNInfoJSONArrays(t *testing.T) {
	b, err := json.Marshal(BuildVPNs([]core.NetInterface{{Name: "wg0-mullvad", Kind: core.IfExitVPN, Provider: "mullvad",
		Label: "Mullvad VPN", Up: true, IsVPN: true, Role: "egress", Addrs: pfx("10.64.1.2/32")}}, nil, core.AccessPolicy{}))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), `"interfaces":["wg0-mullvad"]`) || !strings.Contains(string(b), `"ranges":[]`) ||
		!strings.Contains(string(b), `"role_source":"auto"`) {
		t.Fatal(string(b))
	}
}

func TestDefaultAllowlist(t *testing.T) {
	pp := netip.MustParsePrefix
	ifaces := []core.NetInterface{
		{Name: "lo", Kind: core.IfLoopback, Up: true, Addrs: []netip.Prefix{pp("127.0.0.1/8"), pp("::1/128")}},
		{Name: "eth0", Kind: core.IfLAN, Up: true, Addrs: []netip.Prefix{pp("192.168.1.10/24"), pp("fe80::1/64"), pp("fd00:1::6/64")}},
		{Name: "wlan0", Kind: core.IfWiFi, Up: true, Addrs: []netip.Prefix{pp("10.1.2.3/16")}},
		{Name: "eth1", Kind: core.IfLAN, Up: false, Addrs: []netip.Prefix{pp("172.16.0.5/24")}},
		{Name: "docker0", Kind: core.IfContainer, Up: true, Addrs: []netip.Prefix{pp("172.17.0.1/16")}},
		{Name: "tailscale0", Kind: core.IfTailscale, Up: true, IsVPN: true, Addrs: []netip.Prefix{pp("100.64.0.10/32")}},
		{Name: "wg0", Kind: core.IfWireGuard, Label: "WireGuard", Up: true, IsVPN: true, Addrs: []netip.Prefix{pp("10.8.0.2/24")}},
		{Name: "wg1", Kind: core.IfWireGuard, Label: "WireGuard", Up: true, IsVPN: true, Addrs: []netip.Prefix{pp("10.9.0.2/32")}},
		{Name: "zt0", Kind: core.IfZeroTier, Up: true, IsVPN: true, Addrs: []netip.Prefix{pp("10.147.17.5/24")}},
		{Name: "dup", Kind: core.IfLAN, Up: true, Addrs: []netip.Prefix{pp("192.168.1.7/24"), pp("169.254.3.3/16")}},
		// never: egress, access and overlay VPNs
		{Name: "wg0-mullvad", Kind: core.IfExitVPN, Label: "Mullvad VPN", Up: true, IsVPN: true, Role: "egress", Addrs: []netip.Prefix{pp("10.64.1.2/24")}},
		{Name: "nordlynx", Kind: core.IfExitVPN, Provider: "nordvpn", Label: "NordVPN", Up: true, IsVPN: true, Role: "egress", Addrs: []netip.Prefix{pp("10.5.0.2/16")}},
		{Name: "tun0", Kind: core.IfVPN, Label: "VPN", Up: true, IsVPN: true, Role: "egress", DefaultRoute: true, Addrs: []netip.Prefix{pp("10.20.0.2/24")}},
		{Name: "cscotun0", Kind: core.IfCorpVPN, Label: "Cisco Secure Client", Up: true, IsVPN: true, Role: "access", Addrs: []netip.Prefix{pp("10.200.0.9/24")}},
		{Name: "ygg0", Kind: core.IfYggdrasil, Label: "Yggdrasil", Up: true, IsVPN: true, Role: "overlay", Addrs: []netip.Prefix{pp("201:1:2::3/7")}},
	}
	allow, notes := DefaultAllowlist(ifaces, nil)
	want := "10.1.0.0/16,10.8.0.0/24,10.147.17.0/24,100.64.0.0/10,192.168.1.0/24,fd00:1::/64,fd7a:115c:a1e0::/48"
	if got := strings.Join(allow, ","); got != want {
		t.Fatalf("allow %s\nwant  %s", got, want)
	}
	if len(notes) != 1 || !strings.Contains(notes[0], "WireGuard (wg1)") || !strings.Contains(notes[0], "network allow add") {
		t.Fatalf("notes %v", notes)
	}
	if a, n := DefaultAllowlist(nil, nil); len(a) != 0 || a == nil || len(n) != 0 {
		t.Fatal(a, n)
	}

	// A cloud VM: eth0 carries a public address with the provider's netmask,
	// a private anchor address and the provider's IPv6 /64. Only the private
	// subnet is pre-filled; the public networks are reported.
	allow, notes = DefaultAllowlist([]core.NetInterface{
		{Name: "eth0", Kind: core.IfLAN, Label: "LAN", Up: true,
			Addrs: []netip.Prefix{pp("203.0.113.10/20"), pp("10.17.0.5/16"), pp("2001:db8:400:d1::1/64"), pp("fd12::5/64")}},
		{Name: "eth1", Kind: core.IfLAN, Up: true, Addrs: []netip.Prefix{pp("198.51.100.7/32")}},
		{Name: "cgnat", Kind: core.IfLAN, Up: true, Addrs: []netip.Prefix{pp("100.100.1.2/24")}},
	}, nil)
	if got := strings.Join(allow, ","); got != "10.17.0.0/16,100.100.1.0/24,fd12::/64" {
		t.Fatalf("VPS allow %s", got)
	}
	if len(notes) != 2 || !strings.Contains(notes[0], "eth0 (LAN)") || !strings.Contains(notes[0], "203.0.112.0/20, 2001:db8:400:d1::/64") ||
		!strings.Contains(notes[0], "--allow") || !strings.Contains(notes[1], "eth1") || !strings.Contains(notes[1], "198.51.100.7/32") {
		t.Fatalf("VPS notes %q", notes)
	}
	// A home dual-stack LAN keeps its global IPv6 /64 next to the private IPv4 subnet.
	allow, notes = DefaultAllowlist([]core.NetInterface{
		{Name: "eth2", Kind: core.IfLAN, Up: true, Addrs: []netip.Prefix{pp("192.168.1.10/24"), pp("2001:db8:f030:b300::6/64")}},
	}, nil)
	if got := strings.Join(allow, ","); got != "192.168.1.0/24,2001:db8:f030:b300::/64" || len(notes) != 0 {
		t.Fatalf("home allow %s notes %q", got, notes)
	}
	// Headscale with custom prefixes: nothing guessed, a note instead; a
	// VPN overridden to local counts as a LAN.
	allow, notes = DefaultAllowlist([]core.NetInterface{
		{Name: "tailscale0", Kind: core.IfHeadscale, Label: "Headscale", Up: true, IsVPN: true, Role: "mesh", Addrs: []netip.Prefix{pp("10.99.0.3/32")}},
		{Name: "zt3", Kind: core.IfZeroTier, Label: "ZeroTier", Up: true, IsVPN: true, Role: "local", RoleSource: "override", Addrs: []netip.Prefix{pp("10.147.20.5/24")}},
	}, &core.TailscaleInfo{Kind: core.IfHeadscale, ControlURL: "https://hs.example.org"})
	if got := strings.Join(allow, ","); got != "10.147.20.0/24" || len(notes) != 1 || !strings.Contains(notes[0], "Headscale (hs.example.org): custom Headscale prefixes") {
		t.Fatalf("headscale allow %s notes %q", got, notes)
	}
}

// Setting the Tailscale interface to egress (an exit-node-only machine)
// takes the MagicDNS name out of the URLs and the certificate names too.
func TestMagicDNSFollowsTheTailscaleRole(t *testing.T) {
	env, _ := testEnv(t)
	s := newTestService(t, env, &fakeSource{list: hostList()}, fakeLocalAPI(t, "https://controlplane.tailscale.com", "", nil))
	ctx := context.Background()
	const name = "files.tail1234.ts.net"
	hasMagic := func() bool {
		urls, _ := s.URLs(ctx)
		return slices.Contains(s.Hostnames(), name) && slices.ContainsFunc(urls, func(u core.AccessURL) bool { return u.Kind == core.URLKindMagicDNS })
	}
	if !hasMagic() {
		t.Fatal("MagicDNS missing")
	}
	if _, err := env.Settings.Set(ctx, nil, map[string]json.RawMessage{KeyIfaceRoles: json.RawMessage(`["tailscale0=egress"]`)}); err != nil {
		t.Fatal(err)
	}
	s.refresh(ctx, false, false) // not started: no settings.changed watcher
	urls, _ := s.URLs(ctx)
	if slices.Contains(s.Hostnames(), name) || slices.ContainsFunc(urls, func(u core.AccessURL) bool {
		return u.Kind == core.URLKindMagicDNS || u.Interface == "tailscale0"
	}) {
		t.Fatalf("egress tailscale0 still offered: %v %+v", s.Hostnames(), urls)
	}

	ts := core.NetInterface{Name: "tailscale0", Kind: core.IfTailscale, Up: true, Role: core.VPNRoleMesh}
	down := ts
	down.Up = false
	egress := ts
	egress.Role = core.VPNRoleEgress
	for _, c := range []struct {
		ifs  []core.NetInterface
		want bool
	}{
		{nil, true}, // userspace networking: no interface
		{[]core.NetInterface{ts}, true},
		{[]core.NetInterface{down}, true}, // tailscaled restarting
		{[]core.NetInterface{egress}, false},
	} {
		if got := magicDNSOffered(c.ifs); got != c.want {
			t.Errorf("%+v: %v", c.ifs, got)
		}
	}
}
