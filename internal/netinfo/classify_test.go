package netinfo

import (
	"net"
	"net/netip"
	"slices"
	"testing"

	"fileparcel/internal/core"
)

func pfx(ss ...string) []netip.Prefix {
	out := make([]netip.Prefix, len(ss))
	for i, s := range ss {
		out[i] = netip.MustParsePrefix(s)
	}
	return out
}

const up = net.FlagUp | net.FlagMulticast | net.FlagBroadcast

// fakeProbe returns a probe with the given binaries, processes and tinc /
// innernet interface names (no default routes).
func fakeProbe(binaries, processes, tinc, innernet []string) *hostProbe {
	return &hostProbe{
		hasBinary:      func(n string) bool { return slices.Contains(binaries, n) },
		processNamed:   func(c string) bool { return slices.Contains(processes, c) },
		tincIfaces:     func() []string { return tinc },
		innernetIfaces: func() []string { return innernet },
	}
}

func TestClassifyTable(t *testing.T) {
	tsIP := netip.MustParseAddr("100.101.102.103")
	linux := &classEnv{goos: "linux", probe: fakeProbe(nil, nil, []string{"vpnhome", "tinc-office"}, []string{"corpnet"})}
	linuxTS := &classEnv{goos: "linux", tsIPs: []netip.Addr{tsIP}, tsInstalled: true}
	headscale := &classEnv{goos: "linux", headscale: true}
	darwin := &classEnv{goos: "darwin"}
	darwinTS := &classEnv{goos: "darwin", tsInstalled: true}
	darwinTSIPs := &classEnv{goos: "darwin", tsIPs: []netip.Addr{netip.MustParseAddr("100.64.0.10")}, tsInstalled: true}
	darwinZT := &classEnv{goos: "darwin", probe: fakeProbe([]string{"zerotier-cli"}, nil, nil, nil)}
	withTools := &classEnv{goos: "linux", probe: fakeProbe([]string{"twingate", "vpnclient"}, []string{"openvpn"}, nil, nil)}
	cases := []struct {
		env              *classEnv
		r                rawIface
		kind, role, prov string
	}{
		// 1 loopback
		{linux, rawIface{Name: "lo", Flags: net.FlagUp | net.FlagLoopback, Addrs: pfx("127.0.0.1/8", "::1/128")}, core.IfLoopback, "none", ""},
		// 2 containers and VMs (a TAP that is a bridge port is one; NetworkManager's bridge is not)
		{linux, rawIface{Name: "docker0", Flags: up, Addrs: pfx("172.17.0.1/16")}, core.IfContainer, "none", ""},
		{linux, rawIface{Name: "docker0", Flags: up, Addrs: pfx("fd7a:115c:a1e0::9/128")}, core.IfContainer, "none", ""},
		{linux, rawIface{Name: "br-1a2b3c", Flags: up}, core.IfContainer, "none", ""},
		{linux, rawIface{Name: "veth12ab", Flags: up}, core.IfContainer, "none", ""},
		{linux, rawIface{Name: "virbr0", Flags: up}, core.IfContainer, "none", ""},
		{linux, rawIface{Name: "cni0", Flags: up}, core.IfContainer, "none", ""},
		{linux, rawIface{Name: "flannel.1", Flags: up}, core.IfContainer, "none", ""},
		{linux, rawIface{Name: "cali123", Flags: up}, core.IfContainer, "none", ""},
		{linux, rawIface{Name: "lxcbr0", Flags: up}, core.IfContainer, "none", ""},
		{linux, rawIface{Name: "lxdbr0", Flags: up}, core.IfContainer, "none", ""},
		{darwin, rawIface{Name: "vmnet8", Flags: up}, core.IfContainer, "none", ""},
		{linux, rawIface{Name: "vboxnet0", Flags: up}, core.IfContainer, "none", ""},
		{linux, rawIface{Name: "podman0", Flags: up}, core.IfContainer, "none", ""},
		{linux, rawIface{Name: "vnet3", Flags: up}, core.IfContainer, "none", ""},
		{linux, rawIface{Name: "macvtap0", Flags: up}, core.IfContainer, "none", ""},
		{linux, rawIface{Name: "tap0", Flags: up, IsTun: true, Master: "br0"}, core.IfContainer, "none", ""},
		{linux, rawIface{Name: "nm-bridge", Flags: up, DevType: "bridge", Addrs: pfx("192.168.50.1/24")}, core.IfLAN, "local", ""},
		// 3 Tailscale / Headscale
		{linux, rawIface{Name: "tailscale0", Flags: up, IsTun: true, Addrs: pfx("100.64.0.10/32")}, core.IfTailscale, "mesh", ""},
		{linux, rawIface{Name: "TailScale1", Flags: up}, core.IfTailscale, "mesh", ""},
		{headscale, rawIface{Name: "tailscale0", Flags: up}, core.IfHeadscale, "mesh", ""},
		{linux, rawIface{Name: "ts-custom", Flags: up, Addrs: pfx("fd7a:115c:a1e0::5/128")}, core.IfTailscale, "mesh", ""},
		{linuxTS, rawIface{Name: "userspace0", Flags: up, Addrs: pfx("100.101.102.103/32")}, core.IfTailscale, "mesh", ""},
		{darwinTS, rawIface{Name: "utun4", Flags: up, Addrs: pfx("100.81.1.2/32")}, core.IfTailscale, "mesh", ""},
		{darwin, rawIface{Name: "utun5", Flags: up, Addrs: pfx("fd7a:115c:a1e0::1/128")}, core.IfTailscale, "mesh", ""},
		{darwinTSIPs, rawIface{Name: "utun6", Flags: up, Addrs: pfx("100.64.0.10/32")}, core.IfTailscale, "mesh", ""},
		// Fixes #2: a CGNAT utun is Tailscale only while tailscaled's IPs are
		// unknown and Tailscale is installed (NetBird, WARP and Firezone use
		// 100.64/10 on macOS too).
		{darwin, rawIface{Name: "utun4", Flags: up, Addrs: pfx("100.81.1.2/32")}, core.IfVPN, "unknown", ""},
		{darwinTSIPs, rawIface{Name: "utun4", Flags: up, Addrs: pfx("100.96.0.5/32")}, core.IfVPN, "unknown", ""},
		{darwin, rawIface{Name: "utun2", Flags: up, Addrs: pfx("fe80::1/64")}, core.IfVPN, "unknown", ""},
		{linux, rawIface{Name: "utun3", Flags: up, Addrs: pfx("100.81.1.2/32")}, core.IfVPN, "unknown", ""},
		// 4 Yggdrasil (by name or 200::/7), 5 Husarnet (by name or fc94::/16)
		{linux, rawIface{Name: "ygg0", Flags: up}, core.IfYggdrasil, "overlay", ""},
		{linux, rawIface{Name: "tun0", Flags: up, IsTun: true, Addrs: pfx("200:1234::1/7")}, core.IfYggdrasil, "overlay", ""},
		{darwin, rawIface{Name: "utun5", Flags: up, Addrs: pfx("201:1234::1/7", "300:1234::1/64")}, core.IfYggdrasil, "overlay", ""},
		{linux, rawIface{Name: "tun1", Flags: up, IsTun: true, Addrs: pfx("300:1234:5678:9abc::1/64")}, core.IfYggdrasil, "overlay", ""},
		// A LAN with a Yggdrasil router's advertised 300::/64 subnet stays local.
		{linux, rawIface{Name: "enp3s0", Flags: up, Addrs: pfx("192.168.1.10/24", "fd12:3456:789a::10/64",
			"300:1234:5678:9abc:21a:2bff:fe3c:4d5e/64", "fe80::21a:2bff:fe3c:4d5e/64")}, core.IfLAN, "local", ""},
		{linux, rawIface{Name: "wlp2s0", Flags: up, Wireless: true, Addrs: pfx("300:1234:5678:9abc::7/64")}, core.IfWiFi, "local", ""},
		{linux, rawIface{Name: "hnet0", Flags: up}, core.IfHusarnet, "mesh", ""},
		{linux, rawIface{Name: "tun9", Flags: up, Addrs: pfx("fc94:1:2::3/16")}, core.IfHusarnet, "mesh", ""},
		// 6 NordVPN: Meshnet on nordlynx is mesh, the exit tunnel egress
		{linux, rawIface{Name: "nordlynx", Flags: up, DevType: "wireguard", Addrs: pfx("10.5.0.2/32", "100.90.1.2/32")}, core.IfExitVPN, "mesh", "nordvpn"},
		{linux, rawIface{Name: "nordlynx", Flags: up, DevType: "wireguard", Addrs: pfx("10.5.0.2/32")}, core.IfExitVPN, "egress", "nordvpn"},
		{linux, rawIface{Name: "nordtun", Flags: up, IsTun: true}, core.IfExitVPN, "egress", "nordvpn"},
		// 7 Mullvad, 8 Proton
		{linux, rawIface{Name: "wg0-mullvad", Flags: up, DevType: "wireguard"}, core.IfExitVPN, "egress", "mullvad"},
		{linux, rawIface{Name: "wg-mullvad", Flags: up}, core.IfExitVPN, "egress", "mullvad"},
		{linux, rawIface{Name: "proton0", Flags: up}, core.IfExitVPN, "egress", "proton"},
		{linux, rawIface{Name: "pvpnksintrf0", Flags: up}, core.IfExitVPN, "egress", "proton"},
		{linux, rawIface{Name: "ipv6leakintrf0", Flags: up}, core.IfExitVPN, "egress", "proton"},
		// 9 WARP, 10 Firezone, 11 Twingate, 12 corporate clients
		{linux, rawIface{Name: "CloudflareWARP", Flags: up, Addrs: pfx("100.96.0.5/32")}, core.IfWARP, "egress", "cloudflare"},
		{linux, rawIface{Name: "tun-firezone", Flags: up, IsTun: true}, core.IfFirezone, "access", "firezone"},
		{linux, rawIface{Name: "wg-firezone", Flags: up, DevType: "wireguard"}, core.IfFirezone, "unknown", "firezone"},
		{withTools, rawIface{Name: "sdwan0", Flags: up, IsTun: true}, core.IfTwingate, "access", "twingate"},
		{linux, rawIface{Name: "sdwan0", Flags: up, IsTun: true}, core.IfVPN, "unknown", ""},
		{linux, rawIface{Name: "cscotun0", Flags: up}, core.IfCorpVPN, "access", "cisco"},
		{linux, rawIface{Name: "gpd0", Flags: up}, core.IfCorpVPN, "access", "paloalto"},
		// 13 Netmaker, 14 innernet, 15 tinc
		{linux, rawIface{Name: "netmaker", Flags: up, DevType: "wireguard"}, core.IfNetmaker, "mesh", ""},
		{linux, rawIface{Name: "nm-mynet", Flags: up, DevType: "wireguard"}, core.IfNetmaker, "mesh", ""},
		{linux, rawIface{Name: "nm-mynet", Flags: up}, core.IfLAN, "local", ""},
		{linux, rawIface{Name: "corpnet", Flags: up, DevType: "wireguard"}, core.IfInnernet, "mesh", ""},
		{linux, rawIface{Name: "tinc0", Flags: up}, core.IfTinc, "unknown", ""},
		{linux, rawIface{Name: "vpnhome", Flags: up, IsTun: true}, core.IfTinc, "unknown", ""},
		{linux, rawIface{Name: "tinc-office", Flags: up}, core.IfTinc, "unknown", ""},
		// 16 ZeroTier (macOS feth only with zerotier-cli), 17 NetBird, 18 Nebula
		{linux, rawIface{Name: "zt7nnig26", Flags: up, Addrs: pfx("172.22.0.5/16")}, core.IfZeroTier, "mesh", ""},
		{darwinZT, rawIface{Name: "feth1234", Flags: up}, core.IfZeroTier, "mesh", ""},
		{darwin, rawIface{Name: "feth1234", Flags: up}, core.IfLAN, "local", ""},
		{linux, rawIface{Name: "feth1", Flags: up}, core.IfLAN, "local", ""},
		{linux, rawIface{Name: "wt0", Flags: up, DevType: "wireguard", Addrs: pfx("100.90.1.1/16")}, core.IfNetBird, "mesh", ""},
		{linux, rawIface{Name: "nb-home", Flags: up}, core.IfNetBird, "mesh", ""},
		{linux, rawIface{Name: "netbird1", Flags: up}, core.IfNetBird, "mesh", ""},
		{linux, rawIface{Name: "nebula1", Flags: up}, core.IfNebula, "mesh", ""},
		// 19 WireGuard (by name or DEVTYPE)
		{linux, rawIface{Name: "wg0", Flags: up, Addrs: pfx("10.8.0.1/24")}, core.IfWireGuard, "unknown", ""},
		{linux, rawIface{Name: "office", Flags: up, DevType: "wireguard"}, core.IfWireGuard, "unknown", ""},
		// 20 OpenVPN (by name or DEVTYPE; tun*/tap* only with an openvpn process)
		{linux, rawIface{Name: "ovpn-office", Flags: up}, core.IfOpenVPN, "unknown", ""},
		{linux, rawIface{Name: "as0t0", Flags: up, IsTun: true}, core.IfOpenVPN, "unknown", ""},
		{linux, rawIface{Name: "dco0", Flags: up, DevType: "ovpn-dco"}, core.IfOpenVPN, "unknown", ""},
		{linux, rawIface{Name: "vpn-dco", Flags: up, DevType: "ovpn"}, core.IfOpenVPN, "unknown", ""},
		{withTools, rawIface{Name: "tun0", Flags: up, IsTun: true}, core.IfOpenVPN, "unknown", ""},
		// 21 IPsec, 22 SoftEther (with vpnclient; else a TUN/TAP)
		{linux, rawIface{Name: "ipsec0", Flags: up}, core.IfIPsec, "unknown", ""},
		{linux, rawIface{Name: "xfrm1", Flags: up}, core.IfIPsec, "unknown", ""},
		{linux, rawIface{Name: "vti0", Flags: up}, core.IfIPsec, "unknown", ""},
		{linux, rawIface{Name: "ip_vti0", Flags: up}, core.IfIPsec, "unknown", ""},
		{withTools, rawIface{Name: "vpn_home", Flags: up, IsTun: true}, core.IfSoftEther, "unknown", ""},
		{linux, rawIface{Name: "vpn_home", Flags: up, IsTun: true}, core.IfVPN, "unknown", ""},
		// 23 other tunnels (fixes #3: any Linux TUN/TAP, whatever its name)
		{linux, rawIface{Name: "tun0", Flags: up}, core.IfVPN, "unknown", ""},
		{linux, rawIface{Name: "tap1", Flags: up}, core.IfVPN, "unknown", ""},
		{linux, rawIface{Name: "ppp0", Flags: up}, core.IfVPN, "unknown", ""},
		{linux, rawIface{Name: "edge0", Flags: up, IsTun: true}, core.IfVPN, "unknown", ""},
		// 24 Wi-Fi, 25 LAN
		{linux, rawIface{Name: "wlan0", Flags: up, Wireless: true}, core.IfWiFi, "local", ""},
		{linux, rawIface{Name: "wlp3s0", Flags: up}, core.IfWiFi, "local", ""},
		{linux, rawIface{Name: "mywifi", Flags: up, Wireless: true, DevType: "wlan"}, core.IfWiFi, "local", ""},
		{linux, rawIface{Name: "eth2", Flags: up, Addrs: pfx("192.168.1.10/24")}, core.IfLAN, "local", ""},
		{linux, rawIface{Name: "enp5s0", Flags: up}, core.IfLAN, "local", ""},
		{darwin, rawIface{Name: "en0", Flags: up}, core.IfLAN, "local", ""},
		{linux, rawIface{Name: "eth0", Flags: net.FlagBroadcast}, core.IfLAN, "local", ""}, // down still classified
	}
	for _, c := range cases {
		got := classify(c.r, c.env)
		if got.kind != c.kind || got.role != c.role || got.provider != c.prov || got.label == "" {
			t.Errorf("%s %s %v: got %+v, want %s/%s/%q", c.env.goos, c.r.Name, c.r.Addrs, got, c.kind, c.role, c.prov)
		}
	}
	// Labels and details of the branded rows.
	for name, want := range map[string][2]string{
		"wg0-mullvad": {"Mullvad VPN", ""}, "proton0": {"Proton VPN", ""}, "pvpnksintrf1": {"Proton VPN", detailKillSwitch},
		"cscotun0": {"Cisco Secure Client", ""}, "gpd0": {"GlobalProtect", ""}, "nordtun": {"NordVPN", ""},
	} {
		got := classify(rawIface{Name: name, Flags: up}, linux)
		if got.label != want[0] || got.detail != want[1] {
			t.Errorf("%s: %+v", name, got)
		}
	}
	mesh := classify(rawIface{Name: "nordlynx", Flags: up, Addrs: pfx("100.90.1.2/32")}, linux)
	if mesh.label != "NordVPN Meshnet" || mesh.detail != detailMeshnet {
		t.Errorf("meshnet %+v", mesh)
	}
	// Weak signals are only asked for when a rule needs them.
	asked := map[string]int{}
	counting := &classEnv{goos: "linux", probe: &hostProbe{
		hasBinary:    func(n string) bool { asked["bin:"+n]++; return false },
		processNamed: func(c string) bool { asked["proc:"+c]++; return false },
	}}
	for _, n := range []string{"eth0", "wlan0", "wg0", "tailscale0", "docker0"} {
		classify(rawIface{Name: n, Flags: up}, counting)
	}
	if len(asked) != 0 {
		t.Errorf("probes asked %v", asked)
	}
	classify(rawIface{Name: "tun0", Flags: up}, counting)
	if asked["proc:openvpn"] != 1 {
		t.Errorf("openvpn process not asked for tun0: %v", asked)
	}
}

func TestToNetInterface(t *testing.T) {
	env := &classEnv{goos: "linux"}
	r := rawIface{Name: "tailscale0", Flags: up, MTU: 1280, Addrs: pfx("100.64.0.10/32", "fd7a:115c:a1e0::a/128")}
	ni := toNetInterface(r, classify(r, env), false)
	if ni.Kind != core.IfTailscale || ni.Label != "Tailscale" || !ni.IsVPN || !ni.Up || ni.MTU != 1280 || len(ni.Addrs) != 2 ||
		ni.Role != core.VPNRoleMesh || ni.RoleSource != core.VPNRoleSourceAuto || ni.DefaultRoute || ni.Detail != "" {
		t.Fatalf("%+v", ni)
	}
	// A product mesh VPN stays mesh with the default route (Tailscale exit
	// node in table 52); it is only shown as the detail.
	ni = toNetInterface(r, classify(r, env), true)
	if ni.Role != core.VPNRoleMesh || !ni.DefaultRoute || ni.Detail != detailDefaultRoute {
		t.Fatalf("exit node: %+v", ni)
	}
	hs := toNetInterface(r, classify(r, &classEnv{goos: "linux", headscale: true}), false)
	if hs.Kind != core.IfHeadscale || hs.Label != "Headscale" || !hs.IsVPN {
		t.Fatalf("headscale: %+v", hs)
	}
	lan := rawIface{Name: "eth2", Flags: up, Addrs: pfx("192.168.1.10/24")}
	if ni := toNetInterface(lan, classify(lan, env), true); ni.Kind != core.IfLAN || ni.IsVPN || ni.Label != "LAN" ||
		ni.Role != core.VPNRoleLocal || ni.DefaultRoute || ni.Detail != "" {
		t.Fatalf("lan (default route is no detail there): %+v", ni)
	}
	// The default-route rule: generic tunnels become egress.
	for _, c := range []struct {
		r            rawIface
		defRoute     bool
		role, label  string
		defaultRoute bool
	}{
		{rawIface{Name: "wg0", Flags: up}, false, core.VPNRoleUnknown, "WireGuard", false},
		{rawIface{Name: "wg0", Flags: up}, true, core.VPNRoleEgress, "WireGuard", true},
		{rawIface{Name: "tun0", Flags: up, IsTun: true}, true, core.VPNRoleEgress, "VPN", true},
		{rawIface{Name: "ppp0", Flags: up, Addrs: pfx("203.0.113.5/32")}, true, core.VPNRoleEgress, "PPP internet uplink", true},
		{rawIface{Name: "ppp0", Flags: up}, false, core.VPNRoleUnknown, "VPN", false},
		{rawIface{Name: "ipsec0", Flags: up}, true, core.VPNRoleEgress, "IPsec", true},
		{rawIface{Name: "tinc0", Flags: up}, true, core.VPNRoleEgress, "tinc", true},
		{rawIface{Name: "ovpn0", Flags: up}, true, core.VPNRoleEgress, "OpenVPN", true},
		{rawIface{Name: "zt0", Flags: up}, true, core.VPNRoleMesh, "ZeroTier", true},
		{rawIface{Name: "wt0", Flags: up}, true, core.VPNRoleMesh, "NetBird", true},
		{rawIface{Name: "wg-firezone", Flags: up}, true, core.VPNRoleUnknown, "Firezone", true},
		{rawIface{Name: "wg0-mullvad", Flags: up}, true, core.VPNRoleEgress, "Mullvad VPN", true},
	} {
		ni := toNetInterface(c.r, classify(c.r, env), c.defRoute)
		if ni.Role != c.role || ni.Label != c.label || ni.DefaultRoute != c.defaultRoute ||
			(c.defaultRoute && ni.Detail != detailDefaultRoute) {
			t.Errorf("%s default=%v: %+v", c.r.Name, c.defRoute, ni)
		}
	}
	down := toNetInterface(rawIface{Name: "eth0", Flags: net.FlagBroadcast}, ifaceClass{kind: core.IfLAN, role: "local"}, false)
	if down.Up || offered(down) {
		t.Fatalf("down: %+v", down)
	}
}

func TestPrefixOf(t *testing.T) {
	_, n4, _ := net.ParseCIDR("192.168.1.10/24")
	n4.IP = net.ParseIP("192.168.1.10") // 16-byte form, as net.Interface.Addrs may return
	n4.Mask = net.CIDRMask(120, 128)
	p, ok := prefixOf(n4)
	if !ok || p.String() != "192.168.1.10/24" {
		t.Fatalf("v4 in v6 form: %v %v", p, ok)
	}
	p, ok = prefixOf(&net.IPNet{IP: net.ParseIP("fe80::1"), Mask: net.CIDRMask(64, 128)})
	if !ok || p.String() != "fe80::1/64" {
		t.Fatalf("v6: %v", p)
	}
	p, ok = prefixOf(&net.IPAddr{IP: net.ParseIP("10.0.0.1")})
	if !ok || p.String() != "10.0.0.1/32" {
		t.Fatalf("ipaddr: %v", p)
	}
	if _, ok := prefixOf(&net.UnixAddr{Name: "x"}); ok {
		t.Fatal("unix addr accepted")
	}
}

func TestUsableAddr(t *testing.T) {
	for s, want := range map[string]bool{
		"192.168.1.10": true, "100.64.0.10": true, "2001:db8::1": true, "fd7a:115c:a1e0::1": true,
		"127.0.0.1": false, "::1": false, "fe80::1": false, "169.254.3.4": false, "0.0.0.0": false,
		"224.0.0.251": false, "ff02::fb": false, "::ffff:192.168.1.10": true,
	} {
		if got := usableAddr(netip.MustParseAddr(s)); got != want {
			t.Errorf("%s: %v", s, got)
		}
	}
	if safeIfName("../etc") || safeIfName("") || safeIfName("..") || !safeIfName("eth0") {
		t.Fatal("safeIfName")
	}
}

func TestUeventDevType(t *testing.T) {
	for in, want := range map[string]string{
		"DEVTYPE=wireguard\nINTERFACE=wg0\nIFINDEX=9\n": "wireguard",
		"INTERFACE=ovpn0\nIFINDEX=12\nDEVTYPE=ovpn-dco": "ovpn-dco",
		"INTERFACE=eth0\nIFINDEX=2\n":                   "",
		"DEVTYPE=WLAN\n":                                "wlan",
	} {
		if got := ueventDevType([]byte(in)); got != want {
			t.Errorf("%q: %q", in, got)
		}
	}
}
