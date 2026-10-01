package netinfo

import (
	"net"
	"net/netip"
	"slices"
	"strings"

	"fileparcel/internal/core"
)

// rawIface is one interface as reported by the operating system, before
// classification. The interface source (net.Interfaces on a real system, a
// fake list in tests) produces these.
type rawIface struct {
	Name     string
	Index    int
	Flags    net.Flags
	MTU      int
	Addrs    []netip.Prefix
	Wireless bool   // Linux: /sys/class/net/<name>/wireless or phy80211 exists
	DevType  string // Linux: DEVTYPE= of /sys/class/net/<name>/uevent ("wireguard", "ovpn-dco", "bridge", …)
	IsTun    bool   // Linux: /sys/class/net/<name>/tun_flags exists (TUN/TAP device)
	Master   string // Linux: the bridge or bond the interface is a port of
}

// Address ranges that identify a product (DESIGN §10.1, §10.3).
var (
	tailnetV4    = netip.MustParsePrefix("100.64.0.0/10")
	tailnetV6    = netip.MustParsePrefix("fd7a:115c:a1e0::/48")
	yggdrasilNet = netip.MustParsePrefix("200::/7")
	// yggdrasilNode holds the node addresses, which exist only on the
	// Yggdrasil TUN. 300::/8 are the nodes' /64 subnets, which a router
	// advertises on an ordinary LAN (radvd): a LAN interface with such an
	// address stays local.
	yggdrasilNode = netip.MustParsePrefix("200::/8")
	husarnetNet   = netip.MustParsePrefix("fc94::/16")
)

// kindLabels are the human labels of the interface kinds.
var kindLabels = map[string]string{
	core.IfLoopback:  "Loopback",
	core.IfTailscale: "Tailscale",
	core.IfHeadscale: "Headscale",
	core.IfYggdrasil: "Yggdrasil",
	core.IfHusarnet:  "Husarnet",
	core.IfExitVPN:   "Exit VPN",
	core.IfWARP:      "Cloudflare WARP",
	core.IfFirezone:  "Firezone",
	core.IfTwingate:  "Twingate",
	core.IfCorpVPN:   "Corporate VPN",
	core.IfNetmaker:  "Netmaker",
	core.IfInnernet:  "innernet",
	core.IfTinc:      "tinc",
	core.IfZeroTier:  "ZeroTier",
	core.IfNetBird:   "NetBird",
	core.IfNebula:    "Nebula",
	core.IfWireGuard: "WireGuard",
	core.IfOpenVPN:   "OpenVPN",
	core.IfIPsec:     "IPsec",
	core.IfSoftEther: "SoftEther VPN",
	core.IfVPN:       "VPN",
	core.IfContainer: "Container",
	core.IfWiFi:      "Wi-Fi",
	core.IfLAN:       "LAN",
}

// vpnKinds are the kinds reported with is_vpn = true: every kind but
// loopback, container, wifi and lan.
var vpnKinds = map[string]bool{
	core.IfTailscale: true, core.IfHeadscale: true, core.IfYggdrasil: true, core.IfHusarnet: true,
	core.IfExitVPN: true, core.IfWARP: true, core.IfFirezone: true, core.IfTwingate: true, core.IfCorpVPN: true,
	core.IfNetmaker: true, core.IfInnernet: true, core.IfTinc: true, core.IfZeroTier: true, core.IfNetBird: true,
	core.IfNebula: true, core.IfWireGuard: true, core.IfOpenVPN: true, core.IfIPsec: true, core.IfSoftEther: true,
	core.IfVPN: true,
}

// genericTunnels are the kinds without a product signal: one of them that
// carries the effective default route is an exit VPN or an internet uplink
// (role egress). Product mesh VPNs keep their role with a default route
// (a Tailscale exit node, ZeroTier global routes): their peers still reach
// this machine.
var genericTunnels = map[string]bool{
	core.IfWireGuard: true, core.IfOpenVPN: true, core.IfIPsec: true, core.IfSoftEther: true, core.IfTinc: true,
	core.IfVPN: true,
}

// Name prefixes of the classification table (DESIGN §10.1).
var (
	netbirdPrefixes   = []string{"wt", "nb-", "netbird"}
	ipsecPrefixes     = []string{"ipsec", "xfrm", "vti", "ip_vti"}
	vpnPrefixes       = []string{"tun", "tap", "ppp", "utun"}
	protonPrefixes    = []string{"pvpnksintrf", "ipv6leakintrf"} // Proton VPN's kill-switch dummies
	containerPrefixes = []string{"docker", "br-", "veth", "virbr", "cni", "flannel", "cali", "lxc", "lxd",
		"vmnet", "vboxnet", "podman", "vnet", "macvtap"}
)

// Details of NetInterface.Detail.
const (
	detailDefaultRoute = "carries the default route"
	detailMeshnet      = "NordVPN Meshnet"
	detailKillSwitch   = "kill-switch interface"
)

func hasAnyPrefix(name string, prefixes []string) bool {
	for _, p := range prefixes {
		if strings.HasPrefix(name, p) {
			return true
		}
	}
	return false
}

// carriesTailnet reports whether the interface has an address in the
// Tailscale ranges. strict limits the check to the Tailscale-specific IPv6
// ULA (100.64.0.0/10 is shared with NetBird and ISP CGNAT, DESIGN §18.16).
func carriesTailnet(r rawIface, strict bool) bool {
	return carriesIn(r, tailnetV6) || (!strict && carriesIn(r, tailnetV4))
}

// carriesIn reports whether the interface has an address inside p.
func carriesIn(r rawIface, p netip.Prefix) bool {
	for _, a := range r.Addrs {
		if p.Contains(a.Addr().Unmap().WithZone("")) {
			return true
		}
	}
	return false
}

// carriesAny reports whether the interface has one of ips.
func carriesAny(r rawIface, ips []netip.Addr) bool {
	for _, p := range r.Addrs {
		if slices.Contains(ips, p.Addr().Unmap().WithZone("")) {
			return true
		}
	}
	return false
}

// classEnv holds the signals classification uses beyond the interface
// itself.
type classEnv struct {
	goos string
	// tsIPs are tailscaled's addresses of this node (nil: unknown).
	tsIPs []netip.Addr
	// tsInstalled: a tailscaled socket or the tailscale CLI exists.
	tsInstalled bool
	// headscale: the node's control server is not Tailscale's.
	headscale bool
	// probe supplies the weak signals (installed binaries, running
	// processes, tinc and innernet configuration); nil: none.
	probe *hostProbe
}

func (e *classEnv) hasBinary(name string) bool {
	return e.probe != nil && e.probe.hasBinary != nil && e.probe.hasBinary(name)
}

func (e *classEnv) processNamed(comm string) bool {
	return e.probe != nil && e.probe.processNamed != nil && e.probe.processNamed(comm)
}

func (e *classEnv) tincIface(name string) bool {
	return e.probe != nil && e.probe.tincIfaces != nil && slices.Contains(e.probe.tincIfaces(), name)
}

func (e *classEnv) innernetIface(name string) bool {
	return e.probe != nil && e.probe.innernetIfaces != nil && slices.Contains(e.probe.innernetIfaces(), name)
}

// ifaceClass is the result of classify.
type ifaceClass struct {
	kind, label, provider, role, detail string
}

// classify returns the kind, label, provider and role of r following the
// table of DESIGN §10.1, evaluated top to bottom. Only strong signals (an
// exact product name, a product address range, the Linux DEVTYPE) give
// the excluding roles (access, egress, overlay); weak ones (an installed
// binary, a running process) only refine a label or confirm a generic
// name. The default-route rule is applied afterwards (withDefaultRoute).
//
//	loopback   FlagLoopback                                          none
//	container  docker*, br-*, veth*, virbr*, cni*, flannel*, cali*, lxc*, lxd*,
//	           vmnet*, vboxnet*, podman*, vnet*, macvtap*; a TAP that is a
//	           bridge port                                           none
//	tailscale  tailscale*; an address in fd7a:115c:a1e0::/48 or one of
//	           tailscaled's IPs; darwin utun* with 100.64.0.0/10 only while
//	           those IPs are unknown and Tailscale is installed      mesh
//	yggdrasil  ygg*, an address in 200::/8 (a node address), a TUN with
//	           an address in 200::/7 (300::/8 subnet addresses of a LAN
//	           interface do not count)                               overlay
//	husarnet   hnet*, an address in fc94::/16                        mesh
//	exitvpn    nordlynx (mesh with a 100.64.0.0/10 Meshnet address, then
//	           only those are offered), nordtun, *-mullvad, proton0,
//	           pvpnksintrf*, ipv6leakintrf*                          egress
//	warp       cloudflarewarp                                        egress
//	firezone   tun-firezone (client)                                 access
//	           wg-firezone (0.x server)                              unknown
//	twingate   sdwan0 with the twingate binary                       access
//	corpvpn    cscotun* (Cisco Secure Client), gpd* (GlobalProtect)  access
//	netmaker   netmaker, nm-* with DEVTYPE=wireguard                 mesh
//	innernet   a network name in /etc/innernet/*.conf                mesh
//	tinc       tinc*, a tinc network name or Interface =             unknown
//	zerotier   zt*; darwin feth* with zerotier-cli                   mesh
//	netbird    wt*, nb-*, netbird*                                   mesh
//	nebula     nebula*                                               mesh
//	wireguard  wg*, DEVTYPE=wireguard                                unknown
//	openvpn    ovpn*, as0t*, DEVTYPE=ovpn-dco|ovpn; tun*/tap* while an
//	           openvpn process runs                                  unknown
//	ipsec      ipsec*, xfrm*, vti*, ip_vti*                          unknown
//	softether  vpn_* with the vpnclient binary                       unknown
//	vpn        tun*, tap*, ppp*, other utun*, any Linux TUN/TAP      unknown
//	wifi       Wireless (Linux sysfs) or wl*                         local
//	lan        everything else                                       local
//
// headscale (for tailscale) comes from the control URL (env.headscale).
func classify(r rawIface, env *classEnv) ifaceClass {
	name := strings.ToLower(r.Name)
	c := func(kind, role string) ifaceClass { return ifaceClass{kind: kind, label: kindLabels[kind], role: role} }
	product := func(kind, label, provider, role string) ifaceClass {
		return ifaceClass{kind: kind, label: label, provider: provider, role: role}
	}
	switch {
	case r.Flags&net.FlagLoopback != 0:
		return c(core.IfLoopback, core.VPNRoleNone)
	case hasAnyPrefix(name, containerPrefixes), r.IsTun && r.Master != "":
		return c(core.IfContainer, core.VPNRoleNone)
	case strings.HasPrefix(name, "tailscale"),
		env.goos == "darwin" && strings.HasPrefix(name, "utun") && len(env.tsIPs) == 0 && env.tsInstalled && carriesTailnet(r, false),
		carriesTailnet(r, true),
		len(env.tsIPs) > 0 && carriesAny(r, env.tsIPs):
		if env.headscale {
			return c(core.IfHeadscale, core.VPNRoleMesh)
		}
		return c(core.IfTailscale, core.VPNRoleMesh)
	case strings.HasPrefix(name, "ygg"), carriesIn(r, yggdrasilNode), r.IsTun && carriesIn(r, yggdrasilNet):
		return c(core.IfYggdrasil, core.VPNRoleOverlay)
	case strings.HasPrefix(name, "hnet"), carriesIn(r, husarnetNet):
		return c(core.IfHusarnet, core.VPNRoleMesh)
	case name == "nordlynx":
		if carriesIn(r, tailnetV4) {
			x := product(core.IfExitVPN, "NordVPN Meshnet", "nordvpn", core.VPNRoleMesh)
			x.detail = detailMeshnet
			return x
		}
		return product(core.IfExitVPN, "NordVPN", "nordvpn", core.VPNRoleEgress)
	case name == "nordtun":
		return product(core.IfExitVPN, "NordVPN", "nordvpn", core.VPNRoleEgress)
	case strings.HasSuffix(name, "-mullvad"):
		return product(core.IfExitVPN, "Mullvad VPN", "mullvad", core.VPNRoleEgress)
	case name == "proton0":
		return product(core.IfExitVPN, "Proton VPN", "proton", core.VPNRoleEgress)
	case hasAnyPrefix(name, protonPrefixes):
		x := product(core.IfExitVPN, "Proton VPN", "proton", core.VPNRoleEgress)
		x.detail = detailKillSwitch
		return x
	case name == "cloudflarewarp":
		return product(core.IfWARP, "Cloudflare WARP", "cloudflare", core.VPNRoleEgress)
	case name == "tun-firezone":
		return product(core.IfFirezone, "Firezone", "firezone", core.VPNRoleAccess)
	case name == "wg-firezone":
		return product(core.IfFirezone, "Firezone", "firezone", core.VPNRoleUnknown)
	case name == "sdwan0" && env.hasBinary("twingate"):
		return product(core.IfTwingate, "Twingate", "twingate", core.VPNRoleAccess)
	case strings.HasPrefix(name, "cscotun"):
		return product(core.IfCorpVPN, "Cisco Secure Client", "cisco", core.VPNRoleAccess)
	case strings.HasPrefix(name, "gpd"):
		return product(core.IfCorpVPN, "GlobalProtect", "paloalto", core.VPNRoleAccess)
	case name == "netmaker", strings.HasPrefix(name, "nm-") && r.DevType == "wireguard":
		return c(core.IfNetmaker, core.VPNRoleMesh)
	case env.innernetIface(r.Name):
		return c(core.IfInnernet, core.VPNRoleMesh)
	case strings.HasPrefix(name, "tinc"), env.tincIface(r.Name):
		return c(core.IfTinc, core.VPNRoleUnknown)
	case strings.HasPrefix(name, "zt"), env.goos == "darwin" && strings.HasPrefix(name, "feth") && env.hasBinary("zerotier-cli"):
		return c(core.IfZeroTier, core.VPNRoleMesh)
	case hasAnyPrefix(name, netbirdPrefixes):
		return c(core.IfNetBird, core.VPNRoleMesh)
	case strings.HasPrefix(name, "nebula"):
		return c(core.IfNebula, core.VPNRoleMesh)
	case strings.HasPrefix(name, "wg"), r.DevType == "wireguard":
		return c(core.IfWireGuard, core.VPNRoleUnknown)
	case strings.HasPrefix(name, "ovpn"), strings.HasPrefix(name, "as0t"), r.DevType == "ovpn-dco", r.DevType == "ovpn",
		(strings.HasPrefix(name, "tun") || strings.HasPrefix(name, "tap")) && env.processNamed("openvpn"):
		return c(core.IfOpenVPN, core.VPNRoleUnknown)
	case hasAnyPrefix(name, ipsecPrefixes):
		return c(core.IfIPsec, core.VPNRoleUnknown)
	case strings.HasPrefix(name, "vpn_") && env.hasBinary("vpnclient"):
		return c(core.IfSoftEther, core.VPNRoleUnknown)
	case hasAnyPrefix(name, vpnPrefixes), r.IsTun:
		return c(core.IfVPN, core.VPNRoleUnknown)
	case r.Wireless, strings.HasPrefix(name, "wl"):
		return c(core.IfWiFi, core.VPNRoleLocal)
	}
	return c(core.IfLAN, core.VPNRoleLocal)
}

// toNetInterface builds the API view of a classified interface. defRoute
// reports whether it carries the effective default route: a generic
// tunnel then becomes egress ("PPP internet uplink" for ppp*); every VPN
// shows it as its detail.
func toNetInterface(r rawIface, c ifaceClass, defRoute bool) core.NetInterface {
	addrs := make([]netip.Prefix, 0, len(r.Addrs))
	for _, p := range r.Addrs {
		if p.IsValid() {
			addrs = append(addrs, p)
		}
	}
	ni := core.NetInterface{
		Name:       r.Name,
		Kind:       c.kind,
		Label:      c.label,
		Up:         r.Flags&net.FlagUp != 0,
		Addrs:      addrs,
		MTU:        r.MTU,
		IsVPN:      vpnKinds[c.kind],
		Role:       c.role,
		RoleSource: core.VPNRoleSourceAuto,
		Provider:   c.provider,
		Detail:     c.detail,
	}
	if defRoute && ni.IsVPN {
		ni.DefaultRoute = true
		if genericTunnels[ni.Kind] && ni.Role == core.VPNRoleUnknown {
			ni.Role = core.VPNRoleEgress
			if strings.HasPrefix(strings.ToLower(ni.Name), "ppp") {
				ni.Label = "PPP internet uplink"
			}
		}
		if ni.Detail == "" {
			ni.Detail = detailDefaultRoute
		}
	}
	return ni
}

// usableAddr reports whether a is offered as an access address: a unicast
// address that is neither loopback, unspecified, multicast nor link-local
// (fe80::/10, 169.254.0.0/16 — they need a zone or only work on-link).
func usableAddr(a netip.Addr) bool {
	a = a.Unmap()
	return a.IsValid() && !a.IsLoopback() && !a.IsUnspecified() && !a.IsMulticast() &&
		!a.IsLinkLocalUnicast() && !a.IsLinkLocalMulticast() && !a.IsInterfaceLocalMulticast()
}
