package netinfo

import (
	"fmt"
	"net/netip"
	"net/url"
	"slices"
	"strings"

	"fileparcel/internal/core"
)

// The VPN list (DESIGN §10.3): one entry per detected VPN with the ranges
// "allow" adds, whether the access policy admits them and whether the
// install-time allowlist includes them. It is the basis of
// `fileparcel network vpn …`, the policy editor's suggestions, the
// installer's allowlist and the doctor's VPN rows.

// Texts of the VPN list.
const (
	tailnetWarning = "shared with NetBird, NordVPN Meshnet, Cloudflare WARP and ISP carrier-grade NAT"
	headscaleNote  = "custom Headscale prefixes: add them with `fileparcel network allow add <prefix>` " +
		"(see `prefixes` in headscale's config)"
	husarnetNote     = "every Husarnet device you allowed in your Husarnet dashboard"
	yggdrasilWarning = "public overlay: anyone on the Yggdrasil network"
	overlayWarning   = "public overlay: anyone on it may connect"
	warpNote         = "peer-to-peer in a Zero Trust org uses 100.96.0.0/12; set the role to mesh if you use it"
	firezoneNote     = "on a Firezone Gateway, allow the Firezone client address range manually"
	hostOnlyNote     = "host-only address: add its network with `fileparcel network allow add CIDR`"
)

// Allowed values of VPNInfo.Allowed.
const (
	allowedYes    = "yes"
	allowedPartly = "partly"
	allowedNo     = "no"
)

// singleProduct are the kinds listed as one VPN whatever the number of
// interfaces (ZeroTier networks, …); the others are listed per interface.
var singleProduct = map[string]bool{
	core.IfTailscale: true, core.IfHeadscale: true, core.IfZeroTier: true, core.IfNetBird: true,
	core.IfHusarnet: true, core.IfYggdrasil: true, core.IfWARP: true, core.IfTwingate: true,
}

// roleRank orders the VPN list: VPNs devices come in through first.
var roleRank = map[string]int{core.VPNRoleMesh: 0, core.VPNRoleUnknown: 1, core.VPNRoleOverlay: 2,
	core.VPNRoleLocal: 3, core.VPNRoleAccess: 4, core.VPNRoleEgress: 5, core.VPNRoleNone: 6}

// providerKinds are listed by their provider (one entry for NordVPN,
// Mullvad, Proton, Cisco, GlobalProtect, Firezone) rather than per
// interface.
var providerKinds = map[string]bool{core.IfExitVPN: true, core.IfCorpVPN: true, core.IfFirezone: true}

// vpnID returns the list ID of a VPN interface: the product for
// single-product VPNs and branded exit/corporate VPNs, else the interface
// name. product reports the former.
func vpnID(ni core.NetInterface) (id string, product bool) {
	switch {
	case singleProduct[ni.Kind]:
		return ni.Kind, true
	case providerKinds[ni.Kind] && ni.Provider != "":
		return ni.Provider, true
	}
	return ni.Name, false
}

// listedAsVPN reports whether ni appears in the VPN list: an up VPN
// interface with a usable address, or another interface an administrator
// gave a VPN role.
func listedAsVPN(ni core.NetInterface) bool {
	if !ni.Up || !slices.ContainsFunc(ni.Addrs, func(p netip.Prefix) bool { return usableAddr(p.Addr()) }) {
		return false
	}
	if ni.IsVPN || vpnKinds[ni.Kind] {
		return true
	}
	r := RoleOf(ni)
	return ni.RoleSource == core.VPNRoleSourceOverride && r != core.VPNRoleLocal && r != core.VPNRoleNone
}

// BuildVPNs lists the VPNs of ifaces (DESIGN §10.3). ts (may be nil) tells
// Headscale's node addresses and control server; pol decides Allowed.
// Interfaces of one product (ZeroTier networks, Proton VPN's kill-switch
// interfaces) are merged unless their roles differ (an override on one
// ZeroTier network), then each is listed on its own. VPNs devices come in
// through come first. The list and its arrays are never nil.
func BuildVPNs(ifaces []core.NetInterface, ts *core.TailscaleInfo, pol core.AccessPolicy) []core.VPNInfo {
	m, err := compilePolicy(pol)
	if err != nil {
		m = defaultMatcher()
	}
	type group struct {
		id      string
		product bool
		ifaces  []core.NetInterface
	}
	var groups []*group
	byID := map[string]*group{}
	for _, ni := range ifaces {
		if !listedAsVPN(ni) {
			continue
		}
		id, product := vpnID(ni)
		if g := byID[id]; g != nil {
			g.ifaces = append(g.ifaces, ni)
			continue
		}
		g := &group{id: id, product: product, ifaces: []core.NetInterface{ni}}
		byID[id] = g
		groups = append(groups, g)
	}
	out := []core.VPNInfo{}
	for _, g := range groups {
		mixed := slices.ContainsFunc(g.ifaces, func(ni core.NetInterface) bool {
			return RoleOf(ni) != RoleOf(g.ifaces[0]) || ni.RoleSource != g.ifaces[0].RoleSource
		})
		if mixed {
			for _, ni := range g.ifaces {
				out = append(out, buildVPN(ni.Name, false, []core.NetInterface{ni}, ts, m))
			}
			continue
		}
		out = append(out, buildVPN(g.id, g.product, g.ifaces, ts, m))
	}
	slices.SortStableFunc(out, func(a, b core.VPNInfo) int { return roleRank[a.Role] - roleRank[b.Role] })
	return out
}

// buildVPN builds one list entry of the interfaces ifs (one VPN, one
// role). A product entry is labelled by the product ("ZeroTier"), any
// other by kind and interface ("WireGuard (wg0)").
func buildVPN(id string, product bool, ifs []core.NetInterface, ts *core.TailscaleInfo, m *matcher) core.VPNInfo {
	first := ifs[0]
	v := core.VPNInfo{
		ID:         id,
		Kind:       first.Kind,
		Label:      vpnLabel(first, ts),
		Provider:   first.Provider,
		Role:       RoleOf(first),
		RoleSource: first.RoleSource,
		Interfaces: []string{},
		Ranges:     []string{},
	}
	if v.RoleSource == "" {
		v.RoleSource = core.VPNRoleSourceAuto
	}
	for _, ni := range ifs {
		v.Interfaces = append(v.Interfaces, ni.Name)
	}
	switch {
	case v.Label == "":
		v.Label = first.Name
	case !product:
		v.Label += " (" + first.Name + ")"
	}

	var ranges []netip.Prefix
	addRange := func(p netip.Prefix) {
		if p = p.Masked(); !slices.Contains(ranges, p) {
			ranges = append(ranges, p)
		}
	}
	var notes []string
	subnets := func() {
		hostOnly := false
		for _, ni := range ifs {
			for _, a := range ni.Addrs {
				ip := a.Addr().Unmap().WithZone("")
				if !usableAddr(ip) {
					continue
				}
				if prefixBits(a) >= ip.BitLen() {
					hostOnly = true
					continue
				}
				if p, err := ip.Prefix(prefixBits(a)); err == nil {
					addRange(p)
				}
			}
		}
		if hostOnly && len(ranges) == 0 {
			notes = append(notes, hostOnlyNote)
		}
	}
	switch {
	case !incoming(v.Role) && v.Role != core.VPNRoleOverlay:
		// Egress, access, none: nobody comes in through them, nothing to allow.
	case first.Kind == core.IfYggdrasil:
		addRange(yggdrasilNet)
	case v.Role == core.VPNRoleOverlay:
		subnets()
	case first.Kind == core.IfTailscale:
		addRange(tailnetV4)
		addRange(tailnetV6)
		v.Warning = tailnetWarning
	case first.Kind == core.IfHeadscale:
		inside, outside := headscaleRanges(ifs, ts)
		for _, p := range inside {
			addRange(p)
		}
		if outside {
			notes = append(notes, headscaleNote)
		}
	case meshnetOnly(first):
		addRange(tailnetV4)
	case first.Kind == core.IfHusarnet:
		addRange(husarnetNet)
		notes = append(notes, husarnetNote)
	default:
		subnets()
	}
	switch {
	case first.Kind == core.IfWARP:
		notes = append(notes, warpNote)
	case first.Kind == core.IfFirezone && v.Role == core.VPNRoleAccess:
		notes = append(notes, firezoneNote)
	}
	if v.Role == core.VPNRoleOverlay {
		v.NeedsForce = true
		if first.Kind == core.IfYggdrasil {
			v.Warning = yggdrasilWarning
		} else {
			v.Warning = overlayWarning
		}
	}
	for _, p := range ranges {
		v.Ranges = append(v.Ranges, p.String())
	}
	v.Note = strings.Join(notes, "; ")
	v.CanAllow = len(ranges) > 0 && (incoming(v.Role) || v.Role == core.VPNRoleOverlay)
	v.Recommended = len(ranges) > 0 && (v.Role == core.VPNRoleMesh || v.Role == core.VPNRoleUnknown)
	v.Allowed = allowedOf(m, ranges, ifs)
	return v
}

// prefixBits is the prefix length of an interface address (IPv4-mapped
// prefixes converted to IPv4 lengths).
func prefixBits(a netip.Prefix) int {
	if a.Addr().Is4In6() {
		return max(0, a.Bits()-96)
	}
	return a.Bits()
}

// vpnLabel is the list label: the interface's label; Headscale names its
// control server (DESIGN §10.1) or says it guessed.
func vpnLabel(ni core.NetInterface, ts *core.TailscaleInfo) string {
	if ni.Kind != core.IfHeadscale || ts == nil {
		return ni.Label
	}
	if ts.KindGuessed {
		return "Headscale (self-hosted control server?)"
	}
	if u, err := url.Parse(ts.ControlURL); err == nil && u.Hostname() != "" {
		return "Headscale (" + u.Hostname() + ")"
	}
	return ni.Label
}

// headscaleRanges returns the Tailscale ranges that hold the node's
// addresses (tailscaled's, else the interfaces'), and whether one lies
// outside them (custom prefixes in headscale's config): no range is guessed
// for those.
func headscaleRanges(ifs []core.NetInterface, ts *core.TailscaleInfo) (inside []netip.Prefix, outside bool) {
	var ips []netip.Addr
	if ts != nil {
		ips = slices.Clone(ts.IPs)
	}
	if len(ips) == 0 {
		for _, ni := range ifs {
			for _, a := range ni.Addrs {
				if usableAddr(a.Addr()) {
					ips = append(ips, a.Addr().Unmap().WithZone(""))
				}
			}
		}
	}
	for _, ip := range ips {
		ip = ip.Unmap().WithZone("")
		switch {
		case tailnetV4.Contains(ip):
			if !slices.Contains(inside, tailnetV4) {
				inside = append(inside, tailnetV4)
			}
		case tailnetV6.Contains(ip):
			if !slices.Contains(inside, tailnetV6) {
				inside = append(inside, tailnetV6)
			}
		default:
			outside = true
		}
	}
	slices.SortFunc(inside, func(a, b netip.Prefix) int { return comparePrefix(a, b) })
	return inside, outside
}

// allowedOf is VPNInfo.Allowed: how the policy covers the ranges (or,
// without ranges, the interfaces' own networks).
func allowedOf(m *matcher, ranges []netip.Prefix, ifs []core.NetInterface) string {
	ps := ranges
	if len(ps) == 0 {
		for _, ni := range ifs {
			for _, a := range ni.Addrs {
				if usableAddr(a.Addr()) {
					ip := a.Addr().Unmap().WithZone("")
					if p, err := ip.Prefix(prefixBits(a)); err == nil {
						ps = append(ps, p)
					}
				}
			}
		}
	}
	if len(ps) == 0 {
		return allowedNo
	}
	yes, no := 0, 0
	for _, p := range ps {
		switch m.covers(p) {
		case allowedYes:
			yes++
		case allowedNo:
			no++
		}
	}
	switch {
	case yes == len(ps):
		return allowedYes
	case no == len(ps):
		return allowedNo
	}
	return allowedPartly
}

// covers reports how the policy admits the network p: "yes" when every
// address of it is allowed (mode any, or an allow or private prefix
// contains it) and no deny prefix overlaps it; "partly" when a deny prefix
// overlaps an allowed p or an allow prefix overlaps a p it does not
// contain; "no" otherwise (also when a deny prefix contains p).
func (m *matcher) covers(p netip.Prefix) string {
	if m == nil || !p.IsValid() {
		return allowedNo
	}
	p = netip.PrefixFrom(p.Addr().Unmap().WithZone(""), p.Bits()).Masked()
	denyOverlap := false
	for _, d := range m.deny {
		if prefixContains(d, p) {
			return allowedNo
		}
		denyOverlap = denyOverlap || d.Overlaps(p)
	}
	covered := m.any
	partial := false
	for _, a := range m.allow {
		if prefixContains(a, p) {
			covered = true
			break
		}
		partial = partial || a.Overlaps(p)
	}
	switch {
	case covered && !denyOverlap:
		return allowedYes
	case covered || partial:
		return allowedPartly
	}
	return allowedNo
}

// prefixContains reports whether outer contains all of inner.
func prefixContains(outer, inner netip.Prefix) bool {
	return outer.Bits() <= inner.Bits() && outer.Contains(inner.Addr())
}

// comparePrefix orders prefixes IPv4 first, then by address and length.
func comparePrefix(a, b netip.Prefix) int {
	if a.Addr().Is4() != b.Addr().Is4() {
		if a.Addr().Is4() {
			return -1
		}
		return 1
	}
	if c := a.Addr().Compare(b.Addr()); c != 0 {
		return c
	}
	return a.Bits() - b.Bits()
}

// DefaultAllowlist derives network.allow_cidrs for a new installation
// (DESIGN §10.3): the private subnets of up local (LAN/Wi-Fi) interfaces
// plus their global IPv6 prefixes unless the interface also has a public
// IPv4 address (the eth0 of a cloud VM sits on the provider's network,
// whose subnets hold other tenants), and the ranges of the mesh and unknown
// VPNs (BuildVPNs). Egress and access VPNs (nobody comes in through them),
// overlays (public), loopback and containers are never added. notes
// explain the public networks left out and VPNs without a range (host-only
// addresses, custom Headscale prefixes).
func DefaultAllowlist(ifaces []core.NetInterface, ts *core.TailscaleInfo) (allow, notes []string) {
	var ps []netip.Prefix
	add := func(p netip.Prefix) {
		p = p.Masked()
		if !slices.Contains(ps, p) {
			ps = append(ps, p)
		}
	}
	for _, in := range ifaces {
		if !in.Up || RoleOf(in) != core.VPNRoleLocal {
			continue
		}
		public := slices.ContainsFunc(in.Addrs, func(a netip.Prefix) bool { return publicV4(a.Addr().Unmap()) })
		var skipped []string
		for _, a := range in.Addrs {
			ip := a.Addr().Unmap().WithZone("")
			if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsMulticast() || ip.IsUnspecified() {
				continue
			}
			p, err := ip.Prefix(prefixBits(a))
			if err != nil {
				continue
			}
			// ULA (fc00::/7) prefixes are private; a global IPv6 prefix next
			// to a public IPv4 address is the provider's too.
			if public && (publicV4(ip) || (ip.Is6() && !ip.IsPrivate())) {
				skipped = append(skipped, p.String())
				continue
			}
			add(p)
		}
		if len(skipped) > 0 {
			name := in.Name
			if in.Label != "" {
				name += " (" + in.Label + ")"
			}
			notes = append(notes, fmt.Sprintf("%s has a public address: its networks %s were not added to the allowlist; add the networks that should connect with --allow CIDR",
				name, strings.Join(skipped, ", ")))
		}
	}
	for _, v := range BuildVPNs(ifaces, ts, core.AccessPolicy{Mode: core.AccessAllowlist}) {
		if v.Role != core.VPNRoleMesh && v.Role != core.VPNRoleUnknown {
			continue
		}
		for _, r := range v.Ranges {
			if p, err := netip.ParsePrefix(r); err == nil {
				add(p)
			}
		}
		if len(v.Ranges) == 0 && v.Note != "" {
			notes = append(notes, fmt.Sprintf("%s: %s", v.Label, v.Note))
		}
	}
	slices.SortFunc(ps, comparePrefix)
	allow = make([]string, 0, len(ps))
	for _, p := range ps {
		allow = append(allow, p.String())
	}
	return allow, notes
}

// publicV4 reports whether ip is a public IPv4 address: not RFC 1918 and not
// shared/CGNAT space (100.64.0.0/10, also the tailnet range).
func publicV4(ip netip.Addr) bool {
	return ip.Is4() && !ip.IsPrivate() && !tailnetV4.Contains(ip)
}
