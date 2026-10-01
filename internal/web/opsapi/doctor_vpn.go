package opsapi

import (
	"context"
	"fmt"
	"net/netip"
	"slices"
	"strings"

	"fileparcel/internal/app"
	"fileparcel/internal/core"
)

// Doctor rows of the VPN detection (DESIGN §10.1, §10.3): outgoing VPNs,
// allow-list entries that belong to one, public overlays, the ways around
// the access policy the network service finds on this machine, and a
// MagicDNS name the local certificate cannot cover.
const (
	checkIDExitVPN        = "network.exit_vpn"
	checkIDExitVPNAllowed = "network.exit_vpn_allowed"
	checkIDOverlay        = "network.overlay"
	checkIDExposurePrefix = "network.exposure." // + core.Exposure.ID
	checkIDNameUncovered  = "tailscale.name_uncovered"
)

// Optional extensions of the network service (netinfo) and the certificate
// service (certs) the VPN rows read.
type (
	doctorVPNLister interface {
		VPNs(ctx context.Context) []core.VPNInfo
	}
	doctorExposureLister interface {
		Exposures(ctx context.Context) []core.Exposure
	}
	doctorUncoveredNamer interface{ UncoveredNames() []string }
)

// yggdrasilNet is the public Yggdrasil overlay's address range.
var yggdrasilNet = netip.MustParsePrefix("200::/7")

// exposureNames titles the exposure rows.
var exposureNames = map[string]string{
	"tailscale.userspace":  "Tailscale without a TUN device",
	"tailscale.shields_up": "Tailscale shields-up",
	"cloudflared":          "Cloudflare Tunnel",
}

// ifaceRole is an interface's role (NetInterface.Role); a value built
// without one counts by its kind: LAN and Wi-Fi local, loopback and
// containers none, every other kind a VPN of unknown role.
func ifaceRole(ni core.NetInterface) string {
	if ni.Role != "" {
		return ni.Role
	}
	switch ni.Kind {
	case core.IfLAN, core.IfWiFi:
		return core.VPNRoleLocal
	case core.IfLoopback, core.IfContainer:
		return core.VPNRoleNone
	}
	return core.VPNRoleUnknown
}

// outgoingRole reports the roles nobody comes in through.
func outgoingRole(r string) bool { return r == core.VPNRoleEgress || r == core.VPNRoleAccess }

// checkVPNs reports the VPN rows (no row when there is nothing to say).
func checkVPNs(ctx context.Context, d *app.Deps) []DoctorCheck {
	if d.Network == nil {
		return nil
	}
	var out []DoctorCheck
	ifs, err := d.Network.Interfaces(ctx)
	if err != nil {
		ifs = nil
	}
	pol := d.Network.Policy()
	if v, ok := d.Network.(doctorVPNLister); ok {
		if c := exitVPNCheck(v.VPNs(ctx)); c != nil {
			out = append(out, *c)
		}
	}
	if c := exitVPNAllowedCheck(ifs, pol); c != nil {
		out = append(out, *c)
	}
	if c := overlayCheck(ifs, pol); c != nil {
		out = append(out, *c)
	}
	if e, ok := d.Network.(doctorExposureLister); ok {
		for _, x := range e.Exposures(ctx) {
			out = append(out, exposureCheck(x))
		}
	}
	if c := nameUncoveredCheck(ctx, d); c != nil {
		out = append(out, *c)
	}
	return out
}

// exitVPNCheck lists the outgoing VPNs (exit VPNs, corporate and
// zero-trust clients): informational — they are simply not offered.
func exitVPNCheck(vpns []core.VPNInfo) *DoctorCheck {
	var names, ifaces []string
	for _, v := range vpns {
		if !outgoingRole(v.Role) {
			continue
		}
		names = append(names, fmt.Sprintf("%s (%s)", v.Label, strings.Join(v.Interfaces, ", ")))
		ifaces = append(ifaces, v.Interfaces...)
	}
	if len(names) == 0 {
		return nil
	}
	msg := names[0] + " is an outgoing VPN; it does not let other devices in"
	if len(names) > 1 {
		msg = strings.Join(names, ", ") + " are outgoing VPNs; they do not let other devices in"
	}
	return &DoctorCheck{ID: checkIDExitVPN, Name: "Outgoing VPNs", Status: CheckInfo, Link: "/admin/network",
		Message: msg + ", so their addresses are not offered, allowed or put into the certificate.",
		Hint:    "If devices do reach this server through one: fileparcel network vpn role " + ifaces[0] + " mesh"}
}

// exitVPNAllowedCheck warns about allow-list entries that are exactly the
// network of an outgoing VPN interface (a v3 install allowed every VPN
// subnet; nobody connects from there).
func exitVPNAllowedCheck(ifs []core.NetInterface, pol core.AccessPolicy) *DoctorCheck {
	allowed := map[netip.Prefix]string{}
	for _, a := range pol.Allow {
		if p, ok := parsePolicyEntry(a); ok {
			allowed[p] = a
		}
	}
	var msgs, cmds []string
	for _, ni := range ifs {
		if !ni.Up || !outgoingRole(ifaceRole(ni)) {
			continue
		}
		for _, a := range ni.Addrs {
			p := a.Masked()
			entry, ok := allowed[netip.PrefixFrom(p.Addr().Unmap(), bitsUnmapped(p))]
			if !ok || slices.Contains(cmds, "fileparcel network allow remove "+entry) {
				continue
			}
			label := ni.Label
			if label == "" {
				label = ni.Name
			}
			msgs = append(msgs, fmt.Sprintf("%s belongs to %s (%s)", entry, label, ni.Name))
			cmds = append(cmds, "fileparcel network allow remove "+entry)
		}
	}
	if len(msgs) == 0 {
		return nil
	}
	return &DoctorCheck{ID: checkIDExitVPNAllowed, Name: "Allowed network of an outgoing VPN", Status: CheckWarn,
		Link:    "/admin/network",
		Message: strings.Join(msgs, "; ") + ": an outgoing VPN, nobody connects from there.",
		Hint:    "Remove it: " + strings.Join(cmds, " ; ")}
}

// overlayCheck warns when the access policy admits a public overlay
// network: an allow entry that opens a wide part of Yggdrasil's 200::/7
// (wideOverlayEntry), or mode "any" while an overlay interface is up.
func overlayCheck(ifs []core.NetInterface, pol core.AccessPolicy) *DoctorCheck {
	var entries []string
	for _, a := range pol.Allow {
		if p, ok := parsePolicyEntry(a); ok && wideOverlayEntry(p) {
			entries = append(entries, a)
		}
	}
	var overlay []string
	for _, ni := range ifs {
		if ni.Up && ifaceRole(ni) == core.VPNRoleOverlay {
			overlay = append(overlay, ni.Name)
		}
	}
	c := &DoctorCheck{ID: checkIDOverlay, Name: "Public overlay network", Status: CheckWarn, Link: "/admin/network"}
	switch {
	case len(entries) > 0:
		c.Message = "The allow list admits the public Yggdrasil network (" + strings.Join(entries, ", ") +
			"): anyone on it can reach the sign-in page."
		c.Hint = "Allow single Yggdrasil addresses instead, or remove the entry: fileparcel network allow remove " + entries[0]
	case pol.Mode == core.AccessAny && len(overlay) > 0:
		c.Message = "Access mode \"any\" admits the public overlay network on " + strings.Join(overlay, ", ") +
			": anyone on it can reach the sign-in page."
		c.Hint = "Use an allow list: fileparcel network mode allowlist"
	default:
		return nil
	}
	return c
}

// wideOverlayEntry reports whether the allow entry p admits a wide part of
// the public Yggdrasil network: it overlaps 200::/7 and is shorter than a
// /64 (the whole range, 200::/8, …). A single address (/128) of one's own
// device, or a node's advertised /64 subnet (300:…::/64), is what the hint,
// the Network page and the manual recommend, so it does not warn.
func wideOverlayEntry(p netip.Prefix) bool {
	return p.Overlaps(yggdrasilNet) && p.Bits() < 64
}

// exposureCheck turns one exposure of the network service into a row.
func exposureCheck(x core.Exposure) DoctorCheck {
	name := exposureNames[x.ID]
	if name == "" {
		name = "Access policy bypass"
	}
	status := CheckInfo
	switch x.Severity {
	case "fail":
		status = CheckFail
	case "warn":
		status = CheckWarn
	}
	return DoctorCheck{ID: checkIDExposurePrefix + x.ID, Name: name, Status: status, Message: x.Message, Hint: x.Hint,
		Link: "/admin/network"}
}

// nameUncoveredCheck warns when the MagicDNS name (a Headscale name joined
// after the local CA was created) is left out of the local certificate.
func nameUncoveredCheck(ctx context.Context, d *app.Deps) *DoctorCheck {
	u, ok := d.Certs.(doctorUncoveredNamer)
	if !ok {
		return nil
	}
	ts, err := d.Network.Tailscale(ctx)
	if err != nil || ts == nil || ts.DNSName == "" {
		return nil
	}
	name := strings.TrimSuffix(strings.ToLower(ts.DNSName), ".")
	if !slices.Contains(u.UncoveredNames(), name) {
		return nil
	}
	return &DoctorCheck{ID: checkIDNameUncovered, Name: "MagicDNS name not in the certificate", Status: CheckWarn,
		Link: "/admin/certificates",
		Message: "The local CA was created before " + name + " existed, so the local certificate does not cover it " +
			"(browsers warn when it is used).",
		Hint: "Regenerate the CA (devices must trust the new one): fileparcel ca regenerate — or reach the server by IP address."}
}

// parsePolicyEntry parses an access-policy entry (a CIDR or an address)
// into a masked, unmapped prefix.
func parsePolicyEntry(s string) (netip.Prefix, bool) {
	s = strings.TrimSpace(s)
	if p, err := netip.ParsePrefix(s); err == nil {
		p = p.Masked()
		return netip.PrefixFrom(p.Addr().Unmap(), bitsUnmapped(p)), true
	}
	if a, err := netip.ParseAddr(s); err == nil {
		a = a.Unmap().WithZone("")
		return netip.PrefixFrom(a, a.BitLen()), true
	}
	return netip.Prefix{}, false
}

// bitsUnmapped is the prefix length of p with an IPv4-mapped address
// converted to IPv4 (::ffff:10.0.0.0/104 → 8).
func bitsUnmapped(p netip.Prefix) int {
	if p.Addr().Is4In6() {
		return max(0, p.Bits()-96)
	}
	return p.Bits()
}
