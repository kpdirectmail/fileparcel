package netinfo

import (
	"fmt"
	"net/netip"
	"slices"
	"strings"

	"fileparcel/internal/core"
)

// Interface roles (DESIGN §10.1): what an interface is good for. Only up
// interfaces with role local, mesh or unknown are offered — their
// addresses become access URLs and certificate SANs and count for the
// network.changed fingerprint; mDNS announces on local ones only.

// maxIfaceRoles bounds network.iface_roles.
const maxIfaceRoles = 64

// roleNames are the valid roles of network.iface_roles, in the order the
// documentation lists them.
var roleNames = []string{core.VPNRoleMesh, core.VPNRoleUnknown, core.VPNRoleAccess, core.VPNRoleEgress,
	core.VPNRoleOverlay, core.VPNRoleLocal, core.VPNRoleNone}

// RoleOf returns the role of ni: its Role, or for a value built without one
// (an older server, a test fake) the automatic role of its kind (generic
// tunnels count as unknown, whatever their default route).
func RoleOf(ni core.NetInterface) string {
	if ni.Role != "" {
		return ni.Role
	}
	switch ni.Kind {
	case core.IfLoopback, core.IfContainer:
		return core.VPNRoleNone
	case core.IfLAN, core.IfWiFi:
		return core.VPNRoleLocal
	case core.IfYggdrasil:
		return core.VPNRoleOverlay
	case core.IfExitVPN, core.IfWARP:
		return core.VPNRoleEgress
	case core.IfTwingate, core.IfCorpVPN:
		return core.VPNRoleAccess
	case core.IfTailscale, core.IfHeadscale, core.IfHusarnet, core.IfNetmaker, core.IfInnernet, core.IfZeroTier,
		core.IfNetBird, core.IfNebula:
		return core.VPNRoleMesh
	}
	if ni.IsVPN || vpnKinds[ni.Kind] {
		return core.VPNRoleUnknown
	}
	return core.VPNRoleLocal
}

// incoming reports whether devices can reach this machine through an
// interface of role r (the roles that are offered).
func incoming(r string) bool {
	return r == core.VPNRoleLocal || r == core.VPNRoleMesh || r == core.VPNRoleUnknown
}

// offered reports whether an interface's addresses are offered in access
// URLs and certificate SANs: up, and a role devices come in through.
func offered(ni core.NetInterface) bool {
	return ni.Up && incoming(RoleOf(ni))
}

// offeredAddr reports whether address a of the offered interface ni is
// offered: a usable address (usableAddr); on NordVPN's nordlynx in the mesh
// role only its Meshnet addresses (100.64.0.0/10) — the others are the exit
// tunnel's, which nobody can reach.
func offeredAddr(ni core.NetInterface, a netip.Addr) bool {
	a = a.Unmap().WithZone("")
	if !usableAddr(a) {
		return false
	}
	if meshnetOnly(ni) {
		return tailnetV4.Contains(a)
	}
	return true
}

// meshnetOnly reports whether only the Meshnet addresses of ni count: a
// NordVPN interface in the mesh role that has one.
func meshnetOnly(ni core.NetInterface) bool {
	if ni.Kind != core.IfExitVPN || ni.Provider != "nordvpn" || RoleOf(ni) != core.VPNRoleMesh {
		return false
	}
	return slices.ContainsFunc(ni.Addrs, func(p netip.Prefix) bool { return tailnetV4.Contains(p.Addr().Unmap()) })
}

// parseIfaceRoles parses network.iface_roles ("<interface>=<role>" entries;
// later entries for the same interface win). Invalid entries are an error.
func parseIfaceRoles(entries []string) (map[string]string, error) {
	if len(entries) > maxIfaceRoles {
		return nil, fmt.Errorf("at most %d entries", maxIfaceRoles)
	}
	out := make(map[string]string, len(entries))
	for _, e := range entries {
		e = strings.TrimSpace(e)
		if e == "" {
			continue
		}
		name, role, ok := strings.Cut(e, "=")
		name, role = strings.TrimSpace(name), strings.ToLower(strings.TrimSpace(role))
		if !ok || name == "" {
			return nil, fmt.Errorf("%q: use <interface>=<role>, e.g. wg0=mesh", e)
		}
		if !validIfName(name) {
			return nil, fmt.Errorf("%q is not a valid interface name", name)
		}
		if !slices.Contains(roleNames, role) {
			return nil, fmt.Errorf("%q: the role must be one of %s", e, strings.Join(roleNames, ", "))
		}
		out[name] = role
	}
	return out, nil
}

// validIfName reports whether name can be an interface name: safe in a
// sysfs path, at most 64 bytes, no spaces, "=" or control characters.
func validIfName(name string) bool {
	if !safeIfName(name) || len(name) > 64 {
		return false
	}
	for _, r := range name {
		if r <= ' ' || r == '=' || r == 0x7f {
			return false
		}
	}
	return true
}

// validIfaceRoles is the Validate of network.iface_roles.
func validIfaceRoles(v any) error {
	l, _ := v.([]string)
	_, err := parseIfaceRoles(l)
	return err
}

// applyRoleOverrides sets the overridden roles (network.iface_roles) on
// ifaces in place: Kind and Label stay, RoleSource becomes "override".
func applyRoleOverrides(ifaces []core.NetInterface, roles map[string]string) {
	for i := range ifaces {
		if r, ok := roles[ifaces[i].Name]; ok {
			ifaces[i].Role = r
			ifaces[i].RoleSource = core.VPNRoleSourceOverride
		}
	}
}
