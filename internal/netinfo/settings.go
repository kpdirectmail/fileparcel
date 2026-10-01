package netinfo

import (
	"fmt"
	"strings"

	"fileparcel/internal/core"
	"fileparcel/internal/settings"
)

// Setting keys owned by netinfo (DESIGN §11.2, section "network").
const (
	KeyAccessMode = "network.access_mode"
	KeyAllowCIDRs = "network.allow_cidrs"
	KeyDenyCIDRs  = "network.deny_cidrs"
	KeyStrictHost = "network.strict_host"
	KeyExtraHosts = "network.extra_hosts"
	KeyIfaceRoles = "network.iface_roles"
)

// policyKeys are the settings that make up the access policy.
var policyKeys = []string{KeyAccessMode, KeyAllowCIDRs, KeyDenyCIDRs}

func init() {
	settings.Register(settings.Def{Key: KeyAccessMode, Section: "network", Order: 10, Type: settings.TypeEnum,
		Default: core.AccessAllowlist, Enum: []string{core.AccessPrivate, core.AccessAllowlist, core.AccessAny},
		Label: "Access mode",
		Description: "Which client addresses may connect. private: loopback and private/VPN ranges (10/8, 172.16/12, " +
			"192.168/16, 169.254/16, 100.64/10, fc00::/7, fe80::/10) plus the allow list; allowlist: loopback and the " +
			"allow list only; any: every address (public exposure). The deny list always wins; loopback is always allowed."})
	settings.Register(settings.Def{Key: KeyAllowCIDRs, Section: "network", Order: 20, Type: settings.TypeCIDRs,
		Default: []string{}, Validate: validPolicyList,
		Label:       "Allowed networks",
		Description: "CIDRs or single IP addresses allowed to connect (e.g. 192.168.1.0/24, 100.64.0.0/10)."})
	settings.Register(settings.Def{Key: KeyDenyCIDRs, Section: "network", Order: 30, Type: settings.TypeCIDRs,
		Default: []string{}, Validate: validPolicyList,
		Label:       "Denied networks",
		Description: "CIDRs or single IP addresses that are always refused, whatever the access mode."})
	settings.Register(settings.Def{Key: KeyStrictHost, Section: "network", Order: 40, Type: settings.TypeBool,
		Default: false,
		Label:   "Strict Host check",
		Description: "Only answer requests whose Host header names this server (its addresses, .local and MagicDNS " +
			"names, the public URL and the extra host names). Defeats DNS-rebinding attacks from web pages."})
	settings.Register(settings.Def{Key: KeyExtraHosts, Section: "network", Order: 50, Type: settings.TypeStrings,
		Default: []string{}, Validate: validHostList,
		Label: "Extra host names",
		Description: "Additional DNS names this server answers to (e.g. a name in your own DNS). They are added to " +
			"the local certificate and the access URLs. \"*.example.org\" matches one label."})
	settings.Register(settings.Def{Key: KeyIfaceRoles, Section: "network", Order: 60, Type: settings.TypeStrings,
		Default: []string{}, Validate: validIfaceRoles,
		Label: "Interface roles",
		Description: "Corrects how FileParcel treats a network interface, one \"<interface>=<role>\" entry each " +
			"(e.g. wg0=mesh). mesh: devices of that network can reach this server (its addresses are offered); " +
			"unknown: the same, for a tunnel of unknown kind; local: a LAN, also announced over mDNS; egress: an " +
			"outgoing VPN or internet uplink and access: a corporate or zero-trust client (not offered); overlay: a " +
			"public overlay network (not offered); none: ignored. Later entries win; at most 64."})
}

// validPolicyList checks the entry count and IPv4-mapped prefix rules of a
// CIDR list (the settings type already checks the syntax).
func validPolicyList(v any) error {
	l, _ := v.([]string)
	_, _, err := parseList("value", l)
	if ce := core.AsError(err); ce != nil {
		return fmt.Errorf("%s", ce.Message)
	}
	return err
}

// validHostList checks network.extra_hosts entries.
func validHostList(v any) error {
	l, _ := v.([]string)
	if len(l) > 256 {
		return fmt.Errorf("at most 256 names")
	}
	for _, h := range l {
		h = strings.TrimSuffix(strings.ToLower(h), ".")
		if !validDNSName(h, true) {
			return fmt.Errorf("%q is not a valid host name", h)
		}
	}
	return nil
}
