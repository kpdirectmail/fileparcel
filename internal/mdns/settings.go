package mdns

import (
	"fmt"
	"regexp"
	"strings"

	"fileparcel/internal/settings"
)

// Setting keys owned by mdns (DESIGN §11.2, section "mdns").
const (
	KeyMode       = "mdns.mode"
	KeyName       = "mdns.name"
	KeyInterfaces = "mdns.interfaces"
	KeyZeroTier   = "mdns.zerotier"
)

func init() {
	settings.Register(settings.Def{Key: KeyMode, Section: "mdns", Order: 10, Type: settings.TypeEnum,
		Default: ModeAuto, Enum: []string{ModeAuto, BackendAvahi, BackendDNSSD, BackendBuiltin, ModeOff},
		Label: "mDNS publishing",
		Description: "How <name>.local and the _https._tcp service are announced on the local network. auto: Avahi " +
			"(Linux, via D-Bus) when it runs, dns-sd on macOS, else the builtin responder; off disables publishing."})
	settings.Register(settings.Def{Key: KeyName, Section: "mdns", Order: 20, Type: settings.TypeString, Default: "",
		Validate: validName,
		Label:    "mDNS name",
		Description: "Label published as <name>.local. Empty uses the server name. Lowercase letters, digits and '-'. " +
			"On a name collision \"-2\", \"-3\", … is appended automatically. While the passkey domain " +
			"(auth.webauthn_rp_id) is empty, <name>.local is also the domain passkeys are bound to: changing it makes " +
			"existing passkeys unusable."})
	settings.Register(settings.Def{Key: KeyInterfaces, Section: "mdns", Order: 30, Type: settings.TypeString, Default: "lan",
		Validate: validInterfaces,
		Label:    "mDNS interfaces",
		Description: "\"lan\" publishes on every local interface (LAN and Wi-Fi, never an exit VPN or an unknown tunnel; " +
			"network.iface_roles can set an interface to local); or list interface names separated by commas " +
			"(e.g. \"eth0, wlan0\"), including \"lan\" to add them to the LAN set (e.g. \"lan, br0\"). " +
			"mDNS does not cross routed VPNs (Tailscale, WireGuard): use MagicDNS or the IP there."})
	settings.Register(settings.Def{Key: KeyZeroTier, Section: "mdns", Order: 40, Type: settings.TypeBool, Default: false,
		Label:       "Publish on ZeroTier",
		Description: "Also publish on ZeroTier interfaces (a layer-2 VPN where multicast works) when mDNS interfaces includes \"lan\"."})
}

func validName(v any) error {
	s, _ := v.(string)
	if s != "" && !validLabel(s) {
		return fmt.Errorf("must be empty or a DNS label: 1-63 characters a-z, 0-9 and '-', not starting or ending with '-'")
	}
	return nil
}

var ifNameRe = regexp.MustCompile(`^[A-Za-z0-9_.:@-]{1,15}$`)

func validInterfaces(v any) error {
	s, _ := v.(string)
	s = strings.TrimSpace(s)
	if s == "" || strings.EqualFold(s, "lan") {
		return nil
	}
	names := strings.FieldsFunc(s, func(r rune) bool { return r == ',' || r == ' ' || r == '\t' })
	if len(names) == 0 || len(names) > 64 {
		return fmt.Errorf("list 1 to 64 interface names, or \"lan\"")
	}
	for _, n := range names {
		if !ifNameRe.MatchString(n) {
			return fmt.Errorf("%q is not a valid interface name", n)
		}
	}
	return nil
}
