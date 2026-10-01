package core

// VPN detection (DESIGN §10.1): the interface kinds added in v4, the
// interface roles (NetInterface.Role), the VPN list (NetworkOverview.VPNs)
// and the exposure findings (NetworkOverview.Exposures). The v3 kinds are in
// models.go (IfLoopback … IfLAN).

// Interface kinds added in v4 (NetInterface.Kind).
const (
	IfYggdrasil = "yggdrasil"
	IfHusarnet  = "husarnet"
	IfExitVPN   = "exitvpn" // NordVPN, Mullvad, Proton VPN
	IfWARP      = "warp"    // Cloudflare WARP
	IfFirezone  = "firezone"
	IfTwingate  = "twingate"
	IfCorpVPN   = "corpvpn" // Cisco Secure Client, GlobalProtect
	IfNetmaker  = "netmaker"
	IfInnernet  = "innernet"
	IfTinc      = "tinc"
	IfOpenVPN   = "openvpn"
	IfIPsec     = "ipsec"
	IfSoftEther = "softether"
)

// Interface roles (NetInterface.Role, VPNInfo.Role, network.iface_roles).
const (
	// VPNRoleMesh: devices of that private network can connect to this machine.
	VPNRoleMesh = "mesh"
	// VPNRoleUnknown: a generic tunnel without a product signal (treated like mesh).
	VPNRoleUnknown = "unknown"
	// VPNRoleAccess: a zero-trust or corporate client; nobody comes in through it.
	VPNRoleAccess = "access"
	// VPNRoleEgress: an exit/privacy VPN or internet uplink.
	VPNRoleEgress = "egress"
	// VPNRoleOverlay: a public overlay anyone may connect through (Yggdrasil).
	VPNRoleOverlay = "overlay"
	// VPNRoleLocal: LAN / Wi-Fi.
	VPNRoleLocal = "local"
	// VPNRoleNone: loopback, container, bridge-enslaved TAP.
	VPNRoleNone = "none"
)

// Where an interface role comes from (NetInterface.RoleSource, VPNInfo.RoleSource).
const (
	VPNRoleSourceAuto     = "auto"     // classification
	VPNRoleSourceOverride = "override" // network.iface_roles
)

// VPNInfo is one detected VPN (NetworkOverview.VPNs): the basis of
// "fileparcel network vpn …", the policy editor's suggestions and the
// install-time allowlist.
type VPNInfo struct {
	ID          string   `json:"id"` // "tailscale"/"headscale"/"zerotier"/"netbird"/… for single-product VPNs; the interface name otherwise ("wg0")
	Kind        string   `json:"kind"`
	Label       string   `json:"label"` // "Tailscale", "NordVPN Meshnet", "WireGuard (wg0)"
	Provider    string   `json:"provider,omitempty"`
	Role        string   `json:"role"`
	RoleSource  string   `json:"role_source"`
	Interfaces  []string `json:"interfaces"`
	Ranges      []string `json:"ranges"`      // CIDRs that "allow" adds (empty for egress/access, and when unknown)
	Allowed     string   `json:"allowed"`     // yes|partly|no under the current policy
	CanAllow    bool     `json:"can_allow"`   // false for egress/access/none or empty Ranges
	NeedsForce  bool     `json:"needs_force"` // overlay: needs an explicit confirmation
	Recommended bool     `json:"recommended"` // part of the install-time allow list
	Note        string   `json:"note,omitempty"`
	Warning     string   `json:"warning,omitempty"`
}

// Exposure is a way the access policy may be bypassed (doctor, Network page).
type Exposure struct {
	ID       string `json:"id"`       // "tailscale.userspace" | "tailscale.bypass" | "tailscale.shields_up" | "proxy.local_unconfigured" | "cloudflared"
	Severity string `json:"severity"` // info|warn|fail
	Message  string `json:"message"`
	Hint     string `json:"hint,omitempty"`
}
