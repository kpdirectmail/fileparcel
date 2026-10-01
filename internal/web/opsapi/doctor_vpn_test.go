package opsapi

import (
	"context"
	"net/netip"
	"strings"
	"testing"

	"fileparcel/internal/app"
	"fileparcel/internal/core"
	"fileparcel/internal/svc"
)

// vpnNetwork is a network service with the VPN list, the exposures and a
// Tailscale status (netinfo's optional extensions).
type vpnNetwork struct {
	*fakeNetwork
	vpns      []core.VPNInfo
	exposures []core.Exposure
	ts        *core.TailscaleInfo
}

func (n *vpnNetwork) VPNs(context.Context) []core.VPNInfo       { return n.vpns }
func (n *vpnNetwork) Exposures(context.Context) []core.Exposure { return n.exposures }
func (n *vpnNetwork) Tailscale(context.Context) (*core.TailscaleInfo, error) {
	return n.ts, nil
}

// uncoveredCerts reports names the local CA cannot sign.
type uncoveredCerts struct {
	*fakeCerts
	names []string
}

func (c *uncoveredCerts) UncoveredNames() []string { return c.names }

func vpnIfaces() []core.NetInterface {
	pp := netip.MustParsePrefix
	return []core.NetInterface{
		{Name: "eth0", Kind: core.IfLAN, Label: "LAN", Up: true, Role: core.VPNRoleLocal, Addrs: []netip.Prefix{pp("192.168.1.10/24")}},
		{Name: "tailscale0", Kind: core.IfHeadscale, Label: "Headscale", Up: true, IsVPN: true, Role: core.VPNRoleMesh,
			Addrs: []netip.Prefix{pp("100.64.0.3/32")}},
		{Name: "nordlynx", Kind: core.IfExitVPN, Label: "NordVPN", Provider: "nordvpn", Up: true, IsVPN: true, Role: core.VPNRoleEgress,
			Addrs: []netip.Prefix{pp("10.5.0.2/16")}},
		{Name: "wg0-mullvad", Kind: core.IfExitVPN, Label: "Mullvad VPN", Provider: "mullvad", Up: true, IsVPN: true,
			Role: core.VPNRoleEgress, DefaultRoute: true, Addrs: []netip.Prefix{pp("10.64.1.2/32")}},
		{Name: "cscotun0", Kind: core.IfCorpVPN, Label: "Cisco Secure Client", Up: true, IsVPN: true, Role: core.VPNRoleAccess,
			Addrs: []netip.Prefix{pp("10.200.0.9/24")}},
		{Name: "wg1", Kind: core.IfWireGuard, Label: "WireGuard", Up: true, IsVPN: true, Role: core.VPNRoleMesh,
			RoleSource: core.VPNRoleSourceOverride, Addrs: []netip.Prefix{pp("10.8.0.2/24")}},
		{Name: "ygg0", Kind: core.IfYggdrasil, Label: "Yggdrasil", Up: true, IsVPN: true, Role: core.VPNRoleOverlay,
			Addrs: []netip.Prefix{pp("201:1:2::3/7")}},
	}
}

func vpnRows(te *testEnv) map[string]DoctorCheck {
	te.t.Helper()
	out := map[string]DoctorCheck{}
	for _, c := range checkVPNs(context.Background(), te.d) {
		if c.Name == "" || c.Message == "" || c.Link == "" {
			te.t.Errorf("row without name, message or link: %+v", c)
		}
		if _, dup := out[c.ID]; dup {
			te.t.Errorf("duplicate row %s", c.ID)
		}
		out[c.ID] = c
	}
	return out
}

func TestDoctorVPNRows(t *testing.T) {
	te := newTestEnv(t, app.ModeNetwork)
	n := &vpnNetwork{fakeNetwork: te.net,
		vpns: []core.VPNInfo{
			{ID: "headscale", Label: "Headscale", Role: core.VPNRoleMesh, Interfaces: []string{"tailscale0"}},
			{ID: "nordvpn", Label: "NordVPN", Role: core.VPNRoleEgress, Interfaces: []string{"nordlynx"}},
			{ID: "mullvad", Label: "Mullvad VPN", Role: core.VPNRoleEgress, Interfaces: []string{"wg0-mullvad"}},
			{ID: "cisco", Label: "Cisco Secure Client", Role: core.VPNRoleAccess, Interfaces: []string{"cscotun0"}},
		},
		exposures: []core.Exposure{
			{ID: "tailscale.userspace", Severity: "warn", Message: "Tailscale runs without a TUN device", Hint: "Run tailscaled with a TUN device"},
			{ID: "cloudflared", Severity: "info", Message: "cloudflared runs without a local configuration"},
		},
		ts: &core.TailscaleInfo{Running: true, Kind: core.IfHeadscale, DNSName: "box.hs.example.org"}}
	te.net.ifs = vpnIfaces()
	te.net.pol = core.AccessPolicy{Mode: core.AccessAllowlist,
		Allow: []string{"192.168.1.0/24", "10.5.0.0/16", "10.64.1.2", "100.64.0.0/10", "200::/7"}}
	te.d.Network = n
	te.d.Certs = &uncoveredCerts{fakeCerts: te.certs, names: []string{"box.hs.example.org"}}

	rows := vpnRows(te)
	exit := rows[checkIDExitVPN]
	if exit.Status != CheckInfo ||
		!strings.Contains(exit.Message, "NordVPN (nordlynx), Mullvad VPN (wg0-mullvad), Cisco Secure Client (cscotun0) are outgoing VPNs") ||
		exit.Hint != "If devices do reach this server through one: fileparcel network vpn role nordlynx mesh" {
		t.Errorf("exit_vpn %+v", exit)
	}
	al := rows[checkIDExitVPNAllowed]
	if al.Status != CheckWarn || !strings.Contains(al.Message, "10.5.0.0/16 belongs to NordVPN (nordlynx)") ||
		!strings.Contains(al.Message, "10.64.1.2 belongs to Mullvad VPN (wg0-mullvad)") ||
		al.Hint != "Remove it: fileparcel network allow remove 10.5.0.0/16 ; fileparcel network allow remove 10.64.1.2" {
		t.Errorf("exit_vpn_allowed %+v", al)
	}
	if ov := rows[checkIDOverlay]; ov.Status != CheckWarn || !strings.Contains(ov.Message, "(200::/7)") ||
		!strings.Contains(ov.Hint, "fileparcel network allow remove 200::/7") {
		t.Errorf("overlay %+v", ov)
	}
	if us := rows["network.exposure.tailscale.userspace"]; us.Status != CheckWarn || us.Name != "Tailscale without a TUN device" || us.Hint == "" {
		t.Errorf("userspace %+v", us)
	}
	if cf := rows["network.exposure.cloudflared"]; cf.Status != CheckInfo || cf.Name != "Cloudflare Tunnel" {
		t.Errorf("cloudflared %+v", cf)
	}
	if nu := rows[checkIDNameUncovered]; nu.Status != CheckWarn || !strings.Contains(nu.Message, "box.hs.example.org") ||
		!strings.Contains(nu.Hint, "fileparcel ca regenerate") || nu.Link != "/admin/certificates" {
		t.Errorf("name_uncovered %+v", nu)
	}
	if len(rows) != 6 {
		t.Errorf("rows %v", rows)
	}

	// Access mode "any" while an overlay is up; nothing else to report.
	te.net.pol = core.AccessPolicy{Mode: core.AccessAny}
	n.vpns, n.exposures = nil, nil
	te.d.Certs = &uncoveredCerts{fakeCerts: te.certs}
	rows = vpnRows(te)
	if ov := rows[checkIDOverlay]; len(rows) != 1 || !strings.Contains(ov.Message, "on ygg0") || ov.Hint != "Use an allow list: fileparcel network mode allowlist" {
		t.Errorf("any + overlay %v", rows)
	}

	// A plain LAN machine: no VPN rows; a network service without the
	// extensions and certificates without uncovered names are fine.
	te.net.ifs = vpnIfaces()[:1]
	te.net.pol = core.AccessPolicy{Mode: core.AccessAllowlist, Allow: []string{"192.168.1.0/24"}}
	te.d.Network = te.net
	te.d.Certs = te.certs
	if rows := vpnRows(te); len(rows) != 0 {
		t.Errorf("plain LAN %v", rows)
	}
	te.d.Network = nil
	if rows := checkVPNs(context.Background(), te.d); rows != nil {
		t.Errorf("no network %v", rows)
	}
}

// The firewall hints open the VPNs devices come in through by interface;
// outgoing, corporate and overlay VPNs get no rule, whatever their kind.
func TestDoctorFirewallHintsByRole(t *testing.T) {
	te := newTestEnv(t, app.ModeNetwork)
	te.net.ifs = vpnIfaces()
	te.net.pol = core.AccessPolicy{Mode: core.AccessAllowlist, Allow: []string{"192.168.1.0/24", "100.64.0.0/10", "10.8.0.0/24"}}
	detectFirewalls = func(context.Context) []svc.Firewall { return []svc.Firewall{{Kind: svc.FirewallUFW, Active: true}} }
	ufw := te.doctor("").find("firewall.ufw")
	if ufw == nil {
		t.Fatal("no firewall row")
	}
	for _, want := range []string{"in on tailscale0", "in on wg1", "from 192.168.1.0/24"} {
		if !strings.Contains(ufw.Hint, want) {
			t.Errorf("hint lacks %q: %s", want, ufw.Hint)
		}
	}
	for _, bad := range []string{"nordlynx", "mullvad", "cscotun0", "ygg0", "10.5.", "10.200.", "100.64.0.0/10", "10.8.0.0/24"} {
		if strings.Contains(ufw.Hint, bad) {
			t.Errorf("hint mentions %q: %s", bad, ufw.Hint)
		}
	}
}

func TestIfaceRoleFallback(t *testing.T) {
	for kind, want := range map[string]string{core.IfLAN: "local", core.IfWiFi: "local", core.IfLoopback: "none",
		core.IfContainer: "none", core.IfWireGuard: "unknown", core.IfHeadscale: "unknown"} {
		if got := ifaceRole(core.NetInterface{Kind: kind}); got != want {
			t.Errorf("%s: %s", kind, got)
		}
	}
	if ifaceRole(core.NetInterface{Kind: core.IfLAN, Role: core.VPNRoleEgress}) != core.VPNRoleEgress {
		t.Fatal("role kept")
	}
	for s, want := range map[string]string{"10.5.0.0/16": "10.5.0.0/16", "10.5.3.4/16": "10.5.0.0/16", "10.64.1.2": "10.64.1.2/32",
		"::ffff:10.0.0.0/104": "10.0.0.0/8", "fd7a:115c:a1e0::/48": "fd7a:115c:a1e0::/48"} {
		if p, ok := parsePolicyEntry(s); !ok || p.String() != want {
			t.Errorf("%s: %v %v", s, p, ok)
		}
	}
	if _, ok := parsePolicyEntry("nope"); ok {
		t.Fatal("garbage parsed")
	}
}

// network.overlay warns about allow entries that open a wide part of the
// public Yggdrasil network, not about the single addresses (or a node's own
// /64) its hint recommends.
func TestOverlayCheckSingleAddresses(t *testing.T) {
	for _, c := range []struct {
		entry string
		warn  bool
	}{
		{"200::/7", true},
		{"200::/8", true},
		{"201:5f2b::/32", true},
		{"::/0", true},
		{"201:5f2b:1c3e:9d4a:77aa:1b2c:3d4e:5f60", false},
		{"201:5f2b:1c3e:9d4a:77aa:1b2c:3d4e:5f60/128", false},
		{"300:1234:5678:9abc::/64", false},
		{"fd00::/8", false},
	} {
		pol := core.AccessPolicy{Mode: core.AccessAllowlist, Allow: []string{"192.168.1.0/24", c.entry}}
		got := overlayCheck(nil, pol)
		if (got != nil) != c.warn {
			t.Errorf("%s: warn %v, want %v (%+v)", c.entry, got != nil, c.warn, got)
		}
		if got != nil && !strings.Contains(got.Message, c.entry) {
			t.Errorf("%s: message %q", c.entry, got.Message)
		}
	}
}
