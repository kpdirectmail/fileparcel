package svc

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"net/netip"
	"os"
	"slices"
	"strconv"
	"strings"
)

// Firewall hints (DESIGN §14.2 step 6, §18.6): FileParcel never changes the
// firewall itself (that needs root and is the admin's call); it detects the
// active firewall and prints the exact commands that open the ports for the
// allowed networks.

// Firewall kinds.
const (
	FirewallUFW       = "ufw"
	FirewallFirewalld = "firewalld"
	FirewallNftables  = "nftables"
	FirewallMacOS     = "socketfilterfw"
)

// SocketFilterFW is the macOS application firewall tool.
const SocketFilterFW = "/usr/libexec/ApplicationFirewall/socketfilterfw"

// Firewall is one detected firewall.
type Firewall struct {
	Kind   string `json:"kind"`
	Active bool   `json:"active"`
	Detail string `json:"detail,omitempty"`
}

// readFile is os.ReadFile (tests replace it).
var readFile = os.ReadFile

// DetectFirewalls reports the firewalls found on h (active or not).
// Detection works without root: ufw via /etc/ufw/ufw.conf, firewalld via
// `firewall-cmd --state`, nftables via `systemctl is-active nftables`, macOS
// via socketfilterfw --getglobalstate.
func DetectFirewalls(ctx context.Context, h *Host) []Firewall {
	var out []Firewall
	switch h.GOOS {
	case "linux":
		if b, err := readFile("/etc/ufw/ufw.conf"); err == nil {
			out = append(out, Firewall{Kind: FirewallUFW, Active: ufwEnabled(b), Detail: "/etc/ufw/ufw.conf"})
		}
		if h.Has("firewall-cmd") {
			res, err := h.run(ctx, nil, "firewall-cmd", "--state")
			out = append(out, Firewall{Kind: FirewallFirewalld,
				Active: err == nil && strings.TrimSpace(string(res.Stdout)) == "running"})
		}
		if h.Has("systemctl") && hasNft(h) {
			res, err := h.run(ctx, nil, "systemctl", "is-active", "nftables")
			active := err == nil && strings.TrimSpace(string(res.Stdout)) == "active"
			fw := Firewall{Kind: FirewallNftables, Active: active}
			// nftables.service is commonly enabled with the distribution's
			// accept-everything skeleton while ufw or firewalld does the real
			// filtering. Reporting it then sends the operator after a second
			// set of rules they do not need, so only call it active when its
			// ruleset actually blocks something.
			if active && !nftFilters() {
				fw.Active = false
				fw.Detail = "enabled but no blocking rules in /etc/nftables.conf"
			}
			out = append(out, fw)
		}
	case "darwin":
		if _, err := os.Stat(SocketFilterFW); err == nil || h.Has(SocketFilterFW) {
			res, err := h.run(ctx, nil, SocketFilterFW, "--getglobalstate")
			s := strings.ToLower(string(res.Stdout))
			out = append(out, Firewall{Kind: FirewallMacOS,
				Active: err == nil && (strings.Contains(s, "enabled") || strings.Contains(s, "state = 1"))})
		}
	}
	return out
}

// nftSbin are where distributions install nft: /usr/sbin is not on the
// default PATH of normal users on Debian, which run the user installer and
// doctor.
var nftSbin = []string{"/usr/sbin/nft", "/sbin/nft"}

// hasNft reports whether nftables is installed (nft on PATH or in sbin). The
// check itself never runs nft; this only keeps hosts without nftables from
// getting an (inactive) nftables entry and its removal hints.
func hasNft(h *Host) bool {
	if h.Has("nft") {
		return true
	}
	for _, p := range nftSbin {
		if _, err := statPath(p); err == nil {
			return true
		}
	}
	return false
}

// nftFilters reports whether the nftables configuration contains anything that
// could block an inbound connection: a chain whose policy is drop or reject, an
// explicit drop/reject rule (also written "drop;" or inside a verdict map), or
// an include directive (the included rules are not inspected, so they may
// filter). The live ruleset needs root to read, so this inspects
// /etc/nftables.conf, which the service loads at boot. When the file cannot be
// read the answer is "yes", because an unknown ruleset may filter.
func nftFilters() bool {
	b, err := readFile("/etc/nftables.conf")
	if err != nil {
		return true
	}
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if i := strings.Index(line, "#"); i >= 0 {
			line = strings.TrimSpace(line[:i])
		}
		if strings.Contains(line, "policy drop") || strings.Contains(line, "policy reject") {
			return true
		}
		fields := strings.Fields(line)
		if len(fields) > 0 && fields[0] == "include" {
			return true
		}
		for _, f := range fields {
			if f = strings.Trim(f, ";,{}"); f == "drop" || f == "reject" {
				return true
			}
		}
	}
	return false
}

// avahiSockets are the control sockets of a running Avahi daemon.
var avahiSockets = []string{"/run/avahi-daemon/socket", "/var/run/avahi-daemon/socket"}

// statPath is os.Stat (tests replace it).
var statPath = os.Stat

// BuiltinMDNSLikely reports whether mdns.mode "auto" falls back to the
// builtin mDNS responder on h (DESIGN §10.5): Linux without a running Avahi
// daemon. Only the builtin responder binds UDP 5353 itself and so needs a
// firewall rule (Avahi and macOS dns-sd are system services).
func BuiltinMDNSLikely(h *Host) bool {
	if h.GOOS != "linux" {
		return false
	}
	for _, s := range avahiSockets {
		if _, err := statPath(s); err == nil {
			return false
		}
	}
	return true
}

// ufwEnabled parses ENABLED=yes in ufw.conf.
func ufwEnabled(b []byte) bool {
	sc := bufio.NewScanner(bytes.NewReader(b))
	for sc.Scan() {
		k, v, ok := strings.Cut(strings.TrimSpace(sc.Text()), "=")
		if ok && strings.TrimSpace(k) == "ENABLED" {
			return strings.EqualFold(strings.Trim(strings.TrimSpace(v), `"'`), "yes")
		}
	}
	return false
}

// HintInput describes what must be reachable.
type HintInput struct {
	HTTPSPort int
	HTTPPort  int            // 0 = no redirect listener
	Subnets   []netip.Prefix // LAN/Wi-Fi (and other allowed) subnets
	VPNIfaces []string       // e.g. tailscale0, wg0: allowed by interface
	// BuiltinMDNS: the builtin responder binds UDP 5353 itself (Avahi and
	// dns-sd do not need a rule).
	BuiltinMDNS bool
	Binary      string // macOS application firewall: the server binary
	// Anywhere opens the ports to every source (network.access_mode any).
	Anywhere bool
}

func (in HintInput) ports() []int {
	ps := []int{in.HTTPSPort}
	if in.HTTPPort > 0 && in.HTTPPort != in.HTTPSPort {
		ps = append(ps, in.HTTPPort)
	}
	return ps
}

func joinPorts(ps []int, sep string) string {
	s := make([]string, len(ps))
	for i, p := range ps {
		s[i] = strconv.Itoa(p)
	}
	return strings.Join(s, sep)
}

// uniquePrefixes returns the masked, de-duplicated, sorted subnets without
// loopback and link-local.
func uniquePrefixes(in []netip.Prefix) []netip.Prefix {
	var out []netip.Prefix
	for _, p := range in {
		if !p.IsValid() {
			continue
		}
		p = p.Masked()
		a := p.Addr()
		if a.IsLoopback() || a.IsLinkLocalUnicast() || a.IsUnspecified() {
			continue
		}
		if !slices.Contains(out, p) {
			out = append(out, p)
		}
	}
	slices.SortFunc(out, func(a, b netip.Prefix) int {
		if c := a.Addr().Compare(b.Addr()); c != 0 {
			return c
		}
		return a.Bits() - b.Bits()
	})
	return out
}

// Hints returns the commands that open FileParcel's ports on firewall fw
// for the allowed networks (DESIGN §14.2), e.g.
//
//	sudo ufw allow from 192.168.1.0/24 to any port 8443,8080 proto tcp
//	sudo ufw allow in on tailscale0 to any port 8443 proto tcp
func Hints(fw string, in HintInput) []string { return hints(fw, in, false) }

// hints computes Hints; with in.Anywhere the per-network and per-interface
// TCP rules are left out (the any-source rule covers them), except for
// removal, which also lists the rules earlier advice may have added.
func hints(fw string, in HintInput, removal bool) []string {
	var out []string
	subnets := uniquePrefixes(in.Subnets)
	ports := in.ports()
	tcpSubnets, vpnIfaces := subnets, in.VPNIfaces
	if in.Anywhere && !removal {
		tcpSubnets, vpnIfaces = nil, nil
	}
	switch fw {
	case FirewallUFW:
		if in.Anywhere {
			out = append(out, fmt.Sprintf("sudo ufw allow proto tcp to any port %s", joinPorts(ports, ",")))
		}
		for _, s := range tcpSubnets {
			out = append(out, fmt.Sprintf("sudo ufw allow from %s to any port %s proto tcp", s, joinPorts(ports, ",")))
		}
		for _, i := range vpnIfaces {
			out = append(out, fmt.Sprintf("sudo ufw allow in on %s to any port %d proto tcp", i, in.HTTPSPort))
		}
		if in.BuiltinMDNS {
			for _, s := range subnets {
				if s.Addr().Is4() {
					out = append(out, fmt.Sprintf("sudo ufw allow from %s to any port 5353 proto udp", s))
				}
			}
		}
	case FirewallFirewalld:
		if in.Anywhere {
			for _, p := range ports {
				out = append(out, fmt.Sprintf("sudo firewall-cmd --permanent --add-port=%d/tcp", p))
			}
		}
		for _, s := range tcpSubnets {
			fam := "ipv4"
			if s.Addr().Is6() {
				fam = "ipv6"
			}
			for _, p := range ports {
				out = append(out, fmt.Sprintf(`sudo firewall-cmd --permanent --add-rich-rule='rule family="%s" source address="%s" port port="%d" protocol="tcp" accept'`, fam, s, p))
			}
		}
		for _, i := range vpnIfaces {
			// An interface bound to no zone (NetworkManager leaves
			// tailscale0 unmanaged) makes --get-zone-of-interface fail
			// with "no zone"; its traffic goes to the default zone.
			out = append(out, fmt.Sprintf(`zone=$(firewall-cmd --get-zone-of-interface=%s 2>/dev/null) || zone=$(firewall-cmd --get-default-zone); sudo firewall-cmd --permanent --zone="$zone" --add-port=%d/tcp`, i, in.HTTPSPort))
		}
		if in.BuiltinMDNS {
			out = append(out, "sudo firewall-cmd --permanent --add-service=mdns")
		}
		if len(out) > 0 {
			out = append(out, "sudo firewall-cmd --reload")
		}
	case FirewallNftables:
		// "insert" puts each rule at the head of the chain: nftables counts
		// as active only when the ruleset drops or rejects something, and an
		// appended ("add") accept rule would come after that drop/reject rule
		// and never match.
		set := "{ " + joinPorts(ports, ", ") + " }"
		if in.Anywhere {
			out = append(out, fmt.Sprintf("sudo nft insert rule inet filter input tcp dport %s accept", set))
		}
		for _, s := range tcpSubnets {
			fam := "ip"
			if s.Addr().Is6() {
				fam = "ip6"
			}
			out = append(out, fmt.Sprintf("sudo nft insert rule inet filter input %s saddr %s tcp dport %s accept", fam, s, set))
		}
		for _, i := range vpnIfaces {
			out = append(out, fmt.Sprintf("sudo nft insert rule inet filter input iifname %q tcp dport %d accept", i, in.HTTPSPort))
		}
		if in.BuiltinMDNS {
			for _, s := range subnets {
				if s.Addr().Is4() {
					out = append(out, fmt.Sprintf("sudo nft insert rule inet filter input ip saddr %s udp dport 5353 accept", s))
				}
			}
		}
		if len(out) > 0 {
			out = append(out, "# adjust the table/chain names (inet filter input) to your ruleset; to keep the rules, add them to /etc/nftables.conf before any drop/reject rule of that chain")
		}
	case FirewallMacOS:
		if in.Binary != "" {
			out = append(out,
				"sudo "+SocketFilterFW+" --add "+ShellQuote(in.Binary),
				"sudo "+SocketFilterFW+" --unblockapp "+ShellQuote(in.Binary))
		}
	}
	return out
}

// RemovalHints returns the commands that remove the rules of Hints.
func RemovalHints(fw string, in HintInput) []string {
	var out []string
	switch fw {
	case FirewallUFW:
		for _, h := range hints(fw, in, true) {
			out = append(out, strings.Replace(h, "sudo ufw allow", "sudo ufw delete allow", 1))
		}
	case FirewallFirewalld:
		for _, h := range hints(fw, in, true) {
			h = strings.Replace(h, "--add-rich-rule", "--remove-rich-rule", 1)
			h = strings.Replace(h, "--add-port", "--remove-port", 1)
			h = strings.Replace(h, "--add-service", "--remove-service", 1)
			out = append(out, h)
		}
	case FirewallNftables:
		if len(hints(fw, in, true)) > 0 {
			out = append(out, "sudo nft -a list chain inet filter input   # then: sudo nft delete rule inet filter input handle <N> for the FileParcel rules")
		}
	case FirewallMacOS:
		if in.Binary != "" {
			out = append(out, "sudo "+SocketFilterFW+" --remove "+ShellQuote(in.Binary))
		}
	}
	return out
}
