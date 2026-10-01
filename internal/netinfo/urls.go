package netinfo

import (
	"net"
	"net/netip"
	"net/url"
	"slices"
	"strconv"
	"strings"

	"fileparcel/internal/core"
)

// urlInput is everything buildURLs needs (a pure function, for tests).
type urlInput struct {
	port          int
	ifaces        []core.NetInterface
	mdnsName      string           // effective mDNS FQDN, e.g. "fileparcel.local"
	mdnsPublished bool             // the last mdns.changed reported "published"
	sysHost       string           // FQDN published by the system responder ("fileshare.local")
	magicDNS      string           // MagicDNS FQDN ("node.tailnet.ts.net")
	magicKind     string           // core.IfTailscale | core.IfHeadscale
	magicIface    string           // name of the Tailscale interface
	publicURL     string           // server.public_url
	ingress       []core.AccessURL // Tailscale Serve and Funnel (app mode) while active (core.Ingress.AccessURLs)
	extra         []string
	trusted       func(host string) bool // certificate covers host and is publicly trusted
}

// hostPort renders "host:port" for an https URL (":443" omitted, IPv6 bracketed).
func hostPort(host string, port int) string {
	if port == 443 || port <= 0 {
		if strings.Contains(host, ":") {
			return "[" + host + "]"
		}
		return host
	}
	return net.JoinHostPort(host, strconv.Itoa(port))
}

// httpsURL returns "https://host[:port]/".
func httpsURL(host string, port int) string { return "https://" + hostPort(host, port) + "/" }

// ipRank orders IP URLs: local (LAN/Wi-Fi) interfaces before VPNs,
// IPv4 before IPv6.
func ipRank(ni core.NetInterface, a netip.Addr) int {
	r := 0
	if RoleOf(ni) != core.VPNRoleLocal {
		r += 2
	}
	if !a.Is4() {
		r++
	}
	return r
}

// buildURLs builds the access URLs of DESIGN §10.2 in display order: public
// URL, the Tailscale Serve and Funnel addresses, MagicDNS, mDNS name (only
// while publishing is active), system .local name, IP addresses of the
// offered interfaces (local IPv4, local IPv6, VPN IPv4, VPN IPv6; never an
// exit, corporate or overlay VPN's), extra names.
//
// Recommended: the public URL; MagicDNS when its certificate is publicly
// trusted; the mDNS name (it is listed only once published); and the first LAN/Wi-Fi IPv4
// address (every device can use it, DESIGN §18.3) — or the first IP URL when
// there is no LAN address.
func buildURLs(in urlInput) []core.AccessURL {
	out := []core.AccessURL{}
	seen := map[string]bool{}
	trusted := func(host string) bool { return in.trusted != nil && in.trusted(host) }
	add := func(u core.AccessURL) {
		if u.URL == "" || seen[u.URL] {
			return
		}
		seen[u.URL] = true
		out = append(out, u)
	}

	if pu := strings.TrimSpace(in.publicURL); pu != "" {
		if u, err := url.Parse(pu); err == nil && u.Host != "" {
			add(core.AccessURL{URL: pu, Kind: core.URLKindPublic, Label: "Public URL",
				Trusted: u.Scheme == "https" && trusted(u.Hostname()), Recommended: true})
		}
	}
	for _, u := range in.ingress {
		add(u)
	}
	if in.magicDNS != "" {
		label := "Tailscale MagicDNS"
		if in.magicKind == core.IfHeadscale {
			label = "Headscale MagicDNS"
		}
		t := trusted(in.magicDNS)
		add(core.AccessURL{URL: httpsURL(in.magicDNS, in.port), Kind: core.URLKindMagicDNS, Interface: in.magicIface,
			Label: label, Trusted: t, Recommended: t})
	}
	// Only while the name is really published (DESIGN §10.2): before the
	// first publication, after a failure and with mdns.mode=off nothing
	// answers to it, and a collision may still rename it.
	if in.mdnsName != "" && in.mdnsPublished {
		add(core.AccessURL{URL: httpsURL(in.mdnsName, in.port), Kind: core.URLKindMDNS,
			Label: "Local network name (mDNS)", Trusted: trusted(in.mdnsName), Recommended: true})
	}
	// The system responder answers its name whatever FileParcel's own
	// publication does; when both are the same published name, the mDNS
	// entry above already took the URL (add de-duplicates).
	if in.sysHost != "" {
		add(core.AccessURL{URL: httpsURL(in.sysHost, in.port), Kind: core.URLKindHostname,
			Label: "Computer name (mDNS)", Trusted: trusted(in.sysHost)})
	}

	type ipURL struct {
		ni   core.NetInterface
		addr netip.Addr
		rank int
	}
	var ips []ipURL
	for _, ni := range in.ifaces {
		if !offered(ni) {
			continue
		}
		for _, p := range ni.Addrs {
			a := p.Addr().Unmap().WithZone("")
			if !offeredAddr(ni, a) {
				continue
			}
			ips = append(ips, ipURL{ni: ni, addr: a, rank: ipRank(ni, a)})
		}
	}
	slices.SortStableFunc(ips, func(x, y ipURL) int { return x.rank - y.rank })
	recommendedIP := false
	for _, x := range ips {
		rec := !recommendedIP && x.rank == 0
		if rec {
			recommendedIP = true
		}
		add(core.AccessURL{URL: httpsURL(x.addr.String(), in.port), Kind: core.URLKindIP, Interface: x.ni.Name,
			Label: x.ni.Label + " (" + x.ni.Name + ")", Trusted: trusted(x.addr.String()), Recommended: rec})
	}
	if !recommendedIP {
		for i := range out {
			if out[i].Kind == core.URLKindIP {
				out[i].Recommended = true
				break
			}
		}
	}

	for _, n := range in.extra {
		n = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(n)), ".")
		if n == "" || strings.Contains(n, "*") {
			continue
		}
		if _, err := netip.ParseAddr(n); err == nil {
			continue // IP SANs are already listed per interface
		}
		if !validHostname(n) {
			continue
		}
		add(core.AccessURL{URL: httpsURL(n, in.port), Kind: core.URLKindExtra, Label: "Extra name", Trusted: trusted(n)})
	}
	return out
}

// validHostname reports whether s is a syntactically valid DNS host name.
func validHostname(s string) bool { return validDNSName(s, false) }

// validDNSName reports whether s is a valid DNS name; wildcard admits one
// leading "*." label.
func validDNSName(s string, wildcard bool) bool {
	if wildcard {
		s = strings.TrimPrefix(s, "*.")
	}
	if s == "" || len(s) > 253 {
		return false
	}
	for _, label := range strings.Split(s, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for i := 0; i < len(label); i++ {
			c := label[i]
			if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
				return false
			}
		}
	}
	return true
}
