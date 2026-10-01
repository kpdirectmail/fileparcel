package mw

import (
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"

	"fileparcel/internal/app"
	"fileparcel/internal/core"
	"fileparcel/internal/web/httpx"
)

// ErrMisdirected is the 421 answer of HostCheck.
var ErrMisdirected = &core.Error{Code: "misdirected", Status: http.StatusMisdirectedRequest,
	Message: "this server does not answer to that host name"}

// HostCheck enforces network.strict_host (DESIGN §9.1): when enabled, the
// Host header must name this server — loopback ("localhost", 127.0.0.0/8,
// ::1), one of its addresses (Network.IPs), its names (Network.Hostnames,
// the mDNS name, server.public_url, network.extra_hosts, tls.extra_sans,
// acme.domains; "*.example.org" entries match one label) or an IP address
// configured in one of those settings (a NAT / port-forward address that is
// no interface's) — otherwise 421.
// This defeats DNS-rebinding attacks from web pages on the LAN. Requests
// with a trusted in-process principal (socket / offline CLI) always pass,
// and so do requests of a Tailscale ingress listener: it already checked
// their Host against the name it serves (the MagicDNS name is not always
// among the known names, e.g. right after a rename or with MagicDNS off for
// this machine's own view).
// HostCheck runs ahead of SecurityHeaders in the §9.1 chain, so its own 421
// applies the §9.2 headers before writing ("all responses").
func HostCheck(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		d := Deps(r)
		if trusted(r) || core.IngressFrom(r.Context()) != nil || !strictHost(d) || HostAllowed(d, r.Host) {
			next.ServeHTTP(w, r)
			return
		}
		logger(r).Debug("host check: unknown Host header", "host", sanitizeLog(r.Host), "ip", ClientIP(r).String())
		setSecurityHeaders(w, r)
		if isAPIPath(r.URL.Path) {
			httpx.Error(w, r, ErrMisdirected)
			return
		}
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusMisdirectedRequest)
		_, _ = w.Write([]byte("421 misdirected request: this server does not answer to that host name\n"))
	})
}

func strictHost(d *app.Deps) bool {
	return hasEnv(d) && d.Settings != nil && d.Settings.Bool("network.strict_host")
}

// HostAllowed reports whether hostport (a Host header value) names this
// server (see HostCheck). It does not look at network.strict_host.
func HostAllowed(d *app.Deps, hostport string) bool {
	host := normalizeHost(hostport)
	if host == "" {
		return false
	}
	if ip, err := netip.ParseAddr(host); err == nil {
		ip = ip.Unmap().WithZone("")
		if ip.IsLoopback() {
			return true
		}
		if hasEnv(d) && d.Network != nil {
			for _, a := range d.Network.IPs() {
				if a.Unmap().WithZone("") == ip {
					return true
				}
			}
		}
		// Configured IP entries (an address behind NAT / a port forward in
		// network.extra_hosts, tls.extra_sans or server.public_url), compared
		// as addresses so mapped, compressed and expanded forms all match.
		for _, n := range knownNames(d) {
			if a, err := netip.ParseAddr(normalizeHost(n)); err == nil && a.Unmap().WithZone("") == ip {
				return true
			}
		}
		return false
	}
	if host == "localhost" || strings.HasSuffix(host, ".localhost") {
		return true
	}
	for _, n := range knownNames(d) {
		if matchHost(n, host) {
			return true
		}
	}
	return false
}

// normalizeHost lowercases a Host value and strips the port, IPv6 brackets,
// an IPv6 zone and a trailing dot.
func normalizeHost(hostport string) string {
	h := strings.ToLower(strings.TrimSpace(hostport))
	if host, _, err := net.SplitHostPort(h); err == nil {
		h = host
	}
	h = strings.TrimSuffix(strings.Trim(h, "[]"), ".")
	return h
}

// matchHost matches host against pattern (exact, or "*.domain" for exactly
// one extra label).
func matchHost(pattern, host string) bool {
	pattern = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(pattern)), ".")
	if pattern == "" {
		return false
	}
	if rest, ok := strings.CutPrefix(pattern, "*."); ok {
		label, domain, found := strings.Cut(host, ".")
		return found && label != "" && domain == rest
	}
	return pattern == host
}

// knownNames collects the host names this server answers to.
func knownNames(d *app.Deps) []string {
	if !hasEnv(d) {
		return nil
	}
	var names []string
	if d.Network != nil {
		names = append(names, d.Network.Hostnames()...)
	}
	if d.MDNS != nil {
		names = append(names, d.MDNS.Name())
	}
	if d.Settings != nil {
		for _, k := range []string{"network.extra_hosts", "tls.extra_sans", "acme.domains"} {
			names = append(names, d.Settings.Strings(k)...)
		}
		if u := d.Settings.String("server.public_url"); u != "" {
			names = append(names, urlHost(u))
		}
	}
	if d.Config != nil && d.Config.Server.PublicURL != "" {
		names = append(names, urlHost(d.Config.Server.PublicURL))
	}
	return names
}

func urlHost(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	return u.Hostname()
}

// sanitizeLog bounds and cleans attacker-controlled strings before logging.
func sanitizeLog(s string) string {
	if len(s) > 200 {
		s = s[:200] + "…"
	}
	return strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return '?'
		}
		return r
	}, s)
}
