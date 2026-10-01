package mw

import (
	"net/http"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"time"

	"fileparcel/internal/app"
	"fileparcel/internal/core"
	"fileparcel/internal/web/httpx"
)

// ResolveClientIP resolves the client IP and stores it for ClientIP(r):
//
//   - a request of a Tailscale ingress listener (core.IngressFrom): the
//     client address the listener validated (IngressInfo.ClientIP);
//     server.trusted_proxies does not apply;
//   - otherwise the direct peer (r.RemoteAddr, IPv4-mapped IPv6 unmapped);
//   - X-Forwarded-For is honoured only when the direct peer is in
//     server.trusted_proxies: the hops are walked from the right and the
//     right-most address that is not itself a trusted proxy wins (so a client
//     cannot spoof its address by prepending entries);
//   - a malformed hop stops the walk at the last good address.
//
// Unix-socket and in-process requests resolve to ::1.
//
// A forwarded request from a proxy nobody configured — X-Forwarded-For from
// a peer outside server.trusted_proxies that is this machine (loopback or
// one of its addresses), or a Tailscale address that also sends Tailscale's
// identity header — is
// counted in httpx.ProxySignals.LocalProxy (`tailscale serve
// localhost:8443`, cloudflared, nginx): every visitor behind it looks like
// the proxy. It is still served as before; the doctor reports it.
func ResolveClientIP(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if in := core.IngressFrom(r.Context()); in != nil {
			next.ServeHTTP(w, r.WithContext(httpx.WithClientIP(r.Context(), in.ClientIP)))
			return
		}
		d := Deps(r)
		ip := httpx.RemoteIP(r)
		if trustedList := trustedProxies(d); len(trustedList) > 0 && inAny(ip, trustedList) {
			ip = forwardedFor(r, ip, trustedList)
		} else if unconfiguredProxy(d, r, ip) {
			httpx.ProxySignals.LocalProxy.Note(r.Header.Get("X-Forwarded-Host"), time.Now())
		}
		next.ServeHTTP(w, r.WithContext(httpx.WithClientIP(r.Context(), ip)))
	})
}

// unconfiguredProxy reports whether r was forwarded (X-Forwarded-For) by
// peer, which is not a trusted proxy, from this machine, or from a
// Tailscale address with Tailscale's identity header (a `tailscale serve`
// on another tailnet node). Any client can send those headers: from
// elsewhere they raise no warning. Trusted in-process requests never count.
func unconfiguredProxy(d *app.Deps, r *http.Request, peer netip.Addr) bool {
	if len(r.Header.Values("X-Forwarded-For")) == 0 || trusted(r) {
		return false
	}
	if peer.IsLoopback() || hasEnv(d) && d.Network != nil && d.Network.IsLocal(peer) {
		return true
	}
	return r.Header.Get("Tailscale-User-Login") != "" && tailnetAddr(peer)
}

// Tailscale's address ranges.
var (
	tailnetV4 = netip.MustParsePrefix("100.64.0.0/10")
	tailnetV6 = netip.MustParsePrefix("fd7a:115c:a1e0::/48")
)

// tailnetAddr reports whether ip is in Tailscale's address ranges.
func tailnetAddr(ip netip.Addr) bool {
	ip = ip.Unmap().WithZone("")
	return tailnetV4.Contains(ip) || tailnetV6.Contains(ip)
}

// forwardedFor walks X-Forwarded-For from the right (see ResolveClientIP).
func forwardedFor(r *http.Request, peer netip.Addr, trustedList []netip.Prefix) netip.Addr {
	xff := r.Header.Values("X-Forwarded-For")
	if len(xff) == 0 {
		return peer
	}
	hops := strings.Split(strings.Join(xff, ","), ",")
	ip := peer
	for i := len(hops) - 1; i >= 0; i-- {
		a, err := parseHop(hops[i])
		if err != nil {
			break
		}
		ip = a
		if !inAny(ip, trustedList) {
			break
		}
	}
	return ip
}

// parseHop parses one X-Forwarded-For entry ("1.2.3.4", "1.2.3.4:5678",
// "[::1]:80", "::1"), unmapping IPv4-mapped addresses and dropping zones.
func parseHop(s string) (netip.Addr, error) {
	s = strings.TrimSpace(s)
	if ap, err := netip.ParseAddrPort(s); err == nil {
		return ap.Addr().Unmap().WithZone(""), nil
	}
	a, err := netip.ParseAddr(strings.Trim(s, "[]"))
	if err != nil {
		return netip.Addr{}, err
	}
	return a.Unmap().WithZone(""), nil
}

type proxyCache struct {
	mu   sync.Mutex
	src  []string
	list []netip.Prefix
}

var proxies proxyCache

// trustedProxies returns the parsed server.trusted_proxies (from the
// settings bridge when registered, else the bootstrap config), cached until
// the source list changes.
func trustedProxies(d *app.Deps) []netip.Prefix {
	if !hasEnv(d) {
		return nil
	}
	var src []string
	if d.Settings != nil {
		if _, err := d.Settings.Raw("server.trusted_proxies"); err == nil {
			src = d.Settings.Strings("server.trusted_proxies")
		}
	}
	if src == nil && d.Config != nil {
		src = d.Config.Server.TrustedProxies
	}
	if len(src) == 0 {
		return nil
	}
	proxies.mu.Lock()
	defer proxies.mu.Unlock()
	if !slices.Equal(src, proxies.src) {
		proxies.src = slices.Clone(src)
		proxies.list = parsePrefixes(src)
	}
	return proxies.list
}

// parsePrefixes parses CIDRs or single IPs (IPv4-mapped addresses unmapped;
// a single IP becomes a /32 or /128), skipping invalid entries (config
// validation rejects them at load time).
func parsePrefixes(list []string) []netip.Prefix {
	out := make([]netip.Prefix, 0, len(list))
	for _, s := range list {
		s = strings.TrimSpace(s)
		if p, err := netip.ParsePrefix(s); err == nil {
			if p.Addr().Is4In6() {
				if p.Bits() < 96 {
					continue
				}
				p = netip.PrefixFrom(p.Addr().Unmap(), p.Bits()-96)
			}
			out = append(out, p.Masked())
		} else if a, err := netip.ParseAddr(s); err == nil {
			a = a.Unmap().WithZone("")
			out = append(out, netip.PrefixFrom(a, a.BitLen()))
		}
	}
	return out
}

func inAny(ip netip.Addr, ps []netip.Prefix) bool {
	ip = ip.Unmap()
	for _, p := range ps {
		if p.Contains(ip) {
			return true
		}
	}
	return false
}
