package server

import (
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"fileparcel/internal/app"
	"fileparcel/internal/core"
	"fileparcel/internal/web/httpx"
)

// Hand-made Tailscale proxies (DESIGN §10.6). tailscaled can forward to any
// local target, including FileParcel's own HTTPS port and the admin socket
// — `tailscale funnel https+insecure://localhost:8443` is the example in
// `tailscale funnel --help`. FileParcel's Funnel and Serve use dedicated
// ingress listeners instead (ingress.go); the two entry points below refuse
// requests that can only have come through such a proxy.

// errProxiedSocket is the answer of the admin socket to a proxied request.
var errProxiedSocket = core.Errorf(core.ErrForbidden, "the admin socket does not accept proxied requests")

// refuseProxied guards the admin socket, whose connections carry the system
// principal: a request with X-Forwarded-For, X-Forwarded-Host, Forwarded,
// Via or any Tailscale-* header came through a proxy — `tailscale serve
// unix:<HOME>/run/admin.sock` would otherwise hand every visitor the system
// principal (tailscaled runs as root, which the socket admits). It gets 403
// and an error log line (at most one a minute). The CLI never sends these
// headers (X-FP-As stays allowed); tailscaled always sets X-Forwarded-*.
func refuseProxied(next http.Handler, log *slog.Logger) http.Handler {
	every := &logEvery{every: refusedLogEvery}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !proxied(r.Header) {
			next.ServeHTTP(w, r)
			return
		}
		if n, ok := every.allow(); ok {
			log.Error("admin socket: a proxied request was refused; a proxy (e.g. `tailscale serve unix:…/admin.sock`) "+
				"forwards to the admin socket — remove it", "suppressed", n)
		}
		h := w.Header()
		h.Set("Cache-Control", "no-store")
		h.Set("X-Content-Type-Options", "nosniff")
		httpx.Error(w, r, errProxiedSocket)
	})
}

// proxied reports whether h carries a proxy or Tailscale header.
func proxied(h http.Header) bool {
	for _, name := range []string{"X-Forwarded-For", "X-Forwarded-Host", "Forwarded", "Via"} {
		if len(h.Values(name)) > 0 {
			return true
		}
	}
	for name := range h {
		if strings.HasPrefix(name, "Tailscale-") {
			return true
		}
	}
	return false
}

// funnelToMain answers a request on FileParcel's own HTTPS port that carries
// Tailscale-Funnel-Request: tailscaled deletes that header from what
// clients send and sets it only on Funnel traffic, so the request came
// through a hand-made `tailscale funnel` pointed at this port — on this
// machine (peer: loopback or an own address) or on another tailnet node
// (peer: that node, which the access policy admits for every visitor
// alike). Every visitor would look like that proxy, so the request is
// refused (403 with the removal command). It counts in
// httpx.ProxySignals.FunnelToMain (the doctor's and the Network page's
// failure) only when the peer is where such a proxy can be: loopback, an
// own address or a Tailscale address. Any other client that forges the
// header only refuses itself, and cannot raise the alarm.
func funnelToMain(d *app.Deps, log *slog.Logger) http.Handler {
	every := &logEvery{every: refusedLogEvery}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if proxySource(d, httpx.RemoteIP(r)) {
			httpx.ProxySignals.FunnelToMain.Note(r.Host, time.Now())
			if n, ok := every.allow(); ok {
				log.Warn("a request forwarded by a hand-made `tailscale funnel` to FileParcel's own port was refused; "+
					"use `fileparcel network funnel enable` instead", "host", httpx.SanitizeHost(r.Host), "suppressed", n)
			}
		}
		plainStatus(w, http.StatusForbidden, funnelToMainNotice(r.Host))
	})
}

// Tailscale's address ranges (a hand-made Funnel on another tailnet node
// connects from one of them).
var (
	tailnetV4 = netip.MustParsePrefix("100.64.0.0/10")
	tailnetV6 = netip.MustParsePrefix("fd7a:115c:a1e0::/48")
)

// proxySource reports whether a hand-made Tailscale proxy can connect from
// peer: loopback, an address of this machine, or a Tailscale address.
func proxySource(d *app.Deps, peer netip.Addr) bool {
	peer = peer.Unmap().WithZone("")
	if peer.IsLoopback() || tailnetV4.Contains(peer) || tailnetV6.Contains(peer) {
		return true
	}
	return d != nil && d.Network != nil && d.Network.IsLocal(peer)
}

// funnelToMainNotice is the text of funnelToMain's 403; the port is the one
// the visitor used (the proxy passes the Host through). The command removes
// only that entry (a bare `tailscale serve --https=<port> off` would remove
// every handler of the port, FileParcel's own Funnel or Serve included).
func funnelToMainNotice(host string) string {
	port := "443"
	if _, p, err := net.SplitHostPort(host); err == nil {
		if n, err := strconv.Atoi(p); err == nil && n > 0 && n < 65536 {
			port = strconv.Itoa(n)
		}
	}
	return "403 forbidden: this server is published with a `tailscale funnel` command that points at FileParcel's own " +
		"port, so every visitor would look like that machine.\n\n" +
		"On the machine that runs it, `tailscale funnel status` lists that entry; remove just it " +
		"(`tailscale serve --yes --https=" + port + " --set-path=<its path> off`) and use `fileparcel network funnel enable`.\n"
}
