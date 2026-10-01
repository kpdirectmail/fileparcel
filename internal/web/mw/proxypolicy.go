package mw

import (
	"net/http"

	"fileparcel/internal/core"
	"fileparcel/internal/web/httpx"
)

// errPolicyRefused is the 403 of ProxiedPolicy.
var errPolicyRefused = core.Errorf(core.ErrForbidden, "your address is not allowed by the access policy")

// ProxiedPolicy applies the access policy (DESIGN §10.3) to the client
// address a trusted reverse proxy forwarded (X-Forwarded-For, resolved by
// ResolveClientIP). The listener only sees the proxy — and a proxy on this
// machine connects from loopback, which is always allowed — so without this
// the deny list and the allow list would never reach the clients behind it.
//
// Only requests whose resolved client differs from the direct peer are
// checked: every other request was already checked at Accept(). It only ever
// refuses more than the listener did, so a proxy that forwards a spoofed
// X-Forwarded-For can at worst skip the check, never widen access. Refused
// requests get 403 (JSON on API paths) and appear in the access log;
// in-process requests (socket / offline CLI) always pass. Requests of a
// Tailscale ingress listener pass too: IngressGate applies their policy
// (Funnel is public by design and applies the deny list only).
func ProxiedPolicy(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		d := Deps(r)
		client := ClientIP(r)
		if !hasEnv(d) || d.Network == nil || trusted(r) || core.IngressFrom(r.Context()) != nil || !client.IsValid() ||
			client == httpx.RemoteIP(r) || d.Network.Allowed(client) {
			next.ServeHTTP(w, r)
			return
		}
		logger(r).Debug("request refused by the access policy", "ip", client.String(), "proxy", httpx.RemoteIP(r).String())
		setSecurityHeaders(w, r)
		policyRefused(w, r)
	})
}

// policyRefused writes the 403 of a client the access policy refuses (JSON
// on API paths) and ends the connection.
func policyRefused(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Connection", "close")
	if isAPIPath(r.URL.Path) {
		httpx.Error(w, r, errPolicyRefused)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusForbidden)
	_, _ = w.Write([]byte("403 forbidden: your address is not allowed by the access policy\n"))
}
