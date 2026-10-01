package settingsapi

import (
	"context"
	"fmt"
	"net/http"
	"net/netip"
	"strings"
	"time"

	"fileparcel/internal/core"
	"fileparcel/internal/web/httpx"
	"fileparcel/internal/web/mw"
)

// republishTimeout bounds POST /admin/mdns/republish.
const republishTimeout = 30 * time.Second

// refusedAddr returns the first of addrs that policy p would refuse. It
// reports nothing when p is invalid (the validation that follows rejects it).
func refusedAddr(n core.Network, p core.AccessPolicy, addrs []netip.Addr) (netip.Addr, bool) {
	for _, a := range addrs {
		allowed, err := n.CheckPolicy(p, a)
		if err != nil {
			return netip.Addr{}, false
		}
		if !allowed {
			return a, true
		}
	}
	return netip.Addr{}, false
}

// lockoutError is the 409 of the lockout guard.
func lockoutError(field string, addr netip.Addr, how string) error {
	return &core.Error{Code: core.ErrConflict.Code, Status: core.ErrConflict.Status, Field: field,
		Message: fmt.Sprintf("this access policy would refuse your current address %s; include it in the allow list or confirm with %s", addr, how)}
}

// Optional extensions of the network service (VPN detection, DESIGN
// §10.3): the VPN list and the exposures it finds on this machine. Without
// them the overview lists none.
type (
	vpnLister interface {
		VPNs(ctx context.Context) []core.VPNInfo
	}
	exposureLister interface {
		Exposures(ctx context.Context) []core.Exposure
	}
)

// networkOverview is GET /admin/network: interfaces, access URLs, the
// policy, Tailscale, the cached Funnel/Serve status, the VPNs and the
// exposures (the network service's and the hand-made proxies of
// httpx.ProxyExposures).
func (a *api) networkOverview(w http.ResponseWriter, r *http.Request) {
	n := a.network(w, r)
	if n == nil {
		return
	}
	ctx := r.Context()
	ifs, err := n.Interfaces(ctx)
	if err != nil {
		// Enumeration failed (e.g. netlink denied): still show the policy
		// and URLs — this is the page where the allow list gets fixed.
		a.logger().Warn("settingsapi: listing network interfaces", "err", err)
		ifs = []core.NetInterface{}
	}
	urls, err := n.URLs(ctx)
	if err != nil {
		httpx.Error(w, r, err)
		return
	}
	ts, err := n.Tailscale(ctx)
	if err != nil {
		if ctx.Err() != nil {
			httpx.Error(w, r, err)
			return
		}
		// A provider error is a real problem: Installed keeps the
		// warning in the UI (not the neutral "not installed" text).
		ts = &core.TailscaleInfo{Installed: true, Error: "could not read the Tailscale status"}
		a.logger().Warn("settingsapi: tailscale status", "err", err)
	}
	ov := core.NetworkOverview{
		Interfaces: ifs,
		URLs:       urls,
		Policy:     normPolicy(n.Policy()),
		Tailscale:  ts,
	}
	if ip := mw.ClientIP(r); ip.IsValid() {
		ov.ClientIP = ip.Unmap().WithZone("").String()
	}
	if a.d.Ingress != nil {
		st, err := a.d.Ingress.Status(ctx, false)
		switch {
		case err == nil:
			ov.Ingress = st
		case ctx.Err() != nil:
			httpx.Error(w, r, err)
			return
		default:
			a.logger().Warn("settingsapi: tailscale funnel/serve status", "err", err)
		}
	}
	if v, ok := n.(vpnLister); ok {
		ov.VPNs = v.VPNs(ctx)
	}
	if e, ok := n.(exposureLister); ok {
		ov.Exposures = append(ov.Exposures, e.Exposures(ctx)...)
	}
	now := time.Now()
	if a.d.Env != nil {
		now = a.d.Env.Now()
	}
	ov.Exposures = append(ov.Exposures, httpx.ProxyExposures(ov.Ingress, now)...)
	if ov.Interfaces == nil {
		ov.Interfaces = []core.NetInterface{}
	}
	if ov.URLs == nil {
		ov.URLs = []core.AccessURL{}
	}
	// Arrays in the JSON contract, never null (filled by the VPN detection).
	if ov.VPNs == nil {
		ov.VPNs = []core.VPNInfo{}
	}
	if ov.Exposures == nil {
		ov.Exposures = []core.Exposure{}
	}
	httpx.OK(w, ov)
}

// putPolicy is PUT /admin/network/policy (E). Network.SetPolicy applies the
// lockout guard to the client IP (and audits network.policy); behind a
// trusted reverse proxy the proxy's own address is checked here too, since
// that is the address the listener's allowlist sees. Over Tailscale Funnel
// (reachable with funnel.allow_admin) only the deny list applies to the
// requester, so only a deny list that covers it is refused (putPolicyOverFunnel).
func (a *api) putPolicy(w http.ResponseWriter, r *http.Request) {
	n := a.network(w, r)
	if n == nil {
		return
	}
	in, err := httpx.Decode[core.PolicyInput](r, maxSettingsBody)
	if err != nil {
		httpx.Error(w, r, err)
		return
	}
	if strings.TrimSpace(in.Mode) == "" {
		httpx.Error(w, r, core.Invalid("mode", "required: private, allowlist or any"))
		return
	}
	p := normPolicy(core.AccessPolicy{Mode: in.Mode, Allow: in.Allow, Deny: in.Deny})
	client := mw.ClientIP(r)
	if ing := core.IngressFrom(r.Context()); ing != nil && ing.Kind == core.IngressFunnel {
		a.putPolicyOverFunnel(w, r, n, p, client, in.Force)
		return
	}
	var peers []netip.Addr
	for _, addr := range requesterAddrs(r) {
		if addr != client.Unmap().WithZone("") {
			peers = append(peers, addr)
		}
	}
	peer, peerDenied := refusedAddr(n, p, peers)
	if peerDenied && !in.Force {
		httpx.Error(w, r, lockoutError("allow", peer, "force"))
		return
	}
	warnings, err := n.SetPolicy(r.Context(), mw.Principal(r), p, client, in.Force)
	if err != nil {
		httpx.Error(w, r, err)
		return
	}
	if warnings == nil {
		warnings = []string{}
	}
	if peerDenied {
		warnings = append(warnings, fmt.Sprintf("The reverse proxy address %s is not allowed by this policy: connections through it will be refused.", peer))
	}
	httpx.OK(w, core.PolicyResult{Policy: normPolicy(n.Policy()), Warnings: warnings})
}

// putPolicyOverFunnel stores p for a requester on the public Funnel
// address. The allow list does not apply there (Funnel applies the deny
// list only, DESIGN §10.6), so Network.SetPolicy gets no current address
// (its guard would refuse every allow list without the requester's public
// address) and the guard here refuses a deny list that covers the
// requester instead, unless force.
func (a *api) putPolicyOverFunnel(w http.ResponseWriter, r *http.Request, n core.Network, p core.AccessPolicy,
	client netip.Addr, force bool) {
	if !force && client.IsValid() {
		if allowed, err := n.CheckPolicy(core.AccessPolicy{Mode: core.AccessAny, Deny: p.Deny}, client); err == nil && !allowed {
			httpx.Error(w, r, &core.Error{Code: core.ErrConflict.Code, Status: core.ErrConflict.Status, Field: "deny",
				Message: fmt.Sprintf("this deny list would refuse your current address %s (over Tailscale Funnel only "+
					"the deny list applies); remove it from the deny list or confirm with force", client.Unmap().WithZone(""))})
			return
		}
	}
	warnings, err := n.SetPolicy(r.Context(), mw.Principal(r), p, netip.Addr{}, force)
	if err != nil {
		httpx.Error(w, r, err)
		return
	}
	if warnings == nil {
		warnings = []string{}
	}
	httpx.OK(w, core.PolicyResult{Policy: normPolicy(n.Policy()), Warnings: warnings})
}

// normPolicy returns p with non-nil lists (JSON [] instead of null).
func normPolicy(p core.AccessPolicy) core.AccessPolicy {
	if p.Allow == nil {
		p.Allow = []string{}
	}
	if p.Deny == nil {
		p.Deny = []string{}
	}
	return p
}

// networkURLs is GET /network/urls (F): how to reach the server.
func (a *api) networkURLs(w http.ResponseWriter, r *http.Request) {
	n := a.network(w, r)
	if n == nil {
		return
	}
	urls, err := n.URLs(r.Context())
	if err != nil {
		httpx.Error(w, r, err)
		return
	}
	if urls == nil {
		urls = []core.AccessURL{}
	}
	httpx.OK(w, urls)
}

// mdnsStatus is GET /admin/mdns.
func (a *api) mdnsStatus(w http.ResponseWriter, r *http.Request) {
	m := a.mdns(w, r)
	if m == nil {
		return
	}
	httpx.OK(w, normStatus(m.Status()))
}

// mdnsRepublish is POST /admin/mdns/republish: withdraw and publish the
// name and service again (resolving collisions afresh); answers the status.
func (a *api) mdnsRepublish(w http.ResponseWriter, r *http.Request) {
	m := a.mdns(w, r)
	if m == nil {
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), republishTimeout)
	defer cancel()
	if err := m.Republish(ctx); err != nil {
		if ctx.Err() != nil && r.Context().Err() == nil {
			err = core.Wrap(core.ErrUnavailable, "the mDNS backend did not answer in time", err)
		} else if core.AsError(err) == nil {
			// Backend failures (D-Bus, dns-sd, sockets) are reported to the
			// admin, not hidden behind a generic 500.
			err = &core.Error{Code: core.ErrUnavailable.Code, Status: core.ErrUnavailable.Status,
				Message: "republishing failed: " + err.Error()}
		}
		httpx.Error(w, r, err)
		return
	}
	httpx.OK(w, normStatus(m.Status()))
}

func normStatus(st core.MDNSStatus) core.MDNSStatus {
	if st.Interfaces == nil {
		st.Interfaces = []string{}
	}
	return st
}
