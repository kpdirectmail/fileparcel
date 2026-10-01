package securityapi

import (
	"net/http"
	"net/netip"
	"slices"

	"fileparcel/internal/core"
	"fileparcel/internal/web/httpx"
	"fileparcel/internal/web/mw"
)

// lanPrefixes are the private networks keys.web_unlock=lan accepts:
// loopback, RFC 1918, link-local, CGNAT/tailnet and IPv6 ULA/link-local (the
// "private" set of DESIGN §10.3). The mode also accepts the global IPv6
// subnets of the server's own interfaces (onLink).
var lanPrefixes = []netip.Prefix{
	netip.MustParsePrefix("127.0.0.0/8"),
	netip.MustParsePrefix("10.0.0.0/8"),
	netip.MustParsePrefix("172.16.0.0/12"),
	netip.MustParsePrefix("192.168.0.0/16"),
	netip.MustParsePrefix("169.254.0.0/16"),
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("::1/128"),
	netip.MustParsePrefix("fc00::/7"),
	netip.MustParsePrefix("fe80::/10"),
}

// isLAN reports whether ip is in a private range.
func isLAN(ip netip.Addr) bool {
	ip = ip.Unmap().WithZone("")
	for _, p := range lanPrefixes {
		if p.Contains(ip) {
			return true
		}
	}
	return false
}

// vpnKinds are the VPN interface kinds: their subnets count even next to a
// public IPv4 address (as in the default allowlist).
var vpnKinds = []string{core.IfTailscale, core.IfHeadscale, core.IfWireGuard, core.IfZeroTier, core.IfNetBird,
	core.IfNebula, core.IfVPN}

// onLink reports whether ip is in a global IPv6 subnet (a /64 or a longer
// prefix, not a host-only /128) of one of the server's own up LAN, Wi-Fi or VPN
// interfaces: the prefix a dual-stack home network has next to its private
// IPv4 range. The .local name and the access URLs advertise the server's
// global IPv6 addresses and browsers prefer them, so a phone on the same
// Wi-Fi arrives from its own global address in that /64. As in the default
// allowlist (DESIGN §10.3), an interface that also has a public IPv4 address
// (a cloud VM's uplink) is left out: its subnets hold other tenants.
func onLink(ifaces []core.NetInterface, ip netip.Addr) bool {
	ip = ip.Unmap().WithZone("")
	if !ip.Is6() || !ip.IsGlobalUnicast() || isLAN(ip) {
		return false
	}
	for _, in := range ifaces {
		if !in.Up || in.Kind == core.IfLoopback || in.Kind == core.IfContainer {
			continue
		}
		// Only the roles devices come in through (DESIGN §10.1): the
		// subnet of an outgoing (egress), access or overlay VPN holds other
		// people's addresses, not this network's. An interface without a
		// role (an older network service) is judged by its kind below.
		if in.Role != "" && in.Role != core.VPNRoleLocal && in.Role != core.VPNRoleMesh && in.Role != core.VPNRoleUnknown {
			continue
		}
		if !in.IsVPN && !slices.Contains(vpnKinds, in.Kind) && slices.ContainsFunc(in.Addrs, func(p netip.Prefix) bool {
			a := p.Addr().Unmap()
			return a.Is4() && a.IsGlobalUnicast() && !isLAN(a)
		}) {
			continue
		}
		for _, p := range in.Addrs {
			a := p.Addr()
			if a.Is4() || a.Is4In6() || !a.IsGlobalUnicast() || isLAN(a) || p.Bits() < 64 || p.Bits() == a.BitLen() {
				continue
			}
			if p.Masked().Contains(ip) {
				return true
			}
		}
	}
	return false
}

// localClient reports whether keys.web_unlock=lan admits ip: a private
// range, or a global IPv6 subnet of the server's own interfaces (onLink;
// without network information, or when listing the interfaces fails, only
// the private ranges).
func (a *api) localClient(r *http.Request, ip netip.Addr) bool {
	if isLAN(ip) {
		return true
	}
	if a.d == nil || a.d.Network == nil {
		return false
	}
	ifs, err := a.d.Network.Interfaces(r.Context())
	return err == nil && onLink(ifs, ip)
}

// webUnlockDenied returns why POST /system/unlock refuses the request from
// ip under keys.web_unlock, or nil when it may unlock. The admin socket and
// the in-process CLI always may (also acting as a user with X-FP-As).
func (a *api) webUnlockDenied(r *http.Request, ip netip.Addr) error {
	if p := mw.Principal(r); p != nil && (p.Via == core.ViaSocket || p.Via == core.ViaOffline) {
		return nil
	}
	switch a.webUnlockMode() {
	case "off":
		return core.Errorf(core.ErrForbidden, `unlocking over the web is disabled; use "fileparcel keys unlock"`)
	case "lan":
		if !a.localClient(r, ip) {
			return core.Errorf(core.ErrForbidden, `unlocking is only allowed from the local network; use "fileparcel keys unlock"`)
		}
	}
	return nil
}

// systemStatus is GET /system/status (public): key state, whether the
// first-run setup is pending and, while locked, whether this client may
// unlock over the web (web_unlock).
func (a *api) systemStatus(w http.ResponseWriter, r *http.Request) {
	st := core.SystemStatus{State: core.KeyStateUninitialized}
	if a.d != nil && a.d.Keys != nil {
		st.State = a.d.Keys.State()
	}
	if st.State == core.KeyStateLocked {
		// What POST /system/unlock would answer this client (the unlock page).
		st.WebUnlock = "allowed"
		if err := a.webUnlockDenied(r, mw.ClientIP(r)); err != nil {
			st.WebUnlock = "network"
			if a.webUnlockMode() == "off" {
				st.WebUnlock = "off"
			}
		}
	}
	if a.d != nil && a.d.Users != nil {
		if n, err := a.d.Users.Count(r.Context()); err == nil {
			st.SetupNeeded = n == 0
		}
	}
	httpx.JSON(w, http.StatusOK, st)
}

// systemUnlock is POST /system/unlock (public, rate limited): unlocks the
// sealed master key with the passphrase or a recovery key. Only while
// locked, and only from the networks keys.web_unlock allows (the admin
// socket and the in-process CLI are always allowed, also with X-FP-As).
func (a *api) systemUnlock(w http.ResponseWriter, r *http.Request) {
	k, err := a.keys()
	if err != nil {
		httpx.Error(w, r, err)
		return
	}
	ip := mw.ClientIP(r)
	// The context principal the audit log reads the client from: anonymous
	// callers get one without any identity or rights (no user, no role).
	ctx := r.Context()
	if mw.Principal(r) == nil {
		ctx = core.WithPrincipal(ctx, &core.Principal{IP: ip, UserAgent: r.UserAgent(), RequestID: httpx.RequestID(ctx)})
	}
	if deny := a.webUnlockDenied(r, ip); deny != nil {
		if a.d.Audit != nil {
			a.d.Audit.Record(ctx, core.AuditEntry{Action: core.ActKeysUnlock, Outcome: core.OutcomeDenied, TargetType: "keys",
				Details: map[string]any{"reason": "keys.web_unlock", "web_unlock": a.webUnlockMode()}})
		}
		httpx.Error(w, r, deny)
		return
	}
	switch k.State() {
	case core.KeyStateUnlocked:
		httpx.Error(w, r, core.Errorf(core.ErrConflict, "the server is already unlocked"))
		return
	case core.KeyStateUninitialized:
		httpx.Error(w, r, core.Errorf(core.ErrConflict, "the server has not been initialized"))
		return
	}
	pass, err := passphrase(r)
	if err != nil {
		httpx.Error(w, r, err)
		return
	}
	defer clear(pass)
	// Keys.Unlock audits keys.unlock (success and failure) with ctx's client.
	if err := k.Unlock(ctx, pass); err != nil {
		httpx.Error(w, r, err)
		return
	}
	httpx.JSON(w, http.StatusOK, core.SystemStatus{State: k.State()})
}
