package opsapi

import (
	"context"
	"net/netip"
	"time"

	"fileparcel/internal/app"
	"fileparcel/internal/core"
	"fileparcel/internal/db"
	"fileparcel/internal/svc"
)

// firewallSeenWindow is how far back a sign-in from a network counts as proof
// that the host firewall lets that network in.
const firewallSeenWindow = 14 * 24 * time.Hour

// tailnetRanges are the address ranges of Tailscale and Headscale clients: the
// tailscale interface itself carries a single /32 and /128.
var tailnetRanges = []netip.Prefix{netip.MustParsePrefix("100.64.0.0/10"), netip.MustParsePrefix("fd7a:115c:a1e0::/48")}

// firewallUnseen narrows the firewall hint to the sources nothing has connected
// from lately. The server runs without root and cannot read the firewall's rules,
// but a session whose address lies in a network shows that the firewall lets
// that network in. It returns the input with only the unseen subnets and VPN
// interfaces, and whether every source was seen (the check is then OK).
func firewallUnseen(ctx context.Context, d *app.Deps, in svc.HintInput) (svc.HintInput, bool) {
	if d.DB == nil || in.Anywhere || (len(in.Subnets) == 0 && len(in.VPNIfaces) == 0) {
		return in, false
	}
	rows, err := d.DB.Query(ctx, `SELECT DISTINCT ip FROM sessions WHERE ip IS NOT NULL AND ip != '' AND last_seen_at > ?`,
		db.Ms(d.Now().Add(-firewallSeenWindow)))
	if err != nil {
		return in, false
	}
	// the server's own addresses prove nothing: such connections never cross the firewall
	own := map[netip.Addr]bool{}
	if d.Network != nil {
		if ifs, err := d.Network.Interfaces(ctx); err == nil {
			for _, it := range ifs {
				for _, a := range it.Addrs {
					own[a.Addr().Unmap()] = true
				}
			}
		}
	}
	var seen []netip.Addr
	for rows.Next() {
		var s string
		if rows.Scan(&s) != nil {
			continue
		}
		if a, err := netip.ParseAddr(s); err == nil && !a.Unmap().IsLoopback() && !own[a.Unmap()] {
			seen = append(seen, a.Unmap())
		}
	}
	rows.Close()
	in2 := in
	in2.Subnets, in2.VPNIfaces = nil, nil
	for _, p := range in.Subnets {
		if !anyIn(seen, []netip.Prefix{p}) {
			in2.Subnets = append(in2.Subnets, p)
		}
	}
	ranges := vpnRanges(ctx, d)
	for _, name := range in.VPNIfaces {
		if r := ranges[name]; len(r) == 0 || !anyIn(seen, r) {
			in2.VPNIfaces = append(in2.VPNIfaces, name)
		}
	}
	return in2, len(in2.Subnets) == 0 && len(in2.VPNIfaces) == 0
}

// vpnRanges maps each VPN interface to the networks its clients come from.
func vpnRanges(ctx context.Context, d *app.Deps) map[string][]netip.Prefix {
	out := map[string][]netip.Prefix{}
	if d.Network == nil {
		return out
	}
	ifs, err := d.Network.Interfaces(ctx)
	if err != nil {
		return out
	}
	for _, it := range ifs {
		if it.Kind == core.IfTailscale || it.Kind == core.IfHeadscale {
			out[it.Name] = tailnetRanges
			continue
		}
		for _, a := range it.Addrs {
			out[it.Name] = append(out[it.Name], a.Masked())
		}
	}
	return out
}

func anyIn(addrs []netip.Addr, nets []netip.Prefix) bool {
	for _, a := range addrs {
		for _, n := range nets {
			if n.Contains(a) {
				return true
			}
		}
	}
	return false
}
