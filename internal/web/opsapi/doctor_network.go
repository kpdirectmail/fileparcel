package opsapi

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"fileparcel/internal/app"
	"fileparcel/internal/core"
	"fileparcel/internal/web/httpx"
)

// Doctor rows of Tailscale Funnel and Serve and of hand-made proxies
// (DESIGN §10.6, §17 "doctor"). The local `fileparcel doctor` reports the
// same IDs while the server is stopped (tsingress.OfflineFindings).
const (
	checkIDFunnel     = "network.funnel"
	checkIDServe      = "network.serve"
	checkIDBypass     = "network.funnel_bypass"
	checkIDLocalProxy = "network.proxy_unconfigured"
	checkIDKeyExpiry  = "tailscale.key_expiry" // also the ID of the entries' check
	ingressCheckTCP   = "backend.tcp"
	// ingressCheckPasskeys: passkeys do not work on the Funnel address.
	ingressCheckPasskeys = "passkeys"
	// maxStaffDoctor bounds the accounts read for the Funnel administration
	// warning (only while funnel.allow_admin is on).
	maxStaffDoctor = 2000
)

// checkIngress reports Funnel and Serve (off: no row), the hand-made proxies
// that bypass the access policy, an expiring Tailscale key while Funnel or
// Serve is wanted, and the VPN rows (checkVPNs, doctor_vpn.go).
func checkIngress(ctx context.Context, d *app.Deps, now time.Time) []DoctorCheck {
	var out []DoctorCheck
	var st *core.IngressStatus
	if d.Ingress != nil {
		if s, err := d.Ingress.Status(ctx, false); err == nil {
			st = s
		}
	}
	if st != nil {
		if c := ingressEntryCheck(ctx, d, st, st.Funnel); c != nil {
			out = append(out, *c)
		}
		if c := ingressEntryCheck(ctx, d, st, st.Serve); c != nil {
			out = append(out, *c)
		}
		if c := keyExpiryCheck(st); c != nil {
			out = append(out, *c)
		}
	}
	for _, e := range httpx.ProxyExposures(st, now) {
		c := DoctorCheck{Name: "Tailscale forwarding to FileParcel", Status: CheckFail, Message: e.Message, Hint: e.Hint,
			Link: "/admin/network"}
		c.ID = checkIDBypass
		if e.ID == httpx.ExposureLocalProxy {
			c.ID, c.Name, c.Status = checkIDLocalProxy, "Unconfigured reverse proxy", CheckWarn
		}
		out = append(out, c)
	}
	return append(out, checkVPNs(ctx, d)...)
}

// ingressEntryCheck is the row of one kind (nil while it is off).
func ingressEntryCheck(ctx context.Context, d *app.Deps, st *core.IngressStatus, e core.IngressEntry) *DoctorCheck {
	c := &DoctorCheck{ID: checkIDFunnel, Name: "Tailscale Funnel", Link: "/admin/network#funnel"}
	label := "Funnel"
	if e.Kind == core.IngressServe {
		c.ID, c.Name, c.Link, label = checkIDServe, "Tailscale Serve", "/admin/network#serve", "Serve"
	}
	wanted := e.Mode != "" && e.Mode != core.FunnelOff
	failing := firstFailingCheck(e.Checks)
	switch e.State {
	case core.IngressStateOff:
		return nil
	case core.IngressStateActive:
		c.Status = CheckOK
		switch {
		case e.Kind == core.IngressServe:
			c.Message = "Tailnet devices reach FileParcel at " + e.URL
		case e.Mode == core.FunnelShares:
			c.Message = "Share links are public at " + e.URL
		default:
			c.Status = CheckWarn
			c.Message = "The whole app is public at " + e.URL + " (sign-in with two-factor authentication)"
			if !st.Require2FA {
				c.Message = "The whole app is public at " + e.URL + ", and accounts without two-factor authentication can sign in there"
				c.Hint = "Require two-factor sign-in over Funnel (Admin → Network & VPN), or publish share links only."
			}
			if st.AllowAdmin {
				c.Message += "; administration is allowed over Funnel"
				if names, ok := staffWithout2FA(ctx, d); !ok {
					c.Message += " (the administrators' two-factor status could not be read)"
				} else if len(names) > 0 {
					c.Message += ", and these administrators have no two-factor authentication: " + strings.Join(names, ", ")
					c.Hint = "Ask them to set up an authenticator app or a passkey (Settings → Security), or turn " +
						"administration over Funnel off."
				}
			}
		}
		if pk := findCheck(e.Checks, ingressCheckPasskeys); pk != nil && pk.Status == "warn" && e.Kind == core.IngressFunnel {
			c.Hint = joinSentences(c.Hint, pk.Message+". "+pk.Hint)
		}
		if tcp := findCheck(e.Checks, ingressCheckTCP); tcp != nil && tcp.Status == "warn" {
			c.Status = worse(c.Status, CheckWarn)
			c.Hint = joinSentences(c.Hint, tcp.Message+" "+tcp.Hint)
		}
	case core.IngressStateStopped:
		c.Status, c.Message = CheckInfo, label+" is turned on: "+e.Message
	case core.IngressStateUnavailable:
		if !wanted {
			return nil
		}
		c.Status, c.Message = CheckWarn, label+" is turned on but cannot work: "+e.Message
		if failing != nil {
			c.Hint = failing.Hint
		}
	default: // drift, conflict, paused, error
		c.Status = CheckWarn
		c.Message = label + " needs attention (" + e.State + "): " + e.Message
		switch {
		case failing != nil && failing.Hint != "":
			c.Hint = failing.Hint
		case e.State == core.IngressStateDrift:
			cmd := "fileparcel network funnel reapply"
			if e.Kind == core.IngressServe {
				cmd = "fileparcel network tailscale-serve reapply"
			}
			c.Hint = "Re-apply it in Admin → Network & VPN, or run " + cmd + "."
		}
	}
	return c
}

// keyExpiryCheck warns while Funnel or Serve is wanted and the device's
// Tailscale key expires within 14 days (the entries' key expiry check).
func keyExpiryCheck(st *core.IngressStatus) *DoctorCheck {
	for _, e := range []core.IngressEntry{st.Funnel, st.Serve} {
		if e.Mode == "" || e.Mode == core.FunnelOff {
			continue
		}
		if k := findCheck(e.Checks, checkIDKeyExpiry); k != nil && (k.Status == "warn" || k.Status == "fail") {
			return &DoctorCheck{ID: checkIDKeyExpiry, Name: "Tailscale key expiry", Status: CheckWarn,
				Message: k.Message, Hint: k.Hint, Link: "/admin/network#funnel"}
		}
	}
	return nil
}

// staffWithout2FA lists the active accounts with server permissions (built-in
// owners and administrators, and custom roles holding a server permission)
// that have neither an authenticator app nor a passkey; ok is false when
// that could not be read.
func staffWithout2FA(ctx context.Context, d *app.Deps) (names []string, ok bool) {
	if d.Users == nil || d.Auth == nil {
		return nil, false
	}
	q := core.UserQuery{PageReq: core.PageReq{Limit: maxAdminsDoctor}, Status: "active"}
	seen := 0
	for {
		page, err := d.Users.List(ctx, q)
		if err != nil {
			return nil, false
		}
		for _, u := range page.Items {
			seen++
			if !u.Role.IsAdmin() && u.Permissions.Server() == 0 {
				continue
			}
			mfa, err := d.Auth.MFAStatus(ctx, u.ID)
			switch {
			case errors.Is(err, core.ErrNotFound):
				continue
			case err != nil || mfa == nil:
				return nil, false
			case !mfa.TOTPEnabled && mfa.PasskeyCount == 0:
				names = append(names, u.Username)
			}
		}
		if page.NextCursor == "" || len(page.Items) == 0 {
			break
		}
		if seen >= maxStaffDoctor {
			return nil, false
		}
		q.Cursor = page.NextCursor
	}
	slices.Sort(names)
	if len(names) > 10 {
		names = append(names[:10], fmt.Sprintf("… (%d more)", len(names)-10))
	}
	return names, true
}

// firstFailingCheck returns the first failing check of an entry.
func firstFailingCheck(cs []core.IngressCheck) *core.IngressCheck {
	for i := range cs {
		if cs[i].Status == "fail" {
			return &cs[i]
		}
	}
	return nil
}

// findCheck returns the check with id (nil when absent).
func findCheck(cs []core.IngressCheck, id string) *core.IngressCheck {
	for i := range cs {
		if cs[i].ID == id {
			return &cs[i]
		}
	}
	return nil
}

// worse returns the more severe of two check statuses.
func worse(a, b string) string {
	rank := map[string]int{CheckOK: 0, CheckInfo: 1, CheckWarn: 2, CheckFail: 3}
	if rank[b] > rank[a] {
		return b
	}
	return a
}

// joinSentences joins two hints with a space ("" parts are dropped).
func joinSentences(a, b string) string {
	a, b = strings.TrimSpace(a), strings.TrimSpace(b)
	switch {
	case a == "":
		return b
	case b == "":
		return a
	}
	return a + " " + b
}
