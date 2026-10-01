// Package settingsapi owns the settings, network, mDNS and QR endpoints
// (DESIGN §9.4, unit G). Guards: Cap(x|y) = mw.RequireCap(x, y) (full
// authentication and any of the permissions; owners and admins hold every
// permission; API tokens need the admin scope for them), Adm = mw.RequireAdmin
// (built-in owners/admins), E = elevated, F = full. Routes under /api/v1:
//
//	GET    /admin/settings[?section=]        Cap(settings.manage|network.manage|certs.manage|system.manage):
//	                                         catalog ([]core.SettingView) of the keys the caller may change
//	                                         (caps.go): values, defaults, restart, overridden_by_env; secrets
//	                                         masked (value null, is_set only)
//	PATCH  /admin/settings[?force=1] {key:value,…}  same guard; every key must be one the caller may change
//	                                         (403 with field = the key), E when a key is in a
//	                                         SensitiveSections section
//	                                         → core.SettingsResult {applied, restart_required, warnings}
//	                                         (a name accepted into tls.extra_sans / network.extra_hosts
//	                                         that the local CA may not sign is applied but never reaches
//	                                         the certificate)
//	DELETE /admin/settings/{key}[?force=1]   same guard and key check; E for sensitive sections; reset to
//	                                         default → core.SettingView
//	POST   /admin/settings/email/test        (Adm) core.EmailTestInput → 204 (sends a test e-mail with the
//	                                         stored SMTP settings, which only an elevated admin can change;
//	                                         422 bad address, 503 carries the SMTP error)
//	GET    /admin/network                    Cap(network.manage) → core.NetworkOverview (interfaces, URLs,
//	                                         policy, tailscale, client_ip)
//	PUT    /admin/network/policy             Cap(network.manage), E; core.PolicyInput → core.PolicyResult
//	                                         (lockout guard: 409)
//	GET    /admin/mdns                       Cap(network.manage) → core.MDNSStatus
//	POST   /admin/mdns/republish             Cap(network.manage) → core.MDNSStatus (409 when publishing is
//	                                         not running)
//	GET    /network/urls                     (F) → []core.AccessURL
//	GET    /qr.svg?data=<1..512 bytes>       (F) image/svg+xml (qr.SVG) under the user-content CSP
//
// Per-key permission check (caps.go): which keys a caller may change is
// decided by their permissions — settings.manage the sections general,
// storage and sharing, network.manage network, mdns and funnel,
// certs.manage tls, acme, tailscale and mtls, system.manage the keys
// maintenance.*, log.* and runtime.*; everything else is for built-in
// owners and admins. It runs before the managed-key, elevation, lockout and
// passkey checks (hooks.go).
//
// Lockout guard: every change of the access policy — PUT /admin/network/policy
// and PATCH/DELETE of network.access_mode, network.allow_cidrs or
// network.deny_cidrs — is refused with 409 conflict when the resulting policy
// would no longer admit the requester (the resolved client IP and, behind a
// trusted reverse proxy, the proxy's own address, which is what the listener
// checks), unless force is set (PolicyInput.Force, or ?force=1 on the
// settings routes). In-process callers (admin socket, offline CLI) appear as
// loopback, which is always allowed.
//
// Passkey guard: PATCH/DELETE that turn auth.passkeys off or move the
// configured passkey domain (auth.webauthn_rp_id, or while that is empty
// mdns.name / server.name) are refused with 409 conflict naming the key while
// accounts exist whose only second factor is a passkey, unless ?force=1 —
// for every caller, the admin socket included.
//
// Every handler reads its services from the *app.Deps given to Mount and
// answers 503 unavailable when one is missing.
package settingsapi

import (
	"log/slog"
	"net/http"
	"net/netip"
	"slices"
	"strconv"

	"github.com/go-chi/chi/v5"

	"fileparcel/internal/app"
	"fileparcel/internal/core"
	"fileparcel/internal/web/httpx"
	"fileparcel/internal/web/mw"
)

// maxSettingsBody bounds PATCH /admin/settings and PUT /admin/network/policy.
const maxSettingsBody = 256 << 10

// SensitiveSections are the settings sections whose changes need an open
// step-up window (DESIGN §9.3): auth, network, tls, acme, mtls, keys, backup;
// "server" (listen addresses and ports, the public URL used for links and
// WebAuthn, and the trusted reverse proxies that decide client IPs); "mdns"
// (mdns.name is a certificate name and, like server.name, the default
// passkey domain); "email" (the SMTP relay the stored smtp.password is sent
// to, and which security notifications go out); "tailscale" (the publicly
// trusted certificate FileParcel serves); and "funnel" (how tailscaled
// reaches FileParcel for Tailscale Funnel and Serve).
var SensitiveSections = []string{"auth", "network", "tls", "acme", "mtls", "keys", "backup", "server", "mdns", "email", "tailscale", "funnel"}

// Sensitive reports whether changing a setting of section needs elevation.
func Sensitive(section string) bool { return slices.Contains(SensitiveSections, section) }

// Access-policy setting keys (registered by netinfo).
const (
	keyAccessMode = "network.access_mode"
	keyAllowCIDRs = "network.allow_cidrs"
	keyDenyCIDRs  = "network.deny_cidrs"
)

// Passkey setting keys (registered by auth, mdns and settings); see
// passkeyGuard: the WebAuthn switch and the settings that decide the RP ID.
const (
	keyPasskeys   = "auth.passkeys"
	keyRPID       = "auth.webauthn_rp_id"
	keyMDNSName   = "mdns.name"
	keyServerName = "server.name"
)

// api bundles the handlers.
type api struct{ d *app.Deps }

// Mount registers this package's routes on the /api/v1 router.
func Mount(r chi.Router, d *app.Deps) {
	a := &api{d: d}
	r.Group(func(r chi.Router) {
		r.Use(mw.RequireCap(settingsRouteCaps...))
		r.Get("/admin/settings", a.listSettings)
		r.With(mw.MaxBody(maxSettingsBody)).Patch("/admin/settings", a.patchSettings)
		r.Delete("/admin/settings/{key}", a.resetSetting)
	})
	r.Group(func(r chi.Router) {
		r.Use(mw.RequireAdmin)
		r.With(mw.MaxBody(maxSettingsBody)).Post("/admin/settings/email/test", a.testEmail)
	})
	r.Group(func(r chi.Router) {
		r.Use(mw.RequireCap(core.CapNetworkManage))
		r.Get("/admin/network", a.networkOverview)
		r.With(mw.RequireElevated, mw.MaxBody(maxSettingsBody)).Put("/admin/network/policy", a.putPolicy)
		r.Get("/admin/mdns", a.mdnsStatus)
		r.Post("/admin/mdns/republish", a.mdnsRepublish)
	})
	r.Group(func(r chi.Router) {
		r.Use(mw.RequireFull)
		r.Get("/network/urls", a.networkURLs)
		r.Get("/qr.svg", a.qrSVG)
	})
	a.mountTailscale(r)
}

// ---------- helpers ----------

// unavailable answers 503 for a missing service.
func unavailable(w http.ResponseWriter, r *http.Request, what string) {
	httpx.Error(w, r, core.Errorf(core.ErrUnavailable, "%s is not available", what))
}

func (a *api) settings(w http.ResponseWriter, r *http.Request) core.Settings {
	if a.d == nil || a.d.Env == nil || a.d.Settings == nil {
		unavailable(w, r, "the settings store")
		return nil
	}
	return a.d.Settings
}

func (a *api) network(w http.ResponseWriter, r *http.Request) core.Network {
	if a.d == nil || a.d.Network == nil {
		unavailable(w, r, "network information")
		return nil
	}
	return a.d.Network
}

func (a *api) notify(w http.ResponseWriter, r *http.Request) core.Notify {
	if a.d == nil || a.d.Notify == nil {
		unavailable(w, r, "e-mail notifications")
		return nil
	}
	return a.d.Notify
}

func (a *api) mdns(w http.ResponseWriter, r *http.Request) core.MDNS {
	if a.d == nil || a.d.MDNS == nil {
		unavailable(w, r, "mDNS publishing")
		return nil
	}
	return a.d.MDNS
}

// elevated reports whether the requester's step-up window is open.
func (a *api) elevated(r *http.Request) bool {
	p := mw.Principal(r)
	if p == nil {
		return false
	}
	return p.Elevated(a.d.Env.Now())
}

// forced reports whether ?force=1|true was given.
func forced(r *http.Request) bool {
	v := r.URL.Query().Get("force")
	if v == "" {
		return false
	}
	b, err := strconv.ParseBool(v)
	return err == nil && b
}

// requesterAddrs are the addresses the access policy must keep admitting for
// the requester: the resolved client IP and the direct peer (a trusted
// reverse proxy, whose address is what the listener's allowlist checks).
func requesterAddrs(r *http.Request) []netip.Addr {
	var out []netip.Addr
	for _, a := range []netip.Addr{mw.ClientIP(r), httpx.RemoteIP(r)} {
		if !a.IsValid() {
			continue
		}
		a = a.Unmap().WithZone("")
		if !slices.Contains(out, a) {
			out = append(out, a)
		}
	}
	return out
}

// logger returns the service logger (slog.Default without an environment).
func (a *api) logger() *slog.Logger {
	if a.d != nil && a.d.Env != nil && a.d.Log != nil {
		return a.d.Log
	}
	return slog.Default()
}
