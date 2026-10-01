package pages

import (
	"fileparcel/internal/app"
	"fileparcel/internal/core"
)

// Features is the feature-flag map of the page boot (Boot.Features) and of
// GET /me (core.Me.Features); the client merges both, /me winning, so both
// come from here. p is nil on anonymous pages. Each feature adds its flags in
// its own file: baseFeatures (this file), zipFeatures (features_zip.go),
// ingressFeatures (features_ingress.go), maintenanceFeatures
// (features_maintenance.go).
func Features(d *app.Deps, p *core.Principal) map[string]bool {
	f := baseFeatures(d, p)
	zipFeatures(d, f)
	ingressFeatures(d, p, f)
	maintenanceFeatures(d, f)
	return f
}

// baseFeatures are the flags of v3 plus the permission flags (DESIGN §6a):
// links and requests need the server switch and the permission shares.Create
// checks (shares.links, shares.requests — the built-in Guest holds them only
// while sharing.allow_guests_share is on, which auth folds into the
// principal); directory is the user and role directory of the share and
// grant pickers (users.lookup or users.view); tokens is tokens.create. The
// permission flags are false for anonymous visitors and while the second
// factor is pending (AuthLevel 1), so they reveal nothing about the role
// before it; the setting-only flags are the same for everyone.
func baseFeatures(d *app.Deps, p *core.Principal) map[string]bool {
	var u *core.Principal // the principal the permission flags describe (nil: none)
	if p != nil && p.AuthLevel >= core.AuthLevelFull {
		u = p
	}
	return map[string]bool{
		"passkeys":          boolSetting(d, "auth.passkeys", true),
		"links":             boolSetting(d, "sharing.links_enabled", true) && u.Can(core.CapShareLinks),
		"requests":          boolSetting(d, "sharing.requests_enabled", true) && u.Can(core.CapShareRequests),
		"directory":         u.CanAny(core.CapUsersLookup, core.CapUsersView),
		"tokens":            u.Can(core.CapTokensCreate),
		"thumbnails":        boolSetting(d, "storage.thumbnails", true),
		"mtls_self_service": boolSetting(d, "mtls.self_service", false),
		// The share and file-request dialogs pre-tick and lock "Require a
		// password" from this, instead of letting the user submit a link the
		// server is bound to reject with 422.
		"share_password_required": boolSetting(d, "sharing.require_password", false),
	}
}
