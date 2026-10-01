package settingsapi

import (
	"slices"
	"strings"

	"fileparcel/internal/core"
)

// The permission each setting needs (DESIGN §6a.3). GET /admin/settings
// lists, and PATCH/DELETE change, only the keys the caller may change
// (mayChange): built-in owners and admins every key, a delegate the keys of
// the sections its permissions open. Everything equivalent to full control
// stays with administrators: sign-in and rate limits (auth, ratelimit), the
// audit retention, the SMTP relay that carries invitation links (email),
// where backups go (backup), the master key (keys) and the listener, public
// URL and trusted proxies (server) — and any section not listed here (fail
// closed; TestSettingsSectionsHaveCap names new ones). Sensitive sections
// still need step-up for everyone (checkElevation).

// keyPrefixCaps win over sectionCaps: maintenance mode (section general) and
// the log level and runtime limits (section server) belong to operating the
// server.
var keyPrefixCaps = []struct {
	prefix string
	cap    core.Capability
}{
	{"maintenance.", core.CapSystemManage},
	{"log.", core.CapSystemManage},
	{"runtime.", core.CapSystemManage},
}

// sectionCaps maps the settings sections a delegate may change to the
// permission they need ("funnel" is the Tailscale Funnel/Serve section).
var sectionCaps = map[string]core.Capability{
	"general": core.CapSettingsManage, "storage": core.CapSettingsManage, "sharing": core.CapSettingsManage,
	"network": core.CapNetworkManage, "mdns": core.CapNetworkManage, "funnel": core.CapNetworkManage,
	"tls": core.CapCertsManage, "acme": core.CapCertsManage, "tailscale": core.CapCertsManage, "mtls": core.CapCertsManage,
}

// adminOnlySections are never delegable (DESIGN §6a.3).
var adminOnlySections = []string{"auth", "ratelimit", "audit", "email", "backup", "keys", "server"}

// settingsRouteCaps are the permissions that open the settings routes
// (mw.RequireCap: any of them); the keys are then checked one by one.
var settingsRouteCaps = []core.Capability{core.CapSettingsManage, core.CapNetworkManage, core.CapCertsManage,
	core.CapSystemManage}

// SectionPermission reports how the settings section is delegated: the
// permission that opens it (c != "") or c == "" for an administrators-only
// section; listed is false for a section this table does not know, which is
// administrators-only by default (fail closed; internal/wire
// TestSettingsSectionsHaveCap fails until it is listed). Single keys of a
// section may need another permission (keyPrefixCaps).
func SectionPermission(section string) (c core.Capability, listed bool) {
	if c, ok := sectionCaps[section]; ok {
		return c, true
	}
	return "", slices.Contains(adminOnlySections, section)
}

// settingCap returns the permission that changes key (in section); ok=false
// means administrators only.
func settingCap(key, section string) (c core.Capability, ok bool) {
	for _, kp := range keyPrefixCaps {
		if strings.HasPrefix(key, kp.prefix) {
			return kp.cap, true
		}
	}
	c, ok = sectionCaps[section]
	return c, ok
}

// mayChange reports whether p may see and change key: a built-in
// owner/admin (or the system principal) holding the admin scope, or a holder
// of settingCap(key, section) (Principal.Can: tokens need the admin scope).
func mayChange(p *core.Principal, key, section string) bool {
	if p.IsAdmin() && p.HasScope(core.ScopeAdmin) {
		return true
	}
	c, ok := settingCap(key, section)
	return ok && p.Can(c)
}

// capGuard refuses (403, field = the key) a change of v that p may not make.
func capGuard(p *core.Principal, v core.SettingView) error {
	if mayChange(p, v.Key, v.Section) {
		return nil
	}
	msg := "only administrators can change " + v.Key
	if c, ok := settingCap(v.Key, v.Section); ok {
		msg = "changing " + v.Key + " needs the “" + c.Label() + "” permission"
	}
	return &core.Error{Code: core.ErrForbidden.Code, Status: core.ErrForbidden.Status, Message: msg, Field: v.Key}
}

// capVisible reports whether p may see v in GET /admin/settings.
func capVisible(p *core.Principal, v core.SettingView) bool { return mayChange(p, v.Key, v.Section) }
