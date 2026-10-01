package settingsapi

import (
	"encoding/json"
	"net/http"

	"fileparcel/internal/core"
	"fileparcel/internal/web/mw"
)

// Extension hooks of the settings routes (v4). Every feature adds its per-key
// rules in its own file: caps.go (the permission a key needs; roles),
// managed.go (keys owned by another route; Tailscale Funnel/Serve).

// checkKeys runs the per-key checks of PATCH/DELETE /admin/settings for every
// known key (unknown keys: the store answers 422), before checkElevation:
// capGuard (caps.go, 403) for every key first, then managedGuard (managed.go,
// 409) for every key. A request that touches a key the caller may not change
// is therefore refused with 403 even when another of its keys is managed.
func (a *api) checkKeys(r *http.Request, views map[string]core.SettingView, keys []string) error {
	p := mw.Principal(r)
	return runKeyChecks(views, keys,
		func(v core.SettingView) error { return capGuard(p, v) },
		managedGuard)
}

// runKeyChecks applies each check, in order, to every key of keys that is in
// views; the first error wins.
func runKeyChecks(views map[string]core.SettingView, keys []string, checks ...func(core.SettingView) error) error {
	for _, check := range checks {
		for _, k := range keys {
			v, ok := views[k]
			if !ok {
				continue
			}
			if err := check(v); err != nil {
				return err
			}
		}
	}
	return nil
}

// listable reports whether GET /admin/settings shows v to the caller (capVisible, caps.go).
func listable(p *core.Principal, v core.SettingView) bool { return capVisible(p, v) }

// extraWarnings are appended to the PATCH /admin/settings warnings (ingressWarnings, managed.go).
func (a *api) extraWarnings(changes map[string]json.RawMessage) []string {
	return a.ingressWarnings(changes)
}
