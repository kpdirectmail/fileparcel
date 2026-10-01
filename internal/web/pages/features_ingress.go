package pages

import (
	"net/http"

	"fileparcel/internal/app"
	"fileparcel/internal/core"
)

// Tailscale Funnel/Serve (DESIGN §10.6).

// ingressFeatures adds the ingress flags to f:
//   - internet_links: share links are reachable from the internet (Funnel
//     is active in "shares" or "app" mode; links then carry its address);
//     the share dialog says so under a new link;
//   - funnel_2fa: over Funnel only accounts with a second factor can sign
//     in (funnel.mode = app and funnel.require_2fa); the login page says so
//     when it was opened over Funnel (boot ingress = "funnel").
func ingressFeatures(d *app.Deps, p *core.Principal, f map[string]bool) {
	f["internet_links"] = hasEnv(d) && d.Ingress != nil && d.Ingress.InternetLinks()
	f["funnel_2fa"] = enumSetting(d, "funnel.mode", core.FunnelOff, core.FunnelOff, core.FunnelShares, core.FunnelApp) ==
		core.FunnelApp && boolSetting(d, "funnel.require_2fa", true)
}

// publicOnly reports whether the page r asks for goes to an internet visitor
// over Tailscale Funnel "shares" mode (PageData.PublicOnly; every page
// rendered through NewPageData, the share page and the error pages alike):
// nothing but share links is reachable there, so the page must not lead
// into the app. Fail closed: a Funnel request counts as public unless the
// Funnel policy is "app".
func publicOnly(d *app.Deps, r *http.Request) bool {
	in := core.IngressFrom(r.Context())
	if in == nil || in.Kind != core.IngressFunnel {
		return false
	}
	return !hasEnv(d) || d.Ingress == nil || d.Ingress.Policy(core.IngressFunnel).Mode != core.FunnelApp
}
