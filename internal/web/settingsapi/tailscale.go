package settingsapi

import (
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"

	"fileparcel/internal/core"
	"fileparcel/internal/web/httpx"
	"fileparcel/internal/web/mw"
)

// Tailscale Funnel and Serve (DESIGN §9.4, §10.6). Routes under /api/v1:
//
//	GET  /admin/network/tailscale[?refresh=1]  Cap(network.manage) → core.IngressStatus (a cached read of
//	                                           tailscaled, at most 30 s old; refresh=1 reads it again, asks
//	                                           tailscaled where Funnel can be enabled and re-runs the self-probe)
//	PUT  /admin/network/funnel                 Cap(network.manage), E  core.FunnelInput → core.IngressStatus
//	PUT  /admin/network/serve                  Cap(network.manage), E  core.ServeInput → core.IngressStatus
//	POST /admin/network/tailscale/reapply      Cap(network.manage), E  → core.IngressStatus (writes FileParcel's
//	                                           own entries again: fixes drift)
//
// The write routes answer 422 invalid (field mode, port, allow_admin or
// confirm: widening what the internet reaches needs confirm="public"), 403
// forbidden (turning require_2fa off or allow_admin on needs a built-in
// owner or administrator, whatever network.manage allows), 412
// precondition_failed (field = the failing check ID, message = its message
// and hint), 409 conflict (field port: a foreign serve entry holds it) and
// 503 unavailable (tailscaled does not answer). The service decides all of
// them (core.Ingress); these handlers only decode and delegate. While the
// server is stopped (the offline CLI) an enable is stored and answers state
// "stopped": tailscaled is changed when the server starts.
//
// The funnel.* settings the service stores are managed by these routes:
// PATCH and DELETE /admin/settings refuse them (managed.go).

// mountTailscale registers the Tailscale Funnel/Serve routes.
func (a *api) mountTailscale(r chi.Router) {
	r.Group(func(r chi.Router) {
		r.Use(mw.RequireCap(core.CapNetworkManage), mw.NoStore)
		r.Get("/admin/network/tailscale", a.tailscaleStatus)
		r.Group(func(r chi.Router) {
			r.Use(mw.RequireElevated, mw.MaxBody(maxSettingsBody))
			r.Put("/admin/network/funnel", a.putFunnel)
			r.Put("/admin/network/serve", a.putServe)
			r.Post("/admin/network/tailscale/reapply", a.reapplyTailscale)
		})
	})
}

// ingress returns the Funnel/Serve service (503 when it is not wired).
func (a *api) ingress(w http.ResponseWriter, r *http.Request) core.Ingress {
	if a.d == nil || a.d.Ingress == nil {
		unavailable(w, r, "Tailscale Funnel and Serve")
		return nil
	}
	return a.d.Ingress
}

// tailscaleStatus is GET /admin/network/tailscale[?refresh=1].
func (a *api) tailscaleStatus(w http.ResponseWriter, r *http.Request) {
	in := a.ingress(w, r)
	if in == nil {
		return
	}
	refresh, _ := strconv.ParseBool(r.URL.Query().Get("refresh"))
	st, err := in.Status(r.Context(), refresh)
	if err != nil {
		httpx.Error(w, r, err)
		return
	}
	httpx.OK(w, st)
}

// putFunnel is PUT /admin/network/funnel (E).
func (a *api) putFunnel(w http.ResponseWriter, r *http.Request) {
	in := a.ingress(w, r)
	if in == nil {
		return
	}
	body, err := httpx.Decode[core.FunnelInput](r, maxSettingsBody)
	if err != nil {
		httpx.Error(w, r, err)
		return
	}
	st, err := in.SetFunnel(r.Context(), mw.Principal(r), body)
	if err != nil {
		httpx.Error(w, r, err)
		return
	}
	httpx.OK(w, st)
}

// putServe is PUT /admin/network/serve (E).
func (a *api) putServe(w http.ResponseWriter, r *http.Request) {
	in := a.ingress(w, r)
	if in == nil {
		return
	}
	body, err := httpx.Decode[core.ServeInput](r, maxSettingsBody)
	if err != nil {
		httpx.Error(w, r, err)
		return
	}
	st, err := in.SetServe(r.Context(), mw.Principal(r), body)
	if err != nil {
		httpx.Error(w, r, err)
		return
	}
	httpx.OK(w, st)
}

// reapplyTailscale is POST /admin/network/tailscale/reapply (E).
func (a *api) reapplyTailscale(w http.ResponseWriter, r *http.Request) {
	in := a.ingress(w, r)
	if in == nil {
		return
	}
	st, err := in.Reapply(r.Context(), mw.Principal(r))
	if err != nil {
		httpx.Error(w, r, err)
		return
	}
	httpx.OK(w, st)
}
