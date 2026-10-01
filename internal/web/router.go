// Package web assembles the HTTP handler (DESIGN §9.1). Frozen after
// foundation: route modules register themselves through their Mount /
// MountRoot functions, which this file calls.
package web

import (
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"

	"fileparcel/internal/app"
	"fileparcel/internal/core"
	"fileparcel/internal/web/authapi"
	"fileparcel/internal/web/filesapi"
	"fileparcel/internal/web/httpx"
	"fileparcel/internal/web/meapi"
	"fileparcel/internal/web/mw"
	"fileparcel/internal/web/opsapi"
	"fileparcel/internal/web/pages"
	"fileparcel/internal/web/securityapi"
	"fileparcel/internal/web/settingsapi"
	"fileparcel/internal/web/sharesapi"
	"fileparcel/internal/web/static"
	"fileparcel/internal/web/uploadapi"
	"fileparcel/internal/web/usersapi"
)

// NewRouter builds the root handler:
//
//	root: Inject → GetHead → RequestID → Recover → ResolveClientIP → AccessLog →
//	      ProxiedPolicy → HostCheck → SecurityHeaders → IngressGate →
//	      SealedGate → Maintenance
//	/api/v1: MaxBody(1 MiB) → RateLimit("api", per IP) → Authenticate → CSRF
//	         → per-route guards (in the modules)
//
// Module order: authapi, meapi, usersapi, filesapi, uploadapi, sharesapi,
// securityapi, settingsapi, opsapi; then the root mounts of sharesapi and
// securityapi; pages and static last (SPA routes and the 404 page).
//
// HEAD: chi does not route HEAD to GET handlers by itself, so
// middleware.GetHead sends HEAD requests without an explicit HEAD route to
// the GET handler (net/http discards the body). GET handlers with side
// effects (download counters, single-use tickets, audit) must skip them for
// HEAD.
func NewRouter(d *app.Deps) http.Handler {
	r := chi.NewRouter()
	r.Use(
		mw.Inject(d),
		middleware.GetHead,
		mw.RequestID,
		mw.Recover,
		// ResolveClientIP before AccessLog: it hands the resolved address to
		// the inner handlers through a derived request, so a logger outside it
		// would only ever see the direct peer (the proxy).
		mw.ResolveClientIP,
		mw.AccessLog,
		// The access policy for clients behind a trusted proxy (the
		// listener only saw the proxy); after AccessLog so refusals are logged.
		mw.ProxiedPolicy,
		mw.HostCheck,
		mw.SecurityHeaders,
		// The Tailscale Funnel/Serve policy (requests of the ingress
		// listeners only); its answers carry the security headers.
		mw.IngressGate(http.HandlerFunc(pages.NotFound), pages.RenderError),
		mw.SealedGate,
		mw.Maintenance(http.HandlerFunc(pages.MaintenanceNotice)),
	)

	// The API sub-router. Its middleware chain is attached at the mount point
	// (r.With(...).Mount) so it also runs for unmatched /api/v1 paths even
	// while no module has registered a route yet.
	api := chi.NewRouter()
	api.NotFound(func(w http.ResponseWriter, r *http.Request) {
		httpx.Error(w, r, core.NotFoundf("no such API endpoint"))
	})
	api.MethodNotAllowed(func(w http.ResponseWriter, r *http.Request) {
		httpx.Error(w, r, &core.Error{Code: "method_not_allowed", Status: http.StatusMethodNotAllowed, Message: "method not allowed"})
	})
	authapi.Mount(api, d)
	meapi.Mount(api, d)
	usersapi.Mount(api, d)
	filesapi.Mount(api, d)
	uploadapi.Mount(api, d)
	sharesapi.Mount(api, d)
	securityapi.Mount(api, d)
	settingsapi.Mount(api, d)
	opsapi.Mount(api, d)
	r.With(
		mw.MaxBody(httpx.DefaultMaxBody),
		mw.RateLimit(mw.BucketAPI, mw.PerIP),
		mw.Authenticate,
		mw.CSRF,
	).Mount("/api/v1", api)

	sharesapi.MountRoot(r, d)
	securityapi.MountRoot(r, d)
	pages.MountRoot(r, d)
	static.MountRoot(r, d)
	return r
}
