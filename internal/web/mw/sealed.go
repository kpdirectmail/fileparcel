package mw

import (
	"net/http"
	"strings"

	"fileparcel/internal/core"
	"fileparcel/internal/web/httpx"
)

// sealedExact lists the paths that work while the master key is locked
// (DESIGN §7.2): the unlock and trust pages, health checks, the public
// system status/unlock API, the public auth state (instance name for the
// unlock page) and the small static root files the unlock page loads.
var sealedExact = map[string]bool{
	"/unlock": true, "/trust": true, "/healthz": true, "/readyz": true,
	"/robots.txt": true, "/favicon.ico": true, "/sw.js": true, "/manifest.webmanifest": true,
	"/theme.css": true, "/.well-known/security.txt": true,
	"/api/v1/system/status": true, "/api/v1/system/unlock": true, "/api/v1/auth/state": true,
}

// SealedAllowed reports whether path is reachable while the keys are locked.
func SealedAllowed(path string) bool {
	return sealedExact[path] || strings.HasPrefix(path, "/static/") || strings.HasPrefix(path, "/trust/")
}

// SealedGate blocks everything but the allow-listed paths (SealedAllowed)
// while the master key is locked: API requests (isAPIPath, which includes the
// public share JSON routes /s/{token}/api…) and unsafe methods get 503
// keys_locked, page navigations a 303 redirect to /unlock (with ?next= so the
// user returns after unlocking). Trusted in-process callers (admin socket,
// offline CLI) pass: the services themselves report ErrKeysLocked, and
// `fileparcel status` / `keys status` must keep working.
//
// A request over Tailscale Funnel is never sent to /unlock (the unlock page
// is not reachable over Funnel, and nobody unlocks a server from the
// internet): it gets the 503. IngressGate, which runs just before this gate,
// already answers those with the generic "temporarily unavailable" page;
// the rule here keeps the redirect out even without it.
func SealedGate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		d := Deps(r)
		if !hasEnv(d) || d.Keys == nil || d.Keys.State() != core.KeyStateLocked ||
			SealedAllowed(r.URL.Path) || trusted(r) {
			next.ServeHTTP(w, r)
			return
		}
		if isAPIPath(r.URL.Path) || (r.Method != http.MethodGet && r.Method != http.MethodHead) || overFunnel(r) {
			w.Header().Set("Retry-After", "30")
			httpx.Error(w, r, core.ErrKeysLocked)
			return
		}
		target := "/unlock"
		if r.URL.Path != "/" && !strings.HasPrefix(r.URL.Path, "/s/") {
			target += "?next=" + urlQueryEscape(r.URL.RequestURI())
		}
		http.Redirect(w, r, target, http.StatusSeeOther)
	})
}
