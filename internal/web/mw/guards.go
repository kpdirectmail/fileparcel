package mw

import (
	"fmt"
	"net/http"
	"slices"
	"strings"
	"time"

	"fileparcel/internal/core"
	"fileparcel/internal/web/httpx"
)

// RequireAuth requires an authenticated principal ("A" in DESIGN §9.4):
// 401 unauthorized when anonymous. A principal whose second factor is still
// pending (AuthLevel 1: password verified, TOTP/passkey not yet) is admitted
// only to the MFA-pending routes (mfaPendingAllowed: /auth/*, GET /me,
// GET /me/mfa); elsewhere it gets 401 mfa_required. So RequireAuth is right
// for /auth/logout, /auth/totp, /auth/recovery, /auth/passkey/finish,
// /auth/elevate, GET /me and GET /me/mfa.
//
// Everything else — including the enrollment routes POST
// /me/totp/{begin,confirm} and POST /me/passkeys/{begin,finish} — must use
// RequireFull: it lets users with a pending 2FA *enrollment* (AuthLevel 2 +
// EnrollRequired) through to /me*, but never a password-only session of a
// user who already has 2FA (that would let a stolen password register a new
// authenticator). The enrollment routes add RequireElevated (a new factor
// satisfies step-up, so a hijacked session must not add one); enrolling
// users elevate with the password.
func RequireAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := Principal(r)
		switch {
		case p == nil:
			httpx.Error(w, r, core.ErrUnauthorized)
			return
		case p.AuthLevel < core.AuthLevelFull && !mfaPendingAllowed(r):
			httpx.Error(w, r, core.ErrMFARequired)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// apiPath returns the request path relative to /api/v1.
func apiPath(r *http.Request) string { return strings.TrimPrefix(r.URL.Path, "/api/v1") }

// mfaPendingAllowed lists the routes usable at AuthLevel 1.
func mfaPendingAllowed(r *http.Request) bool {
	p := apiPath(r)
	if strings.HasPrefix(p, "/auth/") {
		return true
	}
	return (r.Method == http.MethodGet || r.Method == http.MethodHead) && (p == "/me" || p == "/me/mfa")
}

// enrollAllowed lists the routes usable while 2FA enrollment is pending
// (DESIGN §9.3: "/me*, /auth/logout and the enrollment routes") and while
// the password must be changed first: /me and everything under /me/, except
// minting long-lived credentials — POST /me/tokens and POST /me/client-certs
// — which would sidestep the 2FA policy or outlive the password the user
// has to replace (deliberate narrowing of §9.3).
func enrollAllowed(r *http.Request) bool {
	p := apiPath(r)
	switch {
	case p == "/auth/logout":
		return true
	case (p == "/me/tokens" || p == "/me/client-certs") && r.Method == http.MethodPost:
		return false
	}
	return p == "/me" || strings.HasPrefix(p, "/me/")
}

func checkFull(w http.ResponseWriter, r *http.Request) bool {
	p := Principal(r)
	switch {
	case p == nil:
		httpx.Error(w, r, core.ErrUnauthorized)
		return false
	case p.AuthLevel < core.AuthLevelFull:
		httpx.Error(w, r, core.ErrMFARequired)
		return false
	case p.EnrollRequired && (p.Via == core.ViaToken || !enrollAllowed(r)):
		// A token cannot enrol (the enrollment routes refuse tokens), so it
		// is refused everywhere until its owner has enrolled in the web UI.
		httpx.Error(w, r, core.ErrEnrollRequired)
		return false
	case p.MustChangePassword && !enrollAllowed(r):
		httpx.Error(w, r, core.ErrPasswordChangeRequired)
		return false
	}
	return true
}

// RequireFull requires complete authentication ("F" in DESIGN §9.4): 401
// unauthorized when anonymous, 401 mfa_required at AuthLevel 1, 403
// mfa_enroll_required while 2FA enrollment is pending — except on /me* and
// /auth/logout (see enrollAllowed) for sessions, so the enrollment routes use
// RequireFull; tokens get it everywhere — and 403 password_change_required
// for a session whose password must be changed first, on the same routes.
func RequireFull(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if checkFull(w, r) {
			next.ServeHTTP(w, r)
		}
	})
}

// RequireAdmin is RequireFull + role owner/admin/system (+ scope "admin" for
// tokens): 403 forbidden otherwise.
func RequireAdmin(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !checkFull(w, r) {
			return
		}
		p := Principal(r)
		if !p.IsAdmin() || !p.HasScope(core.ScopeAdmin) {
			httpx.Error(w, r, core.ErrForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// RequireCap is RequireFull + at least one of caps (Principal.CanAny; owners,
// admins and the system principal always pass; API tokens need the admin
// scope for server permissions). 403 forbidden otherwise, with the message
// `token lacks scope "admin"` when the account holds one of caps but the
// token lacks the admin scope (the CLI's hint keys on "admin"), else
// `this needs the “<Label>” permission` (the label of the first cap).
// Constructing it without capabilities or with an unknown one panics (a
// programming error that would otherwise lock the route for everyone).
func RequireCap(caps ...core.Capability) Middleware {
	if len(caps) == 0 {
		panic("mw.RequireCap: no capability given")
	}
	for _, c := range caps {
		if !c.Valid() {
			panic(fmt.Sprintf("mw.RequireCap: unknown capability %q", string(c)))
		}
	}
	need := core.Errorf(core.ErrForbidden, "this needs the “%s” permission", caps[0].Label())
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !checkFull(w, r) {
				return
			}
			p := Principal(r)
			if p.CanAny(caps...) {
				next.ServeHTTP(w, r)
				return
			}
			if !p.HasScope(core.ScopeAdmin) {
				held := p.RoleCaps()
				for _, c := range caps {
					if held.Has(c) {
						httpx.Error(w, r, core.Errorf(core.ErrForbidden, "token lacks scope %q", core.ScopeAdmin))
						return
					}
				}
			}
			httpx.Error(w, r, need)
		})
	}
}

// RequireRole is RequireFull + one of roles (the system principal always passes).
func RequireRole(roles ...core.Role) Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !checkFull(w, r) {
				return
			}
			p := Principal(r)
			if !p.IsSystem() && !slices.Contains(roles, p.Role) {
				httpx.Error(w, r, core.ErrForbidden)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// RequireElevated requires an open step-up window (DESIGN §9.3): 401 when
// anonymous or MFA is pending, 403 elevation_required when the window is
// closed. Use it on top of RequireFull/RequireAdmin. The system principal is
// always elevated; token principals only when created --elevated (Auth sets
// ElevatedUntil).
func RequireElevated(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := Principal(r)
		switch {
		case p == nil:
			httpx.Error(w, r, core.ErrUnauthorized)
			return
		case p.AuthLevel < core.AuthLevelFull:
			httpx.Error(w, r, core.ErrMFARequired)
			return
		}
		now := time.Now()
		if d := Deps(r); hasEnv(d) {
			now = d.Now()
		}
		if !p.Elevated(now) {
			httpx.Error(w, r, core.ErrElevationRequired)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// RequireScope requires token scope s (non-token principals have every scope).
func RequireScope(s string) Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			p := Principal(r)
			if p == nil {
				httpx.Error(w, r, core.ErrUnauthorized)
				return
			}
			if !p.HasScope(s) {
				httpx.Error(w, r, core.Errorf(core.ErrForbidden, "token lacks scope %q", s))
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// SocketOnly restricts a route to the admin socket and the in-process CLI.
func SocketOnly(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !trusted(r) {
			httpx.Error(w, r, core.Errorf(core.ErrForbidden, "only available through the local admin socket"))
			return
		}
		next.ServeHTTP(w, r)
	})
}
