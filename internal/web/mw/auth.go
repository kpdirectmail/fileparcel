package mw

import (
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"sync"
	"time"

	"fileparcel/internal/app"
	"fileparcel/internal/core"
	"fileparcel/internal/web/httpx"
)

// actAsWindow is how long an X-FP-As principal counts as elevated (it is
// created per request; the window only has to cover the request).
const actAsWindow = time.Hour

// Authenticate resolves the principal (session cookie or Bearer token) with
// d.Auth.Authenticate and stores it in the context. Anonymous requests pass
// through (routes decide with RequireAuth). An invalid Bearer token is an
// error (401 with WWW-Authenticate); a stale cookie is treated as anonymous
// by Auth.
//
// Trusted in-process principals (see package doc) are kept; for them — and
// only for them — the X-FP-As header switches to that user (full auth level,
// elevated, same channel). Network requests carrying X-FP-As are
// authenticated normally and the header is ignored.
func Authenticate(next http.Handler) http.Handler {
	return authenticate(next, false)
}

// AuthenticateOptional is Authenticate for HTML pages: authentication errors
// never fail the request (the visitor is simply anonymous).
func AuthenticateOptional(next http.Handler) http.Handler {
	return authenticate(next, true)
}

func authenticate(next http.Handler, lenient bool) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		d := Deps(r)
		ctx := r.Context()
		p := core.PrincipalFrom(ctx)
		if p != nil {
			// Only in-process code can put a principal into the request
			// context (network requests cannot), so it is kept as is.
			p = p.Clone()
			if as := r.Header.Get(HeaderActAs); as != "" && (p.Via == core.ViaSocket || p.Via == core.ViaOffline) {
				ap, err := actAs(r, d, p, as)
				if err != nil {
					httpx.Error(w, r, err)
					return
				}
				p = ap
			}
		} else {
			if hasEnv(d) && d.Auth != nil {
				var err error
				p, err = d.Auth.Authenticate(r)
				if err != nil {
					if !lenient {
						if errors.Is(err, core.ErrUnauthorized) && r.Header.Get("Authorization") != "" {
							w.Header().Set("WWW-Authenticate", `Bearer realm="fileparcel"`)
						}
						httpx.Error(w, r, err)
						return
					}
					p = nil
				}
			}
		}
		if p != nil {
			if !p.IP.IsValid() || p.Via == core.ViaSession || p.Via == core.ViaToken {
				p.IP = ClientIP(r)
			}
			p.UserAgent = r.UserAgent()
			p.RequestID = httpx.RequestID(ctx)
			name := p.Username
			if name == "" {
				name = p.UserID
			}
			setLogUser(ctx, name, string(p.Via))
			ctx = core.WithPrincipal(ctx, p)
		}
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// actAs builds the principal for X-FP-As (trusted callers only): the role
// and capabilities of the account (core.User.Permissions, as a session of
// that user would carry them), full auth level, elevated for actAsWindow.
// Only an active account can be acted as: "disabled" means the identity
// cannot be used at all, the way auth.CreateToken and files.principalFor
// already refuse it.
func actAs(r *http.Request, d *app.Deps, sys *core.Principal, username string) (*core.Principal, error) {
	if !hasEnv(d) || d.Users == nil {
		return nil, core.Wrap(core.ErrUnavailable, "user lookup unavailable", nil)
	}
	u, err := d.Users.GetByUsername(r.Context(), username)
	if err != nil {
		if errors.Is(err, core.ErrNotFound) {
			return nil, core.Wrap(core.ErrNotFound, "user "+strconv.Quote(username)+" not found", err)
		}
		return nil, err
	}
	if u.Status != core.UserActive {
		return nil, core.Errorf(core.ErrForbidden, "the account %q is disabled", u.Username)
	}
	p := &core.Principal{
		UserID: u.ID, Username: u.Username, Role: u.Role, RoleID: u.RoleID, RoleName: u.RoleName, Via: sys.Via,
		AuthLevel: core.AuthLevelFull, ElevatedUntil: d.Now().Add(actAsWindow),
		IP: sys.IP,
	}
	p.SetCaps(u.Permissions)
	return p, nil
}

func isUnsafe(method string) bool {
	switch method {
	case http.MethodGet, http.MethodHead, http.MethodOptions, http.MethodTrace:
		return false
	}
	return true
}

// originGuard caches an http.CrossOriginProtection per server.public_url
// (whose origin is trusted in addition to same-origin requests, for
// deployments behind a reverse proxy that rewrites Host).
type originGuard struct {
	mu        sync.Mutex
	publicURL string
	cop       *http.CrossOriginProtection
}

var guard originGuard

func crossOriginProtection(d *app.Deps) *http.CrossOriginProtection {
	pub := ""
	if hasEnv(d) && d.Config != nil {
		pub = d.Config.Server.PublicURL
	}
	guard.mu.Lock()
	defer guard.mu.Unlock()
	if guard.cop != nil && guard.publicURL == pub {
		return guard.cop
	}
	cop := http.NewCrossOriginProtection()
	if u, err := url.Parse(pub); err == nil && (u.Scheme == "https" || u.Scheme == "http") && u.Host != "" {
		_ = cop.AddTrustedOrigin(u.Scheme + "://" + u.Host)
	}
	guard.cop, guard.publicURL = cop, pub
	return cop
}

// CSRF protects unsafe methods (DESIGN §9.3): http.CrossOriginProtection for
// every browser request, plus the X-FP-CSRF token (d.Auth.CheckCSRF) for
// cookie sessions. Bearer-token, socket and offline principals are exempt
// (they cannot be forged cross-site). Must run after Authenticate. A bad
// token answers 403 csrf_invalid (core.ErrCSRF, which the web client
// recovers from by re-reading the token), a cross-origin request 403
// forbidden.
func CSRF(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !isUnsafe(r.Method) {
			next.ServeHTTP(w, r)
			return
		}
		p := Principal(r)
		if p != nil && (p.Via == core.ViaToken || p.Via == core.ViaSocket || p.Via == core.ViaOffline) {
			next.ServeHTTP(w, r)
			return
		}
		d := Deps(r)
		if err := crossOriginProtection(d).Check(r); err != nil {
			httpx.Error(w, r, core.Wrap(core.ErrForbidden, "cross-origin request blocked", err))
			return
		}
		if p != nil && p.Via == core.ViaSession {
			if !hasEnv(d) || d.Auth == nil || !d.Auth.CheckCSRF(p, r.Header.Get(HeaderCSRF)) {
				httpx.Error(w, r, core.ErrCSRF)
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

// CrossOrigin applies only http.CrossOriginProtection to unsafe methods (for
// public share routes without sessions).
func CrossOrigin(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if isUnsafe(r.Method) {
			if err := crossOriginProtection(Deps(r)).Check(r); err != nil {
				httpx.Error(w, r, core.Wrap(core.ErrForbidden, "cross-origin request blocked", err))
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

func urlQueryEscape(s string) string { return url.QueryEscape(s) }
