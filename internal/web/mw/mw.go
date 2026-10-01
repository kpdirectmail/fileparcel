// Package mw holds the HTTP middleware (DESIGN §9.1–9.3). The root chain and
// the /api/v1 chain are assembled by web/router.go:
//
//	root:    Inject → GetHead → RequestID → Recover → ResolveClientIP → AccessLog →
//	         ProxiedPolicy → HostCheck → SecurityHeaders → IngressGate →
//	         SealedGate → Maintenance
//	/api/v1: MaxBody(1 MiB) → RateLimit(BucketAPI, PerIP) → Authenticate → CSRF
//	         → per-route guards
//
// Route modules use the per-route helpers (RequireAuth, RequireFull,
// RequireAdmin, RequireCap, RequireRole, RequireElevated, RequireScope,
// RateLimit, MaxBody, NoStore, SocketOnly, CrossOrigin, AuthenticateOptional)
// and the accessors Principal(r), ClientIP(r) and Deps(r). RequireCap(caps…)
// admits a principal holding at least one of the permissions (DESIGN §6a);
// RequireAdmin stays for the admin-only surfaces.
//
// Every middleware here is a plain func(http.Handler) http.Handler (or returns
// one) and reads the services from the request context, where Inject(d) (the
// first root middleware) stored them. Every middleware tolerates a nil Deps
// or nil services (it then does the safe minimum), so handlers can be unit
// tested without a full wire.Build.
//
// Trusted in-process principals: a request whose context already carries a
// core.Principal before Authenticate runs was created in-process (the admin
// Unix socket's ConnContext, or the CLI's in-process RoundTripper); network
// requests can never carry one. Such requests skip HostCheck, SealedGate,
// rate limiting and CSRF, Authenticate keeps their principal, and only they
// may send X-FP-As (act as that user).
//
// Tailscale ingress requests: a request that arrived through a Tailscale
// Funnel or Serve ingress listener carries core.IngressInfo in its context
// (set by package server, which validated tailscaled's proxy headers and
// made the real client the request's RemoteAddr). IngressGate (ingress.go)
// is the policy point for them; ResolveClientIP takes their client address
// as is, and HostCheck and ProxiedPolicy pass them.
//
// CheckSecurityHeaders (headers.go) is the header sweep used by tests of
// every web package.
package mw

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/netip"
	"runtime/debug"

	"fileparcel/internal/app"
	"fileparcel/internal/core"
	"fileparcel/internal/ids"
	"fileparcel/internal/web/httpx"
)

// Header names.
const (
	HeaderRequestID = "X-Request-ID"
	HeaderCSRF      = "X-FP-CSRF"
	// HeaderActAs lets trusted in-process callers (socket / offline CLI, flag
	// --as) act as a user: the value is a username.
	HeaderActAs = "X-FP-As"
)

// Rate-limit bucket names for RateLimit (same values as the ratelimit
// package's Bucket* constants; web packages must not import ratelimit).
// Unit B configures their rates in the ratelimit registry.
const (
	BucketAPI    = "api"    // /api/v1 chain, per IP (ratelimit.api_rps / api_burst)
	BucketLogin  = "login"  // login, TOTP, recovery, passkey finish, setup, invite accept (ratelimit.login_per_min)
	BucketShare  = "share"  // public /s/{token} routes (ratelimit.share_per_min)
	BucketUnlock = "unlock" // POST /system/unlock (ratelimit.unlock_per_min)
	// BucketLoginStart: passkey begin and invitation look-ups, which check no
	// credential (ratelimit.LoginStartFactor × ratelimit.login_per_min): the
	// sign-in page starts a passkey ceremony on every load (autofill), which
	// must not use up the allowance of real sign-in attempts.
	BucketLoginStart = "login_start"

	// Per-/64 aggregates of login, login_start, share and unlock (see RateLimit).
	BucketLoginNet      = "login_net"
	BucketLoginStartNet = "login_start_net"
	BucketShareNet      = "share_net"
	BucketUnlockNet     = "unlock_net"

	// Requests over Tailscale Funnel (IngressGate): per client (PerIP, an
	// IPv6 client per /64; ratelimit.funnel_per_min) and all clients
	// together (key "*"; ratelimit.funnel_global_per_min).
	BucketFunnel       = "funnel"
	BucketFunnelGlobal = "funnel_global"
)

// Middleware is the chi/stdlib middleware shape.
type Middleware = func(http.Handler) http.Handler

type depsKey struct{}

// Inject stores d in every request context; it must be the first root middleware.
func Inject(d *app.Deps) Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), depsKey{}, d)))
		})
	}
}

// Deps returns the services injected by Inject (nil outside the router).
func Deps(r *http.Request) *app.Deps {
	d, _ := r.Context().Value(depsKey{}).(*app.Deps)
	return d
}

// Principal returns the authenticated principal of r (nil = anonymous).
func Principal(r *http.Request) *core.Principal { return core.PrincipalFrom(r.Context()) }

// ClientIP returns the client IP (after trusted-proxy resolution).
func ClientIP(r *http.Request) netip.Addr { return httpx.ClientIP(r) }

// PerIP is a RateLimit key func: the client IP (per address, not per /64:
// on a home LAN or a tailnet every device shares one IPv6 /64). For the
// login, share and unlock buckets RateLimit adds a per-/64 aggregate for
// remote IPv6 clients (netKey), so rotating addresses within one /64 does
// not escape those limits. A request over Tailscale Funnel comes from the
// internet, where one client holds a whole /64: its key is the /64
// (core.IPLimitKey) in every bucket.
func PerIP(r *http.Request) string {
	in := core.IngressFrom(r.Context())
	return core.IPLimitKey(ClientIP(r), in != nil && in.Kind == core.IngressFunnel)
}

// PerUser is a RateLimit key func: the user id, or the client IP when anonymous.
func PerUser(r *http.Request) string {
	if p := Principal(r); p != nil && p.UserID != "" {
		return "u:" + p.UserID
	}
	return "ip:" + PerIP(r)
}

// trusted reports whether r carries a trusted in-process principal (admin
// socket or offline CLI). Only those contexts can contain a principal before
// Authenticate runs, and Authenticate keeps the channel, so the check is the
// same before and after it.
func trusted(r *http.Request) bool {
	p := Principal(r)
	return p != nil && (p.Via == core.ViaSocket || p.Via == core.ViaOffline)
}

// hasEnv reports whether d carries an environment.
func hasEnv(d *app.Deps) bool { return d != nil && d.Env != nil }

// ---------- root chain ----------

// RequestID assigns a request id (16 random bytes, base62), stores it in the
// context (httpx.RequestID) and echoes it in X-Request-ID. Client-supplied
// request ids are ignored (they would let clients forge log correlation).
func RequestID(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := ids.Token(16)
		w.Header().Set(HeaderRequestID, id)
		next.ServeHTTP(w, r.WithContext(httpx.WithRequestID(r.Context(), id)))
	})
}

// Recover turns panics into a 500 error response (http.ErrAbortHandler is
// re-panicked so net/http aborts the connection). The panic value and stack
// are logged (with the redacted httpx.LogPath), never sent to the client. If
// the handler already started the response, the status line is out and a
// clean end would pass a truncated body (a streamed archive, an audit
// export) off as complete: the connection / HTTP/2 stream is aborted instead
// (http.ErrAbortHandler, no final chunk / RST_STREAM), so the client sees a
// failed transfer.
func Recover(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tw := &trackWriter{ResponseWriter: w}
		defer func() {
			if v := recover(); v != nil {
				if v == http.ErrAbortHandler {
					panic(v)
				}
				logger(r).Error("panic", "panic", v, "method", r.Method, "path", httpx.LogPath(r.URL),
					"request_id", httpx.RequestID(r.Context()), "stack", string(debug.Stack()))
				if tw.wrote {
					panic(http.ErrAbortHandler)
				}
				httpx.Error(w, r, errors.New("panic"))
			}
		}()
		next.ServeHTTP(tw, r)
	})
}

// trackWriter records whether the response has started.
type trackWriter struct {
	http.ResponseWriter
	wrote bool
}

func (t *trackWriter) WriteHeader(code int) {
	if code >= 200 {
		t.wrote = true
	}
	t.ResponseWriter.WriteHeader(code)
}

func (t *trackWriter) Write(b []byte) (int, error) {
	t.wrote = true
	return t.ResponseWriter.Write(b)
}

// ReadFrom keeps the underlying writer's io.ReaderFrom fast path (net/http's
// *response implements it; internal/server/streams.go forwards it too).
func (t *trackWriter) ReadFrom(r io.Reader) (int64, error) {
	t.wrote = true
	if rf, ok := t.ResponseWriter.(io.ReaderFrom); ok {
		return rf.ReadFrom(r)
	}
	return io.Copy(writerOnly{t.ResponseWriter}, r)
}

// writerOnly hides a ResponseWriter's ReadFrom (and everything else) so the
// io.Copy fallback of a wrapper's own ReadFrom cannot recurse into itself.
type writerOnly struct{ io.Writer }

// Unwrap exposes the underlying writer to http.ResponseController.
func (t *trackWriter) Unwrap() http.ResponseWriter { return t.ResponseWriter }

// Flush supports streaming responses (SSE, archives).
func (t *trackWriter) Flush() {
	t.wrote = true
	if f, ok := t.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

func logger(r *http.Request) *slog.Logger {
	if d := Deps(r); hasEnv(d) && d.Log != nil {
		return d.Log
	}
	return slog.Default()
}
