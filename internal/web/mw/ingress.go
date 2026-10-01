package mw

import (
	"context"
	"net/http"
	"net/netip"
	"path"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"fileparcel/internal/app"
	"fileparcel/internal/core"
	"fileparcel/internal/shares"
	"fileparcel/internal/web/httpx"
)

// Tailscale Funnel and Serve (DESIGN §10.6): the request policy of the
// ingress listeners. tailscaled terminates TLS for the node's MagicDNS name
// and proxies to a dedicated listener per kind; package server validates
// the proxy headers there and marks every request with core.IngressInfo.
// Which listener a request came through decides what it may reach — never
// a header.

// ErrorPage renders the generic HTML error page (pages.RenderError; mw
// cannot import pages, so web/router.go passes it in).
type ErrorPage func(w http.ResponseWriter, r *http.Request, status int, code, message string)

// In-flight limits of the ingress listeners (a variable so tests can lower
// them). A browser multiplexes a share gallery's thumbnails over one HTTP/2
// connection to tailscaled; each becomes a backend request, so the
// per-client cap waits briefly for a free slot instead of failing at once.
var ingressLimits = struct {
	kind   int           // concurrent requests per kind
	client int           // concurrent requests per Funnel client (core.IPLimitKey)
	wait   time.Duration // how long a request over the per-client cap waits
}{kind: 256, client: 64, wait: 5 * time.Second}

// Answers of IngressGate.
var (
	errFunnelBlocked = core.Errorf(core.ErrForbidden, "not available over the public Funnel address")
	errIngressBusy   = core.Errorf(core.ErrUnavailable, "too many requests in progress; try again in a moment")
	errNoAPI         = core.NotFoundf("no such API endpoint")
)

// funnelBlockedMessage is the text of the HTML 403 page for a blocked path.
const funnelBlockedMessage = "This page is not available over this server's public internet address."

// sealedMessage is the text of the HTML 503 page over Funnel while the keys
// are locked (the internet is not told why).
const sealedMessage = "This server is temporarily unavailable. Please try again later."

// IngressGate applies the Tailscale Funnel/Serve policy to the requests of
// the ingress listeners (core.IngressFrom); every other request passes
// untouched. It runs after SecurityHeaders (its answers carry the §9.2
// headers) and before SealedGate. notFound is the generic 404 page
// (pages.NotFound) and page renders the other HTML answers.
//
// Every ingress request:
//   - fail closed: while Ingress.Policy(kind) is off (a request that raced
//     a disable) → the uniform 404;
//   - path hygiene: a path that path.Clean changes (a trailing "/" aside),
//     a "\" in the path, or an encoded "/" in the raw path → the uniform
//     404;
//   - mTLS: with mtls.mode=required → 403 (ClientCertNotice, JSON on API
//     paths) unless mtls.exempt_shares and MTLSExempt(path): tailscaled
//     terminates TLS, so no client certificate can arrive;
//   - in-flight caps: ingressLimits.kind concurrent requests per kind, and
//     for Funnel ingressLimits.client per client (waiting up to
//     ingressLimits.wait for a slot) → 503 with Retry-After: 5.
//
// Funnel (the internet; every response carries X-Robots-Tag: noindex,
// nofollow):
//   - the deny list (network.deny_cidrs) on the client address → 403 with
//     Connection: close; the allow list and the mode do not apply;
//   - rate limits: BucketFunnel per client (PerIP: an IPv6 client per /64)
//     and BucketFunnelGlobal for everybody → 429 with Retry-After;
//   - mode "shares": only /s/{token} and everything below it (any method;
//     sharesapi enforces the routes), and GET/HEAD of /static/{hash}/…,
//     /theme.css, /favicon.ico, /robots.txt and /manifest.webmanifest; any
//     other path gets the uniform 404 (JSON "no such API endpoint" under
//     /api/), identical to an unknown token or endpoint. The request loses
//     every credential: Authorization, X-FP-CSRF and every cookie but the
//     public share cookies (shares.IsPublicCookie), so no session can exist;
//   - mode "app": the whole app except /setup, /unlock, /trust, /trust/…,
//     /api/v1/auth/setup, /api/v1/system/unlock and /share-target, and —
//     unless funnel.allow_admin — /admin, /admin/… and /api/v1/admin/…:
//     403 (JSON "not available over the public Funnel address" under /api/,
//     the HTML 403 page otherwise). Sign-in rules: package auth;
//   - while the keys are locked, everything SealedAllowed does not list
//     gets 503 (JSON keys_locked under /api/ and for unsafe methods, the
//     "temporarily unavailable" page otherwise), never the /unlock redirect.
//
// Serve (the tailnet): the full access policy (Network.Allowed) on the
// client's tailnet address → 403 with Connection: close.
func IngressGate(notFound http.Handler, page ErrorPage) Middleware {
	g := &ingressGate{notFound: notFound, page: page, clients: clientSlots{m: map[string]*clientSlot{}}}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			in := core.IngressFrom(r.Context())
			if in == nil {
				next.ServeHTTP(w, r)
				return
			}
			g.serve(w, r, in, next)
		})
	}
}

// ingressGate is the state of one IngressGate.
type ingressGate struct {
	notFound http.Handler
	page     ErrorPage
	inflight [2]atomic.Int64 // funnel, serve
	clients  clientSlots
}

func (g *ingressGate) serve(w http.ResponseWriter, r *http.Request, in *core.IngressInfo, next http.Handler) {
	d := Deps(r)
	kind := 0
	switch in.Kind {
	case core.IngressFunnel:
		w.Header().Set("X-Robots-Tag", "noindex, nofollow")
	case core.IngressServe:
		kind = 1
	default:
		g.fail404(w, r)
		return
	}
	funnel := kind == 0
	var pol core.IngressPolicy
	if hasEnv(d) && d.Ingress != nil {
		pol = d.Ingress.Policy(in.Kind)
	}
	if pol.Mode == "" || pol.Mode == core.FunnelOff || !cleanPath(r) {
		g.fail404(w, r)
		return
	}
	if !ingressAllowed(d, in, funnel) {
		logger(r).Debug("ingress request refused by the access policy", "ingress", in.Kind, "ip", in.ClientIP.String())
		policyRefused(w, r)
		return
	}
	if funnel && !funnelRate(w, r, d) {
		return
	}
	if mtlsRequired(d) && !(d.Settings.Bool("mtls.exempt_shares") && MTLSExempt(r.URL.Path)) {
		clientCertRefused(w, r)
		return
	}
	if funnel {
		switch pol.Mode {
		case core.FunnelShares:
			if !funnelSharesPath(r) {
				g.fail404(w, r)
				return
			}
			stripCredentials(r)
		case core.FunnelApp:
			if funnelBlocked(r.URL.Path, pol.AllowAdmin) {
				g.forbidden(w, r)
				return
			}
		default:
			g.fail404(w, r)
			return
		}
		if hasEnv(d) && d.Keys != nil && d.Keys.State() == core.KeyStateLocked && !SealedAllowed(r.URL.Path) {
			g.sealed(w, r)
			return
		}
	}
	clientKey := ""
	if funnel {
		clientKey = PerIP(r)
	}
	release, ok := g.acquire(r.Context(), kind, clientKey)
	if !ok {
		w.Header().Set("Retry-After", "5")
		httpx.Error(w, r, errIngressBusy)
		return
	}
	defer release()
	next.ServeHTTP(w, r)
}

// fail404 is the uniform "not found" of the ingress policy: the API's JSON
// under /api/, the generic 404 page otherwise — byte for byte what an
// unknown endpoint or share token gets.
func (g *ingressGate) fail404(w http.ResponseWriter, r *http.Request) {
	if strings.HasPrefix(r.URL.Path, "/api/") || g.notFound == nil {
		httpx.Error(w, r, errNoAPI)
		return
	}
	g.notFound.ServeHTTP(w, r)
}

// forbidden answers a path Funnel "app" mode blocks.
func (g *ingressGate) forbidden(w http.ResponseWriter, r *http.Request) {
	if isAPIPath(r.URL.Path) || g.page == nil {
		httpx.Error(w, r, errFunnelBlocked)
		return
	}
	g.page(w, r, http.StatusForbidden, core.ErrForbidden.Code, funnelBlockedMessage)
}

// sealed answers a Funnel request while the keys are locked.
func (g *ingressGate) sealed(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Retry-After", "30")
	if isAPIPath(r.URL.Path) || (r.Method != http.MethodGet && r.Method != http.MethodHead) || g.page == nil {
		httpx.Error(w, r, core.ErrKeysLocked)
		return
	}
	g.page(w, r, http.StatusServiceUnavailable, core.ErrKeysLocked.Code, sealedMessage)
}

// acquire takes an in-flight slot of the kind (index) and, when clientKey
// is set, one of that client's (waiting up to ingressLimits.wait for it).
func (g *ingressGate) acquire(ctx context.Context, kind int, clientKey string) (release func(), ok bool) {
	var client func()
	if clientKey != "" {
		if client, ok = g.clients.acquire(ctx, clientKey, ingressLimits.client, ingressLimits.wait); !ok {
			return nil, false
		}
	}
	if g.inflight[kind].Add(1) > int64(ingressLimits.kind) {
		g.inflight[kind].Add(-1)
		if client != nil {
			client()
		}
		return nil, false
	}
	return func() {
		g.inflight[kind].Add(-1)
		if client != nil {
			client()
		}
	}, true
}

// clientSlots are the per-client in-flight slots of Funnel.
type clientSlots struct {
	mu sync.Mutex
	m  map[string]*clientSlot
}

// clientSlot is one client's semaphore; refs counts holders and waiters
// (the entry is dropped when it reaches zero).
type clientSlot struct {
	sem  chan struct{}
	refs int
}

// acquire takes one of key's limit slots, waiting up to wait (or until ctx
// ends) when all are taken.
func (c *clientSlots) acquire(ctx context.Context, key string, limit int, wait time.Duration) (release func(), ok bool) {
	c.mu.Lock()
	s := c.m[key]
	if s == nil {
		s = &clientSlot{sem: make(chan struct{}, max(limit, 1))}
		c.m[key] = s
	}
	s.refs++
	c.mu.Unlock()
	release = func() {
		<-s.sem
		c.done(key, s)
	}
	select {
	case s.sem <- struct{}{}:
		return release, true
	default:
	}
	t := time.NewTimer(wait)
	defer t.Stop()
	select {
	case s.sem <- struct{}{}:
		return release, true
	case <-t.C:
	case <-ctx.Done():
	}
	c.done(key, s)
	return nil, false
}

func (c *clientSlots) done(key string, s *clientSlot) {
	c.mu.Lock()
	s.refs--
	if s.refs == 0 && c.m[key] == s {
		delete(c.m, key)
	}
	c.mu.Unlock()
}

// cleanPath is the path hygiene of ingress requests: the path is what
// path.Clean makes of it (a trailing "/" allowed), it has no "\" (which
// some clients and proxies treat as "/"), and the raw path has no encoded
// "/" (which routing would decode into a different path).
func cleanPath(r *http.Request) bool {
	p := r.URL.Path
	if p == "" || p[0] != '/' || strings.ContainsRune(p, '\\') {
		return false
	}
	if c := path.Clean(p); c != p && c+"/" != p {
		return false
	}
	raw := strings.ToLower(r.URL.RawPath)
	return !strings.Contains(raw, "%2f") && !strings.Contains(raw, "%5c")
}

// denier is the deny-list check of the network service
// (netinfo.Service.Denied, lock-free).
type denier interface {
	Denied(ip netip.Addr) bool
}

// ingressAllowed applies the access policy to an ingress client: Funnel the
// deny list only (it is public by design), Serve the full policy (the
// tailnet peer is treated exactly as on FileParcel's own port).
func ingressAllowed(d *app.Deps, in *core.IngressInfo, funnel bool) bool {
	if !hasEnv(d) || d.Network == nil {
		return false
	}
	if !funnel {
		return d.Network.Allowed(in.ClientIP)
	}
	if dn, ok := d.Network.(denier); ok {
		return !dn.Denied(in.ClientIP)
	}
	ok, err := d.Network.CheckPolicy(core.AccessPolicy{Mode: core.AccessAny, Deny: d.Network.Policy().Deny}, in.ClientIP)
	return err == nil && ok
}

// funnelRate applies the Funnel rate limits (per client, then all clients
// together); false means the 429 was written.
func funnelRate(w http.ResponseWriter, r *http.Request, d *app.Deps) bool {
	if d == nil || d.Limiter == nil {
		return true
	}
	ok, retry := d.Limiter.Allow(BucketFunnel, PerIP(r))
	if ok {
		ok, retry = d.Limiter.Allow(BucketFunnelGlobal, "*")
	}
	if ok {
		return true
	}
	w.Header().Set("Retry-After", strconv.Itoa(retryAfterSeconds(retry.Seconds())))
	httpx.Error(w, r, core.ErrRateLimited)
	return false
}

// funnelSharesPath reports whether Funnel "shares" mode serves r's path.
func funnelSharesPath(r *http.Request) bool {
	p := r.URL.Path
	if rest, ok := strings.CutPrefix(p, "/s/"); ok {
		token, _, _ := strings.Cut(rest, "/")
		return token != ""
	}
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		return false
	}
	switch p {
	case "/theme.css", "/favicon.ico", "/robots.txt", "/manifest.webmanifest":
		return true
	}
	if rest, ok := strings.CutPrefix(p, "/static/"); ok {
		hash, file, found := strings.Cut(rest, "/")
		return found && hash != "" && file != ""
	}
	return false
}

// funnelBlocked reports whether Funnel "app" mode refuses p: first-run
// setup, unlocking, the trust pages, the share-target endpoint of the
// installed app and — unless allowAdmin — administration.
func funnelBlocked(p string, allowAdmin bool) bool {
	if len(p) > 1 {
		p = strings.TrimSuffix(p, "/")
	}
	switch p {
	case "/setup", "/unlock", "/trust", "/share-target", "/api/v1/auth/setup", "/api/v1/system/unlock":
		return true
	}
	if strings.HasPrefix(p, "/trust/") {
		return true
	}
	return !allowAdmin && (p == "/admin" || strings.HasPrefix(p, "/admin/") ||
		p == "/api/v1/admin" || strings.HasPrefix(p, "/api/v1/admin/"))
}

// stripCredentials removes everything that could authenticate a request
// over Funnel "shares" mode: the Authorization and CSRF headers and every
// cookie except the public share cookies (share access and file-request
// visitor cookies, which the public share routes need).
func stripCredentials(r *http.Request) {
	r.Header = r.Header.Clone()
	r.Header.Del("Authorization")
	r.Header.Del(HeaderCSRF)
	var kept []string
	for _, line := range r.Header.Values("Cookie") {
		for _, pair := range strings.Split(line, ";") {
			pair = strings.TrimSpace(pair)
			name, _, _ := strings.Cut(pair, "=")
			if pair != "" && shares.IsPublicCookie(strings.TrimSpace(name)) {
				kept = append(kept, pair)
			}
		}
	}
	r.Header.Del("Cookie")
	if len(kept) > 0 {
		r.Header.Set("Cookie", strings.Join(kept, "; "))
	}
}

// overFunnel reports whether r came through the Tailscale Funnel listener.
func overFunnel(r *http.Request) bool {
	in := core.IngressFrom(r.Context())
	return in != nil && in.Kind == core.IngressFunnel
}

// ---------- client certificates (shared with internal/server's mTLS gate) ----------

// MTLSExempt reports whether path works without a client certificate when
// mtls.exempt_shares is on (DESIGN §10.4): public shares, the trust page and
// downloads, health checks and the static files those pages load.
func MTLSExempt(path string) bool {
	switch path {
	case "/trust", "/healthz", "/readyz", "/favicon.ico", "/robots.txt", "/theme.css", "/.well-known/security.txt":
		return true
	}
	return strings.HasPrefix(path, "/s/") || strings.HasPrefix(path, "/trust/") || strings.HasPrefix(path, "/static/")
}

// ClientCertNotice is the browser answer of the mTLS gates: httpx.Error
// speaks JSON, which is unreadable in a browser (cf. HostCheck).
const ClientCertNotice = "403 forbidden: this server requires a client certificate.\n\n" +
	"Install on this device the .p12 client certificate issued for you (an administrator\n" +
	"creates one with \"fileparcel client-cert issue <user>\"), then reload this page.\n" +
	"This server's CA certificate is at /trust.\n"

// ErrClientCert is the API answer of the mTLS gates.
var ErrClientCert = core.Errorf(core.ErrForbidden, "a valid client certificate issued by this server is required")

// mtlsRequired reports mtls.mode = required.
func mtlsRequired(d *app.Deps) bool {
	return hasEnv(d) && d.Settings != nil && d.Settings.String("mtls.mode") == "required"
}

// clientCertRefused writes the 403 of a request without a client
// certificate (ClientCertNotice as text, ErrClientCert on API paths).
func clientCertRefused(w http.ResponseWriter, r *http.Request) {
	if isAPIPath(r.URL.Path) {
		httpx.Error(w, r, ErrClientCert)
		return
	}
	w.Header().Set("Content-Type", httpx.MIMETextPlain)
	w.WriteHeader(http.StatusForbidden)
	if r.Method != http.MethodHead {
		_, _ = w.Write([]byte(ClientCertNotice))
	}
}
