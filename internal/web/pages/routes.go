package pages

import (
	"context"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"fileparcel/internal/app"
	"fileparcel/internal/core"
	"fileparcel/internal/qr"
	"fileparcel/internal/web/httpx"
	"fileparcel/internal/web/mw"
)

// SPARoutes are the app-shell routes (DESIGN §13.2); SPASubtrees also match
// every path below them.
var (
	SPARoutes   = []string{"/files", "/shared", "/links", "/requests", "/starred", "/recent", "/trash", "/activity", "/search", "/settings", "/admin"}
	SPASubtrees = []string{"/files/*", "/settings/*", "/admin/*"}
)

// MountRoot registers the root page routes (DESIGN §9.4 pages/static).
// HTML pages authenticate optionally (bad or stale credentials make the
// visitor anonymous; they never fail the request).
func MountRoot(r chi.Router, d *app.Deps) {
	r.Get("/healthz", Healthz)
	r.Get("/readyz", readyz(d))
	r.Get("/robots.txt", robots)
	r.Get("/.well-known/security.txt", securityTxt(d))
	r.Get("/theme.css", themeCSS(d))
	r.Get("/sw.js", serviceWorker)
	r.Get("/manifest.webmanifest", manifest(d))
	r.Get("/favicon.ico", favicon)
	// The service worker handles the Web Share Target POST; without it the
	// browser posts here: nothing is stored, the user lands on the upload UI.
	r.With(mw.CrossOrigin).Post("/share-target", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/files?upload=1", http.StatusSeeOther)
	})
	r.Group(func(r chi.Router) {
		r.Use(mw.AuthenticateOptional)
		r.Get("/", root(d))
		for _, p := range append(append([]string{}, SPARoutes...), SPASubtrees...) {
			r.Get(p, spa(d))
		}
		r.Get("/login", login(d))
		r.Get("/setup", setup(d))
		r.Get("/unlock", unlock(d))
		r.Get("/trust", trust(d))
		r.Get("/invite/{token}", invite)
	})
	r.NotFound(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/api/") {
			httpx.Error(w, r, core.NotFoundf("no such API endpoint"))
			return
		}
		NotFound(w, r)
	})
}

func setupNeeded(ctx context.Context, d *app.Deps) bool {
	if d == nil || d.Users == nil {
		return false
	}
	n, err := d.Users.Count(ctx)
	return err == nil && n == 0
}

// signedIn reports a principal whose login is complete (2FA enrollment may
// still be pending — the SPA guides that).
func signedIn(p *core.Principal) bool {
	return p != nil && p.UserID != "" && p.AuthLevel >= core.AuthLevelFull
}

// root redirects "/" to /unlock (keys locked), /setup (no users), /login
// (not signed in) or /files.
func root(d *app.Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		target := "/files"
		switch {
		case keysState(d) == core.KeyStateLocked:
			target = "/unlock"
		case setupNeeded(r.Context(), d):
			target = "/setup"
		case !signedIn(mw.Principal(r)):
			target = "/login"
		}
		redirect(w, r, target)
	}
}

// spa renders the app shell for signed-in users; everybody else is sent to
// /setup (first run) or /login?next=<this page>.
func spa(d *app.Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if setupNeeded(r.Context(), d) {
			redirect(w, r, "/setup")
			return
		}
		if !signedIn(mw.Principal(r)) {
			redirect(w, r, "/login?next="+url.QueryEscape(r.URL.RequestURI()))
			return
		}
		RenderTitled(w, r, "app", "", nil)
	}
}

func login(d *app.Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		needed := setupNeeded(r.Context(), d)
		if needed {
			redirect(w, r, "/setup")
			return
		}
		if signedIn(mw.Principal(r)) {
			redirect(w, r, SafeNext(r.URL.Query().Get("next"), "/files"))
			return
		}
		Render(w, r, "login", map[string]any{"setup_needed": needed})
	}
}

func setup(d *app.Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !setupNeeded(r.Context(), d) {
			redirect(w, r, "/login")
			return
		}
		Render(w, r, "setup", map[string]any{"setup_needed": true})
	}
}

func unlock(d *app.Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if st := keysState(d); st == core.KeyStateUnlocked {
			redirect(w, r, SafeNext(r.URL.Query().Get("next"), "/"))
			return
		}
		Render(w, r, "unlock", map[string]any{"state": keysState(d)})
	}
}

// trust renders /trust with the CA fingerprint, and — for visitors on this
// machine (loopback) — the access URLs and a QR code a phone can scan.
func trust(d *app.Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		data := map[string]any{}
		if d != nil && d.Certs != nil {
			data["fingerprint"] = d.Certs.Fingerprint()
		}
		target := ""
		if ip := mw.ClientIP(r); ip.IsLoopback() && d != nil && d.Network != nil {
			if urls, err := d.Network.URLs(r.Context()); err == nil && len(urls) > 0 {
				data["urls"] = urls
				target = trustTarget(urls)
			}
		}
		if target == "" && knownHost(d, r.Host) {
			target = "https://" + r.Host + "/trust"
		}
		if target != "" {
			if uri, err := qr.DataURI(target); err == nil {
				data["qr"] = uri
				data["qr_target"] = target
			}
		}
		Render(w, r, "trust", data)
	}
}

// trustTarget picks the /trust URL a phone should open: the recommended
// name-based URL, else any recommended URL, else the first one.
func trustTarget(urls []core.AccessURL) string {
	pick := -1
	for i, u := range urls {
		if u.Recommended && u.Kind != core.URLKindIP {
			pick = i
			break
		}
	}
	if pick < 0 {
		for i, u := range urls {
			if u.Recommended {
				pick = i
				break
			}
		}
	}
	if pick < 0 {
		pick = 0
	}
	u, err := url.Parse(urls[pick].URL)
	if err != nil || u.Scheme != "https" || u.Host == "" {
		return ""
	}
	return (&url.URL{Scheme: "https", Host: u.Host, Path: "/trust"}).String()
}

var hostRe = regexp.MustCompile(`^(\[[0-9a-fA-F:.]+\]|[A-Za-z0-9.-]+)(:[0-9]{1,5})?$`)

// validHost reports a syntactically sane Host header.
func validHost(h string) bool { return len(h) <= 255 && hostRe.MatchString(h) }

// knownHost reports whether the request's Host header names this instance:
// one of the certificate's SAN names or addresses, localhost, or the
// configured public URL. A Host header is attacker-controlled, so it is only
// echoed back into a QR code or a security.txt URL once it is recognised —
// otherwise a poisoned request could hand a visitor a link to another site.
func knownHost(d *app.Deps, h string) bool {
	if !validHost(h) {
		return false
	}
	host := h
	if v, _, err := net.SplitHostPort(h); err == nil {
		host = v
	}
	host = strings.ToLower(strings.Trim(host, "[]"))
	if host == "" {
		return false
	}
	if host == "localhost" || host == "127.0.0.1" || host == "::1" {
		return true
	}
	if d != nil && d.Config != nil && d.Config.Server.PublicURL != "" {
		if u, err := url.Parse(d.Config.Server.PublicURL); err == nil && u.Hostname() != "" &&
			strings.EqualFold(u.Hostname(), host) {
			return true
		}
	}
	if d == nil || d.Network == nil {
		return false
	}
	for _, n := range d.Network.Hostnames() {
		if strings.EqualFold(n, host) {
			return true
		}
	}
	if ip, err := netip.ParseAddr(host); err == nil {
		for _, known := range d.Network.IPs() {
			if known.Unmap() == ip.Unmap() {
				return true
			}
		}
	}
	return false
}

var tokenRe = regexp.MustCompile(`^[A-Za-z0-9_-]{8,256}$`)

// invite renders /invite/{token}; malformed tokens get the generic 404 page
// (the invite page looks the token up through the API).
func invite(w http.ResponseWriter, r *http.Request) {
	tok := chi.URLParam(r, "token")
	if !tokenRe.MatchString(tok) {
		NotFound(w, r)
		return
	}
	Render(w, r, "invite", map[string]any{"token": tok})
}

// SafeNext returns next when it is a same-origin path that is safe to
// redirect to after login/unlock (absolute path, no scheme or host, no
// protocol-relative "//" or "/\" prefix, not one of the auth pages), else
// fallback.
func SafeNext(next, fallback string) string {
	if next == "" || !strings.HasPrefix(next, "/") || strings.HasPrefix(next, "//") || strings.HasPrefix(next, "/\\") ||
		strings.ContainsAny(next, "\r\n\t\\") || len(next) > 2048 {
		return fallback
	}
	u, err := url.Parse(next)
	if err != nil || u.Scheme != "" || u.Host != "" || u.User != nil || u.Opaque != "" {
		return fallback
	}
	switch p := u.Path; {
	case p == "/login", p == "/setup", p == "/unlock", strings.HasPrefix(p, "/invite/"), strings.HasPrefix(p, "/api/"):
		return fallback
	}
	return u.RequestURI()
}

// redirect sends a 303 to a same-origin target (never cached).
func redirect(w http.ResponseWriter, r *http.Request, target string) {
	w.Header().Set("Cache-Control", mw.CacheNoStore)
	http.Redirect(w, r, target, http.StatusSeeOther)
}

// Healthz is the liveness check: always 200 "ok".
func Healthz(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Cache-Control", mw.CacheNoStore)
	_, _ = w.Write([]byte("ok\n"))
}

// readyz is the readiness check: 200 "ready" when the database answers and
// the keys are unlocked, else 503 with the reason.
func readyz(d *app.Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !hasEnv(d) || d.DB == nil {
			plainError(w, http.StatusServiceUnavailable, "not ready: no database")
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
		defer cancel()
		if err := d.DB.Ping(ctx); err != nil {
			plainError(w, http.StatusServiceUnavailable, "not ready: database unavailable")
			return
		}
		if st := keysState(d); st != core.KeyStateUnlocked {
			w.Header().Set("Retry-After", "30")
			plainError(w, http.StatusServiceUnavailable, "not ready: keys "+string(st))
			return
		}
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Set("Cache-Control", mw.CacheNoStore)
		_, _ = w.Write([]byte("ready\n"))
	}
}

func robots(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Cache-Control", "public, max-age=86400")
	_, _ = w.Write([]byte("User-agent: *\nDisallow: /\n"))
}

// securityTxt serves RFC 9116 /.well-known/security.txt. The contact is the
// instance itself (server.public_url, else the origin of the request):
// a self-hosted instance has no central security team.
func securityTxt(d *app.Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		origin := ""
		if hasEnv(d) && d.Config != nil && d.Config.Server.PublicURL != "" {
			if u, err := url.Parse(d.Config.Server.PublicURL); err == nil && u.Host != "" {
				origin = u.Scheme + "://" + u.Host
			}
		}
		if origin == "" && knownHost(d, r.Host) {
			origin = "https://" + r.Host
		}
		exp := time.Now().UTC().Truncate(24*time.Hour).AddDate(0, 0, 180).Format(time.RFC3339)
		var b strings.Builder
		b.WriteString("# This is a self-hosted FileParcel instance. Report security problems to its administrator.\n")
		if origin != "" {
			b.WriteString("Contact: " + origin + "/\n")
			b.WriteString("Canonical: " + origin + "/.well-known/security.txt\n")
		}
		b.WriteString("Expires: " + exp + "\n")
		b.WriteString("Preferred-Languages: en\n")
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Set("Cache-Control", "public, max-age=86400")
		_, _ = w.Write([]byte(b.String()))
	}
}
