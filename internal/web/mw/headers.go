package mw

import (
	"errors"
	"fmt"
	"net/http"
	"strings"

	"fileparcel/internal/app"
	"fileparcel/internal/core"
	"fileparcel/internal/web/httpx"
)

// CSPApp is the Content-Security-Policy of app/page HTML (DESIGN §9.2). It is
// the default for every non-API response; download handlers override it.
// "fp" is the app's single Trusted Types policy (same-origin script URLs for
// Web Workers and the service worker only).
const CSPApp = "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data: blob:; " +
	"media-src 'self' blob:; font-src 'self'; connect-src 'self'; worker-src 'self'; manifest-src 'self'; " +
	"frame-src 'self'; object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'; " +
	"require-trusted-types-for 'script'; trusted-types fp"

// CSPAPI is the Content-Security-Policy default of JSON API responses (the
// /api/ tree and the public share JSON routes, see isAPIPath): JSON is
// never rendered as a document, so nothing may load or run. Content
// downloads (httpx.ServeBlob) replace it with the §8.2 sandbox policy.
const CSPAPI = "default-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'"

// PermissionsPolicy is sent on every response.
const PermissionsPolicy = "camera=(), microphone=(), geolocation=(), payment=(), usb=(), clipboard-write=(self)"

// HSTSValue is the Strict-Transport-Security value (DESIGN §9.2).
const HSTSValue = "max-age=31536000"

// Cache-Control values.
const (
	CacheNoStore   = "no-store"
	CacheImmutable = "public, max-age=31536000, immutable"
	CacheNoCache   = "no-cache"
)

// baseHeaders are set on every response.
var baseHeaders = [][2]string{
	{"X-Content-Type-Options", "nosniff"},
	{"Referrer-Policy", "no-referrer"},
	{"X-Frame-Options", "DENY"},
	{"Cross-Origin-Opener-Policy", "same-origin"},
	{"Cross-Origin-Resource-Policy", "same-origin"},
	{"Permissions-Policy", PermissionsPolicy},
}

// SecurityHeaders sets the headers of DESIGN §9.2 on every response:
// nosniff, no-referrer, X-Frame-Options DENY, COOP/CORP same-origin,
// Permissions-Policy, the CSP (CSPApp for pages, CSPAPI for the JSON API
// paths of isAPIPath) and Cache-Control: no-store as defaults (handlers may
// override CSP and Cache-Control), and Strict-Transport-Security on TLS
// requests when tls.hsts = on, or auto and the certificate served for the
// request's SNI name is publicly trusted (d.Certs.PubliclyTrusted).
//
// Requests of a Tailscale ingress listener arrive as plain HTTP from
// tailscaled, which terminated TLS for the node's MagicDNS name: they get
// HSTS by the same rule for that name. With auto that means only when
// FileParcel itself serves a publicly trusted certificate for it
// (tailscale.cert_enabled): HSTS covers every port of the host, so it would
// otherwise take the click-through away from the local-CA certificate on
// FileParcel's own port.
func SecurityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		setSecurityHeaders(w, r)
		next.ServeHTTP(w, r)
	})
}

// setSecurityHeaders applies the DESIGN §9.2 defaults to w. Middleware that
// runs before SecurityHeaders and answers by itself (HostCheck's 421) calls
// it so that every response carries them.
func setSecurityHeaders(w http.ResponseWriter, r *http.Request) {
	h := w.Header()
	for _, kv := range baseHeaders {
		h.Set(kv[0], kv[1])
	}
	if isAPIPath(r.URL.Path) {
		h.Set("Content-Security-Policy", CSPAPI)
	} else {
		h.Set("Content-Security-Policy", CSPApp)
	}
	h.Set("Cache-Control", CacheNoStore)
	if d := Deps(r); (r.TLS != nil && hstsEnabled(d, r.TLS.ServerName)) || ingressHSTS(d, r) {
		h.Set("Strict-Transport-Security", HSTSValue)
	}
}

// ingressHSTS applies hstsEnabled to a request of a Tailscale ingress
// listener, for the MagicDNS name its policy serves.
func ingressHSTS(d *app.Deps, r *http.Request) bool {
	in := core.IngressFrom(r.Context())
	if in == nil || !hasEnv(d) || d.Ingress == nil {
		return false
	}
	return hstsEnabled(d, d.Ingress.Policy(in.Kind).DNSName)
}

// isAPIPath reports whether p is a JSON API path: the /api/ tree, or the
// JSON sub-routes of a public share (/s/{token}/api and /s/{token}/api/…).
// Their responses are never rendered as a document, so they get CSPAPI; the
// /s/{token} HTML page and the /dl, /thumb and /zip content routes do not
// match (content handlers set their own §8.2 CSP in httpx.ServeBlob).
func isAPIPath(p string) bool {
	if strings.HasPrefix(p, "/api/") {
		return true
	}
	rest, ok := strings.CutPrefix(p, "/s/")
	if !ok {
		return false
	}
	i := strings.IndexByte(rest, '/') // end of {token}
	if i < 0 {
		return false
	}
	sub := rest[i:]
	return sub == "/api" || strings.HasPrefix(sub, "/api/")
}

// hstsEnabled applies tls.hsts (on | off | auto; unregistered = auto).
func hstsEnabled(d *app.Deps, serverName string) bool {
	if !hasEnv(d) {
		return false
	}
	mode := "auto"
	if d.Settings != nil {
		if s := d.Settings.String("tls.hsts"); s != "" {
			mode = s
		}
	}
	switch mode {
	case "on":
		return true
	case "off":
		return false
	}
	return d.Certs != nil && serverName != "" && d.Certs.PubliclyTrusted(serverName)
}

// HeaderKind selects the expectations of CheckSecurityHeaders.
type HeaderKind int

// Header kinds.
const (
	// HeadersPage: HTML pages and other root responses (CSPApp, no-store).
	HeadersPage HeaderKind = iota
	// HeadersAPI: JSON responses of /api/ and of the public share JSON
	// routes (CSPAPI, no-store).
	HeadersAPI
	// HeadersStatic: hashed /static/<hash>/… assets (immutable caching).
	HeadersStatic
	// HeadersContent: user content served by httpx.ServeBlob (sandbox CSP,
	// private no-cache).
	HeadersContent
)

// CheckSecurityHeaders is the header sweep (DESIGN §17): it returns an error
// listing every header of h that does not match DESIGN §9.2 (and §8.2 for
// HeadersContent), or nil. Tests of any web package can run it on recorded
// responses:
//
//	if err := mw.CheckSecurityHeaders(rec.Header(), mw.HeadersAPI); err != nil { t.Error(err) }
//
// HSTS is not checked (it depends on the certificate); use HSTSValue.
func CheckSecurityHeaders(h http.Header, kind HeaderKind) error {
	var probs []string
	want := func(name, value string) {
		if got := h.Get(name); got != value {
			probs = append(probs, fmt.Sprintf("%s = %q, want %q", name, got, value))
		}
	}
	oneOf := func(name string, values ...string) {
		got := h.Get(name)
		for _, v := range values {
			if got == v {
				return
			}
		}
		probs = append(probs, fmt.Sprintf("%s = %q, want one of %q", name, got, values))
	}
	for _, kv := range baseHeaders {
		if kind == HeadersContent && kv[0] == "X-Frame-Options" {
			oneOf(kv[0], "DENY", "SAMEORIGIN") // inline PDF previews are framed same-origin
			continue
		}
		want(kv[0], kv[1])
	}
	switch kind {
	case HeadersPage:
		want("Content-Security-Policy", CSPApp)
		oneOf("Cache-Control", CacheNoStore, CacheNoCache)
	case HeadersAPI:
		want("Content-Security-Policy", CSPAPI)
		want("Cache-Control", CacheNoStore)
	case HeadersStatic:
		want("Content-Security-Policy", CSPApp)
		want("Cache-Control", CacheImmutable)
	case HeadersContent:
		oneOf("Content-Security-Policy", httpx.CSPContent, httpx.CSPContentPDF)
		want("Cache-Control", "private, no-cache")
		if ct := h.Get("Content-Type"); ct == "" {
			probs = append(probs, "Content-Type missing")
		}
	}
	for _, leak := range []string{"Server", "X-Powered-By"} {
		if v := h.Get(leak); v != "" {
			probs = append(probs, fmt.Sprintf("%s must not be sent (got %q)", leak, v))
		}
	}
	if len(probs) == 0 {
		return nil
	}
	return errors.New("security headers: " + strings.Join(probs, "; "))
}
