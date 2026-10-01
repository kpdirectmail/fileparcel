package server

import (
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"fileparcel/internal/app"
	"fileparcel/internal/certs"
	"fileparcel/internal/web/httpx"
	"fileparcel/internal/web/mw"
)

// deadlineBody rolls a read deadline over every read of a request body. Once
// the body is complete the deadline goes back to net/http, which owns it
// again (it clears the deadline itself on EOF to start its background read,
// and re-arming it after that would cancel the request context).
//
// A failed read leaves the expired deadline in place on purpose: net/http
// reads the unread rest of the body itself — from (*body).Close, inside
// writing the response header — and that drain has no deadline of its own,
// so clearing it here would block the response instead of freeing the
// connection.
type deadlineBody struct {
	io.ReadCloser
	rc   *http.ResponseController
	d    time.Duration
	done bool
}

func (b *deadlineBody) Read(p []byte) (int, error) {
	if b.done {
		return b.ReadCloser.Read(p)
	}
	_ = b.rc.SetReadDeadline(time.Now().Add(b.d))
	n, err := b.ReadCloser.Read(p)
	if err != nil {
		b.done = true
		if errors.Is(err, io.EOF) {
			_ = b.rc.SetReadDeadline(time.Time{})
		}
	}
	return n, err
}

// hasBody reports whether r carries a request body. HTTP/1 uses http.NoBody
// for bodyless requests, HTTP/2 a real (empty) body with Content-Length 0.
func hasBody(r *http.Request) bool {
	return r.Body != nil && r.Body != http.NoBody && r.ContentLength != 0
}

// bodyTimeout gives every request that carries a body a rolling read
// deadline of d (DESIGN §9.1): a client that keeps sending keeps extending
// it, a client that stops is torn down, so a slow-body (slowloris) sender
// can no longer park unauthenticated connections forever. http.Server's
// ReadTimeout cannot do this — it would also cap long uploads and downloads.
//
// The deadline is armed before the handler runs, not on the first Read:
// requests refused without reading their body (404, 401, 429, 413) would
// otherwise hang in net/http's post-handler body drain, which has no
// deadline of its own. Bodyless requests are left alone: a deadline there
// trips net/http's background read and cancels the request context, which
// would kill long downloads and event streams.
func bodyTimeout(d time.Duration) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		if d <= 0 {
			return next
		}
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if hasBody(r) {
				rc := http.NewResponseController(w)
				if err := rc.SetReadDeadline(time.Now().Add(d)); err == nil {
					r.Body = &deadlineBody{ReadCloser: r.Body, rc: rc, d: d}
				}
			}
			next.ServeHTTP(w, r)
		})
	}
}

// httpsRoot is the handler of the HTTPS port: plain-HTTP requests (sniffed
// on the same port) get the 308 redirect; TLS requests carrying
// Tailscale-Funnel-Request (a hand-made `tailscale funnel` to this port,
// proxied.go) are refused; the others pass the mTLS gate and reach h.
func httpsRoot(d *app.Deps, h http.Handler, lc listenConfig, log *slog.Logger) http.Handler {
	redirect := redirectHandler(lc)
	refuse := funnelToMain(d, log)
	gated := mtlsGate(d, h)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.TLS == nil:
			redirect.ServeHTTP(w, r)
		case len(r.Header.Values("Tailscale-Funnel-Request")) > 0:
			refuse.ServeHTTP(w, r)
		default:
			gated.ServeHTTP(w, r)
		}
	})
}

// redirectHandler answers every request with a 308 redirect to the same
// host on the HTTPS port (or to server.public_url when the request names its
// host). Invalid Host headers fall back to the address the client connected
// to, so the redirect can never point at an arbitrary target.
func redirectHandler(lc listenConfig) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		target := redirectTarget(r, lc)
		h := w.Header()
		h.Set("Location", target)
		h.Set("Content-Type", "text/plain; charset=utf-8")
		h.Set("Cache-Control", "no-store")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Connection", "close")
		w.WriteHeader(http.StatusPermanentRedirect)
		if r.Method != http.MethodHead {
			_, _ = w.Write([]byte("This server only speaks HTTPS: " + target + "\n"))
		}
	})
}

// redirectTarget computes the https:// URL for r.
func redirectTarget(r *http.Request, lc listenConfig) string {
	host := requestHost(r)
	uri := r.URL.RequestURI()
	if !strings.HasPrefix(uri, "/") {
		uri = "/"
	}
	if pu := lc.publicURL; pu != nil && strings.EqualFold(host, pu.Hostname()) {
		return "https://" + pu.Host + uri
	}
	hp := host
	if strings.Contains(host, ":") {
		hp = "[" + host + "]"
	}
	if lc.httpsPort != 443 {
		hp = net.JoinHostPort(host, strconv.Itoa(lc.httpsPort))
	}
	return "https://" + hp + uri
}

// requestHost returns the host name or IP literal the client used, validated;
// otherwise the local address of the connection.
func requestHost(r *http.Request) string {
	host := r.Host
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	host = strings.TrimSuffix(strings.Trim(host, "[]"), ".")
	if ip, err := netip.ParseAddr(host); err == nil {
		return ip.Unmap().WithZone("").String()
	}
	if validHostname(host) {
		return strings.ToLower(host)
	}
	if la, ok := r.Context().Value(http.LocalAddrContextKey).(net.Addr); ok {
		if ap, err := netip.ParseAddrPort(la.String()); err == nil {
			return ap.Addr().Unmap().WithZone("").String()
		}
	}
	return "localhost"
}

// validHostname accepts DNS names made of letters, digits, '-' and '_' labels.
func validHostname(s string) bool {
	if s == "" || len(s) > 253 {
		return false
	}
	for _, label := range strings.Split(s, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for i := 0; i < len(label); i++ {
			c := label[i]
			if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
				return false
			}
		}
	}
	return true
}

// mtlsGate enforces mtls.mode=required per request (the TLS layer only
// requests certificates because exemptions depend on the path): requests
// without a valid, unrevoked client certificate get 403 unless exempt
// (mw.MTLSExempt; the answers mw.ClientCertNotice and mw.ErrClientCert are
// shared with mw.IngressGate).
func mtlsGate(d *app.Deps, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if d.Settings == nil || d.Certs == nil || d.Settings.String(certs.KeyMTLSMode) != certs.MTLSRequired {
			next.ServeHTTP(w, r)
			return
		}
		if d.Settings.Bool(certs.KeyMTLSExempt) && mw.MTLSExempt(r.URL.Path) {
			next.ServeHTTP(w, r)
			return
		}
		if _, err := d.Certs.CheckClient(r.Context(), r.TLS); err != nil {
			h := w.Header()
			h.Set("Cache-Control", "no-store")
			h.Set("X-Content-Type-Options", "nosniff")
			if strings.HasPrefix(r.URL.Path, "/api/") {
				httpx.Error(w, r, mw.ErrClientCert)
				return
			}
			// text/plain, not HTML: mtlsGate runs outside the router, so
			// mw.SecurityHeaders never applies a CSP to this response.
			h.Set("Content-Type", httpx.MIMETextPlain)
			h.Set("Referrer-Policy", "no-referrer")
			w.WriteHeader(http.StatusForbidden)
			if r.Method != http.MethodHead {
				_, _ = w.Write([]byte(mw.ClientCertNotice))
			}
			return
		}
		next.ServeHTTP(w, r)
	})
}
