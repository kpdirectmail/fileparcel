package settingsapi

import (
	"fmt"
	"net/http"
	"unicode/utf8"

	"fileparcel/internal/core"
	"fileparcel/internal/qr"
	"fileparcel/internal/web/httpx"
)

// qrSVG is GET /qr.svg?data=<text> (F): the QR code of text (1..qr.MaxLen
// bytes of UTF-8) as a standalone SVG. The image contains only the module
// path (never the text itself), and is served under the sandboxed
// user-content CSP and never cached, since the text may carry a credential
// (share links, TOTP URIs).
func (a *api) qrSVG(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	data := q.Get("data")
	switch {
	case len(q["data"]) > 1:
		httpx.Error(w, r, core.Invalid("data", "give data once"))
		return
	case data == "":
		httpx.Error(w, r, core.Invalid("data", "required"))
		return
	case len(data) > qr.MaxLen:
		httpx.Error(w, r, core.Invalid("data", fmt.Sprintf("at most %d bytes", qr.MaxLen)))
		return
	case !utf8.ValidString(data):
		httpx.Error(w, r, core.Invalid("data", "must be UTF-8 text"))
		return
	}
	svg, err := qr.SVG(data, qr.Options{Title: "QR code"})
	if err != nil {
		httpx.Error(w, r, core.Wrap(core.ErrInvalid, "the text cannot be encoded as a QR code", err))
		return
	}
	h := w.Header()
	h.Set("Content-Type", "image/svg+xml")
	h.Set("Content-Security-Policy", httpx.CSPContent)
	h.Set("Cache-Control", "private, no-store")
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Content-Length", fmt.Sprint(len(svg)))
	w.WriteHeader(http.StatusOK)
	if r.Method != http.MethodHead {
		_, _ = w.Write(svg)
	}
}
