package httpx

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestContentType(t *testing.T) {
	cases := []struct {
		in       string
		eff      string
		inlineOK bool
	}{
		{"image/png", "image/png", true},
		{"IMAGE/JPEG", "image/jpeg", true},
		{"video/quicktime", "video/quicktime", true},
		{"audio/flac", "audio/flac", true},
		{"application/pdf", "application/pdf", true},
		{"text/plain; charset=latin1", MIMETextPlain, true},
		{"text/markdown", MIMETextPlain, true},
		{"text/css", MIMETextPlain, true},
		{"application/json", MIMETextPlain, true},
		{"application/geo+json", MIMETextPlain, true},
		{"text/html", MIMEOctetStream, false},
		{"text/html; charset=utf-8", MIMEOctetStream, false},
		{"application/xhtml+xml", MIMEOctetStream, false},
		{"image/svg+xml", MIMEOctetStream, false},
		{"text/xml", MIMEOctetStream, false},
		{"application/xml", MIMEOctetStream, false},
		{"text/javascript", MIMEOctetStream, false},
		{"application/javascript", MIMEOctetStream, false},
		{"application/x-msdownload", MIMEOctetStream, false},
		{"image/tiff", MIMEOctetStream, false},
		{"", MIMEOctetStream, false},
		{"garbage;;", MIMEOctetStream, false},
	}
	for _, c := range cases {
		eff, ok := ContentType(c.in)
		if eff != c.eff || ok != c.inlineOK {
			t.Errorf("ContentType(%q) = %q %v, want %q %v", c.in, eff, ok, c.eff, c.inlineOK)
		}
	}
}

func TestServeBlob(t *testing.T) {
	body := strings.Repeat("0123456789", 100)
	mod := time.Date(2026, 9, 19, 10, 0, 0, 0, time.UTC)
	serve := func(method, name, mimeType string, inline bool, hdr map[string]string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, "/x", nil)
		for k, v := range hdr {
			req.Header.Set(k, v)
		}
		rec := httptest.NewRecorder()
		rec.Header().Set("X-Frame-Options", "DENY") // as set by mw.SecurityHeaders
		rec.Header().Set("Cache-Control", "no-store")
		ServeBlob(rec, req, name, mimeType, mod, "ver_1", inline, strings.NewReader(body))
		return rec
	}

	rec := serve("GET", "evil.html", "text/html", true, nil)
	h := rec.Header()
	if rec.Code != 200 || h.Get("Content-Type") != MIMEOctetStream || !strings.HasPrefix(h.Get("Content-Disposition"), "attachment") ||
		!strings.HasSuffix(h.Get("Content-Security-Policy"), "sandbox") || h.Get("X-Content-Type-Options") != "nosniff" ||
		h.Get("Cross-Origin-Resource-Policy") != "same-origin" || h.Get("Cache-Control") != "private, no-cache" ||
		h.Get("ETag") != `"ver_1"` || h.Get("Last-Modified") == "" || h.Get("X-Frame-Options") != "DENY" {
		t.Fatalf("html: %d %v", rec.Code, h)
	}

	rec = serve("GET", "doc.pdf", "application/pdf", true, nil)
	h = rec.Header()
	if h.Get("Content-Type") != "application/pdf" || !strings.HasPrefix(h.Get("Content-Disposition"), "inline") ||
		h.Get("Content-Security-Policy") != CSPContentPDF || h.Get("X-Frame-Options") != "SAMEORIGIN" {
		t.Fatalf("pdf inline: %v", h)
	}
	rec = serve("GET", "doc.pdf", "application/pdf", false, nil)
	if !strings.HasPrefix(rec.Header().Get("Content-Disposition"), "attachment") || rec.Header().Get("Content-Security-Policy") != CSPContent {
		t.Fatalf("pdf attachment: %v", rec.Header())
	}

	rec = serve("GET", "notes.md", "text/markdown", true, map[string]string{"Range": "bytes=10-19"})
	if rec.Code != http.StatusPartialContent || rec.Body.String() != "0123456789" || rec.Header().Get("Content-Type") != MIMETextPlain {
		t.Fatalf("range: %d %q %v", rec.Code, rec.Body.String(), rec.Header())
	}
	rec = serve("GET", "notes.md", "text/markdown", true, map[string]string{"If-None-Match": `"ver_1"`})
	if rec.Code != http.StatusNotModified {
		t.Fatalf("etag: %d", rec.Code)
	}
	rec = serve("HEAD", "a.png", "image/png", true, nil)
	if b, _ := io.ReadAll(rec.Body); rec.Code != 200 || len(b) != 0 || rec.Header().Get("Content-Length") != "1000" {
		t.Fatalf("head: %d %d %v", rec.Code, len(b), rec.Header())
	}
}
