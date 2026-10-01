package securityapi

import (
	"bytes"
	"net/http"
	"time"

	"fileparcel/internal/web/httpx"
)

// trustDownload serves the local CA certificate for device installation
// (GET /trust/ca.crt | ca.pem | ca.mobileconfig; public, works while locked).
func (a *api) trustDownload(format string) handlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		c, err := a.certs()
		if err != nil {
			httpx.Error(w, r, err)
			return
		}
		data, contentType, filename, err := c.CAExport(format)
		if err != nil {
			httpx.Error(w, r, err)
			return
		}
		h := w.Header()
		h.Set("Content-Type", contentType)
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Cache-Control", "no-cache")
		httpx.Attachment(w, filename, false)
		http.ServeContent(w, r, filename, time.Time{}, bytes.NewReader(data))
	}
}
