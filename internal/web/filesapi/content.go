package filesapi

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"fileparcel/internal/core"
	"fileparcel/internal/web/httpx"
	"fileparcel/internal/web/mw"
)

// ---------- content (DESIGN §8.2) ----------

// content serves GET /nodes/{id}/content[?version=ver_…][&inline=1] through
// httpx.ServeBlob: Range / multi-range / If-Range / If-None-Match, ETag =
// the version id, Last-Modified, the inline allow-list and the sandbox
// headers. Downloads are audited (file.download) once per download — not for
// HEAD, conditional hits or follow-up Range requests of a media player. The
// decision is made on the status http.ServeContent commits (auditOnSend),
// not on the request headers, so no Range / If-Range spelling that still
// delivers the whole file escapes the audit.
func (h *handlers) content(w http.ResponseWriter, r *http.Request) {
	f := h.files(w, r)
	if f == nil {
		return
	}
	q := r.URL.Query()
	versionID := q.Get("version")
	inline := truthy(q.Get("inline"))
	n, rd, err := f.Open(r.Context(), mw.Principal(r), chi.URLParam(r, "id"), versionID)
	if err != nil {
		httpx.Error(w, r, err)
		return
	}
	defer rd.Close()
	if r.Method == http.MethodGet {
		w = &auditOnSend{ResponseWriter: w, fire: func() { h.auditDownload(r, n, inline) }}
	}
	httpx.ServeBlob(w, r, n.Name, n.MIME, n.UpdatedAt, n.VersionID, inline, rd)
}

// auditDownload records file.download for n.
func (h *handlers) auditDownload(r *http.Request, n *core.Node, inline bool) {
	if h.d == nil || h.d.Env == nil || h.d.Audit == nil {
		return
	}
	details := map[string]any{"size": n.Size, "version_id": n.VersionID, "inline": inline}
	if rg := r.Header.Get("Range"); rg != "" {
		details["range"] = rg
	}
	h.d.Audit.Record(context.WithoutCancel(r.Context()), core.AuditEntry{Action: core.ActFileDownload,
		TargetType: "node", TargetID: n.ID, TargetName: n.Name, Details: details})
}

// auditOnSend runs fire once, when http.ServeContent commits a status that
// starts a download (deliversStart). ServeContent sets Content-Range and the
// multipart Content-Type before it calls WriteHeader, and answers 304, 412
// and 416 through WriteHeader too, so the committed response — not the
// request's Range / If-* headers — decides.
type auditOnSend struct {
	http.ResponseWriter
	fire    func()
	decided bool
}

func (a *auditOnSend) WriteHeader(code int) {
	if !a.decided {
		a.decided = true
		if deliversStart(code, a.Header()) {
			a.fire()
		}
	}
	a.ResponseWriter.WriteHeader(code)
}

func (a *auditOnSend) Write(p []byte) (int, error) {
	if !a.decided {
		a.WriteHeader(http.StatusOK)
	}
	return a.ResponseWriter.Write(p)
}

// Unwrap lets http.ResponseController reach the underlying writer.
func (a *auditOnSend) Unwrap() http.ResponseWriter { return a.ResponseWriter }

// deliversStart reports whether a content response with status code and
// headers h sends the file from its first byte: a 200 (the whole file, also
// when a Range was ignored or an If-Range did not match), a 206 whose range
// starts at byte 0, or a multipart/byteranges 206 (browsers and players never
// ask for several ranges, so every one counts). A player's follow-up 206 for
// a later range is part of the same view; 304, 412 and 416 send nothing.
func deliversStart(code int, h http.Header) bool {
	switch code {
	case http.StatusOK:
		return true
	case http.StatusPartialContent:
		if strings.HasPrefix(h.Get("Content-Range"), "bytes 0-") {
			return true
		}
		mt, _, _ := strings.Cut(h.Get("Content-Type"), ";")
		return strings.EqualFold(strings.TrimSpace(mt), "multipart/byteranges")
	}
	return false
}

// ---------- thumbnails ----------

var pngMagic = []byte("\x89PNG\r\n\x1a\n")

// thumb serves GET /nodes/{id}/thumb: the stored thumbnail (JPEG, or PNG
// for images with transparency), inline, with the user-content headers.
// ETag is derived from the thumbnail blob id (it changes with every new
// thumbnail; the id itself is not revealed); the ?v= parameter the frontend
// appends is only a cache buster.
func (h *handlers) thumb(w http.ResponseWriter, r *http.Request) {
	f := h.files(w, r)
	if f == nil {
		return
	}
	rd, err := f.Thumbnail(r.Context(), mw.Principal(r), chi.URLParam(r, "id"))
	if err != nil {
		httpx.Error(w, r, err)
		return
	}
	defer rd.Close()
	mime, name := "image/jpeg", "thumbnail.jpg"
	head := make([]byte, len(pngMagic))
	if n, _ := rd.ReadAt(head, 0); n == len(head) && bytes.Equal(head, pngMagic) {
		mime, name = "image/png", "thumbnail.png"
	}
	httpx.ServeBlob(w, r, name, mime, time.Time{}, thumbETag(rd.ID()), true, rd)
}

// thumbETag is the entity tag of a thumbnail blob: an opaque digest of its
// id (blob ids are internal).
func thumbETag(blobID string) string {
	sum := sha256.Sum256([]byte("fp-thumb|" + blobID))
	return "t" + hex.EncodeToString(sum[:12])
}

// ---------- archives ----------

// archivePath is the download URL of a ticket (relative to the host).
func archivePath(ticket string) string { return "/api/v1/archives/" + url.PathEscape(ticket) }

// createArchive is POST /archives: a single-use, 60 s ticket for a zip or
// tar of the given nodes (each needs PermView).
func (h *handlers) createArchive(w http.ResponseWriter, r *http.Request) {
	f := h.files(w, r)
	if f == nil {
		return
	}
	in, err := httpx.Decode[core.ArchiveInput](r, maxJSONBody)
	if err != nil {
		httpx.Error(w, r, err)
		return
	}
	ticket, err := f.CreateArchiveTicket(r.Context(), mw.Principal(r), "", in)
	if err != nil {
		httpx.Error(w, r, err)
		return
	}
	httpx.OK(w, core.ArchiveTicketResponse{Ticket: ticket, URL: archivePath(ticket)})
}

// errShareTicket answers a share-bound ticket presented to the API route
// (the same 404 as an unknown ticket: no oracle).
var errShareTicket = core.NotFoundf("this download link has expired or was already used")

// ticketPeeker is implemented by the files service: it validates a ticket
// without consuming it (HEAD requests must not burn the single use).
type ticketPeeker interface {
	PeekArchiveTicket(ctx context.Context, ticket string) (*core.ArchiveTicket, error)
}

// archiveMIME is the media type of an archive format (delivered as
// application/octet-stream attachment by httpx.ContentHeaders).
func archiveMIME(format string) string {
	if format == core.ArchiveTar {
		return "application/x-tar"
	}
	return "application/zip"
}

// archive is GET /archives/{ticket}: it consumes the ticket and streams the
// archive without Content-Length (a plain navigation shows the browser's
// native download progress). Errors found before the first byte (expired
// or used ticket, lost permission, disabled account) are normal API errors;
// a failure while streaming aborts the connection so the client never
// mistakes a truncated archive for a complete one.
func (h *handlers) archive(w http.ResponseWriter, r *http.Request) {
	f := h.files(w, r)
	if f == nil {
		return
	}
	ctx := r.Context()
	ticket := chi.URLParam(r, "ticket")
	if r.Method == http.MethodHead {
		name, mime := "download.zip", "application/zip"
		if pk, ok := f.(ticketPeeker); ok {
			t, err := pk.PeekArchiveTicket(ctx, ticket)
			if err == nil && t.ShareID != "" {
				err = errShareTicket
			}
			if err != nil {
				httpx.Error(w, r, err)
				return
			}
			name, mime = t.Name, archiveMIME(t.Format)
		}
		httpx.ContentHeaders(w, mime, false)
		httpx.Attachment(w, name, false)
		w.WriteHeader(http.StatusOK)
		return
	}
	t, err := f.ConsumeArchiveTicket(ctx, ticket)
	if err == nil && t.ShareID != "" {
		// Share tickets are redeemed only at /s/{token}/zip/{ticket}, which
		// checks the share password and counts the download.
		err = errShareTicket
	}
	if err != nil {
		httpx.Error(w, r, err)
		return
	}
	lw := &lazyWriter{w: w, start: func() {
		httpx.ContentHeaders(w, archiveMIME(t.Format), false)
		httpx.Attachment(w, t.Name, false)
		w.WriteHeader(http.StatusOK)
	}}
	err = f.WriteArchive(ctx, t, lw)
	switch {
	case err == nil:
		lw.begin() // an archive always has bytes; be safe anyway
	case !lw.started:
		httpx.Error(w, r, err)
	default:
		if ctx.Err() == nil {
			h.log().Warn("archive download failed", "err", err, "request_id", httpx.RequestID(ctx))
		}
		// The status line is out: abort the connection (no final chunk /
		// RST_STREAM) instead of ending a truncated archive cleanly.
		panic(http.ErrAbortHandler)
	}
}

// lazyWriter defers the response headers until the first byte, so errors
// detected before any output can still become proper API errors.
type lazyWriter struct {
	w       http.ResponseWriter
	start   func()
	started bool
}

func (l *lazyWriter) begin() {
	if !l.started {
		l.started = true
		l.start()
	}
}

// Write implements io.Writer.
func (l *lazyWriter) Write(p []byte) (int, error) {
	l.begin()
	return l.w.Write(p)
}

var _ io.Writer = (*lazyWriter)(nil)
