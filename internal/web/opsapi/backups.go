package opsapi

import (
	"context"
	"errors"
	"io"
	"mime"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"fileparcel/internal/app"
	"fileparcel/internal/core"
	"fileparcel/internal/web/httpx"
	"fileparcel/internal/web/mw"
)

// RestoreScheduled is the response of POST /admin/backups/{id}/restore.
// Restarting is false in offline mode: the restore is applied at the next
// server start.
type RestoreScheduled struct {
	Scheduled  bool `json:"scheduled"`
	Restarting bool `json:"restarting"`
}

// VerifyInput is the optional body of POST /admin/backups/{id}/verify.
type VerifyInput struct {
	Deep bool `json:"deep,omitempty"`
}

// identityExporter is implemented by the backup service (not part of core.Backups).
type identityExporter interface {
	ExportIdentity(ctx context.Context, by *core.Principal) (string, string, error)
}

func (h *handlers) listBackups(w http.ResponseWriter, r *http.Request) {
	b := h.backups(w, r)
	if b == nil {
		return
	}
	page, err := b.List(r.Context(), httpx.PageReq(r))
	if err != nil {
		httpx.Error(w, r, err)
		return
	}
	httpx.OK(w, page)
}

func (h *handlers) createBackup(w http.ResponseWriter, r *http.Request) {
	b := h.backups(w, r)
	if b == nil {
		return
	}
	in, err := httpx.Decode[core.BackupInput](r, 0)
	if err != nil {
		httpx.Error(w, r, err)
		return
	}
	if truthy(r.URL.Query().Get("wait")) {
		bk, err := b.CreateSync(r.Context(), mw.Principal(r), in)
		if err != nil {
			httpx.Error(w, r, err)
			return
		}
		httpx.Created(w, bk)
		return
	}
	id, err := b.Create(r.Context(), mw.Principal(r), in)
	if err != nil {
		httpx.Error(w, r, err)
		return
	}
	httpx.JSON(w, http.StatusAccepted, core.JobRef{JobID: id})
}

func (h *handlers) getBackup(w http.ResponseWriter, r *http.Request) {
	b := h.backups(w, r)
	if b == nil {
		return
	}
	bk, err := b.Get(r.Context(), chi.URLParam(r, "id"))
	if err != nil {
		httpx.Error(w, r, err)
		return
	}
	httpx.OK(w, bk)
}

func (h *handlers) deleteBackup(w http.ResponseWriter, r *http.Request) {
	b := h.backups(w, r)
	if b == nil {
		return
	}
	if err := b.Delete(r.Context(), mw.Principal(r), chi.URLParam(r, "id")); err != nil {
		httpx.Error(w, r, err)
		return
	}
	httpx.NoContent(w)
}

func (h *handlers) verifyBackup(w http.ResponseWriter, r *http.Request) {
	b := h.backups(w, r)
	if b == nil {
		return
	}
	in, err := httpx.Decode[VerifyInput](r, 0)
	if err != nil {
		httpx.Error(w, r, err)
		return
	}
	deep := in.Deep || truthy(r.URL.Query().Get("deep"))
	id, err := b.Verify(r.Context(), mw.Principal(r), chi.URLParam(r, "id"), deep)
	if err != nil {
		httpx.Error(w, r, err)
		return
	}
	httpx.JSON(w, http.StatusAccepted, core.JobRef{JobID: id})
}

// noStoreWriter forces Cache-Control: no-store on the response (ServeBlob
// sets "private, no-cache" for user content; backups must never be cached).
type noStoreWriter struct {
	http.ResponseWriter
	done bool
}

func (n *noStoreWriter) fix() {
	if !n.done {
		n.done = true
		n.Header().Set("Cache-Control", mw.CacheNoStore)
	}
}

func (n *noStoreWriter) WriteHeader(code int) { n.fix(); n.ResponseWriter.WriteHeader(code) }

func (n *noStoreWriter) Write(b []byte) (int, error) { n.fix(); return n.ResponseWriter.Write(b) }

// ReadFrom keeps the sendfile fast path of the backup download, whose body is
// an *os.File. The fallback wraps the *underlying* writer, so io.Copy cannot
// recurse into this method.
func (n *noStoreWriter) ReadFrom(r io.Reader) (int64, error) {
	n.fix()
	if rf, ok := n.ResponseWriter.(io.ReaderFrom); ok {
		return rf.ReadFrom(r)
	}
	return io.Copy(struct{ io.Writer }{n.ResponseWriter}, r)
}

func (n *noStoreWriter) Unwrap() http.ResponseWriter { return n.ResponseWriter }

func (h *handlers) downloadBackup(w http.ResponseWriter, r *http.Request) {
	b := h.backups(w, r)
	if b == nil {
		return
	}
	id := chi.URLParam(r, "id")
	rc, size, name, err := b.Download(r.Context(), id)
	if err != nil {
		httpx.Error(w, r, err)
		return
	}
	defer rc.Close()
	if r.Method != http.MethodHead {
		h.record(r, core.AuditEntry{Action: core.ActBackupDownload, TargetType: "backup", TargetID: id, TargetName: name,
			Details: map[string]any{"size": size, "range": r.Header.Get("Range") != ""}})
	}
	nw := &noStoreWriter{ResponseWriter: w}
	var mod time.Time
	etag := ""
	if bk, err := b.Get(r.Context(), id); err == nil {
		etag = bk.SHA256
		if bk.FinishedAt != nil {
			mod = *bk.FinishedAt
		}
	}
	if rs, ok := rc.(io.ReadSeeker); ok {
		httpx.ServeBlob(nw, r, name, httpx.MIMEOctetStream, mod, etag, false, rs)
		return
	}
	httpx.ContentHeaders(nw, httpx.MIMEOctetStream, false)
	httpx.Attachment(nw, name, false)
	nw.Header().Set("Content-Length", strconv.FormatInt(size, 10))
	nw.WriteHeader(http.StatusOK)
	if r.Method != http.MethodHead {
		_, _ = io.Copy(nw, rc)
	}
}

func (h *handlers) importBackup(w http.ResponseWriter, r *http.Request) {
	b := h.backups(w, r)
	if b == nil {
		return
	}
	body := io.Reader(r.Body)
	if ct, params, err := mime.ParseMediaType(r.Header.Get("Content-Type")); err == nil && strings.HasPrefix(ct, "multipart/") {
		if params["boundary"] == "" {
			httpx.Error(w, r, core.Invalid("file", "multipart body without boundary"))
			return
		}
		mr, err := r.MultipartReader()
		if err != nil {
			httpx.Error(w, r, core.Invalid("file", "invalid multipart body"))
			return
		}
		body = nil
		for {
			part, err := mr.NextPart()
			if err != nil {
				if errors.Is(err, io.EOF) {
					break
				}
				httpx.Error(w, r, core.Invalid("file", "invalid multipart body"))
				return
			}
			if part.FileName() != "" || part.FormName() == "file" {
				body = part
				break
			}
			_ = part.Close()
		}
		if body == nil {
			httpx.Error(w, r, core.Invalid("file", "no file in the upload"))
			return
		}
	}
	bk, err := b.Import(r.Context(), mw.Principal(r), body)
	if err != nil {
		httpx.Error(w, r, err)
		return
	}
	httpx.Created(w, bk)
}

func (h *handlers) restoreBackup(w http.ResponseWriter, r *http.Request) {
	b := h.backups(w, r)
	if b == nil {
		return
	}
	creds, err := httpx.Decode[core.RestoreCreds](r, 64<<10)
	if err != nil {
		httpx.Error(w, r, err)
		return
	}
	if err := b.ScheduleRestore(r.Context(), mw.Principal(r), chi.URLParam(r, "id"), creds); err != nil {
		httpx.Error(w, r, err)
		return
	}
	d := h.deps(r)
	httpx.JSON(w, http.StatusAccepted, RestoreScheduled{Scheduled: true, Restarting: d != nil && d.Mode != app.ModeOffline})
}

func (h *handlers) getBackupConfig(w http.ResponseWriter, r *http.Request) {
	b := h.backups(w, r)
	if b == nil {
		return
	}
	c, err := b.Config(r.Context())
	if err != nil {
		httpx.Error(w, r, err)
		return
	}
	httpx.OK(w, c)
}

func (h *handlers) putBackupConfig(w http.ResponseWriter, r *http.Request) {
	b := h.backups(w, r)
	if b == nil {
		return
	}
	in, err := httpx.Decode[core.BackupConfig](r, 0)
	if err != nil {
		httpx.Error(w, r, err)
		return
	}
	if err := b.SetConfig(r.Context(), mw.Principal(r), in); err != nil {
		httpx.Error(w, r, err)
		return
	}
	c, err := b.Config(r.Context())
	if err != nil {
		httpx.Error(w, r, err)
		return
	}
	httpx.OK(w, c)
}

func (h *handlers) generateIdentity(w http.ResponseWriter, r *http.Request) {
	b := h.backups(w, r)
	if b == nil {
		return
	}
	rec, id, err := b.GenerateIdentity(r.Context(), mw.Principal(r))
	if err != nil {
		httpx.Error(w, r, err)
		return
	}
	httpx.Created(w, core.BackupIdentity{Recipient: rec, Identity: id})
}

func (h *handlers) exportIdentity(w http.ResponseWriter, r *http.Request) {
	b := h.backups(w, r)
	if b == nil {
		return
	}
	ex, ok := b.(identityExporter)
	if !ok {
		httpx.Error(w, r, core.ErrNotImplemented)
		return
	}
	rec, id, err := ex.ExportIdentity(r.Context(), mw.Principal(r))
	if err != nil {
		httpx.Error(w, r, err)
		return
	}
	httpx.OK(w, core.BackupIdentity{Recipient: rec, Identity: id})
}

func truthy(s string) bool {
	switch strings.ToLower(s) {
	case "1", "true", "yes", "on":
		return true
	}
	return false
}
