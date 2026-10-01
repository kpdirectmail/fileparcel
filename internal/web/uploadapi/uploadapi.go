// Package uploadapi owns /api/v1/upload-batches* and /uploads* (DESIGN §8.1,
// §9.4, unit E). Every route requires full authentication (F) and, for API
// tokens, the files:write scope:
//
//	POST   /upload-batches                    core.BatchInput → 201 core.UploadBatch
//	GET    /upload-batches                    {"items": [core.UploadBatch]} the caller's unfinished batches
//	GET    /upload-batches/{id}               core.UploadBatch (with files)
//	POST   /upload-batches/{id}/files         []core.UploadFileInput → []core.UploadFileState
//	PUT    /upload-batches/{id}/small?ref=    raw body + X-FP-SHA256 → core.UploadFileState
//	POST   /upload-batches/{id}/complete      core.UploadBatch (202 while a zip is being built)
//	DELETE /upload-batches/{id}               204
//	GET    /uploads/{id}                      core.UploadFileState (parts_done: resume)
//	PUT    /uploads/{id}/parts/{n}            raw body + X-FP-SHA256 → 204
//	POST   /uploads/{id}/complete             core.UploadFileState
//	DELETE /uploads/{id}                      204
//
// Body limits: JSON declarations up to 8 MiB (chunks of 1000+ entries),
// parts up to core.PartSize (the exact part length is enforced by the
// service), small files up to uploads.SmallMax.
//
// Password-protected zips (DESIGN §8.1): a mode=zip POST /upload-batches may
// carry "zip_encryption" (aes256 | zipcrypto; empty with a password means
// aes256) and "zip_password". The service validates both there (422 on the
// field) and stores the password sealed (503 keys_locked while the keys are
// locked); no answer, job or event ever carries it back, the batch shows
// zip_encryption only. POST /upload-batches/{id}/complete answers 412
// precondition_failed or 500 corrupt when the sealed password can no longer
// be used, and the batch stays open.
package uploadapi

import (
	"encoding/hex"
	"net/http"
	"strconv"
	"strings"

	"github.com/go-chi/chi/v5"

	"fileparcel/internal/app"
	"fileparcel/internal/core"
	"fileparcel/internal/web/httpx"
	"fileparcel/internal/web/mw"
)

// Limits of the upload routes.
const (
	// MaxDeclBody bounds JSON bodies declaring files.
	MaxDeclBody = 8 << 20
	// SmallMax mirrors uploads.SmallMax (web packages do not import services).
	SmallMax = 8 << 20
	// MaxPartCount mirrors uploads.MaxPartCount: part numbers run from 0 to
	// MaxPartCount-1 (the service refuses larger files at declaration).
	MaxPartCount = 1 << 20
	// HeaderSHA256 carries the hex SHA-256 of a part or small file.
	HeaderSHA256 = "X-FP-SHA256"
)

// Mount registers this package's routes on the /api/v1 router.
func Mount(api chi.Router, d *app.Deps) {
	api.Group(func(r chi.Router) {
		r.Use(mw.RequireFull, mw.RequireScope(core.ScopeFilesWrite))
		r.With(mw.MaxBody(MaxDeclBody)).Post("/upload-batches", createBatch)
		r.Get("/upload-batches", listBatches)
		r.Get("/upload-batches/{id}", getBatch)
		r.With(mw.MaxBody(MaxDeclBody)).Post("/upload-batches/{id}/files", addFiles)
		r.With(mw.MaxBody(SmallMax)).Put("/upload-batches/{id}/small", putSmall)
		r.Post("/upload-batches/{id}/complete", completeBatch)
		r.Delete("/upload-batches/{id}", abortBatch)
		r.Get("/uploads/{id}", status)
		r.With(mw.MaxBody(core.PartSize)).Put("/uploads/{id}/parts/{n}", putPart)
		r.Post("/uploads/{id}/complete", completeFile)
		r.Delete("/uploads/{id}", abortFile)
	})
}

func actor(r *http.Request) core.UploadActor { return core.UploadActor{P: mw.Principal(r)} }

func uploadsSvc(w http.ResponseWriter, r *http.Request) core.Uploads {
	d := mw.Deps(r)
	if d == nil || d.Uploads == nil {
		httpx.Error(w, r, core.Wrap(core.ErrUnavailable, "uploads are not available", nil))
		return nil
	}
	return d.Uploads
}

func createBatch(w http.ResponseWriter, r *http.Request) {
	svc := uploadsSvc(w, r)
	if svc == nil {
		return
	}
	in, err := httpx.Decode[core.BatchInput](r, MaxDeclBody)
	if err != nil {
		httpx.Error(w, r, err)
		return
	}
	b, err := svc.CreateBatch(r.Context(), actor(r), in)
	if err != nil {
		httpx.Error(w, r, err)
		return
	}
	httpx.Created(w, b)
}

// listBatches answers the caller's own unfinished batches (open or
// finalizing), newest first and without files, so that a batch left behind
// by a closed tab or a killed CLI can be found and cancelled.
func listBatches(w http.ResponseWriter, r *http.Request) {
	svc := uploadsSvc(w, r)
	if svc == nil {
		return
	}
	list, err := svc.ListBatches(r.Context(), actor(r))
	if err != nil {
		httpx.Error(w, r, err)
		return
	}
	httpx.OK(w, core.NewPage(list, ""))
}

func getBatch(w http.ResponseWriter, r *http.Request) {
	svc := uploadsSvc(w, r)
	if svc == nil {
		return
	}
	b, err := svc.GetBatch(r.Context(), actor(r), chi.URLParam(r, "id"))
	if err != nil {
		httpx.Error(w, r, err)
		return
	}
	httpx.OK(w, b)
}

func addFiles(w http.ResponseWriter, r *http.Request) {
	svc := uploadsSvc(w, r)
	if svc == nil {
		return
	}
	in, err := httpx.Decode[[]core.UploadFileInput](r, MaxDeclBody)
	if err != nil {
		httpx.Error(w, r, err)
		return
	}
	states, err := svc.AddFiles(r.Context(), actor(r), chi.URLParam(r, "id"), in)
	if err != nil {
		httpx.Error(w, r, err)
		return
	}
	if states == nil {
		states = []core.UploadFileState{}
	}
	httpx.OK(w, states)
}

func putSmall(w http.ResponseWriter, r *http.Request) {
	svc := uploadsSvc(w, r)
	if svc == nil {
		return
	}
	sha, err := ParseSHA256(r.Header.Get(HeaderSHA256))
	if err != nil {
		httpx.Error(w, r, err)
		return
	}
	ref := r.URL.Query().Get("ref")
	if ref == "" {
		httpx.Error(w, r, core.Invalid("ref", "the client_ref of the file is required (?ref=)"))
		return
	}
	if r.ContentLength > SmallMax {
		httpx.Error(w, r, core.ErrTooLarge)
		return
	}
	st, err := svc.PutSmall(r.Context(), actor(r), chi.URLParam(r, "id"), ref, r.Body, r.ContentLength, sha)
	if err != nil {
		httpx.Error(w, r, err)
		return
	}
	httpx.OK(w, st)
}

func completeBatch(w http.ResponseWriter, r *http.Request) {
	svc := uploadsSvc(w, r)
	if svc == nil {
		return
	}
	b, err := svc.CompleteBatch(r.Context(), actor(r), chi.URLParam(r, "id"))
	if err != nil {
		httpx.Error(w, r, err)
		return
	}
	WriteBatch(w, b)
}

// WriteBatch answers a completed batch: 202 Accepted while a zip is being
// built (state finalizing), 200 otherwise.
func WriteBatch(w http.ResponseWriter, b *core.UploadBatch) {
	status := http.StatusOK
	if b.State == core.BatchFinalizing {
		status = http.StatusAccepted
	}
	httpx.JSON(w, status, b)
}

func abortBatch(w http.ResponseWriter, r *http.Request) {
	svc := uploadsSvc(w, r)
	if svc == nil {
		return
	}
	if err := svc.AbortBatch(r.Context(), actor(r), chi.URLParam(r, "id")); err != nil {
		httpx.Error(w, r, err)
		return
	}
	httpx.NoContent(w)
}

func status(w http.ResponseWriter, r *http.Request) {
	svc := uploadsSvc(w, r)
	if svc == nil {
		return
	}
	st, err := svc.Status(r.Context(), actor(r), chi.URLParam(r, "id"))
	if err != nil {
		httpx.Error(w, r, err)
		return
	}
	httpx.OK(w, st)
}

func putPart(w http.ResponseWriter, r *http.Request) {
	svc := uploadsSvc(w, r)
	if svc == nil {
		return
	}
	n, err := ParsePartNumber(chi.URLParam(r, "n"))
	if err != nil {
		httpx.Error(w, r, err)
		return
	}
	sha, err := ParseSHA256(r.Header.Get(HeaderSHA256))
	if err != nil {
		httpx.Error(w, r, err)
		return
	}
	if r.ContentLength > core.PartSize {
		httpx.Error(w, r, core.ErrTooLarge)
		return
	}
	if err := svc.PutPart(r.Context(), actor(r), chi.URLParam(r, "id"), n, r.Body, r.ContentLength, sha); err != nil {
		httpx.Error(w, r, err)
		return
	}
	httpx.NoContent(w)
}

func completeFile(w http.ResponseWriter, r *http.Request) {
	svc := uploadsSvc(w, r)
	if svc == nil {
		return
	}
	st, err := svc.CompleteFile(r.Context(), actor(r), chi.URLParam(r, "id"))
	if err != nil {
		httpx.Error(w, r, err)
		return
	}
	httpx.OK(w, st)
}

func abortFile(w http.ResponseWriter, r *http.Request) {
	svc := uploadsSvc(w, r)
	if svc == nil {
		return
	}
	if err := svc.AbortFile(r.Context(), actor(r), chi.URLParam(r, "id")); err != nil {
		httpx.Error(w, r, err)
		return
	}
	httpx.NoContent(w)
}

// ParseSHA256 decodes the X-FP-SHA256 header: 64 hex characters (case
// insensitive). Anything else is 422 on field X-FP-SHA256.
func ParseSHA256(v string) ([]byte, error) {
	v = strings.TrimSpace(v)
	if len(v) != 64 {
		return nil, core.Invalid(HeaderSHA256, "the X-FP-SHA256 header must hold the SHA-256 of the body as 64 hex characters")
	}
	b, err := hex.DecodeString(v)
	if err != nil {
		return nil, core.Invalid(HeaderSHA256, "the X-FP-SHA256 header must hold the SHA-256 of the body as 64 hex characters")
	}
	return b, nil
}

// ParsePartNumber parses the {n} path segment (0 … MaxPartCount-1, decimal
// digits only).
func ParsePartNumber(s string) (int, error) {
	if s == "" || len(s) > 7 || strings.TrimLeft(s, "0123456789") != "" {
		return 0, core.Invalid("n", "the part number must be a non-negative integer")
	}
	n, err := strconv.Atoi(s)
	if err != nil || n >= MaxPartCount {
		return 0, core.Invalid("n", "the part number is out of range")
	}
	return n, nil
}
