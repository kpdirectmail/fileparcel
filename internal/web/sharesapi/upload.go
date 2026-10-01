package sharesapi

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"fileparcel/internal/core"
	"fileparcel/internal/shares"
	"fileparcel/internal/web/httpx"
)

var timeZero time.Time

// Visitor cookie of file requests. Every visitor of a file request acts as
// the same principal (the share owner), so the only thing telling their
// batches apart is an opaque id issued here and kept in a per-share cookie;
// uploads.owns binds a batch to it, so one visitor can neither read nor
// abort another's upload. It is a capability, not an identity: it carries no
// information about the visitor and proves nothing beyond "this client
// opened that batch". A client that sends no cookies (curl, a script)
// presents none, and its batches keep the old share-wide behaviour.
//
// The name prefix is shares.VisitorCookiePrefix: over Tailscale Funnel
// "shares" mode, mw.IngressGate keeps only the public share cookies
// (shares.IsPublicCookie), and this is one of them.
const (
	// visitorCookieTTL outlives the longest configurable upload expiry
	// (storage.upload_expiry_hours, at most 720 h), so a batch never outlives
	// the cookie that owns it.
	visitorCookieTTL = 31 * 24 * time.Hour
	visitorIDBytes   = 16
)

// visitorCookieName is the cookie name of a share: the prefix plus the last
// 8 characters of the share id (its random part — the leading characters
// encode the creation time), like shares.CookieName.
func visitorCookieName(shareID string) string {
	suffix := shareID
	if len(suffix) > 8 {
		suffix = suffix[len(suffix)-8:]
	}
	return shares.VisitorCookiePrefix + suffix
}

// visitorID returns the visitor id the request carries for shareID, or "".
func visitorID(r *http.Request, shareID string) string {
	for _, c := range r.CookiesNamed(visitorCookieName(shareID)) {
		if validVisitorID(c.Value) {
			return c.Value
		}
	}
	return ""
}

// issueVisitor gives the visitor of a share that accepts uploads an id when
// the request carries none. It runs on the share page and its info route,
// never on the upload calls themselves: a client that does not send cookies
// back (curl, a script) would otherwise be issued an id, have its batch bound
// to it and be locked out of that batch on the very next call. Such a client
// simply presents nothing, and its batches keep the old share-wide behaviour.
func issueVisitor(w http.ResponseWriter, r *http.Request, s *core.Share) {
	if s == nil || !s.AllowUpload || visitorID(r, s.ID) != "" {
		return
	}
	b := make([]byte, visitorIDBytes)
	if _, err := rand.Read(b); err != nil {
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:     visitorCookieName(s.ID),
		Value:    base64.RawURLEncoding.EncodeToString(b),
		Path:     "/",
		MaxAge:   int(visitorCookieTTL / time.Second),
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})
}

// validVisitorID reports whether v is one of our ids (never trust a value
// the client may have written: it ends up in the actor_session column).
func validVisitorID(v string) bool {
	if len(v) != base64.RawURLEncoding.EncodedLen(visitorIDBytes) {
		return false
	}
	_, err := base64.RawURLEncoding.DecodeString(v)
	return err == nil
}

// uploadActor checks that the share accepts uploads (and that its password
// was entered) and returns the actor for the uploads service: the share
// owner's principal (quota owner) with the visitor's request metadata.
func uploadActor(w http.ResponseWriter, r *http.Request, countFailure bool) (*shareReq, core.UploadActor, bool) {
	sr := resolve(w, r, false, countFailure)
	if sr == nil || !sr.requireAccess(w, r) {
		return nil, core.UploadActor{}, false
	}
	if !sr.s.AllowUpload || !sr.node.IsDir() {
		httpx.Error(w, r, errNoUploads())
		return nil, core.UploadActor{}, false
	}
	if sr.d.Uploads == nil {
		httpx.Error(w, r, core.Wrap(core.ErrUnavailable, "uploads are not available", nil))
		return nil, core.UploadActor{}, false
	}
	p, err := sr.owner(r)
	if err != nil {
		httpx.Error(w, r, err)
		return nil, core.UploadActor{}, false
	}
	// SessionID is unused for Via=share principals and carries the visitor id
	// to the uploads service (actorSession), which binds the batch to it.
	p.SessionID = visitorID(r, sr.s.ID)
	return sr, core.UploadActor{P: p, ShareID: sr.s.ID}, true
}

func parseSHA(v string) ([]byte, error) {
	v = strings.TrimSpace(v)
	b, err := hex.DecodeString(v)
	if len(v) != 64 || err != nil {
		return nil, core.Invalid(headerSHA256, "the X-FP-SHA256 header must hold the SHA-256 of the body as 64 hex characters")
	}
	return b, nil
}

// upCreateBatch is POST /s/{token}/api/upload-batches. A file request never
// produces a password-protected .zip (the owner could not open it, and an
// anonymous visitor could fill the owner's quota with unreadable data): the
// uploads service answers 422 when zip_password or zip_encryption is set.
func upCreateBatch(w http.ResponseWriter, r *http.Request) {
	sr, a, ok := uploadActor(w, r, false)
	if !ok {
		return
	}
	in, err := httpx.Decode[core.BatchInput](r, maxDeclBody)
	if err != nil {
		httpx.Error(w, r, err)
		return
	}
	if in.FolderID == "" {
		in.FolderID = sr.s.NodeID
	}
	b, err := sr.d.Uploads.CreateBatch(r.Context(), a, in)
	if err != nil {
		if errors.Is(err, core.ErrForbidden) {
			// The creator can no longer add files there (a share or group
			// membership was reduced or taken away): the visitor gets the
			// answer of a share without uploads, not the creator's
			// permission error naming the folder. (A file request whose
			// creator cannot write no longer resolves at all.)
			err = errNoUploads()
		}
		httpx.Error(w, r, err)
		return
	}
	httpx.Created(w, visitorBatch(b))
}

// errNoUploads is the refusal of an upload to a share that does not (or no
// longer) accept them.
func errNoUploads() error {
	return core.Errorf(core.ErrForbidden, "this share does not accept uploads")
}

func upAddFiles(w http.ResponseWriter, r *http.Request) {
	sr, a, ok := uploadActor(w, r, false)
	if !ok {
		return
	}
	in, err := httpx.Decode[[]core.UploadFileInput](r, maxDeclBody)
	if err != nil {
		httpx.Error(w, r, err)
		return
	}
	states, err := sr.d.Uploads.AddFiles(r.Context(), a, chi.URLParam(r, "id"), in)
	if err != nil {
		httpx.Error(w, r, err)
		return
	}
	if states == nil {
		states = []core.UploadFileState{}
	}
	httpx.OK(w, states)
}

func upPutSmall(w http.ResponseWriter, r *http.Request) {
	sr, a, ok := uploadActor(w, r, true)
	if !ok {
		return
	}
	sha, err := parseSHA(r.Header.Get(headerSHA256))
	if err != nil {
		httpx.Error(w, r, err)
		return
	}
	ref := r.URL.Query().Get("ref")
	if ref == "" {
		httpx.Error(w, r, core.Invalid("ref", "the client_ref of the file is required (?ref=)"))
		return
	}
	if r.ContentLength > smallMax {
		httpx.Error(w, r, core.ErrTooLarge)
		return
	}
	st, err := sr.d.Uploads.PutSmall(r.Context(), a, chi.URLParam(r, "id"), ref, r.Body, r.ContentLength, sha)
	if err != nil {
		httpx.Error(w, r, err)
		return
	}
	httpx.OK(w, visitorState(st))
}

func upPutPart(w http.ResponseWriter, r *http.Request) {
	sr, a, ok := uploadActor(w, r, true)
	if !ok {
		return
	}
	n, err := parsePart(chi.URLParam(r, "n"))
	if err != nil {
		httpx.Error(w, r, err)
		return
	}
	sha, err := parseSHA(r.Header.Get(headerSHA256))
	if err != nil {
		httpx.Error(w, r, err)
		return
	}
	if r.ContentLength > core.PartSize {
		httpx.Error(w, r, core.ErrTooLarge)
		return
	}
	if err := sr.d.Uploads.PutPart(r.Context(), a, chi.URLParam(r, "id"), n, r.Body, r.ContentLength, sha); err != nil {
		httpx.Error(w, r, err)
		return
	}
	httpx.NoContent(w)
}

func upStatus(w http.ResponseWriter, r *http.Request) {
	sr, a, ok := uploadActor(w, r, true)
	if !ok {
		return
	}
	st, err := sr.d.Uploads.Status(r.Context(), a, chi.URLParam(r, "id"))
	if err != nil {
		httpx.Error(w, r, err)
		return
	}
	httpx.OK(w, visitorState(st))
}

func upCompleteFile(w http.ResponseWriter, r *http.Request) {
	sr, a, ok := uploadActor(w, r, true)
	if !ok {
		return
	}
	st, err := sr.d.Uploads.CompleteFile(r.Context(), a, chi.URLParam(r, "id"))
	if err != nil {
		httpx.Error(w, r, err)
		return
	}
	httpx.OK(w, visitorState(st))
}

func upAbortFile(w http.ResponseWriter, r *http.Request) {
	sr, a, ok := uploadActor(w, r, true)
	if !ok {
		return
	}
	if err := sr.d.Uploads.AbortFile(r.Context(), a, chi.URLParam(r, "id")); err != nil {
		httpx.Error(w, r, err)
		return
	}
	httpx.NoContent(w)
}

// upGetBatch returns a batch of this request (polling while a zip is built).
func upGetBatch(w http.ResponseWriter, r *http.Request) {
	sr, a, ok := uploadActor(w, r, true)
	if !ok {
		return
	}
	b, err := sr.d.Uploads.GetBatch(r.Context(), a, chi.URLParam(r, "id"))
	if err != nil {
		httpx.Error(w, r, err)
		return
	}
	httpx.OK(w, visitorBatch(b))
}

func upCompleteBatch(w http.ResponseWriter, r *http.Request) {
	sr, a, ok := uploadActor(w, r, false)
	if !ok {
		return
	}
	b, err := sr.d.Uploads.CompleteBatch(r.Context(), a, chi.URLParam(r, "id"))
	if err != nil {
		httpx.Error(w, r, err)
		return
	}
	status := http.StatusOK
	if b.State == core.BatchFinalizing {
		status = http.StatusAccepted
	}
	httpx.JSON(w, status, visitorBatch(b))
}

func upAbortBatch(w http.ResponseWriter, r *http.Request) {
	sr, a, ok := uploadActor(w, r, false)
	if !ok {
		return
	}
	if err := sr.d.Uploads.AbortBatch(r.Context(), a, chi.URLParam(r, "id")); err != nil {
		httpx.Error(w, r, err)
		return
	}
	httpx.NoContent(w)
}

// visitorState hides the owner's node ids from anonymous uploaders.
func visitorState(st *core.UploadFileState) *core.UploadFileState {
	if st == nil {
		return nil
	}
	c := *st
	c.NodeID = ""
	return &c
}

// visitorBatch hides the owner's ids (user, folder, result node) from
// anonymous uploaders.
func visitorBatch(b *core.UploadBatch) *core.UploadBatch {
	if b == nil {
		return nil
	}
	c := *b
	c.UserID, c.ResultNodeID, c.JobID = "", "", ""
	if len(c.Files) > 0 {
		files := make([]core.UploadFileState, len(c.Files))
		for i := range c.Files {
			files[i] = *visitorState(&c.Files[i])
		}
		c.Files = files
	}
	return &c
}
