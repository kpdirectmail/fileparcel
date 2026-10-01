package sharesapi

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"strconv"
	"strings"

	"github.com/go-chi/chi/v5"

	"fileparcel/internal/app"
	"fileparcel/internal/core"
	"fileparcel/internal/names"
	"fileparcel/internal/web/httpx"
	"fileparcel/internal/web/mw"
	"fileparcel/internal/web/pages"
)

// Limits of the public routes.
const (
	maxDeclBody   = 8 << 20 // upload declarations
	smallMax      = 8 << 20 // mirrors uploads.SmallMax
	maxArchiveIDs = 1000
	headerSHA256  = "X-FP-SHA256"
)

// MountRoot registers the public share routes on the root router.
func MountRoot(r chi.Router, d *app.Deps) {
	r.Group(func(r chi.Router) {
		r.Use(publicHeaders, mw.CrossOrigin, mw.MaxBody(httpx.DefaultMaxBody))

		// Entry points: every request is rate limited per IP.
		r.Group(func(r chi.Router) {
			r.Use(mw.RateLimit(mw.BucketShare, mw.PerIP))
			r.Get("/s/{token}", page)
			r.Get("/s/{token}/api", info)
			r.Get("/s/{token}/api/list", list)
			r.Post("/s/{token}/api/password", password)
			r.Post("/s/{token}/api/archive", archive)
			r.Get("/s/{token}/zip/{ticket}", zipDownload)
			r.With(mw.MaxBody(maxDeclBody)).Post("/s/{token}/api/upload-batches", upCreateBatch)
			r.With(mw.MaxBody(maxDeclBody)).Post("/s/{token}/api/upload-batches/{id}/files", upAddFiles)
			r.Post("/s/{token}/api/upload-batches/{id}/complete", upCompleteBatch)
			r.Delete("/s/{token}/api/upload-batches/{id}", upAbortBatch)
		})

		// Data routes: only failed resolutions consume rate-limit tokens.
		r.Get("/s/{token}/dl/{nodeId}", download)
		r.Get("/s/{token}/thumb/{nodeId}", thumb)
		r.With(mw.MaxBody(smallMax)).Put("/s/{token}/api/upload-batches/{id}/small", upPutSmall)
		r.With(mw.MaxBody(core.PartSize)).Put("/s/{token}/api/uploads/{id}/parts/{n}", upPutPart)
		r.Get("/s/{token}/api/uploads/{id}", upStatus)
		r.Get("/s/{token}/api/upload-batches/{id}", upGetBatch)
		r.Post("/s/{token}/api/uploads/{id}/complete", upCompleteFile)
		r.Delete("/s/{token}/api/uploads/{id}", upAbortFile)
	})
}

// publicHeaders marks share responses as not indexable (Referrer-Policy:
// no-referrer is already set on every response by mw.SecurityHeaders; it is
// repeated here so the token never leaks through a Referer header even if
// that default changes).
func publicHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("X-Robots-Tag", "noindex, nofollow, noarchive")
		next.ServeHTTP(w, r)
	})
}

// errShareNotFound is the uniform answer for every unusable token.
func errShareNotFound() error { return core.NotFoundf("share not found") }

func errPasswordRequired() error {
	return core.Errorf(core.ErrUnauthorized, "this share is protected by a password")
}

// shareReq is a resolved public share request.
type shareReq struct {
	d     *app.Deps
	s     *core.Share
	node  *core.Node
	token string
}

// resolve resolves {token}. On failure it writes the uniform 404 (the error
// page when html) and returns nil. countFailure consumes a share rate-limit
// token for unresolvable tokens (data routes, which are otherwise not
// limited).
func resolve(w http.ResponseWriter, r *http.Request, html, countFailure bool) *shareReq {
	d := mw.Deps(r)
	if d == nil || d.Env == nil || d.Shares == nil || d.Files == nil {
		httpx.Error(w, r, core.Wrap(core.ErrUnavailable, "sharing is not available", nil))
		return nil
	}
	token := chi.URLParam(r, "token")
	s, n, err := d.Shares.Resolve(r.Context(), token)
	if err == nil {
		return &shareReq{d: d, s: s, node: n, token: token}
	}
	if !errors.Is(err, core.ErrNotFound) {
		if html {
			d.Log.Error("resolve share", "err", err, "request_id", httpx.RequestID(r.Context()))
			pages.RenderError(w, r, http.StatusInternalServerError, core.ErrInternal.Code,
				"Something went wrong. Please try again later.")
			return nil
		}
		httpx.Error(w, r, err)
		return nil
	}
	if countFailure && d.Limiter != nil {
		if ok, _ := d.Limiter.Allow(mw.BucketShare, mw.PerIP(r)); !ok {
			w.Header().Set("Retry-After", "60")
			httpx.Error(w, r, core.ErrRateLimited)
			return nil
		}
	}
	if html {
		pages.NotFound(w, r)
	} else {
		httpx.Error(w, r, errShareNotFound())
	}
	return nil
}

// hasAccess reports whether the share password (if any) was entered.
func (sr *shareReq) hasAccess(r *http.Request) bool { return sr.d.Shares.HasAccess(r, sr.s) }

// requireAccess writes 401 when the password cookie is missing.
func (sr *shareReq) requireAccess(w http.ResponseWriter, r *http.Request) bool {
	if sr.hasAccess(r) {
		return true
	}
	httpx.Error(w, r, errPasswordRequired())
	return false
}

// owner returns the principal of the share's creator, carrying the
// visitor's request metadata (public operations act as the owner).
func (sr *shareReq) owner(r *http.Request) (*core.Principal, error) {
	p, err := sr.d.Files.SysPrincipalFor(r.Context(), sr.s.CreatedBy)
	if err != nil {
		if errors.Is(err, core.ErrNotFound) || errors.Is(err, core.ErrForbidden) {
			return nil, errShareNotFound()
		}
		return nil, err
	}
	p = p.Clone()
	m := httpx.Meta(r)
	p.IP, p.UserAgent, p.RequestID = m.IP, m.UserAgent, m.RequestID
	return p, nil
}

// within reports whether id is the share's node or below it.
func (sr *shareReq) within(r *http.Request, id string) (bool, error) {
	if id == "" {
		return false, nil
	}
	if id == sr.s.NodeID {
		return true, nil
	}
	ok, err := sr.d.Files.IsWithin(r.Context(), sr.s.NodeID, id)
	if errors.Is(err, core.ErrNotFound) {
		return false, nil
	}
	return ok, err
}

// canList reports whether visitors may see the share's contents: only when
// downloads or previews are allowed, and for links that accept no uploads
// (the owner chose to show the folder). A file request, or a link that
// accepts uploads with neither downloads nor previews (a drop box, `share
// create --upload --no-download --no-preview`), hides it: otherwise
// uploaders would see each other's files.
func canList(s *core.Share) bool {
	return s.AllowDownload || s.AllowPreview || (s.Kind == core.ShareLink && !s.AllowUpload)
}

func (sr *shareReq) record(r *http.Request, action, nodeID string, bytes int64) {
	if r.Method == http.MethodHead {
		return
	}
	m := httpx.Meta(r)
	a := core.ShareAccess{Action: action, NodeID: nodeID, Bytes: bytes, UserAgent: m.UserAgent}
	if m.IP.IsValid() {
		a.IP = m.IP.String()
	}
	sr.d.Shares.RecordAccess(r.Context(), sr.s, a)
}

// publicShare is the anonymous view of a share.
func publicShare(s *core.Share, n *core.Node) core.PublicShare {
	return core.PublicShare{
		Kind: s.Kind, NodeID: n.ID, NodeName: n.Name, NodeKind: n.Kind, Title: s.Title, Message: s.Message,
		OwnerName: s.CreatedByName, HasPassword: s.HasPassword, AllowDownload: s.AllowDownload,
		AllowPreview: s.AllowPreview, AllowUpload: s.AllowUpload, RequireUploaderName: s.RequireUploaderName,
		UploadMaxFileBytes: s.UploadMaxFileBytes, ExpiresAt: s.ExpiresAt,
	}
}

// lockedShare is what a visitor sees before entering the password.
func lockedShare(s *core.Share) core.PublicShare {
	return core.PublicShare{Kind: s.Kind, Title: s.Title, HasPassword: true}
}

// publicNode strips everything a visitor must not learn from a node (user
// ids, space, hashes, trash state, the parent of the share root) and, where
// the contents are hidden (canList), how many items a folder holds: the
// uploaders of a file request must not learn how many submissions exist.
func publicNode(n core.Node, s *core.Share) core.Node {
	n.CreatedBy, n.UpdatedBy, n.TrashedBy = "", "", ""
	n.SpaceID, n.Path, n.VersionID, n.ContentHash = "", "", "", ""
	n.TrashedAt, n.TrashRoot, n.Starred = nil, false, false
	n.Perm = core.PermView
	n.ThumbBlobID, n.BlobID = "", ""
	if n.ID == s.NodeID {
		n.ParentID = ""
	}
	if !s.AllowPreview && !s.AllowDownload {
		n.HasThumb = false
	}
	if !canList(s) {
		n.ChildCount = nil
	}
	return n
}

// listPage lists a folder of the share for visitors.
func (sr *shareReq) listPage(r *http.Request, folderID string) (core.Page[core.Node], error) {
	q := core.ListQuery{PageReq: httpx.PageReq(r)}
	page, err := sr.d.Files.ListSys(r.Context(), folderID, q)
	if err != nil {
		return core.Page[core.Node]{}, err
	}
	items := make([]core.Node, 0, len(page.Items))
	for _, n := range page.Items {
		if n.TrashedAt != nil {
			continue
		}
		items = append(items, publicNode(n, sr.s))
	}
	return core.NewPage(items, page.NextCursor), nil
}

// ---------- page & info ----------

// pageData is the boot data of the share page: the token plus the same
// information as GET /s/{token}/api (without the listing).
type pageData struct {
	Token string `json:"token"`
	Kind  string `json:"kind"`
	Title string `json:"title"`
	core.PublicShareInfo
}

func page(w http.ResponseWriter, r *http.Request) {
	sr := resolve(w, r, true, false)
	if sr == nil {
		return
	}
	s := sr.s
	issueVisitor(w, r, s)
	data := pageData{Token: sr.token, Kind: s.Kind, Title: s.Title}
	title := s.Title
	if sr.hasAccess(r) {
		n := publicNode(*sr.node, s)
		data.Share, data.Node = publicShare(s, sr.node), &n
		if title == "" {
			title = sr.node.Name
		}
	} else {
		data.Share, data.PasswordRequired = lockedShare(s), true
	}
	if title == "" {
		title = pages.DefaultTitles["share"]
	}
	pages.RenderTitled(w, r, "share", title, data)
}

func info(w http.ResponseWriter, r *http.Request) {
	sr := resolve(w, r, false, false)
	if sr == nil {
		return
	}
	issueVisitor(w, r, sr.s)
	if !sr.hasAccess(r) {
		httpx.OK(w, core.PublicShareInfo{Share: lockedShare(sr.s), PasswordRequired: true})
		return
	}
	n := publicNode(*sr.node, sr.s)
	out := core.PublicShareInfo{Share: publicShare(sr.s, sr.node), Node: &n}
	if sr.node.IsDir() && canList(sr.s) {
		pg, err := sr.listPage(r, sr.node.ID)
		if err != nil {
			httpx.Error(w, r, err)
			return
		}
		out.Items, out.NextCursor = pg.Items, pg.NextCursor
	}
	sr.record(r, core.AccessView, "", 0)
	httpx.OK(w, out)
}

func list(w http.ResponseWriter, r *http.Request) {
	sr := resolve(w, r, false, false)
	if sr == nil || !sr.requireAccess(w, r) {
		return
	}
	if !canList(sr.s) {
		httpx.Error(w, r, core.Errorf(core.ErrForbidden, "the contents of this share are not visible"))
		return
	}
	id := r.URL.Query().Get("node")
	if id == "" {
		id = sr.s.NodeID
	}
	ok, err := sr.within(r, id)
	if err != nil {
		httpx.Error(w, r, err)
		return
	}
	if !ok {
		httpx.Error(w, r, core.NotFoundf("folder not found"))
		return
	}
	folder, err := sr.d.Files.GetSys(r.Context(), id)
	if err != nil || folder.TrashedAt != nil || !folder.IsDir() {
		if err == nil || errors.Is(err, core.ErrNotFound) {
			err = core.NotFoundf("folder not found")
		}
		httpx.Error(w, r, err)
		return
	}
	pg, err := sr.listPage(r, id)
	if err != nil {
		httpx.Error(w, r, err)
		return
	}
	httpx.OK(w, pg)
}

func password(w http.ResponseWriter, r *http.Request) {
	sr := resolve(w, r, false, false)
	if sr == nil {
		return
	}
	in, err := httpx.Decode[core.PasswordInput](r, 8<<10)
	if err != nil {
		httpx.Error(w, r, err)
		return
	}
	if !sr.s.HasPassword {
		httpx.NoContent(w)
		return
	}
	if err := sr.d.Shares.CheckPassword(r.Context(), sr.s, in.Password, httpx.Meta(r)); err != nil {
		if errors.Is(err, core.ErrRateLimited) {
			w.Header().Set("Retry-After", "60")
		}
		httpx.Error(w, r, err)
		return
	}
	c, err := sr.d.Shares.AccessCookie(sr.s)
	if err != nil {
		httpx.Error(w, r, err)
		return
	}
	http.SetCookie(w, c)
	httpx.NoContent(w)
}

// ---------- content ----------

// firstRange reports whether a request starts at byte 0 (no Range header,
// or a range beginning with 0): only those, and full 200 answers, count as
// a download when the share has no download limit (for statistics).
func firstRange(r *http.Request) bool {
	rg := strings.TrimSpace(r.Header.Get("Range"))
	return rg == "" || strings.HasPrefix(rg, "bytes=0-")
}

// download serves a file of the share (§8.2 content rules via ServeBlob).
// Downloads need allow_download, inline previews allow_preview (or
// allow_download).
//
// Counting follows the manual: previews do not count. A preview is a
// request that is really served inline (?inline=1 on a type the allow-list
// shows in the browser — the same decision ServeBlob makes), so the share
// page's own <img>/<video>/<iframe> never consumes max_downloads; previews
// are gated by allow_preview instead. Everything else leaves as an
// attachment and is a download: with max_downloads set every such transfer
// counts, resumed and ranged ones included, so the limit cannot be
// bypassed; without a limit only whole transfers (a 200, or a range
// starting at byte 0) are counted, for statistics. Every counted transfer
// is also logged, so the access log explains the counter. Exhausting the
// limit answers 403.
//
// The count and the access-log row are committed only once
// http.ServeContent has settled on a status that really transfers content
// (see countedBlob): 304, 412 and 416 send no bytes and are therefore
// neither counted nor logged. HEAD never counts or logs.
func download(w http.ResponseWriter, r *http.Request) {
	sr := resolve(w, r, false, true)
	if sr == nil || !sr.requireAccess(w, r) {
		return
	}
	s := sr.s
	inline := r.URL.Query().Get("inline") == "1"
	switch {
	case inline && !s.AllowPreview && !s.AllowDownload:
		httpx.Error(w, r, core.Errorf(core.ErrForbidden, "previews are not allowed for this share"))
		return
	case !inline && !s.AllowDownload:
		httpx.Error(w, r, core.Errorf(core.ErrForbidden, "downloads are not allowed for this share"))
		return
	case inline && !s.AllowPreview:
		inline = false // previews are off but downloads are allowed: serve as an attachment
	}
	id := chi.URLParam(r, "nodeId")
	ok, err := sr.within(r, id)
	if err != nil {
		httpx.Error(w, r, err)
		return
	}
	if !ok {
		httpx.Error(w, r, core.NotFoundf("file not found"))
		return
	}
	node, rs, err := sr.d.Files.OpenSys(r.Context(), id)
	if err != nil {
		if errors.Is(err, core.ErrNotFound) || errors.Is(err, core.ErrInvalid) { // unknown, trashed, or a folder
			err = core.NotFoundf("file not found")
		}
		httpx.Error(w, r, err)
		return
	}
	defer rs.Close()
	if node.IsDir() || node.TrashedAt != nil {
		httpx.Error(w, r, core.NotFoundf("file not found"))
		return
	}
	// inlineOK reports whether the type is shown in the browser at all: the
	// same allow-list ServeBlob applies, so inline && inlineOK is exactly
	// "this response is a preview". Anything else leaves as an attachment
	// and is a download, ?inline=1 or not.
	_, inlineOK := httpx.ContentType(node.MIME)
	if !s.AllowDownload && !inlineOK {
		// Preview-only share: only types that are really shown inline may be
		// served (anything else would be delivered as an attachment).
		httpx.Error(w, r, core.Errorf(core.ErrForbidden, "this file cannot be previewed and downloads are not allowed"))
		return
	}
	etag := verETag(node.VersionID)
	if r.Method == http.MethodHead { // HEAD has no side effects (§8.2)
		httpx.ServeBlob(w, r, node.Name, node.MIME, node.UpdatedAt, etag, inline, rs)
		return
	}
	cb := &countedBlob{ResponseWriter: w, sr: sr, r: r, node: node, preview: inline && inlineOK}
	httpx.ServeBlob(cb, r, node.Name, node.MIME, node.UpdatedAt, etag, inline, rs)
}

// countedBlob defers the download count and the access-log row until
// http.ServeContent commits a status that really transfers content. 304,
// 412 and 416 send no bytes, so they must neither consume max_downloads nor
// appear as a download in the owner's log. The count still runs before the
// first body byte, so a share exhausted by a concurrent visitor is answered
// 403 instead of a truncated body.
type countedBlob struct {
	http.ResponseWriter
	sr      *shareReq
	r       *http.Request
	node    *core.Node
	preview bool // the response is really served inline
	decided bool // the status was seen (commit ran at most once)
	blocked bool // commit refused: the error is out, stop the body
}

// errBlocked stops http.ServeContent's copy once commit refused the
// transfer: the error response is complete, so reading (and decrypting) the
// rest of the file would only waste work and hold the answer back.
var errBlocked = errors.New("sharesapi: body suppressed after an error response")

func (c *countedBlob) WriteHeader(code int) {
	if !c.decided {
		c.decided = true
		if code == http.StatusOK || code == http.StatusPartialContent {
			if err := c.commit(code); err != nil {
				c.blocked = true
				h := c.Header()
				for _, k := range []string{"Content-Length", "Content-Range", "Content-Disposition", "ETag", "Last-Modified"} {
					h.Del(k)
				}
				httpx.Error(c.ResponseWriter, c.r, err)
				return
			}
		}
	}
	if !c.blocked {
		c.ResponseWriter.WriteHeader(code)
	}
}

func (c *countedBlob) Write(p []byte) (int, error) {
	if !c.decided {
		c.WriteHeader(http.StatusOK)
	}
	if c.blocked {
		return 0, errBlocked
	}
	return c.ResponseWriter.Write(p)
}

// commit counts and logs the transfer now that its status is known. A 200
// sends the whole file even when a Range header asked for less (If-Range
// mismatch, ranges ServeContent collapsed), so it is judged as a whole
// transfer rather than by the Range header.
func (c *countedBlob) commit(code int) error {
	s := c.sr.s
	whole := code == http.StatusOK || firstRange(c.r)
	counted := false
	if !c.preview && (s.MaxDownloads != nil || whole) {
		if err := c.sr.d.Shares.CountDownload(c.r.Context(), s); err != nil {
			if errors.Is(err, core.ErrForbidden) {
				c.sr.record(c.r, core.AccessBlocked, c.node.ID, 0)
			}
			return err
		}
		counted = true
	}
	if counted || whole {
		action := core.AccessDownload
		if c.preview {
			action = core.AccessPreview
		}
		c.sr.record(c.r, action, c.node.ID, c.node.Size)
	}
	return nil
}

// verETag is the entity tag of a file of a share: an opaque digest of its
// version id. Version ids are internal (publicNode strips them from every
// JSON answer), so the raw id must not reach a visitor as an entity tag
// either. Only the shape changes: the tag is still stable per version, so
// If-None-Match and If-Range keep working, and entity tags are per-URL, so
// the authenticated route keeps serving the raw id (DESIGN §8.2). A node
// without a version keeps getting no tag at all rather than the digest of
// the empty id, which every such node would share.
func verETag(versionID string) string {
	if versionID == "" {
		return ""
	}
	sum := sha256.Sum256([]byte("fp-ver|" + versionID))
	return "v" + hex.EncodeToString(sum[:12])
}

// thumb serves the thumbnail of a file of the share (allow_preview or
// allow_download). Thumbnails are not counted.
func thumb(w http.ResponseWriter, r *http.Request) {
	sr := resolve(w, r, false, true)
	if sr == nil || !sr.requireAccess(w, r) {
		return
	}
	if !sr.s.AllowPreview && !sr.s.AllowDownload {
		httpx.Error(w, r, core.Errorf(core.ErrForbidden, "previews are not allowed for this share"))
		return
	}
	id := chi.URLParam(r, "nodeId")
	ok, err := sr.within(r, id)
	if err != nil {
		httpx.Error(w, r, err)
		return
	}
	if !ok {
		httpx.Error(w, r, core.NotFoundf("thumbnail not found"))
		return
	}
	if n, err := sr.d.Files.GetSys(r.Context(), id); err != nil || n.TrashedAt != nil {
		if err == nil || errors.Is(err, core.ErrNotFound) {
			err = core.NotFoundf("thumbnail not found")
		}
		httpx.Error(w, r, err)
		return
	}
	p, err := sr.owner(r)
	if err != nil {
		httpx.Error(w, r, err)
		return
	}
	rs, err := sr.d.Files.Thumbnail(r.Context(), p, id)
	if err != nil {
		httpx.Error(w, r, err)
		return
	}
	defer rs.Close()
	mime := "image/jpeg"
	var magic [8]byte
	if n, _ := rs.ReadAt(magic[:], 0); n == 8 && string(magic[:]) == "\x89PNG\r\n\x1a\n" {
		mime = "image/png"
	}
	httpx.ServeBlob(w, r, "thumbnail", mime, timeZero, thumbETag(rs.ID()), true, rs)
}

// thumbETag is the entity tag of a thumbnail blob: an opaque digest of its
// id. Blob ids are internal (publicNode strips them from every JSON answer,
// and an id names the file on disk), so the raw id must not reach a
// visitor as an entity tag either. The formula matches the authenticated
// route (filesapi), so both agree on the tag of a given thumbnail.
func thumbETag(blobID string) string {
	sum := sha256.Sum256([]byte("fp-thumb|" + blobID))
	return "t" + hex.EncodeToString(sum[:12])
}

// archive issues a single-use archive ticket for nodes of the share.
func archive(w http.ResponseWriter, r *http.Request) {
	sr := resolve(w, r, false, false)
	if sr == nil || !sr.requireAccess(w, r) {
		return
	}
	if !sr.s.AllowDownload {
		httpx.Error(w, r, core.Errorf(core.ErrForbidden, "downloads are not allowed for this share"))
		return
	}
	in, err := httpx.Decode[core.ArchiveInput](r, 0)
	if err != nil {
		httpx.Error(w, r, err)
		return
	}
	if len(in.NodeIDs) == 0 {
		in.NodeIDs = []string{sr.s.NodeID}
	}
	if len(in.NodeIDs) > maxArchiveIDs {
		httpx.Error(w, r, core.Invalid("node_ids", "too many items; download the folder instead"))
		return
	}
	switch in.Format {
	case "":
		in.Format = core.ArchiveZip
	case core.ArchiveZip, core.ArchiveTar:
	default:
		httpx.Error(w, r, core.Invalid("format", `format must be "zip" or "tar"`))
		return
	}
	for _, id := range in.NodeIDs {
		ok, err := sr.within(r, id)
		if err != nil {
			httpx.Error(w, r, err)
			return
		}
		if !ok {
			httpx.Error(w, r, core.NotFoundf("item not found"))
			return
		}
	}
	if in.Name != "" {
		name, _, err := names.Clean(in.Name)
		if err != nil {
			httpx.Error(w, r, core.Invalid("name", "invalid archive name"))
			return
		}
		in.Name = name
	} else {
		in.Name = sr.s.Title
		if in.Name == "" {
			in.Name = sr.node.Name
		}
		if n, _, err := names.Clean(in.Name); err == nil {
			in.Name = n
		} else {
			in.Name = "download"
		}
	}
	p, err := sr.owner(r)
	if err != nil {
		httpx.Error(w, r, err)
		return
	}
	ticket, err := sr.d.Files.CreateArchiveTicket(r.Context(), p, sr.s.ID, in)
	if err != nil {
		httpx.Error(w, r, err)
		return
	}
	httpx.OK(w, core.ArchiveTicketResponse{Ticket: ticket, URL: "/s/" + sr.token + "/zip/" + ticket})
}

// ticketPeeker is implemented by the files service: it validates a ticket
// without consuming it (HEAD requests must not burn the single use).
type ticketPeeker interface {
	PeekArchiveTicket(ctx context.Context, ticket string) (*core.ArchiveTicket, error)
}

// archiveMIME is the media type of an archive format.
func archiveMIME(format string) string {
	if format == core.ArchiveTar {
		return "application/x-tar"
	}
	return "application/zip"
}

// zipDownload streams an archive for a ticket issued by archive. The ticket
// is consumed (single use); HEAD validates the ticket (without consuming
// it) and answers the same headers the download would carry, so a
// pre-flight never reports an unknown ticket as ready.
//
// Like the authenticated archive route (filesapi), the response is held
// back until the archive's first byte (archiveWriter): an error found before
// any output — an item trashed or moved out of the share since the ticket
// was issued, the link disabled meanwhile — is a normal API error, and the
// download is counted (one download; 403 once the limit is reached) and
// logged only then, so a failed archive never consumes max_downloads. A
// failure while streaming aborts the connection, so the visitor never
// mistakes a truncated archive for a complete one.
func zipDownload(w http.ResponseWriter, r *http.Request) {
	sr := resolve(w, r, false, false)
	if sr == nil || !sr.requireAccess(w, r) {
		return
	}
	if !sr.s.AllowDownload {
		httpx.Error(w, r, core.Errorf(core.ErrForbidden, "downloads are not allowed for this share"))
		return
	}
	ticket := chi.URLParam(r, "ticket")
	// The uniform answer for every unusable ticket (no oracle).
	expired := core.NotFoundf("this download link has expired; please try again")
	if r.Method == http.MethodHead {
		name, mime := "download.zip", "application/zip"
		if pk, ok := sr.d.Files.(ticketPeeker); ok {
			t, err := pk.PeekArchiveTicket(r.Context(), ticket)
			if err != nil || t == nil || t.ShareID != sr.s.ID {
				httpx.Error(w, r, expired)
				return
			}
			name, mime = t.Name, archiveMIME(t.Format)
		}
		httpx.ContentHeaders(w, mime, false)
		httpx.Attachment(w, name, false)
		w.WriteHeader(http.StatusOK)
		return
	}
	ctx := r.Context()
	t, err := sr.d.Files.ConsumeArchiveTicket(ctx, ticket)
	if err != nil || t == nil || t.ShareID != sr.s.ID {
		httpx.Error(w, r, expired)
		return
	}
	aw := &archiveWriter{w: w, start: func() error {
		if err := sr.d.Shares.CountDownload(ctx, sr.s); err != nil {
			if errors.Is(err, core.ErrForbidden) {
				sr.record(r, core.AccessBlocked, "", 0)
			}
			return err
		}
		sr.record(r, core.AccessZip, "", 0)
		httpx.ContentHeaders(w, archiveMIME(t.Format), false)
		httpx.Attachment(w, t.Name, false)
		w.WriteHeader(http.StatusOK)
		return nil
	}}
	err = sr.d.Files.WriteArchive(ctx, t, aw)
	if err == nil {
		err = aw.begin() // an archive always has bytes; be safe anyway
	}
	switch {
	case err == nil:
	case !aw.started:
		if aw.err != nil { // the count refused (limit reached, share gone)
			err = aw.err
		}
		httpx.Error(w, r, err)
	default:
		if ctx.Err() == nil {
			sr.d.Log.Warn("share archive failed", "share", sr.s.ID, "err", err, "request_id", httpx.RequestID(ctx))
		}
		// The status line is out: abort the connection (no final chunk /
		// RST_STREAM) instead of ending a truncated archive cleanly.
		panic(http.ErrAbortHandler)
	}
}

// archiveWriter defers the response headers of a share archive — and with
// them the download count and the access-log row — until the first byte, so
// errors found before any output can still become proper API errors (the
// filesapi lazyWriter, with a start that may refuse). When start fails,
// nothing is written: Write returns the error, which stops the archive.
type archiveWriter struct {
	w       http.ResponseWriter
	start   func() error
	started bool
	err     error // start's refusal
}

func (a *archiveWriter) begin() error {
	if !a.started && a.err == nil {
		if a.err = a.start(); a.err == nil {
			a.started = true
		}
	}
	return a.err
}

// Write implements io.Writer.
func (a *archiveWriter) Write(p []byte) (int, error) {
	if err := a.begin(); err != nil {
		return 0, err
	}
	return a.w.Write(p)
}

// parsePart parses the {n} segment of a part upload.
func parsePart(s string) (int, error) {
	if s == "" || len(s) > 7 || strings.TrimLeft(s, "0123456789") != "" {
		return 0, core.Invalid("n", "the part number must be a non-negative integer")
	}
	n, err := strconv.Atoi(s)
	if err != nil || n > 1<<20 {
		return 0, core.Invalid("n", "the part number is out of range")
	}
	return n, nil
}
