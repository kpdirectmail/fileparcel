// Package filesapi owns /api/v1/spaces, /nodes*, /trash*, /search, /recent,
// /starred, /shared-with-me, /archives* and /admin/grants (DESIGN §9.4, unit
// D). All F (RequireFull) except the archive download, whose ticket is the
// credential, and /admin/grants, which needs Cap(users.view)
// (mw.RequireCap):
//
//	GET    /spaces                                   → []core.Space
//	GET    /nodes/{id}                               → core.Node
//	PATCH  /nodes/{id} {name}                        → core.Node (rename)
//	GET    /nodes/{id}/children?cursor&limit&sort=name|size|updated|kind&desc&kind=file|folder
//	                                                 → core.Page[core.Node]
//	GET    /nodes/{id}/breadcrumbs                   → []core.Node (outermost first)
//	POST   /nodes/{id}/folders {name}                → 201 core.Node
//	POST   /nodes/move {ids,dest,conflict}           → []core.Node (conflict default fail)
//	POST   /nodes/copy {ids,dest,conflict}           → []core.Node (conflict default rename)
//	POST   /nodes/trash {ids}                        → 204
//	GET    /nodes/{id}/content[?version=ver_…][&inline=1]   (user content, §8.2)
//	GET    /nodes/{id}/thumb                         → image/jpeg | image/png, 404 when absent
//	GET    /nodes/{id}/stats                         → core.FolderStats
//	GET    /nodes/{id}/versions                      → []core.FileVersion (newest first)
//	POST   /nodes/{id}/versions/{vid}/restore        → core.Node
//	GET    /nodes/{id}/grants                        → []core.Grant (inherited ones first)
//	POST   /nodes/{id}/grants core.GrantInput        → core.Grant (create or update)
//	DELETE /nodes/{id}/grants/{gid}                  → 204
//	PUT    /nodes/{id}/star                          → 204
//	DELETE /nodes/{id}/star                          → 204
//	GET    /trash?cursor&limit&sort&desc&kind        → core.Page[core.Node] (newest first)
//	POST   /trash/restore {ids}                      → []core.Node
//	POST   /trash/purge {ids}                        → 204
//	DELETE /trash                                    → 204 (empty the trash)
//	GET    /search?q=&space=&kind=&cursor&limit&sort&desc → core.Page[core.Node]
//	GET    /recent?limit=                            → []core.Node
//	GET    /starred?cursor&limit&sort&desc&kind      → core.Page[core.Node]
//	GET    /shared-with-me?cursor&limit&sort&desc&kind → core.Page[core.Node]
//	POST   /archives core.ArchiveInput               → core.ArchiveTicketResponse
//	GET    /archives/{ticket}                        → streamed zip / tar (no auth beyond the ticket)
//	GET    /admin/grants?subject_type=user|group|role&subject_id=&expand=1
//	                                                 → core.SubjectGrants (Cap(users.view); names only
//	                                                   of the items the caller may see, the rest counted)
//
// Paginated listings answer {"items":[…],"next_cursor":"…"}; the other
// lists are bare JSON arrays (the CLI and the frontend read them that way).
// Permissions (404 for invisible nodes, 403 for insufficient rights), token
// scopes (files:read / files:write) and audit entries are enforced by the
// files service; the routes repeat the scope check as defense in depth.
//
// HEAD requests reach the GET handlers (middleware.GetHead): they never
// consume an archive ticket and never audit a download.
package filesapi

import (
	"log/slog"
	"net/http"
	"strconv"
	"strings"

	"github.com/go-chi/chi/v5"

	"fileparcel/internal/app"
	"fileparcel/internal/core"
	"fileparcel/internal/web/httpx"
	"fileparcel/internal/web/mw"
)

// maxJSONBody bounds the JSON request bodies of this package (a move of
// 1000 ids is ~40 KiB).
const maxJSONBody = 256 << 10

// Mount registers this package's routes on the /api/v1 router.
func Mount(api chi.Router, d *app.Deps) {
	h := &handlers{d: d}

	// Reads (PermView; token scope files:read).
	api.Group(func(r chi.Router) {
		r.Use(mw.RequireFull, mw.RequireScope(core.ScopeFilesRead))
		r.Get("/spaces", h.spaces)
		r.Get("/nodes/{id}", h.get)
		r.Get("/nodes/{id}/children", h.children)
		r.Get("/nodes/{id}/breadcrumbs", h.breadcrumbs)
		r.Get("/nodes/{id}/content", h.content)
		r.Get("/nodes/{id}/thumb", h.thumb)
		r.Get("/nodes/{id}/stats", h.stats)
		r.Get("/nodes/{id}/versions", h.versions)
		r.Get("/nodes/{id}/grants", h.grants)
		r.Get("/trash", h.listTrash)
		r.Get("/search", h.search)
		r.Get("/recent", h.recent)
		r.Get("/starred", h.starred)
		r.Get("/shared-with-me", h.sharedWithMe)
		r.With(mw.MaxBody(maxJSONBody)).Post("/archives", h.createArchive)
	})

	// Changes (token scope files:write).
	api.Group(func(r chi.Router) {
		r.Use(mw.RequireFull, mw.RequireScope(core.ScopeFilesWrite), mw.MaxBody(maxJSONBody))
		r.Patch("/nodes/{id}", h.rename)
		r.Post("/nodes/{id}/folders", h.mkdir)
		r.Post("/nodes/move", h.move)
		r.Post("/nodes/copy", h.copy)
		r.Post("/nodes/trash", h.trash)
		r.Post("/nodes/{id}/versions/{vid}/restore", h.restoreVersion)
		r.Post("/nodes/{id}/grants", h.setGrant)
		r.Delete("/nodes/{id}/grants/{gid}", h.removeGrant)
		// Starring writes the stars table (files.Star), so it belongs to
		// files:write even though it changes nothing a reader can see.
		r.Put("/nodes/{id}/star", h.star(true))
		r.Delete("/nodes/{id}/star", h.star(false))
		r.Post("/trash/restore", h.restore)
		r.Post("/trash/purge", h.purge)
		r.Delete("/trash", h.emptyTrash)
	})

	// The archive ticket is the credential (single use, 60 s): a plain
	// browser navigation downloads it, with or without a session.
	api.Group(func(r chi.Router) {
		r.Get("/archives/{ticket}", h.archive)
	})

	// Who has access to what (DESIGN §6a): the grants to one subject. The
	// service shows only the items the caller may see (and needs files:read
	// on API tokens, like every listing of names).
	api.Group(func(r chi.Router) {
		r.Use(mw.RequireCap(core.CapUsersView), mw.NoStore)
		r.Get("/admin/grants", h.subjectGrants)
	})
}

// handlers holds the dependencies of the routes.
type handlers struct {
	d *app.Deps
}

// log returns the service logger (slog.Default outside a wired server).
func (h *handlers) log() *slog.Logger {
	if h.d != nil && h.d.Env != nil && h.d.Log != nil {
		return h.d.Log
	}
	return slog.Default()
}

// files returns the files service, or nil (→ 503) when it is not wired.
func (h *handlers) files(w http.ResponseWriter, r *http.Request) core.Files {
	if h.d == nil || h.d.Files == nil {
		httpx.Error(w, r, core.Wrap(core.ErrUnavailable, "the file service is not available", nil))
		return nil
	}
	return h.d.Files
}

// ---------- request helpers ----------

// listQuery parses ?cursor&limit&sort&desc&kind.
func listQuery(r *http.Request) core.ListQuery {
	return core.ListQuery{PageReq: httpx.PageReq(r), Kind: r.URL.Query().Get("kind")}
}

// truthy parses boolean query flags (1, true, yes, on).
func truthy(v string) bool {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "1", "true", "yes", "on":
		return true
	}
	return false
}

// ok writes v with 200, rendering nil slices as [].
func ok[T any](w http.ResponseWriter, list []T) {
	if list == nil {
		list = []T{}
	}
	httpx.OK(w, list)
}

// ---------- spaces & nodes ----------

func (h *handlers) spaces(w http.ResponseWriter, r *http.Request) {
	f := h.files(w, r)
	if f == nil {
		return
	}
	list, err := f.Spaces(r.Context(), mw.Principal(r))
	if err != nil {
		httpx.Error(w, r, err)
		return
	}
	ok(w, list)
}

func (h *handlers) get(w http.ResponseWriter, r *http.Request) {
	f := h.files(w, r)
	if f == nil {
		return
	}
	n, err := f.Get(r.Context(), mw.Principal(r), chi.URLParam(r, "id"))
	if err != nil {
		httpx.Error(w, r, err)
		return
	}
	httpx.OK(w, n)
}

func (h *handlers) children(w http.ResponseWriter, r *http.Request) {
	f := h.files(w, r)
	if f == nil {
		return
	}
	page, err := f.List(r.Context(), mw.Principal(r), chi.URLParam(r, "id"), listQuery(r))
	if err != nil {
		httpx.Error(w, r, err)
		return
	}
	httpx.OK(w, page)
}

func (h *handlers) breadcrumbs(w http.ResponseWriter, r *http.Request) {
	f := h.files(w, r)
	if f == nil {
		return
	}
	list, err := f.Breadcrumbs(r.Context(), mw.Principal(r), chi.URLParam(r, "id"))
	if err != nil {
		httpx.Error(w, r, err)
		return
	}
	ok(w, list)
}

func (h *handlers) mkdir(w http.ResponseWriter, r *http.Request) {
	f := h.files(w, r)
	if f == nil {
		return
	}
	in, err := httpx.Decode[core.NameInput](r, maxJSONBody)
	if err != nil {
		httpx.Error(w, r, err)
		return
	}
	n, err := f.Mkdir(r.Context(), mw.Principal(r), chi.URLParam(r, "id"), in.Name)
	if err != nil {
		httpx.Error(w, r, err)
		return
	}
	httpx.Created(w, n)
}

func (h *handlers) rename(w http.ResponseWriter, r *http.Request) {
	f := h.files(w, r)
	if f == nil {
		return
	}
	in, err := httpx.Decode[core.NameInput](r, maxJSONBody)
	if err != nil {
		httpx.Error(w, r, err)
		return
	}
	n, err := f.Rename(r.Context(), mw.Principal(r), chi.URLParam(r, "id"), in.Name)
	if err != nil {
		httpx.Error(w, r, err)
		return
	}
	httpx.OK(w, n)
}

func (h *handlers) move(w http.ResponseWriter, r *http.Request) {
	f := h.files(w, r)
	if f == nil {
		return
	}
	in, err := httpx.Decode[core.MoveInput](r, maxJSONBody)
	if err != nil {
		httpx.Error(w, r, err)
		return
	}
	if in.Conflict == "" {
		in.Conflict = core.ConflictFail
	}
	list, err := f.Move(r.Context(), mw.Principal(r), in.IDs, in.Dest, in.Conflict)
	if err != nil {
		httpx.Error(w, r, err)
		return
	}
	ok(w, list)
}

func (h *handlers) copy(w http.ResponseWriter, r *http.Request) {
	f := h.files(w, r)
	if f == nil {
		return
	}
	in, err := httpx.Decode[core.MoveInput](r, maxJSONBody)
	if err != nil {
		httpx.Error(w, r, err)
		return
	}
	if in.Conflict == "" {
		in.Conflict = core.ConflictRename
	}
	list, err := f.Copy(r.Context(), mw.Principal(r), in.IDs, in.Dest, in.Conflict)
	if err != nil {
		httpx.Error(w, r, err)
		return
	}
	ok(w, list)
}

func (h *handlers) trash(w http.ResponseWriter, r *http.Request) {
	f := h.files(w, r)
	if f == nil {
		return
	}
	in, err := httpx.Decode[core.NodeIDsInput](r, maxJSONBody)
	if err != nil {
		httpx.Error(w, r, err)
		return
	}
	if err := f.Trash(r.Context(), mw.Principal(r), in.IDs); err != nil {
		httpx.Error(w, r, err)
		return
	}
	httpx.NoContent(w)
}

func (h *handlers) stats(w http.ResponseWriter, r *http.Request) {
	f := h.files(w, r)
	if f == nil {
		return
	}
	st, err := f.Stats(r.Context(), mw.Principal(r), chi.URLParam(r, "id"))
	if err != nil {
		httpx.Error(w, r, err)
		return
	}
	httpx.OK(w, st)
}

// ---------- versions ----------

func (h *handlers) versions(w http.ResponseWriter, r *http.Request) {
	f := h.files(w, r)
	if f == nil {
		return
	}
	list, err := f.Versions(r.Context(), mw.Principal(r), chi.URLParam(r, "id"))
	if err != nil {
		httpx.Error(w, r, err)
		return
	}
	ok(w, list)
}

func (h *handlers) restoreVersion(w http.ResponseWriter, r *http.Request) {
	f := h.files(w, r)
	if f == nil {
		return
	}
	n, err := f.RestoreVersion(r.Context(), mw.Principal(r), chi.URLParam(r, "id"), chi.URLParam(r, "vid"))
	if err != nil {
		httpx.Error(w, r, err)
		return
	}
	httpx.OK(w, n)
}

// ---------- grants & stars ----------

func (h *handlers) grants(w http.ResponseWriter, r *http.Request) {
	f := h.files(w, r)
	if f == nil {
		return
	}
	list, err := f.Grants(r.Context(), mw.Principal(r), chi.URLParam(r, "id"))
	if err != nil {
		httpx.Error(w, r, err)
		return
	}
	ok(w, list)
}

func (h *handlers) setGrant(w http.ResponseWriter, r *http.Request) {
	f := h.files(w, r)
	if f == nil {
		return
	}
	in, err := httpx.Decode[core.GrantInput](r, maxJSONBody)
	if err != nil {
		httpx.Error(w, r, err)
		return
	}
	g, err := f.SetGrant(r.Context(), mw.Principal(r), chi.URLParam(r, "id"), in)
	if err != nil {
		httpx.Error(w, r, err)
		return
	}
	httpx.OK(w, g)
}

func (h *handlers) removeGrant(w http.ResponseWriter, r *http.Request) {
	f := h.files(w, r)
	if f == nil {
		return
	}
	if err := f.RemoveGrant(r.Context(), mw.Principal(r), chi.URLParam(r, "id"), chi.URLParam(r, "gid")); err != nil {
		httpx.Error(w, r, err)
		return
	}
	httpx.NoContent(w)
}

// subjectGrants answers GET /admin/grants?subject_type=user|group|role
// &subject_id=&expand=1 → core.SubjectGrants: the live grants to the subject
// (with expand for a user, also those to their effective groups and their
// custom role) on the items the caller may see; the rest are counted in
// hidden. 422 for a malformed subject, 404 for an unknown one.
func (h *handlers) subjectGrants(w http.ResponseWriter, r *http.Request) {
	f := h.files(w, r)
	if f == nil {
		return
	}
	q := r.URL.Query()
	res, err := f.SubjectGrants(r.Context(), mw.Principal(r), core.SubjectGrantQuery{
		SubjectType: strings.TrimSpace(q.Get("subject_type")),
		SubjectID:   strings.TrimSpace(q.Get("subject_id")),
		Expand:      truthy(q.Get("expand")),
	})
	if err != nil {
		httpx.Error(w, r, err)
		return
	}
	httpx.OK(w, res)
}

// star returns the PUT (on) / DELETE (off) handler of /nodes/{id}/star. The
// request body, if any, is ignored.
func (h *handlers) star(on bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		f := h.files(w, r)
		if f == nil {
			return
		}
		if err := f.Star(r.Context(), mw.Principal(r), chi.URLParam(r, "id"), on); err != nil {
			httpx.Error(w, r, err)
			return
		}
		httpx.NoContent(w)
	}
}

// ---------- trash ----------

func (h *handlers) listTrash(w http.ResponseWriter, r *http.Request) {
	f := h.files(w, r)
	if f == nil {
		return
	}
	page, err := f.ListTrash(r.Context(), mw.Principal(r), listQuery(r))
	if err != nil {
		httpx.Error(w, r, err)
		return
	}
	httpx.OK(w, page)
}

func (h *handlers) restore(w http.ResponseWriter, r *http.Request) {
	f := h.files(w, r)
	if f == nil {
		return
	}
	in, err := httpx.Decode[core.NodeIDsInput](r, maxJSONBody)
	if err != nil {
		httpx.Error(w, r, err)
		return
	}
	list, err := f.Restore(r.Context(), mw.Principal(r), in.IDs)
	if err != nil {
		httpx.Error(w, r, err)
		return
	}
	ok(w, list)
}

func (h *handlers) purge(w http.ResponseWriter, r *http.Request) {
	f := h.files(w, r)
	if f == nil {
		return
	}
	in, err := httpx.Decode[core.NodeIDsInput](r, maxJSONBody)
	if err != nil {
		httpx.Error(w, r, err)
		return
	}
	if err := f.Purge(r.Context(), mw.Principal(r), in.IDs); err != nil {
		httpx.Error(w, r, err)
		return
	}
	httpx.NoContent(w)
}

func (h *handlers) emptyTrash(w http.ResponseWriter, r *http.Request) {
	f := h.files(w, r)
	if f == nil {
		return
	}
	if err := f.EmptyTrash(r.Context(), mw.Principal(r)); err != nil {
		httpx.Error(w, r, err)
		return
	}
	httpx.NoContent(w)
}

// ---------- search & collections ----------

func (h *handlers) search(w http.ResponseWriter, r *http.Request) {
	f := h.files(w, r)
	if f == nil {
		return
	}
	q := r.URL.Query()
	page, err := f.Search(r.Context(), mw.Principal(r), core.SearchQuery{PageReq: httpx.PageReq(r),
		Q: q.Get("q"), SpaceID: q.Get("space"), Kind: q.Get("kind")})
	if err != nil {
		httpx.Error(w, r, err)
		return
	}
	httpx.OK(w, page)
}

func (h *handlers) recent(w http.ResponseWriter, r *http.Request) {
	f := h.files(w, r)
	if f == nil {
		return
	}
	limit := 0 // service default (50, max 200)
	if v := r.URL.Query().Get("limit"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 0 {
			httpx.Error(w, r, core.Invalid("limit", "limit must be a positive number"))
			return
		}
		limit = n
	}
	list, err := f.Recent(r.Context(), mw.Principal(r), limit)
	if err != nil {
		httpx.Error(w, r, err)
		return
	}
	ok(w, list)
}

func (h *handlers) starred(w http.ResponseWriter, r *http.Request) {
	f := h.files(w, r)
	if f == nil {
		return
	}
	page, err := f.Starred(r.Context(), mw.Principal(r), listQuery(r))
	if err != nil {
		httpx.Error(w, r, err)
		return
	}
	httpx.OK(w, page)
}

func (h *handlers) sharedWithMe(w http.ResponseWriter, r *http.Request) {
	f := h.files(w, r)
	if f == nil {
		return
	}
	page, err := f.SharedWithMe(r.Context(), mw.Principal(r), listQuery(r))
	if err != nil {
		httpx.Error(w, r, err)
		return
	}
	httpx.OK(w, page)
}
