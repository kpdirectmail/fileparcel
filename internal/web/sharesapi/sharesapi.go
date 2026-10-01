// Package sharesapi owns /api/v1/shares*, /admin/shares and the public
// share root /s/{token}… (DESIGN §9.4, unit E).
//
// Mount (under /api/v1; F + token scope "shares"; admin list:
// Cap(shares.manage) = mw.RequireCap(core.CapSharesManage), which owners and
// admins hold and API tokens need the admin scope for):
//
//	GET/POST          /shares                (list mine · create → 201 core.Share with url)
//	GET/PATCH/DELETE  /shares/{id}           (core.ShareUpdate for PATCH)
//	GET               /shares/{id}/log       (Page[core.ShareAccess])
//	GET               /shares/{id}/qr.svg    (QR code of the link)
//	GET               /admin/shares          (?user_id=&kind=&status=&node_id=; every share, links
//	                                         only where the shares service shows them to the caller)
//
// MountRoot (public; no session; mw.CrossOrigin on unsafe methods;
// Referrer-Policy no-referrer and X-Robots-Tag noindex):
//
//	GET  /s/{token}                          HTML via pages.RenderTitled(w, r, "share", title, data)
//	GET  /s/{token}/api                      core.PublicShareInfo (share info + root listing)
//	GET  /s/{token}/api/list?node=&cursor=   core.Page[core.Node]
//	POST /s/{token}/api/password {password}  sets the share access cookie (204)
//	GET  /s/{token}/dl/{nodeId}[?inline=1]   httpx.ServeBlob (§8.2 rules)
//	GET  /s/{token}/thumb/{nodeId}
//	POST /s/{token}/api/archive {node_ids,format,name} → core.ArchiveTicketResponse
//	GET  /s/{token}/zip/{ticket}
//	POST   /s/{token}/api/upload-batches                 (file requests / links with uploads)
//	POST   /s/{token}/api/upload-batches/{id}/files
//	PUT    /s/{token}/api/upload-batches/{id}/small?ref=
//	POST   /s/{token}/api/upload-batches/{id}/complete
//	DELETE /s/{token}/api/upload-batches/{id}
//	GET    /s/{token}/api/upload-batches/{id}               (visitor view; polling)
//	GET    /s/{token}/api/uploads/{id}
//	PUT    /s/{token}/api/uploads/{id}/parts/{n}
//	POST   /s/{token}/api/uploads/{id}/complete
//	DELETE /s/{token}/api/uploads/{id}
//
// Rate limiting (mw.BucketShare = ratelimit.share_per_min, per IP): every
// request of the entry routes (page, info, listing, password, archive,
// batch creation) consumes a token; the high-volume data routes (downloads,
// thumbnails, upload parts and small files, completions) consume one only
// when the token does not resolve, so token guessing stays limited while a
// gallery of thumbnails or a large upload is not throttled. Share passwords
// are additionally limited by the shares service, in buckets of their own:
// per share and IP at the sign-in rate (ratelimit.login_per_min), and wrong
// ones per share across all addresses (see shares.CheckPassword).
//
// Invalid, expired, disabled and exhausted tokens all produce the same
// generic 404 (pages.NotFound for the page, {"error":{"code":"not_found"}}
// for the API). HEAD requests reach the GET handlers: they skip download
// counting, the access log and ticket consumption.
package sharesapi

import (
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"

	"github.com/go-chi/chi/v5"

	"fileparcel/internal/app"
	"fileparcel/internal/core"
	"fileparcel/internal/qr"
	"fileparcel/internal/web/httpx"
	"fileparcel/internal/web/mw"
)

// Mount registers this package's routes on the /api/v1 router.
func Mount(api chi.Router, d *app.Deps) {
	api.Group(func(r chi.Router) {
		r.Use(mw.RequireFull, mw.RequireScope(core.ScopeShares))
		r.Get("/shares", listMine)
		r.Post("/shares", create)
		r.Get("/shares/{id}", get)
		r.Patch("/shares/{id}", update)
		r.Delete("/shares/{id}", revoke)
		r.Get("/shares/{id}/log", accessLog)
		r.Get("/shares/{id}/qr.svg", qrSVG)
	})
	api.Group(func(r chi.Router) {
		r.Use(mw.RequireCap(core.CapSharesManage))
		r.Get("/admin/shares", listAll)
	})
}

func sharesSvc(w http.ResponseWriter, r *http.Request) core.Shares {
	d := mw.Deps(r)
	if d == nil || d.Shares == nil {
		httpx.Error(w, r, core.Wrap(core.ErrUnavailable, "sharing is not available", nil))
		return nil
	}
	return d.Shares
}

func shareQuery(r *http.Request) core.ShareQuery {
	q := r.URL.Query()
	node := q.Get("node_id")
	if node == "" {
		node = q.Get("node")
	}
	return core.ShareQuery{PageReq: httpx.PageReq(r), Kind: q.Get("kind"), NodeID: node,
		UserID: q.Get("user_id"), Status: q.Get("status")}
}

func listMine(w http.ResponseWriter, r *http.Request) {
	svc := sharesSvc(w, r)
	if svc == nil {
		return
	}
	q := shareQuery(r)
	q.UserID = ""
	page, err := svc.List(r.Context(), mw.Principal(r), q)
	if err != nil {
		httpx.Error(w, r, err)
		return
	}
	httpx.OK(w, page)
}

func listAll(w http.ResponseWriter, r *http.Request) {
	svc := sharesSvc(w, r)
	if svc == nil {
		return
	}
	page, err := svc.ListAll(r.Context(), shareQuery(r))
	if err != nil {
		httpx.Error(w, r, err)
		return
	}
	httpx.OK(w, page)
}

func create(w http.ResponseWriter, r *http.Request) {
	svc := sharesSvc(w, r)
	if svc == nil {
		return
	}
	in, err := httpx.Decode[core.ShareInput](r, 0)
	if err != nil {
		httpx.Error(w, r, err)
		return
	}
	s, _, err := svc.Create(r.Context(), mw.Principal(r), in)
	if err != nil {
		httpx.Error(w, r, err)
		return
	}
	httpx.Created(w, s)
}

func get(w http.ResponseWriter, r *http.Request) {
	svc := sharesSvc(w, r)
	if svc == nil {
		return
	}
	s, err := svc.Get(r.Context(), mw.Principal(r), chi.URLParam(r, "id"))
	if err != nil {
		httpx.Error(w, r, err)
		return
	}
	httpx.OK(w, s)
}

func update(w http.ResponseWriter, r *http.Request) {
	svc := sharesSvc(w, r)
	if svc == nil {
		return
	}
	in, err := httpx.Decode[core.ShareUpdate](r, 0)
	if err != nil {
		httpx.Error(w, r, err)
		return
	}
	s, err := svc.Update(r.Context(), mw.Principal(r), chi.URLParam(r, "id"), in)
	if err != nil {
		httpx.Error(w, r, err)
		return
	}
	httpx.OK(w, s)
}

func revoke(w http.ResponseWriter, r *http.Request) {
	svc := sharesSvc(w, r)
	if svc == nil {
		return
	}
	if err := svc.Revoke(r.Context(), mw.Principal(r), chi.URLParam(r, "id")); err != nil {
		httpx.Error(w, r, err)
		return
	}
	httpx.NoContent(w)
}

func accessLog(w http.ResponseWriter, r *http.Request) {
	svc := sharesSvc(w, r)
	if svc == nil {
		return
	}
	page, err := svc.AccessLog(r.Context(), mw.Principal(r), chi.URLParam(r, "id"), httpx.PageReq(r))
	if err != nil {
		httpx.Error(w, r, err)
		return
	}
	httpx.OK(w, page)
}

// qrSVG renders the QR code of a share link (absolute URL: server.public_url
// when configured, else the request's host over https when it names this
// server, else the address the connection arrived on).
func qrSVG(w http.ResponseWriter, r *http.Request) {
	svc := sharesSvc(w, r)
	if svc == nil {
		return
	}
	s, err := svc.Get(r.Context(), mw.Principal(r), chi.URLParam(r, "id"))
	if err != nil {
		httpx.Error(w, r, err)
		return
	}
	if s.URL == "" {
		httpx.Error(w, r, core.NotFoundf("the link of this share is not available"))
		return
	}
	svg, err := qr.SVG(absoluteURL(r, s.URL), qr.Options{Title: "Share link"})
	if err != nil {
		httpx.Error(w, r, core.Wrap(core.ErrInvalid, "the link cannot be encoded as a QR code", err))
		return
	}
	h := w.Header()
	h.Set("Content-Type", "image/svg+xml")
	h.Set("Content-Security-Policy", httpx.CSPContent)
	h.Set("Cache-Control", "private, no-store")
	w.WriteHeader(http.StatusOK)
	if r.Method != http.MethodHead {
		_, _ = w.Write(svg)
	}
}

// absoluteURL makes a root-relative link absolute. The Host header is
// client-controlled, so it is used only when it names this server
// (mw.HostAllowed); a foreign host would otherwise be encoded into the QR
// code and send scanners to someone else's origin with the share token.
// The fallback is the address the connection arrived on, the rule the HTTPS
// redirect of internal/server applies. A link is already absolute when
// server.public_url is set (shares.linkFor), so that case never gets here.
func absoluteURL(r *http.Request, u string) string {
	if !strings.HasPrefix(u, "/") {
		return u
	}
	return "https://" + qrHost(r) + u
}

// qrHost returns a host[:port] that is safe to encode into a link: the
// request's own host when it names this server, else the address the
// client connected to, else "localhost".
func qrHost(r *http.Request) string {
	if r.Host != "" && mw.HostAllowed(mw.Deps(r), r.Host) {
		return r.Host
	}
	if la, ok := r.Context().Value(http.LocalAddrContextKey).(net.Addr); ok {
		if ap, err := netip.ParseAddrPort(la.String()); err == nil {
			return net.JoinHostPort(ap.Addr().Unmap().WithZone("").String(), strconv.Itoa(int(ap.Port())))
		}
	}
	return "localhost"
}
