package sharesapi

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html"
	"io"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"

	"fileparcel/internal/app"
	"fileparcel/internal/core"
	"fileparcel/internal/crypt"
	"fileparcel/internal/db"
	"fileparcel/internal/qr"
	"fileparcel/internal/shares"
	"fileparcel/internal/uploads"
	"fileparcel/internal/uploads/uploadtest"
	"fileparcel/internal/web/httpx"
	"fileparcel/internal/web/mw"
)

type fixture struct {
	*uploadtest.Env
	t     *testing.T
	srv   *httptest.Server
	sh    *shares.Service
	files *peekFiles
	alice string
	root  string
	bob   string
	bobRt string
	admin string
}

func setup(t *testing.T) *fixture {
	t.Helper()
	e := uploadtest.New(t)
	up, err := uploads.New(e.Env, e.Files, e.Blobs, e.Jobs)
	if err != nil {
		t.Fatal(err)
	}
	sh, err := shares.New(e.Env, e.Files, e.Limiter)
	if err != nil {
		t.Fatal(err)
	}
	svcs := &core.Services{Uploads: up, Shares: sh, Notify: e.Notify}
	if err := up.Bind(svcs); err != nil {
		t.Fatal(err)
	}
	if err := sh.Bind(svcs); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = sh.Close() })
	d := e.Deps(up, sh)
	d.Files = &peekFiles{Files: e.Files, tickets: map[string]*core.ArchiveTicket{}}
	r := chi.NewRouter()
	r.Use(mw.Inject(d), middleware.GetHead, mw.RequestID, mw.ResolveClientIP, mw.SecurityHeaders)
	api := chi.NewRouter()
	Mount(api, d)
	r.With(mw.MaxBody(httpx.DefaultMaxBody), mw.Authenticate, mw.CSRF).Mount("/api/v1", api)
	MountRoot(r, d)
	srv := httptest.NewServer(r)
	t.Cleanup(srv.Close)
	f := &fixture{Env: e, t: t, srv: srv, sh: sh, files: d.Files.(*peekFiles)}
	f.alice, f.root = e.User("alice", core.RoleMember)
	f.bob, f.bobRt = e.User("bob", core.RoleMember)
	f.admin, _ = e.User("root", core.RoleAdmin)
	return f
}

// peekFiles adds PeekArchiveTicket to the fake files service, which only
// implements the consuming half. The real service (internal/files) has it,
// and HEAD /s/{token}/zip/{ticket} needs it to validate a ticket without
// burning its single use.
type peekFiles struct {
	*uploadtest.Files
	mu      sync.Mutex
	tickets map[string]*core.ArchiveTicket
	// writeArchive replaces WriteArchive when set (failure injection).
	writeArchive func(ctx context.Context, t *core.ArchiveTicket, w io.Writer) error
}

func (f *peekFiles) setWriteArchive(fn func(ctx context.Context, t *core.ArchiveTicket, w io.Writer) error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.writeArchive = fn
}

func (f *peekFiles) WriteArchive(ctx context.Context, t *core.ArchiveTicket, w io.Writer) error {
	f.mu.Lock()
	fn := f.writeArchive
	f.mu.Unlock()
	if fn != nil {
		return fn(ctx, t, w)
	}
	return f.Files.WriteArchive(ctx, t, w)
}

func (f *peekFiles) CreateArchiveTicket(ctx context.Context, p *core.Principal, shareID string, in core.ArchiveInput) (string, error) {
	tok, err := f.Files.CreateArchiveTicket(ctx, p, shareID, in)
	if err == nil {
		f.mu.Lock()
		f.tickets[tok] = &core.ArchiveTicket{ShareID: shareID, NodeIDs: in.NodeIDs, Format: in.Format, Name: in.Name + "." + in.Format}
		f.mu.Unlock()
	}
	return tok, err
}

func (f *peekFiles) ConsumeArchiveTicket(ctx context.Context, tok string) (*core.ArchiveTicket, error) {
	t, err := f.Files.ConsumeArchiveTicket(ctx, tok)
	if err == nil {
		f.mu.Lock()
		delete(f.tickets, tok)
		f.mu.Unlock()
	}
	return t, err
}

func (f *peekFiles) PeekArchiveTicket(_ context.Context, tok string) (*core.ArchiveTicket, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	t := f.tickets[tok]
	if t == nil {
		return nil, core.NotFoundf("ticket not found")
	}
	return t, nil
}

type reply struct {
	*http.Response
	body []byte
}

func (r reply) json(t *testing.T, v any) {
	t.Helper()
	if err := json.Unmarshal(r.body, v); err != nil {
		t.Fatalf("decode %q: %v", r.body, err)
	}
}

type apiErr struct {
	Error struct{ Code, Message, Field, RequestID string } `json:"error"`
}

func (r reply) wantErr(t *testing.T, status int, code string) {
	t.Helper()
	var e apiErr
	_ = json.Unmarshal(r.body, &e)
	if r.StatusCode != status || e.Error.Code != code {
		t.Fatalf("got %d %q (%s), want %d %q", r.StatusCode, e.Error.Code, r.body, status, code)
	}
}

// req is a request description.
type req struct {
	method, path string
	auth         string // user id for Authorization: Bearer
	host         string // forged Host header
	body         []byte
	json         any
	hdr          map[string]string
	cookies      []*http.Cookie
}

func (f *fixture) do(q req) reply {
	f.t.Helper()
	body := q.body
	if q.json != nil {
		body, _ = json.Marshal(q.json)
	}
	var rd io.Reader
	if body != nil {
		rd = bytes.NewReader(body)
	}
	r, err := http.NewRequest(q.method, f.srv.URL+q.path, rd)
	if err != nil {
		f.t.Fatal(err)
	}
	if q.json != nil {
		r.Header.Set("Content-Type", "application/json")
	}
	if q.auth != "" {
		r.Header.Set("Authorization", "Bearer "+q.auth)
	}
	if q.host != "" {
		r.Host = q.host
	}
	for k, v := range q.hdr {
		r.Header.Set(k, v)
	}
	for _, c := range q.cookies {
		r.AddCookie(&http.Cookie{Name: c.Name, Value: c.Value})
	}
	resp, err := http.DefaultClient.Do(r)
	if err != nil {
		f.t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return reply{Response: resp, body: b}
}

func (f *fixture) share(owner string, in core.ShareInput) (*core.Share, string) {
	f.t.Helper()
	s, tok, err := f.sh.Create(context.Background(), f.P(owner), in)
	if err != nil {
		f.t.Fatalf("create share: %v", err)
	}
	return s, tok
}

// setPassword stores a cheap argon2id hash (password_version bumped).
func (f *fixture) setPassword(shareID, pw string) {
	h, err := crypt.HashPasswordParams(pw, crypt.Argon2Params{MemoryKiB: 64, Time: 1, Threads: 1, SaltLen: 16, KeyLen: 32})
	if err != nil {
		f.t.Fatal(err)
	}
	f.Exec(`UPDATE shares SET password_hash = ?, password_version = password_version + 1 WHERE id = ?`, h, shareID)
}

// tree builds Docs/{readme.txt, photo.jpg, page.html, Sub/{deep.txt}} in
// alice's space and a private file next to it.
type tree struct{ docs, sub, readme, photo, page, deep, private string }

func (f *fixture) tree() tree {
	docs := f.Mkdir(f.root, "Docs")
	sub := f.Mkdir(docs, "Sub")
	return tree{
		docs: docs, sub: sub,
		readme:  f.PutFile(docs, "readme.txt", []byte("read me")).ID,
		photo:   f.PutFile(docs, "photo.jpg", []byte("\xff\xd8\xff\xe0 jpeg")).ID,
		page:    f.PutFile(docs, "page.html", []byte("<script>alert(1)</script>")).ID,
		deep:    f.PutFile(sub, "deep.txt", []byte("deep")).ID,
		private: f.PutFile(f.root, "private.txt", []byte("secret")).ID,
	}
}

var bootRe = regexp.MustCompile(`(?s)<script type="application/json" id="fp-boot">(.*?)</script>`)

func bootData(t *testing.T, page []byte) map[string]any {
	t.Helper()
	m := bootRe.FindSubmatch(page)
	if m == nil {
		t.Fatalf("no boot data in %q", page)
	}
	var b struct {
		Data map[string]any `json:"data"`
	}
	if err := json.Unmarshal([]byte(html.UnescapeString(string(m[1]))), &b); err != nil {
		t.Fatalf("boot json: %v", err)
	}
	return b.Data
}

func sum(b []byte) string { s := sha256.Sum256(b); return hex.EncodeToString(s[:]) }

// ---------- owner API ----------

func TestOwnerAPI(t *testing.T) {
	f := setup(t)
	tr := f.tree()
	var s core.Share
	r := f.do(req{method: "POST", path: "/api/v1/shares", auth: f.alice,
		json: core.ShareInput{NodeID: tr.docs, Title: "Docs", Password: "docs password"}})
	if r.StatusCode != 201 {
		t.Fatalf("create: %d %s", r.StatusCode, r.body)
	}
	r.json(t, &s)
	if !strings.HasPrefix(s.URL, "/s/") || !s.HasPassword || s.NodeName != "Docs" || bytes.Contains(r.body, []byte("argon2")) {
		t.Fatalf("share %+v / %s", s, r.body)
	}
	if err := mw.CheckSecurityHeaders(r.Header, mw.HeadersAPI); err != nil {
		t.Error(err)
	}
	var page core.Page[core.Share]
	f.do(req{method: "GET", path: "/api/v1/shares?kind=link", auth: f.alice}).json(t, &page)
	if len(page.Items) != 1 || page.Items[0].URL != s.URL {
		t.Fatalf("list %+v", page)
	}
	f.do(req{method: "GET", path: "/api/v1/shares", auth: f.bob}).json(t, &page)
	if len(page.Items) != 0 {
		t.Fatal("bob sees alice's shares")
	}
	f.do(req{method: "GET", path: "/api/v1/shares/" + s.ID, auth: f.bob}).wantErr(t, 404, "not_found")
	f.do(req{method: "PATCH", path: "/api/v1/shares/" + s.ID, auth: f.bob, json: map[string]any{"title": "x"}}).wantErr(t, 404, "not_found")

	var u core.Share
	r = f.do(req{method: "PATCH", path: "/api/v1/shares/" + s.ID, auth: f.alice,
		json: map[string]any{"title": "Renamed", "max_downloads": 5, "expires_at": nil}})
	r.json(t, &u)
	if r.StatusCode != 200 || u.Title != "Renamed" || u.MaxDownloads == nil || *u.MaxDownloads != 5 || u.ExpiresAt != nil {
		t.Fatalf("patch %d %s", r.StatusCode, r.body)
	}
	f.do(req{method: "PATCH", path: "/api/v1/shares/" + s.ID, auth: f.alice, json: map[string]any{"bogus": 1}}).wantErr(t, 422, "invalid")

	var log core.Page[core.ShareAccess]
	f.do(req{method: "GET", path: "/api/v1/shares/" + s.ID + "/log", auth: f.alice}).json(t, &log)
	if log.Items == nil {
		t.Fatal("log items null")
	}

	r = f.do(req{method: "GET", path: "/api/v1/shares/" + s.ID + "/qr.svg", auth: f.alice})
	if r.StatusCode != 200 || r.Header.Get("Content-Type") != "image/svg+xml" || !bytes.Contains(r.body, []byte("<svg")) ||
		!strings.Contains(r.Header.Get("Content-Security-Policy"), "sandbox") {
		t.Fatalf("qr: %d %v", r.StatusCode, r.Header)
	}
	f.do(req{method: "GET", path: "/api/v1/shares/" + s.ID + "/qr.svg", auth: f.bob}).wantErr(t, 404, "not_found")
	// The Host header is client-controlled: a foreign one must never be
	// encoded into the QR code, or a scanner is sent to someone else's
	// origin with the share token. The fixture serves on loopback, which
	// mw.HostAllowed accepts, so the forged code must equal the honest one.
	fake := f.do(req{method: "GET", path: "/api/v1/shares/" + s.ID + "/qr.svg", auth: f.alice, host: "evil.example.com"})
	if fake.StatusCode != 200 || !bytes.Equal(fake.body, r.body) {
		t.Fatalf("a foreign Host changed the QR code (%d)", fake.StatusCode)
	}
	want, err := qr.SVG("https://"+strings.TrimPrefix(f.srv.URL, "http://")+s.URL, qr.Options{Title: "Share link"})
	if err != nil || !bytes.Equal(r.body, want) {
		t.Fatalf("the QR code does not encode the loopback link (%v)", err)
	}

	// Scope and role guards.
	f.do(req{method: "GET", path: "/api/v1/shares", auth: f.alice + ";files:read"}).wantErr(t, 403, "forbidden")
	f.do(req{method: "GET", path: "/api/v1/shares"}).wantErr(t, 401, "unauthorized")
	f.do(req{method: "GET", path: "/api/v1/admin/shares", auth: f.alice}).wantErr(t, 403, "forbidden")
	var all core.Page[core.Share]
	f.do(req{method: "GET", path: "/api/v1/admin/shares?user_id=" + f.alice, auth: f.admin}).json(t, &all)
	if len(all.Items) != 1 || all.Items[0].URL != "" {
		t.Fatalf("admin list %+v", all)
	}

	if r := f.do(req{method: "DELETE", path: "/api/v1/shares/" + s.ID, auth: f.alice}); r.StatusCode != 204 {
		t.Fatalf("delete %d", r.StatusCode)
	}
	f.do(req{method: "GET", path: s.URL + "/api"}).wantErr(t, 404, "not_found")
}

// ---------- public page & listing ----------

func TestPublicPageAndListing(t *testing.T) {
	f := setup(t)
	tr := f.tree()
	_, tok := f.share(f.alice, core.ShareInput{NodeID: tr.docs, Title: "Team docs", Message: "Hello"})
	base := "/s/" + tok

	r := f.do(req{method: "GET", path: base})
	if r.StatusCode != 200 || !strings.HasPrefix(r.Header.Get("Content-Type"), "text/html") {
		t.Fatalf("page %d %s", r.StatusCode, r.body)
	}
	if err := mw.CheckSecurityHeaders(r.Header, mw.HeadersPage); err != nil {
		t.Error(err)
	}
	if r.Header.Get("Referrer-Policy") != "no-referrer" || !strings.Contains(r.Header.Get("X-Robots-Tag"), "noindex") {
		t.Errorf("headers %v", r.Header)
	}
	data := bootData(t, r.body)
	share, _ := data["share"].(map[string]any)
	node, _ := data["node"].(map[string]any)
	if data["token"] != tok || data["kind"] != "link" || data["title"] != "Team docs" || share["message"] != "Hello" ||
		share["owner_name"] != "Alice" || node["name"] != "Docs" || data["password_required"] == true {
		t.Fatalf("boot data %v", data)
	}
	if !bytes.Contains(r.body, []byte("<title>Team docs")) {
		t.Error("page title")
	}

	var info core.PublicShareInfo
	r = f.do(req{method: "GET", path: base + "/api"})
	r.json(t, &info)
	var names []string
	for _, n := range info.Items {
		names = append(names, n.Name)
	}
	if info.Node == nil || info.Node.ID != tr.docs || info.Node.ParentID != "" || strings.Join(names, ",") != "Sub,page.html,photo.jpg,readme.txt" {
		t.Fatalf("info %+v (%v)", info, names)
	}
	// Nothing identifying the owner or the rest of the space leaks.
	spaceID := f.Str(`SELECT space_id FROM nodes WHERE id = ?`, tr.docs)
	for _, secret := range []string{f.alice, f.root, spaceID, "private.txt", `"created_by"`, `"content_hash"`, `"version_id"`} {
		if bytes.Contains(r.body, []byte(secret)) {
			t.Errorf("public info leaks %q: %s", secret, r.body)
		}
	}
	var pg core.Page[core.Node]
	f.do(req{method: "GET", path: base + "/api/list?node=" + tr.sub}).json(t, &pg)
	if len(pg.Items) != 1 || pg.Items[0].Name != "deep.txt" || pg.Items[0].CreatedBy != "" {
		t.Fatalf("sub listing %+v", pg)
	}
	f.do(req{method: "GET", path: base + "/api/list?node=" + f.root}).wantErr(t, 404, "not_found")
	f.do(req{method: "GET", path: base + "/api/list?node=" + f.bobRt}).wantErr(t, 404, "not_found")
	f.do(req{method: "GET", path: base + "/api/list?node=" + tr.readme}).wantErr(t, 404, "not_found")
	f.do(req{method: "GET", path: base + "/api/list?node=../../x"}).wantErr(t, 404, "not_found")
	// Trashed content disappears.
	if err := f.Files.Trash(context.Background(), f.P(f.alice), []string{tr.sub}); err != nil {
		t.Fatal(err)
	}
	f.do(req{method: "GET", path: base + "/api/list?node=" + tr.sub}).wantErr(t, 404, "not_found")
	f.do(req{method: "GET", path: base + "/dl/" + tr.deep}).wantErr(t, 404, "not_found")

	// The view is logged (not for HEAD).
	f.do(req{method: "HEAD", path: base + "/api"})
	if n := f.Int(`SELECT COUNT(*) FROM share_access_log WHERE action = 'view'`); n != 1 {
		t.Fatalf("view rows = %d", n)
	}
}

func TestTokenNotFoundUniformity(t *testing.T) {
	f := setup(t)
	tr := f.tree()
	mk := func() (*core.Share, string) {
		return f.share(f.alice, core.ShareInput{NodeID: tr.readme, NoExpiry: true})
	}
	exp, expTok := mk()
	f.Exec(`UPDATE shares SET expires_at = ? WHERE id = ?`, db.Ms(f.Clock.Now()), exp.ID)
	dis, disTok := mk()
	f.Exec(`UPDATE shares SET disabled_at = 1 WHERE id = ?`, dis.ID)
	exh, exhTok := mk()
	f.Exec(`UPDATE shares SET max_downloads = 2, download_count = 2 WHERE id = ?`, exh.ID)
	rev, revTok := mk()
	f.Exec(`DELETE FROM shares WHERE id = ?`, rev.ID)
	tokens := map[string]string{
		"unknown": strings.Repeat("A", 22), "malformed": "not-a-token", "long": strings.Repeat("b", 60),
		"expired": expTok, "disabled": disTok, "exhausted": exhTok, "revoked": revTok,
	}
	strip := func(r reply) string {
		return strings.ReplaceAll(string(r.body), r.Header.Get("X-Request-ID"), "RID")
	}
	var refAPI, refPage, refDL string
	for name, tok := range tokens {
		api := f.do(req{method: "GET", path: "/s/" + tok + "/api"})
		api.wantErr(t, 404, "not_found")
		pg := f.do(req{method: "GET", path: "/s/" + tok})
		dl := f.do(req{method: "GET", path: "/s/" + tok + "/dl/" + tr.readme})
		if pg.StatusCode != 404 || dl.StatusCode != 404 {
			t.Fatalf("%s: page %d dl %d", name, pg.StatusCode, dl.StatusCode)
		}
		if refAPI == "" {
			refAPI, refPage, refDL = strip(api), strip(pg), strip(dl)
			continue
		}
		if strip(api) != refAPI || strip(pg) != refPage || strip(dl) != refDL {
			t.Errorf("%s: response differs from the others", name)
		}
	}
	// Uploading to an invalid token is the same 404.
	f.do(req{method: "POST", path: "/s/" + expTok + "/api/upload-batches", json: map[string]any{}}).wantErr(t, 404, "not_found")
}

// ---------- password ----------

func TestPasswordCookieFlow(t *testing.T) {
	f := setup(t)
	tr := f.tree()
	s, tok := f.share(f.alice, core.ShareInput{NodeID: tr.docs, Title: "Locked"})
	f.setPassword(s.ID, "open sesame")
	base := "/s/" + tok

	var info core.PublicShareInfo
	r := f.do(req{method: "GET", path: base + "/api"})
	r.json(t, &info)
	if r.StatusCode != 200 || !info.PasswordRequired || info.Node != nil || len(info.Items) != 0 || info.Share.Title != "Locked" ||
		!info.Share.HasPassword || bytes.Contains(r.body, []byte("readme")) {
		t.Fatalf("locked info %s", r.body)
	}
	data := bootData(t, f.do(req{method: "GET", path: base}).body)
	if data["password_required"] != true || data["node"] != nil {
		t.Fatalf("locked page data %v", data)
	}
	f.do(req{method: "GET", path: base + "/dl/" + tr.readme}).wantErr(t, 401, "unauthorized")
	f.do(req{method: "GET", path: base + "/api/list?node=" + tr.sub}).wantErr(t, 401, "unauthorized")
	f.do(req{method: "POST", path: base + "/api/archive", json: map[string]any{}}).wantErr(t, 401, "unauthorized")

	f.do(req{method: "POST", path: base + "/api/password", json: core.PasswordInput{Password: "wrong"}}).wantErr(t, 401, "unauthorized")
	// Cross-site form posts are refused before the password is checked.
	f.do(req{method: "POST", path: base + "/api/password", json: core.PasswordInput{Password: "open sesame"},
		hdr: map[string]string{"Sec-Fetch-Site": "cross-site"}}).wantErr(t, 403, "forbidden")
	r = f.do(req{method: "POST", path: base + "/api/password", json: core.PasswordInput{Password: "open sesame"}})
	if r.StatusCode != 204 {
		t.Fatalf("password: %d %s", r.StatusCode, r.body)
	}
	cookies := r.Cookies()
	if len(cookies) != 1 || cookies[0].Name != shares.CookieName(s.ID) || !cookies[0].Secure || !cookies[0].HttpOnly ||
		cookies[0].Path != "/" || cookies[0].SameSite != http.SameSiteLaxMode {
		t.Fatalf("cookie %+v", cookies)
	}
	var open core.PublicShareInfo
	f.do(req{method: "GET", path: base + "/api", cookies: cookies}).json(t, &open)
	if open.PasswordRequired || open.Node == nil || len(open.Items) != 4 || open.Share.OwnerName != "Alice" {
		t.Fatalf("unlocked info %+v", open)
	}
	if r := f.do(req{method: "GET", path: base + "/dl/" + tr.readme, cookies: cookies}); r.StatusCode != 200 || string(r.body) != "read me" {
		t.Fatalf("download with cookie: %d", r.StatusCode)
	}
	// Changing the password invalidates the cookie.
	f.setPassword(s.ID, "new one")
	f.do(req{method: "GET", path: base + "/dl/" + tr.readme, cookies: cookies}).wantErr(t, 401, "unauthorized")

	// Password attempts are rate limited per share and IP at the sign-in
	// rate, far below the generic entry limit of the route: the shares
	// service refuses (and logs it) before the route middleware would.
	f.Limiter.Configure(mw.BucketShare, 1000, 1000)
	f.Settings.Put("ratelimit.login_per_min", 2)
	_, tok2 := f.share(f.alice, core.ShareInput{NodeID: tr.readme})
	s2, _, _ := f.sh.Resolve(context.Background(), tok2)
	f.setPassword(s2.ID, "x")
	for range 2 {
		f.do(req{method: "POST", path: "/s/" + tok2 + "/api/password", json: core.PasswordInput{Password: "nope"}}).wantErr(t, 401, "unauthorized")
	}
	r = f.do(req{method: "POST", path: "/s/" + tok2 + "/api/password", json: core.PasswordInput{Password: "x"}})
	r.wantErr(t, 429, "rate_limited")
	var e apiErr
	_ = json.Unmarshal(r.body, &e)
	if e.Error.Message != "too many password attempts; please wait a minute" {
		t.Errorf("refused by %q, want the share password limit", e.Error.Message)
	}
	if r.Header.Get("Retry-After") == "" {
		t.Error("no Retry-After")
	}
	if n := f.Int(`SELECT COUNT(*) FROM share_access_log WHERE share_id = ? AND action = 'blocked'`, s2.ID); n != 1 {
		t.Errorf("blocked rows = %d, want 1", n)
	}
	// Another share is not affected from the same address.
	if r := f.do(req{method: "POST", path: base + "/api/password", json: core.PasswordInput{Password: "new one"}}); r.StatusCode != 204 {
		t.Fatalf("other share: %d %s", r.StatusCode, r.body)
	}
}

// ---------- downloads ----------

func TestDownloads(t *testing.T) {
	f := setup(t)
	tr := f.tree()
	s, tok := f.share(f.alice, core.ShareInput{NodeID: tr.docs})
	base := "/s/" + tok

	r := f.do(req{method: "GET", path: base + "/dl/" + tr.readme})
	if r.StatusCode != 200 || string(r.body) != "read me" || !strings.HasPrefix(r.Header.Get("Content-Disposition"), "attachment") {
		t.Fatalf("download %d %v", r.StatusCode, r.Header)
	}
	if err := mw.CheckSecurityHeaders(r.Header, mw.HeadersContent); err != nil {
		t.Error(err)
	}
	// The entity tag must be opaque: publicNode strips the version id from
	// every JSON answer, so it must not leak through a header either. It
	// must still work as a cache validator.
	vid := f.Str(`SELECT version_id FROM nodes WHERE id = ?`, tr.readme)
	et := r.Header.Get("ETag")
	if vid == "" || et == "" || strings.Contains(et, vid) || strings.Contains(et, "ver_") {
		t.Fatalf("public download ETag must not reveal the version id: %q (version %q)", et, vid)
	}
	if c := f.do(req{method: "GET", path: base + "/dl/" + tr.readme, hdr: map[string]string{"If-None-Match": et}}); c.StatusCode != 304 {
		t.Fatalf("If-None-Match with the public ETag: %d, want 304", c.StatusCode)
	}
	r = f.do(req{method: "GET", path: base + "/dl/" + tr.photo + "?inline=1"})
	if r.StatusCode != 200 || r.Header.Get("Content-Type") != "image/jpeg" || !strings.HasPrefix(r.Header.Get("Content-Disposition"), "inline") {
		t.Fatalf("inline image %d %v", r.StatusCode, r.Header)
	}
	r = f.do(req{method: "GET", path: base + "/dl/" + tr.page + "?inline=1"})
	if r.StatusCode != 200 || r.Header.Get("Content-Type") != "application/octet-stream" ||
		!strings.HasPrefix(r.Header.Get("Content-Disposition"), "attachment") || !strings.Contains(r.Header.Get("Content-Security-Policy"), "sandbox") {
		t.Fatalf("html must be an attachment: %v", r.Header)
	}
	// Range request.
	r = f.do(req{method: "GET", path: base + "/dl/" + tr.readme, hdr: map[string]string{"Range": "bytes=2-4"}})
	if r.StatusCode != 206 || string(r.body) != "ad " {
		t.Fatalf("range %d %q", r.StatusCode, r.body)
	}
	// Outside the share, folders, junk ids.
	f.do(req{method: "GET", path: base + "/dl/" + tr.private}).wantErr(t, 404, "not_found")
	f.do(req{method: "GET", path: base + "/dl/" + tr.sub}).wantErr(t, 404, "not_found")
	f.do(req{method: "GET", path: base + "/dl/nod_doesnotexist"}).wantErr(t, 404, "not_found")
	f.do(req{method: "GET", path: base + "/thumb/" + tr.private}).wantErr(t, 404, "not_found")
	f.do(req{method: "GET", path: base + "/thumb/" + tr.photo}).wantErr(t, 404, "not_found") // no thumbnail yet

	counted := f.Int(`SELECT download_count FROM shares WHERE id = ?`, s.ID)
	logged := f.Int(`SELECT COUNT(*) FROM share_access_log`)
	f.do(req{method: "HEAD", path: base + "/dl/" + tr.readme})
	if f.Int(`SELECT download_count FROM shares WHERE id = ?`, s.ID) != counted || f.Int(`SELECT COUNT(*) FROM share_access_log`) != logged {
		t.Fatal("HEAD counted or logged")
	}

	// Thumbnails.
	w, _ := f.Blobs.Create(context.Background())
	_, _ = w.Write([]byte("\x89PNG\r\n\x1a\nrest"))
	thumb, _ := w.Commit(context.Background())
	f.Exec(`UPDATE nodes SET thumb_blob_id = ? WHERE id = ?`, thumb.ID, tr.photo)
	r = f.do(req{method: "GET", path: base + "/thumb/" + tr.photo})
	if r.StatusCode != 200 || r.Header.Get("Content-Type") != "image/png" {
		t.Fatalf("thumb %d %v", r.StatusCode, r.Header)
	}
	// The entity tag must be opaque: blob ids are internal (they name the
	// file on disk) and publicNode strips them from every JSON answer.
	if et := r.Header.Get("ETag"); et == "" || strings.Contains(et, thumb.ID) {
		t.Fatalf("public thumb ETag must not reveal the blob id: %q (blob %q)", et, thumb.ID)
	}

	// Preview-only share: inline media only.
	po, poTok := f.share(f.alice, core.ShareInput{NodeID: tr.docs, AllowDownload: ptr(false)})
	f.do(req{method: "GET", path: "/s/" + poTok + "/dl/" + tr.readme}).wantErr(t, 403, "forbidden")
	if r := f.do(req{method: "GET", path: "/s/" + poTok + "/dl/" + tr.photo + "?inline=1"}); r.StatusCode != 200 {
		t.Fatalf("preview %d", r.StatusCode)
	}
	f.do(req{method: "GET", path: "/s/" + poTok + "/dl/" + tr.page + "?inline=1"}).wantErr(t, 403, "forbidden")
	f.do(req{method: "POST", path: "/s/" + poTok + "/api/archive", json: map[string]any{}}).wantErr(t, 403, "forbidden")
	// Downloads without previews: inline requests become attachments.
	_, npTok := f.share(f.alice, core.ShareInput{NodeID: tr.docs, AllowPreview: ptr(false)})
	if r := f.do(req{method: "GET", path: "/s/" + npTok + "/dl/" + tr.photo + "?inline=1"}); r.StatusCode != 200 ||
		!strings.HasPrefix(r.Header.Get("Content-Disposition"), "attachment") {
		t.Fatalf("no-preview inline: %d %v", r.StatusCode, r.Header)
	}
	// Neither download nor preview: no thumbnails either.
	f.Exec(`UPDATE shares SET allow_preview = 0 WHERE id = ?`, po.ID)
	f.do(req{method: "GET", path: "/s/" + poTok + "/thumb/" + tr.photo}).wantErr(t, 403, "forbidden")
	f.do(req{method: "GET", path: "/s/" + poTok + "/dl/" + tr.photo + "?inline=1"}).wantErr(t, 403, "forbidden")
}

func TestMaxDownloadsConcurrent(t *testing.T) {
	f := setup(t)
	tr := f.tree()
	s, tok := f.share(f.alice, core.ShareInput{NodeID: tr.readme, MaxDownloads: ptr(int64(3))})
	var mu sync.Mutex
	codes := map[int]int{}
	var wg sync.WaitGroup
	for range 20 {
		wg.Go(func() {
			r := f.do(req{method: "GET", path: "/s/" + tok + "/dl/" + tr.readme})
			mu.Lock()
			codes[r.StatusCode]++
			mu.Unlock()
		})
	}
	wg.Wait()
	if codes[200] != 3 || codes[403]+codes[404] != 17 {
		t.Fatalf("status counts %v", codes)
	}
	if n := f.Int(`SELECT download_count FROM shares WHERE id = ?`, s.ID); n != 3 {
		t.Fatalf("download_count = %d", n)
	}
	f.do(req{method: "GET", path: "/s/" + tok + "/api"}).wantErr(t, 404, "not_found")
}

// TestMaxDownloadsIgnoresPreviews pins the manual's contract: previews do
// not count against max_downloads. The share page renders its own
// <img src=…?inline=1>, so counting previews let the page itself spend the
// limit before the visitor could click Download. A request that only says
// ?inline=1 but leaves as an attachment is a download and still counts, so
// the limit cannot be bypassed either.
func TestMaxDownloadsIgnoresPreviews(t *testing.T) {
	f := setup(t)
	tr := f.tree()
	s, tok := f.share(f.alice, core.ShareInput{NodeID: tr.docs, MaxDownloads: ptr(int64(2))})
	base := "/s/" + tok
	count := func() int64 { return f.Int(`SELECT download_count FROM shares WHERE id = ?`, s.ID) }
	actions := func(a string) int64 {
		return f.Int(`SELECT COUNT(*) FROM share_access_log WHERE share_id = ? AND action = ?`, s.ID, a)
	}

	// The page's own preview, and a seek inside it, are free.
	if r := f.do(req{method: "GET", path: base + "/dl/" + tr.photo + "?inline=1"}); r.StatusCode != 200 {
		t.Fatalf("preview %d", r.StatusCode)
	}
	if r := f.do(req{method: "GET", path: base + "/dl/" + tr.photo + "?inline=1",
		hdr: map[string]string{"Range": "bytes=2-4"}}); r.StatusCode != 206 {
		t.Fatalf("preview seek %d", r.StatusCode)
	}
	if n := count(); n != 0 {
		t.Fatalf("previews counted: download_count = %d", n)
	}
	if n := actions(core.AccessPreview); n != 1 {
		t.Fatalf("preview rows = %d, want 1", n)
	}

	// ?inline=1 on a type that is never shown inline leaves as an
	// attachment: it is a download, counted and logged as one.
	if r := f.do(req{method: "GET", path: base + "/dl/" + tr.page + "?inline=1"}); r.StatusCode != 200 ||
		!strings.HasPrefix(r.Header.Get("Content-Disposition"), "attachment") {
		t.Fatalf("attachment despite ?inline=1: %d %v", r.StatusCode, r.Header)
	}
	if n := count(); n != 1 {
		t.Fatalf("download_count = %d, want 1", n)
	}
	if n := actions(core.AccessDownload); n != 1 {
		t.Fatalf("download rows = %d, want 1", n)
	}
	// A resumed download counts too while a limit applies (no bypass).
	if r := f.do(req{method: "GET", path: base + "/dl/" + tr.readme,
		hdr: map[string]string{"Range": "bytes=3-"}}); r.StatusCode != 206 {
		t.Fatalf("resumed download %d", r.StatusCode)
	}
	if n := count(); n != 2 {
		t.Fatalf("download_count = %d, want 2", n)
	}
	// ... and is logged, so the access log explains the counter.
	if n := actions(core.AccessDownload); n != 2 {
		t.Fatalf("download rows = %d, want 2 (a counted resume must be logged)", n)
	}
	f.do(req{method: "GET", path: base + "/api"}).wantErr(t, 404, "not_found") // exhausted

	// A preview-only link (no downloads) never consumes its limit.
	po, poTok := f.share(f.alice, core.ShareInput{NodeID: tr.docs, AllowDownload: ptr(false), MaxDownloads: ptr(int64(1))})
	for range 3 {
		if r := f.do(req{method: "GET", path: "/s/" + poTok + "/dl/" + tr.photo + "?inline=1"}); r.StatusCode != 200 {
			t.Fatalf("preview-only share: %d", r.StatusCode)
		}
	}
	if n := f.Int(`SELECT download_count FROM shares WHERE id = ?`, po.ID); n != 0 {
		t.Fatalf("preview-only download_count = %d", n)
	}
}

// TestNoBytesNoDownload pins that a response which transfers nothing is
// neither counted nor logged: a browser revalidating its cache (304) or a
// client asking for a range past the end (416) would otherwise drain
// max_downloads and write "download" rows of the full file size.
func TestNoBytesNoDownload(t *testing.T) {
	f := setup(t)
	tr := f.tree()
	s, tok := f.share(f.alice, core.ShareInput{NodeID: tr.docs, MaxDownloads: ptr(int64(5))})
	dl := "/s/" + tok + "/dl/" + tr.readme
	count := func() int64 { return f.Int(`SELECT download_count FROM shares WHERE id = ?`, s.ID) }
	logged := func() int64 { return f.Int(`SELECT COUNT(*) FROM share_access_log WHERE share_id = ?`, s.ID) }

	r := f.do(req{method: "GET", path: dl})
	if r.StatusCode != 200 {
		t.Fatalf("download %d", r.StatusCode)
	}
	etag, mod := r.Header.Get("ETag"), r.Header.Get("Last-Modified")
	if etag == "" || mod == "" {
		t.Fatalf("no cache validators: %v", r.Header)
	}
	if count() != 1 || logged() != 1 {
		t.Fatalf("first download: count %d, log %d", count(), logged())
	}
	for _, c := range []struct {
		want int
		hdr  map[string]string
	}{
		{304, map[string]string{"If-None-Match": etag}},
		{304, map[string]string{"If-Modified-Since": mod}},
		{416, map[string]string{"Range": "bytes=9999-"}},
	} {
		got := f.do(req{method: "GET", path: dl, hdr: c.hdr})
		if got.StatusCode != c.want {
			t.Fatalf("%v: %d, want %d", c.hdr, got.StatusCode, c.want)
		}
		if got.StatusCode == 304 && len(got.body) != 0 {
			t.Fatalf("304 with a body: %q", got.body)
		}
	}
	if count() != 1 || logged() != 1 {
		t.Fatalf("a response without bytes counted: count %d, log %d", count(), logged())
	}
	// Real transfers still count, whole or ranged.
	if got := f.do(req{method: "GET", path: dl, hdr: map[string]string{"Range": "bytes=0-2"}}); got.StatusCode != 206 {
		t.Fatalf("range %d", got.StatusCode)
	}
	if count() != 2 || logged() != 2 {
		t.Fatalf("range from byte 0: count %d, log %d", count(), logged())
	}

	// Without a limit only whole transfers count (statistics): a resume
	// neither counts nor logs, but a stale If-Range makes ServeContent send
	// the whole file (200) whatever the Range says, and that is a download.
	free, freeTok := f.share(f.alice, core.ShareInput{NodeID: tr.docs})
	freeDl := "/s/" + freeTok + "/dl/" + tr.readme
	freeCount := func() int64 { return f.Int(`SELECT download_count FROM shares WHERE id = ?`, free.ID) }
	freeRows := func() int64 {
		return f.Int(`SELECT COUNT(*) FROM share_access_log WHERE share_id = ? AND action = 'download'`, free.ID)
	}
	if got := f.do(req{method: "GET", path: freeDl, hdr: map[string]string{"Range": "bytes=3-"}}); got.StatusCode != 206 {
		t.Fatalf("resume %d", got.StatusCode)
	}
	if freeCount() != 0 || freeRows() != 0 {
		t.Fatalf("resume on an unlimited share: count %d, log %d", freeCount(), freeRows())
	}
	got := f.do(req{method: "GET", path: freeDl, hdr: map[string]string{"Range": "bytes=3-", "If-Range": `"stale"`}})
	if got.StatusCode != 200 || string(got.body) != "read me" {
		t.Fatalf("stale If-Range: %d %q", got.StatusCode, got.body)
	}
	if freeCount() != 1 || freeRows() != 1 {
		t.Fatalf("whole file after a stale If-Range: count %d, log %d", freeCount(), freeRows())
	}
}

// refusingShares refuses every download count (a share exhausted by a
// concurrent visitor) and drops access-log rows.
type refusingShares struct{ core.Shares }

func (refusingShares) CountDownload(context.Context, *core.Share) error {
	return core.Errorf(core.ErrForbidden, "the download limit of this link has been reached")
}

func (refusingShares) RecordAccess(context.Context, *core.Share, core.ShareAccess) {}

// readCounter counts the bytes read from the file being served.
type readCounter struct {
	io.ReadSeeker
	n int64
}

func (c *readCounter) Read(p []byte) (int, error) {
	n, err := c.ReadSeeker.Read(p)
	c.n += int64(n)
	return n, err
}

// TestRefusedDownloadStopsReading pins that a transfer refused at commit
// time (the limit reached by a concurrent visitor) stops reading the file:
// the error response is complete, so reading and decrypting the rest of a
// large file would only waste work and hold the answer back.
func TestRefusedDownloadStopsReading(t *testing.T) {
	const size = 8 << 20
	src := &readCounter{ReadSeeker: bytes.NewReader(make([]byte, size))}
	sr := &shareReq{d: &app.Deps{Shares: refusingShares{}}, s: &core.Share{ID: "shr_x", MaxDownloads: ptr(int64(1))}}
	r := httptest.NewRequest(http.MethodGet, "/s/x/dl/nod_x", nil)
	w := httptest.NewRecorder()
	cb := &countedBlob{ResponseWriter: w, sr: sr, r: r, node: &core.Node{ID: "nod_x", Size: size}}
	httpx.ServeBlob(cb, r, "big.bin", "application/octet-stream", time.Time{}, "", false, src)

	var e apiErr
	if err := json.Unmarshal(w.Body.Bytes(), &e); err != nil || w.Code != 403 || e.Error.Code != "forbidden" {
		t.Fatalf("refused download: %d %q (%v)", w.Code, w.Body.Bytes(), err)
	}
	if cl := w.Header().Get("Content-Length"); cl != fmt.Sprint(w.Body.Len()) {
		t.Fatalf("Content-Length %q for a %d-byte error body", cl, w.Body.Len())
	}
	if src.n > 64<<10 {
		t.Fatalf("read %d bytes of the file after the refusal", src.n)
	}
	if n, err := cb.Write([]byte("more")); n != 0 || err == nil {
		t.Fatalf("Write after a refusal: %d, %v", n, err)
	}
}

func TestArchive(t *testing.T) {
	f := setup(t)
	tr := f.tree()
	s, tok := f.share(f.alice, core.ShareInput{NodeID: tr.docs})
	base := "/s/" + tok
	var tr1 core.ArchiveTicketResponse
	r := f.do(req{method: "POST", path: base + "/api/archive", json: core.ArchiveInput{NodeIDs: []string{tr.readme, tr.photo}}})
	r.json(t, &tr1)
	if r.StatusCode != 200 || tr1.URL != base+"/zip/"+tr1.Ticket {
		t.Fatalf("ticket %d %s", r.StatusCode, r.body)
	}
	// HEAD validates the ticket without consuming it, and answers the name
	// the download would carry (not a generic "download.zip").
	h := f.do(req{method: "HEAD", path: tr1.URL})
	if h.StatusCode != 200 || !strings.Contains(h.Header.Get("Content-Disposition"), "Docs.zip") {
		t.Fatalf("head %d %v", h.StatusCode, h.Header)
	}
	// A ticket that was never issued is not "ready": it is the uniform 404.
	if h := f.do(req{method: "HEAD", path: base + "/zip/deadbeef"}); h.StatusCode != 404 {
		t.Fatalf("head on an unknown ticket: %d %v", h.StatusCode, h.Header)
	}
	// A tar ticket keeps its own name and type.
	var tarT core.ArchiveTicketResponse
	f.do(req{method: "POST", path: base + "/api/archive", json: core.ArchiveInput{Format: core.ArchiveTar, Name: "Backup"}}).json(t, &tarT)
	if h := f.do(req{method: "HEAD", path: tarT.URL}); h.StatusCode != 200 ||
		!strings.Contains(h.Header.Get("Content-Disposition"), "Backup.tar") {
		t.Fatalf("head on a tar ticket: %d %v", h.StatusCode, h.Header)
	}
	r = f.do(req{method: "GET", path: tr1.URL})
	if r.StatusCode != 200 || r.Header.Get("Content-Type") != "application/octet-stream" ||
		!strings.Contains(r.Header.Get("Content-Disposition"), "attachment") || !strings.Contains(r.Header.Get("Content-Security-Policy"), "sandbox") {
		t.Fatalf("zip %d %v", r.StatusCode, r.Header)
	}
	zr, err := zip.NewReader(bytes.NewReader(r.body), int64(len(r.body)))
	if err != nil || len(zr.File) != 2 {
		t.Fatalf("zip %v", err)
	}
	f.do(req{method: "GET", path: tr1.URL}).wantErr(t, 404, "not_found") // single use
	if n := f.Int(`SELECT download_count FROM shares WHERE id = ?`, s.ID); n != 1 {
		t.Fatalf("zip counted %d", n)
	}
	// Default: the whole share; items outside are refused; bad formats.
	var whole core.ArchiveTicketResponse
	f.do(req{method: "POST", path: base + "/api/archive", json: map[string]any{}}).json(t, &whole)
	if whole.Ticket == "" {
		t.Fatal("no ticket for the whole share")
	}
	f.do(req{method: "POST", path: base + "/api/archive", json: core.ArchiveInput{NodeIDs: []string{tr.private}}}).wantErr(t, 404, "not_found")
	f.do(req{method: "POST", path: base + "/api/archive", json: core.ArchiveInput{Format: "rar"}}).wantErr(t, 422, "invalid")
	f.do(req{method: "POST", path: base + "/api/archive", json: core.ArchiveInput{Name: "a/b"}}).wantErr(t, 422, "invalid")
	// A ticket of another share is refused.
	_, tok2 := f.share(f.alice, core.ShareInput{NodeID: tr.docs})
	var other core.ArchiveTicketResponse
	f.do(req{method: "POST", path: "/s/" + tok2 + "/api/archive", json: map[string]any{}}).json(t, &other)
	f.do(req{method: "GET", path: base + "/zip/" + other.Ticket}).wantErr(t, 404, "not_found")
	if h := f.do(req{method: "HEAD", path: base + "/zip/" + other.Ticket}); h.StatusCode != 404 {
		t.Fatalf("head on another share's ticket: %d", h.StatusCode)
	}
	// The earlier HEAD did not consume the tar ticket: it still downloads.
	if g := f.do(req{method: "GET", path: tarT.URL}); g.StatusCode != 200 {
		t.Fatalf("ticket consumed by HEAD: %d", g.StatusCode)
	}
}

// TestArchiveFailures pins the WriteArchive contract on the public route:
// a failure before the first byte is a normal API error that neither counts
// nor logs a download, and a failure while streaming aborts the connection
// instead of ending a truncated archive as a complete download.
func TestArchiveFailures(t *testing.T) {
	f := setup(t)
	tr := f.tree()
	s, tok := f.share(f.alice, core.ShareInput{NodeID: tr.docs, MaxDownloads: ptr(int64(1))})
	base := "/s/" + tok
	ticket := func() string {
		t.Helper()
		var tk core.ArchiveTicketResponse
		f.do(req{method: "POST", path: base + "/api/archive", json: map[string]any{}}).json(t, &tk)
		if tk.URL == "" {
			t.Fatal("no ticket")
		}
		return tk.URL
	}
	count := func() int64 { return f.Int(`SELECT download_count FROM shares WHERE id = ?`, s.ID) }
	rows := func(action string) int64 {
		return f.Int(`SELECT COUNT(*) FROM share_access_log WHERE share_id = ? AND action = ?`, s.ID, action)
	}
	t.Cleanup(func() { f.files.setWriteArchive(nil) })

	// (a) An item was trashed after the ticket was issued: nothing is sent.
	f.files.setWriteArchive(func(context.Context, *core.ArchiveTicket, io.Writer) error {
		return core.NotFoundf("node not found")
	})
	r := f.do(req{method: "GET", path: ticket()})
	r.wantErr(t, 404, "not_found")
	if cd := r.Header.Get("Content-Disposition"); cd != "" {
		t.Fatalf("an error carries attachment headers: %q", cd)
	}
	if count() != 0 || rows(core.AccessZip) != 0 {
		t.Fatalf("a failed archive counted: count %d, zip rows %d", count(), rows(core.AccessZip))
	}

	// (b) A failure after bytes went out aborts the connection: the client
	// sees a broken transfer, not a clean end.
	f.files.setWriteArchive(func(_ context.Context, _ *core.ArchiveTicket, w io.Writer) error {
		// More than net/http buffers: the status line and data are on the wire.
		if _, err := w.Write(bytes.Repeat([]byte("z"), 64<<10)); err != nil {
			return err
		}
		return core.ErrCorrupt
	})
	resp, err := http.Get(f.srv.URL + ticket())
	if err != nil {
		t.Fatal(err)
	}
	_, rerr := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 || rerr == nil {
		t.Fatalf("mid-stream failure: status %d, read error %v (want an aborted body)", resp.StatusCode, rerr)
	}
	if count() != 1 || rows(core.AccessZip) != 1 {
		t.Fatalf("started archive: count %d, zip rows %d", count(), rows(core.AccessZip))
	}

	// (c) The limit is reached by another visitor between the ticket and the
	// first byte: 403 and a blocked row, not an empty 200.
	f.Exec(`UPDATE shares SET download_count = 0 WHERE id = ?`, s.ID)
	late := ticket()
	f.files.setWriteArchive(func(_ context.Context, _ *core.ArchiveTicket, w io.Writer) error {
		f.Exec(`UPDATE shares SET download_count = max_downloads WHERE id = ?`, s.ID)
		_, err := w.Write([]byte("PK"))
		return err
	})
	f.do(req{method: "GET", path: late}).wantErr(t, 403, "forbidden")
	if rows(core.AccessBlocked) != 1 || rows(core.AccessZip) != 1 {
		t.Fatalf("exhausted: blocked rows %d, zip rows %d", rows(core.AccessBlocked), rows(core.AccessZip))
	}

	// Nothing was lost by (a): after a refused archive the download works.
	f.Exec(`UPDATE shares SET download_count = 0 WHERE id = ?`, s.ID)
	f.files.setWriteArchive(nil)
	if r := f.do(req{method: "GET", path: ticket()}); r.StatusCode != 200 || count() != 1 {
		t.Fatalf("download after failures: %d, count %d", r.StatusCode, count())
	}
}

// ---------- file requests ----------

func TestFileRequestUpload(t *testing.T) {
	f := setup(t)
	inbox := f.Mkdir(f.root, "Inbox")
	f.PutFile(inbox, "earlier.txt", []byte("uploaded before"))
	s, tok := f.share(f.alice, core.ShareInput{Kind: core.ShareRequest, NodeID: inbox, RequireUploaderName: true,
		UploadMaxFileBytes: ptr(int64(10 << 20)), UploadQuotaBytes: ptr(int64(12 << 20)), NotifyOwner: true})
	base := "/s/" + tok

	// Visitors of a request do not see its contents.
	var info core.PublicShareInfo
	f.do(req{method: "GET", path: base + "/api"}).json(t, &info)
	if info.Share.Kind != core.ShareRequest || !info.Share.AllowUpload || !info.Share.RequireUploaderName || len(info.Items) != 0 ||
		info.Share.UploadMaxFileBytes == nil {
		t.Fatalf("request info %+v", info)
	}
	f.do(req{method: "GET", path: base + "/api/list"}).wantErr(t, 403, "forbidden")

	big := bytes.Repeat([]byte("0123456789abcdef"), core.PartSize/16+1) // 8 MiB + 16
	files := []core.UploadFileInput{{ClientRef: "a", RelPath: "notes.txt", Size: 5}, {ClientRef: "b", RelPath: "big.bin", Size: int64(len(big))}}
	f.do(req{method: "POST", path: base + "/api/upload-batches", json: core.BatchInput{Files: files}}).wantErr(t, 422, "invalid")
	f.do(req{method: "POST", path: base + "/api/upload-batches", json: core.BatchInput{Uploader: "Eve",
		Files: []core.UploadFileInput{{ClientRef: "x", RelPath: "x", Size: 11 << 20}}}}).wantErr(t, 413, "too_large")
	f.do(req{method: "POST", path: base + "/api/upload-batches", json: core.BatchInput{Uploader: "Eve",
		Files: []core.UploadFileInput{{ClientRef: "x", RelPath: "x", Size: 7 << 20}, {ClientRef: "y", RelPath: "y", Size: 6 << 20}}}}).
		wantErr(t, 507, "quota_exceeded")
	f.do(req{method: "POST", path: base + "/api/upload-batches", json: core.BatchInput{Uploader: "Eve", FolderID: f.root}}).
		wantErr(t, 422, "invalid")
	f.do(req{method: "POST", path: base + "/api/upload-batches", json: core.BatchInput{Uploader: "Eve", Files: files},
		hdr: map[string]string{"Sec-Fetch-Site": "cross-site"}}).wantErr(t, 403, "forbidden")

	var b core.UploadBatch
	r := f.do(req{method: "POST", path: base + "/api/upload-batches", json: core.BatchInput{Uploader: "Eve", Files: files}})
	r.json(t, &b)
	if r.StatusCode != 201 || b.UserID != "" || b.ShareID != s.ID || b.Uploader != "Eve" || len(b.Files) != 2 {
		t.Fatalf("batch %d %s", r.StatusCode, r.body)
	}
	if bytes.Contains(r.body, []byte(f.alice)) {
		t.Error("batch leaks the owner id")
	}
	var st core.UploadFileState
	r = f.do(req{method: "PUT", path: base + "/api/upload-batches/" + b.ID + "/small?ref=a", body: []byte("hello"),
		hdr: map[string]string{"X-FP-SHA256": sum([]byte("hello"))}})
	r.json(t, &st)
	if r.StatusCode != 200 || st.State != core.UploadCommitted || st.NodeID != "" {
		t.Fatalf("small %d %s", r.StatusCode, r.body)
	}
	up := b.Files[1].ID
	for _, n := range []int{1, 0} {
		p := big[n*core.PartSize : min((n+1)*core.PartSize, len(big))]
		if r := f.do(req{method: "PUT", path: fmt.Sprintf("%s/api/uploads/%s/parts/%d", base, up, n), body: p,
			hdr: map[string]string{"X-FP-SHA256": sum(p)}}); r.StatusCode != 204 {
			t.Fatalf("part %d: %d %s", n, r.StatusCode, r.body)
		}
	}
	f.do(req{method: "GET", path: base + "/api/uploads/" + up}).json(t, &st)
	if len(st.PartsDone) != 2 {
		t.Fatalf("status %+v", st)
	}
	f.do(req{method: "POST", path: base + "/api/uploads/" + up + "/complete", json: map[string]any{}}).json(t, &st)
	if st.State != core.UploadCommitted || st.NodeID != "" {
		t.Fatalf("complete file %+v", st)
	}
	var done core.UploadBatch
	r = f.do(req{method: "POST", path: base + "/api/upload-batches/" + b.ID + "/complete", json: map[string]any{}})
	r.json(t, &done)
	if r.StatusCode != 200 || done.State != core.BatchDone || done.UserID != "" {
		t.Fatalf("complete batch %d %s", r.StatusCode, r.body)
	}
	f.do(req{method: "GET", path: base + "/api/upload-batches/" + b.ID}).json(t, &done)
	if done.State != core.BatchDone || done.UserID != "" || len(done.Files) != 2 {
		t.Fatalf("get batch %+v", done)
	}
	// The files are in the owner's folder; usage, access log and notification recorded.
	if n := f.Int(`SELECT COUNT(*) FROM nodes WHERE parent_id = ? AND name IN ('notes.txt', 'big.bin')`, inbox); n != 2 {
		t.Fatalf("stored files %d", n)
	}
	if used := f.Int(`SELECT upload_used_bytes FROM shares WHERE id = ?`, s.ID); used != int64(len(big))+5 {
		t.Fatalf("used %d", used)
	}
	if n := f.Int(`SELECT COUNT(*) FROM share_access_log WHERE share_id = ? AND action = 'upload' AND uploader = 'Eve'`, s.ID); n != 1 {
		t.Fatalf("upload log rows %d", n)
	}
	_ = f.sh.Close()
	if sent := f.Notify.Sent(); len(sent) != 1 || sent[0].To[0] != "alice@example.test" {
		t.Fatalf("notifications %+v", sent)
	}
	// The remaining request quota applies to later uploads.
	f.do(req{method: "POST", path: base + "/api/upload-batches", json: core.BatchInput{Uploader: "Eve",
		Files: []core.UploadFileInput{{ClientRef: "z", RelPath: "z", Size: 4 << 20}}}}).wantErr(t, 507, "quota_exceeded")
	// Batches of one request are invisible through another token.
	_, tok2 := f.share(f.alice, core.ShareInput{Kind: core.ShareRequest, NodeID: inbox})
	f.do(req{method: "GET", path: "/s/" + tok2 + "/api/upload-batches/" + b.ID}).wantErr(t, 404, "not_found")
	// Links without allow_upload refuse uploads.
	_, linkTok := f.share(f.alice, core.ShareInput{NodeID: inbox})
	f.do(req{method: "POST", path: "/s/" + linkTok + "/api/upload-batches", json: core.BatchInput{}}).wantErr(t, 403, "forbidden")
	// Abort over the public API.
	var b3 core.UploadBatch
	f.do(req{method: "POST", path: "/s/" + tok2 + "/api/upload-batches", json: core.BatchInput{
		Files: []core.UploadFileInput{{ClientRef: "q", RelPath: "q", Size: 3}}}}).json(t, &b3)
	if r := f.do(req{method: "DELETE", path: "/s/" + tok2 + "/api/uploads/" + b3.Files[0].ID}); r.StatusCode != 204 {
		t.Fatalf("abort file %d", r.StatusCode)
	}
	if r := f.do(req{method: "DELETE", path: "/s/" + tok2 + "/api/upload-batches/" + b3.ID}); r.StatusCode != 204 {
		t.Fatalf("abort batch %d", r.StatusCode)
	}
}

func TestShareRateLimits(t *testing.T) {
	f := setup(t)
	tr := f.tree()
	_, tok := f.share(f.alice, core.ShareInput{NodeID: tr.docs})
	f.Limiter.Configure(mw.BucketShare, 3, 3)
	// Entry routes consume a token per request.
	for range 3 {
		if r := f.do(req{method: "GET", path: "/s/" + tok + "/api"}); r.StatusCode != 200 {
			t.Fatalf("status %d", r.StatusCode)
		}
	}
	r := f.do(req{method: "GET", path: "/s/" + tok + "/api"})
	r.wantErr(t, 429, "rate_limited")
	// Data routes of a valid token are not limited ...
	for range 5 {
		if r := f.do(req{method: "GET", path: "/s/" + tok + "/dl/" + tr.readme}); r.StatusCode != 200 {
			t.Fatalf("download %d", r.StatusCode)
		}
	}
	// ... but guessing tokens there is.
	f.Clock.Advance(time.Minute)
	for range 3 {
		f.do(req{method: "GET", path: "/s/" + strings.Repeat("Z", 22) + "/dl/" + tr.readme}).wantErr(t, 404, "not_found")
	}
	f.do(req{method: "GET", path: "/s/" + strings.Repeat("Z", 22) + "/dl/" + tr.readme}).wantErr(t, 429, "rate_limited")
}

func TestHelpers(t *testing.T) {
	for _, c := range []struct {
		in string
		ok bool
	}{{"0", true}, {"1048576", true}, {"1048577", false}, {"-1", false}, {"", false}, {"1a", false}} {
		if _, err := parsePart(c.in); (err == nil) != c.ok {
			t.Errorf("parsePart(%q): %v", c.in, err)
		}
	}
	if _, err := parseSHA(strings.Repeat("0", 64)); err != nil {
		t.Error(err)
	}
	if _, err := parseSHA("abc"); err == nil {
		t.Error("short digest accepted")
	}
	// files.local is not a host this server answers to (the request carries
	// no Deps and no local address), so it must not be echoed back.
	r := httptest.NewRequest("GET", "http://files.local:8443/x", nil)
	if got := absoluteURL(r, "/s/abc"); got != "https://localhost/s/abc" {
		t.Errorf("absoluteURL %q", got)
	}
	loop := httptest.NewRequest("GET", "http://127.0.0.1:8443/x", nil)
	if got := absoluteURL(loop, "/s/abc"); got != "https://127.0.0.1:8443/s/abc" {
		t.Errorf("absoluteURL of an allowed host %q", got)
	}
	if got := absoluteURL(r, "https://x/s/abc"); got != "https://x/s/abc" {
		t.Errorf("absoluteURL %q", got)
	}
	st := visitorState(&core.UploadFileState{ID: "upf_1", NodeID: "nod_1"})
	if st.NodeID != "" || visitorState(nil) != nil || visitorBatch(nil) != nil {
		t.Error("visitor views")
	}
	for _, c := range []struct {
		rg   string
		want bool
	}{{"", true}, {"bytes=0-", true}, {"bytes=0-10", true}, {"bytes=5-", false}} {
		r := httptest.NewRequest("GET", "/", nil)
		if c.rg != "" {
			r.Header.Set("Range", c.rg)
		}
		if firstRange(r) != c.want {
			t.Errorf("firstRange(%q)", c.rg)
		}
	}
	// Visitors who may not list a share do not learn how many items its
	// folder holds (the submissions of a file request).
	three := int64(3)
	folder := core.Node{ID: "nod_x", Kind: core.KindFolder, ChildCount: &three}
	for _, c := range []struct {
		s    core.Share
		keep bool
	}{
		{core.Share{Kind: core.ShareRequest, NodeID: "nod_x"}, false},
		{core.Share{Kind: core.ShareRequest, NodeID: "nod_x", AllowDownload: true}, true},
		{core.Share{Kind: core.ShareRequest, NodeID: "nod_x", AllowPreview: true}, true},
		{core.Share{Kind: core.ShareLink, NodeID: "nod_x"}, true},
	} {
		if got := publicNode(folder, &c.s); (got.ChildCount != nil) != c.keep {
			t.Errorf("publicNode child_count with %+v: %v, want kept=%v", c.s, got.ChildCount, c.keep)
		}
	}
}

// TestFileRequestVisitorIsolation pins that one visitor of a file request
// cannot reach another visitor's upload batch. Everyone uploading to a
// request acts as the share owner, so the batch is bound to the visitor
// cookie the share page hands out.
func TestFileRequestVisitorIsolation(t *testing.T) {
	f := setup(t)
	inbox := f.Mkdir(f.root, "Inbox")
	s, tok := f.share(f.alice, core.ShareInput{Kind: core.ShareRequest, NodeID: inbox})
	base := "/s/" + tok

	// The share page hands the visitor an id; a plain link gets none.
	visitor := func() *http.Cookie {
		t.Helper()
		r := f.do(req{method: "GET", path: base + "/api"})
		for _, c := range r.Cookies() {
			if c.Name == visitorCookieName(s.ID) {
				if !c.HttpOnly || !c.Secure || c.Path != "/" || !validVisitorID(c.Value) {
					t.Fatalf("visitor cookie %+v", c)
				}
				return c
			}
		}
		t.Fatal("no visitor cookie on the file-request page")
		return nil
	}
	one, two := visitor(), visitor()
	if one.Value == two.Value {
		t.Fatal("two visitors share one id")
	}
	link, linkTok := f.share(f.alice, core.ShareInput{NodeID: inbox})
	for _, c := range f.do(req{method: "GET", path: "/s/" + linkTok + "/api"}).Cookies() {
		if c.Name == visitorCookieName(link.ID) {
			t.Fatal("a download-only link issues a visitor cookie")
		}
	}

	// The first visitor opens a batch.
	var b core.UploadBatch
	r := f.do(req{method: "POST", path: base + "/api/upload-batches", cookies: []*http.Cookie{one},
		json: core.BatchInput{Files: []core.UploadFileInput{{ClientRef: "a", RelPath: "mine.txt", Size: 5}}}})
	r.json(t, &b)
	if r.StatusCode != 201 || len(b.Files) != 1 {
		t.Fatalf("create batch %d %s", r.StatusCode, r.body)
	}

	// The second visitor of the same share — and a visitor with no cookie at
	// all — must not see or touch it, on any route of the batch.
	for _, who := range []struct {
		name    string
		cookies []*http.Cookie
	}{{"another visitor", []*http.Cookie{two}}, {"no cookie", nil}} {
		t.Run(who.name, func(t *testing.T) {
			f.do(req{method: "GET", path: base + "/api/upload-batches/" + b.ID, cookies: who.cookies}).wantErr(t, 404, "not_found")
			f.do(req{method: "POST", path: base + "/api/upload-batches/" + b.ID + "/files", cookies: who.cookies,
				json: []core.UploadFileInput{{ClientRef: "c", RelPath: "theirs.txt", Size: 1}}}).wantErr(t, 404, "not_found")
			f.do(req{method: "PUT", path: base + "/api/upload-batches/" + b.ID + "/small?ref=a", cookies: who.cookies,
				body: []byte("hello"), hdr: map[string]string{"X-FP-SHA256": sum([]byte("hello"))}}).wantErr(t, 404, "not_found")
			f.do(req{method: "GET", path: base + "/api/uploads/" + b.Files[0].ID, cookies: who.cookies}).wantErr(t, 404, "not_found")
			f.do(req{method: "POST", path: base + "/api/upload-batches/" + b.ID + "/complete", cookies: who.cookies,
				json: map[string]any{}}).wantErr(t, 404, "not_found")
			f.do(req{method: "DELETE", path: base + "/api/uploads/" + b.Files[0].ID, cookies: who.cookies}).wantErr(t, 404, "not_found")
			f.do(req{method: "DELETE", path: base + "/api/upload-batches/" + b.ID, cookies: who.cookies}).wantErr(t, 404, "not_found")
		})
	}
	if st := f.Str(`SELECT state FROM upload_batches WHERE id = ?`, b.ID); st != core.BatchOpen {
		t.Fatalf("batch state after the other visitor tried: %q", st)
	}

	// Its owner still has it.
	var st core.UploadFileState
	r = f.do(req{method: "PUT", path: base + "/api/upload-batches/" + b.ID + "/small?ref=a", cookies: []*http.Cookie{one},
		body: []byte("hello"), hdr: map[string]string{"X-FP-SHA256": sum([]byte("hello"))}})
	r.json(t, &st)
	if r.StatusCode != 200 || st.State != core.UploadCommitted {
		t.Fatalf("own small upload %d %s", r.StatusCode, r.body)
	}
	if r := f.do(req{method: "DELETE", path: base + "/api/upload-batches/" + b.ID, cookies: []*http.Cookie{one}}); r.StatusCode != 204 {
		t.Fatalf("own abort %d %s", r.StatusCode, r.body)
	}

	// Clients that send no cookies (a script, an old client) keep the
	// share-wide behaviour: their batches carry no visitor id to bind.
	var nb core.UploadBatch
	f.do(req{method: "POST", path: base + "/api/upload-batches",
		json: core.BatchInput{Files: []core.UploadFileInput{{ClientRef: "a", RelPath: "script.txt", Size: 5}}}}).json(t, &nb)
	if r := f.do(req{method: "GET", path: base + "/api/upload-batches/" + nb.ID}); r.StatusCode != 200 {
		t.Fatalf("cookie-less client locked out of its own batch: %d %s", r.StatusCode, r.body)
	}
}

// A folder link with allow_upload (`share create --upload`) takes uploads
// like a file request: into its folder, a sub-folder through rel_path (what
// the share page sends for the folder being viewed). One that also turns
// downloads and previews off is a drop box and, like a request, does not
// show its contents: visitors would otherwise see each other's uploads.
func TestLinkUploads(t *testing.T) {
	f := setup(t)
	inbox := f.Mkdir(f.root, "Inbox")
	sub := f.Mkdir(inbox, "Sub")
	f.PutFile(inbox, "earlier.txt", []byte("uploaded before"))
	_, tok := f.share(f.alice, core.ShareInput{NodeID: inbox, AllowUpload: true})
	base := "/s/" + tok

	var info core.PublicShareInfo
	f.do(req{method: "GET", path: base + "/api"}).json(t, &info)
	if info.Share.Kind != core.ShareLink || !info.Share.AllowUpload || len(info.Items) != 2 {
		t.Fatalf("link info %+v", info)
	}
	if r := f.do(req{method: "GET", path: base + "/api/list"}); r.StatusCode != 200 {
		t.Fatalf("link list %d %s", r.StatusCode, r.body)
	}

	files := []core.UploadFileInput{{ClientRef: "a", RelPath: "Sub/a.txt", Size: 5}}
	f.do(req{method: "POST", path: base + "/api/upload-batches", json: core.BatchInput{FolderID: sub, Files: files}}).
		wantErr(t, 422, "invalid")
	var b core.UploadBatch
	r := f.do(req{method: "POST", path: base + "/api/upload-batches", json: core.BatchInput{Files: files}})
	r.json(t, &b)
	if r.StatusCode != 201 || len(b.Files) != 1 {
		t.Fatalf("batch %d %s", r.StatusCode, r.body)
	}
	var st core.UploadFileState
	r = f.do(req{method: "PUT", path: base + "/api/upload-batches/" + b.ID + "/small?ref=a", body: []byte("hello"),
		hdr: map[string]string{"X-FP-SHA256": sum([]byte("hello"))}})
	r.json(t, &st)
	if r.StatusCode != 200 || st.State != core.UploadCommitted {
		t.Fatalf("small %d %s", r.StatusCode, r.body)
	}
	if r := f.do(req{method: "POST", path: base + "/api/upload-batches/" + b.ID + "/complete", json: map[string]any{}}); r.StatusCode != 200 {
		t.Fatalf("complete %d %s", r.StatusCode, r.body)
	}
	if n := f.Int(`SELECT COUNT(*) FROM nodes WHERE parent_id = ? AND name = 'a.txt'`, sub); n != 1 {
		t.Fatalf("a.txt in the sub-folder: %d", n)
	}
	if n := f.Int(`SELECT COUNT(*) FROM nodes WHERE parent_id = ? AND kind = 'folder'`, inbox); n != 1 {
		t.Fatalf("folders in the shared folder: %d (the existing sub-folder must be reused)", n)
	}

	// The drop box: uploads only.
	_, dropTok := f.share(f.alice, core.ShareInput{NodeID: inbox, AllowUpload: true,
		AllowDownload: ptr(false), AllowPreview: ptr(false)})
	info = core.PublicShareInfo{}
	f.do(req{method: "GET", path: "/s/" + dropTok + "/api"}).json(t, &info)
	if !info.Share.AllowUpload || len(info.Items) != 0 || info.NextCursor != "" || info.Node == nil || info.Node.ChildCount != nil {
		t.Fatalf("drop box info %+v", info)
	}
	f.do(req{method: "GET", path: "/s/" + dropTok + "/api/list"}).wantErr(t, 403, "forbidden")
	r = f.do(req{method: "POST", path: "/s/" + dropTok + "/api/upload-batches",
		json: core.BatchInput{Files: []core.UploadFileInput{{ClientRef: "d", RelPath: "d.txt", Size: 1}}}})
	if r.StatusCode != 201 {
		t.Fatalf("drop box batch %d %s", r.StatusCode, r.body)
	}
}

func ptr[T any](v T) *T { return &v }
