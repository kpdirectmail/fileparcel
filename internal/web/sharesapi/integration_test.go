package sharesapi_test

// End-to-end test over the fully wired application (wire.Build, the real
// router, files, blob store, keys, jobs, uploads and shares): a signed-in
// upload (parts, small files, folders, zip-on-upload), a password-protected
// share link with a download limit, and a public file request.

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"fileparcel/internal/app"
	"fileparcel/internal/config"
	"fileparcel/internal/core"
	"fileparcel/internal/home"
	"fileparcel/internal/web"
	"fileparcel/internal/wire"
)

type wired struct {
	t      *testing.T
	d      *app.Deps
	api    *httptest.Server // in-process (trusted) transport acting as a user via X-FP-As
	public *httptest.Server // anonymous network transport
}

func newWired(t *testing.T) *wired {
	t.Helper()
	h, err := home.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := h.EnsureLayout(); err != nil {
		t.Fatal(err)
	}
	if err := config.Default(config.NewInstallID()).SaveTo(h.Config()); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	d, cleanup, err := wire.Build(ctx, h, app.ModeOffline)
	if err != nil {
		t.Skipf("application not buildable yet: %v", err)
	}
	t.Cleanup(cleanup)
	if _, err := d.Keys.Init(ctx, false, nil); err != nil {
		if errors.Is(err, core.ErrNotImplemented) {
			t.Skipf("keys not implemented yet: %v", err)
		}
		t.Fatal(err)
	}
	if err := d.Jobs.Start(ctx); err != nil {
		t.Fatal(err)
	}
	sys := core.SystemPrincipal(core.ViaOffline)
	if _, err := d.Settings.Set(ctx, sys, map[string]json.RawMessage{"storage.fsync": json.RawMessage("false")}); err != nil {
		t.Logf("storage.fsync not changed: %v", err)
	}
	for _, name := range []string{"alice", "bob"} {
		if _, err := d.Users.Create(ctx, sys, core.NewUser{Username: name, DisplayName: strings.ToUpper(name[:1]) + name[1:],
			Email: name + "@example.test", Role: core.RoleMember}); err != nil {
			if errors.Is(err, core.ErrNotImplemented) {
				t.Skipf("users not implemented yet: %v", err)
			}
			t.Fatal(err)
		}
	}
	router := web.NewRouter(d)
	w := &wired{t: t, d: d}
	w.api = httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		router.ServeHTTP(rw, r.WithContext(core.WithPrincipal(r.Context(), core.SystemPrincipal(core.ViaOffline))))
	}))
	w.public = httptest.NewServer(router)
	t.Cleanup(w.api.Close)
	t.Cleanup(w.public.Close)
	return w
}

type resp struct {
	status int
	header http.Header
	body   []byte
}

func (w *wired) call(srv *httptest.Server, as, method, path string, body io.Reader, hdr map[string]string) resp {
	w.t.Helper()
	req, err := http.NewRequest(method, srv.URL+path, body)
	if err != nil {
		w.t.Fatal(err)
	}
	if as != "" {
		req.Header.Set("X-FP-As", as)
	}
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	r, err := http.DefaultClient.Do(req)
	if err != nil {
		w.t.Fatal(err)
	}
	defer r.Body.Close()
	b, _ := io.ReadAll(r.Body)
	return resp{r.StatusCode, r.Header, b}
}

func (w *wired) jsonCall(srv *httptest.Server, as, method, path string, in, out any, want int) resp {
	w.t.Helper()
	var body io.Reader
	hdr := map[string]string{}
	if in != nil {
		b, _ := json.Marshal(in)
		body = bytes.NewReader(b)
		hdr["Content-Type"] = "application/json"
	}
	r := w.call(srv, as, method, path, body, hdr)
	if r.status != want {
		w.t.Fatalf("%s %s: %d %s (want %d)", method, path, r.status, r.body, want)
	}
	if out != nil {
		if err := json.Unmarshal(r.body, out); err != nil {
			w.t.Fatalf("%s %s: %v", method, path, err)
		}
	}
	return r
}

func hexSum(b []byte) string { s := sha256.Sum256(b); return hex.EncodeToString(s[:]) }

func (w *wired) rootOf(username string) string {
	w.t.Helper()
	spaces, err := w.d.Files.Spaces(context.Background(), w.principal(username))
	if err != nil || len(spaces) == 0 {
		w.t.Fatalf("spaces of %s: %v", username, err)
	}
	return spaces[0].RootID
}

// children maps names to nodes of a folder (as the space owner).
func (w *wired) children(username, folder string) map[string]core.Node {
	w.t.Helper()
	var pg core.Page[core.Node]
	w.jsonCall(w.api, username, "GET", "/api/v1/nodes/"+folder+"/children?limit=500", nil, &pg, 200)
	out := map[string]core.Node{}
	for _, n := range pg.Items {
		out[n.Name] = n
	}
	return out
}

func (w *wired) content(username, nodeID string) []byte {
	w.t.Helper()
	r := w.call(w.api, username, "GET", "/api/v1/nodes/"+nodeID+"/content", nil, nil)
	if r.status != 200 {
		w.t.Fatalf("content %s: %d %s", nodeID, r.status, r.body)
	}
	return r.body
}

func pattern(n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(i*7 + i/65536)
	}
	return b
}

func TestWiredUploadShareAndRequest(t *testing.T) {
	w := newWired(t)
	root := w.rootOf("alice")
	big := pattern(core.PartSize + 12345)

	// ---- signed-in folder upload: parts, small files, empty dir ----
	var b core.UploadBatch
	w.jsonCall(w.api, "alice", "POST", "/api/v1/upload-batches", core.BatchInput{FolderID: root, Files: []core.UploadFileInput{
		{ClientRef: "big", RelPath: "Trip/big.bin", Size: int64(len(big))},
		{ClientRef: "s", RelPath: "Trip/day1/note.txt", Size: 5},
		{ClientRef: "d", RelPath: "Trip/empty", Kind: "dir"},
	}}, &b, 201)
	var up string
	for _, f := range b.Files {
		if f.ClientRef == "big" {
			up = f.ID
		}
	}
	for _, n := range []int{1, 0} {
		p := big[n*core.PartSize : min((n+1)*core.PartSize, len(big))]
		if r := w.call(w.api, "alice", "PUT", fmt.Sprintf("/api/v1/uploads/%s/parts/%d", up, n), bytes.NewReader(p),
			map[string]string{"X-FP-SHA256": hexSum(p)}); r.status != 204 {
			t.Fatalf("part %d: %d %s", n, r.status, r.body)
		}
	}
	w.jsonCall(w.api, "alice", "POST", "/api/v1/uploads/"+up+"/complete", nil, nil, 200)
	if r := w.call(w.api, "alice", "PUT", "/api/v1/upload-batches/"+b.ID+"/small?ref=s", strings.NewReader("hello"),
		map[string]string{"X-FP-SHA256": hexSum([]byte("hello"))}); r.status != 200 {
		t.Fatalf("small: %d %s", r.status, r.body)
	}
	var done core.UploadBatch
	w.jsonCall(w.api, "alice", "POST", "/api/v1/upload-batches/"+b.ID+"/complete", nil, &done, 200)
	if done.State != core.BatchDone {
		t.Fatalf("batch %+v", done)
	}
	trip := w.children("alice", root)["Trip"]
	kids := w.children("alice", trip.ID)
	if kids["empty"].Kind != core.KindFolder || kids["day1"].Kind != core.KindFolder {
		t.Fatalf("Trip children %v", kids)
	}
	if got := w.content("alice", kids["big.bin"].ID); !bytes.Equal(got, big) {
		t.Fatal("big.bin differs after the round trip")
	}

	// ---- zip on upload ----
	var z core.UploadBatch
	w.jsonCall(w.api, "alice", "POST", "/api/v1/upload-batches", core.BatchInput{FolderID: root, Mode: "zip", ZipName: "Bundle",
		Files: []core.UploadFileInput{{ClientRef: "a", RelPath: "x/a.txt", Size: 1}, {ClientRef: "e", RelPath: "x/void", Kind: "dir"}}}, &z, 201)
	w.call(w.api, "alice", "PUT", "/api/v1/upload-batches/"+z.ID+"/small?ref=a", strings.NewReader("A"),
		map[string]string{"X-FP-SHA256": hexSum([]byte("A"))})
	w.jsonCall(w.api, "alice", "POST", "/api/v1/upload-batches/"+z.ID+"/complete", nil, nil, 202)
	deadline := time.Now().Add(20 * time.Second)
	for {
		w.jsonCall(w.api, "alice", "GET", "/api/v1/upload-batches/"+z.ID, nil, &z, 200)
		if z.State != core.BatchFinalizing || time.Now().After(deadline) {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if z.State != core.BatchDone || z.ResultNodeID == "" {
		t.Fatalf("zip batch %+v", z)
	}
	zipData := w.content("alice", z.ResultNodeID)
	zr, err := zip.NewReader(bytes.NewReader(zipData), int64(len(zipData)))
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, f := range zr.File {
		names = append(names, f.Name)
	}
	if strings.Join(names, ",") != "x/a.txt,x/void/" {
		t.Fatalf("zip entries %v", names)
	}

	// ---- password-protected link with a download limit ----
	var s core.Share
	w.jsonCall(w.api, "alice", "POST", "/api/v1/shares", core.ShareInput{NodeID: trip.ID, Password: "letmein now",
		MaxDownloads: func() *int64 { v := int64(2); return &v }()}, &s, 201)
	base := s.URL
	var info core.PublicShareInfo
	w.jsonCall(w.public, "", "GET", base+"/api", nil, &info, 200)
	if !info.PasswordRequired || info.Node != nil {
		t.Fatalf("locked info %+v", info)
	}
	if r := w.call(w.public, "", "GET", base+"/dl/"+kids["big.bin"].ID, nil, nil); r.status != 401 {
		t.Fatalf("download without password: %d", r.status)
	}
	r := w.call(w.public, "", "POST", base+"/api/password", strings.NewReader(`{"password":"letmein now"}`),
		map[string]string{"Content-Type": "application/json"})
	if r.status != 204 {
		t.Fatalf("password %d %s", r.status, r.body)
	}
	cookie := strings.SplitN(r.header.Get("Set-Cookie"), ";", 2)[0]
	withCookie := map[string]string{"Cookie": cookie}
	r = w.call(w.public, "", "GET", base+"/api", nil, withCookie)
	info = core.PublicShareInfo{}
	_ = json.Unmarshal(r.body, &info)
	if info.PasswordRequired || len(info.Items) != 3 || bytes.Contains(r.body, []byte(s.CreatedBy)) {
		t.Fatalf("unlocked info %s", r.body)
	}
	// Visitors of a link see the contents, and so how many there are.
	if info.Node == nil || info.Node.ChildCount == nil || *info.Node.ChildCount != 3 {
		t.Fatalf("link root node %+v", info.Node)
	}
	r = w.call(w.public, "", "GET", base+"/dl/"+kids["big.bin"].ID, nil, withCookie)
	if r.status != 200 || !bytes.Equal(r.body, big) || !strings.HasPrefix(r.header.Get("Content-Disposition"), "attachment") {
		t.Fatalf("public download %d", r.status)
	}
	// Outside the share: 404, even for the owner's other files.
	if r := w.call(w.public, "", "GET", base+"/dl/"+z.ResultNodeID, nil, withCookie); r.status != 404 {
		t.Fatalf("outside download %d", r.status)
	}
	// Second counted download, then the link is exhausted (uniform 404).
	if r := w.call(w.public, "", "GET", base+"/dl/"+kids["big.bin"].ID, nil, withCookie); r.status != 200 {
		t.Fatalf("second download %d", r.status)
	}
	if r := w.call(w.public, "", "GET", base+"/api", nil, withCookie); r.status != 404 {
		t.Fatalf("exhausted link %d", r.status)
	}
	if r := w.call(w.public, "", "GET", "/s/"+strings.Repeat("Q", 22)+"/api", nil, nil); r.status != 404 {
		t.Fatalf("unknown token %d", r.status)
	}

	// ---- public file request into bob's inbox ----
	bobRoot := w.rootOf("bob")
	var inbox core.Node
	w.jsonCall(w.api, "bob", "POST", "/api/v1/nodes/"+bobRoot+"/folders", core.NameInput{Name: "Inbox"}, &inbox, 201)
	var req core.Share
	w.jsonCall(w.api, "bob", "POST", "/api/v1/shares", core.ShareInput{Kind: core.ShareRequest, NodeID: inbox.ID,
		RequireUploaderName: true, UploadQuotaBytes: func() *int64 { v := int64(100); return &v }()}, &req, 201)
	var rb core.UploadBatch
	w.jsonCall(w.public, "", "POST", req.URL+"/api/upload-batches", core.BatchInput{Uploader: "Carol",
		Files: []core.UploadFileInput{{ClientRef: "r", RelPath: "report.txt", Size: 6}}}, &rb, 201)
	if r := w.call(w.public, "", "PUT", req.URL+"/api/upload-batches/"+rb.ID+"/small?ref=r", strings.NewReader("report"),
		map[string]string{"X-FP-SHA256": hexSum([]byte("report"))}); r.status != 200 {
		t.Fatalf("request small %d %s", r.status, r.body)
	}
	w.jsonCall(w.public, "", "POST", req.URL+"/api/upload-batches/"+rb.ID+"/complete", nil, nil, 200)
	got := w.children("bob", inbox.ID)["report.txt"]
	if got.ID == "" || string(w.content("bob", got.ID)) != "report" {
		t.Fatalf("request upload not stored: %+v", got)
	}
	w.jsonCall(w.public, "", "POST", req.URL+"/api/upload-batches", core.BatchInput{Uploader: "Carol",
		Files: []core.UploadFileInput{{ClientRef: "r", RelPath: "more.bin", Size: 95}}}, nil, 507)
	var log core.Page[core.ShareAccess]
	w.jsonCall(w.api, "bob", "GET", "/api/v1/shares/"+req.ID+"/log", nil, &log, 200)
	if len(log.Items) == 0 || log.Items[0].Action != core.AccessUpload || log.Items[0].Uploader != "Carol" {
		t.Fatalf("request log %+v", log.Items)
	}
	// Uploaders cannot see what is already there, not even how much: the
	// real files service fills child_count on the request's folder.
	var rinfo core.PublicShareInfo
	r = w.jsonCall(w.public, "", "GET", req.URL+"/api", nil, &rinfo, 200)
	if rinfo.Node == nil || rinfo.Node.ChildCount != nil || len(rinfo.Items) != 0 || bytes.Contains(r.body, []byte("child_count")) {
		t.Fatalf("file request info %s", r.body)
	}
	if r := w.call(w.public, "", "GET", req.URL, nil, nil); r.status != 200 || bytes.Contains(r.body, []byte("child_count")) {
		t.Fatalf("file request page %d leaks the item count", r.status)
	}
}

// principal is a signed-in principal of username.
func (w *wired) principal(username string) *core.Principal {
	w.t.Helper()
	u, err := w.d.Users.GetByUsername(context.Background(), username)
	if err != nil {
		w.t.Fatal(err)
	}
	return &core.Principal{UserID: u.ID, Username: u.Username, Role: u.Role, Via: core.ViaSession, AuthLevel: core.AuthLevelFull}
}

// putSmall uploads a small file into folder and returns its node.
func (w *wired) putSmall(username, folder, name, content string) core.Node {
	w.t.Helper()
	var b core.UploadBatch
	w.jsonCall(w.api, username, "POST", "/api/v1/upload-batches", core.BatchInput{FolderID: folder,
		Files: []core.UploadFileInput{{ClientRef: "f", RelPath: name, Size: int64(len(content))}}}, &b, 201)
	if r := w.call(w.api, username, "PUT", "/api/v1/upload-batches/"+b.ID+"/small?ref=f", strings.NewReader(content),
		map[string]string{"X-FP-SHA256": hexSum([]byte(content))}); r.status != 200 {
		w.t.Fatalf("small %s: %d %s", name, r.status, r.body)
	}
	w.jsonCall(w.api, username, "POST", "/api/v1/upload-batches/"+b.ID+"/complete", nil, nil, 200)
	n := w.children(username, folder)[name]
	if n.ID == "" {
		w.t.Fatalf("%s not stored", name)
	}
	return n
}

// TestWiredPublicArchiveAndAdminLink covers, over the real services: a
// public archive whose item was trashed after the ticket was issued (an API
// error rather than an empty "complete" download, and nothing counted), and
// a link an administrator created through auth.admin_can_access_files (its
// visits are not audited as the admin's own file access, at request rate).
func TestWiredPublicArchiveAndAdminLink(t *testing.T) {
	w := newWired(t)
	ctx := context.Background()
	root := w.rootOf("alice")
	var docs core.Node
	w.jsonCall(w.api, "alice", "POST", "/api/v1/nodes/"+root+"/folders", core.NameInput{Name: "Docs"}, &docs, 201)
	a := w.putSmall("alice", docs.ID, "a.txt", "alpha")
	b := w.putSmall("alice", docs.ID, "b.txt", "bravo")

	// ---- archive of a share: an item trashed after the ticket ----
	one := int64(1)
	var s core.Share
	w.jsonCall(w.api, "alice", "POST", "/api/v1/shares", core.ShareInput{NodeID: docs.ID, MaxDownloads: &one}, &s, 201)
	var tk core.ArchiveTicketResponse
	w.jsonCall(w.public, "", "POST", s.URL+"/api/archive", core.ArchiveInput{NodeIDs: []string{a.ID, b.ID}}, &tk, 200)
	if err := w.d.Files.Trash(ctx, w.principal("alice"), []string{b.ID}); err != nil {
		t.Fatal(err)
	}
	r := w.call(w.public, "", "GET", tk.URL, nil, nil)
	if r.status != 404 || r.header.Get("Content-Disposition") != "" || !bytes.Contains(r.body, []byte(`"not_found"`)) {
		t.Fatalf("archive with a trashed item: %d %q %s", r.status, r.header.Get("Content-Disposition"), r.body)
	}
	var got core.Share
	w.jsonCall(w.api, "alice", "GET", "/api/v1/shares/"+s.ID, nil, &got, 200)
	if got.DownloadCount != 0 {
		t.Fatalf("a failed archive used up the download limit: %d", got.DownloadCount)
	}
	// The one download is still there.
	w.jsonCall(w.public, "", "POST", s.URL+"/api/archive", core.ArchiveInput{NodeIDs: []string{a.ID}}, &tk, 200)
	r = w.call(w.public, "", "GET", tk.URL, nil, nil)
	if r.status != 200 {
		t.Fatalf("archive: %d %s", r.status, r.body)
	}
	zr, err := zip.NewReader(bytes.NewReader(r.body), int64(len(r.body)))
	if err != nil || len(zr.File) != 1 || zr.File[0].Name != "a.txt" {
		t.Fatalf("archive entries %v (%v)", zr, err)
	}

	// ---- a link an admin created through the override ----
	sys := core.SystemPrincipal(core.ViaOffline)
	if _, err := w.d.Users.Create(ctx, sys, core.NewUser{Username: "boss", DisplayName: "Boss",
		Email: "boss@example.test", Role: core.RoleAdmin}); err != nil {
		t.Fatal(err)
	}
	override := func(on bool) {
		t.Helper()
		if _, err := w.d.Settings.Set(ctx, sys, map[string]json.RawMessage{
			"auth.admin_can_access_files": json.RawMessage(fmt.Sprint(on))}); err != nil {
			t.Fatal(err)
		}
	}
	override(true)
	audits := func() int {
		t.Helper()
		var n int
		if err := w.d.DB.QueryRow(ctx, `SELECT COUNT(*) FROM audit_log WHERE action = ?`, core.ActAdminFileAccess).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	var as core.Share
	w.jsonCall(w.api, "boss", "POST", "/api/v1/shares", core.ShareInput{NodeID: a.ID}, &as, 201)
	created := audits()
	if created == 0 {
		t.Fatal("creating a link through the override was not audited")
	}
	for range 3 {
		w.jsonCall(w.public, "", "GET", as.URL+"/api", nil, nil, 200)
		if r := w.call(w.public, "", "GET", as.URL+"/dl/"+a.ID, nil, nil); r.status != 200 || string(r.body) != "alpha" {
			t.Fatalf("download through the admin's link: %d", r.status)
		}
	}
	if n := audits(); n != created {
		t.Fatalf("visits of the admin's link wrote %d admin.file_access entries", n-created)
	}
	// The access itself is still checked: without the override the link
	// stops working.
	override(false)
	if r := w.call(w.public, "", "GET", as.URL+"/api", nil, nil); r.status != 404 {
		t.Fatalf("admin's link without the override: %d", r.status)
	}
}
