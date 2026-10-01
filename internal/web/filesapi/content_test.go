package filesapi

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"crypto/rand"
	"errors"
	"image"
	"image/color"
	"image/png"
	"io"
	"mime"
	"mime/multipart"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	"fileparcel/internal/core"
	"fileparcel/internal/db"
	"fileparcel/internal/ids"
	"fileparcel/internal/web/httpx"
	"fileparcel/internal/web/mw"
)

func TestContentDownload(t *testing.T) {
	e := newEnv(t)
	u := e.user("alice", core.RoleMember)
	p := u.Principal
	data := make([]byte, 200_000)
	_, _ = rand.Read(data)
	n := e.put(u, u.rootID, "data.bin", data)
	url := "/api/v1/nodes/" + n.ID + "/content"

	resp := e.req(p, "GET", url, nil).expect(t, 200)
	if !bytes.Equal(resp.body, data) {
		t.Fatal("content differs")
	}
	if err := mw.CheckSecurityHeaders(resp.header, mw.HeadersContent); err != nil {
		t.Error(err)
	}
	h := resp.header
	checks := map[string]string{
		"ETag":                         `"` + n.VersionID + `"`,
		"Content-Type":                 "application/octet-stream",
		"Content-Disposition":          `attachment; filename="data.bin"`,
		"Content-Security-Policy":      httpx.CSPContent,
		"X-Content-Type-Options":       "nosniff",
		"Cross-Origin-Resource-Policy": "same-origin",
		"Cache-Control":                "private, no-cache",
		"Accept-Ranges":                "bytes",
		"Content-Length":               strconv.Itoa(len(data)),
	}
	for k, v := range checks {
		if got := h.Get(k); got != v {
			t.Errorf("%s = %q, want %q", k, got, v)
		}
	}
	if h.Get("Last-Modified") == "" {
		t.Error("no Last-Modified")
	}
	if e.audit.count(core.ActFileDownload) != 1 {
		t.Fatalf("download audits %d", e.audit.count(core.ActFileDownload))
	}

	// Single ranges across boundaries, suffix range, multi-range.
	for _, r := range [][2]int{{0, 1}, {65535, 2}, {65536, 65536}, {199_990, 10}} {
		resp := e.req(p, "GET", url, nil, "Range: bytes="+strconv.Itoa(r[0])+"-"+strconv.Itoa(r[0]+r[1]-1)).expect(t, 206)
		if !bytes.Equal(resp.body, data[r[0]:r[0]+r[1]]) {
			t.Errorf("range %v differs", r)
		}
	}
	resp = e.req(p, "GET", url, nil, "Range: bytes=-500").expect(t, 206)
	if !bytes.Equal(resp.body, data[len(data)-500:]) {
		t.Error("suffix range differs")
	}
	resp = e.req(p, "GET", url, nil, "Range: bytes=0-9,65530-65545").expect(t, 206)
	mt, params, err := mime.ParseMediaType(resp.header.Get("Content-Type"))
	if err != nil || mt != "multipart/byteranges" {
		t.Fatalf("multi-range type %q", resp.header.Get("Content-Type"))
	}
	mr := multipart.NewReader(bytes.NewReader(resp.body), params["boundary"])
	var parts [][]byte
	for {
		part, err := mr.NextPart()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		b, _ := io.ReadAll(part)
		parts = append(parts, b)
	}
	if len(parts) != 2 || !bytes.Equal(parts[0], data[0:10]) || !bytes.Equal(parts[1], data[65530:65546]) {
		t.Fatal("multi-range parts differ")
	}
	e.req(p, "GET", url, nil, "Range: bytes=300000-").expect(t, http.StatusRequestedRangeNotSatisfiable)

	// Conditional requests.
	e.req(p, "GET", url, nil, "If-None-Match: \""+n.VersionID+"\"").expect(t, 304)
	resp = e.req(p, "GET", url, nil, "If-Range: \"other\"", "Range: bytes=0-9").expect(t, 200)
	if len(resp.body) != len(data) {
		t.Fatal("If-Range mismatch did not send the whole file")
	}
	resp = e.req(p, "GET", url, nil, "If-Range: \""+n.VersionID+"\"", "Range: bytes=0-9").expect(t, 206)
	if len(resp.body) != 10 {
		t.Fatal("If-Range match did not send the range")
	}

	// HEAD: headers only, never audited.
	before := e.audit.count(core.ActFileDownload)
	resp = e.req(p, "HEAD", url, nil).expect(t, 200)
	if len(resp.body) != 0 || resp.header.Get("Content-Length") != strconv.Itoa(len(data)) {
		t.Fatalf("HEAD: %d body bytes, length %q", len(resp.body), resp.header.Get("Content-Length"))
	}
	if e.audit.count(core.ActFileDownload) != before {
		t.Fatal("HEAD was audited")
	}
	// Only downloads count: the full GET, the single range and the
	// multi-range starting at byte 0 and both If-Range requests (bytes=0-9);
	// the 304, the 416 and the other ranges did not.
	if got := e.audit.count(core.ActFileDownload); got != 5 {
		t.Fatalf("download audits %d, want 5", got)
	}

	// Older versions by id; their ETag is the version id.
	n2 := e.put(u, u.rootID, "data.bin", []byte("new content"))
	resp = e.req(p, "GET", url, nil).expect(t, 200)
	if string(resp.body) != "new content" || resp.header.Get("ETag") != `"`+n2.VersionID+`"` {
		t.Fatalf("current version: %q %s", truncate(resp.body), resp.header.Get("ETag"))
	}
	resp = e.req(p, "GET", url+"?version="+n.VersionID, nil).expect(t, 200)
	if !bytes.Equal(resp.body, data) || resp.header.Get("ETag") != `"`+n.VersionID+`"` {
		t.Fatal("old version differs")
	}
	e.req(p, "GET", url+"?version=ver_00000000000000000000000000", nil).expect(t, 404, "not_found")

	// Permissions and folders.
	bob := e.user("bob", core.RoleMember)
	e.req(bob.Principal, "GET", url, nil).expect(t, 404, "not_found")
	e.req(p, "GET", "/api/v1/nodes/"+u.rootID+"/content", nil).expect(t, 422, "invalid")
}

// TestContentDownloadAudit: whether a request is audited depends on what
// http.ServeContent really sends, not on how the Range / If-* headers are
// spelled — every answer that delivers the file from byte 0 is audited, and
// answers that send nothing (304, 412, 416) or only a later range are not.
func TestContentDownloadAudit(t *testing.T) {
	e := newEnv(t)
	u := e.user("alice", core.RoleMember)
	p := u.Principal
	data := make([]byte, 5000)
	_, _ = rand.Read(data)
	n := e.put(u, u.rootID, "data.bin", data)
	url := "/api/v1/nodes/" + n.ID + "/content"
	etag := `"` + n.VersionID + `"`
	cases := []struct {
		name    string
		method  string
		headers []string
		status  int
		audited bool
		body    []byte // nil = not checked
	}{
		{"full", "GET", nil, 200, true, data},
		{"suffix longer than the file", "GET", []string{"Range: bytes=-99999999"}, 206, true, data},
		{"suffix as long as the file", "GET", []string{"Range: bytes=-5000"}, 206, true, data},
		{"leading zero", "GET", []string{"Range: bytes=00-"}, 206, true, data},
		{"overlapping ranges", "GET", []string{"Range: bytes=1-,1-"}, 200, true, data},
		{"multi-range", "GET", []string{"Range: bytes=1-,0-0"}, 206, true, nil},
		{"stale If-Range", "GET", []string{`If-Range: "stale"`, "Range: bytes=100-"}, 200, true, data},
		{"If-Match mismatch", "GET", []string{`If-Match: "nope"`}, 412, false, nil},
		{"If-Unmodified-Since past", "GET", []string{"If-Unmodified-Since: Sat, 01 Jan 2000 00:00:00 GMT"}, 412, false, nil},
		{"If-None-Match hit", "GET", []string{"If-None-Match: " + etag}, 304, false, nil},
		{"unsatisfiable", "GET", []string{"Range: bytes=300000-"}, 416, false, nil},
		{"short suffix", "GET", []string{"Range: bytes=-500"}, 206, false, data[4500:]},
		{"later range", "GET", []string{"Range: bytes=100-"}, 206, false, data[100:]},
		{"matching If-Range, later range", "GET", []string{"If-Range: " + etag, "Range: bytes=100-"}, 206, false, data[100:]},
		{"HEAD", "HEAD", nil, 200, false, nil},
	}
	for _, c := range cases {
		before := e.audit.count(core.ActFileDownload)
		resp := e.req(p, c.method, url, nil, c.headers...)
		if resp.status != c.status {
			t.Errorf("%s: status %d, want %d", c.name, resp.status, c.status)
			continue
		}
		if c.body != nil && !bytes.Equal(resp.body, c.body) {
			t.Errorf("%s: body differs (%d bytes)", c.name, len(resp.body))
		}
		want := 0
		if c.audited {
			want = 1
		}
		if got := e.audit.count(core.ActFileDownload) - before; got != want {
			t.Errorf("%s: %d download audits, want %d", c.name, got, want)
		}
	}
}

func TestContentTypesAndInline(t *testing.T) {
	e := newEnv(t)
	u := e.user("alice", core.RoleMember)
	p := u.Principal
	html := "<!DOCTYPE html><html><body><script>alert(document.cookie)</script></body></html>\n"
	svg := `<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>` + "\n"
	pdf := "%PDF-1.7\n1 0 obj << >> endobj\ntrailer << >>\n%%EOF\n"
	cases := []struct {
		name, data   string
		inline       bool
		ctype, disp  string
		csp          string
		frameOptions string
	}{
		{"evil.html", html, true, "application/octet-stream", "attachment", httpx.CSPContent, "DENY"},
		{"evil.svg", svg, true, "application/octet-stream", "attachment", httpx.CSPContent, "DENY"},
		{"evil.png", html, true, "application/octet-stream", "attachment", httpx.CSPContent, "DENY"}, // sniffed as HTML
		{"script.js", "alert(1)", true, "application/octet-stream", "attachment", httpx.CSPContent, "DENY"},
		{"note.txt", "just text\n", true, "text/plain; charset=utf-8", "inline", httpx.CSPContent, "DENY"},
		{"note.txt", "just text\n", false, "text/plain; charset=utf-8", "attachment", httpx.CSPContent, "DENY"},
		{"data.json", `{"a":1}`, true, "text/plain; charset=utf-8", "inline", httpx.CSPContent, "DENY"},
		{"doc.pdf", pdf, true, "application/pdf", "inline", httpx.CSPContentPDF, "SAMEORIGIN"},
		{"doc.pdf", pdf, false, "application/pdf", "attachment", httpx.CSPContent, "DENY"},
		{"fake.pdf", html, true, "application/octet-stream", "attachment", httpx.CSPContent, "DENY"},
		{"pic.png", string(pngBytes(t, 4, 4, false)), true, "image/png", "inline", httpx.CSPContent, "DENY"},
	}
	for i, c := range cases {
		folder := e.mkdirAPI(u, u.rootID, "case"+strconv.Itoa(i))
		n := e.put(u, folder, c.name, []byte(c.data))
		url := "/api/v1/nodes/" + n.ID + "/content"
		if c.inline {
			url += "?inline=1"
		}
		resp := e.req(p, "GET", url, nil).expect(t, 200)
		h := resp.header
		if got := h.Get("Content-Type"); got != c.ctype {
			t.Errorf("%s inline=%v: Content-Type %q, want %q", c.name, c.inline, got, c.ctype)
		}
		if got := h.Get("Content-Disposition"); !strings.HasPrefix(got, c.disp+";") {
			t.Errorf("%s inline=%v: Content-Disposition %q", c.name, c.inline, got)
		}
		if got := h.Get("Content-Security-Policy"); got != c.csp {
			t.Errorf("%s inline=%v: CSP %q", c.name, c.inline, got)
		}
		if got := h.Get("X-Frame-Options"); got != c.frameOptions {
			t.Errorf("%s inline=%v: X-Frame-Options %q", c.name, c.inline, got)
		}
		if err := mw.CheckSecurityHeaders(h, mw.HeadersContent); err != nil {
			t.Errorf("%s: %v", c.name, err)
		}
		if string(resp.body) != c.data {
			t.Errorf("%s: body differs", c.name)
		}
	}
	// Non-ASCII names use RFC 6266 filename*.
	n := e.put(u, u.rootID, "Grüße ☃.txt", []byte("x"))
	resp := e.req(p, "GET", "/api/v1/nodes/"+n.ID+"/content", nil).expect(t, 200)
	if got := resp.header.Get("Content-Disposition"); !strings.Contains(got, "filename*=UTF-8''Gr%C3%BC%C3%9Fe%20%E2%98%83.txt") {
		t.Errorf("disposition %q", got)
	}
}

// mkdirAPI creates a folder through the API.
func (e *testEnv) mkdirAPI(u *user, parent, name string) string {
	e.t.Helper()
	var n core.Node
	e.req(u.Principal, "POST", "/api/v1/nodes/"+parent+"/folders", core.NameInput{Name: name}).expect(e.t, 201).json(e.t, &n)
	return n.ID
}

// pngBytes returns a w×h PNG image.
func pngBytes(t *testing.T, w, h int, alpha bool) []byte {
	t.Helper()
	img := image.NewNRGBA(image.Rect(0, 0, w, h))
	for y := 0; y < h; y++ {
		for x := 0; x < w; x++ {
			a := uint8(255)
			if alpha && x == 0 {
				a = 10
			}
			img.Set(x, y, color.NRGBA{R: uint8(x * 3), G: uint8(y * 5), B: 90, A: a})
		}
	}
	var buf bytes.Buffer
	if err := png.Encode(&buf, img); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func TestThumb(t *testing.T) {
	e := newEnv(t)
	u := e.user("alice", core.RoleMember)
	p := u.Principal
	n := e.put(u, u.rootID, "photo.png", pngBytes(t, 800, 400, false))
	url := "/api/v1/nodes/" + n.ID + "/thumb?v=" + n.VersionID
	e.req(p, "GET", url, nil).expect(t, 404, "not_found")
	e.jobs.drain(t)
	resp := e.req(p, "GET", url, nil).expect(t, 200)
	h := resp.header
	if h.Get("Content-Type") != "image/jpeg" || !strings.HasPrefix(h.Get("Content-Disposition"), "inline;") ||
		h.Get("ETag") == "" {
		t.Fatalf("thumb headers %v", h)
	}
	if err := mw.CheckSecurityHeaders(h, mw.HeadersContent); err != nil {
		t.Error(err)
	}
	cfg, format, err := image.DecodeConfig(bytes.NewReader(resp.body))
	if err != nil || format != "jpeg" || cfg.Width != 320 || cfg.Height != 160 {
		t.Fatalf("thumb %s %dx%d %v", format, cfg.Width, cfg.Height, err)
	}
	e.req(p, "GET", url, nil, "If-None-Match: "+h.Get("ETag")).expect(t, 304)
	if e.audit.count(core.ActFileDownload) != 0 {
		t.Fatal("thumbnails are audited as downloads")
	}
	// Transparent images get a PNG thumbnail.
	a := e.put(u, u.rootID, "alpha.png", pngBytes(t, 50, 50, true))
	e.jobs.drain(t)
	resp = e.req(p, "GET", "/api/v1/nodes/"+a.ID+"/thumb", nil).expect(t, 200)
	if resp.header.Get("Content-Type") != "image/png" {
		t.Fatalf("alpha thumb type %q", resp.header.Get("Content-Type"))
	}
	bob := e.user("bob", core.RoleMember)
	e.req(bob.Principal, "GET", url, nil).expect(t, 404, "not_found")
}

// zipNames returns the entry names of a zip and the content of files.
func zipContents(t *testing.T, data []byte) map[string]string {
	t.Helper()
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		t.Fatalf("zip: %v", err)
	}
	out := map[string]string{}
	for _, f := range zr.File {
		if strings.HasSuffix(f.Name, "/") {
			out[f.Name] = "<dir>"
			continue
		}
		rc, err := f.Open()
		if err != nil {
			t.Fatal(err)
		}
		b, err := io.ReadAll(rc)
		rc.Close()
		if err != nil {
			t.Fatal(err)
		}
		out[f.Name] = string(b)
	}
	return out
}

func TestArchives(t *testing.T) {
	e := newEnv(t)
	u := e.user("alice", core.RoleMember)
	p := u.Principal
	trip := e.mkdirAPI(u, u.rootID, "Trip")
	e.put(u, trip, "day1/a.txt", []byte("alpha\n"))
	e.put(u, trip, "day2/deep/x/y/z.txt", []byte("deep file\n"))
	e.mkdirAPI(u, trip, "empty")

	var tr core.ArchiveTicketResponse
	e.req(p, "POST", "/api/v1/archives", core.ArchiveInput{NodeIDs: []string{trip}, Format: "zip", Name: "Trip"}).
		expect(t, 200).json(t, &tr)
	if tr.Ticket == "" || tr.URL != "/api/v1/archives/"+tr.Ticket {
		t.Fatalf("ticket response %+v", tr)
	}
	// HEAD does not consume the ticket.
	resp := e.req(nil, "HEAD", tr.URL, nil).expect(t, 200)
	if !strings.HasPrefix(resp.header.Get("Content-Disposition"), `attachment; filename="Trip.zip"`) {
		t.Fatalf("HEAD disposition %q", resp.header.Get("Content-Disposition"))
	}
	// Anonymous GET with the ticket streams the zip.
	resp = e.req(nil, "GET", tr.URL, nil).expect(t, 200)
	if got := resp.header.Get("Content-Disposition"); got != `attachment; filename="Trip.zip"` {
		t.Errorf("disposition %q", got)
	}
	if err := mw.CheckSecurityHeaders(resp.header, mw.HeadersContent); err != nil {
		t.Error(err)
	}
	got := zipContents(t, resp.body)
	for name, want := range map[string]string{
		"Trip/": "<dir>", "Trip/empty/": "<dir>", "Trip/day1/a.txt": "alpha\n", "Trip/day2/deep/x/y/z.txt": "deep file\n",
	} {
		if got[name] != want {
			t.Errorf("zip %q = %q, want %q (entries %v)", name, got[name], want, got)
		}
	}
	if a := e.audit.last(core.ActArchiveDownload); a == nil || a.ActorID != u.UserID {
		t.Fatalf("archive audit %+v", a)
	}
	// Single use.
	e.req(nil, "GET", tr.URL, nil).expect(t, 404, "not_found")
	e.req(nil, "HEAD", tr.URL, nil).expect(t, 404)

	// Tar.
	e.req(p, "POST", "/api/v1/archives", core.ArchiveInput{NodeIDs: []string{trip}, Format: "tar"}).expect(t, 200).json(t, &tr)
	resp = e.req(nil, "GET", tr.URL, nil).expect(t, 200)
	tarRd := tar.NewReader(bytes.NewReader(resp.body))
	var names []string
	for {
		hd, err := tarRd.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		names = append(names, hd.Name)
	}
	if !strings.Contains(strings.Join(names, "\n"), "Trip/day2/deep/x/y/z.txt") {
		t.Fatalf("tar names %v", names)
	}

	// Expired tickets.
	e.req(p, "POST", "/api/v1/archives", core.ArchiveInput{NodeIDs: []string{trip}}).expect(t, 200).json(t, &tr)
	e.clock.advance(61 * time.Second)
	e.req(nil, "GET", tr.URL, nil).expect(t, 404, "not_found")

	// Errors before the first byte are API errors.
	e.req(p, "POST", "/api/v1/archives", core.ArchiveInput{NodeIDs: []string{trip}}).expect(t, 200).json(t, &tr)
	e.req(p, "POST", "/api/v1/nodes/trash", core.NodeIDsInput{IDs: []string{trip}}).expect(t, 204)
	e.req(nil, "GET", tr.URL, nil).expect(t, 404, "not_found")
	e.req(p, "POST", "/api/v1/trash/restore", core.NodeIDsInput{IDs: []string{trip}}).expect(t, 200)

	// Bad requests.
	bob := e.user("bob", core.RoleMember)
	e.req(bob.Principal, "POST", "/api/v1/archives", core.ArchiveInput{NodeIDs: []string{trip}}).expect(t, 404, "not_found")
	e.req(p, "POST", "/api/v1/archives", core.ArchiveInput{}).expect(t, 422, "invalid")
	e.req(p, "POST", "/api/v1/archives", core.ArchiveInput{NodeIDs: []string{trip}, Format: "7z"}).expect(t, 422, "invalid")
	e.req(nil, "GET", "/api/v1/archives/"+strings.Repeat("x", 43), nil).expect(t, 404, "not_found")

	// Share-bound tickets are only redeemed by the share route (password and
	// download counter), never here.
	shareID := ids.New(ids.PrefixShare)
	now := db.Ms(e.clock.Now())
	if _, err := e.db.Exec(e.ctx, `INSERT INTO shares (id, kind, node_id, created_by, token_hash, token_enc, created_at, updated_at)
		VALUES (?, 'link', ?, ?, ?, 'x', ?, ?)`, shareID, trip, u.UserID, ids.HashToken("tok"), now, now); err != nil {
		t.Fatal(err)
	}
	st, err := e.files.CreateArchiveTicket(e.ctx, nil, shareID, core.ArchiveInput{NodeIDs: []string{trip}})
	if err != nil {
		t.Fatal(err)
	}
	e.req(nil, "HEAD", "/api/v1/archives/"+st, nil).expect(t, 404)
	e.req(nil, "GET", "/api/v1/archives/"+st, nil).expect(t, 404, "not_found")
}

// TestArchiveAbort: a failure after the response started aborts the
// connection instead of ending a truncated archive cleanly.
func TestArchiveAbort(t *testing.T) {
	e := newEnv(t)
	u := e.user("alice", core.RoleMember)
	big := make([]byte, 256<<10)
	_, _ = rand.Read(big)
	dir := e.mkdirAPI(u, u.rootID, "D")
	e.put(u, dir, "a.bin", big)
	broken := e.put(u, dir, "b.bin", []byte("gone"))
	var blobID string
	if err := e.db.QueryRow(e.ctx, `SELECT v.blob_id FROM file_versions v WHERE v.id = ?`, broken.VersionID).Scan(&blobID); err != nil {
		t.Fatal(err)
	}
	e.blobs.forget(blobID)
	var tr core.ArchiveTicketResponse
	e.req(u.Principal, "POST", "/api/v1/archives", core.ArchiveInput{NodeIDs: []string{dir}}).expect(t, 200).json(t, &tr)
	req, _ := http.NewRequest("GET", e.srv.URL+tr.URL, nil)
	req.Header.Set("X-Test-Anonymous", "1")
	resp, err := e.srv.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("status %d", resp.StatusCode)
	}
	if _, err := io.ReadAll(resp.Body); err == nil {
		t.Fatal("a truncated archive was delivered as complete")
	}
}

// TestOldVersionServedAsAttachment pins that an older version is never
// delivered under the type the node has today: v1 of "doc.pdf" holds HTML
// (stored as text/html, because names.DetectMIME refuses the name's claim),
// v2 is a real PDF and makes the node application/pdf. Serving v1 as a PDF
// would hand those HTML bytes back inline, with the weaker headers that
// inline PDFs get (CSPContentPDF, X-Frame-Options: SAMEORIGIN).
func TestOldVersionServedAsAttachment(t *testing.T) {
	e := newEnv(t)
	u := e.user("alice", core.RoleMember)
	p := u.Principal
	html := "<!DOCTYPE html><html><body><script>alert(document.cookie)</script></body></html>\n"
	pdf := "%PDF-1.7\n1 0 obj << >> endobj\ntrailer << >>\n%%EOF\n"

	v1 := e.put(u, u.rootID, "doc.pdf", []byte(html))
	if v1.MIME != "text/html; charset=utf-8" && !strings.HasPrefix(v1.MIME, "text/html") {
		t.Fatalf("v1 MIME = %q, want text/html", v1.MIME)
	}
	v2 := e.put(u, u.rootID, "doc.pdf", []byte(pdf))
	if v2.MIME != "application/pdf" {
		t.Fatalf("v2 MIME = %q, want application/pdf", v2.MIME)
	}
	url := "/api/v1/nodes/" + v2.ID + "/content"
	resp := e.req(p, "GET", url+"?inline=1&version="+v1.VersionID, nil).expect(t, 200)
	if string(resp.body) != html {
		t.Fatalf("body of the old version differs")
	}
	if got := resp.header.Get("Content-Type"); got != "application/octet-stream" {
		t.Errorf("old version Content-Type = %q, want application/octet-stream", got)
	}
	if got := resp.header.Get("Content-Disposition"); !strings.HasPrefix(got, "attachment;") {
		t.Errorf("old version Content-Disposition = %q, want attachment", got)
	}
	if got := resp.header.Get("Content-Security-Policy"); got != httpx.CSPContent {
		t.Errorf("old version CSP = %q, want the full sandbox", got)
	}
	if got := resp.header.Get("X-Frame-Options"); got != "DENY" {
		t.Errorf("old version X-Frame-Options = %q, want DENY", got)
	}
	// The current version is unaffected.
	resp = e.req(p, "GET", url+"?inline=1", nil).expect(t, 200)
	if got := resp.header.Get("Content-Type"); got != "application/pdf" {
		t.Errorf("current version Content-Type = %q, want application/pdf", got)
	}
}
