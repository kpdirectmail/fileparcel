package uploadapi

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"

	"fileparcel/internal/core"
	"fileparcel/internal/uploads"
	"fileparcel/internal/uploads/uploadtest"
	"fileparcel/internal/web/httpx"
	"fileparcel/internal/web/mw"
)

type fixture struct {
	*uploadtest.Env
	t     *testing.T
	srv   *httptest.Server
	alice string
	root  string
	bob   string
}

func setup(t *testing.T) *fixture {
	t.Helper()
	e := uploadtest.New(t)
	svc, err := uploads.New(e.Env, e.Files, e.Blobs, e.Jobs)
	if err != nil {
		t.Fatal(err)
	}
	d := e.Deps(svc, nil)
	r := chi.NewRouter()
	r.Use(mw.Inject(d), middleware.GetHead, mw.RequestID, mw.ResolveClientIP, mw.SecurityHeaders)
	api := chi.NewRouter()
	Mount(api, d)
	r.With(mw.MaxBody(httpx.DefaultMaxBody), mw.Authenticate, mw.CSRF).Mount("/api/v1", api)
	srv := httptest.NewServer(r)
	t.Cleanup(srv.Close)
	f := &fixture{Env: e, t: t, srv: srv}
	f.alice, f.root = e.User("alice", core.RoleMember)
	f.bob, _ = e.User("bob", core.RoleMember)
	return f
}

func sum(b []byte) string { s := sha256.Sum256(b); return hex.EncodeToString(s[:]) }

func data(n int) []byte {
	r := rand.New(rand.NewPCG(uint64(n), 7))
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(r.Uint32())
	}
	return b
}

// do sends a request as auth ("" = anonymous) and decodes a JSON response into out.
func (f *fixture) do(method, path, auth string, body io.Reader, hdr map[string]string, out any) *http.Response {
	f.t.Helper()
	req, err := http.NewRequest(method, f.srv.URL+path, body)
	if err != nil {
		f.t.Fatal(err)
	}
	if auth != "" {
		req.Header.Set("Authorization", "Bearer "+auth)
	}
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		f.t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	if out != nil && len(raw) > 0 {
		if err := json.Unmarshal(raw, out); err != nil {
			f.t.Fatalf("%s %s: decode %q: %v", method, path, raw, err)
		}
	}
	resp.Body = io.NopCloser(bytes.NewReader(raw))
	return resp
}

func (f *fixture) json(method, path, auth string, in, out any) *http.Response {
	f.t.Helper()
	var body io.Reader
	if in != nil {
		b, _ := json.Marshal(in)
		body = bytes.NewReader(b)
	}
	return f.do(method, path, auth, body, map[string]string{"Content-Type": "application/json"}, out)
}

type apiErr struct {
	Error struct {
		Code, Message, Field string
	} `json:"error"`
}

func (f *fixture) wantErr(resp *http.Response, status int, code string) {
	f.t.Helper()
	var e apiErr
	_ = json.NewDecoder(resp.Body).Decode(&e)
	if resp.StatusCode != status || e.Error.Code != code {
		f.t.Fatalf("got %d %q (%s), want %d %q", resp.StatusCode, e.Error.Code, e.Error.Message, status, code)
	}
}

func TestPartedUploadOverHTTP(t *testing.T) {
	f := setup(t)
	big := data(2*core.PartSize + 77)
	small := []byte("small file")
	var b core.UploadBatch
	resp := f.json("POST", "/api/v1/upload-batches", f.alice, core.BatchInput{FolderID: f.root, Files: []core.UploadFileInput{
		{ClientRef: "big", RelPath: "Trip/big.bin", Size: int64(len(big))},
		{ClientRef: "s", RelPath: "Trip/small.txt", Size: int64(len(small))},
	}}, &b)
	if resp.StatusCode != http.StatusCreated || b.ID == "" || len(b.Files) != 2 || b.PartSize != core.PartSize ||
		b.SmallMax != SmallMax || b.Parallel < 1 {
		t.Fatalf("create: %d %+v", resp.StatusCode, b)
	}
	if err := mw.CheckSecurityHeaders(resp.Header, mw.HeadersAPI); err != nil {
		t.Error(err)
	}
	up := b.Files[0].ID

	// Parts in parallel, out of order.
	var wg sync.WaitGroup
	for _, n := range []int{2, 0, 1} {
		wg.Go(func() {
			p := big[n*core.PartSize : min((n+1)*core.PartSize, len(big))]
			resp := f.do("PUT", fmt.Sprintf("/api/v1/uploads/%s/parts/%d", up, n), f.alice, bytes.NewReader(p),
				map[string]string{HeaderSHA256: sum(p)}, nil)
			if resp.StatusCode != http.StatusNoContent {
				t.Errorf("part %d: %d", n, resp.StatusCode)
			}
		})
	}
	wg.Wait()
	var st core.UploadFileState
	f.json("GET", "/api/v1/uploads/"+up, f.alice, nil, &st)
	if len(st.PartsDone) != 3 || st.State != core.UploadUploading {
		t.Fatalf("status %+v", st)
	}
	// Idempotent resend and conflicting resend.
	p0 := big[:core.PartSize]
	if r := f.do("PUT", "/api/v1/uploads/"+up+"/parts/0", f.alice, bytes.NewReader(p0), map[string]string{HeaderSHA256: sum(p0)}, nil); r.StatusCode != 204 {
		t.Fatalf("resend: %d", r.StatusCode)
	}
	bad := bytes.Clone(p0)
	bad[0] ^= 1
	f.wantErr(f.do("PUT", "/api/v1/uploads/"+up+"/parts/0", f.alice, bytes.NewReader(bad), map[string]string{HeaderSHA256: sum(bad)}, nil),
		409, "conflict")

	f.json("POST", "/api/v1/uploads/"+up+"/complete", f.alice, nil, &st)
	if st.State != core.UploadCommitted || st.NodeID == "" {
		t.Fatalf("complete: %+v", st)
	}
	resp = f.do("PUT", "/api/v1/upload-batches/"+b.ID+"/small?ref=s", f.alice, bytes.NewReader(small),
		map[string]string{HeaderSHA256: sum(small)}, &st)
	if resp.StatusCode != 200 || st.State != core.UploadCommitted {
		t.Fatalf("small: %d %+v", resp.StatusCode, st)
	}
	var done core.UploadBatch
	resp = f.json("POST", "/api/v1/upload-batches/"+b.ID+"/complete", f.alice, nil, &done)
	if resp.StatusCode != 200 || done.State != core.BatchDone {
		t.Fatalf("complete batch: %d %+v", resp.StatusCode, done)
	}
	var got core.UploadBatch
	f.json("GET", "/api/v1/upload-batches/"+b.ID, f.alice, nil, &got)
	if got.State != core.BatchDone || len(got.Files) != 2 {
		t.Fatalf("get: %+v", got)
	}
	blob := f.Str(`SELECT v.blob_id FROM nodes n JOIN file_versions v ON v.id = n.version_id WHERE n.name = 'big.bin'`)
	if !bytes.Equal(f.Blobs.Bytes(blob), big) {
		t.Fatal("stored content differs")
	}
}

func TestZipAndAbortOverHTTP(t *testing.T) {
	f := setup(t)
	f.Jobs.Manual = true
	var b core.UploadBatch
	f.json("POST", "/api/v1/upload-batches", f.alice, core.BatchInput{FolderID: f.root, Mode: core.UploadModeZip, ZipName: "z",
		Files: []core.UploadFileInput{{ClientRef: "a", RelPath: "a.txt", Size: 1}}}, &b)
	var st core.UploadFileState
	f.do("PUT", "/api/v1/upload-batches/"+b.ID+"/small?ref=a", f.alice, strings.NewReader("a"), map[string]string{HeaderSHA256: sum([]byte("a"))}, &st)
	var fin core.UploadBatch
	resp := f.json("POST", "/api/v1/upload-batches/"+b.ID+"/complete", f.alice, nil, &fin)
	if resp.StatusCode != http.StatusAccepted || fin.State != core.BatchFinalizing || fin.JobID == "" {
		t.Fatalf("zip complete: %d %+v", resp.StatusCode, fin)
	}
	if err := f.Jobs.Run(fin.JobID); err != nil {
		t.Fatal(err)
	}

	// Add files, abort a file, abort the batch.
	var b2 core.UploadBatch
	f.json("POST", "/api/v1/upload-batches", f.alice, core.BatchInput{FolderID: f.root}, &b2)
	var states []core.UploadFileState
	resp = f.json("POST", "/api/v1/upload-batches/"+b2.ID+"/files", f.alice,
		[]core.UploadFileInput{{ClientRef: "x", RelPath: "x.bin", Size: 5}, {ClientRef: "y", RelPath: "y.bin", Size: 6}}, &states)
	if resp.StatusCode != 200 || len(states) != 2 {
		t.Fatalf("add files: %d %+v", resp.StatusCode, states)
	}
	if r := f.do("DELETE", "/api/v1/uploads/"+states[0].ID, f.alice, nil, nil, nil); r.StatusCode != 204 {
		t.Fatalf("abort file: %d", r.StatusCode)
	}
	f.json("GET", "/api/v1/uploads/"+states[0].ID, f.alice, nil, &st)
	if st.State != core.UploadAborted {
		t.Fatalf("aborted file: %+v", st)
	}
	f.wantErr(f.do("DELETE", "/api/v1/upload-batches/"+b2.ID, f.bob, nil, nil, nil), 404, "not_found")
	if r := f.do("DELETE", "/api/v1/upload-batches/"+b2.ID, f.alice, nil, nil, nil); r.StatusCode != 204 {
		t.Fatalf("abort batch: %d", r.StatusCode)
	}
	f.wantErr(f.do("POST", "/api/v1/uploads/"+states[1].ID+"/complete", f.alice, nil, nil, nil), 409, "conflict")
}

func TestErrorsOverHTTP(t *testing.T) {
	f := setup(t)
	var b core.UploadBatch
	f.json("POST", "/api/v1/upload-batches", f.alice, core.BatchInput{FolderID: f.root, Files: []core.UploadFileInput{
		{ClientRef: "big", RelPath: "big.bin", Size: core.PartSize + 1}, {ClientRef: "s", RelPath: "s.txt", Size: 3}}}, &b)
	up := b.Files[0].ID
	part := data(core.PartSize)
	cases := []struct {
		name   string
		method string
		path   string
		auth   string
		body   []byte
		hdr    map[string]string
		status int
		code   string
	}{
		{"anonymous", "GET", "/api/v1/uploads/" + up, "", nil, nil, 401, "unauthorized"},
		{"no write scope", "GET", "/api/v1/uploads/" + up, f.alice + ";files:read", nil, nil, 403, "forbidden"},
		{"other user", "GET", "/api/v1/uploads/" + up, f.bob, nil, nil, 404, "not_found"},
		{"missing digest", "PUT", "/api/v1/uploads/" + up + "/parts/0", f.alice, part, nil, 422, "invalid"},
		{"bad digest header", "PUT", "/api/v1/uploads/" + up + "/parts/0", f.alice, part, map[string]string{HeaderSHA256: "xyz"}, 422, "invalid"},
		{"wrong digest", "PUT", "/api/v1/uploads/" + up + "/parts/0", f.alice, part, map[string]string{HeaderSHA256: sum([]byte("x"))}, 422, "invalid"},
		{"bad part number", "PUT", "/api/v1/uploads/" + up + "/parts/-1", f.alice, part, map[string]string{HeaderSHA256: sum(part)}, 422, "invalid"},
		{"part out of range", "PUT", "/api/v1/uploads/" + up + "/parts/7", f.alice, part, map[string]string{HeaderSHA256: sum(part)}, 422, "invalid"},
		{"part too large", "PUT", "/api/v1/uploads/" + up + "/parts/0", f.alice, append(bytes.Clone(part), 1), map[string]string{HeaderSHA256: sum(part)}, 413, "too_large"},
		{"short last part", "PUT", "/api/v1/uploads/" + up + "/parts/1", f.alice, []byte{}, map[string]string{HeaderSHA256: sum(nil)}, 422, "invalid"},
		{"small without ref", "PUT", "/api/v1/upload-batches/" + b.ID + "/small", f.alice, []byte("abc"), map[string]string{HeaderSHA256: sum([]byte("abc"))}, 422, "invalid"},
		{"small too large", "PUT", "/api/v1/upload-batches/" + b.ID + "/small?ref=s", f.alice, make([]byte, SmallMax+1), map[string]string{HeaderSHA256: sum(nil)}, 413, "too_large"},
		{"small wrong size", "PUT", "/api/v1/upload-batches/" + b.ID + "/small?ref=s", f.alice, []byte("abcd"), map[string]string{HeaderSHA256: sum([]byte("abcd"))}, 422, "invalid"},
		{"unknown batch", "GET", "/api/v1/upload-batches/upb_nope", f.alice, nil, nil, 404, "not_found"},
		{"bad json", "POST", "/api/v1/upload-batches", f.alice, []byte(`{"folder_id":`), map[string]string{"Content-Type": "application/json"}, 422, "invalid"},
		{"unknown field", "POST", "/api/v1/upload-batches", f.alice, []byte(`{"folder_id":"x","evil":1}`), map[string]string{"Content-Type": "application/json"}, 422, "invalid"},
		{"traversal", "POST", "/api/v1/upload-batches", f.alice, []byte(`{"folder_id":"` + f.root + `","files":[{"client_ref":"a","rel_path":"../../etc/passwd","size":1}]}`),
			map[string]string{"Content-Type": "application/json"}, 422, "invalid"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var body io.Reader
			if c.body != nil {
				body = bytes.NewReader(c.body)
			}
			f.wantErr(f.do(c.method, c.path, c.auth, body, c.hdr, nil), c.status, c.code)
		})
	}
	// Chunked body (no Content-Length) larger than a part is cut off at the limit.
	req, _ := http.NewRequest("PUT", f.srv.URL+"/api/v1/uploads/"+up+"/parts/0", io.MultiReader(bytes.NewReader(part), strings.NewReader("extra")))
	req.Header.Set("Authorization", "Bearer "+f.alice)
	req.Header.Set(HeaderSHA256, sum(part))
	req.ContentLength = -1
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversized chunked part: %d", resp.StatusCode)
	}
	var st core.UploadFileState
	f.json("GET", "/api/v1/uploads/"+up, f.alice, nil, &st)
	if len(st.PartsDone) != 0 {
		t.Fatalf("a rejected part was recorded: %v", st.PartsDone)
	}
}

func TestParseHelpers(t *testing.T) {
	good := strings.Repeat("aB", 32)
	for _, c := range []struct {
		in string
		ok bool
	}{{good, true}, {" " + good + " ", true}, {"", false}, {good[:63], false}, {good + "0", false}, {strings.Repeat("zz", 32), false}} {
		b, err := ParseSHA256(c.in)
		if (err == nil) != c.ok || (c.ok && len(b) != 32) {
			t.Errorf("ParseSHA256(%q) = %x, %v", c.in, b, err)
		}
		if err != nil {
			if ce := core.AsError(err); ce == nil || ce.Field != HeaderSHA256 {
				t.Errorf("field of %v", err)
			}
		}
	}
	for _, c := range []struct {
		in   string
		want int
		ok   bool
	}{{"0", 0, true}, {"17", 17, true}, {"1048575", 1<<20 - 1, true}, {"1048576", 0, false}, {"1048577", 0, false},
		{"-1", 0, false}, {"+1", 0, false}, {"1e3", 0, false}, {"", 0, false}, {"12345678", 0, false}, {"0x1", 0, false}} {
		n, err := ParsePartNumber(c.in)
		if (err == nil) != c.ok || n != c.want {
			t.Errorf("ParsePartNumber(%q) = %d, %v", c.in, n, err)
		}
		if err != nil && !errors.Is(err, core.ErrInvalid) {
			t.Errorf("error kind %v", err)
		}
	}
	// The route takes every part of the largest file the service accepts,
	// and no part beyond it.
	if MaxPartCount != uploads.MaxPartCount || uploads.MaxDeclaredFileBytes != int64(MaxPartCount)*core.PartSize {
		t.Fatalf("MaxPartCount %d, uploads.MaxPartCount %d, uploads.MaxDeclaredFileBytes %d",
			MaxPartCount, uploads.MaxPartCount, uploads.MaxDeclaredFileBytes)
	}
	if n, err := ParsePartNumber(fmt.Sprint(MaxPartCount - 1)); err != nil || n != MaxPartCount-1 {
		t.Fatalf("last part of the largest file refused: %d %v", n, err)
	}
}

func TestUnavailable(t *testing.T) {
	e := uploadtest.New(t)
	d := e.Deps(nil, nil)
	r := chi.NewRouter()
	r.Use(mw.Inject(d))
	api := chi.NewRouter()
	Mount(api, d)
	r.With(mw.Authenticate).Mount("/api/v1", api)
	u, _ := e.User("u", core.RoleMember)
	req := httptest.NewRequest("GET", "/api/v1/uploads/upf_x", nil)
	req.Header.Set("Authorization", "Bearer "+u)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status %d", rec.Code)
	}
}

// TestListBatchesOverHTTP: GET /upload-batches lists the caller's own
// unfinished batches, newest first and without files, so that one left
// behind by a closed tab or a killed CLI can be found and cancelled.
func TestListBatchesOverHTTP(t *testing.T) {
	f := setup(t)
	var list core.Page[core.UploadBatch]
	if resp := f.json("GET", "/api/v1/upload-batches", f.alice, nil, &list); resp.StatusCode != 200 || list.Items == nil || len(list.Items) != 0 {
		t.Fatalf("empty list: %d %+v", resp.StatusCode, list)
	}
	var b1, b2, done, other core.UploadBatch
	f.json("POST", "/api/v1/upload-batches", f.alice, core.BatchInput{FolderID: f.root,
		Files: []core.UploadFileInput{{ClientRef: "a", RelPath: "a.bin", Size: 300}}}, &b1)
	f.json("POST", "/api/v1/upload-batches", f.alice, core.BatchInput{FolderID: f.root, Mode: core.UploadModeZip, ZipName: "z.zip",
		Files: []core.UploadFileInput{{ClientRef: "b", RelPath: "b.bin", Size: 5}}}, &b2)
	f.json("POST", "/api/v1/upload-batches", f.alice, core.BatchInput{FolderID: f.root}, &done)
	f.json("POST", "/api/v1/upload-batches/"+done.ID+"/complete", f.alice, nil, nil)
	carol, carolRoot := f.Env.User("carol", core.RoleMember)
	if r := f.json("POST", "/api/v1/upload-batches", carol, core.BatchInput{FolderID: carolRoot}, &other); r.StatusCode != 201 {
		t.Fatalf("carol's batch: %d", r.StatusCode)
	}

	resp := f.json("GET", "/api/v1/upload-batches", f.alice, nil, &list)
	if resp.StatusCode != 200 || len(list.Items) != 2 {
		t.Fatalf("list: %d %+v", resp.StatusCode, list)
	}
	ids := []string{list.Items[0].ID, list.Items[1].ID}
	if !(ids[0] == b2.ID && ids[1] == b1.ID) && !(ids[0] == b1.ID && ids[1] == b2.ID) {
		t.Fatalf("listed %v, want %s and %s", ids, b1.ID, b2.ID)
	}
	for _, b := range list.Items {
		if b.State != core.BatchOpen || len(b.Files) != 0 || b.ReservedBytes <= 0 || b.ExpiresAt.IsZero() {
			t.Errorf("listed batch %+v", b)
		}
	}
	// Cancelling one removes it from the list.
	if r := f.do("DELETE", "/api/v1/upload-batches/"+b1.ID, f.alice, nil, nil, nil); r.StatusCode != 204 {
		t.Fatalf("abort: %d", r.StatusCode)
	}
	f.json("GET", "/api/v1/upload-batches", f.alice, nil, &list)
	if len(list.Items) != 1 || list.Items[0].ID != b2.ID || list.Items[0].ZipName != "z.zip" {
		t.Fatalf("after cancel: %+v", list.Items)
	}
	f.wantErr(f.do("GET", "/api/v1/upload-batches", "", nil, nil, nil), 401, "unauthorized")
}
