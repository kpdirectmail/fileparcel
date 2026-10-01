package static

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/klauspost/compress/gzip"
	"github.com/klauspost/compress/zstd"
)

func router() http.Handler {
	r := chi.NewRouter()
	r.Use(middleware.GetHead)
	MountRoot(r, nil)
	return r
}

func get(t *testing.T, h http.Handler, method, url string, hdr map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, url, nil)
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestBuildHashAndCompression(t *testing.T) {
	big := strings.Repeat("const x = 'hello world';\n", 200)
	fsys := fstest.MapFS{
		"static/js/app.js":       {Data: []byte(big)},
		"static/css/a.css":       {Data: []byte("body{}")}, // < 1 KiB: no variants
		"static/icons/a.png":     {Data: bytes.Repeat([]byte{0}, 4096)},
		"static/.hidden/x.js":    {Data: []byte(big)},
		"static/random.js":       {Data: randomish(4096)}, // incompressible
		"templates/ignored.html": {Data: []byte("x")},
	}
	a := build(fsys, "static")
	if len(a.hash) != 12 {
		t.Fatalf("hash %q", a.hash)
	}
	if len(a.files) != 5 {
		t.Fatalf("files %d", len(a.files))
	}
	js := a.files["js/app.js"]
	if js.Zstd == nil || js.Gzip == nil || len(js.Zstd) >= len(js.Data) {
		t.Fatalf("js variants: zstd %d gzip %d", len(js.Zstd), len(js.Gzip))
	}
	dz, _ := zstd.NewReader(nil)
	plain, err := dz.DecodeAll(js.Zstd, nil)
	if err != nil || string(plain) != big {
		t.Fatalf("zstd round trip: %v", err)
	}
	gr, _ := gzip.NewReader(bytes.NewReader(js.Gzip))
	plain, _ = io.ReadAll(gr)
	if string(plain) != big {
		t.Fatal("gzip round trip")
	}
	if c := a.files["css/a.css"]; c.Zstd != nil || c.Gzip != nil {
		t.Fatal("small file compressed")
	}
	if p := a.files["icons/a.png"]; p.Zstd != nil || p.Gzip != nil {
		t.Fatal("png compressed")
	}
	if r := a.files["random.js"]; r.Zstd != nil || r.Gzip != nil {
		t.Fatal("incompressible file kept a variant")
	}
	// The hash changes with content and with names.
	fsys["static/css/a.css"] = &fstest.MapFile{Data: []byte("body{color:red}")}
	if b := build(fsys, "static"); b.hash == a.hash {
		t.Fatal("hash did not change with content")
	}
	if b := build(fstest.MapFS{}, "static"); len(b.hash) != 12 {
		t.Fatalf("empty fs hash %q", b.hash)
	}
}

func randomish(n int) []byte {
	b := make([]byte, n)
	x := uint32(2463534242)
	for i := range b {
		x ^= x << 13
		x ^= x >> 17
		x ^= x << 5
		b[i] = byte(x)
	}
	return b
}

func TestNegotiate(t *testing.T) {
	cases := []struct {
		accept  string
		zst, gz bool
		want    string
	}{
		{"", true, true, ""},
		{"gzip", true, true, "gzip"},
		{"gzip, deflate, br, zstd", true, true, "zstd"},
		{"zstd;q=0.5, gzip;q=0.8", true, true, "gzip"},
		{"zstd;q=0, gzip", true, true, "gzip"},
		{"zstd", false, true, ""},
		{"*", true, true, "zstd"},
		{"*;q=0", true, true, ""},
		{"gzip;q=0, *", true, true, "zstd"},
		{"gzip;q=0, *", false, true, ""},
		{"x-gzip", true, true, "gzip"},
		{"GZIP", false, true, "gzip"},
		{"gzip;q=bogus", true, true, ""},
		{"br", true, true, ""},
		{"identity", true, true, ""},
	}
	for _, c := range cases {
		if got := Negotiate(c.accept, c.zst, c.gz); got != c.want {
			t.Errorf("%q zst=%v gz=%v: %q want %q", c.accept, c.zst, c.gz, got, c.want)
		}
	}
}

func TestServeHashed(t *testing.T) {
	h := router()
	a := load()
	if len(a.files) == 0 {
		t.Skip("no embedded assets")
	}
	var jsName string
	for n, f := range a.files {
		if strings.HasSuffix(n, ".js") && f.Zstd != nil {
			jsName = n
			break
		}
	}
	if jsName == "" {
		t.Skip("no compressible js asset")
	}
	f := a.files[jsName]
	url := Asset(jsName)

	rec := get(t, h, "GET", url, nil)
	if rec.Code != 200 || rec.Body.String() != string(f.Data) {
		t.Fatalf("identity: %d", rec.Code)
	}
	hd := rec.Header()
	if hd.Get("Content-Type") != "text/javascript; charset=utf-8" || hd.Get("Cache-Control") != CacheImmutable ||
		hd.Get("ETag") != f.ETag("") || hd.Get("Vary") != "Accept-Encoding" || hd.Get("Content-Encoding") != "" {
		t.Fatalf("identity headers: %v", hd)
	}

	rec = get(t, h, "GET", url, map[string]string{"Accept-Encoding": "gzip, deflate, br, zstd"})
	if rec.Code != 200 || rec.Header().Get("Content-Encoding") != "zstd" || !bytes.Equal(rec.Body.Bytes(), f.Zstd) ||
		rec.Header().Get("ETag") != f.ETag("zstd") || rec.Header().Get("Content-Length") == "" {
		t.Fatalf("zstd: %d %v", rec.Code, rec.Header())
	}
	rec = get(t, h, "GET", url, map[string]string{"Accept-Encoding": "gzip"})
	if rec.Header().Get("Content-Encoding") != "gzip" || !bytes.Equal(rec.Body.Bytes(), f.Gzip) {
		t.Fatalf("gzip: %v", rec.Header())
	}
	// Conditional request → 304 per representation.
	rec = get(t, h, "GET", url, map[string]string{"Accept-Encoding": "gzip", "If-None-Match": f.ETag("gzip")})
	if rec.Code != 304 || rec.Body.Len() != 0 {
		t.Fatalf("304: %d", rec.Code)
	}
	rec = get(t, h, "GET", url, map[string]string{"If-None-Match": f.ETag("gzip")})
	if rec.Code != 200 {
		t.Fatalf("etag of another encoding matched: %d", rec.Code)
	}
	// HEAD: headers, no body.
	rec = get(t, h, "HEAD", url, nil)
	if rec.Code != 200 || rec.Body.Len() != 0 || rec.Header().Get("Content-Length") == "" {
		t.Fatalf("HEAD: %d %d", rec.Code, rec.Body.Len())
	}
	// Range on the identity representation.
	rec = get(t, h, "GET", url, map[string]string{"Range": "bytes=0-9"})
	if rec.Code != 206 || rec.Body.String() != string(f.Data[:10]) {
		t.Fatalf("range: %d", rec.Code)
	}
	// Range with Accept-Encoding: the identity bytes, with a matching length
	// (never a slice of a compressed variant with the full variant's length).
	rec = get(t, h, "GET", url, map[string]string{"Range": "bytes=0-9", "Accept-Encoding": "gzip, zstd"})
	if rec.Code != 206 || rec.Body.String() != string(f.Data[:10]) || rec.Header().Get("Content-Encoding") != "" ||
		rec.Header().Get("Content-Length") != "10" || rec.Header().Get("ETag") != f.ETag("") {
		t.Fatalf("range with encoding: %d %v", rec.Code, rec.Header())
	}
	// Stale hash → current content, not cached immutably.
	stale := "/static/0123456789ab/" + jsName
	if Hash() == "0123456789ab" {
		stale = "/static/0123456789ac/" + jsName
	}
	rec = get(t, h, "GET", stale, nil)
	if rec.Code != 200 || rec.Header().Get("Cache-Control") != CacheNoCache {
		t.Fatalf("stale hash: %d %v", rec.Code, rec.Header().Get("Cache-Control"))
	}
}

func TestServeRejects(t *testing.T) {
	h := router()
	base := AssetBase()
	for _, u := range []string{
		base + "/nope.js",
		base + "/",
		base + "/.hidden",
		base + "/js/.secret.js",
		base + "/js/../sw.js",
		base + "/js//app.js",
		"/static/NOTAHASH/js/app.js",
		"/static/0123456789abcdef/js/app.js",
		"/static/" + strings.ToUpper(Hash()) + "/js/app.js",
	} {
		rec := get(t, h, "GET", u, nil)
		if rec.Code != 404 {
			t.Errorf("%s: %d", u, rec.Code)
		}
	}
}

func TestValidRel(t *testing.T) {
	good := []string{"js/app.js", "icons/logo.svg", "sw.js"}
	bad := []string{"", "/js/app.js", "js/../x", "./x", "js/./x", ".env", "js/.x", "a\\b", "js//x", "js/"}
	for _, s := range good {
		if !validRel(s) {
			t.Errorf("rejected %q", s)
		}
	}
	for _, s := range bad {
		if validRel(s) {
			t.Errorf("accepted %q", s)
		}
	}
}

func TestContentTypes(t *testing.T) {
	cases := map[string]string{
		"a.js":                 "text/javascript; charset=utf-8",
		"a.mjs":                "text/javascript; charset=utf-8",
		"a.CSS":                "text/css; charset=utf-8",
		"a.svg":                "image/svg+xml",
		"manifest.webmanifest": "application/manifest+json",
		"a.png":                "image/png",
		"a.json":               "application/json",
		"a.woff2":              "font/woff2",
		"a.ico":                "image/x-icon",
		"noext":                "application/octet-stream",
	}
	for n, want := range cases {
		if got := ContentType(n); got != want {
			t.Errorf("%s: %q want %q", n, got, want)
		}
	}
}

func TestTemplated(t *testing.T) {
	a, ok := Templated("sw.js")
	if !ok {
		t.Skip("no sw.js")
	}
	s := string(a.Data)
	if strings.Contains(s, PlaceholderBase) || strings.Contains(s, PlaceholderHash) || !strings.Contains(s, Hash()) {
		t.Fatal("placeholders not replaced")
	}
	b, _ := Templated("/sw.js")
	if a != b {
		t.Fatal("templated asset not cached")
	}
	if _, ok := Templated("missing.js"); ok {
		t.Fatal("missing file")
	}
	if got := string(Replace([]byte(PlaceholderBase + "|" + PlaceholderHash))); got != AssetBase()+"|"+Hash() {
		t.Fatal(got)
	}
	if !strings.HasPrefix(Asset("/js/app.js"), "/static/"+Hash()+"/js/app.js") {
		t.Fatal(Asset("/js/app.js"))
	}
	if _, ok := File("js/app.js"); !ok {
		t.Fatal("File(js/app.js)")
	}
}
