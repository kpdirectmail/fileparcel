// Package static serves the embedded web assets (webassets.FS "static/")
// under /static/<hash>/… (DESIGN §13.1), where <hash> is the first 12 hex
// digits of a SHA-256 over every static file (path and content), computed
// once at startup. Hashed URLs are cached immutably; a new build changes the
// hash.
//
// At startup every text asset (JS, CSS, SVG, JSON, web manifest, HTML, TXT)
// of at least 1 KiB is also compressed with zstd and gzip (best
// compression) and kept in memory; each request gets the best variant its
// Accept-Encoding allows (zstd > gzip > identity, honouring q-values), with
// Vary: Accept-Encoding and a per-representation strong ETag. Range,
// If-None-Match and HEAD are handled by http.ServeContent.
//
// Dotfiles (any path segment starting with ".") are never served. A request
// for a stale hash (an app shell loaded before an upgrade lazily importing a
// module) gets the current file with Cache-Control: no-cache instead of a 404.
//
// Root files (/sw.js, /manifest.webmanifest, /favicon.ico) are served by
// package pages using Templated and Serve.
//
// Placeholders replaced by Templated in sw.js and manifest.webmanifest:
//
//	__FP_ASSET_BASE__   → "/static/<hash>"
//	__FP_ASSET_HASH__   → "<hash>"
package static

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"io/fs"
	"mime"
	"net/http"
	"path"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/klauspost/compress/gzip"
	"github.com/klauspost/compress/zstd"

	webassets "fileparcel/web"

	"fileparcel/internal/app"
)

// Placeholders replaced in sw.js and manifest.webmanifest.
const (
	PlaceholderBase = "__FP_ASSET_BASE__"
	PlaceholderHash = "__FP_ASSET_HASH__"
)

// Cache-Control values.
const (
	CacheImmutable = "public, max-age=31536000, immutable"
	CacheNoCache   = "no-cache"
)

// MinCompressSize is the smallest asset that gets precompressed variants.
const MinCompressSize = 1024

// Encodings.
const (
	EncIdentity = ""
	EncZstd     = "zstd"
	EncGzip     = "gzip"
)

// Entry is one embedded file with its precompressed variants.
type Entry struct {
	Name  string // path relative to static/
	Data  []byte // identity
	Zstd  []byte // nil when not worthwhile
	Gzip  []byte // nil when not worthwhile
	Sum   string // hex SHA-256 prefix (32 digits) of Data
	CType string // Content-Type
}

// variant returns the bytes and ETag for encoding enc ("" = identity).
func (a *Entry) variant(enc string) []byte {
	switch enc {
	case EncZstd:
		return a.Zstd
	case EncGzip:
		return a.Gzip
	}
	return a.Data
}

// ETag returns the strong ETag of the representation in encoding enc.
func (a *Entry) ETag(enc string) string {
	switch enc {
	case EncZstd:
		return `"` + a.Sum + `-zst"`
	case EncGzip:
		return `"` + a.Sum + `-gz"`
	}
	return `"` + a.Sum + `"`
}

type assets struct {
	hash  string
	files map[string]*Entry
	tmpl  sync.Map // name → *Entry (templated, precompressed)
}

var load = sync.OnceValue(func() *assets { return build(webassets.FS, "static") })

// build reads and hashes every file under dir of fsys and precompresses the
// text assets (in parallel).
func build(fsys fs.FS, dir string) *assets {
	a := &assets{files: map[string]*Entry{}}
	sub, err := fs.Sub(fsys, dir)
	if err != nil {
		a.hash = "000000000000"
		return a
	}
	var names []string
	_ = fs.WalkDir(sub, ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		b, err := fs.ReadFile(sub, p)
		if err != nil {
			return nil
		}
		sum := sha256.Sum256(b)
		a.files[p] = &Entry{Name: p, Data: b, Sum: hex.EncodeToString(sum[:16]), CType: ContentType(p)}
		names = append(names, p)
		return nil
	})
	sort.Strings(names)
	h := sha256.New()
	for _, n := range names {
		h.Write([]byte(n))
		h.Write([]byte{0})
		h.Write(a.files[n].Data)
		h.Write([]byte{0})
	}
	a.hash = hex.EncodeToString(h.Sum(nil))[:12]

	var wg sync.WaitGroup
	sem := make(chan struct{}, 8)
	for _, n := range names {
		f := a.files[n]
		if !Compressible(n) || len(f.Data) < MinCompressSize {
			continue
		}
		wg.Go(func() {
			sem <- struct{}{}
			defer func() { <-sem }()
			f.Zstd, f.Gzip = compress(f.Data)
		})
	}
	wg.Wait()
	return a
}

var zstdEnc = sync.OnceValue(func() *zstd.Encoder {
	enc, err := zstd.NewWriter(nil, zstd.WithEncoderLevel(zstd.SpeedBestCompression),
		zstd.WithEncoderConcurrency(1), zstd.WithZeroFrames(true))
	if err != nil {
		return nil
	}
	return enc
})

// compress returns the zstd and gzip variants of b, each only when it saves
// at least 5 %.
func compress(b []byte) (zst, gz []byte) {
	worth := func(c []byte) []byte {
		if len(c) == 0 || len(c) > len(b)*95/100 {
			return nil
		}
		return c
	}
	if enc := zstdEnc(); enc != nil {
		zst = worth(enc.EncodeAll(b, make([]byte, 0, len(b)/2)))
	}
	var buf bytes.Buffer
	if w, err := gzip.NewWriterLevel(&buf, gzip.BestCompression); err == nil {
		if _, err := w.Write(b); err == nil && w.Close() == nil {
			gz = worth(bytes.Clone(buf.Bytes()))
		}
	}
	return zst, gz
}

// Compressible reports whether a file name has a text type worth compressing.
func Compressible(name string) bool {
	switch strings.ToLower(path.Ext(name)) {
	case ".js", ".mjs", ".css", ".svg", ".json", ".webmanifest", ".html", ".txt", ".map", ".xml", ".ico":
		return true
	}
	return false
}

// Hash returns the 12-hex-digit asset hash.
func Hash() string { return load().hash }

// AssetBase returns "/static/<hash>" (no trailing slash).
func AssetBase() string { return "/static/" + Hash() }

// Asset returns the URL of a static file: AssetBase() + "/" + rel.
func Asset(rel string) string { return AssetBase() + "/" + strings.TrimPrefix(rel, "/") }

// File returns the content of a static file (path relative to static/).
func File(rel string) ([]byte, bool) {
	f, ok := load().files[strings.TrimPrefix(rel, "/")]
	if !ok {
		return nil, false
	}
	return f.Data, true
}

// Lookup returns the asset for a path relative to static/.
func Lookup(rel string) (*Entry, bool) {
	f, ok := load().files[strings.TrimPrefix(rel, "/")]
	return f, ok
}

// Replace substitutes the asset placeholders in b.
func Replace(b []byte) []byte {
	b = bytes.ReplaceAll(b, []byte(PlaceholderBase), []byte(AssetBase()))
	return bytes.ReplaceAll(b, []byte(PlaceholderHash), []byte(Hash()))
}

// NewEntry builds an in-memory asset (for generated root files such as
// /theme.css and /manifest.webmanifest) with its strong ETag and, for
// compressible types of at least MinCompressSize bytes, the zstd and gzip
// variants. name only selects the compression policy and the Range file
// name; ctype "" means ContentType(name).
func NewEntry(name string, data []byte, ctype string) *Entry {
	if ctype == "" {
		ctype = ContentType(name)
	}
	sum := sha256.Sum256(data)
	e := &Entry{Name: path.Base(name), Data: data, Sum: hex.EncodeToString(sum[:16]), CType: ctype}
	if Compressible(name) && len(data) >= MinCompressSize {
		e.Zstd, e.Gzip = compress(data)
	}
	return e
}

// Templated returns a static file with the placeholders substituted
// (computed and precompressed once per file).
func Templated(rel string) (*Entry, bool) {
	a := load()
	rel = strings.TrimPrefix(rel, "/")
	if v, ok := a.tmpl.Load(rel); ok {
		return v.(*Entry), true
	}
	f, ok := a.files[rel]
	if !ok {
		return nil, false
	}
	b := Replace(f.Data)
	sum := sha256.Sum256(b)
	t := &Entry{Name: rel, Data: b, Sum: hex.EncodeToString(sum[:16]), CType: f.CType}
	if Compressible(rel) && len(b) >= MinCompressSize {
		t.Zstd, t.Gzip = compress(b)
	}
	v, _ := a.tmpl.LoadOrStore(rel, t)
	return v.(*Entry), true
}

// MountRoot registers /static/{hash}/*.
func MountRoot(r chi.Router, d *app.Deps) {
	r.Get("/static/{hash}/*", serveHashed)
}

// ContentType returns the MIME type for a static file name.
func ContentType(name string) string {
	switch strings.ToLower(path.Ext(name)) {
	case ".js", ".mjs":
		return "text/javascript; charset=utf-8"
	case ".css":
		return "text/css; charset=utf-8"
	case ".svg":
		return "image/svg+xml"
	case ".webmanifest":
		return "application/manifest+json"
	case ".json", ".map":
		return "application/json"
	case ".html":
		return "text/html; charset=utf-8"
	case ".txt":
		return "text/plain; charset=utf-8"
	case ".woff2":
		return "font/woff2"
	case ".png":
		return "image/png"
	case ".jpg", ".jpeg":
		return "image/jpeg"
	case ".webp":
		return "image/webp"
	case ".ico":
		return "image/x-icon"
	case ".xml":
		return "application/xml"
	case ".wasm":
		return "application/wasm"
	}
	if t := mime.TypeByExtension(path.Ext(name)); t != "" {
		return t
	}
	return "application/octet-stream"
}

var hashRe = regexp.MustCompile(`^[0-9a-f]{12}$`)

// validRel reports whether rel is a clean relative asset path without
// dotfile segments.
func validRel(rel string) bool {
	if rel == "" || strings.HasPrefix(rel, "/") || strings.Contains(rel, "\\") || path.Clean(rel) != rel {
		return false
	}
	for _, seg := range strings.Split(rel, "/") {
		if seg == "" || strings.HasPrefix(seg, ".") {
			return false
		}
	}
	return true
}

func serveHashed(w http.ResponseWriter, r *http.Request) {
	a := load()
	hash := chi.URLParam(r, "hash")
	rel := chi.URLParam(r, "*")
	f, ok := a.files[rel]
	if !hashRe.MatchString(hash) || !validRel(rel) || !ok {
		notFound(w)
		return
	}
	cache := CacheImmutable
	if hash != a.hash {
		cache = CacheNoCache // stale shell after an upgrade: serve current, never cache it long-term
	}
	Serve(w, r, f, cache)
}

func notFound(w http.ResponseWriter) {
	h := w.Header()
	h.Set("Content-Type", "text/plain; charset=utf-8")
	h.Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusNotFound)
	_, _ = w.Write([]byte("404 not found\n"))
}

// Serve writes asset f with content negotiation, a strong per-encoding ETag
// and the given Cache-Control, via http.ServeContent (Range, If-None-Match,
// HEAD). CSP and the other security headers come from mw.SecurityHeaders.
//
// Range requests always get the identity representation: byte ranges of a
// compressed variant are useless to clients, and ServeContent cannot set a
// correct Content-Length for a partial encoded body.
func Serve(w http.ResponseWriter, r *http.Request, f *Entry, cacheControl string) {
	enc := EncIdentity
	if r.Header.Get("Range") == "" {
		enc = Negotiate(r.Header.Get("Accept-Encoding"), f.Zstd != nil, f.Gzip != nil)
	}
	body := f.variant(enc)
	h := w.Header()
	h.Set("Content-Type", f.CType)
	h.Set("Cache-Control", cacheControl)
	h.Set("ETag", f.ETag(enc))
	if f.Zstd != nil || f.Gzip != nil {
		h.Add("Vary", "Accept-Encoding")
	}
	if enc != EncIdentity {
		h.Set("Content-Encoding", enc)
		// ServeContent omits Content-Length when Content-Encoding is set.
		h.Set("Content-Length", strconv.Itoa(len(body)))
	}
	http.ServeContent(w, r, f.Name, time.Time{}, bytes.NewReader(body))
}

// Negotiate picks the response encoding for an Accept-Encoding header given
// the available variants: zstd, then gzip, else identity. Codings with q=0
// are refused; "*" matches codings not listed explicitly.
func Negotiate(accept string, haveZstd, haveGzip bool) string {
	if accept == "" {
		return EncIdentity
	}
	q := map[string]float64{}
	star := -1.0
	for _, part := range strings.Split(accept, ",") {
		name, params, _ := strings.Cut(strings.TrimSpace(part), ";")
		name = strings.ToLower(strings.TrimSpace(name))
		if name == "" {
			continue
		}
		val := 1.0
		for _, p := range strings.Split(params, ";") {
			k, v, ok := strings.Cut(strings.TrimSpace(p), "=")
			if ok && strings.EqualFold(strings.TrimSpace(k), "q") {
				if f, err := strconv.ParseFloat(strings.TrimSpace(v), 64); err == nil && f >= 0 && f <= 1 {
					val = f
				} else {
					val = 0
				}
			}
		}
		if name == "*" {
			star = val
			continue
		}
		if name == "x-gzip" {
			name = EncGzip
		}
		q[name] = val
	}
	weight := func(enc string) float64 {
		if v, ok := q[enc]; ok {
			return v
		}
		if star >= 0 {
			return star
		}
		return 0
	}
	best, bestQ := EncIdentity, 0.0
	if haveZstd && weight(EncZstd) > bestQ {
		best, bestQ = EncZstd, weight(EncZstd)
	}
	if haveGzip && weight(EncGzip) > bestQ {
		best = EncGzip
	}
	return best
}
