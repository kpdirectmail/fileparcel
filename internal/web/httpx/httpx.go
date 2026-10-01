// Package httpx holds the HTTP helpers shared by every handler (DESIGN §5.3,
// §9.5): JSON responses, the error format, strict JSON decoding, pagination
// and cursors, Content-Disposition, the per-request context values set by
// the root middleware (request id, client IP), the user-content download
// rules of §8.2 (ContentType, ContentHeaders, ServeBlob) shared by filesapi
// and sharesapi, and ProxySignals (proxysignals.go), which package server
// and the middleware write and the settings API and doctor read.
//
// Error format:
//
//	{"error":{"code":"not_found","message":"Folder not found","field":"name","request_id":"…"}}
package httpx

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"mime"
	"net"
	"net/http"
	"net/netip"
	"reflect"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"fileparcel/internal/core"
)

// ---------- context values (set by mw) ----------

type ctxKey int

const (
	keyRequestID ctxKey = iota
	keyClientIP
)

// WithRequestID stores the request id in ctx (mw.RequestID does this).
func WithRequestID(ctx context.Context, id string) context.Context {
	return context.WithValue(ctx, keyRequestID, id)
}

// RequestID returns the request id stored in ctx ("" if none).
func RequestID(ctx context.Context) string {
	s, _ := ctx.Value(keyRequestID).(string)
	return s
}

// WithClientIP stores the resolved client IP in ctx (mw.ResolveClientIP does this).
func WithClientIP(ctx context.Context, ip netip.Addr) context.Context {
	return context.WithValue(ctx, keyClientIP, ip)
}

// ClientIP returns the client IP resolved by the middleware, falling back to
// r.RemoteAddr (unmapped). Unix-socket and in-process requests yield ::1.
func ClientIP(r *http.Request) netip.Addr {
	if ip, ok := r.Context().Value(keyClientIP).(netip.Addr); ok && ip.IsValid() {
		return ip
	}
	return RemoteIP(r)
}

// RemoteIP parses r.RemoteAddr (ignoring proxies). Unparseable addresses
// (Unix sockets, in-process) yield the IPv6 loopback.
func RemoteIP(r *http.Request) netip.Addr {
	host := r.RemoteAddr
	if h, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		host = h
	}
	if i := strings.IndexByte(host, '%'); i >= 0 {
		host = host[:i]
	}
	ip, err := netip.ParseAddr(host)
	if err != nil {
		return netip.IPv6Loopback()
	}
	return ip.Unmap()
}

// Meta returns the request metadata (client IP, user agent, request id and
// the Tailscale ingress the request came through, if any).
func Meta(r *http.Request) core.ReqMeta {
	m := core.ReqMeta{IP: ClientIP(r), UserAgent: r.UserAgent(), RequestID: RequestID(r.Context())}
	if in := core.IngressFrom(r.Context()); in != nil {
		m.Ingress = in.Kind
	}
	return m
}

// ---------- responses ----------

// JSON writes v as JSON with the given status.
func JSON(w http.ResponseWriter, status int, v any) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	if err := enc.Encode(v); err != nil {
		slog.Error("httpx: encode response", "err", err)
		http.Error(w, `{"error":{"code":"internal","message":"internal error"}}`, http.StatusInternalServerError)
		return
	}
	h := w.Header()
	h.Set("Content-Type", "application/json; charset=utf-8")
	h.Set("Content-Length", strconv.Itoa(buf.Len()))
	w.WriteHeader(status)
	_, _ = w.Write(buf.Bytes())
}

// OK writes v with 200.
func OK(w http.ResponseWriter, v any) { JSON(w, http.StatusOK, v) }

// Created writes v with 201.
func Created(w http.ResponseWriter, v any) { JSON(w, http.StatusCreated, v) }

// NoContent writes 204.
func NoContent(w http.ResponseWriter) { w.WriteHeader(http.StatusNoContent) }

// ErrorDetail is the body of an error response.
type ErrorDetail struct {
	Code      string `json:"code"`
	Message   string `json:"message"`
	Field     string `json:"field,omitempty"`
	RequestID string `json:"request_id,omitempty"`
}

// ErrorResponse is the error envelope {"error":{…}}.
type ErrorResponse struct {
	Error ErrorDetail `json:"error"`
}

// ToCoreError maps any error to the *core.Error sent to the client:
// *core.Error in the chain → itself; *http.MaxBytesError → ErrTooLarge;
// context deadline → ErrUnavailable; anything else → ErrInternal.
func ToCoreError(err error) *core.Error {
	if e := core.AsError(err); e != nil {
		return e
	}
	var mbe *http.MaxBytesError
	switch {
	case errors.As(err, &mbe):
		return core.ErrTooLarge
	case errors.Is(err, context.DeadlineExceeded):
		return core.ErrUnavailable
	case errors.Is(err, context.Canceled):
		return &core.Error{Code: "canceled", Status: 499, Message: "request canceled"}
	}
	return core.ErrInternal
}

// Error writes err in the API error format. *core.Error values keep their
// code/status/message/field; unknown errors become 500 "internal" with the
// generic message "internal error" and are logged with the request id.
// 5xx core errors that wrap a cause are logged too. The logged path is
// LogPath's, so share, invitation and archive credentials stay out of the log.
//
// A cancellation is the one case with no JSON body: when the request context
// is done the client really went away, so only the 499 status line is
// recorded (for the access log) and nothing is written. A cancellation from
// our own side still gets a proper answer, because the client is waiting.
func Error(w http.ResponseWriter, r *http.Request, err error) {
	ce := ToCoreError(err)
	rid := RequestID(r.Context())
	if ce.HTTPStatus() == 499 {
		if r.Context().Err() != nil {
			// The client is gone; record the status, write no body.
			w.WriteHeader(499)
			return
		}
		// Cancelled by our own side (a handler's sub-context, a service
		// returning ctx.Err() after an internal cancel, the drain of
		// internal/server): answer, and keep the cause for the log below.
		ce = &core.Error{Code: core.ErrUnavailable.Code, Status: core.ErrUnavailable.Status,
			Message: core.ErrUnavailable.Message, Err: err}
	}
	status := ce.HTTPStatus()
	switch {
	case ce == core.ErrInternal:
		slog.Error("request failed", "err", err, "method", r.Method, "path", LogPath(r.URL), "request_id", rid)
	case status >= 500 && ce.Err != nil:
		slog.Warn("request error", "code", ce.Code, "err", err, "path", LogPath(r.URL), "request_id", rid)
	}
	JSON(w, status, ErrorResponse{Error: ErrorDetail{Code: ce.Code, Message: ce.Message, Field: ce.Field, RequestID: rid}})
}

// DecodeError reads an API error response into a *core.Error (Status = the
// HTTP status). Non-JSON bodies produce code "http_<status>" with the body
// text (truncated) as message. The body is not closed.
func DecodeError(resp *http.Response) *core.Error {
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	var er ErrorResponse
	if err := json.Unmarshal(body, &er); err == nil && er.Error.Code != "" {
		return &core.Error{Code: er.Error.Code, Status: resp.StatusCode, Message: er.Error.Message, Field: er.Error.Field}
	}
	msg := strings.TrimSpace(string(body))
	if len(msg) > 300 {
		msg = msg[:300] + "…"
	}
	if msg == "" {
		msg = http.StatusText(resp.StatusCode)
	}
	return &core.Error{Code: "http_" + strconv.Itoa(resp.StatusCode), Status: resp.StatusCode, Message: msg}
}

// ---------- request decoding ----------

// DefaultMaxBody is the default JSON body limit (1 MiB).
const DefaultMaxBody = 1 << 20

// Decode reads a JSON request body into a T (DisallowUnknownFields, single
// value). max <= 0 means DefaultMaxBody. An empty body yields the zero T.
// Errors are *core.Error: 422 invalid (bad JSON, unknown field, wrong type,
// wrong Content-Type) or 413 too_large.
func Decode[T any](r *http.Request, max int64) (T, error) {
	var v T
	if max <= 0 {
		max = DefaultMaxBody
	}
	if r.Body == nil || r.Body == http.NoBody {
		return v, nil
	}
	data, err := io.ReadAll(io.LimitReader(r.Body, max+1))
	if err != nil {
		var mbe *http.MaxBytesError
		if errors.As(err, &mbe) {
			return v, core.ErrTooLarge
		}
		return v, core.Wrap(core.ErrInvalid, "could not read request body", err)
	}
	if int64(len(data)) > max {
		return v, core.ErrTooLarge
	}
	if len(bytes.TrimSpace(data)) == 0 {
		return v, nil
	}
	if ct := r.Header.Get("Content-Type"); ct != "" {
		mt, _, err := mime.ParseMediaType(ct)
		if err != nil || (mt != "application/json" && !strings.HasSuffix(mt, "+json")) {
			return v, core.Invalid("", "expected Content-Type: application/json")
		}
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&v); err != nil {
		return v, jsonError(err)
	}
	if dec.More() {
		return v, core.Invalid("", "unexpected data after the JSON value")
	}
	if _, err := dec.Token(); err != io.EOF {
		return v, core.Invalid("", "unexpected data after the JSON value")
	}
	return v, nil
}

func jsonError(err error) error {
	var se *json.SyntaxError
	var te *json.UnmarshalTypeError
	switch {
	case errors.As(err, &se):
		return core.Invalid("", fmt.Sprintf("malformed JSON at offset %d", se.Offset))
	case errors.As(err, &te):
		return core.Invalid(te.Field, "expected "+jsonTypeName(te.Type))
	case strings.HasPrefix(err.Error(), "json: unknown field "):
		f := strings.Trim(strings.TrimPrefix(err.Error(), "json: unknown field "), `"`)
		return core.Invalid(f, "unknown field")
	case errors.Is(err, io.ErrUnexpectedEOF):
		return core.Invalid("", "truncated JSON")
	}
	if e := core.AsError(err); e != nil {
		return e
	}
	return core.Invalid("", "invalid JSON: "+err.Error())
}

// jsonTypeName names the JSON value a Go type accepts, in words a client can
// act on. It never renders the Go type itself: for a whole-body mismatch
// te.Type is the request struct, and "expected core.ShareInput" would both
// mean nothing to an API consumer and disclose internal type names.
func jsonTypeName(t reflect.Type) string {
	for t != nil && t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	if t == nil {
		return "a different value"
	}
	if t == reflect.TypeOf(time.Time{}) {
		return "an RFC 3339 timestamp"
	}
	switch t.Kind() {
	case reflect.Bool:
		return "a boolean"
	case reflect.String:
		return "a string"
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64,
		reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return "a whole number"
	case reflect.Float32, reflect.Float64:
		return "a number"
	case reflect.Slice, reflect.Array:
		return "a JSON array"
	case reflect.Struct, reflect.Map, reflect.Interface:
		return "a JSON object"
	}
	return "a different value"
}

// ---------- pagination ----------

// PageReq parses ?cursor=&limit=&sort=&desc= (limit default 100, clamped to
// 1..500; desc accepts 1/true/yes).
func PageReq(r *http.Request) core.PageReq {
	q := r.URL.Query()
	p := core.PageReq{Cursor: q.Get("cursor"), Sort: q.Get("sort")}
	if n, err := strconv.Atoi(q.Get("limit")); err == nil {
		p.Limit = n
	}
	p.Limit = p.EffectiveLimit()
	switch strings.ToLower(q.Get("desc")) {
	case "1", "true", "yes", "on":
		p.Desc = true
	}
	return p
}

// EncodeCursor returns an opaque cursor: base64url (no padding) of the JSON of v.
func EncodeCursor(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		return ""
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

// DecodeCursor decodes a cursor produced by EncodeCursor into v. An invalid
// cursor yields a 422 error on field "cursor".
func DecodeCursor(s string, v any) error {
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil || len(b) == 0 {
		return core.Invalid("cursor", "invalid cursor")
	}
	if err := json.Unmarshal(b, v); err != nil {
		return core.Invalid("cursor", "invalid cursor")
	}
	return nil
}

// ---------- downloads ----------

// Attachment sets Content-Disposition for name (RFC 6266): an ASCII fallback
// filename="…" plus filename*=UTF-8”<percent-encoded> when the name is not
// plain ASCII or contains a character that browsers decode in a bare
// filename= ('%' escapes, '?' of RFC 2047 encoded words; Chromium does both
// when no filename* is present). inline selects "inline" instead of
// "attachment".
func Attachment(w http.ResponseWriter, name string, inline bool) {
	w.Header().Set("Content-Disposition", ContentDisposition(name, inline))
}

// ContentDisposition returns the header value used by Attachment.
func ContentDisposition(name string, inline bool) string {
	typ := "attachment"
	if inline {
		typ = "inline"
	}
	name = strings.ToValidUTF8(name, "_")
	if name == "" {
		name = "download"
	}
	fallback := asciiFallback(name)
	v := typ + `; filename="` + fallback + `"`
	if fallback != name {
		v += "; filename*=UTF-8''" + percentEncode(name)
	}
	return v
}

// asciiFallback returns the filename= value: s with non-ASCII characters,
// controls, quoting and path characters replaced by '_'. '%' and '?' are
// replaced too, so a legacy parser has nothing to percent- or RFC 2047-decode
// and such a name always gets the exact filename* as well.
func asciiFallback(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch {
		case r == '"' || r == '\\' || r == '/' || r == ';' || r == '%' || r == '?':
			b.WriteByte('_')
		case r < 0x20 || r == 0x7f:
			b.WriteByte('_')
		case r < utf8.RuneSelf:
			b.WriteRune(r)
		default:
			b.WriteByte('_')
		}
	}
	return b.String()
}

// percentEncode encodes s per RFC 5987 attr-char.
func percentEncode(s string) string {
	const attr = "!#$&+-.^_`|~"
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.IndexByte(attr, c) >= 0 {
			b.WriteByte(c)
		} else {
			fmt.Fprintf(&b, "%%%02X", c)
		}
	}
	return b.String()
}

// ---------- content downloads (DESIGN §8.2) ----------

// Content-Security-Policy values for user content.
const (
	// CSPContent is sent with every user-content response (downloads,
	// previews, thumbnails): nothing may run, the document is sandboxed.
	CSPContent = "default-src 'none'; img-src 'self' data:; media-src 'self'; style-src 'unsafe-inline'; sandbox"
	// CSPContentPDF replaces CSPContent for inline PDFs (Chrome's viewer
	// breaks under sandbox); same-origin framing is allowed for the preview.
	CSPContentPDF = "default-src 'none'; object-src 'self'; frame-ancestors 'self'"
)

// MIMEOctetStream is the type forced on content that is never rendered.
const MIMEOctetStream = "application/octet-stream"

// MIMETextPlain is the type used for inline text/code previews.
const MIMETextPlain = "text/plain; charset=utf-8"

var inlineMedia = map[string]bool{
	"image/png": true, "image/jpeg": true, "image/gif": true, "image/webp": true, "image/avif": true, "image/bmp": true,
	"video/mp4": true, "video/webm": true, "video/ogg": true, "video/quicktime": true,
	"application/pdf": true,
}

// textLike lists non-text/* types that are shown as plain text.
var textLike = map[string]bool{
	"application/json": true, "application/x-ndjson": true, // *+json is handled in ContentType
	"application/yaml": true, "application/x-yaml": true, "application/toml": true, "application/x-toml": true,
	"application/sql": true, "application/x-sh": true, "application/x-shellscript": true, "application/x-csh": true,
	"application/x-python": true, "application/x-perl": true, "application/x-ruby": true, "application/x-php": true,
	"application/x-httpd-php": true, "application/x-tex": true, "application/x-latex": true, "application/typescript": true,
	"application/x-subrip": true, "application/x-go": true,
}

// ContentType classifies a stored MIME type for delivery (DESIGN §8.2) and
// returns the Content-Type to send and whether inline display is allowed:
//
//   - image/{png,jpeg,gif,webp,avif,bmp}, video/{mp4,webm,ogg,quicktime},
//     audio/* and application/pdf keep their type and may be inline;
//   - other text/* and common code/markup types (JSON, YAML, TOML, shell,
//     SQL, …) are always sent as "text/plain; charset=utf-8" and may be inline;
//   - everything else — notably text/html, image/svg+xml, any XML and any
//     JavaScript — is application/octet-stream and never inline.
//
// The web UI mirrors the inline decision in opensInline
// (web/static/js/core/nodes.js) and the public share page in previewKind
// (web/static/js/public/share.js: a "preview" of any other type would be a
// counted download there); keep them in step.
func ContentType(mimeType string) (effective string, inlineOK bool) {
	mt, _, err := mime.ParseMediaType(mimeType)
	if err != nil || mt == "" {
		return MIMEOctetStream, false
	}
	mt = strings.ToLower(mt)
	typ, sub, _ := strings.Cut(mt, "/")
	if strings.Contains(sub, "html") || strings.Contains(sub, "xml") || strings.Contains(sub, "javascript") ||
		strings.Contains(sub, "ecmascript") || strings.Contains(sub, "jscript") || sub == "svg" {
		return MIMEOctetStream, false
	}
	switch {
	case inlineMedia[mt]:
		return mt, true
	case typ == "audio":
		return mt, true
	case typ == "text", textLike[mt], strings.HasSuffix(sub, "+json"):
		return MIMETextPlain, true
	}
	return MIMEOctetStream, false
}

// ContentHeaders sets the headers every user-content response carries
// (DESIGN §8.2) and returns the effective Content-Type and whether the
// response is inline. inline is the caller's request (?inline=1, previews,
// thumbnails); it is honoured only for allow-listed types. Sets
// Content-Type, X-Content-Type-Options: nosniff, Cross-Origin-Resource-Policy:
// same-origin, Cache-Control: private, no-cache, and the sandbox CSP (the
// PDF variant for inline PDFs, which also get X-Frame-Options: SAMEORIGIN so
// the preview iframe works). Content-Disposition is set by the caller
// (Attachment) or by ServeBlob.
func ContentHeaders(w http.ResponseWriter, mimeType string, inline bool) (effectiveMime string, inlined bool) {
	eff, ok := ContentType(mimeType)
	inlined = inline && ok
	h := w.Header()
	h.Set("Content-Type", eff)
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Cross-Origin-Resource-Policy", "same-origin")
	h.Set("Cache-Control", "private, no-cache")
	if inlined && eff == "application/pdf" {
		h.Set("Content-Security-Policy", CSPContentPDF)
		h.Set("X-Frame-Options", "SAMEORIGIN")
	} else {
		h.Set("Content-Security-Policy", CSPContent)
	}
	return eff, inlined
}

// ServeBlob serves user content from rs (e.g. a core.BlobReader) with the
// §8.2 rules: ContentHeaders, Content-Disposition (attachment unless inline
// is honoured), ETag (etag is quoted when needed; "" = none) and
// http.ServeContent for Range, multi-range, If-Range, If-None-Match,
// If-Modified-Since and HEAD. mod is the Last-Modified time (zero = none).
// The caller authorizes, audits and counts BEFORE calling it, and must skip
// side effects (download counters, single-use tickets) for HEAD requests.
func ServeBlob(w http.ResponseWriter, r *http.Request, name, mimeType string, mod time.Time, etag string, inline bool, rs io.ReadSeeker) {
	_, inlined := ContentHeaders(w, mimeType, inline)
	Attachment(w, name, inlined)
	if etag != "" {
		if !strings.HasPrefix(etag, `"`) && !strings.HasPrefix(etag, `W/"`) {
			etag = strconv.Quote(etag)
		}
		w.Header().Set("ETag", etag)
	}
	http.ServeContent(w, r, name, mod, rs)
}
