package httpx

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strings"
	"testing"
	"time"

	"fileparcel/internal/core"
)

func decodeErr(t *testing.T, rec *httptest.ResponseRecorder) ErrorDetail {
	t.Helper()
	var er ErrorResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &er); err != nil {
		t.Fatalf("body %q: %v", rec.Body.String(), err)
	}
	return er.Error
}

func TestJSONAndHelpers(t *testing.T) {
	rec := httptest.NewRecorder()
	JSON(rec, 200, map[string]any{"a": 1, "html": "<b>"})
	if rec.Code != 200 || rec.Header().Get("Content-Type") != "application/json; charset=utf-8" {
		t.Fatalf("%d %v", rec.Code, rec.Header())
	}
	if !strings.Contains(rec.Body.String(), `"a":1`) {
		t.Fatal(rec.Body.String())
	}
	rec = httptest.NewRecorder()
	Created(rec, core.NewPage([]int(nil), ""))
	if rec.Code != 201 || strings.TrimSpace(rec.Body.String()) != `{"items":[]}` {
		t.Fatalf("%d %s", rec.Code, rec.Body.String())
	}
	rec = httptest.NewRecorder()
	NoContent(rec)
	if rec.Code != 204 || rec.Body.Len() != 0 {
		t.Fatal("NoContent")
	}
}

func TestError(t *testing.T) {
	req := httptest.NewRequest("GET", "/x", nil)
	req = req.WithContext(WithRequestID(req.Context(), "rid123"))
	cases := []struct {
		err    error
		status int
		code   string
		msg    string
		field  string
	}{
		{core.ErrNotFound, 404, "not_found", "not found", ""},
		{core.NotFoundf("Folder %s not found", "x"), 404, "not_found", "Folder x not found", ""},
		{core.Invalid("name", "too long"), 422, "invalid", "too long", "name"},
		{fmt.Errorf("ctx: %w", core.ErrQuota), 507, "quota_exceeded", "storage quota exceeded", ""},
		{core.Wrap(core.ErrConflict, "exists", errors.New("db detail")), 409, "conflict", "exists", ""},
		{errors.New("secret db failure"), 500, "internal", "internal error", ""},
		{&http.MaxBytesError{Limit: 1}, 413, "too_large", "request too large", ""},
		{core.ErrKeysLocked, 503, "keys_locked", core.ErrKeysLocked.Message, ""},
		{core.ErrElevationRequired, 403, "elevation_required", core.ErrElevationRequired.Message, ""},
		{core.ErrEnrollRequired, 403, "mfa_enroll_required", core.ErrEnrollRequired.Message, ""},
		{core.ErrMFARequired, 401, "mfa_required", core.ErrMFARequired.Message, ""},
		{core.ErrNotImplemented, 501, "not_implemented", "not implemented", ""},
	}
	for _, c := range cases {
		rec := httptest.NewRecorder()
		Error(rec, req, c.err)
		d := decodeErr(t, rec)
		if rec.Code != c.status || d.Code != c.code || d.Message != c.msg || d.Field != c.field || d.RequestID != "rid123" {
			t.Errorf("%v: got %d %+v", c.err, rec.Code, d)
		}
		if strings.Contains(rec.Body.String(), "secret db failure") || strings.Contains(rec.Body.String(), "db detail") {
			t.Errorf("internal detail leaked: %s", rec.Body.String())
		}
	}
	// Error type semantics.
	if !errors.Is(core.Invalid("a", "b"), core.ErrInvalid) || errors.Is(core.ErrInvalid, core.ErrNotFound) {
		t.Fatal("Is by code")
	}
	inner := errors.New("cause")
	if !errors.Is(core.Wrap(core.ErrNotFound, "", inner), inner) {
		t.Fatal("Unwrap")
	}
}

// A cancellation must never turn into the implicit 200 OK with an empty body
// that a bare return produces: a live client gets a JSON "unavailable", a
// client that really went away gets the 499 status and nothing else.
func TestErrorCanceled(t *testing.T) {
	live := httptest.NewRequest("GET", "/x", nil)
	live = live.WithContext(WithRequestID(live.Context(), "rid123"))
	for _, err := range []error{context.Canceled, fmt.Errorf("service: %w", context.Canceled)} {
		rec := httptest.NewRecorder()
		Error(rec, live, err)
		d := decodeErr(t, rec)
		if rec.Code != 503 || d.Code != "unavailable" || d.RequestID != "rid123" {
			t.Errorf("server-side cancel %v: got %d %+v", err, rec.Code, d)
		}
	}
	// The client went away: status only, no body.
	ctx, cancel := context.WithCancel(live.Context())
	cancel()
	rec := httptest.NewRecorder()
	Error(rec, live.WithContext(ctx), context.Canceled)
	if rec.Code != 499 || rec.Body.Len() != 0 {
		t.Errorf("client cancel: got %d body %q", rec.Code, rec.Body.String())
	}
}

// A JSON type mismatch must describe the value the API wants, never the Go
// type: te.Type is the whole request struct for a body-level mismatch.
func TestDecodeTypeErrorWording(t *testing.T) {
	cases := map[string]string{
		`[1]`:           "expected a JSON object",
		`"hi"`:          "expected a JSON object",
		`3`:             "expected a JSON object",
		`{"name":1}`:    "expected a string",
		`{"count":"x"}`: "expected a whole number",
		`{"ok":"yes"}`:  "expected a boolean",
		`{"at":1}`:      "expected an RFC 3339 timestamp",
		`{"tags":"x"}`:  "expected a JSON array",
		`{"ratio":"x"}`: "expected a number",
	}
	for body, want := range cases {
		_, err := Decode[wide](req(body, "application/json"), 0)
		ce := core.AsError(err)
		if ce == nil || ce.Message != want {
			t.Errorf("%s: got %v, want %q", body, err, want)
		}
		if ce != nil && strings.Contains(ce.Message, "httpx.") {
			t.Errorf("%s: Go type name leaked: %q", body, ce.Message)
		}
	}
}

func TestDecodeErrorRoundTrip(t *testing.T) {
	req := httptest.NewRequest("GET", "/", nil)
	rec := httptest.NewRecorder()
	Error(rec, req, core.Invalid("email", "bad address"))
	ce := DecodeError(rec.Result())
	if ce.Code != "invalid" || ce.Status != 422 || ce.Field != "email" || ce.Message != "bad address" || !errors.Is(ce, core.ErrInvalid) {
		t.Fatalf("%+v", ce)
	}
	rec = httptest.NewRecorder()
	http.Error(rec, "plain failure", http.StatusBadGateway)
	ce = DecodeError(rec.Result())
	if ce.Code != "http_502" || ce.Status != http.StatusBadGateway || ce.Message != "plain failure" {
		t.Fatalf("%+v", ce)
	}
}

type payload struct {
	Name  string `json:"name"`
	Count int    `json:"count"`
}

// wide covers every kind jsonTypeName names.
type wide struct {
	Name  string    `json:"name"`
	Count int       `json:"count"`
	OK    bool      `json:"ok"`
	At    time.Time `json:"at"`
	Tags  []string  `json:"tags"`
	Ratio float64   `json:"ratio"`
}

func req(body, ct string) *http.Request {
	r := httptest.NewRequest("POST", "/", strings.NewReader(body))
	if ct != "" {
		r.Header.Set("Content-Type", ct)
	}
	return r
}

func TestDecode(t *testing.T) {
	v, err := Decode[payload](req(`{"name":"a","count":2}`, "application/json"), 0)
	if err != nil || v.Name != "a" || v.Count != 2 {
		t.Fatalf("%+v %v", v, err)
	}
	if v, err := Decode[payload](req(``, ""), 0); err != nil || v.Name != "" {
		t.Fatal("empty body must give zero value")
	}
	check := func(body, ct string, max int64, code, field string) {
		t.Helper()
		_, err := Decode[payload](req(body, ct), max)
		ce := core.AsError(err)
		if ce == nil || ce.Code != code || ce.Field != field {
			t.Errorf("%q: got %v (%+v)", body, err, ce)
		}
	}
	check(`{"name":"a","extra":1}`, "application/json", 0, "invalid", "extra")
	check(`{"count":"x"}`, "application/json", 0, "invalid", "count")
	check(`{"name":`, "application/json", 0, "invalid", "")
	check(`{"name":"a"} {"name":"b"}`, "application/json", 0, "invalid", "")
	check(`{"name":"a"}`, "text/plain", 0, "invalid", "")
	check(`{"name":"`+strings.Repeat("x", 100)+`"}`, "application/json", 50, "too_large", "")
	// MaxBytesReader from middleware surfaces as too_large as well.
	r := req(`{"name":"`+strings.Repeat("x", 100)+`"}`, "application/json")
	r.Body = http.MaxBytesReader(httptest.NewRecorder(), r.Body, 10)
	if _, err := Decode[payload](r, 0); !errors.Is(err, core.ErrTooLarge) {
		t.Fatalf("MaxBytesReader: %v", err)
	}
	if _, err := Decode[payload](req(`{"name":"a"}`, "application/merge-patch+json"), 0); err != nil {
		t.Fatalf("+json content type: %v", err)
	}
}

func TestPageReqAndCursor(t *testing.T) {
	cases := map[string]core.PageReq{
		"/":                                     {Limit: 100},
		"/?limit=5&sort=name&desc=1&cursor=abc": {Limit: 5, Sort: "name", Desc: true, Cursor: "abc"},
		"/?limit=9999":                          {Limit: 500},
		"/?limit=-3":                            {Limit: 100},
		"/?limit=x&desc=no":                     {Limit: 100},
	}
	for u, want := range cases {
		if got := PageReq(httptest.NewRequest("GET", u, nil)); got != want {
			t.Errorf("%s: got %+v want %+v", u, got, want)
		}
	}
	type cur struct {
		Name string `json:"n"`
		ID   string `json:"i"`
	}
	s := EncodeCursor(cur{"a/b", "nod_1"})
	if strings.ContainsAny(s, "+/=") {
		t.Fatalf("cursor not url-safe: %q", s)
	}
	var back cur
	if err := DecodeCursor(s, &back); err != nil || back.Name != "a/b" || back.ID != "nod_1" {
		t.Fatalf("%+v %v", back, err)
	}
	for _, bad := range []string{"", "!!!", "bm90anNvbg"} {
		err := DecodeCursor(bad, &back)
		if ce := core.AsError(err); ce == nil || ce.Field != "cursor" {
			t.Errorf("DecodeCursor(%q) = %v", bad, err)
		}
	}
}

func TestAttachment(t *testing.T) {
	cases := map[string]string{
		"report.pdf":       `attachment; filename="report.pdf"`,
		`a"b\c.txt`:        `attachment; filename="a_b_c.txt"; filename*=UTF-8''a%22b%5Cc.txt`,
		"Résumé 2024.docx": `attachment; filename="R_sum_ 2024.docx"; filename*=UTF-8''R%C3%A9sum%C3%A9%202024.docx`,
		"日本.txt":           `attachment; filename="__.txt"; filename*=UTF-8''%E6%97%A5%E6%9C%AC.txt`,
		"":                 `attachment; filename="download"`,
		"line\nbreak":      `attachment; filename="line_break"; filename*=UTF-8''line%0Abreak`,
		// '%' and '?' never reach a bare filename=: Chromium percent- and
		// RFC 2047-decodes it when no filename* is present.
		"50%25 off.pdf": `attachment; filename="50_25 off.pdf"; filename*=UTF-8''50%2525%20off.pdf`,
		"100%.txt":      `attachment; filename="100_.txt"; filename*=UTF-8''100%25.txt`,
		"=?utf-8?B?cmVwb3J0LnBkZg==?=": `attachment; filename="=_utf-8_B_cmVwb3J0LnBkZg==_="; ` +
			`filename*=UTF-8''%3D%3Futf-8%3FB%3FcmVwb3J0LnBkZg%3D%3D%3F%3D`,
	}
	for name, want := range cases {
		rec := httptest.NewRecorder()
		Attachment(rec, name, false)
		if got := rec.Header().Get("Content-Disposition"); got != want {
			t.Errorf("%q:\n got %s\nwant %s", name, got, want)
		}
	}
	if got := ContentDisposition("a.png", true); got != `inline; filename="a.png"` {
		t.Fatal(got)
	}
}

func TestMetaAndClientIP(t *testing.T) {
	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = "[::ffff:192.168.1.9]:5555"
	r.Header.Set("User-Agent", "ua/1")
	if ip := ClientIP(r); ip != netip.MustParseAddr("192.168.1.9") {
		t.Fatalf("unmapped ip %v", ip)
	}
	ctx := WithClientIP(WithRequestID(r.Context(), "rid"), netip.MustParseAddr("10.0.0.7"))
	m := Meta(r.WithContext(ctx))
	if m.IP.String() != "10.0.0.7" || m.UserAgent != "ua/1" || m.RequestID != "rid" {
		t.Fatalf("%+v", m)
	}
	r.RemoteAddr = "@"
	if !RemoteIP(r).IsLoopback() {
		t.Fatal("unix socket peers map to loopback")
	}
	if RequestID(context.Background()) != "" {
		t.Fatal("RequestID default")
	}
}

func TestLogPathRedaction(t *testing.T) {
	cases := map[string]string{
		"/s/SECRETTOKEN":                         "/s/…",
		"/s/SECRETTOKEN/":                        "/s/…/",
		"/s/SECRETTOKEN/dl/nod_1?inline=1":       "/s/…/dl/nod_1",
		"/s/SECRETTOKEN/zip/TICKET":              "/s/…/zip/…",
		"/invite/SECRETTOKEN":                    "/invite/…",
		"/api/v1/auth/invite/SECRET/accept":      "/api/v1/auth/invite/…/accept",
		"/api/v1/archives/TICKET":                "/api/v1/archives/…",
		"/api/v1/archives":                       "/api/v1/archives",
		"/login?next=/files":                     "/login",
		"/setup?token=abc":                       "/setup",
		"/api/v1/nodes/x/children?limit=5":       "/api/v1/nodes/x/children?limit=5",
		"/api/v1/qr.svg?data=https://x/s/SECRET": "/api/v1/qr.svg?data=%E2%80%A6",
		"/api/v1/x?Token=abc&limit=2":            "/api/v1/x?Token=%E2%80%A6&limit=2",
		"/s/":                                    "/s/",
	}
	for in, want := range cases {
		u, err := url.Parse(in)
		if err != nil {
			t.Fatal(err)
		}
		if got := LogPath(u); got != want {
			t.Errorf("%s: %q want %q", in, got, want)
		}
	}
}

// The error log lines of Error name the request path like the access log
// does: without the share, invitation or archive credential in it.
func TestErrorLogRedactsCredentials(t *testing.T) {
	var buf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, nil)))
	t.Cleanup(func() { slog.SetDefault(prev) })

	cases := []struct {
		method, path string
		err          error
		want         string
	}{
		{"GET", "/s/SECRETTOKEN123/dl/nod_1", errors.New("database is locked"), "path=/s/…/dl/nod_1"},
		{"GET", "/s/SECRETTOKEN123/zip/SECRETTICKET", errors.New("disk I/O error"), "path=/s/…/zip/…"},
		{"POST", "/api/v1/auth/invite/SECRETINVITE/accept", core.Wrap(core.ErrUnavailable, "busy", errors.New("cause")),
			"path=/api/v1/auth/invite/…/accept"},
		{"PUT", "/s/SECRETTOKEN123/api/uploads/u/parts/0", core.Wrap(core.ErrQuota, "full", errors.New("ENOSPC")),
			"path=/s/…/api/uploads/u/parts/0"},
		{"GET", "/api/v1/archives/SECRETTICKET", errors.New("boom"), "path=/api/v1/archives/…"},
	}
	for _, c := range cases {
		buf.Reset()
		rec := httptest.NewRecorder()
		Error(rec, httptest.NewRequest(c.method, c.path, nil), c.err)
		out := buf.String()
		if !strings.Contains(out, c.want) {
			t.Errorf("%s: log lacks %q: %s", c.path, c.want, out)
		}
		for _, secret := range []string{"SECRETTOKEN123", "SECRETTICKET", "SECRETINVITE"} {
			if strings.Contains(out, secret) {
				t.Errorf("%s: credential logged: %s", c.path, out)
			}
		}
	}
}
