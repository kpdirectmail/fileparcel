package filesapi

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"

	"fileparcel/internal/app"
	"fileparcel/internal/core"
	"fileparcel/internal/db"
	"fileparcel/internal/events"
	"fileparcel/internal/files"
	"fileparcel/internal/ids"
	"fileparcel/internal/names"
	"fileparcel/internal/settings"
	"fileparcel/internal/web/httpx"
	"fileparcel/internal/web/mw"
)

// ---------- fakes ----------

type fakeSettings struct {
	mu sync.Mutex
	m  map[string]any
}

func (f *fakeSettings) value(k string) any {
	f.mu.Lock()
	v, ok := f.m[k]
	f.mu.Unlock()
	if ok {
		return v
	}
	if d, ok := settings.Lookup(k); ok {
		return d.Default
	}
	return nil
}

func (f *fakeSettings) Raw(k string) (json.RawMessage, error) {
	v := f.value(k)
	if v == nil {
		return nil, core.ErrNotFound
	}
	return json.Marshal(v)
}

func (f *fakeSettings) Int(k string) int64 {
	switch n := f.value(k).(type) {
	case int:
		return int64(n)
	case int64:
		return n
	}
	return 0
}

func (f *fakeSettings) Bool(k string) bool     { b, _ := f.value(k).(bool); return b }
func (f *fakeSettings) String(k string) string { s, _ := f.value(k).(string); return s }
func (f *fakeSettings) Strings(string) []string {
	return nil
}
func (f *fakeSettings) Duration(string) time.Duration                        { return 0 }
func (f *fakeSettings) Secret(string) (string, error)                        { return "", nil }
func (f *fakeSettings) Reset(context.Context, *core.Principal, string) error { return nil }
func (f *fakeSettings) Catalog(context.Context) ([]core.SettingView, error)  { return nil, nil }
func (f *fakeSettings) Set(context.Context, *core.Principal, map[string]json.RawMessage) (*core.SettingsResult, error) {
	return nil, core.ErrNotImplemented
}

type fakeAudit struct {
	core.Audit
	mu      sync.Mutex
	entries []core.AuditEntry
}

func (a *fakeAudit) Record(ctx context.Context, e core.AuditEntry) {
	if p := core.PrincipalFrom(ctx); p != nil && e.ActorID == "" && e.ActorName == "" {
		e.ActorID, e.ActorName = p.UserID, p.Username
	}
	a.mu.Lock()
	a.entries = append(a.entries, e)
	a.mu.Unlock()
}

func (a *fakeAudit) RecordTx(ctx context.Context, _ *sql.Tx, e core.AuditEntry) error {
	a.Record(ctx, e)
	return nil
}

func (a *fakeAudit) count(action string) int {
	a.mu.Lock()
	defer a.mu.Unlock()
	n := 0
	for _, e := range a.entries {
		if e.Action == action {
			n++
		}
	}
	return n
}

func (a *fakeAudit) last(action string) *core.AuditEntry {
	a.mu.Lock()
	defer a.mu.Unlock()
	for i := len(a.entries) - 1; i >= 0; i-- {
		if a.entries[i].Action == action {
			e := a.entries[i]
			return &e
		}
	}
	return nil
}

// fakeBlobs keeps blob contents in memory and rows in the real blobs table.
type fakeBlobs struct {
	core.BlobStore
	mu    sync.Mutex
	db    *db.DB
	clock core.Clock
	data  map[string][]byte
}

func (b *fakeBlobs) store(ctx context.Context, data []byte) (*core.BlobInfo, error) {
	id := ids.NewBlobID()
	sum := sha256.Sum256(data)
	hash := "fp1:" + hex.EncodeToString(sum[:])
	now := b.clock.Now()
	if _, err := b.db.Exec(ctx, `INSERT INTO blobs (id, state, size, stored_size, cipher, kek_id, wrapped_dek, content_hash, created_at)
		VALUES (?, 'ready', ?, ?, 1, 'kek_test', x'00', ?, ?)`, id, len(data), len(data)+60, hash, db.Ms(now)); err != nil {
		return nil, err
	}
	b.mu.Lock()
	b.data[id] = bytes.Clone(data)
	b.mu.Unlock()
	return &core.BlobInfo{ID: id, Size: int64(len(data)), ContentHash: hash, Cipher: 1, CreatedAt: now}, nil
}

type blobWriter struct {
	b   *fakeBlobs
	buf bytes.Buffer
}

func (w *blobWriter) Write(p []byte) (int, error) { return w.buf.Write(p) }
func (w *blobWriter) Commit(ctx context.Context) (*core.BlobInfo, error) {
	return w.b.store(ctx, w.buf.Bytes())
}
func (w *blobWriter) Abort() error { return nil }

type blobReader struct {
	*bytes.Reader
	id string
}

func (r *blobReader) Close() error { return nil }
func (r *blobReader) ID() string   { return r.id }
func (r *blobReader) Size() int64  { return r.Reader.Size() }

func (b *fakeBlobs) Create(context.Context) (core.BlobWriter, error) { return &blobWriter{b: b}, nil }
func (b *fakeBlobs) Open(_ context.Context, id string) (core.BlobReader, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	d, ok := b.data[id]
	if !ok {
		return nil, core.NotFoundf("blob not found")
	}
	return &blobReader{Reader: bytes.NewReader(d), id: id}, nil
}
func (b *fakeBlobs) Delete(ctx context.Context, id string) error {
	if _, err := b.db.Exec(ctx, `DELETE FROM blobs WHERE id = ?`, id); err != nil {
		return err
	}
	b.mu.Lock()
	delete(b.data, id)
	b.mu.Unlock()
	return nil
}
func (b *fakeBlobs) forget(id string) {
	b.mu.Lock()
	delete(b.data, id)
	b.mu.Unlock()
}

// fakeJobs records registrations and queued jobs; drain runs them inline.
type fakeJobs struct {
	core.Jobs
	mu    sync.Mutex
	kinds map[string]core.JobFunc
	queue []queued
}

type queued struct {
	kind   string
	params json.RawMessage
}

func (j *fakeJobs) Register(kind string, fn core.JobFunc, _ core.JobOptions) {
	j.mu.Lock()
	j.kinds[kind] = fn
	j.mu.Unlock()
}
func (j *fakeJobs) Schedule(string, string, string, any) error { return nil }
func (j *fakeJobs) Enqueue(_ context.Context, kind string, params any, _ *core.Principal) (string, error) {
	raw, _ := json.Marshal(params)
	j.mu.Lock()
	j.queue = append(j.queue, queued{kind, raw})
	j.mu.Unlock()
	return ids.New(ids.PrefixJob), nil
}

type jobHandle struct{ params json.RawMessage }

func (h *jobHandle) ID() string                    { return "job_test" }
func (h *jobHandle) Params(v any) error            { return json.Unmarshal(h.params, v) }
func (h *jobHandle) Progress(int64, int64, string) {}
func (h *jobHandle) SetResult(any)                 {}

func (j *fakeJobs) drain(t *testing.T) {
	t.Helper()
	j.mu.Lock()
	q := j.queue
	j.queue = nil
	j.mu.Unlock()
	for _, it := range q {
		if err := j.kinds[it.kind](context.Background(), &jobHandle{params: it.params}); err != nil {
			t.Fatalf("job %s: %v", it.kind, err)
		}
	}
}

// ---------- environment ----------

type testClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *testClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *testClock) advance(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

type testEnv struct {
	t        *testing.T
	ctx      context.Context
	db       *db.DB
	clock    *testClock
	settings *fakeSettings
	audit    *fakeAudit
	blobs    *fakeBlobs
	jobs     *fakeJobs
	files    *files.Service
	d        *app.Deps
	srv      *httptest.Server
	who      atomic.Pointer[core.Principal]
}

func newEnv(t *testing.T) *testEnv {
	t.Helper()
	ctx := context.Background()
	d, err := db.Open(filepath.Join(t.TempDir(), "fp.db"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := d.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := d.Exec(ctx, `INSERT INTO keyring (id, purpose, mk_id, wrapped, state, created_at)
		VALUES ('kek_test', 'blob', 'mk_test', x'00', 'active', 0)`); err != nil {
		t.Fatal(err)
	}
	e := &testEnv{t: t, ctx: ctx, db: d,
		clock:    &testClock{t: time.Date(2026, 9, 19, 12, 0, 0, 0, time.UTC)},
		settings: &fakeSettings{m: map[string]any{}},
		audit:    &fakeAudit{},
		jobs:     &fakeJobs{kinds: map[string]core.JobFunc{}},
	}
	e.blobs = &fakeBlobs{db: d, clock: e.clock, data: map[string][]byte{}}
	bus := events.New()
	env := &core.Env{DB: d, Log: slog.New(slog.DiscardHandler), Clock: e.clock, Bus: bus,
		Settings: e.settings, Audit: e.audit}
	svc, err := files.New(env, e.blobs, e.jobs)
	if err != nil {
		t.Fatal(err)
	}
	e.files = svc
	e.d = &app.Deps{Env: env, Files: svc, Blobs: e.blobs, Jobs: e.jobs}

	r := chi.NewRouter()
	r.Use(mw.Inject(e.d), middleware.GetHead, mw.RequestID, mw.Recover, mw.SecurityHeaders)
	r.Use(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			if p := e.who.Load(); p != nil && req.Header.Get("X-Test-Anonymous") == "" {
				req = req.WithContext(core.WithPrincipal(req.Context(), p.Clone()))
			}
			next.ServeHTTP(w, req)
		})
	})
	api := chi.NewRouter()
	Mount(api, e.d)
	r.With(mw.MaxBody(httpx.DefaultMaxBody), mw.Authenticate).Mount("/api/v1", api)
	e.srv = httptest.NewServer(r)
	t.Cleanup(func() {
		e.srv.Close()
		bus.Close()
		_ = d.Close()
	})
	return e
}

// user is a test account with a personal space (not for guests).
type user struct {
	*core.Principal
	spaceID, rootID string
}

func (e *testEnv) user(name string, role core.Role) *user {
	e.t.Helper()
	id := ids.New(ids.PrefixUser)
	handle := make([]byte, 16)
	_, _ = rand.Read(handle)
	now := db.Ms(e.clock.Now())
	if _, err := e.db.Exec(e.ctx, `INSERT INTO users (id, username, role, status, webauthn_handle, created_at, updated_at)
		VALUES (?, ?, ?, 'active', ?, ?, ?)`, id, name, string(role), handle, now, now); err != nil {
		e.t.Fatal(err)
	}
	u := &user{Principal: &core.Principal{UserID: id, Username: name, Role: role, Via: core.ViaSession,
		AuthLevel: core.AuthLevelFull}}
	if role != core.RoleGuest {
		u.spaceID, u.rootID = ids.New(ids.PrefixSpace), ids.New(ids.PrefixNode)
		if _, err := e.db.Exec(e.ctx, `INSERT INTO spaces (id, kind, owner_user_id, name, created_at) VALUES (?, 'user', ?, 'My files', ?)`,
			u.spaceID, id, now); err != nil {
			e.t.Fatal(err)
		}
		if _, err := e.db.Exec(e.ctx, `INSERT INTO nodes (id, space_id, parent_id, kind, name, name_key, created_at, updated_at)
			VALUES (?, ?, NULL, 'folder', 'My files', ?, ?, ?)`, u.rootID, u.spaceID, names.Key("My files"), now, now); err != nil {
			e.t.Fatal(err)
		}
	}
	return u
}

// put commits a file with content data below parent (rel may contain folders).
func (e *testEnv) put(u *user, parent, rel string, data []byte) *core.Node {
	e.t.Helper()
	b, err := e.blobs.store(e.ctx, data)
	if err != nil {
		e.t.Fatal(err)
	}
	n, err := e.files.CommitFile(e.ctx, u.Principal, parent, rel, b, core.FileMeta{}, core.ConflictReplace)
	if err != nil {
		e.t.Fatalf("commit %s: %v", rel, err)
	}
	return n
}

// response is a recorded HTTP response.
type response struct {
	status int
	header http.Header
	body   []byte
	code   string // API error code
}

func (r *response) json(t *testing.T, v any) {
	t.Helper()
	if err := json.Unmarshal(r.body, v); err != nil {
		t.Fatalf("decode %s: %v", r.body, err)
	}
}

// req sends a request as p (nil = anonymous) with optional JSON body and
// extra headers ("Name: value").
func (e *testEnv) req(p *core.Principal, method, path string, body any, headers ...string) *response {
	e.t.Helper()
	var rd io.Reader
	if body != nil {
		if s, ok := body.(string); ok {
			rd = strings.NewReader(s)
		} else {
			b, _ := json.Marshal(body)
			rd = bytes.NewReader(b)
		}
	}
	req, err := http.NewRequest(method, e.srv.URL+path, rd)
	if err != nil {
		e.t.Fatal(err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	for _, h := range headers {
		k, v, _ := strings.Cut(h, ":")
		req.Header.Set(strings.TrimSpace(k), strings.TrimSpace(v))
	}
	if p == nil {
		req.Header.Set("X-Test-Anonymous", "1")
	} else {
		e.who.Store(p)
	}
	resp, err := e.srv.Client().Do(req)
	if err != nil {
		e.t.Fatalf("%s %s: %v", method, path, err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		e.t.Fatalf("%s %s: read body: %v", method, path, err)
	}
	out := &response{status: resp.StatusCode, header: resp.Header, body: raw}
	var er httpx.ErrorResponse
	if resp.StatusCode >= 400 && json.Unmarshal(raw, &er) == nil {
		out.code = er.Error.Code
	}
	return out
}

// expect fails unless the response has status (and, for errors, code).
func (r *response) expect(t *testing.T, status int, code ...string) *response {
	t.Helper()
	if r.status != status {
		t.Fatalf("status %d (%s), want %d: %s", r.status, r.code, status, truncate(r.body))
	}
	if len(code) > 0 && r.code != code[0] {
		t.Fatalf("error code %q, want %q: %s", r.code, code[0], truncate(r.body))
	}
	return r
}

func truncate(b []byte) string {
	if len(b) > 300 {
		return string(b[:300]) + "…"
	}
	return string(b)
}
