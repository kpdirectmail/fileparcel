package files

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
	"path/filepath"
	"sync"
	"testing"
	"time"

	"fileparcel/internal/core"
	"fileparcel/internal/db"
	"fileparcel/internal/events"
	"fileparcel/internal/ids"
	"fileparcel/internal/names"
	"fileparcel/internal/settings"
)

// ---------- fake clock ----------

type testClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *testClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *testClock) Advance(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

// ---------- fake settings ----------

type fakeSettings struct {
	mu sync.Mutex
	m  map[string]any
}

func (f *fakeSettings) set(k string, v any) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.m[k] = v
}

func (f *fakeSettings) value(k string) (any, bool) {
	f.mu.Lock()
	v, ok := f.m[k]
	f.mu.Unlock()
	if ok {
		return v, true
	}
	if d, ok := settings.Lookup(k); ok {
		return d.Default, true
	}
	return nil, false
}

func (f *fakeSettings) Raw(k string) (json.RawMessage, error) {
	v, ok := f.value(k)
	if !ok {
		return nil, core.ErrNotFound
	}
	return json.Marshal(v)
}

func (f *fakeSettings) Int(k string) int64 {
	v, _ := f.value(k)
	switch n := v.(type) {
	case int:
		return int64(n)
	case int64:
		return n
	}
	return 0
}

func (f *fakeSettings) Bool(k string) bool {
	v, _ := f.value(k)
	b, _ := v.(bool)
	return b
}

func (f *fakeSettings) String(k string) string {
	v, _ := f.value(k)
	s, _ := v.(string)
	return s
}

func (f *fakeSettings) Strings(string) []string                              { return nil }
func (f *fakeSettings) Duration(string) time.Duration                        { return 0 }
func (f *fakeSettings) Secret(string) (string, error)                        { return "", nil }
func (f *fakeSettings) Reset(context.Context, *core.Principal, string) error { return nil }
func (f *fakeSettings) Catalog(context.Context) ([]core.SettingView, error)  { return nil, nil }
func (f *fakeSettings) Set(context.Context, *core.Principal, map[string]json.RawMessage) (*core.SettingsResult, error) {
	return nil, core.ErrNotImplemented
}

// ---------- fake audit ----------

type fakeAudit struct {
	mu      sync.Mutex
	entries []core.AuditEntry
}

func (a *fakeAudit) Record(_ context.Context, e core.AuditEntry) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if e.Outcome == "" {
		e.Outcome = core.OutcomeSuccess
	}
	a.entries = append(a.entries, e)
}

func (a *fakeAudit) RecordTx(ctx context.Context, _ *sql.Tx, e core.AuditEntry) error {
	a.Record(ctx, e)
	return nil
}

func (a *fakeAudit) Query(context.Context, core.AuditQuery) (core.Page[core.AuditRecord], error) {
	return core.Page[core.AuditRecord]{}, nil
}
func (a *fakeAudit) Verify(context.Context) (*core.AuditVerify, error) { return nil, nil }
func (a *fakeAudit) Export(context.Context, core.AuditQuery, string, io.Writer) error {
	return nil
}
func (a *fakeAudit) Prune(context.Context, time.Time) (int, error) { return 0, nil }

// actions returns the recorded actions (optionally only those of action).
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

// all returns every recorded entry of action, oldest first.
func (a *fakeAudit) all(action string) []core.AuditEntry {
	a.mu.Lock()
	defer a.mu.Unlock()
	var out []core.AuditEntry
	for _, e := range a.entries {
		if e.Action == action {
			out = append(out, e)
		}
	}
	return out
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

// ---------- fake blob store (rows in the real blobs table) ----------

type fakeBlobs struct {
	mu       sync.Mutex
	db       *db.DB
	clock    core.Clock
	data     map[string][]byte
	deleted  []string
	opens    int
	onDelete func(id string) // optional, called after every Delete
}

func (b *fakeBlobs) put(t testing.TB, data []byte) *core.BlobInfo {
	t.Helper()
	info, err := b.store(context.Background(), data)
	if err != nil {
		t.Fatal(err)
	}
	return info
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

func (b *fakeBlobs) exists(id string) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	_, ok := b.data[id]
	return ok
}

type fakeWriter struct {
	b   *fakeBlobs
	buf bytes.Buffer
}

func (w *fakeWriter) Write(p []byte) (int, error) { return w.buf.Write(p) }
func (w *fakeWriter) Commit(ctx context.Context) (*core.BlobInfo, error) {
	return w.b.store(ctx, w.buf.Bytes())
}
func (w *fakeWriter) Abort() error { return nil }

type fakeReader struct {
	*bytes.Reader
	id string
}

func (r *fakeReader) Close() error { return nil }
func (r *fakeReader) ID() string   { return r.id }
func (r *fakeReader) Size() int64  { return r.Reader.Size() }

func (b *fakeBlobs) Create(context.Context) (core.BlobWriter, error) { return &fakeWriter{b: b}, nil }
func (b *fakeBlobs) CreateParted(context.Context, int64) (core.PartedBlob, error) {
	return nil, core.ErrNotImplemented
}
func (b *fakeBlobs) OpenParted(context.Context, string) (core.PartedBlob, error) {
	return nil, core.ErrNotImplemented
}
func (b *fakeBlobs) Open(_ context.Context, id string) (core.BlobReader, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	d, ok := b.data[id]
	if !ok {
		return nil, core.NotFoundf("blob not found")
	}
	b.opens++
	return &fakeReader{Reader: bytes.NewReader(d), id: id}, nil
}
func (b *fakeBlobs) Stat(_ context.Context, id string) (*core.BlobInfo, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	d, ok := b.data[id]
	if !ok {
		return nil, core.ErrNotFound
	}
	return &core.BlobInfo{ID: id, Size: int64(len(d))}, nil
}
func (b *fakeBlobs) Delete(ctx context.Context, id string) error {
	// The real table enforces the file_versions foreign key: deleting a
	// referenced blob fails, which the tests check.
	if _, err := b.db.Exec(ctx, `DELETE FROM blobs WHERE id = ?`, id); err != nil {
		return err
	}
	b.mu.Lock()
	delete(b.data, id)
	b.deleted = append(b.deleted, id)
	hook := b.onDelete
	b.mu.Unlock()
	if hook != nil {
		hook(id)
	}
	return nil
}
func (b *fakeBlobs) Verify(context.Context, string) error { return nil }
func (b *fakeBlobs) GC(context.Context, time.Duration) (int, int64, error) {
	return 0, 0, nil // the real store's GC is tested in blobstore
}
func (b *fakeBlobs) Reencrypt(context.Context, string) (string, error) {
	return "", core.ErrNotImplemented
}

// ---------- fake jobs ----------

type queuedJob struct {
	kind   string
	params json.RawMessage
}

type fakeJobs struct {
	mu        sync.Mutex
	kinds     map[string]core.JobFunc
	opts      map[string]core.JobOptions
	schedules map[string]string
	queue     []queuedJob
}

func (j *fakeJobs) Register(kind string, fn core.JobFunc, o core.JobOptions) {
	j.mu.Lock()
	defer j.mu.Unlock()
	j.kinds[kind] = fn
	j.opts[kind] = o
}
func (j *fakeJobs) Enqueue(_ context.Context, kind string, params any, _ *core.Principal) (string, error) {
	raw, err := json.Marshal(params)
	if err != nil {
		return "", err
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	j.queue = append(j.queue, queuedJob{kind, raw})
	return ids.New(ids.PrefixJob), nil
}
func (j *fakeJobs) Get(context.Context, string) (*core.Job, error) { return nil, core.ErrNotFound }
func (j *fakeJobs) List(context.Context, core.JobQuery) (core.Page[core.Job], error) {
	return core.Page[core.Job]{}, nil
}
func (j *fakeJobs) Cancel(context.Context, string) error { return nil }
func (j *fakeJobs) Schedule(name, cron, kind string, _ any) error {
	j.mu.Lock()
	defer j.mu.Unlock()
	j.schedules[name] = cron + " " + kind
	return nil
}
func (j *fakeJobs) Unschedule(string)                                     {}
func (j *fakeJobs) Schedules(context.Context) ([]core.JobSchedule, error) { return nil, nil }
func (j *fakeJobs) Start(context.Context) error                           { return nil }
func (j *fakeJobs) Stop(context.Context) error                            { return nil }

type fakeHandle struct {
	params json.RawMessage
	result any
}

func (h *fakeHandle) ID() string                    { return "job_test" }
func (h *fakeHandle) Params(v any) error            { return json.Unmarshal(h.params, v) }
func (h *fakeHandle) Progress(int64, int64, string) {}
func (h *fakeHandle) SetResult(v any)               { h.result = v }

// run runs a registered job kind inline and returns its result.
func (j *fakeJobs) run(t testing.TB, kind string, params any) any {
	t.Helper()
	j.mu.Lock()
	fn := j.kinds[kind]
	j.mu.Unlock()
	if fn == nil {
		t.Fatalf("job %s not registered", kind)
	}
	raw, _ := json.Marshal(params)
	h := &fakeHandle{params: raw}
	if err := fn(context.Background(), h); err != nil {
		t.Fatalf("job %s: %v", kind, err)
	}
	return h.result
}

// drain runs every queued job of kind and returns how many ran.
func (j *fakeJobs) drain(t testing.TB, kind string) int {
	t.Helper()
	j.mu.Lock()
	var run, keep []queuedJob
	for _, q := range j.queue {
		if q.kind == kind {
			run = append(run, q)
		} else {
			keep = append(keep, q)
		}
	}
	j.queue = keep
	j.mu.Unlock()
	for _, q := range run {
		var v any
		_ = json.Unmarshal(q.params, &v)
		j.run(t, kind, v)
	}
	return len(run)
}

func (j *fakeJobs) queued(kind string) int {
	j.mu.Lock()
	defer j.mu.Unlock()
	n := 0
	for _, q := range j.queue {
		if q.kind == kind {
			n++
		}
	}
	return n
}

// ---------- environment ----------

type testEnv struct {
	t        *testing.T
	ctx      context.Context
	db       *db.DB
	env      *core.Env
	clock    *testClock
	settings *fakeSettings
	audit    *fakeAudit
	blobs    *fakeBlobs
	jobs     *fakeJobs
	svc      *Service
}

func newEnv(t *testing.T) *testEnv {
	t.Helper()
	ctx := context.Background()
	d, err := db.Open(filepath.Join(t.TempDir(), "fp.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.Close() })
	if _, err := d.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := d.Exec(ctx, `INSERT INTO keyring (id, purpose, mk_id, wrapped, state, created_at)
		VALUES ('kek_test', 'blob', 'mk_test', x'00', 'active', 0)`); err != nil {
		t.Fatal(err)
	}
	clock := &testClock{t: time.Date(2026, 9, 19, 12, 0, 0, 0, time.UTC)}
	e := &testEnv{t: t, ctx: ctx, db: d, clock: clock,
		settings: &fakeSettings{m: map[string]any{}},
		audit:    &fakeAudit{},
		jobs: &fakeJobs{kinds: map[string]core.JobFunc{}, opts: map[string]core.JobOptions{},
			schedules: map[string]string{}},
	}
	e.blobs = &fakeBlobs{db: d, clock: clock, data: map[string][]byte{}}
	e.env = &core.Env{DB: d, Log: slog.New(slog.DiscardHandler), Clock: clock, Bus: events.New(),
		Settings: e.settings, Audit: e.audit}
	svc, err := New(e.env, e.blobs, e.jobs)
	if err != nil {
		t.Fatal(err)
	}
	e.svc = svc
	return e
}

// user is a test user with a principal and (except guests) a personal space.
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
		u.spaceID, u.rootID = e.space(core.SpaceUser, id, "", "My files")
	}
	return u
}

func (e *testEnv) space(kind, owner, group, name string) (spaceID, rootID string) {
	e.t.Helper()
	spaceID, rootID = ids.New(ids.PrefixSpace), ids.New(ids.PrefixNode)
	now := db.Ms(e.clock.Now())
	if _, err := e.db.Exec(e.ctx, `INSERT INTO spaces (id, kind, owner_user_id, group_id, name, created_at) VALUES (?, ?, ?, ?, ?, ?)`,
		spaceID, kind, db.NullString(owner), db.NullString(group), name, now); err != nil {
		e.t.Fatal(err)
	}
	if _, err := e.db.Exec(e.ctx, `INSERT INTO nodes (id, space_id, parent_id, kind, name, name_key, created_at, updated_at)
		VALUES (?, ?, NULL, 'folder', ?, ?, ?, ?)`, rootID, spaceID, name, names.Key(name), now, now); err != nil {
		e.t.Fatal(err)
	}
	return spaceID, rootID
}

// group creates a group with a team space.
func (e *testEnv) group(name string) (groupID, spaceID, rootID string) {
	e.t.Helper()
	groupID = ids.New(ids.PrefixGroup)
	if _, err := e.db.Exec(e.ctx, `INSERT INTO groups (id, name, created_at) VALUES (?, ?, ?)`,
		groupID, name, db.Ms(e.clock.Now())); err != nil {
		e.t.Fatal(err)
	}
	spaceID, rootID = e.space(core.SpaceGroup, "", groupID, name)
	return groupID, spaceID, rootID
}

func (e *testEnv) member(groupID string, u *user, role string) {
	e.t.Helper()
	if _, err := e.db.Exec(e.ctx, `INSERT INTO group_members (group_id, user_id, role, added_at) VALUES (?, ?, ?, ?)`,
		groupID, u.UserID, role, db.Ms(e.clock.Now())); err != nil {
		e.t.Fatal(err)
	}
}

// mkdir creates a folder or fails the test.
func (e *testEnv) mkdir(p *user, parent, name string) *core.Node {
	e.t.Helper()
	n, err := e.svc.Mkdir(e.ctx, p.Principal, parent, name)
	if err != nil {
		e.t.Fatalf("mkdir %q: %v", name, err)
	}
	return n
}

// file commits a file with content data or fails the test.
func (e *testEnv) file(p *user, parent, rel string, data string) *core.Node {
	e.t.Helper()
	n, err := e.svc.CommitFile(e.ctx, p.Principal, parent, rel, e.blobs.put(e.t, []byte(data)), core.FileMeta{}, core.ConflictFail)
	if err != nil {
		e.t.Fatalf("commit %q: %v", rel, err)
	}
	return n
}

func (e *testEnv) grant(owner *user, node, subjType, subjID, role string) *core.Grant {
	e.t.Helper()
	g, err := e.svc.SetGrant(e.ctx, owner.Principal, node, core.GrantInput{SubjectType: subjType, SubjectID: subjID, Role: role})
	if err != nil {
		e.t.Fatalf("grant: %v", err)
	}
	return g
}

// count runs a single-value COUNT query.
func (e *testEnv) count(q string, args ...any) int64 {
	e.t.Helper()
	var n int64
	if err := e.db.QueryRow(e.ctx, q, args...).Scan(&n); err != nil {
		e.t.Fatal(err)
	}
	return n
}

func (e *testEnv) used(spaceID string) int64 {
	e.t.Helper()
	var n int64
	if err := e.db.QueryRow(e.ctx, `SELECT used_bytes FROM spaces WHERE id = ?`, spaceID).Scan(&n); err != nil {
		e.t.Fatal(err)
	}
	return n
}

// code returns the core error code of err ("" for nil).
func code(err error) string {
	if err == nil {
		return ""
	}
	if ce := core.AsError(err); ce != nil {
		return ce.Code
	}
	return "other: " + err.Error()
}

func wantCode(t *testing.T, err error, want string) {
	t.Helper()
	if got := code(err); got != want {
		t.Fatalf("error %v (code %q), want %q", err, got, want)
	}
}
