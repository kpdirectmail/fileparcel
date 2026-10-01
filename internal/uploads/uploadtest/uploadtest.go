// Package uploadtest provides test doubles for unit E's packages (uploads,
// shares, web/uploadapi, web/sharesapi): a migrated SQLite database in a
// temporary home plus database-backed fakes of the collaborators those
// packages use (Files, BlobStore, Keys, Settings, Jobs, Audit, Notify).
//
// The fakes write the real tables (users, spaces, nodes, file_versions,
// blobs, keyring) so that foreign keys and SQL of the code under test are
// exercised for real; they implement only the methods unit E calls
// (unimplemented core.Files methods panic through the embedded nil
// interface).
//
// It is imported only by _test.go files; it lives in its own package so the
// four packages share one set of doubles (DEVELOPMENT §3 rule 7 keeps
// doubles in the unit's own tree).
package uploadtest

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"fileparcel/internal/app"
	"fileparcel/internal/config"
	"fileparcel/internal/core"
	"fileparcel/internal/crypt"
	"fileparcel/internal/db"
	"fileparcel/internal/events"
	"fileparcel/internal/home"
	"fileparcel/internal/ids"
	"fileparcel/internal/names"
	"fileparcel/internal/ratelimit"
	"fileparcel/internal/settings"
	"fileparcel/internal/ziputil"
)

// KEKID is the keyring row referenced by fake blobs.
const KEKID = "kek_test"

// Env is a test environment.
type Env struct {
	T        testing.TB
	Env      *core.Env
	DB       *db.DB
	Clock    *Clock
	Keys     *Keys
	Settings *Settings
	Audit    *Audit
	Jobs     *Jobs
	Blobs    *Blobs
	Files    *Files
	Notify   *Notify
	Limiter  *ratelimit.Registry
	Bus      *events.Bus
}

// New builds a migrated database in a temporary home and the fakes.
func New(t testing.TB) *Env {
	t.Helper()
	h, err := home.New(filepath.Join(t.TempDir(), "home"))
	if err != nil {
		t.Fatal(err)
	}
	if err := h.EnsureLayout(); err != nil {
		t.Fatal(err)
	}
	d, err := db.Open(h.DB())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := d.Migrate(context.Background()); err != nil {
		t.Fatal(err)
	}
	clock := &Clock{}
	clock.Set(time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC))
	bus := events.New()
	e := &Env{T: t, DB: d, Clock: clock, Bus: bus,
		Keys: NewKeys(), Settings: NewSettings(), Audit: &Audit{}, Jobs: NewJobs(), Notify: &Notify{On: true}}
	cfg := config.Default(config.NewInstallID())
	e.Env = &core.Env{Home: h, Config: cfg, DB: d, Clock: clock, Bus: bus,
		Log: slog.New(slog.NewTextHandler(io.Discard, nil)), Keys: e.Keys, Settings: e.Settings, Audit: e.Audit}
	e.Jobs.env = e.Env
	e.Blobs = &Blobs{env: e.Env, data: map[string][]byte{}, parted: map[string]*parted{}}
	e.Files = &Files{env: e.Env, blobs: e.Blobs, tickets: map[string]*core.ArchiveTicket{}, grants: map[[2]string]core.Perm{}}
	if e.Limiter, err = ratelimit.New(e.Env); err != nil {
		t.Fatal(err)
	}
	e.Exec(`INSERT INTO keyring (id, purpose, mk_id, wrapped, state, created_at) VALUES (?, 'blob', 'mk_test', x'00', 'active', 0)`, KEKID)
	t.Cleanup(func() {
		e.Jobs.Wait()
		_ = e.Limiter.Close()
		bus.Close()
		_ = d.Close()
	})
	return e
}

// Deps returns app.Deps wired with the fakes plus the given services.
func (e *Env) Deps(uploads core.Uploads, shares core.Shares) *app.Deps {
	return &app.Deps{Env: e.Env, Mode: app.ModeNetwork, Auth: &Auth{env: e.Env}, Files: e.Files, Uploads: uploads,
		Shares: shares, Blobs: e.Blobs, Jobs: e.Jobs, Notify: e.Notify, Limiter: e.Limiter}
}

// ---------- auth ----------

// Auth authenticates test requests: "Authorization: Bearer <user id>"
// yields a full API-token principal of that user with every scope, and
// "Bearer <user id>;<scope>,<scope>" one with the listed scopes only.
// Requests without the header are anonymous.
type Auth struct {
	core.Auth
	env *core.Env
}

// Authenticate implements core.Auth.
func (a *Auth) Authenticate(r *http.Request) (*core.Principal, error) {
	h, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	if !ok {
		return nil, nil
	}
	userID, scopes, hasScopes := strings.Cut(h, ";")
	var name, role string
	err := a.env.DB.QueryRow(r.Context(), `SELECT username, role FROM users WHERE id = ?`, userID).Scan(&name, &role)
	if err != nil {
		return nil, core.ErrUnauthorized
	}
	p := &core.Principal{UserID: userID, Username: name, Role: core.Role(role), Via: core.ViaToken,
		TokenID: "tok_test", AuthLevel: core.AuthLevelFull, Scopes: core.AllScopes}
	if hasScopes {
		p.Scopes = strings.Split(scopes, ",")
	}
	return p, nil
}

// Exec runs a write statement or fails the test.
func (e *Env) Exec(q string, args ...any) {
	e.T.Helper()
	if _, err := e.DB.Exec(context.Background(), q, args...); err != nil {
		e.T.Fatalf("exec %q: %v", q, err)
	}
}

// Int runs a single-value integer query.
func (e *Env) Int(q string, args ...any) int64 {
	e.T.Helper()
	var n sql.NullInt64
	if err := e.DB.QueryRow(context.Background(), q, args...).Scan(&n); err != nil {
		e.T.Fatalf("query %q: %v", q, err)
	}
	return n.Int64
}

// Str runs a single-value text query ("" for NULL).
func (e *Env) Str(q string, args ...any) string {
	e.T.Helper()
	var s sql.NullString
	if err := e.DB.QueryRow(context.Background(), q, args...).Scan(&s); err != nil {
		e.T.Fatalf("query %q: %v", q, err)
	}
	return s.String
}

// User creates an active user with a personal space and returns the user id
// and the id of the space's root folder.
func (e *Env) User(username string, role core.Role) (userID, rootID string) {
	e.T.Helper()
	userID = ids.New(ids.PrefixUser)
	spaceID := ids.New(ids.PrefixSpace)
	rootID = ids.New(ids.PrefixNode)
	now := db.Ms(e.Clock.Now())
	e.Exec(`INSERT INTO users (id, username, display_name, email, role, webauthn_handle, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)`, userID, username, strings.ToUpper(username[:1])+username[1:],
		username+"@example.test", string(role), crypt.RandomBytes(16), now, now)
	e.Exec(`INSERT INTO spaces (id, kind, owner_user_id, name, created_at) VALUES (?, 'user', ?, 'My files', ?)`, spaceID, userID, now)
	e.Exec(`INSERT INTO nodes (id, space_id, parent_id, kind, name, name_key, created_at, updated_at, created_by, updated_by)
		VALUES (?, ?, NULL, 'folder', 'My files', 'my files', ?, ?, ?, ?)`, rootID, spaceID, now, now, userID, userID)
	return userID, rootID
}

// SetQuota sets users.quota_bytes (nil = default).
func (e *Env) SetQuota(userID string, q *int64) {
	e.Exec(`UPDATE users SET quota_bytes = ? WHERE id = ?`, db.NullInt64(q), userID)
}

// P returns a full session principal for a user.
func (e *Env) P(userID string) *core.Principal {
	e.T.Helper()
	var name, role string
	if err := e.DB.QueryRow(context.Background(), `SELECT username, role FROM users WHERE id = ?`, userID).Scan(&name, &role); err != nil {
		e.T.Fatalf("principal %s: %v", userID, err)
	}
	return &core.Principal{UserID: userID, Username: name, Role: core.Role(role), Via: core.ViaSession,
		SessionID: "ses_" + name, AuthLevel: core.AuthLevelFull, RequestID: "req-test"}
}

// Mkdir creates a folder (as the owner of the parent's space).
func (e *Env) Mkdir(parentID, name string) string {
	e.T.Helper()
	n, err := e.Files.GetSys(context.Background(), parentID)
	if err != nil {
		e.T.Fatal(err)
	}
	owner := e.Str(`SELECT owner_user_id FROM spaces WHERE id = ?`, n.SpaceID)
	node, err := e.Files.MkdirAll(context.Background(), e.P(owner), parentID, name)
	if err != nil {
		e.T.Fatal(err)
	}
	return node.ID
}

// PutFile stores content as the file relPath below parentID (as the space owner).
func (e *Env) PutFile(parentID, relPath string, content []byte) *core.Node {
	e.T.Helper()
	ctx := context.Background()
	w, err := e.Blobs.Create(ctx)
	if err != nil {
		e.T.Fatal(err)
	}
	_, _ = w.Write(content)
	info, err := w.Commit(ctx)
	if err != nil {
		e.T.Fatal(err)
	}
	n, err := e.Files.GetSys(ctx, parentID)
	if err != nil {
		e.T.Fatal(err)
	}
	owner := e.Str(`SELECT owner_user_id FROM spaces WHERE id = ?`, n.SpaceID)
	node, err := e.Files.CommitFile(ctx, e.P(owner), parentID, relPath, info, core.FileMeta{}, core.ConflictFail)
	if err != nil {
		e.T.Fatal(err)
	}
	return node
}

// ---------- clock ----------

// Clock is a settable clock.
type Clock struct{ ms atomic.Int64 }

// Now implements core.Clock.
func (c *Clock) Now() time.Time { return time.UnixMilli(c.ms.Load()).UTC() }

// Set sets the time.
func (c *Clock) Set(t time.Time) { c.ms.Store(t.UnixMilli()) }

// Advance moves the clock forward.
func (c *Clock) Advance(d time.Duration) { c.ms.Add(d.Milliseconds()) }

// ---------- keys ----------

// Keys implements the field encryption and MAC parts of core.Keys.
type Keys struct {
	core.Keys
	key    []byte
	Locked atomic.Bool
}

// NewKeys returns unlocked fake keys.
func NewKeys() *Keys { return &Keys{key: crypt.RandomBytes(32)} }

// State implements core.Keys.
func (k *Keys) State() core.KeyState {
	if k.Locked.Load() {
		return core.KeyStateLocked
	}
	return core.KeyStateUnlocked
}

// SealField implements core.Keys.
func (k *Keys) SealField(aad string, pt []byte) (string, error) {
	if k.Locked.Load() {
		return "", core.ErrKeysLocked
	}
	ct, err := crypt.SealWithKey(1, k.key, pt, []byte(aad))
	if err != nil {
		return "", err
	}
	return "v1:" + KEKID + ":" + hex.EncodeToString(ct), nil
}

// OpenField implements core.Keys.
func (k *Keys) OpenField(aad, sealed string) ([]byte, error) {
	if k.Locked.Load() {
		return nil, core.ErrKeysLocked
	}
	raw, err := hex.DecodeString(strings.TrimPrefix(sealed, "v1:"+KEKID+":"))
	if err != nil {
		return nil, core.ErrCorrupt
	}
	pt, err := crypt.OpenWithKey(1, k.key, raw, []byte(aad))
	if err != nil {
		return nil, core.ErrCorrupt
	}
	return pt, nil
}

// MAC implements core.Keys (nil while locked).
func (k *Keys) MAC(purpose string, data ...[]byte) []byte {
	if k.Locked.Load() {
		return nil
	}
	return crypt.HMAC(k.key, append([][]byte{[]byte("fp-mac|" + purpose)}, data...)...)
}

// ---------- settings ----------

// Settings is a map-backed core.Settings falling back to the registered
// defaults (settings.Lookup).
type Settings struct {
	core.Settings
	mu sync.Mutex
	m  map[string]any
}

// NewSettings returns an empty override map.
func NewSettings() *Settings { return &Settings{m: map[string]any{}} }

// Put overrides a value.
func (s *Settings) Put(key string, v any) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.m[key] = v
}

// Raw implements core.Settings.
func (s *Settings) Raw(key string) (json.RawMessage, error) {
	s.mu.Lock()
	v, ok := s.m[key]
	s.mu.Unlock()
	if ok {
		return json.Marshal(v)
	}
	d, ok := settings.Lookup(key)
	if !ok {
		return nil, core.NotFoundf("unknown setting %q", key)
	}
	return d.DefaultJSON(), nil
}

func (s *Settings) decode(key string, v any) {
	raw, err := s.Raw(key)
	if err == nil {
		_ = json.Unmarshal(raw, v)
	}
}

// Int implements core.Settings.
func (s *Settings) Int(key string) int64 { var v int64; s.decode(key, &v); return v }

// Bool implements core.Settings.
func (s *Settings) Bool(key string) bool { var v bool; s.decode(key, &v); return v }

// String implements core.Settings.
func (s *Settings) String(key string) string { var v string; s.decode(key, &v); return v }

// Strings implements core.Settings.
func (s *Settings) Strings(key string) []string { var v []string; s.decode(key, &v); return v }

// ---------- audit ----------

// Audit records entries in memory.
type Audit struct {
	core.Audit
	mu      sync.Mutex
	Entries []core.AuditEntry
}

// Record implements core.Audit.
func (a *Audit) Record(ctx context.Context, e core.AuditEntry) {
	if p := core.PrincipalFrom(ctx); p != nil && e.ActorID == "" && e.ActorName == "" {
		e.ActorID, e.ActorName = p.UserID, p.Username
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	a.Entries = append(a.Entries, e)
}

// RecordTx implements core.Audit.
func (a *Audit) RecordTx(ctx context.Context, _ *sql.Tx, e core.AuditEntry) error {
	a.Record(ctx, e)
	return nil
}

// Actions returns the recorded actions.
func (a *Audit) Actions() []string {
	a.mu.Lock()
	defer a.mu.Unlock()
	out := make([]string, 0, len(a.Entries))
	for _, e := range a.Entries {
		out = append(out, e.Action)
	}
	return out
}

// Find returns the last entry with action.
func (a *Audit) Find(action string) (core.AuditEntry, bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	for i := len(a.Entries) - 1; i >= 0; i-- {
		if a.Entries[i].Action == action {
			return a.Entries[i], true
		}
	}
	return core.AuditEntry{}, false
}

// ---------- notify ----------

// Sent is one fake e-mail.
type Sent struct {
	To   []string
	Tmpl string
	Data any
}

// Notify records sends.
type Notify struct {
	On   bool
	mu   sync.Mutex
	sent []Sent
}

// Enabled implements core.Notify.
func (n *Notify) Enabled() bool { return n.On }

// Send implements core.Notify.
func (n *Notify) Send(_ context.Context, to []string, tmpl string, data any) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.sent = append(n.sent, Sent{To: to, Tmpl: tmpl, Data: data})
	return nil
}

// Test implements core.Notify.
func (n *Notify) Test(context.Context, string) error { return nil }

// Sent returns the recorded sends.
func (n *Notify) Sent() []Sent {
	n.mu.Lock()
	defer n.mu.Unlock()
	return append([]Sent(nil), n.sent...)
}

// ---------- jobs ----------

// Jobs runs enqueued jobs in goroutines (or on demand with Manual).
type Jobs struct {
	env    *core.Env
	mu     sync.Mutex
	kinds  map[string]core.JobFunc
	jobs   map[string]*core.Job
	Sched  map[string]string // schedule name → "cron kind"
	Manual bool
	wg     sync.WaitGroup
}

// NewJobs returns an empty job runner.
func NewJobs() *Jobs {
	return &Jobs{kinds: map[string]core.JobFunc{}, jobs: map[string]*core.Job{}, Sched: map[string]string{}}
}

// Register implements core.Jobs.
func (j *Jobs) Register(kind string, fn core.JobFunc, _ core.JobOptions) {
	j.mu.Lock()
	defer j.mu.Unlock()
	j.kinds[kind] = fn
}

// Schedule implements core.Jobs.
func (j *Jobs) Schedule(name, cron, kind string, _ any) error {
	j.mu.Lock()
	defer j.mu.Unlock()
	j.Sched[name] = cron + " " + kind
	return nil
}

// Unschedule implements core.Jobs.
func (j *Jobs) Unschedule(name string) {
	j.mu.Lock()
	defer j.mu.Unlock()
	delete(j.Sched, name)
}

// Schedules implements core.Jobs (not used).
func (j *Jobs) Schedules(context.Context) ([]core.JobSchedule, error) { return nil, nil }

// Enqueue implements core.Jobs.
func (j *Jobs) Enqueue(_ context.Context, kind string, params any, by *core.Principal) (string, error) {
	j.mu.Lock()
	if j.kinds[kind] == nil {
		j.mu.Unlock()
		return "", core.Invalid("kind", "unknown job kind "+kind)
	}
	raw, _ := json.Marshal(params)
	id := ids.New(ids.PrefixJob)
	job := &core.Job{ID: id, Kind: kind, State: core.JobQueued, Params: raw}
	if by != nil {
		job.CreatedBy = by.UserID
	}
	j.jobs[id] = job
	manual := j.Manual
	j.mu.Unlock()
	if !manual {
		j.wg.Add(1)
		go func() {
			defer j.wg.Done()
			j.Run(id)
		}()
	}
	return id, nil
}

// Run executes a queued job synchronously.
func (j *Jobs) Run(id string) error {
	j.mu.Lock()
	job := j.jobs[id]
	if job == nil || job.State != core.JobQueued {
		j.mu.Unlock()
		return errors.New("job not queued")
	}
	fn := j.kinds[job.Kind]
	job.State = core.JobRunning
	j.mu.Unlock()
	h := &handle{j: j, job: job}
	err := fn(context.Background(), h)
	j.mu.Lock()
	defer j.mu.Unlock()
	if err != nil {
		job.State, job.Error = core.JobFailed, err.Error()
	} else {
		job.State = core.JobSucceeded
	}
	return err
}

// Wait waits for every running job.
func (j *Jobs) Wait() { j.wg.Wait() }

// Get implements core.Jobs.
func (j *Jobs) Get(_ context.Context, id string) (*core.Job, error) {
	j.mu.Lock()
	defer j.mu.Unlock()
	job := j.jobs[id]
	if job == nil {
		return nil, core.NotFoundf("job not found")
	}
	c := *job
	return &c, nil
}

// SetState changes a job's state (tests of stuck jobs).
func (j *Jobs) SetState(id, state string) {
	j.mu.Lock()
	defer j.mu.Unlock()
	if job := j.jobs[id]; job != nil {
		job.State = state
	}
}

// Kinds returns the registered kinds.
func (j *Jobs) Kinds() []string {
	j.mu.Lock()
	defer j.mu.Unlock()
	var out []string
	for k := range j.kinds {
		out = append(out, k)
	}
	return out
}

// List implements core.Jobs (not used).
func (j *Jobs) List(context.Context, core.JobQuery) (core.Page[core.Job], error) {
	return core.Page[core.Job]{}, nil
}

// Cancel implements core.Jobs (not used).
func (j *Jobs) Cancel(context.Context, string) error { return nil }

// Start implements core.Jobs.
func (j *Jobs) Start(context.Context) error { return nil }

// Stop implements core.Jobs.
func (j *Jobs) Stop(context.Context) error { return nil }

var _ core.Jobs = (*Jobs)(nil)

type handle struct {
	j   *Jobs
	job *core.Job
}

func (h *handle) ID() string { return h.job.ID }
func (h *handle) Params(v any) error {
	return json.Unmarshal(h.job.Params, v)
}
func (h *handle) Progress(done, total int64, note string) {
	h.j.mu.Lock()
	defer h.j.mu.Unlock()
	h.job.ProgressDone, h.job.ProgressTotal, h.job.Note = done, total, note
}
func (h *handle) SetResult(v any) {
	raw, _ := json.Marshal(v)
	h.j.mu.Lock()
	defer h.j.mu.Unlock()
	h.job.Result = raw
}

// ---------- blobs ----------

// Blobs is an in-memory blob store that keeps blobs rows in the database.
type Blobs struct {
	env    *core.Env
	mu     sync.Mutex
	data   map[string][]byte
	parted map[string]*parted
	// PartHook, when set, runs before a part is stored; an error fails the
	// write (simulating a crash or a broken connection).
	PartHook func(blobID string, n int) error
	// ReadHook, when set, runs before every ReadAt of a reader returned by
	// Open (tests that interrupt a long read). Set it before Open.
	ReadHook func(blobID string, off int64)
	writes   atomic.Int64
}

type parted struct {
	size  int64
	parts map[int][]byte
}

// PartWrites returns how many parts were written.
func (b *Blobs) PartWrites() int64 { return b.writes.Load() }

// Has reports whether a committed or staged blob exists.
func (b *Blobs) Has(id string) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	_, ok := b.data[id]
	_, ok2 := b.parted[id]
	return ok || ok2
}

// Count returns the number of blobs (committed + staged).
func (b *Blobs) Count() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return len(b.data) + len(b.parted)
}

// Bytes returns a committed blob's content.
func (b *Blobs) Bytes(id string) []byte {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.data[id]
}

// ContentHash computes the §7.3 content hash.
func ContentHash(p []byte) string {
	outer := sha256.New()
	for off := 0; off < len(p); off += core.PartSize {
		s := sha256.Sum256(p[off:min(off+core.PartSize, len(p))])
		outer.Write(s[:])
	}
	return "fp1:" + hex.EncodeToString(outer.Sum(nil))
}

func (b *Blobs) insert(ctx context.Context, id string, size int64, state string) error {
	return b.env.DB.Tx(ctx, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `INSERT INTO blobs (id, state, size, cipher, kek_id, wrapped_dek, created_at)
			VALUES (?, ?, ?, 1, ?, x'00', ?)`, id, state, size, KEKID, db.Ms(b.env.Now()))
		return err
	})
}

func (b *Blobs) ready(ctx context.Context, id string, p []byte) (*core.BlobInfo, error) {
	info := &core.BlobInfo{ID: id, Size: int64(len(p)), StoredSize: int64(len(p)) + 60, ContentHash: ContentHash(p),
		Cipher: core.CipherAES256GCM, CreatedAt: b.env.Now()}
	err := b.env.DB.Tx(ctx, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `UPDATE blobs SET state = 'ready', stored_size = ?, content_hash = ? WHERE id = ?`,
			info.StoredSize, info.ContentHash, id)
		return err
	})
	return info, err
}

// Create implements core.BlobStore.
func (b *Blobs) Create(ctx context.Context) (core.BlobWriter, error) {
	return &writer{b: b, id: ids.NewBlobID()}, nil
}

type writer struct {
	b    *Blobs
	id   string
	buf  bytes.Buffer
	done bool
}

func (w *writer) Write(p []byte) (int, error) {
	if w.done {
		return 0, errors.New("blob writer closed")
	}
	return w.buf.Write(p)
}

func (w *writer) Commit(ctx context.Context) (*core.BlobInfo, error) {
	if w.done {
		return nil, errors.New("blob writer closed")
	}
	w.done = true
	p := bytes.Clone(w.buf.Bytes())
	if err := w.b.insert(ctx, w.id, int64(len(p)), "staging"); err != nil {
		return nil, err
	}
	w.b.mu.Lock()
	w.b.data[w.id] = p
	w.b.mu.Unlock()
	return w.b.ready(ctx, w.id, p)
}

func (w *writer) Abort() error { w.done = true; return nil }

// CreateParted implements core.BlobStore.
func (b *Blobs) CreateParted(ctx context.Context, size int64) (core.PartedBlob, error) {
	id := ids.NewBlobID()
	if err := b.insert(ctx, id, size, "staging"); err != nil {
		return nil, err
	}
	b.mu.Lock()
	b.parted[id] = &parted{size: size, parts: map[int][]byte{}}
	b.mu.Unlock()
	return &partedBlob{b: b, id: id}, nil
}

// OpenParted implements core.BlobStore. Like the real store it refuses a
// blob that is already committed (409).
func (b *Blobs) OpenParted(_ context.Context, id string) (core.PartedBlob, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.parted[id] == nil {
		if _, ok := b.data[id]; ok {
			return nil, core.Errorf(core.ErrConflict, "the blob is already committed")
		}
		return nil, core.NotFoundf("parted blob not found")
	}
	return &partedBlob{b: b, id: id}, nil
}

type partedBlob struct {
	b  *Blobs
	id string
}

func (p *partedBlob) st() *parted {
	p.b.mu.Lock()
	defer p.b.mu.Unlock()
	return p.b.parted[p.id]
}

func (p *partedBlob) ID() string { return p.id }
func (p *partedBlob) Size() int64 {
	if s := p.st(); s != nil {
		return s.size
	}
	return 0
}
func (p *partedBlob) PartCount() int {
	s := p.st()
	if s == nil || s.size <= 0 {
		return 1
	}
	return int((s.size + core.PartSize - 1) / core.PartSize)
}

func (p *partedBlob) WritePart(ctx context.Context, n int, r io.Reader, want []byte) ([]byte, error) {
	s := p.st()
	if s == nil {
		return nil, core.NotFoundf("parted blob not found")
	}
	if n < 0 || n >= p.PartCount() {
		return nil, core.Invalid("n", "part out of range")
	}
	ln := min(int64(core.PartSize), s.size-int64(n)*core.PartSize)
	buf := make([]byte, ln)
	if _, err := io.ReadFull(r, buf); err != nil {
		return nil, err
	}
	sum := sha256.Sum256(buf)
	if !bytes.Equal(sum[:], want) {
		return sum[:], core.Invalid("sha256", "part digest mismatch")
	}
	if p.b.PartHook != nil {
		if err := p.b.PartHook(p.id, n); err != nil {
			return nil, err
		}
	}
	p.b.writes.Add(1)
	p.b.mu.Lock()
	defer p.b.mu.Unlock()
	if st := p.b.parted[p.id]; st != nil {
		st.parts[n] = buf
	} else {
		return nil, core.NotFoundf("parted blob deleted")
	}
	return sum[:], nil
}

func (p *partedBlob) Commit(ctx context.Context, digests [][]byte) (*core.BlobInfo, error) {
	p.b.mu.Lock()
	s := p.b.parted[p.id]
	if s == nil {
		p.b.mu.Unlock()
		return nil, core.NotFoundf("parted blob not found")
	}
	count := p.partCountLocked(s)
	if len(digests) != count {
		p.b.mu.Unlock()
		return nil, core.Errorf(core.ErrConflict, "need %d digests", count)
	}
	var out []byte
	for i := 0; i < count; i++ {
		part, ok := s.parts[i]
		if !ok {
			p.b.mu.Unlock()
			return nil, core.Errorf(core.ErrConflict, "part %d missing", i)
		}
		sum := sha256.Sum256(part)
		if !bytes.Equal(sum[:], digests[i]) {
			p.b.mu.Unlock()
			return nil, core.Errorf(core.ErrConflict, "part %d digest", i)
		}
		out = append(out, part...)
	}
	delete(p.b.parted, p.id)
	p.b.data[p.id] = out
	p.b.mu.Unlock()
	return p.b.ready(ctx, p.id, out)
}

func (p *partedBlob) partCountLocked(s *parted) int {
	if s.size <= 0 {
		return 1
	}
	return int((s.size + core.PartSize - 1) / core.PartSize)
}

func (p *partedBlob) Abort() error { return p.b.Delete(context.Background(), p.id) }

// Open implements core.BlobStore.
func (b *Blobs) Open(_ context.Context, id string) (core.BlobReader, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	p, ok := b.data[id]
	if !ok {
		return nil, core.NotFoundf("blob not found")
	}
	return &reader{Reader: bytes.NewReader(p), id: id, size: int64(len(p)), hook: b.ReadHook}, nil
}

type reader struct {
	*bytes.Reader
	id   string
	size int64
	hook func(blobID string, off int64)
}

// ReadAt runs the read hook, then reads.
func (r *reader) ReadAt(p []byte, off int64) (int, error) {
	if r.hook != nil {
		r.hook(r.id, off)
	}
	return r.Reader.ReadAt(p, off)
}

func (r *reader) Close() error { return nil }
func (r *reader) Size() int64  { return r.size }
func (r *reader) ID() string   { return r.id }

// Stat implements core.BlobStore.
func (b *Blobs) Stat(_ context.Context, id string) (*core.BlobInfo, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	p, ok := b.data[id]
	if !ok {
		return nil, core.NotFoundf("blob not found")
	}
	return &core.BlobInfo{ID: id, Size: int64(len(p)), ContentHash: ContentHash(p), Cipher: core.CipherAES256GCM}, nil
}

// Delete implements core.BlobStore. Deleting a blob that a file version
// still references fails (foreign key), which tests rely on.
func (b *Blobs) Delete(ctx context.Context, id string) error {
	err := b.env.DB.Tx(ctx, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `DELETE FROM blobs WHERE id = ?`, id)
		return err
	})
	if err != nil {
		return fmt.Errorf("delete blob %s: %w", id, err)
	}
	b.mu.Lock()
	delete(b.data, id)
	delete(b.parted, id)
	b.mu.Unlock()
	return nil
}

// Verify implements core.BlobStore.
func (b *Blobs) Verify(context.Context, string) error { return nil }

// GC implements core.BlobStore.
func (b *Blobs) GC(context.Context, time.Duration) (int, int64, error) { return 0, 0, nil }

// Reencrypt implements core.BlobStore.
func (b *Blobs) Reencrypt(context.Context, string) (string, error) { return "", core.ErrNotImplemented }

var _ core.BlobStore = (*Blobs)(nil)

// ---------- files ----------

// Files implements the core.Files methods used by unit E over the real
// nodes / file_versions tables. Permissions: the owner of a personal space
// has PermOwner; Grant adds a permission on a node and its descendants.
type Files struct {
	core.Files
	env     *core.Env
	blobs   *Blobs
	mu      sync.Mutex
	tickets map[string]*core.ArchiveTicket
	grants  map[[2]string]core.Perm // (user, node)
}

// Grant gives userID perm on nodeID and its descendants.
func (f *Files) Grant(userID, nodeID string, perm core.Perm) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.grants[[2]string{userID, nodeID}] = perm
}

const nodeCols = `n.rid, n.id, n.space_id, n.parent_id, n.kind, n.name, n.name_key, n.size, n.mime, n.version_id,
	n.content_hash, n.client_mtime, n.created_at, n.updated_at, n.created_by, n.updated_by, n.trashed_at, n.thumb_blob_id, v.blob_id,
	v.zip_encryption`

type scanner interface{ Scan(...any) error }

func scanNode(sc scanner) (*core.Node, error) {
	var (
		n                                                       core.Node
		parent, mimeT, ver, hash, cby, uby, thumb, blob, zipEnc sql.NullString
		mtime, trashed                                          sql.NullInt64
		created, updated                                        int64
	)
	if err := sc.Scan(&n.RID, &n.ID, &n.SpaceID, &parent, &n.Kind, &n.Name, &n.NameKey, &n.Size, &mimeT, &ver,
		&hash, &mtime, &created, &updated, &cby, &uby, &trashed, &thumb, &blob, &zipEnc); err != nil {
		return nil, err
	}
	n.ParentID, n.MIME, n.VersionID, n.ContentHash = parent.String, mimeT.String, ver.String, hash.String
	n.CreatedBy, n.UpdatedBy, n.ThumbBlobID, n.BlobID = cby.String, uby.String, thumb.String, blob.String
	n.ZipEncryption = zipEnc.String
	n.ClientMtime, n.TrashedAt = db.FromNullMs(mtime), db.FromNullMs(trashed)
	n.CreatedAt, n.UpdatedAt = db.FromMs(created), db.FromMs(updated)
	n.HasThumb = n.ThumbBlobID != ""
	return &n, nil
}

func (f *Files) node(ctx context.Context, id string) (*core.Node, error) {
	n, err := scanNode(f.env.DB.QueryRow(ctx, `SELECT `+nodeCols+` FROM nodes n
		LEFT JOIN file_versions v ON v.id = n.version_id WHERE n.id = ?`, id))
	if db.IsNoRows(err) {
		return nil, core.NotFoundf("node not found")
	}
	return n, err
}

// GetSys implements core.Files.
func (f *Files) GetSys(ctx context.Context, id string) (*core.Node, error) { return f.node(ctx, id) }

// ancestors returns id and its ancestors (self first).
func (f *Files) ancestors(ctx context.Context, id string) ([]string, error) {
	rows, err := f.env.DB.Query(ctx, `WITH RECURSIVE up(id, parent_id, d) AS (
			SELECT id, parent_id, 0 FROM nodes WHERE id = ?
			UNION ALL SELECT n.id, n.parent_id, up.d + 1 FROM nodes n JOIN up ON n.id = up.parent_id)
		SELECT id FROM up ORDER BY d`, id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var s string
		if err := rows.Scan(&s); err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

// IsWithin implements core.Files: whether id is anc or lies below it (the
// semantics of the files service).
func (f *Files) IsWithin(ctx context.Context, anc, id string) (bool, error) {
	if anc == id {
		return true, nil
	}
	up, err := f.ancestors(ctx, id)
	if err != nil {
		return false, err
	}
	for _, a := range up[min(1, len(up)):] {
		if a == anc {
			return true, nil
		}
	}
	return false, nil
}

func (f *Files) perm(ctx context.Context, p *core.Principal, n *core.Node) core.Perm {
	if p == nil {
		return core.PermNone
	}
	var owner sql.NullString
	_ = f.env.DB.QueryRow(ctx, `SELECT owner_user_id FROM spaces WHERE id = ?`, n.SpaceID).Scan(&owner)
	if owner.Valid && owner.String == p.UserID {
		return core.PermOwner
	}
	up, _ := f.ancestors(ctx, n.ID)
	best := core.PermNone
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, a := range up {
		if g, ok := f.grants[[2]string{p.UserID, a}]; ok && g > best {
			best = g
		}
	}
	return best
}

// Authorize implements core.Files.
func (f *Files) Authorize(ctx context.Context, p *core.Principal, id string, need core.Perm) (*core.Node, error) {
	n, err := f.node(ctx, id)
	if err != nil {
		return nil, err
	}
	if n.TrashedAt != nil {
		return nil, core.NotFoundf("node not found")
	}
	perm := f.perm(ctx, p, n)
	switch {
	case perm == core.PermNone:
		return nil, core.NotFoundf("node not found")
	case perm < need:
		return nil, core.ErrForbidden
	}
	n.Perm = perm
	return n, nil
}

// SysPrincipalFor implements core.Files.
func (f *Files) SysPrincipalFor(ctx context.Context, userID string) (*core.Principal, error) {
	var name, role, status string
	err := f.env.DB.QueryRow(ctx, `SELECT username, role, status FROM users WHERE id = ?`, userID).Scan(&name, &role, &status)
	if db.IsNoRows(err) {
		return nil, core.NotFoundf("user not found")
	}
	if err != nil {
		return nil, err
	}
	if status != core.UserActive {
		return nil, core.ErrForbidden
	}
	return &core.Principal{UserID: userID, Username: name, Role: core.Role(role), Via: core.ViaShare, AuthLevel: core.AuthLevelFull}, nil
}

// Usage implements core.Files (personal space: live bytes, quota).
func (f *Files) Usage(ctx context.Context, userID string) (*core.Usage, error) {
	u := &core.Usage{UserID: userID}
	var q sql.NullInt64
	if err := f.env.DB.QueryRow(ctx, `SELECT quota_bytes FROM users WHERE id = ?`, userID).Scan(&q); err != nil {
		return nil, core.NotFoundf("user not found")
	}
	if q.Valid && q.Int64 > 0 {
		u.QuotaBytes = q.Int64
	}
	err := f.env.DB.QueryRow(ctx, `SELECT s.id, COALESCE(SUM(n.size), 0) FROM spaces s LEFT JOIN nodes n ON n.space_id = s.id
		AND n.kind = 'file' WHERE s.kind = 'user' AND s.owner_user_id = ? GROUP BY s.id`, userID).Scan(&u.SpaceID, &u.UsedBytes)
	if err != nil && !db.IsNoRows(err) {
		return nil, err
	}
	return u, nil
}

func (f *Files) child(ctx context.Context, parentID, key string) (*core.Node, error) {
	n, err := scanNode(f.env.DB.QueryRow(ctx, `SELECT `+nodeCols+` FROM nodes n LEFT JOIN file_versions v ON v.id = n.version_id
		WHERE n.parent_id = ? AND n.name_key = ? AND n.trashed_at IS NULL`, parentID, key))
	if db.IsNoRows(err) {
		return nil, nil
	}
	return n, err
}

func (f *Files) mkdir(ctx context.Context, p *core.Principal, parent *core.Node, name string) (*core.Node, error) {
	nfc, key, err := names.Clean(name)
	if err != nil {
		return nil, err
	}
	if ex, err := f.child(ctx, parent.ID, key); err != nil || ex != nil {
		if err != nil {
			return nil, err
		}
		if !ex.IsDir() {
			return nil, core.Errorf(core.ErrConflict, "%q is a file", nfc)
		}
		return ex, nil
	}
	id := ids.New(ids.PrefixNode)
	now := db.Ms(f.env.Now())
	if err := f.env.DB.Tx(ctx, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `INSERT INTO nodes (id, space_id, parent_id, kind, name, name_key, created_at, updated_at, created_by, updated_by)
			VALUES (?, ?, ?, 'folder', ?, ?, ?, ?, ?, ?)`, id, parent.SpaceID, parent.ID, nfc, key, now, now, p.UserID, p.UserID)
		return err
	}); err != nil {
		return nil, err
	}
	return f.node(ctx, id)
}

// MkdirAll implements core.Files.
func (f *Files) MkdirAll(ctx context.Context, p *core.Principal, parentID, relPath string) (*core.Node, error) {
	segs, err := names.SplitRelPath(relPath)
	if err != nil {
		return nil, err
	}
	cur, err := f.Authorize(ctx, p, parentID, core.PermEdit)
	if err != nil {
		return nil, err
	}
	for _, s := range segs {
		if cur, err = f.mkdir(ctx, p, cur, s); err != nil {
			return nil, err
		}
	}
	return cur, nil
}

// CommitFile implements core.Files with the unit-D semantics: missing
// folders of relPath are created; skip returns the existing node unchanged;
// m.ZipEncryption is stored on the new version (422 for an unknown value).
func (f *Files) CommitFile(ctx context.Context, p *core.Principal, parentID, relPath string, b *core.BlobInfo, m core.FileMeta, c core.ConflictPolicy) (*core.Node, error) {
	switch m.ZipEncryption {
	case "", core.ZipEncAES256, core.ZipEncZipCrypto:
	default:
		return nil, core.Invalid("zip_encryption", "unknown zip encryption")
	}
	segs, err := names.SplitRelPath(relPath)
	if err != nil {
		return nil, err
	}
	parent, err := f.Authorize(ctx, p, parentID, core.PermEdit)
	if err != nil {
		return nil, err
	}
	for _, s := range segs[:len(segs)-1] {
		if parent, err = f.mkdir(ctx, p, parent, s); err != nil {
			return nil, err
		}
	}
	name := segs[len(segs)-1]
	key := names.Key(name)
	if ex, err := f.child(ctx, parent.ID, key); err != nil {
		return nil, err
	} else if ex != nil {
		switch c {
		case core.ConflictFail:
			return nil, core.Errorf(core.ErrConflict, "%q already exists", name)
		case core.ConflictSkip:
			return ex, nil
		case core.ConflictReplace:
			if ex.IsDir() {
				return nil, core.Errorf(core.ErrConflict, "%q is a folder", name)
			}
			// as files.CommitFile: byte-identical content adds no version
			if b.ContentHash != "" && ex.ContentHash == b.ContentHash && ex.ZipEncryption == m.ZipEncryption {
				return ex, nil
			}
			return f.addVersion(ctx, p, ex.ID, b, m)
		default:
			for i := 1; ; i++ {
				cand := names.Numbered(name, i, false)
				if x, err := f.child(ctx, parent.ID, names.Key(cand)); err != nil {
					return nil, err
				} else if x == nil {
					name, key = cand, names.Key(cand)
					break
				}
			}
		}
	}
	nodeID, verID := ids.New(ids.PrefixNode), ids.New(ids.PrefixVersion)
	now := db.Ms(f.env.Now())
	mime := m.MIME
	if mime == "" {
		mime = "application/octet-stream"
		if strings.HasSuffix(strings.ToLower(name), ".txt") {
			mime = "text/plain"
		}
		if strings.HasSuffix(strings.ToLower(name), ".jpg") {
			mime = "image/jpeg"
		}
	}
	err = f.env.DB.Tx(ctx, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, `INSERT INTO nodes (id, space_id, parent_id, kind, name, name_key, size, mime, version_id,
				content_hash, client_mtime, created_at, updated_at, created_by, updated_by)
			VALUES (?, ?, ?, 'file', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`, nodeID, parent.SpaceID, parent.ID, name, key, b.Size, mime,
			verID, b.ContentHash, db.NullMs(m.ClientMtime), now, now, p.UserID, p.UserID); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO file_versions (id, node_id, blob_id, size, content_hash, created_at, created_by,
				zip_encryption) VALUES (?, ?, ?, ?, ?, ?, ?, NULLIF(?, ''))`,
			verID, nodeID, b.ID, b.Size, b.ContentHash, now, p.UserID, m.ZipEncryption); err != nil {
			return err
		}
		_, err := tx.ExecContext(ctx, `UPDATE spaces SET used_bytes = used_bytes + ? WHERE id = ?`, b.Size, parent.SpaceID)
		return err
	})
	if db.IsUnique(err) {
		return nil, core.Errorf(core.ErrConflict, "%q already exists", name)
	}
	if err != nil {
		return nil, err
	}
	return f.node(ctx, nodeID)
}

func (f *Files) addVersion(ctx context.Context, p *core.Principal, nodeID string, b *core.BlobInfo, m core.FileMeta) (*core.Node, error) {
	verID := ids.New(ids.PrefixVersion)
	now := db.Ms(f.env.Now())
	err := f.env.DB.Tx(ctx, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, `INSERT INTO file_versions (id, node_id, blob_id, size, content_hash, created_at, created_by,
				zip_encryption) VALUES (?, ?, ?, ?, ?, ?, ?, NULLIF(?, ''))`,
			verID, nodeID, b.ID, b.Size, b.ContentHash, now, p.UserID, m.ZipEncryption); err != nil {
			return err
		}
		_, err := tx.ExecContext(ctx, `UPDATE nodes SET size = ?, version_id = ?, content_hash = ?, updated_at = ? WHERE id = ?`,
			b.Size, verID, b.ContentHash, now, nodeID)
		return err
	})
	if err != nil {
		return nil, err
	}
	return f.node(ctx, nodeID)
}

// Trash marks a node and its descendants trashed (test helper).
func (f *Files) Trash(ctx context.Context, p *core.Principal, idList []string) error {
	now := db.Ms(f.env.Now())
	for _, id := range idList {
		if err := f.env.DB.Tx(ctx, func(tx *sql.Tx) error {
			_, err := tx.ExecContext(ctx, `WITH RECURSIVE down(id) AS (SELECT ? UNION ALL
				SELECT n.id FROM nodes n JOIN down ON n.parent_id = down.id)
				UPDATE nodes SET trashed_at = ? WHERE id IN (SELECT id FROM down)`, id, now)
			return err
		}); err != nil {
			return err
		}
	}
	return nil
}

// ListSys implements core.Files (folders first, by name; offset cursor).
func (f *Files) ListSys(ctx context.Context, folderID string, q core.ListQuery) (core.Page[core.Node], error) {
	off := 0
	if q.Cursor != "" {
		_, _ = fmt.Sscanf(q.Cursor, "%d", &off)
	}
	limit := q.EffectiveLimit()
	rows, err := f.env.DB.Query(ctx, `SELECT `+nodeCols+` FROM nodes n LEFT JOIN file_versions v ON v.id = n.version_id
		WHERE n.parent_id = ? AND n.trashed_at IS NULL ORDER BY n.kind DESC, n.name_key LIMIT ? OFFSET ?`, folderID, limit+1, off)
	if err != nil {
		return core.Page[core.Node]{}, err
	}
	defer rows.Close()
	var out []core.Node
	next := ""
	for rows.Next() {
		n, err := scanNode(rows)
		if err != nil {
			return core.Page[core.Node]{}, err
		}
		if len(out) == limit {
			next = fmt.Sprint(off + limit)
			break
		}
		out = append(out, *n)
	}
	return core.NewPage(out, next), rows.Err()
}

// OpenSys implements core.Files.
func (f *Files) OpenSys(ctx context.Context, id string) (*core.Node, core.BlobReader, error) {
	n, err := f.node(ctx, id)
	if err != nil {
		return nil, nil, err
	}
	if n.IsDir() {
		return nil, nil, core.Invalid("id", "not a file")
	}
	r, err := f.blobs.Open(ctx, n.BlobID)
	if err != nil {
		return nil, nil, err
	}
	return n, r, nil
}

// Thumbnail implements core.Files.
func (f *Files) Thumbnail(ctx context.Context, p *core.Principal, id string) (core.BlobReader, error) {
	n, err := f.Authorize(ctx, p, id, core.PermView)
	if err != nil {
		return nil, err
	}
	if n.ThumbBlobID == "" {
		return nil, core.NotFoundf("no thumbnail")
	}
	return f.blobs.Open(ctx, n.ThumbBlobID)
}

// CreateArchiveTicket implements core.Files (in memory).
func (f *Files) CreateArchiveTicket(_ context.Context, p *core.Principal, shareID string, in core.ArchiveInput) (string, error) {
	tok := ids.Token(32)
	t := &core.ArchiveTicket{ShareID: shareID, NodeIDs: in.NodeIDs, Format: in.Format, Name: in.Name + "." + in.Format,
		CreatedAt: f.env.Now(), ExpiresAt: f.env.Now().Add(time.Minute)}
	if shareID == "" && p != nil {
		t.UserID = p.UserID
	}
	f.mu.Lock()
	f.tickets[tok] = t
	f.mu.Unlock()
	return tok, nil
}

// ConsumeArchiveTicket implements core.Files (single use).
func (f *Files) ConsumeArchiveTicket(_ context.Context, tok string) (*core.ArchiveTicket, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	t := f.tickets[tok]
	if t == nil {
		return nil, core.NotFoundf("ticket not found")
	}
	delete(f.tickets, tok)
	return t, nil
}

// WriteArchive implements core.Files (zip of the listed files, flat).
func (f *Files) WriteArchive(ctx context.Context, t *core.ArchiveTicket, w io.Writer) error {
	zw, err := ziputil.New(w, ziputil.Options{})
	if err != nil {
		return err
	}
	for _, id := range t.NodeIDs {
		n, r, err := f.OpenSys(ctx, id)
		if err != nil {
			continue
		}
		err = zw.AddFile(n.Name, n.UpdatedAt, n.Size, r)
		_ = r.Close()
		if err != nil {
			return err
		}
	}
	return zw.Close()
}
