package keys

import (
	"context"
	"database/sql"
	"encoding/json"
	"io"
	"log/slog"
	"os"
	"sync"
	"testing"
	"time"

	"fileparcel/internal/core"
	"fileparcel/internal/crypt"
	"fileparcel/internal/db"
	"fileparcel/internal/events"
	"fileparcel/internal/home"
	"fileparcel/internal/ids"
	"fileparcel/internal/settings"
)

// Test-only settings (never catalog keys): a secret whose row is sealed and
// a plain string whose value may look like a sealed one.
const (
	testSecretKey = "keystest.secret"
	testPlainKey  = "keystest.plain"
)

func init() {
	settings.Register(settings.Def{Key: testSecretKey, Section: "keys", Type: settings.TypeSecret, Default: "", Label: "test secret"})
	settings.Register(settings.Def{Key: testPlainKey, Section: "keys", Type: settings.TypeString, Default: "", Label: "test plain"})
}

// realKDF keeps the production parameters; tests use cheap ones.
var realKDF = defaultKDF

func TestMain(m *testing.M) {
	defaultKDF = kdfConfig{T: 1, MKiB: 64, P: 1}
	os.Exit(m.Run())
}

const testPass = "correct horse battery staple"

// ---------- fakes ----------

type fakeAudit struct {
	mu      sync.Mutex
	entries []core.AuditEntry
}

func (a *fakeAudit) Record(_ context.Context, e core.AuditEntry) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.entries = append(a.entries, e)
}
func (a *fakeAudit) RecordTx(ctx context.Context, _ *sql.Tx, e core.AuditEntry) error {
	a.Record(ctx, e)
	return nil
}
func (a *fakeAudit) Query(context.Context, core.AuditQuery) (core.Page[core.AuditRecord], error) {
	return core.Page[core.AuditRecord]{}, core.ErrNotImplemented
}
func (a *fakeAudit) Verify(context.Context) (*core.AuditVerify, error) {
	return nil, core.ErrNotImplemented
}
func (a *fakeAudit) Export(context.Context, core.AuditQuery, string, io.Writer) error {
	return core.ErrNotImplemented
}
func (a *fakeAudit) Prune(context.Context, time.Time) (int, error) { return 0, core.ErrNotImplemented }

// find returns the entries with action (and outcome when not empty).
func (a *fakeAudit) find(action, outcome string) []core.AuditEntry {
	a.mu.Lock()
	defer a.mu.Unlock()
	var out []core.AuditEntry
	for _, e := range a.entries {
		if e.Action == action && (outcome == "" || e.Outcome == outcome) {
			out = append(out, e)
		}
	}
	return out
}

type fakeSettings struct {
	mu sync.Mutex
	m  map[string]any
}

func (f *fakeSettings) get(k string) (any, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	v, ok := f.m[k]
	return v, ok
}
func (f *fakeSettings) set(k string, v any) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.m == nil {
		f.m = map[string]any{}
	}
	f.m[k] = v
}
func (f *fakeSettings) Raw(k string) (json.RawMessage, error) {
	v, ok := f.get(k)
	if !ok {
		return nil, core.ErrNotFound
	}
	return json.Marshal(v)
}
func (f *fakeSettings) Int(k string) int64 {
	v, _ := f.get(k)
	i, _ := v.(int64)
	return i
}
func (f *fakeSettings) Bool(k string) bool {
	v, _ := f.get(k)
	b, _ := v.(bool)
	return b
}
func (f *fakeSettings) String(k string) string {
	v, _ := f.get(k)
	s, _ := v.(string)
	return s
}
func (f *fakeSettings) Strings(string) []string                             { return nil }
func (f *fakeSettings) Duration(string) time.Duration                       { return 0 }
func (f *fakeSettings) Secret(string) (string, error)                       { return "", core.ErrNotImplemented }
func (f *fakeSettings) Catalog(context.Context) ([]core.SettingView, error) { return nil, nil }
func (f *fakeSettings) Reset(context.Context, *core.Principal, string) error {
	return core.ErrNotImplemented
}
func (f *fakeSettings) Set(context.Context, *core.Principal, map[string]json.RawMessage) (*core.SettingsResult, error) {
	return nil, core.ErrNotImplemented
}

type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}
func (c *fakeClock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

// ---------- environment ----------

type testEnv struct {
	env      *core.Env
	h        *home.Home
	db       *db.DB
	audit    *fakeAudit
	settings *fakeSettings
	clock    *fakeClock
}

func newTestEnv(t testing.TB) *testEnv {
	t.Helper()
	h, err := home.New(t.TempDir())
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
	t.Cleanup(func() { d.Close() })
	if _, err := d.Migrate(context.Background()); err != nil {
		t.Fatal(err)
	}
	bus := events.New()
	t.Cleanup(bus.Close)
	te := &testEnv{h: h, db: d, audit: &fakeAudit{}, settings: &fakeSettings{},
		clock: &fakeClock{t: time.Date(2026, 9, 19, 12, 0, 0, 0, time.UTC)}}
	te.env = &core.Env{Home: h, DB: d, Log: slog.New(slog.DiscardHandler), Clock: te.clock, Bus: bus,
		Settings: te.settings, Audit: te.audit}
	return te
}

// open opens a keys service on the environment (closed at cleanup).
func (te *testEnv) open(t testing.TB) *Service {
	t.Helper()
	s, err := Open(te.env)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	te.env.Keys = s
	return s
}

// initPlain opens and initialises a plain-mode service.
func (te *testEnv) initPlain(t testing.TB) *Service {
	t.Helper()
	s := te.open(t)
	if rk, err := s.Init(context.Background(), false, nil); err != nil || rk != "" {
		t.Fatalf("Init plain: %q %v", rk, err)
	}
	return s
}

// initSealed opens and initialises a sealed-mode service; it returns the
// recovery key.
func (te *testEnv) initSealed(t testing.TB) (*Service, string) {
	t.Helper()
	s := te.open(t)
	rk, err := s.Init(context.Background(), true, []byte(testPass))
	if err != nil {
		t.Fatalf("Init sealed: %v", err)
	}
	return s, rk
}

// reopen closes s and opens a fresh service over the same home and DB.
func (te *testEnv) reopen(t testing.TB, s *Service) *Service {
	t.Helper()
	s.Close()
	return te.open(t)
}

func (te *testEnv) meta(t testing.TB, key string) string {
	t.Helper()
	v, _, err := getMeta(context.Background(), readerQ{te.db}, key)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func (te *testEnv) exec(t testing.TB, q string, args ...any) {
	t.Helper()
	if _, err := te.db.Exec(context.Background(), q, args...); err != nil {
		t.Fatalf("%s: %v", q, err)
	}
}

func (te *testEnv) queryString(t testing.TB, q string, args ...any) string {
	t.Helper()
	var v sql.NullString
	if err := te.db.QueryRow(context.Background(), q, args...).Scan(&v); err != nil {
		t.Fatalf("%s: %v", q, err)
	}
	return v.String
}

func (te *testEnv) count(t testing.TB, q string, args ...any) int64 {
	t.Helper()
	var n int64
	if err := te.db.QueryRow(context.Background(), q, args...).Scan(&n); err != nil {
		t.Fatalf("%s: %v", q, err)
	}
	return n
}

// fixture rows for the sealed columns and blobs.

type fixture struct {
	userID, spaceID, nodeID string
}

func (te *testEnv) fixture(t testing.TB) fixture {
	t.Helper()
	now := db.Ms(te.clock.Now())
	f := fixture{userID: ids.New(ids.PrefixUser), spaceID: ids.New(ids.PrefixSpace), nodeID: ids.New(ids.PrefixNode)}
	te.exec(t, `INSERT INTO users (id, username, role, webauthn_handle, created_at, updated_at) VALUES (?, ?, 'owner', ?, ?, ?)`,
		f.userID, "u"+f.userID[4:12], crypt.RandomBytes(16), now, now)
	te.exec(t, `INSERT INTO spaces (id, kind, owner_user_id, name, created_at) VALUES (?, 'user', ?, 'My files', ?)`,
		f.spaceID, f.userID, now)
	te.exec(t, `INSERT INTO nodes (id, space_id, kind, name, name_key, created_at, updated_at) VALUES (?, ?, 'folder', '', '', ?, ?)`,
		f.nodeID, f.spaceID, now, now)
	return f
}

// insertBlobRow inserts a blobs row with a DEK wrapped by s.
func insertBlobRow(t testing.TB, te *testEnv, s *Service, tx *sql.Tx) (id string, dek []byte) {
	t.Helper()
	id = ids.NewBlobID()
	raw, _ := ids.BlobIDBytes(id)
	dek, wrapped, kekID, err := s.NewDEK(raw)
	if err != nil {
		t.Fatal(err)
	}
	q := `INSERT INTO blobs (id, state, size, stored_size, cipher, kek_id, wrapped_dek, created_at) VALUES (?, 'ready', 0, 60, 1, ?, ?, ?)`
	args := []any{id, kekID, wrapped, db.Ms(te.clock.Now())}
	if tx != nil {
		_, err = tx.Exec(q, args...)
	} else {
		_, err = te.db.Exec(context.Background(), q, args...)
	}
	if err != nil {
		t.Fatal(err)
	}
	return id, dek
}

func activeKEK(t testing.TB, te *testEnv, purpose string) string {
	t.Helper()
	return te.queryString(t, `SELECT id FROM keyring WHERE purpose = ? AND state = 'active'`, purpose)
}

func must[T any](t testing.TB) func(T, error) T {
	return func(v T, err error) T {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
		return v
	}
}

func errIs(t testing.TB, err error, target *core.Error, what string) {
	t.Helper()
	if err == nil || !isErr(err, target) {
		t.Fatalf("%s: got %v, want %s", what, err, target.Code)
	}
}

func isErr(err error, target *core.Error) bool {
	ce := core.AsError(err)
	return ce != nil && ce.Code == target.Code
}
