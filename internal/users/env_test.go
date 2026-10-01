package users

import (
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"io"
	"log/slog"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"fileparcel/internal/config"
	"fileparcel/internal/core"
	"fileparcel/internal/crypt"
	"fileparcel/internal/db"
	"fileparcel/internal/events"
	"fileparcel/internal/home"
)

// ---------- fakes ----------

// fakeKeys implements the field encryption with a random AES key (AAD bound).
type fakeKeys struct {
	core.Keys
	key    []byte
	locked atomic.Bool
}

func newFakeKeys() *fakeKeys { return &fakeKeys{key: crypt.RandomBytes(32)} }

func (k *fakeKeys) State() core.KeyState {
	if k.locked.Load() {
		return core.KeyStateLocked
	}
	return core.KeyStateUnlocked
}

func (k *fakeKeys) SealField(aad string, pt []byte) (string, error) {
	if k.locked.Load() {
		return "", core.ErrKeysLocked
	}
	ct, err := crypt.SealWithKey(1, k.key, pt, []byte(aad))
	if err != nil {
		return "", err
	}
	return "v1:kek_test:" + base64.RawURLEncoding.EncodeToString(ct), nil
}

func (k *fakeKeys) OpenField(aad, sealed string) ([]byte, error) {
	if k.locked.Load() {
		return nil, core.ErrKeysLocked
	}
	b, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(sealed, "v1:kek_test:"))
	if err != nil {
		return nil, core.ErrCorrupt
	}
	pt, err := crypt.OpenWithKey(1, k.key, b, []byte(aad))
	if err != nil {
		return nil, core.ErrCorrupt
	}
	return pt, nil
}

func (k *fakeKeys) MAC(purpose string, data ...[]byte) []byte {
	return crypt.HMAC(k.key, append([][]byte{[]byte(purpose)}, data...)...)
}

// fakeSettings is a map-backed core.Settings.
type fakeSettings struct {
	core.Settings
	mu sync.Mutex
	m  map[string]any
}

func (f *fakeSettings) get(k string) any {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.m[k]
}

func (f *fakeSettings) set(k string, v any) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.m[k] = v
}

func (f *fakeSettings) Int(k string) int64 {
	switch v := f.get(k).(type) {
	case int:
		return int64(v)
	case int64:
		return v
	}
	return 0
}
func (f *fakeSettings) Bool(k string) bool        { b, _ := f.get(k).(bool); return b }
func (f *fakeSettings) String(k string) string    { s, _ := f.get(k).(string); return s }
func (f *fakeSettings) Strings(k string) []string { s, _ := f.get(k).([]string); return s }

// fakeAudit records entries in memory (RecordTx participates in nothing but
// fails when failTx is set, to test that audit failures abort changes).
type fakeAudit struct {
	core.Audit
	mu      sync.Mutex
	entries []core.AuditEntry
	failTx  atomic.Bool
}

func (a *fakeAudit) Record(ctx context.Context, e core.AuditEntry) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.entries = append(a.entries, fill(ctx, e))
}

func (a *fakeAudit) RecordTx(ctx context.Context, tx *sql.Tx, e core.AuditEntry) error {
	if a.failTx.Load() {
		return core.Errorf(core.ErrUnavailable, "audit down")
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	a.entries = append(a.entries, fill(ctx, e))
	return nil
}

func fill(ctx context.Context, e core.AuditEntry) core.AuditEntry {
	if p := core.PrincipalFrom(ctx); p != nil {
		if e.ActorID == "" && e.ActorName == "" {
			e.ActorID, e.ActorName = p.UserID, p.Username
		}
		// Like audit.fill: the client fields come from the principal.
		if e.IP == "" && p.IP.IsValid() {
			e.IP = p.IP.String()
		}
		if e.UserAgent == "" {
			e.UserAgent = p.UserAgent
		}
		if e.RequestID == "" {
			e.RequestID = p.RequestID
		}
	}
	if e.Outcome == "" {
		e.Outcome = core.OutcomeSuccess
	}
	return e
}

func (a *fakeAudit) actions() []string {
	a.mu.Lock()
	defer a.mu.Unlock()
	out := make([]string, len(a.entries))
	for i, e := range a.entries {
		out[i] = e.Action
	}
	return out
}

func (a *fakeAudit) last(action string) (core.AuditEntry, bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	for i := len(a.entries) - 1; i >= 0; i-- {
		if a.entries[i].Action == action {
			return a.entries[i], true
		}
	}
	return core.AuditEntry{}, false
}

func (a *fakeAudit) reset() {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.entries = nil
}

// fakeNotify records sent notifications (or refuses them with fail, like a
// full mail queue).
type fakeNotify struct {
	enabled atomic.Bool
	mu      sync.Mutex
	sent    []sentMail
	fail    error
}

type sentMail struct {
	to   []string
	tmpl string
	data map[string]any
}

func (n *fakeNotify) Enabled() bool { return n.enabled.Load() }
func (n *fakeNotify) Send(_ context.Context, to []string, tmpl string, data any) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.fail != nil {
		return n.fail
	}
	m, _ := data.(map[string]any)
	n.sent = append(n.sent, sentMail{to: to, tmpl: tmpl, data: m})
	return nil
}
func (n *fakeNotify) Test(context.Context, string) error { return nil }
func (n *fakeNotify) mails() []sentMail {
	n.mu.Lock()
	defer n.mu.Unlock()
	return append([]sentMail(nil), n.sent...)
}

// fakeNetwork returns fixed access URLs.
type fakeNetwork struct {
	core.Network
	urls []core.AccessURL
}

func (f *fakeNetwork) URLs(context.Context) ([]core.AccessURL, error) { return f.urls, nil }

// testClock is a settable clock.
type testClock struct{ ms atomic.Int64 }

func (c *testClock) Now() time.Time          { return time.UnixMilli(c.ms.Load()).UTC() }
func (c *testClock) Set(t time.Time)         { c.ms.Store(t.UnixMilli()) }
func (c *testClock) Advance(d time.Duration) { c.ms.Add(d.Milliseconds()) }

// ---------- environment ----------

type testEnv struct {
	env      *core.Env
	svc      *Service
	keys     *fakeKeys
	settings *fakeSettings
	audit    *fakeAudit
	notify   *fakeNotify
	clock    *testClock
}

func newTestEnv(t *testing.T) *testEnv {
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
	clock := &testClock{}
	clock.Set(time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC))
	te := &testEnv{
		keys: newFakeKeys(), settings: &fakeSettings{m: map[string]any{}}, audit: &fakeAudit{},
		notify: &fakeNotify{}, clock: clock,
	}
	bus := events.New()
	te.env = &core.Env{
		Home: h, DB: d, Clock: clock, Bus: bus, Config: config.Default("test"),
		Log:  slog.New(slog.NewTextHandler(io.Discard, nil)),
		Keys: te.keys, Settings: te.settings, Audit: te.audit,
	}
	te.svc, err = New(te.env)
	if err != nil {
		t.Fatal(err)
	}
	if err := te.svc.Bind(&core.Services{Notify: te.notify, Network: &fakeNetwork{urls: []core.AccessURL{
		{URL: "https://192.168.1.10:8443", Kind: "lan"}, {URL: "https://fileparcel.local:8443", Recommended: true},
	}}}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		bus.Close()
		_ = d.Close()
	})
	return te
}

// Principals.
func system() *core.Principal { return core.SystemPrincipal(core.ViaSocket) }

func as(u *core.User) *core.Principal {
	return &core.Principal{UserID: u.ID, Username: u.Username, Role: u.Role, Via: core.ViaSession, AuthLevel: core.AuthLevelFull}
}

// testPHC is a valid (cheap) argon2id hash.
var testPHC = func() string {
	h, err := crypt.HashPasswordParams("correct horse battery staple", crypt.Argon2Params{MemoryKiB: 64, Time: 1, Threads: 1, SaltLen: 16, KeyLen: 32})
	if err != nil {
		panic(err)
	}
	return h
}()

// mkUser creates a user with role (by the system principal).
func (te *testEnv) mkUser(t *testing.T, username string, role core.Role, opts ...func(*core.NewUser)) *core.User {
	t.Helper()
	in := core.NewUser{Username: username, Role: role, PasswordHash: testPHC}
	for _, o := range opts {
		o(&in)
	}
	u, err := te.svc.Create(context.Background(), system(), in)
	if err != nil {
		t.Fatalf("create %s: %v", username, err)
	}
	return u
}

func withEmail(e string) func(*core.NewUser) { return func(in *core.NewUser) { in.Email = e } }

func (te *testEnv) exec(t *testing.T, q string, args ...any) {
	t.Helper()
	if _, err := te.env.DB.Exec(context.Background(), q, args...); err != nil {
		t.Fatalf("exec %q: %v", q, err)
	}
}

func (te *testEnv) count(t *testing.T, q string, args ...any) int {
	t.Helper()
	var n int
	if err := te.env.DB.QueryRow(context.Background(), q, args...).Scan(&n); err != nil {
		t.Fatalf("count %q: %v", q, err)
	}
	return n
}

// mkNode inserts a node directly (the files service is not under test). A
// file gets one version (and blob) of size bytes, like the files service
// creates them.
func (te *testEnv) mkNode(t *testing.T, spaceID, parentID, kind, name string, size int64) string {
	t.Helper()
	id := newID("nod")
	now := db.Ms(te.clock.Now())
	te.exec(t, `INSERT INTO nodes (id, space_id, parent_id, kind, name, name_key, size, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`, id, spaceID, parentID, kind, name, strings.ToLower(name), size, now, now)
	if kind == core.KindFile {
		vid := te.mkVersion(t, id, size)
		te.exec(t, `UPDATE nodes SET version_id = ? WHERE id = ?`, vid, id)
	}
	return id
}

// mkVersion adds a stored version of size bytes (with its blob) to a file node.
func (te *testEnv) mkVersion(t *testing.T, nodeID string, size int64) string {
	t.Helper()
	now := db.Ms(te.clock.Now())
	te.exec(t, `INSERT INTO keyring (id, purpose, mk_id, wrapped, state, created_at)
		VALUES ('kek_test', 'blob', 'mk_test', x'00', 'active', 1) ON CONFLICT DO NOTHING`)
	blob, vid := newID("blob"), newID("ver")
	te.exec(t, `INSERT INTO blobs (id, state, size, stored_size, cipher, kek_id, wrapped_dek, created_at)
		VALUES (?, 'ready', ?, ?, 1, 'kek_test', x'00', ?)`, blob, size, size, now)
	te.exec(t, `INSERT INTO file_versions (id, node_id, blob_id, size, created_at) VALUES (?, ?, ?, ?, ?)`,
		vid, nodeID, blob, size, now)
	return vid
}

var idSeq atomic.Int64

func newID(prefix string) string {
	b, _ := json.Marshal(idSeq.Add(1))
	return prefix + "_test" + string(b)
}

// rootOf returns the root node id of a space.
func (te *testEnv) rootOf(t *testing.T, spaceID string) string {
	t.Helper()
	var id string
	if err := te.env.DB.QueryRow(context.Background(), `SELECT id FROM nodes WHERE space_id = ? AND parent_id IS NULL`, spaceID).Scan(&id); err != nil {
		t.Fatalf("root of %s: %v", spaceID, err)
	}
	return id
}

func ptr[T any](v T) *T { return &v }
