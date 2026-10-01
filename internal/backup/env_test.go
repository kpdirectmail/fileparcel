package backup

import (
	"bytes"
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"fileparcel/internal/config"
	"fileparcel/internal/core"
	"fileparcel/internal/db"
	"fileparcel/internal/events"
	"fileparcel/internal/home"
	"fileparcel/internal/jobs"
	"fileparcel/internal/settings"
)

func TestMain(m *testing.M) {
	scryptWorkFactor = 10 // fast passphrase tests
	os.Exit(m.Run())
}

// fakeKeys is an always-unlocked core.Keys with reversible "sealing". It
// also implements the key material hold that backup.create takes.
type fakeKeys struct {
	core.Keys
	state core.KeyState
	holds atomic.Int32 // holds currently open
	taken atomic.Int32 // holds taken so far
}

func (k *fakeKeys) HoldKeyMaterial() func() {
	k.holds.Add(1)
	k.taken.Add(1)
	var once sync.Once
	return func() { once.Do(func() { k.holds.Add(-1) }) }
}

func (k *fakeKeys) State() core.KeyState {
	if k.state == "" {
		return core.KeyStateUnlocked
	}
	return k.state
}

func (k *fakeKeys) SealField(aad string, pt []byte) (string, error) {
	return "v1:test:" + base64.RawURLEncoding.EncodeToString([]byte(aad+"\x00"+string(pt))), nil
}

func (k *fakeKeys) OpenField(aad, sealed string) ([]byte, error) {
	b, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(sealed, "v1:test:"))
	if err != nil {
		return nil, core.ErrCorrupt
	}
	a, pt, ok := strings.Cut(string(b), "\x00")
	if !ok || a != aad {
		return nil, core.ErrCorrupt
	}
	return []byte(pt), nil
}

func (k *fakeKeys) MAC(purpose string, data ...[]byte) []byte { return []byte("mac") }

// fakeAudit records entries in memory.
type fakeAudit struct {
	mu      sync.Mutex
	entries []core.AuditEntry
}

func (a *fakeAudit) Record(ctx context.Context, e core.AuditEntry) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.entries = append(a.entries, e)
}

func (a *fakeAudit) RecordTx(ctx context.Context, tx *sql.Tx, e core.AuditEntry) error {
	a.Record(ctx, e)
	return nil
}

func (a *fakeAudit) Query(context.Context, core.AuditQuery) (core.Page[core.AuditRecord], error) {
	return core.Page[core.AuditRecord]{}, nil
}
func (a *fakeAudit) Verify(context.Context) (*core.AuditVerify, error)                { return nil, nil }
func (a *fakeAudit) Export(context.Context, core.AuditQuery, string, io.Writer) error { return nil }
func (a *fakeAudit) Prune(context.Context, time.Time) (int, error)                    { return 0, nil }

func (a *fakeAudit) actions() []string {
	a.mu.Lock()
	defer a.mu.Unlock()
	var out []string
	for _, e := range a.entries {
		o := e.Outcome
		if o == "" {
			o = core.OutcomeSuccess
		}
		out = append(out, e.Action+":"+o)
	}
	return out
}

func (a *fakeAudit) has(action, outcome string) bool {
	for _, x := range a.actions() {
		if x == action+":"+outcome {
			return true
		}
	}
	return false
}

// testEnv is a home with a migrated database, real settings, fake keys and
// audit, a real jobs service and the backup service.
type testEnv struct {
	t     *testing.T
	h     *home.Home
	env   *core.Env
	audit *fakeAudit
	jobs  *jobs.Service
	svc   *Service
	bus   *events.Bus
	logs  *logCapture
}

// logCapture records the service's log records (discarding the text) so a
// test can assert at which level a message is written: in offline CLI mode
// warn-and-above reaches the console, so a routine success must not be a
// warning.
type logCapture struct {
	mu   sync.Mutex
	recs []slog.Record
}

func (c *logCapture) Enabled(context.Context, slog.Level) bool { return true }

func (c *logCapture) Handle(_ context.Context, r slog.Record) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.recs = append(c.recs, r.Clone())
	return nil
}

func (c *logCapture) WithAttrs([]slog.Attr) slog.Handler { return c }
func (c *logCapture) WithGroup(string) slog.Handler      { return c }

// records returns a copy of everything logged so far.
func (c *logCapture) records() []slog.Record {
	c.mu.Lock()
	defer c.mu.Unlock()
	return slices.Clone(c.recs)
}

// reset drops everything logged so far.
func (c *logCapture) reset() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.recs = nil
}

func newHome(t *testing.T) *home.Home {
	t.Helper()
	return newHomeAt(t, filepath.Join(t.TempDir(), "home"))
}

// newHomeAt is newHome in the directory dir.
func newHomeAt(t *testing.T, dir string) *home.Home {
	t.Helper()
	h, err := home.New(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := h.EnsureLayout(); err != nil {
		t.Fatal(err)
	}
	if err := config.Default(config.NewInstallID()).SaveTo(h.Config()); err != nil {
		t.Fatal(err)
	}
	// A plain master key file and a few certificate files.
	mustWrite(t, h.KeysFile(), []byte(`{"v":1,"mk_id":"mk_test","mode":"plain","key":"`+randHex(16)+`"}`))
	mustWrite(t, filepath.Join(h.CertsDir(), "ca", "ca.crt"), []byte("-----BEGIN CERTIFICATE-----\n"+randHex(40)+"\n"))
	mustWrite(t, filepath.Join(h.CertsDir(), "server", "leaf.key"), []byte("leaf-"+randHex(20)))
	mustWrite(t, filepath.Join(h.CertsDir(), "acme", "certificates", "acme-v02.api.letsencrypt.org-directory", "x.example", "x.example.crt"), []byte("acme"))
	return h
}

func newTestEnv(t *testing.T) *testEnv {
	return newTestEnvHome(t, newHome(t))
}

func newTestEnvHome(t *testing.T, h *home.Home) *testEnv {
	t.Helper()
	cfg, err := config.Load(h)
	if err != nil {
		t.Fatal(err)
	}
	d, err := db.Open(h.DB())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := d.Migrate(context.Background()); err != nil {
		t.Fatal(err)
	}
	// As on a real installation: the database names the master key that
	// keys/master.key holds (newHome writes mk_test).
	if _, err := d.Exec(context.Background(), `INSERT OR REPLACE INTO meta (key, value) VALUES ('mk_id', 'mk_test')`); err != nil {
		t.Fatal(err)
	}
	bus := events.New()
	te := &testEnv{t: t, h: h, audit: &fakeAudit{}, bus: bus, logs: &logCapture{}}
	te.env = &core.Env{Home: h, Config: cfg, DB: d, Log: slog.New(te.logs),
		Clock: core.SystemClock{}, Bus: bus, Keys: &fakeKeys{}, Audit: te.audit}
	te.env.Build.Version = "vtest"
	st, err := settings.New(te.env)
	if err != nil {
		t.Fatal(err)
	}
	te.env.Settings = st
	te.jobs, err = jobs.New(te.env)
	if err != nil {
		t.Fatal(err)
	}
	te.svc, err = New(te.env, nil, te.jobs)
	if err != nil {
		t.Fatal(err)
	}
	if err := te.svc.RegisterJobs(te.jobs); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { te.close() })
	return te
}

var closed sync.Map

func (te *testEnv) close() {
	if _, dup := closed.LoadOrStore(te, true); dup {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_ = te.jobs.Stop(ctx)
	_ = te.svc.Close()
	if c, ok := te.env.Settings.(io.Closer); ok {
		_ = c.Close()
	}
	te.bus.Close()
	_ = te.env.DB.Close()
}

func (te *testEnv) sys() *core.Principal { return core.SystemPrincipal(core.ViaOffline) }

func (te *testEnv) admin() *core.Principal {
	return &core.Principal{UserID: "usr_admin", Username: "admin", Role: core.RoleAdmin, Via: core.ViaSession, AuthLevel: 2}
}

func (te *testEnv) set(kv map[string]any) {
	te.t.Helper()
	ch := map[string]json.RawMessage{}
	for k, v := range kv {
		b, _ := json.Marshal(v)
		ch[k] = b
	}
	if _, err := te.env.Settings.Set(context.Background(), te.sys(), ch); err != nil {
		te.t.Fatal(err)
	}
}

// seedData adds a keyring row, n ready blobs (rows + files) and a meta row.
// It returns the blob contents by id.
func (te *testEnv) seedData(n int) map[string][]byte {
	te.t.Helper()
	ctx := context.Background()
	out := map[string][]byte{}
	err := te.env.DB.Tx(ctx, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, `INSERT OR IGNORE INTO keyring (id, purpose, mk_id, wrapped, state, created_at)
			VALUES ('kek_test', 'blob', 'mk_test', x'00', 'active', 1)`); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `INSERT OR REPLACE INTO meta (key, value) VALUES ('test_marker', 'before')`); err != nil {
			return err
		}
		for i := 0; i < n; i++ {
			id := randHex(16)
			data := make([]byte, 1000+i*777)
			_, _ = rand.Read(data)
			out[id] = data
			if _, err := tx.ExecContext(ctx, `INSERT INTO blobs (id, state, size, stored_size, cipher, kek_id, wrapped_dek, created_at)
				VALUES (?, 'ready', ?, ?, 1, 'kek_test', x'01', 1)`, id, len(data), len(data)); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		te.t.Fatal(err)
	}
	for id, data := range out {
		mustWrite(te.t, blobPath(te.h, id), data)
	}
	return out
}

func blobPath(h *home.Home, id string) string {
	return filepath.Join(h.BlobsDir(), id[0:2], id[2:4], id)
}

func mustWrite(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
}

func randHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return fmt.Sprintf("%x", b)
}

// fakeBlobStore verifies blobs against the expected contents.
type fakeBlobStore struct {
	core.BlobStore
	h    *home.Home
	want map[string][]byte
	mu   sync.Mutex
	seen []string
}

func (b *fakeBlobStore) Verify(ctx context.Context, id string) error {
	b.mu.Lock()
	b.seen = append(b.seen, id)
	b.mu.Unlock()
	got, err := os.ReadFile(blobPath(b.h, id))
	if err != nil {
		return err
	}
	if !bytes.Equal(got, b.want[id]) {
		return core.Errorf(core.ErrCorrupt, "blob %s corrupt", id)
	}
	return nil
}

// useFakeStores replaces openStores for the test.
func useFakeStores(t *testing.T, want map[string][]byte, state core.KeyState) *fakeBlobStore {
	t.Helper()
	fb := &fakeBlobStore{want: want}
	old := openStores
	openStores = func(env *core.Env) (core.Keys, core.BlobStore, func(), error) {
		fb.h = env.Home
		return &fakeKeys{state: state}, fb, func() {}, nil
	}
	t.Cleanup(func() { openStores = old })
	return fb
}

// tableDump returns the rows of a query as strings (for equality checks).
func tableDump(t *testing.T, q interface {
	Query(string, ...any) (*sql.Rows, error)
}, query string) []string {
	t.Helper()
	rows, err := q.Query(query)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	cols, _ := rows.Columns()
	var out []string
	for rows.Next() {
		vals := make([]any, len(cols))
		ptrs := make([]any, len(cols))
		for i := range vals {
			ptrs[i] = &vals[i]
		}
		if err := rows.Scan(ptrs...); err != nil {
			t.Fatal(err)
		}
		out = append(out, fmt.Sprint(vals...))
	}
	return out
}

func isCode(err error, base *core.Error) bool { return errors.Is(err, base) }
