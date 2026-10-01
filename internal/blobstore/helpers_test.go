package blobstore

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"io"
	"log/slog"
	"math/rand/v2"
	"sync"
	"syscall"
	"testing"
	"time"

	"fileparcel/internal/core"
	"fileparcel/internal/crypt"
	"fileparcel/internal/db"
	"fileparcel/internal/events"
	"fileparcel/internal/home"
	"fileparcel/internal/ids"
	"fileparcel/internal/keys"
)

var ctx = context.Background()

// ---------- fakes ----------

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
func (f *fakeSettings) Secret(string) (string, error)                       { return "", nil }
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

// lockedKeys wraps a real keys service and can pretend to be locked.
type lockedKeys struct {
	core.Keys
	locked bool
}

func (k *lockedKeys) State() core.KeyState {
	if k.locked {
		return core.KeyStateLocked
	}
	return k.Keys.State()
}

// ---------- environment ----------

type testStore struct {
	*Service
	env      *core.Env
	h        *home.Home
	db       *db.DB
	keys     *keys.Service
	settings *fakeSettings
	clock    *fakeClock
}

func newStore(t testing.TB) *testStore {
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
	if _, err := d.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	bus := events.New()
	t.Cleanup(bus.Close)
	ts := &testStore{h: h, db: d, settings: &fakeSettings{}, clock: &fakeClock{t: time.Now().UTC().Truncate(time.Millisecond)}}
	ts.env = &core.Env{Home: h, DB: d, Log: slog.New(slog.DiscardHandler), Clock: ts.clock, Bus: bus, Settings: ts.settings}
	ks, err := keys.Open(ts.env)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ks.Close() })
	if _, err := ks.Init(ctx, false, nil); err != nil {
		t.Fatal(err)
	}
	ts.keys = ks
	ts.env.Keys = ks
	s, err := New(ts.env)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	ts.Service = s
	return ts
}

// randData returns deterministic pseudo-random bytes.
func randData(n int64, seed uint64) []byte {
	r := rand.New(rand.NewPCG(seed, seed^0x9e3779b97f4a7c15))
	b := make([]byte, n)
	for i := 0; i < len(b); i += 8 {
		v := r.Uint64()
		for j := 0; j < 8 && i+j < len(b); j++ {
			b[i+j] = byte(v >> (8 * j))
		}
	}
	return b
}

// expectedHash computes the content hash independently.
func expectedHash(data []byte) string {
	var digests [][]byte
	for off := 0; off < len(data); off += core.PartSize {
		d := sha256.Sum256(data[off:min(off+core.PartSize, len(data))])
		digests = append(digests, d[:])
	}
	return HashOfDigests(digests)
}

// partDigests returns the SHA-256 of every part.
func partDigests(data []byte) [][]byte {
	var out [][]byte
	for off := 0; off < len(data); off += core.PartSize {
		d := sha256.Sum256(data[off:min(off+core.PartSize, len(data))])
		out = append(out, d[:])
	}
	return out
}

// putStream writes data with a streaming writer in irregular chunks.
func (ts *testStore) putStream(t testing.TB, data []byte) *core.BlobInfo {
	t.Helper()
	w, err := ts.Create(ctx)
	if err != nil {
		t.Fatal(err)
	}
	r := rand.New(rand.NewPCG(uint64(len(data)), 7))
	for off := 0; off < len(data); {
		n := min(len(data)-off, 1+r.IntN(3*segSize))
		if _, err := w.Write(data[off : off+n]); err != nil {
			t.Fatal(err)
		}
		off += n
	}
	info, err := w.Commit(ctx)
	if err != nil {
		t.Fatal(err)
	}
	return info
}

// putParted writes data as a parted blob, parts in order.
func (ts *testStore) putParted(t testing.TB, data []byte) *core.BlobInfo {
	t.Helper()
	p, err := ts.CreateParted(ctx, int64(len(data)))
	if err != nil {
		t.Fatal(err)
	}
	var digests [][]byte
	for n := range p.PartCount() {
		part := data[n*core.PartSize : min((n+1)*core.PartSize, len(data))]
		want := sha256.Sum256(part)
		got, err := p.WritePart(ctx, n, bytes.NewReader(part), want[:])
		if err != nil {
			t.Fatal(err)
		}
		digests = append(digests, got)
	}
	info, err := p.Commit(ctx, digests)
	if err != nil {
		t.Fatal(err)
	}
	return info
}

// readAll reads a blob completely.
func (ts *testStore) readAll(t testing.TB, id string) ([]byte, error) {
	t.Helper()
	r, err := ts.Open(ctx, id)
	if err != nil {
		return nil, err
	}
	defer r.Close()
	return io.ReadAll(r)
}

func (ts *testStore) exec(t testing.TB, q string, args ...any) {
	t.Helper()
	if _, err := ts.db.Exec(ctx, q, args...); err != nil {
		t.Fatalf("%s: %v", q, err)
	}
}

func (ts *testStore) count(t testing.TB, q string, args ...any) int64 {
	t.Helper()
	var n int64
	if err := ts.db.QueryRow(ctx, q, args...).Scan(&n); err != nil {
		t.Fatalf("%s: %v", q, err)
	}
	return n
}

func (ts *testStore) state(t testing.TB, id string) string {
	t.Helper()
	var s sql.NullString
	err := ts.db.QueryRow(ctx, `SELECT state FROM blobs WHERE id = ?`, id).Scan(&s)
	if db.IsNoRows(err) {
		return ""
	}
	if err != nil {
		t.Fatal(err)
	}
	return s.String
}

// reference makes a file version point at blobID (user/space/node fixture).
func (ts *testStore) reference(t testing.TB, blobID string) (nodeID string) {
	t.Helper()
	now := db.Ms(ts.clock.Now())
	user, space := ids.New(ids.PrefixUser), ids.New(ids.PrefixSpace)
	nodeID = ids.New(ids.PrefixNode)
	ts.exec(t, `INSERT INTO users (id, username, role, webauthn_handle, created_at, updated_at) VALUES (?, ?, 'member', ?, ?, ?)`,
		user, user, crypt.RandomBytes(16), now, now)
	ts.exec(t, `INSERT INTO spaces (id, kind, owner_user_id, name, created_at) VALUES (?, 'user', ?, 'x', ?)`, space, user, now)
	ts.exec(t, `INSERT INTO nodes (id, space_id, kind, name, name_key, created_at, updated_at) VALUES (?, ?, 'file', 'f', 'f', ?, ?)`,
		nodeID, space, now, now)
	if blobID != "" {
		ts.exec(t, `INSERT INTO file_versions (id, node_id, blob_id, size, created_at) VALUES (?, ?, ?, 0, ?)`,
			ids.New(ids.PrefixVersion), nodeID, blobID, now)
	}
	return nodeID
}

// contextWithCancel returns a cancelable child of the test context.
func contextWithCancel() (context.Context, context.CancelFunc) {
	return context.WithCancel(ctx)
}

// errNoSpace is the "disk full" errno.
func errNoSpace() error { return syscall.ENOSPC }

func isErr(err error, target *core.Error) bool {
	ce := core.AsError(err)
	return ce != nil && ce.Code == target.Code
}

func errIs(t testing.TB, err error, target *core.Error, what string) {
	t.Helper()
	if !isErr(err, target) {
		t.Fatalf("%s: got %v, want %s", what, err, target.Code)
	}
}
