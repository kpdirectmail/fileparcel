package audit

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"fileparcel/internal/core"
	"fileparcel/internal/crypt"
	"fileparcel/internal/db"
	"fileparcel/internal/events"
	"fileparcel/internal/home"
)

// fakeKeys is a core.Keys whose MAC works only while "unlocked".
type fakeKeys struct {
	unlocked atomic.Bool
	headFail atomic.Bool // MAC("audit.head") unavailable (key lost mid-insert)
	key      []byte
}

func newFakeKeys(unlocked bool) *fakeKeys {
	k := &fakeKeys{key: crypt.RandomBytes(32)}
	k.unlocked.Store(unlocked)
	return k
}

func (k *fakeKeys) State() core.KeyState {
	if k.unlocked.Load() {
		return core.KeyStateUnlocked
	}
	return core.KeyStateLocked
}
func (k *fakeKeys) MAC(purpose string, data ...[]byte) []byte {
	if !k.unlocked.Load() || (purpose == purposeHead && k.headFail.Load()) {
		return nil
	}
	return crypt.HMAC(k.key, append([][]byte{[]byte("fp-mac|" + purpose)}, data...)...)
}
func (k *fakeKeys) Init(context.Context, bool, []byte) (string, error) {
	return "", core.ErrNotImplemented
}
func (k *fakeKeys) Unlock(context.Context, []byte) error { return core.ErrNotImplemented }
func (k *fakeKeys) Lock(context.Context) error           { return core.ErrNotImplemented }
func (k *fakeKeys) Status(context.Context) (*core.KeyStatus, error) {
	return nil, core.ErrNotImplemented
}
func (k *fakeKeys) NewDEK([]byte) ([]byte, []byte, string, error) {
	return nil, nil, "", core.ErrNotImplemented
}
func (k *fakeKeys) UnwrapDEK([]byte, string, []byte) ([]byte, error) {
	return nil, core.ErrNotImplemented
}
func (k *fakeKeys) SealField(string, []byte) (string, error) { return "", core.ErrNotImplemented }
func (k *fakeKeys) OpenField(string, string) ([]byte, error) { return nil, core.ErrNotImplemented }
func (k *fakeKeys) Seal(context.Context, []byte) error       { return core.ErrNotImplemented }
func (k *fakeKeys) Unseal(context.Context, []byte) error     { return core.ErrNotImplemented }
func (k *fakeKeys) ChangePassphrase(context.Context, []byte, []byte) error {
	return core.ErrNotImplemented
}
func (k *fakeKeys) RotateKEK(context.Context, string, func(int64, int64)) error {
	return core.ErrNotImplemented
}
func (k *fakeKeys) RotateMaster(context.Context) error             { return core.ErrNotImplemented }
func (k *fakeKeys) ExportRecovery(context.Context) (string, error) { return "", core.ErrNotImplemented }
func (k *fakeKeys) Cipher() core.CipherID                          { return core.CipherAES256GCM }

// fakeSettings is a map-backed core.Settings.
type fakeSettings struct {
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
func (f *fakeSettings) Raw(k string) (json.RawMessage, error) { return json.Marshal(f.get(k)) }
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
func (f *fakeSettings) Duration(k string) time.Duration {
	d, _ := f.get(k).(time.Duration)
	return d
}
func (f *fakeSettings) Secret(k string) (string, error) { return f.String(k), nil }
func (f *fakeSettings) Set(context.Context, *core.Principal, map[string]json.RawMessage) (*core.SettingsResult, error) {
	return nil, core.ErrNotImplemented
}
func (f *fakeSettings) Reset(context.Context, *core.Principal, string) error {
	return core.ErrNotImplemented
}
func (f *fakeSettings) Catalog(context.Context) ([]core.SettingView, error) {
	return nil, core.ErrNotImplemented
}

// testClock is a settable clock.
type testClock struct{ ms atomic.Int64 }

func (c *testClock) Now() time.Time          { return time.UnixMilli(c.ms.Load()).UTC() }
func (c *testClock) Set(t time.Time)         { c.ms.Store(t.UnixMilli()) }
func (c *testClock) Advance(d time.Duration) { c.ms.Add(d.Milliseconds()) }

type testEnv struct {
	env      *core.Env
	keys     *fakeKeys
	settings *fakeSettings
	clock    *testClock
	svc      *Service
}

// newTestEnv builds a migrated database in a temp home and an audit service.
func newTestEnv(t *testing.T, unlocked bool) *testEnv {
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
	te := &testEnv{keys: newFakeKeys(unlocked), settings: &fakeSettings{m: map[string]any{}}, clock: clock}
	bus := events.New()
	te.env = &core.Env{
		Home: h, DB: d, Clock: clock, Bus: bus,
		Log:  slog.New(slog.NewTextHandler(io.Discard, nil)),
		Keys: te.keys, Settings: te.settings,
	}
	te.svc, err = New(te.env)
	if err != nil {
		t.Fatal(err)
	}
	te.env.Audit = te.svc
	t.Cleanup(func() {
		_ = te.svc.Close()
		bus.Close()
		_ = d.Close()
	})
	return te
}

// ctxAs returns a context carrying a principal.
func ctxAs(userID, username string) context.Context {
	return core.WithPrincipal(context.Background(), &core.Principal{
		UserID: userID, Username: username, Role: core.RoleMember, Via: core.ViaSession, AuthLevel: 2,
		UserAgent: "test-agent", RequestID: "req-1",
	})
}

func (te *testEnv) record(t *testing.T, n int, action string) {
	t.Helper()
	for i := 0; i < n; i++ {
		te.svc.Record(ctxAs("usr_a", "alice"), core.AuditEntry{Action: action, TargetType: "node", TargetID: "nod_x", Details: map[string]int{"i": i}})
		te.clock.Advance(time.Second)
	}
}

func (te *testEnv) verify(t *testing.T) *core.AuditVerify {
	t.Helper()
	v, err := te.svc.Verify(context.Background())
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	return v
}

func (te *testEnv) exec(t *testing.T, q string, args ...any) {
	t.Helper()
	if _, err := te.env.DB.Exec(context.Background(), q, args...); err != nil {
		t.Fatalf("exec %q: %v", q, err)
	}
}

func (te *testEnv) meta(t *testing.T, key string) (string, bool) {
	t.Helper()
	v, ok, err := getMeta(context.Background(), te.env.DB.Reader(), key)
	if err != nil {
		t.Fatal(err)
	}
	return v, ok
}

func (te *testEnv) count(t *testing.T) int {
	t.Helper()
	var n int
	if err := te.env.DB.QueryRow(context.Background(), `SELECT count(*) FROM audit_log`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

// waitFor polls cond for up to 5 s.
func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timeout waiting for %s", what)
		}
		time.Sleep(10 * time.Millisecond)
	}
}
