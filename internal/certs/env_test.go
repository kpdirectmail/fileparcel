package certs

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/netip"
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
	"fileparcel/internal/settings"
)

// ---------- fake keys ----------

type fakeKeys struct {
	state atomic.Value // core.KeyState
	aead  cipher.AEAD

	fieldMu sync.Mutex
	// sealedFields keeps the plaintext slices SealField was handed, by
	// reference (never a copy), so tests can assert the caller zeroed them.
	sealedFields [][]byte
}

// sealedFieldsSnapshot returns the plaintext slices of every SealField call.
func (k *fakeKeys) sealedFieldsSnapshot() [][]byte {
	k.fieldMu.Lock()
	defer k.fieldMu.Unlock()
	return append([][]byte(nil), k.sealedFields...)
}

// lastSealedField returns the plaintext slice of the last SealField call.
func (k *fakeKeys) lastSealedField() []byte {
	k.fieldMu.Lock()
	defer k.fieldMu.Unlock()
	if len(k.sealedFields) == 0 {
		return nil
	}
	return k.sealedFields[len(k.sealedFields)-1]
}

func newFakeKeys() *fakeKeys {
	key := make([]byte, 32)
	_, _ = rand.Read(key)
	blk, _ := aes.NewCipher(key)
	g, _ := cipher.NewGCM(blk)
	k := &fakeKeys{aead: g}
	k.state.Store(core.KeyStateUnlocked)
	return k
}

func (k *fakeKeys) setState(s core.KeyState) { k.state.Store(s) }
func (k *fakeKeys) State() core.KeyState     { return k.state.Load().(core.KeyState) }
func (k *fakeKeys) Init(context.Context, bool, []byte) (string, error) {
	return "", core.ErrNotImplemented
}
func (k *fakeKeys) Unlock(context.Context, []byte) error { return core.ErrNotImplemented }
func (k *fakeKeys) Lock(context.Context) error           { return core.ErrNotImplemented }
func (k *fakeKeys) Status(context.Context) (*core.KeyStatus, error) {
	return &core.KeyStatus{State: k.State()}, nil
}
func (k *fakeKeys) NewDEK([]byte) ([]byte, []byte, string, error) {
	return nil, nil, "", core.ErrNotImplemented
}
func (k *fakeKeys) UnwrapDEK([]byte, string, []byte) ([]byte, error) {
	return nil, core.ErrNotImplemented
}
func (k *fakeKeys) SealField(aad string, pt []byte) (string, error) {
	if k.State() != core.KeyStateUnlocked {
		return "", core.ErrKeysLocked
	}
	k.fieldMu.Lock()
	k.sealedFields = append(k.sealedFields, pt)
	k.fieldMu.Unlock()
	nonce := make([]byte, k.aead.NonceSize())
	_, _ = rand.Read(nonce)
	ct := k.aead.Seal(nonce, nonce, pt, []byte(aad))
	return "v1:kek_test:" + base64.RawURLEncoding.EncodeToString(ct), nil
}
func (k *fakeKeys) OpenField(aad, sealed string) ([]byte, error) {
	if k.State() != core.KeyStateUnlocked {
		return nil, core.ErrKeysLocked
	}
	rest, ok := strings.CutPrefix(sealed, "v1:kek_test:")
	if !ok {
		return nil, core.ErrCorrupt
	}
	b, err := base64.RawURLEncoding.DecodeString(rest)
	if err != nil || len(b) < k.aead.NonceSize() {
		return nil, core.ErrCorrupt
	}
	pt, err := k.aead.Open(nil, b[:k.aead.NonceSize()], b[k.aead.NonceSize():], []byte(aad))
	if err != nil {
		return nil, core.ErrCorrupt
	}
	return pt, nil
}
func (k *fakeKeys) MAC(string, ...[]byte) []byte         { return nil }
func (k *fakeKeys) Seal(context.Context, []byte) error   { return core.ErrNotImplemented }
func (k *fakeKeys) Unseal(context.Context, []byte) error { return core.ErrNotImplemented }
func (k *fakeKeys) ChangePassphrase(context.Context, []byte, []byte) error {
	return core.ErrNotImplemented
}
func (k *fakeKeys) RotateKEK(context.Context, string, func(int64, int64)) error { return nil }
func (k *fakeKeys) RotateMaster(context.Context) error                          { return nil }
func (k *fakeKeys) ExportRecovery(context.Context) (string, error)              { return "", core.ErrNotImplemented }
func (k *fakeKeys) Cipher() core.CipherID                                       { return core.CipherAES256GCM }

// ---------- fake settings ----------

type fakeSettings struct {
	mu      sync.Mutex
	m       map[string]any
	secrets int // Secret() calls (ACME credential reads)
	locked  bool
}

// secretReads returns how often Secret was called.
func (s *fakeSettings) secretReads() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.secrets
}

// lockSecrets makes Secret fail like a sealed server does.
func (s *fakeSettings) lockSecrets(v bool) {
	s.mu.Lock()
	s.locked = v
	s.mu.Unlock()
}

func newFakeSettings() *fakeSettings { return &fakeSettings{m: map[string]any{}} }

func (s *fakeSettings) set(key string, v any) {
	s.mu.Lock()
	s.m[key] = v
	s.mu.Unlock()
}

func (s *fakeSettings) value(key string) (any, bool) {
	s.mu.Lock()
	v, ok := s.m[key]
	s.mu.Unlock()
	if ok {
		return v, true
	}
	if d, ok := settings.Lookup(key); ok {
		return d.Default, true
	}
	return nil, false
}

func (s *fakeSettings) Raw(key string) (json.RawMessage, error) {
	v, ok := s.value(key)
	if !ok {
		return nil, core.ErrNotFound
	}
	return json.Marshal(v)
}
func (s *fakeSettings) Int(key string) int64 {
	v, _ := s.value(key)
	switch n := v.(type) {
	case int:
		return int64(n)
	case int64:
		return n
	}
	return 0
}
func (s *fakeSettings) Bool(key string) bool     { v, _ := s.value(key); b, _ := v.(bool); return b }
func (s *fakeSettings) String(key string) string { v, _ := s.value(key); x, _ := v.(string); return x }
func (s *fakeSettings) Strings(key string) []string {
	v, _ := s.value(key)
	x, _ := v.([]string)
	return x
}
func (s *fakeSettings) Duration(string) time.Duration { return 0 }
func (s *fakeSettings) Secret(key string) (string, error) {
	s.mu.Lock()
	s.secrets++
	locked := s.locked
	s.mu.Unlock()
	if locked {
		return "", core.ErrKeysLocked
	}
	return s.String(key), nil
}
func (s *fakeSettings) Set(context.Context, *core.Principal, map[string]json.RawMessage) (*core.SettingsResult, error) {
	return nil, core.ErrNotImplemented
}
func (s *fakeSettings) Reset(context.Context, *core.Principal, string) error { return nil }
func (s *fakeSettings) Catalog(context.Context) ([]core.SettingView, error) {
	return nil, core.ErrNotImplemented
}

// ---------- fake audit ----------

type fakeAudit struct {
	mu      sync.Mutex
	entries []core.AuditEntry
}

func (a *fakeAudit) Record(_ context.Context, e core.AuditEntry) {
	a.mu.Lock()
	a.entries = append(a.entries, e)
	a.mu.Unlock()
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

// actions returns the recorded "action/outcome" pairs.
func (a *fakeAudit) find(action string) []core.AuditEntry {
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

// ---------- fake network ----------

type fakeNet struct {
	mu    sync.Mutex
	names []string
	ips   []netip.Addr
	ts    *core.TailscaleInfo
}

func (n *fakeNet) Interfaces(context.Context) ([]core.NetInterface, error) { return nil, nil }
func (n *fakeNet) URLs(context.Context) ([]core.AccessURL, error)          { return nil, nil }
func (n *fakeNet) Allowed(netip.Addr) bool                                 { return true }
func (n *fakeNet) Policy() core.AccessPolicy                               { return core.AccessPolicy{} }
func (n *fakeNet) SetPolicy(context.Context, *core.Principal, core.AccessPolicy, netip.Addr, bool) ([]string, error) {
	return nil, nil
}
func (n *fakeNet) CheckPolicy(core.AccessPolicy, netip.Addr) (bool, error) { return true, nil }
func (n *fakeNet) IsLocal(netip.Addr) bool                                 { return false }
func (n *fakeNet) Hostnames() []string {
	n.mu.Lock()
	defer n.mu.Unlock()
	return append([]string(nil), n.names...)
}
func (n *fakeNet) IPs() []netip.Addr {
	n.mu.Lock()
	defer n.mu.Unlock()
	return append([]netip.Addr(nil), n.ips...)
}
func (n *fakeNet) setNames(names ...string) {
	n.mu.Lock()
	n.names = names
	n.mu.Unlock()
}
func (n *fakeNet) Tailscale(context.Context) (*core.TailscaleInfo, error) {
	if n.ts == nil {
		return nil, errors.New("not running")
	}
	return n.ts, nil
}
func (n *fakeNet) Start(context.Context) error { return nil }

// ---------- environment ----------

type testClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *testClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *testClock) add(d time.Duration) {
	c.mu.Lock()
	c.now = c.now.Add(d)
	c.mu.Unlock()
}

type testEnv struct {
	env      *core.Env
	keys     *fakeKeys
	settings *fakeSettings
	audit    *fakeAudit
	net      *fakeNet
	clock    *testClock
}

func newTestEnv(t *testing.T) *testEnv {
	t.Helper()
	h, err := home.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := h.EnsureLayout(); err != nil {
		t.Fatal(err)
	}
	cfg := config.Default("0123456789abcdef0123456789abcdef")
	database, err := db.Open(h.DB())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := database.Migrate(context.Background()); err != nil {
		t.Fatal(err)
	}
	bus := events.New()
	t.Cleanup(func() {
		bus.Close()
		database.Close()
	})
	te := &testEnv{
		keys:     newFakeKeys(),
		settings: newFakeSettings(),
		audit:    &fakeAudit{},
		net: &fakeNet{
			names: []string{"fileparcel.local", "myhost.local", "files.tail1234.ts.net"},
			ips:   []netip.Addr{netip.MustParseAddr("192.168.1.10"), netip.MustParseAddr("100.64.0.10"), netip.MustParseAddr("fd7a:115c:a1e0::1")},
		},
		clock: &testClock{now: time.Now().UTC().Truncate(time.Second)}, // real time: TLS clients verify with it
	}
	te.env = &core.Env{
		Home: h, Config: cfg, DB: database, Log: slog.New(slog.DiscardHandler), Clock: te.clock, Bus: bus,
		Keys: te.keys, Settings: te.settings, Audit: te.audit,
	}
	return te
}

// service builds a Service over te (New).
func (te *testEnv) service(t *testing.T) *Service {
	t.Helper()
	svc, err := New(te.env, te.net)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = svc.Close() })
	return svc
}

// initService builds a Service and runs Init.
func (te *testEnv) initService(t *testing.T) *Service {
	t.Helper()
	svc := te.service(t)
	if err := svc.Init(context.Background()); err != nil {
		t.Fatal(err)
	}
	return svc
}

// addUser inserts a users row.
func (te *testEnv) addUser(t *testing.T, id, username, status string) {
	t.Helper()
	now := db.Ms(te.clock.Now())
	err := te.env.DB.Tx(context.Background(), func(tx *sql.Tx) error {
		_, err := tx.Exec(`INSERT INTO users (id, username, role, status, webauthn_handle, created_at, updated_at)
			VALUES (?, ?, 'member', ?, ?, ?, ?)`, id, username, status, []byte(id), now, now)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
}
