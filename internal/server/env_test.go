package server

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"fileparcel/internal/app"
	"fileparcel/internal/certs"
	"fileparcel/internal/config"
	"fileparcel/internal/core"
	"fileparcel/internal/db"
	"fileparcel/internal/events"
	"fileparcel/internal/home"
	"fileparcel/internal/settings"
)

// fakeKeys implements field sealing for the certificate service.
type fakeKeys struct{ aead cipher.AEAD }

func newFakeKeys() *fakeKeys {
	key := make([]byte, 32)
	_, _ = rand.Read(key)
	blk, _ := aes.NewCipher(key)
	g, _ := cipher.NewGCM(blk)
	return &fakeKeys{aead: g}
}

func (k *fakeKeys) State() core.KeyState                               { return core.KeyStateUnlocked }
func (k *fakeKeys) Init(context.Context, bool, []byte) (string, error) { return "", nil }
func (k *fakeKeys) Unlock(context.Context, []byte) error               { return nil }
func (k *fakeKeys) Lock(context.Context) error                         { return nil }
func (k *fakeKeys) Status(context.Context) (*core.KeyStatus, error)    { return &core.KeyStatus{}, nil }
func (k *fakeKeys) NewDEK([]byte) ([]byte, []byte, string, error)      { return nil, nil, "", nil }
func (k *fakeKeys) UnwrapDEK([]byte, string, []byte) ([]byte, error)   { return nil, nil }
func (k *fakeKeys) SealField(aad string, pt []byte) (string, error) {
	nonce := make([]byte, k.aead.NonceSize())
	_, _ = rand.Read(nonce)
	return "v1:t:" + base64.RawURLEncoding.EncodeToString(k.aead.Seal(nonce, nonce, pt, []byte(aad))), nil
}
func (k *fakeKeys) OpenField(aad, sealed string) ([]byte, error) {
	b, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(sealed, "v1:t:"))
	if err != nil || len(b) < k.aead.NonceSize() {
		return nil, core.ErrCorrupt
	}
	return k.aead.Open(nil, b[:k.aead.NonceSize()], b[k.aead.NonceSize():], []byte(aad))
}
func (k *fakeKeys) MAC(string, ...[]byte) []byte                                { return nil }
func (k *fakeKeys) Seal(context.Context, []byte) error                          { return nil }
func (k *fakeKeys) Unseal(context.Context, []byte) error                        { return nil }
func (k *fakeKeys) ChangePassphrase(context.Context, []byte, []byte) error      { return nil }
func (k *fakeKeys) RotateKEK(context.Context, string, func(int64, int64)) error { return nil }
func (k *fakeKeys) RotateMaster(context.Context) error                          { return nil }
func (k *fakeKeys) ExportRecovery(context.Context) (string, error)              { return "", nil }
func (k *fakeKeys) Cipher() core.CipherID                                       { return core.CipherAES256GCM }

// fakeSettings serves registered defaults plus overrides.
type fakeSettings struct {
	mu sync.Mutex
	m  map[string]any
}

func (s *fakeSettings) set(k string, v any) { s.mu.Lock(); s.m[k] = v; s.mu.Unlock() }
func (s *fakeSettings) value(k string) any {
	s.mu.Lock()
	v, ok := s.m[k]
	s.mu.Unlock()
	if ok {
		return v
	}
	if d, ok := settings.Lookup(k); ok {
		return d.Default
	}
	return nil
}
func (s *fakeSettings) Raw(k string) (json.RawMessage, error) {
	v := s.value(k)
	if v == nil {
		return nil, core.ErrNotFound
	}
	return json.Marshal(v)
}
func (s *fakeSettings) Int(k string) int64 {
	switch n := s.value(k).(type) {
	case int:
		return int64(n)
	case int64:
		return n
	}
	return 0
}
func (s *fakeSettings) Bool(k string) bool                                   { b, _ := s.value(k).(bool); return b }
func (s *fakeSettings) String(k string) string                               { x, _ := s.value(k).(string); return x }
func (s *fakeSettings) Strings(k string) []string                            { x, _ := s.value(k).([]string); return x }
func (s *fakeSettings) Duration(string) time.Duration                        { return 0 }
func (s *fakeSettings) Secret(k string) (string, error)                      { return s.String(k), nil }
func (s *fakeSettings) Reset(context.Context, *core.Principal, string) error { return nil }
func (s *fakeSettings) Set(context.Context, *core.Principal, map[string]json.RawMessage) (*core.SettingsResult, error) {
	return nil, nil
}
func (s *fakeSettings) Catalog(context.Context) ([]core.SettingView, error) { return nil, nil }

// fakeAudit records entries.
type fakeAudit struct {
	mu      sync.Mutex
	actions []string
}

func (a *fakeAudit) Record(_ context.Context, e core.AuditEntry) {
	a.mu.Lock()
	a.actions = append(a.actions, e.Action)
	a.mu.Unlock()
}
func (a *fakeAudit) RecordTx(ctx context.Context, _ *sql.Tx, e core.AuditEntry) error {
	a.Record(ctx, e)
	return nil
}
func (a *fakeAudit) Query(context.Context, core.AuditQuery) (core.Page[core.AuditRecord], error) {
	return core.Page[core.AuditRecord]{}, nil
}
func (a *fakeAudit) Verify(context.Context) (*core.AuditVerify, error)                { return nil, nil }
func (a *fakeAudit) Export(context.Context, core.AuditQuery, string, io.Writer) error { return nil }
func (a *fakeAudit) Prune(context.Context, time.Time) (int, error)                    { return 0, nil }
func (a *fakeAudit) has(action string) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	for _, x := range a.actions {
		if x == action {
			return true
		}
	}
	return false
}

// fakeNet controls the allowlist.
type fakeNet struct{ deny atomic.Bool }

func (n *fakeNet) Interfaces(context.Context) ([]core.NetInterface, error) { return nil, nil }
func (n *fakeNet) URLs(context.Context) ([]core.AccessURL, error) {
	return []core.AccessURL{{URL: "https://127.0.0.1:1/", Kind: core.URLKindIP}}, nil
}
func (n *fakeNet) Allowed(ip netip.Addr) bool {
	if ip.Is4In6() {
		panic("allowlist called with an IPv4-mapped address")
	}
	return !n.deny.Load()
}
func (n *fakeNet) Policy() core.AccessPolicy { return core.AccessPolicy{} }
func (n *fakeNet) SetPolicy(context.Context, *core.Principal, core.AccessPolicy, netip.Addr, bool) ([]string, error) {
	return nil, nil
}
func (n *fakeNet) CheckPolicy(core.AccessPolicy, netip.Addr) (bool, error) { return true, nil }
func (n *fakeNet) IsLocal(netip.Addr) bool                                 { return false }
func (n *fakeNet) Hostnames() []string                                     { return []string{"fileparcel.local"} }
func (n *fakeNet) IPs() []netip.Addr                                       { return nil }
func (n *fakeNet) Tailscale(context.Context) (*core.TailscaleInfo, error)  { return nil, nil }
func (n *fakeNet) Start(context.Context) error                             { return nil }

type testDeps struct {
	d        *app.Deps
	net      *fakeNet
	settings *fakeSettings
	audit    *fakeAudit
	certs    *certs.Service
}

// freePort returns a currently unused TCP port on 127.0.0.1.
func freePort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	return ln.Addr().(*net.TCPAddr).Port
}

// newDeps builds services for Run on 127.0.0.1 with free ports.
func newDeps(t *testing.T) *testDeps {
	t.Helper()
	dir, err := shortTempDir(t)
	if err != nil {
		t.Fatal(err)
	}
	h, err := home.New(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := h.EnsureLayout(); err != nil {
		t.Fatal(err)
	}
	cfg := config.Default("fedcba9876543210fedcba9876543210")
	cfg.Server.Bind = []string{"127.0.0.1"}
	cfg.Server.HTTPSPort = freePort(t)
	cfg.Server.HTTPPort = freePort(t)
	cfg.Server.SamePortRedirect = true
	database, err := db.Open(h.DB())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := database.Migrate(context.Background()); err != nil {
		t.Fatal(err)
	}
	bus := events.New()
	t.Cleanup(func() { bus.Close(); database.Close() })
	td := &testDeps{net: &fakeNet{}, settings: &fakeSettings{m: map[string]any{}}, audit: &fakeAudit{}}
	env := &core.Env{Home: h, Config: cfg, DB: database, Log: slog.New(slog.DiscardHandler), Clock: core.SystemClock{},
		Bus: bus, Keys: newFakeKeys(), Settings: td.settings, Audit: td.audit}
	cs, err := certs.New(env, td.net)
	if err != nil {
		t.Fatal(err)
	}
	if err := cs.Init(context.Background()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cs.Close() })
	td.certs = cs
	td.d = &app.Deps{Env: env, Mode: app.ModeNetwork, Certs: cs, Network: td.net}
	return td
}

// shortTempDir returns a temporary directory with a short path (the admin
// socket must fit sun_path in the default case).
func shortTempDir(t *testing.T) (string, error) {
	t.Helper()
	dir, err := os.MkdirTemp("", "fps")
	if err != nil {
		return "", err
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return dir, nil
}
