package settings

import (
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
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
	"fileparcel/internal/logx"
)

// Test-only keys (prefix "sttest.", never catalog keys).
func init() {
	Register(Def{Key: "sttest.count", Section: "storage", Order: 1, Type: TypeInt, Default: 30, Min: 0, Max: 100,
		Label: "Count", Description: "A bounded int"})
	Register(Def{Key: "sttest.mode", Section: "storage", Order: 2, Type: TypeEnum, Default: "a", Enum: []string{"a", "b", "c"}})
	Register(Def{Key: "sttest.list", Section: "storage", Order: 3, Type: TypeStrings, Default: []string{}})
	Register(Def{Key: "sttest.every", Section: "storage", Order: 4, Type: TypeDuration, Default: "15m"})
	Register(Def{Key: "sttest.even", Section: "storage", Order: 5, Type: TypeInt, Default: 2, Validate: func(v any) error {
		if v.(int64)%2 != 0 {
			return errors.New("must be even")
		}
		return nil
	}})
	Register(Def{Key: "sttest.flag", Section: "storage", Order: 6, Type: TypeBool, Default: false})
	Register(Def{Key: "sttest.port", Section: "storage", Order: 7, Type: TypeInt, Default: 1, Min: 1, Max: 65535, Restart: true})
	Register(Def{Key: "sttest.password", Section: "email", Order: 8, Type: TypeSecret, Default: ""})
	Register(Def{Key: "sttest.token", Section: "email", Order: 9, Type: TypeSecret, Default: ""})
}

// ---------- fakes ----------

// fakeKeys seals fields reversibly, binding the AAD, and can be locked.
type fakeKeys struct {
	core.Keys
	locked atomic.Bool
}

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
	return "v1:test:" + base64.RawURLEncoding.EncodeToString(append([]byte(aad+"\x00"), pt...)), nil
}

func (k *fakeKeys) OpenField(aad, sealed string) ([]byte, error) {
	if k.locked.Load() {
		return nil, core.ErrKeysLocked
	}
	b, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(sealed, "v1:test:"))
	if err != nil {
		return nil, core.ErrCorrupt
	}
	pre := []byte(aad + "\x00")
	if len(b) < len(pre) || string(b[:len(pre)]) != string(pre) {
		return nil, core.ErrCorrupt
	}
	return b[len(pre):], nil
}

// fakeAudit records entries; RecordTx requires a transaction.
type fakeAudit struct {
	mu      sync.Mutex
	entries []core.AuditEntry
}

func (a *fakeAudit) Record(ctx context.Context, e core.AuditEntry) {
	if p := core.PrincipalFrom(ctx); p != nil && e.ActorName == "" {
		e.ActorName = p.Username
	}
	a.mu.Lock()
	a.entries = append(a.entries, e)
	a.mu.Unlock()
}

func (a *fakeAudit) RecordTx(ctx context.Context, tx *sql.Tx, e core.AuditEntry) error {
	if tx == nil {
		return errors.New("no tx")
	}
	a.Record(ctx, e)
	return nil
}

func (a *fakeAudit) Query(context.Context, core.AuditQuery) (core.Page[core.AuditRecord], error) {
	return core.Page[core.AuditRecord]{}, nil
}
func (a *fakeAudit) Verify(context.Context) (*core.AuditVerify, error)                { return nil, nil }
func (a *fakeAudit) Export(context.Context, core.AuditQuery, string, io.Writer) error { return nil }
func (a *fakeAudit) Prune(context.Context, time.Time) (int, error)                    { return 0, nil }

func (a *fakeAudit) count() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return len(a.entries)
}

func (a *fakeAudit) last() core.AuditEntry {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.entries[len(a.entries)-1]
}

func (a *fakeAudit) all() []core.AuditEntry {
	a.mu.Lock()
	defer a.mu.Unlock()
	return slices.Clone(a.entries)
}

// fixture is a store over a real migrated database and a real config file.
type fixture struct {
	env   *core.Env
	store *Service
	keys  *fakeKeys
	audit *fakeAudit
	dir   string
	ch    <-chan events.Event
}

func newFixture(t *testing.T, lookupEnv func(string) (string, bool)) *fixture {
	t.Helper()
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "fileparcel.toml")
	if err := config.Default(config.NewInstallID()).SaveTo(cfgPath); err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(cfgPath)
	cfg, err := config.Parse(data)
	if err != nil {
		t.Fatal(err)
	}
	if lookupEnv == nil {
		lookupEnv = func(string) (string, bool) { return "", false }
	}
	if err := cfg.ApplyEnv(lookupEnv); err != nil {
		t.Fatal(err)
	}
	if err := cfg.SaveTo(cfgPath); err != nil { // sets the path
		t.Fatal(err)
	}
	database, err := db.Open(filepath.Join(dir, "fp.db"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := database.Migrate(context.Background()); err != nil {
		t.Fatal(err)
	}
	f := &fixture{dir: dir, keys: &fakeKeys{}, audit: &fakeAudit{}}
	f.env = &core.Env{Config: cfg, DB: database, Bus: events.New(), Clock: core.SystemClock{}, Keys: f.keys, Audit: f.audit}
	ch, unsub := f.env.Bus.Subscribe(events.TopicSettingsChanged)
	f.ch = ch
	f.store, err = New(f.env)
	if err != nil {
		t.Fatal(err)
	}
	f.env.Settings = f.store
	t.Cleanup(func() {
		_ = f.store.Close()
		unsub()
		f.env.Bus.Close()
		_ = database.Close()
		_ = logx.SetLevel("info")
	})
	return f
}

func (f *fixture) set(t *testing.T, kv map[string]string) (*core.SettingsResult, error) {
	t.Helper()
	changes := map[string]json.RawMessage{}
	for k, v := range kv {
		changes[k] = json.RawMessage(v)
	}
	return f.store.Set(context.Background(), &core.Principal{UserID: "usr_1", Username: "admin", Role: core.RoleAdmin}, changes)
}

func (f *fixture) event(t *testing.T) []string {
	t.Helper()
	select {
	case e := <-f.ch:
		return e.Data.(core.SettingsChangedEvent).Keys
	case <-time.After(2 * time.Second):
		t.Fatal("no settings.changed")
	}
	return nil
}

func (f *fixture) noEvent(t *testing.T) {
	t.Helper()
	select {
	case e := <-f.ch:
		t.Fatalf("unexpected event %+v", e)
	case <-time.After(50 * time.Millisecond):
	}
}

func (f *fixture) row(t *testing.T, key string) (string, bool) {
	t.Helper()
	var v string
	err := f.env.DB.QueryRow(context.Background(), `SELECT value FROM settings WHERE key = ?`, key).Scan(&v)
	if db.IsNoRows(err) {
		return "", false
	}
	if err != nil {
		t.Fatal(err)
	}
	return v, true
}

// ---------- tests ----------

func TestStoreValidation(t *testing.T) {
	f := newFixture(t, nil)
	cases := []struct {
		key, val string
	}{
		{"sttest.count", `101`}, {"sttest.count", `-1`}, {"sttest.count", `"7"`}, {"sttest.count", `1.5`},
		{"sttest.mode", `"d"`}, {"sttest.mode", `1`}, {"sttest.list", `"x"`}, {"sttest.every", `"soon"`},
		{"sttest.even", `3`}, {"sttest.flag", `"yes"`}, {"sttest.count", `null`},
	}
	for _, c := range cases {
		_, err := f.set(t, map[string]string{c.key: c.val})
		ce := core.AsError(err)
		if !errors.Is(err, core.ErrInvalid) || ce.Field != c.key {
			t.Errorf("%s=%s: %v", c.key, c.val, err)
		}
	}
	if _, err := f.set(t, map[string]string{"sttest.nope": `1`}); !errors.Is(err, core.ErrInvalid) {
		t.Fatalf("unknown key: %v", err)
	}
	// All or nothing: a bad value anywhere rejects the whole batch.
	if _, err := f.set(t, map[string]string{"sttest.count": `50`, "sttest.mode": `"z"`}); err == nil {
		t.Fatal("batch accepted")
	}
	if f.store.Int("sttest.count") != 30 || f.audit.count() != 0 {
		t.Fatal("partial apply")
	}
	f.noEvent(t)
	if _, ok := f.row(t, "sttest.count"); ok {
		t.Fatal("row written")
	}
}

func TestStoreSetPersistAuditEvents(t *testing.T) {
	f := newFixture(t, nil)
	res, err := f.set(t, map[string]string{
		"sttest.count": `42`, "sttest.mode": `"b"`, "sttest.list": `[" x ","y"]`, "sttest.every": `"90m"`,
		"sttest.flag": `true`, "sttest.port": `8080`, "sttest.even": `2`, // even: unchanged (default)
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Applied) != 7 || !slices.Equal(res.RestartRequired, []string{"sttest.port"}) {
		t.Fatalf("%+v", res)
	}
	keys := f.event(t)
	slices.Sort(keys)
	if !slices.Equal(keys, []string{"sttest.count", "sttest.every", "sttest.flag", "sttest.list", "sttest.mode", "sttest.port"}) {
		t.Fatalf("event keys %v", keys)
	}
	if f.store.Int("sttest.count") != 42 || f.store.String("sttest.mode") != "b" || !f.store.Bool("sttest.flag") ||
		!slices.Equal(f.store.Strings("sttest.list"), []string{"x", "y"}) || f.store.Duration("sttest.every") != 90*time.Minute ||
		f.store.String("sttest.every") != "1h30m" || f.store.String("sttest.count") != "42" {
		t.Fatal("getters")
	}
	raw, err := f.store.Raw("sttest.list")
	if err != nil || string(raw) != `["x","y"]` {
		t.Fatalf("raw %s %v", raw, err)
	}
	if v, ok := f.row(t, "sttest.every"); !ok || v != `"1h30m"` {
		t.Fatalf("row %q", v)
	}
	// One audit entry per changed key, with previous/new values and actor.
	entries := f.audit.all()
	if len(entries) != 6 {
		t.Fatalf("audit entries %d", len(entries))
	}
	for _, e := range entries {
		if e.Action != core.ActSettingsChange || e.TargetType != "setting" || e.ActorName != "admin" {
			t.Fatalf("%+v", e)
		}
	}
	d, _ := json.Marshal(entries[0].Details)
	if !strings.Contains(string(d), `"key":"sttest.count"`) || !strings.Contains(string(d), `"previous":30`) || !strings.Contains(string(d), `"value":42`) {
		t.Fatalf("details %s", d)
	}
	if got := f.store.RestartRequired(); !slices.Equal(got, []string{"sttest.port"}) {
		t.Fatalf("restart required %v", got)
	}

	// Setting the same values again: accepted, no audit, no event.
	n := f.audit.count()
	if res, err := f.set(t, map[string]string{"sttest.count": `42`}); err != nil || len(res.Applied) != 1 || len(res.RestartRequired) != 0 {
		t.Fatalf("%+v %v", res, err)
	}
	if f.audit.count() != n {
		t.Fatal("audited a no-op")
	}
	f.noEvent(t)

	// Setting the default deletes the row.
	if _, err := f.set(t, map[string]string{"sttest.mode": `"a"`}); err != nil {
		t.Fatal(err)
	}
	f.event(t)
	if _, ok := f.row(t, "sttest.mode"); ok {
		t.Fatal("default stored")
	}

	// Persistence: a new store over the same database sees the values.
	s2, err := New(f.env)
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close()
	if s2.Int("sttest.count") != 42 || s2.String("sttest.mode") != "a" || !slices.Equal(s2.Strings("sttest.list"), []string{"x", "y"}) {
		t.Fatal("not persisted")
	}
	if len(s2.RestartRequired()) != 0 {
		t.Fatal("a fresh store starts with the stored values")
	}

	// Catalog.
	cat, err := f.store.Catalog(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	var cv *core.SettingView
	for i := range cat {
		if cat[i].Key == "sttest.count" {
			cv = &cat[i]
		}
	}
	if cv == nil || string(cv.Value) != "42" || string(cv.Default) != "30" || !cv.IsSet || cv.Section != "storage" ||
		cv.Order != 1 || cv.Label != "Count" || cv.Description == "" || cv.Min == nil || *cv.Max != 100 || cv.Type != "int" ||
		cv.UpdatedAt == nil || cv.UpdatedBy != "admin" || cv.Restart {
		t.Fatalf("catalog %+v", cv)
	}

	// Reset.
	if err := f.store.Reset(context.Background(), nil, "sttest.count"); err != nil {
		t.Fatal(err)
	}
	if f.store.Int("sttest.count") != 30 {
		t.Fatal("reset")
	}
	if e := f.audit.last(); e.Details.(map[string]any)["reset"] != true {
		t.Fatalf("reset audit %+v", e)
	}
	if err := f.store.Reset(context.Background(), nil, "sttest.nope"); !errors.Is(err, core.ErrNotFound) {
		t.Fatalf("reset unknown: %v", err)
	}
	if _, err := f.store.Raw("sttest.nope"); !errors.Is(err, core.ErrNotFound) {
		t.Fatal("raw unknown")
	}
}

func TestStoreSecrets(t *testing.T) {
	f := newFixture(t, nil)
	const secret = "hunter2-s3cret"

	// Locked: secrets can be neither stored nor read, everything else works.
	f.keys.locked.Store(true)
	if _, err := f.set(t, map[string]string{"sttest.password": `"` + secret + `"`}); !errors.Is(err, core.ErrKeysLocked) {
		t.Fatalf("locked set: %v", err)
	}
	if _, err := f.set(t, map[string]string{"sttest.count": `5`}); err != nil {
		t.Fatalf("non-secret while locked: %v", err)
	}
	if v, err := f.store.Secret("sttest.password"); err != nil || v != "" {
		t.Fatalf("unset secret while locked: %q %v", v, err)
	}
	f.keys.locked.Store(false)

	if _, err := f.set(t, map[string]string{"sttest.password": `"` + secret + `"`, "sttest.token": `"tok-123"`}); err != nil {
		t.Fatal(err)
	}
	row, ok := f.row(t, "sttest.password")
	if !ok || strings.Contains(row, secret) || !strings.HasPrefix(row, `"v1:`) {
		t.Fatalf("stored %q", row)
	}
	if raw, _ := f.store.Raw("sttest.password"); string(raw) != `"`+Mask+`"` {
		t.Fatalf("raw %s", raw)
	}
	if f.store.String("sttest.password") != "" {
		t.Fatal("String leaks a secret")
	}
	if v, err := f.store.Secret("sttest.password"); err != nil || v != secret {
		t.Fatalf("secret %q %v", v, err)
	}
	if _, err := f.store.Secret("sttest.count"); !errors.Is(err, core.ErrInvalid) {
		t.Fatal("Secret of a non-secret")
	}
	cat, _ := f.store.Catalog(context.Background())
	for _, v := range cat {
		if v.Key == "sttest.password" && (string(v.Value) != "null" || string(v.Default) != "null" || !v.IsSet || !v.Secret) {
			t.Fatalf("catalog %+v", v)
		}
	}
	for _, e := range f.audit.all() {
		d, _ := json.Marshal(e.Details)
		if strings.Contains(string(d), secret) || strings.Contains(string(d), "tok-123") || strings.Contains(string(d), "v1:") {
			t.Fatalf("audit leaks the secret: %s", d)
		}
	}

	// The masked value round-trips without change.
	n := f.audit.count()
	for len(f.ch) > 0 {
		<-f.ch
	}
	if res, err := f.set(t, map[string]string{"sttest.password": `"` + Mask + `"`}); err != nil || len(res.Applied) != 1 {
		t.Fatalf("%+v %v", res, err)
	}
	if v, _ := f.store.Secret("sttest.password"); v != secret || f.audit.count() != n {
		t.Fatal("mask round trip changed the secret")
	}
	f.noEvent(t)

	// Locked again: reading the secret fails, the catalog still works.
	f.keys.locked.Store(true)
	if _, err := f.store.Secret("sttest.password"); !errors.Is(err, core.ErrKeysLocked) {
		t.Fatalf("locked read: %v", err)
	}
	if _, err := f.store.Catalog(context.Background()); err != nil {
		t.Fatal(err)
	}
	f.keys.locked.Store(false)

	// A sealed value moved to another key does not open (AAD binding).
	if _, err := f.env.DB.Exec(context.Background(), `UPDATE settings SET value = ? WHERE key = 'sttest.token'`, row); err != nil {
		t.Fatal(err)
	}
	f.env.Bus.Publish(events.Event{Topic: events.TopicSettingsChanged, Data: core.SettingsChangedEvent{Keys: []string{"sttest.token"}}})
	waitUntil(t, func() bool {
		_, err := f.store.Secret("sttest.token")
		return errors.Is(err, core.ErrCorrupt)
	})

	// Clearing.
	if _, err := f.set(t, map[string]string{"sttest.password": `""`}); err != nil {
		t.Fatal(err)
	}
	if v, err := f.store.Secret("sttest.password"); err != nil || v != "" {
		t.Fatalf("cleared %q %v", v, err)
	}
	if _, ok := f.row(t, "sttest.password"); ok {
		t.Fatal("cleared secret still stored")
	}
	if raw, _ := f.store.Raw("sttest.password"); string(raw) != `""` {
		t.Fatalf("raw after clear %s", raw)
	}
	e := f.audit.last()
	if e.Details.(map[string]any)["value"] != "" || e.Details.(map[string]any)["previous"] != Mask {
		t.Fatalf("clear audit %+v", e.Details)
	}
}

func TestStoreBootstrapBridge(t *testing.T) {
	f := newFixture(t, nil)
	cfgPath := f.env.Config.Path()
	before, _ := os.ReadFile(cfgPath)

	res, err := f.set(t, map[string]string{"server.https_port": `9443`, "log.level": `"debug"`, "server.trusted_proxies": `["10.0.0.1"]`})
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(res.RestartRequired, []string{"server.https_port"}) {
		t.Fatalf("%+v", res)
	}
	if f.store.Int("server.https_port") != 9443 || f.store.String("log.level") != "debug" || logx.Level() != "debug" {
		t.Fatal("live values")
	}
	// The shared startup config is untouched; the file has the new values.
	if f.env.Config.Server.HTTPSPort != 8443 {
		t.Fatal("env.Config modified")
	}
	after, _ := os.ReadFile(cfgPath)
	if !strings.HasPrefix(string(after), config.DefaultHeader) {
		t.Fatalf("header lost:\n%s", after)
	}
	loaded, err := config.LoadFile(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Server.HTTPSPort != 9443 || loaded.Log.Level != "debug" || !slices.Equal(loaded.Server.TrustedProxies, []string{"10.0.0.1"}) {
		t.Fatalf("file: %+v %+v", loaded.Server, loaded.Log)
	}
	if _, ok := f.row(t, "server.https_port"); ok {
		t.Fatal("bootstrap key stored in the database")
	}
	if n := f.audit.count(); n != 3 {
		t.Fatalf("audit %d", n)
	}
	if !slices.Contains(f.store.RestartRequired(), "server.https_port") {
		t.Fatal("restart required")
	}
	cat, _ := f.store.Catalog(context.Background())
	for _, v := range cat {
		if v.Key == "server.https_port" && (string(v.Value) != "9443" || !v.Bootstrap || !v.Restart || v.UpdatedBy != "admin") {
			t.Fatalf("catalog %+v", v)
		}
	}

	// Cross-key validation by config.Validate (http_port must differ).
	if _, err := f.set(t, map[string]string{"server.http_port": `9443`}); err == nil || core.AsError(err).Field != "server.http_port" {
		t.Fatalf("http=https: %v", err)
	}
	cur, _ := os.ReadFile(cfgPath)
	if string(cur) != string(after) {
		t.Fatal("rejected change rewrote the file")
	}
	// Per-key validation (server.name must be a DNS label).
	if _, err := f.set(t, map[string]string{"server.name": `"Bad Name"`}); !errors.Is(err, core.ErrInvalid) {
		t.Fatalf("name: %v", err)
	}

	// A failing database transaction restores the file.
	_ = f.env.DB.Close()
	if _, err := f.set(t, map[string]string{"server.https_port": `9444`}); err == nil {
		t.Fatal("expected a database error")
	}
	cur, _ = os.ReadFile(cfgPath)
	if string(cur) != string(after) {
		t.Fatalf("file not restored:\n%s", cur)
	}
	if f.store.Int("server.https_port") != 9443 {
		t.Fatal("snapshot changed by a failed write")
	}
	_ = before
}

func TestStoreEnvOverride(t *testing.T) {
	f := newFixture(t, func(k string) (string, bool) {
		if k == "FILEPARCEL_SERVER_HTTP_PORT" {
			return "8081", true
		}
		return "", false
	})
	if f.store.Int("server.http_port") != 8081 {
		t.Fatal("env value not visible")
	}
	cat, _ := f.store.Catalog(context.Background())
	for _, v := range cat {
		if v.Key == "server.http_port" && v.OverriddenByEnv != "FILEPARCEL_SERVER_HTTP_PORT" {
			t.Fatalf("%+v", v)
		}
		if v.Key == "server.https_port" && v.OverriddenByEnv != "" {
			t.Fatalf("%+v", v)
		}
	}
	_, err := f.set(t, map[string]string{"server.http_port": `8082`})
	if !errors.Is(err, core.ErrConflict) || !strings.Contains(err.Error(), "FILEPARCEL_SERVER_HTTP_PORT") {
		t.Fatalf("override: %v", err)
	}
	// Sending the current (env) value back is accepted as a no-op.
	if res, err := f.set(t, map[string]string{"server.http_port": `8081`, "sttest.count": `3`}); err != nil || len(res.Applied) != 2 {
		t.Fatalf("%+v %v", res, err)
	}
	if err := f.store.Reset(context.Background(), nil, "server.http_port"); !errors.Is(err, core.ErrConflict) {
		t.Fatalf("reset override: %v", err)
	}
}

func TestStoreReloadOnSettingsChanged(t *testing.T) {
	f := newFixture(t, nil)
	// Another component writes a row and publishes settings.changed.
	if _, err := f.env.DB.Exec(context.Background(), `INSERT INTO settings (key, value, updated_at, updated_by) VALUES ('sttest.count', '77', ?, 'cli')`,
		db.Ms(time.Now())); err != nil {
		t.Fatal(err)
	}
	f.env.Bus.Publish(events.Event{Topic: events.TopicSettingsChanged, Data: core.SettingsChangedEvent{Keys: []string{"sttest.count"}}})
	waitUntil(t, func() bool { return f.store.Int("sttest.count") == 77 })
	// An invalid stored value falls back to the default.
	if _, err := f.env.DB.Exec(context.Background(), `UPDATE settings SET value = '"many"' WHERE key = 'sttest.count'`); err != nil {
		t.Fatal(err)
	}
	f.env.Bus.Publish(events.Event{Topic: events.TopicSettingsChanged})
	waitUntil(t, func() bool { return f.store.Int("sttest.count") == 30 })
	if raw, _ := f.store.Raw("sttest.count"); string(raw) != "30" {
		t.Fatalf("raw %s", raw)
	}
}

func TestStoreConcurrency(t *testing.T) {
	f := newFixture(t, nil)
	ctx := context.Background()
	var wg sync.WaitGroup
	for i := range 8 {
		wg.Go(func() {
			for j := range 20 {
				v := fmt.Sprintf("%d", (i*20+j)%100)
				if _, err := f.store.Set(ctx, nil, map[string]json.RawMessage{"sttest.count": json.RawMessage(v)}); err != nil {
					t.Error(err)
					return
				}
			}
		})
		wg.Go(func() {
			for range 200 {
				if n := f.store.Int("sttest.count"); n < 0 || n > 100 {
					t.Errorf("read %d", n)
				}
				_, _ = f.store.Catalog(ctx)
				_ = f.store.Strings("server.bind")
			}
		})
	}
	wg.Wait()
}

func TestStoreInMemory(t *testing.T) {
	s, err := New(nil)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if _, err := s.Set(context.Background(), nil, map[string]json.RawMessage{"sttest.flag": json.RawMessage(`true`)}); err != nil {
		t.Fatal(err)
	}
	if !s.Bool("sttest.flag") {
		t.Fatal("in-memory set")
	}
	if _, err := s.Set(context.Background(), nil, map[string]json.RawMessage{"sttest.password": json.RawMessage(`"x"`)}); !errors.Is(err, core.ErrKeysLocked) {
		t.Fatalf("secret without keys: %v", err)
	}
	if res, err := s.Set(context.Background(), nil, nil); err != nil || len(res.Applied) != 0 || res.RestartRequired == nil {
		t.Fatalf("%+v %v", res, err)
	}
	// Bootstrap keys without a config fall back to defaults and in-memory rows.
	if s.Int("server.https_port") != 8443 {
		t.Fatal("bootstrap default")
	}
}

func waitUntil(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatal("condition not reached")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// editConfig rewrites the fixture's fileparcel.toml behind the store's back
// (as "fileparcel config edit" does while the server runs) and returns the
// new content.
func editConfig(t *testing.T, f *fixture, edit func(string) string) []byte {
	t.Helper()
	path := f.env.Config.Path()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	out := []byte(edit(string(b)))
	if string(out) == string(b) {
		t.Fatal("edit changed nothing")
	}
	if err := os.WriteFile(path, out, 0o640); err != nil {
		t.Fatal(err)
	}
	return out
}

// TestStoreBootstrapKeepsExternalEdits: a bootstrap change is applied to the
// file as it is on disk, not to the copy read at startup, so edits made
// while the server runs survive (and show up in the catalog).
func TestStoreBootstrapKeepsExternalEdits(t *testing.T) {
	f := newFixture(t, nil)
	cfgPath := f.env.Config.Path()
	editConfig(t, f, func(s string) string {
		s = strings.Replace(s, "https_port = 8443", "https_port = 9443", 1)
		s = strings.Replace(s, "format = 'text'", "format = 'json'", 1)
		return s + "\n[future]\nx = 1\n"
	})
	if _, err := f.set(t, map[string]string{"log.level": `"debug"`}); err != nil {
		t.Fatal(err)
	}
	loaded, err := config.LoadFile(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Log.Format != "json" || loaded.Server.HTTPSPort != 9443 || loaded.Log.Level != "debug" {
		t.Fatalf("file: %+v %+v", loaded.Server, loaded.Log)
	}
	if b, _ := os.ReadFile(cfgPath); !strings.Contains(string(b), "[future]") {
		t.Fatalf("unknown key lost:\n%s", b)
	}
	if f.store.Int("server.https_port") != 9443 || !slices.Contains(f.store.RestartRequired(), "server.https_port") {
		t.Fatalf("edit not visible: %d %v", f.store.Int("server.https_port"), f.store.RestartRequired())
	}
	if f.env.Config.Server.HTTPSPort != 8443 {
		t.Fatal("env.Config modified")
	}

	// A live key edited on disk is picked up with the next change and applied,
	// so the level shown is the level in effect.
	editConfig(t, f, func(s string) string { return strings.Replace(s, "level = 'debug'", "level = 'warn'", 1) })
	if _, err := f.set(t, map[string]string{"server.name": `"box"`}); err != nil {
		t.Fatal(err)
	}
	if f.store.String("log.level") != "warn" || logx.Level() != "warn" {
		t.Fatalf("log level %q, in effect %q", f.store.String("log.level"), logx.Level())
	}

	// A failing database transaction puts back exactly what was on disk,
	// including an edit made after the last change.
	edited := editConfig(t, f, func(s string) string { return strings.Replace(s, "https_port = 9443", "https_port = 9445", 1) })
	_ = f.env.DB.Close()
	if _, err := f.set(t, map[string]string{"log.level": `"error"`}); err == nil {
		t.Fatal("expected a database error")
	}
	if cur, _ := os.ReadFile(cfgPath); string(cur) != string(edited) {
		t.Fatalf("file not restored:\n%s\nwant:\n%s", cur, edited)
	}
	if f.store.String("log.level") != "warn" || logx.Level() != "warn" {
		t.Fatal("a failed write changed the log level")
	}
}

// TestStoreBootstrapEnvAndBrokenFile: environment overrides stay what they
// were at startup (and are never written), and a file edited into an
// invalid state is not rewritten by an unrelated change.
func TestStoreBootstrapEnvAndBrokenFile(t *testing.T) {
	f := newFixture(t, func(k string) (string, bool) {
		if k == "FILEPARCEL_SERVER_HTTP_PORT" {
			return "8081", true
		}
		return "", false
	})
	cfgPath := f.env.Config.Path()
	editConfig(t, f, func(s string) string { return strings.Replace(s, "https_port = 8443", "https_port = 9443", 1) })
	if _, err := f.set(t, map[string]string{"log.level": `"debug"`}); err != nil {
		t.Fatal(err)
	}
	loaded, err := config.LoadFile(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Server.HTTPPort != 8080 || loaded.Server.HTTPSPort != 9443 {
		t.Fatalf("file: %+v", loaded.Server)
	}
	if f.store.Int("server.http_port") != 8081 {
		t.Fatal("env value lost")
	}
	cat, _ := f.store.Catalog(context.Background())
	for _, v := range cat {
		if v.Key == "server.http_port" && v.OverriddenByEnv != "FILEPARCEL_SERVER_HTTP_PORT" {
			t.Fatalf("%+v", v)
		}
	}

	// Broken by hand on a key the change does not touch: 409, file untouched.
	broken := editConfig(t, f, func(s string) string { return strings.Replace(s, "format = 'text'", "format = 'xml'", 1) })
	_, err = f.set(t, map[string]string{"log.level": `"warn"`})
	if !errors.Is(err, core.ErrConflict) || !strings.Contains(err.Error(), "log.format") {
		t.Fatalf("broken file: %v", err)
	}
	if cur, _ := os.ReadFile(cfgPath); string(cur) != string(broken) {
		t.Fatal("broken file rewritten")
	}
	// Not TOML at all: the same.
	garbage := editConfig(t, f, func(s string) string { return s + "\n[server\n" })
	if _, err := f.set(t, map[string]string{"log.level": `"warn"`}); !errors.Is(err, core.ErrConflict) {
		t.Fatalf("unparsable file: %v", err)
	}
	if cur, _ := os.ReadFile(cfgPath); string(cur) != string(garbage) {
		t.Fatal("unparsable file rewritten")
	}
	// A change that repairs the broken key is accepted.
	if err := os.WriteFile(cfgPath, broken, 0o640); err != nil {
		t.Fatal(err)
	}
	editConfig(t, f, func(s string) string { return strings.Replace(s, "level = 'debug'", "level = 'loud'", 1) })
	if _, err := f.set(t, map[string]string{"log.level": `"warn"`}); !errors.Is(err, core.ErrConflict) {
		t.Fatalf("still broken (log.format): %v", err)
	}
	editConfig(t, f, func(s string) string { return strings.Replace(s, "format = 'xml'", "format = 'text'", 1) })
	if _, err := f.set(t, map[string]string{"log.level": `"warn"`}); err != nil {
		t.Fatalf("repairing change: %v", err)
	}
	// A deleted file is recreated.
	if err := os.Remove(cfgPath); err != nil {
		t.Fatal(err)
	}
	if _, err := f.set(t, map[string]string{"log.level": `"info"`}); err != nil {
		t.Fatal(err)
	}
	if loaded, err := config.LoadFile(cfgPath); err != nil || loaded.Log.Level != "info" || loaded.Server.HTTPSPort != 9443 {
		t.Fatalf("recreated file: %+v %v", loaded, err)
	}
}

// TestStoreBindList: a listen list that cannot be bound (a repeated address,
// anything next to a dual-stack wildcard) is refused on the field instead of
// failing the next start with "address already in use".
func TestStoreBindList(t *testing.T) {
	f := newFixture(t, nil)
	for _, v := range []string{`["::","0.0.0.0"]`, `["0.0.0.0","::1"]`, `["::","192.168.1.5"]`, `["::ffff:10.0.0.1","10.0.0.1"]`, `[]`} {
		_, err := f.set(t, map[string]string{"server.bind": v})
		if !errors.Is(err, core.ErrInvalid) || core.AsError(err).Field != "server.bind" {
			t.Errorf("%s: %v", v, err)
		}
	}
	if _, err := f.set(t, map[string]string{"server.bind": `["127.0.0.1","::1"]`}); err != nil {
		t.Fatal(err)
	}
	if got := f.store.Strings("server.bind"); !slices.Equal(got, []string{"127.0.0.1", "::1"}) {
		t.Fatalf("bind %v", got)
	}
}

// TestStorePublicURL: server.public_url is the base of the share and
// invitation links handed to other people, so the field refuses a user name
// or password, a path, a query or fragment and a port out of range instead
// of embedding them in every link after the next restart.
func TestStorePublicURL(t *testing.T) {
	f := newFixture(t, nil)
	for _, v := range []string{`"https://user:secret@files.example"`, `"https://files.example/sub"`,
		`"https://files.example?x=1"`, `"https://files.example#top"`, `"https://files.example:99999"`, `"ftp://files.example"`} {
		_, err := f.set(t, map[string]string{"server.public_url": v})
		if !errors.Is(err, core.ErrInvalid) || core.AsError(err).Field != "server.public_url" {
			t.Errorf("%s: %v", v, err)
		}
	}
	if got := f.store.String("server.public_url"); got != "" {
		t.Fatalf("refused value stored: %q", got)
	}
	if _, err := f.set(t, map[string]string{"server.public_url": `"https://files.example:9443/"`}); err != nil {
		t.Fatal(err)
	}
	if got := f.store.String("server.public_url"); got != "https://files.example:9443/" {
		t.Fatalf("public_url %q", got)
	}
}

// TestStoreResetRemovesInvalidRow: a stored value that no longer validates is
// in effect the default, but resetting (or setting the default) must still
// delete the row rather than report success and keep it.
func TestStoreResetRemovesInvalidRow(t *testing.T) {
	f := newFixture(t, nil)
	ctx := context.Background()
	insert := func(key, value string) {
		t.Helper()
		if _, err := f.env.DB.Exec(ctx, `INSERT INTO settings (key, value, updated_at, updated_by) VALUES (?, ?, ?, 'cli')
			ON CONFLICT(key) DO UPDATE SET value = excluded.value`, key, value, db.Ms(time.Now())); err != nil {
			t.Fatal(err)
		}
	}
	insert("sttest.mode", `"zzz"`)
	insert("sttest.count", `"many"`)
	insert("sttest.port", `0`)
	f.env.Bus.Publish(events.Event{Topic: events.TopicSettingsChanged, Data: core.SettingsChangedEvent{Keys: []string{"sttest.mode"}}})
	waitUntil(t, func() bool { // the rows are loaded (the values are the defaults either way)
		cat, _ := f.store.Catalog(ctx)
		n := 0
		for _, v := range cat {
			if strings.HasPrefix(v.Key, "sttest.") && v.UpdatedBy == "cli" {
				n++
			}
		}
		return n == 3
	})
	if f.store.String("sttest.mode") != "a" || f.store.Int("sttest.count") != 30 || f.store.Int("sttest.port") != 1 {
		t.Fatal("invalid rows not ignored")
	}
	f.event(t) // our own publish

	if err := f.store.Reset(ctx, nil, "sttest.mode"); err != nil {
		t.Fatal(err)
	}
	if _, ok := f.row(t, "sttest.mode"); ok {
		t.Fatal("Reset kept the invalid row")
	}
	if n := f.audit.count(); n != 1 || f.audit.last().Details.(map[string]any)["previous_invalid"] != true {
		t.Fatalf("audit %d %+v", n, f.audit.all())
	}
	f.event(t)
	// Setting the default does the same; a Restart key reports no restart
	// (its value was the default all along).
	res, err := f.set(t, map[string]string{"sttest.count": `30`, "sttest.port": `1`})
	if err != nil || len(res.RestartRequired) != 0 {
		t.Fatalf("%+v %v", res, err)
	}
	for _, k := range []string{"sttest.count", "sttest.port"} {
		if _, ok := f.row(t, k); ok {
			t.Fatalf("setting the default kept the invalid row %s", k)
		}
	}
	f.event(t)
	// Another value overwrites an invalid row, as before.
	insert("sttest.mode", `"zzz"`)
	if _, err := f.set(t, map[string]string{"sttest.mode": `"b"`}); err != nil {
		t.Fatal(err)
	}
	if v, _ := f.row(t, "sttest.mode"); v != `"b"` {
		t.Fatalf("row %q", v)
	}
	f.event(t)
	// Resetting a key without a row is still a no-op.
	n := f.audit.count()
	if err := f.store.Reset(ctx, nil, "sttest.flag"); err != nil || f.audit.count() != n {
		t.Fatalf("reset unset key: %v", err)
	}
	f.noEvent(t)
}
