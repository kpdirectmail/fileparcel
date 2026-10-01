// Package authtest provides test doubles for unit B's packages (auth,
// authapi, meapi): an in-memory Keys, Settings and Audit, a Users service
// backed by the real users table, a mutable clock, a software WebAuthn
// authenticator, and New, which wires them with a migrated SQLite database
// and a real *auth.Service.
//
// It is test support only: import it from _test.go files, never from
// production code.
package authtest

import (
	"cmp"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"fileparcel/internal/auth"
	"fileparcel/internal/config"
	"fileparcel/internal/core"
	"fileparcel/internal/crypt"
	"fileparcel/internal/db"
	"fileparcel/internal/events"
	"fileparcel/internal/ids"
	"fileparcel/internal/ratelimit"
	"fileparcel/internal/settings"
)

// FastHashing lowers the argon2 cost for the whole test binary (call it
// from TestMain before any hashing). Production parameters are restored by
// the returned func.
func FastHashing() (restore func()) {
	old := crypt.PasswordParams
	crypt.PasswordParams = crypt.Argon2Params{MemoryKiB: 64, Time: 1, Threads: 1, SaltLen: 16, KeyLen: 32}
	return func() { crypt.PasswordParams = old }
}

// Env is a wired test environment.
type Env struct {
	Env      *core.Env
	DB       *db.DB
	Bus      *events.Bus
	Clock    *Clock
	Keys     *Keys
	Settings *Settings
	Audit    *Audit
	Users    *Users
	Limiter  *ratelimit.Registry
	Auth     *auth.Service
}

// New builds an Env in t.TempDir(). The clock starts at 2026-09-19 12:00 UTC.
func New(t testing.TB) *Env {
	t.Helper()
	database, err := db.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("db open: %v", err)
	}
	t.Cleanup(func() { _ = database.Close() })
	if _, err := database.Migrate(context.Background()); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	bus := events.New()
	t.Cleanup(bus.Close)
	clock := &Clock{t: time.Date(2026, 9, 19, 12, 0, 0, 0, time.UTC)}
	cfg := config.Default(config.NewInstallID())
	e := &Env{DB: database, Bus: bus, Clock: clock}
	e.Keys = NewKeys()
	e.Settings = NewSettings(bus)
	e.Audit = &Audit{}
	e.Env = &core.Env{
		Config: cfg, DB: database, Log: slog.New(slog.NewTextHandler(io.Discard, nil)), Clock: clock, Bus: bus,
		Keys: e.Keys, Settings: e.Settings, Audit: e.Audit,
	}
	e.Users = &Users{env: e.Env, invites: map[string]*core.Invite{}}
	if e.Limiter, err = ratelimit.New(e.Env); err != nil {
		t.Fatalf("ratelimit: %v", err)
	}
	t.Cleanup(func() { _ = e.Limiter.Close() })
	if e.Auth, err = auth.New(e.Env, e.Users, e.Limiter); err != nil {
		t.Fatalf("auth.New: %v", err)
	}
	return e
}

// AddUser creates an active user with password pw (hashed by the service).
func (e *Env) AddUser(t testing.TB, username, pw string, role core.Role) *core.User {
	t.Helper()
	phc := ""
	if pw != "" {
		var err error
		if phc, err = e.Auth.HashPassword(pw); err != nil {
			t.Fatalf("hash: %v", err)
		}
	}
	u, err := e.Users.Create(context.Background(), core.SystemPrincipal(core.ViaOffline),
		core.NewUser{Username: username, Role: role, PasswordHash: phc, Email: username + "@example.test"})
	if err != nil {
		t.Fatalf("create user: %v", err)
	}
	return u
}

// AddRole stores a custom role (DESIGN §6a) named name, based on base
// (member or guest), with the permissions perms and the delegable flag, and
// returns its id. The users double has no role management of its own; the
// row is written straight into the roles table, as package users would.
func (e *Env) AddRole(t testing.TB, name string, base core.Role, perms core.CapSet, delegable bool) string {
	t.Helper()
	id := ids.New(ids.PrefixRole)
	now := db.Ms(e.Clock.Now())
	if _, err := e.DB.Exec(context.Background(), `INSERT INTO roles (id, name, base, permissions, delegable,
		created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?)`,
		id, name, string(base), core.EncodeCaps(perms), db.Bool(delegable), now, now); err != nil {
		t.Fatalf("add role %s: %v", name, err)
	}
	return id
}

// SetRolePermissions replaces the stored permissions of the custom role id.
func (e *Env) SetRolePermissions(t testing.TB, id string, perms core.CapSet) {
	t.Helper()
	if _, err := e.DB.Exec(context.Background(), `UPDATE roles SET permissions = ?, updated_at = ? WHERE id = ?`,
		core.EncodeCaps(perms), db.Ms(e.Clock.Now()), id); err != nil {
		t.Fatalf("set role permissions: %v", err)
	}
}

// SetUserRole gives the account userID the role roleID: a built-in word
// (the custom role is removed) or a custom role id (users.role becomes its
// base).
func (e *Env) SetUserRole(t testing.TB, userID, roleID string) {
	t.Helper()
	ctx := context.Background()
	var err error
	if core.IsCustomRoleID(roleID) {
		_, err = e.DB.Exec(ctx, `UPDATE users SET role = (SELECT base FROM roles WHERE id = ?), role_id = ? WHERE id = ?`,
			roleID, roleID, userID)
	} else {
		_, err = e.DB.Exec(ctx, `UPDATE users SET role = ?, role_id = NULL WHERE id = ?`, roleID, userID)
	}
	if err != nil {
		t.Fatalf("set role of %s: %v", userID, err)
	}
}

// ---------- clock ----------

// Clock is a settable core.Clock.
type Clock struct {
	mu sync.Mutex
	t  time.Time
}

// Now implements core.Clock.
func (c *Clock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

// Advance moves the clock forward.
func (c *Clock) Advance(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

// Set sets the clock.
func (c *Clock) Set(t time.Time) {
	c.mu.Lock()
	c.t = t.UTC()
	c.mu.Unlock()
}

// ---------- keys ----------

// Keys is an unlocked in-memory core.Keys (field encryption with AES-GCM,
// MAC with HMAC-SHA256). Methods the auth packages do not use return
// ErrUnsupported.
type Keys struct {
	mu     sync.Mutex
	locked bool
	aead   cipher.AEAD
	macKey []byte
}

// NewKeys returns unlocked keys with random key material.
func NewKeys() *Keys {
	blk, err := aes.NewCipher(crypt.RandomBytes(32))
	if err != nil {
		panic(err)
	}
	a, err := cipher.NewGCM(blk)
	if err != nil {
		panic(err)
	}
	return &Keys{aead: a, macKey: crypt.RandomBytes(32)}
}

// SetLocked simulates a locked (sealed) server.
func (k *Keys) SetLocked(v bool) {
	k.mu.Lock()
	k.locked = v
	k.mu.Unlock()
}

// State implements core.Keys.
func (k *Keys) State() core.KeyState {
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.locked {
		return core.KeyStateLocked
	}
	return core.KeyStateUnlocked
}

// Init implements core.Keys.
func (k *Keys) Init(context.Context, bool, []byte) (string, error) { return "", core.ErrConflict }

// Unlock implements core.Keys.
func (k *Keys) Unlock(context.Context, []byte) error { k.SetLocked(false); return nil }

// Lock implements core.Keys.
func (k *Keys) Lock(context.Context) error { k.SetLocked(true); return nil }

// Status implements core.Keys.
func (k *Keys) Status(context.Context) (*core.KeyStatus, error) { return nil, ErrUnsupported }

// NewDEK implements core.Keys.
func (k *Keys) NewDEK([]byte) ([]byte, []byte, string, error) {
	return nil, nil, "", ErrUnsupported
}

// UnwrapDEK implements core.Keys.
func (k *Keys) UnwrapDEK([]byte, string, []byte) ([]byte, error) { return nil, ErrUnsupported }

// SealField implements core.Keys ("v1:test:<b64url(nonce||ct)>").
func (k *Keys) SealField(aad string, plaintext []byte) (string, error) {
	if k.State() != core.KeyStateUnlocked {
		return "", core.ErrKeysLocked
	}
	nonce := crypt.RandomBytes(k.aead.NonceSize())
	ct := k.aead.Seal(nonce, nonce, plaintext, []byte(aad))
	return "v1:test:" + base64.RawURLEncoding.EncodeToString(ct), nil
}

// OpenField implements core.Keys (wrong AAD or tampering → core.ErrCorrupt).
func (k *Keys) OpenField(aad string, sealed string) ([]byte, error) {
	if k.State() != core.KeyStateUnlocked {
		return nil, core.ErrKeysLocked
	}
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(sealed, "v1:test:"))
	if err != nil || len(raw) < k.aead.NonceSize() {
		return nil, core.ErrCorrupt
	}
	pt, err := k.aead.Open(nil, raw[:k.aead.NonceSize()], raw[k.aead.NonceSize():], []byte(aad))
	if err != nil {
		return nil, core.ErrCorrupt
	}
	return pt, nil
}

// MAC implements core.Keys (nil while locked).
func (k *Keys) MAC(purpose string, data ...[]byte) []byte {
	if k.State() != core.KeyStateUnlocked {
		return nil
	}
	return crypt.HMAC(k.macKey, append([][]byte{[]byte("fp-mac|" + purpose)}, data...)...)
}

// Seal implements core.Keys.
func (k *Keys) Seal(context.Context, []byte) error { return ErrUnsupported }

// Unseal implements core.Keys.
func (k *Keys) Unseal(context.Context, []byte) error { return ErrUnsupported }

// ChangePassphrase implements core.Keys.
func (k *Keys) ChangePassphrase(context.Context, []byte, []byte) error { return ErrUnsupported }

// RotateKEK implements core.Keys.
func (k *Keys) RotateKEK(context.Context, string, func(int64, int64)) error {
	return ErrUnsupported
}

// RotateMaster implements core.Keys.
func (k *Keys) RotateMaster(context.Context) error { return ErrUnsupported }

// ExportRecovery implements core.Keys.
func (k *Keys) ExportRecovery(context.Context) (string, error) { return "", ErrUnsupported }

// Cipher implements core.Keys.
func (k *Keys) Cipher() core.CipherID { return core.CipherAES256GCM }

var _ core.Keys = (*Keys)(nil)

// ---------- settings ----------

// Settings is an in-memory core.Settings: registered defaults (package
// settings registry) overridden by Put. Put publishes settings.changed.
type Settings struct {
	mu     sync.Mutex
	values map[string]any
	bus    *events.Bus
}

// NewSettings returns an empty store publishing on bus (may be nil).
func NewSettings(bus *events.Bus) *Settings {
	return &Settings{values: map[string]any{}, bus: bus}
}

// Put overrides key (int, bool, string or []string values).
func (s *Settings) Put(key string, v any) {
	s.mu.Lock()
	s.values[key] = v
	s.mu.Unlock()
	if s.bus != nil {
		s.bus.Publish(events.Event{Topic: events.TopicSettingsChanged, Data: core.SettingsChangedEvent{Keys: []string{key}}})
	}
}

func (s *Settings) value(key string) (any, bool) {
	s.mu.Lock()
	v, ok := s.values[key]
	s.mu.Unlock()
	if ok {
		return v, true
	}
	d, ok := settings.Lookup(key)
	if !ok {
		return nil, false
	}
	return d.Default, true
}

// Raw implements core.Settings.
func (s *Settings) Raw(key string) (json.RawMessage, error) {
	v, ok := s.value(key)
	if !ok {
		return nil, core.NotFoundf("unknown setting %q", key)
	}
	return json.Marshal(v)
}

// Int implements core.Settings.
func (s *Settings) Int(key string) int64 {
	v, _ := s.value(key)
	switch n := v.(type) {
	case int:
		return int64(n)
	case int64:
		return n
	case float64:
		return int64(n)
	}
	return 0
}

// Bool implements core.Settings.
func (s *Settings) Bool(key string) bool {
	v, _ := s.value(key)
	b, _ := v.(bool)
	return b
}

// String implements core.Settings.
func (s *Settings) String(key string) string {
	v, _ := s.value(key)
	switch x := v.(type) {
	case string:
		return x
	case int, int64:
		return fmt.Sprint(x)
	}
	return ""
}

// Strings implements core.Settings.
func (s *Settings) Strings(key string) []string {
	v, _ := s.value(key)
	l, _ := v.([]string)
	return append([]string{}, l...)
}

// Duration implements core.Settings.
func (s *Settings) Duration(key string) time.Duration {
	d, _ := time.ParseDuration(s.String(key))
	return d
}

// Secret implements core.Settings.
func (s *Settings) Secret(key string) (string, error) { return s.String(key), nil }

// Set implements core.Settings (values decoded with the registered definition).
func (s *Settings) Set(_ context.Context, _ *core.Principal, changes map[string]json.RawMessage) (*core.SettingsResult, error) {
	res := &core.SettingsResult{}
	for k, raw := range changes {
		d, ok := settings.Lookup(k)
		if !ok {
			return nil, core.Invalid(k, "unknown setting")
		}
		_, v, err := d.Decode(raw)
		if err != nil {
			return nil, core.Invalid(k, err.Error())
		}
		s.Put(k, v)
		res.Applied = append(res.Applied, k)
	}
	return res, nil
}

// Reset implements core.Settings.
func (s *Settings) Reset(_ context.Context, _ *core.Principal, key string) error {
	s.mu.Lock()
	delete(s.values, key)
	s.mu.Unlock()
	return nil
}

// Catalog implements core.Settings.
func (s *Settings) Catalog(context.Context) ([]core.SettingView, error) {
	return nil, ErrUnsupported
}

var _ core.Settings = (*Settings)(nil)

// ---------- audit ----------

// Audit records entries in memory (actor and client fields filled from the
// context principal like the real service, audit.fill).
type Audit struct {
	mu      sync.Mutex
	entries []core.AuditEntry
}

func fill(ctx context.Context, e *core.AuditEntry) {
	if e.Outcome == "" {
		e.Outcome = core.OutcomeSuccess
	}
	p := core.PrincipalFrom(ctx)
	if p == nil {
		return
	}
	if e.ActorID == "" && e.ActorName == "" {
		e.ActorID, e.ActorName = p.UserID, p.Username
	}
	if e.ActorVia == "" {
		e.ActorVia = string(p.Via)
	}
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

// Record implements core.Audit.
func (a *Audit) Record(ctx context.Context, e core.AuditEntry) {
	fill(ctx, &e)
	a.mu.Lock()
	a.entries = append(a.entries, e)
	a.mu.Unlock()
}

// RecordTx implements core.Audit.
func (a *Audit) RecordTx(ctx context.Context, _ *sql.Tx, e core.AuditEntry) error {
	a.Record(ctx, e)
	return nil
}

// Query implements core.Audit.
func (a *Audit) Query(context.Context, core.AuditQuery) (core.Page[core.AuditRecord], error) {
	return core.Page[core.AuditRecord]{}, ErrUnsupported
}

// Verify implements core.Audit.
func (a *Audit) Verify(context.Context) (*core.AuditVerify, error) {
	return nil, ErrUnsupported
}

// Export implements core.Audit.
func (a *Audit) Export(context.Context, core.AuditQuery, string, io.Writer) error {
	return ErrUnsupported
}

// Prune implements core.Audit.
func (a *Audit) Prune(context.Context, time.Time) (int, error) { return 0, ErrUnsupported }

// Entries returns the recorded entries with the given action ("" = all)
// and outcome ("" = any).
func (a *Audit) Entries(action, outcome string) []core.AuditEntry {
	a.mu.Lock()
	defer a.mu.Unlock()
	var out []core.AuditEntry
	for _, e := range a.entries {
		if (action == "" || e.Action == action) && (outcome == "" || e.Outcome == outcome) {
			out = append(out, e)
		}
	}
	return out
}

// Count returns len(Entries(action, outcome)).
func (a *Audit) Count(action, outcome string) int { return len(a.Entries(action, outcome)) }

var _ core.Audit = (*Audit)(nil)

// ---------- users ----------

// Users is a core.Users over the real users table, implementing what the
// auth packages use (lookups, create/bootstrap, password hash, lockout
// counters with auth.lockout_threshold / auth.lockout_base_min, profile
// updates, a minimal in-memory invitation flow and reads of the roles
// table; Env.AddRole and friends write roles). Other methods return
// ErrUnsupported.
type Users struct {
	env *core.Env

	mu      sync.Mutex
	invites map[string]*core.Invite // token → invite
}

const userColumns = `u.id, u.username, u.display_name, COALESCE(u.email, ''), u.role, u.status,
	COALESCE(u.password_hash, ''), u.password_changed_at, u.must_change_password, u.webauthn_handle, u.failed_logins,
	u.lock_level, u.locked_until, u.last_login_at, COALESCE(u.last_login_ip, ''), u.prefs, u.created_at, u.updated_at,
	u.role_id, r.name, r.permissions, r.delegable
	FROM users u LEFT JOIN roles r ON r.id = u.role_id`

// scanUser reads a userColumns row. The role fields are derived like the
// real users service does: RoleID (the custom role or the base), RoleName,
// Permissions (core.EffectiveRoleCaps; guestsShare applies to built-in
// guests) and RoleDelegable.
func scanUser(sc interface{ Scan(...any) error }, guestsShare bool) (*core.User, error) {
	var u core.User
	var changed, locked, last, delegable sql.NullInt64
	var must int64
	var prefs string
	var created, updated int64
	var roleID, roleName, perms sql.NullString
	if err := sc.Scan(&u.ID, &u.Username, &u.DisplayName, &u.Email, &u.Role, &u.Status, &u.PasswordHash, &changed,
		&must, &u.WebAuthnHandle, &u.FailedLogins, &u.LockLevel, &locked, &last, &u.LastLoginIP, &prefs,
		&created, &updated, &roleID, &roleName, &perms, &delegable); err != nil {
		if db.IsNoRows(err) {
			return nil, core.NotFoundf("user not found")
		}
		return nil, err
	}
	u.PasswordChangedAt, u.LockedUntil, u.LastLoginAt = db.FromNullMs(changed), db.FromNullMs(locked), db.FromNullMs(last)
	u.MustChangePassword = must != 0
	u.Prefs = json.RawMessage(prefs)
	u.CreatedAt, u.UpdatedAt = db.FromMs(created), db.FromMs(updated)
	if u.Role != core.RoleGuest {
		u.SpaceID = "spc_" + strings.TrimPrefix(u.ID, "usr_")
	}
	u.RoleID, u.RoleName = cmp.Or(roleID.String, string(u.Role)), cmp.Or(roleName.String, core.BuiltinRoleName(u.Role))
	u.Permissions = core.EffectiveRoleCaps(u.Role, u.RoleID, core.DecodeStoredCaps(perms.String), guestsShare)
	u.RoleDelegable = core.RoleDelegable(u.RoleID, delegable.Int64 != 0)
	return &u, nil
}

// guestsShare is sharing.allow_guests_share (false unless Put).
func (s *Users) guestsShare() bool {
	if _, err := s.env.Settings.Raw("sharing.allow_guests_share"); err != nil {
		return false
	}
	return s.env.Settings.Bool("sharing.allow_guests_share")
}

// Get implements core.Users.
func (s *Users) Get(ctx context.Context, id string) (*core.User, error) {
	return scanUser(s.env.DB.QueryRow(ctx, `SELECT `+userColumns+` WHERE u.id = ?`, id), s.guestsShare())
}

// GetByUsername implements core.Users.
func (s *Users) GetByUsername(ctx context.Context, username string) (*core.User, error) {
	return scanUser(s.env.DB.QueryRow(ctx, `SELECT `+userColumns+` WHERE u.username = ?`, username), s.guestsShare())
}

// List implements core.Users.
func (s *Users) List(context.Context, core.UserQuery) (core.Page[core.User], error) {
	return core.Page[core.User]{}, ErrUnsupported
}

// Count implements core.Users.
func (s *Users) Count(ctx context.Context) (int, error) {
	var n int
	err := s.env.DB.QueryRow(ctx, `SELECT COUNT(*) FROM users`).Scan(&n)
	return n, err
}

// Create implements core.Users.
func (s *Users) Create(ctx context.Context, _ *core.Principal, in core.NewUser) (*core.User, error) {
	if in.Username == "" {
		return nil, core.Invalid("username", "required")
	}
	if in.Role == "" {
		in.Role = core.RoleMember
	}
	now := s.env.Now()
	id := ids.New(ids.PrefixUser)
	err := s.env.DB.Tx(ctx, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `INSERT INTO users (id, username, display_name, email, role, status, password_hash,
			password_changed_at, must_change_password, webauthn_handle, created_at, updated_at)
			VALUES (?, ?, ?, ?, ?, 'active', ?, ?, ?, ?, ?, ?)`,
			id, in.Username, in.DisplayName, db.NullString(in.Email), in.Role, db.NullString(in.PasswordHash),
			db.Ms(now), db.Bool(in.MustChangePassword), crypt.RandomBytes(32), db.Ms(now), db.Ms(now))
		if db.IsUnique(err) {
			return core.Errorf(core.ErrConflict, "username or e-mail already taken")
		}
		return err
	})
	if err != nil {
		return nil, err
	}
	return s.Get(ctx, id)
}

// Bootstrap implements core.Users.
func (s *Users) Bootstrap(ctx context.Context, in core.NewUser) (*core.User, error) {
	if n, err := s.Count(ctx); err != nil || n > 0 {
		return nil, core.Errorf(core.ErrConflict, "users exist")
	}
	in.Role = core.RoleOwner
	return s.Create(ctx, nil, in)
}

// Update implements core.Users (display name, e-mail, prefs).
func (s *Users) Update(ctx context.Context, _ *core.Principal, id string, in core.UserUpdate) (*core.User, error) {
	if in.Role != nil || in.QuotaBytes.Set || in.MustChangePassword != nil {
		return nil, core.ErrForbidden
	}
	err := s.env.DB.Tx(ctx, func(tx *sql.Tx) error {
		if in.DisplayName != nil {
			if _, err := tx.ExecContext(ctx, `UPDATE users SET display_name = ? WHERE id = ?`, *in.DisplayName, id); err != nil {
				return err
			}
		}
		if in.Email != nil {
			if _, err := tx.ExecContext(ctx, `UPDATE users SET email = ? WHERE id = ?`, db.NullString(*in.Email), id); err != nil {
				return err
			}
		}
		if len(in.Prefs) > 0 {
			if _, err := tx.ExecContext(ctx, `UPDATE users SET prefs = ? WHERE id = ?`, string(in.Prefs), id); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return s.Get(ctx, id)
}

// SetPasswordHash implements core.Users.
func (s *Users) SetPasswordHash(ctx context.Context, _ *core.Principal, id, phc string, mustChange bool) error {
	_, err := s.env.DB.Exec(ctx, `UPDATE users SET password_hash = ?, password_changed_at = ?, must_change_password = ? WHERE id = ?`,
		phc, db.Ms(s.env.Now()), db.Bool(mustChange), id)
	return err
}

// SetPasswordHashTx is SetPasswordHash inside a transaction the caller owns
// (auth.txPasswordWriter), so the tests exercise the same single-transaction
// path as the real users service.
func (s *Users) SetPasswordHashTx(ctx context.Context, tx *sql.Tx, _ *core.Principal, id, phc string, mustChange bool) error {
	_, err := tx.ExecContext(ctx, `UPDATE users SET password_hash = ?, password_changed_at = ?, must_change_password = ? WHERE id = ?`,
		phc, db.Ms(s.env.Now()), db.Bool(mustChange), id)
	return err
}

// SetStatus implements core.Users.
func (s *Users) SetStatus(ctx context.Context, _ *core.Principal, id, status string) error {
	_, err := s.env.DB.Exec(ctx, `UPDATE users SET status = ? WHERE id = ?`, status, id)
	return err
}

// Delete implements core.Users.
func (s *Users) Delete(context.Context, *core.Principal, string, string) error {
	return ErrUnsupported
}

// RecordLoginFailure implements core.Users like the real service: after
// auth.lockout_threshold consecutive failures the account locks for
// auth.lockout_base_min × 2^lock_level minutes (max 24 h) and auth.lockout
// is audited; while a lock is active nothing changes and its end is
// returned.
func (s *Users) RecordLoginFailure(ctx context.Context, id string) (*time.Time, error) {
	var locked *time.Time
	err := s.env.DB.Tx(ctx, func(tx *sql.Tx) error {
		locked = nil
		var failed, level int64
		var until sql.NullInt64
		if err := tx.QueryRowContext(ctx, `SELECT failed_logins, lock_level, locked_until FROM users WHERE id = ?`, id).
			Scan(&failed, &level, &until); err != nil {
			return err
		}
		if t := db.FromNullMs(until); t != nil && s.env.Now().Before(*t) {
			locked = t
			return nil
		}
		failed++
		if failed < s.env.Settings.Int("auth.lockout_threshold") {
			_, err := tx.ExecContext(ctx, `UPDATE users SET failed_logins = ? WHERE id = ?`, failed, id)
			return err
		}
		d := time.Duration(s.env.Settings.Int("auth.lockout_base_min")) * time.Minute << min(level, 10)
		d = min(d, 24*time.Hour)
		end := s.env.Now().Add(d)
		locked = &end
		if _, err := tx.ExecContext(ctx, `UPDATE users SET failed_logins = 0, lock_level = ?, locked_until = ? WHERE id = ?`,
			level+1, db.Ms(end), id); err != nil {
			return err
		}
		return s.env.Audit.RecordTx(ctx, tx, core.AuditEntry{Action: core.ActAuthLockout, Outcome: core.OutcomeDenied,
			TargetType: "user", TargetID: id, Details: map[string]any{"locked_until": end}})
	})
	return locked, err
}

// RecordLoginSuccess implements core.Users.
func (s *Users) RecordLoginSuccess(ctx context.Context, id string, meta core.ReqMeta) error {
	_, err := s.env.DB.Exec(ctx, `UPDATE users SET failed_logins = 0, lock_level = 0, locked_until = NULL,
		last_login_at = ?, last_login_ip = ? WHERE id = ?`, db.Ms(s.env.Now()), meta.IP.String(), id)
	return err
}

// Unlock implements core.Users.
func (s *Users) Unlock(ctx context.Context, _ *core.Principal, id string) error {
	_, err := s.env.DB.Exec(ctx, `UPDATE users SET failed_logins = 0, locked_until = NULL WHERE id = ?`, id)
	return err
}

// Lookup implements core.Users.
func (s *Users) Lookup(context.Context, *core.Principal, string) ([]core.UserRef, error) {
	return nil, ErrUnsupported
}

// ListGroups implements core.Users.
func (s *Users) ListGroups(context.Context, core.PageReq) (core.Page[core.Group], error) {
	return core.Page[core.Group]{}, ErrUnsupported
}

// GetGroup implements core.Users.
func (s *Users) GetGroup(context.Context, string) (*core.Group, error) {
	return nil, ErrUnsupported
}

// CreateGroup implements core.Users.
func (s *Users) CreateGroup(context.Context, *core.Principal, core.GroupInput) (*core.Group, error) {
	return nil, ErrUnsupported
}

// UpdateGroup implements core.Users.
func (s *Users) UpdateGroup(context.Context, *core.Principal, string, core.GroupInput) (*core.Group, error) {
	return nil, ErrUnsupported
}

// DeleteGroup implements core.Users.
func (s *Users) DeleteGroup(context.Context, *core.Principal, string) error {
	return ErrUnsupported
}

// Members implements core.Users.
func (s *Users) Members(context.Context, string) ([]core.GroupMember, error) {
	return nil, ErrUnsupported
}

// SetMember implements core.Users.
func (s *Users) SetMember(context.Context, *core.Principal, string, string, string) error {
	return ErrUnsupported
}

// RemoveMember implements core.Users.
func (s *Users) RemoveMember(context.Context, *core.Principal, string, string) error {
	return ErrUnsupported
}

// GroupIDsOf implements core.Users.
func (s *Users) GroupIDsOf(context.Context, string) ([]string, error) { return nil, nil }

// MyGroups implements core.Users (one fixed group for every user).
func (s *Users) MyGroups(context.Context, *core.Principal) ([]core.Group, error) {
	return []core.Group{{ID: "grp_team", Name: "Team", SpaceID: "spc_team", MyRole: core.GroupRoleMember}}, nil
}

// AddInvite registers an invitation token (test helper).
func (s *Users) AddInvite(token string, role core.Role, expires time.Time) *core.Invite {
	inv := &core.Invite{ID: ids.New(ids.PrefixInvite), Role: role, GroupIDs: []string{"grp_secret"}, MaxUses: 1,
		ExpiresAt: expires, CreatedBy: "usr_admin", CreatedAt: s.env.Now(), Status: core.InviteActive, Note: "welcome",
		URL: "/invite/" + token}
	s.mu.Lock()
	s.invites[token] = inv
	s.mu.Unlock()
	return inv
}

// CreateInvite implements core.Users.
func (s *Users) CreateInvite(context.Context, *core.Principal, core.InviteInput) (*core.Invite, string, error) {
	return nil, "", ErrUnsupported
}

// ListInvites implements core.Users.
func (s *Users) ListInvites(context.Context, *core.Principal, core.PageReq) (core.Page[core.Invite], error) {
	return core.Page[core.Invite]{}, ErrUnsupported
}

// RevokeInvite implements core.Users.
func (s *Users) RevokeInvite(context.Context, *core.Principal, string) error {
	return ErrUnsupported
}

// LookupInvite implements core.Users.
func (s *Users) LookupInvite(_ context.Context, token string) (*core.Invite, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	inv, ok := s.invites[token]
	if !ok {
		return nil, core.NotFoundf("invitation not found")
	}
	c := *inv
	return &c, nil
}

// AcceptInvite implements core.Users.
func (s *Users) AcceptInvite(ctx context.Context, token string, in core.AcceptInvite, phc string, _ core.ReqMeta) (*core.User, error) {
	s.mu.Lock()
	inv, ok := s.invites[token]
	if ok && inv.Uses >= inv.MaxUses {
		ok = false
	}
	email := in.Email
	if ok && inv.Email != "" { // like users.AcceptInvite: the account gets the invited address
		if email != "" && !strings.EqualFold(email, inv.Email) {
			s.mu.Unlock()
			return nil, core.Invalid("email", "use the e-mail address the invitation was sent to")
		}
		email = inv.Email
	}
	if ok {
		inv.Uses++
	}
	s.mu.Unlock()
	if !ok {
		return nil, core.NotFoundf("invitation not found")
	}
	u, err := s.Create(ctx, nil, core.NewUser{Username: in.Username, DisplayName: in.DisplayName, Email: email,
		Role: inv.Role, PasswordHash: phc})
	if err != nil {
		s.mu.Lock()
		inv.Uses--
		s.mu.Unlock()
		return nil, err
	}
	return u, nil
}

// ---------- roles (reads over the roles table; changes are not supported) ----------

// roleColumns selects a roles row (alias r) for scanRoleDef.
const roleColumns = `r.id, r.name, r.description, r.base, r.permissions, r.delegable,
	(SELECT count(*) FROM users u WHERE u.role_id = r.id) FROM roles r`

// scanRoleDef reads a roleColumns row like package users does (permissions
// with the closure applied; Staff; UserCount; no group or grant counts).
func scanRoleDef(sc interface{ Scan(...any) error }) (*core.RoleDef, error) {
	var r core.RoleDef
	var base, perms string
	var delegable int64
	if err := sc.Scan(&r.ID, &r.Name, &r.Description, &base, &perms, &delegable, &r.UserCount); err != nil {
		if db.IsNoRows(err) {
			return nil, core.NotFoundf("role not found")
		}
		return nil, err
	}
	r.Base = core.Role(base)
	r.Permissions = core.EffectiveRoleCaps(r.Base, r.ID, core.DecodeStoredCaps(perms), false)
	r.Delegable, r.Staff = delegable != 0, r.Permissions.Server() != 0
	return &r, nil
}

// ListRoles implements core.Users: the built-in roles, then the custom
// roles by name (Editable and Assignable are not filled).
func (s *Users) ListRoles(ctx context.Context, _ *core.Principal) ([]core.RoleDef, error) {
	out := core.BuiltinRoles(s.guestsShare())
	rows, err := s.env.DB.Query(ctx, `SELECT `+roleColumns+` ORDER BY r.name COLLATE NOCASE, r.id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		r, err := scanRoleDef(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *r)
	}
	return out, rows.Err()
}

// GetRole implements core.Users: a built-in word or a custom role id.
func (s *Users) GetRole(ctx context.Context, _ *core.Principal, id string) (*core.RoleDef, error) {
	for _, r := range core.BuiltinRoles(s.guestsShare()) {
		if r.ID == id {
			return &r, nil
		}
	}
	return scanRoleDef(s.env.DB.QueryRow(ctx, `SELECT `+roleColumns+` WHERE r.id = ?`, id))
}

// CreateRole implements core.Users (use Env.AddRole).
func (s *Users) CreateRole(context.Context, *core.Principal, core.RoleDefInput) (*core.RoleDef, error) {
	return nil, ErrUnsupported
}

// UpdateRole implements core.Users (use Env.SetRolePermissions).
func (s *Users) UpdateRole(context.Context, *core.Principal, string, core.RoleDefUpdate) (*core.RoleDef, error) {
	return nil, ErrUnsupported
}

// DeleteRole implements core.Users.
func (s *Users) DeleteRole(context.Context, *core.Principal, string, string) error {
	return ErrUnsupported
}

// LookupRoles implements core.Users (every caller may search).
func (s *Users) LookupRoles(ctx context.Context, _ *core.Principal) ([]core.RoleRef, error) {
	rows, err := s.env.DB.Query(ctx, `SELECT id, name, description FROM roles ORDER BY name COLLATE NOCASE, id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []core.RoleRef{}
	for rows.Next() {
		var r core.RoleRef
		if err := rows.Scan(&r.ID, &r.Name, &r.Description); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// RoleGroups implements core.Users (this double has no groups).
func (s *Users) RoleGroups(context.Context, string) ([]core.RoleGroup, error) {
	return []core.RoleGroup{}, nil
}

// SetRoleGroup implements core.Users.
func (s *Users) SetRoleGroup(context.Context, *core.Principal, string, string, string) (*core.RoleGroup, error) {
	return nil, ErrUnsupported
}

// RemoveRoleGroup implements core.Users.
func (s *Users) RemoveRoleGroup(context.Context, *core.Principal, string, string) error {
	return ErrUnsupported
}

// GroupsOf implements core.Users (this double has no groups, like GroupIDsOf).
func (s *Users) GroupsOf(context.Context, string) ([]core.AccessGroup, error) {
	return []core.AccessGroup{}, nil
}

var _ core.Users = (*Users)(nil)

// ErrUnsupported is returned by the methods of the test doubles that the
// auth packages never call.
var ErrUnsupported = errors.New("authtest: not supported by this test double")

// ErrNoCredential is returned by the Authenticator when it holds no
// credential usable for the request.
var ErrNoCredential = errors.New("authtest: no matching credential")
