// Package users manages accounts, groups, memberships, invites, quotas and
// the personal/group space bootstrap (DESIGN §5.1b, §6). Owned by unit C.
//
// # Spaces
//
// Creating an owner, admin or member account inserts its personal space
// (spaces.kind = 'user', name "My files") and the space's root folder node
// (parent_id NULL, name "My files"). Guests have no personal space: demoting
// a user to guest removes the (empty) personal space, promoting a guest
// creates one. CreateGroup inserts the group's space ("Team folder",
// spaces.kind = 'group') whose root folder is named after the group; renaming
// the group renames the space and its root. The files service never lets
// users rename or delete a root.
//
// # Role rules (DESIGN §6a)
//
// Every account has one role: a built-in one (owner, admin, member, guest)
// or a custom role based on member or guest (roles.go). Changes are
// authorized by permission, then by the escalation rules of package core:
//
//   - users.manage creates, edits, disables, enables, unlocks and deletes
//     accounts and gives roles; users.credentials resets passwords and
//     second factors (moving another person's files on delete needs it too);
//     invites.manage handles invitations; groups.manage handles groups,
//     memberships and role → group memberships, and initial group_ids of
//     accounts and invitations. Everyone may change their own display name,
//     e-mail and preferences.
//   - core.CheckManage decides who may act on an account: only owners touch
//     owners; owners and admins act on everyone else; a delegate (a
//     non-admin holding one of these permissions) acts only on accounts with
//     a delegable role whose server permissions it holds itself — never on
//     admins, and never on its own role, quota or password policy.
//   - core.CheckAssign decides who may give which role: only owners give the
//     owner role; a delegate gives only Member, Guest and delegable custom
//     roles whose server permissions it holds itself.
//   - Roles themselves are created, edited and deleted by built-in owners and
//     admins only.
//   - Nobody changes their own role, disables or deletes their own account;
//     at least one active owner always remains (the last one cannot be
//     demoted, disabled or deleted).
//
// Checks run inside the write transaction against fresh rows. A refusal by
// the escalation rules is audited as the attempted action with outcome
// denied after the transaction rolled back (auditDenied). Role changes
// publish authz.changed after commit.
//
// # Quotas
//
// users.quota_bytes: NULL = storage.default_quota_gb, 0 = unlimited,
// >0 = limit. The value is mirrored into the personal space's quota_bytes so
// the files service can read either; files and uploads resolve the default
// and enforce the limit.
//
// # Invites
//
// Invite tokens carry 192 random bits (ids.Token(24)); the database stores
// SHA-256(token) for lookups and the field-encrypted token (AAD
// "invites.token_enc|<id>") so administrators can copy an active link again.
// AcceptInvite validates the invite and creates the account atomically; the
// argon2id hash of the new password is computed by the caller (auth).
//
// # Auditing
//
// State changes record the §9.6 actions inside their transaction
// (user.create/update/delete/disable/enable/unlock, auth.lockout,
// group.*, invite.*, role.*). Password changes are audited by the auth service,
// which knows whether SetPasswordHash is a change, a reset or a rehash.
package users

import (
	"cmp"
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"log/slog"
	"strings"
	"sync"
	"time"

	"fileparcel/internal/core"
	"fileparcel/internal/db"
	"fileparcel/internal/ids"
)

// Setting keys read (not owned) by this package.
const (
	settingLockoutThreshold = "auth.lockout_threshold" // registered by auth
	settingLockoutBaseMin   = "auth.lockout_base_min"  // registered by auth
)

// Defaults used when the settings above are unavailable.
const (
	defaultLockoutThreshold = 10
	defaultLockoutBaseMin   = 15
	maxLockout              = 24 * time.Hour
)

// PersonalSpaceName is the name of every personal space and its root folder.
const PersonalSpaceName = "My files"

// Service implements core.Users.
type Service struct {
	env *core.Env
	log *slog.Logger

	mu      sync.RWMutex
	notify  core.Notify  // optional (Bind)
	network core.Network // optional (Bind): absolute URLs for e-mails
}

var (
	_ core.Users  = (*Service)(nil)
	_ core.Binder = (*Service)(nil)
)

// New creates the service (constructor signature fixed by DESIGN §5.2).
func New(env *core.Env) (*Service, error) {
	if env == nil || env.DB == nil {
		return nil, errors.New("users: env with a database required")
	}
	log := env.Log
	if log == nil {
		log = slog.Default()
	}
	return &Service{env: env, log: log.With("component", "users")}, nil
}

// Bind picks up the optional Notify (invite and security e-mails) and Network
// (absolute links) services (core.Binder).
func (s *Service) Bind(reg *core.Services) error {
	if reg == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.notify = reg.Notify
	s.network = reg.Network
	return nil
}

func (s *Service) notifier() core.Notify {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.notify == nil || !s.notify.Enabled() {
		return nil
	}
	return s.notify
}

// ---------- helpers ----------

type queryer interface {
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
}

type scanner interface{ Scan(dest ...any) error }

func (s *Service) now() time.Time { return s.env.Now() }

// auditTx records e inside tx (errors abort the caller's transaction so an
// audited change is never committed without its entry).
func (s *Service) auditTx(ctx context.Context, tx *sql.Tx, e core.AuditEntry) error {
	if s.env.Audit == nil {
		return nil
	}
	return s.env.Audit.RecordTx(ctx, tx, e)
}

// auditByTx records e with the acting principal by as the actor (the context
// principal may be missing or differ, e.g. for in-process callers).
func (s *Service) auditByTx(ctx context.Context, tx *sql.Tx, by *core.Principal, e core.AuditEntry) error {
	if by != nil && e.ActorID == "" && e.ActorName == "" {
		e.ActorID, e.ActorName, e.ActorVia = by.UserID, by.Username, string(by.Via)
		if by.IP.IsValid() && e.IP == "" {
			e.IP = by.IP.String()
		}
		if e.UserAgent == "" {
			e.UserAgent = by.UserAgent
		}
		if e.RequestID == "" {
			e.RequestID = by.RequestID
		}
	}
	return s.auditTx(ctx, tx, e)
}

// actorID returns the principal's user id ("" for system/anonymous).
func actorID(p *core.Principal) string {
	if p == nil {
		return ""
	}
	return p.UserID
}

// likeEscape escapes LIKE wildcards (ESCAPE '\').
func likeEscape(s string) string {
	return strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`).Replace(s)
}

// errUserNotFound is the 404 of a missing account.
func errUserNotFound() error { return core.NotFoundf("user not found") }

// conflictField returns a 409 conflict on a field.
func conflictField(field, msg string) error {
	return &core.Error{Code: core.ErrConflict.Code, Status: core.ErrConflict.Status, Message: msg, Field: field}
}

// ---------- cursors ----------

// cursor is the keyset position of the paginated lists (opaque base64url JSON).
type cursor struct {
	S string `json:"s,omitempty"` // string sort key
	N int64  `json:"n,omitempty"` // numeric sort key
	I string `json:"i"`           // id tie-breaker
}

func encodeCursor(c cursor) string {
	b, _ := json.Marshal(c)
	return base64.RawURLEncoding.EncodeToString(b)
}

func decodeCursor(s string) (cursor, error) {
	var c cursor
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil || len(b) == 0 || json.Unmarshal(b, &c) != nil || c.I == "" {
		return cursor{}, core.Invalid("cursor", "invalid cursor")
	}
	return c, nil
}

// ---------- users: reads ----------

// userCols selects a users row (alias u) plus the derived personal space id,
// the MFA flag and the custom role (id, name, stored permissions, delegable;
// sub-selects, so that every FROM clause stays "users u").
const userCols = `u.id, u.username, u.display_name, u.email, u.role, u.status, u.password_hash,
	u.password_changed_at, u.must_change_password, u.webauthn_handle, u.quota_bytes, u.failed_logins,
	u.lock_level, u.locked_until, u.last_login_at, u.last_login_ip, u.prefs, u.created_at, u.updated_at,
	u.created_by,
	(SELECT sp.id FROM spaces sp WHERE sp.owner_user_id = u.id AND sp.kind = 'user'),
	(EXISTS (SELECT 1 FROM totp_secrets t WHERE t.user_id = u.id AND t.confirmed_at IS NOT NULL)
	 OR EXISTS (SELECT 1 FROM webauthn_credentials w WHERE w.user_id = u.id)),
	u.role_id,
	(SELECT r.name FROM roles r WHERE r.id = u.role_id),
	(SELECT r.permissions FROM roles r WHERE r.id = u.role_id),
	(SELECT r.delegable FROM roles r WHERE r.id = u.role_id)`

// scanUser reads a userCols row. The role fields are derived: RoleID (the
// custom role, else the base), RoleName, Permissions (core.EffectiveRoleCaps
// without sharing.allow_guests_share, which the public getters add with
// withGuestSharing) and RoleDelegable.
func scanUser(sc scanner) (*core.User, error) {
	var (
		u                                          core.User
		role, prefs                                string
		email, phc, lastIP, createdBy, spaceID     sql.NullString
		pwChanged, quota, lockedUntil, lastLoginAt sql.NullInt64
		mustChange, mfa                            int64
		created, updated                           int64
		roleID, roleName, rolePerms                sql.NullString
		roleDelegable                              sql.NullInt64
	)
	err := sc.Scan(&u.ID, &u.Username, &u.DisplayName, &email, &role, &u.Status, &phc,
		&pwChanged, &mustChange, &u.WebAuthnHandle, &quota, &u.FailedLogins,
		&u.LockLevel, &lockedUntil, &lastLoginAt, &lastIP, &prefs, &created, &updated,
		&createdBy, &spaceID, &mfa, &roleID, &roleName, &rolePerms, &roleDelegable)
	if err != nil {
		return nil, err
	}
	u.Email = email.String
	u.Role = core.Role(role)
	u.RoleID = cmp.Or(roleID.String, role)
	u.RoleName = cmp.Or(roleName.String, core.BuiltinRoleName(u.Role))
	u.Permissions = core.EffectiveRoleCaps(u.Role, u.RoleID, core.DecodeStoredCaps(rolePerms.String), false)
	u.RoleDelegable = core.RoleDelegable(u.RoleID, roleDelegable.Int64 != 0)
	u.PasswordHash = phc.String
	u.PasswordChangedAt = db.FromNullMs(pwChanged)
	u.MustChangePassword = mustChange != 0
	u.QuotaBytes = db.FromNullInt64(quota)
	u.LockedUntil = db.FromNullMs(lockedUntil)
	u.LastLoginAt = db.FromNullMs(lastLoginAt)
	u.LastLoginIP = lastIP.String
	if json.Valid([]byte(prefs)) {
		u.Prefs = json.RawMessage(prefs)
	} else {
		u.Prefs = json.RawMessage(`{}`)
	}
	u.CreatedAt = db.FromMs(created)
	u.UpdatedAt = db.FromMs(updated)
	u.CreatedBy = createdBy.String
	u.SpaceID = spaceID.String
	u.MFAEnabled = mfa != 0
	return &u, nil
}

// getUser loads one account by id through q (reader pool or a transaction).
func getUser(ctx context.Context, q queryer, id string) (*core.User, error) {
	u, err := scanUser(q.QueryRowContext(ctx, `SELECT `+userCols+` FROM users u WHERE u.id = ?`, id))
	if db.IsNoRows(err) {
		return nil, errUserNotFound()
	}
	return u, err
}

// Get returns the account with id (404 when missing).
func (s *Service) Get(ctx context.Context, id string) (*core.User, error) {
	if id == "" {
		return nil, errUserNotFound()
	}
	u, err := getUser(ctx, s.env.DB.Reader(), id)
	return s.withGuestSharing(u), err
}

// GetByUsername returns the account with username (case-insensitive; 404 when missing).
func (s *Service) GetByUsername(ctx context.Context, username string) (*core.User, error) {
	username = strings.TrimSpace(username)
	if username == "" || len(username) > maxUsernameLen {
		return nil, errUserNotFound()
	}
	u, err := scanUser(s.env.DB.QueryRow(ctx, `SELECT `+userCols+` FROM users u WHERE u.username = ?`, username))
	if db.IsNoRows(err) {
		return nil, errUserNotFound()
	}
	return s.withGuestSharing(u), err
}

// User list sort orders (UserQuery.Sort).
const (
	SortUsername  = "username" // default
	SortCreated   = "created"
	SortLastLogin = "last_login"
)

// List returns accounts matching q, keyset-paginated. Q matches username,
// display name and e-mail (substring, case-insensitive); Role filters the
// base, RoleID the role (a built-in word: plain holders only; "rol_…": the
// custom role); Sort is username (default), created or last_login; Desc
// reverses.
func (s *Service) List(ctx context.Context, q core.UserQuery) (core.Page[core.User], error) {
	var conds []string
	var args []any
	if t := strings.TrimSpace(q.Q); t != "" {
		if len(t) > 200 {
			return core.Page[core.User]{}, core.Invalid("q", "search text is too long")
		}
		p := "%" + likeEscape(t) + "%"
		conds = append(conds, `(u.username LIKE ? ESCAPE '\' OR u.display_name LIKE ? ESCAPE '\' OR u.email LIKE ? ESCAPE '\')`)
		args = append(args, p, p, p)
	}
	if q.Role != "" {
		if !q.Role.Valid() {
			return core.Page[core.User]{}, core.Invalid("role", "role must be owner, admin, member or guest")
		}
		conds = append(conds, "u.role = ?")
		args = append(args, string(q.Role))
	}
	switch rid := strings.TrimSpace(q.RoleID); {
	case rid == "":
	case core.Role(rid).Valid(): // plain holders of the built-in role
		conds = append(conds, "u.role = ? AND u.role_id IS NULL")
		args = append(args, rid)
	case ids.Valid(ids.PrefixRole, rid):
		conds = append(conds, "u.role_id = ?")
		args = append(args, rid)
	default:
		return core.Page[core.User]{}, core.Invalid("role_id", "unknown role")
	}
	if q.Status != "" {
		if q.Status != core.UserActive && q.Status != core.UserDisabled {
			return core.Page[core.User]{}, core.Invalid("status", "status must be active or disabled")
		}
		conds = append(conds, "u.status = ?")
		args = append(args, q.Status)
	}
	var key string
	numeric := false
	switch q.Sort {
	case "", SortUsername, "name":
		key = "u.username"
	case SortCreated:
		key, numeric = "u.created_at", true
	case SortLastLogin:
		key, numeric = "COALESCE(u.last_login_at, 0)", true
	default:
		return core.Page[core.User]{}, core.Invalid("sort", "sort must be username, created or last_login")
	}
	order, cmp := "ASC", ">"
	if q.Desc {
		order, cmp = "DESC", "<"
	}
	if q.Cursor != "" {
		c, err := decodeCursor(q.Cursor)
		if err != nil {
			return core.Page[core.User]{}, err
		}
		var k any = c.S
		if numeric {
			k = c.N
		}
		conds = append(conds, "("+key+" "+cmp+" ? OR ("+key+" = ? AND u.id "+cmp+" ?))")
		args = append(args, k, k, c.I)
	}
	where := ""
	if len(conds) > 0 {
		where = " WHERE " + strings.Join(conds, " AND ")
	}
	limit := q.EffectiveLimit()
	args = append(args, limit+1)
	rows, err := s.env.DB.Query(ctx, `SELECT `+userCols+` FROM users u`+where+
		` ORDER BY `+key+` `+order+`, u.id `+order+` LIMIT ?`, args...)
	if err != nil {
		return core.Page[core.User]{}, err
	}
	defer rows.Close()
	var out []core.User
	for rows.Next() {
		u, err := scanUser(rows)
		if err != nil {
			return core.Page[core.User]{}, err
		}
		out = append(out, *s.withGuestSharing(u))
	}
	if err := rows.Err(); err != nil {
		return core.Page[core.User]{}, err
	}
	next := ""
	if len(out) > limit {
		out = out[:limit]
		last := out[len(out)-1]
		c := cursor{I: last.ID}
		switch q.Sort {
		case SortCreated:
			c.N = db.Ms(last.CreatedAt)
		case SortLastLogin:
			if last.LastLoginAt != nil {
				c.N = db.Ms(*last.LastLoginAt)
			}
		default:
			c.S = last.Username
		}
		next = encodeCursor(c)
	}
	return core.NewPage(out, next), nil
}

// Count returns the number of accounts (any role or status).
func (s *Service) Count(ctx context.Context) (int, error) {
	var n int
	err := s.env.DB.QueryRow(ctx, `SELECT count(*) FROM users`).Scan(&n)
	return n, err
}

// Lookup finds active accounts for share and grant pickers: at least 2
// characters matched against username and display name (substring,
// case-insensitive) or an exact e-mail address. At most 20 results, exact and
// prefix username matches first. It needs users.lookup or users.view (the
// built-in Guest role has neither).
func (s *Service) Lookup(ctx context.Context, p *core.Principal, q string) ([]core.UserRef, error) {
	if err := requireDirectory(p); err != nil {
		return nil, err
	}
	q = strings.TrimSpace(q)
	if len([]rune(q)) < 2 {
		return nil, core.Invalid("q", "enter at least 2 characters")
	}
	if len(q) > 100 {
		return nil, core.Invalid("q", "search text is too long")
	}
	sub := "%" + likeEscape(q) + "%"
	prefix := likeEscape(q) + "%"
	rows, err := s.env.DB.Query(ctx, `SELECT id, username, display_name FROM users
		WHERE status = 'active' AND (username LIKE ? ESCAPE '\' OR display_name LIKE ? ESCAPE '\' OR email = ?)
		ORDER BY CASE WHEN username = ? THEN 0 WHEN username LIKE ? ESCAPE '\' THEN 1 ELSE 2 END, username, id
		LIMIT 20`, sub, sub, q, q, prefix)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []core.UserRef{}
	for rows.Next() {
		var r core.UserRef
		if err := rows.Scan(&r.ID, &r.Username, &r.DisplayName); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}
