package users

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"fileparcel/internal/core"
	"fileparcel/internal/crypt"
	"fileparcel/internal/db"
	"fileparcel/internal/ids"
)

// webAuthnHandleLen is the size of the random WebAuthn user handle.
const webAuthnHandleLen = 32

// ---------- authorization helpers ----------

// requireCap fails unless by may use capability c (core.Principal.Can: API
// tokens need the admin scope for server permissions): 401 without a
// principal, else 403 `this needs the “<Label>” permission`.
func requireCap(by *core.Principal, c core.Capability) error {
	switch {
	case by == nil:
		return core.ErrUnauthorized
	case !by.Can(c):
		return core.NeedPermission(c)
	}
	return nil
}

// requireGroupsFor fails with 403 on field group_ids unless by may add
// people to groups (groups.manage): initial memberships of new accounts and
// invitations would otherwise bypass group management.
func requireGroupsFor(by *core.Principal, groupIDs []string) error {
	if len(groupIDs) == 0 || by.Can(core.CapGroupsManage) {
		return nil
	}
	return &core.Error{Code: core.ErrForbidden.Code, Status: core.ErrForbidden.Status, Field: "group_ids",
		Message: "adding people to groups needs the “Manage groups” permission"}
}

// requireQuotaFor fails with 403 on field quota_bytes unless by may set a
// storage quota (users.manage): an invitation that names one would
// otherwise give an "Invite people" delegate a quota — unlimited included —
// it could never set on an account. Without a quota the server default
// applies, which needs no permission.
func requireQuotaFor(by *core.Principal, quota *int64) error {
	if quota == nil || by.Can(core.CapUsersManage) {
		return nil
	}
	return &core.Error{Code: core.ErrForbidden.Code, Status: core.ErrForbidden.Status, Field: "quota_bytes",
		Message: "setting a storage quota needs the “Manage accounts” permission"}
}

// errTransferNeedsCredentials refuses a delegate who would move another
// person's files on delete without users.credentials: that is file access
// without any right to the account's sign-in. It is an escalation refusal
// (audited as denied).
func errTransferNeedsCredentials() error {
	const msg = "moving another person's files needs the “Reset sign-in” permission"
	return core.Wrap(core.ErrForbidden, msg,
		&core.EscalationError{Reason: msg, Missing: []core.Capability{core.CapUsersCredentials}})
}

// errTransferToSelf refuses a delegate who would move the files of the
// account being deleted into their own account (CheckManage refuses the
// destination anyway — a delegate never manages their own account — but
// with a message about changing one's own account). An escalation refusal
// (audited as denied).
func errTransferToSelf() error {
	const msg = "you cannot move another person's files to your own account; ask an administrator"
	return core.Wrap(core.ErrForbidden, msg, &core.EscalationError{Reason: msg})
}

// auditDenied records a refused escalation (DESIGN §6a) as action with
// outcome denied and details {"reason", "missing"}, attributed to by. It is
// called after the transaction rolled back (Audit.Record, not RecordTx) and
// is a no-op unless err carries a *core.EscalationError: plain permission
// refusals are not audited (the UI never offers them).
func (s *Service) auditDenied(ctx context.Context, by *core.Principal, action, targetType, targetID, targetName string, err error) {
	esc := core.AsEscalation(err)
	if esc == nil || by == nil || s.env.Audit == nil {
		return
	}
	details := map[string]any{"reason": esc.Reason}
	if len(esc.Missing) > 0 {
		details["missing"] = esc.Missing
	}
	e := core.AuditEntry{Action: action, Outcome: core.OutcomeDenied, TargetType: targetType, TargetID: targetID,
		TargetName: targetName, Details: details, ActorID: by.UserID, ActorName: by.Username, ActorVia: string(by.Via),
		UserAgent: by.UserAgent, RequestID: by.RequestID}
	if by.IP.IsValid() {
		e.IP = by.IP.String()
	}
	s.env.Audit.Record(ctx, e)
}

// auditDeniedUser is auditDenied for an action on the account u (nil: the
// refusal came before the account was loaded, nothing to record).
func (s *Service) auditDeniedUser(ctx context.Context, by *core.Principal, action string, u *core.User, err error) {
	if u != nil {
		s.auditDenied(ctx, by, action, "user", u.ID, u.Username, err)
	}
}

// otherActiveOwners counts active owners other than excludeID.
func otherActiveOwners(ctx context.Context, q queryer, excludeID string) (int, error) {
	var n int
	err := q.QueryRowContext(ctx, `SELECT count(*) FROM users WHERE role = 'owner' AND status = 'active' AND id <> ?`, excludeID).Scan(&n)
	return n, err
}

var errLastOwner = core.Errorf(core.ErrConflict, "at least one active owner must remain")

// ---------- create ----------

// insertOpts tunes insertUser.
type insertOpts struct {
	createdBy    string // users.created_by ("" = NULL)
	strictGroups bool   // unknown group ids are an error (else skipped)
}

// insertUser inserts an account (+ personal space unless its base is guest,
// + group memberships) inside tx. id must be fresh; f.role is the base and
// f.roleID the custom role ("" for built-in roles).
func insertUser(ctx context.Context, tx *sql.Tx, id string, f *userFields, o insertOpts, now int64) error {
	var exists int
	err := tx.QueryRowContext(ctx, `SELECT 1 FROM users WHERE username = ?`, f.username).Scan(&exists)
	switch {
	case err == nil:
		return conflictField("username", fmt.Sprintf("the username %q is already taken", f.username))
	case !db.IsNoRows(err):
		return err
	}
	if f.email != "" {
		err := tx.QueryRowContext(ctx, `SELECT 1 FROM users WHERE email = ?`, f.email).Scan(&exists)
		switch {
		case err == nil:
			return conflictField("email", "this e-mail address is already used by another account")
		case !db.IsNoRows(err):
			return err
		}
	}
	var pwChanged sql.NullInt64
	if f.phc != "" {
		pwChanged = sql.NullInt64{Int64: now, Valid: true}
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO users (id, username, display_name, email, role, role_id, status,
		password_hash, password_changed_at, must_change_password, webauthn_handle, quota_bytes,
		prefs, created_at, updated_at, created_by)
		VALUES (?, ?, ?, ?, ?, ?, 'active', ?, ?, ?, ?, ?, '{}', ?, ?, ?)`,
		id, f.username, f.displayName, db.NullString(f.email), string(f.role), db.NullString(f.roleID),
		db.NullString(f.phc), pwChanged, db.Bool(f.mustChange), crypt.RandomBytes(webAuthnHandleLen),
		db.NullInt64(f.quota), now, now, db.NullString(o.createdBy))
	if err != nil {
		if db.IsUnique(err) {
			return core.Wrap(core.ErrConflict, "the username or e-mail address is already taken", err)
		}
		return fmt.Errorf("users: insert user: %w", err)
	}
	if f.role != core.RoleGuest {
		if _, err := createPersonalSpace(ctx, tx, id, f.quota, o.createdBy, now); err != nil {
			return err
		}
	}
	for _, g := range f.groupIDs {
		res, err := tx.ExecContext(ctx, `INSERT INTO group_members (group_id, user_id, role, added_at)
			SELECT id, ?, 'member', ? FROM groups WHERE id = ? ON CONFLICT DO NOTHING`, id, now, g)
		if err != nil {
			return fmt.Errorf("users: add membership: %w", err)
		}
		if n, _ := res.RowsAffected(); n == 0 && o.strictGroups {
			return core.Invalid("group_ids", fmt.Sprintf("group %s does not exist", g))
		}
	}
	return nil
}

// Create creates an account (and its personal space unless its base is
// guest) with the password hash in in.PasswordHash (in.Password is ignored).
// It needs users.manage; the role (in.Role / in.RoleID, default member)
// must pass core.CheckAssign — only owners create owners, and a delegate
// gives only roles it may hand out —, and initial groups need
// groups.manage. A refused escalation is audited as denied.
func (s *Service) Create(ctx context.Context, by *core.Principal, in core.NewUser) (*core.User, error) {
	if err := requireCap(by, core.CapUsersManage); err != nil {
		return nil, err
	}
	f, err := validateNewUser(in)
	if err != nil {
		return nil, err
	}
	if err := requireGroupsFor(by, f.groupIDs); err != nil {
		return nil, err
	}
	var id string
	err = s.env.DB.Tx(ctx, func(tx *sql.Tx) error {
		to, err := resolveAssignment(ctx, tx, in.Role, in.RoleID)
		if err != nil {
			return err
		}
		if err := core.CheckAssign(by, core.AssignCheck{To: to}); err != nil {
			return err
		}
		uf := *f
		uf.role, uf.roleID = to.Base, customRoleID(to)
		id = ids.New(ids.PrefixUser)
		now := db.Ms(s.now())
		if err := insertUser(ctx, tx, id, &uf, insertOpts{createdBy: actorID(by), strictGroups: true}, now); err != nil {
			return err
		}
		return s.auditByTx(ctx, tx, by, core.AuditEntry{
			Action: core.ActUserCreate, TargetType: "user", TargetID: id, TargetName: uf.username,
			Details: map[string]any{"role": uf.role, "role_id": to.ID, "role_name": to.Name, "email": uf.email,
				"groups": uf.groupIDs, "quota_bytes": uf.quota},
		})
	})
	if err != nil {
		s.auditDenied(ctx, by, core.ActUserCreate, "user", "", f.username, err)
		return nil, err
	}
	return s.Get(ctx, id)
}

// Bootstrap creates the first owner account; it fails with ErrConflict when
// any account exists. The role is always owner.
func (s *Service) Bootstrap(ctx context.Context, in core.NewUser) (*core.User, error) {
	in.Role = core.RoleOwner
	f, err := validateNewUser(in)
	if err != nil {
		return nil, err
	}
	var id string
	err = s.env.DB.Tx(ctx, func(tx *sql.Tx) error {
		var n int
		if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM users`).Scan(&n); err != nil {
			return err
		}
		if n > 0 {
			return core.Errorf(core.ErrConflict, "setup has already been completed")
		}
		id = ids.New(ids.PrefixUser)
		if err := insertUser(ctx, tx, id, f, insertOpts{strictGroups: true}, db.Ms(s.now())); err != nil {
			return err
		}
		e := core.AuditEntry{
			Action: core.ActUserCreate, TargetType: "user", TargetID: id, TargetName: f.username,
			Details: map[string]any{"role": core.RoleOwner, "bootstrap": true},
		}
		if core.PrincipalFrom(ctx) == nil {
			e.ActorID, e.ActorName = id, f.username
		}
		return s.auditTx(ctx, tx, e)
	})
	if err != nil {
		return nil, err
	}
	return s.Get(ctx, id)
}

// ---------- update ----------

// Update applies a partial change. Everyone may change their own display
// name, e-mail and preferences. The admin fields (Role, RoleID, QuotaBytes,
// MustChangePassword) and every change to another account need
// users.manage and core.CheckManage — a delegate never changes their own
// role, quota or password policy —; a role change also needs
// core.CheckAssign. RoleID gives a role (a built-in word or "rol_…"; Role
// must then be absent or its base); Role alone gives that built-in role and
// removes any custom role. Role changes keep the personal space consistent
// with the base (created when leaving guest, removed — when empty — when
// becoming guest-based), close the account's step-up window and publish
// authz.changed. A refused escalation is audited as denied.
func (s *Service) Update(ctx context.Context, by *core.Principal, id string, in core.UserUpdate) (*core.User, error) {
	if by == nil {
		return nil, core.ErrUnauthorized
	}
	self := by.UserID != "" && by.UserID == id
	adminFields := in.Role != nil || in.RoleID != nil || in.QuotaBytes.Set || in.MustChangePassword != nil
	if adminFields || !self {
		if err := requireCap(by, core.CapUsersManage); err != nil {
			return nil, err
		}
	}
	// Validate inputs before opening the transaction.
	var displayName, email, prefs *string
	if in.DisplayName != nil {
		v, err := cleanDisplayName(*in.DisplayName)
		if err != nil {
			return nil, err
		}
		if v == "" {
			return nil, core.Invalid("display_name", "display name must not be empty")
		}
		displayName = &v
	}
	if in.Email != nil {
		v, err := cleanEmail(*in.Email)
		if err != nil {
			return nil, err
		}
		email = &v
	}
	if in.Prefs != nil {
		v, err := cleanPrefs(in.Prefs)
		if err != nil {
			return nil, err
		}
		prefs = &v
	}
	var quota *int64
	if in.QuotaBytes.Set && !in.QuotaBytes.Null {
		q, err := cleanQuota(&in.QuotaBytes.V, "quota_bytes")
		if err != nil {
			return nil, err
		}
		quota = q
	}
	if in.Role != nil && !in.Role.Valid() {
		return nil, core.Invalid("role", "role must be owner, admin, member or guest")
	}

	var cur *core.User
	roleChanged := false
	err := s.env.DB.Tx(ctx, func(tx *sql.Tx) error {
		roleChanged = false
		var err error
		if cur, err = getUser(ctx, tx, id); err != nil {
			return err
		}
		if !self || adminFields {
			if err := core.CheckManage(by, cur, core.CapUsersManage); err != nil {
				return err
			}
		}
		var to *core.RoleDef
		switch {
		case in.RoleID != nil:
			role := core.Role("")
			if in.Role != nil {
				role = *in.Role
			}
			if to, err = resolveAssignment(ctx, tx, role, *in.RoleID); err != nil {
				return err
			}
		case in.Role != nil:
			to = builtinRole(*in.Role)
		}
		now := db.Ms(s.now())
		var sets []string
		var args []any
		changes := map[string]any{}
		audit := false
		if displayName != nil && *displayName != cur.DisplayName {
			sets, args = append(sets, "display_name = ?"), append(args, *displayName)
			changes["display_name"] = *displayName
			audit = true
		}
		if email != nil && !strings.EqualFold(*email, cur.Email) {
			if *email != "" {
				var exists int
				err := tx.QueryRowContext(ctx, `SELECT 1 FROM users WHERE email = ? AND id <> ?`, *email, id).Scan(&exists)
				if err == nil {
					return conflictField("email", "this e-mail address is already used by another account")
				}
				if !db.IsNoRows(err) {
					return err
				}
			}
			sets, args = append(sets, "email = ?"), append(args, db.NullString(*email))
			changes["email"] = *email
			audit = true
		} else if email != nil && *email != cur.Email {
			sets, args = append(sets, "email = ?"), append(args, db.NullString(*email)) // case-only change
		}
		if prefs != nil {
			sets, args = append(sets, "prefs = ?"), append(args, *prefs)
		}
		if in.MustChangePassword != nil && *in.MustChangePassword != cur.MustChangePassword {
			sets, args = append(sets, "must_change_password = ?"), append(args, db.Bool(*in.MustChangePassword))
			changes["must_change_password"] = *in.MustChangePassword
			audit = true
		}
		if in.QuotaBytes.Set && !equalQuota(quota, cur.QuotaBytes) {
			sets, args = append(sets, "quota_bytes = ?"), append(args, db.NullInt64(quota))
			changes["quota_bytes"] = quota
			audit = true
			if _, err := tx.ExecContext(ctx, `UPDATE spaces SET quota_bytes = ? WHERE owner_user_id = ? AND kind = 'user'`,
				db.NullInt64(quota), id); err != nil {
				return err
			}
		}
		if to != nil && to.ID != cur.RoleID {
			effQuota := cur.QuotaBytes // the quota the (new) personal space gets
			if in.QuotaBytes.Set {
				effQuota = quota
			}
			if err := s.changeRole(ctx, tx, by, cur, to, effQuota, now); err != nil {
				return err
			}
			sets, args = append(sets, "role = ?", "role_id = ?"), append(args, string(to.Base), db.NullString(customRoleID(to)))
			if to.Base != cur.Role {
				changes["role"] = map[string]any{"from": cur.Role, "to": to.Base}
			}
			changes["role_id"] = roleAudit(cur.RoleID, to)
			audit, roleChanged = true, true
		}
		if len(sets) == 0 {
			return nil
		}
		sets = append(sets, "updated_at = ?")
		args = append(args, now, id)
		if _, err := tx.ExecContext(ctx, `UPDATE users SET `+strings.Join(sets, ", ")+` WHERE id = ?`, args...); err != nil {
			if db.IsUnique(err) {
				return conflictField("email", "this e-mail address is already used by another account")
			}
			return err
		}
		if !audit { // preferences-only changes are not audited
			return nil
		}
		if err := s.auditByTx(ctx, tx, by, core.AuditEntry{
			Action: core.ActUserUpdate, TargetType: "user", TargetID: id, TargetName: cur.Username, Details: changes,
		}); err != nil {
			return err
		}
		if roleChanged {
			// Invitations the account created for roles its new role does
			// not cover can no longer be accepted: revoke them.
			return s.revokeInvalidInvitesTx(ctx, tx, by, now)
		}
		return nil
	})
	if err != nil {
		s.auditDeniedUser(ctx, by, core.ActUserUpdate, cur, err)
		return nil, err
	}
	if roleChanged {
		s.publishAuthz(core.AuthzChangedEvent{UserIDs: []string{id}, Reason: core.AuthzRoleAssigned})
	}
	return s.Get(ctx, id)
}

func equalQuota(a, b *int64) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	return *a == *b
}

// changeRole enforces the role rules for giving cur the role to (inside
// tx, before the caller writes users.role and users.role_id): nobody changes
// their own role, core.CheckAssign (owners only for owners; delegates only
// roles they may hand out, to accounts they may manage), and at least one
// active owner remains. It keeps the personal space consistent with the new
// base and closes the account's step-up window (a new role's power is not
// usable within an old window, and an --elevated API token of the account
// stops counting as elevated). An account that loses the right to issue
// invitations — administrator rights, or invites.manage — loses its active
// invitations with it; Update then revokes those it may no longer give.
func (s *Service) changeRole(ctx context.Context, tx *sql.Tx, by *core.Principal, cur *core.User, to *core.RoleDef, quota *int64, now int64) error {
	if by.UserID != "" && by.UserID == cur.ID {
		return core.Errorf(core.ErrForbidden, "you cannot change your own role")
	}
	if err := core.CheckAssign(by, core.AssignCheck{To: to, Target: cur}); err != nil {
		return err
	}
	if cur.Role == core.RoleOwner && to.Base != core.RoleOwner && cur.Status == core.UserActive {
		n, err := otherActiveOwners(ctx, tx, cur.ID)
		if err != nil {
			return err
		}
		if n == 0 {
			return errLastOwner
		}
	}
	if (cur.Role.IsAdmin() && !to.Base.IsAdmin()) ||
		(cur.Permissions.Has(core.CapInvitesManage) && !to.Permissions.Has(core.CapInvitesManage)) {
		if err := s.revokeInvitesOfTx(ctx, tx, by, cur.ID, revokeCreatorDemoted, now); err != nil {
			return err
		}
	}
	if err := followBase(ctx, tx, cur.ID, cur.Role, to.Base, quota, actorID(by), now); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE sessions SET elevated_until = NULL WHERE user_id = ?`, cur.ID); err != nil {
		return err
	}
	return dropTokenElevationTx(ctx, tx, `SELECT ?`, cur.ID)
}

// SetPasswordHash stores a new argon2id hash for id. Users may set their
// own; setting another account's needs users.credentials and
// core.CheckManage (owners only for owner accounts, delegates only for the
// accounts their role may manage). Not audited here: the auth service
// records user.password_change / user.password_reset (a rehash on login is
// no change) and the denied attempts.
func (s *Service) SetPasswordHash(ctx context.Context, by *core.Principal, id, phc string, mustChange bool) error {
	return s.env.DB.Tx(ctx, func(tx *sql.Tx) error {
		return s.SetPasswordHashTx(ctx, tx, by, id, phc, mustChange)
	})
}

// SetPasswordHashTx is SetPasswordHash inside a write transaction the caller
// owns, so the new hash, the session and token revocations and the audit
// entry of a password change commit together (auth.ChangePassword and
// auth.AdminSetPassword: a crash between two transactions would leave the
// other sessions of the account alive with nothing in the audit log). It
// must not open a transaction of its own — the database has a single writer.
func (s *Service) SetPasswordHashTx(ctx context.Context, tx *sql.Tx, by *core.Principal, id, phc string, mustChange bool) error {
	if by == nil {
		return core.ErrUnauthorized
	}
	if err := checkPHC(phc); err != nil {
		return err
	}
	cur, err := getUser(ctx, tx, id)
	if err != nil {
		return err
	}
	if by.UserID == "" || by.UserID != id {
		if err := core.CheckManage(by, cur, core.CapUsersCredentials); err != nil {
			return err
		}
	}
	now := db.Ms(s.now())
	_, err = tx.ExecContext(ctx, `UPDATE users SET password_hash = ?, password_changed_at = ?,
		must_change_password = ?, updated_at = ? WHERE id = ?`, phc, now, db.Bool(mustChange), now, id)
	return err
}

// SetStatus enables or disables an account (users.manage and
// core.CheckManage; a refused escalation is audited as denied). Disabling
// revokes the account's browser sessions and the invitations it created
// immediately (enabling restores neither). Nobody disables their own account
// or the last active owner.
func (s *Service) SetStatus(ctx context.Context, by *core.Principal, id, status string) error {
	if err := requireCap(by, core.CapUsersManage); err != nil {
		return err
	}
	if status != core.UserActive && status != core.UserDisabled {
		return core.Invalid("status", "status must be active or disabled")
	}
	if status == core.UserDisabled && by.UserID != "" && by.UserID == id {
		return core.Errorf(core.ErrForbidden, "you cannot disable your own account")
	}
	action := core.ActUserEnable
	if status == core.UserDisabled {
		action = core.ActUserDisable
	}
	var cur *core.User
	err := s.env.DB.Tx(ctx, func(tx *sql.Tx) error {
		var err error
		if cur, err = getUser(ctx, tx, id); err != nil {
			return err
		}
		if err := core.CheckManage(by, cur, core.CapUsersManage); err != nil {
			return err
		}
		if cur.Status == status {
			return nil
		}
		if status == core.UserDisabled && cur.Role == core.RoleOwner {
			n, err := otherActiveOwners(ctx, tx, id)
			if err != nil {
				return err
			}
			if n == 0 {
				return errLastOwner
			}
		}
		now := db.Ms(s.now())
		if _, err := tx.ExecContext(ctx, `UPDATE users SET status = ?, updated_at = ? WHERE id = ?`, status, now, id); err != nil {
			return err
		}
		if status == core.UserDisabled {
			if _, err := tx.ExecContext(ctx, `UPDATE sessions SET revoked_at = ? WHERE user_id = ? AND revoked_at IS NULL`, now, id); err != nil {
				return err
			}
			if err := s.revokeInvitesOfTx(ctx, tx, by, id, revokeCreatorDisabled, now); err != nil {
				return err
			}
		}
		return s.auditByTx(ctx, tx, by, core.AuditEntry{Action: action, TargetType: "user", TargetID: id, TargetName: cur.Username})
	})
	if err != nil {
		s.auditDeniedUser(ctx, by, action, cur, err)
	}
	return err
}

// ---------- delete ----------

// Delete removes an account (users.manage and core.CheckManage). With
// transferTo, the files of the personal space are moved into a new folder
// "From <username>" at the root of that user's personal space; otherwise
// they are deleted with the account (blobs become unreferenced and are
// removed by the blob GC). Moving another person's files is file access, so
// a delegate also needs users.credentials and must be able to manage the
// destination account. Grants naming the user are removed and the
// invitations they created revoked. Nobody deletes their own account or the
// last active owner. A refused escalation is audited as denied.
func (s *Service) Delete(ctx context.Context, by *core.Principal, id, transferTo string) error {
	if err := requireCap(by, core.CapUsersManage); err != nil {
		return err
	}
	if by.UserID != "" && by.UserID == id {
		return core.Errorf(core.ErrForbidden, "you cannot delete your own account")
	}
	transferTo = strings.TrimSpace(transferTo)
	if transferTo != "" && transferTo == id {
		return core.Invalid("transfer_to", "files must be transferred to a different user")
	}
	var cur *core.User
	err := s.env.DB.Tx(ctx, func(tx *sql.Tx) error {
		var err error
		if cur, err = getUser(ctx, tx, id); err != nil {
			return err
		}
		if err := core.CheckManage(by, cur, core.CapUsersManage); err != nil {
			return err
		}
		if cur.Role == core.RoleOwner {
			n, err := otherActiveOwners(ctx, tx, id)
			if err != nil {
				return err
			}
			if n == 0 {
				return errLastOwner
			}
		}
		now := db.Ms(s.now())
		details := map[string]any{"username": cur.Username, "role": cur.Role, "role_id": cur.RoleID}
		if transferTo != "" {
			if !by.IsAdmin() && !by.Can(core.CapUsersCredentials) {
				return errTransferNeedsCredentials()
			}
			dst, err := getUser(ctx, tx, transferTo)
			if errors.Is(err, core.ErrNotFound) {
				return core.Invalid("transfer_to", "the user to transfer the files to does not exist")
			}
			if err != nil {
				return err
			}
			if !by.IsAdmin() {
				if by.UserID != "" && dst.ID == by.UserID {
					return errTransferToSelf()
				}
				if err := core.CheckManage(by, dst, core.CapUsersManage); err != nil {
					return err
				}
			}
			dstSpace, dstRoot, err := personalSpace(ctx, tx, dst.ID)
			if err != nil {
				return err
			}
			if dstSpace == "" {
				return core.Invalid("transfer_to", "the user to transfer the files to has no personal space (guest)")
			}
			details["transfer_to"] = dst.ID
			details["transfer_to_name"] = dst.Username
			if _, srcRoot, err := personalSpace(ctx, tx, id); err != nil {
				return err
			} else if srcRoot != "" {
				folder, moved, err := transferFiles(ctx, tx, srcRoot, dstSpace, dstRoot, cur.Username, actorID(by), now)
				if err != nil {
					return err
				}
				details["transfer_folder"] = folder
				details["moved_nodes"] = moved
			}
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM node_grants WHERE subject_type = 'user' AND subject_id = ?`, id); err != nil {
			return err
		}
		// Before the row goes: ON DELETE SET NULL would make the account's
		// invitations indistinguishable from the system principal's.
		if err := s.revokeInvitesOfTx(ctx, tx, by, id, revokeCreatorDeleted, now); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM users WHERE id = ?`, id); err != nil {
			return fmt.Errorf("users: delete: %w", err)
		}
		return s.auditByTx(ctx, tx, by, core.AuditEntry{
			Action: core.ActUserDelete, TargetType: "user", TargetID: id, TargetName: cur.Username, Details: details,
		})
	})
	if err != nil {
		s.auditDeniedUser(ctx, by, core.ActUserDelete, cur, err)
	}
	return err
}

// marshalGroupIDs renders a group id list for the invites.group_ids column.
func marshalGroupIDs(g []string) string {
	if len(g) == 0 {
		return "[]"
	}
	b, _ := json.Marshal(g)
	return string(b)
}
