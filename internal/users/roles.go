package users

import (
	"cmp"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"unicode"
	"unicode/utf8"

	"fileparcel/internal/core"
	"fileparcel/internal/db"
	"fileparcel/internal/events"
	"fileparcel/internal/ids"
	"fileparcel/internal/names"

	"golang.org/x/text/unicode/norm"
)

// Roles (DESIGN §6a). Every account has exactly one role: a built-in one
// (owner, admin, member, guest; users.role_id NULL) or a custom role
// ("class", table roles, users.role_id) that is based on member or guest
// (users.role = roles.base, also enforced by triggers). A custom role holds a
// set of permissions (core.Capabilities, stored as names, closure applied),
// a delegable flag (may account managers give it and manage its holders?),
// node grants (files) and role → group memberships (role_groups). Creating,
// editing and deleting roles is for built-in owners and admins only;
// role → group memberships need groups.manage. Every change is audited, and
// after commit authz.changed tells the SSE layer whose permissions changed.

// Limits of custom roles (DESIGN §6a).
const (
	maxCustomRoles   = 200
	maxRoleNameRunes = 64
	maxRoleDescRunes = 500
	maxRoleGroups    = 500 // role → group memberships per role
	// maxAuditUserIDs bounds the account ids listed in a role.delete entry.
	maxAuditUserIDs = 1000
	// maxNamedHolders bounds the usernames a refused role deletion names.
	maxNamedHolders = 10
)

// settingGuestsShare is registered by package shares and read by name.
const settingGuestsShare = "sharing.allow_guests_share"

// reservedRoleNames cannot name a custom role (compared by names.Key): the
// built-in roles and words that would read like a special audience.
var reservedRoleNames = map[string]bool{
	"owner": true, "admin": true, "administrator": true, "member": true, "guest": true,
	"system": true, "everyone": true, "all": true, "none": true,
}

// deletedRoleName names the role of an invitation whose custom role is gone.
const deletedRoleName = "Deleted role"

// guestsShare reports whether the built-in Guest role may create share links
// and file requests (sharing.allow_guests_share; false without settings or
// when the key is not registered).
func (s *Service) guestsShare() bool {
	return s.env.Settings != nil && s.env.Settings.Bool(settingGuestsShare)
}

// withGuestSharing adds shares.links and shares.requests to the permissions
// of a plain built-in guest while sharing.allow_guests_share is on (custom
// guest-based roles keep their own permissions). The public getters return
// accounts through it; the transaction-level getUser of the checks does not
// need it (they compare server permissions only). u may be nil.
func (s *Service) withGuestSharing(u *core.User) *core.User {
	if u != nil && u.Role == core.RoleGuest && !core.IsCustomRoleID(u.RoleID) && s.guestsShare() {
		u.Permissions = core.EffectiveRoleCaps(u.Role, u.RoleID, 0, true)
	}
	return u
}

// builtinRole returns the RoleDef of the built-in role r (nil when r is not
// one of owner, admin, member, guest). Its permissions ignore
// sharing.allow_guests_share, which only adds user permissions: the
// escalation rules compare server permissions.
func builtinRole(r core.Role) *core.RoleDef {
	for _, d := range core.BuiltinRoles(false) {
		if d.Base == r {
			return &d
		}
	}
	return nil
}

// roleAdmin reports whether by may create, edit and delete roles: a built-in
// owner or admin (or the system principal) holding the admin scope. Whoever
// edits roles can grant anything, so this is never delegated.
func roleAdmin(by *core.Principal) bool {
	return by.IsAdmin() && by.HasScope(core.ScopeAdmin)
}

// requireRoleAdmin fails unless roleAdmin(by).
func requireRoleAdmin(by *core.Principal) error {
	switch {
	case by == nil:
		return core.ErrUnauthorized
	case !roleAdmin(by):
		return core.Errorf(core.ErrForbidden, "only administrators can manage roles")
	}
	return nil
}

// publishAuthz announces after commit that the permissions of some accounts
// changed (events.TopicAuthzChanged): the SSE layer closes the affected
// streams and the web app reloads /me. The event names no single UserID, so
// that every stream sees it and decides from the payload.
func (s *Service) publishAuthz(ev core.AuthzChangedEvent) {
	if s.env.Bus != nil {
		s.env.Bus.Publish(events.Event{Topic: events.TopicAuthzChanged, Data: ev})
	}
}

// errRoleNotFound is the 404 of a missing role.
func errRoleNotFound() error { return core.NotFoundf("role not found") }

// ---------- validation ----------

// cleanRoleName validates a custom role name (DESIGN §6a): NFC, trimmed, 1–64
// characters, no control, text-direction or other invisible characters
// (names.IsHiddenFormat: a zero-width space would make a second "Finance"
// look like the first in every role picker), not starting with "rol_" (names
// and ids must never be confused) and not a reserved word such as "admin"
// (compared like labels, names.LabelKey: case-insensitively, ignoring
// joiners and direction marks).
func cleanRoleName(s string) (string, error) {
	if !utf8.ValidString(s) {
		return "", core.Invalid("name", "role name is not valid UTF-8")
	}
	s = strings.TrimSpace(norm.NFC.String(s))
	key := names.LabelKey(s)
	switch {
	case s == "":
		return "", core.Invalid("name", "role name must not be empty")
	case utf8.RuneCountInString(s) > maxRoleNameRunes:
		return "", core.Invalid("name", fmt.Sprintf("role name is longer than %d characters", maxRoleNameRunes))
	case strings.ContainsFunc(s, unicode.IsControl) || strings.ContainsFunc(s, names.IsBidiControl):
		return "", core.Invalid("name", "role name must not contain control or text-direction characters")
	case strings.ContainsFunc(s, names.IsHiddenFormat):
		return "", core.Invalid("name", "role name must not contain invisible characters such as a zero-width space")
	case strings.TrimSpace(key) == "":
		return "", core.Invalid("name", "role name must not be empty")
	case strings.HasPrefix(key, ids.PrefixRole+"_"):
		return "", core.Invalid("name", "role names cannot start with “rol_”")
	case reservedRoleNames[key]:
		return "", core.Invalid("name", fmt.Sprintf("“%s” is a reserved role name", s))
	}
	return s, nil
}

// cleanRoleDescription validates a role description: NFC, trimmed, at most
// 500 characters, newlines allowed, no other control characters.
func cleanRoleDescription(s string) (string, error) {
	if !utf8.ValidString(s) {
		return "", core.Invalid("description", "text is not valid UTF-8")
	}
	s = strings.TrimSpace(norm.NFC.String(s))
	if strings.ContainsFunc(s, func(r rune) bool { return unicode.IsControl(r) && r != '\n' }) {
		return "", core.Invalid("description", "text must not contain control characters")
	}
	if utf8.RuneCountInString(s) > maxRoleDescRunes {
		return "", core.Invalid("description", fmt.Sprintf("text is longer than %d characters", maxRoleDescRunes))
	}
	return s, nil
}

// cleanMemberRole validates the role of a role → group membership ("" = member).
func cleanMemberRole(r string) (string, error) {
	switch r {
	case "":
		return core.GroupRoleMember, nil
	case core.GroupRoleMember, core.GroupRoleManager:
		return r, nil
	}
	return "", core.Invalid("member_role", "member_role must be member or manager")
}

// ---------- reads ----------

// querier runs single-row and multi-row queries: the reader pool or a
// transaction.
type querier interface {
	queryer
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
}

// roleCols selects a roles row (alias r).
const roleCols = `r.id, r.name, r.description, r.base, r.permissions, r.delegable, r.created_at, r.updated_at,
	r.created_by, r.updated_by`

// roleCountCols follow roleCols in listings: holders, role → group
// memberships and live node grants to the role (?1 = now in ms).
const roleCountCols = `(SELECT count(*) FROM users u WHERE u.role_id = r.id),
	(SELECT count(*) FROM role_groups rg WHERE rg.role_id = r.id),
	(SELECT count(*) FROM node_grants g WHERE g.subject_type = 'role' AND g.subject_id = r.id
	 AND (g.expires_at IS NULL OR g.expires_at > ?1))`

// scanRole reads roleCols (and roleCountCols when counts). Permissions are
// the stored names with unknown ones dropped and the closure applied.
func scanRole(sc scanner, counts bool) (*core.RoleDef, error) {
	var (
		r                    core.RoleDef
		base, perms          string
		delegable            int64
		created, updated     int64
		createdBy, updatedBy sql.NullString
	)
	dest := []any{&r.ID, &r.Name, &r.Description, &base, &perms, &delegable, &created, &updated, &createdBy, &updatedBy}
	if counts {
		dest = append(dest, &r.UserCount, &r.GroupCount, &r.GrantCount)
	}
	if err := sc.Scan(dest...); err != nil {
		return nil, err
	}
	r.Base = core.Role(base)
	r.Permissions = core.EffectiveRoleCaps(r.Base, r.ID, core.DecodeStoredCaps(perms), false)
	r.Delegable = delegable != 0
	c, u := db.FromMs(created), db.FromMs(updated)
	r.CreatedAt, r.UpdatedAt = &c, &u
	r.CreatedBy, r.UpdatedBy = createdBy.String, updatedBy.String
	r.Staff = r.Permissions.Server() != 0
	return &r, nil
}

// getRole loads the custom role id through q, without counts (404 when
// missing or not a custom role id).
func getRole(ctx context.Context, q queryer, id string) (*core.RoleDef, error) {
	if !ids.Valid(ids.PrefixRole, id) {
		return nil, errRoleNotFound()
	}
	r, err := scanRole(q.QueryRowContext(ctx, `SELECT `+roleCols+` FROM roles r WHERE r.id = ?`, id), false)
	if db.IsNoRows(err) {
		return nil, errRoleNotFound()
	}
	return r, err
}

// loadRole returns the role id through q with its counts: a built-in word
// (owner, admin, member, guest; UserCount counts plain holders only) or a
// custom role id. 404 otherwise.
func (s *Service) loadRole(ctx context.Context, q querier, id string) (*core.RoleDef, error) {
	if r := core.Role(id); r.Valid() {
		d := builtinRoleWithSharing(r, s.guestsShare())
		if err := q.QueryRowContext(ctx, `SELECT count(*) FROM users WHERE role = ? AND role_id IS NULL`, id).Scan(&d.UserCount); err != nil {
			return nil, err
		}
		return d, nil
	}
	if !ids.Valid(ids.PrefixRole, id) {
		return nil, errRoleNotFound()
	}
	r, err := scanRole(q.QueryRowContext(ctx, `SELECT `+roleCols+`, `+roleCountCols+` FROM roles r WHERE r.id = ?2`,
		db.Ms(s.now()), id), true)
	if db.IsNoRows(err) {
		return nil, errRoleNotFound()
	}
	return r, err
}

// builtinRoleWithSharing is the RoleDef of the built-in role r as the API
// shows it (Guest with the permissions sharing.allow_guests_share gives).
func builtinRoleWithSharing(r core.Role, guestsShare bool) *core.RoleDef {
	for _, d := range core.BuiltinRoles(guestsShare) {
		if d.Base == r {
			return &d
		}
	}
	return nil
}

// fillCaller sets the caller-dependent fields of r: Editable (a role
// administrator, custom roles only) and Assignable (by holds users.manage or
// invites.manage and core.CheckAssign allows giving r). by nil leaves both
// false.
func (s *Service) fillCaller(by *core.Principal, r *core.RoleDef) {
	if by == nil {
		return
	}
	r.Editable = roleAdmin(by) && !r.Builtin
	r.Assignable = by.CanAny(core.CapUsersManage, core.CapInvitesManage) &&
		core.CheckAssign(by, core.AssignCheck{To: r}) == nil
}

// ListRoles lists the four built-in roles (owner, admin, member, guest) and
// then the custom roles by name, with their counts; Editable and Assignable
// describe what by may do with each.
func (s *Service) ListRoles(ctx context.Context, by *core.Principal) ([]core.RoleDef, error) {
	out := core.BuiltinRoles(s.guestsShare())
	err := s.env.DB.Read(ctx, func(tx *sql.Tx) error {
		rows, err := tx.QueryContext(ctx, `SELECT role, count(*) FROM users WHERE role_id IS NULL GROUP BY role`)
		if err != nil {
			return err
		}
		counts := map[string]int{}
		for rows.Next() {
			var role string
			var n int
			if err := rows.Scan(&role, &n); err != nil {
				rows.Close()
				return err
			}
			counts[role] = n
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return err
		}
		for i := range out {
			out[i].UserCount = counts[out[i].ID]
		}
		rows, err = tx.QueryContext(ctx, `SELECT `+roleCols+`, `+roleCountCols+` FROM roles r
			ORDER BY r.name COLLATE NOCASE, r.id`, db.Ms(s.now()))
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			r, err := scanRole(rows, true)
			if err != nil {
				return err
			}
			out = append(out, *r)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, err
	}
	for i := range out {
		s.fillCaller(by, &out[i])
	}
	return out, nil
}

// GetRole returns one role: a built-in word (owner, admin, member, guest) or
// a custom role id (404 otherwise). by fills Editable and Assignable (nil:
// both false).
func (s *Service) GetRole(ctx context.Context, by *core.Principal, id string) (*core.RoleDef, error) {
	r, err := s.loadRole(ctx, s.env.DB.Reader(), id)
	if err != nil {
		return nil, err
	}
	s.fillCaller(by, r)
	return r, nil
}

// LookupRoles lists the custom roles (id, name, description) by name for
// the share and grant pickers. Like the user directory it needs
// users.lookup or users.view.
func (s *Service) LookupRoles(ctx context.Context, p *core.Principal) ([]core.RoleRef, error) {
	if err := requireDirectory(p); err != nil {
		return nil, err
	}
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

// requireDirectory fails unless p may search the user directory and the list
// of roles (users.lookup or users.view).
func requireDirectory(p *core.Principal) error {
	switch {
	case p == nil:
		return core.ErrUnauthorized
	case !p.CanAny(core.CapUsersLookup, core.CapUsersView):
		return core.Errorf(core.ErrForbidden, "your role cannot search the user directory")
	}
	return nil
}

// ---------- assignment ----------

// resolveAssignment validates a requested (role, roleID) pair inside q and
// returns the role to give:
//   - roleID "": role ("" = member) must be a built-in role;
//   - roleID a built-in word: role must be "" or the same word;
//   - roleID "rol_…": a live custom role, and role "" or its base;
//   - anything else: 422 role_id "unknown role".
func resolveAssignment(ctx context.Context, q queryer, role core.Role, roleID string) (*core.RoleDef, error) {
	roleID = strings.TrimSpace(roleID)
	switch {
	case roleID == "":
		if role == "" {
			role = core.RoleMember
		}
		if !role.Valid() {
			return nil, core.Invalid("role", "role must be owner, admin, member or guest")
		}
		return builtinRole(role), nil
	case core.Role(roleID).Valid():
		to := builtinRole(core.Role(roleID))
		if role != "" && role != to.Base {
			return nil, core.Invalid("role", fmt.Sprintf("the role “%s” is based on %s", to.Name, to.Base))
		}
		return to, nil
	}
	to, err := getRole(ctx, q, roleID)
	if errors.Is(err, core.ErrNotFound) {
		return nil, core.Invalid("role_id", "unknown role")
	}
	if err != nil {
		return nil, err
	}
	if role != "" && role != to.Base {
		return nil, core.Invalid("role", fmt.Sprintf("the role “%s” is based on %s", to.Name, to.Base))
	}
	return to, nil
}

// customRoleID is the users.role_id / invites.role_id value of r ("" = NULL
// for built-in roles).
func customRoleID(r *core.RoleDef) string {
	if r != nil && core.IsCustomRoleID(r.ID) {
		return r.ID
	}
	return ""
}

// staffRole reports whether r opens server surfaces: owner/admin, or a
// custom role with a server permission (step-up and the staff invitation
// rules apply).
func staffRole(r *core.RoleDef) bool {
	return r != nil && (r.Base.IsAdmin() || r.Permissions.Server() != 0)
}

// roleAudit is the "role_id" detail of an assignment: {from?, to, name}.
func roleAudit(from string, to *core.RoleDef) map[string]any {
	d := map[string]any{"to": to.ID, "name": to.Name}
	if from != "" {
		d["from"] = from
	}
	return d
}

// ---------- create, update, delete ----------

// roleNameFree fails with 409 when another role (not exceptID) uses name.
// Names are compared as labels (names.LabelKey: casefold(NFC) without
// joiners and direction marks, so a look-alike cannot sit next to the
// original), not by the column's NOCASE collation alone, which folds ASCII
// only: the CLI resolves role names case-insensitively. Roles are few
// (≤ 200), so the scan is cheap; the UNIQUE constraint stays as the ASCII
// backstop.
func roleNameFree(ctx context.Context, tx *sql.Tx, name, exceptID string) error {
	rows, err := tx.QueryContext(ctx, `SELECT name FROM roles WHERE id <> ?`, exceptID)
	if err != nil {
		return err
	}
	defer rows.Close()
	key := names.LabelKey(name)
	for rows.Next() {
		var other string
		if err := rows.Scan(&other); err != nil {
			return err
		}
		if names.LabelKey(other) == key {
			return errRoleNameTaken()
		}
	}
	return rows.Err()
}

func errRoleNameTaken() error { return conflictField("name", "a role with this name already exists") }

// CreateRole creates a custom role (built-in owners and admins only). The
// base is in.Base, else the base of in.CopyFrom (owner/admin → member), else
// member; the permissions are in.Permissions when given, else those of
// in.CopyFrom (owner/admin: every permission), else the default of the base
// (member: Member's four; guest: none). Implied permissions are added.
func (s *Service) CreateRole(ctx context.Context, by *core.Principal, in core.RoleDefInput) (*core.RoleDef, error) {
	if err := requireRoleAdmin(by); err != nil {
		return nil, err
	}
	name, err := cleanRoleName(in.Name)
	if err != nil {
		return nil, err
	}
	desc, err := cleanRoleDescription(in.Description)
	if err != nil {
		return nil, err
	}
	switch in.Base {
	case "", core.RoleMember, core.RoleGuest:
	default:
		return nil, core.Invalid("base", "custom roles are based on member or guest")
	}
	var perms core.CapSet
	if in.Permissions != nil {
		if perms, err = core.ParseCaps(*in.Permissions); err != nil {
			return nil, err
		}
	}
	copyFrom := strings.TrimSpace(in.CopyFrom)
	var id string
	err = s.env.DB.Tx(ctx, func(tx *sql.Tx) error {
		base := in.Base
		var start core.CapSet
		switch {
		case copyFrom == "":
			if base == "" {
				base = core.RoleMember
			}
			start = core.BuiltinCaps(base, false)
		case core.Role(copyFrom).Valid():
			src := builtinRoleWithSharing(core.Role(copyFrom), s.guestsShare())
			start = src.Permissions
			if base == "" {
				base = src.Base
			}
		default:
			src, err := getRole(ctx, tx, copyFrom)
			if errors.Is(err, core.ErrNotFound) {
				return core.Invalid("copy_from", "unknown role")
			}
			if err != nil {
				return err
			}
			start = src.Permissions
			if base == "" {
				base = src.Base
			}
		}
		if base.IsAdmin() {
			base = core.RoleMember // copying owner or admin copies their permissions only
		}
		if in.Permissions != nil {
			start = perms
		}
		caps := start.Closure()
		var n int
		if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM roles`).Scan(&n); err != nil {
			return err
		}
		if n >= maxCustomRoles {
			return core.Invalid("name", fmt.Sprintf("at most %d roles", maxCustomRoles))
		}
		if err := roleNameFree(ctx, tx, name, ""); err != nil {
			return err
		}
		id = ids.New(ids.PrefixRole)
		now := db.Ms(s.now())
		if _, err := tx.ExecContext(ctx, `INSERT INTO roles (id, name, description, base, permissions, delegable,
			created_at, updated_at, created_by, updated_by) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			id, name, desc, string(base), core.EncodeCaps(caps), db.Bool(in.Delegable), now, now,
			db.NullString(actorID(by)), db.NullString(actorID(by))); err != nil {
			if db.IsUnique(err) {
				return errRoleNameTaken()
			}
			return fmt.Errorf("users: insert role: %w", err)
		}
		details := map[string]any{"name": name, "base": base, "permissions": caps, "delegable": in.Delegable}
		if copyFrom != "" {
			details["copy_from"] = copyFrom
		}
		return s.auditByTx(ctx, tx, by, core.AuditEntry{
			Action: core.ActRoleCreate, TargetType: "role", TargetID: id, TargetName: name, Details: details,
		})
	})
	if err != nil {
		return nil, err
	}
	return s.GetRole(ctx, by, id)
}

// UpdateRole changes the name, description, permissions (a full replacement,
// or additions and removals — not both) or the delegable flag of a custom
// role (built-in owners and admins only; built-in roles cannot be changed).
// The change applies to every holder on their next request: when server
// permissions are added, the holders' step-up windows are closed; when
// invites.manage is taken away, the invitations the holders created are
// revoked; open invitations that can no longer be accepted (the role became
// staff or stopped being delegable, a holder no longer covers the role they
// invited for) are revoked as well. Audited as role.update (only when
// something changed), then authz.changed is published: reason role_updated
// when the permissions changed, role_details for a name, description or
// delegable change (which leaves the holders' event streams open).
func (s *Service) UpdateRole(ctx context.Context, by *core.Principal, id string, in core.RoleDefUpdate) (*core.RoleDef, error) {
	if err := requireRoleAdmin(by); err != nil {
		return nil, err
	}
	if core.Role(id).Valid() {
		return nil, core.Invalid("id", "built-in roles cannot be changed; duplicate one instead")
	}
	if in.Permissions != nil && (len(in.AddPermissions) > 0 || len(in.RemovePermissions) > 0) {
		return nil, core.Invalid("permissions", "send either permissions or add_permissions/remove_permissions, not both")
	}
	var name, desc *string
	if in.Name != nil {
		v, err := cleanRoleName(*in.Name)
		if err != nil {
			return nil, err
		}
		name = &v
	}
	if in.Description != nil {
		v, err := cleanRoleDescription(*in.Description)
		if err != nil {
			return nil, err
		}
		desc = &v
	}
	var replace *core.CapSet
	if in.Permissions != nil {
		v, err := core.ParseCaps(*in.Permissions)
		if err != nil {
			return nil, err
		}
		replace = &v
	}
	add, err := core.ParseCaps(in.AddPermissions)
	if err != nil {
		return nil, err
	}
	remove, err := core.ParseCaps(in.RemovePermissions)
	if err != nil {
		return nil, err
	}
	changed, permsChanged := false, false
	err = s.env.DB.Tx(ctx, func(tx *sql.Tx) error {
		changed, permsChanged = false, false
		cur, err := getRole(ctx, tx, id)
		if err != nil {
			return err
		}
		caps := cur.Permissions.With(add.List()...).Minus(remove)
		if replace != nil {
			caps = *replace
		}
		caps = caps.Closure()
		now := db.Ms(s.now())
		var sets []string
		var args []any
		details := map[string]any{}
		if name != nil && *name != cur.Name {
			if err := roleNameFree(ctx, tx, *name, id); err != nil {
				return err
			}
			sets, args = append(sets, "name = ?"), append(args, *name)
			details["name"] = map[string]string{"from": cur.Name, "to": *name}
		}
		if desc != nil && *desc != cur.Description {
			sets, args = append(sets, "description = ?"), append(args, *desc)
			details["description"] = true
		}
		added, removed := caps.Minus(cur.Permissions), cur.Permissions.Minus(caps)
		if added != 0 || removed != 0 {
			sets, args = append(sets, "permissions = ?"), append(args, core.EncodeCaps(caps))
			details["permissions"] = map[string]any{"added": added, "removed": removed}
		}
		if in.Delegable != nil && *in.Delegable != cur.Delegable {
			sets, args = append(sets, "delegable = ?"), append(args, db.Bool(*in.Delegable))
			details["delegable"] = map[string]bool{"from": cur.Delegable, "to": *in.Delegable}
		}
		if len(sets) == 0 {
			return nil
		}
		changed, permsChanged = true, added != 0 || removed != 0
		sets = append(sets, "updated_at = ?", "updated_by = ?")
		args = append(args, now, db.NullString(actorID(by)), id)
		if _, err := tx.ExecContext(ctx, `UPDATE roles SET `+strings.Join(sets, ", ")+` WHERE id = ?`, args...); err != nil {
			if db.IsUnique(err) {
				return errRoleNameTaken()
			}
			return err
		}
		if added.Server() != 0 {
			// New server power is not usable within an old step-up window:
			// neither a session's nor that of an --elevated API token.
			if _, err := tx.ExecContext(ctx, `UPDATE sessions SET elevated_until = NULL
				WHERE user_id IN (SELECT id FROM users WHERE role_id = ?)`, id); err != nil {
				return err
			}
			if err := dropTokenElevationTx(ctx, tx, `SELECT id FROM users WHERE role_id = ?`, id); err != nil {
				return err
			}
		}
		if removed.Has(core.CapInvitesManage) {
			if err := s.revokeInvitesOfRoleTx(ctx, tx, by, id, now); err != nil {
				return err
			}
		}
		if added != 0 || removed != 0 || (in.Delegable != nil && *in.Delegable != cur.Delegable) {
			// Open invitations for this role (now staff, or no longer
			// delegable), and those its holders created (for roles they no
			// longer cover), may have become invalid: revoke them.
			if err := s.revokeInvalidInvitesTx(ctx, tx, by, now); err != nil {
				return err
			}
		}
		var holders int
		if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM users WHERE role_id = ?`, id).Scan(&holders); err != nil {
			return err
		}
		details["users"] = holders
		return s.auditByTx(ctx, tx, by, core.AuditEntry{
			Action: core.ActRoleUpdate, TargetType: "role", TargetID: id, TargetName: cmp.Or(deref(name), cur.Name),
			Details: details,
		})
	})
	if err != nil {
		return nil, err
	}
	switch {
	case permsChanged:
		s.publishAuthz(core.AuthzChangedEvent{RoleID: id, Reason: core.AuthzRoleUpdated})
	case changed: // name, description or delegable: the holders may do what they did before
		s.publishAuthz(core.AuthzChangedEvent{RoleID: id, Reason: core.AuthzRoleDetails})
	}
	return s.GetRole(ctx, by, id)
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

// revokeInvitesOfRoleTx revokes the active invitations created by the
// holders of the custom role roleID, which is losing invites.manage (a role
// edit, or its holders moved to a role without it): a link must not outlive
// its creator's right to issue it.
func (s *Service) revokeInvitesOfRoleTx(ctx context.Context, tx *sql.Tx, by *core.Principal, roleID string, now int64) error {
	holders, err := roleHolders(ctx, tx, roleID)
	if err != nil {
		return err
	}
	for _, h := range holders {
		if err := s.revokeInvitesOfTx(ctx, tx, by, h.id, revokeCreatorDemoted, now); err != nil {
			return err
		}
	}
	return nil
}

// holder is an account holding a custom role.
type holder struct{ id, username string }

// roleHolders lists the accounts with the custom role roleID by username.
func roleHolders(ctx context.Context, q querier, roleID string) ([]holder, error) {
	rows, err := q.QueryContext(ctx, `SELECT id, username FROM users WHERE role_id = ? ORDER BY username, id`, roleID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []holder
	for rows.Next() {
		var h holder
		if err := rows.Scan(&h.id, &h.username); err != nil {
			return nil, err
		}
		out = append(out, h)
	}
	return out, rows.Err()
}

// reassignTarget resolves the role DeleteRole moves the holders of id to:
// member, guest or another live custom role.
func reassignTarget(ctx context.Context, q queryer, id, reassignTo string) (*core.RoleDef, error) {
	switch {
	case reassignTo == string(core.RoleMember) || reassignTo == string(core.RoleGuest):
		return builtinRole(core.Role(reassignTo)), nil
	case core.IsCustomRoleID(reassignTo) && reassignTo != id:
		to, err := getRole(ctx, q, reassignTo)
		if errors.Is(err, core.ErrNotFound) {
			return nil, core.Invalid("reassign_to", "unknown role")
		}
		return to, err
	}
	return nil, core.Invalid("reassign_to", "choose member, guest or another custom role")
}

// DeleteRole deletes a custom role (built-in owners and admins only). Its
// holders are moved to reassignTo — member, guest or another custom role;
// there is no implicit fallback, because the base could allow more than the
// role did — which is required while the role has holders (409). When the
// base changes, the personal spaces follow (a holder with personal files
// blocks a move to a guest-based role: 409 naming them). The role's open
// invitations are revoked, its grants and group memberships removed. Audited
// as role.delete, then authz.changed is published.
func (s *Service) DeleteRole(ctx context.Context, by *core.Principal, id, reassignTo string) error {
	if err := requireRoleAdmin(by); err != nil {
		return err
	}
	if core.Role(id).Valid() {
		return core.Invalid("id", "built-in roles cannot be deleted")
	}
	reassignTo = strings.TrimSpace(reassignTo)
	var moved []string
	err := s.env.DB.Tx(ctx, func(tx *sql.Tx) error {
		moved = nil
		cur, err := getRole(ctx, tx, id)
		if err != nil {
			return err
		}
		holders, err := roleHolders(ctx, tx, id)
		if err != nil {
			return err
		}
		var to *core.RoleDef
		switch {
		case reassignTo != "":
			if to, err = reassignTarget(ctx, tx, id, reassignTo); err != nil {
				return err
			}
		case len(holders) == 1:
			return conflictField("reassign_to", "1 account has this role: choose a role to move it to")
		case len(holders) > 1:
			return conflictField("reassign_to", fmt.Sprintf("%d accounts have this role: choose a role to move them to", len(holders)))
		}
		now := db.Ms(s.now())
		details := map[string]any{"name": cur.Name, "base": cur.Base, "users_moved": len(holders)}
		if to != nil {
			details["reassigned_to"], details["reassigned_to_name"] = to.ID, to.Name
		}
		if len(holders) > 0 {
			if err := s.moveHolders(ctx, tx, by, cur, to, holders, now); err != nil {
				return err
			}
			userIDs := make([]string, 0, min(len(holders), maxAuditUserIDs))
			for _, h := range holders {
				moved = append(moved, h.id)
				if len(userIDs) < maxAuditUserIDs {
					userIDs = append(userIDs, h.id)
				}
			}
			details["user_ids"] = userIDs
			if len(holders) > maxAuditUserIDs {
				details["truncated"] = true
			}
		}
		// Only open invitations: used and expired ones keep their status.
		res, err := tx.ExecContext(ctx, `UPDATE invites SET revoked_at = ?1
			WHERE role_id = ?2 AND revoked_at IS NULL AND uses < max_uses AND expires_at > ?1`, now, id)
		if err != nil {
			return err
		}
		n, _ := res.RowsAffected()
		details["invites_revoked"] = n
		if res, err = tx.ExecContext(ctx, `DELETE FROM node_grants WHERE subject_type = 'role' AND subject_id = ?`, id); err != nil {
			return err
		}
		n, _ = res.RowsAffected()
		details["grants_removed"] = n
		var groups int
		if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM role_groups WHERE role_id = ?`, id).Scan(&groups); err != nil {
			return err
		}
		details["groups_removed"] = groups
		if _, err := tx.ExecContext(ctx, `DELETE FROM roles WHERE id = ?`, id); err != nil {
			return fmt.Errorf("users: delete role: %w", err)
		}
		if len(holders) > 0 {
			// The holders now have another role: invitations they created
			// for roles it does not cover are revoked.
			if err := s.revokeInvalidInvitesTx(ctx, tx, by, now); err != nil {
				return err
			}
		}
		return s.auditByTx(ctx, tx, by, core.AuditEntry{
			Action: core.ActRoleDelete, TargetType: "role", TargetID: id, TargetName: cur.Name, Details: details,
		})
	})
	if err != nil {
		return err
	}
	s.publishAuthz(core.AuthzChangedEvent{UserIDs: moved, RoleID: id, Reason: core.AuthzRoleDeleted})
	return nil
}

// moveHolders gives every holder of the role cur the role to (DeleteRole):
// personal spaces follow a base change (a move to a guest-based role is
// refused while holders have personal files, naming up to 10 of them),
// step-up windows close, and invitations the holders created are revoked
// when to cannot create invitations.
func (s *Service) moveHolders(ctx context.Context, tx *sql.Tx, by *core.Principal, cur, to *core.RoleDef, holders []holder, now int64) error {
	if to.Base == core.RoleGuest && cur.Base != core.RoleGuest {
		rows, err := tx.QueryContext(ctx, `SELECT u.username FROM users u
			JOIN spaces sp ON sp.owner_user_id = u.id AND sp.kind = 'user'
			WHERE u.role_id = ? AND EXISTS (SELECT 1 FROM nodes n WHERE n.space_id = sp.id AND n.parent_id IS NOT NULL)
			ORDER BY u.username, u.id`, cur.ID)
		if err != nil {
			return err
		}
		var blocked []string
		for rows.Next() {
			var u string
			if err := rows.Scan(&u); err != nil {
				rows.Close()
				return err
			}
			blocked = append(blocked, u)
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return err
		}
		if len(blocked) > 0 {
			list := strings.Join(blocked[:min(len(blocked), maxNamedHolders)], ", ")
			if len(blocked) > maxNamedHolders {
				list += ", …"
			}
			what := fmt.Sprintf("%d accounts still have", len(blocked))
			if len(blocked) == 1 {
				what = "1 account still has"
			}
			return conflictField("reassign_to", fmt.Sprintf(
				"%s personal files (%s): move or delete them first, or reassign to a member-based role", what, list))
		}
	}
	if cur.Permissions.Has(core.CapInvitesManage) && !to.Permissions.Has(core.CapInvitesManage) {
		if err := s.revokeInvitesOfRoleTx(ctx, tx, by, cur.ID, now); err != nil {
			return err
		}
	}
	for _, h := range holders {
		var quota sql.NullInt64
		if err := tx.QueryRowContext(ctx, `SELECT quota_bytes FROM users WHERE id = ?`, h.id).Scan(&quota); err != nil {
			return err
		}
		if err := followBase(ctx, tx, h.id, cur.Base, to.Base, db.FromNullInt64(quota), actorID(by), now); err != nil {
			return err
		}
	}
	if _, err := tx.ExecContext(ctx, `UPDATE sessions SET elevated_until = NULL
		WHERE user_id IN (SELECT id FROM users WHERE role_id = ?)`, cur.ID); err != nil {
		return err
	}
	if err := dropTokenElevationTx(ctx, tx, `SELECT id FROM users WHERE role_id = ?`, cur.ID); err != nil {
		return err
	}
	_, err := tx.ExecContext(ctx, `UPDATE users SET role = ?, role_id = ?, updated_at = ? WHERE role_id = ?`,
		string(to.Base), db.NullString(customRoleID(to)), now, cur.ID)
	return err
}

// dropTokenElevationTx ends the step-up of the --elevated API tokens of the
// accounts the SQL query users selects (one column of user ids; args are its
// arguments), like UPDATE sessions SET elevated_until = NULL does for
// browser sessions: an --elevated admin token counts as a step-up window of
// up to 30 days, and new server power — permissions added to the role, a
// role change — must not be usable through a step-up taken before it
// (DESIGN §9.3). The tokens keep working with their scopes; the elevation
// comes back only with a new token created after a new step-up. The flag is
// the "elevated" pseudo-scope in api_tokens.scopes (a JSON list; a
// whitespace-separated list is read as well, as package auth does).
func dropTokenElevationTx(ctx context.Context, tx *sql.Tx, users string, args ...any) error {
	rows, err := tx.QueryContext(ctx, `SELECT id, scopes FROM api_tokens
		WHERE revoked_at IS NULL AND instr(scopes, ?) > 0 AND user_id IN (`+users+`)`,
		append([]any{core.ScopeElevated}, args...)...)
	if err != nil {
		return err
	}
	type tok struct{ id, scopes string }
	var list []tok
	for rows.Next() {
		var t tok
		if err := rows.Scan(&t.id, &t.scopes); err != nil {
			rows.Close()
			return err
		}
		list = append(list, t)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	for _, t := range list {
		var scopes []string
		if err := json.Unmarshal([]byte(t.scopes), &scopes); err != nil {
			scopes = strings.Fields(t.scopes)
		}
		if !slices.Contains(scopes, core.ScopeElevated) {
			continue
		}
		b, err := json.Marshal(slices.DeleteFunc(scopes, func(s string) bool { return s == core.ScopeElevated }))
		if err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `UPDATE api_tokens SET scopes = ? WHERE id = ?`, string(b), t.id); err != nil {
			return err
		}
	}
	return nil
}

// ---------- role → group memberships ----------

// roleGroupCols selects a role_groups row (alias rg) with the role and group
// names and the group's space.
const roleGroupCols = `rg.role_id, r.name, rg.group_id, g.name,
	(SELECT sp.id FROM spaces sp WHERE sp.group_id = g.id AND sp.kind = 'group'),
	rg.member_role, rg.added_at, rg.added_by
	FROM role_groups rg JOIN roles r ON r.id = rg.role_id JOIN groups g ON g.id = rg.group_id`

func scanRoleGroup(sc scanner) (*core.RoleGroup, error) {
	var rg core.RoleGroup
	var spaceID, addedBy sql.NullString
	var added int64
	if err := sc.Scan(&rg.RoleID, &rg.RoleName, &rg.GroupID, &rg.GroupName, &spaceID, &rg.MemberRole, &added, &addedBy); err != nil {
		return nil, err
	}
	rg.SpaceID, rg.AddedBy, rg.AddedAt = spaceID.String, addedBy.String, db.FromMs(added)
	return &rg, nil
}

// listRoleGroups runs a roleGroupCols query (where and order appended).
func listRoleGroups(ctx context.Context, q querier, tail string, args ...any) ([]core.RoleGroup, error) {
	rows, err := q.QueryContext(ctx, `SELECT `+roleGroupCols+` `+tail, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []core.RoleGroup{}
	for rows.Next() {
		rg, err := scanRoleGroup(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *rg)
	}
	return out, rows.Err()
}

// RoleGroups lists the groups the role roleID is a member of, by group name
// (built-in roles: none; 404 for an unknown role).
func (s *Service) RoleGroups(ctx context.Context, roleID string) ([]core.RoleGroup, error) {
	if core.Role(roleID).Valid() {
		return []core.RoleGroup{}, nil
	}
	var out []core.RoleGroup
	err := s.env.DB.Read(ctx, func(tx *sql.Tx) error {
		if _, err := getRole(ctx, tx, roleID); err != nil {
			return err
		}
		var err error
		out, err = listRoleGroups(ctx, tx, `WHERE rg.role_id = ? ORDER BY g.name, g.id`, roleID)
		return err
	})
	return out, err
}

// SetRoleGroup makes every holder of the custom role roleID a member (or
// manager) of groupID, including people who get the role later (needs
// groups.manage: a group manager can already add any account to any group).
// Audited as group.role_set and announced with authz.changed when something
// changed.
func (s *Service) SetRoleGroup(ctx context.Context, by *core.Principal, roleID, groupID, memberRole string) (*core.RoleGroup, error) {
	if err := requireCap(by, core.CapGroupsManage); err != nil {
		return nil, err
	}
	memberRole, err := cleanMemberRole(memberRole)
	if err != nil {
		return nil, err
	}
	if core.Role(roleID).Valid() {
		return nil, core.Invalid("role_id", "only custom roles can be members of groups")
	}
	changed := false
	var out *core.RoleGroup
	err = s.env.DB.Tx(ctx, func(tx *sql.Tx) error {
		changed = false
		role, err := getRole(ctx, tx, roleID)
		if err != nil {
			return err
		}
		g, err := getGroup(ctx, tx, groupID)
		if err != nil {
			return err
		}
		var prev string
		err = tx.QueryRowContext(ctx, `SELECT member_role FROM role_groups WHERE role_id = ? AND group_id = ?`, roleID, groupID).Scan(&prev)
		switch {
		case err == nil && prev == memberRole:
		case err == nil:
			_, err = tx.ExecContext(ctx, `UPDATE role_groups SET member_role = ? WHERE role_id = ? AND group_id = ?`,
				memberRole, roleID, groupID)
			changed = true
		case db.IsNoRows(err):
			var n int
			if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM role_groups WHERE role_id = ?`, roleID).Scan(&n); err != nil {
				return err
			}
			if n >= maxRoleGroups {
				return core.Invalid("group_id", fmt.Sprintf("a role can be a member of at most %d groups", maxRoleGroups))
			}
			_, err = tx.ExecContext(ctx, `INSERT INTO role_groups (role_id, group_id, member_role, added_at, added_by)
				VALUES (?, ?, ?, ?, ?)`, roleID, groupID, memberRole, db.Ms(s.now()), db.NullString(actorID(by)))
			changed = true
		}
		if err != nil {
			return err
		}
		if out, err = scanRoleGroup(tx.QueryRowContext(ctx, `SELECT `+roleGroupCols+`
			WHERE rg.role_id = ? AND rg.group_id = ?`, roleID, groupID)); err != nil {
			return err
		}
		if !changed {
			return nil
		}
		return s.auditByTx(ctx, tx, by, core.AuditEntry{
			Action: core.ActGroupRoleSet, TargetType: "group", TargetID: g.ID, TargetName: g.Name,
			Details: map[string]any{"role_id": role.ID, "role_name": role.Name, "member_role": memberRole, "previous": prev},
		})
	})
	if err != nil {
		return nil, err
	}
	if changed {
		s.publishAuthz(core.AuthzChangedEvent{RoleID: roleID, Reason: core.AuthzRoleGroups})
	}
	return out, nil
}

// RemoveRoleGroup ends the membership of the role roleID in groupID (needs
// groups.manage; 404 when the role is not a member). Direct memberships of
// its holders stay. Audited as group.role_remove, then authz.changed.
func (s *Service) RemoveRoleGroup(ctx context.Context, by *core.Principal, roleID, groupID string) error {
	if err := requireCap(by, core.CapGroupsManage); err != nil {
		return err
	}
	err := s.env.DB.Tx(ctx, func(tx *sql.Tx) error {
		rg, err := scanRoleGroup(tx.QueryRowContext(ctx, `SELECT `+roleGroupCols+`
			WHERE rg.role_id = ? AND rg.group_id = ?`, roleID, groupID))
		if db.IsNoRows(err) {
			return core.NotFoundf("the role is not a member of this group")
		}
		if err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM role_groups WHERE role_id = ? AND group_id = ?`, roleID, groupID); err != nil {
			return err
		}
		return s.auditByTx(ctx, tx, by, core.AuditEntry{
			Action: core.ActGroupRoleRemove, TargetType: "group", TargetID: rg.GroupID, TargetName: rg.GroupName,
			Details: map[string]any{"role_id": rg.RoleID, "role_name": rg.RoleName, "member_role": rg.MemberRole},
		})
	})
	if err != nil {
		return err
	}
	s.publishAuthz(core.AuthzChangedEvent{RoleID: roleID, Reason: core.AuthzRoleGroups})
	return nil
}

// GroupsOf lists the effective group memberships of userID by group name:
// direct ones and those through the account's custom role, with the
// effective role (manager wins) and where it comes from.
func (s *Service) GroupsOf(ctx context.Context, userID string) ([]core.AccessGroup, error) {
	rows, err := s.env.DB.Query(ctx, `SELECT e.group_id, g.name,
			COALESCE((SELECT sp.id FROM spaces sp WHERE sp.group_id = g.id AND sp.kind = 'group'), ''),
			e.role, e.source, COALESCE(e.via_role_id, ''), COALESCE(r.name, '')
		FROM effective_group_members e JOIN groups g ON g.id = e.group_id
		LEFT JOIN roles r ON r.id = e.via_role_id
		WHERE e.user_id = ? ORDER BY g.name, g.id, e.source, r.name`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []core.AccessGroup{}
	for rows.Next() {
		var gid, name, spaceID string
		var m membershipRow
		if err := rows.Scan(&gid, &name, &spaceID, &m.role, &m.source, &m.roleID, &m.roleName); err != nil {
			return nil, err
		}
		if n := len(out); n == 0 || out[n-1].GroupID != gid {
			out = append(out, core.AccessGroup{GroupID: gid, Name: name, SpaceID: spaceID})
		}
		a := &out[len(out)-1]
		m.mergeInto(&a.Role, &a.Direct, &a.DirectRole, &a.ViaRoles)
	}
	return out, rows.Err()
}

// membershipRow is one effective_group_members row (source "direct" or
// "role", the role's id and name for the latter).
type membershipRow struct {
	role, source, roleID, roleName string
}

// mergeInto folds m into the fields of an effective membership: the
// effective role (manager wins), the direct membership and its role, and the
// custom roles it comes through (core.AccessGroup, core.GroupMember).
func (m membershipRow) mergeInto(eff *string, direct *bool, directRole *string, via *[]core.RoleRef) {
	if *eff != core.GroupRoleManager {
		*eff = m.role
	}
	switch {
	case m.source == "direct":
		*direct, *directRole = true, m.role
	case !slices.ContainsFunc(*via, func(r core.RoleRef) bool { return r.ID == m.roleID }):
		*via = append(*via, core.RoleRef{ID: m.roleID, Name: m.roleName, MemberRole: m.role})
	}
}
