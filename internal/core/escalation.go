package core

import (
	"errors"
	"fmt"
)

// Escalation rules (DESIGN §6a.4). They decide who may act on another account
// (CheckManage) and who may give which role (CheckAssign), and are the only
// place these rules are written down in code: the users, auth and web
// packages call them. Owners, admins and the system principal keep the
// built-in rules (only owners touch owners); a delegate — a non-admin whose
// role holds users.manage, users.credentials or invites.manage — may act on
// or hand out only Member, Guest and delegable custom roles whose server
// permissions are a subset of their own, never owners or admins and never
// their own account.

// EscalationError is the logged cause of a refusal by CheckManage or
// CheckAssign (never sent to clients: the client sees the message of the
// wrapping *Error). Services find it with errors.As and audit the attempt
// with outcome "denied".
type EscalationError struct {
	Reason  string       // the refusal message
	Missing []Capability // server permissions the actor lacks, when that is the reason
}

// Error implements error.
func (e *EscalationError) Error() string {
	if len(e.Missing) == 0 {
		return "escalation refused: " + e.Reason
	}
	return fmt.Sprintf("escalation refused: %s (missing %v)", e.Reason, e.Missing)
}

// AsEscalation returns the EscalationError in err's chain, or nil.
func AsEscalation(err error) *EscalationError {
	var e *EscalationError
	if errors.As(err, &e) {
		return e
	}
	return nil
}

// escalation returns the 403 of an escalation refusal: msg for the client,
// wrapping an *EscalationError that carries msg and the missing permissions.
func escalation(missing CapSet, format string, a ...any) error {
	msg := fmt.Sprintf(format, a...)
	var names []Capability
	if missing != 0 {
		names = missing.List()
	}
	return Wrap(ErrForbidden, msg, &EscalationError{Reason: msg, Missing: names})
}

// NeedPermission is the 403 of a caller that lacks capability c:
// `this needs the “<Label>” permission` (the text mw.RequireCap uses).
func NeedPermission(c Capability) error {
	return Errorf(ErrForbidden, "this needs the “%s” permission", c.Label())
}

// RoleDelegable reports whether delegates may give the role roleID and manage
// its holders: built-in member and guest always, owner and admin (and the
// system role) never, a custom role when customFlag (roles.delegable) is set.
func RoleDelegable(roleID string, customFlag bool) bool {
	switch {
	case IsCustomRoleID(roleID):
		return customFlag
	case roleID == string(RoleMember) || roleID == string(RoleGuest):
		return true
	}
	return false
}

// Covers reports whether by may hand out or manage something that holds caps:
// by is a built-in owner/admin (or the system principal), or the server
// permissions of caps are a subset of by's own. User permissions are ignored
// on purpose (a Helpdesk without shares.links may still create ordinary
// members), and so are token scopes: RoleCaps is the account's role set, the
// action itself is gated by Can.
func Covers(by *Principal, caps CapSet) bool {
	if by == nil {
		return false
	}
	return by.IsAdmin() || caps.Server().SubsetOf(by.RoleCaps().Server())
}

// ownerTargetMessage is the refusal of a non-owner acting on an owner account;
// the credential flows (auth) have always used their own wording.
func ownerTargetMessage(need Capability) string {
	if need == CapUsersCredentials {
		return "only an owner can manage the credentials of an owner"
	}
	return "administrators cannot modify owner accounts"
}

// CheckManage decides whether by may act on the account target with the
// permission need: users.manage for profile, quota, must_change_password,
// disable/enable, unlock and delete; users.credentials for password and
// two-factor resets, sessions, passkeys, authenticators and tokens of
// others. Callers allow self-service (own profile, password, sessions,
// tokens) before calling it. target must carry Role, RoleID, RoleName,
// Permissions and RoleDelegable (the users service fills them).
//
// Order: nil → 401; system → ok; !by.Can(need) → 403 (NeedPermission); a
// non-owner on an owner → 403; owners/admins → ok; the rest are delegates:
// their own account, admin accounts, holders of a custom role that is not
// delegable, and accounts with a server permission by does not hold are
// refused. Every refusal after the permission check wraps an
// *EscalationError.
func CheckManage(by *Principal, target *User, need Capability) error {
	switch {
	case by == nil:
		return ErrUnauthorized
	case by.IsSystem():
		return nil
	case !by.Can(need):
		return NeedPermission(need)
	case target == nil:
		return NotFoundf("user not found")
	case target.Role == RoleOwner && by.Role != RoleOwner:
		return escalation(0, "%s", ownerTargetMessage(need))
	case by.IsAdmin():
		return nil
	case by.UserID != "" && target.ID == by.UserID:
		return escalation(0, "ask an administrator to change this on your own account")
	case target.Role.IsAdmin():
		return escalation(0, "only administrators can manage administrator accounts")
	case IsCustomRoleID(target.RoleID) && !target.RoleDelegable:
		return escalation(0, "accounts with the role “%s” can only be managed by an administrator", target.RoleName)
	}
	if missing := target.Permissions.Server().Minus(by.RoleCaps().Server()); missing != 0 {
		return escalation(missing, "this account has server permissions you do not have (%s)", missing)
	}
	return nil
}

// AssignCheck describes a role assignment for CheckAssign: To is the role
// being given (a built-in or custom RoleDef with Permissions and Delegable
// filled); Target is the existing account, nil for new accounts and invites.
type AssignCheck struct {
	To     *RoleDef
	Target *User
}

// isBuiltin reports whether r is the built-in role role.
func (r *RoleDef) isBuiltin(role Role) bool {
	return r != nil && !IsCustomRoleID(r.ID) && r.ID == string(role)
}

// CheckAssign decides whether by may give the role c.To (to c.Target, or to a
// new account or invitation). The caller must also hold users.manage
// (accounts) or invites.manage (invitations); the route guard enforces it.
// Self role changes are refused before (users service).
//
// Order: nil → 401; system → ok; the owner role, or an owner target, needs
// an owner; owners/admins → ok; delegates cannot give the admin role or a
// custom role that is not delegable, nor a role whose server permissions
// they lack (Covers), and must be able to manage the target
// (CheckManage users.manage). Every refusal wraps an *EscalationError.
func CheckAssign(by *Principal, c AssignCheck) error {
	switch {
	case by == nil:
		return ErrUnauthorized
	case by.IsSystem():
		return nil
	case c.To == nil:
		return Invalid("role_id", "unknown role")
	case c.To.isBuiltin(RoleOwner) && by.Role != RoleOwner:
		return escalation(0, "only owners can grant the owner role")
	case c.Target != nil && c.Target.Role == RoleOwner && by.Role != RoleOwner:
		return escalation(0, "%s", ownerTargetMessage(CapUsersManage))
	case by.IsAdmin():
		return nil
	case c.To.isBuiltin(RoleAdmin):
		return escalation(0, "only administrators can grant the admin role")
	case IsCustomRoleID(c.To.ID) && !c.To.Delegable:
		return escalation(0, "administrators have not allowed account managers to give the role “%s”", c.To.Name)
	}
	if missing := c.To.Permissions.Server().Minus(by.RoleCaps().Server()); missing != 0 {
		return escalation(missing, "you can only give roles whose server permissions you have yourself (missing: %s)", missing)
	}
	if c.Target != nil {
		return CheckManage(by, c.Target, CapUsersManage)
	}
	return nil
}
