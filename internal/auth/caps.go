package auth

import (
	"cmp"
	"context"
	"database/sql"

	"fileparcel/internal/core"
)

// Role capabilities of the principals this package builds (DESIGN §6a).
// Session and token principals are resolved from the same SQL row that
// authenticates them, on every request: a role change or a permission edit
// applies to the next request, with no cache to invalidate.

// settingGuestsShare is registered by package shares and read by name, the
// way files reads auth.admin_can_access_files.
const settingGuestsShare = "sharing.allow_guests_share"

// principalRoleCols are the role columns the principal builders select next
// to the users row (alias u), with principalRoleJoin: the custom role id and
// the custom role's name and stored permissions (all NULL for built-in
// roles, and for a role_id whose row is gone — which the foreign key
// forbids — so that such an account holds nothing).
const (
	principalRoleCols = `u.role_id, r.name, r.permissions`
	principalRoleJoin = ` LEFT JOIN roles r ON r.id = u.role_id`
)

// guestsShare reports whether the built-in Guest role may create share links
// and file requests (sharing.allow_guests_share; false when not registered).
func (s *Service) guestsShare() bool { return s.settingBool(settingGuestsShare, false) }

// setRoleCaps fills the role fields of p (whose Role is the stored base)
// from the principalRoleCols values: RoleID, RoleName and the capabilities
// (core.EffectiveRoleCaps; token scopes are applied later by Principal.Can).
func (s *Service) setRoleCaps(p *core.Principal, roleID, roleName, perms sql.NullString) {
	p.RoleID = cmp.Or(roleID.String, string(p.Role))
	p.RoleName = cmp.Or(roleName.String, core.BuiltinRoleName(p.Role))
	p.SetCaps(core.EffectiveRoleCaps(p.Role, p.RoleID, core.DecodeStoredCaps(perms.String), s.guestsShare()))
}

// auditDenied records a refused escalation (core.CheckManage) as action with
// outcome denied and details {"reason", "missing"}, attributed to by. It is
// a no-op unless err carries a *core.EscalationError: plain permission
// refusals are not audited (the UI never offers them).
func (s *Service) auditDenied(ctx context.Context, by *core.Principal, action string, target *core.User, err error) {
	esc := core.AsEscalation(err)
	if esc == nil || action == "" || by == nil {
		return
	}
	details := map[string]any{"reason": esc.Reason}
	if len(esc.Missing) > 0 {
		details["missing"] = esc.Missing
	}
	e := core.AuditEntry{Action: action, Outcome: core.OutcomeDenied, TargetType: "user", Details: details,
		ActorID: by.UserID, ActorName: by.Username, ActorVia: string(by.Via), UserAgent: clip(by.UserAgent, maxUserAgent),
		RequestID: by.RequestID}
	if by.IP.IsValid() {
		e.IP = by.IP.String()
	}
	if target != nil {
		e.TargetID, e.TargetName = target.ID, target.Username
	}
	s.record(ctx, e)
}
