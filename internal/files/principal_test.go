package files

import (
	"testing"

	"fileparcel/internal/core"
	"fileparcel/internal/db"
	"fileparcel/internal/ids"
)

// SysPrincipalFor (public share operations, archive tickets) carries the
// role and capabilities of the account, like a session of that user.
func TestSysPrincipalForCarriesCaps(t *testing.T) {
	e := newEnv(t)
	now := db.Ms(e.clock.Now())
	roleID := ids.New(ids.PrefixRole)
	if _, err := e.db.Exec(e.ctx, `INSERT INTO roles (id, name, base, permissions, created_at, updated_at)
		VALUES (?, 'Contractors', 'guest', '["shares.requests","users.manage"]', ?, ?)`, roleID, now, now); err != nil {
		t.Fatal(err)
	}
	admin := e.user("adam", core.RoleAdmin)
	member := e.user("mel", core.RoleMember)
	guest := e.user("gus", core.RoleGuest)
	con := e.user("con", core.RoleGuest)
	if _, err := e.db.Exec(e.ctx, `UPDATE users SET role_id = ? WHERE id = ?`, roleID, con.UserID); err != nil {
		t.Fatal(err)
	}
	contractors := core.NewCapSet(core.CapShareRequests, core.CapUsersManage, core.CapUsersView) // closure applied
	for _, guestsShare := range []bool{false, true} {
		e.settings.set(settingGuestsShare, guestsShare)
		for _, c := range []struct {
			u      *user
			roleID string
			name   string
			caps   core.CapSet
		}{
			{admin, "admin", "Admin", core.AllCaps},
			{member, "member", "Member", core.MemberCaps},
			{guest, "guest", "Guest", core.BuiltinCaps(core.RoleGuest, guestsShare)},
			{con, roleID, "Contractors", contractors},
		} {
			p, err := e.svc.SysPrincipalFor(e.ctx, c.u.UserID)
			if err != nil || p.RoleID != c.roleID || p.RoleName != c.name || p.RoleCaps() != c.caps || p.Role != c.u.Role {
				t.Errorf("%s (guests share %v): %+v %v", c.u.Username, guestsShare, p, err)
			}
		}
	}
}
