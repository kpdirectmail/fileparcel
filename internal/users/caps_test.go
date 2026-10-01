package users

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"fileparcel/internal/core"
	"fileparcel/internal/ids"
)

// mkRole stores a custom role straight into the roles table (the roles API
// of this package is not needed to test how accounts read their role).
func (te *testEnv) mkRole(t *testing.T, name string, base core.Role, perms core.CapSet, delegable bool) string {
	t.Helper()
	id := ids.New(ids.PrefixRole)
	now := te.clock.Now().UnixMilli()
	te.exec(t, `INSERT INTO roles (id, name, base, permissions, delegable, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?)`,
		id, name, string(base), core.EncodeCaps(perms), delegable, now, now)
	return id
}

// giveRole gives u the custom role roleID (users.role becomes its base).
func (te *testEnv) giveRole(t *testing.T, u *core.User, roleID string) {
	t.Helper()
	te.exec(t, `UPDATE users SET role = (SELECT base FROM roles WHERE id = ?), role_id = ? WHERE id = ?`, roleID, roleID, u.ID)
}

// asRole is the principal auth builds for u: the role id, name and
// capabilities of the account.
func asRole(u *core.User) *core.Principal {
	p := as(u)
	p.RoleID, p.RoleName = u.RoleID, u.RoleName
	p.SetCaps(u.Permissions)
	return p
}

// Accounts carry their role: RoleID (custom role or base), RoleName,
// Permissions (closure applied; sharing.allow_guests_share for plain
// guests) and RoleDelegable, in every public getter.
func TestUserRoleFields(t *testing.T) {
	te := newTestEnv(t)
	ctx := context.Background()
	for _, r := range []core.Role{core.RoleOwner, core.RoleAdmin, core.RoleMember, core.RoleGuest} {
		u := te.mkUser(t, string(r)+"1", r)
		if u.RoleID != string(r) || u.RoleName != core.BuiltinRoleName(r) || u.Permissions != core.BuiltinCaps(r, false) ||
			u.RoleDelegable != (r == core.RoleMember || r == core.RoleGuest) {
			t.Errorf("%s: %s %q %v %v", r, u.RoleID, u.RoleName, u.Permissions, u.RoleDelegable)
		}
	}
	helpdesk := te.mkRole(t, "Helpdesk", core.RoleMember, core.MemberCaps.With(core.CapUsersManage), true)
	auditors := te.mkRole(t, "Auditors", core.RoleGuest, core.NewCapSet(core.CapAuditView), false)
	hana := te.mkUser(t, "hana", core.RoleMember)
	te.giveRole(t, hana, helpdesk)
	aud := te.mkUser(t, "aud", core.RoleGuest)
	te.giveRole(t, aud, auditors)
	gus := te.mkUser(t, "gus", core.RoleGuest)

	check := func(what string, u *core.User, roleID, name string, perms core.CapSet, delegable bool) {
		t.Helper()
		if u.RoleID != roleID || u.RoleName != name || u.Permissions != perms || u.RoleDelegable != delegable {
			t.Errorf("%s: %s %q %v %v", what, u.RoleID, u.RoleName, u.Permissions, u.RoleDelegable)
		}
	}
	helpdeskPerms := core.MemberCaps.With(core.CapUsersManage, core.CapUsersView) // users.manage implies users.view
	for what, get := range map[string]func(string) (*core.User, error){
		"Get": func(name string) (*core.User, error) {
			return te.svc.Get(ctx, map[string]string{"hana": hana.ID, "aud": aud.ID, "gus": gus.ID}[name])
		},
		"GetByUsername": func(name string) (*core.User, error) { return te.svc.GetByUsername(ctx, name) },
		"List": func(name string) (*core.User, error) {
			page, err := te.svc.List(ctx, core.UserQuery{Q: name})
			if err != nil || len(page.Items) != 1 {
				return nil, errors.Join(err, errors.New("not listed once"))
			}
			return &page.Items[0], nil
		},
	} {
		for _, guestsShare := range []bool{false, true} {
			te.settings.set(settingGuestsShare, guestsShare)
			u, err := get("hana")
			if err != nil {
				t.Fatalf("%s hana: %v", what, err)
			}
			check(what+" hana", u, helpdesk, "Helpdesk", helpdeskPerms, true)
			if u, err = get("aud"); err != nil {
				t.Fatalf("%s aud: %v", what, err)
			}
			check(what+" aud", u, auditors, "Auditors", core.NewCapSet(core.CapAuditView), false)
			if u, err = get("gus"); err != nil {
				t.Fatalf("%s gus: %v", what, err)
			}
			check(what+" gus", u, "guest", "Guest", core.BuiltinCaps(core.RoleGuest, guestsShare), true)
		}
	}
	// The JSON of an account carries the role (DESIGN §9.4 User).
	te.settings.set(settingGuestsShare, false)
	u, _ := te.svc.Get(ctx, hana.ID)
	b, _ := json.Marshal(u)
	for _, want := range []string{`"role":"member"`, `"role_id":"` + helpdesk + `"`, `"role_name":"Helpdesk"`,
		`"permissions":["shares.links","shares.requests","users.lookup","tokens.create","users.view","users.manage"]`} {
		if !strings.Contains(string(b), want) {
			t.Errorf("JSON lacks %s: %s", want, b)
		}
	}
	if strings.Contains(string(b), "delegable") {
		t.Errorf("JSON exposes RoleDelegable: %s", b)
	}
	// Unknown stored permission names are dropped (a newer build's role).
	te.exec(t, `UPDATE roles SET permissions = '["users.manage","files.teleport"]' WHERE id = ?`, helpdesk)
	if u, err := te.svc.Get(ctx, hana.ID); err != nil || u.Permissions != core.NewCapSet(core.CapUsersManage, core.CapUsersView) {
		t.Errorf("unknown names: %+v %v", u, err)
	}
}

// An invitation link creates an account with a password of the holder's
// choosing: delegates see only the links of invitations they could have
// created themselves.
func TestListInvitesURLVisibility(t *testing.T) {
	te := newTestEnv(t)
	ctx := context.Background()
	admin := te.mkUser(t, "admin", core.RoleAdmin)
	g, err := te.svc.CreateGroup(ctx, as(admin), core.GroupInput{Name: "Team"})
	if err != nil {
		t.Fatal(err)
	}
	memberInv, _, err := te.svc.CreateInvite(ctx, as(admin), core.InviteInput{Role: core.RoleMember})
	if err != nil {
		t.Fatal(err)
	}
	adminInv, _, err := te.svc.CreateInvite(ctx, as(admin), core.InviteInput{Role: core.RoleAdmin})
	if err != nil {
		t.Fatal(err)
	}
	groupInv, _, err := te.svc.CreateInvite(ctx, as(admin), core.InviteInput{Role: core.RoleGuest, GroupIDs: []string{g.ID}})
	if err != nil {
		t.Fatal(err)
	}
	inviters := te.mkRole(t, "Inviters", core.RoleMember, core.MemberCaps.With(core.CapInvitesManage), false)
	groupers := te.mkRole(t, "Group inviters", core.RoleMember, core.MemberCaps.With(core.CapInvitesManage, core.CapGroupsManage), false)
	ivy := te.mkUser(t, "ivy", core.RoleMember)
	te.giveRole(t, ivy, inviters)
	gil := te.mkUser(t, "gil", core.RoleMember)
	te.giveRole(t, gil, groupers)
	mel := te.mkUser(t, "mel", core.RoleMember)
	// An admin invitation that ivy created (while she was an administrator).
	ownInv, _, err := te.svc.CreateInvite(ctx, as(admin), core.InviteInput{Role: core.RoleAdmin})
	if err != nil {
		t.Fatal(err)
	}
	te.exec(t, `UPDATE invites SET created_by = ? WHERE id = ?`, ivy.ID, ownInv.ID)

	links := func(p *core.Principal) map[string]bool {
		t.Helper()
		page, err := te.svc.ListInvites(ctx, p, core.PageReq{})
		if err != nil {
			t.Fatalf("list as %s: %v", p.Username, err)
		}
		out := map[string]bool{}
		for _, inv := range page.Items {
			out[inv.ID] = inv.URL != ""
		}
		if len(out) != 4 {
			t.Fatalf("list as %s: %d rows", p.Username, len(out))
		}
		return out
	}
	get := func(u *core.User) *core.User {
		t.Helper()
		x, err := te.svc.Get(ctx, u.ID)
		if err != nil {
			t.Fatal(err)
		}
		return x
	}
	for who, c := range map[string]struct {
		p    *core.Principal
		want map[string]bool
	}{
		"admin":  {as(admin), map[string]bool{memberInv.ID: true, adminInv.ID: true, groupInv.ID: true, ownInv.ID: true}},
		"system": {system(), map[string]bool{memberInv.ID: true, adminInv.ID: true, groupInv.ID: true, ownInv.ID: true}},
		// Member invitations yes; the admin role no; group memberships need
		// groups.manage; her own invitation always.
		"ivy": {asRole(get(ivy)), map[string]bool{memberInv.ID: true, adminInv.ID: false, groupInv.ID: false, ownInv.ID: true}},
		"gil": {asRole(get(gil)), map[string]bool{memberInv.ID: true, adminInv.ID: false, groupInv.ID: true, ownInv.ID: false}},
	} {
		got := links(c.p)
		for id, want := range c.want {
			if got[id] != want {
				t.Errorf("%s: link of %s shown %v", who, id, got[id])
			}
		}
	}
	// Custom roles: a delegate sees the links of the delegable roles its own
	// server permissions cover, never those of other roles or of a role
	// that is gone.
	staff := te.createRole(t, core.RoleDefInput{Name: "Staff", Delegable: true})
	auditors := te.createRole(t, core.RoleDefInput{Name: "Auditors", Permissions: capList(core.CapAuditView), Delegable: true})
	finance := te.createRole(t, core.RoleDefInput{Name: "Finance"})
	gone := te.createRole(t, core.RoleDefInput{Name: "Gone", Delegable: true})
	custom := map[string]bool{} // invitation id → visible to ivy
	for r, visible := range map[string]bool{staff.ID: true, auditors.ID: false, finance.ID: false, gone.ID: false} {
		inv, _, err := te.svc.CreateInvite(ctx, as(admin), core.InviteInput{RoleID: r})
		if err != nil {
			t.Fatal(err)
		}
		custom[inv.ID] = visible
	}
	te.exec(t, `DELETE FROM roles WHERE id = ?`, gone.ID)
	page, err := te.svc.ListInvites(ctx, asRole(get(ivy)), core.PageReq{})
	if err != nil {
		t.Fatal(err)
	}
	for _, inv := range page.Items {
		if want, ok := custom[inv.ID]; ok && (inv.URL != "") != want {
			t.Errorf("ivy: link of the %s invitation shown %v", inv.RoleName, inv.URL != "")
		}
	}
	page, _ = te.svc.ListInvites(ctx, as(admin), core.PageReq{})
	for _, inv := range page.Items {
		if _, ok := custom[inv.ID]; ok && inv.URL == "" {
			t.Errorf("admin: link of the %s invitation hidden", inv.RoleName)
		}
	}

	// Without invites.manage the list is refused.
	if _, err := te.svc.ListInvites(ctx, asRole(get(mel)), core.PageReq{}); !errors.Is(err, core.ErrForbidden) ||
		core.AsError(err).Message != "this needs the “Invite people” permission" {
		t.Errorf("member lists invites: %v", err)
	}
	if _, err := te.svc.ListInvites(ctx, nil, core.PageReq{}); !errors.Is(err, core.ErrUnauthorized) {
		t.Errorf("anonymous lists invites: %v", err)
	}
}
