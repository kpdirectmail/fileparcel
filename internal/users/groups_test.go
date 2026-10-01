package users

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"fileparcel/internal/core"
)

func TestGroupLifecycle(t *testing.T) {
	te := newTestEnv(t)
	ctx := context.Background()
	admin := te.mkUser(t, "admin", core.RoleAdmin)
	alice := te.mkUser(t, "alice", core.RoleMember)
	bob := te.mkUser(t, "bob", core.RoleMember)

	if _, err := te.svc.CreateGroup(ctx, as(alice), core.GroupInput{Name: "Design"}); !errors.Is(err, core.ErrForbidden) {
		t.Fatalf("member creates group: %v", err)
	}
	g, err := te.svc.CreateGroup(ctx, as(admin), core.GroupInput{Name: " Design ", Description: ptr("The design team")})
	if err != nil {
		t.Fatal(err)
	}
	if g.Name != "Design" || g.Description != "The design team" || g.SpaceID == "" || g.MemberCount != 0 || g.CreatedBy != admin.ID {
		t.Fatalf("group %+v", g)
	}
	var kind, gid, spaceName string
	if err := te.env.DB.QueryRow(ctx, `SELECT kind, group_id, name FROM spaces WHERE id = ?`, g.SpaceID).Scan(&kind, &gid, &spaceName); err != nil {
		t.Fatal(err)
	}
	if kind != core.SpaceGroup || gid != g.ID || spaceName != "Design" {
		t.Fatalf("space %s %s %s", kind, gid, spaceName)
	}
	root := te.rootOf(t, g.SpaceID)
	var rootName, rootKey string
	_ = te.env.DB.QueryRow(ctx, `SELECT name, name_key FROM nodes WHERE id = ?`, root).Scan(&rootName, &rootKey)
	if rootName != "Design" || rootKey != "design" {
		t.Fatalf("root %q %q", rootName, rootKey)
	}

	for _, bad := range []core.GroupInput{{Name: ""}, {Name: "a/b"}, {Name: "a\\b"}, {Name: ".."}, {Name: "x\x00"}} {
		if _, err := te.svc.CreateGroup(ctx, as(admin), bad); !errors.Is(err, core.ErrInvalid) {
			t.Errorf("name %q: %v", bad.Name, err)
		}
	}
	if _, err := te.svc.CreateGroup(ctx, as(admin), core.GroupInput{Name: "DESIGN"}); !errors.Is(err, core.ErrConflict) {
		t.Fatalf("duplicate: %v", err)
	}

	// Membership.
	if err := te.svc.SetMember(ctx, as(admin), g.ID, alice.ID, core.GroupRoleManager); err != nil {
		t.Fatal(err)
	}
	if err := te.svc.SetMember(ctx, as(admin), g.ID, bob.ID, ""); err != nil {
		t.Fatal(err)
	}
	te.audit.reset()
	if err := te.svc.SetMember(ctx, as(admin), g.ID, bob.ID, core.GroupRoleMember); err != nil || len(te.audit.actions()) != 0 {
		t.Fatalf("no-op set: %v %v", err, te.audit.actions())
	}
	for _, c := range []struct {
		gid, uid, role string
		want           error
	}{
		{g.ID, bob.ID, "owner", core.ErrInvalid},
		{"grp_missing", bob.ID, "member", core.ErrNotFound},
		{g.ID, "usr_missing", "member", core.ErrNotFound},
	} {
		if err := te.svc.SetMember(ctx, as(admin), c.gid, c.uid, c.role); !errors.Is(err, c.want) {
			t.Errorf("SetMember %+v: %v", c, err)
		}
	}
	if err := te.svc.SetMember(ctx, as(bob), g.ID, bob.ID, core.GroupRoleManager); !errors.Is(err, core.ErrForbidden) {
		t.Fatalf("member sets member: %v", err)
	}
	members, err := te.svc.Members(ctx, g.ID)
	if err != nil || len(members) != 2 || members[0].Username != "alice" || members[0].Role != core.GroupRoleManager || members[1].Role != core.GroupRoleMember {
		t.Fatalf("members %+v %v", members, err)
	}
	if ids, _ := te.svc.GroupIDsOf(ctx, alice.ID); !slices.Equal(ids, []string{g.ID}) {
		t.Fatalf("GroupIDsOf %v", ids)
	}
	mine, err := te.svc.MyGroups(ctx, as(alice))
	if err != nil || len(mine) != 1 || mine[0].MyRole != core.GroupRoleManager || mine[0].MemberCount != 2 || mine[0].SpaceID != g.SpaceID {
		t.Fatalf("MyGroups %+v %v", mine, err)
	}
	if none, _ := te.svc.MyGroups(ctx, system()); len(none) != 0 {
		t.Fatalf("system groups %v", none)
	}

	// Rename renames the space and its root.
	g2, err := te.svc.UpdateGroup(ctx, as(admin), g.ID, core.GroupInput{Name: "Design Team"})
	if err != nil || g2.Name != "Design Team" || g2.Description != "The design team" {
		t.Fatalf("rename %+v %v", g2, err)
	}
	_ = te.env.DB.QueryRow(ctx, `SELECT name FROM spaces WHERE id = ?`, g.SpaceID).Scan(&spaceName)
	_ = te.env.DB.QueryRow(ctx, `SELECT name, name_key FROM nodes WHERE id = ?`, root).Scan(&rootName, &rootKey)
	if spaceName != "Design Team" || rootName != "Design Team" || rootKey != "design team" {
		t.Fatalf("after rename: %q %q %q", spaceName, rootName, rootKey)
	}
	g3, err := te.svc.UpdateGroup(ctx, as(admin), g.ID, core.GroupInput{Description: ptr("")})
	if err != nil || g3.Name != "Design Team" || g3.Description != "" {
		t.Fatalf("description %+v %v", g3, err)
	}
	other, _ := te.svc.CreateGroup(ctx, as(admin), core.GroupInput{Name: "Marketing"})
	if _, err := te.svc.UpdateGroup(ctx, as(admin), other.ID, core.GroupInput{Name: "design team"}); !errors.Is(err, core.ErrConflict) {
		t.Fatalf("rename conflict: %v", err)
	}

	// Remove membership.
	if err := te.svc.RemoveMember(ctx, as(admin), g.ID, bob.ID); err != nil {
		t.Fatal(err)
	}
	if err := te.svc.RemoveMember(ctx, as(admin), g.ID, bob.ID); !errors.Is(err, core.ErrNotFound) {
		t.Fatalf("remove twice: %v", err)
	}

	// Delete removes the space, its files, memberships and grants naming the group.
	f := te.mkNode(t, g.SpaceID, root, core.KindFile, "plan.pdf", 42)
	te.exec(t, `INSERT INTO node_grants (id, node_id, subject_type, subject_id, role, created_at) VALUES ('gnt_g', ?, 'group', ?, 'viewer', 1)`,
		te.rootOf(t, alice.SpaceID), g.ID)
	if err := te.svc.DeleteGroup(ctx, as(admin), g.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := te.svc.GetGroup(ctx, g.ID); !errors.Is(err, core.ErrNotFound) {
		t.Fatalf("group still exists: %v", err)
	}
	for q, want := range map[string]int{
		`SELECT count(*) FROM spaces WHERE id = '` + g.SpaceID + `'`:         0,
		`SELECT count(*) FROM nodes WHERE id = '` + f + `'`:                  0,
		`SELECT count(*) FROM group_members WHERE group_id = '` + g.ID + `'`: 0,
		`SELECT count(*) FROM node_grants WHERE subject_id = '` + g.ID + `'`: 0,
	} {
		if n := te.count(t, q); n != want {
			t.Errorf("%s = %d", q, n)
		}
	}
	e, ok := te.audit.last(core.ActGroupDelete)
	if !ok || e.Details.(map[string]any)["files"] != int64(1) {
		t.Fatalf("audit %+v", e)
	}
	te.exec(t, `INSERT INTO nodes_fts(nodes_fts) VALUES ('integrity-check')`)
	wantActions := []string{core.ActGroupUpdate, core.ActGroupUpdate, core.ActGroupCreate, core.ActGroupMemberRemove, core.ActGroupDelete}
	if got := te.audit.actions(); !slices.Equal(got, wantActions) {
		t.Fatalf("audit actions %v", got)
	}
}

// Group names follow the node name rules of their team folder: unique by
// casefold(NFC) like node names (SQLite's NOCASE folds ASCII only, and the
// CLI and /Team/<group> paths cannot tell "Équipe" from "équipe"), at most
// 255 bytes, and no text-direction controls.
func TestGroupNameRules(t *testing.T) {
	te := newTestEnv(t)
	ctx := context.Background()
	admin := te.mkUser(t, "admin", core.RoleAdmin)
	mk := func(name string) *core.Group {
		t.Helper()
		g, err := te.svc.CreateGroup(ctx, as(admin), core.GroupInput{Name: name})
		if err != nil {
			t.Fatalf("create %q: %v", name, err)
		}
		return g
	}
	eq := mk("Équipe")
	mk("Straße")
	other := mk("Other")
	for _, dup := range []string{"équipe", "ÉQUIPE", "E\u0301quipe", "STRASSE", "strasse"} {
		if _, err := te.svc.CreateGroup(ctx, as(admin), core.GroupInput{Name: dup}); !errors.Is(err, core.ErrConflict) || fieldOf(err) != "name" {
			t.Errorf("create %q: %v", dup, err)
		}
	}
	if _, err := te.svc.UpdateGroup(ctx, as(admin), other.ID, core.GroupInput{Name: "ÉQUIPE"}); !errors.Is(err, core.ErrConflict) {
		t.Fatalf("rename onto a folded duplicate: %v", err)
	}
	// A group may change the case of its own name.
	g, err := te.svc.UpdateGroup(ctx, as(admin), eq.ID, core.GroupInput{Name: "équipe"})
	if err != nil || g.Name != "équipe" {
		t.Fatalf("recase: %+v %v", g, err)
	}
	var rootName string
	_ = te.env.DB.QueryRow(ctx, `SELECT name FROM nodes WHERE id = ?`, te.rootOf(t, eq.SpaceID)).Scan(&rootName)
	if rootName != "équipe" {
		t.Fatalf("root %q", rootName)
	}

	// Length: the name is also the root folder's, so 255 bytes of UTF-8 at
	// most, checked on the NFC form (U+1D160 grows to three code points).
	long := mk(strings.Repeat("技", 85)) // 255 bytes
	if _, err := te.svc.UpdateGroup(ctx, as(admin), long.ID, core.GroupInput{Name: strings.Repeat("技", 86)}); !errors.Is(err, core.ErrInvalid) ||
		core.AsError(err).Message != "group name is too long" {
		t.Fatalf("rename too long: %v", err)
	}
	for _, bad := range []string{strings.Repeat("技", 90), strings.Repeat("\U0001F600", 64), strings.Repeat("\U0001D160", 32)} {
		if _, err := te.svc.CreateGroup(ctx, as(admin), core.GroupInput{Name: bad}); !errors.Is(err, core.ErrInvalid) ||
			fieldOf(err) != "name" || core.AsError(err).Message != "group name is too long" {
			t.Errorf("create %d bytes: %v", len(bad), err)
		}
	}
	if _, err := te.svc.CreateGroup(ctx, as(admin), core.GroupInput{Name: strings.Repeat("x", 101)}); !errors.Is(err, core.ErrInvalid) {
		t.Fatalf("101 characters: %v", err)
	}
	for _, bad := range []string{"invoice\u202efdp", "a\u2066b\u2069"} {
		if _, err := te.svc.CreateGroup(ctx, as(admin), core.GroupInput{Name: bad}); !errors.Is(err, core.ErrInvalid) || fieldOf(err) != "name" {
			t.Errorf("create %q: %v", bad, err)
		}
	}
	if n := te.count(t, `SELECT count(*) FROM groups`); n != 4 {
		t.Fatalf("%d groups", n)
	}
	if n := te.count(t, `SELECT count(*) FROM spaces WHERE kind = 'group'`); n != 4 {
		t.Fatalf("%d group spaces", n)
	}
}

func TestListGroupsPagination(t *testing.T) {
	te := newTestEnv(t)
	ctx := context.Background()
	for _, n := range []string{"delta", "Alpha", "charlie", "bravo"} {
		if _, err := te.svc.CreateGroup(ctx, system(), core.GroupInput{Name: n}); err != nil {
			t.Fatal(err)
		}
	}
	var got []string
	q := core.PageReq{Limit: 3}
	for {
		p, err := te.svc.ListGroups(ctx, q)
		if err != nil {
			t.Fatal(err)
		}
		for _, g := range p.Items {
			got = append(got, g.Name)
		}
		if p.NextCursor == "" {
			break
		}
		q.Cursor = p.NextCursor
	}
	if !slices.Equal(got, []string{"Alpha", "bravo", "charlie", "delta"}) {
		t.Fatalf("groups %v", got)
	}
	if _, err := te.svc.ListGroups(ctx, core.PageReq{Cursor: "bad!"}); !errors.Is(err, core.ErrInvalid) {
		t.Fatalf("bad cursor: %v", err)
	}
}

func TestCreateUserWithGroups(t *testing.T) {
	te := newTestEnv(t)
	ctx := context.Background()
	g, _ := te.svc.CreateGroup(ctx, system(), core.GroupInput{Name: "Team"})
	u := te.mkUser(t, "zed", core.RoleMember, func(in *core.NewUser) { in.GroupIDs = []string{g.ID, g.ID} })
	members, _ := te.svc.Members(ctx, g.ID)
	if len(members) != 1 || members[0].UserID != u.ID || members[0].Role != core.GroupRoleMember {
		t.Fatalf("members %+v", members)
	}
}

// Role → group memberships: every holder of a custom role counts as a member
// (or manager) of the group, including people who get the role later. The
// membership lists, counts and "my groups" are effective.
func TestRoleGroups(t *testing.T) {
	te := newTestEnv(t)
	ctx := context.Background()
	admin := te.mkUser(t, "admin", core.RoleAdmin)
	finance := te.createRole(t, core.RoleDefInput{Name: "Finance"})
	auditors := te.createRole(t, core.RoleDefInput{Name: "Auditors", Base: core.RoleGuest})
	g, err := te.svc.CreateGroup(ctx, as(admin), core.GroupInput{Name: "Accounts"})
	if err != nil {
		t.Fatal(err)
	}
	other, _ := te.svc.CreateGroup(ctx, as(admin), core.GroupInput{Name: "Other"})
	ann := te.mkUser(t, "ann", core.RoleMember) // Finance holder and direct member
	te.giveRole(t, ann, finance.ID)
	bob := te.mkUser(t, "bob", core.RoleMember) // Finance holder only
	te.giveRole(t, bob, finance.ID)
	cid := te.mkUser(t, "cid", core.RoleMember) // direct member only
	if err := te.svc.SetMember(ctx, as(admin), g.ID, ann.ID, core.GroupRoleMember); err != nil {
		t.Fatal(err)
	}
	te.clock.Advance(time.Minute)
	if err := te.svc.SetMember(ctx, as(admin), g.ID, cid.ID, core.GroupRoleManager); err != nil {
		t.Fatal(err)
	}
	member := as(te.mkUser(t, "mia", core.RoleMember))
	evs := te.authzEvents(t)
	te.audit.reset()
	te.clock.Advance(time.Minute)

	// Refusals.
	_, err = te.svc.SetRoleGroup(ctx, member, finance.ID, g.ID, "")
	wantErr(t, "member", err, core.ErrForbidden, "", "this needs the “Manage groups” permission")
	for _, c := range []struct {
		role, group, memberRole string
		base                    *core.Error
		field                   string
	}{
		{"member", g.ID, "", core.ErrInvalid, "role_id"},
		{"admin", g.ID, "", core.ErrInvalid, "role_id"},
		{finance.ID, g.ID, "owner", core.ErrInvalid, "member_role"},
		{finance.ID, "grp_01j9zq3x4k6m8p0r2t4v6x8z0b", "", core.ErrNotFound, ""},
		{"rol_01k5z8r3m9d4q7w2x6c1v0b5na", g.ID, "", core.ErrNotFound, ""},
	} {
		_, err := te.svc.SetRoleGroup(ctx, as(admin), c.role, c.group, c.memberRole)
		wantErr(t, fmt.Sprintf("set %+v", c), err, c.base, c.field, "")
	}
	if len(te.audit.entries) != 0 || len(evs()) != 0 {
		t.Fatal("refusals audited or announced")
	}

	// Finance → manager of Accounts.
	rg, err := te.svc.SetRoleGroup(ctx, as(admin), finance.ID, g.ID, core.GroupRoleManager)
	if err != nil {
		t.Fatal(err)
	}
	if rg.RoleID != finance.ID || rg.RoleName != "Finance" || rg.GroupID != g.ID || rg.GroupName != "Accounts" ||
		rg.SpaceID != g.SpaceID || rg.MemberRole != core.GroupRoleManager || rg.AddedBy != admin.ID || !rg.AddedAt.Equal(te.clock.Now()) {
		t.Fatalf("role group %+v", rg)
	}
	e, ok := te.audit.last(core.ActGroupRoleSet)
	d, _ := e.Details.(map[string]any)
	if !ok || e.TargetType != "group" || e.TargetID != g.ID || e.TargetName != "Accounts" || d["role_id"] != finance.ID ||
		d["role_name"] != "Finance" || d["member_role"] != core.GroupRoleManager || d["previous"] != "" {
		t.Fatalf("audit %+v", e)
	}
	if ev := evs(); len(ev) != 1 || ev[0].RoleID != finance.ID || ev[0].Reason != core.AuthzRoleGroups {
		t.Fatalf("events %+v", ev)
	}
	// The same again: nothing to audit or announce.
	te.audit.reset()
	if _, err := te.svc.SetRoleGroup(ctx, as(admin), finance.ID, g.ID, core.GroupRoleManager); err != nil ||
		len(te.audit.entries) != 0 || len(evs()) != 0 {
		t.Fatalf("no-op: %v %v", err, te.audit.actions())
	}
	if _, err := te.svc.SetRoleGroup(ctx, system(), auditors.ID, g.ID, ""); err != nil {
		t.Fatal(err)
	}
	if _, err := te.svc.SetRoleGroup(ctx, system(), finance.ID, other.ID, ""); err != nil {
		t.Fatal(err)
	}

	// Effective members: ann both ways (manager wins), bob through the role,
	// cid directly.
	members, err := te.svc.Members(ctx, g.ID)
	if err != nil || len(members) != 3 {
		t.Fatalf("members %+v %v", members, err)
	}
	fr := []core.RoleRef{{ID: finance.ID, Name: "Finance", MemberRole: core.GroupRoleManager}}
	for i, want := range []core.GroupMember{
		{UserID: ann.ID, Username: "ann", Role: core.GroupRoleManager, Direct: true, DirectRole: core.GroupRoleMember, ViaRoles: fr},
		{UserID: bob.ID, Username: "bob", Role: core.GroupRoleManager, ViaRoles: fr},
		{UserID: cid.ID, Username: "cid", Role: core.GroupRoleManager, Direct: true, DirectRole: core.GroupRoleManager},
	} {
		m := members[i]
		if m.UserID != want.UserID || m.Username != want.Username || m.GroupID != g.ID || m.Role != want.Role ||
			m.Direct != want.Direct || m.DirectRole != want.DirectRole || !slices.Equal(m.ViaRoles, want.ViaRoles) {
			t.Errorf("member %d: %+v", i, m)
		}
	}
	// AddedAt: the direct membership's, else the role membership's.
	if !members[0].AddedAt.Before(members[2].AddedAt) || !members[1].AddedAt.Equal(rg.AddedAt) {
		t.Errorf("added: %v %v %v", members[0].AddedAt, members[1].AddedAt, members[2].AddedAt)
	}
	got, err := te.svc.GetGroup(ctx, g.ID)
	if err != nil || got.MemberCount != 3 || got.RoleCount != 2 || len(got.Roles) != 2 ||
		got.Roles[0].RoleName != "Auditors" || got.Roles[1].RoleName != "Finance" {
		t.Fatalf("group %+v %v", got, err)
	}
	page, _ := te.svc.ListGroups(ctx, core.PageReq{})
	if page.Items[0].Name != "Accounts" || page.Items[0].MemberCount != 3 || page.Items[0].RoleCount != 2 || page.Items[0].Roles != nil {
		t.Fatalf("list %+v", page.Items[0])
	}
	list, err := te.svc.RoleGroups(ctx, finance.ID)
	if err != nil || len(list) != 2 || list[0].GroupName != "Accounts" || list[1].GroupName != "Other" {
		t.Fatalf("RoleGroups %+v %v", list, err)
	}
	if list, err := te.svc.RoleGroups(ctx, "member"); err != nil || len(list) != 0 {
		t.Fatalf("built-in RoleGroups %+v %v", list, err)
	}
	if _, err := te.svc.RoleGroups(ctx, "rol_01k5z8r3m9d4q7w2x6c1v0b5na"); !errors.Is(err, core.ErrNotFound) {
		t.Fatalf("unknown RoleGroups %v", err)
	}

	// The holder's own view.
	mine, err := te.svc.MyGroups(ctx, as(bob))
	if err != nil || len(mine) != 2 || mine[0].Name != "Accounts" || mine[0].Via != "role" || mine[0].MyRole != core.GroupRoleManager ||
		mine[1].Via != "role" || mine[1].MyRole != core.GroupRoleMember {
		t.Fatalf("bob's groups %+v %v", mine, err)
	}
	if mine, _ := te.svc.MyGroups(ctx, as(ann)); mine[0].Via != "direct" || mine[0].MyRole != core.GroupRoleManager {
		t.Fatalf("ann's groups %+v", mine)
	}
	if ids, _ := te.svc.GroupIDsOf(ctx, bob.ID); len(ids) != 2 || !slices.Contains(ids, g.ID) || !slices.Contains(ids, other.ID) {
		t.Fatalf("GroupIDsOf %v", ids)
	}
	access, err := te.svc.GroupsOf(ctx, ann.ID)
	if err != nil || len(access) != 2 {
		t.Fatalf("GroupsOf %+v %v", access, err)
	}
	if a := access[0]; a.GroupID != g.ID || a.Name != "Accounts" || a.SpaceID != g.SpaceID || a.Role != core.GroupRoleManager ||
		!a.Direct || a.DirectRole != core.GroupRoleMember || !slices.Equal(a.ViaRoles, fr) {
		t.Fatalf("access %+v", a)
	}
	if a := access[1]; a.GroupID != other.ID || a.Direct || a.Role != core.GroupRoleMember || len(a.ViaRoles) != 1 {
		t.Fatalf("access %+v", a)
	}
	if none, err := te.svc.GroupsOf(ctx, cid.ID+"x"); err != nil || none == nil || len(none) != 0 {
		t.Fatalf("GroupsOf unknown %+v %v", none, err)
	}

	// Someone who gets the role later is a member at once; someone who loses
	// it is not.
	dan := te.mkUser(t, "dan", core.RoleMember)
	if _, err := te.svc.Update(ctx, system(), dan.ID, core.UserUpdate{RoleID: &finance.ID}); err != nil {
		t.Fatal(err)
	}
	if _, err := te.svc.Update(ctx, system(), bob.ID, core.UserUpdate{RoleID: ptr("member")}); err != nil {
		t.Fatal(err)
	}
	if ids, _ := te.svc.GroupIDsOf(ctx, dan.ID); !slices.Contains(ids, g.ID) {
		t.Fatalf("dan %v", ids)
	}
	if ids, _ := te.svc.GroupIDsOf(ctx, bob.ID); len(ids) != 0 {
		t.Fatalf("bob %v", ids)
	}

	// A member only through the role cannot be removed directly; one with a
	// direct membership loses that one and stays through the role.
	err = te.svc.RemoveMember(ctx, as(admin), g.ID, dan.ID)
	wantErr(t, "remove role member", err, core.ErrConflict, "",
		"“dan” is a member through the role “Finance”; remove the role from the group or change their role")
	if err := te.svc.RemoveMember(ctx, as(admin), g.ID, ann.ID); err != nil {
		t.Fatal(err)
	}
	if ids, _ := te.svc.GroupIDsOf(ctx, ann.ID); !slices.Contains(ids, g.ID) {
		t.Fatal("ann lost the role membership")
	}
	if err := te.svc.RemoveMember(ctx, as(admin), g.ID, bob.ID); !errors.Is(err, core.ErrNotFound) {
		t.Fatalf("remove non-member: %v", err)
	}

	// Removing the role from the group.
	evs()
	te.audit.reset()
	err = te.svc.RemoveRoleGroup(ctx, member, finance.ID, g.ID)
	wantErr(t, "member removes", err, core.ErrForbidden, "", "")
	if err := te.svc.RemoveRoleGroup(ctx, as(admin), finance.ID, g.ID); err != nil {
		t.Fatal(err)
	}
	e, _ = te.audit.last(core.ActGroupRoleRemove)
	if d, _ := e.Details.(map[string]any); e.TargetID != g.ID || d["role_id"] != finance.ID || d["member_role"] != core.GroupRoleManager {
		t.Fatalf("remove audit %+v", e)
	}
	if ev := evs(); len(ev) != 1 || ev[0].Reason != core.AuthzRoleGroups {
		t.Fatalf("events %+v", ev)
	}
	err = te.svc.RemoveRoleGroup(ctx, as(admin), finance.ID, g.ID)
	wantErr(t, "remove twice", err, core.ErrNotFound, "", "the role is not a member of this group")
	if ids, _ := te.svc.GroupIDsOf(ctx, dan.ID); slices.Contains(ids, g.ID) {
		t.Fatal("dan still a member")
	}

	// A direct manager who is also a member through the role (added earlier)
	// stays manager, and AddedAt is the direct membership's.
	te.clock.Advance(time.Hour)
	if err := te.svc.SetMember(ctx, as(admin), other.ID, ann.ID, core.GroupRoleManager); err != nil {
		t.Fatal(err)
	}
	members, _ = te.svc.Members(ctx, other.ID)
	i := slices.IndexFunc(members, func(m core.GroupMember) bool { return m.UserID == ann.ID })
	if i < 0 || members[i].Role != core.GroupRoleManager || !members[i].Direct || !members[i].AddedAt.Equal(te.clock.Now()) ||
		len(members[i].ViaRoles) != 1 || members[i].ViaRoles[0].MemberRole != core.GroupRoleMember {
		t.Fatalf("ann in Other: %+v", members)
	}

	// Deleting a group takes its role memberships along.
	evs()
	if err := te.svc.DeleteGroup(ctx, as(admin), other.ID); err != nil {
		t.Fatal(err)
	}
	if n := te.count(t, `SELECT count(*) FROM role_groups WHERE group_id = ?`, other.ID); n != 0 {
		t.Fatalf("%d role memberships left", n)
	}
	e, _ = te.audit.last(core.ActGroupDelete)
	if d := e.Details.(map[string]any); d["roles"] != 1 || d["members"] != 2 {
		t.Fatalf("delete audit %+v", d)
	}
	if ev := evs(); len(ev) != 1 || ev[0].RoleID != finance.ID || ev[0].Reason != core.AuthzRoleGroups {
		t.Fatalf("delete events %+v", ev)
	}
}

// A role can be a member of at most 500 groups.
func TestRoleGroupLimit(t *testing.T) {
	te := newTestEnv(t)
	ctx := context.Background()
	r := te.createRole(t, core.RoleDefInput{Name: "Everywhere"})
	te.exec(t, `WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i + 1 FROM n WHERE i < 500)
		INSERT INTO groups (id, name, description, created_at) SELECT printf('grp_bulk%03d', i), printf('Bulk %03d', i), '', 1 FROM n`)
	te.exec(t, `INSERT INTO role_groups (role_id, group_id, member_role, added_at) SELECT ?, id, 'member', 1 FROM groups`, r.ID)
	g, err := te.svc.CreateGroup(ctx, system(), core.GroupInput{Name: "One more"})
	if err != nil {
		t.Fatal(err)
	}
	_, err = te.svc.SetRoleGroup(ctx, system(), r.ID, g.ID, "")
	wantErr(t, "501st group", err, core.ErrInvalid, "group_id", "a role can be a member of at most 500 groups")
	// Changing an existing membership is not an addition.
	if _, err := te.svc.SetRoleGroup(ctx, system(), r.ID, "grp_bulk001", core.GroupRoleManager); err != nil {
		t.Fatal(err)
	}
}

// Groups are managed with groups.manage, which a custom role can hold.
func TestGroupsManageDelegated(t *testing.T) {
	te := newTestEnv(t)
	ctx := context.Background()
	r := te.createRole(t, core.RoleDefInput{Name: "Group managers", Permissions: capList(core.CapGroupsManage)})
	gm := te.mkUser(t, "gm", core.RoleMember)
	te.giveRole(t, gm, r.ID)
	other := te.mkUser(t, "other", core.RoleMember)
	p := te.principalOf(t, gm)
	g, err := te.svc.CreateGroup(ctx, p, core.GroupInput{Name: "Design"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := te.svc.UpdateGroup(ctx, p, g.ID, core.GroupInput{Name: "Design team"}); err != nil {
		t.Fatal(err)
	}
	if err := te.svc.SetMember(ctx, p, g.ID, other.ID, ""); err != nil {
		t.Fatal(err)
	}
	if _, err := te.svc.SetRoleGroup(ctx, p, r.ID, g.ID, ""); err != nil {
		t.Fatal(err)
	}
	if err := te.svc.RemoveMember(ctx, p, g.ID, other.ID); err != nil {
		t.Fatal(err)
	}
	if err := te.svc.DeleteGroup(ctx, p, g.ID); err != nil {
		t.Fatal(err)
	}
	_, err = te.svc.CreateGroup(ctx, as(other), core.GroupInput{Name: "Nope"})
	wantErr(t, "member", err, core.ErrForbidden, "", "this needs the “Manage groups” permission")
}
