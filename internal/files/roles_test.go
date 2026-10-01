package files

import (
	"slices"
	"testing"
	"time"

	"fileparcel/internal/core"
	"fileparcel/internal/db"
	"fileparcel/internal/ids"
)

// role creates a custom role with the stored permissions caps.
func (e *testEnv) role(name string, base core.Role, caps ...core.Capability) string {
	e.t.Helper()
	id := ids.New(ids.PrefixRole)
	now := db.Ms(e.clock.Now())
	if _, err := e.db.Exec(e.ctx, `INSERT INTO roles (id, name, base, permissions, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?)`, id, name, string(base), core.EncodeCaps(core.NewCapSet(caps...)), now, now); err != nil {
		e.t.Fatal(err)
	}
	return id
}

// assign gives u the custom role roleID ("" = back to the plain built-in
// base role) in the database and updates u's principal the way package auth
// builds it on the next request.
func (e *testEnv) assign(u *user, roleID string) {
	e.t.Helper()
	if roleID == "" {
		if _, err := e.db.Exec(e.ctx, `UPDATE users SET role_id = NULL WHERE id = ?`, u.UserID); err != nil {
			e.t.Fatal(err)
		}
		u.RoleID, u.RoleName = string(u.Role), core.BuiltinRoleName(u.Role)
		u.SetCaps(core.BuiltinCaps(u.Role, false))
		return
	}
	var name, base, perms string
	if err := e.db.QueryRow(e.ctx, `SELECT name, base, permissions FROM roles WHERE id = ?`, roleID).
		Scan(&name, &base, &perms); err != nil {
		e.t.Fatal(err)
	}
	if _, err := e.db.Exec(e.ctx, `UPDATE users SET role = ?, role_id = ? WHERE id = ?`, base, roleID, u.UserID); err != nil {
		e.t.Fatal(err)
	}
	u.Role, u.RoleID, u.RoleName = core.Role(base), roleID, name
	u.SetCaps(core.EffectiveRoleCaps(u.Role, roleID, core.DecodeStoredCaps(perms), false))
}

// roleGroup makes every holder of roleID a member (or manager) of groupID.
func (e *testEnv) roleGroup(roleID, groupID, memberRole string) {
	e.t.Helper()
	if _, err := e.db.Exec(e.ctx, `INSERT INTO role_groups (role_id, group_id, member_role, added_at) VALUES (?, ?, ?, ?)
		ON CONFLICT (role_id, group_id) DO UPDATE SET member_role = excluded.member_role`,
		roleID, groupID, memberRole, db.Ms(e.clock.Now())); err != nil {
		e.t.Fatal(err)
	}
}

// perm returns p's permission on id ("" when it cannot see it).
func (e *testEnv) perm(p *core.Principal, id string) string {
	e.t.Helper()
	n, err := e.svc.Get(e.ctx, p, id)
	if code(err) == "not_found" {
		return ""
	}
	if err != nil {
		e.t.Fatalf("get %s: %v", id, err)
	}
	return n.Perm.String()
}

// A folder shared with a custom role is open to everyone holding it —
// including accounts that get the role later — at the granted level, and
// closes on the next request once the role is gone. Built-in roles never
// match a role grant.
func TestRoleGrants(t *testing.T) {
	e := newEnv(t)
	owner := e.user("olga", core.RoleMember)
	con1 := e.user("con1", core.RoleGuest)
	con2 := e.user("con2", core.RoleGuest)
	guest := e.user("gus", core.RoleGuest)
	member := e.user("mel", core.RoleMember)
	contractors := e.role("Contractors", core.RoleGuest, core.CapShareRequests)
	e.assign(con1, contractors)
	e.assign(con2, contractors)
	e.assign(member, "") // a plain member: RoleID "member", role_id NULL

	briefs := e.mkdir(owner, owner.rootID, "Briefs")
	inner := e.mkdir(owner, briefs.ID, "Round 1")
	doc := e.file(owner, inner.ID, "brief.txt", "the brief")
	e.file(owner, owner.rootID, "private.txt", "no")

	g := e.grant(owner, briefs.ID, core.SubjectRole, contractors, core.GrantViewer)
	if g.SubjectType != core.SubjectRole || g.SubjectID != contractors || g.SubjectName != "Contractors" || g.Role != core.GrantViewer {
		t.Fatalf("grant %+v", g)
	}
	if a := e.audit.last(core.ActGrantSet); a == nil {
		t.Fatal("grant.set not audited")
	} else if d, _ := a.Details.(map[string]any); d["subject_type"] != core.SubjectRole ||
		d["subject_id"] != contractors || d["role"] != core.GrantViewer {
		t.Fatalf("grant.set audit %+v", a)
	}
	for _, u := range []*user{con1, con2} {
		if got := e.perm(u.Principal, doc.ID); got != "view" {
			t.Errorf("%s on the inherited file: %q", u.Username, got)
		}
	}
	for _, u := range []*user{guest, member} {
		if got := e.perm(u.Principal, doc.ID); got != "" {
			t.Errorf("%s sees the role's folder: %q", u.Username, got)
		}
	}
	if got := e.perm(con1.Principal, owner.rootID); got != "" {
		t.Errorf("role holder sees the owner's root: %q", got)
	}
	_, err := e.svc.Mkdir(e.ctx, con1.Principal, briefs.ID, "x")
	wantCode(t, err, "forbidden")

	// Shared with me, search, breadcrumbs and paths start at the grant.
	sw, err := e.svc.SharedWithMe(e.ctx, con1.Principal, core.ListQuery{})
	if err != nil || !slices.Equal(nodeNames(sw.Items), []string{"Briefs"}) || sw.Items[0].Perm != core.PermView {
		t.Fatalf("shared with the role: %+v %v", sw.Items, err)
	}
	if got := e.search(con1, core.SearchQuery{Q: "brief"}); !slices.Equal(got, []string{"Briefs", "brief.txt"}) {
		t.Errorf("search %v", got)
	}
	if got := e.search(con1, core.SearchQuery{Q: "private"}); len(got) != 0 {
		t.Errorf("search outside the grant %v", got)
	}
	bc, err := e.svc.Breadcrumbs(e.ctx, con1.Principal, doc.ID)
	if err != nil || !slices.Equal(nodeNames(bc), []string{"Briefs", "Round 1", "brief.txt"}) {
		t.Fatalf("crumbs %v %v", nodeNames(bc), err)
	}
	rec, err := e.svc.Recent(e.ctx, con1.Principal, 10)
	if err != nil || len(rec) != 1 || rec[0].Path != "/Briefs/Round 1/brief.txt" {
		t.Fatalf("recent %+v %v", rec, err)
	}

	// Editor, then manager: the same grant row is updated.
	g2 := e.grant(owner, briefs.ID, core.SubjectRole, contractors, core.GrantEditor)
	if g2.ID != g.ID {
		t.Fatalf("upsert created a new grant: %s != %s", g2.ID, g.ID)
	}
	if _, err := e.svc.Mkdir(e.ctx, con1.Principal, briefs.ID, "Uploads"); err != nil {
		t.Fatalf("editor mkdir: %v", err)
	}
	_, err = e.svc.Grants(e.ctx, con1.Principal, briefs.ID)
	wantCode(t, err, "forbidden")
	e.grant(owner, briefs.ID, core.SubjectRole, contractors, core.GrantManager)
	if got := e.perm(con1.Principal, doc.ID); got != "manage" {
		t.Fatalf("manager grant: %q", got)
	}
	// A manager re-shares inside the subtree …
	if _, err := e.svc.SetGrant(e.ctx, con1.Principal, inner.ID, core.GrantInput{SubjectType: core.SubjectUser,
		SubjectID: guest.UserID, Role: core.GrantViewer}); err != nil {
		t.Fatalf("manager shares onward: %v", err)
	}
	if got := e.perm(guest.Principal, doc.ID); got != "view" {
		t.Errorf("re-shared: %q", got)
	}
	gl, err := e.svc.Grants(e.ctx, con1.Principal, inner.ID)
	if err != nil || len(gl) != 2 || gl[0].SubjectType != core.SubjectRole || gl[0].Role != core.GrantManager {
		t.Fatalf("grants seen by the manager: %+v %v", gl, err)
	}
	// … but never purges in (or moves out of) a personal space: that stays
	// PermOwner, which grants never give.
	if err := e.svc.Trash(e.ctx, con1.Principal, []string{doc.ID}); err != nil {
		t.Fatalf("manager trashes: %v", err)
	}
	wantCode(t, e.svc.Purge(e.ctx, con1.Principal, []string{doc.ID}), "forbidden")
	if _, err := e.svc.Restore(e.ctx, con1.Principal, []string{doc.ID}); err != nil {
		t.Fatal(err)
	}

	// Live: a new holder gets access on the next call, a former one loses it.
	late := e.user("late", core.RoleGuest)
	if got := e.perm(late.Principal, doc.ID); got != "" {
		t.Fatalf("before the role: %q", got)
	}
	e.assign(late, contractors)
	if got := e.perm(late.Principal, doc.ID); got != "manage" {
		t.Fatalf("after the role: %q", got)
	}
	stale := con2.Clone() // the principal still names the role …
	e.assign(con2, "")    // … but the account no longer holds it
	if got := e.perm(stale, doc.ID); got != "" {
		t.Fatalf("former holder with a stale principal: %q", got)
	}
	if sw, _ := e.svc.SharedWithMe(e.ctx, stale, core.ListQuery{}); len(sw.Items) != 0 {
		t.Fatalf("former holder's shared-with-me: %v", nodeNames(sw.Items))
	}

	// An expired role grant is ignored.
	exp := e.clock.Now().Add(time.Hour)
	other := e.mkdir(owner, owner.rootID, "Later")
	if _, err := e.svc.SetGrant(e.ctx, owner.Principal, other.ID, core.GrantInput{SubjectType: core.SubjectRole,
		SubjectID: contractors, Role: core.GrantEditor, ExpiresAt: &exp}); err != nil {
		t.Fatal(err)
	}
	if got := e.perm(con1.Principal, other.ID); got != "edit" {
		t.Fatalf("live role grant: %q", got)
	}
	e.clock.Advance(2 * time.Hour)
	if got := e.perm(con1.Principal, other.ID); got != "" {
		t.Fatalf("expired role grant: %q", got)
	}
}

// A manager grant on a subfolder of a team folder raises a member (PermEdit
// on the whole team folder) to PermManage there — also in listings of the
// parent — and, in a group space where nobody holds PermOwner, allows
// purging inside that subtree like a group manager.
func TestManagerGrantInTeamFolder(t *testing.T) {
	e := newEnv(t)
	boss := e.user("boss", core.RoleMember)
	mem := e.user("mem", core.RoleMember)
	gid, _, root := e.group("Team")
	e.member(gid, boss, core.GroupRoleManager)
	e.member(gid, mem, core.GroupRoleMember)
	reports := e.mkdir(boss, root, "Reports")
	q3 := e.file(boss, reports.ID, "q3.txt", "q3")
	other := e.mkdir(boss, root, "Other")

	if got := e.perm(mem.Principal, reports.ID); got != "edit" {
		t.Fatalf("member before the grant: %q", got)
	}
	e.grant(boss, reports.ID, core.SubjectUser, mem.UserID, core.GrantManager)
	for id, want := range map[string]string{reports.ID: "manage", q3.ID: "manage", other.ID: "edit", root: "edit"} {
		if got := e.perm(mem.Principal, id); got != want {
			t.Errorf("perm on %s: %q, want %q", id, got, want)
		}
	}
	page, err := e.svc.List(e.ctx, mem.Principal, root, core.ListQuery{})
	if err != nil {
		t.Fatal(err)
	}
	for _, n := range page.Items {
		want := map[string]core.Perm{"Reports": core.PermManage, "Other": core.PermEdit}[n.Name]
		if n.Perm != want {
			t.Errorf("listing: %s has %s, want %s", n.Name, n.Perm, want)
		}
	}
	page, err = e.svc.List(e.ctx, mem.Principal, reports.ID, core.ListQuery{})
	if err != nil || len(page.Items) != 1 || page.Items[0].Perm != core.PermManage {
		t.Fatalf("children of the managed folder: %+v %v", page.Items, err)
	}
	_, err = e.svc.Grants(e.ctx, mem.Principal, root)
	wantCode(t, err, "forbidden")
	if err := e.svc.Trash(e.ctx, mem.Principal, []string{q3.ID}); err != nil {
		t.Fatal(err)
	}
	if err := e.svc.Purge(e.ctx, mem.Principal, []string{q3.ID}); err != nil {
		t.Fatalf("purge inside the managed subtree: %v", err)
	}
	junk := e.file(boss, other.ID, "junk.txt", "j")
	if err := e.svc.Trash(e.ctx, mem.Principal, []string{junk.ID}); err != nil {
		t.Fatal(err)
	}
	wantCode(t, e.svc.Purge(e.ctx, mem.Principal, []string{junk.ID}), "forbidden")
}

// Holders of a role that is a member (or manager) of a group get its team
// folder like direct members: listed under Spaces with PermEdit (PermManage
// for managers; manager wins over a direct member row), searchable, in the
// trash view, kept out of Shared with me, and group grants apply to them.
// Taking the role away closes it on the next call.
func TestRoleGroupMembership(t *testing.T) {
	e := newEnv(t)
	boss := e.user("boss", core.RoleMember)
	fin := e.user("fin", core.RoleMember)
	outsider := e.user("out", core.RoleMember)
	finance := e.role("Finance", core.RoleMember, core.CapShareLinks)
	e.assign(fin, finance)
	gid, spaceID, root := e.group("Finance")
	e.member(gid, boss, core.GroupRoleManager)
	ledger := e.file(boss, root, "ledger.csv", "1,2")

	spaceOf := func(u *user) *core.Space {
		t.Helper()
		list, err := e.svc.Spaces(e.ctx, u.Principal)
		if err != nil {
			t.Fatal(err)
		}
		for i := range list {
			if list[i].ID == spaceID {
				return &list[i]
			}
		}
		return nil
	}
	if spaceOf(fin) != nil || e.perm(fin.Principal, ledger.ID) != "" {
		t.Fatal("team folder visible before the role joined the group")
	}

	e.roleGroup(finance, gid, core.GroupRoleMember)
	if s := spaceOf(fin); s == nil || s.Perm != core.PermEdit || s.RootID != root {
		t.Fatalf("space through the role: %+v", s)
	}
	if spaceOf(outsider) != nil {
		t.Fatal("outsider sees the team folder")
	}
	if got := e.search(fin, core.SearchQuery{Q: "ledger"}); !slices.Equal(got, []string{"ledger.csv"}) {
		t.Errorf("search %v", got)
	}
	if _, err := e.svc.Mkdir(e.ctx, fin.Principal, root, "Invoices"); err != nil {
		t.Fatalf("member through the role creates a folder: %v", err)
	}
	_, err := e.svc.Grants(e.ctx, fin.Principal, root)
	wantCode(t, err, "forbidden")

	// Trash view: the role member sees what was trashed in the team folder.
	if err := e.svc.Trash(e.ctx, boss.Principal, []string{ledger.ID}); err != nil {
		t.Fatal(err)
	}
	tr, err := e.svc.ListTrash(e.ctx, fin.Principal, core.ListQuery{})
	if err != nil || !slices.Equal(nodeNames(tr.Items), []string{"ledger.csv"}) {
		t.Fatalf("trash %v %v", nodeNames(tr.Items), err)
	}
	if _, err := e.svc.Restore(e.ctx, fin.Principal, []string{ledger.ID}); err != nil {
		t.Fatal(err)
	}

	// A grant on the team folder's content is not "shared with me" (the
	// folder is theirs already); a grant to the group elsewhere is.
	e.grant(boss, ledger.ID, core.SubjectUser, fin.UserID, core.GrantEditor)
	elsewhere := e.mkdir(boss, boss.rootID, "Board pack")
	e.grant(boss, elsewhere.ID, core.SubjectGroup, gid, core.GrantViewer)
	sw, err := e.svc.SharedWithMe(e.ctx, fin.Principal, core.ListQuery{})
	if err != nil || !slices.Equal(nodeNames(sw.Items), []string{"Board pack"}) {
		t.Fatalf("shared with me %v %v", nodeNames(sw.Items), err)
	}

	// Manager through the role; manager wins over a direct member row.
	e.roleGroup(finance, gid, core.GroupRoleManager)
	if s := spaceOf(fin); s == nil || s.Perm != core.PermManage {
		t.Fatalf("manager through the role: %+v", s)
	}
	e.member(gid, fin, core.GroupRoleMember)
	if s := spaceOf(fin); s == nil || s.Perm != core.PermManage {
		t.Fatalf("direct member + role manager: %+v", s)
	}
	e.roleGroup(finance, gid, core.GroupRoleMember)
	if _, err := e.db.Exec(e.ctx, `UPDATE group_members SET role = 'manager' WHERE user_id = ?`, fin.UserID); err != nil {
		t.Fatal(err)
	}
	if s := spaceOf(fin); s == nil || s.Perm != core.PermManage {
		t.Fatalf("direct manager + role member: %+v", s)
	}
	if _, err := e.svc.Grants(e.ctx, fin.Principal, root); err != nil {
		t.Fatalf("manager lists grants: %v", err)
	}
	if _, err := e.db.Exec(e.ctx, `DELETE FROM group_members WHERE user_id = ?`, fin.UserID); err != nil {
		t.Fatal(err)
	}

	// Without the role the team folder closes on the next call.
	stale := fin.Clone()
	e.assign(fin, "")
	if spaceOf(fin) != nil || e.perm(stale, root) != "" || e.perm(stale, elsewhere.ID) != "" {
		t.Fatal("team folder still open after the role was taken away")
	}
	if got := e.perm(stale, ledger.ID); got != "edit" { // the grant to the account itself stays
		t.Fatalf("own grant after the role change: %q", got)
	}
}

// SetGrant accepts custom roles as subjects and the manager level, and
// refuses everything else with the field that is wrong.
func TestSetGrantValidation(t *testing.T) {
	e := newEnv(t)
	owner := e.user("olga", core.RoleMember)
	folder := e.mkdir(owner, owner.rootID, "F")
	finance := e.role("Finance", core.RoleMember)
	for _, c := range []struct {
		in           core.GrantInput
		field, msg   string
		code         string
		subjectName  string
		wantSubjType string
	}{
		{in: core.GrantInput{SubjectType: "everyone", SubjectID: finance, Role: core.GrantViewer},
			code: "invalid", field: "subject_type", msg: "subject_type must be user, group or role"},
		{in: core.GrantInput{SubjectType: core.SubjectRole, SubjectID: finance, Role: "owner"},
			code: "invalid", field: "role", msg: "role must be viewer, editor or manager"},
		{in: core.GrantInput{SubjectType: core.SubjectRole, SubjectID: "member", Role: core.GrantViewer},
			code: "invalid", field: "subject_id", msg: "unknown role"},
		{in: core.GrantInput{SubjectType: core.SubjectRole, SubjectID: ids.New(ids.PrefixRole), Role: core.GrantViewer},
			code: "invalid", field: "subject_id", msg: "unknown role"},
		{in: core.GrantInput{SubjectType: core.SubjectGroup, SubjectID: finance, Role: core.GrantViewer},
			code: "invalid", field: "subject_id", msg: "unknown group"},
		{in: core.GrantInput{SubjectType: core.SubjectRole, SubjectID: finance, Role: core.GrantManager},
			subjectName: "Finance"},
	} {
		g, err := e.svc.SetGrant(e.ctx, owner.Principal, folder.ID, c.in)
		if c.code != "" {
			ce := core.AsError(err)
			if ce == nil || ce.Code != c.code || ce.Field != c.field || ce.Message != c.msg {
				t.Errorf("%+v: %v (%+v)", c.in, err, ce)
			}
			continue
		}
		if err != nil || g.SubjectName != c.subjectName || g.Role != core.GrantManager {
			t.Errorf("%+v: %+v %v", c.in, g, err)
		}
	}
	// Grants on the node list the role by name.
	gl, err := e.svc.Grants(e.ctx, owner.Principal, folder.ID)
	if err != nil || len(gl) != 1 || gl[0].SubjectName != "Finance" {
		t.Fatalf("grants %+v %v", gl, err)
	}
}
