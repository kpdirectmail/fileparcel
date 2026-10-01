package files

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"fileparcel/internal/core"
	"fileparcel/internal/db"
	"fileparcel/internal/ids"
	"fileparcel/internal/names"
)

// grantRow renders a SubjectGrants row for comparisons.
func grantRow(g core.Grant) string {
	return fmt.Sprintf("%s:%s %s>%s:%s %s", g.SpaceName, g.NodePath, g.SubjectType, g.SubjectName, g.Role, g.CallerPerm)
}

func grantRows(sg *core.SubjectGrants) string {
	out := make([]string, len(sg.Items))
	for i, g := range sg.Items {
		out[i] = grantRow(g)
	}
	return strings.Join(out, " | ")
}

// SubjectGrants (GET /admin/grants) lists the live grants to one subject —
// with Expand, also those reaching a user through their groups and role —
// and shows each row only to callers who may see the item: everything for
// the system principal, team folders for holders of groups.manage, items
// the caller can open, and items the admin override opens (audited per
// space). The rest is counted in Hidden.
func TestSubjectGrants(t *testing.T) {
	e := newEnv(t)
	alice := e.user("alice", core.RoleMember)
	bob := e.user("bob", core.RoleMember)
	admin := e.user("carl", core.RoleAdmin)
	helpdesk := e.user("hd", core.RoleMember)
	e.assign(helpdesk, e.role("Helpdesk", core.RoleMember, core.CapUsersView, core.CapUsersManage))
	teams := e.user("gm", core.RoleMember)
	e.assign(teams, e.role("Group managers", core.RoleMember, core.CapGroupsManage))
	staffers := e.role("Staffers", core.RoleMember, core.CapShareLinks)
	e.assign(bob, staffers)
	viewers, _, _ := e.group("Viewers")
	e.member(viewers, bob, core.GroupRoleMember)
	designGroup, _, design := e.group("Design")
	designer := e.user("dee", core.RoleMember)
	e.member(designGroup, designer, core.GroupRoleManager)

	private := e.mkdir(alice, alice.rootID, "Private")
	deep := e.mkdir(alice, private.ID, "Deep")
	doc := e.file(alice, deep.ID, "doc.txt", "d")
	shared := e.mkdir(alice, alice.rootID, "Shared")
	roles := e.mkdir(alice, alice.rootID, "Roles")
	old := e.mkdir(alice, alice.rootID, "Old")
	temp := e.mkdir(alice, alice.rootID, "Temp")
	specs := e.mkdir(designer, design, "Specs")

	e.grant(alice, private.ID, core.SubjectUser, bob.UserID, core.GrantViewer)
	e.grant(alice, doc.ID, core.SubjectUser, bob.UserID, core.GrantEditor)
	e.grant(alice, shared.ID, core.SubjectGroup, viewers, core.GrantViewer)
	e.grant(alice, roles.ID, core.SubjectRole, staffers, core.GrantManager)
	e.grant(alice, old.ID, core.SubjectUser, bob.UserID, core.GrantViewer)
	exp := e.clock.Now().Add(time.Hour)
	if _, err := e.svc.SetGrant(e.ctx, alice.Principal, temp.ID, core.GrantInput{SubjectType: core.SubjectUser,
		SubjectID: bob.UserID, Role: core.GrantViewer, ExpiresAt: &exp}); err != nil {
		t.Fatal(err)
	}
	e.grant(designer, specs.ID, core.SubjectUser, bob.UserID, core.GrantEditor)
	e.grant(alice, deep.ID, core.SubjectUser, helpdesk.UserID, core.GrantViewer) // the helpdesk's own access
	if err := e.svc.Trash(e.ctx, alice.Principal, []string{old.ID}); err != nil {
		t.Fatal(err)
	}
	e.clock.Advance(2 * time.Hour) // the grant on Temp has expired

	list := func(p *core.Principal, q core.SubjectGrantQuery) *core.SubjectGrants {
		t.Helper()
		sg, err := e.svc.SubjectGrants(e.ctx, p, q)
		if err != nil {
			t.Fatalf("SubjectGrants(%s, %+v): %v", p.Username, q, err)
		}
		return sg
	}
	userQ := core.SubjectGrantQuery{SubjectType: core.SubjectUser, SubjectID: bob.UserID}
	expandQ := userQ
	expandQ.Expand = true
	sys := core.SystemPrincipal(core.ViaSocket)

	for _, c := range []struct {
		name   string
		p      *core.Principal
		q      core.SubjectGrantQuery
		rows   string
		hidden int
	}{
		{"system", sys, userQ,
			"alice:/Private user>bob:viewer owner | alice:/Private/Deep/doc.txt user>bob:editor owner | " +
				"Design:/Specs user>bob:editor owner", 0},
		{"system, expanded", sys, expandQ,
			"alice:/Private user>bob:viewer owner | alice:/Private/Deep/doc.txt user>bob:editor owner | " +
				"alice:/Roles role>Staffers:manager owner | alice:/Shared group>Viewers:viewer owner | " +
				"Design:/Specs user>bob:editor owner", 0},
		{"group grants", sys, core.SubjectGrantQuery{SubjectType: core.SubjectGroup, SubjectID: viewers},
			"alice:/Shared group>Viewers:viewer owner", 0},
		{"role grants", sys, core.SubjectGrantQuery{SubjectType: core.SubjectRole, SubjectID: staffers},
			"alice:/Roles role>Staffers:manager owner", 0},
		// Built-in admins hold groups.manage: team folders are visible
		// (without a permission of their own there), personal spaces not.
		{"admin", admin.Principal, userQ, "Design:/Specs user>bob:editor none", 2},
		// Only what the caller can open, the path starting at their grant.
		{"helpdesk", helpdesk.Principal, userQ, "alice:/Deep/doc.txt user>bob:editor view", 2},
		{"group managers", teams.Principal, userQ, "Design:/Specs user>bob:editor none", 2},
		{"owner of the items", alice.Principal, expandQ,
			"alice:/Private user>bob:viewer owner | alice:/Private/Deep/doc.txt user>bob:editor owner | " +
				"alice:/Roles role>Staffers:manager owner | alice:/Shared group>Viewers:viewer owner", 1},
		{"team member", designer.Principal, userQ, "Design:/Specs user>bob:editor manage", 2},
	} {
		before := e.audit.count(core.ActAdminFileAccess)
		sg := list(c.p, c.q)
		if got := grantRows(sg); got != c.rows || sg.Hidden != c.hidden {
			t.Errorf("%s:\n got %s (hidden %d)\nwant %s (hidden %d)", c.name, got, sg.Hidden, c.rows, c.hidden)
		}
		if e.audit.count(core.ActAdminFileAccess) != before {
			t.Errorf("%s: audited admin.file_access", c.name)
		}
	}

	// The derived fields of a row, and caller_perm omitted where the caller
	// has no permission of their own.
	sg := list(sys, userQ)
	if g := sg.Items[1]; g.NodeName != "doc.txt" || g.NodeKind != core.KindFile || g.SpaceKind != core.SpaceUser ||
		g.NodeID != doc.ID || g.SubjectID != bob.UserID || g.CreatedBy != alice.UserID {
		t.Errorf("row fields %+v", g)
	}
	b, _ := json.Marshal(list(admin.Principal, userQ).Items[0])
	if strings.Contains(string(b), "caller_perm") || !strings.Contains(string(b), `"space_kind":"group"`) {
		t.Errorf("admin row JSON %s", b)
	}

	// With auth.admin_can_access_files the admin sees everything; opening
	// alice's space that way is audited once, on its root.
	e.settings.set(settingAdminAccess, true)
	before := e.audit.count(core.ActAdminFileAccess)
	sg = list(admin.Principal, expandQ)
	want := "alice:/Private user>bob:viewer manage | alice:/Private/Deep/doc.txt user>bob:editor manage | " +
		"alice:/Roles role>Staffers:manager manage | alice:/Shared group>Viewers:viewer manage | " +
		"Design:/Specs user>bob:editor manage"
	if got := grantRows(sg); got != want || sg.Hidden != 0 {
		t.Errorf("admin with the override:\n got %s (hidden %d)\nwant %s", got, sg.Hidden, want)
	}
	if n := e.audit.count(core.ActAdminFileAccess); n != before+1 {
		t.Errorf("override audited %d times, want once", n-before)
	} else if a := e.audit.last(core.ActAdminFileAccess); a.TargetID != alice.rootID {
		t.Errorf("override audited on %s, want the space root", a.TargetID)
	}
	// Custom roles never get the override.
	if sg := list(helpdesk.Principal, userQ); sg.Hidden != 2 {
		t.Errorf("helpdesk with the override setting: %s (hidden %d)", grantRows(sg), sg.Hidden)
	}
	e.settings.set(settingAdminAccess, false)

	// Errors: malformed subject 422, unknown subject 404, token scope.
	for _, c := range []struct {
		q           core.SubjectGrantQuery
		code, field string
	}{
		{core.SubjectGrantQuery{SubjectType: "everyone", SubjectID: bob.UserID}, "invalid", "subject_type"},
		{core.SubjectGrantQuery{SubjectType: core.SubjectUser, SubjectID: viewers}, "invalid", "subject_id"},
		{core.SubjectGrantQuery{SubjectType: core.SubjectRole, SubjectID: "member"}, "invalid", "subject_id"},
		{core.SubjectGrantQuery{SubjectType: core.SubjectRole, SubjectID: ids.New(ids.PrefixRole)}, "not_found", ""},
		{core.SubjectGrantQuery{SubjectType: core.SubjectGroup, SubjectID: ids.New(ids.PrefixGroup)}, "not_found", ""},
		{core.SubjectGrantQuery{SubjectType: core.SubjectUser, SubjectID: ids.New(ids.PrefixUser)}, "not_found", ""},
	} {
		_, err := e.svc.SubjectGrants(e.ctx, sys, c.q)
		if ce := core.AsError(err); ce == nil || ce.Code != c.code || ce.Field != c.field {
			t.Errorf("%+v: %v", c.q, err)
		}
	}
	tok := admin.Clone()
	tok.Via, tok.Scopes = core.ViaToken, []string{core.ScopeAdmin}
	_, err := e.svc.SubjectGrants(e.ctx, tok, userQ)
	wantCode(t, err, "forbidden")
	tok.Scopes = append(tok.Scopes, core.ScopeFilesRead)
	if _, err := e.svc.SubjectGrants(e.ctx, tok, userQ); err != nil {
		t.Fatalf("token with files:read: %v", err)
	}
	if _, err := e.svc.SubjectGrants(e.ctx, nil, userQ); code(err) != "unauthorized" {
		t.Fatalf("nil principal: %v", err)
	}
}

// At most 1000 rows are returned; Hidden counts the rest.
func TestSubjectGrantsLimit(t *testing.T) {
	e := newEnv(t)
	alice := e.user("alice", core.RoleMember)
	bob := e.user("bob", core.RoleMember)
	const n = maxSubjectGrants + 2
	now := db.Ms(e.clock.Now())
	err := e.db.Tx(context.Background(), func(tx *sql.Tx) error {
		for i := range n {
			id, name := ids.New(ids.PrefixNode), fmt.Sprintf("f%04d", i)
			if _, err := tx.Exec(`INSERT INTO nodes (id, space_id, parent_id, kind, name, name_key, created_at, updated_at)
				VALUES (?, ?, ?, 'folder', ?, ?, ?, ?)`, id, alice.spaceID, alice.rootID, name, names.Key(name), now, now); err != nil {
				return err
			}
			if _, err := tx.Exec(`INSERT INTO node_grants (id, node_id, subject_type, subject_id, role, created_at)
				VALUES (?, ?, 'user', ?, 'viewer', ?)`, ids.New(ids.PrefixGrant), id, bob.UserID, now); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	sg, err := e.svc.SubjectGrants(e.ctx, alice.Principal, core.SubjectGrantQuery{SubjectType: core.SubjectUser,
		SubjectID: bob.UserID})
	if err != nil {
		t.Fatal(err)
	}
	if len(sg.Items) != maxSubjectGrants || sg.Hidden != 2 || sg.Items[0].NodePath != "/f0000" ||
		sg.Items[maxSubjectGrants-1].NodePath != fmt.Sprintf("/f%04d", maxSubjectGrants-1) {
		t.Fatalf("%d rows (first %s, last %s), hidden %d", len(sg.Items), sg.Items[0].NodePath,
			sg.Items[len(sg.Items)-1].NodePath, sg.Hidden)
	}
}
