package filesapi

import (
	"encoding/json"
	"slices"
	"sort"
	"testing"

	"fileparcel/internal/core"
	"fileparcel/internal/db"
	"fileparcel/internal/ids"
)

// GET /admin/grants (DESIGN §9.4): the grants to one subject, for callers
// with users.view, filled in only where the caller may see the item; role
// grants and the manager level go through POST /nodes/{id}/grants.
func TestAdminGrantsRoute(t *testing.T) {
	e := newEnv(t)
	alice := e.user("alice", core.RoleMember)
	bob := e.user("bob", core.RoleMember)
	roleID := ids.New(ids.PrefixRole)
	now := db.Ms(e.clock.Now())
	if _, err := e.db.Exec(e.ctx, `INSERT INTO roles (id, name, base, permissions, created_at, updated_at)
		VALUES (?, 'Contractors', 'guest', '["shares.requests"]', ?, ?)`, roleID, now, now); err != nil {
		t.Fatal(err)
	}
	var briefs core.Node
	e.req(alice.Principal, "POST", "/api/v1/nodes/"+alice.rootID+"/folders", core.NameInput{Name: "Briefs"}).
		expect(t, 201).json(t, &briefs)
	var rg, bg core.Grant
	e.req(alice.Principal, "POST", "/api/v1/nodes/"+briefs.ID+"/grants", core.GrantInput{SubjectType: core.SubjectRole,
		SubjectID: roleID, Role: core.GrantViewer}).expect(t, 200).json(t, &rg)
	if rg.SubjectType != core.SubjectRole || rg.SubjectName != "Contractors" {
		t.Fatalf("role grant %+v", rg)
	}
	e.req(alice.Principal, "POST", "/api/v1/nodes/"+briefs.ID+"/grants", core.GrantInput{SubjectType: core.SubjectUser,
		SubjectID: bob.UserID, Role: core.GrantManager}).expect(t, 200).json(t, &bg)
	if bg.Role != core.GrantManager {
		t.Fatalf("manager grant %+v", bg)
	}

	// alice's role lets her view people: she sees the grants on her own folder.
	viewer := *alice.Principal
	viewer.RoleID, viewer.RoleName = "rol_01k5z8r3m9d4q7w2x6c1v0b5na", "Coordinators"
	viewer.SetCaps(core.MemberCaps.With(core.CapUsersView))
	r := e.req(&viewer, "GET", "/api/v1/admin/grants?subject_type=role&subject_id="+roleID, nil).expect(t, 200)
	var res core.SubjectGrants
	r.json(t, &res)
	if res.Hidden != 0 || len(res.Items) != 1 {
		t.Fatalf("role grants %+v", res)
	}
	g := res.Items[0]
	if g.ID != rg.ID || g.NodeName != "Briefs" || g.NodePath != "/Briefs" || g.NodeKind != core.KindFolder ||
		g.SpaceKind != core.SpaceUser || g.SpaceName != "alice" || g.CallerPerm != core.PermOwner {
		t.Fatalf("row %+v", g)
	}
	var raw struct {
		Items  []map[string]json.RawMessage
		Hidden *int
	}
	r.json(t, &raw)
	var rowKeys []string
	for k := range raw.Items[0] {
		rowKeys = append(rowKeys, k)
	}
	sort.Strings(rowKeys)
	for _, k := range []string{"caller_perm", "node_kind", "node_name", "node_path", "space_kind", "space_name",
		"subject_type", "subject_id", "subject_name", "role"} {
		if !slices.Contains(rowKeys, k) {
			t.Errorf("row lacks %q: %v", k, rowKeys)
		}
	}
	if raw.Hidden == nil {
		t.Error("hidden missing")
	}
	// expand: bob's own grant (manager) and the one to his group.
	groupID := ids.New(ids.PrefixGroup)
	if _, err := e.db.Exec(e.ctx, `INSERT INTO groups (id, name, created_at) VALUES (?, 'Readers', ?)`, groupID, now); err != nil {
		t.Fatal(err)
	}
	if _, err := e.db.Exec(e.ctx, `INSERT INTO group_members (group_id, user_id, role, added_at) VALUES (?, ?, 'member', ?)`,
		groupID, bob.UserID, now); err != nil {
		t.Fatal(err)
	}
	var gg core.Grant
	e.req(alice.Principal, "POST", "/api/v1/nodes/"+briefs.ID+"/grants", core.GrantInput{SubjectType: core.SubjectGroup,
		SubjectID: groupID, Role: core.GrantEditor}).expect(t, 200).json(t, &gg)
	e.req(&viewer, "GET", "/api/v1/admin/grants?subject_type=user&subject_id="+bob.UserID, nil).expect(t, 200).json(t, &res)
	if len(res.Items) != 1 || res.Items[0].ID != bg.ID || res.Items[0].Role != core.GrantManager {
		t.Fatalf("bob's own grants %+v", res)
	}
	e.req(&viewer, "GET", "/api/v1/admin/grants?subject_type=user&subject_id="+bob.UserID+"&expand=1", nil).
		expect(t, 200).json(t, &res)
	if len(res.Items) != 2 || !slices.ContainsFunc(res.Items, func(g core.Grant) bool { return g.ID == gg.ID }) {
		t.Fatalf("expanded %+v", res)
	}

	// An administrator without the files override may not see alice's
	// folder: the grant is only counted.
	admin := e.user("adam", core.RoleAdmin)
	e.req(admin.Principal, "GET", "/api/v1/admin/grants?subject_type=role&subject_id="+roleID, nil).expect(t, 200).json(t, &res)
	if len(res.Items) != 0 || res.Hidden != 1 {
		t.Fatalf("admin without the override %+v", res)
	}

	// The guard: users.view.
	e.req(bob.Principal, "GET", "/api/v1/admin/grants?subject_type=role&subject_id="+roleID, nil).expect(t, 403, "forbidden")
	// Malformed and unknown subjects.
	for q, want := range map[string]int{
		"subject_type=robot&subject_id=" + roleID:            422,
		"subject_type=role&subject_id=usr_x":                 422,
		"subject_id=" + roleID:                               422,
		"subject_type=role&subject_id=" + ids.New("rol"):     404,
		"subject_type=group&subject_id=" + ids.New("grp"):    404,
		"subject_type=user&subject_id=" + ids.New("usr"):     404,
		"subject_type=user&subject_id=" + alice.UserID:       200,
		"subject_type=role&subject_id=" + roleID + "&expand": 200,
	} {
		if r := e.req(&viewer, "GET", "/api/v1/admin/grants?"+q, nil); r.status != want {
			t.Errorf("%s: %d %s, want %d", q, r.status, r.code, want)
		}
	}
	// API tokens: server permissions need the admin scope (the route), and
	// the item names need files:read (the service).
	tok := viewer
	tok.Via, tok.Scopes = core.ViaToken, []string{core.ScopeFilesRead}
	e.req(&tok, "GET", "/api/v1/admin/grants?subject_type=role&subject_id="+roleID, nil).expect(t, 403, "forbidden")
	tok.Scopes = []string{core.ScopeAdmin}
	e.req(&tok, "GET", "/api/v1/admin/grants?subject_type=role&subject_id="+roleID, nil).expect(t, 403, "forbidden")
	tok.Scopes = []string{core.ScopeAdmin, core.ScopeFilesRead}
	e.req(&tok, "GET", "/api/v1/admin/grants?subject_type=role&subject_id="+roleID, nil).expect(t, 200).json(t, &res)
	if len(res.Items) != 1 {
		t.Fatalf("token with both scopes %+v", res)
	}
}
