package wire

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"regexp"
	"testing"

	"fileparcel/internal/core"
	"fileparcel/internal/web"
)

// send runs one request through router as the credential who (a guardEnv
// credential name), each from its own client address.
func (g *guardEnv) send(router http.Handler, who, method, path string, body any) *httptest.ResponseRecorder {
	g.t.Helper()
	var rd *bytes.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	} else {
		rd = bytes.NewReader(nil)
	}
	r := httptest.NewRequest(method, path, rd)
	if body != nil {
		r.Header.Set("Content-Type", "application/json")
	}
	g.calls++
	r.RemoteAddr = fmt.Sprintf("10.%d.%d.%d:40000", byte(g.calls>>16), byte(g.calls>>8), byte(g.calls))
	g.creds[who].apply(r)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, r)
	return rec
}

var bootJSON = regexp.MustCompile(`(?s)<script type="application/json" id="fp-boot">(.*?)</script>`)

// TestRolesAPIEndToEnd drives the roles API with the real services and
// router: an administrator who stepped up creates a role, puts it into a
// group and gives it to a member; an owner shares a folder with the role;
// the holder's /me, page boot, role directory, groups and shared items show
// it; the access preview and the grants listing show what the administrator
// may see; deleting the role needs reassign_to; and every change is in the
// audit log.
func TestRolesAPIEndToEnd(t *testing.T) {
	g := newGuardEnv(t)
	ctx := context.Background()
	router := web.NewRouter(g.d)
	call := func(who, method, path string, body, out any, want int) {
		t.Helper()
		rec := g.send(router, who, method, path, body)
		if rec.Code != want {
			t.Fatalf("%s %s as %s: %d %s, want %d", method, path, who, rec.Code, rec.Body, want)
		}
		if out != nil {
			if err := json.Unmarshal(rec.Body.Bytes(), out); err != nil {
				t.Fatalf("%s %s: %s: %v", method, path, rec.Body, err)
			}
		}
	}
	mel, err := g.d.Users.GetByUsername(ctx, "mel")
	if err != nil {
		t.Fatal(err)
	}

	// Roles CRUD needs a built-in administrator who stepped up.
	in := core.RoleDefInput{Name: "Finance", Description: "Money", Delegable: true}
	call("adam (not elevated)", "POST", "/api/v1/admin/roles", in, nil, http.StatusForbidden)
	call("pat", "POST", "/api/v1/admin/roles", in, nil, http.StatusForbidden) // every permission, still no roles CRUD
	var fin core.RoleDef
	call("adam", "POST", "/api/v1/admin/roles", in, &fin, http.StatusCreated)
	if fin.Base != core.RoleMember || fin.Permissions != core.MemberCaps || !fin.Delegable || fin.Staff {
		t.Fatalf("created %+v", fin)
	}
	call("adam admin token", "PATCH", "/api/v1/admin/roles/"+fin.ID, core.RoleDefUpdate{Description: ptr("Accounts")},
		&fin, http.StatusOK)
	var cat core.CapabilityCatalog
	call("mel", "GET", "/api/v1/admin/capabilities", nil, nil, http.StatusForbidden)
	call("adam admin token", "GET", "/api/v1/admin/capabilities", nil, &cat, http.StatusOK)
	if len(cat.Items) != len(core.Capabilities) {
		t.Fatalf("catalog %d items", len(cat.Items))
	}

	// The role joins a group, and mel gets the role (a role change: step-up).
	var grp core.Group
	call("adam", "POST", "/api/v1/admin/groups", core.GroupInput{Name: "Finance"}, &grp, http.StatusCreated)
	call("adam", "PUT", "/api/v1/admin/roles/"+fin.ID+"/groups/"+grp.ID, core.RoleGroupInput{}, nil, http.StatusOK)
	call("adam (not elevated)", "PATCH", "/api/v1/admin/users/"+mel.ID, core.UserUpdate{RoleID: &fin.ID}, nil, http.StatusForbidden)
	var u core.User
	call("adam", "PATCH", "/api/v1/admin/users/"+mel.ID, core.UserUpdate{RoleID: &fin.ID}, &u, http.StatusOK)
	if u.RoleID != fin.ID || u.RoleName != "Finance" || u.Role != core.RoleMember {
		t.Fatalf("assigned %+v", u)
	}

	// olive shares a folder of her own with the role.
	var spaces []core.Space
	call("olive", "GET", "/api/v1/spaces", nil, &spaces, http.StatusOK)
	var reports core.Node
	call("olive", "POST", "/api/v1/nodes/"+spaces[0].RootID+"/folders", core.NameInput{Name: "Reports"}, &reports, http.StatusCreated)
	call("olive", "POST", "/api/v1/nodes/"+reports.ID+"/grants", core.GrantInput{SubjectType: core.SubjectRole,
		SubjectID: fin.ID, Role: core.GrantEditor}, nil, http.StatusOK)

	// What mel sees.
	var me core.Me
	call("mel", "GET", "/api/v1/me", nil, &me, http.StatusOK)
	if me.User.RoleID != fin.ID || me.User.RoleName != "Finance" || me.Staff || !me.Features["directory"] {
		t.Fatalf("/me %+v staff %v %v", me.User, me.Staff, me.Features)
	}
	page := g.send(router, "mel", "GET", "/files", nil)
	m := bootJSON.FindSubmatch(page.Body.Bytes())
	if page.Code != 200 || m == nil {
		t.Fatalf("page: %d", page.Code)
	}
	var boot struct {
		User struct {
			RoleID   string `json:"role_id"`
			RoleName string `json:"role_name"`
		} `json:"user"`
		Features map[string]bool `json:"features"`
	}
	if err := json.Unmarshal(m[1], &boot); err != nil || boot.User.RoleID != fin.ID || boot.User.RoleName != "Finance" ||
		boot.Features["tokens"] != me.Features["tokens"] {
		t.Fatalf("boot %s: %v", m[1], err)
	}
	var roles core.Page[core.RoleRef]
	call("mel", "GET", "/api/v1/roles", nil, &roles, http.StatusOK)
	if len(roles.Items) != 2 || roles.Items[0].Name != "Finance" { // Finance, Probe
		t.Fatalf("/roles %+v", roles)
	}
	call("gus", "GET", "/api/v1/roles", nil, nil, http.StatusForbidden)
	var groups core.Page[core.Group]
	call("mel", "GET", "/api/v1/groups", nil, &groups, http.StatusOK)
	if len(groups.Items) != 1 || groups.Items[0].ID != grp.ID || groups.Items[0].Via != "role" {
		t.Fatalf("/groups %+v", groups)
	}
	var shared core.Page[core.Node]
	call("mel", "GET", "/api/v1/shared-with-me", nil, &shared, http.StatusOK)
	if len(shared.Items) != 1 || shared.Items[0].ID != reports.ID || shared.Items[0].Perm != core.PermEdit {
		t.Fatalf("shared with me %+v", shared)
	}

	// The access preview and the grants: adam may not open olive's folder
	// (no files override), so the grant is counted, not named; olive, who
	// holds users.view as an owner, sees it.
	var acc core.UserAccess
	call("adam", "GET", "/api/v1/admin/users/"+mel.ID+"/access", nil, &acc, http.StatusOK)
	if acc.Role.ID != fin.ID || len(acc.Groups) != 1 || acc.Groups[0].GroupID != grp.ID || acc.Groups[0].Direct ||
		len(acc.Grants) != 0 || acc.HiddenGrants != 1 || !acc.Manageable || acc.Staff || !acc.PersonalSpace {
		t.Fatalf("access %+v", acc)
	}
	var sg core.SubjectGrants
	call("olive", "GET", "/api/v1/admin/grants?subject_type=role&subject_id="+fin.ID, nil, &sg, http.StatusOK)
	if sg.Hidden != 0 || len(sg.Items) != 1 || sg.Items[0].NodePath != "/Reports" || sg.Items[0].CallerPerm != core.PermOwner {
		t.Fatalf("grants for olive %+v", sg)
	}
	call("olive", "GET", "/api/v1/admin/users/"+mel.ID+"/access", nil, &acc, http.StatusOK)
	if len(acc.Grants) != 1 || acc.Grants[0].SubjectID != fin.ID || acc.HiddenGrants != 0 {
		t.Fatalf("access for olive %+v", acc)
	}

	// Deleting the role: holders need a new role.
	call("adam", "DELETE", "/api/v1/admin/roles/"+fin.ID, nil, nil, http.StatusConflict)
	call("adam", "DELETE", "/api/v1/admin/roles/"+fin.ID+"?reassign_to=member", nil, nil, http.StatusNoContent)
	call("mel", "GET", "/api/v1/me", nil, &me, http.StatusOK)
	if me.User.RoleID != "member" {
		t.Fatalf("after delete %+v", me.User)
	}
	call("mel", "GET", "/api/v1/shared-with-me", nil, &shared, http.StatusOK)
	if len(shared.Items) != 0 {
		t.Fatalf("the role grant outlived the role: %+v", shared)
	}

	// The audit log has every change.
	for _, action := range []string{core.ActRoleCreate, core.ActRoleUpdate, core.ActGroupRoleSet, core.ActUserUpdate,
		core.ActGrantSet, core.ActRoleDelete} {
		pg, err := g.d.Audit.Query(ctx, core.AuditQuery{Action: action})
		if err != nil || len(pg.Items) == 0 {
			t.Errorf("no %s entry: %v", action, err)
		}
	}
}
