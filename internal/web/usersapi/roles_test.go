package usersapi

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"reflect"
	"slices"
	"sort"
	"sync"
	"testing"
	"time"

	"fileparcel/internal/core"
	"fileparcel/internal/ids"
)

// fakeFiles answers SubjectGrants (the only Files method usersapi calls)
// with res or err, recording each query and caller.
type fakeFiles struct {
	core.Files
	mu      sync.Mutex
	queries []core.SubjectGrantQuery
	callers []*core.Principal
	res     core.SubjectGrants
	err     error
}

func (f *fakeFiles) SubjectGrants(_ context.Context, p *core.Principal, q core.SubjectGrantQuery) (*core.SubjectGrants, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.queries, f.callers = append(f.queries, q), append(f.callers, p)
	if f.err != nil {
		return nil, f.err
	}
	res := f.res
	res.Items = slices.Clone(f.res.Items)
	return &res, nil
}

// jsonDo sends a request as p and returns the status and the raw body.
func (te *testEnv) jsonDo(t *testing.T, p *core.Principal, method, path string, body any) (int, []byte) {
	t.Helper()
	te.who.Store(p)
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	req, _ := http.NewRequest(method, te.srv.URL+path, rd)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, raw
}

// keys returns the sorted top-level keys of a JSON object.
func keys(t *testing.T, raw []byte) []string {
	t.Helper()
	var m map[string]json.RawMessage
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatalf("decode %s: %v", raw, err)
	}
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// wantError fails unless the request as p answers status with the error
// field (and message, when not "").
func (te *testEnv) wantError(t *testing.T, p *core.Principal, method, path string, body any, status int, field, msg string) {
	t.Helper()
	te.who.Store(p)
	st, er := rawDo(t, te, method, path, body)
	if st != status || er.Error.Field != field || (msg != "" && er.Error.Message != msg) {
		t.Errorf("%s %s %+v: %d %+v, want %d field %q %q", method, path, body, st, er.Error, status, field, msg)
	}
}

// The roles routes (DESIGN §9.4) as an administrator who stepped up: the
// catalog, the role list and the CRUD answers, role → group memberships and
// deleting with reassign_to, with the JSON shapes of the API contract.
func TestRoleRoutes(t *testing.T) {
	te := newTestEnv(t)
	ctx := context.Background()
	sys := core.SystemPrincipal(core.ViaSocket)
	el := te.principal(te.admin, true)
	as := te.as(el)

	var cat core.CapabilityCatalog
	if st, code := as.do(t, "GET", "/api/v1/admin/capabilities", nil, &cat); st != 200 || !reflect.DeepEqual(cat, core.Catalog()) {
		t.Fatalf("capabilities: %d %s %+v", st, code, cat)
	}

	// Create: the example of the API contract.
	st, raw := te.jsonDo(t, el, "POST", "/api/v1/admin/roles", map[string]any{"name": "Helpdesk",
		"description": "Front-line support", "base": "member", "copy_from": "member",
		"permissions": []string{"shares.links", "users.lookup", "tokens.create", "users.manage", "users.credentials"},
		"delegable":   false})
	if st != http.StatusCreated {
		t.Fatalf("create: %d %s", st, raw)
	}
	var hd core.RoleDef
	if err := json.Unmarshal(raw, &hd); err != nil {
		t.Fatal(err)
	}
	wantKeys := []string{"assignable", "base", "builtin", "created_at", "created_by", "delegable", "description",
		"editable", "grant_count", "group_count", "id", "name", "permissions", "staff", "updated_at", "updated_by",
		"user_count"}
	if got := keys(t, raw); !slices.Equal(got, wantKeys) {
		t.Errorf("RoleDef keys %v, want %v", got, wantKeys)
	}
	wantPerms := []core.Capability{core.CapShareLinks, core.CapUsersLookup, core.CapTokensCreate, core.CapUsersView,
		core.CapUsersManage, core.CapUsersCredentials}
	if !core.IsCustomRoleID(hd.ID) || hd.Name != "Helpdesk" || hd.Description != "Front-line support" || hd.Builtin ||
		hd.Base != core.RoleMember || !slices.Equal(hd.Permissions.List(), wantPerms) || hd.Delegable || !hd.Staff ||
		hd.UserCount != 0 || !hd.Editable || !hd.Assignable || hd.CreatedBy != te.admin.ID || hd.CreatedAt == nil {
		t.Fatalf("created %+v", hd)
	}

	// Read: the list (built-ins first), one role, a built-in word.
	var list core.Page[core.RoleDef]
	if st, _ := as.do(t, "GET", "/api/v1/admin/roles", nil, &list); st != 200 || len(list.Items) != 5 {
		t.Fatalf("list: %d %+v", st, list)
	}
	var order []string
	for _, r := range list.Items {
		order = append(order, r.ID)
	}
	if !slices.Equal(order, []string{"owner", "admin", "member", "guest", hd.ID}) {
		t.Fatalf("order %v", order)
	}
	if o, a := list.Items[0], list.Items[1]; o.Assignable || !a.Assignable || o.Editable || a.Editable || o.UserCount != 2 {
		t.Fatalf("built-ins for an admin: %+v %+v", o, a)
	}
	var got core.RoleDef
	if st, _ := as.do(t, "GET", "/api/v1/admin/roles/"+hd.ID, nil, &got); st != 200 || !reflect.DeepEqual(got, hd) {
		t.Fatalf("get: %d\n got %+v\nwant %+v", st, got, hd)
	}
	if st, _ := as.do(t, "GET", "/api/v1/admin/roles/member", nil, &got); st != 200 || !got.Builtin ||
		got.Permissions != core.MemberCaps || got.Name != "Member" || got.UserCount != 1 {
		t.Fatalf("member: %d %+v", st, got)
	}
	if st, code := as.do(t, "GET", "/api/v1/admin/roles/"+ids.New(ids.PrefixRole), nil, nil); st != 404 || code != "not_found" {
		t.Fatalf("missing role: %d %s", st, code)
	}

	// Refused creations.
	for _, c := range []struct {
		body       any
		status     int
		field, msg string
	}{
		{map[string]any{"name": "helpdesk"}, 409, "name", "a role with this name already exists"},
		{map[string]any{"name": "Admin"}, 422, "name", "“Admin” is a reserved role name"},
		{map[string]any{"name": "X", "permissions": []string{"nope"}}, 422, "permissions", `unknown permission "nope"`},
		{map[string]any{"name": "X", "base": "admin"}, 422, "base", "custom roles are based on member or guest"},
		{map[string]any{"name": "X", "copy_from": ids.New(ids.PrefixRole)}, 422, "copy_from", "unknown role"},
		{map[string]any{"name": "X", "quota": 5}, 422, "quota", "unknown field"},
	} {
		te.wantError(t, el, "POST", "/api/v1/admin/roles", c.body, c.status, c.field, c.msg)
	}

	// Update: additions, the two permission forms, built-ins, names.
	if st, code := as.do(t, "PATCH", "/api/v1/admin/roles/"+hd.ID,
		core.RoleDefUpdate{AddPermissions: []core.Capability{core.CapAuditView}}, &got); st != 200 ||
		!got.Permissions.Has(core.CapAuditView) || !got.Permissions.Has(core.CapUsersManage) {
		t.Fatalf("add permission: %d %s %+v", st, code, got)
	}
	if _, err := te.d.Users.CreateRole(ctx, sys, core.RoleDefInput{Name: "Finance"}); err != nil {
		t.Fatal(err)
	}
	te.wantError(t, el, "PATCH", "/api/v1/admin/roles/"+hd.ID, map[string]any{"permissions": []string{},
		"remove_permissions": []string{"audit.view"}}, 422, "permissions", "")
	te.wantError(t, el, "PATCH", "/api/v1/admin/roles/member", map[string]any{"name": "Members"}, 422, "id",
		"built-in roles cannot be changed; duplicate one instead")
	te.wantError(t, el, "PATCH", "/api/v1/admin/roles/"+hd.ID, map[string]any{"name": "FINANCE"}, 409, "name", "")

	// Role → group memberships.
	g, err := te.d.Users.CreateGroup(ctx, sys, core.GroupInput{Name: "Desk"})
	if err != nil {
		t.Fatal(err)
	}
	base := "/api/v1/admin/roles/" + hd.ID + "/groups"
	st, raw = te.jsonDo(t, el, "PUT", base+"/"+g.ID, core.RoleGroupInput{MemberRole: core.GroupRoleManager})
	var rg core.RoleGroup
	if st != 200 || json.Unmarshal(raw, &rg) != nil || rg.RoleID != hd.ID || rg.RoleName != "Helpdesk" ||
		rg.GroupID != g.ID || rg.GroupName != "Desk" || rg.SpaceID == "" || rg.MemberRole != core.GroupRoleManager ||
		rg.AddedBy != te.admin.ID || rg.AddedAt.IsZero() {
		t.Fatalf("set role group: %d %s", st, raw)
	}
	if got := keys(t, raw); !slices.Equal(got, []string{"added_at", "added_by", "group_id", "group_name", "member_role",
		"role_id", "role_name", "space_id"}) {
		t.Errorf("RoleGroup keys %v", got)
	}
	te.wantError(t, el, "PUT", base+"/"+g.ID, map[string]any{"member_role": "owner"}, 422, "member_role", "")
	te.wantError(t, el, "PUT", "/api/v1/admin/roles/member/groups/"+g.ID, map[string]any{}, 422, "role_id",
		"only custom roles can be members of groups")
	if st, code := as.do(t, "PUT", base+"/"+ids.New(ids.PrefixGroup), map[string]any{}, nil); st != 404 {
		t.Fatalf("unknown group: %d %s", st, code)
	}
	var groups core.Page[core.RoleGroup]
	if st, _ := as.do(t, "GET", base, nil, &groups); st != 200 || len(groups.Items) != 1 || groups.Items[0] != rg {
		t.Fatalf("role groups: %d %+v", st, groups)
	}
	if st, _ := as.do(t, "DELETE", base+"/"+g.ID, nil, nil); st != 204 {
		t.Fatalf("remove role group: %d", st)
	}
	if st, _ := as.do(t, "DELETE", base+"/"+g.ID, nil, nil); st != 404 {
		t.Fatalf("remove again: %d", st)
	}
	st, raw = te.jsonDo(t, el, "GET", "/api/v1/admin/roles/member/groups", nil)
	if st != 200 || string(raw) != `{"items":[]}`+"\n" {
		t.Fatalf("built-in role groups: %d %q", st, raw)
	}

	// Delete: holders need reassign_to.
	if _, err := te.d.Users.Update(ctx, sys, te.member.ID, core.UserUpdate{RoleID: &hd.ID}); err != nil {
		t.Fatal(err)
	}
	te.wantError(t, el, "DELETE", "/api/v1/admin/roles/"+hd.ID, nil, 409, "reassign_to",
		"1 account has this role: choose a role to move it to")
	te.wantError(t, el, "DELETE", "/api/v1/admin/roles/"+hd.ID+"?reassign_to=owner", nil, 422, "reassign_to", "")
	te.wantError(t, el, "DELETE", "/api/v1/admin/roles/guest", nil, 422, "id", "built-in roles cannot be deleted")
	if st, code := as.do(t, "DELETE", "/api/v1/admin/roles/"+hd.ID+"?reassign_to=member", nil, nil); st != 204 {
		t.Fatalf("delete: %d %s", st, code)
	}
	if st, _ := as.do(t, "GET", "/api/v1/admin/roles/"+hd.ID, nil, nil); st != 404 {
		t.Fatalf("deleted role still there: %d", st)
	}
	if u, err := te.d.Users.Get(ctx, te.member.ID); err != nil || u.RoleID != "member" {
		t.Fatalf("holder after delete: %+v %v", u, err)
	}
}

// Creating, editing and deleting roles is for built-in owners and admins
// with step-up; reading them needs users.view and role → group memberships
// groups.manage, which delegates may hold.
func TestRoleRoutesGuards(t *testing.T) {
	te := newTestEnv(t)
	ctx := context.Background()
	sys := core.SystemPrincipal(core.ViaSocket)
	hd, err := te.d.Users.CreateRole(ctx, sys, core.RoleDefInput{Name: "Helpdesk"})
	if err != nil {
		t.Fatal(err)
	}
	g, err := te.d.Users.CreateGroup(ctx, sys, core.GroupInput{Name: "Desk"})
	if err != nil {
		t.Fatal(err)
	}
	writes := []struct {
		method, path string
		body         any
	}{
		{"POST", "/api/v1/admin/roles", core.RoleDefInput{Name: "New"}},
		{"PATCH", "/api/v1/admin/roles/" + hd.ID, core.RoleDefUpdate{Description: ptr("x")}},
		{"DELETE", "/api/v1/admin/roles/" + ids.New(ids.PrefixRole), nil},
	}
	adm := te.principal(te.admin, false)
	for _, c := range writes {
		if st, code := te.as(adm).do(t, c.method, c.path, c.body, nil); st != 403 || code != "elevation_required" {
			t.Errorf("unelevated %s %s: %d %s", c.method, c.path, st, code)
		}
	}
	if st, _ := te.as(adm).do(t, "GET", "/api/v1/admin/roles", nil, nil); st != 200 {
		t.Fatalf("unelevated read: %d", st)
	}
	// An owner who stepped up may, like an admin.
	if st, code := te.as(te.principal(te.owner, true)).do(t, "POST", "/api/v1/admin/roles", core.RoleDefInput{Name: "Owners pick"}, nil); st != 201 {
		t.Fatalf("owner create: %d %s", st, code)
	}

	// A delegate holding every permission still cannot manage roles.
	all := te.delegate(te.holder(t, "allie", te.addRole(t, "Everything", core.AllCaps, false)))
	for _, c := range writes {
		if st, code := te.as(all).do(t, c.method, c.path, c.body, nil); st != 403 || code != "forbidden" {
			t.Errorf("delegate %s %s: %d %s", c.method, c.path, st, code)
		}
	}
	var list core.Page[core.RoleDef]
	if st, _ := te.as(all).do(t, "GET", "/api/v1/admin/roles", nil, &list); st != 200 {
		t.Fatalf("delegate list: %d", st)
	}
	for _, r := range list.Items {
		want := r.ID == "member" || r.ID == "guest" // Helpdesk is not delegable
		if r.Editable || r.Assignable != want {
			t.Errorf("delegate sees %s editable %v assignable %v", r.ID, r.Editable, r.Assignable)
		}
	}
	// groups.manage is enough for role → group memberships.
	gm := te.delegate(te.holder(t, "gina", te.addRole(t, "Group managers", core.MemberCaps.With(core.CapGroupsManage), false)))
	path := "/api/v1/admin/roles/" + hd.ID + "/groups/" + g.ID
	if st, code := te.as(gm).do(t, "PUT", path, core.RoleGroupInput{}, nil); st != 200 {
		t.Fatalf("groups.manage PUT: %d %s", st, code)
	}
	if st, _ := te.as(gm).do(t, "GET", "/api/v1/admin/roles/"+hd.ID+"/groups", nil, nil); st != 200 {
		t.Fatalf("groups.manage reads (users.view is implied): %d", st)
	}
	viewer := te.delegate(te.holder(t, "vera", te.addRole(t, "Viewers", core.MemberCaps.With(core.CapUsersView), false)))
	te.wantError(t, viewer, "DELETE", path, nil, 403, "", "this needs the “Manage groups” permission")
	if st, _ := te.as(viewer).do(t, "GET", "/api/v1/admin/capabilities", nil, nil); st != 200 {
		t.Fatalf("users.view reads the catalog: %d", st)
	}
	if st, _ := te.as(gm).do(t, "DELETE", path, nil, nil); st != 204 {
		t.Fatalf("groups.manage DELETE: %d", st)
	}
}

// GET /roles lists the custom roles (id, name, description) for the share
// and grant pickers, to callers who may search the directory.
func TestLookupRoles(t *testing.T) {
	te := newTestEnv(t)
	ctx := context.Background()
	sys := core.SystemPrincipal(core.ViaSocket)
	for _, in := range []core.RoleDefInput{
		{Name: "helpdesk", Description: "Support", Permissions: &[]core.Capability{core.CapUsersManage}},
		{Name: "Contractors", Base: core.RoleGuest, Permissions: &[]core.Capability{core.CapUsersLookup}},
	} {
		if _, err := te.d.Users.CreateRole(ctx, sys, in); err != nil {
			t.Fatal(err)
		}
	}
	st, raw := te.jsonDo(t, te.principal(te.member, false), "GET", "/api/v1/roles", nil)
	var page core.Page[core.RoleRef]
	if st != 200 || json.Unmarshal(raw, &page) != nil || len(page.Items) != 2 || page.Items[0].Name != "Contractors" ||
		page.Items[1].Name != "helpdesk" || page.Items[1].Description != "Support" {
		t.Fatalf("member: %d %s", st, raw)
	}
	var generic struct{ Items []map[string]any }
	if err := json.Unmarshal(raw, &generic); err != nil {
		t.Fatal(err)
	}
	for _, it := range generic.Items {
		for k := range it {
			if k != "id" && k != "name" && k != "description" {
				t.Errorf("GET /roles shows %q: %v", k, it)
			}
		}
	}
	te.wantError(t, te.principal(te.guest, false), "GET", "/api/v1/roles", nil, 403, "",
		"your role cannot search the user directory")
	contractors, err := te.d.Users.Create(ctx, sys, core.NewUser{Username: "cora", RoleID: page.Items[0].ID})
	if err != nil || contractors.Role != core.RoleGuest {
		t.Fatalf("contractor: %+v %v", contractors, err)
	}
	if st, code := te.as(te.delegate(contractors)).do(t, "GET", "/api/v1/roles", nil, nil); st != 200 {
		t.Fatalf("guest-based role with users.lookup: %d %s", st, code)
	}
	tok := te.principal(te.member, false)
	tok.Via, tok.Scopes = core.ViaToken, []string{core.ScopeFilesRead}
	if st, code := te.as(tok).do(t, "GET", "/api/v1/roles", nil, nil); st != 200 {
		t.Fatalf("member token (users.lookup is no server permission): %d %s", st, code)
	}
}

// GET /admin/users/{id}/access assembles the effective-access preview: the
// role, the permissions, the group memberships with their sources, the
// grants (from the files service, which filters them for the caller), the
// admin tokens for callers who could revoke them, and whether the caller may
// manage the account.
func TestUserAccessRoute(t *testing.T) {
	te := newTestEnv(t)
	ctx := context.Background()
	sys := core.SystemPrincipal(core.ViaSocket)
	files := &fakeFiles{res: core.SubjectGrants{Items: []core.Grant{{ID: "grt_1", NodeID: "nod_1", SubjectType: core.SubjectRole,
		Role: core.GrantManager, NodeName: "Briefs", NodePath: "/Briefs", CallerPerm: core.PermManage}}, Hidden: 2}}
	te.d.Files = files
	hd, err := te.d.Users.CreateRole(ctx, sys, core.RoleDefInput{Name: "Helpdesk",
		Permissions: &[]core.Capability{core.CapUsersManage, core.CapUsersCredentials}})
	if err != nil {
		t.Fatal(err)
	}
	hana := te.holder(t, "hana", hd.ID)
	desk, err := te.d.Users.CreateGroup(ctx, sys, core.GroupInput{Name: "Desk"})
	if err != nil {
		t.Fatal(err)
	}
	support, err := te.d.Users.CreateGroup(ctx, sys, core.GroupInput{Name: "Support"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := te.d.Users.SetRoleGroup(ctx, sys, hd.ID, desk.ID, core.GroupRoleManager); err != nil {
		t.Fatal(err)
	}
	if err := te.d.Users.SetMember(ctx, sys, support.ID, hana.ID, core.GroupRoleMember); err != nil {
		t.Fatal(err)
	}
	past, future := te.now.Add(-time.Hour), te.now.Add(time.Hour)
	te.auth.tokens = map[string][]core.APIToken{hana.ID: {
		{ID: "tok_live", Scopes: []string{core.ScopeAdmin}, ExpiresAt: &future},
		{ID: "tok_forever", Scopes: []string{core.ScopeFilesRead, core.ScopeAdmin}},
		{ID: "tok_revoked", Scopes: []string{core.ScopeAdmin}, RevokedAt: &past},
		{ID: "tok_expired", Scopes: []string{core.ScopeAdmin}, ExpiresAt: &past},
		{ID: "tok_files", Scopes: []string{core.ScopeFilesRead}},
	}}

	adm := te.principal(te.admin, false)
	st, raw := te.jsonDo(t, adm, "GET", "/api/v1/admin/users/"+hana.ID+"/access", nil)
	if st != 200 {
		t.Fatalf("access: %d %s", st, raw)
	}
	if got, want := keys(t, raw), []string{"admin_tokens", "files_override", "grants", "groups", "hidden_grants",
		"manageable", "permissions", "personal_space", "role", "staff", "user"}; !slices.Equal(got, want) {
		t.Errorf("UserAccess keys %v, want %v", got, want)
	}
	var acc core.UserAccess
	if err := json.Unmarshal(raw, &acc); err != nil {
		t.Fatal(err)
	}
	if acc.User.ID != hana.ID || acc.User.Username != "hana" || acc.User.DisplayName != hana.DisplayName || acc.Role.ID != hd.ID || acc.Role.Name != "Helpdesk" ||
		!acc.Role.Editable || acc.Permissions != hana.Permissions || !acc.Staff || acc.FilesOverride ||
		!acc.PersonalSpace || acc.AdminTokens != 2 || !acc.Manageable || acc.HiddenGrants != 2 ||
		len(acc.Grants) != 1 || acc.Grants[0].NodeName != "Briefs" {
		t.Fatalf("access %+v", acc)
	}
	if len(acc.Groups) != 2 || acc.Groups[0].Name != "Desk" || acc.Groups[0].Role != core.GroupRoleManager ||
		acc.Groups[0].Direct || len(acc.Groups[0].ViaRoles) != 1 || acc.Groups[0].ViaRoles[0].ID != hd.ID ||
		acc.Groups[1].Name != "Support" || !acc.Groups[1].Direct || acc.Groups[1].DirectRole != core.GroupRoleMember {
		t.Fatalf("groups %+v", acc.Groups)
	}
	if q := files.queries[0]; q != (core.SubjectGrantQuery{SubjectType: core.SubjectUser, SubjectID: hana.ID, Expand: true}) ||
		files.callers[0].UserID != te.admin.ID {
		t.Fatalf("files asked %+v by %+v", q, files.callers[0])
	}

	// A users.view delegate: no token count (no users.credentials, and
	// ListTokens is not even asked), and hana is not theirs to manage.
	viewer := te.delegate(te.holder(t, "vera", te.addRole(t, "Viewers", core.MemberCaps.With(core.CapUsersView), false)))
	te.auth.calls = nil
	if st, _ := te.as(viewer).do(t, "GET", "/api/v1/admin/users/"+hana.ID+"/access", nil, &acc); st != 200 ||
		acc.AdminTokens != 0 || acc.Manageable || acc.Role.Editable || files.callers[1].UserID != viewer.UserID {
		t.Fatalf("viewer: %d %+v", st, acc)
	}
	if te.auth.called("ListTokens:" + hana.ID) {
		t.Fatal("tokens listed for a caller without users.credentials")
	}
	// A Helpdesk delegate manages plain members, not the holders of a role
	// that is not delegable.
	desker := te.delegate(te.holder(t, "dora", te.addRole(t, "Desk", core.MemberCaps.With(core.CapUsersManage,
		core.CapUsersCredentials), false)))
	for u, want := range map[*core.User]bool{te.member: true, hana: false, te.admin: false} {
		if st, _ := te.as(desker).do(t, "GET", "/api/v1/admin/users/"+u.ID+"/access", nil, &acc); st != 200 || acc.Manageable != want {
			t.Errorf("manageable %s by a delegate: %d %v", u.Username, st, acc.Manageable)
		}
	}
	// The files override is for built-in owners and admins, while the setting is on.
	te.d.Env.Settings = fakeSettings{bools: map[string]bool{settingAdminFiles: true}}
	for u, want := range map[*core.User]bool{te.admin: true, te.owner: true, te.member: false, hana: false} {
		if st, _ := te.as(adm).do(t, "GET", "/api/v1/admin/users/"+u.ID+"/access", nil, &acc); st != 200 || acc.FilesOverride != want {
			t.Errorf("files_override of %s: %d %v", u.Username, st, acc.FilesOverride)
		}
	}
	if st, _ := te.as(adm).do(t, "GET", "/api/v1/admin/users/"+te.guest.ID+"/access", nil, &acc); st != 200 ||
		acc.PersonalSpace || acc.Staff || acc.Role.ID != "guest" || len(acc.Groups) != 0 || acc.Groups == nil {
		t.Fatalf("guest: %d %+v", st, acc)
	}
	// The files service's refusal (e.g. an API token without files:read) is the answer.
	files.err = core.Errorf(core.ErrForbidden, `token lacks scope "files:read"`)
	te.wantError(t, adm, "GET", "/api/v1/admin/users/"+hana.ID+"/access", nil, 403, "", `token lacks scope "files:read"`)
	te.d.Files = nil
	if st, code := te.as(adm).do(t, "GET", "/api/v1/admin/users/"+hana.ID+"/access", nil, nil); st != 503 || code != "unavailable" {
		t.Fatalf("no files service: %d %s", st, code)
	}
}

// GET /admin/invites through the API: a delegate with invites.manage sees
// the links of the invitations it could have created — its own and those for
// Member — but not the link of an admin invitation or of a role it may not
// give, even after stepping up (DESIGN §6a).
func TestInviteLinksForDelegates(t *testing.T) {
	te := newTestEnv(t)
	ctx := context.Background()
	sys := core.SystemPrincipal(core.ViaSocket)
	finance, err := te.d.Users.CreateRole(ctx, sys, core.RoleDefInput{Name: "Finance"})
	if err != nil {
		t.Fatal(err)
	}
	el := te.as(te.principal(te.admin, true))
	created := map[string]core.InviteCreated{}
	for name, in := range map[string]core.InviteInput{
		"admin": {Role: core.RoleAdmin}, "member": {Role: core.RoleMember}, "finance": {RoleID: finance.ID},
	} {
		var c core.InviteCreated
		if st, code := el.do(t, "POST", "/api/v1/admin/invites", in, &c); st != 201 {
			t.Fatalf("%s invite: %d %s", name, st, code)
		}
		created[name] = c
	}
	rec := te.addRole(t, "Recruiters", core.MemberCaps.With(core.CapInvitesManage), false)
	for _, elevated := range []bool{false, true} {
		p := te.delegate(te.holder(t, "rita"+map[bool]string{false: "1", true: "2"}[elevated], rec))
		if !elevated {
			p.ElevatedUntil = time.Time{}
		}
		var own core.InviteCreated
		if st, code := te.as(p).do(t, "POST", "/api/v1/admin/invites", core.InviteInput{}, &own); st != 201 || own.URL == "" {
			t.Fatalf("delegate invite: %d %s", st, code)
		}
		st, raw := te.jsonDo(t, p, "GET", "/api/v1/admin/invites", nil)
		var page core.Page[core.Invite]
		if st != 200 || json.Unmarshal(raw, &page) != nil {
			t.Fatalf("list: %d %s", st, raw)
		}
		shown := map[string]bool{}
		for _, inv := range page.Items {
			shown[inv.ID] = inv.URL != ""
		}
		want := map[string]bool{created["admin"].Invite.ID: false, created["finance"].Invite.ID: false,
			created["member"].Invite.ID: true, own.Invite.ID: true}
		for id, w := range want {
			if s, ok := shown[id]; !ok || s != w {
				t.Errorf("elevated %v: invite %s link shown %v (listed %v), want %v", elevated, id, s, ok, w)
			}
		}
		if bytes.Contains(raw, []byte(created["admin"].URL)) {
			t.Fatalf("the admin invitation link leaks: %s", raw)
		}
	}
}
