package cli

// Tests of "fileparcel role" and the role pieces of user, invite, group and
// access against fake routes built from the contract goldens
// (internal/core/testdata/contract).

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/spf13/cobra"

	"fileparcel/internal/core"
	"fileparcel/internal/ids"
)

// golden decodes a contract golden (the JSON the server sends).
func golden[T any](t *testing.T, name string) T {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "core", "testdata", "contract", name))
	if err != nil {
		t.Fatal(err)
	}
	var v T
	if err := json.Unmarshal(data, &v); err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	return v
}

// fakeRoles is the role store of addRoleRoutes.
type fakeRoles struct {
	mu     sync.Mutex
	roles  []core.RoleDef
	groups map[string][]core.RoleGroup // role id → its groups
	grants map[string][]core.Grant     // role id → grants to it
}

func (s *fakeRoles) find(id string) *core.RoleDef {
	for i := range s.roles {
		if s.roles[i].ID == id {
			return &s.roles[i]
		}
	}
	return nil
}

// addRoleRoutes serves the roles API of plan §9.1: the built-in roles and
// the Helpdesk role of role_def.json (3 people), GET /admin/capabilities
// (the compiled catalog), GET /admin/grants and GET /roles.
func addRoleRoutes(f *fakeAPI) *fakeRoles {
	st := &fakeRoles{groups: map[string][]core.RoleGroup{}, grants: map[string][]core.Grant{}}
	st.roles = core.BuiltinRoles(false)
	st.roles[2].UserCount = 5
	st.roles = append(st.roles, golden[core.RoleDef](f.t, "role_def.json"))
	f.handle("GET", "/api/v1/admin/roles", func(w http.ResponseWriter, r *http.Request) {
		st.mu.Lock()
		defer st.mu.Unlock()
		writeJSON(w, 200, core.Page[core.RoleDef]{Items: st.roles})
	})
	f.handle("GET", "/api/v1/admin/roles/{id}", func(w http.ResponseWriter, r *http.Request) {
		st.mu.Lock()
		defer st.mu.Unlock()
		if rd := st.find(chi.URLParam(r, "id")); rd != nil {
			writeJSON(w, 200, rd)
			return
		}
		writeErr(w, core.NotFoundf("role not found"))
	})
	f.handle("GET", "/api/v1/admin/capabilities", func(w http.ResponseWriter, r *http.Request) { writeJSON(w, 200, core.Catalog()) })
	f.handle("POST", "/api/v1/admin/roles", func(w http.ResponseWriter, r *http.Request) {
		in, _ := decodeBody[core.RoleDefInput](r)
		st.mu.Lock()
		defer st.mu.Unlock()
		for _, rd := range st.roles {
			if strings.EqualFold(rd.Name, in.Name) {
				writeErr(w, core.Errorf(core.ErrConflict, "a role named %q exists", in.Name))
				return
			}
		}
		rd := core.RoleDef{ID: ids.New(ids.PrefixRole), Name: in.Name, Description: in.Description, Base: in.Base,
			Delegable: in.Delegable}
		if rd.Base == "" {
			rd.Base = core.RoleMember
		}
		if src := st.find(in.CopyFrom); src != nil {
			rd.Permissions = src.Permissions
		}
		if in.Permissions != nil {
			rd.Permissions = core.NewCapSet(*in.Permissions...).Closure() // the server adds what a permission needs
		}
		st.roles = append(st.roles, rd)
		writeJSON(w, 201, rd)
	})
	f.handle("PATCH", "/api/v1/admin/roles/{id}", func(w http.ResponseWriter, r *http.Request) {
		in, _ := decodeBody[core.RoleDefUpdate](r)
		st.mu.Lock()
		defer st.mu.Unlock()
		rd := st.find(chi.URLParam(r, "id"))
		switch {
		case rd == nil:
			writeErr(w, core.NotFoundf("role not found"))
			return
		case rd.Builtin:
			writeErr(w, core.Invalid("id", "built-in roles cannot be changed"))
			return
		}
		if in.Name != nil {
			rd.Name = *in.Name
		}
		if in.Description != nil {
			rd.Description = *in.Description
		}
		if in.Delegable != nil {
			rd.Delegable = *in.Delegable
		}
		if in.Permissions != nil {
			rd.Permissions = core.NewCapSet(*in.Permissions...)
		}
		rd.Permissions = rd.Permissions.With(in.AddPermissions...).Without(in.RemovePermissions...).Closure()
		writeJSON(w, 200, rd)
	})
	f.handle("DELETE", "/api/v1/admin/roles/{id}", func(w http.ResponseWriter, r *http.Request) {
		st.mu.Lock()
		defer st.mu.Unlock()
		id := chi.URLParam(r, "id")
		rd := st.find(id)
		switch {
		case rd == nil:
			writeErr(w, core.NotFoundf("role not found"))
		case rd.UserCount > 0 && r.URL.Query().Get("reassign_to") == "":
			writeErr(w, core.Errorf(core.ErrConflict, "the role has people; choose reassign_to"))
		default:
			st.roles = slices.DeleteFunc(st.roles, func(x core.RoleDef) bool { return x.ID == id })
			w.WriteHeader(http.StatusNoContent)
		}
	})
	f.handle("GET", "/api/v1/admin/roles/{id}/groups", func(w http.ResponseWriter, r *http.Request) {
		st.mu.Lock()
		defer st.mu.Unlock()
		writeJSON(w, 200, core.Page[core.RoleGroup]{Items: st.groups[chi.URLParam(r, "id")]})
	})
	f.handle("PUT", "/api/v1/admin/roles/{id}/groups/{gid}", func(w http.ResponseWriter, r *http.Request) {
		in, _ := decodeBody[core.RoleGroupInput](r)
		st.mu.Lock()
		defer st.mu.Unlock()
		id := chi.URLParam(r, "id")
		if core.Role(id).Valid() {
			writeErr(w, core.Invalid("role_id", "built-in roles cannot make people members of groups"))
			return
		}
		rg := core.RoleGroup{RoleID: id, RoleName: st.find(id).Name, GroupID: chi.URLParam(r, "gid"), GroupName: "Design",
			MemberRole: in.MemberRole, AddedAt: time.Now().UTC()}
		st.groups[id] = append(st.groups[id], rg)
		writeJSON(w, 200, rg)
	})
	f.handle("DELETE", "/api/v1/admin/roles/{id}/groups/{gid}", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})
	f.handle("GET", "/api/v1/admin/grants", func(w http.ResponseWriter, r *http.Request) {
		st.mu.Lock()
		defer st.mu.Unlock()
		items := st.grants[r.URL.Query().Get("subject_id")]
		if items == nil {
			items = []core.Grant{}
		}
		writeJSON(w, 200, core.SubjectGrants{Items: items, Hidden: 1})
	})
	f.handle("GET", "/api/v1/roles", func(w http.ResponseWriter, r *http.Request) {
		st.mu.Lock()
		defer st.mu.Unlock()
		refs := []core.RoleRef{}
		for _, rd := range st.roles {
			if !rd.Builtin {
				refs = append(refs, core.RoleRef{ID: rd.ID, Name: rd.Name, Description: rd.Description})
			}
		}
		writeJSON(w, 200, core.Page[core.RoleRef]{Items: refs})
	})
	return st
}

// helpdeskID is the id of the Helpdesk role of role_def.json.
const helpdeskID = "rol_01k5z8r3m9d4q7w2x6c1v0b5na"

func TestRoleListShowPermissions(t *testing.T) {
	f := newFakeAPI(t)
	st := addRoleRoutes(f)
	st.groups[helpdeskID] = []core.RoleGroup{golden[core.RoleGroup](t, "role_group.json")}
	st.grants[helpdeskID] = []core.Grant{golden[core.Grant](t, "grant.json")}

	res := f.run(t, "", "role", "list")
	if res.code != 0 || !regexp.MustCompile(`Helpdesk\s+custom, based on member\s+3\s+6\s+Front-line support\s+`+helpdeskID).MatchString(res.stdout) ||
		!regexp.MustCompile(`Admin\s+built-in\s+0\s+all`).MatchString(res.stdout) {
		t.Fatalf("role list:\n%s%s", res.stdout, res.stderr)
	}
	res = f.run(t, "", "--json", "role", "list")
	var list []core.RoleDef
	if res.code != 0 || json.Unmarshal([]byte(res.stdout), &list) != nil || len(list) != 5 || list[4].ID != helpdeskID {
		t.Fatalf("role list --json: %+v", res)
	}

	// R22: the lines of "role show" and a warning per high-impact permission.
	res = f.run(t, "", "role", "show", "helpdesk")
	for _, want := range []string{
		"Role:        Helpdesk (" + helpdeskID + "), custom, based on member\n",
		"Description: Front-line support\n",
		"Delegable:   no\n",
		"People:      3 (fileparcel role members Helpdesk)\n",
		"Permissions: shares.links, users.lookup, tokens.create, users.view, users.manage, users.credentials\n",
		"Groups:      Finance (member)\n",
		// grant.json: node_path is relative to the space, whose name is repeated in the sample path.
		"Folders:     /Team/Company/Company/Reports (manage), 1 more you may not see\n",
		"Warning:     Can delete accounts together with their personal files",
		"Warning:     Can reset passwords, and so sign in as the accounts they manage",
	} {
		if !strings.Contains(res.stdout, want) {
			t.Errorf("role show lacks %q:\n%s", want, res.stdout)
		}
	}
	// JSON is the role object of the API.
	res = f.run(t, "", "--json", "role", "show", helpdeskID)
	var rd core.RoleDef
	if res.code != 0 || json.Unmarshal([]byte(res.stdout), &rd) != nil || rd.Name != "Helpdesk" || !rd.Permissions.Has(core.CapUsersManage) ||
		strings.Contains(res.stdout, "Finance") {
		t.Fatalf("role show --json: %+v", res)
	}
	if res := f.run(t, "", "role", "show", "admin"); res.code != 0 || !strings.Contains(res.stdout, "Role:        Admin, built-in\n") ||
		!strings.Contains(res.stdout, "Permissions: all") || f.requested("GET /api/v1/admin/roles/admin/groups") != 0 {
		t.Errorf("role show admin: %+v", res)
	}
	if res := f.run(t, "", "role", "show", "nobody"); res.code != ExitFailure || !strings.Contains(res.stderr, `list them with "fileparcel role list"`) {
		t.Errorf("unknown role: %+v", res)
	}

	res = f.run(t, "", "role", "permissions")
	if res.code != 0 || !strings.Contains(res.stdout, "People\n") || !strings.Contains(res.stdout, "users.manage") ||
		!strings.Contains(res.stdout, "Warning: Can make the server reachable from the internet") || strings.Contains(res.stderr, "catalog of this program") {
		t.Fatalf("role permissions: %+v", res)
	}
	res = f.run(t, "", "--json", "role", "perms")
	var cat core.CapabilityCatalog
	if res.code != 0 || json.Unmarshal([]byte(res.stdout), &cat) != nil || len(cat.Items) != len(core.Capabilities) || len(cat.Groups) == 0 {
		t.Fatalf("role permissions --json: %+v", res)
	}
}

func TestRoleCatalogFallback(t *testing.T) {
	f := newFakeAPI(t) // no /admin/capabilities: a server without roles
	res := f.run(t, "", "role", "permissions")
	if res.code != 0 || !strings.Contains(res.stderr, "(catalog of this program; the server may differ)") || !strings.Contains(res.stdout, "audit.view") {
		t.Fatalf("compiled catalog: %+v", res)
	}
	// The roles list of such a server says why it fails.
	if res := f.run(t, "", "role", "list"); res.code != ExitFailure || !strings.Contains(res.stderr, "this server has no custom roles (upgrade it)") {
		t.Errorf("role list: %+v", res)
	}
	if res := f.run(t, "", "user", "set-role", "alice", "contractors"); res.code != ExitFailure ||
		!strings.Contains(res.stderr, "this server has no custom roles") {
		t.Errorf("custom role on an old server: %+v", res)
	}
}

func TestResolveRoleBuiltinOffline(t *testing.T) {
	// Built-in words need no roles API: --role member works against a
	// server without it and is sent as "role".
	f := newFakeAPI(t)
	users := addUserRoutes(f)
	res := f.run(t, "", "user", "create", "carol", "--generate-password", "--role", "Guest")
	var nu core.NewUser
	_ = json.Unmarshal(f.body("POST /api/v1/admin/users"), &nu)
	if res.code != 0 || nu.Role != core.RoleGuest || nu.RoleID != "" || f.requestedPrefix("GET /api/v1/admin/roles") != 0 {
		t.Fatalf("user create --role Guest: %+v %+v", res, nu)
	}
	if res := f.run(t, "", "user", "set-role", "alice", "member"); res.code != 0 || !strings.Contains(res.stdout, `changed the role of "Alice" to "member"`) {
		t.Fatalf("set-role member: %+v", res)
	}
	if got := string(f.body("PATCH /api/v1/admin/users/" + (*users)[1].ID)); got != `{"role":"member"}` {
		t.Errorf("set-role body %s", got)
	}
	if res := f.run(t, "", "user", "list", "--role", "member"); res.code != 0 ||
		!strings.Contains(f.query("GET /api/v1/admin/users"), "role=member") {
		t.Fatalf("user list --role member: %+v", res)
	}
}

func TestRolePiecesOfUserInviteGroup(t *testing.T) {
	f := newFakeAPI(t)
	addRoleRoutes(f)
	users := addUserRoutes(f)
	f.handle("POST", "/api/v1/admin/invites", func(w http.ResponseWriter, r *http.Request) {
		in, _ := decodeBody[core.InviteInput](r)
		inv := &core.Invite{ID: ids.New(ids.PrefixInvite), Role: in.Role, RoleID: in.RoleID, MaxUses: 1, ExpiresAt: time.Now().Add(time.Hour)}
		if in.RoleID == helpdeskID {
			inv.Role, inv.RoleName = core.RoleMember, "Helpdesk"
		}
		writeJSON(w, 201, core.InviteCreated{Invite: inv, URL: "/invite/x"})
	})

	// user set-role with a custom role sends role_id (by name, any case).
	if res := f.run(t, "", "user", "set-role", "alice", "HELPDESK"); res.code != 0 || !strings.Contains(res.stdout, `to "Helpdesk"`) {
		t.Fatalf("set-role Helpdesk: %+v", res)
	}
	if got := string(f.body("PATCH /api/v1/admin/users/" + (*users)[1].ID)); got != `{"role_id":"`+helpdeskID+`"}` {
		t.Errorf("set-role body %s", got)
	}
	// user create/edit --role and invite create --role do the same.
	f.run(t, "", "user", "create", "dave", "--generate-password", "--role", "Helpdesk")
	var nu core.NewUser
	if _ = json.Unmarshal(f.body("POST /api/v1/admin/users"), &nu); nu.RoleID != helpdeskID || nu.Role != "" {
		t.Errorf("user create body %+v", nu)
	}
	if res := f.run(t, "", "user", "edit", "alice", "--role", helpdeskID, "--email", "a@example.com"); res.code != 0 {
		t.Fatalf("user edit --role: %+v", res)
	}
	var uu core.UserUpdate
	if _ = json.Unmarshal(f.body("PATCH /api/v1/admin/users/"+(*users)[1].ID), &uu); uu.RoleID == nil || *uu.RoleID != helpdeskID || uu.Email == nil {
		t.Errorf("user edit body %+v", uu)
	}
	res := f.run(t, "", "invite", "create", "--role", "helpdesk")
	var ii core.InviteInput
	if _ = json.Unmarshal(f.body("POST /api/v1/admin/invites"), &ii); res.code != 0 || ii.RoleID != helpdeskID || ii.Role != "" ||
		!strings.Contains(res.stdout, "(Helpdesk, 1 use,") {
		t.Errorf("invite create --role helpdesk: %+v %+v", res, ii)
	}
	if res := f.run(t, "", "invite", "create", "--role", "Owner"); res.code != ExitUsage {
		t.Errorf("owner invite: %+v", res)
	}
	// List filters: role_id (and role for a built-in word).
	f.run(t, "", "user", "list", "--role", "member")
	if q := f.query("GET /api/v1/admin/users"); !strings.Contains(q, "role_id=member") || !strings.Contains(q, "role=member") {
		t.Errorf("user list --role member: %q", q)
	}
	f.run(t, "", "role", "members", "helpdesk")
	if q := f.query("GET /api/v1/admin/users"); !strings.Contains(q, "role_id="+helpdeskID) || strings.Contains(q, "role=member") {
		t.Errorf("role members helpdesk: %q", q)
	}

	// user show: the role name and id, and the permissions it gives.
	u := golden[core.User](t, "user.json")
	f.handle("GET", "/api/v1/admin/users/{id}", func(w http.ResponseWriter, r *http.Request) { writeJSON(w, 200, u) })
	res = f.run(t, "", "user", "show", u.ID)
	if res.code != 0 || !strings.Contains(res.stdout, "Role:                 Helpdesk ("+helpdeskID+"), based on member\n") ||
		!strings.Contains(res.stdout, "Permissions:          shares.links, users.lookup, tokens.create, users.view, users.manage, users.credentials\n") {
		t.Errorf("user show:\n%s", res.stdout)
	}
	// user list: the role column names custom roles.
	(*users)[1].RoleID, (*users)[1].RoleName = helpdeskID, "Helpdesk"
	if res := f.run(t, "", "user", "list"); !regexp.MustCompile(`Alice\s+-\s+Helpdesk\s`).MatchString(res.stdout) {
		t.Errorf("user list:\n%s", res.stdout)
	}

	// group members: SOURCE.
	gm := golden[core.GroupMember](t, "group_member.json")
	plain := core.GroupMember{Username: "bob", Role: core.GroupRoleMember} // a server without roles
	f.handle("GET", "/api/v1/admin/groups", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, core.Page[core.Group]{Items: []core.Group{{ID: gm.GroupID, Name: "Finance"}}})
	})
	f.handle("GET", "/api/v1/admin/groups/{id}/members", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, core.Page[core.GroupMember]{Items: []core.GroupMember{gm, plain}})
	})
	res = f.run(t, "", "group", "members", "Finance")
	if res.code != 0 || !regexp.MustCompile(`alice\s+Alice\s+manager\s+direct, role:Finance\s`).MatchString(res.stdout) ||
		!regexp.MustCompile(`bob\s+-\s+member\s+direct\s`).MatchString(res.stdout) || !strings.Contains(res.stdout, "SOURCE") {
		t.Errorf("group members:\n%s", res.stdout)
	}
}

func TestRoleCreateFrom(t *testing.T) {
	f := newFakeAPI(t)
	addRoleRoutes(f)
	body := func() core.RoleDefInput {
		var in core.RoleDefInput
		_ = json.Unmarshal(f.body("POST /api/v1/admin/roles"), &in)
		return in
	}
	res := f.run(t, "", "role", "create", "contractors", "--from", "member", "--remove", "shares.links", "--description", "Freelancers")
	in := body()
	if res.code != 0 || in.CopyFrom != "member" || in.Permissions == nil || in.Description != "Freelancers" ||
		!slices.Equal(*in.Permissions, []core.Capability{core.CapShareRequests, core.CapUsersLookup, core.CapTokensCreate}) {
		t.Fatalf("--from member --remove shares.links: %+v %+v", res, in)
	}
	// Without flags the server copies the role (no list is sent); --base
	// guest starts from guest.
	f.run(t, "", "role", "create", "visitors", "--base", "guest")
	if in := body(); in.CopyFrom != "guest" || in.Base != core.RoleGuest || in.Permissions != nil {
		t.Errorf("--base guest: %+v", in)
	}
	// --set replaces the list; the server's additions are named.
	res = f.run(t, "", "role", "create", "helpers", "--from", "admin", "--set", "users.manage,shares.links", "--delegable")
	if in := body(); res.code != 0 || !in.Delegable || in.CopyFrom != "admin" ||
		!slices.Equal(*in.Permissions, []core.Capability{core.CapShareLinks, core.CapUsersManage}) ||
		!strings.Contains(res.stderr, "also allowed: users.view (needed by users.manage)") {
		t.Fatalf("--set: %+v %+v", res, in)
	}
	res = f.run(t, "", "--json", "role", "create", "auditors", "--from", "guest", "--add", "audit.view")
	var rd core.RoleDef
	if res.code != 0 || json.Unmarshal([]byte(res.stdout), &rd) != nil || !rd.Permissions.Has(core.CapAuditView) || !ids.Valid(ids.PrefixRole, rd.ID) {
		t.Fatalf("--json: %+v", res)
	}
	for _, args := range [][]string{
		{"role", "create", "x", "--set", "a", "--add", "b"},
		{"role", "create", "x", "--base", "admin"},
		{"role", "create", "Admin"},
		{"role", "create", "x", "--delegable", "--no-delegable"},
		{"role", "create", "x", "--add", "shares.links", "--remove", "shares.links"},
	} {
		if res := f.run(t, "", args...); res.code != ExitUsage {
			t.Errorf("%v: %+v", args, res)
		}
	}
	if res := f.run(t, "", "role", "create", "contractors"); res.code != ExitFailure || !strings.Contains(res.stderr, "it already exists") {
		t.Errorf("409 on create: %+v", res)
	}
}

func TestRolePermValidation(t *testing.T) {
	f := newFakeAPI(t)
	addRoleRoutes(f)
	res := f.run(t, "", "role", "create", "x", "--add", "shares.link,audit.view")
	if res.code != ExitUsage || !strings.Contains(res.stderr, `unknown permission "shares.link"`) ||
		!strings.Contains(res.stderr, "\tshares.links\n") || f.requestedPrefix("POST ") != 0 {
		t.Fatalf("unknown permission: %+v", res)
	}
	res = f.run(t, "", "--json", "role", "edit", "helpdesk", "--remove", "users.mange")
	var doc struct {
		Error struct{ Code, Message, Hint string }
	}
	if res.code != ExitUsage || json.Unmarshal([]byte(res.stderr), &doc) != nil || doc.Error.Code != "usage" ||
		!strings.Contains(doc.Error.Hint, `"users.manage"`) || f.requestedPrefix("PATCH ") != 0 {
		t.Fatalf("--json: %+v", res)
	}
	// --allow/--deny are not flags: roles only add up.
	if res := runArgs(t, "", "role", "create", "x", "--allow", "a"); res.code != ExitUsage || !strings.Contains(res.stderr, "\t--add\n") {
		t.Errorf("--allow: %+v", res)
	}
	if res := runArgs(t, "", "role", "edit", "x", "--deny", "a"); res.code != ExitUsage || !strings.Contains(res.stderr, "\t--remove\n") {
		t.Errorf("--deny: %+v", res)
	}
	// parsePermList: commas, case, duplicates.
	got, err := parsePermList([]string{"Shares.Links, audit.view", "shares.links"}, core.Catalog().Items)
	if err != nil || !slices.Equal(got, []core.Capability{core.CapShareLinks, core.CapAuditView}) {
		t.Errorf("parsePermList: %v %v", got, err)
	}
}

func TestRoleEditAndGroups(t *testing.T) {
	f := newFakeAPI(t)
	st := addRoleRoutes(f)
	f.handle("GET", "/api/v1/admin/groups", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, core.Page[core.Group]{Items: []core.Group{{ID: f.me.Groups[0].ID, Name: "Design"}}})
	})
	res := f.run(t, "", "role", "edit", "helpdesk", "--add", "groups.manage", "--remove", "users.credentials", "--name", "Support")
	var in core.RoleDefUpdate
	_ = json.Unmarshal(f.body("PATCH /api/v1/admin/roles/"+helpdeskID), &in)
	if res.code != 0 || in.Name == nil || *in.Name != "Support" || !slices.Equal(in.AddPermissions, []core.Capability{core.CapGroupsManage}) ||
		!slices.Equal(in.RemovePermissions, []core.Capability{core.CapUsersCredentials}) || in.Permissions != nil {
		t.Fatalf("edit: %+v %+v", res, in)
	}
	if !st.find(helpdeskID).Permissions.Has(core.CapGroupsManage) || !strings.Contains(res.stdout, `updated role "Support"`) {
		t.Errorf("edit result: %+v", res)
	}
	res = f.run(t, "", "role", "edit", "support", "--set", "audit.view")
	_ = json.Unmarshal(f.body("PATCH /api/v1/admin/roles/"+helpdeskID), &in)
	if res.code != 0 || in.Permissions == nil || !slices.Equal(*in.Permissions, []core.Capability{core.CapAuditView}) {
		t.Fatalf("edit --set: %+v %+v", res, in)
	}
	if res := f.run(t, "", "role", "edit", "support"); res.code != ExitUsage {
		t.Errorf("nothing to change: %+v", res)
	}
	if res := f.run(t, "", "role", "edit", "member", "--add", "audit.view"); res.code != ExitUsage || !strings.Contains(res.stderr, "built-in roles cannot be changed") {
		t.Errorf("built-in role: %+v", res)
	}

	res = f.run(t, "", "--json", "role", "add-group", "support", "Design", "--manager")
	var rg core.RoleGroup
	if res.code != 0 || json.Unmarshal([]byte(res.stdout), &rg) != nil || rg.MemberRole != core.GroupRoleManager || rg.RoleID != helpdeskID {
		t.Fatalf("add-group: %+v", res)
	}
	if res := f.run(t, "", "role", "remove-group", "support", "design"); res.code != 0 ||
		f.requested("DELETE /api/v1/admin/roles/"+helpdeskID+"/groups/"+f.me.Groups[0].ID) != 1 {
		t.Errorf("remove-group: %+v", res)
	}
	if res := f.run(t, "", "role", "add-group", "member", "Design"); res.code != ExitUsage {
		t.Errorf("add-group of a built-in role: %+v", res)
	}
}

func TestRoleDeleteNeedsReassign(t *testing.T) {
	f := newFakeAPI(t)
	st := addRoleRoutes(f)
	// Helpdesk has 3 people: without --reassign-to nothing is sent.
	res := f.run(t, "", "-y", "role", "delete", "helpdesk")
	if res.code != ExitUsage || !strings.Contains(res.stderr, "3 people have the role \"Helpdesk\"") || f.requestedPrefix("DELETE ") != 0 {
		t.Fatalf("no --reassign-to: %+v", res)
	}
	if res := f.run(t, "", "-y", "role", "delete", "admin", "--reassign-to", "member"); res.code != ExitUsage || f.requestedPrefix("DELETE ") != 0 {
		t.Errorf("built-in role: %+v", res)
	}
	if res := f.run(t, "", "-y", "role", "delete", "helpdesk", "--reassign-to", "Helpdesk"); res.code != ExitUsage {
		t.Errorf("reassign to itself: %+v", res)
	}
	res = f.run(t, "", "-y", "--json", "role", "delete", "helpdesk", "--reassign-to", "guest")
	var out roleDeleted
	if res.code != 0 || json.Unmarshal([]byte(res.stdout), &out) != nil || out != (roleDeleted{Deleted: helpdeskID, ReassignedTo: "guest", Moved: 3}) ||
		f.requested("DELETE /api/v1/admin/roles/"+helpdeskID) != 1 || st.find(helpdeskID) != nil {
		t.Fatalf("delete --reassign-to guest: %+v %+v", res, out)
	}
	// A role nobody has needs no --reassign-to.
	st.roles = append(st.roles, core.RoleDef{ID: ids.New(ids.PrefixRole), Name: "empty", Base: core.RoleMember})
	res = f.run(t, "", "-y", "--json", "role", "rm", "empty")
	if res.code != 0 || !strings.Contains(res.stdout, `"moved": 0`) || strings.Contains(res.stdout, "reassigned_to") {
		t.Errorf("delete of an empty role: %+v", res)
	}
}

func TestRoleDeleteConfirm(t *testing.T) {
	f := newFakeAPI(t)
	addRoleRoutes(f)
	// No terminal and no -y: exit 1, nothing deleted.
	res := f.run(t, "", "role", "delete", "helpdesk", "--reassign-to", "member")
	if res.code != ExitFailure || f.requestedPrefix("DELETE ") != 0 {
		t.Fatalf("no -y: %+v", res)
	}
	res = f.run(t, "n\n", "role", "delete", "helpdesk", "--reassign-to", "member")
	if res.code != ExitFailure || !strings.Contains(res.stderr, `Delete role "Helpdesk"? Its 3 people get the role "member".`) ||
		f.requestedPrefix("DELETE ") != 0 {
		t.Fatalf("declined: %+v", res)
	}
}

func TestRoleForbiddenFallback(t *testing.T) {
	// A caller who may not view people finds custom roles through GET /roles.
	f := newFakeAPI(t)
	addRoleRoutes(f)
	f.handle("GET", "/api/v1/admin/roles", func(w http.ResponseWriter, r *http.Request) {
		writeErr(w, core.Errorf(core.ErrForbidden, "this needs the “View people” permission"))
	})
	addGrantRoutes(f, nil)
	res := f.run(t, "", "access", "grant", "/Team/Design", "--role", "helpdesk")
	var in core.GrantInput
	_ = json.Unmarshal(f.body("POST /api/v1/nodes/"+f.teamRoot()+"/grants"), &in)
	if res.code != 0 || in.SubjectType != core.SubjectRole || in.SubjectID != helpdeskID || f.requested("GET /api/v1/roles") != 1 {
		t.Fatalf("grant --role through /roles: %+v %+v", res, in)
	}
}

// TestExamplesUseRealPermissions: every permission an example names (the
// values of --add, --remove and --set) is in the compiled catalog.
func TestExamplesUseRealPermissions(t *testing.T) {
	root := NewRootCmd()
	seen := 0
	walkCommands(root, func(c *cobra.Command) {
		for _, line := range strings.Split(c.Example, "\n") {
			for _, m := range exampleInvocation.FindAllString(line, -1) {
				words := shellWords(t, m)
				for i, w := range words {
					if i+1 >= len(words) || (w != "--add" && w != "--remove" && w != "--set") {
						continue
					}
					for _, name := range strings.Split(words[i+1], ",") {
						seen++
						if !core.Capability(name).Valid() {
							t.Errorf("%s: example %q names the unknown permission %q", c.CommandPath(), m, name)
						}
					}
				}
			}
		}
	})
	if seen < 5 {
		t.Errorf("only %d permissions found in the examples", seen)
	}
	// The help topic and texts name real permissions too.
	for _, name := range regexp.MustCompile(`\b(?:shares|users|tokens|invites|groups|settings|network|certs|backups|system|audit)\.[a-z]+\b`).
		FindAllString(rootLong+helpTopics[4].Long, -1) {
		if !core.Capability(name).Valid() {
			t.Errorf("help text names the unknown permission %q", name)
		}
	}
}
