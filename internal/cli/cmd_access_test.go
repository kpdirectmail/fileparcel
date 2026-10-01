package cli

// Tests of "fileparcel access" against the fake API: levels, the acting
// identity over the admin socket, grant, revoke (also of inherited grants)
// and check.

import (
	"encoding/json"
	"net/http"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"

	"fileparcel/internal/core"
	"fileparcel/internal/ids"
)

// fakeGrants is the grant store of addGrantRoutes, with its user list.
type fakeGrants struct {
	mu     sync.Mutex
	byNode map[string][]core.Grant
	users  *[]core.User
}

// user returns the fake account named username.
func (g *fakeGrants) user(username string) *core.User {
	for i := range *g.users {
		if (*g.users)[i].Username == username {
			return &(*g.users)[i]
		}
	}
	return nil
}

func (g *fakeGrants) add(nodeID string, gr core.Grant) core.Grant {
	g.mu.Lock()
	defer g.mu.Unlock()
	gr.ID, gr.NodeID, gr.CreatedAt = ids.New(ids.PrefixGrant), nodeID, time.Now().UTC()
	g.byNode[nodeID] = append(g.byNode[nodeID], gr)
	return gr
}

// addGrantRoutes serves GET/POST /nodes/{id}/grants (grants on the node and
// its ancestors, outermost first; create or update by subject) and DELETE
// /nodes/{id}/grants/{gid} (only on its own node), plus the admin users
// (admin, Alice, bob) and groups (Design, Marketing) it names subjects from.
// GET /groups answers the groups of the X-FP-As user from memberOf.
func addGrantRoutes(f *fakeAPI, memberOf map[string][]core.Group) *fakeGrants {
	users := addUserRoutes(f)
	*users = append(*users, core.User{ID: ids.New(ids.PrefixUser), Username: "bob", Role: core.RoleMember, RoleID: "member",
		Status: core.UserActive, CreatedAt: time.Now().UTC()})
	groups := []core.Group{{ID: f.me.Groups[0].ID, Name: "Design", SpaceID: f.spaces[1].ID}, {ID: ids.New(ids.PrefixGroup), Name: "Marketing"}}
	f.handle("GET", "/api/v1/admin/groups", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, core.Page[core.Group]{Items: groups})
	})
	f.handle("GET", "/api/v1/groups", func(w http.ResponseWriter, r *http.Request) {
		mine := memberOf[r.Header.Get("X-FP-As")]
		if mine == nil {
			mine = []core.Group{}
		}
		writeJSON(w, 200, core.Page[core.Group]{Items: mine})
	})
	st := &fakeGrants{byNode: map[string][]core.Grant{}, users: users}
	name := func(typ, id string) string {
		for _, u := range *users {
			if u.ID == id {
				return u.Username
			}
		}
		for _, g := range groups {
			if g.ID == id {
				return g.Name
			}
		}
		return ""
	}
	f.handle("GET", "/api/v1/nodes/{id}/grants", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		var chain []string
		for cur := f.nodes[chi.URLParam(r, "id")]; cur != nil; cur = f.nodes[cur.ParentID] {
			chain = append([]string{cur.ID}, chain...)
		}
		f.mu.Unlock()
		st.mu.Lock()
		defer st.mu.Unlock()
		out := []core.Grant{}
		for _, id := range chain {
			out = append(out, st.byNode[id]...)
		}
		writeJSON(w, 200, out)
	})
	f.handle("POST", "/api/v1/nodes/{id}/grants", func(w http.ResponseWriter, r *http.Request) {
		in, _ := decodeBody[core.GrantInput](r)
		node := chi.URLParam(r, "id")
		st.mu.Lock()
		for i, g := range st.byNode[node] {
			if g.SubjectType == in.SubjectType && g.SubjectID == in.SubjectID {
				g.Role, g.ExpiresAt = in.Role, in.ExpiresAt
				st.byNode[node][i] = g
				st.mu.Unlock()
				writeJSON(w, 200, g)
				return
			}
		}
		st.mu.Unlock()
		g := st.add(node, core.Grant{SubjectType: in.SubjectType, SubjectID: in.SubjectID, Role: in.Role, ExpiresAt: in.ExpiresAt,
			SubjectName: name(in.SubjectType, in.SubjectID)})
		writeJSON(w, 200, g)
	})
	f.handle("DELETE", "/api/v1/nodes/{id}/grants/{gid}", func(w http.ResponseWriter, r *http.Request) {
		st.mu.Lock()
		defer st.mu.Unlock()
		node, gid := chi.URLParam(r, "id"), chi.URLParam(r, "gid")
		list := st.byNode[node]
		i := slices.IndexFunc(list, func(g core.Grant) bool { return g.ID == gid })
		if i < 0 {
			writeErr(w, core.NotFoundf("grant not found"))
			return
		}
		st.byNode[node] = slices.Delete(list, i, i+1)
		w.WriteHeader(http.StatusNoContent)
	})
	return st
}

func TestAccessLevels(t *testing.T) {
	for in, want := range map[string]string{"view": core.GrantViewer, "viewer": core.GrantViewer, "EDIT": core.GrantEditor,
		"editor": core.GrantEditor, "manage": core.GrantManager, "manager": core.GrantManager} {
		if got, err := parseGrantLevel(in); err != nil || got != want {
			t.Errorf("%q → %q, %v", in, got, err)
		}
	}
	if _, err := parseGrantLevel("owner"); !isUsage(err) {
		t.Errorf("owner: %v", err)
	}
	// The levels follow the model's constants, and every one is named in
	// both directions.
	for _, l := range grantLevels {
		if levelWord(l.API) != l.Word {
			t.Errorf("levelWord(%q) = %q", l.API, levelWord(l.API))
		}
	}
	if res := runArgs(t, "", "access", "grant", "/Team/Design", "--group", "x", "--level", "upload"); res.code != ExitUsage ||
		!strings.Contains(res.stderr, "view, edit or manage") {
		t.Errorf("--level upload: %+v", res)
	}
}

func TestAccessIdentity(t *testing.T) {
	f := newFakeAPI(t)
	addGrantRoutes(f, nil)
	dir := f.socketHome(t)
	grants := "GET /api/v1/nodes/" + f.teamRoot() + "/grants"

	// Over the socket without --as: the system principal, no X-FP-As.
	res := f.runSocket(t, dir, "", "access", "list", "/Team/Design")
	if as, ok := f.as(grants); res.code != 0 || !ok || as != "" {
		t.Fatalf("socket without --as: %+v (as %q, %v)", res, as, ok)
	}
	// "/My files" and relative paths name nobody then.
	for _, p := range []string{"/My files/Taxes", "Taxes", "~"} {
		before := f.requestedPrefix("")
		res := f.runSocket(t, dir, "", "access", "list", p)
		if res.code != ExitUsage || !strings.Contains(res.stderr, `"/My files" is somebody's own folder: say whose with --as USER`) ||
			f.requestedPrefix("") != before {
			t.Errorf("%s without --as: %+v", p, res)
		}
	}
	// With --as the user's own files resolve and every request acts as them.
	res = f.runSocket(t, dir, "", "--as", "alice", "access", "list", "/My files")
	if as, _ := f.as("GET /api/v1/nodes/" + f.myRoot() + "/grants"); res.code != 0 || as != "alice" {
		t.Fatalf("--as alice: %+v (as %q)", res, as)
	}
	// Remotely the token's user; "/My files" is theirs.
	if res := f.run(t, "", "access", "list", "/My files"); res.code != 0 {
		t.Fatalf("remote: %+v", res)
	}
	// A virtual folder is no file or folder.
	if res := f.runSocket(t, dir, "", "access", "list", "/Team"); res.code != ExitUsage {
		t.Errorf("/Team: %+v", res)
	}
}

func TestAccessGrantListRevoke(t *testing.T) {
	f := newFakeAPI(t)
	st := addGrantRoutes(f, nil)
	briefs := f.addFolder(f.teamRoot(), "Briefs")
	dir := f.socketHome(t)

	res := f.runSocket(t, dir, "", "--json", "access", "grant", "/Team/Design", "--group", "Marketing", "--user", "bob",
		"--level", "edit", "--expires", "30d")
	var out []core.Grant
	if res.code != 0 || json.Unmarshal([]byte(res.stdout), &out) != nil || len(out) != 2 {
		t.Fatalf("grant --json: %+v", res)
	}
	var in core.GrantInput
	_ = json.Unmarshal(f.body("POST /api/v1/nodes/"+f.teamRoot()+"/grants"), &in)
	if in.Role != core.GrantEditor || in.ExpiresAt == nil || time.Until(*in.ExpiresAt) < 29*24*time.Hour {
		t.Errorf("grant body %+v", in)
	}
	if out[0].SubjectType != core.SubjectUser || out[1].SubjectType != core.SubjectGroup {
		t.Errorf("users are granted before groups: %+v", out)
	}
	// Granting again changes the level; the human line says what it is now.
	// Without --expires the grant keeps its expiry (a temporary grant must
	// not become permanent when only its level changes).
	res = f.runSocket(t, dir, "", "access", "grant", "/Team/Design", "--group", "Marketing")
	if res.code != 0 || !strings.Contains(res.stdout, "✓ group Marketing can now view /Team/Design (and everything in it), until ") {
		t.Fatalf("re-grant: %+v", res)
	}
	if g := st.byNode[f.teamRoot()]; len(g) != 2 || g[1].Role != core.GrantViewer || g[1].ExpiresAt == nil ||
		time.Until(*g[1].ExpiresAt) < 29*24*time.Hour {
		t.Errorf("re-grant stored %+v", st.byNode[f.teamRoot()])
	}
	// --expires never makes it permanent on purpose.
	res = f.runSocket(t, dir, "", "access", "grant", "/Team/Design", "--group", "Marketing", "--expires", "never")
	if g := st.byNode[f.teamRoot()]; res.code != 0 || strings.Contains(res.stdout, "until") || len(g) != 2 || g[1].ExpiresAt != nil {
		t.Errorf("re-grant --expires never: %+v %+v", res, g)
	}
	if res := f.runSocket(t, dir, "", "access", "grant", "/Team/Design"); res.code != ExitUsage {
		t.Errorf("grant without a subject: %+v", res)
	}
	if res := f.runSocket(t, dir, "", "access", "grant", "/Team/Design", "--role", "member"); res.code != ExitUsage ||
		!strings.Contains(res.stderr, "built-in role") {
		t.Errorf("--role member: %+v", res)
	}

	// The list of a sub-folder shows the inherited grants with their folder.
	res = f.runSocket(t, dir, "", "access", "list", "/Team/Design/Briefs")
	if res.code != 0 || !strings.Contains(res.stdout, "team folder of Design") || !strings.Contains(res.stdout, "Marketing") ||
		!strings.Contains(res.stdout, "/Team/Design ") || !strings.Contains(res.stdout, "never") {
		t.Fatalf("list: %+v", res)
	}
	res = f.runSocket(t, dir, "", "--json", "access", "list", "/Team/Design/Briefs", "--direct")
	if res.code != 0 || strings.TrimSpace(res.stdout) != "[]" {
		t.Errorf("list --direct: %+v", res)
	}

	res = f.runSocket(t, dir, "", "access", "revoke", "/Team/Design", "--user", "admin")
	if res.code != ExitFailure || !strings.Contains(res.stderr, "admin has no access grant on /Team/Design") ||
		!strings.Contains(res.stderr, `see "fileparcel access check admin /Team/Design"`) {
		t.Errorf("revoke without a grant: %+v", res)
	}
	res = f.runSocket(t, dir, "", "--json", "access", "revoke", "/Team/Design", "--group", "Marketing")
	var rev struct{ Revoked []string }
	if res.code != 0 || json.Unmarshal([]byte(res.stdout), &rev) != nil || len(rev.Revoked) != 1 || len(st.byNode[f.teamRoot()]) != 1 {
		t.Fatalf("revoke: %+v", res)
	}
	// By id, also from a sub-folder: deleted on its own node.
	gid := st.byNode[f.teamRoot()][0].ID
	res = f.runSocket(t, dir, "", "access", "revoke", "/Team/Design/Briefs", gid)
	if res.code != 0 || f.requested("DELETE /api/v1/nodes/"+f.teamRoot()+"/grants/"+gid) != 1 || !strings.Contains(res.stdout, "took back") {
		t.Fatalf("revoke by id: %+v", res)
	}
	for _, args := range [][]string{
		{"access", "revoke", "/Team/Design"},                                                    // neither form
		{"access", "revoke", "/Team/Design", "gnt_01j9zq3x4k6m8p0r2t4v6x8z0b", "--user", "bob"}, // both
		{"access", "revoke", "/Team/Design", "nope"},                                            // not a grant id
	} {
		if res := f.runSocket(t, dir, "", args...); res.code != ExitUsage {
			t.Errorf("%v: %+v", args, res)
		}
	}
	res = f.runSocket(t, dir, "", "access", "revoke", "/Team/Design", "gnt_01j9zq3x4k6m8p0r2t4v6x8z0b")
	if res.code != ExitFailure || !strings.Contains(res.stderr, `list them with "fileparcel access list /Team/Design"`) {
		t.Errorf("revoke of an unknown id: %+v", res)
	}
	_ = briefs
}

func TestAccessRevokeInherited(t *testing.T) {
	f := newFakeAPI(t)
	st := addGrantRoutes(f, nil)
	f.addFolder(f.teamRoot(), "Briefs")
	taxes := f.addFolder(f.myRoot(), "Taxes")
	dir := f.socketHome(t)
	res := f.runSocket(t, dir, "", "access", "grant", "/Team/Design", "--group", "Marketing")
	if res.code != 0 {
		t.Fatalf("grant: %+v", res)
	}
	st.add(f.myRoot(), core.Grant{SubjectType: core.SubjectUser, SubjectID: st.user("bob").ID, SubjectName: "bob", Role: core.GrantViewer})

	// Only an inherited grant: exit 1, nothing deleted, the command that
	// revokes it on its folder.
	res = f.runSocket(t, dir, "", "access", "revoke", "/Team/Design/Briefs", "--group", "Marketing")
	if res.code != ExitFailure || !strings.Contains(res.stderr,
		`group Marketing's access comes from a grant on "/Team/Design" (a parent folder); revoke it there: fileparcel access revoke /Team/Design --group Marketing`) ||
		f.requestedPrefix("DELETE ") != 0 {
		t.Fatalf("revoke inherited: %+v", res)
	}
	// In the acting user's own files the command names "/My files".
	res = f.runSocket(t, dir, "", "--as", "alice", "access", "revoke", "/My files/Taxes", "--user", "bob")
	if res.code != ExitFailure || !strings.Contains(res.stderr,
		`bob's access comes from a grant on "/My files" (a parent folder); revoke it there: fileparcel access revoke '/My files' --user bob`) {
		t.Errorf("revoke inherited in own files: %+v", res)
	}
	// Somebody else's personal files have no path on the command line:
	// the folder is named by its id.
	res = f.runSocket(t, dir, "", "access", "revoke", taxes, "--user", "bob")
	if res.code != ExitFailure || !strings.Contains(res.stderr,
		`bob's access comes from a grant on "/My files (alice)" (a parent folder); revoke it there: fileparcel access revoke `+f.myRoot()+` --user bob`) ||
		f.requestedPrefix("DELETE ") != 0 {
		t.Errorf("revoke inherited in alice's files: %+v", res)
	}
}

func TestAccessCheck(t *testing.T) {
	f := newFakeAPI(t)
	marketing := core.Group{ID: ids.New(ids.PrefixGroup), Name: "Marketing", MyRole: core.GroupRoleMember}
	st := addGrantRoutes(f, map[string][]core.Group{"bob": {marketing}})
	// The fake's Marketing group gets the id bob's groups use.
	st.add(f.teamRoot(), core.Grant{SubjectType: core.SubjectGroup, SubjectID: marketing.ID, SubjectName: "Marketing", Role: core.GrantViewer})
	f.permAs = func(as string, n *fakeNode) core.Perm {
		if as == "bob" && n.SpaceID == f.spaces[1].ID {
			return core.PermView
		}
		return core.PermNone
	}
	dir := f.socketHome(t)

	res := f.runSocket(t, dir, "", "access", "check", "bob", "/Team/Design")
	if res.code != 0 || !strings.Contains(res.stdout, "bob can VIEW /Team/Design\n") ||
		!strings.Contains(res.stdout, "because: grant gnt_") || !strings.Contains(res.stdout, "group Marketing → view (bob is in Marketing)") {
		t.Fatalf("check: %+v", res)
	}
	if as, _ := f.as("GET /api/v1/nodes/" + f.teamRoot()); as != "bob" {
		t.Errorf("the permission is asked as %q", as)
	}
	res = f.runSocket(t, dir, "", "--json", "access", "check", "bob", "/Team/Design")
	var doc accessCheck
	if res.code != 0 || json.Unmarshal([]byte(res.stdout), &doc) != nil || doc.Access != "view" || doc.Username != "bob" ||
		len(doc.Reasons) != 1 || doc.Reasons[0].Kind != "grant" || doc.Reasons[0].GrantID == "" || doc.NodeID != f.teamRoot() {
		t.Fatalf("check --json: %+v", res)
	}
	// No access is an answer, not an error.
	res = f.runSocket(t, dir, "", "access", "check", "admin", "/Team/Design")
	if res.code != 0 || !strings.Contains(res.stdout, "admin cannot open /Team/Design") ||
		!strings.Contains(res.stderr, "fileparcel access grant /Team/Design --user admin") {
		t.Errorf("no access: %+v", res)
	}
	res = f.runSocket(t, dir, "", "--json", "access", "check", "admin", "/Team/Design")
	if res.code != 0 || !strings.Contains(res.stdout, `"reasons": []`) || !strings.Contains(res.stdout, `"access": "none"`) {
		t.Errorf("no access --json: %+v", res)
	}
	// "/My files" is the checked user's own.
	res = f.runSocket(t, dir, "", "access", "check", "bob", "/My files")
	if as, _ := f.as("GET /api/v1/me"); as != "bob" {
		t.Errorf("/My files resolved as %q: %+v", as, res)
	}
	// It needs the admin socket.
	if res := f.run(t, "", "access", "check", "bob", "/Team/Design"); res.code != ExitUsage ||
		!strings.Contains(res.stderr, "access check needs the admin socket") {
		t.Errorf("remote: %+v", res)
	}
}

// The other reasons: the team folder of the user's group, a grant to their
// role and, for an owner or admin, the access to all files.
func TestAccessCheckReasons(t *testing.T) {
	f := newFakeAPI(t)
	design := core.Group{ID: f.me.Groups[0].ID, Name: "Design", SpaceID: f.spaces[1].ID, MyRole: core.GroupRoleMember}
	memberOf := map[string][]core.Group{"bob": {design}}
	st := addGrantRoutes(f, memberOf)
	const contractors = "rol_01j9zq3x4k6m8p0r2t4v6x8z0c"
	st.user("bob").RoleID, st.user("bob").RoleName = contractors, "contractors"
	briefs := f.addFolder(f.teamRoot(), "Briefs")
	g := st.add(briefs, core.Grant{SubjectType: core.SubjectRole, SubjectID: contractors, SubjectName: "contractors", Role: core.GrantManager})
	f.permAs = func(as string, n *fakeNode) core.Perm {
		switch {
		case as == "bob" && n.ID == briefs, as == "admin":
			return core.PermManage
		case as == "bob":
			return core.PermEdit
		}
		return core.PermNone
	}
	dir := f.socketHome(t)

	res := f.runSocket(t, dir, "", "access", "check", "bob", "/Team/Design/Briefs")
	want := "bob can MANAGE /Team/Design/Briefs\n" +
		"  because: member of group Design (team folder: edit)\n" +
		"           grant " + g.ID + " on /Team/Design/Briefs: role contractors → manage (bob has this role)\n"
	if res.code != 0 || res.stdout != want {
		t.Fatalf("check bob:\n%s\nwant:\n%s%s", res.stdout, want, res.stderr)
	}
	res = f.runSocket(t, dir, "", "--json", "access", "check", "bob", "/Team/Design/Briefs")
	var doc accessCheck
	if res.code != 0 || json.Unmarshal([]byte(res.stdout), &doc) != nil || doc.Access != "manage" || len(doc.Reasons) != 2 ||
		doc.Reasons[0].Kind != "group" || doc.Reasons[0].Access != "edit" || doc.Reasons[1].Kind != "grant" ||
		doc.Reasons[1].Access != "manage" || doc.Reasons[1].GrantID != g.ID {
		t.Fatalf("check bob --json: %+v", res)
	}
	// A membership only through the role says so.
	memberOf["bob"][0].Via = "role"
	res = f.runSocket(t, dir, "", "access", "check", "bob", "/Team/Design/Briefs")
	if res.code != 0 || !strings.Contains(res.stdout, "  because: member of group Design through the role contractors (team folder: edit)\n") {
		t.Errorf("check bob, member through the role:\n%s%s", res.stdout, res.stderr)
	}
	// The owner is in no group and has no grant: the access to all files.
	res = f.runSocket(t, dir, "", "access", "check", "admin", "/Team/Design")
	if res.code != 0 || res.stdout != "admin can MANAGE /Team/Design\n"+
		"  because: admin access to all files (auth.admin_can_access_files is on)\n" {
		t.Errorf("check admin: %+v", res)
	}
}
