package filesapi

import (
	"net/http"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"

	"fileparcel/internal/core"
	"fileparcel/internal/web/mw"
)

// routes lists every mounted route (method + pattern).
func routes(t *testing.T, e *testEnv) [][2]string {
	t.Helper()
	api := chi.NewRouter()
	Mount(api, e.d)
	var out [][2]string
	_ = chi.Walk(api, func(method, route string, _ http.Handler, _ ...func(http.Handler) http.Handler) error {
		out = append(out, [2]string{method, route})
		return nil
	})
	return out
}

var paramRe = regexp.MustCompile(`\{[^}]+\}`)

// TestRouteTable checks that every route of DESIGN §9.4 (filesapi row) is
// mounted.
func TestRouteTable(t *testing.T) {
	e := newEnv(t)
	got := map[string]bool{}
	for _, r := range routes(t, e) {
		got[r[0]+" "+r[1]] = true
	}
	want := []string{
		"GET /spaces", "GET /nodes/{id}", "GET /nodes/{id}/children", "GET /nodes/{id}/breadcrumbs",
		"POST /nodes/{id}/folders", "PATCH /nodes/{id}", "POST /nodes/move", "POST /nodes/copy", "POST /nodes/trash",
		"GET /nodes/{id}/content", "GET /nodes/{id}/thumb", "GET /nodes/{id}/stats", "GET /nodes/{id}/versions",
		"POST /nodes/{id}/versions/{vid}/restore", "GET /nodes/{id}/grants", "POST /nodes/{id}/grants",
		"DELETE /nodes/{id}/grants/{gid}", "PUT /nodes/{id}/star", "DELETE /nodes/{id}/star", "GET /trash",
		"POST /trash/restore", "POST /trash/purge", "DELETE /trash", "GET /search", "GET /recent", "GET /starred",
		"GET /shared-with-me", "POST /archives", "GET /archives/{ticket}", "GET /admin/grants",
	}
	for _, w := range want {
		if !got[w] {
			t.Errorf("route %s missing", w)
		}
	}
	if len(got) != len(want) {
		t.Errorf("%d routes mounted, want %d: %v", len(got), len(want), got)
	}
}

// TestRouteProtectionSweep: every route except the archive ticket download
// answers 401 to anonymous requests and to MFA-pending sessions.
func TestRouteProtectionSweep(t *testing.T) {
	e := newEnv(t)
	u := e.user("alice", core.RoleMember)
	pending := *u.Principal
	pending.AuthLevel = core.AuthLevelPassword
	enroll := *u.Principal
	enroll.EnrollRequired = true
	for _, r := range routes(t, e) {
		path := "/api/v1" + paramRe.ReplaceAllString(r[1], "x")
		if r[1] == "/archives/{ticket}" {
			e.req(nil, r[0], path, nil).expect(t, http.StatusNotFound, "not_found")
			continue
		}
		var body any
		if r[0] != http.MethodGet && r[0] != http.MethodDelete {
			body = map[string]any{}
		}
		if resp := e.req(nil, r[0], path, body); resp.status != http.StatusUnauthorized || resp.code != "unauthorized" {
			t.Errorf("anonymous %s %s: %d %s", r[0], r[1], resp.status, resp.code)
		}
		if resp := e.req(&pending, r[0], path, body); resp.status != http.StatusUnauthorized || resp.code != "mfa_required" {
			t.Errorf("mfa pending %s %s: %d %s", r[0], r[1], resp.status, resp.code)
		}
		if resp := e.req(&enroll, r[0], path, body); resp.status != http.StatusForbidden || resp.code != "mfa_enroll_required" {
			t.Errorf("enrollment pending %s %s: %d %s", r[0], r[1], resp.status, resp.code)
		}
	}
}

func TestTokenScopes(t *testing.T) {
	e := newEnv(t)
	u := e.user("alice", core.RoleMember)
	ro := *u.Principal
	ro.Via, ro.Scopes = core.ViaToken, []string{core.ScopeFilesRead}
	e.req(&ro, "GET", "/api/v1/spaces", nil).expect(t, 200)
	e.req(&ro, "POST", "/api/v1/nodes/"+u.rootID+"/folders", core.NameInput{Name: "x"}).expect(t, 403, "forbidden")
	e.req(&ro, "POST", "/api/v1/archives", core.ArchiveInput{NodeIDs: []string{u.rootID}}).expect(t, 200)
	// Starring writes the stars table, so a read-only token must not do it.
	e.req(&ro, "PUT", "/api/v1/nodes/"+u.rootID+"/star", nil).expect(t, 403, "forbidden")
	e.req(&ro, "DELETE", "/api/v1/nodes/"+u.rootID+"/star", nil).expect(t, 403, "forbidden")
	// Listing grants is a read: files:read, although it needs PermManage.
	e.req(&ro, "GET", "/api/v1/nodes/"+u.rootID+"/grants", nil).expect(t, 200)
	wo := *u.Principal
	wo.Via, wo.Scopes = core.ViaToken, []string{core.ScopeFilesWrite}
	e.req(&wo, "GET", "/api/v1/spaces", nil).expect(t, 403, "forbidden")
	e.req(&wo, "GET", "/api/v1/nodes/"+u.rootID+"/grants", nil).expect(t, 403, "forbidden")
	e.req(&wo, "POST", "/api/v1/nodes/"+u.rootID+"/folders", core.NameInput{Name: "x"}).expect(t, 201)
	e.req(&wo, "PUT", "/api/v1/nodes/"+u.rootID+"/star", nil).expect(t, 204)
	e.req(&wo, "DELETE", "/api/v1/nodes/"+u.rootID+"/star", nil).expect(t, 204)
}

func TestTreeRoutes(t *testing.T) {
	e := newEnv(t)
	alice := e.user("alice", core.RoleMember)
	bob := e.user("bob", core.RoleMember)
	p := alice.Principal

	// Spaces are a bare array.
	var spaces []core.Space
	e.req(p, "GET", "/api/v1/spaces", nil).expect(t, 200).json(t, &spaces)
	if len(spaces) != 1 || spaces[0].RootID != alice.rootID || spaces[0].Perm != core.PermOwner {
		t.Fatalf("spaces %+v", spaces)
	}

	// Folders.
	var docs, sub core.Node
	e.req(p, "POST", "/api/v1/nodes/"+alice.rootID+"/folders", core.NameInput{Name: "Docs"}).expect(t, 201).json(t, &docs)
	e.req(p, "POST", "/api/v1/nodes/"+docs.ID+"/folders", core.NameInput{Name: "Sub"}).expect(t, 201).json(t, &sub)
	e.req(p, "POST", "/api/v1/nodes/"+alice.rootID+"/folders", core.NameInput{Name: "docs"}).expect(t, 409, "conflict")
	e.req(p, "POST", "/api/v1/nodes/"+alice.rootID+"/folders", core.NameInput{Name: "a/b"}).expect(t, 422, "invalid")
	e.req(p, "POST", "/api/v1/nodes/"+alice.rootID+"/folders", `{"name":"x","extra":1}`).expect(t, 422, "invalid")
	e.req(p, "POST", "/api/v1/nodes/"+alice.rootID+"/folders", `{"name":`).expect(t, 422, "invalid")
	e.req(p, "POST", "/api/v1/nodes/"+alice.rootID+"/folders", `{"name":"`+strings.Repeat("x", 300<<10)+`"}`).expect(t, 413, "too_large")
	if e.audit.count(core.ActFolderCreate) != 2 {
		t.Fatalf("folder.create audits %d", e.audit.count(core.ActFolderCreate))
	}

	// Get, children (a Page), breadcrumbs (a bare array).
	var n core.Node
	e.req(p, "GET", "/api/v1/nodes/"+docs.ID, nil).expect(t, 200).json(t, &n)
	if n.Name != "Docs" || n.Perm != core.PermOwner || n.ChildCount == nil || *n.ChildCount != 1 {
		t.Fatalf("get %+v", n)
	}
	f := e.put(alice, docs.ID, "a.txt", []byte("hello"))
	var page core.Page[core.Node]
	e.req(p, "GET", "/api/v1/nodes/"+docs.ID+"/children?limit=1", nil).expect(t, 200).json(t, &page)
	if len(page.Items) != 1 || page.Items[0].Name != "Sub" || page.NextCursor == "" {
		t.Fatalf("children page 1 %+v", page)
	}
	var page2 core.Page[core.Node]
	e.req(p, "GET", "/api/v1/nodes/"+docs.ID+"/children?limit=1&cursor="+page.NextCursor, nil).expect(t, 200).json(t, &page2)
	if len(page2.Items) != 1 || page2.Items[0].Name != "a.txt" || page2.NextCursor != "" {
		t.Fatalf("children page 2 %+v", page2)
	}
	var files core.Page[core.Node]
	e.req(p, "GET", "/api/v1/nodes/"+docs.ID+"/children?kind=file", nil).expect(t, 200).json(t, &files)
	if len(files.Items) != 1 || files.Items[0].ID != f.ID {
		t.Fatalf("kind filter %+v", files.Items)
	}
	e.req(p, "GET", "/api/v1/nodes/"+docs.ID+"/children?sort=color", nil).expect(t, 422, "invalid")
	var crumbs []core.Node
	e.req(p, "GET", "/api/v1/nodes/"+f.ID+"/breadcrumbs", nil).expect(t, 200).json(t, &crumbs)
	if len(crumbs) != 3 || crumbs[0].ID != alice.rootID || crumbs[2].ID != f.ID {
		t.Fatalf("breadcrumbs %+v", crumbs)
	}

	// 404 for invisible nodes, 403 for insufficient rights.
	e.req(bob.Principal, "GET", "/api/v1/nodes/"+docs.ID, nil).expect(t, 404, "not_found")
	e.req(bob.Principal, "GET", "/api/v1/nodes/nod_00000000000000000000000000", nil).expect(t, 404, "not_found")
	e.req(bob.Principal, "GET", "/api/v1/nodes/move", nil).expect(t, 404, "not_found")

	// Grants.
	var g core.Grant
	e.req(p, "POST", "/api/v1/nodes/"+docs.ID+"/grants", core.GrantInput{SubjectType: core.SubjectUser, SubjectID: bob.UserID,
		Role: core.GrantViewer}).expect(t, 200).json(t, &g)
	if g.SubjectName != "bob" || g.Role != core.GrantViewer {
		t.Fatalf("grant %+v", g)
	}
	var grants []core.Grant
	e.req(p, "GET", "/api/v1/nodes/"+sub.ID+"/grants", nil).expect(t, 200).json(t, &grants)
	if len(grants) != 1 || grants[0].NodeID != docs.ID {
		t.Fatalf("inherited grants %+v", grants)
	}
	e.req(bob.Principal, "GET", "/api/v1/nodes/"+docs.ID, nil).expect(t, 200)
	e.req(bob.Principal, "PATCH", "/api/v1/nodes/"+docs.ID, core.NameInput{Name: "Mine"}).expect(t, 403, "forbidden")
	e.req(bob.Principal, "GET", "/api/v1/nodes/"+docs.ID+"/grants", nil).expect(t, 403, "forbidden")
	var shared core.Page[core.Node]
	e.req(bob.Principal, "GET", "/api/v1/shared-with-me", nil).expect(t, 200).json(t, &shared)
	if len(shared.Items) != 1 || shared.Items[0].ID != docs.ID {
		t.Fatalf("shared with me %+v", shared)
	}
	e.req(p, "POST", "/api/v1/nodes/"+docs.ID+"/grants", core.GrantInput{SubjectType: "robot", SubjectID: bob.UserID,
		Role: core.GrantViewer}).expect(t, 422, "invalid")
	e.req(p, "DELETE", "/api/v1/nodes/"+docs.ID+"/grants/"+g.ID, nil).expect(t, 204)
	e.req(p, "DELETE", "/api/v1/nodes/"+docs.ID+"/grants/"+g.ID, nil).expect(t, 404, "not_found")
	e.req(bob.Principal, "GET", "/api/v1/nodes/"+docs.ID, nil).expect(t, 404, "not_found")

	// Rename.
	e.req(p, "PATCH", "/api/v1/nodes/"+f.ID, core.NameInput{Name: "b.txt"}).expect(t, 200).json(t, &n)
	if n.Name != "b.txt" {
		t.Fatalf("rename %+v", n)
	}
	e.req(p, "PATCH", "/api/v1/nodes/"+alice.rootID, core.NameInput{Name: "Root"}).expect(t, 403, "forbidden")

	// Move (default conflict: fail) and copy (default: rename).
	var moved []core.Node
	e.req(p, "POST", "/api/v1/nodes/move", core.MoveInput{IDs: []string{f.ID}, Dest: sub.ID}).expect(t, 200).json(t, &moved)
	if len(moved) != 1 || moved[0].ParentID != sub.ID {
		t.Fatalf("move %+v", moved)
	}
	e.req(p, "POST", "/api/v1/nodes/move", core.MoveInput{IDs: []string{docs.ID}, Dest: sub.ID}).expect(t, 422, "invalid")
	var copies []core.Node
	e.req(p, "POST", "/api/v1/nodes/copy", core.MoveInput{IDs: []string{f.ID}, Dest: sub.ID}).expect(t, 200).json(t, &copies)
	if len(copies) != 1 || copies[0].Name != "b (1).txt" {
		t.Fatalf("copy %+v", copies)
	}
	e.req(p, "POST", "/api/v1/nodes/move", core.MoveInput{IDs: []string{copies[0].ID}, Dest: sub.ID}).expect(t, 200)
	e.req(p, "POST", "/api/v1/nodes/copy", core.MoveInput{IDs: []string{f.ID}, Dest: sub.ID, Conflict: core.ConflictFail}).
		expect(t, 409, "conflict")
	e.req(p, "POST", "/api/v1/nodes/copy", core.MoveInput{IDs: []string{f.ID}, Dest: sub.ID, Conflict: "merge"}).
		expect(t, 422, "invalid")

	// Stats.
	var st core.FolderStats
	e.req(p, "GET", "/api/v1/nodes/"+docs.ID+"/stats", nil).expect(t, 200).json(t, &st)
	if st.Files != 2 || st.Folders != 1 || st.Bytes != 10 {
		t.Fatalf("stats %+v", st)
	}

	// Stars.
	e.req(p, "PUT", "/api/v1/nodes/"+f.ID+"/star", map[string]any{}).expect(t, 204)
	e.req(p, "PUT", "/api/v1/nodes/"+f.ID+"/star", nil).expect(t, 204)
	var starred core.Page[core.Node]
	e.req(p, "GET", "/api/v1/starred", nil).expect(t, 200).json(t, &starred)
	if len(starred.Items) != 1 || !starred.Items[0].Starred {
		t.Fatalf("starred %+v", starred)
	}
	e.req(p, "DELETE", "/api/v1/nodes/"+f.ID+"/star", nil).expect(t, 204)
	e.req(p, "GET", "/api/v1/starred", nil).expect(t, 200).json(t, &starred)
	if len(starred.Items) != 0 || starred.Items == nil {
		t.Fatalf("starred after delete %+v", starred.Items)
	}

	// Search and recent.
	var found core.Page[core.Node]
	e.req(p, "GET", "/api/v1/search?q=b%20(1", nil).expect(t, 200).json(t, &found)
	if len(found.Items) != 1 || found.Items[0].Path != "/Docs/Sub/b (1).txt" {
		t.Fatalf("search %+v", found)
	}
	e.req(p, "GET", "/api/v1/search?q=", nil).expect(t, 422, "invalid")
	e.req(p, "GET", "/api/v1/search?q=Sub&kind=folder&space="+alice.spaceID, nil).expect(t, 200).json(t, &found)
	if len(found.Items) != 1 || found.Items[0].ID != sub.ID {
		t.Fatalf("search folder %+v", found)
	}
	var recent []core.Node
	e.req(p, "GET", "/api/v1/recent?limit=1", nil).expect(t, 200).json(t, &recent)
	if len(recent) != 1 {
		t.Fatalf("recent %+v", recent)
	}
	e.req(p, "GET", "/api/v1/recent?limit=abc", nil).expect(t, 422, "invalid")

	// Versions.
	e.put(alice, sub.ID, "b.txt", []byte("version two"))
	var vs []core.FileVersion
	e.req(p, "GET", "/api/v1/nodes/"+f.ID+"/versions", nil).expect(t, 200).json(t, &vs)
	if len(vs) != 2 || !vs[0].Current || vs[0].Size != 11 {
		t.Fatalf("versions %+v", vs)
	}
	e.req(p, "POST", "/api/v1/nodes/"+f.ID+"/versions/"+vs[1].ID+"/restore", map[string]any{}).expect(t, 200).json(t, &n)
	if n.Size != 5 || n.VersionID == vs[1].ID {
		t.Fatalf("restored version %+v", n)
	}
	e.req(p, "POST", "/api/v1/nodes/"+f.ID+"/versions/ver_00000000000000000000000000/restore", nil).expect(t, 404, "not_found")

	// Trash, restore, purge, empty.
	e.req(p, "POST", "/api/v1/nodes/trash", core.NodeIDsInput{IDs: []string{sub.ID}}).expect(t, 204)
	e.req(p, "POST", "/api/v1/nodes/trash", core.NodeIDsInput{}).expect(t, 422, "invalid")
	var trash core.Page[core.Node]
	e.req(p, "GET", "/api/v1/trash", nil).expect(t, 200).json(t, &trash)
	if len(trash.Items) != 1 || trash.Items[0].ID != sub.ID || trash.Items[0].Path != "/Docs/Sub" {
		t.Fatalf("trash %+v", trash)
	}
	var restored []core.Node
	e.req(p, "POST", "/api/v1/trash/restore", core.NodeIDsInput{IDs: []string{sub.ID}}).expect(t, 200).json(t, &restored)
	if len(restored) != 1 || restored[0].TrashedAt != nil {
		t.Fatalf("restore %+v", restored)
	}
	e.req(p, "POST", "/api/v1/trash/purge", core.NodeIDsInput{IDs: []string{sub.ID}}).expect(t, 422, "invalid")
	e.req(p, "POST", "/api/v1/nodes/trash", core.NodeIDsInput{IDs: []string{sub.ID, docs.ID}}).expect(t, 204)
	e.req(p, "POST", "/api/v1/trash/purge", core.NodeIDsInput{IDs: []string{sub.ID}}).expect(t, 204)
	e.req(p, "DELETE", "/api/v1/trash", nil).expect(t, 204)
	e.req(p, "GET", "/api/v1/trash", nil).expect(t, 200).json(t, &trash)
	if len(trash.Items) != 0 {
		t.Fatalf("trash after empty %+v", trash.Items)
	}
	e.req(p, "GET", "/api/v1/nodes/"+docs.ID, nil).expect(t, 404, "not_found")
	for _, a := range []string{core.ActFileTrash, core.ActFileRestore, core.ActFilePurge, core.ActFileMove, core.ActFileCopy,
		core.ActFileRename, core.ActGrantSet, core.ActGrantRemove, core.ActFileVersionRestore} {
		if e.audit.count(a) == 0 {
			t.Errorf("no %s audit", a)
		}
	}
	// JSON responses carry the API security headers.
	resp := e.req(p, "GET", "/api/v1/spaces", nil)
	if err := mw.CheckSecurityHeaders(resp.header, mw.HeadersAPI); err != nil {
		t.Error(err)
	}
	if !slices.Contains([]string{"application/json", "application/json; charset=utf-8"}, resp.header.Get("Content-Type")) {
		t.Errorf("content type %q", resp.header.Get("Content-Type"))
	}
}
