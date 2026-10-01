package files

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"slices"
	"strings"
	"testing"
	"time"

	"fileparcel/internal/core"
)

func (e *testEnv) search(p *user, q core.SearchQuery) []string {
	e.t.Helper()
	page, err := e.svc.Search(e.ctx, p.Principal, q)
	if err != nil {
		e.t.Fatalf("search %q: %v", q.Q, err)
	}
	out := nodeNames(page.Items)
	slices.Sort(out)
	return out
}

func TestSearch(t *testing.T) {
	e := newEnv(t)
	u := e.user("alice", core.RoleMember)
	friend := e.user("bob", core.RoleMember)
	stranger := e.user("eve", core.RoleMember)
	docs := e.mkdir(u, u.rootID, "Docs")
	e.file(u, docs.ID, "Quarterly Report 2024.pdf", "%PDF-1.7")
	e.file(u, docs.ID, "report-final.docx", "PK")
	e.file(u, u.rootID, "Résumé.txt", "cv")
	e.file(u, u.rootID, "ab.txt", "x")
	e.file(u, u.rootID, "100%_done.txt", "x")
	e.file(u, u.rootID, `quote"name.txt`, "x")
	e.file(u, u.rootID, "Straße.txt", "x")
	e.file(u, u.rootID, "ﬁle-lig.txt", "x") // U+FB01, folded to "fi"
	e.mkdir(u, u.rootID, "Reports")
	gone := e.file(u, u.rootID, "old report.txt", "x")
	if err := e.svc.Trash(e.ctx, u.Principal, []string{gone.ID}); err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		q, kind string
		want    []string
	}{
		{"port", "", []string{"Quarterly Report 2024.pdf", "Reports", "report-final.docx"}}, // FTS substring
		{"PORT", "", []string{"Quarterly Report 2024.pdf", "Reports", "report-final.docx"}}, // case-insensitive
		{"report", core.KindFile, []string{"Quarterly Report 2024.pdf", "report-final.docx"}},
		{"report", core.KindFolder, []string{"Reports"}},
		{"sum", "", []string{"Résumé.txt"}},
		{"résumé", "", []string{"Résumé.txt"}},
		{"résumé", "", []string{"Résumé.txt"}}, // NFD query
		{"ab", "", []string{"ab.txt"}},           // LIKE (< 3 characters)
		{"AB", "", []string{"ab.txt"}},
		{"%", "", []string{"100%_done.txt"}}, // LIKE metacharacters are literal
		{"%_", "", []string{"100%_done.txt"}},
		{"_", "", []string{"100%_done.txt"}},
		{`e"n`, "", []string{`quote"name.txt`}}, // FTS quoting
		{"2024", "", []string{"Quarterly Report 2024.pdf"}},
		// Full case folding, the same that makes names equal in a folder,
		// for index (>= 3 folded characters) and LIKE queries alike.
		{"strasse", "", []string{"Straße.txt"}},
		{"STRASSE", "", []string{"Straße.txt"}},
		{"asse", "", []string{"Straße.txt"}},
		{"straße", "", []string{"Straße.txt"}},
		{"STRAßE", "", []string{"Straße.txt"}},
		{"ss", "", []string{"Straße.txt"}},
		{"ß", "", []string{"Straße.txt"}},
		{"file", "", []string{"ﬁle-lig.txt"}},
		{"FILE", "", []string{"ﬁle-lig.txt"}},
		{"ﬁle", "", []string{"ﬁle-lig.txt"}},
		{"nothing here", "", []string{}},
		{"old report", "", []string{}}, // trashed
	}
	for _, c := range cases {
		got := e.search(u, core.SearchQuery{Q: c.q, Kind: c.kind})
		if got == nil {
			got = []string{}
		}
		if !slices.Equal(got, c.want) {
			t.Errorf("search %q (kind %q) = %q, want %q", c.q, c.kind, got, c.want)
		}
	}
	// Space roots never match.
	if got := e.search(u, core.SearchQuery{Q: "My files"}); len(got) != 0 {
		t.Errorf("root matched: %v", got)
	}
	// Path is the location in the space.
	page, err := e.svc.Search(e.ctx, u.Principal, core.SearchQuery{Q: "final"})
	if err != nil || len(page.Items) != 1 || page.Items[0].Path != "/Docs/report-final.docx" {
		t.Fatalf("path: %+v %v", page.Items, err)
	}
	// Pagination.
	var all []string
	cursor := ""
	for i := 0; i < 5; i++ {
		page, err := e.svc.Search(e.ctx, u.Principal, core.SearchQuery{Q: "report", PageReq: core.PageReq{Limit: 1, Cursor: cursor}})
		if err != nil {
			t.Fatal(err)
		}
		all = append(all, nodeNames(page.Items)...)
		if cursor = page.NextCursor; cursor == "" {
			break
		}
	}
	if !slices.Equal(all, []string{"Reports", "Quarterly Report 2024.pdf", "report-final.docx"}) {
		t.Fatalf("paged search %v", all)
	}
	// Space filter.
	if got := e.search(u, core.SearchQuery{Q: "report", SpaceID: friend.spaceID}); len(got) != 0 {
		t.Fatalf("space filter: %v", got)
	}
	// Other users see nothing, grantees see the granted subtree only (path
	// relative to the granted folder).
	if got := e.search(stranger, core.SearchQuery{Q: "report"}); len(got) != 0 {
		t.Fatalf("stranger sees %v", got)
	}
	e.grant(u, docs.ID, core.SubjectUser, friend.UserID, core.GrantViewer)
	if got := e.search(friend, core.SearchQuery{Q: "report"}); !slices.Equal(got, []string{"Quarterly Report 2024.pdf", "report-final.docx"}) {
		t.Fatalf("grantee sees %v", got)
	}
	page, _ = e.svc.Search(e.ctx, friend.Principal, core.SearchQuery{Q: "final"})
	if len(page.Items) != 1 || page.Items[0].Path != "/Docs/report-final.docx" || page.Items[0].Perm != core.PermView {
		t.Fatalf("grantee result %+v", page.Items)
	}
	// Input validation.
	for _, q := range []string{"", "   ", strings.Repeat("x", 201)} {
		if _, err := e.svc.Search(e.ctx, u.Principal, core.SearchQuery{Q: q}); code(err) != "invalid" {
			t.Errorf("search %q: %v", q, err)
		}
	}
	if _, err := e.svc.Search(e.ctx, u.Principal, core.SearchQuery{Q: "abc", Kind: "link"}); code(err) != "invalid" {
		t.Errorf("bad kind: %v", err)
	}
	// Renames are indexed.
	n := e.file(u, u.rootID, "zzz.txt", "x")
	if _, err := e.svc.Rename(e.ctx, u.Principal, n.ID, "renamed-xyz.txt"); err != nil {
		t.Fatal(err)
	}
	if got := e.search(u, core.SearchQuery{Q: "xyz"}); !slices.Equal(got, []string{"renamed-xyz.txt"}) {
		t.Fatalf("after rename %v", got)
	}
	if got := e.search(u, core.SearchQuery{Q: "zzz"}); len(got) != 0 {
		t.Fatalf("old name still indexed %v", got)
	}
}

// TestSearchAdminOverride: with auth.admin_can_access_files an admin
// searches another user's space by choosing it as the location (the Search
// page offers every space GET /spaces lists), audited like opening its root
// folder; "all locations" and Recent keep to the admin's own scope.
func TestSearchAdminOverride(t *testing.T) {
	e := newEnv(t)
	alice := e.user("alice", core.RoleMember)
	admin := e.user("admin", core.RoleAdmin)
	e.file(alice, alice.rootID, "invoice.pdf", "%PDF-1.7")
	own := e.file(admin, admin.rootID, "invoice-own.txt", "x")
	q := core.SearchQuery{Q: "invoice", SpaceID: alice.spaceID}

	// Without the setting: nothing, and nothing audited.
	if got := e.search(admin, q); len(got) != 0 {
		t.Fatalf("without the override: %v", got)
	}
	if n := e.audit.count(core.ActAdminFileAccess); n != 0 {
		t.Fatalf("%d admin.file_access entries without the override", n)
	}

	e.settings.set(settingAdminAccess, true)
	page, err := e.svc.Search(e.ctx, admin.Principal, q)
	if err != nil || len(page.Items) != 1 || page.Items[0].Name != "invoice.pdf" ||
		page.Items[0].Perm != core.PermManage || page.Items[0].Path != "/invoice.pdf" {
		t.Fatalf("search in alice's space: %+v %v", page.Items, err)
	}
	if n := e.audit.count(core.ActAdminFileAccess); n != 1 {
		t.Fatalf("%d admin.file_access entries, want 1", n)
	}
	if a := e.audit.last(core.ActAdminFileAccess); a.TargetID != alice.rootID {
		t.Fatalf("audited %+v, want alice's root", a)
	}
	// Short queries (LIKE) and the kind filter go through the same scope.
	if got := e.search(admin, core.SearchQuery{Q: "in", SpaceID: alice.spaceID, Kind: core.KindFile}); !slices.Equal(got, []string{"invoice.pdf"}) {
		t.Fatalf("short query in alice's space: %v", got)
	}
	// "All locations" and Recent never use the override.
	if got := e.search(admin, core.SearchQuery{Q: "invoice"}); !slices.Equal(got, []string{"invoice-own.txt"}) {
		t.Fatalf("all locations: %v", got)
	}
	if rec, err := e.svc.Recent(e.ctx, admin.Principal, 10); err != nil || len(rec) != 1 || rec[0].ID != own.ID {
		t.Fatalf("recent: %+v %v", rec, err)
	}
	// Searching one's own space is no override: nothing audited.
	before := e.audit.count(core.ActAdminFileAccess)
	if got := e.search(admin, core.SearchQuery{Q: "invoice", SpaceID: admin.spaceID}); !slices.Equal(got, []string{"invoice-own.txt"}) {
		t.Fatalf("own space: %v", got)
	}
	if got := e.search(alice, q); !slices.Equal(got, []string{"invoice.pdf"}) {
		t.Fatalf("alice in her space: %v", got)
	}
	if n := e.audit.count(core.ActAdminFileAccess); n != before {
		t.Fatalf("searching a space of one's own audited %d entries", n-before)
	}
	// An admin token without the admin scope gets no override.
	tok := *admin.Principal
	tok.Via, tok.Scopes = core.ViaToken, []string{core.ScopeFilesRead}
	page, err = e.svc.Search(e.ctx, &tok, q)
	if err != nil || len(page.Items) != 0 || e.audit.count(core.ActAdminFileAccess) != before {
		t.Fatalf("admin token without the admin scope: %+v %v", page.Items, err)
	}
	// Unknown spaces find nothing.
	if got := e.search(admin, core.SearchQuery{Q: "invoice", SpaceID: "spc_00000000000000000000000000"}); len(got) != 0 {
		t.Fatalf("unknown space: %v", got)
	}
}

func TestListPagination(t *testing.T) {
	e := newEnv(t)
	u := e.user("u", core.RoleMember)
	e.mkdir(u, u.rootID, "b-folder")
	e.mkdir(u, u.rootID, "A-folder")
	e.file(u, u.rootID, "c.txt", "123")
	e.clock.Advance(time.Second)
	e.file(u, u.rootID, "B.txt", "1")
	e.clock.Advance(time.Second)
	e.file(u, u.rootID, "a.txt", "12")

	collect := func(q core.ListQuery) []string {
		t.Helper()
		var out []string
		for i := 0; i < 20; i++ {
			page, err := e.svc.List(e.ctx, u.Principal, u.rootID, q)
			if err != nil {
				t.Fatal(err)
			}
			out = append(out, nodeNames(page.Items)...)
			if page.NextCursor == "" {
				return out
			}
			q.Cursor = page.NextCursor
		}
		t.Fatal("pagination does not end")
		return nil
	}
	cases := []struct {
		sort string
		desc bool
		kind string
		want []string
	}{
		{"", false, "", []string{"A-folder", "b-folder", "a.txt", "B.txt", "c.txt"}},
		{"name", true, "", []string{"b-folder", "A-folder", "c.txt", "B.txt", "a.txt"}},
		{"size", false, core.KindFile, []string{"B.txt", "a.txt", "c.txt"}},
		{"size", true, core.KindFile, []string{"c.txt", "a.txt", "B.txt"}},
		{"updated", true, core.KindFile, []string{"a.txt", "B.txt", "c.txt"}},
		{"kind", true, "", []string{"a.txt", "B.txt", "c.txt", "A-folder", "b-folder"}},
		{"", false, core.KindFolder, []string{"A-folder", "b-folder"}},
	}
	for _, c := range cases {
		for _, limit := range []int{1, 2, 100} {
			got := collect(core.ListQuery{PageReq: core.PageReq{Sort: c.sort, Desc: c.desc, Limit: limit}, Kind: c.kind})
			if !slices.Equal(got, c.want) {
				t.Errorf("sort=%s desc=%v kind=%s limit=%d: %v, want %v", c.sort, c.desc, c.kind, limit, got, c.want)
			}
		}
	}
	page, _ := e.svc.List(e.ctx, u.Principal, u.rootID, core.ListQuery{PageReq: core.PageReq{Limit: 1}})
	if _, err := e.svc.List(e.ctx, u.Principal, u.rootID, core.ListQuery{PageReq: core.PageReq{Limit: 1, Sort: "size",
		Cursor: page.NextCursor}}); code(err) != "invalid" {
		t.Fatalf("cursor of another sort: %v", err)
	}
	for _, bad := range []core.ListQuery{{PageReq: core.PageReq{Cursor: "!!"}}, {PageReq: core.PageReq{Sort: "color"}},
		{Kind: "x"}, {PageReq: core.PageReq{Sort: "trashed"}}} {
		if _, err := e.svc.List(e.ctx, u.Principal, u.rootID, bad); code(err) != "invalid" {
			t.Errorf("list %+v: %v", bad, err)
		}
	}
	// Folders carry their child count; files cannot be listed.
	page, _ = e.svc.List(e.ctx, u.Principal, u.rootID, core.ListQuery{Kind: core.KindFolder})
	if page.Items[0].ChildCount == nil || *page.Items[0].ChildCount != 0 {
		t.Fatalf("child count %+v", page.Items[0])
	}
	root, _ := e.svc.Get(e.ctx, u.Principal, u.rootID)
	if root.ChildCount == nil || *root.ChildCount != 5 {
		t.Fatalf("root child count %v", root.ChildCount)
	}
	f := e.file(u, u.rootID, "x.bin", "x")
	if _, err := e.svc.List(e.ctx, u.Principal, f.ID, core.ListQuery{}); code(err) != "invalid" {
		t.Fatalf("list a file: %v", err)
	}
}

// TestSortOrderContract pins what the web UI's client-side sortNodes
// (core/nodes.js) mirrors for the lists it sorts itself: "kind" groups
// folders and files (files first when descending) and orders by name
// inside each group — never by extension — and names compare by name_key,
// code point by code point (file10 before file2), not naturally.
func TestSortOrderContract(t *testing.T) {
	e := newEnv(t)
	u := e.user("u", core.RoleMember)
	for _, n := range []string{"c.doc", "b.txt", "a.zip", "file2.txt", "file10.txt"} {
		e.file(u, u.rootID, n, "x")
	}
	e.mkdir(u, u.rootID, "Zeta")
	e.mkdir(u, u.rootID, "alpha")
	cases := []struct {
		sort string
		desc bool
		want []string
	}{
		{"kind", false, []string{"alpha", "Zeta", "a.zip", "b.txt", "c.doc", "file10.txt", "file2.txt"}},
		{"kind", true, []string{"a.zip", "b.txt", "c.doc", "file10.txt", "file2.txt", "alpha", "Zeta"}},
		{"name", false, []string{"alpha", "Zeta", "a.zip", "b.txt", "c.doc", "file10.txt", "file2.txt"}},
		{"name", true, []string{"Zeta", "alpha", "file2.txt", "file10.txt", "c.doc", "b.txt", "a.zip"}},
	}
	for _, c := range cases {
		for _, limit := range []int{1, 2, 100} {
			var got []string
			q := core.ListQuery{PageReq: core.PageReq{Sort: c.sort, Desc: c.desc, Limit: limit}}
			for range 20 {
				page, err := e.svc.List(e.ctx, u.Principal, u.rootID, q)
				if err != nil {
					t.Fatal(err)
				}
				got = append(got, nodeNames(page.Items)...)
				if q.Cursor = page.NextCursor; q.Cursor == "" {
					break
				}
			}
			if !slices.Equal(got, c.want) {
				t.Errorf("sort=%s desc=%v limit=%d: %v, want %v", c.sort, c.desc, limit, got, c.want)
			}
		}
	}
}

func TestWalkOrdering(t *testing.T) {
	e := newEnv(t)
	u := e.user("u", core.RoleMember)
	top := e.mkdir(u, u.rootID, "Top")
	e.file(u, top.ID, "b.txt", "b")
	e.file(u, top.ID, "A.txt", "a")
	sub := e.mkdir(u, top.ID, "sub")
	e.mkdir(u, sub.ID, "empty")
	e.file(u, sub.ID, "deep.txt", "d")
	gone := e.file(u, top.ID, "gone.txt", "g")
	if err := e.svc.Trash(e.ctx, u.Principal, []string{gone.ID}); err != nil {
		t.Fatal(err)
	}
	// More children than one keyset page.
	many := e.mkdir(u, top.ID, "many")
	const n = walkPage + 17
	for i := 0; i < n; i++ {
		if _, err := e.svc.Mkdir(e.ctx, u.Principal, many.ID, fmt.Sprintf("d%04d", n-i)); err != nil {
			t.Fatal(err)
		}
	}
	lone := e.file(u, u.rootID, "lone.txt", "l")

	var paths []string
	var depths []int
	err := e.svc.Walk(e.ctx, u.Principal, []string{top.ID, lone.ID}, func(we core.WalkEntry) error {
		paths = append(paths, we.Path)
		depths = append(depths, we.Depth)
		if we.Node.Perm != core.PermOwner {
			return fmt.Errorf("perm %v on %s", we.Node.Perm, we.Path)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"Top", "Top/A.txt", "Top/b.txt", "Top/many"}
	for i := 1; i <= n; i++ {
		want = append(want, fmt.Sprintf("Top/many/d%04d", i))
	}
	want = append(want, "Top/sub", "Top/sub/deep.txt", "Top/sub/empty", "lone.txt")
	if !slices.Equal(paths, want) {
		t.Fatalf("walk order:\n got %v\nwant %v", paths, want)
	}
	if depths[0] != 0 || depths[1] != 1 || depths[len(depths)-2] != 2 || depths[len(depths)-1] != 0 {
		t.Fatalf("depths %v", depths)
	}

	// SkipDir skips a folder's contents; other errors stop the walk.
	paths = nil
	err = e.svc.Walk(e.ctx, u.Principal, []string{top.ID}, func(we core.WalkEntry) error {
		paths = append(paths, we.Path)
		if we.Node.Name == "many" {
			return fs.SkipDir
		}
		return nil
	})
	if err != nil || !slices.Equal(paths, []string{"Top", "Top/A.txt", "Top/b.txt", "Top/many", "Top/sub", "Top/sub/deep.txt", "Top/sub/empty"}) {
		t.Fatalf("skipdir: %v %v", paths, err)
	}
	stop := errors.New("stop")
	count := 0
	err = e.svc.Walk(e.ctx, u.Principal, []string{top.ID}, func(core.WalkEntry) error {
		count++
		if count == 3 {
			return stop
		}
		return nil
	})
	if !errors.Is(err, stop) || count != 3 {
		t.Fatalf("stop: %v after %d", err, count)
	}
	// Cancellation stops the walk.
	ctx, cancel := context.WithCancel(e.ctx)
	count = 0
	err = e.svc.Walk(ctx, u.Principal, []string{top.ID}, func(core.WalkEntry) error {
		count++
		if count == 10 {
			cancel()
		}
		return nil
	})
	if !errors.Is(err, context.Canceled) || count != 10 {
		t.Fatalf("cancel: %v after %d", err, count)
	}
	// Permissions: a stranger cannot walk, trashed roots are 404.
	stranger := e.user("x", core.RoleMember)
	if err := e.svc.Walk(e.ctx, stranger.Principal, []string{top.ID}, func(core.WalkEntry) error { return nil }); code(err) != "not_found" {
		t.Fatalf("stranger walk: %v", err)
	}
	if err := e.svc.Walk(e.ctx, u.Principal, []string{gone.ID}, func(core.WalkEntry) error { return nil }); code(err) != "not_found" {
		t.Fatalf("trashed walk: %v", err)
	}
}

func TestStarsSharedRecentBreadcrumbs(t *testing.T) {
	e := newEnv(t)
	u := e.user("owner", core.RoleMember)
	friend := e.user("friend", core.RoleMember)
	teamMate := e.user("mate", core.RoleMember)
	gid, _, _ := e.group("Friends")
	e.member(gid, teamMate, core.GroupRoleMember)

	a := e.mkdir(u, u.rootID, "A")
	b := e.mkdir(u, a.ID, "B")
	f := e.file(u, b.ID, "f.txt", "f")
	e.clock.Advance(time.Second)
	g := e.file(u, u.rootID, "g.txt", "g")

	// Stars.
	if err := e.svc.Star(e.ctx, u.Principal, f.ID, true); err != nil {
		t.Fatal(err)
	}
	if err := e.svc.Star(e.ctx, u.Principal, f.ID, true); err != nil { // idempotent
		t.Fatal(err)
	}
	if err := e.svc.Star(e.ctx, u.Principal, a.ID, true); err != nil {
		t.Fatal(err)
	}
	if n, _ := e.svc.Get(e.ctx, u.Principal, f.ID); !n.Starred {
		t.Fatal("Starred not set")
	}
	st, err := e.svc.Starred(e.ctx, u.Principal, core.ListQuery{})
	if err != nil || !slices.Equal(nodeNames(st.Items), []string{"A", "f.txt"}) || st.Items[1].Path != "/A/B/f.txt" {
		t.Fatalf("starred %v %v", nodeNames(st.Items), err)
	}
	if err := e.svc.Star(e.ctx, u.Principal, a.ID, false); err != nil {
		t.Fatal(err)
	}
	if st, _ := e.svc.Starred(e.ctx, u.Principal, core.ListQuery{}); !slices.Equal(nodeNames(st.Items), []string{"f.txt"}) {
		t.Fatalf("after unstar %v", nodeNames(st.Items))
	}
	if err := e.svc.Star(e.ctx, friend.Principal, f.ID, true); code(err) != "not_found" {
		t.Fatalf("friend stars invisible node: %v", err)
	}

	// Shared with me: direct user grants and group grants; own spaces excluded.
	e.grant(u, b.ID, core.SubjectUser, friend.UserID, core.GrantEditor)
	e.grant(u, g.ID, core.SubjectGroup, gid, core.GrantViewer)
	sw, err := e.svc.SharedWithMe(e.ctx, friend.Principal, core.ListQuery{})
	if err != nil || !slices.Equal(nodeNames(sw.Items), []string{"B"}) || sw.Items[0].Perm != core.PermEdit {
		t.Fatalf("shared with friend %+v %v", sw.Items, err)
	}
	sw, _ = e.svc.SharedWithMe(e.ctx, teamMate.Principal, core.ListQuery{})
	if !slices.Equal(nodeNames(sw.Items), []string{"g.txt"}) || sw.Items[0].Perm != core.PermView {
		t.Fatalf("shared with group %+v", sw.Items)
	}
	if sw, _ := e.svc.SharedWithMe(e.ctx, u.Principal, core.ListQuery{}); len(sw.Items) != 0 {
		t.Fatalf("owner shared-with-me %v", nodeNames(sw.Items))
	}
	// The grantee can star what they see.
	if err := e.svc.Star(e.ctx, friend.Principal, f.ID, true); err != nil {
		t.Fatal(err)
	}

	// Breadcrumbs: owner from the root, grantee from the granted folder.
	bc, err := e.svc.Breadcrumbs(e.ctx, u.Principal, f.ID)
	if err != nil || !slices.Equal(nodeNames(bc), []string{"My files", "A", "B", "f.txt"}) {
		t.Fatalf("owner crumbs %v %v", nodeNames(bc), err)
	}
	bc, err = e.svc.Breadcrumbs(e.ctx, friend.Principal, f.ID)
	if err != nil || !slices.Equal(nodeNames(bc), []string{"B", "f.txt"}) {
		t.Fatalf("grantee crumbs %v %v", nodeNames(bc), err)
	}

	// Recent: newest first, files only, readable ones only.
	rec, err := e.svc.Recent(e.ctx, u.Principal, 0)
	if err != nil || !slices.Equal(nodeNames(rec), []string{"g.txt", "f.txt"}) {
		t.Fatalf("recent %v %v", nodeNames(rec), err)
	}
	if rec, _ := e.svc.Recent(e.ctx, u.Principal, 1); len(rec) != 1 {
		t.Fatalf("recent limit %d", len(rec))
	}
	rec, _ = e.svc.Recent(e.ctx, friend.Principal, 10)
	if !slices.Equal(nodeNames(rec), []string{"f.txt"}) {
		t.Fatalf("friend recent %v", nodeNames(rec))
	}

	// Stats.
	e.file(u, a.ID, "big.bin", "0123456789")
	s, err := e.svc.Stats(e.ctx, u.Principal, a.ID)
	if err != nil || s.Files != 2 || s.Folders != 1 || s.Bytes != 11 {
		t.Fatalf("stats %+v %v", s, err)
	}
	s, _ = e.svc.Stats(e.ctx, u.Principal, f.ID)
	if s.Files != 1 || s.Bytes != 1 {
		t.Fatalf("file stats %+v", s)
	}
}

func TestSpacesAndSysHelpers(t *testing.T) {
	e := newEnv(t)
	u := e.user("u", core.RoleMember)
	guest := e.user("guest", core.RoleGuest)
	gid, gspace, groot := e.group("Team")
	e.member(gid, u, core.GroupRoleManager)
	e.member(gid, guest, core.GroupRoleMember)

	sp, err := e.svc.Spaces(e.ctx, u.Principal)
	if err != nil || len(sp) != 2 || sp[0].ID != u.spaceID || sp[0].Perm != core.PermOwner || sp[0].RootID != u.rootID ||
		sp[1].ID != gspace || sp[1].Perm != core.PermManage || sp[1].QuotaBytes != nil {
		t.Fatalf("spaces %+v %v", sp, err)
	}
	sp, _ = e.svc.Spaces(e.ctx, guest.Principal)
	if len(sp) != 1 || sp[0].ID != gspace || sp[0].Perm != core.PermEdit {
		t.Fatalf("guest spaces %+v", sp)
	}
	if _, err := e.db.Exec(e.ctx, `UPDATE users SET quota_bytes = 1000 WHERE id = ?`, u.UserID); err != nil {
		t.Fatal(err)
	}
	if sp, _ := e.svc.Spaces(e.ctx, u.Principal); sp[0].QuotaBytes == nil || *sp[0].QuotaBytes != 1000 {
		t.Fatalf("quota %+v", sp[0])
	}
	if sp, err := e.svc.Spaces(e.ctx, core.SystemPrincipal(core.ViaSocket)); err != nil || len(sp) != 2 { // guests have no personal space
		t.Fatalf("system spaces %d %v", len(sp), err)
	}

	dir := e.mkdir(u, groot, "Dir")
	f := e.file(u, dir.ID, "f.txt", "hello")
	if n, err := e.svc.GetSys(e.ctx, f.ID); err != nil || n.ID != f.ID || n.Perm != core.PermView {
		t.Fatalf("GetSys %+v %v", n, err)
	}
	if _, err := e.svc.GetSys(e.ctx, "nod_00000000000000000000000000"); code(err) != "not_found" {
		t.Fatalf("GetSys unknown: %v", err)
	}
	for _, c := range []struct {
		anc, id string
		want    bool
	}{{groot, f.ID, true}, {dir.ID, f.ID, true}, {f.ID, f.ID, true}, {f.ID, dir.ID, false}, {u.rootID, f.ID, false}, {"bogus", f.ID, false}} {
		if in, err := e.svc.IsWithin(e.ctx, c.anc, c.id); err != nil || in != c.want {
			t.Errorf("IsWithin(%s, %s) = %v %v", c.anc, c.id, in, err)
		}
	}
	page, err := e.svc.ListSys(e.ctx, dir.ID, core.ListQuery{})
	if err != nil || len(page.Items) != 1 || page.Items[0].Perm != core.PermView {
		t.Fatalf("ListSys %+v %v", page, err)
	}
	n, rd, err := e.svc.OpenSys(e.ctx, f.ID)
	if err != nil || n.Size != 5 || rd.Size() != 5 {
		t.Fatalf("OpenSys %v", err)
	}
	rd.Close()
	if _, _, err := e.svc.OpenSys(e.ctx, dir.ID); code(err) != "invalid" {
		t.Fatalf("OpenSys folder: %v", err)
	}
	if err := e.svc.Trash(e.ctx, u.Principal, []string{dir.ID}); err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.ListSys(e.ctx, dir.ID, core.ListQuery{}); code(err) != "not_found" {
		t.Fatalf("ListSys trashed: %v", err)
	}
	if _, _, err := e.svc.OpenSys(e.ctx, f.ID); code(err) != "not_found" {
		t.Fatalf("OpenSys trashed: %v", err)
	}
	// Open (with a principal) still reads trashed files.
	if _, rd, err := e.svc.Open(e.ctx, u.Principal, f.ID, ""); err != nil {
		t.Fatalf("Open trashed: %v", err)
	} else {
		rd.Close()
	}
	// A corrupted size is detected.
	g := e.file(u, groot, "g.txt", "abc")
	if _, err := e.db.Exec(e.ctx, `UPDATE nodes SET size = 99 WHERE id = ?`, g.ID); err != nil {
		t.Fatal(err)
	}
	if _, _, err := e.svc.Open(e.ctx, u.Principal, g.ID, ""); code(err) != "corrupt" {
		t.Fatalf("size mismatch: %v", err)
	}
}
