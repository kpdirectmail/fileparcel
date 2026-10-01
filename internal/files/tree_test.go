package files

import (
	"slices"
	"strings"
	"testing"

	"fileparcel/internal/core"
	"fileparcel/internal/names"
)

func TestNameRules(t *testing.T) {
	e := newEnv(t)
	alice := e.user("alice", core.RoleMember)
	cases := []struct {
		name, want, code string
	}{
		{"Report", "Report", ""},
		{"REPORT", "", "conflict"},         // case-insensitive uniqueness
		{"report", "", "conflict"},         //
		{"caf\u00e9", "caf\u00e9", ""},     // NFC
		{"cafe\u0301", "", "conflict"},     // NFD of the same name
		{"CAFE\u0301", "", "conflict"},     // NFD + case
		{"Stra\u00dfe", "Stra\u00dfe", ""}, //
		{"STRASSE", "", "conflict"},        // full case folding
		{"  padded  ", "padded", ""},       // surrounding spaces trimmed
		{"trailing.", "trailing.", ""},     // trailing dots allowed
		{strings.Repeat("x", 255), strings.Repeat("x", 255), ""},
		{strings.Repeat("y", 256), "", "invalid"},
		{strings.Repeat("\u00e9", 127) + "a", strings.Repeat("\u00e9", 127) + "a", ""}, // 255 bytes
		{strings.Repeat("\u00e8", 128), "", "invalid"},                                 // 256 bytes
		{strings.Repeat("e\u0300", 127) + "b", "", "conflict"},                         // NFD form is 382 bytes; its NFC form (255 bytes) exists already
		{"", "", "invalid"},
		{"   ", "", "invalid"},
		{".", "", "invalid"},
		{"..", "", "invalid"},
		{"a/b", "", "invalid"},
		{`a\b`, "", "invalid"},
		{"a\x00b", "", "invalid"},
		{"tab\there", "", "invalid"},
		{"\xff\xfe", "", "invalid"},
	}
	// The NFD row above normalizes to 127 × "\u00e8" + "b" (255 bytes): create the
	// NFC form first so that it conflicts.
	e.mkdir(alice, alice.rootID, strings.Repeat("\u00e8", 127)+"b")
	for _, c := range cases {
		n, err := e.svc.Mkdir(e.ctx, alice.Principal, alice.rootID, c.name)
		if code(err) != c.code {
			t.Errorf("Mkdir(%q): %v, want code %q", c.name, err, c.code)
			continue
		}
		if err == nil && n.Name != c.want {
			t.Errorf("Mkdir(%q) = %q, want %q", c.name, n.Name, c.want)
		}
		if c.code == "invalid" {
			if f := core.AsError(err).Field; f != "name" {
				t.Errorf("Mkdir(%q): field %q", c.name, f)
			}
		}
	}
	// Rename follows the same rules; a case-only rename of itself is fine.
	n := e.mkdir(alice, alice.rootID, "Docs")
	if r, err := e.svc.Rename(e.ctx, alice.Principal, n.ID, "DOCS"); err != nil || r.Name != "DOCS" {
		t.Fatalf("case-only rename: %v %v", r, err)
	}
	if _, err := e.svc.Rename(e.ctx, alice.Principal, n.ID, "report"); code(err) != "conflict" {
		t.Fatalf("rename onto sibling: %v", err)
	}
	if _, err := e.svc.Rename(e.ctx, alice.Principal, n.ID, "x/y"); code(err) != "invalid" {
		t.Fatalf("rename invalid: %v", err)
	}
	if _, err := e.svc.Rename(e.ctx, alice.Principal, alice.rootID, "Root"); code(err) != "forbidden" {
		t.Fatalf("rename root: %v", err)
	}
	if e.audit.count(core.ActFileRename) != 1 || e.audit.count(core.ActFolderCreate) < 5 {
		t.Fatalf("audit: rename %d, folder.create %d", e.audit.count(core.ActFileRename), e.audit.count(core.ActFolderCreate))
	}
}

func TestCommitFilePolicies(t *testing.T) {
	e := newEnv(t)
	bob := e.user("bob", core.RoleMember)
	first := e.file(bob, bob.rootID, "Trip/day1/a.txt", "one")
	if first.Name != "a.txt" || first.Size != 3 || first.MIME != "text/plain" || first.VersionID == "" {
		t.Fatalf("first: %+v", first)
	}
	// Intermediate folders exist and are reused.
	trip, err := e.svc.MkdirAll(e.ctx, bob.Principal, bob.rootID, "Trip/day1")
	if err != nil || trip.ID != first.ParentID {
		t.Fatalf("MkdirAll reuse: %v %v", trip, err)
	}

	commit := func(data string, c core.ConflictPolicy) (*core.Node, *core.BlobInfo, error) {
		b := e.blobs.put(t, []byte(data))
		n, err := e.svc.CommitFile(e.ctx, bob.Principal, bob.rootID, "Trip/day1/A.TXT", b, core.FileMeta{}, c)
		return n, b, err
	}
	if _, _, err := commit("x", core.ConflictFail); code(err) != "conflict" {
		t.Fatalf("fail: %v", err)
	}
	n, b, err := commit("two", core.ConflictSkip)
	if err != nil || n.ID != first.ID || n.BlobID == b.ID {
		t.Fatalf("skip: %+v %v", n, err)
	}
	n, _, err = commit("three", core.ConflictRename)
	if err != nil || n.Name != "A (1).TXT" {
		t.Fatalf("rename: %+v %v", n, err)
	}
	n, b, err = commit("four!", core.ConflictReplace)
	if err != nil || n.ID != first.ID || n.Size != 5 || n.BlobID != b.ID || n.VersionID == first.VersionID {
		t.Fatalf("replace: %+v %v", n, err)
	}
	vs, err := e.svc.Versions(e.ctx, bob.Principal, first.ID)
	if err != nil || len(vs) != 2 || !vs[0].Current || vs[1].ID != first.VersionID || vs[0].Size != 5 {
		t.Fatalf("versions: %+v %v", vs, err)
	}
	// Replacing a folder with a file is a conflict.
	if _, err := e.svc.CommitFile(e.ctx, bob.Principal, bob.rootID, "Trip", e.blobs.put(t, []byte("z")), core.FileMeta{},
		core.ConflictReplace); code(err) != "conflict" {
		t.Fatalf("replace folder: %v", err)
	}
	// A file in the way of a folder path: "name (1)" folder, reused later.
	e.file(bob, bob.rootID, "blocker", "x")
	x1 := e.file(bob, bob.rootID, "blocker/in.txt", "1")
	x2 := e.file(bob, bob.rootID, "blocker/in2.txt", "2")
	if x1.ParentID != x2.ParentID {
		t.Fatal("numbered folder not reused")
	}
	if p, _ := e.svc.Get(e.ctx, bob.Principal, x1.ParentID); p.Name != "blocker (1)" {
		t.Fatalf("numbered folder name %q", p.Name)
	}
	// Bad inputs.
	if _, err := e.svc.CommitFile(e.ctx, bob.Principal, bob.rootID, "../x", e.blobs.put(t, nil), core.FileMeta{}, ""); code(err) != "invalid" {
		t.Fatalf("traversal: %v", err)
	}
	if _, err := e.svc.CommitFile(e.ctx, bob.Principal, bob.rootID, "x", &core.BlobInfo{ID: "nope"}, core.FileMeta{}, ""); code(err) != "invalid" {
		t.Fatalf("bad blob: %v", err)
	}
	if _, err := e.svc.CommitFile(e.ctx, bob.Principal, bob.rootID, "x", &core.BlobInfo{ID: strings.Repeat("a", 32)}, core.FileMeta{}, ""); code(err) != "invalid" {
		t.Fatalf("unknown blob: %v", err)
	}
	if _, err := e.svc.CommitFile(e.ctx, bob.Principal, first.ID, "x", e.blobs.put(t, nil), core.FileMeta{}, ""); code(err) != "invalid" {
		t.Fatalf("file as parent: %v", err)
	}
	if _, err := e.svc.CommitFile(e.ctx, bob.Principal, bob.rootID, "x", e.blobs.put(t, nil), core.FileMeta{}, "merge"); code(err) != "invalid" {
		t.Fatalf("bad policy: %v", err)
	}
	// Empty files are fine.
	if z := e.file(bob, bob.rootID, "empty.bin", ""); z.Size != 0 {
		t.Fatalf("empty: %+v", z)
	}
	if e.audit.count(core.ActFileUpload) < 5 {
		t.Fatalf("file.upload audits: %d", e.audit.count(core.ActFileUpload))
	}
}

func TestMIMEOnCommitAndRename(t *testing.T) {
	e := newEnv(t)
	u := e.user("u", core.RoleMember)
	html := "<!DOCTYPE html><html><body><script>alert(1)</script></body></html>"
	cases := []struct{ name, data, want string }{
		{"evil.html", html, "text/html"},
		{"evil.svg", "<svg xmlns=\"http://www.w3.org/2000/svg\"><script>alert(1)</script></svg>", "image/svg+xml"},
		{"fake.png", html, "text/html"},
		{"fake.pdf", html, "text/html"},
		{"real.png", "\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR", "image/png"},
		{"notes.md", "# hi", "text/markdown"},
		{"noext", "plain words", "text/plain"},
	}
	for _, c := range cases {
		if n := e.file(u, u.rootID, c.name, c.data); n.MIME != c.want {
			t.Errorf("%s: MIME %q, want %q", c.name, n.MIME, c.want)
		}
	}
	// The client hint is only used for unknown extensions.
	b := e.blobs.put(t, []byte{0, 1, 2, 3, 4, 5, 6, 7, 8})
	n, err := e.svc.CommitFile(e.ctx, u.Principal, u.rootID, "blob.x-unknown-ext", b, core.FileMeta{MIME: "image/avif"}, "")
	if err != nil || n.MIME != "image/avif" {
		t.Fatalf("hint: %+v %v", n, err)
	}
	b = e.blobs.put(t, []byte(html))
	n, err = e.svc.CommitFile(e.ctx, u.Principal, u.rootID, "page.htm", b, core.FileMeta{MIME: "image/png"}, "")
	if err != nil || n.MIME != "text/html" {
		t.Fatalf("hint ignored for known extension: %+v %v", n, err)
	}
	// Renaming to an inline extension re-sniffs: HTML stays HTML.
	evil := e.file(u, u.rootID, "x.txt", html)
	r, err := e.svc.Rename(e.ctx, u.Principal, evil.ID, "x.pdf")
	if err != nil || r.MIME != "text/html" {
		t.Fatalf("rename re-sniff: %+v %v", r, err)
	}
}

func TestMoveAndCopy(t *testing.T) {
	e := newEnv(t)
	alice := e.user("alice", core.RoleMember)
	a := e.mkdir(alice, alice.rootID, "A")
	b := e.mkdir(alice, a.ID, "B")
	c := e.mkdir(alice, b.ID, "C")
	f := e.file(alice, a.ID, "f.txt", "hello")

	// Move into itself or a descendant is rejected.
	for _, dest := range []string{a.ID, b.ID, c.ID} {
		if _, err := e.svc.Move(e.ctx, alice.Principal, []string{a.ID}, dest, ""); code(err) != "invalid" {
			t.Fatalf("move into %s: %v", dest, err)
		}
		if _, err := e.svc.Copy(e.ctx, alice.Principal, []string{a.ID}, dest, ""); code(err) != "invalid" {
			t.Fatalf("copy into %s: %v", dest, err)
		}
	}
	// Roots cannot move; files are not destinations.
	if _, err := e.svc.Move(e.ctx, alice.Principal, []string{alice.rootID}, c.ID, ""); code(err) != "forbidden" {
		t.Fatalf("move root: %v", err)
	}
	if _, err := e.svc.Move(e.ctx, alice.Principal, []string{b.ID}, f.ID, ""); code(err) != "invalid" {
		t.Fatalf("move into file: %v", err)
	}
	// Plain move, then conflicts.
	moved, err := e.svc.Move(e.ctx, alice.Principal, []string{f.ID}, c.ID, "")
	if err != nil || len(moved) != 1 || moved[0].ParentID != c.ID {
		t.Fatalf("move: %+v %v", moved, err)
	}
	f2 := e.file(alice, a.ID, "F.TXT", "other")
	if _, err := e.svc.Move(e.ctx, alice.Principal, []string{f2.ID}, c.ID, core.ConflictFail); code(err) != "conflict" {
		t.Fatalf("move conflict: %v", err)
	}
	if res, err := e.svc.Move(e.ctx, alice.Principal, []string{f2.ID}, c.ID, core.ConflictSkip); err != nil || len(res) != 0 {
		t.Fatalf("move skip: %+v %v", res, err)
	}
	res, err := e.svc.Move(e.ctx, alice.Principal, []string{f2.ID}, c.ID, core.ConflictReplace)
	if err != nil || len(res) != 1 || res[0].Name != "F.TXT" {
		t.Fatalf("move replace: %+v %v", res, err)
	}
	if old, _ := e.svc.Get(e.ctx, alice.Principal, f.ID); old.TrashedAt == nil {
		t.Fatal("replaced file not in trash")
	}
	// Atomic batch: a failing item rolls back the others.
	g := e.file(alice, a.ID, "g.txt", "g")
	e.file(alice, c.ID, "h.txt", "h")
	h2 := e.file(alice, a.ID, "h.txt", "h2")
	if _, err := e.svc.Move(e.ctx, alice.Principal, []string{g.ID, h2.ID}, c.ID, core.ConflictFail); code(err) != "conflict" {
		t.Fatalf("batch: %v", err)
	}
	if gg, _ := e.svc.Get(e.ctx, alice.Principal, g.ID); gg.ParentID != a.ID {
		t.Fatal("batch move not rolled back")
	}
	// Replace only replaces files with files: a conflicting folder fails
	// the whole batch, the file that could have replaced its namesake
	// included (the web UI then asks again, without Replace).
	e.mkdir(alice, c.ID, "K")
	k2 := e.mkdir(alice, a.ID, "K")
	if _, err := e.svc.Move(e.ctx, alice.Principal, []string{h2.ID, k2.ID}, c.ID, core.ConflictReplace); code(err) != "conflict" {
		t.Fatalf("replace with a folder: %v", err)
	}
	if hh, _ := e.svc.Get(e.ctx, alice.Principal, h2.ID); hh.ParentID != a.ID || hh.TrashedAt != nil {
		t.Fatal("replace batch with a folder not rolled back")
	}
	if got := e.children(alice, c.ID); !slices.Equal(got, []string{"K", "F.TXT", "h.txt"}) {
		t.Fatalf("destination after the refused replace: %v", got)
	}

	// Copy: deep, shares blobs, charges quota, rename by default.
	usedBefore := e.used(alice.spaceID)
	copies, err := e.svc.Copy(e.ctx, alice.Principal, []string{a.ID}, alice.rootID, "")
	if err != nil || len(copies) != 1 || copies[0].Name != "A (1)" || copies[0].ID == a.ID {
		t.Fatalf("copy: %+v %v", copies, err)
	}
	var liveBytes int64
	if err := e.db.QueryRow(e.ctx, liveSubtreeSQL+` SELECT COALESCE(SUM(CASE WHEN n.kind='file' THEN n.size END),0)
		FROM nodes n JOIN sub ON n.id = sub.id`, a.ID).Scan(&liveBytes); err != nil {
		t.Fatal(err)
	}
	if got := e.used(alice.spaceID); got != usedBefore+liveBytes {
		t.Fatalf("copy quota: %d, want %d", got, usedBefore+liveBytes)
	}
	st, err := e.svc.Stats(e.ctx, alice.Principal, copies[0].ID)
	st0, _ := e.svc.Stats(e.ctx, alice.Principal, a.ID)
	if err != nil || *st != (core.FolderStats{NodeID: copies[0].ID, Files: st0.Files, Folders: st0.Folders, Bytes: st0.Bytes}) {
		t.Fatalf("copy stats %+v vs %+v (%v)", st, st0, err)
	}
	var shared int
	if err := e.db.QueryRow(e.ctx, `SELECT COUNT(*) FROM file_versions v JOIN nodes n ON n.id = v.node_id
		WHERE v.blob_id = (SELECT v2.blob_id FROM file_versions v2 WHERE v2.id = ?)`, g.VersionID).Scan(&shared); err != nil || shared != 2 {
		t.Fatalf("copy shares blobs: %d %v", shared, err)
	}
	// Copy replace makes a new version of the existing file.
	target := e.file(alice, alice.rootID, "g.txt", "old")
	out, err := e.svc.Copy(e.ctx, alice.Principal, []string{g.ID}, alice.rootID, core.ConflictReplace)
	if err != nil || len(out) != 1 || out[0].ID != target.ID || out[0].Size != 1 {
		t.Fatalf("copy replace: %+v %v", out, err)
	}
	if e.audit.count(core.ActFileMove) < 2 || e.audit.count(core.ActFileCopy) < 2 {
		t.Fatalf("audits move=%d copy=%d", e.audit.count(core.ActFileMove), e.audit.count(core.ActFileCopy))
	}
	// Invalid batches.
	if _, err := e.svc.Move(e.ctx, alice.Principal, nil, c.ID, ""); code(err) != "invalid" {
		t.Fatalf("empty ids: %v", err)
	}
	if _, err := e.svc.Move(e.ctx, alice.Principal, []string{g.ID}, "nod_doesnotexist", ""); code(err) != "not_found" {
		t.Fatalf("bad dest: %v", err)
	}
}

// TestCopyNodeBudget pins that maxCopyNodes bounds the nodes of a whole
// Copy call — one transaction on the single writer connection — not of
// each of its items, and that a refused call copies nothing.
func TestCopyNodeBudget(t *testing.T) {
	defer func(n int64) { maxCopyNodes = n }(maxCopyNodes)
	maxCopyNodes = 5
	e := newEnv(t)
	u := e.user("alice", core.RoleMember)
	tree := func(name string, subs int) *core.Node {
		f := e.mkdir(u, u.rootID, name)
		for i := range subs {
			e.mkdir(u, f.ID, name+strings.Repeat("-", i+1))
		}
		return f
	}
	a, b, big := tree("A", 2), tree("B", 2), tree("Big", 5) // 3, 3 and 6 nodes
	dest := e.mkdir(u, u.rootID, "Dest")
	nodes := func() int64 { return e.count(`SELECT COUNT(*) FROM nodes WHERE space_id = ?`, u.spaceID) }

	if _, err := e.svc.Copy(e.ctx, u.Principal, []string{a.ID}, dest.ID, ""); err != nil {
		t.Fatalf("copy within the budget: %v", err)
	}
	before := nodes()
	for _, ids := range [][]string{{a.ID, b.ID}, {big.ID}} {
		if _, err := e.svc.Copy(e.ctx, u.Principal, ids, dest.ID, ""); code(err) != "too_large" {
			t.Fatalf("copy of %d items over the budget: %v", len(ids), err)
		}
		if n := nodes(); n != before {
			t.Fatalf("a refused copy left %d nodes behind", n-before)
		}
	}
	if got := e.children(u, dest.ID); !slices.Equal(got, []string{"A"}) {
		t.Fatalf("destination %v", got)
	}
}

func TestCrossSpaceMoveAndQuota(t *testing.T) {
	e := newEnv(t)
	alice := e.user("alice", core.RoleMember)
	bob := e.user("bob", core.RoleMember)
	gid, gspace, groot := e.group("Team")
	e.member(gid, alice, core.GroupRoleMember)
	e.member(gid, bob, core.GroupRoleManager)

	doc := e.file(alice, alice.rootID, "doc.txt", "0123456789")
	if e.used(alice.spaceID) != 10 {
		t.Fatalf("used %d", e.used(alice.spaceID))
	}
	// Owner moves her file into the team space: usage follows.
	if _, err := e.svc.Move(e.ctx, alice.Principal, []string{doc.ID}, groot, ""); err != nil {
		t.Fatal(err)
	}
	if e.used(alice.spaceID) != 0 || e.used(gspace) != 10 {
		t.Fatalf("usage after move: %d %d", e.used(alice.spaceID), e.used(gspace))
	}
	// A team member (PermEdit) cannot move it out of the team space…
	if _, err := e.svc.Move(e.ctx, alice.Principal, []string{doc.ID}, alice.rootID, ""); code(err) != "forbidden" {
		t.Fatalf("member moves out: %v", err)
	}
	// …the manager can, into their own space.
	if _, err := e.svc.Move(e.ctx, bob.Principal, []string{doc.ID}, bob.rootID, ""); err != nil {
		t.Fatalf("manager moves out: %v", err)
	}
	if e.used(gspace) != 0 || e.used(bob.spaceID) != 10 {
		t.Fatalf("usage: %d %d", e.used(gspace), e.used(bob.spaceID))
	}

	// User quota (bytes) and the default quota (GB).
	if _, err := e.db.Exec(e.ctx, `UPDATE users SET quota_bytes = 15 WHERE id = ?`, bob.UserID); err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.CommitFile(e.ctx, bob.Principal, bob.rootID, "big", e.blobs.put(t, []byte("123456")), core.FileMeta{}, ""); code(err) != "quota_exceeded" {
		t.Fatalf("quota: %v", err)
	}
	e.file(bob, bob.rootID, "fits", "12345")
	if _, err := e.svc.Copy(e.ctx, bob.Principal, []string{doc.ID}, bob.rootID, ""); code(err) != "quota_exceeded" {
		t.Fatalf("copy quota: %v", err)
	}
	u, err := e.svc.Usage(e.ctx, bob.UserID)
	if err != nil || u.UsedBytes != 15 || u.QuotaBytes != 15 || u.SpaceID != bob.spaceID {
		t.Fatalf("usage: %+v %v", u, err)
	}
	e.settings.set(settingDefaultQuotaGB, int64(1))
	if u, _ := e.svc.Usage(e.ctx, alice.UserID); u.QuotaBytes != 1<<30 {
		t.Fatalf("default quota: %+v", u)
	}
	e.settings.set(settingMaxFileGB, int64(1))
	if err := e.svc.checkMaxFile(1<<30 + 1); code(err) != "too_large" {
		t.Fatalf("max file: %v", err)
	}
	if _, err := e.svc.Usage(e.ctx, "usr_00000000000000000000000000"); code(err) != "not_found" {
		t.Fatalf("usage unknown: %v", err)
	}
}

// TestRenameConflictKeepsTheName pins that the rename conflict policy never
// stores a name the server's own validator would rewrite. A name whose
// "extension" is longer than the whole budget used to come back as " (1)" —
// leading space, no name, no extension — through names.Numbered.
func TestRenameConflictKeepsTheName(t *testing.T) {
	e := newEnv(t)
	u := e.user("alice", core.RoleMember)
	name := "a." + strings.Repeat("x", 253) // 255 bytes: the longest name there is

	first, err := e.svc.CommitFile(e.ctx, u.Principal, u.rootID, name, e.blobs.put(t, []byte("one")),
		core.FileMeta{}, core.ConflictRename)
	if err != nil {
		t.Fatalf("first commit: %v", err)
	}
	second, err := e.svc.CommitFile(e.ctx, u.Principal, u.rootID, name, e.blobs.put(t, []byte("two")),
		core.FileMeta{}, core.ConflictRename)
	if err != nil {
		t.Fatalf("second commit: %v", err)
	}
	if second.ID == first.ID {
		t.Fatal("the second upload replaced the first instead of being renamed")
	}
	if got := second.Name; got != strings.Trim(got, " ") {
		t.Errorf("renamed to %q: leading or trailing space", got)
	}
	if !strings.HasPrefix(second.Name, "a") || !strings.Contains(second.Name, " (1)") {
		t.Errorf("renamed to %q, want the name and the number kept", second.Name)
	}
	if _, _, err := names.Clean(second.Name); err != nil {
		t.Errorf("stored name %q is not a name Clean accepts: %v", second.Name, err)
	}
}

// TestReplaceIdenticalAddsNoVersion: replacing a file with byte-identical
// content keeps the current version (no second copy charged to the quota);
// different content, or the same bytes with another zip protection, still
// adds one.
func TestReplaceIdenticalAddsNoVersion(t *testing.T) {
	e := newEnv(t)
	u := e.user("ivy", core.RoleMember)
	first := e.file(u, u.rootID, "same.txt", "the same bytes")
	used := e.used(u.spaceID)
	for range 3 {
		n, err := e.svc.CommitFile(e.ctx, u.Principal, u.rootID, "same.txt", e.blobs.put(t, []byte("the same bytes")),
			core.FileMeta{}, core.ConflictReplace)
		if err != nil || n.ID != first.ID || n.VersionID != first.VersionID || n.BlobID != first.BlobID {
			t.Fatalf("identical replace: %+v %v", n, err)
		}
	}
	if vs, err := e.svc.Versions(e.ctx, u.Principal, first.ID); err != nil || len(vs) != 1 {
		t.Fatalf("versions after identical replaces: %d %v", len(vs), err)
	}
	if got := e.used(u.spaceID); got != used {
		t.Fatalf("used %d after identical replaces, want %d", got, used)
	}
	n, err := e.svc.CommitFile(e.ctx, u.Principal, u.rootID, "same.txt", e.blobs.put(t, []byte("other bytes")),
		core.FileMeta{}, core.ConflictReplace)
	if err != nil || n.VersionID == first.VersionID {
		t.Fatalf("different content: %+v %v", n, err)
	}
	if vs, _ := e.svc.Versions(e.ctx, u.Principal, first.ID); len(vs) != 2 {
		t.Fatalf("versions after a real replace: %d", len(vs))
	}
	// The same bytes recorded as a protected zip are a different version.
	z := e.file(u, u.rootID, "a.zip", "PK-bytes")
	pz, err := e.svc.CommitFile(e.ctx, u.Principal, u.rootID, "a.zip", e.blobs.put(t, []byte("PK-bytes")),
		core.FileMeta{ZipEncryption: core.ZipEncAES256}, core.ConflictReplace)
	if err != nil || pz.VersionID == z.VersionID || pz.ZipEncryption != core.ZipEncAES256 {
		t.Fatalf("protected replace: %+v %v", pz, err)
	}
}
