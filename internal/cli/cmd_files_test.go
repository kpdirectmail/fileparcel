package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"math/rand/v2"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"
	"unicode/utf8"

	"fileparcel/internal/cli/clikit"
	"fileparcel/internal/core"
	"fileparcel/internal/ids"
	"fileparcel/internal/names"
)

// ---------- remote path parsing ----------

func TestParseRemotePath(t *testing.T) {
	nid := ids.New(ids.PrefixNode)
	tests := []struct {
		in      string
		root    string
		group   string
		id      string
		segs    []string
		display string
		wantErr bool
	}{
		{in: "/My files/Docs/a.txt", root: rootMy, segs: []string{"Docs", "a.txt"}, display: "/My files/Docs/a.txt"},
		{in: "/my files", root: rootMy, display: "/My files"},
		{in: "Docs/a.txt", root: rootMy, segs: []string{"Docs", "a.txt"}, display: "/My files/Docs/a.txt"},
		{in: "a.txt", root: rootMy, segs: []string{"a.txt"}, display: "/My files/a.txt"},
		{in: "~", root: rootMy, display: "/My files"},
		{in: "~/x/y", root: rootMy, segs: []string{"x", "y"}, display: "/My files/x/y"},
		{in: "/", root: rootTop, display: "/"},
		{in: "/..", root: rootTop, display: "/"},
		{in: "//My files//Docs/", root: rootMy, segs: []string{"Docs"}, display: "/My files/Docs"},
		{in: "/My files/./Docs/../Pics", root: rootMy, segs: []string{"Pics"}, display: "/My files/Pics"},
		{in: "/My files/../Team/Design", root: rootTeam, group: "Design", display: "/Team/Design"},
		{in: "/Team", root: rootTeam, display: "/Team"},
		{in: "/team/Design/Brand/logo.svg", root: rootTeam, group: "Design", segs: []string{"Brand", "logo.svg"}, display: "/Team/Design/Brand/logo.svg"},
		{in: "  /Team/Design  ", root: rootTeam, group: "Design", display: "/Team/Design"},
		{in: nid, root: rootID, id: nid, display: nid},
		{in: nid + "/sub/x", root: rootID, id: nid, segs: []string{"sub", "x"}, display: nid + "/sub/x"},
		{in: nid + "/sub/../y", root: rootID, id: nid, segs: []string{"y"}, display: nid + "/y"},
		{in: nid + "/../y", wantErr: true},
		{in: "", wantErr: true},
		{in: "   ", wantErr: true},
		{in: "/Elsewhere/x", wantErr: true},
		{in: "nod_notvalid/x", root: rootMy, segs: []string{"nod_notvalid", "x"}, display: "/My files/nod_notvalid/x"},
	}
	for _, tc := range tests {
		t.Run(tc.in, func(t *testing.T) {
			p, err := parseRemotePath(tc.in)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("want error, got %+v", p)
				}
				if !errors.Is(err, core.ErrInvalid) {
					t.Fatalf("want invalid error, got %v", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if p.Root != tc.root || p.Group != tc.group || p.ID != tc.id || strings.Join(p.Segs, "|") != strings.Join(tc.segs, "|") {
				t.Fatalf("got %+v", p)
			}
			if got := p.String(); got != tc.display {
				t.Fatalf("String() = %q, want %q", got, tc.display)
			}
		})
	}
}

func TestRemotePathParent(t *testing.T) {
	p, _ := parseRemotePath("/My files/a/b")
	pp, name, err := p.parent()
	if err != nil || name != "b" || pp.String() != "/My files/a" {
		t.Fatalf("%v %q %v", pp, name, err)
	}
	for _, root := range []string{"/", "/My files", "/Team/Design"} {
		p, _ := parseRemotePath(root)
		if _, _, err := p.parent(); err == nil {
			t.Errorf("%s: parent of a root must fail", root)
		}
	}
}

// ---------- resolver against the fake API ----------

// fakeTree fills the fake with:
//
//	/My files/Docs/Report.PDF, /My files/Docs/sub/, /My files/Pics/p1..p5.jpg
//	/Team/Design/Brand/logo.svg
func fakeTree(t *testing.T, f *fakeAPI) (docs, report, pics, brand string) {
	t.Helper()
	docs = f.addFolder(f.myRoot(), "Docs")
	report = f.addFile(docs, "Report.PDF", []byte("report v1"))
	f.addFolder(docs, "sub")
	pics = f.addFolder(f.myRoot(), "Pics")
	for i := 1; i <= 5; i++ {
		f.addFile(pics, "p"+string(rune('0'+i))+".jpg", bytes.Repeat([]byte{byte(i)}, 100*i))
	}
	brand = f.addFolder(f.teamRoot(), "Brand")
	f.addFile(brand, "logo.svg", []byte("<svg/>"))
	return
}

func remoteClient(t *testing.T, f *fakeAPI) *Client {
	t.Helper()
	c, err := Connect(Options{Server: f.srv.URL, Token: fakeToken})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	return c
}

func TestResolver(t *testing.T) {
	f := newFakeAPI(t)
	docs, report, _, _ := fakeTree(t, f)
	c := remoteClient(t, f)
	ctx := context.Background()
	r := newResolver(c)

	for _, tc := range []struct {
		in, wantID, wantPath string
		virtual              string
	}{
		{in: "/My files/Docs/Report.PDF", wantID: report, wantPath: "/My files/Docs/Report.PDF"},
		{in: "/my files/docs/report.pdf", wantID: report},
		{in: "Docs", wantID: docs},
		{in: "~/Docs/../Docs/Report.PDF", wantID: report},
		{in: docs + "/Report.PDF", wantID: report, wantPath: docs + "/Report.PDF"},
		{in: "/My files", wantID: f.myRoot()},
		{in: "/Team/design", wantID: f.teamRoot()},
		{in: "/", virtual: virtualTop},
		{in: "/Team", virtual: virtualTeam},
	} {
		tg, err := r.resolve(ctx, tc.in)
		if err != nil {
			t.Fatalf("%s: %v", tc.in, err)
		}
		if tc.virtual != "" {
			if tg.Node != nil || tg.Virtual != tc.virtual {
				t.Fatalf("%s: got %+v", tc.in, tg)
			}
			continue
		}
		if tg.Node == nil || tg.Node.ID != tc.wantID {
			t.Fatalf("%s: got %+v", tc.in, tg)
		}
		if tc.wantPath != "" && tg.Path != tc.wantPath {
			t.Fatalf("%s: path %q", tc.in, tg.Path)
		}
	}
	if logo := f.lookup(f.teamRoot(), "Brand/logo.svg"); logo == nil {
		t.Fatal("fake tree")
	} else if tg, err := r.resolve(ctx, "/Team/Design/Brand/LOGO.svg"); err != nil || tg.Node.ID != logo.ID {
		t.Fatalf("team path: %v %+v", err, tg)
	}

	// Errors.
	_, err := r.resolve(ctx, "/My files/Docs/missing.txt")
	if !errors.Is(err, core.ErrNotFound) || !strings.Contains(err.Error(), "/My files/Docs/missing.txt: no such file or folder") {
		t.Fatalf("missing: %v", err)
	}
	if _, err := r.resolve(ctx, "/My files/Docs/Report.PDF/x"); !errors.Is(err, core.ErrInvalid) || !strings.Contains(err.Error(), "is a file") {
		t.Fatalf("file as folder: %v", err)
	}
	if _, err := r.resolve(ctx, "/Team/Nope"); !errors.Is(err, core.ErrNotFound) || !strings.Contains(err.Error(), "available: Design") {
		t.Fatalf("unknown team: %v", err)
	}
	if _, err := r.resolve(ctx, ids.New(ids.PrefixNode)); !errors.Is(err, core.ErrNotFound) {
		t.Fatalf("unknown id: %v", err)
	}
	if _, err := r.resolveFolder(ctx, "/My files/Docs/Report.PDF"); !errors.Is(err, core.ErrInvalid) {
		t.Fatalf("resolveFolder(file): %v", err)
	}
	if _, err := r.resolveFolder(ctx, "/Team"); !errors.Is(err, core.ErrInvalid) {
		t.Fatalf("resolveFolder(/Team): %v", err)
	}
	if _, err := r.resolveNode(ctx, "/"); !errors.Is(err, core.ErrInvalid) {
		t.Fatalf("resolveNode(/): %v", err)
	}

	// resolveNew.
	parent, name, existing, err := r.resolveNew(ctx, "/My files/Docs/new.txt")
	if err != nil || parent.Node.ID != docs || name != "new.txt" || existing != nil {
		t.Fatalf("resolveNew: %v %q %v", err, name, existing)
	}
	if _, _, existing, err := r.resolveNew(ctx, "Docs/report.pdf"); err != nil || existing == nil || existing.ID != report {
		t.Fatalf("resolveNew existing: %v %v", err, existing)
	}
	if _, _, _, err := r.resolveNew(ctx, "/My files"); err == nil {
		t.Fatal("resolveNew of a root must fail")
	}

	// mkdirAll creates missing folders once.
	tg, created, err := r.mkdirAll(ctx, "/My files/A/B/C")
	if err != nil || len(created) != 3 || tg.Path != "/My files/A/B/C" {
		t.Fatalf("mkdirAll: %v %v %+v", err, created, tg)
	}
	if f.lookup(f.myRoot(), "A/B/C") == nil {
		t.Fatal("folders not created")
	}
	if _, created, err := newResolver(c).mkdirAll(ctx, "/My files/A/B/C"); err != nil || len(created) != 0 {
		t.Fatalf("mkdirAll again: %v %v", err, created)
	}
	if _, _, err := r.mkdirAll(ctx, "/My files/Docs/Report.PDF/x"); !errors.Is(err, core.ErrInvalid) {
		t.Fatalf("mkdirAll through a file: %v", err)
	}

	// displayPath from breadcrumbs.
	rep, _ := r.getNode(ctx, report)
	if got := r.displayPath(ctx, rep); got != "/My files/Docs/Report.PDF" {
		t.Fatalf("displayPath %q", got)
	}
	logo := f.lookup(f.teamRoot(), "Brand/logo.svg")
	if got := r.displayPath(ctx, &logo.Node); got != "/Team/Design/Brand/logo.svg" {
		t.Fatalf("displayPath team %q", got)
	}
}

// ---------- browse commands ----------

func TestFilesLsTreeInfo(t *testing.T) {
	f := newFakeAPI(t)
	docs, report, _, _ := fakeTree(t, f)

	res := f.run(t, "", "files", "ls")
	if res.code != 0 || !strings.Contains(res.stdout, "Docs/") || !strings.Contains(res.stdout, "Pics/") {
		t.Fatalf("ls: %+v", res)
	}
	// Pagination: the fake pages children by 2, all 5 must be listed.
	res = f.run(t, "", "--json", "files", "ls", "/My files/Pics")
	var nodes []core.Node
	if err := json.Unmarshal([]byte(res.stdout), &nodes); err != nil || len(nodes) != 5 {
		t.Fatalf("ls --json: %v %d %s", err, len(nodes), res.stdout)
	}
	res = f.run(t, "", "files", "ls", "/")
	if res.code != 0 || !strings.Contains(res.stdout, "My files/") || !strings.Contains(res.stdout, "Team/") {
		t.Fatalf("ls /: %+v", res)
	}
	res = f.run(t, "", "files", "ls", "/Team")
	if res.code != 0 || !strings.Contains(res.stdout, "Design/") {
		t.Fatalf("ls /Team: %+v", res)
	}
	res = f.run(t, "", "files", "ls", "-l", "/My files/Docs/Report.PDF")
	if res.code != 0 || !strings.Contains(res.stdout, "Report.PDF") || !strings.Contains(res.stdout, report) {
		t.Fatalf("ls file: %+v", res)
	}
	res = f.run(t, "", "files", "ls", "--sort", "bogus")
	if res.code != ExitUsage {
		t.Fatalf("bad sort: %+v", res)
	}
	res = f.run(t, "", "files", "ls", "/Nope")
	if res.code != ExitUsage || !strings.Contains(res.stderr, "unknown top-level folder") {
		t.Fatalf("bad root: %+v", res)
	}
	res = f.run(t, "", "files", "ls", "/My files/Nope")
	if res.code != ExitFailure || !strings.Contains(res.stderr, "no such file or folder") {
		t.Fatalf("missing: %+v", res)
	}

	res = f.run(t, "", "files", "tree")
	if res.code != 0 {
		t.Fatalf("tree: %+v", res)
	}
	for _, want := range []string{"/My files", "├── Docs/", "│   ├── sub/", "│   └── Report.PDF", "└── Pics/", "    └── p5.jpg", "3 folders, 6 files"} {
		if !strings.Contains(res.stdout, want) {
			t.Fatalf("tree output lacks %q:\n%s", want, res.stdout)
		}
	}
	res = f.run(t, "", "--json", "files", "tree", "--depth", "1")
	var entries []core.WalkEntry
	if err := json.Unmarshal([]byte(res.stdout), &entries); err != nil || len(entries) != 2 {
		t.Fatalf("tree --depth 1: %v %s", err, res.stdout)
	}

	res = f.run(t, "", "files", "info", "/My files/Docs")
	if res.code != 0 || !strings.Contains(res.stdout, "1 folder, 1 file") || !strings.Contains(res.stdout, docs) {
		t.Fatalf("info folder: %+v", res)
	}
	res = f.run(t, "", "--json", "files", "info", report)
	var info nodeInfo
	if err := json.Unmarshal([]byte(res.stdout), &info); err != nil || info.Path != "/My files/Docs/Report.PDF" || info.Node.ID != report {
		t.Fatalf("info --json by id: %v %s", err, res.stdout)
	}

	res = f.run(t, "", "files", "search", "p3")
	if res.code != 0 || !strings.Contains(res.stdout, "/My files/Pics/p3.jpg") {
		t.Fatalf("search: %+v", res)
	}
	res = f.run(t, "", "files", "search", "zzz")
	if res.code != 0 || !strings.Contains(res.stderr, "no matches") {
		t.Fatalf("search none: %+v", res)
	}
	res = f.run(t, "", "files", "search", "x", "--kind", "blob")
	if res.code != ExitUsage {
		t.Fatalf("search bad kind: %+v", res)
	}
}

func TestFilesMkdirMvCpRmRestore(t *testing.T) {
	f := newFakeAPI(t)
	docs, report, pics, _ := fakeTree(t, f)

	if res := f.run(t, "", "files", "mkdir", "/My files/New"); res.code != 0 || f.lookup(f.myRoot(), "New") == nil {
		t.Fatalf("mkdir: %+v", res)
	}
	if res := f.run(t, "", "files", "mkdir", "/My files/New"); res.code != ExitFailure || !strings.Contains(res.stderr, "already exists") {
		t.Fatalf("mkdir existing: %+v", res)
	}
	if res := f.run(t, "", "files", "mkdir", "-p", "/My files/New", "/My files/X/Y"); res.code != 0 || f.lookup(f.myRoot(), "X/Y") == nil {
		t.Fatalf("mkdir -p: %+v", res)
	}
	if res := f.run(t, "", "files", "mkdir", "/My files/Missing/Z"); res.code != ExitFailure {
		t.Fatalf("mkdir missing parent: %+v", res)
	}

	// Rename in place (PATCH), then move into a folder (POST /nodes/move).
	if res := f.run(t, "", "files", "mv", "/My files/Docs/Report.PDF", "/My files/Docs/Final.pdf"); res.code != 0 {
		t.Fatalf("mv rename: %+v", res)
	}
	if n := f.lookup(docs, "Final.pdf"); n == nil || n.ID != report {
		t.Fatal("rename did not happen")
	}
	if f.requestedPrefix("POST /api/v1/nodes/move") != 0 {
		t.Fatal("a plain rename must not call move")
	}
	if res := f.run(t, "", "files", "mv", "/My files/Docs/Final.pdf", "/My files/Pics"); res.code != 0 {
		t.Fatalf("mv into folder: %+v", res)
	}
	if f.lookup(pics, "Final.pdf") == nil {
		t.Fatal("move did not happen")
	}
	var mv core.MoveInput
	_ = json.Unmarshal(f.body("POST /api/v1/nodes/move"), &mv)
	if mv.Dest != pics || len(mv.IDs) != 1 || mv.Conflict != core.ConflictFail {
		t.Fatalf("move body %+v", mv)
	}
	// Move and rename in one step.
	if res := f.run(t, "", "files", "mv", "/My files/Pics/Final.pdf", "/Team/Design/Brand/Deck.pdf"); res.code != 0 {
		t.Fatalf("mv+rename: %+v", res)
	}
	if n := f.lookup(f.teamRoot(), "Brand/Deck.pdf"); n == nil || n.ID != report {
		t.Fatal("move+rename did not happen")
	}
	// Copy under a new name; copy into a folder with a conflict → rename.
	if res := f.run(t, "", "files", "cp", "/Team/Design/Brand/Deck.pdf", "/My files/Copy.pdf"); res.code != 0 || f.lookup(f.myRoot(), "Copy.pdf") == nil {
		t.Fatalf("cp new name: %+v", res)
	}
	if res := f.run(t, "", "files", "cp", "/My files/Copy.pdf", "/My files"); res.code != 0 || f.lookup(f.myRoot(), "Copy (1).pdf") == nil {
		t.Fatalf("cp conflict rename: %+v", res)
	}
	if res := f.run(t, "", "files", "mv", "/My files", "/My files/X"); res.code != ExitUsage {
		t.Fatalf("mv root: %+v", res)
	}
	if res := f.run(t, "", "files", "mv", "a", "b", "c", "--conflict", "merge"); res.code != ExitUsage {
		t.Fatalf("bad conflict: %+v", res)
	}
	if res := f.run(t, "", "files", "mv", "/My files/Copy.pdf", "/My files/Pics/p1.jpg"); res.code != ExitFailure || !strings.Contains(res.stderr, "already exists") {
		t.Fatalf("mv onto a file: %+v", res)
	}

	// rm → trash → restore by name → rm --purge.
	if res := f.run(t, "", "files", "rm", "/My files/Copy.pdf"); res.code != 0 {
		t.Fatalf("rm: %+v", res)
	}
	res := f.run(t, "", "files", "trash")
	if res.code != 0 || !strings.Contains(res.stdout, "/My files/Copy.pdf") {
		t.Fatalf("trash: %+v", res)
	}
	if res := f.run(t, "", "files", "restore", "copy.pdf"); res.code != 0 || f.lookup(f.myRoot(), "Copy.pdf") == nil {
		t.Fatalf("restore by name: %+v", res)
	}
	if res := f.run(t, "", "files", "restore", "nothing-here"); res.code != ExitFailure || !strings.Contains(res.stderr, "not in the trash") {
		t.Fatalf("restore missing: %+v", res)
	}
	if res := f.run(t, "", "files", "rm", "--purge", "/My files/Copy.pdf"); res.code != ExitFailure || !strings.Contains(res.stderr, "aborted") && !strings.Contains(res.stderr, "input required") {
		t.Fatalf("purge without -y must not proceed: %+v", res)
	}
	if res := f.run(t, "", "-y", "files", "rm", "--purge", "/My files/Copy.pdf"); res.code != 0 || f.requested("POST /api/v1/trash/purge") != 1 {
		t.Fatalf("rm --purge: %+v", res)
	}
	if res := f.run(t, "", "files", "rm", "/Team/Design"); res.code != ExitUsage {
		t.Fatalf("rm root: %+v", res)
	}
	if res := f.run(t, "", "-y", "files", "trash", "--empty"); res.code != 0 || f.requested("DELETE /api/v1/trash") != 1 {
		t.Fatalf("trash --empty: %+v", res)
	}
}

// In the SRC NEW-PATH form NEW-PATH is free, so --conflict must not be
// applied to the source's current name in the destination folder: that would
// trash or overwrite an unrelated item of that name, or (cp into the same
// folder) rename the source instead of copying it.
func TestFilesMvCpNewPathIgnoresConflict(t *testing.T) {
	f := newFakeAPI(t)
	docs, report, pics, _ := fakeTree(t, f)
	unrelated := f.addFile(pics, "Report.PDF", []byte("unrelated"))

	res := f.run(t, "", "files", "mv", "/My files/Docs/Report.PDF", "/My files/Pics/New.pdf", "--conflict", "replace")
	if res.code != 0 {
		t.Fatalf("mv to a new path: %+v", res)
	}
	var mv core.MoveInput
	_ = json.Unmarshal(f.body("POST /api/v1/nodes/move"), &mv)
	if mv.Conflict != core.ConflictRename {
		t.Fatalf("move body %+v", mv)
	}
	if n := f.lookup(pics, "Report.PDF"); n == nil || n.ID != unrelated || n.TrashedAt != nil || string(n.data) != "unrelated" {
		t.Fatalf("the unrelated file was touched: %+v", n)
	}
	if n := f.lookup(pics, "New.pdf"); n == nil || n.ID != report || n.Name != "New.pdf" {
		t.Fatalf("moved file %+v", n)
	}
	// The default policy (fail) must not refuse a free NEW-PATH either.
	f.addFile(docs, "p1.jpg", []byte("other"))
	if res := f.run(t, "", "files", "mv", "/My files/Pics/p1.jpg", "/My files/Docs/q1.jpg"); res.code != 0 {
		t.Fatalf("mv with the default policy: %+v", res)
	}
	if f.lookup(docs, "q1.jpg") == nil || f.lookup(docs, "p1.jpg") == nil {
		t.Fatal("mv with the default policy did not happen")
	}

	// cp into the same folder under a new name makes a real copy.
	p2 := f.lookup(pics, "p2.jpg")
	res = f.run(t, "", "files", "cp", "/My files/Pics/p2.jpg", "/My files/Pics/p2-copy.jpg", "--conflict", "replace")
	if res.code != 0 {
		t.Fatalf("cp to a new path: %+v", res)
	}
	var cpIn core.MoveInput
	_ = json.Unmarshal(f.body("POST /api/v1/nodes/copy"), &cpIn)
	if cpIn.Conflict != core.ConflictRename {
		t.Fatalf("copy body %+v", cpIn)
	}
	orig, cp := f.lookup(pics, "p2.jpg"), f.lookup(pics, "p2-copy.jpg")
	if orig == nil || orig.ID != p2.ID || cp == nil || cp.ID == p2.ID || !bytes.Equal(cp.data, p2.data) {
		t.Fatalf("cp: original %+v, copy %+v", orig, cp)
	}
	// --conflict skip does not skip a free NEW-PATH.
	res = f.run(t, "", "files", "cp", "/My files/Pics/p3.jpg", "/My files/Pics/p3-copy.jpg", "--conflict", "skip")
	if res.code != 0 || strings.Contains(res.stderr, "nothing was copied") || f.lookup(pics, "p3-copy.jpg") == nil {
		t.Fatalf("cp --conflict skip: %+v", res)
	}
}

// A change of case only is a rename: the destination resolves
// (case-insensitively) to the source itself, which the server accepts.
func TestFilesMvCaseOnlyRename(t *testing.T) {
	f := newFakeAPI(t)
	docs, report, _, _ := fakeTree(t, f)
	if res := f.run(t, "", "files", "mv", "/My files/Docs/Report.PDF", "/My files/Docs/report.pdf"); res.code != 0 {
		t.Fatalf("case-only rename: %+v", res)
	}
	if n := f.lookup(docs, "report.pdf"); n == nil || n.ID != report || n.Name != "report.pdf" {
		t.Fatalf("renamed file %+v", n)
	}
	if res := f.run(t, "", "files", "mv", "/My files/Docs", "/My files/docs"); res.code != 0 {
		t.Fatalf("case-only rename of a folder: %+v", res)
	}
	if n := f.lookup(f.myRoot(), "docs"); n == nil || n.ID != docs || n.Name != "docs" {
		t.Fatalf("renamed folder %+v", n)
	}
	if n := f.requestedPrefix("POST /api/v1/nodes/move"); n != 0 {
		t.Fatalf("a case-only rename must not call move (%d calls)", n)
	}
	// The very same name is not a rename; moving onto another file still fails.
	if res := f.run(t, "", "files", "mv", "/My files/docs/report.pdf", "/My files/docs/report.pdf"); res.code == 0 || !strings.Contains(res.stderr, "already named") {
		t.Fatalf("mv onto itself: %+v", res)
	}
	if res := f.run(t, "", "files", "mv", "/My files/docs/report.pdf", "/My files/Pics/p1.jpg"); res.code != ExitFailure || !strings.Contains(res.stderr, "already exists") {
		t.Fatalf("mv onto another file: %+v", res)
	}
	// cp keeps refusing: a copy cannot differ from the original by case only.
	if res := f.run(t, "", "files", "cp", "/My files/docs/report.pdf", "/My files/docs/REPORT.pdf"); res.code != ExitFailure || !strings.Contains(res.stderr, "already exists") {
		t.Fatalf("cp case-only: %+v", res)
	}
}

// --in narrows a search to a space; a folder would silently search its
// whole space, so it is refused.
func TestFilesSearchInSpaceOnly(t *testing.T) {
	f := newFakeAPI(t)
	_, report, _, _ := fakeTree(t, f)
	res := f.run(t, "", "files", "search", "p3", "--in", "/My files/Docs")
	if res.code != ExitUsage || !strings.Contains(res.stderr, "space") {
		t.Fatalf("--in a folder: %+v", res)
	}
	if res := f.run(t, "", "files", "search", "p3", "--in", report); res.code != ExitUsage {
		t.Fatalf("--in a file: %+v", res)
	}
	res = f.run(t, "", "files", "search", "p3", "--in", "/My files")
	if res.code != 0 || !strings.Contains(res.stdout, "/My files/Pics/p3.jpg") {
		t.Fatalf("--in a space: %+v", res)
	}
	if res := f.run(t, "", "files", "search", "logo", "--in", "/Team/Design"); res.code != 0 {
		t.Fatalf("--in a team folder: %+v", res)
	}
}

// The files help must not promise resumable uploads: every run starts a new
// batch, and an interrupted one is cancelled on the server.
func TestFilesHelpUploadNotResumable(t *testing.T) {
	if long := newFilesCmd().Long; strings.Contains(long, "resumable parts") || !strings.Contains(long, "retried on network errors") {
		t.Fatalf("files help: %q", long)
	}
	if long := newFilesPutCmd().Long; !strings.Contains(long, "starts over") {
		t.Fatalf("files put help: %q", long)
	}
}

func TestFilesVersions(t *testing.T) {
	f := newFakeAPI(t)
	id := f.addFile(f.myRoot(), "doc.txt", []byte("one"))
	f.mu.Lock()
	n := f.nodes[id]
	old := n.VersionID
	f.setContent(n, []byte("two!"))
	f.mu.Unlock()
	res := f.run(t, "", "files", "versions", "doc.txt")
	if res.code != 0 || !strings.Contains(res.stdout, old) || strings.Count(res.stdout, "ver_") != 2 {
		t.Fatalf("versions: %+v", res)
	}
	dir := t.TempDir()
	res = f.run(t, "", "files", "get", "doc.txt", filepath.Join(dir, "old.txt"), "--version", old)
	if res.code != 0 {
		t.Fatalf("get --version: %+v", res)
	}
	if b, _ := os.ReadFile(filepath.Join(dir, "old.txt")); string(b) != "one" {
		t.Fatalf("old version content %q", b)
	}
	if res := f.run(t, "", "files", "get", "doc.txt", "--version", "v1"); res.code != ExitUsage {
		t.Fatalf("bad version id: %+v", res)
	}
	if res := f.run(t, "", "files", "versions", "/My files"); res.code != ExitUsage {
		t.Fatalf("versions of a folder: %+v", res)
	}
}

// ---------- files put ----------

// writeTree creates files (path → size; size < 0 = directory) with random
// content under dir and returns the contents by path.
func writeTree(t *testing.T, dir string, spec map[string]int) map[string][]byte {
	t.Helper()
	rng := rand.New(rand.NewPCG(1, 2))
	out := map[string][]byte{}
	for p, size := range spec {
		full := filepath.Join(dir, filepath.FromSlash(p))
		if size < 0 {
			if err := os.MkdirAll(full, 0o755); err != nil {
				t.Fatal(err)
			}
			continue
		}
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		data := make([]byte, size)
		for i := range data {
			data[i] = byte(rng.IntN(256))
		}
		if err := os.WriteFile(full, data, 0o644); err != nil {
			t.Fatal(err)
		}
		out[p] = data
	}
	return out
}

func fastBackoff(t *testing.T) {
	t.Helper()
	old := transferBackoff
	transferBackoff = clikit.Backoff{Initial: time.Millisecond, Max: 2 * time.Millisecond, Attempts: 6}
	t.Cleanup(func() { transferBackoff = old })
}

func checkUploaded(t *testing.T, f *fakeAPI, root string, want map[string][]byte) {
	t.Helper()
	for p, data := range want {
		n := f.lookup(root, p)
		if n == nil {
			t.Fatalf("%s was not uploaded", p)
		}
		if !bytes.Equal(n.data, data) {
			t.Fatalf("%s: content differs (%d vs %d bytes)", p, len(n.data), len(data))
		}
	}
}

func TestFilesPutChunking(t *testing.T) {
	fastBackoff(t)
	f := newFakeAPI(t) // part size and small_max 64 KiB
	src := filepath.Join(t.TempDir(), "src")
	ps := int(f.partSize)
	want := writeTree(t, src, map[string]int{
		"a.txt": 0, "b.bin": 1, "c.bin": ps, "d.bin": ps + 1, "e.bin": 3*ps + 5,
		"nested/deep/f.txt": 10, "empty": -1, "nested/also-empty": -1,
	})
	res := f.run(t, "", "files", "put", src, "/My files")
	if res.code != 0 {
		t.Fatalf("put: %+v", res)
	}
	prefixed := map[string][]byte{}
	for p, d := range want {
		prefixed["src/"+p] = d
	}
	checkUploaded(t, f, f.myRoot(), prefixed)
	for _, d := range []string{"src/empty", "src/nested/also-empty"} {
		if n := f.lookup(f.myRoot(), d); n == nil || !n.IsDir() {
			t.Fatalf("empty dir %s missing", d)
		}
	}
	// a, b, c and f use the small path; d has 2 parts, e 4 parts.
	if n := f.requestedPrefix("PUT /api/v1/upload-batches/"); n != 4 {
		t.Fatalf("small PUTs: %d", n)
	}
	if n := f.requestedPrefix("PUT /api/v1/uploads/"); n != 6 {
		t.Fatalf("part PUTs: %d", n)
	}
	if n := f.requestedPrefix("POST /api/v1/uploads/"); n != 2 {
		t.Fatalf("file completes: %d", n)
	}
	var in core.BatchInput
	_ = json.Unmarshal(f.body("POST /api/v1/upload-batches"), &in)
	if in.Mode != core.UploadModeFiles || in.Conflict != core.ConflictRename || len(in.Files) != 8 {
		t.Fatalf("batch input %+v", in)
	}
	for _, fi := range in.Files {
		if fi.Kind == core.UploadKindFile && fi.MTime == 0 {
			t.Fatalf("%s: mtime not sent", fi.RelPath)
		}
	}
	if !strings.Contains(res.stdout, "uploaded 6 files") {
		t.Fatalf("summary: %q", res.stdout)
	}
}

func TestFilesPutRealPartSize(t *testing.T) {
	fastBackoff(t)
	f := newFakeAPI(t)
	f.partSize, f.smallMax = core.PartSize, core.PartSize
	dir := t.TempDir()
	want := writeTree(t, dir, map[string]int{"big.bin": 2*core.PartSize + 3})
	res := f.run(t, "", "files", "put", filepath.Join(dir, "big.bin"), "/My files")
	if res.code != 0 {
		t.Fatalf("put: %+v", res)
	}
	checkUploaded(t, f, f.myRoot(), want)
	if n := f.requestedPrefix("PUT /api/v1/uploads/"); n != 3 {
		t.Fatalf("parts: %d", n)
	}
	// The content hash the server would compute matches the local one.
	n := f.lookup(f.myRoot(), "big.bin")
	local, err := clikit.ContentHashFile(filepath.Join(dir, "big.bin"))
	if err != nil || local != n.ContentHash {
		t.Fatalf("content hash %s vs %s (%v)", local, n.ContentHash, err)
	}
}

func TestFilesPutRetryResumeAndChunkedDeclaration(t *testing.T) {
	fastBackoff(t)
	f := newFakeAPI(t)
	ps := int(f.partSize)
	src := filepath.Join(t.TempDir(), "up")
	spec := map[string]int{"big.bin": 4*ps + 7}
	for i := range 1005 {
		spec["dirs/d"+strings.Repeat("x", i%7)+"-"+strconv.Itoa(i)] = -1
	}
	want := writeTree(t, src, spec)
	big := want["big.bin"]
	// The fake reports parts 0 and 2 as already on the server, which the
	// protocol allows (DESIGN §8.1); this client itself starts a new batch
	// on every run, so only the fake produces this case.
	f.preDone = func(rel string) []int {
		if rel == "up/big.bin" {
			return []int{0, 2}
		}
		return nil
	}
	f.preData = func(rel string, n int) []byte { return big[n*ps : (n+1)*ps] }
	// Part 1 fails twice with 503 before it succeeds.
	var fails atomic.Int32
	f.partHook = func(upf string, n int) error {
		if n == 1 && fails.Add(1) <= 2 {
			return core.ErrUnavailable
		}
		return nil
	}
	res := f.run(t, "", "files", "put", src, "/My files", "--parallel", "2")
	if res.code != 0 {
		t.Fatalf("put: %+v", res)
	}
	checkUploaded(t, f, f.myRoot(), map[string][]byte{"up/big.bin": big})
	f.mu.Lock()
	var got []string
	for k, v := range f.partPuts {
		got = append(got, k[strings.LastIndex(k, "/")+1:]+"="+strconv.Itoa(v))
	}
	f.mu.Unlock()
	joined := "," + strings.Join(got, ",") + ","
	for _, want := range []string{",1=3,", ",3=1,", ",4=1,"} {
		if !strings.Contains(joined, want) {
			t.Fatalf("part PUT counts %v lack %s", got, want)
		}
	}
	if strings.Contains(joined, ",0=") || strings.Contains(joined, ",2=") {
		t.Fatalf("parts already on the server were sent again: %v", got)
	}
	// 1006 entries: 1000 in the create request, the rest added in a chunk.
	if n := f.requestedPrefix("POST /api/v1/upload-batches/"); n < 2 { // /files + /complete
		t.Fatalf("declaration chunks: %d", n)
	}
	if f.lookup(f.myRoot(), "up/dirs") == nil {
		t.Fatal("dirs not created")
	}
}

func TestFilesPutAbortsOnPermanentError(t *testing.T) {
	fastBackoff(t)
	f := newFakeAPI(t)
	dir := t.TempDir()
	writeTree(t, dir, map[string]int{"big.bin": 3 * int(f.partSize)})
	var calls atomic.Int32
	f.partHook = func(string, int) error {
		calls.Add(1)
		return core.ErrQuota
	}
	res := f.run(t, "", "files", "put", filepath.Join(dir, "big.bin"), "/My files")
	if res.code != ExitFailure || !strings.Contains(res.stderr, "quota") || !strings.Contains(res.stderr, "hint:") {
		t.Fatalf("put: %+v", res)
	}
	if n := calls.Load(); n > 3 {
		t.Fatalf("quota errors must not be retried (%d calls)", n)
	}
	f.mu.Lock()
	aborted := len(f.aborted)
	f.mu.Unlock()
	if aborted != 1 {
		t.Fatalf("batch not aborted (%d)", aborted)
	}
}

func TestFilesPutLocalFileChanges(t *testing.T) {
	fastBackoff(t)
	f := newFakeAPI(t)
	f.parallel = 1
	dir := t.TempDir()
	p := filepath.Join(dir, "grow.bin")
	writeTree(t, dir, map[string]int{"grow.bin": 3 * int(f.partSize)})
	f.partHook = func(_ string, n int) error {
		if n == 0 {
			fh, err := os.OpenFile(p, os.O_APPEND|os.O_WRONLY, 0)
			if err == nil {
				fh.Write([]byte("more"))
				fh.Close()
			}
		}
		return nil
	}
	res := f.run(t, "", "files", "put", p, "/My files", "--parallel", "1")
	if res.code != ExitFailure || !strings.Contains(res.stderr, "changed while it was being uploaded") {
		t.Fatalf("put: %+v", res)
	}
}

func TestFilesPutZip(t *testing.T) {
	fastBackoff(t)
	f := newFakeAPI(t)
	f.zipJobStates = []string{core.JobRunning, core.JobRunning, core.JobSucceeded}
	src := filepath.Join(t.TempDir(), "photos")
	writeTree(t, src, map[string]int{"a.jpg": 10, "b/c.jpg": 2*int(f.partSize) + 1})
	res := f.run(t, "", "files", "put", src, "/My files", "--zip", "bundle")
	if res.code != 0 {
		t.Fatalf("put --zip: %+v", res)
	}
	var in core.BatchInput
	_ = json.Unmarshal(f.body("POST /api/v1/upload-batches"), &in)
	if in.Mode != core.UploadModeZip || in.ZipName != "bundle.zip" {
		t.Fatalf("batch input %+v", in)
	}
	if n := f.lookup(f.myRoot(), "bundle.zip"); n == nil {
		t.Fatal("zip not created")
	}
	if f.requestedPrefix("GET /api/v1/jobs/") < 3 {
		t.Fatal("the zip job was not polled to the end")
	}
	if !strings.Contains(res.stdout, "as bundle.zip") {
		t.Fatalf("summary %q", res.stdout)
	}
	// The summary names what the server stored: under rename (the default) a
	// second zip of the same name is "bundle (1).zip"; under skip nothing is
	// stored, which must not read as a success.
	res = f.run(t, "", "files", "put", src, "/My files", "--zip", "bundle")
	if res.code != 0 || !strings.Contains(res.stdout, "as bundle (1).zip") || f.lookup(f.myRoot(), "bundle (1).zip") == nil {
		t.Fatalf("put --zip, name taken: %+v", res)
	}
	res = f.run(t, "", "files", "put", src, "/My files", "--zip", "bundle", "--conflict", "skip")
	if res.code != 0 || strings.Contains(res.stdout, "uploaded") || !strings.Contains(res.stderr, "not stored") {
		t.Fatalf("put --zip --conflict skip: %+v", res)
	}
	if f.lookup(f.myRoot(), "bundle (2).zip") != nil {
		t.Fatal("--conflict skip stored a zip")
	}

	// A failing zip job is an error.
	f.zipJobStates = []string{core.JobFailed}
	res = f.run(t, "", "files", "put", src, "/My files", "--zip", "again.zip")
	if res.code != ExitFailure || !strings.Contains(res.stderr, "failed") {
		t.Fatalf("failing zip job: %+v", res)
	}
	if res := f.run(t, "", "files", "put", src, "/My files", "--zip", "bad/name"); res.code != ExitUsage {
		t.Fatalf("bad zip name: %+v", res)
	}
}

func TestFilesPutDestinations(t *testing.T) {
	fastBackoff(t)
	f := newFakeAPI(t)
	docs, _, _, _ := fakeTree(t, f)
	dir := t.TempDir()
	want := writeTree(t, dir, map[string]int{"local.txt": 20, "other.txt": 5})
	lp := filepath.Join(dir, "local.txt")

	// Single file under a new name.
	if res := f.run(t, "", "files", "put", lp, "/My files/Docs/renamed.txt"); res.code != 0 {
		t.Fatalf("put rename: %+v", res)
	}
	checkUploaded(t, f, docs, map[string][]byte{"renamed.txt": want["local.txt"]})
	// A single file with -p means "the destination is a folder", not a new
	// name: the folder is created and the file lands inside it.
	if res := f.run(t, "", "files", "put", lp, "/My files/Docs/NewFolder", "-p"); res.code != 0 {
		t.Fatalf("put single file -p: %+v", res)
	}
	if n := f.lookup(docs, "NewFolder"); n == nil || !n.IsDir() {
		t.Fatalf("-p must create the folder NewFolder, got %+v", n)
	}
	checkUploaded(t, f, docs, map[string][]byte{"NewFolder/local.txt": want["local.txt"]})
	// Missing destination without -p fails with a hint; with -p it is created.
	if res := f.run(t, "", "files", "put", lp, filepath.Join(dir, "other.txt"), "/My files/New/Sub"); res.code != ExitFailure || !strings.Contains(res.stderr, "--parents") {
		t.Fatalf("put missing dest: %+v", res)
	}
	if res := f.run(t, "", "files", "put", lp, filepath.Join(dir, "other.txt"), "/My files/New/Sub", "-p"); res.code != 0 {
		t.Fatalf("put -p: %+v", res)
	}
	checkUploaded(t, f, f.myRoot(), map[string][]byte{"New/Sub/local.txt": want["local.txt"], "New/Sub/other.txt": want["other.txt"]})
	// Conflicts: rename (default), replace (new version), skip.
	if res := f.run(t, "", "files", "put", lp, "/My files/New/Sub"); res.code != 0 || f.lookup(f.myRoot(), "New/Sub/local (1).txt") == nil {
		t.Fatalf("put conflict rename: %+v", res)
	}
	if res := f.run(t, "", "files", "put", lp, "/My files/New/Sub", "--conflict", "replace"); res.code != 0 {
		t.Fatalf("put replace: %+v", res)
	}
	if n := f.lookup(f.myRoot(), "New/Sub/local.txt"); len(n.versions) != 2 {
		t.Fatalf("replace must add a version (%d)", len(n.versions))
	}
	puts := f.requestedPrefix("PUT ")
	res := f.run(t, "", "files", "put", lp, "/My files/New/Sub", "--conflict", "skip")
	if res.code != 0 || !strings.Contains(res.stderr, "skipped") {
		t.Fatalf("put skip: %+v", res)
	}
	// Declared skipped by the server: nothing sent, and the summary counts no bytes.
	if n := f.requestedPrefix("PUT ") - puts; n != 0 || !strings.Contains(res.stdout, "uploaded 0 files (0 B)") {
		t.Fatalf("put skip sent %d requests: %+v", n, res)
	}
	// Usage errors.
	for _, args := range [][]string{
		{"files", "put", lp},
		{"files", "put", lp, "/My files", "--conflict", "merge"},
		{"files", "put", lp, "/My files", "--parallel", "99"},
	} {
		if res := f.run(t, "", args...); res.code != ExitUsage {
			t.Fatalf("%v: %+v", args, res)
		}
	}
	if res := f.run(t, "", "files", "put", filepath.Join(dir, "nope"), "/My files"); res.code != ExitFailure || !strings.Contains(res.stderr, "no such file") {
		t.Fatalf("missing source: %+v", res)
	}
	if res := f.run(t, "", "files", "put", lp, "/My files/Docs/Report.PDF"); res.code != ExitFailure || !strings.Contains(res.stderr, "already exists") {
		t.Fatalf("put onto a file: %+v", res)
	}
}

func TestScanLocal(t *testing.T) {
	dir := t.TempDir()
	writeTree(t, dir, map[string]int{"a/x.txt": 3, "a/empty": -1, "a/full/y": 1, "b.txt": 2})
	if err := os.Symlink(filepath.Join(dir, "b.txt"), filepath.Join(dir, "a", "link")); err != nil {
		t.Skip("symlinks unsupported")
	}
	var warnings []string
	entries, err := scanLocal([]string{filepath.Join(dir, "a"), filepath.Join(dir, "b.txt")}, "", func(format string, a ...any) {
		warnings = append(warnings, format)
	})
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, e := range entries {
		got[e.Rel] = e.Kind
	}
	want := map[string]string{"a/x.txt": "file", "a/empty": "dir", "a/full/y": "file", "b.txt": "file"}
	if len(got) != len(want) {
		t.Fatalf("entries %v", got)
	}
	for k, v := range want {
		if got[k] != v {
			t.Fatalf("entries %v, want %v", got, want)
		}
	}
	if len(warnings) != 1 || !strings.Contains(warnings[0], "symbolic link") {
		t.Fatalf("warnings %v", warnings)
	}
	// A symlinked directory named as a source is followed (WalkDir alone
	// would not descend into it) and uploaded under the link's name, also
	// with a new name, and as "." when the working directory was entered
	// through the link. Symlinks inside it are still skipped.
	alias := filepath.Join(t.TempDir(), "alias")
	if err := os.Symlink(filepath.Join(dir, "a"), alias); err != nil {
		t.Fatal(err)
	}
	wantAlias := map[string]string{"alias/x.txt": "file", "alias/empty": "dir", "alias/full/y": "file"}
	check := func(what string, srcs []string, rename string, want map[string]string) {
		t.Helper()
		var warnings []string
		entries, err := scanLocal(srcs, rename, func(format string, a ...any) {
			warnings = append(warnings, fmt.Sprintf(format, a...))
		})
		if err != nil {
			t.Fatalf("%s: %v", what, err)
		}
		got := map[string]string{}
		for _, e := range entries {
			got[e.Rel] = e.Kind
		}
		if !maps.Equal(got, want) {
			t.Fatalf("%s: entries %v, want %v", what, got, want)
		}
		if len(warnings) != 1 || !strings.Contains(warnings[0], "symbolic link") || !strings.HasSuffix(warnings[0], filepath.Join("alias", "link")) {
			t.Fatalf("%s: warnings %v", what, warnings)
		}
	}
	check("symlinked directory", []string{alias}, "", wantAlias)
	check("symlinked directory with a slash", []string{alias + string(filepath.Separator)}, "", wantAlias)
	check("renamed symlinked directory", []string{alias}, "Renamed", map[string]string{"Renamed/x.txt": "file", "Renamed/empty": "dir", "Renamed/full/y": "file"})
	t.Chdir(alias) // also sets $PWD to the link, so filepath.Abs(".") is the link
	check(`"." through a symlink`, []string{"."}, "", wantAlias)
	// Duplicate top-level names are rejected.
	other := filepath.Join(t.TempDir(), "b.txt")
	os.WriteFile(other, []byte("x"), 0o644)
	if _, err := scanLocal([]string{filepath.Join(dir, "b.txt"), other}, "", func(string, ...any) {}); err == nil {
		t.Fatal("duplicate names accepted")
	}
	// Rename of a single source.
	entries, err = scanLocal([]string{filepath.Join(dir, "b.txt")}, "c.txt", func(string, ...any) {})
	if err != nil || len(entries) != 1 || entries[0].Rel != "c.txt" {
		t.Fatalf("rename: %v %+v", err, entries)
	}
}

func TestZipNameAndConflict(t *testing.T) {
	for in, want := range map[string]string{"a": "a.zip", "b.zip": "b.zip", " C.ZIP ": "C.ZIP", "my photos": "my photos.zip"} {
		if got, err := zipName(in); err != nil || got != want {
			t.Errorf("zipName(%q) = %q, %v", in, got, err)
		}
	}
	for _, bad := range []string{"", "  ", "a/b", "bad\x00name"} {
		if _, err := zipName(bad); err == nil {
			t.Errorf("zipName(%q) accepted", bad)
		}
	}
	for _, ok := range []string{"rename", "REPLACE", " skip ", "fail"} {
		if _, err := parseConflict(ok); err != nil {
			t.Errorf("parseConflict(%q): %v", ok, err)
		}
	}
	if _, err := parseConflict("merge"); err == nil {
		t.Error("parseConflict(merge) accepted")
	}
	if partLen(10, 4, 0) != 4 || partLen(10, 4, 2) != 2 || partLen(8, 4, 1) != 4 {
		t.Error("partLen")
	}
}

// ---------- files get ----------

func TestFilesGetResumeAndVerify(t *testing.T) {
	fastBackoff(t)
	f := newFakeAPI(t)
	data := bytes.Repeat([]byte("0123456789abcdef"), 12800) // 200 KiB
	id := f.addFile(f.myRoot(), "big.bin", data)
	dir := t.TempDir()
	dest := filepath.Join(dir, "big.bin")
	f.mu.Lock()
	ver := f.nodes[id].VersionID
	f.mu.Unlock()

	// A partial download from an earlier attempt of this very node and
	// version (its record says so) is resumed with Range + If-Range.
	seedPartial(t, dest, data[:70000], id+" "+ver)
	res := f.run(t, "", "files", "get", "/My files/big.bin", dir)
	if res.code != 0 || !strings.Contains(res.stdout, "resumed at") || !strings.Contains(res.stdout, "verified") {
		t.Fatalf("get resume: %+v", res)
	}
	if got, _ := os.ReadFile(dest); !bytes.Equal(got, data) {
		t.Fatal("resumed content differs")
	}
	if fileExists(dest+partialSuffix) || fileExists(dest+partialSuffix+partialVersionSuffix) {
		t.Fatal("partial file left behind")
	}
	f.mu.Lock()
	ranges := strings.Join(f.rangeHeaders, ";")
	f.mu.Unlock()
	if ranges != `bytes=70000-|"`+ver+`"` {
		t.Fatalf("range headers %q", ranges)
	}

	// Existing destination: refused without --force.
	res = f.run(t, "", "files", "get", id, dest)
	if res.code != ExitFailure || !strings.Contains(res.stderr, "--force") {
		t.Fatalf("get existing: %+v", res)
	}
	// A corrupt partial file (wrong bytes) fails the content-hash check and is
	// removed; the next run starts over and succeeds.
	os.Remove(dest)
	bad := bytes.Clone(data[:50000])
	bad[100] ^= 0xff
	seedPartial(t, dest, bad, id+" "+ver)
	res = f.run(t, "", "files", "get", id, dest)
	if res.code != ExitFailure || !strings.Contains(res.stderr, "content hash") {
		t.Fatalf("corrupt partial: %+v", res)
	}
	if fileExists(dest+partialSuffix) || fileExists(dest+partialSuffix+partialVersionSuffix) || fileExists(dest) {
		t.Fatal("corrupt data kept")
	}
	res = f.run(t, "", "--json", "files", "get", id, dest)
	if res.code != 0 {
		t.Fatalf("get again: %+v", res)
	}
	var gr getResult
	if err := json.Unmarshal([]byte(res.stdout), &gr); err != nil || !gr.Verified || gr.Bytes != int64(len(data)) || gr.Resumed != 0 {
		t.Fatalf("json result %v %s", err, res.stdout)
	}
	// --no-resume discards a partial file.
	os.Remove(dest)
	seedPartial(t, dest, []byte("junk"), id+" "+ver)
	if res := f.run(t, "", "files", "get", id, dest, "--no-resume"); res.code != 0 || strings.Contains(res.stdout, "resumed at") {
		t.Fatalf("get --no-resume: %+v", res)
	}
	// Standard output.
	res = f.run(t, "", "files", "get", "big.bin", "-")
	if res.code != 0 || res.stdout != string(data) {
		t.Fatalf("get to stdout: code %d, %d bytes", res.code, len(res.stdout))
	}
	// -o and a positional destination together are a usage error.
	if res := f.run(t, "", "files", "get", id, dest, "-o", dest); res.code != ExitUsage {
		t.Fatalf("both destinations: %+v", res)
	}
}

// seedPartial leaves a partial download of dest holding data, with a version
// record naming source ("<node id> <version id>"), or without one when
// source is "" (as an older client left it).
func seedPartial(t *testing.T, dest string, data []byte, source string) {
	t.Helper()
	part := partialPath(dest)
	if err := os.WriteFile(part, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if source == "" {
		_ = os.Remove(part + partialVersionSuffix)
		return
	}
	if err := os.WriteFile(part+partialVersionSuffix, []byte(source+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
}

// A partial file is continued only when its record names the node and
// version being downloaded: If-Range carries the version resolved in this
// run, so it cannot tell that the bytes came from an older one (the file was
// replaced in between), another file of the same name or an older client.
func TestFilesGetResumesOnlyTheSameVersion(t *testing.T) {
	fastBackoff(t)
	f := newFakeAPI(t)
	a, b := bytes.Repeat([]byte("A"), 150000), bytes.Repeat([]byte("B"), 150000)
	id := f.addFile(f.myRoot(), "big.bin", a)
	f.mu.Lock()
	verA := f.nodes[id].VersionID
	f.setContent(f.nodes[id], b)
	verB := f.nodes[id].VersionID
	f.mu.Unlock()
	ranges := func() int {
		f.mu.Lock()
		defer f.mu.Unlock()
		return len(f.rangeHeaders)
	}
	dir := t.TempDir()
	dest := filepath.Join(dir, "big.bin")
	get := func(what string, resumed bool, want []byte, args ...string) {
		t.Helper()
		n := ranges()
		res := f.run(t, "", append([]string{"files", "get"}, args...)...)
		if res.code != 0 || strings.Contains(res.stdout, "resumed at") != resumed || (ranges() > n) != resumed {
			t.Fatalf("%s: %+v (range requests %d → %d)", what, res, n, ranges())
		}
		if got, _ := os.ReadFile(dest); !bytes.Equal(got, want) {
			t.Fatalf("%s: wrong content", what)
		}
		if fileExists(dest+partialSuffix) || fileExists(dest+partialSuffix+partialVersionSuffix) {
			t.Fatalf("%s: partial file left behind", what)
		}
		os.Remove(dest)
	}
	seedPartial(t, dest, a[:100000], id+" "+verA)
	get("replaced since", false, b, "/My files/big.bin", dir)
	seedPartial(t, dest, b[:100000], "")
	get("no record", false, b, "/My files/big.bin", dir)
	seedPartial(t, dest, b[:100000], "nod_01jaaaaaaaaaaaaaaaaaaaaaaa "+verB)
	get("another node", false, b, "/My files/big.bin", dir)
	seedPartial(t, dest, b[:100000], id+" "+verB)
	get("--version of another version", false, a, id, dest, "--version", verA)
	seedPartial(t, dest, a[:100000], id+" "+verA)
	get("--version of the same version", true, a, id, dest, "--version", verA)
	seedPartial(t, dest, b[:100000], id+" "+verB)
	get("same version", true, b, id, dest)
}

// Only a private regular file of ours next to the destination is continued:
// a symlink or hard link planted there (in a shared directory) must never
// receive the download, and the destination must end up a regular file.
func TestFilesGetIgnoresPlantedPartial(t *testing.T) {
	fastBackoff(t)
	f := newFakeAPI(t)
	data := bytes.Repeat([]byte("0123456789abcdef"), 4096) // 64 KiB
	id := f.addFile(f.myRoot(), "report.bin", data)
	f.mu.Lock()
	source := id + " " + f.nodes[id].VersionID
	f.mu.Unlock()
	dir, other := t.TempDir(), t.TempDir()
	dest := filepath.Join(dir, "report.bin")
	part := partialPath(dest)
	if err := os.Symlink(filepath.Join(other, "probe"), part); err != nil {
		t.Skip("symlinks unsupported")
	}
	os.Remove(part)
	get := func(what string) {
		t.Helper()
		res := f.run(t, "", "files", "get", "/My files/report.bin", dir)
		if res.code != 0 || strings.Contains(res.stdout, "resumed at") {
			t.Fatalf("%s: %+v", what, res)
		}
		if fi, err := os.Lstat(dest); err != nil || !fi.Mode().IsRegular() {
			t.Fatalf("%s: destination %v %v", what, fi, err)
		}
		if got, _ := os.ReadFile(dest); !bytes.Equal(got, data) {
			t.Fatalf("%s: wrong content", what)
		}
		for _, p := range []string{part, part + partialVersionSuffix} {
			if _, err := os.Lstat(p); err == nil {
				t.Fatalf("%s: %s left behind", what, p)
			}
		}
		os.Remove(dest)
	}
	small, large := []byte("my precious notes\n"), bytes.Repeat([]byte("L"), len(data)+100)
	for _, tc := range []struct {
		name   string
		victim []byte
	}{{"dangling", nil}, {"smaller", small}, {"larger", large}} {
		victim := filepath.Join(other, tc.name)
		if tc.victim != nil {
			os.WriteFile(victim, tc.victim, 0o600)
		}
		if err := os.Symlink(victim, part); err != nil {
			t.Fatal(err)
		}
		// A matching record does not make the link a partial file of ours.
		os.WriteFile(part+partialVersionSuffix, []byte(source+"\n"), 0o600)
		get("symlink, " + tc.name)
		got, err := os.ReadFile(victim)
		if tc.victim == nil && !errors.Is(err, os.ErrNotExist) || tc.victim != nil && !bytes.Equal(got, tc.victim) {
			t.Fatalf("symlink, %s: the target was written (%q, %v)", tc.name, got, err)
		}
	}
	// A symlinked version record is removed, not followed.
	record := filepath.Join(other, "record")
	os.WriteFile(record, []byte("keep"), 0o600)
	if err := os.Symlink(record, part+partialVersionSuffix); err != nil {
		t.Fatal(err)
	}
	get("symlinked record")
	if got, _ := os.ReadFile(record); string(got) != "keep" {
		t.Fatalf("symlinked record: the target was written (%q)", got)
	}
	// A hard link to another file is not continued either.
	hard := filepath.Join(other, "hard")
	os.WriteFile(hard, small, 0o600)
	if err := os.Link(hard, part); err == nil {
		os.WriteFile(part+partialVersionSuffix, []byte(source+"\n"), 0o600)
		get("hard link")
		if got, _ := os.ReadFile(hard); !bytes.Equal(got, small) {
			t.Fatalf("hard link: the other file was written (%q)", got)
		}
	}
	// Nor is an archive's partial file.
	folder := f.addFolder(f.myRoot(), "Docs")
	zdest := filepath.Join(dir, "Docs.zip")
	zvictim := filepath.Join(other, "zvictim")
	os.WriteFile(zvictim, small, 0o600)
	if err := os.Symlink(zvictim, partialPath(zdest)); err != nil {
		t.Fatal(err)
	}
	if res := f.run(t, "", "files", "get", "/My files/Docs", dir); res.code != 0 {
		t.Fatalf("archive: %+v", res)
	}
	if got, _ := os.ReadFile(zvictim); !bytes.Equal(got, small) {
		t.Fatalf("archive: the target was written (%q)", got)
	}
	if fi, err := os.Lstat(zdest); err != nil || !fi.Mode().IsRegular() {
		t.Fatalf("archive destination %v %v", fi, err)
	}
	if got, _ := os.ReadFile(zdest); string(got) != "ARCHIVE zip Docs "+folder {
		t.Fatalf("archive content %q", got)
	}
}

// A remote file called "-" is saved as ./-: only "-" given as the local
// argument means standard output.
func TestFilesGetRemoteDash(t *testing.T) {
	fastBackoff(t)
	f := newFakeAPI(t)
	f.addFile(f.myRoot(), "-", []byte("DASH-CONTENT"))
	dir := t.TempDir()
	t.Chdir(dir)
	for _, args := range [][]string{{"files", "get", "/My files/-"}, {"files", "get", "/My files/-", ".", "--force"}} {
		res := f.run(t, "", args...)
		if res.code != 0 || strings.Contains(res.stdout, "DASH-CONTENT") {
			t.Fatalf("%v: %+v", args, res)
		}
		if got, err := os.ReadFile(filepath.Join(dir, "-")); err != nil || string(got) != "DASH-CONTENT" {
			t.Fatalf("%v: local file %q %v", args, got, err)
		}
		if fileExists(filepath.Join(dir, "-"+partialSuffix)) {
			t.Fatalf("%v: partial file left behind", args)
		}
	}
	if res := f.run(t, "", "files", "get", "/My files/-", "-"); res.code != 0 || res.stdout != "DASH-CONTENT" {
		t.Fatalf("to standard output: %+v", res)
	}
}

// Names may take all of names.MaxNameBytes; the partial file (and its
// version record) and an archive's extension must still fit in a file name.
func TestPartialPath(t *testing.T) {
	dir := t.TempDir()
	for _, n := range []int{1, 200, names.MaxNameBytes - len(partialSuffix) - len(partialVersionSuffix)} {
		dest := filepath.Join(dir, strings.Repeat("x", n))
		if got := partialPath(dest); got != dest+partialSuffix {
			t.Errorf("partialPath(%d bytes) = %q", n, got)
		}
	}
	long1, long2 := strings.Repeat("中", 84), strings.Repeat("中", 83)+"文" // 252 bytes each
	seen := map[string]bool{}
	for _, name := range []string{long1, long2, strings.Repeat("x", 246), strings.Repeat("x", 255)} {
		dest := filepath.Join(dir, name)
		p := partialPath(dest)
		base := filepath.Base(p)
		if filepath.Dir(p) != dir || !strings.HasSuffix(base, partialSuffix) || len(base)+len(partialVersionSuffix) > names.MaxNameBytes ||
			!utf8.ValidString(base) || p != partialPath(dest) || seen[p] {
			t.Errorf("partialPath(%d bytes) = %q", len(name), p)
		}
		seen[p] = true
	}
}

func TestFilesGetLongNames(t *testing.T) {
	fastBackoff(t)
	f := newFakeAPI(t)
	data := bytes.Repeat([]byte("0123456789abcdef"), 8192) // 128 KiB
	name := strings.Repeat("中", 84)                        // 252 bytes: valid, but "<name>.fpart" is not
	id := f.addFile(f.myRoot(), name, data)
	f.mu.Lock()
	source := id + " " + f.nodes[id].VersionID
	f.mu.Unlock()
	dir := t.TempDir()
	dest := filepath.Join(dir, name)
	if res := f.run(t, "", "files", "get", "/My files/"+name, dir); res.code != 0 {
		t.Fatalf("get: %+v", res)
	}
	if got, _ := os.ReadFile(dest); !bytes.Equal(got, data) {
		t.Fatal("wrong content")
	}
	os.Remove(dest)
	seedPartial(t, dest, data[:50000], source)
	if res := f.run(t, "", "files", "get", "/My files/"+name, dir); res.code != 0 || !strings.Contains(res.stdout, "resumed at") {
		t.Fatalf("resume: %+v", res)
	}
	if got, _ := os.ReadFile(dest); !bytes.Equal(got, data) {
		t.Fatal("wrong resumed content")
	}
	// A folder name of 255 bytes: the archive is named after it, shortened so
	// that ".zip" fits; the server still gets the full name.
	folder := strings.Repeat("中", 85)
	fid := f.addFolder(f.myRoot(), folder)
	if res := f.run(t, "", "files", "get", "/My files/"+folder, dir); res.code != 0 {
		t.Fatalf("get folder: %+v", res)
	}
	ents, _ := os.ReadDir(dir)
	var zips []string
	for _, e := range ents {
		switch n := e.Name(); {
		case strings.HasSuffix(n, partialSuffix) || strings.HasSuffix(n, partialVersionSuffix):
			t.Fatalf("partial file left behind: %q", n)
		case strings.HasSuffix(n, ".zip"):
			zips = append(zips, n)
		}
	}
	if len(zips) != 1 || len(zips[0]) > names.MaxNameBytes || !strings.HasPrefix(zips[0], strings.Repeat("中", 80)) {
		t.Fatalf("archive files %q", zips)
	}
	if got, _ := os.ReadFile(filepath.Join(dir, zips[0])); string(got) != "ARCHIVE zip "+folder+" "+fid {
		t.Fatalf("archive content %q", got)
	}
}

func TestFilesGetArchive(t *testing.T) {
	f := newFakeAPI(t)
	docs, report, _, _ := fakeTree(t, f)
	dir := t.TempDir()
	res := f.run(t, "", "files", "get", "/My files/Docs", dir)
	if res.code != 0 {
		t.Fatalf("get folder: %+v", res)
	}
	got, err := os.ReadFile(filepath.Join(dir, "Docs.zip"))
	if err != nil || string(got) != "ARCHIVE zip Docs "+docs {
		t.Fatalf("zip %q %v", got, err)
	}
	res = f.run(t, "", "files", "get", "/My files/Docs/Report.PDF", "--tar", "-o", filepath.Join(dir, "r.tar"))
	if res.code != 0 {
		t.Fatalf("get --tar: %+v", res)
	}
	if got, _ := os.ReadFile(filepath.Join(dir, "r.tar")); string(got) != "ARCHIVE tar Report.PDF "+report {
		t.Fatalf("tar %q", got)
	}
	if res := f.run(t, "", "files", "get", "/My files/Docs", "--zip", "--tar"); res.code != ExitUsage {
		t.Fatalf("--zip --tar: %+v", res)
	}
	if res := f.run(t, "", "files", "get", "/My files/Docs", dir); res.code != ExitFailure {
		t.Fatalf("existing archive must not be overwritten: %+v", res)
	}
}

func TestLocalDestAndContentRange(t *testing.T) {
	dir := t.TempDir()
	for _, tc := range []struct{ dest, name, want string }{
		{"", "a.txt", "a.txt"},
		{"-", "a.txt", "-"},
		{dir, "a.txt", filepath.Join(dir, "a.txt")},
		// Only a "-" given as the destination means standard output.
		{"", "-", "." + string(filepath.Separator) + "-"},
		{".", "-", "." + string(filepath.Separator) + "-"},
		{"." + string(filepath.Separator), "-", "." + string(filepath.Separator) + "-"},
		{dir, "-", filepath.Join(dir, "-")},
		{filepath.Join(dir, "b.txt"), "a.txt", filepath.Join(dir, "b.txt")},
	} {
		if got, err := localDest(tc.dest, tc.name); err != nil || got != tc.want {
			t.Errorf("localDest(%q, %q) = %q, %v", tc.dest, tc.name, got, err)
		}
	}
	for _, bad := range []string{"../x", "a/b", `a\b`, "..", ""} {
		if _, err := localDest("", bad); err == nil {
			t.Errorf("unsafe remote name %q accepted", bad)
		}
	}
	if _, err := localDest(filepath.Join(dir, "missing")+"/", "a"); err == nil {
		t.Error("missing directory accepted")
	}
	for in, want := range map[string]int64{"bytes 100-199/200": 100, " bytes 0-0/1": 0} {
		if got, err := contentRangeStart(in); err != nil || got != want {
			t.Errorf("contentRangeStart(%q) = %d, %v", in, got, err)
		}
	}
	for _, bad := range []string{"", "items 1-2/3", "bytes x-1/2", "bytes 12"} {
		if _, err := contentRangeStart(bad); err == nil {
			t.Errorf("contentRangeStart(%q) accepted", bad)
		}
	}
}
