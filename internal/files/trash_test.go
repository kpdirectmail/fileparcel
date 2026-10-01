package files

import (
	"context"
	"errors"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"fileparcel/internal/core"
)

func nodeNames(list []core.Node) []string {
	out := make([]string, len(list))
	for i, n := range list {
		out[i] = n.Name
	}
	return out
}

func (e *testEnv) children(p *user, folder string) []string {
	e.t.Helper()
	page, err := e.svc.List(e.ctx, p.Principal, folder, core.ListQuery{})
	if err != nil {
		e.t.Fatalf("list: %v", err)
	}
	return nodeNames(page.Items)
}

func (e *testEnv) trashed(p *user) []string {
	e.t.Helper()
	page, err := e.svc.ListTrash(e.ctx, p.Principal, core.ListQuery{})
	if err != nil {
		e.t.Fatalf("list trash: %v", err)
	}
	return nodeNames(page.Items)
}

func TestTrashRestorePurge(t *testing.T) {
	e := newEnv(t)
	u := e.user("alice", core.RoleMember)
	a := e.mkdir(u, u.rootID, "A")
	f := e.file(u, a.ID, "f.txt", "12345")
	s := e.mkdir(u, a.ID, "S")
	g := e.file(u, s.ID, "g.txt", "1234567")
	if e.used(u.spaceID) != 12 {
		t.Fatalf("used %d", e.used(u.spaceID))
	}

	// The root cannot be trashed; unknown ids are 404; empty lists 422.
	wantCode(t, e.svc.Trash(e.ctx, u.Principal, []string{u.rootID}), "forbidden")
	wantCode(t, e.svc.Trash(e.ctx, u.Principal, []string{"nod_00000000000000000000000000"}), "not_found")
	wantCode(t, e.svc.Trash(e.ctx, u.Principal, nil), "invalid")

	// Trash S first (a nested trash root), then A.
	if err := e.svc.Trash(e.ctx, u.Principal, []string{s.ID}); err != nil {
		t.Fatal(err)
	}
	e.clock.Advance(time.Minute)
	if err := e.svc.Trash(e.ctx, u.Principal, []string{a.ID, a.ID}); err != nil {
		t.Fatal(err)
	}
	// Trashing again is a no-op.
	if err := e.svc.Trash(e.ctx, u.Principal, []string{a.ID}); err != nil {
		t.Fatal(err)
	}
	if got := e.trashed(u); !slices.Equal(got, []string{"A", "S"}) { // newest first
		t.Fatalf("trash = %v", got)
	}
	if got := e.children(u, u.rootID); len(got) != 0 {
		t.Fatalf("root still lists %v", got)
	}
	// Trashed nodes are 404 for normal operations but visible with Get.
	if _, err := e.svc.Authorize(e.ctx, u.Principal, f.ID, core.PermView); code(err) != "not_found" {
		t.Fatalf("authorize trashed: %v", err)
	}
	if n, err := e.svc.Get(e.ctx, u.Principal, f.ID); err != nil || n.TrashedAt == nil || n.TrashRoot {
		t.Fatalf("get trashed child: %+v %v", n, err)
	}
	if _, err := e.svc.Mkdir(e.ctx, u.Principal, a.ID, "x"); code(err) != "not_found" {
		t.Fatalf("mkdir in trash: %v", err)
	}
	// The children of a trashed folder are the items trashed with it.
	page, err := e.svc.List(e.ctx, u.Principal, a.ID, core.ListQuery{})
	if err != nil || !slices.Equal(nodeNames(page.Items), []string{"f.txt"}) {
		t.Fatalf("list trashed folder: %v %v", nodeNames(page.Items), err)
	}
	// The trash keeps the original location in Path.
	tp, _ := e.svc.ListTrash(e.ctx, u.Principal, core.ListQuery{})
	for _, n := range tp.Items {
		if n.Name == "S" && n.Path != "/A/S" {
			t.Fatalf("trash path %q", n.Path)
		}
	}
	// Usage counts the trash.
	us, err := e.svc.Usage(e.ctx, u.UserID)
	if err != nil || us.UsedBytes != 12 || us.TrashBytes != 12 {
		t.Fatalf("usage %+v %v", us, err)
	}

	// A new live "A" takes the name; restoring the old one renames it.
	e.mkdir(u, u.rootID, "a")
	res, err := e.svc.Restore(e.ctx, u.Principal, []string{a.ID})
	if err != nil || len(res) != 1 || res[0].Name != "A (1)" || res[0].TrashedAt != nil || res[0].ParentID != u.rootID {
		t.Fatalf("restore: %+v %v", res, err)
	}
	// f came back with A, S (trashed on its own before) did not.
	if got := e.children(u, a.ID); !slices.Equal(got, []string{"f.txt"}) {
		t.Fatalf("restored children %v", got)
	}
	if got := e.trashed(u); !slices.Equal(got, []string{"S"}) {
		t.Fatalf("trash after restore %v", got)
	}
	// Restoring S puts it back into its (live again) parent.
	res, err = e.svc.Restore(e.ctx, u.Principal, []string{s.ID})
	if err != nil || res[0].ParentID != a.ID || res[0].Name != "S" {
		t.Fatalf("restore S: %+v %v", res, err)
	}
	if n, _ := e.svc.Get(e.ctx, u.Principal, g.ID); n.TrashedAt != nil {
		t.Fatal("g still trashed")
	}
	// Restoring a live item returns it unchanged.
	if res, err := e.svc.Restore(e.ctx, u.Principal, []string{g.ID}); err != nil || res[0].ID != g.ID {
		t.Fatalf("restore live: %v", err)
	}

	// An item whose parent is in the trash goes back to the space root.
	if err := e.svc.Trash(e.ctx, u.Principal, []string{f.ID}); err != nil {
		t.Fatal(err)
	}
	if err := e.svc.Trash(e.ctx, u.Principal, []string{a.ID}); err != nil {
		t.Fatal(err)
	}
	res, err = e.svc.Restore(e.ctx, u.Principal, []string{f.ID})
	if err != nil || res[0].ParentID != u.rootID {
		t.Fatalf("restore to root: %+v %v", res, err)
	}

	// Purge: only trashed items; releases the quota and deletes the blobs.
	wantCode(t, e.svc.Purge(e.ctx, u.Principal, []string{f.ID}), "invalid")
	gBlob := e.blobOf(g.ID)
	if err := e.svc.Purge(e.ctx, u.Principal, []string{a.ID}); err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.Get(e.ctx, u.Principal, g.ID); code(err) != "not_found" {
		t.Fatalf("purged node still there: %v", err)
	}
	if e.blobs.exists(gBlob) {
		t.Fatal("blob of the purged file not deleted")
	}
	if e.used(u.spaceID) != 5 {
		t.Fatalf("used after purge %d", e.used(u.spaceID))
	}
	if e.audit.count(core.ActFileTrash) != 4 || e.audit.count(core.ActFileRestore) != 3 || e.audit.count(core.ActFilePurge) != 1 {
		t.Fatalf("audits trash=%d restore=%d purge=%d", e.audit.count(core.ActFileTrash),
			e.audit.count(core.ActFileRestore), e.audit.count(core.ActFilePurge))
	}

	// Empty the trash.
	h := e.file(u, u.rootID, "h.txt", "xx")
	if err := e.svc.Trash(e.ctx, u.Principal, []string{h.ID, f.ID}); err != nil {
		t.Fatal(err)
	}
	if err := e.svc.EmptyTrash(e.ctx, u.Principal); err != nil {
		t.Fatal(err)
	}
	if got := e.trashed(u); len(got) != 0 {
		t.Fatalf("trash not empty: %v", got)
	}
	if e.used(u.spaceID) != 0 {
		t.Fatalf("used after empty trash %d", e.used(u.spaceID))
	}
}

// blobOf returns the blob id of a file's current version.
func (e *testEnv) blobOf(nodeID string) string {
	e.t.Helper()
	var id string
	if err := e.db.QueryRow(e.ctx, `SELECT v.blob_id FROM nodes n JOIN file_versions v ON v.id = n.version_id WHERE n.id = ?`,
		nodeID).Scan(&id); err != nil {
		e.t.Fatal(err)
	}
	return id
}

func TestTrashInGroupSpace(t *testing.T) {
	e := newEnv(t)
	mgr := e.user("mgr", core.RoleMember)
	mem := e.user("mem", core.RoleMember)
	gid, _, groot := e.group("Team")
	e.member(gid, mgr, core.GroupRoleManager)
	e.member(gid, mem, core.GroupRoleMember)
	doc := e.file(mem, groot, "doc.txt", "d")
	// A member trashes and restores, but cannot purge.
	if err := e.svc.Trash(e.ctx, mem.Principal, []string{doc.ID}); err != nil {
		t.Fatal(err)
	}
	if got := e.trashed(mem); !slices.Equal(got, []string{"doc.txt"}) {
		t.Fatalf("member trash %v", got)
	}
	wantCode(t, e.svc.Purge(e.ctx, mem.Principal, []string{doc.ID}), "forbidden")
	// EmptyTrash of the member leaves the team trash alone — and the
	// member's trash view still lists it, which is how the web UI and the
	// CLI tell what an "Empty trash" could not delete.
	if err := e.svc.EmptyTrash(e.ctx, mem.Principal); err != nil {
		t.Fatal(err)
	}
	if got := e.trashed(mgr); !slices.Equal(got, []string{"doc.txt"}) {
		t.Fatalf("manager trash %v", got)
	}
	if got := e.trashed(mem); !slices.Equal(got, []string{"doc.txt"}) {
		t.Fatalf("member trash after their EmptyTrash %v", got)
	}
	// The manager purges.
	if err := e.svc.EmptyTrash(e.ctx, mgr.Principal); err != nil {
		t.Fatal(err)
	}
	if got := e.trashed(mgr); len(got) != 0 {
		t.Fatalf("team trash not emptied: %v", got)
	}
	// Strangers see nothing of the team trash.
	stranger := e.user("stranger", core.RoleMember)
	d2 := e.file(mem, groot, "d2.txt", "x")
	if err := e.svc.Trash(e.ctx, mem.Principal, []string{d2.ID}); err != nil {
		t.Fatal(err)
	}
	if got := e.trashed(stranger); len(got) != 0 {
		t.Fatalf("stranger sees %v", got)
	}
	_, err := e.svc.Restore(e.ctx, stranger.Principal, []string{d2.ID})
	wantCode(t, err, "not_found")
	wantCode(t, e.svc.Purge(e.ctx, stranger.Principal, []string{d2.ID}), "not_found")
}

func TestTrashRetentionJob(t *testing.T) {
	e := newEnv(t)
	u := e.user("u", core.RoleMember)
	old := e.file(u, u.rootID, "old.txt", "old")
	if err := e.svc.Trash(e.ctx, u.Principal, []string{old.ID}); err != nil {
		t.Fatal(err)
	}
	e.clock.Advance(20 * 24 * time.Hour)
	fresh := e.file(u, u.rootID, "fresh.txt", "fresh")
	if err := e.svc.Trash(e.ctx, u.Principal, []string{fresh.ID}); err != nil {
		t.Fatal(err)
	}
	e.clock.Advance(11 * 24 * time.Hour) // old: 31 days, fresh: 11 days

	e.settings.set(settingTrashDays, int64(0))
	e.jobs.run(t, core.JobMaintTrash, nil)
	if got := e.trashed(u); len(got) != 2 {
		t.Fatalf("retention 0 purged something: %v", got)
	}
	e.settings.set(settingTrashDays, int64(30))
	res := e.jobs.run(t, core.JobMaintTrash, nil).(map[string]any)
	if res["purged"] != 1 {
		t.Fatalf("result %v", res)
	}
	if got := e.trashed(u); !slices.Equal(got, []string{"fresh.txt"}) {
		t.Fatalf("after retention %v", got)
	}
	if e.used(u.spaceID) != 5 {
		t.Fatalf("used %d", e.used(u.spaceID))
	}
	if a := e.audit.last(core.ActFilePurge); a == nil || a.Details.(map[string]any)["reason"] != "retention" || a.ActorVia != "job" {
		t.Fatalf("purge audit %+v", a)
	}
}

// TestRetentionSkipsRetrashedItems: the retention job lists a batch of
// expired trash roots and then purges them one by one, over several
// transactions each. An item of the batch that is restored and trashed
// again in the meantime has a fresh trashed_at and must keep its
// storage.trash_days, not be purged with the stale batch.
func TestRetentionSkipsRetrashedItems(t *testing.T) {
	e := newEnv(t)
	u := e.user("u", core.RoleMember)
	defer func(n int) { maxPurgeNodes = n }(maxPurgeNodes)
	maxPurgeNodes = 4

	big := e.mkdir(u, u.rootID, "big")
	for i := range 10 {
		e.file(u, big.ID, "f"+strconv.Itoa(i)+".txt", "x")
	}
	if err := e.svc.Trash(e.ctx, u.Principal, []string{big.ID}); err != nil {
		t.Fatal(err)
	}
	e.clock.Advance(time.Minute)
	x := e.file(u, u.rootID, "x.txt", "keep me")
	if err := e.svc.Trash(e.ctx, u.Principal, []string{x.ID}); err != nil {
		t.Fatal(err)
	}
	e.clock.Advance(31 * 24 * time.Hour) // both expired; "big" is purged first

	// After the first chunk of "big" has been committed, the user restores
	// x.txt and deletes it again.
	var once sync.Once
	e.blobs.onDelete = func(string) {
		once.Do(func() {
			if _, err := e.svc.Restore(e.ctx, u.Principal, []string{x.ID}); err != nil {
				t.Error(err)
			}
			if err := e.svc.Trash(e.ctx, u.Principal, []string{x.ID}); err != nil {
				t.Error(err)
			}
		})
	}
	e.settings.set(settingTrashDays, int64(30))
	res := e.jobs.run(t, core.JobMaintTrash, nil).(map[string]any)
	e.blobs.onDelete = nil
	if res["purged"] != 1 {
		t.Fatalf("result %v, want only the folder purged", res)
	}
	if e.count(`SELECT COUNT(*) FROM nodes WHERE id = ?`, big.ID) != 0 {
		t.Fatal("the expired folder was not purged")
	}
	n, err := e.svc.Get(e.ctx, u.Principal, x.ID)
	if err != nil || n.TrashedAt == nil || !n.TrashRoot || !n.TrashedAt.Equal(e.clock.Now()) {
		t.Fatalf("the re-trashed item: %+v %v", n, err)
	}
	if got := e.trashed(u); !slices.Equal(got, []string{"x.txt"}) {
		t.Fatalf("trash %v", got)
	}
}

// TestRestoreFallbackNeedsEditOnRoot: an item whose folder is in the trash
// is restored to the space root, which needs PermEdit there like any other
// way of adding an item to it. An editor through a grant inside the space
// is refused (403), not allowed to place items outside the shared folder.
func TestRestoreFallbackNeedsEditOnRoot(t *testing.T) {
	e := newEnv(t)
	alice := e.user("alice", core.RoleMember)
	bob := e.user("bob", core.RoleMember)
	f := e.mkdir(alice, alice.rootID, "F")
	e.grant(alice, f.ID, core.SubjectUser, bob.UserID, core.GrantEditor)
	x := e.file(bob, f.ID, "x.txt", "x")
	if err := e.svc.Trash(e.ctx, bob.Principal, []string{x.ID}); err != nil {
		t.Fatal(err)
	}
	if err := e.svc.Trash(e.ctx, bob.Principal, []string{f.ID}); err != nil {
		t.Fatal(err)
	}
	_, err := e.svc.Restore(e.ctx, bob.Principal, []string{x.ID})
	wantCode(t, err, "forbidden")
	if n, _ := e.svc.Get(e.ctx, alice.Principal, x.ID); n == nil || n.TrashedAt == nil || n.ParentID != f.ID {
		t.Fatalf("refused restore changed the item: %+v", n)
	}
	if got := e.children(alice, alice.rootID); len(got) != 0 {
		t.Fatalf("alice's root lists %v", got)
	}
	// Restoring the folder too (outer items first) puts x back into it.
	res, err := e.svc.Restore(e.ctx, bob.Principal, []string{x.ID, f.ID})
	if err != nil || len(res) != 2 || res[0].ParentID != f.ID || res[1].ParentID != alice.rootID {
		t.Fatalf("restore with the folder: %+v %v", res, err)
	}

	// The owner may still restore into her root.
	if err := e.svc.Trash(e.ctx, bob.Principal, []string{x.ID}); err != nil {
		t.Fatal(err)
	}
	if err := e.svc.Trash(e.ctx, alice.Principal, []string{f.ID}); err != nil {
		t.Fatal(err)
	}
	if res, err := e.svc.Restore(e.ctx, alice.Principal, []string{x.ID}); err != nil || res[0].ParentID != alice.rootID {
		t.Fatalf("owner restore to the root: %+v %v", res, err)
	}

	// So may a plain member of a group space (PermEdit on its root).
	mem := e.user("mem", core.RoleMember)
	gid, _, groot := e.group("Team")
	e.member(gid, mem, core.GroupRoleMember)
	d := e.mkdir(mem, groot, "D")
	y := e.file(mem, d.ID, "y.txt", "y")
	if err := e.svc.Trash(e.ctx, mem.Principal, []string{y.ID}); err != nil {
		t.Fatal(err)
	}
	if err := e.svc.Trash(e.ctx, mem.Principal, []string{d.ID}); err != nil {
		t.Fatal(err)
	}
	if res, err := e.svc.Restore(e.ctx, mem.Principal, []string{y.ID}); err != nil || res[0].ParentID != groot {
		t.Fatalf("member restore to the group root: %+v %v", res, err)
	}
}

func TestVersionsKeepAndRestore(t *testing.T) {
	e := newEnv(t)
	u := e.user("u", core.RoleMember)
	e.settings.set(settingVersionsKeep, int64(3))
	var first *core.Node
	var blobIDs []string
	for i := 1; i <= 5; i++ {
		b := e.blobs.put(t, []byte(string(rune('a'+i-1))+"-"+time.Duration(i).String()))
		n, err := e.svc.CommitFile(e.ctx, u.Principal, u.rootID, "doc.txt", b, core.FileMeta{}, core.ConflictReplace)
		if err != nil {
			t.Fatal(err)
		}
		if first == nil {
			first = n
		}
		blobIDs = append(blobIDs, b.ID)
		e.clock.Advance(time.Second)
	}
	vs, err := e.svc.Versions(e.ctx, u.Principal, first.ID)
	if err != nil || len(vs) != 3 || !vs[0].Current {
		t.Fatalf("versions %+v %v", vs, err)
	}
	var sum int64
	for _, v := range vs {
		sum += v.Size
	}
	if e.used(u.spaceID) != sum {
		t.Fatalf("used %d, want %d", e.used(u.spaceID), sum)
	}
	for i, id := range blobIDs {
		if want := i >= 2; e.blobs.exists(id) != want {
			t.Fatalf("blob %d exists=%v", i, !want)
		}
	}
	// Open an older version.
	n, rd, err := e.svc.Open(e.ctx, u.Principal, first.ID, vs[2].ID)
	if err != nil {
		t.Fatal(err)
	}
	rd.Close()
	if n.VersionID != vs[2].ID || n.Size != vs[2].Size {
		t.Fatalf("open version: %+v", n)
	}
	if _, _, err := e.svc.Open(e.ctx, u.Principal, first.ID, "ver_00000000000000000000000000"); code(err) != "not_found" {
		t.Fatalf("unknown version: %v", err)
	}
	// Restore the oldest kept version: a new current version sharing its blob.
	r, err := e.svc.RestoreVersion(e.ctx, u.Principal, first.ID, vs[2].ID)
	if err != nil || r.VersionID == vs[2].ID || r.BlobID != vs[2].BlobID {
		t.Fatalf("restore version: %+v %v", r, err)
	}
	vs2, _ := e.svc.Versions(e.ctx, u.Principal, first.ID)
	if len(vs2) != 3 || vs2[0].ID != r.VersionID {
		t.Fatalf("versions after restore: %+v", vs2)
	}
	if e.blobs.exists(vs[2].BlobID) != true {
		t.Fatal("restored blob deleted")
	}
	if a := e.audit.last(core.ActFileVersionRestore); a == nil || a.TargetID != first.ID {
		t.Fatalf("audit %+v", a)
	}
	// Restoring the current version is a no-op; folders have no versions.
	if r2, err := e.svc.RestoreVersion(e.ctx, u.Principal, first.ID, r.VersionID); err != nil || r2.VersionID != r.VersionID {
		t.Fatalf("restore current: %v", err)
	}
	if _, err := e.svc.Versions(e.ctx, u.Principal, u.rootID); code(err) != "invalid" {
		t.Fatalf("folder versions: %v", err)
	}
	if _, err := e.svc.RestoreVersion(e.ctx, u.Principal, first.ID, "bogus"); code(err) != "not_found" {
		t.Fatalf("bogus version: %v", err)
	}

	// maintenance.versions applies a lower limit and fixes the usage.
	e.settings.set(settingVersionsKeep, int64(1))
	if _, err := e.db.Exec(e.ctx, `UPDATE spaces SET used_bytes = 999 WHERE id = ?`, u.spaceID); err != nil {
		t.Fatal(err)
	}
	res := e.jobs.run(t, core.JobMaintVersions, nil).(map[string]any)
	if res["versions_deleted"] != int64(2) || res["usage_corrected"] != 1 {
		t.Fatalf("job result %v", res)
	}
	vs3, _ := e.svc.Versions(e.ctx, u.Principal, first.ID)
	if len(vs3) != 1 || e.used(u.spaceID) != vs3[0].Size {
		t.Fatalf("after job: %+v used %d", vs3, e.used(u.spaceID))
	}
}

// versionBlobs returns the blob ids of a file's versions, newest first.
func (e *testEnv) versionBlobs(p *user, id string) []string {
	e.t.Helper()
	vs, err := e.svc.Versions(e.ctx, p.Principal, id)
	if err != nil {
		e.t.Fatal(err)
	}
	out := make([]string, len(vs))
	for i, v := range vs {
		out[i] = v.BlobID
	}
	return out
}

// TestRestoreVersionMovesToTop: restoring a version moves it to the top of
// the history instead of copying it, so a file at storage.versions_keep
// loses no other version, the content is charged to the quota once and a
// full space can still restore.
func TestRestoreVersionMovesToTop(t *testing.T) {
	e := newEnv(t)
	u := e.user("u", core.RoleMember)
	e.settings.set(settingVersionsKeep, int64(3))
	var id string
	var blobs []string
	for _, data := range []string{"v1", "v2-", "v3--"} {
		b := e.blobs.put(t, []byte(data))
		n, err := e.svc.CommitFile(e.ctx, u.Principal, u.rootID, "doc.txt", b, core.FileMeta{}, core.ConflictReplace)
		if err != nil {
			t.Fatal(err)
		}
		id = n.ID
		blobs = append(blobs, b.ID)
		e.clock.Advance(time.Second)
	}
	vs, _ := e.svc.Versions(e.ctx, u.Principal, id)
	if len(vs) != 3 || e.used(u.spaceID) != 9 {
		t.Fatalf("setup: %d versions, used %d", len(vs), e.used(u.spaceID))
	}

	// Restore the middle version: it moves to the top, v1 stays.
	r, err := e.svc.RestoreVersion(e.ctx, u.Principal, id, vs[1].ID)
	if err != nil || r.BlobID != blobs[1] || r.Size != 3 {
		t.Fatalf("restore: %+v %v", r, err)
	}
	if got, want := e.versionBlobs(u, id), []string{blobs[1], blobs[2], blobs[0]}; !slices.Equal(got, want) {
		t.Fatalf("versions after restore %v, want %v", got, want)
	}
	for i, b := range blobs {
		if !e.blobs.exists(b) {
			t.Fatalf("blob of v%d deleted", i+1)
		}
	}
	if used := e.used(u.spaceID); used != 9 {
		t.Fatalf("used %d after the restore, want 9 (each content once)", used)
	}
	if a := e.audit.last(core.ActFileVersionRestore); a == nil || a.Details.(map[string]any)["restored_version_id"] != vs[1].ID {
		t.Fatalf("audit %+v", a)
	}

	// A space that is full can restore: nothing new is stored.
	if _, err := e.db.Exec(e.ctx, `UPDATE users SET quota_bytes = 9 WHERE id = ?`, u.UserID); err != nil {
		t.Fatal(err)
	}
	e.clock.Advance(time.Second)
	after, _ := e.svc.Versions(e.ctx, u.Principal, id)
	if _, err := e.svc.RestoreVersion(e.ctx, u.Principal, id, after[2].ID); err != nil {
		t.Fatalf("restore in a full space: %v", err)
	}
	if got, want := e.versionBlobs(u, id), []string{blobs[0], blobs[1], blobs[2]}; !slices.Equal(got, want) {
		t.Fatalf("versions after the second restore %v, want %v", got, want)
	}
	if used := e.used(u.spaceID); used != 9 {
		t.Fatalf("used %d", used)
	}
}

// TestRestoreVersionDetectsMIME: nodes.mime describes the current version
// only, so restoring an older one detects the type of its bytes again
// instead of keeping the type of the content it replaces (DESIGN §8.2).
func TestRestoreVersionDetectsMIME(t *testing.T) {
	e := newEnv(t)
	u := e.user("u", core.RoleMember)
	html := "<!DOCTYPE html><html><body><script>alert(1)</script></body></html>"
	png := "\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR"
	cases := []struct {
		name, old, oldMIME, cur, curMIME string
	}{
		// HTML bytes must not become an inline application/pdf.
		{"doc.pdf", html, "text/html", "%PDF-1.4\n%âãÏÓ\n", "application/pdf"},
		// A real PDF gets its type (and preview) back.
		{"report.pdf", "%PDF-1.7\n%âãÏÓ\n", "application/pdf", "PK\x03\x04\x14\x00\x06\x00", "application/zip"},
		// A real image gets its type (and thumbnail) back.
		{"logo.png", png, "image/png", html, "text/html"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			v1 := e.file(u, u.rootID, c.name, c.old)
			if v1.MIME != c.oldMIME {
				t.Fatalf("v1 MIME %q, want %q", v1.MIME, c.oldMIME)
			}
			e.clock.Advance(time.Second)
			v2, err := e.svc.CommitFile(e.ctx, u.Principal, u.rootID, c.name, e.blobs.put(t, []byte(c.cur)), core.FileMeta{},
				core.ConflictReplace)
			if err != nil || v2.MIME != c.curMIME {
				t.Fatalf("v2: %+v %v", v2, err)
			}
			e.jobs.drain(t, core.JobThumbsGenerate)
			r, err := e.svc.RestoreVersion(e.ctx, u.Principal, v1.ID, v1.VersionID)
			if err != nil || r.MIME != c.oldMIME || r.BlobID != v1.BlobID {
				t.Fatalf("restore: MIME %q (%v), want %q", r.MIME, err, c.oldMIME)
			}
			n, rd, err := e.svc.Open(e.ctx, u.Principal, v1.ID, "")
			if err != nil {
				t.Fatal(err)
			}
			rd.Close()
			if n.MIME != c.oldMIME {
				t.Fatalf("open after restore: MIME %q, want %q", n.MIME, c.oldMIME)
			}
			if want := map[bool]int{true: 1}[c.oldMIME == "image/png"]; e.jobs.queued(core.JobThumbsGenerate) != want {
				t.Fatalf("%d thumbnail jobs queued, want %d", e.jobs.queued(core.JobThumbsGenerate), want)
			}
		})
	}
}

// TestQuotaChargedAfterPrune: a new version that pushes the oldest one out
// (storage.versions_keep) needs room only for the difference — the quota
// applies to what the transaction commits, not to its peak.
func TestQuotaChargedAfterPrune(t *testing.T) {
	e := newEnv(t)
	u := e.user("u", core.RoleMember)
	e.settings.set(settingVersionsKeep, int64(2))
	replace := func(parent, name, data string) (*core.Node, error) {
		return e.svc.CommitFile(e.ctx, u.Principal, parent, name, e.blobs.put(t, []byte(data)), core.FileMeta{}, core.ConflictReplace)
	}
	a := e.file(u, u.rootID, "a.txt", "0123456789")
	e.clock.Advance(time.Second)
	if _, err := replace(u.rootID, "a.txt", "abcdefghij"); err != nil {
		t.Fatal(err)
	}
	src := e.mkdir(u, u.rootID, "src")
	b := e.file(u, src.ID, "a.txt", "ABCDEFGHIJ")
	if used := e.used(u.spaceID); used != 30 {
		t.Fatalf("used %d", used)
	}
	if _, err := e.db.Exec(e.ctx, `UPDATE users SET quota_bytes = 30 WHERE id = ?`, u.UserID); err != nil {
		t.Fatal(err)
	}

	// A same-size replace in a full space: the oldest version makes room.
	e.clock.Advance(time.Second)
	if _, err := replace(u.rootID, "a.txt", "klmnopqrst"); err != nil {
		t.Fatalf("same-size replace at full quota: %v", err)
	}
	// So does a copy that replaces.
	e.clock.Advance(time.Second)
	if out, err := e.svc.Copy(e.ctx, u.Principal, []string{b.ID}, u.rootID, core.ConflictReplace); err != nil || out[0].ID != a.ID {
		t.Fatalf("copy replace at full quota: %+v %v", out, err)
	}
	if used := e.used(u.spaceID); used != 30 {
		t.Fatalf("used %d", used)
	}

	// One byte more than the prune frees is refused, and the refused
	// transaction changes nothing: no version pruned, no blob deleted.
	before := e.versionBlobs(u, a.ID)
	cur, _ := e.svc.Get(e.ctx, u.Principal, a.ID)
	e.clock.Advance(time.Second)
	_, err := replace(u.rootID, "a.txt", "0123456789X")
	wantCode(t, err, "quota_exceeded")
	if got := e.versionBlobs(u, a.ID); !slices.Equal(got, before) {
		t.Fatalf("versions %v after the refused replace, want %v", got, before)
	}
	if n, _ := e.svc.Get(e.ctx, u.Principal, a.ID); n.VersionID != cur.VersionID {
		t.Fatal("the current version changed")
	}
	for _, id := range before {
		if !e.blobs.exists(id) {
			t.Fatal("the refused replace deleted a blob")
		}
	}
	if used := e.used(u.spaceID); used != 30 {
		t.Fatalf("used %d after the refused replace", used)
	}
}

// TestPurgeNestedTrashRoots: a folder trashed on its own before its parent
// is a separate trash root inside a trashed subtree; purging (or emptying
// the trash) must handle both in one call, in any order.
func TestPurgeNestedTrashRoots(t *testing.T) {
	for _, order := range []string{"parent-first", "child-first", "empty-trash"} {
		t.Run(order, func(t *testing.T) {
			e := newEnv(t)
			u := e.user("alice", core.RoleMember)
			p := e.mkdir(u, u.rootID, "P")
			c := e.mkdir(u, p.ID, "C")
			e.file(u, c.ID, "x.txt", "123")
			e.file(u, p.ID, "y.txt", "45")
			if err := e.svc.Trash(e.ctx, u.Principal, []string{c.ID}); err != nil {
				t.Fatal(err)
			}
			if err := e.svc.Trash(e.ctx, u.Principal, []string{p.ID}); err != nil {
				t.Fatal(err)
			}
			if got := e.trashed(u); len(got) != 2 {
				t.Fatalf("trash %v", got)
			}
			var err error
			switch order {
			case "parent-first":
				err = e.svc.Purge(e.ctx, u.Principal, []string{p.ID, c.ID})
			case "child-first":
				err = e.svc.Purge(e.ctx, u.Principal, []string{c.ID, p.ID})
			default:
				err = e.svc.EmptyTrash(e.ctx, u.Principal)
			}
			if err != nil {
				t.Fatal(err)
			}
			if got := e.trashed(u); len(got) != 0 {
				t.Fatalf("trash not empty: %v", got)
			}
			if e.used(u.spaceID) != 0 {
				t.Fatalf("used %d", e.used(u.spaceID))
			}
			if n := e.audit.count(core.ActFilePurge); n < 1 || n > 2 {
				t.Fatalf("purge audits %d", n)
			}
		})
	}
}

// TestBatchNesting: items of one request that lie inside another item of
// the same request are handled together with it.
func TestBatchNesting(t *testing.T) {
	e := newEnv(t)
	u := e.user("alice", core.RoleMember)
	p := e.mkdir(u, u.rootID, "P")
	q := e.mkdir(u, p.ID, "Q")
	c := e.mkdir(u, q.ID, "C")
	e.file(u, c.ID, "x.txt", "123")
	dest := e.mkdir(u, u.rootID, "Dest")

	// Trash with the child first: one trash entry.
	if err := e.svc.Trash(e.ctx, u.Principal, []string{c.ID, p.ID}); err != nil {
		t.Fatal(err)
	}
	if got := e.trashed(u); !slices.Equal(got, []string{"P"}) {
		t.Fatalf("trash %v", got)
	}
	if _, err := e.svc.Restore(e.ctx, u.Principal, []string{p.ID}); err != nil {
		t.Fatal(err)
	}
	if got := e.children(u, q.ID); !slices.Equal(got, []string{"C"}) {
		t.Fatalf("C not restored with P: %v", got)
	}

	// Two trash roots (C trashed before P) restored together in any order:
	// C returns into Q, not to the space root.
	if err := e.svc.Trash(e.ctx, u.Principal, []string{c.ID}); err != nil {
		t.Fatal(err)
	}
	if err := e.svc.Trash(e.ctx, u.Principal, []string{p.ID}); err != nil {
		t.Fatal(err)
	}
	res, err := e.svc.Restore(e.ctx, u.Principal, []string{c.ID, p.ID})
	if err != nil || len(res) != 2 || res[0].ID != c.ID || res[1].ID != p.ID {
		t.Fatalf("restore: %+v %v", res, err)
	}
	if res[0].ParentID != q.ID {
		t.Fatalf("C restored into %s, want Q", res[0].ParentID)
	}
	if got := e.children(u, u.rootID); !slices.Equal(got, []string{"Dest", "P"}) {
		t.Fatalf("root %v", got)
	}

	// Move: C moves with P (not out of it).
	moved, err := e.svc.Move(e.ctx, u.Principal, []string{c.ID, p.ID}, dest.ID, core.ConflictFail)
	if err != nil || len(moved) != 1 || moved[0].ID != p.ID {
		t.Fatalf("move: %+v %v", moved, err)
	}
	if got := e.children(u, q.ID); !slices.Equal(got, []string{"C"}) {
		t.Fatalf("C moved out of Q: %v", got)
	}

	// Copy: C is copied once, inside the copy of P.
	copies, err := e.svc.Copy(e.ctx, u.Principal, []string{p.ID, c.ID}, u.rootID, core.ConflictRename)
	if err != nil || len(copies) != 1 || copies[0].Name != "P" {
		t.Fatalf("copy: %+v %v", copies, err)
	}
	if got := e.children(u, u.rootID); !slices.Equal(got, []string{"Dest", "P"}) {
		t.Fatalf("root after copy %v", got)
	}
	st, err := e.svc.Stats(e.ctx, u.Principal, copies[0].ID)
	if err != nil || st.Folders != 2 || st.Files != 1 {
		t.Fatalf("copy stats %+v %v", st, err)
	}
}

// TestPurgeRunsInBoundedTransactions pins that a subtree larger than
// maxPurgeNodes is purged over several transactions instead of one
// unbounded delete that holds the single writer connection (DESIGN §6).
// The proof is that work survives: a purge stopped after its first chunk
// has really deleted that chunk, which a single-transaction purge could
// never show.
func TestPurgeRunsInBoundedTransactions(t *testing.T) {
	e := newEnv(t)
	u := e.user("alice", core.RoleMember)
	defer func(n int) { maxPurgeNodes = n }(maxPurgeNodes)
	maxPurgeNodes = 4

	folder := e.mkdir(u, u.rootID, "big")
	const files = 14
	for i := range files {
		e.file(u, folder.ID, "f"+strconv.Itoa(i)+".txt", strings.Repeat("x", 10))
	}
	if used := e.used(u.spaceID); used != files*10 {
		t.Fatalf("used %d before the purge", used)
	}
	if err := e.svc.Trash(e.ctx, u.Principal, []string{folder.ID}); err != nil {
		t.Fatal(err)
	}

	// Stop the purge as soon as the first chunk has been committed (the
	// blobs of a chunk are released after its transaction).
	ctx, cancel := context.WithCancel(e.ctx)
	defer cancel()
	e.blobs.onDelete = func(string) { cancel() }
	err := e.svc.Purge(ctx, u.Principal, []string{folder.ID})
	e.blobs.onDelete = nil
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled purge: %v", err)
	}
	left := e.count(`SELECT COUNT(*) FROM nodes WHERE space_id = ?`, u.spaceID)
	if left == files+2 { // root + folder + files: nothing was committed
		t.Fatal("the cancelled purge deleted nothing: it ran as one transaction")
	}
	if left <= 2 {
		t.Fatalf("%d nodes left: the whole subtree went in one transaction", left)
	}
	if e.count(`SELECT COUNT(*) FROM nodes WHERE id = ?`, folder.ID) != 1 {
		t.Fatal("the folder was purged although the purge stopped after one chunk")
	}
	// What the stopped chunk deleted is audited as a partial purge: no
	// deletion goes unrecorded.
	if got := e.audit.count(core.ActFilePurge); got != 1 {
		t.Fatalf("%d file.purge entries after the first chunk, want 1", got)
	}
	first, _ := e.audit.last(core.ActFilePurge).Details.(map[string]any)
	if first["partial"] != true || first["items"] != maxPurgeNodes {
		t.Fatalf("first chunk audited as %v", first)
	}

	// Resuming finishes it: the subtree is gone, the quota released and the
	// whole purge audited once with the totals of every chunk.
	if err := e.svc.Purge(e.ctx, u.Principal, []string{folder.ID}); err != nil {
		t.Fatalf("resume: %v", err)
	}
	if n := e.count(`SELECT COUNT(*) FROM nodes WHERE space_id = ?`, u.spaceID); n != 1 {
		t.Fatalf("%d nodes left after the purge, want only the root", n)
	}
	if used := e.used(u.spaceID); used != 0 {
		t.Fatalf("used %d after the purge", used)
	}
	// The closing entry covers what the resuming call deleted and is not
	// marked partial; the chunks together account for every node.
	last, _ := e.audit.last(core.ActFilePurge).Details.(map[string]any)
	if last["partial"] != nil {
		t.Fatalf("the finished purge is still marked partial: %v", last)
	}
	var items int
	var bytes int64
	for _, entry := range e.audit.all(core.ActFilePurge) {
		d, _ := entry.Details.(map[string]any)
		items += d["items"].(int)
		bytes += d["bytes"].(int64)
	}
	if items != files+1 || bytes != int64(files*10) {
		t.Fatalf("the purge audits account for %d items / %d bytes, want %d / %d", items, bytes, files+1, files*10)
	}
}

// TestPurgeRejectsTheWholeCall pins that Purge still changes nothing when
// one of its ids cannot be purged: it is checked in a read pass before the
// first delete transaction, so chunking a large subtree over several
// transactions did not turn a bad request into a partial purge.
func TestPurgeRejectsTheWholeCall(t *testing.T) {
	e := newEnv(t)
	u := e.user("alice", core.RoleMember)
	trashed := e.file(u, u.rootID, "gone.txt", "gone")
	live := e.file(u, u.rootID, "here.txt", "here")
	if err := e.svc.Trash(e.ctx, u.Principal, []string{trashed.ID}); err != nil {
		t.Fatal(err)
	}
	if err := e.svc.Purge(e.ctx, u.Principal, []string{trashed.ID, live.ID}); code(err) != "invalid" {
		t.Fatalf("purge of a live node: %v", err)
	}
	if n := e.count(`SELECT COUNT(*) FROM nodes WHERE id = ?`, trashed.ID); n != 1 {
		t.Fatal("the trashed node was purged although the call was refused")
	}
	if e.audit.count(core.ActFilePurge) != 0 {
		t.Fatal("the refused call purged and audited something")
	}
}
