package uploads

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"fileparcel/internal/core"
	"fileparcel/internal/db"
	"fileparcel/internal/events"
	"fileparcel/internal/ids"
	"fileparcel/internal/uploads/uploadtest"
)

// ---------- helpers ----------

// share inserts a share row (a file request by default) for folderID owned
// by ownerID and returns its id.
func (f *fixture) share(ownerID, folderID string, set map[string]any) string {
	f.t.Helper()
	id := ids.New(ids.PrefixShare)
	now := db.Ms(f.Clock.Now())
	f.Exec(`INSERT INTO shares (id, kind, node_id, created_by, token_hash, token_enc, allow_download, allow_preview,
		allow_upload, created_at, updated_at) VALUES (?, 'request', ?, ?, ?, 'x', 0, 0, 1, ?, ?)`,
		id, folderID, ownerID, ids.HashToken(ids.Token(16)), now, now)
	for col, v := range set {
		f.Exec(`UPDATE shares SET `+col+` = ? WHERE id = ?`, v, id)
	}
	return id
}

func (f *fixture) requestActor(ownerID, shareID, uploader string) core.UploadActor {
	p, err := f.Files.SysPrincipalFor(f.ctx, ownerID)
	if err != nil {
		f.t.Fatal(err)
	}
	return core.UploadActor{P: p, ShareID: shareID, Uploader: uploader}
}

func (f *fixture) complete(a core.UploadActor, batchID string) *core.UploadBatch {
	f.t.Helper()
	b, err := f.svc.CompleteBatch(f.ctx, a, batchID)
	if err != nil {
		f.t.Fatalf("CompleteBatch: %v", err)
	}
	return b
}

func (f *fixture) batchState(id string) string {
	return f.Str(`SELECT state FROM upload_batches WHERE id = ?`, id)
}

func refID(b *core.UploadBatch, ref string) string {
	for _, fs := range b.Files {
		if fs.ClientRef == ref {
			return fs.ID
		}
	}
	return ""
}

// ---------- files mode completion ----------

func TestCompleteBatchFiles(t *testing.T) {
	f := setup(t)
	a := f.actor(f.alice)
	ch, unsub := f.Bus.Subscribe(events.TopicUploadBatchDone)
	defer unsub()
	data := content(core.PartSize+3, 9)
	b := f.batch(a, core.BatchInput{FolderID: f.aliceRoot, Files: []core.UploadFileInput{
		{ClientRef: "d1", RelPath: "Trip/empty", Kind: "dir"},
		{ClientRef: "d2", RelPath: "Trip/day1", Kind: "dir"},
		{ClientRef: "f1", RelPath: "Trip/day1/a.txt", Size: 3},
		{ClientRef: "f2", RelPath: "Trip/big.bin", Size: int64(len(data))},
	}})
	f.small(a, b.ID, "f1", []byte("abc"))

	// A file is still missing: 409, nothing finalized.
	_, err := f.svc.CompleteBatch(f.ctx, a, b.ID)
	wantCode(t, err, core.ErrConflict)
	if st := f.batchState(b.ID); st != core.BatchOpen {
		t.Fatalf("state after early complete = %s", st)
	}
	f.parts(a, refID(b, "f2"), data, 1, 0)
	if _, err := f.svc.CompleteFile(f.ctx, a, refID(b, "f2")); err != nil {
		t.Fatal(err)
	}
	done := f.complete(a, b.ID)
	if done.State != core.BatchDone || done.ReservedBytes != 0 {
		t.Fatalf("batch = %+v", done)
	}
	// The empty directory exists, the directory entries are committed.
	emptyID := f.Str(`SELECT n.id FROM nodes n JOIN nodes p ON p.id = n.parent_id
		WHERE p.name = 'Trip' AND n.name = 'empty' AND n.kind = 'folder'`)
	if emptyID == "" {
		t.Fatal("empty directory was not created")
	}
	for _, ref := range []string{"d1", "d2"} {
		st, _ := f.svc.Status(f.ctx, a, refID(b, ref))
		if st.State != core.UploadCommitted || st.NodeID == "" {
			t.Errorf("dir %s: %+v", ref, st)
		}
	}
	if got, _ := f.nodeContent(f.aliceRoot, "Trip/big.bin"); !bytes.Equal(got, data) {
		t.Fatal("big file content differs")
	}
	select {
	case ev := <-ch:
		be := ev.Data.(core.UploadBatchEvent)
		if be.Batch.ID != b.ID || ev.UserID != f.alice || be.Batch.State != core.BatchDone {
			t.Errorf("event %+v", be)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("no upload.batch_done event")
	}
	// Signed-in batches are audited per file by the files service, not here.
	if _, ok := f.Audit.Find(core.ActFileUpload); ok {
		t.Error("a successful batch must not add its own file.upload audit entry")
	}
	// Completing again is idempotent; mutations are refused.
	if again := f.complete(a, b.ID); again.State != core.BatchDone {
		t.Fatalf("complete again: %+v", again)
	}
	_, err = f.svc.AddFiles(f.ctx, a, b.ID, []core.UploadFileInput{{ClientRef: "x", RelPath: "x", Size: 1}})
	wantCode(t, err, core.ErrConflict)
	wantCode(t, f.svc.AbortBatch(f.ctx, a, b.ID), core.ErrConflict)
	// Other users cannot see the batch.
	_, err = f.svc.GetBatch(f.ctx, f.actor(f.bob), b.ID)
	wantCode(t, err, core.ErrNotFound)
}

func TestGetBatchAndAddFiles(t *testing.T) {
	f := setup(t)
	a := f.actor(f.alice)
	data := content(2*core.PartSize+1, 4)
	b := f.batch(a, core.BatchInput{FolderID: f.aliceRoot, Files: []core.UploadFileInput{
		{ClientRef: "f1", RelPath: "one.bin", Size: int64(len(data))}}})
	f.parts(a, refID(b, "f1"), data, 2)

	// Chunked declarations: new entries, an idempotent repeat and a conflict.
	add := []core.UploadFileInput{
		{ClientRef: "f1", RelPath: "one.bin", Size: int64(len(data))},
		{ClientRef: "f2", RelPath: "two.txt", Size: 5},
		{ClientRef: "d", RelPath: "dir", Kind: "dir"},
	}
	states, err := f.svc.AddFiles(f.ctx, a, b.ID, add)
	if err != nil {
		t.Fatal(err)
	}
	if len(states) != 3 || states[0].ID != refID(b, "f1") || !slices.Equal(states[0].PartsDone, []int{2}) ||
		states[1].State != core.UploadPending || states[1].ID == "" || states[2].Kind != core.UploadKindDir {
		t.Fatalf("states = %+v", states)
	}
	_, err = f.svc.AddFiles(f.ctx, a, b.ID, []core.UploadFileInput{{ClientRef: "f2", RelPath: "other.txt", Size: 5}})
	wantCode(t, err, core.ErrConflict)
	_, err = f.svc.AddFiles(f.ctx, f.actor(f.bob), b.ID, add)
	wantCode(t, err, core.ErrNotFound)

	got, err := f.svc.GetBatch(f.ctx, a, b.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.DeclaredFiles != 3 || got.DeclaredBytes != int64(len(data))+5 || got.ReservedBytes != got.DeclaredBytes ||
		len(got.Files) != 3 || got.PartSize != core.PartSize || got.SmallMax != SmallMax {
		t.Fatalf("batch = %+v", got)
	}
	if !slices.Equal(got.Files[0].PartsDone, []int{2}) || len(got.Files[1].PartsDone) != 0 || got.Files[1].PartsDone == nil {
		t.Errorf("parts done: %+v", got.Files)
	}
	_, err = f.svc.GetBatch(f.ctx, a, "upb_nope")
	wantCode(t, err, core.ErrNotFound)
}

// ---------- quota, limits, caps ----------

func TestQuotaReservation(t *testing.T) {
	f := setup(t)
	a := f.actor(f.alice)
	q := int64(100)
	f.SetQuota(f.alice, &q)
	f.PutFile(f.aliceRoot, "existing.txt", []byte("0123456789")) // 10 bytes used

	b1 := f.batch(a, core.BatchInput{FolderID: f.aliceRoot, Files: []core.UploadFileInput{
		{ClientRef: "a", RelPath: "a.bin", Size: 50}, {ClientRef: "b", RelPath: "b.bin", Size: 10}}})
	// 10 used + 60 reserved: 31 more bytes do not fit, and the refusal names
	// what the unfinished upload holds.
	_, err := f.svc.CreateBatch(f.ctx, a, core.BatchInput{FolderID: f.aliceRoot,
		Files: []core.UploadFileInput{{ClientRef: "c", RelPath: "c.bin", Size: 31}}})
	wantCode(t, err, core.ErrQuota)
	if got, want := core.AsError(err).Message, "not enough storage space: the upload needs 31 B, 30 B are available "+
		"(unfinished uploads hold 60 B until they finish, are cancelled or expire)"; got != want {
		t.Fatalf("message %q, want %q", got, want)
	}
	_, err = f.svc.AddFiles(f.ctx, a, b1.ID, []core.UploadFileInput{{ClientRef: "c", RelPath: "c.bin", Size: 31}})
	wantCode(t, err, core.ErrQuota)
	b2 := f.batch(a, core.BatchInput{FolderID: f.aliceRoot, Files: []core.UploadFileInput{
		{ClientRef: "c", RelPath: "c.bin", Size: 30}}})

	// Committing moves bytes from the reservation to the usage.
	f.small(a, b1.ID, "b", bytes.Repeat([]byte("b"), 10))
	if r := f.Int(`SELECT reserved_bytes FROM upload_batches WHERE id = ?`, b1.ID); r != 50 {
		t.Fatalf("reserved after commit = %d", r)
	}
	// Aborting a file releases its reservation; aborting a batch releases the rest.
	if err := f.svc.AbortBatch(f.ctx, a, b2.ID); err != nil {
		t.Fatal(err)
	}
	if r := f.Int(`SELECT reserved_bytes FROM upload_batches WHERE id = ?`, b2.ID); r != 0 {
		t.Fatalf("reserved after abort = %d", r)
	}
	if err := f.svc.AbortFile(f.ctx, a, refID(b1, "a")); err != nil {
		t.Fatal(err)
	}
	if r := f.Int(`SELECT reserved_bytes FROM upload_batches WHERE id = ?`, b1.ID); r != 0 {
		t.Fatalf("reserved after file abort = %d", r)
	}
	// Now 20 bytes are used and nothing is reserved: 80 fit, 81 do not.
	_, err = f.svc.CreateBatch(f.ctx, a, core.BatchInput{FolderID: f.aliceRoot,
		Files: []core.UploadFileInput{{ClientRef: "d", RelPath: "d.bin", Size: 81}}})
	wantCode(t, err, core.ErrQuota)
	f.batch(a, core.BatchInput{FolderID: f.aliceRoot, Files: []core.UploadFileInput{{ClientRef: "d", RelPath: "d.bin", Size: 80}}})
	// Unlimited again.
	f.SetQuota(f.alice, nil)
	f.batch(a, core.BatchInput{FolderID: f.aliceRoot, Files: []core.UploadFileInput{{ClientRef: "e", RelPath: "e.bin", Size: 1 << 40}}})
}

// TestSpaceQuotaMessageHidesOwnerFreeSpace pins the split checkSpaceQuota
// makes: the owner sees the exact remaining space, a file-request uploader
// only learns that the size they declared does not fit. The refusal reaches
// anonymous visitors verbatim (httpx.Error), so the owner's free space must
// not be in it.
func TestSpaceQuotaMessageHidesOwnerFreeSpace(t *testing.T) {
	f := setup(t)
	q := int64(100)
	f.SetQuota(f.alice, &q)
	f.PutFile(f.aliceRoot, "existing.txt", []byte("0123456789")) // 10 of 100 used, 90 left

	// The owner uploading normally keeps the diagnostic figures.
	_, err := f.svc.CreateBatch(f.ctx, f.actor(f.alice), core.BatchInput{FolderID: f.aliceRoot,
		Files: []core.UploadFileInput{{ClientRef: "a", RelPath: "a.bin", Size: 200}}})
	wantCode(t, err, core.ErrQuota)
	if msg := core.AsError(err).Message; msg != "not enough storage space: the upload needs 200 B, 90 B are available" {
		t.Fatalf("owner message = %q, want the needed and the available bytes", msg)
	}

	// Through a file request, the same refusal names only the declared size.
	inbox := f.Mkdir(f.aliceRoot, "Inbox")
	shareID := f.share(f.alice, inbox, nil) // no upload quota: the space quota refuses
	a := f.requestActor(f.alice, shareID, "Eve")
	wantSafe := func(t *testing.T, err error) {
		t.Helper()
		wantCode(t, err, core.ErrQuota)
		msg := core.AsError(err).Message
		if !strings.Contains(msg, "200 B") {
			t.Fatalf("share message = %q, want the size the visitor declared", msg)
		}
		for _, leak := range []string{"90", "available", "100"} {
			if strings.Contains(msg, leak) {
				t.Fatalf("share message = %q leaks the owner's free space (%q)", msg, leak)
			}
		}
	}
	_, err = f.svc.CreateBatch(f.ctx, a, core.BatchInput{Files: []core.UploadFileInput{
		{ClientRef: "a", RelPath: "a.bin", Size: 200}}})
	wantSafe(t, err)

	// AddFiles on an open request batch is the same disclosure.
	b := f.batch(a, core.BatchInput{Files: []core.UploadFileInput{{ClientRef: "a", RelPath: "a.bin", Size: 10}}})
	_, err = f.svc.AddFiles(f.ctx, a, b.ID, []core.UploadFileInput{{ClientRef: "b", RelPath: "b.bin", Size: 200}})
	wantSafe(t, err)

	// A signed-in user uploading through the request link is a visitor too.
	share := f.requestActor(f.alice, shareID, "")
	share.P = f.P(f.alice)
	_, err = f.svc.CreateBatch(f.ctx, share, core.BatchInput{Uploader: "Alice",
		Files: []core.UploadFileInput{{ClientRef: "c", RelPath: "c.bin", Size: 200}}})
	wantSafe(t, err)

	// The share's own upload quota still names its numbers: the owner chose
	// them for uploaders.
	f.Exec(`UPDATE shares SET upload_quota_bytes = 20 WHERE id = ?`, shareID)
	_, err = f.svc.CreateBatch(f.ctx, a, core.BatchInput{Files: []core.UploadFileInput{
		{ClientRef: "d", RelPath: "d.bin", Size: 15}}})
	wantCode(t, err, core.ErrQuota)
	if msg := core.AsError(err).Message; msg != "this file request cannot take 15 B more (10 B left)" {
		t.Fatalf("request quota message = %q, want the request's own figures", msg)
	}
}

func TestDefaultQuotaAndMaxFile(t *testing.T) {
	f := setup(t)
	a := f.actor(f.alice)
	f.Settings.Put(settingMaxFileGB, 1)
	_, err := f.svc.CreateBatch(f.ctx, a, core.BatchInput{FolderID: f.aliceRoot,
		Files: []core.UploadFileInput{{ClientRef: "f", RelPath: "huge", Size: gib + 1}}})
	wantCode(t, err, core.ErrTooLarge)
	f.batch(a, core.BatchInput{FolderID: f.aliceRoot, Files: []core.UploadFileInput{{ClientRef: "f", RelPath: "ok", Size: gib}}})
	f.Settings.Put(settingMaxFileGB, 0)

	// A group-like space quota (spaces.quota_bytes) caps the upload too.
	f.Exec(`UPDATE spaces SET quota_bytes = 10 WHERE owner_user_id = ?`, f.bob)
	_, err = f.svc.CreateBatch(f.ctx, f.actor(f.bob), core.BatchInput{FolderID: f.bobRoot,
		Files: []core.UploadFileInput{{ClientRef: "f", RelPath: "x", Size: 11}}})
	wantCode(t, err, core.ErrQuota)
}

func TestDiskFreeCheck(t *testing.T) {
	f := setup(t)
	a := f.actor(f.alice)
	const total = uint64(100 * gib)
	free := uint64(10 * gib)
	f.svc.diskFree = func(string) (uint64, uint64, error) { return free, total, nil }
	// 2 % of 100 GiB = 2 GiB reserve: 8 GiB fit, 8 GiB + 1 does not.
	f.batch(a, core.BatchInput{FolderID: f.aliceRoot, Files: []core.UploadFileInput{{ClientRef: "f", RelPath: "a", Size: 8 * gib}}})
	_, err := f.svc.CreateBatch(f.ctx, a, core.BatchInput{FolderID: f.aliceRoot,
		Files: []core.UploadFileInput{{ClientRef: "f", RelPath: "a", Size: 8*gib + 1}}})
	wantCode(t, err, core.ErrQuota)
	// Zip mode needs twice the space, and a little more for the zip format.
	_, err = f.svc.CreateBatch(f.ctx, a, core.BatchInput{FolderID: f.aliceRoot, Mode: core.UploadModeZip,
		Files: []core.UploadFileInput{{ClientRef: "f", RelPath: "a", Size: 4 * gib}}})
	wantCode(t, err, core.ErrQuota)
	f.batch(a, core.BatchInput{FolderID: f.aliceRoot, Mode: core.UploadModeZip,
		Files: []core.UploadFileInput{{ClientRef: "f", RelPath: "a", Size: 4*gib - 1<<20}}})
	// The refusal names what the upload needs and the floor the server
	// keeps, so a small file rejected by the floor is not indistinguishable
	// from a genuinely full disk. The actual free figure stays out of it:
	// the same message reaches anonymous file-request visitors.
	free = uint64(1*gib + 30)
	_, err = f.svc.CreateBatch(f.ctx, a, core.BatchInput{FolderID: f.aliceRoot,
		Files: []core.UploadFileInput{{ClientRef: "f", RelPath: "a", Size: 30}}})
	wantCode(t, err, core.ErrQuota)
	if msg := core.AsError(err).Message; !strings.Contains(msg, "30 B") || !strings.Contains(msg, "2.0 GiB") ||
		strings.Contains(msg, "1.0 GiB") {
		t.Fatalf("disk message = %q, want the needed size and the reserve, not the free size", msg)
	}
	// A failing statfs does not block uploads.
	f.svc.diskFree = func(string) (uint64, uint64, error) { return 0, 0, errors.New("no statfs") }
	f.batch(a, core.BatchInput{FolderID: f.aliceRoot, Files: []core.UploadFileInput{{ClientRef: "f", RelPath: "a", Size: 50 * gib}}})
}

func TestOpenBatchCap(t *testing.T) {
	f := setup(t)
	a := f.actor(f.alice)
	var first *core.UploadBatch
	for i := range MaxOpenBatchesPerUser {
		b := f.batch(a, core.BatchInput{FolderID: f.aliceRoot})
		if i == 0 {
			first = b
		}
	}
	_, err := f.svc.CreateBatch(f.ctx, a, core.BatchInput{FolderID: f.aliceRoot})
	// 409, not 429: clients retry a 429 by themselves, and the CLI would say
	// "wait a minute" for a block that lasts until batches end or expire.
	wantCode(t, err, core.ErrConflict)
	if msg := core.AsError(err).Message; !strings.Contains(msg, "at most 20") || !strings.Contains(msg, "48 hours after they started") {
		t.Fatalf("cap message %q", msg)
	}
	// Other users are not affected.
	f.batch(f.actor(f.bob), core.BatchInput{FolderID: f.bobRoot})
	// Finishing one frees a slot.
	f.complete(a, first.ID)
	f.batch(a, core.BatchInput{FolderID: f.aliceRoot})
}

// ---------- aborts & expiry ----------

func TestAbort(t *testing.T) {
	f := setup(t)
	a := f.actor(f.alice)
	data := content(core.PartSize+10, 5)
	b := f.batch(a, core.BatchInput{FolderID: f.aliceRoot, Files: []core.UploadFileInput{
		{ClientRef: "kept", RelPath: "kept.txt", Size: 4},
		{ClientRef: "big", RelPath: "big.bin", Size: int64(len(data))},
		{ClientRef: "big2", RelPath: "big2.bin", Size: int64(len(data))},
	}})
	f.small(a, b.ID, "kept", []byte("keep"))
	f.parts(a, refID(b, "big"), data, 0)
	f.parts(a, refID(b, "big2"), data, 1)
	if f.Blobs.Count() != 3 {
		t.Fatalf("blobs = %d", f.Blobs.Count())
	}

	// Abort one file: its staged blob and parts are gone.
	if err := f.svc.AbortFile(f.ctx, a, refID(b, "big2")); err != nil {
		t.Fatal(err)
	}
	if err := f.svc.AbortFile(f.ctx, a, refID(b, "big2")); err != nil {
		t.Fatalf("second abort: %v", err)
	}
	if f.Blobs.Count() != 2 || f.Int(`SELECT COUNT(*) FROM upload_parts WHERE upload_id = ?`, refID(b, "big2")) != 0 {
		t.Fatal("aborted file left data behind")
	}
	p := part(data, 0)
	err := f.svc.PutPart(f.ctx, a, refID(b, "big2"), 0, bytes.NewReader(p), int64(len(p)), digest(p))
	wantCode(t, err, core.ErrConflict)
	wantCode(t, f.svc.AbortFile(f.ctx, a, refID(b, "kept")), core.ErrConflict)
	wantCode(t, f.svc.AbortFile(f.ctx, f.actor(f.bob), refID(b, "big")), core.ErrNotFound)

	// Abort the batch: remaining staged data is deleted, committed files stay.
	wantCode(t, f.svc.AbortBatch(f.ctx, f.actor(f.bob), b.ID), core.ErrNotFound)
	if err := f.svc.AbortBatch(f.ctx, a, b.ID); err != nil {
		t.Fatal(err)
	}
	if err := f.svc.AbortBatch(f.ctx, a, b.ID); err != nil {
		t.Fatalf("abort twice: %v", err)
	}
	if st := f.batchState(b.ID); st != core.BatchAborted {
		t.Fatalf("state = %s", st)
	}
	if f.Blobs.Count() != 1 {
		t.Fatalf("blobs after abort = %d, want 1 (the committed file)", f.Blobs.Count())
	}
	if got, _ := f.nodeContent(f.aliceRoot, "kept.txt"); string(got) != "keep" {
		t.Fatal("committed file lost")
	}
	st, _ := f.svc.Status(f.ctx, a, refID(b, "big"))
	if st.State != core.UploadAborted || len(st.PartsDone) != 0 {
		t.Fatalf("aborted file: %+v", st)
	}
	err = f.svc.PutPart(f.ctx, a, refID(b, "big"), 1, bytes.NewReader(part(data, 1)), 10, digest(part(data, 1)))
	wantCode(t, err, core.ErrConflict)
	_, err = f.svc.CompleteBatch(f.ctx, a, b.ID)
	wantCode(t, err, core.ErrConflict)
	_, err = f.svc.PutSmall(f.ctx, a, b.ID, "kept", strings.NewReader("KEEP"), 4, digest([]byte("KEEP")))
	wantCode(t, err, core.ErrConflict)
}

func TestExpireStale(t *testing.T) {
	f := setup(t)
	a := f.actor(f.alice)
	data := content(core.PartSize+1, 6)
	stale := f.batch(a, core.BatchInput{FolderID: f.aliceRoot, Files: []core.UploadFileInput{
		{ClientRef: "big", RelPath: "big.bin", Size: int64(len(data))}}})
	f.parts(a, refID(stale, "big"), data, 0)
	done := f.batch(a, core.BatchInput{FolderID: f.aliceRoot})
	f.complete(a, done.ID)

	f.Clock.Advance(DefaultExpiryHours*time.Hour - time.Minute)
	fresh := f.batch(a, core.BatchInput{FolderID: f.aliceRoot})
	if n, err := f.svc.ExpireStale(f.ctx); err != nil || n != 0 {
		t.Fatalf("early expiry: %d %v", n, err)
	}
	f.Clock.Advance(2 * time.Minute)
	n, err := f.svc.ExpireStale(f.ctx)
	if err != nil || n != 1 {
		t.Fatalf("expired %d, %v", n, err)
	}
	if st := f.batchState(stale.ID); st != core.BatchExpired {
		t.Fatalf("stale batch state = %s", st)
	}
	if f.Blobs.Count() != 0 {
		t.Fatal("staged data of an expired batch was kept")
	}
	if st := f.batchState(fresh.ID); st != core.BatchOpen {
		t.Fatalf("fresh batch state = %s", st)
	}
	// Finished batches are forgotten after a week.
	f.Clock.Advance(8 * 24 * time.Hour)
	if _, err := f.svc.ExpireStale(f.ctx); err != nil {
		t.Fatal(err)
	}
	if n := f.Int(`SELECT COUNT(*) FROM upload_batches WHERE id IN (?, ?)`, stale.ID, done.ID); n != 0 {
		t.Fatalf("%d finished batches kept", n)
	}
	// The batch created later expired in the last run and is kept for a week.
	if st := f.batchState(fresh.ID); st != core.BatchExpired {
		t.Fatalf("fresh batch state = %s", st)
	}
	// The job wrapper stores the count as its result.
	h := &resultHandle{}
	if err := f.svc.runExpireJob(f.ctx, h); err != nil || !strings.Contains(string(h.result), `"expired":0`) {
		t.Fatalf("job result %s, %v", h.result, err)
	}
}

type resultHandle struct {
	nopHandle
	result []byte
}

func (h *resultHandle) SetResult(v any) { h.result, _ = json.Marshal(v) }

func mustAddr(t *testing.T, s string) netip.Addr {
	t.Helper()
	a, err := netip.ParseAddr(s)
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func TestExpirySetting(t *testing.T) {
	f := setup(t)
	f.Settings.Put(SettingExpiryHours, 2)
	b := f.batch(f.actor(f.alice), core.BatchInput{FolderID: f.aliceRoot})
	if want := f.Clock.Now().Add(2 * time.Hour); !b.ExpiresAt.Equal(want) {
		t.Fatalf("expires_at = %v, want %v", b.ExpiresAt, want)
	}
}

// ---------- zip on upload ----------

func TestZipOnUpload(t *testing.T) {
	f := setup(t)
	f.Jobs.Manual = true
	a := f.actor(f.alice)
	ch, unsub := f.Bus.Subscribe(events.TopicUploadBatchDone)
	defer unsub()
	big := content(core.PartSize+100, 7)
	files := map[string][]byte{
		"Trip/day1/a.txt": []byte("hello a"),
		"Trip/day2/b.txt": []byte("hello b"),
		"Trip/big.bin":    big,
		"top.txt":         {},
	}
	in := core.BatchInput{FolderID: f.aliceRoot, Mode: core.UploadModeZip, ZipName: "Holiday", Files: []core.UploadFileInput{
		{ClientRef: "d", RelPath: "Trip/empty", Kind: "dir", MTime: 1726700000000},
	}}
	i := 0
	for p, c := range files {
		in.Files = append(in.Files, core.UploadFileInput{ClientRef: fmt.Sprint("f", i), RelPath: p, Size: int64(len(c))})
		i++
	}
	b := f.batch(a, in)
	for _, fs := range b.Files {
		c := files[fs.RelPath]
		switch {
		case fs.Kind == core.UploadKindDir:
		case len(c) <= SmallMax:
			st := f.small(a, b.ID, fs.ClientRef, c)
			if st.State != core.UploadUploaded || st.NodeID != "" {
				t.Fatalf("zip-mode small file must stay staged: %+v", st)
			}
		default:
			f.parts(a, fs.ID, c, 1, 0)
			st, err := f.svc.CompleteFile(f.ctx, a, fs.ID)
			if err != nil || st.State != core.UploadUploaded {
				t.Fatalf("complete big: %+v %v", st, err)
			}
		}
	}
	if n := f.Int(`SELECT COUNT(*) FROM nodes WHERE kind = 'file'`); n != 0 {
		t.Fatalf("%d nodes created before the zip", n)
	}
	staged := f.Blobs.Count()

	fin := f.complete(a, b.ID)
	if fin.State != core.BatchFinalizing || fin.JobID == "" {
		t.Fatalf("complete = %+v", fin)
	}
	// Completing a finalizing batch again returns it; aborting is refused.
	if again := f.complete(a, b.ID); again.State != core.BatchFinalizing {
		t.Fatalf("again = %+v", again)
	}
	wantCode(t, f.svc.AbortBatch(f.ctx, a, b.ID), core.ErrConflict)
	if err := f.Jobs.Run(fin.JobID); err != nil {
		t.Fatalf("zip job: %v", err)
	}

	got, err := f.svc.GetBatch(f.ctx, a, b.ID)
	if err != nil || got.State != core.BatchDone || got.ResultNodeID == "" || got.ReservedBytes != 0 {
		t.Fatalf("batch after job: %+v %v", got, err)
	}
	zipData, node := f.nodeContent(f.aliceRoot, "Holiday.zip")
	if node.ID != got.ResultNodeID {
		t.Fatalf("result node %s != %s", got.ResultNodeID, node.ID)
	}
	zr, err := zip.NewReader(bytes.NewReader(zipData), int64(len(zipData)))
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, zf := range zr.File {
		names = append(names, zf.Name)
		if strings.HasSuffix(zf.Name, "/") {
			continue
		}
		rc, err := zf.Open()
		if err != nil {
			t.Fatal(err)
		}
		c, _ := io.ReadAll(rc)
		rc.Close()
		if !bytes.Equal(c, files[zf.Name]) {
			t.Errorf("%s: content differs", zf.Name)
		}
	}
	for p := range files {
		if !slices.Contains(names, p) {
			t.Errorf("zip lacks %s (entries %v)", p, names)
		}
	}
	if !slices.Contains(names, "Trip/empty/") {
		t.Errorf("zip lacks the empty directory (entries %v)", names)
	}
	// Staged blobs are gone; only the zip remains.
	if f.Blobs.Count() != 1 || staged != 4 {
		t.Fatalf("blobs = %d (staged %d)", f.Blobs.Count(), staged)
	}
	for _, fs := range got.Files {
		if fs.State != core.UploadCommitted || fs.NodeID != node.ID {
			t.Errorf("file %s: %+v", fs.RelPath, fs)
		}
	}
	job, _ := f.Jobs.Get(f.ctx, fin.JobID)
	if job.State != core.JobSucceeded || job.ProgressDone != job.ProgressTotal || len(job.Result) == 0 {
		t.Errorf("job = %+v", job)
	}
	select {
	case ev := <-ch:
		if ev.Data.(core.UploadBatchEvent).Batch.State != core.BatchDone {
			t.Errorf("event %+v", ev)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("no upload.batch_done")
	}

	// A second zip with the same name is renamed (conflict policy).
	b2 := f.batch(a, core.BatchInput{FolderID: f.aliceRoot, Mode: core.UploadModeZip, ZipName: "Holiday.zip",
		Files: []core.UploadFileInput{{ClientRef: "x", RelPath: "x.txt", Size: 1}}})
	f.small(a, b2.ID, "x", []byte("x"))
	fin2 := f.complete(a, b2.ID)
	if err := f.Jobs.Run(fin2.JobID); err != nil {
		t.Fatal(err)
	}
	if _, n := f.nodeContent(f.aliceRoot, "Holiday (1).zip"); n == nil {
		t.Fatal("renamed zip missing")
	}
}

func TestZipIncompleteAndFailure(t *testing.T) {
	f := setup(t)
	f.Jobs.Manual = true
	a := f.actor(f.alice)
	folder := f.Mkdir(f.aliceRoot, "Dest")
	b := f.batch(a, core.BatchInput{FolderID: folder, Mode: core.UploadModeZip,
		Files: []core.UploadFileInput{{ClientRef: "a", RelPath: "a.txt", Size: 1}, {ClientRef: "b", RelPath: "b.txt", Size: 1}}})
	f.small(a, b.ID, "a", []byte("a"))
	_, err := f.svc.CompleteBatch(f.ctx, a, b.ID)
	wantCode(t, err, core.ErrConflict) // b.txt missing
	f.small(a, b.ID, "b", []byte("b"))
	fin := f.complete(a, b.ID)

	// The destination disappears before the job runs: the batch fails and
	// the staged data is deleted.
	if err := f.Files.Trash(f.ctx, a.P, []string{folder}); err != nil {
		t.Fatal(err)
	}
	if err := f.Jobs.Run(fin.JobID); err == nil {
		t.Fatal("zip job succeeded without a destination")
	}
	got, _ := f.svc.GetBatch(f.ctx, a, b.ID)
	if got.State != core.BatchFailed || got.Error == "" || got.ReservedBytes != 0 {
		t.Fatalf("batch = %+v", got)
	}
	if f.Blobs.Count() != 0 {
		t.Fatalf("%d blobs left after a failed zip", f.Blobs.Count())
	}
	if e, ok := f.Audit.Find(core.ActFileUpload); !ok || e.Outcome != core.OutcomeFailure {
		t.Fatalf("failure audit = %+v %v", e, ok)
	}
	// A finished batch's job running again is a no-op.
	if err := f.svc.zipBatch(f.ctx, &nopHandle{}, b.ID); err != nil {
		t.Fatal(err)
	}
}

func TestFailStuckZips(t *testing.T) {
	f := setup(t)
	f.Jobs.Manual = true
	a := f.actor(f.alice)
	b := f.batch(a, core.BatchInput{FolderID: f.aliceRoot, Mode: core.UploadModeZip,
		Files: []core.UploadFileInput{{ClientRef: "a", RelPath: "a.txt", Size: 1}}})
	f.small(a, b.ID, "a", []byte("a"))
	fin := f.complete(a, b.ID)
	// While the job is queued nothing happens.
	if _, err := f.svc.ExpireStale(f.ctx); err != nil {
		t.Fatal(err)
	}
	if st := f.batchState(b.ID); st != core.BatchFinalizing {
		t.Fatalf("state = %s", st)
	}
	// The job died (a restart, a crash): the staged data is intact, so the
	// zip is enqueued again instead of throwing the upload away.
	f.Jobs.SetState(fin.JobID, core.JobFailed)
	if _, err := f.svc.ExpireStale(f.ctx); err != nil {
		t.Fatal(err)
	}
	if st := f.batchState(b.ID); st != core.BatchFinalizing {
		t.Fatalf("state after an interrupted job = %s, want finalizing", st)
	}
	rerun := f.Str(`SELECT job_id FROM upload_batches WHERE id = ?`, b.ID)
	if rerun == "" || rerun == fin.JobID || f.Blobs.Count() != 1 {
		t.Fatalf("job %q (was %s), blobs %d: the zip was not re-enqueued with its data", rerun, fin.JobID, f.Blobs.Count())
	}
	if err := f.Jobs.Run(rerun); err != nil {
		t.Fatalf("re-run: %v", err)
	}
	if st := f.batchState(b.ID); st != core.BatchDone {
		t.Fatalf("state after the re-run = %s", st)
	}
	if got, _ := f.zipNames(f.aliceRoot, b.ZipName); strings.Join(got, ",") != "a.txt" {
		t.Fatalf("zip entries %v", got)
	}

	// A job cancelled by hand fails the batch and deletes its staged data.
	b2 := f.batch(a, core.BatchInput{FolderID: f.aliceRoot, Mode: core.UploadModeZip,
		Files: []core.UploadFileInput{{ClientRef: "a", RelPath: "a.txt", Size: 1}}})
	f.small(a, b2.ID, "a", []byte("a"))
	fin2 := f.complete(a, b2.ID)
	f.Jobs.SetState(fin2.JobID, core.JobCanceled)
	if _, err := f.svc.ExpireStale(f.ctx); err != nil {
		t.Fatal(err)
	}
	if st := f.batchState(b2.ID); st != core.BatchFailed {
		t.Fatalf("state after a cancelled job = %s", st)
	}
	if f.Blobs.Count() != 1 { // the zip of the first batch
		t.Fatalf("blobs = %d: staged blob of the failed batch kept", f.Blobs.Count())
	}

	// A batch that never got its job id (the process died while enqueueing)
	// is left alone for an hour, then enqueued. Retries end once a batch has
	// been finalizing for storage.upload_expiry_hours: it is failed.
	b3 := f.batch(a, core.BatchInput{FolderID: f.aliceRoot, Mode: core.UploadModeZip,
		Files: []core.UploadFileInput{{ClientRef: "a", RelPath: "a.txt", Size: 1}}})
	f.small(a, b3.ID, "a", []byte("a"))
	fin3 := f.complete(a, b3.ID)
	f.Exec(`UPDATE upload_batches SET job_id = NULL WHERE id = ?`, b3.ID)
	f.Clock.Advance(30 * time.Minute)
	if _, err := f.svc.ExpireStale(f.ctx); err != nil {
		t.Fatal(err)
	}
	if got := f.Str(`SELECT job_id FROM upload_batches WHERE id = ?`, b3.ID); got != "" || f.batchState(b3.ID) != core.BatchFinalizing {
		t.Fatalf("a batch being enqueued was touched: job %q, state %s", got, f.batchState(b3.ID))
	}
	f.Clock.Advance(time.Hour)
	if _, err := f.svc.ExpireStale(f.ctx); err != nil {
		t.Fatal(err)
	}
	again := f.Str(`SELECT job_id FROM upload_batches WHERE id = ?`, b3.ID)
	if again == "" || again == fin3.JobID || f.batchState(b3.ID) != core.BatchFinalizing {
		t.Fatalf("a batch without a job was not re-enqueued: job %q, state %s", again, f.batchState(b3.ID))
	}
	f.Jobs.SetState(again, core.JobFailed)
	f.Clock.Advance(DefaultExpiryHours * time.Hour)
	if _, err := f.svc.ExpireStale(f.ctx); err != nil {
		t.Fatal(err)
	}
	if st := f.batchState(b3.ID); st != core.BatchFailed {
		t.Fatalf("state past the retry bound = %s", st)
	}
}

// zipNames returns the sorted entry names of the zip file name in folder.
func (f *fixture) zipNames(folder, name string) ([]string, []byte) {
	f.t.Helper()
	data, _ := f.nodeContent(folder, name)
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		f.t.Fatal(err)
	}
	var out []string
	for _, zf := range zr.File {
		out = append(out, zf.Name)
	}
	slices.Sort(out)
	return out, data
}

// cancelHandle cancels the job's context on its first progress report.
type cancelHandle struct {
	nopHandle
	cancel context.CancelFunc
}

func (h *cancelHandle) Progress(int64, int64, string) { h.cancel() }

// TestZipInterruptedKeepsData pins that a zip job cut short by a shutdown
// (its context is cancelled) leaves the batch finalizing with its staged
// data, and no partial zip behind: maintenance.uploads runs it again.
func TestZipInterruptedKeepsData(t *testing.T) {
	f := setup(t)
	f.Jobs.Manual = true
	a := f.actor(f.alice)
	b := f.batch(a, core.BatchInput{FolderID: f.aliceRoot, Mode: core.UploadModeZip,
		Files: []core.UploadFileInput{{ClientRef: "a", RelPath: "a.txt", Size: 1}, {ClientRef: "b", RelPath: "b.txt", Size: 2}}})
	f.small(a, b.ID, "a", []byte("a"))
	f.small(a, b.ID, "b", []byte("bb"))
	fin := f.complete(a, b.ID)
	// The shutdown comes once the job has started writing the zip.
	ctx, cancel := context.WithCancel(f.ctx)
	defer cancel()
	if err := f.svc.zipBatch(ctx, &cancelHandle{cancel: cancel}, b.ID); !errors.Is(err, context.Canceled) {
		t.Fatalf("zipBatch = %v, want context.Canceled", err)
	}
	if st := f.batchState(b.ID); st != core.BatchFinalizing {
		t.Fatalf("state = %s, want finalizing", st)
	}
	if n := f.Blobs.Count(); n != 2 {
		t.Fatalf("blobs = %d, want the 2 staged ones", n)
	}
	if n := f.Int(`SELECT COUNT(*) FROM upload_files WHERE batch_id = ? AND state = 'uploaded' AND blob_id IS NOT NULL`, b.ID); n != 2 {
		t.Fatalf("%d staged files left", n)
	}
	// The job that ended that way is re-run, and the zip is complete.
	f.Jobs.SetState(fin.JobID, core.JobFailed)
	if _, err := f.svc.ExpireStale(f.ctx); err != nil {
		t.Fatal(err)
	}
	if err := f.Jobs.Run(f.Str(`SELECT job_id FROM upload_batches WHERE id = ?`, b.ID)); err != nil {
		t.Fatal(err)
	}
	if got, _ := f.zipNames(f.aliceRoot, b.ZipName); strings.Join(got, ",") != "a.txt,b.txt" {
		t.Fatalf("zip entries %v", got)
	}
}

type nopHandle struct{}

func (nopHandle) ID() string                    { return "job_test" }
func (nopHandle) Params(any) error              { return nil }
func (nopHandle) Progress(int64, int64, string) {}
func (nopHandle) SetResult(any)                 {}

// ---------- file requests ----------

func TestFileRequestLimits(t *testing.T) {
	f := setup(t)
	inbox := f.Mkdir(f.aliceRoot, "Inbox")
	shareID := f.share(f.alice, inbox, map[string]any{"upload_max_file_bytes": 100, "upload_quota_bytes": 150,
		"require_uploader_name": 1, "notify_owner": 1})
	a := f.requestActor(f.alice, shareID, "")

	cases := []struct {
		name string
		a    core.UploadActor
		in   core.BatchInput
		code *core.Error
	}{
		{"no uploader name", a, core.BatchInput{Files: []core.UploadFileInput{{ClientRef: "f", RelPath: "f", Size: 1}}}, core.ErrInvalid},
		{"file too large", a, core.BatchInput{Uploader: "Eve", Files: []core.UploadFileInput{{ClientRef: "f", RelPath: "f", Size: 101}}}, core.ErrTooLarge},
		{"over request quota", a, core.BatchInput{Uploader: "Eve", Files: []core.UploadFileInput{
			{ClientRef: "f", RelPath: "f", Size: 100}, {ClientRef: "g", RelPath: "g", Size: 51}}}, core.ErrQuota},
		{"other folder", a, core.BatchInput{Uploader: "Eve", FolderID: f.aliceRoot}, core.ErrInvalid},
		{"wrong principal", f.requestActor(f.bob, shareID, "Eve"), core.BatchInput{}, core.ErrForbidden},
		{"control char name", a, core.BatchInput{Uploader: "Ev\x00e"}, core.ErrInvalid},
		{"unknown share", f.requestActor(f.alice, "shr_00000000000000000000000000", "Eve"), core.BatchInput{}, core.ErrNotFound},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := f.svc.CreateBatch(f.ctx, c.a, c.in)
			wantCode(t, err, c.code)
		})
	}

	a.Uploader = "Eve"
	b := f.batch(a, core.BatchInput{Conflict: core.ConflictReplace, Files: []core.UploadFileInput{
		{ClientRef: "f", RelPath: "report.txt", Size: 5}, {ClientRef: "g", RelPath: "sub/g.txt", Size: 3}}})
	if b.UserID != f.alice || b.ShareID != shareID || b.FolderID != inbox || b.Conflict != core.ConflictRename || b.Uploader != "Eve" {
		t.Fatalf("request batch = %+v", b)
	}
	// Owners and other shares cannot touch the request's batch, and vice versa.
	_, err := f.svc.GetBatch(f.ctx, f.actor(f.alice), b.ID)
	wantCode(t, err, core.ErrNotFound)
	other := f.share(f.alice, inbox, nil)
	_, err = f.svc.GetBatch(f.ctx, f.requestActor(f.alice, other, ""), b.ID)
	wantCode(t, err, core.ErrNotFound)
	own := f.batch(f.actor(f.alice), core.BatchInput{FolderID: f.aliceRoot})
	_, err = f.svc.GetBatch(f.ctx, a, own.ID)
	wantCode(t, err, core.ErrNotFound)

	f.PutFile(inbox, "report.txt", []byte("older"))
	f.small(a, b.ID, "f", []byte("hello"))
	f.small(a, b.ID, "g", []byte("abc"))
	done := f.complete(a, b.ID)
	if done.State != core.BatchDone {
		t.Fatalf("done = %+v", done)
	}
	if got, _ := f.nodeContent(inbox, "report (1).txt"); string(got) != "hello" {
		t.Fatalf("renamed upload content %q", got)
	}
	if used := f.Int(`SELECT upload_used_bytes FROM shares WHERE id = ?`, shareID); used != 8 {
		t.Fatalf("upload_used_bytes = %d", used)
	}
	acc := f.shares.accesses()
	if len(acc) != 1 || acc[0].Action != core.AccessUpload || acc[0].Uploader != "Eve" || acc[0].Bytes != 8 {
		t.Fatalf("access log = %+v", acc)
	}
	e, ok := f.Audit.Find(core.ActRequestUpload)
	if !ok || e.TargetID != shareID || e.ActorName != "Eve" || e.ActorVia != string(core.ViaShare) {
		t.Fatalf("audit = %+v %v", e, ok)
	}
	// 8 of 150 bytes used: 142 more fit, 143 do not (per-file limit 100 applies too).
	_, err = f.svc.CreateBatch(f.ctx, a, core.BatchInput{Files: []core.UploadFileInput{
		{ClientRef: "a", RelPath: "a", Size: 100}, {ClientRef: "b", RelPath: "b", Size: 43}}})
	wantCode(t, err, core.ErrQuota)
	b2 := f.batch(a, core.BatchInput{Files: []core.UploadFileInput{
		{ClientRef: "a", RelPath: "a", Size: 100}, {ClientRef: "b", RelPath: "b", Size: 42}}})
	_, err = f.svc.AddFiles(f.ctx, a, b2.ID, []core.UploadFileInput{{ClientRef: "c", RelPath: "c", Size: 1}})
	wantCode(t, err, core.ErrQuota)
	_, err = f.svc.AddFiles(f.ctx, a, b2.ID, []core.UploadFileInput{{ClientRef: "c", RelPath: "c", Size: 101}})
	wantCode(t, err, core.ErrTooLarge)

	// A disabled (or expired) request refuses new batches.
	f.Exec(`UPDATE shares SET disabled_at = 1 WHERE id = ?`, shareID)
	_, err = f.svc.CreateBatch(f.ctx, a, core.BatchInput{})
	wantCode(t, err, core.ErrNotFound)
	f.Exec(`UPDATE shares SET disabled_at = NULL, expires_at = ? WHERE id = ?`, db.Ms(f.Clock.Now()), shareID)
	_, err = f.svc.CreateBatch(f.ctx, a, core.BatchInput{})
	wantCode(t, err, core.ErrNotFound)
	f.Exec(`UPDATE shares SET expires_at = NULL, allow_upload = 0 WHERE id = ?`, shareID)
	_, err = f.svc.CreateBatch(f.ctx, a, core.BatchInput{})
	wantCode(t, err, core.ErrNotFound)
}

func TestFileRequestOpenCaps(t *testing.T) {
	f := setup(t)
	shareID := f.share(f.alice, f.aliceRoot, nil)
	a := f.requestActor(f.alice, shareID, "")
	a.P.IP = mustAddr(t, "192.0.2.7")
	for range MaxOpenBatchesPerShareClient {
		f.batch(a, core.BatchInput{})
	}
	_, err := f.svc.CreateBatch(f.ctx, a, core.BatchInput{})
	wantCode(t, err, core.ErrRateLimited)
	// Another client of the same request is not blocked; the owner's own
	// uploads are counted separately.
	b := f.requestActor(f.alice, shareID, "")
	b.P.IP = mustAddr(t, "192.0.2.8")
	f.batch(b, core.BatchInput{})
	f.batch(f.actor(f.alice), core.BatchInput{FolderID: f.aliceRoot})

	// The cap counts by client IP, so dropping the visitor cookie (or getting
	// a new one) does not reset it.
	fresh := f.requestActor(f.alice, shareID, "")
	fresh.P.IP, fresh.P.SessionID = mustAddr(t, "192.0.2.7"), "brand-new-visitor"
	_, err = f.svc.CreateBatch(f.ctx, fresh, core.BatchInput{})
	wantCode(t, err, core.ErrRateLimited)
	// A different address whose text starts like the capped one is its own
	// client (the comparison includes the separator).
	near := f.requestActor(f.alice, shareID, "")
	near.P.IP, near.P.SessionID = mustAddr(t, "192.0.2.70"), "other-visitor"
	f.batch(near, core.BatchInput{})
}

// TestRequestBatchBoundToVisitor pins that a file-request batch belongs to
// the visitor that opened it, not to everyone holding the share token.
func TestRequestBatchBoundToVisitor(t *testing.T) {
	f := setup(t)
	inbox := f.Mkdir(f.aliceRoot, "Inbox")
	shareID := f.share(f.alice, inbox, nil)
	visitor := func(id string) core.UploadActor {
		a := f.requestActor(f.alice, shareID, "")
		a.P.IP, a.P.SessionID = mustAddr(t, "198.51.100.9"), id // same IP, different visitor
		return a
	}
	one, two, anon := visitor("visitor-one"), visitor("visitor-two"), f.requestActor(f.alice, shareID, "")
	anon.P.IP = mustAddr(t, "198.51.100.9")

	b := f.batch(one, core.BatchInput{Files: []core.UploadFileInput{{ClientRef: "a", RelPath: "mine.txt", Size: 5}}})
	if got := f.Str(`SELECT actor_session FROM upload_batches WHERE id = ?`, b.ID); got != "ip:198.51.100.9|vis:visitor-one" {
		t.Fatalf("actor_session = %q", got)
	}
	for _, other := range []core.UploadActor{two, anon} {
		_, err := f.svc.GetBatch(f.ctx, other, b.ID)
		wantCode(t, err, core.ErrNotFound)
		_, err = f.svc.AddFiles(f.ctx, other, b.ID, []core.UploadFileInput{{ClientRef: "c", RelPath: "c", Size: 1}})
		wantCode(t, err, core.ErrNotFound)
		_, err = f.svc.Status(f.ctx, other, b.Files[0].ID)
		wantCode(t, err, core.ErrNotFound)
		wantCode(t, f.svc.AbortBatch(f.ctx, other, b.ID), core.ErrNotFound)
	}
	if _, err := f.svc.GetBatch(f.ctx, one, b.ID); err != nil {
		t.Fatalf("own batch: %v", err)
	}

	// A batch opened by a client that sends no visitor id stays share-wide:
	// there is nothing to bind it to, and locking its own client out would be
	// worse than the status quo.
	old := f.batch(anon, core.BatchInput{Files: []core.UploadFileInput{{ClientRef: "a", RelPath: "script.txt", Size: 5}}})
	if _, err := f.svc.GetBatch(f.ctx, two, old.ID); err != nil {
		t.Fatalf("cookie-less batch: %v", err)
	}

	// shares.Revoke aborts what is left of a request with an actor that has no
	// principal at all; it owns every batch of its share.
	if err := f.svc.AbortBatch(f.ctx, core.UploadActor{ShareID: shareID}, b.ID); err != nil {
		t.Fatalf("revoke abort: %v", err)
	}
	if st := f.batchState(b.ID); st != core.BatchAborted {
		t.Fatalf("state after revoke abort = %q", st)
	}
	wantCode(t, f.svc.AbortBatch(f.ctx, core.UploadActor{ShareID: ids.New(ids.PrefixShare)}, old.ID), core.ErrNotFound)
}

// ---------- completion robustness ----------

func TestCompleteAfterLostBookkeeping(t *testing.T) {
	f := setup(t)
	a := f.actor(f.alice)
	data := content(core.PartSize+7, 8)
	b := f.batch(a, core.BatchInput{FolderID: f.aliceRoot, Files: []core.UploadFileInput{
		{ClientRef: "f", RelPath: "f.bin", Size: int64(len(data))}}})
	up := refID(b, "f")
	f.parts(a, up, data, 0, 1)
	// Simulate a crash after the blob commit but before the upload row was
	// updated: commit the blob directly.
	blobID := f.Str(`SELECT blob_id FROM upload_files WHERE id = ?`, up)
	pb, err := f.Blobs.OpenParted(f.ctx, blobID)
	if err != nil {
		t.Fatal(err)
	}
	s0, s1 := sha256.Sum256(part(data, 0)), sha256.Sum256(part(data, 1))
	if _, err := pb.Commit(f.ctx, [][]byte{s0[:], s1[:]}); err != nil {
		t.Fatal(err)
	}
	st, err := f.svc.CompleteFile(f.ctx, a, up)
	if err != nil || st.State != core.UploadCommitted {
		t.Fatalf("complete after lost bookkeeping: %+v %v", st, err)
	}
	if got, _ := f.nodeContent(f.aliceRoot, "f.bin"); !bytes.Equal(got, data) {
		t.Fatal("content differs")
	}
	if contentHash([][]byte{s0[:], s1[:]}) != uploadtest.ContentHash(data) {
		t.Fatal("contentHash differs from the blob store formula")
	}
}

func TestConcurrentSmallSends(t *testing.T) {
	f := setup(t)
	a := f.actor(f.alice)
	b := f.batch(a, core.BatchInput{FolderID: f.aliceRoot, Files: []core.UploadFileInput{{ClientRef: "f", RelPath: "f.txt", Size: 4}}})
	var wg sync.WaitGroup
	var mu sync.Mutex
	nodes := map[string]int{}
	for range 8 {
		wg.Go(func() {
			st, err := f.svc.PutSmall(context.Background(), a, b.ID, "f", strings.NewReader("data"), 4, digest([]byte("data")))
			if err != nil {
				t.Error(err)
				return
			}
			mu.Lock()
			nodes[st.NodeID]++
			mu.Unlock()
		})
	}
	wg.Wait()
	if len(nodes) != 1 || f.Int(`SELECT COUNT(*) FROM nodes WHERE kind = 'file'`) != 1 || f.Blobs.Count() != 1 {
		t.Fatalf("concurrent small sends: nodes %v, blobs %d", nodes, f.Blobs.Count())
	}
}

// TestDeclaredSizeOverflowCannotDisableQuotas pins the overflow guard on the
// declared sizes: a client-supplied size is bounded, and a batch whose
// declared sizes would wrap int64 is refused instead of storing a negative
// reservation that switches off the space quota, the file-request quota and
// the free-disk check for every later upload of the space.
func TestDeclaredSizeOverflowCannotDisableQuotas(t *testing.T) {
	f := setup(t)
	a := f.actor(f.alice)
	q := int64(1 << 20)
	f.SetQuota(f.alice, &q)

	huge := int64(1) << 62
	_, err := f.svc.CreateBatch(f.ctx, a, core.BatchInput{FolderID: f.aliceRoot, Files: []core.UploadFileInput{
		{ClientRef: "p1", RelPath: "p1.bin", Size: huge}, {ClientRef: "p2", RelPath: "p2.bin", Size: huge}}})
	if err == nil {
		t.Fatal("a batch declaring 2×2^62 bytes was accepted")
	}
	if n := f.Int(`SELECT COUNT(*) FROM upload_batches`); n != 0 {
		t.Fatalf("%d batch(es) stored", n)
	}

	// A single entry above MaxDeclaredFileBytes is refused on its own.
	_, err = f.svc.CreateBatch(f.ctx, a, core.BatchInput{FolderID: f.aliceRoot,
		Files: []core.UploadFileInput{{ClientRef: "p1", RelPath: "p1.bin", Size: MaxDeclaredFileBytes + 1}}})
	wantCode(t, err, core.ErrTooLarge)
	// The largest file accepted has exactly MaxPartCount parts, so every one
	// of its part numbers passes the routes' parsers.
	most := f.batch(f.actor(f.bob), core.BatchInput{FolderID: f.bobRoot,
		Files: []core.UploadFileInput{{ClientRef: "max", RelPath: "max.bin", Size: MaxDeclaredFileBytes}}})
	if pc := most.Files[0].PartCount; pc != MaxPartCount {
		t.Fatalf("part count of the largest file = %d, want %d", pc, MaxPartCount)
	}

	// AddFiles has the same guard, and leaves no negative reservation.
	b := f.batch(a, core.BatchInput{FolderID: f.aliceRoot,
		Files: []core.UploadFileInput{{ClientRef: "ok", RelPath: "ok.bin", Size: 10}}})
	_, err = f.svc.AddFiles(f.ctx, a, b.ID, []core.UploadFileInput{
		{ClientRef: "h1", RelPath: "h1.bin", Size: huge}, {ClientRef: "h2", RelPath: "h2.bin", Size: huge}})
	if err == nil {
		t.Fatal("AddFiles accepted 2×2^62 bytes")
	}
	if r := f.Int(`SELECT MIN(reserved_bytes) FROM upload_batches`); r < 0 {
		t.Fatalf("reserved_bytes = %d: the quota of the space is no longer enforced", r)
	}
	// The quota still refuses an upload that does not fit.
	_, err = f.svc.CreateBatch(f.ctx, a, core.BatchInput{FolderID: f.aliceRoot,
		Files: []core.UploadFileInput{{ClientRef: "big", RelPath: "big.bin", Size: 4 << 20}}})
	wantCode(t, err, core.ErrQuota)
}

// TestShareQuotaSurvivesOverflowPadding pins the same guard on the
// unauthenticated file-request path: padding entries whose sizes wrap must
// not let bytes past the request's own upload quota.
func TestShareQuotaSurvivesOverflowPadding(t *testing.T) {
	f := setup(t)
	inbox := f.Mkdir(f.aliceRoot, "inbox")
	shareID := f.share(f.alice, inbox, map[string]any{"upload_quota_bytes": 10})
	a := f.requestActor(f.alice, shareID, "Eve")

	huge := int64(1) << 62
	_, err := f.svc.CreateBatch(f.ctx, a, core.BatchInput{Uploader: "Eve", Files: []core.UploadFileInput{
		{ClientRef: "pad1", RelPath: "pad1.bin", Size: huge},
		{ClientRef: "pad2", RelPath: "pad2.bin", Size: huge},
		{ClientRef: "real", RelPath: "real.bin", Size: 50}}})
	if err == nil {
		t.Fatal("the file request took 50 bytes past its 10-byte quota through overflow padding")
	}
	if n := f.Int(`SELECT COUNT(*) FROM upload_batches`); n != 0 {
		t.Fatalf("%d batch(es) stored", n)
	}
}

// TestNegativeReservationCannotBuyQuota pins that the guards fail closed:
// a reservation that went negative in the database (a corrupt or
// hand-edited row) must not make room for another upload.
func TestNegativeReservationCannotBuyQuota(t *testing.T) {
	f := setup(t)
	a := f.actor(f.alice)
	q := int64(1 << 20)
	f.SetQuota(f.alice, &q)
	b := f.batch(a, core.BatchInput{FolderID: f.aliceRoot,
		Files: []core.UploadFileInput{{ClientRef: "a", RelPath: "a.bin", Size: 10}}})
	f.Exec(`UPDATE upload_batches SET reserved_bytes = ? WHERE id = ?`, -(int64(1) << 40), b.ID)

	_, err := f.svc.CreateBatch(f.ctx, a, core.BatchInput{FolderID: f.aliceRoot,
		Files: []core.UploadFileInput{{ClientRef: "big", RelPath: "big.bin", Size: 4 << 20}}})
	wantCode(t, err, core.ErrQuota)
}

// TestZipResultName: the upload.zip result names the .zip as stored, so the
// client announces "Photos (1).zip" when conflict "rename" numbered it.
func TestZipResultName(t *testing.T) {
	f := setup(t)
	f.Jobs.Manual = true
	a := f.actor(f.alice)
	f.PutFile(f.aliceRoot, "Photos.zip", []byte("an older zip"))
	b := f.batch(a, core.BatchInput{FolderID: f.aliceRoot, Mode: core.UploadModeZip, ZipName: "Photos.zip",
		Files: []core.UploadFileInput{{ClientRef: "a", RelPath: "a.txt", Size: 1}}})
	f.small(a, b.ID, "a", []byte("a"))
	fin := f.complete(a, b.ID)
	if err := f.Jobs.Run(fin.JobID); err != nil {
		t.Fatal(err)
	}
	job, err := f.Jobs.Get(f.ctx, fin.JobID)
	if err != nil {
		t.Fatal(err)
	}
	var res struct {
		NodeID string `json:"node_id"`
		Name   string `json:"name"`
	}
	if err := json.Unmarshal(job.Result, &res); err != nil {
		t.Fatal(err)
	}
	_, node := f.nodeContent(f.aliceRoot, "Photos (1).zip")
	if res.Name != "Photos (1).zip" || res.NodeID != node.ID {
		t.Fatalf("result %s, want the name and node of %q (%s)", job.Result, "Photos (1).zip", node.ID)
	}
}
