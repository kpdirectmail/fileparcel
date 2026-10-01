package uploads

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"testing"
	"time"

	"fileparcel/internal/core"
	"fileparcel/internal/events"
	"fileparcel/internal/ziputil"
)

// flakyFiles wraps the files service: CommitFile fails with err for the
// next fail calls; after, when set, runs once a real CommitFile returned.
type flakyFiles struct {
	core.Files
	mu    sync.Mutex
	fail  int
	err   error
	after func()
}

func (w *flakyFiles) CommitFile(ctx context.Context, p *core.Principal, parentID, relPath string, b *core.BlobInfo, m core.FileMeta, c core.ConflictPolicy) (*core.Node, error) {
	w.mu.Lock()
	failNow := w.fail > 0
	if failNow {
		w.fail--
	}
	after := w.after
	w.mu.Unlock()
	if failNow {
		return nil, w.err
	}
	n, err := w.Files.CommitFile(ctx, p, parentID, relPath, b, m, c)
	if after != nil {
		after()
	}
	return n, err
}

// errBusy is a transient node-commit failure (not permanent()).
var errBusy = errors.New("database is locked")

// waiters returns how many holders and waiters key has (tests).
func (l *keyLock) waiters(key string) int {
	l.mu.Lock()
	defer l.mu.Unlock()
	if e := l.m[key]; e != nil {
		return e.refs
	}
	return 0
}

// refState returns the state of the batch entry with client_ref ref.
func refState(f *fixture, batchID, ref string) string {
	return f.Str(`SELECT state FROM upload_files WHERE batch_id = ? AND client_ref = ?`, batchID, ref)
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	for deadline := time.Now().Add(5 * time.Second); !cond(); {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(time.Millisecond)
	}
}

// ---------- zip mode: the .zip is one stored file ----------

// TestZipLimitsApplyToTheZip pins that storage.max_file_gb and a file
// request's per-file limit apply to the .zip a zip-mode batch becomes, not
// only to each of its files: such a batch used to upload everything, then
// fail at commit and delete all of it.
func TestZipLimitsApplyToTheZip(t *testing.T) {
	f := setup(t)
	a := f.actor(f.alice)
	f.Settings.Put(settingMaxFileGB, 1)
	halves := []core.UploadFileInput{{ClientRef: "a", RelPath: "a.mp4", Size: gib/2 + 1}, {ClientRef: "b", RelPath: "b.mp4", Size: gib/2 + 1}}
	_, err := f.svc.CreateBatch(f.ctx, a, core.BatchInput{FolderID: f.aliceRoot, Mode: core.UploadModeZip, Files: halves})
	wantCode(t, err, core.ErrTooLarge)
	if ce := core.AsError(err); ce.Field != "files" || !strings.Contains(ce.Message, ".zip") {
		t.Fatalf("refusal = %+v", ce)
	}
	f.batch(a, core.BatchInput{FolderID: f.aliceRoot, Files: halves}) // separate files fit

	// AddFiles counts what the batch already holds.
	b := f.batch(a, core.BatchInput{FolderID: f.aliceRoot, Mode: core.UploadModeZip, Files: halves[:1]})
	declared := f.Int(`SELECT declared_bytes FROM upload_batches WHERE id = ?`, b.ID)
	_, err = f.svc.AddFiles(f.ctx, a, b.ID, halves[1:])
	wantCode(t, err, core.ErrTooLarge)
	if got := f.Int(`SELECT declared_bytes FROM upload_batches WHERE id = ?`, b.ID); got != declared {
		t.Fatalf("declared_bytes %d → %d after a refused AddFiles", declared, got)
	}
	f.Settings.Put(settingMaxFileGB, 0)

	// A file request's per-file limit bounds the .zip too.
	inbox := f.Mkdir(f.aliceRoot, "Inbox")
	shareID := f.share(f.alice, inbox, map[string]any{"upload_max_file_bytes": 1000})
	r := f.requestActor(f.alice, shareID, "Eve")
	_, err = f.svc.CreateBatch(f.ctx, r, core.BatchInput{Mode: core.UploadModeZip, Files: []core.UploadFileInput{
		{ClientRef: "a", RelPath: "a.bin", Size: 400}, {ClientRef: "b", RelPath: "b.bin", Size: 400}}})
	wantCode(t, err, core.ErrTooLarge)
	f.batch(r, core.BatchInput{Mode: core.UploadModeZip, Files: []core.UploadFileInput{{ClientRef: "a", RelPath: "a.bin", Size: 400}}})
}

// TestZipReservesFormatOverhead pins that a zip-mode batch reserves the
// bound of its .zip, not only its files' data, and that completing it
// checks the quota again: a zip refused at commit fails the batch and
// deletes every staged file, a refusal at completion keeps the batch open.
func TestZipReservesFormatOverhead(t *testing.T) {
	f := setup(t)
	f.Jobs.Manual = true
	a := f.actor(f.alice)
	q := int64(10_000) // small: every file stays within one 16 KiB Deflate bound
	f.SetQuota(f.alice, &q)
	f.PutFile(f.aliceRoot, "existing.txt", []byte("0123456789")) // 10 used, 9 990 left
	files := func(total int64) []core.UploadFileInput {
		return []core.UploadFileInput{{ClientRef: "a", RelPath: "a.bin", Size: total - 10}, {ClientRef: "b", RelPath: "b.txt", Size: 10}}
	}
	overhead := zipEntryOverhead("a.bin", core.UploadKindFile, q-20-10) + zipEntryOverhead("b.txt", core.UploadKindFile, 10) + zipEndOverhead

	// The data alone fits exactly; as a zip it does not.
	_, err := f.svc.CreateBatch(f.ctx, a, core.BatchInput{FolderID: f.aliceRoot, Mode: core.UploadModeZip, Files: files(q - 10)})
	wantCode(t, err, core.ErrQuota)
	fb := f.batch(a, core.BatchInput{FolderID: f.aliceRoot, Files: files(q - 10)})
	if err := f.svc.AbortBatch(f.ctx, a, fb.ID); err != nil {
		t.Fatal(err)
	}
	b := f.batch(a, core.BatchInput{FolderID: f.aliceRoot, Mode: core.UploadModeZip, Files: files(q - 10 - overhead)})
	if b.DeclaredBytes != q-10-overhead || b.ReservedBytes != q-10 {
		t.Fatalf("declared %d, reserved %d; want %d and %d", b.DeclaredBytes, b.ReservedBytes, q-10-overhead, q-10)
	}
	if err := f.svc.AbortBatch(f.ctx, a, b.ID); err != nil {
		t.Fatal(err)
	}

	// AddFiles reserves the overhead of the new entries as well.
	b = f.batch(a, core.BatchInput{FolderID: f.aliceRoot, Mode: core.UploadModeZip})
	_, err = f.svc.AddFiles(f.ctx, a, b.ID, files(q-10-overhead+1))
	wantCode(t, err, core.ErrQuota)
	if _, err := f.svc.AddFiles(f.ctx, a, b.ID, files(q-10-overhead)); err != nil {
		t.Fatal(err)
	}
	if r := f.Int(`SELECT reserved_bytes FROM upload_batches WHERE id = ?`, b.ID); r != q-10 {
		t.Fatalf("reserved after AddFiles = %d, want %d", r, q-10)
	}
	if err := f.svc.AbortBatch(f.ctx, a, b.ID); err != nil {
		t.Fatal(err)
	}

	// The quota shrinks while a zip batch is uploaded: completing it is
	// refused and the staged data kept; with room again it completes.
	b = f.batch(a, core.BatchInput{FolderID: f.aliceRoot, Mode: core.UploadModeZip, ZipName: "Z",
		Files: []core.UploadFileInput{{ClientRef: "x", RelPath: "x.txt", Size: 100}}})
	f.small(a, b.ID, "x", bytes.Repeat([]byte("x"), 100))
	staged := f.Blobs.Count()
	small := int64(10 + 150)
	f.SetQuota(f.alice, &small)
	_, err = f.svc.CompleteBatch(f.ctx, a, b.ID)
	wantCode(t, err, core.ErrQuota)
	if st := f.batchState(b.ID); st != core.BatchOpen || f.Blobs.Count() != staged {
		t.Fatalf("after a refused completion: state %s, blobs %d (want open, %d)", st, f.Blobs.Count(), staged)
	}
	f.SetQuota(f.alice, &q)
	fin := f.complete(a, b.ID)
	if err := f.Jobs.Run(fin.JobID); err != nil {
		t.Fatal(err)
	}
	if st := f.batchState(b.ID); st != core.BatchDone {
		t.Fatalf("state = %s", st)
	}
}

// TestZipOverheadBound keeps zipEntryOverhead honest: whatever ziputil (and
// archive/zip below it) writes stays within the declared data plus the
// bound, for stored and deflated incompressible data, long and multi-byte
// names and names ziputil has to de-duplicate.
func TestZipOverheadBound(t *testing.T) {
	type ent struct {
		rel, kind string
		size      int
	}
	sizes := []int{0, 1, 31, 32, 33, 127, 128, 1000, 16383, 16384, 65535, 65536, 65537, 200_000}
	names := []string{"a", "photo.jpg", "Trip/day1/IMG_0001.JPG", strings.Repeat("ü", 60) + ".txt",
		"x/" + strings.Repeat("y", 200) + ".bin"}
	var all []ent
	for i, s := range sizes {
		all = append(all, ent{fmt.Sprintf("d%d/%s", i, names[i%len(names)]), core.UploadKindFile, s})
	}
	all = append(all, ent{"clash", core.UploadKindFile, 5}, ent{"clash/inner.txt", core.UploadKindFile, 70_000},
		ent{"Clash/deeper/x.bin", core.UploadKindFile, 3}, ent{"clash", core.UploadKindDir, 0},
		ent{"clash (1)/y.txt", core.UploadKindFile, 40_000}, ent{"empty/dir", core.UploadKindDir, 0})
	mod := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	build := func(t *testing.T, c ziputil.Compression, es []ent) {
		t.Helper()
		zw, err := ziputil.New(io.Discard, ziputil.Options{Format: ziputil.FormatZip, Compression: c})
		if err != nil {
			t.Fatal(err)
		}
		bound := int64(zipEndOverhead)
		for i, e := range es {
			bound += int64(e.size) + zipEntryOverhead(e.rel, e.kind, int64(e.size))
			if e.kind == core.UploadKindDir {
				err = zw.AddDir(e.rel, mod)
			} else {
				err = zw.AddFile(e.rel, mod, int64(e.size), bytes.NewReader(content(e.size, uint64(i+1))))
			}
			if err != nil {
				t.Fatal(err)
			}
		}
		if err := zw.Close(); err != nil {
			t.Fatal(err)
		}
		if zw.Written() > bound {
			t.Errorf("%s %v: the zip has %d bytes, the bound is %d", c, es, zw.Written(), bound)
		}
	}
	for _, c := range []ziputil.Compression{ziputil.CompressionStore, ziputil.CompressionDeflate, ziputil.CompressionAuto} {
		t.Run(string(c), func(t *testing.T) {
			build(t, c, all)
			for _, e := range all { // each entry on its own: no slack from the others
				build(t, c, []ent{e})
			}
		})
	}
}

// ---------- small files ----------

// TestSmallResendAfterFailedCommit pins that re-sending a small file whose
// node commit failed for good answers that failure: its staged data is gone,
// and a 200 made the browser show the file as uploaded.
func TestSmallResendAfterFailedCommit(t *testing.T) {
	f := setup(t)
	a := f.actor(f.alice)
	f.Mkdir(f.aliceRoot, "dir.txt")
	for _, c := range []struct {
		policy core.ConflictPolicy
		name   string
	}{{core.ConflictFail, "a.txt"}, {core.ConflictReplace, "dir.txt"}} {
		t.Run(string(c.policy), func(t *testing.T) {
			b := f.batch(a, core.BatchInput{FolderID: f.aliceRoot, Conflict: c.policy,
				Files: []core.UploadFileInput{{ClientRef: "f", RelPath: c.name, Size: 3}}})
			if c.policy == core.ConflictFail {
				// taken after the declaration, which would refuse it (preflight.go)
				f.PutFile(f.aliceRoot, "a.txt", []byte("original"))
			}
			blobs := f.Blobs.Count()
			send := func() error {
				_, err := f.svc.PutSmall(f.ctx, a, b.ID, "f", strings.NewReader("new"), 3, digest([]byte("new")))
				return err
			}
			wantCode(t, send(), core.ErrConflict)
			err := send()
			wantCode(t, err, core.ErrConflict)
			if !strings.Contains(err.Error(), "the upload failed") {
				t.Fatalf("resend: %v", err)
			}
			if st := refState(f, b.ID, "f"); st != core.UploadFailed || f.Blobs.Count() != blobs {
				t.Fatalf("state %s, blobs %d → %d", st, blobs, f.Blobs.Count())
			}
			// A different content is still a conflict of its own.
			_, err = f.svc.PutSmall(f.ctx, a, b.ID, "f", strings.NewReader("NEW"), 3, digest([]byte("NEW")))
			wantCode(t, err, core.ErrConflict)
		})
	}
}

// TestSlowSmallSendDoesNotBlockAbort pins that a small-file send does not
// hold the file lock while it reads the request body: a client trickling
// its body must not stall an abort (or a share revocation) or the expiry
// job, whose context cannot be cancelled once it cleans up.
func TestSlowSmallSendDoesNotBlockAbort(t *testing.T) {
	f := setup(t)
	a := f.actor(f.alice)
	slow := func(b *core.UploadBatch) (*io.PipeWriter, chan error) {
		pr, pw := io.Pipe()
		res := make(chan error, 1)
		go func() {
			_, err := f.svc.PutSmall(context.Background(), a, b.ID, "s", pr, 4, digest([]byte("slow")))
			res <- err
		}()
		if _, err := pw.Write([]byte("s")); err != nil { // read: the send is mid-body
			t.Fatal(err)
		}
		return pw, res
	}
	within := func(what string, fn func() error) {
		t.Helper()
		done := make(chan error, 1)
		go func() { done <- fn() }()
		select {
		case err := <-done:
			if err != nil {
				t.Fatalf("%s: %v", what, err)
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("%s waits for a slow small-file send", what)
		}
	}
	finish := func(pw *io.PipeWriter, res chan error) {
		t.Helper()
		if _, err := pw.Write([]byte("low")); err != nil {
			t.Fatal(err)
		}
		_ = pw.Close()
		wantCode(t, <-res, core.ErrConflict)
	}

	b := f.batch(a, core.BatchInput{FolderID: f.aliceRoot, Files: []core.UploadFileInput{{ClientRef: "s", RelPath: "s.bin", Size: 4}}})
	pw, res := slow(b)
	within("AbortBatch", func() error { return f.svc.AbortBatch(f.ctx, a, b.ID) })
	if st := refState(f, b.ID, "s"); st != core.UploadAborted {
		t.Fatalf("file state = %s", st)
	}
	finish(pw, res)

	b = f.batch(a, core.BatchInput{FolderID: f.aliceRoot, Files: []core.UploadFileInput{{ClientRef: "s", RelPath: "s.bin", Size: 4}}})
	pw, res = slow(b)
	f.Clock.Advance(DefaultExpiryHours*time.Hour + time.Minute)
	within("ExpireStale", func() error { _, err := f.svc.ExpireStale(f.ctx); return err })
	if st := f.batchState(b.ID); st != core.BatchExpired {
		t.Fatalf("batch state = %s", st)
	}
	finish(pw, res)
	if n := f.Blobs.Count(); n != 0 {
		t.Fatalf("%d blobs left by refused sends", n)
	}
}

// ---------- node commits ----------

// TestCompleteBatchCommitsStagedFiles pins that completing a mode=files
// batch commits files left "uploaded" by a transient node-commit failure: a
// client resuming the batch takes them for sent and only completes the
// batch, which used to answer 409 until the batch expired and its data was
// deleted.
func TestCompleteBatchCommitsStagedFiles(t *testing.T) {
	f := setup(t)
	a := f.actor(f.alice)
	ff := &flakyFiles{Files: f.Files, err: errBusy}
	f.svc.files = ff
	data := content(core.PartSize+5, 11)
	b := f.batch(a, core.BatchInput{FolderID: f.aliceRoot, Files: []core.UploadFileInput{
		{ClientRef: "a", RelPath: "a.txt", Size: 5}, {ClientRef: "b", RelPath: "b.txt", Size: 1},
		{ClientRef: "big", RelPath: "big.bin", Size: int64(len(data))}}})
	ff.fail = 1
	_, err := f.svc.PutSmall(f.ctx, a, b.ID, "a", strings.NewReader("hello"), 5, digest([]byte("hello")))
	if !errors.Is(err, errBusy) {
		t.Fatalf("PutSmall a = %v", err)
	}
	f.small(a, b.ID, "b", []byte("b"))
	f.parts(a, refID(b, "big"), data, 0, 1)
	ff.fail = 1
	if _, err := f.svc.CompleteFile(f.ctx, a, refID(b, "big")); !errors.Is(err, errBusy) {
		t.Fatalf("CompleteFile big = %v", err)
	}
	for _, ref := range []string{"a", "big"} {
		if st := refState(f, b.ID, ref); st != core.UploadUploaded {
			t.Fatalf("%s: state %s, want uploaded", ref, st)
		}
	}

	// A commit that keeps failing is reported, and the batch stays open.
	ff.fail = 1
	if _, err := f.svc.CompleteBatch(f.ctx, a, b.ID); !errors.Is(err, errBusy) {
		t.Fatalf("CompleteBatch while the database is busy = %v", err)
	}
	if st := f.batchState(b.ID); st != core.BatchOpen {
		t.Fatalf("state = %s", st)
	}
	done := f.complete(a, b.ID)
	if done.State != core.BatchDone || done.ReservedBytes != 0 {
		t.Fatalf("batch = %+v", done)
	}
	if got, _ := f.nodeContent(f.aliceRoot, "a.txt"); string(got) != "hello" {
		t.Fatalf("a.txt = %q", got)
	}
	if got, _ := f.nodeContent(f.aliceRoot, "big.bin"); !bytes.Equal(got, data) {
		t.Fatal("big.bin differs")
	}
	for _, ref := range []string{"a", "big"} {
		st, _ := f.svc.Status(f.ctx, a, refID(b, ref))
		if st.State != core.UploadCommitted || st.NodeID == "" {
			t.Fatalf("%s: %+v", ref, st)
		}
	}

	// A permanent failure is recorded on the file and the batch finishes
	// (the name is taken after the declaration, which would refuse it).
	b = f.batch(a, core.BatchInput{FolderID: f.aliceRoot, Conflict: core.ConflictFail,
		Files: []core.UploadFileInput{{ClientRef: "c", RelPath: "c.txt", Size: 3}}})
	f.PutFile(f.aliceRoot, "c.txt", []byte("old"))
	blobs := f.Blobs.Count()
	ff.fail = 1
	if _, err := f.svc.PutSmall(f.ctx, a, b.ID, "c", strings.NewReader("new"), 3, digest([]byte("new"))); !errors.Is(err, errBusy) {
		t.Fatalf("PutSmall c = %v", err)
	}
	if done := f.complete(a, b.ID); done.State != core.BatchDone {
		t.Fatalf("batch = %+v", done)
	}
	if st := refState(f, b.ID, "c"); st != core.UploadFailed || f.Blobs.Count() != blobs {
		t.Fatalf("c: state %s, blobs %d (want %d: the staged one deleted)", st, f.Blobs.Count(), blobs)
	}
}

// TestNodeCommitSurvivesDisconnect pins that once CommitFile stored the
// node, the upload is recorded even if the client goes away: the next
// completion used to store the file a second time ("a (1).txt", its space
// charged twice).
func TestNodeCommitSurvivesDisconnect(t *testing.T) {
	f := setup(t)
	ff := &flakyFiles{Files: f.Files}
	f.svc.files = ff
	inbox := f.Mkdir(f.aliceRoot, "Inbox")
	shareID := f.share(f.alice, inbox, nil)
	for _, c := range []struct {
		name   string
		a      core.UploadActor
		folder string
	}{{"user", f.actor(f.alice), f.aliceRoot}, {"request", f.requestActor(f.alice, shareID, "Eve"), inbox}} {
		t.Run(c.name, func(t *testing.T) {
			in := core.BatchInput{Files: []core.UploadFileInput{{ClientRef: "a", RelPath: "a.txt", Size: 4}}}
			if c.a.ShareID == "" {
				in.FolderID = c.folder
			}
			b := f.batch(c.a, in)
			ctx, cancel := context.WithCancel(f.ctx)
			ff.after = cancel
			st, err := f.svc.PutSmall(ctx, c.a, b.ID, "a", strings.NewReader("data"), 4, digest([]byte("data")))
			ff.after = nil
			if err != nil || st.State != core.UploadCommitted || st.NodeID == "" {
				t.Fatalf("PutSmall = %+v, %v", st, err)
			}
			if r := f.Int(`SELECT reserved_bytes FROM upload_batches WHERE id = ?`, b.ID); r != 0 {
				t.Fatalf("reserved = %d", r)
			}
			again, err := f.svc.PutSmall(f.ctx, c.a, b.ID, "a", strings.NewReader("data"), 4, digest([]byte("data")))
			if err != nil || again.NodeID != st.NodeID {
				t.Fatalf("resend = %+v, %v (first node %s)", again, err, st.NodeID)
			}
			if n := f.Int(`SELECT COUNT(*) FROM nodes WHERE parent_id = ? AND kind = 'file'`, c.folder); n != 1 {
				t.Fatalf("%d files in the folder, want 1", n)
			}
			if c.a.ShareID != "" {
				if used := f.Int(`SELECT upload_used_bytes FROM shares WHERE id = ?`, shareID); used != 4 {
					t.Fatalf("upload_used_bytes = %d", used)
				}
			}
		})
	}
}

// ---------- aborts and events ----------

// TestAbortFileRacesFinalizing pins that AbortFile re-checks the batch
// state with the file: a file cancelled while the last other file completes
// the zip batch used to be deleted under the running zip job, which then
// failed the batch and deleted every staged file.
func TestAbortFileRacesFinalizing(t *testing.T) {
	f := setup(t)
	f.Jobs.Manual = true
	a := f.actor(f.alice)
	b := f.batch(a, core.BatchInput{FolderID: f.aliceRoot, Mode: core.UploadModeZip, ZipName: "Both",
		Files: []core.UploadFileInput{{ClientRef: "a", RelPath: "a.txt", Size: 1}, {ClientRef: "b", RelPath: "b.txt", Size: 1}}})
	f.small(a, b.ID, "a", []byte("a"))
	f.small(a, b.ID, "b", []byte("b"))

	key := fileKey(refID(b, "b"))
	unlock, err := f.svc.locks.Lock(f.ctx, key)
	if err != nil {
		t.Fatal(err)
	}
	aborted := make(chan error, 1)
	go func() { aborted <- f.svc.AbortFile(f.ctx, a, refID(b, "b")) }()
	waitFor(t, "AbortFile to wait for the file lock", func() bool { return f.svc.locks.waiters(key) == 2 })
	fin := f.complete(a, b.ID)
	unlock()
	wantCode(t, <-aborted, core.ErrConflict)
	if st := refState(f, b.ID, "b"); st != core.UploadUploaded {
		t.Fatalf("b: state %s", st)
	}
	if err := f.Jobs.Run(fin.JobID); err != nil {
		t.Fatal(err)
	}
	if got, _ := f.zipNames(f.aliceRoot, "Both.zip"); strings.Join(got, ",") != "a.txt,b.txt" {
		t.Fatalf("zip entries %v", got)
	}
}

// TestBatchDoneEventNotMutated pins that the upload.batch_done event of a
// mode=files batch is complete when it is published and not written to
// afterwards (subscribers encode it on their own goroutines; run with -race).
func TestBatchDoneEventNotMutated(t *testing.T) {
	f := setup(t)
	a := f.actor(f.alice)
	ch, unsub := f.Bus.Subscribe(events.TopicUploadBatchDone)
	defer unsub()
	b := f.batch(a, core.BatchInput{FolderID: f.aliceRoot, Files: []core.UploadFileInput{{ClientRef: "x", RelPath: "x.txt", Size: 1}}})
	f.small(a, b.ID, "x", []byte("x"))
	got := make(chan core.UploadBatchEvent, 1)
	go func() {
		ev := <-ch
		for range 50 {
			if _, err := json.Marshal(ev.Data); err != nil {
				t.Error(err)
			}
		}
		got <- ev.Data.(core.UploadBatchEvent)
	}()
	done := f.complete(a, b.ID)
	select {
	case be := <-got:
		if be.Batch == done || be.Batch.PartSize != core.PartSize || be.Batch.SmallMax != SmallMax || be.Batch.Parallel < 1 {
			t.Fatalf("event batch %+v (returned %p, published %p)", be.Batch, done, be.Batch)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("no upload.batch_done")
	}
}
