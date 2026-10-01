package uploads

import (
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"fileparcel/internal/core"
)

// A conflict=skip collision with an existing folder of the same name must
// leave the upload "skipped" (no node id, blob deleted) — in files mode and
// for the zip of a zip-mode batch. The folders appear after the files were
// declared (a name taken at declaration is skipped there: preflight.go), so
// this is the node commit's own check.
func TestSkipOntoFolder(t *testing.T) {
	f := setup(t)
	f.Jobs.Manual = true
	a := f.actor(f.alice)
	blobs := f.Blobs.Count()

	b := f.batch(a, core.BatchInput{FolderID: f.aliceRoot, Conflict: core.ConflictSkip,
		Files: []core.UploadFileInput{{ClientRef: "r", RelPath: "report.txt", Size: 2}}})
	z := f.batch(a, core.BatchInput{FolderID: f.aliceRoot, Mode: core.UploadModeZip, ZipName: "Bundle",
		Conflict: core.ConflictSkip, Files: []core.UploadFileInput{{ClientRef: "x", RelPath: "x.txt", Size: 1}}})
	f.Mkdir(f.aliceRoot, "report.txt")
	f.Mkdir(f.aliceRoot, "Bundle.zip")
	st := f.small(a, b.ID, "r", []byte("hi"))
	if st.State != core.UploadSkipped || st.NodeID != "" {
		t.Fatalf("file skipped onto a folder: %+v", st)
	}
	if f.Blobs.Count() != blobs {
		t.Fatal("the blob of a skipped file was kept")
	}
	if done := f.complete(a, b.ID); done.State != core.BatchDone || done.ReservedBytes != 0 {
		t.Fatalf("batch = %+v", done)
	}

	f.small(a, z.ID, "x", []byte("x"))
	fin := f.complete(a, z.ID)
	if err := f.Jobs.Run(fin.JobID); err != nil {
		t.Fatal(err)
	}
	got, err := f.svc.GetBatch(f.ctx, a, z.ID)
	if err != nil || got.State != core.BatchDone || got.ResultNodeID != "" {
		t.Fatalf("zip skipped onto a folder: %+v %v", got, err)
	}
	// The job still succeeds, but its result has no node_id: that is how the
	// browser tells a skipped .zip from a stored one (upload/engine.js watchJob).
	job, err := f.Jobs.Get(f.ctx, fin.JobID)
	var res struct {
		NodeID *string `json:"node_id"`
		Files  int     `json:"files"`
	}
	if err != nil || job.State != core.JobSucceeded || json.Unmarshal(job.Result, &res) != nil || res.NodeID != nil || res.Files != 1 {
		t.Fatalf("skipped zip job = %+v %v", job, err)
	}
	for _, fs := range got.Files {
		if fs.State != core.UploadSkipped || fs.NodeID != "" {
			t.Errorf("file %s: %+v", fs.RelPath, fs)
		}
	}
	if f.Blobs.Count() != blobs {
		t.Fatalf("blobs = %d, want %d (zip and staged data deleted)", f.Blobs.Count(), blobs)
	}
	if n := f.Int(`SELECT COUNT(*) FROM nodes WHERE kind = 'file'`); n != 0 {
		t.Fatalf("%d file nodes created", n)
	}
}

// Files that a file-request visitor stored before cancelling (or before the
// batch expired) stay in the owner's folder, so they are logged, audited
// and notified like a completed batch; batches that stored nothing are not.
func TestPartialRequestRecorded(t *testing.T) {
	for _, c := range []struct {
		name  string
		state string
		end   func(f *fixture, a core.UploadActor, batchID string)
	}{
		{"aborted", core.BatchAborted, func(f *fixture, a core.UploadActor, batchID string) {
			if err := f.svc.AbortBatch(f.ctx, a, batchID); err != nil {
				f.t.Fatal(err)
			}
		}},
		{"expired", core.BatchExpired, func(f *fixture, _ core.UploadActor, _ string) {
			f.Clock.Advance(DefaultExpiryHours*time.Hour + time.Minute)
			if n, err := f.svc.ExpireStale(f.ctx); err != nil || n != 1 {
				f.t.Fatalf("expired %d, %v", n, err)
			}
		}},
	} {
		t.Run(c.name, func(t *testing.T) {
			f := setup(t)
			inbox := f.Mkdir(f.aliceRoot, "Inbox")
			shareID := f.share(f.alice, inbox, nil)
			a := f.requestActor(f.alice, shareID, "Eve")
			a.P.IP = mustAddr(t, "192.0.2.9")
			b := f.batch(a, core.BatchInput{Files: []core.UploadFileInput{
				{ClientRef: "s", RelPath: "stored.txt", Size: 6}, {ClientRef: "m", RelPath: "missing.txt", Size: 9}}})
			f.small(a, b.ID, "s", []byte("stored"))
			c.end(f, a, b.ID)
			if st := f.batchState(b.ID); st != c.state {
				t.Fatalf("state = %s", st)
			}
			acc := f.shares.accesses()
			if len(acc) != 1 || acc[0].Action != core.AccessUpload || acc[0].Bytes != 6 || acc[0].Uploader != "Eve" ||
				acc[0].IP != "192.0.2.9" {
				t.Fatalf("access log = %+v", acc)
			}
			e, ok := f.Audit.Find(core.ActRequestUpload)
			if !ok || e.TargetID != shareID || e.Outcome == core.OutcomeFailure || e.ActorName != "Eve" || e.IP != "192.0.2.9" {
				t.Fatalf("audit = %+v %v", e, ok)
			}
			if d := fmt.Sprint(e.Details); d == "" {
				t.Fatal("audit details missing")
			}

			// A second batch that stored nothing leaves no trace.
			b2 := f.batch(a, core.BatchInput{Files: []core.UploadFileInput{{ClientRef: "x", RelPath: "x.txt", Size: 1}}})
			if err := f.svc.AbortBatch(f.ctx, a, b2.ID); err != nil {
				t.Fatal(err)
			}
			if n := len(f.shares.accesses()); n != 1 {
				t.Fatalf("%d access log entries after an empty abort", n)
			}
		})
	}
}

// A file-request visitor that keeps the share cookie has its visitor id
// appended to actor_session ("ip:<addr>|vis:<id>"), which must not cost it
// the client IP in the owner's access log or in the request.upload audit
// entry — the normal-browser case.
func TestRequestUploadIPWithVisitorCookie(t *testing.T) {
	for _, visitor := range []string{"", "WD--mhKpFAA6pKhLJpwfqg"} {
		name := "cookieless"
		if visitor != "" {
			name = "cookie"
		}
		t.Run(name, func(t *testing.T) {
			f := setup(t)
			inbox := f.Mkdir(f.aliceRoot, "Inbox")
			shareID := f.share(f.alice, inbox, nil)
			a := f.requestActor(f.alice, shareID, "Eve")
			a.P.IP = mustAddr(t, "203.0.113.7")
			a.P.SessionID = visitor
			b := f.batch(a, core.BatchInput{Files: []core.UploadFileInput{{ClientRef: "s", RelPath: "s.txt", Size: 6}}})
			want := "ip:203.0.113.7"
			if visitor != "" {
				want += "|vis:" + visitor
			}
			if got := f.Str(`SELECT actor_session FROM upload_batches WHERE id = ?`, b.ID); got != want {
				t.Fatalf("actor_session = %q, want %q", got, want)
			}
			f.small(a, b.ID, "s", []byte("stored"))
			if done := f.complete(a, b.ID); done.State != core.BatchDone {
				t.Fatalf("batch = %+v", done)
			}
			acc := f.shares.accesses()
			if len(acc) != 1 || acc[0].IP != "203.0.113.7" {
				t.Fatalf("access log = %+v, want the client IP", acc)
			}
			e, ok := f.Audit.Find(core.ActRequestUpload)
			if !ok || e.IP != "203.0.113.7" {
				t.Fatalf("audit = %+v %v, want the client IP", e, ok)
			}
		})
	}
}

// Public file-request batches hold at most MaxFilesPerShareBatch entries.
func TestShareBatchEntryCap(t *testing.T) {
	f := setup(t)
	shareID := f.share(f.alice, f.aliceRoot, nil)
	a := f.requestActor(f.alice, shareID, "")
	b := f.batch(a, core.BatchInput{})
	chunk := func(start, n int) []core.UploadFileInput {
		out := make([]core.UploadFileInput, n)
		for i := range out {
			out[i] = core.UploadFileInput{ClientRef: fmt.Sprint("r", start+i), RelPath: fmt.Sprintf("d%d", start+i), Kind: core.UploadKindDir}
		}
		return out
	}
	for i := 0; i < MaxFilesPerShareBatch; i += MaxFilesPerCall {
		if _, err := f.svc.AddFiles(f.ctx, a, b.ID, chunk(i, MaxFilesPerCall)); err != nil {
			t.Fatalf("chunk %d: %v", i, err)
		}
	}
	_, err := f.svc.AddFiles(f.ctx, a, b.ID, chunk(MaxFilesPerShareBatch, 1))
	wantCode(t, err, core.ErrInvalid)
	// Re-sending known entries is still idempotent at the cap.
	if _, err := f.svc.AddFiles(f.ctx, a, b.ID, chunk(0, 3)); err != nil {
		t.Fatalf("idempotent resend at the cap: %v", err)
	}
	// Signed-in users are not limited by the share cap.
	own := f.batch(f.actor(f.alice), core.BatchInput{FolderID: f.aliceRoot})
	for i := 0; i <= MaxFilesPerShareBatch; i += MaxFilesPerCall {
		if _, err := f.svc.AddFiles(f.ctx, f.actor(f.alice), own.ID, chunk(i, MaxFilesPerCall)); err != nil {
			t.Fatalf("own chunk %d: %v", i, err)
		}
	}
}
