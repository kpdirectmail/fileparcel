package uploads

import (
	"testing"

	"fileparcel/internal/core"
)

// TestPreflightFilesMode: with conflict "skip" a file whose name is taken is
// declared skipped (nothing reserved or sent), with "fail" the declaration
// is refused — before any byte is uploaded. Paths resolve as the node commit
// resolves them, numbered folders included.
func TestPreflightFilesMode(t *testing.T) {
	f := setup(t)
	a := f.actor(f.alice)
	f.PutFile(f.aliceRoot, "Trip/day1/a.txt", []byte("existing"))
	f.PutFile(f.aliceRoot, "blocker", []byte("a file where a folder goes"))
	f.PutFile(f.aliceRoot, "blocker (1)/x.txt", []byte("in the numbered folder"))
	q := int64(1000)
	f.SetQuota(f.alice, &q)

	b := f.batch(a, core.BatchInput{FolderID: f.aliceRoot, Conflict: core.ConflictSkip, Files: []core.UploadFileInput{
		{ClientRef: "a", RelPath: "Trip/day1/A.TXT", Size: 300}, // name keys fold case
		{ClientRef: "n", RelPath: "Trip/day1/new.txt", Size: 20},
		{ClientRef: "x", RelPath: "blocker/x.txt", Size: 300}, // lands in "blocker (1)", where x.txt exists
		{ClientRef: "y", RelPath: "blocker/y.txt", Size: 5},
		{ClientRef: "z", RelPath: "Nowhere/z.txt", Size: 7},
		{ClientRef: "d", RelPath: "Trip/day1", Kind: "dir"},
	}})
	want := map[string]string{"a": core.UploadSkipped, "n": core.UploadPending, "x": core.UploadSkipped,
		"y": core.UploadPending, "z": core.UploadPending, "d": core.UploadPending}
	for _, st := range b.Files {
		if st.State != want[st.ClientRef] {
			t.Errorf("%s (%s): %s, want %s", st.ClientRef, st.RelPath, st.State, want[st.ClientRef])
		}
		if got := refState(f, b.ID, st.ClientRef); got != want[st.ClientRef] {
			t.Errorf("%s stored as %s", st.ClientRef, got)
		}
	}
	if b.ReservedBytes != 32 || b.DeclaredBytes != 632 {
		t.Fatalf("reserved %d, declared %d; want only the files to send reserved", b.ReservedBytes, b.DeclaredBytes)
	}
	// More entries: the same rule.
	more, err := f.svc.AddFiles(f.ctx, a, b.ID, []core.UploadFileInput{
		{ClientRef: "a2", RelPath: "Trip/day1/a.txt", Size: 900}, {ClientRef: "m", RelPath: "m.txt", Size: 1}})
	if err != nil || more[0].State != core.UploadSkipped || more[1].State != core.UploadPending {
		t.Fatalf("AddFiles: %+v %v", more, err)
	}
	if r := f.Int(`SELECT reserved_bytes FROM upload_batches WHERE id = ?`, b.ID); r != 33 {
		t.Fatalf("reserved after AddFiles = %d", r)
	}
	// Sending the rest completes the batch; the skipped files never needed data.
	for ref, data := range map[string]string{"n": "12345678901234567890", "y": "yyyyy", "z": "zzzzzzz", "m": "m"} {
		f.small(a, b.ID, ref, []byte(data))
	}
	if done := f.complete(a, b.ID); done.State != core.BatchDone || done.ReservedBytes != 0 {
		t.Fatalf("complete: %+v", done)
	}
	if got, _ := f.nodeContent(f.aliceRoot, "Trip/day1/a.txt"); string(got) != "existing" {
		t.Fatalf("the existing file changed: %q", got)
	}

	// "fail": refused at declaration, nothing recorded.
	before := f.Int(`SELECT COUNT(*) FROM upload_batches`)
	_, err = f.svc.CreateBatch(f.ctx, a, core.BatchInput{FolderID: f.aliceRoot, Conflict: core.ConflictFail,
		Files: []core.UploadFileInput{{ClientRef: "ok", RelPath: "fresh.txt", Size: 1}, {ClientRef: "x", RelPath: "blocker/x.txt", Size: 1}}})
	wantCode(t, err, core.ErrConflict)
	if msg := core.AsError(err).Message; msg != "“blocker/x.txt” already exists in this folder" {
		t.Fatalf("fail message %q", msg)
	}
	if n := f.Int(`SELECT COUNT(*) FROM upload_batches`); n != before {
		t.Fatal("a refused batch was recorded")
	}
	fb := f.batch(a, core.BatchInput{FolderID: f.aliceRoot, Conflict: core.ConflictFail,
		Files: []core.UploadFileInput{{ClientRef: "ok", RelPath: "fresh.txt", Size: 1}}})
	_, err = f.svc.AddFiles(f.ctx, a, fb.ID, []core.UploadFileInput{{ClientRef: "t", RelPath: "Trip/day1/a.txt", Size: 1}})
	wantCode(t, err, core.ErrConflict)
	// rename and replace are not affected
	for _, c := range []core.ConflictPolicy{core.ConflictRename, core.ConflictReplace} {
		rb := f.batch(a, core.BatchInput{FolderID: f.aliceRoot, Conflict: c,
			Files: []core.UploadFileInput{{ClientRef: "a", RelPath: "Trip/day1/a.txt", Size: 3}}})
		if rb.Files[0].State != core.UploadPending {
			t.Fatalf("%s: %+v", c, rb.Files[0])
		}
		if err := f.svc.AbortBatch(f.ctx, a, rb.ID); err != nil {
			t.Fatal(err)
		}
	}
}

// TestPreflightZipMode: the .zip's name is checked when the batch is
// declared — "fail" on a taken name and "replace" onto a folder are refused
// at once, "skip" declares every file skipped and completes without a job.
func TestPreflightZipMode(t *testing.T) {
	f := setup(t)
	f.Jobs.Manual = true
	a := f.actor(f.alice)
	f.PutFile(f.aliceRoot, "taken.zip", []byte("an older zip"))
	folder := f.Mkdir(f.aliceRoot, "folder.zip")
	zip := func(name string, c core.ConflictPolicy) (*core.UploadBatch, error) {
		return f.svc.CreateBatch(f.ctx, a, core.BatchInput{FolderID: f.aliceRoot, Mode: core.UploadModeZip, ZipName: name,
			Conflict: c, Files: []core.UploadFileInput{{ClientRef: "a", RelPath: "a.txt", Size: 4}, {ClientRef: "d", RelPath: "sub", Kind: "dir"}}})
	}
	_, err := zip("TAKEN", core.ConflictFail) // ".zip" is added; name keys fold case
	wantCode(t, err, core.ErrConflict)
	if msg := core.AsError(err).Message; msg != "“taken.zip” already exists in this folder" {
		t.Fatalf("fail message %q", msg)
	}
	_, err = zip("folder.zip", core.ConflictReplace)
	wantCode(t, err, core.ErrConflict)
	if msg := core.AsError(err).Message; msg != "“folder.zip” is a folder and cannot be replaced by a file" {
		t.Fatalf("replace-folder message %q", msg)
	}
	for _, c := range []core.ConflictPolicy{core.ConflictReplace, core.ConflictRename} {
		b, err := zip("taken.zip", c)
		if err != nil || b.Files[0].State != core.UploadPending {
			t.Fatalf("%s onto a file: %+v %v", c, b, err)
		}
		if err := f.svc.AbortBatch(f.ctx, a, b.ID); err != nil {
			t.Fatal(err)
		}
	}

	b, err := zip("folder.zip", core.ConflictSkip)
	if err != nil || b.ReservedBytes != 0 {
		t.Fatalf("skip: %+v %v", b, err)
	}
	for _, st := range b.Files {
		if want := map[string]string{"a": core.UploadSkipped, "d": core.UploadPending}[st.ClientRef]; st.State != want {
			t.Fatalf("%s: %s, want %s", st.ClientRef, st.State, want)
		}
	}
	more, err := f.svc.AddFiles(f.ctx, a, b.ID, []core.UploadFileInput{{ClientRef: "b", RelPath: "b.txt", Size: 2}})
	if err != nil || more[0].State != core.UploadSkipped {
		t.Fatalf("AddFiles to a skipped zip: %+v %v", more, err)
	}
	// Freed in between: still no .zip (it would hold none of the files).
	f.Exec(`UPDATE nodes SET trashed_at = 1 WHERE id = ?`, folder)
	done := f.complete(a, b.ID)
	if done.State != core.BatchDone || done.JobID != "" || done.ResultNodeID != "" || done.ReservedBytes != 0 {
		t.Fatalf("complete: %+v", done)
	}
	if n := f.Int(`SELECT COUNT(*) FROM nodes WHERE kind = 'file' AND name LIKE 'folder%'`); n != 0 {
		t.Fatalf("%d .zip nodes stored", n)
	}
	got, err := f.svc.GetBatch(f.ctx, a, b.ID)
	if err != nil {
		t.Fatal(err)
	}
	for _, st := range got.Files {
		if st.State != core.UploadSkipped {
			t.Errorf("%s: %s after completion", st.ClientRef, st.State)
		}
	}
	// Completing again returns the done batch.
	if again := f.complete(a, b.ID); again.State != core.BatchDone {
		t.Fatalf("again: %+v", again)
	}
}
