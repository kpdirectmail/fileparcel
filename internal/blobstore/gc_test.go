package blobstore

import (
	"bytes"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"fileparcel/internal/core"
	"fileparcel/internal/crypt"
	"fileparcel/internal/db"
	"fileparcel/internal/ids"
)

// uploadRef makes an upload file of a batch in state batchState point at
// blobID.
func (ts *testStore) uploadRef(t testing.TB, blobID, batchState string) {
	t.Helper()
	now := db.Ms(ts.clock.Now())
	user, space, folder := ids.New(ids.PrefixUser), ids.New(ids.PrefixSpace), ids.New(ids.PrefixNode)
	ts.exec(t, `INSERT INTO users (id, username, role, webauthn_handle, created_at, updated_at) VALUES (?, ?, 'member', ?, ?, ?)`,
		user, user, crypt.RandomBytes(16), now, now)
	ts.exec(t, `INSERT INTO spaces (id, kind, owner_user_id, name, created_at) VALUES (?, 'user', ?, 'x', ?)`, space, user, now)
	ts.exec(t, `INSERT INTO nodes (id, space_id, kind, name, name_key, created_at, updated_at) VALUES (?, ?, 'folder', '', '', ?, ?)`,
		folder, space, now, now)
	batch := ids.New(ids.PrefixUploadBatch)
	ts.exec(t, `INSERT INTO upload_batches (id, user_id, folder_id, mode, conflict, state, created_at, updated_at, expires_at)
		VALUES (?, ?, ?, 'files', 'rename', ?, ?, ?, ?)`, batch, user, folder, batchState, now, now, now+1)
	ts.exec(t, `INSERT INTO upload_files (id, batch_id, client_ref, rel_path, size, blob_id, state, created_at, updated_at)
		VALUES (?, ?, 'f1', 'a.bin', 10, ?, 'uploading', ?, ?)`, ids.New(ids.PrefixUploadFile), batch, blobID, now, now)
}

// fileExists reports whether the blob file exists.
func (ts *testStore) fileExists(id string) bool {
	_, err := os.Stat(ts.blobFile(id))
	return err == nil
}

// TestGC covers every GC rule: interrupted deletes, abandoned staging
// blobs, unreferenced committed blobs and orphan files, with their
// exceptions (young, referenced, open uploads, active writers, foreign
// names) and the minimum-age floor.
func TestGC(t *testing.T) {
	ts := newStore(t)
	data := randData(3*segSize+9, 1)
	stored := StoredSize(int64(len(data)))

	// ---- old objects (created before the clock jump) ----
	versioned := ts.putStream(t, data)
	ts.reference(t, versioned.ID)
	thumb := ts.putStream(t, data)
	node := ts.reference(t, "")
	ts.exec(t, `UPDATE nodes SET thumb_blob_id = ? WHERE id = ?`, thumb.ID, node)
	unrefReady := ts.putParted(t, data)
	uploadReady := ts.putParted(t, data) // uploaded, batch still open
	ts.uploadRef(t, uploadReady.ID, "open")

	stagingAbandoned, _ := ts.CreateParted(ctx, int64(len(data)))
	stagingOpenBatch, _ := ts.CreateParted(ctx, int64(len(data)))
	ts.uploadRef(t, stagingOpenBatch.ID(), "finalizing")
	stagingDeadBatch, _ := ts.CreateParted(ctx, int64(len(data)))
	ts.uploadRef(t, stagingDeadBatch.ID(), "aborted")
	active, err := ts.Create(ctx) // an open streaming writer
	if err != nil {
		t.Fatal(err)
	}
	if _, err := active.Write(data[:1000]); err != nil {
		t.Fatal(err)
	}
	// a writer that crashed: staging row and file, no longer active
	crashed, _ := ts.Create(ctx)
	_, _ = crashed.Write(data)
	crashedID := crashed.(*writer).id
	ts.active.Delete(crashedID)

	// orphan files (no row): one old, one fresh; plus foreign names
	orphanOld := ids.NewBlobID()
	orphanNew := ids.NewBlobID()
	for _, id := range []string{orphanOld, orphanNew} {
		dir := filepath.Join(ts.h.BlobsDir(), id[:2], id[2:4])
		_ = os.MkdirAll(dir, 0o700)
		if err := os.WriteFile(filepath.Join(dir, id), make([]byte, 100), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	future := time.Now().Add(1000 * time.Hour)
	_ = os.Chtimes(ts.blobFile(orphanNew), future, future)
	misplaced := ids.NewBlobID()
	foreign := []string{
		filepath.Join("zz", "README"),
		filepath.Join("ab", "cd", "notablob"),
		filepath.Join("00", "00", misplaced), // valid id in the wrong fan-out directory
		"lost+found",
	}
	for _, rel := range foreign {
		p := filepath.Join(ts.h.BlobsDir(), rel)
		_ = os.MkdirAll(filepath.Dir(p), 0o700)
		if err := os.WriteFile(p, []byte("keep"), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	// ---- interrupted deletes (any age) ----
	ts.clock.advance(49 * time.Hour)
	deleting := ts.putStream(t, data)
	ts.exec(t, `UPDATE blobs SET state = 'deleting' WHERE id = ?`, deleting.ID)
	deletingNoFile := ts.putStream(t, data)
	ts.exec(t, `UPDATE blobs SET state = 'deleting' WHERE id = ?`, deletingNoFile.ID)
	_ = os.Remove(ts.blobFile(deletingNoFile.ID))
	deletingReferenced := ts.putStream(t, data)
	ts.reference(t, deletingReferenced.ID)
	ts.exec(t, `UPDATE blobs SET state = 'deleting' WHERE id = ?`, deletingReferenced.ID)
	// ---- young objects ----
	youngReady := ts.putStream(t, data)
	youngStaging, _ := ts.CreateParted(ctx, 10)

	removed, freed, err := ts.GC(ctx, 48*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	gone := []string{unrefReady.ID, stagingAbandoned.ID(), stagingDeadBatch.ID(), crashedID, deleting.ID, deletingNoFile.ID}
	kept := []string{versioned.ID, thumb.ID, uploadReady.ID, stagingOpenBatch.ID(), active.(*writer).id, deletingReferenced.ID,
		youngReady.ID, youngStaging.ID()}
	for _, id := range gone {
		if ts.state(t, id) != "" || ts.fileExists(id) {
			t.Errorf("blob %s not collected", id)
		}
	}
	for _, id := range kept {
		if ts.state(t, id) == "" || !ts.fileExists(id) {
			t.Errorf("blob %s must be kept", id)
		}
	}
	if ts.fileExists(orphanOld) || !ts.fileExists(orphanNew) {
		t.Error("orphan files: old must go, fresh must stay")
	}
	for _, rel := range foreign {
		if _, err := os.Stat(filepath.Join(ts.h.BlobsDir(), rel)); err != nil {
			t.Errorf("foreign file %s touched: %v", rel, err)
		}
	}
	// 5 blob files + the crashed writer's partial file + 1 orphan; the
	// deleting row without a file counts as removed but frees nothing.
	crashedSize := int64(headerSize + 3*storedSegSize) // 3 full segments flushed, the 4th still buffered
	if removed != len(gone)+1 || freed != 4*stored+crashedSize+100 {
		t.Fatalf("removed %d (want %d), freed %d (want %d)", removed, len(gone)+1, freed, 4*stored+crashedSize+100)
	}

	// The active writer still commits after GC.
	if _, err := active.Write(data[1000:]); err != nil {
		t.Fatal(err)
	}
	info, err := active.Commit(ctx)
	if err != nil {
		t.Fatalf("commit after GC: %v", err)
	}
	if got, _ := ts.readAll(t, info.ID); !bytes.Equal(got, data) {
		t.Fatal("content after GC")
	}

	// The minimum age floor: minAge 0 still protects fresh blobs.
	fresh := ts.putStream(t, data)
	if n, _, err := ts.GC(ctx, 0); err != nil || ts.state(t, fresh.ID) != stateReady || ts.state(t, youngReady.ID) != stateReady {
		t.Fatalf("GC(0) removed fresh blobs: %d %v", n, err)
	}
	// Idempotent: a second run finds nothing more.
	ts.clock.advance(time.Hour)
	if n, f, err := ts.GC(ctx, 48*time.Hour); err != nil || n != 0 || f != 0 {
		t.Fatalf("second GC: %d %d %v", n, f, err)
	}
}

// TestGCCanceled stops at the context.
func TestGCCanceled(t *testing.T) {
	ts := newStore(t)
	for range 3 {
		ts.putStream(t, []byte("x"))
	}
	ts.clock.advance(100 * time.Hour)
	cctx, cancel := contextWithCancel()
	cancel()
	if _, _, err := ts.GC(cctx, time.Hour); !errors.Is(err, cctx.Err()) {
		t.Fatalf("canceled GC: %v", err)
	}
	if ts.count(t, `SELECT count(*) FROM blobs`) != 3 {
		t.Fatal("canceled GC removed blobs")
	}
}

// TestGCConcurrentWithWriters runs GC (with every blob "old") while
// streaming writers and a parted upload are writing: nothing in flight may
// be collected.
func TestGCConcurrentWithWriters(t *testing.T) {
	ts := newStore(t)
	data := randData(2*segSize+3, 2)
	writers := make([]core.BlobWriter, 4)
	for i := range writers {
		w, err := ts.Create(ctx)
		if err != nil {
			t.Fatal(err)
		}
		writers[i] = w
	}
	big := randData(2*core.PartSize+5, 3)
	p, err := ts.CreateParted(ctx, int64(len(big)))
	if err != nil {
		t.Fatal(err)
	}
	ts.uploadRef(t, p.ID(), "open")
	ts.clock.advance(100 * time.Hour) // everything above is now old

	var wg sync.WaitGroup
	errs := make(chan error, 16)
	for _, w := range writers {
		wg.Go(func() {
			for off := 0; off < len(data); off += 1000 {
				if _, err := w.Write(data[off:min(off+1000, len(data))]); err != nil {
					errs <- err
					return
				}
			}
		})
	}
	digests := partDigests(big)
	for n := range p.PartCount() {
		wg.Go(func() {
			part := big[n*core.PartSize : min((n+1)*core.PartSize, len(big))]
			if _, err := p.WritePart(ctx, n, bytes.NewReader(part), digests[n]); err != nil {
				errs <- err
			}
		})
	}
	for range 5 {
		if _, _, err := ts.GC(ctx, time.Hour); err != nil {
			t.Fatal(err)
		}
	}
	wg.Wait()
	if _, _, err := ts.GC(ctx, time.Hour); err != nil {
		t.Fatal(err)
	}
	close(errs)
	for err := range errs {
		t.Fatal(err)
	}
	for _, w := range writers {
		info, err := w.Commit(ctx)
		if err != nil {
			t.Fatalf("commit after GC: %v", err)
		}
		if got, err := ts.readAll(t, info.ID); err != nil || !bytes.Equal(got, data) {
			t.Fatalf("content: %v", err)
		}
	}
	info, err := p.Commit(ctx, digests)
	if err != nil {
		t.Fatalf("parted commit after GC: %v", err)
	}
	if got, err := ts.readAll(t, info.ID); err != nil || !bytes.Equal(got, big) {
		t.Fatalf("parted content: %v", err)
	}
}

// TestDeleteRemovesStagingAndRetries covers Delete of a staging blob and of
// a row left in state deleting.
func TestDeleteRemovesStagingAndRetries(t *testing.T) {
	ts := newStore(t)
	p, _ := ts.CreateParted(ctx, 100)
	if err := ts.Delete(ctx, p.ID()); err != nil {
		t.Fatal(err)
	}
	if ts.state(t, p.ID()) != "" || ts.fileExists(p.ID()) {
		t.Fatal("staging blob not deleted")
	}
	info := ts.putStream(t, []byte("abc"))
	ts.exec(t, `UPDATE blobs SET state = 'deleting' WHERE id = ?`, info.ID)
	if err := ts.Delete(ctx, info.ID); err != nil {
		t.Fatal(err)
	}
	if ts.state(t, info.ID) != "" || ts.fileExists(info.ID) {
		t.Fatal("deleting blob not finished")
	}
	// A blob whose fan-out directory vanished is still deletable.
	info = ts.putStream(t, []byte("abc"))
	if err := os.RemoveAll(filepath.Dir(ts.blobFile(info.ID))); err != nil {
		t.Fatal(err)
	}
	if err := ts.Delete(ctx, info.ID); err != nil {
		t.Fatalf("delete without file: %v", err)
	}
	if _, err := os.Stat(ts.blobFile(info.ID)); !errors.Is(err, fs.ErrNotExist) || ts.state(t, info.ID) != "" {
		t.Fatal("row left")
	}
	errIs(t, ts.Delete(ctx, ""), core.ErrNotFound, "empty id")
}
