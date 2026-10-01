package uploads

import (
	"context"
	"database/sql"
	"errors"
	"net/netip"
	"strings"
	"time"

	"fileparcel/internal/core"
	"fileparcel/internal/db"
	"fileparcel/internal/events"
)

// CompleteBatch implements core.Uploads.
//
// mode=files: directory entries are created and files whose data is stored
// but whose node commit failed transiently ("uploaded") are committed; every
// file must then be committed, skipped, failed or aborted (409 otherwise);
// the batch becomes "done" and its leftover reservation is released.
//
// mode=zip: every file must be uploaded, and the .zip must fit
// storage.max_file_gb and the space quota; the .zip password of a protected
// batch must still open (412 precondition_failed when it was wiped, 500
// corrupt when it does not decrypt, 503 keys_locked); the batch becomes
// "finalizing" and the upload.zip job is enqueued (the returned batch
// carries job_id). A refusal leaves the batch open.
//
// Completing a done or finalizing batch again returns it unchanged.
func (svc *Service) CompleteBatch(ctx context.Context, a core.UploadActor, batchID string) (*core.UploadBatch, error) {
	if a.P == nil {
		return nil, core.ErrUnauthorized
	}
	b, err := svc.loadBatch(ctx, a, batchID)
	if err != nil {
		return nil, err
	}
	switch b.State {
	case core.BatchDone, core.BatchFinalizing:
		return svc.decorate(b), nil
	case core.BatchOpen:
	default:
		return nil, errBatchState(b.State)
	}
	if b.Mode == core.UploadModeZip {
		return svc.startZip(ctx, a, b)
	}

	// Directory entries (empty folders included) are created now.
	dirs, err := svc.entryIDs(ctx, b.ID, core.UploadKindDir, core.UploadPending)
	if err != nil {
		return nil, err
	}
	for _, id := range dirs {
		if err := svc.completeDirEntry(ctx, a, b, id); err != nil {
			return nil, err
		}
	}
	// So are the nodes of files left "uploaded" by a transient failure (a
	// busy database, a restart) that no file completion has retried: a
	// client resuming the batch sees them as sent and only completes the
	// batch, which would otherwise refuse it until it expires.
	staged, err := svc.entryIDs(ctx, b.ID, core.UploadKindFile, core.UploadUploaded)
	if err != nil {
		return nil, err
	}
	for _, id := range staged {
		if err := svc.completeUploadedEntry(ctx, a, b, id); err != nil {
			return nil, err
		}
	}
	var open int
	var files int
	var bytes int64
	if err := svc.env.DB.QueryRow(ctx, `SELECT
			COALESCE(SUM(state IN ('pending','uploading','uploaded')), 0),
			COALESCE(SUM(state = 'committed' AND kind = 'file'), 0),
			COALESCE(SUM(CASE WHEN state = 'committed' AND kind = 'file' THEN size ELSE 0 END), 0)
		FROM upload_files WHERE batch_id = ?`, b.ID).Scan(&open, &files, &bytes); err != nil {
		return nil, err
	}
	if open > 0 {
		return nil, core.Errorf(core.ErrConflict, "%d files of this batch are not complete yet", open)
	}
	now := svc.env.Now()
	var updated int64
	err = svc.env.DB.Tx(ctx, func(tx *sql.Tx) error {
		res, err := tx.ExecContext(ctx, `UPDATE upload_batches SET state = 'done', reserved_bytes = 0,
			zip_password_enc = NULL, updated_at = ? WHERE id = ? AND state = 'open'`, db.Ms(now), b.ID)
		if err != nil {
			return err
		}
		updated, err = res.RowsAffected()
		return err
	})
	if err != nil {
		return nil, err
	}
	if b, err = svc.batchByID(ctx, svc.env.DB.Reader(), b.ID); err != nil {
		return nil, err
	}
	// Decorated before it is published: the event carries b to the SSE
	// subscribers, which encode it concurrently, so it must not change after.
	svc.decorate(b)
	if updated > 0 {
		svc.finished(ctx, b, b.FolderID, files, bytes)
	}
	return b, nil
}

// entryIDs returns the entries of a batch of one kind in one state.
func (svc *Service) entryIDs(ctx context.Context, batchID, kind, state string) ([]string, error) {
	rows, err := svc.env.DB.Query(ctx, `SELECT id FROM upload_files WHERE batch_id = ? AND kind = ?
		AND state = ? ORDER BY rel_path`, batchID, kind, state)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		out = append(out, id)
	}
	return out, rows.Err()
}

func (svc *Service) completeDirEntry(ctx context.Context, a core.UploadActor, b *core.UploadBatch, id string) error {
	unlock, err := svc.locks.Lock(ctx, fileKey(id))
	if err != nil {
		return err
	}
	defer unlock()
	f, err := svc.fileByID(ctx, svc.env.DB.Reader(), id)
	if err != nil || f.State != core.UploadPending {
		return err
	}
	_, err = svc.commitDir(ctx, a, b, f)
	if err != nil && permanent(err) {
		return nil // recorded as failed on the entry; the batch can still finish
	}
	return err
}

// completeUploadedEntry commits the node of a file of a mode=files batch
// whose blob is stored ("uploaded"). A permanent failure is recorded on the
// file (failed, or skipped) and lets the batch finish; a transient one is
// returned, and the client retries the completion.
func (svc *Service) completeUploadedEntry(ctx context.Context, a core.UploadActor, b *core.UploadBatch, id string) error {
	unlock, err := svc.locks.Lock(ctx, fileKey(id))
	if err != nil {
		return err
	}
	defer unlock()
	f, err := svc.fileByID(ctx, svc.env.DB.Reader(), id)
	if err != nil || f.State != core.UploadUploaded {
		return err
	}
	_, err = svc.commitUploaded(ctx, a, b, f)
	if err != nil && permanent(err) {
		return nil
	}
	return err
}

// startZip moves a zip-mode batch to "finalizing" and enqueues upload.zip.
// The password of a protected batch is opened (and dropped) first, so that
// a batch whose password cannot be used fails here, still open, instead of
// in the job after its data was deleted. An enqueue error moves the batch
// back to open and keeps the sealed password: it can be completed again.
func (svc *Service) startZip(ctx context.Context, a core.UploadActor, b *core.UploadBatch) (*core.UploadBatch, error) {
	if svc.jobs == nil {
		return nil, core.Wrap(core.ErrUnavailable, "background jobs are not available", nil)
	}
	var open, files, skipped int
	if err := svc.env.DB.QueryRow(ctx, `SELECT COALESCE(SUM(kind = 'file' AND state IN ('pending','uploading')), 0),
			COALESCE(SUM(kind = 'file'), 0), COALESCE(SUM(kind = 'file' AND state = 'skipped'), 0)
		FROM upload_files WHERE batch_id = ?`, b.ID).Scan(&open, &files, &skipped); err != nil {
		return nil, err
	}
	if open > 0 {
		return nil, core.Errorf(core.ErrConflict, "%d files of this batch are not complete yet", open)
	}
	if files > 0 && skipped == files {
		// Conflict "skip" found the .zip's name taken when the files were
		// declared (preflight.go): nothing was sent, and no .zip is built —
		// it would hold none of them even if the name was freed since.
		return svc.finishSkippedZip(ctx, b)
	}
	if err := svc.checkZipFits(ctx, b); err != nil {
		return nil, err
	}
	if b.ZipEncryption != "" {
		if _, _, err := svc.openZipPassword(ctx, b.ID); err != nil {
			return nil, err
		}
	}
	now := db.Ms(svc.env.Now())
	setState := func(from, to string) (bool, error) {
		var n int64
		err := svc.env.DB.Tx(ctx, func(tx *sql.Tx) error {
			res, err := tx.ExecContext(ctx, `UPDATE upload_batches SET state = ?, updated_at = ? WHERE id = ? AND state = ?`,
				to, now, b.ID, from)
			if err != nil {
				return err
			}
			n, err = res.RowsAffected()
			return err
		})
		return n > 0, err
	}
	ok, err := setState(core.BatchOpen, core.BatchFinalizing)
	if err != nil {
		return nil, err
	}
	if !ok { // someone else completed or aborted it meanwhile
		if b, err = svc.batchByID(ctx, svc.env.DB.Reader(), b.ID); err != nil {
			return nil, err
		}
		if b.State == core.BatchFinalizing || b.State == core.BatchDone {
			return svc.decorate(b), nil
		}
		return nil, errBatchState(b.State)
	}
	by := a.P
	if a.ShareID != "" {
		by = &core.Principal{UserID: b.UserID}
	}
	// From here on the batch is finalizing: finish the bookkeeping even if
	// the client goes away.
	ctx = context.WithoutCancel(ctx)
	jobID, err := svc.jobs.Enqueue(ctx, core.JobUploadZip, zipParams{BatchID: b.ID}, by)
	if err != nil {
		if _, rerr := setState(core.BatchFinalizing, core.BatchOpen); rerr != nil {
			svc.log.Error("revert batch state", "batch", b.ID, "err", rerr)
		}
		return nil, err
	}
	if err := svc.env.DB.Tx(ctx, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `UPDATE upload_batches SET job_id = ? WHERE id = ? AND job_id IS NULL`, jobID, b.ID)
		return err
	}); err != nil {
		svc.log.Error("record zip job", "batch", b.ID, "job", jobID, "err", err)
	}
	b.State, b.JobID, b.UpdatedAt = core.BatchFinalizing, jobID, db.FromMs(now)
	return svc.decorate(b), nil
}

// finishSkippedZip completes a zip batch whose .zip is skipped: done, no
// result node, like a zip job that found the name taken.
func (svc *Service) finishSkippedZip(ctx context.Context, b *core.UploadBatch) (*core.UploadBatch, error) {
	now := db.Ms(svc.env.Now())
	var updated int64
	err := svc.env.DB.Tx(ctx, func(tx *sql.Tx) error {
		res, err := tx.ExecContext(ctx, `UPDATE upload_batches SET state = 'done', reserved_bytes = 0,
			zip_password_enc = NULL, updated_at = ? WHERE id = ? AND state = 'open'`, now, b.ID)
		if err != nil {
			return err
		}
		if updated, err = res.RowsAffected(); err != nil || updated == 0 {
			return err
		}
		_, err = tx.ExecContext(ctx, `UPDATE upload_files SET state = 'skipped', updated_at = ?
			WHERE batch_id = ? AND kind = 'dir' AND state = 'pending'`, now, b.ID)
		return err
	})
	if err != nil {
		return nil, err
	}
	if b, err = svc.batchByID(ctx, svc.env.DB.Reader(), b.ID); err != nil {
		return nil, err
	}
	svc.decorate(b)
	if updated > 0 {
		svc.finished(ctx, b, b.FolderID, 0, 0)
	} else if b.State != core.BatchDone && b.State != core.BatchFinalizing {
		return nil, errBatchState(b.State) // aborted or expired meanwhile
	}
	return b, nil
}

// checkZipFits checks, before a zip batch is handed to upload.zip, that the
// .zip it becomes can be stored. It is committed as one node, so it must
// fit storage.max_file_gb, the space quota (as Files charges it at commit:
// the used bytes, without reservations) and the free disk. The batch was
// checked when it was declared, but a limit may have changed since, and a
// zip refused at commit fails the batch and deletes every staged file;
// refused here, the batch stays open and can be completed again once there
// is room.
func (svc *Service) checkZipFits(ctx context.Context, b *core.UploadBatch) error {
	need, err := svc.zipBound(ctx, b.ID)
	if err != nil {
		return err
	}
	if err := (limits{maxFile: svc.maxFileBytes()}).checkZip(need); err != nil {
		return err
	}
	var spaceID string
	err = svc.env.DB.QueryRow(ctx, `SELECT space_id FROM nodes WHERE id = ?`, b.FolderID).Scan(&spaceID)
	if db.IsNoRows(err) {
		return core.NotFoundf("folder not found")
	}
	if err != nil {
		return err
	}
	limit, used, err := svc.spaceQuota(ctx, spaceID)
	if err != nil {
		return err
	}
	if limit > 0 && addSat(used, need) > limit {
		avail := max(limit-used, 0)
		if b.ShareID != "" { // as in checkSpaceQuota: a visitor learns only what the upload needs
			svc.log.Warn("zip upload refused: space quota exceeded", "share", b.ShareID, "space", spaceID,
				"need", need, "available", avail)
			return core.Errorf(core.ErrQuota,
				"not enough storage space: this upload needs %s and the file request cannot take it right now",
				humanBytes(need))
		}
		return core.Errorf(core.ErrQuota, "not enough storage space: the .zip needs %s, %s %s available",
			humanBytes(need), humanBytes(avail), isAre(avail))
	}
	return svc.checkDisk(need)
}

// zipBound bounds the size of the .zip upload.zip builds from what a batch
// holds now: the entries the job takes, with their data and overhead.
func (svc *Service) zipBound(ctx context.Context, batchID string) (int64, error) {
	rows, err := svc.env.DB.Query(ctx, `SELECT rel_path, kind, size FROM upload_files WHERE batch_id = ?
		AND ((kind = 'file' AND state = 'uploaded') OR (kind = 'dir' AND state = 'pending'))`, batchID)
	if err != nil {
		return 0, err
	}
	defer rows.Close()
	n := int64(zipEndOverhead)
	for rows.Next() {
		var rel, kind string
		var size int64
		if err := rows.Scan(&rel, &kind, &size); err != nil {
			return 0, err
		}
		n = addSat(n, addSat(max(size, 0), zipEntryOverhead(rel, kind, size)))
	}
	return n, rows.Err()
}

// AbortBatch implements core.Uploads: an open batch is cancelled, the data
// of its unfinished files is deleted and its reservation released. Files
// already committed stay. Aborting an aborted or expired batch is a no-op.
func (svc *Service) AbortBatch(ctx context.Context, a core.UploadActor, batchID string) error {
	b, err := svc.loadBatch(ctx, a, batchID)
	if err != nil {
		return err
	}
	switch b.State {
	case core.BatchAborted, core.BatchExpired, core.BatchFailed:
		return nil
	case core.BatchOpen:
		return svc.abort(ctx, b, core.BatchAborted)
	case core.BatchFinalizing:
		return core.Errorf(core.ErrConflict, "the upload batch is being finalized")
	}
	return core.Errorf(core.ErrConflict, "the upload batch is already complete")
}

// abort moves an open batch to state (aborted | expired) and cleans up; the
// same statement wipes the sealed .zip password.
func (svc *Service) abort(ctx context.Context, b *core.UploadBatch, state string) error {
	now := db.Ms(svc.env.Now())
	var updated int64
	err := svc.env.DB.Tx(ctx, func(tx *sql.Tx) error {
		res, err := tx.ExecContext(ctx, `UPDATE upload_batches SET state = ?, reserved_bytes = 0, zip_password_enc = NULL,
			updated_at = ? WHERE id = ? AND state = 'open'`, state, now, b.ID)
		if err != nil {
			return err
		}
		updated, err = res.RowsAffected()
		return err
	})
	if err != nil {
		return err
	}
	if updated == 0 {
		cur, err := svc.batchByID(ctx, svc.env.DB.Reader(), b.ID)
		if err != nil {
			return err
		}
		if cur.State == core.BatchAborted || cur.State == core.BatchExpired {
			return nil
		}
		return errBatchState(cur.State)
	}
	ctx = context.WithoutCancel(ctx)
	svc.cleanupFiles(ctx, b.ID, core.UploadAborted)
	if b.ShareID != "" {
		svc.recordPartialRequest(ctx, b, state)
	}
	return nil
}

// cleanupFiles marks every unfinished file of a batch with state (aborted
// or failed) and deletes its staged blob. Each file is handled under its
// lock, so a completion in progress either finishes first (the file is
// then committed and kept) or sees the new state.
func (svc *Service) cleanupFiles(ctx context.Context, batchID, state string) {
	rows, err := svc.env.DB.Query(ctx, `SELECT id FROM upload_files WHERE batch_id = ?
		AND (state NOT IN ('committed','skipped','aborted','failed') OR (state IN ('aborted','failed') AND blob_id IS NOT NULL))`, batchID)
	if err != nil {
		svc.log.Error("list upload files for cleanup", "batch", batchID, "err", err)
		return
	}
	// A read that stops early must be logged: the files it did not yield keep
	// their staged blobs, so silently doing less work here leaks storage.
	var idsList []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			svc.log.Error("list upload files for cleanup", "batch", batchID, "err", err)
			break
		}
		idsList = append(idsList, id)
	}
	if err := rows.Err(); err != nil {
		svc.log.Error("list upload files for cleanup", "batch", batchID, "err", err)
	}
	rows.Close()
	for _, id := range idsList {
		if _, err := svc.releaseFile(ctx, id, state, false); err != nil {
			svc.log.Warn("clean up upload file", "upload", id, "err", err)
		}
	}
}

// releaseFile moves one unfinished file to state (aborted or failed),
// forgets its parts and deletes its staged blob. It reports whether the
// file was changed. requireOpen refuses (409) unless the batch is still
// open, checked in the same transaction: a caller that saw an open batch
// before taking the file lock must not pull the data out from under a batch
// that started finalizing meanwhile (the zip job may already have listed
// the file).
func (svc *Service) releaseFile(ctx context.Context, uploadID, state string, requireOpen bool) (bool, error) {
	unlock, err := svc.locks.Lock(ctx, fileKey(uploadID))
	if err != nil {
		return false, err
	}
	defer unlock()
	var blobID string
	var changed bool
	now := db.Ms(svc.env.Now())
	err = svc.env.DB.Tx(ctx, func(tx *sql.Tx) error {
		changed, blobID = false, ""
		var cur string
		var blob sql.NullString
		var size int64
		var batchID string
		if err := tx.QueryRowContext(ctx, `SELECT state, blob_id, size, batch_id FROM upload_files WHERE id = ?`, uploadID).
			Scan(&cur, &blob, &size, &batchID); err != nil {
			return err
		}
		if requireOpen {
			var bstate string
			if err := tx.QueryRowContext(ctx, `SELECT state FROM upload_batches WHERE id = ?`, batchID).Scan(&bstate); err != nil {
				return err
			}
			if bstate != core.BatchOpen {
				return errBatchState(bstate)
			}
		}
		switch cur {
		case core.UploadCommitted, core.UploadSkipped:
			return nil
		case core.UploadAborted, core.UploadFailed:
			blobID = blob.String // leftover blob only
		default:
			changed = true
			blobID = blob.String
			if _, err := tx.ExecContext(ctx, `UPDATE upload_batches SET reserved_bytes = MAX(0, reserved_bytes - ?), updated_at = ?
				WHERE id = ?`, size, now, batchID); err != nil {
				return err
			}
		}
		if _, err := tx.ExecContext(ctx, `UPDATE upload_files SET state = CASE WHEN state IN ('aborted','failed') THEN state ELSE ? END,
			blob_id = NULL, updated_at = ? WHERE id = ?`, state, now, uploadID); err != nil {
			return err
		}
		_, err := tx.ExecContext(ctx, `DELETE FROM upload_parts WHERE upload_id = ?`, uploadID)
		return err
	})
	if err != nil {
		return false, err
	}
	svc.deleteBlob(ctx, blobID)
	return changed, nil
}

// AbortFile implements core.Uploads: an unfinished file of an open batch is
// cancelled, its data deleted and its reservation released. Aborting an
// aborted file is a no-op; a committed file is 409, and so is any file once
// its batch is no longer open (a zip batch that started finalizing keeps
// the file).
func (svc *Service) AbortFile(ctx context.Context, a core.UploadActor, uploadID string) error {
	f, b, err := svc.loadFile(ctx, a, uploadID)
	if err != nil {
		return err
	}
	switch f.State {
	case core.UploadAborted:
		return nil
	case core.UploadCommitted, core.UploadSkipped:
		return core.Errorf(core.ErrConflict, "the file is already stored")
	}
	if b.State != core.BatchOpen {
		return errBatchState(b.State)
	}
	_, err = svc.releaseFile(context.WithoutCancel(ctx), f.ID, core.UploadAborted, true)
	return err
}

// ---------- expiry ----------

// ExpireStale implements core.Uploads (job maintenance.uploads): open
// batches past their expiry are expired and cleaned up; finalizing batches
// whose zip job ended without finishing them are run again or failed; a
// sealed .zip password left on a batch that is no longer open or
// finalizing is wiped; finished batch rows older than a week are deleted.
// It returns the number of expired batches.
func (svc *Service) ExpireStale(ctx context.Context) (int, error) {
	now := svc.env.Now()
	stale, err := svc.batchIDs(ctx, `SELECT id FROM upload_batches WHERE state = 'open' AND expires_at <= ? ORDER BY expires_at LIMIT 10000`, db.Ms(now))
	if err != nil {
		return 0, err
	}
	expired := 0
	for _, id := range stale {
		if err := ctx.Err(); err != nil {
			return expired, err
		}
		b, err := svc.batchByID(ctx, svc.env.DB.Reader(), id)
		if err != nil {
			continue
		}
		if err := svc.abort(ctx, b, core.BatchExpired); err != nil {
			svc.log.Warn("expire upload batch", "batch", id, "err", err)
			continue
		}
		expired++
	}
	if err := svc.failStuckZips(ctx, now); err != nil {
		svc.log.Warn("check finalizing uploads", "err", err)
	}
	// Safety sweep: every transition out of open/finalizing wipes the
	// password in its own statement; this catches anything else (a row
	// changed by hand, a restored backup).
	var wiped int64
	if err := svc.env.DB.Tx(ctx, func(tx *sql.Tx) error {
		res, err := tx.ExecContext(ctx, `UPDATE upload_batches SET zip_password_enc = NULL
			WHERE zip_password_enc IS NOT NULL AND state NOT IN ('open','finalizing')`)
		if err != nil {
			return err
		}
		wiped, err = res.RowsAffected()
		return err
	}); err != nil {
		return expired, err
	}
	if wiped > 0 {
		svc.log.Warn("wiped leftover .zip passwords of finished uploads", "batches", wiped)
	}
	// Forget finished batches after a week (their files stay; staged data
	// was deleted when they finished).
	cutoff := db.Ms(now.Add(-finishedRetention))
	if err := svc.env.DB.Tx(ctx, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `DELETE FROM upload_batches WHERE state IN ('done','aborted','expired','failed')
			AND updated_at < ?`, cutoff)
		return err
	}); err != nil {
		return expired, err
	}
	if expired > 0 {
		svc.log.Info("expired unfinished uploads", "batches", expired)
	}
	return expired, nil
}

func (svc *Service) batchIDs(ctx context.Context, q string, args ...any) ([]string, error) {
	rows, err := svc.env.DB.Query(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		out = append(out, id)
	}
	return out, rows.Err()
}

// failStuckZips looks after finalizing batches whose upload.zip job is no
// longer queued or running. A job that failed without finishing the batch —
// the server stopped or crashed while it ran (zipBatch leaves the batch
// finalizing when its job is cancelled), or it hit a transient error — or
// that is gone is enqueued again: the staged data is intact and the job
// rebuilds the zip from it, so a restart does not throw an upload away. A
// job that was cancelled (an explicit cancel, not a shutdown) or that
// succeeded without finishing the batch fails it, deleting its staged data,
// and so does a batch still not finished storage.upload_expiry_hours after
// it started finalizing.
func (svc *Service) failStuckZips(ctx context.Context, now time.Time) error {
	list, err := svc.batchIDs(ctx, `SELECT id FROM upload_batches WHERE state = 'finalizing'`)
	if err != nil {
		return err
	}
	for _, id := range list {
		b, err := svc.batchByID(ctx, svc.env.DB.Reader(), id)
		if err != nil {
			continue
		}
		// A batch without a job id is being enqueued right now (or the
		// process died in between); give it an hour.
		if b.JobID == "" && now.Sub(b.UpdatedAt) < time.Hour {
			continue
		}
		rerun := b.JobID == ""
		if b.JobID != "" && svc.jobs != nil {
			j, err := svc.jobs.Get(ctx, b.JobID)
			switch {
			case errors.Is(err, core.ErrNotFound):
				rerun = true
			case err != nil:
				continue
			case j.State == core.JobQueued || j.State == core.JobRunning:
				continue
			default:
				rerun = j.State == core.JobFailed
			}
		}
		if rerun && svc.jobs != nil && now.Sub(b.UpdatedAt) < svc.expiry() {
			if err := svc.rerunZip(ctx, b); err != nil {
				svc.log.Warn("re-run zip upload", "batch", b.ID, "err", err) // the next run tries again
			}
			continue
		}
		svc.failBatch(ctx, b, "the upload could not be finished (interrupted)")
	}
	return nil
}

// rerunZip enqueues upload.zip again for a finalizing batch whose job ended
// without finishing it. updated_at is left alone: it still tells when the
// batch started finalizing, which bounds the retries (failStuckZips).
func (svc *Service) rerunZip(ctx context.Context, b *core.UploadBatch) error {
	jobID, err := svc.jobs.Enqueue(ctx, core.JobUploadZip, zipParams{BatchID: b.ID}, &core.Principal{UserID: b.UserID})
	if err != nil {
		return err
	}
	var n int64
	err = svc.env.DB.Tx(ctx, func(tx *sql.Tx) error {
		res, err := tx.ExecContext(ctx, `UPDATE upload_batches SET job_id = ? WHERE id = ? AND state = 'finalizing'
			AND job_id IS ?`, jobID, b.ID, db.NullString(b.JobID))
		if err != nil {
			return err
		}
		n, err = res.RowsAffected()
		return err
	})
	if err != nil || n == 0 {
		// The batch moved on meanwhile (or the row could not be updated):
		// the new job must not run next to another one of this batch.
		if cerr := svc.jobs.Cancel(context.WithoutCancel(ctx), jobID); cerr != nil {
			svc.log.Warn("cancel duplicate zip job", "batch", b.ID, "job", jobID, "err", cerr)
		}
		return err
	}
	svc.log.Info("zip upload re-enqueued after an interrupted run", "batch", b.ID, "job", jobID, "previous", b.JobID)
	return nil
}

func (svc *Service) runExpireJob(ctx context.Context, j core.JobHandle) error {
	n, err := svc.ExpireStale(ctx)
	j.SetResult(map[string]int{"expired": n})
	return err
}

// ---------- completion side effects ----------

// finished records a batch that reached "done" or "failed": the
// upload.batch_done event and, for file requests, the request bookkeeping
// (recordRequest). Every stored file is already audited as file.upload by
// Files.CommitFile, so batches of signed-in users are audited here only
// when they fail (zip mode).
func (svc *Service) finished(ctx context.Context, b *core.UploadBatch, targetID string, files int, bytes int64) {
	ctx = context.WithoutCancel(ctx)
	if b.ShareID != "" {
		svc.recordRequest(ctx, b, targetID, files, bytes)
	} else if b.State != core.BatchDone && svc.env.Audit != nil {
		d := map[string]any{"batch": b.ID, "files": files, "bytes": bytes, "mode": b.Mode, "error": b.Error}
		if b.ZipEncryption != "" {
			d["zip_encryption"] = b.ZipEncryption
		}
		e := core.AuditEntry{Action: core.ActFileUpload, Outcome: core.OutcomeFailure, TargetType: "node", TargetID: targetID,
			Details: d}
		if core.PrincipalFrom(ctx) == nil {
			e.ActorID, e.ActorVia = b.UserID, "job"
		}
		svc.env.Audit.Record(ctx, e)
	}
	if svc.env.Bus != nil {
		// A copy: subscribers encode the event on their own goroutines, so
		// it must not share the caller's batch (a shallow copy will do: the
		// batches published here carry no Files).
		ev := *b
		svc.env.Bus.Publish(events.Event{Topic: events.TopicUploadBatchDone, UserID: b.UserID,
			Data: core.UploadBatchEvent{Batch: &ev, User: b.UserID}})
	}
}

// recordRequest records the outcome of a file-request batch (DESIGN §8.1
// step 8, §9.6): the request.upload audit entry (failure when the batch
// failed) and, when the batch is done or stored files before it was
// aborted or expired, the share access log entry "upload" — which also
// notifies the owner (notify_owner) through the shares service. The
// visitor is anonymous: the actor is the uploader name and the client IP
// recorded with the batch — the part of actor_session ahead of the visitor
// mark, since a visitor that keeps the share cookie has its visitor id
// appended there (actorSession).
func (svc *Service) recordRequest(ctx context.Context, b *core.UploadBatch, targetID string, files int, bytes int64) {
	ip := ""
	client, _, _ := strings.Cut(b.ActorSession, visitorMark)
	if addr, err := netip.ParseAddr(strings.TrimPrefix(client, "ip:")); err == nil {
		ip = addr.String()
	}
	if svc.env.Audit != nil {
		e := core.AuditEntry{Action: core.ActRequestUpload, TargetType: "share", TargetID: b.ShareID,
			ActorName: firstNonEmpty(b.Uploader, "anonymous"), ActorVia: string(core.ViaShare), IP: ip,
			Details: map[string]any{"batch": b.ID, "state": b.State, "files": files, "bytes": bytes, "mode": b.Mode,
				"folder": b.FolderID, "node": targetID, "uploader": b.Uploader}}
		if b.State == core.BatchFailed {
			e.Outcome = core.OutcomeFailure
			e.Details.(map[string]any)["error"] = b.Error
		}
		svc.env.Audit.Record(ctx, e)
	}
	if svc.shares != nil && (b.State == core.BatchDone || files > 0) && b.State != core.BatchFailed {
		svc.shares.RecordAccess(ctx, &core.Share{ID: b.ShareID, CreatedBy: b.UserID}, core.ShareAccess{
			ShareID: b.ShareID, At: svc.env.Now(), Action: core.AccessUpload, NodeID: targetID,
			Bytes: bytes, Files: files, Uploader: b.Uploader, IP: ip})
	}
}

// recordPartialRequest runs recordRequest for a file-request batch that was
// aborted or expired after some of its files were stored: those files stay
// in the owner's folder, so the owner learns about them as for a completed
// batch. Nothing is recorded when no file was stored.
func (svc *Service) recordPartialRequest(ctx context.Context, b *core.UploadBatch, state string) {
	var files int
	var bytes int64
	if err := svc.env.DB.QueryRow(ctx, `SELECT COUNT(*), COALESCE(SUM(size), 0) FROM upload_files
		WHERE batch_id = ? AND kind = 'file' AND state = 'committed'`, b.ID).Scan(&files, &bytes); err != nil {
		svc.log.Warn("count stored request uploads", "batch", b.ID, "err", err)
		return
	}
	if files == 0 {
		return
	}
	nb := *b
	nb.State = state
	svc.recordRequest(ctx, &nb, b.FolderID, files, bytes)
}
