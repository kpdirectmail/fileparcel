package uploads

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io"

	"fileparcel/internal/core"
	"fileparcel/internal/db"
	"fileparcel/internal/ziputil"
)

// zipParams are the parameters of an upload.zip job. They never carry the
// .zip password (GET /jobs/{id} returns them): the job reads it sealed from
// the batch.
type zipParams struct {
	BatchID string `json:"batch_id"`
}

// zipResult is stored as the job result. Name is the name the .zip got
// (conflict "rename" may have numbered it: "photos (1).zip"). Encryption is
// set when the stored .zip is password-protected (a protected batch without
// files has no encrypted entry and no encryption).
type zipResult struct {
	NodeID     string `json:"node_id,omitempty"`
	Name       string `json:"name,omitempty"`
	Size       int64  `json:"size"`
	Files      int    `json:"files"`
	Encryption string `json:"encryption,omitempty"`
}

// ctxReaderAt fails the reads of a staged blob once ctx is done, so that a
// cancelled job stops inside a long entry, not only between files.
type ctxReaderAt struct {
	ctx context.Context
	r   io.ReaderAt
}

func (c ctxReaderAt) ReadAt(p []byte, off int64) (int, error) {
	if err := c.ctx.Err(); err != nil {
		return 0, err
	}
	return c.r.ReadAt(p, off)
}

func (svc *Service) runZipJob(ctx context.Context, j core.JobHandle) error {
	var p zipParams
	if err := j.Params(&p); err != nil {
		return err
	}
	if p.BatchID == "" {
		return core.Invalid("batch_id", "batch_id is required")
	}
	return svc.zipBatch(ctx, j, p.BatchID)
}

func (svc *Service) zipCompression() ziputil.Compression {
	if svc.env.Settings == nil {
		return ziputil.CompressionAuto
	}
	if _, err := svc.env.Settings.Raw(settingZipCompression); err != nil {
		return ziputil.CompressionAuto
	}
	switch c := ziputil.Compression(svc.env.Settings.String(settingZipCompression)); c {
	case ziputil.CompressionStore, ziputil.CompressionDeflate:
		return c
	}
	return ziputil.CompressionAuto
}

// zipBatch implements the upload.zip job: every staged file of a finalizing
// batch is streamed, sorted by rel_path and with directory entries, through
// ziputil into a new blob, which is committed as one node <zip_name> in the
// batch folder (conflict policy applies). The file entries of a protected
// batch are encrypted with its password (opened from the batch row here),
// and the stored version is recorded as protected. Staged blobs are deleted
// afterwards; upload.batch_done is published in every outcome.
func (svc *Service) zipBatch(ctx context.Context, j core.JobHandle, batchID string) error {
	b, err := svc.batchByID(ctx, svc.env.DB.Reader(), batchID)
	if err != nil {
		if errors.Is(err, core.ErrNotFound) {
			return nil // aborted and forgotten, or the share was deleted
		}
		return err
	}
	if b.State != core.BatchFinalizing {
		return nil
	}
	rows, err := svc.env.DB.Query(ctx, `SELECT `+fileCols+` FROM upload_files WHERE batch_id = ?
		AND ((kind = 'file' AND state = 'uploaded') OR (kind = 'dir' AND state = 'pending')) ORDER BY rel_path, kind`, b.ID)
	if err != nil {
		return err
	}
	var list []*fileRow
	var total int64
	for rows.Next() {
		f, err := scanFile(rows)
		if err != nil {
			rows.Close()
			return err
		}
		list = append(list, f)
		total += f.Size
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}

	var w core.BlobWriter
	fail := func(err error) error {
		if w != nil {
			_ = w.Abort()
		}
		if ctx.Err() != nil {
			// The job was cancelled: the server is shutting down, or the
			// job was cancelled by hand. The staged data is intact, so the
			// batch stays finalizing and maintenance.uploads decides from
			// how the job ended — it runs the zip again after a shutdown
			// and fails the batch after a cancel (failStuckZips).
			svc.log.Warn("zip upload interrupted", "batch", b.ID, "err", err)
			return err
		}
		msg := "the zip file could not be created"
		if ce := core.AsError(err); ce != nil {
			msg += ": " + ce.Message
		}
		svc.failBatch(ctx, b, msg)
		return err
	}
	p, err := svc.files.SysPrincipalFor(ctx, b.UserID)
	if err != nil {
		return fail(err)
	}
	enc, pw, err := svc.openZipPassword(ctx, b.ID)
	if errors.Is(err, core.ErrKeysLocked) {
		// Transient: the batch stays finalizing with its data and its sealed
		// password, and maintenance.uploads runs the job again.
		svc.log.Warn("zip upload postponed: the keys are locked", "batch", b.ID)
		return err
	}
	if err != nil {
		return fail(err)
	}
	if w, err = svc.blobs.Create(ctx); err != nil {
		w = nil
		return fail(err)
	}
	// The Writer keeps the password until Close (which drops it).
	zw, err := ziputil.New(w, ziputil.Options{Format: ziputil.FormatZip, Compression: svc.zipCompression(),
		Encryption: ziputil.Encryption(enc), Password: pw})
	if err != nil {
		return fail(err)
	}
	var done int64
	files := 0
	j.Progress(0, total, "")
	for _, f := range list {
		if err := ctx.Err(); err != nil {
			return fail(err)
		}
		mod := b.CreatedAt
		if f.ClientMtime != nil {
			mod = *f.ClientMtime
		}
		if f.Kind == core.UploadKindDir {
			if err := zw.AddDir(f.RelPath, mod); err != nil {
				return fail(err)
			}
			continue
		}
		r, err := svc.blobs.Open(ctx, f.BlobID)
		if err != nil {
			return fail(err)
		}
		err = zw.AddFileAt(f.RelPath, mod, f.Size, ctxReaderAt{ctx: ctx, r: r})
		_ = r.Close()
		if err != nil {
			return fail(err)
		}
		files++
		done += f.Size
		j.Progress(done, total, f.RelPath)
	}
	if err := zw.Close(); err != nil {
		return fail(err)
	}
	info, err := w.Commit(ctx)
	if err != nil {
		return fail(err)
	}
	w = nil
	// A protected batch holding only folders has no encrypted entry: the
	// stored .zip is not marked protected.
	recorded := enc
	if files == 0 {
		recorded = ""
	}
	node, err := svc.files.CommitFile(ctx, p, b.FolderID, b.ZipName, info,
		core.FileMeta{MIME: "application/zip", ClientMtime: nil, ZipEncryption: recorded}, b.Conflict)
	skipped, identical := false, false
	switch {
	case err != nil && b.Conflict == core.ConflictSkip && errors.Is(err, core.ErrConflict):
		skipped = true
	case err != nil:
		svc.deleteBlob(ctx, info.ID)
		return fail(err)
	case unused(node, info) && b.Conflict == core.ConflictReplace && sameContent(node, info):
		identical = true // the file already holds these bytes: no new version, the result is that file
	case unused(node, info):
		skipped = true
	}
	if skipped || identical {
		svc.deleteBlob(ctx, info.ID)
	}

	// Record the outcome; from here on the job must not be interrupted.
	ctx = context.WithoutCancel(ctx)
	now := db.Ms(svc.env.Now())
	nodeID := sql.NullString{}
	fileState := core.UploadSkipped
	if node != nil && !skipped {
		nodeID = sql.NullString{String: node.ID, Valid: true}
		fileState = core.UploadCommitted
	}
	err = svc.env.DB.Tx(ctx, func(tx *sql.Tx) error {
		res, err := tx.ExecContext(ctx, `UPDATE upload_batches SET state = 'done', reserved_bytes = 0, result_node_id = ?,
			error = NULL, zip_password_enc = NULL, updated_at = ? WHERE id = ? AND state = 'finalizing'`, nodeID, now, b.ID)
		if err != nil {
			return err
		}
		if n, err := res.RowsAffected(); err != nil || n == 0 {
			if err == nil {
				err = fmt.Errorf("uploads: batch %s is no longer finalizing", b.ID)
			}
			return err
		}
		if _, err := tx.ExecContext(ctx, `UPDATE upload_files SET state = ?, node_id = ?, updated_at = ?
			WHERE batch_id = ? AND ((kind = 'file' AND state = 'uploaded') OR (kind = 'dir' AND state = 'pending'))`,
			fileState, nodeID, now, b.ID); err != nil {
			return err
		}
		if b.ShareID != "" && nodeID.Valid {
			if _, err := tx.ExecContext(ctx, `UPDATE shares SET upload_used_bytes = upload_used_bytes + ? WHERE id = ?`,
				total, b.ShareID); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		// The batch stays finalizing and the job failed, so maintenance.uploads
		// runs it again — which stores the zip a second time (conflict policy
		// applies) rather than losing the upload.
		svc.log.Error("record finished zip upload", "batch", b.ID, "node", nodeID.String, "err", err)
		return err
	}
	for _, f := range list {
		if f.Kind == core.UploadKindFile {
			svc.deleteStaged(ctx, f)
		}
	}
	nb, err := svc.batchByID(ctx, svc.env.DB.Reader(), b.ID)
	if err != nil {
		return err
	}
	svc.decorate(nb)
	res := zipResult{Size: info.Size, Files: files}
	if nodeID.Valid {
		res.NodeID, res.Name = nodeID.String, node.Name
		res.Encryption = recorded
	}
	j.SetResult(res)
	j.Progress(total, total, "")
	svc.finished(ctx, nb, firstNonEmpty(nodeID.String, b.FolderID), files, total)
	svc.log.Info("zip upload finished", "batch", b.ID, "files", files, "bytes", info.Size, "encryption", recorded)
	return nil
}

// deleteStaged deletes the staged blob of a zipped file and forgets it.
func (svc *Service) deleteStaged(ctx context.Context, f *fileRow) {
	if f.BlobID == "" {
		return
	}
	svc.deleteBlob(ctx, f.BlobID)
	if err := svc.env.DB.Tx(ctx, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `UPDATE upload_files SET blob_id = NULL WHERE id = ?`, f.ID)
		return err
	}); err != nil {
		svc.log.Warn("forget staged blob", "upload", f.ID, "err", err)
	}
}

// failBatch marks a finalizing batch failed (wiping its sealed .zip
// password in the same statement), deletes its staged data and publishes
// upload.batch_done.
func (svc *Service) failBatch(ctx context.Context, b *core.UploadBatch, msg string) {
	ctx = context.WithoutCancel(ctx)
	if len(msg) > 500 {
		msg = msg[:500]
	}
	now := db.Ms(svc.env.Now())
	var updated int64
	err := svc.env.DB.Tx(ctx, func(tx *sql.Tx) error {
		res, err := tx.ExecContext(ctx, `UPDATE upload_batches SET state = 'failed', reserved_bytes = 0, error = ?,
			zip_password_enc = NULL, updated_at = ? WHERE id = ? AND state = 'finalizing'`, msg, now, b.ID)
		if err != nil {
			return err
		}
		updated, err = res.RowsAffected()
		return err
	})
	if err != nil {
		svc.log.Error("mark upload batch failed", "batch", b.ID, "err", err)
		return
	}
	if updated == 0 {
		return
	}
	svc.log.Warn("upload batch failed", "batch", b.ID, "reason", msg)
	svc.cleanupFiles(ctx, b.ID, core.UploadFailed)
	nb, err := svc.batchByID(ctx, svc.env.DB.Reader(), b.ID)
	if err != nil {
		return
	}
	svc.finished(ctx, svc.decorate(nb), b.FolderID, 0, 0)
}
