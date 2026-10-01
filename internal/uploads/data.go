package uploads

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"

	"fileparcel/internal/core"
	"fileparcel/internal/db"
	"fileparcel/internal/ids"
)

// Lock keys.
func fileKey(uploadID string) string        { return "f:" + uploadID }
func partKey(uploadID string, n int) string { return "p:" + uploadID + ":" + strconv.Itoa(n) }

func errDigest() error {
	return core.Invalid("X-FP-SHA256", "the data does not match its SHA-256 digest; please retry")
}

func errBatchState(state string) error {
	return core.Errorf(core.ErrConflict, "the upload batch is %s", state)
}

// recordedPart returns the digest of part n if it was received (nil otherwise).
func (svc *Service) recordedPart(ctx context.Context, uploadID string, n int) ([]byte, error) {
	var sum []byte
	err := svc.env.DB.QueryRow(ctx, `SELECT sha256 FROM upload_parts WHERE upload_id = ? AND n = ?`, uploadID, n).Scan(&sum)
	if db.IsNoRows(err) {
		return nil, nil
	}
	return sum, err
}

// resend answers a part that was already received: the same digest is a
// successful no-op (idempotent retry), a different one is 409.
func resend(have, want []byte, n int) error {
	if bytes.Equal(have, want) {
		return nil
	}
	return core.Errorf(core.ErrConflict, "part %d was already received with different content", n)
}

// PutPart implements core.Uploads: it streams part n of a large file into
// its parted blob, verifying the SHA-256 digest sent by the client. size is
// the request's Content-Length (-1 = unknown); the part must be exactly the
// expected length. Parts may arrive in any order and in parallel. A part
// that was already received with the same digest is accepted without
// rewriting; a different digest is 409.
func (svc *Service) PutPart(ctx context.Context, a core.UploadActor, uploadID string, n int, body io.Reader, size int64, sha []byte) error {
	if len(sha) != sha256.Size {
		return core.Invalid("X-FP-SHA256", "the SHA-256 digest of the part is required (64 hex characters)")
	}
	f, b, err := svc.loadFile(ctx, a, uploadID)
	if err != nil {
		return err
	}
	if f.Kind != core.UploadKindFile {
		return core.Invalid("n", "directories have no data")
	}
	if n < 0 || n >= f.PartCount {
		return core.Invalid("n", fmt.Sprintf("part number must be between 0 and %d", f.PartCount-1))
	}
	if f.Size == 0 {
		return core.Invalid("n", "empty files are sent with the small-file request")
	}
	want := partLen(f.Size, n)
	if size >= 0 && size != want {
		return core.Invalid("body", fmt.Sprintf("part %d must be exactly %d bytes (got %d)", n, want, size))
	}
	if have, err := svc.recordedPart(ctx, f.ID, n); err != nil || have != nil {
		if err != nil {
			return err
		}
		return resend(have, sha, n)
	}
	if b.State != core.BatchOpen {
		return errBatchState(b.State)
	}
	if f.State == core.UploadSkipped && f.BlobID == "" {
		return nil // declared skipped (preflight.go): nothing to store; completing it reports "skipped"
	}
	if f.State != core.UploadPending && f.State != core.UploadUploading {
		return core.Errorf(core.ErrConflict, "the upload is %s", f.State)
	}

	unlock, err := svc.locks.Lock(ctx, partKey(f.ID, n))
	if err != nil {
		return err
	}
	defer unlock()
	// A duplicate send of this part may have finished while we waited.
	if have, err := svc.recordedPart(ctx, f.ID, n); err != nil || have != nil {
		if err != nil {
			return err
		}
		return resend(have, sha, n)
	}
	pb, err := svc.partedBlob(ctx, f.ID)
	if err != nil {
		return err
	}
	br := newBodyReader(body, want)
	got, werr := pb.WritePart(ctx, n, br, sha)
	if cerr := br.clientError(want); cerr != nil {
		return cerr
	}
	switch {
	case br.complete() && !bytes.Equal(br.sum(), sha):
		return errDigest()
	case werr != nil:
		return werr
	case !br.complete():
		return core.Invalid("body", fmt.Sprintf("part %d must be exactly %d bytes", n, want))
	case len(got) != 0 && !bytes.Equal(got, sha):
		return errDigest()
	case size < 0 && br.trailing():
		return br.trailingError(fmt.Sprintf("part %d must be exactly %d bytes", n, want))
	}

	now := db.Ms(svc.env.Now())
	return svc.env.DB.Tx(ctx, func(tx *sql.Tx) error {
		var bstate, fstate string
		if err := tx.QueryRowContext(ctx, `SELECT b.state, f.state FROM upload_files f
			JOIN upload_batches b ON b.id = f.batch_id WHERE f.id = ?`, f.ID).Scan(&bstate, &fstate); err != nil {
			return err
		}
		if bstate != core.BatchOpen {
			return errBatchState(bstate)
		}
		if fstate != core.UploadPending && fstate != core.UploadUploading {
			return core.Errorf(core.ErrConflict, "the upload is %s", fstate)
		}
		var have []byte
		err := tx.QueryRowContext(ctx, `SELECT sha256 FROM upload_parts WHERE upload_id = ? AND n = ?`, f.ID, n).Scan(&have)
		switch {
		case err == nil:
			return resend(have, sha, n)
		case !db.IsNoRows(err):
			return err
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO upload_parts (upload_id, n, size, sha256, received_at) VALUES (?, ?, ?, ?, ?)`,
			f.ID, n, want, sha, now); err != nil {
			return err
		}
		_, err = tx.ExecContext(ctx, `UPDATE upload_files SET state = 'uploading', updated_at = ?,
			parts_done = (SELECT COUNT(*) FROM upload_parts WHERE upload_id = ?) WHERE id = ?`, now, f.ID, f.ID)
		return err
	})
}

// partedBlob returns the parted blob of an upload, creating it on the first
// part. Creation is serialised per upload so parallel first parts share one
// blob.
func (svc *Service) partedBlob(ctx context.Context, uploadID string) (core.PartedBlob, error) {
	unlock, err := svc.locks.Lock(ctx, fileKey(uploadID))
	if err != nil {
		return nil, err
	}
	defer unlock()
	f, err := svc.fileByID(ctx, svc.env.DB.Reader(), uploadID)
	if err != nil {
		return nil, err
	}
	if f.State != core.UploadPending && f.State != core.UploadUploading {
		return nil, core.Errorf(core.ErrConflict, "the upload is %s", f.State)
	}
	if f.BlobID != "" {
		return svc.blobs.OpenParted(ctx, f.BlobID)
	}
	pb, err := svc.blobs.CreateParted(ctx, f.Size)
	if err != nil {
		return nil, err
	}
	if pb.PartCount() != f.PartCount {
		_ = pb.Abort()
		return nil, fmt.Errorf("uploads: blob store part count %d != %d", pb.PartCount(), f.PartCount)
	}
	now := db.Ms(svc.env.Now())
	var updated int64
	err = svc.env.DB.Tx(ctx, func(tx *sql.Tx) error {
		res, err := tx.ExecContext(ctx, `UPDATE upload_files SET blob_id = ?, state = 'uploading', updated_at = ?
			WHERE id = ? AND blob_id IS NULL AND state IN ('pending','uploading')`, pb.ID(), now, uploadID)
		if err != nil {
			return err
		}
		updated, err = res.RowsAffected()
		return err
	})
	if err != nil || updated == 0 {
		_ = pb.Abort()
		if err == nil {
			err = core.Errorf(core.ErrConflict, "the upload was cancelled")
		}
		return nil, err
	}
	return pb, nil
}

// PutSmall implements core.Uploads: the whole content of a file of at most
// SmallMax bytes (including empty files) in one request, streamed into a
// new blob. In mode=files the node is committed right away and the
// returned state carries its node_id. Re-sending the same content is
// idempotent — except for a file whose node commit failed for good, which
// answers that failure (409) as CompleteFile does; different content is
// 409. The file lock is not held while the body is read (only around the
// checks and the recording), so a slow sender cannot stall an abort, the
// expiry job or a share revocation that waits for it.
func (svc *Service) PutSmall(ctx context.Context, a core.UploadActor, batchID, clientRef string, body io.Reader, size int64, sha []byte) (*core.UploadFileState, error) {
	if len(sha) != sha256.Size {
		return nil, core.Invalid("X-FP-SHA256", "the SHA-256 digest of the file is required (64 hex characters)")
	}
	if a.P == nil {
		return nil, core.ErrUnauthorized
	}
	b, err := svc.loadBatch(ctx, a, batchID)
	if err != nil {
		return nil, err
	}
	var uploadID string
	err = svc.env.DB.QueryRow(ctx, `SELECT id FROM upload_files WHERE batch_id = ? AND client_ref = ?`, b.ID, clientRef).Scan(&uploadID)
	if db.IsNoRows(err) {
		return nil, core.NotFoundf("no file with this client_ref in the upload batch")
	}
	if err != nil {
		return nil, err
	}
	f, st, err := svc.smallCheck(ctx, a, b.ID, uploadID, size, sha)
	if err != nil || st != nil {
		return st, err
	}

	w, err := svc.blobs.Create(ctx)
	if err != nil {
		return nil, err
	}
	br := newBodyReader(body, f.Size)
	_, cerr := io.Copy(w, br)
	fail := func(err error) (*core.UploadFileState, error) {
		_ = w.Abort()
		return nil, err
	}
	if e := br.clientError(f.Size); e != nil {
		return fail(e)
	}
	switch {
	case cerr != nil:
		return fail(cerr)
	case !bytes.Equal(br.sum(), sha):
		return fail(errDigest())
	case size < 0 && br.trailing():
		return fail(br.trailingError(fmt.Sprintf("the body must be exactly %d bytes", f.Size)))
	}
	info, err := w.Commit(ctx)
	if err != nil {
		return fail(err)
	}
	// Record the data under the file lock again; the transaction re-checks
	// what the lock-free stream may have missed (an abort, another send).
	unlock, err := svc.locks.Lock(ctx, fileKey(f.ID))
	if err != nil {
		svc.deleteBlob(ctx, info.ID)
		return nil, err
	}
	defer unlock()
	now := db.Ms(svc.env.Now())
	var updated int64
	err = svc.env.DB.Tx(ctx, func(tx *sql.Tx) error {
		var bstate string
		if err := tx.QueryRowContext(ctx, `SELECT state FROM upload_batches WHERE id = ?`, b.ID).Scan(&bstate); err != nil {
			return err
		}
		if bstate != core.BatchOpen {
			return errBatchState(bstate)
		}
		res, err := tx.ExecContext(ctx, `UPDATE upload_files SET blob_id = ?, parts_done = 1, state = 'uploaded', updated_at = ?
			WHERE id = ? AND state = 'pending'`, info.ID, now, f.ID)
		if err != nil {
			return err
		}
		if updated, err = res.RowsAffected(); err != nil || updated == 0 {
			return err
		}
		_, err = tx.ExecContext(ctx, `INSERT INTO upload_parts (upload_id, n, size, sha256, received_at) VALUES (?, 0, ?, ?, ?)`,
			f.ID, f.Size, sha, now)
		return err
	})
	if err != nil || updated == 0 {
		// Blob ids are random per writer, so this is never the blob of a
		// send that won.
		svc.deleteBlob(ctx, info.ID)
		// Another send of this file may have recorded it while this one
		// streamed: the same content gets that send's answer.
		if st, handled, rerr := svc.smallResent(ctx, a, b.ID, f.ID, sha); handled {
			return st, rerr
		}
		if err == nil {
			err = core.Errorf(core.ErrConflict, "the upload was cancelled")
		}
		return nil, err
	}
	f.State, f.BlobID = core.UploadUploaded, info.ID
	if b.Mode == core.UploadModeFiles {
		return svc.commitNode(ctx, a, b, f, info)
	}
	return svc.fileState(ctx, f.ID)
}

// smallCheck runs the checks of a small-file send under the file lock. It
// returns the pending file to stream into, or the answer to a re-send of
// data that was already received.
func (svc *Service) smallCheck(ctx context.Context, a core.UploadActor, batchID, uploadID string, size int64, sha []byte) (*fileRow, *core.UploadFileState, error) {
	unlock, err := svc.locks.Lock(ctx, fileKey(uploadID))
	if err != nil {
		return nil, nil, err
	}
	defer unlock()
	f, err := svc.fileByID(ctx, svc.env.DB.Reader(), uploadID)
	if err != nil {
		return nil, nil, err
	}
	if f.Kind != core.UploadKindFile {
		return nil, nil, core.Invalid("ref", "directories have no data")
	}
	if f.Size > SmallMax {
		return nil, nil, core.Invalid("ref", fmt.Sprintf("files larger than %d bytes are sent in parts", SmallMax))
	}
	if size >= 0 && size != f.Size {
		return nil, nil, core.Invalid("body", fmt.Sprintf("the body must be exactly %d bytes (got %d)", f.Size, size))
	}
	if st, handled, err := svc.smallResent(ctx, a, batchID, f.ID, sha); handled {
		return nil, st, err
	}
	b, err := svc.batchByID(ctx, svc.env.DB.Reader(), batchID)
	if err != nil {
		return nil, nil, err
	}
	if b.State != core.BatchOpen {
		return nil, nil, errBatchState(b.State)
	}
	if f.State == core.UploadSkipped {
		// Declared skipped (its name was taken, preflight.go): a client that
		// sends it anyway learns that from the answer, nothing is stored.
		st, err := svc.fileState(ctx, f.ID)
		return nil, st, err
	}
	if f.State != core.UploadPending {
		return nil, nil, core.Errorf(core.ErrConflict, "the upload is %s", f.State)
	}
	return f, nil, nil
}

// smallResent answers a small-file send whose data was already received
// (called with the file lock held); handled is false when nothing was
// received yet. The same digest is idempotent: the file's state, or in
// mode=files a retry of a node commit that failed transiently. A file
// whose commit failed for good answers that failure, as CompleteFile does:
// its staged data is gone, so a 200 would report a file that was never
// stored. A different digest is 409.
func (svc *Service) smallResent(ctx context.Context, a core.UploadActor, batchID, uploadID string, sha []byte) (st *core.UploadFileState, handled bool, err error) {
	have, err := svc.recordedPart(ctx, uploadID, 0)
	switch {
	case err != nil:
		return nil, true, err
	case have == nil:
		return nil, false, nil
	}
	if err := resend(have, sha, 0); err != nil {
		return nil, true, err
	}
	f, err := svc.fileByID(ctx, svc.env.DB.Reader(), uploadID)
	if err != nil {
		return nil, true, err
	}
	switch f.State {
	case core.UploadFailed:
		return nil, true, core.Errorf(core.ErrConflict, "the upload failed: %s", firstNonEmpty(f.Error, "unknown error"))
	case core.UploadAborted:
		return nil, true, core.Errorf(core.ErrConflict, "the upload was cancelled")
	case core.UploadUploaded:
		b, err := svc.batchByID(ctx, svc.env.DB.Reader(), batchID)
		if err != nil {
			return nil, true, err
		}
		if b.Mode == core.UploadModeFiles && b.State == core.BatchOpen {
			st, err := svc.commitUploaded(ctx, a, b, f) // resume after a failed node commit
			return st, true, err
		}
	}
	st, err = svc.fileState(ctx, f.ID)
	return st, true, err
}

// CompleteFile implements core.Uploads: once every part is present the
// parted blob is committed; in mode=files the node is created (folders of
// rel_path included) with the batch's conflict policy. Directory entries
// create their folder. Completing an already completed file returns its
// state.
func (svc *Service) CompleteFile(ctx context.Context, a core.UploadActor, uploadID string) (*core.UploadFileState, error) {
	if a.P == nil {
		return nil, core.ErrUnauthorized
	}
	if _, _, err := svc.loadFile(ctx, a, uploadID); err != nil {
		return nil, err
	}
	unlock, err := svc.locks.Lock(ctx, fileKey(uploadID))
	if err != nil {
		return nil, err
	}
	defer unlock()
	f, err := svc.fileByID(ctx, svc.env.DB.Reader(), uploadID)
	if err != nil {
		return nil, err
	}
	b, err := svc.batchByID(ctx, svc.env.DB.Reader(), f.BatchID)
	if err != nil {
		return nil, err
	}
	switch f.State {
	case core.UploadCommitted, core.UploadSkipped:
		return svc.fileState(ctx, f.ID)
	case core.UploadFailed:
		return nil, core.Errorf(core.ErrConflict, "the upload failed: %s", firstNonEmpty(f.Error, "unknown error"))
	case core.UploadAborted:
		return nil, core.Errorf(core.ErrConflict, "the upload was cancelled")
	}
	if b.State != core.BatchOpen {
		return nil, errBatchState(b.State)
	}
	if f.Kind == core.UploadKindDir {
		return svc.commitDir(ctx, a, b, f)
	}
	if f.State == core.UploadUploaded {
		if b.Mode == core.UploadModeZip {
			return svc.fileState(ctx, f.ID)
		}
		return svc.commitUploaded(ctx, a, b, f)
	}
	if f.Size == 0 || f.BlobID == "" {
		return nil, core.Errorf(core.ErrConflict, "no data received yet: have 0 of %d parts", f.PartCount)
	}
	digests, stored, err := svc.partDigests(ctx, f.ID)
	if err != nil {
		return nil, err
	}
	if len(digests) != f.PartCount {
		return nil, core.Errorf(core.ErrConflict, "the upload is incomplete: have %d of %d parts (missing: %s)",
			len(stored), f.PartCount, missingParts(stored, f.PartCount))
	}
	info, err := svc.commitParted(ctx, f.BlobID, digests)
	if err != nil {
		return nil, err
	}
	now := db.Ms(svc.env.Now())
	err = svc.env.DB.Tx(ctx, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `UPDATE upload_files SET state = 'uploaded', updated_at = ? WHERE id = ?`, now, f.ID)
		return err
	})
	if err != nil {
		return nil, err
	}
	f.State = core.UploadUploaded
	if b.Mode == core.UploadModeZip {
		return svc.fileState(ctx, f.ID)
	}
	return svc.commitNode(ctx, a, b, f, info)
}

// commitParted commits the parted blob of an upload. When an earlier
// completion committed the blob but could not record it (the blob store
// then refuses to reopen it as a parted blob), the committed blob is
// accepted if its content hash matches the recorded part digests.
func (svc *Service) commitParted(ctx context.Context, blobID string, digests [][]byte) (*core.BlobInfo, error) {
	pb, err := svc.blobs.OpenParted(ctx, blobID)
	if err == nil {
		return pb.Commit(ctx, digests)
	}
	if !errors.Is(err, core.ErrConflict) {
		return nil, err
	}
	info, serr := svc.blobs.Stat(ctx, blobID)
	if serr != nil || info.ContentHash != contentHash(digests) {
		return nil, err
	}
	return info, nil
}

// contentHash is the blob content hash of DESIGN §7.3 computed from the
// SHA-256 digests of the 8 MiB parts: "fp1:" + hex(SHA-256(concat(digests))).
func contentHash(digests [][]byte) string {
	h := sha256.New()
	for _, d := range digests {
		h.Write(d)
	}
	return "fp1:" + hex.EncodeToString(h.Sum(nil))
}

// partDigests returns the part digests of an upload ordered by part number
// and the numbers of the parts stored. digests stops at the first missing
// part, so it holds every part only when none is missing.
func (svc *Service) partDigests(ctx context.Context, uploadID string) (digests [][]byte, stored []int, err error) {
	rows, err := svc.env.DB.Query(ctx, `SELECT n, sha256 FROM upload_parts WHERE upload_id = ? ORDER BY n`, uploadID)
	if err != nil {
		return nil, nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var n int
		var sum []byte
		if err := rows.Scan(&n, &sum); err != nil {
			return nil, nil, err
		}
		if n == len(digests) && len(stored) == len(digests) {
			digests = append(digests, sum)
		}
		stored = append(stored, n)
	}
	return digests, stored, rows.Err()
}

// missingParts lists the part numbers below count that stored (ascending)
// lacks: "1", "0, 2, 5" or, past eight of them, the first eight and
// "and 12 more".
func missingParts(stored []int, count int) string {
	const shown = 8
	var list []string
	more := 0
	for n, i := 0, 0; n < count; n++ {
		for i < len(stored) && stored[i] < n {
			i++
		}
		if i < len(stored) && stored[i] == n {
			continue
		}
		if len(list) < shown {
			list = append(list, strconv.Itoa(n))
		} else {
			more++
		}
	}
	s := strings.Join(list, ", ")
	if more > 0 {
		s += fmt.Sprintf(" and %d more", more)
	}
	return s
}

// commitUploaded commits the node of a file whose blob is already committed
// (retry after a transient node-commit failure).
func (svc *Service) commitUploaded(ctx context.Context, a core.UploadActor, b *core.UploadBatch, f *fileRow) (*core.UploadFileState, error) {
	info, err := svc.blobs.Stat(ctx, f.BlobID)
	if err != nil {
		return nil, err
	}
	return svc.commitNode(ctx, a, b, f, info)
}

// unused reports whether a CommitFile result did not store blob info: no
// node, or (conflict=skip) the existing entry of that name — a file with
// another blob, or a folder (which has no blob at all).
func unused(node *core.Node, info *core.BlobInfo) bool {
	return node == nil || node.Kind != core.KindFile || node.BlobID != info.ID
}

// sameContent reports whether the file node already holds the content of
// blob info (conflict "replace" with byte-identical data adds no version).
func sameContent(node *core.Node, info *core.BlobInfo) bool {
	return node != nil && node.Kind == core.KindFile && info.ContentHash != "" && node.ContentHash == info.ContentHash
}

// permanent reports whether a node-commit error is final (the file is then
// marked failed) rather than transient (the client may retry completion).
func permanent(err error) bool {
	for _, e := range []*core.Error{core.ErrConflict, core.ErrInvalid, core.ErrQuota, core.ErrForbidden,
		core.ErrNotFound, core.ErrTooLarge} {
		if errors.Is(err, e) {
			return true
		}
	}
	return false
}

// commitNode creates the file node for an uploaded blob (mode=files) and
// records the outcome. Called with the file lock held. Files.CommitFile
// creates the missing folders of rel_path. With conflict=skip an existing
// name leaves the file "skipped" (CommitFile then returns the existing node,
// whose blob differs, and the unused blob is deleted); a permanent failure
// (conflict=fail, quota, permission) marks it "failed".
//
// The blob is stored and recorded by now, so the node commit and its
// bookkeeping run to the end even if the client goes away: a cancelled
// CommitFile would leave the file "uploaded", and a bookkeeping transaction
// cancelled after CommitFile stored the node would make the next completion
// store it a second time.
func (svc *Service) commitNode(ctx context.Context, a core.UploadActor, b *core.UploadBatch, f *fileRow, info *core.BlobInfo) (*core.UploadFileState, error) {
	ctx = context.WithoutCancel(ctx)
	node, err := svc.files.CommitFile(ctx, a.P, b.FolderID, f.RelPath, info,
		core.FileMeta{MIME: f.MIME, ClientMtime: f.ClientMtime}, b.Conflict)
	state, msg := core.UploadCommitted, ""
	identical := false
	switch {
	case err != nil && b.Conflict == core.ConflictSkip && errors.Is(err, core.ErrConflict):
		state = core.UploadSkipped
	case err != nil && !permanent(err):
		return nil, err // stays "uploaded": completing the file or the batch retries the node commit
	case err != nil:
		state, msg = core.UploadFailed, errMessage(err)
	case unused(node, info) && b.Conflict == core.ConflictReplace && sameContent(node, info):
		// The file already holds exactly these bytes: CommitFile added no
		// version. The upload still did its job (the file is up to date),
		// so it is committed to that node, and the unused blob goes.
		identical = true
	case unused(node, info):
		state = core.UploadSkipped
	}
	now := db.Ms(svc.env.Now())
	txErr := svc.env.DB.Tx(ctx, func(tx *sql.Tx) error {
		nodeID := sql.NullString{}
		if node != nil && state == core.UploadCommitted {
			nodeID = sql.NullString{String: node.ID, Valid: true}
		}
		if _, err := tx.ExecContext(ctx, `UPDATE upload_files SET state = ?, node_id = ?, error = ?, updated_at = ?
			WHERE id = ?`, state, nodeID, db.NullString(msg), now, f.ID); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `UPDATE upload_batches SET reserved_bytes = MAX(0, reserved_bytes - ?), updated_at = ?
			WHERE id = ?`, f.Size, now, b.ID); err != nil {
			return err
		}
		if b.ShareID != "" && state == core.UploadCommitted {
			if _, err := tx.ExecContext(ctx, `UPDATE shares SET upload_used_bytes = upload_used_bytes + ? WHERE id = ?`,
				f.Size, b.ShareID); err != nil {
				return err
			}
		}
		return nil
	})
	if txErr != nil {
		// The node exists but a database failure kept the upload row from
		// being updated: the next completion attempt re-commits (conflict
		// policy applies) — log it.
		svc.log.Error("record committed upload", "upload", f.ID, "err", txErr)
		return nil, txErr
	}
	if state != core.UploadCommitted || identical {
		svc.deleteBlob(ctx, info.ID)
	}
	if state == core.UploadFailed {
		return nil, err
	}
	return svc.fileState(ctx, f.ID)
}

// commitDir creates the folder of a directory entry (mode=files).
func (svc *Service) commitDir(ctx context.Context, a core.UploadActor, b *core.UploadBatch, f *fileRow) (*core.UploadFileState, error) {
	if b.Mode == core.UploadModeZip {
		return svc.fileState(ctx, f.ID) // directories become zip entries in the job
	}
	node, err := svc.files.MkdirAll(ctx, a.P, b.FolderID, f.RelPath)
	state, msg, nodeID := core.UploadCommitted, "", sql.NullString{}
	switch {
	case err != nil && !permanent(err):
		return nil, err
	case err != nil:
		state, msg = core.UploadFailed, errMessage(err)
	case node != nil:
		nodeID = sql.NullString{String: node.ID, Valid: true}
	}
	now := db.Ms(svc.env.Now())
	if txErr := svc.env.DB.Tx(ctx, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `UPDATE upload_files SET state = ?, node_id = ?, error = ?, updated_at = ? WHERE id = ?`,
			state, nodeID, db.NullString(msg), now, f.ID)
		return err
	}); txErr != nil {
		return nil, txErr
	}
	if state == core.UploadFailed {
		return nil, err
	}
	return svc.fileState(ctx, f.ID)
}

// errMessage returns the user-facing message of err.
func errMessage(err error) string {
	if ce := core.AsError(err); ce != nil {
		return ce.Message
	}
	return "internal error"
}

// deleteBlob removes a blob that is no longer needed (best effort: the blob
// store's GC removes leftovers).
func (svc *Service) deleteBlob(ctx context.Context, id string) {
	if id == "" || !ids.ValidBlobID(id) {
		return
	}
	if err := svc.blobs.Delete(context.WithoutCancel(ctx), id); err != nil && !errors.Is(err, core.ErrNotFound) {
		svc.log.Warn("delete staged blob", "blob", id, "err", err)
	}
}
