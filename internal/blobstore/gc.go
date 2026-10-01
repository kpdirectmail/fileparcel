package blobstore

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"path/filepath"
	"strings"
	"time"

	"fileparcel/internal/db"
	"fileparcel/internal/ids"
)

// gcBatch is the number of rows or files handled per query.
const gcBatch = 500

// Reference conditions (the only columns that point at blobs, DESIGN §6).
// nodes.thumb_blob_id has no index in schema 0001, so the thumbnail test is
// a non-correlated NOT IN (materialised once per query) rather than a
// per-row EXISTS (a scan of nodes per blob).
const (
	condNoVersion = `NOT EXISTS (SELECT 1 FROM file_versions v WHERE v.blob_id = blobs.id)`
	condNoThumb   = `blobs.id NOT IN (SELECT n.thumb_blob_id FROM nodes n WHERE n.thumb_blob_id IS NOT NULL)`
	condNoUpload  = `NOT EXISTS (SELECT 1 FROM upload_files uf JOIN upload_batches ub ON ub.id = uf.batch_id
		WHERE uf.blob_id = blobs.id AND ub.state IN ('open', 'finalizing'))`
)

// The selection rules of GC, exported so that the read-only estimate of
// "fileparcel gc --dry-run" counts exactly what GC removes. The conditions
// apply to the blobs table (unaliased) and take the created_at cutoff (ms)
// as their only argument.
const (
	// GCFloor is the minimum age GC applies (a smaller minAge is raised).
	GCFloor = defaultGCFloor
	// StaleStagingCond selects abandoned staging blobs.
	StaleStagingCond = `state = 'staging' AND created_at < ? AND ` + condNoUpload
	// UnreferencedReadyCond selects ready blobs nothing references.
	UnreferencedReadyCond = `state = 'ready' AND created_at < ? AND ` + condNoVersion + ` AND ` + condNoThumb + ` AND ` + condNoUpload
)

// IsBlobFile reports whether name in the blob store directory dir1/dir2 is
// where the blob store keeps a blob file (<id[0:2]>/<id[2:4]>/<id>): the
// only files GC considers (as orphans when they have no row).
func IsBlobFile(dir1, dir2, name string) bool {
	return isHexName(dir1, 2) && isHexName(dir2, 2) && ids.ValidBlobID(name) && strings.HasPrefix(name, dir1+dir2)
}

// GC removes garbage and returns the number of blobs (rows or orphan files)
// removed and the bytes freed:
//
//   - rows in state deleting (an interrupted Delete/Abort), whatever their age;
//   - staging blobs older than minAge that no open upload batch references
//     (abandoned uploads and writers);
//   - ready blobs older than minAge that nothing references (no file
//     version, thumbnail or open upload batch), e.g. left by a crash between
//     a blob commit and the node commit;
//   - files older than minAge that have no row.
//
// minAge is raised to at least 15 minutes, and blobs with a writer open in
// this process are never touched, so GC is safe to run at any time.
func (s *Service) GC(ctx context.Context, minAge time.Duration) (removed int, freed int64, err error) {
	minAge = max(minAge, s.gcFloor)
	cutoff := s.env.Now().Add(-minAge)
	add := func(ok bool, n int64) {
		if ok {
			removed++
		}
		freed += n
	}

	// 1. interrupted deletes
	err = s.gcRows(ctx, `state = 'deleting'`, nil, func(id string) error {
		_, rel, _ := blobPaths(id)
		var refs int64
		if err := s.env.DB.QueryRow(ctx, `SELECT count(*) FROM file_versions WHERE blob_id = ?`, id).Scan(&refs); err != nil {
			return err
		}
		if refs > 0 {
			s.log.Error("blob in state deleting is still referenced; leaving it", "blob", id)
			return nil
		}
		ok, n, err := s.finishDelete(ctx, id, rel)
		add(ok, n)
		return err
	})
	if err != nil {
		return removed, freed, err
	}

	// 2. abandoned staging blobs, 3. unreferenced ready blobs
	for _, cond := range []string{StaleStagingCond, UnreferencedReadyCond} {
		err = s.gcRows(ctx, cond, []any{db.Ms(cutoff)}, func(id string) error {
			if _, busy := s.active.Load(id); busy {
				return nil
			}
			ok, n, err := s.removeIf(ctx, id, cond, db.Ms(cutoff))
			add(ok, n)
			return err
		})
		if err != nil {
			return removed, freed, err
		}
	}

	// 4. orphan files
	n, f, err := s.gcOrphans(ctx, cutoff)
	removed += n
	freed += f
	if err == nil && removed > 0 {
		s.log.Info("blob GC", "removed", removed, "freed", freed)
	}
	return removed, freed, err
}

// gcRows calls fn for every blob id matching cond (keyset-paged by id).
func (s *Service) gcRows(ctx context.Context, cond string, args []any, fn func(id string) error) error {
	cursor := ""
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		q := `SELECT id FROM blobs WHERE id > ? AND ` + cond + ` ORDER BY id LIMIT ?`
		rs, err := s.env.DB.Query(ctx, q, append(append([]any{cursor}, args...), gcBatch)...)
		if err != nil {
			return err
		}
		var batch []string
		for rs.Next() {
			var id string
			if err := rs.Scan(&id); err != nil {
				rs.Close()
				return err
			}
			batch = append(batch, id)
		}
		rs.Close()
		if err := rs.Err(); err != nil {
			return err
		}
		if len(batch) == 0 {
			return nil
		}
		for _, id := range batch {
			cursor = id
			if !ids.ValidBlobID(id) {
				s.log.Warn("blob row with an invalid id", "id", id)
				continue
			}
			if err := ctx.Err(); err != nil {
				return err
			}
			if err := fn(id); err != nil {
				return err
			}
		}
	}
}

// removeIf marks id deleting when it still matches cond (re-checked inside
// the write transaction), then removes the file and the row.
func (s *Service) removeIf(ctx context.Context, id, cond string, args ...any) (bool, int64, error) {
	var marked bool
	err := s.env.DB.Tx(ctx, func(tx *sql.Tx) error {
		res, err := tx.ExecContext(ctx, `UPDATE blobs SET state = 'deleting' WHERE id = ? AND `+cond,
			append([]any{id}, args...)...)
		if err != nil {
			return err
		}
		n, _ := res.RowsAffected()
		marked = n == 1
		return nil
	})
	if err != nil || !marked {
		return false, 0, err
	}
	_, rel, _ := blobPaths(id)
	return s.finishDelete(ctx, id, rel)
}

// gcOrphans removes blob files older than cutoff that have no row.
func (s *Service) gcOrphans(ctx context.Context, cutoff time.Time) (int, int64, error) {
	var removed int
	var freed int64
	l1, err := s.listDir(".")
	if err != nil {
		return 0, 0, err
	}
	for _, a := range l1 {
		if !a.IsDir() || !isHexName(a.Name(), 2) {
			continue
		}
		l2, err := s.listDir(a.Name())
		if err != nil {
			return removed, freed, err
		}
		for _, b := range l2 {
			if !b.IsDir() || !isHexName(b.Name(), 2) {
				continue
			}
			dir := filepath.Join(a.Name(), b.Name())
			files, err := s.listDir(dir)
			if err != nil {
				return removed, freed, err
			}
			var cand []fs.DirEntry
			for _, f := range files {
				name := f.Name()
				if !f.Type().IsRegular() || !IsBlobFile(a.Name(), b.Name(), name) {
					continue
				}
				cand = append(cand, f)
			}
			for i := 0; i < len(cand); i += gcBatch {
				if err := ctx.Err(); err != nil {
					return removed, freed, err
				}
				chunk := cand[i:min(i+gcBatch, len(cand))]
				known, err := s.existingRows(ctx, chunk)
				if err != nil {
					return removed, freed, err
				}
				for _, f := range chunk {
					if known[f.Name()] {
						continue
					}
					if _, busy := s.active.Load(f.Name()); busy {
						continue
					}
					info, err := f.Info()
					if err != nil || !info.ModTime().Before(cutoff) {
						continue
					}
					if err := s.root.Remove(filepath.Join(dir, f.Name())); err != nil && !errors.Is(err, fs.ErrNotExist) {
						return removed, freed, fmt.Errorf("blobstore: remove orphan: %w", err)
					}
					s.log.Info("removed orphan blob file", "blob", f.Name(), "size", info.Size())
					removed++
					freed += info.Size()
				}
			}
		}
	}
	return removed, freed, nil
}

// existingRows returns which of the files have a blobs row.
func (s *Service) existingRows(ctx context.Context, files []fs.DirEntry) (map[string]bool, error) {
	args := make([]any, len(files))
	for i, f := range files {
		args[i] = f.Name()
	}
	q := `SELECT id FROM blobs WHERE id IN (?` + strings.Repeat(",?", len(files)-1) + `)`
	rs, err := s.env.DB.Query(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rs.Close()
	out := map[string]bool{}
	for rs.Next() {
		var id string
		if err := rs.Scan(&id); err != nil {
			return nil, err
		}
		out[id] = true
	}
	return out, rs.Err()
}

func (s *Service) listDir(dir string) ([]fs.DirEntry, error) {
	d, err := s.root.Open(dir)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	defer d.Close()
	return d.ReadDir(-1)
}

func isHexName(s string, n int) bool {
	if len(s) != n {
		return false
	}
	for i := 0; i < n; i++ {
		c := s[i]
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

// ---------- verify & re-encrypt ----------

// Verify decrypts every segment of a committed blob, checks its
// content_hash and records verified_at. Any failure is core.ErrCorrupt.
func (s *Service) Verify(ctx context.Context, blobID string) error {
	rd, err := s.Open(ctx, blobID)
	if err != nil {
		return err
	}
	defer rd.Close()
	r, err := s.loadRow(ctx, nil, blobID)
	if err != nil {
		return err
	}
	h := newContentHasher()
	if _, err := io.Copy(h, ctxReader{ctx, rd}); err != nil {
		return err
	}
	if r.contentHash.Valid && r.contentHash.String != "" && h.Sum() != r.contentHash.String {
		return corrupt("content does not match its content hash")
	}
	_, err = s.env.DB.Exec(ctx, `UPDATE blobs SET verified_at = ? WHERE id = ?`, db.Ms(s.env.Now()), blobID)
	return err
}

// Reencrypt copies a committed blob into a new blob with a fresh DEK (and
// the currently selected cipher), verifying the content hash, and returns
// the new id. The caller swaps references and deletes the old blob.
func (s *Service) Reencrypt(ctx context.Context, blobID string) (string, error) {
	rd, err := s.Open(ctx, blobID)
	if err != nil {
		return "", err
	}
	defer rd.Close()
	r, err := s.loadRow(ctx, nil, blobID)
	if err != nil {
		return "", err
	}
	w, err := s.Create(ctx)
	if err != nil {
		return "", err
	}
	defer w.Abort() // no-op after Commit
	if _, err := io.Copy(w, ctxReader{ctx, rd}); err != nil {
		return "", err
	}
	info, err := w.Commit(ctx)
	if err != nil {
		return "", err
	}
	if r.contentHash.Valid && r.contentHash.String != "" && info.ContentHash != r.contentHash.String {
		_ = s.Delete(context.WithoutCancel(ctx), info.ID)
		return "", corrupt("content does not match its content hash")
	}
	return info.ID, nil
}

// ctxReader stops a copy when ctx is done.
type ctxReader struct {
	ctx context.Context
	r   io.Reader
}

func (c ctxReader) Read(p []byte) (int, error) {
	if err := c.ctx.Err(); err != nil {
		return 0, err
	}
	return c.r.Read(p)
}
