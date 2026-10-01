package keys

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"sync"
	"time"

	"fileparcel/internal/core"
	"fileparcel/internal/db"
	"fileparcel/internal/ids"
)

// RotateKEKParams are the params of job keys.rotate_kek. An empty Purpose
// rotates both the blob and the field KEK.
type RotateKEKParams struct {
	Purpose string `json:"purpose,omitempty"`
}

// RotateKEKResult is the result of job keys.rotate_kek.
type RotateKEKResult struct {
	Purposes []string `json:"purposes"`
}

// ReencryptParams are the params of job keys.reencrypt. Blobs created at or
// after Before are skipped (default: the job's creation time), which makes
// retries resume where the previous attempt stopped.
type ReencryptParams struct {
	Before *time.Time `json:"before,omitempty"`
}

// ReencryptResult is the result of job keys.reencrypt.
type ReencryptResult struct {
	Total       int64 `json:"total"`
	Reencrypted int64 `json:"reencrypted"`
	Skipped     int64 `json:"skipped"`
	Failed      int64 `json:"failed"`
}

// jobLock serialises the keys jobs.
const jobLock = "keys"

// reencryptBatch is the number of candidate blob ids read per query.
const reencryptBatch = 100

// Bind implements core.Binder: keys.reencrypt needs the blob store.
func (s *Service) Bind(svcs *core.Services) error {
	if svcs != nil {
		s.blobs = svcs.Blobs
	}
	return nil
}

// RegisterJobs implements core.JobRegistrar (DESIGN §9.7): keys.rotate_kek
// and keys.reencrypt.
func (s *Service) RegisterJobs(j core.Jobs) error {
	j.Register(core.JobKeysRotateKEK, s.jobRotateKEK, core.JobOptions{Exclusive: jobLock})
	j.Register(core.JobKeysReencrypt, s.jobReencrypt, core.JobOptions{Exclusive: jobLock})
	return nil
}

func (s *Service) jobRotateKEK(ctx context.Context, j core.JobHandle) error {
	var p RotateKEKParams
	if err := j.Params(&p); err != nil {
		return core.Invalid("params", "invalid job parameters")
	}
	list := []string{core.KEKBlob, core.KEKField}
	if p.Purpose != "" {
		list = []string{p.Purpose}
	}
	res := RotateKEKResult{Purposes: []string{}}
	for _, purpose := range list {
		note := "re-wrapping " + purpose + " keys"
		err := s.RotateKEK(ctx, purpose, func(done, total int64) { j.Progress(done, total, note) })
		if err != nil {
			j.SetResult(res)
			return err
		}
		res.Purposes = append(res.Purposes, purpose)
	}
	j.SetResult(res)
	return nil
}

// jobReencrypt re-encrypts every referenced blob with a fresh DEK (and the
// currently configured cipher): Blobs.Reencrypt writes the new blob, one
// transaction swaps file_versions.blob_id and nodes.thumb_blob_id to it,
// then the old blob is deleted (DESIGN §7.6).
func (s *Service) jobReencrypt(ctx context.Context, j core.JobHandle) error {
	if s.blobs == nil {
		return core.Errorf(core.ErrUnavailable, "the blob store is not available")
	}
	if err := s.requireUnlocked(); err != nil {
		return err
	}
	var p ReencryptParams
	if err := j.Params(&p); err != nil {
		return core.Invalid("params", "invalid job parameters")
	}
	cutoff := s.env.Now()
	if p.Before != nil && !p.Before.IsZero() {
		cutoff = *p.Before
	} else if t, ok := ids.Time(j.ID()); ok {
		cutoff = t
	}
	res, err := s.reencryptAll(ctx, db.Ms(cutoff), func(r ReencryptResult, note string) {
		if note == "" {
			note = "re-encrypting files"
		}
		j.Progress(r.Reencrypted+r.Skipped+r.Failed, r.Total, note)
	})
	j.SetResult(res)
	details := map[string]any{"target": "data", "reencrypted": res.Reencrypted, "skipped": res.Skipped, "failed": res.Failed}
	if err != nil {
		details["error"] = "interrupted"
		s.audit(ctx, core.ActKeysRotate, core.OutcomeFailure, details)
		return err
	}
	if res.Failed > 0 {
		s.audit(ctx, core.ActKeysRotate, core.OutcomeFailure, details)
		return core.Errorf(core.ErrCorrupt, "%d blobs could not be re-encrypted (they fail their integrity check)", res.Failed)
	}
	s.audit(ctx, core.ActKeysRotate, core.OutcomeSuccess, details)
	return nil
}

// candidateWhere selects the referenced ready blobs created before the
// cutoff. The thumbnail test is a non-correlated IN (materialised once per
// query) because nodes.thumb_blob_id is not indexed in schema 0001.
const (
	thumbIn        = `blobs.id IN (SELECT n.thumb_blob_id FROM nodes n WHERE n.thumb_blob_id IS NOT NULL)`
	candidateWhere = `state = 'ready' AND created_at < ? AND (
	EXISTS (SELECT 1 FROM file_versions v WHERE v.blob_id = blobs.id) OR ` + thumbIn + `)`
)

// candidate is a blob to re-encrypt; thumb is set when a node uses it as
// its thumbnail (only then are nodes updated: a file version blob never
// becomes a thumbnail).
type candidate struct {
	id    string
	thumb bool
}

// HoldBlobs pauses data re-encryption (keys.reencrypt) until the returned
// function is called (calling it twice is harmless); it waits for a blob
// that is being re-encrypted right now. A full backup holds it from before
// its database snapshot until it has copied the last blob: re-encryption
// deletes the old blob of every file it re-encrypts, so a blob the snapshot
// lists would otherwise be gone by the time the backup copies it, and the
// archive would miss files the database still references.
func (s *Service) HoldBlobs() func() {
	s.blobMu.RLock()
	var once sync.Once
	return func() { once.Do(s.blobMu.RUnlock) }
}

// holdPoll is how often a paused re-encryption checks whether the backup
// that holds the blobs has finished.
var holdPoll = time.Second

// lockBlobs takes blobMu for writing, waiting (ctx-aware) while a backup
// holds it; waiting (may be nil) is called once when it has to wait.
func (s *Service) lockBlobs(ctx context.Context, waiting func()) error {
	if s.blobMu.TryLock() {
		return nil
	}
	if waiting != nil {
		waiting()
	}
	t := time.NewTicker(holdPoll)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-t.C:
			if s.blobMu.TryLock() {
				return nil
			}
		}
	}
}

// reencryptAll processes every candidate blob (keyset-paged by id). Each
// blob is re-encrypted under blobMu, from the copy to the deletion of the
// old blob, so the job pauses while a backup holds the blobs (HoldBlobs);
// progress gets a note while it waits ("" otherwise).
func (s *Service) reencryptAll(ctx context.Context, cutoffMs int64, progress func(ReencryptResult, string)) (ReencryptResult, error) {
	var res ReencryptResult
	if err := s.env.DB.QueryRow(ctx, `SELECT count(*) FROM blobs WHERE `+candidateWhere, cutoffMs).Scan(&res.Total); err != nil {
		return res, err
	}
	progress(res, "")
	cursor := ""
	for {
		batch, err := s.candidates(ctx, cutoffMs, cursor)
		if err != nil {
			return res, err
		}
		if len(batch) == 0 {
			return res, nil
		}
		for _, c := range batch {
			id := c.id
			cursor = id
			if err := ctx.Err(); err != nil {
				return res, err
			}
			// Not only the swap and the deletion: a copy left unreferenced
			// while the job waits would be removed by the blob GC.
			if err := s.lockBlobs(ctx, func() { progress(res, "waiting for a running backup") }); err != nil {
				return res, err
			}
			err := s.reencryptOne(ctx, c)
			s.blobMu.Unlock()
			switch {
			case err == nil:
				res.Reencrypted++
			case errors.Is(err, errSkip), errors.Is(err, core.ErrNotFound):
				res.Skipped++
			case errors.Is(err, core.ErrCorrupt):
				res.Failed++
				s.log.Error("blob failed its integrity check during re-encryption", "blob", id, "err", err)
			default:
				return res, err
			}
			progress(res, "")
		}
	}
}

func (s *Service) candidates(ctx context.Context, cutoffMs int64, cursor string) ([]candidate, error) {
	rs, err := s.env.DB.Query(ctx, `SELECT id, `+thumbIn+` FROM blobs WHERE id > ? AND `+candidateWhere+` ORDER BY id LIMIT ?`,
		cursor, cutoffMs, reencryptBatch)
	if err != nil {
		return nil, err
	}
	defer rs.Close()
	var out []candidate
	for rs.Next() {
		var c candidate
		if err := rs.Scan(&c.id, &c.thumb); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rs.Err()
}

var errSkip = errors.New("skipped")

// reencryptOne re-encrypts one blob and swaps its references.
func (s *Service) reencryptOne(ctx context.Context, c candidate) error {
	oldID := c.id
	newID, err := s.blobs.Reencrypt(ctx, oldID)
	if err != nil {
		return err
	}
	var swapped int64
	err = s.env.DB.Tx(ctx, func(tx *sql.Tx) error {
		swapped = 0
		r1, err := tx.ExecContext(ctx, `UPDATE file_versions SET blob_id = ? WHERE blob_id = ?`, newID, oldID)
		if err != nil {
			return err
		}
		swapped, _ = r1.RowsAffected()
		if c.thumb {
			r2, err := tx.ExecContext(ctx, `UPDATE nodes SET thumb_blob_id = ? WHERE thumb_blob_id = ?`, newID, oldID)
			if err != nil {
				return err
			}
			n2, _ := r2.RowsAffected()
			swapped += n2
		}
		return nil
	})
	if err != nil {
		if derr := s.blobs.Delete(context.WithoutCancel(ctx), newID); derr != nil {
			s.log.Warn("cannot remove the unused re-encrypted blob (GC will)", "blob", newID, "err", derr)
		}
		return fmt.Errorf("keys: swap blob references: %w", err)
	}
	if swapped == 0 { // purged meanwhile
		if derr := s.blobs.Delete(context.WithoutCancel(ctx), newID); derr != nil {
			s.log.Warn("cannot remove the unused re-encrypted blob (GC will)", "blob", newID, "err", derr)
		}
		return errSkip
	}
	if err := s.blobs.Delete(context.WithoutCancel(ctx), oldID); err != nil {
		s.log.Warn("cannot remove the old blob after re-encryption (GC will)", "blob", oldID, "err", err)
	}
	return nil
}
