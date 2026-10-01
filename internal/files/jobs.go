package files

import (
	"context"
	"errors"
	"time"

	"fileparcel/internal/core"
	"fileparcel/internal/thumbs"
)

// Job tuning.
const (
	// maintLock serializes the storage maintenance jobs.
	maintLock = "files.maintenance"
	// blobMinAge protects fresh blobs (uploads in flight, jobs that have not
	// recorded their blob yet) from garbage collection.
	blobMinAge = 48 * time.Hour
	// thumbTimeout bounds one thumbnail job.
	thumbTimeout = 2 * time.Minute
)

// schedules are the daily maintenance schedules (local time; after the
// nightly quiet hours, before the default backups at 03:00/04:00).
var schedules = []struct{ kind, cron string }{
	{core.JobMaintTrash, "10 2 * * *"},
	{core.JobMaintVersions, "25 2 * * *"},
	{core.JobMaintBlobGC, "40 2 * * *"},
}

// thumbParams are the parameters of a thumbs.generate job.
type thumbParams struct {
	NodeID    string `json:"node_id"`
	VersionID string `json:"version_id"`
}

// registerJobs registers the job kinds owned by files and their schedules.
//
// maintenance.blob_gc is registered only when the blob store does not
// register it itself: the real blob store (a core.JobRegistrar) owns that
// kind — its GC already removes unreferenced ready blobs, abandoned staging
// blobs and orphan files, and its RegisterJobs runs after this constructor,
// so a registration here would only be overridden (with a warning).
func (svc *Service) registerJobs(j core.Jobs) {
	j.Register(core.JobThumbsGenerate, svc.jobThumbs, core.JobOptions{MaxConcurrent: 2, Timeout: thumbTimeout, Hidden: true})
	j.Register(core.JobMaintTrash, svc.jobTrash, core.JobOptions{Exclusive: maintLock, Timeout: 6 * time.Hour})
	j.Register(core.JobMaintVersions, svc.jobVersions, core.JobOptions{Exclusive: maintLock, Timeout: 6 * time.Hour})
	_, blobsOwnGC := svc.blobs.(core.JobRegistrar)
	if !blobsOwnGC {
		j.Register(core.JobMaintBlobGC, svc.jobBlobGC, core.JobOptions{Exclusive: maintLock, Timeout: 6 * time.Hour})
	}
	for _, s := range schedules {
		if s.kind == core.JobMaintBlobGC && blobsOwnGC {
			continue
		}
		if err := j.Schedule(s.kind, s.cron, s.kind, map[string]any{}); err != nil {
			svc.log.Error("cannot schedule maintenance job", "kind", s.kind, "err", err)
		}
	}
}

// enqueueThumb queues a thumbnail job (errors are logged: a missing
// thumbnail is not worth failing an upload for).
func (svc *Service) enqueueThumb(ctx context.Context, t thumbParams) {
	if svc.jobs == nil {
		return
	}
	if _, err := svc.jobs.Enqueue(ctx, core.JobThumbsGenerate, t, nil); err != nil {
		svc.log.Warn("cannot queue thumbnail", "node", t.NodeID, "err", err)
	}
}

// jobThumbs is thumbs.generate: decode the current version of an image
// (bounded, see package thumbs), store the thumbnail as an encrypted blob
// and record it in nodes.thumb_blob_id — unless the node changed meanwhile.
func (svc *Service) jobThumbs(ctx context.Context, j core.JobHandle) error {
	var prm thumbParams
	if err := j.Params(&prm); err != nil {
		return err
	}
	skip := func(reason string) error {
		j.SetResult(map[string]any{"skipped": reason})
		return nil
	}
	if !svc.settingBool(settingThumbnails, true) {
		return skip("thumbnails are disabled")
	}
	if svc.blobs == nil {
		return errors.New("files: no blob store")
	}
	var n *nodeRow
	if err := svc.readSys(ctx, func(o *op) error {
		var err error
		n, err = o.loadNode(prm.NodeID)
		return err
	}); err != nil {
		return err
	}
	switch {
	case n == nil || n.TrashedAt != nil || n.Kind != core.KindFile:
		return skip("gone")
	case n.VersionID != prm.VersionID:
		return skip("stale version")
	case n.ThumbBlobID != "":
		return skip("exists")
	case !thumbs.Supported(n.MIME) || n.BlobID == "":
		return skip("unsupported type")
	}
	r, err := svc.openBlob(ctx, n.BlobID, n.Size)
	if err != nil {
		return err
	}
	th, err := thumbs.Generate(ctx, r, n.Size, thumbs.Options{})
	r.Close()
	if errors.Is(err, thumbs.ErrUnsupported) || errors.Is(err, thumbs.ErrTooLarge) {
		return skip(err.Error())
	}
	if err != nil {
		return err
	}
	bw, err := svc.blobs.Create(ctx)
	if err != nil {
		return err
	}
	if _, err := bw.Write(th.Data); err != nil {
		_ = bw.Abort()
		return err
	}
	info, err := bw.Commit(ctx)
	if err != nil {
		_ = bw.Abort()
		return err
	}
	applied := false
	err = svc.writeSys(ctx, func(o *op) error {
		res, err := o.q.ExecContext(o.ctx, `UPDATE nodes SET thumb_blob_id = ? WHERE id = ? AND version_id = ?
			AND trashed_at IS NULL AND thumb_blob_id IS NULL`, info.ID, n.ID, prm.VersionID)
		if err != nil {
			return err
		}
		c, _ := res.RowsAffected()
		applied = c == 1
		return nil
	})
	if err != nil || !applied {
		svc.deleteUnreferenced(context.WithoutCancel(ctx), []string{info.ID})
		if err != nil {
			return err
		}
		return skip("changed while generating")
	}
	j.SetResult(map[string]any{"mime": th.MIME, "width": th.Width, "height": th.Height, "bytes": len(th.Data)})
	return nil
}

// jobTrash is maintenance.trash: purge trash older than storage.trash_days.
func (svc *Service) jobTrash(ctx context.Context, j core.JobHandle) error {
	days := svc.settingInt(settingTrashDays, 30)
	if days <= 0 {
		j.SetResult(map[string]any{"skipped": "trash retention is unlimited"})
		return nil
	}
	cutoff := svc.env.Now().Add(-time.Duration(days) * 24 * time.Hour)
	n, err := svc.purgeExpired(ctx, cutoff, func(done int) { j.Progress(int64(done), 0, "purging expired trash") })
	j.SetResult(map[string]any{"purged": n, "cutoff": cutoff})
	return err
}

// jobVersions is maintenance.versions: apply storage.versions_keep to every
// file and reconcile the storage usage of every space.
func (svc *Service) jobVersions(ctx context.Context, j core.JobHandle) error {
	pruned, err := svc.pruneAllVersions(ctx)
	if err != nil {
		return err
	}
	fixed, err := svc.reconcileUsage(ctx)
	j.SetResult(map[string]any{"versions_deleted": pruned, "usage_corrected": fixed})
	return err
}

// jobBlobGC is maintenance.blob_gc: the blob store's GC (stale staging
// blobs, orphan files) plus the deletion of committed blobs that no file
// version, thumbnail or upload references any more.
func (svc *Service) jobBlobGC(ctx context.Context, j core.JobHandle) error {
	if svc.blobs == nil {
		return errors.New("files: no blob store")
	}
	removed, freed, gcErr := svc.blobs.GC(ctx, blobMinAge)
	if gcErr != nil {
		svc.log.Warn("blob store GC failed", "err", gcErr)
	}
	swept, err := svc.sweepBlobs(ctx, blobMinAge)
	j.SetResult(map[string]any{"gc_removed": removed, "gc_freed_bytes": freed, "unreferenced_deleted": swept})
	if err != nil {
		return err
	}
	return gcErr
}

// sweepBlobs deletes committed blobs older than minAge that nothing
// references (and retries interrupted deletions).
func (svc *Service) sweepBlobs(ctx context.Context, minAge time.Duration) (int, error) {
	cutoff := svc.env.Now().Add(-minAge).UnixMilli()
	deleted, after := 0, ""
	for {
		rows, err := svc.env.DB.Query(ctx, `SELECT b.id FROM blobs b
			WHERE b.state IN ('ready', 'deleting') AND b.created_at < ? AND b.id > ?
			AND NOT EXISTS (SELECT 1 FROM file_versions v WHERE v.blob_id = b.id)
			AND b.id NOT IN (SELECT thumb_blob_id FROM nodes WHERE thumb_blob_id IS NOT NULL)
			AND NOT EXISTS (SELECT 1 FROM upload_files uf JOIN upload_batches ub ON ub.id = uf.batch_id
				WHERE uf.blob_id = b.id AND ub.state IN ('open', 'finalizing'))
			ORDER BY b.id LIMIT 500`, cutoff, after)
		if err != nil {
			return deleted, err
		}
		var batch []string
		for rows.Next() {
			var id string
			if err := rows.Scan(&id); err != nil {
				rows.Close()
				return deleted, err
			}
			batch = append(batch, id)
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return deleted, err
		}
		if len(batch) == 0 {
			return deleted, nil
		}
		after = batch[len(batch)-1]
		for _, id := range batch {
			if err := ctx.Err(); err != nil {
				return deleted, err
			}
			ref, err := blobReferenced(ctx, svc.env.DB.Reader(), id)
			if err != nil {
				return deleted, err
			}
			if ref {
				continue
			}
			if err := svc.blobs.Delete(ctx, id); err != nil && !errors.Is(err, core.ErrNotFound) {
				svc.log.Warn("blob delete failed", "blob", id, "err", err)
				continue
			}
			deleted++
		}
	}
}
