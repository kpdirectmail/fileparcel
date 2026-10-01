package files

import (
	"context"
	"database/sql"

	"fileparcel/internal/core"
	"fileparcel/internal/db"
	"fileparcel/internal/ids"
	"fileparcel/internal/names"
)

// versionsKeep is storage.versions_keep (at least 1: the current version).
func (svc *Service) versionsKeep() int64 {
	return max(1, svc.settingInt(settingVersionsKeep, 10))
}

// pruneVersions deletes the oldest versions of nodeID beyond keep (never
// the current version), releases their quota and queues their blobs.
func (o *op) pruneVersions(spaceID, nodeID, currentID string, keep int64) error {
	rows, err := o.q.QueryContext(o.ctx, `SELECT id, blob_id, size FROM file_versions WHERE node_id = ? AND id != ?
		ORDER BY created_at DESC, id DESC LIMIT -1 OFFSET ?`, nodeID, currentID, max(0, keep-1))
	if err != nil {
		return err
	}
	var drop []string
	var freed int64
	for rows.Next() {
		var id, blob string
		var size int64
		if err := rows.Scan(&id, &blob, &size); err != nil {
			rows.Close()
			return err
		}
		drop = append(drop, id)
		freed += size
		o.blobCheck = append(o.blobCheck, blob)
	}
	rows.Close()
	if err := rows.Err(); err != nil || len(drop) == 0 {
		return err
	}
	if _, err := o.q.ExecContext(o.ctx, `DELETE FROM file_versions WHERE id IN (`+placeholders(len(drop))+`)`,
		anyArgs(drop)...); err != nil {
		return err
	}
	return o.charge(spaceID, -freed, false)
}

// Versions implements core.Files: the versions of a file, newest first
// (PermView).
func (svc *Service) Versions(ctx context.Context, p *core.Principal, id string) ([]core.FileVersion, error) {
	var out []core.FileVersion
	err := svc.read(ctx, p, func(o *op) error {
		n, err := o.authorize(id, core.PermView, authOpt{allowTrashed: true})
		if err != nil {
			return err
		}
		if n.IsDir() {
			return core.Invalid("id", "folders have no versions")
		}
		rows, err := o.q.QueryContext(o.ctx, `SELECT v.id, v.node_id, v.blob_id, v.size, COALESCE(v.content_hash, ''),
			v.created_at, COALESCE(v.created_by, ''), COALESCE(NULLIF(u.display_name, ''), u.username, ''),
			COALESCE(v.zip_encryption, '')
			FROM file_versions v LEFT JOIN users u ON u.id = v.created_by
			WHERE v.node_id = ? ORDER BY v.created_at DESC, v.id DESC`, n.ID)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var v core.FileVersion
			var created int64
			if err := rows.Scan(&v.ID, &v.NodeID, &v.BlobID, &v.Size, &v.ContentHash, &created, &v.CreatedBy,
				&v.CreatedByName, &v.ZipEncryption); err != nil {
				return err
			}
			v.CreatedAt = db.FromMs(created)
			v.Current = v.ID == n.VersionID
			out = append(out, v)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, err
	}
	if out == nil {
		out = []core.FileVersion{}
	}
	return out, nil
}

// RestoreVersion implements core.Files: makes an older version current
// again (PermEdit). The version moves to the top of the history: a new
// current version sharing its blob takes the place of its row, so the
// history stays chronological, a restore never pushes another version out
// (storage.versions_keep) and the content is not charged to the quota twice.
// The MIME type is detected again from the restored content: nodes.mime
// describes the current version only (DESIGN §8.2). The zip protection
// follows the restored version (restoring an unprotected version clears it).
func (svc *Service) RestoreVersion(ctx context.Context, p *core.Principal, id, versionID string) (*core.Node, error) {
	if !ids.Valid(ids.PrefixVersion, versionID) {
		return nil, core.NotFoundf("version not found")
	}
	// Authorize and find the version first, then sniff its content outside
	// any transaction (like Rename).
	var pre *nodeRow
	var blobID string
	var size int64
	err := svc.read(ctx, p, func(o *op) error {
		n, err := o.authorize(id, core.PermEdit, authOpt{})
		if err != nil {
			return err
		}
		if n.IsDir() {
			return core.Invalid("id", "folders have no versions")
		}
		pre = n
		if versionID == n.VersionID {
			return nil
		}
		err = o.q.QueryRowContext(o.ctx, `SELECT blob_id, size FROM file_versions WHERE id = ? AND node_id = ?`,
			versionID, n.ID).Scan(&blobID, &size)
		if db.IsNoRows(err) {
			return core.NotFoundf("version not found")
		}
		return err
	})
	if err != nil {
		return nil, err
	}
	if versionID == pre.VersionID {
		return &pre.Node, nil
	}
	head := svc.readHead(ctx, blobID, size) // version rows never change their blob

	var out *nodeRow
	err = svc.write(ctx, p, func(o *op) error {
		// The read above audited an access through the admin override.
		n, err := o.authorize(id, core.PermEdit, authOpt{noAdminAudit: true})
		if err != nil {
			return err
		}
		if n.IsDir() {
			return core.Invalid("id", "folders have no versions")
		}
		if versionID == n.VersionID {
			out = n
			return nil
		}
		b := blobRow{}
		err = o.q.QueryRowContext(o.ctx, `SELECT blob_id, size, COALESCE(content_hash, ''), COALESCE(zip_encryption, '')
			FROM file_versions WHERE id = ? AND node_id = ?`, versionID, n.ID).Scan(&b.id, &b.size, &b.hash, &b.zipEnc)
		if db.IsNoRows(err) {
			return core.NotFoundf("version not found")
		}
		if err != nil {
			return err
		}
		// The type of the restored bytes, for the name the file has now (a
		// rename may have come in between). Content that could not be read
		// is never given an inline type.
		mime := names.OctetStream
		if head != nil {
			mime = names.DetectMIME(n.Name, "", head)
		}
		// Its row makes way for the new current version (same blob, which
		// therefore stays referenced), and its quota with it.
		if _, err := o.q.ExecContext(o.ctx, `DELETE FROM file_versions WHERE id = ? AND node_id = ?`,
			versionID, n.ID); err != nil {
			return err
		}
		if err := o.charge(n.SpaceID, -b.size, false); err != nil {
			return err
		}
		out, err = o.addVersion(n.ID, &b, mime, n.ClientMtime, core.ActFileVersionRestore)
		if err == nil {
			o.audits[len(o.audits)-1].Details = versionDetails(&b,
				map[string]any{"restored_version_id": versionID, "size": b.size})
		}
		return err
	})
	if err != nil {
		return nil, err
	}
	return &out.Node, nil
}

// pruneAllVersions applies storage.versions_keep to every file (job
// maintenance.versions) and returns the number of deleted versions.
func (svc *Service) pruneAllVersions(ctx context.Context) (int64, error) {
	keep := svc.versionsKeep()
	var total int64
	after := ""
	for {
		var batch []string
		rows, err := svc.env.DB.Query(ctx, `SELECT node_id FROM file_versions WHERE node_id > ?
			GROUP BY node_id HAVING COUNT(*) > ? ORDER BY node_id LIMIT 200`, after, keep)
		if err != nil {
			return total, err
		}
		for rows.Next() {
			var id string
			if err := rows.Scan(&id); err != nil {
				rows.Close()
				return total, err
			}
			batch = append(batch, id)
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return total, err
		}
		if len(batch) == 0 {
			return total, nil
		}
		after = batch[len(batch)-1]
		var dropped int64 // per attempt: the transaction may be retried
		err = svc.writeSys(ctx, func(o *op) error {
			dropped = 0
			for _, id := range batch {
				n, err := o.loadNode(id)
				if err != nil {
					return err
				}
				if n == nil || n.VersionID == "" {
					continue
				}
				before := len(o.blobCheck)
				if err := o.pruneVersions(n.SpaceID, n.ID, n.VersionID, keep); err != nil {
					return err
				}
				dropped += int64(len(o.blobCheck) - before)
			}
			return nil
		})
		if err != nil {
			return total, err
		}
		total += dropped
		if err := ctx.Err(); err != nil {
			return total, err
		}
	}
}

// reconcileUsage recomputes spaces.used_bytes from the stored versions
// (self-healing after crashes or manual database edits) and returns the
// number of corrected spaces.
func (svc *Service) reconcileUsage(ctx context.Context) (int, error) {
	type fix struct {
		id         string
		have, want int64
	}
	var fixes []fix
	rows, err := svc.env.DB.Query(ctx, `SELECT s.id, s.used_bytes, COALESCE((SELECT SUM(v.size) FROM file_versions v
		JOIN nodes n ON n.id = v.node_id WHERE n.space_id = s.id), 0) FROM spaces s`)
	if err != nil {
		return 0, err
	}
	for rows.Next() {
		var f fix
		if err := rows.Scan(&f.id, &f.have, &f.want); err != nil {
			rows.Close()
			return 0, err
		}
		if f.have != f.want {
			fixes = append(fixes, f)
		}
	}
	rows.Close()
	if err := rows.Err(); err != nil || len(fixes) == 0 {
		return 0, err
	}
	err = svc.env.DB.Tx(ctx, func(tx *sql.Tx) error {
		for _, f := range fixes {
			if _, err := tx.ExecContext(ctx, `UPDATE spaces SET used_bytes = COALESCE((SELECT SUM(v.size) FROM file_versions v
				JOIN nodes n ON n.id = v.node_id WHERE n.space_id = ?1), 0) WHERE id = ?1`, f.id); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return 0, err
	}
	for _, f := range fixes {
		svc.log.Warn("storage usage corrected", "space", f.id, "was", f.have, "now", f.want)
	}
	return len(fixes), nil
}
