package files

import (
	"cmp"
	"context"
	"slices"
	"time"

	"fileparcel/internal/core"
)

// trashOne moves the live node n (and its live descendants) to the trash.
func (o *op) trashOne(n *nodeRow) error {
	if _, err := o.q.ExecContext(o.ctx, `UPDATE nodes SET trashed_at = ?, trashed_by = ?, trash_root = 1 WHERE id = ?`,
		o.ms, o.uid(), n.ID); err != nil {
		return err
	}
	if _, err := o.q.ExecContext(o.ctx, `WITH RECURSIVE sub(id) AS (
			SELECT id FROM nodes WHERE parent_id = ?1 AND trashed_at IS NULL
			UNION ALL
			SELECT c.id FROM nodes c JOIN sub ON c.parent_id = sub.id WHERE c.trashed_at IS NULL
		)
		UPDATE nodes SET trashed_at = ?2, trashed_by = ?3, trash_root = 0 WHERE id IN (SELECT id FROM sub)`,
		n.ID, o.ms, o.uid()); err != nil {
		return err
	}
	o.audit(nodeAudit(core.ActFileTrash, &n.Node, map[string]any{"parent_id": n.ParentID}))
	return nil
}

// Trash implements core.Files: moves ids (and their subtrees) to the trash
// (PermEdit; space roots cannot be trashed; items already in the trash are
// ignored). An item inside another item of the request is trashed together
// with it (one trash entry).
func (svc *Service) Trash(ctx context.Context, p *core.Principal, idList []string) error {
	list, err := checkIDs("ids", idList)
	if err != nil {
		return err
	}
	return svc.write(ctx, p, func(o *op) error {
		items, err := o.outermost(list)
		if err != nil {
			return err
		}
		for _, id := range items {
			n, err := o.authorize(id, core.PermEdit, authOpt{allowTrashed: true})
			if err != nil {
				return err
			}
			if n.TrashedAt != nil {
				continue
			}
			if n.ParentID == "" {
				return forbiddenf("the root folder of a space cannot be moved to the trash")
			}
			if err := o.trashOne(n); err != nil {
				return err
			}
		}
		return nil
	})
}

// Restore implements core.Files: brings trashed items back (PermEdit) with
// everything that was trashed together with them, to their original parent
// — or to the space root when the parent is in the trash itself, which
// needs PermEdit on the root (403 otherwise: restore the folder first). Name
// conflicts are resolved with " (n)". Items that are not in the trash are
// returned unchanged. Outer items are restored before the items inside
// them, so a folder trashed on its own before its parent returns into that
// parent when both are restored together. The result follows the order of
// ids.
func (svc *Service) Restore(ctx context.Context, p *core.Principal, idList []string) ([]core.Node, error) {
	list, err := checkIDs("ids", idList)
	if err != nil {
		return nil, err
	}
	var out []core.Node
	err = svc.write(ctx, p, func(o *op) error {
		out = out[:0]
		ns, err := o.nestingOf(list)
		if err != nil {
			return err
		}
		order := slices.Clone(list)
		slices.SortStableFunc(order, func(a, b string) int { return cmp.Compare(ns.depth[a], ns.depth[b]) })
		done := make(map[string]core.Node, len(list))
		for _, id := range order {
			r, err := o.restoreOne(id)
			if err != nil {
				return err
			}
			done[id] = r.Node
		}
		for _, id := range list {
			out = append(out, done[id])
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (o *op) restoreOne(id string) (*nodeRow, error) {
	n, err := o.authorize(id, core.PermEdit, authOpt{allowTrashed: true})
	if err != nil {
		return nil, err
	}
	if n.TrashedAt == nil {
		return n, nil
	}
	target := n.ParentID
	parent, err := o.loadNode(n.ParentID)
	if err != nil {
		return nil, err
	}
	if parent == nil || parent.TrashedAt != nil {
		if target, err = o.rootOf(n.SpaceID); err != nil {
			return nil, err
		}
		// Adding an item to the space root needs PermEdit there, as for
		// Mkdir, Move and uploads — an editor through a grant inside the
		// space must not place items outside it. Checked before authorize
		// so a root the actor cannot see is refused clearly (not as 404).
		root, err := o.mustNode(target)
		if err != nil {
			return nil, err
		}
		if _, eff, err := o.perms(root); err != nil {
			return nil, err
		} else if eff < core.PermEdit {
			return nil, forbiddenf("“%s” cannot be restored on its own: the folder it was in is in the trash — restore that folder first", n.Name)
		}
		if _, err := o.authorize(target, core.PermEdit, authOpt{}); err != nil { // audits the admin override
			return nil, err
		}
	}
	name, key := n.Name, n.NameKey
	if c, err := o.child(target, key); err != nil {
		return nil, err
	} else if c != nil {
		if name, key, err = o.freeName(target, n.Name, n.IsDir()); err != nil {
			return nil, err
		}
	}
	// Descendants trashed together with n (the walk stops at nested trash roots).
	if _, err := o.q.ExecContext(o.ctx, `WITH RECURSIVE sub(id) AS (
			SELECT id FROM nodes WHERE parent_id = ?1 AND trash_root = 0 AND trashed_at IS NOT NULL
			UNION ALL
			SELECT c.id FROM nodes c JOIN sub ON c.parent_id = sub.id WHERE c.trash_root = 0 AND c.trashed_at IS NOT NULL
		)
		UPDATE nodes SET trashed_at = NULL, trashed_by = NULL WHERE id IN (SELECT id FROM sub)`, n.ID); err != nil {
		return nil, err
	}
	if _, err := o.q.ExecContext(o.ctx, `UPDATE nodes SET parent_id = ?, name = ?, name_key = ?, trashed_at = NULL,
		trashed_by = NULL, trash_root = 0, updated_at = ?, updated_by = ? WHERE id = ?`,
		target, name, key, o.ms, o.uid(), n.ID); err != nil {
		return nil, err
	}
	o.audit(nodeAudit(core.ActFileRestore, &n.Node, map[string]any{"parent_id": target, "name": name}))
	return o.reload(n.ID)
}

// Purge implements core.Files: deletes trashed items permanently with their
// whole subtree (PermOwner; PermManage in group spaces). Items must be in
// the trash (422 otherwise). An item inside the subtree of another item of
// the same call (e.g. a folder trashed on its own before its parent) is
// purged with it, whatever the order of ids. A subtree larger than
// maxPurgeNodes is deleted over several transactions (see purgeRoot), so a
// huge trashed tree never holds the single writer connection for the whole
// deletion.
func (svc *Service) Purge(ctx context.Context, p *core.Principal, idList []string) error {
	list, err := checkIDs("ids", idList)
	if err != nil {
		return err
	}
	// Check every id first, in one read: a call that names something the
	// actor may not purge, or that is not in the trash, must change
	// nothing — it could not, back when the whole call was one transaction.
	if err := svc.read(ctx, p, func(o *op) error {
		for _, id := range list {
			n, err := o.authorize(id, core.PermEdit, authOpt{allowTrashed: true})
			if err != nil {
				return err
			}
			need := transferPerm(n.spaceKind)
			if n.Perm < need {
				return forbiddenf("deleting “%s” permanently needs %s permission", n.Name, need)
			}
			// The override is audited here, once per call and node, with
			// the real requirement; the chunks of purgeRoot only re-check.
			if err := o.auditTransfer(n, need); err != nil {
				return err
			}
			if n.TrashedAt == nil {
				return core.Invalid("ids", "“"+n.Name+"” is not in the trash")
			}
		}
		return nil
	}); err != nil {
		return err
	}
	purged := map[string]bool{}
	for _, id := range list {
		if purged[id] {
			continue
		}
		if err := svc.purgeRoot(ctx, p, id, "user", purged); err != nil {
			return err
		}
	}
	return nil
}

// purgeRoot purges one trashed item and its subtree as p, one bounded
// transaction per chunk, and records the ids it deleted in purged: a later
// id of the same call that lived inside this subtree is then skipped
// instead of answered with 404. The permission is re-checked for every
// chunk, and only ids of a committed chunk reach purged.
func (svc *Service) purgeRoot(ctx context.Context, p *core.Principal, id, reason string, purged map[string]bool) error {
	for {
		var ids []string
		var done bool
		err := svc.write(ctx, p, func(o *op) error {
			// Purge's validation pass audited any use of the admin override
			// (every chunk is a new transaction with a new actor).
			n, err := o.authorize(id, core.PermEdit, authOpt{allowTrashed: true, noAdminAudit: true})
			if err != nil {
				return err
			}
			need := transferPerm(n.spaceKind)
			if n.Perm < need {
				return forbiddenf("deleting “%s” permanently needs %s permission", n.Name, need)
			}
			if n.TrashedAt == nil {
				return core.Invalid("ids", "“"+n.Name+"” is not in the trash")
			}
			ids, done, err = o.purgeChunk(n, reason)
			return err
		})
		if err != nil {
			return err
		}
		for _, pid := range ids {
			purged[pid] = true
		}
		if done {
			return nil
		}
		if err := ctx.Err(); err != nil {
			return err
		}
	}
}

// purgeRootSys is purgeRoot for the system (the retention job): it purges
// the trash root id when it was trashed before cutoff and reports whether
// it did. Every chunk checks that again — the root may have been restored
// and trashed anew (a fresh trashed_at) since the job listed it — and it
// stops quietly when the root is gone or is no longer an expired trash root.
func (svc *Service) purgeRootSys(ctx context.Context, id string, cutoff time.Time, reason string) (bool, error) {
	for {
		var done, skipped bool
		err := svc.writeSys(ctx, func(o *op) error {
			n, err := o.loadNode(id)
			if err != nil || n == nil || n.TrashedAt == nil || !n.TrashRoot ||
				n.TrashedAt.UnixMilli() >= cutoff.UnixMilli() { // the query's trashed_at < cutoff, in ms
				done, skipped = true, true
				return err
			}
			skipped = false
			_, done, err = o.purgeChunk(n, reason)
			return err
		})
		if err != nil {
			return false, err
		}
		if done {
			return !skipped, nil
		}
		if err := ctx.Err(); err != nil {
			return false, err
		}
	}
}

// purgeChunk deletes up to maxPurgeNodes nodes of n's subtree (live or
// trashed) — nodes, versions, grants, stars and shares by cascade —
// releases their quota and queues their blobs for deletion, and returns the
// ids it deleted. Rows go deepest first, so no deep FK cascade chain is
// needed and what is left after a chunk is always a well-formed subtree.
// done says whether n itself went, i.e. whether the subtree is gone.
//
// Bounding the work this way keeps one purge from holding the single writer
// connection (DESIGN §6) for an unbounded number of row deletions and FTS
// delete triggers, which blocks every other write of the server. Every
// chunk is audited with its own figures (`partial` while the subtree is not
// gone yet), so no deletion goes unrecorded when a purge is interrupted.
func (o *op) purgeChunk(n *nodeRow, reason string) (deleted []string, done bool, err error) {
	var freed int64
	type item struct {
		id    string
		depth int
	}
	rows, err := o.q.QueryContext(o.ctx, subtreeSQL+` SELECT id, depth FROM sub ORDER BY depth DESC LIMIT ?`,
		n.ID, maxPurgeNodes)
	if err != nil {
		return nil, false, err
	}
	var items []item
	for rows.Next() {
		var it item
		if err := rows.Scan(&it.id, &it.depth); err != nil {
			rows.Close()
			return nil, false, err
		}
		items = append(items, it)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, false, err
	}
	if len(items) == 0 {
		return nil, true, nil // already gone
	}
	// Deepest first: n itself (depth 0) is the last row, and it is in this
	// chunk only when the whole rest of the subtree fitted in it.
	done = items[len(items)-1].depth == 0

	charges := map[string]int64{}
	for len(items) > 0 {
		k := min(len(items), 500)
		ids := make([]string, k)
		for i := range ids {
			ids[i] = items[i].id
		}
		items = items[k:]
		args := anyArgs(ids)
		ph := placeholders(k)
		// The quota these nodes hold and the blobs to check afterwards —
		// read before the delete cascades their file_versions away.
		usage, err := o.q.QueryContext(o.ctx, `SELECT n.space_id, COALESCE(SUM(v.size), 0) FROM nodes n
			JOIN file_versions v ON v.node_id = n.id WHERE n.id IN (`+ph+`) GROUP BY n.space_id`, args...)
		if err != nil {
			return deleted, false, err
		}
		for usage.Next() {
			var sp string
			var sum int64
			if err := usage.Scan(&sp, &sum); err != nil {
				usage.Close()
				return deleted, false, err
			}
			charges[sp] += sum
		}
		usage.Close()
		if err := usage.Err(); err != nil {
			return deleted, false, err
		}
		blobs, err := o.q.QueryContext(o.ctx, `SELECT v.blob_id FROM file_versions v WHERE v.node_id IN (`+ph+`)
			UNION SELECT n.thumb_blob_id FROM nodes n WHERE n.id IN (`+ph+`) AND n.thumb_blob_id IS NOT NULL`,
			append(append([]any{}, args...), args...)...)
		if err != nil {
			return deleted, false, err
		}
		for blobs.Next() {
			var id string
			if err := blobs.Scan(&id); err != nil {
				blobs.Close()
				return deleted, false, err
			}
			o.blobCheck = append(o.blobCheck, id)
		}
		blobs.Close()
		if err := blobs.Err(); err != nil {
			return deleted, false, err
		}
		if _, err := o.q.ExecContext(o.ctx, `DELETE FROM nodes WHERE id IN (`+ph+`)`, args...); err != nil {
			return deleted, false, err
		}
		deleted = append(deleted, ids...)
	}
	for sp, sum := range charges {
		if err := o.charge(sp, -sum, false); err != nil {
			return deleted, false, err
		}
		freed += sum
	}
	details := map[string]any{"items": len(deleted), "bytes": freed, "reason": reason}
	if !done {
		details["partial"] = true
	}
	o.audit(nodeAudit(core.ActFilePurge, &n.Node, details))
	return deleted, done, nil
}

// trashScope returns the condition (on n/s) selecting trash roots the actor
// sees in the trash view: roots in spaces where the space gives PermEdit,
// plus roots the user trashed elsewhere (filtered by permission later).
func (o *op) trashScope() (string, []any) {
	if o.a.system {
		return "1", nil
	}
	var mem []string
	for g := range o.a.groups {
		mem = append(mem, g)
	}
	cond := "((s.kind = 'user' AND s.owner_user_id = ?) OR n.trashed_by = ?"
	args := []any{o.a.userID, o.a.userID}
	if len(mem) > 0 {
		cond += " OR (s.kind = 'group' AND s.group_id IN (" + placeholders(len(mem)) + "))"
		args = append(args, anyArgs(mem)...)
	}
	return cond + ")", args
}

// ListTrash implements core.Files: the trash roots of the actor's spaces
// (and items the actor trashed elsewhere and can still edit), newest first
// by default (sort=trashed desc; name|size|updated|kind also work). Path is
// the original location.
func (svc *Service) ListTrash(ctx context.Context, p *core.Principal, q core.ListQuery) (core.Page[core.Node], error) {
	sort, desc := q.Sort, q.Desc
	if sort == "" {
		sort, desc = "trashed", true
	}
	sort, err := normalizeSort(sort, true)
	if err != nil {
		return core.Page[core.Node]{}, err
	}
	kcond, kargs, err := kindFilter(q.Kind)
	if err != nil {
		return core.Page[core.Node]{}, err
	}
	var page core.Page[core.Node]
	err = svc.read(ctx, p, func(o *op) error {
		if err := o.checkScope(core.PermView); err != nil {
			return err
		}
		scope, sargs := o.trashScope()
		rows, next, err := o.runList(listSpec{
			where: "n.trash_root = 1 AND n.trashed_at IS NOT NULL AND " + scope + kcond,
			args:  append(sargs, kargs...),
			sort:  sort, desc: desc, cursor: q.Cursor, limit: q.EffectiveLimit(), folderFirst: true,
		})
		if err != nil {
			return err
		}
		if rows, err = o.fillPerms(rows); err != nil {
			return err
		}
		visible := rows[:0]
		for _, r := range rows {
			if r.Perm >= core.PermEdit {
				visible = append(visible, r)
			}
		}
		if err := o.decorate(visible); err != nil {
			return err
		}
		if err := o.fillPaths(visible); err != nil {
			return err
		}
		page = core.NewPage(nodes(visible), next)
		return nil
	})
	return page, err
}

// EmptyTrash implements core.Files: purges every trash root of the spaces
// where the actor may purge (their personal space; group spaces they
// manage), in batches.
func (svc *Service) EmptyTrash(ctx context.Context, p *core.Principal) error {
	for {
		var batch []string
		err := svc.read(ctx, p, func(o *op) error {
			if err := o.checkScope(core.PermEdit); err != nil {
				return err
			}
			cond, args := "", []any{}
			if o.a.system {
				cond = "1"
			} else {
				var mgr []string
				for g, role := range o.a.groups {
					if role == core.GroupRoleManager {
						mgr = append(mgr, g)
					}
				}
				cond = "(s.kind = 'user' AND s.owner_user_id = ?)"
				args = append(args, o.a.userID)
				if len(mgr) > 0 {
					cond = "(" + cond + " OR (s.kind = 'group' AND s.group_id IN (" + placeholders(len(mgr)) + ")))"
					args = append(args, anyArgs(mgr)...)
				}
			}
			rows, err := o.q.QueryContext(o.ctx, `SELECT n.id FROM nodes n JOIN spaces s ON s.id = n.space_id
				WHERE n.trash_root = 1 AND n.trashed_at IS NOT NULL AND `+cond+` LIMIT 100`, args...)
			if err != nil {
				return err
			}
			defer rows.Close()
			for rows.Next() {
				var id string
				if err := rows.Scan(&id); err != nil {
					return err
				}
				batch = append(batch, id)
			}
			return rows.Err()
		})
		if err != nil || len(batch) == 0 {
			return err
		}
		if err := svc.Purge(ctx, p, batch); err != nil {
			return err
		}
		if err := ctx.Err(); err != nil {
			return err
		}
	}
}

// purgeExpired purges trash roots older than the retention (job
// maintenance.trash). It returns the number of purged roots.
func (svc *Service) purgeExpired(ctx context.Context, cutoff time.Time, progress func(n int)) (int, error) {
	done := 0
	for {
		var batch []string
		if err := svc.readSys(ctx, func(o *op) error {
			rows, err := o.q.QueryContext(o.ctx, `SELECT id FROM nodes WHERE trash_root = 1 AND trashed_at IS NOT NULL
				AND trashed_at < ? ORDER BY trashed_at LIMIT 100`, cutoff.UnixMilli())
			if err != nil {
				return err
			}
			defer rows.Close()
			for rows.Next() {
				var id string
				if err := rows.Scan(&id); err != nil {
					return err
				}
				batch = append(batch, id)
			}
			return rows.Err()
		}); err != nil {
			return done, err
		}
		if len(batch) == 0 {
			return done, nil
		}
		for _, id := range batch {
			if err := ctx.Err(); err != nil {
				return done, err
			}
			purged, err := svc.purgeRootSys(ctx, id, cutoff, "retention")
			if err != nil {
				return done, err
			}
			if !purged {
				continue
			}
			done++
			if progress != nil {
				progress(done)
			}
		}
	}
}
