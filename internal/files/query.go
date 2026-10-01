package files

import (
	"context"
	"database/sql"
	"strings"
	"unicode/utf8"

	"golang.org/x/text/unicode/norm"

	"fileparcel/internal/core"
	"fileparcel/internal/db"
	"fileparcel/internal/ids"
	"fileparcel/internal/names"
)

// Spaces implements core.Files: the actor's personal space and the spaces of
// their groups, direct or through their role (every space for the system
// principal and for admins with auth.admin_can_access_files). Perm is the
// permission the space gives on its root; QuotaBytes is the effective quota
// (nil = unlimited).
func (svc *Service) Spaces(ctx context.Context, p *core.Principal) ([]core.Space, error) {
	out := []core.Space{}
	err := svc.read(ctx, p, func(o *op) error {
		if err := o.checkScope(core.PermView); err != nil {
			return err
		}
		where := "1"
		var args []any
		if !o.a.system && !o.a.adminOK {
			where = `(s.kind = 'user' AND s.owner_user_id = ?) OR
				(s.kind = 'group' AND s.group_id IN (SELECT group_id FROM effective_group_members WHERE user_id = ?))`
			args = []any{o.a.userID, o.a.userID}
		}
		rows, err := o.q.QueryContext(o.ctx, `SELECT s.id, s.kind, COALESCE(s.owner_user_id, ''), COALESCE(s.group_id, ''),
			s.name, s.used_bytes, s.created_at, COALESCE(r.id, '')
			FROM spaces s LEFT JOIN nodes r ON r.space_id = s.id AND r.parent_id IS NULL
			WHERE `+where+`
			ORDER BY CASE WHEN s.kind = 'user' AND s.owner_user_id = ? THEN 0 WHEN s.kind = 'group' THEN 1 ELSE 2 END,
				s.name COLLATE NOCASE, s.id`, append(args, o.a.userID)...)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var s core.Space
			var created int64
			if err := rows.Scan(&s.ID, &s.Kind, &s.OwnerUserID, &s.GroupID, &s.Name, &s.UsedBytes, &created, &s.RootID); err != nil {
				return err
			}
			s.CreatedAt = db.FromMs(created)
			s.Perm = o.a.spacePerm(s.Kind, s.OwnerUserID, s.GroupID)
			if o.a.adminOK && s.Perm < core.PermManage {
				s.Perm = core.PermManage
			}
			out = append(out, s)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, err
	}
	for i := range out {
		su, err := svc.spaceQuota(ctx, svc.env.DB.Reader(), out[i].ID)
		if err != nil {
			return nil, err
		}
		if su.quota > 0 {
			q := su.quota
			out[i].QuotaBytes = &q
		}
	}
	return out, nil
}

// Get implements core.Files: one node (PermView; trashed nodes included)
// with Perm, Starred, HasThumb and, for folders, ChildCount.
func (svc *Service) Get(ctx context.Context, p *core.Principal, id string) (*core.Node, error) {
	var out *nodeRow
	err := svc.read(ctx, p, func(o *op) error {
		n, err := o.authorize(id, core.PermView, authOpt{allowTrashed: true})
		if err != nil {
			return err
		}
		out = n
		return o.decorate([]*nodeRow{n})
	})
	if err != nil {
		return nil, err
	}
	return &out.Node, nil
}

// Authorize implements core.Files: returns the live node id when the
// principal holds need on it (404 invisible or trashed, 403 insufficient).
// API tokens need files:write for PermEdit and above, except for PermManage:
// that is the level of sharing (the shares service's only use of it), whose
// writes the shares scope guards — plus files:write, demanded by the shares
// service itself, for a share that accepts uploads — so it needs files:read.
func (svc *Service) Authorize(ctx context.Context, p *core.Principal, id string, need core.Perm) (*core.Node, error) {
	opt := authOpt{}
	if need == core.PermManage {
		opt.scope = core.ScopeFilesRead
	}
	var out *nodeRow
	err := svc.read(ctx, p, func(o *op) error {
		var err error
		out, err = o.authorize(id, need, opt)
		return err
	})
	if err != nil {
		return nil, err
	}
	return &out.Node, nil
}

// List implements core.Files: the children of a folder (PermView), keyset
// paginated by q (sort name|size|updated|kind, folders first). The children
// of a trashed folder are the items trashed together with it.
func (svc *Service) List(ctx context.Context, p *core.Principal, folderID string, q core.ListQuery) (core.Page[core.Node], error) {
	var page core.Page[core.Node]
	err := svc.read(ctx, p, func(o *op) error {
		f, err := o.authorize(folderID, core.PermView, authOpt{allowTrashed: true})
		if err != nil {
			return err
		}
		if !f.IsDir() {
			return core.Invalid("id", "not a folder")
		}
		page, err = o.listChildren(f, q)
		return err
	})
	return page, err
}

// listChildren lists the children of folder f (already authorized, or nil
// permissions for system listings).
func (o *op) listChildren(f *nodeRow, q core.ListQuery) (core.Page[core.Node], error) {
	sort, err := normalizeSort(q.Sort, false)
	if err != nil {
		return core.Page[core.Node]{}, err
	}
	kcond, kargs, err := kindFilter(q.Kind)
	if err != nil {
		return core.Page[core.Node]{}, err
	}
	where := "n.parent_id = ? AND n.trashed_at IS NULL"
	if f.TrashedAt != nil {
		where = "n.parent_id = ? AND n.trash_root = 0 AND n.trashed_at IS NOT NULL"
	}
	rows, next, err := o.runList(listSpec{where: where + kcond, args: append([]any{f.ID}, kargs...),
		sort: sort, desc: q.Desc, cursor: q.Cursor, limit: q.EffectiveLimit(), folderFirst: true})
	if err != nil {
		return core.Page[core.Node]{}, err
	}
	// Children have at least the folder's permission; a grant on a child
	// may raise it (up to PermManage: a manager grant on a subfolder of a
	// team folder the actor may only edit).
	for _, r := range rows {
		r.Perm = f.Perm
	}
	if f.Perm < core.PermManage && !o.a.system {
		if rows, err = o.fillPerms(rows); err != nil {
			return core.Page[core.Node]{}, err
		}
		for _, r := range rows {
			r.Perm = max(r.Perm, f.Perm)
		}
	}
	if err := o.decorate(rows); err != nil {
		return core.Page[core.Node]{}, err
	}
	return core.NewPage(nodes(rows), next), nil
}

// Breadcrumbs implements core.Files: the chain from the space root (or,
// for access through a grant, from the highest granted ancestor) down to
// id itself (PermView).
func (svc *Service) Breadcrumbs(ctx context.Context, p *core.Principal, id string) ([]core.Node, error) {
	var out []core.Node
	err := svc.read(ctx, p, func(o *op) error {
		n, err := o.authorize(id, core.PermView, authOpt{allowTrashed: true})
		if err != nil {
			return err
		}
		gcond, gargs := o.grantCond("g")
		rows, err := o.q.QueryContext(o.ctx, `WITH RECURSIVE anc(id, parent_id, depth) AS (
				SELECT id, parent_id, 0 FROM nodes WHERE id = ?
				UNION ALL
				SELECT n.id, n.parent_id, anc.depth + 1 FROM nodes n JOIN anc ON n.id = anc.parent_id
			)
			SELECT anc.id, EXISTS(SELECT 1 FROM node_grants g WHERE g.node_id = anc.id AND `+gcond+`)
			FROM anc ORDER BY anc.depth DESC`, append([]any{n.ID}, gargs...)...)
		if err != nil {
			return err
		}
		var chain []string
		var granted []bool
		for rows.Next() {
			var cid string
			var g bool
			if err := rows.Scan(&cid, &g); err != nil {
				rows.Close()
				return err
			}
			chain = append(chain, cid)
			granted = append(granted, g)
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return err
		}
		start := 0
		if o.a.spacePerm(n.spaceKind, n.spaceOwner, n.spaceGroup) < core.PermView && !o.a.adminOK {
			start = len(chain) - 1
			for i, g := range granted {
				if g {
					start = i
					break
				}
			}
		}
		chain = chain[start:]
		list, err := collectNodes(o.q.QueryContext(o.ctx, selectNodes+` WHERE n.id IN (`+placeholders(len(chain))+`)`,
			anyArgs(chain)...))
		if err != nil {
			return err
		}
		byID := map[string]*nodeRow{}
		for _, r := range list {
			byID[r.ID] = r
		}
		ordered := make([]*nodeRow, 0, len(chain))
		for _, cid := range chain {
			if r := byID[cid]; r != nil {
				ordered = append(ordered, r)
			}
		}
		if ordered, err = o.fillPerms(ordered); err != nil {
			return err
		}
		out = nodes(ordered)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// readableScope returns a WITH clause and a condition (on n/s) selecting the
// nodes the actor can read without the admin override: every node of the
// spaces where the space gives at least PermView (own space, effective group
// memberships), and the subtrees of live grants. withGrants=false skips the
// grant subtrees. (Search applies the override only to one space the admin
// picks: searchOverride.)
func (o *op) readableScope(withGrants bool) (with, cond string, args []any, err error) {
	if o.a.system {
		return "", "1", nil, nil
	}
	cond = `((s.kind = 'user' AND s.owner_user_id = ?) OR
		(s.kind = 'group' AND s.group_id IN (SELECT group_id FROM effective_group_members WHERE user_id = ?))`
	args = []any{o.a.userID, o.a.userID}
	if withGrants {
		has, err := o.hasGrants()
		if err != nil {
			return "", "", nil, err
		}
		if has {
			gcond, gargs := o.grantCond("g")
			with = `WITH RECURSIVE granted(id) AS (
					SELECT g.node_id FROM node_grants g WHERE ` + gcond + `
					UNION
					SELECT c.id FROM nodes c JOIN granted ON c.parent_id = granted.id
				)`
			cond += ` OR n.id IN (SELECT id FROM granted)`
			args = append(gargs, args...)
		}
	}
	return with, cond + ")", args, nil
}

// ftsQuery quotes q as one FTS5 phrase.
func ftsQuery(q string) string { return `"` + strings.ReplaceAll(q, `"`, `""`) + `"` }

// likePattern escapes q for LIKE … ESCAPE '\' (substring match).
func likePattern(q string) string {
	r := strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`)
	return "%" + r.Replace(q) + "%"
}

// searchOverride reports whether an admin's search restricted to spaceID
// uses the admin override: the space gives the actor no permission of its
// own, and auth.admin_can_access_files lets them browse it. Searching it is
// then audited once, like opening its root folder (admin.file_access).
func (o *op) searchOverride(spaceID string) (bool, error) {
	var rootID, kind, owner, group string
	err := o.q.QueryRowContext(o.ctx, `SELECT r.id, s.kind, COALESCE(s.owner_user_id, ''), COALESCE(s.group_id, '')
		FROM spaces s JOIN nodes r ON r.space_id = s.id AND r.parent_id IS NULL WHERE s.id = ?`, spaceID).
		Scan(&rootID, &kind, &owner, &group)
	if db.IsNoRows(err) {
		return false, nil // an unknown space: no results
	}
	if err != nil || o.a.spacePerm(kind, owner, group) >= core.PermView {
		return false, err
	}
	if _, err := o.authorize(rootID, core.PermView, authOpt{}); err != nil {
		return false, err
	}
	return true, nil
}

// Search implements core.Files: names containing q (case-insensitive: the
// full case fold of name_key) in the spaces the actor can read and in
// subtrees shared with them — and, for an admin with
// auth.admin_can_access_files who picks another user's space (q.SpaceID),
// in that whole space, audited as admin.file_access; "all locations" never
// uses the override. Queries of three or more characters use the FTS5
// trigram index on name_key, shorter ones LIKE on name_key. Filters: space,
// kind. Results carry Path.
func (svc *Service) Search(ctx context.Context, p *core.Principal, q core.SearchQuery) (core.Page[core.Node], error) {
	term := strings.TrimSpace(norm.NFC.String(q.Q))
	switch n := utf8.RuneCountInString(term); {
	case n == 0:
		return core.Page[core.Node]{}, core.Invalid("q", "enter a search term")
	case n > 200:
		return core.Page[core.Node]{}, core.Invalid("q", "the search term is too long")
	}
	sort, err := normalizeSort(q.Sort, false)
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
		with, scope, args, err := o.readableScope(true)
		if err != nil {
			return err
		}
		if q.SpaceID != "" && o.a.adminOK {
			if over, err := o.searchOverride(q.SpaceID); err != nil {
				return err
			} else if over {
				with, scope, args = "", "1", nil // the space filter below keeps it to that space
			}
		}
		where := "n.parent_id IS NOT NULL AND n.trashed_at IS NULL AND " + scope
		// Both paths match the full case fold of name_key (the fold that makes
		// names equal in a folder), so "STRASSE" finds "Straße.txt". The
		// trigram index needs three characters of the folded term.
		key := names.Key(term)
		if utf8.RuneCountInString(key) >= 3 {
			where += " AND n.rid IN (SELECT rowid FROM nodes_fts WHERE nodes_fts MATCH ?)"
			args = append(args, ftsQuery(key))
		} else {
			where += ` AND n.name_key LIKE ? ESCAPE '\'`
			args = append(args, likePattern(key))
		}
		if q.SpaceID != "" {
			where += " AND n.space_id = ?"
			args = append(args, q.SpaceID)
		}
		rows, next, err := o.runList(listSpec{with: with, where: where + kcond, args: append(args, kargs...),
			sort: sort, desc: q.Desc, cursor: q.Cursor, limit: q.EffectiveLimit(), folderFirst: true})
		if err != nil {
			return err
		}
		if rows, err = o.fillPerms(rows); err != nil {
			return err
		}
		if err := o.decorate(rows); err != nil {
			return err
		}
		if err := o.fillPaths(rows); err != nil {
			return err
		}
		page = core.NewPage(nodes(rows), next)
		return nil
	})
	return page, err
}

// Recent implements core.Files: the most recently changed files the actor
// can read (limit 1..200, default 50).
func (svc *Service) Recent(ctx context.Context, p *core.Principal, limit int) ([]core.Node, error) {
	if limit <= 0 {
		limit = 50
	}
	limit = min(limit, 200)
	out := []core.Node{}
	err := svc.read(ctx, p, func(o *op) error {
		if err := o.checkScope(core.PermView); err != nil {
			return err
		}
		with, scope, args, err := o.readableScope(true)
		if err != nil {
			return err
		}
		rows, err := collectNodes(o.q.QueryContext(o.ctx, with+` SELECT `+nodeCols+nodeFrom+`
			WHERE n.kind = 'file' AND n.trashed_at IS NULL AND `+scope+`
			ORDER BY n.updated_at DESC, n.id DESC LIMIT ?`, append(args, limit)...))
		if err != nil {
			return err
		}
		if rows, err = o.fillPerms(rows); err != nil {
			return err
		}
		if err := o.decorate(rows); err != nil {
			return err
		}
		if err := o.fillPaths(rows); err != nil {
			return err
		}
		out = nodes(rows)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// Star implements core.Files: marks (on) or unmarks a node for the actor
// (PermView on the node — you may star anything you can see — but the
// files:write token scope, since it writes the stars table; idempotent).
func (svc *Service) Star(ctx context.Context, p *core.Principal, id string, on bool) error {
	return svc.write(ctx, p, func(o *op) error {
		if o.a.userID == "" {
			return core.Invalid("", "stars need a user")
		}
		n, err := o.authorize(id, core.PermView, authOpt{allowTrashed: !on, scope: core.ScopeFilesWrite})
		if err != nil {
			return err
		}
		if on {
			_, err = o.q.ExecContext(o.ctx, `INSERT INTO stars (user_id, node_id, created_at) VALUES (?, ?, ?)
				ON CONFLICT (user_id, node_id) DO NOTHING`, o.a.userID, n.ID, o.ms)
		} else {
			_, err = o.q.ExecContext(o.ctx, `DELETE FROM stars WHERE user_id = ? AND node_id = ?`, o.a.userID, n.ID)
		}
		return err
	})
}

// Starred implements core.Files: the actor's starred live nodes that they
// can still read.
func (svc *Service) Starred(ctx context.Context, p *core.Principal, q core.ListQuery) (core.Page[core.Node], error) {
	sort, err := normalizeSort(q.Sort, false)
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
		rows, next, err := o.runList(listSpec{
			where: "n.trashed_at IS NULL AND n.id IN (SELECT node_id FROM stars WHERE user_id = ?)" + kcond,
			args:  append([]any{o.a.userID}, kargs...),
			sort:  sort, desc: q.Desc, cursor: q.Cursor, limit: q.EffectiveLimit(), folderFirst: true,
		})
		if err != nil {
			return err
		}
		if rows, err = o.fillPerms(rows); err != nil {
			return err
		}
		if err := o.decorate(rows); err != nil {
			return err
		}
		if err := o.fillPaths(rows); err != nil {
			return err
		}
		page = core.NewPage(nodes(rows), next)
		return nil
	})
	return page, err
}

// SharedWithMe implements core.Files: live nodes with a live grant to the
// actor, one of their groups or their custom role, outside the spaces the
// actor already has through ownership or membership (direct or through the
// role).
func (svc *Service) SharedWithMe(ctx context.Context, p *core.Principal, q core.ListQuery) (core.Page[core.Node], error) {
	sort, err := normalizeSort(q.Sort, false)
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
		if o.a.userID == "" {
			page = core.NewPage[core.Node](nil, "")
			return nil
		}
		gcond, gargs := o.grantCond("g")
		where := `n.trashed_at IS NULL AND n.id IN (SELECT g.node_id FROM node_grants g WHERE ` + gcond + `)
			AND NOT (s.kind = 'user' AND s.owner_user_id = ?)
			AND NOT (s.kind = 'group' AND s.group_id IN (SELECT group_id FROM effective_group_members WHERE user_id = ?))`
		args := append(gargs, o.a.userID, o.a.userID)
		rows, next, err := o.runList(listSpec{where: where + kcond, args: append(args, kargs...),
			sort: sort, desc: q.Desc, cursor: q.Cursor, limit: q.EffectiveLimit(), folderFirst: true})
		if err != nil {
			return err
		}
		if rows, err = o.fillPerms(rows); err != nil {
			return err
		}
		if err := o.decorate(rows); err != nil {
			return err
		}
		page = core.NewPage(nodes(rows), next)
		return nil
	})
	return page, err
}

// Stats implements core.Files: recursive counts and bytes of the live
// subtree below id (PermView).
func (svc *Service) Stats(ctx context.Context, p *core.Principal, id string) (*core.FolderStats, error) {
	var st core.FolderStats
	err := svc.read(ctx, p, func(o *op) error {
		n, err := o.authorize(id, core.PermView, authOpt{allowTrashed: true})
		if err != nil {
			return err
		}
		st.NodeID = n.ID
		if !n.IsDir() {
			st.Files, st.Bytes = 1, n.Size
			return nil
		}
		where := "c.trashed_at IS NULL"
		if n.TrashedAt != nil {
			where = "c.trash_root = 0"
		}
		return o.q.QueryRowContext(o.ctx, `WITH RECURSIVE sub(id, kind, size) AS (
				SELECT c.id, c.kind, c.size FROM nodes c WHERE c.parent_id = ?1 AND `+where+`
				UNION ALL
				SELECT c.id, c.kind, c.size FROM nodes c JOIN sub ON c.parent_id = sub.id WHERE `+where+`
			)
			SELECT COALESCE(SUM(kind = 'file'), 0), COALESCE(SUM(kind = 'folder'), 0),
				COALESCE(SUM(CASE WHEN kind = 'file' THEN size ELSE 0 END), 0) FROM sub`, n.ID).
			Scan(&st.Files, &st.Folders, &st.Bytes)
	})
	if err != nil {
		return nil, err
	}
	return &st, nil
}

// Usage implements core.Files: the storage usage of a user's personal space
// (all versions, trash included), the trash share, open upload reservations
// and the effective quota (0 = unlimited). Guests have no personal space.
func (svc *Service) Usage(ctx context.Context, userID string) (*core.Usage, error) {
	if !ids.Valid(ids.PrefixUser, userID) {
		return nil, core.NotFoundf("user not found")
	}
	u := &core.Usage{UserID: userID}
	err := svc.env.DB.Read(ctx, func(tx *sql.Tx) error {
		var uq sql.NullInt64
		err := tx.QueryRowContext(ctx, `SELECT quota_bytes FROM users WHERE id = ?`, userID).Scan(&uq)
		if db.IsNoRows(err) {
			return core.NotFoundf("user not found")
		}
		if err != nil {
			return err
		}
		u.QuotaBytes = svc.userQuota(uq)
		var sq sql.NullInt64
		err = tx.QueryRowContext(ctx, `SELECT id, used_bytes, quota_bytes FROM spaces WHERE kind = 'user' AND owner_user_id = ?`,
			userID).Scan(&u.SpaceID, &u.UsedBytes, &sq)
		switch {
		case db.IsNoRows(err):
		case err != nil:
			return err
		default:
			if sq.Valid && sq.Int64 > 0 && (u.QuotaBytes == 0 || sq.Int64 < u.QuotaBytes) {
				u.QuotaBytes = sq.Int64
			}
			if err := tx.QueryRowContext(ctx, `SELECT COALESCE(SUM(v.size), 0) FROM file_versions v
				JOIN nodes n ON n.id = v.node_id WHERE n.space_id = ? AND n.trashed_at IS NOT NULL`, u.SpaceID).
				Scan(&u.TrashBytes); err != nil {
				return err
			}
		}
		// MAX(…, 0) per row: a reservation that somehow went negative must
		// never make the reported usage smaller than it is.
		return tx.QueryRowContext(ctx, `SELECT COALESCE(SUM(MAX(reserved_bytes, 0)), 0) FROM upload_batches
			WHERE user_id = ? AND state IN ('open', 'finalizing')`, userID).Scan(&u.ReservedBytes)
	})
	if err != nil {
		return nil, err
	}
	return u, nil
}
