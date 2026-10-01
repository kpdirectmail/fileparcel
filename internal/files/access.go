package files

import (
	"cmp"
	"context"
	"maps"
	"slices"
	"strings"

	"fileparcel/internal/core"
	"fileparcel/internal/db"
	"fileparcel/internal/ids"
	"fileparcel/internal/names"
)

// Bounds of SubjectGrants (GET /admin/grants, no cursor).
const (
	// maxSubjectGrants is the number of rows returned; the rest are counted
	// in Hidden.
	maxSubjectGrants = 1000
	// maxSubjectGrantScan bounds the grants read and checked per call; any
	// beyond it are counted in Hidden as well.
	maxSubjectGrantScan = 5000
	// nodeChunk bounds the nodes of one batched permission or path query.
	nodeChunk = 500
)

// subjectSpaceName is the space display name of SubjectGrants (on the
// spaces alias s): the group name for team folders, the owner's display
// name (else username) for personal spaces — every personal space is
// called "My files", which says nothing to someone else.
const subjectSpaceName = `CASE s.kind WHEN 'user' THEN COALESCE((SELECT COALESCE(NULLIF(u.display_name, ''), u.username)
	FROM users u WHERE u.id = s.owner_user_id), s.name) ELSE s.name END`

// SubjectGrants implements core.Files (GET /admin/grants): the live grants
// to one subject on items that are not in the trash — with q.Expand for a
// user, also the grants to their effective groups and to their custom role,
// i.e. everything that gives them access beyond their own space and team
// folders. The route authorizes (users.view); the rows are then filtered by
// what the caller may see, so that no names leak (DESIGN §6a):
//
//   - the system principal sees every row;
//   - a row whose item the caller can open (PermView or more, through their
//     own space, groups or grants);
//   - a row in a team folder when the caller holds groups.manage (they can
//     join any group anyway; owners and admins hold it);
//   - a row the admin override (auth.admin_can_access_files) opens: audited
//     as admin.file_access on the root of that space, once per space and
//     call, like a search of that space.
//
// Other rows are only counted in Hidden, as are the rows beyond the first
// maxSubjectGrants. CallerPerm is the caller's permission on the item
// (PermManage or more: they may change or remove the grant). NodePath
// starts at the space root, or — for items the caller sees only through a
// grant of their own — at the highest item granted to them, exactly as
// search results do. Rows are ordered by space name, path and subject.
// API tokens need files:read, like every other listing of names.
func (svc *Service) SubjectGrants(ctx context.Context, p *core.Principal, q core.SubjectGrantQuery) (*core.SubjectGrants, error) {
	subj, ok := grantSubjects[q.SubjectType]
	if !ok {
		return nil, core.Invalid("subject_type", "subject_type must be user, group or role")
	}
	if !ids.Valid(subj.prefix, q.SubjectID) {
		return nil, core.Invalid("subject_id", "subject_id is not a valid "+q.SubjectType+" id")
	}
	out := &core.SubjectGrants{Items: []core.Grant{}}
	err := svc.read(ctx, p, func(o *op) error {
		if err := o.checkScope(core.PermView); err != nil {
			return err
		}
		var exists bool
		if err := o.q.QueryRowContext(o.ctx, `SELECT EXISTS(SELECT 1 FROM `+subj.table+` WHERE id = ?)`, q.SubjectID).
			Scan(&exists); err != nil {
			return err
		}
		if !exists {
			return core.NotFoundf("%s not found", q.SubjectType)
		}
		cond := `g.subject_type = ? AND g.subject_id = ?`
		args := []any{q.SubjectType, q.SubjectID}
		if q.Expand && q.SubjectType == core.SubjectUser {
			cond = `((g.subject_type = 'user' AND g.subject_id = ?) OR
				(g.subject_type = 'group' AND g.subject_id IN (SELECT group_id FROM effective_group_members WHERE user_id = ?)) OR
				(g.subject_type = 'role' AND g.subject_id = (SELECT role_id FROM users WHERE id = ?)))`
			args = []any{q.SubjectID, q.SubjectID, q.SubjectID}
		}
		where := ` FROM node_grants g JOIN nodes n ON n.id = g.node_id JOIN spaces s ON s.id = n.space_id
			WHERE (g.expires_at IS NULL OR g.expires_at > ?) AND n.trashed_at IS NULL AND ` + cond
		args = append([]any{o.ms}, args...)
		var total int
		if err := o.q.QueryRowContext(o.ctx, `SELECT count(*)`+where, args...).Scan(&total); err != nil {
			return err
		}
		grants, rows, err := o.scanSubjectGrants(`SELECT `+grantCols+`, `+nodeCols+`, `+subjectSpaceName+where+`
			ORDER BY s.name COLLATE NOCASE, s.id, n.name_key, n.id, g.subject_type, g.subject_id LIMIT ?`,
			append(args, maxSubjectGrantScan)...)
		if err != nil {
			return err
		}
		visible, err := o.subjectGrantsVisible(rows)
		if err != nil {
			return err
		}
		for _, g := range grants {
			r := visible[g.NodeID]
			if r == nil {
				continue
			}
			g.NodeName, g.NodePath, g.NodeKind, g.SpaceKind = r.Name, r.Path, r.Kind, r.spaceKind
			g.CallerPerm = r.Perm
			out.Items = append(out.Items, g)
		}
		slices.SortStableFunc(out.Items, func(a, b core.Grant) int {
			return cmp.Or(strings.Compare(names.Key(a.SpaceName), names.Key(b.SpaceName)),
				strings.Compare(a.SpaceName, b.SpaceName),
				strings.Compare(names.Key(a.NodePath), names.Key(b.NodePath)),
				strings.Compare(a.NodePath, b.NodePath),
				strings.Compare(a.SubjectType, b.SubjectType),
				strings.Compare(names.Key(a.SubjectName), names.Key(b.SubjectName)),
				strings.Compare(a.SubjectID, b.SubjectID))
		})
		if len(out.Items) > maxSubjectGrants {
			out.Items = out.Items[:maxSubjectGrants]
		}
		out.Hidden = total - len(out.Items)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// scanSubjectGrants runs query (grantCols, nodeCols, subjectSpaceName) and
// returns the grants (SpaceName filled) and their distinct nodes.
func (o *op) scanSubjectGrants(query string, args ...any) ([]core.Grant, []*nodeRow, error) {
	rs, err := o.q.QueryContext(o.ctx, query, args...)
	if err != nil {
		return nil, nil, err
	}
	defer rs.Close()
	var grants []core.Grant
	var nodes []*nodeRow
	seen := map[string]bool{}
	for rs.Next() {
		j := &grantNodeScanner{sc: rs}
		g, err := scanGrant(j)
		if err != nil {
			return nil, nil, err
		}
		g.SpaceName = j.spaceName
		grants = append(grants, *g)
		if !seen[j.node.ID] {
			seen[j.node.ID] = true
			nodes = append(nodes, j.node)
		}
	}
	return grants, nodes, rs.Err()
}

// grantNodeScanner scans one row of grantCols, nodeCols and a trailing
// space name with the existing scanners: scanGrant hands it the grant's
// destinations, which it passes to the database in front of those of
// scanNode.
type grantNodeScanner struct {
	sc        scanner
	node      *nodeRow
	spaceName string
}

func (j *grantNodeScanner) Scan(grantDest ...any) error {
	var err error
	j.node, err = scanNode(scanFunc(func(nodeDest ...any) error {
		return j.sc.Scan(slices.Concat(grantDest, nodeDest, []any{&j.spaceName})...)
	}))
	return err
}

// scanFunc adapts a function to the scanner interface.
type scanFunc func(dest ...any) error

func (f scanFunc) Scan(dest ...any) error { return f(dest...) }

// subjectGrantsVisible applies the visibility rule of SubjectGrants to the
// granted nodes and returns the visible ones by id, with Perm (the caller's
// effective permission) and Path set. Nodes seen only through the admin
// override are audited per space.
func (o *op) subjectGrantsVisible(rows []*nodeRow) (map[string]*nodeRow, error) {
	teams := o.a.p.Can(core.CapGroupsManage)
	whole := func(r *nodeRow) bool { // the caller may see the whole space
		return o.a.system || o.a.adminOK || o.a.spacePerm(r.spaceKind, r.spaceOwner, r.spaceGroup) >= core.PermView ||
			(teams && r.spaceKind == core.SpaceGroup)
	}
	visible := map[string]*nodeRow{}
	var shown []*nodeRow
	overrideSpaces := map[string]bool{}
	for chunk := range slices.Chunk(rows, nodeChunk) {
		// fillPerms keeps only what the caller can open (override included)
		// and caches the grant level of every node it had to look up.
		opened, err := o.fillPerms(chunk)
		if err != nil {
			return nil, err
		}
		open := map[string]bool{}
		for _, r := range opened {
			open[r.ID] = true
		}
		for _, r := range chunk {
			natural := o.a.spacePerm(r.spaceKind, r.spaceOwner, r.spaceGroup)
			if natural < core.PermManage {
				natural = max(natural, o.a.grants[r.ID])
			}
			switch {
			case o.a.system, natural >= core.PermView:
			case teams && r.spaceKind == core.SpaceGroup:
			case open[r.ID]: // only the admin override opens it
				overrideSpaces[r.SpaceID] = true
			default:
				continue
			}
			if !open[r.ID] {
				r.Perm = core.PermNone // visible by the groups.manage rule alone
			}
			visible[r.ID] = r
			shown = append(shown, r)
		}
	}
	for _, spaceID := range slices.Sorted(maps.Keys(overrideSpaces)) {
		root, err := o.spaceRoot(spaceID)
		if err != nil {
			return nil, err
		}
		if root != nil {
			o.adminAccess(root, core.PermView)
		}
	}
	return visible, o.nodePaths(shown, whole)
}

// spaceRoot loads the root folder of a space (nil when it has none).
func (o *op) spaceRoot(spaceID string) (*nodeRow, error) {
	var rootID string
	err := o.q.QueryRowContext(o.ctx, `SELECT id FROM nodes WHERE space_id = ? AND parent_id IS NULL`, spaceID).Scan(&rootID)
	if db.IsNoRows(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return o.loadNode(rootID)
}

// nodePaths sets Path ("/Folder/Sub/name", relative to the space root) on
// every row: from the space root where whole(r) says the caller may see the
// whole space, otherwise from the highest ancestor granted to the caller
// (the rule of fillPaths, which knows only the caller's own spaces).
func (o *op) nodePaths(rows []*nodeRow, whole func(*nodeRow) bool) error {
	gcond, gargs := o.grantCond("g")
	for chunk := range slices.Chunk(rows, nodeChunk) {
		list := make([]string, len(chunk))
		for i, r := range chunk {
			list[i] = r.ID
		}
		type seg struct {
			name          string
			root, granted bool
		}
		chains := map[string][]seg{} // start → segments from the node up to the root
		rs, err := o.q.QueryContext(o.ctx, `WITH RECURSIVE anc(start, id, parent_id, name, depth) AS (
				SELECT id, id, parent_id, name, 0 FROM nodes WHERE id IN (`+placeholders(len(list))+`)
				UNION ALL
				SELECT anc.start, n.id, n.parent_id, n.name, anc.depth + 1 FROM nodes n JOIN anc ON n.id = anc.parent_id
			)
			SELECT anc.start, anc.name, anc.parent_id IS NULL,
				EXISTS(SELECT 1 FROM node_grants g WHERE g.node_id = anc.id AND `+gcond+`)
			FROM anc ORDER BY anc.start, anc.depth`, append(anyArgs(list), gargs...)...)
		if err != nil {
			return err
		}
		for rs.Next() {
			var start string
			var s seg
			if err := rs.Scan(&start, &s.name, &s.root, &s.granted); err != nil {
				rs.Close()
				return err
			}
			chains[start] = append(chains[start], s)
		}
		rs.Close()
		if err := rs.Err(); err != nil {
			return err
		}
		for _, r := range chunk {
			chain := chains[r.ID]
			top := len(chain) - 1 // index of the highest visible segment
			if !whole(r) {
				top = 0
				for i := len(chain) - 1; i >= 0; i-- {
					if chain[i].granted {
						top = i
						break
					}
				}
			}
			var parts []string
			for i := top; i >= 0; i-- {
				if !chain[i].root {
					parts = append(parts, chain[i].name)
				}
			}
			r.Path = "/" + strings.Join(parts, "/")
		}
	}
	return nil
}
