package files

import (
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"strings"

	"fileparcel/internal/core"
	"fileparcel/internal/db"
	"fileparcel/internal/ids"
)

// nodeRow is a node plus the space columns needed for authorization.
type nodeRow struct {
	core.Node
	spaceKind  string
	spaceOwner string
	spaceGroup string
}

// nodeCols selects a node (alias n) joined with its space (alias s); the
// column order matches scanNode. The blob and the zip protection come from
// the current version (file_versions.zip_encryption, DESIGN §8.1).
const nodeCols = `n.rid, n.id, n.space_id, COALESCE(n.parent_id, ''), n.kind, n.name, n.name_key, n.size,
	COALESCE(n.mime, ''), COALESCE(n.version_id, ''), COALESCE(n.content_hash, ''), n.client_mtime,
	n.created_at, n.updated_at, COALESCE(n.created_by, ''), COALESCE(n.updated_by, ''), n.trashed_at,
	COALESCE(n.trashed_by, ''), n.trash_root, COALESCE(n.thumb_blob_id, ''),
	COALESCE((SELECT v.blob_id FROM file_versions v WHERE v.id = n.version_id), ''),
	COALESCE((SELECT v.zip_encryption FROM file_versions v WHERE v.id = n.version_id), ''),
	s.kind, COALESCE(s.owner_user_id, ''), COALESCE(s.group_id, '')`

// nodeFrom is the FROM clause matching nodeCols.
const nodeFrom = ` FROM nodes n JOIN spaces s ON s.id = n.space_id`

// selectNodes is "SELECT <nodeCols> FROM nodes n JOIN spaces s".
const selectNodes = `SELECT ` + nodeCols + nodeFrom

type scanner interface{ Scan(dest ...any) error }

func scanNode(sc scanner) (*nodeRow, error) {
	var r nodeRow
	var mtime, trashed sql.NullInt64
	var created, updated int64
	var trashRoot int64
	err := sc.Scan(&r.RID, &r.ID, &r.SpaceID, &r.ParentID, &r.Kind, &r.Name, &r.NameKey, &r.Size,
		&r.MIME, &r.VersionID, &r.ContentHash, &mtime, &created, &updated, &r.CreatedBy, &r.UpdatedBy,
		&trashed, &r.TrashedBy, &trashRoot, &r.ThumbBlobID, &r.BlobID, &r.ZipEncryption,
		&r.spaceKind, &r.spaceOwner, &r.spaceGroup)
	if err != nil {
		return nil, err
	}
	r.ClientMtime = db.FromNullMs(mtime)
	r.CreatedAt = db.FromMs(created)
	r.UpdatedAt = db.FromMs(updated)
	r.TrashedAt = db.FromNullMs(trashed)
	r.TrashRoot = trashRoot != 0
	r.HasThumb = r.ThumbBlobID != ""
	return &r, nil
}

// collectNodes scans all rows.
func collectNodes(rows *sql.Rows, err error) ([]*nodeRow, error) {
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*nodeRow
	for rows.Next() {
		r, err := scanNode(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// loadNode loads one node (nil, nil when it does not exist).
func (o *op) loadNode(id string) (*nodeRow, error) {
	if !ids.Valid(ids.PrefixNode, id) {
		return nil, nil
	}
	r, err := scanNode(o.q.QueryRowContext(o.ctx, selectNodes+` WHERE n.id = ?`, id))
	if db.IsNoRows(err) {
		return nil, nil
	}
	return r, err
}

// mustNode loads a node or fails with 404.
func (o *op) mustNode(id string) (*nodeRow, error) {
	r, err := o.loadNode(id)
	if err != nil {
		return nil, err
	}
	if r == nil {
		return nil, notFound()
	}
	return r, nil
}

// rootOf returns the root node id of a space.
func (o *op) rootOf(spaceID string) (string, error) {
	var id string
	err := o.q.QueryRowContext(o.ctx, `SELECT id FROM nodes WHERE space_id = ? AND parent_id IS NULL`, spaceID).Scan(&id)
	if db.IsNoRows(err) {
		return "", core.NotFoundf("space root not found")
	}
	return id, err
}

// childRef is a live child found by name.
type childRef struct {
	id, kind, name string
}

// child returns the live child of parentID with name key key (nil if none).
func (o *op) child(parentID, key string) (*childRef, error) {
	var c childRef
	err := o.q.QueryRowContext(o.ctx, `SELECT id, kind, name FROM nodes
		WHERE parent_id = ? AND name_key = ? AND trashed_at IS NULL`, parentID, key).Scan(&c.id, &c.kind, &c.name)
	if db.IsNoRows(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &c, nil
}

// isWithin reports whether id is ancestorID or one of its descendants.
func (o *op) isWithin(ancestorID, id string) (bool, error) {
	if ancestorID == id {
		return true, nil
	}
	var one int
	err := o.q.QueryRowContext(o.ctx, `WITH RECURSIVE anc(id, parent_id) AS (
			SELECT id, parent_id FROM nodes WHERE id = ?
			UNION ALL
			SELECT n.id, n.parent_id FROM nodes n JOIN anc ON n.id = anc.parent_id
		)
		SELECT 1 FROM anc WHERE id = ? LIMIT 1`, id, ancestorID).Scan(&one)
	if db.IsNoRows(err) {
		return false, nil
	}
	return err == nil, err
}

// subtreeSQL selects the ids of the node ?1 and all its descendants (live
// and trashed), with their depth below ?1.
const subtreeSQL = `WITH RECURSIVE sub(id, depth) AS (
		SELECT ?1, 0
		UNION ALL
		SELECT c.id, sub.depth + 1 FROM nodes c JOIN sub ON c.parent_id = sub.id
	)`

// liveSubtreeSQL selects ?1 and its live descendants.
const liveSubtreeSQL = `WITH RECURSIVE sub(id) AS (
		SELECT ?1
		UNION ALL
		SELECT c.id FROM nodes c JOIN sub ON c.parent_id = sub.id WHERE c.trashed_at IS NULL
	)`

// placeholders returns "?,?,…" for n arguments.
func placeholders(n int) string {
	if n <= 0 {
		return ""
	}
	return strings.Repeat("?,", n-1) + "?"
}

func anyArgs(ss []string) []any {
	out := make([]any, len(ss))
	for i, s := range ss {
		out[i] = s
	}
	return out
}

// nesting describes how the nodes of one batch request relate: the depth
// of each existing node below its space root, and which ones lie inside the
// subtree of another node of the batch.
type nesting struct {
	depth  map[string]int
	nested map[string]bool
}

// nestingOf resolves the ancestor chains of list (one recursive query).
// Unknown ids are simply absent from the result.
func (o *op) nestingOf(list []string) (*nesting, error) {
	ns := &nesting{depth: make(map[string]int, len(list)), nested: map[string]bool{}}
	if len(list) < 2 {
		return ns, nil
	}
	in := make(map[string]bool, len(list))
	for _, id := range list {
		in[id] = true
	}
	rows, err := o.q.QueryContext(o.ctx, `WITH RECURSIVE anc(start, id, parent_id, d) AS (
			SELECT id, id, parent_id, 0 FROM nodes WHERE id IN (`+placeholders(len(list))+`)
			UNION ALL
			SELECT anc.start, n.id, n.parent_id, anc.d + 1 FROM nodes n JOIN anc ON n.id = anc.parent_id
		)
		SELECT start, id, d FROM anc`, anyArgs(list)...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var start, id string
		var d int
		if err := rows.Scan(&start, &id, &d); err != nil {
			return nil, err
		}
		ns.depth[start] = max(ns.depth[start], d)
		if d > 0 && in[id] {
			ns.nested[start] = true
		}
	}
	return ns, rows.Err()
}

// outermost drops the ids of list that lie inside the subtree of another
// id of list (they are handled together with it), keeping the order.
func (o *op) outermost(list []string) ([]string, error) {
	ns, err := o.nestingOf(list)
	if err != nil || len(ns.nested) == 0 {
		return list, err
	}
	out := make([]string, 0, len(list))
	for _, id := range list {
		if !ns.nested[id] {
			out = append(out, id)
		}
	}
	return out, nil
}

// dedupe returns ids without duplicates or empty strings (order kept).
func dedupe(in []string) []string {
	seen := make(map[string]bool, len(in))
	out := make([]string, 0, len(in))
	for _, s := range in {
		if s == "" || seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	return out
}

// checkIDs validates a batch of node ids.
func checkIDs(field string, in []string) ([]string, error) {
	list := dedupe(in)
	switch {
	case len(list) == 0:
		return nil, core.Invalid(field, "select at least one item")
	case len(list) > maxBatch:
		return nil, core.Invalid(field, "too many items in one request")
	}
	return list, nil
}

// nodes converts rows to plain nodes.
func nodes(rows []*nodeRow) []core.Node {
	out := make([]core.Node, len(rows))
	for i, r := range rows {
		out[i] = r.Node
	}
	return out
}

// ---------- keyset pagination ----------

// listSpec describes one keyset-paginated node listing.
type listSpec struct {
	with   string // optional "WITH …" prefix
	where  string // conditions on n / s (joined with AND)
	args   []any  // arguments of with + where, in order
	sort   string // name | size | updated | kind | trashed
	desc   bool
	cursor string
	limit  int
	// folderFirst groups folders before files (not for "trashed").
	folderFirst bool
}

// cursorData is the opaque cursor (base64url JSON, like httpx.EncodeCursor).
type cursorData struct {
	S  string `json:"s"`
	D  bool   `json:"d,omitempty"`
	F  int    `json:"f"`
	KS string `json:"ks,omitempty"`
	KN int64  `json:"kn,omitempty"`
	I  string `json:"i"`
}

func encodeCursor(c cursorData) string {
	b, _ := json.Marshal(c)
	return base64.RawURLEncoding.EncodeToString(b)
}

func decodeCursor(s string) (cursorData, error) {
	var c cursorData
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil || len(b) == 0 || json.Unmarshal(b, &c) != nil || c.I == "" {
		return c, core.Invalid("cursor", "invalid cursor")
	}
	return c, nil
}

// sortKey returns the SQL key expression and whether it is a string.
func sortKey(sort string) (expr string, isString bool, err error) {
	switch sort {
	case "name", "kind":
		return "n.name_key", true, nil
	case "size":
		return "n.size", false, nil
	case "updated":
		return "n.updated_at", false, nil
	case "trashed":
		return "COALESCE(n.trashed_at, 0)", false, nil
	}
	return "", false, core.Invalid("sort", "unknown sort order (use name, size, updated or kind)")
}

// normalizeSort applies the default order and validates it.
func normalizeSort(sort string, allowTrashed bool) (string, error) {
	if sort == "" {
		return "name", nil
	}
	if sort == "trashed" && !allowTrashed {
		return "", core.Invalid("sort", "unknown sort order")
	}
	if _, _, err := sortKey(sort); err != nil {
		return "", err
	}
	return sort, nil
}

// runList executes a listing and returns the rows of the page and the next cursor.
func (o *op) runList(ls listSpec) ([]*nodeRow, string, error) {
	keyExpr, isStr, err := sortKey(ls.sort)
	if err != nil {
		return nil, "", err
	}
	const isFile = "(n.kind = 'file')"
	folderFirst := ls.folderFirst && ls.sort != "trashed"
	fAsc, kAsc := true, !ls.desc
	if ls.sort == "kind" {
		folderFirst = true
		fAsc, kAsc = !ls.desc, true
	}
	dir := func(asc bool) string {
		if asc {
			return "ASC"
		}
		return "DESC"
	}
	cmp := func(asc bool) string {
		if asc {
			return ">"
		}
		return "<"
	}

	q := ls.with + " SELECT " + nodeCols + nodeFrom + " WHERE " + ls.where
	args := append([]any(nil), ls.args...)
	if ls.cursor != "" {
		c, err := decodeCursor(ls.cursor)
		if err != nil {
			return nil, "", err
		}
		if c.S != ls.sort || c.D != ls.desc {
			return nil, "", core.Invalid("cursor", "the cursor belongs to another sort order")
		}
		var kv any = c.KN
		if isStr {
			kv = c.KS
		}
		keyPred := "(" + keyExpr + " " + cmp(kAsc) + " ? OR (" + keyExpr + " = ? AND n.id " + cmp(kAsc) + " ?))"
		if folderFirst {
			q += " AND (" + isFile + " " + cmp(fAsc) + " ? OR (" + isFile + " = ? AND " + keyPred + "))"
			args = append(args, c.F, c.F, kv, kv, c.I)
		} else {
			q += " AND " + keyPred
			args = append(args, kv, kv, c.I)
		}
	}
	order := keyExpr + " " + dir(kAsc) + ", n.id " + dir(kAsc)
	if folderFirst {
		order = isFile + " " + dir(fAsc) + ", " + order
	}
	limit := ls.limit
	if limit <= 0 || limit > core.MaxPageLimit {
		limit = core.DefaultPageLimit
	}
	q += " ORDER BY " + order + " LIMIT ?"
	args = append(args, limit+1)

	rows, err := collectNodes(o.q.QueryContext(o.ctx, q, args...))
	if err != nil {
		return nil, "", err
	}
	next := ""
	if len(rows) > limit {
		rows = rows[:limit]
		last := rows[len(rows)-1]
		c := cursorData{S: ls.sort, D: ls.desc, I: last.ID}
		if last.Kind == core.KindFile {
			c.F = 1
		}
		switch ls.sort {
		case "name", "kind":
			c.KS = last.NameKey
		case "size":
			c.KN = last.Size
		case "updated":
			c.KN = db.Ms(last.UpdatedAt)
		case "trashed":
			if last.TrashedAt != nil {
				c.KN = db.Ms(*last.TrashedAt)
			}
		}
		next = encodeCursor(c)
	}
	return rows, next, nil
}

// kindFilter validates ListQuery.Kind and returns the SQL condition.
func kindFilter(kind string) (string, []any, error) {
	switch kind {
	case "":
		return "", nil, nil
	case core.KindFile, core.KindFolder:
		return " AND n.kind = ?", []any{kind}, nil
	}
	return "", nil, core.Invalid("kind", "kind must be file or folder")
}

// ---------- decoration ----------

// decorate fills Starred (for the actor's user), ChildCount (folders) and
// HasThumb.
func (o *op) decorate(rows []*nodeRow) error {
	if len(rows) == 0 {
		return nil
	}
	idx := make(map[string]*nodeRow, len(rows))
	var all, liveFolders, trashFolders []string
	for _, r := range rows {
		idx[r.ID] = r
		r.HasThumb = r.ThumbBlobID != ""
		all = append(all, r.ID)
		if r.Kind == core.KindFolder {
			if r.TrashedAt == nil {
				liveFolders = append(liveFolders, r.ID)
			} else {
				trashFolders = append(trashFolders, r.ID)
			}
		}
	}
	if uid := o.a.userID; uid != "" {
		rs, err := o.q.QueryContext(o.ctx, `SELECT node_id FROM stars WHERE user_id = ? AND node_id IN (`+
			placeholders(len(all))+`)`, append([]any{uid}, anyArgs(all)...)...)
		if err != nil {
			return err
		}
		for rs.Next() {
			var id string
			if err := rs.Scan(&id); err != nil {
				rs.Close()
				return err
			}
			if r := idx[id]; r != nil {
				r.Starred = true
			}
		}
		rs.Close()
		if err := rs.Err(); err != nil {
			return err
		}
	}
	count := func(list []string, cond string) error {
		if len(list) == 0 {
			return nil
		}
		for _, id := range list {
			zero := int64(0)
			idx[id].ChildCount = &zero
		}
		rs, err := o.q.QueryContext(o.ctx, `SELECT parent_id, COUNT(*) FROM nodes WHERE parent_id IN (`+
			placeholders(len(list))+`) AND `+cond+` GROUP BY parent_id`, anyArgs(list)...)
		if err != nil {
			return err
		}
		defer rs.Close()
		for rs.Next() {
			var id string
			var n int64
			if err := rs.Scan(&id, &n); err != nil {
				return err
			}
			if r := idx[id]; r != nil {
				r.ChildCount = &n
			}
		}
		return rs.Err()
	}
	if err := count(liveFolders, "trashed_at IS NULL"); err != nil {
		return err
	}
	return count(trashFolders, "trash_root = 0")
}

// fillPaths sets Path ("/Folder/Sub/name", relative to the space root) on
// every row. For nodes the actor sees only through a grant, the path starts
// at the highest granted ancestor, so names above it are not revealed.
func (o *op) fillPaths(rows []*nodeRow) error {
	if len(rows) == 0 {
		return nil
	}
	idx := map[string]*nodeRow{}
	var list []string
	for _, r := range rows {
		if _, dup := idx[r.ID]; !dup {
			list = append(list, r.ID)
		}
		idx[r.ID] = r
	}
	type seg struct {
		name    string
		root    bool
		granted bool
	}
	chains := map[string][]seg{} // start → segments from the node up to the root
	gcond, gargs := o.grantCond("g")
	q := `WITH RECURSIVE anc(start, id, parent_id, name, depth) AS (
			SELECT id, id, parent_id, name, 0 FROM nodes WHERE id IN (` + placeholders(len(list)) + `)
			UNION ALL
			SELECT anc.start, n.id, n.parent_id, n.name, anc.depth + 1 FROM nodes n JOIN anc ON n.id = anc.parent_id
		)
		SELECT anc.start, anc.name, anc.parent_id IS NULL,
			EXISTS(SELECT 1 FROM node_grants g WHERE g.node_id = anc.id AND ` + gcond + `)
		FROM anc ORDER BY anc.start, anc.depth`
	args := append(anyArgs(list), gargs...)
	rs, err := o.q.QueryContext(o.ctx, q, args...)
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
	for _, r := range rows {
		chain := chains[r.ID]
		spaceVisible := o.a.spacePerm(r.spaceKind, r.spaceOwner, r.spaceGroup) >= core.PermView || o.a.adminOK
		top := len(chain) - 1 // index of the highest visible segment
		if !spaceVisible {
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
			if chain[i].root {
				continue
			}
			parts = append(parts, chain[i].name)
		}
		r.Path = "/" + strings.Join(parts, "/")
	}
	return nil
}
