package files

import (
	"context"
	"fmt"

	"fileparcel/internal/core"
)

// settingAdminAccess is the auth setting (unit B) that lets owners/admins
// access every user's files.
const settingAdminAccess = "auth.admin_can_access_files"

// actor is the resolved principal of one call: user, group roles and
// whether the admin override applies. Grant lookups are cached per call
// ("cached per request", DESIGN §6).
type actor struct {
	p       *core.Principal
	userID  string
	system  bool              // system principal without a user: PermOwner everywhere
	adminOK bool              // owner/admin holding the admin scope, with auth.admin_can_access_files
	groups  map[string]string // effective group id → GroupRoleMember | GroupRoleManager (direct or through the role)
	grants  map[string]core.Perm
	anyGr   *bool // whether the user has any live grant at all
	audited map[string]core.Perm
}

// viaJob is the audit channel of changes made by background jobs (trash
// retention, version pruning), like the uploads jobs.
const viaJob core.AuthVia = "job"

// systemActor is the actor of system-level operations (Sys helpers, jobs).
func systemActor() *actor {
	return &actor{p: core.SystemPrincipal(viaJob), system: true, groups: map[string]string{}}
}

// newActor resolves p (nil → 401).
func (svc *Service) newActor(ctx context.Context, q querier, p *core.Principal) (*actor, error) {
	if p == nil {
		return nil, core.ErrUnauthorized
	}
	a := &actor{p: p, userID: p.UserID, groups: map[string]string{}}
	if p.IsSystem() && p.UserID == "" {
		a.system = true
		return a, nil
	}
	if p.UserID == "" {
		return nil, core.ErrUnauthorized
	}
	// The override needs the role *and*, for API tokens, the admin scope:
	// mw.RequireAdmin pairs the same two on /admin/*, so a token that may not
	// use the admin surfaces may not read every user's files either
	// (HasScope is true for sessions, the admin socket and the offline CLI).
	// It is compared with the built-in base role: custom roles are based on
	// member or guest and never get it (DESIGN §6a).
	if (p.Role == core.RoleOwner || p.Role == core.RoleAdmin) && p.HasScope(core.ScopeAdmin) {
		a.adminOK = svc.settingBool(settingAdminAccess, false)
	}
	// Memberships are effective ones: direct rows and those the account's
	// custom role gives (role_groups), read from the database on every call
	// so that a role change applies to the next request. A user may be in a
	// group both ways; the manager membership wins.
	rows, err := q.QueryContext(ctx, `SELECT group_id, role FROM effective_group_members WHERE user_id = ?`, p.UserID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var g, r string
		if err := rows.Scan(&g, &r); err != nil {
			return nil, err
		}
		if a.groups[g] != core.GroupRoleManager {
			a.groups[g] = r
		}
	}
	return a, rows.Err()
}

// spacePerm is the permission the space itself gives (no grants, no override).
func (a *actor) spacePerm(kind, owner, group string) core.Perm {
	switch {
	case a.system:
		return core.PermOwner
	case kind == core.SpaceUser && owner != "" && owner == a.userID:
		return core.PermOwner
	case kind == core.SpaceGroup:
		switch a.groups[group] {
		case core.GroupRoleManager:
			return core.PermManage
		case core.GroupRoleMember:
			return core.PermEdit
		}
	}
	return core.PermNone
}

// auditTransfer audits a purge or cross-space move that only the admin
// override allows. Both callers authorize the node for PermEdit and learn
// the real requirement (transferPerm) from the space kind afterwards, so
// authorize() — which audits when the *natural* permission falls short of
// the need it was given — cannot see it: without this, an owner or admin
// who holds some natural permission but not transferPerm acts purely on
// auth.admin_can_access_files with nothing in the audit log (DESIGN §6:
// every access that needs the override is audited as admin.file_access).
func (o *op) auditTransfer(n *nodeRow, need core.Perm) error {
	natural, _, err := o.perms(n)
	if err != nil {
		return err
	}
	if natural < need {
		o.adminAccess(n, need)
	}
	return nil
}

// transferPerm is the permission needed to purge in, or move out of, a
// space: PermOwner in personal spaces, PermManage in group spaces (where
// nobody holds PermOwner: group managers, and manager grants inside their
// subtree). Grants never give PermOwner, so in personal spaces these stay
// with the owner.
func transferPerm(kind string) core.Perm {
	if kind == core.SpaceGroup {
		return core.PermManage
	}
	return core.PermOwner
}

// grantCond returns an SQL condition (on the node_grants alias g) matching
// live grants to the actor's user, their effective groups or their custom
// role, and its arguments. The expiry is compared with the operation's
// clock. The role is read from users inside the same statement, so a role
// change applies to the next call (a built-in role, role_id NULL, matches
// no role grant: built-in roles are never grant subjects).
func (o *op) grantCond(g string) (string, []any) {
	cond := fmt.Sprintf(`(%[1]s.expires_at IS NULL OR %[1]s.expires_at > ?) AND
		((%[1]s.subject_type = 'user' AND %[1]s.subject_id = ?) OR
		 (%[1]s.subject_type = 'group' AND %[1]s.subject_id IN (SELECT group_id FROM effective_group_members WHERE user_id = ?)) OR
		 (%[1]s.subject_type = 'role' AND %[1]s.subject_id = (SELECT role_id FROM users WHERE id = ?)))`, g)
	return cond, []any{o.ms, o.a.userID, o.a.userID, o.a.userID}
}

// grantLevel is the SQL expression (on the node_grants alias g) of the
// permission a grant gives: manager → PermManage (3), editor → PermEdit (2),
// viewer → PermView (1).
const grantLevel = `CASE g.role WHEN 'manager' THEN 3 WHEN 'editor' THEN 2 WHEN 'viewer' THEN 1 ELSE 0 END`

// hasGrants reports whether the user holds any live grant (cached).
func (o *op) hasGrants() (bool, error) {
	a := o.a
	if a.system || a.userID == "" {
		return false, nil
	}
	if a.anyGr != nil {
		return *a.anyGr, nil
	}
	cond, args := o.grantCond("g")
	var has bool
	if err := o.q.QueryRowContext(o.ctx, `SELECT EXISTS(SELECT 1 FROM node_grants g WHERE `+cond+`)`, args...).Scan(&has); err != nil {
		return false, err
	}
	a.anyGr = &has
	return has, nil
}

// grantPerm is the best live grant on id or an ancestor.
func (o *op) grantPerm(id string) (core.Perm, error) {
	if p, ok := o.a.grants[id]; ok {
		return p, nil
	}
	if ok, err := o.hasGrants(); err != nil || !ok {
		return core.PermNone, err
	}
	cond, args := o.grantCond("g")
	var best int
	err := o.q.QueryRowContext(o.ctx, `WITH RECURSIVE anc(id, parent_id) AS (
			SELECT id, parent_id FROM nodes WHERE id = ?
			UNION ALL
			SELECT n.id, n.parent_id FROM nodes n JOIN anc ON n.id = anc.parent_id
		)
		SELECT COALESCE(MAX(`+grantLevel+`), 0)
		FROM anc JOIN node_grants g ON g.node_id = anc.id WHERE `+cond, append([]any{id}, args...)...).Scan(&best)
	if err != nil {
		return core.PermNone, err
	}
	p := core.Perm(best) // 1 = PermView, 2 = PermEdit, 3 = PermManage
	if o.a.grants == nil {
		o.a.grants = map[string]core.Perm{}
	}
	o.a.grants[id] = p
	return p, nil
}

// perms returns the natural permission of the actor on r (space + grants)
// and the effective one (with the admin override).
func (o *op) perms(r *nodeRow) (natural, effective core.Perm, err error) {
	natural = o.a.spacePerm(r.spaceKind, r.spaceOwner, r.spaceGroup)
	if natural < core.PermManage { // grants give at most PermManage
		g, err := o.grantPerm(r.ID)
		if err != nil {
			return 0, 0, err
		}
		natural = max(natural, g)
	}
	effective = natural
	if o.a.adminOK && effective < core.PermManage {
		effective = core.PermManage
	}
	return natural, effective, nil
}

// fillPerms sets Perm on every row (batched grant resolution) and returns
// the rows the actor can see (Perm >= PermView).
func (o *op) fillPerms(rows []*nodeRow) ([]*nodeRow, error) {
	var need []string
	for _, r := range rows {
		r.Perm = o.a.spacePerm(r.spaceKind, r.spaceOwner, r.spaceGroup)
		if r.Perm < core.PermManage { // grants give at most PermManage
			if _, cached := o.a.grants[r.ID]; !cached {
				need = append(need, r.ID)
			}
		}
	}
	if len(need) > 0 {
		ok, err := o.hasGrants()
		if err != nil {
			return nil, err
		}
		if o.a.grants == nil {
			o.a.grants = map[string]core.Perm{}
		}
		for _, id := range need {
			o.a.grants[id] = core.PermNone
		}
		if ok {
			cond, args := o.grantCond("g")
			q := `WITH RECURSIVE anc(start, id, parent_id) AS (
					SELECT id, id, parent_id FROM nodes WHERE id IN (` + placeholders(len(need)) + `)
					UNION ALL
					SELECT anc.start, n.id, n.parent_id FROM nodes n JOIN anc ON n.id = anc.parent_id
				)
				SELECT anc.start, MAX(` + grantLevel + `)
				FROM anc JOIN node_grants g ON g.node_id = anc.id WHERE ` + cond + ` GROUP BY anc.start`
			rs, err := o.q.QueryContext(o.ctx, q, append(anyArgs(need), args...)...)
			if err != nil {
				return nil, err
			}
			for rs.Next() {
				var id string
				var best int
				if err := rs.Scan(&id, &best); err != nil {
					rs.Close()
					return nil, err
				}
				o.a.grants[id] = core.Perm(best)
			}
			rs.Close()
			if err := rs.Err(); err != nil {
				return nil, err
			}
		}
	}
	out := rows[:0:0]
	for _, r := range rows {
		if r.Perm < core.PermManage {
			r.Perm = max(r.Perm, o.a.grants[r.ID])
		}
		if o.a.adminOK && r.Perm < core.PermManage {
			r.Perm = core.PermManage
		}
		if r.Perm >= core.PermView {
			out = append(out, r)
		}
	}
	return out, nil
}

// authOpt tunes authorize.
type authOpt struct {
	allowTrashed bool
	// scope overrides the API token scope derived from need, both ways: a
	// call that writes but needs only PermView on the node — starring, which
	// you may do on any file you can see — must still demand files:write,
	// and one that only reads but needs PermManage — listing grants — must
	// not demand it.
	scope string
	// noAdminAudit skips the admin.file_access entry: for a later
	// transaction of a call whose first pass already audited the override
	// (purgeRoot's chunks). The permission is still checked.
	noAdminAudit bool
}

// authorize loads id and checks that the actor holds need on it: 404 when
// the node does not exist or is invisible to the actor, 403 when visible
// but insufficient, 404 for trashed nodes unless allowed. API tokens need
// files:read (need <= PermView) or files:write, unless opt.scope names the
// scope. Access that only the admin override grants is audited
// (admin.file_access).
func (o *op) authorize(id string, need core.Perm, opt authOpt) (*nodeRow, error) {
	r, err := o.loadNode(id)
	if err != nil {
		return nil, err
	}
	if r == nil {
		return nil, notFound()
	}
	natural, eff, err := o.perms(r)
	if err != nil {
		return nil, err
	}
	if eff == core.PermNone {
		return nil, notFound()
	}
	scope := opt.scope
	if scope == "" {
		scope = scopeFor(need)
	}
	if err := o.requireScope(scope); err != nil {
		return nil, err
	}
	if eff < need {
		return nil, forbiddenf("you need %s permission on %q", need, r.Name)
	}
	if natural < need && !opt.noAdminAudit {
		o.adminAccess(r, need)
	}
	if r.TrashedAt != nil && !opt.allowTrashed {
		return nil, core.NotFoundf("%q is in the trash", r.Name)
	}
	r.Perm = eff
	return r, nil
}

// checkScope enforces the API token scope that need implies.
func (o *op) checkScope(need core.Perm) error { return o.requireScope(scopeFor(need)) }

// scopeFor is the API token scope a call needing need implies.
func scopeFor(need core.Perm) string {
	if need >= core.PermEdit {
		return core.ScopeFilesWrite
	}
	return core.ScopeFilesRead
}

// requireScope enforces one API token scope.
func (o *op) requireScope(scope string) error {
	if !o.a.p.HasScope(scope) {
		return forbiddenf("token lacks scope %q", scope)
	}
	return nil
}

// adminAccess audits an access granted only by the admin override (once per
// node and call — again only when a later step of the same call needs more
// than the entry already written, e.g. a purge that turns out to need
// PermOwner after the node was authorized for PermEdit).
//
// Public share requests (Via share: Files.SysPrincipalFor) act as the link's
// creator on behalf of an anonymous visitor. When an administrator created
// the link through the override, that access was audited when the link was
// created (shares.Create authorizes PermManage), and every visit is in the
// share access log: auditing it again on each page, download or thumbnail
// would attribute a visitor's requests to the admin, at request rate. The
// permission itself is still checked, so the link stops working when the
// override is turned off.
func (o *op) adminAccess(r *nodeRow, need core.Perm) {
	if o.a.p != nil && o.a.p.Via == core.ViaShare {
		return
	}
	if o.a.audited == nil {
		o.a.audited = map[string]core.Perm{}
	}
	if p, ok := o.a.audited[r.ID]; ok && p >= need {
		return
	}
	o.a.audited[r.ID] = need
	o.always = append(o.always, core.AuditEntry{Action: core.ActAdminFileAccess, TargetType: "node",
		TargetID: r.ID, TargetName: r.Name,
		Details: map[string]any{"need": need.String(), "space_id": r.SpaceID}})
}
