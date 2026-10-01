package files

import (
	"context"
	"database/sql"
	"fmt"
	"math"
	"time"

	"fileparcel/internal/core"
	"fileparcel/internal/db"
	"fileparcel/internal/ids"
)

// grantCols selects a grant (alias g) with the subject's display name.
const grantCols = `g.id, g.node_id, g.subject_type, g.subject_id, g.role, COALESCE(g.created_by, ''), g.created_at, g.expires_at,
	COALESCE(CASE g.subject_type
		WHEN 'user' THEN (SELECT COALESCE(NULLIF(u.display_name, ''), u.username) FROM users u WHERE u.id = g.subject_id)
		WHEN 'group' THEN (SELECT gr.name FROM groups gr WHERE gr.id = g.subject_id)
		WHEN 'role' THEN (SELECT r.name FROM roles r WHERE r.id = g.subject_id) END, '')`

func scanGrant(sc scanner) (*core.Grant, error) {
	var g core.Grant
	var created int64
	var exp sql.NullInt64
	if err := sc.Scan(&g.ID, &g.NodeID, &g.SubjectType, &g.SubjectID, &g.Role, &g.CreatedBy, &created, &exp,
		&g.SubjectName); err != nil {
		return nil, err
	}
	g.CreatedAt = db.FromMs(created)
	g.ExpiresAt = db.FromNullMs(exp)
	return &g, nil
}

// Grants implements core.Files: the live grants on id and its ancestors
// (inherited grants have a different NodeID), outermost first (PermManage;
// token scope files:read).
func (svc *Service) Grants(ctx context.Context, p *core.Principal, id string) ([]core.Grant, error) {
	out := []core.Grant{}
	err := svc.read(ctx, p, func(o *op) error {
		// Listing grants is a read: a token needs files:read, like the other
		// reads, even though the node needs PermManage.
		n, err := o.authorize(id, core.PermManage, authOpt{scope: core.ScopeFilesRead})
		if err != nil {
			return err
		}
		rows, err := o.q.QueryContext(o.ctx, `WITH RECURSIVE anc(id, parent_id, depth) AS (
				SELECT id, parent_id, 0 FROM nodes WHERE id = ?
				UNION ALL
				SELECT n.id, n.parent_id, anc.depth + 1 FROM nodes n JOIN anc ON n.id = anc.parent_id
			)
			SELECT `+grantCols+` FROM anc JOIN node_grants g ON g.node_id = anc.id
			WHERE g.expires_at IS NULL OR g.expires_at > ?
			ORDER BY anc.depth DESC, g.created_at, g.id`, n.ID, o.ms)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			g, err := scanGrant(rows)
			if err != nil {
				return err
			}
			out = append(out, *g)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// grantSubjects maps each grant subject type to its id prefix and table.
// Custom roles are subjects (everyone holding the role, including people
// who get it later); built-in roles are not: share with a group instead.
var grantSubjects = map[string]struct{ prefix, table string }{
	core.SubjectUser:  {ids.PrefixUser, "users"},
	core.SubjectGroup: {ids.PrefixGroup, "groups"},
	core.SubjectRole:  {ids.PrefixRole, "roles"},
}

// SetGrant implements core.Files: gives a user, group or custom role
// viewer, editor or manager access to id and its descendants, or updates the
// existing grant of that subject — level and expiry both: ExpiresAt nil
// means no expiry (PermManage — sharing with a role is not an escalation: it
// needs exactly what sharing with a group needs). Grants to oneself are
// rejected; ExpiresAt must be in the future. A grant to a group or role the
// caller belongs to must not outlast the caller's own access of that level
// when it comes from expiring grants (selfGrantLimit): otherwise the holder
// of an expiring manager grant could re-grant their own group or role
// without an expiry and keep the access for ever.
func (svc *Service) SetGrant(ctx context.Context, p *core.Principal, id string, in core.GrantInput) (*core.Grant, error) {
	subj, ok := grantSubjects[in.SubjectType]
	if !ok {
		return nil, core.Invalid("subject_type", "subject_type must be user, group or role")
	}
	switch in.Role {
	case core.GrantViewer, core.GrantEditor, core.GrantManager:
	default:
		return nil, core.Invalid("role", "role must be viewer, editor or manager")
	}
	if !ids.Valid(subj.prefix, in.SubjectID) {
		return nil, core.Invalid("subject_id", "unknown "+in.SubjectType)
	}
	var out *core.Grant
	err := svc.write(ctx, p, func(o *op) error {
		n, err := o.authorize(id, core.PermManage, authOpt{})
		if err != nil {
			return err
		}
		if in.ExpiresAt != nil && !in.ExpiresAt.After(o.now) {
			return core.Invalid("expires_at", "the expiry must be in the future")
		}
		if in.SubjectType == core.SubjectUser && in.SubjectID == o.a.userID {
			return core.Invalid("subject_id", "you cannot share with yourself")
		}
		var exists bool
		if err := o.q.QueryRowContext(o.ctx, `SELECT EXISTS(SELECT 1 FROM `+subj.table+` WHERE id = ?)`, in.SubjectID).
			Scan(&exists); err != nil {
			return err
		}
		if !exists {
			return core.Invalid("subject_id", "unknown "+in.SubjectType)
		}
		if limit, err := o.selfGrantLimit(n, in); err != nil {
			return err
		} else if limit != nil && (in.ExpiresAt == nil || in.ExpiresAt.After(*limit)) {
			return core.Invalid("expires_at", fmt.Sprintf(
				"your own access to %q ends on %s: a group or role you belong to can get access only until then",
				n.Name, limit.UTC().Format(time.RFC3339)))
		}
		if _, err := o.q.ExecContext(o.ctx, `INSERT INTO node_grants
			(id, node_id, subject_type, subject_id, role, created_by, created_at, expires_at)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?)
			ON CONFLICT (node_id, subject_type, subject_id) DO UPDATE SET role = excluded.role, expires_at = excluded.expires_at`,
			ids.New(ids.PrefixGrant), n.ID, in.SubjectType, in.SubjectID, in.Role, o.uid(), o.ms, db.NullMs(in.ExpiresAt)); err != nil {
			return err
		}
		out, err = scanGrant(o.q.QueryRowContext(o.ctx, `SELECT `+grantCols+` FROM node_grants g
			WHERE g.node_id = ? AND g.subject_type = ? AND g.subject_id = ?`, n.ID, in.SubjectType, in.SubjectID))
		if err != nil {
			return err
		}
		o.audit(nodeAudit(core.ActGrantSet, &n.Node, map[string]any{"grant_id": out.ID, "subject_type": out.SubjectType,
			"subject_id": out.SubjectID, "role": out.Role, "expires_at": out.ExpiresAt}))
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// selfGrantLimit returns until when a grant of in.Role to in.SubjectType /
// in.SubjectID on n may last, or nil for no limit. The limit exists only
// when the subject includes the actor — a group they are an effective member
// of, or their custom role (their own account is refused before) — and the
// actor's access of that level comes from grants alone: not from the space
// (their personal space, a group they manage or, for editor and viewer, are
// a member of), not from the administrators' file-access override. It is
// then the latest expiry among the actor's live grants of at least that
// level on n and its ancestors (one without expiry: no limit).
func (o *op) selfGrantLimit(n *nodeRow, in core.GrantInput) (*time.Time, error) {
	a := o.a
	if a.system || a.adminOK || a.userID == "" {
		return nil, nil
	}
	switch in.SubjectType {
	case core.SubjectGroup:
		if _, member := a.groups[in.SubjectID]; !member {
			return nil, nil
		}
	case core.SubjectRole:
		var roleID sql.NullString
		if err := o.q.QueryRowContext(o.ctx, `SELECT role_id FROM users WHERE id = ?`, a.userID).Scan(&roleID); err != nil {
			if db.IsNoRows(err) {
				return nil, nil
			}
			return nil, err
		}
		if roleID.String != in.SubjectID {
			return nil, nil
		}
	default:
		return nil, nil
	}
	level := grantRolePerm(in.Role)
	if a.spacePerm(n.spaceKind, n.spaceOwner, n.spaceGroup) >= level {
		return nil, nil
	}
	cond, args := o.grantCond("g")
	var latest sql.NullInt64
	err := o.q.QueryRowContext(o.ctx, `WITH RECURSIVE anc(id, parent_id) AS (
			SELECT id, parent_id FROM nodes WHERE id = ?
			UNION ALL
			SELECT n.id, n.parent_id FROM nodes n JOIN anc ON n.id = anc.parent_id
		)
		SELECT MAX(COALESCE(g.expires_at, 9223372036854775807))
		FROM anc JOIN node_grants g ON g.node_id = anc.id WHERE `+cond+` AND `+grantLevel+` >= ?`,
		append(append([]any{n.ID}, args...), int(level))...).Scan(&latest)
	if err != nil {
		return nil, err
	}
	switch {
	case !latest.Valid: // no grant of that level: nothing to extend, and nothing to give either
		t := o.now
		return &t, nil
	case latest.Int64 == math.MaxInt64:
		return nil, nil
	}
	t := db.FromMs(latest.Int64)
	return &t, nil
}

// grantRolePerm is the node permission a grant role gives (grantLevel in Go).
func grantRolePerm(role string) core.Perm {
	switch role {
	case core.GrantManager:
		return core.PermManage
	case core.GrantEditor:
		return core.PermEdit
	case core.GrantViewer:
		return core.PermView
	}
	return core.PermNone
}

// RemoveGrant implements core.Files: deletes the grant grantID set directly
// on id (PermManage; inherited grants are removed on their own node).
func (svc *Service) RemoveGrant(ctx context.Context, p *core.Principal, id, grantID string) error {
	return svc.write(ctx, p, func(o *op) error {
		n, err := o.authorize(id, core.PermManage, authOpt{})
		if err != nil {
			return err
		}
		var subjType, subjID, role string
		err = o.q.QueryRowContext(o.ctx, `SELECT subject_type, subject_id, role FROM node_grants WHERE id = ? AND node_id = ?`,
			grantID, n.ID).Scan(&subjType, &subjID, &role)
		if db.IsNoRows(err) {
			return core.NotFoundf("grant not found")
		}
		if err != nil {
			return err
		}
		if _, err := o.q.ExecContext(o.ctx, `DELETE FROM node_grants WHERE id = ?`, grantID); err != nil {
			return err
		}
		o.audit(nodeAudit(core.ActGrantRemove, &n.Node, map[string]any{"grant_id": grantID, "subject_type": subjType,
			"subject_id": subjID, "role": role}))
		return nil
	})
}
