package users

import (
	"context"
	"database/sql"
	"strings"

	"fileparcel/internal/core"
	"fileparcel/internal/db"
	"fileparcel/internal/ids"
	"fileparcel/internal/names"
)

// Group memberships are direct (group_members) or through a custom role
// (role_groups: every holder of the role is a member or manager of the
// group). The view effective_group_members lists both; every read that asks
// "who is in this group" or "which groups is this user in" uses it, and a
// user in a group both ways counts once, as manager when either row says so.

// groupCols selects a groups row (alias g) plus the number of distinct
// effective members, the space id and the number of member roles.
const groupCols = `g.id, g.name, g.description, g.created_at, g.created_by,
	(SELECT count(DISTINCT e.user_id) FROM effective_group_members e WHERE e.group_id = g.id),
	(SELECT sp.id FROM spaces sp WHERE sp.group_id = g.id AND sp.kind = 'group'),
	(SELECT count(*) FROM role_groups rg WHERE rg.group_id = g.id)`

func scanGroup(sc scanner, extra ...any) (*core.Group, error) {
	var g core.Group
	var created int64
	var createdBy, spaceID sql.NullString
	dest := append([]any{&g.ID, &g.Name, &g.Description, &created, &createdBy, &g.MemberCount, &spaceID, &g.RoleCount}, extra...)
	if err := sc.Scan(dest...); err != nil {
		return nil, err
	}
	g.CreatedAt = db.FromMs(created)
	g.CreatedBy = createdBy.String
	g.SpaceID = spaceID.String
	return &g, nil
}

func errGroupNotFound() error { return core.NotFoundf("group not found") }

func getGroup(ctx context.Context, q queryer, id string) (*core.Group, error) {
	g, err := scanGroup(q.QueryRowContext(ctx, `SELECT `+groupCols+` FROM groups g WHERE g.id = ?`, id))
	if db.IsNoRows(err) {
		return nil, errGroupNotFound()
	}
	return g, err
}

// ListGroups lists every group by name (case-insensitive), keyset-paginated.
func (s *Service) ListGroups(ctx context.Context, q core.PageReq) (core.Page[core.Group], error) {
	order, cmp := "ASC", ">"
	if q.Desc {
		order, cmp = "DESC", "<"
	}
	where := ""
	var args []any
	if q.Cursor != "" {
		c, err := decodeCursor(q.Cursor)
		if err != nil {
			return core.Page[core.Group]{}, err
		}
		where = ` WHERE (g.name ` + cmp + ` ? OR (g.name = ? AND g.id ` + cmp + ` ?))`
		args = append(args, c.S, c.S, c.I)
	}
	switch q.Sort {
	case "", "name":
	default:
		return core.Page[core.Group]{}, core.Invalid("sort", "sort must be name")
	}
	limit := q.EffectiveLimit()
	args = append(args, limit+1)
	rows, err := s.env.DB.Query(ctx, `SELECT `+groupCols+` FROM groups g`+where+
		` ORDER BY g.name `+order+`, g.id `+order+` LIMIT ?`, args...)
	if err != nil {
		return core.Page[core.Group]{}, err
	}
	defer rows.Close()
	var out []core.Group
	for rows.Next() {
		g, err := scanGroup(rows)
		if err != nil {
			return core.Page[core.Group]{}, err
		}
		out = append(out, *g)
	}
	if err := rows.Err(); err != nil {
		return core.Page[core.Group]{}, err
	}
	next := ""
	if len(out) > limit {
		out = out[:limit]
		last := out[len(out)-1]
		next = encodeCursor(cursor{S: last.Name, I: last.ID})
	}
	return core.NewPage(out, next), nil
}

// GetGroup returns one group with the custom roles that are its members
// (Roles, by role name; 404 when missing).
func (s *Service) GetGroup(ctx context.Context, id string) (*core.Group, error) {
	if id == "" {
		return nil, errGroupNotFound()
	}
	var g *core.Group
	err := s.env.DB.Read(ctx, func(tx *sql.Tx) error {
		var err error
		if g, err = getGroup(ctx, tx, id); err != nil {
			return err
		}
		g.Roles, err = listRoleGroups(ctx, tx, `WHERE rg.group_id = ? ORDER BY r.name COLLATE NOCASE, r.id`, id)
		return err
	})
	return g, err
}

// CreateGroup creates a group and its "Team folder" space whose root folder
// is named after the group (groups.manage).
func (s *Service) CreateGroup(ctx context.Context, by *core.Principal, in core.GroupInput) (*core.Group, error) {
	if err := requireCap(by, core.CapGroupsManage); err != nil {
		return nil, err
	}
	name, err := cleanGroupName(in.Name)
	if err != nil {
		return nil, err
	}
	desc := ""
	if in.Description != nil {
		if desc, err = cleanLongText(*in.Description, "description", maxDescriptionLen); err != nil {
			return nil, err
		}
	}
	var id string
	err = s.env.DB.Tx(ctx, func(tx *sql.Tx) error {
		if err := groupNameFree(ctx, tx, name, ""); err != nil {
			return err
		}
		id = ids.New(ids.PrefixGroup)
		now := db.Ms(s.now())
		if _, err := tx.ExecContext(ctx, `INSERT INTO groups (id, name, description, created_at, created_by) VALUES (?, ?, ?, ?, ?)`,
			id, name, desc, now, db.NullString(actorID(by))); err != nil {
			if db.IsUnique(err) {
				return conflictField("name", "a group with this name already exists")
			}
			return err
		}
		spaceID, err := insertSpace(ctx, tx, core.SpaceGroup, "", id, name, nil, actorID(by), now)
		if err != nil {
			return err
		}
		return s.auditByTx(ctx, tx, by, core.AuditEntry{
			Action: core.ActGroupCreate, TargetType: "group", TargetID: id, TargetName: name,
			Details: map[string]any{"space_id": spaceID},
		})
	})
	if err != nil {
		return nil, err
	}
	return s.GetGroup(ctx, id)
}

// groupNameFree fails with a conflict when another group uses name. Names
// are compared as labels (names.LabelKey: casefold(NFC) without joiners and
// direction marks), not by the column's NOCASE collation alone, which folds
// ASCII only: "Équipe" and "équipe" would be two groups that the CLI and the
// /Team/<group> paths cannot tell apart, and "Design\u200D" one that looks
// like "Design". Groups are few, so the scan is cheap; the UNIQUE
// constraint stays as the ASCII backstop.
func groupNameFree(ctx context.Context, tx *sql.Tx, name, exceptID string) error {
	rows, err := tx.QueryContext(ctx, `SELECT name FROM groups WHERE id <> ?`, exceptID)
	if err != nil {
		return err
	}
	defer rows.Close()
	key := names.LabelKey(name)
	for rows.Next() {
		var other string
		if err := rows.Scan(&other); err != nil {
			return err
		}
		if names.LabelKey(other) == key {
			return conflictField("name", "a group with this name already exists")
		}
	}
	return rows.Err()
}

// UpdateGroup renames a group and/or changes its description
// (groups.manage). A rename also renames the group's space and root folder.
func (s *Service) UpdateGroup(ctx context.Context, by *core.Principal, id string, in core.GroupInput) (*core.Group, error) {
	if err := requireCap(by, core.CapGroupsManage); err != nil {
		return nil, err
	}
	var name, desc string
	var err error
	if strings.TrimSpace(in.Name) != "" {
		if name, err = cleanGroupName(in.Name); err != nil {
			return nil, err
		}
	}
	if in.Description != nil {
		if desc, err = cleanLongText(*in.Description, "description", maxDescriptionLen); err != nil {
			return nil, err
		}
	}
	err = s.env.DB.Tx(ctx, func(tx *sql.Tx) error {
		cur, err := getGroup(ctx, tx, id)
		if err != nil {
			return err
		}
		changes := map[string]any{}
		if name != "" && name != cur.Name {
			if err := groupNameFree(ctx, tx, name, id); err != nil {
				return err
			}
			nfc, key, err := names.Clean(name)
			if err != nil {
				return err
			}
			if _, err := tx.ExecContext(ctx, `UPDATE groups SET name = ? WHERE id = ?`, name, id); err != nil {
				if db.IsUnique(err) {
					return conflictField("name", "a group with this name already exists")
				}
				return err
			}
			spaceID, rootID, err := groupSpace(ctx, tx, id)
			if err != nil {
				return err
			}
			if spaceID != "" {
				if _, err := tx.ExecContext(ctx, `UPDATE spaces SET name = ? WHERE id = ?`, nfc, spaceID); err != nil {
					return err
				}
			}
			if rootID != "" {
				if _, err := tx.ExecContext(ctx, `UPDATE nodes SET name = ?, name_key = ?, updated_at = ? WHERE id = ?`,
					nfc, key, db.Ms(s.now()), rootID); err != nil {
					return err
				}
			}
			changes["name"] = map[string]string{"from": cur.Name, "to": name}
		}
		if in.Description != nil && desc != cur.Description {
			if _, err := tx.ExecContext(ctx, `UPDATE groups SET description = ? WHERE id = ?`, desc, id); err != nil {
				return err
			}
			changes["description"] = true
		}
		if len(changes) == 0 {
			return nil
		}
		return s.auditByTx(ctx, tx, by, core.AuditEntry{
			Action: core.ActGroupUpdate, TargetType: "group", TargetID: id, TargetName: cur.Name, Details: changes,
		})
	})
	if err != nil {
		return nil, err
	}
	return s.GetGroup(ctx, id)
}

// DeleteGroup deletes a group, its memberships (direct and through roles),
// the grants naming it and its Team folder with every file in it
// (groups.manage; blobs become unreferenced and are removed by the blob GC).
// The holders of the roles that were members lose the group:
// authz.changed is published for each such role.
func (s *Service) DeleteGroup(ctx context.Context, by *core.Principal, id string) error {
	if err := requireCap(by, core.CapGroupsManage); err != nil {
		return err
	}
	var roleIDs []string
	err := s.env.DB.Tx(ctx, func(tx *sql.Tx) error {
		cur, err := getGroup(ctx, tx, id)
		if err != nil {
			return err
		}
		var files, bytes int64
		if cur.SpaceID != "" {
			if err := tx.QueryRowContext(ctx, `SELECT count(*), COALESCE(SUM(size), 0) FROM nodes WHERE space_id = ? AND kind = 'file'`,
				cur.SpaceID).Scan(&files, &bytes); err != nil {
				return err
			}
		}
		rgs, err := listRoleGroups(ctx, tx, `WHERE rg.group_id = ? ORDER BY rg.role_id`, id)
		if err != nil {
			return err
		}
		roleIDs = roleIDs[:0]
		for _, rg := range rgs {
			roleIDs = append(roleIDs, rg.RoleID)
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM node_grants WHERE subject_type = 'group' AND subject_id = ?`, id); err != nil {
			return err
		}
		// role_groups rows go with the group (ON DELETE CASCADE).
		if _, err := tx.ExecContext(ctx, `DELETE FROM groups WHERE id = ?`, id); err != nil {
			return err
		}
		return s.auditByTx(ctx, tx, by, core.AuditEntry{
			Action: core.ActGroupDelete, TargetType: "group", TargetID: id, TargetName: cur.Name,
			Details: map[string]any{"members": cur.MemberCount, "roles": len(rgs), "files": files, "bytes": bytes},
		})
	})
	if err != nil {
		return err
	}
	for _, r := range roleIDs {
		s.publishAuthz(core.AuthzChangedEvent{RoleID: r, Reason: core.AuthzRoleGroups})
	}
	return nil
}

// Members lists a group's effective members by username (404 for a missing
// group): one row per user, with the effective role (manager wins), the
// direct membership and the custom roles the user is a member through.
// AddedAt is the direct membership's, else the earliest role membership's.
func (s *Service) Members(ctx context.Context, groupID string) ([]core.GroupMember, error) {
	out := []core.GroupMember{}
	err := s.env.DB.Read(ctx, func(tx *sql.Tx) error {
		if _, err := getGroup(ctx, tx, groupID); err != nil {
			return err
		}
		rows, err := tx.QueryContext(ctx, `SELECT e.user_id, u.username, u.display_name, e.role, e.source,
				COALESCE(e.via_role_id, ''), COALESCE(r.name, ''),
				CASE e.source
					WHEN 'direct' THEN (SELECT m.added_at FROM group_members m WHERE m.group_id = e.group_id AND m.user_id = e.user_id)
					ELSE (SELECT rg.added_at FROM role_groups rg WHERE rg.group_id = e.group_id AND rg.role_id = e.via_role_id)
				END
			FROM effective_group_members e JOIN users u ON u.id = e.user_id LEFT JOIN roles r ON r.id = e.via_role_id
			WHERE e.group_id = ? ORDER BY u.username, u.id, e.source, r.name`, groupID)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var gm core.GroupMember
			var m membershipRow
			var added int64
			if err := rows.Scan(&gm.UserID, &gm.Username, &gm.DisplayName, &m.role, &m.source, &m.roleID, &m.roleName, &added); err != nil {
				return err
			}
			// Rows come per user, the direct one first ("direct" < "role").
			n := len(out)
			if n == 0 || out[n-1].UserID != gm.UserID {
				gm.GroupID, gm.AddedAt = groupID, db.FromMs(added)
				out = append(out, gm)
			}
			cur := &out[len(out)-1]
			if t := db.FromMs(added); !cur.Direct && t.Before(cur.AddedAt) {
				cur.AddedAt = t
			}
			m.mergeInto(&cur.Role, &cur.Direct, &cur.DirectRole, &cur.ViaRoles)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// SetMember adds userID to groupID or changes the role of the direct
// membership (member | manager; groups.manage). Memberships through a role
// are independent of it. Audited as group.member_set when something changed.
func (s *Service) SetMember(ctx context.Context, by *core.Principal, groupID, userID, role string) error {
	if err := requireCap(by, core.CapGroupsManage); err != nil {
		return err
	}
	if role == "" {
		role = core.GroupRoleMember
	}
	if role != core.GroupRoleMember && role != core.GroupRoleManager {
		return core.Invalid("role", "role must be member or manager")
	}
	return s.env.DB.Tx(ctx, func(tx *sql.Tx) error {
		g, err := getGroup(ctx, tx, groupID)
		if err != nil {
			return err
		}
		u, err := getUser(ctx, tx, userID)
		if err != nil {
			return err
		}
		var cur string
		err = tx.QueryRowContext(ctx, `SELECT role FROM group_members WHERE group_id = ? AND user_id = ?`, groupID, userID).Scan(&cur)
		switch {
		case err == nil && cur == role:
			return nil
		case err == nil:
			_, err = tx.ExecContext(ctx, `UPDATE group_members SET role = ? WHERE group_id = ? AND user_id = ?`, role, groupID, userID)
		case db.IsNoRows(err):
			_, err = tx.ExecContext(ctx, `INSERT INTO group_members (group_id, user_id, role, added_at) VALUES (?, ?, ?, ?)`,
				groupID, userID, role, db.Ms(s.now()))
		}
		if err != nil {
			return err
		}
		return s.auditByTx(ctx, tx, by, core.AuditEntry{
			Action: core.ActGroupMemberSet, TargetType: "group", TargetID: groupID, TargetName: g.Name,
			Details: map[string]any{"user_id": u.ID, "username": u.Username, "role": role, "previous_role": cur},
		})
	})
}

// RemoveMember ends the direct membership of userID in groupID
// (groups.manage). 404 when the user is not a member; 409 when they are a
// member only through their role (that membership ends with the role → group
// membership or a role change).
func (s *Service) RemoveMember(ctx context.Context, by *core.Principal, groupID, userID string) error {
	if err := requireCap(by, core.CapGroupsManage); err != nil {
		return err
	}
	return s.env.DB.Tx(ctx, func(tx *sql.Tx) error {
		g, err := getGroup(ctx, tx, groupID)
		if err != nil {
			return err
		}
		var username string
		_ = tx.QueryRowContext(ctx, `SELECT username FROM users WHERE id = ?`, userID).Scan(&username)
		res, err := tx.ExecContext(ctx, `DELETE FROM group_members WHERE group_id = ? AND user_id = ?`, groupID, userID)
		if err != nil {
			return err
		}
		if n, _ := res.RowsAffected(); n == 0 {
			var roleName string
			err := tx.QueryRowContext(ctx, `SELECT r.name FROM role_groups rg JOIN roles r ON r.id = rg.role_id
				JOIN users u ON u.role_id = rg.role_id WHERE rg.group_id = ? AND u.id = ?`, groupID, userID).Scan(&roleName)
			switch {
			case err == nil:
				return core.Errorf(core.ErrConflict,
					"“%s” is a member through the role “%s”; remove the role from the group or change their role", username, roleName)
			case !db.IsNoRows(err):
				return err
			}
			return core.NotFoundf("the user is not a member of this group")
		}
		return s.auditByTx(ctx, tx, by, core.AuditEntry{
			Action: core.ActGroupMemberRemove, TargetType: "group", TargetID: groupID, TargetName: g.Name,
			Details: map[string]any{"user_id": userID, "username": username},
		})
	})
}

// GroupIDsOf returns the ids of the groups userID belongs to, directly or
// through their custom role.
func (s *Service) GroupIDsOf(ctx context.Context, userID string) ([]string, error) {
	rows, err := s.env.DB.Query(ctx, `SELECT DISTINCT group_id FROM effective_group_members WHERE user_id = ? ORDER BY group_id`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []string{}
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		out = append(out, id)
	}
	return out, rows.Err()
}

// MyGroups lists the principal's groups (direct or through their custom
// role) by name with the effective membership role (MyRole, manager wins),
// how they belong to it (Via: "direct" when a direct membership exists,
// else "role"), the member count and the space id.
func (s *Service) MyGroups(ctx context.Context, p *core.Principal) ([]core.Group, error) {
	out := []core.Group{}
	if p == nil || p.UserID == "" {
		return out, nil
	}
	rows, err := s.env.DB.Query(ctx, `SELECT `+groupCols+`, MAX(CASE e.role WHEN 'manager' THEN 2 ELSE 1 END), MIN(e.source)
		FROM groups g JOIN effective_group_members e ON e.group_id = g.id
		WHERE e.user_id = ? GROUP BY g.id ORDER BY g.name, g.id`, p.UserID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var rank int
		var via string
		g, err := scanGroup(rows, &rank, &via)
		if err != nil {
			return nil, err
		}
		g.MyRole, g.Via = core.GroupRoleMember, via
		if rank == 2 {
			g.MyRole = core.GroupRoleManager
		}
		out = append(out, *g)
	}
	return out, rows.Err()
}
