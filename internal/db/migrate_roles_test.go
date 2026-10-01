package db

import (
	"context"
	"slices"
	"strings"
	"testing"
	"time"
)

// TestMigration0002 checks the schema rules of 0002_roles (DESIGN §6,
// rbac-final §4) on a v1 database brought up to date: the id, name and base
// constraints of roles, the triggers that keep users.role and invites.role
// equal to the base of their custom role and the base immutable, the grant
// subjects and levels, what deleting a role, a group or a user takes along,
// the effective membership view and the indexes it uses.
func TestMigration0002(t *testing.T) {
	ctx := context.Background()
	d := v1DB(t)
	now := Ms(time.Now())
	exec := func(q string, args ...any) error {
		_, err := d.Exec(ctx, q, args...)
		return err
	}
	must := func(q string, args ...any) {
		t.Helper()
		if err := exec(q, args...); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}
	refused := func(what, q string, args ...any) {
		t.Helper()
		if err := exec(q, args...); err == nil {
			t.Errorf("%s: accepted", what)
		}
	}
	must(`INSERT INTO users(id, username, role, webauthn_handle, created_at, updated_at) VALUES
		('usr_o','olivia','owner',X'01',?1,?1), ('usr_m','mia','member',X'02',?1,?1),
		('usr_f','fin','member',X'03',?1,?1), ('usr_g','gus','guest',X'04',?1,?1)`, now)
	must(`INSERT INTO groups(id, name, created_at) VALUES ('grp_1','Finance',?1), ('grp_2','Other',?1)`, now)
	must(`INSERT INTO group_members(group_id, user_id, role, added_at) VALUES ('grp_1','usr_m','member',?1)`, now)
	must(`INSERT INTO spaces(id, kind, group_id, name, created_at) VALUES ('spc_g','group','grp_1','Finance',?1)`, now)
	must(`INSERT INTO nodes(id, space_id, parent_id, kind, name, name_key, created_at, updated_at) VALUES
		('nod_g','spc_g',NULL,'folder','','',?1,?1)`, now)
	must(`INSERT INTO node_grants(id, node_id, subject_type, subject_id, role, created_at, expires_at) VALUES
		('gnt_u','nod_g','user','usr_g','viewer',?1,NULL), ('gnt_g','nod_g','group','grp_2','editor',?1,?2)`,
		now, now+3_600_000)
	must(`INSERT INTO invites(id, token_hash, token_enc, role, created_at, expires_at) VALUES ('inv_a',X'01','v1:x','admin',?1,?1)`, now)
	if applied, err := d.Migrate(ctx); err != nil || !slices.Equal(applied, []int{2, 3, 4}) {
		t.Fatalf("migrate: %v %v", applied, err)
	}
	if got := dump(t, d, `SELECT id, subject_type, subject_id, role FROM node_grants ORDER BY id`); got != "gnt_g|group|grp_2|editor\ngnt_u|user|usr_g|viewer" {
		t.Fatalf("grants: %s", got)
	}

	const fin, vis, spare = "rol_0123456789abcdefghjkmnpqrs", "rol_1123456789abcdefghjkmnpqrs", "rol_2123456789abcdefghjkmnpqrs"
	must(`INSERT INTO roles(id, name, base, created_at, updated_at, created_by) VALUES
		(?1,'Finance','member',?4,?4,'usr_o'), (?2,'Visitors','guest',?4,?4,NULL), (?3,'Spare','member',?4,?4,NULL)`,
		fin, vis, spare, now)

	// roles: id, name and base constraints; the base and id never change.
	refused("short id", `INSERT INTO roles(id, name, base, created_at, updated_at) VALUES ('rol_short','X','member',1,1)`)
	refused("wrong prefix", `INSERT INTO roles(id, name, base, created_at, updated_at) VALUES ('grp_0123456789abcdefghjkmnpqrs','X','member',1,1)`)
	refused("admin base", `INSERT INTO roles(id, name, base, created_at, updated_at) VALUES ('rol_3123456789abcdefghjkmnpqrs','X','admin',1,1)`)
	refused("name taken (case)", `INSERT INTO roles(id, name, base, created_at, updated_at) VALUES ('rol_3123456789abcdefghjkmnpqrs','FINANCE','member',1,1)`)
	refused("base change", `UPDATE roles SET base = 'guest' WHERE id = ?`, fin)
	refused("id change", `UPDATE roles SET id = 'rol_3123456789abcdefghjkmnpqrs' WHERE id = ?`, fin)
	must(`UPDATE roles SET name = 'Finance team', permissions = '["users.view"]', delegable = 1 WHERE id = ?`, fin)
	refused("delegable 2", `UPDATE roles SET delegable = 2 WHERE id = ?`, fin)

	// users and invites: role = the base of role_id.
	must(`UPDATE users SET role_id = ? WHERE id = 'usr_f'`, fin)
	refused("user base mismatch", `UPDATE users SET role_id = ? WHERE id = 'usr_m'`, vis)
	refused("user role change under a custom role", `UPDATE users SET role = 'guest' WHERE id = 'usr_f'`)
	refused("user insert mismatch", `INSERT INTO users(id, username, role, role_id, webauthn_handle, created_at, updated_at)
		VALUES ('usr_x','x','member',?1,X'09',1,1)`, vis)
	must(`UPDATE users SET role_id = ? WHERE id = 'usr_g'`, vis)
	refused("unknown role", `UPDATE users SET role_id = 'rol_3123456789abcdefghjkmnpqrs' WHERE id = 'usr_m'`)
	refused("users.role unknown", `UPDATE users SET role = 'boss', role_id = NULL WHERE id = 'usr_m'`)
	refused("invite base mismatch", `INSERT INTO invites(id, token_hash, token_enc, role, role_id, created_at, expires_at)
		VALUES ('inv_x',X'02','v1:x','member',?1,1,1)`, vis)
	must(`INSERT INTO invites(id, token_hash, token_enc, role, role_id, created_at, expires_at)
		VALUES ('inv_v',X'03','v1:x','guest',?1,1,1)`, vis)
	refused("invite role change", `UPDATE invites SET role = 'member' WHERE id = 'inv_v'`)

	// node_grants: role subjects, the manager level, nothing else.
	must(`INSERT INTO node_grants(id, node_id, subject_type, subject_id, role, created_at) VALUES
		('gnt_rf','nod_g','role',?1,'manager',1), ('gnt_rs','nod_g','role',?2,'viewer',1)`, fin, spare)
	refused("subject team", `INSERT INTO node_grants(id, node_id, subject_type, subject_id, role, created_at) VALUES ('gnt_x','nod_g','team','x','viewer',1)`)
	refused("level owner", `INSERT INTO node_grants(id, node_id, subject_type, subject_id, role, created_at) VALUES ('gnt_x','nod_g','user','usr_m','owner',1)`)
	refused("duplicate subject", `INSERT INTO node_grants(id, node_id, subject_type, subject_id, role, created_at) VALUES ('gnt_x','nod_g','role',?1,'viewer',1)`, fin)

	// role_groups and the effective membership view.
	must(`INSERT INTO role_groups(role_id, group_id, member_role, added_at, added_by) VALUES
		(?1,'grp_1','manager',1,'usr_o'), (?2,'grp_1','member',1,NULL), (?3,'grp_2','member',1,NULL)`, fin, vis, spare)
	refused("member_role owner", `INSERT INTO role_groups(role_id, group_id, member_role, added_at) VALUES (?1,'grp_2','owner',1)`, fin)
	refused("built-in role in a group", `INSERT INTO role_groups(role_id, group_id, added_at) VALUES ('member','grp_2',1)`)
	if got := dump(t, d, `SELECT group_id, user_id, role, source, coalesce(via_role_id, '-') FROM effective_group_members
		ORDER BY group_id, user_id, source`); got != strings.Join([]string{
		"grp_1|usr_f|manager|role|" + fin, "grp_1|usr_g|member|role|" + vis, "grp_1|usr_m|member|direct|-"}, "\n") {
		t.Fatalf("effective_group_members:\n%s", got)
	}

	// An assigned role cannot be deleted; an unassigned one takes its grants
	// and group memberships along.
	refused("delete an assigned role", `DELETE FROM roles WHERE id = ?`, fin)
	must(`DELETE FROM roles WHERE id = ?`, spare)
	if got := dump(t, d, `SELECT count(*) FROM node_grants WHERE subject_id = ?`, spare); got != "0" {
		t.Errorf("grants of the deleted role: %s", got)
	}
	if got := dump(t, d, `SELECT count(*) FROM role_groups WHERE role_id = ?`, spare); got != "0" {
		t.Errorf("groups of the deleted role: %s", got)
	}
	// Used invitations keep the id of a deleted role (no foreign key).
	must(`UPDATE users SET role_id = NULL WHERE role_id = ?`, vis)
	must(`DELETE FROM roles WHERE id = ?`, vis)
	if got := dump(t, d, `SELECT role, role_id FROM invites WHERE id = 'inv_v'`); got != "guest|"+vis {
		t.Errorf("invite of a deleted role: %s", got)
	}
	// Deleting a group takes its role memberships; deleting the creator of a
	// role clears created_by.
	must(`DELETE FROM groups WHERE id = 'grp_1'`)
	if got := dump(t, d, `SELECT count(*) FROM role_groups WHERE group_id = 'grp_1'`); got != "0" {
		t.Errorf("role_groups of the deleted group: %s", got)
	}
	must(`DELETE FROM users WHERE id = 'usr_o'`)
	if got := dump(t, d, `SELECT coalesce(created_by, 'NULL') FROM roles WHERE id = ?`, fin); got != "NULL" {
		t.Errorf("created_by of a deleted user: %s", got)
	}
	checkIntegrity(t, d)

	// The view is read by user and by group through indexes: no table scan
	// (only the view's own result is scanned).
	for q, uses := range map[string][]string{
		`SELECT group_id, role FROM effective_group_members WHERE user_id = 'usr_m'`: {
			"INDEX group_members_user", "INDEX sqlite_autoindex_users_1", "rg USING PRIMARY KEY"},
		`SELECT user_id, role FROM effective_group_members WHERE group_id = 'grp_2'`: {
			"m USING PRIMARY KEY", "INDEX role_groups_group", "INDEX users_role_id"},
	} {
		plan := dump(t, d, `EXPLAIN QUERY PLAN `+q)
		for _, line := range strings.Split(plan, "\n") {
			if strings.Contains(line, "SCAN ") && !strings.Contains(line, "SCAN effective_group_members") {
				t.Errorf("%s scans a table:\n%s", q, plan)
				break
			}
		}
		for _, u := range uses {
			if !strings.Contains(plan, u) {
				t.Errorf("%s does not use %s:\n%s", q, u, plan)
			}
		}
	}
}
