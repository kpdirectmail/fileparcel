package db

import (
	"context"
	"database/sql"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"testing/fstest"
	"time"
)

// v4 migration numbering (DESIGN §6 "Migration numbering"): 0002_roles,
// 0003_zip_password and 0004_fts_name_key; versions are 1..N without gaps and
// Migrate applies every version not recorded in schema_migrations.

func TestMigrationsContiguous(t *testing.T) {
	ms, err := Migrations()
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for i, m := range ms {
		if m.Version != i+1 {
			t.Fatalf("migration %d has version %d", i, m.Version)
		}
		got = append(got, m.Name)
	}
	if want := []string{"init", "roles", "zip_password", "fts_name_key"}; !slices.Equal(got, want) {
		t.Fatalf("embedded migrations %v, want %v", got, want)
	}
	if LatestVersion() != 4 {
		t.Fatalf("LatestVersion %d", LatestVersion())
	}
	sql := func(s string) *fstest.MapFile { return &fstest.MapFile{Data: []byte(s)} }
	for _, c := range []struct {
		files map[string]string
		err   string
	}{
		{map[string]string{"0001_a.sql": "", "0003_c.sql": ""}, "db: missing migration 0002 (migrations must be numbered without gaps)"},
		{map[string]string{"0002_b.sql": ""}, "db: missing migration 0001 (migrations must be numbered without gaps)"},
		{map[string]string{"0001_a.sql": "", "0002_b.sql": "", "0004_d.sql": ""}, "db: missing migration 0003 (migrations must be numbered without gaps)"},
		{map[string]string{"0001_a.sql": "", "0002_b.sql": ""}, ""},
		{map[string]string{"0001_a.sql": "", "01_b.sql": ""}, `db: bad migration file name "01_b.sql" (want NNNN_name.sql)`},
	} {
		fsys := fstest.MapFS{}
		for name, body := range c.files {
			fsys["migrations/"+name] = sql(body)
		}
		ms, err := migrationsFrom(fsys)
		switch {
		case c.err == "" && err != nil:
			t.Errorf("%v: %v", c.files, err)
		case c.err == "" && len(ms) != len(c.files):
			t.Errorf("%v: %d migrations", c.files, len(ms))
		case c.err != "" && (err == nil || err.Error() != c.err):
			t.Errorf("%v: error %v, want %q", c.files, err, c.err)
		}
	}
	// The renamed FTS migration keeps its SQL and names itself in its header.
	if first, _, _ := strings.Cut(ms[3].SQL, "\n"); !strings.HasPrefix(first, "-- 0004_fts_name_key: ") {
		t.Errorf("0004 header %q", first)
	}
	if first, _, _ := strings.Cut(ms[1].SQL, "\n"); !strings.HasPrefix(first, "-- 0002_roles: ") {
		t.Errorf("0002 header %q", first)
	}
	if first, _, _ := strings.Cut(ms[2].SQL, "\n"); !strings.HasPrefix(first, "-- 0003_zip_password.sql: ") {
		t.Errorf("0003 header %q", first)
	}
}

func TestMigrateFresh(t *testing.T) {
	ctx := context.Background()
	d := openRaw(t)
	applied, err := d.Migrate(ctx)
	if err != nil || !slices.Equal(applied, []int{1, 2, 3, 4}) {
		t.Fatalf("migrate: %v %v", applied, err)
	}
	if got := recorded(t, d); got != "1 init, 2 roles, 3 zip_password, 4 fts_name_key" {
		t.Fatalf("schema_migrations: %s", got)
	}
	for _, obj := range []struct{ typ, name string }{
		{"table", "roles"}, {"table", "role_groups"}, {"view", "effective_group_members"},
		{"index", "users_role_id"}, {"index", "invites_role_id"}, {"index", "role_groups_group"},
		{"index", "grants_subject"}, {"trigger", "roles_identity_fixed"}, {"trigger", "users_role_id_ins"},
		{"trigger", "users_role_id_upd"}, {"trigger", "invites_role_id_ins"}, {"trigger", "invites_role_id_upd"},
		{"trigger", "roles_delete_grants"}, {"trigger", "nodes_fts_au"},
	} {
		var n int
		if err := d.QueryRow(ctx, `SELECT count(*) FROM sqlite_master WHERE type = ? AND name = ?`, obj.typ, obj.name).Scan(&n); err != nil || n != 1 {
			t.Errorf("%s %s missing (%v)", obj.typ, obj.name, err)
		}
	}
	for table, cols := range map[string][]string{
		"users":          {"role_id"},
		"invites":        {"role_id"},
		"upload_batches": {"zip_encryption", "zip_password_enc"},
		"file_versions":  {"zip_encryption"},
		"node_grants":    {"id", "node_id", "subject_type", "subject_id", "role", "created_by", "created_at", "expires_at"},
	} {
		have := columns(t, d, table)
		for _, c := range cols {
			if !slices.Contains(have, c) {
				t.Errorf("%s.%s missing (%v)", table, c, have)
			}
		}
	}
	checkIntegrity(t, d)
	if applied, err := d.Migrate(ctx); err != nil || len(applied) != 0 {
		t.Fatalf("second migrate: %v %v", applied, err)
	}
	if v, err := d.SchemaVersion(ctx); err != nil || v != 4 {
		t.Fatalf("schema version %d %v", v, err)
	}
}

// A recorded version whose name differs from the binary's is refused before
// anything runs: the database was migrated by a build that numbered its
// migrations differently.
func TestMigrateNameMismatch(t *testing.T) {
	ctx := context.Background()
	d := v1DB(t)
	if _, err := d.Exec(ctx, `INSERT INTO schema_migrations(version, name, applied_at) VALUES (2, 'fts_name_key', 0)`); err != nil {
		t.Fatal(err)
	}
	applied, err := d.Migrate(ctx)
	want := `db: migration 0002 is "fts_name_key" in the database but "roles" in this binary`
	if err == nil || err.Error() != want || len(applied) != 0 {
		t.Fatalf("migrate: %v %v, want %q", applied, err, want)
	}
	var n int
	if err := d.QueryRow(ctx, `SELECT count(*) FROM sqlite_master WHERE name = 'roles'`).Scan(&n); err != nil || n != 0 {
		t.Fatalf("0002 ran anyway (%d, %v)", n, err)
	}
	// The same check on a later version: 1..3 applied, 4 recorded as something else.
	d = openRaw(t)
	ms, err := Migrations()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := d.migrate(ctx, ms[:3]); err != nil {
		t.Fatal(err)
	}
	if _, err := d.Exec(ctx, `INSERT INTO schema_migrations(version, name, applied_at) VALUES (4, 'share_notes', 0)`); err != nil {
		t.Fatal(err)
	}
	if _, err := d.Migrate(ctx); err == nil || !strings.Contains(err.Error(), `migration 0004 is "share_notes" in the database but "fts_name_key"`) {
		t.Fatalf("version 4 mismatch: %v", err)
	}
	// A mismatch above unapplied versions: nothing runs, not even the
	// versions below it (the check comes before the first migration).
	d = v1DB(t)
	if _, err := d.Exec(ctx, `INSERT INTO schema_migrations(version, name, applied_at) VALUES (4, 'share_notes', 0)`); err != nil {
		t.Fatal(err)
	}
	if applied, err := d.Migrate(ctx); err == nil || len(applied) != 0 {
		t.Fatalf("mismatch at 4 on a v1 database: %v %v", applied, err)
	}
	if got := recorded(t, d); got != "1 init, 4 share_notes" {
		t.Fatalf("schema_migrations after a refused migrate: %s", got)
	}
	if err := d.QueryRow(ctx, `SELECT count(*) FROM sqlite_master WHERE name IN ('roles', 'role_groups')`).Scan(&n); err != nil || n != 0 {
		t.Fatalf("0002 ran before the name check (%d, %v)", n, err)
	}
}

// Set-based apply: a migration numbered below an applied one still runs,
// and a recorded row without a name counts as applied.
func TestMigrateSetBased(t *testing.T) {
	ctx := context.Background()
	d := v1DB(t)
	ms, err := Migrations()
	if err != nil {
		t.Fatal(err)
	}
	// 0004 applied (and recorded) before 0002 and 0003.
	if err := d.Tx(ctx, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, ms[3].SQL); err != nil {
			return err
		}
		_, err := tx.ExecContext(ctx, `INSERT INTO schema_migrations(version, name, applied_at) VALUES (4, 'fts_name_key', 0)`)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	applied, err := d.Migrate(ctx)
	if err != nil || !slices.Equal(applied, []int{2, 3}) {
		t.Fatalf("migrate: %v %v", applied, err)
	}
	if got := recorded(t, d); got != "1 init, 2 roles, 3 zip_password, 4 fts_name_key" {
		t.Fatalf("schema_migrations: %s", got)
	}
	checkIntegrity(t, d)

	// 0002 recorded without a name: applied.
	d = v1DB(t)
	if err := d.Tx(ctx, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, ms[1].SQL); err != nil {
			return err
		}
		_, err := tx.ExecContext(ctx, `INSERT INTO schema_migrations(version, name, applied_at) VALUES (2, NULL, 0)`)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if applied, err := d.Migrate(ctx); err != nil || !slices.Equal(applied, []int{3, 4}) {
		t.Fatalf("migrate with an unnamed row: %v %v", applied, err)
	}
}

// A version-1 (v3) database with data in every table the new migrations
// touch migrates to 4 without losing or changing a row.
func TestMigrateFromV1(t *testing.T) {
	ctx := context.Background()
	d := v1DB(t)
	now := Ms(time.Now())
	exp := now + int64(time.Hour/time.Millisecond)
	seedSQL := []string{
		`INSERT INTO users(id, username, role, webauthn_handle, created_at, updated_at) VALUES
			('usr_o','olivia','owner',X'01',?1,?1), ('usr_a','adam','admin',X'02',?1,?1),
			('usr_m','mia','member',X'03',?1,?1), ('usr_g','gus','guest',X'04',?1,?1)`,
		`INSERT INTO sessions(id, token_hash, user_id, auth_level, csrf_secret, created_at, last_seen_at, idle_expires_at, expires_at)
			VALUES ('ses_1', X'aa', 'usr_m', 2, X'bb', ?1, ?1, ?1, ?1)`,
		`INSERT INTO api_tokens(id, user_id, name, token_hash, scopes, created_at) VALUES ('tok_1','usr_a','cli',X'cc','["admin"]',?1)`,
		`INSERT INTO groups(id, name, created_at, created_by) VALUES ('grp_1','Design',?1,'usr_a')`,
		`INSERT INTO group_members(group_id, user_id, role, added_at) VALUES ('grp_1','usr_m','manager',?1)`,
		`INSERT INTO invites(id, token_hash, token_enc, role, created_by, created_at, expires_at) VALUES ('inv_1',X'dd','v1:x','admin','usr_o',?1,?1)`,
		`INSERT INTO spaces(id, kind, owner_user_id, name, created_at) VALUES ('spc_u','user','usr_m','My files',?1)`,
		`INSERT INTO spaces(id, kind, group_id, name, created_at) VALUES ('spc_g','group','grp_1','Design',?1)`,
		`INSERT INTO nodes(id, space_id, parent_id, kind, name, name_key, created_at, updated_at) VALUES
			('nod_ur','spc_u',NULL,'folder','','',?1,?1), ('nod_gr','spc_g',NULL,'folder','','',?1,?1),
			('nod_f','spc_u','nod_ur','file','Straße.txt','strasse.txt',?1,?1)`,
		`INSERT INTO keyring(id, purpose, mk_id, wrapped, state, created_at) VALUES ('kek_1','blob','mk_1',X'00','active',?1)`,
		`INSERT INTO blobs(id, state, size, cipher, kek_id, wrapped_dek, created_at) VALUES ('b1','ready',5,1,'kek_1',X'00',?1)`,
		`INSERT INTO file_versions(id, node_id, blob_id, size, created_at, created_by) VALUES ('ver_1','nod_f','b1',5,?1,'usr_m')`,
		`INSERT INTO node_grants(id, node_id, subject_type, subject_id, role, created_by, created_at, expires_at) VALUES
			('gnt_u','nod_f','user','usr_g','viewer','usr_m',?1,NULL), ('gnt_g','nod_ur','group','grp_1','editor','usr_m',?1,?2)`,
		`INSERT INTO upload_batches(id, user_id, folder_id, mode, zip_name, conflict, state, created_at, updated_at, expires_at)
			VALUES ('upb_1','usr_m','nod_ur','zip','Trip','rename','open',?1,?1,?1)`,
	}
	for _, q := range seedSQL {
		if _, err := d.Exec(ctx, q, now, exp); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}
	tables := []string{"users", "sessions", "api_tokens", "groups", "group_members", "invites", "spaces", "nodes",
		"blobs", "file_versions", "node_grants", "upload_batches"}
	before := map[string]int{}
	for _, tb := range tables {
		before[tb] = countRows(t, d, tb)
	}
	grantsBefore := dump(t, d, `SELECT id, node_id, subject_type, subject_id, role, created_by, created_at, coalesce(expires_at, 0) FROM node_grants ORDER BY id`)

	applied, err := d.Migrate(ctx)
	if err != nil || !slices.Equal(applied, []int{2, 3, 4}) {
		t.Fatalf("migrate: %v %v", applied, err)
	}
	for _, tb := range tables {
		if n := countRows(t, d, tb); n != before[tb] {
			t.Errorf("%s: %d rows, was %d", tb, n, before[tb])
		}
	}
	if got := dump(t, d, `SELECT id, node_id, subject_type, subject_id, role, created_by, created_at, coalesce(expires_at, 0) FROM node_grants ORDER BY id`); got != grantsBefore {
		t.Errorf("grants changed:\n%s\nwas\n%s", got, grantsBefore)
	}
	// New columns read NULL (built-in roles, unprotected batches and versions).
	if got := dump(t, d, `SELECT count(*) FROM users WHERE role_id IS NULL`); got != "4" {
		t.Errorf("users.role_id: %s", got)
	}
	if got := dump(t, d, `SELECT count(*) FROM invites WHERE role_id IS NULL`); got != "1" {
		t.Errorf("invites.role_id: %s", got)
	}
	if got := dump(t, d, `SELECT count(*) FROM upload_batches WHERE zip_encryption IS NULL AND zip_password_enc IS NULL`); got != "1" {
		t.Errorf("upload_batches: %s", got)
	}
	if got := dump(t, d, `SELECT count(*) FROM file_versions WHERE zip_encryption IS NULL`); got != "1" {
		t.Errorf("file_versions: %s", got)
	}
	// The view returns the direct membership.
	if got := dump(t, d, `SELECT group_id, user_id, role, source, coalesce(via_role_id, '-') FROM effective_group_members`); got != "grp_1|usr_m|manager|direct|-" {
		t.Errorf("effective_group_members: %s", got)
	}
	// The rebuilt node_grants takes the new subject and level, and still refuses others.
	if _, err := d.Exec(ctx, `INSERT INTO roles(id, name, base, created_at, updated_at) VALUES ('rol_0123456789abcdefghjkmnpqrs','Finance','member',?1,?1)`, now); err != nil {
		t.Fatal(err)
	}
	if _, err := d.Exec(ctx, `INSERT INTO node_grants(id, node_id, subject_type, subject_id, role, created_at)
		VALUES ('gnt_r','nod_gr','role','rol_0123456789abcdefghjkmnpqrs','manager',?1)`, now); err != nil {
		t.Fatalf("role/manager grant: %v", err)
	}
	for _, bad := range []string{`('gnt_x','nod_gr','team','x','viewer',?1)`, `('gnt_y','nod_gr','user','usr_m','owner',?1)`} {
		if _, err := d.Exec(ctx, `INSERT INTO node_grants(id, node_id, subject_type, subject_id, role, created_at) VALUES `+bad, now); err == nil {
			t.Errorf("node_grants accepted %s", bad)
		}
	}
	if _, err := d.Exec(ctx, `UPDATE upload_batches SET zip_encryption = 'bogus'`); err == nil {
		t.Error("upload_batches.zip_encryption accepted 'bogus'")
	}
	// Search still answers on name_key (0004 rebuilt the index over the old rows).
	if got := search(t, d, "STRASSE"); !slices.Equal(got, []string{"nod_f"}) {
		t.Errorf("search after the migration: %v", got)
	}
	checkIntegrity(t, d)
}

// ---------- helpers ----------

// openRaw opens an empty database without migrating it.
func openRaw(t *testing.T) *DB {
	t.Helper()
	d, err := Open(filepath.Join(t.TempDir(), "raw.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.Close() })
	return d
}

// v1DB returns a database at version 1 (0001_init applied and recorded).
func v1DB(t *testing.T) *DB {
	t.Helper()
	d := openRaw(t)
	ms, err := Migrations()
	if err != nil {
		t.Fatal(err)
	}
	if applied, err := d.migrate(context.Background(), ms[:1]); err != nil || !slices.Equal(applied, []int{1}) {
		t.Fatalf("v1: %v %v", applied, err)
	}
	return d
}

func recorded(t *testing.T, d *DB) string {
	t.Helper()
	return strings.ReplaceAll(dump(t, d, `SELECT version || ' ' || coalesce(name, '') FROM schema_migrations ORDER BY version`), "\n", ", ")
}

func columns(t *testing.T, d *DB, table string) []string {
	t.Helper()
	return strings.Split(dump(t, d, `SELECT name FROM pragma_table_info(?)`, table), "\n")
}

func countRows(t *testing.T, d *DB, table string) int {
	t.Helper()
	var n int
	if err := d.QueryRow(context.Background(), `SELECT count(*) FROM `+table).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

// dump renders the rows of q as lines of "|"-joined columns.
func dump(t *testing.T, d *DB, q string, args ...any) string {
	t.Helper()
	rows, err := d.Query(context.Background(), q, args...)
	if err != nil {
		t.Fatalf("%s: %v", q, err)
	}
	defer rows.Close()
	cols, _ := rows.Columns()
	var lines []string
	for rows.Next() {
		vals := make([]sql.NullString, len(cols))
		ptrs := make([]any, len(cols))
		for i := range vals {
			ptrs[i] = &vals[i]
		}
		if err := rows.Scan(ptrs...); err != nil {
			t.Fatal(err)
		}
		parts := make([]string, len(vals))
		for i, v := range vals {
			parts[i] = v.String
		}
		lines = append(lines, strings.Join(parts, "|"))
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return strings.Join(lines, "\n")
}

func checkIntegrity(t *testing.T, d *DB) {
	t.Helper()
	if got := dump(t, d, `PRAGMA foreign_key_check`); got != "" {
		t.Errorf("foreign_key_check: %s", got)
	}
	if got := dump(t, d, `PRAGMA integrity_check`); got != "ok" {
		t.Errorf("integrity_check: %s", got)
	}
	if _, err := d.Exec(context.Background(), `INSERT INTO nodes_fts(nodes_fts, rank) VALUES('integrity-check', 1)`); err != nil {
		t.Errorf("fts integrity: %v", err)
	}
}
