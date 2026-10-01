package db

import (
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"sort"
	"sync"
	"testing"
	"time"
)

func openTest(t *testing.T) *DB {
	t.Helper()
	d, err := Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.Close() })
	if _, err := d.Migrate(context.Background()); err != nil {
		t.Fatal(err)
	}
	return d
}

func TestPragmas(t *testing.T) {
	d := openTest(t)
	ctx := context.Background()
	check := func(pool *sql.DB, pragma string, want int64) {
		t.Helper()
		var got int64
		if err := pool.QueryRowContext(ctx, "PRAGMA "+pragma).Scan(&got); err != nil {
			t.Fatalf("%s: %v", pragma, err)
		}
		if got != want {
			t.Errorf("%s = %d, want %d", pragma, got, want)
		}
	}
	for _, pool := range []*sql.DB{d.Writer(), d.Reader()} {
		check(pool, "foreign_keys", 1)
		check(pool, "busy_timeout", 10000)
		check(pool, "synchronous", 1) // NORMAL
		check(pool, "temp_store", 2)  // MEMORY
		check(pool, "cache_size", -65536)
		check(pool, "wal_autocheckpoint", 1000)
	}
	check(d.Reader(), "query_only", 1)
	check(d.Writer(), "query_only", 0)
	// A transaction lowers busy_timeout on the connection it holds and must
	// put it back, or the statements that need the long wait
	// (wal_checkpoint(TRUNCATE), VACUUM) would silently get 250 ms.
	if err := d.Tx(ctx, func(tx *sql.Tx) error { return nil }); err != nil {
		t.Fatal(err)
	}
	check(d.Writer(), "busy_timeout", 10000)
	var mode string
	if err := d.Reader().QueryRow("PRAGMA journal_mode").Scan(&mode); err != nil || mode != "wal" {
		t.Fatalf("journal_mode = %q, %v", mode, err)
	}
	if st := d.Writer().Stats(); st.MaxOpenConnections != 1 {
		t.Errorf("writer max conns = %d", st.MaxOpenConnections)
	}
}

func TestMigrateIdempotentAndTooNew(t *testing.T) {
	d := openTest(t)
	ctx := context.Background()
	v, err := d.SchemaVersion(ctx)
	if err != nil || v != LatestVersion() || v < 4 {
		t.Fatalf("version %d err %v latest %d", v, err, LatestVersion())
	}
	applied, err := d.Migrate(ctx)
	if err != nil || len(applied) != 0 {
		t.Fatalf("second migrate: %v %v", applied, err)
	}
	// Every table of DESIGN §6 exists.
	want := []string{"api_tokens", "archive_tickets", "audit_log", "backups", "blobs", "client_certs",
		"file_versions", "group_members", "groups", "invites", "jobs", "keyring", "meta", "node_grants",
		"nodes", "nodes_fts", "recovery_codes", "role_groups", "roles", "schedules", "sessions", "settings",
		"share_access_log", "shares", "spaces", "stars", "totp_secrets", "upload_batches", "upload_files",
		"upload_parts", "users", "webauthn_credentials"}
	for _, name := range want {
		var n int
		if err := d.QueryRow(ctx, `SELECT count(*) FROM sqlite_master WHERE name=?`, name).Scan(&n); err != nil || n != 1 {
			t.Errorf("table %s missing (%v)", name, err)
		}
	}
	if _, err := d.Exec(ctx, `INSERT INTO schema_migrations(version,name,applied_at) VALUES (9999,'future',0)`); err != nil {
		t.Fatal(err)
	}
	if _, err := d.Migrate(ctx); !errors.Is(err, ErrSchemaTooNew) {
		t.Fatalf("want ErrSchemaTooNew, got %v", err)
	}
}

// seed inserts a user, a space and a root folder; returns space id and root node id.
func seed(t *testing.T, d *DB) (string, string) {
	t.Helper()
	ctx := context.Background()
	now := Ms(time.Now())
	err := d.Tx(ctx, func(tx *sql.Tx) error {
		if _, err := tx.Exec(`INSERT INTO users(id, username, role, webauthn_handle, created_at, updated_at)
			VALUES ('usr_1','alice','owner',X'01',?,?)`, now, now); err != nil {
			return err
		}
		if _, err := tx.Exec(`INSERT INTO spaces(id, kind, owner_user_id, name, created_at) VALUES ('spc_1','user','usr_1','My files',?)`, now); err != nil {
			return err
		}
		_, err := tx.Exec(`INSERT INTO nodes(id, space_id, parent_id, kind, name, name_key, created_at, updated_at)
			VALUES ('nod_root','spc_1',NULL,'folder','','',?,?)`, now, now)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	return "spc_1", "nod_root"
}

func addNode(t *testing.T, d *DB, id, parent, name string) {
	t.Helper()
	now := Ms(time.Now())
	_, err := d.Exec(context.Background(), `INSERT INTO nodes(id, space_id, parent_id, kind, name, name_key, created_at, updated_at)
		VALUES (?, 'spc_1', ?, 'file', ?, lower(?), ?, ?)`, id, parent, name, name, now, now)
	if err != nil {
		t.Fatal(err)
	}
}

func search(t *testing.T, d *DB, q string) []string {
	t.Helper()
	rows, err := d.Query(context.Background(),
		`SELECT n.id FROM nodes_fts f JOIN nodes n ON n.rid = f.rowid WHERE nodes_fts MATCH ? ORDER BY n.id`, `"`+q+`"`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			t.Fatal(err)
		}
		out = append(out, id)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return out
}

func TestFTSTrigram(t *testing.T) {
	d := openTest(t)
	ctx := context.Background()
	_, root := seed(t, d)
	addNode(t, d, "nod_a", root, "Holiday Photos 2024.zip")
	addNode(t, d, "nod_b", root, "invoice-photographer.pdf")
	addNode(t, d, "nod_c", root, "Résumé final.docx")

	eq := func(got []string, want ...string) {
		t.Helper()
		sort.Strings(got)
		if len(got) != len(want) {
			t.Fatalf("got %v want %v", got, want)
		}
		for i := range got {
			if got[i] != want[i] {
				t.Fatalf("got %v want %v", got, want)
			}
		}
	}
	eq(search(t, d, "photo"), "nod_a", "nod_b") // substring, case-insensitive
	eq(search(t, d, "PHOTOS"), "nod_a")
	eq(search(t, d, "sumé"), "nod_c") // unicode substring
	eq(search(t, d, "2024.z"), "nod_a")
	eq(search(t, d, "nomatch"))

	// update trigger (the index covers name_key, which every rename sets)
	if _, err := d.Exec(ctx, `UPDATE nodes SET name='Holiday Videos.zip', name_key='holiday videos.zip' WHERE id='nod_a'`); err != nil {
		t.Fatal(err)
	}
	eq(search(t, d, "photo"), "nod_b")
	eq(search(t, d, "videos"), "nod_a")
	// delete trigger
	if _, err := d.Exec(ctx, `DELETE FROM nodes WHERE id='nod_b'`); err != nil {
		t.Fatal(err)
	}
	eq(search(t, d, "photo"))
	// integrity of the external-content index
	if _, err := d.Exec(ctx, `INSERT INTO nodes_fts(nodes_fts, rank) VALUES('integrity-check', 1)`); err != nil {
		t.Fatalf("fts integrity: %v", err)
	}
}

func TestConstraintHelpers(t *testing.T) {
	d := openTest(t)
	ctx := context.Background()
	_, root := seed(t, d)
	addNode(t, d, "nod_x", root, "a.txt")
	now := Ms(time.Now())
	// same name_key under the same parent -> UNIQUE (nodes_live_name)
	_, err := d.Exec(ctx, `INSERT INTO nodes(id, space_id, parent_id, kind, name, name_key, created_at, updated_at)
		VALUES ('nod_y','spc_1',?,'file','A.TXT','a.txt',?,?)`, root, now, now)
	if !IsUnique(err) || IsForeignKey(err) || !IsConstraint(err) {
		t.Fatalf("want unique violation, got %v", err)
	}
	// unknown parent -> FOREIGN KEY
	_, err = d.Exec(ctx, `INSERT INTO nodes(id, space_id, parent_id, kind, name, name_key, created_at, updated_at)
		VALUES ('nod_z','spc_1','nod_missing','file','b','b',?,?)`, now, now)
	if !IsForeignKey(err) || IsUnique(err) {
		t.Fatalf("want fk violation, got %v", err)
	}
	// duplicate primary key
	_, err = d.Exec(ctx, `INSERT INTO meta(key,value) VALUES('k','1')`)
	if err != nil {
		t.Fatal(err)
	}
	_, err = d.Exec(ctx, `INSERT INTO meta(key,value) VALUES('k','2')`)
	if !IsUnique(err) {
		t.Fatalf("want pk violation, got %v", err)
	}
	if IsUnique(errors.New("UNIQUE constraint failed")) {
		t.Fatal("plain errors must not match")
	}
}

func TestReaderIsQueryOnly(t *testing.T) {
	d := openTest(t)
	if _, err := d.Reader().Exec(`INSERT INTO meta(key,value) VALUES('x','y')`); err == nil {
		t.Fatal("reader pool accepted a write")
	}
}

func TestTxRollbackAndRead(t *testing.T) {
	d := openTest(t)
	ctx := context.Background()
	sentinel := errors.New("boom")
	err := d.Tx(ctx, func(tx *sql.Tx) error {
		if _, err := tx.Exec(`INSERT INTO meta(key,value) VALUES('a','1')`); err != nil {
			return err
		}
		return sentinel
	})
	if !errors.Is(err, sentinel) {
		t.Fatalf("got %v", err)
	}
	var n int
	if err := d.QueryRow(ctx, `SELECT count(*) FROM meta`).Scan(&n); err != nil || n != 0 {
		t.Fatalf("rolled back row visible: %d %v", n, err)
	}
	if err := d.Tx(ctx, func(tx *sql.Tx) error {
		_, err := tx.Exec(`INSERT INTO meta(key,value) VALUES('a','1')`)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	err = d.Read(ctx, func(tx *sql.Tx) error {
		return tx.QueryRow(`SELECT count(*) FROM meta`).Scan(&n)
	})
	if err != nil || n != 1 {
		t.Fatalf("read: %d %v", n, err)
	}
}

// Readers are not blocked by an open write transaction (WAL) and see the last
// committed snapshot; concurrent writers are serialized on the single conn.
func TestConcurrentReadersAndWriter(t *testing.T) {
	d := openTest(t)
	ctx := context.Background()
	inTx := make(chan struct{})
	release := make(chan struct{})
	done := make(chan error, 1)
	go func() {
		done <- d.Tx(ctx, func(tx *sql.Tx) error {
			if _, err := tx.Exec(`INSERT INTO meta(key,value) VALUES('w','1')`); err != nil {
				return err
			}
			close(inTx)
			<-release
			return nil
		})
	}()
	<-inTx
	var n int
	if err := d.QueryRow(ctx, `SELECT count(*) FROM meta WHERE key='w'`).Scan(&n); err != nil || n != 0 {
		t.Fatalf("reader during write tx: n=%d err=%v", n, err)
	}
	close(release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if err := d.QueryRow(ctx, `SELECT count(*) FROM meta WHERE key='w'`).Scan(&n); err != nil || n != 1 {
		t.Fatalf("after commit n=%d err=%v", n, err)
	}

	var wg sync.WaitGroup
	for i := range 20 {
		wg.Go(func() {
			if _, err := d.Exec(ctx, `INSERT INTO meta(key,value) VALUES(?, 'v')`, "k"+string(rune('a'+i))); err != nil {
				t.Error(err)
			}
			var c int
			if err := d.QueryRow(ctx, `SELECT count(*) FROM meta`).Scan(&c); err != nil {
				t.Error(err)
			}
		})
	}
	wg.Wait()
	if err := d.QueryRow(ctx, `SELECT count(*) FROM meta`).Scan(&n); err != nil || n != 21 {
		t.Fatalf("count=%d err=%v", n, err)
	}
}

func TestTimeHelpers(t *testing.T) {
	now := time.Date(2026, 9, 19, 10, 0, 0, 123_456_789, time.FixedZone("x", 3600))
	ms := Ms(now)
	back := FromMs(ms)
	if !back.Equal(now.Truncate(time.Millisecond)) || back.Location() != time.UTC {
		t.Fatalf("roundtrip %v -> %v", now, back)
	}
	if Ms(time.Time{}) != 0 || !FromMs(0).IsZero() {
		t.Fatal("zero handling")
	}
	if NullMs(nil).Valid || NullTime(time.Time{}).Valid {
		t.Fatal("null handling")
	}
	n := NullMs(&now)
	if p := FromNullMs(n); p == nil || !p.Equal(back) {
		t.Fatal("FromNullMs")
	}
	if FromNullMs(sql.NullInt64{}) != nil {
		t.Fatal("FromNullMs(NULL)")
	}
}

// A write blocked by another process must not hold the single writer
// connection past the caller's deadline: SQLite's busy wait ignores the
// context, so Tx keeps the driver-side wait short and does the waiting
// itself. It must also report the busy error, not only the context error.
func TestTxBusyHonoursContext(t *testing.T) {
	d := openTest(t)
	ctx := context.Background()
	if _, err := d.Exec(ctx, `CREATE TABLE busy_t(a INTEGER)`); err != nil {
		t.Fatal(err)
	}
	// A second handle on the same file, holding a write transaction.
	other, err := Open(d.Path())
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	otx, err := other.Writer().BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := otx.Exec(`INSERT INTO busy_t VALUES (1)`); err != nil {
		t.Fatal(err)
	}

	tctx, cancel := context.WithTimeout(ctx, 500*time.Millisecond)
	defer cancel()
	start := time.Now()
	err = d.Tx(tctx, func(tx *sql.Tx) error {
		_, e := tx.ExecContext(tctx, `INSERT INTO busy_t VALUES (2)`)
		return e
	})
	elapsed := time.Since(start)
	if err == nil {
		t.Fatal("write succeeded while another process held the lock")
	}
	if elapsed > 3*time.Second {
		t.Errorf("held the writer %v past a 500ms deadline", elapsed)
	}
	if !IsBusy(err) {
		t.Errorf("busy error masked: %v", err)
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("context cause lost: %v", err)
	}
	// The writer must be usable again at once, not after the old 10s wait.
	if err := otx.Rollback(); err != nil {
		t.Fatal(err)
	}
	start = time.Now()
	if _, err := d.Exec(ctx, `INSERT INTO busy_t VALUES (3)`); err != nil {
		t.Fatal(err)
	}
	if d := time.Since(start); d > time.Second {
		t.Errorf("writer still blocked: next write took %v", d)
	}
}
