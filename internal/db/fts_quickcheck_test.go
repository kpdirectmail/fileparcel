package db

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// ftsSchema is the nodes/nodes_fts part of 0001_init.sql (DESIGN §6): an
// external-content fts5 index kept in sync by triggers. (0004 moved the
// index to nodes.name_key; the structure, and so this test, is the same.)
const ftsSchema = `
CREATE TABLE nodes (rid INTEGER PRIMARY KEY, id TEXT NOT NULL UNIQUE, name TEXT NOT NULL);
CREATE VIRTUAL TABLE nodes_fts USING fts5(name, content='nodes', content_rowid='rid', tokenize='trigram');
CREATE TRIGGER nodes_fts_ai AFTER INSERT ON nodes BEGIN
  INSERT INTO nodes_fts(rowid, name) VALUES (new.rid, new.name); END;
CREATE TRIGGER nodes_fts_ad AFTER DELETE ON nodes BEGIN
  INSERT INTO nodes_fts(nodes_fts, rowid, name) VALUES ('delete', old.rid, old.name); END;
CREATE TRIGGER nodes_fts_au AFTER UPDATE OF name ON nodes BEGIN
  INSERT INTO nodes_fts(nodes_fts, rowid, name) VALUES ('delete', old.rid, old.name);
  INSERT INTO nodes_fts(rowid, name) VALUES (new.rid, new.name); END;
`

// ftsFixture builds a database with the nodes/nodes_fts schema, fills it, and
// churns the index the way a live server does (renames, purges, re-uploads)
// so fts5 merges and frees segments.
func ftsFixture(t *testing.T) *DB {
	t.Helper()
	path := filepath.Join(t.TempDir(), "fts.db")
	d, err := Open(path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { d.Close() })
	ctx := context.Background()
	if _, err := d.Writer().ExecContext(ctx, ftsSchema); err != nil {
		t.Fatalf("schema: %v", err)
	}
	for i := range 200 {
		if _, err := d.Exec(ctx, `INSERT INTO nodes(id, name) VALUES (?, ?)`,
			fmt.Sprint(i), fmt.Sprintf("document-%06d.txt", i)); err != nil {
			t.Fatalf("insert: %v", err)
		}
	}
	return d
}

func ftsChurn(t *testing.T, d *DB) {
	t.Helper()
	ctx := context.Background()
	for round := range 6 {
		for i := range 200 {
			if _, err := d.Exec(ctx, `UPDATE nodes SET name = ? WHERE id = ?`,
				fmt.Sprintf("renamed-%d-%06d.txt", round, i), fmt.Sprint(i)); err != nil {
				t.Fatalf("update: %v", err)
			}
		}
		if _, err := d.Exec(ctx, `DELETE FROM nodes WHERE rid % 3 = 0`); err != nil {
			t.Fatalf("delete: %v", err)
		}
		for i := range 200 {
			if _, err := d.Exec(ctx, `INSERT OR IGNORE INTO nodes(id, name) VALUES (?, ?)`,
				fmt.Sprintf("r%d-%d", round, i), fmt.Sprintf("document-%06d.txt", i)); err != nil {
				t.Fatalf("reinsert: %v", err)
			}
		}
	}
}

// TestIntegrityCheckAfterSearchAndChurn is the regression test for the
// "Database integrity — Damaged: fts5: corruption found reading blob N from
// table nodes_fts" that GET /admin/system/doctor reported on an intact
// database (and which told the admin to restore from backup).
//
// PRAGMA quick_check has called every virtual table's xIntegrity method since
// SQLite 3.44. fts5 answers it from the structure record cached on that
// connection, and that path performs no xBegin, so nothing refreshes the
// cache. A pooled reader that has served a /search request therefore keeps
// walking a structure the writer has since merged away, and reports the
// segment page it can no longer find as corruption. DB.IntegrityCheck runs on
// its own connection so it reports the file, not a stale cache.
func TestIntegrityCheckAfterSearchAndChurn(t *testing.T) {
	t.Parallel()
	d := ftsFixture(t)
	ctx := context.Background()

	// Pin one connection and warm its fts5 cache, exactly as GET /search does.
	conn, err := d.Reader().Conn(ctx)
	if err != nil {
		t.Fatalf("conn: %v", err)
	}
	defer conn.Close()
	var n int
	if err := conn.QueryRowContext(ctx,
		`SELECT count(*) FROM nodes_fts WHERE nodes_fts MATCH ?`, "document").Scan(&n); err != nil {
		t.Fatalf("search: %v", err)
	}
	if n != 200 {
		t.Fatalf("search found %d, want 200", n)
	}

	ftsChurn(t, d)

	// The file is intact: fts5's own check on the writer agrees.
	if _, err := d.Writer().ExecContext(ctx,
		`INSERT INTO nodes_fts(nodes_fts, rank) VALUES('integrity-check', 1)`); err != nil {
		t.Fatalf("fts5 integrity-check on the writer: %v", err)
	}

	// Record what the warmed connection says. Today it misreports — that is
	// the bug being worked around — but the contract below holds either way,
	// so this test keeps its meaning if SQLite ever fixes it upstream.
	if stale := pragmaRows(t, conn, "quick_check"); len(stale) > 0 {
		t.Logf("warmed pooled connection still misreports (the bug being worked around): %v", stale)
	} else {
		t.Log("warmed pooled connection is clean: fts5 may have been fixed upstream; " +
			"DB.IntegrityCheck's own connection remains the contract")
	}

	// What the doctor calls must be right regardless.
	problems, err := d.IntegrityCheck(ctx, false)
	if err != nil {
		t.Fatalf("IntegrityCheck: %v", err)
	}
	if len(problems) != 0 {
		t.Fatalf("IntegrityCheck reports corruption on an intact database: %v", strings.Join(problems, "; "))
	}
	full, err := d.IntegrityCheck(ctx, true)
	if err != nil {
		t.Fatalf("IntegrityCheck(full): %v", err)
	}
	if len(full) != 0 {
		t.Fatalf("IntegrityCheck(full) reports corruption on an intact database: %v", strings.Join(full, "; "))
	}
}

// TestIntegrityCheckRepeatedUnderChurn calls IntegrityCheck the way the
// doctor page does — repeatedly, while the server keeps writing — and
// requires every call to come back clean.
func TestIntegrityCheckRepeatedUnderChurn(t *testing.T) {
	t.Parallel()
	d := ftsFixture(t)
	ctx := context.Background()
	var n int
	if err := d.Reader().QueryRowContext(ctx,
		`SELECT count(*) FROM nodes_fts WHERE nodes_fts MATCH ?`, "document").Scan(&n); err != nil {
		t.Fatalf("search: %v", err)
	}
	for round := range 4 {
		ftsChurn(t, d)
		if err := d.Reader().QueryRowContext(ctx,
			`SELECT count(*) FROM nodes_fts WHERE nodes_fts MATCH ?`, "document").Scan(&n); err != nil {
			t.Fatalf("search round %d: %v", round, err)
		}
		problems, err := d.IntegrityCheck(ctx, false)
		if err != nil {
			t.Fatalf("IntegrityCheck round %d: %v", round, err)
		}
		if len(problems) != 0 {
			t.Fatalf("IntegrityCheck round %d reports corruption: %v", round, strings.Join(problems, "; "))
		}
	}
}

// TestIntegrityCheckDoesNotUseReaderPool: IntegrityCheck must not wait for a
// pooled reader, not even to detect a closed handle. With every reader held
// by the caller (a pool of one is what GOMAXPROCS=1 gives), it used to block
// until the context expired.
func TestIntegrityCheckDoesNotUseReaderPool(t *testing.T) {
	d := ftsFixture(t)
	d.Reader().SetMaxOpenConns(1)
	conn, err := d.Reader().Conn(context.Background())
	if err != nil {
		t.Fatalf("conn: %v", err)
	}
	defer conn.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	problems, err := d.IntegrityCheck(ctx, false)
	if err != nil {
		t.Fatalf("IntegrityCheck with the reader pool exhausted: %v", err)
	}
	if len(problems) != 0 {
		t.Fatalf("IntegrityCheck: %v", problems)
	}
}

// TestIntegrityCheckAfterClose: a closed handle is an error, and the file is
// not reopened (so not recreated) behind the caller's back.
func TestIntegrityCheckAfterClose(t *testing.T) {
	d := ftsFixture(t)
	if err := d.Close(); err != nil {
		t.Fatal(err)
	}
	for _, suffix := range []string{"", "-wal", "-shm"} {
		_ = os.Remove(d.Path() + suffix)
	}
	if _, err := d.IntegrityCheck(context.Background(), false); !errors.Is(err, ErrClosed) {
		t.Fatalf("IntegrityCheck on a closed handle: %v", err)
	}
	if _, err := os.Stat(d.Path()); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("IntegrityCheck recreated the closed database: %v", err)
	}
}

// TestSearchStaysCorrectAfterChurn pins the other half of the diagnosis: the
// stale cache never reached query results, only the integrity pragma. A
// pooled connection that searched before the churn must still see the current
// index afterwards.
func TestSearchStaysCorrectAfterChurn(t *testing.T) {
	t.Parallel()
	d := ftsFixture(t)
	ctx := context.Background()
	conn, err := d.Reader().Conn(ctx)
	if err != nil {
		t.Fatalf("conn: %v", err)
	}
	defer conn.Close()
	var n int
	if err := conn.QueryRowContext(ctx,
		`SELECT count(*) FROM nodes_fts WHERE nodes_fts MATCH ?`, "document").Scan(&n); err != nil {
		t.Fatalf("search: %v", err)
	}
	ftsChurn(t, d)

	// The index and the content table must agree, seen from the warmed connection.
	var viaIndex, viaTable int
	if err := conn.QueryRowContext(ctx,
		`SELECT count(*) FROM nodes_fts WHERE nodes_fts MATCH ?`, "renamed").Scan(&viaIndex); err != nil {
		t.Fatalf("search after churn: %v", err)
	}
	if err := conn.QueryRowContext(ctx,
		`SELECT count(*) FROM nodes WHERE name LIKE 'renamed%'`).Scan(&viaTable); err != nil {
		t.Fatalf("count: %v", err)
	}
	if viaIndex != viaTable {
		t.Fatalf("fts5 index and nodes disagree after churn: MATCH %d, LIKE %d", viaIndex, viaTable)
	}
	if viaTable == 0 {
		t.Fatal("fixture churned nothing")
	}
}

// pragmaRows runs a pragma on one connection and returns the rows that are
// not "ok".
func pragmaRows(t *testing.T, conn *sql.Conn, pragma string) []string {
	t.Helper()
	rows, err := conn.QueryContext(context.Background(), "PRAGMA "+pragma)
	if err != nil {
		t.Fatalf("%s: %v", pragma, err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var m string
		if err := rows.Scan(&m); err != nil {
			t.Fatalf("scan: %v", err)
		}
		if m != "ok" {
			out = append(out, m)
		}
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("rows: %v", err)
	}
	return out
}
