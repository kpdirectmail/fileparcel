package cli

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"encoding/json"
	"errors"
	"io"
	"slices"
	"strings"
	"testing"

	"fileparcel/internal/db"
)

// `db check` must fail (exit 1) on a real foreign key violation and pass on a
// clean database.
func TestDBCheckForeignKeyViolations(t *testing.T) {
	h := testHome(t)
	ctx := context.Background()
	d, err := db.Open(h.DB())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := d.Migrate(ctx); err != nil {
		d.Close()
		t.Fatal(err)
	}
	d.Close()

	res := runArgs(t, "", "--home", h.Dir(), "db", "check")
	if res.code != 0 || !strings.Contains(res.stdout, "foreign keys: 0 violations") {
		t.Fatalf("clean database: code=%d stdout=%q stderr=%q", res.code, res.stdout, res.stderr)
	}

	// A child row whose parent is missing (inserted with the constraint off,
	// the way a damaged or hand-edited database looks).
	if d, err = db.Open(h.DB()); err != nil {
		t.Fatal(err)
	}
	for _, q := range []string{
		`PRAGMA foreign_keys=OFF`,
		`CREATE TABLE fk_probe (id TEXT PRIMARY KEY, user_id TEXT NOT NULL REFERENCES users(id))`,
		`INSERT INTO fk_probe VALUES ('p1','usr_gone')`,
	} {
		if _, err := d.Writer().ExecContext(ctx, q); err != nil {
			d.Close()
			t.Fatalf("%s: %v", q, err)
		}
	}
	d.Close()

	res = runArgs(t, "", "--home", h.Dir(), "db", "check")
	if res.code != ExitFailure || !strings.Contains(res.stdout, "foreign keys: 1 violations") ||
		!strings.Contains(res.stdout, "fk_probe") {
		t.Fatalf("violation: code=%d stdout=%q stderr=%q", res.code, res.stdout, res.stderr)
	}
}

// A scan that stops because of an error instead of running out of rows must
// reach the caller. SQLite reports a corrupt page, a cancelled scan or
// SQLITE_BUSY on a *step* ("stepping, database disk image is malformed"),
// which database/sql surfaces only through Rows.Err() — dropping it would let
// `db check` print "0 violations" and exit 0 on a broken database.
func TestDBCheckScanStepErrorIsReported(t *testing.T) {
	const malformed = "stepping, database disk image is malformed (11)"
	ctx := context.Background()

	t.Run("integrity", func(t *testing.T) {
		q := sql.OpenDB(&stepErrConnector{
			cols: []string{"integrity_check"},
			rows: [][]driver.Value{{"ok"}},
			err:  errors.New(malformed),
		})
		defer q.Close()
		got, err := dbPragmaStrings(ctx, q, "integrity_check")
		if err == nil || !strings.Contains(err.Error(), "malformed") {
			t.Fatalf("got rows=%v err=%v, want the step error", got, err)
		}
	})

	t.Run("foreign_key_check", func(t *testing.T) {
		q := sql.OpenDB(&stepErrConnector{
			cols: []string{"table", "rowid", "parent", "fkid"},
			rows: [][]driver.Value{{"nodes", int64(7), "users", int64(0)}},
			err:  errors.New(malformed),
		})
		defer q.Close()
		n, list, err := dbForeignKeyCheck(ctx, q, 20)
		if err == nil || !strings.Contains(err.Error(), "malformed") {
			t.Fatalf("got n=%d rows=%v err=%v, want the step error", n, list, err)
		}
	})

	t.Run("no error at the end of the rows", func(t *testing.T) {
		q := sql.OpenDB(&stepErrConnector{
			cols: []string{"table", "rowid", "parent", "fkid"},
			rows: [][]driver.Value{{"nodes", int64(7), "users", int64(0)}, {"nodes", int64(8), "users", int64(0)}},
		})
		defer q.Close()
		n, list, err := dbForeignKeyCheck(ctx, q, 1)
		if err != nil || n != 2 || len(list) != 1 || !strings.Contains(list[0], "nodes row 7") {
			t.Fatalf("n=%d rows=%v err=%v", n, list, err)
		}
	})
}

// ---------- a driver whose rows fail on a step ----------

type stepErrConnector struct {
	cols []string
	rows [][]driver.Value
	err  error // returned after the last row (nil = clean end of rows)
}

func (c *stepErrConnector) Connect(context.Context) (driver.Conn, error) { return stepErrConn{c}, nil }
func (c *stepErrConnector) Driver() driver.Driver                        { return stepErrDriver{c} }

type stepErrDriver struct{ c *stepErrConnector }

func (d stepErrDriver) Open(string) (driver.Conn, error) { return stepErrConn(d), nil }

type stepErrConn struct{ c *stepErrConnector }

func (c stepErrConn) Prepare(string) (driver.Stmt, error) { return stepErrStmt(c), nil }
func (c stepErrConn) Close() error                        { return nil }
func (c stepErrConn) Begin() (driver.Tx, error)           { return nil, errors.New("no transactions") }

type stepErrStmt struct{ c *stepErrConnector }

func (s stepErrStmt) Close() error  { return nil }
func (s stepErrStmt) NumInput() int { return 0 }
func (s stepErrStmt) Exec([]driver.Value) (driver.Result, error) {
	return nil, errors.New("no writes")
}
func (s stepErrStmt) Query([]driver.Value) (driver.Rows, error) { return &stepErrRows{c: s.c}, nil }

type stepErrRows struct {
	c *stepErrConnector
	i int
}

func (r *stepErrRows) Columns() []string { return r.c.cols }
func (r *stepErrRows) Close() error      { return nil }
func (r *stepErrRows) Next(dest []driver.Value) error {
	if r.i < len(r.c.rows) {
		copy(dest, r.c.rows[r.i])
		r.i++
		return nil
	}
	if r.c.err != nil {
		return r.c.err
	}
	return io.EOF
}

// db stats counts every table of statTables, the v4 role tables included:
// a name missing from the schema would be skipped silently.
func TestDBStatsTables(t *testing.T) {
	h := testHome(t)
	ctx := context.Background()
	d, err := db.Open(h.DB())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := d.Migrate(ctx); err != nil {
		d.Close()
		t.Fatal(err)
	}
	d.Close()
	res := runArgs(t, "", "--home", h.Dir(), "--json", "db", "stats")
	var st dbStats
	if res.code != 0 || json.Unmarshal([]byte(res.stdout), &st) != nil {
		t.Fatalf("db stats: %+v", res)
	}
	for _, name := range statTables {
		if _, ok := st.Tables[name]; !ok {
			t.Errorf("table %q is not counted (not in the schema?)", name)
		}
	}
	for _, name := range []string{"roles", "role_groups", "node_grants"} {
		if !slices.Contains(statTables, name) {
			t.Errorf("%s is not in statTables", name)
		}
	}
}
