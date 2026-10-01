// Package db opens the SQLite database (modernc.org/sqlite, pure Go) with one
// writer connection and a pool of read-only reader connections, applies the
// pragmas of DESIGN §6, runs the embedded migrations and offers transaction
// helpers.
//
// Rules for callers (DESIGN §18.8):
//   - All writes go through Tx (or Exec) on the single writer connection;
//     transactions start with BEGIN IMMEDIATE. Keep them short and never do
//     blob/file I/O inside a write transaction.
//   - Reads use Read / Query / QueryRow on the reader pool (query_only).
//   - Timestamps are INTEGER Unix milliseconds UTC: use Ms/FromMs/NullMs/FromNullMs.
//   - Only parameterized SQL.
package db

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"runtime"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"modernc.org/sqlite"
)

// Pragmas applied to every connection (DESIGN §6). journal_mode=WAL is set on
// the writer only (it is persistent in the database file).
var connPragmas = []string{
	"busy_timeout(10000)",
	"synchronous(NORMAL)",
	"foreign_keys(ON)",
	"temp_store(MEMORY)",
	"cache_size(-65536)",
	"mmap_size(268435456)",
	"wal_autocheckpoint(1000)",
}

// DB is the database handle: a single-connection writer pool and a
// query-only reader pool over the same file.
type DB struct {
	w, r   *sql.DB
	path   string
	closed atomic.Bool // set by Close
}

// ErrClosed is returned by IntegrityCheck on a closed handle.
var ErrClosed = errors.New("db: database is closed")

// MaxReaders is the upper bound of the reader pool: N = min(8, GOMAXPROCS).
const MaxReaders = 8

// Open opens (creating if needed) the database file at path. The parent
// directory must exist. The path must not contain '?'.
func Open(path string) (*DB, error) {
	if strings.ContainsRune(path, '?') {
		return nil, fmt.Errorf("db: path must not contain '?': %q", path)
	}
	w, err := sql.Open("sqlite", dsn(path, true))
	if err != nil {
		return nil, fmt.Errorf("db: open writer: %w", err)
	}
	w.SetMaxOpenConns(1)
	w.SetMaxIdleConns(1)
	w.SetConnMaxLifetime(0)
	w.SetConnMaxIdleTime(0)
	if err := w.Ping(); err != nil {
		w.Close()
		return nil, fmt.Errorf("db: open %s: %w", path, err)
	}
	var mode string
	if err := w.QueryRow("PRAGMA journal_mode").Scan(&mode); err != nil || !strings.EqualFold(mode, "wal") {
		w.Close()
		if err == nil {
			err = fmt.Errorf("journal_mode is %q, want wal", mode)
		}
		return nil, fmt.Errorf("db: %w", err)
	}

	r, err := sql.Open("sqlite", dsn(path, false))
	if err != nil {
		w.Close()
		return nil, fmt.Errorf("db: open reader: %w", err)
	}
	n := min(MaxReaders, runtime.GOMAXPROCS(0))
	r.SetMaxOpenConns(n)
	r.SetMaxIdleConns(n)
	r.SetConnMaxIdleTime(5 * time.Minute)
	if err := r.Ping(); err != nil {
		w.Close()
		r.Close()
		return nil, fmt.Errorf("db: open reader: %w", err)
	}
	return &DB{w: w, r: r, path: path}, nil
}

func dsn(path string, writer bool) string {
	var b strings.Builder
	b.WriteString(path)
	b.WriteString("?")
	for i, p := range connPragmas {
		if i > 0 {
			b.WriteString("&")
		}
		b.WriteString("_pragma=")
		b.WriteString(p)
	}
	if writer {
		b.WriteString("&_pragma=journal_mode(WAL)&_txlock=immediate")
	} else {
		b.WriteString("&_query_only=on")
	}
	return b.String()
}

// Path returns the database file path.
func (d *DB) Path() string { return d.path }

// Writer returns the single-connection writer pool. Prefer Tx/Exec; use this
// only for special statements (VACUUM INTO, wal_checkpoint, PRAGMA optimize).
func (d *DB) Writer() *sql.DB { return d.w }

// Reader returns the query-only reader pool.
func (d *DB) Reader() *sql.DB { return d.r }

// Close closes both pools.
func (d *DB) Close() error {
	d.closed.Store(true)
	return errors.Join(d.r.Close(), d.w.Close())
}

// Ping checks both pools.
func (d *DB) Ping(ctx context.Context) error {
	if err := d.w.PingContext(ctx); err != nil {
		return err
	}
	return d.r.PingContext(ctx)
}

// Retry policy for SQLITE_BUSY/LOCKED that survives busy_timeout (e.g. another
// process holding the write lock, or a checkpoint).
//
// SQLite's own busy wait runs inside the driver and is not interruptible by a
// context: with the connection's busy_timeout of 10 s, a write blocked by
// another process held the single writer connection for the whole 10 s, long
// past the caller's deadline, and the SQLITE_BUSY was then replaced by
// database/sql's context error, so IsBusy was false and this loop never ran.
// A transaction therefore lowers busy_timeout on the connection it holds and
// does the waiting here, between attempts, where ctx is honoured; the pragma
// is restored before the connection goes back to the pool, so the statements
// that want a long wait (Writer(): VACUUM, wal_checkpoint(TRUNCATE), PRAGMA
// optimize) keep connBusyTimeout.
const (
	connBusyTimeout = 10 * time.Second       // busy_timeout of connPragmas
	txBusyTimeout   = 250 * time.Millisecond // driver-side wait inside one attempt
	busyBudget      = 10 * time.Second       // total wait one Tx call spends
	busyBackoff     = 20 * time.Millisecond
	maxBusyBackoff  = 250 * time.Millisecond
)

// Tx runs fn inside a write transaction (BEGIN IMMEDIATE on the writer
// connection) and commits if fn returns nil; otherwise it rolls back and
// returns fn's error unchanged. If beginning or committing fails with
// SQLITE_BUSY/SQLITE_LOCKED the whole transaction is retried with backoff for
// up to busyBudget, so fn may run more than once: it must not have side
// effects outside the transaction. A cancelled context ends the retries at
// once and returns the busy error joined with ctx.Err(), so callers can tell
// both apart. Do not call Tx from inside fn (single writer ⇒ deadlock).
func (d *DB) Tx(ctx context.Context, fn func(*sql.Tx) error) error {
	deadline := time.Now().Add(busyBudget)
	backoff := busyBackoff
	for {
		err := d.txOnce(ctx, fn)
		if err == nil || !IsBusy(err) || !time.Now().Before(deadline) {
			return err
		}
		select {
		case <-ctx.Done():
			return errors.Join(err, ctx.Err())
		case <-time.After(backoff):
		}
		if backoff < maxBusyBackoff {
			backoff *= 2
		}
	}
}

// busyPragma is the statement that sets a connection's busy timeout.
func busyPragma(d time.Duration) string {
	return "PRAGMA busy_timeout = " + strconv.FormatInt(d.Milliseconds(), 10)
}

func (d *DB) txOnce(ctx context.Context, fn func(*sql.Tx) error) (err error) {
	// Pin the connection so the short busy timeout applies to this
	// transaction only, and is undone before anyone else sees it.
	conn, err := d.w.Conn(ctx)
	if err != nil {
		return err
	}
	defer conn.Close()
	if _, err := conn.ExecContext(ctx, busyPragma(txBusyTimeout)); err != nil {
		return err
	}
	defer func() {
		// WithoutCancel: restore it even when the caller's context is done.
		_, _ = conn.ExecContext(context.WithoutCancel(ctx), busyPragma(connBusyTimeout))
	}()
	tx, err := conn.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() {
		if p := recover(); p != nil {
			_ = tx.Rollback()
			panic(p)
		}
	}()
	if ferr := fn(tx); ferr != nil {
		// Busy errors raised by statements inside fn are retried by Tx too
		// (the transaction is rolled back first); other errors are final.
		_ = tx.Rollback()
		return ferr
	}
	return tx.Commit()
}

// Read runs fn inside a read-only transaction on the reader pool, giving it a
// consistent snapshot across several queries. fn's error is returned as-is.
func (d *DB) Read(ctx context.Context, fn func(*sql.Tx) error) error {
	tx, err := d.r.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return err
	}
	defer tx.Rollback()
	return fn(tx)
}

// Exec runs a single auto-commit write statement on the writer connection,
// retrying on SQLITE_BUSY.
func (d *DB) Exec(ctx context.Context, query string, args ...any) (sql.Result, error) {
	var res sql.Result
	err := d.Tx(ctx, func(tx *sql.Tx) error {
		var err error
		res, err = tx.ExecContext(ctx, query, args...)
		return err
	})
	return res, err
}

// Query runs a read query on the reader pool.
func (d *DB) Query(ctx context.Context, query string, args ...any) (*sql.Rows, error) {
	return d.r.QueryContext(ctx, query, args...)
}

// QueryRow runs a single-row read query on the reader pool.
func (d *DB) QueryRow(ctx context.Context, query string, args ...any) *sql.Row {
	return d.r.QueryRowContext(ctx, query, args...)
}

// IntegrityCheck runs "PRAGMA quick_check" (or integrity_check when full is
// set) and returns every row that is not "ok" — empty means a healthy file.
//
// It deliberately opens its own short-lived read-only connection instead of
// borrowing one from the reader pool. Since SQLite 3.44 these pragmas also
// call each virtual table's xIntegrity method, and fts5 answers that one from
// the structure record it cached the last time this connection queried the
// index — without the xBegin that a normal query performs and that would
// refresh it. On a pooled connection that has served a /search request, the
// cache goes stale as soon as the writer merges or frees a segment, and the
// check then walks the old structure and reports the segment page it can no
// longer find as "fts5: corruption found reading blob N from table …" on a
// perfectly intact database (DESIGN §6; internal/db/fts_quickcheck_test.go).
// A fresh connection has nothing cached, so what it reports is the file.
// Nothing here touches the reader pool, not even the closed-handle check, so
// a caller holding every pooled reader (a pool of one with GOMAXPROCS=1)
// cannot deadlock it.
func (d *DB) IntegrityCheck(ctx context.Context, full bool) ([]string, error) {
	// Fail on a closed handle rather than quietly reopening the file behind
	// the caller's back.
	if d.closed.Load() {
		return nil, ErrClosed
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	c, err := sql.Open("sqlite", dsn(d.path, false))
	if err != nil {
		return nil, err
	}
	defer c.Close()
	c.SetMaxOpenConns(1)
	pragma := "quick_check"
	if full {
		pragma = "integrity_check"
	}
	rows, err := c.QueryContext(ctx, "PRAGMA "+pragma)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var problems []string
	for rows.Next() {
		var m string
		if err := rows.Scan(&m); err != nil {
			return nil, err
		}
		if m != "ok" {
			problems = append(problems, m)
		}
	}
	return problems, rows.Err()
}

// sqliteCode extracts the (extended) SQLite result code from err.
func sqliteCode(err error) (int, bool) {
	var se *sqlite.Error
	if errors.As(err, &se) {
		return se.Code(), true
	}
	return 0, false
}

// SQLite result codes used by the helpers below.
const (
	codeBusy                 = 5
	codeLocked               = 6
	codeConstraint           = 19
	codeConstraintForeignKey = 787
	codeConstraintPrimaryKey = 1555
	codeConstraintUnique     = 2067
)

// IsBusy reports whether err is SQLITE_BUSY or SQLITE_LOCKED (any extended code).
func IsBusy(err error) bool {
	c, ok := sqliteCode(err)
	return ok && (c&0xff == codeBusy || c&0xff == codeLocked)
}

// IsUnique reports whether err is a UNIQUE or PRIMARY KEY constraint violation.
func IsUnique(err error) bool {
	c, ok := sqliteCode(err)
	if !ok {
		return false
	}
	switch c {
	case codeConstraintUnique, codeConstraintPrimaryKey:
		return true
	case codeConstraint:
		return strings.Contains(err.Error(), "UNIQUE constraint failed")
	}
	return false
}

// IsForeignKey reports whether err is a FOREIGN KEY constraint violation.
func IsForeignKey(err error) bool {
	c, ok := sqliteCode(err)
	if !ok {
		return false
	}
	return c == codeConstraintForeignKey || (c == codeConstraint && strings.Contains(err.Error(), "FOREIGN KEY constraint failed"))
}

// IsConstraint reports whether err is any constraint violation (UNIQUE, CHECK,
// NOT NULL, FOREIGN KEY, …).
func IsConstraint(err error) bool {
	c, ok := sqliteCode(err)
	return ok && c&0xff == codeConstraint
}

// IsNoRows reports whether err is sql.ErrNoRows.
func IsNoRows(err error) bool { return errors.Is(err, sql.ErrNoRows) }
