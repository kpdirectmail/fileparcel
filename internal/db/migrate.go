package db

import (
	"context"
	"database/sql"
	"embed"
	"errors"
	"fmt"
	"io/fs"
	"path"
	"sort"
	"strconv"
	"strings"
	"time"
)

//go:embed migrations/*.sql
var migrationsFS embed.FS

// Migration is one embedded migration file migrations/NNNN_name.sql.
type Migration struct {
	Version int
	Name    string
	SQL     string
}

// ErrSchemaTooNew is returned by Migrate when the database was migrated by a
// newer binary than this one.
var ErrSchemaTooNew = errors.New("db: database schema is newer than this binary supports (downgrade not possible; restore a backup or upgrade FileParcel)")

// Migrations returns the embedded migrations sorted by version. The versions
// must be exactly 1..N (DESIGN §6 "Migration numbering"): a binary with a gap
// refuses to start instead of leaving a database without a migration.
func Migrations() ([]Migration, error) { return migrationsFrom(migrationsFS) }

// migrationsFrom parses the migrations/NNNN_name.sql files of fsys, sorted by
// version, and checks that the versions are 1..N without gaps.
func migrationsFrom(fsys fs.FS) ([]Migration, error) {
	entries, err := fs.ReadDir(fsys, "migrations")
	if err != nil {
		return nil, err
	}
	var out []Migration
	seen := map[int]string{}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".sql") {
			continue
		}
		base := strings.TrimSuffix(e.Name(), ".sql")
		num, name, ok := strings.Cut(base, "_")
		v, err := strconv.Atoi(num)
		if !ok || err != nil || v <= 0 || len(num) != 4 {
			return nil, fmt.Errorf("db: bad migration file name %q (want NNNN_name.sql)", e.Name())
		}
		if prev, dup := seen[v]; dup {
			return nil, fmt.Errorf("db: duplicate migration version %d (%s, %s)", v, prev, e.Name())
		}
		seen[v] = e.Name()
		body, err := fs.ReadFile(fsys, path.Join("migrations", e.Name()))
		if err != nil {
			return nil, err
		}
		out = append(out, Migration{Version: v, Name: name, SQL: string(body)})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Version < out[j].Version })
	for i, m := range out {
		if want := i + 1; m.Version != want {
			return nil, fmt.Errorf("db: missing migration %04d (migrations must be numbered without gaps)", want)
		}
	}
	return out, nil
}

// LatestVersion returns the highest embedded migration version.
func LatestVersion() int {
	ms, err := Migrations()
	if err != nil || len(ms) == 0 {
		return 0
	}
	return ms[len(ms)-1].Version
}

const createMigrationsTable = `CREATE TABLE IF NOT EXISTS schema_migrations (
  version INTEGER PRIMARY KEY, name TEXT, applied_at INTEGER)`

// SchemaVersion returns the highest applied migration version (0 for a fresh DB).
func (d *DB) SchemaVersion(ctx context.Context) (int, error) {
	var exists int
	if err := d.w.QueryRowContext(ctx,
		`SELECT count(*) FROM sqlite_master WHERE type='table' AND name='schema_migrations'`).Scan(&exists); err != nil {
		return 0, err
	}
	if exists == 0 {
		return 0, nil
	}
	var v sql.NullInt64
	if err := d.w.QueryRowContext(ctx, `SELECT max(version) FROM schema_migrations`).Scan(&v); err != nil {
		return 0, err
	}
	return int(v.Int64), nil
}

// Migrate applies every embedded migration that the database has not
// recorded in schema_migrations, in ascending order, each in its own
// transaction together with its schema_migrations row (set-based, so a
// migration numbered below an applied one still runs). A recorded version
// whose name differs from the embedded migration's name is an error, raised
// before any migration runs: the database was migrated by a build that
// numbered its migrations differently. A recorded row without a name counts
// as applied.
// Migrate refuses (ErrSchemaTooNew) to touch a database whose highest version
// is above LatestVersion(). It returns the list of applied versions.
func (d *DB) Migrate(ctx context.Context) ([]int, error) {
	ms, err := Migrations()
	if err != nil {
		return nil, err
	}
	return d.migrate(ctx, ms)
}

// migrate is Migrate over the migrations ms (sorted, contiguous).
func (d *DB) migrate(ctx context.Context, ms []Migration) ([]int, error) {
	if _, err := d.w.ExecContext(ctx, createMigrationsTable); err != nil {
		return nil, fmt.Errorf("db: migrate: %w", err)
	}
	recorded, err := d.recordedMigrations(ctx)
	if err != nil {
		return nil, fmt.Errorf("db: migrate: %w", err)
	}
	cur := 0
	for v := range recorded {
		cur = max(cur, v)
	}
	latest := 0
	if len(ms) > 0 {
		latest = ms[len(ms)-1].Version
	}
	if cur > latest {
		return nil, fmt.Errorf("%w (database version %d, binary knows %d)", ErrSchemaTooNew, cur, latest)
	}
	// Every name is checked before anything runs, so a database migrated by
	// a build that numbered its migrations differently is left untouched.
	for _, m := range ms {
		if name, done := recorded[m.Version]; done && name != "" && name != m.Name {
			return nil, fmt.Errorf("db: migration %04d is %q in the database but %q in this binary", m.Version, name, m.Name)
		}
	}
	var applied []int
	for _, m := range ms {
		if _, done := recorded[m.Version]; done {
			continue
		}
		err := d.Tx(ctx, func(tx *sql.Tx) error {
			if _, err := tx.ExecContext(ctx, m.SQL); err != nil {
				return err
			}
			_, err := tx.ExecContext(ctx,
				`INSERT INTO schema_migrations(version, name, applied_at) VALUES (?, ?, ?)`,
				m.Version, m.Name, time.Now().UnixMilli())
			return err
		})
		if err != nil {
			return applied, fmt.Errorf("db: migration %04d_%s: %w", m.Version, m.Name, err)
		}
		applied = append(applied, m.Version)
	}
	return applied, nil
}

// recordedMigrations reads schema_migrations: version → name ("" when the
// row has no name).
func (d *DB) recordedMigrations(ctx context.Context) (map[int]string, error) {
	rows, err := d.w.QueryContext(ctx, `SELECT version, name FROM schema_migrations`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[int]string{}
	for rows.Next() {
		var v int
		var name sql.NullString
		if err := rows.Scan(&v, &name); err != nil {
			return nil, err
		}
		out[v] = name.String
	}
	return out, rows.Err()
}
