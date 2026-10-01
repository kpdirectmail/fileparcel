package cli

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"fileparcel/internal/blobstore"
	"fileparcel/internal/core"
	"fileparcel/internal/db"
	"fileparcel/internal/home"
)

func init() {
	Register(newDBCmd)
	Register(newGCCmd)
}

// dbHandle is the database opened by the db/gc commands, directly on the
// home (not through the API): exclusively when the server is stopped (home
// lock held), read-only next to a running server.
type dbHandle struct {
	h       *home.Home
	full    *db.DB  // exclusive access (server stopped)
	ro      *sql.DB // read-only connection (server running)
	running bool
	unlock  func()
}

// reader returns a pool for queries.
func (d *dbHandle) reader() *sql.DB {
	if d.full != nil {
		return d.full.Reader()
	}
	return d.ro
}

func (d *dbHandle) Close() {
	if d.full != nil {
		d.full.Close()
	}
	if d.ro != nil {
		d.ro.Close()
	}
	if d.unlock != nil {
		d.unlock()
	}
}

// readOnlyDSN returns a modernc/sqlite DSN opening path read-only.
func readOnlyDSN(path string) string {
	u := url.URL{Scheme: "file", Path: filepath.ToSlash(path)}
	return u.String() + "?mode=ro&_pragma=busy_timeout(10000)&_query_only=on"
}

// openHomeDB opens the database of the resolved home. write requires the
// server to be stopped; read-only access works next to a running server.
func openHomeDB(write bool, what string) (*dbHandle, error) {
	if G.Server != "" {
		return nil, UsageError("%s works only on the server host (not with --server)", what)
	}
	h, err := home.Resolve(G.Home)
	if err != nil {
		return nil, err
	}
	if !h.Exists() {
		return nil, notAHomeError(h.Dir())
	}
	if _, err := os.Stat(h.DB()); err != nil {
		return nil, fmt.Errorf("no database at %s: %w", h.DB(), err)
	}
	unlock, err := h.Lock()
	switch {
	case err == nil:
		full, err := db.Open(h.DB())
		if err != nil {
			unlock()
			return nil, err
		}
		return &dbHandle{h: h, full: full, unlock: unlock}, nil
	case !errors.Is(err, home.ErrLocked):
		return nil, err
	case write:
		return nil, fmt.Errorf("%s needs exclusive access, but the server is running; stop it first (\"fileparcel service stop\")", what)
	}
	ro, err := sql.Open("sqlite", readOnlyDSN(h.DB()))
	if err != nil {
		return nil, err
	}
	ro.SetMaxOpenConns(1)
	if err := ro.Ping(); err != nil {
		ro.Close()
		return nil, fmt.Errorf("open %s read-only: %w", h.DB(), err)
	}
	return &dbHandle{h: h, ro: ro, running: true}, nil
}

func cmdContext(cmd *cobra.Command) context.Context {
	if ctx := cmd.Context(); ctx != nil {
		return ctx
	}
	return context.Background()
}

// schemaVersion reads the applied schema version (0 when unmigrated).
func schemaVersion(ctx context.Context, q *sql.DB) (int, error) {
	var n int
	if err := q.QueryRowContext(ctx, `SELECT count(*) FROM sqlite_master WHERE type='table' AND name='schema_migrations'`).Scan(&n); err != nil {
		return 0, err
	}
	if n == 0 {
		return 0, nil
	}
	var v sql.NullInt64
	if err := q.QueryRowContext(ctx, `SELECT max(version) FROM schema_migrations`).Scan(&v); err != nil {
		return 0, err
	}
	return int(v.Int64), nil
}

// dbPragmaStrings runs a single-column pragma (integrity_check/quick_check)
// and returns its rows. An error that ends the iteration instead of the rows
// running out — a corrupt page reported on a step, a cancelled context,
// SQLITE_BUSY — is returned: a check that did not finish must never be
// reported as a clean result.
func dbPragmaStrings(ctx context.Context, q *sql.DB, pragma string) ([]string, error) {
	rows, err := q.QueryContext(ctx, "PRAGMA "+pragma)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var s string
		if err := rows.Scan(&s); err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

// dbForeignKeyCheck runs PRAGMA foreign_key_check and returns the number of
// violations and the first limit of them, formatted for display. As in
// dbPragmaStrings an iteration error is returned rather than swallowed:
// "0 violations" must mean the scan reached the end.
func dbForeignKeyCheck(ctx context.Context, q *sql.DB, limit int) (int, []string, error) {
	rows, err := q.QueryContext(ctx, "PRAGMA foreign_key_check")
	if err != nil {
		return 0, nil, err
	}
	defer rows.Close()
	var (
		n    int
		list []string
	)
	for rows.Next() {
		var table, parent string
		var rowid sql.NullInt64
		var idx int
		if err := rows.Scan(&table, &rowid, &parent, &idx); err != nil {
			return 0, nil, err
		}
		n++
		if len(list) < limit {
			list = append(list, fmt.Sprintf("%s row %d → %s", table, rowid.Int64, parent))
		}
	}
	if err := rows.Err(); err != nil {
		return 0, nil, err
	}
	return n, list, nil
}

func newDBCmd() *cobra.Command {
	cmd := groupCmd("db", "Check, compact and inspect the database",
		`Low-level care of the SQLite database (<HOME>/data/fileparcel.db). "check" and
"stats" also work while the server runs (they only read); "vacuum" and
"migrate" need the server stopped. The server tunes the database by itself
every day (the maintenance.db_optimize job).`,
		`  fileparcel db check
  fileparcel db stats
  fileparcel service stop && fileparcel db vacuum && fileparcel service start`, "database")
	cmd.AddCommand(newDBCheckCmd(), newDBVacuumCmd(), newDBMigrateCmd(), newDBStatsCmd())
	return cmd
}

// dbCheckResult is the --json output of db check.
type dbCheckResult struct {
	OK             bool     `json:"ok"`
	Integrity      []string `json:"integrity"`
	ForeignKeys    int      `json:"foreign_key_violations"`
	SchemaVersion  int      `json:"schema_version"`
	BinaryVersion  int      `json:"binary_schema_version"`
	ServerRunning  bool     `json:"server_running"`
	FTS            string   `json:"fts,omitempty"`
	ForeignKeyRows []string `json:"foreign_key_rows,omitempty"`
}

func newDBCheckCmd() *cobra.Command {
	var quick bool
	cmd := &cobra.Command{
		Use:   "check",
		Short: "Check the database for corruption",
		Long: `Run SQLite's integrity check (--quick: the faster quick_check), the foreign
key check and a schema version comparison; with the server stopped also the
full-text index check. Exits with status 1 when a problem is found.`,
		Example: `  fileparcel db check
  fileparcel db check --quick --json`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			d, err := openHomeDB(false, "db check")
			if err != nil {
				return err
			}
			defer d.Close()
			ctx := cmdContext(cmd)
			q := d.reader()
			res := dbCheckResult{BinaryVersion: db.LatestVersion(), ServerRunning: d.running}
			pragma := "integrity_check"
			if quick {
				pragma = "quick_check"
			}
			// This must run on a connection that has not queried nodes_fts:
			// since SQLite 3.44 these pragmas call fts5's xIntegrity, which
			// answers from a per-connection cache that a concurrent writer
			// can leave stale, and then reports phantom corruption (see
			// db.DB.IntegrityCheck). Here the pool is freshly opened by this
			// command, so nothing is cached — do not query the index above.
			if res.Integrity, err = dbPragmaStrings(ctx, q, pragma); err != nil {
				return err
			}
			if res.ForeignKeys, res.ForeignKeyRows, err = dbForeignKeyCheck(ctx, q, 20); err != nil {
				return err
			}
			if res.SchemaVersion, err = schemaVersion(ctx, q); err != nil {
				return err
			}
			if d.full != nil {
				if _, err := d.full.Writer().ExecContext(ctx, `INSERT INTO nodes_fts(nodes_fts, rank) VALUES('integrity-check', 1)`); err != nil {
					res.FTS = err.Error()
				} else {
					res.FTS = "ok"
				}
			}
			res.OK = len(res.Integrity) == 1 && res.Integrity[0] == "ok" && res.ForeignKeys == 0 &&
				res.SchemaVersion <= res.BinaryVersion && (res.FTS == "" || res.FTS == "ok")
			if err := Print(cmd, &res, func(w io.Writer) error {
				mark := func(ok bool) string {
					if ok {
						return Green("ok  ")
					}
					return Red("FAIL")
				}
				integ := strings.Join(res.Integrity, "; ")
				fmt.Fprintf(w, "%s %s: %s\n", mark(integ == "ok"), pragma, Truncate(integ, 300))
				fmt.Fprintf(w, "%s foreign keys: %d violations\n", mark(res.ForeignKeys == 0), res.ForeignKeys)
				for _, r := range res.ForeignKeyRows {
					fmt.Fprintf(w, "       %s\n", r)
				}
				fmt.Fprintf(w, "%s schema version %d (this binary knows %d)\n", mark(res.SchemaVersion <= res.BinaryVersion), res.SchemaVersion, res.BinaryVersion)
				if res.FTS != "" {
					fmt.Fprintf(w, "%s search index: %s\n", mark(res.FTS == "ok"), res.FTS)
				}
				if d.running {
					Infof(cmd, "The server is running: checked read-only (the search index check needs the server stopped).")
				}
				return nil
			}); err != nil {
				return err
			}
			if !res.OK {
				return &ExitCodeError{Code: ExitFailure, Err: errors.New(`database problems found; consider restoring a backup ("fileparcel backup list")`)}
			}
			return nil
		},
	}
	cmd.Flags().BoolVar(&quick, "quick", false, "use quick_check (faster, fewer checks)")
	return cmd
}

// fileSize returns the size of path (0 when missing).
func fileSize(path string) int64 {
	if fi, err := os.Stat(path); err == nil {
		return fi.Size()
	}
	return 0
}

func newDBVacuumCmd() *cobra.Command {
	return &cobra.Command{
		Use:     "vacuum",
		Aliases: []string{"compact"},
		Short:   "Compact the database (server stopped)",
		Long: `Rebuild the database file to give free space back to the disk (VACUUM), empty
the write-ahead log and refresh the query planner statistics. Needs the server
stopped and, for a moment, free disk space of up to twice the database size.`,
		Example: `  fileparcel service stop && fileparcel db vacuum && fileparcel service start
  fileparcel --offline db vacuum`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			d, err := openHomeDB(true, "db vacuum")
			if err != nil {
				return err
			}
			closed := false
			defer func() {
				if !closed {
					d.Close()
				}
			}()
			ctx := cmdContext(cmd)
			path := d.h.DB()
			before := fileSize(path) + fileSize(path+"-wal")
			start := time.Now()
			w := d.full.Writer()
			// "PRAGMA optimize" refreshes the planner statistics, so it runs
			// before the last checkpoint: measuring after a write would count
			// a write-ahead log that is about to be folded back in.
			for _, stmt := range []string{"PRAGMA wal_checkpoint(TRUNCATE)", "VACUUM", "PRAGMA optimize"} {
				if _, err := w.ExecContext(ctx, stmt); err != nil {
					return fmt.Errorf("%s: %w", stmt, err)
				}
			}
			// A checkpoint that cannot truncate the log reports busy=1 in its
			// result row rather than an error; without this the leftover log
			// is counted as growth and "database rebuilt: X → Y" reads as a
			// contradiction of "db stats", which counts pages only.
			var busy, logPages, ckPages sql.NullInt64
			if err := w.QueryRowContext(ctx, "PRAGMA wal_checkpoint(TRUNCATE)").Scan(&busy, &logPages, &ckPages); err != nil {
				return fmt.Errorf("PRAGMA wal_checkpoint(TRUNCATE): %w", err)
			}
			// Close before measuring: the size that counts is the one left on
			// disk when the command is done, not a snapshot taken mid-flight.
			d.Close()
			closed = true
			if busy.Int64 != 0 {
				Warnf(cmd, "the write-ahead log could not be truncated (something else is still reading %s); %s remain in %s-wal",
					path, HumanBytes(fileSize(path+"-wal")), path)
			}
			after := fileSize(path) + fileSize(path+"-wal")
			out := map[string]any{"before_bytes": before, "after_bytes": after, "seconds": time.Since(start).Seconds()}
			return done(cmd, out, "database rebuilt: %s → %s in %s", HumanBytes(before), HumanBytes(after), HumanDuration(time.Since(start)))
		},
	}
}

func newDBMigrateCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "migrate",
		Short: "Apply database upgrades (server stopped)",
		Long: `Apply the database upgrades (schema migrations) this program carries. The
server does this by itself at start; run it by hand after replacing the
program to see the result before starting. A database newer than the program
is never touched. Make a backup first ("fileparcel backup create --scope
metadata").`,
		Example: `  fileparcel db migrate
  fileparcel --home /opt/fileparcel db migrate`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmdContext(cmd)
			d, err := openHomeDB(false, "db migrate")
			if err != nil {
				return err
			}
			defer d.Close()
			latest := db.LatestVersion()
			if d.running {
				v, err := schemaVersion(ctx, d.reader())
				if err != nil {
					return err
				}
				out := map[string]any{"schema_version": v, "binary_schema_version": latest, "server_running": true}
				if v < latest {
					return &ExitCodeError{Code: ExitFailure, Err: fmt.Errorf("schema version %d, this binary knows %d: restart the server to migrate (fileparcel service restart)", v, latest)}
				}
				return done(cmd, out, "schema version %d is current (the running server migrates at start)", v)
			}
			applied, err := d.full.Migrate(ctx)
			if err != nil {
				return err
			}
			v, err := d.full.SchemaVersion(ctx)
			if err != nil {
				return err
			}
			if applied == nil {
				applied = []int{}
			}
			out := map[string]any{"applied": applied, "schema_version": v, "binary_schema_version": latest}
			if len(applied) == 0 {
				return done(cmd, out, "schema version %d is current; nothing to do", v)
			}
			return done(cmd, out, "applied %s; schema version is now %d", Plural(int64(len(applied)), "migration"), v)
		},
	}
}

// dbStats is the --json output of db stats.
type dbStats struct {
	Path          string           `json:"path"`
	FileBytes     int64            `json:"file_bytes"`
	WALBytes      int64            `json:"wal_bytes"`
	PageSize      int64            `json:"page_size"`
	PageCount     int64            `json:"page_count"`
	FreePages     int64            `json:"freelist_count"`
	SchemaVersion int              `json:"schema_version"`
	Tables        map[string]int64 `json:"tables"`
	ServerRunning bool             `json:"server_running"`
}

// statTables are the tables counted by db stats, in display order.
var statTables = []string{"users", "roles", "groups", "group_members", "role_groups", "sessions", "api_tokens", "spaces",
	"nodes", "node_grants", "file_versions", "blobs", "shares", "share_access_log", "upload_batches", "upload_files", "invites",
	"client_certs", "jobs", "backups", "audit_log", "settings"}

func newDBStatsCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "stats",
		Short: "Show database size and table row counts",
		Long: `Show the size of the database file and its write-ahead log, page usage, the
schema version and the number of rows per table. Works while the server runs
(it only reads).`,
		Example: `  fileparcel db stats
  fileparcel db stats --json`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			d, err := openHomeDB(false, "db stats")
			if err != nil {
				return err
			}
			defer d.Close()
			ctx := cmdContext(cmd)
			q := d.reader()
			st := dbStats{Path: d.h.DB(), FileBytes: fileSize(d.h.DB()), WALBytes: fileSize(d.h.DB() + "-wal"),
				Tables: map[string]int64{}, ServerRunning: d.running}
			for _, p := range []struct {
				name string
				dst  *int64
			}{{"page_size", &st.PageSize}, {"page_count", &st.PageCount}, {"freelist_count", &st.FreePages}} {
				if err := q.QueryRowContext(ctx, "PRAGMA "+p.name).Scan(p.dst); err != nil {
					return err
				}
			}
			if st.SchemaVersion, err = schemaVersion(ctx, q); err != nil {
				return err
			}
			for _, t := range statTables {
				var n int64
				// Table names come from the fixed list above, never from input.
				if err := q.QueryRowContext(ctx, "SELECT count(*) FROM "+t).Scan(&n); err != nil {
					continue // table absent in this schema version
				}
				st.Tables[t] = n
			}
			return Print(cmd, &st, func(w io.Writer) error {
				kv := NewKV()
				kv.Add("File", st.Path)
				kv.Add("Size", HumanBytes(st.FileBytes))
				kv.Add("WAL", HumanBytes(st.WALBytes))
				kv.Add("Pages", fmt.Sprintf("%d × %s (%d free, %s reclaimable by \"db vacuum\")", st.PageCount, HumanBytes(st.PageSize),
					st.FreePages, HumanBytes(st.FreePages*st.PageSize)))
				kv.Add("Schema version", st.SchemaVersion)
				if err := kv.Render(w); err != nil {
					return err
				}
				fmt.Fprintln(w)
				t := NewTable("TABLE", "ROWS")
				for _, name := range statTables {
					if n, ok := st.Tables[name]; ok {
						t.Add(name, n)
					}
				}
				return t.Render(w)
			})
		},
	}
}

// ---------- gc ----------

// gcEstimate is the dry-run result of gc.
type gcEstimate struct {
	StagingBlobs      int64 `json:"stale_staging_blobs"`
	StagingBytes      int64 `json:"stale_staging_bytes"`
	UnreferencedBlobs int64 `json:"unreferenced_blobs"`
	UnreferencedBytes int64 `json:"unreferenced_bytes"`
	DeletingBlobs     int64 `json:"deleting_blobs"`
	OrphanFiles       int64 `json:"orphan_files"`
	OrphanBytes       int64 `json:"orphan_bytes"`
}

// estimateGC computes what blob garbage collection would remove, read-only:
// with the selection rules of blobstore.GC (the same conditions, the same
// minimum age blobstore.GCFloor, stray files only where the blob store keeps
// blob files), so the dry run reports what "fileparcel gc" really removes.
func estimateGC(ctx context.Context, d *dbHandle, minAge time.Duration) (*gcEstimate, error) {
	q := d.reader()
	cutoff := time.Now().Add(-max(minAge, blobstore.GCFloor))
	var e gcEstimate
	const sum = `SELECT count(*), coalesce(sum(coalesce(stored_size, size)), 0) FROM blobs WHERE `
	if err := q.QueryRowContext(ctx, sum+blobstore.StaleStagingCond, db.Ms(cutoff)).Scan(&e.StagingBlobs, &e.StagingBytes); err != nil {
		return nil, err
	}
	if err := q.QueryRowContext(ctx, sum+blobstore.UnreferencedReadyCond, db.Ms(cutoff)).Scan(&e.UnreferencedBlobs, &e.UnreferencedBytes); err != nil {
		return nil, err
	}
	if err := q.QueryRowContext(ctx, `SELECT count(*) FROM blobs WHERE state = 'deleting'`).Scan(&e.DeletingBlobs); err != nil {
		return nil, err
	}
	known := map[string]struct{}{}
	rows, err := q.QueryContext(ctx, `SELECT id FROM blobs`)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return nil, err
		}
		known[id] = struct{}{}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	// Stray files: regular files at <id[0:2]>/<id[2:4]>/<id> without a row
	// (blobstore.GC's gcOrphans), older than the cutoff.
	readDir := func(dir string) ([]fs.DirEntry, error) {
		list, err := os.ReadDir(dir)
		if errors.Is(err, fs.ErrNotExist) {
			return nil, nil
		}
		return list, err
	}
	root := d.h.BlobsDir()
	l1, err := readDir(root)
	if err != nil {
		return nil, err
	}
	for _, a := range l1 {
		if !a.IsDir() || len(a.Name()) != 2 {
			continue
		}
		l2, err := readDir(filepath.Join(root, a.Name()))
		if err != nil {
			return nil, err
		}
		for _, b := range l2 {
			if !b.IsDir() || len(b.Name()) != 2 {
				continue
			}
			files, err := readDir(filepath.Join(root, a.Name(), b.Name()))
			if err != nil {
				return nil, err
			}
			for _, f := range files {
				if !f.Type().IsRegular() || !blobstore.IsBlobFile(a.Name(), b.Name(), f.Name()) {
					continue
				}
				if _, ok := known[f.Name()]; ok {
					continue
				}
				fi, err := f.Info()
				if err != nil || !fi.ModTime().Before(cutoff) {
					continue
				}
				e.OrphanFiles++
				e.OrphanBytes += fi.Size()
			}
		}
	}
	return &e, nil
}

func newGCCmd() *cobra.Command {
	var dryRun bool
	var minAge time.Duration
	cmd := &cobra.Command{
		Use:     "gc",
		Aliases: []string{"cleanup"},
		Short:   "Free disk space used by deleted files",
		Long: `Delete stored file data that no file, version, thumbnail or upload uses any
more, abandoned upload data and stray files in the blob store. This runs daily
(maintenance.blob_gc); run it by hand after deleting a lot. --dry-run only
reports what would be removed (it only reads, so it is safe while the server
runs). --min-age is raised to at least 15 minutes, so data being written right
now is never touched.`,
		Example: `  fileparcel gc --dry-run
  fileparcel gc
  fileparcel --offline gc --min-age 7d`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if minAge < 0 {
				return UsageError("--min-age must not be negative")
			}
			ctx := cmdContext(cmd)
			if dryRun {
				d, err := openHomeDB(false, "gc --dry-run")
				if err != nil {
					return err
				}
				defer d.Close()
				e, err := estimateGC(ctx, d, minAge)
				if err != nil {
					return err
				}
				return Print(cmd, e, func(w io.Writer) error {
					kv := NewKV()
					kv.Add("Stale upload staging", fmt.Sprintf("%s (%s)", Plural(e.StagingBlobs, "blob"), HumanBytes(e.StagingBytes)))
					kv.Add("Unreferenced blobs", fmt.Sprintf("%s (%s)", Plural(e.UnreferencedBlobs, "blob"), HumanBytes(e.UnreferencedBytes)))
					kv.Add("Interrupted deletions", Plural(e.DeletingBlobs, "blob"))
					kv.Add("Stray files", fmt.Sprintf("%s (%s)", Plural(e.OrphanFiles, "file"), HumanBytes(e.OrphanBytes)))
					if err := kv.Render(w); err != nil {
						return err
					}
					total := e.StagingBytes + e.UnreferencedBytes + e.OrphanBytes
					_, err := fmt.Fprintf(w, "\nAbout %s would be freed (dry run; nothing was deleted).\n", HumanBytes(total))
					return err
				})
			}
			return WithClient(cmd, func(ctx context.Context, c *Client) error {
				if c.Mode() == ModeOffline {
					d := c.Deps()
					if d == nil || d.Blobs == nil {
						return errors.New("the blob store is not available in-process")
					}
					removed, freed, err := d.Blobs.GC(ctx, minAge)
					if err != nil {
						return err
					}
					return done(cmd, map[string]any{"removed": removed, "freed_bytes": freed},
						"removed %s, freed %s", Plural(int64(removed), "blob"), HumanBytes(freed))
				}
				// The maintenance.blob_gc job takes no parameters, so the
				// running server always uses its own cutoff: refuse --min-age
				// here instead of discarding it silently.
				if cmd.Flags().Changed("min-age") {
					return UsageError("--min-age needs --offline or --dry-run; the running server's maintenance.blob_gc job uses its own cutoff")
				}
				var ref core.JobRef
				if err := c.Do(ctx, "POST", api("/admin/jobs/run"), core.RunJobInput{Kind: core.JobMaintBlobGC}, &ref); err != nil {
					return err
				}
				j, err := waitJob(ctx, cmd, c, ref.JobID, true, "collecting")
				if err != nil {
					return err
				}
				return done(cmd, j, "garbage collection %s%s", gcResultText(j.Result), noteSuffix(j.Note))
			})
		},
	}
	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "only report what would be removed")
	durationVar(cmd.Flags(), &minAge, "min-age", 48*time.Hour, "only collect data older than this, at least 15m (needs --offline or --dry-run)")
	return cmd
}

// gcResultText formats the result of a maintenance.blob_gc job (see
// internal/files/jobs.go) for the success line.
func gcResultText(raw json.RawMessage) string {
	var r struct {
		Removed      int64 `json:"gc_removed"`
		Freed        int64 `json:"gc_freed_bytes"`
		Unreferenced int64 `json:"unreferenced_deleted"`
	}
	if len(raw) == 0 || json.Unmarshal(raw, &r) != nil {
		return "finished"
	}
	s := fmt.Sprintf("removed %s, freed %s", Plural(r.Removed, "blob"), HumanBytes(r.Freed))
	if r.Unreferenced > 0 {
		s += fmt.Sprintf(" (%s no longer referenced)", Plural(r.Unreferenced, "blob"))
	}
	return s
}
