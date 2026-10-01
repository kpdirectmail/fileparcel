package db

import (
	"context"
	"database/sql"
	"path/filepath"
	"slices"
	"testing"
	"time"
)

// TestFTSNameKeyMigration: 0004_fts_name_key moves the search index from
// nodes.name to nodes.name_key (the full case fold names are compared with)
// and fills it for the rows a version-1 database already holds.
func TestFTSNameKeyMigration(t *testing.T) {
	ctx := context.Background()
	d, err := Open(filepath.Join(t.TempDir(), "v1.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.Close() })
	ms, err := Migrations()
	if err != nil || len(ms) < 2 || ms[0].Version != 1 {
		t.Fatalf("migrations %v %v", len(ms), err)
	}
	fts := slices.IndexFunc(ms, func(m Migration) bool { return m.Name == "fts_name_key" })
	if fts < 0 || ms[fts].Version != 4 {
		t.Fatalf("no fts_name_key migration at version 4: %v", fts)
	}
	// A database at version 1, with a node in it.
	if _, err := d.Writer().ExecContext(ctx, createMigrationsTable); err != nil {
		t.Fatal(err)
	}
	if err := d.Tx(ctx, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, ms[0].SQL); err != nil {
			return err
		}
		_, err := tx.ExecContext(ctx, `INSERT INTO schema_migrations(version, name, applied_at) VALUES (1, ?, 0)`, ms[0].Name)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	_, root := seed(t, d)
	now := Ms(time.Now())
	if _, err := d.Exec(ctx, `INSERT INTO nodes(id, space_id, parent_id, kind, name, name_key, created_at, updated_at)
		VALUES ('nod_s', 'spc_1', ?, 'file', 'Straße.txt', 'strasse.txt', ?, ?)`, root, now, now); err != nil {
		t.Fatal(err)
	}
	if got := search(t, d, "strasse"); len(got) != 0 {
		t.Fatalf("the version-1 index (on name) matched the folded name: %v", got)
	}

	applied, err := d.Migrate(ctx)
	if err != nil || !slices.Equal(applied, []int{2, 3, 4}) {
		t.Fatalf("migrate: %v %v", applied, err)
	}
	for _, q := range []string{"strasse", "STRASSE", "asse.t"} {
		if got := search(t, d, q); !slices.Equal(got, []string{"nod_s"}) {
			t.Errorf("search %q after the migration: %v", q, got)
		}
	}
	// New rows and renames keep the index in sync through the new triggers.
	if _, err := d.Exec(ctx, `UPDATE nodes SET name = 'Größe.txt', name_key = 'grösse.txt' WHERE id = 'nod_s'`); err != nil {
		t.Fatal(err)
	}
	if got := search(t, d, "strasse"); len(got) != 0 {
		t.Fatalf("stale index entry after a rename: %v", got)
	}
	if got := search(t, d, "GRÖSSE"); !slices.Equal(got, []string{"nod_s"}) {
		t.Fatalf("renamed node not found: %v", got)
	}
	if _, err := d.Exec(ctx, `INSERT INTO nodes_fts(nodes_fts, rank) VALUES('integrity-check', 1)`); err != nil {
		t.Fatalf("fts integrity: %v", err)
	}
}
