package jobs

import (
	"context"
	"database/sql"
	"encoding/json"
	"testing"
	"time"

	"fileparcel/internal/core"
	"fileparcel/internal/db"
)

// TestDBOptimizePrunesShareAccessLog pins the retention of share access logs
// (sharing.access_log_days, applied by maintenance.db_optimize): the rows
// carry visitors' IP addresses and every visit of a public link adds one,
// so they must not be kept forever.
func TestDBOptimizePrunesShareAccessLog(t *testing.T) {
	te := newTestEnv(t)
	ctx := context.Background()
	now := time.Now()
	old, recent := db.Ms(now.Add(-400*24*time.Hour)), db.Ms(now.Add(-24*time.Hour))
	const oldRows = deleteBatch + 5 // more than one delete transaction
	err := te.env.DB.Tx(ctx, func(tx *sql.Tx) error {
		for _, q := range []string{
			`INSERT INTO users (id, username, role, webauthn_handle, created_at, updated_at)
				VALUES ('usr_1', 'u1', 'member', x'01', 1, 1)`,
			`INSERT INTO spaces (id, kind, owner_user_id, name, created_at) VALUES ('spc_1', 'user', 'usr_1', 'u1', 1)`,
			`INSERT INTO nodes (id, space_id, kind, name, name_key, created_at, updated_at)
				VALUES ('nod_1', 'spc_1', 'folder', 'r', 'r', 1, 1)`,
			`INSERT INTO shares (id, kind, node_id, created_by, token_hash, token_enc, created_at, updated_at)
				VALUES ('shr_1', 'link', 'nod_1', 'usr_1', x'01', 'x', 1, 1)`,
		} {
			if _, err := tx.ExecContext(ctx, q); err != nil {
				return err
			}
		}
		ins := `INSERT INTO share_access_log (share_id, at, action, ip) VALUES ('shr_1', ?, 'view', '192.0.2.1')`
		for range oldRows {
			if _, err := tx.ExecContext(ctx, ins, old); err != nil {
				return err
			}
		}
		_, err := tx.ExecContext(ctx, ins, recent)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	rows := func() (n, oldest int64) {
		t.Helper()
		if err := te.env.DB.QueryRow(ctx, `SELECT COUNT(*), COALESCE(MIN(at), 0) FROM share_access_log`).Scan(&n, &oldest); err != nil {
			t.Fatal(err)
		}
		return n, oldest
	}
	run := func(settings core.Settings) DBOptimizeResult {
		t.Helper()
		te.env.Settings = settings
		j, err := te.svc.RunInline(ctx, core.JobMaintDBOptimize, nil, nil)
		if err != nil || j.State != core.JobSucceeded {
			t.Fatalf("db optimize %v %+v", err, j)
		}
		var r DBOptimizeResult
		if err := json.Unmarshal(j.Result, &r); err != nil {
			t.Fatal(err)
		}
		return r
	}

	// No settings service, or retention 0: everything is kept.
	for _, st := range []core.Settings{nil, fakeSettings{ints: map[string]int64{settingShareLogDays: 0}}} {
		if r := run(st); r.ShareLogPruned != 0 {
			t.Fatalf("retention off pruned %d rows", r.ShareLogPruned)
		}
		if n, _ := rows(); n != oldRows+1 {
			t.Fatalf("retention off: %d rows left", n)
		}
	}
	// 365 days: the old rows go (in several batches), the recent one stays.
	if r := run(fakeSettings{ints: map[string]int64{settingShareLogDays: 365}}); r.ShareLogPruned != oldRows {
		t.Fatalf("pruned %d rows, want %d", r.ShareLogPruned, oldRows)
	}
	if n, oldest := rows(); n != 1 || oldest != recent {
		t.Fatalf("after pruning: %d rows, oldest %d (want the recent one, %d)", n, oldest, recent)
	}
}
