package jobs

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"fileparcel/internal/core"
	"fileparcel/internal/db"
)

// Maintenance schedules owned by this package (DESIGN §9.7). The schedule
// name equals the job kind. Minutes are staggered so the daily jobs do not
// collide with the default backup schedules (03:00 metadata, Sunday 04:00 full).
const (
	cronSessions   = "15 * * * *" // hourly
	cronAuditPrune = "30 3 * * *" // daily (same spec as package audit, which may re-register it)
	cronDBOptimize = "45 4 * * *" // daily
)

// Retention of the session and ticket rows removed by maintenance.sessions.
const (
	sessionGrace = 7 * 24 * time.Hour // expired/revoked sessions are kept this long (visible in "sessions")
	ticketGrace  = time.Hour          // expired or used archive tickets
	deleteBatch  = 1000               // rows per delete transaction
)

// Default retention for audit rows when no Settings service is available.
const defaultAuditRetentionDays = 365

// settingAuditRetention is owned (registered) by package audit.
const settingAuditRetention = "audit.retention_days"

// settingShareLogDays is owned (registered) by package shares: the age after
// which maintenance.db_optimize deletes share access-log rows (0 = keep).
const settingShareLogDays = "sharing.access_log_days"

// SessionsResult is the result of maintenance.sessions.
type SessionsResult struct {
	Sessions int64 `json:"sessions"`
	Tickets  int64 `json:"tickets"`
}

// AuditPruneResult is the result of maintenance.audit_prune.
type AuditPruneResult struct {
	Pruned        int    `json:"pruned"`
	RetentionDays int64  `json:"retention_days"`
	Skipped       string `json:"skipped,omitempty"`
}

// DBOptimizeResult is the result of maintenance.db_optimize.
// CheckpointTruncated is false when SQLite reported the truncating
// checkpoint as busy (readers were active): the journal was not truncated,
// so the doctor's "database.wal" warning stays until a later run succeeds.
type DBOptimizeResult struct {
	CheckpointBusy      int64 `json:"checkpoint_busy"`
	CheckpointLog       int64 `json:"checkpoint_log"`
	CheckpointedPages   int64 `json:"checkpointed_pages"`
	CheckpointTruncated bool  `json:"checkpoint_truncated"`
	JobsPruned          int64 `json:"jobs_pruned"`
	ShareLogPruned      int64 `json:"share_log_pruned"`
}

// msgCheckpointBusy is the note maintenance.db_optimize records when
// PRAGMA wal_checkpoint(TRUNCATE) came back busy. SQLite reports that in the
// first column of the result row, not as an error, so the job would
// otherwise look completely successful while the journal is unchanged.
const msgCheckpointBusy = "the write-ahead log could not be truncated: readers were active; run this job again when the server is idle"

// registerMaintenance registers and schedules the maintenance kinds this
// package owns. Other packages may re-register a kind (the later
// registration wins silently for these built-ins).
func (s *Service) registerMaintenance() error {
	defs := []struct {
		kind, spec string
		fn         core.JobFunc
		opts       core.JobOptions
	}{
		{core.JobMaintSessions, cronSessions, s.jobSessions, core.JobOptions{Exclusive: "maintenance.sessions", Timeout: 30 * time.Minute, Hidden: true}},
		{core.JobMaintAuditPrune, cronAuditPrune, s.jobAuditPrune, core.JobOptions{Exclusive: "audit", Timeout: time.Hour}},
		{core.JobMaintDBOptimize, cronDBOptimize, s.jobDBOptimize, core.JobOptions{Exclusive: "maintenance.db", Timeout: 30 * time.Minute}},
	}
	for _, d := range defs {
		s.mu.Lock()
		s.kinds[d.kind] = &kindDef{kind: d.kind, fn: d.fn, opts: d.opts, builtin: true}
		s.mu.Unlock()
		if err := s.Schedule(d.kind, d.spec, d.kind, nil); err != nil {
			return err
		}
	}
	return nil
}

// deleteBatched runs a DELETE … WHERE rowid IN (SELECT … LIMIT n) statement
// repeatedly (short write transactions) until it affects no rows.
func (s *Service) deleteBatched(ctx context.Context, query string, args ...any) (int64, error) {
	var total int64
	for {
		if err := ctx.Err(); err != nil {
			return total, err
		}
		var n int64
		err := s.env.DB.Tx(ctx, func(tx *sql.Tx) error {
			res, err := tx.ExecContext(ctx, query, append(args, deleteBatch)...)
			if err != nil {
				return err
			}
			n, err = res.RowsAffected()
			return err
		})
		if err != nil {
			return total, err
		}
		total += n
		if n < deleteBatch {
			return total, nil
		}
	}
}

// jobSessions deletes sessions that expired or were revoked more than a week
// ago and archive tickets that expired (or were used) more than an hour ago.
func (s *Service) jobSessions(ctx context.Context, h core.JobHandle) error {
	now := s.env.Now()
	cut := db.Ms(now.Add(-sessionGrace))
	sessions, err := s.deleteBatched(ctx, `DELETE FROM sessions WHERE id IN (SELECT id FROM sessions
		WHERE expires_at < ? OR idle_expires_at < ? OR (revoked_at IS NOT NULL AND revoked_at < ?) LIMIT ?)`, cut, cut, cut)
	if err != nil {
		return err
	}
	h.Progress(1, 2, "sessions")
	tcut := db.Ms(now.Add(-ticketGrace))
	tickets, err := s.deleteBatched(ctx, `DELETE FROM archive_tickets WHERE id_hash IN (SELECT id_hash FROM archive_tickets
		WHERE expires_at < ? OR (used_at IS NOT NULL AND used_at < ?) LIMIT ?)`, tcut, tcut)
	if err != nil {
		return err
	}
	h.Progress(2, 2, "archive tickets")
	h.SetResult(SessionsResult{Sessions: sessions, Tickets: tickets})
	return nil
}

// jobAuditPrune applies audit.retention_days (0 = keep forever).
func (s *Service) jobAuditPrune(ctx context.Context, h core.JobHandle) error {
	if s.env.Audit == nil {
		h.SetResult(AuditPruneResult{Skipped: "audit service unavailable"})
		return nil
	}
	days := int64(defaultAuditRetentionDays)
	if s.env.Settings != nil {
		days = s.env.Settings.Int(settingAuditRetention)
	}
	if days <= 0 {
		h.SetResult(AuditPruneResult{Skipped: "retention disabled", RetentionDays: days})
		return nil
	}
	before := s.env.Now().Add(-time.Duration(days) * 24 * time.Hour)
	n, err := s.env.Audit.Prune(ctx, before)
	if errors.Is(err, core.ErrKeysLocked) {
		h.SetResult(AuditPruneResult{Skipped: "keys locked", RetentionDays: days})
		return nil
	}
	h.SetResult(AuditPruneResult{Pruned: n, RetentionDays: days})
	return err
}

// jobDBOptimize runs PRAGMA optimize and a truncating WAL checkpoint, and
// prunes finished job rows older than finishedRetention and share
// access-log rows older than sharing.access_log_days.
func (s *Service) jobDBOptimize(ctx context.Context, h core.JobHandle) error {
	var res DBOptimizeResult
	cut := db.Ms(s.env.Now().Add(-finishedRetention))
	n, err := s.deleteBatched(ctx, `DELETE FROM jobs WHERE id IN (SELECT id FROM jobs
		WHERE state IN ('succeeded','failed','canceled') AND finished_at IS NOT NULL AND finished_at < ? LIMIT ?)`, cut)
	if err != nil {
		return err
	}
	res.JobsPruned = n
	// Share access logs hold visitors' IP addresses and grow with every
	// visit of a public link; nothing else ever deletes them but the
	// deletion of the link. Rows are appended in time order, so the oldest
	// are the lowest ids.
	if s.env.Settings != nil {
		if days := s.env.Settings.Int(settingShareLogDays); days > 0 {
			scut := db.Ms(s.env.Now().Add(-time.Duration(days) * 24 * time.Hour))
			if res.ShareLogPruned, err = s.deleteBatched(ctx, `DELETE FROM share_access_log WHERE id IN
				(SELECT id FROM share_access_log WHERE at < ? LIMIT ?)`, scut); err != nil {
				return err
			}
		}
	}
	h.Progress(1, 3, "jobs and share access logs pruned")
	w := s.env.DB.Writer()
	if _, err := w.ExecContext(ctx, `PRAGMA optimize`); err != nil {
		return err
	}
	h.Progress(2, 3, "optimized")
	if err := w.QueryRowContext(ctx, `PRAGMA wal_checkpoint(TRUNCATE)`).
		Scan(&res.CheckpointBusy, &res.CheckpointLog, &res.CheckpointedPages); err != nil {
		return err
	}
	res.CheckpointTruncated = res.CheckpointBusy == 0
	note := "checkpointed"
	if !res.CheckpointTruncated {
		note = msgCheckpointBusy
		s.log.Warn("jobs: wal_checkpoint(TRUNCATE) was busy", "wal_pages", res.CheckpointLog,
			"checkpointed_pages", res.CheckpointedPages)
	}
	h.Progress(3, 3, note)
	h.SetResult(res)
	return nil
}
