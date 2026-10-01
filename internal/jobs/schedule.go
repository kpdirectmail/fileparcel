package jobs

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"fileparcel/internal/core"
	"fileparcel/internal/db"
	"fileparcel/internal/ids"
	"fileparcel/internal/jobs/cron"
)

// maxScheduleName bounds schedule names (they are primary keys and appear in
// job rows).
const maxScheduleName = 100

// Schedule implements core.Jobs: it creates or replaces the schedule name,
// which enqueues a job of kind with params at every activation of cronSpec
// (5-field cron or descriptor; local time). An unchanged schedule keeps its
// next run time (so a run missed while the server was down still happens
// once after start); a changed spec recomputes it. It may be called before
// Start and before kind is registered (unknown kinds are skipped at run time).
// It must not be called inside a database write transaction.
func (s *Service) Schedule(name, cronSpec, kind string, params any) error {
	name = strings.TrimSpace(name)
	if name == "" || len(name) > maxScheduleName {
		return core.Invalid("name", "schedule name must be 1-100 characters")
	}
	if kind == "" {
		return core.Invalid("kind", "job kind required")
	}
	sc, err := cron.Parse(cronSpec)
	if err != nil {
		return core.Invalid("cron", err.Error())
	}
	raw, err := marshalParams(params)
	if err != nil {
		return err
	}
	spec := sc.String()
	now := s.env.Now()
	next := sc.Next(now.In(s.loc))
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	err = s.env.DB.Tx(ctx, func(tx *sql.Tx) error {
		var oldCron, oldKind, oldParams string
		var enabled int64
		var oldNext sql.NullInt64
		err := tx.QueryRowContext(ctx, `SELECT cron, kind, params, enabled, next_run_at FROM schedules WHERE name = ?`, name).
			Scan(&oldCron, &oldKind, &oldParams, &enabled, &oldNext)
		switch {
		case db.IsNoRows(err):
			_, err = tx.ExecContext(ctx, `INSERT INTO schedules (name, cron, kind, params, enabled, next_run_at)
				VALUES (?, ?, ?, ?, 1, ?)`, name, spec, kind, string(raw), nullNext(next))
			return err
		case err != nil:
			return err
		}
		if oldCron == spec && oldKind == kind && oldParams == string(raw) && enabled == 1 && oldNext.Valid {
			return nil // unchanged: keep the pending next run
		}
		nextVal := nullNext(next)
		if oldCron == spec && enabled == 1 && oldNext.Valid {
			nextVal = oldNext // same timing, different kind/params
		}
		_, err = tx.ExecContext(ctx, `UPDATE schedules SET cron = ?, kind = ?, params = ?, enabled = 1, next_run_at = ?
			WHERE name = ?`, spec, kind, string(raw), nextVal, name)
		return err
	})
	if err != nil {
		return fmt.Errorf("jobs: schedule %s: %w", name, err)
	}
	s.signal(s.schedWake)
	return nil
}

func nullNext(t time.Time) sql.NullInt64 {
	if t.IsZero() {
		return sql.NullInt64{}
	}
	return sql.NullInt64{Int64: db.Ms(t), Valid: true}
}

// Unschedule implements core.Jobs: removes the schedule (no-op when absent).
// Jobs it already enqueued are not affected.
func (s *Service) Unschedule(name string) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if _, err := s.env.DB.Exec(ctx, `DELETE FROM schedules WHERE name = ?`, name); err != nil {
		s.log.Error("jobs: unschedule", "schedule", name, "err", err)
		return
	}
	s.signal(s.schedWake)
}

// Schedules implements core.Jobs: every schedule, by name.
func (s *Service) Schedules(ctx context.Context) ([]core.JobSchedule, error) {
	rows, err := s.env.DB.Query(ctx, `SELECT name, cron, kind, params, enabled, last_run_at, next_run_at, last_job_id
		FROM schedules ORDER BY name`)
	if err != nil {
		return nil, fmt.Errorf("jobs: schedules: %w", err)
	}
	defer rows.Close()
	out := []core.JobSchedule{}
	for rows.Next() {
		var (
			js         core.JobSchedule
			params     string
			enabled    int64
			last, next sql.NullInt64
			lastJob    sql.NullString
		)
		if err := rows.Scan(&js.Name, &js.Cron, &js.Kind, &params, &enabled, &last, &next, &lastJob); err != nil {
			return nil, fmt.Errorf("jobs: schedules: %w", err)
		}
		if params != "" && params != "{}" {
			js.Params = json.RawMessage(params)
		}
		js.Enabled = enabled != 0
		js.LastRunAt = db.FromNullMs(last)
		js.NextRunAt = db.FromNullMs(next)
		js.LastJobID = lastJob.String
		out = append(out, js)
	}
	return out, rows.Err()
}

// initSchedules (Start) computes next_run_at for enabled schedules that have
// none (created while their spec was invalid, or by an older version).
func (s *Service) initSchedules(ctx context.Context) error {
	type row struct{ name, spec string }
	var todo []row
	rows, err := s.env.DB.Query(ctx, `SELECT name, cron FROM schedules WHERE enabled = 1 AND next_run_at IS NULL`)
	if err != nil {
		return fmt.Errorf("jobs: read schedules: %w", err)
	}
	for rows.Next() {
		var r row
		if err := rows.Scan(&r.name, &r.spec); err != nil {
			rows.Close()
			return fmt.Errorf("jobs: read schedules: %w", err)
		}
		todo = append(todo, r)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return fmt.Errorf("jobs: read schedules: %w", err)
	}
	if len(todo) == 0 {
		return nil
	}
	now := s.env.Now().In(s.loc)
	return s.env.DB.Tx(ctx, func(tx *sql.Tx) error {
		for _, r := range todo {
			sc, err := cron.Parse(r.spec)
			if err != nil {
				s.log.Warn("jobs: invalid schedule ignored", "schedule", r.name, "cron", r.spec, "err", err)
				continue
			}
			if _, err := tx.ExecContext(ctx, `UPDATE schedules SET next_run_at = ? WHERE name = ?`,
				nullNext(sc.Next(now)), r.name); err != nil {
				return err
			}
		}
		return nil
	})
}

// schedLoop enqueues due schedules. It sleeps until the earliest next run
// (bounded by schedMaxSleep) or until woken by Schedule/Unschedule.
func (s *Service) schedLoop() {
	defer s.loops.Done()
	for {
		wait := s.runDue(s.runCtx)
		if wait > schedMaxSleep || wait <= 0 {
			wait = schedMaxSleep
		}
		t := time.NewTimer(wait)
		select {
		case <-s.runCtx.Done():
			t.Stop()
			return
		case <-s.schedWake:
		case <-t.C:
		}
		t.Stop()
	}
}

type dueSchedule struct {
	name, spec, kind, params string
	lastJob                  sql.NullString
}

// runDue enqueues every due schedule and returns the time until the next one
// (0 = none known).
func (s *Service) runDue(ctx context.Context) time.Duration {
	now := s.env.Now()
	rows, err := s.env.DB.Query(ctx, `SELECT name, cron, kind, params, last_job_id FROM schedules
		WHERE enabled = 1 AND next_run_at IS NOT NULL AND next_run_at <= ? ORDER BY next_run_at, name`, db.Ms(now))
	if err != nil {
		if ctx.Err() == nil {
			s.log.Error("jobs: read due schedules", "err", err)
		}
		return 0
	}
	var due []dueSchedule
	for rows.Next() {
		var d dueSchedule
		if err := rows.Scan(&d.name, &d.spec, &d.kind, &d.params, &d.lastJob); err != nil {
			s.log.Error("jobs: read due schedules", "err", err)
			break
		}
		due = append(due, d)
	}
	rows.Close()
	if err := rows.Err(); err != nil && ctx.Err() == nil {
		s.log.Error("jobs: read due schedules", "err", err)
	}
	for _, d := range due {
		if ctx.Err() != nil {
			return 0
		}
		s.fire(ctx, d, now)
	}
	var next sql.NullInt64
	if err := s.env.DB.QueryRow(ctx, `SELECT min(next_run_at) FROM schedules WHERE enabled = 1`).Scan(&next); err != nil || !next.Valid {
		return 0
	}
	wait := db.FromMs(next.Int64).Sub(s.env.Now())
	if wait < time.Second {
		wait = time.Second
	}
	return wait
}

// fire enqueues one due schedule and advances its next run in the same
// transaction. The run is skipped when the kind is unknown or when the job
// of the previous activation is still queued or running.
func (s *Service) fire(ctx context.Context, d dueSchedule, now time.Time) {
	sc, parseErr := cron.Parse(d.spec)
	var next sql.NullInt64
	if parseErr == nil {
		next = nullNext(sc.Next(now.In(s.loc)))
	} else {
		s.log.Warn("jobs: invalid schedule disabled until changed", "schedule", d.name, "err", parseErr)
	}
	known := s.kind(d.kind) != nil
	if !known {
		s.mu.Lock()
		first := !s.warned[d.name]
		s.warned[d.name] = true
		s.mu.Unlock()
		if first {
			s.log.Warn("jobs: schedule names an unregistered job kind; skipped", "schedule", d.name, "kind", d.kind)
		}
	}
	jobID := ""
	err := s.env.DB.Tx(ctx, func(tx *sql.Tx) error {
		jobID = ""
		run := known && parseErr == nil
		if run && d.lastJob.Valid {
			var st string
			e := tx.QueryRowContext(ctx, `SELECT state FROM jobs WHERE id = ?`, d.lastJob.String).Scan(&st)
			if e == nil && (st == core.JobQueued || st == core.JobRunning) {
				run = false
				s.log.Info("jobs: previous scheduled run still active; skipping", "schedule", d.name, "job", d.lastJob.String)
			} else if e != nil && !db.IsNoRows(e) {
				return e
			}
		}
		if run {
			jobID = ids.New(ids.PrefixJob)
			if _, e := tx.ExecContext(ctx, `INSERT INTO jobs (id, kind, state, params, schedule, created_at)
				VALUES (?, ?, 'queued', ?, ?, ?)`, jobID, d.kind, d.params, d.name, db.Ms(now)); e != nil {
				return e
			}
			_, e := tx.ExecContext(ctx, `UPDATE schedules SET next_run_at = ?, last_run_at = ?, last_job_id = ? WHERE name = ?`,
				next, db.Ms(now), jobID, d.name)
			return e
		}
		_, e := tx.ExecContext(ctx, `UPDATE schedules SET next_run_at = ? WHERE name = ?`, next, d.name)
		return e
	})
	if err != nil {
		if ctx.Err() == nil {
			s.log.Error("jobs: run schedule", "schedule", d.name, "err", err)
		}
		return
	}
	if jobID != "" {
		s.log.Debug("jobs: scheduled job enqueued", "schedule", d.name, "kind", d.kind, "job", jobID)
		s.signal(s.wake)
	}
}
