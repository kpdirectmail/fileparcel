// Package jobs is the persistent job queue, runner, cron-lite scheduler and
// the maintenance jobs (DESIGN §9.7). Owned by unit H.
//
// Jobs are rows of the jobs table. Enqueue inserts a queued row; once Start
// has run, a dispatcher claims queued rows and runs them on a worker pool
// bounded by GOMAXPROCS (minimum 2), honouring each kind's MaxConcurrent
// (0 = 1), Exclusive lock group and Timeout. Progress is kept in memory and
// flushed to the database (and published as job.progress) at most once per
// second; the final state is written when the job returns and published as
// job.done. Cancel cancels the job's context. Jobs left "running" by a
// crashed process are marked failed ("interrupted") by Start.
//
// Register and Schedule may be called before Start (services register their
// kinds while being wired). Schedule persists the schedule in the schedules
// table; Start computes missing next-run times and runs the scheduler loop,
// which enqueues due schedules (a schedule missed while the server was down
// runs once, soon after start). Cron specs use package cron and local time.
//
// In ModeOffline wire.Start never calls Start: Enqueue then only persists
// queued jobs (they run at the next server start). Callers that need the
// result right away use RunInline (see Running).
package jobs

import (
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"runtime"
	"runtime/debug"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode/utf8"

	"fileparcel/internal/core"
	"fileparcel/internal/db"
	"fileparcel/internal/events"
	"fileparcel/internal/ids"
)

// Tunables (variables so tests can shorten them).
var (
	// progressInterval throttles progress writes and job.progress events.
	progressInterval = time.Second
	// pollInterval is the dispatcher's safety-net poll (it is normally woken
	// by Enqueue and by finishing jobs).
	pollInterval = 5 * time.Second
	// schedMaxSleep bounds the scheduler's sleep so wall-clock jumps (NTP,
	// suspend, DST) are noticed quickly.
	schedMaxSleep = time.Minute
	// finishedRetention is how long finished job rows are kept
	// (maintenance.db_optimize prunes older ones).
	finishedRetention = 30 * 24 * time.Hour
)

// Bounds of the stored error message and progress note (bytes).
const (
	maxErrorLen = 2000
	maxNoteLen  = 500
)

// Error message stored for jobs interrupted by a crash or shutdown.
const (
	msgInterrupted = "interrupted (the server stopped while the job was running)"
	msgShutdown    = "interrupted by server shutdown"
)

// Service implements core.Jobs.
type Service struct {
	env     *core.Env
	log     *slog.Logger
	loc     *time.Location // cron wall clock (time.Local)
	workers int

	mu        sync.Mutex
	kinds     map[string]*kindDef
	running   map[string]*runningJob // by job id
	canceling map[string]bool        // ids a Cancel call is working on (see Cancel)
	perKind   map[string]int         // running count per kind
	locks     map[string]string      // exclusive group → job id
	started   bool
	stopping  bool
	runCtx    context.Context
	runCancel context.CancelFunc
	loops     sync.WaitGroup // dispatcher, scheduler, progress flusher
	jobsWG    sync.WaitGroup // running job goroutines
	wake      chan struct{}
	schedWake chan struct{}
	warned    map[string]bool // unknown schedule kinds already logged
}

var _ core.Jobs = (*Service)(nil)

type kindDef struct {
	kind    string
	fn      core.JobFunc
	opts    core.JobOptions
	builtin bool // registered by this package; replaced silently
}

func (k *kindDef) maxConcurrent() int {
	if k.opts.MaxConcurrent <= 0 {
		return 1
	}
	return k.opts.MaxConcurrent
}

// New creates the service (constructor signature fixed by DESIGN §5.2) and
// registers and schedules the maintenance jobs it owns
// (maintenance.sessions, maintenance.audit_prune, maintenance.db_optimize).
func New(env *core.Env) (*Service, error) {
	if env == nil || env.DB == nil {
		return nil, errors.New("jobs: env with a database required")
	}
	log := env.Log
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	s := &Service{
		env:       env,
		log:       log.With("svc", "jobs"),
		loc:       time.Local,
		workers:   max(2, runtime.GOMAXPROCS(0)),
		kinds:     map[string]*kindDef{},
		running:   map[string]*runningJob{},
		canceling: map[string]bool{},
		perKind:   map[string]int{},
		locks:     map[string]string{},
		wake:      make(chan struct{}, 1),
		schedWake: make(chan struct{}, 1),
		warned:    map[string]bool{},
	}
	if err := s.registerMaintenance(); err != nil {
		return nil, err
	}
	return s, nil
}

// ---------- registry ----------

// Register implements core.Jobs. Registering a kind twice replaces the
// earlier definition (logged). It may be called before or after Start.
func (s *Service) Register(kind string, fn core.JobFunc, o core.JobOptions) {
	if kind == "" || fn == nil {
		s.log.Error("jobs: invalid registration", "kind", kind)
		return
	}
	s.mu.Lock()
	if old, dup := s.kinds[kind]; dup && !old.builtin {
		s.log.Warn("jobs: kind registered twice; the later registration wins", "kind", kind)
	}
	s.kinds[kind] = &kindDef{kind: kind, fn: fn, opts: o}
	s.mu.Unlock()
	s.signal(s.wake)
}

// Registered reports whether kind has a registered function.
func (s *Service) Registered(kind string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.kinds[kind] != nil
}

// Kinds returns the registered kinds, sorted.
func (s *Service) Kinds() []string {
	s.mu.Lock()
	out := make([]string, 0, len(s.kinds))
	for k := range s.kinds {
		out = append(out, k)
	}
	s.mu.Unlock()
	slices.Sort(out)
	return out
}

// Running reports whether the runner has been started and not stopped, i.e.
// whether enqueued jobs will be executed by this process.
func (s *Service) Running() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.started && !s.stopping
}

func (s *Service) kind(kind string) *kindDef {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.kinds[kind]
}

// hiddenKinds returns the registered kinds marked Hidden, split into the
// ones an administrator may start by hand (core.RunnableJobKinds, so a run
// someone asked for is never swallowed) and the rest. Both are sorted.
func (s *Service) hiddenKinds() (all, runnable []string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for k, d := range s.kinds {
		if !d.opts.Hidden {
			continue
		}
		all = append(all, k)
		if slices.Contains(core.RunnableJobKinds, k) {
			runnable = append(runnable, k)
		}
	}
	slices.Sort(all)
	slices.Sort(runnable)
	return all, runnable
}

func (s *Service) signal(ch chan struct{}) {
	select {
	case ch <- struct{}{}:
	default:
	}
}

// ---------- queue ----------

// Enqueue implements core.Jobs: it persists a queued job and wakes the
// dispatcher. The kind must be registered. It must not be called inside a
// database write transaction (single writer).
func (s *Service) Enqueue(ctx context.Context, kind string, params any, by *core.Principal) (string, error) {
	if s.kind(kind) == nil {
		return "", core.Invalid("kind", fmt.Sprintf("unknown job kind %q", kind))
	}
	raw, err := marshalParams(params)
	if err != nil {
		return "", err
	}
	id := ids.New(ids.PrefixJob)
	now := s.env.Now()
	err = s.env.DB.Tx(ctx, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `INSERT INTO jobs (id, kind, state, params, created_by, created_at)
			VALUES (?, ?, 'queued', ?, ?, ?)`, id, kind, string(raw), db.NullString(userOf(by)), db.Ms(now))
		return err
	})
	if err != nil {
		return "", fmt.Errorf("jobs: enqueue %s: %w", kind, err)
	}
	s.signal(s.wake)
	return id, nil
}

// RunInline creates a job row and runs it synchronously in the calling
// goroutine (waiting for its Exclusive group and MaxConcurrent slot), then
// returns the finished job. It works whether or not the runner is started
// and is meant for the offline CLI (where no runner executes queued jobs)
// and for tests. The job's context derives from ctx.
func (s *Service) RunInline(ctx context.Context, kind string, params any, by *core.Principal) (*core.Job, error) {
	def := s.kind(kind)
	if def == nil {
		return nil, core.Invalid("kind", fmt.Sprintf("unknown job kind %q", kind))
	}
	raw, err := marshalParams(params)
	if err != nil {
		return nil, err
	}
	id := ids.New(ids.PrefixJob)
	now := s.env.Now()
	// Wait for a slot (Exclusive / MaxConcurrent); the pool size is not
	// enforced for inline runs (the caller's goroutine does the work).
	for {
		s.mu.Lock()
		if s.stopping {
			s.mu.Unlock()
			return nil, core.Errorf(core.ErrUnavailable, "the job runner is shutting down")
		}
		if s.canStartLocked(def, false) {
			rj := s.reserveLocked(def, id, userOf(by), raw)
			s.mu.Unlock()
			err := s.env.DB.Tx(ctx, func(tx *sql.Tx) error {
				_, err := tx.ExecContext(ctx, `INSERT INTO jobs (id, kind, state, params, created_by, attempts, created_at, started_at)
					VALUES (?, ?, 'running', ?, ?, 1, ?, ?)`, id, kind, string(raw), db.NullString(userOf(by)), db.Ms(now), db.Ms(now))
				return err
			})
			if err != nil {
				s.release(rj)
				s.jobsWG.Done()
				return nil, fmt.Errorf("jobs: run %s: %w", kind, err)
			}
			rj.startedAt = now
			rj.createdAt = now
			s.execute(ctx, def, rj)
			return s.Get(context.WithoutCancel(ctx), id)
		}
		s.mu.Unlock()
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(100 * time.Millisecond):
		}
	}
}

func marshalParams(params any) (json.RawMessage, error) {
	switch p := params.(type) {
	case nil:
		return json.RawMessage(`{}`), nil
	case json.RawMessage:
		if len(p) == 0 || string(p) == "null" {
			return json.RawMessage(`{}`), nil
		}
		if !json.Valid(p) {
			return nil, core.Invalid("params", "params must be valid JSON")
		}
		return p, nil
	}
	b, err := json.Marshal(params)
	if err != nil {
		return nil, core.Invalid("params", "params cannot be encoded: "+err.Error())
	}
	if string(b) == "null" {
		return json.RawMessage(`{}`), nil
	}
	return b, nil
}

func userOf(p *core.Principal) string {
	if p == nil {
		return ""
	}
	return p.UserID
}

// ---------- reading ----------

const jobCols = `id, kind, state, params, result, error, progress_done, progress_total, note,
	created_by, schedule, attempts, created_at, started_at, finished_at`

func scanJob(sc interface{ Scan(...any) error }) (*core.Job, error) {
	var (
		j                                  core.Job
		params                             string
		result, errStr, note, by, schedule sql.NullString
		createdAt                          int64
		startedAt, finishedAt              sql.NullInt64
	)
	if err := sc.Scan(&j.ID, &j.Kind, &j.State, &params, &result, &errStr, &j.ProgressDone, &j.ProgressTotal,
		&note, &by, &schedule, &j.Attempts, &createdAt, &startedAt, &finishedAt); err != nil {
		return nil, err
	}
	if params != "" && params != "{}" {
		j.Params = json.RawMessage(params)
	}
	if result.Valid && result.String != "" {
		j.Result = json.RawMessage(result.String)
	}
	j.Error, j.Note, j.CreatedBy, j.Schedule = errStr.String, note.String, by.String, schedule.String
	j.CreatedAt = db.FromMs(createdAt)
	j.StartedAt = db.FromNullMs(startedAt)
	j.FinishedAt = db.FromNullMs(finishedAt)
	return &j, nil
}

// Get implements core.Jobs. Progress of a job running in this process is
// taken from memory (the stored value lags by up to a second).
func (s *Service) Get(ctx context.Context, id string) (*core.Job, error) {
	if !ids.Valid(ids.PrefixJob, id) {
		return nil, core.NotFoundf("job not found")
	}
	j, err := scanJob(s.env.DB.QueryRow(ctx, `SELECT `+jobCols+` FROM jobs WHERE id = ?`, id))
	if db.IsNoRows(err) {
		return nil, core.NotFoundf("job not found")
	}
	if err != nil {
		return nil, fmt.Errorf("jobs: get: %w", err)
	}
	s.overlay(j)
	return j, nil
}

func (s *Service) overlay(j *core.Job) {
	if j.State != core.JobRunning {
		return
	}
	s.mu.Lock()
	rj := s.running[j.ID]
	s.mu.Unlock()
	if rj != nil {
		rj.mu.Lock()
		j.ProgressDone, j.ProgressTotal, j.Note = rj.done, rj.total, rj.note
		rj.mu.Unlock()
	}
}

type jobCursor struct {
	T  int64  `json:"t"`
	ID string `json:"id"`
}

// List implements core.Jobs: newest first, keyset-paginated.
//
// Hidden kinds (routine housekeeping such as maintenance.sessions or
// thumbs.generate) are left out so the list is not drowned in them — but only
// for runs nobody asked for and nobody has to act on. A job of a hidden kind
// is still listed when q.Kind names the kind, when it failed, and when it was
// started by hand rather than automatically (created_by set, or an unattended
// non-scheduled run of a kind of core.RunnableJobKinds: "fileparcel jobs run"
// over the admin socket has no user).
//
// The "failed" rule keeps this list in step with the failed-job counts of
// GET /admin/dashboard and the doctor, which aggregate over every kind: a
// warning there must always lead to rows here.
func (s *Service) List(ctx context.Context, q core.JobQuery) (core.Page[core.Job], error) {
	where := []string{"1=1"}
	var args []any
	if q.Kind != "" {
		where = append(where, "kind = ?")
		args = append(args, q.Kind)
	} else if hidden, handRunnable := s.hiddenKinds(); len(hidden) > 0 {
		cond := "kind NOT IN (" + placeholders(len(hidden)) + ") OR state = 'failed' OR created_by IS NOT NULL"
		for _, h := range hidden {
			args = append(args, h)
		}
		if len(handRunnable) > 0 {
			cond += " OR (schedule IS NULL AND kind IN (" + placeholders(len(handRunnable)) + "))"
			for _, h := range handRunnable {
				args = append(args, h)
			}
		}
		where = append(where, "("+cond+")")
	}
	if q.State != "" {
		switch q.State {
		case core.JobQueued, core.JobRunning, core.JobSucceeded, core.JobFailed, core.JobCanceled:
		case "active":
			where = append(where, "state IN ('queued','running')")
		default:
			return core.Page[core.Job]{}, core.Invalid("state", "unknown job state")
		}
		if q.State != "active" {
			where = append(where, "state = ?")
			args = append(args, q.State)
		}
	}
	if q.CreatedBy != "" {
		where = append(where, "created_by = ?")
		args = append(args, q.CreatedBy)
	}
	if q.Cursor != "" {
		var c jobCursor
		if err := decodeCursor(q.Cursor, &c); err != nil {
			return core.Page[core.Job]{}, err
		}
		where = append(where, "(created_at < ? OR (created_at = ? AND id < ?))")
		args = append(args, c.T, c.T, c.ID)
	}
	limit := q.EffectiveLimit()
	args = append(args, limit+1)
	rows, err := s.env.DB.Query(ctx, `SELECT `+jobCols+` FROM jobs WHERE `+strings.Join(where, " AND ")+
		` ORDER BY created_at DESC, id DESC LIMIT ?`, args...)
	if err != nil {
		return core.Page[core.Job]{}, fmt.Errorf("jobs: list: %w", err)
	}
	defer rows.Close()
	var items []core.Job
	for rows.Next() {
		j, err := scanJob(rows)
		if err != nil {
			return core.Page[core.Job]{}, fmt.Errorf("jobs: list: %w", err)
		}
		items = append(items, *j)
	}
	if err := rows.Err(); err != nil {
		return core.Page[core.Job]{}, fmt.Errorf("jobs: list: %w", err)
	}
	next := ""
	if len(items) > limit {
		items = items[:limit]
		last := items[len(items)-1]
		next = encodeCursor(jobCursor{T: db.Ms(last.CreatedAt), ID: last.ID})
	}
	for i := range items {
		s.overlay(&items[i])
	}
	return core.NewPage(items, next), nil
}

func placeholders(n int) string {
	return strings.TrimSuffix(strings.Repeat("?,", n), ",")
}

func encodeCursor(v any) string {
	b, _ := json.Marshal(v)
	return base64.RawURLEncoding.EncodeToString(b)
}

func decodeCursor(s string, v any) error {
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil || len(b) == 0 || json.Unmarshal(b, v) != nil {
		return core.Invalid("cursor", "invalid cursor")
	}
	return nil
}

// ---------- cancel ----------

// Cancel implements core.Jobs: a queued job becomes canceled at once; a
// running job's context is canceled (it ends as canceled unless it still
// succeeds). Finished jobs → ErrConflict.
func (s *Service) Cancel(ctx context.Context, id string) error {
	j, err := s.Get(ctx, id)
	if err != nil {
		return err
	}
	switch j.State {
	case core.JobSucceeded, core.JobFailed, core.JobCanceled:
		return core.Errorf(core.ErrConflict, "job already %s", j.State)
	}
	// Publish the intent before touching the row: the dispatcher may claim
	// this job (reserveLocked + UPDATE … state = 'queued') at any point from
	// here on, and reserveLocked hands the flag to the runner. Without it a
	// cancellation could be written to a row whose job is running in this
	// process and keeps running (the row would then be overwritten by the
	// real outcome when the job returns).
	s.mu.Lock()
	rj := s.running[id]
	if rj == nil {
		s.canceling[id] = true
	}
	s.mu.Unlock()
	if rj != nil {
		rj.requestCancel()
		return nil
	}
	defer func() {
		s.mu.Lock()
		delete(s.canceling, id)
		s.mu.Unlock()
	}()

	now := s.env.Now()
	var n int64
	err = s.env.DB.Tx(ctx, func(tx *sql.Tx) error {
		res, err := tx.ExecContext(ctx, `UPDATE jobs SET state = 'canceled', error = 'canceled', finished_at = ?
			WHERE id = ? AND state = 'queued'`, db.Ms(now), id)
		if err != nil {
			return err
		}
		n, err = res.RowsAffected()
		return err
	})
	if err != nil {
		return fmt.Errorf("jobs: cancel: %w", err)
	}
	if n == 0 {
		// Claimed by the dispatcher in the meantime: cancel the running job
		// (reserveLocked already set the flag; this also cancels its context).
		s.mu.Lock()
		rj = s.running[id]
		s.mu.Unlock()
		if rj != nil {
			rj.requestCancel()
			return nil
		}
		// Neither queued nor running here: a "running" row left by a crashed
		// process is stale (only one process uses a home at a time).
		err = s.env.DB.Tx(ctx, func(tx *sql.Tx) error {
			res, err := tx.ExecContext(ctx, `UPDATE jobs SET state = 'canceled', error = 'canceled', finished_at = ?
				WHERE id = ? AND state = 'running'`, db.Ms(now), id)
			if err != nil {
				return err
			}
			n, err = res.RowsAffected()
			return err
		})
		if err != nil {
			return fmt.Errorf("jobs: cancel: %w", err)
		}
		if n == 0 {
			return core.Errorf(core.ErrConflict, "job already finished")
		}
	}
	if fj, err := s.Get(context.WithoutCancel(ctx), id); err == nil {
		s.publish(events.TopicJobDone, fj)
	}
	return nil
}

// ---------- lifecycle ----------

// Start implements core.Jobs: marks jobs left running by a previous process
// as failed, computes missing schedule next-run times and starts the
// dispatcher, the scheduler and the progress flusher. Calling it twice is a
// no-op.
func (s *Service) Start(ctx context.Context) error {
	s.mu.Lock()
	if s.started {
		s.mu.Unlock()
		return nil
	}
	s.mu.Unlock()

	if err := s.recoverInterrupted(ctx); err != nil {
		return err
	}
	if err := s.initSchedules(ctx); err != nil {
		return err
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if s.started {
		return nil
	}
	s.started = true
	// The runner lives until Stop, independent of the caller's ctx
	// (wire.Start's context may be short-lived).
	s.runCtx, s.runCancel = context.WithCancel(context.WithoutCancel(ctx))
	s.loops.Add(3)
	go s.dispatchLoop()
	go s.schedLoop()
	go s.progressLoop()
	s.log.Info("jobs runner started", "workers", s.workers)
	return nil
}

func (s *Service) recoverInterrupted(ctx context.Context) error {
	now := s.env.Now()
	var n int64
	err := s.env.DB.Tx(ctx, func(tx *sql.Tx) error {
		res, err := tx.ExecContext(ctx, `UPDATE jobs SET state = 'failed', error = ?, finished_at = ?
			WHERE state = 'running'`, msgInterrupted, db.Ms(now))
		if err != nil {
			return err
		}
		n, err = res.RowsAffected()
		return err
	})
	if err != nil {
		return fmt.Errorf("jobs: recover interrupted jobs: %w", err)
	}
	if n > 0 {
		s.log.Warn("jobs interrupted by a previous shutdown marked failed", "count", n)
	}
	return nil
}

// Stop implements core.Jobs: stops dispatching and scheduling, waits for
// running jobs until ctx is done, then cancels them (they are recorded as
// failed "interrupted by server shutdown") and waits briefly for them to
// return. Safe to call without Start and more than once.
func (s *Service) Stop(ctx context.Context) error {
	s.mu.Lock()
	if !s.started || s.stopping {
		s.mu.Unlock()
		return nil
	}
	s.stopping = true
	s.mu.Unlock()

	done := make(chan struct{})
	go func() { s.jobsWG.Wait(); close(done) }()
	var err error
	select {
	case <-done:
	case <-ctx.Done():
		s.mu.Lock()
		n := len(s.running)
		s.mu.Unlock()
		s.log.Warn("jobs: canceling running jobs for shutdown", "count", n)
		s.runCancel()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			err = errors.New("jobs: some jobs did not stop in time")
			s.log.Error(err.Error())
		}
	}
	s.runCancel()
	s.loops.Wait()
	s.flushProgress(context.Background())
	return err
}

// ---------- dispatcher ----------

func (s *Service) dispatchLoop() {
	defer s.loops.Done()
	t := time.NewTicker(pollInterval)
	defer t.Stop()
	for {
		s.dispatch(s.runCtx)
		select {
		case <-s.runCtx.Done():
			return
		case <-s.wake:
		case <-t.C:
		}
	}
}

// canStartLocked reports whether a job of def may start now. pool=false
// ignores the worker pool size (RunInline).
func (s *Service) canStartLocked(def *kindDef, pool bool) bool {
	if pool && len(s.running) >= s.workers {
		return false
	}
	if s.perKind[def.kind] >= def.maxConcurrent() {
		return false
	}
	if g := def.opts.Exclusive; g != "" {
		if _, held := s.locks[g]; held {
			return false
		}
	}
	return true
}

// reserveLocked takes a slot for a job about to start (s.mu held, not
// stopping). It also adds the job to jobsWG, so that Stop, which sets
// stopping under s.mu before waiting, never races with Add; the caller must
// call jobsWG.Done (execute does) or release + jobsWG.Done on failure.
//
// A Cancel that is in flight for this id (s.canceling) is picked up here, so
// a cancellation that arrived while the job was still queued is never lost
// when the dispatcher claims it in the same window (execute re-checks the
// flag once the job context exists).
func (s *Service) reserveLocked(def *kindDef, id, createdBy string, params json.RawMessage) *runningJob {
	rj := &runningJob{s: s, id: id, kind: def.kind, createdBy: createdBy, params: params, exclusive: def.opts.Exclusive}
	if s.canceling[id] {
		rj.canceled.Store(true)
	}
	s.jobsWG.Add(1)
	s.running[id] = rj
	s.perKind[def.kind]++
	if g := def.opts.Exclusive; g != "" {
		s.locks[g] = id
	}
	return rj
}

func (s *Service) release(rj *runningJob) {
	s.mu.Lock()
	delete(s.running, rj.id)
	if s.perKind[rj.kind]--; s.perKind[rj.kind] <= 0 {
		delete(s.perKind, rj.kind)
	}
	if rj.exclusive != "" && s.locks[rj.exclusive] == rj.id {
		delete(s.locks, rj.exclusive)
	}
	s.mu.Unlock()
	s.signal(s.wake)
}

type queuedRow struct {
	id, kind, params, createdBy string
	createdAt                   int64
}

// blockedKindsLocked lists kinds that cannot start right now (saturated or
// exclusive group held), so the queue query skips them and later jobs of
// other kinds are not starved behind them.
func (s *Service) blockedKindsLocked() []string {
	var out []string
	for k, d := range s.kinds {
		if !s.canStartLocked(d, false) {
			out = append(out, k)
		}
	}
	return out
}

func (s *Service) dispatch(ctx context.Context) {
	for ctx.Err() == nil {
		s.mu.Lock()
		if s.stopping || len(s.running) >= s.workers {
			s.mu.Unlock()
			return
		}
		blocked := s.blockedKindsLocked()
		s.mu.Unlock()

		q := `SELECT id, kind, params, created_by, created_at FROM jobs WHERE state = 'queued'`
		var args []any
		if len(blocked) > 0 {
			q += ` AND kind NOT IN (` + placeholders(len(blocked)) + `)`
			for _, k := range blocked {
				args = append(args, k)
			}
		}
		q += ` ORDER BY created_at, id LIMIT 50`
		rows, err := s.env.DB.Query(ctx, q, args...)
		if err != nil {
			if ctx.Err() == nil {
				s.log.Error("jobs: read queue", "err", err)
			}
			return
		}
		var batch []queuedRow
		for rows.Next() {
			var r queuedRow
			var by sql.NullString
			if err := rows.Scan(&r.id, &r.kind, &r.params, &by, &r.createdAt); err != nil {
				s.log.Error("jobs: read queue", "err", err)
				break
			}
			r.createdBy = by.String
			batch = append(batch, r)
		}
		rows.Close()
		if err := rows.Err(); err != nil && ctx.Err() == nil {
			s.log.Error("jobs: read queue", "err", err)
		}
		if len(batch) == 0 {
			return
		}
		launched := 0
		for _, r := range batch {
			if s.tryLaunch(ctx, r) {
				launched++
			}
		}
		if launched == 0 {
			return
		}
	}
}

func (s *Service) tryLaunch(ctx context.Context, r queuedRow) bool {
	s.mu.Lock()
	if s.stopping || len(s.running) >= s.workers {
		s.mu.Unlock()
		return false
	}
	def := s.kinds[r.kind]
	if def == nil {
		s.mu.Unlock()
		s.failQueued(ctx, r.id, fmt.Sprintf("unknown job kind %q", r.kind))
		return false
	}
	if !s.canStartLocked(def, true) {
		s.mu.Unlock()
		return false
	}
	rj := s.reserveLocked(def, r.id, r.createdBy, json.RawMessage(r.params))
	s.mu.Unlock()

	now := s.env.Now()
	var claimed int64
	err := s.env.DB.Tx(ctx, func(tx *sql.Tx) error {
		res, err := tx.ExecContext(ctx, `UPDATE jobs SET state = 'running', started_at = ?, attempts = attempts + 1
			WHERE id = ? AND state = 'queued'`, db.Ms(now), r.id)
		if err != nil {
			return err
		}
		claimed, err = res.RowsAffected()
		return err
	})
	if err != nil || claimed == 0 {
		if err != nil && ctx.Err() == nil {
			s.log.Error("jobs: claim", "job", r.id, "err", err)
		}
		s.release(rj)
		s.jobsWG.Done()
		return false
	}
	rj.createdAt = db.FromMs(r.createdAt)
	rj.startedAt = now
	go s.execute(s.runCtx, def, rj)
	return true
}

func (s *Service) failQueued(ctx context.Context, id, msg string) {
	now := s.env.Now()
	err := s.env.DB.Tx(ctx, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `UPDATE jobs SET state = 'failed', error = ?, finished_at = ?
			WHERE id = ? AND state = 'queued'`, msg, db.Ms(now), id)
		return err
	})
	if err != nil {
		s.log.Error("jobs: fail queued job", "job", id, "err", err)
		return
	}
	s.log.Warn("jobs: queued job failed", "job", id, "reason", msg)
	if j, err := s.Get(ctx, id); err == nil {
		s.publish(events.TopicJobDone, j)
	}
}

// execute runs one reserved job to completion and records the outcome
// (reserveLocked added it to jobsWG).
func (s *Service) execute(parent context.Context, def *kindDef, rj *runningJob) {
	defer s.jobsWG.Done()
	var (
		jctx   context.Context
		cancel context.CancelFunc
	)
	if def.opts.Timeout > 0 {
		jctx, cancel = context.WithTimeout(parent, def.opts.Timeout)
	} else {
		jctx, cancel = context.WithCancel(parent)
	}
	defer cancel()
	rj.setCancel(cancel)
	// Cancel may have been requested between reservation and here.
	if rj.canceled.Load() {
		cancel()
	}
	jctx = core.WithPrincipal(jctx, jobPrincipal(rj))

	if j := rj.snapshot(core.JobRunning); j != nil {
		s.publish(events.TopicJobProgress, j)
	}
	err := s.safeCall(jctx, def.fn, rj)

	state, msg := core.JobSucceeded, ""
	switch {
	case err == nil:
	case rj.canceled.Load():
		state, msg = core.JobCanceled, "canceled"
	case s.isStopping() && parent.Err() != nil:
		state, msg = core.JobFailed, msgShutdown
	case def.opts.Timeout > 0 && errors.Is(jctx.Err(), context.DeadlineExceeded):
		state, msg = core.JobFailed, fmt.Sprintf("timed out after %s", def.opts.Timeout)
	default:
		state, msg = core.JobFailed, errorMessage(err)
	}
	if state == core.JobFailed {
		s.log.Warn("job failed", "job", rj.id, "kind", rj.kind, "err", msg)
	}
	s.finish(rj, state, msg)
	s.release(rj)
}

func (s *Service) isStopping() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.stopping
}

// jobPrincipal is the context principal of a running job: the plain system
// principal (no user identity, so services keep full system authority),
// carrying the job id as request id. The creator is recorded in
// jobs.created_by and, for hand-triggered runs, in the job.run audit entry.
func jobPrincipal(rj *runningJob) *core.Principal {
	p := core.SystemPrincipal(core.ViaOffline)
	p.Username = "system:job"
	p.RequestID = rj.id
	return p
}

// safeCall runs fn, turning a panic into an error (logged with its stack).
func (s *Service) safeCall(ctx context.Context, fn core.JobFunc, h core.JobHandle) (err error) {
	defer func() {
		if r := recover(); r != nil {
			s.log.Error("jobs: job panicked", "job", h.ID(), "panic", r, "stack", string(debug.Stack()))
			err = fmt.Errorf("job panicked: %v", r)
		}
	}()
	return fn(ctx, h)
}

func errorMessage(err error) string {
	msg := err.Error()
	if ce := core.AsError(err); ce != nil && ce.Message != "" && ce.Err == nil {
		msg = ce.Message
	}
	if len(msg) > maxErrorLen {
		msg = truncateUTF8(msg, maxErrorLen) + "…"
	}
	return msg
}

// truncateUTF8 cuts s to at most n bytes without splitting a UTF-8 sequence.
func truncateUTF8(s string, n int) string {
	if len(s) <= n {
		return s
	}
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	return s[:n]
}

func (s *Service) finish(rj *runningJob, state, msg string) {
	now := s.env.Now()
	rj.mu.Lock()
	done, total, note := rj.done, rj.total, rj.note
	result := rj.result
	rj.dirty = false
	rj.mu.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	err := s.env.DB.Tx(ctx, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `UPDATE jobs SET state = ?, error = ?, result = ?, progress_done = ?,
			progress_total = ?, note = ?, finished_at = ? WHERE id = ?`,
			state, db.NullString(msg), nullJSON(result), done, total, db.NullString(note), db.Ms(now), rj.id)
		return err
	})
	if err != nil {
		s.log.Error("jobs: record job result", "job", rj.id, "state", state, "err", err)
	}
	j := rj.snapshot(state)
	j.Error = msg
	j.FinishedAt = &now
	rj.pubMu.Lock()
	rj.ended = true
	s.publish(events.TopicJobDone, j)
	rj.pubMu.Unlock()
}

func nullJSON(b json.RawMessage) sql.NullString {
	if len(b) == 0 {
		return sql.NullString{}
	}
	return sql.NullString{String: string(b), Valid: true}
}

func (s *Service) publish(topic string, j *core.Job) {
	if s.env.Bus == nil || j == nil {
		return
	}
	s.env.Bus.Publish(events.Event{Topic: topic, UserID: j.CreatedBy, Data: core.JobEvent{Job: j, User: j.CreatedBy}})
}

// ---------- progress ----------

func (s *Service) progressLoop() {
	defer s.loops.Done()
	t := time.NewTicker(progressInterval)
	defer t.Stop()
	for {
		select {
		case <-s.runCtx.Done():
			return
		case <-t.C:
			s.flushProgress(s.runCtx)
		}
	}
}

// flushProgress writes the progress of every job whose progress changed
// since the last flush (one transaction) and publishes job.progress.
func (s *Service) flushProgress(ctx context.Context) {
	s.mu.Lock()
	var dirty []*runningJob
	for _, rj := range s.running {
		rj.mu.Lock()
		if rj.dirty {
			dirty = append(dirty, rj)
		}
		rj.mu.Unlock()
	}
	s.mu.Unlock()
	if len(dirty) == 0 {
		return
	}
	type upd struct {
		id          string
		done, total int64
		note        string
	}
	ups := make([]upd, 0, len(dirty))
	for _, rj := range dirty {
		rj.mu.Lock()
		ups = append(ups, upd{rj.id, rj.done, rj.total, rj.note})
		rj.dirty = false
		rj.mu.Unlock()
	}
	wctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
	defer cancel()
	err := s.env.DB.Tx(wctx, func(tx *sql.Tx) error {
		for _, u := range ups {
			if _, err := tx.ExecContext(wctx, `UPDATE jobs SET progress_done = ?, progress_total = ?, note = ?
				WHERE id = ? AND state = 'running'`, u.done, u.total, db.NullString(u.note), u.id); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		s.log.Warn("jobs: write progress", "err", err)
	}
	for _, rj := range dirty {
		// Never publish job.progress after job.done: the job may have
		// finished while the write above was in flight (the row itself is
		// guarded by "AND state = 'running'").
		rj.pubMu.Lock()
		if !rj.ended {
			s.publish(events.TopicJobProgress, rj.snapshot(core.JobRunning))
		}
		rj.pubMu.Unlock()
	}
}

// runningJob is the in-memory state of a running job; it implements
// core.JobHandle. Progress never touches the database directly (jobs may
// report progress from inside their own transactions); the flusher does.
type runningJob struct {
	s                    *Service
	id, kind, createdBy  string
	exclusive            string
	params               json.RawMessage
	createdAt, startedAt time.Time
	canceled             atomic.Bool
	cancelMu             sync.Mutex
	cancel               context.CancelFunc // set by execute

	// pubMu orders the job's events: finish sets ended and publishes
	// job.done under it, and the progress flusher skips job.progress once
	// ended is set. Without it a flush that started before the job returned
	// could publish job.progress{running} after job.done and resurrect a
	// finished job in the browser's job store.
	pubMu sync.Mutex
	ended bool

	mu          sync.Mutex
	done, total int64
	note        string
	dirty       bool
	result      json.RawMessage
}

// setCancel records the job context's cancel func (execute).
func (rj *runningJob) setCancel(c context.CancelFunc) {
	rj.cancelMu.Lock()
	rj.cancel = c
	rj.cancelMu.Unlock()
}

// requestCancel marks the job canceled and cancels its context once it has
// one (execute re-checks the flag after installing the context).
func (rj *runningJob) requestCancel() {
	rj.canceled.Store(true)
	rj.cancelMu.Lock()
	c := rj.cancel
	rj.cancelMu.Unlock()
	if c != nil {
		c()
	}
}

// ID implements core.JobHandle.
func (rj *runningJob) ID() string { return rj.id }

// Params implements core.JobHandle.
func (rj *runningJob) Params(v any) error {
	if len(rj.params) == 0 {
		return nil
	}
	if err := json.Unmarshal(rj.params, v); err != nil {
		return core.Wrap(core.ErrInvalid, "invalid job parameters", err)
	}
	return nil
}

// Progress implements core.JobHandle (cheap; throttled persistence).
func (rj *runningJob) Progress(done, total int64, note string) {
	note = truncateUTF8(note, maxNoteLen)
	rj.mu.Lock()
	if rj.done != done || rj.total != total || rj.note != note {
		rj.done, rj.total, rj.note = done, total, note
		rj.dirty = true
	}
	rj.mu.Unlock()
}

// SetResult implements core.JobHandle.
func (rj *runningJob) SetResult(v any) {
	b, err := json.Marshal(v)
	if err != nil {
		rj.s.log.Error("jobs: encode job result", "job", rj.id, "err", err)
		return
	}
	rj.mu.Lock()
	rj.result = b
	rj.mu.Unlock()
}

func (rj *runningJob) snapshot(state string) *core.Job {
	rj.mu.Lock()
	defer rj.mu.Unlock()
	j := &core.Job{
		ID: rj.id, Kind: rj.kind, State: state, ProgressDone: rj.done, ProgressTotal: rj.total,
		Note: rj.note, CreatedBy: rj.createdBy, Attempts: 1, CreatedAt: rj.createdAt, Result: rj.result,
	}
	if len(rj.params) > 0 && string(rj.params) != "{}" {
		j.Params = rj.params
	}
	if !rj.startedAt.IsZero() {
		t := rj.startedAt
		j.StartedAt = &t
	}
	return j
}
