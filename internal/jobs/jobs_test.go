package jobs

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"fileparcel/internal/core"
	"fileparcel/internal/db"
	"fileparcel/internal/events"
)

func init() {
	progressInterval = 20 * time.Millisecond
	pollInterval = 50 * time.Millisecond
}

type testEnv struct {
	env *core.Env
	svc *Service
	bus *events.Bus
}

func newTestEnv(t *testing.T) *testEnv {
	t.Helper()
	d, err := db.Open(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := d.Migrate(context.Background()); err != nil {
		t.Fatal(err)
	}
	bus := events.New()
	env := &core.Env{DB: d, Bus: bus, Clock: core.SystemClock{}, Log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	svc, err := New(env)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = svc.Stop(ctx)
		bus.Close()
		_ = d.Close()
	})
	return &testEnv{env: env, svc: svc, bus: bus}
}

func (te *testEnv) start(t *testing.T) {
	t.Helper()
	if err := te.svc.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func (te *testEnv) wait(t *testing.T, id string) *core.Job {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for {
		j, err := te.svc.Get(context.Background(), id)
		if err != nil {
			t.Fatal(err)
		}
		if j.State != core.JobQueued && j.State != core.JobRunning {
			return j
		}
		if time.Now().After(deadline) {
			t.Fatalf("job %s still %s", id, j.State)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func user(id string) *core.Principal {
	return &core.Principal{UserID: id, Username: id, Role: core.RoleMember, Via: core.ViaSession, AuthLevel: 2}
}

func TestLifecycle(t *testing.T) {
	te := newTestEnv(t)
	ctx := context.Background()
	type params struct{ N int64 }
	te.svc.Register("test.ok", func(ctx context.Context, h core.JobHandle) error {
		var p params
		if err := h.Params(&p); err != nil {
			return err
		}
		for i := int64(1); i <= p.N; i++ {
			h.Progress(i, p.N, "step")
			time.Sleep(15 * time.Millisecond)
		}
		if p := core.PrincipalFrom(ctx); p == nil || !p.IsSystem() {
			return errors.New("job context lacks the system principal")
		}
		h.SetResult(map[string]any{"done": p.N})
		return nil
	}, core.JobOptions{})
	te.svc.Register("test.fail", func(ctx context.Context, h core.JobHandle) error {
		return core.Errorf(core.ErrConflict, "nope %d", 7)
	}, core.JobOptions{})
	te.svc.Register("test.panic", func(ctx context.Context, h core.JobHandle) error {
		panic("boom")
	}, core.JobOptions{})
	te.svc.Register("test.badparams", func(ctx context.Context, h core.JobHandle) error {
		var p params
		return h.Params(&p)
	}, core.JobOptions{})

	if _, err := te.svc.Enqueue(ctx, "test.unknown", nil, nil); !errors.Is(err, core.ErrInvalid) {
		t.Fatalf("unknown kind: %v", err)
	}
	if _, err := te.svc.Enqueue(ctx, "test.ok", json.RawMessage(`{bad`), nil); !errors.Is(err, core.ErrInvalid) {
		t.Fatalf("bad params: %v", err)
	}
	evs, cancel := te.bus.Subscribe("job.*")
	defer cancel()

	okID, err := te.svc.Enqueue(ctx, "test.ok", params{N: 5}, user("usr_a"))
	if err != nil {
		t.Fatal(err)
	}
	j, _ := te.svc.Get(ctx, okID)
	if j.State != core.JobQueued || j.CreatedBy != "usr_a" || string(j.Params) != `{"N":5}` {
		t.Fatalf("queued job %+v", j)
	}
	failID, _ := te.svc.Enqueue(ctx, "test.fail", nil, nil)
	panicID, _ := te.svc.Enqueue(ctx, "test.panic", nil, nil)
	badID, _ := te.svc.Enqueue(ctx, "test.badparams", json.RawMessage(`{"N":"x"}`), nil)
	te.start(t)
	if err := te.svc.Start(ctx); err != nil { // idempotent
		t.Fatal(err)
	}
	if !te.svc.Running() {
		t.Fatal("not running")
	}

	j = te.wait(t, okID)
	if j.State != core.JobSucceeded || j.ProgressDone != 5 || j.ProgressTotal != 5 || string(j.Result) != `{"done":5}` ||
		j.StartedAt == nil || j.FinishedAt == nil || j.Attempts != 1 || j.Error != "" {
		t.Fatalf("ok job %+v", j)
	}
	if j := te.wait(t, failID); j.State != core.JobFailed || j.Error != "nope 7" {
		t.Fatalf("fail job %+v", j)
	}
	if j := te.wait(t, panicID); j.State != core.JobFailed || !strings.Contains(j.Error, "panicked") {
		t.Fatalf("panic job %+v", j)
	}
	if j := te.wait(t, badID); j.State != core.JobFailed || !strings.Contains(j.Error, "invalid job parameters") {
		t.Fatalf("bad params job %+v", j)
	}

	// Events: progress and done for the user's job carry the creator's id.
	var sawProgress, sawDone bool
	timeout := time.After(2 * time.Second)
	for !(sawProgress && sawDone) {
		select {
		case e := <-evs:
			je := e.Data.(core.JobEvent)
			if je.Job.ID != okID {
				continue
			}
			if e.UserID != "usr_a" || je.User != "usr_a" {
				t.Fatalf("event user %q/%q", e.UserID, je.User)
			}
			switch e.Topic {
			case events.TopicJobProgress:
				sawProgress = true
			case events.TopicJobDone:
				sawDone = true
				if je.Job.State != core.JobSucceeded || je.Job.FinishedAt == nil {
					t.Fatalf("done event %+v", je.Job)
				}
			}
		case <-timeout:
			t.Fatalf("events: progress %v done %v", sawProgress, sawDone)
		}
	}

	// Cancel of a finished job is a conflict; unknown ids are 404.
	if err := te.svc.Cancel(ctx, okID); !errors.Is(err, core.ErrConflict) {
		t.Fatalf("cancel finished: %v", err)
	}
	if _, err := te.svc.Get(ctx, "job_nope"); !errors.Is(err, core.ErrNotFound) {
		t.Fatalf("get bad id: %v", err)
	}
	if err := te.svc.Cancel(ctx, "job_00000000000000000000000000"); !errors.Is(err, core.ErrNotFound) {
		t.Fatalf("cancel unknown: %v", err)
	}
}

func TestCancel(t *testing.T) {
	te := newTestEnv(t)
	ctx := context.Background()
	started := make(chan struct{}, 1)
	var ran atomic.Int32
	te.svc.Register("test.block", func(ctx context.Context, h core.JobHandle) error {
		ran.Add(1)
		started <- struct{}{}
		<-ctx.Done()
		return ctx.Err()
	}, core.JobOptions{})

	// Queued job canceled before the runner starts never runs.
	q, _ := te.svc.Enqueue(ctx, "test.block", nil, nil)
	if err := te.svc.Cancel(ctx, q); err != nil {
		t.Fatal(err)
	}
	if j, _ := te.svc.Get(ctx, q); j.State != core.JobCanceled {
		t.Fatalf("queued cancel: %s", j.State)
	}
	te.start(t)
	r, _ := te.svc.Enqueue(ctx, "test.block", nil, nil)
	select {
	case <-started:
	case <-time.After(5 * time.Second):
		t.Fatal("job did not start")
	}
	if err := te.svc.Cancel(ctx, r); err != nil {
		t.Fatal(err)
	}
	if j := te.wait(t, r); j.State != core.JobCanceled || j.Error != "canceled" {
		t.Fatalf("running cancel %+v", j)
	}
	if ran.Load() != 1 {
		t.Fatalf("ran %d times", ran.Load())
	}
}

func TestLimitsTimeoutAndExclusive(t *testing.T) {
	te := newTestEnv(t)
	ctx := context.Background()
	var mu sync.Mutex
	cur := map[string]int{}
	peak := map[string]int{}
	track := func(group string) core.JobFunc {
		return func(ctx context.Context, h core.JobHandle) error {
			mu.Lock()
			cur[group]++
			if cur[group] > peak[group] {
				peak[group] = cur[group]
			}
			mu.Unlock()
			time.Sleep(60 * time.Millisecond)
			mu.Lock()
			cur[group]--
			mu.Unlock()
			return nil
		}
	}
	te.svc.Register("test.two", track("two"), core.JobOptions{MaxConcurrent: 2})
	te.svc.Register("test.one", track("one"), core.JobOptions{})
	te.svc.Register("test.exA", track("ex"), core.JobOptions{Exclusive: "g", MaxConcurrent: 5})
	te.svc.Register("test.exB", track("ex"), core.JobOptions{Exclusive: "g", MaxConcurrent: 5})
	te.svc.Register("test.slow", func(ctx context.Context, h core.JobHandle) error {
		<-ctx.Done()
		return ctx.Err()
	}, core.JobOptions{Timeout: 50 * time.Millisecond})
	var ids []string
	for i := 0; i < 5; i++ {
		a, _ := te.svc.Enqueue(ctx, "test.two", nil, nil)
		b, _ := te.svc.Enqueue(ctx, "test.one", nil, nil)
		c, _ := te.svc.Enqueue(ctx, "test.exA", nil, nil)
		d, _ := te.svc.Enqueue(ctx, "test.exB", nil, nil)
		ids = append(ids, a, b, c, d)
	}
	slow, _ := te.svc.Enqueue(ctx, "test.slow", nil, nil)
	te.svc.workers = 8
	te.start(t)
	for _, id := range ids {
		if j := te.wait(t, id); j.State != core.JobSucceeded {
			t.Fatalf("%s %s", j.Kind, j.State)
		}
	}
	if j := te.wait(t, slow); j.State != core.JobFailed || !strings.Contains(j.Error, "timed out") {
		t.Fatalf("timeout job %+v", j)
	}
	mu.Lock()
	defer mu.Unlock()
	if peak["two"] != 2 || peak["one"] != 1 || peak["ex"] != 1 {
		t.Fatalf("peaks %v", peak)
	}
}

func TestCrashRecoveryAndUnknownKind(t *testing.T) {
	te := newTestEnv(t)
	ctx := context.Background()
	now := db.Ms(time.Now())
	if _, err := te.env.DB.Exec(ctx, `INSERT INTO jobs (id, kind, state, created_at, started_at) VALUES
		('job_0000000000000000000000000a', 'x.crashed', 'running', ?, ?),
		('job_0000000000000000000000000b', 'x.gone', 'queued', ?, NULL)`, now, now, now); err != nil {
		t.Fatal(err)
	}
	te.start(t)
	j, _ := te.svc.Get(ctx, "job_0000000000000000000000000a")
	if j.State != core.JobFailed || !strings.Contains(j.Error, "interrupted") || j.FinishedAt == nil {
		t.Fatalf("crashed job %+v", j)
	}
	if j := te.wait(t, "job_0000000000000000000000000b"); j.State != core.JobFailed || !strings.Contains(j.Error, "unknown job kind") {
		t.Fatalf("unknown kind job %+v", j)
	}
}

func TestStopDrainsAndInterrupts(t *testing.T) {
	te := newTestEnv(t)
	ctx := context.Background()
	release := make(chan struct{})
	te.svc.Register("test.wait", func(ctx context.Context, h core.JobHandle) error {
		select {
		case <-release:
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	}, core.JobOptions{MaxConcurrent: 2})
	// Stop without Start is safe.
	fresh, _ := New(te.env)
	if err := fresh.Stop(ctx); err != nil {
		t.Fatal(err)
	}
	te.start(t)
	a, _ := te.svc.Enqueue(ctx, "test.wait", nil, nil)
	waitState(t, te, a, core.JobRunning)
	// Graceful: the job finishes within the stop deadline.
	go func() { time.Sleep(50 * time.Millisecond); close(release) }()
	sctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if err := te.svc.Stop(sctx); err != nil {
		t.Fatal(err)
	}
	if j, _ := te.svc.Get(ctx, a); j.State != core.JobSucceeded {
		t.Fatalf("drained job %s", j.State)
	}
	if err := te.svc.Stop(ctx); err != nil { // twice
		t.Fatal(err)
	}

	// Forced: the deadline passes and the job is interrupted.
	te2 := newTestEnv(t)
	te2.svc.Register("test.forever", func(ctx context.Context, h core.JobHandle) error {
		<-ctx.Done()
		return ctx.Err()
	}, core.JobOptions{})
	te2.start(t)
	b, _ := te2.svc.Enqueue(ctx, "test.forever", nil, nil)
	waitState(t, te2, b, core.JobRunning)
	sctx2, cancel2 := context.WithTimeout(ctx, 50*time.Millisecond)
	defer cancel2()
	if err := te2.svc.Stop(sctx2); err != nil {
		t.Fatal(err)
	}
	if j, _ := te2.svc.Get(ctx, b); j.State != core.JobFailed || j.Error != msgShutdown {
		t.Fatalf("interrupted job %+v", j)
	}
}

func waitState(t *testing.T, te *testEnv, id, state string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		j, err := te.svc.Get(context.Background(), id)
		if err != nil {
			t.Fatal(err)
		}
		if j.State == state {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("job %s is %s, want %s", id, j.State, state)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func TestRunInlineAndList(t *testing.T) {
	te := newTestEnv(t)
	ctx := context.Background()
	te.svc.Register("test.inline", func(ctx context.Context, h core.JobHandle) error {
		h.Progress(1, 1, "")
		h.SetResult("ok")
		return nil
	}, core.JobOptions{})
	te.svc.Register("test.hidden", func(ctx context.Context, h core.JobHandle) error { return nil }, core.JobOptions{Hidden: true})
	j, err := te.svc.RunInline(ctx, "test.inline", map[string]int{"a": 1}, user("usr_b"))
	if err != nil {
		t.Fatal(err)
	}
	if j.State != core.JobSucceeded || string(j.Result) != `"ok"` || j.CreatedBy != "usr_b" || j.ProgressDone != 1 {
		t.Fatalf("inline %+v", j)
	}
	if _, err := te.svc.RunInline(ctx, "test.nope", nil, nil); !errors.Is(err, core.ErrInvalid) {
		t.Fatal(err)
	}
	for i := 0; i < 5; i++ {
		if _, err := te.svc.Enqueue(ctx, "test.inline", nil, user("usr_c")); err != nil {
			t.Fatal(err)
		}
		time.Sleep(2 * time.Millisecond) // distinct created_at
	}
	if _, err := te.svc.Enqueue(ctx, "test.hidden", nil, nil); err != nil {
		t.Fatal(err)
	}
	var all []core.Job
	page, err := te.svc.List(ctx, core.JobQuery{PageReq: core.PageReq{Limit: 2}})
	for err == nil {
		all = append(all, page.Items...)
		if page.NextCursor == "" {
			break
		}
		page, err = te.svc.List(ctx, core.JobQuery{PageReq: core.PageReq{Limit: 2, Cursor: page.NextCursor}})
	}
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != 6 { // hidden kinds and maintenance kinds are omitted
		t.Fatalf("listed %d", len(all))
	}
	for i := 1; i < len(all); i++ {
		if all[i].CreatedAt.After(all[i-1].CreatedAt) {
			t.Fatal("not newest first")
		}
	}
	p, _ := te.svc.List(ctx, core.JobQuery{Kind: "test.hidden"})
	if len(p.Items) != 1 {
		t.Fatal("explicit hidden kind not listed")
	}
	p, _ = te.svc.List(ctx, core.JobQuery{CreatedBy: "usr_c", State: core.JobQueued})
	if len(p.Items) != 5 {
		t.Fatalf("filter: %d", len(p.Items))
	}
	p, _ = te.svc.List(ctx, core.JobQuery{State: "active"})
	if len(p.Items) != 5 { // the hidden one is omitted
		t.Fatalf("active: %d", len(p.Items))
	}
	if _, err := te.svc.List(ctx, core.JobQuery{State: "weird"}); !errors.Is(err, core.ErrInvalid) {
		t.Fatal(err)
	}
	if _, err := te.svc.List(ctx, core.JobQuery{PageReq: core.PageReq{Cursor: "!!"}}); !errors.Is(err, core.ErrInvalid) {
		t.Fatal(err)
	}
	kinds := te.svc.Kinds()
	if !te.svc.Registered(core.JobMaintSessions) || len(kinds) < 5 {
		t.Fatalf("kinds %v", kinds)
	}
}

func TestSchedules(t *testing.T) {
	te := newTestEnv(t)
	ctx := context.Background()
	var runs atomic.Int32
	te.svc.Register("test.cron", func(ctx context.Context, h core.JobHandle) error {
		runs.Add(1)
		return nil
	}, core.JobOptions{})
	if err := te.svc.Schedule("bad", "61 * * * *", "test.cron", nil); !errors.Is(err, core.ErrInvalid) {
		t.Fatalf("bad cron: %v", err)
	}
	// A spec that parses but can never match would be stored enabled with
	// next_run_at NULL, which runDue never selects again: a schedule that is
	// silently dead for ever. It must be refused like any other bad spec.
	if err := te.svc.Schedule("dead", "0 3 30 2 *", "test.cron", nil); !errors.Is(err, core.ErrInvalid) {
		t.Fatalf("unreachable cron: %v", err)
	}
	if scs, _ := te.svc.Schedules(ctx); len(scs) > 0 {
		for _, sc := range scs {
			if sc.Name == "dead" {
				t.Fatalf("an unreachable schedule was stored: %+v", sc)
			}
		}
	}
	if err := te.svc.Schedule("", "* * * * *", "test.cron", nil); !errors.Is(err, core.ErrInvalid) {
		t.Fatalf("empty name: %v", err)
	}
	if err := te.svc.Schedule("s1", "@daily", "test.cron", map[string]int{"x": 1}); err != nil {
		t.Fatal(err)
	}
	get := func(name string) *core.JobSchedule {
		scs, err := te.svc.Schedules(ctx)
		if err != nil {
			t.Fatal(err)
		}
		for i := range scs {
			if scs[i].Name == name {
				return &scs[i]
			}
		}
		return nil
	}
	s1 := get("s1")
	if s1 == nil || s1.Cron != "0 0 * * *" || !s1.Enabled || s1.NextRunAt == nil || string(s1.Params) != `{"x":1}` {
		t.Fatalf("s1 %+v", s1)
	}
	if !s1.NextRunAt.After(time.Now()) {
		t.Fatal("next run in the past")
	}
	// Maintenance schedules are registered by New.
	for _, k := range []string{core.JobMaintSessions, core.JobMaintAuditPrune, core.JobMaintDBOptimize} {
		if get(k) == nil {
			t.Fatalf("missing schedule %s", k)
		}
	}
	// Re-scheduling unchanged keeps an overdue next run (missed runs happen once after start).
	past := db.Ms(time.Now().Add(-time.Hour))
	if _, err := te.env.DB.Exec(ctx, `UPDATE schedules SET next_run_at = ? WHERE name = 's1'`, past); err != nil {
		t.Fatal(err)
	}
	if err := te.svc.Schedule("s1", "@daily", "test.cron", map[string]int{"x": 1}); err != nil {
		t.Fatal(err)
	}
	if got := get("s1"); db.Ms(*got.NextRunAt) != past {
		t.Fatal("unchanged schedule lost its pending run")
	}
	// Due: one job, next run advanced, last_job_id set.
	te.svc.runDue(ctx)
	s1 = get("s1")
	if s1.LastJobID == "" || s1.LastRunAt == nil || !s1.NextRunAt.After(time.Now()) {
		t.Fatalf("after run %+v", s1)
	}
	j, _ := te.svc.Get(ctx, s1.LastJobID)
	if j.Schedule != "s1" || j.Kind != "test.cron" || j.State != core.JobQueued || string(j.Params) != `{"x":1}` {
		t.Fatalf("scheduled job %+v", j)
	}
	// Due again while the previous run is still queued: skipped.
	if _, err := te.env.DB.Exec(ctx, `UPDATE schedules SET next_run_at = ? WHERE name = 's1'`, past); err != nil {
		t.Fatal(err)
	}
	te.svc.runDue(ctx)
	if got := get("s1"); got.LastJobID != s1.LastJobID || !got.NextRunAt.After(time.Now()) {
		t.Fatalf("overlapping run not skipped: %+v", got)
	}
	// Unknown kinds are skipped (no job).
	if err := te.svc.Schedule("s2", "* * * * *", "test.unregistered", nil); err != nil {
		t.Fatal(err)
	}
	if _, err := te.env.DB.Exec(ctx, `UPDATE schedules SET next_run_at = ? WHERE name = 's2'`, past); err != nil {
		t.Fatal(err)
	}
	te.svc.runDue(ctx)
	if got := get("s2"); got.LastJobID != "" {
		t.Fatal("unknown kind enqueued")
	}
	// A changed spec recomputes the next run.
	if err := te.svc.Schedule("s1", "*/5 * * * *", "test.cron", nil); err != nil {
		t.Fatal(err)
	}
	if got := get("s1"); got.Cron != "*/5 * * * *" || time.Until(*got.NextRunAt) > 5*time.Minute+time.Second {
		t.Fatalf("changed %+v", got)
	}
	te.svc.Unschedule("s2")
	te.svc.Unschedule("never-existed")
	if get("s2") != nil {
		t.Fatal("unschedule")
	}
	// Start computes missing next runs, and the loop runs due schedules.
	if _, err := te.env.DB.Exec(ctx, `UPDATE schedules SET next_run_at = NULL WHERE name = 's1'`); err != nil {
		t.Fatal(err)
	}
	te.start(t)
	if got := get("s1"); got.NextRunAt == nil {
		t.Fatal("Start did not compute next run")
	}
	if j := te.wait(t, s1.LastJobID); j.State != core.JobSucceeded { // the run queued earlier
		t.Fatalf("queued scheduled job %+v", j)
	}
	if _, err := te.env.DB.Exec(ctx, `UPDATE schedules SET next_run_at = ? WHERE name = 's1'`, past); err != nil {
		t.Fatal(err)
	}
	te.svc.signal(te.svc.schedWake)
	deadline := time.Now().Add(5 * time.Second)
	for runs.Load() < 2 { // the earlier queued run and the new one
		if time.Now().After(deadline) {
			t.Fatalf("scheduled jobs ran %d times", runs.Load())
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// fakeSettings serves fixed ints.
type fakeSettings struct {
	core.Settings
	ints map[string]int64
}

func (f fakeSettings) Int(key string) int64 { return f.ints[key] }

type fakeAudit struct {
	core.Audit
	before time.Time
	err    error
}

func (a *fakeAudit) Prune(ctx context.Context, before time.Time) (int, error) {
	a.before = before
	return 3, a.err
}

func TestMaintenanceJobs(t *testing.T) {
	te := newTestEnv(t)
	ctx := context.Background()
	now := time.Now()
	ms := func(d time.Duration) int64 { return db.Ms(now.Add(d)) }
	err := te.env.DB.Tx(ctx, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, `INSERT INTO users (id, username, role, webauthn_handle, created_at, updated_at)
			VALUES ('usr_1', 'u1', 'member', x'01', 1, 1)`); err != nil {
			return err
		}
		sess := `INSERT INTO sessions (id, token_hash, user_id, auth_level, csrf_secret, created_at, last_seen_at,
			idle_expires_at, expires_at, revoked_at) VALUES (?, ?, 'usr_1', 2, x'00', 1, 1, ?, ?, ?)`
		rows := []struct {
			id        string
			idle, exp int64
			revoked   any
		}{
			{"ses_old_expired", ms(-9 * 24 * time.Hour), ms(-8 * 24 * time.Hour), nil},
			{"ses_recent_expired", ms(-2 * 24 * time.Hour), ms(-24 * time.Hour), nil},
			{"ses_old_revoked", ms(time.Hour), ms(10 * 24 * time.Hour), ms(-8 * 24 * time.Hour)},
			{"ses_old_idle", ms(-8 * 24 * time.Hour), ms(10 * 24 * time.Hour), nil},
			{"ses_active", ms(time.Hour), ms(24 * time.Hour), nil},
		}
		for i, r := range rows {
			if _, err := tx.ExecContext(ctx, sess, r.id, []byte{byte(i)}, r.idle, r.exp, r.revoked); err != nil {
				return err
			}
		}
		tick := `INSERT INTO archive_tickets (id_hash, user_id, node_ids, format, name, created_at, expires_at, used_at)
			VALUES (?, 'usr_1', '[]', 'zip', 'a', 1, ?, ?)`
		if _, err := tx.ExecContext(ctx, tick, []byte{1}, ms(-2*time.Hour), nil); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, tick, []byte{2}, ms(time.Minute), nil); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, tick, []byte{3}, ms(time.Minute), ms(-2*time.Hour)); err != nil {
			return err
		}
		_, err := tx.ExecContext(ctx, `INSERT INTO jobs (id, kind, state, created_at, finished_at) VALUES
			('job_old', 'x', 'succeeded', 1, ?), ('job_new', 'x', 'failed', 1, ?), ('job_q', 'x', 'queued', 1, NULL)`,
			ms(-40*24*time.Hour), ms(-time.Hour))
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	j, err := te.svc.RunInline(ctx, core.JobMaintSessions, nil, nil)
	if err != nil || j.State != core.JobSucceeded {
		t.Fatalf("sessions %v %+v", err, j)
	}
	var sr SessionsResult
	_ = json.Unmarshal(j.Result, &sr)
	if sr.Sessions != 3 || sr.Tickets != 2 {
		t.Fatalf("sessions result %+v", sr)
	}
	var left []string
	rows, _ := te.env.DB.Query(ctx, `SELECT id FROM sessions ORDER BY id`)
	for rows.Next() {
		var id string
		_ = rows.Scan(&id)
		left = append(left, id)
	}
	rows.Close()
	if strings.Join(left, ",") != "ses_active,ses_recent_expired" {
		t.Fatalf("sessions left %v", left)
	}

	j, err = te.svc.RunInline(ctx, core.JobMaintDBOptimize, nil, nil)
	if err != nil || j.State != core.JobSucceeded {
		t.Fatalf("db optimize %v %+v", err, j)
	}
	var dr DBOptimizeResult
	_ = json.Unmarshal(j.Result, &dr)
	if dr.JobsPruned != 1 {
		t.Fatalf("db optimize result %+v", dr)
	}
	if _, err := te.svc.Get(ctx, "job_old"); err == nil {
		t.Fatal("old job not pruned")
	}

	// Audit prune: no audit service → skipped; with retention → Prune(now - days).
	j, _ = te.svc.RunInline(ctx, core.JobMaintAuditPrune, nil, nil)
	if j.State != core.JobSucceeded || !strings.Contains(string(j.Result), "unavailable") {
		t.Fatalf("audit prune without audit %+v", j)
	}
	fa := &fakeAudit{}
	te.env.Audit = fa
	te.env.Settings = fakeSettings{ints: map[string]int64{settingAuditRetention: 30}}
	j, _ = te.svc.RunInline(ctx, core.JobMaintAuditPrune, nil, nil)
	var ar AuditPruneResult
	_ = json.Unmarshal(j.Result, &ar)
	if j.State != core.JobSucceeded || ar.Pruned != 3 || ar.RetentionDays != 30 {
		t.Fatalf("audit prune %+v %+v", j, ar)
	}
	if d := time.Since(fa.before) - 30*24*time.Hour; d < 0 || d > time.Minute {
		t.Fatalf("prune before %v", fa.before)
	}
	te.env.Settings = fakeSettings{ints: map[string]int64{settingAuditRetention: 0}}
	fa.before = time.Time{}
	j, _ = te.svc.RunInline(ctx, core.JobMaintAuditPrune, nil, nil)
	if j.State != core.JobSucceeded || !fa.before.IsZero() {
		t.Fatal("retention 0 must not prune")
	}
	te.env.Settings = fakeSettings{ints: map[string]int64{settingAuditRetention: 10}}
	fa.err = core.ErrKeysLocked
	j, _ = te.svc.RunInline(ctx, core.JobMaintAuditPrune, nil, nil)
	if j.State != core.JobSucceeded || !strings.Contains(string(j.Result), "locked") {
		t.Fatalf("locked keys %+v", j)
	}
	// Another package may re-register a built-in kind silently.
	te.svc.Register(core.JobMaintAuditPrune, func(ctx context.Context, h core.JobHandle) error { return nil }, core.JobOptions{})
}

// ---------- regression tests ----------

// A Cancel that races the dispatcher's claim must not be lost. Cancel used to
// read s.running, find nothing for a still-queued job and then write
// "canceled" with "WHERE state IN ('queued','running')"; when the dispatcher
// reserved and claimed the job in that window the update hit a row this
// process was really running, whose cancel flag was never set. The API
// answered 204, the row said canceled, and the job ran on and overwrote it
// with its real outcome — while a second attempt answered 409.
func TestCancelRacingDispatcherClaim(t *testing.T) {
	te := newTestEnv(t)
	ctx := context.Background()
	const jobRun = 1500 * time.Millisecond
	te.svc.Register("test.cancelrace", func(ctx context.Context, h core.JobHandle) error {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(jobRun):
			return nil
		}
	}, core.JobOptions{MaxConcurrent: 64})
	te.svc.workers = 64 // before Start: widen the claim window
	te.start(t)

	const workers, iters = 8, 40
	var (
		mu       sync.Mutex
		accepted []string
		wg       sync.WaitGroup
	)
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < iters; i++ {
				id, err := te.svc.Enqueue(ctx, "test.cancelrace", nil, nil)
				if err != nil {
					t.Error(err)
					return
				}
				if err := te.svc.Cancel(ctx, id); err == nil {
					mu.Lock()
					accepted = append(accepted, id)
					mu.Unlock()
				}
			}
		}()
	}
	wg.Wait()

	// Wait until nothing runs any more: a lost cancellation only shows when
	// the job that kept running writes its own outcome over the row.
	deadline := time.Now().Add(30 * time.Second)
	for {
		te.svc.mu.Lock()
		n := len(te.svc.running)
		te.svc.mu.Unlock()
		if n == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("%d jobs still running", n)
		}
		time.Sleep(10 * time.Millisecond)
	}
	if len(accepted) < workers*iters/2 {
		t.Fatalf("only %d of %d cancels were accepted", len(accepted), workers*iters)
	}
	lost := 0
	for _, id := range accepted {
		j, err := te.svc.Get(ctx, id)
		if err != nil {
			t.Fatal(err)
		}
		if j.State != core.JobCanceled {
			lost++
			if lost <= 3 {
				t.Errorf("cancel of %s reported success but the job ended %s (error %q)", id, j.State, j.Error)
			}
		}
	}
	if lost > 0 {
		t.Fatalf("%d of %d accepted cancellations were lost", lost, len(accepted))
	}
}

// job.progress must never follow job.done for the same job: the browser's
// job store merges the late event, puts the entry back into "running" and
// never evicts it, so the "Background jobs" badge stays stuck.
//
// The flusher collects the dirty jobs, writes them in one transaction and
// only then publishes; a job that finishes inside that window used to get a
// job.progress{running} after its job.done. Several rounds of many jobs
// finishing at staggered times make that window easy to hit.
func TestProgressNeverPublishedAfterDone(t *testing.T) {
	te := newTestEnv(t)
	ctx := context.Background()
	var next atomic.Int64
	te.svc.Register("test.lateprogress", func(ctx context.Context, h core.JobHandle) error {
		steps := 1 + int(next.Add(1))%150
		for i := 0; i < steps; i++ {
			h.Progress(int64(i), int64(steps), "step")
			time.Sleep(2 * time.Millisecond)
		}
		return nil
	}, core.JobOptions{MaxConcurrent: 400})
	te.svc.workers = 400 // many dirty jobs → a long progress flush

	ch, unsub := te.bus.Subscribe(events.TopicJobProgress, events.TopicJobDone)
	defer unsub()
	var (
		mu       sync.Mutex
		finished = map[string]bool{}
		late     []string
	)
	collected := make(chan struct{})
	go func() {
		defer close(collected)
		for e := range ch {
			je, ok := e.Data.(core.JobEvent)
			if !ok || je.Job == nil {
				continue
			}
			mu.Lock()
			switch e.Topic {
			case events.TopicJobDone:
				finished[je.Job.ID] = true
			case events.TopicJobProgress:
				if finished[je.Job.ID] {
					late = append(late, je.Job.ID+" ("+je.Job.State+")")
				}
			}
			mu.Unlock()
		}
	}()

	te.start(t)
	const rounds, n = 3, 400
	for r := 0; r < rounds; r++ {
		ids := make([]string, 0, n)
		for i := 0; i < n; i++ {
			id, err := te.svc.Enqueue(ctx, "test.lateprogress", nil, nil)
			if err != nil {
				t.Fatal(err)
			}
			ids = append(ids, id)
		}
		for _, id := range ids {
			te.wait(t, id)
		}
	}
	time.Sleep(5 * progressInterval) // let any trailing flush publish
	unsub()
	<-collected
	mu.Lock()
	defer mu.Unlock()
	if len(late) > 0 {
		show := late
		if len(show) > 5 {
			show = show[:5]
		}
		t.Fatalf("%d job.progress events published after job.done: %v", len(late), show)
	}
}

// Hidden kinds keep routine housekeeping out of the job list, but the
// dashboard and the doctor count failed jobs over every kind: a failure they
// warn about must be reachable from GET /admin/jobs. A run started by hand
// must stay listed too, instead of vanishing on the next reload.
func TestHiddenKindsStayListedWhenTheyMatter(t *testing.T) {
	te := newTestEnv(t)
	ctx := context.Background()
	te.svc.Register("test.invisible", func(ctx context.Context, h core.JobHandle) error { return nil },
		core.JobOptions{Hidden: true})
	now := time.Now()
	ins := func(id, kind, state, by, schedule string) {
		t.Helper()
		if _, err := te.env.DB.Exec(ctx, `INSERT INTO jobs (id, kind, state, params, created_by, schedule, created_at, finished_at)
			VALUES (?, ?, ?, '{}', ?, ?, ?, ?)`, id, kind, state, db.NullString(by), db.NullString(schedule),
			db.Ms(now), db.Ms(now)); err != nil {
			t.Fatal(err)
		}
	}
	// maintenance.sessions is registered Hidden and is hand-runnable.
	ins("job_00000000000000000000000001", core.JobMaintSessions, core.JobFailed, "", core.JobMaintSessions)    // scheduled, failed
	ins("job_00000000000000000000000002", core.JobMaintSessions, core.JobSucceeded, "usr_admin", "")           // started from the admin UI
	ins("job_00000000000000000000000003", core.JobMaintSessions, core.JobSucceeded, "", "")                    // "fileparcel jobs run" (no user)
	ins("job_00000000000000000000000004", core.JobMaintSessions, core.JobSucceeded, "", core.JobMaintSessions) // routine run
	ins("job_00000000000000000000000005", "test.invisible", core.JobSucceeded, "", "")                         // never hand-started
	ins("job_00000000000000000000000006", "test.invisible", core.JobFailed, "", "")                            // failed

	listed := map[string]bool{}
	page, err := te.svc.List(ctx, core.JobQuery{PageReq: core.PageReq{Limit: 100}})
	if err != nil {
		t.Fatal(err)
	}
	for _, j := range page.Items {
		listed[j.ID] = true
	}
	for _, id := range []string{"job_00000000000000000000000001", "job_00000000000000000000000002",
		"job_00000000000000000000000003", "job_00000000000000000000000006"} {
		if !listed[id] {
			t.Errorf("%s is not listed", id)
		}
	}
	for _, id := range []string{"job_00000000000000000000000004", "job_00000000000000000000000005"} {
		if listed[id] {
			t.Errorf("routine hidden run %s should not be listed", id)
		}
	}

	// The invariant the dashboard and the doctor depend on: every failed job
	// they count is reachable through GET /admin/jobs?state=failed.
	var counted int
	if err := te.env.DB.QueryRow(ctx, `SELECT count(*) FROM jobs WHERE state = 'failed' AND finished_at > ?`,
		db.Ms(now.Add(-24*time.Hour))).Scan(&counted); err != nil {
		t.Fatal(err)
	}
	failed, err := te.svc.List(ctx, core.JobQuery{PageReq: core.PageReq{Limit: 100}, State: core.JobFailed})
	if err != nil {
		t.Fatal(err)
	}
	if counted == 0 || len(failed.Items) != counted {
		t.Fatalf("the dashboard counts %d failed jobs, GET /admin/jobs?state=failed lists %d", counted, len(failed.Items))
	}
}

// probeHandle is a core.JobHandle that records what a job reports. Its
// Progress hook runs synchronously inside the job, which lets a test change
// the database state between two steps of the job.
type probeHandle struct {
	id     string
	hook   func(done, total int64, note string)
	note   string
	result any
}

func (h *probeHandle) ID() string         { return h.id }
func (h *probeHandle) Params(v any) error { return nil }
func (h *probeHandle) SetResult(v any)    { h.result = v }
func (h *probeHandle) Progress(done, total int64, note string) {
	h.note = note
	if h.hook != nil {
		h.hook(done, total, note)
	}
}

// SQLite reports a truncating WAL checkpoint that could not run because
// readers were active in the first column of the PRAGMA result row, not as
// an error. maintenance.db_optimize used to store that number and report
// plain success, so an operator following the doctor's "run
// maintenance.db_optimize to checkpoint it" hint saw a green job and an
// unchanged warning.
func TestDBOptimizeReportsBlockedCheckpoint(t *testing.T) {
	te := newTestEnv(t)
	ctx := context.Background()
	fill := func(prefix string, n int) {
		t.Helper()
		for i := 0; i < n; i++ {
			id := fmt.Sprintf("job_%s%022d", prefix, i)
			if _, err := te.env.DB.Exec(ctx, `INSERT INTO jobs (id, kind, state, params, created_at)
				VALUES (?, 'test.filler', 'queued', '{}', ?)`, id, db.Ms(time.Now())); err != nil {
				t.Fatal(err)
			}
		}
	}
	fill("a", 200)
	// Hold a read snapshot open: the truncating checkpoint cannot pass it.
	conn, err := te.env.DB.Reader().Conn(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	rtx, err := conn.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		t.Fatal(err)
	}
	defer rtx.Rollback() //nolint:errcheck
	var n int
	if err := rtx.QueryRowContext(ctx, `SELECT count(*) FROM jobs`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	fill("b", 200) // frames the reader still needs

	h := &probeHandle{id: "job_probe"}
	h.hook = func(done, total int64, note string) {
		// Just before the checkpoint: shorten the writer's busy timeout so
		// the blocked checkpoint gives up in milliseconds instead of 10 s.
		// (The writer pool holds exactly one connection, and DB.Tx has
		// already restored the pragma after the prune above.)
		if done == 2 {
			if _, err := te.env.DB.Writer().ExecContext(ctx, `PRAGMA busy_timeout = 100`); err != nil {
				t.Error(err)
			}
		}
	}
	if err := te.svc.jobDBOptimize(ctx, h); err != nil {
		t.Fatalf("db_optimize returned %v", err)
	}
	if _, err := te.env.DB.Writer().ExecContext(ctx, `PRAGMA busy_timeout = 10000`); err != nil {
		t.Fatal(err)
	}
	res, ok := h.result.(DBOptimizeResult)
	if !ok {
		t.Fatalf("result %T", h.result)
	}
	if res.CheckpointBusy == 0 {
		t.Skip("the checkpoint was not blocked on this platform")
	}
	if res.CheckpointTruncated {
		t.Errorf("checkpoint_truncated = true although SQLite reported busy = %d", res.CheckpointBusy)
	}
	if !strings.Contains(h.note, "could not be truncated") {
		t.Errorf("a blocked checkpoint left no trace for the operator: note = %q, result = %+v", h.note, res)
	}
}
