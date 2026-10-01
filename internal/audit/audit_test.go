package audit

import (
	"bufio"
	"bytes"
	"context"
	"database/sql"
	"database/sql/driver"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"fileparcel/internal/config"
	"fileparcel/internal/core"
	"fileparcel/internal/events"
)

func TestRecordFillsAndVerifies(t *testing.T) {
	te := newTestEnv(t, true)
	te.record(t, 5, core.ActFileRename)
	te.svc.Record(context.Background(), core.AuditEntry{Action: core.ActAuthLogin, Outcome: core.OutcomeFailure, ActorName: "mallory", IP: "192.0.2.1"})

	p, err := te.svc.Query(context.Background(), core.AuditQuery{PageReq: core.PageReq{Sort: SortOldest}})
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Items) != 6 {
		t.Fatalf("got %d rows", len(p.Items))
	}
	r := p.Items[0]
	if r.ActorID != "usr_a" || r.ActorName != "alice" || r.ActorVia != "session" || r.UserAgent != "test-agent" ||
		r.RequestID != "req-1" || r.Outcome != core.OutcomeSuccess || r.TargetID != "nod_x" || string(r.Details) != `{"i":0}` {
		t.Fatalf("row not filled: %+v", r)
	}
	if last := p.Items[5]; last.ActorName != "mallory" || last.ActorID != "" || last.Outcome != core.OutcomeFailure || last.IP != "192.0.2.1" {
		t.Fatalf("explicit actor not kept: %+v", last)
	}
	v := te.verify(t)
	if !v.OK || v.Checked != 6 || v.FirstSeq != 1 || v.LastSeq != 6 || v.Message != "" {
		t.Fatalf("verify: %+v", v)
	}
	if h, ok := te.meta(t, metaHead); !ok || !strings.HasPrefix(h, "6:") {
		t.Fatalf("head checkpoint %q", h)
	}
}

func TestRecordSanitizes(t *testing.T) {
	te := newTestEnv(t, true)
	te.svc.Record(context.Background(), core.AuditEntry{
		Action: "", Outcome: "bogus", TargetName: "bad\xff\x00name" + strings.Repeat("x", 2000),
		Details: map[string]any{"ch": make(chan int)},
	})
	te.svc.Record(context.Background(), core.AuditEntry{Action: "x.big", Details: strings.Repeat("a", maxDetails+10)})
	p, err := te.svc.Query(context.Background(), core.AuditQuery{PageReq: core.PageReq{Sort: SortOldest}})
	if err != nil {
		t.Fatal(err)
	}
	r := p.Items[0]
	if r.Action != "unknown" || r.Outcome != core.OutcomeFailure || len(r.TargetName) > 512 ||
		strings.Contains(r.TargetName, "\x00") || !strings.HasPrefix(r.TargetName, "bad�name") {
		t.Fatalf("not sanitized: %+v", r)
	}
	if !strings.Contains(string(r.Details), "_error") || string(p.Items[1].Details) != `{"_truncated":true}` {
		t.Fatalf("details: %s / %s", r.Details, p.Items[1].Details)
	}
	if v := te.verify(t); !v.OK {
		t.Fatalf("verify: %+v", v)
	}
}

func TestRecordTxRollsBackWithCaller(t *testing.T) {
	te := newTestEnv(t, true)
	te.record(t, 2, core.ActFileTrash)
	boom := errors.New("boom")
	err := te.env.DB.Tx(context.Background(), func(tx *sql.Tx) error {
		if err := te.svc.RecordTx(ctxAs("usr_b", "bob"), tx, core.AuditEntry{Action: core.ActFilePurge}); err != nil {
			return err
		}
		return boom
	})
	if !errors.Is(err, boom) {
		t.Fatal(err)
	}
	err = te.env.DB.Tx(context.Background(), func(tx *sql.Tx) error {
		return te.svc.RecordTx(ctxAs("usr_b", "bob"), tx, core.AuditEntry{Action: core.ActFileRestore})
	})
	if err != nil {
		t.Fatal(err)
	}
	if n := te.count(t); n != 3 {
		t.Fatalf("rows %d", n)
	}
	if v := te.verify(t); !v.OK || v.Checked != 3 {
		t.Fatalf("verify: %+v", v)
	}
}

func TestTamperDetection(t *testing.T) {
	cases := []struct {
		name   string
		tamper func(t *testing.T, te *testEnv)
		broken int64
	}{
		{"modified action", func(t *testing.T, te *testEnv) {
			te.exec(t, `UPDATE audit_log SET action = 'file.download' WHERE seq = 3`)
		}, 3},
		{"modified details", func(t *testing.T, te *testEnv) {
			te.exec(t, `UPDATE audit_log SET details = '{"i":42}' WHERE seq = 2`)
		}, 2},
		{"modified time", func(t *testing.T, te *testEnv) {
			te.exec(t, `UPDATE audit_log SET at = at + 1 WHERE seq = 5`)
		}, 5},
		{"cleared actor", func(t *testing.T, te *testEnv) {
			te.exec(t, `UPDATE audit_log SET actor_name = NULL WHERE seq = 1`)
		}, 1},
		{"deleted middle row", func(t *testing.T, te *testEnv) {
			te.exec(t, `DELETE FROM audit_log WHERE seq = 3`)
		}, 4},
		{"deleted first row", func(t *testing.T, te *testEnv) {
			te.exec(t, `DELETE FROM audit_log WHERE seq = 1`)
		}, 2},
		{"truncated tail", func(t *testing.T, te *testEnv) {
			te.exec(t, `DELETE FROM audit_log WHERE seq >= 4`)
		}, 5},
		{"swapped hashes", func(t *testing.T, te *testEnv) {
			te.exec(t, `UPDATE audit_log SET hash = (SELECT hash FROM audit_log WHERE seq = 5) WHERE seq = 4`)
		}, 4},
		{"forged head checkpoint", func(t *testing.T, te *testEnv) {
			te.exec(t, `UPDATE meta SET value = '3:' || substr(value, instr(value, ':') + 1) WHERE key = 'audit_head'`)
		}, 3},
		{"deleted head checkpoint", func(t *testing.T, te *testEnv) {
			te.exec(t, `DELETE FROM meta WHERE key = 'audit_head'`)
		}, 1},
		{"forged anchor hides deleted prefix", func(t *testing.T, te *testEnv) {
			te.exec(t, `INSERT INTO meta (key, value) VALUES ('audit_anchor_seq', '2'),
				('audit_anchor_hash', (SELECT hex(hash) FROM audit_log WHERE seq = 2)), ('audit_anchor_mac', '00')`)
			te.exec(t, `DELETE FROM audit_log WHERE seq <= 2`)
		}, 2},
		{"unkeyed rewrite with forged marker", func(t *testing.T, te *testEnv) {
			rewriteUnkeyed(t, te, 1)
		}, 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			te := newTestEnv(t, true)
			te.record(t, 5, core.ActFileUpload)
			if v := te.verify(t); !v.OK {
				t.Fatalf("pre-tamper verify: %+v", v)
			}
			tc.tamper(t, te)
			v := te.verify(t)
			if v.OK || v.BrokenAt != tc.broken || v.Message == "" {
				t.Fatalf("tamper not detected as expected (broken at %d): %+v", tc.broken, v)
			}
		})
	}
}

// rewriteUnkeyed simulates an attacker who sets the unsealed marker to seq
// `from` and recomputes the chain from there with the (public) unkeyed hash.
func rewriteUnkeyed(t *testing.T, te *testEnv, from int64) {
	t.Helper()
	ctx := context.Background()
	err := te.env.DB.Tx(ctx, func(tx *sql.Tx) error {
		prev := zeroHash
		if from > 1 {
			if err := tx.QueryRowContext(ctx, `SELECT hash FROM audit_log WHERE seq = ?`, from-1).Scan(&prev); err != nil {
				return err
			}
		}
		rows, err := tx.QueryContext(ctx, `SELECT `+rowCols+` FROM audit_log WHERE seq >= ? ORDER BY seq`, from)
		if err != nil {
			return err
		}
		var all []*row
		for rows.Next() {
			r, err := scanRow(rows)
			if err != nil {
				return err
			}
			all = append(all, r)
		}
		rows.Close()
		for _, r := range all {
			h := unkeyedChain(prev, r.canonical())
			if _, err := tx.ExecContext(ctx, `UPDATE audit_log SET prev_hash = ?, hash = ? WHERE seq = ?`, prev, h, r.seq); err != nil {
				return err
			}
			prev = h
		}
		return setMeta(ctx, tx, metaUnsealed, "1")
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestLockedRowsAreSealedOnUnlockEvent(t *testing.T) {
	te := newTestEnv(t, false)
	te.record(t, 3, core.ActSystemStart)
	if m, ok := te.meta(t, metaUnsealed); !ok || m != "1" {
		t.Fatalf("marker %q %v", m, ok)
	}
	if _, ok := te.meta(t, metaHead); ok {
		t.Fatal("head written while locked")
	}
	// A never-sealed log verifies without the key and reports unsealed rows.
	v := te.verify(t)
	if !v.OK || v.Checked != 3 || !strings.Contains(v.Message, "3 of 3 rows are not sealed") {
		t.Fatalf("locked verify: %+v", v)
	}

	te.keys.unlocked.Store(true)
	te.env.Bus.Publish(events.Event{Topic: events.TopicKeysState, Data: core.KeysStateEvent{State: core.KeyStateUnlocked}})
	waitFor(t, "reseal", func() bool { _, ok := te.meta(t, metaUnsealed); return !ok })
	v = te.verify(t)
	if !v.OK || v.Checked != 3 || v.Message != "" {
		t.Fatalf("after unlock: %+v", v)
	}
	// Rows are now MAC-chained.
	var prev, h []byte
	if err := te.env.DB.QueryRow(context.Background(), `SELECT prev_hash, hash FROM audit_log WHERE seq = 1`).Scan(&prev, &h); err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(h, unkeyedChain(prev, mustRow(t, te, 1).canonical())) {
		t.Fatal("row 1 still unkeyed")
	}
}

func mustRow(t *testing.T, te *testEnv, seq int64) *row {
	t.Helper()
	r, err := scanRow(te.env.DB.QueryRow(context.Background(), `SELECT `+rowCols+` FROM audit_log WHERE seq = ?`, seq))
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func TestMixedLockedSegmentSealedLazily(t *testing.T) {
	te := newTestEnv(t, true)
	te.record(t, 2, core.ActAuthLogin)
	te.keys.unlocked.Store(false) // e.g. sealed mode after a restart
	te.record(t, 2, core.ActKeysUnlock)
	if m, _ := te.meta(t, metaUnsealed); m != "3" {
		t.Fatalf("marker %q", m)
	}
	if _, err := te.svc.Verify(context.Background()); !errors.Is(err, core.ErrKeysLocked) {
		t.Fatalf("verify while locked: %v", err)
	}
	// Prune never touches unsealed rows and needs the key.
	if _, err := te.svc.Prune(context.Background(), te.clock.Now()); !errors.Is(err, core.ErrKeysLocked) {
		t.Fatalf("prune while locked: %v", err)
	}

	te.keys.unlocked.Store(true) // no event: the next Record seals lazily
	err := te.env.DB.Tx(context.Background(), func(tx *sql.Tx) error {
		return te.svc.RecordTx(context.Background(), tx, core.AuditEntry{Action: core.ActKeysUnlock})
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := te.meta(t, metaUnsealed); ok {
		t.Fatal("marker not removed")
	}
	if v := te.verify(t); !v.OK || v.Checked != 5 || v.Message != "" {
		t.Fatalf("verify: %+v", v)
	}
}

// TestKeyLostMidInsertDowngradesRow covers the race where the MAC key
// disappears between the chain MAC and the head checkpoint of one insert:
// the row must become the first unsealed row (the head keeps naming the last
// sealed row), and the next unlock seals it normally.
func TestKeyLostMidInsertDowngradesRow(t *testing.T) {
	te := newTestEnv(t, true)
	te.record(t, 2, core.ActAuthLogin)
	te.keys.headFail.Store(true)
	te.record(t, 1, core.ActAuthLogout)
	if m, _ := te.meta(t, metaUnsealed); m != "3" {
		t.Fatalf("marker %q, want 3", m)
	}
	if h, _ := te.meta(t, metaHead); !strings.HasPrefix(h, "2:") {
		t.Fatalf("head %q moved past the last sealed row", h)
	}
	r := mustRow(t, te, 3)
	if !bytes.Equal(r.hash, unkeyedChain(r.prevHash, r.canonical())) {
		t.Fatal("row 3 is not chained with the unkeyed hash")
	}
	te.keys.headFail.Store(false)
	if v := te.verify(t); !v.OK || !strings.Contains(v.Message, "1 of 3 rows are not sealed") {
		t.Fatalf("verify with downgraded row: %+v", v)
	}
	if err := te.svc.Reseal(context.Background()); err != nil {
		t.Fatalf("reseal: %v", err)
	}
	if _, ok := te.meta(t, metaUnsealed); ok {
		t.Fatal("marker not removed")
	}
	if h, _ := te.meta(t, metaHead); !strings.HasPrefix(h, "3:") {
		t.Fatalf("head %q after reseal", h)
	}
	if v := te.verify(t); !v.OK || v.Checked != 3 || v.Message != "" {
		t.Fatalf("verify after reseal: %+v", v)
	}
}

// ---------- truncated reseal scan ----------

// faultDriver wraps the sqlite driver so that the reseal batch scan fails at
// row level: the query succeeds and the first Next reports an error. That is
// the shape of a truncated read (a lost connection, an I/O error, a
// cancelled context) and rows.Close cannot report it — only rows.Err can.
type faultDriver struct{ d driver.Driver }

type faultConn struct{ driver.Conn }

type faultStmt struct {
	driver.Stmt
	q string
}

type faultRows struct{ driver.Rows }

const faultQuery = "FROM audit_log WHERE seq >= ?"

var errInjectedRead = errors.New("injected read fault")

func (f faultDriver) Open(name string) (driver.Conn, error) {
	c, err := f.d.Open(name)
	if err != nil {
		return nil, err
	}
	return faultConn{c}, nil
}

func (c faultConn) Prepare(q string) (driver.Stmt, error) {
	st, err := c.Conn.Prepare(q)
	if err != nil {
		return nil, err
	}
	if _, ok := st.(driver.StmtQueryContext); !ok {
		return nil, errors.New("fault driver: the underlying statement does not implement StmtQueryContext")
	}
	return faultStmt{Stmt: st, q: q}, nil
}

// QueryContext is the interceptor. database/sql prefers StmtQueryContext over
// the deprecated Stmt.Query, and the embedded driver.Stmt keeps the legacy
// method promoted so the interface stays satisfied.
func (s faultStmt) QueryContext(ctx context.Context, args []driver.NamedValue) (driver.Rows, error) {
	rows, err := s.Stmt.(driver.StmtQueryContext).QueryContext(ctx, args)
	if err != nil || !strings.Contains(s.q, faultQuery) {
		return rows, err
	}
	return faultRows{rows}, nil
}

func (faultRows) Next([]driver.Value) error { return errInjectedRead }

var faultOnce sync.Once

// faultyDB opens path through faultDriver.
func faultyDB(t *testing.T, path string) *sql.DB {
	t.Helper()
	faultOnce.Do(func() {
		base, err := sql.Open("sqlite", ":memory:")
		if err != nil {
			t.Fatalf("base driver: %v", err)
		}
		sql.Register("sqlite-audit-fault", faultDriver{d: base.Driver()})
		_ = base.Close()
	})
	d, err := sql.Open("sqlite-audit-fault", path+"?_pragma=busy_timeout(5000)&_txlock=immediate")
	if err != nil {
		t.Fatalf("faulty db: %v", err)
	}
	d.SetMaxOpenConns(1)
	t.Cleanup(func() { _ = d.Close() })
	return d
}

// A row-level read error truncates the reseal scan: the batch comes back
// empty although unsealed rows remain. resealTx must report it instead of
// treating it as "no rows left" — clearing the marker there would leave
// unkeyed rows behind, and the next Verify would report tampering on a log
// nobody touched.
func TestResealStopsOnTruncatedScan(t *testing.T) {
	te := newTestEnv(t, false) // locked keys: the rows are written unsealed
	te.record(t, 3, core.ActSystemStart)
	if m, ok := te.meta(t, metaUnsealed); !ok || m != "1" {
		t.Fatalf("marker %q %v", m, ok)
	}
	te.keys.unlocked.Store(true)

	ctx := context.Background()
	fdb := faultyDB(t, te.env.Home.DB())
	tx, err := fdb.BeginTx(ctx, nil)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	err = te.svc.resealTx(ctx, tx, 1)
	if err == nil {
		// the caller would commit a half-resealed log
		_ = tx.Commit()
		t.Fatal("a truncated scan must abort the reseal")
	}
	if !errors.Is(err, errInjectedRead) {
		t.Fatalf("reseal error %v, want the read fault", err)
	}
	if err := tx.Commit(); err != nil { // the savepoint rolled the work back
		t.Fatalf("commit: %v", err)
	}
	if m, ok := te.meta(t, metaUnsealed); !ok || m != "1" {
		t.Fatalf("marker cleared after a truncated scan: %q %v", m, ok)
	}
	if v := te.verify(t); !v.OK || !strings.Contains(v.Message, "3 of 3 rows are not sealed") {
		t.Fatalf("verify after the failed reseal: %+v", v)
	}
	// the next attempt (a healthy connection) seals them normally
	if err := te.svc.Reseal(ctx); err != nil {
		t.Fatalf("retry: %v", err)
	}
	if _, ok := te.meta(t, metaUnsealed); ok {
		t.Fatal("marker not removed by the retry")
	}
	if v := te.verify(t); !v.OK || v.Checked != 3 || v.Message != "" {
		t.Fatalf("verify after the retry: %+v", v)
	}
}

func TestResealRefusesForgedSegment(t *testing.T) {
	te := newTestEnv(t, true)
	te.record(t, 4, core.ActFileUpload)
	rewriteUnkeyed(t, te, 1) // forged marker before sealed rows
	err := te.svc.Reseal(context.Background())
	if !errors.Is(err, errTampered) {
		t.Fatalf("reseal of forged segment: %v", err)
	}
	if _, ok := te.meta(t, metaUnsealed); !ok {
		t.Fatal("forged marker removed")
	}
	// New rows stay unsealed; the log keeps reporting the break.
	te.record(t, 1, core.ActFileUpload)
	if v := te.verify(t); v.OK {
		t.Fatalf("forged chain verified: %+v", v)
	}

	// A modified unsealed row is refused too.
	te2 := newTestEnv(t, false)
	te2.record(t, 3, core.ActSystemStart)
	te2.exec(t, `UPDATE audit_log SET action = 'x' WHERE seq = 2`)
	te2.keys.unlocked.Store(true)
	if err := te2.svc.Reseal(context.Background()); !errors.Is(err, errTampered) {
		t.Fatalf("reseal of modified unsealed row: %v", err)
	}
}

func TestPruneAnchor(t *testing.T) {
	te := newTestEnv(t, true)
	start := te.clock.Now()
	te.record(t, 10, core.ActFileDownload) // at = start + i s
	n, err := te.svc.Prune(context.Background(), start.Add(4*time.Second))
	if err != nil || n != 4 {
		t.Fatalf("prune %d %v", n, err)
	}
	v := te.verify(t)
	if !v.OK || v.Checked != 6 || v.FirstSeq != 5 || v.LastSeq != 10 {
		t.Fatalf("verify after prune: %+v", v)
	}
	if s, _ := te.meta(t, metaAnchorSeq); s != "4" {
		t.Fatalf("anchor seq %q", s)
	}
	// Nothing older left: no-op.
	if n, err := te.svc.Prune(context.Background(), start.Add(4*time.Second)); err != nil || n != 0 {
		t.Fatalf("second prune %d %v", n, err)
	}
	te.record(t, 2, core.ActFileDownload)
	if v := te.verify(t); !v.OK || v.Checked != 8 {
		t.Fatalf("verify after append: %+v", v)
	}
	// Prune everything; new rows chain to the anchor.
	if n, err := te.svc.Prune(context.Background(), te.clock.Now().Add(time.Hour)); err != nil || n != 8 {
		t.Fatalf("prune all %d %v", n, err)
	}
	if v := te.verify(t); !v.OK || v.Checked != 0 {
		t.Fatalf("verify empty: %+v", v)
	}
	te.record(t, 1, core.ActFileDownload)
	if v := te.verify(t); !v.OK || v.Checked != 1 || v.FirstSeq != 13 {
		t.Fatalf("verify after re-append: %+v", v)
	}
	// Tampering with the anchor is detected.
	te.exec(t, `UPDATE meta SET value = '0000000000000000000000000000000000000000000000000000000000000000' WHERE key = 'audit_anchor_hash'`)
	if v := te.verify(t); v.OK {
		t.Fatalf("forged anchor accepted: %+v", v)
	}
}

func TestPruneStopsAtOutOfOrderTimeAndUnsealed(t *testing.T) {
	te := newTestEnv(t, true)
	base := te.clock.Now()
	te.record(t, 3, core.ActFileUpload) // seq 1..3 at base+0..2s
	te.clock.Set(base.Add(time.Hour))   // seq 4 is new
	te.record(t, 1, core.ActFileUpload)
	te.clock.Set(base.Add(10 * time.Second)) // seq 5 is old again (clock step back)
	te.record(t, 1, core.ActFileUpload)
	n, err := te.svc.Prune(context.Background(), base.Add(30*time.Minute))
	if err != nil || n != 3 {
		t.Fatalf("prune %d %v", n, err)
	}
	if v := te.verify(t); !v.OK || v.FirstSeq != 4 {
		t.Fatalf("verify: %+v", v)
	}

	te2 := newTestEnv(t, true)
	te2.record(t, 2, core.ActFileUpload)
	te2.keys.unlocked.Store(false)
	te2.record(t, 2, core.ActFileUpload)
	te2.keys.unlocked.Store(true)
	// Reseal is pending (no event, no record) — prune must stop before the marker.
	if _, ok := te2.meta(t, metaUnsealed); !ok {
		t.Fatal("expected marker")
	}
	if n, err := te2.svc.Prune(context.Background(), te2.clock.Now().Add(time.Hour)); err != nil || n != 2 {
		t.Fatalf("prune %d %v", n, err)
	}
	if err := te2.svc.Reseal(context.Background()); err != nil {
		t.Fatal(err)
	}
	if v := te2.verify(t); !v.OK || v.Checked != 2 || v.FirstSeq != 3 {
		t.Fatalf("verify: %+v", v)
	}
}

func TestQueryFiltersAndPagination(t *testing.T) {
	te := newTestEnv(t, true)
	ctx := context.Background()
	t0 := te.clock.Now()
	add := func(p context.Context, e core.AuditEntry) {
		te.svc.Record(p, e)
		te.clock.Advance(time.Minute)
	}
	add(ctxAs("usr_a", "alice"), core.AuditEntry{Action: core.ActAuthLogin})
	add(ctxAs("usr_b", "bob"), core.AuditEntry{Action: core.ActAuthLogin, Outcome: core.OutcomeFailure})
	add(ctxAs("usr_a", "alice"), core.AuditEntry{Action: core.ActAuthLogout})
	add(ctxAs("usr_a", "alice"), core.AuditEntry{Action: core.ActFileRename, TargetType: "node", TargetID: "nod_1", TargetName: "Report_100%.pdf"})
	add(ctxAs("usr_b", "bob"), core.AuditEntry{Action: core.ActShareCreate, TargetType: "share", TargetID: "shr_1", Outcome: core.OutcomeDenied})
	add(context.Background(), core.AuditEntry{Action: "authx.weird"})

	cases := []struct {
		name string
		q    core.AuditQuery
		want []int64
	}{
		{"all newest first", core.AuditQuery{}, []int64{6, 5, 4, 3, 2, 1}},
		{"oldest first", core.AuditQuery{PageReq: core.PageReq{Sort: SortOldest}}, []int64{1, 2, 3, 4, 5, 6}},
		{"action exact", core.AuditQuery{Action: core.ActAuthLogin}, []int64{2, 1}},
		{"action prefix dot", core.AuditQuery{Action: "auth."}, []int64{3, 2, 1}},
		{"action prefix star", core.AuditQuery{Action: "auth.*"}, []int64{3, 2, 1}},
		{"actor", core.AuditQuery{ActorID: "usr_b"}, []int64{5, 2}},
		{"outcome", core.AuditQuery{Outcome: core.OutcomeDenied}, []int64{5}},
		{"target", core.AuditQuery{TargetType: "node", TargetID: "nod_1"}, []int64{4}},
		{"since/until", core.AuditQuery{Since: ptr(t0.Add(time.Minute)), Until: ptr(t0.Add(3 * time.Minute))}, []int64{4, 3, 2}},
		{"q name with wildcard", core.AuditQuery{Q: "100%"}, []int64{4}},
		{"q no wildcard leak", core.AuditQuery{Q: "_"}, []int64{4}},
		{"q actor", core.AuditQuery{Q: "bo"}, []int64{5, 2}},
		{"q target id", core.AuditQuery{Q: "shr_1"}, []int64{5}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p, err := te.svc.Query(ctx, tc.q)
			if err != nil {
				t.Fatal(err)
			}
			var got []int64
			for _, r := range p.Items {
				got = append(got, r.Seq)
			}
			if !equalSeqs(got, tc.want) {
				t.Fatalf("got %v want %v", got, tc.want)
			}
		})
	}

	// Keyset pagination in both directions.
	for _, sort := range []string{"", SortOldest} {
		var seen []int64
		q := core.AuditQuery{PageReq: core.PageReq{Limit: 4, Sort: sort}}
		for i := 0; i < 5; i++ {
			p, err := te.svc.Query(ctx, q)
			if err != nil {
				t.Fatal(err)
			}
			for _, r := range p.Items {
				seen = append(seen, r.Seq)
			}
			if p.NextCursor == "" {
				break
			}
			q.Cursor = p.NextCursor
		}
		if len(seen) != 6 {
			t.Fatalf("sort %q paginated %v", sort, seen)
		}
	}

	for _, bad := range []core.AuditQuery{
		{Outcome: "maybe"},
		{PageReq: core.PageReq{Cursor: "!!!"}},
		{PageReq: core.PageReq{Sort: "random"}},
		{Q: strings.Repeat("x", 300)},
	} {
		if _, err := te.svc.Query(ctx, bad); !errors.Is(err, core.ErrInvalid) {
			t.Errorf("query %+v: %v", bad, err)
		}
	}
}

func ptr[T any](v T) *T { return &v }

func equalSeqs(a, b []int64) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func TestExport(t *testing.T) {
	te := newTestEnv(t, true)
	ctx := context.Background()
	te.svc.Record(ctxAs("usr_a", "=cmd|' /C calc'!A0"), core.AuditEntry{Action: core.ActFileRename, TargetName: "+evil", Details: map[string]string{"k": "v"}})
	te.record(t, 1200, core.ActFileDownload) // more than one export batch

	var buf bytes.Buffer
	if err := te.svc.Export(ctx, core.AuditQuery{}, FormatCSV, &buf); err != nil {
		t.Fatal(err)
	}
	recs, err := csv.NewReader(&buf).ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) != 1202 || recs[0][0] != "seq" || recs[1][0] != "1" || recs[1202-1][0] != "1201" {
		t.Fatalf("csv rows %d first %v", len(recs), recs[:2])
	}
	if recs[1][4] != "'=cmd|' /C calc'!A0" || recs[1][13] != "'+evil" || recs[1][14] != `{"k":"v"}` || len(recs[1][16]) != 64 {
		t.Fatalf("csv not sanitized: %q", recs[1])
	}

	buf.Reset()
	if err := te.svc.Export(ctx, core.AuditQuery{Action: core.ActFileRename}, FormatJSONL, &buf); err != nil {
		t.Fatal(err)
	}
	sc := bufio.NewScanner(&buf)
	var lines []map[string]any
	for sc.Scan() {
		var m map[string]any
		if err := json.Unmarshal(sc.Bytes(), &m); err != nil {
			t.Fatal(err)
		}
		lines = append(lines, m)
	}
	if len(lines) != 1 || lines[0]["action"] != core.ActFileRename || len(lines[0]["hash"].(string)) != 64 {
		t.Fatalf("jsonl %v", lines)
	}
	if err := te.svc.Export(ctx, core.AuditQuery{}, "xml", &buf); !errors.Is(err, core.ErrInvalid) {
		t.Fatalf("bad format: %v", err)
	}
	cctx, cancel := context.WithCancel(ctx)
	cancel()
	if err := te.svc.Export(cctx, core.AuditQuery{}, FormatJSONL, &buf); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled export: %v", err)
	}
}

func TestFailedWritesAreRetried(t *testing.T) {
	te := newTestEnv(t, true)
	te.record(t, 1, core.ActFileUpload)
	te.exec(t, `CREATE TRIGGER audit_fail BEFORE INSERT ON audit_log BEGIN SELECT RAISE(ABORT, 'disk full'); END`)
	te.svc.Record(ctxAs("usr_a", "alice"), core.AuditEntry{Action: core.ActFileTrash}) // must not panic or block
	if n := te.svc.pendingLen(); n != 1 {
		t.Fatalf("pending %d", n)
	}
	te.exec(t, `DROP TRIGGER audit_fail`)
	te.svc.signal()
	waitFor(t, "retry", func() bool { return te.svc.pendingLen() == 0 })
	if n := te.count(t); n != 2 {
		t.Fatalf("rows %d", n)
	}
	if v := te.verify(t); !v.OK {
		t.Fatalf("verify %+v", v)
	}

	// The queue is bounded.
	te2 := newTestEnv(t, true)
	for i := 0; i < MaxPending+5; i++ {
		te2.svc.enqueue(&row{id: "x"})
	}
	if n := te2.svc.pendingLen(); n != MaxPending || te2.svc.dropped != 5 {
		t.Fatalf("pending %d dropped %d", n, te2.svc.dropped)
	}
	te2.svc.mu.Lock()
	te2.svc.pending = nil
	te2.svc.mu.Unlock()
}

func TestConcurrentRecords(t *testing.T) {
	te := newTestEnv(t, true)
	var wg sync.WaitGroup
	for g := 0; g < 8; g++ {
		wg.Go(func() {
			for i := 0; i < 25; i++ {
				if i%2 == 0 {
					te.svc.Record(ctxAs("usr_c", "carol"), core.AuditEntry{Action: core.ActFileCopy})
				} else {
					_ = te.env.DB.Tx(context.Background(), func(tx *sql.Tx) error {
						return te.svc.RecordTx(ctxAs("usr_c", "carol"), tx, core.AuditEntry{Action: core.ActFileMove})
					})
				}
			}
		})
	}
	wg.Wait()
	if v := te.verify(t); !v.OK || v.Checked != 200 {
		t.Fatalf("verify %+v", v)
	}
}

func TestMirrorJSONL(t *testing.T) {
	te := newTestEnv(t, true)
	te.record(t, 3, core.ActFileUpload)
	te.settings.set(SettingMirrorJSONL, true)
	te.svc.signal()
	path := filepath.Join(te.env.Home.LogsDir(), mirrorFileName)
	countLines := func() int {
		b, err := os.ReadFile(path)
		if err != nil {
			return 0
		}
		return bytes.Count(b, []byte("\n"))
	}
	waitFor(t, "mirror", func() bool { return countLines() == 3 })
	te.record(t, 2, core.ActFileDownload)
	waitFor(t, "mirror append", func() bool { return countLines() == 5 })
	waitFor(t, "position", func() bool { v, _ := te.meta(t, metaMirrorSeq); return v == "5" })

	// A new service instance resumes at the saved position (no duplicates).
	if err := te.svc.Close(); err != nil {
		t.Fatal(err)
	}
	svc2, err := New(te.env)
	if err != nil {
		t.Fatal(err)
	}
	defer svc2.Close()
	svc2.Record(context.Background(), core.AuditEntry{Action: core.ActSystemStart})
	waitFor(t, "resume", func() bool { return countLines() == 6 })
	b, _ := os.ReadFile(path)
	var last core.AuditRecord
	lines := bytes.Split(bytes.TrimSpace(b), []byte("\n"))
	if err := json.Unmarshal(lines[len(lines)-1], &last); err != nil || last.Seq != 6 || last.Action != core.ActSystemStart {
		t.Fatalf("last line %s (%v)", lines[len(lines)-1], err)
	}
}

type fakeJobHandle struct{ result any }

func (f *fakeJobHandle) ID() string                    { return "job_x" }
func (f *fakeJobHandle) Params(any) error              { return nil }
func (f *fakeJobHandle) Progress(int64, int64, string) {}
func (f *fakeJobHandle) SetResult(v any)               { f.result = v }

type fakeJobs struct {
	core.Jobs
	kinds     map[string]core.JobFunc
	schedules map[string]string
}

func (f *fakeJobs) Register(kind string, fn core.JobFunc, _ core.JobOptions) { f.kinds[kind] = fn }
func (f *fakeJobs) Schedule(name, cron, kind string, _ any) error {
	f.schedules[name] = cron + " " + kind
	return nil
}

func TestPruneJob(t *testing.T) {
	te := newTestEnv(t, true)
	te.record(t, 3, core.ActFileUpload)
	j := &fakeJobs{kinds: map[string]core.JobFunc{}, schedules: map[string]string{}}
	if err := te.svc.RegisterJobs(j); err != nil {
		t.Fatal(err)
	}
	fn := j.kinds[core.JobMaintAuditPrune]
	if fn == nil || j.schedules[pruneSchedule] != pruneCron+" "+core.JobMaintAuditPrune {
		t.Fatalf("not registered: %v", j.schedules)
	}
	h := &fakeJobHandle{}
	if err := fn(context.Background(), h); err != nil || h.result.(PruneResult).Skipped == "" {
		t.Fatalf("disabled retention: %v %+v", err, h.result)
	}
	te.settings.set(SettingRetentionDays, int64(1))
	te.clock.Advance(48 * time.Hour)
	te.record(t, 1, core.ActFileUpload)
	if err := fn(context.Background(), h); err != nil || h.result.(PruneResult).Pruned != 3 {
		t.Fatalf("prune job: %v %+v", err, h.result)
	}
	if v := te.verify(t); !v.OK || v.Checked != 1 {
		t.Fatalf("verify %+v", v)
	}
}

func TestCursorRoundTrip(t *testing.T) {
	c := encodeCursor(42)
	if n, err := decodeCursor(c); err != nil || n != 42 {
		t.Fatalf("%d %v", n, err)
	}
	for _, bad := range []string{"", "e30", "eyJzIjotMX0"} { // "", {}, {"s":-1}
		if _, err := decodeCursor(bad); err == nil {
			t.Errorf("cursor %q accepted", bad)
		}
	}
}

func TestVerifyDetectsMissingHeadAfterPrune(t *testing.T) {
	te := newTestEnv(t, true)
	start := te.clock.Now()
	te.record(t, 6, core.ActFileUpload)
	if n, err := te.svc.Prune(context.Background(), start.Add(3*time.Second)); err != nil || n != 3 {
		t.Fatalf("prune %d %v", n, err)
	}
	// An attacker deletes the head checkpoint, marks every remaining row as
	// unsealed and rewrites them with the unkeyed hash from the anchor on.
	te.exec(t, `DELETE FROM meta WHERE key = 'audit_head'`)
	ctx := context.Background()
	err := te.env.DB.Tx(ctx, func(tx *sql.Tx) error {
		a, _, err := readAnchor(ctx, tx)
		if err != nil {
			return err
		}
		prev := a.hash
		for seq := int64(4); seq <= 6; seq++ {
			r, err := scanRow(tx.QueryRowContext(ctx, `SELECT `+rowCols+` FROM audit_log WHERE seq = ?`, seq))
			if err != nil {
				return err
			}
			r.action = "forged"
			h := unkeyedChain(prev, r.canonical())
			if _, err := tx.ExecContext(ctx, `UPDATE audit_log SET action = ?, prev_hash = ?, hash = ? WHERE seq = ?`, r.action, prev, h, seq); err != nil {
				return err
			}
			prev = h
		}
		return setMeta(ctx, tx, metaUnsealed, "4")
	})
	if err != nil {
		t.Fatal(err)
	}
	v := te.verify(t)
	if v.OK || v.BrokenAt != 3 {
		t.Fatalf("forgery not detected: %+v", v)
	}
	if err := te.svc.Reseal(ctx); !errors.Is(err, errTampered) {
		t.Fatalf("reseal blessed a forged segment: %v", err)
	}
}

// ---------- rows sealed without proof of origin ----------

// appendForeignUnsealed simulates a database writer without the keys: it
// appends an unkeyed row that continues the chain and, unless rows are
// already unsealed, points the unsealed marker at it. It returns its seq.
func appendForeignUnsealed(t *testing.T, te *testEnv, action string) int64 {
	t.Helper()
	ctx := context.Background()
	var seq int64
	err := te.env.DB.Tx(ctx, func(tx *sql.Tx) error {
		prev, err := chainHead(ctx, tx)
		if err != nil {
			return err
		}
		r := te.svc.prepare(core.AuditEntry{Action: action, ActorID: "usr_victim", ActorName: "victim",
			TargetType: "node", TargetID: "nod_secret"})
		if seq, err = insertRow(ctx, tx, r, prev, unkeyedChain(prev, r.canonical())); err != nil {
			return err
		}
		if _, ok, err := metaInt(ctx, tx, metaUnsealed); err != nil || ok {
			return err
		}
		return setMeta(ctx, tx, metaUnsealed, strconv.FormatInt(seq, 10))
	})
	if err != nil {
		t.Fatal(err)
	}
	return seq
}

// resealEntries returns the audit.reseal rows (outcome must be failure).
func resealEntries(t *testing.T, te *testEnv) []resealDetails {
	t.Helper()
	rows, err := te.env.DB.Query(context.Background(), `SELECT outcome, details FROM audit_log WHERE action = ? ORDER BY seq`, core.ActAuditReseal)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var out []resealDetails
	for rows.Next() {
		var outcome, details string
		if err := rows.Scan(&outcome, &details); err != nil {
			t.Fatal(err)
		}
		var d resealDetails
		if err := json.Unmarshal([]byte(details), &d); err != nil || outcome != core.OutcomeFailure {
			t.Fatalf("audit.reseal entry %s (%s): %v", details, outcome, err)
		}
		out = append(out, d)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return out
}

// TestResealFlagsForeignRows: an unkeyed row appended by someone without the
// keys is sealed by the next Record (the chain must stay continuous), but a
// sealed audit.reseal entry names it and Verify reports it, instead of the
// row becoming indistinguishable from genuine ones.
func TestResealFlagsForeignRows(t *testing.T) {
	te := newTestEnv(t, true)
	ctx := context.Background()
	te.record(t, 3, core.ActFileUpload)
	forged := appendForeignUnsealed(t, te, core.ActFileDownload)
	if v := te.verify(t); !v.OK || !strings.Contains(v.Message, "1 of 4 rows are not sealed") {
		t.Fatalf("before the reseal: %+v", v)
	}
	te.clock.Advance(time.Second)
	te.record(t, 1, core.ActAuthLogin) // seals lazily
	if _, ok := te.meta(t, metaUnsealed); ok {
		t.Fatal("marker not removed")
	}
	got := resealEntries(t, te)
	if len(got) != 1 || got[0].FromSeq != forged || got[0].ToSeq != forged || got[0].Sealed != 1 ||
		got[0].Unverified != 1 || !equalSeqs(got[0].UnverifiedSeqs, []int64{forged}) {
		t.Fatalf("audit.reseal entries %+v", got)
	}
	if r := mustRow(t, te, forged+1); r.action != core.ActAuditReseal {
		t.Fatalf("row after the sealed segment is %q", r.action)
	}
	v := te.verify(t)
	if !v.OK || v.Checked != 6 || !strings.Contains(v.Message, "1 row was sealed after an unlock without proof of origin") ||
		!strings.Contains(v.Message, "(seq 4;") {
		t.Fatalf("verify after the reseal: %+v", v)
	}
	// The note goes away with the flagged rows.
	if n, err := te.svc.Prune(ctx, te.clock.Now().Add(-time.Second)); err != nil || n != 4 {
		t.Fatalf("prune %d %v", n, err)
	}
	if v := te.verify(t); !v.OK || v.Checked != 2 || v.Message != "" {
		t.Fatalf("verify after prune: %+v", v)
	}
}

// TestResealByNewServiceFlagsEarlierRows: rows another process wrote while
// the keys were locked (an earlier server run, an offline command) are
// flagged when sealed; the sealing process's own rows are not.
func TestResealByNewServiceFlagsEarlierRows(t *testing.T) {
	te := newTestEnv(t, false)
	ctx := context.Background()
	te.record(t, 2, core.ActSystemStart) // a run that stopped before an unlock
	if err := te.svc.Close(); err != nil {
		t.Fatal(err)
	}
	svc2, err := New(te.env)
	if err != nil {
		t.Fatal(err)
	}
	defer svc2.Close()
	svc2.Record(ctx, core.AuditEntry{Action: core.ActSystemStart})
	te.keys.unlocked.Store(true)
	if err := svc2.Reseal(ctx); err != nil {
		t.Fatalf("reseal: %v", err)
	}
	got := resealEntries(t, te)
	if len(got) != 1 || got[0].FromSeq != 1 || got[0].ToSeq != 3 || got[0].Sealed != 3 ||
		got[0].Unverified != 2 || !equalSeqs(got[0].UnverifiedSeqs, []int64{1, 2}) {
		t.Fatalf("audit.reseal entries %+v", got)
	}
	v, err := svc2.Verify(ctx)
	if err != nil || !v.OK || v.Checked != 4 || !strings.Contains(v.Message, "2 rows were sealed") || !strings.Contains(v.Message, "(seq 1, 2;") {
		t.Fatalf("verify: %+v %v", v, err)
	}

	// A later locked period of the same process is sealed silently.
	svc2.Record(ctx, core.AuditEntry{Action: core.ActAuthLogin})
	te.keys.unlocked.Store(false)
	svc2.Record(ctx, core.AuditEntry{Action: core.ActKeysLock})
	te.keys.unlocked.Store(true)
	if err := svc2.Reseal(ctx); err != nil {
		t.Fatalf("second reseal: %v", err)
	}
	if got := resealEntries(t, te); len(got) != 1 {
		t.Fatalf("own rows flagged: %+v", got)
	}
	if v, err := svc2.Verify(ctx); err != nil || !v.OK || v.Checked != 6 {
		t.Fatalf("verify: %+v %v", v, err)
	}
}

// ---------- retention job while locked ----------

// TestPruneJobSkipsWhileLocked: the registration replaces the jobs package's
// built-in, so it must also report a locked server as a skip, not a failure.
func TestPruneJobSkipsWhileLocked(t *testing.T) {
	te := newTestEnv(t, false)
	te.record(t, 2, core.ActSystemStart)
	te.settings.set(SettingRetentionDays, int64(1))
	j := &fakeJobs{kinds: map[string]core.JobFunc{}, schedules: map[string]string{}}
	if err := te.svc.RegisterJobs(j); err != nil {
		t.Fatal(err)
	}
	h := &fakeJobHandle{}
	if err := j.kinds[core.JobMaintAuditPrune](context.Background(), h); err != nil {
		t.Fatalf("locked prune job failed: %v", err)
	}
	if res, _ := h.result.(PruneResult); res.Skipped != "keys locked" || res.RetentionDays != 1 {
		t.Fatalf("result %+v", h.result)
	}
}

// ---------- JSONL mirror lines ----------

// TestMirrorJSONLRotationKeepsLinesWhole: a backlog far larger than one
// write chunk, mirrored across several rotations, leaves every record on a
// line of its own in exactly one file.
func TestMirrorJSONLRotationKeepsLinesWhole(t *testing.T) {
	te := newTestEnv(t, true)
	ctx := context.Background()
	const n = 2500
	pad := strings.Repeat("x", 900)
	err := te.env.DB.Tx(ctx, func(tx *sql.Tx) error {
		for i := 0; i < n; i++ {
			if err := te.svc.RecordTx(ctx, tx, core.AuditEntry{Action: core.ActFileUpload, Details: map[string]any{"i": i, "pad": pad}}); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{}
	cfg.Log.MaxSizeMB, cfg.Log.MaxFiles = 1, 10
	te.env.Config = cfg // read by the loop only once the mirror is enabled below
	te.settings.set(SettingMirrorJSONL, true)
	te.svc.signal()
	waitFor(t, "mirror", func() bool { v, _ := te.meta(t, metaMirrorSeq); return v == strconv.Itoa(n) })

	base := filepath.Join(te.env.Home.LogsDir(), mirrorFileName)
	var files []string
	for i := cfg.Log.MaxFiles; i >= 1; i-- {
		if p := fmt.Sprintf("%s.%d", base, i); fileExists(p) {
			files = append(files, p)
		}
	}
	if len(files) < 2 {
		t.Fatalf("expected at least two rotations, got %v", files)
	}
	files = append(files, base)
	seen := make(map[int64]int, n)
	for _, p := range files {
		b, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		if len(b) == 0 || b[len(b)-1] != '\n' {
			t.Errorf("%s does not end with a whole line", filepath.Base(p))
			continue
		}
		for _, line := range bytes.Split(bytes.TrimSuffix(b, []byte("\n")), []byte("\n")) {
			var rec core.AuditRecord
			if err := json.Unmarshal(line, &rec); err != nil {
				t.Fatalf("%s: line is not a whole record: %.60q… (%v)", filepath.Base(p), line, err)
			}
			seen[rec.Seq]++
		}
	}
	for seq := int64(1); seq <= n; seq++ {
		if seen[seq] != 1 {
			t.Fatalf("seq %d mirrored %d times", seq, seen[seq])
		}
	}
}

func fileExists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}

// TestMirrorJSONLEndsTornLine: a partial last line (a write that failed
// part-way, a crash) is ended before new rows are appended, so the next
// record does not get glued onto it.
func TestMirrorJSONLEndsTornLine(t *testing.T) {
	te := newTestEnv(t, true)
	te.record(t, 2, core.ActFileUpload)
	path := filepath.Join(te.env.Home.LogsDir(), mirrorFileName)
	const fragment = `{"seq":0,"id":"aud_x","at":"2026`
	if err := os.WriteFile(path, []byte(fragment), 0o640); err != nil {
		t.Fatal(err)
	}
	te.settings.set(SettingMirrorJSONL, true)
	te.svc.signal()
	waitFor(t, "mirror", func() bool { v, _ := te.meta(t, metaMirrorSeq); return v == "2" })
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	lines := bytes.Split(bytes.TrimSuffix(b, []byte("\n")), []byte("\n"))
	if len(lines) != 3 || string(lines[0]) != fragment {
		t.Fatalf("mirror file %q", b)
	}
	for i, line := range lines[1:] {
		var rec core.AuditRecord
		if err := json.Unmarshal(line, &rec); err != nil || rec.Seq != int64(i+1) {
			t.Fatalf("line %d %q: %v", i+2, line, err)
		}
	}
}
