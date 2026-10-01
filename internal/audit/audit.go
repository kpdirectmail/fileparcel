// Package audit implements the HMAC-chained audit log (DESIGN §9.6; owned by
// unit C).
//
// # Chain
//
// Every row of audit_log carries prev_hash (the hash of the previous row, or
// the prune anchor, or 32 zero bytes for the very first row) and
//
//	hash = Keys.MAC("audit", prev_hash, canonical(row))
//
// where canonical(row) is the JSON array
// ["v1", id, at_ms, actor_id, actor_name, actor_via, ip, user_agent,
// request_id, action, outcome, target_type, target_id, target_name, details].
//
// # Key-state rule (core.Audit)
//
// Rows are persisted immediately in every key state. While the mac KEK is
// unavailable (keys locked or uninitialized) a row is chained with the
// unkeyed hash SHA-256(prev_hash || canonical(row)) and meta
// "audit_unsealed_seq" records the first such row. When the keys become
// unlocked (keys.state event, or lazily on the next Record) every row from
// that seq is re-chained with the MAC in one transaction ("resealing") and the
// marker is removed. Verify reports rows that are still unsealed.
//
// An unsealed row proves nothing about its origin: the unkeyed hash needs no
// key, so anyone who can write the database while the keys are unavailable
// can append rows that the next reseal would seal. The service therefore
// remembers the unkeyed hashes of the rows it wrote unsealed itself, and a
// reseal that seals any other row (written by an earlier server run, an
// offline command, or someone else) appends a sealed audit.reseal entry
// naming those rows. Verify reports them for as long as that entry is kept.
//
// # Checkpoints
//
// Two MAC-authenticated checkpoints live in meta:
//
//   - audit_head = "<seq>:<hex hash>:<hex mac>" names the last sealed row. It
//     lets Verify detect a truncated tail and stops a forged unsealed marker
//     from getting earlier (sealed) rows re-blessed by a reseal.
//   - audit_anchor_seq / audit_anchor_hash (+ audit_anchor_mac) name the last
//     row removed by Prune, so a pruned prefix still verifies.
//
// # Other features
//
// Rows that could not be written (database error) are kept in a bounded
// in-memory queue (10 000 entries) and retried in the background, so Record
// never fails its caller. When the setting audit.mirror_jsonl is on, committed
// rows are appended to logs/audit.jsonl by the same background loop (never
// inside a transaction). Retention (audit.retention_days) is applied by the
// maintenance.audit_prune job registered through RegisterJobs.
package audit

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"fileparcel/internal/core"
	"fileparcel/internal/db"
	"fileparcel/internal/events"
	"fileparcel/internal/ids"
	"fileparcel/internal/logx"
)

// Meta keys used by the audit log.
const (
	metaUnsealed   = "audit_unsealed_seq" // first row chained without the MAC (core.Audit rule)
	metaHead       = "audit_head"         // "<seq>:<hex hash>:<hex mac>" of the last sealed row
	metaAnchorSeq  = "audit_anchor_seq"   // last pruned seq
	metaAnchorHash = "audit_anchor_hash"  // hex hash of the last pruned row
	metaAnchorMAC  = "audit_anchor_mac"   // hex MAC("audit.anchor", seq, hash)
	metaMirrorSeq  = "audit_mirror_seq"   // last seq written to logs/audit.jsonl
)

// MAC purposes.
const (
	purposeChain  = "audit"
	purposeHead   = "audit.head"
	purposeAnchor = "audit.anchor"
)

// Limits.
const (
	// MaxPending bounds the in-memory retry queue of rows that failed to persist.
	MaxPending = 10000
	// maxDetails bounds the stored details JSON.
	maxDetails = 32 << 10
	// canonicalVersion is the first element of the canonical row encoding.
	canonicalVersion = "v1"
	// recordTimeout bounds one Record write (it survives request cancellation).
	recordTimeout = 30 * time.Second
	// loopInterval is the background retry/mirror period.
	loopInterval = 2 * time.Second
	// maxOwnUnsealed bounds Service.own; rows beyond it count as foreign.
	maxOwnUnsealed = 100000
	// maxResealSeqs bounds the seq list of an audit.reseal entry.
	maxResealSeqs = 100
)

var zeroHash = make([]byte, sha256.Size)

// Service implements core.Audit.
type Service struct {
	env *core.Env
	log *slog.Logger

	mu      sync.Mutex
	pending []*row // rows that could not be written yet (bounded by MaxPending)
	dropped uint64 // rows lost because the pending queue overflowed
	// own holds the unkeyed hashes of the rows this process wrote unsealed
	// (bounded by maxOwnUnsealed): only those are sealed without an
	// audit.reseal entry. Hashes of rolled-back or resealed rows are
	// harmless (a row's hash commits to its predecessor, so it cannot
	// recur) and are dropped once no row is unsealed (forgetSealed).
	own map[[sha256.Size]byte]struct{}

	wake      chan struct{}
	stop      chan struct{}
	done      chan struct{}
	closeOnce sync.Once
	unsub     func()
	keysCh    <-chan events.Event

	// mirror state (owned by the background loop)
	mirror    *logx.RotatingFile
	mirrorSeq int64 // -1 = not loaded yet
}

var (
	_ core.Audit        = (*Service)(nil)
	_ core.JobRegistrar = (*Service)(nil) // replaces the jobs package's maintenance.audit_prune
)

// New creates the audit service and starts its background loop (reseal on
// unlock, retry queue, JSONL mirror). Close stops it.
func New(env *core.Env) (*Service, error) {
	if env == nil || env.DB == nil {
		return nil, errors.New("audit: env with a database required")
	}
	log := env.Log
	if log == nil {
		log = slog.Default()
	}
	s := &Service{
		env:       env,
		log:       log.With("component", "audit"),
		wake:      make(chan struct{}, 1),
		stop:      make(chan struct{}),
		done:      make(chan struct{}),
		mirrorSeq: -1,
	}
	if env.Bus != nil {
		s.keysCh, s.unsub = env.Bus.Subscribe(events.TopicKeysState)
	}
	go s.loop()
	return s, nil
}

// Close stops the background loop after a final retry of pending rows and a
// final mirror pass. It is idempotent.
func (s *Service) Close() error {
	s.closeOnce.Do(func() {
		close(s.stop)
		select {
		case <-s.done:
		case <-time.After(15 * time.Second):
			s.log.Warn("audit: background loop did not stop in time")
		}
		if s.unsub != nil {
			s.unsub()
		}
		if n := s.pendingLen(); n > 0 {
			s.log.Error("audit: entries could not be persisted before shutdown", "count", n)
		}
	})
	return nil
}

// ---------- recording ----------

// row is one prepared audit row.
type row struct {
	seq        int64
	id         string
	at         int64
	actorID    string
	actorName  string
	actorVia   string
	ip         string
	userAgent  string
	requestID  string
	action     string
	outcome    string
	targetType string
	targetID   string
	targetName string
	details    string
	prevHash   []byte
	hash       []byte
}

// canonical returns the byte string covered by the chain hash.
func (r *row) canonical() []byte {
	b, _ := json.Marshal([]any{canonicalVersion, r.id, r.at, r.actorID, r.actorName, r.actorVia, r.ip,
		r.userAgent, r.requestID, r.action, r.outcome, r.targetType, r.targetID, r.targetName, r.details})
	return b
}

// record converts a stored row to the API model.
func (r *row) record() core.AuditRecord {
	d := json.RawMessage(r.details)
	if !json.Valid(d) {
		d = json.RawMessage(`{}`)
	}
	return core.AuditRecord{
		Seq: r.seq, ID: r.id, At: db.FromMs(r.at), ActorID: r.actorID, ActorName: r.actorName,
		ActorVia: r.actorVia, IP: r.ip, UserAgent: r.userAgent, RequestID: r.requestID,
		Action: r.action, Outcome: r.outcome, TargetType: r.targetType, TargetID: r.targetID,
		TargetName: r.targetName, Details: d, PrevHash: r.prevHash, Hash: r.hash,
	}
}

// Record writes e in its own transaction. It never fails the caller: when the
// write fails the row is queued in memory and retried in the background.
// Actor, IP, user agent and request id are filled from the ctx principal when
// empty. Do not call Record from inside a DB.Tx callback; use RecordTx.
func (s *Service) Record(ctx context.Context, e core.AuditEntry) {
	fill(ctx, &e)
	r := s.prepare(e)
	wctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), recordTimeout)
	defer cancel()
	err := s.env.DB.Tx(wctx, func(tx *sql.Tx) error {
		s.forgetSealed(wctx, tx)
		return s.insert(wctx, tx, r)
	})
	if err != nil {
		s.log.Error("audit: record failed; queued for retry", "action", r.action, "err", err)
		s.enqueue(r)
	}
	s.signal()
}

// RecordTx writes e inside the caller's write transaction (rolled back with
// it). Actor fields are filled from the ctx principal when empty.
func (s *Service) RecordTx(ctx context.Context, tx *sql.Tx, e core.AuditEntry) error {
	if tx == nil {
		return errors.New("audit: RecordTx needs a transaction")
	}
	fill(ctx, &e)
	r := s.prepare(e)
	if err := s.insert(ctx, tx, r); err != nil {
		return fmt.Errorf("audit: %w", err)
	}
	s.signal()
	return nil
}

// fill completes actor, IP, user agent, request id and outcome from ctx.
func fill(ctx context.Context, e *core.AuditEntry) {
	if e.Outcome == "" {
		e.Outcome = core.OutcomeSuccess
	}
	p := core.PrincipalFrom(ctx)
	if p == nil {
		return
	}
	if e.ActorID == "" && e.ActorName == "" {
		e.ActorID, e.ActorName = p.UserID, p.Username
	}
	if e.ActorVia == "" {
		e.ActorVia = string(p.Via)
	}
	if e.IP == "" && p.IP.IsValid() {
		e.IP = p.IP.String()
	}
	if e.UserAgent == "" {
		e.UserAgent = p.UserAgent
	}
	if e.RequestID == "" {
		e.RequestID = p.RequestID
	}
}

// clip returns s as valid UTF-8 without NUL bytes, truncated to max bytes at
// a rune boundary.
func clip(s string, max int) string {
	s = strings.ToValidUTF8(s, "�")
	s = strings.ReplaceAll(s, "\x00", "")
	if len(s) <= max {
		return s
	}
	for max > 0 && !utf8.RuneStart(s[max]) {
		max--
	}
	return s[:max]
}

// prepare validates and normalizes an entry into a row (id and time set).
func (s *Service) prepare(e core.AuditEntry) *row {
	r := &row{
		id:         ids.New(ids.PrefixAudit),
		at:         db.Ms(s.env.Now()),
		actorID:    clip(e.ActorID, 64),
		actorName:  clip(e.ActorName, 256),
		actorVia:   clip(e.ActorVia, 32),
		ip:         clip(e.IP, 64),
		userAgent:  clip(e.UserAgent, 512),
		requestID:  clip(e.RequestID, 64),
		action:     clip(e.Action, 64),
		outcome:    e.Outcome,
		targetType: clip(e.TargetType, 64),
		targetID:   clip(e.TargetID, 128),
		targetName: clip(e.TargetName, 512),
		details:    "{}",
	}
	if r.action == "" {
		s.log.Warn("audit: entry without action")
		r.action = "unknown"
	}
	switch r.outcome {
	case core.OutcomeSuccess, core.OutcomeFailure, core.OutcomeDenied:
	default:
		s.log.Warn("audit: invalid outcome coerced to failure", "action", r.action, "outcome", r.outcome)
		r.outcome = core.OutcomeFailure
	}
	if e.Details != nil {
		b, err := json.Marshal(e.Details)
		switch {
		case err != nil:
			s.log.Warn("audit: details not serializable", "action", r.action, "err", err)
			r.details = `{"_error":"details not serializable"}`
		case len(b) > maxDetails:
			r.details = `{"_truncated":true}`
		case string(b) == "null":
		default:
			r.details = strings.ToValidUTF8(string(b), "�")
		}
	}
	return r
}

// insert chains and inserts r inside tx (see the package doc).
func (s *Service) insert(ctx context.Context, tx *sql.Tx, r *row) error {
	marker, hasMarker, err := metaInt(ctx, tx, metaUnsealed)
	if err != nil {
		return err
	}
	if hasMarker && s.keysUnlocked() {
		if err := s.resealTx(ctx, tx, marker); err != nil {
			if errors.Is(err, errTampered) {
				s.log.Error("audit: cannot seal the unsealed segment; new rows stay unsealed", "err", err)
			} else {
				s.log.Warn("audit: sealing deferred", "err", err)
			}
		} else {
			hasMarker = false
		}
	}
	prev, err := chainHead(ctx, tx)
	if err != nil {
		return err
	}
	canon := r.canonical()
	var h []byte
	if !hasMarker {
		h = s.macChain(prev, canon)
	}
	sealed := h != nil
	if !sealed {
		h = unkeyedChain(prev, canon)
		s.rememberOwn(h)
	}
	seq, err := insertRow(ctx, tx, r, prev, h)
	if err != nil {
		return err
	}
	if sealed {
		err := s.writeHead(ctx, tx, seq, h)
		if err == nil || !errors.Is(err, core.ErrKeysLocked) {
			return err
		}
		// The MAC key disappeared between the chain MAC and the head
		// checkpoint: downgrade the row to unsealed so that the head keeps
		// naming the last sealed row (the reseal on unlock relies on it).
		uh := unkeyedChain(prev, canon)
		s.rememberOwn(uh)
		if _, err := tx.ExecContext(ctx, `UPDATE audit_log SET hash = ? WHERE seq = ?`, uh, seq); err != nil {
			return err
		}
	}
	if !hasMarker { // first unsealed row (sealed rows returned above)
		return setMeta(ctx, tx, metaUnsealed, strconv.FormatInt(seq, 10))
	}
	return nil
}

// insertRow inserts r with the given chain hashes and returns its seq.
func insertRow(ctx context.Context, tx *sql.Tx, r *row, prev, h []byte) (int64, error) {
	res, err := tx.ExecContext(ctx, `INSERT INTO audit_log (id, at, actor_id, actor_name, actor_via, ip,
		user_agent, request_id, action, outcome, target_type, target_id, target_name, details, prev_hash, hash)
		VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		r.id, r.at, db.NullString(r.actorID), db.NullString(r.actorName), db.NullString(r.actorVia),
		db.NullString(r.ip), db.NullString(r.userAgent), db.NullString(r.requestID), r.action, r.outcome,
		db.NullString(r.targetType), db.NullString(r.targetID), db.NullString(r.targetName), r.details,
		prev, h)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

// rememberOwn records that this process wrote the unsealed row with hash h.
func (s *Service) rememberOwn(h []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(h) != sha256.Size || len(s.own) >= maxOwnUnsealed {
		return
	}
	if s.own == nil {
		s.own = make(map[[sha256.Size]byte]struct{})
	}
	s.own[[sha256.Size]byte(h)] = struct{}{}
}

// isOwn reports whether this process wrote the unsealed row with hash h.
func (s *Service) isOwn(h []byte) bool {
	if len(h) != sha256.Size {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	_, ok := s.own[[sha256.Size]byte(h)]
	return ok
}

// forgetSealed empties the set of own unsealed rows once no row is unsealed.
// It must be the first statement of a write transaction: writers are
// serialized, so only then does a missing marker mean that no unsealed row
// exists, committed or in flight (a reseal earlier in the same transaction
// could still be rolled back).
func (s *Service) forgetSealed(ctx context.Context, tx *sql.Tx) {
	s.mu.Lock()
	n := len(s.own)
	s.mu.Unlock()
	if n == 0 {
		return
	}
	if _, ok, err := metaInt(ctx, tx, metaUnsealed); err == nil && !ok {
		s.mu.Lock()
		s.own = nil
		s.mu.Unlock()
	}
}

// keysUnlocked reports whether the keys service claims to be unlocked.
func (s *Service) keysUnlocked() bool {
	return s.env.Keys != nil && s.env.Keys.State() == core.KeyStateUnlocked
}

// macOf returns Keys.MAC(purpose, data...) or nil when unavailable.
func (s *Service) macOf(purpose string, data ...[]byte) []byte {
	if s.env.Keys == nil {
		return nil
	}
	m := s.env.Keys.MAC(purpose, data...)
	if len(m) != sha256.Size {
		return nil
	}
	return m
}

// macChain is the sealed chain hash (nil when the MAC key is unavailable).
func (s *Service) macChain(prev, canon []byte) []byte { return s.macOf(purposeChain, prev, canon) }

// unkeyedChain is the chain hash used while the keys are unavailable.
func unkeyedChain(prev, canon []byte) []byte {
	h := sha256.New()
	h.Write(prev)
	h.Write(canon)
	return h.Sum(nil)
}

func be64(n int64) []byte {
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], uint64(n))
	return b[:]
}

// writeHead records the authenticated chain head checkpoint. It returns
// core.ErrKeysLocked (and writes nothing) when the MAC key is unavailable.
func (s *Service) writeHead(ctx context.Context, tx *sql.Tx, seq int64, h []byte) error {
	m := s.macOf(purposeHead, be64(seq), h)
	if m == nil {
		return core.ErrKeysLocked
	}
	return setMeta(ctx, tx, metaHead, fmt.Sprintf("%d:%s:%s", seq, hex.EncodeToString(h), hex.EncodeToString(m)))
}

// checkpoint is a parsed seq/hash/mac triple.
type checkpoint struct {
	seq  int64
	hash []byte
	mac  []byte
}

func parseHead(v string) (checkpoint, bool) {
	parts := strings.Split(v, ":")
	if len(parts) != 3 {
		return checkpoint{}, false
	}
	seq, err := strconv.ParseInt(parts[0], 10, 64)
	h, err2 := hex.DecodeString(parts[1])
	m, err3 := hex.DecodeString(parts[2])
	if err != nil || err2 != nil || err3 != nil || seq < 0 {
		return checkpoint{}, false
	}
	return checkpoint{seq: seq, hash: h, mac: m}, true
}

// headValid reports whether c carries a valid MAC (false when the key is unavailable).
func (s *Service) headValid(c checkpoint) bool {
	m := s.macOf(purposeHead, be64(c.seq), c.hash)
	return m != nil && ids.EqualBytes(m, c.mac)
}

func (s *Service) anchorValid(c checkpoint) bool {
	m := s.macOf(purposeAnchor, be64(c.seq), c.hash)
	return m != nil && ids.EqualBytes(m, c.mac)
}

// ---------- meta helpers ----------

type queryer interface {
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
}

func getMeta(ctx context.Context, q queryer, key string) (string, bool, error) {
	var v string
	err := q.QueryRowContext(ctx, `SELECT value FROM meta WHERE key = ?`, key).Scan(&v)
	if db.IsNoRows(err) {
		return "", false, nil
	}
	if err != nil {
		return "", false, err
	}
	return v, true, nil
}

func metaInt(ctx context.Context, q queryer, key string) (int64, bool, error) {
	v, ok, err := getMeta(ctx, q, key)
	if err != nil || !ok {
		return 0, false, err
	}
	n, err := strconv.ParseInt(v, 10, 64)
	if err != nil {
		return 0, false, fmt.Errorf("audit: meta %s: %w", key, err)
	}
	return n, true, nil
}

func setMeta(ctx context.Context, tx *sql.Tx, key, val string) error {
	_, err := tx.ExecContext(ctx, `INSERT INTO meta (key, value) VALUES (?, ?)
		ON CONFLICT(key) DO UPDATE SET value = excluded.value`, key, val)
	return err
}

func delMeta(ctx context.Context, tx *sql.Tx, keys ...string) error {
	for _, k := range keys {
		if _, err := tx.ExecContext(ctx, `DELETE FROM meta WHERE key = ?`, k); err != nil {
			return err
		}
	}
	return nil
}

// readAnchor returns the prune anchor (ok=false when nothing was pruned).
func readAnchor(ctx context.Context, q queryer) (checkpoint, bool, error) {
	seq, ok, err := metaInt(ctx, q, metaAnchorSeq)
	if err != nil || !ok {
		return checkpoint{}, false, err
	}
	hs, _, err := getMeta(ctx, q, metaAnchorHash)
	if err != nil {
		return checkpoint{}, false, err
	}
	ms, _, err := getMeta(ctx, q, metaAnchorMAC)
	if err != nil {
		return checkpoint{}, false, err
	}
	h, err := hex.DecodeString(hs)
	if err != nil || len(h) != sha256.Size {
		return checkpoint{}, false, fmt.Errorf("audit: corrupt anchor hash")
	}
	m, _ := hex.DecodeString(ms)
	return checkpoint{seq: seq, hash: h, mac: m}, true, nil
}

// chainHead returns the hash the next row chains to: the last row's hash, the
// prune anchor when the table is empty, or zeros.
func chainHead(ctx context.Context, q queryer) ([]byte, error) {
	var h []byte
	err := q.QueryRowContext(ctx, `SELECT hash FROM audit_log ORDER BY seq DESC LIMIT 1`).Scan(&h)
	if err == nil {
		return h, nil
	}
	if !db.IsNoRows(err) {
		return nil, err
	}
	a, ok, err := readAnchor(ctx, q)
	if err != nil {
		return nil, err
	}
	if ok {
		return a.hash, nil
	}
	return zeroHash, nil
}

// ---------- resealing ----------

const rowCols = `seq, id, at, COALESCE(actor_id,''), COALESCE(actor_name,''), COALESCE(actor_via,''),
	COALESCE(ip,''), COALESCE(user_agent,''), COALESCE(request_id,''), action, outcome,
	COALESCE(target_type,''), COALESCE(target_id,''), COALESCE(target_name,''), details, prev_hash, hash`

type scanner interface{ Scan(dest ...any) error }

func scanRow(sc scanner) (*row, error) {
	r := &row{}
	err := sc.Scan(&r.seq, &r.id, &r.at, &r.actorID, &r.actorName, &r.actorVia, &r.ip, &r.userAgent,
		&r.requestID, &r.action, &r.outcome, &r.targetType, &r.targetID, &r.targetName, &r.details,
		&r.prevHash, &r.hash)
	return r, err
}

// errTampered marks chain inconsistencies found while resealing.
var errTampered = errors.New("audit chain inconsistent")

// Reseal re-chains the rows written while the keys were unavailable with the
// MAC (see the package doc). It is called automatically on the keys.state
// "unlocked" event and lazily by the next Record; it is a no-op when nothing
// is unsealed or the keys are unavailable.
func (s *Service) Reseal(ctx context.Context) error {
	if !s.keysUnlocked() {
		return nil
	}
	return s.env.DB.Tx(ctx, func(tx *sql.Tx) error {
		s.forgetSealed(ctx, tx)
		marker, ok, err := metaInt(ctx, tx, metaUnsealed)
		if err != nil || !ok {
			return err
		}
		return s.resealTx(ctx, tx, marker)
	})
}

// resealDetails is the details object of an audit.reseal entry: the rows
// from_seq..to_seq were sealed, and the ones listed (the first
// maxResealSeqs of Unverified) had not been written by this process.
type resealDetails struct {
	FromSeq        int64   `json:"from_seq"`
	ToSeq          int64   `json:"to_seq"`
	Sealed         int64   `json:"sealed"`
	Unverified     int64   `json:"unverified"`
	UnverifiedSeqs []int64 `json:"unverified_seqs"`
	Note           string  `json:"note"`
}

const resealNote = "written while the keys were unavailable, not by the server process that sealed them: their origin is not authenticated"

// resealTx re-chains every row with seq >= marker inside tx. The unsealed
// segment must continue the authenticated head checkpoint and verify with the
// unkeyed hash; otherwise nothing is changed and errTampered is returned.
// Rows this process did not write itself are sealed too (the chain must stay
// continuous), and a sealed audit.reseal entry naming them is appended after
// the segment. The work runs in a savepoint so a failure leaves the caller's
// transaction untouched.
func (s *Service) resealTx(ctx context.Context, tx *sql.Tx, marker int64) (err error) {
	if _, err := tx.ExecContext(ctx, `SAVEPOINT audit_reseal`); err != nil {
		return err
	}
	defer func() {
		if err != nil {
			_, _ = tx.ExecContext(ctx, `ROLLBACK TO audit_reseal`)
		}
		_, rerr := tx.ExecContext(ctx, `RELEASE audit_reseal`)
		if err == nil {
			err = rerr
		}
	}()

	// The sealed row (or anchor) the unsealed segment continues.
	var prevSeq int64
	var prevHash []byte
	e := tx.QueryRowContext(ctx, `SELECT seq, hash FROM audit_log WHERE seq < ? ORDER BY seq DESC LIMIT 1`, marker).
		Scan(&prevSeq, &prevHash)
	switch {
	case db.IsNoRows(e):
		a, ok, aerr := readAnchor(ctx, tx)
		if aerr != nil {
			return aerr
		}
		if ok {
			if !s.anchorValid(a) {
				return fmt.Errorf("%w: prune anchor is not authentic", errTampered)
			}
			prevSeq, prevHash = a.seq, a.hash
		} else {
			prevSeq, prevHash = 0, zeroHash
		}
	case e != nil:
		return e
	}

	hv, hasHead, err := getMeta(ctx, tx, metaHead)
	if err != nil {
		return err
	}
	if hasHead {
		c, ok := parseHead(hv)
		if !ok || !s.headValid(c) {
			return fmt.Errorf("%w: head checkpoint is not authentic", errTampered)
		}
		if c.seq != prevSeq || !bytes.Equal(c.hash, prevHash) {
			return fmt.Errorf("%w: unsealed segment at seq %d does not continue the sealed head (seq %d)", errTampered, marker, c.seq)
		}
	} else if prevSeq != 0 {
		return fmt.Errorf("%w: sealed rows exist but the head checkpoint is missing", errTampered)
	}

	oldPrev, newPrev := prevHash, prevHash
	next, last := marker, int64(-1)
	var lastHash []byte
	var sealedN, foreignN int64
	var foreign []int64
	for {
		rows, err := tx.QueryContext(ctx, `SELECT `+rowCols+` FROM audit_log WHERE seq >= ? ORDER BY seq LIMIT 500`, next)
		if err != nil {
			return err
		}
		var batch []*row
		for rows.Next() {
			r, err := scanRow(rows)
			if err != nil {
				rows.Close()
				return err
			}
			batch = append(batch, r)
		}
		// rows.Close does not report a row-level iteration error, so a
		// truncated scan would look like "no rows left" and clear the
		// unsealed marker with rows still unsealed (a later Verify would
		// then report tampering). Check rows.Err before deciding.
		iterErr := rows.Err()
		if err := rows.Close(); err != nil {
			return err
		}
		if iterErr != nil {
			return iterErr
		}
		if len(batch) == 0 {
			break
		}
		for _, r := range batch {
			canon := r.canonical()
			if !bytes.Equal(r.prevHash, oldPrev) || !bytes.Equal(r.hash, unkeyedChain(oldPrev, canon)) {
				return fmt.Errorf("%w: unsealed row seq %d does not verify", errTampered, r.seq)
			}
			nh := s.macChain(newPrev, canon)
			if nh == nil {
				return core.ErrKeysLocked
			}
			if _, err := tx.ExecContext(ctx, `UPDATE audit_log SET prev_hash = ?, hash = ? WHERE seq = ?`, newPrev, nh, r.seq); err != nil {
				return err
			}
			sealedN++
			if !s.isOwn(r.hash) {
				foreignN++
				if len(foreign) < maxResealSeqs {
					foreign = append(foreign, r.seq)
				}
			}
			oldPrev, newPrev = r.hash, nh
			last, lastHash = r.seq, nh
		}
		next = batch[len(batch)-1].seq + 1
	}
	if err := delMeta(ctx, tx, metaUnsealed); err != nil {
		return err
	}
	if last < 0 {
		return nil
	}
	segEnd := last
	if foreignN > 0 {
		// Record the rows without proof of origin in the authenticated log.
		r := s.prepare(core.AuditEntry{Action: core.ActAuditReseal, Outcome: core.OutcomeFailure,
			ActorName: "system", TargetType: "audit", Details: resealDetails{FromSeq: marker, ToSeq: segEnd,
				Sealed: sealedN, Unverified: foreignN, UnverifiedSeqs: foreign, Note: resealNote}})
		h := s.macChain(lastHash, r.canonical())
		if h == nil {
			return core.ErrKeysLocked
		}
		seq, err := insertRow(ctx, tx, r, lastHash, h)
		if err != nil {
			return err
		}
		last, lastHash = seq, h
	}
	if err := s.writeHead(ctx, tx, last, lastHash); err != nil {
		return err
	}
	s.log.Info("audit: sealed rows written while the keys were unavailable", "from_seq", marker, "to_seq", segEnd, "rows", sealedN)
	if foreignN > 0 {
		s.log.Warn("audit: sealed rows this process did not write; their origin is not authenticated",
			"count", foreignN, "seqs", foreign, "audit_reseal_seq", last)
	}
	return nil
}
