package audit

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"fileparcel/internal/core"
	"fileparcel/internal/logx"
)

// retention job schedule (daily, after the 03:00/04:00 backups start).
const (
	pruneSchedule     = "maintenance.audit_prune"
	pruneCron         = "30 3 * * *"
	mirrorFileName    = "audit.jsonl"
	defaultMirrorSize = 50 << 20
	defaultMirrorKeep = 5
	mirrorChunk       = 64 << 10 // bytes of whole lines per mirror write
	// defaultRetentionDays applies when no Settings service is available
	// (the audit.retention_days default, as in the jobs package's built-in).
	defaultRetentionDays = 365
)

// signal wakes the background loop without blocking.
func (s *Service) signal() {
	select {
	case s.wake <- struct{}{}:
	default:
	}
}

// loop is the background worker: it reseals after an unlock, retries rows
// that failed to persist and feeds the JSONL mirror.
func (s *Service) loop() {
	defer close(s.done)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { <-s.stop; cancel() }()

	s.tryReseal(ctx) // keys may already be unlocked (plain mode)
	t := time.NewTicker(loopInterval)
	defer t.Stop()
	for {
		select {
		case <-s.stop:
			fctx, fcancel := context.WithTimeout(context.Background(), 10*time.Second)
			s.flushPending(fctx)
			s.mirrorOnce(fctx)
			fcancel()
			s.closeMirror()
			return
		case ev, ok := <-s.keysCh:
			if !ok {
				s.keysCh = nil
				continue
			}
			if st, ok := ev.Data.(core.KeysStateEvent); ok && st.State == core.KeyStateUnlocked {
				s.tryReseal(ctx)
			}
		case <-s.wake:
		case <-t.C:
		}
		s.flushPending(ctx)
		s.mirrorOnce(ctx)
	}
}

func (s *Service) tryReseal(ctx context.Context) {
	if err := s.Reseal(ctx); err != nil && ctx.Err() == nil {
		if errors.Is(err, errTampered) {
			s.log.Error("audit: rows written while locked cannot be sealed", "err", err)
		} else {
			s.log.Warn("audit: sealing deferred", "err", err)
		}
	}
}

// ---------- retry queue ----------

func (s *Service) enqueue(r *row) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.pending) >= MaxPending {
		s.pending = s.pending[1:]
		s.dropped++
		s.log.Error("audit: retry queue full; oldest entry dropped", "dropped_total", s.dropped)
	}
	s.pending = append(s.pending, r)
}

func (s *Service) pendingLen() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.pending)
}

// flushPending retries queued rows (oldest first, up to 500 per transaction).
func (s *Service) flushPending(ctx context.Context) {
	for {
		s.mu.Lock()
		n := min(len(s.pending), 500)
		batch := append([]*row(nil), s.pending[:n]...)
		s.mu.Unlock()
		if n == 0 {
			return
		}
		err := s.env.DB.Tx(ctx, func(tx *sql.Tx) error {
			s.forgetSealed(ctx, tx)
			for _, r := range batch {
				if err := s.insert(ctx, tx, r); err != nil {
					return err
				}
			}
			return nil
		})
		if err != nil {
			if ctx.Err() == nil {
				s.log.Warn("audit: retrying queued entries failed", "count", n, "err", err)
			}
			return
		}
		s.mu.Lock()
		// Entries may have been dropped from the front meanwhile; remove the
		// written ones by identity.
		written := make(map[*row]bool, n)
		for _, r := range batch {
			written[r] = true
		}
		keep := s.pending[:0]
		for _, r := range s.pending {
			if !written[r] {
				keep = append(keep, r)
			}
		}
		s.pending = keep
		s.mu.Unlock()
	}
}

// ---------- JSONL mirror ----------

func (s *Service) mirrorEnabled() bool {
	return s.env.Settings != nil && s.env.Home != nil && s.env.Settings.Bool(SettingMirrorJSONL)
}

func (s *Service) closeMirror() {
	if s.mirror != nil {
		_ = s.mirror.Close()
		s.mirror = nil
	}
}

// endTornLine ends a partial last line of the file at path (left by a
// mirror write that failed part-way, e.g. on a full disk, or by a crash), so
// the retried rows start on lines of their own. The newline is appended to
// that same file, not through the rotating writer, which could rotate first
// and leave the fragment unterminated.
func endTornLine(path string) error {
	f, err := os.OpenFile(path, os.O_RDWR|os.O_APPEND, 0)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	st, err := f.Stat()
	if err == nil && st.Size() > 0 {
		var b [1]byte
		if _, err = f.ReadAt(b[:], st.Size()-1); err == nil && b[0] != '\n' {
			_, err = f.Write([]byte{'\n'})
		}
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	return err
}

// mirrorTailBytes bounds how much of the end of the mirror file
// lastMirrored reads to find its last record.
const mirrorTailBytes = 1 << 20

// lastMirrored returns the seq and id of the last record in the mirror file
// at path (0 when the file is missing, empty or its tail holds no record).
func lastMirrored(path string) (int64, string, error) {
	f, err := os.Open(path)
	if errors.Is(err, fs.ErrNotExist) {
		return 0, "", nil
	}
	if err != nil {
		return 0, "", err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return 0, "", err
	}
	off := max(st.Size()-mirrorTailBytes, 0)
	buf := make([]byte, st.Size()-off)
	if _, err := f.ReadAt(buf, off); err != nil {
		return 0, "", err
	}
	lines := bytes.Split(bytes.TrimRight(buf, "\n"), []byte("\n"))
	for i := len(lines) - 1; i >= 0; i-- {
		var rec struct {
			Seq int64  `json:"seq"`
			ID  string `json:"id"`
		}
		if json.Unmarshal(lines[i], &rec) == nil && rec.Seq > 0 && rec.ID != "" {
			return rec.Seq, rec.ID, nil
		}
	}
	return 0, "", nil
}

// setAsideForkedMirror moves the mirror file at path away when its last
// record is not in the database: the database was rewound under it — a
// backup restore (logs/ is neither backed up nor restored) or a database
// replaced by hand — and the next rows would reuse seq numbers the file
// already holds with other content, which a log shipper cannot tell apart.
// The file becomes audit.jsonl.pre-restore-<UTC time> next to it (rotated
// siblings keep their names), a fresh file starts, and the move is logged.
// A record missing because retention pruned it is no fork: its seq is below
// the database's newest.
func (s *Service) setAsideForkedMirror(ctx context.Context, path string) error {
	seq, id, err := lastMirrored(path)
	if err != nil || seq == 0 {
		return err
	}
	q := s.env.DB.Reader()
	var dbID string
	err = q.QueryRowContext(ctx, `SELECT id FROM audit_log WHERE seq = ?`, seq).Scan(&dbID)
	switch {
	case err == nil && dbID == id:
		return nil // the database has the file's last record: no fork
	case err != nil && !errors.Is(err, sql.ErrNoRows):
		return err
	case errors.Is(err, sql.ErrNoRows):
		var newest int64
		if err := q.QueryRowContext(ctx, `SELECT COALESCE(MAX(seq), 0) FROM audit_log`).Scan(&newest); err != nil {
			return err
		}
		if seq <= newest {
			return nil // pruned by retention
		}
	}
	dst := path + ".pre-restore-" + s.env.Now().UTC().Format("20060102-150405")
	for i := 2; ; i++ {
		if _, err := os.Lstat(dst); errors.Is(err, fs.ErrNotExist) {
			break
		}
		dst = fmt.Sprintf("%s.pre-restore-%s-%d", path, s.env.Now().UTC().Format("20060102-150405"), i)
	}
	if err := os.Rename(path, dst); err != nil {
		return err
	}
	s.log.Warn("audit: the JSONL mirror holds entries the database no longer has (restored from a backup?); "+
		"moved it aside and started a new one", "moved_to", dst, "last_seq", seq)
	return nil
}

// mirrorOnce appends every committed row after the last mirrored seq to
// logs/audit.jsonl and records the position in meta (at-least-once).
func (s *Service) mirrorOnce(ctx context.Context) {
	if !s.mirrorEnabled() {
		s.closeMirror()
		return
	}
	if s.mirror == nil {
		size, keep := int64(defaultMirrorSize), defaultMirrorKeep
		if c := s.env.Config; c != nil {
			if c.Log.MaxSizeMB > 0 {
				size = int64(c.Log.MaxSizeMB) << 20
			}
			if c.Log.MaxFiles > 0 {
				keep = c.Log.MaxFiles
			}
		}
		path := filepath.Join(s.env.Home.LogsDir(), mirrorFileName)
		if err := endTornLine(path); err != nil {
			s.log.Warn("audit: cannot open the JSONL mirror", "err", err)
			return
		}
		if err := s.setAsideForkedMirror(ctx, path); err != nil {
			s.log.Warn("audit: cannot open the JSONL mirror", "err", err)
			return
		}
		f, err := logx.NewRotatingFile(path, size, keep)
		if err != nil {
			s.log.Warn("audit: cannot open the JSONL mirror", "err", err)
			return
		}
		s.mirror = f
	}
	if s.mirrorSeq < 0 {
		seq, _, err := metaInt(ctx, s.env.DB.Reader(), metaMirrorSeq)
		if err != nil {
			s.log.Warn("audit: mirror position unreadable", "err", err)
			return
		}
		s.mirrorSeq = seq
	}
	start := s.mirrorSeq
	for ctx.Err() == nil {
		rows, err := s.page(ctx, "1=1", nil, false, s.mirrorSeq, exportBatch)
		if err != nil {
			s.log.Warn("audit: mirror read failed", "err", err)
			break
		}
		if len(rows) == 0 {
			break
		}
		// Hand the rotating file whole lines only (in chunks of about
		// mirrorChunk bytes): it rotates before a Write that would exceed the
		// size limit, so a chunk cut mid-line would split a record across two
		// files.
		var buf bytes.Buffer
		var werr error
		for _, r := range rows {
			line, err := json.Marshal(r.record())
			if err != nil {
				werr = err
				break
			}
			if buf.Len() > 0 && buf.Len()+len(line)+1 > mirrorChunk {
				if _, werr = s.mirror.Write(buf.Bytes()); werr != nil {
					break
				}
				buf.Reset()
			}
			buf.Write(line)
			buf.WriteByte('\n')
		}
		if werr == nil && buf.Len() > 0 {
			_, werr = s.mirror.Write(buf.Bytes())
		}
		if werr != nil {
			s.log.Warn("audit: mirror write failed", "err", werr)
			s.closeMirror()
			break
		}
		s.mirrorSeq = rows[len(rows)-1].seq
		if len(rows) < exportBatch {
			break
		}
	}
	if s.mirrorSeq != start {
		if _, err := s.env.DB.Exec(context.WithoutCancel(ctx), `INSERT INTO meta (key, value) VALUES (?, ?)
			ON CONFLICT(key) DO UPDATE SET value = excluded.value`, metaMirrorSeq, strconv.FormatInt(s.mirrorSeq, 10)); err != nil {
			s.log.Warn("audit: mirror position not saved", "err", err)
		}
	}
}

// ---------- retention job ----------

// RegisterJobs registers the maintenance.audit_prune job (daily) which
// applies audit.retention_days (core.JobRegistrar).
func (s *Service) RegisterJobs(j core.Jobs) error {
	j.Register(core.JobMaintAuditPrune, s.pruneJob, core.JobOptions{Exclusive: "audit", Timeout: time.Hour})
	if err := j.Schedule(pruneSchedule, pruneCron, core.JobMaintAuditPrune, nil); err != nil && !errors.Is(err, core.ErrNotImplemented) {
		return err
	}
	return nil
}

// PruneResult is the result of the maintenance.audit_prune job.
type PruneResult struct {
	Pruned        int    `json:"pruned"`
	RetentionDays int64  `json:"retention_days"`
	Skipped       string `json:"skipped,omitempty"`
}

func (s *Service) pruneJob(ctx context.Context, h core.JobHandle) error {
	days := int64(defaultRetentionDays)
	if s.env.Settings != nil {
		days = s.env.Settings.Int(SettingRetentionDays)
	}
	if days <= 0 {
		h.SetResult(PruneResult{Skipped: "retention disabled"})
		return nil
	}
	before := s.env.Now().Add(-time.Duration(days) * 24 * time.Hour)
	n, err := s.Prune(ctx, before)
	if errors.Is(err, core.ErrKeysLocked) {
		// A sealed server that is not unlocked yet: nothing to do until the
		// next run, which is not a failure (same as the jobs package's
		// built-in this registration replaces).
		h.SetResult(PruneResult{Pruned: n, RetentionDays: days, Skipped: "keys locked"})
		return nil
	}
	h.SetResult(PruneResult{Pruned: n, RetentionDays: days})
	return err
}
