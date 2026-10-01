// Package backup creates, verifies, restores, prunes and schedules encrypted
// backups (DESIGN §1, §9.7, §11.2, §14.2). Owned by unit H.
//
// A backup is one file backups/fp-<install8>-<YYYYmmdd-HHMMSS>-<scope>.fpbak:
// a tar archive (see archive.go for the members) compressed with zstd and
// encrypted with age — to X25519 recipients (backup.recipients; the
// matching identity is the secret setting backup.identity) or to a
// passphrase (age scrypt; backup.passphrase). The file is a plain age file,
// so it can also be inspected without FileParcel:
//
//	age -d -i identity.txt fp-….fpbak | zstd -d | tar -t
//
// Scope "metadata" holds the database snapshot (VACUUM INTO), fileparcel.toml,
// keys/master.key and certs/; scope "full" additionally holds every ready
// blob (already encrypted at rest; streamed, never loaded into memory).
// Every backup has a row in the backups table.
//
// Restores replace data/, keys/, certs/ and fileparcel.toml of the home
// (the previous ones are moved to <home>/pre-restore-<ts>/). They run either
// offline (RestoreOffline; the server must be stopped) or, from the running
// server, via ScheduleRestore → restart → ApplyPendingRestore before the
// database is opened.
package backup

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"fileparcel/internal/core"
	"fileparcel/internal/db"
	"fileparcel/internal/events"
	"fileparcel/internal/home"
	"fileparcel/internal/ids"
)

// Schedule names (jobs.schedules) re-applied from the settings.
const (
	ScheduleMeta = "backup.schedule_meta"
	ScheduleFull = "backup.schedule_full"
)

// exclusiveGroup serializes the heavy backup jobs.
const exclusiveGroup = "backup"

// Retention of failed backup rows.
const failedRetention = 7 * 24 * time.Hour

// metaIdentityExported (meta table) records when the backup identity was last
// shown to an administrator (generate / export), for the doctor check.
const metaIdentityExported = "backup_identity_exported_at"

// fileNameRe matches the backup file names this package writes (and accepts
// in restore requests).
var fileNameRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,200}\.fpbak$`)

// Service implements core.Backups.
type Service struct {
	env   *core.Env
	blobs core.BlobStore
	jobs  core.Jobs
	log   *slog.Logger

	createMu sync.Mutex // one archive written at a time (jobs and CreateSync)
	nameMu   sync.Mutex // choosing a backup file name and claiming it (row or file): create and Import
	schedMu  sync.Mutex // serializes applySchedules (settings watcher vs RegisterJobs)

	stopWatch func()
	watchDone chan struct{}
	closeOnce sync.Once
}

var (
	_ core.Backups      = (*Service)(nil)
	_ core.JobRegistrar = (*Service)(nil)
	_ io.Closer         = (*Service)(nil)
)

// New creates the service (constructor signature fixed by DESIGN §5.2). It
// settles the backups left "running" by a previous process (see
// recoverStale), removes their partial files and the scratch data of
// interrupted backups, restores and verifications under tmp/ (sweepScratch),
// and starts watching settings.changed to re-apply the backup schedules. Job
// kinds and schedules are registered by RegisterJobs.
func New(env *core.Env, blobs core.BlobStore, jobs core.Jobs) (*Service, error) {
	if env == nil || env.DB == nil || env.Home == nil {
		return nil, errors.New("backup: env with home and database required")
	}
	log := env.Log
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	s := &Service{env: env, blobs: blobs, jobs: jobs, log: log.With("svc", "backup")}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	s.recoverStale(ctx)
	if env.Bus != nil {
		ch, stop := env.Bus.Subscribe(events.TopicSettingsChanged)
		s.stopWatch, s.watchDone = stop, make(chan struct{})
		go s.watch(ch)
	}
	return s, nil
}

// Close stops the settings watcher (io.Closer). Idempotent.
func (s *Service) Close() error {
	s.closeOnce.Do(func() {
		if s.stopWatch != nil {
			s.stopWatch()
			<-s.watchDone
		}
	})
	return nil
}

// RegisterJobs registers backup.create, backup.verify and backup.prune and
// applies the backup schedules (core.JobRegistrar).
func (s *Service) RegisterJobs(j core.Jobs) error {
	if j == nil {
		return nil
	}
	s.schedMu.Lock()
	if s.jobs == nil {
		s.jobs = j
	}
	s.schedMu.Unlock()
	j.Register(core.JobBackupCreate, s.jobCreate, core.JobOptions{Exclusive: exclusiveGroup})
	j.Register(core.JobBackupVerify, s.jobVerify, core.JobOptions{Exclusive: exclusiveGroup})
	j.Register(core.JobBackupPrune, s.jobPrune, core.JobOptions{Exclusive: exclusiveGroup, Timeout: time.Hour})
	return s.applySchedules()
}

// watch re-applies the schedules when a backup.* setting changes.
func (s *Service) watch(ch <-chan events.Event) {
	defer close(s.watchDone)
	for e := range ch {
		ev, ok := e.Data.(core.SettingsChangedEvent)
		if !ok {
			continue
		}
		relevant := false
		for _, k := range ev.Keys {
			if k == SettingEnabled || k == SettingScheduleMeta || k == SettingScheduleFull {
				relevant = true
			}
		}
		if relevant {
			if err := s.applySchedules(); err != nil {
				s.log.Warn("backup: applying the schedules failed", "err", err)
			}
		}
	}
}

// applySchedules (re)creates or removes the two backup schedules from the settings.
func (s *Service) applySchedules() error {
	s.schedMu.Lock()
	defer s.schedMu.Unlock()
	if s.jobs == nil || s.env.Settings == nil {
		return nil
	}
	enabled := s.env.Settings.Bool(SettingEnabled)
	var errs []error
	for _, sc := range []struct{ name, key, scope string }{
		{ScheduleMeta, SettingScheduleMeta, core.BackupMetadata},
		{ScheduleFull, SettingScheduleFull, core.BackupFull},
	} {
		spec := strings.TrimSpace(s.env.Settings.String(sc.key))
		if !enabled || spec == "" {
			s.jobs.Unschedule(sc.name)
			continue
		}
		p := createParams{Scope: sc.scope, Trigger: core.TriggerSchedule}
		if err := s.jobs.Schedule(sc.name, spec, core.JobBackupCreate, p); err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", sc.name, err))
		}
	}
	return errors.Join(errs...)
}

// interruptedAfterWriteMsg is the error of a backup whose archive was
// complete when the server stopped, before the backup was recorded as
// finished (recoverStale).
const interruptedAfterWriteMsg = "the server stopped before this backup was recorded as finished: the archive is complete, " +
	"but its checksum was not recorded and no copy to backup.copy_to was made"

// recoverStale settles the backups left running by a crashed process and
// removes stray partial files and scratch data (sweepScratch). A backup whose
// archive already carries its final name is complete (writeArchive renames
// the fsynced .partial file only at the very end; the copy to
// backup.copy_to and the "ready" record come after that), so it becomes
// ready — with a note, and without the checksum that was never recorded —
// instead of a failed row whose valid archive Prune would delete. The others
// are marked failed. Only one process uses a home at a time (the home lock),
// so nothing else can be writing any of these.
func (s *Service) recoverStale(ctx context.Context) {
	now := s.env.Now()
	var failed, completed int
	err := s.env.DB.Tx(ctx, func(tx *sql.Tx) error {
		rows, err := tx.QueryContext(ctx, `SELECT id, file_name FROM backups WHERE state = 'running'`)
		if err != nil {
			return err
		}
		type stale struct{ id, name string }
		var list []stale
		for rows.Next() {
			var r stale
			if err := rows.Scan(&r.id, &r.name); err != nil {
				rows.Close()
				return err
			}
			list = append(list, r)
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return err
		}
		for _, r := range list {
			if size, ok := s.archiveFile(r.name); ok {
				if _, err := tx.ExecContext(ctx, `UPDATE backups SET state = 'ready', size = ?, finished_at = ?, error = ?
					WHERE id = ?`, size, db.Ms(now), interruptedAfterWriteMsg, r.id); err != nil {
					return err
				}
				completed++
				continue
			}
			if _, err := tx.ExecContext(ctx, `UPDATE backups SET state = 'failed', error = ?, finished_at = ? WHERE id = ?`,
				"interrupted (the server stopped while the backup was running)", db.Ms(now), r.id); err != nil {
				return err
			}
			failed++
		}
		return nil
	})
	switch {
	case err != nil:
		s.log.Warn("backup: recovering interrupted backups failed", "err", err)
	case failed > 0 || completed > 0:
		s.log.Warn("backup: interrupted backups recovered", "failed", failed, "complete_archives", completed)
	}
	if entries, err := os.ReadDir(s.env.Home.BackupsDir()); err == nil {
		for _, e := range entries {
			if e.Type().IsRegular() && strings.HasPrefix(e.Name(), ".") && strings.HasSuffix(e.Name(), ".partial") {
				_ = os.Remove(filepath.Join(s.env.Home.BackupsDir(), e.Name()))
			}
		}
	}
	sweepScratch(s.env.Home, s.log)
}

// archiveFile reports whether backups/<name> is a (non-empty) regular file,
// and its size.
func (s *Service) archiveFile(name string) (int64, bool) {
	if !fileNameRe.MatchString(name) {
		return 0, false
	}
	st, err := os.Lstat(filepath.Join(s.env.Home.BackupsDir(), name))
	if err != nil || !st.Mode().IsRegular() || st.Size() == 0 {
		return 0, false
	}
	return st.Size(), true
}

// scratchFileRe matches the scratch files a backup writes into tmp/: the
// database snapshot (with its SQLite companions) and the member index.
var scratchFileRe = regexp.MustCompile(`^(snapshot-` + ids.PrefixBackup + `_[A-Za-z0-9]+\.db(-wal|-shm|-journal)?|members-[0-9]+\.ndjson)$`)

// sweepScratch removes what an interrupted backup, restore or deep
// verification left under tmp/: the restore staging directories
// tmp/restore/restore-* (up to a copy of all file data, plus the backup's
// master key), the temporary verification homes tmp/verify/verify-*, and the
// database snapshots and member indexes of backups (tmp/snapshot-bak_….db,
// tmp/members-*.ndjson). They are otherwise removed only by the process that
// made them, so after a SIGKILL, an OOM kill or a power loss they stayed
// forever — and a leftover staging directory made every later restore fail
// its free-space check. Nothing else in tmp/ is touched (uploads, zip
// streams, and the release directories of a running "fileparcel upgrade",
// which does not take the home lock). The caller holds the home lock, before
// any job runs: nothing can be using these then. Symlinks are removed, never
// followed.
func sweepScratch(h *home.Home, log *slog.Logger) {
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	var removed []string
	var freed int64
	sweep := func(dir string, match func(name string, isDir bool) bool) {
		entries, err := os.ReadDir(dir)
		if err != nil {
			return
		}
		for _, e := range entries {
			if !match(e.Name(), e.IsDir()) {
				continue
			}
			p := filepath.Join(dir, e.Name())
			n := treeSize(p)
			if err := os.RemoveAll(p); err != nil {
				log.Warn("backup: removing leftover scratch data failed", "path", p, "err", err)
				continue
			}
			removed = append(removed, p)
			freed += n
		}
	}
	sweep(h.TmpDir(home.TmpRestore), func(name string, _ bool) bool { return strings.HasPrefix(name, "restore-") })
	sweep(h.TmpDir(home.TmpVerify), func(name string, _ bool) bool { return strings.HasPrefix(name, "verify-") })
	sweep(h.TmpDir(""), func(name string, isDir bool) bool { return !isDir && scratchFileRe.MatchString(name) })
	if len(removed) > 0 {
		log.Warn("backup: removed scratch data left by an interrupted backup, restore or verification",
			"count", len(removed), "freed", humanBytes(freed), "paths", truncate(strings.Join(removed, ", "), 500))
	}
}

// treeSize is the total size of the regular files at or below p (symlinks
// are not followed).
func treeSize(p string) int64 {
	var n int64
	_ = filepath.WalkDir(p, func(_ string, d fs.DirEntry, err error) error {
		if err == nil && d.Type().IsRegular() {
			if info, err := d.Info(); err == nil {
				n += info.Size()
			}
		}
		return nil
	})
	return n
}

// ---------- rows ----------

const backupCols = `id, scope, state, file_name, size, sha256, encryption, recipients, blob_count, blob_bytes,
	db_size, app_version, schema_version, note, "trigger", job_id, created_by, created_at, finished_at,
	verified_at, verify_ok, error, copied_to`

func scanBackup(sc interface{ Scan(...any) error }) (*core.Backup, error) {
	var (
		b                                                  core.Backup
		size, blobCount, blobBytes, dbSize, schema, vok    sql.NullInt64
		sha, recips, appVer, note, jobID, by, errS, copied sql.NullString
		createdAt                                          int64
		finishedAt, verifiedAt                             sql.NullInt64
	)
	if err := sc.Scan(&b.ID, &b.Scope, &b.State, &b.FileName, &size, &sha, &b.Encryption, &recips, &blobCount,
		&blobBytes, &dbSize, &appVer, &schema, &note, &b.Trigger, &jobID, &by, &createdAt, &finishedAt,
		&verifiedAt, &vok, &errS, &copied); err != nil {
		return nil, err
	}
	b.Size, b.SHA256 = size.Int64, sha.String
	if recips.Valid && recips.String != "" {
		_ = json.Unmarshal([]byte(recips.String), &b.Recipients)
	}
	b.BlobCount, b.BlobBytes, b.DBSize = blobCount.Int64, blobBytes.Int64, dbSize.Int64
	b.AppVersion, b.SchemaVersion, b.Note = appVer.String, int(schema.Int64), note.String
	b.JobID, b.CreatedBy, b.Error, b.CopiedTo = jobID.String, by.String, errS.String, copied.String
	b.CreatedAt = db.FromMs(createdAt)
	b.FinishedAt = db.FromNullMs(finishedAt)
	b.VerifiedAt = db.FromNullMs(verifiedAt)
	if vok.Valid {
		ok := vok.Int64 != 0
		b.VerifyOK = &ok
	}
	return &b, nil
}

// Get implements core.Backups.
func (s *Service) Get(ctx context.Context, id string) (*core.Backup, error) {
	if !ids.Valid(ids.PrefixBackup, id) {
		return nil, core.NotFoundf("backup not found")
	}
	b, err := scanBackup(s.env.DB.QueryRow(ctx, `SELECT `+backupCols+` FROM backups WHERE id = ?`, id))
	if db.IsNoRows(err) {
		return nil, core.NotFoundf("backup not found")
	}
	if err != nil {
		return nil, fmt.Errorf("backup: get: %w", err)
	}
	return b, nil
}

type listCursor struct {
	T  int64  `json:"t"`
	ID string `json:"id"`
}

// List implements core.Backups: newest first, keyset-paginated.
func (s *Service) List(ctx context.Context, q core.PageReq) (core.Page[core.Backup], error) {
	where, args := "1=1", []any{}
	if q.Cursor != "" {
		var c listCursor
		if err := decodeCursor(q.Cursor, &c); err != nil {
			return core.Page[core.Backup]{}, err
		}
		where = "(created_at < ? OR (created_at = ? AND id < ?))"
		args = append(args, c.T, c.T, c.ID)
	}
	limit := q.EffectiveLimit()
	args = append(args, limit+1)
	rows, err := s.env.DB.Query(ctx, `SELECT `+backupCols+` FROM backups WHERE `+where+
		` ORDER BY created_at DESC, id DESC LIMIT ?`, args...)
	if err != nil {
		return core.Page[core.Backup]{}, fmt.Errorf("backup: list: %w", err)
	}
	defer rows.Close()
	var items []core.Backup
	for rows.Next() {
		b, err := scanBackup(rows)
		if err != nil {
			return core.Page[core.Backup]{}, fmt.Errorf("backup: list: %w", err)
		}
		items = append(items, *b)
	}
	if err := rows.Err(); err != nil {
		return core.Page[core.Backup]{}, fmt.Errorf("backup: list: %w", err)
	}
	next := ""
	if len(items) > limit {
		items = items[:limit]
		last := items[len(items)-1]
		next = encodeCursor(listCursor{T: db.Ms(last.CreatedAt), ID: last.ID})
	}
	return core.NewPage(items, next), nil
}

// path returns the file of a backup row inside backups/ (the name is validated).
func (s *Service) path(b *core.Backup) (string, error) {
	if !fileNameRe.MatchString(b.FileName) {
		return "", core.Errorf(core.ErrCorrupt, "backup %s has an invalid file name", b.ID)
	}
	return filepath.Join(s.env.Home.BackupsDir(), b.FileName), nil
}

// Delete implements core.Backups: removes the file and the row (audited).
// Running backups cannot be deleted.
func (s *Service) Delete(ctx context.Context, by *core.Principal, id string) error {
	b, err := s.Get(ctx, id)
	if err != nil {
		return err
	}
	if b.State == core.BackupRunning {
		return core.Errorf(core.ErrConflict, "the backup is still running")
	}
	return s.deleteBackup(ctx, by, b, "")
}

func (s *Service) deleteBackup(ctx context.Context, by *core.Principal, b *core.Backup, reason string) error {
	if p, err := s.path(b); err == nil {
		if err := os.Remove(p); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return fmt.Errorf("backup: delete %s: %w", b.FileName, err)
		}
	}
	if by != nil {
		ctx = core.WithPrincipal(ctx, by)
	}
	details := map[string]any{"scope": b.Scope, "trigger": b.Trigger, "created_at": b.CreatedAt}
	if reason != "" {
		details["reason"] = reason
	}
	err := s.env.DB.Tx(ctx, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, `DELETE FROM backups WHERE id = ?`, b.ID); err != nil {
			return err
		}
		if s.env.Audit != nil {
			return s.env.Audit.RecordTx(ctx, tx, core.AuditEntry{Action: core.ActBackupDelete, TargetType: "backup",
				TargetID: b.ID, TargetName: b.FileName, Details: details})
		}
		return nil
	})
	if err != nil {
		return fmt.Errorf("backup: delete: %w", err)
	}
	return nil
}

// Download implements core.Backups: the file (an *os.File, so callers can
// seek for Range requests), its size and file name. Only ready backups can
// be downloaded. The caller audits (skipping HEAD requests).
func (s *Service) Download(ctx context.Context, id string) (io.ReadCloser, int64, string, error) {
	b, err := s.Get(ctx, id)
	if err != nil {
		return nil, 0, "", err
	}
	if b.State != core.BackupReady {
		return nil, 0, "", core.Errorf(core.ErrConflict, "the backup is not ready")
	}
	p, err := s.path(b)
	if err != nil {
		return nil, 0, "", err
	}
	f, err := os.Open(p)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, 0, "", core.NotFoundf("the backup file is missing")
	}
	if err != nil {
		return nil, 0, "", fmt.Errorf("backup: open: %w", err)
	}
	st, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, 0, "", fmt.Errorf("backup: stat: %w", err)
	}
	return f, st.Size(), b.FileName, nil
}

// ---------- helpers ----------

func (s *Service) audit(ctx context.Context, e core.AuditEntry) {
	if s.env.Audit != nil {
		s.env.Audit.Record(ctx, e)
	}
}

func (s *Service) publishFinished(b *core.Backup) {
	if s.env.Bus != nil && b != nil {
		s.env.Bus.Publish(events.Event{Topic: events.TopicBackupFinished, Data: core.BackupEvent{Backup: b}})
	}
}

// installPrefix returns the first 8 characters of the install id ("fileparcel" fallback).
func (s *Service) installPrefix() string {
	return install8(s.installID())
}

func (s *Service) installID() string {
	if s.env.Config != nil {
		return s.env.Config.InstallID
	}
	return ""
}

func install8(id string) string {
	id = strings.ToLower(id)
	var b strings.Builder
	for _, r := range id {
		if (r >= '0' && r <= '9') || (r >= 'a' && r <= 'z') {
			b.WriteRune(r)
		}
		if b.Len() == 8 {
			break
		}
	}
	if b.Len() == 0 {
		return "unknown"
	}
	return b.String()
}

// uniqueFileName returns fp-<install8>-<ts>-<scope>.fpbak, adding -2, -3, …
// when a file or row with that name exists.
func (s *Service) uniqueFileName(ctx context.Context, inst string, t time.Time, scope string) (string, error) {
	base := fmt.Sprintf("fp-%s-%s-%s", inst, t.UTC().Format("20060102-150405"), scope)
	for i := 1; i < 1000; i++ {
		name := base + ".fpbak"
		if i > 1 {
			name = fmt.Sprintf("%s-%d.fpbak", base, i)
		}
		if _, err := os.Lstat(filepath.Join(s.env.Home.BackupsDir(), name)); err == nil {
			continue
		}
		var n int
		if err := s.env.DB.QueryRow(ctx, `SELECT count(*) FROM backups WHERE file_name = ?`, name).Scan(&n); err != nil {
			return "", err
		}
		if n == 0 {
			return name, nil
		}
	}
	return "", errors.New("backup: no free file name")
}

// setMeta upserts a meta row.
func (s *Service) setMeta(ctx context.Context, key, value string) error {
	_, err := s.env.DB.Exec(ctx, `INSERT INTO meta (key, value) VALUES (?, ?)
		ON CONFLICT(key) DO UPDATE SET value = excluded.value`, key, value)
	return err
}

// IdentityExportedAt reports when the backup identity was last shown to an
// administrator (nil = never), for GET /admin/system/doctor.
func (s *Service) IdentityExportedAt(ctx context.Context) *time.Time {
	var v string
	if err := s.env.DB.QueryRow(ctx, `SELECT value FROM meta WHERE key = ?`, metaIdentityExported).Scan(&v); err != nil {
		return nil
	}
	t, err := time.Parse(time.RFC3339, v)
	if err != nil {
		return nil
	}
	return &t
}

func syncDir(dir string) {
	if d, err := os.Open(dir); err == nil {
		_ = d.Sync()
		_ = d.Close()
	}
}

// writeFileAtomic writes data to path via path.tmp: create exclusive (mode
// mode), chmod, write, fsync, close, rename, fsync the directory. The
// Remove + O_EXCL pair matters: it holds for restore.key, so a stale or
// planted path.tmp can never lend the new file its mode — nor be a symlink
// the secret is written through.
func writeFileAtomic(path string, data []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	tmp := path + ".tmp"
	_ = os.Remove(tmp)
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return err
	}
	fail := func(err error) error {
		_ = f.Close()
		_ = os.Remove(tmp)
		return err
	}
	if err := f.Chmod(mode); err != nil { // umask-independent
		return fail(err)
	}
	if _, err := f.Write(data); err != nil {
		return fail(err)
	}
	if err := f.Sync(); err != nil {
		return fail(err)
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	syncDir(dir)
	return nil
}
