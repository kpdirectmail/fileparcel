package backup

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"

	"fileparcel/internal/config"
	"fileparcel/internal/core"
	"fileparcel/internal/db"
	"fileparcel/internal/events"
	"fileparcel/internal/home"
)

// verifyParams are the parameters of a backup.verify job.
type verifyParams struct {
	ID            string `json:"id"`
	Deep          bool   `json:"deep,omitempty"`
	CreatedBy     string `json:"created_by,omitempty"`
	CreatedByName string `json:"created_by_name,omitempty"`
}

// VerifyResult is the result of a backup.verify job.
type VerifyResult struct {
	BackupID      string   `json:"backup_id"`
	OK            bool     `json:"ok"`
	Deep          bool     `json:"deep"`
	Members       int      `json:"members"`
	Blobs         int64    `json:"blobs"`
	BlobsVerified int64    `json:"blobs_verified"`
	BlobsFailed   int64    `json:"blobs_failed"`
	SchemaVersion int      `json:"schema_version"`
	Notes         []string `json:"notes,omitempty"`
	Error         string   `json:"error,omitempty"`
}

// maxBlobErrors bounds the per-blob errors listed in a verify result.
const maxBlobErrors = 20

func closeAny(v any) {
	if c, ok := v.(io.Closer); ok {
		_ = c.Close()
	}
}

// Verify implements core.Backups: enqueues a backup.verify job.
func (s *Service) Verify(ctx context.Context, by *core.Principal, id string, deep bool) (string, error) {
	b, err := s.Get(ctx, id)
	if err != nil {
		return "", err
	}
	if b.State != core.BackupReady {
		return "", core.Errorf(core.ErrConflict, "only ready backups can be verified")
	}
	if s.jobs == nil {
		return "", core.Errorf(core.ErrUnavailable, "the job runner is not available")
	}
	p := verifyParams{ID: id, Deep: deep}
	if by != nil {
		p.CreatedBy, p.CreatedByName = by.UserID, by.Username
	}
	return s.jobs.Enqueue(ctx, core.JobBackupVerify, p, by)
}

func (s *Service) jobVerify(ctx context.Context, h core.JobHandle) error {
	var p verifyParams
	if err := h.Params(&p); err != nil {
		return err
	}
	res, err := s.VerifyNow(ctx, p.ID, p.Deep, h)
	if res != nil {
		h.SetResult(res)
	}
	if err == nil && res != nil && !res.OK {
		err = core.Errorf(core.ErrCorrupt, "%s", res.Error)
	}
	actx := context.WithoutCancel(ctx)
	e := core.AuditEntry{Action: core.ActBackupVerify, TargetType: "backup", TargetID: p.ID,
		ActorID: p.CreatedBy, ActorName: p.CreatedByName, Details: map[string]any{"deep": p.Deep}}
	if err != nil {
		e.Outcome = core.OutcomeFailure
		e.Details = map[string]any{"deep": p.Deep, "error": errorMessage(err)}
	}
	s.audit(actx, e)
	return err
}

// VerifyNow verifies a backup synchronously (the backup.verify job and the
// offline CLI): the file hash against the recorded one, decryption with the
// configured identity/passphrase, decompression, every member against the
// manifest and the schema version. deep additionally checks the database
// snapshot (quick_check) and decrypts every blob with the backup's own keys
// in a temporary home under tmp/verify. The row's verified_at/verify_ok and
// its verification error are updated (recordVerify). A verification failure
// is reported in the result (OK=false) with a nil error; errors are returned
// for operational problems (backup missing, no identity, canceled).
func (s *Service) VerifyNow(ctx context.Context, id string, deep bool, h core.JobHandle) (*VerifyResult, error) {
	b, err := s.Get(ctx, id)
	if err != nil {
		return nil, err
	}
	if b.State != core.BackupReady {
		return nil, core.Errorf(core.ErrConflict, "only ready backups can be verified")
	}
	path, err := s.path(b)
	if err != nil {
		return nil, err
	}
	ids, err := s.configuredIdentities()
	if err != nil {
		return nil, err
	}
	f, err := os.Open(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			res := &VerifyResult{BackupID: id, Deep: deep, Error: "the backup file is missing"}
			s.recordVerify(ctx, b.ID, res)
			return res, nil
		}
		return nil, err
	}
	defer f.Close()
	st, _ := f.Stat()
	res, verr := s.verifyStream(ctx, f, st.Size(), ids, deep, b, h)
	if verr != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		ce := core.AsError(verr)
		if ce == nil || (ce.Code != core.ErrCorrupt.Code && ce.Code != core.ErrForbidden.Code && ce.Code != core.ErrInvalid.Code) {
			return nil, verr
		}
		res.OK = false
		res.Error = errorMessage(verr)
	}
	s.recordVerify(ctx, b.ID, res)
	return res, nil
}

// recordVerify stores the outcome of a verification on the backup row. The
// error column of a ready backup can already hold a problem of its creation
// (a failed copy to backup.copy_to — the only record that the off-site copy
// is missing), so a verification only replaces its own part of it (see
// withVerifyError) instead of clearing or overwriting the whole column.
func (s *Service) recordVerify(ctx context.Context, id string, res *VerifyResult) {
	actx := context.WithoutCancel(ctx)
	now := s.env.Now()
	if err := s.env.DB.Tx(actx, func(tx *sql.Tx) error {
		var cur sql.NullString
		if err := tx.QueryRowContext(actx, `SELECT error FROM backups WHERE id = ?`, id).Scan(&cur); err != nil {
			return err
		}
		msg := ""
		if !res.OK {
			msg = res.Error
			if msg == "" {
				msg = "unknown error"
			}
		}
		_, err := tx.ExecContext(actx, `UPDATE backups SET verified_at = ?, verify_ok = ?, error = ? WHERE id = ?`,
			db.Ms(now), db.Bool(res.OK), db.NullString(withVerifyError(cur.String, msg)), id)
		return err
	}); err != nil {
		s.log.Warn("backup: recording the verification failed", "backup", id, "err", err)
	}
}

// verifyErrPrefix starts the part of a backup's error that a verification
// wrote; everything before it belongs to the backup's creation.
const verifyErrPrefix = "verification failed: "

// withVerifyError returns the error column cur with its verification part
// replaced by msg ("" = the verification passed): the part of the creation
// is kept, and a previous verification failure is dropped.
func withVerifyError(cur, msg string) string {
	base := cur
	if strings.HasPrefix(base, verifyErrPrefix) {
		base = ""
	} else if i := strings.Index(base, "; "+verifyErrPrefix); i >= 0 {
		base = base[:i]
	}
	switch {
	case msg == "":
		return base
	case base == "":
		return verifyErrPrefix + msg
	}
	return base + "; " + verifyErrPrefix + msg
}

// verifyStream walks the archive. It always returns a non-nil result.
func (s *Service) verifyStream(ctx context.Context, src io.Reader, size int64, ids []ageIdentity, deep bool,
	b *core.Backup, h core.JobHandle) (*VerifyResult, error) {
	res := &VerifyResult{BackupID: b.ID, Deep: deep}
	var dv *deepVerifier
	if deep {
		var err error
		dv, err = s.newDeepVerifier(ctx)
		if err != nil {
			return res, err
		}
		defer dv.close()
	}
	var read int64
	progress := &progressReader{r: src, fn: func(n int64) {
		read += n
		if h != nil {
			h.Progress(read, size, "")
		}
	}}
	wr, err := walkArchive(ctx, progress, ids, func(hd Header) error {
		res.SchemaVersion = hd.SchemaVersion
		if latest := db.LatestVersion(); hd.SchemaVersion > latest {
			return core.Errorf(core.ErrInvalid, "the backup needs a newer FileParcel (schema %d, this version supports %d)",
				hd.SchemaVersion, latest)
		}
		return nil
	}, func(m memberInfo, r io.Reader) error {
		if m.Kind == kindBlob {
			res.Blobs++
		}
		if dv == nil {
			return nil
		}
		return dv.member(ctx, m, r, res)
	})
	if err != nil {
		return res, err
	}
	res.Members = int(wr.Members)
	if b.SHA256 != "" && !strings.EqualFold(b.SHA256, wr.FileSHA256) {
		return res, core.Errorf(core.ErrCorrupt, "the backup file does not match its recorded checksum (modified or replaced?)")
	}
	if b.Size > 0 && b.Size != wr.FileSize {
		return res, core.Errorf(core.ErrCorrupt, "the backup file size does not match the recorded size")
	}
	if n := wr.MissingBlobs; n > 0 {
		res.Notes = append(res.Notes, fmt.Sprintf("%d files were deleted while the backup ran and are not included", n))
	}
	if dv != nil {
		if err := dv.finish(ctx, wr, res); err != nil {
			return res, err
		}
	}
	res.OK = true
	if h != nil && len(res.Notes) > 0 {
		// The job's note is what the web interface shows when the job has
		// finished: a verification that passed with a reservation (file
		// contents a deep verification could not decrypt) must say so there.
		h.Progress(read, size, strings.Join(res.Notes, "; "))
	}
	return res, nil
}

// deepVerifier extracts the database and keys of an archive into a temporary
// home and verifies every blob with the backup's own keys, one at a time.
type deepVerifier struct {
	s       *Service
	dir     string
	h       *home.Home
	env     *core.Env
	sdb     *db.DB
	keys    core.Keys
	blobs   core.BlobStore
	closeFn func()
	opened  bool
	sealed  bool
	errs    []string
}

func (s *Service) newDeepVerifier(ctx context.Context) (*deepVerifier, error) {
	base := s.env.Home.TmpDir(home.TmpVerify)
	if err := os.MkdirAll(base, 0o700); err != nil {
		return nil, err
	}
	dir, err := os.MkdirTemp(base, "verify-*")
	if err != nil {
		return nil, err
	}
	h, err := home.New(dir)
	if err != nil {
		os.RemoveAll(dir)
		return nil, err
	}
	for _, d := range []string{"data/blobs", "keys", "certs", "logs", "run", "tmp"} {
		if err := os.MkdirAll(filepath.Join(dir, filepath.FromSlash(d)), 0o700); err != nil {
			os.RemoveAll(dir)
			return nil, err
		}
	}
	return &deepVerifier{s: s, dir: dir, h: h}, nil
}

func (d *deepVerifier) close() {
	if d.closeFn != nil {
		d.closeFn()
	}
	if d.sdb != nil {
		_ = d.sdb.Close()
	}
	if d.env != nil && d.env.Bus != nil {
		d.env.Bus.Close()
	}
	_ = os.RemoveAll(d.dir)
}

// member writes database, configuration and key members into the temporary
// home and verifies blob members.
func (d *deepVerifier) member(ctx context.Context, m memberInfo, r io.Reader, res *VerifyResult) error {
	switch m.Kind {
	case kindDB, kindConfig, kindKey:
		return writeMember(filepath.Join(d.dir, filepath.FromSlash(m.Name)), r, 0o600)
	case kindBlob:
		if err := d.open(ctx); err != nil {
			return err
		}
		if d.sealed {
			return nil
		}
		id := filepath.Base(m.Name)
		p := filepath.Join(d.dir, filepath.FromSlash(m.Name))
		if err := writeMember(p, r, 0o600); err != nil {
			return err
		}
		verr := d.blobs.Verify(ctx, id)
		_ = os.Remove(p)
		if verr != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			res.BlobsFailed++
			if len(d.errs) < maxBlobErrors {
				d.errs = append(d.errs, id+": "+errorMessage(verr))
			}
			return nil
		}
		res.BlobsVerified++
	}
	return nil
}

// open opens the temporary database, keys and blob store (once).
func (d *deepVerifier) open(ctx context.Context) error {
	if d.opened {
		return nil
	}
	d.opened = true
	sdb, err := db.Open(d.h.DB())
	if err != nil {
		return core.Wrap(core.ErrCorrupt, "the database snapshot cannot be opened", err)
	}
	d.sdb = sdb
	if err := quickCheck(ctx, sdb.Reader()); err != nil {
		return err
	}
	// Bring an older snapshot to this binary's schema (it is a private copy).
	if _, err := sdb.Migrate(ctx); err != nil {
		return core.Wrap(core.ErrCorrupt, "the database snapshot cannot be migrated", err)
	}
	cfg, err := config.Load(d.h)
	if err != nil {
		cfg = config.Default(d.s.installID())
	}
	d.env = &core.Env{Home: d.h, Config: cfg, DB: sdb, Log: d.s.log.With("verify", "deep"),
		Clock: d.s.env.Clock, Bus: events.New(), Build: d.s.env.Build,
		Settings: defaultSettings{}, Audit: nopAudit{}}
	if d.env.Log == nil {
		d.env.Log = slog.New(slog.DiscardHandler)
	}
	k, b, closeFn, err := openStores(d.env)
	if err != nil {
		return core.Wrap(core.ErrCorrupt, "the backup's keys cannot be opened", err)
	}
	d.keys, d.blobs, d.closeFn = k, b, closeFn
	switch k.State() {
	case core.KeyStateUnlocked:
	case core.KeyStateLocked:
		d.sealed = true
	default:
		return core.Errorf(core.ErrCorrupt, "the backup's master key is missing or invalid")
	}
	return nil
}

// finish runs the checks that need the whole archive.
func (d *deepVerifier) finish(ctx context.Context, wr *walkResult, res *VerifyResult) error {
	if err := d.open(ctx); err != nil {
		return err
	}
	if d.sealed && res.Blobs > 0 {
		// Not a failure (nothing was found wrong), but not the check a deep
		// verification promises either: say so wherever the result is shown.
		res.Notes = append(res.Notes, "file contents were not decrypted: the backup's master key is sealed with a passphrase "+
			"(only the archive, its checksums and the database were checked)")
	}
	if res.BlobsFailed > 0 {
		return core.Errorf(core.ErrCorrupt, "%d files failed verification: %s", res.BlobsFailed, strings.Join(d.errs, "; "))
	}
	if wr.Header.Scope == core.BackupFull {
		var ready int64
		if err := d.sdb.QueryRow(ctx, `SELECT count(*) FROM blobs WHERE state = 'ready'`).Scan(&ready); err != nil {
			return core.Wrap(core.ErrCorrupt, "the database snapshot is unreadable", err)
		}
		if want := ready - wr.MissingBlobs; res.Blobs < want {
			return core.Errorf(core.ErrCorrupt, "the backup holds %d files but the database references %d", res.Blobs, want)
		}
	}
	return nil
}

// quickCheck runs PRAGMA quick_check.
func quickCheck(ctx context.Context, q interface {
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
}) error {
	rows, err := q.QueryContext(ctx, `PRAGMA quick_check`)
	if err != nil {
		return core.Wrap(core.ErrCorrupt, "the database snapshot cannot be checked", err)
	}
	defer rows.Close()
	var msgs []string
	for rows.Next() {
		var m string
		if err := rows.Scan(&m); err != nil {
			return core.Wrap(core.ErrCorrupt, "the database snapshot cannot be checked", err)
		}
		if m != "ok" && len(msgs) < 5 {
			msgs = append(msgs, m)
		}
	}
	if err := rows.Err(); err != nil {
		return core.Wrap(core.ErrCorrupt, "the database snapshot cannot be checked", err)
	}
	if len(msgs) > 0 {
		return core.Errorf(core.ErrCorrupt, "the database snapshot is damaged: %s", strings.Join(msgs, "; "))
	}
	return nil
}

// writeMember writes r to path (parents created 0700), fsynced.
func writeMember(path string, r io.Reader, mode os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return err
	}
	if _, err := io.Copy(f, r); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}
