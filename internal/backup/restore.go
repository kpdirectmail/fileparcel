package backup

import (
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"maps"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"time"

	"fileparcel/internal/core"
	"fileparcel/internal/crypt"
	"fileparcel/internal/db"
	"fileparcel/internal/events"
	"fileparcel/internal/home"
	"fileparcel/internal/ids"
)

// Pending restore request files (run/). The credentials in restore.json are
// sealed with a random one-time key kept in restore.key; both are 0600 and
// removed when the restore is applied or fails.
const (
	restoreKeyName    = "restore.key"
	restoreFailedName = "restore.json.failed"
	restoreRequestV   = 1
)

// restoreRequest is run/restore.json.
type restoreRequest struct {
	V           int              `json:"v"`
	BackupID    string           `json:"backup_id"`
	File        string           `json:"file"` // base name in backups/
	SHA256      string           `json:"sha256,omitempty"`
	Creds       string           `json:"creds"` // base64(nonce||ct), AES-256-GCM, AAD "fp-restore|<backup_id>"
	Opts        core.RestoreOpts `json:"opts"`
	RequestedAt time.Time        `json:"requested_at"`
	RequestedBy string           `json:"requested_by,omitempty"`
}

// restoreFailure is run/restore.json.failed (no credentials).
type restoreFailure struct {
	BackupID string    `json:"backup_id"`
	File     string    `json:"file"`
	Error    string    `json:"error"`
	FailedAt time.Time `json:"failed_at"`
}

// RestoreReport summarizes a restore (or a dry run).
type RestoreReport struct {
	Header       Header `json:"header"`
	Members      int    `json:"members"`
	Blobs        int64  `json:"blobs"`
	BlobsSkipped bool   `json:"blobs_skipped"`
	PreRestore   string `json:"pre_restore,omitempty"` // where the previous data was moved
	DryRun       bool   `json:"dry_run"`
	// For a restore that keeps the current file data (a metadata backup or
	// MetadataOnly): the ready blobs the restored database lists, and how
	// many of them have no file in the kept data (see missingKeptBlobs).
	ListedBlobs  int64 `json:"listed_blobs,omitempty"`
	MissingBlobs int64 `json:"missing_blobs,omitempty"`
}

func restoreAAD(backupID string) []byte { return []byte("fp-restore|" + backupID) }

// ScheduleRestore implements core.Backups: checks that the backup decrypts
// with c (or the configured identity/passphrase when c is empty), that this
// binary supports its schema and that the disk has room for it, writes
// run/restore.json (credentials sealed with a one-time key in
// run/restore.key, both 0600), audits and requests a restart
// (events.TopicSystemRestart). The restore itself runs at the next start
// (ApplyPendingRestore).
func (s *Service) ScheduleRestore(ctx context.Context, by *core.Principal, id string, c core.RestoreCreds) error {
	b, err := s.Get(ctx, id)
	if err != nil {
		return err
	}
	if b.State != core.BackupReady {
		return core.Errorf(core.ErrConflict, "only ready backups can be restored")
	}
	path, err := s.path(b)
	if err != nil {
		return err
	}
	creds, err := s.resolveCreds(c)
	if err != nil {
		return err
	}
	if by != nil {
		ctx = core.WithPrincipal(ctx, by)
	}
	hdr, err := checkHeader(ctx, path, creds)
	if err != nil {
		if ce := core.AsError(err); ce != nil && (ce.Code == core.ErrForbidden.Code || ce.Code == core.ErrCorrupt.Code) {
			s.audit(context.WithoutCancel(ctx), core.AuditEntry{Action: core.ActBackupRestore, Outcome: core.OutcomeFailure,
				TargetType: "backup", TargetID: b.ID, TargetName: b.FileName,
				Details: map[string]any{"scheduled": true, "error": errorMessage(err)}})
		}
		return err
	}
	// The space check the restore runs at the next start, done now: a restore
	// that cannot fit is refused here (507) instead of costing a restart and
	// failing where only run/restore.json.failed records it. The check at the
	// start stays authoritative (free space can change meanwhile).
	archiveSize := b.Size
	if st, err := os.Stat(path); err == nil {
		archiveSize = st.Size()
	}
	staging := s.env.Home.TmpDir(home.TmpRestore)
	if err := os.MkdirAll(staging, 0o700); err != nil {
		return err
	}
	if err := checkRestoreSpace(staging, *hdr, hdr.Scope == core.BackupMetadata, archiveSize); err != nil {
		return err
	}
	credsJSON, _ := json.Marshal(creds)
	key := crypt.RandomBytes(crypt.KeySize)
	defer crypt.Zero(key)
	sealed, err := crypt.SealWithKey(crypt.CipherAES256GCM, key, credsJSON, restoreAAD(b.ID))
	crypt.Zero(credsJSON)
	if err != nil {
		return err
	}
	req := restoreRequest{V: restoreRequestV, BackupID: b.ID, File: b.FileName, SHA256: b.SHA256,
		Creds: base64.StdEncoding.EncodeToString(sealed), RequestedAt: s.env.Now().UTC()}
	if by != nil {
		req.RequestedBy = by.Username
	}
	data, _ := json.MarshalIndent(req, "", "  ")
	hm := s.env.Home
	if err := os.MkdirAll(hm.RunDir(), 0o700); err != nil {
		return err
	}
	keyPath := filepath.Join(hm.RunDir(), restoreKeyName)
	if err := writeFileAtomic(keyPath, []byte(base64.StdEncoding.EncodeToString(key)), 0o600); err != nil {
		return fmt.Errorf("backup: write restore key: %w", err)
	}
	if err := writeFileAtomic(hm.RestoreFile(), data, 0o600); err != nil {
		os.Remove(keyPath)
		return fmt.Errorf("backup: write restore request: %w", err)
	}
	// A newly scheduled restore supersedes the previous failure: drop the
	// marker the doctor and "fileparcel status" read, otherwise "the last
	// scheduled restore failed" keeps warning until some restore succeeds.
	_ = os.Remove(filepath.Join(hm.RunDir(), restoreFailedName))
	s.audit(ctx, core.AuditEntry{Action: core.ActBackupRestore, TargetType: "backup", TargetID: b.ID, TargetName: b.FileName,
		Details: map[string]any{"scheduled": true, "scope": b.Scope, "created_at": b.CreatedAt}})
	s.log.Warn("backup: restore scheduled; restarting", "backup", b.ID, "file", b.FileName)
	if s.env.Bus != nil {
		s.env.Bus.Publish(events.Event{Topic: events.TopicSystemRestart})
	}
	return nil
}

// checkHeader decrypts path with creds far enough to read the archive header
// and checks the format and schema version.
func checkHeader(ctx context.Context, path string, creds core.RestoreCreds) (*Header, error) {
	idents, err := credsIdentities(creds)
	if err != nil {
		return nil, err
	}
	f, err := os.Open(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, core.NotFoundf("the backup file is missing")
		}
		return nil, err
	}
	defer f.Close()
	var hdr Header
	_, err = walkArchive(ctx, f, idents, func(h Header) error {
		hdr = h
		if latest := db.LatestVersion(); h.SchemaVersion > latest {
			return core.Errorf(core.ErrInvalid, "the backup needs a newer FileParcel (schema %d, this version supports %d)",
				h.SchemaVersion, latest)
		}
		return errStopWalk
	}, nil)
	if err != nil {
		return nil, err
	}
	return &hdr, nil
}

// RestoreOffline implements core.Backups: restores file (a path, or the id of
// a backup listed in this server) into the home. The server must be stopped:
// it fails with 409 when another process holds the home lock or when this
// process runs the server. Empty credentials use the configured identity or
// passphrase. After a successful (non-dry-run) restore this process must not
// use its services any more (their database handle refers to the moved-away
// data); the CLI exits.
func (s *Service) RestoreOffline(ctx context.Context, file string, c core.RestoreCreds, o core.RestoreOpts) error {
	_, err := s.RestoreOfflineReport(ctx, file, c, o)
	return err
}

// RestoreOfflineReport is RestoreOffline returning a summary.
func (s *Service) RestoreOfflineReport(ctx context.Context, file string, c core.RestoreCreds, o core.RestoreOpts) (*RestoreReport, error) {
	hm := s.env.Home
	if r, ok := s.jobs.(interface{ Running() bool }); ok && r.Running() {
		return nil, core.Errorf(core.ErrConflict, "the server is running: stop it first, or restore from the web interface")
	}
	unlock, err := s.holdLock(hm)
	if err != nil {
		return nil, err
	}
	defer unlock()

	path := file
	expect := ""
	if ids.Valid(ids.PrefixBackup, file) {
		b, err := s.Get(ctx, file)
		if err != nil {
			return nil, err
		}
		if b.State != core.BackupReady {
			return nil, core.Errorf(core.ErrConflict, "only ready backups can be restored")
		}
		if path, err = s.path(b); err != nil {
			return nil, err
		}
		expect = b.SHA256
	} else {
		abs, err := filepath.Abs(file)
		if err != nil {
			return nil, core.Invalid("file", "invalid backup path")
		}
		path = abs
	}
	creds, err := s.resolveCreds(c)
	if err != nil {
		return nil, err
	}
	var beforeSwap func(Header)
	if !o.DryRun {
		// The success entry is written once the archive has been checked
		// completely, right before the swap — never before a restore that
		// then fails (wrong identity, damaged archive, no disk space), which
		// left a success and a failure entry for the same attempt. It has to
		// go into the current database before that is moved aside, so after
		// the restore it lives in pre-restore-<ts>/ (the restored log has the
		// state of the backup).
		beforeSwap = func(hd Header) {
			s.audit(ctx, core.AuditEntry{Action: core.ActBackupRestore, TargetType: "backup", TargetName: filepath.Base(path),
				Details: map[string]any{"offline": true, "metadata_only": o.MetadataOnly, "backup_id": hd.BackupID}})
			// Make the database file self-contained (this entry included)
			// before it is moved aside.
			if _, err := s.env.DB.Writer().ExecContext(ctx, `PRAGMA wal_checkpoint(TRUNCATE)`); err != nil {
				s.log.Warn("backup: checkpoint before restore failed", "err", err)
			}
		}
	}
	rep, err := restoreHome(ctx, hm, path, creds, o, expect, s.log, beforeSwap)
	if err != nil && !o.DryRun {
		s.audit(context.WithoutCancel(ctx), core.AuditEntry{Action: core.ActBackupRestore, Outcome: core.OutcomeFailure,
			TargetType: "backup", TargetName: filepath.Base(path), Details: map[string]any{"offline": true, "error": errorMessage(err)}})
	}
	return rep, err
}

// holdLock makes sure no other process uses the home. It takes the home lock
// when it is free; when it is held, it must be held by this process (the
// offline CLI holds it while its services exist).
func (s *Service) holdLock(hm *home.Home) (func(), error) {
	unlock, err := hm.Lock()
	if err == nil {
		return unlock, nil
	}
	if !errors.Is(err, home.ErrLocked) {
		return nil, err
	}
	pids, ok := lockHolders(hm.LockFile())
	if ok {
		me := os.Getpid()
		for _, p := range pids {
			if p != me {
				return nil, core.Errorf(core.ErrConflict, "the FileParcel home is in use by another process (pid %d); stop the server first", p)
			}
		}
		return func() {}, nil
	}
	// Owner unknown (non-Linux): this process holds it when the services
	// were built by the offline CLI; refuse only when a server pid file
	// names another live process.
	if pid := readPID(hm.PIDFile()); pid > 0 && pid != os.Getpid() && processAlive(pid) {
		return nil, core.Errorf(core.ErrConflict, "the server is running (pid %d); stop it first", pid)
	}
	return func() {}, nil
}

func readPID(path string) int {
	b, err := os.ReadFile(path)
	if err != nil {
		return 0
	}
	var pid int
	if _, err := fmt.Sscanf(strings.TrimSpace(string(b)), "%d", &pid); err != nil {
		return 0
	}
	return pid
}

// ApplyPendingRestore applies a restore scheduled by Backups.ScheduleRestore
// (h.RestoreFile() = run/restore.json). Contract with `serve`: it is called
// after taking the home lock and BEFORE wire.Build opens the database. It
// returns applied=false and a nil error when nothing is pending. The request
// and its key file are removed as soon as they are read, whatever the
// outcome (a crash during the restore cannot make it loop or re-apply);
// on failure the current data is left untouched, a credential-free
// run/restore.json.failed records the error, and the error is returned
// (serve logs it and continues with the existing data). It needs no
// services: the credentials were sealed into the request by ScheduleRestore.
func ApplyPendingRestore(ctx context.Context, h *home.Home, log *slog.Logger) (applied bool, err error) {
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	// Under the home lock and before anything runs: clear what an interrupted
	// restore, verification or backup left under tmp/, so the space check of
	// a pending restore does not count it as used.
	sweepScratch(h, log)
	reqPath := h.RestoreFile()
	keyPath := filepath.Join(h.RunDir(), restoreKeyName)
	if _, err := os.Stat(reqPath); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			_ = os.Remove(keyPath) // orphaned key
			return false, nil
		}
		return false, err
	}
	var req restoreRequest
	fail := func(err error) (bool, error) {
		f := restoreFailure{BackupID: req.BackupID, File: req.File, Error: errorMessage(err), FailedAt: time.Now().UTC()}
		data, _ := json.MarshalIndent(f, "", "  ")
		_ = writeFileAtomic(filepath.Join(h.RunDir(), restoreFailedName), data, 0o600)
		_ = os.Remove(reqPath)
		_ = os.Remove(keyPath)
		log.Error("backup: the scheduled restore failed; starting with the existing data", "backup", req.BackupID, "err", err)
		return false, err
	}
	raw, err := readSmall(reqPath, 1<<20)
	if err != nil {
		return fail(fmt.Errorf("read restore request: %w", err))
	}
	keyB64, keyErr := readSmall(keyPath, 4096)
	// Consume the request before doing anything that can take long or
	// crash: an interrupted restore is never re-attempted at the next start
	// (the current data is only replaced by the final directory swap, so it
	// stays intact; the administrator schedules the restore again).
	_ = os.Remove(reqPath)
	_ = os.Remove(keyPath)
	syncDir(h.RunDir())
	if err := json.Unmarshal(raw, &req); err != nil || req.V != restoreRequestV {
		return fail(errors.New("the restore request is unreadable"))
	}
	if !fileNameRe.MatchString(req.File) || filepath.Base(req.File) != req.File {
		return fail(errors.New("the restore request names an invalid file"))
	}
	if keyErr != nil {
		return fail(fmt.Errorf("read restore key: %w", keyErr))
	}
	key, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(keyB64)))
	if err != nil {
		return fail(errors.New("the restore key is unreadable"))
	}
	defer crypt.Zero(key)
	sealed, err := base64.StdEncoding.DecodeString(req.Creds)
	if err != nil {
		return fail(errors.New("the restore credentials are unreadable"))
	}
	pt, err := crypt.OpenWithKey(crypt.CipherAES256GCM, key, sealed, restoreAAD(req.BackupID))
	if err != nil {
		return fail(errors.New("the restore credentials failed their integrity check"))
	}
	var creds core.RestoreCreds
	err = json.Unmarshal(pt, &creds)
	crypt.Zero(pt)
	if err != nil {
		return fail(errors.New("the restore credentials are unreadable"))
	}
	log.Warn("backup: applying the scheduled restore", "backup", req.BackupID, "file", req.File)
	rep, err := restoreHome(ctx, h, filepath.Join(h.BackupsDir(), req.File), creds, req.Opts, req.SHA256, log, nil)
	if err != nil {
		return fail(err)
	}
	_ = os.Remove(reqPath)
	_ = os.Remove(keyPath)
	_ = os.Remove(filepath.Join(h.RunDir(), restoreFailedName))
	log.Warn("backup: restore applied", "backup", req.BackupID, "previous_data", rep.PreRestore)
	return true, nil
}

// restoreSlack is the head room a restore keeps on top of the data it
// stages (SQLite journals, the RESTORE-INFO file, rounding).
const restoreSlack = 64 << 20

// checkRestoreSpace refuses a restore that cannot fit before anything is
// extracted. Everything is staged under <home>/tmp/restore and only then
// swapped in, and the replaced data stays behind in pre-restore-<ts>/, so a
// restore needs room for a second copy of the data it restores. Without this
// check the failure comes after a full extract, on a disk that is by then
// completely full.
func checkRestoreSpace(staging string, hd Header, skipBlobs bool, archiveSize int64) error {
	need := hd.DBSize
	if !skipBlobs {
		need += hd.BlobBytes
	}
	if need == 0 {
		// Written before the header carried the sizes: the compressed
		// archive is a lower bound (blob data does not compress).
		need = archiveSize
	}
	need += restoreSlack
	free, ok := diskFree(staging)
	if !ok || free >= need {
		return nil
	}
	return core.Errorf(core.ErrQuota,
		"not enough free disk space to restore this backup (needs about %s in the installation directory, %s free)",
		humanBytes(need), humanBytes(free))
}

func readSmall(path string, max int64) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return io.ReadAll(io.LimitReader(f, max))
}

// RestoreHome restores the archive at path into h without any services
// (restoreHome): the CLI's fallback when the current installation cannot be
// opened at all (a damaged database or master key, or a database migrated by
// a newer version), which is exactly when a restore is needed. The caller
// holds h.Lock() and passes explicit credentials (the configured identity is
// stored in the database that cannot be opened); expectSHA may be empty.
// Scratch data of interrupted runs is cleared first (sweepScratch): the
// services that would otherwise do that at start cannot be built here.
func RestoreHome(ctx context.Context, h *home.Home, path string, creds core.RestoreCreds, o core.RestoreOpts,
	expectSHA string, log *slog.Logger) (*RestoreReport, error) {
	sweepScratch(h, log)
	return restoreHome(ctx, h, path, creds, o, expectSHA, log, nil)
}

// restoreHome extracts the archive at path into a staging directory under
// tmp/restore, validates it completely (manifest, checksums, schema version,
// database quick_check) and then swaps data/, keys/, certs/ and
// fileparcel.toml into the home, moving the current ones to
// <home>/pre-restore-<ts>/. For metadata backups (or MetadataOnly) the
// current data/blobs is kept, and pre-restore-<ts>/data/blobs gets hard links
// to it (preserveKeptBlobs). beforeSwap (may be nil) is called once
// everything has been checked, right before the swap. The caller guarantees
// exclusive use of the home.
func restoreHome(ctx context.Context, h *home.Home, path string, creds core.RestoreCreds, o core.RestoreOpts,
	expectSHA string, log *slog.Logger, beforeSwap func(Header)) (*RestoreReport, error) {
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	idents, err := credsIdentities(creds)
	if err != nil {
		return nil, err
	}
	if len(idents) == 0 {
		return nil, core.Invalid("identity", "provide the backup identity or passphrase")
	}
	f, err := os.Open(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, core.NotFoundf("the backup file %s does not exist", filepath.Base(path))
		}
		return nil, err
	}
	defer f.Close()
	archiveSize := int64(0)
	if st, err := f.Stat(); err == nil {
		archiveSize = st.Size()
	}

	base := h.TmpDir(home.TmpRestore)
	if err := os.MkdirAll(base, 0o700); err != nil {
		return nil, err
	}
	staging, err := os.MkdirTemp(base, "restore-*")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(staging)
	root, err := os.OpenRoot(staging)
	if err != nil {
		return nil, err
	}
	defer root.Close()

	rep := &RestoreReport{DryRun: o.DryRun}
	skipBlobs := o.MetadataOnly || o.DryRun
	wr, err := walkArchive(ctx, f, idents, func(hd Header) error {
		if latest := db.LatestVersion(); hd.SchemaVersion > latest {
			return core.Errorf(core.ErrInvalid, "the backup needs a newer FileParcel (schema %d, this version supports %d)",
				hd.SchemaVersion, latest)
		}
		if hd.Scope == core.BackupMetadata {
			skipBlobs = true
		}
		return checkRestoreSpace(staging, hd, skipBlobs, archiveSize)
	}, func(m memberInfo, r io.Reader) error {
		switch m.Kind {
		case kindBlob:
			rep.Blobs++
			if skipBlobs {
				return nil
			}
			return extract(root, m.Name, r, 0o600)
		case kindConfig:
			return extract(root, m.Name, r, home.ModeConfig)
		case kindDB, kindKey, kindCert:
			return extract(root, m.Name, r, 0o600)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	rep.Header = wr.Header
	rep.Members = int(wr.Members)
	rep.BlobsSkipped = skipBlobs && rep.Blobs > 0
	if expectSHA != "" && !strings.EqualFold(expectSHA, wr.FileSHA256) {
		return nil, core.Errorf(core.ErrCorrupt, "the backup file does not match its recorded checksum")
	}
	if _, err := os.Stat(filepath.Join(staging, memberConfig)); err != nil {
		return nil, core.Errorf(core.ErrCorrupt, "the backup has no configuration file")
	}
	stagedDB := filepath.Join(staging, filepath.FromSlash(memberDB))
	if err := prepareRestoredDB(ctx, stagedDB, wr, h.BackupsDir(), path); err != nil {
		return nil, err
	}
	keepBlobs := wr.Header.Scope == core.BackupMetadata || o.MetadataOnly
	if keepBlobs {
		// The restored database meets the file data of this installation.
		// When its blobs are not there (a metadata backup taken before "keys
		// rotate --data", which gave every file a new blob id, or one from
		// another installation), its files cannot be opened: say so, in a dry
		// run too.
		missing, listed, err := missingKeptBlobs(ctx, stagedDB, h.BlobsDir())
		if err != nil {
			return nil, core.Wrap(core.ErrCorrupt, "the database snapshot is unreadable", err)
		}
		rep.ListedBlobs, rep.MissingBlobs = listed, missing
		if missing > 0 {
			log.Warn("backup: stored files the restored database lists have no data in this installation "+
				"(re-encrypted or deleted after the backup was made, or a backup of another installation); "+
				"they cannot be opened after the restore, a full backup restores them",
				"missing", missing, "listed", listed, "backup", wr.Header.BackupID)
		}
	}
	if o.DryRun {
		log.Info("backup: restore dry run succeeded", "backup", wr.Header.BackupID, "members", rep.Members)
		return rep, nil
	}
	if beforeSwap != nil {
		beforeSwap(wr.Header)
	}
	pre, err := swapIn(h, staging, keepBlobs, time.Now())
	if err != nil {
		return nil, err
	}
	rep.PreRestore = pre
	info := fmt.Sprintf("FileParcel restore\n\nrestored:  %s (backup %s, %s, created %s)\nrestored at: %s\n\n"+
		"This directory holds the data, keys, certificates and configuration that were\n"+
		"replaced by the restore. Delete it once the restored server works. To undo the\n"+
		"restore, stop the server and put data/, keys/, certs/ and fileparcel.toml from\n"+
		"here back in place of the restored ones.\n",
		filepath.Base(path), wr.Header.BackupID, wr.Header.Scope, wr.Header.CreatedAt.Format(time.RFC3339),
		time.Now().UTC().Format(time.RFC3339))
	if keepBlobs {
		// The kept blob store was moved back into the live data/, so the
		// replaced database here would refer to nothing: the restored server
		// deletes the blobs its database does not list (files uploaded after
		// the backup, every file after a data re-encryption), and an undo
		// would then find their data gone. Hard links keep it for the undo.
		kept, left, lerr := preserveKeptBlobs(context.WithoutCancel(ctx), h.BlobsDir(), filepath.Join(pre, "data", "blobs"), h.DB())
		info += "\nThis restore kept the installation's file data in place: data/blobs here holds\n" +
			"hard links to it (no extra space), so the data of files the restored database\n" +
			"does not know stays here after the restored server deletes it; that space is\n" +
			"freed when this directory is deleted.\n"
		if left > 0 {
			log.Warn("backup: some kept file data could not be linked into the pre-restore directory",
				"count", left, "err", lerr, "previous_data", pre)
			info += fmt.Sprintf("\n%d stored files could not be linked here (%v); they are only in the\n"+
				"installation's data/blobs. Before undoing the restore, copy them into data/blobs here.\n", left, lerr)
		}
		if rep.MissingBlobs > 0 {
			info += fmt.Sprintf("\n%d of the %d stored files the restored database lists have no data in this\n"+
				"installation: they were re-encrypted (\"keys rotate --data\") or deleted after the\n"+
				"backup was made, or the backup comes from another installation. Those files\n"+
				"cannot be opened; restore a full backup instead, or undo this restore.\n", rep.MissingBlobs, rep.ListedBlobs)
		}
		log.Info("backup: kept file data linked into the pre-restore directory", "blobs", kept)
	}
	_ = os.WriteFile(filepath.Join(pre, "RESTORE-INFO.txt"), []byte(info), 0o600)
	log.Info("backup: restore complete", "backup", wr.Header.BackupID, "scope", wr.Header.Scope,
		"blobs", rep.Blobs, "previous_data", pre)
	return rep, nil
}

// missingKeptBlobs counts the ready blobs the database at dbPath lists
// (listed) and those of them that have no file in blobsDir (missing).
func missingKeptBlobs(ctx context.Context, dbPath, blobsDir string) (missing, listed int64, err error) {
	sdb, err := db.Open(dbPath)
	if err != nil {
		return 0, 0, err
	}
	defer sdb.Close()
	rows, err := sdb.Query(ctx, `SELECT id FROM blobs WHERE state = 'ready'`)
	if err != nil {
		return 0, 0, err
	}
	defer rows.Close()
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return 0, 0, err
		}
		if !ids.ValidBlobID(id) {
			continue
		}
		listed++
		if _, err := os.Lstat(filepath.Join(blobsDir, id[0:2], id[2:4], id)); errors.Is(err, fs.ErrNotExist) {
			missing++
		}
	}
	return missing, listed, rows.Err()
}

// linkFile is os.Link (a variable so tests can take hard links away).
var linkFile = os.Link

// preserveKeptBlobs gives every blob file of live (the blob store a metadata
// restore kept) a hard link at the same place below dst (the pre-restore
// directory's data/blobs), so the replaced database there keeps its data
// whatever the restored server deletes. Blob files are never modified once
// written (a re-encryption writes a new blob), so a link is an exact copy
// that costs no space. Where the file system has no hard links, a blob the
// restored database (restoredDB) does not list is moved there instead — the
// restored server would delete it as an orphan — and the others stay only
// in live (left, with the first error). It never fails the restore, which is
// complete by then.
func preserveKeptBlobs(ctx context.Context, live, dst, restoredDB string) (kept, left int64, firstErr error) {
	var rdb *db.DB
	defer func() {
		if rdb != nil {
			_ = rdb.Close()
		}
	}()
	listed := func(id string) (bool, error) {
		if rdb == nil {
			d, err := db.Open(restoredDB)
			if err != nil {
				return false, err
			}
			rdb = d
		}
		var one int
		err := rdb.QueryRow(ctx, `SELECT 1 FROM blobs WHERE id = ?`, id).Scan(&one)
		if db.IsNoRows(err) {
			return false, nil
		}
		return err == nil, err
	}
	fail := func(err error) {
		left++
		if firstErr == nil {
			firstErr = err
		}
	}
	_ = filepath.WalkDir(live, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			if firstErr == nil && !errors.Is(err, fs.ErrNotExist) {
				firstErr = err
			}
			return nil
		}
		id := d.Name()
		if !d.Type().IsRegular() || !ids.ValidBlobID(id) {
			return nil
		}
		rel := filepath.Join(id[0:2], id[2:4], id)
		if p != filepath.Join(live, rel) {
			return nil // not in the store's layout
		}
		target := filepath.Join(dst, rel)
		if err := os.MkdirAll(filepath.Dir(target), 0o700); err != nil {
			fail(err)
			return nil
		}
		lerr := linkFile(p, target)
		if lerr == nil || errors.Is(lerr, fs.ErrExist) {
			kept++
			return nil
		}
		if known, err := listed(id); err == nil && !known {
			if err := os.Rename(p, target); err == nil {
				kept++
				return nil
			}
		}
		fail(lerr)
		return nil
	})
	return kept, left, firstErr
}

// extract writes one member below root (parents 0700).
func extract(root *os.Root, name string, r io.Reader, mode os.FileMode) error {
	if dir := filepath.Dir(filepath.FromSlash(name)); dir != "." {
		if err := root.MkdirAll(dir, 0o700); err != nil {
			return err
		}
	}
	f, err := root.OpenFile(filepath.FromSlash(name), os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
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

// prepareRestoredDB checks the extracted snapshot (schema version,
// quick_check) and makes its backups table match backupsDir as it will be
// after the restore: the row of the backup itself (at snapshot time it was
// still running, as was its job) becomes ready when its archive is in
// backupsDir — under the name it was restored from (srcPath) when that is
// there, e.g. an imported copy — and is dropped otherwise (a restore from a
// USB disk on a new machine); ready rows whose file is gone (pruned or
// deleted after the snapshot, or never copied to this machine) are dropped;
// backup files the snapshot does not know are registered (orphanBackups).
// When backupsDir cannot be listed, only the own row is fixed.
func prepareRestoredDB(ctx context.Context, path string, wr *walkResult, backupsDir, srcPath string) error {
	sdb, err := db.Open(path)
	if err != nil {
		return core.Wrap(core.ErrCorrupt, "the database snapshot cannot be opened", err)
	}
	defer sdb.Close()
	v, err := sdb.SchemaVersion(ctx)
	if err != nil {
		return core.Wrap(core.ErrCorrupt, "the database snapshot is unreadable", err)
	}
	if v > db.LatestVersion() {
		return core.Errorf(core.ErrInvalid, "the backup needs a newer FileParcel (schema %d)", v)
	}
	if err := quickCheck(ctx, sdb.Reader()); err != nil {
		return err
	}
	srcName := "" // the archive's name when it was read from backupsDir itself
	if srcPath != "" && filepath.Clean(filepath.Dir(srcPath)) == filepath.Clean(backupsDir) {
		srcName = filepath.Base(srcPath)
	}
	var ownName string // the backup's own row, running at snapshot time
	if err := sdb.QueryRow(ctx, `SELECT file_name FROM backups WHERE id = ? AND state = 'running'`,
		wr.Header.BackupID).Scan(&ownName); err != nil && !db.IsNoRows(err) {
		return core.Wrap(core.ErrCorrupt, "the database snapshot is unreadable", err)
	}
	files, listed := backupFiles(backupsDir)
	// Where the own row's archive is after the restore ("" = not in backupsDir).
	ownFile := ownName
	switch {
	case srcName != "":
		ownFile = srcName
	case !listed:
	default:
		if fi, ok := files[ownName]; !ok || fi.Size() != wr.FileSize {
			ownFile = ""
		}
	}
	var orphans []orphan
	if listed {
		if orphans, err = orphanBackups(ctx, sdb, backupsDir, files, ownName, ownFile); err != nil {
			return core.Wrap(core.ErrCorrupt, "the database snapshot is unreadable", err)
		}
	}
	now := db.Ms(time.Now())
	return sdb.Tx(ctx, func(tx *sql.Tx) error {
		switch {
		case ownName == "":
		case ownFile != "":
			if _, err := tx.ExecContext(ctx, `UPDATE backups SET state = 'ready', file_name = ?, size = ?, sha256 = ?,
				blob_count = ?, blob_bytes = ?, db_size = ?, finished_at = coalesce(finished_at, ?)
				WHERE id = ?`, ownFile, wr.FileSize, wr.FileSHA256, wr.Manifest.Counts.Blobs,
				wr.Manifest.Counts.BlobBytes, wr.Manifest.Counts.DBSize, now, wr.Header.BackupID); err != nil {
				return err
			}
		default:
			// Restored from a file outside backupsDir that is not in it: a
			// row nothing could be downloaded, verified or restored from.
			if _, err := tx.ExecContext(ctx, `DELETE FROM backups WHERE id = ?`, wr.Header.BackupID); err != nil {
				return err
			}
		}
		if listed {
			if err := dropMissingBackups(ctx, tx, files, wr.Header.BackupID); err != nil {
				return err
			}
		}
		if wr.Header.JobID != "" {
			res, _ := json.Marshal(CreateResult{BackupID: wr.Header.BackupID, Size: wr.FileSize})
			if _, err := tx.ExecContext(ctx, `UPDATE jobs SET state = 'succeeded', result = ?, finished_at = ?
				WHERE id = ? AND state = 'running'`, string(res), now, wr.Header.JobID); err != nil {
				return err
			}
		}
		for _, o := range orphans {
			if _, err := tx.ExecContext(ctx, `INSERT INTO backups (id, scope, state, file_name, size, encryption, note,
				"trigger", created_at, finished_at) VALUES (?, ?, 'ready', ?, ?, ?, ?, 'import', ?, ?)`,
				ids.New(ids.PrefixBackup), o.scope, o.name, o.size, o.encryption,
				"found in backups/ after a restore (not known to the restored database)", db.Ms(o.modTime), now); err != nil {
				return err
			}
		}
		return nil
	})
}

// orphan is a backup file the restored database does not list.
type orphan struct {
	name, scope, encryption string
	size                    int64
	modTime                 time.Time
}

// scopeSuffixRe extracts the scope from fp-<install8>-<ts>-<scope>[-n].fpbak.
var scopeSuffixRe = regexp.MustCompile(`-(full|metadata)(-[0-9]+)?\.fpbak$`)

// backupFiles lists the backup files of dir (regular files with a valid
// name, not hidden) by name. ok is false when dir cannot be listed; a dir
// that does not exist (not even as a dangling symlink) has no files.
func backupFiles(dir string) (files map[string]fs.FileInfo, ok bool) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		if _, lerr := os.Lstat(dir); errors.Is(err, fs.ErrNotExist) && errors.Is(lerr, fs.ErrNotExist) {
			return map[string]fs.FileInfo{}, true
		}
		return nil, false
	}
	files = map[string]fs.FileInfo{}
	for _, e := range entries {
		name := e.Name()
		if !e.Type().IsRegular() || strings.HasPrefix(name, ".") || !fileNameRe.MatchString(name) {
			continue
		}
		if info, err := e.Info(); err == nil {
			files[name] = info
		}
	}
	return files, true
}

// dropMissingBackups deletes the ready rows (except skipID) whose file is
// not in files: after a restore they would offer a download, verification
// and restore of an archive that is not there, and keep the "last backup"
// checks green.
func dropMissingBackups(ctx context.Context, tx *sql.Tx, files map[string]fs.FileInfo, skipID string) error {
	rows, err := tx.QueryContext(ctx, `SELECT id, file_name FROM backups WHERE state = 'ready' AND id <> ?`, skipID)
	if err != nil {
		return err
	}
	var gone []string
	for rows.Next() {
		var id, name string
		if err := rows.Scan(&id, &name); err != nil {
			rows.Close()
			return err
		}
		if _, ok := files[name]; !ok {
			gone = append(gone, id)
		}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	for _, id := range gone {
		if _, err := tx.ExecContext(ctx, `DELETE FROM backups WHERE id = ?`, id); err != nil {
			return err
		}
	}
	return nil
}

// orphanBackups returns the backup files of dir (files, see backupFiles)
// that are age files with no row in the restored database: backups made
// after the restored one, or by the replaced installation. Registering them
// keeps them visible (and deletable/restorable) after the restore. The row
// of the restored backup itself names ownFrom in the snapshot and ownTo
// after the restore ("" = its row is dropped).
func orphanBackups(ctx context.Context, sdb *db.DB, dir string, files map[string]fs.FileInfo, ownFrom, ownTo string) ([]orphan, error) {
	known := map[string]bool{}
	rows, err := sdb.Query(ctx, `SELECT file_name FROM backups`)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			rows.Close()
			return nil, err
		}
		known[n] = true
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if ownFrom != "" {
		delete(known, ownFrom)
		if ownTo != "" {
			known[ownTo] = true
		}
	}
	names := slices.Sorted(maps.Keys(files))
	var out []orphan
	for _, name := range names {
		if known[name] {
			continue
		}
		info := files[name]
		f, err := os.Open(filepath.Join(dir, name))
		if err != nil {
			continue
		}
		hi, err := readAgeHeader(io.LimitReader(f, 1<<20))
		f.Close()
		if err != nil {
			continue // not a backup
		}
		o := orphan{name: name, scope: core.BackupFull, encryption: hi.encryption(), size: info.Size(), modTime: info.ModTime()}
		if m := scopeSuffixRe.FindStringSubmatch(name); m != nil {
			o.scope = m[1]
		}
		out = append(out, o)
	}
	return out, nil
}

// restoredItems are the home entries a restore replaces.
var restoredItems = []string{"data", "keys", "certs", home.ConfigName}

// swapIn moves the current items of the home to <home>/pre-restore-<ts>/
// and the staged ones in. Every rename is undone when a later one fails.
func swapIn(h *home.Home, staging string, keepBlobs bool, now time.Time) (string, error) {
	pre := h.Path("pre-restore-" + now.UTC().Format("20060102-150405"))
	for i := 2; ; i++ {
		if _, err := os.Lstat(pre); errors.Is(err, fs.ErrNotExist) {
			break
		}
		pre = h.Path(fmt.Sprintf("pre-restore-%s-%d", now.UTC().Format("20060102-150405"), i))
	}
	if err := os.Mkdir(pre, 0o700); err != nil {
		return "", err
	}
	type move struct{ from, to string }
	var done []move
	mv := func(from, to string) error {
		if err := os.Rename(from, to); err != nil {
			return err
		}
		done = append(done, move{from, to})
		return nil
	}
	rollback := func(cause error) (string, error) {
		for i := len(done) - 1; i >= 0; i-- {
			_ = os.Rename(done[i].to, done[i].from)
		}
		_ = os.Remove(pre)
		return "", fmt.Errorf("backup: restore swap failed (nothing was changed): %w", cause)
	}
	exists := func(p string) bool { _, err := os.Lstat(p); return err == nil }
	for _, it := range restoredItems {
		if cur := h.Path(it); exists(cur) {
			if err := mv(cur, filepath.Join(pre, it)); err != nil {
				return rollback(err)
			}
		}
	}
	for _, it := range restoredItems {
		if st := filepath.Join(staging, it); exists(st) {
			if err := mv(st, h.Path(it)); err != nil {
				return rollback(err)
			}
		}
	}
	if keepBlobs {
		oldBlobs := filepath.Join(pre, "data", "blobs")
		newBlobs := filepath.Join(h.DataDir(), "blobs")
		if exists(oldBlobs) {
			_ = os.Remove(newBlobs) // only succeeds when empty
			if err := mv(oldBlobs, newBlobs); err != nil {
				return rollback(err)
			}
		}
	}
	// Directories the archive did not contain (e.g. no certs yet) are
	// recreated empty so the layout stays complete.
	for _, d := range []string{"data", "data/blobs", "keys", "certs"} {
		_ = os.MkdirAll(h.Path(filepath.FromSlash(d)), 0o700)
	}
	syncDir(h.Dir())
	return pre, nil
}
