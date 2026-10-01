package backup

import (
	"bufio"
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"filippo.io/age"

	"fileparcel/internal/core"
	"fileparcel/internal/db"
	"fileparcel/internal/ids"
)

// maxNoteLen bounds BackupInput.Note.
const maxNoteLen = 500

// createParams are the parameters of a backup.create job.
type createParams struct {
	Scope         string `json:"scope"`
	Note          string `json:"note,omitempty"`
	Trigger       string `json:"trigger"`
	CopyTo        string `json:"copy_to,omitempty"`
	CreatedBy     string `json:"created_by,omitempty"`
	CreatedByName string `json:"created_by_name,omitempty"`
}

// CreateResult is the result of a backup.create job.
type CreateResult struct {
	BackupID string `json:"backup_id"`
	FileName string `json:"file_name"`
	Size     int64  `json:"size"`
}

// normalize validates a BackupInput for principal by.
func normalize(by *core.Principal, in core.BackupInput) (createParams, error) {
	p := createParams{Scope: in.Scope, Note: strings.TrimSpace(in.Note), Trigger: in.Trigger, CopyTo: copyToDir(in.CopyTo)}
	if p.Scope == "" {
		p.Scope = core.BackupFull
	}
	if p.Scope != core.BackupFull && p.Scope != core.BackupMetadata {
		return p, core.Invalid("scope", "scope must be full or metadata")
	}
	if len([]rune(p.Note)) > maxNoteLen {
		return p, core.Invalid("note", "the note is too long (max 500 characters)")
	}
	if p.Trigger == "" {
		p.Trigger = core.TriggerManual
	}
	system := by != nil && by.IsSystem()
	switch p.Trigger {
	case core.TriggerManual:
	case core.TriggerPreUpgrade, core.TriggerFinal:
		if !system {
			return p, core.Invalid("trigger", "this trigger is reserved for the local administrator")
		}
	default:
		return p, core.Invalid("trigger", "trigger must be manual, pre-upgrade or final")
	}
	if p.CopyTo != "" {
		if !system {
			return p, core.Invalid("copy_to", "copy_to is reserved for the local administrator")
		}
		if err := validCopyTo(p.CopyTo); err != nil {
			return p, core.Invalid("copy_to", err.Error())
		}
	}
	if by != nil {
		p.CreatedBy, p.CreatedByName = by.UserID, by.Username
	}
	return p, nil
}

// Create implements core.Backups: validates the input and enqueues a
// backup.create job (Exclusive "backup").
func (s *Service) Create(ctx context.Context, by *core.Principal, in core.BackupInput) (string, error) {
	p, err := normalize(by, in)
	if err != nil {
		return "", err
	}
	if err := s.checkCopyTo(p.CopyTo); err != nil {
		return "", err
	}
	if s.jobs == nil {
		return "", core.Errorf(core.ErrUnavailable, "the job runner is not available")
	}
	if err := s.precheckEncryption(); err != nil {
		return "", err
	}
	return s.jobs.Enqueue(ctx, core.JobBackupCreate, p, by)
}

// CreateSync implements core.Backups: writes the backup in the calling
// goroutine (pre-upgrade/final backups, offline CLI) and returns it.
func (s *Service) CreateSync(ctx context.Context, by *core.Principal, in core.BackupInput) (*core.Backup, error) {
	p, err := normalize(by, in)
	if err != nil {
		return nil, err
	}
	if err := s.checkCopyTo(p.CopyTo); err != nil {
		return nil, err
	}
	if err := s.precheckEncryption(); err != nil {
		return nil, err
	}
	return s.create(ctx, p, nil)
}

func (s *Service) jobCreate(ctx context.Context, h core.JobHandle) error {
	var p createParams
	if err := h.Params(&p); err != nil {
		return err
	}
	if p.Scope == "" {
		p.Scope = core.BackupFull
	}
	if p.Trigger == "" {
		p.Trigger = core.TriggerManual
	}
	b, err := s.create(ctx, p, h)
	if err != nil {
		return err
	}
	h.SetResult(CreateResult{BackupID: b.ID, FileName: b.FileName, Size: b.Size})
	if p.Trigger == core.TriggerSchedule && s.jobs != nil {
		if _, err := s.jobs.Enqueue(context.WithoutCancel(ctx), core.JobBackupPrune, nil, nil); err != nil {
			s.log.Warn("backup: enqueue prune failed", "err", err)
		}
	}
	return nil
}

// precheckEncryption fails fast when no backup can be encrypted with the
// current configuration (it never generates or reads secrets).
func (s *Service) precheckEncryption() error {
	st := s.env.Settings
	if st == nil {
		return core.Errorf(core.ErrUnavailable, "settings unavailable")
	}
	switch st.String(SettingEncryption) {
	case core.BackupPassphrase:
		if !secretSet(st, SettingPassphrase) {
			return core.Invalid("encryption", "passphrase encryption is selected but no backup passphrase is set")
		}
		if s.env.Keys == nil || s.env.Keys.State() != core.KeyStateUnlocked {
			return core.ErrKeysLocked
		}
	default:
		list := st.Strings(SettingRecipients)
		if len(list) == 0 && (s.env.Keys == nil || s.env.Keys.State() != core.KeyStateUnlocked) {
			return core.Invalid("recipients", "no backup recipient is configured; generate a backup identity first")
		}
		// A list stored before mixed kinds were refused: every backup would
		// fail in age.Encrypt, after its row was already recorded.
		var all []age.Recipient
		for _, l := range list {
			if rs, err := parseRecipients(l); err == nil {
				all = append(all, rs...)
			}
		}
		if err := checkRecipientMix(all); err != nil {
			return core.Invalid("recipients", err.Error())
		}
	}
	return nil
}

// secretSet reports whether a secret setting holds a value (Raw is masked).
func secretSet(st core.Settings, key string) bool {
	raw, err := st.Raw(key)
	return err == nil && string(raw) != `""` && string(raw) != "null" && len(raw) > 0
}

// encryptionPlan resolves how the next backup is encrypted. In x25519 mode
// the recipients are backup.recipients plus the server's own backup key; a
// backup identity is generated (and stored) first when there is no recipient
// at all, or when the stored identity is of the other kind (classic or
// post-quantum) than the list.
func (s *Service) encryptionPlan(ctx context.Context) (*encryptionPlan, error) {
	st := s.env.Settings
	if st == nil {
		return nil, core.Errorf(core.ErrUnavailable, "settings unavailable")
	}
	if st.String(SettingEncryption) == core.BackupPassphrase {
		pass, err := st.Secret(SettingPassphrase)
		if err != nil {
			return nil, err
		}
		if pass == "" {
			return nil, core.Invalid("encryption", "passphrase encryption is selected but no backup passphrase is set")
		}
		r, err := age.NewScryptRecipient(pass)
		if err != nil {
			return nil, core.Invalid("passphrase", "invalid backup passphrase")
		}
		r.SetWorkFactor(scryptWorkFactor)
		return &encryptionPlan{mode: core.BackupPassphrase, recipients: []age.Recipient{r}}, nil
	}
	list := st.Strings(SettingRecipients)
	// The server's own backup key is a recipient of every backup, whatever
	// the stored list says (it can be replaced as a whole, also through the
	// generic settings), so the stored identity verifies and restores every
	// backup and the copy of it kept offline decrypts them. While the keys
	// are locked the identity cannot be read, and x25519 backups need no
	// secret: the stored list is used as it is (SetConfig and
	// generateIdentity keep the key in it).
	own, err := s.ownRecipient()
	if err != nil && !errors.Is(err, core.ErrKeysLocked) {
		return nil, err
	}
	why := ""
	switch {
	case own != "":
		if l, ok := withRecipient(list, own); ok {
			list = l
		} else {
			why = "the backup recipients are of the other kind (classic or post-quantum) than the backup identity; generating a backup identity of their kind"
		}
	case len(list) == 0:
		why = "no backup recipient configured; generating a backup identity"
	}
	if why != "" {
		s.log.Warn("backup: " + why + " (export it from the Backups page and keep it safe)")
		if _, _, err := s.generateIdentity(ctx, core.SystemPrincipal(core.ViaOffline), false); err != nil {
			return nil, fmt.Errorf("backup: generate identity: %w", err)
		}
		list = st.Strings(SettingRecipients)
		if len(list) == 0 {
			return nil, core.Invalid("recipients", "no backup recipient is configured")
		}
	}
	plan := &encryptionPlan{mode: core.BackupX25519}
	for _, l := range list {
		rs, err := parseRecipients(l)
		if err != nil {
			return nil, core.Invalid("recipients", err.Error())
		}
		plan.recipients = append(plan.recipients, rs...)
		plan.public = append(plan.public, strings.TrimSpace(l))
	}
	if err := checkRecipientMix(plan.recipients); err != nil {
		return nil, core.Invalid("recipients", err.Error())
	}
	return plan, nil
}

// create writes one backup (row, snapshot, archive, copy) and returns it.
// h (may be nil) receives progress.
func (s *Service) create(ctx context.Context, p createParams, h core.JobHandle) (*core.Backup, error) {
	s.createMu.Lock()
	defer s.createMu.Unlock()

	plan, err := s.encryptionPlan(ctx)
	if err != nil {
		return nil, err
	}
	hm := s.env.Home
	if err := os.MkdirAll(hm.BackupsDir(), 0o700); err != nil {
		return nil, fmt.Errorf("backup: %w", err)
	}
	schema, err := s.env.DB.SchemaVersion(ctx)
	if err != nil {
		return nil, fmt.Errorf("backup: schema version: %w", err)
	}
	now := s.env.Now()
	id := ids.New(ids.PrefixBackup)
	jobID := ""
	if h != nil {
		jobID = h.ID()
	}
	var recipients sql.NullString
	if len(plan.public) > 0 {
		b, _ := json.Marshal(plan.public)
		recipients = sql.NullString{String: string(b), Valid: true}
	}
	appVersion := s.env.Build.Version
	// The row claims the name (the file only appears at the end); an import
	// choosing a name meanwhile waits for it (see Import).
	s.nameMu.Lock()
	name, err := s.uniqueFileName(ctx, s.installPrefix(), now, p.Scope)
	if err == nil {
		err = s.env.DB.Tx(ctx, func(tx *sql.Tx) error {
			_, err := tx.ExecContext(ctx, `INSERT INTO backups (id, scope, state, file_name, encryption, recipients,
				app_version, schema_version, note, "trigger", job_id, created_by, created_at)
				VALUES (?, ?, 'running', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
				id, p.Scope, name, plan.mode, recipients, appVersion, schema, db.NullString(p.Note), p.Trigger,
				db.NullString(jobID), db.NullString(p.CreatedBy), db.Ms(now))
			return err
		})
		if err != nil {
			err = fmt.Errorf("backup: record: %w", err)
		}
	}
	s.nameMu.Unlock()
	if err != nil {
		return nil, err
	}
	s.log.Info("backup started", "backup", id, "scope", p.Scope, "trigger", p.Trigger, "file", name)

	hdr := Header{Format: FormatName, Version: FormatVersion, BackupID: id, JobID: jobID, AppVersion: appVersion,
		SchemaVersion: schema, Scope: p.Scope, InstallID: s.installID(), CreatedAt: now.UTC().Truncate(time.Second),
		Encryption: plan.mode}
	res, werr := s.writeArchive(ctx, hdr, name, plan, h)
	auditCtx := context.WithoutCancel(ctx)
	if werr != nil {
		msg := errorMessage(werr)
		fin := s.env.Now()
		if err := s.env.DB.Tx(auditCtx, func(tx *sql.Tx) error {
			_, err := tx.ExecContext(auditCtx, `UPDATE backups SET state = 'failed', error = ?, finished_at = ? WHERE id = ?`,
				msg, db.Ms(fin), id)
			return err
		}); err != nil {
			s.log.Error("backup: recording the failure failed", "backup", id, "err", err)
		}
		s.log.Warn("backup failed", "backup", id, "err", werr)
		s.audit(auditCtx, core.AuditEntry{Action: core.ActBackupCreate, Outcome: core.OutcomeFailure, TargetType: "backup",
			TargetID: id, TargetName: name, ActorID: p.CreatedBy, ActorName: p.CreatedByName,
			Details: map[string]any{"scope": p.Scope, "trigger": p.Trigger, "error": msg}})
		if b, err := s.Get(auditCtx, id); err == nil {
			s.publishFinished(b)
		}
		return nil, werr
	}

	fin := s.env.Now()
	copyTo := p.CopyTo
	if copyTo == "" && s.env.Settings != nil {
		copyTo = copyToDir(s.env.Settings.String(SettingCopyTo))
	}
	var copied, copyErr string
	if copyTo != "" {
		if dst, err := s.copyTo(ctx, filepath.Join(hm.BackupsDir(), name), copyTo, name); err != nil {
			copyErr = "copy to " + copyTo + " failed: " + errorMessage(err)
			s.log.Warn("backup: copy failed", "backup", id, "dest", copyTo, "err", err)
		} else {
			copied = dst
		}
	}
	err = s.env.DB.Tx(auditCtx, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(auditCtx, `UPDATE backups SET state = 'ready', size = ?, sha256 = ?, blob_count = ?,
			blob_bytes = ?, db_size = ?, finished_at = ?, copied_to = ?, error = ? WHERE id = ?`,
			res.size, res.sha256, res.manifest.Counts.Blobs, res.manifest.Counts.BlobBytes, res.manifest.Counts.DBSize,
			db.Ms(fin), db.NullString(copied), db.NullString(copyErr), id)
		return err
	})
	if err != nil {
		return nil, fmt.Errorf("backup: record: %w", err)
	}
	details := map[string]any{"scope": p.Scope, "trigger": p.Trigger, "size": res.size, "blobs": res.manifest.Counts.Blobs}
	if len(res.manifest.MissingBlobs) > 0 {
		details["missing_blobs"] = len(res.manifest.MissingBlobs)
	}
	if copied != "" {
		details["copied_to"] = copied
	}
	s.audit(auditCtx, core.AuditEntry{Action: core.ActBackupCreate, TargetType: "backup", TargetID: id, TargetName: name,
		ActorID: p.CreatedBy, ActorName: p.CreatedByName, Details: details})
	b, err := s.Get(auditCtx, id)
	if err != nil {
		return nil, err
	}
	s.log.Info("backup finished", "backup", id, "file", name, "size", res.size, "blobs", res.manifest.Counts.Blobs,
		"dur", fin.Sub(now).Round(time.Millisecond))
	s.publishFinished(b)
	return b, nil
}

type writeResult struct {
	size     int64
	sha256   string
	manifest *Manifest
}

// writeArchive snapshots the database and writes the archive to
// backups/<name> (via a hidden .partial file).
func (s *Service) writeArchive(ctx context.Context, hdr Header, name string, plan *encryptionPlan, h core.JobHandle) (*writeResult, error) {
	hm := s.env.Home
	// The database snapshot, keys/master.key and the sealed files under
	// certs/ only restore together, so no key rotation may run between them:
	// hold the key material until the last of them is in the archive (the
	// blobs that follow do not depend on it).
	releaseKeys := s.holdKeyMaterial()
	defer releaseKeys()
	// A full backup copies the blobs its snapshot lists, so data
	// re-encryption (which deletes the old blob of every file it
	// re-encrypts) pauses from before the snapshot until the last blob is in.
	releaseBlobs := func() {}
	if hdr.Scope == core.BackupFull {
		releaseBlobs = s.holdBlobs()
	}
	defer releaseBlobs()
	snap := filepath.Join(hm.TmpDir(""), "snapshot-"+hdr.BackupID+".db")
	if err := os.MkdirAll(filepath.Dir(snap), 0o700); err != nil {
		return nil, err
	}
	// VACUUM INTO writes a full copy of the live pages. Check for room before
	// it runs: on a nearly full disk it would otherwise fill the filesystem
	// under the live server (whose own writes then fail too) and end with
	// SQLite's "database or disk is full" instead of this message.
	if need := s.snapshotSize(ctx) + snapshotSlack; need > snapshotSlack {
		if free, ok := diskFree(filepath.Dir(snap)); ok && free < need {
			return nil, core.Errorf(core.ErrQuota, "not enough free disk space for the backup (needs about %s, %s free)",
				humanBytes(need), humanBytes(free))
		}
	}
	defer removeDB(snap)
	if h != nil {
		h.Progress(0, 0, "snapshotting the database")
	}
	if err := s.snapshot(ctx, snap); err != nil {
		return nil, fmt.Errorf("database snapshot: %w", err)
	}
	st, err := os.Stat(snap)
	if err != nil {
		return nil, err
	}
	dbSize := st.Size()
	snapKeys, err := snapshotKeyState(ctx, snap)
	if err != nil {
		return nil, fmt.Errorf("read the snapshot's key state: %w", err)
	}

	var blobs []blobRef
	var blobBytes int64
	if hdr.Scope == core.BackupFull {
		blobs, blobBytes, err = readyBlobs(ctx, snap)
		if err != nil {
			return nil, fmt.Errorf("list blobs: %w", err)
		}
	}
	hdr.MKID, hdr.DBSize, hdr.BlobBytes = snapKeys.mkID, dbSize, blobBytes
	need := dbSize + blobBytes + 64<<20
	if free, ok := diskFree(hm.BackupsDir()); ok && free < need {
		return nil, core.Errorf(core.ErrQuota, "not enough free disk space for the backup (needs about %s, %s free)",
			humanBytes(need), humanBytes(free))
	}

	final := filepath.Join(hm.BackupsDir(), name)
	partial := filepath.Join(hm.BackupsDir(), "."+name+".partial")
	f, err := os.OpenFile(partial, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return nil, err
	}
	ok := false
	defer func() {
		if !ok {
			f.Close()
			os.Remove(partial)
		}
	}()
	bw := bufio.NewWriterSize(f, 1<<20)
	aw, err := newArchiveWriter(ctx, bw, plan.recipients, hdr.CreatedAt, hm.TmpDir(""))
	if err != nil {
		return nil, err
	}
	defer func() {
		if !ok {
			aw.abort()
		}
	}()
	hb, _ := json.Marshal(hdr)
	if err := aw.addBytes(memberHeader, hb); err != nil {
		return nil, err
	}
	total := dbSize + blobBytes
	var done int64
	progress := func(n int64) {
		done += n
		if h != nil {
			h.Progress(done, total, "")
		}
	}
	if h != nil {
		h.Progress(0, total, "database")
	}
	if _, err := aw.addFile(memberDB, snap, progress); err != nil {
		return nil, fmt.Errorf("add database: %w", err)
	}
	if _, err := aw.addFile(memberConfig, hm.Config(), nil); err != nil {
		return nil, fmt.Errorf("add configuration: %w", err)
	}
	keyFiles, err := listKeyFiles(hm.KeysDir())
	if err != nil {
		return nil, err
	}
	for _, kf := range keyFiles {
		if _, err := aw.addFile(prefixKeys+kf, filepath.Join(hm.KeysDir(), kf), nil); err != nil {
			return nil, fmt.Errorf("add key file: %w", err)
		}
	}
	certFiles, err := listCertFiles(hm.CertsDir())
	if err != nil {
		return nil, err
	}
	for _, cf := range certFiles {
		if _, err := aw.addFile(prefixCerts+cf, filepath.Join(hm.CertsDir(), filepath.FromSlash(cf)), nil); err != nil {
			return nil, fmt.Errorf("add certificate file: %w", err)
		}
	}
	// Every member that belongs to the key material is in the archive now.
	// Belt and braces for a key service that does not support the hold
	// (HoldKeyMaterial is optional): make sure the live installation still
	// uses the keys the snapshot names, rather than writing an archive that
	// cannot be restored.
	liveKeys, err := liveKeyState(ctx, s.env.DB)
	if err != nil {
		return nil, fmt.Errorf("read the key state: %w", err)
	}
	if liveKeys != snapKeys {
		return nil, core.Errorf(core.ErrConflict,
			"the keys were rotated while the backup was being written; start the backup again")
	}
	releaseKeys()

	m := &Manifest{Header: hdr}
	m.Counts.DBSize = dbSize
	m.Counts.CertFiles = len(certFiles)
	if h != nil && len(blobs) > 0 {
		h.Progress(done, total, fmt.Sprintf("%d files", len(blobs)))
	}
	for _, b := range blobs {
		p := filepath.Join(hm.BlobsDir(), b.id[0:2], b.id[2:4], b.id)
		n, err := aw.addFile(blobMemberName(b.id), p, progress)
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				// Deleted after the snapshot (e.g. purged meanwhile).
				m.MissingBlobs = append(m.MissingBlobs, b.id)
				progress(b.size)
				continue
			}
			return nil, fmt.Errorf("add blob %s: %w", b.id, err)
		}
		m.Counts.Blobs++
		m.Counts.BlobBytes += n
	}
	releaseBlobs()
	if len(m.MissingBlobs) > 0 {
		s.log.Warn("backup: blobs deleted while the backup ran were skipped", "count", len(m.MissingBlobs))
	}
	size, sum, err := aw.finish(m)
	if err != nil {
		return nil, err
	}
	if err := bw.Flush(); err != nil {
		return nil, err
	}
	if err := f.Sync(); err != nil {
		return nil, err
	}
	if err := f.Close(); err != nil {
		return nil, err
	}
	if err := os.Rename(partial, final); err != nil {
		os.Remove(partial)
		return nil, err
	}
	ok = true
	syncDir(hm.BackupsDir())
	return &writeResult{size: size, sha256: sum, manifest: m}, nil
}

// snapshot writes a consistent copy of the live database to path with
// VACUUM INTO, on a private connection opened for it and closed afterwards
// (as db.IntegrityCheck does). Neither the single writer nor a connection of
// the reader pool is held while the copy is written: the pool is sized by
// GOMAXPROCS, so on a one-CPU host it is a single connection, and every
// request (session lookups, /readyz, the watchdog's health check) would
// otherwise wait for the whole snapshot.
func (s *Service) snapshot(ctx context.Context, path string) error {
	removeDB(path)
	// The live database path, as db.Open uses it (it holds no '?').
	c, err := sql.Open("sqlite", s.env.DB.Path()+"?_pragma=busy_timeout(10000)")
	if err != nil {
		return err
	}
	defer c.Close()
	c.SetMaxOpenConns(1)
	if _, err := c.ExecContext(ctx, `VACUUM INTO ?`, path); err != nil {
		return err
	}
	return os.Chmod(path, 0o600)
}

// snapshotSlack is the head room the free-space check before a database
// snapshot keeps on top of its estimated size (a variable so tests can raise it).
var snapshotSlack int64 = 64 << 20

// snapshotSize estimates what a snapshot of the live database writes: the
// pages in use (VACUUM INTO drops the free ones), as the committed state
// including the WAL shows them. When that cannot be read, the size of the
// database file and its WAL is an upper bound; 0 means unknown.
func (s *Service) snapshotSize(ctx context.Context) int64 {
	var n int64
	err := s.env.DB.Reader().QueryRowContext(ctx, `SELECT (c.page_count - f.freelist_count) * p.page_size
		FROM pragma_page_count() c, pragma_freelist_count() f, pragma_page_size() p`).Scan(&n)
	if err == nil && n > 0 {
		return n
	}
	n = 0
	for _, suf := range []string{"", "-wal"} {
		if st, err := os.Stat(s.env.Home.DB() + suf); err == nil {
			n += st.Size()
		}
	}
	return n
}

// keyState identifies the key material a database belongs to: the master
// key (meta.mk_id) and the field KEK that seals the key files under certs/.
type keyState struct {
	mkID, fieldKEK string
}

// snapshotKeyState reads the key state of a snapshot database.
func snapshotKeyState(ctx context.Context, snapPath string) (keyState, error) {
	sdb, err := openReadOnly(snapPath)
	if err != nil {
		return keyState{}, err
	}
	defer sdb.Close()
	return scanKeyState(func(q string, args ...any) *sql.Row { return sdb.QueryRowContext(ctx, q, args...) })
}

// liveKeyState reads the key state of the running installation.
func liveKeyState(ctx context.Context, d *db.DB) (keyState, error) {
	return scanKeyState(func(q string, args ...any) *sql.Row { return d.QueryRow(ctx, q, args...) })
}

func scanKeyState(row func(string, ...any) *sql.Row) (keyState, error) {
	var ks keyState
	err := row(`SELECT value FROM meta WHERE key = 'mk_id'`).Scan(&ks.mkID)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return ks, err
	}
	err = row(`SELECT id FROM keyring WHERE purpose = ? AND state = 'active'`, core.KEKField).Scan(&ks.fieldKEK)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return ks, err
	}
	return ks, nil
}

// keyMaterialHolder is implemented by *keys.Service: it blocks key
// rotations while an archive copies the key files (see keys.HoldKeyMaterial).
type keyMaterialHolder interface{ HoldKeyMaterial() func() }

// holdKeyMaterial blocks key rotations until the returned func is called
// (calling it twice is harmless).
func (s *Service) holdKeyMaterial() func() {
	if k, ok := s.env.Keys.(keyMaterialHolder); ok {
		return k.HoldKeyMaterial()
	}
	return func() {}
}

// blobHolder is implemented by *keys.Service: it pauses data re-encryption
// while a full backup copies the blobs (see keys.HoldBlobs).
type blobHolder interface{ HoldBlobs() func() }

// holdBlobs pauses data re-encryption until the returned func is called
// (calling it twice is harmless).
func (s *Service) holdBlobs() func() {
	if k, ok := s.env.Keys.(blobHolder); ok {
		return k.HoldBlobs()
	}
	return func() {}
}

type blobRef struct {
	id   string
	size int64
}

// readyBlobs lists the ready blobs of a snapshot database (opened read-only).
func readyBlobs(ctx context.Context, snapPath string) ([]blobRef, int64, error) {
	sdb, err := openReadOnly(snapPath)
	if err != nil {
		return nil, 0, err
	}
	defer sdb.Close()
	rows, err := sdb.QueryContext(ctx, `SELECT id, coalesce(stored_size, 0) FROM blobs WHERE state = 'ready' ORDER BY id`)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	var out []blobRef
	var total int64
	for rows.Next() {
		var b blobRef
		if err := rows.Scan(&b.id, &b.size); err != nil {
			return nil, 0, err
		}
		if !ids.ValidBlobID(b.id) {
			continue
		}
		out = append(out, b)
		total += b.size
	}
	return out, total, rows.Err()
}

// openReadOnly opens a SQLite file read-only and immutable (no journal, no
// locks): only for private snapshot copies. The path is escaped into the URI:
// SQLite would otherwise read a '#' in the home path as a fragment and
// decode a '%41' in it as another byte.
func openReadOnly(path string) (*sql.DB, error) {
	u := url.URL{Scheme: "file", Path: filepath.ToSlash(path), RawQuery: "mode=ro&immutable=1"}
	d, err := sql.Open("sqlite", u.String())
	if err != nil {
		return nil, err
	}
	d.SetMaxOpenConns(1)
	if err := d.PingContext(context.Background()); err != nil {
		d.Close()
		return nil, err
	}
	return d, nil
}

// removeDB removes a SQLite file and its -wal/-shm/-journal companions.
func removeDB(path string) {
	for _, suf := range []string{"", "-wal", "-shm", "-journal"} {
		_ = os.Remove(path + suf)
	}
}

// listKeyFiles returns the key files to back up (master.key and a pending
// master.key.next).
func listKeyFiles(dir string) ([]string, error) {
	var out []string
	for _, n := range []string{"master.key", "master.key.next"} {
		st, err := os.Lstat(filepath.Join(dir, n))
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err != nil {
			return nil, err
		}
		if st.Mode().IsRegular() {
			out = append(out, n)
		}
	}
	if !slices.Contains(out, "master.key") {
		return nil, core.Errorf(core.ErrUnavailable, "the master key file is missing (keys/master.key); initialise the server first")
	}
	return out, nil
}

// listCertFiles returns every regular file below certs/ (slash-separated,
// relative, sorted); symlinks and names outside the archive rules are skipped.
func listCertFiles(dir string) ([]string, error) {
	var out []string
	err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				return nil
			}
			return err
		}
		if !d.Type().IsRegular() {
			return nil
		}
		rel, err := filepath.Rel(dir, p)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		if classify(prefixCerts+rel) != kindCert {
			return nil
		}
		out = append(out, rel)
		return nil
	})
	if err != nil {
		return nil, err
	}
	slices.Sort(out)
	return out, nil
}

// copyTo copies a finished backup into dir (write to a hidden temp file,
// fsync, rename). It returns the destination path.
func (s *Service) copyTo(ctx context.Context, src, dir, name string) (string, error) {
	if s.insideHome(dir) {
		// A value stored before the rule, or set through the generic
		// settings route: the copy would be no second copy (the same file,
		// for the backups folder itself).
		return "", errCopyToInsideHome
	}
	st, err := os.Stat(dir)
	if err != nil {
		return "", err
	}
	if !st.IsDir() {
		return "", fmt.Errorf("%s is not a directory", dir)
	}
	in, err := os.Open(src)
	if err != nil {
		return "", err
	}
	defer in.Close()
	dst := filepath.Join(dir, name)
	// dir belongs to the admin (a NAS mount, a USB disk); its contents are
	// not ours. Work through an os.Root so no step follows a symlink, drop a
	// stale partial by name (nothing sweeps this directory), and create the
	// file exclusively with an explicit mode, so the mode of the finished
	// copy never depends on what was already at that path.
	root, err := os.OpenRoot(dir)
	if err != nil {
		return "", err
	}
	defer root.Close()
	tmp := "." + name + ".partial"
	_ = root.Remove(tmp) // removes a stale partial or a planted symlink, never follows it
	out, err := root.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return "", err
	}
	if err := out.Chmod(0o600); err != nil {
		out.Close()
		root.Remove(tmp)
		return "", err
	}
	if _, err := io.Copy(ctxWriter{ctx, out}, in); err != nil {
		out.Close()
		root.Remove(tmp)
		return "", err
	}
	if err := out.Sync(); err != nil {
		out.Close()
		root.Remove(tmp)
		return "", err
	}
	if err := out.Close(); err != nil {
		root.Remove(tmp)
		return "", err
	}
	if err := root.Rename(tmp, name); err != nil {
		root.Remove(tmp)
		return "", err
	}
	syncDir(dir)
	return dst, nil
}

// errorMessage returns a user-facing message for err.
func errorMessage(err error) string {
	msg := err.Error()
	if ce := core.AsError(err); ce != nil && ce.Message != "" {
		msg = ce.Message
	}
	return truncate(msg, 1000)
}

func humanBytes(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(unit), 0
	for m := n / unit; m >= unit; m /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(n)/float64(div), "KMGTPE"[exp])
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
