package backup

import (
	"bufio"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"fileparcel/internal/core"
	"fileparcel/internal/db"
	"fileparcel/internal/ids"
)

// Import implements core.Backups: streams an uploaded backup file into
// backups/ (checking the age header first), reads the archive header when
// the configured identity/passphrase can decrypt it, and registers it
// (trigger "import"). Backups made by a newer FileParcel are rejected, and so
// are files the configured secrets decrypt but that are damaged or not a
// FileParcel archive. Imports that cannot be decrypted with the configured
// secrets are still registered (scope "full" assumed); restore them with
// explicit credentials.
func (s *Service) Import(ctx context.Context, by *core.Principal, r io.Reader) (*core.Backup, error) {
	hm := s.env.Home
	if err := os.MkdirAll(hm.BackupsDir(), 0o700); err != nil {
		return nil, err
	}
	br := bufio.NewReaderSize(r, 64<<10)
	magic, err := br.Peek(len(ageMagic))
	if err != nil || string(magic) != ageMagic {
		return nil, core.Invalid("file", "not a FileParcel backup (an age-encrypted .fpbak file is expected)")
	}
	id := ids.New(ids.PrefixBackup)
	partial := filepath.Join(hm.BackupsDir(), ".import-"+id+".partial")
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
	h := sha256.New()
	guard := &spaceGuard{dir: hm.BackupsDir()}
	size, err := io.Copy(io.MultiWriter(guard, f, h), ctxReader{ctx, br})
	if err != nil {
		if ce := core.AsError(err); ce != nil {
			return nil, err
		}
		return nil, fmt.Errorf("backup: import: %w", err)
	}
	if err := f.Sync(); err != nil {
		return nil, err
	}
	if err := f.Close(); err != nil {
		return nil, err
	}
	sum := hex.EncodeToString(h.Sum(nil))

	rf, err := os.Open(partial)
	if err != nil {
		return nil, err
	}
	hi, err := readAgeHeader(rf)
	rf.Close()
	if err != nil {
		return nil, err
	}

	now := s.env.Now()
	scope, appVersion, schema, createdAt := core.BackupFull, "", 0, now
	inst := "import"
	note := "imported"
	if idents, err := s.configuredIdentities(); err == nil {
		if hdr, err := checkHeaderIdents(ctx, partial, idents); err == nil {
			if latest := db.LatestVersion(); hdr.SchemaVersion > latest {
				return nil, core.Errorf(core.ErrInvalid, "the backup was made by a newer FileParcel (schema %d, this version supports %d)",
					hdr.SchemaVersion, latest)
			}
			scope, appVersion, schema, createdAt = hdr.Scope, hdr.AppVersion, hdr.SchemaVersion, hdr.CreatedAt
			inst = install8(hdr.InstallID)
			if hdr.InstallID != "" && hdr.InstallID != s.installID() {
				note = "imported from another installation (" + inst + ")"
			}
		} else if ce := core.AsError(err); ce != nil && ce.Code == core.ErrForbidden.Code {
			// Encrypted for someone else: other credentials may decrypt it.
			note = "imported; not decryptable with the configured identity or passphrase (provide credentials to restore)"
		} else if ce != nil && ce.Code == core.ErrCorrupt.Code {
			// The configured secrets decrypted it, but what is inside is
			// damaged or not a FileParcel archive: no credentials would
			// make it restorable, so it is not registered as one.
			return nil, core.Invalid("file", "the file is not a usable FileParcel backup ("+errorMessage(err)+")")
		} else {
			return nil, err // a newer format, a canceled request, an I/O error
		}
	} else {
		note = "imported; no identity or passphrase is configured to check it"
	}
	// Two imports of the same archive (or a backup made meanwhile) compute
	// the same name: choosing a free one and claiming it (the file appears
	// under it; a backup claims its name with its row) must not interleave,
	// or both would pick the same name and the second rename would silently
	// replace the first file, leaving two rows for one file.
	s.nameMu.Lock()
	name, err := s.uniqueFileName(ctx, inst, createdAt, scope)
	final := filepath.Join(hm.BackupsDir(), name)
	if err == nil {
		err = os.Rename(partial, final)
	}
	s.nameMu.Unlock()
	if err != nil {
		return nil, err
	}
	ok = true
	syncDir(hm.BackupsDir())

	var byID string
	if by != nil {
		byID = by.UserID
		ctx = core.WithPrincipal(ctx, by)
	}
	err = s.env.DB.Tx(ctx, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, `INSERT INTO backups (id, scope, state, file_name, size, sha256, encryption,
			app_version, schema_version, note, "trigger", created_by, created_at, finished_at)
			VALUES (?, ?, 'ready', ?, ?, ?, ?, ?, ?, ?, 'import', ?, ?, ?)`,
			id, scope, name, size, sum, hi.encryption(), db.NullString(appVersion), schema, note,
			db.NullString(byID), db.Ms(createdAt), db.Ms(now)); err != nil {
			return err
		}
		if s.env.Audit != nil {
			return s.env.Audit.RecordTx(ctx, tx, core.AuditEntry{Action: core.ActBackupImport, TargetType: "backup",
				TargetID: id, TargetName: name, Details: map[string]any{"size": size, "scope": scope}})
		}
		return nil
	})
	if err != nil {
		os.Remove(final)
		return nil, fmt.Errorf("backup: import: %w", err)
	}
	s.log.Info("backup imported", "backup", id, "file", name, "size", size)
	return s.Get(ctx, id)
}

// checkHeaderIdents reads the archive header of path with identities.
func checkHeaderIdents(ctx context.Context, path string, idents []ageIdentity) (*Header, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var hdr Header
	_, err = walkArchive(ctx, f, idents, func(h Header) error { hdr = h; return errStopWalk }, nil)
	if err != nil {
		return nil, err
	}
	return &hdr, nil
}

// Import disk-space guard: the upload is aborted when less than
// importMinFree bytes would remain free (checked every importCheckEvery bytes).
var (
	importMinFree    int64 = 256 << 20
	importCheckEvery int64 = 64 << 20
)

// spaceGuard fails writes once the filesystem of dir runs low on space.
type spaceGuard struct {
	dir       string
	sinceLast int64
	checked   bool
}

func (g *spaceGuard) Write(p []byte) (int, error) {
	g.sinceLast += int64(len(p))
	if !g.checked || g.sinceLast >= importCheckEvery {
		g.checked, g.sinceLast = true, 0
		if free, ok := diskFree(g.dir); ok && free-int64(len(p)) < importMinFree {
			return 0, core.Errorf(core.ErrQuota, "not enough free disk space to import the backup (%s free)", humanBytes(free))
		}
	}
	return len(p), nil
}
