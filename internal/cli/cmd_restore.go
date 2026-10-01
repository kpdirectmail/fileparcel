package cli

import (
	"bufio"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"fileparcel/internal/backup"
	"fileparcel/internal/core"
	"fileparcel/internal/home"
	"fileparcel/internal/ids"
	"fileparcel/internal/server"
	"fileparcel/internal/svc"
)

// restoreResult is the --json output of backup restore.
type restoreResult struct {
	File         string          `json:"file"`
	DryRun       bool            `json:"dry_run"`
	MetadataOnly bool            `json:"metadata_only"`
	Report       json.RawMessage `json:"report,omitempty"` // backup.RestoreReport when available
}

// restoreReporter is implemented by the backup service (RestoreOffline with
// a summary of what was restored).
type restoreReporter interface {
	RestoreOfflineReport(ctx context.Context, file string, c core.RestoreCreds, o core.RestoreOpts) (*backup.RestoreReport, error)
}

// restoreReportField returns a top-level string field of a JSON report.
func restoreReportField(raw json.RawMessage, key string) string {
	var m map[string]any
	if len(raw) == 0 || json.Unmarshal(raw, &m) != nil {
		return ""
	}
	s, _ := m[key].(string)
	return s
}

// newRestoreCmd is "backup restore" (and the hidden legacy copy "restore",
// legacy.go).
func newRestoreCmd() *cobra.Command {
	var identityFile, pwFile string
	var pwStdin, identityStdin bool
	var opts core.RestoreOpts
	cmd := &cobra.Command{
		Use:   "restore <backup>",
		Short: "Restore a backup (stop the server first)",
		Long: `Replaces everything in this installation (database, files, keys, settings)
with the backup. Stop the server first ("fileparcel service stop"); the old
data is moved to <HOME>/pre-restore-<date>/. The restore runs in this process;
start the server again afterwards. It asks before replacing anything; -y skips
the question.

The archive is a backup id (bak_…, from <HOME>/backups) or a path to a .fpbak
file. Decryption uses --identity-file FILE (an age identity file: every
AGE-SECRET-KEY-… line in it is tried, so the file "backup identity generate"
prints also opens backups made with the identities it lists as previous),
--identity-stdin, --passphrase-stdin/--passphrase-file (passphrase mode), or
by default the identity/passphrase stored in the backup settings. When the
identity or passphrase is read from stdin, stdin cannot answer the
confirmation: pass -y.

When the current installation cannot be opened at all (a damaged database or
master key, or a database already migrated by a newer version), the restore
still works, but the stored identity cannot be read then: pass
--identity-file (or a passphrase flag), and the archive's path if its id
cannot be looked up.

--dry-run decrypts and checks the archive without changing anything.
--metadata-only keeps the current file data, but still restores the database,
the keys, the certificates and fileparcel.toml: the restored database refers to
the backup's keyring, so the keys must come with it. The replaced items are
moved to <HOME>/pre-restore-<date>/ like in a full restore.`,
		Example: `  fileparcel service stop && fileparcel backup restore bak_01j9zq3x4k6m8p0r2t4v6x8z0b -y && fileparcel service start
  fileparcel backup restore /mnt/usb/fp-5f0c81d2-20260919-040000-full.fpbak --identity-file ~/backup-identity.txt --dry-run
  fileparcel backup restore old.fpbak --passphrase-stdin -y < /secure/backup.pass`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if G.Server != "" {
				return UsageError("restore works only on the server host (it cannot be run with --server)")
			}
			var creds core.RestoreCreds
			switch n := countTrue(identityFile != "", identityStdin, pwStdin, pwFile != ""); {
			case n > 1:
				return UsageError("use only one of --identity-file, --identity-stdin, --passphrase-stdin and --passphrase-file")
			case identityFile != "":
				id, err := readAgeIdentity(identityFile)
				if err != nil {
					return err
				}
				creds.Identity = id
			case identityStdin:
				id, err := parseAgeIdentity(cmd.InOrStdin(), "stdin")
				if err != nil {
					return err
				}
				creds.Identity = id
			case pwStdin || pwFile != "":
				pw, err := secretFrom(cmd, pwStdin, pwFile, "passphrase", false)
				if err != nil {
					return err
				}
				creds.Passphrase = pw
			}
			h, err := home.Resolve(G.Home)
			if err != nil {
				return err
			}
			if serverRunning(h) {
				return errors.New(`the server is running; stop it first ("fileparcel service stop"), then run the restore again` +
					"\n  hint: while the server runs, a restore can be scheduled from the web UI (Admin → Backups), which restarts the server")
			}
			// Do not ask for a confirmation of a restore that cannot run
			// (the lock is checked again when it is taken).
			if h.Exists() && lcHomeBusy(h) {
				return restoreBusyError(h)
			}
			ref := args[0]
			if !ids.Valid(ids.PrefixBackup, ref) {
				abs, err := filepath.Abs(ref)
				if err != nil {
					return err
				}
				fi, err := os.Stat(abs)
				switch {
				case errors.Is(err, os.ErrNotExist) && strings.HasPrefix(ref, ids.PrefixBackup+"_"):
					// Not a valid id, and no such file either: a mistyped id.
					return &hintError{core.NotFoundf("no backup with id %s", ref), `list them with "fileparcel backup list"`}
				case errors.Is(err, os.ErrNotExist):
					return &hintError{fmt.Errorf("%s: no such file", ref),
						`give a backup id (bak_…, see "fileparcel backup list") or the path of a .fpbak file`}
				case err != nil:
					return fmt.Errorf("%s: %w", ref, err)
				}
				if !fi.Mode().IsRegular() {
					return fmt.Errorf("%s is not a regular file", ref)
				}
				ref = abs
			}
			if !opts.DryRun {
				what := "ALL current data (database, files, settings)"
				if opts.MetadataOnly {
					what = "the database (users, folders, shares, settings)"
				}
				if err := confirmOrAbort(cmd, fmt.Sprintf("Restore %s? This replaces %s in %s.", args[0], what, h.Dir())); err != nil {
					return err
				}
			}
			ctx := cmdContext(cmd)
			o := G.ConnectOptions()
			o.Offline = true
			c, err := Connect(o)
			if err != nil {
				return restoreWithoutServices(ctx, cmd, h, ref, creds, opts, err)
			}
			defer c.Close()
			d := c.Deps()
			if d == nil || d.Backups == nil {
				return errors.New("the backup service is not available in-process")
			}
			// A backup id is passed through as is: the backup service then
			// also checks the archive against its recorded SHA-256.
			file := ref
			if ids.Valid(ids.PrefixBackup, ref) {
				b, err := d.Backups.Get(ctx, ref)
				if err != nil {
					return err
				}
				if b.State != core.BackupReady {
					return fmt.Errorf("backup %s is %s, not ready", b.ID, b.State)
				}
				file = filepath.Join(h.BackupsDir(), b.FileName)
			}
			start := restoreStarting(cmd, file, opts)
			res := restoreResult{File: file, DryRun: opts.DryRun, MetadataOnly: opts.MetadataOnly}
			if rr, ok := d.Backups.(restoreReporter); ok {
				rep, err := rr.RestoreOfflineReport(ctx, ref, creds, opts)
				if err != nil {
					return archiveError(err)
				}
				if raw, err := json.Marshal(rep); err == nil && string(raw) != "null" {
					res.Report = raw
				}
			} else if err := d.Backups.RestoreOffline(ctx, ref, creds, opts); err != nil {
				return archiveError(err)
			}
			return restorePrint(cmd, h, res, start)
		},
	}
	f := cmd.Flags()
	f.StringVar(&identityFile, "identity-file", "", "age identity file (AGE-SECRET-KEY-…) for x25519 backups")
	f.BoolVar(&identityStdin, "identity-stdin", false, "read the age identity from stdin")
	f.BoolVar(&pwStdin, "passphrase-stdin", false, "read the backup passphrase from stdin (passphrase mode)")
	f.StringVar(&pwFile, "passphrase-file", "", "read the backup passphrase from a file (passphrase mode)")
	f.BoolVar(&opts.MetadataOnly, "metadata-only", false, "restore the database, keys, certificates and configuration; keep the current file blobs")
	f.BoolVar(&opts.DryRun, "dry-run", false, "decrypt and check the archive without changing anything")
	return cmd
}

func countTrue(bs ...bool) int {
	n := 0
	for _, b := range bs {
		if b {
			n++
		}
	}
	return n
}

// restoreStarting announces the restore of file and returns its start time.
func restoreStarting(cmd *cobra.Command, file string, opts core.RestoreOpts) time.Time {
	if opts.DryRun {
		Infof(cmd, "Checking %s (dry run)…", file)
	} else {
		Infof(cmd, "Restoring %s…", file)
	}
	return time.Now()
}

// restorePrint prints the outcome of a restore (JSON: res).
func restorePrint(cmd *cobra.Command, h *home.Home, res restoreResult, start time.Time) error {
	return Print(cmd, res, func(w io.Writer) error {
		if res.DryRun {
			Successf(cmd, "the backup can be restored (checked in %s; nothing was changed)", HumanDuration(time.Since(start)))
			return nil
		}
		Successf(cmd, "restored %s in %s", filepath.Base(res.File), HumanDuration(time.Since(start)))
		if pre := restoreReportField(res.Report, "pre_restore"); pre != "" {
			Infof(cmd, "The previous data was moved to %s (delete it once the restored server works).", pre)
		}
		Infof(cmd, "Start the server again: %s", startCommand(h))
		return nil
	})
}

// startCommand is how to start the server of h: its registered service,
// else "fileparcel serve".
func startCommand(h *home.Home) string {
	if rec, err := svc.ReadInstalled(h); err == nil && rec != nil && rec.Kind != "" && rec.Kind != svc.KindNone {
		return "fileparcel service start"
	}
	return "fileparcel serve"
}

// archiveError explains a restore that failed on the archive itself: a
// damaged, truncated or foreign file is not the installation's stored data,
// so the generic advice for ErrCorrupt (run doctor, restore a backup) does
// not apply.
func archiveError(err error) error {
	if errors.Is(err, core.ErrCorrupt) {
		return &hintError{err, "the archive itself is at fault (damaged, incomplete or not a FileParcel backup), not this installation; " +
			"nothing was changed: try another copy of the backup"}
	}
	return err
}

// restoreBusyError is the error of a restore while another process holds
// the home lock: restore always works offline, so the generic "omit
// --offline" advice of Connect does not apply.
func restoreBusyError(h *home.Home) error {
	return fmt.Errorf("the home %s is in use by another FileParcel process (the server, or a command running offline); "+
		"stop the server (\"fileparcel service stop\") or wait for that command to finish, then run the restore again", h.Dir())
}

// restoreWithoutServices restores ref when the services of the current
// installation cannot be built (cause: a damaged database or master key, a
// database migrated by a newer version …). The restore itself needs none of
// them — it replaces data/, keys/, certs/ and fileparcel.toml — but the
// configured identity lives in that database, so explicit credentials are
// required, and a backup id is looked up read-only (no migration). The WAL
// checkpoint and the audit entries of the normal path are skipped: the whole
// data/ directory, -wal and -shm included, is moved to pre-restore-<ts>/.
func restoreWithoutServices(ctx context.Context, cmd *cobra.Command, h *home.Home, ref string, creds core.RestoreCreds,
	opts core.RestoreOpts, cause error) error {
	if !h.Exists() {
		return cause
	}
	unlock, err := lockHome(h) // as root: gives the restored files to the home's account
	if err != nil {
		if errors.Is(err, home.ErrLocked) {
			return restoreBusyError(h)
		}
		return err
	}
	defer unlock()
	if creds.Identity == "" && creds.Passphrase == "" {
		return UsageError("the current installation cannot be opened (%v), so the backup identity stored in it cannot be read "+
			"either; pass --identity-file FILE (or --identity-stdin, --passphrase-file, --passphrase-stdin) to restore without it", cause)
	}
	Warnf(cmd, "the current installation cannot be opened (%v); restoring without it", cause)
	file, expect := ref, ""
	if ids.Valid(ids.PrefixBackup, ref) {
		if file, expect, err = restoreBackupFile(ctx, h, ref); err != nil {
			return fmt.Errorf("%w; pass the path of the archive instead (%s)", err,
				filepath.Join(h.BackupsDir(), "<file>.fpbak"))
		}
	}
	start := restoreStarting(cmd, file, opts)
	rep, err := backup.RestoreHome(ctx, h, file, creds, opts, expect, nil)
	if err != nil {
		return archiveError(err)
	}
	res := restoreResult{File: file, DryRun: opts.DryRun, MetadataOnly: opts.MetadataOnly}
	if raw, err := json.Marshal(rep); err == nil && string(raw) != "null" {
		res.Report = raw
	}
	return restorePrint(cmd, h, res, start)
}

// restoreBackupFile resolves backup id to its archive in <HOME>/backups and
// the recorded SHA-256, reading the database read-only (never migrating it).
func restoreBackupFile(ctx context.Context, h *home.Home, id string) (path, sha string, err error) {
	q, err := sql.Open("sqlite", readOnlyDSN(h.DB()))
	if err != nil {
		return "", "", err
	}
	defer q.Close()
	var name, state string
	var sum sql.NullString
	err = q.QueryRowContext(ctx, `SELECT file_name, state, sha256 FROM backups WHERE id = ?`, id).Scan(&name, &state, &sum)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return "", "", fmt.Errorf("backup %s not found", id)
	case err != nil:
		return "", "", fmt.Errorf("cannot look up backup %s: %w", id, err)
	case state != core.BackupReady:
		return "", "", fmt.Errorf("backup %s is %s, not ready", id, state)
	case name == "" || name[0] == '.' || filepath.Base(name) != name || !strings.HasSuffix(name, ".fpbak"):
		return "", "", fmt.Errorf("backup %s has an invalid file name", id)
	}
	return filepath.Join(h.BackupsDir(), name), sum.String, nil
}

// serverRunning reports whether a server answers on the admin socket (with
// the dialer of connectSocket, which handles socket paths beyond the
// sun_path limit).
func serverRunning(h *home.Home) bool {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	conn, err := server.DialSocket(ctx, h.Socket())
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

// readAgeIdentity reads the AGE-SECRET-KEY-… lines of an identity file.
func readAgeIdentity(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	return parseAgeIdentity(f, path)
}

// parseAgeIdentity returns every age identity line in r, one per line
// (comments and blank lines are skipped, as in age identity files). All of
// them are tried: the file "backup identity generate" prints lists the
// previous identities after the new one, for older backups.
func parseAgeIdentity(r io.Reader, name string) (string, error) {
	sc := bufio.NewScanner(io.LimitReader(r, 1<<20))
	var ids []string
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if strings.HasPrefix(line, "AGE-SECRET-KEY-") {
			ids = append(ids, line)
		}
	}
	if err := sc.Err(); err != nil {
		return "", err
	}
	if len(ids) == 0 {
		return "", fmt.Errorf("%s: no age identity (AGE-SECRET-KEY-…) found", name)
	}
	return strings.Join(ids, "\n"), nil
}
