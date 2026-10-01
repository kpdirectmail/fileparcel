package cli

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"fileparcel/internal/cli/clikit"
	"fileparcel/internal/core"
	"fileparcel/internal/ids"
)

func init() { Register(newBackupCmd) }

func newBackupCmd() *cobra.Command {
	cmd := groupCmd("backup", "Back up, verify and restore your data",
		`A backup is one encrypted archive of the database, the settings, the master
key, the certificates and (scope "full", the default) every stored file, kept
in <HOME>/backups. Automatic backups run on a schedule and old ones are
deleted by the retention rules. Backups are encrypted to a public key, so
restoring needs its secret identity (or the passphrase in passphrase mode):
keep that somewhere safe, away from the server.

Restore with "fileparcel backup restore" while the server is stopped.`,
		`  fileparcel backup create --wait
  fileparcel backup list
  fileparcel backup verify bak_01j9zq3x4k6m8p0r2t4v6x8z0b --deep
  fileparcel backup restore bak_01j9zq3x4k6m8p0r2t4v6x8z0b`, "backups")
	cmd.AddCommand(newBackupCreateCmd(), newBackupListCmd(), newBackupShowCmd(), newBackupVerifyCmd(), newRestoreCmd(),
		newBackupPruneCmd(), newBackupDeleteCmd(), newBackupScheduleCmd(), newBackupIdentityCmd(), newBackupExportCmd(),
		newBackupImportCmd(), newBackupConfigCmd())
	setListHint(cmd, "fileparcel backup list")
	return cmd
}

func renderBackups(w io.Writer, list []core.Backup) error {
	// A ready backup can still carry an error (a failed copy to
	// backup.copy_to, for instance); show it rather than let the table say
	// "ready" and nothing else.
	errs := slices.ContainsFunc(list, func(b core.Backup) bool { return b.Error != "" })
	headers := []string{"ID", "CREATED", "SCOPE", "STATE", "SIZE", "TRIGGER", "VERIFIED", "NOTE"}
	if errs {
		headers = append(headers, "ERROR")
	}
	t := NewTable(headers...)
	for _, b := range list {
		ver := ""
		if b.VerifyOK != nil {
			ver = "ok"
			if !*b.VerifyOK {
				ver = "FAILED"
			}
			if b.VerifiedAt != nil {
				ver += " " + HumanTime(*b.VerifiedAt)
			}
		}
		row := []any{b.ID, b.CreatedAt, b.Scope, b.State, HumanBytes(b.Size), b.Trigger, ver, Truncate(b.Note, 30)}
		if errs {
			row = append(row, Truncate(b.Error, 40))
		}
		t.Add(row...)
	}
	return t.Render(w)
}

func renderBackup(w io.Writer, b *core.Backup) error {
	kv := NewKV()
	kv.Add("ID", b.ID)
	kv.Add("State", b.State)
	kv.Add("Scope", b.Scope)
	kv.Add("Trigger", b.Trigger)
	kv.Add("File", b.FileName)
	kv.Add("Size", HumanBytes(b.Size))
	kv.Add("SHA-256", b.SHA256)
	kv.Add("Encryption", b.Encryption)
	kv.Add("Recipients", strings.Join(b.Recipients, ", "))
	kv.Add("Blobs", fmt.Sprintf("%d (%s)", b.BlobCount, HumanBytes(b.BlobBytes)))
	kv.Add("Database", HumanBytes(b.DBSize))
	kv.Add("App version", b.AppVersion)
	kv.Add("Schema version", b.SchemaVersion)
	kv.Add("Note", b.Note)
	kv.Add("Created", b.CreatedAt)
	kv.Add("Finished", b.FinishedAt)
	if b.VerifyOK != nil {
		kv.Add("Verified", fmt.Sprintf("%s (%s)", YesNo(*b.VerifyOK), HumanTimePtr(b.VerifiedAt)))
	}
	kv.Add("Copied to", b.CopiedTo)
	kv.Add("Error", b.Error)
	return kv.Render(w)
}

// getBackup fetches one backup.
func getBackup(ctx context.Context, c *Client, id string) (*core.Backup, error) {
	if !ids.Valid(ids.PrefixBackup, id) {
		return nil, UsageError("%q is not a backup id (bak_…; see \"fileparcel backup list\")", id)
	}
	var b core.Backup
	if err := c.Do(ctx, http.MethodGet, api("/admin/backups/"+pathEsc(id)), nil, &b); err != nil {
		return nil, err
	}
	return &b, nil
}

// backupOfJob finds the backup created by a finished backup.create job.
func backupOfJob(ctx context.Context, c *Client, j *core.Job) (*core.Backup, error) {
	if id := jobResultBackupID(j.Result); id != "" {
		return getBackup(ctx, c, id)
	}
	list, err := listAll[core.Backup](ctx, c, api("/admin/backups", "limit", "50"), 50)
	if err != nil {
		return nil, err
	}
	for i := range list {
		if list[i].JobID == j.ID {
			return &list[i], nil
		}
	}
	return nil, fmt.Errorf("job %s finished but its backup was not found", j.ID)
}

// ---------- create ----------

func newBackupCreateCmd() *cobra.Command {
	var in core.BackupInput
	var out string
	var force bool
	var wait *waitFlags
	cmd := &cobra.Command{
		Use:   "create",
		Short: "Create a backup now",
		Long: `Start a backup. Every backup holds the database, fileparcel.toml,
keys/master.key and certs/. Scope "full" (default) also includes every stored
file; "metadata" leaves the file contents out (small and fast; files are not
recoverable from it, but it does contain the master key).

By default the command returns once the backup job is queued; --wait follows it
to the end. -o/--output PATH also copies the finished archive to PATH (a file
or an existing directory; "-" writes it to standard output and nothing else),
which implies --wait. An existing file is only replaced with --force; this is
checked before the backup starts. When the server is stopped the backup runs
in-process and the command waits for it.`,
		Example: `  fileparcel backup create --wait
  fileparcel backup create --scope metadata --note "before upgrade" --wait
  fileparcel backup create -o /mnt/usb/
  fileparcel backup create -o - | ssh backup-host 'cat > fp.fpbak'`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			switch in.Scope {
			case core.BackupFull, core.BackupMetadata:
			default:
				return UsageError("invalid --scope %q (full or metadata)", in.Scope)
			}
			if out != "" && !wait.Wait() && wait.Explicit() {
				return UsageError("--output needs the finished backup; drop --no-wait")
			}
			if out == "-" && G.JSON {
				return UsageError("--output - writes the archive to standard output and cannot be combined with --json")
			}
			// Refuse a destination that cannot be written before the backup
			// runs (a full backup can take hours), not after it.
			if err := checkBackupOut(out, force); err != nil {
				return err
			}
			return WithClient(cmd, func(ctx context.Context, c *Client) error {
				var b *core.Backup
				if c.Mode() == ModeOffline {
					d := c.Deps()
					if d == nil || d.Backups == nil {
						return errors.New("backups are not available in offline mode")
					}
					Infof(cmd, "The server is not running; creating the backup in-process…")
					var err error
					if b, err = d.Backups.CreateSync(ctx, core.SystemPrincipal(core.ViaOffline), in); err != nil {
						return err
					}
				} else {
					var ref core.JobRef
					if err := c.Do(ctx, http.MethodPost, api("/admin/backups"), in, &ref); err != nil {
						return err
					}
					if out == "" && !wait.Wait() {
						return done(cmd, &ref, "backup job %s started (follow it with \"fileparcel jobs show %s --wait\")", ref.JobID, ref.JobID)
					}
					j, err := waitJob(ctx, cmd, c, ref.JobID, true, "backup")
					if err != nil {
						return err
					}
					if b, err = backupOfJob(ctx, c, j); err != nil {
						return err
					}
				}
				if b.State == core.BackupFailed {
					return fmt.Errorf("backup %s failed: %s", b.ID, dash(b.Error))
				}
				// The archive is ready but part of the work failed (most
				// often the copy to backup.copy_to). Say so and exit non-zero
				// so a cron job or script does not take this for a clean run.
				partial := b.Error != ""
				if out != "" {
					dest, n, err := exportBackup(ctx, cmd, c, b, out, force)
					if err != nil {
						return fmt.Errorf("backup %s created, but copying it failed: %w", b.ID, err)
					}
					if dest == "-" {
						// Standard output carries the archive and nothing
						// else: the summary goes to stderr.
						Infof(cmd, "backup %s created (%s, %s) and written to standard output", b.ID, b.Scope, HumanBytes(n))
						if partial {
							Warnf(cmd, "backup %s: %s", b.ID, b.Error)
							return &ExitCodeError{Code: ExitFailure}
						}
						return nil
					}
					Infof(cmd, "Copied %s to %s", HumanBytes(n), dest)
				}
				if err := Print(cmd, b, func(w io.Writer) error {
					Successf(cmd, "backup %s created (%s, %s)", b.ID, b.Scope, HumanBytes(b.Size))
					return nil
				}); err != nil {
					return err
				}
				if partial {
					Warnf(cmd, "backup %s: %s", b.ID, b.Error)
					return &ExitCodeError{Code: ExitFailure}
				}
				return nil
			})
		},
	}
	f := cmd.Flags()
	f.StringVar(&in.Scope, "scope", core.BackupFull, "full (metadata + every stored file) or metadata (database, configuration, keys and certificates; no file contents)")
	f.StringVar(&in.Note, "note", "", "a note stored with the backup")
	addOutputFlag(cmd, &out, "also copy the finished backup to this file or directory, or - for standard output (implies --wait)")
	wait = addWaitFlags(cmd, false, "the backup is finished")
	addForceFlag(cmd, &force, "overwrite an existing --output file")
	// Used by the installer when the installed binary makes the pre-upgrade
	// backup (lcDelegateBackup); only the local administrator (offline or
	// admin socket) may set it, which the backup service enforces.
	f.StringVar(&in.Trigger, "trigger", "", "backup trigger: pre-upgrade or final (installer use)")
	_ = f.MarkHidden("trigger")
	return cmd
}

// checkBackupOut refuses an --output destination of backup create that would
// only fail once the backup is made: an existing file without --force, or a
// directory path (trailing separator) that does not exist. A directory gets
// the archive's own file name, which exportBackup checks again.
func checkBackupOut(out string, force bool) error {
	if out == "" || out == "-" {
		return nil
	}
	if fi, err := os.Stat(out); err == nil && fi.IsDir() {
		return nil
	}
	if strings.HasSuffix(out, string(filepath.Separator)) || strings.HasSuffix(out, "/") {
		return UsageError("--output %s: no such directory", out)
	}
	if !force && fileExists(out) {
		return UsageError("%s already exists (use --force to overwrite)", out)
	}
	return nil
}

// ---------- list / show ----------

func newBackupListCmd() *cobra.Command {
	var limit int
	cmd := &cobra.Command{
		Use:     "list",
		Aliases: []string{"ls"},
		Short:   "List backups",
		Long: `List backups, newest first, with scope, state, size, what started them and
the result of the last check ("fileparcel backup verify").`,
		Example: `  fileparcel backup list
  fileparcel backup list --limit 5 --json`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return WithClient(cmd, func(ctx context.Context, c *Client) error {
				list, err := listAll[core.Backup](ctx, c, api("/admin/backups", "limit", limitParam(limit)), limit)
				if err != nil {
					return err
				}
				slices.SortStableFunc(list, func(a, b core.Backup) int { return b.CreatedAt.Compare(a.CreatedAt) })
				return Print(cmd, list, func(w io.Writer) error {
					if len(list) == 0 {
						Infof(cmd, "no backups yet (create one with \"fileparcel backup create\")")
						return nil
					}
					return renderBackups(w, list)
				})
			})
		},
	}
	cmd.Flags().IntVar(&limit, "limit", 0, "maximum number of backups (0 = all)")
	return cmd
}

func newBackupShowCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "show <backup>",
		Short: "Show every detail of a backup",
		Long: `Show every detail of a backup: file, size, checksum, encryption, contents and
the result of the last check.`,
		Example: `  fileparcel backup show bak_01j9zq3x4k6m8p0r2t4v6x8z0b
  fileparcel backup show bak_01j9zq3x4k6m8p0r2t4v6x8z0b --json`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return WithClient(cmd, func(ctx context.Context, c *Client) error {
				b, err := getBackup(ctx, c, args[0])
				if err != nil {
					return err
				}
				return Print(cmd, b, func(w io.Writer) error { return renderBackup(w, b) })
			})
		},
	}
}

// ---------- verify / import ----------

func newBackupVerifyCmd() *cobra.Command {
	var deep bool
	var wait *waitFlags
	cmd := &cobra.Command{
		Use:   "verify <backup>",
		Short: "Check that a backup can be restored",
		Long: `Check a backup archive: decrypt and unpack it and check the database inside
(--deep also checks every stored file against its content hash). The backup
is a bak_… id or a local .fpbak file, which is added to the server's backup
list first. The command waits for the check unless --no-wait and exits with
status 1 when it fails.`,
		Example: `  fileparcel backup verify bak_01j9zq3x4k6m8p0r2t4v6x8z0b
  fileparcel backup verify bak_01j9zq3x4k6m8p0r2t4v6x8z0b --deep
  fileparcel backup verify /mnt/usb/fp-5f0c81d2-20260919-040000-full.fpbak`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return WithClient(cmd, func(ctx context.Context, c *Client) error {
				id := args[0]
				if !ids.Valid(ids.PrefixBackup, id) {
					if !fileExists(id) {
						return UsageError("%q is neither a backup id nor a local backup file", id)
					}
					b, err := importBackup(ctx, cmd, c, id)
					if err != nil {
						return err
					}
					Infof(cmd, "Imported %s as %s", id, b.ID)
					id = b.ID
				}
				if c.Mode() == ModeOffline {
					// No job runner offline: verify in-process.
					if _, err := getBackup(ctx, c, id); err != nil {
						return err
					}
					j, ok, err := runJobInline(ctx, cmd, c, core.JobBackupVerify, map[string]any{"id": id, "deep": deep})
					if !ok {
						return requireServer(c, "backup verify")
					}
					if j == nil {
						return err
					}
					return reportVerified(ctx, cmd, c, id, deep, j, err)
				}
				var ref core.JobRef
				if err := c.Do(ctx, http.MethodPost, api("/admin/backups/"+pathEsc(id)+"/verify", "deep", strconv.FormatBool(deep)), nil, &ref); err != nil {
					return err
				}
				if !wait.Wait() {
					return done(cmd, &ref, "verification job %s started", ref.JobID)
				}
				j, err := waitJob(ctx, cmd, c, ref.JobID, true, "verifying")
				if j == nil {
					return err
				}
				return reportVerified(ctx, cmd, c, id, deep, j, err)
			})
		},
	}
	cmd.Flags().BoolVar(&deep, "deep", false, "also verify every file blob (slow for large backups)")
	wait = addWaitFlags(cmd, true, "the verification is finished")
	return cmd
}

// reportVerified prints the verification result of backup id after its
// verification job j finished (jobErr is the job's failure, if any). A failed
// verification is an error (exit status 1) with the job's reason (the
// backup's error column also keeps a problem of its creation, such as a
// failed copy to backup.copy_to). The notes of a verification that passed
// are shown, and a deep verification that could not decrypt the files (a
// sealed master key in the backup) is not reported as deep-verified.
func reportVerified(ctx context.Context, cmd *cobra.Command, c *Client, id string, deep bool, j *core.Job, jobErr error) error {
	var r struct { // backup.VerifyResult
		Error         string   `json:"error"`
		Notes         []string `json:"notes"`
		Blobs         int64    `json:"blobs"`
		BlobsVerified int64    `json:"blobs_verified"`
	}
	if j != nil && len(j.Result) > 0 {
		_ = json.Unmarshal(j.Result, &r)
	}
	b, err := getBackup(ctx, c, id)
	if err != nil {
		if jobErr != nil {
			return jobErr
		}
		return err
	}
	if b.VerifyOK != nil && !*b.VerifyOK {
		reason := r.Error
		if reason == "" {
			reason = b.Error
		}
		return fmt.Errorf("backup %s FAILED verification: %s", b.ID, dash(reason))
	}
	if jobErr != nil {
		return jobErr
	}
	for _, n := range r.Notes {
		Warnf(cmd, "backup %s: %s", b.ID, n)
	}
	switch {
	case !deep:
		return done(cmd, b, "backup %s verified successfully", b.ID)
	case r.Blobs > 0 && r.BlobsVerified == 0:
		return done(cmd, b, "backup %s verified, but its file contents were not decrypted", b.ID)
	}
	return done(cmd, b, "backup %s deep-verified successfully", b.ID)
}

// importBackup uploads a local backup archive (POST /admin/backups/import).
func importBackup(ctx context.Context, cmd *cobra.Command, c *Client, path string) (*core.Backup, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !fi.Mode().IsRegular() {
		return nil, fmt.Errorf("%s is not a regular file", path)
	}
	prog := clikit.NewProgress(cmd.ErrOrStderr(), progressEnabled(cmd, false), "importing", fi.Size())
	prog.Start(200 * time.Millisecond)
	defer prog.Finish()
	body := &sizedBody{r: &clikit.CountingReader{R: f, P: prog}, n: fi.Size()}
	hdr := http.Header{"Content-Type": {"application/octet-stream"}}
	var rd io.Reader = body
	if fi.Size() == 0 {
		rd = http.NoBody
	}
	resp, err := c.Stream(ctx, http.MethodPost, api("/admin/backups/import"), rd, hdr)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var b core.Backup
	if err := decodeJSONBody(resp.Body, &b); err != nil {
		return nil, fmt.Errorf("decode response: %w", err)
	}
	if b.ID == "" {
		return nil, errors.New("the server did not return the imported backup")
	}
	return &b, nil
}

func newBackupImportCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "import <file>",
		Short: "Add a backup archive from another disk or server",
		Long: `Add a backup archive (.fpbak) made by this or another FileParcel installation
to <HOME>/backups, so it can be checked and restored.

` + elevationNote,
		Example: `  fileparcel backup import /mnt/usb/fp-5f0c81d2-20260919-040000-full.fpbak
  fileparcel backup import ./old.fpbak --json`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return WithClient(cmd, func(ctx context.Context, c *Client) error {
				b, err := importBackup(ctx, cmd, c, args[0])
				if err != nil {
					return err
				}
				return done(cmd, b, "imported %s as %s", args[0], b.ID)
			})
		},
	}
}

// ---------- prune / delete ----------

func newBackupPruneCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "prune",
		Short: "Delete old automatic backups by the retention rules",
		Long: `Apply the retention rules now (backup.keep_last, keep_daily, keep_weekly,
keep_monthly; see "fileparcel backup config") and delete the automatic backups
they do not keep. Manual, imported, pre-upgrade and final backups stay until
you delete them. This also runs after every automatic backup.`,
		Example: `  fileparcel backup prune
  fileparcel backup prune --json`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return WithClient(cmd, func(ctx context.Context, c *Client) error {
				if c.Mode() == ModeOffline {
					n, err := c.Deps().Backups.Prune(ctx)
					if err != nil {
						return err
					}
					return done(cmd, map[string]int{"deleted": n}, "pruned %s", Plural(int64(n), "backup"))
				}
				var ref core.JobRef
				if err := c.Do(ctx, http.MethodPost, api("/admin/jobs/run"), core.RunJobInput{Kind: core.JobBackupPrune}, &ref); err != nil {
					return err
				}
				j, err := waitJob(ctx, cmd, c, ref.JobID, true, "pruning")
				if err != nil {
					return err
				}
				return done(cmd, j, "pruned %s%s", Plural(prunedCount(j.Result), "backup"), noteSuffix(j.Note))
			})
		},
	}
}

// prunedCount reads {"deleted": n} from a backup.prune job result
// (backup.PruneResult).
func prunedCount(raw json.RawMessage) int64 {
	var r struct {
		Deleted int64 `json:"deleted"`
	}
	if len(raw) == 0 || json.Unmarshal(raw, &r) != nil {
		return 0
	}
	return r.Deleted
}

func newBackupDeleteCmd() *cobra.Command {
	return &cobra.Command{
		Use:     "delete <backup>",
		Aliases: []string{"rm"},
		Short:   "Delete a backup",
		Long: `Delete a backup archive and its entry for good.

` + confirmNote + "\n" + elevationNote,
		Example: `  fileparcel backup delete bak_01j9zq3x4k6m8p0r2t4v6x8z0b
  fileparcel backup delete bak_01j9zq3x4k6m8p0r2t4v6x8z0b -y`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return WithClient(cmd, func(ctx context.Context, c *Client) error {
				b, err := getBackup(ctx, c, args[0])
				if err != nil {
					return err
				}
				if err := confirmOrAbort(cmd, fmt.Sprintf("Delete backup %s from %s (%s)?", b.ID, HumanTime(b.CreatedAt), HumanBytes(b.Size))); err != nil {
					return err
				}
				if err := c.Do(ctx, http.MethodDelete, api("/admin/backups/"+pathEsc(b.ID)), nil, nil); err != nil {
					return err
				}
				return done(cmd, map[string]string{"deleted": b.ID}, "deleted backup %s", b.ID)
			})
		},
	}
}

// ---------- export ----------

// exportBackup downloads a backup archive to dest (a file, an existing
// directory or "-"), verifying its SHA-256 when known. It returns the local
// path and the number of bytes.
func exportBackup(ctx context.Context, cmd *cobra.Command, c *Client, b *core.Backup, dest string, force bool) (string, int64, error) {
	name := b.FileName
	if name == "" || strings.ContainsAny(name, `/\`) {
		name = b.ID + ".fpbak"
	}
	var err error
	if dest, err = localDest(dest, name); err != nil {
		return "", 0, err
	}
	if dest != "-" && !force && fileExists(dest) {
		return "", 0, fmt.Errorf("%s already exists (use --force to overwrite)", dest)
	}
	resp, err := c.Stream(ctx, http.MethodGet, api("/admin/backups/"+pathEsc(b.ID)+"/download"), nil, nil)
	if err != nil {
		return "", 0, err
	}
	defer resp.Body.Close()
	h := sha256.New()
	if dest == "-" {
		n, err := io.Copy(io.MultiWriter(cmd.OutOrStdout(), h), resp.Body)
		if err != nil {
			return "", n, err
		}
		return dest, n, checkBackupSum(b, h.Sum(nil))
	}
	total := b.Size
	if resp.ContentLength > 0 {
		total = resp.ContentLength
	}
	prog := clikit.NewProgress(cmd.ErrOrStderr(), progressEnabled(cmd, false), "exporting", total)
	prog.Start(200 * time.Millisecond)
	part := dest + partialSuffix
	f, err := createPartial(part, "") // never through a planted symlink or into a planted file
	if err != nil {
		prog.Finish()
		return "", 0, err
	}
	n, cerr := io.Copy(io.MultiWriter(&clikit.CountingWriter{W: f, P: prog}, h), resp.Body)
	if err := f.Sync(); err != nil && cerr == nil {
		cerr = err
	}
	if err := f.Close(); err != nil && cerr == nil {
		cerr = err
	}
	prog.Finish()
	if cerr == nil {
		cerr = checkBackupSum(b, h.Sum(nil))
	}
	if cerr != nil {
		_ = os.Remove(part)
		return "", n, cerr
	}
	if err := os.Rename(part, dest); err != nil {
		return "", n, err
	}
	return dest, n, nil
}

func checkBackupSum(b *core.Backup, sum []byte) error {
	want := strings.ToLower(strings.TrimPrefix(b.SHA256, "sha256:"))
	if want == "" {
		return nil
	}
	if got := hex.EncodeToString(sum); got != want {
		return fmt.Errorf("checksum mismatch for backup %s: got %s, want %s", b.ID, got, want)
	}
	return nil
}

func newBackupExportCmd() *cobra.Command {
	var force bool
	cmd := &cobra.Command{
		Use:   "export <backup> <path>",
		Short: "Copy a backup archive to a file or disk",
		Long: `Download a backup archive to a local file or directory (or "-" for standard
output), for example to keep a copy on another disk. Its SHA-256 checksum is
verified. The archive stays encrypted; keep the backup identity or passphrase
somewhere else.

` + elevationNote,
		Example: `  fileparcel backup export bak_01j9zq3x4k6m8p0r2t4v6x8z0b /mnt/usb/
  fileparcel backup export bak_01j9zq3x4k6m8p0r2t4v6x8z0b - | ssh backup-host 'cat > fp.fpbak'`,
		Args: cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			return WithClient(cmd, func(ctx context.Context, c *Client) error {
				b, err := getBackup(ctx, c, args[0])
				if err != nil {
					return err
				}
				if b.State != core.BackupReady {
					return fmt.Errorf("backup %s is %s, not ready", b.ID, b.State)
				}
				dest, n, err := exportBackup(ctx, cmd, c, b, args[1], force)
				if err != nil {
					return err
				}
				if dest == "-" {
					return nil
				}
				return done(cmd, map[string]any{"backup": b.ID, "path": dest, "bytes": n}, "exported backup %s to %s (%s)", b.ID, dest, HumanBytes(n))
			})
		},
	}
	addForceFlag(cmd, &force, "overwrite an existing file")
	return cmd
}

// ---------- config / schedule / identity ----------

func getBackupConfig(ctx context.Context, c *Client) (*core.BackupConfig, error) {
	var cfg core.BackupConfig
	if err := c.Do(ctx, http.MethodGet, api("/admin/backups/config"), nil, &cfg); err != nil {
		return nil, err
	}
	return &cfg, nil
}

func putBackupConfig(ctx context.Context, c *Client, cfg *core.BackupConfig) error {
	// BackupConfig.MarshalJSON never serializes the input-only Passphrase, so
	// it is added explicitly; has_identity/has_passphrase/identity_recipient
	// are output-only.
	data, err := json.Marshal(cfg)
	if err != nil {
		return err
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(data, &m); err != nil {
		return err
	}
	delete(m, "has_identity")
	delete(m, "has_passphrase")
	delete(m, "identity_recipient")
	if cfg.Passphrase != nil {
		pw, _ := json.Marshal(*cfg.Passphrase)
		m["passphrase"] = pw
	}
	return c.Do(ctx, http.MethodPut, api("/admin/backups/config"), m, nil)
}

// effectiveRecipients is what backups are encrypted to: backup.recipients
// plus the server's own backup key (the stored identity's public key) unless
// an entry already holds it.
func effectiveRecipients(cfg *core.BackupConfig) []string {
	out := slices.Clone(cfg.Recipients)
	if out == nil {
		out = []string{}
	}
	own := cfg.IdentityRecipient
	if own == "" {
		return out
	}
	for _, l := range cfg.Recipients {
		if slices.Contains(strings.Fields(l), own) {
			return out
		}
	}
	return append(out, own)
}

func renderBackupConfig(w io.Writer, cfg *core.BackupConfig) error {
	kv := NewKV()
	kv.Add("Scheduled backups", cfg.Enabled)
	kv.Add("Metadata schedule", cronText(cfg.ScheduleMeta))
	kv.Add("Full schedule", cronText(cfg.ScheduleFull))
	kv.Add("Keep", fmt.Sprintf("last %d, daily %d, weekly %d, monthly %d", cfg.KeepLast, cfg.KeepDaily, cfg.KeepWeekly, cfg.KeepMonthly))
	kv.Add("Encryption", cfg.Encryption)
	kv.Add("Recipients", strings.Join(cfg.Recipients, ", "))
	kv.Add("Identity stored", cfg.HasIdentity)
	if cfg.IdentityRecipient != "" {
		kv.Add("Server's own key", cfg.IdentityRecipient+" (always a recipient)")
	}
	kv.Add("Passphrase set", cfg.HasPassphrase)
	kv.Add("Copy to", cfg.CopyTo)
	return kv.Render(w)
}

func cronText(s string) string {
	if s == "" {
		return "off"
	}
	return s
}

func newBackupConfigCmd() *cobra.Command {
	cmd := groupCmd("config", "Show or change retention, encryption and copies",
		`Show or change how many backups are kept, how they are encrypted and where a
copy of each goes (the backup.* settings). Alone it shows them.`,
		`  fileparcel backup config show
  fileparcel backup config set --keep-last 10 --keep-monthly 12
  fileparcel backup config set --copy-to /mnt/nas/fileparcel`)
	show := &cobra.Command{
		Use:   "show",
		Short: "Show the backup settings",
		Long: `Show the backup schedule, the retention rules, the encryption and where
copies go.`,
		Example: `  fileparcel backup config show
  fileparcel backup config show --json`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return WithClient(cmd, func(ctx context.Context, c *Client) error {
				cfg, err := getBackupConfig(ctx, c)
				if err != nil {
					return err
				}
				return Print(cmd, cfg, func(w io.Writer) error { return renderBackupConfig(w, cfg) })
			})
		},
	}
	var keepLast, keepDaily, keepWeekly, keepMonthly int
	var encryption, copyTo string
	var recipients []string
	var pwStdin bool
	var pwFile string
	set := &cobra.Command{
		Use:   "set",
		Short: "Change backup settings",
		Long: `Change backup settings; only the flags you pass are changed. --encryption
passphrase needs a passphrase (--passphrase-stdin / --passphrase-file or a
prompt); x25519 uses the recipients (see "fileparcel backup identity").

` + elevationNote,
		Example: `  fileparcel backup config set --keep-last 10 --keep-daily 14
  fileparcel backup config set --encryption passphrase --passphrase-file /root/fp-backup.pass
  fileparcel backup config set --recipient age1… --recipient age1…
  fileparcel backup config set --copy-to ""`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			f := cmd.Flags()
			if !anyChanged(f, "keep-last", "keep-daily", "keep-weekly", "keep-monthly", "encryption", "recipient", "copy-to",
				"passphrase-stdin", "passphrase-file") {
				return UsageError("nothing to change; see \"fileparcel backup config set --help\"")
			}
			for name, v := range map[string]int{"keep-last": keepLast, "keep-daily": keepDaily, "keep-weekly": keepWeekly, "keep-monthly": keepMonthly} {
				if f.Changed(name) && v < 0 {
					return UsageError("--%s must not be negative", name)
				}
			}
			if f.Changed("encryption") && encryption != core.BackupX25519 && encryption != core.BackupPassphrase {
				return UsageError("invalid --encryption %q (x25519 or passphrase)", encryption)
			}
			return WithClient(cmd, func(ctx context.Context, c *Client) error {
				cfg, err := getBackupConfig(ctx, c)
				if err != nil {
					return err
				}
				if f.Changed("keep-last") {
					cfg.KeepLast = keepLast
				}
				if f.Changed("keep-daily") {
					cfg.KeepDaily = keepDaily
				}
				if f.Changed("keep-weekly") {
					cfg.KeepWeekly = keepWeekly
				}
				if f.Changed("keep-monthly") {
					cfg.KeepMonthly = keepMonthly
				}
				if f.Changed("encryption") {
					cfg.Encryption = encryption
				}
				if f.Changed("recipient") {
					cfg.Recipients = recipients
				}
				if f.Changed("copy-to") {
					if copyTo != "" && !filepath.IsAbs(copyTo) {
						return UsageError("--copy-to must be an absolute path")
					}
					// The path is on the server host, so it can only be
					// checked when this command runs there.
					if copyTo != "" && c.Mode() != ModeRemote {
						if st, err := os.Stat(copyTo); err != nil || !st.IsDir() {
							Warnf(cmd, "%s is not an existing directory; every backup copy will fail until it is", copyTo)
						}
					}
					cfg.CopyTo = copyTo
				}
				if pwStdin || pwFile != "" || (f.Changed("encryption") && encryption == core.BackupPassphrase && !cfg.HasPassphrase) {
					pw, err := secretFrom(cmd, pwStdin, pwFile, "passphrase", true)
					if err != nil {
						return err
					}
					cfg.Passphrase = &pw
				}
				if err := putBackupConfig(ctx, c, cfg); err != nil {
					return err
				}
				cfg.Passphrase = nil
				return done(cmd, cfg, "updated the backup settings")
			})
		},
	}
	sf := set.Flags()
	sf.IntVar(&keepLast, "keep-last", 0, "always keep this many newest backups (scheduled backups only)")
	sf.IntVar(&keepDaily, "keep-daily", 0, "keep one backup per day for this many days (scheduled backups only)")
	sf.IntVar(&keepWeekly, "keep-weekly", 0, "keep one backup per week for this many weeks (scheduled backups only)")
	sf.IntVar(&keepMonthly, "keep-monthly", 0, "keep one backup per month for this many months (scheduled backups only)")
	sf.StringVar(&encryption, "encryption", "", "x25519 (age recipients) or passphrase")
	sf.StringArrayVar(&recipients, "recipient", nil, "age recipient (age1…); repeat for several; replaces the list")
	sf.StringVar(&copyTo, "copy-to", "", `also copy every backup to this absolute directory ("" = off)`)
	sf.BoolVar(&pwStdin, "passphrase-stdin", false, "read the backup passphrase from stdin")
	sf.StringVar(&pwFile, "passphrase-file", "", "read the backup passphrase from a file")
	cmd.AddCommand(show, set)
	bareShows(cmd, show)
	return cmd
}

func newBackupScheduleCmd() *cobra.Command {
	cmd := groupCmd("schedule", "Show or change when backups run automatically",
		`Automatic backups: a metadata backup (default daily 03:00) and a full backup
(default Sundays 04:00), in 5-field cron syntax (minute hour day month
weekday). "disable" pauses them; manual backups always work. Alone it shows
the schedule.`,
		`  fileparcel backup schedule show
  fileparcel backup schedule set --meta "0 3 * * *" --full "0 4 * * 0"
  fileparcel backup schedule disable`)
	show := &cobra.Command{
		Use:   "show",
		Short: "Show the backup schedule",
		Long:  "Show whether automatic backups are on and when they run.",
		Example: `  fileparcel backup schedule show
  fileparcel backup schedule show --json`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return WithClient(cmd, func(ctx context.Context, c *Client) error {
				cfg, err := getBackupConfig(ctx, c)
				if err != nil {
					return err
				}
				out := map[string]any{"enabled": cfg.Enabled, "schedule_meta": cfg.ScheduleMeta, "schedule_full": cfg.ScheduleFull}
				return Print(cmd, out, func(w io.Writer) error {
					kv := NewKV()
					kv.Add("Enabled", cfg.Enabled)
					kv.Add("Metadata backups", cronText(cfg.ScheduleMeta))
					kv.Add("Full backups", cronText(cfg.ScheduleFull))
					return kv.Render(w)
				})
			})
		},
	}
	var meta, full string
	set := &cobra.Command{
		Use:   "set",
		Short: "Change when automatic backups run",
		Long: `Set the cron schedules of metadata and/or full backups ("" or "off" turns
one of them off).`,
		Example: `  fileparcel backup schedule set --meta "30 2 * * *"
  fileparcel backup schedule set --full "0 4 * * 6" --meta off`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			f := cmd.Flags()
			if !f.Changed("meta") && !f.Changed("full") {
				return UsageError("pass --meta and/or --full")
			}
			for _, v := range []*string{&meta, &full} {
				if strings.EqualFold(strings.TrimSpace(*v), "off") {
					*v = ""
				}
				if *v != "" && len(strings.Fields(*v)) != 5 {
					return UsageError("invalid cron expression %q (5 fields: minute hour day month weekday)", *v)
				}
			}
			return WithClient(cmd, func(ctx context.Context, c *Client) error {
				cfg, err := getBackupConfig(ctx, c)
				if err != nil {
					return err
				}
				if f.Changed("meta") {
					cfg.ScheduleMeta = strings.Join(strings.Fields(meta), " ")
				}
				if f.Changed("full") {
					cfg.ScheduleFull = strings.Join(strings.Fields(full), " ")
				}
				if err := putBackupConfig(ctx, c, cfg); err != nil {
					return err
				}
				return done(cmd, cfg, "backup schedule: metadata %s, full %s", cronText(cfg.ScheduleMeta), cronText(cfg.ScheduleFull))
			})
		},
	}
	set.Flags().StringVar(&meta, "meta", "", `cron schedule of metadata backups ("off" disables)`)
	set.Flags().StringVar(&full, "full", "", `cron schedule of full backups ("off" disables)`)
	toggle := func(on bool) *cobra.Command {
		use, short := "disable", "Pause automatic backups"
		if on {
			use, short = "enable", "Resume automatic backups"
		}
		return &cobra.Command{
			Use:   use,
			Short: short,
			Long:  short + " (backup.enabled). Manual backups always work.",
			Example: fmt.Sprintf(`  fileparcel backup schedule %[1]s
  fileparcel backup schedule %[1]s --json`, use),
			Args: cobra.NoArgs,
			RunE: func(cmd *cobra.Command, args []string) error {
				return WithClient(cmd, func(ctx context.Context, c *Client) error {
					cfg, err := getBackupConfig(ctx, c)
					if err != nil {
						return err
					}
					cfg.Enabled = on
					if err := putBackupConfig(ctx, c, cfg); err != nil {
						return err
					}
					return done(cmd, cfg, "scheduled backups %sd", use)
				})
			},
		}
	}
	cmd.AddCommand(show, set, toggle(false), toggle(true))
	bareShows(cmd, show)
	return cmd
}

func newBackupIdentityCmd() *cobra.Command {
	cmd := groupCmd("identity", "Show or create the backup encryption key pair",
		`Backups in x25519 mode are encrypted to age recipients (public keys); the
matching identity (secret key) is needed to restore them. "generate" creates a
new key pair: the identity is printed ONCE, so store it offline (password
manager, paper): backups cannot be restored without it. Alone it shows the
public keys.`,
		`  fileparcel backup identity show
  fileparcel backup identity generate -y > /secure/fileparcel-backup-identity.txt`)
	show := &cobra.Command{
		Use:   "show",
		Short: "Show the public keys backups are encrypted to",
		Long: `Show the public age recipients backups are encrypted to and whether an
identity is stored on the server.`,
		Example: `  fileparcel backup identity show
  fileparcel backup identity show --json`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return WithClient(cmd, func(ctx context.Context, c *Client) error {
				cfg, err := getBackupConfig(ctx, c)
				if err != nil {
					return err
				}
				// recipients: every key a backup is encrypted to, the server's
				// own (the stored identity's) included even when
				// backup.recipients (configured_recipients) is empty.
				all := effectiveRecipients(cfg)
				out := map[string]any{"encryption": cfg.Encryption, "recipients": all, "configured_recipients": cfg.Recipients,
					"has_identity": cfg.HasIdentity}
				if cfg.IdentityRecipient != "" {
					out["identity_recipient"] = cfg.IdentityRecipient
				}
				return Print(cmd, out, func(w io.Writer) error {
					kv := NewKV()
					kv.Add("Encryption", cfg.Encryption)
					kv.Add("Identity stored on server", cfg.HasIdentity)
					label := "Recipient"
					if len(all) > 1 {
						label = "Recipients"
					}
					for i, r := range all { // one per line: an age recipient is long
						if i > 0 {
							label = "" // a continuation row
						}
						if r == cfg.IdentityRecipient {
							r += "  (the server's own backup key)"
						}
						kv.Add(label, r)
					}
					return kv.Render(w)
				})
			})
		},
	}
	generate := &cobra.Command{
		Use:   "generate",
		Short: "Create a new backup key pair (the identity is shown once)",
		Long: `Create a new age key pair for backups. New backups are encrypted to the new
recipient. The identity file is printed once on standard output: redirect it
to a safe place, readable only by you. Below the new identity it lists up to
five previous ones, so "backup restore --identity-file" with it also opens
older backups; keep an older identity file for backups made before that.

` + confirmNote + "\n" + elevationNote,
		Example: `  (umask 077; fileparcel backup identity generate -y > /secure/fileparcel-backup-identity.txt)
  fileparcel backup identity generate --json`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return WithClient(cmd, func(ctx context.Context, c *Client) error {
				if err := confirmOrAbort(cmd, "Generate a new backup key pair? New backups are encrypted to it; keep your old identity file for older backups."); err != nil {
					return err
				}
				var id core.BackupIdentity
				if err := c.Do(ctx, http.MethodPost, api("/admin/backups/identity"), nil, &id); err != nil {
					return err
				}
				return Print(cmd, id, func(w io.Writer) error {
					Infof(cmd, "Recipient (public): %s", id.Recipient)
					Warnf(cmd, "the identity below is shown only once; store it offline — backups cannot be restored without it")
					_, err := fmt.Fprintln(w, id.Identity)
					return err
				})
			})
		},
	}
	cmd.AddCommand(show, generate)
	bareShows(cmd, show)
	return cmd
}

// bareShows makes the group cmd run its "show" subcommand when it is run
// alone ("fileparcel backup schedule"), like "maintenance" and "cert sans"
// show their state. show must have no flags of its own.
func bareShows(cmd, show *cobra.Command) {
	if cmd.Annotations == nil {
		cmd.Annotations = map[string]string{}
	}
	cmd.Annotations[annBare] = show.Name()
	cmd.RunE = func(c *cobra.Command, args []string) error {
		if len(args) > 0 {
			return unknownCommandError(c, args[0])
		}
		return show.RunE(c, nil)
	}
}
