package installer

import (
	"archive/zip"
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"fileparcel/internal/buildinfo"
	"fileparcel/internal/core"
	"fileparcel/internal/home"
	"fileparcel/internal/svc"
)

// UpgradeOptions configure Upgrade.
type UpgradeOptions struct {
	Home   *home.Home
	Binary string // the new binary (verified by the caller or PrepareRelease)
	// BinarySHA256 is the verified SHA-256 of Binary (hex, Release.SHA256;
	// "" = not checked): checked again before the binary is run and on the
	// copy that is installed, so a file swapped after the verification is
	// neither run nor installed.
	BinarySHA256 string
	SourceDir    string // where uninstall.sh and docs/ of the new release are
	Force        bool   // continue when the pre-upgrade backup fails
	DryRun       bool
	Yes          bool
	SkipBackup   bool
	// Install is set when `install` found an existing home: missing pieces
	// (service registration, symlink, installed.json) are repaired using
	// these options.
	Install *InstallOptions
}

// Upgrade replaces the binary of an installed home (DESIGN §14.2 step 2):
// pre-upgrade metadata backup, stop, bin/fileparcel → bin/fileparcel.prev,
// atomic copy of the new binary, refresh of the service registration, start
// (migrations run at start), a 30 s health check pinned to the local CA, and
// a rollback to .prev when the new version does not start or is not healthy
// (also after Ctrl-C during the check). VERSION, docs/ and uninstall.sh are
// refreshed only after the health check, so a rolled-back upgrade never
// leaves them describing a release that is not in bin/.
func (in *Installer) Upgrade(ctx context.Context, o UpgradeOptions) error {
	h := o.Home
	if h == nil || !h.Exists() {
		return errors.New("no FileParcel installation to upgrade")
	}
	rec, err := svc.ReadInstalled(h)
	if err != nil {
		return err
	}
	// A repair registers the service and the command link again: for a home
	// without a record (an interrupted install, a home made with `init`)
	// and, when `install` runs on it, for a home that is not (or no longer)
	// fully installed — after `uninstall --keep-data`, after an install that
	// failed once the home was initialised, or after the home was moved.
	repair := rec == nil || (o.Install != nil && (rec.Incomplete || movedHome(rec.Home, h.Dir())))
	var repairNotes []string
	if repair {
		old := rec
		rec = &svc.Installed{Kind: svc.KindNone, Home: h.Dir(), InstalledAt: in.now()}
		if o.Install != nil {
			if rec, repairNotes, err = in.repairRecord(h, *o.Install); err != nil {
				return err
			}
		}
		if old != nil {
			keepRecorded(rec, old)
		}
	}
	newBin, err := filepath.Abs(o.Binary)
	if err != nil {
		return err
	}
	same := sameFile(newBin, h.Binary())
	var newInfo buildinfo.Info
	if same {
		newInfo = in.Build
	} else {
		// Run only the verified bytes (the file may have been replaced since
		// PrepareRelease checked it).
		if err := checkSHA256(newBin, o.BinarySHA256); err != nil {
			return err
		}
		if newInfo, err = in.binaryInfo(ctx, newBin); err != nil {
			return err
		}
	}
	cur := readVersion(h)
	// The same release again (install.sh run twice, `upgrade` with the
	// installed binary): identical bytes, or the same version and commit.
	// Nothing is swapped, so bin/fileparcel.prev keeps the previous
	// version and the documented rollback still works.
	if !same && in.sameRelease(ctx, h, newBin, o.BinarySHA256, newInfo, cur) {
		same = true
	}
	if same && !repair {
		// Through the summary, so --json still prints JSON.
		v := firstWord(cur)
		if v == "" {
			v = newInfo.Version
		}
		s := &Summary{Action: "upgrade", Home: h.Dir(), Version: v, PreviousVersion: v, Service: rec.Kind, Boot: rec.Boot,
			Symlink: rec.Symlink, Unchanged: true}
		return s.Print(in.Out, in.JSON)
	}

	downgrade := "" // set when --force installs an older release
	var mgr svc.Manager
	if rec.Kind != svc.KindNone {
		// Home as the registration names it (svc.RegisteredHome): the same
		// directory reached by another path is still this home's service.
		if mgr, err = svc.NewManager(in.Host, svc.Options{Kind: rec.Kind, Home: svc.RegisteredHome(h, rec), Binary: h.Binary(), Boot: rec.Boot,
			User: svc.ServiceUser(in.Host), HTTPSPort: rec.HTTPSPort, HTTPPort: rec.HTTPPort, Force: o.Force && repair}); err != nil {
			return err
		}
	}
	active := false
	if mgr != nil {
		if st, err := mgr.Status(ctx); err == nil && st.Installed && st.Active {
			active = true
		}
	}
	var blockers []string // what a dry run reports instead of refusing
	if !active && serverRunning(h) {
		msg := "a FileParcel server or command is using this home outside the service manager; stop it (or wait for the command to finish) and run the upgrade again"
		if !o.DryRun {
			return errors.New(msg)
		}
		blockers = append(blockers, msg)
	}
	// A downgrade: the database may already have a schema the older version
	// refuses to open.
	if older, ok := olderRelease(newInfo.Version, firstWord(cur)); ok && older && !same {
		msg := fmt.Sprintf("%s is older than the installed %s: the older version may refuse the database, which %s "+
			"already migrated (restore a backup made with that version instead)", newInfo.Version, firstWord(cur), firstWord(cur))
		switch {
		case o.Force:
			downgrade = msg
		case o.DryRun:
			blockers = append(blockers, msg+"; --force installs it anyway")
		default:
			return errors.New(msg + "; use --force to install it anyway")
		}
	}
	port := rec.HTTPSPort
	if cfgPort := configPort(h); cfgPort > 0 {
		port = cfgPort
	}

	plan := &svc.Plan{Title: "FileParcel upgrade plan"}
	if repair && same {
		plan.Title = "FileParcel repair plan"
	}
	if o.DryRun {
		plan.Title += " (dry run: nothing will be changed)"
	}
	plan.Fact("Install directory", h.Dir())
	plan.Fact("Installed version", dashIfEmpty(cur))
	plan.Fact("New version", newInfo.String())
	if !same {
		plan.Fact("New binary", newBin)
	}
	svcState := rec.Kind.Describe()
	if mgr != nil {
		svcState += map[bool]string{true: " (running)", false: " (stopped)"}[active]
	}
	plan.Fact("Service", svcState)
	sf := in.supportFiles(newBin, o.SourceDir)

	var backupDesc string
	var warnings []string
	if downgrade != "" {
		warnings = append(warnings, "downgrade: "+downgrade)
	}
	// havePrev: the swap kept the previous binary as bin/fileparcel.prev (a
	// home made with `init` has none), so a failed start can be rolled back.
	started, healthy, swapped, havePrev := false, false, false, false
	lingerOurs := rec.LingerEnabledByUs
	if !same {
		if !o.SkipBackup {
			plan.Add("Create a pre-upgrade metadata backup", func(ctx context.Context) error {
				if in.Hooks.Backup == nil {
					return errors.New("backups are not available")
				}
				b, err := in.Hooks.Backup(ctx, h, core.BackupInput{Scope: core.BackupMetadata, Trigger: core.TriggerPreUpgrade,
					Note: "before the upgrade to " + newInfo.Version})
				if err != nil {
					if o.Force {
						warnings = append(warnings, "the pre-upgrade backup failed (continuing because of --force): "+causeText(err))
						return nil
					}
					return &causeError{msg: "the pre-upgrade backup failed (" + causeText(err) +
						"); fix that, or use --force to upgrade without it", err: err}
				}
				if b != nil {
					backupDesc = fmt.Sprintf("pre-upgrade backup %s (%s)", b.ID, b.FileName)
				}
				return nil
			})
		}
		if active {
			plan.Add("Stop the service", func(ctx context.Context) error { return mgr.Stop(ctx) })
		}
		title := "Install the new binary (the current one is kept as bin/fileparcel.prev)"
		if _, err := os.Stat(h.Binary()); err != nil {
			title = "Install the binary"
		}
		plan.Add(title, func(ctx context.Context) error {
			kept, err := swapBinary(h, newBin, o.BinarySHA256)
			if err != nil {
				return err
			}
			swapped, havePrev = true, kept
			return nil
		}, newBin+" -> "+h.Binary())
	}
	if repair && o.Install != nil && rec.Symlink != "" {
		plan.Add("Link "+rec.Symlink+" -> "+h.Binary(), func(ctx context.Context) error {
			_, err := svc.EnsureSymlink(rec.Symlink, h.Binary(), o.Force)
			return err
		})
	}
	if repair && rec.Kind.System() {
		// As in a fresh system install: the unit runs as the service account,
		// which needs to exist and to own the home (a home made with `init`
		// as root, or a fresh install that failed before this step).
		plan.Add("Create the service account "+rec.ServiceUser+" (if missing)", func(ctx context.Context) error {
			created, err := svc.EnsureSystemUser(ctx, in.Host, rec.ServiceUser, h.Dir())
			if created {
				rec.CreatedUser = rec.ServiceUser
			}
			return err
		})
		plan.Add("Give "+h.Dir()+" to "+rec.ServiceUser+" (bin/ stays owned by root)", func(ctx context.Context) error {
			return giveHome(h, rec.ServiceUser)
		})
	}
	if mgr != nil {
		// Start it again when it was running (or is being registered now,
		// unless --no-start); a deliberately stopped service stays stopped.
		start := active || (repair && (o.Install == nil || !o.Install.NoStart))
		title := "Refresh the service registration"
		if repair {
			title = "Register the " + rec.Kind.Describe()
		}
		if start {
			title += " and start it"
		}
		plan.Add(title, func(ctx context.Context) error {
			if repair && rec.Kind == svc.KindSystemdUser && rec.Boot {
				if changed, err := svc.EnableLinger(ctx, in.Host); err == nil {
					lingerOurs = lingerOurs || changed
				} else {
					warnings = append(warnings, "could not enable linger: "+err.Error())
				}
			}
			if err := mgr.Install(ctx, start); err != nil {
				// A systemd start waits for READY=1: a new version that
				// exits during its migrations or cannot bind fails here,
				// before the health check.
				if start && swapped && havePrev {
					return in.rollback(ctx, h, mgr, port, cur, backupDesc, fmt.Errorf("the new version did not start: %w", err))
				}
				return err
			}
			started = start
			return nil
		}, mgr.RegistrationPath())
		if start {
			plan.Add(fmt.Sprintf("Check https://127.0.0.1:%d/healthz (up to %s)", port, in.healthTimeout()), func(ctx context.Context) error {
				err := in.healthWait(ctx, h, port)
				if err == nil {
					healthy = true
					return nil
				}
				if ctx.Err() != nil {
					err = fmt.Errorf("the health check was interrupted (%w)", ctx.Err())
				}
				switch {
				case !swapped:
					warnings = append(warnings, "the server did not pass its health check: "+err.Error())
					return nil
				case !havePrev:
					warnings = append(warnings, "the server did not pass its health check (there is no previous binary to roll back to): "+
						err.Error()+" (see \"fileparcel logs\" and \"fileparcel doctor\")")
					return nil
				}
				return in.rollback(ctx, h, mgr, port, cur, backupDesc, err)
			})
		} else if repair {
			plan.Note("The service is registered but not started (--no-start): start it with \"fileparcel service start\".")
		} else {
			plan.Note("The service was stopped and stays stopped: start it with \"fileparcel service start\".")
		}
	}
	for _, n := range repairNotes {
		plan.Note("Note: %s", n)
	}
	if downgrade != "" {
		plan.Note("Warning: %s.", downgrade)
	}
	for _, b := range blockers {
		plan.Note("Blocked: %s.", b)
	}
	// After the health check: a rolled-back upgrade must not leave VERSION,
	// docs/ and uninstall.sh describing a release that is not in bin/.
	files, detail := []string{"VERSION"}, []string(nil)
	if sf.Uninstall != "" {
		files = append(files, "uninstall.sh")
		detail = append(detail, sf.Uninstall+" -> "+h.UninstallScript())
	}
	if sf.Docs != "" {
		files = append(files, "docs/")
		detail = append(detail, sf.Docs+"/ -> "+h.DocsDir()+"/")
	}
	last := len(files) - 1
	title := files[last]
	if last > 0 {
		title = strings.Join(files[:last], ", ") + " and " + files[last]
	}
	plan.Add("Update "+title, func(ctx context.Context) error {
		return installFiles(h, h.Binary(), sf, newInfo)
	}, detail...)
	if !same && sf.Uninstall == "" && sf.Docs == "" {
		plan.Note("uninstall.sh and docs/ are not refreshed: none were found for the new binary (they come from the release zip, --source, or the release directory whose SHA256SUMS lists the binary).")
	}
	if rec.Kind.System() {
		// Also for homes installed when HOME itself belonged to the service
		// account (DESIGN §14.4); the tree below is not walked again. The
		// account is the host's, never a name read from installed.json.
		account := svc.ServiceUser(in.Host)
		plan.Add("Keep "+h.Dir()+" root:"+account+" 01770 (bin/ and uninstall.sh owned by root)", func(ctx context.Context) error {
			_, gid, err := svc.AccountIDs(account)
			if err != nil {
				return err
			}
			return svc.LockSystemHome(h, gid)
		})
	}
	plan.Add("Record the new version in "+svc.InstalledPath(h), func(ctx context.Context) error {
		rec.Version = newInfo.Version
		rec.LingerEnabledByUs = lingerOurs
		if mgr != nil {
			rec.UnitPath = mgr.RegistrationPath()
		}
		if !same {
			rec.UpgradedAt = in.now()
		}
		return in.writeRecord(h, rec)
	})
	if mgr == nil && !same {
		plan.Note("No service is registered: restart your FileParcel server yourself to run the new version.")
	}

	if o.DryRun {
		return plan.Print(in.Out)
	}
	if in.interactive(o.Yes) {
		if err := plan.Print(in.Err); err != nil {
			return err
		}
		ok, err := in.Prompt.Confirm("\nProceed?", true)
		if err != nil {
			return err
		}
		if !ok {
			return errors.New("upgrade cancelled")
		}
	}
	if err := plan.Execute(ctx, in.Err); err != nil {
		return err
	}
	s := &Summary{Action: "upgrade", Home: h.Dir(), Version: newInfo.Version, PreviousVersion: firstWord(cur),
		Service: rec.Kind, Boot: rec.Boot, Started: started, Healthy: healthy, Backup: backupDesc, Symlink: rec.Symlink,
		Warnings: append(warnings, repairNotes...)}
	if mgr == nil {
		s.NextSteps = append(s.NextSteps, "restart the server: "+svc.ShellQuote(h.Binary())+" serve --home "+svc.ShellQuote(h.Dir()))
	} else if !started {
		s.NextSteps = append(s.NextSteps, "start the service: fileparcel service start")
	}
	s.NextSteps = append(s.NextSteps, "check everything with \"fileparcel doctor\"")
	return s.Print(in.Out, in.JSON)
}

// rollback restores bin/fileparcel.prev after a failed start or health check
// and restarts the previous version. It runs to its end even when ctx was
// cancelled (Ctrl-C during the health check), so bin/ always holds what the
// service runs.
func (in *Installer) rollback(ctx context.Context, h *home.Home, mgr svc.Manager, port int, prev, backup string, cause error) error {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 2*time.Minute)
	defer cancel()
	in.warnf("the upgrade failed (%v); rolling back to %s", cause, dashIfEmpty(prev))
	if err := mgr.Stop(ctx); err != nil && !errors.Is(err, svc.ErrNotInstalled) {
		return fmt.Errorf("upgrade failed (%v) and the service could not be stopped for the rollback: %w; the new version is still in %s, the previous one in %s",
			cause, err, h.Binary(), h.PrevBinary())
	}
	if err := os.Rename(h.PrevBinary(), h.Binary()); err != nil {
		return fmt.Errorf("upgrade failed (%v) and the rollback failed too: %w; restore %s manually", cause, err, h.PrevBinary())
	}
	if err := mgr.Start(ctx); err != nil {
		return fmt.Errorf("upgrade failed (%v); the previous binary is back but did not start: %w", cause, err)
	}
	msg := fmt.Sprintf("upgrade failed and was rolled back to %s: %v", dashIfEmpty(prev), cause)
	if err := in.healthWait(ctx, h, port); err != nil {
		msg += fmt.Sprintf("; the previous version is not healthy either (%v): the database may already have been migrated", err)
		if backup != "" {
			msg += " — restore the " + backup + " with \"fileparcel backup restore\""
		}
	}
	return errors.New(msg)
}

// swapBinary installs newBin as <HOME>/bin/fileparcel, keeping the current
// binary as fileparcel.prev (both renames are atomic on one filesystem).
// wantSHA256 (hex, "" = unchecked) is checked on the staged copy, so exactly
// the verified bytes are installed. keptPrev reports whether a previous
// binary was kept; without one a stale fileparcel.prev is removed, so a
// rollback can never restore an unrelated older binary.
func swapBinary(h *home.Home, newBin, wantSHA256 string) (keptPrev bool, err error) {
	staged := h.Binary() + ".new"
	if err := copyFile(newBin, staged, 0o755); err != nil {
		return false, err
	}
	if err := checkSHA256(staged, wantSHA256); err != nil {
		os.Remove(staged)
		return false, err
	}
	_ = os.Remove(h.PrevBinary())
	if _, err := os.Stat(h.Binary()); err == nil {
		if err := os.Link(h.Binary(), h.PrevBinary()); err != nil {
			if err := copyFile(h.Binary(), h.PrevBinary(), 0o755); err != nil {
				os.Remove(staged)
				return false, fmt.Errorf("keep previous binary: %w", err)
			}
		}
		keptPrev = true
	}
	if err := os.Rename(staged, h.Binary()); err != nil {
		os.Remove(staged)
		return false, err
	}
	return keptPrev, nil
}

// causeText is the message of err's cause without the internal prefixes
// of the layers it passed ("wire: layout: home: create …"): the first
// file-system error of the chain (it names the path), else the innermost.
func causeText(err error) string {
	for e := err; e != nil; {
		var pe *fs.PathError
		if errors.As(e, &pe) {
			return pe.Error()
		}
		next := errors.Unwrap(e)
		if next == nil {
			return e.Error()
		}
		e = next
	}
	return ""
}

// causeError shows msg and keeps err for errors.Is/As.
type causeError struct {
	msg string
	err error
}

func (e *causeError) Error() string { return e.msg }
func (e *causeError) Unwrap() error { return e.err }

// sameRelease reports whether newBin is the release installed in h: the
// same bytes as bin/fileparcel (wantSHA256, the verified hash, when given),
// or the same version and commit as the installed binary reports (a rebuild
// of one release; never for "dev" builds). VERSION (cur) is only the
// fallback for a binary that is missing or does not run: after a rollback by hand
// (bin/fileparcel.prev copied back) it still names the newer release, and
// trusting it would refuse the retried upgrade as "already installed".
func (in *Installer) sameRelease(ctx context.Context, h *home.Home, newBin, wantSHA256 string, newInfo buildinfo.Info, cur string) bool {
	if installed, err := fileSHA256(h.Binary()); err == nil {
		want := wantSHA256
		if want == "" {
			want, _ = fileSHA256(newBin)
		}
		if want != "" && strings.EqualFold(installed, want) {
			return true
		}
	}
	if newInfo.Version == "" || newInfo.Version == "dev" || newInfo.Commit == "" {
		return false
	}
	version, commit := "", ""
	if bi, err := in.binaryInfo(ctx, h.Binary()); err == nil {
		version, commit = bi.Version, bi.Commit
	} else if f := strings.Fields(cur); len(f) >= 2 {
		version, commit = f[0], f[1]
	}
	return version == newInfo.Version && commit == newInfo.Commit
}

// olderRelease reports whether release version next ("v40") is older than
// cur ("v41"); ok is false unless both are release numbers.
func olderRelease(next, cur string) (older, ok bool) {
	n, err1 := strconv.Atoi(strings.TrimPrefix(next, "v"))
	c, err2 := strconv.Atoi(strings.TrimPrefix(cur, "v"))
	if err1 != nil || err2 != nil || !strings.HasPrefix(next, "v") || !strings.HasPrefix(cur, "v") {
		return false, false
	}
	return n < c, true
}

// checkSHA256 checks that file p has the SHA-256 want (hex; "" = no check).
func checkSHA256(p, want string) error {
	if want == "" {
		return nil
	}
	got, err := fileSHA256(p)
	if err != nil {
		return err
	}
	if !strings.EqualFold(got, want) {
		return fmt.Errorf("%s changed after it was verified (expected SHA-256 %s, got %s)", p, want, got)
	}
	return nil
}

// movedHome reports whether an install record written for the home at
// recorded describes the home now at dir, which is another directory: the
// home was moved (or copied), and its service and link point elsewhere.
func movedHome(recorded, dir string) bool {
	return recorded != "" && recorded != dir && !sameFile(recorded, dir)
}

// keepRecorded carries over into rec, the record rebuilt for a repair, what
// the previous record knows and the install options do not: the account
// and linger the installer created earlier (so uninstall still undoes
// them), the firewall inputs, the ports and the install time.
func keepRecorded(rec, old *svc.Installed) {
	rec.CreatedUser, rec.LingerEnabledByUs = old.CreatedUser, old.LingerEnabledByUs
	rec.FirewallSubnets, rec.FirewallIfaces, rec.FirewallAnywhere = old.FirewallSubnets, old.FirewallIfaces, old.FirewallAnywhere
	rec.Version, rec.UpgradedAt = old.Version, old.UpgradedAt
	if rec.HTTPSPort == 0 {
		rec.HTTPSPort = old.HTTPSPort
	}
	if rec.HTTPPort == 0 {
		rec.HTTPPort = old.HTTPPort
	}
	if !old.InstalledAt.IsZero() {
		rec.InstalledAt = old.InstalledAt
	}
}

// giveHome gives h to the service account user of a system install (DESIGN
// §14.4): everything but bin/ and uninstall.sh, which stay owned by root, and
// HOME itself, which becomes root:<group> 01770 (svc.SecureSystemHome).
func giveHome(h *home.Home, user string) error {
	uid, gid, err := svc.AccountIDs(user)
	if err != nil {
		return err
	}
	return svc.SecureSystemHome(h, uid, gid)
}

// repairRecord builds an install record for a home that has none (an
// interrupted install, or a home created with `init`) or that is repaired
// (see Upgrade). The command link is checked like a fresh install's, before
// anything changes; notes are for the plan.
func (in *Installer) repairRecord(h *home.Home, o InstallOptions) (*svc.Installed, []string, error) {
	kind, _, err := svc.ResolveKind(in.Host, o.Service)
	if err != nil {
		return nil, nil, err
	}
	rec := &svc.Installed{Kind: kind, Boot: kind != svc.KindNone && (o.Boot == nil || *o.Boot), Home: h.Dir(), InstalledAt: in.now()}
	if kind.System() {
		rec.ServiceUser = svc.ServiceUser(in.Host)
	}
	link, notes, err := in.resolveSymlink(h, o)
	if err != nil {
		return nil, nil, err
	}
	rec.Symlink = link
	rec.HTTPSPort = configPort(h)
	return rec, notes, nil
}

// configPort returns server.https_port from fileparcel.toml (0 on error).
func configPort(h *home.Home) int {
	b, err := os.ReadFile(h.Config())
	if err != nil {
		return 0
	}
	// A tiny parse is enough (and works without env overrides).
	sc := bufio.NewScanner(bytes.NewReader(b))
	section := ""
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if strings.HasPrefix(line, "[") {
			section = strings.Trim(line, "[] ")
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if ok && section == "server" && strings.TrimSpace(k) == "https_port" {
			var n int
			if _, err := fmt.Sscanf(strings.TrimSpace(v), "%d", &n); err == nil {
				return n
			}
		}
	}
	return 0
}

func firstWord(s string) string {
	f, _, _ := strings.Cut(strings.TrimSpace(s), " ")
	return f
}

// ---------- release verification ----------

// maxBinary bounds a binary taken from a release (zip entry or file).
const maxBinary = 512 << 20

// Release is a verified new binary plus its support files.
type Release struct {
	Binary    string // verified binary
	SHA256    string // hex SHA-256 of Binary as verified ("" when not verified); pass it as UpgradeOptions.BinarySHA256
	SourceDir string // directory with uninstall.sh and docs/ of an extracted zip ("" = a bare binary: see Installer.releaseFiles)
	Verified  bool   // checked against SHA256SUMS
	cleanup   func()
}

// Close removes extracted files.
func (r *Release) Close() {
	if r != nil && r.cleanup != nil {
		r.cleanup()
	}
}

// ReleaseBinaryName is the release path of the binary for goos/goarch.
func ReleaseBinaryName(goos, goarch string) string { return "bin/fileparcel-" + goos + "-" + goarch }

// PrepareRelease verifies src — a release zip or a binary — for goos/goarch
// and returns the verified binary (DESIGN §12 upgrade: "verify SHA256SUMS").
// Zip releases are extracted into a fresh directory below tmpDir (only the
// binary, uninstall.sh and docs/, with path checks); tmpDir must be private
// to this process's user (see StagingDir). A bare binary is verified
// against a SHA256SUMS file next to it (or one directory up); without one
// it is refused unless allowUnverified.
func PrepareRelease(src, tmpDir, goos, goarch string, allowUnverified bool) (*Release, error) {
	f, err := os.Open(src)
	if err != nil {
		return nil, err
	}
	magic := make([]byte, 4)
	_, _ = io.ReadFull(f, magic)
	f.Close()
	if bytes.Equal(magic, []byte("PK\x03\x04")) || strings.EqualFold(filepath.Ext(src), ".zip") {
		return prepareZip(src, tmpDir, goos, goarch)
	}
	return prepareBinary(src, goos, goarch, allowUnverified)
}

// StagingDir returns where `fileparcel upgrade` extracts a release for h:
// <HOME>/tmp, or <HOME>/bin when this process runs as root and tmp/ belongs
// to another account (a system install gives tmp/ to the service account,
// which could otherwise swap the verified binary before root runs and
// installs it). bin/ stays owned by root, allows exec and is on the
// filesystem of the binary it replaces.
func StagingDir(h *home.Home) string { return stagingDir(h, os.Geteuid()) }

func stagingDir(h *home.Home, euid int) string {
	if uid, ok := fileOwner(h.TmpDir("")); ok && euid == 0 && uid != euid {
		return h.BinDir()
	}
	return h.TmpDir("")
}

// checkPrivateDir refuses a directory that is a symlink, or that another
// account owns or may write (group/other write without the sticky bit).
func checkPrivateDir(dir string) error {
	fi, err := os.Lstat(dir)
	if err != nil {
		return err
	}
	if !fi.IsDir() {
		return fmt.Errorf("%s is not a directory", dir)
	}
	uid, ok := fileOwner(dir)
	if (ok && uid != os.Geteuid()) || (fi.Mode().Perm()&0o022 != 0 && fi.Mode()&fs.ModeSticky == 0) {
		return fmt.Errorf("%s can be changed by another account; refusing to extract a release there", dir)
	}
	return nil
}

// parseSums parses SHA256SUMS ("<hex>  <name>" or "<hex> *<name>").
func parseSums(r io.Reader) map[string]string {
	out := map[string]string{}
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) != 2 || len(f[0]) != 64 {
			continue
		}
		if _, err := hex.DecodeString(f[0]); err != nil {
			continue
		}
		name := strings.TrimPrefix(strings.TrimPrefix(f[1], "*"), "./")
		out[name] = strings.ToLower(f[0])
	}
	return out
}

func prepareBinary(src, goos, goarch string, allowUnverified bool) (*Release, error) {
	abs, err := filepath.Abs(src)
	if err != nil {
		return nil, err
	}
	fi, err := os.Stat(abs)
	if err != nil {
		return nil, err
	}
	if !fi.Mode().IsRegular() || fi.Size() > maxBinary {
		return nil, fmt.Errorf("%s is not a plausible fileparcel binary", abs)
	}
	dir := filepath.Dir(abs)
	base := filepath.Base(abs)
	// No SourceDir: Upgrade takes uninstall.sh and docs/ only from the
	// release around the binary that its SHA256SUMS verifies (releaseFiles),
	// never from whatever else lies next to it.
	rel := &Release{Binary: abs}
	for _, cand := range []struct{ file, name string }{
		{filepath.Join(dir, "SHA256SUMS"), base},
		{filepath.Join(filepath.Dir(dir), "SHA256SUMS"), path.Join(filepath.Base(dir), base)},
	} {
		sf, err := os.Open(cand.file)
		if err != nil {
			continue
		}
		sums := parseSums(sf)
		sf.Close()
		want, ok := sums[cand.name]
		if !ok {
			continue
		}
		got, err := fileSHA256(abs)
		if err != nil {
			return nil, err
		}
		if got != want {
			return nil, fmt.Errorf("checksum mismatch for %s (expected %s, got %s): the file is corrupt or was modified", abs, want, got)
		}
		rel.Verified, rel.SHA256 = true, got
		return rel, nil
	}
	if !allowUnverified {
		return nil, fmt.Errorf("no SHA256SUMS entry found for %s; upgrade from the release zip, or use --force to install an unverified binary", abs)
	}
	return rel, nil
}

func fileSHA256(p string) (string, error) {
	f, err := os.Open(p)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func prepareZip(src, tmpDir, goos, goarch string) (_ *Release, err error) {
	zr, err := zip.OpenReader(src)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", src, err)
	}
	defer zr.Close()
	want := ReleaseBinaryName(goos, goarch)
	// The release zip has one top-level directory (fileparcel-vN/); accept
	// a flat layout too.
	prefix := ""
	var binEntry, sumsEntry *zip.File
	for _, f := range zr.File {
		name := f.Name
		switch {
		case strings.HasSuffix(name, "/"+want) || name == want:
			binEntry = f
			prefix = strings.TrimSuffix(name, want)
		}
	}
	if binEntry == nil {
		return nil, fmt.Errorf("%s does not contain %s (wrong platform or not a FileParcel release)", src, want)
	}
	for _, f := range zr.File {
		if f.Name == prefix+"SHA256SUMS" {
			sumsEntry = f
		}
	}
	if sumsEntry == nil {
		return nil, fmt.Errorf("%s has no SHA256SUMS; refusing an unverifiable release", src)
	}
	rc, err := sumsEntry.Open()
	if err != nil {
		return nil, err
	}
	sums := parseSums(io.LimitReader(rc, 1<<20))
	rc.Close()
	expected, ok := sums[want]
	if !ok {
		return nil, fmt.Errorf("SHA256SUMS in %s has no entry for %s", src, want)
	}
	if err := os.MkdirAll(tmpDir, 0o700); err != nil {
		return nil, err
	}
	// The binary is checked here and run and installed later by path:
	// nobody else may be able to rename the extraction directory meanwhile.
	if err := checkPrivateDir(tmpDir); err != nil {
		return nil, err
	}
	dir, err := os.MkdirTemp(tmpDir, "release-")
	if err != nil {
		return nil, err
	}
	rel := &Release{SourceDir: dir, SHA256: expected, Verified: true, cleanup: func() { os.RemoveAll(dir) }}
	defer func() {
		if err != nil {
			rel.Close()
		}
	}()
	rel.Binary = filepath.Join(dir, "fileparcel")
	got, err := extractEntry(binEntry, rel.Binary, 0o755, maxBinary)
	if err != nil {
		return nil, err
	}
	if got != expected {
		return nil, fmt.Errorf("checksum mismatch for %s in %s (expected %s, got %s): the download is corrupt or was modified", want, src, expected, got)
	}
	var docsTotal int64
	for _, f := range zr.File {
		name := strings.TrimPrefix(f.Name, prefix)
		if !strings.HasPrefix(f.Name, prefix) || f.FileInfo().IsDir() || !f.Mode().IsRegular() {
			continue
		}
		switch {
		case name == "uninstall.sh":
			if _, err := extractEntry(f, filepath.Join(dir, "uninstall.sh"), 0o755, 1<<20); err != nil {
				return nil, err
			}
		case strings.HasPrefix(name, "docs/"):
			clean := path.Clean(name)
			if clean != name || strings.Contains(name, "..") || strings.Contains(name, "\\") {
				continue
			}
			docsTotal += int64(f.UncompressedSize64)
			if docsTotal > maxDocsBytes {
				return nil, errors.New("docs/ in the release is too large")
			}
			if _, err := extractEntry(f, filepath.Join(dir, filepath.FromSlash(name)), 0o640, maxDocsBytes); err != nil {
				return nil, err
			}
		}
	}
	return rel, nil
}

// extractEntry writes a zip entry to dst (at most max bytes) and returns its
// SHA-256.
func extractEntry(f *zip.File, dst string, mode fs.FileMode, max int64) (string, error) {
	if f.UncompressedSize64 > uint64(max) {
		return "", fmt.Errorf("%s is too large", f.Name)
	}
	rc, err := f.Open()
	if err != nil {
		return "", err
	}
	defer rc.Close()
	if err := os.MkdirAll(filepath.Dir(dst), 0o700); err != nil {
		return "", err
	}
	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return "", err
	}
	h := sha256.New()
	n, err := io.Copy(io.MultiWriter(out, h), io.LimitReader(rc, max+1))
	if cerr := out.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return "", err
	}
	if n > max {
		return "", fmt.Errorf("%s is too large", f.Name)
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
