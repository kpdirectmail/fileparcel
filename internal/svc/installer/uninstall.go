package installer

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/netip"
	"os"
	"path/filepath"
	"strings"

	"fileparcel/internal/core"
	"fileparcel/internal/home"
	"fileparcel/internal/svc"
	"fileparcel/internal/tsingress"
)

// UninstallOptions are the flags of `fileparcel uninstall` (DESIGN §14.6).
type UninstallOptions struct {
	Home        *home.Home
	Purge       bool   // delete HOME (after overwriting the key files); default keeps the data
	FinalBackup bool   // full backup before removing anything
	BackupTo    string // copy the final backup into this directory (outside HOME, created if missing); implies FinalBackup, required for it with Purge
	RemoveUser  bool   // delete the service account the installer created
	Yes         bool
	DryRun      bool
}

// Uninstall removes the service registration, linger (when the installer
// enabled it and nothing else needs it), the command symlink (only when it
// points into HOME) and — with Purge — the home itself, after crypto-erasing
// the master key and certificate keys.
func (in *Installer) Uninstall(ctx context.Context, o UninstallOptions) error {
	h := o.Home
	if h == nil || !h.Exists() {
		return errors.New("no FileParcel installation found (no fileparcel.toml)")
	}
	if o.BackupTo != "" {
		o.FinalBackup = true
		abs, err := filepath.Abs(expandHome(o.BackupTo, in.Host.HomeDir))
		if err != nil {
			return err
		}
		if svc.Within(h.Dir(), abs) {
			return errors.New("--backup-to must be outside the FileParcel home (it is deleted or left behind)")
		}
		if fi, err := os.Stat(abs); err == nil && !fi.IsDir() {
			return fmt.Errorf("--backup-to %s is not a directory", abs)
		}
		o.BackupTo = abs
	}
	if o.Purge && o.FinalBackup && o.BackupTo == "" {
		// The backup would be written to <HOME>/backups and deleted with
		// the home in the same run.
		return fmt.Errorf("--final-backup with --purge needs --backup-to DIR outside the home: a backup left in %s is deleted with it", h.BackupsDir())
	}
	if o.Purge && svc.DangerousHome(h.Dir(), in.Host.HomeDir) {
		return fmt.Errorf("refusing to purge %s", h.Dir())
	}
	rec, err := svc.ReadInstalled(h)
	if err != nil {
		in.warnf("%v (continuing with defaults)", err)
	}
	if rec == nil {
		rec = &svc.Installed{Kind: svc.KindNone, Home: h.Dir()}
		// A registration made without the installer (fileparcel service install).
		if kind, _, err := svc.ResolveKind(in.Host, ""); err == nil && kind != svc.KindNone {
			o2 := svc.Options{Kind: kind, Home: h.Dir(), Binary: h.Binary(), User: svc.ServiceUser(in.Host)}
			if m, err := svc.NewManager(in.Host, o2); err == nil {
				if st, err := m.Status(ctx); err == nil && st.Installed {
					rec.Kind, rec.ServiceUser = kind, o2.User
				}
			}
		}
	}
	// The service registration and the command link name HOME as the
	// installer was given it, which can be another path to h (a symlinked
	// component, or the physical path uninstall.sh and home.Resolve find):
	// reg is only used to recognise them; the files are handled through h.
	reg := h
	if d := svc.RegisteredHome(h, rec); d != h.Dir() {
		if r, err := home.New(d); err == nil {
			reg = r
		}
	}
	var mgr svc.Manager
	if rec.Kind != svc.KindNone {
		m, err := in.managerFor(reg, rec, rec.Boot)
		switch {
		case err == nil:
			mgr = m
		case (rec.Kind.Systemd() && in.Host.GOOS == "linux") || (rec.Kind.Launchd() && in.Host.GOOS == "darwin"):
			// The service can exist here, but this user cannot manage it (a
			// user service and sudo, a system service without it): going on
			// would record "no service" while it stays registered and running.
			hint := "check the record"
			switch {
			case rec.Kind.System() && !in.Host.Root():
				hint = "run the uninstall as root (sudo)"
			case !rec.Kind.System() && in.Host.Root():
				hint = "run the uninstall as the user who installed it (without sudo)"
			}
			return fmt.Errorf("cannot manage the %s recorded in %s: %v; nothing was changed: %s",
				rec.Kind.Describe(), svc.InstalledPath(h), err, hint)
		default:
			// A kind that cannot exist on this system (a home copied from
			// another OS): nothing to unregister here.
			in.warnf("cannot manage the %s: %v", rec.Kind.Describe(), err)
		}
	}
	symlink := rec.Symlink
	if symlink == "" {
		symlink = svc.DefaultSymlink(in.Host)
	}
	// A server started by hand ("fileparcel serve"; also next to a stopped
	// service) keeps serving after the service is gone: it is stopped like
	// uninstall.sh's fallback does. A process that holds the home but
	// cannot be identified is reported (and refuses --purge before anything
	// changes).
	active := false
	if mgr != nil {
		if st, err := mgr.Status(ctx); err == nil && st.Installed && st.Active {
			active = true
		}
	}
	handPID, busy := 0, false
	if !active && serverRunning(h) {
		if handPID = in.handServer(h); handPID == 0 {
			busy = true
		}
	}
	const busyMsg = "a FileParcel process that is not the service uses the home (a server started by hand, or another " +
		"fileparcel command); stop it"
	if busy && o.Purge && !o.DryRun {
		return errors.New(busyMsg + " first; nothing was removed")
	}

	plan := &svc.Plan{Title: "FileParcel uninstall plan"}
	if o.DryRun {
		plan.Title += " (dry run: nothing will be changed)"
	}
	plan.Fact("Install directory", h.Dir())
	plan.Fact("Version", dashIfEmpty(readVersion(h)))
	plan.Fact("Service", rec.Kind.Describe())
	if o.Purge {
		plan.Fact("Data", "DELETED (keys overwritten first)")
	} else {
		plan.Fact("Data", "kept in "+h.Dir())
	}

	var backupDesc string
	var warnings []string
	if o.FinalBackup {
		title := "Create a final full backup"
		if o.BackupTo != "" {
			title += " and copy it to " + o.BackupTo + " (created if missing)"
		}
		// This is the first step: when it fails, nothing has been removed.
		plan.Add(title, func(ctx context.Context) error {
			if in.Hooks.Backup == nil {
				return errors.New("backups are not available")
			}
			// The copy is made below by this process (root or the home's
			// owner), not by the server: a system service cannot write
			// outside HOME (ProtectSystem=strict).
			b, err := in.Hooks.Backup(ctx, h, core.BackupInput{Scope: core.BackupFull, Trigger: core.TriggerFinal,
				Note: "final backup before uninstall"})
			if err != nil {
				return err
			}
			if b == nil || b.FileName == "" || b.State == core.BackupFailed {
				return errors.New("the final backup was not created; nothing was removed")
			}
			backupDesc = "final backup " + b.ID + " (" + b.FileName + ")"
			if o.BackupTo != "" {
				dst, err := copyBackup(ctx, h, b, o.BackupTo)
				if err != nil {
					return fmt.Errorf("the final backup %s is in %s but could not be copied to %s: %w; nothing was removed",
						b.ID, h.BackupsDir(), o.BackupTo, err)
				}
				backupDesc += ", copied to " + dst
			} else if b.CopiedTo != "" {
				backupDesc += ", copied to " + b.CopiedTo
			}
			if b.Error != "" {
				warnings = append(warnings, "final backup: "+b.Error)
			}
			return nil
		})
	}
	if tsingress.HasMarker(h) {
		// Before the service stops: nothing FileParcel published on the
		// tailnet or the internet outlives the installation (DESIGN §10.6
		// "Uninstall"), also with the data kept. A failure only warns, with
		// the commands that remove the entries by hand.
		plan.Add("Remove FileParcel's Tailscale Funnel/Serve entries", func(ctx context.Context) error {
			if err := tsingress.RemoveMarked(ctx, h, in.Tailscale); err != nil {
				warnings = append(warnings, "Tailscale: "+err.Error())
			}
			return nil
		})
	}
	if handPID > 0 {
		plan.Add(fmt.Sprintf("Stop the server started by hand (pid %d)", handPID), func(ctx context.Context) error {
			return in.stopServer(ctx, h, handPID)
		})
	}
	if mgr != nil {
		plan.Add("Stop and unregister the "+rec.Kind.Describe(), func(ctx context.Context) error {
			if err := mgr.Uninstall(ctx); err != nil {
				if errors.Is(err, svc.ErrNotOurs) {
					warnings = append(warnings, err.Error())
					return nil
				}
				return err
			}
			return nil
		}, mgr.RegistrationPath())
	}
	// --purge: once the servers are stopped nothing may use the home any
	// more; checked before the linger, the command link and the keys
	// change, so a refusal leaves the installation as it was.
	var unlock func()
	if o.Purge {
		plan.Add("Make sure no FileParcel process uses the home", func(ctx context.Context) error {
			u, err := h.Lock()
			if err != nil {
				if errors.Is(err, home.ErrLocked) {
					return errors.New("the home is still in use (a server started outside the service manager, or another fileparcel command); stop it first")
				}
				return err
			}
			unlock = u
			return nil
		})
	}
	if rec.LingerEnabledByUs && rec.Kind == svc.KindSystemdUser {
		plan.Add("Disable linger for "+in.Host.User+" (the installer enabled it) unless other user services need it", func(ctx context.Context) error {
			if others := svc.OtherUserUnitsEnabled(in.Host); len(others) > 0 {
				warnings = append(warnings, fmt.Sprintf("linger stays enabled: other user services are enabled (%v)", others))
				return nil
			}
			if err := svc.DisableLinger(ctx, in.Host); err != nil {
				warnings = append(warnings, "could not disable linger: "+err.Error())
			}
			return nil
		})
	}
	plan.Add("Remove the command link "+symlink+" (only if it points into "+reg.Dir()+")", func(ctx context.Context) error {
		removed, err := svc.RemoveSymlink(symlink, reg.Dir())
		if err == nil && !removed && reg != h {
			_, err = svc.RemoveSymlink(symlink, h.Dir())
		}
		return err
	})
	if o.Purge {
		plan.Add("Overwrite the master key and certificate keys with random bytes (including the copies restores keep in pre-restore-*/)", func(ctx context.Context) error {
			return shredKeys(h)
		}, shredTargets(h)...)
		plan.Add("Delete "+h.Dir(), func(ctx context.Context) error {
			defer func() {
				if unlock != nil {
					unlock()
				}
			}()
			if !h.Exists() || svc.DangerousHome(h.Dir(), in.Host.HomeDir) {
				return fmt.Errorf("refusing to delete %s", h.Dir())
			}
			return os.RemoveAll(h.Dir())
		})
		plan.Note("Note: on SSDs and copy-on-write file systems overwritten blocks can survive; the files were encrypted, and without the master key they cannot be decrypted.")
	} else {
		plan.Add("Mark the home as not installed (data, keys and backups stay in "+h.Dir()+")", func(ctx context.Context) error {
			keep := *rec
			keep.Kind, keep.UnitPath, keep.Boot, keep.LingerEnabledByUs, keep.Symlink = svc.KindNone, "", false, false, ""
			// install.sh --dir on this home registers the service and the
			// command link again (Upgrade treats the record as a repair).
			keep.Incomplete = true
			return in.writeRecord(h, &keep)
		})
	}
	if o.RemoveUser {
		if rec.CreatedUser != "" {
			plan.Add("Delete the service account "+rec.CreatedUser, func(ctx context.Context) error {
				return svc.RemoveSystemUser(ctx, in.Host, rec.CreatedUser)
			})
			if !o.Purge {
				plan.Note("Note: the kept files stay owned by the numeric id of the deleted account %s.", rec.CreatedUser)
			}
		} else {
			plan.Note("--remove-user: the installer did not create a service account; nothing to remove.")
		}
	}

	if busy {
		if o.Purge {
			plan.Note("Blocked: %s first (--purge refuses to run while it does).", busyMsg)
		} else {
			plan.Note("Note: %s yourself; it keeps serving from %s after the uninstall.", busyMsg, h.Dir())
			warnings = append(warnings, busyMsg+" yourself: it keeps serving from "+h.Dir())
		}
	}
	if o.DryRun {
		return plan.Print(in.Out)
	}
	if !o.Yes {
		if !in.interactive(false) {
			return errors.New("uninstall needs confirmation: run it in a terminal or pass -y")
		}
		if err := plan.Print(in.Err); err != nil {
			return err
		}
		q := "\nUninstall FileParcel (your data stays in " + h.Dir() + ")?"
		if o.Purge {
			q = "\nPERMANENTLY DELETE " + h.Dir() + " with all files, keys and backups?"
		}
		ok, err := in.Prompt.Confirm(q, false)
		if err != nil {
			return err
		}
		if ok && o.Purge {
			ans, err := in.Prompt.Ask("Type the directory name ("+filepath.Base(h.Dir())+") to confirm", "")
			if err != nil {
				return err
			}
			ok = ans == filepath.Base(h.Dir())
		}
		if !ok {
			return errors.New("uninstall cancelled")
		}
	}
	if err := plan.Execute(ctx, in.Err); err != nil {
		return err
	}
	s := &Summary{Action: "uninstall", Home: h.Dir(), Version: readVersion(h), Service: rec.Kind, Backup: backupDesc,
		Warnings: warnings}
	fi := svc.HintInput{HTTPSPort: rec.HTTPSPort, HTTPPort: rec.HTTPPort, VPNIfaces: rec.FirewallIfaces, Binary: h.Binary(),
		Anywhere: rec.FirewallAnywhere, BuiltinMDNS: svc.BuiltinMDNSLikely(in.Host)}
	if fi.HTTPSPort == 0 {
		fi.HTTPSPort = configPort(h)
	}
	for _, c := range rec.FirewallSubnets {
		if p, err := netip.ParsePrefix(c); err == nil {
			fi.Subnets = append(fi.Subnets, p)
		}
	}
	if fi.HTTPSPort > 0 {
		s.Firewall = firewallAdvice(svc.DetectFirewalls(ctx, in.Host), fi, true)
	}
	if !o.Purge {
		s.NextSteps = append(s.NextSteps,
			"your data is still in "+h.Dir()+"; reinstall with install.sh --dir "+svc.ShellQuote(h.Dir())+
				", or delete it for good with: "+svc.ShellQuote(h.Binary())+" uninstall --purge --home "+svc.ShellQuote(h.Dir()))
	}
	return s.Print(in.Out, in.JSON)
}

// maxShred bounds the size of a file overwritten by shredKeys.
const maxShred = 4 << 20

// shredKeys overwrites every regular file under the shredTargets with
// random bytes of the same length and syncs it (crypto-erase of the master
// key and the CA/leaf/custom keys before the home is deleted).
func shredKeys(h *home.Home) error {
	var errs []error
	for _, dir := range shredTargets(h) {
		// WalkDir does not follow a symlinked root, and symlinked files are
		// skipped below: nothing outside the home is overwritten.
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
			errs = append(errs, overwrite(p))
			return nil
		})
		errs = append(errs, err)
	}
	return errors.Join(errs...)
}

// shredTargets lists what shredKeys overwrites: keys/ and certs/, the copies
// of both that every restore keeps in pre-restore-<ts>/ (often the current
// master key itself), those in restore and deep-verify staging directories a
// crash left in tmp/, and the one-time key of a pending restore. Only real
// directories are used (never a symlink); missing paths are skipped.
func shredTargets(h *home.Home) []string {
	out := []string{h.KeysDir(), h.CertsDir()}
	sub := func(dir string, match func(name string) bool) {
		entries, _ := os.ReadDir(dir)
		for _, e := range entries {
			if e.IsDir() && match(e.Name()) {
				out = append(out, filepath.Join(dir, e.Name(), "keys"), filepath.Join(dir, e.Name(), "certs"))
			}
		}
	}
	sub(h.Dir(), func(name string) bool { return strings.HasPrefix(name, "pre-restore-") })
	all := func(string) bool { return true }
	if realDir(h.TmpDir("")) {
		for _, t := range []string{home.TmpRestore, home.TmpVerify} {
			if realDir(h.TmpDir(t)) {
				sub(h.TmpDir(t), all)
			}
		}
	}
	if k := filepath.Join(h.RunDir(), "restore.key"); fileExists(k) {
		out = append(out, k)
	}
	return out
}

// realDir reports whether p is a directory and not a symlink.
func realDir(p string) bool {
	fi, err := os.Lstat(p)
	return err == nil && fi.IsDir()
}

// fileExists reports whether p exists (not following a symlink).
func fileExists(p string) bool {
	_, err := os.Lstat(p)
	return err == nil
}

// copyBackup copies the archive of b from <HOME>/backups into dir (created
// 0700 when missing) and checks the copy against the recorded size and
// SHA-256. Both directories are used through os.Root, so no symlink leads
// out of them; the copy is written exclusively as a hidden partial file
// (0600), synced and renamed into place. It returns the copy's path.
func copyBackup(ctx context.Context, h *home.Home, b *core.Backup, dir string) (string, error) {
	name := b.FileName
	if name != filepath.Base(name) || name == "." || name == ".." || strings.HasPrefix(name, ".") {
		return "", fmt.Errorf("unexpected backup file name %q", name)
	}
	src, err := os.OpenRoot(h.BackupsDir())
	if err != nil {
		return "", err
	}
	defer src.Close()
	in, err := src.Open(name)
	if err != nil {
		return "", err
	}
	defer in.Close()
	if fi, err := in.Stat(); err != nil {
		return "", err
	} else if !fi.Mode().IsRegular() {
		return "", fmt.Errorf("%s is not a regular file", name)
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		return "", err
	}
	defer root.Close()
	tmp := "." + name + ".partial"
	_ = root.Remove(tmp) // a stale partial or a planted symlink; never followed
	out, err := root.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return "", err
	}
	err = func() error {
		if err := out.Chmod(0o600); err != nil {
			return err
		}
		sum := sha256.New()
		n, err := io.Copy(ctxWriter{ctx, io.MultiWriter(out, sum)}, in)
		if err != nil {
			return err
		}
		if b.Size > 0 && n != b.Size {
			return fmt.Errorf("copied %d bytes, the backup has %d", n, b.Size)
		}
		want := strings.ToLower(strings.TrimPrefix(b.SHA256, "sha256:"))
		if want != "" && want != hex.EncodeToString(sum.Sum(nil)) {
			return errors.New("the copy does not match the backup's SHA-256")
		}
		return out.Sync()
	}()
	if cerr := out.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = root.Rename(tmp, name)
	}
	if err != nil {
		_ = root.Remove(tmp)
		return "", err
	}
	if d, err := os.Open(dir); err == nil {
		_ = d.Sync()
		_ = d.Close()
	}
	return filepath.Join(dir, name), nil
}

// ctxWriter stops a copy when ctx is cancelled.
type ctxWriter struct {
	ctx context.Context
	w   io.Writer
}

func (c ctxWriter) Write(p []byte) (int, error) {
	if err := c.ctx.Err(); err != nil {
		return 0, err
	}
	return c.w.Write(p)
}

func overwrite(p string) error {
	f, err := os.OpenFile(p, os.O_WRONLY, 0)
	if err != nil {
		return err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return err
	}
	n := min(fi.Size(), maxShred)
	if _, err := io.CopyN(f, rand.Reader, n); err != nil {
		return err
	}
	return f.Sync()
}
