// Package installer implements `fileparcel install`, `upgrade` and
// `uninstall` (DESIGN §14.2, §14.6): it resolves defaults and interactive
// answers into a svc.Plan (printed by --dry-run, executed otherwise), copies
// the binary and support files into the home, provisions a fresh home
// through Hooks.InitHome, registers the service (svc), takes pre-upgrade and
// final backups through Hooks.Backup, health-checks and rolls back upgrades,
// and prints the summary (URLs with terminal QR codes, CA fingerprint,
// credentials shown once, firewall hints).
//
// Everything that needs the full service graph (wire) is injected by the
// CLI through Hooks, so this package is testable with fakes. Owned by unit I.
package installer

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"fileparcel/internal/buildinfo"
	"fileparcel/internal/core"
	"fileparcel/internal/home"
	"fileparcel/internal/svc"
	"fileparcel/internal/svc/provision"
	"fileparcel/internal/tslocal"
)

// SourceEnv names the directory holding uninstall.sh and docs/ (set by
// install.sh to its own directory).
const SourceEnv = "FILEPARCEL_INSTALL_SOURCE"

// Prompter asks the user questions (implemented by the CLI on the terminal).
type Prompter interface {
	// Interactive reports whether questions can be asked at all.
	Interactive() bool
	Ask(question, def string) (string, error)
	Confirm(question string, def bool) (bool, error)
	// Secret reads a secret without echo; confirm asks twice.
	Secret(prompt string, confirm bool) (string, error)
}

// Hooks connect the installer to the service graph.
type Hooks struct {
	// InitHome creates and provisions a fresh home (provision.PrepareHome +
	// wire.Build offline + provision.Provision), rolling back on failure.
	InitHome func(ctx context.Context, dir string, c provision.ConfigOptions, o provision.Options) (*provision.Result, error)
	// Backup creates a backup of h through the running server (admin
	// socket) or in-process when it is stopped, and waits for it.
	Backup func(ctx context.Context, h *home.Home, in core.BackupInput) (*core.Backup, error)
}

// Installer holds the environment of one install/upgrade/uninstall run.
type Installer struct {
	Host   *svc.Host
	Out    io.Writer // plan, summary
	Err    io.Writer // progress, warnings
	Prompt Prompter
	Hooks  Hooks
	// JSON prints the summary as JSON on Out (progress still goes to Err).
	JSON bool
	// Executable is the running binary (the binary `install` installs).
	Executable string
	// Build is the running binary's build info.
	Build buildinfo.Info
	// Now, PortFree and HealthWait are replaceable for tests.
	Now        func() time.Time
	PortFree   func(port int) bool
	HealthWait func(ctx context.Context, h *home.Home, port int, total time.Duration) error
	// BinaryInfo runs `<bin> version --json` (tests replace it).
	BinaryInfo func(ctx context.Context, bin string) (buildinfo.Info, error)
	// HealthTimeout bounds the post-start health check (DESIGN: 30 s).
	HealthTimeout time.Duration
	// Tailscale is the tailscaled client uninstall removes FileParcel's
	// Funnel/Serve entries with (nil: tslocal.Default(); tests use a fake).
	Tailscale *tslocal.Client
	// HandServer returns the pid of a FileParcel server started by hand
	// (not through the service manager) that uses h, 0 when none or not
	// known; StopServer stops it (SIGTERM, then waits for the home lock).
	// Tests replace them.
	HandServer func(h *home.Home) int
	StopServer func(ctx context.Context, h *home.Home, pid int) error
	// removeUser is svc.RemoveSystemUser (tests replace it).
	removeUser func(ctx context.Context, h *svc.Host, name string) error
	// chown gives path to account (tests replace it; see writeRecord).
	chown func(path, account string) error
}

// New returns an Installer for the current process.
func New(out, errOut io.Writer, p Prompter, hooks Hooks) *Installer {
	exe, _ := os.Executable()
	if real, err := filepath.EvalSymlinks(exe); err == nil {
		exe = real
	}
	return &Installer{Host: svc.CurrentHost(), Out: out, Err: errOut, Prompt: p, Hooks: hooks, Executable: exe,
		Build: buildinfo.Get()}
}

func (in *Installer) now() time.Time {
	if in.Now != nil {
		return in.Now().UTC()
	}
	return time.Now().UTC()
}

func (in *Installer) portFree(p int) bool {
	if in.PortFree != nil {
		return in.PortFree(p)
	}
	return svc.PortFree(p)
}

func (in *Installer) healthWait(ctx context.Context, h *home.Home, port int) error {
	total := in.HealthTimeout
	if total <= 0 {
		total = 30 * time.Second
	}
	if in.HealthWait != nil {
		return in.HealthWait(ctx, h, port, total)
	}
	return svc.WaitHealthy(ctx, h, port, total, 500*time.Millisecond)
}

func (in *Installer) removeSystemUser(ctx context.Context, name string) error {
	if in.removeUser != nil {
		return in.removeUser(ctx, in.Host, name)
	}
	return svc.RemoveSystemUser(ctx, in.Host, name)
}

// writeRecord writes installed.json. As root, a record that names a service
// account (a system install, also after `uninstall --keep-data`) is given to
// that account, as the rest of the home is: written by root it would be
// root:root 0640, and the account could no longer read it (`sudo -u
// fileparcel fileparcel status` and `service`, doctor). The account is the
// host's, never the name read from the record.
func (in *Installer) writeRecord(h *home.Home, rec *svc.Installed) error {
	if err := svc.WriteInstalled(h, rec); err != nil {
		return err
	}
	if rec.ServiceUser != "" && in.Host.Root() {
		chown := in.chown
		if chown == nil {
			chown = func(p, account string) error {
				uid, gid, err := svc.AccountIDs(account)
				if err != nil {
					return err
				}
				return os.Lchown(p, uid, gid)
			}
		}
		// Best effort (the account may be gone after --remove-user).
		_ = chown(svc.InstalledPath(h), svc.ServiceUser(in.Host))
	}
	return nil
}

func (in *Installer) binaryInfo(ctx context.Context, bin string) (buildinfo.Info, error) {
	if in.BinaryInfo != nil {
		return in.BinaryInfo(ctx, bin)
	}
	return BinaryInfo(ctx, bin)
}

func (in *Installer) warnf(format string, a ...any) {
	if in.Err != nil {
		fmt.Fprintf(in.Err, "warning: "+format+"\n", a...)
	}
}

func (in *Installer) infof(format string, a ...any) {
	if in.Err != nil {
		fmt.Fprintf(in.Err, format+"\n", a...)
	}
}

func (in *Installer) interactive(yes bool) bool {
	return !yes && in.Prompt != nil && in.Prompt.Interactive()
}

// BinaryInfo runs `<bin> version --json` and decodes the build info (also a
// check that the binary runs on this machine).
func BinaryInfo(ctx context.Context, bin string) (buildinfo.Info, error) {
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, bin, "version", "--json")
	cmd.Env = append(os.Environ(), "FILEPARCEL_HOME=")
	out, err := cmd.Output()
	if err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) && len(ee.Stderr) > 0 {
			return buildinfo.Info{}, fmt.Errorf("%s does not run: %v: %s", bin, err, strings.TrimSpace(string(ee.Stderr)))
		}
		return buildinfo.Info{}, fmt.Errorf("%s does not run on this machine: %w", bin, err)
	}
	var bi buildinfo.Info
	if err := json.Unmarshal(out, &bi); err != nil || bi.Version == "" {
		return buildinfo.Info{}, fmt.Errorf("%s: unexpected `version --json` output", bin)
	}
	return bi, nil
}

// ---------- files ----------

// copyFile copies src to dst atomically (temp file in dst's directory,
// fsync, rename) with mode.
func copyFile(src, dst string, mode fs.FileMode) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(dst), "."+filepath.Base(dst)+".tmp*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	ok := false
	defer func() {
		if !ok {
			f.Close()
			os.Remove(tmp)
		}
	}()
	if _, err := io.Copy(f, in); err != nil {
		return err
	}
	if err := f.Chmod(mode); err != nil {
		return err
	}
	if err := f.Sync(); err != nil {
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp, dst); err != nil {
		return err
	}
	ok = true
	return nil
}

// sameFile reports whether a and b are the same file.
func sameFile(a, b string) bool {
	sa, err1 := os.Stat(a)
	sb, err2 := os.Stat(b)
	return err1 == nil && err2 == nil && os.SameFile(sa, sb)
}

// maxDocsBytes bounds the docs/ copy (a misdetected source dir must not
// copy a whole tree).
const maxDocsBytes = 64 << 20

// copyDocs copies the regular files under src (a docs/ directory) into dst
// (dirs 0750, files 0640), replacing dst's previous content.
func copyDocs(src, dst string) error {
	var total int64
	type item struct {
		rel string
		dir bool
	}
	var items []item
	err := filepath.WalkDir(src, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(src, p)
		if rel == "." {
			return nil
		}
		if strings.HasPrefix(d.Name(), ".") {
			if d.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		switch {
		case d.IsDir():
			items = append(items, item{rel, true})
		case d.Type().IsRegular():
			fi, err := d.Info()
			if err != nil {
				return err
			}
			total += fi.Size()
			if total > maxDocsBytes {
				return fmt.Errorf("%s is larger than %d MiB; not copying it", src, maxDocsBytes>>20)
			}
			items = append(items, item{rel, false})
		}
		return nil
	})
	if err != nil {
		return err
	}
	tmp := dst + ".new"
	_ = os.RemoveAll(tmp)
	// Explicit chmod: the process umask (077) would otherwise narrow 0750.
	mkdir := func(p string) error {
		if err := os.MkdirAll(p, home.ModeDocs); err != nil {
			return err
		}
		return os.Chmod(p, home.ModeDocs)
	}
	if err := mkdir(tmp); err != nil {
		return err
	}
	for _, it := range items {
		target := filepath.Join(tmp, it.rel)
		if it.dir {
			if err := mkdir(target); err != nil {
				return err
			}
			continue
		}
		if err := copyFile(filepath.Join(src, it.rel), target, 0o640); err != nil {
			return err
		}
	}
	old := dst + ".old"
	_ = os.RemoveAll(old)
	if _, err := os.Stat(dst); err == nil {
		if err := os.Rename(dst, old); err != nil {
			return err
		}
	}
	if err := os.Rename(tmp, dst); err != nil {
		return err
	}
	return os.RemoveAll(old)
}

// SupportFiles are the optional files installed next to the binary.
type SupportFiles struct {
	Uninstall string // path of uninstall.sh ("" = not found)
	Docs      string // path of docs/ ("" = not found)
}

// FindSupportFiles returns uninstall.sh and docs/ (either may be missing)
// from the first of dirs that is a directory: both always come from one
// source, so a source without docs/ never falls through to another one.
// Symlinks are not followed.
func FindSupportFiles(dirs ...string) SupportFiles {
	var sf SupportFiles
	for _, d := range dirs {
		if fi, err := os.Stat(d); d == "" || err != nil || !fi.IsDir() {
			continue
		}
		if fi, err := os.Lstat(filepath.Join(d, "uninstall.sh")); err == nil && fi.Mode().IsRegular() {
			sf.Uninstall = filepath.Join(d, "uninstall.sh")
		}
		if fi, err := os.Lstat(filepath.Join(d, "docs")); err == nil && fi.IsDir() {
			sf.Docs = filepath.Join(d, "docs")
		}
		break
	}
	return sf
}

// supportFiles returns the uninstall.sh and docs/ to install with binary
// bin: from explicit (--source, or the extracted release zip), else from
// $FILEPARCEL_INSTALL_SOURCE (install.sh sets it to its own directory),
// else from the verified release around bin (releaseFiles). Whatever else
// lies next to the binary (~/Downloads, /tmp) is never taken: uninstall.sh
// is installed as <HOME>/uninstall.sh, which root runs for system installs.
func (in *Installer) supportFiles(bin, explicit string) SupportFiles {
	dirs := []string{explicit}
	if s := in.env(SourceEnv); filepath.IsAbs(s) {
		dirs = append(dirs, s)
	}
	for _, d := range dirs {
		if fi, err := os.Stat(d); d != "" && err == nil && fi.IsDir() {
			return FindSupportFiles(d)
		}
	}
	if bin == "" {
		return SupportFiles{}
	}
	return in.releaseFiles(bin)
}

// releaseFiles returns the support files of the unpacked release that bin
// belongs to: bin's directory or its parent (release layout
// bin/fileparcel-<os>-<arch>) when its SHA256SUMS lists bin and uninstall.sh
// with their current hashes. SHA256SUMS, uninstall.sh and docs/ must belong
// to root, to this process's user or to the owner of bin (not to another
// account that shares the directory), and docs/ is taken only when
// SHA256SUMS lists files below it.
func (in *Installer) releaseFiles(bin string) SupportFiles {
	binOwner, _ := fileOwner(bin)
	trusted := func(p string, dir bool) bool {
		fi, err := os.Lstat(p)
		if err != nil || (dir && !fi.IsDir()) || (!dir && !fi.Mode().IsRegular()) {
			return false
		}
		uid, ok := fileOwner(p)
		return !ok || uid == 0 || uid == os.Geteuid() || uid == binOwner
	}
	d := filepath.Dir(bin)
	for _, root := range []string{d, filepath.Dir(d)} {
		sumsFile, uninstall := filepath.Join(root, "SHA256SUMS"), filepath.Join(root, "uninstall.sh")
		if !trusted(sumsFile, false) {
			continue
		}
		f, err := os.Open(sumsFile)
		if err != nil {
			continue
		}
		sums := parseSums(io.LimitReader(f, 1<<20))
		f.Close()
		rel, err := filepath.Rel(root, bin)
		if err != nil {
			continue
		}
		wantBin, wantUninstall := sums[filepath.ToSlash(rel)], sums["uninstall.sh"]
		if wantBin == "" || wantUninstall == "" {
			continue
		}
		if got, err := fileSHA256(bin); err != nil || got != wantBin {
			continue // another release's SHA256SUMS (or a rebuilt binary)
		}
		if !trusted(uninstall, false) {
			in.warnf("%s is missing, a symlink or another account's file; uninstall.sh and docs/ are not installed", uninstall)
			return SupportFiles{}
		}
		if got, err := fileSHA256(uninstall); err != nil || got != wantUninstall {
			in.warnf("%s does not match %s; uninstall.sh and docs/ are not installed", uninstall, sumsFile)
			return SupportFiles{}
		}
		sf := SupportFiles{Uninstall: uninstall}
		for name := range sums {
			if strings.HasPrefix(name, "docs/") {
				if docs := filepath.Join(root, "docs"); trusted(docs, true) {
					sf.Docs = docs
				}
				break
			}
		}
		return sf
	}
	return SupportFiles{}
}

// installFiles puts the binary (unless it already is the target), VERSION,
// uninstall.sh and docs/ into h.
func installFiles(h *home.Home, bin string, sf SupportFiles, info buildinfo.Info) error {
	if err := os.MkdirAll(h.BinDir(), home.ModeBin); err != nil {
		return err
	}
	if !sameFile(bin, h.Binary()) {
		if err := copyFile(bin, h.Binary(), 0o755); err != nil {
			return fmt.Errorf("copy binary: %w", err)
		}
	}
	if err := svc.WriteFileAtomic(h.VersionFile(), []byte(info.String()+"\n"), 0o644); err != nil {
		return err
	}
	if sf.Uninstall != "" && !sameFile(sf.Uninstall, h.UninstallScript()) {
		if err := copyFile(sf.Uninstall, h.UninstallScript(), 0o755); err != nil {
			return fmt.Errorf("copy uninstall.sh: %w", err)
		}
	}
	if sf.Docs != "" && !sameFile(sf.Docs, h.DocsDir()) {
		if err := copyDocs(sf.Docs, h.DocsDir()); err != nil {
			return fmt.Errorf("copy docs: %w", err)
		}
	}
	return nil
}

// serverRunning reports whether another process holds the home lock (a
// running server or an offline CLI command).
func serverRunning(h *home.Home) bool {
	unlock, err := h.Lock()
	if err != nil {
		return errors.Is(err, home.ErrLocked)
	}
	unlock()
	return false
}

// handServer returns the pid of a server started by hand that holds h's
// lock: the pid of run/fileparcel.pid when that process is a fileparcel
// (0 otherwise: no such server, or not verifiable).
func (in *Installer) handServer(h *home.Home) int {
	if in.HandServer != nil {
		return in.HandServer(h)
	}
	if !serverRunning(h) {
		return 0
	}
	b, err := os.ReadFile(h.PIDFile())
	if err != nil {
		return 0
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(b)))
	if err != nil || !processIsFileParcel(pid) {
		return 0
	}
	return pid
}

// stopServer stops a server started by hand (SIGTERM) and waits up to 40 s
// until the home is free.
func (in *Installer) stopServer(ctx context.Context, h *home.Home, pid int) error {
	if in.StopServer != nil {
		return in.StopServer(ctx, h, pid)
	}
	ctx, cancel := context.WithTimeout(ctx, 40*time.Second)
	defer cancel()
	if err := terminateProcess(ctx, pid, func() bool { return !serverRunning(h) }); err != nil {
		return fmt.Errorf("the server (pid %d) did not stop: %w; stop it yourself", pid, err)
	}
	return nil
}

func itoa(n int) string { return strconv.Itoa(n) }

// readVersion returns the first line of <HOME>/VERSION ("" when absent).
func readVersion(h *home.Home) string {
	b, err := os.ReadFile(h.VersionFile())
	if err != nil {
		return ""
	}
	line, _, _ := strings.Cut(string(b), "\n")
	return strings.TrimSpace(line)
}

// managerFor returns the service manager recorded for h (nil for none).
func (in *Installer) managerFor(h *home.Home, rec *svc.Installed, boot bool) (svc.Manager, error) {
	if rec == nil || rec.Kind == svc.KindNone || rec.Kind == "" {
		return nil, nil
	}
	// The service account is the host's, never installed.json's
	// service_user (the account itself can write that file).
	o := svc.Options{Kind: rec.Kind, Home: h.Dir(), Binary: h.Binary(), Boot: boot, User: svc.ServiceUser(in.Host),
		HTTPSPort: rec.HTTPSPort, HTTPPort: rec.HTTPPort}
	return svc.NewManager(in.Host, o)
}
