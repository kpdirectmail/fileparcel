// Package home resolves and describes the self-contained FileParcel install
// directory ("HOME", DESIGN §3). Everything the server owns — config, DB,
// blobs, keys, certs, backups, logs, tmp and the admin socket — lives below it.
//
// Resolution precedence (Resolve): --home flag > $FILEPARCEL_HOME > the
// directory of the running binary (symlinks resolved) or its parent, whichever
// contains fileparcel.toml.
package home

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
)

// Well-known names.
const (
	// ConfigName is the bootstrap config file; it doubles as the home marker.
	ConfigName = "fileparcel.toml"
	// EnvVar is the environment variable that selects the home directory.
	EnvVar = "FILEPARCEL_HOME"
	// BinaryName is the executable name inside bin/.
	BinaryName = "fileparcel"
)

// Directory and file modes of the layout (DESIGN §3).
const (
	ModeHome    fs.FileMode = 0o750
	ModePrivate fs.FileMode = 0o700 // data, keys, certs, backups, tmp, run
	ModeLogs    fs.FileMode = 0o750
	ModeBin     fs.FileMode = 0o755
	ModeService fs.FileMode = 0o750
	ModeDocs    fs.FileMode = 0o750
	ModeConfig  fs.FileMode = 0o640 // fileparcel.toml
	ModeSecret  fs.FileMode = 0o600 // keys/master.key and other secret files
	// ModeSystemHome is the HOME of a system install, owned by
	// root:<service group> (DESIGN §14.4): the service account writes in
	// it, and the sticky bit keeps it from renaming or replacing the
	// root-owned bin/ and uninstall.sh. EnsureLayout leaves it as it is.
	ModeSystemHome fs.FileMode = 0o770 | fs.ModeSticky
)

// IsSystemHomeMode reports whether mode is ModeSystemHome.
func IsSystemHomeMode(mode fs.FileMode) bool {
	return mode.IsDir() && mode&(fs.ModePerm|fs.ModeSticky|fs.ModeSetuid|fs.ModeSetgid) == ModeSystemHome
}

// Tmp sub-directories created by EnsureLayout.
const (
	TmpUploads = "uploads"
	TmpZip     = "zip"
	TmpRestore = "restore"
	TmpVerify  = "verify"
)

// ErrNoHome is returned by Resolve when no home can be located.
var ErrNoHome = errors.New(`no FileParcel home found; run "fileparcel init --home DIR"`)

// ErrLocked is returned by Lock when another process holds the home lock
// (a running server, or another offline CLI invocation).
var ErrLocked = errors.New("the FileParcel home is locked by another process (is the server running?)")

// Home is an absolute install directory. All accessors return absolute paths.
// A Home value is immutable and safe for concurrent use.
type Home struct {
	dir string
}

// New returns a Home for dir (made absolute and cleaned). It does not check
// that the directory exists or contains fileparcel.toml; `init` uses it to
// describe a home that is about to be created.
func New(dir string) (*Home, error) {
	if dir == "" {
		return nil, errors.New("home: empty directory")
	}
	abs, err := filepath.Abs(dir)
	if err != nil {
		return nil, fmt.Errorf("home: %w", err)
	}
	return &Home{dir: filepath.Clean(abs)}, nil
}

// Resolve locates the home directory.
//
// An explicit location (flag, then $FILEPARCEL_HOME) is returned as-is without
// requiring the marker file, so that `init --home DIR` and
// `serve --init-if-missing` can work with a not-yet-initialised directory;
// callers that need an initialised home check h.Exists(). Otherwise the
// directory of the running executable (after EvalSymlinks) and then its parent
// are tried; the first that contains fileparcel.toml wins. If none does,
// ErrNoHome is returned.
func Resolve(flag string) (*Home, error) {
	if flag != "" {
		return New(flag)
	}
	if env := os.Getenv(EnvVar); env != "" {
		return New(env)
	}
	exe, err := os.Executable()
	if err != nil {
		return nil, ErrNoHome
	}
	if real, err := filepath.EvalSymlinks(exe); err == nil {
		exe = real
	}
	dir := filepath.Dir(exe)
	for _, cand := range []string{dir, filepath.Dir(dir)} {
		if IsHome(cand) {
			return New(cand)
		}
	}
	return nil, ErrNoHome
}

// IsHome reports whether dir contains a regular fileparcel.toml file.
func IsHome(dir string) bool {
	st, err := os.Stat(filepath.Join(dir, ConfigName))
	return err == nil && st.Mode().IsRegular()
}

// Exists reports whether this home is initialised (contains fileparcel.toml).
func (h *Home) Exists() bool { return IsHome(h.dir) }

// Dir returns the absolute home directory.
func (h *Home) Dir() string { return h.dir }

// String returns the home directory.
func (h *Home) String() string { return h.dir }

// Path joins elem onto the home directory.
func (h *Home) Path(elem ...string) string {
	return filepath.Join(append([]string{h.dir}, elem...)...)
}

// Config returns <HOME>/fileparcel.toml.
func (h *Home) Config() string { return h.Path(ConfigName) }

// VersionFile returns <HOME>/VERSION.
func (h *Home) VersionFile() string { return h.Path("VERSION") }

// BinDir returns <HOME>/bin.
func (h *Home) BinDir() string { return h.Path("bin") }

// Binary returns <HOME>/bin/fileparcel.
func (h *Home) Binary() string { return h.Path("bin", BinaryName) }

// PrevBinary returns <HOME>/bin/fileparcel.prev (rollback copy).
func (h *Home) PrevBinary() string { return h.Path("bin", BinaryName+".prev") }

// DocsDir returns <HOME>/docs.
func (h *Home) DocsDir() string { return h.Path("docs") }

// UninstallScript returns <HOME>/uninstall.sh.
func (h *Home) UninstallScript() string { return h.Path("uninstall.sh") }

// DataDir returns <HOME>/data.
func (h *Home) DataDir() string { return h.Path("data") }

// DB returns <HOME>/data/fileparcel.db.
func (h *Home) DB() string { return h.Path("data", "fileparcel.db") }

// BlobsDir returns <HOME>/data/blobs.
func (h *Home) BlobsDir() string { return h.Path("data", "blobs") }

// KeysDir returns <HOME>/keys.
func (h *Home) KeysDir() string { return h.Path("keys") }

// KeysFile returns <HOME>/keys/master.key.
func (h *Home) KeysFile() string { return h.Path("keys", "master.key") }

// CertsDir returns <HOME>/certs.
func (h *Home) CertsDir() string { return h.Path("certs") }

// BackupsDir returns <HOME>/backups.
func (h *Home) BackupsDir() string { return h.Path("backups") }

// LogsDir returns <HOME>/logs.
func (h *Home) LogsDir() string { return h.Path("logs") }

// LogFile returns <HOME>/logs/fileparcel.log.
func (h *Home) LogFile() string { return h.Path("logs", "fileparcel.log") }

// TmpDir returns <HOME>/tmp/<sub> (or <HOME>/tmp when sub is empty). Use the
// Tmp* constants for sub.
func (h *Home) TmpDir(sub string) string {
	if sub == "" {
		return h.Path("tmp")
	}
	return h.Path("tmp", sub)
}

// RunDir returns <HOME>/run.
func (h *Home) RunDir() string { return h.Path("run") }

// Socket returns <HOME>/run/admin.sock (the admin Unix socket).
func (h *Home) Socket() string { return h.Path("run", "admin.sock") }

// LockFile returns <HOME>/run/fileparcel.lock.
func (h *Home) LockFile() string { return h.Path("run", "fileparcel.lock") }

// PIDFile returns <HOME>/run/fileparcel.pid.
func (h *Home) PIDFile() string { return h.Path("run", "fileparcel.pid") }

// CleanShutdownFile returns <HOME>/run/clean-shutdown.
func (h *Home) CleanShutdownFile() string { return h.Path("run", "clean-shutdown") }

// RestoreFile returns <HOME>/run/restore.json (scheduled restore request).
func (h *Home) RestoreFile() string { return h.Path("run", "restore.json") }

// ServiceDir returns <HOME>/service.
func (h *Home) ServiceDir() string { return h.Path("service") }

type layoutDir struct {
	rel  string
	mode fs.FileMode
}

// layout lists every directory EnsureLayout creates, parents first.
var layout = []layoutDir{
	{"bin", ModeBin},
	{"docs", ModeDocs},
	{"data", ModePrivate},
	{"data/blobs", ModePrivate},
	{"keys", ModePrivate},
	{"certs", ModePrivate},
	{"certs/ca", ModePrivate},
	{"certs/server", ModePrivate},
	{"certs/acme", ModePrivate},
	{"certs/tailscale", ModePrivate},
	{"certs/custom", ModePrivate},
	{"backups", ModePrivate},
	{"logs", ModeLogs},
	{"tmp", ModePrivate},
	{"tmp/" + TmpUploads, ModePrivate},
	{"tmp/" + TmpZip, ModePrivate},
	{"tmp/" + TmpRestore, ModePrivate},
	{"tmp/" + TmpVerify, ModePrivate},
	{"run", ModePrivate},
	{"service", ModeService},
}

// EnsureLayout creates the home directory and every sub-directory of DESIGN §3
// and (re)applies their modes explicitly, so the result does not depend on the
// process umask. It never touches files. Safe to call repeatedly.
func (h *Home) EnsureLayout() error {
	// A system install's HOME (ModeSystemHome, owned by root) is kept as it
	// is: the service account cannot chmod it, and its sticky bit must stay.
	if st, err := os.Stat(h.dir); err != nil || !IsSystemHomeMode(st.Mode()) {
		if err := ensureDir(h.dir, ModeHome); err != nil {
			return err
		}
	}
	for _, d := range layout {
		if err := ensureDir(filepath.Join(h.dir, filepath.FromSlash(d.rel)), d.mode); err != nil {
			return err
		}
	}
	return nil
}

func ensureDir(p string, mode fs.FileMode) error {
	if err := os.MkdirAll(p, mode); err != nil {
		return fmt.Errorf("home: create %s: %w", p, err)
	}
	st, err := os.Stat(p)
	if err != nil {
		return fmt.Errorf("home: %w", err)
	}
	if !st.IsDir() {
		return fmt.Errorf("home: %s exists and is not a directory", p)
	}
	if st.Mode().Perm() != mode {
		if err := os.Chmod(p, mode); err != nil {
			return fmt.Errorf("home: chmod %s: %w", p, err)
		}
	}
	return nil
}
