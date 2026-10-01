// Package logx builds the process logger: log/slog to stderr and (optionally)
// to a size-rotated file <HOME>/logs/fileparcel.log (+ .1 … .N), configured by
// the [log] section of fileparcel.toml.
//
// The level is process-global and can be changed live with SetLevel (the
// settings package does this when log.level changes).
package logx

import (
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"fileparcel/internal/config"
)

var level = new(slog.LevelVar) // default Info

// SetLevel changes the global log level: "debug", "info", "warn" or "error".
func SetLevel(s string) error {
	l, err := ParseLevel(s)
	if err != nil {
		return err
	}
	level.Set(l)
	return nil
}

// Level returns the current global level name.
func Level() string { return strings.ToLower(level.Level().String()) }

// Leveler returns the live global level (for custom handlers).
func Leveler() slog.Leveler { return level }

// ParseLevel parses debug|info|warn|error (case-insensitive; "warning" accepted).
func ParseLevel(s string) (slog.Level, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "debug":
		return slog.LevelDebug, nil
	case "info", "":
		return slog.LevelInfo, nil
	case "warn", "warning":
		return slog.LevelWarn, nil
	case "error":
		return slog.LevelError, nil
	}
	return 0, fmt.Errorf("logx: unknown level %q", s)
}

// Options configures New.
type Options struct {
	Config config.LogConfig
	// Dir is the logs directory (home.LogsDir()); the file is Dir/fileparcel.log.
	Dir string
	// Stderr receives console logs; nil disables console logging.
	Stderr io.Writer
	// StderrQuiet limits console output to warn and above regardless of the
	// global level (CLI offline mode, so command output stays clean).
	StderrQuiet bool
}

// FileName is the active log file name inside the logs directory.
const FileName = "fileparcel.log"

// New builds the logger and sets the global level from o.Config.Level. The
// returned closer closes the log file (if any). Console output is always text;
// the file uses o.Config.Format (text|json).
func New(o Options) (*slog.Logger, io.Closer, error) {
	if err := SetLevel(o.Config.Level); err != nil {
		return nil, nil, err
	}
	var handlers []slog.Handler
	if o.Stderr != nil {
		var lv slog.Leveler = level
		if o.StderrQuiet {
			lv = maxLevel{level, slog.LevelWarn}
		}
		handlers = append(handlers, slog.NewTextHandler(o.Stderr, &slog.HandlerOptions{Level: lv}))
	}
	var closer io.Closer = nopCloser{}
	if o.Config.File && o.Dir != "" {
		maxSize := int64(o.Config.MaxSizeMB) << 20
		if maxSize <= 0 {
			maxSize = 50 << 20
		}
		files := o.Config.MaxFiles
		if files <= 0 {
			files = 5
		}
		rw, err := NewRotatingFile(filepath.Join(o.Dir, FileName), maxSize, files)
		if err != nil {
			return nil, nil, err
		}
		closer = rw
		hopts := &slog.HandlerOptions{Level: level}
		if o.Config.Format == "json" {
			handlers = append(handlers, slog.NewJSONHandler(rw, hopts))
		} else {
			handlers = append(handlers, slog.NewTextHandler(rw, hopts))
		}
	}
	var h slog.Handler
	switch len(handlers) {
	case 0:
		h = slog.DiscardHandler
	case 1:
		h = handlers[0]
	default:
		h = slog.NewMultiHandler(handlers...)
	}
	return slog.New(h), closer, nil
}

type maxLevel struct{ a, b slog.Leveler }

func (m maxLevel) Level() slog.Level { return max(m.a.Level(), m.b.Level()) }

type nopCloser struct{}

func (nopCloser) Close() error { return nil }

// RotatingFile is an io.WriteCloser that rotates path to path.1 … path.N when
// it would exceed maxSize bytes. It is safe for concurrent use.
//
// If the file cannot be opened again after a rotation (descriptor or inode
// exhaustion, a permission change …), writes fail but the file is retried at
// most every reopenDelay, so a passing problem does not end file logging for
// the rest of the process. Only Close makes the failure permanent.
type RotatingFile struct {
	mu      sync.Mutex
	path    string
	maxSize int64
	keep    int
	f       *os.File
	size    int64
	closed  bool      // Close was called
	retryAt time.Time // no reopen attempt before this
	openErr error     // why the last (re)open failed; nil while the file is open
}

// reopenDelay is the minimum time between two attempts to reopen a lost file.
var reopenDelay = 5 * time.Second

// reportTo receives the one-line notice that the file was lost or recovered:
// the logger cannot report the failure of its own file through itself, and
// stderr ends up in the journal (or launchd's log) either way.
var reportTo io.Writer = os.Stderr

// NewRotatingFile opens (appends to) path with mode 0640, keeping keep rotated files.
func NewRotatingFile(path string, maxSize int64, keep int) (*RotatingFile, error) {
	r := &RotatingFile{path: path, maxSize: maxSize, keep: keep}
	if err := r.open(); err != nil {
		return nil, err
	}
	return r, nil
}

func (r *RotatingFile) open() error {
	if err := os.MkdirAll(filepath.Dir(r.path), 0o750); err != nil {
		return fmt.Errorf("logx: %w", err)
	}
	f, err := os.OpenFile(r.path, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o640)
	if err != nil {
		return fmt.Errorf("logx: %w", err)
	}
	st, err := f.Stat()
	if err != nil {
		f.Close()
		return fmt.Errorf("logx: %w", err)
	}
	r.f, r.size = f, st.Size()
	return nil
}

// reopen opens the file after it was lost, rate-limiting further attempts on
// failure and reporting only the first failure (and the recovery).
func (r *RotatingFile) reopen() error {
	if err := r.open(); err != nil {
		r.retryAt = time.Now().Add(reopenDelay)
		if r.openErr == nil {
			fmt.Fprintf(reportTo, "%v; file logging paused, retrying\n", err)
		}
		r.openErr = err
		return err
	}
	if r.openErr != nil {
		fmt.Fprintf(reportTo, "logx: reopened %s; file logging resumed\n", r.path)
		r.openErr = nil
	}
	return nil
}

// ensureOpen makes sure r.f is usable: os.ErrClosed after Close, the last
// open error while a reopen attempt is not yet due. r.mu must be held.
func (r *RotatingFile) ensureOpen() error {
	switch {
	case r.f != nil:
		return nil
	case r.closed:
		return os.ErrClosed
	case time.Now().Before(r.retryAt):
		return r.openErr
	}
	return r.reopen()
}

// Write appends p, rotating first if the file would exceed the size limit.
func (r *RotatingFile) Write(p []byte) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if err := r.ensureOpen(); err != nil {
		return 0, err
	}
	if r.size > 0 && r.size+int64(len(p)) > r.maxSize {
		if err := r.rotate(); err != nil {
			return 0, err
		}
	}
	n, err := r.f.Write(p)
	r.size += int64(n)
	return n, err
}

func (r *RotatingFile) rotate() error {
	_ = r.f.Close()
	r.f = nil
	_ = os.Remove(fmt.Sprintf("%s.%d", r.path, r.keep))
	for i := r.keep - 1; i >= 1; i-- {
		_ = os.Rename(fmt.Sprintf("%s.%d", r.path, i), fmt.Sprintf("%s.%d", r.path, i+1))
	}
	if r.keep >= 1 {
		_ = os.Rename(r.path, r.path+".1")
	} else {
		_ = os.Remove(r.path)
	}
	return r.reopen()
}

// Rotate forces a rotation.
func (r *RotatingFile) Rotate() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if err := r.ensureOpen(); err != nil {
		return err
	}
	return r.rotate()
}

// Close closes the file. Later writes fail with os.ErrClosed.
func (r *RotatingFile) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.closed = true
	if r.f == nil {
		return nil
	}
	err := r.f.Close()
	r.f = nil
	return err
}
