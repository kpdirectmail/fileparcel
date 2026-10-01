package server

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// maxSocketPath is the usable length of sockaddr_un.sun_path (including the
// terminating NUL: 108 bytes on Linux, 104 on macOS/BSD). Longer paths are
// reached through a short alias (DESIGN §18.17), see shortSocketPath.
var maxSocketPath = sunPathMax - 1

// socketListener is the admin Unix socket: only peers with the same uid as
// the server (or root) are accepted (SO_PEERCRED / LOCAL_PEERCRED).
type socketListener struct {
	*net.UnixListener
	path   string
	log    *slog.Logger
	uid    int
	remove sync.Once
}

// listenSocket creates the admin socket at path (0600). A stale socket file
// is removed; a socket that still answers means another server is running.
func listenSocket(path string, log *slog.Logger) (*socketListener, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	if fi, err := os.Lstat(path); err == nil {
		if fi.Mode()&os.ModeSocket == 0 {
			return nil, fmt.Errorf("%s exists and is not a socket", path)
		}
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		c, derr := DialSocket(ctx, path)
		cancel()
		if derr == nil {
			c.Close()
			return nil, fmt.Errorf("another server is listening on %s", path)
		}
		if err := os.Remove(path); err != nil {
			return nil, fmt.Errorf("remove stale socket: %w", err)
		}
	}
	ul, err := bindUnix(path)
	if err != nil {
		return nil, err
	}
	// The listener may have been bound through an alias path; never let
	// Close unlink by that name — removeFile unlinks the real path.
	ul.SetUnlinkOnClose(false)
	if err := os.Chmod(path, 0o600); err != nil {
		ul.Close()
		_ = os.Remove(path)
		return nil, err
	}
	return &socketListener{UnixListener: ul, path: path, log: log, uid: os.Getuid()}, nil
}

// bindUnix listens on path, working around the sun_path length limit.
func bindUnix(path string) (*net.UnixListener, error) {
	if len(path) <= maxSocketPath {
		return net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	}
	var ul *net.UnixListener
	err := withShortSocketPath(path, func(short string) error {
		var err error
		ul, err = net.ListenUnix("unix", &net.UnixAddr{Name: short, Net: "unix"})
		return err
	})
	return ul, err
}

// DialSocket connects to the admin socket at path, handling paths longer
// than the platform's sun_path limit (DESIGN §18.17). The CLI uses it.
func DialSocket(ctx context.Context, path string) (net.Conn, error) {
	var d net.Dialer
	if len(path) <= maxSocketPath {
		return d.DialContext(ctx, "unix", path)
	}
	var c net.Conn
	err := withShortSocketPath(path, func(short string) error {
		var err error
		c, err = d.DialContext(ctx, "unix", short)
		return err
	})
	return c, err
}

// chdirMu serializes the chdir fallback of withShortSocketPath.
var chdirMu sync.Mutex

// withShortSocketPath calls fn with a short name for path: on Linux
// "/proc/self/fd/<dirfd>/<base>" (the kernel resolves the directory through
// the descriptor), otherwise — or when /proc is unavailable — the bare base
// name after a temporary chdir into the directory (process-wide, so it is
// serialized and kept as short as possible).
func withShortSocketPath(path string, fn func(short string) error) error {
	dir, base := filepath.Split(path)
	if len(base) > maxSocketPath-1 {
		return fmt.Errorf("socket name %q is too long", base)
	}
	if d, err := os.Open(dir); err == nil {
		short := fmt.Sprintf("/proc/self/fd/%d/%s", d.Fd(), base)
		if len(short) <= maxSocketPath && procFDWorks(d) {
			err := fn(short)
			d.Close()
			return err
		}
		d.Close()
	}
	chdirMu.Lock()
	defer chdirMu.Unlock()
	wd, err := os.Getwd()
	if err != nil {
		return err
	}
	if err := os.Chdir(dir); err != nil {
		return err
	}
	ferr := fn(base)
	if err := os.Chdir(wd); err != nil {
		return errors.Join(ferr, fmt.Errorf("restore working directory: %w", err))
	}
	return ferr
}

// procFDWorks reports whether /proc/self/fd/<fd> resolves to the opened
// directory (Linux with /proc mounted).
func procFDWorks(d *os.File) bool {
	fi1, err := d.Stat()
	if err != nil {
		return false
	}
	fi2, err := os.Stat(fmt.Sprintf("/proc/self/fd/%d", d.Fd()))
	return err == nil && os.SameFile(fi1, fi2)
}

// Accept returns the next connection whose peer passes the credential check.
func (l *socketListener) Accept() (net.Conn, error) {
	for {
		c, err := l.AcceptUnix()
		if err != nil {
			return nil, err
		}
		uid, err := peerUID(c)
		if err != nil || (uid != l.uid && uid != 0) {
			l.log.Warn("admin socket: connection refused", "peer_uid", uid, "err", err)
			c.Close()
			continue
		}
		return c, nil
	}
}

// removeFile unlinks the socket file (once).
func (l *socketListener) removeFile() {
	l.remove.Do(func() {
		if err := os.Remove(l.path); err != nil && !errors.Is(err, os.ErrNotExist) {
			l.log.Warn("cannot remove the admin socket", "err", err)
		}
	})
}
