//go:build unix

package home

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

// Lock takes an exclusive, non-blocking flock(2) on run/fileparcel.lock.
// It is held by `serve` for its lifetime and by the offline CLI mode.
//
// It returns ErrLocked when another process (or another open file description
// in this process) holds the lock. The returned unlock func releases the lock
// and closes the file; it is idempotent. The lock is released automatically
// by the kernel if the process dies. The run/ directory is created if needed.
func (h *Home) Lock() (unlock func(), err error) {
	if err := os.MkdirAll(h.RunDir(), ModePrivate); err != nil {
		return nil, fmt.Errorf("home: lock: %w", err)
	}
	f, err := os.OpenFile(h.LockFile(), os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return nil, fmt.Errorf("home: lock: %w", err)
	}
	for {
		err = unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB)
		if !errors.Is(err, unix.EINTR) {
			break
		}
	}
	if err != nil {
		f.Close()
		if errors.Is(err, unix.EWOULDBLOCK) || errors.Is(err, unix.EAGAIN) {
			return nil, ErrLocked
		}
		return nil, fmt.Errorf("home: lock %s: %w", filepath.Base(h.LockFile()), err)
	}
	done := false
	return func() {
		if done {
			return
		}
		done = true
		_ = unix.Flock(int(f.Fd()), unix.LOCK_UN)
		_ = f.Close()
	}, nil
}
