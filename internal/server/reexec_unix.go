//go:build unix

package server

import (
	"os"
	"path/filepath"
	"syscall"
)

// ReExec replaces the current process with a fresh copy of the same binary
// and arguments (restart without a supervisor, DESIGN §11.3). Call it only
// after every resource was released (database closed, home lock released);
// on success it does not return.
func ReExec() error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	if resolved, err := filepath.EvalSymlinks(exe); err == nil {
		exe = resolved
	}
	return syscall.Exec(exe, os.Args, os.Environ())
}
