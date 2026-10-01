//go:build unix

package installer

import (
	"context"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"syscall"
	"time"
)

// processIsFileParcel reports whether pid is a running fileparcel process
// (a stale PID file may name a reused pid): /proc/<pid>/comm on Linux, ps
// elsewhere — like uninstall.sh does.
func processIsFileParcel(pid int) bool {
	if pid <= 1 {
		return false
	}
	if err := syscall.Kill(pid, 0); err != nil && err != syscall.EPERM {
		return false
	}
	if runtime.GOOS == "linux" {
		b, err := os.ReadFile("/proc/" + itoa(pid) + "/comm")
		return err == nil && strings.HasPrefix(strings.TrimSpace(string(b)), "fileparcel")
	}
	out, err := exec.Command("ps", "-p", itoa(pid), "-o", "comm=").Output()
	return err == nil && strings.Contains(string(out), "fileparcel")
}

// terminateProcess sends SIGTERM to pid and waits until gone() or ctx ends.
func terminateProcess(ctx context.Context, pid int, gone func() bool) error {
	if err := syscall.Kill(pid, syscall.SIGTERM); err != nil && err != syscall.ESRCH {
		return err
	}
	t := time.NewTicker(250 * time.Millisecond)
	defer t.Stop()
	for !gone() {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-t.C:
		}
	}
	return nil
}
