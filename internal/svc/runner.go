package svc

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"
)

// Result is the outcome of one external command.
type Result struct {
	Stdout   []byte
	Stderr   []byte
	ExitCode int
}

// Runner runs external commands (systemctl, loginctl, launchctl, useradd,
// dscl, firewall tools). Implementations return a *CommandError for a
// non-zero exit status (Result is filled either way) and another error when
// the command could not be started.
type Runner interface {
	Run(ctx context.Context, env []string, name string, args ...string) (Result, error)
}

// CommandError is a command that ran and failed.
type CommandError struct {
	Cmd      string
	ExitCode int
	Stderr   string
}

// Error implements error: "systemctl --user start x: exit 1: <stderr>".
func (e *CommandError) Error() string {
	msg := fmt.Sprintf("%s: exit %d", e.Cmd, e.ExitCode)
	if s := strings.TrimSpace(e.Stderr); s != "" {
		if len(s) > 500 {
			s = s[:500] + "…"
		}
		msg += ": " + s
	}
	return msg
}

// ExitCodeOf returns the exit code of a *CommandError in err (-1 otherwise).
func ExitCodeOf(err error) int {
	var ce *CommandError
	if errors.As(err, &ce) {
		return ce.ExitCode
	}
	return -1
}

// CommandLine renders name and args as a shell-like line (for logs and
// dry-run output; arguments with special characters are single-quoted).
func CommandLine(name string, args ...string) string {
	parts := make([]string, 0, len(args)+1)
	for _, a := range append([]string{name}, args...) {
		parts = append(parts, ShellQuote(a))
	}
	return strings.Join(parts, " ")
}

// ShellQuote quotes s for POSIX sh when needed.
func ShellQuote(s string) string {
	if s == "" {
		return "''"
	}
	safe := true
	for _, r := range s {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || strings.ContainsRune("@%+=:,./-_", r)) {
			safe = false
			break
		}
	}
	if safe {
		return s
	}
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// ExecRunner runs commands with os/exec. Each command gets Timeout (default
// 60 s); env entries are appended to the process environment.
type ExecRunner struct {
	Timeout time.Duration
}

// Run implements Runner.
func (x ExecRunner) Run(ctx context.Context, env []string, name string, args ...string) (Result, error) {
	to := x.Timeout
	if to <= 0 {
		to = 60 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, to)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Env = append(os.Environ(), env...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	cmd.WaitDelay = 5 * time.Second
	err := cmd.Run()
	res := Result{Stdout: stdout.Bytes(), Stderr: stderr.Bytes()}
	if err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			res.ExitCode = ee.ExitCode()
			return res, &CommandError{Cmd: CommandLine(name, args...), ExitCode: res.ExitCode, Stderr: stderr.String()}
		}
		return res, fmt.Errorf("%s: %w", CommandLine(name, args...), err)
	}
	return res, nil
}

// Host describes the machine and account the installer runs on. Tests
// replace every field; CurrentHost fills them from the running process.
type Host struct {
	GOOS    string
	UID     int
	GID     int
	User    string // login name of UID
	HomeDir string // $HOME of User
	Runner  Runner
	// Getenv reads the environment (os.Getenv).
	Getenv func(string) string
	// LookPath finds executables (exec.LookPath).
	LookPath func(string) (string, error)
	// Paths of the registration directories (defaults from DefaultPaths).
	Paths Paths
}

// Paths are the directories the service registrations live in.
type Paths struct {
	// UserUnitDir is where `systemctl --user link` registers user units:
	// the user manager's ~/.config/systemd/user (its own $XDG_CONFIG_HOME,
	// not this process's). Empty: asked from the user manager when first
	// needed (Host.userUnitDir).
	UserUnitDir      string
	SystemUnitDir    string // /etc/systemd/system
	LaunchAgentsDir  string // ~/Library/LaunchAgents
	LaunchDaemonsDir string // /Library/LaunchDaemons
	LingerDir        string // /var/lib/systemd/linger
	RunUserDir       string // /run/user (XDG_RUNTIME_DIR parent)
	SystemdRunDir    string // /run/systemd/system: exists while systemd is the init (sd_booted); "" = assume it is
}

// DefaultPaths returns the standard registration directories for a user
// whose home directory is userHome. UserUnitDir is left empty: the user
// manager, not the environment, says where it is.
func DefaultPaths(userHome string) Paths {
	return Paths{
		SystemUnitDir:    "/etc/systemd/system",
		LaunchAgentsDir:  filepath.Join(userHome, "Library", "LaunchAgents"),
		LaunchDaemonsDir: "/Library/LaunchDaemons",
		LingerDir:        "/var/lib/systemd/linger",
		RunUserDir:       "/run/user",
		SystemdRunDir:    "/run/systemd/system",
	}
}

// CurrentHost describes the running process.
func CurrentHost() *Host {
	h := &Host{
		GOOS: runtime.GOOS, UID: os.Geteuid(), GID: os.Getegid(),
		Runner: ExecRunner{}, Getenv: os.Getenv, LookPath: exec.LookPath,
	}
	if u, err := user.LookupId(strconv.Itoa(h.UID)); err == nil {
		h.User, h.HomeDir = u.Username, u.HomeDir
	}
	if h.User == "" {
		h.User = os.Getenv("USER")
	}
	if hd, err := os.UserHomeDir(); err == nil && (h.HomeDir == "" || h.UID != 0) {
		h.HomeDir = hd
	}
	h.Paths = DefaultPaths(h.HomeDir)
	return h
}

// Root reports whether the host runs as root.
func (h *Host) Root() bool { return h.UID == 0 }

func (h *Host) getenv(k string) string {
	if h.Getenv == nil {
		return ""
	}
	return h.Getenv(k)
}

// Has reports whether an executable is available.
func (h *Host) Has(name string) bool {
	if h.LookPath == nil {
		return false
	}
	_, err := h.LookPath(name)
	return err == nil
}

func (h *Host) run(ctx context.Context, env []string, name string, args ...string) (Result, error) {
	if h.Runner == nil {
		return Result{}, errors.New("svc: no command runner")
	}
	return h.Runner.Run(ctx, env, name, args...)
}
