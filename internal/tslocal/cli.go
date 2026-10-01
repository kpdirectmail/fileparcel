package tslocal

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

// RunCLI runs the tailscale command with args (stdout ≤ 8 MiB, stderr
// ≤ 4 KiB kept, WaitDelay 1 s). Failures whose output matches a known
// tailscaled refusal wrap the sentinel error (ErrUnixForbidden, …).
func (c *Client) RunCLI(ctx context.Context, timeout time.Duration, args ...string) ([]byte, error) {
	bin := c.cli()
	if bin == "" {
		return nil, fmt.Errorf("tailscale CLI not found: %w", exec.ErrNotFound)
	}
	return c.runCLI(ctx, bin, timeout, args...)
}

func (c *Client) runCLI(ctx context.Context, bin string, timeout time.Duration, args ...string) ([]byte, error) {
	if timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	}
	cmd := exec.CommandContext(ctx, bin, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &limitedWriter{w: &stdout, n: maxBody}
	cmd.Stderr = &truncatingWriter{w: &stderr, n: maxStderr}
	cmd.WaitDelay = time.Second
	err := cmd.Run()
	if err == nil {
		return stdout.Bytes(), nil
	}
	// tailscale prints some refusals on stdout; look at both.
	text := strings.TrimSpace(stderr.String())
	if text == "" {
		text = strings.TrimSpace(clip(stdout.String(), maxStderr))
	}
	name := "tailscale " + strings.Join(args, " ")
	if ctx.Err() != nil {
		return nil, fmt.Errorf("%s: %w", name, ctx.Err())
	}
	// The output goes last: joinDistinct recognises the same complaint of
	// the LocalAPI and the CLI by its common tail.
	if s := sentinelText(text); s != nil {
		return nil, fmt.Errorf("%w: %s: %s", s, name, clip(firstLine(text), maxErrBody))
	}
	if text != "" {
		return nil, fmt.Errorf("%s: %w: %s", name, err, clip(firstLine(text), maxErrBody))
	}
	return nil, fmt.Errorf("%s: %w", name, err)
}

func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i > 0 {
		return strings.TrimSpace(s[:i])
	}
	return s
}

// limitedWriter fails once more than n bytes were written, which stops the
// command: its output cannot exhaust memory.
type limitedWriter struct {
	w io.Writer
	n int64
}

func (l *limitedWriter) Write(p []byte) (int, error) {
	if int64(len(p)) > l.n {
		return 0, errors.New("output too large")
	}
	l.n -= int64(len(p))
	return l.w.Write(p)
}

// truncatingWriter keeps the first n bytes and discards the rest.
type truncatingWriter struct {
	w io.Writer
	n int64
}

func (t *truncatingWriter) Write(p []byte) (int, error) {
	if t.n > 0 {
		k := min(int64(len(p)), t.n)
		if _, err := t.w.Write(p[:k]); err != nil {
			return 0, err
		}
		t.n -= k
	}
	return len(p), nil
}

// ServeArgs is the argument list that publishes target on the mount "/" of
// HTTPS port with the tailscale CLI: `funnel --bg --yes --https=<port>
// --set-path=/ <target>` for Funnel, `serve …` for Serve.
func ServeArgs(funnel bool, port int, target string) []string {
	cmd := "serve"
	if funnel {
		cmd = "funnel"
	}
	return []string{cmd, "--bg", "--yes", "--https=" + strconv.Itoa(port), "--set-path=/", target}
}

// ServeOffArgs is the argument list that removes the mount "/" of HTTPS
// port, for Funnel and Serve alike: `serve --yes --https=<port> --set-path=/
// off`. Never `tailscale funnel … off`: it runs Funnel's interactive feature
// check (for port 443, whatever the port) first and may exit without
// applying. Without --set-path every mount of the port would go.
func ServeOffArgs(port int) []string {
	return []string{"serve", "--yes", "--https=" + strconv.Itoa(port), "--set-path=/", "off"}
}

// OffCommand renders the removal command for people (hints, uninstall
// warnings), with sudo when tailscaled requires it (ErrUnixForbidden).
func OffCommand(port int, sudo bool) string {
	s := "tailscale " + strings.Join(ServeOffArgs(port), " ")
	if sudo {
		s = "sudo " + s
	}
	return s
}

// ServeCLI publishes target on the HTTPS port with the tailscale CLI (the
// transport when no LocalAPI socket exists). The caller checks Funnel's
// prerequisites first: `tailscale funnel` would otherwise prompt or exit.
func (c *Client) ServeCLI(ctx context.Context, funnel bool, port int, target string) error {
	_, err := c.RunCLI(ctx, CLITimeout, ServeArgs(funnel, port, target)...)
	return err
}

// ServeOffCLI removes the mount "/" of the HTTPS port with the tailscale CLI
// (see ServeOffArgs).
func (c *Client) ServeOffCLI(ctx context.Context, port int) error {
	_, err := c.RunCLI(ctx, CLITimeout, ServeOffArgs(port)...)
	return err
}
