package cli

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"fileparcel/internal/config"
	"fileparcel/internal/home"
	"fileparcel/internal/svc"
)

func init() { Register(newLogsCmd) }

// Limits of `fileparcel logs`.
const (
	lcMaxLogLines = 100000
	lcLogScan     = 16 << 20 // bytes read from the end of the file at most
	lcMaxLineLen  = 64 << 10
)

func newLogsCmd() *cobra.Command {
	var n int
	var follow bool
	cmd := &cobra.Command{
		Use:   "logs",
		Short: "Show the server log",
		Long: `Print the last lines of <HOME>/logs/fileparcel.log; -f keeps following it
(across log rotation) until interrupted. With --server the lines come from GET
/api/v1/admin/system/logs (no -f). When file logging is disabled
(log.file = false) use the service manager's log instead: journalctl --user -u
fileparcel for a user service, sudo journalctl -u fileparcel for a system
service, <HOME>/logs/launchd.err.log on macOS.

With --json the tail is one object; with -f every line is printed as its own
JSON object as it arrives.`,
		Example: `  fileparcel logs
  fileparcel logs -n 50 -f
  fileparcel logs -f --json`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if n < 0 || n > lcMaxLogLines {
				return UsageError("-n must be between 0 and %d", lcMaxLogLines)
			}
			ctx := lcCtx(cmd)
			w := cmd.OutOrStdout()
			if G.Server != "" {
				if follow {
					return UsageError("-f is not available with --server")
				}
				return lcRemoteLogs(ctx, cmd, n)
			}
			h, err := home.Resolve(G.Home)
			if err != nil {
				return err
			}
			if !h.Exists() {
				return notAHomeError(h.Dir())
			}
			path := h.LogFile()
			if _, err := os.Stat(path); errors.Is(err, fs.ErrNotExist) {
				hint := "the server has not written a log yet"
				if cfg, err := config.Load(h); err == nil && !cfg.Log.File {
					var kind svc.Kind
					if rec, err := svc.ReadInstalled(h); err == nil && rec != nil {
						kind = rec.Kind
					}
					hint = "file logging is disabled (log.file = false); " + lcServiceLogHint(kind, h.Dir())
				}
				return fmt.Errorf("%s does not exist: %s", path, hint)
			}
			lines, err := lcTailFile(path, n)
			if err != nil {
				return err
			}
			if !follow {
				if G.JSON {
					if lines == nil {
						lines = []string{} // [] rather than null (-n 0, an empty log), as the server sends
					}
					return PrintJSON(w, map[string]any{"file": path, "lines": lines})
				}
				for _, l := range lines {
					if err := lcWriteLogLine(w, l); err != nil {
						return err
					}
				}
				return nil
			}
			write := lcLineWriter()
			for _, l := range lines {
				if err := write(w, l); err != nil {
					return err
				}
			}
			return lcFollow(ctx, path, w, write, 500*time.Millisecond)
		},
	}
	cmd.Flags().IntVarP(&n, "lines", "n", 200, "number of lines to show")
	cmd.Flags().BoolVarP(&follow, "follow", "f", false, "keep printing new lines")
	return cmd
}

// lcRemoteLogs prints the log tail of a remote server.
func lcRemoteLogs(ctx context.Context, cmd *cobra.Command, n int) error {
	c, err := Connect(G.ConnectOptions())
	if err != nil {
		return err
	}
	defer c.Close()
	var tail struct {
		File      string   `json:"file"`
		Lines     []string `json:"lines"`
		Truncated bool     `json:"truncated"`
		Missing   bool     `json:"missing"`
		// FileLogging is the server's log.file (nil: a server too old to say).
		FileLogging *bool `json:"file_logging,omitempty"`
	}
	if err := c.Do(ctx, http.MethodGet, "/api/v1/admin/system/logs?n="+strconv.Itoa(max(n, 1)), nil, &tail); err != nil {
		return err
	}
	// Say why there is nothing, like the local path, instead of printing an
	// empty tail; lines that remain after log.file was turned off are old.
	off := tail.FileLogging != nil && !*tail.FileLogging
	if tail.Missing {
		hint := "the server has not written a log yet"
		if off {
			hint = "file logging is disabled (log.file = false); see the service manager's log on the server " +
				"(sudo journalctl -u fileparcel for a system service, journalctl --user -u fileparcel for a user service, " +
				"<HOME>/logs/launchd.err.log on macOS)"
		}
		return fmt.Errorf("%s does not exist on the server: %s", tail.File, hint)
	}
	if off {
		Warnf(cmd, "file logging is disabled on the server (log.file = false): these lines are from before it was turned off")
	}
	if n == 0 || tail.Lines == nil {
		tail.Lines = []string{} // --json prints [] rather than null
	}
	return Print(cmd, tail, func(w io.Writer) error {
		for _, l := range tail.Lines {
			if err := lcWriteLogLine(w, l); err != nil {
				return err
			}
		}
		return nil
	})
}

// lcServiceLogHint says where the log goes when file logging is off: the
// journal of the recorded service (a system unit's is not in the --user
// journal), launchd's stderr file, or, without a service manager, the
// standard error of whatever runs "fileparcel serve".
func lcServiceLogHint(kind svc.Kind, homeDir string) string {
	switch {
	case kind == svc.KindSystemdSystem:
		return "see sudo journalctl -u fileparcel"
	case kind == svc.KindSystemdUser:
		return "see journalctl --user -u fileparcel"
	case kind.Launchd():
		return "see " + filepath.Join(homeDir, "logs", "launchd.err.log")
	}
	return "the log goes only to the standard error of \"fileparcel serve\" (or to whatever runs it, such as docker logs)"
}

// lcLineWriter returns the function that prints one followed log line: plain
// text, or one JSON object per line with --json (like `audit list --follow`).
// The JSON path needs no lcCleanLogLine: encoding/json escapes ESC and the
// other control characters, as in the non-follow branch and lcRemoteLogs.
func lcLineWriter() func(io.Writer, string) error {
	if G.JSON {
		return func(w io.Writer, line string) error {
			return PrintJSONLine(w, map[string]string{"line": line})
		}
	}
	return lcWriteLogLine
}

// lcWriteLogLine prints one log line with terminal control characters removed
// (log lines can carry client-supplied strings).
func lcWriteLogLine(w io.Writer, line string) error {
	_, err := fmt.Fprintln(w, lcCleanLogLine(line))
	return err
}

// lcCleanLogLine drops control characters other than tab (e.g. ESC sequences).
func lcCleanLogLine(s string) string {
	return strings.Map(func(r rune) rune {
		if (r < 0x20 && r != '\t') || r == 0x7f || (r >= 0x80 && r < 0xa0) {
			return -1
		}
		return r
	}, s)
}

// lcTailFile returns the last n lines of path (reading at most lcLogScan
// bytes from its end).
func lcTailFile(path string, n int) ([]string, error) {
	if n == 0 {
		return nil, nil
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return nil, err
	}
	size := fi.Size()
	start := max(int64(0), size-lcLogScan)
	buf := make([]byte, size-start)
	if _, err := f.ReadAt(buf, start); err != nil && !errors.Is(err, io.EOF) {
		return nil, err
	}
	if start > 0 {
		if i := bytes.IndexByte(buf, '\n'); i >= 0 {
			buf = buf[i+1:] // drop the partial first line
		}
	}
	buf = bytes.TrimRight(buf, "\n")
	if len(buf) == 0 {
		return nil, nil
	}
	all := strings.Split(string(buf), "\n")
	if len(all) > n {
		all = all[len(all)-n:]
	}
	return all, nil
}

// lcFollow prints lines appended to path until ctx ends, with write (plain
// text or JSON, see lcLineWriter). It reopens the file when it is rotated (a
// new inode) or truncated.
func lcFollow(ctx context.Context, path string, w io.Writer, write func(io.Writer, string) error, interval time.Duration) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer func() { f.Close() }()
	if _, err := f.Seek(0, io.SeekEnd); err != nil {
		return err
	}
	rd := bufio.NewReaderSize(f, 64<<10)
	var partial []byte
	for {
		for {
			chunk, err := rd.ReadSlice('\n')
			partial = append(partial, chunk...)
			if len(partial) > lcMaxLineLen {
				partial = append(partial[:lcMaxLineLen], '\n')
				err = nil
			}
			if err == nil {
				if werr := write(w, strings.TrimRight(string(partial), "\r\n")); werr != nil {
					return werr
				}
				partial = partial[:0]
				continue
			}
			if errors.Is(err, bufio.ErrBufferFull) {
				continue
			}
			if !errors.Is(err, io.EOF) {
				return err
			}
			break
		}
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(interval):
		}
		// Rotation (new file at path) or truncation: start over at the new beginning.
		cur, err1 := f.Stat()
		now, err2 := os.Stat(path)
		if err2 != nil {
			continue // between rename and re-create
		}
		pos, _ := f.Seek(0, io.SeekCurrent)
		switch {
		case err1 == nil && !os.SameFile(cur, now):
			nf, err := os.Open(path)
			if err != nil {
				continue
			}
			// Drain what was appended to the old file before the rotation.
			if rest, err := io.ReadAll(io.LimitReader(rd, lcLogScan)); err == nil && len(rest) > 0 {
				for _, l := range strings.Split(strings.TrimRight(string(append(partial, rest...)), "\n"), "\n") {
					if err := write(w, l); err != nil {
						nf.Close()
						return err
					}
				}
			}
			partial = partial[:0]
			f.Close()
			f = nf
			rd.Reset(f)
		case now.Size() < pos-int64(rd.Buffered()):
			if _, err := f.Seek(0, io.SeekStart); err == nil {
				rd.Reset(f)
				partial = partial[:0]
			}
		}
	}
}
