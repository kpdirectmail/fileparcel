package netinfo

import (
	"bufio"
	"bytes"
	"context"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// psTimeout bounds one ps run.
const psTimeout = 2 * time.Second

// runningProcesses returns the executable names of the running processes
// (ps -A -c -o comm=).
func runningProcesses() map[string]bool {
	out := map[string]bool{}
	for _, l := range psLines("-A", "-c", "-o", "comm=") {
		out[filepath.Base(l)] = true
	}
	return out
}

// processArgs returns the argument vectors of the running processes named
// comm (ps -A -o args=; arguments with spaces cannot be told apart, which
// only matters for cloudflared's --url, a URL without spaces).
func processArgs(comm string) [][]string {
	var out [][]string
	for _, l := range psLines("-A", "-o", "args=") {
		f := strings.Fields(l)
		if len(f) > 0 && filepath.Base(f[0]) == comm {
			out = append(out, f)
		}
		if len(out) >= 32 {
			break
		}
	}
	return out
}

// psLines runs ps with args (2 s, 4 MiB of output at most) and returns
// its non-empty lines.
func psLines(args ...string) []string {
	ctx, cancel := context.WithTimeout(context.Background(), psTimeout)
	defer cancel()
	b, err := exec.CommandContext(ctx, "/bin/ps", args...).Output()
	if err != nil || len(b) > 4<<20 {
		return nil
	}
	var out []string
	sc := bufio.NewScanner(bytes.NewReader(b))
	sc.Buffer(make([]byte, 64<<10), 64<<10)
	for sc.Scan() {
		if l := strings.TrimSpace(sc.Text()); l != "" {
			out = append(out, l)
		}
	}
	return out
}
