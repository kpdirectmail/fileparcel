package netinfo

import (
	"bytes"
	"os"
	"strconv"
	"strings"
)

// maxProcScan bounds the processes the probes look at.
const maxProcScan = 100_000

// runningProcesses returns the command names (/proc/<pid>/comm, at most 15
// bytes) of the running processes.
func runningProcesses() map[string]bool {
	out := map[string]bool{}
	procEach(func(pid string) bool {
		if b, err := os.ReadFile("/proc/" + pid + "/comm"); err == nil {
			out[strings.TrimSpace(string(b))] = true
		}
		return true
	})
	return out
}

// processArgs returns the argument vectors of the running processes named
// comm (for cloudflared's --url; at most 64 KiB per process).
func processArgs(comm string) [][]string {
	var out [][]string
	procEach(func(pid string) bool {
		b, err := os.ReadFile("/proc/" + pid + "/comm")
		if err != nil || strings.TrimSpace(string(b)) != comm {
			return true
		}
		if cmd, ok := readSmallProc("/proc/"+pid+"/cmdline", 64<<10); ok {
			out = append(out, strings.Split(string(bytes.TrimRight(cmd, "\x00")), "\x00"))
		}
		return len(out) < 32
	})
	return out
}

// readSmallProc reads a /proc file (size 0 in stat) of at most limit bytes.
func readSmallProc(path string, limit int) ([]byte, bool) {
	f, err := os.Open(path)
	if err != nil {
		return nil, false
	}
	defer f.Close()
	buf := make([]byte, limit+1)
	n, _ := f.Read(buf)
	if n == 0 || n > limit {
		return nil, false
	}
	return buf[:n], true
}

// procEach calls fn with every numeric /proc entry until fn returns false.
func procEach(fn func(pid string) bool) {
	d, err := os.Open("/proc")
	if err != nil {
		return
	}
	defer d.Close()
	names, err := d.Readdirnames(maxProcScan)
	if err != nil && len(names) == 0 {
		return
	}
	for _, n := range names {
		if _, err := strconv.Atoi(n); err != nil {
			continue
		}
		if !fn(n) {
			return
		}
	}
}
