package opsapi

import (
	"bytes"
	"errors"
	"io"
	"net/http"
	"os"
	"runtime"
	"runtime/debug"
	"strconv"
	"strings"
	"time"

	"fileparcel/internal/app"
	"fileparcel/internal/core"
	"fileparcel/internal/events"
	"fileparcel/internal/web/httpx"
	"fileparcel/internal/web/mw"
)

// SystemResponse is GET /admin/system: core.SystemInfo plus runtime and
// subsystem details (the embedded fields are flattened in JSON).
type SystemResponse struct {
	core.SystemInfo
	Mode string `json:"mode"` // network | offline
	// StatsUnavailable is true when a database read for this page failed:
	// the figures it feeds (schema_version, blob_count, blobs_bytes) are
	// then zero because nothing could be read, not because there is nothing.
	StatsUnavailable bool             `json:"stats_unavailable,omitempty"`
	BlobCount        int64            `json:"blob_count"`
	Goroutines       int              `json:"goroutines"`
	Memory           MemoryInfo       `json:"memory"`
	NumCPU           int              `json:"num_cpu"`
	Certs            *core.CertStatus `json:"certs,omitempty"`
	MDNS             *core.MDNSStatus `json:"mdns,omitempty"`
	Network          *NetworkSummary  `json:"network,omitempty"`
	// Maintenance is maintenance.enabled: only administrators and "Operate
	// the server" get past mw.Maintenance (`fileparcel status` says so).
	Maintenance bool `json:"maintenance,omitempty"`
}

// MemoryInfo is the Go runtime memory summary.
type MemoryInfo struct {
	HeapAlloc  uint64 `json:"heap_alloc"`
	HeapInuse  uint64 `json:"heap_inuse"`
	Sys        uint64 `json:"sys"`
	NumGC      uint32 `json:"num_gc"`
	MemLimit   int64  `json:"mem_limit"`
	TotalAlloc uint64 `json:"total_alloc"`
}

// NetworkSummary is the network part of GET /admin/system.
type NetworkSummary struct {
	Policy     core.AccessPolicy `json:"policy"`
	URLs       []core.AccessURL  `json:"urls"`
	Interfaces int               `json:"interfaces"`
}

// LogTail is GET /admin/system/logs. Missing and FileLogging tell an empty
// tail apart from a quiet server: with log.file = false the server logs only
// to its service manager (journald, launchd's log file, docker logs), and
// any file left over is from before file logging was turned off.
type LogTail struct {
	File        string   `json:"file"`
	Lines       []string `json:"lines"`
	Truncated   bool     `json:"truncated"`    // older lines exist
	Missing     bool     `json:"missing"`      // the file does not exist
	FileLogging bool     `json:"file_logging"` // log.file of the running configuration
}

// Log tail limits.
const (
	defaultLogLines = 200
	maxLogLines     = 5000
	maxLogScan      = 8 << 20 // bytes read from the end at most
)

func (h *handlers) system(w http.ResponseWriter, r *http.Request) {
	d := h.deps(r)
	if d == nil || d.Env == nil {
		httpx.Error(w, r, errUnavailable)
		return
	}
	ctx := r.Context()
	now := h.now(r)
	b := d.Build
	info := core.SystemInfo{
		Version: b.Version, Commit: b.Commit, BuildDate: b.Date, GoVersion: runtime.Version(),
		OS: runtime.GOOS, Arch: runtime.GOARCH, PID: os.Getpid(), StartedAt: processStart.UTC(),
		UptimeSeconds: int64(time.Since(processStart).Seconds()), RestartRequired: []string{},
		Supervisor: supervisor(),
	}
	info.Hostname, _ = os.Hostname()
	if d.Home != nil {
		info.Home = d.Home.Dir()
		info.DBBytes = fileSize(d.Home.DB()) + fileSize(d.Home.DB()+"-wal")
		info.DiskSizeBytes, info.DiskFreeBytes = diskUsage(d.Home.Dir())
	}
	if d.Keys != nil {
		info.KeysState = d.Keys.State()
		if st, err := d.Keys.Status(ctx); err == nil && st != nil {
			info.KeyMode = st.Mode
		}
	}
	schemaErr := false
	if d.DB != nil {
		var err error
		if info.SchemaVersion, err = d.DB.SchemaVersion(ctx); err != nil {
			schemaErr = true
		}
	}
	if rr, ok := d.Settings.(interface{ RestartRequired() []string }); ok && d.Settings != nil {
		if l := rr.RestartRequired(); l != nil {
			info.RestartRequired = l
		}
	}
	resp := SystemResponse{SystemInfo: info, Mode: d.Mode.String(), Goroutines: runtime.NumGoroutine(), NumCPU: runtime.NumCPU(),
		Maintenance: mw.MaintenanceOn(d)}
	stats := collectStats(ctx, d, now)
	resp.BlobCount, resp.BlobsBytes = stats.blobCount, stats.blobBytes
	resp.StatsUnavailable = stats.unavailable || schemaErr
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	resp.Memory = MemoryInfo{HeapAlloc: ms.HeapAlloc, HeapInuse: ms.HeapInuse, Sys: ms.Sys, NumGC: ms.NumGC,
		TotalAlloc: ms.TotalAlloc, MemLimit: memLimit()}
	if d.Certs != nil {
		if cs, err := d.Certs.Status(ctx); err == nil {
			resp.Certs = cs
		}
	}
	if d.MDNS != nil {
		st := d.MDNS.Status()
		resp.MDNS = &st
	}
	if d.Network != nil {
		ns := &NetworkSummary{Policy: d.Network.Policy(), URLs: []core.AccessURL{}}
		if urls, err := d.Network.URLs(ctx); err == nil && urls != nil {
			ns.URLs = urls
		}
		if ifs, err := d.Network.Interfaces(ctx); err == nil {
			ns.Interfaces = len(ifs)
		}
		resp.Network = ns
	}
	httpx.OK(w, resp)
}

// restart is POST /admin/system/restart (E): audit, then ask the server to
// restart. Nobody listens in offline mode → 409.
func (h *handlers) restart(w http.ResponseWriter, r *http.Request) {
	d := h.deps(r)
	if d == nil || d.Env == nil {
		httpx.Error(w, r, errUnavailable)
		return
	}
	if d.Mode == app.ModeOffline {
		httpx.Error(w, r, core.Errorf(core.ErrConflict, "the server is not running (offline mode): start it instead"))
		return
	}
	if d.Bus == nil {
		httpx.Error(w, r, errUnavailable)
		return
	}
	h.record(r, core.AuditEntry{Action: core.ActSystemRestart, TargetType: "system"})
	if d.Log != nil {
		d.Log.Warn("restart requested through the API")
	}
	d.Bus.Publish(events.Event{Topic: events.TopicSystemRestart})
	httpx.JSON(w, http.StatusAccepted, map[string]bool{"restarting": true})
}

// logs is GET /admin/system/logs?n=: the last n lines of logs/fileparcel.log.
func (h *handlers) logs(w http.ResponseWriter, r *http.Request) {
	d := h.deps(r)
	if d == nil || d.Env == nil || d.Home == nil {
		httpx.Error(w, r, errUnavailable)
		return
	}
	n := defaultLogLines
	if s := r.URL.Query().Get("n"); s != "" {
		v, err := strconv.Atoi(s)
		if err != nil || v < 1 {
			httpx.Error(w, r, core.Invalid("n", "n must be a positive number"))
			return
		}
		n = min(v, maxLogLines)
	}
	lines, truncated, err := tailFile(d.Home.LogFile(), n, maxLogScan)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		httpx.Error(w, r, err)
		return
	}
	if lines == nil {
		lines = []string{}
	}
	httpx.OK(w, LogTail{File: "logs/fileparcel.log", Lines: lines, Truncated: truncated,
		Missing: errors.Is(err, os.ErrNotExist), FileLogging: d.Config == nil || d.Config.Log.File})
}

// tailFile returns the last n lines of path, reading at most maxScan bytes
// from its end. truncated reports whether earlier content exists.
func tailFile(path string, n int, maxScan int64) ([]string, bool, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, false, err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return nil, false, err
	}
	size := st.Size()
	const chunk = 64 << 10
	var buf []byte
	pos := size
	for pos > 0 && int64(len(buf)) < maxScan && bytes.Count(buf, []byte{'\n'}) <= n {
		step := min(int64(chunk), pos, maxScan-int64(len(buf)))
		pos -= step
		b := make([]byte, step)
		if _, err := f.ReadAt(b, pos); err != nil && !errors.Is(err, io.EOF) {
			return nil, false, err
		}
		buf = append(b, buf...)
	}
	buf = bytes.TrimRight(buf, "\n")
	var parts [][]byte
	if len(buf) > 0 {
		parts = bytes.Split(buf, []byte{'\n'})
	}
	truncated := pos > 0
	if pos > 0 && len(parts) > 0 {
		parts = parts[1:] // first line is probably partial
	}
	if len(parts) > n {
		parts = parts[len(parts)-n:]
		truncated = true
	}
	out := make([]string, len(parts))
	for i, p := range parts {
		out[i] = string(bytes.ToValidUTF8(p, []byte("�")))
	}
	return out, truncated, nil
}

func fileSize(path string) int64 {
	st, err := os.Stat(path)
	if err != nil {
		return 0
	}
	return st.Size()
}

// supervisor names the process supervisor, from the environment checks of
// server.Supervised (which decides how a restart behaves, so the System page
// must not disagree with it): systemd, launchd running our own job
// (com.fileparcel.*; terminal apps such as iTerm2 set XPC_SERVICE_NAME for
// every process they start), Docker, or "external" for any other supervisor
// declared with FILEPARCEL_SUPERVISED=1. It is non-empty whenever
// server.Supervised is true; "docker" alone is not supervised for a restart
// (it re-executes in place), but its restart policy covers reboots and
// crashes, which is what the System page's service notice is about.
func supervisor() string {
	switch {
	case os.Getenv("INVOCATION_ID") != "" || os.Getenv("NOTIFY_SOCKET") != "":
		return "systemd"
	case strings.HasPrefix(os.Getenv("XPC_SERVICE_NAME"), "com.fileparcel."):
		return "launchd"
	}
	if _, err := os.Stat("/.dockerenv"); err == nil {
		return "docker"
	}
	if os.Getenv("FILEPARCEL_SUPERVISED") == "1" {
		return "external"
	}
	return ""
}

// memLimit returns the soft memory limit (-1 = none).
func memLimit() int64 {
	l := debug.SetMemoryLimit(-1)
	if l == int64(^uint64(0)>>1) {
		return -1
	}
	return l
}
