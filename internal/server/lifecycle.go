package server

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"fileparcel/internal/core"
	"fileparcel/internal/events"
	"fileparcel/internal/mdns"
)

// preparePIDFile checks the markers of the previous run (a PID file without
// a clean-shutdown marker means it crashed or was killed), then writes
// run/fileparcel.pid and removes the marker.
func (r *runner) preparePIDFile() {
	h := r.d.Home
	if _, err := os.Stat(h.CleanShutdownFile()); errors.Is(err, os.ErrNotExist) {
		if b, err := os.ReadFile(h.PIDFile()); err == nil {
			r.log.Warn("the previous run did not shut down cleanly", "previous_pid", strings.TrimSpace(string(b)))
		}
	}
	_ = os.Remove(h.CleanShutdownFile())
	if err := writeFileAtomic(h.PIDFile(), []byte(strconv.Itoa(os.Getpid())+"\n"), 0o644); err != nil {
		r.log.Warn("cannot write the PID file", "err", err)
	}
}

// removePIDFile removes the PID file if it still names this process.
func removePIDFile(path string) {
	b, err := os.ReadFile(path)
	if err != nil || strings.TrimSpace(string(b)) != strconv.Itoa(os.Getpid()) {
		return
	}
	_ = os.Remove(path)
}

// writeCleanShutdown records a graceful stop (run/clean-shutdown).
func writeCleanShutdown(path string, now time.Time) {
	_ = writeFileAtomic(path, []byte(now.UTC().Format(time.RFC3339)+"\n"), 0o600)
}

func writeFileAtomic(path string, data []byte, mode os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".tmp*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	_, werr := f.Write(data)
	if werr == nil {
		werr = f.Chmod(mode)
	}
	if werr == nil {
		werr = f.Sync()
	}
	if cerr := f.Close(); werr == nil {
		werr = cerr
	}
	if werr == nil {
		werr = os.Rename(tmp, path)
	}
	if werr != nil {
		_ = os.Remove(tmp)
	}
	return werr
}

// mdnsSettleTimeout bounds the wait for the first mDNS publication result so
// that the startup URLs carry the effective .local name — the one a collision
// renamed to — instead of the configured one. It delays only the readiness
// banner (and sd_notify READY=1); the listeners already serve requests.
const mdnsSettleTimeout = 2 * time.Second

// mdnsSettled reports whether st is a final publication result. "publishing"
// and "collision" are not: the supervisor renames and retries immediately.
// State "off" while the mode is not off means "no status yet" — core.MDNS
// reports the zero value that way before its supervisor's first step.
func mdnsSettled(st core.MDNSStatus) bool {
	switch st.State {
	case core.MDNSPublished, core.MDNSError:
		return true
	case core.MDNSOff:
		return st.Mode == mdns.ModeOff
	}
	return false
}

// settleMDNS waits until mDNS reports a final state, the timeout expires or
// ctx ends. Without mDNS (or a bus) it returns at once.
func (r *runner) settleMDNS(ctx context.Context) {
	d := r.d
	if d.MDNS == nil || d.Bus == nil {
		return
	}
	// Subscribe before reading the status, so a result that lands between
	// the two arrives on the channel instead of being missed.
	ch, unsub := d.Bus.Subscribe(events.TopicMDNSChanged)
	defer unsub()
	if mdnsSettled(d.MDNS.Status()) {
		return
	}
	t := time.NewTimer(mdnsSettleTimeout)
	defer t.Stop()
	for {
		select {
		case e, ok := <-ch:
			if !ok {
				return
			}
			if st, isStatus := e.Data.(core.MDNSStatus); isStatus && mdnsSettled(st) {
				return
			}
		case <-t.C:
			r.log.Debug("mDNS has not settled yet; the access URLs may still change", "waited", mdnsSettleTimeout.String())
			return
		case <-ctx.Done():
			return
		}
	}
}

// announce reports readiness: sd_notify READY=1 + STATUS, the watchdog, the
// access URLs (log, and stderr in the foreground), and the system.start
// audit entry. It first waits, briefly, for mDNS to settle, so the URLs it
// prints once are the ones the instance actually answers to.
func (r *runner) announce(ctx context.Context) {
	d := r.d
	r.settleMDNS(ctx)
	var urls []string
	if d.Network != nil {
		uctx, cancel := context.WithTimeout(ctx, 5*time.Second)
		list, err := d.Network.URLs(uctx)
		cancel()
		if err != nil {
			r.log.Warn("cannot list the access URLs", "err", err)
		}
		for _, u := range list {
			urls = append(urls, u.URL)
			r.log.Info("reachable at", "url", u.URL, "kind", u.Kind, "interface", u.Interface, "recommended", u.Recommended)
		}
	}
	if len(urls) == 0 {
		urls = append(urls, fmt.Sprintf("https://localhost:%d/", r.cfg.httpsPort))
	}
	version := d.Build.Version
	if version == "" {
		version = "dev"
	}
	fp := ""
	if d.Certs != nil {
		fp = d.Certs.Fingerprint()
	}
	r.log.Info("FileParcel started", "version", version, "pid", os.Getpid(), "https_port", r.cfg.httpsPort,
		"http_port", r.cfg.httpPort, "keys", keysState(d.Keys), "ca_fingerprint", fp)
	if r.opts.Foreground {
		locked := keysState(d.Keys) == string(core.KeyStateLocked)
		_, _ = io.WriteString(os.Stderr, banner(version, os.Getpid(), urls, fp, locked))
	}
	sdNotify("READY=1\nMAINPID=" + strconv.Itoa(os.Getpid()) + "\nSTATUS=Serving on " + strings.Join(urls[:min(len(urls), 3)], " "))
	if iv := watchdogInterval(); iv > 0 {
		r.wg.Add(1)
		wctx, cancel := context.WithCancel(ctx)
		r.stopWatchdog = cancel
		go func() {
			defer r.wg.Done()
			watchdog(wctx, iv, r.healthy, func(err error) { r.log.Warn("watchdog health check failed", "err", err) })
		}()
	}
	if d.Audit != nil {
		d.Audit.Record(ctx, core.AuditEntry{Action: core.ActSystemStart, TargetType: "system", ActorName: "system",
			Details: map[string]any{"version": version, "pid": os.Getpid(), "https_port": r.cfg.httpsPort}})
	}
}

// banner is the human-readable startup summary of the foreground mode. urls
// is never empty; its first entry (server.public_url when set, as typed)
// is the base of the /trust and /unlock links.
func banner(version string, pid int, urls []string, fp string, locked bool) string {
	var b strings.Builder
	fmt.Fprintf(&b, "FileParcel %s is running (pid %d). Open:\n", version, pid)
	for _, u := range urls {
		fmt.Fprintf(&b, "  %s\n", u)
	}
	if fp != "" {
		fmt.Fprintf(&b, "CA fingerprint (SHA-256): %s\nTrust instructions: %s\n", fp, pageURL(urls[0], "trust"))
	}
	if locked {
		fmt.Fprintf(&b, "The master key is sealed: unlock at %s or with \"fileparcel keys unlock\".\n", pageURL(urls[0], "unlock"))
	}
	b.WriteString("Press Ctrl+C to stop.\n")
	return b.String()
}

// pageURL joins an access URL and an app page ("trust", "unlock") with
// exactly one slash, keeping a path prefix (a reverse proxy serving under
// /base), like the share and invitation links do.
func pageURL(base, page string) string { return strings.TrimRight(base, "/") + "/" + page }

// healthy is the watchdog health check: the database answers.
func (r *runner) healthy(ctx context.Context) error {
	if r.d.DB == nil {
		return nil
	}
	return r.d.DB.Reader().PingContext(ctx)
}

func keysState(k core.Keys) string {
	if k == nil {
		return ""
	}
	return string(k.State())
}

// Supervised reports whether a service manager restarts FileParcel when it
// exits with ExitRestart: systemd (INVOCATION_ID / NOTIFY_SOCKET) or launchd
// (XPC_SERVICE_NAME = our job label, com.fileparcel.*). Docker restart
// policies are invisible to the process; FILEPARCEL_SUPERVISED=1 declares
// them (and any other supervisor).
func Supervised() bool {
	if os.Getenv("FILEPARCEL_SUPERVISED") == "1" || os.Getenv("INVOCATION_ID") != "" || os.Getenv("NOTIFY_SOCKET") != "" {
		return true
	}
	return strings.HasPrefix(os.Getenv("XPC_SERVICE_NAME"), "com.fileparcel.")
}

// slogWriterLog adapts http.Server.ErrorLog to slog: TLS handshake noise
// (scanners, clients rejecting the local CA) goes to debug, the rest to warn.
type slogWriterLog struct{ log *slog.Logger }

func newErrorLog(l *slog.Logger) *slogWriterLog {
	return &slogWriterLog{log: l.With("component", "http")}
}

func (w *slogWriterLog) logger() *log.Logger { return log.New(w, "", 0) }

// Write implements io.Writer for log.Logger.
func (w *slogWriterLog) Write(p []byte) (int, error) {
	msg := string(bytes.TrimSpace(p))
	level := slog.LevelWarn
	if strings.Contains(msg, "TLS handshake error") || strings.Contains(msg, "http2: server: error reading preface") ||
		strings.Contains(msg, "use of closed network connection") {
		level = slog.LevelDebug
	}
	w.log.Log(context.Background(), level, msg)
	return len(p), nil
}
