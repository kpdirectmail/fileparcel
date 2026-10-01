package server

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"fileparcel/internal/certs"
	"fileparcel/internal/core"
	"fileparcel/internal/events"
	"fileparcel/internal/logx"
	"fileparcel/internal/svc"
)

// testHandler answers with the request's principal channel, a slow path and
// an event stream.
func testHandler(hits *atomic.Int64) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		via := "anonymous"
		if p := core.PrincipalFrom(r.Context()); p != nil {
			via = string(p.Via) + ":" + string(p.Role)
		}
		fmt.Fprintf(w, "hello %s %s", via, r.Proto)
	})
	mux.HandleFunc("/slow", func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(400 * time.Millisecond)
		fmt.Fprint(w, "slow done")
	})
	mux.HandleFunc("/ingress-info", func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		fmt.Fprint(w, ingressInfoLine(r))
	})
	mux.HandleFunc("/events", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		http.NewResponseController(w).Flush()
		<-r.Context().Done()
	})
	return mux
}

type running struct {
	td     *testDeps
	cancel context.CancelFunc
	done   chan struct{} // closed when Run returned; err holds its result
	err    error
	hits   atomic.Int64
	client *http.Client
	https  string
}

// start runs Run and waits until the HTTPS port answers.
func start(t *testing.T, td *testDeps, opts Options) *running {
	t.Helper()
	rn := &running{td: td, done: make(chan struct{})}
	ctx, cancel := context.WithCancel(context.Background())
	rn.cancel = cancel
	go func() {
		rn.err = Run(ctx, td.d, testHandler(&rn.hits), opts)
		close(rn.done)
	}()
	pemData, _, _, err := td.certs.CAExport("pem")
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(pemData)
	rn.client = &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool}, ForceAttemptHTTP2: true},
		Timeout: 10 * time.Second}
	rn.https = "https://127.0.0.1:" + strconv.Itoa(td.d.Config.Server.HTTPSPort)
	deadline := time.Now().Add(10 * time.Second)
	for {
		resp, err := rn.client.Get(rn.https + "/")
		if err == nil {
			resp.Body.Close()
			break
		}
		select {
		case <-rn.done:
			t.Fatalf("Run returned early: %v", rn.err)
		default:
		}
		if time.Now().After(deadline) {
			t.Fatalf("server did not come up: %v", err)
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Cleanup(func() {
		cancel()
		select {
		case <-rn.done:
		case <-time.After(ShutdownTimeout + 5*time.Second):
		}
	})
	return rn
}

func (rn *running) stop(t *testing.T) error {
	t.Helper()
	rn.cancel()
	select {
	case <-rn.done:
		return rn.err
	case <-time.After(15 * time.Second):
		t.Fatal("Run did not return after cancel")
		return nil
	}
}

func noRedirect(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }

func TestRunTLSRedirectsSocketAndShutdown(t *testing.T) {
	td := newDeps(t)
	rn := start(t, td, Options{})
	cfg := td.d.Config.Server
	h := td.d.Home
	base := rn.hits.Load()

	// TLS with the local CA; HTTP/2 negotiated.
	resp, err := rn.client.Get(rn.https + "/")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if string(body) != "hello anonymous HTTP/2.0" {
		t.Fatalf("TLS response %q", body)
	}
	if resp.TLS == nil || resp.TLS.Version != tls.VersionTLS13 {
		t.Fatal("not TLS 1.3")
	}

	// Plain HTTP on the TLS port → 308 to https on the same port.
	plain := &http.Client{CheckRedirect: noRedirect, Timeout: 5 * time.Second}
	resp, err = plain.Get("http://127.0.0.1:" + strconv.Itoa(cfg.HTTPSPort) + "/files/a?x=1")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusPermanentRedirect || resp.Header.Get("Location") != rn.https+"/files/a?x=1" {
		t.Fatalf("same-port redirect: %d %q", resp.StatusCode, resp.Header.Get("Location"))
	}

	// The HTTP port redirects too, keeping a valid Host name.
	req, _ := http.NewRequest(http.MethodPost, "http://127.0.0.1:"+strconv.Itoa(cfg.HTTPPort)+"/s/abc", strings.NewReader("x"))
	req.Host = "fileparcel.local:" + strconv.Itoa(cfg.HTTPPort)
	resp, err = plain.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	want := "https://fileparcel.local:" + strconv.Itoa(cfg.HTTPSPort) + "/s/abc"
	if resp.StatusCode != http.StatusPermanentRedirect || resp.Header.Get("Location") != want {
		t.Fatalf("http port redirect: %d %q", resp.StatusCode, resp.Header.Get("Location"))
	}
	if rn.hits.Load() != base+1 {
		t.Fatalf("redirects reached the application handler: %d", rn.hits.Load())
	}

	// Admin socket: 0600, system principal, peer credentials accepted.
	fi, err := os.Stat(h.Socket())
	if err != nil || fi.Mode()&os.ModeSocket == 0 || fi.Mode().Perm() != 0o600 {
		t.Fatalf("socket %v %v", fi, err)
	}
	sockClient := &http.Client{Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return DialSocket(ctx, h.Socket())
	}}}
	resp, err = sockClient.Get("http://localhost/")
	if err != nil {
		t.Fatal(err)
	}
	body, _ = io.ReadAll(resp.Body)
	resp.Body.Close()
	if string(body) != "hello socket:system HTTP/1.1" {
		t.Fatalf("socket response %q", body)
	}

	// PID file while running.
	if b, err := os.ReadFile(h.PIDFile()); err != nil || strings.TrimSpace(string(b)) != strconv.Itoa(os.Getpid()) {
		t.Fatalf("pid file %q %v", b, err)
	}
	if !td.audit.has(core.ActSystemStart) {
		t.Fatal("system.start not audited")
	}

	// Graceful shutdown: an in-flight request completes, an open event
	// stream does not hold the shutdown back.
	stream, err := rn.client.Get(rn.https + "/events")
	if err != nil {
		t.Fatal(err)
	}
	defer stream.Body.Close()
	slow := make(chan string, 1)
	go func() {
		resp, err := rn.client.Get(rn.https + "/slow")
		if err != nil {
			slow <- err.Error()
			return
		}
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		slow <- string(b)
	}()
	time.Sleep(100 * time.Millisecond)
	began := time.Now()
	if err := rn.stop(t); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if took := time.Since(began); took > 10*time.Second {
		t.Fatalf("shutdown took %v", took)
	}
	if got := <-slow; got != "slow done" {
		t.Fatalf("in-flight request: %q", got)
	}
	if _, err := os.Stat(h.PIDFile()); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("pid file not removed")
	}
	if _, err := os.Stat(h.CleanShutdownFile()); err != nil {
		t.Fatal("clean-shutdown marker not written")
	}
	if _, err := os.Stat(h.Socket()); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("socket file not removed")
	}
	if !td.audit.has(core.ActSystemStop) {
		t.Fatal("system.stop not audited")
	}
	if _, err := net.DialTimeout("tcp", "127.0.0.1:"+strconv.Itoa(cfg.HTTPSPort), time.Second); err == nil {
		t.Fatal("HTTPS port still open")
	}
}

func TestRunRestartEvent(t *testing.T) {
	td := newDeps(t)
	rn := start(t, td, Options{})
	td.d.Bus.Publish(events.Event{Topic: events.TopicSystemRestart})
	select {
	case <-rn.done:
		if !errors.Is(rn.err, ErrRestart) {
			t.Fatalf("Run returned %v, want ErrRestart", rn.err)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("restart event ignored")
	}
	if _, err := os.Stat(td.d.Home.CleanShutdownFile()); err != nil {
		t.Fatal("restart is a clean shutdown")
	}
}

// fakeJobs records how shutdown stops the job runner.
type fakeJobs struct {
	core.Jobs
	mu       sync.Mutex
	calls    int
	at       time.Time
	deadline time.Time
}

func (j *fakeJobs) Stop(ctx context.Context) error {
	j.mu.Lock()
	defer j.mu.Unlock()
	j.calls++
	j.at = time.Now()
	j.deadline, _ = ctx.Deadline()
	return nil
}

// The services stop (Options.Cleanup) before the clean-shutdown marker is
// written and the PID file removed, so a stop killed by the supervisor while
// they close counts as unclean. The job runner stops during the HTTP drain,
// not after it, within the drain's deadline.
func TestRunCleanupBeforeCleanShutdownMarker(t *testing.T) {
	td := newDeps(t)
	jobs := &fakeJobs{}
	td.d.Jobs = jobs
	h := td.d.Home
	var cleanups atomic.Int32
	var markerEarly, pidGone atomic.Bool
	rn := start(t, td, Options{Cleanup: func() {
		cleanups.Add(1)
		if _, err := os.Stat(h.CleanShutdownFile()); err == nil {
			markerEarly.Store(true)
		}
		if _, err := os.Stat(h.PIDFile()); err != nil {
			pidGone.Store(true)
		}
	}})
	slow := make(chan time.Time, 1)
	go func() {
		if resp, err := rn.client.Get(rn.https + "/slow"); err == nil {
			_, _ = io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
		}
		slow <- time.Now()
	}()
	time.Sleep(100 * time.Millisecond)
	began := time.Now()
	if err := rn.stop(t); err != nil {
		t.Fatal(err)
	}
	slowDone := <-slow
	if n := cleanups.Load(); n != 1 {
		t.Fatalf("Cleanup called %d times", n)
	}
	if markerEarly.Load() || pidGone.Load() {
		t.Fatalf("Cleanup ran after the clean-shutdown bookkeeping: marker=%v pid removed=%v", markerEarly.Load(), pidGone.Load())
	}
	if _, err := os.Stat(h.CleanShutdownFile()); err != nil {
		t.Fatal("clean-shutdown marker not written")
	}
	if _, err := os.Stat(h.PIDFile()); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("pid file not removed")
	}
	jobs.mu.Lock()
	defer jobs.mu.Unlock()
	if jobs.calls != 1 || !jobs.at.Before(slowDone) {
		t.Fatalf("jobs.Stop: %d calls, at %v; the drain ended %v", jobs.calls, jobs.at, slowDone)
	}
	if limit := began.Add(ShutdownTimeout - jobsCancelGrace + time.Second); jobs.deadline.IsZero() || jobs.deadline.After(limit) {
		t.Fatalf("jobs.Stop deadline %v, want by %v", jobs.deadline, limit)
	}
}

// A failed start leaves the cleanup to the caller.
func TestRunFailedStartSkipsCleanup(t *testing.T) {
	td := newDeps(t)
	ln, err := net.Listen("tcp", "127.0.0.1:"+strconv.Itoa(td.d.Config.Server.HTTPSPort))
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	called := false
	if err := Run(context.Background(), td.d, http.NotFoundHandler(), Options{Cleanup: func() { called = true }}); err == nil {
		t.Fatal("Run with a busy port succeeded")
	}
	if called {
		t.Fatal("Cleanup called after a failed start")
	}
}

// Overlapping server.bind entries start (the duplicate is ignored) instead
// of failing with "address already in use".
func TestRunOverlappingBinds(t *testing.T) {
	td := newDeps(t)
	td.d.Config.Server.Bind = []string{"127.0.0.1", "::ffff:127.0.0.1", "127.0.0.1"}
	rn := start(t, td, Options{})
	if err := rn.stop(t); err != nil {
		t.Fatal(err)
	}
}

// serve --dev logs at debug level.
func TestRunDevLogsAtDebug(t *testing.T) {
	if err := logx.SetLevel("info"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = logx.SetLevel("info") })
	start(t, newDeps(t), Options{Dev: true})
	if got := logx.Level(); got != "debug" {
		t.Fatalf("log level with Dev: %s", got)
	}
}

// The local health probe (svc.HealthCheck: upgrades, service start/restart,
// doctor, the Docker HEALTHCHECK) has no client certificate. It must pass
// against a running server in mtls.mode=required with and without the share
// exemptions — without them the handshake itself refuses the probe (its
// certificate_required alert, from a server the probe verified against the
// local CA, counts as up) — or every upgrade would roll back.
func TestRunHealthCheckMTLSRequired(t *testing.T) {
	td := newDeps(t)
	rn := start(t, td, Options{})
	port := td.d.Config.Server.HTTPSPort
	td.settings.set(certs.KeyMTLSMode, certs.MTLSRequired)
	for _, exempt := range []bool{true, false} {
		td.settings.set(certs.KeyMTLSExempt, exempt)
		if err := svc.HealthCheck(context.Background(), td.d.Home, port, 5*time.Second); err != nil {
			t.Fatalf("health check, mtls required, exempt_shares=%v: %v", exempt, err)
		}
	}
	// Without the exemptions a new connection without a client certificate
	// is indeed refused.
	rn.client.CloseIdleConnections()
	if resp, err := rn.client.Get(rn.https + "/healthz"); err == nil {
		resp.Body.Close()
		t.Fatalf("/healthz without a client certificate: %d", resp.StatusCode)
	}
}

// dialRefused dials addr and returns the connection, or nil when the peer
// refused it at connect time. refuse() closes denied connections with
// SetLinger(0), so the RST can arrive while the local connect is still
// completing and Dial itself fails with ECONNRESET — that is the refusal the
// caller is testing for, not a failure.
func dialRefused(t *testing.T, addr string) net.Conn {
	t.Helper()
	c, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		if errors.Is(err, syscall.ECONNRESET) || errors.Is(err, syscall.ECONNREFUSED) || errors.Is(err, syscall.EPIPE) {
			return nil
		}
		t.Fatal(err)
	}
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	return c
}

func TestRunAllowlistRejectsBeforeTLS(t *testing.T) {
	td := newDeps(t)
	rn := start(t, td, Options{})
	td.net.deny.Store(true)
	before := rn.hits.Load()

	// TLS: the connection is closed before any handshake.
	if conn := dialRefused(t, "127.0.0.1:"+strconv.Itoa(td.d.Config.Server.HTTPSPort)); conn != nil {
		tc := tls.Client(conn, &tls.Config{InsecureSkipVerify: true}) //nolint:gosec // the handshake must not even start
		if err := tc.Handshake(); err == nil {
			t.Fatal("TLS handshake succeeded for a denied address")
		}
		conn.Close()
	}

	// Plain HTTP on the redirect port: closed without an answer.
	if conn := dialRefused(t, "127.0.0.1:"+strconv.Itoa(td.d.Config.Server.HTTPPort)); conn != nil {
		_, _ = conn.Write([]byte("GET / HTTP/1.1\r\nHost: x\r\n\r\n"))
		if line, err := bufio.NewReader(conn).ReadString('\n'); err == nil {
			t.Fatalf("denied connection got an answer: %q", line)
		}
		conn.Close()
	}
	if rn.hits.Load() != before {
		t.Fatal("denied connection reached the handler")
	}

	// The admin socket is not subject to the network allowlist.
	resp, err := (&http.Client{Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return DialSocket(ctx, td.d.Home.Socket())
	}}}).Get("http://localhost/")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	td.net.deny.Store(false)
	if resp, err := rn.client.Get(rn.https + "/"); err != nil {
		t.Fatalf("allowed again: %v", err)
	} else {
		resp.Body.Close()
	}
}

// With ACME HTTP-01 configured the HTTP port admits addresses outside the
// access policy, but serves them only the challenge path.
func TestRunACMEChallengeBypassesAllowlistOnHTTPPort(t *testing.T) {
	td := newDeps(t)
	rn := start(t, td, Options{})
	td.net.deny.Store(true)
	td.settings.set(certs.KeyACMEEnabled, true)
	td.settings.set(certs.KeyACMEChallenge, certs.ChallengeHTTP)
	httpBase := "http://127.0.0.1:" + strconv.Itoa(td.d.Config.Server.HTTPPort)
	plain := &http.Client{CheckRedirect: noRedirect, Timeout: 5 * time.Second}
	before := rn.hits.Load()

	for _, tc := range []struct {
		method, path string
		status       int
	}{
		{"GET", "/.well-known/acme-challenge/tok123", http.StatusNotFound}, // no active challenge
		{"GET", "/", http.StatusForbidden},
		{"GET", "/.well-known/acme-challenge", http.StatusForbidden},
		{"POST", "/.well-known/acme-challenge/tok123", http.StatusForbidden},
	} {
		req, _ := http.NewRequest(tc.method, httpBase+tc.path, nil)
		resp, err := plain.Do(req)
		if err != nil {
			t.Fatalf("%s %s: %v", tc.method, tc.path, err)
		}
		resp.Body.Close()
		if resp.StatusCode != tc.status || resp.Header.Get("Location") != "" || !resp.Close {
			t.Fatalf("%s %s: %d location=%q close=%v", tc.method, tc.path, resp.StatusCode, resp.Header.Get("Location"), resp.Close)
		}
	}
	// The HTTPS port still refuses the address.
	if conn := dialRefused(t, "127.0.0.1:"+strconv.Itoa(td.d.Config.Server.HTTPSPort)); conn != nil {
		if err := tls.Client(conn, &tls.Config{InsecureSkipVerify: true}).Handshake(); err == nil { //nolint:gosec // must not start
			t.Fatal("HTTPS handshake for a denied address")
		}
		conn.Close()
	}
	// Allowed addresses keep getting the redirect.
	td.net.deny.Store(false)
	resp, err := plain.Get(httpBase + "/x")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusPermanentRedirect {
		t.Fatalf("allowed address: %d", resp.StatusCode)
	}
	// Without the http challenge, denied addresses are refused again.
	td.net.deny.Store(true)
	td.settings.set(certs.KeyACMEChallenge, certs.ChallengeDNS)
	if _, err := plain.Get(httpBase + "/.well-known/acme-challenge/tok123"); err == nil {
		t.Fatal("denied address answered without the http challenge")
	}
	if rn.hits.Load() != before {
		t.Fatal("the application handler was reached")
	}
}

func TestRunNoSamePortRedirect(t *testing.T) {
	td := newDeps(t)
	td.d.Config.Server.SamePortRedirect = false
	td.d.Config.Server.HTTPPort = 0
	td.d.Config.AdminSocket.Enabled = false
	rn := start(t, td, Options{})
	conn, err := net.DialTimeout("tcp", "127.0.0.1:"+strconv.Itoa(td.d.Config.Server.HTTPSPort), 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	_, _ = conn.Write([]byte("GET / HTTP/1.1\r\nHost: x\r\n\r\n"))
	if line, err := bufio.NewReader(conn).ReadString('\n'); err == nil {
		t.Fatalf("plain HTTP answered without same_port_redirect: %q", line)
	}
	if _, err := os.Stat(td.d.Home.Socket()); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("admin socket created although disabled")
	}
	_ = rn
}

func TestRunListenFailure(t *testing.T) {
	td := newDeps(t)
	ln, err := net.Listen("tcp", "127.0.0.1:"+strconv.Itoa(td.d.Config.Server.HTTPPort))
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	errc := make(chan error, 1)
	go func() { errc <- Run(context.Background(), td.d, http.NotFoundHandler(), Options{}) }()
	select {
	case err := <-errc:
		if err == nil || !strings.Contains(err.Error(), "listen") {
			t.Fatalf("Run with a busy port: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Run did not fail")
	}
	if _, err := os.Stat(td.d.Home.PIDFile()); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("pid file left after a failed start")
	}
	// The HTTPS port opened before the failure was released again.
	if c, err := net.DialTimeout("tcp", "127.0.0.1:"+strconv.Itoa(td.d.Config.Server.HTTPSPort), time.Second); err == nil {
		c.Close()
		t.Fatal("HTTPS listener leaked after a failed start")
	}
}

func TestRunValidatesDeps(t *testing.T) {
	if err := Run(context.Background(), nil, http.NotFoundHandler(), Options{}); err == nil {
		t.Fatal("nil deps accepted")
	}
	td := newDeps(t)
	if err := Run(context.Background(), td.d, nil, Options{}); err == nil {
		t.Fatal("nil handler accepted")
	}
}

func TestRunSDNotifyAndWatchdog(t *testing.T) {
	td := newDeps(t)
	// An abstract socket (Linux) keeps the name short and off the filesystem.
	sockPath := "@fp-notify-" + strconv.FormatInt(time.Now().UnixNano(), 36)
	if runtime.GOOS != "linux" {
		dir, err := shortTempDir(t)
		if err != nil {
			t.Fatal(err)
		}
		sockPath = filepath.Join(dir, "notify")
	}
	pc, err := net.ListenUnixgram("unixgram", &net.UnixAddr{Name: sockPath, Net: "unixgram"})
	if err != nil {
		t.Skipf("unixgram unavailable: %v", err)
	}
	defer pc.Close()
	t.Setenv("NOTIFY_SOCKET", sockPath)
	t.Setenv("WATCHDOG_USEC", "200000")
	t.Setenv("WATCHDOG_PID", strconv.Itoa(os.Getpid()))
	msgs := make(chan string, 64)
	go func() {
		buf := make([]byte, 4096)
		for {
			n, _, err := pc.ReadFromUnix(buf)
			if err != nil {
				return
			}
			msgs <- string(buf[:n])
		}
	}()
	rn := start(t, td, Options{Foreground: false})
	seen := map[string]bool{}
	deadline := time.After(10 * time.Second)
	for !seen["READY=1"] || !seen["WATCHDOG=1"] {
		select {
		case m := <-msgs:
			for _, line := range strings.Split(m, "\n") {
				seen[line] = true
			}
		case <-deadline:
			t.Fatalf("notifications %v", seen)
		}
	}
	if err := rn.stop(t); err != nil {
		t.Fatal(err)
	}
	for {
		select {
		case m := <-msgs:
			if strings.Contains(m, "STOPPING=1") {
				return
			}
		case <-time.After(5 * time.Second):
			t.Fatal("STOPPING=1 not sent")
		}
	}
}

func TestSDNotifyWithoutSocket(t *testing.T) {
	t.Setenv("NOTIFY_SOCKET", "")
	if sdNotify("READY=1") {
		t.Fatal("notification without NOTIFY_SOCKET")
	}
	t.Setenv("WATCHDOG_USEC", "1000000")
	t.Setenv("WATCHDOG_PID", "1")
	if watchdogInterval() != 0 {
		t.Fatal("watchdog for another pid")
	}
	t.Setenv("WATCHDOG_PID", "")
	if watchdogInterval() != 500*time.Millisecond {
		t.Fatal("watchdog interval must be half of WATCHDOG_USEC")
	}
}

func TestSupervised(t *testing.T) {
	for _, k := range []string{"FILEPARCEL_SUPERVISED", "INVOCATION_ID", "NOTIFY_SOCKET", "XPC_SERVICE_NAME"} {
		t.Setenv(k, "")
	}
	if Supervised() {
		t.Fatal("supervised without markers")
	}
	t.Setenv("XPC_SERVICE_NAME", "application.com.apple.Terminal.1")
	if Supervised() {
		t.Fatal("terminal counted as launchd job")
	}
	t.Setenv("XPC_SERVICE_NAME", "com.fileparcel.server")
	if !Supervised() {
		t.Fatal("launchd job not detected")
	}
	t.Setenv("XPC_SERVICE_NAME", "")
	t.Setenv("INVOCATION_ID", "abc")
	if !Supervised() {
		t.Fatal("systemd not detected")
	}
}

func TestRedirectTarget(t *testing.T) {
	pu, _ := url.Parse("https://files.example.com")
	lc := listenConfig{httpsPort: 8443, publicURL: pu}
	tests := []struct {
		host, uri, want string
	}{
		{"fileparcel.local:8080", "/a?b=1", "https://fileparcel.local:8443/a?b=1"},
		{"192.168.1.10", "/", "https://192.168.1.10:8443/"},
		{"[fd7a::1]:8080", "/x", "https://[fd7a::1]:8443/x"},
		{"FILES.example.com", "/s/t", "https://files.example.com/s/t"},
		{"bad host!", "/", "https://10.9.8.7:8443/"},
		{"evil.com@x", "/", "https://10.9.8.7:8443/"},
		{"a.local", "//evil.com/p", "https://a.local:8443//evil.com/p"},
	}
	for _, tc := range tests {
		r, _ := http.NewRequest(http.MethodGet, "http://placeholder"+tc.uri, nil)
		r.Host = tc.host
		r = r.WithContext(context.WithValue(r.Context(), http.LocalAddrContextKey, &net.TCPAddr{IP: net.ParseIP("10.9.8.7"), Port: 8443}))
		if got := redirectTarget(r, lc); got != tc.want {
			t.Errorf("%s %s → %s, want %s", tc.host, tc.uri, got, tc.want)
		}
	}
	lc443 := listenConfig{httpsPort: 443}
	r, _ := http.NewRequest(http.MethodGet, "http://x/", nil)
	r.Host = "::1"
	if got := redirectTarget(r, lc443); got != "https://[::1]/" {
		t.Errorf("port 443 IPv6: %s", got)
	}
}
