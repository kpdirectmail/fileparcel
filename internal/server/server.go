// Package server runs the network side of `fileparcel serve` (DESIGN §9.1,
// §10, §14): listeners with the access allowlist enforced at Accept (before
// any TLS handshake), TLS/plain-HTTP sniffing with 308 redirects on the HTTPS
// port, the optional HTTP redirect/ACME port, ACME validation from outside the
// access policy (while ACME uses the HTTP-01 or TLS-ALPN-01 challenge, other
// addresses may reach /.well-known/acme-challenge/ on the HTTP port or
// complete an acme-tls/1 handshake on the HTTPS port — nothing else), the
// admin Unix socket
// (peer-cred checked; its connections carry
// core.SystemPrincipal(core.ViaSocket) in the request context via
// http.Server.ConnContext; proxied requests are refused), the mTLS gate,
// http.Server with HTTP/2 tuning, sd_notify/watchdog, graceful shutdown,
// restart requests (ErrRestart → exit 75), and the PID and clean-shutdown
// files. The access policy also reaches connections that are already open
// (connTracker). The Tailscale Funnel/Serve ingress listeners (ingress.go)
// are opened and closed by the Ingress service (Attach after the listeners
// are up, Detach before the drain); the main listener refuses requests of a
// hand-made `tailscale funnel` to its port (proxied.go). Owned by unit F.
package server

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"sync"
	"syscall"
	"time"

	"fileparcel/internal/app"
	"fileparcel/internal/certs"
	"fileparcel/internal/core"
	"fileparcel/internal/events"
	"fileparcel/internal/logx"
)

// Options configures Run. Zero ports mean "use the config values".
type Options struct {
	// Foreground: attached to a terminal (human-readable startup summary;
	// re-exec on restart when no supervisor is present).
	Foreground bool
	// Dev: development mode — Run sets the process log level to debug
	// (until log.level is changed live). Static assets keep their long-lived
	// caching: their URLs carry a content hash, so a rebuild changes them.
	Dev bool
	// Cleanup, when set, stops the services (the serve command passes wire's
	// cleanup). Run calls it after the HTTP drain and only then records the
	// clean shutdown and removes the PID file, so a stop that the supervisor
	// kills while services close is reported as unclean at the next start.
	Cleanup func()
	// HTTPSPort overrides server.https_port when > 0.
	HTTPSPort int
	// HTTPPort overrides server.http_port when > 0.
	HTTPPort int
}

// ExitRestart is the process exit code that asks the supervisor
// (systemd/launchd) to restart FileParcel (DESIGN §11.3).
const ExitRestart = 75

// ErrRestart is returned by Run after a graceful shutdown that was requested
// through events.TopicSystemRestart. The serve command then exits with
// ExitRestart (or re-execs itself when no supervisor restarts it, see
// Supervised and ReExec).
var ErrRestart = errors.New("server: restart requested")

// Timeouts and limits of the HTTP servers (DESIGN §9.1, §18.14).
const (
	readHeaderTimeout = 10 * time.Second
	idleTimeout       = 120 * time.Second
	maxHeaderBytes    = 64 << 10
	sniffTimeout      = 10 * time.Second
	// bodyIdleTimeout bounds how long one read of a request body may wait
	// for the client (rolling, see bodyTimeout): a stalled sender is torn
	// down, a slow but steady one is not.
	bodyIdleTimeout = 30 * time.Second
	// ShutdownTimeout bounds the graceful drain on stop/restart. The job
	// runner stops in the same window (jobs still running after
	// ShutdownTimeout-jobsCancelGrace are cancelled), which leaves the
	// service cleanup that follows (Options.Cleanup) about 10 s of the
	// supervisor's stop timeout (TimeoutStopSec=40, Docker
	// stop_grace_period 40s, launchd ExitTimeOut 40).
	ShutdownTimeout = 30 * time.Second
	// jobsCancelGrace is how long jobs.Stop waits for cancelled jobs.
	jobsCancelGrace = 5 * time.Second
	// HTTP/2 flow-control windows: large enough for 8 MiB upload parts over
	// high-latency links (VPNs) without stalls.
	h2ConnWindow   = 16 << 20
	h2StreamWindow = 8 << 20
)

// runner holds the state of one Run.
type runner struct {
	d    *app.Deps
	log  *slog.Logger
	opts Options
	cfg  listenConfig

	streams *streams
	conns   *connTracker
	servers []*http.Server
	sock    *socketListener
	ingress *ingressManager // nil without an Ingress service
	errCh   chan error
	wg      sync.WaitGroup

	stopWatchdog context.CancelFunc
	stopSweep    context.CancelFunc
}

// Run serves h until ctx is cancelled or SIGTERM/SIGINT arrives (graceful
// shutdown, returns nil), a restart is requested (returns ErrRestart after
// the graceful shutdown) or a listener fails (returns the error). d must come
// from wire.Build(…, app.ModeNetwork) and wire.Start must have been called.
// After the drain Run calls opts.Cleanup, then writes the clean-shutdown
// marker (stop and restart only) and removes the PID file; a failed start
// returns before either and leaves the cleanup to the caller.
func Run(ctx context.Context, d *app.Deps, h http.Handler, opts Options) error {
	if d == nil || d.Env == nil || d.Config == nil || d.Home == nil {
		return errors.New("server: incomplete dependencies")
	}
	if h == nil {
		return errors.New("server: nil handler")
	}
	log := d.Log
	if log == nil {
		log = slog.Default()
	}
	if opts.Dev {
		if err := logx.SetLevel("debug"); err == nil {
			log.Debug("development mode: logging at debug level")
		}
	}
	r := &runner{d: d, log: log.With("component", "server"), opts: opts, streams: &streams{}}
	r.cfg = resolveListenConfig(d, opts)

	ctx, stopSignals := signal.NotifyContext(ctx, syscall.SIGTERM, os.Interrupt)
	defer stopSignals()
	var restartCh <-chan events.Event
	if d.Bus != nil {
		ch, unsub := d.Bus.Subscribe(events.TopicSystemRestart)
		defer unsub()
		restartCh = ch
	}

	r.preparePIDFile()
	if err := r.listen(ctx, h); err != nil {
		r.closeAll()
		removePIDFile(d.Home.PIDFile())
		return err
	}
	r.startSweep(ctx)
	if d.Ingress != nil {
		// The first reconcile runs in the background: tailscaled is only
		// pointed at an ingress listener once it is open.
		r.ingress = newIngressManager(d, h, r.log, newErrorLog(r.log))
		d.Ingress.Attach(r.ingress)
	}
	r.announce(ctx)

	reason, result := r.wait(ctx, restartCh)
	r.shutdown(reason)
	if opts.Cleanup != nil {
		opts.Cleanup()
	}
	if result == nil || errors.Is(result, ErrRestart) {
		writeCleanShutdown(d.Home.CleanShutdownFile(), d.Now())
	}
	removePIDFile(d.Home.PIDFile())
	return result
}

// wait blocks until a stop, restart or listener failure.
func (r *runner) wait(ctx context.Context, restartCh <-chan events.Event) (reason string, err error) {
	for {
		select {
		case <-ctx.Done():
			return "stop", nil
		case _, ok := <-restartCh:
			if !ok {
				restartCh = nil // bus closed: keep serving until stopped
				continue
			}
			r.log.Info("restart requested")
			return "restart", ErrRestart
		case err := <-r.errCh:
			r.log.Error("listener failed; shutting down", "err", err)
			return "error", err
		}
	}
}

// listen opens every listener and starts the servers.
func (r *runner) listen(ctx context.Context, h http.Handler) error {
	r.errCh = make(chan error, 16)
	d := r.d
	if d.Certs == nil || d.Certs.TLSConfig() == nil {
		return errors.New("server: no TLS configuration (certificates service missing)")
	}
	if d.Certs.Fingerprint() == "" {
		r.log.Warn(`no local CA exists; HTTPS handshakes will fail until "fileparcel init" creates the certificates`)
	}
	errorLog := newErrorLog(r.log)
	if len(r.cfg.bindsDropped) > 0 {
		r.log.Warn("server.bind: ignoring addresses another entry already covers (\"::\" and \"0.0.0.0\" listen on every address)",
			"ignored", r.cfg.bindsDropped, "listening_on", r.cfg.binds)
	}
	r.conns = newConnTracker(allowFunc(d), newDenyLog(r.log))
	httpsHandler := r.streams.wrap(r.conns.guard(httpsRoot(d, h, r.cfg, r.log)))
	httpsSrv := newHTTPServer(httpsHandler, errorLog, true)
	httpsSrv.ConnState = r.conns.connState
	httpsSrv.ConnContext = r.conns.connContext
	r.servers = append(r.servers, httpsSrv)
	for _, bind := range r.cfg.binds {
		ln, err := listenTCP(ctx, bind, r.cfg.httpsPort)
		if err != nil {
			return fmt.Errorf("server: listen on %s: %w", net.JoinHostPort(bind, strconv.Itoa(r.cfg.httpsPort)), err)
		}
		mux := newMuxListener(ln, allowFunc(d), acmeChallengeOpen(d, certs.ChallengeTLSALPN), d.Certs.TLSConfig(),
			r.cfg.samePortRedirect, newDenyLog(r.log))
		r.serve(httpsSrv, mux)
		r.log.Info("HTTPS listener started", "addr", ln.Addr().String(), "plain_http_redirect", r.cfg.samePortRedirect)
	}

	if r.cfg.httpPort > 0 {
		httpSrv := newHTTPServer(challengeGate(d.Certs.HTTPChallenge(redirectHandler(r.cfg)),
			d.Certs.HTTPChallenge(http.NotFoundHandler())), errorLog, false)
		httpSrv.ConnContext = challengeConnContext
		r.servers = append(r.servers, httpSrv)
		for _, bind := range r.cfg.binds {
			ln, err := listenTCP(ctx, bind, r.cfg.httpPort)
			if err != nil {
				return fmt.Errorf("server: listen on %s: %w", net.JoinHostPort(bind, strconv.Itoa(r.cfg.httpPort)), err)
			}
			r.serve(httpSrv, &filterListener{Listener: ln, allowed: allowFunc(d), challengeOnly: acmeChallengeOpen(d, certs.ChallengeHTTP),
				deny: newDenyLog(r.log)})
			r.log.Info("HTTP redirect listener started", "addr", ln.Addr().String())
		}
	}

	if d.Config.AdminSocket.Enabled {
		sl, err := listenSocket(d.Home.Socket(), r.log)
		if err != nil {
			return fmt.Errorf("server: admin socket: %w", err)
		}
		r.sock = sl
		sockSrv := newHTTPServer(r.streams.wrap(refuseProxied(h, r.log)), errorLog, false)
		sockSrv.ConnContext = func(ctx context.Context, _ net.Conn) context.Context {
			return core.WithPrincipal(ctx, core.SystemPrincipal(core.ViaSocket))
		}
		r.servers = append(r.servers, sockSrv)
		r.serve(sockSrv, sl)
		r.log.Info("admin socket listening", "path", d.Home.Socket())
	}
	return nil
}

// serve runs srv on ln in a goroutine; unexpected errors go to errCh.
func (r *runner) serve(srv *http.Server, ln net.Listener) {
	r.wg.Add(1)
	go func() {
		defer r.wg.Done()
		if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			select {
			case r.errCh <- err:
			default:
			}
		}
	}()
}

// newHTTPServer returns an http.Server with the DESIGN §9.1 limits, request
// bodies under the rolling bodyIdleTimeout. tls enables HTTP/2 (negotiated by
// ALPN on the TLS connections the mux listener produces); plain listeners
// speak HTTP/1.1 only.
func newHTTPServer(h http.Handler, errorLog *slogWriterLog, tls bool) *http.Server {
	srv := &http.Server{
		Handler:           bodyTimeout(bodyIdleTimeout)(h),
		ReadHeaderTimeout: readHeaderTimeout,
		IdleTimeout:       idleTimeout,
		MaxHeaderBytes:    maxHeaderBytes,
		ErrorLog:          errorLog.logger(),
	}
	p := new(http.Protocols)
	p.SetHTTP1(true)
	if tls {
		p.SetHTTP2(true)
		srv.HTTP2 = &http.HTTP2Config{
			MaxReceiveBufferPerConnection: h2ConnWindow,
			MaxReceiveBufferPerStream:     h2StreamWindow,
		}
	}
	srv.Protocols = p
	return srv
}

// startSweep re-checks the open HTTPS connections against the access policy
// every policySweepEvery until shutdown (see connTracker).
func (r *runner) startSweep(ctx context.Context) {
	if r.conns == nil {
		return
	}
	sctx, cancel := context.WithCancel(ctx)
	r.stopSweep = cancel
	every := policySweepEvery
	r.wg.Go(func() { r.conns.run(sctx, every) })
}

// shutdown drains every server for up to ShutdownTimeout, then closes what
// is left. The job runner stops meanwhile — it no longer starts jobs, and
// cancels the ones still running jobsCancelGrace before the drain deadline —
// instead of after the drain, so that the two waits do not add up.
//
// The Ingress service is detached first (bounded by ingressDetachTimeout):
// with the TCP backend it removes FileParcel's entries from tailscaled while
// the ingress listeners still hold their ports, so no other program can take
// them over in between. The ingress listeners then drain with the others.
func (r *runner) shutdown(reason string) {
	sdNotify("STOPPING=1\nSTATUS=Stopping (" + reason + ")")
	r.log.Info("shutting down", "reason", reason, "drain", ShutdownTimeout.String())
	if r.stopWatchdog != nil {
		r.stopWatchdog()
	}
	if r.stopSweep != nil {
		r.stopSweep()
	}
	var ingress []*ingressLn
	if r.ingress != nil {
		ingress = r.ingress.stop()
		dctx, dcancel := context.WithTimeout(context.Background(), ingressDetachTimeout)
		r.d.Ingress.Detach(dctx)
		dcancel()
	}
	r.streams.closeAll()
	ctx, cancel := context.WithTimeout(context.Background(), ShutdownTimeout)
	defer cancel()
	var wg sync.WaitGroup
	if r.d.Jobs != nil {
		wg.Go(func() {
			jctx, jcancel := context.WithTimeout(ctx, ShutdownTimeout-jobsCancelGrace)
			defer jcancel()
			if err := r.d.Jobs.Stop(jctx); err != nil {
				r.log.Warn("jobs did not stop cleanly", "err", err)
			}
		})
	}
	for _, srv := range r.servers {
		wg.Go(func() {
			if err := srv.Shutdown(ctx); err != nil {
				r.log.Warn("graceful shutdown incomplete; closing remaining connections", "err", err)
				_ = srv.Close()
			}
		})
	}
	if r.ingress != nil {
		wg.Go(func() { r.ingress.drain(ctx, ingress) })
	}
	wg.Wait()
	if r.sock != nil {
		r.sock.removeFile()
	}
	r.wg.Wait()
	if r.d.Audit != nil {
		r.d.Audit.Record(context.Background(), core.AuditEntry{Action: core.ActSystemStop, TargetType: "system",
			ActorName: "system", Details: map[string]any{"reason": reason}})
	}
	r.log.Info("server stopped", "reason", reason)
}

// closeAll closes servers after a failed start.
func (r *runner) closeAll() {
	for _, srv := range r.servers {
		_ = srv.Close()
	}
	if r.sock != nil {
		_ = r.sock.Close()
		r.sock.removeFile()
	}
	r.wg.Wait()
}
