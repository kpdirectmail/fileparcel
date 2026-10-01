package server

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"fileparcel/internal/app"
	"fileparcel/internal/certs"
)

// listenConfig is the resolved listener configuration.
type listenConfig struct {
	binds            []string
	bindsDropped     []string // server.bind entries another entry covers (see mergeBinds)
	httpsPort        int
	httpPort         int
	samePortRedirect bool
	publicURL        *url.URL // nil when unset or invalid
}

// resolveListenConfig reads server.* from the bootstrap config (restart
// required settings) and applies the Options overrides.
func resolveListenConfig(d *app.Deps, opts Options) listenConfig {
	c := d.Config.Server
	lc := listenConfig{
		binds:            append([]string(nil), c.Bind...),
		httpsPort:        c.HTTPSPort,
		httpPort:         c.HTTPPort,
		samePortRedirect: c.SamePortRedirect,
	}
	if len(lc.binds) == 0 {
		lc.binds = []string{"::"}
	}
	lc.binds, lc.bindsDropped = mergeBinds(lc.binds)
	if lc.httpsPort <= 0 {
		lc.httpsPort = 8443
	}
	if opts.HTTPSPort > 0 {
		lc.httpsPort = opts.HTTPSPort
	}
	if opts.HTTPPort > 0 {
		lc.httpPort = opts.HTTPPort
	}
	if lc.httpPort < 0 {
		lc.httpPort = 0
	}
	if c.PublicURL != "" {
		if u, err := url.Parse(c.PublicURL); err == nil && u.Scheme == "https" && u.Host != "" {
			lc.publicURL = u
		}
	}
	return lc
}

// mergeBinds drops the server.bind entries that another entry already
// covers: repeated addresses (compared unmapped, so ::ffff:127.0.0.1 is
// 127.0.0.1) and, next to a wildcard, everything else — "::" and "0.0.0.0"
// both listen on every IPv4 and IPv6 address (Go opens either dual-stack),
// so the list [::, 0.0.0.0] or [::, 100.64.0.1] would otherwise fail to
// listen with "address already in use" and keep the server from starting.
// The first wildcard wins. Entries that are not IP addresses are kept (the
// listener reports them).
func mergeBinds(binds []string) (keep, dropped []string) {
	for i, b := range binds {
		if a, err := netip.ParseAddr(strings.Trim(b, "[]")); err == nil && a.IsUnspecified() {
			return []string{b}, append(slices.Clone(binds[:i]), binds[i+1:]...)
		}
	}
	seen := map[netip.Addr]bool{}
	for _, b := range binds {
		a, err := netip.ParseAddr(strings.Trim(b, "[]"))
		if err == nil {
			if a = a.Unmap(); seen[a] {
				dropped = append(dropped, b)
				continue
			}
			seen[a] = true
		}
		keep = append(keep, b)
	}
	return keep, dropped
}

// listenTCP listens on bind:port. The dual-stack wildcard "::" falls back to
// 0.0.0.0 on hosts without IPv6.
func listenTCP(ctx context.Context, bind string, port int) (net.Listener, error) {
	var lc net.ListenConfig
	addr := net.JoinHostPort(strings.Trim(bind, "[]"), strconv.Itoa(port))
	ln, err := lc.Listen(ctx, "tcp", addr)
	if err != nil && (bind == "::" || bind == "[::]") && isNoIPv6(err) {
		return lc.Listen(ctx, "tcp4", net.JoinHostPort("0.0.0.0", strconv.Itoa(port)))
	}
	return ln, err
}

func isNoIPv6(err error) bool {
	return errors.Is(err, syscall.EAFNOSUPPORT) || errors.Is(err, syscall.EADDRNOTAVAIL) || errors.Is(err, syscall.EPROTONOSUPPORT)
}

// allowFunc returns the access-policy check (DESIGN §10.3); a missing
// network service allows everything.
func allowFunc(d *app.Deps) func(netip.Addr) bool {
	if d.Network == nil {
		return func(netip.Addr) bool { return true }
	}
	return d.Network.Allowed
}

// acmeChallengeOpen reports whether ACME uses the given challenge type,
// whose validation servers must reach us from public addresses (HTTP-01 on
// the HTTP port, TLS-ALPN-01 on the HTTPS port).
func acmeChallengeOpen(d *app.Deps, challenge string) func() bool {
	return func() bool {
		return d.Settings != nil && d.Settings.Bool(certs.KeyACMEEnabled) &&
			d.Settings.String(certs.KeyACMEChallenge) == challenge
	}
}

// remoteIP returns the unmapped remote IP of a TCP connection.
func remoteIP(c net.Conn) netip.Addr {
	if a, ok := c.RemoteAddr().(*net.TCPAddr); ok {
		return a.AddrPort().Addr().Unmap().WithZone("")
	}
	if ap, err := netip.ParseAddrPort(c.RemoteAddr().String()); err == nil {
		return ap.Addr().Unmap().WithZone("")
	}
	return netip.Addr{}
}

// denyLog logs refused connections, at most one line per denyLogEvery with
// the number of suppressed ones (denials are not audited, DESIGN §10.3).
type denyLog struct {
	log        *slog.Logger
	mu         sync.Mutex
	last       time.Time
	suppressed int
}

const denyLogEvery = 10 * time.Second

func newDenyLog(log *slog.Logger) *denyLog { return &denyLog{log: log} }

func (l *denyLog) denied(ip netip.Addr, local net.Addr) {
	l.mu.Lock()
	now := time.Now()
	if now.Sub(l.last) < denyLogEvery {
		l.suppressed++
		l.mu.Unlock()
		return
	}
	n := l.suppressed
	l.last, l.suppressed = now, 0
	l.mu.Unlock()
	l.log.Warn("connection refused by the access policy", "ip", ip.String(), "listener", local.String(), "suppressed", n)
}

// refuse closes a connection refused by the access policy immediately
// (before any TLS handshake or HTTP parsing).
func refuse(c net.Conn, ip netip.Addr, deny *denyLog) {
	if tc, ok := c.(*net.TCPConn); ok {
		_ = tc.SetLinger(0) // RST: no FIN_WAIT for refused peers
	}
	_ = c.Close()
	deny.denied(ip, c.LocalAddr())
}

// acceptBackoff sleeps after a temporary Accept error (like net/http).
func acceptBackoff(delay time.Duration) time.Duration {
	if delay == 0 {
		delay = 5 * time.Millisecond
	} else {
		delay *= 2
	}
	return min(delay, time.Second)
}

// filterListener enforces the allowlist on a plain listener (HTTP port).
// While challengeOnly reports true (ACME HTTP-01 is configured), refused
// addresses are admitted as *challengeConn instead: the ACME validation
// servers connect from public addresses, and those connections are served
// nothing but /.well-known/acme-challenge/ (see challengeGate).
type filterListener struct {
	net.Listener
	allowed       func(netip.Addr) bool
	challengeOnly func() bool // nil = never
	deny          *denyLog
}

// Accept returns the next allowed connection.
func (l *filterListener) Accept() (net.Conn, error) {
	for {
		c, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		ip := remoteIP(c)
		if ip.IsValid() && l.allowed(ip) {
			return c, nil
		}
		if ip.IsValid() && l.challengeOnly != nil && l.challengeOnly() {
			return &challengeConn{Conn: c}, nil
		}
		refuse(c, ip, l.deny)
	}
}

// challengeConn marks a connection from an address outside the access
// policy that was admitted only for ACME HTTP-01 validation.
type challengeConn struct{ net.Conn }

type challengeOnlyKey struct{}

// challengeConnContext tags the requests of a challengeConn (http.Server.ConnContext).
func challengeConnContext(ctx context.Context, c net.Conn) context.Context {
	if _, ok := c.(*challengeConn); ok {
		return context.WithValue(ctx, challengeOnlyKey{}, true)
	}
	return ctx
}

// acmeChallengePrefix is the RFC 8555 HTTP-01 path.
const acmeChallengePrefix = "/.well-known/acme-challenge/"

// challengeGate serves the HTTP port: normal requests get the ACME answer
// or the 308 redirect (full); requests on a challengeConn get only the ACME
// answer (challenge, which ends in 404) and anything else 403 with the
// connection closed.
func challengeGate(full, challenge http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Context().Value(challengeOnlyKey{}) == nil {
			full.ServeHTTP(w, r)
			return
		}
		w.Header().Set("Connection", "close")
		if r.Method != http.MethodGet || !strings.HasPrefix(r.URL.Path, acmeChallengePrefix) {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		challenge.ServeHTTP(w, r)
	})
}

// muxListener serves the HTTPS port: it accepts TCP connections, applies the
// allowlist, sniffs the first byte (0x16 = TLS handshake record) and hands
// out *tls.Conn values for TLS and prefix-replaying plain connections for
// HTTP (when same-port redirects are enabled; otherwise those are closed).
// The http.Server performs the TLS handshake itself (with its timeouts) and
// answers plain requests with the 308 redirect (httpsRoot).
//
// While challengeOnly reports true (ACME uses the TLS-ALPN-01 challenge),
// addresses outside the access policy may complete an acme-tls/1 validation
// handshake (RFC 8737) and nothing else: any other ClientHello is refused
// and such connections never reach the http.Server.
type muxListener struct {
	ln            net.Listener
	allowed       func(netip.Addr) bool
	challengeOnly func() bool // nil = never
	tlsConf       *tls.Config
	redirect      bool
	deny          *denyLog

	conns     chan net.Conn
	done      chan struct{}
	closeOnce sync.Once
	errMu     sync.Mutex
	err       error
	wg        sync.WaitGroup
}

func newMuxListener(ln net.Listener, allowed func(netip.Addr) bool, challengeOnly func() bool, tlsConf *tls.Config,
	redirect bool, deny *denyLog) *muxListener {
	m := &muxListener{ln: ln, allowed: allowed, challengeOnly: challengeOnly, tlsConf: tlsConf, redirect: redirect, deny: deny,
		conns: make(chan net.Conn), done: make(chan struct{})}
	m.wg.Add(1)
	go m.acceptLoop()
	return m
}

func (m *muxListener) acceptLoop() {
	defer m.wg.Done()
	var delay time.Duration
	for {
		c, err := m.ln.Accept()
		if err != nil {
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				delay = acceptBackoff(delay)
				select {
				case <-time.After(delay):
					continue
				case <-m.done:
					return
				}
			}
			if isTemporaryAcceptError(err) {
				delay = acceptBackoff(delay)
				select {
				case <-time.After(delay):
					continue
				case <-m.done:
					return
				}
			}
			m.fail(err)
			return
		}
		delay = 0
		ip := remoteIP(c)
		switch {
		case ip.IsValid() && m.allowed(ip):
			go m.sniff(c)
		case ip.IsValid() && m.challengeOnly != nil && m.challengeOnly():
			go m.challenge(c)
		default:
			refuse(c, ip, m.deny)
		}
	}
}

// errNotACME refuses non-validation handshakes of challenge-only peers.
var errNotACME = errors.New("server: address not allowed (only ACME TLS-ALPN validation)")

// isACMEHello reports whether hello is an ACME TLS-ALPN-01 validation
// (RFC 8737: SNI set and acme-tls/1 as the only protocol).
func isACMEHello(hello *tls.ClientHelloInfo) bool {
	return hello.ServerName != "" && len(hello.SupportedProtos) == 1 && hello.SupportedProtos[0] == "acme-tls/1"
}

// challenge completes an ACME TLS-ALPN-01 validation handshake for a peer
// outside the access policy (the certificate service answers it) and closes
// the connection; anything else fails the handshake.
func (m *muxListener) challenge(c net.Conn) {
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(sniffTimeout))
	base := m.tlsConf
	tc := tls.Server(c, &tls.Config{
		MinVersion: tls.VersionTLS12,
		GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
			if !isACMEHello(hello) || base == nil || base.GetConfigForClient == nil {
				return nil, errNotACME
			}
			return base.GetConfigForClient(hello)
		},
	})
	if err := tc.Handshake(); err != nil {
		m.deny.denied(remoteIP(c), c.LocalAddr())
		return
	}
	_ = tc.Close() // the validator only checks the handshake
}

// isTemporaryAcceptError reports resource exhaustion errors worth retrying.
func isTemporaryAcceptError(err error) bool {
	return errors.Is(err, syscall.EMFILE) || errors.Is(err, syscall.ENFILE) || errors.Is(err, syscall.ENOBUFS) ||
		errors.Is(err, syscall.ENOMEM) || errors.Is(err, syscall.ECONNABORTED)
}

// sniff reads the first byte (bounded by sniffTimeout) and dispatches c.
func (m *muxListener) sniff(c net.Conn) {
	_ = c.SetReadDeadline(time.Now().Add(sniffTimeout))
	var b [1]byte
	if _, err := io.ReadFull(c, b[:]); err != nil {
		_ = c.Close()
		return
	}
	_ = c.SetReadDeadline(time.Time{})
	pc := &prefixConn{Conn: c, prefix: b[:]}
	var out net.Conn
	switch {
	case b[0] == 0x16:
		out = tls.Server(pc, m.tlsConf)
	case m.redirect:
		out = pc
	default:
		_ = c.Close()
		return
	}
	select {
	case m.conns <- out:
	case <-m.done:
		_ = c.Close()
	}
}

// Accept implements net.Listener.
func (m *muxListener) Accept() (net.Conn, error) {
	select {
	case c := <-m.conns:
		return c, nil
	case <-m.done:
		m.errMu.Lock()
		defer m.errMu.Unlock()
		if m.err != nil {
			return nil, m.err
		}
		return nil, net.ErrClosed
	}
}

// fail records a permanent accept error and closes the listener.
func (m *muxListener) fail(err error) {
	m.errMu.Lock()
	if m.err == nil {
		m.err = err
	}
	m.errMu.Unlock()
	_ = m.Close()
}

// Close implements net.Listener (idempotent).
func (m *muxListener) Close() error {
	var err error
	m.closeOnce.Do(func() {
		close(m.done)
		err = m.ln.Close()
	})
	return err
}

// Addr implements net.Listener.
func (m *muxListener) Addr() net.Addr { return m.ln.Addr() }

// prefixConn replays already-read bytes before reading from the connection.
type prefixConn struct {
	net.Conn
	prefix []byte
}

// Read implements io.Reader.
func (c *prefixConn) Read(p []byte) (int, error) {
	if len(c.prefix) > 0 {
		n := copy(p, c.prefix)
		c.prefix = c.prefix[n:]
		return n, nil
	}
	return c.Conn.Read(p)
}
