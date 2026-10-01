package server

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"fileparcel/internal/app"
	"fileparcel/internal/core"
	"fileparcel/internal/tsingress"
	"fileparcel/internal/web/mw"
)

// Tailscale Funnel and Serve ingress listeners (DESIGN §10.6). tailscaled
// terminates TLS for the node's MagicDNS name and proxies HTTP/1.1 to a
// dedicated listener per kind, which package tsingress asks for through
// core.IngressListeners: a Unix socket <HOME>/run/ts-{funnel,serve}.sock
// (0600 in the 0700 run directory), or 127.0.0.1:<port> where tailscaled
// refuses Unix-socket targets. Only tailscaled may connect: the peer's uid
// must be root, the owner of tailscaled's socket or this process's (checked
// at Accept). Requests are told apart by the listener they came through,
// never by a header: ingressHandler validates tailscaled's proxy headers,
// makes the real client the request's RemoteAddr, marks the request with
// core.IngressInfo and removes the headers; mw.IngressGate then applies the
// kind's policy. These listeners serve plain HTTP (TLS ended in tailscaled),
// so neither the HTTPS redirect nor the mTLS gate of the main listener
// applies, and the connection tracker of the access policy does not either
// (their peer is tailscaled; IngressGate checks every request).

// Ingress listener errors.
var (
	errShuttingDown = errors.New("server: shutting down")
	errPathTooLong  = errors.New("server: the ingress socket path is too long for tailscaled to dial")
)

// Timeouts of the ingress listeners.
const (
	ingressCloseTimeout  = 5 * time.Second // Close(kind): drain, then close
	ingressDetachTimeout = 5 * time.Second // Ingress.Detach on shutdown
	refusedLogEvery      = time.Minute
)

// ingressManager implements core.IngressListeners for the running server.
type ingressManager struct {
	d        *app.Deps
	h        http.Handler // the root router
	log      *slog.Logger
	errorLog *slogWriterLog

	mu     sync.Mutex
	closed bool // set when the shutdown begins; Open then fails with errShuttingDown
	// open holds the listeners by kind and address. A kind normally has one;
	// with the TCP backend tsingress keeps the old 127.0.0.1 port bound
	// (OpenAt) while tailscaled may still route to it.
	open map[lnKey]*ingressLn
	wg   sync.WaitGroup // Serve goroutines
}

// lnKey identifies one ingress listener.
type lnKey struct{ kind, address string }

// ingressLn is one open ingress listener and its server.
type ingressLn struct {
	kind, network, address string
	peerUIDs               []int
	ln                     *ingressListener
	srv                    *http.Server
	streams                *streams
	sock                   *socketListener // unix: removes the socket file
}

var _ core.IngressListeners = (*ingressManager)(nil)

// tsingress type-asserts these methods (its addrListeners): without them it
// could not keep an old 127.0.0.1 port bound next to the new listener.
var _ interface {
	OpenAt(kind, network, address string, peerUIDs []int) error
	CloseAt(kind, network, address string)
} = (*ingressManager)(nil)

func newIngressManager(d *app.Deps, h http.Handler, log *slog.Logger, errorLog *slogWriterLog) *ingressManager {
	return &ingressManager{d: d, h: h, log: log, errorLog: errorLog, open: map[lnKey]*ingressLn{}}
}

// Open starts kind's ingress listener on network ("unix": a socket in the
// run directory; "tcp4": 127.0.0.1:<port>) at address, accepting only the
// peer uids listed. The same arguments again are a no-op; different ones
// close kind's listeners and open the new one.
func (m *ingressManager) Open(kind, network, address string, peerUIDs []int) error {
	return m.open1(kind, network, address, peerUIDs, true)
}

// OpenAt is Open without closing kind's listeners at other addresses
// (tsingress keeps an old 127.0.0.1 port bound while tailscaled may still
// route to it).
func (m *ingressManager) OpenAt(kind, network, address string, peerUIDs []int) error {
	return m.open1(kind, network, address, peerUIDs, false)
}

// CloseAt closes kind's listener at address, like Close.
func (m *ingressManager) CloseAt(kind, network, address string) {
	m.mu.Lock()
	l := m.open[lnKey{kind, address}]
	if l != nil && l.network != network {
		l = nil
	}
	if l != nil {
		delete(m.open, lnKey{kind, address})
	}
	m.mu.Unlock()
	if l != nil {
		m.closeLn(l, ingressCloseTimeout)
	}
}

func (m *ingressManager) open1(kind, network, address string, peerUIDs []int, only bool) error {
	if kind != core.IngressFunnel && kind != core.IngressServe {
		return fmt.Errorf("server: unknown ingress kind %q", kind)
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return errShuttingDown
	}
	key := lnKey{kind, address}
	for k, cur := range m.open {
		if k.kind != kind || k != key && !only {
			continue
		}
		if k == key && cur.network == network && slices.Equal(cur.peerUIDs, peerUIDs) {
			continue
		}
		delete(m.open, k)
		m.closeLn(cur, ingressCloseTimeout)
	}
	if m.open[key] != nil {
		return nil
	}
	l, err := m.listen(kind, network, address, peerUIDs)
	if err != nil {
		return err
	}
	st := &streams{}
	srv := newHTTPServer(st.wrap(ingressHandler(m.d, m.h, kind, m.log)), m.errorLog, false)
	l.srv, l.streams = srv, st
	m.open[key] = l
	m.wg.Add(1)
	go func() {
		defer m.wg.Done()
		if err := srv.Serve(l.ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			m.log.Warn("ingress listener stopped", "kind", kind, "err", err)
		}
	}()
	m.log.Info("ingress listener started", "kind", kind, "network", network, "address", address)
	return nil
}

// listen creates the listener of Open.
func (m *ingressManager) listen(kind, network, address string, peerUIDs []int) (*ingressLn, error) {
	l := &ingressLn{kind: kind, network: network, address: address, peerUIDs: slices.Clone(peerUIDs)}
	il := &ingressListener{kind: kind, allowed: l.peerUIDs, log: m.log, refused: &logEvery{every: refusedLogEvery}}
	switch network {
	case "unix":
		if m.d == nil || m.d.Home == nil || filepath.Dir(address) != filepath.Clean(m.d.Home.RunDir()) {
			return nil, fmt.Errorf("server: the %s ingress socket must be in %s", kind, m.runDir())
		}
		if len(address) > maxSocketPath {
			return nil, errPathTooLong
		}
		sl, err := listenSocket(address, m.log)
		if err != nil {
			return nil, err
		}
		l.sock = sl
		il.Listener, il.uidOf = sl.UnixListener, unixPeerUID
	case "tcp4":
		ap, err := netip.ParseAddrPort(address)
		if err != nil || ap.Addr() != netip.AddrFrom4([4]byte{127, 0, 0, 1}) || ap.Port() == 0 {
			return nil, fmt.Errorf("server: the %s ingress listener must be on 127.0.0.1 with a port, not %q", kind, address)
		}
		ln, err := net.Listen("tcp4", ap.String())
		if err != nil {
			return nil, err
		}
		il.Listener, il.uidOf = ln, loopbackPeerUID
	default:
		return nil, fmt.Errorf("server: unsupported ingress network %q", network)
	}
	l.ln = il
	return l, nil
}

func (m *ingressManager) runDir() string {
	if m.d == nil || m.d.Home == nil {
		return "the run directory"
	}
	return m.d.Home.RunDir()
}

// Close stops kind's listeners: open requests get ingressCloseTimeout to
// finish (event streams end at once), then the rest are closed; a socket
// file is removed.
func (m *ingressManager) Close(kind string) {
	m.mu.Lock()
	var ls []*ingressLn
	for k, l := range m.open {
		if k.kind == kind {
			ls = append(ls, l)
			delete(m.open, k)
		}
	}
	m.mu.Unlock()
	for _, l := range ls {
		m.closeLn(l, ingressCloseTimeout)
	}
}

// closeLn drains and closes one listener within timeout.
func (m *ingressManager) closeLn(l *ingressLn, timeout time.Duration) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	m.drainLn(ctx, l)
}

// drainLn shuts l's server down within ctx and removes its socket file.
func (m *ingressManager) drainLn(ctx context.Context, l *ingressLn) {
	l.streams.closeAll()
	if err := l.srv.Shutdown(ctx); err != nil {
		_ = l.srv.Close()
	}
	// Shutdown closes only the listeners Serve has registered: one whose
	// Serve goroutine has not run yet would stay bound until it does (and
	// then returns ErrServerClosed). Close it here so the port or socket is
	// free when Close/CloseAt return.
	_ = l.ln.Close()
	if l.sock != nil {
		l.sock.removeFile()
	}
	m.log.Info("ingress listener stopped", "kind", l.kind)
}

// stop refuses every later Open (the shutdown began) and returns the open
// listeners, which the shutdown drains with the other servers (drain).
func (m *ingressManager) stop() []*ingressLn {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.closed = true
	out := make([]*ingressLn, 0, len(m.open))
	for _, l := range m.open {
		out = append(out, l)
	}
	clear(m.open)
	return out
}

// drain shuts the listeners stop returned down within ctx and waits for
// their Serve goroutines.
func (m *ingressManager) drain(ctx context.Context, ls []*ingressLn) {
	var wg sync.WaitGroup
	for _, l := range ls {
		wg.Go(func() { m.drainLn(ctx, l) })
	}
	wg.Wait()
	m.wg.Wait()
}

// kinds lists the open listeners (tests).
func (m *ingressManager) kinds() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []string
	for k := range m.open {
		if !slices.Contains(out, k.kind) {
			out = append(out, k.kind)
		}
	}
	slices.Sort(out)
	return out
}

// ---------- the listener: peer check at Accept ----------

// errPeerUnverifiable is returned by loopbackPeerUID where the peer of a
// loopback TCP connection cannot be looked up (not Linux).
var errPeerUnverifiable = errors.New("the peer of a loopback connection cannot be verified on this OS")

// ingressListener accepts only connections whose peer uid is allowed.
type ingressListener struct {
	net.Listener
	kind    string
	allowed []int
	uidOf   func(net.Conn) (int, error)
	log     *slog.Logger
	refused *logEvery
	warned  sync.Once
}

// Accept returns the next connection from an allowed peer; others are
// closed at once (rate-limited warning).
func (l *ingressListener) Accept() (net.Conn, error) {
	for {
		c, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		uid, err := l.uidOf(c)
		switch {
		case errors.Is(err, errPeerUnverifiable):
			l.warned.Do(func() {
				l.log.Warn("ingress: the peer of the TCP ingress listener is not verifiable on this OS; any local program can connect",
					"kind", l.kind)
			})
			return c, nil
		case err == nil && slices.Contains(l.allowed, uid):
			return c, nil
		}
		if tc, ok := c.(*net.TCPConn); ok {
			_ = tc.SetLinger(0)
		}
		_ = c.Close()
		if n, ok := l.refused.allow(); ok {
			if err != nil {
				l.log.Warn("ingress: connection refused: its peer could not be identified", "kind", l.kind, "err", err,
					"suppressed", n)
			} else {
				l.log.Warn("ingress: connection from uid "+strconv.Itoa(uid)+" refused", "kind", l.kind, "suppressed", n)
			}
		}
	}
}

// unixPeerUID is the peer uid of a Unix-socket connection (SO_PEERCRED /
// LOCAL_PEERCRED).
func unixPeerUID(c net.Conn) (int, error) {
	uc, ok := c.(*net.UnixConn)
	if !ok {
		return -1, fmt.Errorf("not a Unix-socket connection: %T", c)
	}
	return peerUID(uc)
}

// logEvery lets one log line through per interval and counts the rest.
type logEvery struct {
	every      time.Duration
	mu         sync.Mutex
	last       time.Time
	suppressed int
}

// allow reports whether a line may be logged now, with the number of lines
// suppressed since the last one.
func (l *logEvery) allow() (suppressed int, ok bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	if !l.last.IsZero() && now.Sub(l.last) < l.every {
		l.suppressed++
		return 0, false
	}
	n := l.suppressed
	l.last, l.suppressed = now, 0
	return n, true
}

// ---------- the handler: header trust ----------

// maxTSUser bounds the Tailscale-User-Login value kept for the log.
const maxTSUser = 256

// ingressHandler validates what tailscaled forwards on kind's listener and
// hands the request to h (the router, where mw.IngressGate applies the
// policy):
//
//  1. X-Forwarded-For (tailscaled sets exactly one address, the client's)
//     must be one header line holding one IP address — no port, no zone;
//     loopback, unspecified and multicast addresses are refused → 400.
//  2. The Funnel/Serve policy of kind must be on (fail closed) → 404.
//  3. X-Forwarded-Host is the Host the client sent (tailscaled routes by
//     TLS SNI and never compares it): lowercased and without a trailing
//     dot it must be the MagicDNS name, and a port, if any, the kind's
//     port → 421. The request's Host becomes name or name:port.
//  4. Tailscale-Funnel-Request on the serve listener means Funnel was
//     turned on for the tailnet-only port: 403 (the next reconcile removes
//     that flag; the status shows it). On the funnel listener it only marks
//     the request as public (for "last public request").
//  5. GET of the self-probe path with the nonce of a running probe → 204.
//  6. RemoteAddr becomes the client's address (every later consumer sees
//     the real client, never tailscaled), the context gets
//     core.IngressInfo, and the proxy headers are removed (X-Forwarded-*,
//     Forwarded, X-Real-Ip, Via, every Tailscale-* header, X-FP-As).
func ingressHandler(d *app.Deps, h http.Handler, kind string, log *slog.Logger) http.Handler {
	funnelOnServe := &logEvery{every: refusedLogEvery}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if d == nil || d.Ingress == nil {
			plainStatus(w, http.StatusNotFound, "404 not found\n")
			return
		}
		ip, ok := forwardedClient(r.Header.Values("X-Forwarded-For"))
		if !ok {
			log.Debug("ingress: invalid X-Forwarded-For", "kind", kind, "value", sanitizeHeader(r.Header.Values("X-Forwarded-For")))
			w.Header().Set("Connection", "close")
			plainStatus(w, http.StatusBadRequest, "400 bad request\n")
			return
		}
		pol := d.Ingress.Policy(kind)
		if pol.Mode == "" || pol.Mode == core.FunnelOff || pol.DNSName == "" {
			plainStatus(w, http.StatusNotFound, "404 not found\n")
			return
		}
		host, ok := ingressHost(r.Header.Values("X-Forwarded-Host"), pol)
		if !ok {
			log.Debug("ingress: unexpected X-Forwarded-Host", "kind", kind,
				"value", sanitizeHeader(r.Header.Values("X-Forwarded-Host")))
			plainStatus(w, http.StatusMisdirectedRequest, "421 misdirected request: this address does not serve that host name\n")
			return
		}
		public := false
		if r.Header.Get("Tailscale-Funnel-Request") != "" {
			if kind == core.IngressServe {
				d.Ingress.Note(core.IngressServe, false, true)
				if n, ok := funnelOnServe.allow(); ok {
					log.Warn("ingress: a Tailscale Funnel request reached the tailnet-only Serve address; "+
						"Funnel was turned on for its port outside FileParcel", "suppressed", n)
				}
				plainStatus(w, http.StatusForbidden, "403 forbidden: this address is not published on the internet\n")
				return
			}
			public = true
		}
		if nonce, ok := strings.CutPrefix(r.URL.Path, tsingress.ProbePath); ok && r.Method == http.MethodGet &&
			nonce != "" && !strings.Contains(nonce, "/") && d.Ingress.CheckProbe(kind, nonce) {
			w.Header().Set("Cache-Control", "no-store")
			w.WriteHeader(http.StatusNoContent)
			return
		}
		tsUser := ""
		if kind == core.IngressServe {
			tsUser = clipString(r.Header.Get("Tailscale-User-Login"), maxTSUser)
		}
		r2 := r.WithContext(core.WithIngress(r.Context(), &core.IngressInfo{Kind: kind, ClientIP: ip, Public: public,
			Host: host, TSUser: tsUser}))
		r2.RemoteAddr = netip.AddrPortFrom(ip, 0).String()
		r2.Host = host
		r2.URL.Host = ""
		r2.Header = r.Header.Clone()
		stripProxyHeaders(r2.Header)
		d.Ingress.Note(kind, public, false)
		h.ServeHTTP(w, r2)
	})
}

// forwardedClient validates X-Forwarded-For as tailscaled sets it: one
// header line with one IP address (no port, no zone), not loopback,
// unspecified or multicast. IPv4-mapped addresses are unmapped.
func forwardedClient(values []string) (netip.Addr, bool) {
	if len(values) != 1 {
		return netip.Addr{}, false
	}
	ip, err := netip.ParseAddr(values[0])
	if err != nil || ip.Zone() != "" {
		return netip.Addr{}, false
	}
	ip = ip.Unmap()
	if ip.IsLoopback() || ip.IsUnspecified() || ip.IsMulticast() {
		return netip.Addr{}, false
	}
	return ip, true
}

// ingressHost checks X-Forwarded-Host against the policy's MagicDNS name
// and port and returns the canonical Host: name for port 443, name:port
// otherwise.
func ingressHost(values []string, pol core.IngressPolicy) (string, bool) {
	if len(values) != 1 {
		return "", false
	}
	v := strings.ToLower(strings.TrimSpace(values[0]))
	host, port := v, ""
	if i := strings.LastIndexByte(v, ':'); i >= 0 && !strings.Contains(v, "]") {
		host, port = v[:i], v[i+1:]
		if port == "" {
			return "", false
		}
	}
	host = strings.TrimSuffix(host, ".")
	want := strings.TrimSuffix(strings.ToLower(pol.DNSName), ".")
	if want == "" || host != want || pol.Port <= 0 {
		return "", false
	}
	if port != "" && port != strconv.Itoa(pol.Port) {
		return "", false
	}
	if pol.Port == 443 {
		return want, true
	}
	return want + ":" + strconv.Itoa(pol.Port), true
}

// stripProxyHeaders removes the proxy and identity headers of tailscaled
// (and any a client smuggled past it) once they have been used.
func stripProxyHeaders(h http.Header) {
	for name := range h {
		if strings.HasPrefix(name, "X-Forwarded-") || strings.HasPrefix(name, "Tailscale-") {
			delete(h, name)
		}
	}
	for _, name := range []string{"Forwarded", "X-Real-Ip", "Via", mw.HeaderActAs} {
		h.Del(name)
	}
}

// plainStatus writes a short text answer outside the router (which would
// otherwise add the security headers).
func plainStatus(w http.ResponseWriter, status int, msg string) {
	h := w.Header()
	h.Set("Content-Type", "text/plain; charset=utf-8")
	h.Set("Cache-Control", "no-store")
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Referrer-Policy", "no-referrer")
	w.WriteHeader(status)
	_, _ = w.Write([]byte(msg))
}

// sanitizeHeader bounds and cleans header values for the log.
func sanitizeHeader(values []string) string {
	return strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return '?'
		}
		return r
	}, clipString(strings.Join(values, ", "), 200))
}

// clipString truncates s to at most n bytes (at a rune boundary).
func clipString(s string, n int) string {
	if len(s) <= n {
		return s
	}
	for n > 0 && s[n]&0xC0 == 0x80 {
		n--
	}
	return s[:n]
}
