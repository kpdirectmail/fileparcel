package cli

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/term"

	"fileparcel/internal/app"
	"fileparcel/internal/config"
	"fileparcel/internal/core"
	"fileparcel/internal/home"
	"fileparcel/internal/server"
	"fileparcel/internal/web"
	"fileparcel/internal/web/httpx"
	"fileparcel/internal/web/mw"
	"fileparcel/internal/wire"
)

// Transport modes of a Client.
const (
	ModeSocket  = "socket"  // admin Unix socket of a running server
	ModeOffline = "offline" // in-process router over the home (server not running)
	ModeRemote  = "remote"  // --server URL --token PAT over HTTPS
)

// Options selects and configures the transport (see Connect).
type Options struct {
	Home        string // --home
	Offline     bool   // force in-process
	Server      string // remote base URL
	Token       string // remote API token
	CAFile      string // remote: extra trusted CA (PEM)
	Fingerprint string // remote: SHA-256 pin of the server certificate or of its issuer
	As          string // socket/offline: act as this username (X-FP-As)
	// Passphrase is called when offline mode finds the master key sealed.
	// nil = prompt on the terminal when stdin is a TTY, else stay locked.
	Passphrase func() ([]byte, error)
	// Context (the command's) interrupts the offline start: schema
	// migrations and the passphrase prompt. It does not bound the client's
	// lifetime, which ends with Close. nil = not interruptible.
	Context context.Context
}

// Client talks to the FileParcel REST API over one of the three transports.
// All commands use the same /api/v1 endpoints as the web UI.
type Client struct {
	mode  string
	hc    *http.Client
	base  *url.URL
	token string
	as    string
	home  *home.Home
	deps  *app.Deps

	closeOnce sync.Once
	closeFn   func()
}

// Connect chooses the transport (DESIGN §12):
//
//  1. --server URL → remote (requires a token; custom CA or fingerprint pinning).
//  2. otherwise resolve the home; unless Offline is set, use the admin socket
//     run/admin.sock if a server answers on it;
//  3. if nothing listens and the home lock is free → take the lock, build the
//     services in-process (wire.Build(ModeOffline)) and serve requests through
//     the same router via an in-memory RoundTripper, authenticated as
//     core.SystemPrincipal(core.ViaOffline) (a context value, never a header);
//  4. if the lock is held but the socket is dead → error with a doctor hint.
//
// Close the client when done (releases the lock and services in offline mode).
func Connect(opts Options) (*Client, error) {
	if opts.Server != "" {
		return connectRemote(opts)
	}
	h, err := home.Resolve(opts.Home)
	if err != nil {
		if errors.Is(err, home.ErrNoHome) {
			return nil, &hintError{err, homeHint}
		}
		return nil, err
	}
	if !h.Exists() {
		return nil, notAHomeError(h.Dir())
	}
	if !opts.Offline {
		c, err := connectSocket(h, opts)
		if err == nil {
			return c, nil
		}
		if !errors.Is(err, errNoServer) {
			return nil, err
		}
	}
	return connectOffline(h, opts)
}

var errNoServer = errors.New("no server on the admin socket")

// homeHint says where FileParcel homes usually are and how to make one.
const homeHint = `pass --home DIR or set FILEPARCEL_HOME (usual places: ~/.local/share/fileparcel, /opt/fileparcel, ` +
	`~/Library/Application Support/FileParcel, /usr/local/fileparcel); to install run ./install.sh or "fileparcel install" ` +
	`(a data directory without a service: "fileparcel init --home DIR")`

// notAHomeError is the error for a directory without fileparcel.toml.
func notAHomeError(dir string) error {
	return &hintError{fmt.Errorf("%s is not a FileParcel home (no %s)", dir, home.ConfigName), homeHint}
}

// socketAccessError explains an admin socket this user may not connect to:
// the server runs as another account (a system service).
func socketAccessError(sock string, err error) error {
	owner := ""
	if fi, serr := os.Stat(sock); serr == nil {
		if uid, _, _, ok := fileOwner(fi); ok {
			owner = lcAccountName(uid)
		}
	}
	if owner == "" || strings.HasPrefix(owner, "uid ") {
		return &hintError{err, "the server runs as another system user; run the command as that user or as root (sudo fileparcel …)"}
	}
	return &hintError{err, fmt.Sprintf("the server runs as another system user (%s); run the command as that user or root: sudo -u %s fileparcel …", owner, owner)}
}

func connectSocket(h *home.Home, opts Options) (*Client, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	return connectSocketContext(ctx, h, opts)
}

// connectSocketContext is connectSocket with the first dial bounded by ctx
// (shell completion gives up sooner than a command).
func connectSocketContext(ctx context.Context, h *home.Home, opts Options) (*Client, error) {
	sock := h.Socket()
	conn, err := server.DialSocket(ctx, sock) // handles paths beyond the sun_path limit (DESIGN §18.17)
	if err != nil {
		if errors.Is(err, syscall.ENOENT) || errors.Is(err, syscall.ECONNREFUSED) || errors.Is(err, os.ErrNotExist) {
			return nil, errNoServer
		}
		err = fmt.Errorf("admin socket %s: %w", sock, err)
		if errors.Is(err, syscall.EACCES) || errors.Is(err, syscall.EPERM) {
			return nil, socketAccessError(sock, err)
		}
		return nil, err
	}
	conn.Close()
	tr := &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return server.DialSocket(ctx, sock)
		},
		MaxIdleConns:        4,
		IdleConnTimeout:     30 * time.Second,
		DisableCompression:  true,
		TLSHandshakeTimeout: 0,
	}
	base, _ := url.Parse("http://localhost")
	return &Client{mode: ModeSocket, hc: &http.Client{Transport: tr}, base: base, as: opts.As, home: h,
		closeFn: tr.CloseIdleConnections}, nil
}

func connectOffline(h *home.Home, opts Options) (*Client, error) {
	// Run as root on a home that belongs to another account (sudo on a
	// system install), unlock also gives what was written back to it.
	unlock, err := lockHome(h)
	if err != nil {
		if errors.Is(err, home.ErrLocked) {
			if cfg, cerr := config.Load(h); cerr == nil && !cfg.AdminSocket.Enabled {
				// Nothing can answer on the socket: not a hang, a setting.
				return nil, fmt.Errorf("the home %s is locked (the server is running?) and the admin socket is disabled "+
					"(admin_socket.enabled = false in fileparcel.toml): enable it and restart the server to use admin "+
					"commands while it runs, or stop it", h.Dir())
			}
			if opts.Offline {
				return nil, errors.New("the FileParcel server is running (home locked); omit --offline to use it")
			}
			return nil, fmt.Errorf("the home %s is locked by another process but its admin socket is not answering; run \"fileparcel doctor\"", h.Dir())
		}
		return nil, err
	}
	// ctx bounds the in-process services (until Close); startCtx also ends
	// on Ctrl-C, so migrations and the unlock prompt can be interrupted.
	ctx, cancel := context.WithCancel(context.Background())
	startCtx := opts.Context
	if startCtx == nil {
		startCtx = context.Background()
	}
	d, cleanup, err := wire.Build(startCtx, h, app.ModeOffline)
	if err != nil {
		cancel()
		unlock()
		return nil, err
	}
	closeAll := func() {
		cancel()
		cleanup()
		unlock()
	}
	if err := wire.Start(ctx, d); err != nil {
		closeAll()
		return nil, err
	}
	if d.Keys.State() == core.KeyStateLocked {
		ask := opts.Passphrase
		if ask == nil && term.IsTerminal(int(os.Stdin.Fd())) {
			ask = func() ([]byte, error) {
				return promptPassphrase(startCtx, "Master key passphrase (or recovery key): ")
			}
		}
		if ask != nil {
			pass, err := ask()
			if err == nil {
				err = d.Keys.Unlock(startCtx, pass)
			}
			if err != nil {
				closeAll()
				return nil, fmt.Errorf("unlock: %w", err)
			}
		}
	}
	rt := &inProcessTransport{h: web.NewRouter(d), p: core.SystemPrincipal(core.ViaOffline)}
	base, _ := url.Parse("http://localhost")
	return &Client{mode: ModeOffline, hc: &http.Client{Transport: rt}, base: base, as: opts.As, home: h, deps: d,
		closeFn: closeAll}, nil
}

func connectRemote(opts Options) (*Client, error) {
	if opts.As != "" {
		return nil, UsageError("--as only works over the admin socket or offline")
	}
	if opts.Token == "" {
		return nil, UsageError("--server needs an API token: $" + TokenEnv + ", --token-file FILE or --token")
	}
	base, err := url.Parse(strings.TrimRight(opts.Server, "/"))
	if err != nil || (base.Scheme != "https" && base.Scheme != "http") || base.Host == "" {
		return nil, UsageError("invalid --server URL %q", opts.Server)
	}
	if base.Scheme == "http" {
		// The server never serves the API over plain HTTP (DESIGN §9.1: it
		// answers with a 308 to https), so an http:// URL would only put the
		// token and request bodies on the wire in cleartext before Go
		// silently follows the redirect. Plain http is left for loopback
		// (an SSH tunnel's local end, tests), where nothing crosses a network.
		if !isLoopbackHost(base.Hostname()) {
			return nil, UsageError("--server must be an https:// URL (FileParcel does not serve its API over plain HTTP, and the token would be sent in cleartext): %q", opts.Server)
		}
		if opts.CAFile != "" || opts.Fingerprint != "" {
			return nil, UsageError("--ca-file and --fingerprint need an https:// --server URL")
		}
	}
	tlsCfg := &tls.Config{MinVersion: tls.VersionTLS12}
	if opts.CAFile != "" {
		pem, err := os.ReadFile(opts.CAFile)
		if err != nil {
			return nil, err
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("%s: no PEM certificates found", opts.CAFile)
		}
		tlsCfg.RootCAs = pool
	}
	if opts.Fingerprint != "" {
		pin, err := normalizeFingerprint(opts.Fingerprint)
		if err != nil {
			return nil, err
		}
		host := base.Hostname()
		if opts.CAFile == "" {
			// Pinning replaces chain verification (self-signed local CA):
			// Go's own verification is switched off and redone in
			// verifyPinned, with the pinned certificate as trust anchor.
			tlsCfg.InsecureSkipVerify = true
			tlsCfg.VerifyConnection = func(cs tls.ConnectionState) error {
				return verifyPinned(cs, pin, host)
			}
		} else {
			// The chain is already verified against --ca-file; the pin is an
			// additional constraint on it: the pinned certificate must be
			// on a verified chain (the leaf, an intermediate or a --ca-file
			// root the server need not send). Merely being presented proves
			// nothing: extra certificates the peer appends are ignored by
			// chain building, and the pinned one is usually public.
			tlsCfg.VerifyConnection = func(cs tls.ConnectionState) error {
				for _, chain := range cs.VerifiedChains {
					for _, c := range chain {
						sum := sha256.Sum256(c.Raw)
						if hex.EncodeToString(sum[:]) == pin {
							return nil
						}
					}
				}
				return errPinMismatch
			}
		}
	}
	tr := &http.Transport{
		Proxy:               http.ProxyFromEnvironment,
		TLSClientConfig:     tlsCfg,
		ForceAttemptHTTP2:   true,
		MaxIdleConns:        8,
		IdleConnTimeout:     60 * time.Second,
		TLSHandshakeTimeout: 15 * time.Second,
	}
	// The REST API never redirects. Refuse redirects that leave the server
	// or downgrade the scheme, so a misconfigured proxy cannot bounce the
	// token (or a replayed 307/308 body such as a passphrase) elsewhere.
	checkRedirect := func(r *http.Request, via []*http.Request) error {
		if len(via) >= 10 {
			return errors.New("stopped after 10 redirects")
		}
		if !strings.EqualFold(r.URL.Host, base.Host) || (r.URL.Scheme != "https" && r.URL.Scheme != base.Scheme) {
			return fmt.Errorf("refusing to follow a redirect to %s", r.URL.Redacted())
		}
		return nil
	}
	return &Client{mode: ModeRemote, hc: &http.Client{Transport: tr, CheckRedirect: checkRedirect}, base: base,
		token: opts.Token, closeFn: tr.CloseIdleConnections}, nil
}

// isLoopbackHost reports whether a URL host name (without port) is
// "localhost" or a loopback IP (127.0.0.0/8, ::1).
func isLoopbackHost(h string) bool {
	if strings.EqualFold(h, "localhost") {
		return true
	}
	a, err := netip.ParseAddr(h)
	return err == nil && a.Unmap().IsLoopback()
}

var errPinMismatch = errors.New("server certificate does not match the pinned fingerprint")

// verifyPinned verifies the server chain with the pinned certificate as the
// only trust anchor. Either the leaf itself is the pinned certificate (the
// handshake then proves possession of its private key), or a certificate in
// the chain matches the pin and actually issued the leaf. Chain membership
// alone proves nothing: the pinned certificate is usually the local CA, which
// is public (/trust/ca.crt), so anyone could append it to a chain headed by
// their own self-signed leaf. When the pin names an issuer, the leaf must also
// be valid for the host the CLI dialed (a CA can sign for any name), be
// in-date and carry the serverAuth usage.
func verifyPinned(cs tls.ConnectionState, pin, host string) error {
	if len(cs.PeerCertificates) == 0 {
		return errors.New("the server presented no certificate")
	}
	leaf := cs.PeerCertificates[0]
	sum := sha256.Sum256(leaf.Raw)
	if hex.EncodeToString(sum[:]) == pin {
		return nil
	}
	roots, inter := x509.NewCertPool(), x509.NewCertPool()
	pinned := false
	for _, c := range cs.PeerCertificates[1:] {
		s := sha256.Sum256(c.Raw)
		if hex.EncodeToString(s[:]) == pin {
			roots.AddCert(c)
			pinned = true
			continue
		}
		inter.AddCert(c)
	}
	if !pinned {
		return errPinMismatch
	}
	if _, err := leaf.Verify(x509.VerifyOptions{
		Roots:         roots,
		Intermediates: inter,
		DNSName:       host,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}); err != nil {
		return fmt.Errorf("the server certificate is not issued by the pinned certificate: %w", err)
	}
	return nil
}

// normalizeFingerprint accepts "AB:CD:…", "abcd…" or "sha256:…" and returns 64 lowercase hex chars.
func normalizeFingerprint(s string) (string, error) {
	s = strings.ToLower(strings.TrimSpace(s))
	s = strings.TrimPrefix(s, "sha256:")
	s = strings.NewReplacer(":", "", " ", "", "-", "").Replace(s)
	if b, err := hex.DecodeString(s); err != nil || len(b) != sha256.Size {
		return "", UsageError("--fingerprint must be a SHA-256 fingerprint (64 hex digits, colons optional)")
	}
	return s, nil
}

// Mode returns ModeSocket, ModeOffline or ModeRemote.
func (c *Client) Mode() string { return c.mode }

// Home returns the resolved home (nil in remote mode).
func (c *Client) Home() *home.Home { return c.home }

// Deps returns the in-process services in offline mode (nil otherwise). Use
// it only for operations that have no API (e.g. init, restore).
func (c *Client) Deps() *app.Deps { return c.deps }

// Close releases the transport (offline: stops services, closes the DB,
// gives what a root command wrote back to the home's account — see lockHome
// — and releases the home lock). Safe to call more than once.
func (c *Client) Close() error {
	c.closeOnce.Do(func() {
		if c.closeFn != nil {
			c.closeFn()
		}
	})
	return nil
}

func (c *Client) newRequest(ctx context.Context, method, path string, body io.Reader) (*http.Request, error) {
	if !strings.HasPrefix(path, "/") {
		return nil, fmt.Errorf("cli: request path must start with '/': %q", path)
	}
	u := *c.base
	rel, err := url.Parse(path)
	if err != nil {
		return nil, err
	}
	u.Path = strings.TrimRight(c.base.Path, "/") + rel.Path
	u.RawPath = ""
	u.RawQuery = rel.RawQuery
	req, err := http.NewRequestWithContext(ctx, method, u.String(), body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "fileparcel-cli")
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}
	if c.as != "" {
		req.Header.Set(mw.HeaderActAs, c.as)
	}
	return req, nil
}

// Do sends a JSON request and decodes a JSON response. path is the full path
// including query ("/api/v1/admin/users?limit=10"). body may be nil, a
// json.RawMessage / []byte (sent as-is) or any value (JSON-encoded). out may
// be nil (response discarded). API errors (§9.5) are returned as *core.Error
// with Status set to the HTTP status.
func (c *Client) Do(ctx context.Context, method, path string, body any, out any) error {
	var rd io.Reader
	switch b := body.(type) {
	case nil:
	case json.RawMessage:
		rd = bytes.NewReader(b)
	case []byte:
		rd = bytes.NewReader(b)
	default:
		data, err := json.Marshal(body)
		if err != nil {
			return err
		}
		rd = bytes.NewReader(data)
	}
	req, err := c.newRequest(ctx, method, path, rd)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	if rd != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.hc.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return httpx.DecodeError(resp)
	}
	if out == nil || resp.StatusCode == http.StatusNoContent {
		_, _ = io.Copy(io.Discard, resp.Body)
		return nil
	}
	if err := json.NewDecoder(resp.Body).Decode(out); err != nil && !errors.Is(err, io.EOF) {
		return fmt.Errorf("decode response: %w", err)
	}
	return nil
}

// Stream sends a raw request body (e.g. an upload part or a backup import)
// and returns the raw response for 2xx statuses; the caller must close
// resp.Body. hdr adds request headers (Content-Type, X-FP-SHA256, …). Error
// statuses are decoded into *core.Error (and the body closed).
func (c *Client) Stream(ctx context.Context, method, path string, body io.Reader, hdr http.Header) (*http.Response, error) {
	req, err := c.newRequest(ctx, method, path, body)
	if err != nil {
		return nil, err
	}
	for k, vs := range hdr {
		for _, v := range vs {
			req.Header.Add(k, v)
		}
	}
	if sz, ok := body.(interface{ Size() int64 }); ok && req.ContentLength == 0 {
		req.ContentLength = sz.Size()
	}
	resp, err := c.hc.Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode >= 400 {
		defer resp.Body.Close()
		return nil, httpx.DecodeError(resp)
	}
	return resp, nil
}

// PromptPassphrase reads a secret from the terminal without echo.
func PromptPassphrase(prompt string) ([]byte, error) {
	return promptPassphrase(context.Background(), prompt)
}

// promptPassphrase is PromptPassphrase that returns (restoring the
// terminal) when ctx is cancelled (ttyRead).
func promptPassphrase(ctx context.Context, prompt string) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	fd := int(os.Stdin.Fd())
	fmt.Fprint(os.Stderr, prompt)
	b, err := ttyRead(ctx, fd, func() ([]byte, error) { return term.ReadPassword(fd) })
	fmt.Fprintln(os.Stderr)
	return b, err
}

// ---------- in-process transport ----------

// inProcessTransport serves requests with the router in this process. The
// system principal is attached as a context value (which mw.Authenticate
// trusts); nothing in the request itself can grant it.
type inProcessTransport struct {
	h http.Handler
	p *core.Principal
}

func (t *inProcessTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	ctx := core.WithPrincipal(req.Context(), t.p.Clone())
	r := req.Clone(ctx)
	r.RequestURI = req.URL.RequestURI()
	r.RemoteAddr = "[::1]:0"
	if r.Host == "" {
		r.Host = req.URL.Host
	}
	if r.Body == nil {
		r.Body = http.NoBody
	}
	pr, pw := io.Pipe()
	w := &pipeResponseWriter{header: http.Header{}, pw: pw, ready: make(chan struct{})}
	go func() {
		defer func() {
			if v := recover(); v != nil {
				w.fail(fmt.Errorf("handler panic: %v", v))
				return
			}
			w.WriteHeader(http.StatusOK) // no-op if already written
			pw.Close()
		}()
		t.h.ServeHTTP(w, r)
	}()
	select {
	case <-w.ready:
	case <-req.Context().Done():
		pw.CloseWithError(req.Context().Err())
		return nil, req.Context().Err()
	}
	if w.err != nil {
		return nil, w.err
	}
	return &http.Response{
		Status:        fmt.Sprintf("%d %s", w.status, http.StatusText(w.status)),
		StatusCode:    w.status,
		Proto:         "HTTP/1.1",
		ProtoMajor:    1,
		ProtoMinor:    1,
		Header:        w.sent,
		Body:          pr,
		ContentLength: -1,
		Request:       req,
	}, nil
}

// pipeResponseWriter streams a handler's response through an io.Pipe.
type pipeResponseWriter struct {
	header http.Header
	sent   http.Header
	pw     *io.PipeWriter
	status int
	once   sync.Once
	ready  chan struct{}
	err    error
}

func (w *pipeResponseWriter) Header() http.Header { return w.header }

func (w *pipeResponseWriter) WriteHeader(code int) {
	if code >= 100 && code < 200 && code != http.StatusSwitchingProtocols {
		return // informational responses are not forwarded
	}
	w.once.Do(func() {
		w.status = code
		w.sent = w.header.Clone()
		close(w.ready)
	})
}

func (w *pipeResponseWriter) Write(b []byte) (int, error) {
	w.WriteHeader(http.StatusOK)
	return w.pw.Write(b)
}

// Flush is a no-op: the pipe is unbuffered, so data is already delivered.
func (w *pipeResponseWriter) Flush() {}

func (w *pipeResponseWriter) fail(err error) {
	w.once.Do(func() {
		w.err = err
		close(w.ready)
	})
	w.pw.CloseWithError(err)
}
