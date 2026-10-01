package server

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"fileparcel/internal/app"
	"fileparcel/internal/certs"
	"fileparcel/internal/config"
	"fileparcel/internal/core"
	"fileparcel/internal/events"
)

var discard = slog.New(slog.DiscardHandler)

func TestSocketPeerCredentials(t *testing.T) {
	dir, err := shortTempDir(t)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "admin.sock")
	sl, err := listenSocket(path, discard)
	if err != nil {
		t.Fatal(err)
	}
	defer sl.Close()
	// Our own uid is accepted.
	go func() {
		c, err := DialSocket(context.Background(), path)
		if err == nil {
			_, _ = c.Write([]byte("x"))
			time.Sleep(50 * time.Millisecond)
			c.Close()
		}
	}()
	c, err := sl.Accept()
	if err != nil {
		t.Fatal(err)
	}
	c.Close()

	// A listener expecting another uid refuses us (unless we are root, who
	// is always allowed).
	if os.Getuid() == 0 {
		t.Skip("running as root")
	}
	sl.uid = os.Getuid() + 1
	accepted := make(chan net.Conn, 1)
	go func() {
		c, err := sl.Accept()
		if err == nil {
			accepted <- c
		}
	}()
	cc, err := DialSocket(context.Background(), path)
	if err != nil {
		t.Fatal(err)
	}
	defer cc.Close()
	_ = cc.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, err := cc.Read(make([]byte, 1)); err == nil || errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("foreign peer not disconnected: %v", err)
	}
	select {
	case <-accepted:
		t.Fatal("foreign peer accepted")
	case <-time.After(100 * time.Millisecond):
	}
}

func TestPeerUIDMatchesProcess(t *testing.T) {
	dir, err := shortTempDir(t)
	if err != nil {
		t.Fatal(err)
	}
	ln, err := bindUnix(filepath.Join(dir, "s"))
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		if c, err := DialSocket(context.Background(), filepath.Join(dir, "s")); err == nil {
			time.Sleep(100 * time.Millisecond)
			c.Close()
		}
	}()
	c, err := ln.AcceptUnix()
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	uid, err := peerUID(c)
	if err != nil || uid != os.Getuid() {
		t.Fatalf("peerUID = %d, %v", uid, err)
	}
}

func TestLongSocketPath(t *testing.T) {
	dir, err := shortTempDir(t)
	if err != nil {
		t.Fatal(err)
	}
	long := filepath.Join(dir, strings.Repeat("d", 60), strings.Repeat("e", 60), "run")
	if err := os.MkdirAll(long, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(long, "admin.sock")
	if len(path) <= maxSocketPath {
		t.Fatalf("path not long enough: %d", len(path))
	}
	sl, err := listenSocket(path, discard)
	if err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(path)
	if err != nil || fi.Mode()&os.ModeSocket == 0 || fi.Mode().Perm() != 0o600 {
		t.Fatalf("socket at the long path: %v %v", fi, err)
	}
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, "ok") })}
	go func() { _ = srv.Serve(sl) }()
	defer srv.Close()
	client := &http.Client{Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return DialSocket(ctx, path)
	}}}
	resp, err := client.Get("http://localhost/")
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if string(b) != "ok" {
		t.Fatalf("%q", b)
	}
	wd, _ := os.Getwd()
	if strings.HasPrefix(wd, dir) {
		t.Fatal("working directory not restored")
	}
	sl.removeFile()
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("socket not removed")
	}
}

func TestListenSocketStaleAndBusy(t *testing.T) {
	dir, err := shortTempDir(t)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "admin.sock")
	// A stale socket file (nobody listening) is replaced.
	stale, err := bindUnix(path)
	if err != nil {
		t.Fatal(err)
	}
	stale.SetUnlinkOnClose(false)
	stale.Close()
	sl, err := listenSocket(path, discard)
	if err != nil {
		t.Fatalf("stale socket: %v", err)
	}
	// A live socket is not stolen.
	if _, err := listenSocket(path, discard); err == nil || !strings.Contains(err.Error(), "another server") {
		t.Fatalf("second listener: %v", err)
	}
	sl.Close()
	sl.removeFile()
	// A regular file is never removed.
	if err := os.WriteFile(path, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := listenSocket(path, discard); err == nil {
		t.Fatal("regular file replaced by the socket")
	}
}

// fakeCerts implements CheckClient for the mTLS gate.
type fakeCerts struct {
	core.Certs
	ok bool
}

func (f *fakeCerts) CheckClient(context.Context, *tls.ConnectionState) (*core.ClientCert, error) {
	if f.ok {
		return &core.ClientCert{ID: "ccr_1"}, nil
	}
	return nil, core.ErrUnauthorized
}

func TestMTLSGate(t *testing.T) {
	st := &fakeSettings{m: map[string]any{}}
	fc := &fakeCerts{}
	d := &app.Deps{Env: &core.Env{Settings: st}, Certs: fc}
	gate := mtlsGate(d, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(299) }))
	code := func(path string) int {
		r := httptest.NewRequest(http.MethodGet, "https://x"+path, nil)
		r.TLS = &tls.ConnectionState{}
		w := httptest.NewRecorder()
		gate.ServeHTTP(w, r)
		return w.Code
	}
	if code("/files") != 299 {
		t.Fatal("mtls off must pass")
	}
	st.set(certs.KeyMTLSMode, certs.MTLSOptional)
	if code("/files") != 299 {
		t.Fatal("mtls optional must pass")
	}
	st.set(certs.KeyMTLSMode, certs.MTLSRequired)
	for path, want := range map[string]int{
		"/files": 403, "/api/v1/me": 403, "/": 403, "/s/tok": 299, "/s/tok/dl/n": 299, "/trust": 299, "/trust/ca.crt": 299,
		"/healthz": 299, "/readyz": 299, "/static/abc/app.js": 299, "/theme.css": 299, "/sharing": 403, "/strust": 403,
	} {
		if got := code(path); got != want {
			t.Errorf("%s: %d, want %d", path, got, want)
		}
	}
	st.set(certs.KeyMTLSExempt, false)
	if code("/s/tok") != 403 {
		t.Fatal("share exemption applied although disabled")
	}
	fc.ok = true
	if code("/files") != 299 {
		t.Fatal("valid client certificate refused")
	}
}

// Overlapping server.bind entries would fail with EADDRINUSE: "::" and
// "0.0.0.0" listen dual-stack on every address, and a repeated address
// twice.
func TestMergeBinds(t *testing.T) {
	for _, tc := range []struct {
		in, keep, dropped []string
	}{
		{[]string{"::"}, []string{"::"}, nil},
		{[]string{"0.0.0.0"}, []string{"0.0.0.0"}, nil},
		{[]string{"::", "0.0.0.0"}, []string{"::"}, []string{"0.0.0.0"}},
		{[]string{"100.64.0.1", "::"}, []string{"::"}, []string{"100.64.0.1"}},
		{[]string{"0.0.0.0", "::1", "::"}, []string{"0.0.0.0"}, []string{"::1", "::"}},
		{[]string{"[::]", "::"}, []string{"[::]"}, []string{"::"}},
		{[]string{"127.0.0.1", "127.0.0.1"}, []string{"127.0.0.1"}, []string{"127.0.0.1"}},
		{[]string{"::ffff:127.0.0.1", "127.0.0.1"}, []string{"::ffff:127.0.0.1"}, []string{"127.0.0.1"}},
		{[]string{"127.0.0.1", "::1", "192.168.1.5"}, []string{"127.0.0.1", "::1", "192.168.1.5"}, nil},
		{[]string{"fe80::1%eth0", "fe80::1%eth1"}, []string{"fe80::1%eth0", "fe80::1%eth1"}, nil},
	} {
		keep, dropped := mergeBinds(tc.in)
		if !slices.Equal(keep, tc.keep) || !slices.Equal(dropped, tc.dropped) {
			t.Errorf("mergeBinds(%q) = %q, %q; want %q, %q", tc.in, keep, dropped, tc.keep, tc.dropped)
		}
	}
	d := &app.Deps{Env: &core.Env{Config: &config.Config{}}}
	d.Config.Server.Bind = []string{"::", "0.0.0.0"}
	if lc := resolveListenConfig(d, Options{}); !slices.Equal(lc.binds, []string{"::"}) || !slices.Equal(lc.bindsDropped, []string{"0.0.0.0"}) {
		t.Fatalf("resolveListenConfig: binds %q, dropped %q", lc.binds, lc.bindsDropped)
	}
}

// The /trust and /unlock links of the foreground banner are joined with
// exactly one slash to server.public_url, which is stored as typed.
func TestBannerLinks(t *testing.T) {
	for base, want := range map[string]string{
		"https://files.example.com":      "https://files.example.com/trust",
		"https://files.example.com/":     "https://files.example.com/trust",
		"https://files.example.org/base": "https://files.example.org/base/trust",
		"https://192.168.1.5:9443/":      "https://192.168.1.5:9443/trust",
	} {
		if got := pageURL(base, "trust"); got != want {
			t.Errorf("pageURL(%q) = %q, want %q", base, got, want)
		}
	}
	b := banner("1.2.3", 42, []string{"https://files.example.com", "https://192.168.1.5:8443/"}, "AB:CD", true)
	for _, want := range []string{
		"FileParcel 1.2.3 is running (pid 42). Open:\n  https://files.example.com\n  https://192.168.1.5:8443/\n",
		"CA fingerprint (SHA-256): AB:CD\nTrust instructions: https://files.example.com/trust\n",
		"unlock at https://files.example.com/unlock or with",
	} {
		if !strings.Contains(b, want) {
			t.Errorf("banner lacks %q:\n%s", want, b)
		}
	}
	if b := banner("1.2.3", 42, []string{"https://localhost:8443/"}, "", false); strings.Contains(b, "trust") || strings.Contains(b, "unlock") {
		t.Errorf("banner without CA or sealed key:\n%s", b)
	}
}

func TestStreamsCancelledOnShutdown(t *testing.T) {
	s := &streams{}
	started := make(chan struct{})
	ended := make(chan error, 1)
	h := s.wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream; charset=utf-8")
		w.(http.Flusher).Flush()
		close(started)
		<-r.Context().Done()
		ended <- r.Context().Err()
	}))
	go h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/events", nil))
	<-started
	s.closeAll()
	select {
	case err := <-ended:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("stream ended with %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("stream not cancelled")
	}
	// Ordinary requests are not tracked; streams started after closeAll end at once.
	plain := s.wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte("x")) }))
	plain.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/", nil))
	late := make(chan error, 1)
	s.wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(200)
		late <- r.Context().Err()
	})).ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/events", nil))
	if err := <-late; !errors.Is(err, context.Canceled) {
		t.Fatalf("late stream not cancelled: %v", err)
	}
	if len(s.active) != 0 {
		t.Fatal("streams leaked")
	}
}

func TestStreamWriterPassThrough(t *testing.T) {
	s := &streams{}
	rec := httptest.NewRecorder()
	s.wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, ok := w.(io.ReaderFrom); !ok {
			t.Error("io.ReaderFrom lost")
		}
		_, _ = io.Copy(w, strings.NewReader("payload"))
		if err := http.NewResponseController(w).Flush(); err != nil {
			t.Errorf("flush: %v", err)
		}
	})).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	if rec.Body.String() != "payload" || !rec.Flushed {
		t.Fatalf("body %q flushed %v", rec.Body.String(), rec.Flushed)
	}
}

func TestMuxListenerSniffTimeoutAndClose(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	m := newMuxListener(ln, func(netip.Addr) bool { return true }, nil, &tls.Config{}, true, newDenyLog(discard))
	// A silent client does not block other connections.
	silent, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer silent.Close()
	talker, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer talker.Close()
	_, _ = talker.Write([]byte("G"))
	got := make(chan net.Conn, 1)
	go func() {
		c, err := m.Accept()
		if err == nil {
			got <- c
		}
	}()
	select {
	case c := <-got:
		b := make([]byte, 1)
		if _, err := c.Read(b); err != nil || b[0] != 'G' {
			t.Fatalf("prefix not replayed: %q %v", b, err)
		}
		c.Close()
	case <-time.After(3 * time.Second):
		t.Fatal("plain connection not dispatched")
	}
	if err := m.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Accept(); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("Accept after Close: %v", err)
	}
	_ = m.Close()
}

// selfSigned returns a throw-away certificate for name.
func selfSigned(t *testing.T, name string) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: name}, DNSNames: []string{name},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// Addresses outside the access policy may only complete an ACME TLS-ALPN-01
// validation handshake while that challenge is configured; nothing of it
// reaches the HTTP server.
func TestMuxListenerACMETLSALPNChallengeOnly(t *testing.T) {
	cert := selfSigned(t, "files.example.com")
	var acmeHellos atomic.Int32
	serverConf := &tls.Config{GetConfigForClient: func(h *tls.ClientHelloInfo) (*tls.Config, error) {
		if len(h.SupportedProtos) == 1 && h.SupportedProtos[0] == "acme-tls/1" {
			acmeHellos.Add(1)
			return &tls.Config{Certificates: []tls.Certificate{cert}, NextProtos: []string{"acme-tls/1"}}, nil
		}
		return &tls.Config{Certificates: []tls.Certificate{cert}, NextProtos: []string{"h2", "http/1.1"}}, nil
	}}
	var open atomic.Bool
	open.Store(true)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	m := newMuxListener(ln, func(netip.Addr) bool { return false }, open.Load, serverConf, true, newDenyLog(discard))
	defer m.Close()
	accepted := make(chan net.Conn, 4)
	go func() {
		for {
			c, err := m.Accept()
			if err != nil {
				return
			}
			accepted <- c
		}
	}()
	dial := func(conf *tls.Config) (*tls.Conn, error) {
		c, err := net.DialTimeout("tcp", ln.Addr().String(), 2*time.Second)
		if err != nil {
			return nil, err
		}
		_ = c.SetDeadline(time.Now().Add(5 * time.Second))
		tc := tls.Client(c, conf)
		if err := tc.Handshake(); err != nil {
			c.Close()
			return nil, err
		}
		return tc, nil
	}
	//nolint:gosec // test peers do not verify the throw-away certificate
	acme := &tls.Config{ServerName: "files.example.com", NextProtos: []string{"acme-tls/1"}, InsecureSkipVerify: true}
	//nolint:gosec // see above
	normal := &tls.Config{ServerName: "files.example.com", NextProtos: []string{"h2", "http/1.1"}, InsecureSkipVerify: true}

	// The validation handshake works, then the server closes the connection.
	tc, err := dial(acme)
	if err != nil {
		t.Fatalf("ACME validation handshake: %v", err)
	}
	if tc.ConnectionState().NegotiatedProtocol != "acme-tls/1" {
		t.Fatalf("ALPN %q", tc.ConnectionState().NegotiatedProtocol)
	}
	if _, err := tc.Read(make([]byte, 1)); err == nil {
		t.Fatal("connection kept open after the validation handshake")
	}
	tc.Close()
	if acmeHellos.Load() != 1 {
		t.Fatalf("certificate service consulted %d times", acmeHellos.Load())
	}
	// Ordinary handshakes and plain HTTP are refused.
	if tc, err := dial(normal); err == nil {
		tc.Close()
		t.Fatal("normal handshake from a denied address")
	}
	c, err := net.DialTimeout("tcp", ln.Addr().String(), 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	_, _ = c.Write([]byte("GET / HTTP/1.1\r\nHost: x\r\n\r\n"))
	if n, _ := c.Read(make([]byte, 64)); n > 0 {
		t.Fatal("plain HTTP answered for a denied address")
	}
	c.Close()
	// Without the tls-alpn challenge the address is refused outright.
	open.Store(false)
	if tc, err := dial(acme); err == nil {
		tc.Close()
		t.Fatal("validation handshake without the tls-alpn challenge")
	}
	if acmeHellos.Load() != 1 {
		t.Fatal("certificate service consulted for a refused address")
	}
	select {
	case c := <-accepted:
		c.Close()
		t.Fatal("a challenge-only connection reached the HTTP server")
	case <-time.After(100 * time.Millisecond):
	}
}

func TestIsACMEHello(t *testing.T) {
	for _, tc := range []struct {
		name   string
		protos []string
		want   bool
	}{
		{"a.example", []string{"acme-tls/1"}, true},
		{"", []string{"acme-tls/1"}, false},
		{"a.example", []string{"acme-tls/1", "h2"}, false},
		{"a.example", []string{"h2"}, false},
		{"a.example", nil, false},
	} {
		if got := isACMEHello(&tls.ClientHelloInfo{ServerName: tc.name, SupportedProtos: tc.protos}); got != tc.want {
			t.Errorf("%q %v: %v", tc.name, tc.protos, got)
		}
	}
}

// ---------- mDNS settling ----------

// fakeMDNS implements core.MDNS with a status the test drives.
type fakeMDNS struct {
	mu sync.Mutex
	st core.MDNSStatus
}

func (m *fakeMDNS) set(st core.MDNSStatus) {
	m.mu.Lock()
	m.st = st
	m.mu.Unlock()
}
func (m *fakeMDNS) Status() core.MDNSStatus {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.st
}
func (m *fakeMDNS) Name() string                    { return m.Status().Name }
func (m *fakeMDNS) Republish(context.Context) error { return nil }
func (m *fakeMDNS) Start(context.Context) error     { return nil }
func (m *fakeMDNS) Stop() error                     { return nil }

func newSettleRunner(t *testing.T, m core.MDNS) (*runner, *events.Bus) {
	t.Helper()
	bus := events.New()
	t.Cleanup(bus.Close)
	d := &app.Deps{Env: &core.Env{Bus: bus, Log: discard}, MDNS: m}
	return &runner{d: d, log: discard}, bus
}

// took runs settleMDNS and reports how long it blocked.
func took(ctx context.Context, r *runner) time.Duration {
	start := time.Now()
	r.settleMDNS(ctx)
	return time.Since(start)
}

func TestSettleMDNSWaitsForTheEffectiveName(t *testing.T) {
	ctx := context.Background()

	// Already published, or publishing switched off: no wait.
	for _, st := range []core.MDNSStatus{
		{Mode: "auto", Backend: "avahi", Name: "fileparcel.local", State: core.MDNSPublished},
		{Mode: "auto", Backend: "avahi", Name: "fileparcel.local", State: core.MDNSError, Error: "no avahi"},
		{Mode: "off", Name: "fileparcel.local", State: core.MDNSOff},
	} {
		r, _ := newSettleRunner(t, &fakeMDNS{st: st})
		if d := took(ctx, r); d > time.Second {
			t.Fatalf("state %q mode %q blocked for %v", st.State, st.Mode, d)
		}
	}

	// Not settled yet (the supervisor has not run, so Status reports "off"
	// while the mode is "auto"): wait for the final result and ignore the
	// collision renames on the way.
	m := &fakeMDNS{st: core.MDNSStatus{Mode: "auto", State: core.MDNSOff, Name: "fileparcel.local"}}
	r, bus := newSettleRunner(t, m)
	go func() {
		for _, st := range []core.MDNSStatus{
			{Mode: "auto", Backend: "avahi", Name: "fileparcel.local", State: core.MDNSPublishing},
			{Mode: "auto", Backend: "avahi", Name: "fileparcel.local", State: core.MDNSCollision},
			{Mode: "auto", Backend: "avahi", Name: "fileparcel-2.local", State: core.MDNSPublished},
		} {
			time.Sleep(20 * time.Millisecond)
			m.set(st)
			bus.Publish(events.Event{Topic: events.TopicMDNSChanged, Data: st})
		}
	}()
	if d := took(ctx, r); d >= mdnsSettleTimeout {
		t.Fatalf("did not return on the published event (%v)", d)
	}
	if got := m.Status().Name; got != "fileparcel-2.local" {
		t.Fatalf("settled on %q", got)
	}

	// A cancelled context and a missing service never block.
	cctx, cancel := context.WithCancel(ctx)
	cancel()
	r, _ = newSettleRunner(t, &fakeMDNS{st: core.MDNSStatus{Mode: "auto", State: core.MDNSPublishing}})
	if d := took(cctx, r); d > time.Second {
		t.Fatalf("cancelled context blocked for %v", d)
	}
	r, _ = newSettleRunner(t, nil)
	r.d.MDNS = nil
	if d := took(ctx, r); d > time.Second {
		t.Fatalf("without mDNS blocked for %v", d)
	}
}

// TestSettleMDNSIsBounded: a backend that never reports back delays the
// readiness banner by at most mdnsSettleTimeout.
func TestSettleMDNSIsBounded(t *testing.T) {
	r, _ := newSettleRunner(t, &fakeMDNS{st: core.MDNSStatus{Mode: "auto", State: core.MDNSPublishing}})
	d := took(context.Background(), r)
	if d < mdnsSettleTimeout || d > mdnsSettleTimeout+5*time.Second {
		t.Fatalf("waited %v, want about %v", d, mdnsSettleTimeout)
	}
}

// ---------- request body deadlines ----------

// bodyTimeoutServer serves the probes of the body-deadline tests with a
// short rolling deadline.
func bodyTimeoutServer(t *testing.T, d time.Duration, readErr, ctxErr *atomic.Value) *httptest.Server {
	t.Helper()
	h := bodyTimeout(d)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/reject": // refuses without touching the body
			w.WriteHeader(http.StatusNotFound)
		case "/bodyless": // slower than the deadline: must not be cancelled
			time.Sleep(4 * d)
			if err := r.Context().Err(); err != nil {
				ctxErr.Store(err.Error())
			}
			w.WriteHeader(http.StatusOK)
		default:
			if _, err := io.ReadAll(r.Body); err != nil {
				readErr.Store(err.Error())
				w.WriteHeader(http.StatusRequestTimeout)
				return
			}
			w.WriteHeader(http.StatusOK)
		}
	}))
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	return srv
}

func dialRaw(t *testing.T, srv *httptest.Server) (net.Conn, *bufio.Reader) {
	t.Helper()
	c, err := net.Dial("tcp", strings.TrimPrefix(srv.URL, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	_ = c.SetDeadline(time.Now().Add(20 * time.Second))
	return c, bufio.NewReader(c)
}

func writeHead(t *testing.T, c net.Conn, method, path string, length int) {
	t.Helper()
	req := method + " " + path + " HTTP/1.1\r\nHost: localhost\r\n"
	if length >= 0 {
		req += "Content-Type: application/octet-stream\r\nContent-Length: " + strconv.Itoa(length) + "\r\n"
	}
	if _, err := io.WriteString(c, req+"\r\n"); err != nil {
		t.Fatal(err)
	}
}

func TestBodyTimeoutStalledSender(t *testing.T) {
	const d = 300 * time.Millisecond
	var readErr, ctxErr atomic.Value
	srv := bodyTimeoutServer(t, d, &readErr, &ctxErr)

	// A sender that stops mid-body is torn down instead of parking the
	// connection forever.
	c, br := dialRaw(t, srv)
	writeHead(t, c, "POST", "/", 4096)
	if _, err := c.Write([]byte("{")); err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatalf("no answer to the stalled body: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusRequestTimeout {
		t.Fatalf("status %d, want 408", resp.StatusCode)
	}
	if el := time.Since(start); el > 20*d {
		t.Fatalf("torn down only after %v", el)
	}
	if s, _ := readErr.Load().(string); !strings.Contains(s, "deadline") && !strings.Contains(s, "timeout") {
		t.Fatalf("body read error %q", s)
	}
}

func TestBodyTimeoutRejectedRequestDoesNotPark(t *testing.T) {
	const d = 300 * time.Millisecond
	var readErr, ctxErr atomic.Value
	srv := bodyTimeoutServer(t, d, &readErr, &ctxErr)

	// The handler answers 404 without reading the body: net/http's drain has
	// no deadline of its own, so the deadline armed before the handler is
	// what frees the connection.
	c, br := dialRaw(t, srv)
	start := time.Now()
	writeHead(t, c, "POST", "/reject", 4096)
	_ = c.SetReadDeadline(time.Now().Add(20 * d))
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatalf("no answer after %v: %v", time.Since(start), err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("status %d, want 404", resp.StatusCode)
	}
	// io.Copy reports nil once the server closed the connection; anything
	// else means the client still holds a live, parked connection.
	if _, err := io.Copy(io.Discard, br); err != nil {
		t.Fatalf("the connection was not freed (%v after %v)", err, time.Since(start))
	}
	if el := time.Since(start); el > 20*d {
		t.Fatalf("connection freed only after %v", el)
	}
}

func TestBodyTimeoutSlowButSteadySenderAndBodylessRequest(t *testing.T) {
	const d = 300 * time.Millisecond
	var readErr, ctxErr atomic.Value
	srv := bodyTimeoutServer(t, d, &readErr, &ctxErr)

	// Slow but steady: every byte extends the deadline, so a long upload on
	// a bad link still completes.
	c, br := dialRaw(t, srv)
	const n = 6
	writeHead(t, c, "POST", "/", n)
	for range n {
		time.Sleep(d / 3)
		if _, err := c.Write([]byte("x")); err != nil {
			t.Fatal(err)
		}
	}
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("trickled body: %d", resp.StatusCode)
	}
	if s, ok := readErr.Load().(string); ok {
		t.Fatalf("body read error %q", s)
	}

	// A bodyless request keeps no deadline: arming one would trip net/http's
	// background read and cancel the request context (downloads, SSE).
	c2, br2 := dialRaw(t, srv)
	writeHead(t, c2, "GET", "/bodyless", -1)
	resp, err = http.ReadResponse(br2, nil)
	if err != nil {
		t.Fatalf("bodyless request: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("bodyless: %d", resp.StatusCode)
	}
	if s, ok := ctxErr.Load().(string); ok {
		t.Fatalf("request context cancelled: %q", s)
	}
}

func TestBodyTimeoutOverHTTP2(t *testing.T) {
	const d = 300 * time.Millisecond
	var readErr, ctxErr atomic.Value
	h := bodyTimeout(d)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, err := io.ReadAll(r.Body); err != nil {
			readErr.Store(err.Error())
			w.WriteHeader(http.StatusRequestTimeout)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	srv := httptest.NewUnstartedServer(h)
	srv.EnableHTTP2 = true
	srv.StartTLS()
	t.Cleanup(srv.Close)

	// A stream whose body stalls is torn down too: SetReadDeadline reaches
	// the HTTP/2 stream, where 250 of them share one TCP connection.
	pr, pw := io.Pipe()
	t.Cleanup(func() { _ = pw.Close() })
	req, err := http.NewRequest(http.MethodPost, srv.URL+"/", pr)
	if err != nil {
		t.Fatal(err)
	}
	req.ContentLength = -1
	start := time.Now()
	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatalf("no answer to the stalled h2 body: %v", err)
	}
	defer resp.Body.Close()
	if resp.ProtoMajor != 2 {
		t.Fatalf("proto %s", resp.Proto)
	}
	if resp.StatusCode != http.StatusRequestTimeout {
		t.Fatalf("status %d, want 408", resp.StatusCode)
	}
	if el := time.Since(start); el > 20*d {
		t.Fatalf("torn down only after %v", el)
	}
	if s, _ := readErr.Load().(string); s == "" {
		t.Fatal("the body read did not fail")
	}
	_ = ctxErr
}
