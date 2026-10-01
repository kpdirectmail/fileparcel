package server

import (
	"bufio"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"fileparcel/internal/app"
	"fileparcel/internal/core"
	"fileparcel/internal/tsingress"
	"fileparcel/internal/web/httpx"
	"fileparcel/internal/web/mw"
)

// ---------- fakes ----------

// fakeIngress is the part of core.Ingress the server uses (the rest panics).
type fakeIngress struct {
	core.Ingress
	mu       sync.Mutex
	pol      map[string]core.IngressPolicy
	nonce    string
	notes    []string
	attached chan core.IngressListeners
	onDetach func()
	detached atomic.Int32
}

func newFakeIngress() *fakeIngress {
	return &fakeIngress{attached: make(chan core.IngressListeners, 1), pol: map[string]core.IngressPolicy{
		core.IngressFunnel: {Mode: core.FunnelShares, DNSName: "node.tail.ts.net", Port: 443},
		core.IngressServe:  {Mode: core.FunnelApp, DNSName: "node.tail.ts.net", Port: 8443},
	}}
}

func (f *fakeIngress) Attach(l core.IngressListeners) { f.attached <- l }
func (f *fakeIngress) Detach(context.Context) {
	if f.onDetach != nil {
		f.onDetach()
	}
	f.detached.Add(1)
}
func (f *fakeIngress) Policy(kind string) core.IngressPolicy {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.pol[kind]
}
func (f *fakeIngress) setPolicy(kind string, p core.IngressPolicy) {
	f.mu.Lock()
	f.pol[kind] = p
	f.mu.Unlock()
}
func (f *fakeIngress) CheckProbe(kind, nonce string) bool {
	return kind == core.IngressFunnel && f.nonce != "" && nonce == f.nonce
}
func (f *fakeIngress) Note(kind string, public, conflict bool) {
	f.mu.Lock()
	f.notes = append(f.notes, fmt.Sprintf("%s public=%v conflict=%v", kind, public, conflict))
	f.mu.Unlock()
}
func (f *fakeIngress) lastNote() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.notes) == 0 {
		return ""
	}
	return f.notes[len(f.notes)-1]
}

// ingressInfoLine describes what the application handler saw of an
// ingress request.
func ingressInfoLine(r *http.Request) string {
	in := core.IngressFrom(r.Context())
	if in == nil {
		return "direct remote=" + r.RemoteAddr
	}
	var hdr []string
	for _, k := range []string{"X-Forwarded-For", "X-Forwarded-Host", "X-Forwarded-Proto", "Forwarded", "X-Real-Ip", "Via",
		"Tailscale-Funnel-Request", "Tailscale-User-Login", "X-Fp-As", "X-Forwarded-Port"} {
		if r.Header.Get(k) != "" {
			hdr = append(hdr, k)
		}
	}
	return fmt.Sprintf("kind=%s ip=%s public=%v host=%s tsuser=%s remote=%s rhost=%s urlhost=%s leftover=%s tls=%v",
		in.Kind, in.ClientIP, in.Public, in.Host, in.TSUser, r.RemoteAddr, r.Host, r.URL.Host, strings.Join(hdr, ","), r.TLS != nil)
}

// ---------- the handler: header trust ----------

func ingressRequest(method, target string, hdr map[string][]string) *http.Request {
	r := httptest.NewRequest(method, target, nil)
	r.RemoteAddr = "@"
	r.Host = "localhost"
	for k, vs := range hdr {
		for _, v := range vs {
			r.Header.Add(k, v)
		}
	}
	return r
}

func TestIngressHandlerHeaderTrust(t *testing.T) {
	fi := newFakeIngress()
	d := &app.Deps{Ingress: fi}
	var hits atomic.Int64
	h := func(kind string) http.Handler {
		return ingressHandler(d, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			hits.Add(1)
			fmt.Fprint(w, ingressInfoLine(r))
		}), kind, slog.New(slog.DiscardHandler))
	}
	do := func(kind, target string, hdr map[string][]string) *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		h(kind).ServeHTTP(rec, ingressRequest(http.MethodGet, target, hdr))
		return rec
	}
	good := func(extra map[string][]string) map[string][]string {
		m := map[string][]string{"X-Forwarded-For": {"203.0.113.9"}, "X-Forwarded-Host": {"node.tail.ts.net"}}
		for k, v := range extra {
			m[k] = v
		}
		return m
	}

	// 1. X-Forwarded-For: exactly one line with one address; no loopback,
	// unspecified or multicast.
	for name, xff := range map[string][]string{
		"missing": nil, "two lines": {"203.0.113.9", "198.51.100.1"}, "two values": {"203.0.113.9, 198.51.100.1"},
		"garbage": {"not-an-ip"}, "with port": {"203.0.113.9:4433"}, "zone": {"fe80::1%eth0"}, "loopback": {"127.0.0.1"},
		"loopback6": {"::1"}, "unspecified": {"::"}, "unspecified4": {"0.0.0.0"}, "multicast": {"ff02::1"},
		"spaces": {" 203.0.113.9"}, "empty": {""},
	} {
		hdr := good(nil)
		if xff == nil {
			delete(hdr, "X-Forwarded-For")
		} else {
			hdr["X-Forwarded-For"] = xff
		}
		rec := do(core.IngressFunnel, "/s/x", hdr)
		if rec.Code != http.StatusBadRequest || rec.Header().Get("Connection") != "close" {
			t.Errorf("XFF %s: %d %v", name, rec.Code, rec.Header())
		}
	}
	if hits.Load() != 0 {
		t.Fatalf("a refused request reached the router (%d)", hits.Load())
	}

	// 2. X-Forwarded-Host: the MagicDNS name, the kind's port if any.
	for _, xfh := range []string{"node.tail.ts.net", "node.tail.ts.net:443", "NODE.Tail.TS.net", "node.tail.ts.net.",
		"Node.Tail.Ts.Net.:443"} {
		rec := do(core.IngressFunnel, "/s/x", good(map[string][]string{"X-Forwarded-Host": {xfh}}))
		if rec.Code != 200 || !strings.Contains(rec.Body.String(), "rhost=node.tail.ts.net ") {
			t.Errorf("XFH %q: %d %s", xfh, rec.Code, rec.Body.String())
		}
	}
	for _, xfh := range [][]string{nil, {"evil.example"}, {"node.tail.ts.net:8443"}, {"node.tail.ts.net:"}, {"node.tail.ts.net", "node.tail.ts.net"},
		{"other.tail.ts.net"}, {"[::1]:443"}, {"node.tail.ts.net.evil"}} {
		hdr := good(nil)
		if xfh == nil {
			delete(hdr, "X-Forwarded-Host")
		} else {
			hdr["X-Forwarded-Host"] = xfh
		}
		if rec := do(core.IngressFunnel, "/s/x", hdr); rec.Code != http.StatusMisdirectedRequest {
			t.Errorf("XFH %q: %d", xfh, rec.Code)
		}
	}
	// A port other than 443 is kept in the canonical Host.
	rec := do(core.IngressServe, "/", good(map[string][]string{"X-Forwarded-Host": {"node.tail.ts.net:8443"}}))
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), "rhost=node.tail.ts.net:8443 ") {
		t.Fatalf("serve on 8443: %d %s", rec.Code, rec.Body.String())
	}
	if rec := do(core.IngressServe, "/", good(nil)); rec.Code != 200 {
		t.Fatalf("serve without a port in the host: %d", rec.Code)
	}

	// 5/6. The client becomes the request's address; the proxy headers
	// (and X-FP-As) are gone; the URL's host is cleared; no TLS redirect.
	rec = do(core.IngressFunnel, "http://attacker.example/s/x", good(map[string][]string{
		"Tailscale-Funnel-Request": {"?1"}, "X-Forwarded-Proto": {"https"}, "Forwarded": {"for=1.2.3.4"}, "X-Real-Ip": {"1.2.3.4"},
		"Via": {"1.1 proxy"}, "Tailscale-User-Login": {"alice@example.com"}, mw.HeaderActAs: {"admin"}, "X-Forwarded-Port": {"443"},
	}))
	want := "kind=funnel ip=203.0.113.9 public=true host=node.tail.ts.net tsuser= remote=203.0.113.9:0 rhost=node.tail.ts.net " +
		"urlhost= leftover= tls=false"
	if rec.Code != 200 || rec.Body.String() != want {
		t.Fatalf("funnel request:\n got %d %s\nwant %s", rec.Code, rec.Body.String(), want)
	}
	if fi.lastNote() != "funnel public=true conflict=false" {
		t.Fatalf("note %q", fi.lastNote())
	}
	// IPv6 and IPv4-mapped clients.
	rec = do(core.IngressFunnel, "/s/x", good(map[string][]string{"X-Forwarded-For": {"2001:db8::7"}}))
	if !strings.Contains(rec.Body.String(), "ip=2001:db8::7 ") || !strings.Contains(rec.Body.String(), "remote=[2001:db8::7]:0 ") {
		t.Fatalf("v6 client: %s", rec.Body.String())
	}
	rec = do(core.IngressFunnel, "/s/x", good(map[string][]string{"X-Forwarded-For": {"::ffff:203.0.113.9"}}))
	if !strings.Contains(rec.Body.String(), "ip=203.0.113.9 ") {
		t.Fatalf("v4-mapped client: %s", rec.Body.String())
	}
	// Without the Funnel marker a funnel request is not public (a tailnet
	// device on the Funnel port); Serve keeps the tailnet login for the log.
	rec = do(core.IngressFunnel, "/s/x", good(nil))
	if !strings.Contains(rec.Body.String(), "public=false") || fi.lastNote() != "funnel public=false conflict=false" {
		t.Fatalf("tailnet on the funnel port: %s %q", rec.Body.String(), fi.lastNote())
	}
	rec = do(core.IngressServe, "/", good(map[string][]string{"Tailscale-User-Login": {"alice@example.com"}}))
	if !strings.Contains(rec.Body.String(), "kind=serve ") || !strings.Contains(rec.Body.String(), "tsuser=alice@example.com ") ||
		!strings.Contains(rec.Body.String(), "leftover= ") {
		t.Fatalf("serve: %s", rec.Body.String())
	}

	// 3. The Funnel marker on the serve listener: 403, noted as a conflict.
	n := hits.Load()
	rec = do(core.IngressServe, "/", good(map[string][]string{"Tailscale-Funnel-Request": {"?1"}}))
	if rec.Code != http.StatusForbidden || hits.Load() != n || fi.lastNote() != "serve public=false conflict=true" {
		t.Fatalf("funnel on serve: %d %q", rec.Code, fi.lastNote())
	}

	// 4. The self-probe: 204 for the nonce in flight, else the app.
	fi.nonce = "n0nce"
	rec = do(core.IngressFunnel, tsingress.ProbePath+"n0nce", good(nil))
	if rec.Code != http.StatusNoContent || rec.Header().Get("Cache-Control") != "no-store" || hits.Load() != n {
		t.Fatalf("probe: %d %v", rec.Code, rec.Header())
	}
	for _, p := range []string{tsingress.ProbePath + "wrong", tsingress.ProbePath, tsingress.ProbePath + "n0nce/x"} {
		if rec := do(core.IngressFunnel, p, good(nil)); rec.Code != 200 || hits.Load() == n {
			t.Fatalf("probe %s: %d", p, rec.Code)
		}
		n = hits.Load()
	}
	if rec := do(core.IngressServe, tsingress.ProbePath+"n0nce", good(nil)); rec.Code != 200 {
		t.Fatalf("probe nonce of another kind: %d", rec.Code)
	}

	// Fail closed while the policy is off (a request that raced a disable).
	fi.setPolicy(core.IngressFunnel, core.IngressPolicy{Mode: core.FunnelOff})
	n = hits.Load()
	if rec := do(core.IngressFunnel, "/s/x", good(nil)); rec.Code != http.StatusNotFound || hits.Load() != n {
		t.Fatalf("policy off: %d", rec.Code)
	}
	// And without an Ingress service at all.
	rec = httptest.NewRecorder()
	ingressHandler(&app.Deps{}, http.NotFoundHandler(), core.IngressFunnel, slog.New(slog.DiscardHandler)).
		ServeHTTP(rec, ingressRequest(http.MethodGet, "/s/x", good(nil)))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("no ingress service: %d", rec.Code)
	}
}

// ---------- peer credentials ----------

// A fixed /proc/net/tcp table (little-endian host): tailscaled (uid 0) is
// connected from 127.0.0.1:41234 to FileParcel's 127.0.0.1:18443.
const procNetTCP = `  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 0100007F:4823 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 11 1 0000000000000000 100 0 0 10 0
   1: 0100007F:A0D2 0100007F:4823 01 00000000:00000000 00:00000000 00000000     0        0 12 1 0000000000000000 20 4 30 10 -1
   2: 0100007F:4823 0100007F:A0D2 01 00000000:00000000 00:00000000 00000000  1000        0 13 1 0000000000000000 20 4 30 10 -1
   3: 0100007F:A0D3 0100007F:4824 01 00000000:00000000 00:00000000 00000000   977        0 14 1 0000000000000000 20 4 30 10 -1
`

// The same peer as a dual-stack socket in /proc/net/tcp6 (::ffff:127.0.0.1).
const procNetTCP6 = `  sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 0000000000000000FFFF00000100007F:A0D2 0000000000000000FFFF00000100007F:4823 01 00000000:00000000 00:00000000 00000000   108        0 21 1 0000000000000000 20 4 30 10 -1
   1: 00000000000000000000000001000000:1F90 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 22 1 0000000000000000 100 0 0 10 0
`

func TestProcNetPeerUID(t *testing.T) {
	ap := netip.MustParseAddrPort
	le := binary.LittleEndian
	peer, ours := ap("127.0.0.1:41170"), ap("127.0.0.1:18467")
	if uid, ok := procNetPeerUID([]byte(procNetTCP), peer, ours, le); !ok || uid != 0 {
		t.Fatalf("v4 row: %d %v", uid, ok)
	}
	// Our own end of the connection has local/remote swapped: never taken
	// for the peer's.
	if uid, ok := procNetPeerUID([]byte(procNetTCP), ours, peer, le); !ok || uid != 1000 {
		t.Fatalf("own row: %d %v", uid, ok)
	}
	// Another connection (other ports), and no row at all.
	if _, ok := procNetPeerUID([]byte(procNetTCP), ap("127.0.0.1:41171"), ours, le); ok {
		t.Fatal("wrong row matched")
	}
	if _, ok := procNetPeerUID([]byte(procNetTCP), ap("127.0.0.1:41170"), ap("127.0.0.1:18468"), le); ok {
		t.Fatal("row with another local port matched")
	}
	if _, ok := procNetPeerUID([]byte(procNetTCP[:strings.IndexByte(procNetTCP, '\n')+1]), peer, ours, le); ok {
		t.Fatal("header only")
	}
	// v4-mapped peer in tcp6; the lookup is by the IPv4 form.
	if uid, ok := procNetPeerUID([]byte(procNetTCP6), peer, ours, le); !ok || uid != 108 {
		t.Fatalf("tcp6 row: %d %v", uid, ok)
	}
	if uid, ok := procNetPeerUID([]byte(procNetTCP6), ap("[::ffff:127.0.0.1]:41170"), ap("[::ffff:127.0.0.1]:18467"), le); !ok || uid != 108 {
		t.Fatalf("tcp6 row by mapped address: %d %v", uid, ok)
	}
	// Big-endian hosts print the words the other way round.
	be := strings.ReplaceAll(procNetTCP, "0100007F", "7F000001")
	if uid, ok := procNetPeerUID([]byte(be), peer, ours, binary.BigEndian); !ok || uid != 0 {
		t.Fatalf("big-endian row: %d %v", uid, ok)
	}
	// Malformed rows are skipped.
	for _, bad := range []string{"0: zz:4823 0100007F:A0D2 01 0 0 0 0", "0: 0100007F:A0D2", "0: 0100007F:A0D2 0100007F:4823 01 0 0 0 x"} {
		if _, ok := procNetPeerUID([]byte("header\n"+bad+"\n"), peer, ours, le); ok {
			t.Errorf("malformed row %q matched", bad)
		}
	}
}

// fixedUIDListener wraps a listener with a fake peer lookup.
func fixedUIDListener(t *testing.T, ln net.Listener, uid int, err error, allowed ...int) *ingressListener {
	t.Helper()
	return &ingressListener{Listener: ln, kind: core.IngressFunnel, allowed: allowed,
		uidOf: func(net.Conn) (int, error) { return uid, err }, log: slog.New(slog.DiscardHandler),
		refused: &logEvery{every: time.Minute}}
}

func TestIngressListenerPeerCheck(t *testing.T) {
	dir, err := shortTempDir(t)
	if err != nil {
		t.Fatal(err)
	}
	accept := func(il *ingressListener, path string) bool {
		t.Helper()
		got := make(chan net.Conn, 1)
		go func() {
			c, err := il.Accept()
			if err == nil {
				got <- c
			}
			close(got)
		}()
		c, err := net.Dial("unix", path)
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		select {
		case sc, ok := <-got:
			if ok {
				sc.Close()
			}
			return ok
		case <-time.After(300 * time.Millisecond):
			// Refused: Accept closed the connection and waits for the next.
			_ = c.SetReadDeadline(time.Now().Add(time.Second))
			if _, err := c.Read(make([]byte, 1)); err == nil {
				t.Fatal("refused connection still open")
			}
			il.Close()
			<-got
			return false
		}
	}
	for name, tc := range map[string]struct {
		uid     int
		err     error
		allowed []int
		want    bool
	}{
		"own uid":       {uid: os.Getuid(), allowed: []int{0, os.Getuid()}, want: true},
		"root":          {uid: 0, allowed: []int{0, os.Getuid()}, want: true},
		"foreign":       {uid: 4242, allowed: []int{0, os.Getuid()}},
		"lookup failed": {uid: -1, err: errors.New("no row"), allowed: []int{-1}},
		"unverifiable":  {uid: -1, err: errPeerUnverifiable, allowed: []int{0}, want: true},
	} {
		path := filepath.Join(dir, "t.sock")
		ln, err := net.Listen("unix", path)
		if err != nil {
			t.Fatal(err)
		}
		il := fixedUIDListener(t, ln, tc.uid, tc.err, tc.allowed...)
		if got := accept(il, path); got != tc.want {
			t.Errorf("%s: accepted=%v", name, got)
		}
		il.Close()
		_ = os.Remove(path)
	}
	// The real SO_PEERCRED lookup names this process.
	path := filepath.Join(dir, "r.sock")
	ln, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		c, _ := net.Dial("unix", path)
		if c != nil {
			time.Sleep(200 * time.Millisecond)
			c.Close()
		}
	}()
	c, err := ln.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if uid, err := unixPeerUID(c); (runtime.GOOS == "linux" || runtime.GOOS == "darwin") && (err != nil || uid != os.Getuid()) {
		t.Fatalf("unix peer uid %d %v", uid, err)
	}
}

// The loopback TCP lookup of this machine finds the test's own uid.
func TestLoopbackPeerUID(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("/proc/net/tcp is Linux-only")
	}
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		c, _ := net.Dial("tcp4", ln.Addr().String())
		if c != nil {
			time.Sleep(300 * time.Millisecond)
			c.Close()
		}
	}()
	c, err := ln.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	uid, err := loopbackPeerUID(c)
	if err != nil || uid != os.Getuid() {
		t.Fatalf("peer uid %d %v, want %d", uid, err, os.Getuid())
	}
}

// ---------- the listener manager ----------

func TestIngressManagerOpenErrors(t *testing.T) {
	td := newDeps(t)
	h := td.d.Home
	m := newIngressManager(td.d, http.NotFoundHandler(), slog.New(slog.DiscardHandler), newErrorLog(slog.New(slog.DiscardHandler)))
	defer func() { m.drain(context.Background(), m.stop()) }()
	uids := []int{os.Getuid()}
	for name, tc := range map[string]struct{ kind, network, address string }{
		"unknown kind":        {"magic", "unix", filepath.Join(h.RunDir(), "ts-funnel.sock")},
		"outside run dir":     {core.IngressFunnel, "unix", filepath.Join(os.TempDir(), "ts-funnel.sock")},
		"relative":            {core.IngressFunnel, "unix", "run/ts-funnel.sock"},
		"not loopback":        {core.IngressFunnel, "tcp4", "0.0.0.0:18443"},
		"IPv6 loopback":       {core.IngressFunnel, "tcp4", "[::1]:18443"},
		"no port":             {core.IngressFunnel, "tcp4", "127.0.0.1:0"},
		"unsupported network": {core.IngressFunnel, "tcp6", "[::1]:18443"},
	} {
		if err := m.Open(tc.kind, tc.network, tc.address, uids); err == nil {
			t.Errorf("%s: opened", name)
		}
	}
	// A path tailscaled cannot dial.
	long := filepath.Join(h.RunDir(), strings.Repeat("x", maxSocketPath))
	if err := m.Open(core.IngressFunnel, "unix", long, uids); !errors.Is(err, errPathTooLong) {
		t.Errorf("long path: %v", err)
	}
	// A busy TCP port is an error, never shared.
	busy, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer busy.Close()
	if err := m.Open(core.IngressServe, "tcp4", busy.Addr().String(), uids); err == nil {
		t.Error("busy port opened")
	}
	// A stale socket file is replaced; a live one is not.
	sock := filepath.Join(h.RunDir(), "ts-funnel.sock")
	stale, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	stale.(*net.UnixListener).SetUnlinkOnClose(false)
	stale.Close()
	if err := m.Open(core.IngressFunnel, "unix", sock, uids); err != nil {
		t.Fatalf("stale socket: %v", err)
	}
	m2 := newIngressManager(td.d, http.NotFoundHandler(), slog.New(slog.DiscardHandler), newErrorLog(slog.New(slog.DiscardHandler)))
	if err := m2.Open(core.IngressFunnel, "unix", sock, uids); err == nil {
		t.Fatal("a live socket was taken over")
	}
	if got := m.kinds(); !slices.Equal(got, []string{core.IngressFunnel}) {
		t.Fatalf("open kinds %v", got)
	}
}

// OpenAt keeps a kind's listener at another address bound (tsingress keeps
// the old 127.0.0.1 port while tailscaled may still route to it); CloseAt
// closes just one; Open and Close act on all of the kind.
func TestIngressManagerOpenAt(t *testing.T) {
	td := newDeps(t)
	m := newIngressManager(td.d, http.NotFoundHandler(), slog.New(slog.DiscardHandler), newErrorLog(slog.New(slog.DiscardHandler)))
	defer func() { m.drain(context.Background(), m.stop()) }()
	uids := []int{os.Getuid()}
	bound := func(addr string) bool {
		ln, err := net.Listen("tcp4", addr)
		if err != nil {
			return true
		}
		ln.Close()
		return false
	}
	a := "127.0.0.1:" + strconv.Itoa(freePort(t))
	b := "127.0.0.1:" + strconv.Itoa(freePort(t))
	sock := filepath.Join(td.d.Home.RunDir(), "ts-funnel.sock")
	if err := m.OpenAt(core.IngressFunnel, "tcp4", a, uids); err != nil {
		t.Fatal(err)
	}
	if err := m.OpenAt(core.IngressFunnel, "unix", sock, uids); err != nil {
		t.Fatal(err)
	}
	if err := m.OpenAt(core.IngressFunnel, "tcp4", a, uids); err != nil { // idempotent
		t.Fatal(err)
	}
	if !bound(a) || len(m.open) != 2 {
		t.Fatalf("both listeners: %v %d", bound(a), len(m.open))
	}
	m.CloseAt(core.IngressFunnel, "tcp4", a)
	if bound(a) || len(m.open) != 1 {
		t.Fatalf("after CloseAt: %v %d", bound(a), len(m.open))
	}
	if err := m.OpenAt(core.IngressFunnel, "tcp4", b, uids); err != nil {
		t.Fatal(err)
	}
	// Open replaces every listener of the kind.
	if err := m.Open(core.IngressFunnel, "tcp4", a, uids); err != nil {
		t.Fatal(err)
	}
	if !bound(a) || bound(b) || len(m.open) != 1 {
		t.Fatalf("after Open: %v %v %d", bound(a), bound(b), len(m.open))
	}
	if err := m.OpenAt(core.IngressServe, "tcp4", b, uids); err != nil {
		t.Fatal(err)
	}
	m.Close(core.IngressFunnel)
	if bound(a) || !bound(b) || !slices.Equal(m.kinds(), []string{core.IngressServe}) {
		t.Fatalf("after Close: %v %v %v", bound(a), bound(b), m.kinds())
	}
}

// socketClient is an HTTP client that dials the Unix socket path (as
// tailscaled does for a unix: target).
func socketClient(path string) *http.Client {
	return &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{DisableKeepAlives: true,
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "unix", path)
		}}}
}

// tailscaledGet sends what tailscaled forwards for a Funnel visitor.
func tailscaledGet(c *http.Client, url string, hdr map[string]string) (int, string, error) {
	req, _ := http.NewRequest(http.MethodGet, url, nil)
	req.Header.Set("X-Forwarded-For", "203.0.113.9")
	req.Header.Set("X-Forwarded-Host", "node.tail.ts.net")
	req.Header.Set("X-Forwarded-Proto", "https")
	req.Header.Set("Tailscale-Funnel-Request", "?1")
	for k, v := range hdr {
		if v == "" {
			req.Header.Del(k)
		} else {
			req.Header.Set(k, v)
		}
	}
	resp, err := c.Do(req)
	if err != nil {
		return 0, "", err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b), nil
}

// Run attaches the Ingress service after its listeners are up; the
// listeners it opens serve the router with the ingress marking; the
// shutdown detaches the service before the drain and closes them.
func TestRunIngressListeners(t *testing.T) {
	td := newDeps(t)
	fi := newFakeIngress()
	td.d.Ingress = fi
	sock := filepath.Join(td.d.Home.RunDir(), "ts-funnel.sock")
	fi.onDetach = func() {
		// Detach runs before the drain: the listeners still exist.
		if _, err := os.Stat(sock); err != nil {
			t.Errorf("funnel socket gone before Detach: %v", err)
		}
	}
	rn := start(t, td, Options{})
	var lis core.IngressListeners
	select {
	case lis = <-fi.attached:
	case <-time.After(5 * time.Second):
		t.Fatal("Attach not called")
	}
	uids := []int{0, os.Getuid()}
	if err := lis.Open(core.IngressFunnel, "unix", sock, uids); err != nil {
		t.Fatal(err)
	}
	if err := lis.Open(core.IngressFunnel, "unix", sock, uids); err != nil { // idempotent
		t.Fatal(err)
	}
	if fi, err := os.Stat(sock); err != nil || fi.Mode()&os.ModeSocket == 0 || fi.Mode().Perm() != 0o600 {
		t.Fatalf("socket %v %v", fi, err)
	}
	c := socketClient(sock)
	code, body, err := tailscaledGet(c, "http://localhost/ingress-info", map[string]string{mw.HeaderActAs: "admin"})
	if err != nil || code != 200 {
		t.Fatalf("funnel request: %d %s %v", code, body, err)
	}
	if want := "kind=funnel ip=203.0.113.9 public=true host=node.tail.ts.net tsuser= remote=203.0.113.9:0 " +
		"rhost=node.tail.ts.net urlhost= leftover= tls=false"; body != want {
		t.Fatalf("funnel request:\n got %s\nwant %s", body, want)
	}
	// The ingress listener carries no principal: no socket privileges.
	if code, body, _ := tailscaledGet(c, "http://localhost/", nil); code != 200 || !strings.HasPrefix(body, "hello anonymous HTTP/1.1") {
		t.Fatalf("principal on the ingress listener: %d %s", code, body)
	}

	// Only the listed peers are accepted.
	if os.Getuid() != 0 {
		if err := lis.Open(core.IngressFunnel, "unix", sock, []int{0}); err != nil {
			t.Fatal(err)
		}
		if _, _, err := tailscaledGet(c, "http://localhost/ingress-info", nil); err == nil {
			t.Fatal("a foreign peer was accepted")
		}
		if err := lis.Open(core.IngressFunnel, "unix", sock, uids); err != nil {
			t.Fatal(err)
		}
	}

	// The TCP backend on 127.0.0.1.
	port := freePort(t)
	if err := lis.Open(core.IngressServe, "tcp4", "127.0.0.1:"+strconv.Itoa(port), uids); err != nil {
		t.Fatal(err)
	}
	tcp := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{DisableKeepAlives: true}}
	code, body, err = tailscaledGet(tcp, "http://127.0.0.1:"+strconv.Itoa(port)+"/ingress-info",
		map[string]string{"Tailscale-Funnel-Request": "", "X-Forwarded-Host": "node.tail.ts.net:8443"})
	if err != nil || code != 200 || !strings.HasPrefix(body, "kind=serve ip=203.0.113.9 public=false host=node.tail.ts.net:8443 ") {
		t.Fatalf("serve over TCP: %d %s %v", code, body, err)
	}
	if runtime.GOOS == "linux" && os.Getuid() != 0 {
		if err := lis.Open(core.IngressServe, "tcp4", "127.0.0.1:"+strconv.Itoa(port), []int{0}); err != nil {
			t.Fatal(err)
		}
		if _, _, err := tailscaledGet(tcp, "http://127.0.0.1:"+strconv.Itoa(port)+"/ingress-info",
			map[string]string{"Tailscale-Funnel-Request": ""}); err == nil {
			t.Fatal("a foreign TCP peer was accepted")
		}
	}
	lis.Close(core.IngressServe)
	if _, err := net.DialTimeout("tcp4", "127.0.0.1:"+strconv.Itoa(port), time.Second); err == nil {
		t.Fatal("serve port still open after Close")
	}
	lis.Close(core.IngressServe) // idempotent

	if err := rn.stop(t); err != nil {
		t.Fatal(err)
	}
	if fi.detached.Load() != 1 {
		t.Fatalf("Detach called %d times", fi.detached.Load())
	}
	if _, err := os.Stat(sock); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("funnel socket not removed: %v", err)
	}
	if err := lis.Open(core.IngressFunnel, "unix", sock, uids); !errors.Is(err, errShuttingDown) {
		t.Fatalf("Open after the shutdown: %v", err)
	}
}

// A Close with a request in flight lets it finish; an event stream on the
// listener ends at once.
func TestIngressCloseDrains(t *testing.T) {
	td := newDeps(t)
	fi := newFakeIngress()
	started := make(chan struct{}, 2)
	h := http.NewServeMux()
	h.HandleFunc("/slow", func(w http.ResponseWriter, r *http.Request) {
		started <- struct{}{}
		time.Sleep(300 * time.Millisecond)
		fmt.Fprint(w, "slow done")
	})
	h.HandleFunc("/events", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(200)
		http.NewResponseController(w).Flush()
		started <- struct{}{}
		<-r.Context().Done()
	})
	td.d.Ingress = fi
	m := newIngressManager(td.d, h, slog.New(slog.DiscardHandler), newErrorLog(slog.New(slog.DiscardHandler)))
	sock := filepath.Join(td.d.Home.RunDir(), "ts-funnel.sock")
	if err := m.Open(core.IngressFunnel, "unix", sock, []int{0, os.Getuid()}); err != nil {
		t.Fatal(err)
	}
	c := socketClient(sock)
	slow := make(chan string, 1)
	go func() {
		_, body, err := tailscaledGet(c, "http://localhost/slow", nil)
		if err != nil {
			body = err.Error()
		}
		slow <- body
	}()
	events, err := net.Dial("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	defer events.Close()
	fmt.Fprint(events, "GET /events HTTP/1.1\r\nHost: localhost\r\nX-Forwarded-For: 203.0.113.9\r\nX-Forwarded-Host: node.tail.ts.net\r\n\r\n")
	br := bufio.NewReader(events)
	if _, err := http.ReadResponse(br, nil); err != nil {
		t.Fatal(err)
	}
	<-started
	<-started
	began := time.Now()
	m.Close(core.IngressFunnel)
	if took := time.Since(began); took > 3*time.Second {
		t.Fatalf("Close took %v (the event stream held it)", took)
	}
	if got := <-slow; got != "slow done" {
		t.Fatalf("in-flight request: %q", got)
	}
	if _, err := os.Stat(sock); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("socket not removed")
	}
	m.drain(context.Background(), m.stop())
}

// ---------- hand-made Tailscale proxies ----------

func TestAdminSocketRefusesProxiedRequests(t *testing.T) {
	td := newDeps(t)
	start(t, td, Options{})
	c := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return DialSocket(ctx, td.d.Home.Socket())
	}}}
	get := func(hdr map[string]string) (int, string) {
		t.Helper()
		req, _ := http.NewRequest(http.MethodGet, "http://localhost/", nil)
		for k, v := range hdr {
			req.Header.Set(k, v)
		}
		resp, err := c.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, string(b)
	}
	for _, hdr := range []map[string]string{
		{"X-Forwarded-For": "203.0.113.9"}, {"X-Forwarded-Host": "node.tail.ts.net"}, {"Forwarded": "for=203.0.113.9"},
		{"Via": "1.1 tailscaled"}, {"Tailscale-User-Login": "alice@example.com"}, {"Tailscale-Funnel-Request": "?1"},
		{"tailscale-headers-info": "x"},
	} {
		code, body := get(hdr)
		if code != http.StatusForbidden || !strings.Contains(body, "does not accept proxied requests") {
			t.Errorf("%v: %d %s", hdr, code, body)
		}
	}
	// The CLI's own header passes.
	if code, body := get(map[string]string{mw.HeaderActAs: "alice"}); code != 200 || body != "hello socket:system HTTP/1.1" {
		t.Fatalf("X-FP-As: %d %s", code, body)
	}
}

func TestMainListenerRefusesFunnelHeader(t *testing.T) {
	td := newDeps(t)
	rn := start(t, td, Options{})
	before := httpx.ProxySignals.FunnelToMain.Snapshot().Count
	req, _ := http.NewRequest(http.MethodGet, rn.https+"/", nil)
	req.Header.Set("Tailscale-Funnel-Request", "?1")
	req.Host = "node.tail.ts.net:8443"
	base := rn.hits.Load()
	resp, err := rn.client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden || !strings.Contains(string(b), "tailscale serve --yes --https=8443 --set-path=") ||
		!strings.Contains(string(b), "fileparcel network funnel enable") || rn.hits.Load() != base {
		t.Fatalf("funnel header on the main port: %d %s", resp.StatusCode, b)
	}
	s := httpx.ProxySignals.FunnelToMain.Snapshot()
	if s.Count != before+1 || s.Host != "node.tail.ts.net:8443" || time.Since(s.Last) > time.Minute {
		t.Fatalf("signal %+v (before %d)", s, before)
	}
	// Without the header: the normal chain.
	resp, err = rn.client.Get(rn.https + "/")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("plain request: %d", resp.StatusCode)
	}

	// From a peer that is not loopback (a Funnel on another tailnet node
	// pointed at this server): refused the same way.
	var reached bool
	root := httpsRoot(td.d, http.HandlerFunc(func(http.ResponseWriter, *http.Request) { reached = true }),
		listenConfig{httpsPort: 8443}, slog.New(slog.DiscardHandler))
	r := httptest.NewRequest(http.MethodGet, "https://fileparcel.local/", nil)
	r.RemoteAddr = "100.101.102.104:40000"
	r.Header.Set("Tailscale-Funnel-Request", "?1")
	rec := httptest.NewRecorder()
	root.ServeHTTP(rec, r)
	if rec.Code != http.StatusForbidden || reached || !strings.Contains(rec.Body.String(), "--https=443 --set-path=") {
		t.Fatalf("remote peer: %d %s", rec.Code, rec.Body.String())
	}
	if got := httpx.ProxySignals.FunnelToMain.Snapshot().Count; got != before+2 {
		t.Fatalf("signal count %d", got)
	}

	// Any other client can send the header itself: it is refused, but it
	// raises no alarm (no doctor failure whose hint would remove
	// FileParcel's own entries).
	r = httptest.NewRequest(http.MethodGet, "https://fileparcel.local/", nil)
	r.RemoteAddr = "192.0.2.77:40000"
	r.Host = "node.tail.ts.net:443"
	r.Header.Set("Tailscale-Funnel-Request", "?1")
	rec = httptest.NewRecorder()
	root.ServeHTTP(rec, r)
	if rec.Code != http.StatusForbidden || reached {
		t.Fatalf("forged header: %d %s", rec.Code, rec.Body.String())
	}
	if got := httpx.ProxySignals.FunnelToMain.Snapshot().Count; got != before+2 {
		t.Fatalf("a forged header counted: %d", got)
	}
}
