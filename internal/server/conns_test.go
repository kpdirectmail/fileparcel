package server

import (
	"crypto/tls"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"os"
	"sync/atomic"
	"testing"
	"time"
)

// openStream opens /events and returns a channel that receives the error
// ending its body (nil: the server ended it cleanly).
func openStream(t *testing.T, c *http.Client, url, proto string) <-chan error {
	t.Helper()
	resp, err := c.Get(url + "/events")
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK || resp.Proto != proto {
		t.Fatalf("event stream: %d %s, want 200 %s", resp.StatusCode, resp.Proto, proto)
	}
	t.Cleanup(func() { resp.Body.Close() })
	ended := make(chan error, 1)
	go func() {
		_, err := io.Copy(io.Discard, resp.Body)
		ended <- err
	}()
	return ended
}

// http1Client is rn.client restricted to HTTP/1.1 (keep-alive connections).
func http1Client(rn *running) *http.Client {
	tc := rn.client.Transport.(*http.Transport).TLSClientConfig.Clone()
	tc.NextProtos = nil // the HTTP/2 transport added "h2"
	p := new(http.Protocols)
	p.SetHTTP1(true)
	return &http.Client{Transport: &http.Transport{TLSClientConfig: tc, Protocols: p}, Timeout: 10 * time.Second}
}

func getOK(t *testing.T, c *http.Client, url, proto string) {
	t.Helper()
	resp, err := c.Get(url + "/")
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || resp.Proto != proto {
		t.Fatalf("GET /: %d %s, want 200 %s", resp.StatusCode, resp.Proto, proto)
	}
}

func waitEnded(t *testing.T, what string, ended <-chan error, within time.Duration) {
	t.Helper()
	select {
	case <-ended:
	case <-time.After(within):
		t.Fatalf("%s still open after the access policy stopped admitting its peer", what)
	}
}

// A device denied after it connected loses its open connections: idle
// keep-alive connections and event streams (the sweep), and any connection
// it sends another request on (the request guard) — nothing more is served.
func TestRunPolicyChangeClosesOpenConnections(t *testing.T) {
	old := policySweepEvery
	policySweepEvery = 50 * time.Millisecond
	t.Cleanup(func() { policySweepEvery = old })
	td := newDeps(t)
	rn := start(t, td, Options{})
	h1 := http1Client(rn)

	h2Stream := openStream(t, rn.client, rn.https, "HTTP/2.0")
	h1Stream := openStream(t, h1, rn.https, "HTTP/1.1")
	getOK(t, h1, rn.https, "HTTP/1.1") // leaves an idle keep-alive connection
	// Sweeps under an unchanged policy keep everything open.
	time.Sleep(4 * policySweepEvery)
	getOK(t, rn.client, rn.https, "HTTP/2.0")
	getOK(t, h1, rn.https, "HTTP/1.1")
	select {
	case err := <-h2Stream:
		t.Fatalf("HTTP/2 event stream closed while allowed: %v", err)
	case err := <-h1Stream:
		t.Fatalf("HTTP/1.1 event stream closed while allowed: %v", err)
	default:
	}

	td.net.deny.Store(true)
	before := rn.hits.Load()
	waitEnded(t, "HTTP/2 event stream", h2Stream, 3*time.Second)
	waitEnded(t, "HTTP/1.1 event stream", h1Stream, 3*time.Second)
	for name, c := range map[string]*http.Client{"HTTP/2": rn.client, "HTTP/1.1": h1} {
		if resp, err := c.Get(rn.https + "/"); err == nil {
			resp.Body.Close()
			t.Fatalf("%s: denied peer served: %d", name, resp.StatusCode)
		}
	}
	if rn.hits.Load() != before {
		t.Fatal("a denied peer reached the handler over an open connection")
	}

	td.net.deny.Store(false)
	getOK(t, rn.client, rn.https, "HTTP/2.0")
}

// Without waiting for a sweep, the first request over an open connection
// after the policy changed is refused and takes the whole connection down,
// with the event stream it carries.
func TestRunPolicyGuardRefusesRequestsOnOpenConnection(t *testing.T) {
	old := policySweepEvery
	policySweepEvery = time.Hour
	t.Cleanup(func() { policySweepEvery = old })
	td := newDeps(t)
	rn := start(t, td, Options{})
	stream := openStream(t, rn.client, rn.https, "HTTP/2.0")
	getOK(t, rn.client, rn.https, "HTTP/2.0")

	td.net.deny.Store(true)
	before := rn.hits.Load()
	if resp, err := rn.client.Get(rn.https + "/"); err == nil {
		resp.Body.Close()
		t.Fatalf("denied peer served over its open HTTP/2 connection: %d", resp.StatusCode)
	}
	if rn.hits.Load() != before {
		t.Fatal("the refused request reached the handler")
	}
	waitEnded(t, "event stream on the refused connection", stream, 3*time.Second)
}

// tcpPair returns both ends of a loopback TCP connection.
func tcpPair(t *testing.T) (server, client net.Conn) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	client, err = net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	server, err = ln.Accept()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { server.Close(); client.Close() })
	return server, client
}

// closedByPeer reports whether c was closed by the other side (EOF or reset)
// rather than merely idle.
func closedByPeer(c net.Conn) bool {
	_ = c.SetReadDeadline(time.Now().Add(time.Second))
	_, err := c.Read(make([]byte, 1))
	return err != nil && !errors.Is(err, os.ErrDeadlineExceeded)
}

func TestConnTrackerStateNewAndSweep(t *testing.T) {
	var deny atomic.Bool
	tr := newConnTracker(func(netip.Addr) bool { return !deny.Load() }, newDenyLog(slog.New(slog.DiscardHandler)))
	tracked := func() int { tr.mu.Lock(); defer tr.mu.Unlock(); return len(tr.conns) }

	// The policy changed between Accept and the server taking the
	// connection over (it waited in the TLS sniff): closed at StateNew.
	s1, c1 := tcpPair(t)
	deny.Store(true)
	tr.connState(s1, http.StateNew)
	if !closedByPeer(c1) || tracked() != 0 {
		t.Fatalf("connection refused at StateNew: closed=%v tracked=%d", !closedByPeer(c1), tracked())
	}

	// An allowed connection (as the mux listener hands it out) is tracked,
	// survives sweeps while allowed and is closed by the first sweep after.
	deny.Store(false)
	s2, c2 := tcpPair(t)
	tlsConn := tls.Server(&prefixConn{Conn: s2}, &tls.Config{})
	tr.connState(tlsConn, http.StateNew)
	tr.sweep()
	if tracked() != 1 || closedByPeer(c2) {
		t.Fatalf("allowed connection: tracked=%d or closed", tracked())
	}
	deny.Store(true)
	tr.sweep()
	if !closedByPeer(c2) {
		t.Fatal("sweep kept a connection the policy no longer admits")
	}
	tr.connState(tlsConn, http.StateClosed)
	if tracked() != 0 {
		t.Fatal("closed connection still tracked")
	}

	// rawConn unwraps what the mux listener produces.
	s3, _ := tcpPair(t)
	for _, c := range []net.Conn{s3, &prefixConn{Conn: s3}, tls.Server(&prefixConn{Conn: s3}, &tls.Config{})} {
		if rawConn(c) != s3 {
			t.Fatalf("rawConn(%T) is not the TCP connection", c)
		}
	}
}
