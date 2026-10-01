package server

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"net/netip"
	"sync"
	"time"
)

// policySweepEvery is how often the open HTTPS connections are checked
// against the access policy again (a variable for tests).
var policySweepEvery = 2 * time.Second

// connTracker applies the access policy (DESIGN §10.3) to connections that
// are already open, not only at Accept: browsers keep an HTTP/2 connection
// (with its event stream) open indefinitely, so a device denied — or no
// longer allowed — after it connected would otherwise keep using it. It is
// the HTTPS server's ConnState and ConnContext hook plus a request guard:
//
//   - a connection whose peer is no longer allowed by the time the server
//     takes it over (it was accepted, then waited in the TLS sniff) is
//     closed at StateNew;
//   - every request is checked first; a refused one closes its whole
//     connection before anything is served;
//   - sweep, run every policySweepEvery, closes idle connections and open
//     event streams and downloads of peers the policy no longer admits.
//
// Closing the connection cancels the request contexts on it, which ends
// the event streams. The admin socket (no IP) and the HTTP redirect port
// (Connection: close on every answer) are not tracked.
type connTracker struct {
	allowed func(netip.Addr) bool
	deny    *denyLog

	mu    sync.Mutex
	conns map[net.Conn]netip.Addr
}

func newConnTracker(allowed func(netip.Addr) bool, deny *denyLog) *connTracker {
	return &connTracker{allowed: allowed, deny: deny, conns: map[net.Conn]netip.Addr{}}
}

// connKey carries the accepted connection in the request context.
type connKey struct{}

// connContext is http.Server.ConnContext: it lets guard close the
// connection a refused request came over.
func (t *connTracker) connContext(ctx context.Context, c net.Conn) context.Context {
	return context.WithValue(ctx, connKey{}, c)
}

// connState is http.Server.ConnState.
func (t *connTracker) connState(c net.Conn, st http.ConnState) {
	switch st {
	case http.StateNew:
		ip := remoteIP(c)
		if ip.IsValid() && !t.allowed(ip) {
			t.drop(c, ip)
			return
		}
		t.mu.Lock()
		t.conns[c] = ip
		t.mu.Unlock()
	case http.StateClosed, http.StateHijacked:
		t.mu.Lock()
		delete(t.conns, c)
		t.mu.Unlock()
	}
}

// guard refuses requests from peers the access policy no longer admits and
// closes their connection (like refuse at Accept: no answer, a TCP reset).
// r.RemoteAddr is still the TCP peer here: the client-IP middleware of the
// router runs later.
func (t *connTracker) guard(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if ap, err := netip.ParseAddrPort(r.RemoteAddr); err == nil {
			if ip := ap.Addr().Unmap().WithZone(""); !t.allowed(ip) {
				if c, ok := r.Context().Value(connKey{}).(net.Conn); ok {
					t.drop(c, ip)
				}
				panic(http.ErrAbortHandler) // no response; HTTP/2 resets the stream
			}
		}
		next.ServeHTTP(w, r)
	})
}

// sweep closes every tracked connection whose peer is no longer allowed.
func (t *connTracker) sweep() {
	type refused struct {
		c  net.Conn
		ip netip.Addr
	}
	var drop []refused
	t.mu.Lock()
	for c, ip := range t.conns {
		if ip.IsValid() && !t.allowed(ip) {
			drop = append(drop, refused{c, ip})
		}
	}
	t.mu.Unlock()
	for _, x := range drop {
		t.drop(x.c, x.ip)
	}
}

// run sweeps every interval until ctx ends.
func (t *connTracker) run(ctx context.Context, every time.Duration) {
	tk := time.NewTicker(every)
	defer tk.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tk.C:
			t.sweep()
		}
	}
}

// drop closes the TCP connection under c with a reset. Closing the raw
// connection, not the *tls.Conn, never waits for a close_notify alert to
// be written to a peer that does not read. net/http notices the closed
// connection, cancels its requests and reports StateClosed.
func (t *connTracker) drop(c net.Conn, ip netip.Addr) {
	refuse(rawConn(c), ip, t.deny)
}

// rawConn returns the TCP connection under a connection of the mux listener
// (*tls.Conn over *prefixConn, or a plain *prefixConn).
func rawConn(c net.Conn) net.Conn {
	if tc, ok := c.(*tls.Conn); ok {
		c = tc.NetConn()
	}
	if pc, ok := c.(*prefixConn); ok {
		c = pc.Conn
	}
	return c
}
