package tsingress

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"

	"fileparcel/internal/core"
)

// probeServer is tailscaled's TLS front for node.tail.ts.net: it answers
// the probe path like the ingress handler (204 for the nonce in flight).
func probeServer(t *testing.T, h *harness, status int, trusted bool) {
	t.Helper()
	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	caTmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test CA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true,
		BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	ca, _ := x509.ParseCertificate(caDER)
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	leafTmpl := &x509.Certificate{SerialNumber: big.NewInt(2), DNSNames: []string{"node.tail.ts.net"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, ca, &key.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nonce, ok := strings.CutPrefix(r.URL.Path, ProbePath)
		switch {
		case status != http.StatusNoContent:
			w.WriteHeader(status)
		case ok && r.Host == "node.tail.ts.net" && h.s.CheckProbe(core.IngressFunnel, nonce):
			w.WriteHeader(http.StatusNoContent)
		default:
			http.NotFound(w, r)
		}
	}))
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{leafDER}, PrivateKey: key}}}
	srv.Config.ErrorLog = log.New(io.Discard, "", 0) // the untrusted first attempt logs a handshake error
	srv.StartTLS()
	t.Cleanup(srv.Close)
	addr := srv.Listener.Addr().String()
	h.s.probeDial = func(ctx context.Context, network, want string) (net.Conn, error) {
		if want != "100.101.102.103:443" {
			t.Errorf("probe dialled %s", want)
		}
		return (&net.Dialer{}).DialContext(ctx, network, addr)
	}
	if trusted {
		pool := x509.NewCertPool()
		pool.AddCert(ca)
		h.s.probeRoots = pool
	} else {
		h.s.probeRoots = x509.NewCertPool() // trusts nothing: issuance pending
	}
	h.s.localAddr = func(ip netip.Addr) bool { return ip == netip.MustParseAddr("100.101.102.103") }
}

func TestProbe(t *testing.T) {
	for _, tc := range []struct {
		name    string
		status  int
		trusted bool
		want    string
		text    string
	}{
		{"reachable", http.StatusNoContent, true, statusOK, "reached FileParcel"},
		{"certificate pending", http.StatusNoContent, false, statusWarn, "not trusted yet"},
		{"bad gateway", http.StatusBadGateway, true, statusWarn, "cannot reach FileParcel's backend unix:"},
		{"other", http.StatusNotFound, true, statusWarn, "HTTP 404"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t)
			probeServer(t, h, tc.status, tc.trusted)
			h.s.t.probeDelay = time.Millisecond
			h.attach()
			h.enable(core.FunnelShares)
			var c *core.IngressCheck
			for deadline := time.Now().Add(10 * time.Second); time.Now().Before(deadline); time.Sleep(10 * time.Millisecond) {
				h.s.stMu.Lock()
				c = h.s.kst[0].reachable
				h.s.stMu.Unlock()
				if c != nil {
					break
				}
			}
			if c == nil || c.Status != tc.want || !strings.Contains(c.Message, tc.text) {
				t.Fatalf("probe %+v", c)
			}
			st := h.status()
			found := false
			for _, ch := range st.Funnel.Checks {
				found = found || ch.ID == checkReachable && ch.Status == tc.want
			}
			if !found || st.Funnel.ProbedAt == nil {
				t.Fatalf("status checks %+v", st.Funnel.Checks)
			}
			// The nonce is gone after the probe.
			if h.s.nonce[0].Load() != nil {
				t.Fatal("nonce left")
			}
			// A failed probe is retried later.
			h.s.stMu.Lock()
			retry := h.s.probeTimers[0] != nil
			h.s.stMu.Unlock()
			if retry != (tc.want == statusWarn) {
				t.Fatalf("retry scheduled %v", retry)
			}
		})
	}
}

// Without a local interface carrying the Tailscale address (userspace
// networking, containers, test fakes) the probe is skipped.
func TestProbeSkippedWithoutLocalAddress(t *testing.T) {
	h := newHarness(t)
	h.attach()
	h.enable(core.FunnelShares)
	c := h.s.probe(context.Background(), core.IngressFunnel, "unix:/x")
	if c.Status != statusSkip || !strings.Contains(c.Message, "Cannot be tested from this machine") {
		t.Fatalf("%+v", c)
	}
	if c := h.s.probe(context.Background(), core.IngressServe, ""); c.Status != statusSkip || c.Message != "Not published" {
		t.Fatalf("%+v", c)
	}
	// Status(refresh) re-runs it and waits.
	h.s.stMu.Lock()
	h.s.kst[0].reachable = nil
	h.s.stMu.Unlock()
	st, _ := h.s.Status(context.Background(), true)
	if st.Funnel.ProbedAt == nil {
		t.Fatalf("refresh did not probe: %+v", st.Funnel)
	}
}

func TestCheckProbeNonce(t *testing.T) {
	h := newHarness(t)
	h.s.nonce[0].Store(&probeNonce{value: "abcdef", expires: h.clock().Add(2 * time.Minute)})
	if !h.s.CheckProbe(core.IngressFunnel, "abcdef") {
		t.Fatal("valid nonce refused")
	}
	for _, tc := range []struct{ kind, nonce string }{
		{core.IngressFunnel, "abcdeg"}, {core.IngressFunnel, ""}, {core.IngressServe, "abcdef"}, {"x", "abcdef"},
	} {
		if h.s.CheckProbe(tc.kind, tc.nonce) {
			t.Fatalf("accepted %+v", tc)
		}
	}
	h.advance(3 * time.Minute)
	if h.s.CheckProbe(core.IngressFunnel, "abcdef") {
		t.Fatal("expired nonce accepted")
	}
}
