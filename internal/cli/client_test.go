package cli

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"fileparcel/internal/config"
	"fileparcel/internal/core"
	"fileparcel/internal/home"
)

func testHome(t *testing.T) *home.Home {
	t.Helper()
	h, _ := home.New(t.TempDir())
	if err := h.EnsureLayout(); err != nil {
		t.Fatal(err)
	}
	if err := config.Default(config.NewInstallID()).SaveTo(h.Config()); err != nil {
		t.Fatal(err)
	}
	return h
}

func TestConnectOffline(t *testing.T) {
	h := testHome(t)
	c, err := Connect(Options{Home: h.Dir()})
	if err != nil {
		t.Fatal(err)
	}
	if c.Mode() != ModeOffline || c.Deps() == nil {
		t.Fatalf("mode %s", c.Mode())
	}
	ctx := context.Background()
	err = c.Do(ctx, "GET", "/api/v1/no-such-endpoint", nil, nil)
	var ce *core.Error
	if !errors.As(err, &ce) || ce.Code != "not_found" || ce.Status != 404 {
		t.Fatalf("got %v", err)
	}
	// Unsafe method with the system principal passes CSRF (exempt) and reaches routing.
	err = c.Do(ctx, "POST", "/api/v1/no-such-endpoint", map[string]string{"a": "b"}, nil)
	if !errors.As(err, &ce) || ce.Code != "not_found" {
		t.Fatalf("POST got %v", err)
	}
	resp, err := c.Stream(ctx, "GET", "/healthz", nil, http.Header{"X-Test": {"1"}})
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if strings.TrimSpace(string(body)) != "ok" {
		t.Fatalf("healthz body %q", body)
	}

	// While the offline client holds the lock, a second one cannot start.
	if _, err := Connect(Options{Home: h.Dir()}); err == nil || !strings.Contains(err.Error(), "doctor") {
		t.Fatalf("second connect: %v", err)
	}
	if _, err := Connect(Options{Home: h.Dir(), Offline: true}); err == nil {
		t.Fatal("forced offline connect while locked")
	}
	c.Close()
	c.Close()
	c2, err := Connect(Options{Home: h.Dir(), Offline: true})
	if err != nil {
		t.Fatalf("reconnect after close: %v", err)
	}
	c2.Close()
}

func TestConnectErrors(t *testing.T) {
	if _, err := Connect(Options{Home: t.TempDir()}); err == nil || !strings.Contains(err.Error(), "fileparcel init") {
		t.Fatalf("uninitialised home: %v", err)
	}
	if _, err := Connect(Options{Server: "https://example.invalid"}); err == nil {
		t.Fatal("remote without token")
	}
	if _, err := Connect(Options{Server: "https://example.invalid", Token: "x", As: "bob"}); err == nil {
		t.Fatal("--as with remote")
	}
	if _, err := Connect(Options{Server: "https://example.invalid", Token: "x", Fingerprint: "zz"}); err == nil {
		t.Fatal("bad fingerprint")
	}
	c, err := Connect(Options{Server: "https://example.invalid/", Token: "x",
		Fingerprint: strings.Repeat("AB:", 31) + "AB"})
	if err != nil || c.Mode() != ModeRemote {
		t.Fatalf("remote: %v", err)
	}
	c.Close()
	if fp, err := normalizeFingerprint("sha256:" + strings.Repeat("Ab", 32)); err != nil || fp != strings.Repeat("ab", 32) {
		t.Fatal(fp, err)
	}
}

func TestVersionCommand(t *testing.T) {
	root := NewRootCmd()
	var out strings.Builder
	root.SetOut(&out)
	root.SetArgs([]string{"version"})
	if err := root.Execute(); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(out.String(), "FileParcel ") {
		t.Fatalf("%q", out.String())
	}
}

// ---------- --fingerprint pinning ----------

type pinKP struct {
	der  []byte
	key  *ecdsa.PrivateKey
	cert *x509.Certificate
}

// pinMake issues tmpl, self-signed when parent is nil.
func pinMake(t *testing.T, tmpl *x509.Certificate, parent *pinKP) *pinKP {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, pcert := any(key), tmpl
	if parent != nil {
		signer, pcert = parent.key, parent.cert
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, pcert, &key.PublicKey, signer)
	if err != nil {
		t.Fatal(err)
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return &pinKP{der: der, key: key, cert: c}
}

func pinCATmpl(cn string) *x509.Certificate {
	return &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
}

func pinLeafTmpl(hosts ...string) *x509.Certificate {
	c := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano() + 1),
		Subject:               pkix.Name{CommonName: "fileparcel"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	for _, h := range hosts {
		if ip := net.ParseIP(h); ip != nil {
			c.IPAddresses = append(c.IPAddresses, ip)
		} else {
			c.DNSNames = append(c.DNSNames, h)
		}
	}
	return c
}

func pinFP(der []byte) string { s := sha256.Sum256(der); return hex.EncodeToString(s[:]) }

// pinServe starts a TLS server presenting exactly the given DER chain and
// records the Authorization header of the first request that reaches it.
func pinServe(t *testing.T, key *ecdsa.PrivateKey, chain [][]byte, seen *string) *httptest.Server {
	t.Helper()
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if *seen == "" {
			*seen = r.Header.Get("Authorization")
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{{Certificate: chain, PrivateKey: key}}}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv
}

// pinTry runs one pinned request and returns its error (nil = the CLI trusted
// the server and sent the token).
func pinTry(t *testing.T, srv *httptest.Server, pin string) error {
	t.Helper()
	c, err := Connect(Options{Server: srv.URL, Token: "fpt_secret_token", Fingerprint: pin})
	if err != nil {
		return err
	}
	defer c.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return c.Do(ctx, http.MethodGet, "/api/v1/system/status", nil, nil)
}

// TestPinRejectsAppendedCA: the pinned certificate is a trust anchor, not just
// a chain member. The local CA certificate is public (/trust/ca.crt), so an
// attacker can append it to a chain headed by its own self-signed leaf.
func TestPinRejectsAppendedCA(t *testing.T) {
	ca := pinMake(t, pinCATmpl("FileParcel Local CA"), nil)       // genuine, public CA cert
	atk := pinMake(t, pinLeafTmpl("127.0.0.1", "localhost"), nil) // attacker, self-signed

	var auth string
	srv := pinServe(t, atk.key, [][]byte{atk.der, ca.der}, &auth)
	if err := pinTry(t, srv, pinFP(ca.der)); err == nil {
		t.Fatalf("pin bypassed: attacker leaf accepted because the public CA was appended (token leaked as %q)", auth)
	}
	if auth != "" {
		t.Fatalf("token sent to an untrusted server: %q", auth)
	}

	// The same trick with a genuine leaf appended instead of the CA.
	good := pinMake(t, pinLeafTmpl("127.0.0.1", "localhost"), ca)
	auth = ""
	srv2 := pinServe(t, atk.key, [][]byte{atk.der, good.der}, &auth)
	if err := pinTry(t, srv2, pinFP(good.der)); err == nil {
		t.Fatalf("pin bypassed: attacker leaf accepted with the pinned leaf appended (token leaked as %q)", auth)
	}
}

// TestPinRejectsUnrelatedCert: a bare attacker leaf, and a chain signed by a
// CA other than the pinned one, are rejected.
func TestPinRejectsUnrelatedCert(t *testing.T) {
	ca := pinMake(t, pinCATmpl("FileParcel Local CA"), nil)
	atk := pinMake(t, pinLeafTmpl("127.0.0.1", "localhost"), nil)
	var auth string
	srv := pinServe(t, atk.key, [][]byte{atk.der}, &auth)
	if err := pinTry(t, srv, pinFP(ca.der)); err == nil {
		t.Fatalf("bare attacker leaf accepted (token leaked as %q)", auth)
	}

	other := pinMake(t, pinCATmpl("Other CA"), nil)
	leaf := pinMake(t, pinLeafTmpl("127.0.0.1", "localhost"), other)
	auth = ""
	srv2 := pinServe(t, leaf.key, [][]byte{leaf.der, other.der}, &auth)
	if err := pinTry(t, srv2, pinFP(ca.der)); err == nil {
		t.Fatalf("chain under an unpinned CA accepted (token leaked as %q)", auth)
	}
}

// TestPinRejectsWrongHostname: signed by the pinned CA, but not for the host
// the CLI dialed.
func TestPinRejectsWrongHostname(t *testing.T) {
	ca := pinMake(t, pinCATmpl("FileParcel Local CA"), nil)
	leaf := pinMake(t, pinLeafTmpl("evil.example"), ca)
	var auth string
	srv := pinServe(t, leaf.key, [][]byte{leaf.der, ca.der}, &auth)
	err := pinTry(t, srv, pinFP(ca.der))
	if err == nil {
		t.Fatalf("leaf without a SAN for the dialed host accepted (token leaked as %q)", auth)
	}
	if !strings.Contains(err.Error(), "pinned certificate") {
		t.Fatalf("unexpected error: %v", err)
	}
}

// TestPinAcceptsGenuine: the honest paths keep working — a leaf issued by the
// pinned CA, and pinning the leaf itself (which needs no hostname match: the
// handshake proves possession of exactly that certificate's key, so an SSH
// tunnel or an alternative name still works).
func TestPinAcceptsGenuine(t *testing.T) {
	ca := pinMake(t, pinCATmpl("FileParcel Local CA"), nil)
	leaf := pinMake(t, pinLeafTmpl("127.0.0.1", "localhost"), ca)

	var auth string
	srv := pinServe(t, leaf.key, [][]byte{leaf.der, ca.der}, &auth)
	if err := pinTry(t, srv, pinFP(ca.der)); err != nil {
		t.Fatalf("genuine chain rejected: %v", err)
	}
	if auth != "Bearer fpt_secret_token" {
		t.Fatalf("token not sent: %q", auth)
	}
	if err := pinTry(t, srv, pinFP(leaf.der)); err != nil {
		t.Fatalf("leaf pin rejected: %v", err)
	}

	// Leaf pin, chain of one, no SAN for the dialed address (tunnel case).
	tun := pinMake(t, pinLeafTmpl("fileparcel.example"), ca)
	auth = ""
	srv2 := pinServe(t, tun.key, [][]byte{tun.der}, &auth)
	if err := pinTry(t, srv2, pinFP(tun.der)); err != nil {
		t.Fatalf("leaf pin through a tunnel rejected: %v", err)
	}
}

// pinPEM encodes certificates as a PEM bundle (a --ca-file).
func pinPEM(certs ...*pinKP) []byte {
	var b []byte
	for _, c := range certs {
		b = append(b, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.der})...)
	}
	return b
}

// pinTryCA is pinTry with a --ca-file as well.
func pinTryCA(t *testing.T, srv *httptest.Server, bundle []byte, pin string) error {
	t.Helper()
	f := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(f, bundle, 0o600); err != nil {
		t.Fatal(err)
	}
	c, err := Connect(Options{Server: srv.URL, Token: "fpt_secret_token", CAFile: f, Fingerprint: pin})
	if err != nil {
		return err
	}
	defer c.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return c.Do(ctx, http.MethodGet, "/api/v1/system/status", nil, nil)
}

// TestPinWithCAFileRejectsAppendedCert: with --ca-file the pin constrains
// the verified chain. A certificate the peer merely appends (the genuine
// leaf, or the public local CA) does not satisfy it for a leaf that another
// CA in the bundle issued.
func TestPinWithCAFileRejectsAppendedCert(t *testing.T) {
	corp := pinMake(t, pinCATmpl("Corp CA"), nil)
	fpca := pinMake(t, pinCATmpl("FileParcel Local CA"), nil)
	bundle := pinPEM(corp, fpca)
	genuine := pinMake(t, pinLeafTmpl("127.0.0.1", "localhost"), fpca)
	atk := pinMake(t, pinLeafTmpl("127.0.0.1", "localhost"), corp)
	for name, c := range map[string]struct {
		chain [][]byte
		pin   string
	}{
		"genuine leaf appended":    {[][]byte{atk.der, genuine.der}, pinFP(genuine.der)},
		"FileParcel CA appended":   {[][]byte{atk.der, fpca.der}, pinFP(fpca.der)},
		"attacker leaf, CA pinned": {[][]byte{atk.der}, pinFP(fpca.der)},
	} {
		var auth string
		srv := pinServe(t, atk.key, c.chain, &auth)
		if err := pinTryCA(t, srv, bundle, c.pin); err == nil {
			t.Errorf("%s: pin bypassed (token leaked as %q)", name, auth)
		}
		if auth != "" {
			t.Errorf("%s: token sent to an unpinned server: %q", name, auth)
		}
	}
}

// TestPinWithCAFileAcceptsGenuine: pinning the leaf, a CA the server sends,
// or a --ca-file root the server does not send all work.
func TestPinWithCAFileAcceptsGenuine(t *testing.T) {
	fpca := pinMake(t, pinCATmpl("FileParcel Local CA"), nil)
	leaf := pinMake(t, pinLeafTmpl("127.0.0.1", "localhost"), fpca)
	bundle := pinPEM(fpca)
	var auth string
	withCA := pinServe(t, leaf.key, [][]byte{leaf.der, fpca.der}, &auth)
	leafOnly := pinServe(t, leaf.key, [][]byte{leaf.der}, &auth)
	for name, c := range map[string]struct {
		srv *httptest.Server
		pin string
	}{
		"leaf pinned":          {withCA, pinFP(leaf.der)},
		"CA pinned, CA sent":   {withCA, pinFP(fpca.der)},
		"CA pinned, leaf only": {leafOnly, pinFP(fpca.der)},
	} {
		auth = ""
		if err := pinTryCA(t, c.srv, bundle, c.pin); err != nil {
			t.Errorf("%s: rejected: %v", name, err)
		}
		if auth != "Bearer fpt_secret_token" {
			t.Errorf("%s: token not sent: %q", name, auth)
		}
	}
}

// A plain http:// --server would put the token (and bodies such as a
// passphrase) on the wire in cleartext before the server's redirect to
// https: refused, except for a loopback host.
func TestRemoteRefusesPlainHTTP(t *testing.T) {
	for _, u := range []string{"http://example.invalid", "http://192.168.1.10:8443", "http://nas.local:8443"} {
		_, err := Connect(Options{Server: u, Token: "x"})
		var ee *ExitCodeError
		if !errors.As(err, &ee) || ee.Code != ExitUsage || !strings.Contains(err.Error(), "https://") {
			t.Errorf("%s: %v", u, err)
		}
	}
	for _, u := range []string{"http://127.0.0.1:1", "http://localhost:1", "http://[::1]:1"} {
		c, err := Connect(Options{Server: u, Token: "x"})
		if err != nil || c.Mode() != ModeRemote {
			t.Errorf("%s: %v", u, err)
			continue
		}
		c.Close()
	}
	if _, err := Connect(Options{Server: "http://127.0.0.1:1", Token: "x", Fingerprint: strings.Repeat("ab", 32)}); err == nil {
		t.Error("--fingerprint with an http:// URL accepted")
	}
	res := runArgs(t, "", "--server", "http://nas.example:8443", "--token", "fpt_x", "status")
	if res.code != ExitUsage || !strings.Contains(res.stderr, "https://") {
		t.Errorf("CLI: %+v", res)
	}
}

// The REST API never redirects; the remote client must not follow one to
// another server, which would resend a 307/308 body (a passphrase) there.
func TestRemoteRefusesForeignRedirect(t *testing.T) {
	var got []string
	var mu sync.Mutex
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		mu.Lock()
		got = append(got, r.Header.Get("Authorization")+" "+string(b))
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{}`))
	}))
	defer other.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, other.URL+r.URL.Path, http.StatusPermanentRedirect)
	}))
	defer srv.Close()
	c, err := Connect(Options{Server: srv.URL, Token: "fpt_secret_token"})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	err = c.Do(context.Background(), http.MethodPost, "/api/v1/system/unlock", map[string]string{"passphrase": "hunter2"}, nil)
	if err == nil || !strings.Contains(err.Error(), "refusing to follow a redirect") {
		t.Fatalf("redirect followed: %v", err)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(got) != 0 {
		t.Fatalf("the other server received %q", got)
	}
}
