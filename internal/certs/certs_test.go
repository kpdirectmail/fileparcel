package certs

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/caddyserver/certmagic"

	"fileparcel/internal/core"
	"fileparcel/internal/events"
	"fileparcel/internal/settings"
)

// ---------- helpers ----------

// testCA is an independent CA for custom/Tailscale/ACME test certificates.
type testCA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
}

func newTestCA(t *testing.T, cn string) *testCA {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: cn},
		NotBefore: time.Now().Add(-48 * time.Hour), NotAfter: time.Now().Add(10 * 365 * 24 * time.Hour),
		KeyUsage: x509.KeyUsageCertSign, BasicConstraintsValid: true, IsCA: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	c, _ := x509.ParseCertificate(der)
	return &testCA{cert: c, key: key}
}

type leafOpts struct {
	names     []string
	notBefore time.Time
	notAfter  time.Time
	eku       []x509.ExtKeyUsage
	isCA      bool
}

// leaf issues a certificate; returns chain PEM (leaf + CA), key PEM and the leaf.
func (ca *testCA) leaf(t *testing.T, o leafOpts) (certPEMData, keyPEMData []byte, leaf *x509.Certificate) {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if o.notBefore.IsZero() {
		o.notBefore = time.Now().Add(-time.Hour)
	}
	if o.notAfter.IsZero() {
		o.notAfter = time.Now().Add(90 * 24 * time.Hour)
	}
	if o.eku == nil {
		o.eku = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
	}
	serial, _ := newSerial()
	tmpl := &x509.Certificate{
		SerialNumber: serial, Subject: pkix.Name{CommonName: "test"},
		NotBefore: o.notBefore, NotAfter: o.notAfter, KeyUsage: x509.KeyUsageDigitalSignature,
		ExtKeyUsage: o.eku, BasicConstraintsValid: true, IsCA: o.isCA,
	}
	for _, n := range o.names {
		if ip := net.ParseIP(n); ip != nil {
			tmpl.IPAddresses = append(tmpl.IPAddresses, ip)
		} else {
			tmpl.DNSNames = append(tmpl.DNSNames, n)
		}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, key.Public(), ca.key)
	if err != nil {
		t.Fatal(err)
	}
	leaf, _ = x509.ParseCertificate(der)
	kd, _ := x509.MarshalPKCS8PrivateKey(key)
	certPEMData = append(certPEM(der), certPEM(ca.cert.Raw)...)
	keyPEMData = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: kd})
	return certPEMData, keyPEMData, leaf
}

// handshake runs a TLS handshake against svc's server configuration over an
// in-memory pipe and returns the client's view.
func handshake(t *testing.T, svc *Service, conf *tls.Config) (tls.ConnectionState, error) {
	t.Helper()
	cc, sc := net.Pipe()
	defer cc.Close()
	defer sc.Close()
	deadline := time.Now().Add(10 * time.Second)
	_ = cc.SetDeadline(deadline)
	_ = sc.SetDeadline(deadline)
	srv := tls.Server(sc, svc.TLSConfig())
	done := make(chan error, 1)
	go func() {
		err := srv.Handshake()
		if err != nil {
			sc.Close()
		}
		done <- err
	}()
	cli := tls.Client(cc, conf)
	err := cli.Handshake()
	if err != nil {
		cc.Close()
	} else {
		// Drain post-handshake records (tickets, alerts) so the server's
		// writes on the synchronous pipe never block.
		go func() { _, _ = io.Copy(io.Discard, cli) }()
	}
	serr := <-done
	if err == nil {
		err = serr
	}
	return cli.ConnectionState(), err
}

func caPool(c ...*x509.Certificate) *x509.CertPool { return poolOf(c...) }

func mustStat(t *testing.T, path string) os.FileInfo {
	t.Helper()
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	return fi
}

// ---------- CA + leaf ----------

func TestInitCreatesCAClientCAAndLeaf(t *testing.T) {
	te := newTestEnv(t)
	svc := te.initService(t)
	st := svc.snapshot()
	if st.ca == nil || st.clientCA == nil || st.leaf == nil {
		t.Fatal("Init did not create every certificate")
	}
	ca := st.ca
	if !ca.IsCA || !ca.MaxPathLenZero || ca.MaxPathLen != 0 || !ca.BasicConstraintsValid {
		t.Fatalf("CA basic constraints: %+v", ca)
	}
	if ca.KeyUsage != x509.KeyUsageCertSign|x509.KeyUsageCRLSign {
		t.Fatalf("CA key usage %v", ca.KeyUsage)
	}
	if pk, ok := ca.PublicKey.(*ecdsa.PublicKey); !ok || pk.Curve != elliptic.P256() {
		t.Fatal("CA key is not ECDSA P-256")
	}
	if got := ca.NotAfter.Sub(ca.NotBefore); got < 3649*24*time.Hour {
		t.Fatalf("CA validity %v", got)
	}
	if want := "FileParcel Local CA (fileparcel 01234567)"; ca.Subject.CommonName != want {
		t.Fatalf("CA CN %q, want %q", ca.Subject.CommonName, want)
	}
	if !ca.PermittedDNSDomainsCritical || !slices.Contains(ca.PermittedDNSDomains, ".local") ||
		!slices.Contains(ca.PermittedDNSDomains, ".ts.net") || !slices.Contains(ca.PermittedDNSDomains, "localhost") {
		t.Fatalf("CA DNS constraints %v", ca.PermittedDNSDomains)
	}
	if len(ca.PermittedIPRanges) == 0 {
		t.Fatal("CA has no IP constraints")
	}
	if st.clientCA.Equal(ca) || st.clientCA.Subject.CommonName == ca.Subject.CommonName {
		t.Fatal("client CA must be a separate CA")
	}

	// Files and modes; the CA keys are sealed, the leaf key is not.
	for rel, mode := range map[string]os.FileMode{fileCAKey: 0o600, fileClientCAKey: 0o600, fileLeafKey: 0o600, fileCACert: 0o644, fileLeafCert: 0o644} {
		fi := mustStat(t, svc.path(rel))
		if fi.Mode().Perm() != mode {
			t.Errorf("%s mode %v, want %v", rel, fi.Mode().Perm(), mode)
		}
	}
	for _, rel := range []string{fileCAKey, fileClientCAKey} {
		b, _ := os.ReadFile(svc.path(rel))
		if !strings.HasPrefix(string(b), "v1:") || bytes.Contains(b, []byte("PRIVATE KEY")) {
			t.Errorf("%s is not sealed", rel)
		}
	}
	if b, _ := os.ReadFile(svc.path(fileLeafKey)); !bytes.Contains(b, []byte("PRIVATE KEY")) {
		t.Error("leaf key must be a plain PEM key")
	}

	// Leaf: EKU serverAuth, validity tls.leaf_days, SANs incl. loopback.
	leaf := st.leaf.Leaf
	if !slices.Equal(leaf.ExtKeyUsage, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}) {
		t.Fatalf("leaf EKU %v", leaf.ExtKeyUsage)
	}
	if d := leaf.NotAfter.Sub(leaf.NotBefore); d != 397*24*time.Hour {
		t.Fatalf("leaf validity %v", d)
	}
	opts := x509.VerifyOptions{Roots: caPool(ca), CurrentTime: te.clock.Now(), KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	for _, name := range []string{"fileparcel.local", "myhost.local", "localhost", "files.tail1234.ts.net", "127.0.0.1", "::1", "192.168.1.10", "100.64.0.10", "fd7a:115c:a1e0::1"} {
		o := opts
		o.DNSName = name
		if _, err := leaf.Verify(o); err != nil {
			t.Errorf("leaf does not verify for %s: %v", name, err)
		}
	}

	// Init is idempotent and New reloads the same state.
	fp := svc.Fingerprint()
	if err := svc.Init(context.Background()); err != nil {
		t.Fatal(err)
	}
	if svc.Fingerprint() != fp || !svc.snapshot().leaf.Leaf.Equal(leaf) {
		t.Fatal("second Init changed the certificates")
	}
	svc2 := te.service(t)
	if svc2.Fingerprint() != fp || !svc2.snapshot().leaf.Leaf.Equal(leaf) || svc2.snapshot().clientCA == nil {
		t.Fatal("New did not load the certificates from disk")
	}

	// The leaf is presented WITH the local CA: "fileparcel ... --fingerprint
	// <CA fingerprint>" pins the CA, and a client only ever sees what the
	// handshake sends. Both paths that build state.leaf must do it: the fresh
	// issue above and the reload from disk (leaf.crt is leaf-only on purpose).
	for _, c := range []struct {
		name string
		s    *Service
	}{{"issued", svc}, {"reloaded", svc2}} {
		st := c.s.snapshot()
		if len(st.leaf.Certificate) != 2 || !bytes.Equal(st.leaf.Certificate[1], st.ca.Raw) {
			t.Errorf("%s leaf chain = %d cert(s); --fingerprint <CA> needs leaf+CA", c.name, len(st.leaf.Certificate))
		}
	}
}

func TestInitNeedsUnlockedKeys(t *testing.T) {
	te := newTestEnv(t)
	te.keys.setState(core.KeyStateLocked)
	svc := te.service(t)
	if err := svc.Init(context.Background()); !errors.Is(err, core.ErrKeysLocked) {
		t.Fatalf("Init while locked: %v", err)
	}
}

func TestFingerprintFormat(t *testing.T) {
	te := newTestEnv(t)
	svc := te.service(t)
	if svc.Fingerprint() != "" {
		t.Fatal("fingerprint without CA")
	}
	if err := svc.Init(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !regexp.MustCompile(`^([0-9A-F]{2}:){31}[0-9A-F]{2}$`).MatchString(svc.Fingerprint()) {
		t.Fatalf("fingerprint %q", svc.Fingerprint())
	}
}

func TestCANameConstraints(t *testing.T) {
	te := newTestEnv(t)
	te.env.Config.Server.PublicURL = "https://files.example.org:8443/"
	te.settings.set(KeyExtraSANs, []string{"nas.home.arpa", "198.51.100.7"})
	svc := te.initService(t)
	ca := svc.snapshot().ca
	caKey, err := svc.openSealedKey(fileCAKey, aadCAKey)
	if err != nil {
		t.Fatal(err)
	}
	sign := func(names ...string) *x509.Certificate {
		tmpl := &x509.Certificate{SerialNumber: big.NewInt(99), NotBefore: te.clock.Now().Add(-time.Hour),
			NotAfter: te.clock.Now().Add(time.Hour), ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
		for _, n := range names {
			if ip := net.ParseIP(n); ip != nil {
				tmpl.IPAddresses = append(tmpl.IPAddresses, ip)
			} else {
				tmpl.DNSNames = append(tmpl.DNSNames, n)
			}
		}
		k, _ := newKey()
		der, err := x509.CreateCertificate(rand.Reader, tmpl, ca, k.Public(), caKey)
		if err != nil {
			t.Fatal(err)
		}
		c, _ := x509.ParseCertificate(der)
		return c
	}
	tests := []struct {
		name string
		ok   bool
	}{
		{"fileparcel.local", true},
		{"a.b.local", true},
		{"localhost", true},
		{"box.tail1234.ts.net", true},
		{"nas.home.arpa", true},         // tls.extra_sans at creation
		{"files.example.org", true},     // public_url host
		{"198.51.100.7", true},          // extra IP
		{"10.1.2.3", true},              // private range
		{"100.100.1.1", true},           // CGNAT / tailnet
		{"fd00::5", true},               // ULA
		{"www.google.com", false},       // arbitrary public name
		{"evil.example.org", false},     // sibling of an allowed host
		{"8.8.8.8", false},              // public IP
		{"2001:4860:4860::8888", false}, // public IPv6
	}
	for _, tc := range tests {
		leaf := sign(tc.name)
		_, err := leaf.Verify(x509.VerifyOptions{Roots: caPool(ca), CurrentTime: te.clock.Now(), DNSName: tc.name})
		if (err == nil) != tc.ok {
			t.Errorf("%s: verify err=%v, want ok=%v", tc.name, err, tc.ok)
		}
	}
	constrained, dns, ips := constraintsOf(ca)
	if !constrained || !slices.Contains(dns, "files.example.org") || len(ips) == 0 {
		t.Fatalf("constraintsOf: %v %v %v", constrained, dns, ips)
	}
}

// signWithCA signs a leaf template with the local CA's (unsealed) key.
func signWithCA(t *testing.T, svc *Service, tmpl *x509.Certificate) *x509.Certificate {
	t.Helper()
	caKey, err := svc.openSealedKey(fileCAKey, aadCAKey)
	if err != nil {
		t.Fatal(err)
	}
	if tmpl.SerialNumber == nil {
		tmpl.SerialNumber, _ = newSerial()
	}
	k, _ := newKey()
	der, err := x509.CreateCertificate(rand.Reader, tmpl, svc.snapshot().ca, k.Public(), caKey)
	if err != nil {
		t.Fatal(err)
	}
	c, _ := x509.ParseCertificate(der)
	return c
}

// A dNSName constraint also permits every name below it, so a machine called
// "dev" (or "*.com" in tls.extra_sans) gave the constrained CA the right to
// sign for a whole public TLD — the one thing the constraints are there to
// rule out should its key leak.
func TestCANameConstraintsSkipPublicSuffix(t *testing.T) {
	te := newTestEnv(t)
	te.net.setNames("fileparcel.local", "dev", "dev.local", "nas")
	te.settings.set(KeyExtraSANs, []string{"*.com", "*.co.uk", "*.github.io", "files.example.com", "*.home.arpa"})
	svc := te.initService(t)
	ca := svc.snapshot().ca
	for _, d := range []string{"dev", "com", "co.uk", "github.io"} {
		if slices.Contains(ca.PermittedDNSDomains, d) {
			t.Errorf("constraint %q spans a public suffix: %v", d, ca.PermittedDNSDomains)
		}
	}
	for _, d := range []string{"nas", "files.example.com", "home.arpa", ".ts.net"} {
		if !slices.Contains(ca.PermittedDNSDomains, d) {
			t.Errorf("constraint %q missing: %v", d, ca.PermittedDNSDomains)
		}
	}
	if got := svc.UnsignableNames([]string{"web.dev", "dev", "google.com", "x.nas", "a.home.arpa", "dev.local"}); !slices.Equal(got,
		[]string{"dev", "google.com", "web.dev"}) {
		t.Fatalf("UnsignableNames = %v", got)
	}
	leaf := svc.snapshot().leaf.Leaf
	if slices.Contains(leaf.DNSNames, "dev") || !slices.Contains(leaf.DNSNames, "dev.local") || !slices.Contains(leaf.DNSNames, "nas") {
		t.Fatalf("leaf names %v", leaf.DNSNames)
	}
	if got := svc.UncoveredNames(); !slices.Contains(got, "dev") {
		t.Fatalf("UncoveredNames = %v, want it to report dev", got)
	}
	for name, ok := range map[string]bool{"web.dev": false, "x.co.uk": false, "x.nas": true, "files.example.com": true} {
		c := signWithCA(t, svc, &x509.Certificate{DNSNames: []string{name}, NotBefore: te.clock.Now().Add(-time.Hour),
			NotAfter: te.clock.Now().Add(time.Hour), ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}})
		if _, err := c.Verify(x509.VerifyOptions{Roots: caPool(ca), CurrentTime: te.clock.Now(), DNSName: name}); (err == nil) != ok {
			t.Errorf("%s: verify err=%v, want ok=%v", name, err, ok)
		}
	}
	// CAs created before are detected (Start logs a warning); .ts.net is deliberate.
	if got := publicSuffixConstraints(ca); len(got) != 0 {
		t.Fatalf("publicSuffixConstraints(new CA) = %v", got)
	}
	old := &x509.Certificate{PermittedDNSDomains: []string{".local", "local", "localhost", ".ts.net", "null", "dev", "nas.home.arpa"}}
	if got := publicSuffixConstraints(old); !slices.Equal(got, []string{"dev"}) {
		t.Fatalf("publicSuffixConstraints(old CA) = %v", got)
	}
}

// The local CA had no EKU: under a root trusted for every purpose (Windows
// Trusted Root, macOS "Always Trust") a leaked key could still sign
// code-signing and S/MIME certificates, which name constraints on DNS and IP
// names do not reach.
func TestLocalCAIsServerAuthOnly(t *testing.T) {
	te := newTestEnv(t)
	svc := te.initService(t)
	check := func(what string) {
		t.Helper()
		ca := svc.snapshot().ca
		if !slices.Equal(ca.ExtKeyUsage, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}) {
			t.Fatalf("%s: CA EKU %v", what, ca.ExtKeyUsage)
		}
		now := te.clock.Now()
		code := signWithCA(t, svc, &x509.Certificate{Subject: pkix.Name{CommonName: "Some Publisher"}, NotBefore: now.Add(-time.Hour),
			NotAfter: now.Add(time.Hour), ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning}})
		if _, err := code.Verify(x509.VerifyOptions{Roots: caPool(ca), CurrentTime: now,
			KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning}}); err == nil {
			t.Errorf("%s: a code-signing certificate verifies", what)
		}
		mail := signWithCA(t, svc, &x509.Certificate{EmailAddresses: []string{"ceo@bank.example"}, NotBefore: now.Add(-time.Hour),
			NotAfter: now.Add(time.Hour), ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageEmailProtection}})
		if _, err := mail.Verify(x509.VerifyOptions{Roots: caPool(ca), CurrentTime: now,
			KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageEmailProtection}}); err == nil {
			t.Errorf("%s: an S/MIME certificate verifies", what)
		}
		if _, err := svc.snapshot().leaf.Leaf.Verify(x509.VerifyOptions{Roots: caPool(ca), CurrentTime: now,
			DNSName: "fileparcel.local"}); err != nil {
			t.Errorf("%s: the server leaf does not verify: %v", what, err)
		}
	}
	check("constrained")
	if ca := svc.snapshot().ca; !slices.Equal(ca.PermittedEmailAddresses, []string{".invalid"}) {
		t.Fatalf("e-mail constraints %v", ca.PermittedEmailAddresses)
	}
	if err := svc.RegenerateCA(context.Background(), nil, false); err != nil {
		t.Fatal(err)
	}
	check("unconstrained")
}

func TestLeafDropsNamesOutsideConstraints(t *testing.T) {
	te := newTestEnv(t)
	svc := te.initService(t)
	te.settings.set(KeyExtraSANs, []string{"files.example.com", "203.0.113.5", "extra.local"})
	if err := svc.RenewLocal(context.Background(), false); err != nil {
		t.Fatal(err)
	}
	sans := sansOf(svc.snapshot().leaf.Leaf).strings()
	if !slices.Contains(sans, "extra.local") {
		t.Fatalf("permitted extra SAN missing: %v", sans)
	}
	if slices.Contains(sans, "files.example.com") || slices.Contains(sans, "203.0.113.5") {
		t.Fatalf("names outside the constraints must be left out: %v", sans)
	}
	// Regenerating the CA picks the extra names up into its constraints.
	if err := svc.RegenerateCA(context.Background(), nil, true); err != nil {
		t.Fatal(err)
	}
	sans = sansOf(svc.snapshot().leaf.Leaf).strings()
	if !slices.Contains(sans, "files.example.com") || !slices.Contains(sans, "203.0.113.5") {
		t.Fatalf("regenerated CA should cover extra SANs: %v", sans)
	}
}

// The validity span (NotAfter-NotBefore, which is what Apple's 825-day rule is
// evaluated on) must be exactly tls.leaf_days, including at the registered
// maximum: NotBefore is backdated, so anchoring NotAfter on the clock would
// make the span a backdate longer than the setting allows.
func TestLeafValiditySpanMatchesSetting(t *testing.T) {
	def, ok := settings.Lookup(KeyLeafDays)
	if !ok {
		t.Fatalf("%s is not registered", KeyLeafDays)
	}
	if def.Max > 825 {
		t.Fatalf("%s max %d exceeds the Apple limit", KeyLeafDays, def.Max)
	}
	for _, days := range []int64{def.Min, 397, def.Max} {
		te := newTestEnv(t)
		te.settings.set(KeyLeafDays, days)
		svc := te.initService(t)
		leaf := svc.snapshot().leaf.Leaf
		if span := leaf.NotAfter.Sub(leaf.NotBefore); span != time.Duration(days)*24*time.Hour {
			t.Errorf("leaf_days=%d: validity span %v, want %v", days, span, time.Duration(days)*24*time.Hour)
		}
		if !leaf.NotBefore.Before(te.clock.Now()) {
			t.Errorf("leaf_days=%d: NotBefore %v is not backdated against clock skew", days, leaf.NotBefore)
		}
	}
}

func TestSANChangeReissue(t *testing.T) {
	te := newTestEnv(t)
	svc := te.initService(t)
	ch, unsub := te.env.Bus.Subscribe(events.TopicCertsChanged)
	defer unsub()
	serial := svc.snapshot().leaf.Leaf.SerialNumber

	// No change → no reissue.
	if err := svc.RenewLocal(context.Background(), false); err != nil {
		t.Fatal(err)
	}
	if svc.snapshot().leaf.Leaf.SerialNumber.Cmp(serial) != 0 {
		t.Fatal("leaf reissued without a reason")
	}

	te.net.setNames("fileparcel-2.local", "myhost.local")
	if need, why := svc.leafNeedsRenewal(svc.snapshot(), false); !need || why != "sans_changed" {
		t.Fatalf("leafNeedsRenewal = %v %q", need, why)
	}
	if err := svc.RenewLocal(context.Background(), false); err != nil {
		t.Fatal(err)
	}
	leaf := svc.snapshot().leaf.Leaf
	if leaf.SerialNumber.Cmp(serial) == 0 || leaf.VerifyHostname("fileparcel-2.local") != nil || leaf.VerifyHostname("fileparcel.local") == nil {
		t.Fatalf("reissued leaf SANs %v", leaf.DNSNames)
	}
	select {
	case <-ch:
	case <-time.After(time.Second):
		t.Fatal("certs.changed not published")
	}
	if e := te.audit.find(core.ActCertRenew); len(e) != 1 || e[0].Outcome != "" {
		t.Fatalf("cert.renew audit %+v", e)
	}
	// The reissued leaf is on disk.
	if svc2 := te.service(t); !svc2.snapshot().leaf.Leaf.Equal(leaf) {
		t.Fatal("reissued leaf not persisted")
	}
}

// server.name is flagged "restart required", while mDNS and the host names
// follow it at once: until the restart the leaf keeps the running name, so
// https://<old>.local keeps validating; the restart drops it.
func TestRenamePendingKeepsRunningName(t *testing.T) {
	te := newTestEnv(t)
	svc := te.initService(t)
	te.settings.set("server.name", "renamed")
	te.net.setNames("renamed.local", "myhost.local")
	if err := svc.RenewLocal(context.Background(), false); err != nil {
		t.Fatal(err)
	}
	leaf := svc.snapshot().leaf.Leaf
	if leaf.VerifyHostname("renamed.local") != nil || leaf.VerifyHostname("fileparcel.local") != nil {
		t.Fatalf("pending rename: SANs %v", leaf.DNSNames)
	}
	// After the restart the server runs with the new name.
	te.env.Config.Server.Name = "renamed"
	if need, why := svc.leafNeedsRenewal(svc.snapshot(), false); !need || why != "sans_changed" {
		t.Fatalf("leafNeedsRenewal = %v %q", need, why)
	}
	if err := svc.RenewLocal(context.Background(), false); err != nil {
		t.Fatal(err)
	}
	if leaf := svc.snapshot().leaf.Leaf; leaf.VerifyHostname("fileparcel.local") == nil || leaf.VerifyHostname("renamed.local") != nil {
		t.Fatalf("after the restart: SANs %v", leaf.DNSNames)
	}
}

func TestRenewWhenExpiringAndForced(t *testing.T) {
	te := newTestEnv(t)
	svc := te.initService(t)
	leaf := svc.snapshot().leaf.Leaf
	te.clock.add(leaf.NotAfter.Sub(te.clock.Now()) - 31*24*time.Hour)
	if need, _ := svc.leafNeedsRenewal(svc.snapshot(), false); need {
		t.Fatal("renewal 31 days before expiry")
	}
	te.clock.add(2 * 24 * time.Hour)
	if need, why := svc.leafNeedsRenewal(svc.snapshot(), false); !need || why != "expiring" {
		t.Fatalf("no renewal 29 days before expiry: %v %s", need, why)
	}
	if err := svc.RenewLocal(context.Background(), false); err != nil {
		t.Fatal(err)
	}
	if !svc.snapshot().leaf.Leaf.NotAfter.After(leaf.NotAfter) {
		t.Fatal("leaf not renewed")
	}
	serial := svc.snapshot().leaf.Leaf.SerialNumber
	if err := svc.RenewLocal(context.Background(), true); err != nil {
		t.Fatal(err)
	}
	if svc.snapshot().leaf.Leaf.SerialNumber.Cmp(serial) == 0 {
		t.Fatal("forced renewal did nothing")
	}
}

func TestRenewWhileLocked(t *testing.T) {
	te := newTestEnv(t)
	svc := te.initService(t)
	te.net.setNames("other.local")
	te.keys.setState(core.KeyStateLocked)
	err := svc.RenewLocal(context.Background(), false)
	if !errors.Is(err, core.ErrKeysLocked) || !svc.pendingRenew.Load() {
		t.Fatalf("RenewLocal while locked: %v pending=%v", err, svc.pendingRenew.Load())
	}
	if e := te.audit.find(core.ActCertRenew); len(e) != 1 || e[0].Outcome != core.OutcomeFailure {
		t.Fatalf("failure not audited: %+v", e)
	}
	// The existing leaf keeps being served.
	if _, err := handshake(t, svc, &tls.Config{ServerName: "fileparcel.local", RootCAs: caPool(svc.snapshot().ca)}); err != nil {
		t.Fatalf("handshake while locked: %v", err)
	}
}

func TestRenewWithoutCA(t *testing.T) {
	te := newTestEnv(t)
	svc := te.service(t)
	if err := svc.RenewLocal(context.Background(), false); !errors.Is(err, core.ErrPrecondition) {
		t.Fatalf("RenewLocal without CA: %v", err)
	}
}

func TestRegenerateCA(t *testing.T) {
	te := newTestEnv(t)
	svc := te.initService(t)
	old := svc.Fingerprint()
	if err := svc.RegenerateCA(context.Background(), nil, false); err != nil {
		t.Fatal(err)
	}
	st := svc.snapshot()
	if svc.Fingerprint() == old {
		t.Fatal("fingerprint unchanged")
	}
	if len(st.ca.PermittedDNSDomains) != 0 || len(st.ca.PermittedIPRanges) != 0 {
		t.Fatal("unconstrained CA has constraints")
	}
	if err := st.leaf.Leaf.CheckSignatureFrom(st.ca); err != nil {
		t.Fatalf("leaf not reissued by the new CA: %v", err)
	}
	e := te.audit.find(core.ActCARegenerate)
	if len(e) != 1 || e[0].Details.(map[string]any)["constrained"] != false {
		t.Fatalf("ca.regenerate audit %+v", e)
	}
}

// ---------- corrupt files ----------

func TestCorruptFilesAreReplacedByInit(t *testing.T) {
	te := newTestEnv(t)
	svc := te.initService(t)
	if err := os.WriteFile(svc.path(fileLeafCert), []byte("garbage"), 0o644); err != nil {
		t.Fatal(err)
	}
	svc2 := te.service(t)
	if svc2.snapshot().leaf != nil {
		t.Fatal("corrupt leaf loaded")
	}
	if err := svc2.Init(context.Background()); err != nil {
		t.Fatal(err)
	}
	if svc2.snapshot().leaf == nil || svc2.Fingerprint() != svc.Fingerprint() {
		t.Fatal("Init did not replace the leaf (or replaced the CA)")
	}
}

// ---------- handshake / SNI ----------

func TestHandshakeVersionsSuitesALPN(t *testing.T) {
	te := newTestEnv(t)
	svc := te.initService(t)
	roots := caPool(svc.snapshot().ca)

	cs, err := handshake(t, svc, &tls.Config{ServerName: "fileparcel.local", RootCAs: roots, NextProtos: []string{"h2", "http/1.1"}})
	if err != nil {
		t.Fatal(err)
	}
	if cs.NegotiatedProtocol != "h2" || cs.Version != tls.VersionTLS13 {
		t.Fatalf("ALPN %q version %x", cs.NegotiatedProtocol, cs.Version)
	}
	// TLS 1.2 with a modern suite works by default…
	cs, err = handshake(t, svc, &tls.Config{ServerName: "fileparcel.local", RootCAs: roots, MaxVersion: tls.VersionTLS12})
	if err != nil || cs.Version != tls.VersionTLS12 || !slices.Contains(tls12Suites, cs.CipherSuite) {
		t.Fatalf("TLS 1.2: %v %x", err, cs.CipherSuite)
	}
	// …a CBC-only client is refused…
	_, err = handshake(t, svc, &tls.Config{ServerName: "fileparcel.local", RootCAs: roots, MaxVersion: tls.VersionTLS12,
		CipherSuites: []uint16{tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA}})
	if err == nil {
		t.Fatal("CBC suite accepted")
	}
	// …and tls.min_version=1.3 refuses TLS 1.2.
	te.settings.set(KeyMinVersion, "1.3")
	if _, err := handshake(t, svc, &tls.Config{ServerName: "fileparcel.local", RootCAs: roots, MaxVersion: tls.VersionTLS12}); err == nil {
		t.Fatal("TLS 1.2 accepted with min_version 1.3")
	}
	// TLS 1.1 is never accepted.
	te.settings.set(KeyMinVersion, "1.2")
	if _, err := handshake(t, svc, &tls.Config{ServerName: "fileparcel.local", RootCAs: roots, MaxVersion: tls.VersionTLS11}); err == nil {
		t.Fatal("TLS 1.1 accepted")
	}
}

func TestHandshakeClientCertModes(t *testing.T) {
	te := newTestEnv(t)
	svc := te.initService(t)
	roots := caPool(svc.snapshot().ca)
	asked := false
	conf := func() *tls.Config {
		return &tls.Config{ServerName: "fileparcel.local", RootCAs: roots,
			GetClientCertificate: func(cri *tls.CertificateRequestInfo) (*tls.Certificate, error) {
				asked = true
				return &tls.Certificate{}, nil
			}}
	}
	if _, err := handshake(t, svc, conf()); err != nil || asked {
		t.Fatalf("mtls off: err=%v asked=%v", err, asked)
	}
	te.settings.set(KeyMTLSMode, MTLSOptional)
	if _, err := handshake(t, svc, conf()); err != nil || !asked {
		t.Fatalf("mtls optional: err=%v asked=%v", err, asked)
	}
	te.settings.set(KeyMTLSMode, MTLSRequired) // exempt_shares defaults to true → request only
	asked = false
	if _, err := handshake(t, svc, conf()); err != nil || !asked {
		t.Fatalf("mtls required+exempt: err=%v asked=%v", err, asked)
	}
	te.settings.set(KeyMTLSExempt, false)
	if _, err := handshake(t, svc, conf()); err == nil {
		t.Fatal("mtls required without exemptions accepted a handshake without a certificate")
	}
}

func TestSNIDispatch(t *testing.T) {
	te := newTestEnv(t)
	svc := te.initService(t)
	local := svc.snapshot().leaf.Leaf
	pub := newTestCA(t, "Test Public Root")

	// Custom certificate for files.example.com.
	cp, kp, customLeaf := pub.leaf(t, leafOpts{names: []string{"files.example.com"}})
	if err := svc.SetCustom(context.Background(), nil, cp, kp); err != nil {
		t.Fatal(err)
	}
	// Tailscale certificate for the MagicDNS name.
	tsCert, tsKey, tsLeaf := pub.leaf(t, leafOpts{names: []string{"files.tail1234.ts.net"}})
	kpair, err := tls.X509KeyPair(tsCert, tsKey)
	if err != nil {
		t.Fatal(err)
	}
	next := svc.snapshot().clone()
	next.tailscale = &kpair
	svc.state.Store(next)

	roots := caPool(svc.snapshot().ca, pub.cert)
	served := func(name string) *x509.Certificate {
		t.Helper()
		cs, err := handshake(t, svc, &tls.Config{ServerName: name, RootCAs: roots})
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		return cs.PeerCertificates[0]
	}
	if c := served("files.example.com"); !c.Equal(customLeaf) {
		t.Fatal("custom certificate not served for its name")
	}
	if c := served("fileparcel.local"); !c.Equal(local) {
		t.Fatal("local leaf not served for .local")
	}
	// Tailscale certificate only when tailscale.cert_enabled.
	if c := served("files.tail1234.ts.net"); !c.Equal(local) {
		t.Fatal("tailscale certificate served while disabled")
	}
	te.settings.set(KeyTailscaleCert, true)
	if c := served("files.tail1234.ts.net"); !c.Equal(tsLeaf) {
		t.Fatal("tailscale certificate not served")
	}
	if src := svc.ServedSource("files.example.com"); src != core.CertSourceCustom {
		t.Fatalf("ServedSource custom = %q", src)
	}

	// ACME domains win over everything else.
	acmeCert, acmeKey, acmeLeaf := pub.leaf(t, leafOpts{names: []string{"files.example.com", "*.wild.example.com"}})
	a, err := svc.newACMEState(acmeConfig{Domains: []string{"*.wild.example.com", "files.example.com"}, Challenge: ChallengeHTTP,
		CA: acmeDirectory("staging")})
	if err != nil {
		t.Fatal(err)
	}
	defer a.stop()
	tc, err := tls.X509KeyPair(acmeCert, acmeKey)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.magic.CacheUnmanagedTLSCertificate(context.Background(), tc, nil); err != nil {
		t.Fatal(err)
	}
	svc.acme.Store(a)
	if c := served("files.example.com"); !c.Equal(acmeLeaf) {
		t.Fatal("ACME certificate not preferred")
	}
	if c := served("x.wild.example.com"); !c.Equal(acmeLeaf) {
		t.Fatal("ACME wildcard not served")
	}
	if src := svc.ServedSource("x.wild.example.com"); src != core.CertSourceACME {
		t.Fatalf("ServedSource wildcard = %q", src)
	}
	if c := served("fileparcel.local"); !c.Equal(local) {
		t.Fatal("local leaf not served next to ACME")
	}
	svc.acme.Store(nil)
}

func TestACMECovers(t *testing.T) {
	a := &acmeState{domains: []string{"*.example.com", "files.example.org"}}
	for name, want := range map[string]bool{
		"a.example.com": true, "example.com": false, "a.b.example.com": false,
		"files.example.org": true, "x.files.example.org": false, "other.org": false,
	} {
		if got := a.covers(name); got != want {
			t.Errorf("covers(%q) = %v", name, got)
		}
	}
	var nilState *acmeState
	if nilState.covers("a.example.com") {
		t.Fatal("nil state covers names")
	}
}

// certmagic indexes a wildcard certificate under "*.example.com"; the status
// looked it up as "example.com", so a wildcard-only setup showed no ACME
// certificate anywhere and never got an expiry warning.
func TestACMECertificatesIncludeWildcards(t *testing.T) {
	var cache *certmagic.Cache
	cache = certmagic.NewCache(certmagic.CacheOptions{GetConfigForCert: func(certmagic.Certificate) (*certmagic.Config, error) {
		return certmagic.New(cache, certmagic.Config{}), nil
	}})
	t.Cleanup(cache.Stop)
	cfg := certmagic.New(cache, certmagic.Config{})
	pub := newTestCA(t, "acme")
	for _, name := range []string{"*.example.com", "files.example.org"} {
		cp, kp, _ := pub.leaf(t, leafOpts{names: []string{name}})
		kc, err := tls.X509KeyPair(cp, kp)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := cfg.CacheUnmanagedTLSCertificate(context.Background(), kc, nil); err != nil {
			t.Fatal(err)
		}
	}
	a := &acmeState{cache: cache, domains: []string{"*.example.com", "files.example.org"}}
	var names []string
	for _, c := range a.certificates() {
		names = append(names, c.DNSNames...)
	}
	slices.Sort(names)
	if !slices.Equal(names, []string{"*.example.com", "files.example.org"}) {
		t.Fatalf("certificates() found %v", names)
	}
}

func TestPubliclyTrusted(t *testing.T) {
	te := newTestEnv(t)
	svc := te.initService(t)
	if svc.PubliclyTrusted("fileparcel.local") {
		t.Fatal("local CA reported as publicly trusted")
	}
	pub := newTestCA(t, "Pretend Public Root")
	orig := systemRoots
	systemRoots = func() (*x509.CertPool, error) { return caPool(pub.cert), nil }
	defer func() { systemRoots = orig }()
	cp, kp, _ := pub.leaf(t, leafOpts{names: []string{"files.example.com"},
		notBefore: te.clock.Now().Add(-time.Hour), notAfter: te.clock.Now().Add(60 * 24 * time.Hour)})
	if err := svc.SetCustom(context.Background(), nil, cp, kp); err != nil {
		t.Fatal(err)
	}
	if !svc.PubliclyTrusted("files.example.com") || !svc.PubliclyTrusted("FILES.example.com.") {
		t.Fatal("custom certificate from a public root not trusted")
	}
	if svc.PubliclyTrusted("fileparcel.local") {
		t.Fatal("local name trusted")
	}
	st, _ := svc.Status(context.Background())
	if st.HSTS || st.PubliclyTrusted {
		t.Fatalf("default name is local: hsts=%v trusted=%v", st.HSTS, st.PubliclyTrusted)
	}
	te.env.Config.Server.PublicURL = "https://files.example.com:8443"
	st, _ = svc.Status(context.Background())
	if !st.HSTS || !st.PubliclyTrusted {
		t.Fatalf("public_url name: hsts=%v trusted=%v", st.HSTS, st.PubliclyTrusted)
	}
	te.settings.set(KeyHSTS, "off")
	if st, _ = svc.Status(context.Background()); st.HSTS {
		t.Fatal("tls.hsts=off ignored")
	}
}

// ---------- custom certificates ----------

func TestValidateCustom(t *testing.T) {
	now := time.Now()
	pub := newTestCA(t, "root")
	inter := &testCA{}
	{
		// intermediate signed by pub
		key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		tmpl := &x509.Certificate{SerialNumber: big.NewInt(7), Subject: pkix.Name{CommonName: "inter"},
			NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour * 365), KeyUsage: x509.KeyUsageCertSign,
			BasicConstraintsValid: true, IsCA: true}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, pub.cert, key.Public(), pub.key)
		if err != nil {
			t.Fatal(err)
		}
		inter.cert, _ = x509.ParseCertificate(der)
		inter.key = key
	}
	good, goodKey, _ := pub.leaf(t, leafOpts{names: []string{"a.example.com"}})
	_, otherKey, _ := pub.leaf(t, leafOpts{names: []string{"b.example.com"}})
	expired, expiredKey, _ := pub.leaf(t, leafOpts{names: []string{"a.example.com"}, notBefore: now.Add(-48 * time.Hour), notAfter: now.Add(-time.Hour)})
	future, futureKey, _ := pub.leaf(t, leafOpts{names: []string{"a.example.com"}, notBefore: now.Add(time.Hour), notAfter: now.Add(48 * time.Hour)})
	noSAN, noSANKey, _ := pub.leaf(t, leafOpts{})
	clientOnly, clientOnlyKey, _ := pub.leaf(t, leafOpts{names: []string{"a.example.com"}, eku: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}})
	caLeaf, caLeafKey, _ := pub.leaf(t, leafOpts{names: []string{"a.example.com"}, isCA: true})
	chained, chainedKey, chainedLeaf := inter.leaf(t, leafOpts{names: []string{"c.example.com"}})
	// chained = leaf + inter; build a correctly ordered and a reversed chain.
	ordered := append(certPEM(chainedLeaf.Raw), append(certPEM(inter.cert.Raw), certPEM(pub.cert.Raw)...)...)
	reversed := append(certPEM(chainedLeaf.Raw), append(certPEM(pub.cert.Raw), certPEM(inter.cert.Raw)...)...)
	_ = chained
	encKey := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Headers: map[string]string{"Proc-Type": "4,ENCRYPTED", "DEK-Info": "AES-128-CBC,00"}, Bytes: []byte{1, 2, 3}})

	tests := []struct {
		name      string
		cert, key []byte
		field     string // "" = valid
	}{
		{"valid", good, goodKey, ""},
		{"valid chain", ordered, chainedKey, ""},
		{"missing cert", nil, goodKey, "cert_pem"},
		{"missing key", good, nil, "key_pem"},
		{"garbage cert", []byte("nope"), goodKey, "cert_pem"},
		{"garbage key", good, []byte("nope"), "key_pem"},
		{"encrypted key", good, encKey, "key_pem"},
		{"key mismatch", good, otherKey, "key_pem"},
		{"expired", expired, expiredKey, "cert_pem"},
		{"not yet valid", future, futureKey, "cert_pem"},
		{"no SANs", noSAN, noSANKey, "cert_pem"},
		{"client-only EKU", clientOnly, clientOnlyKey, "cert_pem"},
		{"CA as leaf", caLeaf, caLeafKey, "cert_pem"},
		{"chain out of order", reversed, chainedKey, "cert_pem"},
		{"too large", bytes.Repeat([]byte("A"), MaxCustomCertPEM+1), goodKey, "cert_pem"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := validateCustom(tc.cert, tc.key, now)
			if tc.field == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}
			ce := core.AsError(err)
			if ce == nil || ce.Code != core.ErrInvalid.Code || ce.Field != tc.field {
				t.Fatalf("got %v, want invalid %s", err, tc.field)
			}
		})
	}
}

func TestSetClearCustom(t *testing.T) {
	te := newTestEnv(t)
	svc := te.initService(t)
	pub := newTestCA(t, "root")
	cp, kp, leaf := pub.leaf(t, leafOpts{names: []string{"files.example.com", "192.168.1.10"},
		notBefore: te.clock.Now().Add(-time.Hour), notAfter: te.clock.Now().Add(30 * 24 * time.Hour)})

	// Invalid input is audited as a failure and changes nothing.
	if err := svc.SetCustom(context.Background(), nil, cp, []byte("x")); err == nil {
		t.Fatal("invalid key accepted")
	}
	if e := te.audit.find(core.ActCertCustomSet); len(e) != 1 || e[0].Outcome != core.OutcomeFailure {
		t.Fatalf("failure audit %+v", e)
	}
	if err := svc.SetCustom(context.Background(), nil, cp, kp); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(svc.path(fileCustomKey))
	if !strings.HasPrefix(string(b), "v1:") || bytes.Contains(b, []byte("PRIVATE")) {
		t.Fatal("custom key stored unsealed")
	}
	if fi := mustStat(t, svc.path(fileCustomKey)); fi.Mode().Perm() != 0o600 {
		t.Fatalf("custom key mode %v", fi.Mode().Perm())
	}
	st, _ := svc.Status(context.Background())
	if st.Custom == nil || st.Custom.Fingerprint != fingerprint(leaf.Raw) {
		t.Fatalf("status custom %+v", st.Custom)
	}

	// Reload while locked: certificate known, key sealed until unlock.
	te.keys.setState(core.KeyStateLocked)
	svc2 := te.service(t)
	if svc2.snapshot().customCert == nil || svc2.snapshot().custom != nil {
		t.Fatal("custom key must stay sealed while locked")
	}
	if st, _ := svc2.Status(context.Background()); st.Custom == nil || !strings.Contains(st.Custom.Source, "locked") {
		t.Fatalf("status while locked %+v", st.Custom)
	}
	te.keys.setState(core.KeyStateUnlocked)
	svc2.ensureCustomLoaded()
	if svc2.snapshot().custom == nil {
		t.Fatal("custom key not loaded after unlock")
	}

	if err := svc.ClearCustom(context.Background(), nil); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(svc.path(fileCustomCert)); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("custom certificate file left behind")
	}
	if err := svc.ClearCustom(context.Background(), nil); !errors.Is(err, core.ErrNotFound) {
		t.Fatalf("second ClearCustom: %v", err)
	}
	if len(te.audit.find(core.ActCertCustomClear)) != 1 {
		t.Fatal("cert.custom_clear not audited")
	}
}

// ---------- exports ----------

func TestCAExport(t *testing.T) {
	te := newTestEnv(t)
	svc := te.service(t)
	if _, _, _, err := svc.CAExport("pem"); !errors.Is(err, core.ErrNotFound) {
		t.Fatalf("export without CA: %v", err)
	}
	if err := svc.Init(context.Background()); err != nil {
		t.Fatal(err)
	}
	ca := svc.snapshot().ca

	data, ct, name, err := svc.CAExport("pem")
	if err != nil || ct != MIMEPEM || name != "fileparcel-ca.pem" {
		t.Fatalf("pem: %v %s %s", err, ct, name)
	}
	if certs, err := parseCertsPEM(data); err != nil || !certs[0].Equal(ca) {
		t.Fatal("pem export does not parse to the CA")
	}
	for _, f := range []string{"der", "crt", "DER"} {
		data, ct, name, err = svc.CAExport(f)
		if err != nil || ct != MIMEDER || name != "fileparcel-ca.crt" {
			t.Fatalf("%s: %v %s %s", f, err, ct, name)
		}
		if c, err := x509.ParseCertificate(data); err != nil || !c.Equal(ca) {
			t.Fatalf("%s export does not parse", f)
		}
	}
	if _, _, _, err := svc.CAExport("p7b"); !errors.Is(err, core.ErrInvalid) {
		t.Fatalf("unknown format: %v", err)
	}
	data, ct, name, err = svc.CAExport("mobileconfig")
	if err != nil || ct != MIMEMobileconfig || name != "fileparcel-ca.mobileconfig" {
		t.Fatalf("mobileconfig: %v %s %s", err, ct, name)
	}
	checkMobileconfig(t, data, ca)
	// Stable payload UUIDs: re-downloading updates the same profile.
	again, _, _, _ := svc.CAExport("mobileconfig")
	if !bytes.Equal(data, again) {
		t.Fatal("mobileconfig not deterministic")
	}
}

// checkMobileconfig parses the profile as an XML property list and checks
// the Apple configuration-profile structure with the root payload.
func checkMobileconfig(t *testing.T, data []byte, ca *x509.Certificate) {
	t.Helper()
	root, err := parsePlist(data)
	if err != nil {
		t.Fatalf("mobileconfig is not a valid plist: %v\n%s", err, data)
	}
	top, ok := root.(map[string]any)
	if !ok {
		t.Fatal("plist root is not a dict")
	}
	uuidRe := regexp.MustCompile(`^[0-9A-F]{8}-[0-9A-F]{4}-5[0-9A-F]{3}-[89AB][0-9A-F]{3}-[0-9A-F]{12}$`)
	for k, want := range map[string]any{"PayloadType": "Configuration", "PayloadVersion": int64(1), "PayloadRemovalDisallowed": false} {
		if top[k] != want {
			t.Errorf("%s = %#v, want %#v", k, top[k], want)
		}
	}
	for _, k := range []string{"PayloadIdentifier", "PayloadDisplayName", "PayloadUUID", "PayloadDescription"} {
		if s, _ := top[k].(string); s == "" {
			t.Errorf("missing %s", k)
		}
	}
	if !uuidRe.MatchString(top["PayloadUUID"].(string)) {
		t.Errorf("PayloadUUID %q", top["PayloadUUID"])
	}
	content, _ := top["PayloadContent"].([]any)
	if len(content) != 1 {
		t.Fatalf("PayloadContent %#v", top["PayloadContent"])
	}
	p := content[0].(map[string]any)
	if p["PayloadType"] != "com.apple.security.root" || p["PayloadVersion"] != int64(1) {
		t.Fatalf("payload %#v", p)
	}
	if !uuidRe.MatchString(p["PayloadUUID"].(string)) || p["PayloadUUID"] == top["PayloadUUID"] {
		t.Fatalf("payload UUID %q", p["PayloadUUID"])
	}
	der, _ := p["PayloadContent"].([]byte)
	if c, err := x509.ParseCertificate(der); err != nil || !c.Equal(ca) {
		t.Fatal("payload does not carry the CA certificate")
	}
	if !strings.HasPrefix(p["PayloadIdentifier"].(string), top["PayloadIdentifier"].(string)) {
		t.Fatal("payload identifier not under the profile identifier")
	}
}

func TestSerialAndCertInfo(t *testing.T) {
	te := newTestEnv(t)
	svc := te.initService(t)
	st, err := svc.Status(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if st.CA == nil || st.Leaf == nil || st.ClientCA == nil || st.Leaf.Source != core.CertSourceLocal {
		t.Fatalf("status %+v", st)
	}
	if !st.CAConstrained || len(st.PermittedDNS) == 0 || st.MTLSMode != MTLSOff || st.ACMEEnabled {
		t.Fatalf("status flags %+v", st)
	}
	if !slices.Contains(st.Leaf.IPs, "127.0.0.1") || !slices.Contains(st.Leaf.DNSNames, "localhost") {
		t.Fatalf("leaf info %+v", st.Leaf)
	}
	if st.Leaf.Serial != strings.ToUpper(svc.snapshot().leaf.Leaf.SerialNumber.Text(16)) {
		t.Fatal("serial format")
	}
}

func TestIsPrivate(t *testing.T) {
	for s, want := range map[string]bool{
		"10.0.0.1": true, "192.168.1.10": true, "172.16.5.5": true, "172.32.0.1": false, "100.64.0.10": true,
		"::ffff:192.168.1.1": true, "fd7a:115c:a1e0::1": true, "fe80::1": true, "8.8.8.8": false, "::1": true,
		"2001:db8::1": false, "127.0.0.1": true,
	} {
		if got := IsPrivate(netip.MustParseAddr(s)); got != want {
			t.Errorf("IsPrivate(%s) = %v", s, got)
		}
	}
}

func TestValidDNSName(t *testing.T) {
	for s, want := range map[string]bool{
		"a.example.com": true, "fileparcel.local": true, "*.example.com": true, "x_y.local": true,
		"": false, "-a.com": false, "a-.com": false, "a..b": false, "UPPER.com": false, "sp ace.com": false,
		strings.Repeat("a", 64) + ".com": false, "*.*.com": false,
	} {
		if got := validDNSName(s, true); got != want {
			t.Errorf("validDNSName(%q) = %v", s, got)
		}
	}
	if validDNSName("*.example.com", false) {
		t.Error("wildcard accepted without the flag")
	}
}

func TestStateFilesSurviveReload(t *testing.T) {
	te := newTestEnv(t)
	svc := te.initService(t)
	_ = svc
	// Nothing but the documented files exists under certs/.
	var files []string
	_ = filepath.Walk(te.env.Home.CertsDir(), func(p string, fi os.FileInfo, err error) error {
		if err == nil && !fi.IsDir() {
			rel, _ := filepath.Rel(te.env.Home.CertsDir(), p)
			files = append(files, filepath.ToSlash(rel))
		}
		return nil
	})
	slices.Sort(files)
	want := []string{fileCACert, fileCAKey, fileClientCACert, fileClientCAKey, fileLeafCert, fileLeafKey}
	slices.Sort(want)
	if !slices.Equal(files, want) {
		t.Fatalf("files %v, want %v", files, want)
	}
}

// ---------- plist parser (tests only) ----------

var _ = base64.StdEncoding

// A sealed CA key that does not belong to the CA certificate (an interrupted
// regeneration) must never be used to sign.
func TestMismatchedCAKeysRefuseToSign(t *testing.T) {
	te := newTestEnv(t)
	te.addUser(t, aliceID, "alice", "active")
	svc := te.initService(t)
	other, err := newKey()
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range []struct{ rel, aad string }{{fileCAKey, aadCAKey}, {fileClientCAKey, aadClientCAKey}} {
		if err := svc.sealKeyFile(f.rel, f.aad, other); err != nil {
			t.Fatal(err)
		}
	}
	before := svc.snapshot().leaf
	if err := svc.RenewLocal(context.Background(), true); !errors.Is(err, core.ErrCorrupt) {
		t.Fatalf("RenewLocal with a foreign CA key: %v", err)
	}
	if svc.snapshot().leaf != before {
		t.Fatal("leaf replaced")
	}
	_, _, err = svc.IssueClient(context.Background(), nil, core.ClientCertInput{UserID: aliceID, Password: "s3cret-pass"})
	if !errors.Is(err, core.ErrCorrupt) {
		t.Fatalf("IssueClient with a foreign client CA key: %v", err)
	}
	// Regenerating the CA repairs it.
	if err := svc.RegenerateCA(context.Background(), nil, true); err != nil {
		t.Fatal(err)
	}
	if err := svc.RenewLocal(context.Background(), true); err != nil {
		t.Fatalf("after regeneration: %v", err)
	}
}

// When the leaf cannot be reissued after a CA regeneration (keys locked in
// between), the new CA is kept, announced, and the leaf renewal is pending.
func TestRegenerateCALeafFailure(t *testing.T) {
	te := newTestEnv(t)
	svc := te.initService(t)
	ch, unsub := te.env.Bus.Subscribe(events.TopicCertsChanged)
	defer unsub()
	old := svc.snapshot()
	// createCA seals the new key fine; reading it back for signing fails.
	origKeys := te.env.Keys
	te.env.Keys = &failOpenKeys{fakeKeys: te.keys}
	defer func() { te.env.Keys = origKeys }()
	err := svc.RegenerateCA(context.Background(), nil, true)
	if err == nil {
		t.Fatal("RegenerateCA succeeded although the leaf could not be signed")
	}
	st := svc.snapshot()
	if st.ca == nil || st.ca.Equal(old.ca) || st.leaf != old.leaf || !svc.pendingRenew.Load() {
		t.Fatal("new CA not stored or leaf replaced")
	}
	select {
	case <-ch:
	case <-time.After(5 * time.Second):
		t.Fatal("certs.changed not published")
	}
	if e := te.audit.find(core.ActCARegenerate); len(e) != 1 || e[0].Outcome != core.OutcomeFailure {
		t.Fatalf("audit %+v", e)
	}
	if need, reason := svc.leafNeedsRenewal(st, false); !need || reason != "ca_changed" {
		t.Fatalf("leafNeedsRenewal = %v %q", need, reason)
	}
}

// failOpenKeys seals normally but cannot open sealed files.
type failOpenKeys struct{ *fakeKeys }

func (k *failOpenKeys) OpenField(string, string) ([]byte, error) { return nil, core.ErrCorrupt }

// TestSealedPrivateKeysAreZeroed checks the promise of the package doc: the
// PKCS#8 DER of a CA key handed to Keys.SealField is wiped again, on the
// success path and when writing the file fails.
func TestSealedPrivateKeysAreZeroed(t *testing.T) {
	te := newTestEnv(t)
	svc := te.initService(t) // seals the local CA and the client CA keys
	fields := te.keys.sealedFieldsSnapshot()
	if len(fields) < 2 {
		t.Fatalf("SealField calls: %d, want the CA and the client CA", len(fields))
	}
	for i, f := range fields {
		if len(f) == 0 {
			t.Fatalf("sealed field %d is empty", i)
		}
		if !allZero(f) {
			t.Fatalf("sealed field %d still holds key material: %x", i, f)
		}
	}

	// The key is zeroed even when the write fails (ca/ca.crt is a file, so
	// creating a directory below it cannot work).
	key, err := newKey()
	if err != nil {
		t.Fatal(err)
	}
	if err := svc.sealKeyFile(fileCACert+"/nope.key.enc", aadCAKey, key); err == nil {
		t.Fatal("sealKeyFile into a file path succeeded")
	}
	last := te.keys.lastSealedField()
	if len(last) == 0 {
		t.Fatal("SealField was not called")
	}
	if !allZero(last) {
		t.Fatalf("key material survives a failed write: %x", last)
	}
}

func allZero(b []byte) bool {
	for _, c := range b {
		if c != 0 {
			return false
		}
	}
	return true
}
