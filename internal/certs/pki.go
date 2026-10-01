package certs

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"golang.org/x/net/publicsuffix"

	"fileparcel/internal/core"
	"fileparcel/internal/crypt"
)

// Validity periods and renewal thresholds (DESIGN §10.4).
const (
	caValidity       = 10 * 365 * 24 * time.Hour
	leafRenewBefore  = 30 * 24 * time.Hour
	tsRenewBefore    = 14 * 24 * time.Hour
	backdate         = time.Hour // NotBefore offset against clock skew
	maxClientDays    = 3650
	defaultClientDay = 365
)

// newKey returns a fresh ECDSA P-256 key.
func newKey() (*ecdsa.PrivateKey, error) {
	return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
}

// newSerial returns a random positive 128-bit serial number.
func newSerial() (*big.Int, error) {
	limit := new(big.Int).Lsh(big.NewInt(1), 128)
	for {
		n, err := rand.Int(rand.Reader, limit)
		if err != nil {
			return nil, err
		}
		if n.Sign() > 0 {
			return n, nil
		}
	}
}

// fingerprint returns the SHA-256 of der as upper-case hex pairs separated by
// colons ("AB:CD:…"), the format shown for out-of-band verification.
func fingerprint(der []byte) string {
	sum := sha256.Sum256(der)
	h := strings.ToUpper(hex.EncodeToString(sum[:]))
	var b strings.Builder
	b.Grow(len(h) + len(h)/2)
	for i := 0; i < len(h); i += 2 {
		if i > 0 {
			b.WriteByte(':')
		}
		b.WriteString(h[i : i+2])
	}
	return b.String()
}

func certPEM(der []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func keyPKCS8(key crypto.PrivateKey) ([]byte, error) {
	return x509.MarshalPKCS8PrivateKey(key)
}

// parseCertsPEM decodes every CERTIFICATE block of data in order.
func parseCertsPEM(data []byte) ([]*x509.Certificate, error) {
	var out []*x509.Certificate
	for {
		var b *pem.Block
		b, data = pem.Decode(data)
		if b == nil {
			break
		}
		if b.Type != "CERTIFICATE" {
			continue
		}
		c, err := x509.ParseCertificate(b.Bytes)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	if len(out) == 0 {
		return nil, errors.New("no PEM certificate found")
	}
	return out, nil
}

// parsePrivateKey parses a DER private key in PKCS#8, PKCS#1 (RSA) or SEC 1
// (EC) form.
func parsePrivateKey(der []byte) (crypto.Signer, error) {
	if k, err := x509.ParsePKCS8PrivateKey(der); err == nil {
		s, ok := k.(crypto.Signer)
		if !ok {
			return nil, errors.New("unsupported private key type")
		}
		return s, nil
	}
	if k, err := x509.ParsePKCS1PrivateKey(der); err == nil {
		return k, nil
	}
	if k, err := x509.ParseECPrivateKey(der); err == nil {
		return k, nil
	}
	return nil, errors.New("unsupported or malformed private key")
}

// parseKeyPEM returns the first private key block of data. The decoded DER is
// zeroed afterwards (best effort: an uploaded key also lives in the immutable
// JSON string it was decoded from).
func parseKeyPEM(data []byte) (crypto.Signer, error) {
	for {
		var b *pem.Block
		b, data = pem.Decode(data)
		if b == nil {
			return nil, errors.New("no PEM private key found")
		}
		if strings.HasSuffix(b.Type, "PRIVATE KEY") {
			//lint:ignore SA1019 the deprecated RFC 1423 encryption is exactly what this detects, in order to reject it with a clear message
			if x509.IsEncryptedPEMBlock(b) { //nolint:staticcheck // detect legacy encrypted keys to reject them
				return nil, errors.New("encrypted private keys are not supported; remove the passphrase first")
			}
			k, err := parsePrivateKey(b.Bytes)
			crypt.Zero(b.Bytes)
			return k, err
		}
	}
}

// publicKeysEqual reports whether a and b are the same public key.
func publicKeysEqual(a, b crypto.PublicKey) bool {
	type equaler interface{ Equal(crypto.PublicKey) bool }
	e, ok := a.(equaler)
	return ok && e.Equal(b)
}

// tlsCert builds a tls.Certificate from a chain and key with Leaf set.
func tlsCert(chain []*x509.Certificate, key crypto.PrivateKey) *tls.Certificate {
	c := &tls.Certificate{PrivateKey: key, Leaf: chain[0]}
	for _, x := range chain {
		c.Certificate = append(c.Certificate, x.Raw)
	}
	return c
}

// certInfo describes c for the API.
func certInfo(c *x509.Certificate, source string) *core.CertInfo {
	if c == nil {
		return nil
	}
	ci := &core.CertInfo{
		Subject:     c.Subject.String(),
		Issuer:      c.Issuer.String(),
		Serial:      strings.ToUpper(c.SerialNumber.Text(16)),
		DNSNames:    slices.Clone(c.DNSNames),
		NotBefore:   c.NotBefore.UTC(),
		NotAfter:    c.NotAfter.UTC(),
		Fingerprint: fingerprint(c.Raw),
		Source:      source,
	}
	for _, ip := range c.IPAddresses {
		ci.IPs = append(ci.IPs, ip.String())
	}
	return ci
}

// ---------- name constraints ----------

// privatePrefixes are the address ranges a constrained local CA may issue
// for (DESIGN §10.3 "private" plus loopback).
var privatePrefixes = []netip.Prefix{
	netip.MustParsePrefix("127.0.0.0/8"),
	netip.MustParsePrefix("10.0.0.0/8"),
	netip.MustParsePrefix("172.16.0.0/12"),
	netip.MustParsePrefix("192.168.0.0/16"),
	netip.MustParsePrefix("169.254.0.0/16"),
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("::1/128"),
	netip.MustParsePrefix("fc00::/7"),
	netip.MustParsePrefix("fe80::/10"),
}

// IsPrivate reports whether ip (IPv4-mapped addresses are unmapped) is in a
// private, loopback, link-local or CGNAT/tailnet range (DESIGN §10.3).
func IsPrivate(ip netip.Addr) bool {
	ip = ip.Unmap()
	for _, p := range privatePrefixes {
		if p.Contains(ip) {
			return true
		}
	}
	return false
}

// baseDNSConstraints are always permitted by a constrained CA.
var baseDNSConstraints = []string{".local", "local", "localhost", ".ts.net"}

func toIPNet(p netip.Prefix) *net.IPNet {
	p = p.Masked()
	return &net.IPNet{IP: net.IP(p.Addr().AsSlice()), Mask: net.CIDRMask(p.Bits(), p.Addr().BitLen())}
}

// publicSuffixConstraint reports whether a dNSName constraint of d would span
// a public suffix — a TLD such as "dev" or "app", or "co.uk", "github.io".
// RFC 5280 lets such a constraint sign every name below it, so a machine that
// happens to be called "dev" would turn the constrained CA into one for the
// whole .dev TLD. Unlisted single labels ("nas", "lan"), which only match the
// list's default "*" rule, stay allowed, and so does home.arpa (RFC 8375, the
// home-network domain, which the list files under ICANN).
func publicSuffixConstraint(d string) bool {
	d = strings.TrimPrefix(d, ".")
	if d == "" || d == "home.arpa" {
		return false
	}
	ps, icann := publicsuffix.PublicSuffix(d)
	return ps == d && (icann || strings.Contains(d, "."))
}

// constraintDomain maps a SAN DNS name to the constraint that covers it
// ("*.example.com" → "example.com"; names already covered by the base list
// return "").
func constraintDomain(name string) string {
	name = strings.TrimPrefix(name, "*.")
	for _, base := range []string{"local", "localhost", "ts.net"} {
		if name == base || strings.HasSuffix(name, "."+base) {
			return ""
		}
	}
	return name
}

// dnsPermitted reports whether name is allowed by the DNS name constraints of
// ca (RFC 5280 semantics as implemented by crypto/x509: "example.com" permits
// the domain and its subdomains, ".example.com" only subdomains).
func dnsPermitted(ca *x509.Certificate, name string) bool {
	if ca == nil || len(ca.PermittedDNSDomains) == 0 {
		return true
	}
	name = strings.TrimPrefix(name, "*.")
	for _, c := range ca.PermittedDNSDomains {
		c = strings.ToLower(c)
		if strings.HasPrefix(c, ".") {
			if strings.HasSuffix(name, c) && len(name) > len(c) {
				return true
			}
			continue
		}
		if name == c || strings.HasSuffix(name, "."+c) {
			return true
		}
	}
	return false
}

// ipPermitted reports whether ip is allowed by the IP constraints of ca.
func ipPermitted(ca *x509.Certificate, ip netip.Addr) bool {
	if ca == nil || len(ca.PermittedIPRanges) == 0 {
		return true
	}
	std := net.IP(ip.Unmap().AsSlice())
	for _, n := range ca.PermittedIPRanges {
		if n.Contains(std) {
			return true
		}
	}
	return false
}

// ---------- files ----------

// writeFileAtomic writes data to path via a temporary file in the same
// directory (fsync + rename + directory fsync) with the given mode.
func writeFileAtomic(path string, data []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	f, err := os.CreateTemp(dir, "."+filepath.Base(path)+".tmp*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	ok := false
	defer func() {
		if !ok {
			_ = os.Remove(tmp)
		}
	}()
	if err := f.Chmod(mode); err != nil {
		f.Close()
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		return err
	}
	ok = true
	syncDir(dir)
	return nil
}

// renameSync renames from to to and syncs the directory, so the rename
// survives a crash.
func renameSync(from, to string) error {
	if err := os.Rename(from, to); err != nil {
		return err
	}
	syncDir(filepath.Dir(to))
	return nil
}

// syncDir fsyncs a directory (best effort).
func syncDir(dir string) {
	if d, err := os.Open(dir); err == nil {
		_ = d.Sync()
		d.Close()
	}
}

// readOptional reads path; a missing file yields (nil, nil).
func readOptional(path string) ([]byte, error) {
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	return b, err
}

// removeOptional removes path, ignoring a missing file.
func removeOptional(path string) error {
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

// checkValidity returns an error when c is not valid at now.
func checkValidity(c *x509.Certificate, now time.Time) error {
	if now.Before(c.NotBefore) {
		return fmt.Errorf("certificate is not valid before %s", c.NotBefore.UTC().Format(time.RFC3339))
	}
	if !now.Before(c.NotAfter) {
		return fmt.Errorf("certificate expired on %s", c.NotAfter.UTC().Format(time.RFC3339))
	}
	return nil
}
