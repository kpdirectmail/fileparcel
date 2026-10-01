package certs

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"

	"fileparcel/internal/core"
)

// tls12Suites are the TLS 1.2 suites offered: ECDHE with AEAD ciphers only
// (TLS 1.3 suites are always modern and not configurable).
var tls12Suites = []uint16{
	tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
	tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
	tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
	tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
	tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
	tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
}

// ALPN protocol names.
const (
	alpnH2      = "h2"
	alpnHTTP11  = "http/1.1"
	alpnACMETLS = "acme-tls/1"
)

// isACMEChallengeHello reports whether hello is an ACME TLS-ALPN-01
// validation (RFC 8737: SNI set and acme-tls/1 as the only protocol).
func isACMEChallengeHello(hello *tls.ClientHelloInfo) bool {
	return hello.ServerName != "" && len(hello.SupportedProtos) == 1 && hello.SupportedProtos[0] == alpnACMETLS
}

// minVersion maps tls.min_version to a crypto/tls constant.
func (svc *Service) minVersion() uint16 {
	if svc.settingString(KeyMinVersion) == "1.3" {
		return tls.VersionTLS13
	}
	return tls.VersionTLS12
}

// getConfigForClient builds the per-connection configuration (DESIGN §10.4):
// tls.min_version, modern suites, ALPN h2/http1.1 (+acme-tls/1 while an
// ACME TLS-ALPN challenge may be pending), the client-certificate request of
// mtls.mode and the SNI certificate dispatch.
func (svc *Service) getConfigForClient(hello *tls.ClientHelloInfo) (*tls.Config, error) {
	a := svc.acme.Load()
	if isACMEChallengeHello(hello) {
		if a == nil || a.magic == nil {
			return nil, errors.New("certs: no ACME configuration for a TLS-ALPN challenge")
		}
		return &tls.Config{
			MinVersion:     tls.VersionTLS12,
			NextProtos:     []string{alpnACMETLS},
			GetCertificate: a.magic.GetCertificate,
		}, nil
	}
	cfg := &tls.Config{
		MinVersion:     svc.minVersion(),
		CipherSuites:   tls12Suites,
		NextProtos:     []string{alpnH2, alpnHTTP11},
		GetCertificate: svc.getCertificate,
	}
	if a != nil && a.alpn {
		cfg.NextProtos = append(cfg.NextProtos, alpnACMETLS)
	}
	st := svc.snapshot()
	switch svc.mtlsMode() {
	case MTLSOptional:
		cfg.ClientAuth = tls.RequestClientCert
		cfg.ClientCAs = st.clientPool
	case MTLSRequired:
		// TLS cannot vary by path: with share exemptions the certificate is
		// only requested here and the HTTP gate (package server) rejects
		// requests without a valid one (DESIGN §10.4).
		cfg.ClientAuth = tls.RequestClientCert
		if !svc.settingBool(KeyMTLSExempt) {
			cfg.ClientAuth = tls.RequireAnyClientCert
		}
		cfg.ClientCAs = st.clientPool
	}
	return cfg, nil
}

// getCertificate is the SNI dispatch.
func (svc *Service) getCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	if c, _ := svc.certFor(hello); c != nil {
		return c, nil
	}
	return nil, errors.New("certs: no certificate available (run \"fileparcel init\")")
}

// certFor selects the certificate for hello (DESIGN §10.4 SNI dispatch):
// ACME domains (exact or wildcard) → certmagic; the Tailscale FQDN →
// Tailscale certificate; names of the custom certificate → custom; otherwise
// the local leaf. Returns the certificate and its source.
func (svc *Service) certFor(hello *tls.ClientHelloInfo) (*tls.Certificate, string) {
	name := strings.TrimSuffix(strings.ToLower(hello.ServerName), ".")
	st := svc.snapshot()
	if a := svc.acme.Load(); a != nil && name != "" && a.covers(name) {
		if c := a.certFor(hello); c != nil {
			return c, core.CertSourceACME
		}
	}
	if st.tailscale != nil && name != "" && svc.settingBool(KeyTailscaleCert) && coversName(st.tailscale, name) {
		return st.tailscale, core.CertSourceTailscale
	}
	if st.custom != nil {
		target := name
		if target == "" && hello.Conn != nil {
			if ip := localIP(hello.Conn); ip.IsValid() {
				target = ip.String()
			}
		}
		if target != "" && coversName(st.custom, target) {
			return st.custom, core.CertSourceCustom
		}
	}
	return st.leaf, core.CertSourceLocal
}

// coversName reports whether c's leaf is valid for name (DNS name with
// wildcard support, or an IP literal).
func coversName(c *tls.Certificate, name string) bool {
	leaf := c.Leaf
	if leaf == nil && len(c.Certificate) > 0 {
		var err error
		if leaf, err = x509.ParseCertificate(c.Certificate[0]); err != nil {
			return false
		}
	}
	return leaf != nil && leaf.VerifyHostname(name) == nil
}

func localIP(c net.Conn) netip.Addr {
	if a, ok := c.LocalAddr().(*net.TCPAddr); ok {
		if ip, ok := netip.AddrFromSlice(a.IP); ok {
			return ip.Unmap()
		}
	}
	return netip.Addr{}
}

// PubliclyTrusted implements core.Certs: whether the certificate served for
// serverName chains to a public root (ACME production, Tailscale, a custom
// certificate from a public CA). The local CA is never publicly trusted.
// Called per request for the HSTS decision, so results are cached briefly.
func (svc *Service) PubliclyTrusted(serverName string) bool {
	name := strings.TrimSuffix(strings.ToLower(serverName), ".")
	if v, ok := svc.trust.get(name, svc.env.Now()); ok {
		return v
	}
	cert, src := svc.certFor(&tls.ClientHelloInfo{ServerName: name})
	v := src != core.CertSourceLocal && cert != nil && svc.systemTrusted(cert)
	svc.trust.put(name, v, svc.env.Now())
	return v
}

// systemRoots returns the system trust store (replaced in tests).
var systemRoots = sync.OnceValues(x509.SystemCertPool)

// systemTrusted verifies cert's chain against the system roots.
func (svc *Service) systemTrusted(cert *tls.Certificate) bool {
	if len(cert.Certificate) == 0 {
		return false
	}
	leaf := cert.Leaf
	if leaf == nil {
		var err error
		if leaf, err = x509.ParseCertificate(cert.Certificate[0]); err != nil {
			return false
		}
	}
	roots, err := systemRoots()
	if err != nil || roots == nil {
		return false
	}
	inter := x509.NewCertPool()
	for _, der := range cert.Certificate[1:] {
		if c, err := x509.ParseCertificate(der); err == nil {
			inter.AddCert(c)
		}
	}
	_, err = leaf.Verify(x509.VerifyOptions{
		Roots: roots, Intermediates: inter, CurrentTime: svc.env.Now(),
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	})
	return err == nil
}

// trustCache memoizes PubliclyTrusted per server name for trustTTL. SNI
// values are client-controlled, so the map is bounded.
type trustCache struct {
	mu sync.Mutex
	m  map[string]trustEntry
}

type trustEntry struct {
	v   bool
	exp time.Time
}

const (
	trustTTL     = 5 * time.Minute
	trustMaxSize = 512
)

func (c *trustCache) get(name string, now time.Time) (bool, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.m[name]
	if !ok || now.After(e.exp) {
		return false, false
	}
	return e.v, true
}

func (c *trustCache) put(name string, v bool, now time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.m == nil || len(c.m) >= trustMaxSize {
		c.m = map[string]trustEntry{}
	}
	c.m[name] = trustEntry{v: v, exp: now.Add(trustTTL)}
}

func (c *trustCache) reset() {
	c.mu.Lock()
	c.m = nil
	c.mu.Unlock()
}
