package svc

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"fileparcel/internal/config"
	"fileparcel/internal/home"
)

// testLeaf returns a CA and a leaf for "localhost" (the name HealthClient
// verifies) signed by it.
func testLeaf(t *testing.T) (caPEM []byte, leaf tls.Certificate) {
	t.Helper()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Test Local CA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, &x509.Certificate{
		SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "localhost"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true, DNSNames: []string{"localhost"},
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
	}, caCert, &leafKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}),
		tls.Certificate{Certificate: [][]byte{leafDER}, PrivateKey: leafKey}
}

// healthHome returns a home whose local CA is caPEM and whose config points
// at a TLS server (tlsCfg) that serves /healthz on a free loopback port.
func healthHome(t *testing.T, caPEM []byte, tlsCfg *tls.Config) (*home.Home, int) {
	t.Helper()
	h, _ := home.New(t.TempDir())
	if err := h.EnsureLayout(); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(h.CertsDir(), "ca"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(CACertPath(h), caPEM, 0o644); err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/healthz" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		_, _ = w.Write([]byte("ok"))
	}), TLSConfig: tlsCfg, ErrorLog: log.New(io.Discard, "", 0)}
	go func() { _ = srv.ServeTLS(ln, "", "") }()
	t.Cleanup(func() { _ = srv.Close() })

	cfg := config.Default(config.NewInstallID())
	cfg.Server.HTTPSPort = port
	cfg.Server.Bind = []string{"127.0.0.1"}
	if err := cfg.SaveTo(h.Config()); err != nil {
		t.Fatal(err)
	}
	return h, port
}

// TestHealthCheckURLReportsProbedURL pins that the health check reports the
// URL it actually probed, including the configured port (doctor prints it).
func TestHealthCheckURLReportsProbedURL(t *testing.T) {
	caPEM, leaf := testLeaf(t)
	h, port := healthHome(t, caPEM, &tls.Config{Certificates: []tls.Certificate{leaf}})

	u, err := HealthCheckURL(context.Background(), h, 0, 5*time.Second)
	if err != nil {
		t.Fatalf("health check: %v", err)
	}
	want := "https://" + net.JoinHostPort("127.0.0.1", strconv.Itoa(port)) + "/healthz"
	if u != want {
		t.Errorf("probed URL = %q, want %q", u, want)
	}
	if !strings.Contains(u, ":"+strconv.Itoa(port)+"/") {
		t.Errorf("URL %q lacks the configured port %d", u, port)
	}
	if err := HealthCheck(context.Background(), h, 0, 5*time.Second); err != nil {
		t.Errorf("HealthCheck wrapper: %v", err)
	}
}

// With mtls.mode=required and mtls.exempt_shares off the server refuses
// every connection without a client certificate at the TLS layer
// (RequireAnyClientCert), /healthz included. That refusal comes from a
// server whose certificate the probe verified against the local CA, so the
// server is up: upgrades must not roll back, and `fileparcel healthcheck`
// must pass. A server with another CA's certificate still fails.
func TestHealthCheckMTLSRequired(t *testing.T) {
	caPEM, leaf := testLeaf(t)
	h, _ := healthHome(t, caPEM, &tls.Config{Certificates: []tls.Certificate{leaf}, ClientAuth: tls.RequireAnyClientCert})
	if err := HealthCheck(context.Background(), h, 0, 5*time.Second); err != nil {
		t.Fatalf("health check against a client-certificate-only server: %v", err)
	}

	otherCA, _ := testLeaf(t)
	h2, _ := healthHome(t, otherCA, &tls.Config{Certificates: []tls.Certificate{leaf}, ClientAuth: tls.RequireAnyClientCert})
	if err := HealthCheck(context.Background(), h2, 0, 5*time.Second); err == nil {
		t.Fatal("a server whose certificate the local CA did not issue passed the health check")
	}
}
