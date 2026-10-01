package svc

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"fileparcel/internal/config"
	"fileparcel/internal/home"
)

// CACertPath returns <HOME>/certs/ca/ca.crt (the local CA, DESIGN §3).
func CACertPath(h *home.Home) string { return filepath.Join(h.CertsDir(), "ca", "ca.crt") }

// HealthTargets returns the loopback (or explicitly bound) addresses the
// health check should try for the configured bind list.
func HealthTargets(bind []string) []string {
	var out []string
	add := func(s string) {
		for _, o := range out {
			if o == s {
				return
			}
		}
		out = append(out, s)
	}
	wild := len(bind) == 0
	for _, b := range bind {
		a, err := netip.ParseAddr(b)
		if err != nil {
			continue
		}
		switch {
		case a.IsUnspecified():
			wild = true
		case a.IsLoopback():
			add(a.String())
		}
	}
	if wild {
		add("127.0.0.1")
		add("::1")
	}
	for _, b := range bind {
		if a, err := netip.ParseAddr(b); err == nil && !a.IsUnspecified() && !a.IsLoopback() {
			add(a.Unmap().String())
		}
	}
	return out
}

// HealthClient returns an HTTPS client that trusts only the CA in caPEM
// (the local CA; no system roots) and verifies the server name "localhost".
func HealthClient(caPEM []byte, timeout time.Duration) (*http.Client, error) {
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return nil, errors.New("no PEM certificate in the local CA file")
	}
	tr := &http.Transport{
		TLSClientConfig:   &tls.Config{RootCAs: pool, ServerName: "localhost", MinVersion: tls.VersionTLS12},
		DisableKeepAlives: true,
		Proxy:             nil,
		DialContext:       (&net.Dialer{Timeout: timeout}).DialContext,
	}
	return &http.Client{Transport: tr, Timeout: timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}, nil
}

// HealthCheck performs GET https://127.0.0.1:<port>/healthz (and the other
// HealthTargets) pinned to the local CA of h (DESIGN §14.2, §14.7). port 0
// means server.https_port from fileparcel.toml (env overrides applied). It
// returns nil on the first 200 answer, or when the server (its certificate
// verified) refuses the probe for lack of a client certificate
// (mtls.mode=required without share exemptions; see clientCertRequired).
func HealthCheck(ctx context.Context, h *home.Home, port int, timeout time.Duration) error {
	_, err := HealthCheckURL(ctx, h, port, timeout)
	return err
}

// HealthCheckURL is HealthCheck and additionally returns the URL that
// answered, so callers can report exactly what was probed.
func HealthCheckURL(ctx context.Context, h *home.Home, port int, timeout time.Duration) (string, error) {
	bind := []string{"::"}
	if cfg, err := config.Load(h); err == nil {
		if port <= 0 {
			port = cfg.Server.HTTPSPort
		}
		bind = cfg.Server.Bind
	} else if port <= 0 {
		return "", err
	}
	ca, err := os.ReadFile(CACertPath(h))
	if err != nil {
		return "", fmt.Errorf("local CA: %w", err)
	}
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	client, err := HealthClient(ca, timeout)
	if err != nil {
		return "", err
	}
	var errs []string
	for _, addr := range HealthTargets(bind) {
		u := "https://" + net.JoinHostPort(addr, strconv.Itoa(port)) + "/healthz"
		err := probe(ctx, client, u)
		if err == nil {
			return u, nil
		}
		errs = append(errs, err.Error())
	}
	return "", errors.New(strings.Join(errs, "; "))
}

func probe(ctx context.Context, c *http.Client, u string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", "fileparcel-healthcheck")
	resp, err := c.Do(req)
	if err != nil {
		if clientCertRequired(err) {
			return nil
		}
		return fmt.Errorf("%s: %w", u, err)
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%s: HTTP %d", u, resp.StatusCode)
	}
	return nil
}

// clientCertRequired reports whether err is the server's TLS 1.3
// "certificate required" alert: with mtls.mode=required and
// mtls.exempt_shares off the server refuses every connection without a
// client certificate, /healthz included, and the probe has none. The alert
// arrives only after the client verified the server's certificate against
// the local CA (HealthClient), so it proves this home's server is up and
// serving TLS — what /healthz (liveness: always "ok") would have answered.
func clientCertRequired(err error) bool {
	var op *net.OpError
	return errors.As(err, &op) && op.Op == "remote error" && op.Err != nil &&
		op.Err.Error() == "tls: certificate required"
}

// WaitHealthy polls HealthCheck every interval until it succeeds or total
// elapses (DESIGN §14.2: 30 s after an upgrade). It returns the last error.
func WaitHealthy(ctx context.Context, h *home.Home, port int, total, interval time.Duration) error {
	if interval <= 0 {
		interval = 500 * time.Millisecond
	}
	ctx, cancel := context.WithTimeout(ctx, total)
	defer cancel()
	var last error
	for {
		if last = HealthCheck(ctx, h, port, 3*time.Second); last == nil {
			return nil
		}
		select {
		case <-ctx.Done():
			if last == nil {
				last = ctx.Err()
			}
			return fmt.Errorf("server not healthy after %s: %w", total, last)
		case <-time.After(interval):
		}
	}
}
