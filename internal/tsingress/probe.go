package tsingress

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"sync"
	"time"

	"fileparcel/internal/core"
	"fileparcel/internal/ids"
)

// ProbePath is the path prefix of the self-probe: the ingress handler
// answers GET ProbePath+<nonce> with 204 when CheckProbe accepts the nonce.
const ProbePath = "/.well-known/fileparcel-ingress-probe/"

// probeNonce is the nonce of the probe in flight.
type probeNonce struct {
	value   string
	expires time.Time
}

// CheckProbe reports whether nonce is the one of kind's probe in flight
// (constant-time; it lives nonceTTL).
func (s *Service) CheckProbe(kind, nonce string) bool {
	i := kindIndex(kind)
	if i < 0 || nonce == "" {
		return false
	}
	p := s.nonce[i].Load()
	if p == nil || s.now().After(p.expires) {
		return false
	}
	return ids.Equal(p.value, nonce)
}

// scheduleProbe runs kind's self-probe after delay (while attached).
func (s *Service) scheduleProbe(kind string, delay time.Duration) {
	i := kindIndex(kind)
	s.stMu.Lock()
	defer s.stMu.Unlock()
	if s.lis == nil {
		return
	}
	if t := s.probeTimers[i]; t != nil {
		t.Stop()
	}
	ctx := s.attachCtx
	s.probeTimers[i] = time.AfterFunc(delay, func() { s.probeKind(ctx, kind) })
}

// probeNow re-runs the probes of the active kinds and waits for them up to
// probeWait (a slower probe announces its result with ingress.changed).
func (s *Service) probeNow(ctx context.Context) {
	var wg sync.WaitGroup
	for i, k := range kinds {
		s.stMu.Lock()
		run := s.lis != nil && s.kst[i].state == core.IngressStateActive
		actx := s.attachCtx
		s.stMu.Unlock()
		if !run {
			continue
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			s.probeKind(actx, k)
		}()
	}
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()
	t := time.NewTimer(s.t.probeWait)
	defer t.Stop()
	select {
	case <-done:
	case <-t.C:
	case <-ctx.Done():
	}
}

// probeKind runs one probe of kind, records the result and, while it fails
// and the entry is active, schedules the next one.
func (s *Service) probeKind(ctx context.Context, kind string) {
	i := kindIndex(kind)
	s.probeMu[i].Lock()
	defer s.probeMu[i].Unlock()
	if ctx.Err() != nil {
		return
	}
	s.stMu.Lock()
	ks := s.kst[i]
	s.stMu.Unlock()
	if ks.state != core.IngressStateActive {
		return
	}
	c := s.probe(ctx, kind, ks.proxy)
	if ctx.Err() != nil {
		return
	}
	now := s.now()
	s.stMu.Lock()
	if s.kst[i].state == core.IngressStateActive {
		s.kst[i].reachable, s.kst[i].probedAt = &c, &now
	}
	if s.probeTimers[i] != nil {
		s.probeTimers[i].Stop()
		s.probeTimers[i] = nil
	}
	if c.Status == statusWarn && s.lis != nil && s.kst[i].state == core.IngressStateActive {
		s.probeTimers[i] = time.AfterFunc(s.t.probeRetry, func() { s.probeKind(ctx, kind) })
	}
	s.stMu.Unlock()
	s.publish()
}

// probe sends GET ProbePath<nonce> through tailscaled to FileParcel's own
// entry over the tailnet (TLS to the node's first IPv4 Tailscale address
// with the MagicDNS name) and expects the 204 of the ingress handler. It
// cannot prove public DNS or the Funnel relays (DESIGN §10.6 "Self-probe").
func (s *Service) probe(ctx context.Context, kind, proxy string) core.IngressCheck {
	c := core.IngressCheck{ID: checkReachable, Label: "Reachable over the tailnet"}
	pol := s.Policy(kind)
	if pol.Mode == core.FunnelOff || pol.DNSName == "" || pol.Port == 0 {
		c.Status, c.Message = statusSkip, "Not published"
		return c
	}
	v := s.readView(ctx, s.t.statusTTL)
	var target netip.Addr
	if v.st != nil {
		for _, ip := range v.st.IPs() {
			if ip.Is4() && s.localAddr(ip) {
				target = ip
				break
			}
		}
	}
	if !target.IsValid() {
		c.Status = statusSkip
		c.Message = "Cannot be tested from this machine (no local interface has its Tailscale address)"
		return c
	}
	i := kindIndex(kind)
	n := &probeNonce{value: ids.Token(32), expires: s.now().Add(s.t.nonceTTL)}
	s.nonce[i].Store(n)
	defer s.nonce[i].CompareAndSwap(n, nil)

	addr := netip.AddrPortFrom(target, uint16(pol.Port)).String()
	host := pol.DNSName
	if pol.Port != 443 {
		host += ":" + strconv.Itoa(pol.Port)
	}
	pctx, cancel := context.WithTimeout(ctx, s.t.probeTimeout)
	defer cancel()
	status, err := s.probeOnce(pctx, addr, pol.DNSName, host, n.value, false)
	var verr *tls.CertificateVerificationError
	if err != nil && errors.As(err, &verr) {
		if st2, err2 := s.probeOnce(pctx, addr, pol.DNSName, host, n.value, true); err2 == nil && st2 == http.StatusNoContent {
			c.Status = statusWarn
			c.Message = "Tailscale reached FileParcel, but its certificate is not trusted yet (issuance pending)"
			return c
		}
	}
	switch {
	case err != nil:
		c.Status, c.Message = statusWarn, "The test request failed: "+err.Error()
	case status == http.StatusNoContent:
		c.Status, c.Message = statusOK, "Tailscale reached FileParcel"
	case status == http.StatusBadGateway:
		c.Status = statusWarn
		c.Message = "tailscaled cannot reach FileParcel's backend " + proxy
		c.Hint = "Does tailscaled run as another user or in a sandbox or SELinux domain? Try funnel.backend tcp."
	default:
		c.Status, c.Message = statusWarn, "Unexpected answer to the test request: HTTP "+strconv.Itoa(status)
	}
	return c
}

// probeOnce sends one probe request. insecure skips the certificate check:
// the second attempt only tells a pending certificate from an unreachable
// backend, and nothing is sent that needs protection.
func (s *Service) probeOnce(ctx context.Context, addr, serverName, host, nonce string, insecure bool) (int, error) {
	tr := &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) { return s.probeDial(ctx, "tcp", addr) },
		TLSClientConfig: &tls.Config{ServerName: serverName, RootCAs: s.probeRoots, MinVersion: tls.VersionTLS12,
			InsecureSkipVerify: insecure}, //nolint:gosec // see above
		DisableKeepAlives: true,
	}
	defer tr.CloseIdleConnections()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+host+ProbePath+nonce, nil)
	if err != nil {
		return 0, err
	}
	hc := &http.Client{Transport: tr, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := hc.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4<<10))
	return resp.StatusCode, nil
}
