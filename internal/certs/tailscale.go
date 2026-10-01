package certs

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net/http"
	"path/filepath"
	"strings"
	"time"

	"fileparcel/internal/core"
	"fileparcel/internal/tslocal"
)

// tsClient returns the tailscaled client for certificate fetches: the same
// daemon, sockets and CLI fallback as Tailscale detection (netinfo), so a
// certificate the admin page offers can also be fetched (replaced in tests).
var tsClient = tslocal.Default

// tailscaleName returns the FQDN to fetch a certificate for:
// tailscale.domain or the MagicDNS name of this node.
func (svc *Service) tailscaleName(ctx context.Context) (string, error) {
	if n := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(svc.settingString(KeyTailscaleName))), "."); n != "" {
		return n, nil
	}
	if svc.net == nil {
		return "", core.Errorf(core.ErrPrecondition, "network information is unavailable")
	}
	info, err := svc.net.Tailscale(ctx)
	if err != nil {
		return "", core.Wrap(core.ErrPrecondition, "cannot query Tailscale: "+err.Error(), err)
	}
	if info == nil || !info.Running || info.DNSName == "" {
		return "", core.Errorf(core.ErrPrecondition, "Tailscale is not running or MagicDNS has no name for this machine")
	}
	return strings.TrimSuffix(strings.ToLower(info.DNSName), "."), nil
}

// FetchTailscale implements core.Certs: fetches a certificate for the
// MagicDNS name from tailscaled (LocalAPI, falling back to the tailscale
// CLI), stores it in certs/tailscale/ and serves it for that name.
func (svc *Service) FetchTailscale(ctx context.Context) error {
	name, err := svc.tailscaleName(ctx)
	if err != nil {
		svc.tsErr.Store(errString(err))
		return err
	}
	entry := core.AuditEntry{Action: core.ActCertTailscale, TargetType: "certificate", TargetName: name}
	fail := func(err error) error {
		svc.tsErr.Store(errString(err))
		entry.Outcome = core.OutcomeFailure
		entry.Details = map[string]any{"error": errText(err)}
		svc.audit(ctx, entry)
		return err
	}
	certPEMData, keyPEMData, err := svc.fetchTailscalePair(ctx, name)
	if err != nil {
		msg := "Tailscale certificate: " + err.Error()
		if svc.onHeadscale(ctx) {
			msg += " (Headscale has no ts.net certificates: juanfont/headscale#1921)"
		}
		return fail(core.Wrap(core.ErrUnavailable, msg, err))
	}
	kp, err := tls.X509KeyPair(certPEMData, keyPEMData)
	if err != nil {
		return fail(core.Wrap(core.ErrUnavailable, "Tailscale returned an unusable certificate", err))
	}
	if kp.Leaf == nil || kp.Leaf.VerifyHostname(name) != nil {
		return fail(core.Errorf(core.ErrUnavailable, "the Tailscale certificate does not cover %s", name))
	}
	if err := checkValidity(kp.Leaf, svc.env.Now()); err != nil {
		return fail(core.Wrap(core.ErrUnavailable, "Tailscale certificate: "+err.Error(), err))
	}
	svc.opMu.Lock()
	err = writeFileAtomic(svc.path(fileTSKey), keyPEMData, 0o600)
	if err == nil {
		err = writeFileAtomic(svc.path(fileTSCert), certPEMData, 0o644)
	}
	if err == nil {
		next := svc.snapshot().clone()
		next.tailscale = &kp
		svc.state.Store(next)
	}
	svc.opMu.Unlock()
	if err != nil {
		return fail(err)
	}
	svc.tsErr.Store(nil)
	svc.publishChanged()
	entry.Details = map[string]any{"not_after": kp.Leaf.NotAfter.UTC().Format(time.RFC3339), "fingerprint": fingerprint(kp.Leaf.Raw)}
	svc.audit(ctx, entry)
	svc.log.Info("Tailscale certificate installed", "name", name, "not_after", kp.Leaf.NotAfter.UTC().Format(time.RFC3339))
	return nil
}

// fetchTailscalePair asks tailscaled for the pair (LocalAPI sockets, then
// `tailscale cert` into a private directory under certs/tailscale; see
// tslocal.Client.CertPair, which also bounds the wait).
func (svc *Service) fetchTailscalePair(ctx context.Context, name string) (certPEMData, keyPEMData []byte, err error) {
	c := *tsClient()
	c.TempDir = filepath.Dir(svc.path(fileTSCert))
	certPEMData, keyPEMData, err = c.CertPair(ctx, name)
	if err != nil {
		var ae *tslocal.APIError
		if errors.As(err, &ae) && ae.Status == http.StatusForbidden {
			err = fmt.Errorf("%w (allow this user with \"sudo tailscale set --operator=$USER\")", err)
		}
		return nil, nil, err
	}
	return certPEMData, keyPEMData, nil
}

// onHeadscale reports whether this node uses a self-hosted control server
// (for the hint on a failed fetch).
func (svc *Service) onHeadscale(ctx context.Context) bool {
	if svc.net == nil {
		return false
	}
	info, err := svc.net.Tailscale(ctx)
	return err == nil && info != nil && info.Kind == core.IfHeadscale
}

// tailscaleNeedsRefresh reports whether the Tailscale certificate is
// missing, expires within tsRenewBefore or no longer covers the name to
// serve (tailscaleNameStale).
func (svc *Service) tailscaleNeedsRefresh(ctx context.Context) bool {
	ts := svc.snapshot().tailscale
	if ts == nil || ts.Leaf == nil || ts.Leaf.NotAfter.Sub(svc.env.Now()) < tsRenewBefore {
		return true
	}
	return svc.tailscaleNameStale(ctx)
}

// tailscaleNameStale reports whether a stored Tailscale certificate does
// not cover the current name (tailscale.domain, or the MagicDNS name after
// the node or tailnet was renamed). An unknown name (Tailscale stopped)
// counts as not stale, so a stopped daemon does not cause fetch attempts.
func (svc *Service) tailscaleNameStale(ctx context.Context) bool {
	ts := svc.snapshot().tailscale
	if ts == nil {
		return false
	}
	name, err := svc.tailscaleName(ctx)
	return err == nil && !coversName(ts, name)
}
