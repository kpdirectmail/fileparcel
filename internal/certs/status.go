package certs

import (
	"context"
	"crypto/tls"
	"strings"

	"fileparcel/internal/core"
)

// defaultServerName is the name used for the "publicly trusted" and HSTS
// verdict of Status: the public_url host, else the first SAN host name.
func (svc *Service) defaultServerName() string {
	if h := svc.publicURLHost(); h != "" {
		return h
	}
	if svc.net != nil {
		for _, n := range svc.net.Hostnames() {
			if n = strings.TrimSuffix(strings.ToLower(n), "."); n != "" && n != "localhost" {
				return n
			}
		}
	}
	return "localhost"
}

// hstsOn applies tls.hsts for serverName (DESIGN §9.2).
func (svc *Service) hstsOn(serverName string) bool {
	switch svc.settingString(KeyHSTS) {
	case "on":
		return true
	case "off":
		return false
	}
	return svc.PubliclyTrusted(serverName)
}

// Status implements core.Certs: every certificate with its source, names,
// validity, issuer and fingerprint, the CA's name constraints, ACME and
// Tailscale state, the mTLS mode and the HSTS / public-trust verdict for the
// default server name. Works offline and while the keys are locked.
func (svc *Service) Status(ctx context.Context) (*core.CertStatus, error) {
	st := svc.snapshot()
	cs := &core.CertStatus{
		CA:          certInfo(st.ca, core.CertSourceLocal),
		ClientCA:    certInfo(st.clientCA, core.CertSourceLocal),
		Custom:      certInfo(st.customCert, core.CertSourceCustom),
		ACMEEnabled: svc.settingBool(KeyACMEEnabled),
		ACMEError:   loadString(&svc.acmeErr),
		MTLSMode:    svc.mtlsMode(),
	}
	cs.CAConstrained, cs.PermittedDNS, cs.PermittedIPs = constraintsOf(st.ca)
	if st.leaf != nil {
		cs.Leaf = certInfo(st.leaf.Leaf, core.CertSourceLocal)
	}
	// Only while tailscale.cert_enabled is on: a stored certificate is not
	// served otherwise (certFor), nor renewed, so reporting it (or the last
	// fetch error) drove "certificate problem" and, ~90 days later,
	// "certificate expired" warnings about something nobody is served.
	if svc.settingBool(KeyTailscaleCert) {
		cs.TailscaleError = loadString(&svc.tsErr)
		if st.tailscale != nil {
			cs.Tailscale = certInfo(st.tailscale.Leaf, core.CertSourceTailscale)
		}
	}
	for _, c := range svc.acme.Load().certificates() {
		cs.ACME = append(cs.ACME, *certInfo(c, core.CertSourceACME))
	}
	if cs.Custom != nil && st.custom == nil && !svc.keysUnlocked() {
		cs.Custom.Source = core.CertSourceCustom + " (key locked)"
	}
	name := svc.defaultServerName()
	cs.PubliclyTrusted = svc.PubliclyTrusted(name)
	cs.HSTS = svc.hstsOn(name)
	return cs, nil
}

// ServedSource reports which certificate source answers a handshake for
// serverName (acme, tailscale, custom or local); "" when none is available.
func (svc *Service) ServedSource(serverName string) string {
	c, src := svc.certFor(&tls.ClientHelloInfo{ServerName: strings.ToLower(serverName)})
	if c == nil {
		return ""
	}
	return src
}
