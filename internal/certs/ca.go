package certs

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"os"
	"slices"
	"strings"

	"fileparcel/internal/core"
	"fileparcel/internal/crypt"
)

// sealKeyFile seals a private key (PKCS#8 DER) with the field KEK and writes
// it atomically (0600). The marshalled key is zeroed on every path. Sealing
// and writing run under the key-file lock (lockKeyFiles), so a field KEK
// rotation re-sealing the same file cannot put the previous key back.
func (svc *Service) sealKeyFile(rel, aad string, key crypto.PrivateKey) error {
	if svc.env.Keys == nil {
		return errNoKeys
	}
	der, err := keyPKCS8(key)
	if err != nil {
		return err
	}
	defer crypt.Zero(der)
	release := svc.lockKeyFiles()
	defer release()
	sealed, err := svc.env.Keys.SealField(aad, der)
	if err != nil {
		return err
	}
	return writeFileAtomic(svc.path(rel), []byte(sealed+"\n"), 0o600)
}

// keyFileLocker is implemented by *keys.Service: it serialises writes of the
// sealed key files with a field KEK rotation, which re-seals them.
type keyFileLocker interface{ LockKeyFiles() func() }

// lockKeyFiles takes the key-file lock of the keys service (a no-op without
// one) until the returned func is called. Hold it around sealing and
// writing, or removing, a sealed key file.
func (svc *Service) lockKeyFiles() func() {
	if l, ok := svc.env.Keys.(keyFileLocker); ok {
		return l.LockKeyFiles()
	}
	return func() {}
}

// openSealedKey reads and unseals a key written by sealKeyFile.
func (svc *Service) openSealedKey(rel, aad string) (crypto.Signer, error) {
	if svc.env.Keys == nil {
		return nil, errNoKeys
	}
	b, err := os.ReadFile(svc.path(rel))
	if err != nil {
		if os.IsNotExist(err) {
			return nil, core.Errorf(core.ErrPrecondition, "private key %s is missing", rel)
		}
		return nil, err
	}
	der, err := svc.env.Keys.OpenField(aad, strings.TrimSpace(string(b)))
	if err != nil {
		return nil, err
	}
	key, err := parsePrivateKey(der)
	crypt.Zero(der)
	if err != nil {
		return nil, core.Wrap(core.ErrCorrupt, "", fmt.Errorf("%s: %w", rel, err))
	}
	return key, nil
}

// caName returns "<prefix> (<server name> <install id[:8]>)".
func (svc *Service) caName(prefix string) string {
	name, id := "fileparcel", ""
	if c := svc.env.Config; c != nil {
		if c.Server.Name != "" {
			name = c.Server.Name
		}
		id = c.InstallID
	}
	if len(id) > 8 {
		id = id[:8]
	}
	if id == "" {
		return fmt.Sprintf("%s (%s)", prefix, name)
	}
	return fmt.Sprintf("%s (%s %s)", prefix, name, id)
}

// caConstraints computes the name constraints of a constrained local CA
// (DESIGN §10.4): .local, local, localhost, .ts.net, the machine hostname,
// the current SAN host names, tls.extra_sans and the public_url host; the
// private ranges of §10.3, the host's global IPv6 /64s and global IPv4
// addresses, and IP entries of tls.extra_sans. A name that is itself a
// public suffix (a host called "dev", "*.com" in tls.extra_sans) is left
// out: the constraint would permit the whole TLD. desiredSANs then drops it
// from the leaf and reports it as uncovered; <host>.local still works.
func (svc *Service) caConstraints() (dns []string, ips []netip.Prefix) {
	dns = slices.Clone(baseDNSConstraints)
	addDNS := func(name string) {
		name = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(name)), ".")
		if name == "" || !validDNSName(name, true) {
			return
		}
		if d := constraintDomain(name); d != "" && !publicSuffixConstraint(d) && !slices.Contains(dns, d) {
			dns = append(dns, d)
		}
	}
	if h, err := os.Hostname(); err == nil {
		addDNS(h)
	}
	if svc.net != nil {
		for _, n := range svc.net.Hostnames() {
			addDNS(n)
		}
	}
	ips = slices.Clone(privatePrefixes)
	addIP := func(p netip.Prefix) {
		p = p.Masked()
		for _, q := range ips {
			if q.Bits() <= p.Bits() && q.Contains(p.Addr()) {
				return
			}
		}
		ips = append(ips, p)
	}
	for _, s := range svc.settingStrings(KeyExtraSANs) {
		if ip, err := netip.ParseAddr(s); err == nil {
			ip = ip.Unmap()
			addIP(netip.PrefixFrom(ip, ip.BitLen()))
		} else {
			addDNS(s)
		}
	}
	if c := svc.env.Config; c != nil && c.Server.PublicURL != "" {
		if u, err := url.Parse(c.Server.PublicURL); err == nil && u.Hostname() != "" {
			if ip, err := netip.ParseAddr(u.Hostname()); err == nil {
				ip = ip.Unmap()
				addIP(netip.PrefixFrom(ip, ip.BitLen()))
			} else {
				addDNS(u.Hostname())
			}
		}
	}
	if svc.net != nil {
		for _, ip := range svc.net.IPs() {
			ip = ip.Unmap()
			if !ip.IsGlobalUnicast() || IsPrivate(ip) {
				continue
			}
			if ip.Is6() {
				p, _ := ip.Prefix(64)
				addIP(p)
			} else {
				addIP(netip.PrefixFrom(ip, 32))
			}
		}
	}
	return dns, ips
}

// newCATemplate returns a CA certificate template (pathlen 0, cert+CRL sign).
func (svc *Service) newCATemplate(cn string) (*x509.Certificate, error) {
	serial, err := newSerial()
	if err != nil {
		return nil, err
	}
	now := svc.env.Now()
	return &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: cn, Organization: []string{"FileParcel"}},
		NotBefore:             now.Add(-backdate),
		NotAfter:              now.Add(caValidity),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0,
		MaxPathLenZero:        true,
	}, nil
}

// createCA generates and stores a new local CA (certificate + sealed key).
// The CA only ever signs the serverAuth leaf, so its EKU is serverAuth,
// constrained or not: a device that trusts it as a root (Windows, macOS
// "Always Trust") must not accept code-signing or S/MIME certificates made
// with a leaked key. The constrained CA also permits no e-mail addresses
// (rfc822Name ".invalid"): name types without a constraint stay open.
func (svc *Service) createCA(ctx context.Context, constrained bool) (*x509.Certificate, error) {
	tmpl, err := svc.newCATemplate(svc.caName("FileParcel Local CA"))
	if err != nil {
		return nil, err
	}
	tmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
	if constrained {
		dns, ips := svc.caConstraints()
		tmpl.PermittedDNSDomainsCritical = true
		tmpl.PermittedDNSDomains = dns
		for _, p := range ips {
			tmpl.PermittedIPRanges = append(tmpl.PermittedIPRanges, toIPNet(p))
		}
		tmpl.PermittedEmailAddresses = []string{".invalid"}
	}
	return svc.selfSign(tmpl, fileCACert, fileCAKey, aadCAKey)
}

// createClientCA generates and stores the separate mTLS client CA. Its EKU
// is clientAuth (it signs nothing else), so it can never vouch for a server.
// It carries no name constraints: with any constraint in the chain,
// crypto/x509 rejects the host-less SAN URI fileparcel:user:<id> of every
// client certificate.
func (svc *Service) createClientCA(ctx context.Context) (*x509.Certificate, error) {
	tmpl, err := svc.newCATemplate(svc.caName("FileParcel Client CA"))
	if err != nil {
		return nil, err
	}
	tmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	return svc.selfSign(tmpl, fileClientCACert, fileClientCAKey, aadClientCAKey)
}

// publicSuffixConstraints returns the DNS constraints of ca that span a
// public suffix (see publicSuffixConstraint) — present in CAs created before
// such names were left out; only regenerating the CA removes them.
func publicSuffixConstraints(ca *x509.Certificate) []string {
	if ca == nil {
		return nil
	}
	var out []string
	for _, d := range ca.PermittedDNSDomains {
		if slices.Contains(baseDNSConstraints, d) { // .ts.net is deliberate
			continue
		}
		if publicSuffixConstraint(strings.ToLower(d)) {
			out = append(out, d)
		}
	}
	return out
}

// selfSign creates a self-signed CA from tmpl, seals its key and writes both
// files (key first, so a certificate on disk always has its key).
func (svc *Service) selfSign(tmpl *x509.Certificate, certRel, keyRel, aad string) (*x509.Certificate, error) {
	if svc.env.Keys == nil || svc.env.Keys.State() != core.KeyStateUnlocked {
		return nil, core.ErrKeysLocked
	}
	key, err := newKey()
	if err != nil {
		return nil, err
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		return nil, fmt.Errorf("certs: create CA: %w", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	if err := svc.sealKeyFile(keyRel, aad, key); err != nil {
		return nil, err
	}
	if err := writeFileAtomic(svc.path(certRel), certPEM(der), 0o644); err != nil {
		return nil, err
	}
	return cert, nil
}

// RegenerateCA implements core.Certs: replaces the local CA (constrained or
// not) and reissues the leaf. Every device must trust the new CA again.
func (svc *Service) RegenerateCA(ctx context.Context, by *core.Principal, constrained bool) error {
	svc.opMu.Lock()
	defer svc.opMu.Unlock()
	entry := core.AuditEntry{Action: core.ActCARegenerate, TargetType: "ca", Details: map[string]any{"constrained": constrained}}
	fail := func(err error) error {
		entry.Outcome = core.OutcomeFailure
		svc.audit(ctx, entry)
		return err
	}
	ca, err := svc.createCA(ctx, constrained)
	if err != nil {
		return fail(err)
	}
	st := svc.snapshot().clone()
	st.ca = ca
	leaf, err := svc.issueLeaf(ctx, ca)
	if err != nil {
		// The new CA is stored; keep serving the old leaf until a renewal
		// works (leafNeedsRenewal reports "ca_changed").
		svc.state.Store(st)
		svc.pendingRenew.Store(true)
		svc.publishChanged()
		return fail(err)
	}
	st.leaf = leaf
	svc.state.Store(st)
	svc.publishChanged()
	entry.TargetName = ca.Subject.CommonName
	entry.Details = map[string]any{"constrained": constrained, "fingerprint": fingerprint(ca.Raw)}
	svc.audit(ctx, entry)
	if !constrained {
		svc.log.Warn("the local CA was regenerated WITHOUT name constraints; it can sign certificates for any name")
	}
	svc.log.Info("local CA regenerated", "fingerprint", fingerprint(ca.Raw), "constrained", constrained)
	return nil
}

// constraintsOf returns the permitted names of ca for the status view.
func constraintsOf(ca *x509.Certificate) (constrained bool, dns, ips []string) {
	if ca == nil {
		return false, nil, nil
	}
	for _, n := range ca.PermittedIPRanges {
		ips = append(ips, (&net.IPNet{IP: n.IP, Mask: n.Mask}).String())
	}
	dns = slices.Clone(ca.PermittedDNSDomains)
	return len(dns) > 0 || len(ips) > 0, dns, ips
}
