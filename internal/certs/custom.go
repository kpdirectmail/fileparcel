package certs

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"slices"
	"time"

	"fileparcel/internal/core"
)

// Size limits of uploaded PEM material.
const (
	MaxCustomCertPEM = 64 << 10
	MaxCustomKeyPEM  = 16 << 10
)

// validateCustom checks an uploaded chain and key (DESIGN §10.4): PEM
// parses, the key matches the leaf, the leaf is currently valid, usable for
// TLS servers and carries SANs, and the chain is in order (each certificate
// signed by the next one).
func validateCustom(certPEMData, keyPEMData []byte, now time.Time) ([]*x509.Certificate, error) {
	if len(certPEMData) == 0 {
		return nil, core.Invalid("cert_pem", "the certificate chain is required")
	}
	if len(keyPEMData) == 0 {
		return nil, core.Invalid("key_pem", "the private key is required")
	}
	if len(certPEMData) > MaxCustomCertPEM {
		return nil, core.Invalid("cert_pem", "the certificate chain is too large")
	}
	if len(keyPEMData) > MaxCustomKeyPEM {
		return nil, core.Invalid("key_pem", "the private key is too large")
	}
	chain, err := parseCertsPEM(certPEMData)
	if err != nil {
		return nil, core.Invalid("cert_pem", "cannot parse the certificate chain: "+err.Error())
	}
	key, err := parseKeyPEM(keyPEMData)
	if err != nil {
		return nil, core.Invalid("key_pem", "cannot parse the private key: "+err.Error())
	}
	leaf := chain[0]
	if !publicKeysEqual(leaf.PublicKey, key.Public()) {
		return nil, core.Invalid("key_pem", "the private key does not match the certificate")
	}
	if err := checkValidity(leaf, now); err != nil {
		return nil, core.Invalid("cert_pem", err.Error())
	}
	if leaf.IsCA {
		return nil, core.Invalid("cert_pem", "the first certificate must be the server certificate, not a CA")
	}
	if len(leaf.DNSNames) == 0 && len(leaf.IPAddresses) == 0 {
		return nil, core.Invalid("cert_pem", "the certificate has no DNS or IP subject alternative names")
	}
	if len(leaf.ExtKeyUsage) > 0 && !slices.Contains(leaf.ExtKeyUsage, x509.ExtKeyUsageServerAuth) &&
		!slices.Contains(leaf.ExtKeyUsage, x509.ExtKeyUsageAny) {
		return nil, core.Invalid("cert_pem", "the certificate is not valid for TLS servers (extended key usage)")
	}
	for i := 0; i+1 < len(chain); i++ {
		if err := chain[i].CheckSignatureFrom(chain[i+1]); err != nil {
			return nil, core.Invalid("cert_pem", fmt.Sprintf("the chain is not in order: certificate %d is not signed by certificate %d", i+1, i+2))
		}
	}
	return chain, nil
}

// SetCustom implements core.Certs: installs an uploaded certificate chain
// and key (key sealed at rest). It is served for the names it covers.
func (svc *Service) SetCustom(ctx context.Context, by *core.Principal, certPEMData, keyPEMData []byte) error {
	entry := core.AuditEntry{Action: core.ActCertCustomSet, TargetType: "certificate", TargetName: "custom"}
	chain, err := validateCustom(certPEMData, keyPEMData, svc.env.Now())
	if err != nil {
		entry.Outcome = core.OutcomeFailure
		entry.Details = map[string]any{"error": err.Error()}
		svc.audit(ctx, entry)
		return err
	}
	key, _ := parseKeyPEM(keyPEMData) // validated above
	if !svc.keysUnlocked() {
		return core.ErrKeysLocked
	}
	svc.opMu.Lock()
	defer svc.opMu.Unlock()
	if err := svc.sealKeyFile(fileCustomKey, aadCustomKey, key); err != nil {
		return err
	}
	var pemChain []byte
	for _, c := range chain {
		pemChain = append(pemChain, certPEM(c.Raw)...)
	}
	if err := writeFileAtomic(svc.path(fileCustomCert), pemChain, 0o644); err != nil {
		return err
	}
	next := svc.snapshot().clone()
	next.customCert = chain[0]
	next.custom = tlsCert(chain, key)
	svc.state.Store(next)
	svc.publishChanged()
	info := certInfo(chain[0], core.CertSourceCustom)
	entry.Details = map[string]any{"names": append(info.DNSNames, info.IPs...), "issuer": info.Issuer,
		"not_after": info.NotAfter.Format(time.RFC3339), "fingerprint": info.Fingerprint}
	svc.audit(ctx, entry)
	return nil
}

// ClearCustom implements core.Certs: removes the uploaded certificate.
func (svc *Service) ClearCustom(ctx context.Context, by *core.Principal) error {
	svc.opMu.Lock()
	defer svc.opMu.Unlock()
	st := svc.snapshot()
	if st.customCert == nil {
		if b, _ := readOptional(svc.path(fileCustomKey)); b == nil {
			return core.NotFoundf("no custom certificate is installed")
		}
	}
	release := svc.lockKeyFiles() // a rotation must not re-create the key file
	err := errors.Join(removeOptional(svc.path(fileCustomCert)), removeOptional(svc.path(fileCustomKey)))
	release()
	if err != nil {
		return err
	}
	next := st.clone()
	next.customCert, next.custom = nil, nil
	svc.state.Store(next)
	svc.publishChanged()
	svc.audit(ctx, core.AuditEntry{Action: core.ActCertCustomClear, TargetType: "certificate", TargetName: "custom"})
	return nil
}
