package certs

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"

	"fileparcel/internal/core"
)

// loadState reads every certificate present on disk. Problems are logged and
// the affected certificate is treated as missing.
func (svc *Service) loadState() *state {
	st := &state{}
	if c, err := svc.loadCertFile(fileCACert); err != nil {
		svc.log.Warn("cannot load the local CA certificate", "err", err)
	} else {
		st.ca = c
	}
	if c, err := svc.loadCertFile(fileClientCACert); err != nil {
		svc.log.Warn("cannot load the client CA certificate", "err", err)
	} else if c != nil {
		st.clientCA = c
		st.clientPool = poolOf(c)
	}
	if kp, err := svc.loadLeafPair(); err != nil {
		svc.log.Warn("cannot load the local server certificate", "err", err)
	} else {
		st.leaf = withIssuer(kp, st.ca)
	}
	if kp, err := svc.loadKeyPair(fileTSCert, fileTSKey); err != nil {
		svc.log.Warn("cannot load the Tailscale certificate", "err", err)
	} else {
		st.tailscale = kp
	}
	svc.loadCustomInto(st)
	return st
}

// loadCertFile parses the first certificate of a PEM file (nil when missing).
func (svc *Service) loadCertFile(rel string) (*x509.Certificate, error) {
	b, err := readOptional(svc.path(rel))
	if err != nil || b == nil {
		return nil, err
	}
	certs, err := parseCertsPEM(b)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", rel, err)
	}
	return certs[0], nil
}

// loadKeyPair loads an unsealed PEM certificate chain and key (nil when
// either file is missing).
func (svc *Service) loadKeyPair(certRel, keyRel string) (*tls.Certificate, error) {
	cb, err := readOptional(svc.path(certRel))
	if err != nil || cb == nil {
		return nil, err
	}
	kb, err := readOptional(svc.path(keyRel))
	if err != nil || kb == nil {
		return nil, err
	}
	kp, err := tls.X509KeyPair(cb, kb)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", certRel, err)
	}
	return &kp, nil
}

// loadLeafPair loads the local leaf. When leaf.key is missing or does not
// match leaf.crt, a swap was interrupted after its commit point (issueLeaf)
// and the matching key is still staged as leaf.key.next. Nothing is written
// here: settleLeafKey completes the swap before the next one.
func (svc *Service) loadLeafPair() (*tls.Certificate, error) {
	kp, err := svc.loadKeyPair(fileLeafCert, fileLeafKey)
	if err == nil && kp != nil {
		return kp, nil
	}
	if staged, serr := svc.loadKeyPair(fileLeafCert, fileLeafKeyNext); serr == nil && staged != nil {
		svc.log.Info("using the staged key of an interrupted server certificate renewal", "file", fileLeafKeyNext)
		return staged, nil
	}
	return kp, err
}

// loadCustomInto loads the custom certificate (and its sealed key when the
// keys are unlocked) into st.
func (svc *Service) loadCustomInto(st *state) {
	cb, err := readOptional(svc.path(fileCustomCert))
	if err != nil {
		svc.log.Warn("cannot read the custom certificate", "err", err)
		return
	}
	if cb == nil {
		st.customCert, st.custom = nil, nil
		return
	}
	chain, err := parseCertsPEM(cb)
	if err != nil {
		svc.log.Warn("cannot parse the custom certificate", "err", err)
		return
	}
	st.customCert = chain[0]
	st.custom = nil
	if !svc.keysUnlocked() {
		return
	}
	key, err := svc.openSealedKey(fileCustomKey, aadCustomKey)
	if err != nil {
		svc.log.Warn("cannot open the custom certificate key", "err", err)
		return
	}
	if !publicKeysEqual(chain[0].PublicKey, key.Public()) {
		svc.log.Warn("the custom certificate key does not match the certificate")
		return
	}
	st.custom = tlsCert(chain, key)
}

// ensureCustomLoaded unseals the custom key once the keys become available.
func (svc *Service) ensureCustomLoaded() {
	if st := svc.snapshot(); st.customCert == nil || st.custom != nil || !svc.keysUnlocked() {
		return
	}
	svc.opMu.Lock()
	defer svc.opMu.Unlock()
	st := svc.snapshot()
	if st.customCert == nil || st.custom != nil {
		return
	}
	next := st.clone()
	svc.loadCustomInto(next)
	if next.custom != nil {
		svc.state.Store(next)
		svc.publishChanged()
	}
}

var errNoKeys = errors.New("certs: keys service unavailable")

// errKeyMismatch reports a sealed CA key that does not belong to the CA
// certificate on disk (e.g. a regeneration interrupted between writing the
// new key and the new certificate). Signing with it would produce
// certificates nobody can verify, so issuing refuses.
func errKeyMismatch(which string) error {
	return core.Errorf(core.ErrCorrupt, "the %s private key does not match its certificate; regenerate the CA", which)
}

// withIssuer appends ca to kp's presented chain when ca actually issued kp's
// leaf, so a client pinning the local CA (--fingerprint) receives the
// certificate it pinned. certs/server/leaf.crt itself stays leaf-only; only
// the in-memory chain grows. A stale or foreign CA is left out; the leaf is
// reissued by leafNeedsRenewal ("ca_changed") in that case.
func withIssuer(kp *tls.Certificate, ca *x509.Certificate) *tls.Certificate {
	if kp == nil || ca == nil || len(kp.Certificate) != 1 {
		return kp
	}
	leaf := kp.Leaf
	if leaf == nil {
		var err error
		if leaf, err = x509.ParseCertificate(kp.Certificate[0]); err != nil {
			return kp
		}
		kp.Leaf = leaf
	}
	if leaf.CheckSignatureFrom(ca) != nil {
		return kp
	}
	kp.Certificate = append(kp.Certificate, ca.Raw)
	return kp
}
