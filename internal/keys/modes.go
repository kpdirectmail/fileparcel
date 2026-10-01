package keys

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"fileparcel/internal/core"
	"fileparcel/internal/crypt"
	"fileparcel/internal/ids"
)

// Seal switches plain → sealed: the MK is sealed with a key derived from
// newPass (argon2id, fresh salt). An existing recovery slot is kept.
func (s *Service) Seal(ctx context.Context, newPass []byte) error {
	s.opMu.Lock()
	defer s.opMu.Unlock()
	if err := s.requireUnlocked(); err != nil {
		return err
	}
	if s.mode() != core.KeyModePlain {
		return core.Errorf(core.ErrConflict, "the master key is already sealed")
	}
	if err := checkPassphrase("passphrase", newPass); err != nil {
		return err
	}
	details, err := s.committed(s.writeSealed(newPass), nil)
	if err != nil {
		s.audit(ctx, core.ActKeysSeal, core.OutcomeFailure, nil)
		return err
	}
	s.audit(ctx, core.ActKeysSeal, core.OutcomeSuccess, details)
	s.publishState()
	s.log.Info("master key sealed with a passphrase")
	return nil
}

// Unseal switches sealed → plain after checking pass (the passphrase or the
// recovery key). The recovery slot is kept.
func (s *Service) Unseal(ctx context.Context, pass []byte) error {
	s.opMu.Lock()
	defer s.opMu.Unlock()
	if err := s.requireUnlocked(); err != nil {
		return err
	}
	if s.mode() != core.KeyModeSealed {
		return core.Errorf(core.ErrConflict, "the master key is not sealed")
	}
	if !s.verifySecret(pass) {
		s.audit(ctx, core.ActKeysUnseal, core.OutcomeFailure, map[string]any{"reason": "wrong passphrase or recovery key"})
		return errWrongSecret("passphrase")
	}
	kf := s.currentFile()
	if err := s.withMK(func(mk []byte) error {
		// replaceFile writes the key itself (marshalWith).
		kf.Mode, kf.Key, kf.KDF, kf.Nonce, kf.CT = core.KeyModePlain, "", nil, "", ""
		return kf.setEscrow(mk, escrowPass, nil)
	}); err != nil {
		return err
	}
	details, err := s.committed(s.replaceFile(kf, nil), nil)
	if err != nil {
		s.audit(ctx, core.ActKeysUnseal, core.OutcomeFailure, nil)
		return err
	}
	s.audit(ctx, core.ActKeysUnseal, core.OutcomeSuccess, details)
	s.publishState()
	s.log.Info("master key unsealed (plain mode)")
	return nil
}

// ChangePassphrase re-seals the MK under newPass. oldPass may be the current
// passphrase or the recovery key (forgotten-passphrase reset).
func (s *Service) ChangePassphrase(ctx context.Context, oldPass, newPass []byte) error {
	s.opMu.Lock()
	defer s.opMu.Unlock()
	if err := s.requireUnlocked(); err != nil {
		return err
	}
	if s.mode() != core.KeyModeSealed {
		return core.Errorf(core.ErrPrecondition, "the master key is not sealed; use seal to set a passphrase")
	}
	if err := checkPassphrase("new_passphrase", newPass); err != nil {
		return err
	}
	if !s.verifySecret(oldPass) {
		s.audit(ctx, core.ActKeysPassphrase, core.OutcomeFailure, map[string]any{"reason": "wrong passphrase or recovery key"})
		return errWrongSecret("current_passphrase")
	}
	details, err := s.committed(s.writeSealed(newPass), nil)
	if err != nil {
		s.audit(ctx, core.ActKeysPassphrase, core.OutcomeFailure, nil)
		return err
	}
	s.audit(ctx, core.ActKeysPassphrase, core.OutcomeSuccess, details)
	s.log.Info("master key passphrase changed")
	return nil
}

// ExportRecovery creates a new recovery key (returned once) and replaces the
// recovery slot of keys/master.key; the previous recovery key stops working.
func (s *Service) ExportRecovery(ctx context.Context) (string, error) {
	s.opMu.Lock()
	defer s.opMu.Unlock()
	if err := s.requireUnlocked(); err != nil {
		return "", err
	}
	raw := crypt.RandomBytes(recoveryRawSize)
	rk := formatRecoveryKey(raw)
	rh := recoveryHash(raw)
	crypt.Zero(raw)
	defer crypt.Zero(rh)
	kf := s.currentFile()
	if err := s.withMK(func(mk []byte) (err error) {
		if kf.Recovery, err = sealBox(rh, mk, aadRecovery(kf.MKID)); err != nil {
			return err
		}
		return kf.setEscrow(mk, escrowRecovery, rh)
	}); err != nil {
		return "", err
	}
	// Once the new file is in place the new recovery key is the only one
	// that opens it, so it is returned even if a follow-up step failed.
	details, err := s.committed(s.replaceFile(kf, func(m *material) {
		m.vault.release(m.recKey)
		m.recKey = m.vault.put(rh)
	}), map[string]any{"mode": kf.Mode})
	if err != nil {
		s.audit(ctx, core.ActKeysRecoveryExport, core.OutcomeFailure, nil)
		return "", err
	}
	s.audit(ctx, core.ActKeysRecoveryExport, core.OutcomeSuccess, details)
	s.log.Info("new recovery key exported")
	return rk, nil
}

// writeSealed writes a sealed key file for the current MK under a key
// derived from pass (fresh salt) and caches that key.
func (s *Service) writeSealed(pass []byte) error {
	kf := s.currentFile()
	kf.Mode, kf.Key = core.KeyModeSealed, ""
	kf.KDF = newKDF(s.kdf)
	pk, err := deriveKey(pass, kf.KDF)
	if err != nil {
		return err
	}
	defer crypt.Zero(pk)
	if err := s.withMK(func(mk []byte) error {
		box, err := sealBox(pk, mk, aadMK(kf.MKID))
		if err != nil {
			return err
		}
		kf.Nonce, kf.CT = box.Nonce, box.CT
		return kf.setEscrow(mk, escrowPass, pk)
	}); err != nil {
		return err
	}
	return s.replaceFile(kf, func(m *material) {
		m.vault.release(m.passKey)
		m.passKey = m.vault.put(pk)
	})
}

// verifySecret reports whether secret opens the current key file (as the
// passphrase or the recovery key) and yields the loaded MK.
func (s *Service) verifySecret(secret []byte) bool {
	if len(secret) == 0 || len(secret) > MaxPassphraseLen+64 {
		return false
	}
	s.mu.RLock()
	kf := s.file
	s.mu.RUnlock()
	mk, pk, rh, _ := openMaster(kf, secret)
	defer crypt.Zero(mk)
	defer crypt.Zero(pk)
	defer crypt.Zero(rh)
	if mk == nil {
		return false
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.m != nil && ids.EqualBytes(mk, s.m.mk.b)
}

// replaceFile atomically writes kf as keys/master.key and makes it current;
// update (optional) adjusts the cached material under the write lock. An
// error before the rename leaves everything as it was. Once the new file is
// in place, memory follows it whatever fails next (the directory fsync,
// removing a stale master.key.next): such a failure comes back as a
// *committedError, which the callers report as a warning of a change that
// took effect (committed), never as "nothing changed".
func (s *Service) replaceFile(kf *keyFile, update func(*material)) error {
	var data []byte
	if err := s.withMK(func(mk []byte) error {
		data = kf.marshalWith(mk)
		return nil
	}); err != nil {
		return err
	}
	defer clear(data)
	err := writeFileAtomic(s.path, data, 0o600)
	var nd *notDurableError
	if err != nil && !errors.As(err, &nd) {
		return fmt.Errorf("keys: write %s: %w", s.path, err)
	}
	s.mu.Lock()
	s.file = kf
	if update != nil && s.m != nil {
		update(s.m)
	}
	if kf.Mode == core.KeyModePlain && s.m != nil {
		s.m.vault.release(s.m.passKey)
		s.m.passKey = nil
	}
	s.mu.Unlock()
	if derr := s.dropStaleNext(); derr != nil {
		err = errors.Join(err, derr)
	}
	if err != nil {
		return &committedError{fmt.Errorf("keys: %s was replaced and is in use, but: %w", s.path, err)}
	}
	return nil
}

// committedError is returned by replaceFile for a failure after the new key
// file was renamed into place: the change took effect.
type committedError struct{ err error }

func (e *committedError) Error() string { return e.err.Error() }
func (e *committedError) Unwrap() error { return e.err }

// committed sorts a replaceFile error for the callers: a committedError
// means the new key file is in place and in use, so the operation succeeded;
// the problem is logged and added to the audit details (details may be
// nil). Any other error is returned unchanged.
func (s *Service) committed(err error, details map[string]any) (map[string]any, error) {
	var ce *committedError
	if !errors.As(err, &ce) {
		return details, err
	}
	s.log.Error("the key file change is in effect, but a follow-up step failed", "err", ce.err)
	if details == nil {
		details = map[string]any{}
	}
	details["warning"] = ce.err.Error()
	return details, nil
}

// dropStaleNext removes a keys/master.key.next left behind by a rotation
// whose final rename failed. It is only called after master.key itself was
// rewritten, which makes the .next stale by definition: recoverNext would
// otherwise rename it over master.key on the next start (its mk_id matches
// meta.mk_id, so it wins) and silently undo this write — reverting a new
// passphrase or a fresh recovery key, and putting a plain master key back
// on disk after a Seal.
func (s *Service) dropStaleNext() error {
	next := s.path + fileSuffixNx
	if err := os.Remove(next); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil
		}
		return fmt.Errorf("remove the stale %s by hand before the next start, which would otherwise undo this change: %w", next, err)
	}
	if err := syncDir(filepath.Dir(s.path)); err != nil {
		return fmt.Errorf("keys: %w", err)
	}
	s.log.Warn("removed a stale key file from an interrupted master key rotation", "file", next)
	return nil
}

// currentFile returns a copy of the current key file.
func (s *Service) currentFile() *keyFile {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.file.clone()
}

// withMK runs fn with the master key under the read lock (errLocked when
// the keys are not available).
func (s *Service) withMK(fn func(mk []byte) error) error {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.m == nil {
		return errLocked
	}
	return fn(s.m.mk.b)
}
