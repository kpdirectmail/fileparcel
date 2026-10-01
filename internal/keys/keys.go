// Package keys manages the master key file (plain or sealed), the keyring
// (KEKs), DEK wrapping, field encryption, MACs and rotation (DESIGN §7; owned
// by unit A).
//
// Key hierarchy: the 32-byte master key (MK) lives in keys/master.key, either
// in plain form (auto-unlock at start) or sealed with an argon2id-derived
// passphrase key (the server starts locked). The MK wraps one active KEK per
// purpose (blob, field, mac) in the keyring table; retired KEKs stay until
// nothing references them. KEK[blob] wraps per-blob DEKs, KEK[field] seals
// sensitive columns and key files, KEK[mac] derives HKDF subkeys for MACs.
//
// Concurrency: state-changing operations (Init, Unlock, Lock, Seal, Unseal,
// ChangePassphrase, ExportRecovery, RotateMaster and the keyring changes of
// RotateKEK) are serialised; the hot paths (NewDEK, UnwrapDEK, SealField,
// OpenField, MAC) only take a read lock. Key material is held in mlock'ed
// memory when possible and zeroed on Lock and Close.
//
// Recovery keys: a sealed Init creates one (returned once); plain-mode Init
// does not (the MK is on disk in plain form, so a recovery key would add no
// protection, and disaster recovery of a lost key file is the job of the
// backups, which contain keys/master.key). ExportRecovery replaces the
// recovery key in either mode; in plain mode the slot is kept so that a
// later Seal leaves it valid. Unlock, Unseal and ChangePassphrase accept the
// recovery key wherever they accept the passphrase, so a forgotten
// passphrase is reset with ChangePassphrase(recoveryKey, newPassphrase).
// A recovery key only unwraps the MK stored in keys/master.key; it does not
// replace a lost key file.
package keys

import (
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"fileparcel/internal/core"
	"fileparcel/internal/crypt"
	"fileparcel/internal/db"
	"fileparcel/internal/events"
	"fileparcel/internal/ids"
)

// Service implements core.Keys.
type Service struct {
	env  *core.Env
	log  *slog.Logger
	path string // keys/master.key

	kdf          kdfConfig     // argon2id parameters for new seals
	retiredGrace time.Duration // retired KEKs younger than this are never deleted
	batchSize    int           // rows per re-wrap transaction

	// Lock order: rotMu → keyRotMu → keyMu → blobMu → opMu → mu, and
	// fileMu → mu.
	opMu  sync.Mutex // serialises state changes and keyring changes
	rotMu sync.Mutex // serialises RotateKEK runs
	// keyRotMu serialises the writers of keyMu (RotateMaster and
	// RotateKEK("field")), so that a failed keyMu.TryLock always means a
	// reader — a backup — holds it, and the conflict names the right cause.
	keyRotMu sync.Mutex
	// keyMu guards the on-disk key material (keys/master.key and the sealed
	// key files under certs/) together with the keyring rows that belong to
	// it. RotateMaster and RotateKEK("field") take it for writing (always
	// before opMu); a reader that copies the key files and a database
	// snapshot as one unit — backup.create — holds it for reading via
	// HoldKeyMaterial.
	keyMu sync.RWMutex
	// fileMu serialises the writes of the sealed key files under certs/:
	// resealFile's changed-file check and rename run under it, and package
	// certs holds it (LockKeyFiles) around sealing and writing or removing
	// such a file, so a rotation never renames an old key back over a new one.
	fileMu sync.Mutex
	// blobMu keeps data re-encryption (keys.reencrypt, which deletes the old
	// blob of every file it re-encrypts) away from a full backup that copies
	// the blobs its database snapshot lists: the job holds it for writing
	// around each blob, a backup holds it for reading via HoldBlobs.
	blobMu sync.RWMutex

	mu    sync.RWMutex // guards the fields below
	state core.KeyState
	file  *keyFile  // parsed master.key (nil while uninitialized)
	m     *material // key material while unlocked
	stale bool      // master.key exists but the database has no keyring (interrupted init)

	blobs core.BlobStore // from Bind; used by the keys.reencrypt job
}

var (
	_ core.Keys         = (*Service)(nil)
	_ core.Binder       = (*Service)(nil)
	_ core.JobRegistrar = (*Service)(nil)
)

const (
	openTimeout         = 30 * time.Second
	defaultRetiredGrace = 15 * time.Minute
	rewrapBatch         = 500
)

// Open loads keys/master.key (plain → unlocked, sealed → locked, missing →
// uninitialized). It never blocks waiting for a passphrase. It refuses to
// start (returns an error) when the key file does not belong to the
// database, when the database was initialised but the key file is missing,
// or when a plain master key fails its mk_check. An interrupted master key
// rotation (keys/master.key.next) is completed or rolled back first.
func Open(env *core.Env) (*Service, error) {
	if env == nil || env.Home == nil || env.DB == nil {
		return nil, errors.New("keys: environment needs Home and DB")
	}
	log := env.Log
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	s := &Service{
		env:          env,
		log:          log.With("svc", "keys"),
		path:         env.Home.KeysFile(),
		kdf:          defaultKDF,
		retiredGrace: defaultRetiredGrace,
		batchSize:    rewrapBatch,
		state:        core.KeyStateUninitialized,
	}
	ctx, cancel := context.WithTimeout(context.Background(), openTimeout)
	defer cancel()
	if err := s.load(ctx); err != nil {
		return nil, err
	}
	return s, nil
}

// load reads the key file and the keyring into s (called by Open).
func (s *Service) load(ctx context.Context) error {
	q := readerQ{s.env.DB}
	_ = os.Remove(s.path + fileSuffixTm)
	_ = os.Remove(s.path + fileSuffixNx + fileSuffixTm)
	metaID, hasMK, err := getMeta(ctx, q, metaMKID)
	if err != nil {
		return fmt.Errorf("keys: read meta: %w", err)
	}
	if err := s.recoverNext(metaID, hasMK); err != nil {
		return err
	}
	data, err := os.ReadFile(s.path)
	if errors.Is(err, fs.ErrNotExist) {
		if hasMK {
			return fmt.Errorf("keys: %s is missing but the database belongs to master key %s; restore the key file from a backup", s.path, metaID)
		}
		return nil // uninitialized
	}
	if err != nil {
		return fmt.Errorf("keys: %w", err)
	}
	defer clear(data)
	s.checkPerm()
	kf, err := parseKeyFile(data)
	if err != nil {
		return fmt.Errorf("keys: %s: %w", s.path, err)
	}
	if !hasMK {
		n, err := countKeyring(ctx, q)
		if err != nil {
			return fmt.Errorf("keys: %w", err)
		}
		if n > 0 {
			return errors.New("keys: the keyring exists but meta.mk_id is missing; the database is damaged")
		}
		s.log.Warn("master key file exists but the database has no keyring (interrupted init); init will replace it", "path", s.path)
		s.stale = true
		return nil
	}
	if kf.MKID != metaID {
		return fmt.Errorf("keys: %s holds master key %s but the database belongs to %s; refusing to start with a foreign key file", s.path, kf.MKID, metaID)
	}
	s.file = kf
	if kf.Mode == core.KeyModeSealed {
		s.state = core.KeyStateLocked
		s.log.Info("master key is sealed; waiting for unlock", "mk_id", kf.MKID)
		return nil
	}
	mk, err := kf.plainKey()
	if err != nil {
		return fmt.Errorf("keys: %s: %w", s.path, err)
	}
	defer crypt.Zero(mk)
	// The vault holds the MK from here on; the cached file does not keep a
	// copy (replaceFile writes it back with marshalWith).
	kf.Key = ""
	check, _, err := getMeta(ctx, q, metaMKCheck)
	if err != nil {
		return fmt.Errorf("keys: read meta: %w", err)
	}
	m, err := buildMaterial(ctx, q, mk, kf.MKID, check)
	if err != nil {
		return fmt.Errorf("keys: %w", err)
	}
	s.adoptEscrow(m, kf, mk)
	s.m = m
	s.state = core.KeyStateUnlocked
	return nil
}

// checkPerm tightens keys/master.key to 0600 if it is group/world accessible.
func (s *Service) checkPerm() {
	st, err := os.Stat(s.path)
	if err != nil {
		return
	}
	if st.Mode().Perm()&0o077 != 0 {
		s.log.Warn("master key file was accessible by other users; fixing its mode to 0600", "path", s.path, "mode", st.Mode().Perm().String())
		_ = os.Chmod(s.path, 0o600)
	}
}

// Close zeroes the key material (io.Closer; called by wire's cleanup).
func (s *Service) Close() error {
	s.mu.Lock()
	m := s.m
	s.m = nil
	if s.state == core.KeyStateUnlocked {
		s.state = core.KeyStateLocked
	}
	s.mu.Unlock()
	m.destroy()
	return nil
}

// State reports the key state.
func (s *Service) State() core.KeyState {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.state
}

// mode returns the current key file mode ("" while uninitialized).
func (s *Service) mode() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.file == nil {
		return ""
	}
	return s.file.Mode
}

// Init creates the master key and keyring (see core.Keys.Init). In sealed
// mode it returns the one-time recovery key; plain mode returns "".
func (s *Service) Init(ctx context.Context, sealed bool, passphrase []byte) (recoveryKey string, err error) {
	s.opMu.Lock()
	defer s.opMu.Unlock()
	if s.State() != core.KeyStateUninitialized {
		return "", core.Errorf(core.ErrConflict, "the master key is already initialized")
	}
	if sealed {
		if err := checkPassphrase("passphrase", passphrase); err != nil {
			return "", err
		}
	} else if len(passphrase) > 0 {
		return "", core.Invalid("passphrase", "a passphrase is only used in sealed mode")
	}
	q := readerQ{s.env.DB}
	if _, has, err := getMeta(ctx, q, metaMKID); err != nil {
		return "", err
	} else if has {
		return "", core.Errorf(core.ErrConflict, "the database already has a master key")
	}
	if n, err := countKeyring(ctx, q); err != nil {
		return "", err
	} else if n > 0 {
		return "", core.Errorf(core.ErrConflict, "the database already has a keyring")
	}

	m := newMaterial()
	ok := false
	defer func() {
		if !ok {
			m.destroy()
		}
	}()
	mk := crypt.RandomBytes(secretSize)
	defer crypt.Zero(mk)
	mkID := ids.New(ids.PrefixMasterKey)
	m.mk = m.vault.put(mk)
	m.mkID = mkID

	kf := &keyFile{V: fileVersion, MKID: mkID}
	if sealed {
		kf.Mode = core.KeyModeSealed
		kf.KDF = newKDF(s.kdf)
		pk, err := deriveKey(passphrase, kf.KDF)
		if err != nil {
			return "", err
		}
		defer crypt.Zero(pk)
		box, err := sealBox(pk, mk, aadMK(mkID))
		if err != nil {
			return "", err
		}
		m.passKey = m.vault.put(pk)
		kf.Nonce, kf.CT = box.Nonce, box.CT
		raw := crypt.RandomBytes(recoveryRawSize)
		recoveryKey = formatRecoveryKey(raw)
		rh := recoveryHash(raw)
		crypt.Zero(raw)
		defer crypt.Zero(rh)
		if kf.Recovery, err = sealBox(rh, mk, aadRecovery(mkID)); err != nil {
			return "", err
		}
		m.recKey = m.vault.put(rh)
		if err := kf.setEscrow(mk, escrowPass, pk); err != nil {
			return "", err
		}
		if err := kf.setEscrow(mk, escrowRecovery, rh); err != nil {
			return "", err
		}
	} else {
		kf.Mode = core.KeyModePlain // the key itself is only written (marshalWith)
	}

	now := s.env.Now()
	type newRow struct {
		id, purpose string
		wrapped     []byte
	}
	var rows []newRow
	for _, p := range purposes {
		id := ids.New(ids.PrefixKEK)
		raw := crypt.RandomBytes(secretSize)
		w, err := wrapKEK(mk, id, p, raw)
		if err == nil {
			err = m.addKEK(id, p, core.KEKActive, raw, now, nil)
		}
		crypt.Zero(raw)
		if err != nil {
			return "", err
		}
		rows = append(rows, newRow{id, p, w})
	}

	data := kf.marshalWith(mk)
	defer clear(data)
	if err := writeFileAtomic(s.path, data, 0o600); err != nil {
		return "", fmt.Errorf("keys: write %s: %w", s.path, err)
	}
	check := mkCheck(mk, mkID)
	err = s.env.DB.Tx(ctx, func(tx *sql.Tx) error {
		if _, has, err := getMeta(ctx, tx, metaMKID); err != nil {
			return err
		} else if has {
			return core.Errorf(core.ErrConflict, "the database already has a master key")
		}
		for _, r := range rows {
			if _, err := tx.ExecContext(ctx, `INSERT INTO keyring (id, purpose, mk_id, wrapped, state, created_at)
				VALUES (?, ?, ?, ?, 'active', ?)`, r.id, r.purpose, mkID, r.wrapped, db.Ms(now)); err != nil {
				return err
			}
		}
		if err := setMeta(ctx, tx, metaMKID, mkID); err != nil {
			return err
		}
		return setMeta(ctx, tx, metaMKCheck, check)
	})
	if err != nil {
		_ = os.Remove(s.path)
		_ = syncDir(s.env.Home.KeysDir())
		return "", fmt.Errorf("keys: init keyring: %w", err)
	}
	ok = true
	s.mu.Lock()
	s.file, s.m, s.state, s.stale = kf, m, core.KeyStateUnlocked, false
	s.mu.Unlock()
	s.publishState()
	s.log.Info("master key initialized", "mode", kf.Mode, "mk_id", mkID)
	return recoveryKey, nil
}

// Unlock unlocks a sealed master key with the passphrase or a recovery key.
// A wrong secret returns a 422 on field "passphrase" (and is audited).
func (s *Service) Unlock(ctx context.Context, passphrase []byte) error {
	s.opMu.Lock()
	defer s.opMu.Unlock()
	switch s.State() {
	case core.KeyStateUninitialized:
		return core.Errorf(core.ErrPrecondition, "the master key is not initialized")
	case core.KeyStateUnlocked:
		return core.Errorf(core.ErrConflict, "the server is already unlocked")
	}
	if len(passphrase) == 0 {
		return core.Invalid("passphrase", "passphrase or recovery key required")
	}
	if len(passphrase) > MaxPassphraseLen+64 {
		s.audit(ctx, core.ActKeysUnlock, core.OutcomeFailure, map[string]any{"reason": "too long"})
		return errWrongSecret("passphrase")
	}
	s.mu.RLock()
	kf := s.file
	s.mu.RUnlock()
	mk, pk, rh, method := openMaster(kf, passphrase)
	if mk == nil {
		s.audit(ctx, core.ActKeysUnlock, core.OutcomeFailure, map[string]any{"reason": "wrong passphrase or recovery key"})
		s.log.Warn("unlock failed: wrong passphrase or recovery key")
		return errWrongSecret("passphrase")
	}
	defer crypt.Zero(mk)
	defer crypt.Zero(pk)
	defer crypt.Zero(rh)
	q := readerQ{s.env.DB}
	metaID, _, err := getMeta(ctx, q, metaMKID)
	if err != nil {
		return err
	}
	if metaID != kf.MKID {
		return core.Wrap(core.ErrCorrupt, "the master key file does not belong to this database", nil)
	}
	check, _, err := getMeta(ctx, q, metaMKCheck)
	if err != nil {
		return err
	}
	m, err := buildMaterial(ctx, q, mk, kf.MKID, check)
	if err != nil {
		s.audit(ctx, core.ActKeysUnlock, core.OutcomeFailure, map[string]any{"reason": "keyring check failed"})
		return err
	}
	if pk != nil {
		m.passKey = m.vault.put(pk)
	}
	if rh != nil {
		m.recKey = m.vault.put(rh)
	}
	s.adoptEscrow(m, kf, mk)
	s.mu.Lock()
	s.m, s.state = m, core.KeyStateUnlocked
	s.mu.Unlock()
	s.publishState()
	s.audit(ctx, core.ActKeysUnlock, core.OutcomeSuccess, map[string]any{"method": method})
	s.log.Info("keys unlocked", "method", method)
	return nil
}

// openMaster tries secret as a recovery key (when it has that shape and the
// file has a recovery slot) and as a passphrase. It returns the MK plus the
// passphrase key or recovery hash that opened it (all to be zeroed by the
// caller), or mk == nil.
func openMaster(kf *keyFile, secretIn []byte) (mk, passKey, recHash []byte, method string) {
	if kf == nil || kf.Mode != core.KeyModeSealed && kf.Recovery == nil {
		return nil, nil, nil, ""
	}
	if raw, err := parseRecoveryKey(secretIn); err == nil {
		// Passphrases can never have the shape of a recovery key
		// (checkPassphrase), so the (slow) passphrase attempt is skipped.
		rh := recoveryHash(raw)
		crypt.Zero(raw)
		if kf.Recovery != nil {
			if mk, err := openBox(rh, kf.Recovery, aadRecovery(kf.MKID)); err == nil {
				return mk, nil, rh, "recovery_key"
			}
		}
		crypt.Zero(rh)
		return nil, nil, nil, ""
	}
	if kf.Mode != core.KeyModeSealed {
		return nil, nil, nil, ""
	}
	pk, err := deriveKey(secretIn, kf.KDF)
	if err != nil {
		return nil, nil, nil, ""
	}
	mk, err = openBox(pk, &sealedBox{Nonce: kf.Nonce, CT: kf.CT}, aadMK(kf.MKID))
	if err != nil {
		crypt.Zero(pk)
		return nil, nil, nil, ""
	}
	return mk, pk, nil, "passphrase"
}

// adoptEscrow caches the passphrase key and the recovery hash from the key
// file's escrow when m does not know them yet. Each escrowed value is used
// only if it actually opens its slot of kf; anything else is ignored (and
// logged), so a damaged escrow never prevents an unlock.
func (s *Service) adoptEscrow(m *material, kf *keyFile, mk []byte) {
	pk, rh, err := kf.openEscrow(mk)
	defer crypt.Zero(pk)
	defer crypt.Zero(rh)
	if err != nil {
		s.log.Warn("ignoring a key file escrow entry that fails authentication", "err", err)
	}
	opens := func(key []byte, box *sealedBox, aad []byte) bool {
		got, err := openBox(key, box, aad)
		defer crypt.Zero(got)
		return err == nil && ids.EqualBytes(got, mk)
	}
	if pk != nil && m.passKey == nil {
		if opens(pk, &sealedBox{Nonce: kf.Nonce, CT: kf.CT}, aadMK(kf.MKID)) {
			m.passKey = m.vault.put(pk)
		} else {
			s.log.Warn("ignoring a stale passphrase escrow in the key file")
		}
	}
	if rh != nil && m.recKey == nil {
		if opens(rh, kf.Recovery, aadRecovery(kf.MKID)) {
			m.recKey = m.vault.put(rh)
		} else {
			s.log.Warn("ignoring a stale recovery escrow in the key file")
		}
	}
}

func errWrongSecret(field string) error {
	return core.Invalid(field, "wrong passphrase or recovery key")
}

// checkPassphrase validates a new passphrase: at least MinPassphraseLen
// characters (runes; an invalid UTF-8 byte counts as one) and at most
// MaxPassphraseLen bytes.
func checkPassphrase(field string, p []byte) error {
	switch {
	case utf8.RuneCount(p) < MinPassphraseLen:
		return core.Invalid(field, fmt.Sprintf("the passphrase must be at least %d characters", MinPassphraseLen))
	case len(p) > MaxPassphraseLen:
		return core.Invalid(field, fmt.Sprintf("the passphrase must be at most %d bytes", MaxPassphraseLen))
	}
	if _, err := parseRecoveryKey(p); err == nil {
		return core.Invalid(field, "a recovery key cannot be used as the passphrase")
	}
	return nil
}

// Lock forgets the master key (sealed mode only). Locking an already locked
// service is a no-op.
func (s *Service) Lock(ctx context.Context) error {
	s.opMu.Lock()
	defer s.opMu.Unlock()
	switch s.State() {
	case core.KeyStateUninitialized:
		return core.Errorf(core.ErrPrecondition, "the master key is not initialized")
	case core.KeyStateLocked:
		return nil
	}
	if s.mode() != core.KeyModeSealed {
		return core.Errorf(core.ErrPrecondition, "only a sealed master key can be locked (seal it with a passphrase first)")
	}
	// Audit before forgetting the keys so the row is MAC-chained right away.
	s.audit(ctx, core.ActKeysLock, core.OutcomeSuccess, nil)
	s.mu.Lock()
	m := s.m
	s.m, s.state = nil, core.KeyStateLocked
	s.mu.Unlock()
	m.destroy()
	s.publishState()
	s.log.Info("keys locked")
	return nil
}

// Status returns the key status (works in every state; no secrets).
func (s *Service) Status(ctx context.Context) (*core.KeyStatus, error) {
	st := &core.KeyStatus{
		State:     s.State(),
		Cipher:    s.Cipher(),
		WebUnlock: s.settingString(settingWebUnlock, "lan"),
		KEKs:      []core.KEKInfo{},
	}
	st.CipherName = st.Cipher.String()
	s.mu.RLock()
	if s.file != nil {
		st.Mode, st.MKID, st.RecoveryConfigured = s.file.Mode, s.file.MKID, s.file.Recovery != nil
	}
	if s.m != nil {
		st.Mlocked = s.m.vault.mlocked()
	}
	s.mu.RUnlock()
	if st.State == core.KeyStateUninitialized {
		return st, nil
	}
	infos, err := s.kekInfos(ctx)
	if err != nil {
		return nil, err
	}
	st.KEKs = infos
	return st, nil
}

// ---------- hot paths ----------

// dekAAD returns "fp-dek|<32hex>" for a blob ID given as 16 raw bytes or as
// its 32-character hex form.
func dekAAD(blobID []byte) ([]byte, error) {
	var h string
	switch {
	case len(blobID) == 16:
		h = hex.EncodeToString(blobID)
	case len(blobID) == 32 && ids.ValidBlobID(string(blobID)):
		h = string(blobID)
	default:
		return nil, core.Invalid("blob_id", "invalid blob id")
	}
	return []byte("fp-dek|" + h), nil
}

// NewDEK returns a fresh 32-byte DEK and its wrapping under the active blob
// KEK (AAD "fp-dek|<32hex blob id>"). blobID is the 16 raw bytes (or the hex
// string). The caller owns dek and should zero it after use.
func (s *Service) NewDEK(blobID []byte) (dek, wrapped []byte, kekID string, err error) {
	aad, err := dekAAD(blobID)
	if err != nil {
		return nil, nil, "", err
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.m == nil {
		return nil, nil, "", errLocked
	}
	k := s.m.active[core.KEKBlob]
	if k == nil {
		return nil, nil, "", core.Wrap(core.ErrCorrupt, "no active blob key", nil)
	}
	dek = crypt.RandomBytes(secretSize)
	return dek, crypt.Seal(k.aead, dek, aad), k.id, nil
}

// UnwrapDEK unwraps a blob's DEK. Unknown KEKs and authentication failures
// return core.ErrCorrupt.
func (s *Service) UnwrapDEK(blobID []byte, kekID string, wrapped []byte) ([]byte, error) {
	aad, err := dekAAD(blobID)
	if err != nil {
		return nil, err
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.m == nil {
		return nil, errLocked
	}
	return unwrapWith(s.m, kekID, wrapped, aad)
}

func unwrapWith(m *material, kekID string, wrapped, aad []byte) ([]byte, error) {
	k := m.keks[kekID]
	if k == nil || k.purpose != core.KEKBlob {
		return nil, core.Wrap(core.ErrCorrupt, "blob key wrapped by an unknown key", nil)
	}
	dek, err := crypt.Open(k.aead, wrapped, aad)
	if err != nil || len(dek) != secretSize {
		crypt.Zero(dek)
		return nil, core.Wrap(core.ErrCorrupt, "blob key failed authentication", nil)
	}
	return dek, nil
}

const fieldVersion = "v1"

// SealField encrypts a DB field value (or key file) bound to aad under the
// active field KEK: "v1:<kek_id>:" + base64url(nonce || ct).
func (s *Service) SealField(aad string, plaintext []byte) (string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.m == nil {
		return "", errLocked
	}
	k := s.m.active[core.KEKField]
	if k == nil {
		return "", core.Wrap(core.ErrCorrupt, "no active field key", nil)
	}
	return sealFieldWith(k, aad, plaintext), nil
}

func sealFieldWith(k *kek, aad string, pt []byte) string {
	return fieldVersion + ":" + k.id + ":" + base64.RawURLEncoding.EncodeToString(crypt.Seal(k.aead, pt, []byte(aad)))
}

// parseSealed splits "v1:<kek>:<b64>" into the KEK id and the raw box.
func parseSealed(sealed string) (kekID string, box []byte, err error) {
	v, rest, ok1 := strings.Cut(sealed, ":")
	id, enc, ok2 := strings.Cut(rest, ":")
	if !ok1 || !ok2 || v != fieldVersion || id == "" {
		return "", nil, core.Wrap(core.ErrCorrupt, "malformed sealed value", nil)
	}
	box, err = base64.RawURLEncoding.DecodeString(enc)
	if err != nil {
		return "", nil, core.Wrap(core.ErrCorrupt, "malformed sealed value", nil)
	}
	return id, box, nil
}

// OpenField decrypts a sealed field value. A value sealed for another aad
// (e.g. copied from another row), with an unknown KEK or tampered with
// returns core.ErrCorrupt.
func (s *Service) OpenField(aad string, sealed string) ([]byte, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.m == nil {
		return nil, errLocked
	}
	return openFieldWith(s.m, aad, sealed)
}

func openFieldWith(m *material, aad, sealed string) ([]byte, error) {
	id, box, err := parseSealed(sealed)
	if err != nil {
		return nil, err
	}
	k := m.keks[id]
	if k == nil || k.purpose != core.KEKField {
		return nil, core.Wrap(core.ErrCorrupt, "value sealed with an unknown key", nil)
	}
	pt, err := crypt.Open(k.aead, box, []byte(aad))
	if err != nil {
		return nil, core.Wrap(core.ErrCorrupt, "sealed value failed authentication", nil)
	}
	return pt, nil
}

// MAC computes HMAC-SHA256 over the length-framed data (crypt.HMAC) with the
// subkey HKDF-SHA256(KEK[mac], info "fp-mac|"+purpose). It returns nil while
// the keys are unavailable.
func (s *Service) MAC(purpose string, data ...[]byte) []byte {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.m == nil {
		return nil
	}
	key := s.m.macKey(purpose)
	if key == nil {
		return nil
	}
	return crypt.HMAC(key, data...)
}

// Cipher returns the cipher for new blobs: storage.cipher, or with "auto"
// AES-256-GCM when the CPU has AES+carry-less multiply instructions and
// ChaCha20-Poly1305 otherwise (DESIGN §7.7).
func (s *Service) Cipher() core.CipherID {
	switch s.settingString(settingCipher, "auto") {
	case cipherAESGCM:
		return core.CipherAES256GCM
	case cipherChaCha:
		return core.CipherChaCha20Poly1305
	}
	return core.CipherID(crypt.AutoCipher())
}

// ---------- helpers ----------

// settingString reads a string setting lazily (Settings is constructed
// after keys.Open).
func (s *Service) settingString(key, def string) string {
	if s.env.Settings == nil {
		return def
	}
	if v := s.env.Settings.String(key); v != "" {
		return v
	}
	return def
}

// publishState announces the current state on keys.state.
func (s *Service) publishState() {
	if s.env.Bus == nil {
		return
	}
	s.env.Bus.Publish(events.Event{Topic: events.TopicKeysState, Data: core.KeysStateEvent{State: s.State()}})
}

// audit records a keys.* action. It must not be called while holding s.mu.
func (s *Service) audit(ctx context.Context, action, outcome string, details map[string]any) {
	if s.env.Audit == nil {
		return
	}
	e := core.AuditEntry{Action: action, Outcome: outcome, TargetType: "keys", Details: details}
	s.mu.RLock()
	if s.file != nil {
		e.TargetID = s.file.MKID
	}
	s.mu.RUnlock()
	if details == nil {
		e.Details = map[string]any{}
	}
	s.env.Audit.Record(ctx, e)
}

// requireUnlocked returns errLocked unless the keys are unlocked.
func (s *Service) requireUnlocked() error {
	if s.State() != core.KeyStateUnlocked {
		return errLocked
	}
	return nil
}
