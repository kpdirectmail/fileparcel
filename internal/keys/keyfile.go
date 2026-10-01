package keys

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"fileparcel/internal/core"
	"fileparcel/internal/crypt"
	"fileparcel/internal/ids"
)

// keys/master.key (DESIGN §7.2):
//
//	{"v":1,"mk_id":"mk_…","mode":"plain","key":"<base64 32B>"}
//	{"v":1,"mk_id":"mk_…","mode":"sealed",
//	 "kdf":{"alg":"argon2id","t":3,"m_kib":131072,"p":4,"salt":"<b64 16B>"},
//	 "nonce":"<b64>","ct":"<b64 MK sealed with the KDF key, AAD 'fp-mk|<mk_id>'>",
//	 "recovery":{"nonce":"<b64>","ct":"<b64 MK sealed with SHA-256(recovery key), AAD 'fp-mk-recovery|<mk_id>'>"}}
//
// Every seal uses AES-256-GCM with a random 96-bit nonce. The recovery slot
// is optional in both modes: it is created by a sealed Init and by
// ExportRecovery, and it survives Seal/Unseal/ChangePassphrase (the MK does
// not change). A plain file may carry it so that a later Seal keeps the
// already exported recovery key valid.
//
// Escrow (an addition to DESIGN §7.2): the file may also carry copies of the
// passphrase-derived key and of the recovery hash, each sealed under the MK
// itself:
//
//	"escrow":{"pass":{"nonce":"…","ct":"<argon2id key, AAD 'fp-mk-escrow|pass|<mk_id>'>"},
//	          "recovery":{"nonce":"…","ct":"<SHA-256(recovery key), AAD 'fp-mk-escrow|recovery|<mk_id>'>"}}
//
// They are only readable with the MK, but they outlive it: whoever held an
// MK together with the file that carried it keeps both secrets, and a master
// rotation keeps them (RotateMaster), so they open every later key file too
// until the passphrase is changed (fresh salt) and a new recovery key is
// exported. What they buy is that RotateMaster can re-seal the new MK under
// the unchanged passphrase and keep the recovery key valid however the
// server was unlocked (passphrase or recovery key, before or after a
// restart). Files without escrow remain valid.

const (
	fileVersion  = 1
	kdfAlg       = "argon2id"
	saltLen      = 16
	mkSealedLen  = secretSize + crypt.TagSize
	fileSuffixNx = ".next" // master.key.next during RotateMaster
	fileSuffixTm = ".tmp"  // atomic-write temporary
)

// Passphrase bounds (sealed mode): the minimum counts characters, the
// maximum bytes.
const (
	MinPassphraseLen = 8
	MaxPassphraseLen = 1024
)

// kdfConfig are the argon2id parameters used for new passphrase seals.
type kdfConfig struct {
	T    uint32
	MKiB uint32
	P    uint8
}

// defaultKDF is argon2id t=3, m=128 MiB, p=4 (DESIGN §7.2 / task spec).
var defaultKDF = kdfConfig{T: 3, MKiB: 128 * 1024, P: 4}

// Bounds accepted when reading a key file (a tampered file must not be able
// to make Unlock allocate unbounded memory).
const (
	maxKDFTime = 16
	// No seal may ask for more argon2 memory than the whole process-wide
	// budget, which is what actually bounds a derivation (DESIGN §18.12).
	maxKDFMKiB = crypt.Argon2BudgetKiB // 256 MiB
	maxKDFP    = 16
)

type kdfParams struct {
	Alg  string `json:"alg"`
	T    uint32 `json:"t"`
	MKiB uint32 `json:"m_kib"`
	P    uint8  `json:"p"`
	Salt string `json:"salt"`
}

type sealedBox struct {
	Nonce string `json:"nonce"`
	CT    string `json:"ct"`
}

// keyFile is the parsed keys/master.key. Key (the base64 MK of a plain
// file) is only set in a file as read from disk; the service's cached file
// never keeps it, and writes fill it in with marshalWith.
type keyFile struct {
	V        int        `json:"v"`
	MKID     string     `json:"mk_id"`
	Mode     string     `json:"mode"`
	Key      string     `json:"key,omitempty"`
	KDF      *kdfParams `json:"kdf,omitempty"`
	Nonce    string     `json:"nonce,omitempty"`
	CT       string     `json:"ct,omitempty"`
	Recovery *sealedBox `json:"recovery,omitempty"`
	Escrow   *escrow    `json:"escrow,omitempty"`
}

// escrow holds the passphrase-derived key (sealed mode) and the recovery
// hash (when a recovery slot exists), each sealed under the MK.
type escrow struct {
	Pass     *sealedBox `json:"pass,omitempty"`
	Recovery *sealedBox `json:"recovery,omitempty"`
}

// Escrow entries.
const (
	escrowPass     = "pass"
	escrowRecovery = "recovery"
)

var b64 = base64.StdEncoding

func aadMK(mkID string) []byte       { return []byte("fp-mk|" + mkID) }
func aadRecovery(mkID string) []byte { return []byte("fp-mk-recovery|" + mkID) }
func aadEscrow(what, mkID string) []byte {
	return []byte("fp-mk-escrow|" + what + "|" + mkID)
}

// errKeyFile marks a malformed key file.
var errKeyFile = errors.New("malformed master key file")

// parseKeyFile decodes and validates a key file.
func parseKeyFile(data []byte) (*keyFile, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var kf keyFile
	if err := dec.Decode(&kf); err != nil {
		return nil, fmt.Errorf("%w: %v", errKeyFile, err)
	}
	if kf.V != fileVersion {
		return nil, fmt.Errorf("%w: unsupported version %d", errKeyFile, kf.V)
	}
	if !ids.Valid(ids.PrefixMasterKey, kf.MKID) {
		return nil, fmt.Errorf("%w: invalid mk_id", errKeyFile)
	}
	if kf.Recovery != nil {
		if err := checkBox(kf.Recovery.Nonce, kf.Recovery.CT); err != nil {
			return nil, fmt.Errorf("%w: recovery: %v", errKeyFile, err)
		}
	}
	switch kf.Mode {
	case core.KeyModePlain:
		k, err := b64.DecodeString(kf.Key)
		if err != nil || len(k) != secretSize {
			return nil, fmt.Errorf("%w: key must be 32 base64 bytes", errKeyFile)
		}
		crypt.Zero(k)
		if kf.KDF != nil || kf.Nonce != "" || kf.CT != "" {
			return nil, fmt.Errorf("%w: plain file with sealed fields", errKeyFile)
		}
	case core.KeyModeSealed:
		if kf.Key != "" {
			return nil, fmt.Errorf("%w: sealed file with a plain key", errKeyFile)
		}
		if err := checkKDF(kf.KDF); err != nil {
			return nil, fmt.Errorf("%w: kdf: %v", errKeyFile, err)
		}
		if err := checkBox(kf.Nonce, kf.CT); err != nil {
			return nil, fmt.Errorf("%w: %v", errKeyFile, err)
		}
	default:
		return nil, fmt.Errorf("%w: unknown mode %q", errKeyFile, kf.Mode)
	}
	if e := kf.Escrow; e != nil {
		switch {
		case e.Pass == nil && e.Recovery == nil:
			return nil, fmt.Errorf("%w: empty escrow", errKeyFile)
		case e.Pass != nil && kf.Mode != core.KeyModeSealed:
			return nil, fmt.Errorf("%w: passphrase escrow in a plain file", errKeyFile)
		case e.Recovery != nil && kf.Recovery == nil:
			return nil, fmt.Errorf("%w: recovery escrow without a recovery slot", errKeyFile)
		}
		for what, box := range map[string]*sealedBox{escrowPass: e.Pass, escrowRecovery: e.Recovery} {
			if box == nil {
				continue
			}
			if err := checkBox(box.Nonce, box.CT); err != nil {
				return nil, fmt.Errorf("%w: escrow %s: %v", errKeyFile, what, err)
			}
		}
	}
	return &kf, nil
}

// setEscrow seals secret (nil = remove) as escrow entry what under mk.
func (kf *keyFile) setEscrow(mk []byte, what string, secret []byte) error {
	var box *sealedBox
	if secret != nil {
		var err error
		if box, err = sealBox(mk, secret, aadEscrow(what, kf.MKID)); err != nil {
			return err
		}
	}
	if kf.Escrow == nil {
		kf.Escrow = &escrow{}
	}
	switch what {
	case escrowPass:
		kf.Escrow.Pass = box
	case escrowRecovery:
		kf.Escrow.Recovery = box
	}
	if kf.Escrow.Pass == nil && kf.Escrow.Recovery == nil {
		kf.Escrow = nil
	}
	return nil
}

// openEscrow returns the escrowed passphrase key and recovery hash (nil
// when absent or when they fail authentication under mk). The caller zeroes
// both.
func (kf *keyFile) openEscrow(mk []byte) (passKey, recHash []byte, err error) {
	if kf.Escrow == nil {
		return nil, nil, nil
	}
	if b := kf.Escrow.Pass; b != nil && kf.Mode == core.KeyModeSealed {
		if passKey, err = openBox(mk, b, aadEscrow(escrowPass, kf.MKID)); err != nil {
			passKey, err = nil, fmt.Errorf("passphrase escrow: %w", err)
		}
	}
	if b := kf.Escrow.Recovery; b != nil && kf.Recovery != nil {
		var rerr error
		if recHash, rerr = openBox(mk, b, aadEscrow(escrowRecovery, kf.MKID)); rerr != nil {
			recHash, err = nil, errors.Join(err, fmt.Errorf("recovery escrow: %w", rerr))
		}
	}
	return passKey, recHash, err
}

func checkKDF(k *kdfParams) error {
	if k == nil {
		return errors.New("missing")
	}
	if k.Alg != kdfAlg {
		return fmt.Errorf("unsupported algorithm %q", k.Alg)
	}
	if k.T < 1 || k.T > maxKDFTime || k.P < 1 || k.P > maxKDFP || k.MKiB < 8*uint32(k.P) || k.MKiB > maxKDFMKiB {
		return errors.New("parameters out of range")
	}
	salt, err := b64.DecodeString(k.Salt)
	if err != nil || len(salt) < saltLen {
		return errors.New("bad salt")
	}
	return nil
}

func checkBox(nonce, ct string) error {
	n, err := b64.DecodeString(nonce)
	if err != nil || len(n) != crypt.NonceSize {
		return errors.New("bad nonce")
	}
	c, err := b64.DecodeString(ct)
	if err != nil || len(c) != mkSealedLen {
		return errors.New("bad ciphertext")
	}
	return nil
}

// marshalWith encodes the key file like marshal, filling in the master key
// mk when the file is plain. The key files the service keeps in memory
// never hold it (the vault does), so it only exists in the returned bytes,
// which the caller clears once they are written.
func (kf *keyFile) marshalWith(mk []byte) []byte {
	if kf.Mode != core.KeyModePlain {
		return kf.marshal()
	}
	c := *kf
	c.Key = b64.EncodeToString(mk)
	return c.marshal()
}

// marshal encodes the key file (indented JSON + newline).
func (kf *keyFile) marshal() []byte {
	b, err := json.MarshalIndent(kf, "", "  ")
	if err != nil {
		panic(err) // plain struct of strings and numbers
	}
	return append(b, '\n')
}

// clone returns a deep copy.
func (kf *keyFile) clone() *keyFile {
	c := *kf
	if kf.KDF != nil {
		k := *kf.KDF
		c.KDF = &k
	}
	if kf.Recovery != nil {
		r := *kf.Recovery
		c.Recovery = &r
	}
	if kf.Escrow != nil {
		e := escrow{}
		if kf.Escrow.Pass != nil {
			p := *kf.Escrow.Pass
			e.Pass = &p
		}
		if kf.Escrow.Recovery != nil {
			r := *kf.Escrow.Recovery
			e.Recovery = &r
		}
		c.Escrow = &e
	}
	return &c
}

// plainKey decodes the MK of a plain file (caller zeroes it).
func (kf *keyFile) plainKey() ([]byte, error) {
	k, err := b64.DecodeString(kf.Key)
	if err != nil || len(k) != secretSize {
		return nil, errKeyFile
	}
	return k, nil
}

// sealBox encrypts mk under key (AES-256-GCM, random nonce).
func sealBox(key, mk, aad []byte) (*sealedBox, error) {
	a, err := crypt.NewAEAD(crypt.CipherAES256GCM, key)
	if err != nil {
		return nil, err
	}
	s := crypt.Seal(a, mk, aad)
	return &sealedBox{Nonce: b64.EncodeToString(s[:crypt.NonceSize]), CT: b64.EncodeToString(s[crypt.NonceSize:])}, nil
}

// openBox decrypts a sealed MK (caller zeroes the result).
func openBox(key []byte, box *sealedBox, aad []byte) ([]byte, error) {
	n, err1 := b64.DecodeString(box.Nonce)
	c, err2 := b64.DecodeString(box.CT)
	if err1 != nil || err2 != nil {
		return nil, errKeyFile
	}
	a, err := crypt.NewAEAD(crypt.CipherAES256GCM, key)
	if err != nil {
		return nil, err
	}
	mk, err := crypt.Open(a, append(n, c...), aad)
	if err != nil {
		return nil, err
	}
	if len(mk) != secretSize {
		crypt.Zero(mk)
		return nil, errKeyFile
	}
	return mk, nil
}

// newKDF returns fresh parameters (new salt) from cfg.
func newKDF(cfg kdfConfig) *kdfParams {
	return &kdfParams{Alg: kdfAlg, T: cfg.T, MKiB: cfg.MKiB, P: cfg.P, Salt: b64.EncodeToString(crypt.RandomBytes(saltLen))}
}

// deriveKey runs argon2id over the passphrase (caller zeroes the result).
// The argon2 memory is bounded process-wide by crypt's semaphore.
func deriveKey(pass []byte, k *kdfParams) ([]byte, error) {
	if err := checkKDF(k); err != nil {
		return nil, err
	}
	salt, _ := b64.DecodeString(k.Salt)
	return crypt.Argon2Key(pass, salt, k.T, k.MKiB, k.P, secretSize), nil
}

// recoveryHash is the key that seals the MK in the recovery slot:
// SHA-256 of the 32 raw recovery-key bytes (caller zeroes it).
func recoveryHash(raw []byte) []byte {
	h := sha256.Sum256(raw)
	return h[:]
}

// writeFileAtomic writes data to path via path.tmp: create exclusive
// (mode perm), write, fsync, close, rename, fsync the directory.
func writeFileAtomic(path string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	tmp := path + fileSuffixTm
	_ = os.Remove(tmp)
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, perm)
	if err != nil {
		return err
	}
	fail := func(err error) error {
		_ = f.Close()
		_ = os.Remove(tmp)
		return err
	}
	if err := f.Chmod(perm); err != nil { // umask-independent
		return fail(err)
	}
	if _, err := f.Write(data); err != nil {
		return fail(err)
	}
	if err := f.Sync(); err != nil {
		return fail(err)
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	if err := syncRenamed(dir); err != nil {
		return &notDurableError{err}
	}
	return nil
}

// syncRenamed is syncDir for writeFileAtomic's final directory fsync
// (replaceable in tests).
var syncRenamed = syncDir

// notDurableError is returned by writeFileAtomic when the new file is
// already in place and only the directory fsync that makes the rename
// durable failed: unlike every other error, the write took effect.
type notDurableError struct{ err error }

func (e *notDurableError) Error() string {
	return "the file was replaced, but the rename may not be durable: " + e.err.Error()
}
func (e *notDurableError) Unwrap() error { return e.err }

// syncDir fsyncs a directory so that renames/creations in it are durable.
func syncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	if err := d.Sync(); err != nil && !errors.Is(err, os.ErrInvalid) {
		return err
	}
	return nil
}
