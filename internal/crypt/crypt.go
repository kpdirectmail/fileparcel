// Package crypt holds the low-level cryptographic helpers shared by the
// service packages: AEAD construction and sealing with random nonces, HKDF,
// HMAC, argon2id password hashing (PHC strings), secure randomness and the
// common-password list (IsCommonPassword).
//
// crypt is a leaf package (stdlib + x/crypto + x/sys only). Key management
// (master key, KEKs, DEKs) lives in package keys.
package crypt

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"runtime"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/sys/cpu"
)

// Cipher identifiers (stored in blob headers and blobs.cipher; mirror core.CipherID).
const (
	CipherAES256GCM        uint8 = 1
	CipherChaCha20Poly1305 uint8 = 2
)

// KeySize is the key length of both supported AEADs (32 bytes).
const KeySize = 32

// NonceSize is the nonce length of both supported AEADs (12 bytes).
const NonceSize = 12

// TagSize is the authentication tag length (16 bytes).
const TagSize = 16

// ErrDecrypt is returned when authentication fails (wrong key, wrong AAD,
// tampered or truncated ciphertext). Never return unauthenticated plaintext.
var ErrDecrypt = errors.New("crypt: message authentication failed")

// NewAEAD returns the AEAD for cipherID (1 = AES-256-GCM, 2 =
// ChaCha20-Poly1305) with a 32-byte key. Both use 12-byte nonces and 16-byte tags.
func NewAEAD(cipherID uint8, key []byte) (cipher.AEAD, error) {
	if len(key) != KeySize {
		return nil, fmt.Errorf("crypt: key must be %d bytes, got %d", KeySize, len(key))
	}
	switch cipherID {
	case CipherAES256GCM:
		b, err := aes.NewCipher(key)
		if err != nil {
			return nil, err
		}
		return cipher.NewGCM(b)
	case CipherChaCha20Poly1305:
		return chacha20poly1305.New(key)
	default:
		return nil, fmt.Errorf("crypt: unknown cipher id %d", cipherID)
	}
}

// Seal encrypts plaintext with a fresh random nonce and returns
// nonce || ciphertext || tag.
func Seal(a cipher.AEAD, plaintext, aad []byte) []byte {
	ns := a.NonceSize()
	out := make([]byte, ns, ns+len(plaintext)+a.Overhead())
	_, _ = rand.Read(out[:ns])
	return a.Seal(out, out[:ns], plaintext, aad)
}

// Open reverses Seal. It returns ErrDecrypt on any authentication failure.
func Open(a cipher.AEAD, sealed, aad []byte) ([]byte, error) {
	ns := a.NonceSize()
	if len(sealed) < ns+a.Overhead() {
		return nil, ErrDecrypt
	}
	pt, err := a.Open(nil, sealed[:ns], sealed[ns:], aad)
	if err != nil {
		return nil, ErrDecrypt
	}
	return pt, nil
}

// SealWithKey is NewAEAD + Seal.
func SealWithKey(cipherID uint8, key, plaintext, aad []byte) ([]byte, error) {
	a, err := NewAEAD(cipherID, key)
	if err != nil {
		return nil, err
	}
	return Seal(a, plaintext, aad), nil
}

// OpenWithKey is NewAEAD + Open.
func OpenWithKey(cipherID uint8, key, sealed, aad []byte) ([]byte, error) {
	a, err := NewAEAD(cipherID, key)
	if err != nil {
		return nil, err
	}
	return Open(a, sealed, aad)
}

// HKDF derives n bytes from secret with HKDF-SHA256 (crypto/hkdf). salt may be nil.
func HKDF(secret, salt []byte, info string, n int) ([]byte, error) {
	return hkdf.Key(sha256.New, secret, salt, info, n)
}

// HMAC returns HMAC-SHA256(key, parts). To make the encoding unambiguous each
// part is prefixed with its length as a 4-byte big-endian integer, so
// HMAC(k, "ab", "c") != HMAC(k, "a", "bc").
func HMAC(key []byte, parts ...[]byte) []byte {
	m := hmac.New(sha256.New, key)
	var l [4]byte
	for _, p := range parts {
		binary.BigEndian.PutUint32(l[:], uint32(len(p)))
		m.Write(l[:])
		m.Write(p)
	}
	return m.Sum(nil)
}

// HMACRaw returns HMAC-SHA256(key, data) over the plain concatenation of data
// (no length framing) - for interoperable constructions such as the CSRF token
// (DESIGN §9.3) and meta.mk_check.
func HMACRaw(key []byte, data ...[]byte) []byte {
	m := hmac.New(sha256.New, key)
	for _, d := range data {
		m.Write(d)
	}
	return m.Sum(nil)
}

// RandomBytes returns n cryptographically secure random bytes. (crypto/rand
// never fails on supported platforms; it crashes the program instead.)
func RandomBytes(n int) []byte {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return b
}

// Zero overwrites b with zeros (best effort key hygiene).
func Zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
	runtime.KeepAlive(b)
}

// HasAESHardware reports whether AES-GCM runs on dedicated instructions here
// (DESIGN §7.7): the CPU must have AES + carry-less multiplication (amd64:
// AES-NI + PCLMULQDQ; arm64: AES + PMULL) *and* Go must ship the matching
// assembly for GOARCH — on every other architecture crypto/aes falls back to
// the generic table-driven implementation, which is both slow and a
// cache-timing risk, so ChaCha20-Poly1305 is the better choice there.
//
// Go 1.27 builds the AES and GHASH assembly for amd64, arm64, ppc64,
// ppc64le and s390x only (crypto/internal/fips140/aes/aes_asm.go,
// aes_s390x.go, .../gcm/gcm_asm.go, gcm_ppc64x.go, gcm_s390x.go). Notably
// 386 has none, although x/sys/cpu reports AES-NI on any modern x86.
func HasAESHardware() bool { return hasAESHardware(runtime.GOARCH) }

func hasAESHardware(goarch string) bool {
	switch goarch {
	case "amd64":
		return cpu.X86.HasAES && cpu.X86.HasPCLMULQDQ
	case "arm64":
		return cpu.ARM64.HasAES && cpu.ARM64.HasPMULL
	case "s390x":
		return cpu.S390X.HasAES && cpu.S390X.HasGHASH
	case "ppc64", "ppc64le":
		// Go's ppc64x assembly uses the POWER8 vector crypto instructions
		// and is compiled unconditionally, so POWER8 is the requirement.
		return cpu.PPC64.IsPOWER8 || cpu.PPC64.IsPOWER9 || cpu.PPC64.IsPOWER10
	}
	return false
}

// AutoCipher returns the cipher for new blobs when storage.cipher = "auto"
// (DESIGN §7.7): AES-256-GCM with hardware support, else ChaCha20-Poly1305.
func AutoCipher() uint8 {
	if HasAESHardware() {
		return CipherAES256GCM
	}
	return CipherChaCha20Poly1305
}

// CipherName returns "aes-256-gcm", "chacha20-poly1305" or "unknown".
func CipherName(id uint8) string {
	switch id {
	case CipherAES256GCM:
		return "aes-256-gcm"
	case CipherChaCha20Poly1305:
		return "chacha20-poly1305"
	}
	return "unknown"
}
