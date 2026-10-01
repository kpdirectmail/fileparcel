package ziputil

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/pbkdf2"
	"crypto/sha1"
	"crypto/subtle"
	"encoding/binary"
	"fmt"
	"hash"
	"io"
)

// WinZip AES encryption, AE-2 (§3.2; https://www.winzip.com/en/support/aes-encryption/).
// Per entry: a fresh salt, PBKDF2-HMAC-SHA1 (1000 iterations) derives the
// AES key, the HMAC key and a 2-byte password verification value; the inner
// data is encrypted with AES-256 in WinZip's counter mode and authenticated
// with HMAC-SHA1 over the ciphertext, truncated to 10 bytes. AE-2 stores CRC
// 0: the MAC authenticates every byte, and a CRC would leak information
// about small files.
const (
	aesKeyLen       = 32 // AES-256
	aesSaltLen      = 16 // for AES-256
	aesPVVLen       = 2
	aesMACLen       = 10
	aesIterations   = 1000
	aesOverhead     = aesSaltLen + aesPVVLen + aesMACLen // 28
	aeVersion2      = 2
	aesStrength256  = 3
	methodWinZipAES = 99
	zipVersionAES   = 51 // version needed to extract, as 7-Zip writes it
)

// leCTR is AES in WinZip's counter mode (Gladman's fcrypt, 7-Zip's AesCtr2):
// keystream block n, counting from 1, is AES(key, LE64(n) ‖ 0⁸) — a 64-bit
// little-endian counter. crypto/cipher's CTR (a 128-bit big-endian counter)
// is a different stream and must not be used. The keystream is produced 256
// blocks at a time.
type leCTR struct {
	b   cipher.Block
	n   uint64
	ks  [256 * aes.BlockSize]byte
	off int
}

func newLECTR(b cipher.Block) *leCTR {
	c := new(leCTR)
	c.init(b)
	return c
}

// init starts the stream of block b at counter 1.
func (c *leCTR) init(b cipher.Block) {
	c.b, c.n, c.off = b, 0, len(c.ks)
}

// refill encrypts the next 256 counter blocks into ks.
func (c *leCTR) refill() {
	for i := 0; i < len(c.ks); i += aes.BlockSize {
		c.n++
		blk := c.ks[i : i+aes.BlockSize]
		binary.LittleEndian.PutUint64(blk, c.n)
		clear(blk[8:])
		c.b.Encrypt(blk, blk)
	}
	c.off = 0
}

// XORKeyStream XORs src with the keystream into dst (len(dst) >= len(src)).
func (c *leCTR) XORKeyStream(dst, src []byte) {
	for len(src) > 0 {
		if c.off == len(c.ks) {
			c.refill()
		}
		k := subtle.XORBytes(dst, src, c.ks[c.off:])
		c.off += k
		dst, src = dst[k:], src[k:]
	}
}

// wipe clears the unused keystream and drops the key.
func (c *leCTR) wipe() {
	clear(c.ks[:])
	c.b, c.n, c.off = nil, 0, len(c.ks)
}

// aesWriter encrypts the inner data of one AE-2 entry: it writes salt ‖ pvv
// when it starts, the ciphertext on Write, and the MAC on Close.
type aesWriter struct {
	w   io.Writer
	ctr leCTR
	mac hash.Hash
	buf [chunkSize]byte
}

// newAESWriter starts an AE-2 entry on w with a salt read from rnd.
func newAESWriter(w io.Writer, password string, rnd io.Reader) (*aesWriter, error) {
	a := new(aesWriter)
	if err := a.reset(w, password, rnd); err != nil {
		return nil, err
	}
	return a, nil
}

// reset starts a new entry on w, reusing a's buffers.
func (a *aesWriter) reset(w io.Writer, password string, rnd io.Reader) error {
	var head [aesSaltLen + aesPVVLen]byte
	salt := head[:aesSaltLen]
	if _, err := io.ReadFull(rnd, salt); err != nil {
		return fmt.Errorf("ziputil: reading a salt: %w", err)
	}
	dk, err := aesKeys(password, salt)
	if err != nil {
		return err
	}
	defer clear(dk)
	b, err := aes.NewCipher(dk[:aesKeyLen])
	if err != nil {
		return err
	}
	a.w = w
	a.ctr.init(b)
	a.mac = hmac.New(sha1.New, dk[aesKeyLen:2*aesKeyLen])
	copy(head[aesSaltLen:], dk[2*aesKeyLen:])
	_, err = w.Write(head[:])
	return err
}

// aesKeys derives encKey ‖ authKey ‖ pvv (32 + 32 + 2 bytes) from the password
// and salt. pbkdf2.Key fails only in FIPS 140-only mode (SHA-1, short salt).
func aesKeys(password string, salt []byte) ([]byte, error) {
	dk, err := pbkdf2.Key(sha1.New, password, salt, aesIterations, 2*aesKeyLen+aesPVVLen)
	if err != nil {
		return nil, fmt.Errorf("ziputil: deriving the AES key: %w", err)
	}
	return dk, nil
}

// Write encrypts p into a's own buffer (p is never modified), feeds the MAC
// and writes the ciphertext.
func (a *aesWriter) Write(p []byte) (int, error) {
	done := 0
	for done < len(p) {
		out := a.buf[:min(len(p)-done, len(a.buf))]
		a.ctr.XORKeyStream(out, p[done:done+len(out)])
		a.mac.Write(out)
		if _, err := a.w.Write(out); err != nil {
			return done, err
		}
		done += len(out)
	}
	return done, nil
}

// Close writes the 10-byte MAC and wipes the writer.
func (a *aesWriter) Close() error {
	sum := a.mac.Sum(nil)
	_, err := a.w.Write(sum[:aesMACLen])
	a.wipe()
	return err
}

// wipe clears the keystream and the buffer and drops the keys.
func (a *aesWriter) wipe() {
	a.ctr.wipe()
	clear(a.buf[:])
	a.w, a.mac = nil, nil
}
