package ziputil

import (
	"fmt"
	"hash/crc32"
	"io"
)

// Traditional PKWARE encryption, "ZipCrypto" (§3.3; APPNOTE.TXT 6.1). It is
// weak: about 12 known plaintext bytes recover the keys (Biham–Kocher,
// bkcrack) whatever the password. It is offered only because it is the one
// method the unzip built into Windows and macOS opens.
//
// Entry data: a 12-byte header (11 random bytes and a check byte) followed by
// the inner data, all encrypted with the running keys.
const zipCryptoHeaderLen = 12

// zipCrypto holds the three running keys.
type zipCrypto struct{ k0, k1, k2 uint32 }

// newZipCrypto returns the keys initialised with the password bytes.
func newZipCrypto(password string) zipCrypto {
	z := zipCrypto{k0: 0x12345678, k1: 0x23456789, k2: 0x34567890}
	for i := 0; i < len(password); i++ {
		z.update(password[i])
	}
	return z
}

// crc32Byte is one step of the IEEE CRC-32 (without the final inversion).
func crc32Byte(x uint32, b byte) uint32 {
	return crc32.IEEETable[byte(x)^b] ^ x>>8
}

// update mixes one plaintext byte into the keys.
func (z *zipCrypto) update(b byte) {
	z.k0 = crc32Byte(z.k0, b)
	z.k1 = (z.k1+z.k0&0xff)*134775813 + 1
	z.k2 = crc32Byte(z.k2, byte(z.k1>>24))
}

// keyByte is the next keystream byte.
func (z *zipCrypto) keyByte() byte {
	t := uint16(z.k2 | 2)
	return byte((uint32(t) * uint32(t^1)) >> 8)
}

// encrypt encrypts src into dst (they may be the same slice); the keys are
// updated with the plaintext bytes.
func (z *zipCrypto) encrypt(dst, src []byte) {
	for i, p := range src {
		dst[i] = p ^ z.keyByte()
		z.update(p)
	}
}

// zipCryptoWriter encrypts the inner data of one ZipCrypto entry: it writes
// the encrypted header when it starts and the ciphertext on Write.
type zipCryptoWriter struct {
	w   io.Writer
	z   zipCrypto
	buf [chunkSize]byte
}

// newZipCryptoWriter starts a ZipCrypto entry on w: 11 header bytes are read
// from rnd, check is the 12th (§3.3).
func newZipCryptoWriter(w io.Writer, password string, check byte, rnd io.Reader) (*zipCryptoWriter, error) {
	z := new(zipCryptoWriter)
	if err := z.reset(w, password, check, rnd); err != nil {
		return nil, err
	}
	return z, nil
}

// reset starts a new entry on w, reusing z's buffer.
func (z *zipCryptoWriter) reset(w io.Writer, password string, check byte, rnd io.Reader) error {
	var head [zipCryptoHeaderLen]byte
	if _, err := io.ReadFull(rnd, head[:zipCryptoHeaderLen-1]); err != nil {
		return fmt.Errorf("ziputil: reading the ZipCrypto header: %w", err)
	}
	head[zipCryptoHeaderLen-1] = check
	z.w = w
	z.z = newZipCrypto(password)
	z.z.encrypt(head[:], head[:])
	_, err := w.Write(head[:])
	return err
}

// Write encrypts p into z's own buffer (p is never modified) and writes it.
func (z *zipCryptoWriter) Write(p []byte) (int, error) {
	done := 0
	for done < len(p) {
		out := z.buf[:min(len(p)-done, len(z.buf))]
		z.z.encrypt(out, p[done:done+len(out)])
		if _, err := z.w.Write(out); err != nil {
			return done, err
		}
		done += len(out)
	}
	return done, nil
}

// Close wipes the writer; ZipCrypto has no trailer.
func (z *zipCryptoWriter) Close() error {
	z.wipe()
	return nil
}

// wipe clears the keys and the buffer.
func (z *zipCryptoWriter) wipe() {
	z.z = zipCrypto{}
	clear(z.buf[:])
	z.w = nil
}
