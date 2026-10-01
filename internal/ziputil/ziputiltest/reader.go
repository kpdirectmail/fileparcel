// Package ziputiltest reads password-protected zip archives in tests:
// WinZip AES (AE-1 and AE-2, 128, 192 and 256-bit keys) and traditional
// PKWARE encryption (ZipCrypto). It also finds 7-Zip and Info-ZIP unzip for
// interoperability tests.
//
// It is written independently of the ziputil writer (its own extra-field
// parsing, counter loop, key schedule and check-byte rule, and the standard
// library's inflate), so a test that round-trips an archive through both
// checks the zip format rather than a bug the two could share.
//
// It is imported only by _test.go files (ziputil, uploads).
package ziputiltest

import (
	"archive/zip"
	"bytes"
	"compress/flate"
	"crypto/aes"
	"crypto/hmac"
	"crypto/pbkdf2"
	"crypto/sha1"
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"os/exec"
	"strings"
	"testing"
	"time"
)

// Entry is one decrypted archive entry.
type Entry struct {
	Name       string
	Dir        bool
	Encryption string // "", "zipcrypto", "aes128", "aes192" or "aes256"
	AEVersion  int    // 1 or 2 for WinZip AES entries, 0 otherwise
	Method     uint16 // method field of the header: 99 for WinZip AES
	Inner      uint16 // compression method of the data (for AES, the one in the 0x9901 extra)
	Flags      uint16
	Modified   time.Time
	Data       []byte
}

// Errors of encrypted entries.
var (
	// ErrWrongPassword: the AES password verification value or the ZipCrypto
	// check byte does not match.
	ErrWrongPassword = errors.New("ziputiltest: wrong password")
	// ErrAuthFailed: the AES MAC over the ciphertext does not match (tampered
	// data, or a wrong password that passed the 2-byte verification value).
	ErrAuthFailed = errors.New("ziputiltest: authentication code mismatch")
	// ErrCRC: the decrypted data does not match the header's CRC-32 or size,
	// or does not inflate (ZipCrypto; AE-1).
	ErrCRC = errors.New("ziputiltest: decrypted data fails the CRC-32 check")
)

// Header values of the formats, from APPNOTE.TXT and the WinZip AES spec.
const (
	methodStore   = 0
	methodDeflate = 8
	methodAES     = 99
	aesExtraID    = 0x9901
	aesMACLen     = 10
	aesPVVLen     = 2
	aesIterations = 1000
	zcHeaderLen   = 12
)

// Read decrypts every entry of the archive r of size bytes with password.
// Unencrypted entries are read with zip.File.Open; encrypted ones (flag bit
// 0) through zip.File.OpenRaw, because Open fails with zip.ErrAlgorithm for
// method 99 and would return ZipCrypto ciphertext as data.
func Read(r io.ReaderAt, size int64, password string) ([]Entry, error) {
	zr, err := zip.NewReader(r, size)
	if err != nil {
		return nil, err
	}
	out := make([]Entry, 0, len(zr.File))
	for _, f := range zr.File {
		e, err := readEntry(f, password)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", f.Name, err)
		}
		out = append(out, e)
	}
	return out, nil
}

// ReadBytes is Read of an archive held in memory.
func ReadBytes(b []byte, password string) ([]Entry, error) {
	return Read(bytes.NewReader(b), int64(len(b)), password)
}

func readEntry(f *zip.File, password string) (Entry, error) {
	e := Entry{Name: f.Name, Dir: strings.HasSuffix(f.Name, "/"), Method: f.Method, Inner: f.Method,
		Flags: f.Flags, Modified: f.Modified}
	if f.Flags&1 == 0 {
		if f.Method == methodAES {
			return e, errors.New("WinZip AES entry without the encryption flag")
		}
		rc, err := f.Open()
		if err != nil {
			return e, err
		}
		defer rc.Close()
		e.Data, err = io.ReadAll(rc)
		return e, err
	}

	raw, err := f.OpenRaw()
	if err != nil {
		return e, err
	}
	body, err := io.ReadAll(raw)
	if err != nil {
		return e, err
	}
	if uint64(len(body)) != f.CompressedSize64 {
		return e, fmt.Errorf("read %d bytes of entry data, the directory says %d", len(body), f.CompressedSize64)
	}
	var inner []byte
	if f.Method == methodAES {
		version, strength, method, err := parseAESExtra(f.Extra)
		if err != nil {
			return e, err
		}
		e.AEVersion, e.Inner = version, method
		e.Encryption = fmt.Sprintf("aes%d", 64+64*strength)
		if inner, err = decryptAES(body, password, strength); err != nil {
			return e, err
		}
	} else {
		e.Encryption = "zipcrypto"
		// The check byte is the CRC's high byte, or the DOS time's when a data
		// descriptor carries the CRC (bit 3), as Info-ZIP decides it.
		check := byte(f.CRC32 >> 24)
		if f.Flags&8 != 0 {
			check = byte(f.ModifiedTime >> 8)
		}
		if inner, err = decryptZipCrypto(body, password, check); err != nil {
			return e, err
		}
	}
	data, err := decompress(e.Inner, inner)
	switch {
	case err != nil && e.AEVersion == 2:
		return e, err // the MAC passed: a writer bug, not a wrong password
	case err != nil:
		return e, fmt.Errorf("%w: %v", ErrCRC, err)
	case uint64(len(data)) != f.UncompressedSize64:
		return e, fmt.Errorf("%w: %d bytes, the directory says %d", ErrCRC, len(data), f.UncompressedSize64)
	case e.AEVersion != 2 && crc32.ChecksumIEEE(data) != f.CRC32:
		return e, ErrCRC
	}
	e.Data = data
	return e, nil
}

// parseAESExtra finds the 0x9901 extra field: vendor version (1 = AE-1,
// 2 = AE-2), vendor id "AE", strength (1, 2, 3 = AES-128, -192, -256) and the
// compression method of the data.
func parseAESExtra(extra []byte) (version, strength int, method uint16, err error) {
	for len(extra) >= 4 {
		id := binary.LittleEndian.Uint16(extra)
		n := int(binary.LittleEndian.Uint16(extra[2:]))
		if len(extra) < 4+n {
			break
		}
		field := extra[4 : 4+n]
		extra = extra[4+n:]
		if id != aesExtraID {
			continue
		}
		if n != 7 || field[2] != 'A' || field[3] != 'E' {
			return 0, 0, 0, fmt.Errorf("malformed 0x9901 extra field % x", field)
		}
		version = int(binary.LittleEndian.Uint16(field))
		strength = int(field[4])
		method = binary.LittleEndian.Uint16(field[5:])
		if version != 1 && version != 2 || strength < 1 || strength > 3 {
			return 0, 0, 0, fmt.Errorf("unsupported WinZip AES version %d, strength %d", version, strength)
		}
		return version, strength, method, nil
	}
	return 0, 0, 0, errors.New("method 99 without a 0x9901 extra field")
}

// decryptAES checks and decrypts salt ‖ pvv ‖ ciphertext ‖ mac.
func decryptAES(body []byte, password string, strength int) ([]byte, error) {
	keyLen := 8 + 8*strength // 16, 24, 32
	saltLen := keyLen / 2    // 8, 12, 16
	if len(body) < saltLen+aesPVVLen+aesMACLen {
		return nil, fmt.Errorf("AES entry data of %d bytes is too short", len(body))
	}
	salt := body[:saltLen]
	pvv := body[saltLen : saltLen+aesPVVLen]
	ct := body[saltLen+aesPVVLen : len(body)-aesMACLen]
	mac := body[len(body)-aesMACLen:]

	dk, err := pbkdf2.Key(sha1.New, password, salt, aesIterations, 2*keyLen+aesPVVLen)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(dk[2*keyLen:], pvv) {
		return nil, ErrWrongPassword
	}
	h := hmac.New(sha1.New, dk[keyLen:2*keyLen])
	h.Write(ct)
	if !hmac.Equal(h.Sum(nil)[:aesMACLen], mac) {
		return nil, ErrAuthFailed
	}
	block, err := aes.NewCipher(dk[:keyLen])
	if err != nil {
		return nil, err
	}
	// Counter block i (from 1) = little-endian 64-bit i, then 8 zero bytes.
	out := make([]byte, len(ct))
	var ctr, ks [aes.BlockSize]byte
	for i := 0; i < len(ct); i += aes.BlockSize {
		binary.LittleEndian.PutUint64(ctr[:8], uint64(i/aes.BlockSize)+1)
		block.Encrypt(ks[:], ctr[:])
		for j := i; j < len(ct) && j < i+aes.BlockSize; j++ {
			out[j] = ct[j] ^ ks[j-i]
		}
	}
	return out, nil
}

var crcTable = crc32.MakeTable(crc32.IEEE)

// zcKeys are the three ZipCrypto keys (APPNOTE.TXT 6.1.5).
type zcKeys [3]uint32

func (k *zcKeys) update(c byte) {
	k[0] = crcTable[(k[0]^uint32(c))&0xff] ^ (k[0] >> 8)
	k[1] += k[0] & 0xff
	k[1] = k[1]*134775813 + 1
	k[2] = crcTable[(k[2]^(k[1]>>24))&0xff] ^ (k[2] >> 8)
}

func (k *zcKeys) decryptByte() byte {
	temp := k[2]&0xffff | 2
	return byte((temp * (temp ^ 1)) >> 8)
}

// decryptZipCrypto decrypts the 12-byte header and the data after it.
func decryptZipCrypto(body []byte, password string, check byte) ([]byte, error) {
	if len(body) < zcHeaderLen {
		return nil, fmt.Errorf("ZipCrypto entry data of %d bytes is too short", len(body))
	}
	k := zcKeys{0x12345678, 0x23456789, 0x34567890}
	for i := 0; i < len(password); i++ {
		k.update(password[i])
	}
	out := make([]byte, len(body))
	for i, c := range body {
		p := c ^ k.decryptByte()
		k.update(p)
		out[i] = p
	}
	if out[zcHeaderLen-1] != check {
		return nil, ErrWrongPassword
	}
	return out[zcHeaderLen:], nil
}

func decompress(method uint16, data []byte) ([]byte, error) {
	switch method {
	case methodStore:
		return data, nil
	case methodDeflate:
		fr := flate.NewReader(bytes.NewReader(data))
		defer fr.Close()
		return io.ReadAll(fr)
	}
	return nil, fmt.Errorf("unsupported compression method %d", method)
}

// Require7z returns the path of 7-Zip (7z, 7zz or 7za) and skips the test
// when none is installed.
func Require7z(t testing.TB) string {
	t.Helper()
	for _, name := range []string{"7z", "7zz", "7za"} {
		if p, err := exec.LookPath(name); err == nil {
			return p
		}
	}
	t.Skip("7-Zip (7z, 7zz or 7za) is not installed")
	return ""
}

// RequireUnzip returns the path of Info-ZIP unzip and skips the test when it
// is not installed (or another unzip, without -P, is).
func RequireUnzip(t testing.TB) string {
	t.Helper()
	p, err := exec.LookPath("unzip")
	if err != nil {
		t.Skip("Info-ZIP unzip is not installed")
	}
	if out, _ := exec.Command(p, "-v").CombinedOutput(); !bytes.Contains(out, []byte("Info-ZIP")) {
		t.Skip("unzip is not Info-ZIP unzip")
	}
	return p
}
