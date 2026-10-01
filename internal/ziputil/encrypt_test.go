package ziputil

import (
	"archive/zip"
	"bytes"
	"crypto/aes"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"hash/crc32"
	"io"
	"math"
	"math/rand/v2"
	"strings"
	"testing"
	"time"

	"github.com/klauspost/compress/flate"

	"fileparcel/internal/ziputil/ziputiltest"
)

// Known-answer vectors of zip-password-final §3.6, recomputed independently
// and cross-checked with 7-Zip.
const (
	katPassword  = "correct horse battery staple"
	katSalt      = "000102030405060708090a0b0c0d0e0f"
	katPlain     = "hello, fileparcel\n"
	katDK        = "00e9bf90e6fff98019dd9c12a2062036ef5f3b583df3ad7a5144f6c7727371ecdcebbe1607aadfd4f985bbb2944c9fe404ca57cce278ee01d0da2f28b2a6821d790e"
	katEncKey    = "00e9bf90e6fff98019dd9c12a2062036ef5f3b583df3ad7a5144f6c7727371ec"
	katAuthKey   = "dcebbe1607aadfd4f985bbb2944c9fe404ca57cce278ee01d0da2f28b2a6821d"
	katPVV       = "790e"
	katKS1       = "129180ad1cb2cbce5d95ef0af169ff49"
	katKS2       = "7ab0a0282151d56c774b314d098989b0"
	katAESData   = "000102030405060708090a0b0c0d0e0f" + "790e" + "7af4ecc1739eeba834f98a7a901b9c2c16ba" + "7c2a0ecd45f25f68d369"
	katZCHeader  = "000102030405060708090a"
	katZCCRC     = 0x37d13eb4
	katZCData    = "7f43ccea3111f047a21c6ddda653c626ced7572dcd233592e10b771e29a8"
	wrongAuthPW  = "wrong password 84278" // PVV 790e for katSalt: passes the AES check, fails the MAC
	wrongCRCPW   = "wrong password 74"    // decrypts the ZipCrypto header to check byte 0x37: fails the CRC
	wrongPlainPW = "wrong password 1"     // PVV cb94, check byte c8: rejected at once by both
)

// testMod has an odd second and a fraction: the DOS time keeps even seconds,
// the 0x5455 extra the exact second.
var testMod = time.Date(2026, 9, 19, 10, 11, 13, 500_000_000, time.UTC)

func unhex(t testing.TB, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// rawEntryData returns the stored (encrypted) bytes of every file entry.
func rawEntryData(t testing.TB, archive []byte) map[string][]byte {
	t.Helper()
	zr, err := zip.NewReader(bytes.NewReader(archive), int64(len(archive)))
	if err != nil {
		t.Fatal(err)
	}
	out := map[string][]byte{}
	for _, f := range zr.File {
		rc, err := f.OpenRaw()
		if err != nil {
			t.Fatal(err)
		}
		b, err := io.ReadAll(rc)
		if err != nil {
			t.Fatal(err)
		}
		out[f.Name] = b
	}
	return out
}

// katArchive is a one-entry Store archive of katPlain with the injected
// salt (AES) or header bytes (ZipCrypto).
func katArchive(t testing.TB, enc Encryption) []byte {
	t.Helper()
	rnd := katSalt
	if enc == EncryptionZipCrypto {
		rnd = katZCHeader
	}
	var buf bytes.Buffer
	w, err := New(&buf, Options{Compression: CompressionStore, Encryption: enc, Password: katPassword,
		Rand: bytes.NewReader(unhex(t, rnd))})
	if err != nil {
		t.Fatal(err)
	}
	must(t, w.AddFileAt("text.txt", testMod, int64(len(katPlain)), strings.NewReader(katPlain)))
	must(t, w.Close())
	return buf.Bytes()
}

func TestAESKnownAnswer(t *testing.T) {
	salt := unhex(t, katSalt)
	dk, err := aesKeys(katPassword, salt)
	if err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(dk) != katDK {
		t.Fatalf("dk %x", dk)
	}
	if got := hex.EncodeToString(dk[:aesKeyLen]); got != katEncKey {
		t.Errorf("encKey %s", got)
	}
	if got := hex.EncodeToString(dk[aesKeyLen : 2*aesKeyLen]); got != katAuthKey {
		t.Errorf("authKey %s", got)
	}
	if got := hex.EncodeToString(dk[2*aesKeyLen:]); got != katPVV {
		t.Errorf("pvv %s", got)
	}

	// Keystream blocks 1 and 2, then block 2³²+5 (the carry out of the low
	// 32 bits): AES(encKey, LE64(n) ‖ 0⁸).
	block, err := aes.NewCipher(dk[:aesKeyLen])
	if err != nil {
		t.Fatal(err)
	}
	ks := make([]byte, 32)
	newLECTR(block).XORKeyStream(ks, make([]byte, 32))
	if got := hex.EncodeToString(ks); got != katKS1+katKS2 {
		t.Errorf("keystream blocks 1, 2: %s", got)
	}
	c := newLECTR(block)
	c.n = 1<<32 + 4
	got := make([]byte, 16)
	c.XORKeyStream(got, make([]byte, 16))
	var ctr, want [16]byte
	binary.LittleEndian.PutUint64(ctr[:], 1<<32+5)
	block.Encrypt(want[:], ctr[:])
	if !bytes.Equal(got, want[:]) {
		t.Errorf("keystream block 2^32+5: %x, want %x", got, want)
	}
	// Byte-wise XORKeyStream calls give the same stream as one call.
	c = newLECTR(block)
	one := make([]byte, 32)
	for i := range one {
		c.XORKeyStream(one[i:i+1], []byte{0})
	}
	if !bytes.Equal(one, ks) {
		t.Errorf("byte-wise keystream %x", one)
	}

	archive := katArchive(t, EncryptionAES256)
	if got := rawEntryData(t, archive)["text.txt"]; hex.EncodeToString(got) != katAESData {
		t.Fatalf("entry data %x\nwant       %s", got, katAESData)
	}
	es, err := ziputiltest.ReadBytes(archive, katPassword)
	if err != nil || len(es) != 1 || string(es[0].Data) != katPlain || es[0].AEVersion != 2 || es[0].Encryption != "aes256" {
		t.Fatalf("read back: %+v %v", es, err)
	}
}

func TestZipCryptoKnownAnswer(t *testing.T) {
	if crc := crc32.ChecksumIEEE([]byte(katPlain)); crc != katZCCRC {
		t.Fatalf("crc %08x", crc)
	}
	archive := katArchive(t, EncryptionZipCrypto)
	if got := rawEntryData(t, archive)["text.txt"]; hex.EncodeToString(got) != katZCData {
		t.Fatalf("entry data %x\nwant       %s", got, katZCData)
	}
	zr, err := zip.NewReader(bytes.NewReader(archive), int64(len(archive)))
	if err != nil {
		t.Fatal(err)
	}
	if f := zr.File[0]; f.CRC32 != katZCCRC || f.Method != zip.Store || f.Flags != 1 || f.CompressedSize64 != 30 {
		t.Fatalf("header %+v", f.FileHeader)
	}
	es, err := ziputiltest.ReadBytes(archive, katPassword)
	if err != nil || string(es[0].Data) != katPlain || es[0].Encryption != "zipcrypto" {
		t.Fatalf("read back: %+v %v", es, err)
	}
}

func TestWrongPasswordVectors(t *testing.T) {
	aes := katArchive(t, EncryptionAES256)
	zc := katArchive(t, EncryptionZipCrypto)
	for _, c := range []struct {
		name, archive string
		b             []byte
		pw            string
		want          error
	}{
		{"aes collision", "aes", aes, wrongAuthPW, ziputiltest.ErrAuthFailed},
		{"aes plain", "aes", aes, wrongPlainPW, ziputiltest.ErrWrongPassword},
		{"zipcrypto collision", "zipcrypto", zc, wrongCRCPW, ziputiltest.ErrCRC},
		{"zipcrypto plain", "zipcrypto", zc, wrongPlainPW, ziputiltest.ErrWrongPassword},
	} {
		if _, err := ziputiltest.ReadBytes(c.b, c.pw); !errors.Is(err, c.want) {
			t.Errorf("%s: %q gave %v, want %v", c.name, c.pw, err, c.want)
		}
	}
}

// entrySpec is one entry of the round-trip set (§13.1 tests 4 and 6).
type entrySpec struct {
	name string // name added and expected in the archive
	dir  bool
	data []byte
	// inner is the expected inner (AES) or header (ZipCrypto) method under
	// CompressionAuto; CompressionStore always stores.
	inner uint16
	utf8  bool // expects the UTF-8 flag
}

// seeded returns n deterministic pseudo-random bytes.
func seeded(n int, seed byte) []byte {
	b := make([]byte, n)
	rand.NewChaCha8([32]byte{seed}).Read(b)
	return b
}

func foxText(n int) []byte {
	return []byte(strings.Repeat("the quick brown fox\n", n/20+1)[:n])
}

func roundTripSet() []entrySpec {
	return []entrySpec{
		{name: "docs/", dir: true},
		{name: "docs/fox.txt", data: foxText(20000), inner: zip.Deflate},
		{name: "docs/rand.bin", data: seeded(5000, 1), inner: zip.Store}, // Deflate does not shrink it
		{name: "photo.jpg", data: foxText(3000), inner: zip.Store},       // Store by extension
		{name: "empty.txt", data: []byte{}, inner: zip.Store},
		{name: "café über.txt", data: []byte(strings.Repeat("über café ", 200)), inner: zip.Deflate, utf8: true},
		{name: "tilde~x.txt", data: []byte("tilde"), inner: zip.Store, utf8: true},
		{name: "two.bin", data: []byte("hi"), inner: zip.Store},
	}
}

// buildSet writes the entries with AddDir/AddFileAt and returns the archive.
func buildSet(t testing.TB, o Options, set []entrySpec) []byte {
	t.Helper()
	var buf bytes.Buffer
	w, err := New(&buf, o)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range set {
		if e.dir {
			must(t, w.AddDir(e.name, testMod))
		} else {
			must(t, w.AddFileAt(e.name, testMod, int64(len(e.data)), bytes.NewReader(e.data)))
		}
	}
	must(t, w.Close())
	if w.Written() != int64(buf.Len()) {
		t.Fatalf("Written %d != %d", w.Written(), buf.Len())
	}
	return buf.Bytes()
}

// deflatedLen is the length of klauspost flate level 5 output for p.
func deflatedLen(t testing.TB, p []byte) int64 {
	t.Helper()
	var buf bytes.Buffer
	fw, err := flate.NewWriter(&buf, DeflateLevel)
	if err != nil {
		t.Fatal(err)
	}
	fw.Write(p)
	fw.Close()
	return int64(buf.Len())
}

// extraFields splits a zip extra block into id → data.
func extraFields(t testing.TB, extra []byte) map[uint16][]byte {
	t.Helper()
	out := map[uint16][]byte{}
	for len(extra) > 0 {
		if len(extra) < 4 {
			t.Fatalf("truncated extra % x", extra)
		}
		id, n := binary.LittleEndian.Uint16(extra), int(binary.LittleEndian.Uint16(extra[2:]))
		if len(extra) < 4+n {
			t.Fatalf("truncated extra field %#04x", id)
		}
		out[id] = extra[4 : 4+n]
		extra = extra[4+n:]
	}
	return out
}

// checkRoundTrip checks every header of an encrypted archive of set and reads
// it back with the independent reader.
func checkRoundTrip(t *testing.T, archive []byte, enc Encryption, comp Compression, set []entrySpec) {
	t.Helper()
	zr, err := zip.NewReader(bytes.NewReader(archive), int64(len(archive)))
	if err != nil {
		t.Fatal(err)
	}
	if len(zr.File) != len(set) {
		t.Fatalf("%d entries, want %d", len(zr.File), len(set))
	}
	for i, e := range set {
		f := zr.File[i]
		if f.Name != e.name {
			t.Fatalf("entry %d is %q, want %q", i, f.Name, e.name)
		}
		if got := f.Flags&0x800 != 0; got != e.utf8 {
			t.Errorf("%s: UTF-8 flag %v", e.name, got)
		}
		ex := extraFields(t, f.Extra)
		if e.dir {
			if f.Flags&1 != 0 || f.Method != zip.Store || ex[0x9901] != nil {
				t.Errorf("%s: directory entry is encrypted: %+v", e.name, f.FileHeader)
			}
			continue
		}
		inner := e.inner
		if comp == CompressionStore {
			inner = zip.Store
		}
		clen := int64(len(e.data))
		if inner == zip.Deflate {
			clen = deflatedLen(t, e.data)
		}
		if f.Flags&1 == 0 || f.Flags&8 != 0 || f.UncompressedSize64 != uint64(len(e.data)) {
			t.Errorf("%s: flags %#x, size %d", e.name, f.Flags, f.UncompressedSize64)
		}
		if ts := ex[0x5455]; len(ts) != 5 || ts[0] != 1 || int64(binary.LittleEndian.Uint32(ts[1:])) != testMod.Unix() {
			t.Errorf("%s: 0x5455 extra % x", e.name, ts)
		}
		switch enc {
		case EncryptionAES256:
			want := []byte{2, 0, 'A', 'E', 3, byte(inner), 0}
			if f.Method != 99 || f.CRC32 != 0 || f.ReaderVersion != 51 || f.CreatorVersion != 0x0333 ||
				!bytes.Equal(ex[0x9901], want) || f.CompressedSize64 != uint64(clen+28) {
				t.Errorf("%s: header %+v, 0x9901 % x (want % x), inner length %d", e.name, f.FileHeader, ex[0x9901], want, clen)
			}
		case EncryptionZipCrypto:
			if f.Method != inner || f.CRC32 != crc32.ChecksumIEEE(e.data) || f.ReaderVersion != 20 ||
				f.CreatorVersion != 0x0314 || ex[0x9901] != nil || f.CompressedSize64 != uint64(clen+12) {
				t.Errorf("%s: header %+v, inner length %d", e.name, f.FileHeader, clen)
			}
			// The check byte is the CRC's high byte (decrypted here with the
			// writer's own key schedule).
			raw, err := f.OpenRaw()
			if err != nil {
				t.Fatal(err)
			}
			head := make([]byte, zipCryptoHeaderLen)
			if _, err := io.ReadFull(raw, head); err != nil {
				t.Fatal(err)
			}
			z := newZipCrypto(katPassword)
			for i, c := range head {
				head[i] = c ^ z.keyByte()
				z.update(head[i])
			}
			if head[11] != byte(f.CRC32>>24) {
				t.Errorf("%s: check byte %#x, CRC %08x", e.name, head[11], f.CRC32)
			}
		}
		if mode := f.Mode(); mode != 0o644 {
			t.Errorf("%s: mode %v", e.name, mode)
		}
	}

	es, err := ziputiltest.ReadBytes(archive, katPassword)
	if err != nil {
		t.Fatal(err)
	}
	for i, e := range set {
		got := es[i]
		if e.dir {
			if !got.Dir || got.Encryption != "" {
				t.Errorf("%s: read back as %+v", e.name, got)
			}
			continue
		}
		if !bytes.Equal(got.Data, e.data) {
			t.Errorf("%s: data differs (%d bytes, want %d)", e.name, len(got.Data), len(e.data))
		}
		if !got.Modified.Equal(testMod.Truncate(time.Second)) {
			t.Errorf("%s: modified %v", e.name, got.Modified)
		}
		if wantEnc := string(enc); got.Encryption != wantEnc {
			t.Errorf("%s: encryption %q", e.name, got.Encryption)
		}
	}
	if _, err := ziputiltest.ReadBytes(archive, wrongPlainPW); err == nil {
		t.Error("a wrong password read the archive")
	}
}

func TestAESRoundTrip(t *testing.T) {
	for _, comp := range []Compression{CompressionAuto, CompressionStore} {
		t.Run(string(comp), func(t *testing.T) {
			set := roundTripSet()
			archive := buildSet(t, Options{Compression: comp, Encryption: EncryptionAES256, Password: katPassword}, set)
			checkRoundTrip(t, archive, EncryptionAES256, comp, set)
		})
	}
}

func TestZipCryptoRoundTrip(t *testing.T) {
	for _, comp := range []Compression{CompressionAuto, CompressionStore} {
		t.Run(string(comp), func(t *testing.T) {
			set := roundTripSet()
			archive := buildSet(t, Options{Compression: comp, Encryption: EncryptionZipCrypto, Password: katPassword}, set)
			checkRoundTrip(t, archive, EncryptionZipCrypto, comp, set)
		})
	}
}

// localEntry is a local file header parsed from the raw archive bytes.
type localEntry struct {
	readerVersion, flags, method, modTime, modDate uint16
	crc, csize, usize                              uint32
	name                                           string
	extra                                          []byte
	descriptor                                     []byte // after the data when flag bit 3 is set
	next                                           uint32 // signature after the entry
}

// walkLocal parses the local header of every entry in order, using the
// central directory's sizes to skip the data (and the descriptor, if any).
func walkLocal(t testing.TB, b []byte) (*zip.Reader, []localEntry) {
	t.Helper()
	zr, err := zip.NewReader(bytes.NewReader(b), int64(len(b)))
	if err != nil {
		t.Fatal(err)
	}
	var out []localEntry
	off := 0
	for _, f := range zr.File {
		h := b[off:]
		if binary.LittleEndian.Uint32(h) != 0x04034b50 {
			t.Fatalf("%s: no local header at %d", f.Name, off)
		}
		le := binary.LittleEndian
		e := localEntry{readerVersion: le.Uint16(h[4:]), flags: le.Uint16(h[6:]), method: le.Uint16(h[8:]),
			modTime: le.Uint16(h[10:]), modDate: le.Uint16(h[12:]), crc: le.Uint32(h[14:]),
			csize: le.Uint32(h[18:]), usize: le.Uint32(h[22:])}
		n, x := int(le.Uint16(h[26:])), int(le.Uint16(h[28:]))
		e.name = string(h[30 : 30+n])
		e.extra = h[30+n : 30+n+x]
		data := off + 30 + n + x
		if d, err := f.DataOffset(); err != nil || d != int64(data) {
			t.Fatalf("%s: data offset %d, central %d %v", f.Name, data, d, err)
		}
		off = data + int(f.CompressedSize64)
		if e.flags&8 != 0 {
			dlen := 16
			if f.CompressedSize64 > math.MaxUint32 || f.UncompressedSize64 > math.MaxUint32 {
				dlen = 24
			}
			e.descriptor = b[off : off+dlen]
			off += dlen
		}
		e.next = binary.LittleEndian.Uint32(b[off:])
		out = append(out, e)
	}
	return zr, out
}

func TestLocalHeadersComplete(t *testing.T) {
	for _, enc := range []Encryption{EncryptionAES256, EncryptionZipCrypto} {
		set := roundTripSet()
		archive := buildSet(t, Options{Encryption: enc, Password: katPassword}, set)
		zr, locals := walkLocal(t, archive)
		for i, l := range locals {
			f := zr.File[i]
			if set[i].dir {
				continue
			}
			if l.flags&8 != 0 || l.descriptor != nil {
				t.Errorf("%s %s: data descriptor flag", enc, f.Name)
			}
			if l.crc != f.CRC32 || uint64(l.csize) != f.CompressedSize64 || uint64(l.usize) != f.UncompressedSize64 {
				t.Errorf("%s %s: local crc/sizes %08x/%d/%d, central %08x/%d/%d", enc, f.Name,
					l.crc, l.csize, l.usize, f.CRC32, f.CompressedSize64, f.UncompressedSize64)
			}
			if l.name != f.Name || l.flags != f.Flags || l.method != f.Method || l.readerVersion != f.ReaderVersion ||
				l.modTime != f.ModifiedTime || l.modDate != f.ModifiedDate || !bytes.Equal(l.extra, f.Extra) {
				t.Errorf("%s %s: local header differs from the central one", enc, f.Name)
			}
			if l.next == 0x08074b50 {
				t.Errorf("%s %s: a data descriptor follows", enc, f.Name)
			}
		}
	}
}

func TestTamperDetected(t *testing.T) {
	archive := buildSet(t, Options{Compression: CompressionStore, Encryption: EncryptionAES256, Password: katPassword},
		[]entrySpec{{name: "a.txt", data: foxText(100)}})
	zr, err := zip.NewReader(bytes.NewReader(archive), int64(len(archive)))
	if err != nil {
		t.Fatal(err)
	}
	data, err := zr.File[0].DataOffset()
	if err != nil {
		t.Fatal(err)
	}
	end := data + int64(zr.File[0].CompressedSize64)
	for _, c := range []struct {
		name string
		off  int64
		want []error
	}{
		{"salt", data + 3, []error{ziputiltest.ErrWrongPassword, ziputiltest.ErrAuthFailed}},
		{"ciphertext", data + 18 + 50, []error{ziputiltest.ErrAuthFailed}},
		{"mac", end - 1, []error{ziputiltest.ErrAuthFailed}},
	} {
		b := bytes.Clone(archive)
		b[c.off] ^= 0x01
		_, err := ziputiltest.ReadBytes(b, katPassword)
		ok := false
		for _, w := range c.want {
			ok = ok || errors.Is(err, w)
		}
		if !ok {
			t.Errorf("flipped %s byte: %v, want one of %v", c.name, err, c.want)
		}
	}
}

func TestSaltsUnique(t *testing.T) {
	var buf bytes.Buffer
	w, err := New(&buf, Options{Encryption: EncryptionAES256, Password: katPassword}) // crypto/rand
	if err != nil {
		t.Fatal(err)
	}
	const n = 1000
	for i := range n {
		must(t, w.AddFileAt(strings.Repeat("e", 1+i%7)+string(rune('a'+i%26))+".txt", testMod, 0, bytes.NewReader(nil)))
	}
	must(t, w.Close())
	raw := rawEntryData(t, buf.Bytes())
	if len(raw) != n {
		t.Fatalf("%d entries", len(raw))
	}
	salts := map[string]bool{}
	for name, b := range raw {
		if len(b) != aesOverhead {
			t.Fatalf("%s: %d bytes", name, len(b))
		}
		salts[string(b[:aesSaltLen])] = true
	}
	if len(salts) != n {
		t.Fatalf("%d distinct salts for %d entries", len(salts), n)
	}
}

// changingReaderAt returns other bytes from the second read of offset 0 on.
type changingReaderAt struct {
	data      []byte
	zeroReads int
}

func (c *changingReaderAt) ReadAt(p []byte, off int64) (int, error) {
	if off >= int64(len(c.data)) {
		return 0, io.EOF
	}
	n := copy(p, c.data[off:])
	if off == 0 {
		if c.zeroReads++; c.zeroReads > 1 {
			p[0] ^= 0xff
		}
	}
	if n < len(p) {
		return n, io.EOF
	}
	return n, nil
}

// errReaderAt fails every read (a canceled job context).
type errReaderAt struct{ err error }

func (e errReaderAt) ReadAt([]byte, int64) (int, error) { return 0, e.err }

// fullErrReaderAt fills every read but reports err with it.
type fullErrReaderAt struct{ err error }

func (e fullErrReaderAt) ReadAt(p []byte, _ int64) (int, error) {
	clear(p)
	return len(p), e.err
}

func TestTwoPassSourceChanged(t *testing.T) {
	big := foxText(6 << 20)
	hexBig := []byte(hex.EncodeToString(seeded(6<<20, 2))) // 12 MiB, Deflate to more than 4 MiB
	for _, c := range []struct {
		name string
		o    Options
		data []byte
	}{
		{"zipcrypto store", Options{Compression: CompressionStore, Encryption: EncryptionZipCrypto}, big},
		{"aes deflate not kept", Options{Compression: CompressionDeflate, Encryption: EncryptionAES256}, hexBig},
		{"zipcrypto deflate not kept", Options{Compression: CompressionDeflate, Encryption: EncryptionZipCrypto}, hexBig},
		{"aes store fallback", Options{Compression: CompressionDeflate, Encryption: EncryptionAES256}, seeded(6<<20, 3)},
	} {
		c.o.Password = katPassword
		w, err := New(io.Discard, c.o)
		if err != nil {
			t.Fatal(err)
		}
		src := &changingReaderAt{data: c.data}
		err = w.AddFileAt("big.bin", testMod, int64(len(c.data)), src)
		if !errors.Is(err, ErrSourceChanged) || src.zeroReads != 2 {
			t.Errorf("%s: %v after %d reads of offset 0", c.name, err, src.zeroReads)
		}
		if err := w.AddDir("later", testMod); !errors.Is(err, ErrSourceChanged) {
			t.Errorf("%s: the Writer is usable after the error: %v", c.name, err)
		}
	}

	canceled := errors.New("job canceled")
	for _, enc := range []Encryption{EncryptionAES256, EncryptionZipCrypto} {
		for _, size := range []int{1000, 6 << 20} {
			data := foxText(size)
			for _, c := range []struct {
				name string
				size int64
				src  io.ReaderAt
				want error
			}{
				{"short", int64(size) + 10, bytes.NewReader(data), ErrSizeMismatch},
				{"long", int64(size) - 1, bytes.NewReader(data), ErrSizeMismatch},
				{"read error", int64(size), errReaderAt{canceled}, canceled},
				{"full read with an error", int64(size), fullErrReaderAt{canceled}, canceled},
			} {
				for _, comp := range []Compression{CompressionStore, CompressionDeflate} {
					w, err := New(io.Discard, Options{Compression: comp, Encryption: enc, Password: katPassword})
					if err != nil {
						t.Fatal(err)
					}
					if err := w.AddFileAt("a.txt", testMod, c.size, c.src); !errors.Is(err, c.want) {
						t.Errorf("%s %s %d %s: %v, want %v", enc, comp, size, c.name, err, c.want)
					}
					if err := w.AddFileAt("b.txt", testMod, 1, strings.NewReader("b")); !errors.Is(err, c.want) {
						t.Errorf("%s %s %d %s: the Writer is usable after the error: %v", enc, comp, size, c.name, err)
					}
				}
			}
		}
	}
}

// countingReaderAt counts the bytes read from it.
type countingReaderAt struct {
	r *bytes.Reader
	n int64
}

func (c *countingReaderAt) ReadAt(p []byte, off int64) (int, error) {
	n, err := c.r.ReadAt(p, off)
	c.n += int64(n)
	return n, err
}

func TestPassCounts(t *testing.T) {
	mib := func(n int) int { return n << 20 }
	for _, c := range []struct {
		name  string
		enc   Encryption
		comp  Compression
		data  []byte
		inner uint16
		reads int64
	}{
		{"aes store 1 MiB", EncryptionAES256, CompressionStore, foxText(mib(1)), zip.Store, 1},
		{"aes deflate 1 MiB", EncryptionAES256, CompressionDeflate, foxText(mib(1)), zip.Deflate, 1},
		{"aes fallback 1 MiB", EncryptionAES256, CompressionDeflate, seeded(mib(1), 4), zip.Store, 1},
		{"zipcrypto store 1 MiB", EncryptionZipCrypto, CompressionStore, foxText(mib(1)), zip.Store, 1},
		{"zipcrypto deflate 1 MiB", EncryptionZipCrypto, CompressionDeflate, foxText(mib(1)), zip.Deflate, 1},
		{"zipcrypto fallback 1 MiB", EncryptionZipCrypto, CompressionDeflate, seeded(mib(1), 5), zip.Store, 1},
		{"aes store 6 MiB", EncryptionAES256, CompressionStore, foxText(mib(6)), zip.Store, 1},
		{"aes deflate kept 6 MiB", EncryptionAES256, CompressionDeflate, foxText(mib(6)), zip.Deflate, 1},
		{"aes fallback 6 MiB", EncryptionAES256, CompressionDeflate, seeded(mib(6), 6), zip.Store, 2},
		{"zipcrypto store 6 MiB", EncryptionZipCrypto, CompressionStore, foxText(mib(6)), zip.Store, 2},
		{"zipcrypto deflate kept 6 MiB", EncryptionZipCrypto, CompressionDeflate, foxText(mib(6)), zip.Deflate, 1},
		{"zipcrypto fallback 6 MiB", EncryptionZipCrypto, CompressionDeflate, seeded(mib(6), 7), zip.Store, 2},
		{"aes deflate 12 MiB hex", EncryptionAES256, CompressionDeflate, []byte(hex.EncodeToString(seeded(mib(6), 8))), zip.Deflate, 2},
		{"zipcrypto deflate 12 MiB hex", EncryptionZipCrypto, CompressionDeflate, []byte(hex.EncodeToString(seeded(mib(6), 9))), zip.Deflate, 2},
	} {
		t.Run(c.name, func(t *testing.T) {
			var buf bytes.Buffer
			w, err := New(&buf, Options{Compression: c.comp, Encryption: c.enc, Password: katPassword})
			if err != nil {
				t.Fatal(err)
			}
			src := &countingReaderAt{r: bytes.NewReader(c.data)}
			must(t, w.AddFileAt("f.bin", testMod, int64(len(c.data)), src))
			must(t, w.Close())
			if src.n != c.reads*int64(len(c.data)) {
				t.Errorf("read %d bytes = %.2f passes, want %d", src.n, float64(src.n)/float64(len(c.data)), c.reads)
			}
			es, err := ziputiltest.ReadBytes(buf.Bytes(), katPassword)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(es[0].Data, c.data) || es[0].Inner != c.inner {
				t.Errorf("read back %d bytes, inner method %d (want %d)", len(es[0].Data), es[0].Inner, c.inner)
			}
		})
	}
}

func TestNeedsDescriptor(t *testing.T) {
	for _, c := range []struct {
		size, csize int64
		want        bool
	}{
		{0xFFFFFFFE, 0xFFFFFFFE + 28, false},
		{0xFFFFFFFF, 0xFFFFFFFF + 28, true},
		{0x100000000, 0x100000000 + 12, false},
		{0xFFFFFFFF - 28, 0xFFFFFFFF, true},
		{0, 28, false},
	} {
		if got := needsDescriptor(c.size, c.csize); got != c.want {
			t.Errorf("needsDescriptor(%#x, %#x) = %v", c.size, c.csize, got)
		}
	}
}

// forceDescriptor sets testForceDescriptor for the test.
func forceDescriptor(t *testing.T, names ...string) {
	t.Cleanup(func() { testForceDescriptor = nil })
	testForceDescriptor = func(name string) bool {
		for _, n := range names {
			if n == name {
				return true
			}
		}
		return false
	}
}

// descriptorSet has one entry written with a data descriptor.
func descriptorSet() []entrySpec {
	return []entrySpec{
		{name: "before.txt", data: foxText(500), inner: zip.Deflate},
		{name: "forced.txt", data: foxText(3000), inner: zip.Deflate},
		{name: "forced.bin", data: seeded(700, 10), inner: zip.Store},
		{name: "after.txt", data: []byte("after"), inner: zip.Store},
	}
}

func TestDescriptorPath(t *testing.T) {
	forceDescriptor(t, "forced.txt", "forced.bin")
	for _, enc := range []Encryption{EncryptionAES256, EncryptionZipCrypto} {
		set := descriptorSet()
		archive := buildSet(t, Options{Encryption: enc, Password: katPassword}, set)
		zr, locals := walkLocal(t, archive)
		for i, l := range locals {
			f := zr.File[i]
			forced := strings.HasPrefix(f.Name, "forced")
			if !forced {
				if l.flags&8 != 0 {
					t.Errorf("%s %s: unexpected descriptor", enc, f.Name)
				}
				continue
			}
			if l.flags&8 == 0 || f.Flags&8 == 0 || l.crc != 0 || l.csize != 0 || l.usize != 0 {
				t.Errorf("%s %s: local header flags %#x crc %08x sizes %d/%d", enc, f.Name, l.flags, l.crc, l.csize, l.usize)
				continue
			}
			d := l.descriptor
			le := binary.LittleEndian
			if le.Uint32(d) != 0x08074b50 || le.Uint32(d[4:]) != f.CRC32 ||
				uint64(le.Uint32(d[8:])) != f.CompressedSize64 || uint64(le.Uint32(d[12:])) != f.UncompressedSize64 {
				t.Errorf("%s %s: descriptor % x for crc %08x sizes %d/%d", enc, f.Name, d, f.CRC32, f.CompressedSize64, f.UncompressedSize64)
			}
			if enc == EncryptionZipCrypto {
				raw, err := f.OpenRaw()
				if err != nil {
					t.Fatal(err)
				}
				head := make([]byte, zipCryptoHeaderLen)
				io.ReadFull(raw, head)
				z := newZipCrypto(katPassword)
				for i, c := range head {
					head[i] = c ^ z.keyByte()
					z.update(head[i])
				}
				if head[11] != byte(f.ModifiedTime>>8) {
					t.Errorf("%s: check byte %#x, want the time's high byte %#x", f.Name, head[11], byte(f.ModifiedTime>>8))
				}
			}
		}
		es, err := ziputiltest.ReadBytes(archive, katPassword)
		if err != nil {
			t.Fatalf("%s: %v", enc, err)
		}
		for i, e := range set {
			if !bytes.Equal(es[i].Data, e.data) {
				t.Errorf("%s %s: data differs", enc, e.name)
			}
		}
	}
}

func TestNewValidation(t *testing.T) {
	for _, c := range []struct {
		name string
		o    Options
	}{
		{"tar", Options{Format: FormatTar, Encryption: EncryptionAES256, Password: katPassword}},
		{"no password", Options{Encryption: EncryptionAES256}},
		{"no encryption", Options{Password: katPassword}},
		{"non-ASCII", Options{Encryption: EncryptionAES256, Password: "pässwörd long enough"}},
		{"control", Options{Encryption: EncryptionZipCrypto, Password: "tab\tinside the password"}},
		{"DEL", Options{Encryption: EncryptionZipCrypto, Password: "delete\x7f"}},
		{"100 bytes", Options{Encryption: EncryptionAES256, Password: strings.Repeat("a", MaxPasswordLen+1)}},
		{"unknown method", Options{Encryption: "aes128", Password: katPassword}},
	} {
		w, err := New(io.Discard, c.o)
		if err == nil {
			t.Errorf("%s: accepted", c.name)
			continue
		}
		if c.o.Password != "" && strings.Contains(err.Error(), c.o.Password) {
			t.Errorf("%s: the error contains the password: %v", c.name, err)
		}
		if w != nil {
			t.Errorf("%s: a Writer with the error", c.name)
		}
	}
	for _, pw := range []string{" ", strings.Repeat("~", MaxPasswordLen), " leading and trailing spaces "} {
		if _, err := New(io.Discard, Options{Encryption: EncryptionAES256, Password: pw}); err != nil {
			t.Errorf("password %q refused: %v", pw, err)
		}
	}

	w, err := New(io.Discard, Options{Encryption: EncryptionZipCrypto, Password: katPassword})
	if err != nil {
		t.Fatal(err)
	}
	if err := w.AddFile("a.txt", testMod, 1, strings.NewReader("a")); !errors.Is(err, ErrReaderAtRequired) {
		t.Fatalf("AddFile on an encrypting Writer: %v", err)
	}
	if err := w.AddDir("d", testMod); !errors.Is(err, ErrReaderAtRequired) {
		t.Fatalf("the Writer is usable after ErrReaderAtRequired: %v", err)
	}
}

// TestAddFileAtMatchesAddFile: unencrypted, AddFileAt writes exactly what
// AddFile writes, so unprotected zip uploads stay byte-identical.
func TestAddFileAtMatchesAddFile(t *testing.T) {
	type ent struct {
		name string
		data []byte
	}
	ents := []ent{{"d/", nil}, {"d/a.txt", foxText(5000)}, {"D/A.txt", []byte("dup")}, {"photo.JPG", foxText(900)},
		{"empty", []byte{}}, {"rand.bin", seeded(3000, 11)}, {"ünïcødé ✓.md", []byte("ok")}, {"../x", []byte("x")},
		{"big.txt", foxText(5 << 20)}}
	build := func(o Options, at bool) []byte {
		var buf bytes.Buffer
		w, err := New(&buf, o)
		if err != nil {
			t.Fatal(err)
		}
		for _, e := range ents {
			switch {
			case strings.HasSuffix(e.name, "/"):
				must(t, w.AddDir(e.name, testMod))
			case at:
				must(t, w.AddFileAt(e.name, testMod, int64(len(e.data)), bytes.NewReader(e.data)))
			default:
				must(t, w.AddFile(e.name, testMod, int64(len(e.data)), bytes.NewReader(e.data)))
			}
		}
		must(t, w.Close())
		return buf.Bytes()
	}
	for _, o := range []Options{{Compression: CompressionAuto}, {Compression: CompressionStore},
		{Compression: CompressionDeflate}, {Format: FormatTar}} {
		if a, b := build(o, false), build(o, true); !bytes.Equal(a, b) {
			t.Errorf("%+v: AddFileAt output (%d bytes) differs from AddFile's (%d bytes)", o, len(b), len(a))
		}
	}
	// The overrun check works through AddFileAt too.
	w, _ := New(io.Discard, Options{})
	if err := w.AddFileAt("a", testMod, 2, strings.NewReader("abc")); !errors.Is(err, ErrSizeMismatch) {
		t.Errorf("long source: %v", err)
	}
	w, _ = New(io.Discard, Options{})
	if err := w.AddFileAt("a", testMod, 4, strings.NewReader("abc")); !errors.Is(err, ErrSizeMismatch) {
		t.Errorf("short source: %v", err)
	}
	w, _ = New(io.Discard, Options{})
	if err := w.AddFileAt("a", testMod, -1, strings.NewReader("abc")); err == nil {
		t.Error("negative size accepted")
	}
}

// fullCapacity returns the whole backing array of an emptied buffer.
func fullCapacity(b *bytes.Buffer) []byte {
	p := b.AvailableBuffer()
	return p[:cap(p)]
}

func TestBuffersCleared(t *testing.T) {
	for _, enc := range []Encryption{EncryptionAES256, EncryptionZipCrypto} {
		w, err := New(io.Discard, Options{Compression: CompressionDeflate, Encryption: enc, Password: katPassword})
		if err != nil {
			t.Fatal(err)
		}
		for _, data := range [][]byte{foxText(100 << 10), seeded(200<<10, 12), seeded(3<<20, 13), seeded(memPassMax, 14),
			foxText(6 << 20)} {
			must(t, w.AddFileAt("f.txt", testMod, int64(len(data)), bytes.NewReader(data)))
			st := w.enc
			plain, comp := fullCapacity(&st.plain), fullCapacity(&st.comp)
			if len(plain) == 0 || len(comp) == 0 {
				t.Fatalf("%s: the pass buffers were not used (%d, %d bytes)", enc, len(plain), len(comp))
			}
			if len(plain) > memPassMax || len(comp) > memPassMax {
				t.Errorf("%s: pass buffers of %d and %d bytes, more than %d", enc, len(plain), len(comp), memPassMax)
			}
			if st.plain.Len() != 0 || st.comp.Len() != 0 || !allZero(plain) || !allZero(comp) ||
				!allZero(st.chunk) || !allZero(st.aes.buf[:]) || !allZero(st.aes.ctr.ks[:]) ||
				!allZero(st.zc.buf[:]) || st.zc.z != (zipCrypto{}) || st.aes.mac != nil {
				t.Errorf("%s, %d bytes: a buffer still holds data after AddFileAt", enc, len(data))
			}
		}
		must(t, w.Close())
		if w.enc != nil || w.opts.Password != "" {
			t.Errorf("%s: Close kept the buffers or the password", enc)
		}
	}
	// A failed entry clears them too.
	w, _ := New(io.Discard, Options{Encryption: EncryptionZipCrypto, Password: katPassword})
	data := foxText(1000)
	if err := w.AddFileAt("f.txt", testMod, 2000, bytes.NewReader(data)); !errors.Is(err, ErrSizeMismatch) {
		t.Fatal(err)
	}
	if st := w.enc; !allZero(fullCapacity(&st.plain)) || !allZero(st.chunk) {
		t.Error("a failed entry left plaintext in the buffers")
	}
	w.Close()
	if w.enc != nil || w.opts.Password != "" {
		t.Error("Close after an error kept the buffers or the password")
	}
}

// TestUTF8FlagMatchesArchiveZip: encrypted entries set the UTF-8 flag exactly
// when archive/zip's CreateHeader would (as it does for directory entries).
func TestUTF8FlagMatchesArchiveZip(t *testing.T) {
	names := []string{"plain.txt", "tilde~x", "back\\slash", "brace}", "café", "日本", "a\x01b", "ok ok", "{curly"}
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for _, n := range names {
		fh := &zip.FileHeader{Name: n}
		if _, err := zw.CreateHeader(fh); err != nil {
			t.Fatal(err)
		}
		if want := fh.Flags&0x800 != 0; needsUTF8Flag(n) != want {
			t.Errorf("%q: needsUTF8Flag %v, archive/zip %v", n, !want, want)
		}
	}
}

func TestDOSDateTimeAndExtTime(t *testing.T) {
	for _, c := range []struct {
		t          time.Time
		date, time uint16
		unix       uint32
	}{
		{time.Date(2026, 9, 19, 10, 11, 13, 0, time.UTC), 46<<9 | 9<<5 | 19, 10<<11 | 11<<5 | 6, 1789812673},
		{time.Date(1970, 1, 1, 0, 0, 5, 0, time.UTC), 1<<5 | 1, 0, 5},
		{time.Date(1960, 1, 1, 0, 0, 0, 0, time.UTC), 1<<5 | 1, 0, 0},
		{time.Date(2200, 1, 1, 0, 0, 0, 0, time.UTC), 127<<9 | 12<<5 | 31, 23<<11 | 59<<5 | 29, math.MaxUint32},
	} {
		d, tm := dosDateTime(c.t)
		if d != c.date || tm != c.time {
			t.Errorf("%v: DOS %#04x %#04x, want %#04x %#04x", c.t, d, tm, c.date, c.time)
		}
		x := extTimeExtra(c.t)
		if len(x) != 9 || !bytes.Equal(x[:5], []byte{0x55, 0x54, 5, 0, 1}) || binary.LittleEndian.Uint32(x[5:]) != c.unix {
			t.Errorf("%v: 0x5455 extra % x", c.t, x)
		}
	}
	if x := extTimeExtra(time.Time{}); x != nil {
		t.Errorf("zero time: extra % x", x)
	}
	if d, tm := dosDateTime(time.Time{}); d != 1<<5|1 || tm != 0 {
		t.Errorf("zero time: DOS %#04x %#04x", d, tm)
	}
}

// TestEncryptedCipherWritersKeepInput: Write never modifies the caller's slice.
func TestEncryptedCipherWritersKeepInput(t *testing.T) {
	in := foxText(100 << 10)
	orig := bytes.Clone(in)
	aw, err := newAESWriter(io.Discard, katPassword, bytes.NewReader(unhex(t, katSalt)))
	if err != nil {
		t.Fatal(err)
	}
	if n, err := aw.Write(in); err != nil || n != len(in) {
		t.Fatalf("aes Write %d %v", n, err)
	}
	must(t, aw.Close())
	zw, err := newZipCryptoWriter(io.Discard, katPassword, 0x37, bytes.NewReader(unhex(t, katZCHeader)))
	if err != nil {
		t.Fatal(err)
	}
	if n, err := zw.Write(in); err != nil || n != len(in) {
		t.Fatalf("zipcrypto Write %d %v", n, err)
	}
	must(t, zw.Close())
	if !bytes.Equal(in, orig) {
		t.Fatal("a cipher writer modified its input")
	}
	// A failing salt source is an error, not a zero salt.
	if _, err := newAESWriter(io.Discard, katPassword, bytes.NewReader(make([]byte, 5))); err == nil {
		t.Error("short salt accepted")
	}
}
