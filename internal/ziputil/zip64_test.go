package ziputil

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/aes"
	"crypto/hmac"
	"crypto/pbkdf2"
	"crypto/sha1"
	"encoding/binary"
	"errors"
	"hash"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"fileparcel/internal/ziputil/ziputiltest"
)

// zeroReader yields zeros.
type zeroReader struct{}

func (zeroReader) Read(p []byte) (int, error) {
	clear(p)
	return len(p), nil
}

// sparseFile records an archive without storing long runs of zeros, and
// serves it back through ReadAt (so a 4.5 GB stored entry needs a few KiB).
type sparseFile struct {
	segs []segment
	size int64
}

type segment struct {
	off  int64
	n    int64
	data []byte // nil = zeros
}

var zeros = make([]byte, 1<<20)

func allZero(p []byte) bool {
	for len(p) > 0 {
		n := min(len(p), len(zeros))
		if !bytes.Equal(p[:n], zeros[:n]) {
			return false
		}
		p = p[n:]
	}
	return true
}

func (s *sparseFile) Write(p []byte) (int, error) {
	n := int64(len(p))
	if len(p) >= 1024 && allZero(p) {
		if l := len(s.segs); l > 0 && s.segs[l-1].data == nil {
			s.segs[l-1].n += n
		} else {
			s.segs = append(s.segs, segment{off: s.size, n: n})
		}
	} else {
		s.segs = append(s.segs, segment{off: s.size, n: n, data: bytes.Clone(p)})
	}
	s.size += n
	return len(p), nil
}

func (s *sparseFile) ReadAt(p []byte, off int64) (int, error) {
	if off >= s.size {
		return 0, io.EOF
	}
	done := 0
	i := sort.Search(len(s.segs), func(i int) bool { return s.segs[i].off+s.segs[i].n > off })
	for ; i < len(s.segs) && done < len(p); i++ {
		sg := s.segs[i]
		from := off + int64(done) - sg.off
		k := int(min(int64(len(p)-done), sg.n-from))
		if sg.data == nil {
			clear(p[done : done+k])
		} else {
			copy(p[done:done+k], sg.data[from:])
		}
		done += k
	}
	if done < len(p) {
		return done, io.EOF
	}
	return done, nil
}

// TestZip64 writes a 4.5 GB entry (zip64 sizes and offsets) and a small
// entry after it, then parses the archive back.
func TestZip64(t *testing.T) {
	if testing.Short() {
		t.Skip("writes a 4.5 GB synthetic entry")
	}
	const big = int64(4<<30) + 512<<20
	var sf sparseFile
	w, err := New(&sf, Options{Compression: CompressionStore})
	if err != nil {
		t.Fatal(err)
	}
	mod := time.Date(2026, 9, 19, 10, 0, 0, 0, time.UTC)
	must(t, w.AddDir("disk", mod))
	must(t, w.AddFile("disk/huge.img", mod, big, io.LimitReader(zeroReader{}, big)))
	must(t, w.AddFile("disk/after.txt", mod, 5, strings.NewReader("after")))
	must(t, w.Close())
	if sf.size <= big || w.Written() != sf.size {
		t.Fatalf("archive size %d (written %d)", sf.size, w.Written())
	}

	zr, err := zip.NewReader(&sf, sf.size)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(zr.File) != 3 {
		t.Fatalf("%d entries", len(zr.File))
	}
	huge := zr.File[1]
	if huge.Name != "disk/huge.img" || huge.UncompressedSize64 != uint64(big) || huge.CompressedSize64 != uint64(big) ||
		huge.Method != zip.Store {
		t.Fatalf("huge entry %+v", huge.FileHeader)
	}
	off, err := huge.DataOffset()
	if err != nil || off <= 0 {
		t.Fatalf("data offset %d %v", off, err)
	}
	// The entry after the 4 GiB mark needs a zip64 offset; read it back.
	after := zr.File[2]
	rc, err := after.Open()
	if err != nil {
		t.Fatal(err)
	}
	b, err := io.ReadAll(rc)
	rc.Close()
	if err != nil || string(b) != "after" {
		t.Fatalf("entry after 4 GiB: %q %v", b, err)
	}
	if off2, _ := after.DataOffset(); off2 <= int64(1)<<32 {
		t.Fatalf("offset of the last entry %d is below 4 GiB", off2)
	}
}

// zeroSource is an io.ReaderAt of that many zero bytes.
type zeroSource int64

func (z zeroSource) ReadAt(p []byte, off int64) (int, error) {
	if off >= int64(z) {
		return 0, io.EOF
	}
	n := min(int64(len(p)), int64(z)-off)
	clear(p[:n])
	if n < int64(len(p)) {
		return int(n), io.EOF
	}
	return int(n), nil
}

// aesVerifySink checks, while an archive streams through it, its first entry:
// a WinZip AES Store entry of size plaintext bytes. It keeps the local header
// with the salt and password verification value, feeds the ciphertext to its
// own HMAC, keeps the first and last ciphertext blocks, and keeps everything
// after the ciphertext (MAC, later entries, central directory).
type aesVerifySink struct {
	size    int64
	off     int64
	head    []byte
	encKey  []byte
	mac     hash.Hash
	ctStart int64
	first   [16]byte
	last    [16]byte
	tail    []byte
}

func (s *aesVerifySink) Write(p []byte) (int, error) {
	n := len(p)
	le := binary.LittleEndian
	for len(p) > 0 {
		if s.mac == nil { // still in the local header, salt and pvv
			need := 30
			if len(s.head) >= 30 {
				need += int(le.Uint16(s.head[26:])) + int(le.Uint16(s.head[28:])) + aesSaltLen + aesPVVLen
			}
			k := min(len(p), need-len(s.head))
			s.head, p, s.off = append(s.head, p[:k]...), p[k:], s.off+int64(k)
			if need > 30 && len(s.head) == need {
				salt := s.head[need-aesSaltLen-aesPVVLen : need-aesPVVLen]
				dk, err := pbkdf2.Key(sha1.New, katPassword, salt, 1000, 66)
				if err != nil {
					return 0, err
				}
				if !bytes.Equal(dk[64:], s.head[need-aesPVVLen:]) {
					return 0, errors.New("password verification value mismatch")
				}
				s.encKey, s.mac, s.ctStart = dk[:32], hmac.New(sha1.New, dk[32:64]), s.off
			}
			continue
		}
		if ctEnd := s.ctStart + s.size; s.off < ctEnd {
			k := int(min(int64(len(p)), ctEnd-s.off))
			chunk := p[:k]
			s.mac.Write(chunk)
			if s.off < s.ctStart+16 {
				copy(s.first[s.off-s.ctStart:], chunk)
			}
			if lastStart := ctEnd - 16; s.off+int64(k) > lastStart {
				from := max(s.off, lastStart)
				copy(s.last[from-lastStart:], chunk[from-s.off:])
			}
			p, s.off = p[k:], s.off+int64(k)
			continue
		}
		s.tail, s.off, p = append(s.tail, p...), s.off+int64(len(p)), nil
	}
	return n, nil
}

// ReadAt serves the kept parts of the archive, zeros for the ciphertext:
// enough for zip.NewReader, which reads only the end records and the central
// directory.
func (s *aesVerifySink) ReadAt(p []byte, off int64) (int, error) {
	gapEnd := s.ctStart + s.size
	for i := range p {
		switch o := off + int64(i); {
		case o >= s.off:
			return i, io.EOF
		case o < int64(len(s.head)):
			p[i] = s.head[o]
		case o < gapEnd:
			p[i] = 0
		default:
			p[i] = s.tail[o-gapEnd]
		}
	}
	return len(p), nil
}

// TestEncryptedZip64 writes a 4.5 GiB all-zero AES Store entry (zip64 sizes,
// counter near 2^28) and a small entry after it, and checks the MAC, the
// first and last blocks, the local zip64 extra (both sizes, no descriptor)
// and the central zip64 sizes. FP_TEST_BIG=1 also writes the archive to disk
// and has 7-Zip extract it.
func TestEncryptedZip64(t *testing.T) {
	if testing.Short() {
		t.Skip("encrypts a 4.5 GiB synthetic entry")
	}
	const big = int64(4<<30) + 512<<20 // a multiple of the AES block size
	write := func(dst io.Writer) *Writer {
		w, err := New(dst, Options{Compression: CompressionStore, Encryption: EncryptionAES256, Password: katPassword})
		if err != nil {
			t.Fatal(err)
		}
		must(t, w.AddFileAt("disk/huge.img", testMod, big, zeroSource(big)))
		must(t, w.AddFileAt("disk/after.txt", testMod, 5, strings.NewReader("after")))
		must(t, w.Close())
		return w
	}
	s := &aesVerifySink{size: big}
	if w := write(s); w.Written() != s.off || s.mac == nil {
		t.Fatalf("written %d, sink saw %d", w.Written(), s.off)
	}

	le := binary.LittleEndian
	h := s.head
	if le.Uint32(h) != 0x04034b50 || le.Uint16(h[4:]) != 51 || le.Uint16(h[6:]) != 1 || le.Uint16(h[8:]) != 99 ||
		le.Uint32(h[14:]) != 0 || le.Uint32(h[18:]) != 0xFFFFFFFF || le.Uint32(h[22:]) != 0xFFFFFFFF {
		t.Fatalf("local header % x", h[:30])
	}
	n := int(le.Uint16(h[26:]))
	ex := extraFields(t, h[30+n:30+n+int(le.Uint16(h[28:]))])
	if z := ex[0x0001]; len(z) != 16 || le.Uint64(z) != uint64(big) || le.Uint64(z[8:]) != uint64(big+aesOverhead) {
		t.Errorf("local zip64 extra % x", z)
	}
	if !bytes.Equal(ex[0x9901], []byte{2, 0, 'A', 'E', 3, 0, 0}) {
		t.Errorf("0x9901 extra % x", ex[0x9901])
	}
	if len(s.tail) < aesMACLen || !hmac.Equal(s.tail[:aesMACLen], s.mac.Sum(nil)[:aesMACLen]) {
		t.Error("MAC mismatch")
	}
	block, err := aes.NewCipher(s.encKey)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		ct *[16]byte
		n  uint64
	}{{&s.first, 1}, {&s.last, uint64(big / 16)}} {
		var ctr, ks [16]byte
		le.PutUint64(ctr[:], c.n)
		block.Encrypt(ks[:], ctr[:])
		for i := range ks {
			if c.ct[i]^ks[i] != 0 {
				t.Fatalf("block %d does not decrypt to zeros", c.n)
			}
		}
	}

	zr, err := zip.NewReader(s, s.off)
	if err != nil {
		t.Fatalf("central directory: %v", err)
	}
	if len(zr.File) != 2 {
		t.Fatalf("%d entries", len(zr.File))
	}
	huge, after := zr.File[0], zr.File[1]
	if huge.Method != 99 || huge.UncompressedSize64 != uint64(big) || huge.CompressedSize64 != uint64(big+aesOverhead) ||
		huge.Flags&8 != 0 {
		t.Errorf("central header %+v", huge.FileHeader)
	}
	if z := extraFields(t, huge.Extra)[0x0001]; len(z) != 16 || le.Uint64(z) != uint64(big) || le.Uint64(z[8:]) != uint64(big+aesOverhead) {
		t.Errorf("central zip64 extra % x", z)
	}
	if off, err := after.DataOffset(); err != nil || off <= big || after.CompressedSize64 != 5+aesOverhead {
		t.Errorf("entry after 4 GiB: offset %d %v, %+v", off, err, after.FileHeader)
	}

	if os.Getenv("FP_TEST_BIG") != "1" {
		return
	}
	sz := ziputiltest.Require7z(t)
	path := filepath.Join(t.TempDir(), "big.zip")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	write(f)
	must(t, f.Close())
	cmd := exec.Command(sz, "e", "-so", "-p"+katPassword, path, "disk/huge.img")
	out, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	must(t, cmd.Start())
	var total int64
	buf := make([]byte, 1<<20)
	for {
		k, err := out.Read(buf)
		if !allZero(buf[:k]) {
			t.Fatalf("7z extracted a non-zero byte near offset %d", total)
		}
		total += int64(k)
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
	}
	if err := cmd.Wait(); err != nil || total != big {
		t.Fatalf("7z e: %v, %d bytes", err, total)
	}
	if b, err := exec.Command(sz, "e", "-so", "-p"+katPassword, path, "disk/after.txt").Output(); err != nil || string(b) != "after" {
		t.Fatalf("7z e after.txt: %q %v", b, err)
	}
}

// failingWriter fails every write after canceled is set (a disconnected client).
type failingWriter struct {
	ctx context.Context
	buf bytes.Buffer
}

func (f *failingWriter) Write(p []byte) (int, error) {
	if err := f.ctx.Err(); err != nil {
		return 0, err
	}
	return f.buf.Write(p)
}

// TestWriteErrorsAreSticky: once the destination fails (client gone,
// context canceled), every later call fails too and nothing more is written.
func TestWriteErrorsAreSticky(t *testing.T) {
	for _, format := range []Format{FormatZip, FormatTar} {
		ctx, cancel := context.WithCancel(context.Background())
		fw := &failingWriter{ctx: ctx}
		w, err := New(fw, Options{Format: format, Compression: CompressionStore})
		if err != nil {
			t.Fatal(err)
		}
		mod := time.Now()
		must(t, w.AddFile("a.txt", mod, 3, strings.NewReader("abc")))
		cancel()
		big := int64(1 << 20)
		err = w.AddFile("b.bin", mod, big, io.LimitReader(zeroReader{}, big))
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("%s: AddFile after cancel: %v", format, err)
		}
		n := fw.buf.Len()
		if err := w.AddDir("d", mod); !errors.Is(err, context.Canceled) {
			t.Fatalf("%s: AddDir after failure: %v", format, err)
		}
		if err := w.AddFile("c.txt", mod, 1, strings.NewReader("c")); !errors.Is(err, context.Canceled) {
			t.Fatalf("%s: AddFile after failure: %v", format, err)
		}
		if err := w.Close(); !errors.Is(err, context.Canceled) {
			t.Fatalf("%s: Close after failure: %v", format, err)
		}
		if fw.buf.Len() != n {
			t.Fatalf("%s: wrote after the failure", format)
		}
	}
}

// TestEmptyArchive: an archive without entries is still valid.
func TestEmptyArchive(t *testing.T) {
	var buf bytes.Buffer
	w, err := New(&buf, Options{})
	if err != nil {
		t.Fatal(err)
	}
	must(t, w.Close())
	must(t, w.Close()) // idempotent
	zr, err := zip.NewReader(bytes.NewReader(buf.Bytes()), int64(buf.Len()))
	if err != nil || len(zr.File) != 0 {
		t.Fatalf("empty zip: %v %d", err, len(zr.File))
	}
	if err := w.AddFile("late.txt", time.Now(), 1, strings.NewReader("x")); !errors.Is(err, ErrClosed) {
		t.Fatalf("AddFile after Close: %v", err)
	}
}
