package ziputil

import (
	"archive/zip"
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"hash/crc32"
	"io"
	"math"
	"time"

	"github.com/klauspost/compress/flate"
)

// Write strategy of encrypted entries (§3.4). Every header value of an
// encrypted entry is final before archive/zip.Writer.CreateRaw writes the
// local header, so no data descriptor follows the data (bit 3 is set only in
// the 0xFFFFFFFF edge, see needsDescriptor). Entries up to memPassMax are read
// into memory once. A larger entry is streamed in one pass when its header
// needs nothing from the data (AES with inner Store); otherwise pass 1 reads
// it for the plaintext CRC and the compressed length, and pass 2 reads it
// again to encrypt it, unless the compressed form fits in memory. Pass 2
// checks that it saw the same bytes (ErrSourceChanged).
const (
	memPassMax = 4 << 20  // largest entry, or compressed entry, kept in memory
	chunkSize  = 32 << 10 // size of every ReadAt of a source
)

// encState holds the pass buffers and cipher writers of an encrypting Writer.
// It is allocated on the first encrypted entry, reused for the next ones and
// released by Close. plain and comp hold plaintext or its compressed form, so
// the used part of every buffer is cleared after each entry.
type encState struct {
	plain, comp bytes.Buffer
	chunk       []byte
	fw          *flate.Writer
	aes         aesWriter
	zc          zipCryptoWriter
}

// testForceDescriptor, when set by a test, writes the named entries with a
// data descriptor as if a size were exactly 0xFFFFFFFF (§13.1).
var testForceDescriptor func(name string) bool

// checkEncryption validates the encryption options of New (after the format
// default is applied). No message contains the password.
func checkEncryption(o Options) error {
	switch o.Encryption {
	case EncryptionNone:
		if o.Password != "" {
			return errors.New("ziputil: a password needs an encryption method")
		}
		return nil
	case EncryptionAES256, EncryptionZipCrypto:
	default:
		return fmt.Errorf("ziputil: unknown encryption %q", o.Encryption)
	}
	if o.Format != FormatZip {
		return errors.New("ziputil: only zip archives can be encrypted")
	}
	if o.Password == "" {
		return errors.New("ziputil: encryption needs a password")
	}
	if len(o.Password) > MaxPasswordLen {
		return fmt.Errorf("ziputil: the password is longer than %d bytes", MaxPasswordLen)
	}
	for i := 0; i < len(o.Password); i++ {
		if c := o.Password[i]; c < 0x20 || c > 0x7e {
			return errors.New("ziputil: the password may contain printable ASCII characters only")
		}
	}
	return nil
}

// state returns the pass buffers, allocating them on first use.
func (a *Writer) state() *encState {
	if a.enc == nil {
		a.enc = &encState{chunk: make([]byte, chunkSize)}
	}
	return a.enc
}

// releaseEncryption clears and drops the pass buffers and the password.
func (a *Writer) releaseEncryption() {
	a.opts.Password = ""
	if a.enc != nil {
		a.enc.clear()
		a.enc = nil
	}
}

// clear wipes what the last entry left in the buffers and cipher writers.
func (st *encState) clear() {
	wipeBuffer(&st.plain)
	wipeBuffer(&st.comp)
	clear(st.chunk)
	st.aes.wipe()
	st.zc.wipe()
}

// wipeBuffer zeroes the used part of b and empties it. The buffers are sized
// (reserve) before an entry is written into them and never grow while it is,
// so no abandoned backing array holds data either.
func wipeBuffer(b *bytes.Buffer) {
	clear(b.Bytes())
	b.Reset()
}

// reserve makes the empty buffer b hold n bytes without growing, allocating
// exactly n when it is too small (Grow would double: 8 MiB for a 4 MiB pass).
func reserve(b *bytes.Buffer, n int) {
	if b.Available() < n {
		*b = *bytes.NewBuffer(make([]byte, 0, n))
	}
}

// flateTo returns the reusable Deflate compressor, reset to write to w.
func (st *encState) flateTo(w io.Writer) (*flate.Writer, error) {
	if st.fw == nil {
		fw, err := flate.NewWriter(w, DeflateLevel)
		if err != nil {
			return nil, err
		}
		st.fw = fw
		return fw, nil
	}
	st.fw.Reset(w)
	return st.fw, nil
}

// read reads src[0:size) in chunks of chunkSize and hands each to fn. A source
// that ends early, or that still has a byte at size, fails with
// ErrSizeMismatch; other read errors (a canceled context) are returned as is.
func (st *encState) read(src io.ReaderAt, full string, size int64, fn func([]byte) error) error {
	buf := st.chunk
	for off := int64(0); off < size; {
		n := int(min(int64(len(buf)), size-off))
		m, err := src.ReadAt(buf[:n], off)
		switch {
		case err != nil && !errors.Is(err, io.EOF):
			return err
		case m < n:
			return fmt.Errorf("%w: %q: got %d of %d bytes", ErrSizeMismatch, full, off+int64(m), size)
		}
		if err := fn(buf[:n]); err != nil {
			return err
		}
		off += int64(n)
	}
	if m, _ := src.ReadAt(buf[:1], size); m > 0 {
		return fmt.Errorf("%w: %q: more than %d bytes", ErrSizeMismatch, full, size)
	}
	return nil
}

// addEncrypted writes the file entry full, of size bytes read from src, with
// the Writer's encryption (§3.4).
func (a *Writer) addEncrypted(full string, mod time.Time, size int64, src io.ReaderAt) error {
	st := a.state()
	defer st.clear()
	inner := a.innerMethod(full, size)
	if a.opts.Encryption == EncryptionAES256 && inner == zip.Store {
		// AE-2 stores no CRC and Store knows its size: one streaming pass.
		return a.writeEntry(full, mod, size, size, zip.Store, 0, func(w io.Writer) error {
			return st.read(src, full, size, func(p []byte) error {
				_, err := w.Write(p)
				return err
			})
		})
	}

	// Pass 1: the plaintext CRC and, for Deflate, the compressed length and
	// CRC. An entry up to memPassMax keeps its plaintext; the compressed form
	// is kept while it fits in memPassMax (and, for such a small entry, while
	// it is shorter than the plaintext, the only case it is used in).
	small := size <= memPassMax
	if small {
		reserve(&st.plain, int(size))
	}
	var comp *countCRCWriter
	var fw *flate.Writer
	if inner == zip.Deflate {
		keep := int64(memPassMax)
		if small {
			keep = size - 1
		}
		reserve(&st.comp, int(keep))
		comp = &countCRCWriter{crc: crc32.NewIEEE(), buf: &st.comp, keep: true, max: keep}
		var err error
		if fw, err = st.flateTo(comp); err != nil {
			return err
		}
	}
	crc := crc32.NewIEEE()
	err := st.read(src, full, size, func(p []byte) error {
		crc.Write(p)
		if small {
			st.plain.Write(p)
		}
		if fw != nil {
			_, err := fw.Write(p)
			return err
		}
		return nil
	})
	if err != nil {
		return err
	}
	sum := crc.Sum32()
	clen := size
	if comp != nil {
		if err := fw.Close(); err != nil {
			return err
		}
		if comp.n < size {
			clen = comp.n
		} else {
			// Deflate does not shrink it: Store, as 7-Zip does.
			inner = zip.Store
			comp.drop()
		}
	}
	switch {
	case inner == zip.Deflate && comp.keep:
		return a.writeEntry(full, mod, size, clen, inner, sum, writeAll(st.comp.Bytes()))
	case inner == zip.Store && small:
		return a.writeEntry(full, mod, size, clen, inner, sum, writeAll(st.plain.Bytes()))
	}

	// Pass 2: read the source again, check that it is unchanged, encrypt.
	return a.writeEntry(full, mod, size, clen, inner, sum, func(w io.Writer) error {
		return st.pass2(w, src, full, size, inner, sum, comp)
	})
}

// pass2 reads src again and writes its inner data (Store, or Deflate as long
// as in pass 1) to w, checking that the plaintext CRC and, for Deflate, the
// compressed length and CRC equal those of pass 1 (comp).
func (st *encState) pass2(w io.Writer, src io.ReaderAt, full string, size int64, inner uint16, crc uint32, comp *countCRCWriter) error {
	var fw *flate.Writer
	var again *countCRCWriter
	if inner == zip.Deflate {
		again = &countCRCWriter{crc: crc32.NewIEEE(), w: w, max: comp.n}
		var err error
		if fw, err = st.flateTo(again); err != nil {
			return err
		}
	}
	crc2 := crc32.NewIEEE()
	err := st.read(src, full, size, func(p []byte) error {
		crc2.Write(p)
		var err error
		if fw != nil {
			_, err = fw.Write(p)
		} else {
			_, err = w.Write(p)
		}
		return err
	})
	if err == nil && fw != nil {
		err = fw.Close()
	}
	switch {
	case errors.Is(err, errCompressedOverrun):
		return fmt.Errorf("%w: %q", ErrSourceChanged, full)
	case err != nil:
		return err
	case crc2.Sum32() != crc,
		again != nil && (again.n != comp.n || again.crc.Sum32() != comp.crc.Sum32()):
		return fmt.Errorf("%w: %q", ErrSourceChanged, full)
	}
	return nil
}

// writeAll returns an entry body that writes p.
func writeAll(p []byte) func(io.Writer) error {
	return func(w io.Writer) error {
		_, err := w.Write(p)
		return err
	}
}

// writeEntry writes the header of an encrypted entry whose inner data (Store
// or Deflate) is clen bytes long, then its encrypted data, produced by body
// writing the inner data to the cipher writer.
func (a *Writer) writeEntry(full string, mod time.Time, size, clen int64, inner uint16, crc uint32, body func(io.Writer) error) error {
	overhead := int64(aesOverhead)
	if a.opts.Encryption == EncryptionZipCrypto {
		overhead = zipCryptoHeaderLen
	}
	csize := clen + overhead
	descriptor := needsDescriptor(size, csize) || testForceDescriptor != nil && testForceDescriptor(full)
	fh := a.encryptedHeader(full, mod, size, csize, inner, crc, descriptor)
	raw, err := a.zw.CreateRaw(fh)
	if err != nil {
		return err
	}
	out := &countWriter{w: raw}
	st := a.enc
	var cw io.WriteCloser
	if a.opts.Encryption == EncryptionAES256 {
		err = st.aes.reset(out, a.opts.Password, a.opts.Rand)
		cw = &st.aes
	} else {
		// The check byte lets readers reject a wrong password: the CRC's
		// high byte, or the DOS time's when the CRC follows the data.
		check := byte(crc >> 24)
		if descriptor {
			//lint:ignore SA1019 CreateRaw writes the raw DOS fields, not Modified; the check byte must match them
			check = byte(fh.ModifiedTime >> 8)
		}
		err = st.zc.reset(out, a.opts.Password, check, a.opts.Rand)
		cw = &st.zc
	}
	if err != nil {
		return err
	}
	if err := body(cw); err != nil {
		return err
	}
	if err := cw.Close(); err != nil {
		return err
	}
	if out.n != csize {
		// Unreachable: the sizes above are exact. A mismatch would make every
		// later entry unreadable, so it is an error rather than a panic.
		return fmt.Errorf("ziputil: %q: wrote %d encrypted bytes, the header says %d", full, out.n, csize)
	}
	return nil
}

// encryptedHeader builds the complete header of an encrypted entry: every
// field is final before CreateRaw, which writes it as given (§3.2, §3.3).
func (a *Writer) encryptedHeader(full string, mod time.Time, size, csize int64, inner uint16, crc uint32, descriptor bool) *zip.FileHeader {
	fh := &zip.FileHeader{Name: full, UncompressedSize64: uint64(size), CompressedSize64: uint64(csize)}
	//lint:ignore SA1019 CreateRaw ignores Modified and writes these raw DOS fields as given
	fh.ModifiedDate, fh.ModifiedTime = dosDateTime(mod)
	fh.Flags = 0x1 // encrypted
	if needsUTF8Flag(full) {
		fh.Flags |= 0x800
	}
	if descriptor {
		fh.Flags |= 0x8
	}
	fh.Extra = extTimeExtra(mod)
	switch a.opts.Encryption {
	case EncryptionAES256:
		fh.CreatorVersion, fh.ReaderVersion = zipVersionAES, zipVersionAES
		fh.Method, fh.CRC32 = methodWinZipAES, 0
		fh.Extra = append(fh.Extra, aesExtra(inner)...)
	case EncryptionZipCrypto:
		fh.CreatorVersion, fh.ReaderVersion = 20, 20
		fh.Method, fh.CRC32 = inner, crc
	}
	fh.SetMode(0o644) // after CreatorVersion: sets its high byte to 3 (Unix)
	return fh
}

// needsDescriptor reports whether an entry must be written with a data
// descriptor: a size of exactly 0xFFFFFFFF would be written literally in the
// local header, where readers take it as a zip64 marker (Go adds the local
// zip64 extra only above it).
func needsDescriptor(size, csize int64) bool {
	return size == math.MaxUint32 || csize == math.MaxUint32
}

// needsUTF8Flag is archive/zip's detectUTF8 rule, which CreateHeader applies
// to the directory entries of the same archive: any rune below 0x20, above
// 0x7d, or a backslash. Names are valid UTF-8 (splitClean).
func needsUTF8Flag(name string) bool {
	for _, r := range name {
		if r < 0x20 || r > 0x7d || r == 0x5c {
			return true
		}
	}
	return false
}

// dosDateTime converts t, as given (callers pass UTC, like CreateHeader's
// Modified), to MS-DOS date and time, clamped to the representable range
// 1980-01-01 00:00:00 … 2107-12-31 23:59:58.
func dosDateTime(t time.Time) (date, clock uint16) {
	switch y := t.Year(); {
	case y < 1980:
		return 1<<5 | 1, 0
	case y > 2107:
		return 127<<9 | 12<<5 | 31, 23<<11 | 59<<5 | 29
	}
	date = uint16((t.Year()-1980)<<9 | int(t.Month())<<5 | t.Day())
	clock = uint16(t.Hour()<<11 | t.Minute()<<5 | t.Second()/2)
	return date, clock
}

// extTimeExtra is the 0x5455 extended-timestamp extra field (mtime only), as
// CreateHeader writes it, with the time clamped to [0, 2³²−1]; nil for a zero
// time. The slice is fresh: archive/zip appends the zip64 extra to it.
func extTimeExtra(t time.Time) []byte {
	if t.IsZero() {
		return nil
	}
	b := []byte{0x55, 0x54, 5, 0, 1, 0, 0, 0, 0}
	binary.LittleEndian.PutUint32(b[5:], uint32(min(max(t.Unix(), 0), math.MaxUint32)))
	return b
}

// aesExtra is the WinZip AES extra field 0x9901: AE-2, vendor "AE", AES-256,
// and the inner compression method.
func aesExtra(inner uint16) []byte {
	return []byte{0x01, 0x99, 7, 0, aeVersion2, 0, 'A', 'E', aesStrength256, byte(inner), byte(inner >> 8)}
}

// errCompressedOverrun: pass 2 compressed to more bytes than pass 1.
var errCompressedOverrun = errors.New("ziputil: compressed data longer than in the first pass")

// countCRCWriter counts and checksums a compressed stream. In pass 1 it keeps
// a copy in buf while the stream stays within max bytes; in pass 2 it
// forwards the stream to w and refuses to go past max bytes.
type countCRCWriter struct {
	n    int64
	crc  hash.Hash32
	buf  *bytes.Buffer
	keep bool
	w    io.Writer
	max  int64
}

func (c *countCRCWriter) Write(p []byte) (int, error) {
	if c.w != nil && c.n+int64(len(p)) > c.max {
		return 0, errCompressedOverrun
	}
	c.n += int64(len(p))
	c.crc.Write(p)
	if c.keep {
		if c.n <= c.max {
			c.buf.Write(p)
		} else {
			c.drop()
		}
	}
	if c.w != nil {
		return c.w.Write(p)
	}
	return len(p), nil
}

// drop clears and forgets the kept copy.
func (c *countCRCWriter) drop() {
	if c.buf != nil {
		wipeBuffer(c.buf)
	}
	c.keep = false
}
