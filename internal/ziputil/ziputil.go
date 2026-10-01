// Package ziputil writes streaming zip and tar archives for folder downloads
// and zip-on-upload (DESIGN §8.2): Store vs Deflate policy by extension
// (storage.zip_compression = auto|store|deflate, klauspost flate level 5),
// zip64 via UncompressedSize64, UTF-8 names, name sanitation (no "..", no
// leading "/", backslashes → "_") and " (n)" de-duplication, directory entries
// for empty folders, and USTAR/PAX tar output.
//
// A zip Writer can also password-protect every file entry (Options.Encryption):
// WinZip AES-256 (AE-2) or the weak legacy ZipCrypto, built on
// archive/zip.Writer.CreateRaw with stdlib crypto only (encrypt.go,
// winzipaes.go, zipcrypto.go). Encrypted entries get a complete local header
// without data descriptor, so every header value must be known before the
// data is written: they are added with AddFileAt, whose io.ReaderAt may be
// read twice for entries above 4 MiB. Directory entries, names, sizes and
// times stay readable (a limit of the zip format).
//
// The Writer only writes; the caller walks the tree (Files.Walk) and stops on
// context cancellation — a write to a disconnected client fails anyway.
// Parent directory entries are NOT added implicitly: call AddDir for the
// folders that must exist (e.g. empty ones).
//
// Owned by unit D. Importable by files and uploads only.
package ziputil

import (
	"archive/tar"
	"archive/zip"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"math"
	"path"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/klauspost/compress/flate"

	"fileparcel/internal/names"
)

// Format is the archive format (core.ArchiveZip / core.ArchiveTar values).
type Format string

// Formats. The zero value means FormatZip.
const (
	FormatZip Format = "zip"
	FormatTar Format = "tar"
)

// Compression is the zip compression policy (storage.zip_compression).
type Compression string

// Compression policies. The zero value means CompressionAuto.
const (
	CompressionAuto    Compression = "auto"    // Store for already-compressed types, Deflate otherwise
	CompressionStore   Compression = "store"   // never compress
	CompressionDeflate Compression = "deflate" // always Deflate
)

// DeflateLevel is the klauspost flate level used for Deflate entries.
const DeflateLevel = 5

// Encryption is the password protection of the file entries of a zip
// (core.ZipEncAES256 / core.ZipEncZipCrypto values).
type Encryption string

// Encryption methods. The zero value means no encryption.
const (
	EncryptionNone      Encryption = ""
	EncryptionAES256    Encryption = "aes256"    // WinZip AE-2: AES-256-CTR (LE counter) + HMAC-SHA1-80
	EncryptionZipCrypto Encryption = "zipcrypto" // traditional PKWARE: weak, compatibility only
)

// MaxPasswordLen is the longest zip password New accepts, in bytes. 7-Zip
// (and p7zip, 7zz, PeaZip, Keka, which use its code) refuses WinZip AES
// passwords longer than 99 bytes: it will not open such an archive and
// reports a wrong password. One limit applies to both methods.
const MaxPasswordLen = 99

// Options configures a Writer.
type Options struct {
	Format      Format
	Compression Compression // zip only
	// Encryption protects every file entry with Password (zip only). Directory
	// entries are never encrypted; names, sizes and times stay readable.
	Encryption Encryption
	// Password is printable ASCII (0x20..0x7e), 1..MaxPasswordLen bytes;
	// callers apply their own policy on top. Close drops the Writer's copy.
	Password string
	// Rand supplies the AES salts and the ZipCrypto header bytes. nil means
	// crypto/rand.Reader; only tests set it.
	Rand io.Reader
}

// ErrSizeMismatch is returned by AddFile and AddFileAt when the source
// yields fewer or more bytes than the declared size. The archive is unusable
// afterwards.
var ErrSizeMismatch = errors.New("ziputil: entry size does not match the declared size")

// ErrClosed is returned after Close or after a previous write error.
var ErrClosed = errors.New("ziputil: writer closed")

// ErrReaderAtRequired is returned by AddFile on an encrypting Writer: an
// encrypted entry needs its header values before its data, so it must be
// added with AddFileAt. The archive is unusable afterwards.
var ErrReaderAtRequired = errors.New("ziputil: encrypted entries must be added with AddFileAt")

// ErrSourceChanged is returned by AddFileAt when an entry read twice (§3.4)
// yields different bytes the second time. The archive is unusable afterwards.
var ErrSourceChanged = errors.New("ziputil: the entry changed between the two encryption passes")

// storeExt lists already-compressed types stored without compression (§8.2).
var storeExt = map[string]bool{}

func init() {
	for _, e := range strings.Fields("jpg jpeg png gif webp avif heic heif mp4 m4v m4a mov mkv webm mp3 aac ogg oga ogv opus flac " +
		"zip 7z rar gz tgz bz2 xz zst zstd lz4 br docx xlsx pptx odt ods odp epub apk jar pdf woff woff2") {
		storeExt["."+e] = true
	}
}

// Compressed reports whether name has an already-compressed extension.
func Compressed(name string) bool { return storeExt[strings.ToLower(path.Ext(name))] }

const (
	kindDir  = 1
	kindFile = 2
	// kindRenamed marks the new path of a directory renamed because a file
	// holds its name. A real directory of that path is renamed in turn, so
	// the two never merge.
	kindRenamed = 3
)

// Writer streams an archive. It is not safe for concurrent use.
type Writer struct {
	opts Options
	cw   *countWriter
	zw   *zip.Writer
	tw   *tar.Writer
	err  error

	kinds   map[string]int    // lower(emitted or implied path) → kindDir | kindFile | kindRenamed
	renamed map[string]string // lower(original dir path) → emitted dir path
	written map[string]bool   // lower(dir path) → directory entry written

	enc *encState // pass buffers of encrypted entries; allocated lazily, released by Close
}

type countWriter struct {
	w io.Writer
	n int64
}

func (c *countWriter) Write(p []byte) (int, error) {
	n, err := c.w.Write(p)
	c.n += int64(n)
	return n, err
}

// New starts an archive on w. It rejects an unknown format, compression or
// encryption, encryption of a tar archive, encryption without a password, a
// password without encryption, and a password longer than MaxPasswordLen or
// with a byte outside 0x20..0x7e.
func New(w io.Writer, o Options) (*Writer, error) {
	switch o.Format {
	case "":
		o.Format = FormatZip
	case FormatZip, FormatTar:
	default:
		return nil, fmt.Errorf("ziputil: unknown format %q", o.Format)
	}
	switch o.Compression {
	case "":
		o.Compression = CompressionAuto
	case CompressionAuto, CompressionStore, CompressionDeflate:
	default:
		return nil, fmt.Errorf("ziputil: unknown compression %q", o.Compression)
	}
	if err := checkEncryption(o); err != nil {
		return nil, err
	}
	if o.Encryption != EncryptionNone && o.Rand == nil {
		o.Rand = rand.Reader
	}
	a := &Writer{opts: o, cw: &countWriter{w: w},
		kinds: map[string]int{}, renamed: map[string]string{}, written: map[string]bool{}}
	if o.Format == FormatTar {
		a.tw = tar.NewWriter(a.cw)
	} else {
		a.zw = zip.NewWriter(a.cw)
		a.zw.RegisterCompressor(zip.Deflate, func(out io.Writer) (io.WriteCloser, error) {
			return flate.NewWriter(out, DeflateLevel)
		})
	}
	return a, nil
}

// Written returns the number of archive bytes written to the underlying writer.
func (a *Writer) Written() int64 { return a.cw.n }

// AddDir adds a directory entry (sanitized, de-duplicated). Adding the same
// directory twice is a no-op; an empty name is ignored.
func (a *Writer) AddDir(name string, mod time.Time) error {
	if a.err != nil {
		return a.err
	}
	segs := splitClean(name)
	if len(segs) == 0 {
		return nil
	}
	parent := a.resolveParents(segs[:len(segs)-1])
	full := a.dirPath(parent, segs[len(segs)-1])
	key := strings.ToLower(full)
	if a.written[key] {
		return nil
	}
	a.written[key] = true
	if a.tw != nil {
		return a.fail(a.tw.WriteHeader(&tar.Header{Typeflag: tar.TypeDir, Name: full + "/", Mode: 0o755, ModTime: tarTime(mod)}))
	}
	fh := &zip.FileHeader{Name: full + "/", Method: zip.Store, Modified: mod}
	fh.SetMode(fs.ModeDir | 0o755)
	_, err := a.zw.CreateHeader(fh)
	return a.fail(err)
}

// AddFile adds a file of exactly size bytes read from r. The name is
// sanitized and de-duplicated case-insensitively ("a.txt", "A (1).txt").
// A reader that yields fewer or more bytes fails with ErrSizeMismatch.
// On an encrypting Writer it fails with ErrReaderAtRequired.
func (a *Writer) AddFile(name string, mod time.Time, size int64, r io.Reader) error {
	if a.err != nil {
		return a.err
	}
	if a.opts.Encryption != EncryptionNone {
		return a.fail(ErrReaderAtRequired)
	}
	full, err := a.fileName(name, size)
	if err != nil {
		return err
	}

	var w io.Writer
	if a.tw != nil {
		if err := a.tw.WriteHeader(&tar.Header{Typeflag: tar.TypeReg, Name: full, Size: size, Mode: 0o644, ModTime: tarTime(mod)}); err != nil {
			return a.fail(err)
		}
		w = a.tw
	} else {
		fh := &zip.FileHeader{Name: full, Method: a.innerMethod(full, size), Modified: mod, UncompressedSize64: uint64(size)}
		fh.SetMode(0o644)
		zf, err := a.zw.CreateHeader(fh)
		if err != nil {
			return a.fail(err)
		}
		w = zf
	}
	n, err := io.CopyN(w, r, size)
	switch {
	case errors.Is(err, io.EOF) || (err == nil && n < size):
		return a.fail(fmt.Errorf("%w: %q: got %d of %d bytes", ErrSizeMismatch, full, n, size))
	case err != nil:
		return a.fail(err)
	}
	var one [1]byte
	if m, _ := io.ReadFull(r, one[:]); m > 0 {
		return a.fail(fmt.Errorf("%w: %q: more than %d bytes", ErrSizeMismatch, full, size))
	}
	return nil
}

// AddFileAt adds a file of exactly size bytes read from r at [0, size); a
// source that is shorter or longer fails with ErrSizeMismatch. Unencrypted,
// the output is byte-identical to AddFile's. Encrypted, r is read once or,
// for some entries above 4 MiB, twice (§3.4); a source that changes between
// the two reads fails with ErrSourceChanged.
func (a *Writer) AddFileAt(name string, mod time.Time, size int64, r io.ReaderAt) error {
	if a.err != nil {
		return a.err
	}
	if a.opts.Encryption == EncryptionNone {
		// One byte past size lets AddFile's overrun check see a longer source.
		limit := size
		if size >= 0 && size < math.MaxInt64 {
			limit = size + 1
		}
		return a.AddFile(name, mod, size, io.NewSectionReader(r, 0, limit))
	}
	full, err := a.fileName(name, size)
	if err != nil {
		return err
	}
	return a.fail(a.addEncrypted(full, mod, size, r))
}

// fileName checks size and returns the sanitized, de-duplicated archive path
// of a file entry, recording it as taken.
func (a *Writer) fileName(name string, size int64) (string, error) {
	if size < 0 {
		return "", a.fail(fmt.Errorf("ziputil: negative size for %q", name))
	}
	segs := splitClean(name)
	if len(segs) == 0 {
		segs = []string{"unnamed"}
	}
	parent := a.resolveParents(segs[:len(segs)-1])
	return a.uniqueFile(parent, segs[len(segs)-1]), nil
}

// innerMethod is the Store/Deflate policy of a file entry: Store for
// storage.zip_compression = store, for auto and an already-compressed
// extension, and for empty files; Deflate otherwise. An encrypted entry may
// still fall back to Store when Deflate does not shrink it.
func (a *Writer) innerMethod(full string, size int64) uint16 {
	switch {
	case a.opts.Compression == CompressionStore, a.opts.Compression == CompressionAuto && Compressed(full), size == 0:
		return zip.Store
	}
	return zip.Deflate
}

// Close finishes the archive (zip central directory / tar trailer). It does
// not close the underlying writer. It also clears and releases the pass
// buffers of encrypted entries and drops the password, whatever it returns.
func (a *Writer) Close() error {
	a.releaseEncryption()
	if a.err != nil {
		if errors.Is(a.err, ErrClosed) {
			return nil
		}
		return a.err
	}
	var err error
	if a.tw != nil {
		err = a.tw.Close()
	} else {
		err = a.zw.Close()
	}
	if err != nil {
		return a.fail(err)
	}
	a.err = ErrClosed
	return nil
}

func (a *Writer) fail(err error) error {
	if err != nil && a.err == nil {
		a.err = err
	}
	return err
}

// resolveParents maps sanitized parent segments to the emitted directory
// path, renaming a directory whose path is already taken by a file (or by
// another directory's rename).
func (a *Writer) resolveParents(segs []string) string {
	cur := ""
	for _, s := range segs {
		cand := join(cur, s)
		key := strings.ToLower(cand)
		if m, ok := a.renamed[key]; ok {
			cur = m
			continue
		}
		if k := a.kinds[key]; k == kindFile || k == kindRenamed {
			cur = a.renameDir(cur, s, key)
			continue
		}
		a.kinds[key] = kindDir
		cur = cand
	}
	return cur
}

// dirPath returns the emitted path of directory s under parent.
func (a *Writer) dirPath(parent, s string) string {
	cand := join(parent, s)
	key := strings.ToLower(cand)
	if m, ok := a.renamed[key]; ok {
		return m
	}
	if k := a.kinds[key]; k == kindFile || k == kindRenamed {
		return a.renameDir(parent, s, key)
	}
	a.kinds[key] = kindDir
	return cand
}

// renameDir gives the directory s under parent (whose path, origKey, is
// taken) the first numbered name that nothing uses yet. An existing
// directory of that name is not reused: it is another folder, and merging
// the two would mix their contents.
func (a *Writer) renameDir(parent, s, origKey string) string {
	for n := 1; ; n++ {
		cand := join(parent, names.Numbered(s, n, true))
		k := strings.ToLower(cand)
		if a.kinds[k] == 0 {
			a.kinds[k] = kindRenamed
			a.renamed[origKey] = cand
			return cand
		}
	}
}

func (a *Writer) uniqueFile(parent, s string) string {
	for n := 0; ; n++ {
		cand := join(parent, names.Numbered(s, n, false))
		k := strings.ToLower(cand)
		if _, dirRenamed := a.renamed[k]; a.kinds[k] == 0 && !dirRenamed {
			a.kinds[k] = kindFile
			return cand
		}
	}
}

func join(parent, s string) string {
	if parent == "" {
		return s
	}
	return parent + "/" + s
}

func tarTime(t time.Time) time.Time {
	if t.IsZero() {
		return time.Unix(0, 0)
	}
	return t.Truncate(time.Second)
}

// SanitizePath makes an archive entry path safe to extract: slash-separated,
// relative, no "" / "." / ".." segments, backslashes and control characters
// replaced by "_", invalid UTF-8 replaced, surrounding spaces of each segment
// trimmed. It may return "" (nothing left).
func SanitizePath(p string) string {
	return strings.Join(splitClean(p), "/")
}

func splitClean(p string) []string {
	p = strings.ToValidUTF8(p, "_")
	var out []string
	for _, seg := range strings.Split(p, "/") {
		seg = strings.Map(func(r rune) rune {
			if r == '\\' || r == 0 || unicode.IsControl(r) || r == utf8.RuneError {
				return '_'
			}
			return r
		}, seg)
		seg = strings.TrimSpace(seg)
		if seg == "" || seg == "." || seg == ".." {
			continue
		}
		out = append(out, seg)
	}
	return out
}
