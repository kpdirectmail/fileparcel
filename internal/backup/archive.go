package backup

import (
	"archive/tar"
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"io"
	"maps"
	"os"
	"reflect"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"time"

	"filippo.io/age"
	"github.com/klauspost/compress/zstd"

	"fileparcel/internal/core"
)

// Archive layout (inside age → zstd → tar). Member names are relative to the
// home directory, so a restore extracts into a staging home and swaps
// directories:
//
//	fileparcel-backup.json   Header (first member; lets tools identify the archive early)
//	data/fileparcel.db       consistent snapshot (VACUUM INTO)
//	fileparcel.toml          bootstrap configuration
//	keys/master.key          master key file (plain or sealed, as on disk)
//	certs/…                  CA, client CA, leaf, custom, ACME and Tailscale files
//	data/blobs/ab/cd/<id>    every ready blob (scope "full" only; already encrypted)
//	manifest.json            Manifest (last member): header, counts and the
//	                         size and SHA-256 of every other member, listed in
//	                         archive order
//
// Neither side ever holds the member list in memory: the writer spills it to
// a temporary file and streams it into the manifest, the reader folds both
// lists into a rolling digest as they go (which is why the manifest has to
// list the members in archive order).
const (
	FormatName    = "fileparcel-backup"
	FormatVersion = 1

	memberHeader   = "fileparcel-backup.json"
	memberManifest = "manifest.json"
	memberDB       = "data/fileparcel.db"
	memberConfig   = "fileparcel.toml"
	memberMasterKy = "keys/master.key"
	prefixKeys     = "keys/"
	prefixCerts    = "certs/"
	prefixBlobs    = "data/blobs/"
)

// Size limits for small members (DoS guards when reading untrusted archives).
const (
	maxHeaderSize   = 1 << 20
	maxManifestSize = 1 << 30
	maxConfigSize   = 4 << 20
	maxKeySize      = 4 << 20
	maxCertSize     = 64 << 20
	// maxMembers bounds the member count. One member costs constant memory
	// on both sides, so this is a sanity bound on the archive, not a memory
	// bound: five million members are more files than any FileParcel
	// installation holds and already imply a multi-gigabyte archive.
	maxMembers = 5_000_000
	// memberEntryOverhead is what one manifest entry costs beyond the member
	// name: {"name":"…","size":<digits>,"sha256":"<64 hex>"} plus a comma.
	// Member names need no JSON escaping (classify restricts them), so the
	// sum over the members actually read is a tight upper bound for the
	// member list — which is how a small archive is kept from handing us a
	// huge one. The missing_blobs array (blobs deleted while the backup ran,
	// 35 bytes per id, not members) is bounded by the size of the database
	// snapshot instead: every id in it is a ready row of that database.
	memberEntryOverhead = 144
	// maxTrackedMembers bounds the members compared by name (for precise
	// error messages); everything beyond that is covered by the digest only.
	maxTrackedMembers = 10_000
	// maxMissingKept bounds the missing blob ids kept from a manifest (only
	// their number is used).
	maxMissingKept = 1_000
	// maxKeyPeek bounds the key file read along the way to check that it
	// belongs to the archived database.
	maxKeyPeek = 64 << 10
)

// Header identifies an archive. It is the first member and repeated in the
// manifest. MKID, DBSize and BlobBytes are known before the first byte is
// written and are repeated in the manifest's counts: they let a reader check
// that the archived key file belongs to the archived database, and size a
// restore's free-space check, before any member is extracted. Archives
// written by older versions leave them empty.
type Header struct {
	Format        string    `json:"format"`
	Version       int       `json:"version"`
	BackupID      string    `json:"backup_id"`
	JobID         string    `json:"job_id,omitempty"`
	AppVersion    string    `json:"app_version"`
	SchemaVersion int       `json:"schema_version"`
	Scope         string    `json:"scope"`
	InstallID     string    `json:"install_id"`
	CreatedAt     time.Time `json:"created_at"`
	Encryption    string    `json:"encryption"`
	MKID          string    `json:"mk_id,omitempty"`      // meta.mk_id of the snapshot
	DBSize        int64     `json:"db_size,omitempty"`    // size of the database snapshot
	BlobBytes     int64     `json:"blob_bytes,omitempty"` // size of all blob members
}

// Member is one archive member recorded in the manifest.
type Member struct {
	Name   string `json:"name"`
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`
}

// Counts summarizes an archive.
type Counts struct {
	Members   int   `json:"members"`
	Blobs     int64 `json:"blobs"`
	BlobBytes int64 `json:"blob_bytes"`
	DBSize    int64 `json:"db_size"`
	CertFiles int   `json:"cert_files"`
}

// Manifest is the last member of an archive. Members lists every other
// member in archive order; it is written and read as a stream, so a Manifest
// that walkArchive returns carries no Members (walkResult.Members holds
// their number) and at most maxMissingKept MissingBlobs.
type Manifest struct {
	Header
	Counts       Counts   `json:"counts"`
	Members      []Member `json:"members"`
	MissingBlobs []string `json:"missing_blobs,omitempty"`
}

// manifestHead is a Manifest without the member list: it is marshalled on
// its own and the streamed members are spliced into it (finish).
type manifestHead struct {
	Header
	Counts Counts `json:"counts"`
}

// memberKind classifies member names.
type memberKind int

const (
	kindInvalid memberKind = iota
	kindHeader
	kindManifest
	kindDB
	kindConfig
	kindKey
	kindCert
	kindBlob
)

var (
	blobMemberRe = regexp.MustCompile(`^data/blobs/([0-9a-f]{2})/([0-9a-f]{2})/([0-9a-f]{32})$`)
	keyMemberRe  = regexp.MustCompile(`^keys/master\.key(\.next)?$`)
	segmentRe    = regexp.MustCompile(`^[A-Za-z0-9._@+=,~-]{1,255}$`)
)

// classify validates a member name (strictly: no traversal, no absolute
// paths, only the layout above) and returns its kind.
func classify(name string) memberKind {
	switch name {
	case memberHeader:
		return kindHeader
	case memberManifest:
		return kindManifest
	case memberDB:
		return kindDB
	case memberConfig:
		return kindConfig
	}
	if len(name) > 1024 {
		return kindInvalid
	}
	if keyMemberRe.MatchString(name) {
		return kindKey
	}
	if m := blobMemberRe.FindStringSubmatch(name); m != nil {
		if m[3][0:2] == m[1] && m[3][2:4] == m[2] {
			return kindBlob
		}
		return kindInvalid
	}
	if rest, ok := strings.CutPrefix(name, prefixCerts); ok && rest != "" {
		segs := strings.Split(rest, "/")
		if len(segs) > 16 {
			return kindInvalid
		}
		for _, s := range segs {
			if s == "." || s == ".." || !segmentRe.MatchString(s) {
				return kindInvalid
			}
		}
		return kindCert
	}
	return kindInvalid
}

// blobMemberName returns the archive member of a blob id (DESIGN §3 layout).
func blobMemberName(id string) string {
	return prefixBlobs + id[0:2] + "/" + id[2:4] + "/" + id
}

// maxSize returns the size limit of a member kind (-1 = unlimited).
func (k memberKind) maxSize() int64 {
	switch k {
	case kindHeader:
		return maxHeaderSize
	case kindManifest:
		return maxManifestSize
	case kindConfig:
		return maxConfigSize
	case kindKey:
		return maxKeySize
	case kindCert:
		return maxCertSize
	}
	return -1
}

// ---------- writing ----------

// countingHash hashes and counts everything written through it.
type countingHash struct {
	h hash.Hash
	n int64
}

func (c *countingHash) Write(p []byte) (int, error) {
	c.h.Write(p)
	c.n += int64(len(p))
	return len(p), nil
}

// archiveWriter writes tar → zstd → age into dst and hashes the ciphertext.
type archiveWriter struct {
	ctx     context.Context
	file    *countingHash // ciphertext hash and size
	age     io.WriteCloser
	zw      *zstd.Encoder
	tw      *tar.Writer
	modTime time.Time
	idx     *memberIndex
	// seen holds the non-blob member names (a handful): blob members are
	// unique by construction (blobs.id is a primary key) and must not cost
	// memory per file.
	seen map[string]bool
}

// newArchiveWriter starts an archive on dst encrypted to recipients. tmpDir
// (may be empty) holds the spilled member list.
func newArchiveWriter(ctx context.Context, dst io.Writer, recipients []age.Recipient, modTime time.Time, tmpDir string) (*archiveWriter, error) {
	idx, err := newMemberIndex(tmpDir)
	if err != nil {
		return nil, fmt.Errorf("backup: member list: %w", err)
	}
	a := &archiveWriter{ctx: ctx, file: &countingHash{h: sha256.New()}, modTime: modTime.UTC().Truncate(time.Second),
		idx: idx, seen: map[string]bool{}}
	aw, err := age.Encrypt(ctxWriter{ctx, io.MultiWriter(dst, a.file)}, recipients...)
	if err != nil {
		idx.close()
		return nil, fmt.Errorf("backup: encrypt: %w", err)
	}
	zw, err := zstd.NewWriter(aw, zstd.WithEncoderLevel(zstd.SpeedDefault),
		zstd.WithEncoderConcurrency(min(4, runtime.GOMAXPROCS(0))), zstd.WithWindowSize(8<<20))
	if err != nil {
		_ = aw.Close()
		idx.close()
		return nil, fmt.Errorf("backup: compress: %w", err)
	}
	a.age, a.zw, a.tw = aw, zw, tar.NewWriter(zw)
	return a, nil
}

func (a *archiveWriter) header(name string, size int64, mode int64) *tar.Header {
	return &tar.Header{Typeflag: tar.TypeReg, Name: name, Size: size, Mode: mode, ModTime: a.modTime,
		Format: tar.FormatPAX}
}

// claim records name as written, rejecting a duplicate non-blob member.
func (a *archiveWriter) claim(name string) error {
	if strings.HasPrefix(name, prefixBlobs) {
		return nil
	}
	if a.seen[name] {
		return fmt.Errorf("backup: duplicate member %s", name)
	}
	a.seen[name] = true
	return nil
}

// addBytes adds a small member from memory.
func (a *archiveWriter) addBytes(name string, data []byte) error {
	if err := a.claim(name); err != nil {
		return err
	}
	if err := a.tw.WriteHeader(a.header(name, int64(len(data)), 0o600)); err != nil {
		return err
	}
	if _, err := a.tw.Write(data); err != nil {
		return err
	}
	sum := sha256.Sum256(data)
	return a.idx.add(Member{Name: name, Size: int64(len(data)), SHA256: hex.EncodeToString(sum[:])})
}

// addFile streams the regular file at path as member name and returns its size.
// progress (may be nil) receives the bytes copied.
func (a *archiveWriter) addFile(name, path string, progress func(int64)) (int64, error) {
	if err := a.claim(name); err != nil {
		return 0, err
	}
	f, err := os.Open(path)
	if err != nil {
		return 0, err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return 0, err
	}
	if !st.Mode().IsRegular() {
		return 0, fmt.Errorf("backup: %s is not a regular file", path)
	}
	size := st.Size()
	if err := a.tw.WriteHeader(a.header(name, size, 0o600)); err != nil {
		return 0, err
	}
	h := sha256.New()
	src := io.TeeReader(ctxReader{a.ctx, f}, h)
	if progress != nil {
		src = &progressReader{r: src, fn: progress}
	}
	n, err := io.CopyN(a.tw, src, size)
	if err != nil {
		if errors.Is(err, io.EOF) {
			return n, fmt.Errorf("backup: %s shrank while it was being read", path)
		}
		return n, err
	}
	if err := a.idx.add(Member{Name: name, Size: size, SHA256: hex.EncodeToString(h.Sum(nil))}); err != nil {
		return size, err
	}
	return size, nil
}

// finish writes the manifest — the spilled member list streamed into the
// marshalled head — and closes every layer. It returns the ciphertext size
// and SHA-256.
func (a *archiveWriter) finish(m *Manifest) (int64, string, error) {
	defer a.idx.close()
	if err := a.claim(memberManifest); err != nil {
		return 0, "", err
	}
	m.Counts.Members = int(a.idx.n)
	head, err := json.Marshal(manifestHead{Header: m.Header, Counts: m.Counts})
	if err != nil {
		return 0, "", err
	}
	if len(head) < 2 || head[0] != '{' || head[len(head)-1] != '}' {
		return 0, "", errors.New("backup: cannot write the manifest")
	}
	prefix := string(head[:len(head)-1]) // "{…" without the closing brace
	if len(prefix) > 1 {
		prefix += ","
	}
	prefix += `"members":`
	tail := []byte("}")
	if len(m.MissingBlobs) > 0 {
		mb, err := json.Marshal(m.MissingBlobs)
		if err != nil {
			return 0, "", err
		}
		tail = append(append([]byte(`,"missing_blobs":`), mb...), '}')
	}
	size := int64(len(prefix)) + a.idx.jsonLen() + int64(len(tail))
	if err := a.tw.WriteHeader(a.header(memberManifest, size, 0o600)); err != nil {
		return 0, "", err
	}
	if _, err := io.WriteString(a.tw, prefix); err != nil {
		return 0, "", err
	}
	if err := a.idx.writeJSON(a.tw); err != nil {
		return 0, "", err
	}
	if _, err := a.tw.Write(tail); err != nil {
		return 0, "", err
	}
	if err := a.tw.Close(); err != nil {
		return 0, "", err
	}
	if err := a.zw.Close(); err != nil {
		return 0, "", err
	}
	if err := a.age.Close(); err != nil {
		return 0, "", err
	}
	return a.file.n, hex.EncodeToString(a.file.h.Sum(nil)), nil
}

// abort releases the encoder and the spill file (the destination is
// discarded by the caller).
func (a *archiveWriter) abort() {
	if a.zw != nil {
		_ = a.zw.Close()
	}
	a.idx.close()
}

// memberIndex collects the manifest's member list outside the heap: one
// JSON object per line in a temporary file, streamed back into the manifest
// by writeJSON. An archive of a million files would otherwise need about a
// gigabyte for the list and its JSON alone.
type memberIndex struct {
	f     *os.File
	w     *bufio.Writer
	n     int64 // members added
	bytes int64 // bytes of the JSON objects, without the newlines
}

func newMemberIndex(dir string) (*memberIndex, error) {
	if dir != "" {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return nil, err
		}
	}
	f, err := os.CreateTemp(dir, "members-*.ndjson")
	if err != nil {
		return nil, err
	}
	return &memberIndex{f: f, w: bufio.NewWriterSize(f, 64<<10)}, nil
}

func (x *memberIndex) add(m Member) error {
	b, err := json.Marshal(m)
	if err != nil {
		return err
	}
	if _, err := x.w.Write(b); err != nil {
		return err
	}
	if err := x.w.WriteByte('\n'); err != nil {
		return err
	}
	x.n++
	x.bytes += int64(len(b))
	return nil
}

// jsonLen is the length of the JSON array writeJSON produces.
func (x *memberIndex) jsonLen() int64 {
	if x.n == 0 {
		return 2 // "[]"
	}
	return 2 + x.bytes + x.n - 1 // brackets, objects, separating commas
}

// writeJSON writes the members as one JSON array, in the order they were added.
func (x *memberIndex) writeJSON(w io.Writer) error {
	if err := x.w.Flush(); err != nil {
		return err
	}
	if _, err := x.f.Seek(0, io.SeekStart); err != nil {
		return err
	}
	if _, err := io.WriteString(w, "["); err != nil {
		return err
	}
	r := bufio.NewReaderSize(x.f, 64<<10)
	for i := int64(0); i < x.n; i++ {
		line, err := r.ReadString('\n')
		if err != nil {
			return fmt.Errorf("backup: member list: %w", err)
		}
		if i > 0 {
			if _, err := io.WriteString(w, ","); err != nil {
				return err
			}
		}
		if _, err := io.WriteString(w, line[:len(line)-1]); err != nil {
			return err
		}
	}
	_, err := io.WriteString(w, "]")
	return err
}

func (x *memberIndex) close() {
	if x == nil || x.f == nil {
		return
	}
	name := x.f.Name()
	_ = x.f.Close()
	_ = os.Remove(name)
	x.f = nil
}

type progressReader struct {
	r  io.Reader
	fn func(int64)
}

func (p *progressReader) Read(b []byte) (int, error) {
	n, err := p.r.Read(b)
	if n > 0 {
		p.fn(int64(n))
	}
	return n, err
}

// ---------- reading ----------

// memberInfo describes a member passed to the walk callback.
type memberInfo struct {
	Name string
	Kind memberKind
	Size int64
}

// walkResult is the outcome of walking an archive.
type walkResult struct {
	Header Header
	// Manifest carries no member list (it is streamed); Members and
	// MissingBlobs hold their numbers.
	Manifest     *Manifest
	Members      int64
	MissingBlobs int64
	// FileSHA256/FileSize describe the ciphertext actually read (the whole file).
	FileSHA256 string
	FileSize   int64
}

// errStopWalk stops a walk early without error (header-only checks).
var errStopWalk = errors.New("stop walk")

// openPlain decrypts and decompresses an archive stream. The returned close
// func releases the decompressor.
func openPlain(ctx context.Context, src io.Reader, ids []age.Identity) (*tar.Reader, func(), error) {
	if len(ids) == 0 {
		return nil, nil, core.Invalid("identity", "an identity or passphrase is required to decrypt the backup")
	}
	ar, err := age.Decrypt(src, ids...)
	if err != nil {
		return nil, nil, decryptError(err)
	}
	zr, err := zstd.NewReader(ctxReader{ctx, ar}, zstd.WithDecoderConcurrency(2),
		zstd.WithDecoderMaxWindow(64<<20), zstd.WithDecoderMaxMemory(1<<30))
	if err != nil {
		return nil, nil, core.Wrap(core.ErrCorrupt, "the backup is not a FileParcel archive", err)
	}
	return tar.NewReader(zr), zr.Close, nil
}

// walkArchive decrypts src with ids, validates every member name and type,
// hashes every member and calls fn for each member except the header and the
// manifest (fn may read the member partially; the rest is drained and
// hashed). At the end it checks the manifest against what was read. fn
// returning errStopWalk ends the walk early after the header was read (no
// manifest check; walkResult.Manifest is nil). header (may be nil) is called
// once the header was parsed, before any other member.
func walkArchive(ctx context.Context, src io.Reader, ids []age.Identity, header func(Header) error,
	fn func(m memberInfo, r io.Reader) error) (*walkResult, error) {
	fileHash := &countingHash{h: sha256.New()}
	tee := io.TeeReader(src, fileHash)
	tr, closeZ, err := openPlain(ctx, tee, ids)
	if err != nil {
		return nil, err
	}
	defer closeZ()
	res := &walkResult{}
	corrupt := func(format string, a ...any) error {
		return core.Errorf(core.ErrCorrupt, "backup archive: "+format, a...)
	}
	next := func() (*tar.Header, error) {
		h, err := tr.Next()
		if err != nil {
			if errors.Is(err, io.EOF) {
				return nil, io.EOF
			}
			if ce := core.AsError(err); ce != nil {
				return nil, err
			}
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			return nil, core.Wrap(core.ErrCorrupt, "the backup archive is damaged or truncated", err)
		}
		return h, nil
	}

	// Header first.
	th, err := next()
	if err != nil {
		if errors.Is(err, io.EOF) {
			return nil, corrupt("empty archive")
		}
		return nil, err
	}
	if th.Name != memberHeader || th.Typeflag != tar.TypeReg || th.Size > maxHeaderSize || th.Size < 2 {
		return nil, corrupt("missing header")
	}
	hb, err := io.ReadAll(io.LimitReader(tr, maxHeaderSize))
	if err != nil {
		return nil, core.Wrap(core.ErrCorrupt, "the backup archive is damaged", err)
	}
	if err := json.Unmarshal(hb, &res.Header); err != nil {
		return nil, corrupt("unreadable header")
	}
	if err := res.Header.validate(); err != nil {
		return nil, err
	}
	if header != nil {
		if err := header(res.Header); err != nil {
			if errors.Is(err, errStopWalk) {
				return res, nil
			}
			return nil, err
		}
	}
	// Both member lists are folded into a rolling digest (archive order), so
	// neither the archive's nor the manifest's list is ever held in memory.
	// tracked keeps the first maxTrackedMembers non-blob members so that a
	// mismatch among them can name the member.
	chain := newMemberChain()
	listed := newMemberChain()
	// manifestBudget grows with every member: what the manifest may cost.
	manifestBudget := int64(1 << 20)
	tracked := map[string]Member{}
	hdrMember := Member{Name: memberHeader, Size: int64(len(hb)), SHA256: sha256Hex(hb)}
	chain.add(hdrMember)
	manifestBudget += int64(len(memberHeader)) + memberEntryOverhead
	tracked[memberHeader] = hdrMember
	var sawDB, sawKey bool
	var keyMKID string

	// Members until the manifest.
	var m *Manifest
	for {
		th, err := next()
		if errors.Is(err, io.EOF) {
			return nil, corrupt("manifest missing (archive truncated?)")
		}
		if err != nil {
			return nil, err
		}
		if chain.n > maxMembers {
			return nil, corrupt("too many members")
		}
		kind := classify(th.Name)
		if kind == kindInvalid || kind == kindHeader {
			return nil, corrupt("unexpected member %q", truncate(th.Name, 120))
		}
		if th.Typeflag != tar.TypeReg {
			return nil, corrupt("member %q is not a regular file", truncate(th.Name, 120))
		}
		if kind != kindBlob && len(tracked) < maxTrackedMembers {
			if _, dup := tracked[th.Name]; dup {
				return nil, corrupt("duplicate member %q", truncate(th.Name, 120))
			}
		}
		lim := kind.maxSize()
		if kind == kindManifest {
			lim = min(lim, manifestBudget)
		} else {
			manifestBudget += int64(len(th.Name)) + memberEntryOverhead
			if kind == kindDB {
				// missing_blobs lists blobs that are not members; each is a
				// ready row of this database (id stored in the row and in its
				// primary key index), so the snapshot, read in full below,
				// bounds that list.
				manifestBudget += max(th.Size, 0)
			}
		}
		if lim >= 0 && th.Size > lim {
			return nil, corrupt("member %q is too large", truncate(th.Name, 120))
		}
		if kind == kindManifest {
			mf, missing, derr := decodeManifest(io.LimitReader(tr, lim), func(mm Member) error {
				listed.add(mm)
				want, ok := tracked[mm.Name]
				if !ok {
					return nil // only the digest covers it
				}
				if want.Size != mm.Size || !strings.EqualFold(want.SHA256, mm.SHA256) {
					return corrupt("member %q does not match its checksum", truncate(mm.Name, 120))
				}
				delete(tracked, mm.Name)
				return nil
			})
			if derr != nil {
				if errors.Is(derr, errBadManifest) {
					return nil, corrupt("unreadable manifest")
				}
				return nil, derr
			}
			m, res.MissingBlobs = mf, missing
			break
		}
		switch th.Name {
		case memberDB:
			sawDB = true
		case memberMasterKy:
			sawKey = true
		}
		h := sha256.New()
		var sink io.Writer = h
		var keyBuf *bytes.Buffer
		if th.Name == memberMasterKy && th.Size > 0 && th.Size <= maxKeyPeek {
			keyBuf = new(bytes.Buffer)
			keyBuf.Grow(int(th.Size))
			sink = io.MultiWriter(h, keyBuf)
		}
		mr := io.TeeReader(tr, sink)
		if fn != nil {
			if err := fn(memberInfo{Name: th.Name, Kind: kind, Size: th.Size}, mr); err != nil {
				if errors.Is(err, errStopWalk) {
					return res, nil
				}
				return nil, err
			}
		}
		if _, err := io.Copy(sink, tr); err != nil { // drain what fn did not read
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			return nil, core.Wrap(core.ErrCorrupt, "the backup archive is damaged", err)
		}
		if keyBuf != nil {
			keyMKID = keyFileMKID(keyBuf.Bytes())
		}
		cm := Member{Name: th.Name, Size: th.Size, SHA256: hex.EncodeToString(h.Sum(nil))}
		chain.add(cm)
		if kind != kindBlob && len(tracked) < maxTrackedMembers {
			tracked[th.Name] = cm
		}
	}
	if _, err := next(); !errors.Is(err, io.EOF) {
		if err != nil {
			return nil, err
		}
		return nil, corrupt("data after the manifest")
	}
	// Drain the rest of the ciphertext so the file hash covers everything.
	if _, err := io.Copy(io.Discard, ctxReader{ctx, tee}); err != nil {
		return nil, core.Wrap(core.ErrCorrupt, "the backup file could not be read to the end", err)
	}
	res.FileSHA256 = hex.EncodeToString(fileHash.h.Sum(nil))
	res.FileSize = fileHash.n

	if !m.Header.equal(res.Header) {
		return nil, corrupt("manifest does not match the header")
	}
	if listed.n != chain.n {
		return nil, corrupt("manifest lists %d members, archive has %d", listed.n, chain.n)
	}
	if name, ok := anyKey(tracked); ok {
		return nil, corrupt("member %q is missing from the manifest", truncate(name, 120))
	}
	if listed.sum() != chain.sum() {
		// Same number of members, same names for those compared by name:
		// the lists differ in order, in a blob member or beyond the first
		// maxTrackedMembers members.
		return nil, corrupt("the manifest does not match the archive members")
	}
	if m.Counts.Members != 0 && int64(m.Counts.Members) != chain.n {
		return nil, corrupt("manifest counts %d members, archive has %d", m.Counts.Members, chain.n)
	}
	if !sawDB {
		return nil, corrupt("database snapshot missing")
	}
	if !sawKey {
		return nil, corrupt("master key missing")
	}
	// The key file and the database snapshot only restore together: a master
	// key rotation between the snapshot and the key file leaves an archive
	// whose restored server refuses to start ("foreign key file").
	if res.Header.MKID != "" && keyMKID != "" && keyMKID != res.Header.MKID {
		return nil, corrupt("the archived master key belongs to %s, the archived database to %s: this backup cannot be restored",
			truncate(keyMKID, 40), truncate(res.Header.MKID, 40))
	}
	res.Manifest = m
	res.Members = chain.n
	return res, nil
}

// anyKey returns the lexically smallest key of m (deterministic messages).
func anyKey(m map[string]Member) (string, bool) {
	out, ok := "", false
	for k := range m {
		if !ok || k < out {
			out, ok = k, true
		}
	}
	return out, ok
}

// keyFileMKID returns the mk_id of a keys/master.key member ("" when it
// cannot be read: an older or hand-made archive).
func keyFileMKID(b []byte) string {
	var kf struct {
		MKID string `json:"mk_id"`
	}
	if json.Unmarshal(b, &kf) != nil {
		return ""
	}
	return kf.MKID
}

// memberChain folds a member list into a rolling digest, in list order.
type memberChain struct {
	h   hash.Hash
	n   int64
	buf []byte
}

func newMemberChain() *memberChain { return &memberChain{h: sha256.New()} }

func (c *memberChain) add(m Member) {
	c.buf = strconv.AppendInt(c.buf[:0], int64(len(m.Name)), 10)
	c.buf = append(c.buf, 0)
	c.buf = append(c.buf, m.Name...)
	c.buf = append(c.buf, 0)
	c.buf = strconv.AppendInt(c.buf, m.Size, 10)
	c.buf = append(c.buf, 0)
	c.buf = append(c.buf, strings.ToLower(m.SHA256)...)
	c.buf = append(c.buf, '\n')
	c.h.Write(c.buf)
	c.n++
}

func (c *memberChain) sum() string { return hex.EncodeToString(c.h.Sum(nil)) }

// errBadManifest marks a manifest that is not readable JSON of the expected
// shape (it never carries details of its content).
var errBadManifest = errors.New("unreadable manifest")

// decodeManifest reads a manifest without keeping its member list in memory:
// every entry of "members" goes to onMember (in archive order), and
// "missing_blobs" is only counted (at most maxMissingKept ids are kept).
// Errors from onMember are returned unchanged.
func decodeManifest(r io.Reader, onMember func(Member) error) (*Manifest, int64, error) {
	dec := json.NewDecoder(r)
	if t, err := dec.Token(); err != nil || t != json.Delim('{') {
		return nil, 0, errBadManifest
	}
	var m Manifest
	var missing int64
	for dec.More() {
		kt, err := dec.Token()
		if err != nil {
			return nil, 0, errBadManifest
		}
		key, ok := kt.(string)
		if !ok {
			return nil, 0, errBadManifest
		}
		switch key {
		case "members":
			err = decodeArray(dec, func() error {
				var mm Member
				if err := dec.Decode(&mm); err != nil {
					return errBadManifest
				}
				return onMember(mm)
			})
		case "missing_blobs":
			err = decodeArray(dec, func() error {
				var id string
				if err := dec.Decode(&id); err != nil {
					return errBadManifest
				}
				missing++
				if len(m.MissingBlobs) < maxMissingKept {
					m.MissingBlobs = append(m.MissingBlobs, id)
				}
				return nil
			})
		default:
			if manifestFields[key] {
				err = decodeField(dec, key, &m)
				break
			}
			err = skipValue(dec) // unknown field: never buffered
		}
		if err != nil {
			return nil, 0, err
		}
	}
	if t, err := dec.Token(); err != nil || t != json.Delim('}') {
		return nil, 0, errBadManifest
	}
	return &m, missing, nil
}

// manifestFields are the JSON names of the Manifest fields (the embedded
// header included). A manifest's other fields are skipped without being
// read into memory.
var manifestFields = jsonFieldNames(reflect.TypeOf(Manifest{}))

func jsonFieldNames(t reflect.Type) map[string]bool {
	out := map[string]bool{}
	for i := range t.NumField() {
		f := t.Field(i)
		if f.Anonymous && f.Type.Kind() == reflect.Struct {
			maps.Copy(out, jsonFieldNames(f.Type))
			continue
		}
		if name, _, _ := strings.Cut(f.Tag.Get("json"), ","); name != "" && name != "-" {
			out[name] = true
		}
	}
	return out
}

// maxFieldBytes bounds one scalar manifest field (members and missing_blobs
// are streamed, everything else is small).
const maxFieldBytes = 64 << 10

// skipValue reads the next value and discards it.
func skipValue(dec *json.Decoder) error {
	depth := 0
	for {
		t, err := dec.Token()
		if err != nil {
			return errBadManifest
		}
		switch t {
		case json.Delim('{'), json.Delim('['):
			depth++
		case json.Delim('}'), json.Delim(']'):
			depth--
		}
		if depth == 0 {
			return nil
		}
	}
}

// decodeField decodes the next value into m's field named key.
func decodeField(dec *json.Decoder, key string, m *Manifest) error {
	var raw json.RawMessage
	if err := dec.Decode(&raw); err != nil {
		return errBadManifest
	}
	if len(raw) > maxFieldBytes {
		return errBadManifest
	}
	kb, err := json.Marshal(key)
	if err != nil {
		return errBadManifest
	}
	one := make([]byte, 0, len(kb)+len(raw)+3)
	one = append(one, '{')
	one = append(one, kb...)
	one = append(one, ':')
	one = append(one, raw...)
	one = append(one, '}')
	if err := json.Unmarshal(one, m); err != nil {
		return errBadManifest
	}
	return nil
}

// decodeArray calls elem for every element of the next JSON array (null
// counts as empty).
func decodeArray(dec *json.Decoder, elem func() error) error {
	t, err := dec.Token()
	if err != nil {
		return errBadManifest
	}
	if t == nil {
		return nil
	}
	if t != json.Delim('[') {
		return errBadManifest
	}
	for dec.More() {
		if err := elem(); err != nil {
			return err
		}
	}
	if _, err := dec.Token(); err != nil { // ']'
		return errBadManifest
	}
	return nil
}

// equal compares two headers (timestamps by instant).
func (h Header) equal(o Header) bool {
	a, b := h, o
	a.CreatedAt, b.CreatedAt = time.Time{}, time.Time{}
	return a == b && h.CreatedAt.Equal(o.CreatedAt)
}

// validate checks the header fields of an archive.
func (h Header) validate() error {
	if h.Format != FormatName {
		return core.Errorf(core.ErrCorrupt, "not a FileParcel backup")
	}
	if h.Version < 1 || h.Version > FormatVersion {
		return core.Errorf(core.ErrInvalid, "backup format version %d is not supported by this FileParcel version", h.Version)
	}
	if h.Scope != core.BackupFull && h.Scope != core.BackupMetadata {
		return core.Errorf(core.ErrCorrupt, "backup archive: unknown scope %q", truncate(h.Scope, 40))
	}
	if h.SchemaVersion < 1 {
		return core.Errorf(core.ErrCorrupt, "backup archive: invalid schema version")
	}
	return nil
}

func sha256Hex(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}
