package blobstore

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"strconv"
	"sync"
	"time"

	"fileparcel/internal/core"
	"fileparcel/internal/crypt"
	"fileparcel/internal/db"
	"fileparcel/internal/ids"
)

// parted is a core.PartedBlob. It holds no file handle and no key material
// between calls (a part usually arrives in its own HTTP request): WritePart
// opens the file and unwraps the DEK itself.
type parted struct {
	s       *Service
	id      string
	idRaw   []byte
	size    int64
	cipher  core.CipherID
	created time.Time
}

var _ core.PartedBlob = (*parted)(nil)

// ID returns the blob id.
func (p *parted) ID() string { return p.id }

// Size returns the declared plaintext size.
func (p *parted) Size() int64 { return p.size }

// PartCount returns ceil(Size/PartSize) (0 for an empty blob).
func (p *parted) PartCount() int { return partCount(p.size) }

// partLen is the plaintext length of part n.
func (p *parted) partLen(n int) int64 {
	return min(int64(core.PartSize), p.size-int64(n)*core.PartSize)
}

// bufPool recycles plaintext segment buffers (cleared before reuse).
var bufPool = sync.Pool{New: func() any { b := make([]byte, segSize); return &b }}

// sealPool recycles sealed segment buffers.
var sealPool = sync.Pool{New: func() any { b := make([]byte, 0, storedSegSize); return &b }}

// WritePart streams part n (exactly its length) from r: every segment is
// encrypted with a fresh random nonce and written at its fixed offset,
// while SHA-256 of the plaintext is computed. The part is fsynced
// (storage.fsync) before returning. When wantSHA256 is set and differs from
// the digest, the digest is returned with a 422 (the data stays written; a
// retry simply rewrites it). Re-writing a part is safe; writes of the same
// part are serialised.
func (p *parted) WritePart(ctx context.Context, n int, r io.Reader, wantSHA256 []byte) ([]byte, error) {
	if n < 0 || n >= p.PartCount() {
		return nil, core.Invalid("n", fmt.Sprintf("part index must be between 0 and %d", p.PartCount()-1))
	}
	if len(wantSHA256) != 0 && len(wantSHA256) != sha256.Size {
		return nil, core.Invalid("sha256", "the digest must be 32 bytes")
	}
	k, err := p.s.keys()
	if err != nil {
		return nil, err
	}
	// Parts of one blob are written in parallel (shared blob lock) but a
	// part is never written twice at once, and Commit (exclusive blob lock)
	// waits for in-flight parts: a part written after Commit sees the
	// committed state and is refused instead of changing committed data.
	unlockBlob := p.s.blobLocks.rlock(p.id)
	defer unlockBlob()
	unlockPart := p.s.partLocks.lock(p.id + "/" + strconv.Itoa(n))
	defer unlockPart()

	row, err := p.s.loadRow(ctx, nil, p.id)
	if err != nil {
		return nil, err
	}
	switch row.state {
	case stateReady:
		return nil, core.Errorf(core.ErrConflict, "the blob is already committed")
	case stateDeleting:
		return nil, core.NotFoundf("blob not found")
	}
	_, rel, _ := blobPaths(p.id)
	f, err := p.s.root.OpenFile(rel, os.O_WRONLY, 0)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, core.NotFoundf("blob file not found")
	}
	if err != nil {
		return nil, fmt.Errorf("blobstore: %w", err)
	}
	defer f.Close()
	dek, err := k.UnwrapDEK(p.idRaw, row.kekID, row.wrapped)
	if err != nil {
		return nil, err
	}
	a, err := newAEAD(row.cipher, dek)
	crypt.Zero(dek)
	if err != nil {
		return nil, err
	}

	h := makeHeader(row.cipher, p.idRaw)
	sc := newSegCipher(a, &h)
	bp := bufPool.Get().(*[]byte)
	sp := sealPool.Get().(*[]byte)
	defer func() {
		clear(*bp)
		bufPool.Put(bp)
		sealPool.Put(sp)
	}()
	buf := *bp
	digest := sha256.New()
	last := numSegments(p.size) - 1
	seg := int64(n) * segsPerPart
	for remaining := p.partLen(n); remaining > 0; seg++ {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		l := min(remaining, segSize)
		if _, err := io.ReadFull(r, buf[:l]); err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
				return nil, core.Invalid("body", "the part is shorter than expected")
			}
			return nil, err
		}
		digest.Write(buf[:l])
		sealed := sc.seal(seg, seg == last, buf[:l], (*sp)[:0])
		if _, err := f.WriteAt(sealed, segOffset(seg)); err != nil {
			return nil, diskErr(err)
		}
		remaining -= l
	}
	var extra [1]byte
	switch _, err := io.ReadFull(r, extra[:]); {
	case err == nil:
		return nil, core.Invalid("body", "the part is longer than expected")
	case !errors.Is(err, io.EOF):
		return nil, err
	}
	if p.s.fsyncEnabled() {
		if err := f.Sync(); err != nil {
			return nil, diskErr(err)
		}
	}
	got := digest.Sum(nil)
	if len(wantSHA256) != 0 && !ids.EqualBytes(got, wantSHA256) {
		return got, core.Invalid("sha256", "the part does not match its SHA-256 digest")
	}
	return got, nil
}

// Commit requires one digest per part (as returned by WritePart), checks
// that every part was written (the header and the nonce of every segment of
// every part — a never-written segment reads back as zeros), fsyncs and
// marks the blob ready with content_hash derived from the digests. It waits
// for parts still being written in this process; parts sent afterwards are
// refused (ErrConflict). Committing an already committed blob with the same
// digests returns its info again. The check detects segments that were
// never written, not torn ones; use Verify for that.
func (p *parted) Commit(ctx context.Context, partDigests [][]byte) (*core.BlobInfo, error) {
	pc := p.PartCount()
	if len(partDigests) != pc {
		return nil, core.Invalid("parts", fmt.Sprintf("expected %d part digests, got %d", pc, len(partDigests)))
	}
	for i, d := range partDigests {
		if len(d) != sha256.Size {
			return nil, core.Invalid("parts", fmt.Sprintf("part %d: digest must be 32 bytes", i))
		}
	}
	hash := HashOfDigests(partDigests)
	stored := StoredSize(p.size)
	unlock := p.s.blobLocks.lock(p.id)
	defer unlock()
	row, err := p.s.loadRow(ctx, nil, p.id)
	if err != nil {
		return nil, err
	}
	switch row.state {
	case stateReady:
		if row.contentHash.String == hash {
			return row.info(), nil
		}
		return nil, core.Errorf(core.ErrConflict, "the blob is already committed with other content")
	case stateDeleting:
		return nil, core.NotFoundf("blob not found")
	}
	_, rel, _ := blobPaths(p.id)
	f, err := p.s.root.OpenFile(rel, os.O_RDWR, 0)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, core.NotFoundf("blob file not found")
	}
	if err != nil {
		return nil, fmt.Errorf("blobstore: %w", err)
	}
	defer f.Close()
	if st, err := f.Stat(); err != nil || st.Size() != stored {
		return nil, corrupt("file has an unexpected size")
	}
	hdr := make([]byte, headerSize)
	if _, err := f.ReadAt(hdr, 0); err != nil {
		return nil, corrupt("header unreadable")
	}
	if err := checkHeader(hdr, p.idRaw, row.cipher); err != nil {
		return nil, err
	}
	for n := range pc {
		first := int64(n) * segsPerPart
		end := first + (p.partLen(n)+segSize-1)/segSize
		for seg := first; seg < end; seg++ {
			if !written(f, seg) {
				return nil, core.Errorf(core.ErrPrecondition, "part %d is incomplete or has not been uploaded", n)
			}
		}
	}
	if p.s.fsyncEnabled() {
		if err := f.Sync(); err != nil {
			return nil, diskErr(err)
		}
	}
	var changed int64
	err = p.s.env.DB.Tx(ctx, func(tx *sql.Tx) error {
		res, err := tx.ExecContext(ctx, `UPDATE blobs SET state = 'ready', stored_size = ?, content_hash = ?, parts_done = ?
			WHERE id = ? AND state = 'staging'`, stored, hash, pc, p.id)
		if err != nil {
			return err
		}
		changed, _ = res.RowsAffected()
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("blobstore: commit %s: %w", p.id, err)
	}
	if changed != 1 {
		return nil, core.Errorf(core.ErrConflict, "the blob changed state during commit")
	}
	return &core.BlobInfo{ID: p.id, Size: p.size, StoredSize: stored, ContentHash: hash, Cipher: row.cipher, CreatedAt: db.FromMs(row.createdAt)}, nil
}

// written reports whether segment seg has a non-zero nonce (preallocated,
// never written regions read as zeros).
func written(f *os.File, seg int64) bool {
	var nonce [nonceSize]byte
	if _, err := f.ReadAt(nonce[:], segOffset(seg)); err != nil {
		return false
	}
	return nonce != [nonceSize]byte{}
}

// Abort deletes the staging blob (a committed blob is left alone).
func (p *parted) Abort() error {
	_, _, err := p.s.remove(context.Background(), p.id, stateStaging)
	return err
}

// keyedMutex is a set of reader/writer mutexes keyed by string, created on
// demand and dropped when unused.
type keyedMutex struct {
	mu sync.Mutex
	m  map[string]*kmEntry
}

type kmEntry struct {
	mu sync.RWMutex
	n  int
}

// acquire returns the entry of key with its reference count raised.
func (k *keyedMutex) acquire(key string) *kmEntry {
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.m == nil {
		k.m = map[string]*kmEntry{}
	}
	e := k.m[key]
	if e == nil {
		e = &kmEntry{}
		k.m[key] = e
	}
	e.n++
	return e
}

// drop lowers the reference count of key's entry and forgets it when unused.
func (k *keyedMutex) drop(key string, e *kmEntry) {
	k.mu.Lock()
	defer k.mu.Unlock()
	e.n--
	if e.n == 0 {
		delete(k.m, key)
	}
}

// lock locks key exclusively and returns its unlock func.
func (k *keyedMutex) lock(key string) func() {
	e := k.acquire(key)
	e.mu.Lock()
	return func() {
		e.mu.Unlock()
		k.drop(key, e)
	}
}

// rlock locks key shared and returns its unlock func.
func (k *keyedMutex) rlock(key string) func() {
	e := k.acquire(key)
	e.mu.RLock()
	return func() {
		e.mu.RUnlock()
		k.drop(key, e)
	}
}
