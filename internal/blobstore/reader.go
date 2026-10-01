package blobstore

import (
	"crypto/cipher"
	"errors"
	"io"
	"os"
	"sync"

	"fileparcel/internal/core"
)

// reader is the core.BlobReader: O(1) mapping of plaintext offsets to
// segments (offset>>16, offset&0xFFFF), authenticated decryption of each
// segment, and a one-segment cache. It is safe for concurrent use
// (io.ReaderAt contract); calls are serialised.
type reader struct {
	mu     sync.Mutex
	f      *os.File
	id     string
	sc     *segCipher
	size   int64 // plaintext size P
	nseg   int64
	pos    int64
	cached int64  // index of the cached segment, -1 = none
	cache  []byte // plaintext of the cached segment
	raw    []byte // stored segment scratch
	closed bool
}

var _ core.BlobReader = (*reader)(nil)

// newReader checks the file size (stored size of P) and the header, then
// returns a reader. f is owned by the reader on success.
func newReader(f *os.File, id string, idRaw []byte, c core.CipherID, a cipher.AEAD, size int64) (*reader, error) {
	st, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if st.Size() != StoredSize(size) {
		return nil, corrupt("file size does not match its recorded size (truncated or extended)")
	}
	hb := make([]byte, headerSize)
	if _, err := f.ReadAt(hb, 0); err != nil {
		return nil, corrupt("header unreadable")
	}
	if err := checkHeader(hb, idRaw, c); err != nil {
		return nil, err
	}
	var h header
	copy(h[:], hb)
	r := &reader{f: f, id: id, sc: newSegCipher(a, &h), size: size, nseg: numSegments(size), cached: -1,
		cache: make([]byte, 0, segSize), raw: make([]byte, storedSegSize)}
	if size == 0 { // authenticate the single empty segment right away
		if _, err := r.segment(0); err != nil {
			return nil, err
		}
	}
	return r, nil
}

// ID returns the blob id.
func (r *reader) ID() string { return r.id }

// Size returns the plaintext size.
func (r *reader) Size() int64 { return r.size }

// segment returns the plaintext of segment i (cached).
func (r *reader) segment(i int64) ([]byte, error) {
	if i == r.cached {
		return r.cache, nil
	}
	l := segPlainLen(r.size, i) + segOverhead
	buf := r.raw[:l]
	if _, err := r.f.ReadAt(buf, segOffset(i)); err != nil {
		r.cached = -1
		if errors.Is(err, io.EOF) {
			return nil, corrupt("truncated")
		}
		return nil, err
	}
	pt, err := r.sc.open(i, i == r.nseg-1, buf, r.cache)
	if err != nil {
		r.cached = -1
		clear(r.cache[:cap(r.cache)])
		return nil, err
	}
	r.cache, r.cached = pt, i
	return pt, nil
}

// readAt is ReadAt without locking.
func (r *reader) readAt(p []byte, off int64) (int, error) {
	if r.closed {
		return 0, os.ErrClosed
	}
	if off < 0 {
		return 0, errors.New("blobstore: negative offset")
	}
	if off >= r.size {
		return 0, io.EOF
	}
	n := 0
	for n < len(p) && off < r.size {
		seg, err := r.segment(off >> segLog2)
		if err != nil {
			return n, err
		}
		c := copy(p[n:], seg[off&(segSize-1):])
		n += c
		off += int64(c)
	}
	if n < len(p) {
		return n, io.EOF
	}
	return n, nil
}

// ReadAt implements io.ReaderAt.
func (r *reader) ReadAt(p []byte, off int64) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.readAt(p, off)
}

// Read implements io.Reader.
func (r *reader) Read(p []byte) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(p) == 0 {
		if r.closed {
			return 0, os.ErrClosed
		}
		return 0, nil
	}
	n, err := r.readAt(p, r.pos)
	r.pos += int64(n)
	if n > 0 && err == io.EOF {
		err = nil
	}
	return n, err
}

// Seek implements io.Seeker (seeking past the end is allowed; reads there
// return io.EOF).
func (r *reader) Seek(offset int64, whence int) (int64, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return 0, os.ErrClosed
	}
	var abs int64
	switch whence {
	case io.SeekStart:
		abs = offset
	case io.SeekCurrent:
		abs = r.pos + offset
	case io.SeekEnd:
		abs = r.size + offset
	default:
		return 0, errors.New("blobstore: invalid whence")
	}
	if abs < 0 {
		return 0, errors.New("blobstore: negative position")
	}
	r.pos = abs
	return abs, nil
}

// Close zeroes the cached plaintext and closes the file.
func (r *reader) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return nil
	}
	r.closed = true
	clear(r.cache[:cap(r.cache)])
	r.cached = -1
	r.sc = nil
	return r.f.Close()
}
