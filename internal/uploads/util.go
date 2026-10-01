package uploads

import (
	"context"
	"crypto/sha256"
	"errors"
	"hash"
	"io"
	"math"
	"net/http"
	"strconv"
	"sync"

	"fileparcel/internal/core"
)

// keyLock is an in-process lock per key (upload file, part). Lock waits
// until the key is free or ctx is done. Entries are reference counted and
// removed when unused, so memory stays bounded by the number of waiters.
type keyLock struct {
	mu sync.Mutex
	m  map[string]*lockEntry
}

type lockEntry struct {
	ch   chan struct{}
	refs int
}

// Lock acquires key and returns the unlock func (call exactly once).
func (l *keyLock) Lock(ctx context.Context, key string) (func(), error) {
	l.mu.Lock()
	if l.m == nil {
		l.m = map[string]*lockEntry{}
	}
	e := l.m[key]
	if e == nil {
		e = &lockEntry{ch: make(chan struct{}, 1)}
		l.m[key] = e
	}
	e.refs++
	l.mu.Unlock()

	select {
	case e.ch <- struct{}{}:
		var once sync.Once
		return func() {
			once.Do(func() {
				<-e.ch
				l.release(key, e)
			})
		}, nil
	case <-ctx.Done():
		l.release(key, e)
		return nil, ctx.Err()
	}
}

func (l *keyLock) release(key string, e *lockEntry) {
	l.mu.Lock()
	e.refs--
	if e.refs == 0 && l.m[key] == e {
		delete(l.m, key)
	}
	l.mu.Unlock()
}

// size returns the number of tracked keys (tests).
func (l *keyLock) size() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.m)
}

// bodyReader reads exactly want bytes from r while hashing them. It returns
// io.ErrUnexpectedEOF (and records short) when r ends early, and records
// the first read error of r so that client-side failures (disconnects,
// oversized bodies) can be told apart from storage errors.
type bodyReader struct {
	r         io.Reader
	remaining int64
	h         hash.Hash
	short     bool
	readErr   error
}

func newBodyReader(r io.Reader, want int64) *bodyReader {
	if r == nil {
		r = http.NoBody
	}
	return &bodyReader{r: r, remaining: want, h: sha256.New()}
}

// Read implements io.Reader.
func (b *bodyReader) Read(p []byte) (int, error) {
	if b.remaining <= 0 {
		return 0, io.EOF
	}
	if int64(len(p)) > b.remaining {
		p = p[:b.remaining]
	}
	n, err := b.r.Read(p)
	if n > 0 {
		b.h.Write(p[:n])
		b.remaining -= int64(n)
	}
	switch {
	case err == io.EOF:
		if b.remaining > 0 {
			b.short = true
			b.readErr = io.ErrUnexpectedEOF
			return n, io.ErrUnexpectedEOF
		}
		return n, io.EOF
	case err != nil:
		if b.readErr == nil {
			b.readErr = err
		}
		return n, err
	}
	return n, nil
}

// complete reports whether every expected byte was read.
func (b *bodyReader) complete() bool { return b.remaining == 0 }

// sum returns the SHA-256 of the bytes read so far.
func (b *bodyReader) sum() []byte { return b.h.Sum(nil) }

// trailing reports whether r does not end cleanly after the expected bytes
// (only possible for bodies without a Content-Length): more data follows,
// or the read fails with anything but io.EOF — e.g. *http.MaxBytesError
// when the extra data exceeds the request body limit.
func (b *bodyReader) trailing() bool {
	var one [1]byte
	for range 64 { // bounded: a reader returning (0, nil) forever must not hang us
		n, err := b.r.Read(one[:])
		if n > 0 {
			return true
		}
		if err != nil {
			if err != io.EOF && b.readErr == nil {
				b.readErr = err
			}
			return err != io.EOF
		}
	}
	return true
}

// trailingError is the error for a body that does not end after the
// expected bytes: 413 when it exceeded the body limit, 422 otherwise.
func (b *bodyReader) trailingError(msg string) error {
	var mbe *http.MaxBytesError
	if errors.As(b.readErr, &mbe) {
		return core.ErrTooLarge
	}
	return core.Invalid("body", msg)
}

// clientError maps a failed body read to the error sent to the client, or
// returns nil when the body was read fine (the failure is elsewhere).
func (b *bodyReader) clientError(want int64) error {
	if b.readErr == nil {
		return nil
	}
	var mbe *http.MaxBytesError
	switch {
	case b.short:
		return core.Invalid("body", "the request body ended early (expected "+strconv.FormatInt(want, 10)+" bytes); please retry")
	case errors.As(b.readErr, &mbe):
		return core.ErrTooLarge
	case errors.Is(b.readErr, context.Canceled), errors.Is(b.readErr, context.DeadlineExceeded):
		return b.readErr
	}
	return core.Wrap(core.ErrInvalid, "could not read the request body; please retry", b.readErr)
}

// partLen returns the plaintext length of part n of a file of size bytes.
func partLen(size int64, n int) int64 {
	off := int64(n) * core.PartSize
	if off >= size {
		return 0
	}
	return min(core.PartSize, size-off)
}

// twice doubles n without wrapping: a zip batch stages the parts and the
// zip at the same time, so its disk need is twice its declared size.
func twice(n int64) int64 {
	if n > math.MaxInt64/2 {
		return math.MaxInt64
	}
	return n * 2
}

// addSat adds two non-negative amounts without wrapping.
func addSat(a, b int64) int64 {
	if a > math.MaxInt64-b {
		return math.MaxInt64
	}
	return a + b
}

// Bounds of what the zip upload.zip builds (archive/zip through ziputil)
// adds to the data it holds. They are deliberately generous: the zip is
// stored as one file, and these bounds decide up front whether it will fit
// the space quota and the per-file limits — a zip refused at commit fails
// the batch and deletes every staged file.
const (
	// zipFileOverhead: local header 30, central directory record 46, zip64
	// data descriptor 24, the extended-timestamp extra in both headers 2×9,
	// zip64 extras 20 + 28, and the empty final block (5) that ends a
	// Deflate stream.
	zipFileOverhead = 30 + 46 + 24 + 2*9 + 20 + 28 + 5
	// zipDirOverhead: the same without a data descriptor and Deflate.
	zipDirOverhead = 30 + 46 + 2*9 + 20 + 28
	// zipNameSlack covers what ziputil may add to a name (the " (n)" of a
	// de-duplicated name, the "/" of a directory); the name is in both headers.
	zipNameSlack = 16
	// zipDeflateBlock: Deflate never shrinks incompressible data; it stores
	// it in blocks with a 5-byte header. The encoder's blocks hold up to
	// 64 KiB (and at least 16 KiB but the last); one header per 16 KiB is
	// the safe bound.
	zipDeflateBlock = 16 << 10
	// zipEndOverhead: end of central directory 22, zip64 end record 56 and
	// zip64 end locator 20, once per zip.
	zipEndOverhead = 22 + 56 + 20
)

// zipEntryOverhead bounds the bytes one batch entry adds to the zip beyond
// its data. Every file is counted as Deflated: whether ziputil stores or
// deflates it depends on a setting that may change before the zip is built.
func zipEntryOverhead(relPath, kind string, size int64) int64 {
	name := 2 * int64(len(relPath)+zipNameSlack)
	if kind == core.UploadKindDir {
		return zipDirOverhead + name
	}
	return zipFileOverhead + name + 5*(max(size, 0)/zipDeflateBlock+1)
}

// zipOverhead bounds the bytes validated entries add to a zip beyond their
// data (without the end records).
func zipOverhead(entries []entry) int64 {
	var n int64
	for i := range entries {
		n = addSat(n, zipEntryOverhead(entries[i].relPath, entries[i].kind, entries[i].size))
	}
	return n
}

// partCount returns the number of parts of a file (1 for empty files).
func partCount(size int64) int {
	if size <= 0 {
		return 1
	}
	return int((size + core.PartSize - 1) / core.PartSize)
}
