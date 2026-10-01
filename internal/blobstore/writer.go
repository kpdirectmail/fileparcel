package blobstore

import (
	"context"
	"crypto/cipher"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"sync"
	"time"

	"fileparcel/internal/core"
)

// writer is the streaming core.BlobWriter: it buffers one segment and
// writes it as soon as more data arrives (so the last segment can be
// marked final on Commit).
type writer struct {
	mu      sync.Mutex
	s       *Service
	id      string
	c       core.CipherID
	sc      *segCipher
	f       *os.File
	created time.Time

	buf  []byte // plaintext of the pending segment
	out  []byte // scratch for the sealed segment
	seg  int64  // index of the pending segment
	size int64  // plaintext bytes written
	hash *contentHasher
	err  error // sticky write error
	done bool  // committed or aborted
}

var _ core.BlobWriter = (*writer)(nil)

var errWriterDone = errors.New("blobstore: writer already committed or aborted")

func newWriter(s *Service, id string, idRaw []byte, c core.CipherID, a cipher.AEAD, f *os.File, created time.Time) *writer {
	h := makeHeader(c, idRaw)
	return &writer{s: s, id: id, c: c, sc: newSegCipher(a, &h), f: f, created: created,
		buf: make([]byte, 0, segSize), out: make([]byte, 0, storedSegSize), hash: newContentHasher()}
}

// Write implements io.Writer.
func (w *writer) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.done {
		return 0, errWriterDone
	}
	if w.err != nil {
		return 0, w.err
	}
	n := 0
	for len(p) > 0 {
		if len(w.buf) == segSize {
			if err := w.flush(false); err != nil {
				w.err = err
				return n, err
			}
		}
		c := min(len(p), segSize-len(w.buf))
		w.buf = append(w.buf, p[:c]...)
		w.hash.Write(p[:c])
		w.size += int64(c)
		n += c
		p = p[c:]
	}
	return n, nil
}

// flush encrypts and writes the pending segment.
func (w *writer) flush(final bool) error {
	sealed := w.sc.seal(w.seg, final, w.buf, w.out)
	if _, err := w.f.WriteAt(sealed, segOffset(w.seg)); err != nil {
		return diskErr(err)
	}
	clear(w.buf)
	w.buf = w.buf[:0]
	w.seg++
	return nil
}

// Commit writes the final segment, fsyncs the file and its directory
// (storage.fsync) and marks the blob ready. After a failed Commit the
// writer only accepts Abort.
func (w *writer) Commit(ctx context.Context) (*core.BlobInfo, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.done {
		return nil, errWriterDone
	}
	if w.err != nil {
		return nil, w.err
	}
	if err := w.flush(true); err != nil {
		w.err = err
		return nil, err
	}
	stored := StoredSize(w.size)
	if st, err := w.f.Stat(); err != nil || st.Size() != stored {
		w.err = fmt.Errorf("blobstore: blob %s has an unexpected size", w.id)
		return nil, w.err
	}
	if w.s.fsyncEnabled() {
		if err := w.f.Sync(); err != nil {
			w.err = diskErr(err)
			return nil, w.err
		}
	}
	if err := w.f.Close(); err != nil {
		w.f = nil
		w.err = diskErr(err)
		return nil, w.err
	}
	w.f = nil
	if w.s.fsyncEnabled() {
		dir, _, _ := blobPaths(w.id)
		if err := w.s.syncDir(dir); err != nil {
			w.err = fmt.Errorf("blobstore: %w", err)
			return nil, w.err
		}
	}
	hash := w.hash.Sum()
	var n int64
	err := w.s.env.DB.Tx(ctx, func(tx *sql.Tx) error {
		res, err := tx.ExecContext(ctx, `UPDATE blobs SET state = 'ready', size = ?, stored_size = ?, content_hash = ?,
			parts_done = ? WHERE id = ? AND state = 'staging'`, w.size, stored, hash, partCount(w.size), w.id)
		if err != nil {
			return err
		}
		n, _ = res.RowsAffected()
		return nil
	})
	if err != nil {
		// The file is closed and its last segment sealed: the writer
		// cannot be committed again, only aborted.
		w.err = fmt.Errorf("blobstore: commit %s: %w", w.id, err)
		return nil, w.err
	}
	if n != 1 {
		w.err = core.Errorf(core.ErrConflict, "the blob was removed before it was committed")
		return nil, w.err
	}
	w.done = true
	w.release()
	return &core.BlobInfo{ID: w.id, Size: w.size, StoredSize: stored, ContentHash: hash, Cipher: w.c, CreatedAt: w.created}, nil
}

// Abort deletes the staging blob (no-op after a successful Commit).
func (w *writer) Abort() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.done {
		return nil
	}
	w.done = true
	if w.f != nil {
		_ = w.f.Close()
		w.f = nil
	}
	w.release()
	_, _, err := w.s.remove(context.Background(), w.id, stateStaging)
	return err
}

// release drops buffers and the GC protection.
func (w *writer) release() {
	clear(w.buf[:cap(w.buf)])
	w.buf, w.out, w.sc = nil, nil, nil
	w.s.active.Delete(w.id)
}
