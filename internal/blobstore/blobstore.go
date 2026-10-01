// Package blobstore stores file contents as encrypted, segmented blobs under
// data/blobs/ab/cd/<32hex> (DESIGN §7.3): streaming and parted writers,
// random-access readers (http.ServeContent compatible), verify, GC and
// re-encryption. Owned by unit A.
//
// Every blob has a row in the blobs table with a small state machine:
// staging (being written) → ready (committed); deleting marks a blob whose
// file is being removed (Delete, Abort and GC finish it). The row is always
// inserted before the file is created and the file is always removed before
// the row, so a file without a row is garbage left by a crash.
//
// The storage directory is accessed through an os.Root opened on data/blobs;
// file paths are derived only from validated 32-hex blob IDs. Each blob has
// its own random DEK, wrapped by the keys service and stored only in the
// row, so deleting the row crypto-shreds the blob. Operations that encrypt
// or decrypt return core.ErrKeysLocked while the keys are locked; any
// authentication failure is core.ErrCorrupt.
//
// The daily maintenance.blob_gc job belongs to package files, which calls
// GC and then sweeps committed blobs that nothing references.
package blobstore

import (
	"context"
	"crypto/cipher"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"time"

	"fileparcel/internal/core"
	"fileparcel/internal/crypt"
	"fileparcel/internal/db"
	"fileparcel/internal/ids"
)

// Service implements core.BlobStore.
type Service struct {
	env  *core.Env
	log  *slog.Logger
	root *os.Root // data/blobs

	dirs      sync.Map   // "ab/cd" → struct{}: fan-out dirs known to exist durably
	partLocks keyedMutex // "<id>/<n>": serialises writes of the same part
	blobLocks keyedMutex // "<id>": WritePart (shared) vs parted Commit (exclusive)
	active    sync.Map   // blob id → struct{}: open streaming writers (GC skips them)

	// gcFloor is the minimum age GC applies to staging/ready/orphan blobs,
	// whatever minAge the caller passes (protects in-flight writes).
	gcFloor time.Duration

	closeOnce sync.Once
}

var _ core.BlobStore = (*Service)(nil)

// Blob row states.
const (
	stateStaging  = "staging"
	stateReady    = "ready"
	stateDeleting = "deleting"
)

const defaultGCFloor = 15 * time.Minute

// New creates the service (constructor signature fixed by DESIGN §5.2). It
// creates data/blobs (0700) if needed and opens it as an os.Root.
func New(env *core.Env) (*Service, error) {
	if env == nil || env.Home == nil || env.DB == nil {
		return nil, errors.New("blobstore: environment needs Home and DB")
	}
	log := env.Log
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	dir := env.Home.BlobsDir()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("blobstore: %w", err)
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		return nil, fmt.Errorf("blobstore: %w", err)
	}
	return &Service{env: env, log: log.With("svc", "blobstore"), root: root, gcFloor: defaultGCFloor}, nil
}

// Close releases the storage directory handle (io.Closer).
func (s *Service) Close() error {
	var err error
	s.closeOnce.Do(func() { err = s.root.Close() })
	return err
}

// ---------- helpers ----------

// blobPaths returns the fan-out directory ("ab/cd") and the relative file
// path ("ab/cd/<id>") of a validated blob id.
func blobPaths(id string) (dir, rel string, err error) {
	if !ids.ValidBlobID(id) {
		return "", "", core.NotFoundf("blob not found")
	}
	dir = filepath.Join(id[0:2], id[2:4])
	return dir, filepath.Join(dir, id), nil
}

func idBytes(id string) []byte {
	b, _ := hex.DecodeString(id)
	return b
}

// keys returns the keys service when unlocked.
func (s *Service) keys() (core.Keys, error) {
	k := s.env.Keys
	if k == nil || k.State() != core.KeyStateUnlocked {
		return nil, core.ErrKeysLocked
	}
	return k, nil
}

// fsyncEnabled reads storage.fsync (default true).
func (s *Service) fsyncEnabled() bool {
	st := s.env.Settings
	if st == nil {
		return true
	}
	if _, err := st.Raw(settingFsync); err != nil {
		return true
	}
	return st.Bool(settingFsync)
}

// ensureDir creates the fan-out directory of a blob and, the first time it
// is used in this process, fsyncs its parents so the entries are durable.
func (s *Service) ensureDir(dir string) error {
	if _, ok := s.dirs.Load(dir); ok {
		return nil
	}
	if err := s.root.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	if s.fsyncEnabled() {
		if err := s.syncDir(filepath.Dir(dir)); err != nil {
			return err
		}
		if err := s.syncDir("."); err != nil {
			return err
		}
	}
	s.dirs.Store(dir, struct{}{})
	return nil
}

// syncDir fsyncs a directory inside the root.
func (s *Service) syncDir(dir string) error {
	d, err := s.root.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	if err := d.Sync(); err != nil && !errors.Is(err, os.ErrInvalid) {
		return err
	}
	return nil
}

// newAEAD builds the blob cipher from a DEK.
func newAEAD(c core.CipherID, dek []byte) (cipher.AEAD, error) {
	if c != core.CipherAES256GCM && c != core.CipherChaCha20Poly1305 {
		return nil, corrupt(fmt.Sprintf("uses unknown cipher %d", c))
	}
	return crypt.NewAEAD(uint8(c), dek)
}

// blobRow is one row of the blobs table.
type blobRow struct {
	id, state, kekID string
	size             int64
	stored           sql.NullInt64
	cipher           core.CipherID
	segLog2          int
	wrapped          []byte
	contentHash      sql.NullString
	createdAt        int64
}

func (r *blobRow) info() *core.BlobInfo {
	return &core.BlobInfo{ID: r.id, Size: r.size, StoredSize: StoredSize(r.size), ContentHash: r.contentHash.String,
		Cipher: r.cipher, CreatedAt: db.FromMs(r.createdAt)}
}

type rowQuerier interface {
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
}

type readerPool struct{ d *db.DB }

func (r readerPool) QueryRowContext(ctx context.Context, q string, a ...any) *sql.Row {
	return r.d.QueryRow(ctx, q, a...)
}

// loadRow reads a blob row (ErrNotFound when missing).
func (s *Service) loadRow(ctx context.Context, q rowQuerier, id string) (*blobRow, error) {
	if q == nil {
		q = readerPool{s.env.DB}
	}
	var r blobRow
	var c int64
	err := q.QueryRowContext(ctx, `SELECT id, state, size, stored_size, cipher, seg_log2, kek_id, wrapped_dek, content_hash, created_at
		FROM blobs WHERE id = ?`, id).Scan(&r.id, &r.state, &r.size, &r.stored, &c, &r.segLog2, &r.kekID, &r.wrapped, &r.contentHash, &r.createdAt)
	if db.IsNoRows(err) {
		return nil, core.NotFoundf("blob not found")
	}
	if err != nil {
		return nil, err
	}
	r.cipher = core.CipherID(c)
	return &r, nil
}

// newBlob creates the staging row and the file of a new blob (header
// written; the file is returned open for writing). size < 0 means unknown
// (streaming). The DEK is returned for the caller to zero.
func (s *Service) newBlob(ctx context.Context, size int64) (id string, idRaw, dek []byte, c core.CipherID, f *os.File, created time.Time, err error) {
	k, err := s.keys()
	if err != nil {
		return
	}
	id = ids.NewBlobID()
	idRaw = idBytes(id)
	c = k.Cipher()
	dek, wrapped, kekID, err := k.NewDEK(idRaw)
	if err != nil {
		return
	}
	dir, rel, _ := blobPaths(id)
	created = s.env.Now()
	rowSize, stored := int64(0), sql.NullInt64{}
	if size >= 0 {
		rowSize, stored = size, sql.NullInt64{Int64: StoredSize(size), Valid: true}
	}
	_, err = s.env.DB.Exec(ctx, `INSERT INTO blobs (id, state, size, stored_size, cipher, seg_log2, kek_id, wrapped_dek, parts_done, created_at)
		VALUES (?, 'staging', ?, ?, ?, ?, ?, ?, 0, ?)`, id, rowSize, stored, int64(c), segLog2, kekID, wrapped, db.Ms(created))
	if err != nil {
		crypt.Zero(dek)
		dek = nil
		err = fmt.Errorf("blobstore: insert blob: %w", err)
		return
	}
	fail := func(e error) {
		if f != nil {
			_ = f.Close()
			_ = s.root.Remove(rel)
			f = nil
		}
		_, _ = s.env.DB.Exec(context.WithoutCancel(ctx), `DELETE FROM blobs WHERE id = ? AND state = 'staging'`, id)
		crypt.Zero(dek)
		dek = nil
		err = e
	}
	if e := s.ensureDir(dir); e != nil {
		fail(fmt.Errorf("blobstore: %w", e))
		return
	}
	f, e := s.root.OpenFile(rel, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0o600)
	if e != nil {
		fail(fmt.Errorf("blobstore: %w", e))
		return
	}
	h := makeHeader(c, idRaw)
	if _, e := f.WriteAt(h[:], 0); e != nil {
		fail(diskErr(e))
		return
	}
	return id, idRaw, dek, c, f, created, nil
}

// diskErr maps "no space left" to a 507 error.
func diskErr(err error) error {
	if isNoSpace(err) {
		return core.Wrap(core.ErrQuota, "not enough free disk space", err)
	}
	return fmt.Errorf("blobstore: %w", err)
}

// remove deletes a blob: mark it deleting (only if its state is one of
// from), remove the file, delete the row. It returns whether a row was
// removed and the bytes freed. Blobs still referenced by file_versions are
// never removed (ErrConflict).
func (s *Service) remove(ctx context.Context, id string, from ...string) (bool, int64, error) {
	_, rel, err := blobPaths(id)
	if err != nil {
		return false, 0, err
	}
	marked := false
	err = s.env.DB.Tx(ctx, func(tx *sql.Tx) error {
		marked = false
		var state string
		err := tx.QueryRowContext(ctx, `SELECT state FROM blobs WHERE id = ?`, id).Scan(&state)
		if db.IsNoRows(err) {
			return nil
		}
		if err != nil {
			return err
		}
		if !contains(from, state) {
			return nil
		}
		var refs int64
		if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM file_versions WHERE blob_id = ?`, id).Scan(&refs); err != nil {
			return err
		}
		if refs > 0 {
			return core.Errorf(core.ErrConflict, "the blob is still referenced by %d file versions", refs)
		}
		if _, err := tx.ExecContext(ctx, `UPDATE blobs SET state = 'deleting' WHERE id = ?`, id); err != nil {
			return err
		}
		marked = true
		return nil
	})
	if err != nil || !marked {
		return false, 0, err
	}
	return s.finishDelete(ctx, id, rel)
}

// finishDelete removes the file of a blob in state deleting, then its row.
func (s *Service) finishDelete(ctx context.Context, id, rel string) (bool, int64, error) {
	var freed int64
	if st, err := s.root.Stat(rel); err == nil {
		freed = st.Size()
	}
	if err := s.root.Remove(rel); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return false, 0, fmt.Errorf("blobstore: remove %s: %w", id, err)
	}
	if s.fsyncEnabled() {
		dir, _, _ := blobPaths(id)
		_ = s.syncDir(dir)
	}
	res, err := s.env.DB.Exec(context.WithoutCancel(ctx), `DELETE FROM blobs WHERE id = ? AND state = 'deleting'`, id)
	if err != nil {
		return false, freed, fmt.Errorf("blobstore: delete row %s: %w", id, err)
	}
	n, _ := res.RowsAffected()
	return n == 1, freed, nil
}

func contains(list []string, v string) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}

// ---------- core.BlobStore ----------

// Create starts a streaming blob of unknown size (see core.BlobWriter). The
// caller must Commit or Abort it.
func (s *Service) Create(ctx context.Context) (core.BlobWriter, error) {
	id, idRaw, dek, c, f, created, err := s.newBlob(ctx, -1)
	if err != nil {
		return nil, err
	}
	a, err := newAEAD(c, dek)
	crypt.Zero(dek)
	if err != nil {
		_ = f.Close()
		_, _, _ = s.remove(context.WithoutCancel(ctx), id, stateStaging)
		return nil, err
	}
	s.active.Store(id, struct{}{})
	return newWriter(s, id, idRaw, c, a, f, created), nil
}

// CreateParted starts a blob of declared size written in PartSize parts
// (see core.PartedBlob). The file is preallocated to its stored size.
func (s *Service) CreateParted(ctx context.Context, size int64) (core.PartedBlob, error) {
	if size < 0 {
		return nil, core.Invalid("size", "size must not be negative")
	}
	id, idRaw, dek, c, f, created, err := s.newBlob(ctx, size)
	if err != nil {
		return nil, err
	}
	defer crypt.Zero(dek)
	fail := func(e error) (core.PartedBlob, error) {
		_ = f.Close()
		_, _, _ = s.remove(context.WithoutCancel(ctx), id, stateStaging)
		return nil, e
	}
	if err := preallocate(f, StoredSize(size)); err != nil {
		return fail(diskErr(err))
	}
	if size == 0 { // the single, empty, final segment
		a, err := newAEAD(c, dek)
		if err != nil {
			return fail(err)
		}
		h := makeHeader(c, idRaw)
		seg := newSegCipher(a, &h).seal(0, true, nil, make([]byte, 0, segOverhead))
		if _, err := f.WriteAt(seg, segOffset(0)); err != nil {
			return fail(diskErr(err))
		}
	}
	if s.fsyncEnabled() {
		if err := f.Sync(); err != nil {
			return fail(diskErr(err))
		}
		dir, _, _ := blobPaths(id)
		if err := s.syncDir(dir); err != nil {
			return fail(fmt.Errorf("blobstore: %w", err))
		}
	}
	if err := f.Close(); err != nil {
		return fail(diskErr(err))
	}
	return &parted{s: s, id: id, idRaw: idRaw, size: size, cipher: c, created: created}, nil
}

// OpenParted resumes a staging parted blob. A committed blob returns
// ErrConflict, an unknown or deleted one ErrNotFound.
func (s *Service) OpenParted(ctx context.Context, blobID string) (core.PartedBlob, error) {
	_, rel, err := blobPaths(blobID)
	if err != nil {
		return nil, err
	}
	r, err := s.loadRow(ctx, nil, blobID)
	if err != nil {
		return nil, err
	}
	switch r.state {
	case stateReady:
		return nil, core.Errorf(core.ErrConflict, "the blob is already committed")
	case stateDeleting:
		return nil, core.NotFoundf("blob not found")
	}
	if !r.stored.Valid || r.segLog2 != segLog2 {
		return nil, core.Errorf(core.ErrConflict, "the blob is not a parted blob")
	}
	if _, err := s.root.Stat(rel); err != nil {
		return nil, core.NotFoundf("blob file not found")
	}
	return &parted{s: s, id: r.id, idRaw: idBytes(r.id), size: r.size, cipher: r.cipher, created: db.FromMs(r.createdAt)}, nil
}

// Open opens a committed blob for random-access reading. The file size must
// match the size recorded in the database and the header must name this
// blob and its cipher (core.ErrCorrupt otherwise).
func (s *Service) Open(ctx context.Context, blobID string) (core.BlobReader, error) {
	_, rel, err := blobPaths(blobID)
	if err != nil {
		return nil, err
	}
	k, err := s.keys()
	if err != nil {
		return nil, err
	}
	r, err := s.loadRow(ctx, nil, blobID)
	if err != nil {
		return nil, err
	}
	if r.state != stateReady {
		return nil, core.NotFoundf("blob not found")
	}
	if r.segLog2 != segLog2 {
		return nil, corrupt(fmt.Sprintf("has unsupported segment size 2^%d", r.segLog2))
	}
	idRaw := idBytes(r.id)
	dek, err := k.UnwrapDEK(idRaw, r.kekID, r.wrapped)
	if err != nil {
		return nil, err
	}
	a, err := newAEAD(r.cipher, dek)
	crypt.Zero(dek)
	if err != nil {
		return nil, err
	}
	f, err := s.root.Open(rel)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, corrupt("file is missing")
	}
	if err != nil {
		return nil, fmt.Errorf("blobstore: %w", err)
	}
	rd, err := newReader(f, r.id, idRaw, r.cipher, a, r.size)
	if err != nil {
		_ = f.Close()
		return nil, err
	}
	return rd, nil
}

// Stat returns the info of a committed blob (ErrNotFound when missing or
// deleted, ErrConflict while it is still being written).
func (s *Service) Stat(ctx context.Context, blobID string) (*core.BlobInfo, error) {
	if !ids.ValidBlobID(blobID) {
		return nil, core.NotFoundf("blob not found")
	}
	r, err := s.loadRow(ctx, nil, blobID)
	if err != nil {
		return nil, err
	}
	switch r.state {
	case stateReady:
		return r.info(), nil
	case stateStaging:
		return nil, core.Errorf(core.ErrConflict, "the blob is still being written")
	}
	return nil, core.NotFoundf("blob not found")
}

// Delete marks a blob deleting, removes its file and deletes its row
// (crypto-shredding it). Deleting a missing blob is a no-op; a blob still
// referenced by a file version returns ErrConflict.
func (s *Service) Delete(ctx context.Context, blobID string) error {
	if !ids.ValidBlobID(blobID) {
		return core.NotFoundf("blob not found")
	}
	_, _, err := s.remove(ctx, blobID, stateStaging, stateReady, stateDeleting)
	return err
}
