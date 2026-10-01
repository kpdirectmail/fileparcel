package blobstore

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"math/rand/v2"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"fileparcel/internal/core"
)

func TestLayoutMath(t *testing.T) {
	for _, tc := range []struct {
		p       int64
		n       int64
		stored  int64
		parts   int
		lastLen int64
	}{
		{0, 1, 32 + 28, 0, 0},
		{1, 1, 32 + 1 + 28, 1, 1},
		{65535, 1, 32 + 65535 + 28, 1, 65535},
		{65536, 1, 32 + 65536 + 28, 1, 65536},
		{65537, 2, 32 + 65537 + 56, 1, 1},
		{core.PartSize, 128, 32 + core.PartSize + 128*28, 1, 65536},
		{core.PartSize + 1, 129, 32 + core.PartSize + 1 + 129*28, 2, 1},
	} {
		if numSegments(tc.p) != tc.n || StoredSize(tc.p) != tc.stored || partCount(tc.p) != tc.parts || segPlainLen(tc.p, tc.n-1) != tc.lastLen {
			t.Errorf("P=%d: N=%d stored=%d parts=%d last=%d", tc.p, numSegments(tc.p), StoredSize(tc.p), partCount(tc.p), segPlainLen(tc.p, tc.n-1))
		}
	}
	if segOffset(0) != 32 || segOffset(3) != 32+3*(65536+28) || segsPerPart != 128 {
		t.Fatal("offsets")
	}
	if HashOfDigests(nil) != "fp1:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" {
		t.Fatal("empty content hash must hash the empty concatenation")
	}
}

// TestRoundTripSizes covers the sizes of DESIGN §17 with both writers.
func TestRoundTripSizes(t *testing.T) {
	ts := newStore(t)
	r := rand.New(rand.NewPCG(uint64(os.Getpid()), 1))
	sizes := []int64{0, 1, 65535, 65536, 65537, core.PartSize - 1, core.PartSize, core.PartSize + 1, 3*core.PartSize + 5,
		1 + r.Int64N(64<<20)}
	if testing.Short() {
		sizes = sizes[:len(sizes)-1]
	}
	for i, size := range sizes {
		data := randData(size, uint64(i))
		for _, mode := range []string{"stream", "parted"} {
			var info *core.BlobInfo
			if mode == "stream" {
				info = ts.putStream(t, data)
			} else {
				info = ts.putParted(t, data)
			}
			if info.Size != size || info.StoredSize != StoredSize(size) || info.ContentHash != expectedHash(data) ||
				info.Cipher != ts.keys.Cipher() || !ts.clock.Now().Equal(info.CreatedAt) {
				t.Fatalf("%s %d: info %+v", mode, size, info)
			}
			st, err := ts.Stat(ctx, info.ID)
			if err != nil || *st != *info {
				t.Fatalf("%s %d: stat %+v %v", mode, size, st, err)
			}
			fi, err := os.Stat(filepath.Join(ts.h.BlobsDir(), info.ID[:2], info.ID[2:4], info.ID))
			if err != nil || fi.Size() != StoredSize(size) || fi.Mode().Perm() != 0o600 {
				t.Fatalf("%s %d: file %v %v", mode, size, fi, err)
			}
			got, err := ts.readAll(t, info.ID)
			if err != nil || !bytes.Equal(got, data) {
				t.Fatalf("%s %d: read back %d bytes, %v", mode, size, len(got), err)
			}
			if err := ts.Verify(ctx, info.ID); err != nil {
				t.Fatalf("%s %d: verify %v", mode, size, err)
			}
			rd, _ := ts.Open(ctx, info.ID)
			for range 20 {
				if size == 0 {
					break
				}
				off := r.Int64N(size)
				buf := make([]byte, 1+r.IntN(200000))
				n, err := rd.ReadAt(buf, off)
				want := data[off:min(off+int64(len(buf)), size)]
				if n != len(want) || !bytes.Equal(buf[:n], want) || (n < len(buf)) != (err == io.EOF) {
					t.Fatalf("%s %d: ReadAt(%d,%d) = %d %v", mode, size, off, len(buf), n, err)
				}
			}
			rd.Close()
		}
	}
}

func TestReaderSemantics(t *testing.T) {
	ts := newStore(t)
	data := randData(3*segSize+100, 3)
	info := ts.putStream(t, data)
	r, err := ts.Open(ctx, info.ID)
	if err != nil {
		t.Fatal(err)
	}
	if r.ID() != info.ID || r.Size() != int64(len(data)) {
		t.Fatal("id/size")
	}
	if n, err := r.Seek(-10, io.SeekEnd); err != nil || n != int64(len(data))-10 {
		t.Fatal(n, err)
	}
	b, _ := io.ReadAll(r)
	if !bytes.Equal(b, data[len(data)-10:]) {
		t.Fatal("tail")
	}
	if n, _ := r.Read(make([]byte, 5)); n != 0 {
		t.Fatal("read at EOF")
	}
	if _, err := r.Seek(-1, io.SeekStart); err == nil {
		t.Fatal("negative seek")
	}
	if _, err := r.Seek(0, 7); err == nil {
		t.Fatal("bad whence")
	}
	if p, _ := r.Seek(int64(len(data))+100, io.SeekStart); p != int64(len(data))+100 {
		t.Fatal("seek past end")
	}
	if _, err := r.Read(make([]byte, 1)); err != io.EOF {
		t.Fatalf("read past end: %v", err)
	}
	_, _ = r.Seek(segSize-3, io.SeekStart)
	_, _ = r.Seek(2, io.SeekCurrent)
	buf := make([]byte, 6)
	if _, err := io.ReadFull(r, buf); err != nil || !bytes.Equal(buf, data[segSize-1:segSize+5]) {
		t.Fatal("read across a boundary")
	}
	if _, err := r.ReadAt(buf, -1); err == nil {
		t.Fatal("negative ReadAt")
	}
	// concurrent ReadAt (io.ReaderAt contract)
	var wg sync.WaitGroup
	for g := range 8 {
		wg.Go(func() {
			rr := rand.New(rand.NewPCG(uint64(g), 9))
			for range 200 {
				off := rr.Int64N(int64(len(data)))
				p := make([]byte, 1+rr.IntN(70000))
				n, _ := r.ReadAt(p, off)
				if !bytes.Equal(p[:n], data[off:off+int64(n)]) {
					t.Error("concurrent ReadAt mismatch")
					return
				}
			}
		})
	}
	wg.Wait()
	if err := r.Close(); err != nil {
		t.Fatal(err)
	}
	if err := r.Close(); err != nil {
		t.Fatal("double close")
	}
	if _, err := r.Read(buf); !errors.Is(err, os.ErrClosed) {
		t.Fatalf("read after close: %v", err)
	}
	if _, err := r.ReadAt(buf, 0); !errors.Is(err, os.ErrClosed) {
		t.Fatalf("ReadAt after close: %v", err)
	}
	if _, err := r.Seek(0, io.SeekStart); !errors.Is(err, os.ErrClosed) {
		t.Fatalf("seek after close: %v", err)
	}
}

func TestWriterLifecycle(t *testing.T) {
	ts := newStore(t)
	w, err := ts.Create(ctx)
	if err != nil {
		t.Fatal(err)
	}
	id := w.(*writer).id
	if ts.state(t, id) != stateStaging {
		t.Fatal("staging row missing")
	}
	if _, err := ts.Stat(ctx, id); !isErr(err, core.ErrConflict) {
		t.Fatalf("stat staging: %v", err)
	}
	if _, err := ts.Open(ctx, id); !isErr(err, core.ErrNotFound) {
		t.Fatalf("open staging: %v", err)
	}
	_, _ = w.Write([]byte("hello"))
	if err := w.Abort(); err != nil {
		t.Fatal(err)
	}
	if ts.state(t, id) != "" {
		t.Fatal("row not removed by Abort")
	}
	if _, err := os.Stat(filepath.Join(ts.h.BlobsDir(), id[:2], id[2:4], id)); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("file not removed by Abort")
	}
	if _, err := w.Write([]byte("x")); err == nil {
		t.Fatal("write after abort")
	}
	if _, err := w.Commit(ctx); err == nil {
		t.Fatal("commit after abort")
	}
	if err := w.Abort(); err != nil {
		t.Fatal("double abort")
	}

	w, _ = ts.Create(ctx)
	_, _ = w.Write([]byte("data"))
	info, err := w.Commit(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Commit(ctx); err == nil {
		t.Fatal("double commit")
	}
	if err := w.Abort(); err != nil || ts.state(t, info.ID) != stateReady {
		t.Fatal("abort after commit must be a no-op")
	}
	if n := ts.count(t, `SELECT parts_done FROM blobs WHERE id = ?`, info.ID); n != 1 {
		t.Fatalf("parts_done %d", n)
	}
}

func TestPartedErrors(t *testing.T) {
	ts := newStore(t)
	_, err := ts.CreateParted(ctx, -1)
	errIs(t, err, core.ErrInvalid, "negative size")
	data := randData(2*core.PartSize+10, 5)
	p, err := ts.CreateParted(ctx, int64(len(data)))
	if err != nil {
		t.Fatal(err)
	}
	if p.PartCount() != 3 || p.Size() != int64(len(data)) || len(p.ID()) != 32 {
		t.Fatal("accessors")
	}
	part := func(n int) []byte { return data[n*core.PartSize : min((n+1)*core.PartSize, len(data))] }
	for _, n := range []int{-1, 3} {
		_, err := p.WritePart(ctx, n, bytes.NewReader(nil), nil)
		errIs(t, err, core.ErrInvalid, "part index")
	}
	_, err = p.WritePart(ctx, 0, bytes.NewReader(part(0)), []byte{1, 2})
	errIs(t, err, core.ErrInvalid, "bad digest length")
	_, err = p.WritePart(ctx, 0, bytes.NewReader(part(0)[:100]), nil)
	errIs(t, err, core.ErrInvalid, "short body")
	_, err = p.WritePart(ctx, 2, bytes.NewReader(append(bytes.Clone(part(2)), 'x')), nil)
	errIs(t, err, core.ErrInvalid, "long body")
	wrong := sha256.Sum256([]byte("nope"))
	got, err := p.WritePart(ctx, 1, bytes.NewReader(part(1)), wrong[:])
	errIs(t, err, core.ErrInvalid, "digest mismatch")
	if want := sha256.Sum256(part(1)); !bytes.Equal(got, want[:]) {
		t.Fatal("mismatch must return the computed digest")
	}
	_, err = p.WritePart(ctx, 0, errReader{}, nil)
	if err == nil || isErr(err, core.ErrInvalid) {
		t.Fatalf("reader error: %v", err)
	}
	cctx, cancel := contextWithCancel()
	cancel()
	if _, err := p.WritePart(cctx, 0, bytes.NewReader(part(0)), nil); err == nil {
		t.Fatal("canceled context")
	}
	_, err = p.Commit(ctx, [][]byte{got})
	errIs(t, err, core.ErrInvalid, "digest count")
	_, err = p.Commit(ctx, [][]byte{got, got, {1}})
	errIs(t, err, core.ErrInvalid, "digest length")
	// part 0 and 2 never completely written
	d := partDigests(data)
	_, err = p.Commit(ctx, d)
	errIs(t, err, core.ErrPrecondition, "missing parts")

	// resume with a fresh handle
	p2, err := ts.OpenParted(ctx, p.ID())
	if err != nil {
		t.Fatal(err)
	}
	for _, n := range []int{2, 0} {
		if _, err := p2.WritePart(ctx, n, bytes.NewReader(part(n)), d[n]); err != nil {
			t.Fatal(err)
		}
	}
	info, err := p2.Commit(ctx, d)
	if err != nil {
		t.Fatal(err)
	}
	if again, err := p.Commit(ctx, d); err != nil || again.ContentHash != info.ContentHash {
		t.Fatalf("idempotent commit: %v", err)
	}
	d2 := partDigests(data)
	d2[0] = wrong[:]
	_, err = p.Commit(ctx, d2)
	errIs(t, err, core.ErrConflict, "commit with other digests")
	_, err = p.WritePart(ctx, 0, bytes.NewReader(part(0)), nil)
	errIs(t, err, core.ErrConflict, "write after commit")
	_, err = ts.OpenParted(ctx, p.ID())
	errIs(t, err, core.ErrConflict, "open committed")
	if err := p.Abort(); err != nil || ts.state(t, p.ID()) != stateReady {
		t.Fatal("abort must not delete a committed blob")
	}
	if got, _ := ts.readAll(t, p.ID()); !bytes.Equal(got, data) {
		t.Fatal("content")
	}
	for _, bad := range []string{"", "zz", strings.Repeat("A", 32), "../../../../etc/passwd", strings.Repeat("0", 31) + "/"} {
		_, err = ts.OpenParted(ctx, bad)
		errIs(t, err, core.ErrNotFound, "OpenParted("+bad+")")
	}

	// abort of a staging parted blob removes everything
	p3, _ := ts.CreateParted(ctx, 10)
	if err := p3.Abort(); err != nil || ts.state(t, p3.ID()) != "" {
		t.Fatal("abort staging")
	}
	_, err = ts.OpenParted(ctx, p3.ID())
	errIs(t, err, core.ErrNotFound, "open aborted")
	_, err = p3.WritePart(ctx, 0, bytes.NewReader(make([]byte, 10)), nil)
	errIs(t, err, core.ErrNotFound, "write aborted")
	_, err = p3.Commit(ctx, [][]byte{make([]byte, 32)})
	errIs(t, err, core.ErrNotFound, "commit aborted")
}

type errReader struct{}

func (errReader) Read([]byte) (int, error) { return 0, errors.New("connection reset") }

// TestPartedOutOfOrderWithRetries writes parts in parallel, in random
// order, with failed attempts, wrong digests and duplicate writes.
func TestPartedOutOfOrderWithRetries(t *testing.T) {
	ts := newStore(t)
	data := randData(5*core.PartSize+12345, 11)
	p, err := ts.CreateParted(ctx, int64(len(data)))
	if err != nil {
		t.Fatal(err)
	}
	digests := partDigests(data)
	order := rand.Perm(p.PartCount())
	var wg sync.WaitGroup
	for i, n := range order {
		part := data[n*core.PartSize : min((n+1)*core.PartSize, len(data))]
		wg.Go(func() {
			// a broken first attempt: half the body, then a network error
			_, _ = p.WritePart(ctx, n, io.MultiReader(bytes.NewReader(part[:len(part)/2]), errReader{}), digests[n])
			// a corrupted upload is detected by the digest
			bad := bytes.Clone(part)
			bad[len(bad)/3] ^= 0x55
			if _, err := p.WritePart(ctx, n, bytes.NewReader(bad), digests[n]); !isErr(err, core.ErrInvalid) {
				t.Errorf("part %d: corrupted body accepted: %v", n, err)
			}
			// the retry, sometimes twice (idempotent), racing with itself
			tries := 1 + i%2
			var inner sync.WaitGroup
			for range tries {
				inner.Go(func() {
					got, err := p.WritePart(ctx, n, bytes.NewReader(part), digests[n])
					if err != nil || !bytes.Equal(got, digests[n]) {
						t.Errorf("part %d: %v", n, err)
					}
				})
			}
			inner.Wait()
		})
	}
	wg.Wait()
	info, err := p.Commit(ctx, digests)
	if err != nil {
		t.Fatal(err)
	}
	if info.ContentHash != expectedHash(data) {
		t.Fatal("content hash")
	}
	got, err := ts.readAll(t, info.ID)
	if err != nil || !bytes.Equal(got, data) {
		t.Fatalf("read back: %v", err)
	}
	if err := ts.Verify(ctx, info.ID); err != nil {
		t.Fatal(err)
	}
}

// gatedReader serves data after gate is closed, signalling started first.
type gatedReader struct {
	r       io.Reader
	started chan struct{}
	gate    chan struct{}
	once    sync.Once
}

func (g *gatedReader) Read(p []byte) (int, error) {
	g.once.Do(func() { close(g.started); <-g.gate })
	return g.r.Read(p)
}

// TestPartedCommitWaitsForInFlightParts: Commit waits for a part that is
// still being (re)written, and a part sent after Commit is refused instead
// of changing committed data.
func TestPartedCommitWaitsForInFlightParts(t *testing.T) {
	ts := newStore(t)
	data := randData(core.PartSize+777, 13)
	digests := partDigests(data)
	p, err := ts.CreateParted(ctx, int64(len(data)))
	if err != nil {
		t.Fatal(err)
	}
	for n := range p.PartCount() {
		part := data[n*core.PartSize : min((n+1)*core.PartSize, len(data))]
		if _, err := p.WritePart(ctx, n, bytes.NewReader(part), digests[n]); err != nil {
			t.Fatal(err)
		}
	}
	// A retry of part 1 is in flight (its body is slow to arrive).
	g := &gatedReader{r: bytes.NewReader(data[core.PartSize:]), started: make(chan struct{}), gate: make(chan struct{})}
	retry := make(chan error, 1)
	go func() {
		_, err := p.WritePart(ctx, 1, g, digests[1])
		retry <- err
	}()
	<-g.started
	committed := make(chan error, 1)
	go func() {
		_, err := p.Commit(ctx, digests)
		committed <- err
	}()
	select {
	case err := <-committed:
		t.Fatalf("commit finished while a part was being written: %v", err)
	case <-time.After(100 * time.Millisecond):
	}
	close(g.gate)
	if err := <-retry; err != nil {
		t.Fatalf("in-flight retry: %v", err)
	}
	if err := <-committed; err != nil {
		t.Fatalf("commit: %v", err)
	}
	evil := bytes.Repeat([]byte{'x'}, len(data)-core.PartSize)
	_, err = p.WritePart(ctx, 1, bytes.NewReader(evil), nil)
	errIs(t, err, core.ErrConflict, "write after commit")
	if got, err := ts.readAll(t, p.ID()); err != nil || !bytes.Equal(got, data) {
		t.Fatalf("content changed after commit: %v", err)
	}
	if err := ts.Verify(ctx, p.ID()); err != nil {
		t.Fatal(err)
	}
}

func TestKeyedMutex(t *testing.T) {
	var k keyedMutex
	var mu sync.Mutex
	inside := map[string]int{}
	var wg sync.WaitGroup
	for i := range 64 {
		key := []string{"a", "b"}[i%2]
		wg.Go(func() {
			unlock := k.lock(key)
			mu.Lock()
			inside[key]++
			if inside[key] != 1 {
				t.Errorf("%s: %d holders of an exclusive lock", key, inside[key])
			}
			mu.Unlock()
			time.Sleep(time.Millisecond)
			mu.Lock()
			inside[key]--
			mu.Unlock()
			unlock()
		})
		wg.Go(func() {
			unlock := k.rlock(key + "r")
			time.Sleep(time.Millisecond)
			unlock()
		})
	}
	wg.Wait()
	if len(k.m) != 0 {
		t.Fatalf("entries left: %v", k.m)
	}
}

func TestChaChaPath(t *testing.T) {
	ts := newStore(t)
	ts.settings.set("storage.cipher", "chacha20-poly1305")
	data := randData(200000, 21)
	for _, info := range []*core.BlobInfo{ts.putStream(t, data), ts.putParted(t, data)} {
		if info.Cipher != core.CipherChaCha20Poly1305 {
			t.Fatalf("cipher %d", info.Cipher)
		}
		hdr := make([]byte, 8)
		f, _ := os.Open(filepath.Join(ts.h.BlobsDir(), info.ID[:2], info.ID[2:4], info.ID))
		_, _ = f.ReadAt(hdr, 0)
		f.Close()
		if string(hdr[:4]) != "FPB1" || hdr[4] != 1 || hdr[5] != 2 || hdr[6] != 16 || hdr[7] != 0 {
			t.Fatalf("header % x", hdr)
		}
		if got, err := ts.readAll(t, info.ID); err != nil || !bytes.Equal(got, data) {
			t.Fatal(err)
		}
	}
	// Readers honour the header's cipher: an AES blob stays readable after
	// switching the setting.
	ts.settings.set("storage.cipher", "aes-gcm")
	aes := ts.putStream(t, data)
	ts.settings.set("storage.cipher", "chacha20-poly1305")
	if got, err := ts.readAll(t, aes.ID); err != nil || !bytes.Equal(got, data) || aes.Cipher != core.CipherAES256GCM {
		t.Fatal(err)
	}
}

func TestFsyncOff(t *testing.T) {
	ts := newStore(t)
	ts.settings.set("storage.fsync", false)
	if ts.fsyncEnabled() {
		t.Fatal("setting ignored")
	}
	data := randData(core.PartSize+3, 4)
	for _, info := range []*core.BlobInfo{ts.putStream(t, data), ts.putParted(t, data)} {
		if got, _ := ts.readAll(t, info.ID); !bytes.Equal(got, data) {
			t.Fatal("content")
		}
	}
	ts.settings.set("storage.fsync", true)
	if !ts.fsyncEnabled() {
		t.Fatal("fsync on")
	}
}

func TestKeysLocked(t *testing.T) {
	ts := newStore(t)
	info := ts.putStream(t, []byte("before lock"))
	p, _ := ts.CreateParted(ctx, 5)
	lk := &lockedKeys{Keys: ts.keys, locked: true}
	ts.env.Keys = lk
	_, err := ts.Create(ctx)
	errIs(t, err, core.ErrKeysLocked, "Create")
	_, err = ts.CreateParted(ctx, 1)
	errIs(t, err, core.ErrKeysLocked, "CreateParted")
	_, err = ts.Open(ctx, info.ID)
	errIs(t, err, core.ErrKeysLocked, "Open")
	_, err = p.WritePart(ctx, 0, bytes.NewReader([]byte("12345")), nil)
	errIs(t, err, core.ErrKeysLocked, "WritePart")
	errIs(t, ts.Verify(ctx, info.ID), core.ErrKeysLocked, "Verify")
	_, err = ts.Reencrypt(ctx, info.ID)
	errIs(t, err, core.ErrKeysLocked, "Reencrypt")
	// metadata operations work without keys
	if _, err := ts.Stat(ctx, info.ID); err != nil {
		t.Fatal(err)
	}
	if _, _, err := ts.GC(ctx, 0); err != nil {
		t.Fatal(err)
	}
	if err := ts.Delete(ctx, info.ID); err != nil {
		t.Fatal(err)
	}
	ts.env.Keys = nil
	_, err = ts.Create(ctx)
	errIs(t, err, core.ErrKeysLocked, "no keys")
}

func TestDelete(t *testing.T) {
	ts := newStore(t)
	a := ts.putStream(t, []byte("a"))
	b := ts.putParted(t, []byte("b"))
	ts.reference(t, a.ID)
	errIs(t, ts.Delete(ctx, a.ID), core.ErrConflict, "referenced blob")
	if ts.state(t, a.ID) != stateReady {
		t.Fatal("referenced blob touched")
	}
	if got, _ := ts.readAll(t, a.ID); string(got) != "a" {
		t.Fatal("referenced blob damaged")
	}
	if err := ts.Delete(ctx, b.ID); err != nil {
		t.Fatal(err)
	}
	if ts.state(t, b.ID) != "" {
		t.Fatal("row left")
	}
	if _, err := os.Stat(filepath.Join(ts.h.BlobsDir(), b.ID[:2], b.ID[2:4], b.ID)); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("file left")
	}
	if err := ts.Delete(ctx, b.ID); err != nil {
		t.Fatal("delete of a missing blob must be a no-op")
	}
	errIs(t, ts.Delete(ctx, "../x"), core.ErrNotFound, "invalid id")
	_, err := ts.Stat(ctx, b.ID)
	errIs(t, err, core.ErrNotFound, "stat deleted")
	_, err = ts.Open(ctx, b.ID)
	errIs(t, err, core.ErrNotFound, "open deleted")
	_, err = ts.Stat(ctx, "nope")
	errIs(t, err, core.ErrNotFound, "stat invalid")
	_, err = ts.Open(ctx, strings.ToUpper(a.ID))
	errIs(t, err, core.ErrNotFound, "uppercase id")
}

func TestReencrypt(t *testing.T) {
	ts := newStore(t)
	data := randData(3*segSize+17, 8)
	old := ts.putStream(t, data)
	newID, err := ts.Reencrypt(ctx, old.ID)
	if err != nil {
		t.Fatal(err)
	}
	if newID == old.ID {
		t.Fatal("same id")
	}
	got, err := ts.readAll(t, newID)
	if err != nil || !bytes.Equal(got, data) {
		t.Fatal(err)
	}
	var w1, w2 []byte
	_ = ts.db.QueryRow(ctx, `SELECT wrapped_dek FROM blobs WHERE id = ?`, old.ID).Scan(&w1)
	_ = ts.db.QueryRow(ctx, `SELECT wrapped_dek FROM blobs WHERE id = ?`, newID).Scan(&w2)
	if bytes.Equal(w1, w2) {
		t.Fatal("DEK reused")
	}
	st, _ := ts.Stat(ctx, newID)
	if st.ContentHash != old.ContentHash {
		t.Fatal("content hash")
	}
	if ts.state(t, old.ID) != stateReady {
		t.Fatal("old blob is removed by the caller, not by Reencrypt")
	}
	// The new blob uses the currently selected cipher; the empty blob works.
	ts.settings.set("storage.cipher", "chacha20-poly1305")
	for _, src := range []*core.BlobInfo{old, ts.putStream(t, nil)} {
		id, err := ts.Reencrypt(ctx, src.ID)
		if err != nil {
			t.Fatal(err)
		}
		st, _ := ts.Stat(ctx, id)
		if st.Cipher != core.CipherChaCha20Poly1305 || st.ContentHash != src.ContentHash || st.Size != src.Size {
			t.Fatalf("re-encrypted %+v from %+v", st, src)
		}
	}
	// A corrupted source is refused and leaves no new blob behind.
	before := ts.count(t, `SELECT count(*) FROM blobs`)
	flipByte(t, ts, old.ID, segOffset(1)+100)
	_, err = ts.Reencrypt(ctx, old.ID)
	errIs(t, err, core.ErrCorrupt, "corrupted source")
	if ts.count(t, `SELECT count(*) FROM blobs`) != before {
		t.Fatal("partial re-encryption left behind")
	}
	_, err = ts.Reencrypt(ctx, "0123456789abcdef0123456789abcdef")
	errIs(t, err, core.ErrNotFound, "missing")
}

func TestVerify(t *testing.T) {
	ts := newStore(t)
	info := ts.putParted(t, randData(core.PartSize+99, 12))
	if err := ts.Verify(ctx, info.ID); err != nil {
		t.Fatal(err)
	}
	if ts.count(t, `SELECT count(*) FROM blobs WHERE id = ? AND verified_at IS NOT NULL`, info.ID) != 1 {
		t.Fatal("verified_at not set")
	}
	ts.exec(t, `UPDATE blobs SET content_hash = ? WHERE id = ?`, "fp1:"+strings.Repeat("0", 64), info.ID)
	errIs(t, ts.Verify(ctx, info.ID), core.ErrCorrupt, "content hash mismatch")
	ts.exec(t, `UPDATE blobs SET content_hash = ? WHERE id = ?`, info.ContentHash, info.ID)
	flipByte(t, ts, info.ID, StoredSize(info.Size)-1)
	errIs(t, ts.Verify(ctx, info.ID), core.ErrCorrupt, "tampered tag")
	cctx, cancel := contextWithCancel()
	cancel()
	if err := ts.Verify(cctx, info.ID); err == nil {
		t.Fatal("canceled verify")
	}
}

func flipByte(t testing.TB, ts *testStore, id string, off int64) {
	t.Helper()
	path := filepath.Join(ts.h.BlobsDir(), id[:2], id[2:4], id)
	f, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	b := make([]byte, 1)
	if _, err := f.ReadAt(b, off); err != nil {
		t.Fatal(err)
	}
	b[0] ^= 0x01
	if _, err := f.WriteAt(b, off); err != nil {
		t.Fatal(err)
	}
}

func TestDiskErrorMapping(t *testing.T) {
	if !isErr(diskErr(os.NewSyscallError("write", errNoSpace())), core.ErrQuota) {
		t.Fatal("ENOSPC must map to 507")
	}
	if !isErr(diskErr(os.NewSyscallError("write", syscall.EDQUOT)), core.ErrQuota) {
		t.Fatal("EDQUOT (disk quota exhausted) must map to 507")
	}
	if isErr(diskErr(errors.New("x")), core.ErrQuota) {
		t.Fatal("other errors")
	}
}

func TestNewErrors(t *testing.T) {
	if _, err := New(nil); err == nil {
		t.Fatal("nil env")
	}
	if _, err := New(&core.Env{}); err == nil {
		t.Fatal("env without home")
	}
	ts := newStore(t)
	// data/blobs is a file: the store cannot be opened.
	h := ts.h
	if err := os.RemoveAll(h.BlobsDir()); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(h.BlobsDir(), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := New(ts.env); err == nil {
		t.Fatal("blobs dir is a file")
	}
}

// TestFailurePaths covers cleanup after failures: an unwritable store,
// a blob removed under an open writer, inconsistent parted blobs.
func TestFailurePaths(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("permissions are not enforced for root")
	}
	ts := newStore(t)
	// Unwritable storage: nothing may be left behind.
	if err := os.Chmod(ts.h.BlobsDir(), 0o500); err != nil {
		t.Fatal(err)
	}
	_, err := ts.Create(ctx)
	_, err2 := ts.CreateParted(ctx, 10)
	_ = os.Chmod(ts.h.BlobsDir(), 0o700)
	if err == nil || err2 == nil {
		t.Fatalf("unwritable store: %v %v", err, err2)
	}
	if n := ts.count(t, `SELECT count(*) FROM blobs`); n != 0 {
		t.Fatalf("%d rows left after failed creates", n)
	}

	// The blob is deleted while a writer is still open: Commit fails, and
	// only Abort is accepted afterwards.
	w, err := ts.Create(ctx)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = w.Write([]byte("data"))
	id := w.(*writer).id
	if err := ts.Delete(ctx, id); err != nil {
		t.Fatal(err)
	}
	_, err = w.Commit(ctx)
	errIs(t, err, core.ErrConflict, "commit of a deleted blob")
	if _, err := w.Commit(ctx); err == nil {
		t.Fatal("second commit after failure")
	}
	if _, err := w.Write([]byte("x")); err == nil {
		t.Fatal("write after failed commit")
	}
	if err := w.Abort(); err != nil {
		t.Fatal(err)
	}

	// A streaming staging blob is not a parted blob.
	w, _ = ts.Create(ctx)
	_, err = ts.OpenParted(ctx, w.(*writer).id)
	errIs(t, err, core.ErrConflict, "OpenParted of a streaming blob")
	_ = w.Abort()

	// Parted blob whose file vanished or was damaged.
	data := randData(segSize+10, 77)
	p, _ := ts.CreateParted(ctx, int64(len(data)))
	d := partDigests(data)
	if _, err := p.WritePart(ctx, 0, bytes.NewReader(data), d[0]); err != nil {
		t.Fatal(err)
	}
	orig := ts.readFile(t, p.ID())
	ts.writeFile(t, p.ID(), orig[:len(orig)-1])
	_, err = p.Commit(ctx, d)
	errIs(t, err, core.ErrCorrupt, "commit with a short file")
	bad := bytes.Clone(orig)
	bad[5] ^= 1 // cipher byte
	ts.writeFile(t, p.ID(), bad)
	_, err = p.Commit(ctx, d)
	errIs(t, err, core.ErrCorrupt, "commit with a damaged header")
	if err := os.Remove(ts.blobFile(p.ID())); err != nil {
		t.Fatal(err)
	}
	_, err = ts.OpenParted(ctx, p.ID())
	errIs(t, err, core.ErrNotFound, "OpenParted without file")
	_, err = p.WritePart(ctx, 0, bytes.NewReader(data), d[0])
	errIs(t, err, core.ErrNotFound, "WritePart without file")
	_, err = p.Commit(ctx, d)
	errIs(t, err, core.ErrNotFound, "Commit without file")
	if err := p.Abort(); err != nil || ts.state(t, p.ID()) != "" {
		t.Fatalf("abort without file: %v", err)
	}
}

// TestHashOfDigests checks the content hash against an independent
// computation for streamed and parted blobs of several parts.
func TestHashOfDigests(t *testing.T) {
	h := newContentHasher()
	data := randData(2*core.PartSize+3, 13)
	for off := 0; off < len(data); off += 777777 {
		_, _ = h.Write(data[off:min(off+777777, len(data))])
	}
	a, b := sha256.Sum256(data[:core.PartSize]), sha256.Sum256(data[core.PartSize:2*core.PartSize])
	c := sha256.Sum256(data[2*core.PartSize:])
	outer := sha256.Sum256(append(append(a[:], b[:]...), c[:]...))
	want := "fp1:" + hex.EncodeToString(outer[:])
	if got := h.Sum(); got != want || HashOfDigests([][]byte{a[:], b[:], c[:]}) != want {
		t.Fatalf("content hash %s, want %s", got, want)
	}
}

// TestPartedCommitRejectsInteriorHole: Commit must check every segment of
// every part, not just the first and the last. An interior segment that was
// never written (preallocated zeros, or lost after a crash with
// storage.fsync=false) used to pass, and the blob was marked ready with a
// content hash it does not have — the damage only surfaced on the first
// download.
func TestPartedCommitRejectsInteriorHole(t *testing.T) {
	ts := newStore(t)
	data := randData(core.PartSize+segSize+10, 31)
	p, err := ts.CreateParted(ctx, int64(len(data)))
	if err != nil {
		t.Fatal(err)
	}
	d := partDigests(data)
	for n := range p.PartCount() {
		part := data[n*core.PartSize : min((n+1)*core.PartSize, len(data))]
		if _, err := p.WritePart(ctx, n, bytes.NewReader(part), d[n]); err != nil {
			t.Fatal(err)
		}
	}
	// Punch out an interior segment of part 0 (neither its first nor its
	// last), exactly as a never-written region reads back.
	const hole = 60
	raw := ts.readFile(t, p.ID())
	clear(raw[segOffset(hole) : segOffset(hole)+storedSegSize])
	ts.writeFile(t, p.ID(), raw)

	_, err = p.Commit(ctx, d)
	errIs(t, err, core.ErrPrecondition, "commit with an unwritten interior segment")
	if st := ts.state(t, p.ID()); st != "staging" {
		t.Fatalf("state %q after the refused commit, want staging", st)
	}
	// Rewriting the part repairs it and the blob commits and reads back.
	if _, err := p.WritePart(ctx, 0, bytes.NewReader(data[:core.PartSize]), d[0]); err != nil {
		t.Fatal(err)
	}
	if _, err := p.Commit(ctx, d); err != nil {
		t.Fatal(err)
	}
	got, err := ts.readAll(t, p.ID())
	if err != nil || !bytes.Equal(got, data) {
		t.Fatalf("read back after the repaired commit: %v", err)
	}
}
