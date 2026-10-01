package blobstore

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"fileparcel/internal/core"
	"fileparcel/internal/ids"
)

// blobFile returns the on-disk path of a blob.
func (ts *testStore) blobFile(id string) string {
	return filepath.Join(ts.h.BlobsDir(), id[:2], id[2:4], id)
}

// readFile / writeFile access a blob file directly.
func (ts *testStore) readFile(t testing.TB, id string) []byte {
	t.Helper()
	b, err := os.ReadFile(ts.blobFile(id))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func (ts *testStore) writeFile(t testing.TB, id string, b []byte) {
	t.Helper()
	if err := os.WriteFile(ts.blobFile(id), b, 0o600); err != nil {
		t.Fatal(err)
	}
}

// fullRead opens a blob and reads it completely; it returns the first error.
func (ts *testStore) fullRead(id string) ([]byte, error) {
	r, err := ts.Open(ctx, id)
	if err != nil {
		return nil, err
	}
	defer r.Close()
	return io.ReadAll(r)
}

// segmentReadable reports whether segment i of blob id authenticates
// (reads one byte inside it with ReadAt).
func (ts *testStore) segmentReadable(t testing.TB, id string, i int64) error {
	t.Helper()
	r, err := ts.Open(ctx, id)
	if err != nil {
		return err
	}
	defer r.Close()
	_, err = r.ReadAt(make([]byte, 1), i*segSize)
	return err
}

// TestTamperMatrix covers every tampering of DESIGN §17: bit flips in each
// segment (nonce, ciphertext, tag), every header byte, truncation,
// extension, segment swap, blob swap, a wrong DEK and inconsistent rows.
// Every case must fail with core.ErrCorrupt and never return
// unauthenticated plaintext.
func TestTamperMatrix(t *testing.T) {
	ts := newStore(t)
	const size = 3*segSize + 1000 // 4 segments, short final segment
	data := randData(size, 42)

	mustCorrupt := func(t *testing.T, id, what string) {
		t.Helper()
		got, err := ts.fullRead(id)
		if !isErr(err, core.ErrCorrupt) {
			t.Fatalf("%s: read: %v", what, err)
		}
		if len(got) > 0 && !bytes.Equal(got, data[:len(got)]) {
			t.Fatalf("%s: returned unauthenticated plaintext", what)
		}
		errIs(t, ts.Verify(ctx, id), core.ErrCorrupt, what+": verify")
		_, err = ts.Reencrypt(ctx, id)
		errIs(t, err, core.ErrCorrupt, what+": reencrypt")
	}

	t.Run("segment bit flips", func(t *testing.T) {
		for i := int64(0); i < numSegments(size); i++ {
			plen := segPlainLen(size, i)
			for _, region := range []struct {
				name string
				off  int64
			}{{"nonce", 3}, {"ciphertext", nonceSize + plen/2}, {"tag", nonceSize + plen + 7}} {
				info := ts.putStream(t, data)
				flipByte(t, ts, info.ID, segOffset(i)+region.off)
				what := region.name
				mustCorrupt(t, info.ID, what)
				// Authentication is per segment: the others stay readable.
				for j := int64(0); j < numSegments(size); j++ {
					err := ts.segmentReadable(t, info.ID, j)
					if (j == i) != isErr(err, core.ErrCorrupt) || (j != i && err != nil) {
						t.Fatalf("flip in segment %d (%s): segment %d → %v", i, what, j, err)
					}
				}
			}
		}
	})

	t.Run("header bytes", func(t *testing.T) {
		info := ts.putStream(t, data)
		orig := ts.readFile(t, info.ID)
		for i := range headerSize {
			b := bytes.Clone(orig)
			b[i] ^= 0x80
			ts.writeFile(t, info.ID, b)
			_, err := ts.Open(ctx, info.ID)
			errIs(t, err, core.ErrCorrupt, "header byte")
		}
		ts.writeFile(t, info.ID, orig)
		if got, err := ts.fullRead(info.ID); err != nil || !bytes.Equal(got, data) {
			t.Fatal("restored file must read again")
		}
	})

	t.Run("truncation", func(t *testing.T) {
		info := ts.putStream(t, data)
		orig := ts.readFile(t, info.ID)
		for _, cut := range []int{1, segOverhead, 1000 + segOverhead, len(orig) - headerSize, len(orig)} {
			ts.writeFile(t, info.ID, orig[:len(orig)-cut])
			mustCorrupt(t, info.ID, "truncated file")
		}
		// Drop the final segment and make the row agree: the new last
		// segment was not sealed as final.
		ts.writeFile(t, info.ID, orig[:StoredSize(3*segSize)])
		ts.exec(t, `UPDATE blobs SET size = ?, stored_size = ? WHERE id = ?`, 3*segSize, StoredSize(3*segSize), info.ID)
		mustCorrupt(t, info.ID, "dropped final segment")
		if err := ts.segmentReadable(t, info.ID, 0); err != nil {
			t.Fatalf("earlier segments stay readable: %v", err)
		}
	})

	t.Run("extension", func(t *testing.T) {
		full := randData(3*segSize, 43) // final segment is full
		info := ts.putStream(t, full)
		orig := ts.readFile(t, info.ID)
		ts.writeFile(t, info.ID, append(bytes.Clone(orig), 0))
		_, err := ts.Open(ctx, info.ID)
		errIs(t, err, core.ErrCorrupt, "one extra byte")
		// Append a copy of segment 1 and make the row agree: the old final
		// segment is now read as non-final and the copy has index 1.
		seg1 := orig[segOffset(1):segOffset(2)]
		ts.writeFile(t, info.ID, append(bytes.Clone(orig), seg1...))
		ts.exec(t, `UPDATE blobs SET size = ?, stored_size = ? WHERE id = ?`, 4*segSize, StoredSize(4*segSize), info.ID)
		for _, i := range []int64{2, 3} {
			errIs(t, ts.segmentReadable(t, info.ID, i), core.ErrCorrupt, "extended segment")
		}
	})

	t.Run("segment swap", func(t *testing.T) {
		info := ts.putStream(t, data)
		b := ts.readFile(t, info.ID)
		s0 := bytes.Clone(b[segOffset(0):segOffset(1)])
		copy(b[segOffset(0):], b[segOffset(1):segOffset(2)])
		copy(b[segOffset(1):], s0)
		ts.writeFile(t, info.ID, b)
		mustCorrupt(t, info.ID, "segment swap")
		for _, i := range []int64{0, 1} {
			errIs(t, ts.segmentReadable(t, info.ID, i), core.ErrCorrupt, "swapped segment")
		}
		if err := ts.segmentReadable(t, info.ID, 2); err != nil {
			t.Fatalf("untouched segment: %v", err)
		}
	})

	t.Run("blob swap", func(t *testing.T) {
		a, b := ts.putStream(t, data), ts.putStream(t, data)
		fb := ts.readFile(t, b.ID)
		ts.writeFile(t, a.ID, fb)
		_, err := ts.Open(ctx, a.ID)
		errIs(t, err, core.ErrCorrupt, "other blob's file")
		// Even with a's header patched in, every segment was sealed with
		// b's header in its AAD (and under b's DEK).
		fa := bytes.Clone(fb)
		idRaw, _ := ids.BlobIDBytes(a.ID)
		copy(fa[8:24], idRaw)
		ts.writeFile(t, a.ID, fa)
		mustCorrupt(t, a.ID, "patched header")
	})

	t.Run("wrong DEK", func(t *testing.T) {
		a, b := ts.putStream(t, data), ts.putStream(t, data)
		// b's wrapped DEK in a's row: bound to b's id → unwrap fails.
		var wb []byte
		var kb string
		if err := ts.db.QueryRow(ctx, `SELECT wrapped_dek, kek_id FROM blobs WHERE id = ?`, b.ID).Scan(&wb, &kb); err != nil {
			t.Fatal(err)
		}
		ts.exec(t, `UPDATE blobs SET wrapped_dek = ?, kek_id = ? WHERE id = ?`, wb, kb, a.ID)
		mustCorrupt(t, a.ID, "wrapped DEK of another blob")
		// A validly wrapped but different DEK for a: segments fail.
		idRaw, _ := ids.BlobIDBytes(a.ID)
		_, w, k, err := ts.keys.NewDEK(idRaw)
		if err != nil {
			t.Fatal(err)
		}
		ts.exec(t, `UPDATE blobs SET wrapped_dek = ?, kek_id = ? WHERE id = ?`, w, k, a.ID)
		if _, err := ts.Open(ctx, a.ID); err != nil {
			t.Fatalf("open with a wrong DEK must succeed (header ok): %v", err)
		}
		mustCorrupt(t, a.ID, "wrong DEK")
		// A KEK of another purpose (kek_id has a foreign key, so an unknown
		// id cannot even be stored).
		ts.exec(t, `UPDATE blobs SET kek_id = (SELECT id FROM keyring WHERE purpose = 'field') WHERE id = ?`, a.ID)
		mustCorrupt(t, a.ID, "field KEK")
	})

	t.Run("inconsistent row", func(t *testing.T) {
		other := map[core.CipherID]core.CipherID{core.CipherAES256GCM: core.CipherChaCha20Poly1305, core.CipherChaCha20Poly1305: core.CipherAES256GCM}
		for name, q := range map[string]string{
			"size smaller": `UPDATE blobs SET size = size - 1 WHERE id = ?`,
			"size larger":  `UPDATE blobs SET size = size + 1 WHERE id = ?`,
			"cipher":       `UPDATE blobs SET cipher = ` + strconv.Itoa(int(other[ts.keys.Cipher()])) + ` WHERE id = ?`,
			"seg_log2":     `UPDATE blobs SET seg_log2 = 20 WHERE id = ?`,
			"bad cipher":   `UPDATE blobs SET cipher = 9 WHERE id = ?`,
		} {
			info := ts.putStream(t, data)
			ts.exec(t, q, info.ID)
			_, err := ts.Open(ctx, info.ID)
			errIs(t, err, core.ErrCorrupt, name)
		}
		info := ts.putStream(t, data)
		if err := os.Remove(ts.blobFile(info.ID)); err != nil {
			t.Fatal(err)
		}
		_, err := ts.Open(ctx, info.ID)
		errIs(t, err, core.ErrCorrupt, "missing file")
	})

	t.Run("empty blob", func(t *testing.T) {
		info := ts.putStream(t, nil)
		flipByte(t, ts, info.ID, headerSize+nonceSize) // the tag of the only segment
		_, err := ts.Open(ctx, info.ID)
		errIs(t, err, core.ErrCorrupt, "empty blob tag")
	})
}

// FuzzTamper flips arbitrary bits anywhere in a stored blob: reading it
// completely must always fail with core.ErrCorrupt.
func FuzzTamper(f *testing.F) {
	ts := newStore(f)
	data := randData(2*segSize+100, 9)
	info := ts.putStream(f, data)
	orig := ts.readFile(f, info.ID)
	for _, pos := range []uint32{0, 7, headerSize, headerSize + nonceSize, uint32(segOffset(1)) - 1, uint32(segOffset(2)) + 50, uint32(len(orig)) - 1} {
		f.Add(pos, uint8(1))
	}
	f.Fuzz(func(t *testing.T, pos uint32, mask uint8) {
		if mask == 0 {
			mask = 0x40
		}
		b := bytes.Clone(orig)
		b[int(pos)%len(b)] ^= mask
		ts.writeFile(t, info.ID, b)
		defer ts.writeFile(t, info.ID, orig)
		got, err := ts.fullRead(info.ID)
		if !isErr(err, core.ErrCorrupt) {
			t.Fatalf("flip at %d: %v", int(pos)%len(b), err)
		}
		if !bytes.Equal(got, data[:len(got)]) {
			t.Fatal("unauthenticated plaintext returned")
		}
	})
}
