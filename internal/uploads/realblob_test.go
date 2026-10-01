package uploads

// Integration tests of the upload protocol against the real encrypted blob
// store (and the real keyring), so that part sizes, streaming, digests and
// commits are exercised on the actual on-disk format.

import (
	"archive/zip"
	"bytes"
	"context"
	"io"
	"strings"
	"sync"
	"testing"

	"fileparcel/internal/blobstore"
	"fileparcel/internal/core"
	"fileparcel/internal/keys"
	"fileparcel/internal/uploads/uploadtest"
	"fileparcel/internal/ziputil/ziputiltest"
)

// setupReal is setup with a real blob store.
func setupReal(t *testing.T) (*fixture, *blobstore.Service) {
	t.Helper()
	e := uploadtest.New(t)
	e.Settings.Put("storage.fsync", false)
	// The fake keyring row would collide with the real keyring's active KEK.
	e.Exec(`DELETE FROM keyring WHERE id = ?`, uploadtest.KEKID)
	env := *e.Env
	ks, err := keys.Open(&env)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ks.Close() })
	if _, err := ks.Init(context.Background(), false, nil); err != nil {
		t.Fatal(err)
	}
	env.Keys = ks
	bs, err := blobstore.New(&env)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = bs.Close() })
	svc, err := New(&env, e.Files, bs, e.Jobs)
	if err != nil {
		t.Fatal(err)
	}
	svc.diskFree = func(string) (uint64, uint64, error) { return 1 << 50, 1 << 51, nil }
	f := &fixture{Env: e, t: t, svc: svc, ctx: context.Background(), shares: &recShares{}}
	f.alice, f.aliceRoot = e.User("alice", core.RoleMember)
	f.bob, f.bobRoot = e.User("bob", core.RoleMember)
	return f, bs
}

// realContent reads the current content of the file relPath below folder
// from the real blob store.
func realContent(f *fixture, bs *blobstore.Service, folder, name string) []byte {
	f.t.Helper()
	blob := f.Str(`SELECT v.blob_id FROM nodes n JOIN file_versions v ON v.id = n.version_id
		WHERE n.parent_id = ? AND n.name = ?`, folder, name)
	r, err := bs.Open(f.ctx, blob)
	if err != nil {
		f.t.Fatalf("open %s: %v", name, err)
	}
	defer r.Close()
	b, err := io.ReadAll(r)
	if err != nil {
		f.t.Fatal(err)
	}
	return b
}

func TestRealBlobPartedUpload(t *testing.T) {
	f, bs := setupReal(t)
	a := f.actor(f.alice)
	data := content(3*core.PartSize+5, 11)
	b := f.batch(a, core.BatchInput{FolderID: f.aliceRoot, Files: []core.UploadFileInput{
		{ClientRef: "big", RelPath: "big.bin", Size: int64(len(data))},
		{ClientRef: "empty", RelPath: "empty.txt", Size: 0},
		{ClientRef: "small", RelPath: "small.txt", Size: 11},
	}})
	up := refID(b, "big")

	// A broken transfer of part 2 first, then every part in parallel, out of
	// order, with a duplicate.
	p2 := part(data, 2)
	if err := f.svc.PutPart(f.ctx, a, up, 2, bytes.NewReader(p2[:1000]), int64(len(p2)), digest(p2)); err == nil {
		t.Fatal("short part accepted")
	}
	bad := bytes.Clone(p2)
	bad[5] ^= 0xff
	wantCode(t, f.svc.PutPart(f.ctx, a, up, 2, bytes.NewReader(bad), int64(len(bad)), digest(p2)), core.ErrInvalid)
	var wg sync.WaitGroup
	errs := make(chan error, 8)
	for _, n := range []int{3, 2, 0, 1, 3} {
		wg.Go(func() {
			p := part(data, n)
			errs <- f.svc.PutPart(f.ctx, a, up, n, bytes.NewReader(p), -1, digest(p))
		})
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("PutPart: %v", err)
		}
	}
	st, err := f.svc.CompleteFile(f.ctx, a, up)
	if err != nil || st.State != core.UploadCommitted {
		t.Fatalf("complete: %+v %v", st, err)
	}
	if got := realContent(f, bs, f.aliceRoot, "big.bin"); !bytes.Equal(got, data) {
		t.Fatal("big.bin differs")
	}
	if h := f.Str(`SELECT content_hash FROM nodes WHERE name = 'big.bin'`); h != uploadtest.ContentHash(data) {
		t.Fatalf("content hash %s", h)
	}
	f.small(a, b.ID, "empty", nil)
	f.small(a, b.ID, "small", []byte("small world"))
	if got := realContent(f, bs, f.aliceRoot, "empty.txt"); len(got) != 0 {
		t.Fatal("empty file not empty")
	}
	if got := realContent(f, bs, f.aliceRoot, "small.txt"); string(got) != "small world" {
		t.Fatalf("small.txt = %q", got)
	}
	if done := f.complete(a, b.ID); done.State != core.BatchDone {
		t.Fatalf("batch %+v", done)
	}
}

func TestRealBlobAbortAndZip(t *testing.T) {
	f, bs := setupReal(t)
	f.Jobs.Manual = true
	a := f.actor(f.alice)
	data := content(core.PartSize+9, 12)

	// Abort removes the staged parted blob from the store.
	b := f.batch(a, core.BatchInput{FolderID: f.aliceRoot, Files: []core.UploadFileInput{
		{ClientRef: "big", RelPath: "big.bin", Size: int64(len(data))}}})
	f.parts(a, refID(b, "big"), data, 1)
	blobID := f.Str(`SELECT blob_id FROM upload_files WHERE id = ?`, refID(b, "big"))
	if err := f.svc.AbortBatch(f.ctx, a, b.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := bs.Stat(f.ctx, blobID); err == nil {
		t.Fatal("staged blob survived the abort")
	}

	// Zip on upload with real blobs.
	z := f.batch(a, core.BatchInput{FolderID: f.aliceRoot, Mode: core.UploadModeZip, ZipName: "bundle",
		Files: []core.UploadFileInput{
			{ClientRef: "big", RelPath: "dir/big.bin", Size: int64(len(data))},
			{ClientRef: "s", RelPath: "dir/sub/s.txt", Size: 2},
			{ClientRef: "d", RelPath: "dir/void", Kind: "dir"},
		}})
	f.parts(a, refID(z, "big"), data, 0, 1)
	if _, err := f.svc.CompleteFile(f.ctx, a, refID(z, "big")); err != nil {
		t.Fatal(err)
	}
	f.small(a, z.ID, "s", []byte("hi"))
	fin := f.complete(a, z.ID)
	if err := f.Jobs.Run(fin.JobID); err != nil {
		t.Fatal(err)
	}
	zipData := realContent(f, bs, f.aliceRoot, "bundle.zip")
	zr, err := zip.NewReader(bytes.NewReader(zipData), int64(len(zipData)))
	if err != nil {
		t.Fatal(err)
	}
	want := map[string][]byte{"dir/big.bin": data, "dir/sub/s.txt": []byte("hi"), "dir/void/": nil}
	for _, zf := range zr.File {
		w, ok := want[zf.Name]
		if !ok {
			continue
		}
		delete(want, zf.Name)
		if zf.FileInfo().IsDir() {
			continue
		}
		rc, err := zf.Open()
		if err != nil {
			t.Fatal(err)
		}
		got, _ := io.ReadAll(rc)
		rc.Close()
		if !bytes.Equal(got, w) {
			t.Errorf("%s differs", zf.Name)
		}
	}
	if len(want) != 0 {
		t.Fatalf("missing zip entries: %v", want)
	}
	// Only the zip blob is left (staged blobs deleted).
	if n := f.Int(`SELECT COUNT(*) FROM blobs`); n != 1 {
		t.Fatalf("blobs rows = %d", n)
	}
}

// TestRealBlobProtectedZip builds protected zips from real encrypted blobs
// with the real keyring: the password is sealed by the field KEK, and large
// entries take the two-pass paths (ZipCrypto CRC, Deflate → Store fallback),
// which read the staged blobs at arbitrary offsets and probe past their end.
func TestRealBlobProtectedZip(t *testing.T) {
	for _, enc := range []string{core.ZipEncAES256, core.ZipEncZipCrypto} {
		t.Run(enc, func(t *testing.T) {
			f, bs := setupReal(t)
			f.Jobs.Manual = true
			a := f.actor(f.alice)
			big := content(core.PartSize+9, 13) // random: Deflate does not shrink it
			text := bytes.Repeat([]byte("protected text\n"), 400_000)[:5<<20+3]
			entries := []zipEntry{{rel: "dir/big.bin", data: big}, {rel: "dir/text.txt", data: text},
				{rel: "small.txt", data: []byte("hi")}, {rel: "dir", dir: true}}
			b := f.protectedBatch(a, "vault", enc, goodZipPW, entries)
			if sealed := f.sealedPW(b.ID); !strings.HasPrefix(sealed, "v1:kek_") {
				t.Fatalf("sealed value %q", sealed)
			}
			f.sendAll(a, b, entries)
			if _, err := f.runZip(a, b); err != nil {
				t.Fatalf("zip job: %v", err)
			}
			got, err := ziputiltest.ReadBytes(realContent(f, bs, f.aliceRoot, "vault.zip"), goodZipPW)
			if err != nil {
				t.Fatalf("read: %v", err)
			}
			files := 0
			for _, e := range got {
				if e.Dir {
					continue
				}
				files++
				var want []byte
				for _, w := range entries {
					if w.rel == e.Name {
						want = w.data
					}
				}
				if e.Encryption != enc || !bytes.Equal(e.Data, want) {
					t.Errorf("%s: encryption %q, %d bytes (want %d)", e.Name, e.Encryption, len(e.Data), len(want))
				}
			}
			if files != 3 || f.sealedPW(b.ID) != "" {
				t.Fatalf("%d files, sealed %q", files, f.sealedPW(b.ID))
			}
		})
	}
}
