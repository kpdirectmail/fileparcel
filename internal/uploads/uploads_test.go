package uploads

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"io"
	"math/rand/v2"
	"strings"
	"sync"
	"testing"

	"fileparcel/internal/core"
	"fileparcel/internal/uploads/uploadtest"
)

type fixture struct {
	*uploadtest.Env
	t         *testing.T
	svc       *Service
	ctx       context.Context
	alice     string
	aliceRoot string
	bob       string
	bobRoot   string
	shares    *recShares
}

// recShares records RecordAccess calls of the bound shares service.
type recShares struct {
	core.Shares
	mu  sync.Mutex
	acc []core.ShareAccess
}

func (r *recShares) RecordAccess(_ context.Context, _ *core.Share, a core.ShareAccess) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.acc = append(r.acc, a)
}

func (r *recShares) accesses() []core.ShareAccess {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]core.ShareAccess(nil), r.acc...)
}

func setup(t *testing.T) *fixture {
	t.Helper()
	e := uploadtest.New(t)
	svc, err := New(e.Env, e.Files, e.Blobs, e.Jobs)
	if err != nil {
		t.Fatal(err)
	}
	svc.diskFree = func(string) (uint64, uint64, error) { return 1 << 50, 1 << 51, nil }
	rs := &recShares{}
	if err := svc.Bind(&core.Services{Shares: rs}); err != nil {
		t.Fatal(err)
	}
	f := &fixture{Env: e, t: t, svc: svc, ctx: context.Background(), shares: rs}
	f.alice, f.aliceRoot = e.User("alice", core.RoleMember)
	f.bob, f.bobRoot = e.User("bob", core.RoleMember)
	return f
}

func (f *fixture) actor(userID string) core.UploadActor { return core.UploadActor{P: f.P(userID)} }

func digest(b []byte) []byte { s := sha256.Sum256(b); return s[:] }

// content returns n deterministic pseudo-random bytes.
func content(n int, seed uint64) []byte {
	r := rand.New(rand.NewPCG(seed, seed^0x9e3779b97f4a7c15))
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(r.Uint32())
	}
	return b
}

func part(b []byte, n int) []byte {
	off := n * core.PartSize
	return b[off:min(off+core.PartSize, len(b))]
}

func (f *fixture) batch(a core.UploadActor, in core.BatchInput) *core.UploadBatch {
	f.t.Helper()
	b, err := f.svc.CreateBatch(f.ctx, a, in)
	if err != nil {
		f.t.Fatalf("CreateBatch: %v", err)
	}
	return b
}

func (f *fixture) small(a core.UploadActor, batchID, ref string, data []byte) *core.UploadFileState {
	f.t.Helper()
	st, err := f.svc.PutSmall(f.ctx, a, batchID, ref, bytes.NewReader(data), int64(len(data)), digest(data))
	if err != nil {
		f.t.Fatalf("PutSmall %s: %v", ref, err)
	}
	return st
}

func (f *fixture) parts(a core.UploadActor, uploadID string, data []byte, order ...int) {
	f.t.Helper()
	for _, n := range order {
		p := part(data, n)
		if err := f.svc.PutPart(f.ctx, a, uploadID, n, bytes.NewReader(p), int64(len(p)), digest(p)); err != nil {
			f.t.Fatalf("PutPart %d: %v", n, err)
		}
	}
}

// nodeContent returns the content of the file relPath below folder.
func (f *fixture) nodeContent(folder, relPath string) ([]byte, *core.Node) {
	f.t.Helper()
	cur := folder
	segs := strings.Split(relPath, "/")
	for i, s := range segs {
		id := f.Str(`SELECT id FROM nodes WHERE parent_id = ? AND name = ? AND trashed_at IS NULL`, cur, s)
		if id == "" {
			f.t.Fatalf("%s: %q not found", relPath, s)
		}
		if i == len(segs)-1 {
			n, r, err := f.Files.OpenSys(f.ctx, id)
			if err != nil {
				f.t.Fatal(err)
			}
			defer r.Close()
			b, _ := io.ReadAll(r)
			return b, n
		}
		cur = id
	}
	return nil, nil
}

func wantCode(t *testing.T, err error, want *core.Error) {
	t.Helper()
	if !errors.Is(err, want) {
		t.Fatalf("error = %v, want %s", err, want.Code)
	}
}

// ---------- tests ----------

func TestNewRegistersJobs(t *testing.T) {
	f := setup(t)
	kinds := strings.Join(f.Jobs.Kinds(), ",")
	for _, k := range []string{core.JobUploadZip, core.JobMaintUploads} {
		if !strings.Contains(kinds, k) {
			t.Errorf("job kind %s not registered (%s)", k, kinds)
		}
	}
	if got := f.Jobs.Sched[core.JobMaintUploads]; !strings.HasSuffix(got, core.JobMaintUploads) || strings.Count(got, " ") != 5 {
		t.Errorf("schedule = %q", got)
	}
}

func TestValidateEntries(t *testing.T) {
	deep := strings.Repeat("a/", 64) + "f"
	long := strings.Repeat("x", 200) + "/" + strings.Repeat(strings.Repeat("y", 200)+"/", 20) + "f"
	cases := []struct {
		name  string
		in    core.UploadFileInput
		lim   limits
		field string
		code  *core.Error
	}{
		{"dotdot", core.UploadFileInput{ClientRef: "a", RelPath: "a/../b", Size: 1}, limits{}, "files[0].rel_path", core.ErrInvalid},
		{"absolute", core.UploadFileInput{ClientRef: "a", RelPath: "/etc/passwd", Size: 1}, limits{}, "files[0].rel_path", core.ErrInvalid},
		{"empty segment", core.UploadFileInput{ClientRef: "a", RelPath: "a//b", Size: 1}, limits{}, "files[0].rel_path", core.ErrInvalid},
		{"dot", core.UploadFileInput{ClientRef: "a", RelPath: "./b", Size: 1}, limits{}, "files[0].rel_path", core.ErrInvalid},
		{"backslash", core.UploadFileInput{ClientRef: "a", RelPath: `a\b`, Size: 1}, limits{}, "files[0].rel_path", core.ErrInvalid},
		{"control", core.UploadFileInput{ClientRef: "a", RelPath: "a\x01b", Size: 1}, limits{}, "files[0].rel_path", core.ErrInvalid},
		{"too deep", core.UploadFileInput{ClientRef: "a", RelPath: deep, Size: 1}, limits{}, "files[0].rel_path", core.ErrInvalid},
		{"too long", core.UploadFileInput{ClientRef: "a", RelPath: long, Size: 1}, limits{}, "files[0].rel_path", core.ErrInvalid},
		{"empty path", core.UploadFileInput{ClientRef: "a", RelPath: "", Size: 1}, limits{}, "files[0].rel_path", core.ErrInvalid},
		{"negative size", core.UploadFileInput{ClientRef: "a", RelPath: "a", Size: -1}, limits{}, "files[0].size", core.ErrInvalid},
		{"dir with size", core.UploadFileInput{ClientRef: "a", RelPath: "a", Size: 5, Kind: "dir"}, limits{}, "files[0].size", core.ErrInvalid},
		{"bad kind", core.UploadFileInput{ClientRef: "a", RelPath: "a", Kind: "link"}, limits{}, "files[0].kind", core.ErrInvalid},
		{"no ref", core.UploadFileInput{RelPath: "a"}, limits{}, "files[0].client_ref", core.ErrInvalid},
		{"long ref", core.UploadFileInput{ClientRef: strings.Repeat("r", 129), RelPath: "a"}, limits{}, "files[0].client_ref", core.ErrInvalid},
		{"max file", core.UploadFileInput{ClientRef: "a", RelPath: "a", Size: 11}, limits{maxFile: 10}, "files[0].size", core.ErrTooLarge},
		{"share max", core.UploadFileInput{ClientRef: "a", RelPath: "a", Size: 11}, limits{shareMaxFile: 10}, "files[0].size", core.ErrTooLarge},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, _, err := validateEntries([]core.UploadFileInput{c.in}, c.lim)
			wantCode(t, err, c.code)
			if ce := core.AsError(err); ce.Field != c.field {
				t.Errorf("field = %q, want %q (%v)", ce.Field, c.field, err)
			}
		})
	}
	t.Run("ok", func(t *testing.T) {
		es, total, err := validateEntries([]core.UploadFileInput{
			{ClientRef: "f1", RelPath: "Trip/day1/a.jpg", Size: 3*core.PartSize + 5, MTime: 1726700000000},
			{ClientRef: "d1", RelPath: "Trip/empty/", Kind: "dir"},
			{ClientRef: "f2", RelPath: " spaced .txt", Size: 0, MIME: "text/plain; charset=utf-8"},
		}, limits{maxFile: 1 << 40})
		if err != nil {
			t.Fatal(err)
		}
		if total != 3*core.PartSize+5 || es[0].partCount != 4 || es[1].partCount != 0 || es[2].partCount != 1 {
			t.Errorf("total %d parts %d/%d/%d", total, es[0].partCount, es[1].partCount, es[2].partCount)
		}
		if es[1].relPath != "Trip/empty" || es[2].relPath != "spaced .txt" || es[2].mime != "text/plain" || !es[0].mtime.Valid {
			t.Errorf("normalised entries: %+v", es)
		}
	})
	t.Run("duplicate ref", func(t *testing.T) {
		_, _, err := validateEntries([]core.UploadFileInput{{ClientRef: "x", RelPath: "a"}, {ClientRef: "x", RelPath: "b"}}, limits{})
		wantCode(t, err, core.ErrInvalid)
	})
	t.Run("too many", func(t *testing.T) {
		_, _, err := validateEntries(make([]core.UploadFileInput, MaxFilesPerCall+1), limits{})
		wantCode(t, err, core.ErrInvalid)
	})
}

func TestCreateBatchValidation(t *testing.T) {
	f := setup(t)
	file := f.PutFile(f.aliceRoot, "doc.txt", []byte("hi"))
	a := f.actor(f.alice)
	cases := []struct {
		name string
		a    core.UploadActor
		in   core.BatchInput
		code *core.Error
	}{
		{"no principal", core.UploadActor{}, core.BatchInput{FolderID: f.aliceRoot}, core.ErrUnauthorized},
		{"no folder", a, core.BatchInput{}, core.ErrInvalid},
		{"not a folder", a, core.BatchInput{FolderID: file.ID}, core.ErrInvalid},
		{"foreign folder", a, core.BatchInput{FolderID: f.bobRoot}, core.ErrNotFound},
		{"bad mode", a, core.BatchInput{FolderID: f.aliceRoot, Mode: "tar"}, core.ErrInvalid},
		{"bad conflict", a, core.BatchInput{FolderID: f.aliceRoot, Conflict: "merge"}, core.ErrInvalid},
		{"uploader outside requests", a, core.BatchInput{FolderID: f.aliceRoot, Uploader: "x"}, core.ErrInvalid},
		{"zip name in files mode", a, core.BatchInput{FolderID: f.aliceRoot, ZipName: "x.zip"}, core.ErrInvalid},
		{"bad zip name", a, core.BatchInput{FolderID: f.aliceRoot, Mode: "zip", ZipName: "a/b"}, core.ErrInvalid},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := f.svc.CreateBatch(f.ctx, c.a, c.in)
			wantCode(t, err, c.code)
		})
	}
	t.Run("defaults", func(t *testing.T) {
		b := f.batch(a, core.BatchInput{FolderID: f.aliceRoot, Files: []core.UploadFileInput{{ClientRef: "f", RelPath: "x", Size: 10}}})
		if b.Mode != core.UploadModeFiles || b.Conflict != core.ConflictRename || b.State != core.BatchOpen ||
			b.PartSize != core.PartSize || b.SmallMax != SmallMax || b.Parallel != DefaultParallel ||
			b.DeclaredBytes != 10 || b.ReservedBytes != 10 || len(b.Files) != 1 || b.Files[0].State != core.UploadPending ||
			!b.ExpiresAt.Equal(f.Clock.Now().Add(DefaultExpiryHours*3600e9)) {
			t.Errorf("batch = %+v", b)
		}
		z := f.batch(a, core.BatchInput{FolderID: f.aliceRoot, Mode: "zip", ZipName: "Photos"})
		if z.ZipName != "Photos.zip" {
			t.Errorf("zip name = %q", z.ZipName)
		}
		z2 := f.batch(a, core.BatchInput{FolderID: f.aliceRoot, Mode: "zip"})
		if !strings.HasPrefix(z2.ZipName, "Upload 2026-09-01") || !strings.HasSuffix(z2.ZipName, ".zip") {
			t.Errorf("default zip name = %q", z2.ZipName)
		}
	})
	t.Run("parallel setting", func(t *testing.T) {
		f.Settings.Put(SettingParallel, 7)
		defer f.Settings.Put(SettingParallel, DefaultParallel)
		if b := f.batch(a, core.BatchInput{FolderID: f.aliceRoot}); b.Parallel != 7 {
			t.Errorf("parallel = %d", b.Parallel)
		}
	})
	t.Run("edit grant", func(t *testing.T) {
		shared := f.Mkdir(f.bobRoot, "Shared")
		f.Files.Grant(f.alice, shared, core.PermView)
		_, err := f.svc.CreateBatch(f.ctx, a, core.BatchInput{FolderID: shared})
		wantCode(t, err, core.ErrForbidden)
		f.Files.Grant(f.alice, shared, core.PermEdit)
		f.batch(a, core.BatchInput{FolderID: shared})
	})
}

func TestSmallUploads(t *testing.T) {
	f := setup(t)
	a := f.actor(f.alice)
	txt := []byte("hello small world")
	b := f.batch(a, core.BatchInput{FolderID: f.aliceRoot, Files: []core.UploadFileInput{
		{ClientRef: "f1", RelPath: "Trip/day1/a.txt", Size: int64(len(txt)), MTime: 1726700000000},
		{ClientRef: "f2", RelPath: "empty.bin", Size: 0},
		{ClientRef: "f3", RelPath: "other.txt", Size: 4},
		{ClientRef: "big", RelPath: "big.bin", Size: SmallMax + 1},
	}})
	st := f.small(a, b.ID, "f1", txt)
	if st.State != core.UploadCommitted || st.NodeID == "" || len(st.PartsDone) != 1 {
		t.Fatalf("state = %+v", st)
	}
	got, node := f.nodeContent(f.aliceRoot, "Trip/day1/a.txt")
	if !bytes.Equal(got, txt) || node.ClientMtime == nil || node.ClientMtime.UnixMilli() != 1726700000000 {
		t.Fatalf("content %q node %+v", got, node)
	}
	if st := f.small(a, b.ID, "f2", nil); st.State != core.UploadCommitted {
		t.Fatalf("empty file: %+v", st)
	}
	if got, _ := f.nodeContent(f.aliceRoot, "empty.bin"); len(got) != 0 {
		t.Fatalf("empty content %q", got)
	}
	blobsBefore := f.Blobs.Count()

	t.Run("idempotent resend", func(t *testing.T) {
		st2 := f.small(a, b.ID, "f1", txt)
		if st2.NodeID != st.NodeID || st2.State != core.UploadCommitted || f.Blobs.Count() != blobsBefore {
			t.Fatalf("resend: %+v (blobs %d → %d)", st2, blobsBefore, f.Blobs.Count())
		}
	})
	t.Run("conflicting resend", func(t *testing.T) {
		other := []byte("HELLO SMALL WORLD")
		_, err := f.svc.PutSmall(f.ctx, a, b.ID, "f1", bytes.NewReader(other), int64(len(other)), digest(other))
		wantCode(t, err, core.ErrConflict)
	})
	t.Run("digest mismatch", func(t *testing.T) {
		_, err := f.svc.PutSmall(f.ctx, a, b.ID, "f3", strings.NewReader("abcd"), 4, digest([]byte("abce")))
		wantCode(t, err, core.ErrInvalid)
		if f.Blobs.Count() != blobsBefore {
			t.Fatal("blob of a failed small upload was kept")
		}
		if st, _ := f.svc.fileState(f.ctx, stateByRef(t, f, b.ID, "f3")); st.State != core.UploadPending {
			t.Fatalf("state after mismatch: %s", st.State)
		}
	})
	t.Run("wrong length", func(t *testing.T) {
		_, err := f.svc.PutSmall(f.ctx, a, b.ID, "f3", strings.NewReader("abc"), 3, digest([]byte("abc")))
		wantCode(t, err, core.ErrInvalid)
		// Unknown length, short body.
		_, err = f.svc.PutSmall(f.ctx, a, b.ID, "f3", strings.NewReader("abc"), -1, digest([]byte("abc")))
		wantCode(t, err, core.ErrInvalid)
		// Unknown length, body too long.
		_, err = f.svc.PutSmall(f.ctx, a, b.ID, "f3", strings.NewReader("abcde"), -1, digest([]byte("abcd")))
		wantCode(t, err, core.ErrInvalid)
	})
	t.Run("missing digest", func(t *testing.T) {
		_, err := f.svc.PutSmall(f.ctx, a, b.ID, "f3", strings.NewReader("abcd"), 4, nil)
		wantCode(t, err, core.ErrInvalid)
	})
	t.Run("too big for small path", func(t *testing.T) {
		_, err := f.svc.PutSmall(f.ctx, a, b.ID, "big", strings.NewReader(""), 0, digest(nil))
		wantCode(t, err, core.ErrInvalid)
	})
	t.Run("unknown ref", func(t *testing.T) {
		_, err := f.svc.PutSmall(f.ctx, a, b.ID, "nope", strings.NewReader(""), 0, digest(nil))
		wantCode(t, err, core.ErrNotFound)
	})
	t.Run("other user", func(t *testing.T) {
		_, err := f.svc.PutSmall(f.ctx, f.actor(f.bob), b.ID, "f3", strings.NewReader("abcd"), 4, digest([]byte("abcd")))
		wantCode(t, err, core.ErrNotFound)
	})
	t.Run("unknown length ok", func(t *testing.T) {
		st, err := f.svc.PutSmall(f.ctx, a, b.ID, "f3", strings.NewReader("abcd"), -1, digest([]byte("abcd")))
		if err != nil || st.State != core.UploadCommitted {
			t.Fatalf("%v %+v", err, st)
		}
	})
	// Reservation is released per committed file.
	if r := f.Int(`SELECT reserved_bytes FROM upload_batches WHERE id = ?`, b.ID); r != SmallMax+1 {
		t.Errorf("reserved = %d, want %d", r, SmallMax+1)
	}
}

func stateByRef(t *testing.T, f *fixture, batchID, ref string) string {
	t.Helper()
	return f.Str(`SELECT id FROM upload_files WHERE batch_id = ? AND client_ref = ?`, batchID, ref)
}

func TestPartsOutOfOrderParallel(t *testing.T) {
	f := setup(t)
	a := f.actor(f.alice)
	data := content(3*core.PartSize+5, 1)
	b := f.batch(a, core.BatchInput{FolderID: f.aliceRoot, Files: []core.UploadFileInput{
		{ClientRef: "f1", RelPath: "movies/clip.bin", Size: int64(len(data))}}})
	up := b.Files[0]
	if up.PartCount != 4 {
		t.Fatalf("part count %d", up.PartCount)
	}
	// Parallel, out of order, with a duplicate send of part 2.
	var wg sync.WaitGroup
	errs := make(chan error, 8)
	for _, n := range []int{3, 1, 2, 0, 2} {
		wg.Go(func() {
			p := part(data, n)
			errs <- f.svc.PutPart(f.ctx, a, up.ID, n, bytes.NewReader(p), int64(len(p)), digest(p))
		})
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("PutPart: %v", err)
		}
	}
	if n := f.Int(`SELECT COUNT(DISTINCT blob_id) FROM upload_files WHERE id = ?`, up.ID); n != 1 {
		t.Fatalf("blobs per upload = %d", n)
	}
	if f.Blobs.Count() != 1 {
		t.Fatalf("blob store holds %d blobs, want 1 (parallel first parts must share one blob)", f.Blobs.Count())
	}
	st, err := f.svc.Status(f.ctx, a, up.ID)
	if err != nil || len(st.PartsDone) != 4 || st.State != core.UploadUploading {
		t.Fatalf("status %+v %v", st, err)
	}
	writes := f.Blobs.PartWrites()

	// Idempotent retry: same digest, no rewrite; different digest: 409.
	p1 := part(data, 1)
	if err := f.svc.PutPart(f.ctx, a, up.ID, 1, bytes.NewReader(p1), int64(len(p1)), digest(p1)); err != nil {
		t.Fatalf("idempotent resend: %v", err)
	}
	if f.Blobs.PartWrites() != writes {
		t.Fatal("a resent part was rewritten")
	}
	bad := bytes.Clone(p1)
	bad[0] ^= 1
	err = f.svc.PutPart(f.ctx, a, up.ID, 1, bytes.NewReader(bad), int64(len(bad)), digest(bad))
	wantCode(t, err, core.ErrConflict)

	done, err := f.svc.CompleteFile(f.ctx, a, up.ID)
	if err != nil || done.State != core.UploadCommitted || done.NodeID == "" {
		t.Fatalf("complete %+v %v", done, err)
	}
	got, node := f.nodeContent(f.aliceRoot, "movies/clip.bin")
	if !bytes.Equal(got, data) || node.ContentHash != uploadtest.ContentHash(data) {
		t.Fatal("assembled content differs")
	}
	// Completing again is idempotent; parts after commit are 409 unless identical.
	if again, err := f.svc.CompleteFile(f.ctx, a, up.ID); err != nil || again.NodeID != done.NodeID {
		t.Fatalf("complete again %+v %v", again, err)
	}
	if err := f.svc.PutPart(f.ctx, a, up.ID, 1, bytes.NewReader(p1), int64(len(p1)), digest(p1)); err != nil {
		t.Fatalf("identical resend after commit: %v", err)
	}
}

func TestPartErrors(t *testing.T) {
	f := setup(t)
	a := f.actor(f.alice)
	data := content(core.PartSize+100, 2)
	b := f.batch(a, core.BatchInput{FolderID: f.aliceRoot, Files: []core.UploadFileInput{
		{ClientRef: "f1", RelPath: "x.bin", Size: int64(len(data))},
		{ClientRef: "z", RelPath: "zero.bin", Size: 0},
		{ClientRef: "d", RelPath: "dir", Kind: "dir"},
	}})
	up := b.Files[0]
	p0, p1 := part(data, 0), part(data, 1)
	cases := []struct {
		name string
		id   string
		n    int
		body []byte
		size int64
		sha  []byte
		code *core.Error
	}{
		{"digest mismatch", up.ID, 1, p1, int64(len(p1)), digest(p0), core.ErrInvalid},
		{"no digest", up.ID, 1, p1, int64(len(p1)), nil, core.ErrInvalid},
		{"wrong length", up.ID, 1, p1[:50], 50, digest(p1[:50]), core.ErrInvalid},
		{"part out of range", up.ID, 2, p1, int64(len(p1)), digest(p1), core.ErrInvalid},
		{"negative part", up.ID, -1, p1, int64(len(p1)), digest(p1), core.ErrInvalid},
		{"empty file", b.Files[1].ID, 0, nil, 0, digest(nil), core.ErrInvalid},
		{"directory", b.Files[2].ID, 0, nil, 0, digest(nil), core.ErrInvalid},
		{"unknown upload", "upf_00000000000000000000000000", 0, p0, int64(len(p0)), digest(p0), core.ErrNotFound},
		{"malformed id", "../x", 0, p0, int64(len(p0)), digest(p0), core.ErrNotFound},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := f.svc.PutPart(f.ctx, a, c.id, c.n, bytes.NewReader(c.body), c.size, c.sha)
			wantCode(t, err, c.code)
		})
	}
	if st, _ := f.svc.Status(f.ctx, a, up.ID); len(st.PartsDone) != 0 {
		t.Fatalf("failed parts were recorded: %v", st.PartsDone)
	}
	t.Run("other user", func(t *testing.T) {
		err := f.svc.PutPart(f.ctx, f.actor(f.bob), up.ID, 0, bytes.NewReader(p0), int64(len(p0)), digest(p0))
		wantCode(t, err, core.ErrNotFound)
		_, err = f.svc.Status(f.ctx, f.actor(f.bob), up.ID)
		wantCode(t, err, core.ErrNotFound)
	})
	t.Run("missing parts", func(t *testing.T) {
		f.parts(a, up.ID, data, 1)
		_, err := f.svc.CompleteFile(f.ctx, a, up.ID)
		wantCode(t, err, core.ErrConflict)
	})
}

// failingReader returns n bytes of b, then err.
type failingReader struct {
	b   []byte
	n   int
	err error
}

func (r *failingReader) Read(p []byte) (int, error) {
	if r.n <= 0 {
		return 0, r.err
	}
	k := copy(p, r.b[:min(len(p), r.n)])
	r.b, r.n = r.b[k:], r.n-k
	return k, nil
}

func TestResumeAfterAbortedPart(t *testing.T) {
	f := setup(t)
	a := f.actor(f.alice)
	data := content(2*core.PartSize+17, 3)
	b := f.batch(a, core.BatchInput{FolderID: f.aliceRoot, Files: []core.UploadFileInput{
		{ClientRef: "f1", RelPath: "r.bin", Size: int64(len(data))}}})
	up := b.Files[0]
	f.parts(a, up.ID, data, 0)

	// The connection breaks in the middle of part 1.
	p1 := part(data, 1)
	err := f.svc.PutPart(f.ctx, a, up.ID, 1, &failingReader{b: p1, n: len(p1) / 2, err: io.ErrUnexpectedEOF}, int64(len(p1)), digest(p1))
	if err == nil {
		t.Fatal("broken part accepted")
	}
	// The body ends early (client sent fewer bytes than announced).
	err = f.svc.PutPart(f.ctx, a, up.ID, 1, bytes.NewReader(p1[:1000]), int64(len(p1)), digest(p1))
	wantCode(t, err, core.ErrInvalid)
	// A storage failure while writing.
	f.Blobs.PartHook = func(_ string, n int) error {
		if n == 2 {
			return errors.New("disk on fire")
		}
		return nil
	}
	p2 := part(data, 2)
	if err := f.svc.PutPart(f.ctx, a, up.ID, 2, bytes.NewReader(p2), int64(len(p2)), digest(p2)); err == nil {
		t.Fatal("storage failure hidden")
	}
	f.Blobs.PartHook = nil

	st, _ := f.svc.Status(f.ctx, a, up.ID)
	if len(st.PartsDone) != 1 || st.PartsDone[0] != 0 {
		t.Fatalf("parts done after failures = %v", st.PartsDone)
	}
	// Resume: resend the missing parts, complete.
	f.parts(a, up.ID, data, 2, 1)
	if _, err := f.svc.CompleteFile(f.ctx, a, up.ID); err != nil {
		t.Fatal(err)
	}
	if got, _ := f.nodeContent(f.aliceRoot, "r.bin"); !bytes.Equal(got, data) {
		t.Fatal("resumed content differs")
	}
	if f.svc.locks.size() != 0 {
		t.Errorf("%d lock entries leaked", f.svc.locks.size())
	}
}

func TestConflictPolicies(t *testing.T) {
	f := setup(t)
	a := f.actor(f.alice)
	orig := f.PutFile(f.aliceRoot, "a.txt", []byte("original"))
	upload := func(policy core.ConflictPolicy) (*core.UploadFileState, error) {
		b := f.batch(a, core.BatchInput{FolderID: f.aliceRoot, Conflict: policy,
			Files: []core.UploadFileInput{{ClientRef: "f", RelPath: "a.txt", Size: 3}}})
		return f.svc.PutSmall(f.ctx, a, b.ID, "f", strings.NewReader("new"), 3, digest([]byte("new")))
	}
	blobs := f.Blobs.Count()

	// "fail" and "skip" find the taken name when the file is declared
	// (preflight.go; the commit-time path is TestSmallResendAfterFailedCommit
	// and TestSkipOntoFolder): nothing is reserved or sent.
	batches := f.Int(`SELECT COUNT(*) FROM upload_batches`)
	_, err := f.svc.CreateBatch(f.ctx, a, core.BatchInput{FolderID: f.aliceRoot, Conflict: core.ConflictFail,
		Files: []core.UploadFileInput{{ClientRef: "f", RelPath: "a.txt", Size: 3}}})
	wantCode(t, err, core.ErrConflict)
	if ce := core.AsError(err); ce.Message != "“a.txt” already exists in this folder" {
		t.Fatalf("fail policy: %v", err)
	}
	if n := f.Int(`SELECT COUNT(*) FROM upload_batches`); n != batches {
		t.Fatal("a refused batch was recorded")
	}

	sb := f.batch(a, core.BatchInput{FolderID: f.aliceRoot, Conflict: core.ConflictSkip,
		Files: []core.UploadFileInput{{ClientRef: "f", RelPath: "a.txt", Size: 3}}})
	if sb.Files[0].State != core.UploadSkipped || sb.ReservedBytes != 0 {
		t.Fatalf("skip at declaration: %+v", sb)
	}
	// a client that sends it anyway is told, and nothing is stored
	st, err := f.svc.PutSmall(f.ctx, a, sb.ID, "f", strings.NewReader("new"), 3, digest([]byte("new")))
	if err != nil || st.State != core.UploadSkipped || st.NodeID != "" {
		t.Fatalf("skip: %+v %v", st, err)
	}
	if f.Blobs.Count() != blobs {
		t.Error("blob of a skipped file was kept")
	}
	if done := f.complete(a, sb.ID); done.State != core.BatchDone {
		t.Fatalf("skipped batch: %+v", done)
	}

	st, err = upload(core.ConflictRename)
	if err != nil || st.State != core.UploadCommitted {
		t.Fatalf("rename: %+v %v", st, err)
	}
	if got, _ := f.nodeContent(f.aliceRoot, "a (1).txt"); string(got) != "new" {
		t.Fatalf("renamed content %q", got)
	}

	st, err = upload(core.ConflictReplace)
	if err != nil || st.NodeID != orig.ID {
		t.Fatalf("replace: %+v %v", st, err)
	}
	if got, _ := f.nodeContent(f.aliceRoot, "a.txt"); string(got) != "new" {
		t.Fatalf("replaced content %q", got)
	}
	if n := f.Int(`SELECT COUNT(*) FROM file_versions WHERE node_id = ?`, orig.ID); n != 2 {
		t.Errorf("versions = %d", n)
	}

	// Replacing with byte-identical content adds no version (and charges
	// no second copy): the file is committed to the node it already is,
	// and the blob that was sent is dropped.
	blobs = f.Blobs.Count()
	st, err = upload(core.ConflictReplace)
	if err != nil || st.State != core.UploadCommitted || st.NodeID != orig.ID {
		t.Fatalf("identical replace: %+v %v", st, err)
	}
	if n := f.Int(`SELECT COUNT(*) FROM file_versions WHERE node_id = ?`, orig.ID); n != 2 {
		t.Errorf("versions after an identical replace = %d", n)
	}
	if f.Blobs.Count() != blobs {
		t.Error("the blob of an identical replace was kept")
	}
}

func TestKeyLock(t *testing.T) {
	var l keyLock
	ctx := context.Background()
	unlock, err := l.Lock(ctx, "k")
	if err != nil {
		t.Fatal(err)
	}
	cctx, cancel := context.WithCancel(ctx)
	done := make(chan error)
	go func() {
		_, err := l.Lock(cctx, "k")
		done <- err
	}()
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("waiter: %v", err)
	}
	var wg sync.WaitGroup
	counter := 0
	unlock()
	for range 50 {
		wg.Go(func() {
			u, err := l.Lock(ctx, "k")
			if err != nil {
				t.Error(err)
				return
			}
			counter++
			u()
			u() // idempotent
		})
	}
	wg.Wait()
	if counter != 50 || l.size() != 0 {
		t.Fatalf("counter %d size %d", counter, l.size())
	}
}

func TestBodyReader(t *testing.T) {
	br := newBodyReader(strings.NewReader("abcdef"), 6)
	b, err := io.ReadAll(br)
	if err != nil || string(b) != "abcdef" || !br.complete() || br.trailing() || br.clientError(6) != nil {
		t.Fatalf("exact: %q %v", b, err)
	}
	br = newBodyReader(strings.NewReader("abc"), 6)
	if _, err := io.ReadAll(br); !errors.Is(err, io.ErrUnexpectedEOF) || br.complete() {
		t.Fatalf("short: %v", err)
	}
	wantCode(t, br.clientError(6), core.ErrInvalid)
	br = newBodyReader(strings.NewReader("abcdefgh"), 6)
	b, _ = io.ReadAll(br)
	if string(b) != "abcdef" || !br.trailing() {
		t.Fatalf("long: %q", b)
	}
	br = newBodyReader(&failingReader{err: context.Canceled}, 6)
	_, _ = io.ReadAll(br)
	if err := br.clientError(6); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled: %v", err)
	}
}

// TestIncompleteNamesStoredParts: completing an upload with a gap reports
// how many parts are stored and which are missing, not "have 0".
func TestIncompleteNamesStoredParts(t *testing.T) {
	f := setup(t)
	a := f.actor(f.alice)
	data := content(2*core.PartSize+10, 21)
	b := f.batch(a, core.BatchInput{FolderID: f.aliceRoot, Files: []core.UploadFileInput{
		{ClientRef: "f", RelPath: "three.bin", Size: int64(len(data))}}})
	up := b.Files[0].ID
	f.parts(a, up, data, 2, 0)
	_, err := f.svc.CompleteFile(f.ctx, a, up)
	wantCode(t, err, core.ErrConflict)
	if got, want := core.AsError(err).Message, "the upload is incomplete: have 2 of 3 parts (missing: 1)"; got != want {
		t.Fatalf("message %q, want %q", got, want)
	}
	f.parts(a, up, data, 1)
	if st, err := f.svc.CompleteFile(f.ctx, a, up); err != nil || st.State != core.UploadCommitted {
		t.Fatalf("complete after the last part: %+v %v", st, err)
	}
	if got, _ := f.nodeContent(f.aliceRoot, "three.bin"); !bytes.Equal(got, data) {
		t.Fatal("content differs")
	}
}

func TestMissingParts(t *testing.T) {
	for _, c := range []struct {
		stored []int
		count  int
		want   string
	}{
		{[]int{0, 2}, 3, "1"},
		{[]int{1}, 3, "0, 2"},
		{nil, 2, "0, 1"},
		{[]int{3}, 12, "0, 1, 2, 4, 5, 6, 7, 8 and 3 more"},
	} {
		if got := missingParts(c.stored, c.count); got != c.want {
			t.Errorf("missingParts(%v, %d) = %q, want %q", c.stored, c.count, got, c.want)
		}
	}
}
