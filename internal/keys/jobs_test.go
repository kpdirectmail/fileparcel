package keys

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"os"
	"sync"
	"testing"
	"time"

	"fileparcel/internal/blobstore"
	"fileparcel/internal/core"
	"fileparcel/internal/crypt"
	"fileparcel/internal/db"
	"fileparcel/internal/ids"
)

type fakeJobs struct {
	mu    sync.Mutex
	kinds map[string]core.JobFunc
	opts  map[string]core.JobOptions
}

func (f *fakeJobs) Register(kind string, fn core.JobFunc, o core.JobOptions) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.kinds == nil {
		f.kinds, f.opts = map[string]core.JobFunc{}, map[string]core.JobOptions{}
	}
	f.kinds[kind], f.opts[kind] = fn, o
}
func (f *fakeJobs) Enqueue(context.Context, string, any, *core.Principal) (string, error) {
	return "", core.ErrNotImplemented
}
func (f *fakeJobs) Get(context.Context, string) (*core.Job, error) {
	return nil, core.ErrNotImplemented
}
func (f *fakeJobs) List(context.Context, core.JobQuery) (core.Page[core.Job], error) {
	return core.Page[core.Job]{}, core.ErrNotImplemented
}
func (f *fakeJobs) Cancel(context.Context, string) error                  { return core.ErrNotImplemented }
func (f *fakeJobs) Schedule(string, string, string, any) error            { return nil }
func (f *fakeJobs) Unschedule(string)                                     {}
func (f *fakeJobs) Schedules(context.Context) ([]core.JobSchedule, error) { return nil, nil }
func (f *fakeJobs) Start(context.Context) error                           { return nil }
func (f *fakeJobs) Stop(context.Context) error                            { return nil }

type fakeHandle struct {
	id       string
	params   json.RawMessage
	result   any
	progress [][2]int64
}

func (h *fakeHandle) ID() string { return h.id }
func (h *fakeHandle) Params(v any) error {
	if len(h.params) == 0 {
		return nil
	}
	return json.Unmarshal(h.params, v)
}
func (h *fakeHandle) Progress(done, total int64, _ string) {
	h.progress = append(h.progress, [2]int64{done, total})
}
func (h *fakeHandle) SetResult(v any) { h.result = v }

func TestRegisterJobsAndRotateJob(t *testing.T) {
	te := newTestEnv(t)
	s := te.initPlain(t)
	j := &fakeJobs{}
	if err := s.RegisterJobs(j); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{core.JobKeysRotateKEK, core.JobKeysReencrypt} {
		if j.kinds[k] == nil || j.opts[k].Exclusive != jobLock {
			t.Fatalf("kind %s not registered", k)
		}
	}
	blobKEK, fieldKEK := activeKEK(t, te, core.KEKBlob), activeKEK(t, te, core.KEKField)
	insertBlobRow(t, te, s, nil)
	h := &fakeHandle{id: ids.New(ids.PrefixJob), params: json.RawMessage(`{"purpose":"blob"}`)}
	if err := j.kinds[core.JobKeysRotateKEK](ctx, h); err != nil {
		t.Fatal(err)
	}
	if res := h.result.(RotateKEKResult); len(res.Purposes) != 1 || res.Purposes[0] != "blob" {
		t.Fatalf("result %+v", res)
	}
	if len(h.progress) == 0 || h.progress[len(h.progress)-1] != [2]int64{1, 1} {
		t.Fatalf("progress %v", h.progress)
	}
	if activeKEK(t, te, core.KEKBlob) == blobKEK || activeKEK(t, te, core.KEKField) != fieldKEK {
		t.Fatal("only the blob KEK must rotate")
	}
	// empty purpose rotates both
	h = &fakeHandle{id: ids.New(ids.PrefixJob)}
	if err := j.kinds[core.JobKeysRotateKEK](ctx, h); err != nil {
		t.Fatal(err)
	}
	if activeKEK(t, te, core.KEKField) == fieldKEK {
		t.Fatal("field KEK not rotated")
	}
	h = &fakeHandle{id: "x", params: json.RawMessage(`{"purpose":"mac"}`)}
	errIs(t, j.kinds[core.JobKeysRotateKEK](ctx, h), core.ErrInvalid, "mac job")
	h = &fakeHandle{id: "x", params: json.RawMessage(`{"purpose":1}`)}
	errIs(t, j.kinds[core.JobKeysRotateKEK](ctx, h), core.ErrInvalid, "bad params")
}

func TestReencryptJob(t *testing.T) {
	te := newTestEnv(t)
	s := te.initPlain(t)
	blobs, err := blobstore.New(te.env)
	if err != nil {
		t.Fatal(err)
	}
	defer blobs.Close()
	if err := s.Bind(&core.Services{Blobs: blobs}); err != nil {
		t.Fatal(err)
	}
	// Blobs are old; the job is enqueued now; blobs it writes are newer
	// than its creation time (cutoff), as with a real clock.
	te.clock.t = time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)
	f := te.fixture(t)
	now := db.Ms(te.clock.Now())
	put := func(data []byte) *core.BlobInfo {
		w, err := blobs.Create(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write(data); err != nil {
			t.Fatal(err)
		}
		info, err := w.Commit(ctx)
		if err != nil {
			t.Fatal(err)
		}
		return info
	}
	contents := map[string][]byte{}
	var versions, thumbs []string
	for i := range 5 {
		data := crypt.RandomBytes(1000 + i*70000)
		info := put(data)
		node := ids.New(ids.PrefixNode)
		te.exec(t, `INSERT INTO nodes (id, space_id, parent_id, kind, name, name_key, created_at, updated_at) VALUES (?, ?, ?, 'file', ?, ?, ?, ?)`,
			node, f.spaceID, f.nodeID, node, node, now, now)
		ver := ids.New(ids.PrefixVersion)
		te.exec(t, `INSERT INTO file_versions (id, node_id, blob_id, size, created_at) VALUES (?, ?, ?, ?, ?)`, ver, node, info.ID, info.Size, now)
		contents[ver] = data
		versions = append(versions, ver)
		if i < 2 {
			th := crypt.RandomBytes(500)
			ti := put(th)
			te.exec(t, `UPDATE nodes SET thumb_blob_id = ? WHERE id = ?`, ti.ID, node)
			contents[node] = th
			thumbs = append(thumbs, node)
		}
	}
	orphan := put([]byte("unreferenced"))
	before := map[string]string{}
	for _, v := range versions {
		before[v] = te.queryString(t, `SELECT blob_id FROM file_versions WHERE id = ?`, v)
	}
	jobID := ids.New(ids.PrefixJob)
	te.clock.t = time.Now().Add(time.Hour)
	j := &fakeJobs{}
	_ = s.RegisterJobs(j)
	h := &fakeHandle{id: jobID}
	if err := j.kinds[core.JobKeysReencrypt](ctx, h); err != nil {
		t.Fatal(err)
	}
	res := h.result.(ReencryptResult)
	if res.Total != 7 || res.Reencrypted != 7 || res.Failed != 0 {
		t.Fatalf("result %+v", res)
	}
	read := func(id string) []byte {
		r, err := blobs.Open(ctx, id)
		if err != nil {
			t.Fatal(err)
		}
		defer r.Close()
		b, _ := io.ReadAll(r)
		return b
	}
	for _, v := range versions {
		id := te.queryString(t, `SELECT blob_id FROM file_versions WHERE id = ?`, v)
		if id == before[v] {
			t.Fatalf("version %s not re-encrypted", v)
		}
		if !bytes.Equal(read(id), contents[v]) {
			t.Fatal("content changed")
		}
		if _, err := blobs.Stat(ctx, before[v]); !isErr(err, core.ErrNotFound) {
			t.Fatalf("old blob still present: %v", err)
		}
	}
	for _, n := range thumbs {
		id := te.queryString(t, `SELECT thumb_blob_id FROM nodes WHERE id = ?`, n)
		if !bytes.Equal(read(id), contents[n]) {
			t.Fatal("thumb changed")
		}
	}
	if _, err := blobs.Stat(ctx, orphan.ID); err != nil {
		t.Fatal("unreferenced blob must be left to GC")
	}
	if len(te.audit.find(core.ActKeysRotate, core.OutcomeSuccess)) != 1 {
		t.Fatal("not audited")
	}
	// Re-running with the same cutoff finds nothing left (resumable).
	h = &fakeHandle{id: jobID}
	if err := j.kinds[core.JobKeysReencrypt](ctx, h); err != nil {
		t.Fatal(err)
	}
	if res := h.result.(ReencryptResult); res.Total != 0 {
		t.Fatalf("second run %+v", res)
	}
	// An explicit cutoff before every blob selects nothing either.
	h = &fakeHandle{id: "x", params: json.RawMessage(`{"before":"2019-01-01T00:00:00Z"}`)}
	if err := j.kinds[core.JobKeysReencrypt](ctx, h); err != nil || h.result.(ReencryptResult).Total != 0 {
		t.Fatalf("explicit cutoff: %v %+v", err, h.result)
	}
	// Without a blob store the job fails cleanly.
	s2 := &Service{env: te.env, log: s.log}
	errIs(t, s2.jobReencrypt(ctx, &fakeHandle{}), core.ErrUnavailable, "no blob store")
}

// purgingBlobs wraps a blob store; its Reencrypt removes the references of
// one blob right after copying it (a purge racing with the job).
type purgingBlobs struct {
	core.BlobStore
	te     *testEnv
	t      *testing.T
	target string
}

func (p *purgingBlobs) Reencrypt(ctx context.Context, id string) (string, error) {
	newID, err := p.BlobStore.Reencrypt(ctx, id)
	if err == nil && id == p.target {
		p.te.exec(p.t, `DELETE FROM file_versions WHERE blob_id = ?`, id)
	}
	return newID, err
}

func TestReencryptJobFailures(t *testing.T) {
	te := newTestEnv(t)
	s, _ := te.initSealed(t)
	blobs, err := blobstore.New(te.env)
	if err != nil {
		t.Fatal(err)
	}
	defer blobs.Close()
	f := te.fixture(t)
	now := db.Ms(te.clock.Now())
	put := func() string {
		w, err := blobs.Create(ctx)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = w.Write(crypt.RandomBytes(200000))
		info, err := w.Commit(ctx)
		if err != nil {
			t.Fatal(err)
		}
		node := ids.New(ids.PrefixNode)
		te.exec(t, `INSERT INTO nodes (id, space_id, parent_id, kind, name, name_key, created_at, updated_at) VALUES (?, ?, ?, 'file', ?, ?, ?, ?)`,
			node, f.spaceID, f.nodeID, node, node, now, now)
		te.exec(t, `INSERT INTO file_versions (id, node_id, blob_id, size, created_at) VALUES (?, ?, ?, ?, ?)`,
			ids.New(ids.PrefixVersion), node, info.ID, info.Size, now)
		return info.ID
	}
	good, damaged, purged := put(), put(), put()
	// damage the second segment of one blob
	path := te.h.BlobsDir() + "/" + damaged[:2] + "/" + damaged[2:4] + "/" + damaged
	b, _ := os.ReadFile(path)
	b[32+65536+28+100] ^= 1
	_ = os.WriteFile(path, b, 0o600)

	_ = s.Bind(&core.Services{Blobs: &purgingBlobs{BlobStore: blobs, te: te, t: t, target: purged}})
	j := &fakeJobs{}
	_ = s.RegisterJobs(j)
	te.clock.advance(time.Hour)
	h := &fakeHandle{id: "job_x"}
	err = j.kinds[core.JobKeysReencrypt](ctx, h)
	errIs(t, err, core.ErrCorrupt, "damaged blob")
	res := h.result.(ReencryptResult)
	if res.Total != 3 || res.Reencrypted != 1 || res.Failed != 1 || res.Skipped != 1 {
		t.Fatalf("result %+v", res)
	}
	if n := te.count(t, `SELECT count(*) FROM file_versions WHERE blob_id = ?`, damaged); n != 1 {
		t.Fatal("the damaged blob must keep its reference")
	}
	if n := te.count(t, `SELECT count(*) FROM file_versions WHERE blob_id = ?`, good); n != 0 {
		t.Fatal("good blob not swapped")
	}
	// the copy of the purged blob was removed again; the purged original is
	// left to GC (unreferenced)
	if n := te.count(t, `SELECT count(*) FROM blobs`); n != 3 {
		t.Fatalf("%d blobs, want good copy + damaged + purged original", n)
	}
	if len(te.audit.find(core.ActKeysRotate, core.OutcomeFailure)) != 1 {
		t.Fatal("failure not audited")
	}
	// locked keys: the job refuses to start
	if err := s.Lock(ctx); err != nil {
		t.Fatal(err)
	}
	errIs(t, j.kinds[core.JobKeysReencrypt](ctx, &fakeHandle{id: "job_y"}), core.ErrKeysLocked, "locked")
	// canceled context: interrupted, audited as failure
	if err := s.Unlock(ctx, []byte(testPass)); err != nil {
		t.Fatal(err)
	}
	cctx, cancel := context.WithCancel(ctx)
	cancel()
	h = &fakeHandle{id: "job_z", params: json.RawMessage(`{"before":"2100-01-01T00:00:00Z"}`)}
	if err := j.kinds[core.JobKeysReencrypt](cctx, h); err == nil {
		t.Fatal("canceled job succeeded")
	}
}
