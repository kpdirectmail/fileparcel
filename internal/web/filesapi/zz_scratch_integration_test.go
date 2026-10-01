package filesapi_test

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"image"
	"image/png"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"fileparcel/internal/app"
	"fileparcel/internal/config"
	"fileparcel/internal/core"
	"fileparcel/internal/home"
	"fileparcel/internal/web"
	"fileparcel/internal/wire"
)

func TestScratchWired(t *testing.T) {
	h, err := home.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := h.EnsureLayout(); err != nil {
		t.Fatal(err)
	}
	c := config.Default(config.NewInstallID())
	if err := c.SaveTo(h.Config()); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	d, cleanup, err := wire.Build(ctx, h, app.ModeOffline)
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()
	if _, err := d.Keys.Init(ctx, false, nil); err != nil {
		t.Fatal(err)
	}
	if err := wire.Start(ctx, d); err != nil {
		t.Fatal(err)
	}
	if err := d.Jobs.Start(ctx); err != nil {
		t.Fatal(err)
	}
	defer d.Jobs.Stop(ctx)
	sys := core.SystemPrincipal(core.ViaOffline)
	u, err := d.Users.Create(ctx, sys, core.NewUser{Username: "alice"})
	if err != nil {
		t.Fatal(err)
	}
	p, err := d.Files.SysPrincipalFor(ctx, u.ID)
	if err != nil {
		t.Fatal(err)
	}
	p.Via = core.ViaSession
	spaces, err := d.Files.Spaces(ctx, p)
	if err != nil || len(spaces) != 1 {
		t.Fatalf("spaces %v %v", spaces, err)
	}
	root := spaces[0].RootID
	data := make([]byte, 300_000)
	_, _ = rand.Read(data)
	bw, err := d.Blobs.Create(ctx)
	if err != nil {
		t.Fatal(err)
	}
	bw.Write(data)
	info, err := bw.Commit(ctx)
	if err != nil {
		t.Fatal(err)
	}
	n, err := d.Files.CommitFile(ctx, p, root, "Trip/a.bin", info, core.FileMeta{}, core.ConflictFail)
	if err != nil {
		t.Fatal(err)
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r = r.WithContext(core.WithPrincipal(r.Context(), core.SystemPrincipal(core.ViaOffline)))
		r.Header.Set("X-FP-As", "alice")
		web.NewRouter(d).ServeHTTP(w, r)
	}))
	defer srv.Close()
	get := func(path string, hdr ...string) (*http.Response, []byte) {
		req, _ := http.NewRequest("GET", srv.URL+path, nil)
		for i := 0; i+1 < len(hdr); i += 2 {
			req.Header.Set(hdr[i], hdr[i+1])
		}
		resp, err := srv.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return resp, b
	}
	resp, body := get("/api/v1/nodes/" + n.ID + "/content")
	if resp.StatusCode != 200 || !bytes.Equal(body, data) {
		t.Fatalf("content %d %d", resp.StatusCode, len(body))
	}
	t.Logf("headers %v", resp.Header)
	resp, body = get("/api/v1/nodes/"+n.ID+"/content", "Range", "bytes=65530-131080")
	if resp.StatusCode != 206 || !bytes.Equal(body, data[65530:131081]) {
		t.Fatalf("range %d %d", resp.StatusCode, len(body))
	}
	// archive
	req, _ := http.NewRequest("POST", srv.URL+"/api/v1/archives", bytes.NewReader([]byte(`{"node_ids":["`+n.ParentID+`"]}`)))
	req.Header.Set("Content-Type", "application/json")
	resp, err = srv.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	var tr core.ArchiveTicketResponse
	json.NewDecoder(resp.Body).Decode(&tr)
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("archive ticket %d", resp.StatusCode)
	}
	resp, body = get(tr.URL)
	zr, err := zip.NewReader(bytes.NewReader(body), int64(len(body)))
	if err != nil {
		t.Fatalf("zip %d %v", resp.StatusCode, err)
	}
	for _, f := range zr.File {
		t.Logf("zip entry %s %d", f.Name, f.UncompressedSize64)
	}
	// thumbnail job
	var jobs core.Page[core.Job]
	time.Sleep(200 * time.Millisecond)
	jobs, _ = d.Jobs.List(ctx, core.JobQuery{})
	for _, j := range jobs.Items {
		t.Logf("job %s %s %s", j.Kind, j.State, j.Error)
	}
	sch, _ := d.Jobs.Schedules(ctx)
	for _, s := range sch {
		t.Logf("schedule %+v", s)
	}
	// run maintenance jobs
	for _, k := range []string{core.JobMaintTrash, core.JobMaintVersions, core.JobMaintBlobGC} {
		id, err := d.Jobs.Enqueue(ctx, k, map[string]any{}, sys)
		if err != nil {
			t.Fatal(err)
		}
		for i := 0; i < 100; i++ {
			j, _ := d.Jobs.Get(ctx, id)
			if j != nil && (j.State == "succeeded" || j.State == "failed") {
				t.Logf("job %s %s %s %s", k, j.State, j.Error, j.Result)
				break
			}
			time.Sleep(50 * time.Millisecond)
		}
	}
	// trash + purge → blob deleted
	if err := d.Files.Trash(ctx, p, []string{n.ParentID}); err != nil {
		t.Fatal(err)
	}
	if err := d.Files.EmptyTrash(ctx, p); err != nil {
		t.Fatal(err)
	}
	if _, err := d.Blobs.Stat(ctx, info.ID); err == nil {
		t.Fatal("blob survived purge")
	}
	// thumbnail via the real job runner
	img := image.NewRGBA(image.Rect(0, 0, 900, 600))
	for i := range img.Pix {
		img.Pix[i] = byte(i)
	}
	var pb bytes.Buffer
	png.Encode(&pb, img)
	bw, _ = d.Blobs.Create(ctx)
	bw.Write(pb.Bytes())
	info, _ = bw.Commit(ctx)
	pn, err := d.Files.CommitFile(ctx, p, root, "pic.png", info, core.FileMeta{}, core.ConflictFail)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 100; i++ {
		resp, body = get("/api/v1/nodes/" + pn.ID + "/thumb")
		if resp.StatusCode == 200 {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	cfg, f, err := image.DecodeConfig(bytes.NewReader(body))
	t.Logf("thumb %d %s %v %v", resp.StatusCode, f, cfg.Width, err)
	us, err := d.Files.Usage(ctx, u.ID)
	t.Logf("usage %+v %v", us, err)
}
