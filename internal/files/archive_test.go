package files

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"errors"
	"image"
	"image/color"
	"image/png"
	"io"
	"slices"
	"strings"
	"testing"
	"time"

	"fileparcel/internal/core"
	"fileparcel/internal/db"
	"fileparcel/internal/ids"
)

// zipEntries reads a zip into name → content ("<dir>" for directories).
func zipEntries(t *testing.T, data []byte) map[string]string {
	t.Helper()
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		t.Fatalf("zip: %v", err)
	}
	out := map[string]string{}
	for _, f := range zr.File {
		if strings.HasSuffix(f.Name, "/") {
			out[f.Name] = "<dir>"
			continue
		}
		rc, err := f.Open()
		if err != nil {
			t.Fatal(err)
		}
		b, err := io.ReadAll(rc)
		rc.Close()
		if err != nil {
			t.Fatalf("read %s: %v", f.Name, err)
		}
		out[f.Name] = string(b)
	}
	return out
}

func TestArchiveTickets(t *testing.T) {
	e := newEnv(t)
	u := e.user("alice", core.RoleMember)
	trip := e.mkdir(u, u.rootID, "Trip")
	e.file(u, trip.ID, "day1/a.txt", "alpha")
	e.file(u, trip.ID, "day1/photo.jpg", "\xff\xd8\xff\xe0 not really a jpeg")
	e.mkdir(u, trip.ID, "empty")
	e.file(u, trip.ID, "Grüße ☃.txt", "unicode")
	e.file(u, trip.ID, "zero.txt", "")
	gone := e.file(u, trip.ID, "gone.txt", "trashed")
	if err := e.svc.Trash(e.ctx, u.Principal, []string{gone.ID}); err != nil {
		t.Fatal(err)
	}
	solo := e.file(u, u.rootID, "solo.md", "# solo")

	// Input validation.
	for _, in := range []core.ArchiveInput{{}, {NodeIDs: []string{trip.ID}, Format: "rar"}} {
		if _, err := e.svc.CreateArchiveTicket(e.ctx, u.Principal, "", in); code(err) != "invalid" {
			t.Errorf("ticket %+v: %v", in, err)
		}
	}
	stranger := e.user("eve", core.RoleMember)
	if _, err := e.svc.CreateArchiveTicket(e.ctx, stranger.Principal, "", core.ArchiveInput{NodeIDs: []string{trip.ID}}); code(err) != "not_found" {
		t.Fatalf("stranger ticket: %v", err)
	}

	ticket, err := e.svc.CreateArchiveTicket(e.ctx, u.Principal, "", core.ArchiveInput{NodeIDs: []string{trip.ID, solo.ID}, Name: "My Trip.zip"})
	if err != nil {
		t.Fatal(err)
	}
	// Stored hashed only.
	var n int
	if err := e.db.QueryRow(e.ctx, `SELECT COUNT(*) FROM archive_tickets WHERE id_hash = ?`, ids.HashToken(ticket)).Scan(&n); err != nil || n != 1 {
		t.Fatalf("ticket row: %d %v", n, err)
	}
	// Peek does not consume.
	if pt, err := e.svc.PeekArchiveTicket(e.ctx, ticket); err != nil || pt.Name != "My Trip.zip" || pt.UserID != u.UserID {
		t.Fatalf("peek %+v %v", pt, err)
	}
	tk, err := e.svc.ConsumeArchiveTicket(e.ctx, ticket)
	if err != nil || tk.Format != core.ArchiveZip || !slices.Equal(tk.NodeIDs, []string{trip.ID, solo.ID}) ||
		tk.ExpiresAt.Sub(tk.CreatedAt) != ticketTTL {
		t.Fatalf("consume %+v %v", tk, err)
	}
	// Single use.
	if _, err := e.svc.ConsumeArchiveTicket(e.ctx, ticket); code(err) != "not_found" {
		t.Fatalf("second use: %v", err)
	}
	if _, err := e.svc.PeekArchiveTicket(e.ctx, ticket); code(err) != "not_found" {
		t.Fatalf("peek used: %v", err)
	}
	for _, bad := range []string{"", "short", strings.Repeat("A", 43), "not a ticket!!!!!!!!!!!!!!!!!!!!!!!"} {
		if _, err := e.svc.ConsumeArchiveTicket(e.ctx, bad); code(err) != "not_found" {
			t.Errorf("consume %q: %v", bad, err)
		}
	}

	var buf bytes.Buffer
	if err := e.svc.WriteArchive(e.ctx, tk, &buf); err != nil {
		t.Fatal(err)
	}
	got := zipEntries(t, buf.Bytes())
	want := map[string]string{
		"Trip/":               "<dir>",
		"Trip/day1/":          "<dir>",
		"Trip/day1/a.txt":     "alpha",
		"Trip/day1/photo.jpg": "\xff\xd8\xff\xe0 not really a jpeg",
		"Trip/empty/":         "<dir>",
		"Trip/Grüße ☃.txt":    "unicode",
		"Trip/zero.txt":       "",
		"solo.md":             "# solo",
	}
	if len(got) != len(want) {
		t.Fatalf("zip entries %v", got)
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("zip %q = %q, want %q", k, got[k], v)
		}
	}
	a := e.audit.last(core.ActArchiveDownload)
	if a == nil || a.ActorID != u.UserID || a.TargetName != "My Trip.zip" || a.Details.(map[string]any)["files"] != int64(5) {
		t.Fatalf("archive audit %+v", a)
	}

	// Expiry.
	ticket, err = e.svc.CreateArchiveTicket(e.ctx, u.Principal, "", core.ArchiveInput{NodeIDs: []string{solo.ID}, Format: core.ArchiveTar})
	if err != nil {
		t.Fatal(err)
	}
	e.clock.Advance(ticketTTL + time.Second)
	if _, err := e.svc.ConsumeArchiveTicket(e.ctx, ticket); code(err) != "not_found" {
		t.Fatalf("expired: %v", err)
	}

	// Tar, and a lost permission between ticket and download.
	ticket, _ = e.svc.CreateArchiveTicket(e.ctx, u.Principal, "", core.ArchiveInput{NodeIDs: []string{trip.ID}, Format: core.ArchiveTar})
	tk, err = e.svc.ConsumeArchiveTicket(e.ctx, ticket)
	if err != nil || tk.Name != "Trip.tar" {
		t.Fatalf("tar ticket %+v %v", tk, err)
	}
	buf.Reset()
	if err := e.svc.WriteArchive(e.ctx, tk, &buf); err != nil {
		t.Fatal(err)
	}
	tr := tar.NewReader(&buf)
	var tarNames []string
	for {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		tarNames = append(tarNames, h.Name)
	}
	if !slices.Contains(tarNames, "Trip/day1/a.txt") || !slices.Contains(tarNames, "Trip/empty/") {
		t.Fatalf("tar names %v", tarNames)
	}
	if err := e.svc.Trash(e.ctx, u.Principal, []string{trip.ID}); err != nil {
		t.Fatal(err)
	}
	if err := e.svc.WriteArchive(e.ctx, tk, io.Discard); code(err) != "not_found" {
		t.Fatalf("trashed after ticket: %v", err)
	}
	if _, err := e.db.Exec(e.ctx, `UPDATE users SET status = 'disabled' WHERE id = ?`, u.UserID); err != nil {
		t.Fatal(err)
	}
	if err := e.svc.WriteArchive(e.ctx, &core.ArchiveTicket{UserID: u.UserID, NodeIDs: []string{solo.ID}, Format: "zip"}, io.Discard); code(err) != "forbidden" {
		t.Fatalf("disabled user: %v", err)
	}
}

func TestArchiveNames(t *testing.T) {
	cases := []struct {
		given  string
		items  []string
		format string
		want   string
	}{
		{"", []string{"Photos"}, "zip", "Photos.zip"},
		{"", []string{"a", "b"}, "zip", "download.zip"},
		{"Backup.ZIP", nil, "zip", "Backup.zip"},
		{"x.tar", nil, "tar", "x.tar"},
		{"../../etc", nil, "zip", "download.zip"},
		{strings.Repeat("é", 200), nil, "zip", strings.Repeat("é", 125) + ".zip"},
	}
	for _, c := range cases {
		if got := archiveName(c.given, c.items, c.format); got != c.want {
			t.Errorf("archiveName(%q, %v) = %q, want %q", c.given, c.items, got, c.want)
		}
	}
}

func TestShareArchive(t *testing.T) {
	e := newEnv(t)
	u := e.user("alice", core.RoleMember)
	pub := e.mkdir(u, u.rootID, "Public")
	in := e.file(u, pub.ID, "in.txt", "inside")
	out := e.file(u, u.rootID, "out.txt", "outside")
	shareID := ids.New(ids.PrefixShare)
	now := db.Ms(e.clock.Now())
	if _, err := e.db.Exec(e.ctx, `INSERT INTO shares (id, kind, node_id, created_by, token_hash, token_enc, created_at, updated_at)
		VALUES (?, 'link', ?, ?, ?, 'x', ?, ?)`, shareID, pub.ID, u.UserID, ids.HashToken("tok"), now, now); err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.CreateArchiveTicket(e.ctx, nil, shareID, core.ArchiveInput{NodeIDs: []string{out.ID}}); code(err) != "not_found" {
		t.Fatalf("outside the share: %v", err)
	}
	ticket, err := e.svc.CreateArchiveTicket(e.ctx, nil, shareID, core.ArchiveInput{NodeIDs: []string{pub.ID}})
	if err != nil {
		t.Fatal(err)
	}
	tk, err := e.svc.ConsumeArchiveTicket(e.ctx, ticket)
	if err != nil || tk.ShareID != shareID || tk.UserID != "" || tk.Name != "Public.zip" {
		t.Fatalf("share ticket %+v %v", tk, err)
	}
	var buf bytes.Buffer
	if err := e.svc.WriteArchive(e.ctx, tk, &buf); err != nil {
		t.Fatal(err)
	}
	if got := zipEntries(t, buf.Bytes()); got["Public/in.txt"] != "inside" || len(got) != 2 {
		t.Fatalf("share zip %v", got)
	}
	if a := e.audit.last(core.ActArchiveDownload); a == nil || a.TargetID != shareID || a.ActorVia != string(core.ViaShare) {
		t.Fatalf("share archive audit %+v", a)
	}
	// Forged ticket with a node outside the share.
	if err := e.svc.WriteArchive(e.ctx, &core.ArchiveTicket{ShareID: shareID, NodeIDs: []string{out.ID}, Format: "zip"}, io.Discard); code(err) != "not_found" {
		t.Fatalf("forged share ticket: %v", err)
	}
	// Downloads disabled / share disabled / expired.
	if _, err := e.db.Exec(e.ctx, `UPDATE shares SET allow_download = 0 WHERE id = ?`, shareID); err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.CreateArchiveTicket(e.ctx, nil, shareID, core.ArchiveInput{NodeIDs: []string{in.ID}}); code(err) != "forbidden" {
		t.Fatalf("downloads disabled: %v", err)
	}
	if _, err := e.db.Exec(e.ctx, `UPDATE shares SET allow_download = 1, disabled_at = ? WHERE id = ?`, now, shareID); err != nil {
		t.Fatal(err)
	}
	if err := e.svc.WriteArchive(e.ctx, tk, io.Discard); code(err) != "not_found" {
		t.Fatalf("disabled share: %v", err)
	}
	if _, err := e.db.Exec(e.ctx, `UPDATE shares SET disabled_at = NULL, expires_at = ? WHERE id = ?`, now, shareID); err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.CreateArchiveTicket(e.ctx, nil, shareID, core.ArchiveInput{NodeIDs: []string{in.ID}}); code(err) != "not_found" {
		t.Fatalf("expired share: %v", err)
	}
}

// failAfter fails writes after n bytes.
type failAfter struct{ n int }

func (f *failAfter) Write(p []byte) (int, error) {
	if len(p) > f.n {
		return 0, errors.New("client gone")
	}
	f.n -= len(p)
	return len(p), nil
}

func TestWriteArchiveCompressionAndErrors(t *testing.T) {
	e := newEnv(t)
	u := e.user("u", core.RoleMember)
	text := strings.Repeat("compress me ", 1000)
	e.file(u, u.rootID, "text.txt", text)
	e.file(u, u.rootID, "pic.jpg", text)
	methods := func(comp string) map[string]uint16 {
		t.Helper()
		e.settings.set(settingZipCompression, comp)
		var buf bytes.Buffer
		err := e.svc.WriteArchive(e.ctx, &core.ArchiveTicket{UserID: u.UserID, NodeIDs: []string{u.rootID}, Format: "zip"}, &buf)
		if err != nil {
			t.Fatal(err)
		}
		zr, err := zip.NewReader(bytes.NewReader(buf.Bytes()), int64(buf.Len()))
		if err != nil {
			t.Fatal(err)
		}
		out := map[string]uint16{}
		for _, f := range zr.File {
			out[f.Name] = f.Method
		}
		return out
	}
	if m := methods("auto"); m["My files/text.txt"] != zip.Deflate || m["My files/pic.jpg"] != zip.Store {
		t.Fatalf("auto %v", m)
	}
	if m := methods("store"); m["My files/text.txt"] != zip.Store {
		t.Fatalf("store %v", m)
	}
	if m := methods("deflate"); m["My files/pic.jpg"] != zip.Deflate {
		t.Fatalf("deflate %v", m)
	}
	if m := methods("bogus"); m["My files/text.txt"] != zip.Deflate { // falls back to auto
		t.Fatalf("bogus %v", m)
	}
	// A write error stops the archive and is audited as a failure.
	err := e.svc.WriteArchive(e.ctx, &core.ArchiveTicket{UserID: u.UserID, NodeIDs: []string{u.rootID}, Format: "zip"}, &failAfter{n: 100})
	if err == nil {
		t.Fatal("no error on a failing writer")
	}
	if a := e.audit.last(core.ActArchiveDownload); a == nil || a.Outcome != core.OutcomeFailure {
		t.Fatalf("failure audit %+v", a)
	}
	if err := e.svc.WriteArchive(e.ctx, nil, io.Discard); code(err) != "invalid" {
		t.Fatalf("nil ticket: %v", err)
	}
}

// pngImage returns a w×h PNG (with transparency when alpha is set).
func pngImage(t *testing.T, w, h int, alpha bool) []byte {
	t.Helper()
	img := image.NewNRGBA(image.Rect(0, 0, w, h))
	for y := 0; y < h; y++ {
		for x := 0; x < w; x++ {
			a := uint8(255)
			if alpha && x < w/2 {
				a = 0
			}
			img.Set(x, y, color.NRGBA{R: uint8(x), G: uint8(y), B: 100, A: a})
		}
	}
	var buf bytes.Buffer
	if err := png.Encode(&buf, img); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func TestThumbnails(t *testing.T) {
	e := newEnv(t)
	u := e.user("u", core.RoleMember)
	img := e.file(u, u.rootID, "pic.png", string(pngImage(t, 640, 480, false)))
	if img.MIME != "image/png" {
		t.Fatalf("mime %q", img.MIME)
	}
	e.file(u, u.rootID, "notes.txt", "no thumbnail")
	if q := e.jobs.queued(core.JobThumbsGenerate); q != 1 {
		t.Fatalf("queued %d thumbnail jobs", q)
	}
	if _, err := e.svc.Thumbnail(e.ctx, u.Principal, img.ID); code(err) != "not_found" {
		t.Fatalf("thumb before job: %v", err)
	}
	e.jobs.drain(t, core.JobThumbsGenerate)
	n, _ := e.svc.Get(e.ctx, u.Principal, img.ID)
	if !n.HasThumb {
		t.Fatal("no thumbnail after the job")
	}
	rd, err := e.svc.Thumbnail(e.ctx, u.Principal, img.ID)
	if err != nil {
		t.Fatal(err)
	}
	cfg, format, err := image.DecodeConfig(rd)
	rd.Close()
	if err != nil || format != "jpeg" || cfg.Width != 320 || cfg.Height != 240 {
		t.Fatalf("thumb %s %dx%d %v", format, cfg.Width, cfg.Height, err)
	}
	thumbBlob := n.ThumbBlobID
	// Strangers cannot read it.
	other := e.user("o", core.RoleMember)
	if _, err := e.svc.Thumbnail(e.ctx, other.Principal, img.ID); code(err) != "not_found" {
		t.Fatalf("stranger thumb: %v", err)
	}
	// A copy shares the thumbnail; a new version resets it, the old thumbnail
	// blob survives while the copy references it.
	cp, err := e.svc.Copy(e.ctx, u.Principal, []string{img.ID}, u.rootID, "")
	if err != nil || !cp[0].HasThumb {
		t.Fatalf("copy thumb: %+v %v", cp, err)
	}
	b := e.blobs.put(t, pngImage(t, 64, 64, true))
	if _, err := e.svc.CommitFile(e.ctx, u.Principal, u.rootID, "pic.png", b, core.FileMeta{}, core.ConflictReplace); err != nil {
		t.Fatal(err)
	}
	if n, _ := e.svc.Get(e.ctx, u.Principal, img.ID); n.HasThumb {
		t.Fatal("thumbnail kept for the new version")
	}
	if !e.blobs.exists(thumbBlob) {
		t.Fatal("shared thumbnail blob deleted")
	}
	// A stale job (older version) is skipped; the current one makes a PNG.
	stale := thumbParams{NodeID: img.ID, VersionID: img.VersionID}
	if res := e.jobs.run(t, core.JobThumbsGenerate, stale).(map[string]any); res["skipped"] != "stale version" {
		t.Fatalf("stale job %v", res)
	}
	e.jobs.drain(t, core.JobThumbsGenerate)
	rd, err = e.svc.Thumbnail(e.ctx, u.Principal, img.ID)
	if err != nil {
		t.Fatal(err)
	}
	_, format, _ = image.DecodeConfig(rd)
	rd.Close()
	if format != "png" {
		t.Fatalf("alpha thumbnail format %s", format)
	}
	// Purging the copy releases the old thumbnail blob.
	if err := e.svc.Trash(e.ctx, u.Principal, []string{cp[0].ID}); err != nil {
		t.Fatal(err)
	}
	if err := e.svc.Purge(e.ctx, u.Principal, []string{cp[0].ID}); err != nil {
		t.Fatal(err)
	}
	if e.blobs.exists(thumbBlob) {
		t.Fatal("unreferenced thumbnail blob kept")
	}
	// Disabled thumbnails: nothing is queued, queued jobs are skipped.
	e.settings.set(settingThumbnails, false)
	e.file(u, u.rootID, "second.png", string(pngImage(t, 10, 10, false)))
	if q := e.jobs.queued(core.JobThumbsGenerate); q != 0 {
		t.Fatalf("queued %d with thumbnails off", q)
	}
	// A copy made before the thumbnail exists gets its own thumbnail job.
	e.settings.set(settingThumbnails, true)
	early := e.file(u, u.rootID, "early.png", string(pngImage(t, 40, 30, false)))
	early2, err := e.svc.Copy(e.ctx, u.Principal, []string{early.ID}, u.rootID, "")
	if err != nil {
		t.Fatal(err)
	}
	if q := e.jobs.drain(t, core.JobThumbsGenerate); q != 2 {
		t.Fatalf("%d thumbnail jobs for an image and its early copy", q)
	}
	for _, id := range []string{early.ID, early2[0].ID} {
		if n, _ := e.svc.Get(e.ctx, u.Principal, id); !n.HasThumb {
			t.Fatalf("no thumbnail for %s", n.Name)
		}
	}
	// Undecodable images are skipped without an error.
	bad := e.file(u, u.rootID, "bad.png", "\x89PNG\r\n\x1a\ngarbage")
	res := e.jobs.run(t, core.JobThumbsGenerate, thumbParams{NodeID: bad.ID, VersionID: bad.VersionID}).(map[string]any)
	if res["skipped"] == nil {
		t.Fatalf("bad image %v", res)
	}
}

func TestBlobLifecycle(t *testing.T) {
	e := newEnv(t)
	u := e.user("u", core.RoleMember)
	f := e.file(u, u.rootID, "f.txt", "shared content")
	blob := e.blobOf(f.ID)
	cp, err := e.svc.Copy(e.ctx, u.Principal, []string{f.ID}, u.rootID, "")
	if err != nil {
		t.Fatal(err)
	}
	if e.blobOf(cp[0].ID) != blob {
		t.Fatal("copy does not share the blob")
	}
	if e.used(u.spaceID) != 28 {
		t.Fatalf("used %d", e.used(u.spaceID))
	}
	// Purging one copy keeps the blob, purging the last one deletes it.
	for i, id := range []string{f.ID, cp[0].ID} {
		if err := e.svc.Trash(e.ctx, u.Principal, []string{id}); err != nil {
			t.Fatal(err)
		}
		if err := e.svc.Purge(e.ctx, u.Principal, []string{id}); err != nil {
			t.Fatal(err)
		}
		if want := i == 0; e.blobs.exists(blob) != want {
			t.Fatalf("after purge %d: blob exists=%v", i, !want)
		}
	}
	if e.used(u.spaceID) != 0 {
		t.Fatalf("used %d", e.used(u.spaceID))
	}

	// maintenance.blob_gc (registered because the fake store does not own a
	// GC job) deletes old unreferenced blobs, but not fresh ones or blobs of
	// open uploads.
	if _, ok := e.jobs.kinds[core.JobMaintBlobGC]; !ok {
		t.Fatal("blob_gc not registered")
	}
	orphan := e.blobs.put(t, []byte("orphan"))
	staged := e.blobs.put(t, []byte("staged"))
	now := db.Ms(e.clock.Now())
	batch := ids.New(ids.PrefixUploadBatch)
	if _, err := e.db.Exec(e.ctx, `INSERT INTO upload_batches (id, user_id, folder_id, mode, conflict, state, created_at, updated_at, expires_at)
		VALUES (?, ?, ?, 'files', 'rename', 'open', ?, ?, ?)`, batch, u.UserID, u.rootID, now, now, now); err != nil {
		t.Fatal(err)
	}
	if _, err := e.db.Exec(e.ctx, `INSERT INTO upload_files (id, batch_id, client_ref, rel_path, size, blob_id, state, created_at, updated_at)
		VALUES (?, ?, 'r', 'x', 6, ?, 'uploaded', ?, ?)`, ids.New(ids.PrefixUploadFile), batch, staged.ID, now, now); err != nil {
		t.Fatal(err)
	}
	e.clock.Advance(47 * time.Hour)
	fresh := e.blobs.put(t, []byte("fresh"))
	e.clock.Advance(2 * time.Hour)
	res := e.jobs.run(t, core.JobMaintBlobGC, nil).(map[string]any)
	if res["unreferenced_deleted"] != 1 {
		t.Fatalf("gc result %v", res)
	}
	if e.blobs.exists(orphan.ID) || !e.blobs.exists(staged.ID) || !e.blobs.exists(fresh.ID) {
		t.Fatalf("gc: orphan=%v staged=%v fresh=%v", e.blobs.exists(orphan.ID), e.blobs.exists(staged.ID), e.blobs.exists(fresh.ID))
	}
	// Once the batch is finished its rows no longer protect the blob.
	if _, err := e.db.Exec(e.ctx, `UPDATE upload_batches SET state = 'done' WHERE id = ?`, batch); err != nil {
		t.Fatal(err)
	}
	e.jobs.run(t, core.JobMaintBlobGC, nil)
	if e.blobs.exists(staged.ID) {
		t.Fatal("blob of a finished batch kept")
	}
	// The daily schedules exist.
	for _, k := range []string{core.JobMaintTrash, core.JobMaintVersions, core.JobMaintBlobGC} {
		if e.jobs.schedules[k] == "" {
			t.Errorf("no schedule for %s", k)
		}
	}
	if o := e.jobs.opts[core.JobThumbsGenerate]; o.MaxConcurrent != 2 {
		t.Errorf("thumbs concurrency %d", o.MaxConcurrent)
	}
}

// ownGCBlobs is a blob store that registers its own maintenance.blob_gc.
type ownGCBlobs struct{ *fakeBlobs }

func (ownGCBlobs) RegisterJobs(core.Jobs) error { return nil }

func TestBlobGCOwnedByBlobStore(t *testing.T) {
	e := newEnv(t)
	jobs := &fakeJobs{kinds: map[string]core.JobFunc{}, opts: map[string]core.JobOptions{}, schedules: map[string]string{}}
	if _, err := New(e.env, ownGCBlobs{e.blobs}, jobs); err != nil {
		t.Fatal(err)
	}
	if _, ok := jobs.kinds[core.JobMaintBlobGC]; ok || jobs.schedules[core.JobMaintBlobGC] != "" {
		t.Fatal("files registered maintenance.blob_gc although the blob store owns it")
	}
	for _, k := range []string{core.JobThumbsGenerate, core.JobMaintTrash, core.JobMaintVersions} {
		if _, ok := jobs.kinds[k]; !ok {
			t.Errorf("%s not registered", k)
		}
	}
}
