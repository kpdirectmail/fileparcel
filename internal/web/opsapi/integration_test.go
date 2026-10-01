package opsapi_test

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"fileparcel/internal/app"
	"fileparcel/internal/backup"
	"fileparcel/internal/config"
	"fileparcel/internal/core"
	"fileparcel/internal/db"
	"fileparcel/internal/home"
	"fileparcel/internal/web"
	"fileparcel/internal/web/opsapi"
	"fileparcel/internal/wire"
)

// client drives the real router in-process as the offline CLI does (system
// principal in the request context).
type client struct {
	t *testing.T
	h http.Handler
}

func (c client) do(method, path string, in, out any) (int, []byte) {
	c.t.Helper()
	var body io.Reader
	if in != nil {
		b, _ := json.Marshal(in)
		body = bytes.NewReader(b)
	}
	req := httptest.NewRequest(method, "/api/v1"+path, body)
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req = req.WithContext(core.WithPrincipal(req.Context(), core.SystemPrincipal(core.ViaOffline)))
	rec := httptest.NewRecorder()
	c.h.ServeHTTP(rec, req)
	if out != nil && rec.Code < 300 {
		if err := json.Unmarshal(rec.Body.Bytes(), out); err != nil {
			c.t.Fatalf("%s %s: decode %q: %v", method, path, rec.Body.Bytes(), err)
		}
	}
	return rec.Code, rec.Body.Bytes()
}

func build(t *testing.T, h *home.Home) (*app.Deps, func()) {
	t.Helper()
	d, cleanup, err := wire.Build(context.Background(), h, app.ModeOffline)
	if err != nil {
		t.Fatal(err)
	}
	return d, cleanup
}

// TestOfflineIntegration exercises the ops API over the fully wired services:
// identity, synchronous backup, listing, download, system/dashboard/doctor,
// job queueing, audit, offline restart refusal and a scheduled restore that
// ApplyPendingRestore applies before the next start.
func TestOfflineIntegration(t *testing.T) {
	ctx := context.Background()
	h, err := home.New(filepath.Join(t.TempDir(), "home"))
	if err != nil {
		t.Fatal(err)
	}
	if err := h.EnsureLayout(); err != nil {
		t.Fatal(err)
	}
	if err := config.Default(config.NewInstallID()).SaveTo(h.Config()); err != nil {
		t.Fatal(err)
	}
	d, cleanup := build(t, h)
	closed := false
	defer func() {
		if !closed {
			cleanup()
		}
	}()
	if _, err := d.Keys.Init(ctx, false, nil); err != nil {
		t.Fatal(err)
	}
	if err := wire.Start(ctx, d); err != nil {
		t.Fatal(err)
	}
	c := client{t: t, h: web.NewRouter(d)}

	var id core.BackupIdentity
	if code, body := c.do("POST", "/admin/backups/identity", nil, &id); code != 201 || id.Identity == "" {
		t.Fatalf("identity %d %s", code, body)
	}
	var b core.Backup
	if code, body := c.do("POST", "/admin/backups?wait=1", core.BackupInput{Scope: core.BackupFull, Note: "it"}, &b); code != 201 ||
		b.State != core.BackupReady {
		t.Fatalf("backup %d %s", code, body)
	}
	var page core.Page[core.Backup]
	if code, _ := c.do("GET", "/admin/backups", nil, &page); code != 200 || len(page.Items) != 1 || page.Items[0].ID != b.ID {
		t.Fatalf("list %d %+v", code, page)
	}
	code, dl := c.do("GET", "/admin/backups/"+b.ID+"/download", nil, nil)
	onDisk, _ := os.ReadFile(filepath.Join(h.BackupsDir(), b.FileName))
	if code != 200 || !bytes.Equal(dl, onDisk) || int64(len(dl)) != b.Size {
		t.Fatalf("download %d %d/%d bytes", code, len(dl), len(onDisk))
	}

	var sys opsapi.SystemResponse
	if code, body := c.do("GET", "/admin/system", nil, &sys); code != 200 || sys.KeysState != core.KeyStateUnlocked ||
		sys.Mode != "offline" || sys.SchemaVersion != db.LatestVersion() {
		t.Fatalf("system %d %s", code, body)
	}
	var dash core.Dashboard
	if code, body := c.do("GET", "/admin/dashboard", nil, &dash); code != 200 || dash.LastBackup == nil || dash.LastBackup.ID != b.ID {
		t.Fatalf("dashboard %d %s", code, body)
	}
	var rep opsapi.DoctorReport
	if code, body := c.do("GET", "/admin/system/doctor", nil, &rep); code != 200 || len(rep.Checks) == 0 {
		t.Fatalf("doctor %d %s", code, body)
	}
	for _, ch := range rep.Checks {
		switch ch.ID {
		case "keys", "backup.recent", "backup.identity", "database":
			if ch.Status != opsapi.CheckOK {
				t.Errorf("doctor %s: %s %q", ch.ID, ch.Status, ch.Message)
			}
		}
	}

	var ref core.JobRef
	if code, body := c.do("POST", "/admin/jobs/run", core.RunJobInput{Kind: core.JobMaintSessions}, &ref); code != 202 || ref.JobID == "" {
		t.Fatalf("run job %d %s", code, body)
	}
	var job core.Job
	if code, _ := c.do("GET", "/admin/jobs/"+ref.JobID, nil, &job); code != 200 || job.State != core.JobQueued {
		t.Fatalf("job %d %+v", code, job)
	}
	if code, _ := c.do("POST", "/admin/system/restart", nil, nil); code != 409 {
		t.Fatalf("offline restart %d", code)
	}
	var audit core.Page[core.AuditRecord]
	if code, _ := c.do("GET", "/admin/audit?action=backup.", nil, &audit); code != 200 || len(audit.Items) == 0 {
		t.Fatalf("audit %d %+v", code, audit)
	}

	// Schedule a restore (offline: applied at the next start), then change
	// something that the restore must undo.
	var rs opsapi.RestoreScheduled
	if code, body := c.do("POST", "/admin/backups/"+b.ID+"/restore", core.RestoreCreds{Identity: id.Identity}, &rs); code != 202 ||
		!rs.Scheduled || rs.Restarting {
		t.Fatalf("restore %d %s", code, body)
	}
	if _, err := os.Stat(h.RestoreFile()); err != nil {
		t.Fatal("restore request not written")
	}
	var later core.Backup
	if code, body := c.do("POST", "/admin/backups?wait=1", core.BackupInput{Scope: core.BackupMetadata}, &later); code != 201 {
		t.Fatalf("second backup %d %s", code, body)
	}
	cleanup()
	closed = true

	applied, err := backup.ApplyPendingRestore(ctx, h, nil)
	if err != nil || !applied {
		t.Fatalf("apply pending restore: %v %v", applied, err)
	}
	if _, err := os.Stat(h.RestoreFile()); !os.IsNotExist(err) {
		t.Fatal("restore request not removed")
	}
	d2, cleanup2 := build(t, h)
	defer cleanup2()
	got, err := d2.Backups.Get(ctx, b.ID)
	if err != nil || got.State != core.BackupReady {
		t.Fatalf("restored backup row %+v %v", got, err)
	}
	if _, err := d2.Backups.Get(ctx, later.ID); err == nil {
		t.Fatal("a row created after the restored backup survived the restore")
	}
	if d2.Keys.State() != core.KeyStateUnlocked {
		t.Fatalf("restored keys %s", d2.Keys.State())
	}
}
