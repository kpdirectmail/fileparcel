package opsapi

import (
	"bytes"
	"encoding/json"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"fileparcel/internal/app"
	"fileparcel/internal/core"
	"fileparcel/internal/events"
	"fileparcel/internal/server"
	"fileparcel/internal/web/mw"
)

func TestRouteProtection(t *testing.T) {
	te := newTestEnv(t, app.ModeNetwork)
	te.backups.items = []core.Backup{{ID: "bak_1", State: core.BackupReady, FileName: "fp-a.fpbak"}}
	te.backups.file = filepath.Join(t.TempDir(), "b.fpbak")
	if err := os.WriteFile(te.backups.file, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	type route struct {
		method, path string
		elevated     bool
	}
	routes := []route{
		{"GET", "/admin/backups", false},
		{"POST", "/admin/backups", false},
		{"GET", "/admin/backups/config", false},
		{"GET", "/admin/backups/bak_1", false},
		{"POST", "/admin/backups/bak_1/verify", false},
		{"GET", "/admin/jobs", false},
		{"GET", "/admin/jobs/schedules", false},
		{"GET", "/admin/jobs/kinds", false},
		{"GET", "/admin/jobs/job_x", false},
		{"POST", "/admin/jobs/job_x/cancel", false},
		{"POST", "/admin/jobs/run", false},
		{"GET", "/admin/system", false},
		{"GET", "/admin/system/doctor", false},
		{"GET", "/admin/system/logs", false},
		{"GET", "/admin/dashboard", false},
		{"GET", "/admin/audit", false},
		{"GET", "/admin/audit/verify", false},
		{"GET", "/admin/audit/export", false},
		{"DELETE", "/admin/backups/bak_1", true},
		{"GET", "/admin/backups/bak_1/download", true},
		{"POST", "/admin/backups/bak_1/restore", true},
		{"PUT", "/admin/backups/config", true},
		{"POST", "/admin/backups/identity", true},
		{"POST", "/admin/backups/identity/export", true},
		{"POST", "/admin/backups/import", true},
		{"POST", "/admin/system/restart", true},
	}
	for _, rt := range routes {
		t.Run(rt.method+" "+rt.path, func(t *testing.T) {
			if r := te.do(rt.method, rt.path, "", nil); r.code != http.StatusUnauthorized {
				t.Errorf("anonymous: %d", r.code)
			}
			if r := te.do(rt.method, rt.path, "mfa", nil); r.code != http.StatusUnauthorized || r.errCode() != "mfa_required" {
				t.Errorf("mfa pending: %d %s", r.code, r.errCode())
			}
			if r := te.do(rt.method, rt.path, "alice", nil); r.code != http.StatusForbidden {
				t.Errorf("member: %d", r.code)
			}
			if r := te.do(rt.method, rt.path, "token", nil); r.code != http.StatusForbidden {
				t.Errorf("token without admin scope: %d", r.code)
			}
			r := te.do(rt.method, rt.path, "admin", nil)
			if rt.elevated {
				if r.code != http.StatusForbidden || r.errCode() != "elevation_required" {
					t.Errorf("admin without step-up: %d %s", r.code, r.errCode())
				}
			} else if r.code == http.StatusForbidden || r.code == http.StatusUnauthorized {
				t.Errorf("admin: %d %s", r.code, r.body)
			}
			if r := te.do(rt.method, rt.path, "elevated", nil); r.code == http.StatusForbidden || r.code == http.StatusUnauthorized {
				t.Errorf("elevated admin: %d %s", r.code, r.body)
			}
			if rt.method == "GET" {
				if cc := te.do(rt.method, rt.path, "elevated", nil).hdr.Get("Cache-Control"); cc != "no-store" {
					t.Errorf("Cache-Control %q", cc)
				}
			}
		})
	}
	// F routes: anonymous 401, members allowed.
	for _, p := range []string{"/jobs/job_x"} {
		if r := te.do("GET", p, "", nil); r.code != http.StatusUnauthorized {
			t.Errorf("%s anonymous: %d", p, r.code)
		}
	}
}

func TestBackupEndpoints(t *testing.T) {
	te := newTestEnv(t, app.ModeNetwork)
	fin := te.now.Add(-time.Hour)
	te.backups.items = []core.Backup{{ID: "bak_1", State: core.BackupReady, FileName: "fp-abc-20260101-000000-full.fpbak",
		SHA256: strings.Repeat("ab", 32), FinishedAt: &fin, Scope: core.BackupFull}}
	te.backups.file = filepath.Join(t.TempDir(), "file.fpbak")
	content := bytes.Repeat([]byte("0123456789"), 1000)
	if err := os.WriteFile(te.backups.file, content, 0o600); err != nil {
		t.Fatal(err)
	}

	var page core.Page[core.Backup]
	r := te.do("GET", "/admin/backups", "admin", nil)
	r.json(t, &page)
	if r.code != 200 || len(page.Items) != 1 {
		t.Fatalf("list %d %s", r.code, r.body)
	}
	r = te.do("POST", "/admin/backups", "admin", jsonBody(core.BackupInput{Scope: "metadata", Note: "n"}))
	var ref core.JobRef
	r.json(t, &ref)
	if r.code != http.StatusAccepted || ref.JobID != "job_create" || te.backups.lastInput.Scope != "metadata" {
		t.Fatalf("create %d %s", r.code, r.body)
	}
	if r := te.do("POST", "/admin/backups", "admin", strings.NewReader(`{"scope":"full","bogus":1}`)); r.code != 422 {
		t.Fatalf("unknown field accepted: %d", r.code)
	}
	r = te.do("POST", "/admin/backups?wait=1", "admin", jsonBody(core.BackupInput{Scope: "full"}))
	if r.code != http.StatusCreated || !te.backups.called("createsync") {
		t.Fatalf("create sync %d %s", r.code, r.body)
	}
	if r := te.do("GET", "/admin/backups/bak_1", "admin", nil); r.code != 200 {
		t.Fatalf("get %d", r.code)
	}
	if r := te.do("GET", "/admin/backups/bak_nope", "admin", nil); r.code != 404 {
		t.Fatalf("get missing %d", r.code)
	}
	// Verify: body or query.
	if r := te.do("POST", "/admin/backups/bak_1/verify?deep=1", "admin", nil); r.code != 202 || !te.backups.lastVerifyD {
		t.Fatalf("verify ?deep %d %v", r.code, te.backups.lastVerifyD)
	}
	if r := te.do("POST", "/admin/backups/bak_1/verify", "admin", jsonBody(VerifyInput{})); r.code != 202 || te.backups.lastVerifyD {
		t.Fatalf("verify shallow %d", r.code)
	}
	if r := te.do("POST", "/admin/backups/bak_1/verify", "admin", jsonBody(VerifyInput{Deep: true})); r.code != 202 || !te.backups.lastVerifyD {
		t.Fatalf("verify body deep %d", r.code)
	}

	// Download: full, range, HEAD; audited for GET only.
	r = te.do("GET", "/admin/backups/bak_1/download", "elevated", nil)
	if r.code != 200 || !bytes.Equal(r.body, content) {
		t.Fatalf("download %d len %d", r.code, len(r.body))
	}
	if cc := r.hdr.Get("Cache-Control"); cc != "no-store" {
		t.Fatalf("download Cache-Control %q", cc)
	}
	if cd := r.hdr.Get("Content-Disposition"); !strings.HasPrefix(cd, "attachment") || !strings.Contains(cd, "fp-abc-") {
		t.Fatalf("Content-Disposition %q", cd)
	}
	r = te.do("GET", "/admin/backups/bak_1/download", "elevated", nil, "Range", "bytes=10-19")
	if r.code != http.StatusPartialContent || string(r.body) != "0123456789" {
		t.Fatalf("range %d %q", r.code, r.body)
	}
	if n := te.audit.count(core.ActBackupDownload); n != 2 {
		t.Fatalf("download audits %d", n)
	}
	r = te.do("HEAD", "/admin/backups/bak_1/download", "elevated", nil)
	if r.code != 200 || te.audit.count(core.ActBackupDownload) != 2 {
		t.Fatalf("HEAD %d audits %d", r.code, te.audit.count(core.ActBackupDownload))
	}

	// Delete, restore.
	if r := te.do("DELETE", "/admin/backups/bak_1", "elevated", nil); r.code != 204 || !te.backups.called("delete:bak_1") {
		t.Fatalf("delete %d", r.code)
	}
	r = te.do("POST", "/admin/backups/bak_1/restore", "elevated", jsonBody(core.RestoreCreds{Passphrase: "correct horse battery"}))
	var rs RestoreScheduled
	r.json(t, &rs)
	if r.code != 202 || !rs.Scheduled || !rs.Restarting || te.backups.lastCreds.Passphrase != "correct horse battery" {
		t.Fatalf("restore %d %s", r.code, r.body)
	}

	// Import: raw body and multipart.
	payload := []byte("age-encryption.org/v1\n-> X25519 abc\n")
	r = te.do("POST", "/admin/backups/import", "elevated", bytes.NewReader(payload), "Content-Type", "application/octet-stream")
	if r.code != 201 || !bytes.Equal(te.backups.lastImport, payload) {
		t.Fatalf("import raw %d %s", r.code, r.body)
	}
	var mp bytes.Buffer
	mwr := multipart.NewWriter(&mp)
	_ = mwr.WriteField("note", "ignored")
	fw, _ := mwr.CreateFormFile("file", "x.fpbak")
	_, _ = fw.Write(payload)
	_ = mwr.Close()
	te.backups.lastImport = nil
	r = te.do("POST", "/admin/backups/import", "elevated", &mp, "Content-Type", mwr.FormDataContentType())
	if r.code != 201 || !bytes.Equal(te.backups.lastImport, payload) {
		t.Fatalf("import multipart %d %s", r.code, r.body)
	}
	var empty bytes.Buffer
	mwr = multipart.NewWriter(&empty)
	_ = mwr.WriteField("note", "no file")
	_ = mwr.Close()
	if r := te.do("POST", "/admin/backups/import", "elevated", &empty, "Content-Type", mwr.FormDataContentType()); r.code != 422 {
		t.Fatalf("import without file %d", r.code)
	}
	// A body above the default 1 MiB API limit is accepted by the import route.
	big := append([]byte("age-encryption.org/v1\n"), bytes.Repeat([]byte{1}, 3<<20)...)
	if r := te.do("POST", "/admin/backups/import", "elevated", bytes.NewReader(big), "Content-Type", "application/octet-stream"); r.code != 201 {
		t.Fatalf("large import %d %s", r.code, r.body)
	}

	// Config and identity.
	var cfg core.BackupConfig
	r = te.do("GET", "/admin/backups/config", "admin", nil)
	r.json(t, &cfg)
	if r.code != 200 || !cfg.Enabled || cfg.ScheduleMeta != "0 3 * * *" {
		t.Fatalf("config %d %s", r.code, r.body)
	}
	// BackupConfig.MarshalJSON never renders the passphrase, so build the
	// input object by hand (as the web client does).
	pass := "a long enough passphrase"
	cfg.Encryption = core.BackupPassphrase
	var in map[string]any
	raw, _ := json.Marshal(cfg)
	_ = json.Unmarshal(raw, &in)
	in["passphrase"] = pass
	delete(in, "has_identity")
	delete(in, "has_passphrase")
	r = te.do("PUT", "/admin/backups/config", "elevated", jsonBody(in))
	if r.code != 200 || bytes.Contains(r.body, []byte(pass)) || !te.backups.called("setconfig") {
		t.Fatalf("put config %d %s", r.code, r.body)
	}
	var out core.BackupConfig
	r.json(t, &out)
	if !out.HasPassphrase || out.Encryption != core.BackupPassphrase {
		t.Fatalf("put config result %+v", out)
	}
	var id core.BackupIdentity
	r = te.do("POST", "/admin/backups/identity", "elevated", nil)
	r.json(t, &id)
	if r.code != 201 || id.Recipient != "age1recipient" || id.Identity == "" {
		t.Fatalf("identity %d %s", r.code, r.body)
	}
	r = te.do("POST", "/admin/backups/identity/export", "elevated", nil)
	if r.code != 200 || !te.backups.called("export") {
		t.Fatalf("export %d", r.code)
	}

	// Without a backup service → 503.
	te.d.Backups = nil
	if r := te.do("GET", "/admin/backups", "admin", nil); r.code != 503 {
		t.Fatalf("no service %d", r.code)
	}
}

func TestRestoreScheduledOfflineDoesNotRestart(t *testing.T) {
	te := newTestEnv(t, app.ModeOffline)
	te.backups.items = []core.Backup{{ID: "bak_1", State: core.BackupReady}}
	var rs RestoreScheduled
	r := te.do("POST", "/admin/backups/bak_1/restore", "system", jsonBody(core.RestoreCreds{}))
	r.json(t, &rs)
	if r.code != 202 || !rs.Scheduled || rs.Restarting {
		t.Fatalf("%d %+v", r.code, rs)
	}
}

func TestJobEndpoints(t *testing.T) {
	te := newTestEnv(t, app.ModeNetwork)
	te.jobs.add(core.Job{ID: "job_alice", Kind: core.JobUploadZip, State: core.JobRunning, CreatedBy: "usr_alice"})
	te.jobs.add(core.Job{ID: "job_sys", Kind: core.JobMaintSessions, State: core.JobSucceeded})
	te.jobs.schedules = []core.JobSchedule{{Name: "maintenance.sessions", Cron: "15 * * * *", Kind: core.JobMaintSessions, Enabled: true}}

	// /jobs/{id}: own jobs only (404 for others, no existence leak); admins any.
	if r := te.do("GET", "/jobs/job_alice", "alice", nil); r.code != 200 {
		t.Fatalf("own job %d", r.code)
	}
	if r := te.do("GET", "/jobs/job_alice", "bob", nil); r.code != 404 {
		t.Fatalf("other's job %d", r.code)
	}
	if r := te.do("GET", "/jobs/job_sys", "alice", nil); r.code != 404 {
		t.Fatalf("system job for member %d", r.code)
	}
	if r := te.do("GET", "/jobs/job_sys", "admin", nil); r.code != 200 {
		t.Fatalf("admin any job %d", r.code)
	}
	if r := te.do("GET", "/jobs/job_sys", "token", nil); r.code != 404 {
		t.Fatalf("admin token without admin scope %d", r.code)
	}
	if r := te.do("GET", "/jobs/job_nope", "alice", nil); r.code != 404 {
		t.Fatalf("missing %d", r.code)
	}

	var page core.Page[core.Job]
	r := te.do("GET", "/admin/jobs?kind="+core.JobUploadZip, "admin", nil)
	r.json(t, &page)
	if r.code != 200 || len(page.Items) != 1 {
		t.Fatalf("list %d %s", r.code, r.body)
	}
	var scs []core.JobSchedule
	r = te.do("GET", "/admin/jobs/schedules", "admin", nil)
	r.json(t, &scs)
	if len(scs) != 1 {
		t.Fatalf("schedules %s", r.body)
	}
	te.jobs.schedules = nil
	if r := te.do("GET", "/admin/jobs/schedules", "admin", nil); string(bytes.TrimSpace(r.body)) != "[]" {
		t.Fatalf("empty schedules %s", r.body)
	}
	var kinds []string
	te.do("GET", "/admin/jobs/kinds", "admin", nil).json(t, &kinds)
	if !slices.Contains(kinds, core.JobMaintSessions) || slices.Contains(kinds, core.JobMaintTrash) || !slices.IsSorted(kinds) {
		t.Fatalf("kinds %v", kinds)
	}

	if r := te.do("POST", "/admin/jobs/job_alice/cancel", "admin", nil); r.code != 204 || !slices.Contains(te.jobs.canceled, "job_alice") {
		t.Fatalf("cancel %d", r.code)
	}
	if r := te.do("POST", "/admin/jobs/job_nope/cancel", "admin", nil); r.code != 404 {
		t.Fatalf("cancel missing %d", r.code)
	}

	run := func(in any) resp { return te.do("POST", "/admin/jobs/run", "admin", jsonBody(in)) }
	if r := run(core.RunJobInput{Kind: core.JobMaintSessions}); r.code != 202 || te.jobs.enqueued[len(te.jobs.enqueued)-1] != core.JobMaintSessions {
		t.Fatalf("run %d %s", r.code, r.body)
	}
	// The job context carries the plain system principal, so this entry and
	// jobs.created_by are the only record of who asked for the run.
	if n := len(te.audit.entries); n == 0 {
		t.Fatal("POST /admin/jobs/run was not audited")
	} else {
		e := te.audit.entries[n-1]
		det, _ := e.Details.(map[string]any)
		if e.Action != core.ActJobRun || e.TargetType != "job" || e.TargetID == "" || det["kind"] != core.JobMaintSessions {
			t.Fatalf("job.run audit entry %+v", e)
		}
	}
	if r := run(core.RunJobInput{Kind: core.JobUploadZip}); r.code != 422 {
		t.Fatalf("run not allowed %d", r.code)
	}
	if r := run(core.RunJobInput{Kind: core.JobMaintTrash}); r.code != 422 {
		t.Fatalf("run unregistered %d", r.code)
	}
	if r := run(core.RunJobInput{Kind: core.JobMaintSessions, Params: json.RawMessage(`{"x":1}`)}); r.code != 422 {
		t.Fatalf("run with params %d", r.code)
	}
	if r := run(core.RunJobInput{Kind: core.JobMaintSessions, Params: json.RawMessage(`{}`)}); r.code != 202 {
		t.Fatalf("run with empty params %d", r.code)
	}
	if r := run(core.RunJobInput{Kind: core.JobBackupCreate, Params: json.RawMessage(`{"scope":"metadata"}`)}); r.code != 202 ||
		te.backups.lastInput.Scope != "metadata" {
		t.Fatalf("run backup.create %d", r.code)
	}
	if r := run(core.RunJobInput{Kind: core.JobBackupCreate, Params: json.RawMessage(`{"nope":1}`)}); r.code != 422 {
		t.Fatalf("run backup.create bad params %d", r.code)
	}
	if r := run(core.RunJobInput{Kind: core.JobBackupVerify, Params: json.RawMessage(`{"id":"bak_1","deep":true}`)}); r.code != 202 ||
		!te.backups.called("verify:bak_1") || !te.backups.lastVerifyD {
		t.Fatalf("run backup.verify %d", r.code)
	}
}

func TestSystemRestartAndLogs(t *testing.T) {
	te := newTestEnv(t, app.ModeNetwork)
	var info SystemResponse
	r := te.do("GET", "/admin/system", "admin", nil)
	r.json(t, &info)
	if r.code != 200 || info.Version != "v9" || info.GoVersion == "" || info.Home != te.h.Dir() || info.KeysState != core.KeyStateUnlocked ||
		info.KeyMode != core.KeyModePlain || info.SchemaVersion < 1 || info.DBBytes == 0 || info.Certs == nil || info.MDNS == nil ||
		info.Network == nil || info.Mode != "network" || info.Goroutines == 0 || info.RestartRequired == nil {
		t.Fatalf("system %d %s", r.code, r.body)
	}

	ch, cancel := te.bus.Subscribe(events.TopicSystemRestart)
	defer cancel()
	if r := te.do("POST", "/admin/system/restart", "elevated", nil); r.code != 202 {
		t.Fatalf("restart %d %s", r.code, r.body)
	}
	select {
	case <-ch:
	case <-time.After(time.Second):
		t.Fatal("no system.restart event")
	}
	if !te.audit.has(core.ActSystemRestart) {
		t.Fatal("restart not audited")
	}
	te.d.Mode = app.ModeOffline
	if r := te.do("POST", "/admin/system/restart", "elevated", nil); r.code != 409 {
		t.Fatalf("offline restart %d", r.code)
	}

	// Logs. A missing file says so, and whether file logging is on at all
	// (log.file = false: the lines are in journald / launchd's log instead).
	var lt LogTail
	r = te.do("GET", "/admin/system/logs", "admin", nil)
	r.json(t, &lt)
	if r.code != 200 || len(lt.Lines) != 0 || !lt.Missing || !lt.FileLogging {
		t.Fatalf("logs without file %d %s", r.code, r.body)
	}
	te.d.Config.Log.File = false
	lt = LogTail{}
	te.do("GET", "/admin/system/logs", "admin", nil).json(t, &lt)
	if !lt.Missing || lt.FileLogging {
		t.Fatalf("file logging off: %+v", lt)
	}
	te.d.Config.Log.File = true
	var sb strings.Builder
	for i := 1; i <= 50; i++ {
		sb.WriteString("line " + strings.Repeat("x", i%7) + "\n")
	}
	sb.WriteString("last line\n")
	if err := os.WriteFile(te.h.LogFile(), []byte(sb.String()), 0o600); err != nil {
		t.Fatal(err)
	}
	r = te.do("GET", "/admin/system/logs?n=2", "admin", nil)
	lt = LogTail{}
	r.json(t, &lt)
	if len(lt.Lines) != 2 || lt.Lines[1] != "last line" || !lt.Truncated || lt.Missing || !lt.FileLogging {
		t.Fatalf("logs %+v", lt)
	}
	for _, bad := range []string{"0", "-3", "x"} {
		if r := te.do("GET", "/admin/system/logs?n="+bad, "admin", nil); r.code != 422 {
			t.Fatalf("n=%s → %d", bad, r.code)
		}
	}
}

func TestTailFile(t *testing.T) {
	dir := t.TempDir()
	write := func(s string) string {
		p := filepath.Join(dir, "f")
		if err := os.WriteFile(p, []byte(s), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	long := strings.Repeat("a", 100) + "\n" + strings.Repeat("b", 100) + "\nend\n"
	tests := []struct {
		name      string
		content   string
		n         int
		scan      int64
		want      []string
		truncated bool
	}{
		{"empty", "", 5, 1 << 20, nil, false},
		{"fewer", "a\nb\n", 5, 1 << 20, []string{"a", "b"}, false},
		{"exact", "a\nb\nc\n", 3, 1 << 20, []string{"a", "b", "c"}, false},
		{"more", "a\nb\nc\nd\n", 2, 1 << 20, []string{"c", "d"}, true},
		{"no trailing newline", "a\nb", 5, 1 << 20, []string{"a", "b"}, false},
		{"scan limit drops partial first line", long, 10, 120, []string{strings.Repeat("b", 100), "end"}, true},
		{"scan limit inside the last line", long, 10, 3, nil, true},
		{"invalid utf8", "ok\n\xff\xfe\n", 5, 1 << 20, []string{"ok", "�"}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, tr, err := tailFile(write(tt.content), tt.n, tt.scan)
			if err != nil {
				t.Fatal(err)
			}
			if !slices.Equal(got, tt.want) || tr != tt.truncated {
				t.Fatalf("got %q %v, want %q %v", got, tr, tt.want, tt.truncated)
			}
		})
	}
	if _, _, err := tailFile(filepath.Join(dir, "missing"), 1, 10); !os.IsNotExist(err) {
		t.Fatalf("missing file: %v", err)
	}
}

func TestDashboard(t *testing.T) {
	te := newTestEnv(t, app.ModeNetwork)
	te.users.users = []core.User{{ID: "usr_admin", Username: "admin", Role: core.RoleAdmin, Status: "active"}}
	ctx := t.Context()
	if _, err := te.d.DB.Exec(ctx, `INSERT INTO jobs (id, kind, state, params, created_at, finished_at) VALUES
		('job_a', 'x', 'running', '{}', 1, NULL), ('job_b', 'y', 'failed', '{}', 1, ?)`, te.now.UnixMilli()); err != nil {
		t.Fatal(err)
	}
	var dash core.Dashboard
	r := te.do("GET", "/admin/dashboard", "admin", nil)
	r.json(t, &dash)
	if r.code != 200 || dash.Users != 1 || dash.RunningJobs != 1 || dash.FailedJobs24h != 1 || dash.KeysState != core.KeyStateUnlocked ||
		dash.Cert == nil || len(dash.RecentAudit) != 1 || dash.Version != "v9" || dash.LastBackup != nil {
		t.Fatalf("dashboard %d %s", r.code, r.body)
	}
	hasWarn := func(sub string) bool {
		for _, w := range dash.Warnings {
			if strings.Contains(w, sub) {
				return true
			}
		}
		return false
	}
	if !hasWarn("No backup") || !hasWarn("failed in the last 24 hours") {
		t.Fatalf("warnings %v", dash.Warnings)
	}
	// Locked keys, expiring certificate, stale & failed backup, access "any".
	te.keys.state = core.KeyStateLocked
	te.certs.st.Leaf.NotBefore = te.now.Add(-394 * 24 * time.Hour) // a 397-day leaf
	te.certs.st.Leaf.NotAfter = te.now.Add(3 * 24 * time.Hour)
	te.net.pol.Mode = core.AccessAny
	old := te.now.Add(-20 * 24 * time.Hour)
	te.backups.items = []core.Backup{
		{ID: "bak_2", State: core.BackupFailed, Error: "disk full", CreatedAt: te.now.Add(-time.Hour)},
		{ID: "bak_1", State: core.BackupReady, CreatedAt: old},
	}
	dash = core.Dashboard{}
	te.do("GET", "/admin/dashboard", "admin", nil).json(t, &dash)
	for _, want := range []string{"locked", "certificate expires in 3 days", "20 days old", "disk full", "any address"} {
		if !hasWarn(want) {
			t.Errorf("missing warning %q in %v", want, dash.Warnings)
		}
	}
	if dash.LastBackup == nil || dash.LastBackup.ID != "bak_1" {
		t.Fatalf("last backup %+v", dash.LastBackup)
	}
}

// The dashboard's backup warnings are about this server's own, usable
// backups: an import (dated "now" when it cannot be decrypted) must not hide
// a failing schedule, a backup that failed verification is not the last
// good one, and a list that cannot be read is not "no backup yet".
func TestDashboardBackupWarnings(t *testing.T) {
	te := newTestEnv(t, app.ModeNetwork)
	get := func() core.Dashboard {
		t.Helper()
		var dash core.Dashboard
		if r := te.do("GET", "/admin/dashboard", "admin", nil); r.code != 200 {
			t.Fatalf("dashboard %d %s", r.code, r.body)
		} else {
			r.json(t, &dash)
		}
		return dash
	}
	hasWarn := func(d core.Dashboard, sub string) bool {
		for _, w := range d.Warnings {
			if strings.Contains(w, sub) {
				return true
			}
		}
		return false
	}
	te.backups.items = []core.Backup{
		{ID: "bak_imp", State: core.BackupReady, Trigger: core.TriggerImport, CreatedAt: te.now},
		{ID: "bak_f", State: core.BackupFailed, Trigger: core.TriggerSchedule, Error: "disk full", CreatedAt: te.now.Add(-time.Hour)},
		{ID: "bak_old", State: core.BackupReady, Trigger: core.TriggerSchedule, CreatedAt: te.now.Add(-30 * 24 * time.Hour)},
	}
	dash := get()
	if !hasWarn(dash, "The last backup is 30 days old") || !hasWarn(dash, "The last backup failed: disk full") ||
		dash.LastBackup == nil || dash.LastBackup.ID != "bak_old" {
		t.Errorf("an import hides the schedule: last %+v, warnings %v", dash.LastBackup, dash.Warnings)
	}
	te.backups.items = te.backups.items[:1]
	if dash = get(); !hasWarn(dash, "No backup has been made yet") || dash.LastBackup != nil {
		t.Errorf("only an import: last %+v, warnings %v", dash.LastBackup, dash.Warnings)
	}

	no := false
	te.backups.items = []core.Backup{
		{ID: "bak_2", State: core.BackupReady, CreatedAt: te.now.Add(-time.Hour), VerifyOK: &no, Error: "verification failed: the backup file is missing"},
		{ID: "bak_1", State: core.BackupReady, CreatedAt: te.now.Add(-48 * time.Hour)},
	}
	if dash = get(); dash.LastBackup == nil || dash.LastBackup.ID != "bak_1" ||
		!hasWarn(dash, "failed verification: the backup file is missing") {
		t.Errorf("failed verification: last %+v, warnings %v", dash.LastBackup, dash.Warnings)
	}
	te.backups.items = te.backups.items[:1]
	if dash = get(); dash.LastBackup != nil || !hasWarn(dash, "failed verification") || hasWarn(dash, "No backup has been made yet") {
		t.Errorf("only a failed verification: last %+v, warnings %v", dash.LastBackup, dash.Warnings)
	}

	te.backups.listErr = core.Errorf(core.ErrUnavailable, "database is locked")
	dash = get()
	if !hasWarn(dash, "backup list could not be read") || hasWarn(dash, "No backup has been made yet") {
		t.Errorf("unreadable list: warnings %v", dash.Warnings)
	}
	if v, _ := dash.Extra["backup_unavailable"].(bool); !v {
		t.Errorf("extra.backup_unavailable = %v", dash.Extra["backup_unavailable"])
	}
}

// supervisor() names what server.Supervised() detects: the System page must
// not say "launchd" for a terminal app's XPC_SERVICE_NAME, nor "nothing"
// for FILEPARCEL_SUPERVISED=1.
func TestSupervisorMatchesServer(t *testing.T) {
	if _, err := os.Stat("/.dockerenv"); err == nil {
		t.Skip("inside Docker: supervisor() always answers docker")
	}
	for _, k := range []string{"FILEPARCEL_SUPERVISED", "INVOCATION_ID", "NOTIFY_SOCKET", "XPC_SERVICE_NAME"} {
		t.Setenv(k, "")
	}
	tests := []struct{ key, val, want string }{
		{"", "", ""},
		{"XPC_SERVICE_NAME", "application.com.googlecode.iterm2.1234", ""},
		{"XPC_SERVICE_NAME", "0", ""},
		{"XPC_SERVICE_NAME", "com.fileparcel.server", "launchd"},
		{"FILEPARCEL_SUPERVISED", "1", "external"},
		{"FILEPARCEL_SUPERVISED", "0", ""},
		{"INVOCATION_ID", "abc", "systemd"},
		{"NOTIFY_SOCKET", "/run/systemd/notify", "systemd"},
	}
	for _, tt := range tests {
		if tt.key != "" {
			t.Setenv(tt.key, tt.val)
		}
		if got := supervisor(); got != tt.want || (got != "") != server.Supervised() {
			t.Errorf("%s=%q: supervisor() = %q (want %q), server.Supervised() = %v", tt.key, tt.val, got, tt.want, server.Supervised())
		}
		if tt.key != "" {
			t.Setenv(tt.key, "")
		}
	}
}

func TestAuditEndpoints(t *testing.T) {
	te := newTestEnv(t, app.ModeNetwork)
	r := te.do("GET", "/admin/audit?action=auth.&outcome=failure&since=24h&until=2026-09-01T00:00:00Z&q=bob&limit=5&desc=true", "admin", nil)
	if r.code != 200 {
		t.Fatalf("query %d %s", r.code, r.body)
	}
	q := te.audit.lastQ
	if q.Action != "auth." || q.Outcome != "failure" || q.Q != "bob" || q.Limit != 5 || q.Since == nil || q.Until == nil ||
		te.now.Sub(*q.Since) != 24*time.Hour {
		t.Fatalf("parsed query %+v", q)
	}
	for _, bad := range []string{"outcome=maybe", "since=yesterday", "until=-5h", "q=" + strings.Repeat("x", 201)} {
		if r := te.do("GET", "/admin/audit?"+bad, "admin", nil); r.code != 422 {
			t.Errorf("%s → %d", bad, r.code)
		}
	}
	var v core.AuditVerify
	te.do("GET", "/admin/audit/verify", "admin", nil).json(t, &v)
	if !v.OK {
		t.Fatal("verify")
	}
	r = te.do("GET", "/admin/audit/export?format=csv", "admin", nil)
	if r.code != 200 || !strings.HasPrefix(r.hdr.Get("Content-Type"), "text/csv") ||
		!strings.Contains(r.hdr.Get("Content-Disposition"), ".csv") || !strings.Contains(string(r.body), "auth.login") {
		t.Fatalf("csv %d %v %s", r.code, r.hdr, r.body)
	}
	r = te.do("GET", "/admin/audit/export?format=jsonl", "admin", nil)
	if r.code != 200 || r.hdr.Get("Content-Type") != "application/x-ndjson" {
		t.Fatalf("jsonl %d %v", r.code, r.hdr)
	}
	if r := te.do("GET", "/admin/audit/export?format=xml", "admin", nil); r.code != 422 {
		t.Fatalf("bad format %d", r.code)
	}
	te.audit.failExp = true
	r = te.do("GET", "/admin/audit/export", "admin", nil)
	if r.code != 503 || r.hdr.Get("Content-Disposition") != "" {
		t.Fatalf("failed export %d %v", r.code, r.hdr)
	}
}

// An export that fails after rows went out aborts the connection: a clean
// end would pass the truncated file (which ends on a whole row) off as the
// complete audit log, and `audit export -o` would keep it.
func TestAuditExportAbort(t *testing.T) {
	te := newTestEnv(t, app.ModeNetwork)
	te.audit.failMid = true
	srv := httptest.NewServer(mw.Recover(te.handler))
	defer srv.Close()
	for _, format := range []string{"csv", "jsonl"} {
		req, _ := http.NewRequest("GET", srv.URL+"/api/v1/admin/audit/export?format="+format, nil)
		req.Header.Set("X-Test-As", "admin")
		resp, err := srv.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		if resp.StatusCode != 200 {
			t.Fatalf("%s: status %d", format, resp.StatusCode)
		}
		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err == nil {
			t.Fatalf("%s: a truncated export (%d bytes) was delivered as complete", format, len(body))
		}
	}
}

func TestParseWhen(t *testing.T) {
	now := time.Date(2026, 9, 19, 12, 0, 0, 0, time.UTC)
	tests := []struct {
		in   string
		want time.Time
		err  bool
	}{
		{"", time.Time{}, false},
		{"2026-01-02T03:04:05Z", time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC), false},
		{"2026-01-02", time.Date(2026, 1, 2, 0, 0, 0, 0, time.UTC), false},
		{"90m", now.Add(-90 * time.Minute), false},
		{"-1h", time.Time{}, true},
		{"soon", time.Time{}, true},
	}
	for _, tt := range tests {
		got, err := parseWhen(tt.in, "since", now)
		if (err != nil) != tt.err {
			t.Errorf("%q: err %v", tt.in, err)
			continue
		}
		if tt.want.IsZero() {
			if got != nil {
				t.Errorf("%q: %v", tt.in, got)
			}
		} else if got == nil || !got.Equal(tt.want) {
			t.Errorf("%q: %v want %v", tt.in, got, tt.want)
		}
	}
}

func TestHelpers(t *testing.T) {
	for in, want := range map[int64]string{0: "0 B", 1023: "1023 B", 1024: "1.0 KiB", 5 << 30: "5.0 GiB"} {
		if got := human(in); got != want {
			t.Errorf("human(%d) = %q", in, got)
		}
	}
	day := 24 * time.Hour
	for in, want := range map[time.Duration]string{-3 * day: "3 days ago (expired)", -25 * time.Hour: "1 day ago (expired)",
		-time.Hour: "today (already expired)",
		time.Hour:  "today", day + time.Hour: "tomorrow", 10 * day: "in 10 days"} {
		if got := when(in); got != want {
			t.Errorf("when(%v) = %q", in, got)
		}
	}
	for in, want := range map[time.Duration]string{
		time.Second: "just now", 59 * time.Second: "just now",
		time.Minute: "1 minute ago", 90 * time.Second: "1 minute ago", 5 * time.Minute: "5 minutes ago",
		time.Hour: "1 hour ago", 90 * time.Minute: "1 hour ago", 3 * time.Hour: "3 hours ago",
		36 * time.Hour: "36 hours ago", 2 * day: "2 days ago", 3 * day: "3 days ago"} {
		if got := ago(in); got != want {
			t.Errorf("ago(%v) = %q", in, got)
		}
	}
	if got := truncateText("héllo wörld", 2); got != "h…" {
		t.Errorf("truncate %q", got)
	}
	for _, s := range []string{"1", "true", "YES", "on"} {
		if !truthy(s) {
			t.Errorf("truthy(%q)", s)
		}
	}
	if truthy("0") || truthy("") {
		t.Error("truthy false values")
	}
}

// A database that does not answer must not make the dashboard look healthier
// than a working one. Every aggregate is best effort and stays at zero, so
// the "N background jobs failed" warning silently disappeared and an
// all-zero page reported a quiet, healthy server.
func TestDashboardSaysWhenStatsCannotBeRead(t *testing.T) {
	te := newTestEnv(t, app.ModeNetwork)
	ctx := t.Context()
	if _, err := te.d.DB.Exec(ctx, `INSERT INTO jobs (id, kind, state, params, created_at, finished_at) VALUES
		('job_r1', 'x', 'running', '{}', 1, NULL), ('job_r2', 'x', 'running', '{}', 1, NULL),
		('job_r3', 'x', 'running', '{}', 1, NULL), ('job_f1', 'y', 'failed', '{}', 1, ?)`, te.now.UnixMilli()); err != nil {
		t.Fatal(err)
	}
	hasWarn := func(d *core.Dashboard, sub string) bool {
		for _, w := range d.Warnings {
			if strings.Contains(w, sub) {
				return true
			}
		}
		return false
	}
	var dash core.Dashboard
	te.do("GET", "/admin/dashboard", "admin", nil).json(t, &dash)
	if dash.RunningJobs != 3 || dash.FailedJobs24h != 1 || !hasWarn(&dash, "failed in the last 24 hours") {
		t.Fatalf("healthy dashboard %+v", dash)
	}
	if v, _ := dash.Extra["stats_unavailable"].(bool); v {
		t.Errorf("stats_unavailable set on a healthy dashboard")
	}

	if err := te.d.DB.Close(); err != nil {
		t.Fatal(err)
	}
	dash = core.Dashboard{}
	r := te.do("GET", "/admin/dashboard", "admin", nil)
	r.json(t, &dash)
	if r.code != 200 {
		t.Fatalf("dashboard %d %s", r.code, r.body)
	}
	if !hasWarn(&dash, "could not be read") {
		t.Errorf("a failing database reads as a quiet one: %d running, %d failed, warnings %v",
			dash.RunningJobs, dash.FailedJobs24h, dash.Warnings)
	}
	if v, _ := dash.Extra["stats_unavailable"].(bool); !v {
		t.Errorf("extra.stats_unavailable = %v, want true", dash.Extra["stats_unavailable"])
	}

	var sys SystemResponse
	r = te.do("GET", "/admin/system", "admin", nil)
	r.json(t, &sys)
	if r.code != 200 || !sys.StatsUnavailable {
		t.Errorf("GET /admin/system reports schema_version=%d blob_count=%d as facts (stats_unavailable=%v)",
			sys.SchemaVersion, sys.BlobCount, sys.StatsUnavailable)
	}
}
