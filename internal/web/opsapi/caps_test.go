package opsapi

import (
	"net/http"
	"testing"
	"time"

	"fileparcel/internal/app"
	"fileparcel/internal/core"
)

// delegate is a session of a member-based custom role holding caps
// (elevated), the principal package auth builds for such an account.
func delegate(name string, caps ...core.Capability) *core.Principal {
	p := &core.Principal{UserID: "usr_" + name, Username: name, Role: core.RoleMember,
		RoleID: "rol_01k5z8r3m9d4q7w2x6c1v0b5na", RoleName: "Delegates", Via: core.ViaSession,
		AuthLevel: core.AuthLevelFull, ElevatedUntil: time.Now().Add(time.Hour)}
	p.SetCaps(core.MemberCaps.With(caps...).Closure())
	return p
}

func init() {
	principals["viewer"] = delegate("vic", core.CapSystemView)
	principals["operator"] = delegate("otto", core.CapSystemManage) // implies system.view
	principals["backupper"] = delegate("bea", core.CapBackupsRun)
	principals["auditor"] = delegate("aud", core.CapSystemView, core.CapAuditView)
	principals["dashboard+backups"] = delegate("dan", core.CapSystemView, core.CapBackupsRun)
	tok := delegate("otto", core.CapSystemManage)
	tok.Via, tok.Scopes = core.ViaToken, []string{core.ScopeFilesRead}
	principals["operator files token"] = tok
}

// A job is started and cancelled with the permission of its kind: backups
// with "Run backups", everything else with "Operate the server".
func TestJobPermissionsByKind(t *testing.T) {
	te := newTestEnv(t, app.ModeNetwork)
	te.jobs.add(core.Job{ID: "job_maint", Kind: core.JobMaintSessions, State: core.JobRunning})
	te.jobs.add(core.Job{ID: "job_backup", Kind: core.JobBackupCreate, State: core.JobRunning})
	needs := func(c core.Capability) string { return "this needs the “" + c.Label() + "” permission" }
	for _, c := range []struct {
		who, method, path string
		body              any
		want              int
		msg               string
	}{
		{"operator", "POST", "/admin/jobs/run", map[string]string{"kind": core.JobMaintSessions}, http.StatusAccepted, ""},
		{"operator", "POST", "/admin/jobs/run", map[string]string{"kind": core.JobBackupCreate}, http.StatusForbidden,
			needs(core.CapBackupsRun)},
		{"operator", "POST", "/admin/jobs/run", map[string]string{"kind": core.JobBackupPrune}, http.StatusForbidden,
			needs(core.CapBackupsRun)},
		{"backupper", "POST", "/admin/jobs/run", map[string]string{"kind": core.JobBackupCreate}, http.StatusAccepted, ""},
		{"backupper", "POST", "/admin/jobs/run", map[string]string{"kind": core.JobMaintSessions}, http.StatusForbidden,
			needs(core.CapSystemManage)},
		// An unknown kind is not a backup: its permission is "Operate the server".
		{"backupper", "POST", "/admin/jobs/run", map[string]string{"kind": "nope"}, http.StatusForbidden,
			needs(core.CapSystemManage)},
		{"operator", "POST", "/admin/jobs/run", map[string]string{"kind": "nope"}, http.StatusUnprocessableEntity, ""},
		{"viewer", "POST", "/admin/jobs/run", map[string]string{"kind": core.JobMaintSessions}, http.StatusForbidden,
			needs(core.CapSystemManage)},
		{"operator files token", "POST", "/admin/jobs/run", map[string]string{"kind": core.JobMaintSessions},
			http.StatusForbidden, `token lacks scope "admin"`},

		{"backupper", "POST", "/admin/jobs/job_maint/cancel", nil, http.StatusForbidden, needs(core.CapSystemManage)},
		{"operator", "POST", "/admin/jobs/job_backup/cancel", nil, http.StatusForbidden, needs(core.CapBackupsRun)},
		{"operator", "POST", "/admin/jobs/job_nope/cancel", nil, http.StatusNotFound, ""},
		{"backupper", "POST", "/admin/jobs/job_nope/cancel", nil, http.StatusNotFound, ""},
		{"operator", "POST", "/admin/jobs/job_maint/cancel", nil, http.StatusNoContent, ""},
		{"backupper", "POST", "/admin/jobs/job_backup/cancel", nil, http.StatusNoContent, ""},
		{"admin", "POST", "/admin/jobs/job_backup/cancel", nil, http.StatusNoContent, ""},
	} {
		var r resp
		if c.body != nil {
			r = te.do(c.method, c.path, c.who, jsonBody(c.body))
		} else {
			r = te.do(c.method, c.path, c.who, nil)
		}
		if r.code != c.want || (c.msg != "" && errMessage(t, r) != c.msg) {
			t.Errorf("%s %s %v as %s: %d %s", c.method, c.path, c.body, c.who, r.code, r.body)
		}
	}
	if got := te.jobs.enqueued; len(got) != 1 || got[0] != core.JobMaintSessions {
		t.Errorf("enqueued %v", got)
	}
	if !te.backups.called("create") {
		t.Error("the backup runner's backup was not started")
	}
	if n := te.audit.count(core.ActJobRun); n != 2 {
		t.Errorf("%d job.run entries, want 2", n)
	}
}

// GET /jobs/{id} shows every job to holders of system.view, as
// GET /admin/jobs/{id} does; everyone else sees only their own.
func TestOwnJobWithSystemView(t *testing.T) {
	te := newTestEnv(t, app.ModeNetwork)
	te.jobs.add(core.Job{ID: "job_alice", Kind: core.JobUploadZip, State: core.JobRunning, CreatedBy: "usr_alice"})
	for who, want := range map[string]int{"viewer": 200, "operator": 200, "backupper": 404, "bob": 404, "alice": 200,
		"operator files token": 404} {
		if r := te.do("GET", "/jobs/job_alice", who, nil); r.code != want {
			t.Errorf("%s: %d, want %d", who, r.code, want)
		}
	}
}

// The dashboard (system.view) lists the newest audit entries only for
// holders of audit.view and the last backup only for holders of
// backups.run; the warnings are the same for everyone.
func TestDashboardPerPermission(t *testing.T) {
	te := newTestEnv(t, app.ModeNetwork)
	te.backups.items = []core.Backup{{ID: "bak_1", State: core.BackupReady, CreatedAt: te.now.Add(-time.Hour)}}
	te.keys.state = core.KeyStateLocked
	get := func(who string) core.Dashboard {
		t.Helper()
		var dash core.Dashboard
		r := te.do("GET", "/admin/dashboard", who, nil)
		if r.code != http.StatusOK {
			t.Fatalf("%s: %d %s", who, r.code, r.body)
		}
		r.json(t, &dash)
		return dash
	}
	admin := get("admin")
	if len(admin.RecentAudit) != 1 || admin.LastBackup == nil || len(admin.Warnings) == 0 {
		t.Fatalf("admin: %+v", admin)
	}
	for who, want := range map[string]struct{ audit, backup bool }{
		"viewer":            {false, false},
		"operator":          {false, false},
		"auditor":           {true, false},
		"dashboard+backups": {false, true},
	} {
		d := get(who)
		if (len(d.RecentAudit) > 0) != want.audit || (d.LastBackup != nil) != want.backup {
			t.Errorf("%s: recent audit %d, last backup %v", who, len(d.RecentAudit), d.LastBackup)
		}
		if d.RecentAudit == nil {
			t.Errorf("%s: recent_audit is null, want []", who)
		}
		if len(d.Warnings) != len(admin.Warnings) {
			t.Errorf("%s: warnings %v, admin %v", who, d.Warnings, admin.Warnings)
		}
	}
	for _, who := range []string{"backupper", "alice"} {
		if r := te.do("GET", "/admin/dashboard", who, nil); r.code != http.StatusForbidden {
			t.Errorf("%s: %d", who, r.code)
		}
	}
}

func errMessage(t *testing.T, r resp) string {
	t.Helper()
	var e struct {
		Error struct {
			Message string `json:"message"`
		} `json:"error"`
	}
	r.json(t, &e)
	return e.Error.Message
}
