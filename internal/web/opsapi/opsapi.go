// Package opsapi owns backups, jobs, system, dashboard, audit and the SSE
// event stream (DESIGN §9.4, unit H). Guards: Cap(x|y) = mw.RequireCap(x, y)
// (full authentication and any of the permissions; owners and admins hold
// every permission; API tokens need the admin scope for them), Adm =
// mw.RequireAdmin (built-in owners/admins only: a backup holds everything,
// and a restore brings back a database in which a delegate may have been an
// administrator), E = elevated, F = full:
//
//	GET/POST  /admin/backups                 Cap(backups.run)  list | start a backup → 202 core.JobRef (?wait=1 → 201 core.Backup)
//	POST      /admin/backups/import          (Adm, E; raw or multipart body up to 1 TiB) → 201 core.Backup
//	GET       /admin/backups/config          Cap(backups.run) core.BackupConfig
//	PUT       /admin/backups/config          (Adm, E) core.BackupConfig
//	POST      /admin/backups/identity        (Adm, E) new identity → 201 core.BackupIdentity (shown once)
//	POST      /admin/backups/identity/export (Adm, E) current identity → core.BackupIdentity
//	GET       /admin/backups/{id}            Cap(backups.run)
//	DELETE    /admin/backups/{id}            (Adm, E)
//	POST      /admin/backups/{id}/verify     Cap(backups.run) {deep} or ?deep=1 → 202 core.JobRef
//	GET       /admin/backups/{id}/download   (Adm, E) Range-capable; audited (not for HEAD)
//	POST      /admin/backups/{id}/restore    (Adm, E) core.RestoreCreds → 202 RestoreScheduled
//	GET       /admin/jobs                    Cap(system.view) ?kind=&state=&created_by=&cursor=&limit=
//	GET       /admin/jobs/schedules          Cap(system.view) []core.JobSchedule
//	GET       /admin/jobs/kinds              Cap(system.view) kinds accepted by POST /admin/jobs/run
//	GET       /admin/jobs/{id}               Cap(system.view)
//	POST      /admin/jobs/{id}/cancel        Cap(system.manage|backups.run) + the permission of the job's kind (jobCap) → 204
//	POST      /admin/jobs/run                Cap(system.manage|backups.run) + the permission of the kind (jobCap)
//	                                         core.RunJobInput → 202 core.JobRef
//	GET       /admin/system                  Cap(system.view) SystemResponse (core.SystemInfo + details)
//	POST      /admin/system/restart          Cap(system.manage), E → 202; 409 in offline mode
//	GET       /admin/system/doctor           Cap(system.view) DoctorReport
//	GET       /admin/system/logs?n=          Cap(audit.view) LogTail (last n lines of logs/fileparcel.log; missing, file_logging)
//	GET       /admin/dashboard               Cap(system.view) core.Dashboard (recent_audit only with audit.view,
//	                                         last_backup only with backups.run)
//	GET       /admin/audit                   Cap(audit.view) ?since=&until=&actor_id=&action=&outcome=&target_type=&target_id=&q=
//	GET       /admin/audit/verify            Cap(audit.view) core.AuditVerify
//	GET       /admin/audit/export?format=csv|jsonl  Cap(audit.view) attachment (same filters)
//	GET       /jobs/{id}                     (F) own jobs (holders of system.view: any)
//	GET       /events                        (F) SSE; filtered per principal and permission (sse.go); heartbeat 25 s
//
// POST /admin/system/restart audits core.ActSystemRestart and publishes
// events.TopicSystemRestart (package server exits with code 75); in
// ModeOffline nobody listens, so it answers 409 conflict.
package opsapi

import (
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"

	"fileparcel/internal/app"
	"fileparcel/internal/core"
	"fileparcel/internal/web/httpx"
	"fileparcel/internal/web/mw"
)

// MaxImportBytes bounds POST /admin/backups/import (1 TiB).
const MaxImportBytes = 1 << 40

// processStart approximates the process start (package initialisation).
var processStart = time.Now()

// Mount registers this package's routes on the /api/v1 router, grouped by
// the permission they need (chi allows one path pattern in several groups
// with different methods).
func Mount(api chi.Router, d *app.Deps) {
	h := &handlers{d: d, sse: newSSELimiter()}
	api.Group(func(r chi.Router) {
		r.Use(mw.RequireCap(core.CapBackupsRun), mw.NoStore)
		r.Get("/admin/backups", h.listBackups)
		r.Post("/admin/backups", h.createBackup)
		r.Get("/admin/backups/config", h.getBackupConfig)
		r.Get("/admin/backups/{id}", h.getBackup)
		r.Post("/admin/backups/{id}/verify", h.verifyBackup)
	})
	api.Group(func(r chi.Router) {
		r.Use(mw.RequireCap(core.CapSystemView), mw.NoStore)
		r.Get("/admin/jobs", h.listJobs)
		r.Get("/admin/jobs/schedules", h.listSchedules)
		r.Get("/admin/jobs/kinds", h.runnableKinds)
		r.Get("/admin/jobs/{id}", h.getJob)
		r.Get("/admin/system", h.system)
		r.Get("/admin/system/doctor", h.doctor)
		r.Get("/admin/dashboard", h.dashboard)
	})
	api.Group(func(r chi.Router) {
		// Either permission opens the routes; the handlers then require the
		// one of the job's kind (jobCap).
		r.Use(mw.RequireCap(core.CapSystemManage, core.CapBackupsRun), mw.NoStore)
		r.Post("/admin/jobs/{id}/cancel", h.cancelJob)
		r.Post("/admin/jobs/run", h.runJob)
	})
	api.Group(func(r chi.Router) {
		r.Use(mw.RequireCap(core.CapSystemManage), mw.NoStore, mw.RequireElevated)
		r.Post("/admin/system/restart", h.restart)
	})
	api.Group(func(r chi.Router) {
		r.Use(mw.RequireCap(core.CapAuditView), mw.NoStore)
		r.Get("/admin/system/logs", h.logs)
		r.Get("/admin/audit", h.auditQuery)
		r.Get("/admin/audit/verify", h.auditVerify)
		r.Get("/admin/audit/export", h.auditExport)
	})
	api.Group(func(r chi.Router) {
		r.Use(mw.RequireAdmin, mw.NoStore, mw.RequireElevated)
		r.Delete("/admin/backups/{id}", h.deleteBackup)
		r.Get("/admin/backups/{id}/download", h.downloadBackup)
		r.Post("/admin/backups/{id}/restore", h.restoreBackup)
		r.Put("/admin/backups/config", h.putBackupConfig)
		r.Post("/admin/backups/identity", h.generateIdentity)
		r.Post("/admin/backups/identity/export", h.exportIdentity)
		r.With(mw.MaxBody(MaxImportBytes)).Post("/admin/backups/import", h.importBackup)
	})
	api.Group(func(r chi.Router) {
		r.Use(mw.RequireFull, mw.NoStore)
		r.Get("/jobs/{id}", h.ownJob)
		r.Get("/events", h.events)
	})
}

type handlers struct {
	d   *app.Deps
	sse *sseLimiter
	qc  quickCheckCache
}

// deps returns the services (the injected ones win, for in-process callers).
func (h *handlers) deps(r *http.Request) *app.Deps {
	if d := mw.Deps(r); d != nil && d.Env != nil {
		return d
	}
	return h.d
}

func (h *handlers) now(r *http.Request) time.Time {
	if d := h.deps(r); d != nil && d.Env != nil {
		return d.Now()
	}
	return time.Now()
}

var errUnavailable = core.Errorf(core.ErrUnavailable, "this service is not available")

func (h *handlers) backups(w http.ResponseWriter, r *http.Request) core.Backups {
	d := h.deps(r)
	if d == nil || d.Backups == nil {
		httpx.Error(w, r, errUnavailable)
		return nil
	}
	return d.Backups
}

func (h *handlers) jobs(w http.ResponseWriter, r *http.Request) core.Jobs {
	d := h.deps(r)
	if d == nil || d.Jobs == nil {
		httpx.Error(w, r, errUnavailable)
		return nil
	}
	return d.Jobs
}

func (h *handlers) audit(w http.ResponseWriter, r *http.Request) core.Audit {
	d := h.deps(r)
	if d == nil || d.Env == nil || d.Audit == nil {
		httpx.Error(w, r, errUnavailable)
		return nil
	}
	return d.Audit
}

// record writes an audit entry when the audit service exists.
func (h *handlers) record(r *http.Request, e core.AuditEntry) {
	if d := h.deps(r); d != nil && d.Env != nil && d.Audit != nil {
		d.Audit.Record(r.Context(), e)
	}
}
