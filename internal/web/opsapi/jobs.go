package opsapi

import (
	"bytes"
	"encoding/json"
	"net/http"
	"slices"
	"strings"

	"github.com/go-chi/chi/v5"

	"fileparcel/internal/core"
	"fileparcel/internal/web/httpx"
	"fileparcel/internal/web/mw"
)

// The kinds POST /admin/jobs/run may start are core.RunnableJobKinds, shared
// with GET /admin/jobs/kinds and "fileparcel jobs run" so the three can never
// disagree. backup.create and backup.verify go through the backup service
// (params: core.BackupInput / {"id","deep"}); the rest take no parameters.

// runVerifyParams are the params of POST /admin/jobs/run {kind: backup.verify}.
type runVerifyParams struct {
	ID   string `json:"id"`
	Deep bool   `json:"deep,omitempty"`
}

// kindLister is implemented by the jobs service (registered kinds).
type kindLister interface{ Registered(kind string) bool }

// jobCap is the permission that starts or cancels a job of kind (DESIGN
// §6a): "Run backups" for the backup kinds, "Operate the server" for every
// other kind (maintenance, keys, certificates, uploads, thumbnails).
func jobCap(kind string) core.Capability {
	if strings.HasPrefix(kind, "backup.") {
		return core.CapBackupsRun
	}
	return core.CapSystemManage
}

func (h *handlers) listJobs(w http.ResponseWriter, r *http.Request) {
	j := h.jobs(w, r)
	if j == nil {
		return
	}
	v := r.URL.Query()
	q := core.JobQuery{PageReq: httpx.PageReq(r), Kind: strings.TrimSpace(v.Get("kind")),
		State: strings.TrimSpace(v.Get("state")), CreatedBy: strings.TrimSpace(v.Get("created_by"))}
	page, err := j.List(r.Context(), q)
	if err != nil {
		httpx.Error(w, r, err)
		return
	}
	httpx.OK(w, page)
}

func (h *handlers) listSchedules(w http.ResponseWriter, r *http.Request) {
	j := h.jobs(w, r)
	if j == nil {
		return
	}
	scs, err := j.Schedules(r.Context())
	if err != nil {
		httpx.Error(w, r, err)
		return
	}
	if scs == nil {
		scs = []core.JobSchedule{}
	}
	httpx.OK(w, scs)
}

func (h *handlers) runnableKinds(w http.ResponseWriter, r *http.Request) {
	j := h.jobs(w, r)
	if j == nil {
		return
	}
	out := []string{}
	kl, _ := j.(kindLister)
	for _, k := range core.RunnableJobKinds {
		if kl == nil || kl.Registered(k) {
			out = append(out, k)
		}
	}
	slices.Sort(out)
	httpx.OK(w, out)
}

func (h *handlers) getJob(w http.ResponseWriter, r *http.Request) {
	j := h.jobs(w, r)
	if j == nil {
		return
	}
	job, err := j.Get(r.Context(), chi.URLParam(r, "id"))
	if err != nil {
		httpx.Error(w, r, err)
		return
	}
	httpx.OK(w, job)
}

// ownJob is GET /jobs/{id}: a user sees only the jobs they created (404
// otherwise, no existence leak); holders of system.view (administrators
// among them; API tokens need the admin scope) see every job, as on
// GET /admin/jobs/{id}.
func (h *handlers) ownJob(w http.ResponseWriter, r *http.Request) {
	j := h.jobs(w, r)
	if j == nil {
		return
	}
	p := mw.Principal(r)
	job, err := j.Get(r.Context(), chi.URLParam(r, "id"))
	if err != nil {
		httpx.Error(w, r, err)
		return
	}
	if !p.Can(core.CapSystemView) && (p.UserID == "" || job.CreatedBy != p.UserID) {
		httpx.Error(w, r, core.NotFoundf("job not found"))
		return
	}
	httpx.OK(w, job)
}

// cancelJob is POST /admin/jobs/{id}/cancel: the caller needs the
// permission of the job's kind (jobCap), so the job is loaded first (404 as
// before for an unknown one).
func (h *handlers) cancelJob(w http.ResponseWriter, r *http.Request) {
	j := h.jobs(w, r)
	if j == nil {
		return
	}
	job, err := j.Get(r.Context(), chi.URLParam(r, "id"))
	if err != nil {
		httpx.Error(w, r, err)
		return
	}
	if c := jobCap(job.Kind); !mw.Principal(r).Can(c) {
		httpx.Error(w, r, core.NeedPermission(c))
		return
	}
	if err := j.Cancel(r.Context(), job.ID); err != nil {
		httpx.Error(w, r, err)
		return
	}
	httpx.NoContent(w)
}

// runJob is POST /admin/jobs/run: the caller needs the permission of the
// kind (jobCap) before anything about the kind is checked.
func (h *handlers) runJob(w http.ResponseWriter, r *http.Request) {
	j := h.jobs(w, r)
	if j == nil {
		return
	}
	in, err := httpx.Decode[core.RunJobInput](r, 0)
	if err != nil {
		httpx.Error(w, r, err)
		return
	}
	kind := strings.TrimSpace(in.Kind)
	p := mw.Principal(r)
	if c := jobCap(kind); !p.Can(c) {
		httpx.Error(w, r, core.NeedPermission(c))
		return
	}
	var id string
	switch kind {
	case core.JobBackupCreate:
		b := h.backups(w, r)
		if b == nil {
			return
		}
		var bi core.BackupInput
		if err := decodeParams(in.Params, &bi); err != nil {
			httpx.Error(w, r, err)
			return
		}
		id, err = b.Create(r.Context(), p, bi)
	case core.JobBackupVerify:
		b := h.backups(w, r)
		if b == nil {
			return
		}
		var vp runVerifyParams
		if err := decodeParams(in.Params, &vp); err != nil {
			httpx.Error(w, r, err)
			return
		}
		id, err = b.Verify(r.Context(), p, vp.ID, vp.Deep)
	default:
		if !slices.Contains(core.RunnableJobKinds, kind) {
			httpx.Error(w, r, core.Invalid("kind", "this job kind cannot be started by hand"))
			return
		}
		if kl, ok := j.(kindLister); ok && !kl.Registered(kind) {
			httpx.Error(w, r, core.Invalid("kind", "this job kind is not available"))
			return
		}
		if len(bytes.TrimSpace(in.Params)) > 0 && !isEmptyJSON(in.Params) {
			httpx.Error(w, r, core.Invalid("params", "this job kind takes no parameters"))
			return
		}
		id, err = j.Enqueue(r.Context(), kind, nil, p)
	}
	if err != nil {
		httpx.Error(w, r, err)
		return
	}
	// Hand-started runs are audited here: the job principal carries no user
	// identity, so jobs.created_by and this entry are the only record of who
	// asked. h.record fills actor/ip/user_agent/request_id from the context.
	h.record(r, core.AuditEntry{Action: core.ActJobRun, TargetType: "job", TargetID: id,
		Details: map[string]any{"kind": kind}})
	httpx.JSON(w, http.StatusAccepted, core.JobRef{JobID: id})
}

// decodeParams strictly decodes job params (empty = zero value).
func decodeParams(raw json.RawMessage, v any) error {
	if len(bytes.TrimSpace(raw)) == 0 || isEmptyJSON(raw) {
		return nil
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return core.Invalid("params", "invalid parameters: "+err.Error())
	}
	return nil
}

func isEmptyJSON(raw json.RawMessage) bool {
	s := string(bytes.TrimSpace(raw))
	return s == "null" || s == "{}"
}
