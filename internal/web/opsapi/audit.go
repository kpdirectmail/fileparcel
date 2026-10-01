package opsapi

import (
	"net/http"
	"strings"
	"time"

	"fileparcel/internal/core"
	"fileparcel/internal/web/httpx"
)

// auditQuery parses the filters shared by GET /admin/audit and
// /admin/audit/export: ?since=&until= (RFC 3339, or a Go duration such as
// "24h" meaning that long ago), actor_id, action, outcome, target_type,
// target_id, q, cursor, limit.
func parseAuditQuery(r *http.Request, now time.Time) (core.AuditQuery, error) {
	v := r.URL.Query()
	q := core.AuditQuery{
		PageReq:    httpx.PageReq(r),
		ActorID:    strings.TrimSpace(v.Get("actor_id")),
		Action:     strings.TrimSpace(v.Get("action")),
		Outcome:    strings.TrimSpace(v.Get("outcome")),
		TargetType: strings.TrimSpace(v.Get("target_type")),
		TargetID:   strings.TrimSpace(v.Get("target_id")),
		Q:          strings.TrimSpace(v.Get("q")),
	}
	switch q.Outcome {
	case "", core.OutcomeSuccess, core.OutcomeFailure, core.OutcomeDenied:
	default:
		return q, core.Invalid("outcome", "outcome must be success, failure or denied")
	}
	if len(q.Q) > 200 {
		return q, core.Invalid("q", "the search text is too long")
	}
	var err error
	if q.Since, err = parseWhen(v.Get("since"), "since", now); err != nil {
		return q, err
	}
	if q.Until, err = parseWhen(v.Get("until"), "until", now); err != nil {
		return q, err
	}
	return q, nil
}

// parseWhen parses an RFC 3339 time or a duration before now ("" = nil).
func parseWhen(s, field string, now time.Time) (*time.Time, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, nil
	}
	if t, err := time.Parse(time.RFC3339, s); err == nil {
		return &t, nil
	}
	if d, err := time.ParseDuration(s); err == nil && d >= 0 {
		t := now.Add(-d)
		return &t, nil
	}
	if t, err := time.Parse("2006-01-02", s); err == nil {
		return &t, nil
	}
	return nil, core.Invalid(field, "expected an RFC 3339 time (2026-01-02T15:04:05Z), a date or a duration such as 24h")
}

func (h *handlers) auditQuery(w http.ResponseWriter, r *http.Request) {
	a := h.audit(w, r)
	if a == nil {
		return
	}
	q, err := parseAuditQuery(r, h.now(r))
	if err != nil {
		httpx.Error(w, r, err)
		return
	}
	page, err := a.Query(r.Context(), q)
	if err != nil {
		httpx.Error(w, r, err)
		return
	}
	httpx.OK(w, page)
}

func (h *handlers) auditVerify(w http.ResponseWriter, r *http.Request) {
	a := h.audit(w, r)
	if a == nil {
		return
	}
	res, err := a.Verify(r.Context())
	if err != nil {
		httpx.Error(w, r, err)
		return
	}
	httpx.OK(w, res)
}

// auditExport streams the audit log as CSV or JSON lines (attachment).
func (h *handlers) auditExport(w http.ResponseWriter, r *http.Request) {
	a := h.audit(w, r)
	if a == nil {
		return
	}
	format := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("format")))
	if format == "" {
		format = "csv"
	}
	var ctype, ext string
	switch format {
	case "csv":
		ctype, ext = "text/csv; charset=utf-8", "csv"
	case "jsonl":
		ctype, ext = "application/x-ndjson", "jsonl"
	default:
		httpx.Error(w, r, core.Invalid("format", "format must be csv or jsonl"))
		return
	}
	q, err := parseAuditQuery(r, h.now(r))
	if err != nil {
		httpx.Error(w, r, err)
		return
	}
	hd := w.Header()
	hd.Set("Content-Type", ctype)
	hd.Set("X-Content-Type-Options", "nosniff")
	httpx.Attachment(w, "fileparcel-audit-"+h.now(r).UTC().Format("20060102-150405")+"."+ext, false)
	if r.Method == http.MethodHead {
		w.WriteHeader(http.StatusOK)
		return
	}
	sw := &startWriter{w: w}
	if err := a.Export(r.Context(), q, format, sw); err != nil {
		if !sw.started {
			hd.Del("Content-Disposition")
			httpx.Error(w, r, err)
			return
		}
		if r.Context().Err() == nil {
			if d := h.deps(r); d != nil && d.Env != nil && d.Log != nil {
				d.Log.Warn("audit export aborted", "err", err, "request_id", httpx.RequestID(r.Context()))
			}
		}
		// The status line is out: abort the connection (no final chunk /
		// RST_STREAM) instead of ending a truncated export cleanly. The rows
		// end on a line boundary, so a clean end would pass for the whole log
		// (browsers and `fileparcel audit export -o` would keep it).
		panic(http.ErrAbortHandler)
	}
}

// startWriter records whether anything was written.
type startWriter struct {
	w       http.ResponseWriter
	started bool
}

func (s *startWriter) Write(p []byte) (int, error) {
	s.started = true
	return s.w.Write(p)
}
