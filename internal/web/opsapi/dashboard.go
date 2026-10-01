package opsapi

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"fileparcel/internal/app"
	"fileparcel/internal/core"
	"fileparcel/internal/web/httpx"
	"fileparcel/internal/web/mw"
)

// stats are read-only aggregates for the dashboard and system pages.
// unavailable is set when any of the queries failed or timed out: its value
// is then zero, which must never be read as "nothing to report" — a degraded
// database would otherwise make the dashboard look healthier than a working
// one (the doctor deliberately does the opposite, see checkJobs).
type stats struct {
	groups, files, folders            int64
	blobCount, blobBytes              int64
	activeShares, activeUploads       int64
	runningJobs, failedJobs24h        int64
	spaceUsed, spaceQuota, quotaUsers int64
	unavailable                       bool
}

// collectStats runs the aggregate queries (each best effort: a failing query
// leaves its value at zero and sets unavailable).
func collectStats(ctx context.Context, d *app.Deps, now time.Time) stats {
	var s stats
	if d == nil || d.Env == nil || d.DB == nil {
		s.unavailable = true
		return s
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	nowMs := unixMs(now)
	q := func(dst []any, query string, args ...any) {
		if err := d.DB.QueryRow(ctx, query, args...).Scan(dst...); err != nil {
			s.unavailable = true
			if d.Log != nil {
				d.Log.Debug("opsapi: stats query failed", "err", err)
			}
		}
	}
	q([]any{&s.groups}, `SELECT count(*) FROM groups`)
	q([]any{&s.files, &s.folders}, `SELECT coalesce(sum(kind = 'file'), 0), coalesce(sum(kind = 'folder'), 0)
		FROM nodes WHERE trashed_at IS NULL AND parent_id IS NOT NULL`)
	q([]any{&s.blobCount, &s.blobBytes}, `SELECT count(*), coalesce(sum(coalesce(stored_size, size)), 0) FROM blobs WHERE state = 'ready'`)
	q([]any{&s.activeShares}, `SELECT count(*) FROM shares WHERE disabled_at IS NULL AND (expires_at IS NULL OR expires_at > ?)
		AND (max_downloads IS NULL OR download_count < max_downloads)`, nowMs)
	q([]any{&s.activeUploads}, `SELECT count(*) FROM upload_batches WHERE state IN ('open','finalizing') AND expires_at > ?`, nowMs)
	q([]any{&s.runningJobs}, `SELECT count(*) FROM jobs WHERE state = 'running'`)
	q([]any{&s.failedJobs24h}, `SELECT count(*) FROM jobs WHERE state = 'failed' AND finished_at > ?`, unixMs(now.Add(-24*time.Hour)))
	q([]any{&s.spaceUsed, &s.spaceQuota, &s.quotaUsers}, `SELECT coalesce(sum(used_bytes), 0),
		coalesce(sum(CASE WHEN quota_bytes > 0 THEN quota_bytes END), 0), count(quota_bytes) FROM spaces`)
	return s
}

// backupState is what the dashboard and the doctor say about backups.
type backupState struct {
	ready     *core.Backup // newest usable backup: ready and not failed verification
	newest    *core.Backup // newest finished backup (ready or failed)
	badVerify *core.Backup // newest ready backup whose last verification failed
}

// lastBackup reads the newest backups this installation made. Imported rows
// (trigger "import": uploaded archives, and files found after a restore) are
// skipped: an archive from elsewhere — or one this server cannot even
// decrypt, dated the moment it was imported — says nothing about whether
// this server's own backups work. A backup whose verification failed (file
// missing, corrupt, not decryptable) stays "ready" but is not usable, so it
// is reported in badVerify instead of ready. An unreadable list is an error,
// never "no backup yet".
func lastBackup(ctx context.Context, b core.Backups) (backupState, error) {
	var st backupState
	if b == nil {
		return st, nil
	}
	page, err := b.List(ctx, core.PageReq{Limit: 50})
	if err != nil {
		return st, err
	}
	for i := range page.Items {
		it := &page.Items[i]
		if it.Trigger == core.TriggerImport {
			continue
		}
		if st.newest == nil && it.State != core.BackupRunning {
			st.newest = it
		}
		if it.State != core.BackupReady {
			continue
		}
		if it.VerifyOK != nil && !*it.VerifyOK {
			if st.badVerify == nil {
				st.badVerify = it
			}
		} else if st.ready == nil {
			st.ready = it
		}
	}
	return st, nil
}

// failedVerify returns the backup that failed verification more recently
// than the newest usable one was made (nil: nothing to report).
func (st backupState) failedVerify() *core.Backup {
	if b := st.badVerify; b != nil && (st.ready == nil || b.CreatedAt.After(st.ready.CreatedAt)) {
		return b
	}
	return nil
}

// verifyError is the verification failure recorded on b. The error column
// can also hold a problem of the backup's creation (a failed copy to
// backup.copy_to); the verification's own part follows "verification failed: ".
func verifyError(b *core.Backup) string {
	const marker = "verification failed: "
	e := b.Error
	if i := strings.LastIndex(e, marker); i >= 0 {
		e = e[i+len(marker):]
	}
	if e = strings.TrimSpace(e); e == "" {
		return "no reason was recorded"
	}
	return e
}

// backupStale is how old the newest backup may be before a warning.
const backupStale = 8 * 24 * time.Hour

// Certificate warning thresholds.
const (
	certWarn = 14 * 24 * time.Hour
	caWarn   = 90 * 24 * time.Hour
	// leafRenewWindow is certs.leafRenewBefore: the local leaf is reissued
	// when less than min(30 days, a third of its own lifetime) is left
	// (certs.renewBefore, DESIGN §10.4). Keep the two in step.
	leafRenewWindow = 30 * 24 * time.Hour
)

// leafWarn is how close to expiry the local server certificate may get
// before the dashboard and the doctor call it expiring: half its renewal
// window, so only a renewal that is overdue by at least one missed
// certs.renew_check shows, and never later than certWarn. A fixed certWarn
// flagged every healthy short-lived leaf (tls.leaf_days may be as low as 7,
// renewed with 2⅓ days left) as expiring, permanently. The default 397-day
// leaf keeps the 14 days. Custom certificates are not renewed automatically
// and keep certWarn.
func leafWarn(ci *core.CertInfo) time.Duration {
	renew := leafRenewWindow
	if span := ci.NotAfter.Sub(ci.NotBefore); span > 0 {
		renew = min(renew, span/3)
	}
	return min(certWarn, renew/2)
}

// dashboard is GET /admin/dashboard (system.view). The newest audit entries
// are listed only for holders of audit.view and the last backup only for
// holders of backups.run (owners and admins hold both); the warnings stay
// for everyone who may see the dashboard.
func (h *handlers) dashboard(w http.ResponseWriter, r *http.Request) {
	d := h.deps(r)
	if d == nil || d.Env == nil {
		httpx.Error(w, r, errUnavailable)
		return
	}
	ctx := r.Context()
	now := h.now(r)
	p := mw.Principal(r)
	s := collectStats(ctx, d, now)
	dash := core.Dashboard{
		Groups: int(s.groups), Files: s.files, Folders: s.folders, StoredBytes: s.blobBytes,
		ActiveShares: int(s.activeShares), ActiveUploads: int(s.activeUploads),
		RunningJobs: int(s.runningJobs), FailedJobs24h: int(s.failedJobs24h),
		RecentAudit: []core.AuditRecord{}, Warnings: []string{}, Version: d.Build.Version,
		Extra: map[string]any{
			"blob_count":        s.blobCount,
			"space_used_bytes":  s.spaceUsed,
			"space_quota_bytes": s.spaceQuota,
			"mode":              d.Mode.String(),
			"stats_unavailable": s.unavailable,
		},
	}
	if s.unavailable {
		// The figures below are zero because the database did not answer,
		// not because there is nothing to report: say so instead of letting
		// a degraded server look like a quiet one.
		dash.Warnings = append(dash.Warnings,
			"Some figures on this page could not be read from the database and are shown as zero")
	}
	if d.Home != nil {
		dash.DiskSizeBytes, dash.DiskFreeBytes = diskUsage(d.Home.Dir())
		if dash.DiskSizeBytes > 0 && dash.DiskFreeBytes < dash.DiskSizeBytes/20 {
			dash.Warnings = append(dash.Warnings, fmt.Sprintf("Low disk space: %s free", human(dash.DiskFreeBytes)))
		}
	}
	if d.Users != nil {
		if n, err := d.Users.Count(ctx); err == nil {
			dash.Users = n
		}
	}
	if d.Keys != nil {
		dash.KeysState = d.Keys.State()
		if dash.KeysState != core.KeyStateUnlocked {
			dash.Warnings = append(dash.Warnings, "The server is locked: files cannot be accessed until it is unlocked")
		}
	}
	if d.Certs != nil {
		if cs, err := d.Certs.Status(ctx); err == nil && cs != nil && cs.Leaf != nil {
			dash.Cert = cs.Leaf
			if left := cs.Leaf.NotAfter.Sub(now); left < leafWarn(cs.Leaf) {
				dash.Warnings = append(dash.Warnings, fmt.Sprintf("The server certificate expires %s", when(left)))
			}
		}
	}
	bk, berr := lastBackup(ctx, d.Backups)
	ready := bk.ready
	if p.Can(core.CapBackupsRun) {
		dash.LastBackup = ready
	}
	switch {
	case d.Backups == nil:
	case berr != nil:
		// Not "no backup yet": nothing is known about the backups.
		dash.Extra["backup_unavailable"] = true
		dash.Warnings = append(dash.Warnings, "The backup list could not be read")
	case ready == nil && bk.badVerify == nil:
		dash.Warnings = append(dash.Warnings, "No backup has been made yet")
	case ready == nil:
	case now.Sub(ready.CreatedAt) > backupStale:
		dash.Warnings = append(dash.Warnings, fmt.Sprintf("The last backup is %d days old", int(now.Sub(ready.CreatedAt).Hours()/24)))
	}
	if bad := bk.failedVerify(); bad != nil {
		dash.Warnings = append(dash.Warnings, fmt.Sprintf("The backup made %s failed verification: %s",
			ago(now.Sub(bad.CreatedAt)), verifyError(bad)))
	}
	if bk.newest != nil && bk.newest.State == core.BackupFailed {
		dash.Warnings = append(dash.Warnings, "The last backup failed: "+bk.newest.Error)
	}
	if d.Network != nil && d.Network.Policy().Mode == core.AccessAny {
		dash.Warnings = append(dash.Warnings, "The server accepts connections from any address (access mode \"any\")")
	}
	if s.failedJobs24h > 0 {
		dash.Warnings = append(dash.Warnings, fmt.Sprintf("%d background jobs failed in the last 24 hours", s.failedJobs24h))
	}
	if d.Audit != nil && p.Can(core.CapAuditView) {
		if page, err := d.Audit.Query(ctx, core.AuditQuery{PageReq: core.PageReq{Limit: 10}}); err == nil && page.Items != nil {
			dash.RecentAudit = page.Items
		}
	}
	httpx.OK(w, dash)
}

// human formats a byte count.
func human(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(unit), 0
	for m := n / unit; m >= unit; m /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(n)/float64(div), "KMGTPE"[exp])
}

// when describes a remaining duration ("in 3 days", "today", "3 days ago").
func when(left time.Duration) string {
	days := int(left.Hours() / 24)
	switch {
	case left < 0 && days == 0:
		return "today (already expired)"
	case left < 0:
		return agoUnits(-days, "day") + " (expired)"
	case days == 0:
		return "today"
	case days == 1:
		return "tomorrow"
	}
	return fmt.Sprintf("in %d days", days)
}

// unixMs converts t to the database representation (Unix milliseconds).
func unixMs(t time.Time) int64 { return t.UnixMilli() }
