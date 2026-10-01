package opsapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"fileparcel/internal/app"
	"fileparcel/internal/core"
	"fileparcel/internal/mdns"
	"fileparcel/internal/svc"
	"fileparcel/internal/web/httpx"
)

// Doctor check statuses.
const (
	CheckOK   = "ok"
	CheckWarn = "warn"
	CheckFail = "fail"
	CheckInfo = "info"
)

// DoctorCheck is one result of GET /admin/system/doctor.
type DoctorCheck struct {
	ID      string `json:"id"`     // stable machine id ("keys", "cert.leaf", "backup.recent", …)
	Name    string `json:"name"`   // human title
	Status  string `json:"status"` // ok | warn | fail | info
	Message string `json:"message"`
	Hint    string `json:"hint,omitempty"` // what to do about it
	Link    string `json:"link,omitempty"` // admin page that fixes it
}

// DoctorReport is GET /admin/system/doctor. OK is false when any check failed.
type DoctorReport struct {
	OK          bool          `json:"ok"`
	Failures    int           `json:"failures"`
	Warnings    int           `json:"warnings"`
	Checks      []DoctorCheck `json:"checks"`
	GeneratedAt time.Time     `json:"generated_at"`
}

// Thresholds of the checks.
const (
	diskFailBytes   = 1 << 30 // < 1 GiB free
	diskWarnBytes   = 5 << 30 // < 5 GiB free
	diskFailPercent = 2
	diskWarnPercent = 10
	walWarnBytes    = 1 << 30
	clockSkewAllow  = 5 * time.Minute
	quickCheckTTL   = 10 * time.Minute
	quickCheckLimit = 20 * time.Second
	maxAdminsDoctor = 200
)

// quickCheckCache remembers the last PRAGMA quick_check (it reads the whole
// database, and the dashboard loads the doctor on every visit).
type quickCheckCache struct {
	mu    sync.Mutex
	at    time.Time
	check DoctorCheck
}

// detectFirewalls finds the host firewalls with the detection the installer
// and the CLI doctor use (ufw, firewalld, a filtering nftables ruleset, the
// macOS application firewall), so Admin → System and `fileparcel doctor`
// report the same ones. builtinMDNSLikely answers for a server whose mDNS
// service is not running (offline mode). Variables for tests.
var (
	detectFirewalls = func(ctx context.Context) []svc.Firewall {
		cctx, cancel := context.WithTimeout(ctx, 3*time.Second)
		defer cancel()
		return svc.DetectFirewalls(cctx, svc.CurrentHost())
	}
	builtinMDNSLikely = func() bool { return svc.BuiltinMDNSLikely(svc.CurrentHost()) }
)

// Optional service extensions (implemented by the concrete services).
type (
	identityExportTracker interface {
		IdentityExportedAt(ctx context.Context) *time.Time
	}
	runnerState interface{ Running() bool }
)

// doctor is GET /admin/system/doctor (?refresh=1 re-runs the cached database check).
func (h *handlers) doctor(w http.ResponseWriter, r *http.Request) {
	d := h.deps(r)
	if d == nil || d.Env == nil {
		httpx.Error(w, r, errUnavailable)
		return
	}
	rep := h.runDoctor(r.Context(), d, h.now(r), truthy(r.URL.Query().Get("refresh")))
	httpx.OK(w, rep)
}

// runDoctor runs every check (each is best effort and bounded).
func (h *handlers) runDoctor(ctx context.Context, d *app.Deps, now time.Time, refresh bool) *DoctorReport {
	var checks []DoctorCheck
	add := func(c ...DoctorCheck) { checks = append(checks, c...) }
	add(checkKeys(ctx, d))
	add(checkCerts(ctx, d, now)...)
	add(checkBackups(ctx, d, now)...)
	add(checkDisk(d))
	add(h.checkDatabase(ctx, d, now, refresh)...)
	add(checkClock(ctx, d, now))
	add(checkMDNS(d))
	add(checkAccess(d))
	add(checkAdmin2FA(ctx, d))
	add(checkJobs(ctx, d, now)...)
	add(checkRestart(d, now)...)
	add(checkFirewall(ctx, d)...)
	add(checkIngress(ctx, d, now)...)
	add(checkMaintenance(d)...)
	rep := &DoctorReport{Checks: checks, GeneratedAt: now.UTC()}
	for _, c := range checks {
		switch c.Status {
		case CheckFail:
			rep.Failures++
		case CheckWarn:
			rep.Warnings++
		}
	}
	rep.OK = rep.Failures == 0
	return rep
}

func checkKeys(ctx context.Context, d *app.Deps) DoctorCheck {
	c := DoctorCheck{ID: "keys", Name: "Encryption keys", Link: "/admin/encryption"}
	if d.Keys == nil {
		c.Status, c.Message = CheckFail, "The key service is not available"
		return c
	}
	mode := ""
	st, err := d.Keys.Status(ctx)
	if err == nil && st != nil {
		mode = st.Mode
	}
	switch d.Keys.State() {
	case core.KeyStateUnlocked:
		c.Status, c.Message = CheckOK, "Unlocked"
		if mode != "" {
			c.Message += " (" + mode + " master key)"
		}
		if mode == core.KeyModeSealed && st != nil && !st.RecoveryConfigured {
			c.Status = CheckWarn
			c.Message += "; no recovery key is configured"
			c.Hint = "Export a recovery key and store it offline: without it a forgotten passphrase means losing all data."
		}
	case core.KeyStateLocked:
		c.Status, c.Message = CheckFail, "Locked: files cannot be read or written"
		c.Hint = "Unlock the server on the /unlock page or with \"fileparcel keys unlock\"."
	default:
		c.Status, c.Message = CheckFail, "No master key: the server is not initialised"
		c.Hint = "Run \"fileparcel init\"."
	}
	return c
}

func certCheck(id, name string, ci *core.CertInfo, now time.Time, warn time.Duration) DoctorCheck {
	c := DoctorCheck{ID: id, Name: name, Link: "/admin/certificates"}
	left := ci.NotAfter.Sub(now)
	switch {
	case left <= 0:
		c.Status = CheckFail
		c.Message = fmt.Sprintf("Expired on %s", ci.NotAfter.UTC().Format("2006-01-02"))
		c.Hint = "Renew the certificate on the Certificates page."
	case now.Before(ci.NotBefore):
		c.Status = CheckWarn
		c.Message = fmt.Sprintf("Not valid before %s (is the system clock right?)", ci.NotBefore.UTC().Format(time.RFC3339))
	case left < warn:
		c.Status = CheckWarn
		c.Message = fmt.Sprintf("Expires %s (%s)", when(left), ci.NotAfter.UTC().Format("2006-01-02"))
		c.Hint = "Renew the certificate on the Certificates page."
	default:
		c.Status = CheckOK
		c.Message = fmt.Sprintf("Valid until %s", ci.NotAfter.UTC().Format("2006-01-02"))
	}
	return c
}

func checkCerts(ctx context.Context, d *app.Deps, now time.Time) []DoctorCheck {
	if d.Certs == nil {
		return []DoctorCheck{{ID: "cert.leaf", Name: "Server certificate", Status: CheckWarn,
			Message: "The certificate service is not available", Link: "/admin/certificates"}}
	}
	cctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	cs, err := d.Certs.Status(cctx)
	if err != nil || cs == nil {
		msg := "The certificate status could not be read"
		if ce := core.AsError(err); ce != nil && ce.Message != "" {
			msg += ": " + ce.Message
		}
		return []DoctorCheck{{ID: "cert.leaf", Name: "Server certificate", Status: CheckWarn, Message: msg, Link: "/admin/certificates"}}
	}
	var out []DoctorCheck
	if cs.Leaf == nil {
		out = append(out, DoctorCheck{ID: "cert.leaf", Name: "Server certificate", Status: CheckFail,
			Message: "No server certificate", Hint: "Run \"fileparcel cert renew\".", Link: "/admin/certificates"})
	} else {
		out = append(out, certCheck("cert.leaf", "Server certificate", cs.Leaf, now, leafWarn(cs.Leaf)))
	}
	if cs.CA != nil {
		out = append(out, certCheck("cert.ca", "Local certificate authority", cs.CA, now, caWarn))
	}
	if cs.Custom != nil {
		out = append(out, certCheck("cert.custom", "Custom certificate", cs.Custom, now, certWarn))
	}
	if cs.ACMEEnabled && cs.ACMEError != "" {
		out = append(out, DoctorCheck{ID: "cert.acme", Name: "ACME certificate", Status: CheckWarn,
			Message: truncateText(cs.ACMEError, 300), Link: "/admin/certificates"})
	}
	if cs.TailscaleError != "" {
		out = append(out, DoctorCheck{ID: "cert.tailscale", Name: "Tailscale certificate", Status: CheckWarn,
			Message: truncateText(cs.TailscaleError, 300), Link: "/admin/certificates",
			Hint: "\"tailscale cert\" needs HTTPS enabled for the tailnet and operator permission (sudo tailscale set --operator=$USER)."})
	}
	return out
}

func checkBackups(ctx context.Context, d *app.Deps, now time.Time) []DoctorCheck {
	const link = "/admin/backups"
	if d.Backups == nil {
		return []DoctorCheck{{ID: "backup.recent", Name: "Backups", Status: CheckWarn, Message: "The backup service is not available", Link: link}}
	}
	rec := DoctorCheck{ID: "backup.recent", Name: "Recent backup", Link: link}
	lctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	bk, err := lastBackup(lctx, d.Backups)
	lateList := lctx.Err() != nil
	cancel()
	ready, newest := bk.ready, bk.newest
	switch {
	case err != nil:
		// Not "no backup yet": nothing is known (info leaves the summary alone).
		rec.Status, rec.Message = CheckInfo, "The backup list could not be read"
		if lateList {
			rec.Message = "The backup list did not load in time"
		}
	case ready == nil && bk.badVerify == nil:
		rec.Status, rec.Message = CheckWarn, "No backup has been made yet"
		rec.Hint = "Create a backup on the Backups page (or \"fileparcel backup create\")."
	case ready == nil:
		rec.Status, rec.Message = CheckWarn, "No usable backup"
	case now.Sub(ready.CreatedAt) > backupStale:
		rec.Status = CheckWarn
		rec.Message = fmt.Sprintf("The last backup is %d days old", int(now.Sub(ready.CreatedAt).Hours()/24))
		rec.Hint = "Check the backup schedule and the job log."
	default:
		rec.Status = CheckOK
		rec.Message = fmt.Sprintf("Last backup %s (%s, %s)", ago(now.Sub(ready.CreatedAt)), ready.Scope, human(ready.Size))
	}
	// A warning, not a failure: after the backup identity or passphrase
	// changed, an older archive that is fine can fail verification here.
	if bad := bk.failedVerify(); bad != nil {
		rec.Status = CheckWarn
		rec.Message += fmt.Sprintf("; the backup made %s failed verification: %s", ago(now.Sub(bad.CreatedAt)), truncateText(verifyError(bad), 200))
		rec.Hint = "Create a new backup, and check the backups directory and the backup identity or passphrase (Backups page)."
	}
	if newest != nil && newest.State == core.BackupFailed && (ready == nil || newest.CreatedAt.After(ready.CreatedAt)) {
		rec.Status = CheckWarn
		rec.Message += "; the latest attempt failed: " + truncateText(newest.Error, 200)
	}
	out := []DoctorCheck{rec}

	cfg, err := d.Backups.Config(ctx)
	if err != nil || cfg == nil {
		return out
	}
	if !cfg.Enabled || (strings.TrimSpace(cfg.ScheduleMeta) == "" && strings.TrimSpace(cfg.ScheduleFull) == "") {
		out = append(out, DoctorCheck{ID: "backup.schedule", Name: "Backup schedule", Status: CheckWarn,
			Message: "Scheduled backups are off", Hint: "Enable the backup schedules on the Backups page.", Link: link})
	}
	id := DoctorCheck{ID: "backup.identity", Name: "Backup decryption key", Link: link}
	switch {
	case cfg.Encryption == core.BackupPassphrase:
		if cfg.HasPassphrase {
			id.Status, id.Message = CheckOK, "Backups are encrypted with the backup passphrase; keep it somewhere safe"
		} else {
			id.Status, id.Message = CheckFail, "Passphrase encryption is selected but no passphrase is set"
			id.Hint = "Set a backup passphrase on the Backups page."
		}
	case cfg.HasIdentity:
		var exported *time.Time
		if t, ok := d.Backups.(identityExportTracker); ok {
			exported = t.IdentityExportedAt(ctx)
		}
		// The export record belongs to the current identity: one the server
		// generates by itself (no recipient configured) clears it, so an
		// export of the identity it replaced does not count here.
		if exported == nil {
			id.Status = CheckWarn
			id.Message = "The current backup identity has never been exported"
			id.Hint = "Export the backup identity and store it offline: backups cannot be restored on a new machine without it."
		} else {
			id.Status = CheckOK
			id.Message = "Backup identity exported " + ago(now.Sub(*exported))
		}
	case len(cfg.Recipients) > 0:
		id.Status = CheckInfo
		id.Message = "Backups are encrypted to external recipients only; this server cannot verify or restore them without their identity"
	default:
		id.Status, id.Message = CheckWarn, "No backup identity is configured yet"
		id.Hint = "Generate a backup identity on the Backups page and store it offline."
	}
	return append(out, id)
}

func checkDisk(d *app.Deps) DoctorCheck {
	c := DoctorCheck{ID: "disk", Name: "Disk space", Link: "/admin/system"}
	if d.Home == nil {
		c.Status, c.Message = CheckInfo, "Unknown"
		return c
	}
	size, free := diskUsage(d.Home.Dir())
	if size <= 0 {
		c.Status, c.Message = CheckInfo, "The free space could not be determined"
		return c
	}
	diskStatus(&c, size, free)
	return c
}

// diskStatus fills in the message, status and hint for a filesystem of size
// bytes with free bytes available (size > 0). The message reports the *used*
// share — the same figure the admin UI shows beside it on /admin and
// /admin/system — rounded half up like format.pct() there, so an operator
// never sees the same disk described by two different percentages. The
// thresholds still work off the free share.
func diskStatus(c *DoctorCheck, size, free int64) {
	freePct := free * 100 / size
	c.Message = fmt.Sprintf("%s free of %s (%s%% used)", human(free), human(size), uiPercent(size-free, size))
	switch {
	case free < diskFailBytes || freePct < diskFailPercent:
		c.Status, c.Hint = CheckFail, "Free up space: uploads, backups and the database need room to grow."
	case free < diskWarnBytes || freePct < diskWarnPercent:
		c.Status, c.Hint = CheckWarn, "Free up space or delete old backups soon."
	default:
		c.Status = CheckOK
	}
}

// uiPercent formats a/b (b > 0) exactly as format.pct() does in the admin UI
// (web/static/js/core/format.js): rounded half up, clamped to 0..100, with one
// decimal between 0 and 1 so a nearly empty disk does not read as "0%". Keep
// the two in step: the same number is printed twice on /admin and
// /admin/system, once by the browser and once from here.
func uiPercent(a, b int64) string {
	v := math.Max(0, math.Min(100, float64(a)/float64(b)*100))
	if v > 0 && v < 1 {
		return strconv.FormatFloat(math.Round(v*10)/10, 'f', 1, 64)
	}
	return strconv.FormatInt(int64(math.Round(v)), 10)
}

// checkDatabase runs PRAGMA quick_check (cached) and reports the WAL size.
func (h *handlers) checkDatabase(ctx context.Context, d *app.Deps, now time.Time, refresh bool) []DoctorCheck {
	if d.DB == nil {
		return []DoctorCheck{{ID: "database", Name: "Database", Status: CheckFail, Message: "The database is not open"}}
	}
	h.qc.mu.Lock()
	defer h.qc.mu.Unlock()
	integrity := h.qc.check
	if refresh || h.qc.at.IsZero() || now.Sub(h.qc.at) > quickCheckTTL || now.Before(h.qc.at) {
		cached := !h.qc.at.IsZero()
		c := quickCheck(ctx, d)
		// Only a check that really ran goes into the shared cache. quickCheck
		// reports "did not finish in time" whenever its context is done, and
		// that context comes from the request: a client that navigates away
		// mid-check would otherwise make every later visitor see an
		// unknown-integrity database for the whole TTL.
		switch {
		case ctx.Err() == nil:
			h.qc.check, h.qc.at = c, now
			integrity = c
		case cached:
			integrity = h.qc.check // keep serving the last real result
		default:
			integrity = c // nothing cached yet: report it, but do not store it
		}
	}
	out := []DoctorCheck{integrity}
	if d.Home != nil {
		if wal := fileSize(d.Home.DB() + "-wal"); wal > walWarnBytes {
			c := DoctorCheck{ID: "database.wal", Name: "Database journal", Status: CheckWarn,
				Message: "The write-ahead log is " + human(wal),
				Hint:    "Run the maintenance.db_optimize job (Jobs page) to checkpoint it.", Link: "/admin/jobs"}
			// Telling the operator to run a job that already ran and could
			// not do it would loop for ever: say what is actually in the way.
			if lastCheckpointWasBusy(ctx, d) {
				c.Message += "; the last maintenance.db_optimize could not truncate it (readers were active)"
				c.Hint = "Run the maintenance.db_optimize job (Jobs page) again when the server is idle."
			}
			out = append(out, c)
		}
	}
	return out
}

// lastCheckpointWasBusy reports whether the newest finished
// maintenance.db_optimize job found the truncating WAL checkpoint blocked
// (jobs.result.checkpoint_busy). Any read problem answers false: the plain
// hint is then still the right advice.
func lastCheckpointWasBusy(ctx context.Context, d *app.Deps) bool {
	if d.DB == nil {
		return false
	}
	cctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	var result []byte
	err := d.DB.QueryRow(cctx, `SELECT result FROM jobs WHERE kind = ? AND state = 'succeeded'
		AND finished_at IS NOT NULL ORDER BY finished_at DESC, id DESC LIMIT 1`, core.JobMaintDBOptimize).Scan(&result)
	if err != nil || len(result) == 0 {
		return false
	}
	var r struct {
		CheckpointBusy      int64 `json:"checkpoint_busy"`
		CheckpointTruncated bool  `json:"checkpoint_truncated"`
	}
	if json.Unmarshal(result, &r) != nil {
		return false
	}
	return r.CheckpointBusy != 0 && !r.CheckpointTruncated
}

func quickCheck(ctx context.Context, d *app.Deps) DoctorCheck {
	c := DoctorCheck{ID: "database", Name: "Database integrity", Link: "/admin/system"}
	cctx, cancel := context.WithTimeout(ctx, quickCheckLimit)
	defer cancel()
	// DB.IntegrityCheck runs on its own connection on purpose: a pooled
	// reader that has served a /search request reports phantom fts5
	// corruption after the writer merges a segment (see internal/db).
	problems, err := d.DB.IntegrityCheck(cctx, false)
	if err != nil {
		if cctx.Err() != nil {
			c.Status, c.Message = CheckInfo, "The integrity check did not finish in time"
			return c
		}
		c.Status, c.Message = CheckFail, "The integrity check failed: "+truncateText(err.Error(), 200)
		return c
	}
	if len(problems) > 3 {
		problems = problems[:3]
	}
	if len(problems) > 0 {
		c.Status = CheckFail
		c.Message = "Damaged: " + truncateText(strings.Join(problems, "; "), 300)
		c.Hint = "Restore the latest good backup (fileparcel backup restore)."
		return c
	}
	c.Status, c.Message = CheckOK, "quick_check passed"
	if d.Home != nil {
		c.Message += " (" + human(fileSize(d.Home.DB())) + ")"
	}
	return c
}

// buildTime parses the build date (RFC 3339 or YYYY-MM-DD; zero when unknown).
func buildTime(s string) time.Time {
	s = strings.TrimSpace(s)
	if t, err := time.Parse(time.RFC3339, s); err == nil {
		return t
	}
	if t, err := time.Parse("2006-01-02", s); err == nil {
		return t
	}
	return time.Time{}
}

// checkClock compares the clock with the build date and the newest stored
// timestamps (a clock behind them breaks expiry, TOTP and certificates).
func checkClock(ctx context.Context, d *app.Deps, now time.Time) DoctorCheck {
	c := DoctorCheck{ID: "clock", Name: "System clock", Link: "/admin/system"}
	if bt := buildTime(d.Build.Date); !bt.IsZero() && now.Add(24*time.Hour).Before(bt) {
		c.Status = CheckFail
		c.Message = fmt.Sprintf("The clock (%s) is before this program's build date (%s)",
			now.UTC().Format(time.RFC3339), bt.UTC().Format("2006-01-02"))
		c.Hint = "Enable time synchronisation (e.g. systemd-timesyncd or chrony)."
		return c
	}
	if d.DB != nil {
		var latest int64
		cctx, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
		// audit_log.at is indexed; jobs.created_at is covered by jobs_state.
		if err := d.DB.QueryRow(cctx, `SELECT max(m) FROM (SELECT max(at) AS m FROM audit_log
			UNION ALL SELECT max(created_at) FROM jobs)`).Scan(&latest); err == nil && latest > 0 {
			if t := time.UnixMilli(latest); t.After(now.Add(clockSkewAllow)) {
				c.Status = CheckWarn
				c.Message = fmt.Sprintf("Stored events are dated up to %s, after the current time %s: the clock went backwards",
					t.UTC().Format(time.RFC3339), now.UTC().Format(time.RFC3339))
				c.Hint = "Check the time synchronisation of this machine."
				return c
			}
		}
	}
	c.Status = CheckOK
	c.Message = now.Local().Format("2006-01-02 15:04:05 MST")
	return c
}

func checkMDNS(d *app.Deps) DoctorCheck {
	c := DoctorCheck{ID: "mdns", Name: "Local name (mDNS)", Link: "/admin/network"}
	if d.MDNS == nil {
		c.Status, c.Message = CheckInfo, "Not running (offline mode)"
		if d.Mode != app.ModeOffline {
			c.Message = "The mDNS service is not available"
		}
		return c
	}
	st := d.MDNS.Status()
	switch st.State {
	case core.MDNSPublished:
		c.Status, c.Message = CheckOK, fmt.Sprintf("%s published (%s)", st.Name, st.Backend)
		if st.Configured != "" && !strings.EqualFold(st.Name, st.Configured) {
			c.Status = CheckWarn
			c.Message = fmt.Sprintf("Published as %s, not as the configured %s (%s)", st.Name, st.Configured, st.Backend)
			c.Hint = "Another device on the network uses that name. Pick a different mDNS name, or republish once the other device is gone."
		}
	case core.MDNSOff:
		c.Status, c.Message = CheckInfo, "mDNS is off; use the IP address URLs"
		if d.Mode == app.ModeOffline {
			c.Message = "Not running (offline mode)"
		}
	case core.MDNSPublishing:
		c.Status, c.Message = CheckInfo, fmt.Sprintf("Publishing %s…", st.Name)
	case core.MDNSCollision:
		c.Status, c.Message = CheckWarn, fmt.Sprintf("Another device already uses %s", st.Name)
		c.Hint = "Choose another mDNS name in the network settings."
	default:
		c.Status = CheckWarn
		c.Message = "mDNS publishing failed"
		if st.Error != "" {
			c.Message += ": " + truncateText(st.Error, 200)
		}
		c.Hint = "On Linux, check that avahi-daemon is running."
	}
	return c
}

func checkAccess(d *app.Deps) DoctorCheck {
	c := DoctorCheck{ID: "access", Name: "Network access policy", Link: "/admin/network"}
	if d.Network == nil {
		c.Status, c.Message = CheckInfo, "Unknown"
		return c
	}
	pol := d.Network.Policy()
	if pol.Mode == core.AccessAny {
		c.Status = CheckWarn
		c.Message = "Connections are accepted from any address"
		c.Hint = "Unless the server sits behind another firewall, restrict access to your LAN and VPN networks."
		return c
	}
	c.Status = CheckOK
	c.Message = fmt.Sprintf("Mode %q (%d allowed, %d denied networks)", pol.Mode, len(pol.Allow), len(pol.Deny))
	return c
}

// checkAdmin2FA lists the active staff accounts without two-factor
// authentication: owners, admins and the holders of every custom role with a
// server permission (DESIGN §6a; auth.require_2fa=admins covers the same
// accounts).
func checkAdmin2FA(ctx context.Context, d *app.Deps) DoctorCheck {
	c := DoctorCheck{ID: "admin_2fa", Name: "Two-factor authentication for staff accounts", Link: "/admin/users"}
	if d.Users == nil || d.Auth == nil {
		c.Status, c.Message = CheckInfo, "Unknown"
		return c
	}
	queries := []core.UserQuery{{Role: core.RoleOwner}, {Role: core.RoleAdmin}}
	roles, err := d.Users.ListRoles(ctx, nil)
	if err != nil {
		c.Status, c.Message = CheckInfo, "The staff accounts could not be listed"
		return c
	}
	for _, r := range roles {
		if !r.Builtin && r.Staff {
			queries = append(queries, core.UserQuery{RoleID: r.ID})
		}
	}
	var staff []core.User
	for _, q := range queries {
		q.PageReq, q.Status = core.PageReq{Limit: maxAdminsDoctor}, "active"
		page, err := d.Users.List(ctx, q)
		if err != nil {
			c.Status, c.Message = CheckInfo, "The staff accounts could not be listed"
			return c
		}
		staff = append(staff, page.Items...)
	}
	// A status that cannot be read is never counted as "uses 2FA": the check
	// would otherwise vouch for accounts it did not inspect.
	var without []string
	total, unknown := 0, 0
	for _, u := range staff {
		if u.Status != "" && u.Status != "active" {
			continue
		}
		st, err := d.Auth.MFAStatus(ctx, u.ID)
		if errors.Is(err, core.ErrNotFound) {
			continue // deleted since the list was read
		}
		total++
		if err != nil || st == nil {
			unknown++
			continue
		}
		if !st.TOTPEnabled && st.PasskeyCount == 0 {
			without = append(without, u.Username)
		}
	}
	slices.Sort(without)
	switch {
	case total == 0:
		c.Status, c.Message = CheckInfo, "No active staff account"
	case len(without) > 0:
		c.Status = CheckWarn
		if len(without) > 10 {
			without = append(without[:10], "…")
		}
		c.Message = "Without two-factor authentication: " + strings.Join(without, ", ")
		if unknown > 0 {
			c.Message += fmt.Sprintf(" (the status of %d more could not be read)", unknown)
		}
		c.Hint = "Ask them to set up an authenticator app or a passkey (Settings → Security)."
	case unknown > 0:
		c.Status = CheckInfo
		c.Message = fmt.Sprintf("The two-factor status of %d of %d staff accounts could not be read", unknown, total)
	default:
		c.Status, c.Message = CheckOK, fmt.Sprintf("All %d staff accounts use two-factor authentication", total)
	}
	return c
}

func checkJobs(ctx context.Context, d *app.Deps, now time.Time) []DoctorCheck {
	var out []DoctorCheck
	if d.Jobs != nil {
		c := DoctorCheck{ID: "jobs.runner", Name: "Background jobs", Link: "/admin/jobs"}
		rs, ok := d.Jobs.(runnerState)
		switch {
		case d.Mode == app.ModeOffline:
			c.Status, c.Message = CheckInfo, "Not running (offline mode): queued jobs run when the server starts"
		case ok && !rs.Running():
			c.Status, c.Message = CheckWarn, "The job runner is not running"
		default:
			c.Status, c.Message = CheckOK, "Running"
		}
		out = append(out, c)
	}
	if d.DB != nil {
		cctx, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
		rows, err := d.DB.Query(cctx, `SELECT kind, count(*) FROM jobs WHERE state = 'failed' AND finished_at > ?
			GROUP BY kind ORDER BY kind`, now.Add(-24*time.Hour).UnixMilli())
		var parts []string
		total := 0
		if err == nil {
			for rows.Next() {
				var kind string
				var n int
				if err = rows.Scan(&kind, &n); err != nil {
					break
				}
				parts = append(parts, fmt.Sprintf("%s ×%d", kind, n))
				total += n
			}
			rows.Close()
			if err == nil {
				err = rows.Err()
			}
		}
		// A read that fails (or times out) must not read as "no failed jobs":
		// report it as info, which leaves the aggregate status alone.
		switch {
		case err != nil:
			msg := "The job history could not be read"
			if cctx.Err() != nil {
				msg = "The job history did not load in time"
			}
			out = append(out, DoctorCheck{ID: "jobs.failed", Name: "Failed jobs", Status: CheckInfo,
				Message: msg, Link: "/admin/jobs"})
		case total > 0:
			out = append(out, DoctorCheck{ID: "jobs.failed", Name: "Failed jobs", Status: CheckWarn,
				Message: fmt.Sprintf("%d failed in the last 24 hours: %s", total, strings.Join(parts, ", ")),
				Hint:    "Open the Jobs page for the error messages.", Link: "/admin/jobs"})
		}
	}
	if c := checkSchedules(ctx, d); c != nil {
		out = append(out, *c)
	}
	return out
}

// checkSchedules reports enabled schedules that have no next run. A cron
// spec that parses but can never match (February 30) used to be accepted
// everywhere and left the schedule enabled with next_run_at NULL, which the
// scheduler never selects again — dead for ever, with nothing to see. Rows
// written by such a version are still out there, so the doctor names them.
func checkSchedules(ctx context.Context, d *app.Deps) *DoctorCheck {
	if d.Jobs == nil || d.Mode == app.ModeOffline {
		return nil
	}
	cctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	scs, err := d.Jobs.Schedules(cctx)
	if err != nil {
		return nil
	}
	var dead []string
	for _, sc := range scs {
		if sc.Enabled && sc.NextRunAt == nil {
			dead = append(dead, fmt.Sprintf("%s (%s)", sc.Name, sc.Cron))
		}
	}
	if len(dead) == 0 {
		return nil
	}
	slices.Sort(dead)
	if len(dead) > 10 {
		dead = append(dead[:10], "…")
	}
	return &DoctorCheck{ID: "jobs.schedules", Name: "Job schedules", Status: CheckWarn,
		Message: "Enabled but never due again: " + strings.Join(dead, ", "),
		Hint:    "The schedule is enabled with no next run. Set a valid schedule (Backups page for backups, otherwise restart the server).",
		Link:    "/admin/jobs"}
}

// restoreFailedStale is how long a failed scheduled restore stays a warning.
// Only scheduling another restore or a later successful one removes
// run/restore.json.failed, so an operator who decides not to retry at all
// would otherwise never see the doctor go green again; after this it is
// reported as information.
const restoreFailedStale = 30 * 24 * time.Hour

// checkRestart reports settings waiting for a restart and the outcome of a
// scheduled restore.
func checkRestart(d *app.Deps, now time.Time) []DoctorCheck {
	var out []DoctorCheck
	if rr, ok := d.Settings.(interface{ RestartRequired() []string }); ok && d.Settings != nil {
		if l := rr.RestartRequired(); len(l) > 0 {
			out = append(out, DoctorCheck{ID: "restart", Name: "Restart required", Status: CheckWarn,
				Message: "Changed settings take effect after a restart: " + strings.Join(l, ", "),
				Hint:    "Restart the server (System page).", Link: "/admin/system"})
		}
	}
	if d.Home == nil {
		return out
	}
	if _, err := os.Stat(d.Home.RestoreFile()); err == nil {
		out = append(out, DoctorCheck{ID: "restore.pending", Name: "Pending restore", Status: CheckInfo,
			Message: "A restore is scheduled and runs at the next start", Link: "/admin/backups"})
	}
	marker := filepath.Join(d.Home.RunDir(), "restore.json.failed")
	if b, err := readLimited(marker, 64<<10); err == nil {
		var f struct {
			Error    string    `json:"error"`
			File     string    `json:"file"`
			FailedAt time.Time `json:"failed_at"`
		}
		msg := "The last scheduled restore failed"
		parsed := json.Unmarshal(b, &f) == nil
		if parsed && f.Error != "" {
			msg += " (" + f.File + "): " + truncateText(f.Error, 300)
		}
		c := DoctorCheck{ID: "restore.failed", Name: "Scheduled restore", Status: CheckWarn, Message: msg,
			Hint: "The server kept its previous data. Check the credentials and try again.", Link: "/admin/backups"}
		if parsed && !f.FailedAt.IsZero() && now.Sub(f.FailedAt) > restoreFailedStale {
			c.Status = CheckInfo
			c.Message = msg + " (" + ago(now.Sub(f.FailedAt)) + ")"
			c.Hint = "Nothing is wrong with the server. Delete " + marker + " to clear this note."
		}
		out = append(out, c)
	}
	return out
}

// checkFirewall prints, for every active host firewall, the rules that open
// the ports (and UDP 5353 for the builtin mDNS responder) with svc.Hints —
// the commands the installer summary and `fileparcel doctor` print.
func checkFirewall(ctx context.Context, d *app.Deps) []DoctorCheck {
	var active []svc.Firewall
	for _, fw := range detectFirewalls(ctx) {
		if fw.Active {
			active = append(active, fw)
		}
	}
	if len(active) == 0 {
		return nil
	}
	in := firewallInput(ctx, d)
	ports := strconv.Itoa(in.HTTPSPort)
	if in.HTTPPort > 0 && in.HTTPPort != in.HTTPSPort {
		ports += ", " + strconv.Itoa(in.HTTPPort)
	}
	need := "TCP port " + ports
	if in.BuiltinMDNS {
		need += " (and UDP port 5353 for the .local name)"
	}
	var out []DoctorCheck
	for _, fw := range active {
		c := DoctorCheck{ID: "firewall." + fw.Kind, Name: "Host firewall (" + fw.Kind + ")", Status: CheckInfo, Link: "/admin/network",
			Message: fmt.Sprintf("%s is active: other devices can only connect if it allows %s", fw.Kind, need)}
		if cmds := svc.Hints(fw.Kind, in); len(cmds) > 0 {
			c.Hint = "If devices cannot connect: " + strings.Join(cmds, " ; ")
		} else {
			c.Hint = fmt.Sprintf("Allow TCP port %d from your networks.", in.HTTPSPort)
		}
		out = append(out, c)
	}
	return out
}

// firewallInput describes what must be reachable, like the installer's
// summary does: the local (LAN/Wi-Fi) subnets and the other allowed
// networks by source, the VPNs devices come in through (roles mesh and
// unknown: Tailscale, Headscale, WireGuard, …) by their real interface
// names — never an exit, corporate or overlay VPN (DESIGN §10.1) — UDP 5353
// when the builtin mDNS responder answers, and every source when the access
// mode is "any".
func firewallInput(ctx context.Context, d *app.Deps) svc.HintInput {
	in := svc.HintInput{HTTPSPort: 8443}
	if d.Config != nil {
		in.HTTPSPort, in.HTTPPort = d.Config.Server.HTTPSPort, d.Config.Server.HTTPPort
	}
	if bin, err := os.Executable(); err == nil {
		in.Binary = bin
	}
	if d.MDNS != nil {
		st := d.MDNS.Status()
		in.BuiltinMDNS = st.Backend == mdns.BackendBuiltin && st.State != core.MDNSOff
	} else {
		in.BuiltinMDNS = builtinMDNSLikely()
	}
	if d.Network == nil {
		return in
	}
	pol := d.Network.Policy()
	in.Anywhere = pol.Mode == core.AccessAny
	var vpnNets []netip.Prefix
	if ifs, err := d.Network.Interfaces(ctx); err == nil {
		for _, it := range ifs {
			if !it.Up {
				continue
			}
			switch ifaceRole(it) {
			case core.VPNRoleLocal:
				for _, a := range it.Addrs {
					if a.Addr().Is4() && !a.Addr().IsLoopback() {
						in.Subnets = append(in.Subnets, a.Masked())
					}
				}
			case core.VPNRoleMesh, core.VPNRoleUnknown:
				if it.Name != "" && !slices.Contains(in.VPNIfaces, it.Name) {
					in.VPNIfaces = append(in.VPNIfaces, it.Name)
				}
				vpnNets = append(vpnNets, it.Addrs...)
			}
		}
	}
	// Allowed networks that are not a VPN range (those are opened by
	// interface above); svc.Hints drops duplicates, loopback and "everything".
	for _, s := range pol.Allow {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			a, aerr := netip.ParseAddr(s)
			if aerr != nil {
				continue
			}
			p = netip.PrefixFrom(a, a.BitLen())
		}
		if !slices.ContainsFunc(vpnNets, p.Overlaps) {
			in.Subnets = append(in.Subnets, p)
		}
	}
	return in
}

// ago describes a past duration ("just now", "1 minute ago", "3 hours ago",
// "2 days ago").
func ago(d time.Duration) string {
	switch {
	case d < time.Minute:
		return "just now"
	case d < time.Hour:
		return agoUnits(int(d.Minutes()), "minute")
	case d < 48*time.Hour:
		return agoUnits(int(d.Hours()), "hour")
	}
	return agoUnits(int(d.Hours()/24), "day")
}

// agoUnits renders "1 minute ago" / "5 minutes ago" (the unit is singular).
func agoUnits(n int, unit string) string {
	if n == 1 {
		return fmt.Sprintf("1 %s ago", unit)
	}
	return fmt.Sprintf("%d %ss ago", n, unit)
}

func truncateText(s string, n int) string {
	s = strings.TrimSpace(s)
	if len(s) <= n {
		return s
	}
	// Cut on a rune boundary.
	for n > 0 && n < len(s) && (s[n]&0xC0) == 0x80 {
		n--
	}
	return s[:n] + "…"
}

// readLimited reads at most max bytes of a small file.
func readLimited(path string, max int64) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return io.ReadAll(io.LimitReader(f, max))
}
