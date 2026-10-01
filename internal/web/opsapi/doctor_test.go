package opsapi

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"fileparcel/internal/app"
	"fileparcel/internal/core"
	"fileparcel/internal/home"
	"fileparcel/internal/svc"
)

func (r *DoctorReport) find(id string) *DoctorCheck {
	for i := range r.Checks {
		if r.Checks[i].ID == id {
			return &r.Checks[i]
		}
	}
	return nil
}

func (te *testEnv) doctor(query string) *DoctorReport {
	te.t.Helper()
	var rep DoctorReport
	r := te.do("GET", "/admin/system/doctor"+query, "admin", nil)
	if r.code != 200 {
		te.t.Fatalf("doctor %d %s", r.code, r.body)
	}
	r.json(te.t, &rep)
	return &rep
}

// A job history that cannot be read must not look like "no failed jobs":
// the check reports the failure (as info, so the overall status is unchanged).
func TestDoctorJobsUnreadable(t *testing.T) {
	te := newTestEnv(t, app.ModeNetwork)
	if _, err := te.d.DB.Exec(context.Background(), `DROP TABLE jobs`); err != nil {
		t.Fatal(err)
	}
	c := te.doctor("").find("jobs.failed")
	if c == nil || c.Status != CheckInfo || !strings.Contains(c.Message, "could not be read") {
		t.Fatalf("jobs.failed = %+v", c)
	}
}

func TestDoctorHealthy(t *testing.T) {
	te := newTestEnv(t, app.ModeNetwork)
	te.jobs.running = true
	exported := te.now.Add(-48 * time.Hour)
	te.backups.exportedAt = &exported
	te.backups.items = []core.Backup{{ID: "bak_1", State: core.BackupReady, Scope: core.BackupFull, CreatedAt: te.now.Add(-2 * time.Hour), Size: 1 << 20}}
	te.users.users = []core.User{
		{ID: "usr_owner", Username: "owner", Role: core.RoleOwner, Status: "active"},
		{ID: "usr_admin", Username: "admin", Role: core.RoleAdmin, Status: "active"},
		{ID: "usr_member", Username: "member", Role: core.RoleMember, Status: "active"},
	}
	te.auth.mfa["usr_owner"] = &core.MFAStatus{TOTPEnabled: true}
	te.auth.mfa["usr_admin"] = &core.MFAStatus{PasskeyCount: 1}

	rep := te.doctor("")
	if rep.GeneratedAt.IsZero() || len(rep.Checks) == 0 {
		t.Fatalf("report %+v", rep)
	}
	for _, id := range []string{"keys", "cert.leaf", "cert.ca", "backup.recent", "backup.identity", "database", "clock",
		"mdns", "access", "admin_2fa", "jobs.runner"} {
		c := rep.find(id)
		if c == nil {
			t.Errorf("check %s missing", id)
			continue
		}
		if c.Status != CheckOK {
			t.Errorf("check %s: %s %q", id, c.Status, c.Message)
		}
		if c.Name == "" || c.Message == "" {
			t.Errorf("check %s without name/message", id)
		}
	}
	for _, id := range []string{"backup.schedule", "jobs.failed", "restart", "restore.failed", "cert.acme"} {
		if c := rep.find(id); c != nil {
			t.Errorf("unexpected check %s: %+v", id, c)
		}
	}
	for _, c := range rep.Checks {
		if strings.HasPrefix(c.ID, "firewall") {
			t.Errorf("firewall check without an active firewall: %+v", c)
		}
	}
	// "disk" depends on the machine running the test: just present.
	if rep.find("disk") == nil {
		t.Error("disk check missing")
	}
	if rep.find("admin_2fa").Message != "All 2 staff accounts use two-factor authentication" {
		t.Errorf("2fa message %q", rep.find("admin_2fa").Message)
	}
}

func TestDoctorProblems(t *testing.T) {
	te := newTestEnv(t, app.ModeNetwork)
	te.keys.state = core.KeyStateLocked
	te.certs.st.Leaf.NotAfter = te.now.Add(-time.Hour)
	te.certs.st.CA.NotAfter = te.now.Add(30 * 24 * time.Hour)
	te.certs.st.ACMEEnabled, te.certs.st.ACMEError = true, "DNS challenge failed"
	te.certs.st.TailscaleError = "no operator"
	te.mdns.st = core.MDNSStatus{State: core.MDNSError, Error: "avahi not running"}
	te.net.pol = core.AccessPolicy{Mode: core.AccessAny}
	te.net.ifs = []core.NetInterface{
		{Name: "eth0", Kind: core.IfLAN, Up: true, Addrs: []netip.Prefix{netip.MustParsePrefix("192.168.1.10/24"), netip.MustParsePrefix("fe80::1/64")}},
		{Name: "tailscale0", Kind: core.IfTailscale, Up: true},
	}
	te.users.users = []core.User{{ID: "usr_admin", Username: "admin", Role: core.RoleAdmin, Status: "active"}}
	te.backups.items = []core.Backup{
		{ID: "bak_2", State: core.BackupFailed, Error: "disk full", CreatedAt: te.now.Add(-time.Hour)},
		{ID: "bak_1", State: core.BackupReady, CreatedAt: te.now.Add(-30 * 24 * time.Hour)},
	}
	te.backups.config.Enabled = false
	te.backups.exportedAt = nil
	te.jobs.running = false
	detectFirewalls = func(context.Context) []svc.Firewall { return []svc.Firewall{{Kind: svc.FirewallUFW, Active: true}} }
	ctx := context.Background()
	if _, err := te.d.DB.Exec(ctx, `INSERT INTO jobs (id, kind, state, params, created_at, finished_at) VALUES
		('job_f1', 'backup.create', 'failed', '{}', ?, ?), ('job_f2', 'backup.create', 'failed', '{}', ?, ?)`,
		te.now.UnixMilli(), te.now.UnixMilli(), te.now.UnixMilli(), te.now.UnixMilli()); err != nil {
		t.Fatal(err)
	}
	// A stored event from the future: the clock went backwards.
	if _, err := te.d.DB.Exec(ctx, `INSERT INTO jobs (id, kind, state, params, created_at) VALUES ('job_future', 'x', 'queued', '{}', ?)`,
		te.now.Add(time.Hour).UnixMilli()); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(te.h.RunDir(), "restore.json.failed"),
		[]byte(`{"backup_id":"bak_9","file":"fp-x.fpbak","error":"wrong identity","failed_at":"`+
			te.now.Add(-48*time.Hour).UTC().Format(time.RFC3339)+`"}`), 0o600); err != nil {
		t.Fatal(err)
	}

	rep := te.doctor("")
	want := map[string]string{
		"keys": CheckFail, "cert.leaf": CheckFail, "cert.ca": CheckWarn, "cert.acme": CheckWarn, "cert.tailscale": CheckWarn,
		"backup.recent": CheckWarn, "backup.schedule": CheckWarn, "backup.identity": CheckWarn, "mdns": CheckWarn,
		"access": CheckWarn, "admin_2fa": CheckWarn, "jobs.runner": CheckWarn, "jobs.failed": CheckWarn, "clock": CheckWarn,
		"restore.failed": CheckWarn, "firewall.ufw": CheckInfo,
	}
	for id, st := range want {
		c := rep.find(id)
		if c == nil {
			t.Errorf("check %s missing", id)
			continue
		}
		if c.Status != st {
			t.Errorf("check %s: %s (%q), want %s", id, c.Status, c.Message, st)
		}
	}
	if rep.OK || rep.Failures < 2 || rep.Warnings < 10 {
		t.Errorf("summary ok=%v failures=%d warnings=%d", rep.OK, rep.Failures, rep.Warnings)
	}
	if m := rep.find("backup.recent").Message; !strings.Contains(m, "30 days old") || !strings.Contains(m, "disk full") {
		t.Errorf("backup message %q", m)
	}
	if m := rep.find("jobs.failed").Message; !strings.Contains(m, "backup.create ×2") {
		t.Errorf("failed jobs message %q", m)
	}
	if m := rep.find("restore.failed").Message; !strings.Contains(m, "wrong identity") {
		t.Errorf("restore message %q", m)
	}
	// Access mode "any": one rule for every source (per-network and
	// per-interface rules would be redundant next to it).
	fw := rep.find("firewall.ufw")
	if !strings.Contains(fw.Hint, "sudo ufw allow proto tcp to any port 8443,8080") ||
		strings.Contains(fw.Hint, "from 192.168.1.0/24 to any port 8443,8080 proto tcp") || strings.Contains(fw.Hint, "in on tailscale0") {
		t.Errorf("firewall hint %q", fw.Hint)
	}
	if c := rep.find("admin_2fa"); !strings.Contains(c.Message, "admin") {
		t.Errorf("2fa message %q", c.Message)
	}

	// firewalld hint (access mode "any" here: the ports are open to every source).
	detectFirewalls = func(context.Context) []svc.Firewall {
		return []svc.Firewall{{Kind: svc.FirewallFirewalld, Active: true}}
	}
	if h := te.doctor("").find("firewall.firewalld").Hint; !strings.Contains(h, "--add-port=8443/tcp") || !strings.Contains(h, "--reload") {
		t.Errorf("firewalld hint %q", h)
	}
}

func TestDoctorVariants(t *testing.T) {
	te := newTestEnv(t, app.ModeOffline)
	te.keys.state, te.keys.mode, te.keys.rec = core.KeyStateUnlocked, core.KeyModeSealed, false
	te.backups.config = core.BackupConfig{Enabled: true, ScheduleMeta: "0 3 * * *", Encryption: core.BackupPassphrase}
	te.d.MDNS = nil
	te.d.Network = nil
	te.d.Certs = nil
	te.d.Users = nil
	rep := te.doctor("")
	checks := map[string]string{
		"keys": CheckWarn, "backup.identity": CheckFail, "mdns": CheckInfo, "access": CheckInfo,
		"cert.leaf": CheckWarn, "admin_2fa": CheckInfo, "jobs.runner": CheckInfo, "backup.recent": CheckWarn,
	}
	for id, st := range checks {
		if c := rep.find(id); c == nil || c.Status != st {
			t.Errorf("check %s = %+v, want %s", id, c, st)
		}
	}
	te.backups.config.HasPassphrase = true
	if c := te.doctor("").find("backup.identity"); c.Status != CheckOK {
		t.Errorf("passphrase configured: %+v", c)
	}
	te.backups.config = core.BackupConfig{Enabled: true, ScheduleFull: "0 4 * * 0", Encryption: core.BackupX25519, Recipients: []string{"age1x"}}
	if c := te.doctor("").find("backup.identity"); c.Status != CheckInfo {
		t.Errorf("external recipients: %+v", c)
	}
	te.backups.config.Recipients = nil
	if c := te.doctor("").find("backup.identity"); c.Status != CheckWarn {
		t.Errorf("no identity: %+v", c)
	}
	te.keys.state = core.KeyStateUninitialized
	if c := te.doctor("").find("keys"); c.Status != CheckFail {
		t.Errorf("uninitialized keys: %+v", c)
	}
	te.d.Backups = nil
	if c := te.doctor("").find("backup.recent"); c == nil || c.Status != CheckWarn {
		t.Errorf("no backup service: %+v", c)
	}
	// A pending restore is reported.
	if err := os.WriteFile(te.h.RestoreFile(), []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	if c := te.doctor("").find("restore.pending"); c == nil || c.Status != CheckInfo {
		t.Errorf("pending restore: %+v", c)
	}
}

func TestDoctorQuickCheckCache(t *testing.T) {
	te := newTestEnv(t, app.ModeNetwork)
	first := te.doctor("").find("database")
	if first == nil || first.Status != CheckOK {
		t.Fatalf("database check %+v", first)
	}
	// A closed database makes a fresh check fail; the cached one is served
	// until it expires or ?refresh=1 is given.
	_ = te.d.DB.Close()
	if c := te.doctor("").find("database"); c.Status != CheckOK {
		t.Fatalf("cache not used: %+v", c)
	}
	if c := te.doctor("?refresh=1").find("database"); c.Status != CheckFail {
		t.Fatalf("refresh not honoured: %+v", c)
	}
	te.now = te.now.Add(quickCheckTTL + time.Minute)
	if c := te.doctor("").find("database"); c.Status != CheckFail {
		t.Fatalf("cache did not expire: %+v", c)
	}
}

func TestCertCheckAndClock(t *testing.T) {
	now := time.Date(2026, 9, 19, 12, 0, 0, 0, time.UTC)
	day := 24 * time.Hour
	tests := []struct {
		nb, na time.Time
		want   string
	}{
		{now.Add(-day), now.Add(100 * day), CheckOK},
		{now.Add(-day), now.Add(5 * day), CheckWarn},
		{now.Add(-day), now.Add(-time.Second), CheckFail},
		{now.Add(day), now.Add(100 * day), CheckWarn},
	}
	for i, tt := range tests {
		c := certCheck("cert.leaf", "Server certificate", &core.CertInfo{NotBefore: tt.nb, NotAfter: tt.na}, now, certWarn)
		if c.Status != tt.want {
			t.Errorf("%d: %s %q", i, c.Status, c.Message)
		}
	}
	for in, ok := range map[string]bool{"2026-01-02T03:04:05Z": true, "2026-01-02": true, "": false, "garbage": false} {
		if got := !buildTime(in).IsZero(); got != ok {
			t.Errorf("buildTime(%q)", in)
		}
	}
	// A clock before the build date fails.
	te := newTestEnv(t, app.ModeNetwork)
	te.d.Build.Date = te.now.Add(10 * day).Format(time.RFC3339)
	if c := te.doctor("").find("clock"); c.Status != CheckFail {
		t.Errorf("clock before build: %+v", c)
	}
}

// The disk check reports the same share of the disk the admin UI shows next
// to it (used, not free) and in the same units, so /admin and /admin/system
// never describe one disk with two contradictory percentages. The thresholds
// still work off the free share.
func TestDiskStatusReportsUsedShare(t *testing.T) {
	const gib = int64(1) << 30
	tests := []struct {
		size, free int64
		want       string
		status     string
	}{
		// Live values from one page load of a 7.2 GiB disk: the storage tile
		// says "(69% used)", so the health check must not say "(31%)".
		{7696261120, 2408849408, "2.2 GiB free of 7.2 GiB (69% used)", CheckWarn},
		{7696261120, 2974367744, "2.8 GiB free of 7.2 GiB (61% used)", CheckWarn},
		{7696261120, 2791728742, "2.6 GiB free of 7.2 GiB (64% used)", CheckWarn},
		{100 * gib, 50 * gib, "50.0 GiB free of 100.0 GiB (50% used)", CheckOK},
		{100 * gib, 6 * gib, "6.0 GiB free of 100.0 GiB (94% used)", CheckWarn},     // < 10% free
		{100 * gib, 3 * gib, "3.0 GiB free of 100.0 GiB (97% used)", CheckWarn},     // < 5 GiB free
		{100 * gib, gib + gib/2, "1.5 GiB free of 100.0 GiB (99% used)", CheckFail}, // < 2% free
		{100 * gib, gib / 2, "512.0 MiB free of 100.0 GiB (100% used)", CheckFail},  // < 1 GiB free
		{gib, 0, "0 B free of 1.0 GiB (100% used)", CheckFail},
		{gib, gib, "1.0 GiB free of 1.0 GiB (0% used)", CheckWarn}, // empty but tiny disk
		// Below 1% the UI prints one decimal; so does the doctor.
		{100 * gib, 100*gib - 300<<20, "99.7 GiB free of 100.0 GiB (0.3% used)", CheckOK},
	}
	for _, tt := range tests {
		c := DoctorCheck{ID: "disk"}
		diskStatus(&c, tt.size, tt.free)
		if c.Message != tt.want {
			t.Errorf("size=%d free=%d: %q, want %q", tt.size, tt.free, c.Message, tt.want)
		}
		if c.Status != tt.status {
			t.Errorf("size=%d free=%d: status %s, want %s", tt.size, tt.free, c.Status, tt.status)
		}
		if strings.Contains(c.Message, "%)") {
			t.Errorf("size=%d free=%d: unlabelled percentage in %q", tt.size, tt.free, c.Message)
		}
	}
	// The percentage rounds exactly like format.pct() in the admin UI
	// (web/static/js/core/format.js), which rounds half up.
	for _, size := range []int64{7696261120, 100 << 30, 999, 1 << 40, 3} {
		for i := range int64(101) {
			free := size * i / 100
			c := DoctorCheck{ID: "disk"}
			diskStatus(&c, size, free)
			want := math.Round(float64(size-free) / float64(size) * 100)
			if got := pctIn(t, c.Message); got != want {
				t.Fatalf("size=%d free=%d: %q reports %v%%, the UI shows %v%%", size, free, c.Message, got, want)
			}
		}
	}
}

// pctIn extracts the "(NN% used)" figure from a disk message.
func pctIn(t *testing.T, msg string) float64 {
	t.Helper()
	_, rest, ok := strings.Cut(msg, "(")
	pct, _, ok2 := strings.Cut(rest, "% used)")
	n, err := strconv.ParseFloat(pct, 64)
	if !ok || !ok2 || err != nil {
		t.Fatalf("no percentage in %q", msg)
	}
	return n
}

// doctorAborted performs GET /admin/system/doctor with an already-cancelled
// context — what the handler sees when a client navigates away mid-request.
func (te *testEnv) doctorAborted(query string) *DoctorReport {
	te.t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	req := httptest.NewRequest("GET", "/api/v1/admin/system/doctor"+query, nil).WithContext(ctx)
	req.Header.Set("X-Test-As", "admin")
	rec := httptest.NewRecorder()
	te.handler.ServeHTTP(rec, req)
	if rec.Code != 200 {
		te.t.Fatalf("doctor %d %s", rec.Code, rec.Body.Bytes())
	}
	var rep DoctorReport
	if err := json.Unmarshal(rec.Body.Bytes(), &rep); err != nil {
		te.t.Fatalf("decode %q: %v", rec.Body.Bytes(), err)
	}
	return &rep
}

// The quick_check result is cached for ten minutes and shared by everyone;
// the dashboard loads the doctor on every visit. A request whose client went
// away makes quickCheck report "did not finish in time", and caching that
// made a perfectly healthy server report an unknown-integrity database to
// everyone for the rest of the TTL.
func TestDoctorQuickCheckCacheSurvivesAbortedRequest(t *testing.T) {
	te := newTestEnv(t, app.ModeNetwork)
	// Nothing cached yet: an abandoned page load must not become the answer.
	te.doctorAborted("")
	te.now = te.now.Add(time.Minute)
	if c := te.doctor("").find("database"); c == nil || c.Status != CheckOK || !strings.Contains(c.Message, "quick_check passed") {
		t.Fatalf("the cache was poisoned by an aborted request: %+v", c)
	}
	// With a real result cached, an aborted refresh must not replace it
	// either — neither for itself nor for the next visitor.
	if c := te.doctorAborted("?refresh=1").find("database"); c == nil || c.Status != CheckOK {
		t.Errorf("aborted refresh served %+v, want the cached result", c)
	}
	te.now = te.now.Add(time.Minute)
	if c := te.doctor("").find("database"); c == nil || c.Status != CheckOK {
		t.Fatalf("the cache was poisoned by an aborted refresh: %+v", c)
	}
}

// An enabled schedule with no next run never fires again. Nothing else
// reports it (Schedules() just says enabled=true, next_run_at=null), so the
// doctor has to.
func TestDoctorDeadSchedule(t *testing.T) {
	te := newTestEnv(t, app.ModeNetwork)
	next := te.now.Add(time.Hour)
	te.jobs.schedules = []core.JobSchedule{
		{Name: "backup.meta", Cron: "0 3 * * *", Kind: core.JobBackupCreate, Enabled: true, NextRunAt: &next},
		{Name: "off", Cron: "0 3 30 2 *", Kind: core.JobBackupCreate, Enabled: false},
	}
	if c := te.doctor("").find("jobs.schedules"); c != nil {
		t.Fatalf("unexpected check %+v", c)
	}
	te.jobs.schedules = append(te.jobs.schedules,
		core.JobSchedule{Name: "backup.full", Cron: "0 3 30 2 *", Kind: core.JobBackupCreate, Enabled: true})
	c := te.doctor("").find("jobs.schedules")
	if c == nil || c.Status != CheckWarn || !strings.Contains(c.Message, "backup.full") ||
		!strings.Contains(c.Message, "0 3 30 2 *") {
		t.Fatalf("jobs.schedules = %+v", c)
	}
	if strings.Contains(c.Message, "backup.meta") || strings.Contains(c.Message, "off") {
		t.Errorf("healthy and disabled schedules reported: %q", c.Message)
	}
}

// Telling the operator to run maintenance.db_optimize when the last run
// already tried and was blocked by active readers loops for ever: the hint
// has to say what is in the way.
func TestDoctorWALHintAfterBlockedCheckpoint(t *testing.T) {
	te := newTestEnv(t, app.ModeNetwork)
	// Point Home at an empty layout whose journal is a big sparse file (the
	// live database's own WAL must not be touched).
	h2, err := home.New(filepath.Join(t.TempDir(), "home2"))
	if err != nil {
		t.Fatal(err)
	}
	if err := h2.EnsureLayout(); err != nil {
		t.Fatal(err)
	}
	wal := h2.DB() + "-wal"
	if err := os.WriteFile(wal, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Truncate(wal, walWarnBytes+1); err != nil {
		t.Fatal(err)
	}
	te.d.Env.Home = h2

	c := te.doctor("").find("database.wal")
	if c == nil || c.Status != CheckWarn || !strings.Contains(c.Hint, "maintenance.db_optimize") {
		t.Fatalf("database.wal = %+v", c)
	}
	if strings.Contains(c.Hint, "idle") {
		t.Errorf("hint blames readers with no evidence: %q", c.Hint)
	}
	ctx := context.Background()
	if _, err := te.d.DB.Exec(ctx, `INSERT INTO jobs (id, kind, state, params, result, created_at, finished_at)
		VALUES ('job_ck', ?, 'succeeded', '{}', ?, ?, ?)`, core.JobMaintDBOptimize,
		`{"checkpoint_busy":1,"checkpoint_log":317,"checkpointed_pages":109,"checkpoint_truncated":false}`,
		te.now.UnixMilli(), te.now.UnixMilli()); err != nil {
		t.Fatal(err)
	}
	c = te.doctor("?refresh=1").find("database.wal")
	if c == nil || !strings.Contains(c.Message, "could not truncate") || !strings.Contains(c.Hint, "idle") {
		t.Fatalf("after a blocked checkpoint: %+v", c)
	}
}

// Only a later successful restore removes run/restore.json.failed, so an
// operator who decides not to retry would never see the doctor go green
// again. Old failures step down to information and say how to clear them.
func TestDoctorRestoreFailedAgesOut(t *testing.T) {
	te := newTestEnv(t, app.ModeNetwork)
	marker := filepath.Join(te.h.RunDir(), "restore.json.failed")
	write := func(age time.Duration) {
		t.Helper()
		body := fmt.Sprintf(`{"backup_id":"bak_9","file":"fileparcel-2026-01-01.tar.age","error":"wrong passphrase","failed_at":%q}`,
			te.now.Add(-age).UTC().Format(time.RFC3339))
		if err := os.WriteFile(marker, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write(48 * time.Hour)
	if c := te.doctor("").find("restore.failed"); c == nil || c.Status != CheckWarn {
		t.Fatalf("a recent failure must still warn: %+v", c)
	}
	write(400 * 24 * time.Hour)
	c := te.doctor("").find("restore.failed")
	if c == nil || c.Status != CheckInfo {
		t.Fatalf("a 400-day-old failure still blocks a green doctor: %+v", c)
	}
	if !strings.Contains(c.Hint, marker) {
		t.Errorf("no way to clear it: hint = %q", c.Hint)
	}
	if rep := te.doctor(""); rep.Warnings != 0 {
		for _, ch := range rep.Checks {
			if ch.Status == CheckWarn {
				t.Logf("still warning: %+v", ch)
			}
		}
	}
}

// The web doctor prints the same firewall commands as the installer and
// `fileparcel doctor` (svc.Hints): every active firewall (nftables and the
// macOS application firewall too), every VPN interface by its real name —
// a Headscale node's tailscale0 is kind "headscale" — the other allowed
// networks by source, and UDP 5353 when the builtin mDNS responder answers.
func TestDoctorFirewallHints(t *testing.T) {
	te := newTestEnv(t, app.ModeNetwork)
	te.net.pol = core.AccessPolicy{Mode: core.AccessAllowlist, Allow: []string{"192.168.1.0/24", "100.64.0.0/10", "10.9.0.0/16", "192.168.7.20"}}
	te.net.ifs = []core.NetInterface{
		{Name: "lo", Kind: core.IfLoopback, Up: true, Addrs: []netip.Prefix{netip.MustParsePrefix("127.0.0.1/8")}},
		{Name: "eth0", Kind: core.IfLAN, Up: true, Addrs: []netip.Prefix{netip.MustParsePrefix("192.168.1.10/24"), netip.MustParsePrefix("fe80::1/64")}},
		{Name: "tailscale0", Kind: core.IfHeadscale, Up: true, Addrs: []netip.Prefix{netip.MustParsePrefix("100.101.102.103/32")}},
		{Name: "wg0", Kind: core.IfWireGuard, Up: true, Addrs: []netip.Prefix{netip.MustParsePrefix("10.8.0.1/24")}},
		{Name: "docker0", Kind: core.IfContainer, Up: true, Addrs: []netip.Prefix{netip.MustParsePrefix("172.17.0.1/16")}},
		{Name: "zt0", Kind: core.IfZeroTier, Up: false},
	}
	te.mdns.st = core.MDNSStatus{State: core.MDNSPublished, Name: "fileparcel.local", Backend: "builtin"}
	fws := []svc.Firewall{{Kind: svc.FirewallUFW, Active: true}, {Kind: svc.FirewallNftables, Active: true},
		{Kind: svc.FirewallFirewalld, Active: false}}
	detectFirewalls = func(context.Context) []svc.Firewall { return fws }

	rep := te.doctor("")
	ufw, nft := rep.find("firewall.ufw"), rep.find("firewall.nftables")
	if ufw == nil || nft == nil || rep.find("firewall.firewalld") != nil {
		t.Fatalf("firewall checks: %+v", rep.Checks)
	}
	if ufw.Status != CheckInfo || nft.Status != CheckInfo || !strings.Contains(ufw.Message, "UDP port 5353") {
		t.Errorf("ufw %+v nftables %+v", ufw, nft)
	}
	for _, want := range []string{
		"sudo ufw allow from 192.168.1.0/24 to any port 8443,8080 proto tcp",
		"sudo ufw allow from 10.9.0.0/16 to any port 8443,8080 proto tcp",
		"sudo ufw allow from 192.168.7.20/32 to any port 8443,8080 proto tcp",
		"sudo ufw allow in on tailscale0 to any port 8443 proto tcp",
		"sudo ufw allow in on wg0 to any port 8443 proto tcp",
		"sudo ufw allow from 192.168.1.0/24 to any port 5353 proto udp",
	} {
		if !strings.Contains(ufw.Hint, want) {
			t.Errorf("ufw hint lacks %q: %q", want, ufw.Hint)
		}
	}
	// VPN ranges are opened by interface; containers, loopback and down
	// interfaces not at all.
	for _, bad := range []string{"100.64.0.0/10", "10.8.0.0/24", "docker0", "172.17.", "127.0.0", "zt0", "fe80"} {
		if strings.Contains(ufw.Hint, bad) {
			t.Errorf("ufw hint mentions %q: %q", bad, ufw.Hint)
		}
	}
	if !strings.Contains(nft.Hint, "nft insert rule inet filter input ip saddr 192.168.1.0/24") ||
		!strings.Contains(nft.Hint, `iifname "tailscale0"`) || !strings.Contains(nft.Hint, "udp dport 5353") {
		t.Errorf("nftables hint %q", nft.Hint)
	}

	// firewalld: source-restricted rich rules (not the ports for everyone)
	// and the mdns service.
	fws = []svc.Firewall{{Kind: svc.FirewallFirewalld, Active: true}}
	fwd := te.doctor("").find("firewall.firewalld")
	if fwd == nil || !strings.Contains(fwd.Hint, `source address="192.168.1.0/24" port port="8443"`) ||
		!strings.Contains(fwd.Hint, "--add-service=mdns") || !strings.Contains(fwd.Hint, "--reload") ||
		strings.Contains(fwd.Hint, "sudo firewall-cmd --permanent --add-port=8443/tcp") {
		t.Errorf("firewalld %+v", fwd)
	}

	// A Tailscale interface that is not called tailscale0; Avahi answers
	// mDNS itself, so no 5353 rule.
	te.net.ifs = []core.NetInterface{
		{Name: "eth0", Kind: core.IfLAN, Up: true, Addrs: []netip.Prefix{netip.MustParsePrefix("192.168.1.10/24")}},
		{Name: "ts-custom", Kind: core.IfTailscale, Up: true},
	}
	te.mdns.st.Backend = "avahi"
	fws = []svc.Firewall{{Kind: svc.FirewallUFW, Active: true}}
	ufw = te.doctor("").find("firewall.ufw")
	if ufw == nil || !strings.Contains(ufw.Hint, "sudo ufw allow in on ts-custom to any port 8443 proto tcp") ||
		strings.Contains(ufw.Hint, "tailscale0") || strings.Contains(ufw.Hint, "5353") || strings.Contains(ufw.Message, "5353") {
		t.Errorf("ufw %+v", ufw)
	}

	// The macOS application firewall allows the binary.
	fws = []svc.Firewall{{Kind: svc.FirewallMacOS, Active: true}}
	if c := te.doctor("").find("firewall." + svc.FirewallMacOS); c == nil || !strings.Contains(c.Hint, "--unblockapp") {
		t.Errorf("socketfilterfw %+v", c)
	}
}

// The newest usable backup is the one the dashboard and the doctor vouch
// for: not an imported archive (dated "now" when this server cannot decrypt
// it), not one whose verification failed, and an unreadable list is not
// "no backup yet".
func TestDoctorBackupHealth(t *testing.T) {
	te := newTestEnv(t, app.ModeNetwork)
	no, yes := false, true
	recent := func() *DoctorCheck {
		t.Helper()
		c := te.doctor("").find("backup.recent")
		if c == nil {
			t.Fatal("backup.recent missing")
		}
		return c
	}

	// Only a backup that failed verification.
	te.backups.items = []core.Backup{{ID: "bak_2", State: core.BackupReady, Scope: core.BackupFull, CreatedAt: te.now.Add(-time.Hour),
		VerifyOK: &no, Error: "verification failed: the backup file is missing"}}
	c := recent()
	if c.Status != CheckWarn || !strings.Contains(c.Message, "No usable backup") || !strings.Contains(c.Message, "failed verification: the backup file is missing") ||
		strings.Contains(c.Message, "verification failed: verification failed") {
		t.Errorf("only a bad backup: %+v", c)
	}
	// An older good one: that is the last backup, and the failure still shows.
	te.backups.items = append(te.backups.items, core.Backup{ID: "bak_1", State: core.BackupReady, Scope: core.BackupFull,
		CreatedAt: te.now.Add(-48 * time.Hour), Size: 1 << 20})
	if c := recent(); c.Status != CheckWarn || !strings.HasPrefix(c.Message, "Last backup 2 days ago") || !strings.Contains(c.Message, "failed verification") {
		t.Errorf("bad backup over a good one: %+v", c)
	}
	// Verified fine: all good. Unverified backups count too.
	te.backups.items[0].VerifyOK, te.backups.items[0].Error = &yes, ""
	if c := recent(); c.Status != CheckOK || !strings.Contains(c.Message, "1 hour ago") {
		t.Errorf("verified backup: %+v", c)
	}
	// An older backup that fails verification (say, after an identity change)
	// under a newer good one is not this check's business.
	te.backups.items[1].VerifyOK = &no
	if c := recent(); c.Status != CheckOK {
		t.Errorf("older failed verification: %+v", c)
	}

	// Imported archives say nothing about this server's backups.
	te.backups.items = []core.Backup{
		{ID: "bak_imp", State: core.BackupReady, Trigger: core.TriggerImport, Scope: core.BackupFull, CreatedAt: te.now},
		{ID: "bak_f", State: core.BackupFailed, Trigger: core.TriggerSchedule, Error: "disk full", CreatedAt: te.now.Add(-time.Hour)},
		{ID: "bak_old", State: core.BackupReady, Trigger: core.TriggerSchedule, Scope: core.BackupFull, CreatedAt: te.now.Add(-30 * 24 * time.Hour)},
	}
	if c := recent(); c.Status != CheckWarn || !strings.Contains(c.Message, "30 days old") || !strings.Contains(c.Message, "disk full") {
		t.Errorf("import hides a stale, failing schedule: %+v", c)
	}
	te.backups.items = te.backups.items[:1]
	if c := recent(); c.Status != CheckWarn || c.Message != "No backup has been made yet" {
		t.Errorf("only an import: %+v", c)
	}

	// The list cannot be read: say so (info), not "create a backup".
	te.backups.items = []core.Backup{{ID: "bak_1", State: core.BackupReady, CreatedAt: te.now.Add(-time.Hour)}}
	te.backups.listErr = core.Errorf(core.ErrUnavailable, "database is locked")
	c = recent()
	if c.Status != CheckInfo || !strings.Contains(c.Message, "could not be read") || strings.Contains(c.Hint, "Create a backup") {
		t.Errorf("unreadable list: %+v", c)
	}
	if te.doctor("").find("backup.identity") == nil {
		t.Error("the configuration checks were skipped")
	}
}

// A status that cannot be read never counts as "uses 2FA".
func TestDoctorAdmin2FAUnreadable(t *testing.T) {
	te := newTestEnv(t, app.ModeNetwork)
	te.users.users = []core.User{
		{ID: "usr_a", Username: "anna", Role: core.RoleOwner, Status: "active"},
		{ID: "usr_b", Username: "ben", Role: core.RoleAdmin, Status: "active"},
	}
	locked := fmt.Errorf("database is locked")
	te.auth.errs = map[string]error{"usr_a": locked, "usr_b": locked}
	c := te.doctor("").find("admin_2fa")
	if c.Status != CheckInfo || !strings.Contains(c.Message, "2 of 2") || !strings.Contains(c.Message, "could not be read") {
		t.Errorf("all unreadable: %+v", c)
	}
	// One unreadable, one without 2FA: the known gap wins.
	delete(te.auth.errs, "usr_b")
	c = te.doctor("").find("admin_2fa")
	if c.Status != CheckWarn || !strings.Contains(c.Message, "ben") || !strings.Contains(c.Message, "1 more could not be read") {
		t.Errorf("mixed: %+v", c)
	}
	// Deleted since the list was read: not counted at all.
	te.auth.errs["usr_a"] = core.NotFoundf("user not found")
	te.auth.mfa["usr_b"] = &core.MFAStatus{TOTPEnabled: true}
	c = te.doctor("").find("admin_2fa")
	if c.Status != CheckOK || c.Message != "All 1 staff accounts use two-factor authentication" {
		t.Errorf("deleted admin: %+v", c)
	}
}

// The local leaf renews after two thirds of its own lifetime when that is
// less than 30 days (certs.renewBefore): a healthy short-lived leaf is not
// "expiring", an overdue renewal is, and the default leaf keeps 14 days.
func TestLeafWarnFollowsLifetime(t *testing.T) {
	day := 24 * time.Hour
	leaf := func(nb time.Time, span time.Duration) *core.CertInfo {
		return &core.CertInfo{NotBefore: nb, NotAfter: nb.Add(span)}
	}
	now := time.Date(2026, 9, 19, 12, 0, 0, 0, time.UTC)
	if got := leafWarn(leaf(now, 397*day)); got != certWarn {
		t.Errorf("leafWarn(397d) = %v", got)
	}
	if got := leafWarn(leaf(now, 7*day)); got != 7*day/6 {
		t.Errorf("leafWarn(7d) = %v", got)
	}
	if got := leafWarn(&core.CertInfo{}); got != certWarn {
		t.Errorf("leafWarn(no span) = %v", got)
	}
	tests := []struct {
		ci   *core.CertInfo
		want string
	}{
		{leaf(now.Add(-time.Hour), 7*day), CheckOK},              // just issued
		{leaf(now.Add(-5*day), 7*day), CheckOK},                  // 2 d left: renewal due (2⅓ d), not late
		{leaf(now.Add(-6*day-2*time.Hour), 7*day), CheckWarn},    // 22 h left: renewal is overdue
		{leaf(now.Add(-7*day-time.Hour), 7*day), CheckFail},      // expired
		{leaf(now.Add(day), 7*day), CheckWarn},                   // not valid yet
		{leaf(now.Add(-7*day), 14*day), CheckOK},                 // 7 d left of 14
		{leaf(now.Add(-14*day+time.Hour), 14*day), CheckWarn},    // 1 h left of 14
		{leaf(now.Add(-20*day), 40*day), CheckOK},                // 20 d left, renews at 13⅓
		{leaf(now.Add(-37*day), 40*day), CheckWarn},              // 3 d left
		{leaf(now.Add(-300*day), 397*day), CheckOK},              // 97 d left
		{leaf(now.Add(-100*day), 115*day), CheckOK},              // 15 d left
		{leaf(now.Add(-387*day), 397*day), CheckWarn},            // 10 d left: the 14 days still apply
		{&core.CertInfo{NotAfter: now.Add(20 * day)}, CheckOK},   // no NotBefore
		{&core.CertInfo{NotAfter: now.Add(10 * day)}, CheckWarn}, // … the 14 days apply
	}
	for i, tt := range tests {
		if c := certCheck("cert.leaf", "Server certificate", tt.ci, now, leafWarn(tt.ci)); c.Status != tt.want {
			t.Errorf("%d: %s %q (warn below %v)", i, c.Status, c.Message, leafWarn(tt.ci))
		}
	}

	// The doctor and the dashboard use it for the local leaf.
	te := newTestEnv(t, app.ModeNetwork)
	te.certs.st.Leaf = leaf(te.now.Add(-2*day), 7*day)
	if c := te.doctor("").find("cert.leaf"); c.Status != CheckOK {
		t.Errorf("healthy 7-day leaf: %+v", c)
	}
	var dash core.Dashboard
	te.do("GET", "/admin/dashboard", "admin", nil).json(t, &dash)
	for _, w := range dash.Warnings {
		if strings.Contains(w, "certificate expires") {
			t.Errorf("healthy 7-day leaf: dashboard warns %q", w)
		}
	}
	te.certs.st.Leaf = leaf(te.now.Add(-6*day-12*time.Hour), 7*day)
	if c := te.doctor("").find("cert.leaf"); c.Status != CheckWarn {
		t.Errorf("overdue 7-day leaf: %+v", c)
	}
}
