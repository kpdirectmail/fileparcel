package wire

import (
	"context"
	"net/http"
	"slices"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"

	"fileparcel/internal/app"
	"fileparcel/internal/core"
	"fileparcel/internal/jobs"
	"fileparcel/internal/settings"
	"fileparcel/internal/web"
)

// designRoutes is the route table of DESIGN §9.4, one "METHOD path" per
// entry, with the chi parameter names the modules use. Everything the router
// mounts must be here, and everything here must be mounted: this test fails
// on both a missing route and an undocumented one, so §9.4 and the code
// cannot drift apart silently.
var designRoutes = []string{
	// authapi (B)
	"GET /api/v1/auth/state",
	"POST /api/v1/auth/login", "POST /api/v1/auth/totp", "POST /api/v1/auth/recovery",
	"POST /api/v1/auth/passkey/begin", "POST /api/v1/auth/passkey/finish",
	"POST /api/v1/auth/logout", "POST /api/v1/auth/elevate", "POST /api/v1/auth/setup",
	"GET /api/v1/auth/invite/{token}", "POST /api/v1/auth/invite/{token}/accept",

	// meapi (B)
	"GET /api/v1/me", "PATCH /api/v1/me/profile", "POST /api/v1/me/password",
	"GET /api/v1/me/sessions", "DELETE /api/v1/me/sessions/{id}", "POST /api/v1/me/sessions/revoke-others",
	"GET /api/v1/me/mfa", "POST /api/v1/me/totp/begin", "POST /api/v1/me/totp/confirm", "DELETE /api/v1/me/totp",
	"POST /api/v1/me/recovery-codes",
	"GET /api/v1/me/passkeys", "POST /api/v1/me/passkeys/begin", "POST /api/v1/me/passkeys/finish",
	"PATCH /api/v1/me/passkeys/{id}", "DELETE /api/v1/me/passkeys/{id}",
	"GET /api/v1/me/tokens", "POST /api/v1/me/tokens", "DELETE /api/v1/me/tokens/{id}",
	"GET /api/v1/me/usage",

	// usersapi (C)
	"GET /api/v1/admin/users", "POST /api/v1/admin/users",
	"GET /api/v1/admin/users/{id}", "PATCH /api/v1/admin/users/{id}", "DELETE /api/v1/admin/users/{id}",
	"POST /api/v1/admin/users/{id}/password", "POST /api/v1/admin/users/{id}/unlock",
	"POST /api/v1/admin/users/{id}/reset-mfa",
	"POST /api/v1/admin/users/{id}/disable", "POST /api/v1/admin/users/{id}/enable",
	"GET /api/v1/admin/users/{id}/sessions", "DELETE /api/v1/admin/users/{id}/sessions",
	"GET /api/v1/admin/invites", "POST /api/v1/admin/invites", "DELETE /api/v1/admin/invites/{id}",
	"GET /api/v1/admin/groups", "POST /api/v1/admin/groups",
	"GET /api/v1/admin/groups/{id}", "PATCH /api/v1/admin/groups/{id}", "DELETE /api/v1/admin/groups/{id}",
	"GET /api/v1/admin/groups/{id}/members",
	"PUT /api/v1/admin/groups/{id}/members/{userId}", "DELETE /api/v1/admin/groups/{id}/members/{userId}",
	"GET /api/v1/groups", "GET /api/v1/users/lookup", "GET /api/v1/activity",
	"GET /api/v1/admin/roles", "POST /api/v1/admin/roles",
	"GET /api/v1/admin/roles/{id}", "PATCH /api/v1/admin/roles/{id}", "DELETE /api/v1/admin/roles/{id}",
	"GET /api/v1/admin/roles/{id}/groups",
	"PUT /api/v1/admin/roles/{id}/groups/{groupId}", "DELETE /api/v1/admin/roles/{id}/groups/{groupId}",
	"GET /api/v1/admin/capabilities", "GET /api/v1/admin/users/{id}/access", "GET /api/v1/roles",

	// filesapi (D)
	"GET /api/v1/spaces", "GET /api/v1/nodes/{id}", "GET /api/v1/nodes/{id}/children",
	"GET /api/v1/nodes/{id}/breadcrumbs", "POST /api/v1/nodes/{id}/folders", "PATCH /api/v1/nodes/{id}",
	"POST /api/v1/nodes/move", "POST /api/v1/nodes/copy", "POST /api/v1/nodes/trash",
	"GET /api/v1/nodes/{id}/content", "GET /api/v1/nodes/{id}/thumb", "GET /api/v1/nodes/{id}/stats",
	"GET /api/v1/nodes/{id}/versions", "POST /api/v1/nodes/{id}/versions/{vid}/restore",
	"GET /api/v1/nodes/{id}/grants", "POST /api/v1/nodes/{id}/grants", "DELETE /api/v1/nodes/{id}/grants/{gid}",
	"PUT /api/v1/nodes/{id}/star", "DELETE /api/v1/nodes/{id}/star",
	"GET /api/v1/trash", "POST /api/v1/trash/restore", "POST /api/v1/trash/purge", "DELETE /api/v1/trash",
	"GET /api/v1/search", "GET /api/v1/recent", "GET /api/v1/starred", "GET /api/v1/shared-with-me",
	"POST /api/v1/archives", "GET /api/v1/archives/{ticket}",
	"GET /api/v1/admin/grants",

	// uploadapi (E)
	"POST /api/v1/upload-batches", "GET /api/v1/upload-batches", "GET /api/v1/upload-batches/{id}",
	"POST /api/v1/upload-batches/{id}/files",
	"PUT /api/v1/upload-batches/{id}/small", "POST /api/v1/upload-batches/{id}/complete",
	"DELETE /api/v1/upload-batches/{id}",
	"GET /api/v1/uploads/{id}", "PUT /api/v1/uploads/{id}/parts/{n}", "POST /api/v1/uploads/{id}/complete",
	"DELETE /api/v1/uploads/{id}",

	// sharesapi (E)
	"GET /api/v1/shares", "POST /api/v1/shares",
	"GET /api/v1/shares/{id}", "PATCH /api/v1/shares/{id}", "DELETE /api/v1/shares/{id}",
	"GET /api/v1/shares/{id}/log", "GET /api/v1/shares/{id}/qr.svg", "GET /api/v1/admin/shares",
	"GET /s/{token}", "GET /s/{token}/api", "GET /s/{token}/api/list", "POST /s/{token}/api/password",
	"GET /s/{token}/dl/{nodeId}", "GET /s/{token}/thumb/{nodeId}",
	"POST /s/{token}/api/archive", "GET /s/{token}/zip/{ticket}",
	"POST /s/{token}/api/upload-batches", "PUT /s/{token}/api/upload-batches/{id}/small",
	"PUT /s/{token}/api/uploads/{id}/parts/{n}", "GET /s/{token}/api/uploads/{id}",
	"POST /s/{token}/api/uploads/{id}/complete", "POST /s/{token}/api/upload-batches/{id}/complete",
	// The share upload flow mirrors uploadapi, so the public root also needs
	// the batch/upload lookup, the multi-file registration and the cancels.
	"GET /s/{token}/api/upload-batches/{id}", "POST /s/{token}/api/upload-batches/{id}/files",
	"DELETE /s/{token}/api/upload-batches/{id}", "DELETE /s/{token}/api/uploads/{id}",

	// securityapi (F)
	"GET /api/v1/admin/certs", "POST /api/v1/admin/certs/renew", "POST /api/v1/admin/certs/ca/regenerate",
	"PUT /api/v1/admin/certs/custom", "DELETE /api/v1/admin/certs/custom",
	"POST /api/v1/admin/certs/acme/apply", "POST /api/v1/admin/certs/tailscale/fetch",
	"GET /api/v1/admin/client-certs", "POST /api/v1/admin/client-certs",
	"DELETE /api/v1/admin/client-certs/{id}",
	"GET /api/v1/admin/keys",
	"POST /api/v1/admin/keys/lock", "POST /api/v1/admin/keys/seal", "POST /api/v1/admin/keys/unseal",
	"POST /api/v1/admin/keys/passphrase", "POST /api/v1/admin/keys/rotate", "POST /api/v1/admin/keys/recovery",
	"GET /api/v1/me/client-certs", "POST /api/v1/me/client-certs",
	"GET /api/v1/system/status", "POST /api/v1/system/unlock",
	"GET /trust/ca.crt", "GET /trust/ca.pem", "GET /trust/ca.mobileconfig",
	// The .p12 is returned once; these serve the single-use download link.
	"GET /api/v1/admin/client-certs/download", "GET /api/v1/me/client-certs/download",
	"DELETE /api/v1/me/client-certs/{id}",

	// settingsapi (G)
	"GET /api/v1/admin/settings", "PATCH /api/v1/admin/settings", "DELETE /api/v1/admin/settings/{key}",
	"POST /api/v1/admin/settings/email/test",
	"GET /api/v1/admin/network", "PUT /api/v1/admin/network/policy",
	"GET /api/v1/admin/network/tailscale", "PUT /api/v1/admin/network/funnel", "PUT /api/v1/admin/network/serve", "POST /api/v1/admin/network/tailscale/reapply",
	"GET /api/v1/admin/mdns", "POST /api/v1/admin/mdns/republish",
	"GET /api/v1/network/urls", "GET /api/v1/qr.svg",

	// opsapi (H)
	"GET /api/v1/admin/backups", "POST /api/v1/admin/backups",
	"GET /api/v1/admin/backups/{id}", "DELETE /api/v1/admin/backups/{id}",
	"POST /api/v1/admin/backups/{id}/verify", "GET /api/v1/admin/backups/{id}/download",
	"POST /api/v1/admin/backups/import", "POST /api/v1/admin/backups/{id}/restore",
	"GET /api/v1/admin/backups/config", "PUT /api/v1/admin/backups/config",
	"POST /api/v1/admin/backups/identity", "POST /api/v1/admin/backups/identity/export",
	"GET /api/v1/admin/jobs", "GET /api/v1/admin/jobs/{id}", "POST /api/v1/admin/jobs/{id}/cancel",
	"POST /api/v1/admin/jobs/run", "GET /api/v1/admin/jobs/kinds", "GET /api/v1/admin/jobs/schedules",
	"GET /api/v1/admin/system", "POST /api/v1/admin/system/restart", "GET /api/v1/admin/system/doctor",
	"GET /api/v1/admin/system/logs", "GET /api/v1/admin/dashboard",
	"GET /api/v1/admin/audit", "GET /api/v1/admin/audit/verify", "GET /api/v1/admin/audit/export",
	"GET /api/v1/jobs/{id}", "GET /api/v1/events",

	// pages / static (I)
	"GET /", "GET /files", "GET /files/*", "GET /shared", "GET /links", "GET /requests",
	"GET /starred", "GET /recent", "GET /trash", "GET /activity", "GET /search",
	"GET /settings", "GET /settings/*", "GET /admin", "GET /admin/*",
	"GET /login", "GET /invite/{token}", "GET /setup", "GET /unlock", "GET /trust",
	"GET /static/{hash}/*", "GET /sw.js", "GET /manifest.webmanifest", "GET /theme.css",
	"GET /favicon.ico", "GET /robots.txt", "GET /.well-known/security.txt",
	"GET /healthz", "GET /readyz",
	// PWA share target (§13.7): the OS posts shared files here.
	"POST /share-target",
}

// mountedRoutes walks the real router of a fully wired deployment.
func mountedRoutes(t *testing.T, d *app.Deps) []string {
	t.Helper()
	var out []string
	err := chi.Walk(web.NewRouter(d).(chi.Routes),
		func(method, route string, _ http.Handler, _ ...func(http.Handler) http.Handler) error {
			out = append(out, method+" "+route)
			return nil
		})
	if err != nil {
		t.Fatal(err)
	}
	slices.Sort(out)
	return out
}

// buildForAudit wires every service over a temp home in network mode.
func buildForAudit(t *testing.T) *app.Deps {
	t.Helper()
	d, cleanup, err := Build(context.Background(), newTestHome(t), app.ModeNetwork)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(cleanup)
	return d
}

// diff reports the entries of want that got lacks and vice versa.
func diff(want, got []string) (missing, extra []string) {
	for _, w := range want {
		if !slices.Contains(got, w) {
			missing = append(missing, w)
		}
	}
	for _, g := range got {
		if !slices.Contains(want, g) {
			extra = append(extra, g)
		}
	}
	slices.Sort(missing)
	slices.Sort(extra)
	return missing, extra
}

// The mounted route table equals DESIGN §9.4.
func TestRouterMatchesDesign(t *testing.T) {
	got := mountedRoutes(t, buildForAudit(t))
	// chi routes HEAD through middleware.GetHead, so the walk reports GET only.
	for _, r := range got {
		if strings.HasPrefix(r, "HEAD ") {
			t.Errorf("unexpected explicit HEAD route: %s", r)
		}
	}
	missing, extra := diff(designRoutes, got)
	for _, m := range missing {
		t.Errorf("DESIGN §9.4 route not mounted: %s", m)
	}
	for _, e := range extra {
		t.Errorf("route mounted but not in DESIGN §9.4 (document it or drop it): %s", e)
	}
}

// Every job kind of DESIGN §9.7 is registered, and the periodic ones are
// scheduled.
func TestJobKindsMatchDesign(t *testing.T) {
	d := buildForAudit(t)
	want := []string{
		core.JobUploadZip, core.JobThumbsGenerate,
		core.JobBackupCreate, core.JobBackupVerify, core.JobBackupPrune,
		core.JobKeysRotateKEK, core.JobKeysReencrypt,
		core.JobMaintSessions, core.JobMaintUploads, core.JobMaintTrash, core.JobMaintBlobGC,
		core.JobMaintAuditPrune, core.JobMaintDBOptimize, core.JobMaintVersions,
		core.JobCertsRenewCheck,
	}
	js, ok := d.Jobs.(*jobs.Service)
	if !ok {
		t.Fatalf("jobs service is %T", d.Jobs)
	}
	got := js.Kinds()
	missing, extra := diff(want, got)
	for _, m := range missing {
		t.Errorf("DESIGN §9.7 job kind not registered: %s", m)
	}
	for _, e := range extra {
		t.Errorf("job kind registered but not in DESIGN §9.7: %s", e)
	}

	scheds, err := d.Jobs.Schedules(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	scheduled := map[string]bool{}
	for _, s := range scheds {
		scheduled[s.Kind] = true
	}
	// §9.7 gives these a cadence; the rest run on demand or after another job.
	for _, k := range []string{
		core.JobMaintSessions, core.JobMaintUploads, core.JobMaintTrash, core.JobMaintBlobGC,
		core.JobMaintAuditPrune, core.JobMaintDBOptimize, core.JobMaintVersions,
		core.JobCertsRenewCheck, core.JobBackupCreate,
	} {
		if !scheduled[k] {
			t.Errorf("%s has no schedule", k)
		}
	}
}

// Every setting of DESIGN §11.2 is registered by its owning package, with the
// documented default, and no package registers anything else.
func TestSettingsCatalogMatchesDesign(t *testing.T) {
	buildForAudit(t) // the settings.Register calls happen in the packages' init()
	want := map[string]string{
		// general (I)
		"ui.instance_name": `"FileParcel"`, "ui.accent_color": `"#2b7ad6"`,
		"ui.default_theme": `"system"`, "ui.login_message": `""`, "ui.default_view": `"list"`,
		"maintenance.enabled": `false`, "maintenance.message": `""`,
		// network (G)
		"network.access_mode": `"allowlist"`, "network.allow_cidrs": `[]`, "network.deny_cidrs": `[]`,
		"network.strict_host": `false`, "network.extra_hosts": `[]`,
		"network.iface_roles": `[]`,
		// mdns (G)
		"mdns.mode": `"auto"`, "mdns.name": `""`, "mdns.interfaces": `"lan"`, "mdns.zerotier": `false`,
		// tls (F)
		"tls.extra_sans": `[]`, "tls.hsts": `"auto"`, "tls.min_version": `"1.2"`, "tls.leaf_days": `397`,
		// acme (F)
		"acme.enabled": `false`, "acme.email": `""`, "acme.domains": `[]`, "acme.ca": `"staging"`,
		"acme.challenge": `"dns"`, "acme.dns_provider": `"cloudflare"`, "acme.dns_credentials": `""`,
		// tailscale (F)
		"tailscale.cert_enabled": `false`, "tailscale.domain": `""`,
		// funnel (G)
		"funnel.mode": `"off"`, "funnel.port": `443`, "funnel.allow_admin": `false`, "funnel.require_2fa": `true`,
		"funnel.serve": `false`, "funnel.serve_port": `443`, "funnel.node": `""`,
		"funnel.backend": `"auto"`, "funnel.backend_port": `0`,
		// mtls (F)
		"mtls.mode": `"off"`, "mtls.exempt_shares": `true`, "mtls.self_service": `false`,
		// auth (B)
		"auth.password_min": `12`, "auth.require_2fa": `"admins"`, "auth.passkeys": `true`,
		"auth.webauthn_rp_id": `""`, "auth.webauthn_origins": `[]`,
		"auth.session_idle_min": `720`, "auth.session_max_days": `30`,
		"auth.lockout_threshold": `10`, "auth.lockout_base_min": `15`, "auth.stepup_min": `10`,
		"auth.admin_can_access_files": `false`,
		// ratelimit (B)
		"ratelimit.login_per_min": `10`, "ratelimit.api_rps": `50`, "ratelimit.api_burst": `200`,
		"ratelimit.share_per_min": `120`, "ratelimit.unlock_per_min": `5`,
		"ratelimit.funnel_per_min": `1200`, "ratelimit.funnel_global_per_min": `12000`,
		// storage (A, D, E)
		"storage.default_quota_gb": `0`, "storage.max_file_gb": `0`, "storage.upload_parallel": `4`,
		"storage.upload_expiry_hours": `48`, "storage.trash_days": `30`, "storage.versions_keep": `10`,
		"storage.cipher": `"auto"`, "storage.zip_compression": `"auto"`, "storage.thumbnails": `true`,
		"storage.fsync": `true`,
		// storage, v4 password-protected zips (uploads)
		"storage.zip_password_min": `12`, "storage.zip_legacy_encryption": `true`,
		// sharing (E)
		"sharing.links_enabled": `true`, "sharing.require_password": `false`,
		"sharing.max_expiry_days": `0`, "sharing.default_expiry_days": `7`,
		"sharing.requests_enabled": `true`, "sharing.allow_guests_share": `false`,
		"sharing.access_log_days": `365`,
		// keys (A)
		"keys.web_unlock": `"lan"`,
		// backup (H)
		"backup.enabled": `true`, "backup.schedule_meta": `"0 3 * * *"`, "backup.schedule_full": `"0 4 * * 0"`,
		"backup.keep_last": `7`, "backup.keep_daily": `7`, "backup.keep_weekly": `4`, "backup.keep_monthly": `6`,
		"backup.encryption": `"x25519"`, "backup.recipients": `[]`, "backup.identity": `""`,
		"backup.passphrase": `""`, "backup.copy_to": `""`,
		// email (C)
		"smtp.host": `""`, "smtp.port": `587`, "smtp.tls": `"starttls"`, "smtp.username": `""`,
		"smtp.password": `""`, "smtp.from": `""`,
		"notify.events": `["share.upload","security"]`,
		// audit (C)
		"audit.retention_days": `365`, "audit.mirror_jsonl": `false`,
		// server bootstrap bridge (G)
		"server.https_port": `8443`, "server.http_port": `8080`, "server.bind": `["::"]`,
		"server.name": `"fileparcel"`, "server.public_url": `""`, "server.trusted_proxies": `[]`,
		"log.level": `"info"`, "runtime.gomemlimit_mb": `0`,
	}
	// §11.2 marks these "R" (restart required).
	restart := []string{"server.https_port", "server.http_port", "server.bind", "server.name",
		"server.public_url", "runtime.gomemlimit_mb"}

	var keys []string
	for _, d := range settings.Defs() {
		if strings.HasPrefix(d.Key, "test.") { // registered by other tests in this package
			continue
		}
		keys = append(keys, d.Key)
		w, ok := want[d.Key]
		if !ok {
			continue // reported as an extra below
		}
		if got := strings.TrimSpace(string(d.DefaultJSON())); got != w {
			t.Errorf("%s: default %s, DESIGN §11.2 says %s", d.Key, got, w)
		}
		if got, wantR := d.Restart, slices.Contains(restart, d.Key); got != wantR {
			t.Errorf("%s: restart=%v, DESIGN §11.2 says %v", d.Key, got, wantR)
		}
	}
	wantKeys := make([]string, 0, len(want))
	for k := range want {
		wantKeys = append(wantKeys, k)
	}
	missing, extra := diff(wantKeys, keys)
	for _, m := range missing {
		t.Errorf("DESIGN §11.2 setting not registered: %s", m)
	}
	for _, e := range extra {
		t.Errorf("setting registered but not in DESIGN §11.2: %s", e)
	}
	if t.Failed() {
		t.Logf("%d registered, %d documented", len(keys), len(want))
	}
}
