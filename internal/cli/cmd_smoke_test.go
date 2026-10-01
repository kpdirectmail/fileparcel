package cli

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"fileparcel/internal/core"
	"fileparcel/internal/ids"
)

// smokeCase runs one command against the fake API with a few extra routes
// and checks the exit code, an output fragment and the requests made.
type smokeCase struct {
	name   string
	routes map[string]any // "METHOD /path" → response value (nil → 204; error → error response)
	args   []string
	stdin  string
	code   int
	out    string   // expected fragment of stdout+stderr
	calls  []string // "METHOD /path" that must have been requested
}

func runSmoke(t *testing.T, cases []smokeCase) {
	t.Helper()
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newFakeAPI(t)
			addUserRoutes(f)
			for route, resp := range tc.routes {
				method, pattern, _ := strings.Cut(route, " ")
				resp := resp
				f.handle(method, pattern, func(w http.ResponseWriter, r *http.Request) {
					switch v := resp.(type) {
					case nil:
						w.WriteHeader(http.StatusNoContent)
					case error:
						writeErr(w, v)
					case string:
						w.Write([]byte(v))
					default:
						writeJSON(w, 200, v)
					}
				})
			}
			res := f.run(t, tc.stdin, tc.args...)
			if res.code != tc.code {
				t.Fatalf("exit %d, want %d\nstdout: %s\nstderr: %s", res.code, tc.code, res.stdout, res.stderr)
			}
			if tc.out != "" && !strings.Contains(res.stdout+res.stderr, tc.out) {
				t.Fatalf("output lacks %q\nstdout: %s\nstderr: %s", tc.out, res.stdout, res.stderr)
			}
			for _, c := range tc.calls {
				if f.requestedPrefix(c) == 0 {
					t.Fatalf("no request %q (made: %v)", c, f.requests)
				}
			}
		})
	}
}

func TestSmokeUsersGroupsInvites(t *testing.T) {
	gid := ids.New(ids.PrefixGroup)
	groups := core.Page[core.Group]{Items: []core.Group{{ID: gid, Name: "Design", MemberCount: 1, Description: "d"}}}
	now := time.Now()
	runSmoke(t, []smokeCase{
		{name: "user disable", args: []string{"user", "disable", "alice"}, routes: map[string]any{"POST /api/v1/admin/users/{id}/disable": nil},
			out: `disabled user "Alice"`, calls: []string{"POST /api/v1/admin/users/"}},
		{name: "user enable json", args: []string{"--json", "user", "enable", "alice"}, routes: map[string]any{"POST /api/v1/admin/users/{id}/enable": nil},
			out: `"action": "enable"`},
		{name: "user unlock", args: []string{"user", "unlock", "admin"}, routes: map[string]any{"POST /api/v1/admin/users/{id}/unlock": nil}, out: "unlocked"},
		{name: "user reset-2fa", args: []string{"-y", "user", "reset-2fa", "alice"}, routes: map[string]any{"POST /api/v1/admin/users/{id}/reset-mfa": nil},
			out: "second factors"},
		{name: "user reset-2fa declined", args: []string{"user", "reset-2fa", "alice"}, stdin: "no\n", code: ExitFailure, out: "aborted"},
		{name: "user sessions", args: []string{"user", "sessions", "alice"}, routes: map[string]any{"GET /api/v1/admin/users/{id}/sessions": []core.Session{
			{ID: "ses_1", IP: "10.0.0.1", UserAgent: "Firefox", CreatedAt: now, LastSeenAt: now, ExpiresAt: now.Add(time.Hour)}}}, out: "Firefox"},
		{name: "user revoke-sessions", args: []string{"user", "revoke-sessions", "alice"}, routes: map[string]any{"DELETE /api/v1/admin/users/{id}/sessions": nil},
			out: "revoked all sessions"},
		{name: "user edit", args: []string{"user", "edit", "alice", "--display-name", "Alice L", "--email", "", "--must-change"}, out: "updated user"},
		{name: "user passwd stdin", args: []string{"user", "passwd", "alice", "--password-stdin"}, stdin: "new pass phrase\n", out: "reset the password"},
		{name: "group list", args: []string{"group", "list"}, routes: map[string]any{"GET /api/v1/admin/groups": groups}, out: "Design"},
		{name: "group create", args: []string{"group", "create", "Ops", "--description", "ops team"},
			routes: map[string]any{"POST /api/v1/admin/groups": core.Group{ID: gid, Name: "Ops"}}, out: `created group "Ops"`},
		{name: "group rename", args: []string{"group", "rename", "design", "Product"}, routes: map[string]any{"GET /api/v1/admin/groups": groups,
			"PATCH /api/v1/admin/groups/{id}": core.Group{ID: gid, Name: "Product"}}, out: `renamed group "Design" to "Product"`},
		{name: "group delete", args: []string{"-y", "group", "delete", "Design"}, routes: map[string]any{"GET /api/v1/admin/groups": groups,
			"DELETE /api/v1/admin/groups/{id}": nil}, out: "deleted group", calls: []string{"DELETE /api/v1/admin/groups/" + gid}},
		{name: "group members", args: []string{"group", "members", gid}, routes: map[string]any{"GET /api/v1/admin/groups/{id}": groups.Items[0],
			"GET /api/v1/admin/groups/{id}/members": []core.GroupMember{{Username: "bob", Role: core.GroupRoleManager}}}, out: "manager"},
		{name: "group remove-member", args: []string{"group", "remove-member", "Design", "alice"}, routes: map[string]any{"GET /api/v1/admin/groups": groups,
			"DELETE /api/v1/admin/groups/{id}/members/{uid}": nil}, out: "removed"},
		{name: "invite list", args: []string{"invite", "list"}, routes: map[string]any{"GET /api/v1/admin/invites": core.Page[core.Invite]{Items: []core.Invite{
			{ID: "inv_a", Role: core.RoleMember, Status: core.InviteActive, MaxUses: 1, ExpiresAt: now, Note: "workshop"},
			{ID: "inv_b", Role: core.RoleGuest, Status: core.InviteExpired}}}}, out: "workshop"},
		{name: "invite revoke", args: []string{"invite", "revoke", "inv_a"}, routes: map[string]any{"DELETE /api/v1/admin/invites/{id}": nil}, out: "revoked invite"},
		{name: "token revoke", args: []string{"token", "revoke", "tok_x"}, routes: map[string]any{"DELETE /api/v1/me/tokens/{id}": nil}, out: "revoked token"},
	})
}

func TestSmokeSecurity(t *testing.T) {
	now := time.Now()
	status := core.CertStatus{CA: &core.CertInfo{Subject: "FileParcel Local CA", NotAfter: now.Add(24 * time.Hour)}, CAConstrained: true,
		PermittedDNS: []string{".local"}, Leaf: &core.CertInfo{Subject: "leaf", DNSNames: []string{"fileparcel.local"}, IPs: []string{"127.0.0.1"}},
		MTLSMode: "off", ACMEEnabled: true, ACME: []core.CertInfo{{Subject: "files.example.com"}}, ACMEError: "rate limited",
		TailscaleError: "no operator"}
	keys := core.KeyStatus{State: core.KeyStateUnlocked, Mode: core.KeyModeSealed}
	dir := t.TempDir()
	certPEM := filepath.Join(dir, "c.pem")
	keyPEM := filepath.Join(dir, "k.pem")
	os.WriteFile(certPEM, []byte("-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n"), 0o600)
	os.WriteFile(keyPEM, []byte("-----BEGIN PRIVATE KEY-----\nMIIB\n-----END PRIVATE KEY-----\n"), 0o600)
	notPEM := filepath.Join(dir, "x.txt")
	os.WriteFile(notPEM, []byte("hello"), 0o600)
	runSmoke(t, []smokeCase{
		{name: "cert status", args: []string{"cert", "status"}, routes: map[string]any{"GET /api/v1/admin/certs": status}, out: "rate limited"},
		{name: "cert renew force", args: []string{"cert", "renew", "--force"}, routes: map[string]any{"POST /api/v1/admin/certs/renew": status}, out: "reissued"},
		{name: "cert upload", args: []string{"cert", "upload", "--cert", certPEM, "--key", keyPEM}, routes: map[string]any{"PUT /api/v1/admin/certs/custom": status},
			out: "custom certificate installed"},
		{name: "cert upload not pem", args: []string{"cert", "upload", "--cert", notPEM, "--key", keyPEM}, code: ExitFailure, out: "not a PEM file"},
		{name: "cert upload missing key", args: []string{"cert", "upload", "--cert", certPEM}, code: ExitUsage},
		{name: "cert clear-custom", args: []string{"cert", "clear-custom"}, routes: map[string]any{"DELETE /api/v1/admin/certs/custom": nil}, out: "removed"},
		{name: "cert tailscale fetch", args: []string{"cert", "tailscale", "fetch"}, routes: map[string]any{"POST /api/v1/admin/certs/tailscale/fetch": status}, out: "fetched"},
		{name: "ca show", args: []string{"ca", "show"}, routes: map[string]any{"GET /api/v1/admin/certs": status}, out: "Permitted names"},
		{name: "ca show no ca", args: []string{"ca", "show"}, routes: map[string]any{"GET /api/v1/admin/certs": core.CertStatus{}}, code: ExitFailure, out: "no local CA"},
		{name: "ca regenerate", args: []string{"-y", "ca", "regenerate", "--unconstrained"}, routes: map[string]any{"POST /api/v1/admin/certs/ca/regenerate": status},
			out: "new local CA created"},
		{name: "client-cert list", args: []string{"client-cert", "list", "--all"}, routes: map[string]any{"GET /api/v1/admin/client-certs": core.Page[core.ClientCert]{
			Items: []core.ClientCert{{ID: "ccr_1", Name: "phone", Serial: "0a:0b", NotAfter: now.Add(-time.Hour)}, {ID: "ccr_2", Name: "laptop", NotAfter: now.Add(time.Hour)}}}},
			out: "expired"},
		{name: "client-cert revoke by serial", args: []string{"client-cert", "revoke", "0A0B", "--reason", "lost"}, routes: map[string]any{
			"GET /api/v1/admin/client-certs":         core.Page[core.ClientCert]{Items: []core.ClientCert{{ID: "ccr_1", Serial: "0a:0b"}}},
			"DELETE /api/v1/admin/client-certs/{id}": nil}, out: "revoked client certificate ccr_1", calls: []string{"DELETE /api/v1/admin/client-certs/ccr_1"}},
		{name: "client-cert revoke unknown", args: []string{"client-cert", "revoke", "ff"}, routes: map[string]any{
			"GET /api/v1/admin/client-certs": core.Page[core.ClientCert]{}}, code: ExitFailure, out: "no client certificate"},
		{name: "keys unlock", args: []string{"keys", "unlock", "--passphrase-stdin"}, stdin: "my pass\n", routes: map[string]any{
			"GET /api/v1/system/status": core.SystemStatus{State: core.KeyStateLocked}, "POST /api/v1/system/unlock": nil}, out: "unlocked"},
		{name: "keys unlock already", args: []string{"keys", "unlock"}, routes: map[string]any{
			"GET /api/v1/system/status": core.SystemStatus{State: core.KeyStateUnlocked}}, out: "already unlocked"},
		{name: "keys lock", args: []string{"-y", "keys", "lock"}, routes: map[string]any{"POST /api/v1/admin/keys/lock": keys}, out: "locked"},
		{name: "keys seal", args: []string{"-y", "keys", "seal", "--passphrase-stdin"}, stdin: "a long enough passphrase\n",
			routes: map[string]any{"POST /api/v1/admin/keys/seal": keys}, out: "sealed"},
		{name: "keys seal short", args: []string{"-y", "keys", "seal", "--passphrase-stdin"}, stdin: "short\n",
			routes: map[string]any{"POST /api/v1/admin/keys/seal": keys}, out: "weak"},
		{name: "keys unseal", args: []string{"-y", "keys", "unseal", "--passphrase-stdin"}, stdin: "pass\n",
			routes: map[string]any{"POST /api/v1/admin/keys/unseal": keys}, out: "unsealed"},
		{name: "keys export-recovery", args: []string{"-y", "keys", "export-recovery"}, routes: map[string]any{
			"POST /api/v1/admin/keys/recovery": core.RecoveryKey{RecoveryKey: "FPRK-AAAA-BBBB"}}, out: "FPRK-AAAA-BBBB"},
		{name: "keys rotate master", args: []string{"keys", "rotate", "--master"}, routes: map[string]any{"POST /api/v1/admin/keys/rotate": keys},
			out: "rotated the master key"},
		{name: "keys rotate data no-wait", args: []string{"keys", "rotate", "--data", "--no-wait"}, routes: map[string]any{
			"POST /api/v1/admin/keys/rotate": core.JobRef{JobID: "job_123"}}, out: "job job_123 started"},
		{name: "keys rotate purpose without kek", args: []string{"keys", "rotate", "--master", "--purpose", "field"}, code: ExitUsage},
		{name: "keys status locked", args: []string{"keys", "status"}, routes: map[string]any{"GET /api/v1/admin/keys": core.ErrKeysLocked,
			"GET /api/v1/system/status": core.SystemStatus{State: core.KeyStateLocked}}, out: "State: locked"},
		{name: "mdns status", args: []string{"mdns", "status"}, routes: map[string]any{"GET /api/v1/admin/mdns": core.MDNSStatus{Name: "fileparcel.local",
			State: core.MDNSPublished, Backend: "avahi"}}, out: "avahi"},
		{name: "mdns republish", args: []string{"mdns", "republish"}, routes: map[string]any{"POST /api/v1/admin/mdns/republish": nil}, out: "republished"},
		{name: "network interfaces", args: []string{"network", "interfaces"}, routes: map[string]any{"GET /api/v1/admin/network": core.NetworkOverview{
			Interfaces: []core.NetInterface{{Name: "tailscale0", Label: "Tailscale", Up: true, IsVPN: true}}}}, out: "tailscale0"},
		{name: "network policy json", args: []string{"--json", "network", "policy"}, routes: map[string]any{"GET /api/v1/admin/network": core.NetworkOverview{
			Policy: core.AccessPolicy{Mode: "private"}}}, out: `"mode": "private"`},
		{name: "network allow list", args: []string{"network", "allow", "list"}, routes: map[string]any{"GET /api/v1/admin/network": core.NetworkOverview{
			Policy: core.AccessPolicy{Mode: "allowlist", Allow: []string{"10.0.0.0/8"}}}}, out: "10.0.0.0/8"},
	})
}

func TestSmokeBackupsSharesJobs(t *testing.T) {
	now := time.Now()
	bid := ids.New(ids.PrefixBackup)
	ok, bad := true, false
	backup := core.Backup{ID: bid, State: core.BackupReady, Scope: core.BackupFull, Size: 10, CreatedAt: now, VerifyOK: &ok, VerifiedAt: &now,
		Recipients: []string{"age1abc"}, FileName: "b.fpbak"}
	failed := backup
	failed.VerifyOK, failed.Error = &bad, "bad member"
	cfg := core.BackupConfig{Enabled: true, Encryption: core.BackupX25519, Recipients: []string{"age1abc"}, HasIdentity: true}
	dir := t.TempDir()
	local := filepath.Join(dir, "x.fpbak")
	os.WriteFile(local, []byte("archive"), 0o600)
	share := core.Share{ID: "shr_1", Kind: core.ShareLink, NodeName: "a.pdf", Status: core.ShareActive, URL: "/s/abc", CreatedAt: now}
	runSmoke(t, []smokeCase{
		{name: "backup list", args: []string{"backup", "list"}, routes: map[string]any{"GET /api/v1/admin/backups": core.Page[core.Backup]{Items: []core.Backup{backup, failed}}},
			out: "FAILED"},
		{name: "backup list empty", args: []string{"backup", "list"}, routes: map[string]any{"GET /api/v1/admin/backups": core.Page[core.Backup]{}}, out: "no backups yet"},
		{name: "backup show", args: []string{"backup", "show", bid}, routes: map[string]any{"GET /api/v1/admin/backups/{id}": backup}, out: "age1abc"},
		{name: "backup delete", args: []string{"-y", "backup", "delete", bid}, routes: map[string]any{"GET /api/v1/admin/backups/{id}": backup,
			"DELETE /api/v1/admin/backups/{id}": nil}, out: "deleted backup"},
		{name: "backup verify no-wait", args: []string{"backup", "verify", bid, "--deep", "--no-wait"}, routes: map[string]any{
			"POST /api/v1/admin/backups/{id}/verify": core.JobRef{JobID: "job_v"}}, out: "verification job job_v started",
			calls: []string{"POST /api/v1/admin/backups/" + bid + "/verify"}},
		{name: "backup import", args: []string{"backup", "import", local}, routes: map[string]any{"POST /api/v1/admin/backups/import": backup}, out: "imported"},
		{name: "backup verify missing file", args: []string{"backup", "verify", filepath.Join(dir, "nope.fpbak")}, code: ExitUsage},
		{name: "backup schedule show", args: []string{"backup", "schedule", "show"}, routes: map[string]any{"GET /api/v1/admin/backups/config": cfg}, out: "Metadata backups"},
		{name: "backup schedule disable", args: []string{"backup", "schedule", "disable"}, routes: map[string]any{"GET /api/v1/admin/backups/config": cfg,
			"PUT /api/v1/admin/backups/config": nil}, out: "scheduled backups disabled"},
		{name: "backup config show", args: []string{"backup", "config", "show"}, routes: map[string]any{"GET /api/v1/admin/backups/config": cfg}, out: "Identity stored"},
		{name: "backup config set nothing", args: []string{"backup", "config", "set"}, code: ExitUsage},
		{name: "backup identity show", args: []string{"backup", "identity", "show"}, routes: map[string]any{"GET /api/v1/admin/backups/config": cfg}, out: "age1abc"},
		{name: "backup identity generate", args: []string{"-y", "backup", "identity", "generate"}, routes: map[string]any{
			"POST /api/v1/admin/backups/identity": core.BackupIdentity{Recipient: "age1new", Identity: "AGE-SECRET-KEY-1XYZ"}}, out: "AGE-SECRET-KEY-1XYZ"},
		{name: "backup export not ready", args: []string{"backup", "export", bid, dir}, routes: map[string]any{
			"GET /api/v1/admin/backups/{id}": core.Backup{ID: bid, State: core.BackupRunning}}, code: ExitFailure, out: "not ready"},
		{name: "backup prune", args: []string{"backup", "prune"}, routes: map[string]any{"POST /api/v1/admin/jobs/run": core.ErrConflict}, code: ExitFailure},
		{name: "restore remote", args: []string{"restore", bid}, code: ExitUsage, out: "server host"},
		{name: "share show", args: []string{"share", "show", "shr_1", "--qr"}, routes: map[string]any{"GET /api/v1/shares/{id}": share}, out: "/s/abc"},
		{name: "share log", args: []string{"share", "log", "shr_1"}, routes: map[string]any{"GET /api/v1/shares/{id}": share,
			"GET /api/v1/shares/{id}/log": core.Page[core.ShareAccess]{Items: []core.ShareAccess{{Action: core.AccessDownload, IP: "10.1.1.1", Bytes: 2048, At: now}}}},
			out: "2.0 KiB"},
		{name: "share list all", args: []string{"share", "list", "--all", "--user", "alice"}, routes: map[string]any{"GET /api/v1/admin/shares": core.Page[core.Share]{
			Items: []core.Share{{ID: "shr_2", Kind: core.ShareLink, Status: core.ShareActive, CreatedByName: "Alice"}}}}, out: "OWNER"},
		{name: "share list user without all", args: []string{"share", "list", "--user", "x"}, code: ExitUsage},
		{name: "share edit", args: []string{"share", "edit", "shr_1", "--expires", "30d", "--no-password"}, routes: map[string]any{"GET /api/v1/shares/{id}": share,
			"PATCH /api/v1/shares/{id}": share}, out: "updated share link shr_1"},
		{name: "request list", args: []string{"request", "list", "--inactive"}, routes: map[string]any{"GET /api/v1/shares": core.Page[core.Share]{
			Items: []core.Share{{ID: "shr_r", Kind: core.ShareRequest, Title: "Photos", Status: core.ShareExpired}}}}, out: "Photos"},
		{name: "jobs cancel", args: []string{"jobs", "cancel", "job_01j9zq3x4k6m8p0r2t4v6x8z0b"}, routes: map[string]any{
			"POST /api/v1/admin/jobs/{id}/cancel": nil}, out: "cancellation"},
		{name: "jobs show", args: []string{"jobs", "show", "job_01j9zq3x4k6m8p0r2t4v6x8z0b"}, routes: map[string]any{
			"GET /api/v1/admin/jobs/{id}": core.Job{ID: "job_01j9zq3x4k6m8p0r2t4v6x8z0b", Kind: "backup.create", State: core.JobSucceeded,
				Result: json.RawMessage(`{"backup_id":"bak_1"}`), StartedAt: &now, FinishedAt: &now}}, out: "bak_1"},
		{name: "files search in space", args: []string{"files", "search", "p", "--in", "/Team/Design", "--limit", "1"}, out: ""},
	})
}

func TestRestoreArgs(t *testing.T) {
	h := testHome(t)
	for _, args := range [][]string{
		{"restore", "x", "--identity", "a", "--passphrase-stdin"},
		{"restore", "x", "--identity-stdin", "--passphrase-file", "f"},
		{"restore"},
	} {
		if res := runArgs(t, "", append([]string{"--home", h.Dir()}, args...)...); res.code != ExitUsage {
			t.Errorf("%v: %+v", args, res)
		}
	}
	res := runArgs(t, "", "--home", h.Dir(), "restore", filepath.Join(t.TempDir(), "missing.fpbak"), "--dry-run")
	if res.code != ExitFailure || !strings.Contains(res.stderr, "missing.fpbak") {
		t.Fatalf("missing file: %+v", res)
	}
	res = runArgs(t, "", "--home", h.Dir(), "restore", "x.fpbak", "--identity", filepath.Join(t.TempDir(), "nope"))
	if res.code != ExitFailure {
		t.Fatalf("missing identity file: %+v", res)
	}
	idFile := filepath.Join(t.TempDir(), "id.txt")
	os.WriteFile(idFile, []byte("# no key here\n"), 0o600)
	res = runArgs(t, "", "--home", h.Dir(), "restore", "x.fpbak", "--identity", idFile)
	if res.code != ExitFailure || !strings.Contains(res.stderr, "no age identity") {
		t.Fatalf("identity file without key: %+v", res)
	}
	// A declined confirmation changes nothing.
	archive := filepath.Join(t.TempDir(), "b.fpbak")
	os.WriteFile(archive, []byte("x"), 0o600)
	res = runArgs(t, "n\n", "--home", h.Dir(), "restore", archive)
	if res.code != ExitFailure || !strings.Contains(res.stderr, "aborted") {
		t.Fatalf("declined: %+v", res)
	}
}
