package cli

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"fileparcel/internal/core"
	"fileparcel/internal/ids"
)

// Regression tests for the admin commands (user, network, mdns, cert, ca,
// client-cert, keys, jobs, maintenance).

// "keys seal" never creates a recovery key; the CLI must say so, as the web
// UI does, without breaking the single JSON document of --json.
func TestKeysSealWarnsWithoutRecoveryKey(t *testing.T) {
	for _, c := range []struct {
		name     string
		recovery bool
		json     bool
	}{
		{"no recovery key", false, false},
		{"recovery key", true, false},
		{"json", false, true},
	} {
		t.Run(c.name, func(t *testing.T) {
			f := newFakeAPI(t)
			f.handle("POST", "/api/v1/admin/keys/seal", func(w http.ResponseWriter, r *http.Request) {
				writeJSON(w, 200, core.KeyStatus{State: core.KeyStateUnlocked, Mode: core.KeyModeSealed, RecoveryConfigured: c.recovery})
			})
			args := []string{"-y", "keys", "seal", "--passphrase-stdin"}
			if c.json {
				args = append([]string{"--json"}, args...)
			}
			res := f.run(t, "a long enough passphrase\n", args...)
			if res.code != 0 {
				t.Fatalf("keys seal: %+v", res)
			}
			warned := strings.Contains(res.stderr, "keys recovery-key")
			if warned == c.recovery || strings.Contains(res.stdout, "recovery-key") {
				t.Fatalf("recovery configured %v, warning shown %v: %+v", c.recovery, warned, res)
			}
			if c.json {
				var st core.KeyStatus
				if err := json.Unmarshal([]byte(res.stdout), &st); err != nil || st.Mode != core.KeyModeSealed {
					t.Fatalf("--json must stay one KeyStatus document: %v\n%s", err, res.stdout)
				}
			}
		})
	}
}

// "keys unseal" and "keys passphrase" shadow the global --passphrase-* flags,
// so offline on a sealed home they must unlock with the passphrase they were
// given (without a terminal there is no other way).
func TestKeysUnsealAndPassphraseWorkOffline(t *testing.T) {
	dir := t.TempDir()
	pp := filepath.Join(dir, "pp")
	newPP := filepath.Join(dir, "newpp")
	if err := os.WriteFile(pp, []byte("correct horse battery staple\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(newPP, []byte("another long passphrase\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	status := func(t *testing.T, home string, extra ...string) (core.KeyStatus, cliResult) {
		t.Helper()
		res := runArgs(t, "", append(append([]string{"--home", home, "--offline", "--json"}, extra...), "keys", "status")...)
		var st core.KeyStatus
		if res.code == 0 {
			if err := json.Unmarshal([]byte(res.stdout), &st); err != nil {
				t.Fatalf("keys status: %v\n%s", err, res.stdout)
			}
		}
		return st, res
	}

	t.Run("unseal", func(t *testing.T) {
		h, _ := lcInitTestHome(t, "--sealed", "--passphrase-file", pp)
		if res := runArgs(t, "", "--home", h.Dir(), "--offline", "-y", "keys", "unseal", "--passphrase-file", pp); res.code != 0 {
			t.Fatalf("keys unseal offline: %+v", res)
		}
		if st, res := status(t, h.Dir()); res.code != 0 || st.Mode != core.KeyModePlain || st.State != core.KeyStateUnlocked {
			t.Fatalf("after unseal: %+v %+v", st, res)
		}
	})

	t.Run("passphrase", func(t *testing.T) {
		h, _ := lcInitTestHome(t, "--sealed", "--passphrase-file", pp)
		res := runArgs(t, "correct horse battery staple\nanother long passphrase\n",
			"--home", h.Dir(), "--offline", "keys", "passphrase", "--passphrase-stdin")
		if res.code != 0 {
			t.Fatalf("keys passphrase offline: %+v", res)
		}
		if st, res := status(t, h.Dir(), "--passphrase-file", newPP); res.code != 0 || st.State != core.KeyStateUnlocked {
			t.Fatalf("the new passphrase must unlock: %+v %+v", st, res)
		}
		if _, res := status(t, h.Dir(), "--passphrase-file", pp); res.code == 0 {
			t.Fatalf("the old passphrase must no longer unlock: %+v", res)
		}
		// A wrong current passphrase fails at the unlock, not with the
		// circular "pass the passphrase to the command itself" hint.
		bad := runArgs(t, "wrong wrong wrong wrong\nyet another passphrase\n",
			"--home", h.Dir(), "--offline", "keys", "passphrase", "--passphrase-stdin")
		if bad.code == 0 || strings.Contains(bad.stderr, "to the command itself") {
			t.Fatalf("wrong current passphrase: %+v", bad)
		}
	})
}

// Private mode admits the allow list too: the note after "network allow add"
// is only right for mode "any".
func TestNetworkAllowAddNoteOnlyInModeAny(t *testing.T) {
	for _, c := range []struct {
		mode string
		note bool
	}{{core.AccessPrivate, false}, {core.AccessAllowlist, false}, {core.AccessAny, true}} {
		t.Run(c.mode, func(t *testing.T) {
			f := newFakeAPI(t)
			f.handle("GET", "/api/v1/admin/network", func(w http.ResponseWriter, r *http.Request) {
				writeJSON(w, 200, core.NetworkOverview{Policy: core.AccessPolicy{Mode: c.mode}})
			})
			f.handle("PUT", "/api/v1/admin/network/policy", func(w http.ResponseWriter, r *http.Request) {
				in, _ := decodeBody[core.PolicyInput](r)
				writeJSON(w, 200, core.PolicyResult{Policy: core.AccessPolicy{Mode: in.Mode, Allow: in.Allow, Deny: in.Deny}})
			})
			res := f.run(t, "", "network", "allow", "add", "2001:db8:f030:b300::/64")
			if res.code != 0 {
				t.Fatalf("allow add: %+v", res)
			}
			if got := strings.Contains(res.stderr, "Note:"); got != c.note || strings.Contains(res.stderr, "used in allowlist mode") {
				t.Fatalf("mode %s: note shown %v, want %v: %q", c.mode, got, c.note, res.stderr)
			}
		})
	}
	if res := runArgs(t, "", "network", "allow", "--help"); !strings.Contains(res.stdout, "private mode") {
		t.Fatalf("the allow help must mention private mode: %q", res.stdout)
	}
}

// A collision rename (§10.5) is a lasting state, not a pending republish,
// and must be shown even when mdns.name is empty (derived from server.name).
func TestMDNSStatusExplainsACollisionRename(t *testing.T) {
	for _, c := range []struct {
		name    string
		setting string
		st      core.MDNSStatus
		want    []string
		notWant []string
	}{
		{"named", "files", core.MDNSStatus{Name: "files-2.local", Configured: "files.local", State: core.MDNSPublished},
			[]string{"collision", "configured: files.local"}, []string{"republishing"}},
		{"derived", "", core.MDNSStatus{Name: "fileparcel-2.local", Configured: "fileparcel.local", State: core.MDNSPublished},
			[]string{"collision", "fileparcel.local"}, []string{"republishing"}},
		{"settings lag", "new", core.MDNSStatus{Name: "files.local", Configured: "files.local", State: core.MDNSPublished},
			[]string{`"new.local" configured, republishing`}, []string{"collision"}},
		{"in sync", "files", core.MDNSStatus{Name: "files.local", Configured: "files.local", State: core.MDNSPublished},
			nil, []string{"collision", "republishing"}},
	} {
		t.Run(c.name, func(t *testing.T) {
			f := newFakeAPI(t)
			name, _ := json.Marshal(c.setting)
			f.handle("GET", "/api/v1/admin/settings", func(w http.ResponseWriter, r *http.Request) {
				writeJSON(w, 200, []core.SettingView{
					{Key: "mdns.mode", Section: "mdns", Type: "enum", Value: json.RawMessage(`"auto"`), Default: json.RawMessage(`"auto"`)},
					{Key: "mdns.name", Section: "mdns", Type: "string", Value: name, Default: json.RawMessage(`""`)},
				})
			})
			st := c.st
			st.Mode, st.Backend = "auto", "avahi"
			f.handle("GET", "/api/v1/admin/mdns", func(w http.ResponseWriter, r *http.Request) { writeJSON(w, 200, st) })
			res := f.run(t, "", "mdns", "status")
			if res.code != 0 {
				t.Fatalf("mdns status: %+v", res)
			}
			for _, w := range c.want {
				if !strings.Contains(res.stdout, w) {
					t.Errorf("%q missing: %q", w, res.stdout)
				}
			}
			for _, w := range c.notWant {
				if strings.Contains(res.stdout, w) {
					t.Errorf("%q must not be shown: %q", w, res.stdout)
				}
			}
		})
	}
}

func TestMDNSNameAcceptsAnyCaseSuffix(t *testing.T) {
	f := newFakeAPI(t)
	store := addSettingsRoutes(f)
	for _, in := range []string{"Files.LOCAL", "files.Local", "FILES"} {
		store.Delete("mdns.name")
		if res := f.run(t, "", "mdns", "name", in); res.code != 0 || stored(store, "mdns.name") != `"files"` {
			t.Fatalf("mdns name %s: %+v (stored %s)", in, res, stored(store, "mdns.name"))
		}
	}
}

// The rfc2136 example in the help must be what certs.dnsProvider reads, and
// credentials without the provider's required keys must be refused before
// any setting (acme.enabled=true among them) is written.
func TestCertACMEEnableChecksCredentials(t *testing.T) {
	long := newCertACMECmd()
	var help string
	for _, sub := range long.Commands() {
		if sub.Name() == "enable" {
			help = sub.Long
		}
	}
	_, line, ok := strings.Cut(help, "rfc2136:")
	if !ok {
		t.Fatalf("no rfc2136 example in the help: %q", help)
	}
	line, _, _ = strings.Cut(strings.TrimSpace(line), "\n")
	var ex map[string]any
	if err := json.Unmarshal([]byte(line), &ex); err != nil {
		t.Fatalf("the rfc2136 example is not JSON: %v (%q)", err, line)
	}
	if err := checkDNSCredentials("rfc2136", ex); err != nil {
		t.Fatalf("the documented rfc2136 example is refused: %v", err)
	}

	f := newFakeAPI(t)
	store := addSettingsRoutes(f)
	f.handle("POST", "/api/v1/admin/certs/acme/apply", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusNoContent) })
	f.handle("GET", "/api/v1/admin/certs", func(w http.ResponseWriter, r *http.Request) { // enable waits for the certificate
		writeJSON(w, 200, core.CertStatus{ACMEEnabled: true, ACME: []core.CertInfo{{DNSNames: []string{"files.example.com"}}}})
	})
	enable := []string{"cert", "acme", "enable", "--email", "a@example.com", "--domain", "files.example.com", "--credentials-stdin"}
	for _, c := range []struct {
		provider, creds string
	}{
		{"rfc2136", `{"nameserver":"ns1:53","tsig_key":"k","tsig_secret":"s"}`},
		{"rfc2136", `{"server":"ns1:53","key_name":"k.","key":""}`},
		{"cloudflare", `{"token":"x"}`},
		{"cloudflare", `{"api_token":42}`},
	} {
		res := f.run(t, c.creds, append(enable, "--dns-provider", c.provider)...)
		if res.code != ExitUsage || !strings.Contains(res.stderr, "credentials need") {
			t.Fatalf("%s %s: %+v", c.provider, c.creds, res)
		}
		if f.requested("PATCH /api/v1/admin/settings") != 0 {
			t.Fatalf("%s %s: settings were written", c.provider, c.creds)
		}
	}
	good := `{"server":"ns1.example.com:53","key_name":"fileparcel.","key":"c2VjcmV0"}`
	if res := f.run(t, good, append(enable, "--dns-provider", "rfc2136")...); res.code != 0 {
		t.Fatalf("valid rfc2136 credentials: %+v", res)
	}
	var creds string
	if err := json.Unmarshal([]byte(stored(store, "acme.dns_credentials")), &creds); err != nil || creds != good {
		t.Fatalf("stored credentials %q (%v)", stored(store, "acme.dns_credentials"), err)
	}

	// --credentials-file reads the whole file (the JSON may span lines).
	file := filepath.Join(t.TempDir(), "cloudflare.json")
	if err := os.WriteFile(file, []byte("{\n  \"api_token\": \"cf-token\"\n}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	fromFile := []string{"cert", "acme", "enable", "--email", "a@example.com", "--domain", "files.example.com", "--credentials-file", file}
	if res := f.run(t, "", fromFile...); res.code != 0 {
		t.Fatalf("--credentials-file: %+v", res)
	}
	if err := json.Unmarshal([]byte(stored(store, "acme.dns_credentials")), &creds); err != nil || !strings.Contains(creds, `"cf-token"`) {
		t.Fatalf("stored credentials from the file %q (%v)", stored(store, "acme.dns_credentials"), err)
	}
	if res := f.run(t, good, append(fromFile, "--credentials-stdin")...); res.code != ExitUsage {
		t.Fatalf("--credentials-file with --credentials-stdin: %+v", res)
	}
	if err := os.WriteFile(file, []byte("api_token=x\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if res := f.run(t, "", fromFile...); res.code != ExitUsage || !strings.Contains(res.stderr, "--credentials-file expects a JSON object") {
		t.Fatalf("--credentials-file without JSON: %+v", res)
	}
}

// An expired lockout stays in users.locked_until until the next login or
// "user unlock"; it must not be shown as a current lock.
func TestUserLockShownOnlyWhileInEffect(t *testing.T) {
	past, future := time.Now().Add(-time.Hour), time.Now().Add(time.Hour)
	users := []core.User{
		{ID: "usr_a", Username: "expired", Status: "active", LockedUntil: &past},
		{ID: "usr_b", Username: "current", Status: "active", LockedUntil: &future},
	}
	var b bytes.Buffer
	if err := renderUsers(&b, users); err != nil {
		t.Fatal(err)
	}
	for _, l := range strings.Split(b.String(), "\n") {
		switch {
		case strings.Contains(l, "expired") && strings.Contains(l, "(locked)"):
			t.Errorf("an expired lock is shown: %q", l)
		case strings.Contains(l, "current") && !strings.Contains(l, "(locked)"):
			t.Errorf("a current lock is not shown: %q", l)
		}
	}
	for i, want := range []bool{false, true} {
		b.Reset()
		if err := renderUser(&b, &users[i]); err != nil {
			t.Fatal(err)
		}
		if got := strings.Contains(b.String(), "Locked until"); got != want {
			t.Errorf("%s: Locked until shown %v, want %v\n%s", users[i].Username, got, want, b.String())
		}
	}
	if res := runArgs(t, "", "user", "show", "--help"); strings.Contains(res.stdout, "storage usage") {
		t.Errorf("user show promises storage usage it does not print: %q", res.stdout)
	}
}

// A size that rounds to zero or overflows int64 must not become an
// unlimited quota.
func TestQuotaSizesNeverBecomeUnlimitedByAccident(t *testing.T) {
	for _, s := range []string{"0.5", "0.0004k", "0K", "8192P", "9223372036854775807"} {
		if q, err := parseUserQuota(s); err == nil {
			t.Errorf("parseUserQuota(%q) = %+v, want an error", s, q)
		}
	}
	for _, s := range []string{"0", "unlimited", "none"} {
		if q, err := parseUserQuota(s); err != nil || !q.Set || q.Null || q.V != 0 {
			t.Errorf("parseUserQuota(%q) = %+v, %v; want unlimited (0)", s, q, err)
		}
	}
	for _, c := range []struct {
		in   string
		want int64
	}{{"8191P", 8191 << 50}, {"1.5G", 3 << 29}, {"512", 512}} {
		if n, err := ParseSize(c.in); err != nil || n != c.want {
			t.Errorf("ParseSize(%q) = %d, %v; want %d", c.in, n, err, c.want)
		}
	}
	for _, s := range []string{"8192P", "9223372036854775807", "-1", "NaN", "Inf", ""} {
		if n, err := ParseSize(s); err == nil {
			t.Errorf("ParseSize(%q) = %d, want an error", s, n)
		}
	}
	if n, err := ParseSize("8191.9999P"); err == nil && n < 8191<<50 {
		t.Errorf("ParseSize near the limit wrapped: %d", n)
	}
}

// Offline "jobs run" runs the job in-process; it must follow the rules of
// POST /admin/jobs/run and leave the same job.run audit entry.
func TestJobsRunOfflineFollowsTheServerRules(t *testing.T) {
	h, _ := lcInitTestHome(t)
	off := func(args ...string) cliResult {
		return runArgs(t, "", append([]string{"--home", h.Dir(), "--offline"}, args...)...)
	}
	for _, k := range []string{core.JobKeysRotateKEK, core.JobUploadZip} {
		if res := off("jobs", "run", k); res.code != ExitUsage || !strings.Contains(res.stderr, "cannot be started by hand") {
			t.Fatalf("jobs run %s offline: %+v", k, res)
		}
	}
	if res := off("jobs", "run", core.JobMaintTrash, "--params", `{"bogus":1}`); res.code != ExitUsage ||
		!strings.Contains(res.stderr, "takes no parameters") {
		t.Fatalf("parameters for a maintenance job: %+v", res)
	}
	res := off("--json", "jobs", "run", core.JobMaintTrash)
	if res.code != 0 {
		t.Fatalf("jobs run %s offline: %+v", core.JobMaintTrash, res)
	}
	var j core.Job
	if err := json.Unmarshal([]byte(res.stdout), &j); err != nil || j.ID == "" {
		t.Fatalf("job output: %v\n%s", err, res.stdout)
	}
	res = off("--json", "audit", "list", "--action", core.ActJobRun)
	var rows []core.AuditRecord
	if err := json.Unmarshal([]byte(res.stdout), &rows); err != nil {
		t.Fatalf("audit list: %v\n%+v", err, res)
	}
	if len(rows) != 1 || rows[0].TargetID != j.ID || !strings.Contains(string(rows[0].Details), core.JobMaintTrash) {
		t.Fatalf("job.run audit entries: %+v", rows)
	}
}

// The .p12 destination is checked before the certificate is issued, is
// always written with mode 0600 (also over an existing file with --force),
// and a certificate whose file could not be written is revoked again.
func TestClientCertIssueOutput(t *testing.T) {
	f := newFakeAPI(t)
	addUserRoutes(f)
	p12 := []byte("PKCS12-DATA")
	var onIssue func()
	var lastID string
	f.handle("POST", "/api/v1/admin/client-certs", func(w http.ResponseWriter, r *http.Request) {
		if onIssue != nil {
			onIssue()
		}
		lastID = ids.New(ids.PrefixClientCert)
		writeJSON(w, 201, map[string]any{"client_cert": core.ClientCert{ID: lastID},
			"p12": base64.StdEncoding.EncodeToString(p12), "password": "pw"})
	})
	f.handle("DELETE", "/api/v1/admin/client-certs/{id}", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})
	issued := func() int { return f.requested("POST /api/v1/admin/client-certs") }
	dir := t.TempDir()

	// A missing directory and a directory as the destination fail first.
	for _, c := range []struct {
		out   string
		force bool
	}{{filepath.Join(dir, "missing", "a.p12"), false}, {dir, true}} {
		args := []string{"client-cert", "issue", "alice", "--out", c.out}
		if c.force {
			args = append(args, "--force")
		}
		if res := f.run(t, "", args...); res.code != ExitFailure || issued() != 0 {
			t.Fatalf("--out %s: %+v (issued %d)", c.out, res, issued())
		}
	}

	if runtime.GOOS != "windows" {
		// --force over a world-readable file leaves a 0600 file.
		dest := filepath.Join(dir, "alice.p12")
		if err := os.WriteFile(dest, []byte("old"), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(dest, 0o644); err != nil {
			t.Fatal(err)
		}
		if res := f.run(t, "", "client-cert", "issue", "alice", "--out", dest, "--force"); res.code != 0 {
			t.Fatalf("issue --force: %+v", res)
		}
		if st, err := os.Stat(dest); err != nil || st.Mode().Perm() != 0o600 {
			t.Fatalf("mode after --force: %v %v", st, err)
		}
		if got, _ := os.ReadFile(dest); !bytes.Equal(got, p12) {
			t.Fatalf("content after --force: %q", got)
		}

		// A symlink is replaced, not written through.
		target := filepath.Join(dir, "target")
		if err := os.WriteFile(target, []byte("keep"), 0o644); err != nil {
			t.Fatal(err)
		}
		link := filepath.Join(dir, "link.p12")
		if err := os.Symlink(target, link); err != nil {
			t.Fatal(err)
		}
		if res := f.run(t, "", "client-cert", "issue", "alice", "--out", link, "--force"); res.code != 0 {
			t.Fatalf("issue --force over a symlink: %+v", res)
		}
		if got, _ := os.ReadFile(target); string(got) != "keep" {
			t.Fatalf("the symlink target was written: %q", got)
		}
		if st, err := os.Lstat(link); err != nil || !st.Mode().IsRegular() || st.Mode().Perm() != 0o600 {
			t.Fatalf("the destination must be a regular 0600 file: %v %v", st, err)
		}
	}

	// The directory disappears while the certificate is issued: the file
	// cannot be put in place, so the new certificate is revoked again.
	gone := filepath.Join(dir, "gone")
	if err := os.Mkdir(gone, 0o700); err != nil {
		t.Fatal(err)
	}
	onIssue = func() { os.RemoveAll(gone) }
	res := f.run(t, "", "client-cert", "issue", "alice", "--out", filepath.Join(gone, "a.p12"))
	onIssue = nil
	if res.code != ExitFailure || !strings.Contains(res.stderr, "revoked again") ||
		f.requested("DELETE /api/v1/admin/client-certs/"+lastID) != 1 {
		t.Fatalf("unwritable output after issuing: %+v", res)
	}
	matches, _ := filepath.Glob(filepath.Join(dir, "."+"*"+partialSuffix))
	if len(matches) != 0 {
		t.Fatalf("temporary files left behind: %v", matches)
	}
}

// trust-help commands must name the file the server actually serves
// (<server.name>-ca.crt) and the iOS profile's real name.
func TestTrustInstructionsUseTheServerName(t *testing.T) {
	tc := trustContext{CRTName: "files-ca.crt"}
	for o, want := range map[string]string{
		"windows": "certutil -addstore -f Root files-ca.crt",
		"macos":   "System.keychain files-ca.crt",
		"ios":     `"FileParcel CA (files)"`,
	} {
		if s := trustInstructions(o, tc); !strings.Contains(s, want) {
			t.Errorf("%s: %q missing:\n%s", o, want, s)
		}
	}
	if strings.Contains(trustInstructions("ios", tc), `"FileParcel Local CA" → Install`) {
		t.Error("iOS step 2 names the certificate instead of the profile")
	}
	for _, o := range []string{"windows", "macos"} {
		if s := trustInstructions(o, trustContext{}); !strings.Contains(s, "fileparcel-ca.crt") {
			t.Errorf("%s: default file name missing:\n%s", o, s)
		}
	}
}

// Validation errors of maintenance.message must reach the user; only a
// server without the setting gets the "not supported" message.
func TestMaintenanceMessageErrors(t *testing.T) {
	catalog := func(f *fakeAPI, withMessage bool) {
		list := []core.SettingView{{Key: maintenanceKey, Type: "bool", Value: json.RawMessage("false"), Default: json.RawMessage("false")}}
		if withMessage {
			list = append(list, core.SettingView{Key: maintenanceMessageKey, Type: "string", Value: json.RawMessage(`""`), Default: json.RawMessage(`""`)})
		}
		f.handle("GET", "/api/v1/admin/settings", func(w http.ResponseWriter, r *http.Request) { writeJSON(w, 200, list) })
	}

	f := newFakeAPI(t)
	catalog(f, true)
	f.handle("PATCH", "/api/v1/admin/settings", func(w http.ResponseWriter, r *http.Request) {
		writeErr(w, core.Invalid(maintenanceMessageKey, "must be at most 2000 characters"))
	})
	res := f.run(t, "", "maintenance", "on", "--message", strings.Repeat("x", 2500))
	if res.code != ExitUsage || !strings.Contains(res.stderr, "at most 2000 characters") || strings.Contains(res.stderr, "does not support") {
		t.Fatalf("too long a message: %+v", res)
	}

	f = newFakeAPI(t)
	catalog(f, false)
	res = f.run(t, "", "maintenance", "on", "--message", "x")
	if res.code != ExitUsage || !strings.Contains(res.stderr, "does not support a maintenance message") ||
		f.requested("PATCH /api/v1/admin/settings") != 0 {
		t.Fatalf("server without maintenance.message: %+v", res)
	}
}
