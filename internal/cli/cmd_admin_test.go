package cli

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"

	"fileparcel/internal/core"
	"fileparcel/internal/ids"
)

// ---------- users, groups, invites, tokens ----------

func addUserRoutes(f *fakeAPI) (users *[]core.User) {
	now := time.Now().UTC()
	list := []core.User{
		{ID: ids.New(ids.PrefixUser), Username: "admin", Role: core.RoleOwner, Status: core.UserActive, CreatedAt: now.Add(-time.Hour)},
		{ID: ids.New(ids.PrefixUser), Username: "Alice", Role: core.RoleMember, Status: core.UserActive, CreatedAt: now},
	}
	var mu sync.Mutex
	find := func(id string) *core.User {
		for i := range list {
			if list[i].ID == id {
				return &list[i]
			}
		}
		return nil
	}
	f.handle("GET", "/api/v1/admin/users", func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		q := strings.ToLower(r.URL.Query().Get("q"))
		out := []core.User{}
		for _, u := range list {
			if q == "" || strings.Contains(strings.ToLower(u.Username), q) {
				out = append(out, u)
			}
		}
		writeJSON(w, 200, core.Page[core.User]{Items: out})
	})
	f.handle("POST", "/api/v1/admin/users", func(w http.ResponseWriter, r *http.Request) {
		in, _ := decodeBody[core.NewUser](r)
		mu.Lock()
		defer mu.Unlock()
		u := core.User{ID: ids.New(ids.PrefixUser), Username: in.Username, Role: in.Role, Status: core.UserActive, Email: in.Email}
		list = append(list, u)
		res := core.UserCreated{User: &u}
		if in.GeneratePassword {
			res.Password = "Gen-3rated-Pw"
		}
		writeJSON(w, 201, res)
	})
	f.handle("GET", "/api/v1/admin/users/{id}", func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		if u := find(chi.URLParam(r, "id")); u != nil {
			writeJSON(w, 200, u)
			return
		}
		writeErr(w, core.NotFoundf("user not found"))
	})
	f.handle("PATCH", "/api/v1/admin/users/{id}", func(w http.ResponseWriter, r *http.Request) {
		in, _ := decodeBody[core.UserUpdate](r)
		mu.Lock()
		defer mu.Unlock()
		u := find(chi.URLParam(r, "id"))
		if in.Role != nil {
			u.Role = *in.Role
		}
		if in.QuotaBytes.Set {
			u.QuotaBytes = in.QuotaBytes.Ptr()
		}
		writeJSON(w, 200, u)
	})
	f.handle("POST", "/api/v1/admin/users/{id}/password", func(w http.ResponseWriter, r *http.Request) {
		in, _ := decodeBody[core.PasswordResetInput](r)
		if in.Generate {
			writeJSON(w, 200, core.PasswordReset{Password: "new-generated"})
			return
		}
		writeJSON(w, 200, core.PasswordReset{})
	})
	f.handle("DELETE", "/api/v1/admin/users/{id}", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})
	return &list
}

func TestUserCommands(t *testing.T) {
	f := newFakeAPI(t)
	users := addUserRoutes(f)

	res := f.run(t, "", "user", "list")
	if res.code != 0 || !strings.Contains(res.stdout, "Alice") || !strings.Contains(res.stdout, "USERNAME") {
		t.Fatalf("user list: %+v", res)
	}
	res = f.run(t, "", "--json", "user", "show", "alice") // case-insensitive username
	var u core.User
	if res.code != 0 || json.Unmarshal([]byte(res.stdout), &u) != nil || u.Username != "Alice" {
		t.Fatalf("user show: %+v", res)
	}
	res = f.run(t, "", "user", "show", "nobody")
	if res.code != ExitFailure || !strings.Contains(res.stderr, `user "nobody" not found`) {
		t.Fatalf("user show missing: %+v", res)
	}

	// add: password from stdin is sent in the body; --generate prints it once.
	res = f.run(t, "correct horse battery\n", "user", "add", "bob", "--password-stdin", "--role", "admin", "--quota", "10G")
	if res.code != 0 {
		t.Fatalf("user add: %+v", res)
	}
	var nu core.NewUser
	_ = json.Unmarshal(f.body("POST /api/v1/admin/users"), &nu)
	if nu.Password != "correct horse battery" || nu.Role != core.RoleAdmin || nu.QuotaBytes == nil || *nu.QuotaBytes != 10<<30 {
		t.Fatalf("user add body %+v", nu)
	}
	res = f.run(t, "", "user", "add", "carol", "--generate")
	if res.code != 0 || !strings.Contains(res.stdout, "Password: Gen-3rated-Pw") {
		t.Fatalf("user add --generate: %+v", res)
	}
	if res := f.run(t, "x\n", "user", "add", "dave", "--generate", "--password-stdin"); res.code != ExitUsage {
		t.Fatalf("--generate with --password-stdin: %+v", res)
	}
	if res := f.run(t, "", "user", "add", "erin"); res.code != ExitFailure || !strings.Contains(res.stderr, "Empty input") && !strings.Contains(res.stderr, "EOF") {
		t.Fatalf("user add without password source: %+v", res)
	}

	// set-role / quota send PATCH bodies.
	if res := f.run(t, "", "user", "set-role", "alice", "admin"); res.code != 0 || (*users)[1].Role != core.RoleAdmin {
		t.Fatalf("set-role: %+v", res)
	}
	if res := f.run(t, "", "user", "quota", "alice", "default"); res.code != 0 {
		t.Fatalf("quota default: %+v", res)
	}
	if got := string(f.body("PATCH /api/v1/admin/users/" + (*users)[1].ID)); got != `{"quota_bytes":null}` {
		t.Fatalf("quota default body %s", got)
	}
	if res := f.run(t, "", "user", "quota", "alice", "unlimited"); res.code != 0 {
		t.Fatalf("quota unlimited: %+v", res)
	}
	if got := string(f.body("PATCH /api/v1/admin/users/" + (*users)[1].ID)); got != `{"quota_bytes":0}` {
		t.Fatalf("quota unlimited body %s", got)
	}
	if res := f.run(t, "", "user", "edit", "alice"); res.code != ExitUsage {
		t.Fatalf("edit without flags: %+v", res)
	}
	if res := f.run(t, "", "user", "passwd", "alice", "--generate"); res.code != 0 || !strings.Contains(res.stdout, "new-generated") {
		t.Fatalf("passwd --generate: %+v", res)
	}
	// delete needs confirmation.
	if res := f.run(t, "n\n", "user", "delete", "alice"); res.code != ExitFailure || f.requestedPrefix("DELETE /api/v1/admin/users/") != 0 {
		t.Fatalf("delete declined: %+v", res)
	}
	if res := f.run(t, "y\n", "user", "delete", "alice", "--transfer-to", "admin"); res.code != 0 || f.requestedPrefix("DELETE /api/v1/admin/users/") != 1 {
		t.Fatalf("delete confirmed: %+v", res)
	}
	if res := f.run(t, "", "-y", "user", "delete", "alice", "--transfer-to", "alice"); res.code != ExitUsage {
		t.Fatalf("transfer to self: %+v", res)
	}
}

func TestGroupInviteTokenCommands(t *testing.T) {
	f := newFakeAPI(t)
	users := addUserRoutes(f)
	gid := ids.New(ids.PrefixGroup)
	f.handle("GET", "/api/v1/admin/groups", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, core.Page[core.Group]{Items: []core.Group{{ID: gid, Name: "Design", MemberCount: 2}}})
	})
	f.handle("PUT", "/api/v1/admin/groups/{id}/members/{uid}", func(w http.ResponseWriter, r *http.Request) {
		if chi.URLParam(r, "id") != gid || chi.URLParam(r, "uid") != (*users)[1].ID {
			writeErr(w, core.NotFoundf("no"))
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
	f.handle("POST", "/api/v1/admin/invites", func(w http.ResponseWriter, r *http.Request) {
		in, _ := decodeBody[core.InviteInput](r)
		writeJSON(w, 201, core.InviteCreated{Invite: &core.Invite{ID: ids.New(ids.PrefixInvite), Role: in.Role, MaxUses: in.MaxUses,
			GroupIDs: in.GroupIDs, ExpiresAt: *in.ExpiresAt}, URL: "/invite/tok123"})
	})
	f.handle("POST", "/api/v1/me/tokens", func(w http.ResponseWriter, r *http.Request) {
		in, _ := decodeBody[core.TokenInput](r)
		writeJSON(w, 201, core.TokenCreated{Token: &core.APIToken{ID: ids.New(ids.PrefixToken), Name: in.Name, Scopes: in.Scopes}, Secret: "fpt_abc_secret"})
	})
	var enrollRequired atomic.Bool
	f.handle("GET", "/api/v1/me/mfa", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, core.MFAStatus{Required: enrollRequired.Load(), EnrollRequired: enrollRequired.Load()})
	})
	past := time.Now().Add(-time.Hour)
	f.handle("GET", "/api/v1/me/tokens", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, core.Page[core.APIToken]{Items: []core.APIToken{
			{ID: "tok_live", Name: "laptop", Scopes: []string{"files:read"}},
			{ID: "tok_dead", Name: "old", RevokedAt: &past},
		}})
	})

	if res := f.run(t, "", "group", "add-member", "design", "alice", "--manager"); res.code != 0 {
		t.Fatalf("add-member: %+v", res)
	}
	var ri core.RoleInput
	_ = json.Unmarshal(f.body("PUT /api/v1/admin/groups/"+gid+"/members/"+(*users)[1].ID), &ri)
	if ri.Role != core.GroupRoleManager {
		t.Fatalf("role body %+v", ri)
	}
	if res := f.run(t, "", "group", "members", "Nope"); res.code != ExitFailure || !strings.Contains(res.stderr, `group "Nope" not found`) {
		t.Fatalf("unknown group: %+v", res)
	}

	res := f.run(t, "", "invite", "create", "--group", "Design", "--expires", "3d", "--uses", "2")
	if res.code != 0 || !strings.Contains(res.stdout, f.srv.URL+"/invite/tok123") {
		t.Fatalf("invite create: %+v", res)
	}
	var ii core.InviteInput
	_ = json.Unmarshal(f.body("POST /api/v1/admin/invites"), &ii)
	if ii.Role != core.RoleMember || ii.MaxUses != 2 || len(ii.GroupIDs) != 1 || ii.GroupIDs[0] != gid ||
		ii.ExpiresAt == nil || time.Until(*ii.ExpiresAt) < 71*time.Hour {
		t.Fatalf("invite body %+v", ii)
	}
	if res := f.run(t, "", "invite", "create", "--role", "owner"); res.code != ExitUsage {
		t.Fatalf("owner invite: %+v", res)
	}
	if res := f.run(t, "", "invite", "create", "--send"); res.code != ExitUsage {
		t.Fatalf("--send without --email: %+v", res)
	}

	res = f.run(t, "", "token", "create", "--name", "ci", "--scopes", "files:read", "--expires", "30d")
	if res.code != 0 || !strings.Contains(res.stdout, "fpt_abc_secret") {
		t.Fatalf("token create: %+v", res)
	}
	if strings.Contains(res.stderr, "two-factor") {
		t.Fatalf("2FA warning without enrolment required: %+v", res)
	}
	var ti core.TokenInput
	_ = json.Unmarshal(f.body("POST /api/v1/me/tokens"), &ti)
	if ti.Name != "ci" || len(ti.Scopes) != 1 || ti.ExpiresAt == nil {
		t.Fatalf("token body %+v", ti)
	}
	// The owner still has to enrol: the token would be refused on every
	// remote route, so say so instead of promising it works.
	enrollRequired.Store(true)
	res = f.run(t, "", "token", "create", "--name", "ci2", "--scopes", "files:read")
	if res.code != 0 || !strings.Contains(res.stdout, "fpt_abc_secret") ||
		!strings.Contains(res.stderr, "two-factor authentication is set up in the web UI") {
		t.Fatalf("token create without a second factor: %+v", res)
	}
	res = f.run(t, "", "--json", "token", "create", "--name", "ci3", "--scopes", "files:read")
	if res.code != 0 || !strings.Contains(res.stdout, `"fpt_abc_secret"`) || strings.Contains(res.stdout, "two-factor") {
		t.Fatalf("token create --json: %+v", res)
	}
	enrollRequired.Store(false)
	for _, args := range [][]string{
		{"token", "create"},
		{"token", "create", "--name", "x", "--elevated", "--scopes", "admin"},                     // no expiry
		{"token", "create", "--name", "x", "--elevated", "--scopes", "admin", "--expires", "60d"}, // too long
		{"token", "create", "--name", "x", "--elevated", "--expires", "7d"},                       // no admin scope
		{"token", "list", "--user", "bob"},                                                        // remote
	} {
		if res := f.run(t, "", args...); res.code != ExitUsage {
			t.Errorf("%v: %+v", args, res)
		}
	}
	res = f.run(t, "", "token", "list")
	if res.code != 0 || !strings.Contains(res.stdout, "tok_live") || strings.Contains(res.stdout, "tok_dead") {
		t.Fatalf("token list: %+v", res)
	}
	if res := f.run(t, "", "token", "list", "--all"); !strings.Contains(res.stdout, "tok_dead") {
		t.Fatalf("token list --all: %+v", res)
	}
}

// ---------- settings, network, mdns, maintenance, cert ----------

func addSettingsRoutes(f *fakeAPI, extra ...core.SettingView) *sync.Map {
	store := &sync.Map{}
	catalog := []core.SettingView{
		{Key: "storage.trash_days", Section: "storage", Type: "int", Value: json.RawMessage("30"), Default: json.RawMessage("30")},
		{Key: "smtp.password", Section: "email", Type: "secret", Secret: true},
		{Key: "tls.extra_sans", Section: "tls", Type: "strings", Value: json.RawMessage(`["a.lan"]`), Default: json.RawMessage(`[]`), IsSet: true},
		{Key: "server.https_port", Section: "server", Type: "int", Value: json.RawMessage("8443"), Default: json.RawMessage("8443"), Restart: true, Bootstrap: true},
		{Key: "mdns.name", Section: "mdns", Type: "string", Value: json.RawMessage(`""`), Default: json.RawMessage(`""`)},
		{Key: "mdns.mode", Section: "mdns", Type: "enum", Value: json.RawMessage(`"auto"`), Default: json.RawMessage(`"auto"`)},
	}
	catalog = append(catalog, extra...)
	f.handle("GET", "/api/v1/admin/settings", func(w http.ResponseWriter, r *http.Request) { writeJSON(w, 200, catalog) })
	f.handle("PATCH", "/api/v1/admin/settings", func(w http.ResponseWriter, r *http.Request) {
		in, _ := decodeBody[map[string]json.RawMessage](r)
		res := core.SettingsResult{Applied: []string{}, RestartRequired: []string{}}
		for k, v := range in {
			store.Store(k, string(v))
			res.Applied = append(res.Applied, k)
			if strings.HasPrefix(k, "server.") {
				res.RestartRequired = append(res.RestartRequired, k)
			}
		}
		writeJSON(w, 200, res)
	})
	f.handle("DELETE", "/api/v1/admin/settings/{key}", func(w http.ResponseWriter, r *http.Request) {
		store.Store("reset:"+chi.URLParam(r, "key"), "1")
		w.WriteHeader(http.StatusNoContent)
	})
	return store
}

func stored(m *sync.Map, key string) string {
	v, _ := m.Load(key)
	s, _ := v.(string)
	return s
}

func TestConfigCommands(t *testing.T) {
	f := newFakeAPI(t)
	store := addSettingsRoutes(f)

	res := f.run(t, "", "config", "list")
	if res.code != 0 || !strings.Contains(res.stdout, "tls.extra_sans") || strings.Contains(res.stdout, "storage.trash_days") {
		t.Fatalf("config list: %+v", res)
	}
	res = f.run(t, "", "config", "list", "--all", "--section", "storage")
	if res.code != 0 || !strings.Contains(res.stdout, "storage.trash_days") || strings.Contains(res.stdout, "tls.") {
		t.Fatalf("config list --all: %+v", res)
	}
	if res := f.run(t, "", "config", "get", "tls.extra_sans"); res.stdout != "a.lan\n" {
		t.Fatalf("config get: %+v", res)
	}
	if res := f.run(t, "", "config", "get", "smtp.password"); res.stdout != "(not set)\n" {
		t.Fatalf("config get secret: %+v", res)
	}
	if res := f.run(t, "", "config", "set", "storage.trash_days", "14"); res.code != 0 || stored(store, "storage.trash_days") != "14" {
		t.Fatalf("config set int: %+v", res)
	}
	if res := f.run(t, "", "config", "set", "storage.trash_days", "two weeks"); res.code != ExitUsage {
		t.Fatalf("config set bad int: %+v", res)
	}
	if res := f.run(t, "", "config", "set", "tls.extra_sans", "x.lan, y.lan"); res.code != 0 || stored(store, "tls.extra_sans") != `["x.lan","y.lan"]` {
		t.Fatalf("config set list: %+v %q", res, stored(store, "tls.extra_sans"))
	}
	// Secrets: never on the command line; read from stdin (multi-line kept).
	if res := f.run(t, "", "config", "set", "smtp.password", "hunter2"); res.code != ExitUsage || stored(store, "smtp.password") != "" {
		t.Fatalf("secret on the command line: %+v", res)
	}
	res = f.run(t, "s3cret\n", "config", "set", "smtp.password")
	if res.code != 0 || stored(store, "smtp.password") != `"s3cret"` || strings.Contains(res.stdout+res.stderr, "s3cret") {
		t.Fatalf("secret from stdin: %+v", res)
	}
	res = f.run(t, "", "config", "set", "server.https_port", "9443")
	if res.code != 0 || !strings.Contains(res.stderr, "restart the server") {
		t.Fatalf("restart note: %+v", res)
	}
	if res := f.run(t, "", "config", "set", "no.such_key", "1"); res.code != ExitFailure || !strings.Contains(res.stderr, "unknown setting") {
		t.Fatalf("unknown key: %+v", res)
	}
	if res := f.run(t, "", "config", "set", "storage.trash_days"); res.code != ExitUsage {
		t.Fatalf("missing value: %+v", res)
	}
	if res := f.run(t, "", "config", "unset", "storage.trash_days"); res.code != 0 || stored(store, "reset:storage.trash_days") != "1" {
		t.Fatalf("config unset: %+v", res)
	}
	// config path works without a server.
	h := testHome(t)
	if res := runArgs(t, "", "--home", h.Dir(), "config", "path"); res.code != 0 || strings.TrimSpace(res.stdout) != h.Config() {
		t.Fatalf("config path: %+v", res)
	}
}

func TestValidateTOML(t *testing.T) {
	h := testHome(t)
	data, err := os.ReadFile(h.Config())
	if err != nil {
		t.Fatal(err)
	}
	if err := validateTOML(data); err != nil {
		t.Fatalf("default config invalid: %v", err)
	}
	if err := validateTOML([]byte("[server\nhttps_port = ")); err == nil {
		t.Fatal("broken TOML accepted")
	}
}

func TestNetworkCommands(t *testing.T) {
	f := newFakeAPI(t)
	policy := core.AccessPolicy{Mode: core.AccessAllowlist, Allow: []string{"192.168.1.0/24"}, Deny: []string{}}
	var mu sync.Mutex
	f.handle("GET", "/api/v1/admin/network", func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		writeJSON(w, 200, core.NetworkOverview{Policy: policy, ClientIP: "192.168.1.5",
			URLs: []core.AccessURL{{URL: "https://192.168.1.10:8443/", Kind: core.URLKindIP, Label: "LAN", Interface: "eth0"}}})
	})
	f.handle("PUT", "/api/v1/admin/network/policy", func(w http.ResponseWriter, r *http.Request) {
		in, _ := decodeBody[core.PolicyInput](r)
		mu.Lock()
		defer mu.Unlock()
		if in.Mode == core.AccessAllowlist && len(in.Allow) == 0 && !in.Force {
			writeErr(w, core.Errorf(core.ErrConflict, "this change would lock you out"))
			return
		}
		policy = core.AccessPolicy{Mode: in.Mode, Allow: in.Allow, Deny: in.Deny}
		writeJSON(w, 200, core.PolicyResult{Policy: policy, Warnings: []string{"check your firewall"}})
	})

	res := f.run(t, "", "network")
	if res.code != 0 || !strings.Contains(res.stdout, "https://192.168.1.10:8443/") || !strings.Contains(res.stdout, "allowlist") {
		t.Fatalf("network overview: %+v", res)
	}
	res = f.run(t, "", "network", "allow", "add", "10.8.0.7/24", "192.168.1.9/24")
	if res.code != 0 || !strings.Contains(res.stderr, "check your firewall") {
		t.Fatalf("allow add: %+v", res)
	}
	if strings.Join(policy.Allow, ",") != "192.168.1.0/24,10.8.0.0/24" {
		t.Fatalf("allow list %v (duplicates must be merged)", policy.Allow)
	}
	res = f.run(t, "", "network", "allow", "remove", "192.168.1.0/24", "10.8.0.0/24")
	if res.code != ExitFailure || !strings.Contains(res.stderr, "--force") {
		t.Fatalf("lockout guard: %+v", res)
	}
	if res := f.run(t, "", "network", "allow", "remove", "192.168.1.0/24", "10.8.0.0/24", "--force"); res.code != 0 || len(policy.Allow) != 0 {
		t.Fatalf("allow remove --force: %+v", res)
	}
	if res := f.run(t, "", "network", "mode", "private"); res.code != 0 || policy.Mode != core.AccessPrivate {
		t.Fatalf("mode: %+v", res)
	}
	if res := f.run(t, "", "network", "deny", "add", "10.0.0.66"); res.code != 0 || strings.Join(policy.Deny, ",") != "10.0.0.66" {
		t.Fatalf("deny add: %+v", res)
	}
	var pi core.PolicyInput
	_ = json.Unmarshal(f.body("PUT /api/v1/admin/network/policy"), &pi)
	if pi.Mode != core.AccessPrivate || pi.Allow == nil || pi.Force {
		t.Fatalf("policy body %+v (allow must be [] not null)", pi)
	}
	if res := f.run(t, "", "network", "allow", "add", "not-an-ip"); res.code != ExitUsage {
		t.Fatalf("bad cidr: %+v", res)
	}
	res = f.run(t, "", "--json", "network", "urls")
	var urls []core.AccessURL
	if res.code != 0 || json.Unmarshal([]byte(res.stdout), &urls) != nil || len(urls) != 1 {
		t.Fatalf("urls --json: %+v", res)
	}
	res = f.run(t, "", "network", "urls", "--qr")
	if res.code != 0 || !strings.Contains(res.stdout, "█") {
		t.Fatalf("urls --qr: %+v", res)
	}
}

func TestMDNSMaintenanceCert(t *testing.T) {
	f := newFakeAPI(t)
	store := addSettingsRoutes(f)
	f.handle("GET", "/api/v1/admin/certs", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, core.CertStatus{Leaf: &core.CertInfo{Subject: "fileparcel", DNSNames: []string{"fileparcel.local"}}})
	})
	f.handle("POST", "/api/v1/admin/certs/tailscale/fetch", func(w http.ResponseWriter, r *http.Request) {
		writeErr(w, core.Errorf(core.ErrUnavailable, "tailscale is not running"))
	})

	if res := f.run(t, "", "mdns", "name", "Files.local"); res.code != 0 || stored(store, "mdns.name") != `"files"` {
		t.Fatalf("mdns name: %+v", res)
	}
	if res := f.run(t, "", "mdns", "name", "bad_label"); res.code != ExitUsage {
		t.Fatalf("bad label: %+v", res)
	}
	if res := f.run(t, "", "mdns", "disable"); res.code != 0 || stored(store, "mdns.mode") != `"off"` {
		t.Fatalf("mdns disable: %+v", res)
	}
	if res := f.run(t, "", "mdns", "mode", "nope"); res.code != ExitUsage {
		t.Fatalf("bad mode: %+v", res)
	}

	// Without the setting the server has no maintenance mode.
	if res := f.run(t, "", "maintenance", "on"); res.code != ExitFailure || !strings.Contains(res.stderr, "maintenance.enabled") {
		t.Fatalf("maintenance unsupported: %+v", res)
	}

	res := f.run(t, "", "cert", "sans", "--add", "files.home.arpa", "--add", "A.LAN", "--remove", "none.lan")
	if res.code != 0 || stored(store, "tls.extra_sans") != `["a.lan","files.home.arpa"]` {
		t.Fatalf("cert sans: %+v %s", res, stored(store, "tls.extra_sans"))
	}
	res = f.run(t, "", "cert", "sans")
	if res.code != 0 || !strings.Contains(res.stdout, "fileparcel.local") {
		t.Fatalf("cert sans show: %+v", res)
	}
	if res := f.run(t, "", "cert", "sans", "--add", "bad name"); res.code != ExitUsage {
		t.Fatalf("bad san: %+v", res)
	}
	res = f.run(t, "", "cert", "tailscale", "enable")
	if res.code != ExitFailure || stored(store, "tailscale.cert_enabled") != "true" || !strings.Contains(res.stderr, "operator") {
		t.Fatalf("tailscale enable: %+v", res)
	}
	res = f.run(t, `{"api_token":"cf-token"}`, "cert", "acme", "enable", "--email", "me@example.com", "--domain", "files.example.com", "--credentials-stdin")
	if res.code != ExitFailure { // the fake has no /admin/certs/acme/apply
		t.Fatalf("acme enable: %+v", res)
	}
	if stored(store, "acme.ca") != `"staging"` || stored(store, "acme.dns_credentials") != `"{\"api_token\":\"cf-token\"}"` ||
		stored(store, "acme.domains") != `["files.example.com"]` {
		t.Fatalf("acme settings: ca=%s creds=%s", stored(store, "acme.ca"), stored(store, "acme.dns_credentials"))
	}
	if res := f.run(t, "not json", "cert", "acme", "enable", "--email", "e@x", "--domain", "a.b", "--credentials-stdin"); res.code != ExitUsage {
		t.Fatalf("acme bad creds: %+v", res)
	}
	if res := f.run(t, "", "cert", "acme", "enable", "--email", "e@x", "--domain", "10.0.0.1"); res.code != ExitUsage {
		t.Fatalf("acme ip domain: %+v", res)
	}
}

func TestMaintenanceMode(t *testing.T) {
	f := newFakeAPI(t)
	store := addSettingsRoutes(f,
		core.SettingView{Key: maintenanceKey, Type: "bool", Value: json.RawMessage("false"), Default: json.RawMessage("false")},
		core.SettingView{Key: maintenanceMessageKey, Type: "string", Value: json.RawMessage(`""`), Default: json.RawMessage(`""`)})
	if res := f.run(t, "", "maintenance", "on", "--message", "back at 14:00"); res.code != 0 ||
		stored(store, maintenanceKey) != "true" || stored(store, maintenanceMessageKey) != `"back at 14:00"` {
		t.Fatalf("maintenance on: %+v", res)
	}
	if res := f.run(t, "", "maintenance", "off"); res.code != 0 || stored(store, maintenanceKey) != "false" {
		t.Fatalf("maintenance off: %+v", res)
	}
	if res := f.run(t, "", "maintenance"); res.code != 0 || !strings.Contains(res.stdout, "Maintenance mode: off") {
		t.Fatalf("maintenance status: %+v", res)
	}
	if res := f.run(t, "", "maintenance", "off", "--message", "x"); res.code != ExitUsage {
		t.Fatalf("--message with off: %+v", res)
	}
}

// ---------- shares and requests ----------

func TestShareAndRequestCommands(t *testing.T) {
	f := newFakeAPI(t)
	docs, report, _, _ := fakeTree(t, f)
	var mu sync.Mutex
	shares := map[string]*core.Share{}
	f.handle("POST", "/api/v1/shares", func(w http.ResponseWriter, r *http.Request) {
		in, _ := decodeBody[core.ShareInput](r)
		mu.Lock()
		defer mu.Unlock()
		s := &core.Share{ID: ids.New(ids.PrefixShare), Kind: in.Kind, NodeID: in.NodeID, ExpiresAt: in.ExpiresAt, HasPassword: in.Password != "",
			MaxDownloads: in.MaxDownloads, Status: core.ShareActive, URL: "/s/tok-" + in.Kind, AllowUpload: in.AllowUpload}
		shares[s.ID] = s
		writeJSON(w, 201, s)
	})
	f.handle("GET", "/api/v1/shares", func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		out := []core.Share{}
		for _, s := range shares {
			if s.Kind == r.URL.Query().Get("kind") {
				out = append(out, *s)
			}
		}
		writeJSON(w, 200, core.Page[core.Share]{Items: out})
	})
	f.handle("GET", "/api/v1/shares/{id}", func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		if s := shares[chi.URLParam(r, "id")]; s != nil {
			writeJSON(w, 200, s)
			return
		}
		writeErr(w, core.NotFoundf("share not found"))
	})
	f.handle("PATCH", "/api/v1/shares/{id}", func(w http.ResponseWriter, r *http.Request) {
		in, _ := decodeBody[core.ShareUpdate](r)
		mu.Lock()
		defer mu.Unlock()
		s := shares[chi.URLParam(r, "id")]
		if in.Disabled != nil && *in.Disabled {
			s.Status = core.ShareDisabled
		}
		writeJSON(w, 200, s)
	})
	f.handle("DELETE", "/api/v1/shares/{id}", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusNoContent) })

	res := f.run(t, "pass-word-1\n", "share", "create", "/My files/Docs/Report.PDF", "--expires", "3d", "--password-stdin", "--max-downloads", "5", "--qr")
	if res.code != 0 || !strings.Contains(res.stdout, f.srv.URL+"/s/tok-link") || !strings.Contains(res.stdout, "█") {
		t.Fatalf("share create: %+v", res)
	}
	var si core.ShareInput
	_ = json.Unmarshal(f.body("POST /api/v1/shares"), &si)
	if si.Kind != core.ShareLink || si.NodeID != report || si.Password != "pass-word-1" || si.MaxDownloads == nil || *si.MaxDownloads != 5 ||
		si.ExpiresAt == nil || si.AllowDownload != nil {
		t.Fatalf("share body %+v", si)
	}
	if res := f.run(t, "", "share", "create", "/My files"); res.code != ExitUsage {
		t.Fatalf("sharing a root: %+v", res)
	}
	if res := f.run(t, "", "share", "create", "/My files/Docs/Report.PDF", "--upload"); res.code != ExitUsage {
		t.Fatalf("--upload on a file: %+v", res)
	}
	if res := f.run(t, "", "share", "create", "/My files/Docs", "--no-download", "--no-preview"); res.code != ExitUsage {
		t.Fatalf("nothing to share: %+v", res)
	}
	res = f.run(t, "", "request", "create", "/My files/Docs", "--max-size", "2G", "--quota", "unlimited", "--require-name", "--expires", "never")
	if res.code != 0 || !strings.Contains(res.stdout, "/s/tok-request") {
		t.Fatalf("request create: %+v", res)
	}
	_ = json.Unmarshal(f.body("POST /api/v1/shares"), &si)
	if si.Kind != core.ShareRequest || si.NodeID != docs || !si.AllowUpload || si.UploadMaxFileBytes == nil || *si.UploadMaxFileBytes != 2<<30 ||
		si.UploadQuotaBytes != nil || !si.NoExpiry || !si.RequireUploaderName || si.AllowDownload == nil || *si.AllowDownload {
		t.Fatalf("request body %+v", si)
	}
	if res := f.run(t, "", "request", "create", "/My files/Docs/Report.PDF"); res.code != ExitUsage {
		t.Fatalf("request on a file: %+v", res)
	}

	res = f.run(t, "", "--json", "share", "list")
	var list []core.Share
	if res.code != 0 || json.Unmarshal([]byte(res.stdout), &list) != nil || len(list) != 1 || !strings.HasPrefix(list[0].URL, f.srv.URL) {
		t.Fatalf("share list: %+v", res)
	}
	reqID := ""
	for id, s := range shares {
		if s.Kind == core.ShareRequest {
			reqID = id
		}
	}
	if res := f.run(t, "", "request", "close", reqID); res.code != 0 || shares[reqID].Status != core.ShareDisabled {
		t.Fatalf("request close: %+v", res)
	}
	if res := f.run(t, "", "share", "revoke", reqID); res.code != ExitUsage || !strings.Contains(res.stderr, "fileparcel request") {
		t.Fatalf("share revoke of a request: %+v", res)
	}
	if res := f.run(t, "", "request", "delete", reqID); res.code != 0 {
		t.Fatalf("request delete: %+v", res)
	}
	if res := f.run(t, "", "share", "edit", list[0].ID); res.code != ExitUsage {
		t.Fatalf("edit without flags: %+v", res)
	}
}

// ---------- backups, jobs, audit, keys ----------

func TestBackupCommands(t *testing.T) {
	f := newFakeAPI(t)
	archive := []byte("age-encrypted-backup-bytes")
	sum := sha256.Sum256(archive)
	bid := ids.New(ids.PrefixBackup)
	backup := core.Backup{ID: bid, Scope: core.BackupFull, State: core.BackupReady, FileName: "fileparcel-2026.fpbak",
		Size: int64(len(archive)), SHA256: hex.EncodeToString(sum[:]), Trigger: core.TriggerManual, CreatedAt: time.Now()}
	jobID := f.addJob(core.JobBackupCreate, map[string]string{"backup_id": bid}, core.JobQueued, core.JobRunning, core.JobSucceeded)
	f.handle("POST", "/api/v1/admin/backups", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 202, core.JobRef{JobID: jobID})
	})
	f.handle("GET", "/api/v1/admin/backups", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, core.Page[core.Backup]{Items: []core.Backup{backup}})
	})
	f.handle("GET", "/api/v1/admin/backups/{id}", func(w http.ResponseWriter, r *http.Request) { writeJSON(w, 200, backup) })
	corrupt := false
	f.handle("GET", "/api/v1/admin/backups/{id}/download", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/octet-stream")
		if corrupt {
			w.Write(append([]byte("X"), archive[1:]...))
			return
		}
		w.Write(archive)
	})
	cfg := core.BackupConfig{Enabled: true, ScheduleMeta: "0 3 * * *", ScheduleFull: "0 4 * * 0", KeepLast: 7, Encryption: core.BackupX25519, HasIdentity: true}
	var putBody []byte
	f.handle("GET", "/api/v1/admin/backups/config", func(w http.ResponseWriter, r *http.Request) { writeJSON(w, 200, cfg) })
	f.handle("PUT", "/api/v1/admin/backups/config", func(w http.ResponseWriter, r *http.Request) {
		putBody = bytes.Clone(f.body("PUT /api/v1/admin/backups/config"))
		w.WriteHeader(http.StatusNoContent)
	})

	out := t.TempDir()
	res := f.run(t, "", "backup", "create", "--wait", "--out", out, "--note", "pre")
	if res.code != 0 || !strings.Contains(res.stdout, bid) {
		t.Fatalf("backup create: %+v", res)
	}
	if got, _ := os.ReadFile(filepath.Join(out, "fileparcel-2026.fpbak")); !bytes.Equal(got, archive) {
		t.Fatal("exported archive differs")
	}
	var bi core.BackupInput
	_ = json.Unmarshal(f.body("POST /api/v1/admin/backups"), &bi)
	if bi.Scope != core.BackupFull || bi.Note != "pre" {
		t.Fatalf("backup body %+v", bi)
	}
	// Without --wait the job id is printed.
	if res := f.run(t, "", "backup", "create"); res.code != 0 || !strings.Contains(res.stdout, jobID) {
		t.Fatalf("backup create (no wait): %+v", res)
	}
	// export verifies the checksum.
	corrupt = true
	res = f.run(t, "", "backup", "export", bid, filepath.Join(out, "bad.fpbak"))
	if res.code != ExitFailure || !strings.Contains(res.stderr, "checksum mismatch") || fileExists(filepath.Join(out, "bad.fpbak")) {
		t.Fatalf("corrupt export: %+v", res)
	}
	corrupt = false
	if res := f.run(t, "", "backup", "export", bid, "-"); res.code != 0 || res.stdout != string(archive) {
		t.Fatalf("export to stdout: %+v", res)
	}
	if res := f.run(t, "", "backup", "show", "not-an-id"); res.code != ExitUsage {
		t.Fatalf("bad id: %+v", res)
	}

	// Schedule and retention settings go through PUT /admin/backups/config.
	if res := f.run(t, "", "backup", "schedule", "set", "--meta", "off", "--full", "30 2 * * 6"); res.code != 0 {
		t.Fatalf("schedule set: %+v", res)
	}
	var sent map[string]any
	_ = json.Unmarshal(putBody, &sent)
	if sent["schedule_meta"] != "" || sent["schedule_full"] != "30 2 * * 6" || sent["has_identity"] != nil {
		t.Fatalf("schedule body %s", putBody)
	}
	if res := f.run(t, "", "backup", "schedule", "set", "--meta", "every day"); res.code != ExitUsage {
		t.Fatalf("bad cron: %+v", res)
	}
	if res := f.run(t, "pp-secret\n", "backup", "config", "set", "--encryption", "passphrase", "--passphrase-stdin", "--keep-last", "3"); res.code != 0 {
		t.Fatalf("config set: %+v", res)
	}
	_ = json.Unmarshal(putBody, &sent)
	if sent["passphrase"] != "pp-secret" || sent["encryption"] != "passphrase" || sent["keep_last"] != float64(3) {
		t.Fatalf("config body %s", putBody)
	}
	if res := f.run(t, "", "backup", "config", "set", "--copy-to", "relative/dir"); res.code != ExitUsage {
		t.Fatalf("relative copy-to: %+v", res)
	}
}

func TestJobsAuditKeysCommands(t *testing.T) {
	f := newFakeAPI(t)
	okJob := f.addJob(core.JobMaintTrash, nil, core.JobRunning, core.JobSucceeded)
	badJob := f.addJob(core.JobMaintBlobGC, nil, core.JobRunning, core.JobFailed)
	f.handle("POST", "/api/v1/admin/jobs/run", func(w http.ResponseWriter, r *http.Request) {
		in, _ := decodeBody[core.RunJobInput](r)
		if in.Kind == core.JobMaintBlobGC {
			writeJSON(w, 202, core.JobRef{JobID: badJob})
			return
		}
		writeJSON(w, 202, core.JobRef{JobID: okJob})
	})
	f.handle("GET", "/api/v1/admin/jobs", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, core.Page[core.Job]{Items: []core.Job{{ID: okJob, Kind: core.JobMaintTrash, State: core.JobSucceeded}}})
	})
	if res := f.run(t, "", "jobs", "run", "maintenance.trash", "--wait"); res.code != 0 || !strings.Contains(res.stdout, "finished") {
		t.Fatalf("jobs run: %+v", res)
	}
	if res := f.run(t, "", "gc"); res.code != ExitFailure || !strings.Contains(res.stderr, "simulated failure") {
		t.Fatalf("gc failing job: %+v", res)
	}
	if res := f.run(t, "", "jobs", "run", "x", "--params", "[1]"); res.code != ExitUsage {
		t.Fatalf("bad params: %+v", res)
	}
	if res := f.run(t, "", "jobs", "list", "--state", "weird"); res.code != ExitUsage {
		t.Fatalf("bad state: %+v", res)
	}
	if res := f.run(t, "", "jobs", "list"); res.code != 0 || !strings.Contains(res.stdout, okJob) {
		t.Fatalf("jobs list: %+v", res)
	}
	if res := f.run(t, "", "jobs", "show", badJob, "--wait"); res.code != ExitFailure || !strings.Contains(res.stdout, "failed") {
		t.Fatalf("jobs show --wait failing: %+v", res)
	}

	// audit list / verify / export.
	now := time.Now().UTC()
	f.handle("GET", "/api/v1/admin/audit", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		if q.Get("action") != "auth." || q.Get("outcome") != "failure" || q.Get("since") == "" {
			writeErr(w, core.Invalid("q", "unexpected query "+r.URL.RawQuery))
			return
		}
		writeJSON(w, 200, core.Page[core.AuditRecord]{Items: []core.AuditRecord{
			{Seq: 2, At: now, ActorName: "mallory", Action: "auth.login", Outcome: "failure", IP: "10.0.0.9"},
			{Seq: 1, At: now.Add(-time.Minute), ActorName: "mallory", Action: "auth.login", Outcome: "failure", TargetType: "user", TargetName: "admin"},
		}})
	})
	res := f.run(t, "", "audit", "list", "--since", "24h", "--action", "auth.", "--outcome", "failure")
	if res.code != 0 || strings.Index(res.stdout, "user:admin") > strings.Index(res.stdout, "10.0.0.9") {
		t.Fatalf("audit list (oldest first): %+v", res)
	}
	if res := f.run(t, "", "audit", "list", "--outcome", "meh"); res.code != ExitUsage {
		t.Fatalf("bad outcome: %+v", res)
	}
	f.handle("GET", "/api/v1/admin/audit/verify", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, core.AuditVerify{OK: false, Checked: 10, BrokenAt: 7, Message: "hash mismatch"})
	})
	if res := f.run(t, "", "audit", "verify"); res.code != ExitFailure || !strings.Contains(res.stdout, "broken at seq 7") {
		t.Fatalf("audit verify: %+v", res)
	}
	f.handle("GET", "/api/v1/admin/audit/export", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("seq,action\n1,auth.login\n"))
	})
	dest := filepath.Join(t.TempDir(), "audit.csv")
	if res := f.run(t, "", "audit", "export", "-o", dest); res.code != 0 {
		t.Fatalf("audit export: %+v", res)
	}
	if got, _ := os.ReadFile(dest); string(got) != "seq,action\n1,auth.login\n" {
		t.Fatalf("export content %q", got)
	}
	if res := f.run(t, "", "audit", "export", "-o", dest); res.code != ExitFailure {
		t.Fatalf("export over an existing file: %+v", res)
	}
	// The server aborts an export that fails after rows went out: that is an
	// error, not a complete (shorter) file, and no partial file stays behind.
	f.handle("GET", "/api/v1/admin/audit/export", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("seq,action\n1,auth.login\n"))
		w.(http.Flusher).Flush()
		panic(http.ErrAbortHandler)
	})
	cut := filepath.Join(t.TempDir(), "cut.csv")
	if res := f.run(t, "", "audit", "export", "-o", cut); res.code == 0 {
		t.Fatalf("aborted export reported success: %+v", res)
	}
	for _, p := range []string{cut, cut + partialSuffix} {
		if _, err := os.Lstat(p); !os.IsNotExist(err) {
			t.Fatalf("aborted export left %s (%v)", p, err)
		}
	}
	if res := f.run(t, "", "audit", "export"); res.code == 0 {
		t.Fatalf("aborted export to stdout reported success: %+v", res)
	}

	// keys.
	st := core.KeyStatus{State: core.KeyStateUnlocked, Mode: core.KeyModePlain, CipherName: "aes-256-gcm", KEKs: []core.KEKInfo{
		{ID: "kek_a", Purpose: core.KEKBlob, State: core.KEKActive}, {ID: "kek_b", Purpose: core.KEKField, State: core.KEKActive},
	}}
	f.handle("GET", "/api/v1/admin/keys", func(w http.ResponseWriter, r *http.Request) { writeJSON(w, 200, st) })
	if res := f.run(t, "", "keys", "status"); res.code != 0 || !strings.Contains(res.stdout, "aes-256-gcm") || !strings.Contains(res.stdout, "kek_b") {
		t.Fatalf("keys status: %+v", res)
	}
	if res := f.run(t, "", "keys", "verify"); res.code != ExitFailure || !strings.Contains(res.stdout, "FAIL one active mac KEK") {
		t.Fatalf("keys verify: %+v", res)
	}
	f.handle("POST", "/api/v1/admin/keys/rotate", func(w http.ResponseWriter, r *http.Request) {
		writeErr(w, core.ErrElevationRequired)
	})
	res = f.run(t, "", "keys", "rotate", "--kek")
	if res.code != ExitFailure || !strings.Contains(res.stderr, "admin socket is always elevated") {
		t.Fatalf("elevation hint: %+v", res)
	}
	f.handle("POST", "/api/v1/admin/keys/passphrase", func(w http.ResponseWriter, r *http.Request) { writeJSON(w, 200, st) })
	if res := f.run(t, "old-pass\nnew-pass\n", "keys", "passphrase", "--passphrase-stdin"); res.code != 0 {
		t.Fatalf("keys passphrase: %+v", res)
	}
	var pc core.PassphraseChangeInput
	_ = json.Unmarshal(f.body("POST /api/v1/admin/keys/passphrase"), &pc)
	if pc.CurrentPassphrase != "old-pass" || pc.NewPassphrase != "new-pass" {
		t.Fatalf("passphrase body %+v", pc)
	}
	if res := f.run(t, "same\nsame\n", "keys", "passphrase", "--passphrase-stdin"); res.code != ExitUsage {
		t.Fatalf("same passphrase: %+v", res)
	}
}

// ---------- CA and client certificates ----------

func TestCAAndClientCertCommands(t *testing.T) {
	f := newFakeAPI(t)
	addUserRoutes(f)
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(7), Subject: pkix.Name{CommonName: "FileParcel Local CA"},
		NotBefore: time.Now(), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	pemData := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	f.handle("GET", "/trust/ca.pem", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Disposition", `attachment; filename="fileparcel-ca.pem"`)
		w.Write(pemData)
	})
	f.handle("GET", "/trust/ca.crt", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Disposition", `attachment; filename="../../evil.crt"`)
		w.Write(der)
	})
	sum := sha256.Sum256(der)
	res := f.run(t, "", "ca", "fingerprint")
	if res.code != 0 || strings.TrimSpace(res.stdout) != colonHex(sum[:]) {
		t.Fatalf("ca fingerprint: %+v", res)
	}
	if res := f.run(t, "", "ca", "export"); res.code != 0 || res.stdout != string(pemData) {
		t.Fatalf("ca export pem: %+v", res)
	}
	dir := t.TempDir()
	if res := f.run(t, "", "ca", "export", "--format", "crt", "-o", dir); res.code != 0 {
		t.Fatalf("ca export der: %+v", res)
	}
	if got, err := os.ReadFile(filepath.Join(dir, "evil.crt")); err != nil || !bytes.Equal(got, der) {
		t.Fatalf("server file name must be reduced to its base name: %v", err)
	}
	if res := f.run(t, "", "ca", "export", "--format", "p7b"); res.code != ExitUsage {
		t.Fatalf("bad format: %+v", res)
	}

	p12 := []byte("PKCS12-DATA")
	f.handle("POST", "/api/v1/admin/client-certs", func(w http.ResponseWriter, r *http.Request) {
		in, _ := decodeBody[core.ClientCertInput](r)
		out := map[string]any{"client_cert": core.ClientCert{ID: ids.New(ids.PrefixClientCert), UserID: in.UserID, Name: in.Name},
			"p12": base64.StdEncoding.EncodeToString(p12), "filename": "x.p12"}
		if in.Password == "" {
			out["password"] = "generated-p12-pw"
		}
		writeJSON(w, 201, out)
	})
	dest := filepath.Join(dir, "alice.p12")
	res = f.run(t, "", "client-cert", "issue", "alice", "--name", "phone", "--out", dest)
	if res.code != 0 || !strings.Contains(res.stdout, "generated-p12-pw") {
		t.Fatalf("client-cert issue: %+v", res)
	}
	st, err := os.Stat(dest)
	if err != nil || st.Mode().Perm() != 0o600 {
		t.Fatalf("p12 file mode: %v %v", st, err)
	}
	if got, _ := os.ReadFile(dest); !bytes.Equal(got, p12) {
		t.Fatal("p12 content")
	}
	res = f.run(t, "own-pw\n", "client-cert", "issue", "alice", "--out", dest, "--force", "--password-stdin", "--legacy")
	if res.code != 0 || strings.Contains(res.stdout, "own-pw") {
		t.Fatalf("issue with own password: %+v", res)
	}
	var ci core.ClientCertInput
	_ = json.Unmarshal(f.body("POST /api/v1/admin/client-certs"), &ci)
	if ci.Password != "own-pw" || !ci.Legacy || ci.Days != 365 || ci.Name != "Alice device" {
		t.Fatalf("issue body %+v", ci)
	}
	if res := f.run(t, "", "client-cert", "issue", "alice", "--out", dest); res.code != ExitFailure || !strings.Contains(res.stderr, "already exists") {
		t.Fatalf("existing output: %+v", res)
	}
}
