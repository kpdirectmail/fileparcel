package cli

// Tests of shell completion (complete.go): static words, names and ids from
// the server over the admin socket, remote paths, the acting user, and the
// rules that completion never works offline, gives up quickly and never
// completes secrets.

import (
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

	"fileparcel/internal/config"
	"fileparcel/internal/core"
	"fileparcel/internal/home"
)

// completion runs "fileparcel __complete args…" and returns the candidate
// values (descriptions cut off) and the directive.
func completion(t *testing.T, args ...string) (values []string, dir cobra.ShellCompDirective) {
	t.Helper()
	res := runArgs(t, "", append([]string{"__complete"}, args...)...)
	if res.code != 0 {
		t.Fatalf("__complete %q: %+v", args, res)
	}
	lines := strings.Split(strings.TrimRight(res.stdout, "\n"), "\n")
	last := lines[len(lines)-1]
	if !strings.HasPrefix(last, ":") {
		t.Fatalf("__complete %q: no directive line in %q", args, res.stdout)
	}
	n, err := strconv.Atoi(last[1:])
	if err != nil {
		t.Fatalf("__complete %q: directive %q", args, last)
	}
	for _, l := range lines[:len(lines)-1] {
		v, _, _ := strings.Cut(l, "\t")
		values = append(values, v)
	}
	return values, cobra.ShellCompDirective(n)
}

func sameWords(got, want []string) bool {
	return slices.Equal(slices.Sorted(slices.Values(got)), slices.Sorted(slices.Values(want)))
}

func TestCompletionStaticWords(t *testing.T) {
	home := filepath.Join(t.TempDir(), "none") // no server: static words only
	for _, tc := range []struct {
		args []string
		want []string
	}{
		{[]string{"network", "funnel", "enable", "--mode", ""}, []string{"shares", "app"}},
		{[]string{"network", "funnel", "enable", "--port", ""}, []string{"443", "8443", "10000"}},
		{[]string{"files", "put", "a", "b", "--zip-encryption", ""}, []string{"aes256", "zipcrypto"}},
		{[]string{"access", "grant", "/Team/Design", "--level", ""}, []string{"view", "edit", "manage"}},
		{[]string{"role", "create", "x", "--base", ""}, []string{"member", "guest"}},
		{[]string{"files", "mv", "a", "b", "--conflict", "re"}, []string{"rename", "replace"}},
		{[]string{"audit", "list", "--outcome", ""}, []string{"success", "failure", "denied"}},
		{[]string{"ca", "export", "--format", ""}, []string{"pem", "der", "mobileconfig"}},
		{[]string{"audit", "export", "--format", ""}, []string{"csv", "jsonl"}},
		{[]string{"audit", "export", "--outcome", "f"}, []string{"failure"}},
		{[]string{"keys", "rotate", "--kek", "--purpose", ""}, []string{"blob", "field"}},
		{[]string{"config", "list", "--section", "sh"}, []string{"sharing"}},
		{[]string{"install", "--service", ""}, []string{"user", "system", "none"}},
		{[]string{"user", "set-quota", "alice", ""}, []string{"unlimited", "default"}},
		{[]string{"network", "vpn", "role", "wg0", "e"}, []string{"egress"}},
		{[]string{"token", "create", "t", "--scopes", "files:read,s"}, []string{"files:read,shares"}},
		// Built-in roles are known without a server; custom ones are not.
		{[]string{"user", "create", "bob", "--role", ""}, []string{"owner", "admin", "member", "guest"}},
		{[]string{"access", "grant", "/Team/Design", "--role", ""}, nil},
		// Permissions and setting keys fall back to this program's catalogs.
		{[]string{"role", "create", "x", "--add", "users.v"}, []string{"users.view"}},
		{[]string{"role", "edit", "x", "--set", "users.view,users.v"}, nil},
		{[]string{"config", "get", "auth.require_2"}, []string{"auth.require_2fa"}},
		{[]string{"config", "set", "auth.require_2fa", ""}, []string{"off", "admins", "all"}},
		// Names from the server: nothing without one.
		{[]string{"user", "show", ""}, nil},
		{[]string{"files", "ls", "/My files/"}, nil},
	} {
		got, dir := completion(t, append([]string{"--home", home}, tc.args...)...)
		if !sameWords(got, tc.want) {
			t.Errorf("%q: got %q, want %q", tc.args, got, tc.want)
		}
		if dir&cobra.ShellCompDirectiveNoFileComp == 0 {
			t.Errorf("%q: directive %d offers local files", tc.args, dir)
		}
	}
	// Local files where the argument is a local file; nothing for commands
	// without arguments.
	for _, args := range [][]string{{"upgrade", ""}, {"backup", "import", ""}, {"files", "put", ""}, {"files", "get", "/My files/a", ""},
		{"backup", "restore", "./"}} {
		if got, dir := completion(t, append([]string{"--home", home}, args...)...); len(got) != 0 || dir != cobra.ShellCompDirectiveDefault {
			t.Errorf("%q: %q %d, want local files", args, got, dir)
		}
	}
	if got, dir := completion(t, "--home", home, "status", ""); len(got) != 0 || dir != cobra.ShellCompDirectiveNoFileComp {
		t.Errorf("status: %q %d", got, dir)
	}
}

// completionServer is a fake server on the admin socket with users (admin,
// Alice, bob), groups, the roles of addRoleRoutes, settings, network, links,
// tokens, invitations, backups, jobs, client certificates and a grant.
func completionServer(t *testing.T) (*fakeAPI, string, *fakeGrants) {
	t.Helper()
	f := newFakeAPI(t)
	grants := addGrantRoutes(f, nil)
	addRoleRoutes(f)
	addIngressRoutes(f)
	now := time.Now().UTC()
	f.handle("GET", "/api/v1/admin/settings", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, []core.SettingView{
			{Key: "auth.require_2fa", Type: "enum", Enum: []string{"off", "admins", "all"}, Label: "Require 2FA"},
			{Key: "ui.login_message", Type: "string"},
			{Key: "smtp.password", Type: "secret", Secret: true},
			{Key: "search.enabled", Type: "bool"},
		})
	})
	f.handle("GET", "/api/v1/shares", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, core.Page[core.Share]{Items: []core.Share{
			{ID: "shr_01j9zq3x4k6m8p0r2t4v6x8z0b", Kind: r.URL.Query().Get("kind"), NodeName: "a.pdf", Status: core.ShareActive},
		}})
	})
	f.handle("GET", "/api/v1/me/tokens", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, core.Page[core.APIToken]{Items: []core.APIToken{
			{ID: "tok_01j9zq3x4k6m8p0r2t4v6x8z0b", Name: "laptop"},
			{ID: "tok_01j9zq3x4k6m8p0r2t4v6x8z0c", Name: "old", RevokedAt: &now},
		}})
	})
	f.handle("GET", "/api/v1/admin/invites", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, core.Page[core.Invite]{Items: []core.Invite{
			{ID: "inv_01j9zq3x4k6m8p0r2t4v6x8z0b", Email: "carol@example.com", Status: core.InviteActive},
			{ID: "inv_01j9zq3x4k6m8p0r2t4v6x8z0c", Status: "used"},
		}})
	})
	f.handle("GET", "/api/v1/admin/backups", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, core.Page[core.Backup]{Items: []core.Backup{{ID: "bak_01j9zq3x4k6m8p0r2t4v6x8z0b", Scope: core.BackupFull, CreatedAt: now}}})
	})
	f.handle("GET", "/api/v1/admin/jobs", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, core.Page[core.Job]{Items: []core.Job{
			{ID: "job_01j9zq3x4k6m8p0r2t4v6x8z0b", Kind: core.JobBackupCreate, State: core.JobRunning},
			{ID: "job_01j9zq3x4k6m8p0r2t4v6x8z0c", Kind: core.JobBackupVerify, State: core.JobSucceeded},
		}})
	})
	f.handle("GET", "/api/v1/admin/client-certs", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, core.Page[core.ClientCert]{Items: []core.ClientCert{{ID: "ccr_01j9zq3x4k6m8p0r2t4v6x8z0b", Username: "bob", Name: "phone"}}})
	})
	f.addFolder(f.myRoot(), "Docs")
	f.addFile(f.myRoot(), "a.txt", []byte("a"))
	f.addFolder(f.teamRoot(), "Briefs")
	return f, f.socketHome(t), grants
}

func TestCompletionFromServer(t *testing.T) {
	f, dir, grants := completionServer(t)
	gr := grants.add(f.teamRoot(), core.Grant{SubjectType: core.SubjectGroup, SubjectName: "Marketing", Role: core.GrantViewer})
	for _, tc := range []struct {
		args []string
		want []string
	}{
		{[]string{"user", "show", ""}, []string{"admin", "Alice", "bob"}},
		{[]string{"user", "show", "b"}, []string{"bob"}},
		{[]string{"--as", ""}, []string{"admin", "Alice", "bob"}},
		{[]string{"user", "delete", "bob", "--transfer-to", "A"}, []string{"Alice"}},
		{[]string{"group", "add-member", ""}, []string{"Design", "Marketing"}},
		{[]string{"group", "add-member", "Design", "alice", "b"}, []string{"bob"}},
		{[]string{"user", "set-role", "bob", ""}, []string{"owner", "admin", "member", "guest", "Helpdesk"}},
		{[]string{"access", "grant", "/Team/Design", "--role", ""}, []string{"Helpdesk"}},
		{[]string{"role", "delete", "Helpdesk", "--reassign-to", "m"}, []string{"member"}},
		{[]string{"role", "edit", "Helpdesk", "--remove", "users.v"}, []string{"users.view"}},
		{[]string{"config", "get", ""}, []string{"auth.require_2fa", "ui.login_message", "smtp.password", "search.enabled"}},
		{[]string{"config", "set", "auth.require_2fa", ""}, []string{"off", "admins", "all"}},
		{[]string{"config", "set", "search.enabled", ""}, []string{"true", "false"}},
		{[]string{"config", "set", "smtp.password", ""}, nil}, // never a secret
		{[]string{"network", "vpn", "allow", "y"}, []string{"yggdrasil"}},
		{[]string{"network", "vpn", "role", ""}, []string{"eth0", "wg0-mullvad"}},
		{[]string{"share", "show", ""}, []string{"shr_01j9zq3x4k6m8p0r2t4v6x8z0b"}},
		{[]string{"request", "close", ""}, []string{"shr_01j9zq3x4k6m8p0r2t4v6x8z0b"}},
		{[]string{"token", "revoke", ""}, []string{"tok_01j9zq3x4k6m8p0r2t4v6x8z0b"}},
		{[]string{"invite", "revoke", ""}, []string{"inv_01j9zq3x4k6m8p0r2t4v6x8z0b"}},
		{[]string{"backup", "verify", ""}, []string{"bak_01j9zq3x4k6m8p0r2t4v6x8z0b"}},
		{[]string{"jobs", "show", ""}, []string{"job_01j9zq3x4k6m8p0r2t4v6x8z0b", "job_01j9zq3x4k6m8p0r2t4v6x8z0c"}},
		{[]string{"jobs", "cancel", ""}, []string{"job_01j9zq3x4k6m8p0r2t4v6x8z0b"}},
		{[]string{"client-cert", "revoke", ""}, []string{"ccr_01j9zq3x4k6m8p0r2t4v6x8z0b"}},
		{[]string{"access", "revoke", "/Team/Design", ""}, []string{gr.ID}},
		{[]string{"files", "ls", ""}, []string{"/My files/", "/Team/"}},
		{[]string{"files", "ls", "/"}, []string{"/My files/", "/Team/"}},
		{[]string{"files", "ls", "/Team/"}, []string{"/Team/Design/"}},
		{[]string{"files", "ls", "/My files/"}, []string{"/My files/Docs/", "/My files/a.txt"}},
		{[]string{"files", "rm", "/My files/a.txt", "/My files/D"}, []string{"/My files/Docs/"}},
		{[]string{"files", "ls", "D"}, []string{"Docs/"}},
		{[]string{"request", "create", "/My files/"}, []string{"/My files/Docs/"}}, // folders only
		{[]string{"files", "put", "./x", "/Team/Design/"}, []string{"/Team/Design/Briefs/"}},
		{[]string{"access", "list", "/Team/Design/"}, []string{"/Team/Design/Briefs/"}},
	} {
		got, _ := completion(t, append([]string{"--home", dir}, tc.args...)...)
		if !sameWords(got, tc.want) {
			t.Errorf("%q: got %q, want %q", tc.args, got, tc.want)
		}
	}

	// A folder among the candidates keeps the shell from adding a space.
	if _, d := completion(t, "--home", dir, "files", "ls", "/My files/D"); d&cobra.ShellCompDirectiveNoSpace == 0 {
		t.Errorf("folder: directive %d lacks NoSpace", d)
	}
	if _, d := completion(t, "--home", dir, "files", "ls", "/My files/a"); d&cobra.ShellCompDirectiveNoSpace != 0 {
		t.Errorf("file: directive %d has NoSpace", d)
	}
	// File commands act as the first owner over the socket, like the
	// commands themselves; --as wins; access commands keep the socket's
	// rights.
	completion(t, "--home", dir, "files", "ls", "/My files/")
	if as, _ := f.as("GET /api/v1/spaces"); as != "admin" {
		t.Errorf("files completion acts as %q, want the first owner", as)
	}
	completion(t, "--home", dir, "--as", "bob", "share", "show", "")
	if as, _ := f.as("GET /api/v1/shares"); as != "bob" {
		t.Errorf("share completion with --as bob acts as %q", as)
	}
	completion(t, "--home", dir, "access", "list", "/Team/")
	if as, _ := f.as("GET /api/v1/spaces"); as != "" {
		t.Errorf("access completion acts as %q, want the socket's rights", as)
	}
	completion(t, "--home", dir, "access", "check", "bob", "/My files/")
	if as, _ := f.as("GET /api/v1/spaces"); as != "bob" {
		t.Errorf("access check completion acts as %q, want the checked user", as)
	}
	// A backup file works too: nothing matching → local files.
	if got, d := completion(t, "--home", dir, "backup", "restore", "./"); len(got) != 0 || d != cobra.ShellCompDirectiveDefault {
		t.Errorf("backup restore ./: %q %d", got, d)
	}
}

func TestCompletionRemote(t *testing.T) {
	f := newFakeAPI(t)
	addUserRoutes(f)
	got, _ := completion(t, "--server", f.srv.URL, "--token", fakeToken, "user", "show", "")
	if !sameWords(got, []string{"admin", "Alice"}) {
		t.Errorf("remote: %q", got)
	}
	// --token-file is read for completions too (the root hook that reads it
	// for commands does not run).
	tf := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(tf, []byte(fakeToken+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got, _ := completion(t, "--server", f.srv.URL, "--token-file", tf, "user", "show", "A"); !sameWords(got, []string{"Alice"}) {
		t.Errorf("remote with --token-file: %q", got)
	}
}

// Completion never works offline: a stopped server gives nothing, and the
// home is not opened (no lock, no database, no passphrase prompt).
func TestCompletionNeverOffline(t *testing.T) {
	dir := t.TempDir()
	h, err := home.New(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := h.EnsureLayout(); err != nil {
		t.Fatal(err)
	}
	if err := config.Default(config.NewInstallID()).SaveTo(h.Config()); err != nil {
		t.Fatal(err)
	}
	before := listTree(t, dir)
	for _, args := range [][]string{{"user", "show", ""}, {"files", "ls", "/My files/"}, {"share", "show", ""}} {
		if got, _ := completion(t, append([]string{"--home", dir}, args...)...); len(got) != 0 {
			t.Errorf("%q with the server stopped: %q", args, got)
		}
	}
	if after := listTree(t, dir); !slices.Equal(before, after) {
		t.Errorf("completion changed the home:\nbefore %q\nafter  %q", before, after)
	}
	// --offline turns server completion off even while a server runs.
	f := newFakeAPI(t)
	addUserRoutes(f)
	sock := f.socketHome(t)
	if got, _ := completion(t, "--home", sock, "--offline", "user", "show", ""); len(got) != 0 ||
		f.requested("GET /api/v1/admin/users") != 0 {
		t.Errorf("--offline: %q (%d requests)", got, f.requested("GET /api/v1/admin/users"))
	}
}

func listTree(t *testing.T, dir string) []string {
	t.Helper()
	var out []string
	err := filepath.WalkDir(dir, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		out = append(out, strings.TrimPrefix(p, dir))
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// A server that does not answer in time gives no candidates, quickly.
func TestCompletionTimeout(t *testing.T) {
	f := newFakeAPI(t)
	release := make(chan struct{})
	t.Cleanup(func() { close(release) })
	f.handle("GET", "/api/v1/admin/users", func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-release:
		case <-r.Context().Done():
		}
	})
	dir := f.socketHome(t)
	start := time.Now()
	got, _ := completion(t, "--home", dir, "user", "show", "")
	if len(got) != 0 {
		t.Errorf("slow server: %q", got)
	}
	if d := time.Since(start); d > completionTimeout+2*time.Second {
		t.Errorf("completion took %s", d)
	}
}

// No flag that carries a secret has a completion function, and every
// secret-prompt flag is a switch (secrets are never offered or read from
// the server).
func TestCompletionNeverSecrets(t *testing.T) {
	root := NewRootCmd()
	walkCommands(root, func(c *cobra.Command) {
		visit := func(f *pflag.Flag) {
			name := f.Name
			if !strings.Contains(name, "password") && !strings.Contains(name, "passphrase") && !strings.Contains(name, "secret") &&
				!strings.Contains(name, "credentials") && !strings.Contains(name, "identity") && name != "token" {
				return
			}
			if _, ok := c.GetFlagCompletionFunc(name); ok {
				t.Errorf("%s --%s has a completion function", c.CommandPath(), name)
			}
		}
		c.Flags().VisitAll(visit)
		c.PersistentFlags().VisitAll(visit)
	})
}

// Every placeholder of a Use line either has a source, asks for local
// files, or is a word the user makes up; a new placeholder must be added
// to argSource (or here, when nothing can complete it).
func TestCompletionPlaceholdersKnown(t *testing.T) {
	free := []string{"<name>", "<new-name>", "<query>", "<label>", "<cidr|ip>", "<name|ip>", "<path|id|name>", "<kind>",
		"<bash|zsh|fish|powershell>", "<private|allowlist|any>", "<auto|avahi|dnssd|builtin|off>"}
	root := NewRootCmd()
	walkCommands(root, func(c *cobra.Command) {
		if c.Hidden {
			return
		}
		for _, ph := range placeholders(c) {
			src, local := argSource(c, ph, "")
			if src == nil && !local && !slices.Contains(free, strings.TrimSuffix(ph, "...")) {
				t.Errorf("%s: placeholder %s completes nothing", c.CommandPath(), ph)
			}
		}
	})
	if got := placeholders(findCommand(root, "keys rotate")); len(got) != 0 {
		t.Errorf("keys rotate: flag groups taken for placeholders: %q", got)
	}
	if got := placeholders(findCommand(root, "group add-member")); !slices.Equal(got, []string{"<group>", "<user>..."}) {
		t.Errorf("group add-member: %q", got)
	}
}
