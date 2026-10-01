package config

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"fileparcel/internal/home"
)

const id = "0123456789abcdef0123456789abcdef"

func newHome(t *testing.T, content string) *home.Home {
	t.Helper()
	h, _ := home.New(t.TempDir())
	if content != "" {
		if err := os.WriteFile(h.Config(), []byte(content), 0o640); err != nil {
			t.Fatal(err)
		}
	}
	return h
}

func TestDefaultValidAndSaveLoad(t *testing.T) {
	c := Default(id)
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	h := newHome(t, "")
	if err := c.SaveTo(h.Config()); err != nil {
		t.Fatal(err)
	}
	st, _ := os.Stat(h.Config())
	if st.Mode().Perm() != 0o640 {
		t.Fatalf("mode %o", st.Mode().Perm())
	}
	data, _ := os.ReadFile(h.Config())
	if !strings.HasPrefix(string(data), DefaultHeader+"\n\n") {
		t.Fatalf("header missing:\n%s", data)
	}
	for _, want := range []string{"install_id = '" + id + "'", "[server]", "https_port = 8443", "http_port = 8080",
		"[log]", "max_size_mb = 50", "[admin_socket]", "[runtime]", "gomemlimit_mb = 0"} {
		if !strings.Contains(string(data), want) {
			t.Errorf("saved file lacks %q:\n%s", want, data)
		}
	}
	got, err := Load(h)
	if err != nil {
		t.Fatal(err)
	}
	if got.Server.Name != c.Server.Name || got.Server.HTTPSPort != c.Server.HTTPSPort || got.Server.HTTPPort != c.Server.HTTPPort {
		t.Fatalf("roundtrip mismatch: %+v", got.Server)
	}
	if got.InstallID != id || got.Log != c.Log || got.AdminSocket != c.AdminSocket || got.Runtime != c.Runtime ||
		len(got.Server.Bind) != 1 || got.Server.Bind[0] != "::" || !got.Server.SamePortRedirect {
		t.Fatalf("roundtrip mismatch: %+v", got)
	}
	if _, err := os.Stat(h.Config() + ".tmp"); !os.IsNotExist(err) {
		t.Fatal("tmp file left behind")
	}
}

func TestLoadPartialAndUnknownKeys(t *testing.T) {
	h := newHome(t, `# My custom header
# second line

install_id = "`+id+`"
[server]
https_port = 9443
bogus = 1
[log]
level = "debug"
`)
	c, err := Load(h)
	if err != nil {
		t.Fatal(err)
	}
	if c.Server.HTTPSPort != 9443 || c.Server.HTTPPort != 8080 || c.Log.Level != "debug" || c.Log.MaxFiles != 5 {
		t.Fatalf("defaults not applied: %+v", c)
	}
	if w := c.Warnings(); len(w) != 1 || !strings.Contains(w[0], "server.bogus") {
		t.Fatalf("warnings %v", w)
	}
	c.Server.Name = "box"
	if err := c.Save(); err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(h.Config())
	if !strings.HasPrefix(string(data), "# My custom header\n# second line\n\n") {
		t.Fatalf("header not preserved:\n%s", data)
	}
	c2, err := Load(h)
	if err != nil || c2.Server.Name != "box" {
		t.Fatalf("reload: %v %+v", err, c2)
	}
	// Saving twice must not duplicate the header or key comments.
	if err := c2.Save(); err != nil {
		t.Fatal(err)
	}
	data2, _ := os.ReadFile(h.Config())
	if strings.Count(string(data2), "# My custom header") != 1 || string(data2) != string(data) {
		t.Fatalf("second save changed file:\n%s\n---\n%s", data, data2)
	}
	if !strings.Contains(string(data), "bogus = 1") {
		t.Fatalf("Save dropped the unknown key:\n%s", data)
	}
}

// Save must not delete keys this binary does not model: a rolled-back binary
// would otherwise destroy the newer version's configuration the first time a
// bootstrap setting changes (settings.Store does this on every server.* /
// log.level change).
func TestSavePreservesUnknownKeys(t *testing.T) {
	h := newHome(t, `# Custom header

install_id = "`+id+`"
future_top = 7
[server]
https_port = 9443
future_key = "keep me"
[log]
level = "debug"
[future_section]
a = 1
b = ["x", "y"]
[future_section.sub]
c = "z"
`)
	c, err := Load(h)
	if err != nil {
		t.Fatal(err)
	}
	if w := c.Warnings(); len(w) != 4 {
		t.Fatalf("warnings %v", w)
	}
	c.Server.Name = "box"
	if err := c.Save(); err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(h.Config())
	for _, want := range []string{
		"# Custom header", "future_top = 7", `future_key = 'keep me'`,
		"[future_section]", "a = 1", `b = ['x', 'y']`, "[future_section.sub]", `c = 'z'`,
		"name = 'box'", "# mDNS label",
	} {
		if !strings.Contains(string(data), want) {
			t.Errorf("Save lost %q:\n%s", want, data)
		}
	}
	// future_top is a root key: it must stay above the first table header.
	if i, j := strings.Index(string(data), "future_top"), strings.Index(string(data), "["+"server]"); i < 0 || j < 0 || i > j {
		t.Errorf("root key moved into a table:\n%s", data)
	}
	// The result must load again, with the same values and warnings…
	c2, err := Load(h)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	if c2.Server.Name != "box" || c2.Server.HTTPSPort != 9443 || len(c2.Warnings()) != 4 {
		t.Fatalf("reload: %+v %v", c2, c2.Warnings())
	}
	// …and saving again must be a no-op (no duplicated tables).
	if err := c2.Save(); err != nil {
		t.Fatal(err)
	}
	data2, _ := os.ReadFile(h.Config())
	if string(data2) != string(data) {
		t.Fatalf("second save changed the file:\n%s\n---\n%s", data, data2)
	}
	if n := strings.Count(string(data2), "[server]"); n != 1 {
		t.Fatalf("[server] appears %d times:\n%s", n, data2)
	}
}

func TestEnvOverrides(t *testing.T) {
	h := newHome(t, "install_id = \""+id+"\"\n[server]\nhttps_port = 9443\n")
	t.Setenv("FILEPARCEL_SERVER_HTTPS_PORT", "10443")
	t.Setenv("FILEPARCEL_SERVER_BIND", "127.0.0.1, ::1")
	t.Setenv("FILEPARCEL_LOG_FILE", "false")
	t.Setenv("FILEPARCEL_INSTALL_ID", "ffffffffffffffffffffffffffffffff") // not overridable
	c, err := Load(h)
	if err != nil {
		t.Fatal(err)
	}
	if c.Server.HTTPSPort != 10443 || len(c.Server.Bind) != 2 || c.Server.Bind[1] != "::1" || c.Log.File || c.InstallID != id {
		t.Fatalf("env not applied: %+v", c)
	}
	want := []string{"log.file", "server.bind", "server.https_port"}
	if got := c.Overridden(); strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("overridden %v", got)
	}
	if !c.IsOverridden("server.https_port") || c.IsOverridden("server.http_port") {
		t.Fatal("IsOverridden")
	}
	if EnvName("server.https_port") != "FILEPARCEL_SERVER_HTTPS_PORT" {
		t.Fatal("EnvName")
	}
	// Save keeps the file value for env-provided keys, but persists real changes.
	c.Server.HTTPPort = 8081
	if err := c.Save(); err != nil {
		t.Fatal(err)
	}
	os.Unsetenv("FILEPARCEL_SERVER_HTTPS_PORT")
	os.Unsetenv("FILEPARCEL_SERVER_BIND")
	os.Unsetenv("FILEPARCEL_LOG_FILE")
	c2, err := Load(h)
	if err != nil {
		t.Fatal(err)
	}
	if c2.Server.HTTPSPort != 9443 || c2.Server.HTTPPort != 8081 || !c2.Log.File || len(c2.Server.Bind) != 1 {
		t.Fatalf("env values leaked into file: %+v", c2)
	}

	t.Setenv("FILEPARCEL_SERVER_HTTPS_PORT", "abc")
	if _, err := Load(h); err == nil || !strings.Contains(err.Error(), "FILEPARCEL_SERVER_HTTPS_PORT") {
		t.Fatalf("bad env value: %v", err)
	}
}

func TestValidate(t *testing.T) {
	c := Default("nothex")
	c.Server.Name = "Bad_Name"
	c.Server.HTTPSPort = 0
	c.Server.HTTPPort = 70000
	c.Server.Bind = []string{"not-an-ip"}
	c.Server.PublicURL = "ftp://x"
	c.Server.TrustedProxies = []string{"10.0.0.0/8", "nope"}
	c.Log.Level = "loud"
	c.Log.Format = "xml"
	c.Log.MaxSizeMB = 0
	c.Log.MaxFiles = 0
	c.Runtime.GOMemLimitMB = -1
	err := c.Validate()
	if err == nil {
		t.Fatal("expected errors")
	}
	keys := map[string]bool{}
	for _, e := range err.(interface{ Unwrap() []error }).Unwrap() {
		var ve *ValidationError
		if errors.As(e, &ve) {
			keys[ve.Key] = true
		}
	}
	for _, k := range []string{"install_id", "server.name", "server.https_port", "server.http_port", "server.bind",
		"server.public_url", "server.trusted_proxies", "log.level", "log.format", "log.max_size_mb", "log.max_files",
		"runtime.gomemlimit_mb"} {
		if !keys[k] {
			t.Errorf("no error for %s", k)
		}
	}
	d := Default(id)
	d.Server.HTTPPort = d.Server.HTTPSPort
	if d.Validate() == nil {
		t.Fatal("same ports accepted")
	}
}

// TestCheckBindList: every entry is bound separately on one port, so a
// repeated address or anything next to a dual-stack wildcard cannot start.
// config.Validate itself only checks each entry (the server skips covered
// entries), so the CLI still works on a file that has such a list.
func TestCheckBindList(t *testing.T) {
	for _, l := range [][]string{
		{"::", "0.0.0.0"}, {"0.0.0.0", "::"}, {"::", "::"}, {"0.0.0.0", "::1"}, {"::", "192.168.1.5"},
		{"::ffff:10.0.0.1", "10.0.0.1"}, {"127.0.0.1", "127.0.0.1"}, {}, {"nope"}, {"127.0.0.1", "nope"},
	} {
		if err := CheckBindList(l); err == nil {
			t.Errorf("%q accepted", l)
		}
	}
	for _, l := range [][]string{{"::"}, {"0.0.0.0"}, {"127.0.0.1", "::1"}, {"192.168.1.5", "fd00::5", "100.64.0.1"}} {
		if err := CheckBindList(l); err != nil {
			t.Errorf("%q: %v", l, err)
		}
	}
	c := Default(id)
	c.Server.Bind = []string{"::", "0.0.0.0"}
	if err := c.Validate(); err != nil {
		t.Fatalf("Validate refuses an overlapping list: %v", err)
	}
}

// TestCheckPublicURL: server.public_url is the base of every share and
// invitation link sent to other people, so it is an origin only — no user
// name or password (they would travel with each link), no path (the web app
// is served from the root), query or fragment, and a port in range.
func TestCheckPublicURL(t *testing.T) {
	for _, s := range []string{
		"ftp://files.example", "files.example", "https://", "https:files.example", "https://:443",
		"https://user:secret@files.example", "https://user@files.example", "https://@files.example",
		"https://files.example/sub", "https://files.example//", "https://files.example/%2F",
		"https://files.example?a=1", "https://files.example/?", "https://files.example#top", "https://files.example/#",
		"https://files.example:99999", "https://files.example:0", "https://files.example:", "https://files.example:abc",
		" https://files.example",
	} {
		if err := CheckPublicURL(s); err == nil {
			t.Errorf("%q accepted", s)
		}
	}
	for _, s := range []string{
		"", "https://files.example", "https://files.example/", "HTTPS://Files.Example", "http://files.lan",
		"https://files.example:8443", "https://files.example:65535/", "https://192.168.1.5:9443/", "https://[2001:db8::7]:8443/",
	} {
		if err := CheckPublicURL(s); err != nil {
			t.Errorf("%q: %v", s, err)
		}
	}
	c := Default(id)
	c.Server.PublicURL = "https://user:secret@files.example:99999/sub"
	var ve *ValidationError
	if err := c.Validate(); !errors.As(err, &ve) || ve.Key != "server.public_url" || !strings.Contains(ve.Msg, "user name or password") {
		t.Fatalf("Validate: %v", err)
	}
}

// TestRereadAndRestore: Reread returns the file as it is now, with the
// environment overrides recorded at load time on top (never persisted), and
// RestoreFile puts the exact content back.
func TestRereadAndRestore(t *testing.T) {
	h := newHome(t, "install_id = \""+id+"\"\n[server]\nhttps_port = 9443\n")
	t.Setenv("FILEPARCEL_SERVER_HTTP_PORT", "8081")
	c, err := Load(h)
	if err != nil {
		t.Fatal(err)
	}
	os.Unsetenv("FILEPARCEL_SERVER_HTTP_PORT") // the recorded value counts, not the current environment
	edited := "# mine\n\ninstall_id = \"" + id + "\"\n[server]\nhttps_port = 9444\nhttp_port = 8090\n[log]\nformat = \"json\"\n[future]\nx = 1\n"
	if err := os.WriteFile(h.Config(), []byte(edited), 0o640); err != nil {
		t.Fatal(err)
	}
	n, data, err := c.Reread()
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != edited || n.Path() != h.Config() {
		t.Fatalf("Reread content %q path %q", data, n.Path())
	}
	if n.Server.HTTPSPort != 9444 || n.Log.Format != "json" || n.Server.HTTPPort != 8081 ||
		!n.IsOverridden("server.http_port") || len(n.Overridden()) != 1 {
		t.Fatalf("Reread: %+v %+v %v", n.Server, n.Log, n.Overridden())
	}
	n.Log.Level = "debug"
	if err := n.Save(); err != nil {
		t.Fatal(err)
	}
	saved, _ := os.ReadFile(h.Config())
	for _, want := range []string{"# mine\n", "https_port = 9444", "http_port = 8090", "format = 'json'", "level = 'debug'", "[future]"} {
		if !strings.Contains(string(saved), want) {
			t.Errorf("saved file lacks %q:\n%s", want, saved)
		}
	}
	if err := n.RestoreFile(data); err != nil {
		t.Fatal(err)
	}
	if back, _ := os.ReadFile(h.Config()); string(back) != edited {
		t.Fatalf("RestoreFile:\n%s", back)
	}
	if err := os.Remove(h.Config()); err != nil {
		t.Fatal(err)
	}
	if _, _, err := c.Reread(); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("Reread of a missing file: %v", err)
	}
}

func TestGetSetKeys(t *testing.T) {
	c := Default(id)
	if v, ok := c.Get("server.https_port"); !ok || v != 8443 {
		t.Fatalf("Get %v %v", v, ok)
	}
	if err := c.Set("server.https_port", float64(9000)); err != nil || c.Server.HTTPSPort != 9000 {
		t.Fatal(err)
	}
	if err := c.Set("server.https_port", 1.5); err == nil {
		t.Fatal("fraction accepted")
	}
	if err := c.Set("server.trusted_proxies", []any{"10.0.0.1"}); err != nil || c.Server.TrustedProxies[0] != "10.0.0.1" {
		t.Fatal(err)
	}
	if err := c.Set("log.level", "warn"); err != nil || c.Log.Level != "warn" {
		t.Fatal(err)
	}
	if err := c.Set("nope.key", 1); err == nil {
		t.Fatal("unknown key accepted")
	}
	v, _ := c.Get("server.bind")
	v.([]string)[0] = "mutated"
	if c.Server.Bind[0] == "mutated" {
		t.Fatal("Get must return a copy")
	}
	if len(Keys()) != 15 || Keys()[0] != "install_id" {
		t.Fatalf("Keys %v", Keys())
	}
	p, err := ParsePrefixOrAddr("::ffff:10.1.2.3")
	if err != nil || p.String() != "10.1.2.3/32" {
		t.Fatalf("ParsePrefixOrAddr: %v %v", p, err)
	}
	if _, err := LoadFile(filepath.Join(t.TempDir(), "missing.toml")); err == nil || !strings.Contains(err.Error(), "fileparcel init") {
		t.Fatalf("missing file: %v", err)
	}
	if !ValidDNSLabel("file-parcel2") || ValidDNSLabel("-x") || ValidDNSLabel("") {
		t.Fatal("ValidDNSLabel")
	}
}
