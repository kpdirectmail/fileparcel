// Package scripts_test runs the POSIX shell scripts (install/uninstall
// helpers, scripts/env.sh, scripts/dev.sh, scripts/release.sh) against
// scratch directories and stub commands, and pins the ignore files that keep
// secrets out of commits and release zips. Nothing here touches a real
// installation: every home, service file, symlink and command is created
// below t.TempDir(), and the stubs come first on PATH.
package scripts_test

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"
)

// repoRoot walks up from the test's directory to the module root.
func repoRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("go.mod not found above the test directory")
		}
		dir = parent
	}
}

func needSh(t *testing.T) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("POSIX shell scripts")
	}
	if _, err := exec.LookPath("sh"); err != nil {
		t.Skip("no sh")
	}
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func write(t *testing.T, path, content string, mode os.FileMode) {
	t.Helper()
	must(t, os.MkdirAll(filepath.Dir(path), 0o755))
	must(t, os.WriteFile(path, []byte(content), mode))
}

// run runs "sh args..." in dir with exactly env (plus nothing inherited)
// and returns stdout, stderr and the exit code.
func run(t *testing.T, dir string, env []string, args ...string) (string, string, int) {
	t.Helper()
	cmd := exec.Command("sh", args...)
	cmd.Dir = dir
	cmd.Env = env
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	err := cmd.Run()
	code := 0
	if err != nil {
		ee, ok := err.(*exec.ExitError)
		if !ok {
			t.Fatalf("sh %v: %v", args, err)
		}
		code = ee.ExitCode()
	}
	return out.String(), errb.String(), code
}

const sysPath = "/usr/bin:/bin"

// ---------- scripts/env.sh ----------

// goStub writes a fake go that reports version v for "go env GOVERSION"
// and fails everything else.
func goStub(t *testing.T, dir, v string) {
	t.Helper()
	write(t, filepath.Join(dir, "go"), "#!/bin/sh\nif [ \"$1 $2\" = \"env GOVERSION\" ]; then echo "+v+"; exit 0; fi\nexit 1\n", 0o755)
}

func TestEnvShOldGoOnPathUsesSDK(t *testing.T) {
	needSh(t)
	repo := repoRoot(t)
	for _, c := range []struct {
		name    string
		pathGo  string // version of the go on PATH ("" = none)
		sdkGo   string // version in ~/sdk ("" = none)
		want    string
		wantErr string
	}{
		{"old distro go, newer in ~/sdk", "go1.19.8", "go1.27.1", "go1.27.1", ""},
		{"no go on PATH", "", "go1.27.1", "go1.27.1", ""},
		{"a go >= 1.26 on PATH stays first", "go1.26.2", "go1.27.1", "go1.26.2", ""},
		{"old go and an empty ~/sdk: unchanged", "go1.22.2", "", "go1.22.2", ""},
		{"no go at all", "", "", "", "no Go toolchain found"},
	} {
		t.Run(c.name, func(t *testing.T) {
			tmp := t.TempDir()
			path := sysPath
			if c.pathGo != "" {
				goStub(t, filepath.Join(tmp, "pathgo"), c.pathGo)
				path = filepath.Join(tmp, "pathgo") + ":" + path
			}
			if c.sdkGo != "" {
				goStub(t, filepath.Join(tmp, "home", "sdk", c.sdkGo, "bin"), c.sdkGo)
			}
			must(t, os.MkdirAll(filepath.Join(tmp, "home"), 0o755))
			script := `. "$1/scripts/env.sh"; if command -v go >/dev/null 2>&1; then go env GOVERSION; fi`
			out, errOut, code := run(t, tmp, []string{"HOME=" + filepath.Join(tmp, "home"), "PATH=" + path},
				"-c", script, "sh", repo)
			if code != 0 || strings.TrimSpace(out) != c.want || !strings.Contains(errOut, c.wantErr) ||
				(c.wantErr == "" && errOut != "") {
				t.Fatalf("got %q (exit %d, stderr %q), want %q", out, code, errOut, c.want)
			}
		})
	}
}

// build.sh reports exit 3 ("too old") only when no usable Go exists: an
// old go on PATH with a new one in ~/sdk gets past the version check.
func TestBuildShOldGoOnPath(t *testing.T) {
	needSh(t)
	repo := repoRoot(t)
	for _, withSDK := range []bool{false, true} {
		tmp := t.TempDir()
		goStub(t, filepath.Join(tmp, "pathgo"), "go1.19.8")
		must(t, os.MkdirAll(filepath.Join(tmp, "home"), 0o755))
		if withSDK {
			goStub(t, filepath.Join(tmp, "home", "sdk", "go1.27.1", "bin"), "go1.27.1")
		}
		env := []string{"HOME=" + filepath.Join(tmp, "home"), "PATH=" + filepath.Join(tmp, "pathgo") + ":" + sysPath, "TMPDIR=" + tmp}
		_, errOut, code := run(t, tmp, env, filepath.Join(repo, "scripts", "build.sh"), "-q", "-s", repo, "-o", filepath.Join(tmp, "out"),
			"-v", "v1", "-c", "abc", "-d", "2026-01-01T00:00:00Z", "host")
		switch {
		case !withSDK && (code != 3 || !strings.Contains(errOut, "go1.19.8 is too old")):
			t.Errorf("old go only: exit %d, stderr %q; want exit 3 (too old)", code, errOut)
		case withSDK && (code == 3 || strings.Contains(errOut, "too old")):
			t.Errorf("old go on PATH, go1.27.1 in ~/sdk: exit %d, stderr %q; the ~/sdk toolchain was not used", code, errOut)
		}
	}
}

// ---------- scripts/dev.sh ----------

// fakeRepo creates a repository copy holding scripts/dev.sh and a "live
// installation" in server/ (with the install record the installer writes).
func fakeRepo(t *testing.T) string {
	t.Helper()
	repo := repoRoot(t)
	fake := filepath.Join(t.TempDir(), "repo")
	b, err := os.ReadFile(filepath.Join(repo, "scripts", "dev.sh"))
	must(t, err)
	write(t, filepath.Join(fake, "scripts", "dev.sh"), string(b), 0o755)
	write(t, filepath.Join(fake, "server", "fileparcel.toml"), "# live\n", 0o600)
	write(t, filepath.Join(fake, "server", "service", "installed.json"), `{"kind":"systemd-user","home":"x"}`+"\n", 0o600)
	write(t, filepath.Join(fake, "server", "keys", "master.key"), "secret", 0o600)
	// Resolve the temp dir itself (macOS: /var -> /private/var) like dev.sh's pwd -P.
	real, err := filepath.EvalSymlinks(fake)
	must(t, err)
	return real
}

func TestDevShRefusesLiveInstallation(t *testing.T) {
	needSh(t)
	fake := fakeRepo(t)
	must(t, os.Symlink("server", filepath.Join(fake, "live-link")))
	other := filepath.Join(t.TempDir(), "installed-elsewhere")
	write(t, filepath.Join(other, "fileparcel.toml"), "", 0o600)
	write(t, filepath.Join(other, "service", "installed.json"), "{}\n", 0o600)
	env := []string{"HOME=" + t.TempDir(), "PATH=" + sysPath}
	for _, c := range []struct {
		home string
		env  string // FILEPARCEL_DEV_HOME instead of --home
		want string
	}{
		{home: "server", want: "refusing to use"},
		{home: "./server", want: "refusing to use"},
		{home: "scripts/../server", want: "refusing to use"},
		{home: fake + "//server", want: "refusing to use"},
		{home: fake + "/server/", want: "refusing to use"},
		{home: "live-link", want: "refusing to use"},
		{home: "server/sub", want: "refusing to use"},
		{home: fake + "/missing/../server", want: "invalid --home"},
		{env: fake + "/./server", want: "refusing to use"},
		{home: other, want: "installed FileParcel home"},
	} {
		args := []string{filepath.Join(fake, "scripts", "dev.sh"), "--no-build", "--reset", "-y"}
		e := env
		if c.env != "" {
			e = append(append([]string{}, env...), "FILEPARCEL_DEV_HOME="+c.env)
		} else {
			args = append(args, "--home", c.home)
		}
		_, errOut, code := run(t, fake, e, args...)
		if code == 0 || !strings.Contains(errOut, c.want) || strings.Contains(errOut, "Deleted") {
			t.Errorf("home %q%s: exit %d, stderr %q; want a refusal (%s)", c.home, c.env, code, errOut, c.want)
		}
		for _, p := range []string{filepath.Join(fake, "server", "keys", "master.key"), filepath.Join(other, "fileparcel.toml")} {
			if _, err := os.Stat(p); err != nil {
				t.Fatalf("home %q%s: %s was deleted", c.home, c.env, p)
			}
		}
	}

	// A real dev home is still reset (then the missing binary stops it).
	dev := filepath.Join(fake, "tmp", "dev-home")
	write(t, filepath.Join(dev, "fileparcel.toml"), "", 0o600)
	_, errOut, _ := run(t, fake, env, filepath.Join(fake, "scripts", "dev.sh"), "--no-build", "--reset", "-y", "--home", "tmp/dev-home")
	if !strings.Contains(errOut, "Deleted "+dev) {
		t.Errorf("dev home not reset: %q", errOut)
	}
	if _, err := os.Stat(dev); !os.IsNotExist(err) {
		t.Errorf("dev home still exists: %v", err)
	}
}

// ---------- uninstall.sh ----------

// uninstallFuncs returns the definitions of the named shell functions of
// uninstall.sh (to be evaluated with FP_HOME and REG_HOME set).
func uninstallFuncs(t *testing.T, names ...string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(repoRoot(t), "uninstall.sh"))
	must(t, err)
	var out strings.Builder
	for _, n := range names {
		m := regexp.MustCompile(`(?ms)^` + regexp.QuoteMeta(n) + `\(\) \{\n.*?^\}\n`).FindString(string(b))
		if m == "" {
			t.Fatalf("uninstall.sh has no function %s", n)
		}
		out.WriteString(m)
	}
	return out.String()
}

// The fallback matches the service file's exact --home argument (like the
// Go ownership checks), never a sibling installation whose path starts with
// HOME.
func TestUninstallFallbackMatchesExactHome(t *testing.T) {
	needSh(t)
	repo := repoRoot(t)
	funcs := uninstallFuncs(t, "unit_is_ours", "plist_is_ours")
	fixture := func(name, from, to string) string {
		b, err := os.ReadFile(filepath.Join(repo, "internal", "svc", "testdata", name))
		must(t, err)
		p := filepath.Join(t.TempDir(), name)
		must(t, os.WriteFile(p, []byte(strings.ReplaceAll(string(b), from, to)), 0o644))
		return p
	}
	sysUnit := fixture("systemd-system.service", "", "")
	sysUnitNew := fixture("systemd-system.service", "/opt/fileparcel", "/opt/fileparcel-new")
	special := fixture("systemd-user-special.service", "", "")
	plist := fixture("launchd-daemon.plist", "", "")
	plistNew := fixture("launchd-daemon.plist", "/usr/local/fileparcel", "/usr/local/fileparcel2")
	for _, c := range []struct {
		fn, file, home, reg string
		want                bool
	}{
		{"unit_is_ours", sysUnit, "/opt/fileparcel", "", true},
		{"unit_is_ours", sysUnitNew, "/opt/fileparcel", "", false},
		{"unit_is_ours", sysUnitNew, "/opt/fileparcel-new", "", true},
		{"unit_is_ours", sysUnit, "/var/opt/fileparcel", "/opt/fileparcel", true}, // physical HOME, recorded spelling
		{"unit_is_ours", sysUnit, "/var/opt/fileparcel", "", false},
		{"unit_is_ours", special, `/home/a b/100%$x"q`, "", true},
		{"unit_is_ours", special, `/home/a b/100`, "", false},
		{"unit_is_ours", filepath.Join(t.TempDir(), "missing"), "/opt/fileparcel", "", false},
		{"plist_is_ours", plist, "/usr/local/fileparcel", "", true},
		{"plist_is_ours", plistNew, "/usr/local/fileparcel", "", false},
		{"plist_is_ours", plistNew, "/usr/local/fileparcel2", "", true},
	} {
		reg := c.reg
		if reg == "" {
			reg = c.home
		}
		_, errOut, code := run(t, t.TempDir(), []string{"PATH=" + sysPath, "FP_HOME=" + c.home, "REG_HOME=" + reg},
			"-c", funcs+`FP_HOME=$FP_HOME REG_HOME=$REG_HOME; `+c.fn+` "$1"`, "sh", c.file)
		if got := code == 0; got != c.want {
			t.Errorf("%s %s with HOME %q (recorded %q) = %v (stderr %q), want %v", c.fn, filepath.Base(c.file), c.home, c.reg, got,
				errOut, c.want)
		}
	}
}

// uninstallEnv is a scratch user: HOME, XDG dirs and a stub systemctl that
// records its arguments, first on PATH.
type uninstallEnv struct {
	root, home, config, calls string
	env                       []string
}

func newUninstallEnv(t *testing.T) *uninstallEnv {
	t.Helper()
	root, err := filepath.EvalSymlinks(t.TempDir())
	must(t, err)
	u := &uninstallEnv{root: root, home: filepath.Join(root, "home"), config: filepath.Join(root, "config"),
		calls: filepath.Join(root, "calls")}
	stubs := filepath.Join(root, "stubs")
	write(t, filepath.Join(stubs, "systemctl"), "#!/bin/sh\nprintf 'systemctl %s\\n' \"$*\" >>'"+u.calls+"'\nexit 0\n", 0o755)
	must(t, os.MkdirAll(u.home, 0o755))
	u.env = []string{"HOME=" + u.home, "XDG_CONFIG_HOME=" + u.config, "XDG_RUNTIME_DIR=" + root, "PATH=" + stubs + ":" + sysPath}
	return u
}

// install creates an installation at dir without a working binary (so
// uninstall.sh uses its fallback), recording home as recorded.
func (u *uninstallEnv) install(t *testing.T, dir, recorded string) {
	t.Helper()
	write(t, filepath.Join(dir, "fileparcel.toml"), "", 0o600)
	must(t, os.MkdirAll(filepath.Join(dir, "data"), 0o700))
	write(t, filepath.Join(dir, "service", "installed.json"),
		`{"kind":"systemd-user","home":"`+recorded+`","symlink":"`+filepath.Join(u.home, ".local", "bin", "fileparcel")+`","version":"v1"}`+"\n", 0o640)
}

func (u *uninstallEnv) userUnit() string {
	return filepath.Join(u.config, "systemd", "user", "fileparcel.service")
}

func linuxNonRoot(t *testing.T) {
	t.Helper()
	needSh(t)
	if runtime.GOOS != "linux" {
		t.Skip("the fallback's systemd branch runs on Linux")
	}
	if os.Geteuid() == 0 {
		t.Skip("as root the fallback manages the real system unit")
	}
}

// A home installed as <root>/opt/fp, with opt a symlink to var/opt: the
// fallback gets the physical path but recognises the unit and the command
// link that name the recorded one.
func TestUninstallFallbackSymlinkedHome(t *testing.T) {
	linuxNonRoot(t)
	u := newUninstallEnv(t)
	must(t, os.MkdirAll(filepath.Join(u.root, "var", "opt"), 0o755))
	must(t, os.Symlink(filepath.Join("var", "opt"), filepath.Join(u.root, "opt")))
	logical := filepath.Join(u.root, "opt", "fp")
	u.install(t, filepath.Join(u.root, "var", "opt", "fp"), logical)
	// `systemctl --user link` registration and the command link, both
	// naming the logical path.
	must(t, os.MkdirAll(filepath.Dir(u.userUnit()), 0o755))
	must(t, os.Symlink(filepath.Join(logical, "service", "fileparcel.service"), u.userUnit()))
	link := filepath.Join(u.home, ".local", "bin", "fileparcel")
	must(t, os.MkdirAll(filepath.Dir(link), 0o755))
	must(t, os.Symlink(filepath.Join(logical, "bin", "fileparcel"), link))

	_, errOut, code := run(t, u.root, u.env, filepath.Join(repoRoot(t), "uninstall.sh"), "--dir", logical, "-y")
	if code != 0 {
		t.Fatalf("exit %d: %s", code, errOut)
	}
	calls, _ := os.ReadFile(u.calls)
	for _, want := range []string{"systemctl --user stop fileparcel.service", "systemctl --user disable fileparcel.service"} {
		if !strings.Contains(string(calls), want) {
			t.Errorf("missing %q in\n%s\nstderr: %s", want, calls, errOut)
		}
	}
	for _, p := range []string{u.userUnit(), link} {
		if _, err := os.Lstat(p); !os.IsNotExist(err) {
			t.Errorf("%s not removed (stderr: %s)", p, errOut)
		}
	}
}

// Another installation whose path starts with this one's keeps its service.
func TestUninstallFallbackLeavesSiblingService(t *testing.T) {
	linuxNonRoot(t)
	u := newUninstallEnv(t)
	dir := filepath.Join(u.root, "fileparcel")
	u.install(t, dir, dir)
	write(t, u.userUnit(), "[Unit]\nDescription=FileParcel file sharing server\n[Service]\nExecStart=\""+dir+
		"-new/bin/fileparcel\" serve --home \""+dir+"-new\"\n", 0o644)
	_, errOut, code := run(t, u.root, u.env, filepath.Join(repoRoot(t), "uninstall.sh"), "--dir", dir, "-y")
	if code != 0 {
		t.Fatalf("exit %d: %s", code, errOut)
	}
	if calls, _ := os.ReadFile(u.calls); strings.Contains(string(calls), "stop") || strings.Contains(string(calls), "disable") {
		t.Errorf("the sibling's service was stopped:\n%s", calls)
	}
	if _, err := os.Stat(u.userUnit()); err != nil {
		t.Errorf("the sibling's unit was removed: %v", err)
	}
}

// Discovery finds the installer's $XDG_DATA_HOME default and stops (never
// picks one) when several installations are found.
func TestUninstallDiscovery(t *testing.T) {
	needSh(t)
	if runtime.GOOS != "linux" {
		t.Skip("the $XDG_DATA_HOME default is Linux's")
	}
	if os.Geteuid() == 0 {
		t.Skip("root's defaults are system directories")
	}
	// uninstall.sh also looks at these system paths: a real installation
	// there would be found as well.
	for _, p := range []string{"/usr/local/bin/fileparcel", "/usr/bin/fileparcel", "/bin/fileparcel", "/opt/fileparcel", "/usr/local/fileparcel"} {
		if _, err := os.Lstat(p); err == nil {
			t.Skipf("%s exists on this machine", p)
		}
	}
	repo := repoRoot(t)
	mk := func(dir, log string) {
		write(t, filepath.Join(dir, "fileparcel.toml"), "", 0o600)
		must(t, os.MkdirAll(filepath.Join(dir, "data"), 0o700))
		// A stub binary: "version" works, "uninstall" records its arguments.
		write(t, filepath.Join(dir, "bin", "fileparcel"), "#!/bin/sh\n[ \"$1\" = version ] && exit 0\nprintf '%s\\n' \"$*\" >'"+log+"'\n", 0o755)
	}
	for _, c := range []struct {
		name     string
		xdg      string // XDG_DATA_HOME relative to the root ("" = unset)
		fpHome   string // FILEPARCEL_HOME relative to the root
		wantHome string // the home the binary gets, relative to the root ("" = none)
		wantErr  string
	}{
		{"XDG default", "/xdg", "", "xdg/fileparcel", ""},
		{"FILEPARCEL_HOME is the same installation", "/xdg", "xdg/fileparcel", "xdg/fileparcel", ""},
		{"two installations", "/xdg", "other", "", "More than one FileParcel installation"},
		{"relative XDG_DATA_HOME is ignored", "xdg", "", "", "no FileParcel installation found"},
	} {
		t.Run(c.name, func(t *testing.T) {
			root, err := filepath.EvalSymlinks(t.TempDir())
			must(t, err)
			log := filepath.Join(root, "exec.log")
			mk(filepath.Join(root, "xdg", "fileparcel"), log)
			mk(filepath.Join(root, "other"), log)
			must(t, os.MkdirAll(filepath.Join(root, "home"), 0o755))
			env := []string{"HOME=" + filepath.Join(root, "home"), "PATH=" + sysPath}
			switch {
			case strings.HasPrefix(c.xdg, "/"):
				env = append(env, "XDG_DATA_HOME="+root+c.xdg)
			case c.xdg != "":
				env = append(env, "XDG_DATA_HOME="+c.xdg)
			}
			if c.fpHome != "" {
				env = append(env, "FILEPARCEL_HOME="+filepath.Join(root, c.fpHome))
			}
			_, errOut, code := run(t, root, env, filepath.Join(repo, "uninstall.sh"), "--dry-run")
			got, _ := os.ReadFile(log)
			if c.wantHome == "" {
				if code == 0 || !strings.Contains(errOut, c.wantErr) || len(got) != 0 {
					t.Fatalf("exit %d, stderr %q, binary ran with %q; want %q", code, errOut, got, c.wantErr)
				}
				return
			}
			if want := "uninstall --home " + filepath.Join(root, c.wantHome) + " --dry-run\n"; code != 0 || string(got) != want {
				t.Fatalf("exit %d, stderr %q, binary ran with %q, want %q", code, errOut, got, want)
			}
		})
	}
}

// ---------- secrets never committed or packaged ----------

// The Docker quick start creates the container's home and the admin
// password next to docker-compose.yml, in the repository root: both must be
// ignored by git (and so never reach a release's src/), as they are by
// .dockerignore.
func TestGitignoreCoversSecrets(t *testing.T) {
	repo := repoRoot(t)
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("no git")
	}
	if _, err := os.Stat(filepath.Join(repo, ".git")); err != nil {
		t.Skip("not a git checkout (release src/)")
	}
	for _, p := range []string{"fileparcel-data/keys/master.key", "fileparcel-data/fileparcel.toml",
		"secrets/fp_admin_password.txt", "server/fileparcel.toml", "server/keys/master.key"} {
		cmd := exec.Command("git", "check-ignore", "-q", "--no-index", p)
		cmd.Dir = repo
		if err := cmd.Run(); err != nil {
			t.Errorf("%s is not ignored by .gitignore (git check-ignore: %v)", p, err)
		}
	}
	for _, p := range []string{"internal/cli/secretowner_unix.go", "internal/keys/keys.go"} {
		cmd := exec.Command("git", "check-ignore", "-q", "--no-index", p)
		cmd.Dir = repo
		if err := cmd.Run(); err == nil {
			t.Errorf("%s is ignored by .gitignore", p)
		}
	}
}

// release.sh refuses a commit that contains a home or a secret.
func TestReleaseRefusesCommittedSecrets(t *testing.T) {
	repo := repoRoot(t)
	b, err := os.ReadFile(filepath.Join(repo, "scripts", "release.sh"))
	must(t, err)
	m := regexp.MustCompile(`grep -E '(\^\(server\|[^']*)'`).FindStringSubmatch(string(b))
	if m == nil {
		t.Fatal("release.sh: the committed-secrets check is missing")
	}
	re := regexp.MustCompile(m[1])
	for p, want := range map[string]bool{
		"secrets/fp_admin_password.txt":    true,
		"fileparcel-data/keys/master.key":  true,
		"server/fileparcel.toml":           true,
		"fileparcel.toml":                  true,
		"tmp/dev-home/keys/master.key":     true,
		"internal/keys/keys.go":            false,
		"internal/cli/secretowner_unix.go": false,
		"docs/fileparcel.toml.example":     false,
	} {
		if re.MatchString(p) != want {
			t.Errorf("release.sh secrets check on %s = %v, want %v", p, !want, want)
		}
	}
	// The tree as committed today must be releasable.
	if _, err := exec.LookPath("git"); err == nil {
		cmd := exec.Command("git", "ls-files")
		cmd.Dir = repo
		if out, err := cmd.Output(); err == nil {
			for _, f := range strings.Split(strings.TrimSpace(string(out)), "\n") {
				if re.MatchString(f) {
					t.Errorf("tracked file %s would stop every release", f)
				}
			}
		}
	}
}

// ---------- release layout: Docker ----------

// The release zip ships docker-compose.yml at its top level, but the
// source (go.mod, Dockerfile, .dockerignore) only in src/: release.sh must
// point the build context there and not ship a Dockerfile that cannot
// build at the top.
func TestReleaseComposeBuildsFromSrc(t *testing.T) {
	needSh(t)
	repo := repoRoot(t)
	b, err := os.ReadFile(filepath.Join(repo, "scripts", "release.sh"))
	must(t, err)
	rel := string(b)
	loop := regexp.MustCompile(`(?m)^for f in (README\.md[^;]*); do$`).FindStringSubmatch(rel)
	if loop == nil {
		t.Fatal("release.sh: top-level file loop not found")
	}
	if strings.Contains(loop[1], "Dockerfile") || !strings.Contains(loop[1], "docker-compose.yml") {
		t.Errorf("release.sh copies %q to the top level: want docker-compose.yml without Dockerfile", loop[1])
	}
	// Run release.sh's own rewrite on a copy of docker-compose.yml.
	block := regexp.MustCompile(`(?ms)^if \[ -f "\$STAGE/docker-compose\.yml" \]; then\n.*?^fi\n`).FindString(rel)
	if block == "" {
		t.Fatal("release.sh: the docker-compose.yml rewrite is missing")
	}
	stage := t.TempDir()
	compose, err := os.ReadFile(filepath.Join(repo, "docker-compose.yml"))
	must(t, err)
	must(t, os.WriteFile(filepath.Join(stage, "docker-compose.yml"), compose, 0o644))
	script := "fail() { echo \"FAIL: $*\" >&2; exit 1; }\nSTAGE=$1 V=v42 SHA12=0123456789ab\n" + block
	_, errOut, code := run(t, stage, []string{"PATH=" + sysPath}, "-c", script, "sh", stage)
	if code != 0 {
		t.Fatalf("rewrite failed (exit %d): %s", code, errOut)
	}
	got, err := os.ReadFile(filepath.Join(stage, "docker-compose.yml"))
	must(t, err)
	ctx := regexp.MustCompile(`(?m)^      context: (.*)$`).FindAllStringSubmatch(string(got), -1)
	if len(ctx) != 1 || ctx[0][1] != "src" {
		t.Fatalf("build context after the rewrite: %q", ctx)
	}
	if !strings.Contains(string(got), "${FILEPARCEL_VERSION:-v42}") || !strings.Contains(string(got), "${FILEPARCEL_COMMIT:-0123456789ab}") {
		t.Errorf("version defaults not rewritten:\n%s", got)
	}
	// src/ is the committed tree: everything the Dockerfile needs is there.
	for _, f := range []string{"go.mod", "go.sum", "Dockerfile", ".dockerignore", "cmd/fileparcel"} {
		if _, err := os.Stat(filepath.Join(repo, f)); err != nil {
			t.Errorf("the build context (src/) lacks %s", f)
		}
	}
	// The repository's own compose file keeps building from its directory.
	if !regexp.MustCompile(`(?m)^      context: \.$`).Match(compose) {
		t.Error("docker-compose.yml: the build context is not \".\"")
	}
}
