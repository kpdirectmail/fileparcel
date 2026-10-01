package docs_test

// Prose checks for the manual, the design document and the security notes:
// statements that once contradicted the code are pinned here, derived from
// the code (or from the UI source) wherever that is possible, so the next
// change to either side has to update both.

import (
	"go/build"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"

	"fileparcel/internal/cli"
	"fileparcel/internal/web/settingsapi"
)

// manualProse is docs/FILEPARCEL.md without the generated settings reference
// (checked by its generator). The generated command reference lives in
// docs/COMMANDS.md (TestCLIReferenceUpToDate).
func manualProse(t *testing.T) string {
	t.Helper()
	man := read(t, "docs/FILEPARCEL.md")
	for _, m := range [][2]string{
		{"<!-- BEGIN GENERATED SETTINGS REFERENCE -->", "<!-- END GENERATED SETTINGS REFERENCE -->"},
	} {
		before, rest, ok := strings.Cut(man, m[0])
		if !ok {
			t.Fatalf("docs/FILEPARCEL.md has no %s marker", m[0])
		}
		_, after, ok := strings.Cut(rest, m[1])
		if !ok {
			t.Fatalf("docs/FILEPARCEL.md has no %s marker", m[1])
		}
		man = before + after
	}
	return man
}

// generatedSettings is the generated settings reference of docs/FILEPARCEL.md
// (kept equal to the program's catalog by scripts/gen-settings-docs.sh --check).
func generatedSettings(t *testing.T) string {
	t.Helper()
	man := read(t, "docs/FILEPARCEL.md")
	_, rest, ok := strings.Cut(man, "<!-- BEGIN GENERATED SETTINGS REFERENCE -->")
	if !ok {
		t.Fatal("docs/FILEPARCEL.md has no generated settings reference")
	}
	ref, _, ok := strings.Cut(rest, "<!-- END GENERATED SETTINGS REFERENCE -->")
	if !ok {
		t.Fatal("docs/FILEPARCEL.md: the generated settings reference is not closed")
	}
	return ref
}

// section returns the text of the markdown section that starts with the
// heading line head, up to the next heading of the same or a higher level
// (lines inside fenced code blocks are not headings).
func section(t *testing.T, doc, head string) string {
	t.Helper()
	level := len(head) - len(strings.TrimLeft(head, "#"))
	lines := strings.Split(doc, "\n")
	start := slices.Index(lines, head)
	if start < 0 {
		t.Fatalf("heading %q not found", head)
	}
	fenced := false
	for i := start + 1; i < len(lines); i++ {
		l := lines[i]
		if strings.HasPrefix(l, "```") {
			fenced = !fenced
			continue
		}
		if n := len(l) - len(strings.TrimLeft(l, "#")); !fenced && n > 0 && n <= level && strings.HasPrefix(l[n:], " ") {
			return strings.Join(lines[start+1:i], "\n")
		}
	}
	return strings.Join(lines[start+1:], "\n")
}

// oneLine collapses all whitespace (line breaks of wrapped prose) to single
// spaces.
func oneLine(s string) string { return strings.Join(strings.Fields(s), " ") }

// settingsSections parses the SECTIONS table of the admin settings page:
// section id → label shown in Admin → Settings.
func settingsSections(t *testing.T) (ids []string, labels map[string]string) {
	t.Helper()
	js := read(t, "web/static/js/pages/admin/settings.js")
	m := regexp.MustCompile(`\['([a-z_]+)', '([^']+)', '[^']+'\]`).FindAllStringSubmatch(js, -1)
	if len(m) < 10 {
		t.Fatalf("could not parse SECTIONS from web/static/js/pages/admin/settings.js (%d entries)", len(m))
	}
	labels = map[string]string{}
	for _, e := range m {
		ids = append(ids, e[1])
		labels[e[1]] = e[2]
	}
	return ids, labels
}

// TestNameConflictReplaceOnMove: moving with "replace" trashes the existing
// file (internal/files/tree.go moveOne → trashOne); only uploads and copies
// add a version. The manual must not promise the old content under Versions
// for a move.
func TestNameConflictReplaceOnMove(t *testing.T) {
	tree := read(t, "internal/files/tree.go")
	if !strings.Contains(tree, "o.trashOne(old)") {
		t.Skip("internal/files/tree.go no longer trashes the replaced file on a move; re-check the Name conflicts bullet")
	}
	prose := oneLine(manualProse(t))
	mustNotContain(t, "docs/FILEPARCEL.md", prose,
		"*replace* makes the new file the current version of the existing one",
		"a move with replace trashes the existing file; only uploads and copies add a version.")
	mustContain(t, "docs/FILEPARCEL.md", prose,
		"when moving, it moves the existing file to the trash",
		"the Name conflicts bullet must say what replace does for a move.")
}

// TestDocsMatchCode pins single statements that contradicted the code.
func TestDocsMatchCode(t *testing.T) {
	prose := oneLine(manualProse(t))
	design := oneLine(read(t, "docs/DESIGN.md"))
	security := oneLine(read(t, "docs/SECURITY.md"))
	readme := oneLine(read(t, "README.md"))

	// File-request uploads land in the request folder (uploads: conflict=rename);
	// the uploader name goes to the access log, the audit log and the e-mail.
	mustNotContain(t, "docs/FILEPARCEL.md", prose, "the upload's folder",
		"no per-uploader folder exists; the name is recorded in the access and audit logs.")

	// shares.CookieName / sharesapi.visitorCookieName use the last 8 characters.
	mustNotContain(t, "docs/DESIGN.md", design, "first 8 of share id",
		"the share cookies are named after the last 8 characters of the share id (the random part).")
	mustContain(t, "docs/DESIGN.md", design, "`__Host-fp_s_<last 8 characters of share id>`",
		"DESIGN §9.4 names the share access cookie.")
	mustContain(t, "docs/DESIGN.md", design, "`__Host-fp_uv_<last 8 characters of share id>`",
		"DESIGN §9.4 names the file-request visitor cookie.")

	// A Headscale name is covered only if it existed when the CA was created.
	mustNotContain(t, "docs/FILEPARCEL.md", prose, "the local CA covers the MagicDNS names.",
		"certs.caConstraints only adds the Network.Hostnames() present at CA creation.")
	mustNotContain(t, "docs/DESIGN.md", design, "local CA covers MagicDNS names.",
		"certs.caConstraints only adds the Network.Hostnames() present at CA creation.")

	// <HOME>/service holds installed.json and only the systemd user unit.
	mustNotContain(t, "docs/FILEPARCEL.md", prose, "the systemd unit or launchd plist, installed.json",
		"system units and launchd plists are written outside <HOME> (internal/svc).")
	mustNotContain(t, "docs/DESIGN.md", design, "fileparcel.service | com.fileparcel.server.plist",
		"system units and launchd plists are written outside <HOME> (internal/svc).")

	// config.SaveTo keeps only the leading comment block.
	mustNotContain(t, "docs/FILEPARCEL.md", prose, "keeping its comments",
		"a settings change rewrites fileparcel.toml and keeps only the comment block at the top.")

	// A restart request re-execs unless FILEPARCEL_SUPERVISED=1 (server.Supervised).
	// The operating system notes live in the installation guide.
	install := read(t, "docs/INSTALL.md")
	alpine := oneLine(section(t, install, "### Install on Alpine or another system without systemd"))
	mustContain(t, "docs/INSTALL.md (Alpine section)", alpine, "FILEPARCEL_SUPERVISED=1",
		"under OpenRC/runit/s6 a restart re-execs in place unless FILEPARCEL_SUPERVISED=1 is set.")
	for name, doc := range map[string]string{"docs/FILEPARCEL.md": prose, "docs/INSTALL.md": oneLine(install)} {
		mustNotContain(t, name, doc, "exits with code 75 when it wants to be restarted",
			"exit code 75 needs a detected supervisor (server.Supervised).")
	}

	// The system unit gets CAP_NET_BIND_SERVICE only when it is rendered.
	mustContain(t, "docs/FILEPARCEL.md", prose, "apply the change with `sudo fileparcel service install --start`",
		"moving a system install to or from a port below 1024 needs the unit re-rendered, not just a restart.")

	// FAQ: quote the message internal/cli/client.go prints.
	const lockMsg = "is locked by another process but its admin socket is not answering"
	if !strings.Contains(read(t, "internal/cli/client.go"), lockMsg) {
		t.Errorf("internal/cli/client.go no longer prints %q; update the FAQ heading in docs/FILEPARCEL.md", lockMsg)
	}
	mustContain(t, "docs/FILEPARCEL.md", prose, lockMsg, "the FAQ quotes the CLI's lock message.")
	mustNotContain(t, "docs/FILEPARCEL.md", prose, "database is locked by another process",
		"no FileParcel message says that.")

	// iOS: the /trust page's button (web/static/js/public/trust.js). The per-device
	// trust steps live in the installation guide.
	trust := read(t, "web/static/js/public/trust.js")
	iosSteps := oneLine(section(t, install, "### Trust it on an iPhone or iPad"))
	if m := regexp.MustCompile(`fileLabel: '([^']+)',\s*steps: \[\s*'Open this page in Safari`).FindStringSubmatch(trust); m != nil {
		mustContain(t, "docs/INSTALL.md (iPhone and iPad)", iosSteps, "tap **"+m[1]+"**", "the iOS steps name the /trust page's button.")
	} else {
		t.Error("could not find the iOS button label in web/static/js/public/trust.js")
	}
	for name, doc := range map[string]string{"docs/FILEPARCEL.md": prose, "docs/INSTALL.md": oneLine(install)} {
		mustNotContain(t, name, doc, "Install profile for iOS", "no such button exists.")
	}

	// A LaunchAgent starts at login, not at boot.
	mustNotContain(t, "README.md", readme, "a launchd agent and starts at boot",
		"LaunchAgents run only after login; boot-time start needs the LaunchDaemon.")

	// The icon generator was never committed.
	for _, doc := range []string{"docs/DESIGN.md", "docs/DEVELOPMENT.md"} {
		mustNotContain(t, doc, read(t, doc), "icongen", "there is no tools/icongen; the icons are committed files.")
	}

	// Leaf validity: the documented bound is the registered maximum.
	leafMax := regexp.MustCompile("\\| `tls\\.leaf_days` \\|[^\n]*Range 7–([0-9]+)\\.").FindStringSubmatch(generatedSettings(t))
	if leafMax == nil {
		t.Fatal("tls.leaf_days has no range in the generated settings reference")
	}
	mustContain(t, "docs/SECURITY.md", security, "at most "+leafMax[1],
		"tls.leaf_days accepts up to its registered maximum.")
	mustNotContain(t, "docs/SECURITY.md", security, "≤ 397 days", "397 is only the default of tls.leaf_days.")
}

// TestAdminPagesExist: every "Admin → X" in the manual, the installation and
// command guides, the README and the security notes names an item of the
// admin navigation (web/static/js/nav.js), and every "Admin → Settings → X" a
// section of the settings page.
func TestAdminPagesExist(t *testing.T) {
	nav := read(t, "web/static/js/nav.js")
	var pages []string
	for _, m := range regexp.MustCompile(`\{ id: 'admin[a-z-]*', label: '([^']+)'`).FindAllStringSubmatch(nav, -1) {
		pages = append(pages, m[1])
	}
	if !slices.Contains(pages, "Settings") || !slices.Contains(pages, "Dashboard") {
		t.Fatalf("could not parse the admin navigation from web/static/js/nav.js (got %q)", pages)
	}
	_, labels := settingsSections(t)
	for _, doc := range []string{"docs/FILEPARCEL.md", "docs/INSTALL.md", "docs/COMMANDS.md", "README.md", "docs/SECURITY.md"} {
		text := oneLine(read(t, doc))
		for _, part := range strings.Split(text, "Admin → ")[1:] {
			ok := false
			for _, p := range pages {
				if strings.HasPrefix(part, p) {
					ok = true
					break
				}
			}
			if !ok {
				t.Errorf("%s refers to \"Admin → %.40s…\", which is not an admin page (%q)", doc, part, pages)
				continue
			}
			if sub, isSettings := strings.CutPrefix(part, "Settings → "); isSettings && !strings.HasPrefix(sub, "*") {
				found := false
				for _, l := range labels {
					if strings.HasPrefix(sub, l) {
						found = true
					}
				}
				if !found {
					t.Errorf("%s refers to \"Admin → Settings → %.40s…\", which is not a settings section", doc, sub)
				}
			}
		}
	}
}

// TestSettingsSectionsDocumented: the manual's section table and the headings
// of the generated settings reference use the labels of Admin → Settings,
// and the step-up paragraph lists exactly settingsapi.SensitiveSections.
func TestSettingsSectionsDocumented(t *testing.T) {
	ids, labels := settingsSections(t)
	man := read(t, "docs/FILEPARCEL.md")

	table := section(t, man, "### The admin settings pages")
	var rows []string
	for _, m := range regexp.MustCompile(`(?m)^\| ([^|]+?) \| [^|]+ \|$`).FindAllStringSubmatch(table, -1) {
		if m[1] != "Section" {
			rows = append(rows, m[1])
		}
	}
	for _, id := range ids {
		if !slices.Contains(rows, labels[id]) {
			t.Errorf("the admin settings table in docs/FILEPARCEL.md has no row %q (section %s)", labels[id], id)
		}
	}
	for _, r := range rows {
		found := false
		for _, l := range labels {
			found = found || r == l
		}
		if !found {
			t.Errorf("the admin settings table in docs/FILEPARCEL.md has a row %q, which is not a section of Admin → Settings", r)
		}
	}

	ref := generatedSettings(t)
	for _, id := range ids {
		h := "\n#### " + labels[id]
		if !strings.Contains(ref, h+"\n") && !strings.Contains(ref, h+" (") {
			t.Errorf("the generated settings reference has no heading %q (section %s); "+
				"align TITLES in scripts/gen-settings-docs.sh with web/static/js/pages/admin/settings.js", labels[id], id)
		}
	}

	stepUp := oneLine(section(t, man, "### Confirming your identity (step-up)"))
	_, list, ok := strings.Cut(stepUp, "changing settings in the ")
	if list, _, ok2 := strings.Cut(list, " sections"); ok && ok2 {
		var got []string
		for _, w := range regexp.MustCompile(`[a-z]+`).FindAllString(list, -1) {
			if w != "and" && w != "the" {
				got = append(got, w)
			}
		}
		want := slices.Clone(settingsapi.SensitiveSections)
		slices.Sort(got)
		slices.Sort(want)
		if !slices.Equal(got, want) {
			t.Errorf("the step-up paragraph of docs/FILEPARCEL.md lists sections %q; settingsapi.SensitiveSections is %q", got, want)
		}
	} else {
		t.Error("the step-up paragraph of docs/FILEPARCEL.md no longer lists the settings sections")
	}
}

// TestBootstrapKeysDocumented: every fileparcel.toml key the manual lists is
// either a runtime setting too (editable with config set and in the web app)
// or marked as editable with "config edit" only.
func TestBootstrapKeysDocumented(t *testing.T) {
	man := read(t, "docs/FILEPARCEL.md")
	ref := generatedSettings(t)
	table := section(t, man, "### fileparcel.toml")
	rows := regexp.MustCompile("(?m)^\\| `([a-z_.]+)` \\|[^\n]*\\|$").FindAllStringSubmatch(table, -1)
	if len(rows) < 10 {
		t.Fatalf("could not parse the fileparcel.toml table (%d rows)", len(rows))
	}
	for _, r := range rows {
		key, line := r[1], r[0]
		if key == "install_id" {
			continue
		}
		catalog := strings.Contains(ref, "| `"+key+"` |")
		editOnly := strings.Contains(line, "*`config edit` only.*")
		switch {
		case catalog && editOnly:
			t.Errorf("fileparcel.toml table: %s is a runtime setting but marked `config edit` only", key)
		case !catalog && !editOnly:
			t.Errorf("fileparcel.toml table: %s is not in the settings catalog (config set rejects it); mark it `config edit` only", key)
		}
	}
	// Every key the prose tells people to "config set" exists.
	prose := manualProse(t)
	for _, m := range regexp.MustCompile(`config set ([a-z0-9_]+\.[a-z0-9_.]+)`).FindAllStringSubmatch(prose, -1) {
		if !strings.Contains(ref, "| `"+m[1]+"` |") {
			t.Errorf("docs/FILEPARCEL.md says \"config set %s\", which is not a registered setting", m[1])
		}
	}
}

// TestServiceImportRules: the service packages import only what DESIGN §2
// and docs/DEVELOPMENT.md §4 allow (including their listed exceptions).
func TestServiceImportRules(t *testing.T) {
	root := repoRoot(t)
	base := []string{"core", "db", "crypt", "ids", "events", "settings", "config", "home", "buildinfo", "logx",
		"qr", "names", "jobs/cron", "tslocal"}
	exceptions := map[string][]string{
		"uploads": {"ziputil"},
		"files":   {"ziputil", "thumbs"},
		"auth":    {"ratelimit"},
		"shares":  {"ratelimit"},
		"backup":  {"keys", "blobstore"},
	}
	services := strings.Fields("keys blobstore audit auth users files ziputil thumbs uploads shares backup jobs certs netinfo tsingress mdns qr settings ratelimit notify")
	for _, svc := range services {
		pkg, err := build.Default.ImportDir(filepath.Join(root, "internal", filepath.FromSlash(svc)), 0)
		if err != nil {
			t.Fatalf("%s: %v", svc, err)
		}
		for _, imp := range pkg.Imports {
			rel, ok := strings.CutPrefix(imp, "fileparcel/internal/")
			if !ok || rel == svc || slices.Contains(base, rel) || slices.Contains(exceptions[svc], rel) {
				continue
			}
			t.Errorf("internal/%s imports %s, which DESIGN §2 / docs/DEVELOPMENT.md §4 do not allow; "+
				"use a core interface or document the exception", svc, imp)
		}
	}
	mustContain(t, "docs/DEVELOPMENT.md", oneLine(read(t, "docs/DEVELOPMENT.md")), "`backup` → `keys`",
		"the backup deep-verify exception is documented.")
	mustContain(t, "docs/DESIGN.md", oneLine(read(t, "docs/DESIGN.md")), "`backup` may import `keys`",
		"the backup deep-verify exception is documented.")
}

// TestUninstallBackupToRule: the uninstaller refuses only --final-backup
// combined with --purge without --backup-to (the backup would stay in
// <HOME>/backups and be deleted with the home); --purge alone makes no
// backup and is not refused. The help of uninstall.sh and of "fileparcel
// uninstall", the installation guide, the manual and DESIGN §14.6 must not
// claim that --purge needs --backup-to.
func TestUninstallBackupToRule(t *testing.T) {
	if !strings.Contains(read(t, "internal/svc/installer/uninstall.go"), `o.Purge && o.FinalBackup && o.BackupTo == ""`) {
		t.Skip("internal/svc/installer/uninstall.go no longer has the --final-backup/--purge rule; re-check the uninstall help texts")
	}
	wrong := regexp.MustCompile("(?i)required with `?--purge")
	root := cli.NewRootCmd()
	un, _, err := root.Find([]string{"uninstall"})
	if err != nil || un.Name() != "uninstall" {
		t.Fatalf("no uninstall command: %v", err)
	}
	flag := un.Flags().Lookup("backup-to")
	if flag == nil {
		t.Fatal("uninstall has no --backup-to flag")
	}
	for name, doc := range map[string]string{
		"uninstall.sh":                     read(t, "uninstall.sh"),
		"fileparcel uninstall --help":      un.Long,
		"fileparcel uninstall --backup-to": flag.Usage,
		"docs/FILEPARCEL.md":               read(t, "docs/FILEPARCEL.md"),
		"docs/INSTALL.md":                  read(t, "docs/INSTALL.md"),
		"docs/COMMANDS.md":                 read(t, "docs/COMMANDS.md"),
		"docs/DESIGN.md":                   read(t, "docs/DESIGN.md"),
		"README.md":                        read(t, "README.md"),
	} {
		if m := wrong.FindString(oneLine(doc)); m != "" {
			t.Errorf("%s says %q, but --purge alone needs no backup: only --final-backup with --purge needs --backup-to", name, m)
		}
	}
	mustContain(t, "uninstall.sh", oneLine(read(t, "uninstall.sh")),
		"Required when --final-backup is combined with --purge", "the usage states the actual rule.")
	mustContain(t, "fileparcel uninstall --backup-to", flag.Usage,
		"needed when --final-backup is combined with --purge", "the flag help states the actual rule.")
	mustContain(t, "fileparcel uninstall --help", oneLine(un.Long),
		"--final-backup together with --purge needs --backup-to", "the long help states the actual rule.")
	// The uninstall options table lives in the installation guide.
	mustContain(t, "docs/INSTALL.md (All uninstall options)", oneLine(section(t, read(t, "docs/INSTALL.md"), "### All uninstall options")),
		"Required when `--final-backup` is combined with `--purge`", "the uninstall table states the actual rule.")
}
