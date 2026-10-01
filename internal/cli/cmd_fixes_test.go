package cli

// Regression tests for reported CLI defects: silently ignored input, success
// lines that hide a failure, and machine output that disagrees with the table
// next to it.

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"fileparcel/internal/core"
	"fileparcel/internal/db"
	"fileparcel/internal/ids"
	"fileparcel/internal/svc"
)

// "cert sans --add" used to print a plain success for a name the local CA's
// name constraints forbid: the setting was stored, the leaf never changed and
// nothing said so.
func TestCertSansReportsNamesTheCACannotIssue(t *testing.T) {
	f := newFakeAPI(t)
	store := addSettingsRoutes(f)
	f.handle("GET", "/api/v1/admin/certs", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, core.CertStatus{
			CAConstrained: true,
			PermittedDNS:  []string{".local", "localhost"},
			PermittedIPs:  []string{"192.168.1.0/24"},
			Leaf:          &core.CertInfo{Subject: "fileparcel", DNSNames: []string{"fileparcel.local"}},
		})
	})

	res := f.run(t, "", "cert", "sans", "--add", "nas.example.lan")
	if res.code != 0 || stored(store, "tls.extra_sans") == "" {
		t.Fatalf("the name must still be stored for \"ca regenerate\": %+v", res)
	}
	if !strings.Contains(res.stderr, "nas.example.lan") || !strings.Contains(res.stderr, "ca regenerate") {
		t.Fatalf("no warning about the forbidden name: stderr=%q", res.stderr)
	}

	// A permitted DNS name and a permitted IP address stay silent.
	for _, name := range []string{"files.local", "192.168.1.9"} {
		res := f.run(t, "", "cert", "sans", "--add", name)
		if res.code != 0 || strings.Contains(res.stderr, "ca regenerate") {
			t.Fatalf("%s must be accepted without a warning: %+v", name, res)
		}
	}
	// An unconstrained CA never warns.
	f2 := newFakeAPI(t)
	addSettingsRoutes(f2)
	f2.handle("GET", "/api/v1/admin/certs", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, core.CertStatus{Leaf: &core.CertInfo{Subject: "fileparcel"}})
	})
	if res := f2.run(t, "", "cert", "sans", "--add", "nas.example.lan"); res.code != 0 || strings.Contains(res.stderr, "ca regenerate") {
		t.Fatalf("unconstrained CA: %+v", res)
	}
}

func TestCAPermitsName(t *testing.T) {
	st := &core.CertStatus{CAConstrained: true, PermittedDNS: []string{".local", "localhost", "example.com"},
		PermittedIPs: []string{"192.168.1.0/24", "10.0.0.0/8"}}
	for _, c := range []struct {
		name string
		want bool
	}{
		{"files.local", true}, {"FILES.LOCAL.", true}, {"localhost", true}, {"nas.example.lan", false},
		{"example.com", true}, {"a.example.com", true}, {"notexample.com", false}, {".local", false},
		{"192.168.1.9", true}, {"10.1.2.3", true}, {"172.16.0.1", false}, {"::1", false},
	} {
		if got := caPermitsName(st, c.name); got != c.want {
			t.Errorf("caPermitsName(%q) = %v, want %v", c.name, got, c.want)
		}
	}
	// No constraints at all permits everything.
	if !caPermitsName(&core.CertStatus{}, "anything.example") || !caPermitsName(&core.CertStatus{}, "9.9.9.9") {
		t.Error("an unconstrained CA must permit every name")
	}
}

// A backup whose off-site copy failed is "ready" with an error recorded.
// "backup create --wait" used to print a bare success and exit 0, and
// "backup list" showed nothing at all.
func TestBackupCreateReportsRecordedError(t *testing.T) {
	f := newFakeAPI(t)
	bid := ids.New(ids.PrefixBackup)
	b := core.Backup{ID: bid, Scope: core.BackupMetadata, State: core.BackupReady, FileName: "fp.fpbak",
		Size: 4096, Trigger: core.TriggerManual, CreatedAt: time.Now(),
		Error: "copy to /nonexistent-mount/fp failed: no such file or directory"}
	jobID := f.addJob(core.JobBackupCreate, map[string]string{"backup_id": bid}, core.JobSucceeded)
	f.handle("POST", "/api/v1/admin/backups", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 202, core.JobRef{JobID: jobID})
	})
	f.handle("GET", "/api/v1/admin/backups/{id}", func(w http.ResponseWriter, r *http.Request) { writeJSON(w, 200, b) })
	f.handle("GET", "/api/v1/admin/backups", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, core.Page[core.Backup]{Items: []core.Backup{b}})
	})

	res := f.run(t, "", "backup", "create", "--scope", "metadata", "--wait")
	if res.code == 0 {
		t.Fatalf("a failed off-site copy must not exit 0: %+v", res)
	}
	if !strings.Contains(res.stderr, "nonexistent-mount") {
		t.Fatalf("the recorded error must be reported: stderr=%q", res.stderr)
	}
	if list := f.run(t, "", "backup", "list"); list.code != 0 || !strings.Contains(list.stdout, "ERROR") ||
		!strings.Contains(list.stdout, "nonexistent-mount") {
		t.Fatalf("backup list must show the error: %+v", list)
	}

	// A clean backup keeps exit 0 and the plain table.
	b.Error = ""
	ok := f.run(t, "", "backup", "create", "--scope", "metadata", "--wait")
	if ok.code != 0 || !strings.Contains(ok.stdout, bid) {
		t.Fatalf("clean backup: %+v", ok)
	}
	if list := f.run(t, "", "backup", "list"); list.code != 0 || strings.Contains(list.stdout, "ERROR") {
		t.Fatalf("clean backup list must not grow an ERROR column: %+v", list)
	}
}

// "backup prune" printed the literal "(-)" because the job never sets a note;
// the count is in the job result.
func TestBackupPruneReportsTheCount(t *testing.T) {
	f := newFakeAPI(t)
	jobID := f.addJob(core.JobBackupPrune, map[string]int{"deleted": 3}, core.JobSucceeded)
	f.handle("POST", "/api/v1/admin/jobs/run", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 202, core.JobRef{JobID: jobID})
	})
	res := f.run(t, "", "backup", "prune")
	if res.code != 0 || !strings.Contains(res.stdout, "pruned 3 backups") {
		t.Fatalf("backup prune: %+v", res)
	}
	if strings.Contains(res.stdout, "(-)") {
		t.Fatalf("the empty note placeholder is still printed: %q", res.stdout)
	}
}

// "gc" reported nothing although the job result carries the counts.
func TestGCReportsTheJobResult(t *testing.T) {
	f := newFakeAPI(t)
	jobID := f.addJob(core.JobMaintBlobGC,
		map[string]int64{"gc_removed": 7, "gc_freed_bytes": 2048, "unreferenced_deleted": 2}, core.JobSucceeded)
	f.handle("POST", "/api/v1/admin/jobs/run", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 202, core.JobRef{JobID: jobID})
	})
	res := f.run(t, "", "gc")
	if res.code != 0 || !strings.Contains(res.stdout, "removed 7 blobs") || !strings.Contains(res.stdout, "2.0 KiB") {
		t.Fatalf("gc: %+v", res)
	}
	// --min-age cannot reach the job, so it must be refused, not discarded.
	bad := f.run(t, "", "gc", "--min-age", "0")
	if bad.code != ExitUsage || !strings.Contains(bad.stderr, "--offline") {
		t.Fatalf("gc --min-age against a running server: %+v", bad)
	}
}

// The JSON of "files search" / "files trash" carried a space-relative path:
// ambiguous between spaces and not accepted by the other files commands.
func TestFilesSearchAndTrashJSONPathsAreAddressable(t *testing.T) {
	f := newFakeAPI(t)
	photos := f.addFolder(f.myRoot(), "photos")
	f.addFile(photos, "notes.txt", []byte("mine"))
	design2 := f.addFolder(f.teamRoot(), "Design2")
	f.addFile(design2, "notes.txt", []byte("team"))

	res := f.run(t, "", "files", "search", "notes", "--json")
	if res.code != 0 {
		t.Fatalf("search: %+v", res)
	}
	var nodes []core.Node
	if err := json.Unmarshal([]byte(res.stdout), &nodes); err != nil {
		t.Fatalf("json: %v\n%s", err, res.stdout)
	}
	if len(nodes) != 2 {
		t.Fatalf("want 2 hits, got %d: %s", len(nodes), res.stdout)
	}
	got := map[string]bool{}
	for _, n := range nodes {
		got[n.Path] = true
	}
	for _, want := range []string{"/My files/photos/notes.txt", "/Team/Design/Design2/notes.txt"} {
		if !got[want] {
			t.Fatalf("missing %q in %v", want, got)
		}
	}

	// The trash JSON uses the same addressable paths.
	if res := f.run(t, "", "files", "rm", "/My files/photos/notes.txt"); res.code != 0 {
		t.Fatalf("rm: %+v", res)
	}
	res = f.run(t, "", "files", "trash", "--json")
	if res.code != 0 {
		t.Fatalf("trash: %+v", res)
	}
	nodes = nil
	if err := json.Unmarshal([]byte(res.stdout), &nodes); err != nil {
		t.Fatalf("trash json: %v\n%s", err, res.stdout)
	}
	if len(nodes) != 1 || nodes[0].Path != "/My files/photos/notes.txt" {
		t.Fatalf("trash path %q (%s)", nodes[0].Path, res.stdout)
	}
}

// The single-file rename form named the parent folder, so nothing said what
// the uploaded file is now called.
func TestFilesPutRenameNamesTheFile(t *testing.T) {
	f := newFakeAPI(t)
	src := filepath.Join(t.TempDir(), "notes.txt")
	if err := os.WriteFile(src, []byte("hello"), 0o600); err != nil {
		t.Fatal(err)
	}
	res := f.run(t, "", "files", "put", src, "/My files/RenamedTarget", "--no-progress")
	if res.code != 0 {
		t.Fatalf("put: %+v", res)
	}
	if !strings.Contains(res.stdout, "/My files/RenamedTarget") || !strings.Contains(res.stdout, "notes.txt") {
		t.Fatalf("the created path is not named: %q", res.stdout)
	}
	// Uploading into an existing folder keeps the folder wording.
	res = f.run(t, "", "files", "put", src, "/My files", "--no-progress")
	if res.code != 0 || !strings.Contains(res.stdout, "uploaded 1 file") {
		t.Fatalf("put into a folder: %+v", res)
	}
}

// --all lists other users' shares, whose link the server hides: a column of
// dashes with no explanation.
func TestShareListAllDropsTheEmptyURLColumn(t *testing.T) {
	f := newFakeAPI(t)
	mine := core.Share{ID: ids.New(ids.PrefixShare), Kind: core.ShareLink, NodeName: "report.pdf",
		Status: core.ShareActive, URL: "/s/abc", CreatedByName: "alice"}
	hidden := core.Share{ID: ids.New(ids.PrefixShare), Kind: core.ShareLink, NodeName: "report.pdf",
		Status: core.ShareActive, CreatedByName: "alice"}
	f.handle("GET", "/api/v1/shares", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, core.Page[core.Share]{Items: []core.Share{mine}})
	})
	f.handle("GET", "/api/v1/admin/shares", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, core.Page[core.Share]{Items: []core.Share{hidden}})
	})
	if res := f.run(t, "", "share", "list"); res.code != 0 || !strings.Contains(res.stdout, "URL") {
		t.Fatalf("share list must keep the URL column: %+v", res)
	}
	res := f.run(t, "", "share", "list", "--all")
	if res.code != 0 || strings.Contains(res.stdout, "URL") {
		t.Fatalf("share list --all must drop the empty URL column: %+v", res)
	}
	if !strings.Contains(res.stderr, "admin_can_access_files") {
		t.Fatalf("no explanation for the missing links: stderr=%q", res.stderr)
	}
}

// "mdns status" reports the running responder, which lags a setting change by
// seconds; it must not contradict the command that just succeeded.
func TestMDNSStatusShowsTheConfiguredValue(t *testing.T) {
	f := newFakeAPI(t)
	// "mdns disable" has stored mode=off; the responder still says "auto".
	f.handle("GET", "/api/v1/admin/settings", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, []core.SettingView{
			{Key: "mdns.mode", Section: "mdns", Type: "enum", Value: json.RawMessage(`"off"`), Default: json.RawMessage(`"auto"`), IsSet: true},
			{Key: "mdns.name", Section: "mdns", Type: "string", Value: json.RawMessage(`"fp-sweep"`), Default: json.RawMessage(`""`), IsSet: true},
		})
	})
	f.handle("GET", "/api/v1/admin/mdns", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, core.MDNSStatus{Mode: "auto", Backend: "avahi", Name: "fptest.local", State: "publishing"})
	})
	res := f.run(t, "", "mdns", "status")
	if res.code != 0 {
		t.Fatalf("mdns status: %+v", res)
	}
	if !strings.Contains(res.stdout, `"off" configured`) {
		t.Fatalf("the configured mode is not shown: %q", res.stdout)
	}
	if !strings.Contains(res.stdout, `"fp-sweep.local" configured`) {
		t.Fatalf("the configured name is not shown: %q", res.stdout)
	}
	var out mdnsStatusOut
	j := f.run(t, "", "mdns", "status", "--json")
	if err := json.Unmarshal([]byte(j.stdout), &out); err != nil || out.SettingMode != "off" || out.Mode != "auto" || out.SettingName != "fp-sweep" {
		t.Fatalf("json %q (%v)", j.stdout, err)
	}
}

// Every other flag-validation error exits 2 (invalid usage); the remote
// transport ones exited 1.
func TestTransportFlagErrorsExitUsage(t *testing.T) {
	for _, c := range []struct{ args []string }{
		{[]string{"--server", "notaurl", "--token", "fpt_x", "status"}},
		{[]string{"--server", "https://localhost:1", "status"}},
		{[]string{"--server", "https://localhost:1", "--token", "fpt_x", "--fingerprint", "AA:BB", "status"}},
		{[]string{"--server", "https://localhost:1", "--token", "fpt_x", "--as", "bob", "status"}},
	} {
		res := runArgs(t, "", c.args...)
		if res.code != ExitUsage {
			t.Errorf("%v: exit %d, want %d (%s)", c.args, res.code, ExitUsage, res.stderr)
		}
	}
}

func TestPluralHandlesWordsEndingInY(t *testing.T) {
	for _, c := range []struct{ n, want string }{
		{"entry", "2 entries"}, {"file", "2 files"}, {"key", "2 keys"}, {"day", "2 days"},
		{"policy", "2 policies"}, {"backup", "2 backups"},
	} {
		if got := Plural(2, c.n); got != c.want {
			t.Errorf("Plural(2, %q) = %q, want %q", c.n, got, c.want)
		}
		if got := Plural(1, c.n); got != "1 "+c.n {
			t.Errorf("Plural(1, %q) = %q", c.n, got)
		}
	}
}

// "audit verify" printed "212 entrys".
func TestAuditVerifyPluralizesEntries(t *testing.T) {
	f := newFakeAPI(t)
	f.handle("GET", "/api/v1/admin/audit/verify", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, core.AuditVerify{OK: true, Checked: 212, FirstSeq: 1, LastSeq: 212})
	})
	res := f.run(t, "", "audit", "verify")
	if res.code != 0 || !strings.Contains(res.stdout, "212 entries") || strings.Contains(res.stdout, "entrys") {
		t.Fatalf("audit verify: %+v", res)
	}
}

// "db vacuum" stat'ed the database before the final checkpoint, so it could
// report growth and disagree with "db stats" a moment later.
func TestDBVacuumReportsTheSettledSize(t *testing.T) {
	h := testHome(t)
	d, err := db.Open(h.DB())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := d.Migrate(context.Background()); err != nil {
		d.Close()
		t.Fatal(err)
	}
	d.Close()

	res := runArgs(t, "", "--home", h.Dir(), "db", "vacuum", "--json")
	if res.code != 0 {
		t.Fatalf("db vacuum: %+v", res)
	}
	var out struct {
		Before int64 `json:"before_bytes"`
		After  int64 `json:"after_bytes"`
	}
	if err := json.Unmarshal([]byte(res.stdout), &out); err != nil {
		t.Fatalf("json: %v\n%s", err, res.stdout)
	}
	// The reported size must be the one the files actually hold once the
	// command is done: it used to be stat'ed mid-flight, with a write-ahead
	// log still waiting to be checkpointed into the database.
	size := fileSize(h.DB()) + fileSize(h.DB()+"-wal")
	if out.After != size {
		t.Fatalf("reported after_bytes %d, but the files hold %d", out.After, size)
	}
	if wal := fileSize(h.DB() + "-wal"); wal != 0 {
		t.Fatalf("the write-ahead log was not truncated: %d bytes", wal)
	}
	if plain := runArgs(t, "", "--home", h.Dir(), "db", "vacuum"); plain.code != 0 ||
		!strings.Contains(plain.stdout, "database rebuilt") || strings.Contains(plain.stdout, "compacted") {
		t.Fatalf("a no-shrink rebuild must not claim it compacted: %+v", plain)
	}
}

// Offline commands on a sealed home had no scripted way to supply the
// passphrase: the error pointed at "keys unlock", which refuses offline.
func TestGlobalPassphraseFlagsUnlockOffline(t *testing.T) {
	pp := filepath.Join(t.TempDir(), "pp")
	if err := os.WriteFile(pp, []byte("correct horse battery staple\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	h, _ := lcInitTestHome(t, "--sealed", "--passphrase-file", pp)

	state := func(t *testing.T, args ...string) string {
		t.Helper()
		res := runArgs(t, args[0], append([]string{"--home", h.Dir(), "--offline", "--json"}, args[1:]...)...)
		if res.code != 0 {
			t.Fatalf("%v: %+v", args[1:], res)
		}
		var st core.KeyStatus
		if err := json.Unmarshal([]byte(res.stdout), &st); err != nil {
			t.Fatalf("%v: %v\n%s", args[1:], err, res.stdout)
		}
		return string(st.State)
	}
	if got := state(t, "", "keys", "status"); got != string(core.KeyStateLocked) {
		t.Fatalf("a sealed home must start locked, got %q", got)
	}
	if got := state(t, "", "--passphrase-file", pp, "keys", "status"); got != string(core.KeyStateUnlocked) {
		t.Fatalf("--passphrase-file must unlock offline, got %q", got)
	}
	if got := state(t, "correct horse battery staple\n", "--passphrase-stdin", "keys", "status"); got != string(core.KeyStateUnlocked) {
		t.Fatalf("--passphrase-stdin must unlock offline, got %q", got)
	}
	if both := runArgs(t, "", "--home", h.Dir(), "--offline", "--passphrase-stdin", "--passphrase-file", pp, "keys", "status"); both.code != ExitUsage {
		t.Fatalf("both flags at once must be a usage error: %+v", both)
	}
	// The offline refusal of "keys unlock" names the flags that do work.
	ref := runArgs(t, "", "--home", h.Dir(), "--offline", "keys", "unlock", "--passphrase-file", pp)
	if !strings.Contains(ref.stderr, "--passphrase-file") || strings.Contains(ref.stderr, "ask for the passphrase themselves") {
		t.Fatalf("keys unlock offline message: %q", ref.stderr)
	}
}

// Help texts that described behaviour the commands do not have.
func TestHelpTextsMatchBehaviour(t *testing.T) {
	for _, c := range []struct {
		args []string
		want string
	}{
		{[]string{"keys", "lock", "--help"}, "local admin socket"},
		{[]string{"keys", "rotate", "--help"}, "15 minutes"},
		{[]string{"backup", "prune", "--help"}, "final backups stay until"},
		{[]string{"backup", "config", "set", "--help"}, "scheduled backups only"},
		{[]string{"share", "list", "--help"}, "admin_can_access_files"},
		{[]string{"cert", "sans", "--help"}, "ca regenerate"},
		{[]string{"gc", "--help"}, "needs --offline or --dry-run"},
	} {
		res := runArgs(t, "", c.args...)
		if !strings.Contains(res.stdout+res.stderr, c.want) {
			t.Errorf("%v: %q missing from the help", c.args, c.want)
		}
	}
}

// "jobs run" must offer only the kinds the server accepts.
func TestJobsRunOffersOnlyRunnableKinds(t *testing.T) {
	res := runArgs(t, "", "jobs", "run", "--help")
	for _, k := range []string{core.JobUploadZip, core.JobThumbsGenerate, core.JobKeysRotateKEK, core.JobKeysReencrypt} {
		if strings.Contains(res.stdout+res.stderr, k) {
			t.Errorf("%q cannot be started by hand but is listed in the help", k)
		}
	}
	if !strings.Contains(res.stdout+res.stderr, core.JobMaintTrash) {
		t.Error("the runnable kinds are missing from the help")
	}
}

// The global --passphrase-stdin must also reach "serve": a global flag that a
// command accepts and then ignores is the defect this set is about.
func TestServeUnlocksFromPassphraseStdin(t *testing.T) {
	pp := filepath.Join(t.TempDir(), "pp")
	if err := os.WriteFile(pp, []byte("correct horse battery staple\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	h, _ := lcInitTestHome(t, "--sealed", "--passphrase-file", pp)

	ctx, cancel := context.WithCancel(context.Background())
	NewRootCmd() // reset the globals before the serve goroutine starts
	G.Home = h.Dir()
	G.PassphraseStdin = true
	cmd := newServeCmd()
	stderr := &lcSyncBuffer{}
	cmd.SetOut(stderr)
	cmd.SetErr(stderr)
	cmd.SetIn(strings.NewReader("correct horse battery staple\n"))
	cmd.SetContext(ctx)
	done := make(chan error, 1)
	go func() { done <- runServe(cmd, serveOptions{}) }()

	if err := svc.WaitHealthy(ctx, h, 0, 30*time.Second, 100*time.Millisecond); err != nil {
		cancel()
		t.Fatalf("%v\n%s", err, stderr.String())
	}
	rep, err := lcCollectStatus(ctx)
	cancel()
	if werr := lcWaitDone(t, done); werr != nil {
		t.Fatal(werr)
	}
	if err != nil || rep.sys == nil || rep.sys.KeysState != core.KeyStateUnlocked {
		t.Fatalf("serve --passphrase-stdin did not unlock: %+v %v\n%s", rep, err, stderr.String())
	}
}
