package cli

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/spf13/cobra"

	"fileparcel/internal/core"
	"fileparcel/internal/db"
	"fileparcel/internal/home"
	"fileparcel/internal/ids"
	"fileparcel/internal/svc"
)

// `gc --dry-run` must count what the blob store's GC removes: staging and
// ready blobs referenced by an open upload batch are kept, a ready blob
// referenced only by a finished batch is garbage, the 15-minute floor
// applies even to --min-age 0, and stray files count only where the blob
// store keeps blob files.
func TestEstimateGCMatchesBlobGC(t *testing.T) {
	h := testHome(t)
	ctx := context.Background()
	d, err := db.Open(h.DB())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := d.Migrate(ctx); err != nil {
		d.Close()
		t.Fatal(err)
	}
	w := d.Writer()
	exec := func(q string, args ...any) {
		t.Helper()
		if _, err := w.ExecContext(ctx, q, args...); err != nil {
			d.Close()
			t.Fatalf("%s: %v", q, err)
		}
	}
	// Only the columns GC looks at matter; the referenced users, folders and
	// keyring rows do not exist.
	exec(`PRAGMA foreign_keys=OFF`)
	now := time.Now()
	old, recent := db.Ms(now.Add(-72*time.Hour)), db.Ms(now.Add(-time.Minute))
	blob := func(state string, created int64) string {
		id := ids.NewBlobID()
		exec(`INSERT INTO blobs (id, state, size, stored_size, cipher, kek_id, wrapped_dek, created_at)
			VALUES (?, ?, 100, 110, 1, 'kek_x', x'00', ?)`, id, state, created)
		return id
	}
	batch := func(state string) string {
		id := ids.New(ids.PrefixUploadBatch)
		exec(`INSERT INTO upload_batches (id, user_id, folder_id, mode, conflict, state, created_at, updated_at, expires_at)
			VALUES (?, 'usr_x', 'nod_x', 'files', 'rename', ?, ?, ?, ?)`, id, state, old, old, old)
		return id
	}
	uploadRef := func(batchID, blobID, state string) {
		exec(`INSERT INTO upload_files (id, batch_id, client_ref, rel_path, size, blob_id, state, created_at, updated_at)
			VALUES (?, ?, ?, 'f.bin', 100, ?, ?, ?, ?)`, ids.New(ids.PrefixUploadFile), batchID, blobID, blobID, state, old, old)
	}
	open, finished := batch("open"), batch("done")
	uploadRef(open, blob("staging", old), "uploading")   // an upload in progress: kept
	blob("staging", old)                                 // abandoned staging: garbage
	blob("staging", recent)                              // being written: kept (floor)
	uploadRef(finished, blob("ready", old), "committed") // only a finished batch refers to it: garbage
	uploadRef(open, blob("ready", old), "uploaded")      // an open batch refers to it: kept
	blob("deleting", old)                                // interrupted delete: garbage
	d.Close()

	orphan := func(dir, name string, mtime time.Time) {
		t.Helper()
		p := filepath.Join(h.BlobsDir(), dir, name)
		if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, make([]byte, 50), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chtimes(p, mtime, mtime); err != nil {
			t.Fatal(err)
		}
	}
	id := ids.NewBlobID()
	orphan(filepath.Join(id[0:2], id[2:4]), id, now.Add(-72*time.Hour)) // a stray blob file: garbage
	fresh := ids.NewBlobID()
	orphan(filepath.Join(fresh[0:2], fresh[2:4]), fresh, now) // being written: kept (floor)
	orphan("misc", ids.NewBlobID(), now.Add(-72*time.Hour))   // not where blobs live: ignored
	other := ids.NewBlobID()
	if other[0:4] == id[0:4] {
		t.Skip("colliding random ids")
	}
	orphan(filepath.Join(id[0:2], id[2:4]), other, now.Add(-72*time.Hour)) // wrong directory: ignored

	for _, minAge := range []time.Duration{48 * time.Hour, 0} {
		full, err := db.Open(h.DB())
		if err != nil {
			t.Fatal(err)
		}
		e, err := estimateGC(ctx, &dbHandle{h: h, full: full}, minAge)
		full.Close()
		if err != nil {
			t.Fatal(err)
		}
		if e.StagingBlobs != 1 || e.StagingBytes != 110 || e.UnreferencedBlobs != 1 || e.UnreferencedBytes != 110 ||
			e.DeletingBlobs != 1 || e.OrphanFiles != 1 || e.OrphanBytes != 50 {
			t.Fatalf("min-age %s: estimate %+v", minAge, *e)
		}
	}

	// The blob store's GC removes exactly what the dry run reported.
	c, err := Connect(Options{Home: h.Dir(), Offline: true})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if c.Deps() == nil || c.Deps().Blobs == nil {
		t.Fatal("no blob store")
	}
	removed, _, err := c.Deps().Blobs.GC(ctx, 48*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if removed != 4 {
		t.Fatalf("GC removed %d, the dry run reported 4", removed)
	}
}

// A character device that is not a terminal (/dev/null) is not a terminal.
func TestLCIsTerminalDevNull(t *testing.T) {
	f, err := os.Open(os.DevNull)
	if err != nil {
		t.Skip(err)
	}
	defer f.Close()
	if lcIsTerminal(f) {
		t.Fatal("/dev/null taken for a terminal")
	}
}

// restoreTestHome initialises a home with a metadata backup and returns it,
// the backup and a file with the backup identity.
func restoreTestHome(t *testing.T) (*home.Home, core.Backup, string) {
	t.Helper()
	h, sum := lcInitTestHome(t)
	if sum.BackupIdentity == "" {
		t.Fatal("init printed no backup identity")
	}
	idFile := filepath.Join(t.TempDir(), "identity.txt")
	if err := os.WriteFile(idFile, []byte(sum.BackupIdentity+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	res := runArgs(t, "", "--home", h.Dir(), "--json", "backup", "create", "--scope", "metadata")
	var b core.Backup
	if res.code != 0 || json.Unmarshal([]byte(res.stdout), &b) != nil || b.ID == "" {
		t.Fatalf("backup create: %+v", res)
	}
	return h, b, idFile
}

// dbSchema reads the schema version of h's database without migrating it.
func dbSchema(t *testing.T, h *home.Home) int {
	t.Helper()
	d, err := db.Open(h.DB())
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	v, err := d.SchemaVersion(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	return v
}

// restore must work when the current installation cannot be opened (a
// database migrated by a newer version, a damaged database or master key) —
// exactly when a restore is needed — given explicit credentials.
func TestRestoreWhenHomeCannotBeOpened(t *testing.T) {
	h, b, idFile := restoreTestHome(t)
	archive := filepath.Join(h.BackupsDir(), b.FileName)
	restore := func(args ...string) cliResult {
		t.Helper()
		return runArgs(t, "", append([]string{"--home", h.Dir(), "restore"}, args...)...)
	}

	// A healthy home still uses the configured identity.
	if res := restore(b.ID, "--dry-run", "-y"); res.code != 0 {
		t.Fatalf("healthy dry run: %+v", res)
	}

	// A database migrated by a newer version.
	d, err := db.Open(h.DB())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := d.Writer().Exec(`INSERT INTO schema_migrations(version, name, applied_at) VALUES (?, 'newer', 0)`,
		db.LatestVersion()+1); err != nil {
		d.Close()
		t.Fatal(err)
	}
	d.Close()
	if res := restore(b.ID, "-y"); res.code != ExitUsage || !strings.Contains(res.stderr, "--identity") ||
		!strings.Contains(res.stderr, "cannot be opened") {
		t.Fatalf("newer schema without --identity: %+v", res)
	}
	if res := restore(b.ID, "--identity", idFile, "-y"); res.code != 0 {
		t.Fatalf("newer schema: %+v", res)
	}
	if v := dbSchema(t, h); v != db.LatestVersion() {
		t.Fatalf("restored schema %d, want %d", v, db.LatestVersion())
	}
	if pre, _ := filepath.Glob(filepath.Join(h.Dir(), "pre-restore-*")); len(pre) == 0 {
		t.Fatal("the replaced data was not kept in pre-restore-*")
	}

	// Another process holds the home: refused, with advice that applies to
	// restore (it never takes --offline).
	unlock, err := h.Lock()
	if err != nil {
		t.Fatal(err)
	}
	res := restore(archive, "--identity", idFile, "--dry-run", "-y")
	unlock()
	if res.code == 0 || strings.Contains(res.stderr, "omit --offline") || !strings.Contains(res.stderr, "in use by another FileParcel process") {
		t.Fatalf("locked home: %+v", res)
	}

	// A damaged database.
	for _, sfx := range []string{"-wal", "-shm"} {
		_ = os.Remove(h.DB() + sfx)
	}
	if err := os.WriteFile(h.DB(), bytes.Repeat([]byte("garbage!"), 1024), 0o600); err != nil {
		t.Fatal(err)
	}
	if res := restore(archive, "--identity", idFile, "-y"); res.code != 0 {
		t.Fatalf("damaged database: %+v", res)
	}
	if v := dbSchema(t, h); v != db.LatestVersion() {
		t.Fatalf("restored schema %d", v)
	}

	// A damaged master key (a dry run changes nothing).
	if err := os.WriteFile(h.KeysFile(), []byte("not a key file"), 0o600); err != nil {
		t.Fatal(err)
	}
	if res := restore(archive, "--identity", idFile, "--dry-run", "-y"); res.code != 0 {
		t.Fatalf("damaged master key: %+v", res)
	}
	if got, _ := os.ReadFile(h.KeysFile()); string(got) != "not a key file" {
		t.Fatal("the dry run changed the key file")
	}
}

// The documented `restore … --passphrase-stdin < file` needs -y: stdin
// cannot also answer the confirmation.
func TestRestoreStdinCredentialsNeedYes(t *testing.T) {
	if !strings.Contains(newRestoreCmd().Example, "--passphrase-stdin -y <") {
		t.Fatal("the restore example feeds stdin without -y")
	}
	dir := t.TempDir()
	archive := filepath.Join(dir, "old.fpbak")
	pw := filepath.Join(dir, "pw")
	for _, p := range []string{archive, pw} {
		if err := os.WriteFile(p, []byte("secret\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	runWithFile := func(args ...string) cliResult {
		t.Helper()
		f, err := os.Open(pw)
		if err != nil {
			t.Fatal(err)
		}
		defer f.Close()
		root := NewRootCmd()
		var out, errb bytes.Buffer
		root.SetOut(&out)
		root.SetErr(&errb)
		root.SetIn(f)
		code := run(context.Background(), root, append([]string{"--home", filepath.Join(dir, "nohome")}, args...), &errb)
		return cliResult{code: code, stdout: out.String(), stderr: errb.String()}
	}
	if res := runWithFile("restore", archive, "--passphrase-stdin"); res.code == 0 || !strings.Contains(res.stderr, "not a terminal") {
		t.Fatalf("without -y: %+v", res)
	}
	// With -y it gets past the confirmation (and fails on the missing home).
	if res := runWithFile("restore", archive, "--passphrase-stdin", "-y"); strings.Contains(res.stderr, "not a terminal") ||
		!strings.Contains(res.stderr, "not a FileParcel home") {
		t.Fatalf("with -y: %+v", res)
	}
}

// writeFakeBinary installs a shell script as h's bin/fileparcel that records
// its arguments in <bin>/args.log and prints out (unless asked for --help).
func writeFakeBinary(t *testing.T, h *home.Home, out string) string {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("shell script")
	}
	if err := os.MkdirAll(filepath.Dir(h.Binary()), 0o755); err != nil {
		t.Fatal(err)
	}
	script := "#!/bin/sh\nprintf '%s\\n' \"$*\" >> \"$(dirname \"$0\")/args.log\"\n" +
		"case \" $* \" in *' --help '*) exit 0 ;; esac\ncat <<'EOF'\n" + out + "\nEOF\n"
	if err := os.WriteFile(h.Binary(), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	return filepath.Join(filepath.Dir(h.Binary()), "args.log")
}

func testCmd(stdin string) (*cobra.Command, *bytes.Buffer) {
	cmd := &cobra.Command{}
	var errb bytes.Buffer
	cmd.SetOut(&errb)
	cmd.SetErr(&errb)
	cmd.SetIn(strings.NewReader(stdin))
	return cmd, &errb
}

// The pre-upgrade backup of a stopped home, run by the new release
// (install.sh), must not migrate the database first: the installed binary
// makes it when the database is older than this binary's schema.
func TestPreUpgradeBackupDoesNotMigrate(t *testing.T) {
	NewRootCmd() // reset the globals
	h, _ := lcInitTestHome(t)
	fake := core.Backup{ID: ids.New(ids.PrefixBackup), State: core.BackupReady, Scope: core.BackupMetadata, Trigger: core.TriggerPreUpgrade}
	raw, _ := json.Marshal(fake)
	argsLog := writeFakeBinary(t, h, string(raw))
	ctx := context.Background()
	in := core.BackupInput{Scope: core.BackupMetadata, Trigger: core.TriggerPreUpgrade, Note: "before the upgrade to v9"}

	// The database has this binary's schema: the backup is made in-process.
	cmd, _ := testCmd("")
	b, err := lcBackup(ctx, cmd, h, in)
	if err != nil {
		t.Fatal(err)
	}
	if b.Trigger != core.TriggerPreUpgrade || b.ID == fake.ID || lcExists(argsLog) {
		t.Fatalf("in-process backup %+v (installed binary called: %v)", b, lcExists(argsLog))
	}

	// An older schema (the installed release): the installed binary makes
	// the backup and nothing is migrated.
	d, err := db.Open(h.DB())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := d.Writer().Exec(`DELETE FROM schema_migrations WHERE version = (SELECT max(version) FROM schema_migrations)`); err != nil {
		d.Close()
		t.Fatal(err)
	}
	d.Close()
	older := dbSchema(t, h)
	cmd, _ = testCmd("")
	b, err = lcBackup(ctx, cmd, h, in)
	if err != nil {
		t.Fatal(err)
	}
	if b.ID != fake.ID {
		t.Fatalf("backup %+v, want the installed binary's %s", b, fake.ID)
	}
	if v := dbSchema(t, h); v != older {
		t.Fatalf("the database was migrated from %d to %d before the upgrade", older, v)
	}
	log, _ := os.ReadFile(argsLog)
	want := "--home " + h.Dir() + " --json backup create --scope metadata --wait --note before the upgrade to v9 --trigger pre-upgrade"
	if !strings.Contains(string(log), want) {
		t.Fatalf("installed binary called with\n%s\nwant %q", log, want)
	}
}

// Backups of the installer (final, pre-upgrade) on a stopped sealed home:
// the key may stay locked (x25519 backups need only the recipient), the
// global passphrase flags are honoured, and a backup that does need the key
// names flags that work.
func TestLifecycleBackupSealedHome(t *testing.T) {
	pp := filepath.Join(t.TempDir(), "pp")
	const pass = "correct horse battery staple"
	if err := os.WriteFile(pp, []byte(pass+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	NewRootCmd()
	h, _ := lcInitTestHome(t, "--sealed", "--passphrase-file", pp)
	ctx := context.Background()
	final := core.BackupInput{Scope: core.BackupMetadata, Trigger: core.TriggerFinal}

	NewRootCmd()
	cmd, _ := testCmd("")
	if b, err := lcBackup(ctx, cmd, h, final); err != nil || b.Trigger != core.TriggerFinal {
		t.Fatalf("locked key, x25519: %+v %v", b, err)
	}
	G.PassphraseFile = pp
	if b, err := lcBackup(ctx, cmd, h, final); err != nil || b.Trigger != core.TriggerFinal {
		t.Fatalf("--passphrase-file: %+v %v", b, err)
	}

	// Passphrase encryption needs the unlocked key.
	c, err := Connect(Options{Home: h.Dir(), Offline: true, Passphrase: func() ([]byte, error) { return []byte(pass), nil }})
	if err != nil {
		t.Fatal(err)
	}
	_, err = c.Deps().Settings.Set(ctx, core.SystemPrincipal(core.ViaOffline), map[string]json.RawMessage{
		"backup.encryption": json.RawMessage(`"passphrase"`), "backup.passphrase": json.RawMessage(`"backup pass phrase 123"`)})
	c.Close()
	if err != nil {
		t.Fatal(err)
	}
	NewRootCmd()
	if _, err := lcBackup(ctx, cmd, h, final); err == nil || !strings.Contains(err.Error(), "--passphrase-file") ||
		strings.Contains(err.Error(), "keys unlock") {
		t.Fatalf("passphrase mode, locked: %v", err)
	}
	G.PassphraseFile = pp
	if b, err := lcBackup(ctx, cmd, h, final); err != nil || b.Trigger != core.TriggerFinal {
		t.Fatalf("passphrase mode, --passphrase-file: %+v %v", b, err)
	}
	NewRootCmd()
}

// The installer's wait for a server-side backup job has no deadline (a full
// final backup takes hours); Ctrl-C stops waiting and names the job.
func TestLCWaitBackup(t *testing.T) {
	f := newFakeAPI(t)
	bid := ids.New(ids.PrefixBackup)
	f.handle("GET", "/api/v1/admin/backups/{id}", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, core.Backup{ID: bid, State: core.BackupReady, Trigger: core.TriggerFinal})
	})
	c := remoteClient(t, f)
	job := f.addJob(core.JobBackupCreate, map[string]string{"backup_id": bid}, core.JobRunning, core.JobRunning, core.JobSucceeded)
	b, err := lcWaitBackup(context.Background(), c, job)
	if err != nil || b.ID != bid {
		t.Fatalf("%+v %v", b, err)
	}
	running := f.addJob(core.JobBackupCreate, nil, core.JobRunning)
	ctx, cancel := context.WithTimeout(context.Background(), 400*time.Millisecond)
	defer cancel()
	if _, err := lcWaitBackup(ctx, c, running); err == nil || !strings.Contains(err.Error(), running) ||
		!strings.Contains(err.Error(), "continues in the background") {
		t.Fatalf("interrupted wait: %v", err)
	}
}

// `backup create --out`: "-" carries the archive and nothing else, an
// existing file is refused before the backup starts unless --force, and the
// help describes what a metadata backup holds.
func TestBackupCreateOut(t *testing.T) {
	f := newFakeAPI(t)
	archive := []byte("age-encrypted-backup-bytes")
	sum := sha256.Sum256(archive)
	bid := ids.New(ids.PrefixBackup)
	backup := core.Backup{ID: bid, Scope: core.BackupFull, State: core.BackupReady, FileName: "fileparcel-2026.fpbak",
		Size: int64(len(archive)), SHA256: hex.EncodeToString(sum[:]), Trigger: core.TriggerManual, CreatedAt: time.Now()}
	f.handle("POST", "/api/v1/admin/backups", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 202, core.JobRef{JobID: f.addJob(core.JobBackupCreate, map[string]string{"backup_id": bid}, core.JobSucceeded)})
	})
	f.handle("GET", "/api/v1/admin/backups/{id}", func(w http.ResponseWriter, r *http.Request) { writeJSON(w, 200, backup) })
	f.handle("GET", "/api/v1/admin/backups/{id}/download", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Write(archive)
	})
	posts := func() int { return f.requested("POST /api/v1/admin/backups") }

	res := f.run(t, "", "backup", "create", "--out", "-")
	if res.code != 0 || res.stdout != string(archive) || !strings.Contains(res.stderr, bid) {
		t.Fatalf("--out -: %+v", res)
	}
	n := posts()
	if res := f.run(t, "", "--json", "backup", "create", "--out", "-"); res.code != ExitUsage || posts() != n {
		t.Fatalf("--json --out -: %+v", res)
	}

	dir := t.TempDir()
	dest := filepath.Join(dir, "latest.fpbak")
	if err := os.WriteFile(dest, []byte("older"), 0o600); err != nil {
		t.Fatal(err)
	}
	if res := f.run(t, "", "backup", "create", "--out", dest); res.code != ExitUsage || !strings.Contains(res.stderr, "already exists") || posts() != n {
		t.Fatalf("existing --out: %+v", res)
	}
	if res := f.run(t, "", "backup", "create", "--out", dest, "--force"); res.code != 0 {
		t.Fatalf("--force: %+v", res)
	}
	if got, _ := os.ReadFile(dest); !bytes.Equal(got, archive) {
		t.Fatal("--force did not replace the file")
	}
	n = posts()
	if res := f.run(t, "", "backup", "create", "--out", filepath.Join(dir, "missing")+"/"); res.code != ExitUsage || posts() != n {
		t.Fatalf("missing directory: %+v", res)
	}

	help := newBackupCreateCmd()
	text := help.Long + help.Flags().Lookup("scope").Usage
	if !strings.Contains(text, "keys") || strings.Contains(text, "database only") || strings.Contains(text, "only the database") {
		t.Fatalf("backup create help misdescribes the metadata scope:\n%s", text)
	}
}

// fakeManager is a svc.Manager whose Status reports active, recording the
// start/restart calls.
type fakeManager struct {
	svc.Manager
	active  bool
	started []string
}

func (m *fakeManager) Status(context.Context) (*svc.Status, error) {
	return &svc.Status{Active: m.active}, nil
}
func (m *fakeManager) Start(context.Context) error {
	m.started = append(m.started, "start")
	return nil
}
func (m *fakeManager) Restart(context.Context) error {
	m.started = append(m.started, "restart")
	return nil
}

// `service restart` refuses, like `service start`, while a process outside
// the service manager holds the home.
func TestServiceRestartRefusesForeignServer(t *testing.T) {
	h := testHome(t)
	ctx := context.Background()
	for _, action := range []string{"start", "restart"} {
		m := &fakeManager{}
		if err := lcControl(ctx, m, h, action); err != nil || len(m.started) != 1 {
			t.Fatalf("%s, home free: %v %v", action, err, m.started)
		}
		unlock, err := h.Lock()
		if err != nil {
			t.Fatal(err)
		}
		m = &fakeManager{}
		if err := lcControl(ctx, m, h, action); err == nil || len(m.started) != 0 {
			t.Errorf("%s with a foreign holder: %v %v", action, err, m.started)
		}
		m = &fakeManager{active: true} // the service itself holds the lock
		if err := lcControl(ctx, m, h, action); err != nil || len(m.started) != 1 {
			t.Errorf("%s, service active: %v %v", action, err, m.started)
		}
		unlock()
	}
}
