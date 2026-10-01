package backup

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"filippo.io/age"

	"fileparcel/internal/core"
	"fileparcel/internal/db"
	"fileparcel/internal/events"
	"fileparcel/internal/home"
	"fileparcel/internal/settings"
)

func TestClassify(t *testing.T) {
	blob := "0123456789abcdef0123456789abcdef"
	tests := []struct {
		name string
		want memberKind
	}{
		{"fileparcel-backup.json", kindHeader},
		{"manifest.json", kindManifest},
		{"data/fileparcel.db", kindDB},
		{"fileparcel.toml", kindConfig},
		{"keys/master.key", kindKey},
		{"keys/master.key.next", kindKey},
		{"keys/other", kindInvalid},
		{"certs/ca/ca.crt", kindCert},
		{"certs/acme/certificates/acme-v02.api.letsencrypt.org-directory/a.example/a.example.key", kindCert},
		{"certs/../keys/master.key", kindInvalid},
		{"certs/./x", kindInvalid},
		{"certs//x", kindInvalid},
		{"certs/", kindInvalid},
		{"certs/a b", kindInvalid},
		{"/etc/passwd", kindInvalid},
		{"../fileparcel.toml", kindInvalid},
		{"data/blobs/01/23/" + blob, kindBlob},
		{"data/blobs/01/24/" + blob, kindInvalid},
		{"data/blobs/01/23/" + strings.ToUpper(blob), kindInvalid},
		{"data/blobs/01/23/" + blob + "/x", kindInvalid},
		{"data/other.db", kindInvalid},
		{"data/fileparcel.db-wal", kindInvalid},
		{"", kindInvalid},
	}
	for _, tt := range tests {
		if got := classify(tt.name); got != tt.want {
			t.Errorf("classify(%q) = %v, want %v", tt.name, got, tt.want)
		}
	}
}

func TestGFSPolicy(t *testing.T) {
	loc := time.UTC
	day := func(d, h int) time.Time { return time.Date(2026, 1, d, h, 0, 0, 0, loc) }
	// 40 daily backups at 03:00, Jan 1 … Feb 9, plus a second backup on the newest day.
	var items []Item
	for i := 0; i < 40; i++ {
		items = append(items, Item{ID: day(1+i, 3).Format("0102-15"), CreatedAt: day(1+i, 3)})
	}
	items = append(items, Item{ID: day(40, 20).Format("0102-15"), CreatedAt: day(40, 20)})
	ids := func(keep map[string]bool) []string {
		var out []string
		for k, v := range keep {
			if v {
				out = append(out, k)
			}
		}
		slices.Sort(out)
		return out
	}
	tests := []struct {
		name string
		pol  Policy
		want []string
	}{
		{"disabled keeps all", Policy{}, nil},
		{"last 2", Policy{Last: 2}, []string{"0209-03", "0209-20"}},
		{"daily 3 (newest per day)", Policy{Daily: 3}, []string{"0207-03", "0208-03", "0209-20"}},
		// ISO weeks: Feb 9 2026 is a Monday (W07); Feb 2-8 W06; Jan 26-Feb 1 W05.
		{"weekly 3", Policy{Weekly: 3}, []string{"0201-03", "0208-03", "0209-20"}},
		{"monthly 2", Policy{Monthly: 2}, []string{"0131-03", "0209-20"}},
		{"monthly more than exist", Policy{Monthly: 12}, []string{"0131-03", "0209-20"}},
		{"combined", Policy{Last: 1, Daily: 2, Weekly: 2, Monthly: 2},
			[]string{"0131-03", "0208-03", "0209-20"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			keep := tt.pol.Keep(items, loc)
			got := ids(keep)
			if tt.want == nil {
				if len(got) != len(items) {
					t.Fatalf("kept %d of %d", len(got), len(items))
				}
				return
			}
			if !slices.Equal(got, tt.want) {
				t.Fatalf("kept %v, want %v", got, tt.want)
			}
		})
	}
	// Shuffled input gives the same answer.
	rev := slices.Clone(items)
	slices.Reverse(rev)
	if !slices.Equal(ids(Policy{Daily: 5, Weekly: 2}.Keep(rev, loc)), ids(Policy{Daily: 5, Weekly: 2}.Keep(items, loc))) {
		t.Fatal("order dependent")
	}
}

func TestIdentityAndConfig(t *testing.T) {
	te := newTestEnv(t)
	ctx := context.Background()
	c, err := te.svc.Config(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !c.Enabled || c.Encryption != core.BackupX25519 || c.HasIdentity || c.KeepLast != 7 || c.ScheduleMeta != "0 3 * * *" {
		t.Fatalf("defaults: %+v", c)
	}
	rec, idFile, err := te.svc.GenerateIdentity(ctx, te.admin())
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(rec, "age1") || !strings.Contains(idFile, "AGE-SECRET-KEY-1") {
		t.Fatalf("identity %q / %q", rec, idFile)
	}
	if te.svc.IdentityExportedAt(ctx) == nil {
		t.Fatal("generate should count as exported")
	}
	c, _ = te.svc.Config(ctx)
	if !c.HasIdentity || !slices.Equal(c.Recipients, []string{rec}) {
		t.Fatalf("after generate: %+v", c)
	}
	// A second identity replaces the recipient and keeps the old identity for decryption.
	rec2, idFile2, err := te.svc.GenerateIdentity(ctx, te.admin())
	if err != nil {
		t.Fatal(err)
	}
	c, _ = te.svc.Config(ctx)
	if !slices.Equal(c.Recipients, []string{rec2}) {
		t.Fatalf("recipients %v", c.Recipients)
	}
	lines := identityLines(idFile2)
	if len(lines) != 2 || lines[1] != identityLines(idFile)[0] {
		t.Fatalf("identity file keeps previous: %q", idFile2)
	}
	gotRec, exp, err := te.svc.ExportIdentity(ctx, te.admin())
	if err != nil || gotRec != rec2 || exp != idFile2 {
		t.Fatalf("export: %v %q", err, gotRec)
	}
	if !te.audit.has(core.ActBackupDownload, core.OutcomeSuccess) {
		t.Fatal("export not audited")
	}

	// SetConfig validation.
	pp := "short"
	bad := *c
	bad.Encryption, bad.Passphrase = core.BackupPassphrase, &pp
	if err := te.svc.SetConfig(ctx, te.admin(), bad); !isCode(err, core.ErrInvalid) {
		t.Fatalf("short passphrase: %v", err)
	}
	bad = *c
	bad.Encryption = core.BackupPassphrase
	if err := te.svc.SetConfig(ctx, te.admin(), bad); !isCode(err, core.ErrInvalid) {
		t.Fatalf("passphrase mode without passphrase: %v", err)
	}
	bad = *c
	bad.ScheduleFull = "61 * * * *"
	if err := te.svc.SetConfig(ctx, te.admin(), bad); !isCode(err, core.ErrInvalid) {
		t.Fatalf("bad cron: %v", err)
	}
	bad = *c
	bad.Recipients = []string{"age1notakey"}
	if err := te.svc.SetConfig(ctx, te.admin(), bad); !isCode(err, core.ErrInvalid) {
		t.Fatalf("bad recipient: %v", err)
	}
	good := *c
	pp = "correct horse battery staple"
	good.Passphrase, good.KeepLast, good.CopyTo = &pp, 3, ""
	if err := te.svc.SetConfig(ctx, te.admin(), good); err != nil {
		t.Fatal(err)
	}
	c, _ = te.svc.Config(ctx)
	if !c.HasPassphrase || c.KeepLast != 3 {
		t.Fatalf("after set: %+v", c)
	}
	b, _ := json.Marshal(c)
	if strings.Contains(string(b), pp) || strings.Contains(string(b), "AGE-SECRET") {
		t.Fatal("config leaks secrets")
	}
}

func TestSchedulesFollowSettings(t *testing.T) {
	te := newTestEnv(t)
	ctx := context.Background()
	names := func() map[string]string {
		scs, err := te.jobs.Schedules(ctx)
		if err != nil {
			t.Fatal(err)
		}
		m := map[string]string{}
		for _, s := range scs {
			m[s.Name] = s.Cron + " " + s.Kind + " " + string(s.Params)
		}
		return m
	}
	m := names()
	if !strings.HasPrefix(m[ScheduleMeta], "0 3 * * * backup.create") || !strings.Contains(m[ScheduleMeta], `"metadata"`) ||
		!strings.HasPrefix(m[ScheduleFull], "0 4 * * 0 backup.create") {
		t.Fatalf("schedules %v", m)
	}
	te.set(map[string]any{SettingScheduleFull: "", SettingScheduleMeta: "30 2 * * *"})
	waitFor(t, func() bool {
		m := names()
		_, full := m[ScheduleFull]
		return !full && strings.HasPrefix(m[ScheduleMeta], "30 2 * * *")
	})
	te.set(map[string]any{SettingEnabled: false})
	waitFor(t, func() bool {
		m := names()
		_, a := m[ScheduleMeta]
		_, b := m[ScheduleFull]
		return !a && !b
	})
}

func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatal("condition not met in time")
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func TestCreateVerifyRestoreRoundTrip(t *testing.T) {
	src := newTestEnv(t)
	ctx := context.Background()
	blobs := src.seedData(4)
	_, identity, err := src.svc.GenerateIdentity(ctx, src.admin())
	if err != nil {
		t.Fatal(err)
	}
	var finished []*core.Backup
	ch, cancel := src.bus.Subscribe(events.TopicBackupFinished)
	defer cancel()

	// Manual backup through the job runner.
	jobID, err := src.svc.Create(ctx, src.admin(), core.BackupInput{Scope: core.BackupFull, Note: "first"})
	if err != nil {
		t.Fatal(err)
	}
	startJobs(t, src)
	j := waitJob(t, src, jobID)
	if j.State != core.JobSucceeded {
		t.Fatalf("job %s: %s", j.State, j.Error)
	}
	var cr CreateResult
	_ = json.Unmarshal(j.Result, &cr)
	b, err := src.svc.Get(ctx, cr.BackupID)
	if err != nil {
		t.Fatal(err)
	}
	select {
	case e := <-ch:
		finished = append(finished, e.Data.(core.BackupEvent).Backup)
	case <-time.After(2 * time.Second):
		t.Fatal("no backup.finished event")
	}
	if finished[0].ID != b.ID {
		t.Fatal("event backup id")
	}
	if b.State != core.BackupReady || b.BlobCount != 4 || b.Size == 0 || len(b.SHA256) != 64 || b.Note != "first" ||
		b.Trigger != core.TriggerManual || b.CreatedBy != "usr_admin" || b.SchemaVersion != db.LatestVersion() ||
		b.Encryption != core.BackupX25519 || len(b.Recipients) != 1 || b.JobID != jobID {
		t.Fatalf("backup row %+v", b)
	}
	if !strings.HasPrefix(b.FileName, "fp-"+install8(src.env.Config.InstallID)+"-") || !strings.HasSuffix(b.FileName, "-full.fpbak") {
		t.Fatalf("file name %s", b.FileName)
	}
	path := filepath.Join(src.h.BackupsDir(), b.FileName)
	st, err := os.Stat(path)
	if err != nil || st.Mode().Perm() != 0o600 || st.Size() != b.Size {
		t.Fatalf("file %v %v", st, err)
	}
	if !src.audit.has(core.ActBackupCreate, core.OutcomeSuccess) {
		t.Fatal("create not audited")
	}
	// The file is a plain age file decryptable with the identity.
	raw, _ := os.ReadFile(path)
	if !bytes.HasPrefix(raw, []byte(ageMagic)) {
		t.Fatal("not an age file")
	}
	ids, _ := parseIdentities(identity)
	if _, err := age.Decrypt(bytes.NewReader(raw), ids...); err != nil {
		t.Fatal(err)
	}

	// Deep verify (fake stores check every blob byte for byte).
	fb := useFakeStores(t, blobs, "")
	res, err := src.svc.VerifyNow(ctx, b.ID, true, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !res.OK || res.BlobsVerified != 4 || res.Blobs != 4 || res.Members == 0 {
		t.Fatalf("verify %+v", res)
	}
	if len(fb.seen) != 4 {
		t.Fatalf("verified blobs %v", fb.seen)
	}
	b, _ = src.svc.Get(ctx, b.ID)
	if b.VerifyOK == nil || !*b.VerifyOK || b.VerifiedAt == nil {
		t.Fatalf("verify not recorded: %+v", b)
	}
	// Verify via the job as well.
	vj, err := src.svc.Verify(ctx, src.admin(), b.ID, false)
	if err != nil {
		t.Fatal(err)
	}
	if j := waitJob(t, src, vj); j.State != core.JobSucceeded {
		t.Fatalf("verify job %s %s", j.State, j.Error)
	}
	if !src.audit.has(core.ActBackupVerify, core.OutcomeSuccess) {
		t.Fatal("verify not audited")
	}

	// Change the source after the backup; the restore must bring the old state back.
	wantMeta := tableDump(t, src.env.DB.Reader(), `SELECT key, value FROM meta WHERE key = 'test_marker'`)
	wantBlobs := tableDump(t, src.env.DB.Reader(), `SELECT id, state, size, stored_size, kek_id FROM blobs ORDER BY id`)
	wantKeyring := tableDump(t, src.env.DB.Reader(), `SELECT id, purpose, mk_id, state FROM keyring ORDER BY id`)

	// Restore into a different, existing home, with the archive copied into
	// its backups/ too (the row of the restored backup only stays when its
	// file is there, see TestRestoreReconcilesBackupRows).
	dst := newTestEnv(t)
	dst.seedData(1) // pre-existing different data
	oldKey, _ := os.ReadFile(dst.h.KeysFile())
	mustWrite(t, filepath.Join(dst.h.BackupsDir(), b.FileName), raw)
	dst.logs.reset()
	rep, err := dst.svc.RestoreOfflineReport(ctx, path, core.RestoreCreds{Identity: identity}, core.RestoreOpts{})
	if err != nil {
		t.Fatal(err)
	}
	if rep.PreRestore == "" || rep.Blobs != 4 || rep.Header.BackupID != b.ID {
		t.Fatalf("report %+v", rep)
	}
	// A successful restore must not log at warn or above: offline CLI mode
	// shows warn-and-above on stderr, so such a line lands raw in the
	// middle of the command's own output.
	checkRestoreLogLevels(t, dst.logs.records())
	dst.close()
	rdb, err := db.Open(dst.h.DB())
	if err != nil {
		t.Fatal(err)
	}
	defer rdb.Close()
	if got := tableDump(t, rdb.Reader(), `SELECT key, value FROM meta WHERE key = 'test_marker'`); !slices.Equal(got, wantMeta) {
		t.Fatalf("meta %v want %v", got, wantMeta)
	}
	if got := tableDump(t, rdb.Reader(), `SELECT id, state, size, stored_size, kek_id FROM blobs ORDER BY id`); !slices.Equal(got, wantBlobs) {
		t.Fatalf("blobs %v want %v", got, wantBlobs)
	}
	if got := tableDump(t, rdb.Reader(), `SELECT id, purpose, mk_id, state FROM keyring ORDER BY id`); !slices.Equal(got, wantKeyring) {
		t.Fatal("keyring differs")
	}
	// The restored backups row describes the backup itself as ready.
	var state, sha string
	if err := rdb.QueryRow(ctx, `SELECT state, sha256 FROM backups WHERE id = ?`, b.ID).Scan(&state, &sha); err != nil ||
		state != core.BackupReady || sha != b.SHA256 {
		t.Fatalf("restored backup row %s %s %v", state, sha, err)
	}
	var jstate string
	if err := rdb.QueryRow(ctx, `SELECT state FROM jobs WHERE id = ?`, jobID).Scan(&jstate); err != nil || jstate != core.JobSucceeded {
		t.Fatalf("restored job row %s %v", jstate, err)
	}
	for id, data := range blobs {
		got, err := os.ReadFile(blobPath(dst.h, id))
		if err != nil || !bytes.Equal(got, data) {
			t.Fatalf("blob %s differs: %v", id, err)
		}
	}
	for _, rel := range []string{"keys/master.key", "fileparcel.toml", "certs/ca/ca.crt", "certs/server/leaf.key",
		"certs/acme/certificates/acme-v02.api.letsencrypt.org-directory/x.example/x.example.crt"} {
		a, _ := os.ReadFile(src.h.Path(rel))
		c, err := os.ReadFile(dst.h.Path(rel))
		if err != nil || !bytes.Equal(a, c) {
			t.Fatalf("%s differs (%v)", rel, err)
		}
	}
	if st, _ := os.Stat(dst.h.Config()); st.Mode().Perm() != home.ModeConfig {
		t.Fatalf("config mode %v", st.Mode())
	}
	// The previous data was moved aside, not deleted.
	prevKey, err := os.ReadFile(filepath.Join(rep.PreRestore, "keys", "master.key"))
	if err != nil || !bytes.Equal(prevKey, oldKey) {
		t.Fatal("previous keys not kept")
	}
	if _, err := os.Stat(filepath.Join(rep.PreRestore, "data", "fileparcel.db")); err != nil {
		t.Fatal("previous database not kept")
	}
	// Staging was cleaned up.
	if ents, _ := os.ReadDir(dst.h.TmpDir(home.TmpRestore)); len(ents) != 0 {
		t.Fatalf("staging left behind: %v", ents)
	}
}

func startJobs(t *testing.T, te *testEnv) {
	t.Helper()
	if err := te.jobs.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func waitJob(t *testing.T, te *testEnv, id string) *core.Job {
	t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	for {
		j, err := te.jobs.Get(context.Background(), id)
		if err != nil {
			t.Fatal(err)
		}
		if j.State != core.JobQueued && j.State != core.JobRunning {
			return j
		}
		if time.Now().After(deadline) {
			t.Fatalf("job %s still %s", id, j.State)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func TestWrongCredentialsAndTamper(t *testing.T) {
	te := newTestEnv(t)
	ctx := context.Background()
	te.seedData(2)
	if _, _, err := te.svc.GenerateIdentity(ctx, te.admin()); err != nil {
		t.Fatal(err)
	}
	b, err := te.svc.CreateSync(ctx, te.sys(), core.BackupInput{Scope: core.BackupMetadata})
	if err != nil {
		t.Fatal(err)
	}
	if b.BlobCount != 0 || b.Scope != core.BackupMetadata {
		t.Fatalf("metadata backup %+v", b)
	}
	path := filepath.Join(te.h.BackupsDir(), b.FileName)
	other, _ := age.GenerateX25519Identity()
	dst := newTestEnv(t)
	before, _ := os.ReadFile(dst.h.KeysFile())
	err = dst.svc.RestoreOffline(ctx, path, core.RestoreCreds{Identity: other.String()}, core.RestoreOpts{})
	if !isCode(err, core.ErrForbidden) {
		t.Fatalf("wrong identity: %v", err)
	}
	if err := dst.svc.RestoreOffline(ctx, path, core.RestoreCreds{Passphrase: "wrong passphrase!"}, core.RestoreOpts{}); !isCode(err, core.ErrForbidden) {
		t.Fatalf("passphrase for an x25519 backup: %v", err)
	}
	if err := dst.svc.RestoreOffline(ctx, path, core.RestoreCreds{Identity: "garbage"}, core.RestoreOpts{}); !isCode(err, core.ErrInvalid) {
		t.Fatalf("garbage identity: %v", err)
	}
	after, _ := os.ReadFile(dst.h.KeysFile())
	if !bytes.Equal(before, after) {
		t.Fatal("failed restore changed the home")
	}
	if ents, _ := os.ReadDir(dst.h.Dir()); slices.ContainsFunc(ents, func(e os.DirEntry) bool { return strings.HasPrefix(e.Name(), "pre-restore") }) {
		t.Fatal("failed restore created pre-restore dir")
	}

	// Flip one byte in the payload: verification reports corruption.
	raw, _ := os.ReadFile(path)
	raw[len(raw)-40] ^= 0x01
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	res, err := te.svc.VerifyNow(ctx, b.ID, false, nil)
	if err != nil {
		t.Fatal(err)
	}
	if res.OK || res.Error == "" {
		t.Fatalf("tampered verify %+v", res)
	}
	got, _ := te.svc.Get(ctx, b.ID)
	if got.VerifyOK == nil || *got.VerifyOK {
		t.Fatal("verify failure not recorded")
	}
	// Truncation is detected too.
	if err := os.WriteFile(path, raw[:len(raw)/2], 0o600); err != nil {
		t.Fatal(err)
	}
	if res, _ := te.svc.VerifyNow(ctx, b.ID, false, nil); res == nil || res.OK {
		t.Fatal("truncated backup verified")
	}
	// A missing file is reported.
	os.Remove(path)
	if res, _ := te.svc.VerifyNow(ctx, b.ID, false, nil); res == nil || res.OK || !strings.Contains(res.Error, "missing") {
		t.Fatalf("missing file: %+v", res)
	}
}

func TestPassphraseBackup(t *testing.T) {
	te := newTestEnv(t)
	ctx := context.Background()
	te.seedData(1)
	pass := "a very long backup passphrase"
	te.set(map[string]any{SettingEncryption: core.BackupPassphrase, SettingPassphrase: pass})
	b, err := te.svc.CreateSync(ctx, te.sys(), core.BackupInput{})
	if err != nil {
		t.Fatal(err)
	}
	if b.Encryption != core.BackupPassphrase || len(b.Recipients) != 0 || b.Scope != core.BackupFull {
		t.Fatalf("row %+v", b)
	}
	path := filepath.Join(te.h.BackupsDir(), b.FileName)
	if _, err := checkHeader(ctx, path, core.RestoreCreds{Passphrase: "wrong passphrase value"}); !isCode(err, core.ErrForbidden) {
		t.Fatalf("wrong passphrase: %v", err)
	}
	hdr, err := checkHeader(ctx, path, core.RestoreCreds{Passphrase: pass})
	if err != nil || hdr.Encryption != core.BackupPassphrase || hdr.BackupID != b.ID {
		t.Fatalf("right passphrase: %v %+v", err, hdr)
	}
	// Verify uses the configured passphrase.
	res, err := te.svc.VerifyNow(ctx, b.ID, false, nil)
	if err != nil || !res.OK {
		t.Fatalf("verify %v %+v", err, res)
	}
	// Import into another server (which cannot decrypt it) registers it anyway.
	dst := newTestEnv(t)
	f, _ := os.Open(path)
	defer f.Close()
	imp, err := dst.svc.Import(ctx, dst.admin(), f)
	if err != nil {
		t.Fatal(err)
	}
	if imp.Trigger != core.TriggerImport || imp.Encryption != core.BackupPassphrase || imp.SHA256 != b.SHA256 ||
		!strings.Contains(imp.Note, "imported") {
		t.Fatalf("import %+v", imp)
	}
	if !dst.audit.has(core.ActBackupImport, core.OutcomeSuccess) {
		t.Fatal("import not audited")
	}
	// With the passphrase configured the header is read.
	dst.set(map[string]any{SettingPassphrase: pass})
	f2, _ := os.Open(path)
	defer f2.Close()
	imp2, err := dst.svc.Import(ctx, dst.admin(), f2)
	if err != nil {
		t.Fatal(err)
	}
	if imp2.SchemaVersion != db.LatestVersion() || imp2.AppVersion != "vtest" || !strings.Contains(imp2.Note, "another installation") ||
		!imp2.CreatedAt.Equal(b.CreatedAt.Truncate(time.Second)) || imp2.FileName == imp.FileName {
		t.Fatalf("import with key %+v", imp2)
	}
	// Garbage is refused before anything is stored.
	if _, err := dst.svc.Import(ctx, dst.admin(), strings.NewReader("hello, not a backup")); !isCode(err, core.ErrInvalid) {
		t.Fatalf("garbage import: %v", err)
	}
	ents, _ := os.ReadDir(dst.h.BackupsDir())
	for _, e := range ents {
		if strings.HasSuffix(e.Name(), ".partial") {
			t.Fatal("partial file left behind")
		}
	}
}

func TestMetadataRestoreKeepsBlobs(t *testing.T) {
	src := newTestEnv(t)
	ctx := context.Background()
	src.seedData(2)
	_, identity, err := src.svc.GenerateIdentity(ctx, src.admin())
	if err != nil {
		t.Fatal(err)
	}
	b, err := src.svc.CreateSync(ctx, src.sys(), core.BackupInput{Scope: core.BackupMetadata})
	if err != nil {
		t.Fatal(err)
	}
	dst := newTestEnv(t)
	dstBlobs := dst.seedData(3)
	// Dry run changes nothing.
	path := filepath.Join(src.h.BackupsDir(), b.FileName)
	rep, err := dst.svc.RestoreOfflineReport(ctx, path, core.RestoreCreds{Identity: identity}, core.RestoreOpts{DryRun: true})
	if err != nil || !rep.DryRun || rep.PreRestore != "" {
		t.Fatalf("dry run %v %+v", err, rep)
	}
	rep, err = dst.svc.RestoreOfflineReport(ctx, path, core.RestoreCreds{Identity: identity}, core.RestoreOpts{})
	if err != nil {
		t.Fatal(err)
	}
	for id, data := range dstBlobs {
		got, err := os.ReadFile(blobPath(dst.h, id))
		if err != nil || !bytes.Equal(got, data) {
			t.Fatalf("existing blob %s lost by a metadata restore: %v", id, err)
		}
	}
	// The replaced database in pre-restore-<ts>/ refers to these blobs, which
	// the restored database does not list: the restored server deletes them
	// (blob GC), and an undo "by hand" found their data gone. pre-restore
	// keeps hard links to them.
	for id, data := range dstBlobs {
		live, err := os.Stat(blobPath(dst.h, id))
		if err != nil {
			t.Fatal(err)
		}
		kept := filepath.Join(rep.PreRestore, "data", "blobs", id[0:2], id[2:4], id)
		st, err := os.Stat(kept)
		if err != nil || !os.SameFile(live, st) {
			t.Fatalf("blob %s not linked into pre-restore: %v", id, err)
		}
		if err := os.Remove(blobPath(dst.h, id)); err != nil { // what GC does to an orphan
			t.Fatal(err)
		}
		if got, err := os.ReadFile(kept); err != nil || !bytes.Equal(got, data) {
			t.Fatalf("pre-restore copy of %s gone with the live file: %v", id, err)
		}
	}
	info, err := os.ReadFile(filepath.Join(rep.PreRestore, "RESTORE-INFO.txt"))
	if err != nil || !strings.Contains(string(info), "hard links") {
		t.Fatalf("RESTORE-INFO.txt does not explain the linked file data: %q %v", info, err)
	}
}

func TestScheduleAndApplyPendingRestore(t *testing.T) {
	te := newTestEnv(t)
	ctx := context.Background()
	blobs := te.seedData(2)
	if _, _, err := te.svc.GenerateIdentity(ctx, te.admin()); err != nil {
		t.Fatal(err)
	}
	b, err := te.svc.CreateSync(ctx, te.sys(), core.BackupInput{})
	if err != nil {
		t.Fatal(err)
	}
	// Change data after the backup.
	if _, err := te.env.DB.Exec(ctx, `UPDATE meta SET value = 'after' WHERE key = 'test_marker'`); err != nil {
		t.Fatal(err)
	}
	restart, cancel := te.bus.Subscribe(events.TopicSystemRestart)
	defer cancel()
	// Wrong credentials are refused before anything is written.
	other, _ := age.GenerateX25519Identity()
	if err := te.svc.ScheduleRestore(ctx, te.admin(), b.ID, core.RestoreCreds{Identity: other.String()}); !isCode(err, core.ErrForbidden) {
		t.Fatalf("wrong identity: %v", err)
	}
	if _, err := os.Stat(te.h.RestoreFile()); err == nil {
		t.Fatal("request written for wrong credentials")
	}
	if !te.audit.has(core.ActBackupRestore, core.OutcomeFailure) {
		t.Fatal("refused restore not audited")
	}
	// Empty credentials use the configured identity.
	if err := te.svc.ScheduleRestore(ctx, te.admin(), b.ID, core.RestoreCreds{}); err != nil {
		t.Fatal(err)
	}
	select {
	case <-restart:
	case <-time.After(2 * time.Second):
		t.Fatal("no restart requested")
	}
	for _, p := range []string{te.h.RestoreFile(), filepath.Join(te.h.RunDir(), restoreKeyName)} {
		st, err := os.Stat(p)
		if err != nil || st.Mode().Perm() != 0o600 {
			t.Fatalf("%s: %v %v", p, st, err)
		}
	}
	raw, _ := os.ReadFile(te.h.RestoreFile())
	if strings.Contains(string(raw), "AGE-SECRET-KEY") {
		t.Fatal("credentials stored in clear")
	}
	if !te.audit.has(core.ActBackupRestore, core.OutcomeSuccess) {
		t.Fatal("restore not audited")
	}
	// A backup made after the restored one stays listed after the restore.
	later, err := te.svc.CreateSync(ctx, te.sys(), core.BackupInput{Scope: core.BackupMetadata})
	if err != nil {
		t.Fatal(err)
	}
	mustWrite(t, filepath.Join(te.h.BackupsDir(), "notes.fpbak"), []byte("not an age file"))
	te.close() // "server stops"

	applied, err := ApplyPendingRestore(ctx, te.h, nil)
	if err != nil || !applied {
		t.Fatalf("apply: %v %v", applied, err)
	}
	for _, p := range []string{te.h.RestoreFile(), filepath.Join(te.h.RunDir(), restoreKeyName)} {
		if _, err := os.Stat(p); err == nil {
			t.Fatalf("%s left behind", p)
		}
	}
	rdb, err := db.Open(te.h.DB())
	if err != nil {
		t.Fatal(err)
	}
	var v string
	_ = rdb.QueryRow(ctx, `SELECT value FROM meta WHERE key = 'test_marker'`).Scan(&v)
	var scope, trigger, enc string
	var size int64
	err = rdb.QueryRow(ctx, `SELECT scope, "trigger", encryption, size FROM backups WHERE file_name = ?`, later.FileName).
		Scan(&scope, &trigger, &enc, &size)
	if err != nil || scope != core.BackupMetadata || trigger != core.TriggerImport || enc != core.BackupX25519 || size != later.Size {
		t.Fatalf("later backup not adopted: %v %s %s %s %d", err, scope, trigger, enc, size)
	}
	var junk int
	_ = rdb.QueryRow(ctx, `SELECT count(*) FROM backups WHERE file_name = 'notes.fpbak'`).Scan(&junk)
	rdb.Close()
	if junk != 0 {
		t.Fatal("a non-backup file was adopted")
	}
	if v != "before" {
		t.Fatalf("marker %q after restore", v)
	}
	for id, data := range blobs {
		if got, _ := os.ReadFile(blobPath(te.h, id)); !bytes.Equal(got, data) {
			t.Fatal("blob differs")
		}
	}
	// Nothing pending now.
	if applied, err := ApplyPendingRestore(ctx, te.h, nil); applied || err != nil {
		t.Fatalf("second apply %v %v", applied, err)
	}
}

func TestApplyPendingRestoreFailure(t *testing.T) {
	h := newHome(t)
	ctx := context.Background()
	mustWrite(t, h.RestoreFile(), []byte(`{"v":1,"backup_id":"bak_x","file":"../../etc/passwd","creds":""}`))
	mustWrite(t, filepath.Join(h.RunDir(), restoreKeyName), []byte("AAAA"))
	keyBefore, _ := os.ReadFile(h.KeysFile())
	applied, err := ApplyPendingRestore(ctx, h, nil)
	if applied || err == nil {
		t.Fatalf("applied %v err %v", applied, err)
	}
	if _, err := os.Stat(h.RestoreFile()); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("request not removed")
	}
	if _, err := os.Stat(filepath.Join(h.RunDir(), restoreKeyName)); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("key not removed")
	}
	fail, err := os.ReadFile(filepath.Join(h.RunDir(), restoreFailedName))
	if err != nil || !strings.Contains(string(fail), "invalid file") {
		t.Fatalf("failure record %q %v", fail, err)
	}
	if after, _ := os.ReadFile(h.KeysFile()); !bytes.Equal(after, keyBefore) {
		t.Fatal("home changed")
	}
	// Valid request, but the backup file does not exist.
	mustWrite(t, h.RestoreFile(), []byte(`{"v":1,"backup_id":"bak_x","file":"fp-x.fpbak","creds":"AAAA"}`))
	mustWrite(t, filepath.Join(h.RunDir(), restoreKeyName), []byte("AAAA"))
	if applied, err := ApplyPendingRestore(ctx, h, nil); applied || err == nil {
		t.Fatal("expected failure")
	}
	// Nothing pending.
	if applied, err := ApplyPendingRestore(ctx, h, nil); applied || err != nil {
		t.Fatal("expected no-op")
	}
}

func TestRestoreRefusedWhileLocked(t *testing.T) {
	te := newTestEnv(t)
	ctx := context.Background()
	if _, _, err := te.svc.GenerateIdentity(ctx, te.admin()); err != nil {
		t.Fatal(err)
	}
	b, err := te.svc.CreateSync(ctx, te.sys(), core.BackupInput{Scope: core.BackupMetadata})
	if err != nil {
		t.Fatal(err)
	}
	// This process holding the lock (offline CLI) is fine: dry run passes.
	unlock, err := te.h.Lock()
	if err != nil {
		t.Fatal(err)
	}
	defer unlock()
	if _, err := te.svc.RestoreOfflineReport(ctx, b.ID, core.RestoreCreds{}, core.RestoreOpts{DryRun: true}); err != nil {
		t.Fatalf("own lock: %v", err)
	}
	// A running server (jobs runner started in this process) refuses.
	startJobs(t, te)
	if err := te.svc.RestoreOffline(ctx, b.ID, core.RestoreCreds{}, core.RestoreOpts{DryRun: true}); !isCode(err, core.ErrConflict) {
		t.Fatalf("running server: %v", err)
	}
}

func TestPruneAndDelete(t *testing.T) {
	te := newTestEnv(t)
	ctx := context.Background()
	te.set(map[string]any{SettingKeepLast: 2, SettingKeepDaily: 0, SettingKeepWeekly: 0, SettingKeepMonthly: 0})
	now := time.Now()
	insert := func(id, scope, state, trigger string, age time.Duration) {
		name := "fp-test-" + id + ".fpbak"
		if state != core.BackupFailed { // a failed backup has no archive
			mustWrite(t, filepath.Join(te.h.BackupsDir(), name), []byte("x"))
		}
		if _, err := te.env.DB.Exec(ctx, `INSERT INTO backups (id, scope, state, file_name, encryption, "trigger", created_at)
			VALUES (?, ?, ?, ?, 'x25519', ?, ?)`, id, scope, state, name, trigger, db.Ms(now.Add(-age))); err != nil {
			t.Fatal(err)
		}
	}
	id := func(n int) string {
		return "bak_" + strings.Repeat("0", 25) + string("0123456789abcdefghjkmnpqrstvwxyz"[n])
	}
	for i := 0; i < 4; i++ {
		insert(id(i), core.BackupFull, core.BackupReady, core.TriggerSchedule, time.Duration(i)*time.Hour)
	}
	for i := 4; i < 7; i++ {
		insert(id(i), core.BackupMetadata, core.BackupReady, core.TriggerSchedule, time.Duration(i)*time.Hour)
	}
	insert(id(7), core.BackupFull, core.BackupReady, core.TriggerManual, 100*time.Hour)
	insert(id(8), core.BackupFull, core.BackupReady, core.TriggerImport, 100*time.Hour)
	insert(id(9), core.BackupFull, core.BackupFailed, core.TriggerSchedule, 10*24*time.Hour)
	insert(id(10), core.BackupFull, core.BackupFailed, core.TriggerSchedule, time.Hour)
	// A failed row whose archive is complete (marked failed after a crash by
	// an older version): the archive is a valid backup and must survive.
	insert(id(12), core.BackupFull, core.BackupFailed, core.TriggerSchedule, 10*24*time.Hour)
	mustWrite(t, filepath.Join(te.h.BackupsDir(), "fp-test-"+id(12)+".fpbak"), []byte("a complete archive"))

	n, err := te.svc.Prune(ctx)
	if err != nil {
		t.Fatal(err)
	}
	// full: keep 0,1 (delete 2,3); metadata: keep 4,5 (delete 6); failed old: delete 9, keep 12 (archive).
	if n != 4 {
		t.Fatalf("deleted %d", n)
	}
	if _, err := os.Stat(filepath.Join(te.h.BackupsDir(), "fp-test-"+id(12)+".fpbak")); err != nil {
		t.Fatalf("the archive of a failed backup was pruned: %v", err)
	}
	if err := te.svc.Delete(ctx, te.admin(), id(12)); err != nil { // by hand it goes
		t.Fatal(err)
	}
	page, err := te.svc.List(ctx, core.PageReq{Limit: 3})
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for {
		for _, b := range page.Items {
			got = append(got, b.ID)
		}
		if page.NextCursor == "" {
			break
		}
		if page, err = te.svc.List(ctx, core.PageReq{Limit: 3, Cursor: page.NextCursor}); err != nil {
			t.Fatal(err)
		}
	}
	want := []string{id(0), id(10), id(1), id(4), id(5), id(7), id(8)}
	slices.Sort(got)
	slices.Sort(want)
	if !slices.Equal(got, want) {
		t.Fatalf("remaining %v\nwant %v", got, want)
	}
	if _, err := os.Stat(filepath.Join(te.h.BackupsDir(), "fp-test-"+id(2)+".fpbak")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("pruned file still there")
	}
	// Delete: running backups are protected; others go with their file.
	insert(id(11), core.BackupFull, core.BackupRunning, core.TriggerManual, 0)
	if err := te.svc.Delete(ctx, te.admin(), id(11)); !isCode(err, core.ErrConflict) {
		t.Fatalf("delete running: %v", err)
	}
	if err := te.svc.Delete(ctx, te.admin(), id(7)); err != nil {
		t.Fatal(err)
	}
	if _, err := te.svc.Get(ctx, id(7)); !isCode(err, core.ErrNotFound) {
		t.Fatal("row not deleted")
	}
	if !te.audit.has(core.ActBackupDelete, core.OutcomeSuccess) {
		t.Fatal("delete not audited")
	}
	if _, err := te.svc.Get(ctx, "nope"); !isCode(err, core.ErrNotFound) {
		t.Fatal("bad id")
	}
	// Download.
	rc, size, name, err := te.svc.Download(ctx, id(0))
	if err != nil || size != 1 || name != "fp-test-"+id(0)+".fpbak" {
		t.Fatalf("download %v %d %s", err, size, name)
	}
	rc.Close()
	if _, _, _, err := te.svc.Download(ctx, id(10)); !isCode(err, core.ErrConflict) {
		t.Fatalf("download failed backup: %v", err)
	}
}

func TestCreateValidationAndRecovery(t *testing.T) {
	te := newTestEnv(t)
	ctx := context.Background()
	tests := []struct {
		by *core.Principal
		in core.BackupInput
	}{
		{te.admin(), core.BackupInput{Scope: "everything"}},
		{te.admin(), core.BackupInput{Trigger: core.TriggerPreUpgrade}},
		{te.admin(), core.BackupInput{Trigger: core.TriggerSchedule}},
		{te.admin(), core.BackupInput{CopyTo: "/tmp"}},
		{te.sys(), core.BackupInput{CopyTo: "relative/dir"}},
		{te.admin(), core.BackupInput{Note: strings.Repeat("x", 501)}},
	}
	for i, tt := range tests {
		if _, err := te.svc.Create(ctx, tt.by, tt.in); !isCode(err, core.ErrInvalid) {
			t.Errorf("case %d: %v", i, err)
		}
	}
	// No recipient and locked keys: refused up front.
	te.env.Keys = &fakeKeys{state: core.KeyStateLocked}
	if _, err := te.svc.Create(ctx, te.admin(), core.BackupInput{}); !isCode(err, core.ErrInvalid) {
		t.Fatalf("no recipients, locked: %v", err)
	}
	te.env.Keys = &fakeKeys{}
	// No recipient but unlocked: an identity is generated automatically
	// (not counted as exported).
	copyDir := t.TempDir()
	b, err := te.svc.CreateSync(ctx, te.sys(), core.BackupInput{Trigger: core.TriggerPreUpgrade, CopyTo: copyDir})
	if err != nil {
		t.Fatal(err)
	}
	if c, _ := te.svc.Config(ctx); !c.HasIdentity || len(c.Recipients) != 1 {
		t.Fatalf("auto identity %+v", c)
	}
	if te.svc.IdentityExportedAt(ctx) != nil {
		t.Fatal("auto identity must not count as exported")
	}
	if b.Trigger != core.TriggerPreUpgrade || b.CopiedTo != filepath.Join(copyDir, b.FileName) {
		t.Fatalf("row %+v", b)
	}
	a, _ := os.ReadFile(filepath.Join(te.h.BackupsDir(), b.FileName))
	c, _ := os.ReadFile(b.CopiedTo)
	if !bytes.Equal(a, c) {
		t.Fatal("copy differs")
	}

	// A crashed backup (running row + partial file) is recovered by New.
	partial := filepath.Join(te.h.BackupsDir(), ".fp-x.fpbak.partial")
	mustWrite(t, partial, []byte("partial"))
	if _, err := te.env.DB.Exec(ctx, `INSERT INTO backups (id, scope, state, file_name, encryption, "trigger", created_at)
		VALUES ('bak_0000000000000000000000000z', 'full', 'running', 'fp-x.fpbak', 'x25519', 'manual', 1)`); err != nil {
		t.Fatal(err)
	}
	s2, err := New(te.env, nil, te.jobs)
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close()
	got, err := s2.Get(ctx, "bak_0000000000000000000000000z")
	if err != nil || got.State != core.BackupFailed || !strings.Contains(got.Error, "interrupted") {
		t.Fatalf("recovered %+v %v", got, err)
	}
	if _, err := os.Stat(partial); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("partial file not removed")
	}
}

func TestDeepVerifySealedAndCorruptBlob(t *testing.T) {
	te := newTestEnv(t)
	ctx := context.Background()
	blobs := te.seedData(3)
	if _, _, err := te.svc.GenerateIdentity(ctx, te.admin()); err != nil {
		t.Fatal(err)
	}
	b, err := te.svc.CreateSync(ctx, te.sys(), core.BackupInput{})
	if err != nil {
		t.Fatal(err)
	}
	// Sealed master key in the backup: blobs cannot be checked, verify still
	// passes, with a note that says so — also as the job's final note, which
	// is what the web interface shows when the job is done.
	useFakeStores(t, blobs, core.KeyStateLocked)
	var notes []string
	res, err := te.svc.VerifyNow(ctx, b.ID, true, hookHandle{fn: func(note string) { notes = append(notes, note) }})
	if err != nil || !res.OK || res.BlobsVerified != 0 || len(res.Notes) == 0 || !strings.Contains(res.Notes[0], "not decrypted") {
		t.Fatalf("sealed deep verify %v %+v", err, res)
	}
	if len(notes) == 0 || !strings.Contains(notes[len(notes)-1], "not decrypted") {
		t.Fatalf("the job's last note does not say the files were not decrypted: %q", notes)
	}
	// A metadata backup has no file contents to decrypt: nothing to note.
	mb, err := te.svc.CreateSync(ctx, te.sys(), core.BackupInput{Scope: core.BackupMetadata})
	if err != nil {
		t.Fatal(err)
	}
	if res, err := te.svc.VerifyNow(ctx, mb.ID, true, nil); err != nil || !res.OK || len(res.Notes) != 0 {
		t.Fatalf("sealed deep verify of a metadata backup %v %+v", err, res)
	}
	// One blob differs from what the store expects: deep verify fails.
	bad := map[string][]byte{}
	first := ""
	for id, data := range blobs {
		bad[id] = data
		if first == "" {
			first = id
		}
	}
	bad[first] = []byte("something else")
	useFakeStores(t, bad, "")
	res, err = te.svc.VerifyNow(ctx, b.ID, true, nil)
	if err != nil || res.OK || res.BlobsFailed != 1 || res.BlobsVerified != 2 || !strings.Contains(res.Error, first) {
		t.Fatalf("corrupt blob deep verify %v %+v", err, res)
	}
	if ents, _ := os.ReadDir(te.h.TmpDir(home.TmpVerify)); len(ents) != 0 {
		t.Fatalf("verify temp dir left behind: %v", ents)
	}
}

// TestScheduledBackupEnqueuesPrune: a backup made by a schedule is followed
// by a backup.prune job that applies the retention policy.
func TestScheduledBackupEnqueuesPrune(t *testing.T) {
	te := newTestEnv(t)
	ctx := context.Background()
	te.set(map[string]any{SettingKeepLast: 1, SettingKeepDaily: 0, SettingKeepWeekly: 0, SettingKeepMonthly: 0})
	if _, _, err := te.svc.GenerateIdentity(ctx, te.admin()); err != nil {
		t.Fatal(err)
	}
	startJobs(t, te)
	var created []string
	for i := 0; i < 2; i++ {
		id, err := te.jobs.Enqueue(ctx, core.JobBackupCreate, createParams{Scope: core.BackupMetadata, Trigger: core.TriggerSchedule}, nil)
		if err != nil {
			t.Fatal(err)
		}
		j := waitJob(t, te, id)
		if j.State != core.JobSucceeded {
			t.Fatalf("scheduled backup %s: %s", j.State, j.Error)
		}
		var cr CreateResult
		_ = json.Unmarshal(j.Result, &cr)
		created = append(created, cr.BackupID)
		// The prune job enqueued by this backup finishes too.
		waitFor(t, func() bool {
			page, err := te.jobs.List(ctx, core.JobQuery{Kind: core.JobBackupPrune})
			if err != nil {
				t.Fatal(err)
			}
			done := 0
			for _, pj := range page.Items {
				if pj.State == core.JobSucceeded {
					done++
				}
			}
			return done == i+1
		})
	}
	// keep_last = 1: the first scheduled backup was pruned by the second run.
	if _, err := te.svc.Get(ctx, created[0]); !isCode(err, core.ErrNotFound) {
		t.Fatalf("old scheduled backup kept: %v", err)
	}
	if b, err := te.svc.Get(ctx, created[1]); err != nil || b.Trigger != core.TriggerSchedule {
		t.Fatalf("newest scheduled backup: %+v %v", b, err)
	}
}

func TestImportRefusedWhenDiskIsFull(t *testing.T) {
	te := newTestEnv(t)
	old := importMinFree
	importMinFree = 1 << 62 // no filesystem has that much free space
	defer func() { importMinFree = old }()
	body := strings.NewReader("age-encryption.org/v1\n-> X25519 abc\n" + strings.Repeat("x", 1000))
	if _, err := te.svc.Import(context.Background(), te.admin(), body); !isCode(err, core.ErrQuota) {
		t.Fatalf("import on a full disk: %v", err)
	}
	ents, _ := os.ReadDir(te.h.BackupsDir())
	if len(ents) != 0 {
		t.Fatalf("files left behind: %v", ents)
	}
}

// A backup copied into backup.copy_to must end up 0600 no matter what was at
// the temp path first, and must never be written through a symlink.
func TestCopyToIgnoresWhatIsAlreadyThere(t *testing.T) {
	te := newTestEnv(t)
	ctx := context.Background()
	src := filepath.Join(t.TempDir(), "src.fpbak")
	mustWrite(t, src, []byte("backup-bytes"))
	const name = "fp-copy.fpbak"

	check := func(t *testing.T, dir string) {
		t.Helper()
		dst, err := te.svc.copyTo(ctx, src, dir, name)
		if err != nil {
			t.Fatalf("copyTo: %v", err)
		}
		if want := filepath.Join(dir, name); dst != want {
			t.Fatalf("dst = %s, want %s", dst, want)
		}
		fi, err := os.Lstat(dst)
		if err != nil {
			t.Fatal(err)
		}
		if fi.Mode()&os.ModeSymlink != 0 {
			t.Fatal("copy is a symlink")
		}
		if got := fi.Mode().Perm(); got != 0o600 {
			t.Fatalf("copy mode = %v, want 0600", got)
		}
		if b, err := os.ReadFile(dst); err != nil || string(b) != "backup-bytes" {
			t.Fatalf("copy contents %q %v", b, err)
		}
		// Nothing but the copy is left in the directory.
		ents, err := os.ReadDir(dir)
		if err != nil {
			t.Fatal(err)
		}
		if len(ents) != 1 || ents[0].Name() != name {
			t.Fatalf("leftovers: %v", ents)
		}
	}

	t.Run("clean", func(t *testing.T) { check(t, t.TempDir()) })

	t.Run("stale partial with a wider mode", func(t *testing.T) {
		dir := t.TempDir()
		partial := filepath.Join(dir, "."+name+".partial")
		mustWrite(t, partial, []byte("leftover from an interrupted copy"))
		if err := os.Chmod(partial, 0o644); err != nil {
			t.Fatal(err)
		}
		check(t, dir)
	})

	t.Run("symlinked partial", func(t *testing.T) {
		dir := t.TempDir()
		outside := filepath.Join(t.TempDir(), "victim")
		mustWrite(t, outside, []byte("not ours"))
		if err := os.Symlink(outside, filepath.Join(dir, "."+name+".partial")); err != nil {
			t.Fatal(err)
		}
		check(t, dir)
		if b, _ := os.ReadFile(outside); string(b) != "not ours" {
			t.Fatalf("wrote through the symlink: %q", b)
		}
	})

	t.Run("symlinked destination", func(t *testing.T) {
		dir := t.TempDir()
		outside := filepath.Join(t.TempDir(), "victim")
		mustWrite(t, outside, []byte("not ours"))
		if err := os.Symlink(outside, filepath.Join(dir, name)); err != nil {
			t.Fatal(err)
		}
		check(t, dir)
		if b, _ := os.ReadFile(outside); string(b) != "not ours" {
			t.Fatalf("wrote through the symlink: %q", b)
		}
	})
}

// checkRestoreLogLevels asserts that a successful offline restore logged
// "backup: restore complete" at info and nothing at warn or above: in
// offline CLI mode the console handler lets warn-and-above through, so such
// a record is printed raw between the command's own sentences.
func checkRestoreLogLevels(t *testing.T, recs []slog.Record) {
	t.Helper()
	found := false
	for _, r := range recs {
		if r.Message == "backup: restore complete" {
			found = true
			if r.Level != slog.LevelInfo {
				t.Errorf("%q logged at %s, want INFO", r.Message, r.Level)
			}
		}
		if r.Level >= slog.LevelWarn {
			t.Errorf("successful restore logged at %s: %q", r.Level, r.Message)
		}
	}
	if !found {
		t.Error(`no "backup: restore complete" record`)
	}
}

// hookHandle is a core.JobHandle that calls fn on every progress report.
type hookHandle struct{ fn func(note string) }

func (h hookHandle) ID() string                       { return "job_0000000000000000000000000" }
func (h hookHandle) Params(any) error                 { return nil }
func (h hookHandle) Progress(_, _ int64, note string) { h.fn(note) }
func (h hookHandle) SetResult(any)                    {}

// probeHeader is the header create() builds, without the key state.
func probeHeader(t *testing.T, te *testEnv, plan *encryptionPlan, scope string) Header {
	t.Helper()
	return Header{Format: FormatName, Version: FormatVersion, BackupID: "bak_0000000000000000000000000",
		AppVersion: "vtest", SchemaVersion: db.LatestVersion(), Scope: scope,
		InstallID: install8(te.env.Config.InstallID), CreatedAt: time.Now().UTC().Truncate(time.Second),
		Encryption: plan.mode}
}

func testPlan(t *testing.T, te *testEnv) *encryptionPlan {
	t.Helper()
	if _, _, err := te.svc.GenerateIdentity(context.Background(), te.admin()); err != nil {
		t.Fatal(err)
	}
	plan, err := te.svc.encryptionPlan(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	return plan
}

// TestWriteArchiveAbortsWhenTheKeysRotate: the database snapshot and the key
// files are copied minutes apart on a big installation. A master key
// rotation in between writes an archive whose keys/master.key does not
// belong to its database — state "ready", shallow verification green, and a
// restored server that refuses to start. The archive must fail instead.
func TestWriteArchiveAbortsWhenTheKeysRotate(t *testing.T) {
	te := newTestEnv(t)
	ctx := context.Background()
	te.seedData(2)
	plan := testPlan(t, te)
	var once sync.Once
	h := hookHandle{fn: func(note string) {
		if note != "database" {
			return
		}
		// Right after the snapshot, before the key file is read.
		once.Do(func() {
			if _, err := te.env.DB.Exec(ctx, `UPDATE meta SET value = 'mk_rotated' WHERE key = 'mk_id'`); err != nil {
				t.Error(err)
			}
			mustWrite(t, te.h.KeysFile(), []byte(`{"v":1,"mk_id":"mk_rotated","mode":"plain","key":"AAAA"}`))
		})
	}}
	_, err := te.svc.writeArchive(ctx, probeHeader(t, te, plan, core.BackupFull), "probe.fpbak", plan, h)
	if !isCode(err, core.ErrConflict) {
		t.Fatalf("archive written across a key rotation: %v", err)
	}
	ents, _ := os.ReadDir(te.h.BackupsDir())
	for _, e := range ents {
		t.Fatalf("partial archive left behind: %s", e.Name())
	}
}

// TestCreateHoldsTheKeyMaterial: with a key service that supports it, the
// rotations are blocked outright while the key material is copied, and the
// hold ends before the (much longer) blob phase.
func TestCreateHoldsTheKeyMaterial(t *testing.T) {
	te := newTestEnv(t)
	ctx := context.Background()
	te.seedData(2)
	fk := te.env.Keys.(*fakeKeys)
	plan := testPlan(t, te)
	var held int32
	h := hookHandle{fn: func(note string) {
		if note == "database" {
			held = fk.holds.Load()
		}
	}}
	if _, err := te.svc.writeArchive(ctx, probeHeader(t, te, plan, core.BackupFull), "held.fpbak", plan, h); err != nil {
		t.Fatal(err)
	}
	if fk.taken.Load() == 0 || held != 1 {
		t.Fatalf("key material not held while the snapshot and the key files were copied (taken=%d, held=%d)",
			fk.taken.Load(), held)
	}
	if n := fk.holds.Load(); n != 0 {
		t.Fatalf("%d key material holds still open after the archive was written", n)
	}
}

// TestPruneKeepsPreUpgradeBackups: the pre-upgrade backup is the documented
// rollback path for a problem noticed days later, and the manual promises it
// is never pruned automatically. It used to be pruned by the GFS policy like
// a scheduled backup — with the shipped defaults, seven days after the
// upgrade.
func TestPruneKeepsPreUpgradeBackups(t *testing.T) {
	te := newTestEnv(t)
	ctx := context.Background()
	te.set(map[string]any{SettingKeepLast: 1, SettingKeepDaily: 0, SettingKeepWeekly: 0, SettingKeepMonthly: 0})
	now := time.Now()
	insert := func(id, trigger string, age time.Duration) {
		name := "fp-test-" + id + ".fpbak"
		mustWrite(t, filepath.Join(te.h.BackupsDir(), name), []byte("x"))
		if _, err := te.env.DB.Exec(ctx, `INSERT INTO backups (id, scope, state, file_name, encryption, "trigger", created_at)
			VALUES (?, 'metadata', 'ready', ?, 'x25519', ?, ?)`, id, name, trigger, db.Ms(now.Add(-age))); err != nil {
			t.Fatal(err)
		}
	}
	id := func(n int) string {
		return "bak_" + strings.Repeat("0", 25) + string("0123456789abcdefghjkmnpqrstvwxyz"[n])
	}
	insert(id(0), core.TriggerSchedule, time.Hour)
	insert(id(1), core.TriggerSchedule, 2*time.Hour)
	insert(id(2), core.TriggerPreUpgrade, 8*24*time.Hour)
	insert(id(3), core.TriggerFinal, 8*24*time.Hour)
	insert(id(4), core.TriggerManual, 8*24*time.Hour)
	insert(id(5), core.TriggerImport, 8*24*time.Hour)

	n, err := te.svc.Prune(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("deleted %d, want 1 (only the older scheduled backup)", n)
	}
	for _, want := range []string{id(0), id(2), id(3), id(4), id(5)} {
		if _, err := te.svc.Get(ctx, want); err != nil {
			t.Errorf("%s was pruned: %v", want, err)
		}
	}
	if _, err := te.svc.Get(ctx, id(1)); !isCode(err, core.ErrNotFound) {
		t.Fatalf("the older scheduled backup survived: %v", err)
	}
}

// TestRestoreChecksFreeSpace: a restore stages the whole archive under
// <home>/tmp/restore before it swaps anything in, so it needs room for a
// second copy of the data. Without a precheck an admin learns that only
// after a long extract, with the disk full.
func TestRestoreChecksFreeSpace(t *testing.T) {
	te := newTestEnv(t)
	ctx := context.Background()
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	hdr := testHeader(db.LatestVersion())
	hdr.DBSize = 1 << 50 // a petabyte of database: nothing has room for it
	path := filepath.Join(t.TempDir(), "huge.fpbak")
	mustWrite(t, path, craftArchive(t, id.Recipient(), validMembers(t, hdr, nil)))
	_, err = restoreHome(ctx, te.h, path, core.RestoreCreds{Identity: id.String()}, core.RestoreOpts{},
		"", slog.New(slog.DiscardHandler), nil)
	if !isCode(err, core.ErrQuota) || !strings.Contains(err.Error(), "free disk space") {
		t.Fatalf("restore without room: %v", err)
	}
	if ents, _ := os.ReadDir(te.h.TmpDir(home.TmpRestore)); len(ents) != 0 {
		t.Fatalf("staging left behind: %v", ents)
	}
}

// TestCopyToAcceptsTrailingSlash: an operator pastes or tab-completes a
// mount point. The value means the same directory with or without the
// trailing separator, so it must be normalised rather than refused with
// "must be a clean absolute directory path".
func TestCopyToAcceptsTrailingSlash(t *testing.T) {
	for _, s := range []string{"/mnt/nas/fileparcel", "/mnt/nas/fileparcel/", "/mnt/nas/fileparcel//", "  /mnt/nas/fileparcel/  "} {
		if err := validCopyTo(s); err != nil {
			t.Errorf("%q rejected: %v", s, err)
		}
		if got := copyToDir(s); got != "/mnt/nas/fileparcel" {
			t.Errorf("copyToDir(%q) = %q", s, got)
		}
	}
	for _, s := range []string{"relative/dir", "~/backups", "/mnt/../etc", "/mnt/./nas", "/mnt//nas", "/mnt/nas\x00"} {
		if err := validCopyTo(s); err == nil {
			t.Errorf("%q accepted", s)
		}
	}
	if err := validCopyTo(""); err != nil {
		t.Errorf("empty rejected: %v", err)
	}

	// End to end through the settings.
	te := newTestEnv(t)
	ctx := context.Background()
	cfg, err := te.svc.Config(ctx)
	if err != nil {
		t.Fatal(err)
	}
	cfg.CopyTo = "/mnt/nas/fileparcel/"
	if err := te.svc.SetConfig(ctx, te.admin(), *cfg); err != nil {
		t.Fatalf("set copy_to with a trailing slash: %v", err)
	}
	got, err := te.svc.Config(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if got.CopyTo != "/mnt/nas/fileparcel" {
		t.Fatalf("stored copy_to = %q", got.CopyTo)
	}
}

// TestRetentionOffIsDocumented: all four keep_* values at 0 keep every
// backup (Policy.Disabled), the opposite of what "keep this many" reads
// like, so the setting descriptions have to say so.
func TestRetentionOffIsDocumented(t *testing.T) {
	if !(Policy{}).Disabled() {
		t.Fatal("a zero policy must keep everything")
	}
	for _, k := range []string{SettingKeepLast, SettingKeepDaily, SettingKeepWeekly, SettingKeepMonthly} {
		d, ok := settings.Lookup(k)
		if !ok {
			t.Fatalf("%s not registered", k)
		}
		if !strings.Contains(d.Description, "0 =") {
			t.Errorf("%s does not document what 0 means: %q", k, d.Description)
		}
	}
	d, _ := settings.Lookup(SettingKeepLast)
	if !strings.Contains(d.Description, "all four") {
		t.Errorf("%s does not say that all four at 0 turn retention off: %q", SettingKeepLast, d.Description)
	}
}

// TestRecipientKindsCannotMix: age refuses to encrypt to post-quantum
// (age1pq1…) and classic (age1…) recipients together, so a list mixing them
// made every backup fail after it had been accepted as valid — and
// "Generate identity" produced such a list from a post-quantum one.
func TestRecipientKindsCannotMix(t *testing.T) {
	x1, _ := age.GenerateX25519Identity()
	x2, _ := age.GenerateX25519Identity()
	p1, err := age.GenerateHybridIdentity()
	if err != nil {
		t.Fatal(err)
	}
	p2, _ := age.GenerateHybridIdentity()
	xr1, xr2 := x1.Recipient().String(), x2.Recipient().String()
	pr1, pr2 := p1.Recipient().String(), p2.Recipient().String()
	for _, tt := range []struct {
		list []string
		ok   bool
	}{
		{[]string{xr1, xr2}, true},
		{[]string{pr1, pr2}, true},
		{[]string{xr1, pr1}, false},
		{[]string{pr1, xr1}, false},
		{[]string{xr1 + "\n" + pr1}, false}, // one entry holding both kinds
	} {
		if err := validRecipients(tt.list); (err == nil) != tt.ok {
			t.Errorf("validRecipients(%d entries, ok=%v) = %v", len(tt.list), tt.ok, err)
		}
	}

	te := newTestEnv(t)
	ctx := context.Background()
	c, err := te.svc.Config(ctx)
	if err != nil {
		t.Fatal(err)
	}
	mixed := *c
	mixed.Recipients = []string{xr1, pr1}
	if err := te.svc.SetConfig(ctx, te.admin(), mixed); !isCode(err, core.ErrInvalid) {
		t.Fatalf("mixed recipients accepted: %v", err)
	}
	if got, _ := te.svc.Config(ctx); len(got.Recipients) != 0 {
		t.Fatalf("a refused change stored recipients: %v", got.Recipients)
	}

	// A post-quantum list gets a post-quantum identity, and backups work.
	pq := *c
	pq.Recipients = []string{pr1}
	if err := te.svc.SetConfig(ctx, te.admin(), pq); err != nil {
		t.Fatal(err)
	}
	rec, identity, err := te.svc.GenerateIdentity(ctx, te.admin())
	if err != nil {
		t.Fatalf("generate identity next to a post-quantum recipient: %v", err)
	}
	if !strings.HasPrefix(rec, "age1pq1") || !strings.Contains(identity, "AGE-SECRET-KEY-PQ-1") {
		t.Fatalf("generated a %.10s… identity for a post-quantum list", rec)
	}
	got, _ := te.svc.Config(ctx)
	if !slices.Equal(got.Recipients, []string{pr1, rec}) {
		t.Fatalf("recipients after generate: %d entries", len(got.Recipients))
	}
	b, err := te.svc.CreateSync(ctx, te.sys(), core.BackupInput{Scope: core.BackupMetadata})
	if err != nil {
		t.Fatalf("backup to post-quantum recipients: %v", err)
	}
	if res, err := te.svc.VerifyNow(ctx, b.ID, false, nil); err != nil || !res.OK {
		t.Fatalf("verify with the generated post-quantum identity: %v %+v", err, res)
	}
	// Generating again keeps the kind (the previous identity is post-quantum).
	if rec2, _, err := te.svc.GenerateIdentity(ctx, te.admin()); err != nil || !strings.HasPrefix(rec2, "age1pq1") {
		t.Fatalf("second generate: %v %.10s…", err, rec2)
	}
	// The encryption plan refuses a mixed list with a clear message rather
	// than failing inside age.Encrypt.
	if err := checkRecipientMix([]age.Recipient{x1.Recipient(), p1.Recipient()}); err == nil {
		t.Fatal("checkRecipientMix accepted a mixed list")
	}
}

// TestBackupInAHomeWithURICharacters: the snapshot is opened through a
// SQLite URI, where '#' starts a fragment and '%41' decodes to 'A'. A home
// whose path holds either ran normally but every backup failed after the
// snapshot had been written.
func TestBackupInAHomeWithURICharacters(t *testing.T) {
	te := newTestEnvHome(t, newHomeAt(t, filepath.Join(t.TempDir(), "home#2%41b sp")))
	ctx := context.Background()
	te.seedData(2)
	if _, _, err := te.svc.GenerateIdentity(ctx, te.admin()); err != nil {
		t.Fatal(err)
	}
	b, err := te.svc.CreateSync(ctx, te.sys(), core.BackupInput{Scope: core.BackupFull})
	if err != nil {
		t.Fatalf("backup in %s: %v", te.h.Dir(), err)
	}
	if b.BlobCount != 2 {
		t.Fatalf("blob count %d", b.BlobCount)
	}
}

// TestBackupChecksFreeSpaceBeforeTheSnapshot: VACUUM INTO writes a full copy
// of the database before anything else is checked. On a nearly full disk it
// filled the filesystem under the live server and failed with SQLite's
// "database or disk is full"; the free-space message was never reached.
func TestBackupChecksFreeSpaceBeforeTheSnapshot(t *testing.T) {
	te := newTestEnv(t)
	ctx := context.Background()
	if _, _, err := te.svc.GenerateIdentity(ctx, te.admin()); err != nil {
		t.Fatal(err)
	}
	old := snapshotSlack
	snapshotSlack = 1 << 62 // no filesystem has that much free space
	defer func() { snapshotSlack = old }()
	_, err := te.svc.CreateSync(ctx, te.sys(), core.BackupInput{Scope: core.BackupMetadata})
	if !isCode(err, core.ErrQuota) || !strings.Contains(err.Error(), "free disk space") {
		t.Fatalf("backup without room for the snapshot: %v", err)
	}
	page, err := te.svc.List(ctx, core.PageReq{})
	if err != nil || len(page.Items) != 1 {
		t.Fatalf("backups %v %v", page.Items, err)
	}
	if b := page.Items[0]; b.State != core.BackupFailed || !strings.Contains(b.Error, "free disk space") {
		t.Fatalf("row %s %q", b.State, b.Error)
	}
	for _, dir := range []string{te.h.TmpDir(""), te.h.BackupsDir()} {
		ents, _ := os.ReadDir(dir)
		for _, e := range ents {
			if strings.HasPrefix(e.Name(), "snapshot-") || strings.HasSuffix(e.Name(), ".partial") {
				t.Fatalf("left behind: %s", filepath.Join(dir, e.Name()))
			}
		}
	}
	if te.svc.snapshotSize(ctx) <= 0 {
		t.Fatal("no snapshot size estimate")
	}
}

// An identity the server generates on its own (nobody has seen it) must not
// inherit the export record of the identity it replaced: that offline copy
// cannot decrypt the backups made from now on, so the doctor has to warn.
func TestAutoIdentityClearsExportRecord(t *testing.T) {
	te := newTestEnv(t)
	ctx := context.Background()
	if _, _, err := te.svc.GenerateIdentity(ctx, te.admin()); err != nil {
		t.Fatal(err)
	}
	if te.svc.IdentityExportedAt(ctx) == nil {
		t.Fatal("generate should count as exported")
	}
	if _, _, err := te.svc.generateIdentity(ctx, te.sys(), false); err != nil {
		t.Fatal(err)
	}
	if at := te.svc.IdentityExportedAt(ctx); at != nil {
		t.Fatalf("a server-made identity inherited the export of %v", at)
	}
	if _, _, err := te.svc.ExportIdentity(ctx, te.admin()); err != nil {
		t.Fatal(err)
	}
	if te.svc.IdentityExportedAt(ctx) == nil {
		t.Fatal("export not recorded")
	}
}

// lockedKeys is fakeKeys in the locked state: secrets cannot be opened.
type lockedKeys struct{ *fakeKeys }

func (lockedKeys) State() core.KeyState { return core.KeyStateLocked }

func (lockedKeys) OpenField(string, string) ([]byte, error) { return nil, core.ErrKeysLocked }

// setRecipients stores list through SetConfig (PUT /admin/backups/config,
// backup config set --recipient).
func (te *testEnv) setRecipients(list ...string) {
	te.t.Helper()
	c, err := te.svc.Config(context.Background())
	if err != nil {
		te.t.Fatal(err)
	}
	c.Recipients = list
	if err := te.svc.SetConfig(context.Background(), te.admin(), *c); err != nil {
		te.t.Fatalf("set recipients: %v", err)
	}
}

// storedRecipients returns backup.recipients as stored.
func (te *testEnv) storedRecipients() []string {
	te.t.Helper()
	c, err := te.svc.Config(context.Background())
	if err != nil {
		te.t.Fatal(err)
	}
	return c.Recipients
}

// sameSet reports whether a and b hold the same strings, in any order.
func sameSet(a, b []string) bool {
	return slices.Equal(slices.Sorted(slices.Values(a)), slices.Sorted(slices.Values(b)))
}

// abbrev shortens recipients for test messages (a post-quantum one is
// almost 2000 characters).
func abbrev(list []string) []string {
	out := make([]string, len(list))
	for i, r := range list {
		out[i] = truncate(r, 20)
	}
	return out
}

// TestServerRecipientIsAlwaysIncluded: backup.recipients is replaced as a
// whole (backup config set --recipient "replaces the list", the web dialog,
// the generic settings), and backups were encrypted to that list only. Once
// the server's own key was left out, the stored identity could no longer
// verify or restore new backups and the copy of it kept offline could not
// decrypt them; an emptied list even made the next backup switch to a new
// identity nobody had exported.
func TestServerRecipientIsAlwaysIncluded(t *testing.T) {
	te := newTestEnv(t)
	ctx := context.Background()
	own, exported, err := te.svc.GenerateIdentity(ctx, te.admin())
	if err != nil {
		t.Fatal(err)
	}
	exportedIDs, err := parseIdentities(exported)
	if err != nil {
		t.Fatal(err)
	}
	offline, _ := age.GenerateX25519Identity()
	other := offline.Recipient().String()

	backup := func(what string, want ...string) *core.Backup {
		t.Helper()
		b, err := te.svc.CreateSync(ctx, te.sys(), core.BackupInput{Scope: core.BackupMetadata})
		if err != nil {
			t.Fatalf("%s: backup: %v", what, err)
		}
		if !sameSet(b.Recipients, want) {
			t.Fatalf("%s: encrypted to %v, want %v", what, b.Recipients, want)
		}
		return b
	}
	check := func(what string, b *core.Backup) {
		t.Helper()
		if res, err := te.svc.VerifyNow(ctx, b.ID, false, nil); err != nil || !res.OK {
			t.Fatalf("%s: verify with the stored identity: %v %+v", what, err, res)
		}
		if _, err := checkHeaderIdents(ctx, filepath.Join(te.h.BackupsDir(), b.FileName), exportedIDs); err != nil {
			t.Fatalf("%s: the exported identity does not decrypt the backup: %v", what, err)
		}
		if slices.Contains(b.Recipients, other) {
			if _, err := checkHeaderIdents(ctx, filepath.Join(te.h.BackupsDir(), b.FileName), []ageIdentity{offline}); err != nil {
				t.Fatalf("%s: the offline key does not decrypt the backup: %v", what, err)
			}
		}
		if r, _, err := te.svc.ExportIdentity(ctx, te.admin()); err != nil || r != own {
			t.Fatalf("%s: the backup identity changed to %s (%v)", what, r, err)
		}
	}

	// Replaced by another key: the server's own key stays in the list.
	te.setRecipients(other)
	if got := te.storedRecipients(); !slices.Equal(got, []string{other, own}) {
		t.Fatalf("stored recipients %v", got)
	}
	check("replaced list", backup("replaced list", other, own))

	// Emptied: the server's own key, not a new identity.
	te.setRecipients()
	if got := te.storedRecipients(); !slices.Equal(got, []string{own}) {
		t.Fatalf("stored recipients after emptying the list %v", got)
	}
	check("emptied list", backup("emptied list", own))

	// Replaced through the generic settings (stored as given): every backup
	// still includes the server's own key.
	te.set(map[string]any{SettingRecipients: []string{other}})
	check("list set through the settings", backup("list set through the settings", other, own))
	te.set(map[string]any{SettingRecipients: []string{}})
	check("list emptied through the settings", backup("list emptied through the settings", own))

	// Keys locked (sealed, not unlocked yet): the identity cannot be read, so
	// the stored list is used, which SetConfig kept complete.
	te.setRecipients(other)
	unlocked := te.env.Keys
	te.env.Keys = lockedKeys{&fakeKeys{}}
	b := backup("keys locked", other, own)
	te.env.Keys = unlocked
	check("keys locked", b)
}

// TestIdentityFollowsTheRecipientsKind: age cannot encrypt to post-quantum
// and classic recipients together, so when the list switches kind the
// server's own key cannot stay in it as it is: a backup identity of the
// list's kind replaces it (the older ones are kept for older backups), and
// it counts as not exported.
func TestIdentityFollowsTheRecipientsKind(t *testing.T) {
	te := newTestEnv(t)
	ctx := context.Background()
	classic, _, err := te.svc.GenerateIdentity(ctx, te.admin())
	if err != nil {
		t.Fatal(err)
	}
	b1, err := te.svc.CreateSync(ctx, te.sys(), core.BackupInput{Scope: core.BackupMetadata})
	if err != nil {
		t.Fatal(err)
	}
	p, err := age.GenerateHybridIdentity()
	if err != nil {
		t.Fatal(err)
	}
	pq := p.Recipient().String()

	// Through SetConfig: the new identity is made right away.
	te.setRecipients(pq)
	got := te.storedRecipients()
	if len(got) != 2 || got[0] != pq || !strings.HasPrefix(got[1], "age1pq1") || got[1] == pq {
		t.Fatalf("stored recipients after switching to post-quantum: %v", abbrev(got))
	}
	ownPQ := got[1]
	if te.svc.IdentityExportedAt(ctx) != nil {
		t.Fatal("an identity nobody has seen counts as exported")
	}
	b2, err := te.svc.CreateSync(ctx, te.sys(), core.BackupInput{Scope: core.BackupMetadata})
	if err != nil {
		t.Fatalf("backup after switching to post-quantum: %v", err)
	}
	if !sameSet(b2.Recipients, []string{pq, ownPQ}) {
		t.Fatalf("encrypted to %v", abbrev(b2.Recipients))
	}

	// Through the generic settings: the next backup makes it.
	x, _ := age.GenerateX25519Identity()
	te.set(map[string]any{SettingRecipients: []string{x.Recipient().String()}})
	b3, err := te.svc.CreateSync(ctx, te.sys(), core.BackupInput{Scope: core.BackupMetadata})
	if err != nil {
		t.Fatalf("backup after switching back to classic keys: %v", err)
	}
	own, _, err := te.svc.ExportIdentity(ctx, te.admin())
	if err != nil {
		t.Fatal(err)
	}
	if strings.HasPrefix(own, "age1pq1") || own == classic {
		t.Fatalf("identity after switching back to classic keys: %.12s…", own)
	}
	if !sameSet(b3.Recipients, []string{x.Recipient().String(), own}) {
		t.Fatalf("encrypted to %v", abbrev(b3.Recipients))
	}
	// Every backup still verifies with the stored identity file.
	for _, b := range []*core.Backup{b1, b2, b3} {
		if res, err := te.svc.VerifyNow(ctx, b.ID, false, nil); err != nil || !res.OK {
			t.Fatalf("verify %s: %v %+v", b.FileName, err, res)
		}
	}
}

// TestSnapshotDoesNotHoldAReaderConnection: the snapshot borrowed a
// connection of the reader pool for the whole VACUUM INTO. The pool is sized
// by GOMAXPROCS, a single connection on a one-CPU host, so every read of
// every request waited for the snapshot. Here each pooled reader is busy.
func TestSnapshotDoesNotHoldAReaderConnection(t *testing.T) {
	te := newTestEnv(t)
	te.seedData(3)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	r := te.env.DB.Reader()
	n := r.Stats().MaxOpenConnections
	for range n {
		c, err := r.Conn(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
	}
	path := filepath.Join(te.h.TmpDir(""), "snapshot-test.db")
	defer removeDB(path)
	if err := te.svc.snapshot(ctx, path); err != nil {
		t.Fatalf("snapshot with every reader in use: %v", err)
	}
	if st := r.Stats(); st.OpenConnections != n || st.InUse != n {
		t.Fatalf("reader pool after the snapshot: %d open, %d in use (want %d)", st.OpenConnections, st.InUse, n)
	}
	blobs, _, err := readyBlobs(ctx, path)
	if err != nil || len(blobs) != 3 {
		t.Fatalf("snapshot lists %d blobs: %v", len(blobs), err)
	}
	if fi, err := os.Stat(path); err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("snapshot file: %v %v", fi, err)
	}
}

// TestConcurrentImportsGetTheirOwnFiles: two imports of the same archive
// compute the same file name. Choosing a free name and renaming onto it did
// not exclude each other, so both could pick one name: the second rename
// replaced the first file and two rows pointed to one file (deleting either
// then removed the other's data).
func TestConcurrentImportsGetTheirOwnFiles(t *testing.T) {
	te := newTestEnv(t)
	ctx := context.Background()
	if _, _, err := te.svc.GenerateIdentity(ctx, te.admin()); err != nil {
		t.Fatal(err)
	}
	b, err := te.svc.CreateSync(ctx, te.sys(), core.BackupInput{Scope: core.BackupMetadata})
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(te.h.BackupsDir(), b.FileName))
	if err != nil {
		t.Fatal(err)
	}
	const n = 16
	start := make(chan struct{})
	errs := make(chan error, n)
	var wg sync.WaitGroup
	for range n {
		wg.Go(func() {
			<-start
			_, err := te.svc.Import(ctx, te.admin(), bytes.NewReader(data))
			errs <- err
		})
	}
	close(start)
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("import: %v", err)
		}
	}
	dups := tableDump(t, te.env.DB.Reader(), `SELECT file_name, count(*) FROM backups GROUP BY file_name HAVING count(*) > 1`)
	if len(dups) > 0 {
		t.Fatalf("file names shared by several rows: %v", dups)
	}
	ents, err := os.ReadDir(te.h.BackupsDir())
	if err != nil {
		t.Fatal(err)
	}
	files := 0
	for _, e := range ents {
		if strings.HasSuffix(e.Name(), ".partial") {
			t.Fatalf("left behind: %s", e.Name())
		}
		if strings.HasSuffix(e.Name(), ".fpbak") {
			files++
			got, err := os.ReadFile(filepath.Join(te.h.BackupsDir(), e.Name()))
			if err != nil || !bytes.Equal(got, data) {
				t.Fatalf("%s differs from the imported file: %v", e.Name(), err)
			}
		}
	}
	if files != n+1 {
		t.Fatalf("%d backup files, want %d", files, n+1)
	}
}
