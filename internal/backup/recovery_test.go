package backup

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"filippo.io/age"

	"fileparcel/internal/core"
	"fileparcel/internal/db"
	"fileparcel/internal/events"
	"fileparcel/internal/home"
	"fileparcel/internal/ids"
)

// TestInterruptedBackupWithCompleteArchive: the archive gets its final name
// only once it is complete; the copy to backup.copy_to and the "ready"
// record come after that. A crash in between left a row marked failed
// ("interrupted") next to a valid archive, which the failed-row cleanup of
// Prune deleted a week later — with retention turned off, too.
func TestInterruptedBackupWithCompleteArchive(t *testing.T) {
	te := newTestEnv(t)
	ctx := context.Background()
	te.set(map[string]any{SettingKeepLast: 0, SettingKeepDaily: 0, SettingKeepWeekly: 0, SettingKeepMonthly: 0})
	if _, _, err := te.svc.GenerateIdentity(ctx, te.admin()); err != nil {
		t.Fatal(err)
	}
	b, err := te.svc.CreateSync(ctx, te.sys(), core.BackupInput{Scope: core.BackupMetadata})
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(te.h.BackupsDir(), b.FileName)
	// As if the server had died after the rename, eight days ago…
	weekAgo := db.Ms(time.Now().Add(-8 * 24 * time.Hour))
	if _, err := te.env.DB.Exec(ctx, `UPDATE backups SET state = 'running', size = NULL, sha256 = NULL, finished_at = NULL,
		created_at = ? WHERE id = ?`, weekAgo, b.ID); err != nil {
		t.Fatal(err)
	}
	// …and another backup before its archive was complete.
	const torn = "bak_0000000000000000000000000y"
	if _, err := te.env.DB.Exec(ctx, `INSERT INTO backups (id, scope, state, file_name, encryption, "trigger", created_at)
		VALUES (?, 'full', 'running', 'fp-torn.fpbak', 'x25519', 'manual', ?)`, torn, weekAgo); err != nil {
		t.Fatal(err)
	}
	s2, err := New(te.env, nil, te.jobs)
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close()
	got, err := s2.Get(ctx, b.ID)
	if err != nil || got.State != core.BackupReady || got.Size != b.Size || got.Error != interruptedAfterWriteMsg {
		t.Fatalf("complete archive after a crash: %+v %v", got, err)
	}
	if g, err := s2.Get(ctx, torn); err != nil || g.State != core.BackupFailed || !strings.Contains(g.Error, "interrupted") {
		t.Fatalf("incomplete backup after a crash: %+v %v", g, err)
	}
	if res, err := s2.VerifyNow(ctx, b.ID, false, nil); err != nil || !res.OK {
		t.Fatalf("verify the recovered backup: %v %+v", err, res)
	}
	n, err := s2.Prune(ctx)
	if err != nil || n != 1 {
		t.Fatalf("prune: deleted %d (want the failed row without an archive), %v", n, err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("the complete archive was pruned: %v", err)
	}
	if _, err := s2.Get(ctx, torn); !isCode(err, core.ErrNotFound) {
		t.Fatalf("the failed row without an archive was kept: %v", err)
	}
}

// TestScratchLeftoversAreSweptAtStart: restore staging, deep-verify homes,
// database snapshots and member indexes under tmp/ were removed only by the
// process that made them. After a hard kill they stayed forever — a restore
// staging directory as large as the data, and a leftover that made every
// later restore fail its free-space check.
func TestScratchLeftoversAreSweptAtStart(t *testing.T) {
	te := newTestEnv(t)
	ctx := context.Background()
	tmp := te.h.TmpDir("")
	restoreDir := te.h.TmpDir(home.TmpRestore)
	verifyDir := te.h.TmpDir(home.TmpVerify)
	leftovers := []string{
		filepath.Join(restoreDir, "restore-123", "keys", "master.key"),
		filepath.Join(restoreDir, "restore-123", "data", "blobs", "ab", "cd", "x"),
		filepath.Join(verifyDir, "verify-456", "data", "fileparcel.db"),
		filepath.Join(tmp, "snapshot-bak_0000000000000000000000000x.db"),
		filepath.Join(tmp, "snapshot-bak_0000000000000000000000000x.db-wal"),
		filepath.Join(tmp, "members-123456.ndjson"),
	}
	kept := []string{
		filepath.Join(tmp, "release-abc", "docs", "a.md"), // a running "fileparcel upgrade"
		filepath.Join(tmp, "uploads", "u1"),
		filepath.Join(tmp, "keep.txt"),
		filepath.Join(tmp, "snapshot-notes.txt"),
	}
	for _, p := range append(slices.Clone(leftovers), kept...) {
		mustWrite(t, p, []byte("x"))
	}
	outside := filepath.Join(t.TempDir(), "outside")
	mustWrite(t, filepath.Join(outside, "victim"), []byte("not ours"))
	if err := os.Symlink(outside, filepath.Join(restoreDir, "restore-link")); err != nil {
		t.Fatal(err)
	}

	s2, err := New(te.env, nil, te.jobs)
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close()
	for _, p := range append(leftovers, filepath.Join(restoreDir, "restore-123"), filepath.Join(verifyDir, "verify-456"),
		filepath.Join(restoreDir, "restore-link")) {
		if _, err := os.Lstat(p); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("left behind: %s (%v)", p, err)
		}
	}
	for _, p := range append(kept, restoreDir, verifyDir, filepath.Join(outside, "victim")) {
		if _, err := os.Stat(p); err != nil {
			t.Errorf("removed: %s (%v)", p, err)
		}
	}
	// Every server start sweeps before a pending restore checks its space,
	// whether one is pending or not.
	mustWrite(t, leftovers[0], []byte("x"))
	if applied, err := ApplyPendingRestore(ctx, te.h, nil); applied || err != nil {
		t.Fatalf("nothing pending: %v %v", applied, err)
	}
	if _, err := os.Lstat(filepath.Join(restoreDir, "restore-123")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("ApplyPendingRestore left the staging directory: %v", err)
	}
}

// TestVerifyKeepsTheCopyError: the error of a ready backup is the only
// record that its copy to backup.copy_to failed. A verification cleared it
// (or replaced it with its own message), so the list showed "ready,
// verified" and nothing said the off-site copy was missing.
func TestVerifyKeepsTheCopyError(t *testing.T) {
	for _, tt := range []struct{ cur, msg, want string }{
		{"", "", ""},
		{"", "bad", "verification failed: bad"},
		{"verification failed: old", "", ""},
		{"verification failed: old", "new", "verification failed: new"},
		{"copy to /x failed: y", "", "copy to /x failed: y"},
		{"copy to /x failed: y", "bad", "copy to /x failed: y; verification failed: bad"},
		{"copy to /x failed: y; verification failed: old", "", "copy to /x failed: y"},
		{"copy to /x failed: y; verification failed: old", "new", "copy to /x failed: y; verification failed: new"},
	} {
		if got := withVerifyError(tt.cur, tt.msg); got != tt.want {
			t.Errorf("withVerifyError(%q, %q) = %q, want %q", tt.cur, tt.msg, got, tt.want)
		}
	}

	te := newTestEnv(t)
	ctx := context.Background()
	if _, _, err := te.svc.GenerateIdentity(ctx, te.admin()); err != nil {
		t.Fatal(err)
	}
	notADir := filepath.Join(t.TempDir(), "not-a-dir")
	mustWrite(t, notADir, []byte("x"))
	b, err := te.svc.CreateSync(ctx, te.sys(), core.BackupInput{Scope: core.BackupMetadata, CopyTo: notADir})
	if err != nil || b.State != core.BackupReady || b.CopiedTo != "" || !strings.HasPrefix(b.Error, "copy to ") {
		t.Fatalf("backup with a failed copy: %+v %v", b, err)
	}
	copyErr := b.Error
	check := func(wantOK bool, wantErr string) {
		t.Helper()
		got, err := te.svc.Get(ctx, b.ID)
		if err != nil || got.VerifyOK == nil || *got.VerifyOK != wantOK || got.Error != wantErr {
			t.Fatalf("after verify: ok=%v error=%q (want %v %q) %v", got.VerifyOK, got.Error, wantOK, wantErr, err)
		}
	}
	if res, err := te.svc.VerifyNow(ctx, b.ID, false, nil); err != nil || !res.OK {
		t.Fatalf("verify: %v %+v", err, res)
	}
	check(true, copyErr)
	path := filepath.Join(te.h.BackupsDir(), b.FileName)
	raw, _ := os.ReadFile(path)
	bad := slices.Clone(raw)
	bad[len(bad)-40] ^= 0x01
	mustWrite(t, path, bad)
	res, err := te.svc.VerifyNow(ctx, b.ID, false, nil)
	if err != nil || res.OK {
		t.Fatalf("verify of a damaged archive: %v %+v", err, res)
	}
	check(false, copyErr+"; "+verifyErrPrefix+res.Error)
	mustWrite(t, path, raw)
	if res, err := te.svc.VerifyNow(ctx, b.ID, false, nil); err != nil || !res.OK {
		t.Fatalf("verify after the repair: %v %+v", err, res)
	}
	check(true, copyErr)
}

// TestOfflineRestoreAuditsOnce: the success entry of an offline restore was
// written before anything was checked, so a restore that then failed (wrong
// identity, damaged archive, no space) was logged as a success and a failure.
func TestOfflineRestoreAuditsOnce(t *testing.T) {
	ctx := context.Background()
	src := newTestEnv(t)
	_, identity, err := src.svc.GenerateIdentity(ctx, src.admin())
	if err != nil {
		t.Fatal(err)
	}
	b, err := src.svc.CreateSync(ctx, src.sys(), core.BackupInput{Scope: core.BackupMetadata})
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(src.h.BackupsDir(), b.FileName)
	dst := newTestEnv(t)
	restores := func(from int) []string {
		var out []string
		for _, a := range dst.audit.actions()[from:] {
			if strings.HasPrefix(a, core.ActBackupRestore+":") {
				out = append(out, a)
			}
		}
		return out
	}
	other, _ := age.GenerateX25519Identity()
	n := len(dst.audit.actions())
	if err := dst.svc.RestoreOffline(ctx, path, core.RestoreCreds{Identity: other.String()}, core.RestoreOpts{}); !isCode(err, core.ErrForbidden) {
		t.Fatalf("wrong identity: %v", err)
	}
	if got := restores(n); !slices.Equal(got, []string{core.ActBackupRestore + ":" + core.OutcomeFailure}) {
		t.Fatalf("failed restore audited as %v", got)
	}
	n = len(dst.audit.actions())
	if _, err := dst.svc.RestoreOfflineReport(ctx, path, core.RestoreCreds{Identity: identity}, core.RestoreOpts{DryRun: true}); err != nil {
		t.Fatal(err)
	}
	if got := restores(n); len(got) != 0 {
		t.Fatalf("dry run audited as %v", got)
	}
	n = len(dst.audit.actions())
	if _, err := dst.svc.RestoreOfflineReport(ctx, path, core.RestoreCreds{Identity: identity}, core.RestoreOpts{}); err != nil {
		t.Fatal(err)
	}
	if got := restores(n); !slices.Equal(got, []string{core.ActBackupRestore + ":" + core.OutcomeSuccess}) {
		t.Fatalf("restore audited as %v", got)
	}
	dst.audit.mu.Lock()
	last := dst.audit.entries[len(dst.audit.entries)-1]
	dst.audit.mu.Unlock()
	if d, _ := last.Details.(map[string]any); d["backup_id"] != b.ID {
		t.Fatalf("restore entry details %v", last.Details)
	}
}

// TestImportRejectsDamagedArchives: a file the configured identity decrypts
// but that is damaged or not a FileParcel archive was registered as a ready
// full backup "not decryptable with the configured identity" — sending the
// admin to look for other credentials for a file no credentials can restore.
func TestImportRejectsDamagedArchives(t *testing.T) {
	te := newTestEnv(t)
	ctx := context.Background()
	rec, _, err := te.svc.GenerateIdentity(ctx, te.admin())
	if err != nil {
		t.Fatal(err)
	}
	r, err := age.ParseX25519Recipient(rec)
	if err != nil {
		t.Fatal(err)
	}
	var plain bytes.Buffer
	w, err := age.Encrypt(&plain, r)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = w.Write([]byte("plain text, not a backup"))
	_ = w.Close()
	b, err := te.svc.CreateSync(ctx, te.sys(), core.BackupInput{Scope: core.BackupMetadata})
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(filepath.Join(te.h.BackupsDir(), b.FileName))
	for name, body := range map[string][]byte{"not an archive": plain.Bytes(), "truncated": raw[:400]} {
		if _, err := te.svc.Import(ctx, te.admin(), bytes.NewReader(body)); !isCode(err, core.ErrInvalid) ||
			!strings.Contains(err.Error(), "not a usable FileParcel backup") {
			t.Errorf("%s: %v", name, err)
		}
	}
	ents, _ := os.ReadDir(te.h.BackupsDir())
	if len(ents) != 1 || ents[0].Name() != b.FileName {
		t.Fatalf("files left behind: %v", ents)
	}
	// A backup for other credentials is still registered (ErrForbidden).
	other, _ := age.GenerateX25519Identity()
	foreign := craftArchive(t, other.Recipient(), validMembers(t, testHeader(db.LatestVersion()), nil))
	imp, err := te.svc.Import(ctx, te.admin(), bytes.NewReader(foreign))
	if err != nil || !strings.Contains(imp.Note, "not decryptable") {
		t.Fatalf("import of a backup for other credentials: %+v %v", imp, err)
	}
}

// backupRows lists the backups rows of the database of h as
// "id state file_name trigger", sorted.
func backupRows(t *testing.T, h *home.Home) []string {
	t.Helper()
	d, err := db.Open(h.DB())
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	got := tableDump(t, d.Reader(), `SELECT id || ' ' || state || ' ' || file_name || ' ' || "trigger" FROM backups`)
	slices.Sort(got)
	return got
}

// TestRestoreReconcilesBackupRows: the restored database lists the backups
// that existed when it was taken. Rows whose file is not in backups/ after
// the restore (a new machine, or pruned since) stayed "ready" — including
// the restored backup's own row when it came from a USB disk — offering
// downloads and restores that fail, and keeping the "last backup" checks
// green. An imported copy of it was listed twice.
func TestRestoreReconcilesBackupRows(t *testing.T) {
	ctx := context.Background()
	src := newTestEnv(t)
	_, identity, err := src.svc.GenerateIdentity(ctx, src.admin())
	if err != nil {
		t.Fatal(err)
	}
	b1, err := src.svc.CreateSync(ctx, src.sys(), core.BackupInput{Scope: core.BackupMetadata})
	if err != nil {
		t.Fatal(err)
	}
	b2, err := src.svc.CreateSync(ctx, src.sys(), core.BackupInput{Scope: core.BackupMetadata, Note: "second"})
	if err != nil {
		t.Fatal(err)
	}
	p2 := filepath.Join(src.h.BackupsDir(), b2.FileName)
	creds := core.RestoreCreds{Identity: identity}

	// A new machine, restored from a USB disk: no backup file is there.
	fresh := newTestEnv(t)
	if _, err := fresh.svc.RestoreOfflineReport(ctx, p2, creds, core.RestoreOpts{}); err != nil {
		t.Fatal(err)
	}
	fresh.close()
	if got := backupRows(t, fresh.h); len(got) != 0 {
		t.Fatalf("rows without files after a restore on a new machine: %v", got)
	}

	// Restored from an imported copy with another name: one row, its own.
	imported := newTestEnv(t)
	const copyName = "fp-import-20260101-000000-full.fpbak"
	raw, _ := os.ReadFile(p2)
	mustWrite(t, filepath.Join(imported.h.BackupsDir(), copyName), raw)
	if _, err := imported.svc.RestoreOfflineReport(ctx, filepath.Join(imported.h.BackupsDir(), copyName), creds,
		core.RestoreOpts{}); err != nil {
		t.Fatal(err)
	}
	imported.close()
	if got, want := backupRows(t, imported.h), []string{b2.ID + " ready " + copyName + " manual"}; !slices.Equal(got, want) {
		t.Fatalf("rows after restoring an imported copy: %v, want %v", got, want)
	}

	// The same machine, where the older backup was deleted since.
	if err := os.Remove(filepath.Join(src.h.BackupsDir(), b1.FileName)); err != nil {
		t.Fatal(err)
	}
	if _, err := src.svc.RestoreOfflineReport(ctx, b2.ID, creds, core.RestoreOpts{}); err != nil {
		t.Fatal(err)
	}
	src.close()
	if got, want := backupRows(t, src.h), []string{b2.ID + " ready " + b2.FileName + " manual"}; !slices.Equal(got, want) {
		t.Fatalf("rows after a restore on the same machine: %v, want %v", got, want)
	}
}

// TestScheduleRestoreChecksFreeSpace: the web restore restarted the server
// before anything checked the disk; a restore that could not fit then failed
// at boot, recorded only in run/restore.json.failed.
func TestScheduleRestoreChecksFreeSpace(t *testing.T) {
	te := newTestEnv(t)
	ctx := context.Background()
	rec, _, err := te.svc.GenerateIdentity(ctx, te.admin())
	if err != nil {
		t.Fatal(err)
	}
	r, err := age.ParseX25519Recipient(rec)
	if err != nil {
		t.Fatal(err)
	}
	hdr := testHeader(db.LatestVersion())
	hdr.DBSize = 1 << 50 // a petabyte of database: nothing has room for it
	const name = "fp-huge-metadata.fpbak"
	mustWrite(t, filepath.Join(te.h.BackupsDir(), name), craftArchive(t, r, validMembers(t, hdr, nil)))
	id := ids.New(ids.PrefixBackup)
	if _, err := te.env.DB.Exec(ctx, `INSERT INTO backups (id, scope, state, file_name, encryption, "trigger", created_at)
		VALUES (?, 'metadata', 'ready', ?, 'x25519', 'import', ?)`, id, name, db.Ms(time.Now())); err != nil {
		t.Fatal(err)
	}
	restart, cancel := te.bus.Subscribe(events.TopicSystemRestart)
	defer cancel()
	err = te.svc.ScheduleRestore(ctx, te.admin(), id, core.RestoreCreds{})
	if !isCode(err, core.ErrQuota) || !strings.Contains(err.Error(), "free disk space") {
		t.Fatalf("scheduling a restore without room: %v", err)
	}
	for _, p := range []string{te.h.RestoreFile(), filepath.Join(te.h.RunDir(), restoreKeyName)} {
		if _, err := os.Stat(p); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("%s written: %v", p, err)
		}
	}
	select {
	case <-restart:
		t.Fatal("restart requested for a restore that cannot fit")
	case <-time.After(200 * time.Millisecond):
	}
}

// TestMetadataRestoreReportsMissingData: a metadata restore keeps the file
// data of the installation and brings a database that may not match it — a
// metadata backup taken before "keys rotate --data" (every file has a new
// blob id since) or of another installation. Its files then cannot be
// opened; the restore says so, in a dry run too.
func TestMetadataRestoreReportsMissingData(t *testing.T) {
	ctx := context.Background()
	src := newTestEnv(t)
	srcBlobs := src.seedData(2)
	_, identity, err := src.svc.GenerateIdentity(ctx, src.admin())
	if err != nil {
		t.Fatal(err)
	}
	b, err := src.svc.CreateSync(ctx, src.sys(), core.BackupInput{Scope: core.BackupMetadata})
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(src.h.BackupsDir(), b.FileName)
	creds := core.RestoreCreds{Identity: identity}
	dst := newTestEnv(t)
	dst.seedData(1)
	rep, err := dst.svc.RestoreOfflineReport(ctx, path, creds, core.RestoreOpts{DryRun: true})
	if err != nil || rep.ListedBlobs != 2 || rep.MissingBlobs != 2 {
		t.Fatalf("dry run: %+v %v", rep, err)
	}
	for id, data := range srcBlobs { // one of them is there after all
		mustWrite(t, blobPath(dst.h, id), data)
		break
	}
	rep, err = dst.svc.RestoreOfflineReport(ctx, path, creds, core.RestoreOpts{})
	if err != nil || rep.ListedBlobs != 2 || rep.MissingBlobs != 1 {
		t.Fatalf("restore: %+v %v", rep, err)
	}
	info, err := os.ReadFile(filepath.Join(rep.PreRestore, "RESTORE-INFO.txt"))
	if err != nil || !strings.Contains(string(info), "1 of the 2 stored files") {
		t.Fatalf("RESTORE-INFO.txt: %q %v", info, err)
	}
	// A full restore brings the file data along: nothing to report.
	full := newTestEnv(t)
	full.seedData(1)
	fb, err := full.svc.CreateSync(ctx, full.sys(), core.BackupInput{Scope: core.BackupFull})
	if err != nil {
		t.Fatal(err)
	}
	rep, err = full.svc.RestoreOfflineReport(ctx, fb.ID, core.RestoreCreds{}, core.RestoreOpts{DryRun: true})
	if err != nil || rep.ListedBlobs != 0 || rep.MissingBlobs != 0 {
		t.Fatalf("full dry run: %+v %v", rep, err)
	}
}

// TestMetadataRestoreWithoutHardLinks: where the file system has no hard
// links, the kept blobs the restored database does not list — the ones the
// restored server would delete — are moved into pre-restore instead, and
// RESTORE-INFO.txt names the ones that stay only in the live store.
func TestMetadataRestoreWithoutHardLinks(t *testing.T) {
	old := linkFile
	linkFile = func(string, string) error { return &os.LinkError{Op: "link", Err: errors.ErrUnsupported} }
	defer func() { linkFile = old }()
	ctx := context.Background()
	src := newTestEnv(t)
	srcBlobs := src.seedData(1)
	_, identity, err := src.svc.GenerateIdentity(ctx, src.admin())
	if err != nil {
		t.Fatal(err)
	}
	b, err := src.svc.CreateSync(ctx, src.sys(), core.BackupInput{Scope: core.BackupMetadata})
	if err != nil {
		t.Fatal(err)
	}
	dst := newTestEnv(t)
	dstBlobs := dst.seedData(2)
	var shared string
	for id, data := range srcBlobs { // also in the kept store, and listed by the restored database
		shared = id
		mustWrite(t, blobPath(dst.h, id), data)
	}
	rep, err := dst.svc.RestoreOfflineReport(ctx, filepath.Join(src.h.BackupsDir(), b.FileName),
		core.RestoreCreds{Identity: identity}, core.RestoreOpts{})
	if err != nil {
		t.Fatal(err)
	}
	for id, data := range dstBlobs {
		moved := filepath.Join(rep.PreRestore, "data", "blobs", id[0:2], id[2:4], id)
		if got, err := os.ReadFile(moved); err != nil || !bytes.Equal(got, data) {
			t.Fatalf("blob %s unknown to the restored database not moved into pre-restore: %v", id, err)
		}
		if _, err := os.Stat(blobPath(dst.h, id)); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("blob %s still in the live store: %v", id, err)
		}
	}
	if _, err := os.Stat(blobPath(dst.h, shared)); err != nil {
		t.Fatalf("a blob of the restored database was taken from the live store: %v", err)
	}
	info, _ := os.ReadFile(filepath.Join(rep.PreRestore, "RESTORE-INFO.txt"))
	if !strings.Contains(string(info), "1 stored files could not be linked") {
		t.Fatalf("RESTORE-INFO.txt: %q", info)
	}
}
