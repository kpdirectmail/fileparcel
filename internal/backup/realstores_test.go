package backup

import (
	"bytes"
	"context"
	"crypto/rand"
	"database/sql"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"testing"
	"time"

	"fileparcel/internal/blobstore"
	"fileparcel/internal/config"
	"fileparcel/internal/core"
	"fileparcel/internal/db"
	"fileparcel/internal/events"
	"fileparcel/internal/home"
	"fileparcel/internal/jobs"
	"fileparcel/internal/keys"
	"fileparcel/internal/settings"
)

// realEnv is a home with real keys (plain master key), settings, blob store,
// jobs and backup services — the production stack minus the HTTP layer.
type realEnv struct {
	h     *home.Home
	env   *core.Env
	keys  *keys.Service
	blobs *blobstore.Service
	jobs  *jobs.Service
	svc   *Service
	audit *fakeAudit
}

func newRealEnv(t *testing.T, h *home.Home, initKeys bool) *realEnv {
	t.Helper()
	ctx := context.Background()
	cfg, err := config.Load(h)
	if err != nil {
		t.Fatal(err)
	}
	d, err := db.Open(h.DB())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := d.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	re := &realEnv{h: h, audit: &fakeAudit{}}
	bus := events.New()
	re.env = &core.Env{Home: h, Config: cfg, DB: d, Log: slog.New(slog.NewTextHandler(io.Discard, nil)),
		Clock: core.SystemClock{}, Bus: bus, Audit: re.audit}
	re.env.Build.Version = "vtest"
	if initKeys {
		_ = os.Remove(h.KeysFile()) // newHome writes a placeholder key file
	}
	if re.keys, err = keys.Open(re.env); err != nil {
		t.Fatal(err)
	}
	re.env.Keys = re.keys
	if initKeys {
		if _, err := re.keys.Init(ctx, false, nil); err != nil {
			t.Fatal(err)
		}
	}
	st, err := settings.New(re.env)
	if err != nil {
		t.Fatal(err)
	}
	re.env.Settings = st
	if re.blobs, err = blobstore.New(re.env); err != nil {
		t.Fatal(err)
	}
	if re.jobs, err = jobs.New(re.env); err != nil {
		t.Fatal(err)
	}
	if re.svc, err = New(re.env, re.blobs, re.jobs); err != nil {
		t.Fatal(err)
	}
	if err := re.svc.RegisterJobs(re.jobs); err != nil {
		t.Fatal(err)
	}
	closed := false
	t.Cleanup(func() {
		if !closed {
			closed = true
			re.close()
		}
	})
	return re
}

func (re *realEnv) close() {
	_ = re.jobs.Stop(context.Background())
	_ = re.svc.Close()
	_ = re.blobs.Close()
	if c, ok := re.env.Settings.(io.Closer); ok {
		_ = c.Close()
	}
	re.env.Bus.Close()
	_ = re.env.DB.Close()
}

// putBlob stores data as a new blob and returns its id.
func (re *realEnv) putBlob(t *testing.T, data []byte) string {
	t.Helper()
	ctx := context.Background()
	w, err := re.blobs.Create(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write(data); err != nil {
		t.Fatal(err)
	}
	bi, err := w.Commit(ctx)
	if err != nil {
		t.Fatal(err)
	}
	return bi.ID
}

func readBlob(t *testing.T, bs core.BlobStore, id string) []byte {
	t.Helper()
	r, err := bs.Open(context.Background(), id)
	if err != nil {
		t.Fatalf("open blob %s: %v", id, err)
	}
	defer r.Close()
	b, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("read blob %s: %v", id, err)
	}
	return b
}

// TestRealStoresDeepVerifyAndRestore runs the whole cycle with the real key
// service and blob store: full backup → deep verify (every blob decrypted
// with the backup's own keys) → offline restore into another installation →
// every row and blob readable with the restored keys.
func TestRealStoresDeepVerifyAndRestore(t *testing.T) {
	ctx := context.Background()
	src := newRealEnv(t, newHome(t), true)
	contents := map[string][]byte{}
	for _, n := range []int{0, 1, 65536, 65537, 200_000} {
		data := make([]byte, n)
		_, _ = rand.Read(data)
		contents[src.putBlob(t, data)] = data
	}
	_, identity, err := src.svc.GenerateIdentity(ctx, core.SystemPrincipal(core.ViaOffline))
	if err != nil {
		t.Fatal(err)
	}
	b, err := src.svc.CreateSync(ctx, core.SystemPrincipal(core.ViaOffline), core.BackupInput{Scope: core.BackupFull})
	if err != nil {
		t.Fatal(err)
	}
	if b.BlobCount != int64(len(contents)) {
		t.Fatalf("blob count %d, want %d", b.BlobCount, len(contents))
	}

	res, err := src.svc.VerifyNow(ctx, b.ID, true, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !res.OK || res.BlobsVerified != int64(len(contents)) || res.BlobsFailed != 0 {
		t.Fatalf("deep verify: %+v", res)
	}
	// The temporary verification home is gone.
	if ents, _ := os.ReadDir(src.h.TmpDir(home.TmpVerify)); len(ents) != 0 {
		t.Fatalf("verify home left behind: %v", ents)
	}

	wantBlobs := tableDump(t, src.env.DB.Reader(), `SELECT id, state, size, stored_size, cipher, kek_id, hex(wrapped_dek), content_hash FROM blobs ORDER BY id`)
	wantKeyring := tableDump(t, src.env.DB.Reader(), `SELECT id, purpose, mk_id, hex(wrapped), state FROM keyring ORDER BY id`)

	// Restore into a different installation (its own keys and data are replaced).
	dstHome := newHome(t)
	dst := newRealEnv(t, dstHome, true)
	other := dst.putBlob(t, []byte("belongs to the other installation"))
	if err := dst.svc.RestoreOffline(ctx, filepath.Join(src.h.BackupsDir(), b.FileName),
		core.RestoreCreds{Identity: identity}, core.RestoreOpts{}); err != nil {
		t.Fatal(err)
	}
	dst.close()

	// Reopen the restored home with fresh services.
	re := newRealEnv(t, dstHome, false)
	if re.keys.State() != core.KeyStateUnlocked {
		t.Fatalf("restored keys %s", re.keys.State())
	}
	if got := tableDump(t, re.env.DB.Reader(), `SELECT id, state, size, stored_size, cipher, kek_id, hex(wrapped_dek), content_hash FROM blobs ORDER BY id`); !slices.Equal(got, wantBlobs) {
		t.Fatalf("blob rows differ:\n%v\n%v", got, wantBlobs)
	}
	if got := tableDump(t, re.env.DB.Reader(), `SELECT id, purpose, mk_id, hex(wrapped), state FROM keyring ORDER BY id`); !slices.Equal(got, wantKeyring) {
		t.Fatal("keyring differs")
	}
	for id, data := range contents {
		if got := readBlob(t, re.blobs, id); !bytes.Equal(got, data) {
			t.Fatalf("blob %s differs after restore", id)
		}
	}
	if _, err := re.blobs.Open(ctx, other); err == nil {
		t.Fatal("a blob of the replaced installation is still visible")
	}
	// The restored settings (sealed with the restored field KEK) decrypt.
	if got, err := re.env.Settings.Secret(SettingIdentity); err != nil || got == "" {
		t.Fatalf("restored backup identity: %q %v", got, err)
	}
}

// TestRealStoresDeepVerifyDetectsDamagedBlob damages a blob file on disk
// before the backup: the archive checksums still match, but decrypting the
// blob with the backup's keys fails.
func TestRealStoresDeepVerifyDetectsDamagedBlob(t *testing.T) {
	ctx := context.Background()
	src := newRealEnv(t, newHome(t), true)
	good := src.putBlob(t, bytes.Repeat([]byte("x"), 70000))
	bad := src.putBlob(t, bytes.Repeat([]byte("y"), 70000))
	p := blobPath(src.h, bad)
	raw, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	raw[len(raw)-40] ^= 0xff
	if err := os.WriteFile(p, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := src.svc.GenerateIdentity(ctx, core.SystemPrincipal(core.ViaOffline)); err != nil {
		t.Fatal(err)
	}
	b, err := src.svc.CreateSync(ctx, core.SystemPrincipal(core.ViaOffline), core.BackupInput{Scope: core.BackupFull})
	if err != nil {
		t.Fatal(err)
	}
	shallow, err := src.svc.VerifyNow(ctx, b.ID, false, nil)
	if err != nil || !shallow.OK {
		t.Fatalf("shallow verify: %+v %v", shallow, err)
	}
	res, err := src.svc.VerifyNow(ctx, b.ID, true, nil)
	if err != nil {
		t.Fatal(err)
	}
	if res.OK || res.BlobsFailed != 1 || res.BlobsVerified != 1 || !bytes.Contains([]byte(res.Error), []byte(bad)) {
		t.Fatalf("deep verify of a damaged blob: %+v (good %s)", res, good)
	}
	got, _ := src.svc.Get(ctx, b.ID)
	if got.VerifyOK == nil || *got.VerifyOK {
		t.Fatal("failed verification not recorded")
	}
}

// TestRealStoresBackupBlocksAKeyRotation reproduces the original problem with
// the real key service: a master key rotation between the database snapshot
// (VACUUM INTO, minutes on a big installation) and keys/master.key produced a
// "ready" backup whose archived key file belonged to a different master key.
// The row said ready, the default verification passed, restoreHome moved the
// live data aside — and the restored server refused to start. The rotation
// must lose that race instead.
func TestRealStoresBackupBlocksAKeyRotation(t *testing.T) {
	ctx := context.Background()
	src := newRealEnv(t, newHome(t), true)
	contents := map[string][]byte{}
	data := []byte("some file data")
	contents[src.putBlob(t, data)] = data
	_, identity, err := src.svc.GenerateIdentity(ctx, core.SystemPrincipal(core.ViaOffline))
	if err != nil {
		t.Fatal(err)
	}
	plan, err := src.svc.encryptionPlan(ctx)
	if err != nil {
		t.Fatal(err)
	}
	before, _, err := getMetaValue(ctx, src.env.DB, "mk_id")
	if err != nil {
		t.Fatal(err)
	}
	var rotErr error
	var once sync.Once
	h := hookHandle{fn: func(note string) {
		if note != "database" {
			return
		}
		// Right after the snapshot, before the key file is archived.
		once.Do(func() { rotErr = src.keys.RotateMaster(ctx) })
	}}
	hdr := Header{Format: FormatName, Version: FormatVersion, BackupID: "bak_0000000000000000000000000",
		AppVersion: "vtest", SchemaVersion: db.LatestVersion(), Scope: core.BackupFull,
		InstallID: install8(src.env.Config.InstallID), CreatedAt: time.Now().UTC().Truncate(time.Second),
		Encryption: plan.mode}
	if _, err := src.svc.writeArchive(ctx, hdr, "probe.fpbak", plan, h); err != nil {
		t.Fatalf("write archive: %v", err)
	}
	if !isCode(rotErr, core.ErrConflict) {
		t.Fatalf("the master key rotation was not blocked while the key material was copied: %v", rotErr)
	}
	if after, _, _ := getMetaValue(ctx, src.env.DB, "mk_id"); after != before {
		t.Fatalf("the master key changed under the backup: %s → %s", before, after)
	}
	// Once the archive is written, the rotation goes through.
	if err := src.keys.RotateMaster(ctx); err != nil {
		t.Fatalf("rotation after the backup: %v", err)
	}
	// The archive restores into a fresh installation that starts up.
	dstHome := newHome(t)
	dst := newRealEnv(t, dstHome, true)
	if err := dst.svc.RestoreOffline(ctx, filepath.Join(src.h.BackupsDir(), "probe.fpbak"),
		core.RestoreCreds{Identity: identity}, core.RestoreOpts{}); err != nil {
		t.Fatalf("restore: %v", err)
	}
	dst.close()
	re := newRealEnv(t, dstHome, false) // keys.Open refuses a foreign key file
	if re.keys.State() != core.KeyStateUnlocked {
		t.Fatalf("restored keys %s", re.keys.State())
	}
	for id, want := range contents {
		if got := readBlob(t, re.blobs, id); !bytes.Equal(got, want) {
			t.Fatalf("blob %s differs after restore", id)
		}
	}
}

// getMetaValue reads one meta row.
func getMetaValue(ctx context.Context, d *db.DB, key string) (string, bool, error) {
	var v string
	err := d.QueryRow(ctx, `SELECT value FROM meta WHERE key = ?`, key).Scan(&v)
	if errors.Is(err, sql.ErrNoRows) {
		return "", false, nil
	}
	return v, err == nil, err
}

// TestRealStoresMetadataRestoreSurvivesGC: a metadata restore keeps the
// installation's blob store and moved only the replaced database into
// pre-restore-<ts>/. Files uploaded after the backup have no row in the
// restored database, so the nightly blob GC deletes them as orphans — and
// the documented undo (put pre-restore-<ts>/data back) found a database
// whose newer files had no data any more. pre-restore now holds hard links.
func TestRealStoresMetadataRestoreSurvivesGC(t *testing.T) {
	ctx := context.Background()
	sys := core.SystemPrincipal(core.ViaOffline)
	src := newRealEnv(t, newHome(t), true)
	before := []byte("uploaded before the backup")
	a := src.putBlob(t, before)
	_, identity, err := src.svc.GenerateIdentity(ctx, sys)
	if err != nil {
		t.Fatal(err)
	}
	b, err := src.svc.CreateSync(ctx, sys, core.BackupInput{Scope: core.BackupMetadata})
	if err != nil {
		t.Fatal(err)
	}
	after := []byte("uploaded after the backup")
	later := src.putBlob(t, after)
	old := time.Now().Add(-72 * time.Hour)
	if err := os.Chtimes(blobPath(src.h, later), old, old); err != nil {
		t.Fatal(err)
	}
	rep, err := src.svc.RestoreOfflineReport(ctx, b.ID, core.RestoreCreds{Identity: identity}, core.RestoreOpts{})
	if err != nil {
		t.Fatal(err)
	}
	src.close()

	re := newRealEnv(t, src.h, false)
	if removed, _, err := re.blobs.GC(ctx, 48*time.Hour); err != nil || removed == 0 {
		t.Fatalf("blob GC after the restore: removed %d, %v", removed, err)
	}
	if _, err := os.Stat(blobPath(src.h, later)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("GC kept the blob the restored database does not know (test premise): %v", err)
	}
	if got := readBlob(t, re.blobs, a); !bytes.Equal(got, before) {
		t.Fatal("a blob of the restored database differs")
	}
	re.close()

	// Undo by hand: the replaced data goes back in place.
	if err := os.Rename(src.h.DataDir(), filepath.Join(t.TempDir(), "restored-data")); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(filepath.Join(rep.PreRestore, "data"), src.h.DataDir()); err != nil {
		t.Fatal(err)
	}
	un := newRealEnv(t, src.h, false)
	if got := readBlob(t, un.blobs, later); !bytes.Equal(got, after) {
		t.Fatal("the file uploaded after the backup is gone after undoing the restore")
	}
}
