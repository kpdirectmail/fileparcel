package keys

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"fileparcel/internal/blobstore"
	"fileparcel/internal/core"
	"fileparcel/internal/crypt"
	"fileparcel/internal/db"
	"fileparcel/internal/ids"
)

// TestCheckPassphraseCountsCharacters: the minimum is 8 characters, not 8
// bytes (the error says characters, and every other password minimum counts
// runes); the maximum stays 1024 bytes.
func TestCheckPassphraseCountsCharacters(t *testing.T) {
	for _, bad := range []string{"😀😀😀", "1234567", "日本語日本語日"} { // 12, 7 and 21 bytes
		err := checkPassphrase("p", []byte(bad))
		errIs(t, err, core.ErrInvalid, fmt.Sprintf("%q", bad))
		if !strings.Contains(err.Error(), "at least 8 characters") {
			t.Errorf("%q: message %q", bad, err)
		}
	}
	for _, good := range [][]byte{[]byte("12345678"), []byte("日本語日本語日本"), bytes.Repeat([]byte("é"), 512),
		bytes.Repeat([]byte{0xff}, 8) /* an invalid UTF-8 byte counts as one */} {
		if err := checkPassphrase("p", good); err != nil {
			t.Errorf("%q refused: %v", good, err)
		}
	}
	errIs(t, checkPassphrase("p", bytes.Repeat([]byte("é"), 513)), core.ErrInvalid, "1026 bytes")
	te := newTestEnv(t)
	s := te.initPlain(t)
	errIs(t, s.Seal(ctx, []byte("😀😀😀")), core.ErrInvalid, "seal with a 3-character passphrase")
}

// liveMK returns a copy of the loaded master key.
func liveMK(t *testing.T, s *Service) []byte {
	t.Helper()
	var mk []byte
	if err := s.withMK(func(k []byte) error { mk = bytes.Clone(k); return nil }); err != nil {
		t.Fatal(err)
	}
	return mk
}

// diskFile parses keys/master.key.
func diskFile(t *testing.T, te *testEnv) *keyFile {
	t.Helper()
	kf, err := parseKeyFile(must[[]byte](t)(os.ReadFile(te.h.KeysFile())))
	if err != nil {
		t.Fatal(err)
	}
	return kf
}

// TestPlainKeyNotCachedInMemory: in plain mode the master key lives in the
// vault only. The parsed key file the service keeps (s.file) never holds the
// base64 key, and every write still puts a complete plain file on disk.
func TestPlainKeyNotCachedInMemory(t *testing.T) {
	te := newTestEnv(t)
	s := te.initPlain(t)
	check := func(step string) {
		t.Helper()
		s.mu.RLock()
		cached := s.file.Key
		s.mu.RUnlock()
		if cached != "" {
			t.Fatalf("%s: the cached key file holds the master key", step)
		}
		if kf := diskFile(t, te); kf.Mode == core.KeyModePlain {
			mk, err := kf.plainKey()
			if err != nil || !bytes.Equal(mk, liveMK(t, s)) {
				t.Fatalf("%s: the plain key file on disk does not hold the loaded master key (%v)", step, err)
			}
		}
	}
	reopen := func(step string) {
		t.Helper()
		s = te.reopen(t, s)
		if s.State() != core.KeyStateUnlocked {
			t.Fatalf("%s: a plain key file must unlock at start, state %s", step, s.State())
		}
		check(step + " + reopen")
	}
	check("init")
	reopen("init")
	rk := must[string](t)(s.ExportRecovery(ctx))
	check("export recovery")
	reopen("export recovery")
	if err := s.RotateMaster(ctx); err != nil {
		t.Fatal(err)
	}
	check("rotate")
	reopen("rotate")
	if err := s.Seal(ctx, []byte(testPass)); err != nil {
		t.Fatal(err)
	}
	if err := s.Unseal(ctx, []byte(rk)); err != nil {
		t.Fatal(err)
	}
	check("unseal")
	reopen("unseal")
}

// sameAsDisk fails unless the key file the service uses is the one on disk.
func sameAsDisk(t *testing.T, te *testEnv, s *Service, step string) {
	t.Helper()
	kf := diskFile(t, te)
	kf.Key = "" // never cached
	s.mu.RLock()
	cur := s.file.marshal()
	s.mu.RUnlock()
	if !bytes.Equal(cur, kf.marshal()) {
		t.Fatalf("%s: the key file in memory is not the one on disk", step)
	}
}

// TestKeyFileWriteCommittedDespiteFollowUpFailure: once the new
// keys/master.key is renamed into place, a later failure (the directory
// fsync, removing a stale master.key.next) must not be reported as "nothing
// changed": memory follows the disk, the operation succeeds with a warning,
// and ExportRecovery returns the key that is now the only one that works.
func TestKeyFileWriteCommittedDespiteFollowUpFailure(t *testing.T) {
	te := newTestEnv(t)
	s, rk := te.initSealed(t)
	next := te.h.KeysFile() + fileSuffixNx
	// A master.key.next that cannot be removed: dropStaleNext fails after
	// the rename.
	if err := os.MkdirAll(filepath.Join(next, "x"), 0o700); err != nil {
		t.Fatal(err)
	}
	rk2, err := s.ExportRecovery(ctx)
	if err != nil || !recoveryRe.MatchString(rk2) {
		t.Fatalf("ExportRecovery = %q, %v; the new recovery key is lost", rk2, err)
	}
	if !s.verifySecret([]byte(rk2)) || s.verifySecret([]byte(rk)) {
		t.Fatal("memory does not follow the new key file")
	}
	sameAsDisk(t, te, s, "export")
	e := te.audit.find(core.ActKeysRecoveryExport, core.OutcomeSuccess)
	if len(e) != 1 || !strings.Contains(fmt.Sprint(e[0].Details.(map[string]any)["warning"]), next) {
		t.Fatalf("audit %+v: want a success naming %s", e, next)
	}
	const pass2 = "a second passphrase"
	if err := s.ChangePassphrase(ctx, []byte(testPass), []byte(pass2)); err != nil {
		t.Fatalf("ChangePassphrase: %v", err)
	}
	if !s.verifySecret([]byte(pass2)) || s.verifySecret([]byte(testPass)) {
		t.Fatal("memory does not follow the new passphrase")
	}
	sameAsDisk(t, te, s, "passphrase")

	// The directory fsync after the rename fails: the change took effect.
	syncRenamed = func(string) error { return errors.New("simulated EIO") }
	rk3, err := s.ExportRecovery(ctx)
	syncRenamed = syncDir
	if err != nil || rk3 == "" || !s.verifySecret([]byte(rk3)) {
		t.Fatalf("ExportRecovery with a failed directory fsync = %q, %v", rk3, err)
	}
	sameAsDisk(t, te, s, "fsync")

	// A failure before the rename (the temporary path is taken) changes
	// nothing and is an error.
	tmp := te.h.KeysFile() + fileSuffixTm
	if err := os.MkdirAll(filepath.Join(tmp, "x"), 0o700); err != nil {
		t.Fatal(err)
	}
	if got, err := s.ExportRecovery(ctx); err == nil || got != "" {
		t.Fatalf("ExportRecovery without a writable temporary = %q, %v", got, err)
	}
	if !s.verifySecret([]byte(rk3)) {
		t.Fatal("a failed write replaced the recovery key")
	}
	sameAsDisk(t, te, s, "failed write")

	for _, p := range []string{next, tmp} {
		if err := os.RemoveAll(p); err != nil {
			t.Fatal(err)
		}
	}
	for _, secret := range []string{rk3, pass2} {
		s = te.reopen(t, s)
		if err := s.Unlock(ctx, []byte(secret)); err != nil {
			t.Fatalf("unlock with %.4s… after a restart: %v", secret, err)
		}
	}

	// Seal (plain → sealed) the same way.
	te2 := newTestEnv(t)
	p := te2.initPlain(t)
	next2 := te2.h.KeysFile() + fileSuffixNx
	if err := os.MkdirAll(filepath.Join(next2, "x"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := p.Seal(ctx, []byte(testPass)); err != nil {
		t.Fatalf("Seal: %v", err)
	}
	if p.mode() != core.KeyModeSealed {
		t.Fatal("Seal reported success but the service is not sealed")
	}
	sameAsDisk(t, te2, p, "seal")
	if err := os.RemoveAll(next2); err != nil {
		t.Fatal(err)
	}
	p = te2.reopen(t, p)
	if p.State() != core.KeyStateLocked {
		t.Fatalf("state after restart %s, want locked", p.State())
	}
	if err := p.Unlock(ctx, []byte(testPass)); err != nil {
		t.Fatal(err)
	}
}

// TestMasterRotationKeepsUnlockSecretsUntilChanged pins what the docs say
// about a copied key file: its escrow (readable by whoever held its MK)
// yields the passphrase key and the recovery hash, which a master rotation
// keeps, so they open the rotated file too — until the passphrase is changed
// and a new recovery key is exported.
func TestMasterRotationKeepsUnlockSecretsUntilChanged(t *testing.T) {
	opens := func(t *testing.T, s *Service, key []byte, box *sealedBox, aad []byte) bool {
		t.Helper()
		got, err := openBox(key, box, aad)
		return err == nil && bytes.Equal(got, liveMK(t, s))
	}
	t.Run("sealed", func(t *testing.T) {
		te := newTestEnv(t)
		s, _ := te.initSealed(t)
		// The attacker's copy of the file, whose passphrase they learned.
		old := diskFile(t, te)
		pk0 := must[[]byte](t)(deriveKey([]byte(testPass), old.KDF))
		mk1 := must[[]byte](t)(openBox(pk0, &sealedBox{Nonce: old.Nonce, CT: old.CT}, aadMK(old.MKID)))
		pk, rh, err := old.openEscrow(mk1)
		if err != nil || pk == nil || rh == nil {
			t.Fatalf("escrow: %v", err)
		}
		if err := s.RotateMaster(ctx); err != nil {
			t.Fatal(err)
		}
		cur := diskFile(t, te)
		if !opens(t, s, rh, cur.Recovery, aadRecovery(cur.MKID)) || !opens(t, s, pk, &sealedBox{Nonce: cur.Nonce, CT: cur.CT}, aadMK(cur.MKID)) {
			t.Fatal("a master rotation changed the unlock secrets; update the docs (§7.2 escrow, §7.6)")
		}
		// The documented response to a leak.
		if err := s.ChangePassphrase(ctx, []byte(testPass), []byte("a brand new passphrase")); err != nil {
			t.Fatal(err)
		}
		if _, err := s.ExportRecovery(ctx); err != nil {
			t.Fatal(err)
		}
		cur = diskFile(t, te)
		if cur.KDF.Salt == old.KDF.Salt {
			t.Fatal("a passphrase change kept the salt")
		}
		if opens(t, s, rh, cur.Recovery, aadRecovery(cur.MKID)) || opens(t, s, pk, &sealedBox{Nonce: cur.Nonce, CT: cur.CT}, aadMK(cur.MKID)) {
			t.Fatal("the leaked unlock secrets still open the key file after a passphrase change and a new recovery key")
		}
	})
	t.Run("plain copy, sealed later", func(t *testing.T) {
		te := newTestEnv(t)
		s := te.initPlain(t)
		if _, err := s.ExportRecovery(ctx); err != nil {
			t.Fatal(err)
		}
		old := diskFile(t, te) // a plain copy: MK1 in the clear plus escrow.recovery
		mk1 := must[[]byte](t)(old.plainKey())
		_, rh, err := old.openEscrow(mk1)
		if err != nil || rh == nil {
			t.Fatalf("escrow: %v", err)
		}
		if err := s.Seal(ctx, []byte(testPass)); err != nil {
			t.Fatal(err)
		}
		if err := s.RotateMaster(ctx); err != nil {
			t.Fatal(err)
		}
		cur := diskFile(t, te)
		if !opens(t, s, rh, cur.Recovery, aadRecovery(cur.MKID)) {
			t.Fatal("seal + master rotation changed the recovery hash; update the docs")
		}
		if _, err := s.ExportRecovery(ctx); err != nil {
			t.Fatal(err)
		}
		cur = diskFile(t, te)
		if opens(t, s, rh, cur.Recovery, aadRecovery(cur.MKID)) {
			t.Fatal("the leaked recovery hash still opens the key file after a new recovery key")
		}
	})
}

// TestSealedFilesRefusesSymlinks: package certs reads and writes the sealed
// key files through symbolic links, but the walk that counts their KEK
// references does not follow them. A symlinked certs/, directory under it
// or *.enc file must therefore fail the enumeration (and with it the field
// rotation and the prune) instead of hiding a reference: otherwise the KEK
// the key file needs is deleted and the CA key is crypto-shredded.
func TestSealedFilesRefusesSymlinks(t *testing.T) {
	for _, shape := range []struct{ name, rel string }{
		{"certs", ""},
		{"certs/ca", "ca"},
		{"certs/ca/ca.key.enc", filepath.Join("ca", "ca.key.enc")},
	} {
		t.Run(shape.name, func(t *testing.T) {
			te := newTestEnv(t)
			s := te.initPlain(t)
			s.retiredGrace = 0
			ff := makeFieldFixture(t, te, s)
			oldKEK := activeKEK(t, te, core.KEKField)
			orig := filepath.Join(te.h.CertsDir(), shape.rel)
			moved := filepath.Join(t.TempDir(), "moved")
			if err := os.Rename(orig, moved); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(moved, orig); err != nil {
				t.Fatal(err)
			}
			if _, err := os.ReadFile(ff.file); err != nil {
				t.Fatalf("the key file is not reachable through the link: %v", err)
			}
			if _, err := s.sealedFiles(); err == nil || !strings.Contains(err.Error(), "symbolic link") {
				t.Fatalf("sealedFiles: %v", err)
			}
			for i := range 2 {
				if err := s.RotateKEK(ctx, core.KEKField, nil); err == nil {
					t.Fatalf("field rotation %d succeeded with the key file behind a link", i+1)
				}
			}
			if _, err := s.PruneRetired(ctx); err == nil {
				t.Fatal("PruneRetired succeeded with the key file behind a link")
			}
			if n := te.count(t, `SELECT count(*) FROM keyring WHERE id = ?`, oldKEK); n != 1 {
				t.Fatalf("field KEK %s was deleted while its key file was behind a link", oldKEK)
			}
			rep := must[*VerifyReport](t)(s.Verify(ctx))
			if rep.OK || !strings.Contains(strings.Join(rep.Problems, "\n"), "cannot enumerate the sealed key files") {
				t.Fatalf("verify: ok=%v problems=%q", rep.OK, rep.Problems)
			}
			if slices.Contains(rep.Unreferenced, oldKEK) {
				t.Fatalf("%s reported as unreferenced", oldKEK)
			}

			// Replacing the link with what it points to makes everything work.
			if err := os.Remove(orig); err != nil {
				t.Fatal(err)
			}
			if err := os.Rename(moved, orig); err != nil {
				t.Fatal(err)
			}
			s = te.reopen(t, s)
			b := must[[]byte](t)(os.ReadFile(ff.file))
			if pt, err := s.OpenField("file|certs/ca/ca.key", strings.TrimSpace(string(b))); err != nil || string(pt) != "PRIVATE KEY DER" {
				t.Fatalf("OpenField after the refused rotations: %q %v", pt, err)
			}
			if err := s.RotateKEK(ctx, core.KEKField, nil); err != nil {
				t.Fatal(err)
			}
			b = must[[]byte](t)(os.ReadFile(ff.file))
			if want := "v1:" + activeKEK(t, te, core.KEKField) + ":"; !strings.HasPrefix(string(b), want) {
				t.Fatalf("key file not re-sealed under %s", want)
			}
		})
	}
}

// TestSealedFilesIgnoresHarmlessSymlinks: a link to a file that is no
// sealed key, and a dangling link, hold no reference and block nothing.
func TestSealedFilesIgnoresHarmlessSymlinks(t *testing.T) {
	te := newTestEnv(t)
	s := te.initPlain(t)
	makeFieldFixture(t, te, s)
	certs := te.h.CertsDir()
	target := filepath.Join(t.TempDir(), "leaf.crt")
	if err := os.WriteFile(target, []byte("CERT"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(certs, "server"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(certs, "server", "leaf.crt")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(t.TempDir(), "gone.enc"), filepath.Join(certs, "dangling.enc")); err != nil {
		t.Fatal(err)
	}
	if files := must[[]sealedFile](t)(s.sealedFiles()); len(files) != 1 {
		t.Fatalf("%d sealed files, want the CA key only", len(files))
	}
	if err := s.RotateKEK(ctx, core.KEKField, nil); err != nil {
		t.Fatalf("rotation blocked by a harmless link: %v", err)
	}
}

// TestKeyRotationConflictNamesTheCause: a master rotation and a field KEK
// rotation exclude each other; the refusal must say so, not blame a backup
// that is not running. A real backup hold still reports the backup.
func TestKeyRotationConflictNamesTheCause(t *testing.T) {
	te := newTestEnv(t)
	s := te.initPlain(t)
	makeFieldFixture(t, te, s)
	var during error
	var once sync.Once
	if err := s.RotateKEK(ctx, core.KEKField, func(int64, int64) {
		once.Do(func() { during = s.RotateMaster(ctx) })
	}); err != nil {
		t.Fatal(err)
	}
	errIs(t, during, core.ErrConflict, "RotateMaster during a field KEK rotation")
	if during != errKeyRotationRunning || strings.Contains(during.Error(), "backup") {
		t.Fatalf("RotateMaster during a field KEK rotation: %v", during)
	}
	during = nil
	testHook = func(stage string) error {
		if stage == "next-written" {
			during = s.RotateKEK(ctx, core.KEKField, nil)
		}
		return nil
	}
	err := s.RotateMaster(ctx)
	testHook = nil
	if err != nil {
		t.Fatal(err)
	}
	if during != errKeyRotationRunning {
		t.Fatalf("RotateKEK(field) during a master rotation: %v", during)
	}
	release := s.HoldKeyMaterial()
	if err := s.RotateMaster(ctx); err != errKeyMaterialHeld {
		t.Fatalf("RotateMaster during a backup: %v", err)
	}
	if err := s.RotateKEK(ctx, core.KEKField, nil); err != errKeyMaterialHeld {
		t.Fatalf("RotateKEK(field) during a backup: %v", err)
	}
	release()
	if err := s.RotateMaster(ctx); err != nil {
		t.Fatalf("rotation after the conflicts: %v", err)
	}
}

// TestResealNeverOverwritesAConcurrentKeyFileWrite: a key file its owner
// (package certs) writes while a field rotation re-seals it — between the
// rotation's changed-file check and its rename — must survive: both hold
// the key-file lock, so the owner's write lands after the rename, never
// before it (where the rename would put the previous key back).
func TestResealNeverOverwritesAConcurrentKeyFileWrite(t *testing.T) {
	te := newTestEnv(t)
	s := te.initPlain(t)
	s.retiredGrace = 0
	ff := makeFieldFixture(t, te, s)
	const aad = "file|certs/ca/ca.key"
	done := make(chan error, 1)
	beforeResealRename = func(path string) {
		if path != ff.file {
			return
		}
		started := make(chan struct{})
		go func() {
			close(started)
			// What certs.sealKeyFile does: lock, seal, write, rename.
			release := s.LockKeyFiles()
			defer release()
			sealed, err := s.SealField(aad, []byte("A NEWER PRIVATE KEY"))
			if err == nil {
				tmp := ff.file + ".owner-tmp"
				if err = os.WriteFile(tmp, []byte(sealed+"\n"), 0o600); err == nil {
					err = os.Rename(tmp, ff.file)
				}
			}
			done <- err
		}()
		<-started
		time.Sleep(50 * time.Millisecond) // unserialised, the owner's write would land now
	}
	err := s.RotateKEK(ctx, core.KEKField, nil)
	beforeResealRename = nil
	if err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the owner's write never ran")
	}
	b := must[[]byte](t)(os.ReadFile(ff.file))
	if pt, err := s.OpenField(aad, strings.TrimSpace(string(b))); err != nil || string(pt) != "A NEWER PRIVATE KEY" {
		t.Fatalf("the rotation overwrote the newer key file: %q %v", pt, err)
	}
	if rep := must[*VerifyReport](t)(s.Verify(ctx)); !rep.OK {
		t.Fatalf("verify: %q", rep.Problems)
	}
}

// noteHandle is a job handle whose progress notes can be read while the job
// runs.
type noteHandle struct {
	fakeHandle
	mu    sync.Mutex
	notes []string
}

func (h *noteHandle) Progress(done, total int64, note string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.notes = append(h.notes, note)
}

func (h *noteHandle) waitNote(t *testing.T, note string) {
	t.Helper()
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); time.Sleep(time.Millisecond) {
		h.mu.Lock()
		found := slices.Contains(h.notes, note)
		h.mu.Unlock()
		if found {
			return
		}
	}
	t.Fatalf("no progress note %q", note)
}

// TestReencryptPausesWhileBlobsAreHeld: a full backup holds the blobs
// (HoldBlobs) from before its snapshot until the last blob is copied. Data
// re-encryption deletes the old blob of every file it re-encrypts, so it must
// neither copy, swap nor delete anything meanwhile — the archive would miss
// those files — and continue once the hold is released.
func TestReencryptPausesWhileBlobsAreHeld(t *testing.T) {
	te := newTestEnv(t)
	s := te.initPlain(t)
	blobs, err := blobstore.New(te.env)
	if err != nil {
		t.Fatal(err)
	}
	defer blobs.Close()
	if err := s.Bind(&core.Services{Blobs: blobs}); err != nil {
		t.Fatal(err)
	}
	defer func(p time.Duration) { holdPoll = p }(holdPoll)
	holdPoll = 5 * time.Millisecond
	te.clock.t = time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)
	f := te.fixture(t)
	now := db.Ms(te.clock.Now())
	before := map[string]string{} // version → blob
	for range 3 {
		w, err := blobs.Create(ctx)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = w.Write(crypt.RandomBytes(1000))
		info, err := w.Commit(ctx)
		if err != nil {
			t.Fatal(err)
		}
		node, ver := ids.New(ids.PrefixNode), ids.New(ids.PrefixVersion)
		te.exec(t, `INSERT INTO nodes (id, space_id, parent_id, kind, name, name_key, created_at, updated_at) VALUES (?, ?, ?, 'file', ?, ?, ?, ?)`,
			node, f.spaceID, f.nodeID, node, node, now, now)
		te.exec(t, `INSERT INTO file_versions (id, node_id, blob_id, size, created_at) VALUES (?, ?, ?, ?, ?)`, ver, node, info.ID, info.Size, now)
		before[ver] = info.ID
	}
	untouched := func(step string) {
		t.Helper()
		for ver, blob := range before {
			if got := te.queryString(t, `SELECT blob_id FROM file_versions WHERE id = ?`, ver); got != blob {
				t.Fatalf("%s: version %s was swapped to %s while the blobs were held", step, ver, got)
			}
			if _, err := blobs.Stat(ctx, blob); err != nil {
				t.Fatalf("%s: blob %s deleted while the blobs were held: %v", step, blob, err)
			}
		}
		if n := te.count(t, `SELECT count(*) FROM blobs`); n != int64(len(before)) {
			t.Fatalf("%s: %d blobs, want %d (a copy was written while held)", step, n, len(before))
		}
	}
	jobID := ids.New(ids.PrefixJob)
	te.clock.t = time.Now().Add(time.Hour) // copies are newer than the job
	j := &fakeJobs{}
	_ = s.RegisterJobs(j)
	run := j.kinds[core.JobKeysReencrypt]
	const waiting = "waiting for a running backup"

	release := s.HoldBlobs()
	// Cancelled while it waits: it returns promptly and changed nothing.
	cctx, cancel := context.WithCancel(ctx)
	errc := make(chan error, 1)
	h := &noteHandle{fakeHandle: fakeHandle{id: jobID}}
	go func() { errc <- run(cctx, h) }()
	h.waitNote(t, waiting)
	time.Sleep(20 * time.Millisecond)
	untouched("waiting")
	cancel()
	select {
	case err := <-errc:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("cancelled job: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("a job waiting for the hold ignored its cancellation")
	}
	untouched("cancelled")

	// Released: it continues and finishes.
	h = &noteHandle{fakeHandle: fakeHandle{id: jobID}}
	go func() { errc <- run(ctx, h) }()
	h.waitNote(t, waiting)
	untouched("waiting again")
	release()
	release() // idempotent
	select {
	case err := <-errc:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the job did not continue after the hold was released")
	}
	if res := h.result.(ReencryptResult); res.Reencrypted != int64(len(before)) {
		t.Fatalf("result %+v", res)
	}
	for ver, blob := range before {
		if got := te.queryString(t, `SELECT blob_id FROM file_versions WHERE id = ?`, ver); got == blob {
			t.Fatalf("version %s not re-encrypted", ver)
		}
	}
}
