package keys

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"fileparcel/internal/core"
	"fileparcel/internal/crypt"
	"fileparcel/internal/db"
	"fileparcel/internal/events"
	"fileparcel/internal/ids"
)

// lookalike is a plain setting value (JSON) shaped like a sealed one.
const lookalike = `"v1:kek_not_a_key:just text"`

// TestRotateKEKBlob10k re-wraps 10 000 DEKs (DESIGN §17).
func TestRotateKEKBlob10k(t *testing.T) {
	te := newTestEnv(t)
	s := te.initPlain(t)
	s.retiredGrace = 0
	oldKEK := activeKEK(t, te, core.KEKBlob)
	const n = 10000
	deks := make(map[string][]byte, n)
	err := te.db.Tx(ctx, func(tx *sql.Tx) error {
		clear(deks)
		for range n {
			id, dek := insertBlobRow(t, te, s, tx)
			deks[id] = dek
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	var calls int
	var last [2]int64
	start := time.Now()
	err = s.RotateKEK(ctx, core.KEKBlob, func(done, total int64) {
		calls++
		if done < last[0] || total != n {
			t.Errorf("progress %d/%d after %d", done, total, last[0])
		}
		last = [2]int64{done, total}
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("re-wrapped %d DEKs in %v (%d progress calls)", n, time.Since(start), calls)
	if last != [2]int64{n, n} || calls < n/rewrapBatch {
		t.Fatalf("final progress %v, %d calls", last, calls)
	}
	newKEK := activeKEK(t, te, core.KEKBlob)
	if newKEK == oldKEK {
		t.Fatal("KEK not rotated")
	}
	if c := te.count(t, `SELECT count(*) FROM blobs WHERE kek_id <> ?`, newKEK); c != 0 {
		t.Fatalf("%d blobs not re-wrapped", c)
	}
	// Every DEK still unwraps to the same value, also after a restart.
	s = te.reopen(t, s)
	rs, err := te.db.Query(ctx, `SELECT id, kek_id, wrapped_dek FROM blobs`)
	if err != nil {
		t.Fatal(err)
	}
	defer rs.Close()
	checked := 0
	for rs.Next() {
		var id, kek string
		var w []byte
		if err := rs.Scan(&id, &kek, &w); err != nil {
			t.Fatal(err)
		}
		raw, _ := ids.BlobIDBytes(id)
		got, err := s.UnwrapDEK(raw, kek, w)
		if err != nil || !bytes.Equal(got, deks[id]) {
			t.Fatalf("blob %s: %v", id, err)
		}
		checked++
	}
	if checked != n {
		t.Fatalf("checked %d", checked)
	}
	// grace 0: the old KEK was unreferenced and is gone
	if c := te.count(t, `SELECT count(*) FROM keyring WHERE id = ?`, oldKEK); c != 0 {
		t.Fatal("unreferenced retired KEK not pruned")
	}
	if e := te.audit.find(core.ActKeysRotate, core.OutcomeSuccess); len(e) != 1 || e[0].Details.(map[string]any)["purpose"] != "blob" {
		t.Fatalf("audit %+v", e)
	}
}

// TestRotateKEKGraceAndVerify keeps a freshly retired KEK and reports it.
func TestRotateKEKGraceAndVerify(t *testing.T) {
	te := newTestEnv(t)
	s := te.initPlain(t)
	oldKEK := activeKEK(t, te, core.KEKBlob)
	id, dek := insertBlobRow(t, te, s, nil)
	errIs(t, s.RotateKEK(ctx, core.KEKMAC, nil), core.ErrInvalid, "mac rotation")
	errIs(t, s.RotateKEK(ctx, "nope", nil), core.ErrInvalid, "bad purpose")
	if err := s.RotateKEK(ctx, core.KEKBlob, nil); err != nil {
		t.Fatal(err)
	}
	rep, err := s.Verify(ctx)
	if err != nil || !rep.OK || !rep.MKCheck {
		t.Fatalf("verify %+v %v", rep, err)
	}
	if len(rep.Unreferenced) != 1 || rep.Unreferenced[0] != oldKEK || len(rep.Retired) != 0 {
		t.Fatalf("unreferenced %+v retired %+v", rep.Unreferenced, rep.Retired)
	}
	st := must[*core.KeyStatus](t)(s.Status(ctx))
	var found bool
	for _, k := range st.KEKs {
		if k.ID == oldKEK {
			found = k.State == core.KEKRetired && k.Refs == 0 && k.RetiredAt != nil
		}
		if k.Purpose == core.KEKBlob && k.State == core.KEKActive && k.Refs != 1 {
			t.Fatalf("active blob kek refs %d", k.Refs)
		}
	}
	if !found {
		t.Fatalf("retired kek not in status: %+v", st.KEKs)
	}
	// After the grace period the next rotation prunes it.
	te.clock.advance(defaultRetiredGrace + time.Minute)
	if err := s.RotateKEK(ctx, core.KEKBlob, nil); err != nil {
		t.Fatal(err)
	}
	if te.count(t, `SELECT count(*) FROM keyring WHERE id = ?`, oldKEK) != 0 {
		t.Fatal("old KEK not pruned after grace")
	}
	if te.count(t, `SELECT count(*) FROM keyring WHERE purpose = 'blob'`) != 2 {
		t.Fatal("second retired KEK must be kept (within grace)")
	}
	raw, _ := ids.BlobIDBytes(id)
	kek := te.queryString(t, `SELECT kek_id FROM blobs WHERE id = ?`, id)
	var w []byte
	_ = te.db.QueryRow(ctx, `SELECT wrapped_dek FROM blobs WHERE id = ?`, id).Scan(&w)
	if got, err := s.UnwrapDEK(raw, kek, w); err != nil || !bytes.Equal(got, dek) {
		t.Fatal("dek lost")
	}
	// PruneRetired with everything referenced/young does nothing harmful.
	if _, err := s.PruneRetired(ctx); err != nil {
		t.Fatal(err)
	}
}

// fieldFixture fills every sealed column plus a sealed key file.
type fieldFixture struct {
	values map[string]string // aad → plaintext
	file   string
	batch  string // upload batch holding a sealed .zip password
}

func makeFieldFixture(t *testing.T, te *testEnv, s *Service) fieldFixture {
	t.Helper()
	f := te.fixture(t)
	now := db.Ms(te.clock.Now())
	ff := fieldFixture{values: map[string]string{}}
	seal := func(aad, pt string) string {
		ff.values[aad] = pt
		return must[string](t)(s.SealField(aad, []byte(pt)))
	}
	te.exec(t, `INSERT INTO totp_secrets (user_id, secret_enc, created_at) VALUES (?, ?, ?)`,
		f.userID, seal("totp_secrets.secret_enc|"+f.userID, "TOTPSECRET"), now)
	pk := ids.New(ids.PrefixPasskey)
	te.exec(t, `INSERT INTO webauthn_credentials (id, user_id, credential_id, credential_enc, rp_id, created_at) VALUES (?, ?, ?, ?, 'fileparcel.local', ?)`,
		pk, f.userID, crypt.RandomBytes(16), seal("webauthn_credentials.credential_enc|"+pk, `{"cred":1}`), now)
	for i := range 3 {
		inv := ids.New(ids.PrefixInvite)
		te.exec(t, `INSERT INTO invites (id, token_hash, token_enc, role, expires_at, created_at) VALUES (?, ?, ?, 'member', ?, ?)`,
			inv, crypt.RandomBytes(32), seal("invites.token_enc|"+inv, "invite"+string(rune('0'+i))), now+1e6, now)
	}
	shr := ids.New(ids.PrefixShare)
	te.exec(t, `INSERT INTO shares (id, kind, node_id, created_by, token_hash, token_enc, created_at, updated_at) VALUES (?, 'link', ?, ?, ?, ?, ?, ?)`,
		shr, f.nodeID, f.userID, crypt.RandomBytes(32), seal("shares.token_enc|"+shr, "sharetoken"), now, now)
	// A protected upload in flight holds its sealed .zip password; a finished
	// one holds NULL (never counted, never re-sealed).
	ff.batch = ids.New(ids.PrefixUploadBatch)
	te.exec(t, `INSERT INTO upload_batches (id, user_id, folder_id, mode, zip_name, zip_encryption, zip_password_enc,
		conflict, state, created_at, updated_at, expires_at) VALUES (?, ?, ?, 'zip', 'a.zip', 'aes256', ?, 'rename', 'open', ?, ?, ?)`,
		ff.batch, f.userID, f.nodeID, seal("upload_batches.zip_password_enc|"+ff.batch, "zip password 1"), now, now, now+1e6)
	te.exec(t, `INSERT INTO upload_batches (id, user_id, folder_id, mode, zip_name, zip_encryption, zip_password_enc,
		conflict, state, created_at, updated_at, expires_at) VALUES (?, ?, ?, 'zip', 'b.zip', 'aes256', NULL, 'rename', 'done', ?, ?, ?)`,
		ids.New(ids.PrefixUploadBatch), f.userID, f.nodeID, now, now, now+1e6)
	sv, _ := json.Marshal(seal("settings.value|"+testSecretKey, "smtp-pw"))
	te.exec(t, `INSERT INTO settings (key, value, updated_at) VALUES (?, ?, ?)`, testSecretKey, string(sv), now)
	te.exec(t, `INSERT INTO settings (key, value, updated_at) VALUES ('ui.instance_name', '"Plain value"', ?)`, now)
	// Plain (non-secret) strings that merely look sealed are left alone.
	te.exec(t, `INSERT INTO settings (key, value, updated_at) VALUES (?, ?, ?)`, testPlainKey, lookalike, now)
	te.exec(t, `INSERT INTO settings (key, value, updated_at) VALUES ('unregistered.key', ?, ?)`, lookalike, now)
	// sealed key file as written by package certs
	ff.file = filepath.Join(te.h.CertsDir(), "ca", "ca.key.enc")
	_ = os.MkdirAll(filepath.Dir(ff.file), 0o700)
	if err := os.WriteFile(ff.file, []byte(seal("file|certs/ca/ca.key", "PRIVATE KEY DER")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return ff
}

// readSealed returns every sealed value by AAD.
func readSealed(t *testing.T, te *testEnv, ff fieldFixture) map[string]string {
	t.Helper()
	out := map[string]string{}
	for _, c := range sealedColumns {
		rs, err := te.db.Query(ctx, `SELECT `+c.pk+`, `+c.col+` FROM `+c.table)
		if err != nil {
			t.Fatal(err)
		}
		for rs.Next() {
			var k string
			var nv sql.NullString
			_ = rs.Scan(&k, &nv)
			if !nv.Valid || c.only != nil && !slices.Contains(c.only(), k) {
				continue
			}
			v := nv.String
			if c.json {
				if err := json.Unmarshal([]byte(v), &v); err != nil {
					t.Fatal(err)
				}
				if !strings.HasPrefix(v, "v1:") {
					continue
				}
			}
			out[c.aadPrefix+k] = v
		}
		rs.Close()
	}
	b, _ := os.ReadFile(ff.file)
	out["file|certs/ca/ca.key"] = strings.TrimSpace(string(b))
	return out
}

func TestRotateKEKField(t *testing.T) {
	te := newTestEnv(t)
	s := te.initPlain(t)
	s.retiredGrace = 0
	ff := makeFieldFixture(t, te, s)
	oldKEK := activeKEK(t, te, core.KEKField)
	if st := must[*core.KeyStatus](t)(s.Status(ctx)); !kekHasRefs(st, oldKEK, int64(len(ff.values))) {
		t.Fatalf("refs before rotation: %+v", st.KEKs)
	}
	evs, cancel := te.env.Bus.Subscribe(events.TopicSettingsChanged)
	defer cancel()
	var last [2]int64
	if err := s.RotateKEK(ctx, core.KEKField, func(d, total int64) { last = [2]int64{d, total} }); err != nil {
		t.Fatal(err)
	}
	if want := int64(len(ff.values)); last != [2]int64{want, want} {
		t.Fatalf("progress %v want %d", last, want)
	}
	newKEK := activeKEK(t, te, core.KEKField)
	got := readSealed(t, te, ff)
	if len(got) != len(ff.values) {
		t.Fatalf("found %d sealed values, want %d", len(got), len(ff.values))
	}
	s = te.reopen(t, s)
	for aad, sealed := range got {
		if !strings.HasPrefix(sealed, "v1:"+newKEK+":") {
			t.Errorf("%s still sealed with %q", aad, sealed[:30])
		}
		pt, err := s.OpenField(aad, sealed)
		if err != nil || string(pt) != ff.values[aad] {
			t.Errorf("%s: %q %v", aad, pt, err)
		}
	}
	if v := te.queryString(t, `SELECT value FROM settings WHERE key = 'ui.instance_name'`); v != `"Plain value"` {
		t.Fatalf("plain setting touched: %s", v)
	}
	for _, k := range []string{testPlainKey, "unregistered.key"} {
		if v := te.queryString(t, `SELECT value FROM settings WHERE key = ?`, k); v != lookalike {
			t.Fatalf("look-alike plain setting %s touched: %s", k, v)
		}
	}
	if fi, _ := os.Stat(ff.file); fi.Mode().Perm() != 0o600 {
		t.Fatal("key file mode")
	}
	select {
	case ev := <-evs:
		if keys := ev.Data.(core.SettingsChangedEvent).Keys; keys == nil || len(keys) != 0 {
			t.Fatalf("settings event keys %v", keys)
		}
	case <-time.After(time.Second):
		t.Fatal("no settings.changed event")
	}
	if te.count(t, `SELECT count(*) FROM keyring WHERE id = ?`, oldKEK) != 0 {
		t.Fatal("old field KEK not pruned")
	}
	if rep := must[*VerifyReport](t)(s.Verify(ctx)); !rep.OK {
		t.Fatalf("verify: %+v", rep.Problems)
	}
}

func kekHasRefs(st *core.KeyStatus, id string, want int64) bool {
	for _, k := range st.KEKs {
		if k.ID == id {
			return k.Refs == want
		}
	}
	return false
}

func TestRotateKEKFieldCorruptValue(t *testing.T) {
	te := newTestEnv(t)
	s := te.initPlain(t)
	s.retiredGrace = 0
	ff := makeFieldFixture(t, te, s)
	oldKEK := activeKEK(t, te, core.KEKField)
	// Damage one invite token (still names the old KEK).
	var id, v string
	_ = te.db.QueryRow(ctx, `SELECT id, token_enc FROM invites ORDER BY id LIMIT 1`).Scan(&id, &v)
	te.exec(t, `UPDATE invites SET token_enc = ? WHERE id = ?`, v[:len(v)-4]+"AAAA", id)
	err := s.RotateKEK(ctx, core.KEKField, nil)
	errIs(t, err, core.ErrCorrupt, "rotation with a damaged value")
	if !strings.Contains(err.Error(), "1 stored values") {
		t.Fatalf("message %q", err)
	}
	// Everything else was re-sealed; the damaged value still names the old
	// KEK, which is therefore kept.
	got := readSealed(t, te, ff)
	newKEK := activeKEK(t, te, core.KEKField)
	for aad, sealed := range got {
		if aad == "invites.token_enc|"+id {
			continue
		}
		if !strings.HasPrefix(sealed, "v1:"+newKEK+":") {
			t.Errorf("%s not re-sealed", aad)
		}
	}
	if te.count(t, `SELECT count(*) FROM keyring WHERE id = ?`, oldKEK) != 1 {
		t.Fatal("referenced KEK pruned")
	}
	rep := must[*VerifyReport](t)(s.Verify(ctx))
	if len(rep.Retired) != 1 || rep.Retired[0] != oldKEK {
		t.Fatalf("verify retired %+v", rep)
	}
	if len(te.audit.find(core.ActKeysRotate, core.OutcomeFailure)) != 1 {
		t.Fatal("failed rotation not audited")
	}
}

func TestRotateMasterPlain(t *testing.T) {
	te := newTestEnv(t)
	s := te.initPlain(t)
	ff := makeFieldFixture(t, te, s)
	blobID, dek := insertBlobRow(t, te, s, nil)
	mac := s.MAC("audit", []byte("x"))
	oldID := te.meta(t, metaMKID)
	oldFile, _ := os.ReadFile(te.h.KeysFile())
	if err := s.RotateMaster(ctx); err != nil {
		t.Fatal(err)
	}
	newID := te.meta(t, metaMKID)
	if newID == oldID || te.count(t, `SELECT count(*) FROM keyring WHERE mk_id <> ?`, newID) != 0 {
		t.Fatal("keyring not re-wrapped")
	}
	if _, err := os.Stat(te.h.KeysFile() + ".next"); !errors.Is(err, os.ErrNotExist) {
		t.Fatal(".next left behind")
	}
	newFile, _ := os.ReadFile(te.h.KeysFile())
	if bytes.Equal(oldFile, newFile) || !strings.Contains(string(newFile), newID) {
		t.Fatal("key file not replaced")
	}
	checkAllValues(t, te, s, ff, blobID, dek, mac)
	s = te.reopen(t, s)
	checkAllValues(t, te, s, ff, blobID, dek, mac)
	if rep := must[*VerifyReport](t)(s.Verify(ctx)); !rep.OK || rep.MKID != newID {
		t.Fatalf("verify %+v", rep)
	}
	// The old key file no longer opens the database.
	s.Close()
	_ = os.WriteFile(te.h.KeysFile(), oldFile, 0o600)
	if _, err := Open(te.env); err == nil {
		t.Fatal("old key file accepted after rotation")
	}
}

func checkAllValues(t *testing.T, te *testEnv, s *Service, ff fieldFixture, blobID string, dek, mac []byte) {
	t.Helper()
	for aad, sealed := range readSealed(t, te, ff) {
		if pt, err := s.OpenField(aad, sealed); err != nil || string(pt) != ff.values[aad] {
			t.Fatalf("%s: %v", aad, err)
		}
	}
	raw, _ := ids.BlobIDBytes(blobID)
	var kek string
	var w []byte
	_ = te.db.QueryRow(ctx, `SELECT kek_id, wrapped_dek FROM blobs WHERE id = ?`, blobID).Scan(&kek, &w)
	if got, err := s.UnwrapDEK(raw, kek, w); err != nil || !bytes.Equal(got, dek) {
		t.Fatalf("dek: %v", err)
	}
	if !bytes.Equal(s.MAC("audit", []byte("x")), mac) {
		t.Fatal("mac KEK value must survive a master rotation")
	}
}

func TestRotateMasterSealed(t *testing.T) {
	te := newTestEnv(t)
	s, rk := te.initSealed(t)
	sealed := must[string](t)(s.SealField("a", []byte("v")))
	check := func(s *Service) {
		t.Helper()
		if pt, err := s.OpenField("a", sealed); err != nil || string(pt) != "v" {
			t.Fatalf("value lost: %v", err)
		}
	}
	// Rotations after a passphrase unlock and after a recovery-key unlock
	// (both after a restart, so nothing is cached from Init): the escrow
	// keeps the passphrase and the recovery key valid.
	for _, unlockWith := range []string{"", testPass, rk, testPass} {
		if unlockWith != "" {
			s = te.reopen(t, s)
			if err := s.Unlock(ctx, []byte(unlockWith)); err != nil {
				t.Fatalf("unlock: %v", err)
			}
		}
		before := te.meta(t, metaMKID)
		if err := s.RotateMaster(ctx); err != nil {
			t.Fatalf("rotate after unlock with %.4s…: %v", unlockWith, err)
		}
		if te.meta(t, metaMKID) == before {
			t.Fatal("mk_id unchanged")
		}
		if st := must[*core.KeyStatus](t)(s.Status(ctx)); !st.RecoveryConfigured || st.Mode != core.KeyModeSealed {
			t.Fatalf("status %+v", st)
		}
		check(s)
		for _, secret := range []string{testPass, rk} {
			s = te.reopen(t, s)
			if err := s.Unlock(ctx, []byte(secret)); err != nil {
				t.Fatalf("unlock with %.4s… after rotation: %v", secret, err)
			}
			check(s)
		}
	}
	for _, e := range te.audit.find(core.ActKeysRotate, core.OutcomeSuccess) {
		if e.Details.(map[string]any)["recovery_invalidated"] != false {
			t.Fatalf("audit %+v", e)
		}
	}
}

// TestRotateMasterSealedWithoutEscrow covers key files without escrow
// (hand-written or older): the cached secrets decide.
func TestRotateMasterSealedWithoutEscrow(t *testing.T) {
	te := newTestEnv(t)
	s, rk := te.initSealed(t)
	sealed := must[string](t)(s.SealField("a", []byte("v")))
	stripEscrow := func() {
		t.Helper()
		data, _ := os.ReadFile(te.h.KeysFile())
		kf, err := parseKeyFile(data)
		if err != nil || kf.Escrow == nil || kf.Escrow.Pass == nil || kf.Escrow.Recovery == nil {
			t.Fatalf("escrow missing: %+v %v", kf, err)
		}
		kf.Escrow = nil
		if err := writeFileAtomic(te.h.KeysFile(), kf.marshal(), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	stripEscrow()
	// Unlocked with the recovery key: no passphrase key → refused.
	s = te.reopen(t, s)
	if err := s.Unlock(ctx, []byte(rk)); err != nil {
		t.Fatal(err)
	}
	errIs(t, s.RotateMaster(ctx), core.ErrPrecondition, "rotate after recovery unlock without escrow")
	// Resetting the passphrase with the recovery key writes a new escrow.
	if err := s.ChangePassphrase(ctx, []byte(rk), []byte(testPass)); err != nil {
		t.Fatal(err)
	}
	if err := s.RotateMaster(ctx); err != nil {
		t.Fatalf("rotate after passphrase reset: %v", err)
	}
	stripEscrow()
	// Unlocked with the passphrase only: the recovery hash is unknown, so
	// the rotation invalidates the recovery key.
	s = te.reopen(t, s)
	if err := s.Unlock(ctx, []byte(testPass)); err != nil {
		t.Fatal(err)
	}
	if err := s.RotateMaster(ctx); err != nil {
		t.Fatal(err)
	}
	if st := must[*core.KeyStatus](t)(s.Status(ctx)); st.RecoveryConfigured {
		t.Fatal("recovery must be dropped")
	}
	e := te.audit.find(core.ActKeysRotate, core.OutcomeSuccess)
	if len(e) != 2 || e[1].Details.(map[string]any)["recovery_invalidated"] != true {
		t.Fatalf("audit %+v", e)
	}
	s = te.reopen(t, s)
	errIs(t, s.Unlock(ctx, []byte(rk)), core.ErrInvalid, "old recovery key")
	if err := s.Unlock(ctx, []byte(testPass)); err != nil {
		t.Fatal(err)
	}
	if pt, err := s.OpenField("a", sealed); err != nil || string(pt) != "v" {
		t.Fatal("value lost")
	}
}

// TestEscrowDamagedOrStale checks that a bad escrow never blocks an unlock
// and is never used.
func TestEscrowDamagedOrStale(t *testing.T) {
	te := newTestEnv(t)
	s, rk := te.initSealed(t)
	s.Close()
	data, _ := os.ReadFile(te.h.KeysFile())
	kf, err := parseKeyFile(data)
	if err != nil {
		t.Fatal(err)
	}
	// Damaged: the pass escrow fails authentication (another MK), the
	// recovery escrow opens but holds a stale hash (a different key).
	kf.Escrow.Pass, _ = sealBox(crypt.RandomBytes(32), crypt.RandomBytes(32), aadEscrow(escrowPass, kf.MKID))
	if err := writeFileAtomic(te.h.KeysFile(), kf.marshal(), 0o600); err != nil {
		t.Fatal(err)
	}
	var mk []byte
	s = te.open(t)
	if err := s.Unlock(ctx, []byte(rk)); err != nil {
		t.Fatalf("unlock with a damaged escrow: %v", err)
	}
	_ = s.withMK(func(k []byte) error { mk = bytes.Clone(k); return nil })
	if s.m.passKey != nil {
		t.Fatal("damaged pass escrow adopted")
	}
	errIs(t, s.RotateMaster(ctx), core.ErrPrecondition, "rotation without a usable passphrase key")
	// A pass escrow sealed correctly under the MK but holding a key that
	// does not open the MK slot (stale) is ignored as well.
	s.Close()
	if err := kf.setEscrow(mk, escrowPass, crypt.RandomBytes(32)); err != nil {
		t.Fatal(err)
	}
	if err := kf.setEscrow(mk, escrowRecovery, crypt.RandomBytes(32)); err != nil {
		t.Fatal(err)
	}
	_ = writeFileAtomic(te.h.KeysFile(), kf.marshal(), 0o600)
	s = te.open(t)
	if err := s.Unlock(ctx, []byte(testPass)); err != nil {
		t.Fatal(err)
	}
	if s.m.recKey != nil || s.m.passKey == nil {
		t.Fatal("stale recovery escrow adopted (or passphrase key lost)")
	}
	// Seal-type changes rewrite a consistent escrow.
	if _, err := s.ExportRecovery(ctx); err != nil {
		t.Fatal(err)
	}
	data, _ = os.ReadFile(te.h.KeysFile())
	kf2, _ := parseKeyFile(data)
	pk, rh, err := kf2.openEscrow(mk)
	if err != nil || pk == nil || rh == nil {
		t.Fatalf("escrow after export: %v", err)
	}
	// Unseal drops the passphrase escrow but keeps the recovery escrow.
	if err := s.Unseal(ctx, []byte(testPass)); err != nil {
		t.Fatal(err)
	}
	data, _ = os.ReadFile(te.h.KeysFile())
	kf3, err := parseKeyFile(data)
	if err != nil || kf3.Escrow == nil || kf3.Escrow.Pass != nil || kf3.Escrow.Recovery == nil {
		t.Fatalf("escrow after unseal: %+v %v", kf3.Escrow, err)
	}
	// Plain reopen adopts the recovery hash: a later seal + rotation keeps
	// the exported recovery key.
	s = te.reopen(t, s)
	if s.m.recKey == nil {
		t.Fatal("plain load did not adopt the recovery escrow")
	}
}

// TestRotateMasterCrashRecovery simulates a crash after writing .next and
// after committing the keyring (DESIGN §17).
func TestRotateMasterCrashRecovery(t *testing.T) {
	crash := errors.New("simulated crash")
	for _, sealed := range []bool{false, true} {
		for _, stage := range []string{"next-written", "committed"} {
			name := map[bool]string{false: "plain/", true: "sealed/"}[sealed] + stage
			t.Run(name, func(t *testing.T) {
				te := newTestEnv(t)
				var s *Service
				if sealed {
					s, _ = te.initSealed(t)
				} else {
					s = te.initPlain(t)
				}
				ff := makeFieldFixture(t, te, s)
				blobID, dek := insertBlobRow(t, te, s, nil)
				mac := s.MAC("audit", []byte("x"))
				oldID := te.meta(t, metaMKID)
				testHook = func(st string) error {
					if st == stage {
						return crash
					}
					return nil
				}
				err := s.RotateMaster(ctx)
				testHook = nil
				if !errors.Is(err, crash) {
					t.Fatalf("rotate: %v", err)
				}
				if _, err := os.Stat(te.h.KeysFile() + ".next"); err != nil {
					t.Fatal(".next must exist after the crash")
				}
				s = te.reopen(t, s)
				if _, err := os.Stat(te.h.KeysFile() + ".next"); !errors.Is(err, os.ErrNotExist) {
					t.Fatal(".next not cleaned up")
				}
				newID := te.meta(t, metaMKID)
				if (stage == "next-written") != (newID == oldID) {
					t.Fatalf("stage %s: mk_id %s → %s", stage, oldID, newID)
				}
				if sealed {
					if s.State() != core.KeyStateLocked {
						t.Fatal("sealed state")
					}
					if err := s.Unlock(ctx, []byte(testPass)); err != nil {
						t.Fatal(err)
					}
				}
				checkAllValues(t, te, s, ff, blobID, dek, mac)
				if rep := must[*VerifyReport](t)(s.Verify(ctx)); !rep.OK {
					t.Fatalf("verify %+v", rep.Problems)
				}
			})
		}
	}
}

// TestConcurrentUseDuringRotationAndLock exercises the hot paths while
// rotations and lock/unlock cycles run (for the race detector).
func TestConcurrentUseDuringRotationAndLock(t *testing.T) {
	te := newTestEnv(t)
	s, _ := te.initSealed(t)
	for range 200 {
		insertBlobRow(t, te, s, nil)
	}
	var stop atomic.Bool
	var wg sync.WaitGroup
	var ops atomic.Int64
	for range 4 {
		wg.Go(func() {
			id := crypt.RandomBytes(16)
			for !stop.Load() {
				dek, w, k, err := s.NewDEK(id)
				if err == nil {
					if got, err := s.UnwrapDEK(id, k, w); err != nil && !isErr(err, core.ErrKeysLocked) {
						t.Errorf("unwrap: %v", err)
					} else if err == nil && !bytes.Equal(got, dek) {
						t.Error("dek mismatch")
					}
				} else if !isErr(err, core.ErrKeysLocked) {
					t.Errorf("newdek: %v", err)
				}
				if v, err := s.SealField("x", []byte("y")); err == nil {
					if _, err := s.OpenField("x", v); err != nil && !isErr(err, core.ErrKeysLocked) {
						t.Errorf("open: %v", err)
					}
				}
				s.MAC("audit", []byte("z"))
				_ = s.State()
				ops.Add(1)
			}
		})
	}
	for i := range 6 {
		if err := s.RotateKEK(ctx, []string{core.KEKBlob, core.KEKField}[i%2], nil); err != nil {
			t.Fatal(err)
		}
		if err := s.Lock(ctx); err != nil {
			t.Fatal(err)
		}
		if err := s.Unlock(ctx, []byte(testPass)); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.RotateMaster(ctx); err != nil {
		t.Fatal(err)
	}
	stop.Store(true)
	wg.Wait()
	t.Logf("%d concurrent operations", ops.Load())
	if rep := must[*VerifyReport](t)(s.Verify(ctx)); !rep.OK {
		t.Fatalf("verify %+v", rep.Problems)
	}
}

func TestVerifyDetectsProblems(t *testing.T) {
	te := newTestEnv(t)
	s := te.initPlain(t)
	_, err := (&Service{env: te.env, state: core.KeyStateLocked}).Verify(ctx)
	errIs(t, err, core.ErrKeysLocked, "verify locked")
	te.exec(t, `INSERT INTO settings (key, value, updated_at) VALUES (?, '"v1:kek_gone:AAAA"', 0)`, testSecretKey)
	te.exec(t, `INSERT INTO settings (key, value, updated_at) VALUES (?, ?, 0)`, testPlainKey, lookalike)
	_ = os.Chmod(te.h.KeysFile(), 0o644)
	var w []byte
	_ = te.db.QueryRow(ctx, `SELECT wrapped FROM keyring WHERE purpose = 'mac'`).Scan(&w)
	w[len(w)-1] ^= 1
	te.exec(t, `UPDATE keyring SET wrapped = ? WHERE purpose = 'mac'`, w)
	rep := must[*VerifyReport](t)(s.Verify(ctx))
	if rep.OK || len(rep.Problems) != 3 {
		t.Fatalf("problems %q", rep.Problems)
	}
	joined := strings.Join(rep.Problems, "\n")
	for _, want := range []string{"unknown key \"kek_gone\"", "mode", "fails authentication"} {
		if !strings.Contains(joined, want) {
			t.Errorf("missing problem %q in %q", want, joined)
		}
	}
}

// TestRotateKEKFieldUnreadableCertsFailsClosed: a certs/ subdirectory that
// cannot be walked must abort the rotation and the prune instead of
// counting the sealed key files it hides as "no reference" — otherwise the
// field KEK they still need is deleted and the CA private key is
// crypto-shredded.
func TestRotateKEKFieldUnreadableCertsFailsClosed(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root ignores directory permissions")
	}
	te := newTestEnv(t)
	s := te.initPlain(t)
	s.retiredGrace = 0
	ff := makeFieldFixture(t, te, s)
	oldKEK := activeKEK(t, te, core.KEKField)
	dir := filepath.Dir(ff.file)
	if err := os.Chmod(dir, 0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })

	// The enumeration fails, so the rotation must fail too.
	if _, err := s.sealedFiles(); err == nil {
		t.Fatal("sealedFiles succeeded on an unreadable directory")
	}
	if err := s.RotateKEK(ctx, core.KEKField, nil); err == nil {
		t.Fatal("RotateKEK succeeded although certs/ could not be walked")
	}
	// A second rotation (the reporter's scenario: retire, then prune) must
	// not delete the KEK the hidden file is sealed with either.
	if err := s.RotateKEK(ctx, core.KEKField, nil); err == nil {
		t.Fatal("second RotateKEK succeeded although certs/ could not be walked")
	}
	if _, err := s.PruneRetired(ctx); err == nil {
		t.Fatal("PruneRetired succeeded although certs/ could not be walked")
	}
	if n := te.count(t, `SELECT count(*) FROM keyring WHERE id = ?`, oldKEK); n != 1 {
		t.Fatalf("field KEK %s was deleted while its key file was invisible", oldKEK)
	}
	// Verify still renders, but says so and calls nothing unreferenced.
	rep := must[*VerifyReport](t)(s.Verify(ctx))
	if rep.OK || !strings.Contains(strings.Join(rep.Problems, "\n"), "cannot enumerate the sealed key files") {
		t.Fatalf("verify: ok=%v problems=%q", rep.OK, rep.Problems)
	}
	if slices.Contains(rep.Unreferenced, oldKEK) {
		t.Fatalf("%s reported as unreferenced: %q", oldKEK, rep.Unreferenced)
	}

	// Once the directory is readable again the key file still opens.
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	s = te.reopen(t, s)
	b, err := os.ReadFile(ff.file)
	if err != nil {
		t.Fatal(err)
	}
	pt, err := s.OpenField("file|certs/ca/ca.key", strings.TrimSpace(string(b)))
	if err != nil || string(pt) != "PRIVATE KEY DER" {
		t.Fatalf("OpenField after the failed rotations: %q %v", pt, err)
	}
	// And a rotation now works, re-sealing the file under the new KEK.
	if err := s.RotateKEK(ctx, core.KEKField, nil); err != nil {
		t.Fatal(err)
	}
	b = must[[]byte](t)(os.ReadFile(ff.file))
	if want := "v1:" + activeKEK(t, te, core.KEKField) + ":"; !strings.HasPrefix(strings.TrimSpace(string(b)), want) {
		t.Fatalf("key file not re-sealed under %s", want)
	}
}

// TestSealedFilesTolerates: certs/ missing, an unparsable *.enc file and a
// file removed mid-walk are no reference and must not block a rotation.
func TestSealedFilesTolerates(t *testing.T) {
	te := newTestEnv(t)
	s := te.initPlain(t)
	certs := te.h.CertsDir()
	if err := os.RemoveAll(certs); err != nil {
		t.Fatal(err)
	}
	if files := must[[]sealedFile](t)(s.sealedFiles()); len(files) != 0 {
		t.Fatalf("no certs dir: %d files", len(files))
	}
	if err := os.MkdirAll(filepath.Join(certs, "custom"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(certs, "custom", "stray.enc"), []byte("not sealed\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if files := must[[]sealedFile](t)(s.sealedFiles()); len(files) != 0 {
		t.Fatalf("stray .enc counted: %+v", files)
	}
	if err := s.RotateKEK(ctx, core.KEKField, nil); err != nil {
		t.Fatalf("rotation blocked by a stray .enc file: %v", err)
	}
}

// TestStaleNextDoesNotRevertKeyFileWrites: a master key rotation whose final
// rename fails leaves keys/master.key.next behind with the mk_id the database
// now names, so recoverNext renames it over master.key at the next start.
// Every later key file write (Seal, Unseal, ChangePassphrase, ExportRecovery)
// must therefore drop it — otherwise the restart silently undoes that write:
// the server falls back to plain mode (master key in the clear again) or to
// the previous passphrase.
func TestStaleNextDoesNotRevertKeyFileWrites(t *testing.T) {
	te := newTestEnv(t)
	s := te.initPlain(t)
	next := te.h.KeysFile() + fileSuffixNx
	// Simulate the failed rename: .next holds the file of the current mk_id.
	staleNext := func() {
		t.Helper()
		cur, err := os.ReadFile(te.h.KeysFile())
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(next, cur, 0o600); err != nil {
			t.Fatal(err)
		}
	}

	staleNext()
	if err := s.Seal(ctx, []byte(testPass)); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(next); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("Seal left %s in place: %v", next, err)
	}
	s = te.reopen(t, s)
	if st := s.State(); st != core.KeyStateLocked {
		t.Fatalf("state after restart = %s, want locked: the server reverted to plain mode and the master key is in the clear again", st)
	}
	if err := s.Unlock(ctx, []byte(testPass)); err != nil {
		t.Fatal(err)
	}

	const newPass = "an entirely different passphrase"
	staleNext()
	if err := s.ChangePassphrase(ctx, []byte(testPass), []byte(newPass)); err != nil {
		t.Fatal(err)
	}
	s = te.reopen(t, s)
	if err := s.Unlock(ctx, []byte(newPass)); err != nil {
		t.Fatalf("the new passphrase no longer unlocks after a restart: %v", err)
	}
	if s.verifySecret([]byte(testPass)) {
		t.Fatal("the old passphrase still unlocks after ChangePassphrase and a restart")
	}
}

// TestRotationsWaitForTheKeyMaterialHold: while a backup copies the key
// material (HoldKeyMaterial), a master key rotation and a field KEK rotation
// must not run — they would leave an archive whose keys/master.key or
// certs/*.enc do not belong to its database snapshot. A blob KEK rotation
// touches no key file and stays allowed.
func TestRotationsWaitForTheKeyMaterialHold(t *testing.T) {
	te := newTestEnv(t)
	s := te.initPlain(t)
	s.retiredGrace = 0
	release := s.HoldKeyMaterial()
	errIs(t, s.RotateMaster(ctx), core.ErrConflict, "RotateMaster while the key material is held")
	errIs(t, s.RotateKEK(ctx, core.KEKField, nil), core.ErrConflict, "RotateKEK(field) while the key material is held")
	if err := s.RotateKEK(ctx, core.KEKBlob, nil); err != nil {
		t.Fatalf("RotateKEK(blob) must not be blocked: %v", err)
	}
	release()
	release() // idempotent
	if err := s.RotateMaster(ctx); err != nil {
		t.Fatalf("rotation after the hold was released: %v", err)
	}
	if err := s.RotateKEK(ctx, core.KEKField, nil); err != nil {
		t.Fatalf("field rotation after the hold was released: %v", err)
	}
}

// TestRotateKEKFieldSkipsFileChangedMeanwhile: a key file that its owner
// rewrites between the enumeration and the replacing rename is left alone —
// it still names its own KEK, so it must be counted neither as re-wrapped
// (the audit entry would claim a file it did not touch) nor as failed.
func TestRotateKEKFieldSkipsFileChangedMeanwhile(t *testing.T) {
	te := newTestEnv(t)
	s := te.initPlain(t)
	s.retiredGrace = 0
	ff := makeFieldFixture(t, te, s)
	const aad = "file|certs/ca/ca.key"
	var once sync.Once
	// The column phase runs before the key files, so this rewrite lands
	// between sealedFiles() and the rename of certs/ca/ca.key.enc.
	err := s.RotateKEK(ctx, core.KEKField, func(int64, int64) {
		once.Do(func() {
			sealed, err := s.SealField(aad, []byte("A NEWER PRIVATE KEY"))
			if err != nil {
				t.Error(err)
				return
			}
			if err := os.WriteFile(ff.file, []byte(sealed+"\n"), 0o600); err != nil {
				t.Error(err)
			}
		})
	})
	if err != nil {
		t.Fatalf("rotation: %v", err)
	}
	entries := te.audit.find(core.ActKeysRotate, core.OutcomeSuccess)
	if len(entries) == 0 {
		t.Fatal("no rotation audit entry")
	}
	d, _ := entries[len(entries)-1].Details.(map[string]any)
	if d == nil {
		t.Fatal("rotation audit details missing")
	}
	wantRewrapped := int64(len(ff.values) - 1) // the values minus the key file
	if got := d["rewrapped"]; got != wantRewrapped {
		t.Errorf("rewrapped = %v, want %d: the key file was left as it was and must not be counted", got, wantRewrapped)
	}
	if got := d["skipped"]; got != int64(1) {
		t.Errorf("skipped = %v, want 1", got)
	}
	if got := d["failed"]; got != int64(0) {
		t.Errorf("failed = %v, want 0", got)
	}
	// What its owner wrote is still there and still readable.
	pt, err := s.OpenField(aad, strings.TrimSpace(string(must[[]byte](t)(os.ReadFile(ff.file)))))
	if err != nil || string(pt) != "A NEWER PRIVATE KEY" {
		t.Fatalf("key file content: %q %v", pt, err)
	}
}

// TestRotateKEKFieldZipPasswordWipedMeanwhile: a .zip password wiped to NULL
// (its batch finished) while the field KEK rotates stays NULL: the
// compare-and-swap never writes a re-sealed copy back, and the old KEK is
// not kept for it.
func TestRotateKEKFieldZipPasswordWipedMeanwhile(t *testing.T) {
	te := newTestEnv(t)
	s := te.initPlain(t)
	s.retiredGrace = 0
	ff := makeFieldFixture(t, te, s)
	oldKEK := activeKEK(t, te, core.KEKField)
	var once sync.Once
	// upload_batches is re-sealed after the other columns: the first
	// progress report comes before it.
	if err := s.RotateKEK(ctx, core.KEKField, func(int64, int64) {
		once.Do(func() {
			te.exec(t, `UPDATE upload_batches SET state = 'done', zip_password_enc = NULL WHERE id = ?`, ff.batch)
		})
	}); err != nil {
		t.Fatalf("rotation: %v", err)
	}
	if n := te.count(t, `SELECT count(*) FROM upload_batches WHERE zip_password_enc IS NOT NULL`); n != 0 {
		t.Fatalf("%d .zip passwords after the rotation", n)
	}
	newKEK := activeKEK(t, te, core.KEKField)
	got := readSealed(t, te, ff)
	if len(got) != len(ff.values)-1 {
		t.Fatalf("found %d sealed values, want %d", len(got), len(ff.values)-1)
	}
	for aad, sealed := range got {
		if !strings.HasPrefix(sealed, "v1:"+newKEK+":") {
			t.Errorf("%s not re-sealed", aad)
		}
	}
	entries := te.audit.find(core.ActKeysRotate, core.OutcomeSuccess)
	if len(entries) == 0 {
		t.Fatal("no rotation audit entry")
	}
	if d, _ := entries[len(entries)-1].Details.(map[string]any); d["rewrapped"] != int64(len(ff.values)-1) || d["failed"] != int64(0) {
		t.Fatalf("audit details %v", d)
	}
	if te.count(t, `SELECT count(*) FROM keyring WHERE id = ?`, oldKEK) != 0 {
		t.Fatal("the old field KEK was kept for a wiped value")
	}
	if rep := must[*VerifyReport](t)(s.Verify(ctx)); !rep.OK {
		t.Fatalf("verify: %+v", rep.Problems)
	}
}
