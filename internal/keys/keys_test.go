package keys

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"

	"fileparcel/internal/core"
	"fileparcel/internal/crypt"
	"fileparcel/internal/events"
	"fileparcel/internal/ids"
)

var ctx = context.Background()

var recoveryRe = regexp.MustCompile(`^FPRK(-[0-9A-HJKMNP-TV-Z]{4}){13}$`)

func TestPlainInitAndReopen(t *testing.T) {
	te := newTestEnv(t)
	s := te.open(t)
	if s.State() != core.KeyStateUninitialized {
		t.Fatalf("state %s", s.State())
	}
	if _, _, _, err := s.NewDEK(make([]byte, 16)); !isErr(err, core.ErrKeysLocked) {
		t.Fatalf("NewDEK uninitialized: %v", err)
	}
	st, err := s.Status(ctx)
	if err != nil || st.State != core.KeyStateUninitialized || len(st.KEKs) != 0 {
		t.Fatalf("status %+v %v", st, err)
	}
	events, cancel := te.env.Bus.Subscribe("keys.state")
	defer cancel()
	rk, err := s.Init(ctx, false, nil)
	if err != nil || rk != "" {
		t.Fatalf("Init: %q %v", rk, err)
	}
	if s.State() != core.KeyStateUnlocked {
		t.Fatalf("state %s", s.State())
	}
	select {
	case ev := <-events:
		if ev.Data.(core.KeysStateEvent).State != core.KeyStateUnlocked {
			t.Fatalf("event %+v", ev)
		}
	case <-time.After(time.Second):
		t.Fatal("no keys.state event")
	}
	fi, err := os.Stat(te.h.KeysFile())
	if err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("key file mode %v %v", fi.Mode(), err)
	}
	var kf map[string]any
	data, _ := os.ReadFile(te.h.KeysFile())
	if err := json.Unmarshal(data, &kf); err != nil || kf["mode"] != "plain" || kf["v"] != 1.0 {
		t.Fatalf("key file %s", data)
	}
	if !ids.Valid(ids.PrefixMasterKey, te.meta(t, metaMKID)) || len(te.meta(t, metaMKCheck)) != 64 {
		t.Fatal("meta not written")
	}
	if n := te.count(t, `SELECT count(*) FROM keyring WHERE state = 'active'`); n != 3 {
		t.Fatalf("active keks %d", n)
	}

	blobID := crypt.RandomBytes(16)
	dek, wrapped, kekID, err := s.NewDEK(blobID)
	if err != nil || len(dek) != 32 {
		t.Fatal(err)
	}
	sealed := must[string](t)(s.SealField("invites.token_enc|inv_1", []byte("secret token")))
	mac := s.MAC("audit", []byte("row"))
	if len(mac) != 32 {
		t.Fatal("mac length")
	}

	s2 := te.reopen(t, s)
	if s2.State() != core.KeyStateUnlocked {
		t.Fatalf("reopened plain state %s", s2.State())
	}
	got, err := s2.UnwrapDEK(blobID, kekID, wrapped)
	if err != nil || !bytes.Equal(got, dek) {
		t.Fatalf("unwrap after reopen: %v", err)
	}
	pt, err := s2.OpenField("invites.token_enc|inv_1", sealed)
	if err != nil || string(pt) != "secret token" {
		t.Fatalf("open field after reopen: %q %v", pt, err)
	}
	if !bytes.Equal(s2.MAC("audit", []byte("row")), mac) {
		t.Fatal("MAC changed across restart")
	}
	st, err = s2.Status(ctx)
	if err != nil || st.Mode != core.KeyModePlain || st.RecoveryConfigured || len(st.KEKs) != 3 || st.WebUnlock != "lan" ||
		st.CipherName == "" || st.MKID != te.meta(t, metaMKID) {
		t.Fatalf("status %+v %v", st, err)
	}
}

func TestInitErrors(t *testing.T) {
	te := newTestEnv(t)
	s := te.open(t)
	_, err := s.Init(ctx, true, nil)
	errIs(t, err, core.ErrInvalid, "sealed without passphrase")
	_, err = s.Init(ctx, true, []byte("short"))
	errIs(t, err, core.ErrInvalid, "short passphrase")
	_, err = s.Init(ctx, true, bytes.Repeat([]byte("x"), MaxPassphraseLen+1))
	errIs(t, err, core.ErrInvalid, "long passphrase")
	_, err = s.Init(ctx, false, []byte(testPass))
	errIs(t, err, core.ErrInvalid, "plain with passphrase")
	if _, err := s.Init(ctx, false, nil); err != nil {
		t.Fatal(err)
	}
	_, err = s.Init(ctx, false, nil)
	errIs(t, err, core.ErrConflict, "second init")
	// A fresh service over an initialised database refuses too.
	s2 := te.reopen(t, s)
	_, err = s2.Init(ctx, true, []byte(testPass))
	errIs(t, err, core.ErrConflict, "init after reopen")
}

func TestSealedRoundTrip(t *testing.T) {
	te := newTestEnv(t)
	s, rk := te.initSealed(t)
	if !recoveryRe.MatchString(rk) {
		t.Fatalf("recovery key format %q", rk)
	}
	blobID := crypt.RandomBytes(16)
	dek, wrapped, kekID := must3(t)(s.NewDEK(blobID))
	sealed := must[string](t)(s.SealField("shares.token_enc|shr_1", []byte("tok")))
	mac := s.MAC("recovery", []byte("u"), []byte("code"))
	st := must[*core.KeyStatus](t)(s.Status(ctx))
	if st.Mode != core.KeyModeSealed || !st.RecoveryConfigured {
		t.Fatalf("status %+v", st)
	}

	s = te.reopen(t, s)
	if s.State() != core.KeyStateLocked {
		t.Fatalf("sealed reopen state %s", s.State())
	}
	// Everything but State/Status/Unlock is locked.
	if _, _, _, err := s.NewDEK(blobID); !isErr(err, core.ErrKeysLocked) {
		t.Fatalf("NewDEK: %v", err)
	}
	if _, err := s.UnwrapDEK(blobID, kekID, wrapped); !isErr(err, core.ErrKeysLocked) {
		t.Fatalf("UnwrapDEK: %v", err)
	}
	if _, err := s.SealField("a", nil); !isErr(err, core.ErrKeysLocked) {
		t.Fatalf("SealField: %v", err)
	}
	if _, err := s.OpenField("a", sealed); !isErr(err, core.ErrKeysLocked) {
		t.Fatalf("OpenField: %v", err)
	}
	if s.MAC("recovery") != nil {
		t.Fatal("MAC while locked")
	}
	for name, err := range map[string]error{
		"Seal":           s.Seal(ctx, []byte(testPass)),
		"Unseal":         s.Unseal(ctx, []byte(testPass)),
		"Passphrase":     s.ChangePassphrase(ctx, []byte(testPass), []byte(testPass+"2")),
		"RotateKEK":      s.RotateKEK(ctx, core.KEKBlob, nil),
		"RotateMaster":   s.RotateMaster(ctx),
		"ExportRecovery": func() error { _, err := s.ExportRecovery(ctx); return err }(),
	} {
		if !isErr(err, core.ErrKeysLocked) {
			t.Errorf("%s while locked: %v", name, err)
		}
	}
	if st := must[*core.KeyStatus](t)(s.Status(ctx)); st.State != core.KeyStateLocked || len(st.KEKs) != 3 {
		t.Fatalf("locked status %+v", st)
	}

	errIs(t, s.Unlock(ctx, []byte("wrong passphrase")), core.ErrInvalid, "wrong passphrase")
	errIs(t, s.Unlock(ctx, nil), core.ErrInvalid, "empty passphrase")
	if len(te.audit.find(core.ActKeysUnlock, core.OutcomeFailure)) != 1 {
		t.Fatal("failed unlock not audited")
	}
	evs, cancel := te.env.Bus.Subscribe(events.TopicKeysState)
	defer cancel()
	if err := s.Unlock(ctx, []byte(testPass)); err != nil {
		t.Fatal(err)
	}
	if ev := <-evs; ev.Data.(core.KeysStateEvent).State != core.KeyStateUnlocked {
		t.Fatalf("event %+v", ev)
	}
	if e := te.audit.find(core.ActKeysUnlock, core.OutcomeSuccess); len(e) != 1 || e[0].Details.(map[string]any)["method"] != "passphrase" {
		t.Fatalf("unlock audit %+v", e)
	}
	errIs(t, s.Unlock(ctx, []byte(testPass)), core.ErrConflict, "unlock twice")
	if got := must[[]byte](t)(s.UnwrapDEK(blobID, kekID, wrapped)); !bytes.Equal(got, dek) {
		t.Fatal("DEK changed")
	}
	if pt := must[[]byte](t)(s.OpenField("shares.token_enc|shr_1", sealed)); string(pt) != "tok" {
		t.Fatal("field changed")
	}
	if !bytes.Equal(s.MAC("recovery", []byte("u"), []byte("code")), mac) {
		t.Fatal("MAC changed")
	}

	// Lock, then unlock with the recovery key in a sloppy spelling.
	if err := s.Lock(ctx); err != nil {
		t.Fatal(err)
	}
	if s.State() != core.KeyStateLocked || s.MAC("x") != nil {
		t.Fatal("not locked")
	}
	if err := s.Lock(ctx); err != nil {
		t.Fatalf("second lock: %v", err)
	}
	sloppy := strings.ToLower(strings.ReplaceAll(rk, "-", " "))
	if err := s.Unlock(ctx, []byte(sloppy)); err != nil {
		t.Fatalf("recovery unlock: %v", err)
	}
	if e := te.audit.find(core.ActKeysUnlock, core.OutcomeSuccess); len(e) != 2 || e[1].Details.(map[string]any)["method"] != "recovery_key" {
		t.Fatalf("recovery unlock audit %+v", e)
	}
	if len(te.audit.find(core.ActKeysLock, core.OutcomeSuccess)) != 1 {
		t.Fatal("lock not audited")
	}
}

func must3(t testing.TB) func(a, b []byte, c string, err error) ([]byte, []byte, string) {
	return func(a, b []byte, c string, err error) ([]byte, []byte, string) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
		return a, b, c
	}
}

func TestLockRequiresSealed(t *testing.T) {
	te := newTestEnv(t)
	s := te.open(t)
	errIs(t, s.Lock(ctx), core.ErrPrecondition, "lock uninitialized")
	errIs(t, s.Unlock(ctx, []byte(testPass)), core.ErrPrecondition, "unlock uninitialized")
	te.initPlainOn(t, s)
	errIs(t, s.Lock(ctx), core.ErrPrecondition, "lock plain")
	errIs(t, s.Unlock(ctx, []byte(testPass)), core.ErrConflict, "unlock unlocked")
}

func (te *testEnv) initPlainOn(t testing.TB, s *Service) {
	t.Helper()
	if _, err := s.Init(ctx, false, nil); err != nil {
		t.Fatal(err)
	}
}

func TestSealUnsealPassphraseRecovery(t *testing.T) {
	te := newTestEnv(t)
	s := te.initPlain(t)
	sealed := must[string](t)(s.SealField("settings.value|smtp.password", []byte("pw")))

	errIs(t, s.ChangePassphrase(ctx, []byte(testPass), []byte(testPass)), core.ErrPrecondition, "passphrase on plain")
	errIs(t, s.Unseal(ctx, []byte(testPass)), core.ErrConflict, "unseal plain")
	errIs(t, s.Seal(ctx, []byte("short")), core.ErrInvalid, "short seal passphrase")
	if err := s.Seal(ctx, []byte(testPass)); err != nil {
		t.Fatal(err)
	}
	errIs(t, s.Seal(ctx, []byte(testPass)), core.ErrConflict, "seal twice")
	if s.State() != core.KeyStateUnlocked || s.mode() != core.KeyModeSealed {
		t.Fatal("seal changed state")
	}
	if len(te.audit.find(core.ActKeysSeal, core.OutcomeSuccess)) != 1 {
		t.Fatal("seal not audited")
	}

	s = te.reopen(t, s)
	if s.State() != core.KeyStateLocked {
		t.Fatalf("state after seal+reopen %s", s.State())
	}
	if err := s.Unlock(ctx, []byte(testPass)); err != nil {
		t.Fatal(err)
	}
	pass2 := []byte("another good passphrase")
	errIs(t, s.ChangePassphrase(ctx, []byte("not the passphrase"), pass2), core.ErrInvalid, "wrong old passphrase")
	if err := s.ChangePassphrase(ctx, []byte(testPass), pass2); err != nil {
		t.Fatal(err)
	}
	s = te.reopen(t, s)
	errIs(t, s.Unlock(ctx, []byte(testPass)), core.ErrInvalid, "old passphrase after change")
	if err := s.Unlock(ctx, pass2); err != nil {
		t.Fatal(err)
	}

	// A plain init has no recovery key; export one and use it to reset a
	// forgotten passphrase.
	if st := must[*core.KeyStatus](t)(s.Status(ctx)); st.RecoveryConfigured {
		t.Fatal("recovery configured without export")
	}
	rk := must[string](t)(s.ExportRecovery(ctx))
	if !recoveryRe.MatchString(rk) {
		t.Fatalf("recovery %q", rk)
	}
	rk2 := must[string](t)(s.ExportRecovery(ctx))
	errIs(t, s.ChangePassphrase(ctx, []byte(rk), []byte(testPass)), core.ErrInvalid, "replaced recovery key")
	errIs(t, s.ChangePassphrase(ctx, []byte(rk2), []byte(rk2)), core.ErrInvalid, "recovery key as passphrase")
	pass3 := []byte("third passphrase here")
	if err := s.ChangePassphrase(ctx, []byte(rk2), pass3); err != nil {
		t.Fatalf("reset via recovery key: %v", err)
	}
	s = te.reopen(t, s)
	if err := s.Unlock(ctx, pass3); err != nil {
		t.Fatal(err)
	}
	s = te.reopen(t, s)
	if err := s.Unlock(ctx, []byte(rk2)); err != nil {
		t.Fatalf("recovery key survives passphrase change: %v", err)
	}

	errIs(t, s.Unseal(ctx, []byte("wrong")), core.ErrInvalid, "unseal wrong")
	if err := s.Unseal(ctx, pass3); err != nil {
		t.Fatal(err)
	}
	s = te.reopen(t, s)
	if s.State() != core.KeyStateUnlocked {
		t.Fatalf("unsealed reopen %s", s.State())
	}
	if pt := must[[]byte](t)(s.OpenField("settings.value|smtp.password", sealed)); string(pt) != "pw" {
		t.Fatal("field lost")
	}
	// The recovery slot survives unseal and becomes valid again after a seal.
	if st := must[*core.KeyStatus](t)(s.Status(ctx)); !st.RecoveryConfigured {
		t.Fatal("recovery slot dropped by unseal")
	}
	if err := s.Seal(ctx, []byte(testPass)); err != nil {
		t.Fatal(err)
	}
	s = te.reopen(t, s)
	if err := s.Unlock(ctx, []byte(rk2)); err != nil {
		t.Fatalf("recovery after re-seal: %v", err)
	}
	for _, a := range []string{core.ActKeysPassphrase, core.ActKeysUnseal, core.ActKeysRecoveryExport} {
		if len(te.audit.find(a, core.OutcomeSuccess)) == 0 {
			t.Errorf("%s not audited", a)
		}
	}
}

func TestRecoveryKeyFormat(t *testing.T) {
	for range 50 {
		raw := crypt.RandomBytes(32)
		s := formatRecoveryKey(raw)
		if !recoveryRe.MatchString(s) {
			t.Fatalf("format %q", s)
		}
		for _, v := range []string{s, strings.ToLower(s), strings.ReplaceAll(s, "-", ""), " " + strings.ReplaceAll(s, "-", " ") + "\n",
			strings.NewReplacer("0", "o", "1", "l").Replace(s)} {
			got, err := parseRecoveryKey([]byte(v))
			if err != nil || !bytes.Equal(got, raw) {
				t.Fatalf("parse %q: %v", v, err)
			}
		}
	}
	good := formatRecoveryKey(make([]byte, 32))
	for _, bad := range []string{"", "FPRK", good[:len(good)-1], good + "0", "XPRK" + good[4:], good[:10] + "U" + good[11:],
		good[:len(good)-1] + "1" /* padding bit set */} {
		if _, err := parseRecoveryKey([]byte(bad)); !errors.Is(err, errNotRecoveryKey) {
			t.Errorf("accepted %q", bad)
		}
	}
	errIs(t, checkPassphrase("p", []byte(good)), core.ErrInvalid, "recovery key as passphrase")
}

func TestDEKWrapping(t *testing.T) {
	te := newTestEnv(t)
	s := te.initPlain(t)
	idA, idB := crypt.RandomBytes(16), crypt.RandomBytes(16)
	dek, wrapped, kekID := must3(t)(s.NewDEK(idA))
	// hex form is equivalent to raw form
	hexA := []byte(strings.ToLower(hexString(idA)))
	if got, err := s.UnwrapDEK(hexA, kekID, wrapped); err != nil || !bytes.Equal(got, dek) {
		t.Fatalf("hex id: %v", err)
	}
	_, err := s.UnwrapDEK(idB, kekID, wrapped)
	errIs(t, err, core.ErrCorrupt, "other blob id")
	_, err = s.UnwrapDEK(idA, "kek_unknown", wrapped)
	errIs(t, err, core.ErrCorrupt, "unknown kek")
	_, err = s.UnwrapDEK(idA, activeKEK(t, te, core.KEKField), wrapped)
	errIs(t, err, core.ErrCorrupt, "field kek for dek")
	bad := bytes.Clone(wrapped)
	bad[len(bad)-1] ^= 1
	_, err = s.UnwrapDEK(idA, kekID, bad)
	errIs(t, err, core.ErrCorrupt, "tampered")
	_, err = s.UnwrapDEK(idA, kekID, wrapped[:10])
	errIs(t, err, core.ErrCorrupt, "short")
	for _, id := range [][]byte{nil, make([]byte, 15), []byte("ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ"), []byte("../../../../../../../etc/passwd00")} {
		if _, _, _, err := s.NewDEK(id); !isErr(err, core.ErrInvalid) {
			t.Errorf("NewDEK(%q): %v", id, err)
		}
	}
	_, w2, _ := must3(t)(s.NewDEK(idA))
	if bytes.Equal(w2, wrapped) {
		t.Fatal("DEKs must be random")
	}
}

func hexString(b []byte) string {
	const hx = "0123456789abcdef"
	out := make([]byte, 0, len(b)*2)
	for _, c := range b {
		out = append(out, hx[c>>4], hx[c&15])
	}
	return string(out)
}

func TestFieldAADBinding(t *testing.T) {
	te := newTestEnv(t)
	s := te.initPlain(t)
	a := must[string](t)(s.SealField("totp_secrets.secret_enc|usr_a", []byte("JBSWY3DPEHPK3PXP")))
	b := must[string](t)(s.SealField("totp_secrets.secret_enc|usr_b", []byte("OTHERSECRET")))
	if !strings.HasPrefix(a, "v1:"+activeKEK(t, te, core.KEKField)+":") {
		t.Fatalf("format %q", a)
	}
	if strings.ContainsAny(strings.SplitN(a, ":", 3)[2], "+/=") {
		t.Fatal("not base64url without padding")
	}
	// Row swap: b's value copied into a's row must not open.
	_, err := s.OpenField("totp_secrets.secret_enc|usr_a", b)
	errIs(t, err, core.ErrCorrupt, "row swap")
	if pt := must[[]byte](t)(s.OpenField("totp_secrets.secret_enc|usr_b", b)); string(pt) != "OTHERSECRET" {
		t.Fatal("open b")
	}
	parts := strings.SplitN(a, ":", 3)
	blobKEK := activeKEK(t, te, core.KEKBlob)
	for name, v := range map[string]string{
		"tampered":    parts[0] + ":" + parts[1] + ":" + flipB64(parts[2]),
		"unknown kek": parts[0] + ":kek_nope:" + parts[2],
		"blob kek":    parts[0] + ":" + blobKEK + ":" + parts[2],
		"version":     "v2:" + parts[1] + ":" + parts[2],
		"no colon":    "garbage",
		"bad b64":     parts[0] + ":" + parts[1] + ":***",
		"empty":       "",
		"truncated":   parts[0] + ":" + parts[1] + ":" + parts[2][:8],
	} {
		if _, err := s.OpenField("totp_secrets.secret_enc|usr_a", v); !isErr(err, core.ErrCorrupt) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if a == must[string](t)(s.SealField("totp_secrets.secret_enc|usr_a", []byte("JBSWY3DPEHPK3PXP"))) {
		t.Fatal("field nonces must be random")
	}
}

func flipB64(s string) string {
	b := []byte(s)
	i := len(b) / 2
	if b[i] == 'A' {
		b[i] = 'B'
	} else {
		b[i] = 'A'
	}
	return string(b)
}

func TestMAC(t *testing.T) {
	te := newTestEnv(t)
	s := te.initPlain(t)
	m1 := s.MAC("audit", []byte("a"), []byte("b"))
	if !bytes.Equal(m1, s.MAC("audit", []byte("a"), []byte("b"))) {
		t.Fatal("not deterministic")
	}
	if bytes.Equal(m1, s.MAC("share", []byte("a"), []byte("b"))) {
		t.Fatal("purposes must be separated")
	}
	if bytes.Equal(m1, s.MAC("audit", []byte("ab"))) || bytes.Equal(s.MAC("audit", []byte("ab"), []byte("c")), s.MAC("audit", []byte("a"), []byte("bc"))) {
		t.Fatal("framing must be unambiguous")
	}
	// The subkey is HKDF(KEK[mac], "fp-mac|"+purpose) and the data length-framed.
	var macKEK []byte
	_ = s.withMaterial(func(m *material) error { macKEK = bytes.Clone(m.active[core.KEKMAC].key.b); return nil })
	sub, _ := crypt.HKDF(macKEK, nil, "fp-mac|audit", 32)
	if !bytes.Equal(m1, crypt.HMAC(sub, []byte("a"), []byte("b"))) {
		t.Fatal("MAC construction")
	}
	for i := range maxMACCache + 10 { // beyond the cache bound still works
		if len(s.MAC("p"+string(rune('a'+i%26))+strings.Repeat("x", i))) != 32 {
			t.Fatal("uncached MAC")
		}
	}
}

func TestCipherSetting(t *testing.T) {
	te := newTestEnv(t)
	s := te.initPlain(t)
	if s.Cipher() != core.CipherID(crypt.AutoCipher()) {
		t.Fatal("auto")
	}
	te.settings.set(settingCipher, cipherChaCha)
	if s.Cipher() != core.CipherChaCha20Poly1305 {
		t.Fatal("chacha")
	}
	te.settings.set(settingCipher, cipherAESGCM)
	if s.Cipher() != core.CipherAES256GCM {
		t.Fatal("aes")
	}
	te.settings.set(settingWebUnlock, "off")
	if st := must[*core.KeyStatus](t)(s.Status(ctx)); st.WebUnlock != "off" || st.Cipher != core.CipherAES256GCM || st.CipherName != "aes-256-gcm" {
		t.Fatalf("status %+v", st)
	}
}

func TestOpenRefusesForeignOrMissingKeyFile(t *testing.T) {
	a, b := newTestEnv(t), newTestEnv(t)
	sa := a.initPlain(t)
	sb := b.initPlain(t)
	sa.Close()
	sb.Close()
	keyA, _ := os.ReadFile(a.h.KeysFile())
	keyB, _ := os.ReadFile(b.h.KeysFile())

	// foreign key file (another install)
	if err := os.WriteFile(b.h.KeysFile(), keyA, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(b.env); err == nil || !strings.Contains(err.Error(), "foreign") {
		t.Fatalf("foreign key file: %v", err)
	}
	// same mk_id but another key (tampered file): mk_check fails
	var kf keyFile
	_ = json.Unmarshal(keyB, &kf)
	kf.Key = b64.EncodeToString(crypt.RandomBytes(32))
	_ = os.WriteFile(b.h.KeysFile(), kf.marshal(), 0o600)
	if _, err := Open(b.env); err == nil || !strings.Contains(err.Error(), "mk_check") {
		t.Fatalf("wrong key: %v", err)
	}
	// malformed file
	_ = os.WriteFile(b.h.KeysFile(), []byte(`{"v":1,"mode":"plain"}`), 0o600)
	if _, err := Open(b.env); err == nil {
		t.Fatal("malformed accepted")
	}
	_ = os.WriteFile(b.h.KeysFile(), []byte(`{"v":1,"mk_id":"`+kf.MKID+`","mode":"plain","key":"`+kf.Key+`","extra":1}`), 0o600)
	if _, err := Open(b.env); err == nil {
		t.Fatal("unknown field accepted")
	}
	// missing file for an initialised database
	_ = os.Remove(b.h.KeysFile())
	if _, err := Open(b.env); err == nil || !strings.Contains(err.Error(), "missing") {
		t.Fatalf("missing: %v", err)
	}
	// the right file works again
	_ = os.WriteFile(b.h.KeysFile(), keyB, 0o644)
	s := b.open(t)
	if s.State() != core.KeyStateUnlocked {
		t.Fatal("restored key file")
	}
	if fi, _ := os.Stat(b.h.KeysFile()); fi.Mode().Perm() != 0o600 {
		t.Fatalf("mode not tightened: %v", fi.Mode())
	}
}

func TestSealedForeignKeyRejectedAtUnlock(t *testing.T) {
	te := newTestEnv(t)
	s, _ := te.initSealed(t)
	s.Close()
	// Re-seal the key file around a different MK but keep mk_id: Open
	// accepts it (mk_id matches), Unlock must refuse via mk_check.
	data, _ := os.ReadFile(te.h.KeysFile())
	kf, err := parseKeyFile(data)
	if err != nil {
		t.Fatal(err)
	}
	pk, _ := deriveKey([]byte(testPass), kf.KDF)
	box, _ := sealBox(pk, crypt.RandomBytes(32), aadMK(kf.MKID))
	kf.Nonce, kf.CT = box.Nonce, box.CT
	_ = os.WriteFile(te.h.KeysFile(), kf.marshal(), 0o600)
	s = te.open(t)
	err = s.Unlock(ctx, []byte(testPass))
	errIs(t, err, core.ErrCorrupt, "foreign sealed MK")
	if s.State() != core.KeyStateLocked {
		t.Fatal("unlocked with a foreign key")
	}
}

func TestInterruptedInitIsReplaced(t *testing.T) {
	te := newTestEnv(t)
	// A key file without any keyring (crash between file write and DB tx).
	kf := &keyFile{V: 1, MKID: ids.New(ids.PrefixMasterKey), Mode: core.KeyModePlain, Key: b64.EncodeToString(crypt.RandomBytes(32))}
	if err := writeFileAtomic(te.h.KeysFile(), kf.marshal(), 0o600); err != nil {
		t.Fatal(err)
	}
	s := te.open(t)
	if s.State() != core.KeyStateUninitialized {
		t.Fatalf("state %s", s.State())
	}
	if _, err := s.Init(ctx, false, nil); err != nil {
		t.Fatal(err)
	}
	if te.meta(t, metaMKID) == kf.MKID {
		t.Fatal("stale key reused")
	}
	s = te.reopen(t, s)
	if s.State() != core.KeyStateUnlocked {
		t.Fatal("reopen")
	}
}

func TestVault(t *testing.T) {
	v := newVault()
	var list []*secret
	for i := range 300 { // spans several pages
		s := v.put(bytes.Repeat([]byte{byte(i)}, 32))
		list = append(list, s)
	}
	for i, s := range list {
		if s.Bytes()[0] != byte(i) || s.Bytes()[31] != byte(i) {
			t.Fatal("slot overlap")
		}
	}
	b := list[5].Bytes()
	v.release(list[5])
	if !bytes.Equal(b, make([]byte, 32)) {
		t.Fatal("release must zero")
	}
	v.release(list[5]) // idempotent
	n := v.put(bytes.Repeat([]byte{9}, 32))
	if n.Bytes()[0] != 9 {
		t.Fatal("reuse")
	}
	t.Logf("vault mlocked: %v", v.mlocked())
	mem := list[0].Bytes()
	v.destroy()
	v.destroy()
	_ = mem // unmapped: must not be touched
	defer func() {
		if recover() == nil {
			t.Fatal("put after destroy must panic")
		}
	}()
	v.put(make([]byte, 32))
}

func TestKeyFileParse(t *testing.T) {
	good := &keyFile{V: 1, MKID: ids.New(ids.PrefixMasterKey), Mode: core.KeyModeSealed,
		KDF: newKDF(kdfConfig{T: 3, MKiB: 131072, P: 4})}
	box, _ := sealBox(crypt.RandomBytes(32), crypt.RandomBytes(32), nil)
	good.Nonce, good.CT = box.Nonce, box.CT
	if _, err := parseKeyFile(good.marshal()); err != nil {
		t.Fatal(err)
	}
	withEscrow := good.clone()
	withEscrow.Recovery = box
	withEscrow.Escrow = &escrow{Pass: box, Recovery: box}
	if _, err := parseKeyFile(withEscrow.marshal()); err != nil {
		t.Fatalf("escrow: %v", err)
	}
	mut := func(f func(k *keyFile)) []byte { k := good.clone(); f(k); return k.marshal() }
	for name, data := range map[string][]byte{
		"version":                      mut(func(k *keyFile) { k.V = 2 }),
		"mode":                         mut(func(k *keyFile) { k.Mode = "weird" }),
		"mk_id":                        mut(func(k *keyFile) { k.MKID = "kek_x" }),
		"huge memory":                  mut(func(k *keyFile) { k.KDF.MKiB = 1 << 30 }),
		"time":                         mut(func(k *keyFile) { k.KDF.T = 1000 }),
		"alg":                          mut(func(k *keyFile) { k.KDF.Alg = "scrypt" }),
		"salt":                         mut(func(k *keyFile) { k.KDF.Salt = "AAAA" }),
		"nonce":                        mut(func(k *keyFile) { k.Nonce = "AAAA" }),
		"ct":                           mut(func(k *keyFile) { k.CT = "AAAA" }),
		"no kdf":                       mut(func(k *keyFile) { k.KDF = nil }),
		"plain key":                    mut(func(k *keyFile) { k.Key = b64.EncodeToString(make([]byte, 32)) }),
		"recovery":                     mut(func(k *keyFile) { k.Recovery = &sealedBox{Nonce: "x", CT: "y"} }),
		"not json":                     []byte("{"),
		"empty escrow":                 mut(func(k *keyFile) { k.Escrow = &escrow{} }),
		"bad escrow":                   mut(func(k *keyFile) { k.Escrow = &escrow{Pass: &sealedBox{Nonce: "x", CT: "y"}} }),
		"recovery escrow without slot": mut(func(k *keyFile) { k.Escrow = &escrow{Recovery: box} }),
		"pass escrow in plain file": mut(func(k *keyFile) {
			k.Mode, k.KDF, k.Nonce, k.CT, k.Key = core.KeyModePlain, nil, "", "", b64.EncodeToString(make([]byte, 32))
			k.Escrow = &escrow{Pass: box}
		}),
	} {
		if _, err := parseKeyFile(data); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}

// TestProductionKDF runs one sealed init/unlock with the real argon2id
// parameters (t=3, m=128 MiB, p=4).
func TestProductionKDF(t *testing.T) {
	if realKDF != (kdfConfig{T: 3, MKiB: 128 * 1024, P: 4}) {
		t.Fatalf("default KDF %+v", realKDF)
	}
	if testing.Short() || raceEnabled {
		t.Skip("argon2id with 128 MiB is slow in -short/-race mode")
	}
	te := newTestEnv(t)
	s := te.open(t)
	s.kdf = realKDF
	if _, err := s.Init(ctx, true, []byte(testPass)); err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(te.h.KeysFile())
	kf, _ := parseKeyFile(data)
	if kf.KDF.T != 3 || kf.KDF.MKiB != 131072 || kf.KDF.P != 4 || kf.KDF.Alg != "argon2id" {
		t.Fatalf("kdf %+v", kf.KDF)
	}
	s = te.reopen(t, s)
	start := time.Now()
	if err := s.Unlock(ctx, []byte(testPass)); err != nil {
		t.Fatal(err)
	}
	t.Logf("unlock with production KDF took %v", time.Since(start))
}

// TestDamagedKeyring: a keyring that does not fully authenticate under the
// master key refuses to load (plain: Open fails; sealed: Unlock fails with
// ErrCorrupt and the service stays locked).
func TestDamagedKeyring(t *testing.T) {
	for _, tc := range []struct {
		name, want string
		damage     func(t *testing.T, te *testEnv)
	}{
		{"foreign wrapping", "another master key", func(t *testing.T, te *testEnv) {
			te.exec(t, `UPDATE keyring SET mk_id = ? WHERE purpose = 'blob'`, ids.New(ids.PrefixMasterKey))
		}},
		{"tampered entry", "failed authentication", func(t *testing.T, te *testEnv) {
			var w []byte
			_ = te.db.QueryRow(ctx, `SELECT wrapped FROM keyring WHERE purpose = 'field'`).Scan(&w)
			w[0] ^= 1
			te.exec(t, `UPDATE keyring SET wrapped = ? WHERE purpose = 'field'`, w)
		}},
		{"entry moved to another purpose", "failed authentication", func(t *testing.T, te *testEnv) {
			// The AAD binds id and purpose: relabelling a KEK is detected.
			te.exec(t, `UPDATE keyring SET state = 'retired', retired_at = 1 WHERE purpose = 'mac'`)
			te.exec(t, `UPDATE keyring SET purpose = 'mac' WHERE purpose = 'blob'`)
		}},
		{"no active key", "no active key for purpose mac", func(t *testing.T, te *testEnv) {
			te.exec(t, `UPDATE keyring SET state = 'retired', retired_at = 1 WHERE purpose = 'mac'`)
		}},
	} {
		t.Run(tc.name+"/plain", func(t *testing.T) {
			te := newTestEnv(t)
			s := te.initPlain(t)
			s.Close()
			tc.damage(t, te)
			if _, err := Open(te.env); err == nil || !strings.Contains(err.Error(), tc.want) || !isErr(err, core.ErrCorrupt) {
				t.Fatalf("Open: %v, want %q", err, tc.want)
			}
		})
		t.Run(tc.name+"/sealed", func(t *testing.T) {
			te := newTestEnv(t)
			s, rk := te.initSealed(t)
			s.Close()
			tc.damage(t, te)
			s = te.open(t)
			for _, secret := range []string{testPass, rk} {
				err := s.Unlock(ctx, []byte(secret))
				errIs(t, err, core.ErrCorrupt, "unlock of a damaged keyring")
				if !strings.Contains(err.Error(), tc.want) {
					t.Fatalf("unlock: %v, want %q", err, tc.want)
				}
			}
			if s.State() != core.KeyStateLocked || s.MAC("x") != nil {
				t.Fatal("damaged keyring unlocked")
			}
			if e := te.audit.find(core.ActKeysUnlock, core.OutcomeFailure); len(e) != 2 {
				t.Fatalf("failed unlocks audited %d times", len(e))
			}
		})
	}
}
