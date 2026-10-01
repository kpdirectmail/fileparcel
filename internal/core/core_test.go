package core

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestOptJSON(t *testing.T) {
	var u ShareUpdate
	if err := json.Unmarshal([]byte(`{"max_downloads":null,"expires_at":"2026-10-01T00:00:00Z"}`), &u); err != nil {
		t.Fatal(err)
	}
	if !u.MaxDownloads.Set || !u.MaxDownloads.Null || u.MaxDownloads.Ptr() != nil {
		t.Fatalf("null: %+v", u.MaxDownloads)
	}
	if !u.ExpiresAt.Set || u.ExpiresAt.Null || u.ExpiresAt.V.Year() != 2026 {
		t.Fatalf("value: %+v", u.ExpiresAt)
	}
	if u.UploadQuotaBytes.Set {
		t.Fatal("absent field marked set")
	}
	out, _ := json.Marshal(ShareUpdate{MaxDownloads: Some[int64](3), UploadQuotaBytes: Null[int64]()})
	if string(out) != `{"upload_quota_bytes":null,"max_downloads":3}` {
		t.Fatalf("marshal: %s", out)
	}
	var uu UserUpdate
	if err := json.Unmarshal([]byte(`{"quota_bytes":0}`), &uu); err != nil || !uu.QuotaBytes.Set || uu.QuotaBytes.Null || *uu.QuotaBytes.Ptr() != 0 {
		t.Fatalf("user quota: %+v %v", uu.QuotaBytes, err)
	}
}

func TestPageAndPerm(t *testing.T) {
	b, _ := json.Marshal(Page[int]{})
	if string(b) != `{"items":[]}` {
		t.Fatalf("empty page: %s", b)
	}
	b, _ = json.Marshal(NewPage([]string{"a"}, "c1"))
	if string(b) != `{"items":["a"],"next_cursor":"c1"}` {
		t.Fatalf("page: %s", b)
	}
	if (PageReq{}).EffectiveLimit() != 100 || (PageReq{Limit: 1000}).EffectiveLimit() != 500 {
		t.Fatal("EffectiveLimit")
	}
	b, _ = json.Marshal(Node{ID: "nod_1", Kind: KindFile, Perm: PermEdit})
	if !strings.Contains(string(b), `"perm":"edit"`) || strings.Contains(string(b), "blob") || strings.Contains(string(b), "name_key") {
		t.Fatalf("node json: %s", b)
	}
	var p Perm
	if err := json.Unmarshal([]byte(`"manage"`), &p); err != nil || p != PermManage {
		t.Fatal(err)
	}
	if !(PermNone < PermView && PermView < PermEdit && PermEdit < PermManage && PermManage < PermOwner) {
		t.Fatal("perm order")
	}
	if !ConflictRename.Valid() || ConflictPolicy("x").Valid() {
		t.Fatal("conflict")
	}
}

func TestSecretsNotSerialized(t *testing.T) {
	u := User{ID: "usr_1", PasswordHash: "$argon2id$secret", WebAuthnHandle: []byte("h")}
	s := Share{ID: "shr_1", PasswordHash: "pwhash", TokenHash: []byte("th")}
	sess := Session{ID: "ses_1", TokenHash: []byte("x"), CSRFSecret: []byte("y")}
	tok := APIToken{ID: "tok_1", TokenHash: []byte("z")}
	lr := LoginResult{Token: "raw-session-token"}
	for _, v := range []any{u, s, sess, tok, lr} {
		b, _ := json.Marshal(v)
		for _, bad := range []string{"argon2id", "pwhash", "raw-session-token", "token_hash", "csrf_secret", "password_hash", "webauthn_handle"} {
			if strings.Contains(string(b), bad) {
				t.Errorf("%T leaks %q: %s", v, bad, b)
			}
		}
	}
}

func TestPrincipal(t *testing.T) {
	now := time.Now()
	var nilP *Principal
	if nilP.IsAdmin() || nilP.Elevated(now) || nilP.Full() || nilP.HasScope(ScopeAdmin) {
		t.Fatal("nil principal")
	}
	sys := SystemPrincipal(ViaSocket)
	if !sys.IsAdmin() || !sys.IsSystem() || !sys.Elevated(now) || !sys.Full() || !sys.HasScope(ScopeAdmin) || sys.UserID != "" {
		t.Fatalf("system: %+v", sys)
	}
	tok := &Principal{Role: RoleAdmin, Via: ViaToken, AuthLevel: 2, Scopes: []string{ScopeFilesRead}}
	if tok.HasScope(ScopeAdmin) || !tok.HasScope(ScopeFilesRead) {
		t.Fatal("token scopes")
	}
	m := &Principal{Role: RoleMember, Via: ViaSession, AuthLevel: 2, ElevatedUntil: now.Add(time.Minute)}
	if m.IsAdmin() || !m.Elevated(now) || m.Elevated(now.Add(2*time.Minute)) {
		t.Fatal("elevation window")
	}
	m.EnrollRequired = true
	if m.Full() {
		t.Fatal("enroll required is not full")
	}
	ctx := WithPrincipal(context.Background(), m)
	if PrincipalFrom(ctx) != m || PrincipalFrom(context.Background()) != nil {
		t.Fatal("context")
	}
	c := tok.Clone()
	c.Scopes[0] = "x"
	if tok.Scopes[0] != ScopeFilesRead {
		t.Fatal("Clone must copy scopes")
	}
	if !RoleOwner.Valid() || RoleSystem.Valid() {
		t.Fatal("Role.Valid")
	}
}

func TestErrors(t *testing.T) {
	err := Errorf(ErrConflict, "%q exists", "a.txt")
	if !errors.Is(err, ErrConflict) || errors.Is(err, ErrNotFound) || err.Error() != `"a.txt" exists` {
		t.Fatalf("%v", err)
	}
	inv := Invalid("name", "too long")
	if AsError(inv).Status != 422 || inv.Error() != "name: too long" {
		t.Fatalf("%v", inv)
	}
	cause := errors.New("disk")
	w := Wrap(ErrUnavailable, "", cause)
	if !errors.Is(w, cause) || AsError(w).Message != ErrUnavailable.Message {
		t.Fatal("Wrap")
	}
	if AsError(errors.New("x")) != nil {
		t.Fatal("AsError on plain error")
	}
	if ErrNotFound.HTTPStatus() != 404 || (&Error{}).HTTPStatus() != 500 {
		t.Fatal("HTTPStatus")
	}
	if CipherAES256GCM.String() != "aes-256-gcm" || CipherID(9).String() != "unknown" {
		t.Fatal("CipherID")
	}
}

func TestInputOnlySecrets(t *testing.T) {
	pass := "hunter2-backup"
	b, err := json.Marshal(BackupConfig{Encryption: BackupPassphrase, Passphrase: &pass})
	if err != nil || strings.Contains(string(b), pass) || strings.Contains(string(b), `"passphrase":`) {
		t.Fatalf("BackupConfig leaks the passphrase: %s %v", b, err)
	}
	var in BackupConfig
	if err := json.Unmarshal([]byte(`{"encryption":"passphrase","passphrase":"p"}`), &in); err != nil || in.Passphrase == nil || *in.Passphrase != "p" {
		t.Fatalf("BackupConfig input: %+v %v", in, err)
	}
	// ProfileUpdate cannot carry admin-only fields.
	dec := json.NewDecoder(strings.NewReader(`{"display_name":"Bob","role":"owner"}`))
	dec.DisallowUnknownFields()
	var pu ProfileUpdate
	if err := dec.Decode(&pu); err == nil {
		t.Fatal("ProfileUpdate accepted role")
	}
	name := "Bob"
	uu := ProfileUpdate{DisplayName: &name}.UserUpdate()
	if uu.DisplayName != &name || uu.Role != nil || uu.QuotaBytes.Set || uu.MustChangePassword != nil {
		t.Fatalf("UserUpdate: %+v", uu)
	}
	if !errors.Is(Wrap(ErrCorrupt, "segment 3", nil), ErrCorrupt) || ErrCorrupt.HTTPStatus() != 500 {
		t.Fatal("ErrCorrupt")
	}
}
