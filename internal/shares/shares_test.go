package shares

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/netip"
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
	"fileparcel/internal/ratelimit"
	"fileparcel/internal/uploads/uploadtest"
)

// cheap argon2id parameters for tests.
var cheap = crypt.Argon2Params{MemoryKiB: 64, Time: 1, Threads: 1, SaltLen: 16, KeyLen: 32}

type fixture struct {
	*uploadtest.Env
	t         *testing.T
	svc       *Service
	ctx       context.Context
	alice     string
	aliceRoot string
	bob       string
	bobRoot   string
	uploads   *recUploads
}

// recUploads records AbortBatch calls (Revoke aborts open request batches).
type recUploads struct {
	core.Uploads
	mu      sync.Mutex
	aborted []string
}

func (u *recUploads) AbortBatch(_ context.Context, a core.UploadActor, id string) error {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.aborted = append(u.aborted, a.ShareID+"/"+id)
	return nil
}

func setup(t *testing.T) *fixture {
	t.Helper()
	e := uploadtest.New(t)
	svc, err := New(e.Env, e.Files, e.Limiter)
	if err != nil {
		t.Fatal(err)
	}
	svc.hashPassword = func(pw string) (string, error) { return crypt.HashPasswordParams(pw, cheap) }
	up := &recUploads{}
	if err := svc.Bind(&core.Services{Notify: e.Notify, Uploads: up}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = svc.Close() })
	f := &fixture{Env: e, t: t, svc: svc, ctx: context.Background(), uploads: up}
	f.alice, f.aliceRoot = e.User("alice", core.RoleMember)
	f.bob, f.bobRoot = e.User("bob", core.RoleMember)
	return f
}

func wantCode(t *testing.T, err error, want *core.Error) {
	t.Helper()
	if !errors.Is(err, want) {
		t.Fatalf("error = %v, want %s", err, want.Code)
	}
}

func ptr[T any](v T) *T { return &v }

func (f *fixture) create(p *core.Principal, in core.ShareInput) (*core.Share, string) {
	f.t.Helper()
	s, tok, err := f.svc.Create(f.ctx, p, in)
	if err != nil {
		f.t.Fatalf("Create: %v", err)
	}
	return s, tok
}

// ---------- create ----------

func TestCreate(t *testing.T) {
	f := setup(t)
	alice := f.P(f.alice)
	folder := f.Mkdir(f.aliceRoot, "Photos")
	file := f.PutFile(folder, "a.jpg", []byte("jpeg"))

	s, tok := f.create(alice, core.ShareInput{NodeID: file.ID, Title: "  Holiday  ", Message: "line1\nline2"})
	if s.Kind != core.ShareLink || s.Title != "Holiday" || s.Message != "line1\nline2" || !s.AllowDownload || !s.AllowPreview ||
		s.AllowUpload || s.HasPassword || s.Status != core.ShareActive || s.NodeName != "a.jpg" || s.CreatedByName != "Alice" {
		t.Fatalf("share = %+v", s)
	}
	if len(tok) != 22 || !ids.ValidToken(tok) || !ValidToken(tok) || s.URL != "/s/"+tok {
		t.Fatalf("token %q url %q", tok, s.URL)
	}
	// Default expiry: sharing.default_expiry_days (7).
	if s.ExpiresAt == nil || !s.ExpiresAt.Equal(f.Clock.Now().Add(7*24*time.Hour)) {
		t.Fatalf("expires_at = %v", s.ExpiresAt)
	}
	// Stored hashed and field-encrypted, bound to the row.
	var hash []byte
	var enc string
	if err := f.DB.QueryRow(f.ctx, `SELECT token_hash, token_enc FROM shares WHERE id = ?`, s.ID).Scan(&hash, &enc); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256([]byte(tok))
	if string(hash) != string(sum[:]) || strings.Contains(enc, tok) {
		t.Fatal("token not stored as SHA-256 + sealed copy")
	}
	if pt, err := f.Keys.OpenField("shares.token_enc|"+s.ID, enc); err != nil || string(pt) != tok {
		t.Fatalf("sealed token: %q %v", pt, err)
	}
	if _, err := f.Keys.OpenField("shares.token_enc|shr_other", enc); err == nil {
		t.Fatal("sealed token not bound to its row")
	}
	if e, ok := f.Audit.Find(core.ActShareCreate); !ok || e.TargetID != s.ID {
		t.Fatalf("audit %+v", e)
	}
	// The owner sees the link again.
	got, err := f.svc.Get(f.ctx, alice, s.ID)
	if err != nil || got.URL != "/s/"+tok {
		t.Fatalf("get: %+v %v", got, err)
	}
	// Absolute link with server.public_url.
	f.Env.Env.Config.Server.PublicURL = "https://files.example.test/"
	if got, _ := f.svc.Get(f.ctx, alice, s.ID); got.URL != "https://files.example.test/s/"+tok {
		t.Fatalf("absolute url %q", got.URL)
	}
	f.Env.Env.Config.Server.PublicURL = ""

	// File request: folder only, upload-only defaults.
	r, _ := f.create(alice, core.ShareInput{Kind: core.ShareRequest, NodeID: folder, RequireUploaderName: true,
		UploadMaxFileBytes: ptr(int64(1000)), UploadQuotaBytes: ptr(int64(5000)), NoExpiry: true})
	if !r.AllowUpload || r.AllowDownload || r.AllowPreview || !r.RequireUploaderName || r.ExpiresAt != nil ||
		*r.UploadMaxFileBytes != 1000 || *r.UploadQuotaBytes != 5000 {
		t.Fatalf("request = %+v", r)
	}
	// Password: hashed with argon2id, version 1.
	pw, _ := f.create(alice, core.ShareInput{NodeID: folder, Password: "s3cret pass", MaxDownloads: ptr(int64(3))})
	var phc string
	var ver int
	_ = f.DB.QueryRow(f.ctx, `SELECT password_hash, password_version FROM shares WHERE id = ?`, pw.ID).Scan(&phc, &ver)
	if !pw.HasPassword || !strings.HasPrefix(phc, "$argon2id$") || ver != 1 || *pw.MaxDownloads != 3 {
		t.Fatalf("password share %+v %q %d", pw, phc, ver)
	}
}

func TestCreateValidation(t *testing.T) {
	f := setup(t)
	alice := f.P(f.alice)
	folder := f.Mkdir(f.aliceRoot, "F")
	file := f.PutFile(folder, "x.txt", []byte("x"))
	past := f.Clock.Now().Add(-time.Hour)
	cases := []struct {
		name string
		p    *core.Principal
		in   core.ShareInput
		code *core.Error
	}{
		{"anonymous", nil, core.ShareInput{NodeID: file.ID}, core.ErrUnauthorized},
		{"no node", alice, core.ShareInput{}, core.ErrInvalid},
		{"bad kind", alice, core.ShareInput{Kind: "public", NodeID: file.ID}, core.ErrInvalid},
		{"foreign node", alice, core.ShareInput{NodeID: f.bobRoot}, core.ErrNotFound},
		{"request on a file", alice, core.ShareInput{Kind: core.ShareRequest, NodeID: file.ID}, core.ErrInvalid},
		{"upload on a file", alice, core.ShareInput{NodeID: file.ID, AllowUpload: true}, core.ErrInvalid},
		{"zero downloads", alice, core.ShareInput{NodeID: file.ID, MaxDownloads: ptr(int64(0))}, core.ErrInvalid},
		{"negative quota", alice, core.ShareInput{Kind: core.ShareRequest, NodeID: folder, UploadQuotaBytes: ptr(int64(-1))}, core.ErrInvalid},
		{"past expiry", alice, core.ShareInput{NodeID: file.ID, ExpiresAt: &past}, core.ErrInvalid},
		{"long title", alice, core.ShareInput{NodeID: file.ID, Title: strings.Repeat("t", MaxTitle+1)}, core.ErrInvalid},
		{"control title", alice, core.ShareInput{NodeID: file.ID, Title: "a\x07b"}, core.ErrInvalid},
		{"long message", alice, core.ShareInput{NodeID: file.ID, Message: strings.Repeat("m", MaxMessage+1)}, core.ErrInvalid},
		{"long password", alice, core.ShareInput{NodeID: file.ID, Password: strings.Repeat("p", MaxPassword+1)}, core.ErrInvalid},
		{"short password", alice, core.ShareInput{NodeID: file.ID, Password: "x"}, core.ErrInvalid},
		{"seven-character password", alice, core.ShareInput{NodeID: file.ID, Password: "abcdefg"}, core.ErrInvalid},
		{"repetitive password", alice, core.ShareInput{NodeID: file.ID, Password: "abababab"}, core.ErrInvalid},
		{"control password", alice, core.ShareInput{NodeID: file.ID, Password: "pass\x07word"}, core.ErrInvalid},
		{"token without scope", &core.Principal{UserID: f.alice, Role: core.RoleMember, Via: core.ViaToken, Scopes: []string{core.ScopeFilesRead}},
			core.ShareInput{NodeID: file.ID}, core.ErrForbidden},
		// Uploads through a share write files: files:write is needed too.
		{"read-only token, request", &core.Principal{UserID: f.alice, Role: core.RoleMember, Via: core.ViaToken,
			Scopes: []string{core.ScopeShares, core.ScopeFilesRead}}, core.ShareInput{Kind: core.ShareRequest, NodeID: folder}, core.ErrForbidden},
		{"read-only token, upload link", &core.Principal{UserID: f.alice, Role: core.RoleMember, Via: core.ViaToken,
			Scopes: []string{core.ScopeShares, core.ScopeFilesRead}}, core.ShareInput{NodeID: folder, AllowUpload: true}, core.ErrForbidden},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, _, err := f.svc.Create(f.ctx, c.p, c.in)
			wantCode(t, err, c.code)
		})
	}
	t.Run("read-only token, link", func(t *testing.T) {
		// A share bot needs no write access to the files it links to.
		bot := &core.Principal{UserID: f.alice, Role: core.RoleMember, Via: core.ViaToken, Scopes: []string{core.ScopeShares, core.ScopeFilesRead}}
		if _, _, err := f.svc.Create(f.ctx, bot, core.ShareInput{NodeID: file.ID}); err != nil {
			t.Fatalf("link with shares,files:read: %v", err)
		}
	})
	t.Run("manage permission", func(t *testing.T) {
		shared := f.Mkdir(f.bobRoot, "Team")
		f.Files.Grant(f.alice, shared, core.PermEdit)
		_, _, err := f.svc.Create(f.ctx, alice, core.ShareInput{NodeID: shared})
		wantCode(t, err, core.ErrForbidden)
		f.Files.Grant(f.alice, shared, core.PermManage)
		f.create(alice, core.ShareInput{NodeID: shared})
	})
	t.Run("settings", func(t *testing.T) {
		f.Settings.Put(SettingLinksEnabled, false)
		_, _, err := f.svc.Create(f.ctx, alice, core.ShareInput{NodeID: file.ID})
		wantCode(t, err, core.ErrForbidden)
		f.Settings.Put(SettingLinksEnabled, true)
		f.Settings.Put(SettingRequestsEnabled, false)
		_, _, err = f.svc.Create(f.ctx, alice, core.ShareInput{Kind: core.ShareRequest, NodeID: folder})
		wantCode(t, err, core.ErrForbidden)
		f.Settings.Put(SettingRequestsEnabled, true)
		f.Settings.Put(SettingRequirePassword, true)
		_, _, err = f.svc.Create(f.ctx, alice, core.ShareInput{NodeID: file.ID})
		wantCode(t, err, core.ErrInvalid)
		f.create(alice, core.ShareInput{NodeID: file.ID, Password: "open sesame"})
		f.Settings.Put(SettingRequirePassword, false)
	})
	t.Run("guests", func(t *testing.T) {
		// Package auth folds sharing.allow_guests_share into the
		// capabilities of built-in guests on every request.
		guest := asGuest(f.P(f.alice), false)
		_, _, err := f.svc.Create(f.ctx, guest, core.ShareInput{NodeID: file.ID})
		wantCode(t, err, core.ErrForbidden)
		f.Settings.Put(SettingAllowGuestsShare, true)
		defer f.Settings.Put(SettingAllowGuestsShare, false)
		f.create(asGuest(guest, true), core.ShareInput{NodeID: file.ID})
	})
}

func TestExpiryPolicy(t *testing.T) {
	f := setup(t)
	alice := f.P(f.alice)
	file := f.PutFile(f.aliceRoot, "x.txt", []byte("x"))
	now := f.Clock.Now()
	day := 24 * time.Hour

	f.Settings.Put(SettingDefaultExpiryDays, 0)
	if s, _ := f.create(alice, core.ShareInput{NodeID: file.ID}); s.ExpiresAt != nil {
		t.Fatalf("no default expiry expected, got %v", s.ExpiresAt)
	}
	f.Settings.Put(SettingMaxExpiryDays, 30)
	f.Settings.Put(SettingDefaultExpiryDays, 60)
	if s, _ := f.create(alice, core.ShareInput{NodeID: file.ID}); s.ExpiresAt == nil || !s.ExpiresAt.Equal(now.Add(30*day)) {
		t.Fatalf("default capped at the maximum: %v", s.ExpiresAt)
	}
	f.Settings.Put(SettingDefaultExpiryDays, 0)
	if s, _ := f.create(alice, core.ShareInput{NodeID: file.ID}); s.ExpiresAt == nil || !s.ExpiresAt.Equal(now.Add(30*day)) {
		t.Fatalf("no default but a maximum: %v", s.ExpiresAt)
	}
	_, _, err := f.svc.Create(f.ctx, alice, core.ShareInput{NodeID: file.ID, NoExpiry: true})
	wantCode(t, err, core.ErrInvalid)
	late := now.Add(31 * day)
	_, _, err = f.svc.Create(f.ctx, alice, core.ShareInput{NodeID: file.ID, ExpiresAt: &late})
	wantCode(t, err, core.ErrInvalid)
	ok := now.Add(29 * day)
	if s, _ := f.create(alice, core.ShareInput{NodeID: file.ID, ExpiresAt: &ok}); !s.ExpiresAt.Equal(ok) {
		t.Fatalf("explicit expiry %v", s.ExpiresAt)
	}
	// Update cannot remove the expiry while a maximum applies.
	s, _ := f.create(alice, core.ShareInput{NodeID: file.ID})
	_, err = f.svc.Update(f.ctx, alice, s.ID, core.ShareUpdate{ExpiresAt: core.Null[time.Time]()})
	wantCode(t, err, core.ErrInvalid)
	f.Settings.Put(SettingMaxExpiryDays, 0)
	got, err := f.svc.Update(f.ctx, alice, s.ID, core.ShareUpdate{ExpiresAt: core.Null[time.Time]()})
	if err != nil || got.ExpiresAt != nil {
		t.Fatalf("clear expiry: %+v %v", got, err)
	}
}

// TestExpiryCapIsALifetime pins sharing.max_expiry_days as a cap on the
// whole life of a link: without it, editing expires_at every few days
// renews a link for ever, so the maximum an administrator sets means
// nothing.
func TestExpiryCapIsALifetime(t *testing.T) {
	f := setup(t)
	alice := f.P(f.alice)
	file := f.PutFile(f.aliceRoot, "x.txt", []byte("x"))
	day := 24 * time.Hour
	f.Settings.Put(SettingMaxExpiryDays, 7)
	created := f.Clock.Now()
	s, _ := f.create(alice, core.ShareInput{NodeID: file.ID})

	// Six days on, the owner bumps the expiry by another six days: inside
	// "7 days from now", but past "7 days from creation".
	f.Clock.Advance(6 * day)
	_, err := f.svc.Update(f.ctx, alice, s.ID, core.ShareUpdate{ExpiresAt: core.Some(f.Clock.Now().Add(6 * day))})
	wantCode(t, err, core.ErrInvalid)
	if n := f.Int(`SELECT expires_at FROM shares WHERE id = ?`, s.ID); n != db.Ms(created.Add(7*day)) {
		t.Fatalf("expires_at changed to %v", db.FromMs(n))
	}
	// Up to the end of that lifetime an edit is fine.
	within := created.Add(7 * day).Add(-time.Hour)
	if got, err := f.svc.Update(f.ctx, alice, s.ID, core.ShareUpdate{ExpiresAt: core.Some(within)}); err != nil ||
		got.ExpiresAt == nil || !got.ExpiresAt.Equal(within) {
		t.Fatalf("edit inside the lifetime: %+v %v", got, err)
	}

	// Shortening is always allowed, even for a share that already reaches
	// past the maximum (set while none applied, or lowered afterwards):
	// otherwise lowering the setting would freeze old shares' expiry.
	f.Settings.Put(SettingMaxExpiryDays, 0)
	far := f.Clock.Now().Add(300 * day)
	if _, err := f.svc.Update(f.ctx, alice, s.ID, core.ShareUpdate{ExpiresAt: core.Some(far)}); err != nil {
		t.Fatalf("no maximum: %v", err)
	}
	f.Settings.Put(SettingMaxExpiryDays, 7)
	nearer := f.Clock.Now().Add(5 * day)
	if got, err := f.svc.Update(f.ctx, alice, s.ID, core.ShareUpdate{ExpiresAt: core.Some(nearer)}); err != nil ||
		got.ExpiresAt == nil || !got.ExpiresAt.Equal(nearer) {
		t.Fatalf("shortening: %+v %v", got, err)
	}
}

// ---------- get / list / update / revoke ----------

func TestVisibilityAndLists(t *testing.T) {
	f := setup(t)
	alice, bob := f.P(f.alice), f.P(f.bob)
	folder := f.Mkdir(f.aliceRoot, "F")
	file := f.PutFile(folder, "x.txt", []byte("x"))
	var mine []string
	for i := range 5 {
		in := core.ShareInput{NodeID: file.ID}
		if i%2 == 1 {
			in = core.ShareInput{Kind: core.ShareRequest, NodeID: folder}
		}
		s, _ := f.create(alice, in)
		mine = append(mine, s.ID)
		f.Clock.Advance(time.Second)
	}
	bs, _ := f.create(bob, core.ShareInput{NodeID: f.PutFile(f.bobRoot, "b.txt", []byte("b")).ID})

	_, err := f.svc.Get(f.ctx, bob, mine[0])
	wantCode(t, err, core.ErrNotFound)
	_, err = f.svc.Update(f.ctx, bob, mine[0], core.ShareUpdate{Title: ptr("x")})
	wantCode(t, err, core.ErrNotFound)
	wantCode(t, f.svc.Revoke(f.ctx, bob, mine[0]), core.ErrNotFound)
	_, err = f.svc.AccessLog(f.ctx, bob, mine[0], core.PageReq{})
	wantCode(t, err, core.ErrNotFound)
	_, err = f.svc.Get(f.ctx, alice, "shr_bogus")
	wantCode(t, err, core.ErrNotFound)

	// Pagination, newest first.
	var got []string
	cursor := ""
	for {
		pg, err := f.svc.List(f.ctx, alice, core.ShareQuery{PageReq: core.PageReq{Limit: 2, Cursor: cursor}})
		if err != nil {
			t.Fatal(err)
		}
		for _, s := range pg.Items {
			got = append(got, s.ID)
			if s.URL == "" {
				t.Errorf("own share without url")
			}
		}
		if pg.NextCursor == "" {
			break
		}
		cursor = pg.NextCursor
	}
	if len(got) != 5 || got[0] != mine[4] || got[4] != mine[0] {
		t.Fatalf("list order %v, want reverse of %v", got, mine)
	}
	pg, _ := f.svc.List(f.ctx, alice, core.ShareQuery{Kind: core.ShareRequest})
	if len(pg.Items) != 2 {
		t.Fatalf("requests = %d", len(pg.Items))
	}
	pg, _ = f.svc.List(f.ctx, alice, core.ShareQuery{NodeID: file.ID})
	if len(pg.Items) != 3 {
		t.Fatalf("by node = %d", len(pg.Items))
	}
	if _, err := f.svc.List(f.ctx, alice, core.ShareQuery{Kind: "x"}); err == nil {
		t.Fatal("bad kind accepted")
	}
	if _, err := f.svc.List(f.ctx, alice, core.ShareQuery{PageReq: core.PageReq{Cursor: "!!"}}); err == nil {
		t.Fatal("bad cursor accepted")
	}
	// Status filter.
	if _, err := f.svc.Update(f.ctx, alice, mine[0], core.ShareUpdate{Disabled: ptr(true)}); err != nil {
		t.Fatal(err)
	}
	act, _ := f.svc.List(f.ctx, alice, core.ShareQuery{Status: core.ShareActive})
	inact, _ := f.svc.List(f.ctx, alice, core.ShareQuery{Status: "inactive"})
	if len(act.Items) != 4 || len(inact.Items) != 1 || inact.Items[0].Status != core.ShareDisabled {
		t.Fatalf("active %d inactive %+v", len(act.Items), inact.Items)
	}

	// Admins see every share, but not the links (auth.admin_can_access_files off).
	admin := &core.Principal{UserID: "usr_admin", Username: "root", Role: core.RoleAdmin, Via: core.ViaSession, AuthLevel: 2}
	all, err := f.svc.ListAll(core.WithPrincipal(f.ctx, admin), core.ShareQuery{})
	if err != nil || len(all.Items) != 6 {
		t.Fatalf("list all: %d %v", len(all.Items), err)
	}
	for _, s := range all.Items {
		if s.URL != "" {
			t.Fatal("admin sees a share link")
		}
	}
	byBob, _ := f.svc.ListAll(f.ctx, core.ShareQuery{UserID: f.bob})
	if len(byBob.Items) != 1 || byBob.Items[0].ID != bs.ID {
		t.Fatalf("filter by user: %+v", byBob.Items)
	}
	if g, err := f.svc.Get(f.ctx, admin, mine[1]); err != nil || g.URL != "" {
		t.Fatalf("admin get: %+v %v", g, err)
	}
	f.Settings.Put(settingAdminFiles, true)
	if g, _ := f.svc.Get(f.ctx, admin, mine[1]); g.URL == "" {
		t.Fatal("admin with file access should see the link")
	}
	f.Settings.Put(settingAdminFiles, false)
	// Admins may only disable/enable other users' shares.
	_, err = f.svc.Update(f.ctx, admin, mine[1], core.ShareUpdate{Title: ptr("hijack")})
	wantCode(t, err, core.ErrForbidden)
	if s, err := f.svc.Update(f.ctx, admin, mine[1], core.ShareUpdate{Disabled: ptr(true)}); err != nil || s.Status != core.ShareDisabled {
		t.Fatalf("admin disable: %+v %v", s, err)
	}
}

// TestAdminTokenNeedsAdminScope pins that the cross-user admin view needs the
// admin *scope* too, not just the role: a token scoped "shares" only may not
// reach, change or delete another user's share (mw.RequireAdmin refuses it on
// /admin/shares, so /shares/{id} must refuse it as well).
func TestAdminTokenNeedsAdminScope(t *testing.T) {
	f := setup(t)
	file := f.PutFile(f.aliceRoot, "secret.txt", []byte("s"))
	s, _ := f.create(f.P(f.alice), core.ShareInput{NodeID: file.ID})
	f.Settings.Put(settingAdminFiles, true)
	defer f.Settings.Put(settingAdminFiles, false)

	adminToken := func(scopes ...string) *core.Principal {
		return &core.Principal{UserID: "usr_admin", Username: "root", Role: core.RoleAdmin,
			Via: core.ViaToken, TokenID: "tok_1", Scopes: scopes, AuthLevel: core.AuthLevelFull}
	}
	noAdmin := adminToken(core.ScopeShares, core.ScopeFilesRead)
	_, err := f.svc.Get(f.ctx, noAdmin, s.ID)
	wantCode(t, err, core.ErrNotFound)
	_, err = f.svc.Update(f.ctx, noAdmin, s.ID, core.ShareUpdate{Disabled: ptr(true)})
	wantCode(t, err, core.ErrNotFound)
	_, err = f.svc.AccessLog(f.ctx, noAdmin, s.ID, core.PageReq{})
	wantCode(t, err, core.ErrNotFound)
	wantCode(t, f.svc.Revoke(f.ctx, noAdmin, s.ID), core.ErrNotFound)
	all, err := f.svc.ListAll(core.WithPrincipal(f.ctx, noAdmin), core.ShareQuery{})
	if err != nil {
		t.Fatal(err)
	}
	for _, item := range all.Items {
		if item.URL != "" {
			t.Fatal("token without the admin scope sees a share link")
		}
	}

	// With the admin scope the admin view works as before.
	withAdmin := adminToken(core.ScopeShares, core.ScopeAdmin)
	g, err := f.svc.Get(f.ctx, withAdmin, s.ID)
	if err != nil || g.URL == "" {
		t.Fatalf("admin-scoped get: %+v %v", g, err)
	}
	if _, err := f.svc.AccessLog(f.ctx, withAdmin, s.ID, core.PageReq{}); err != nil {
		t.Fatal(err)
	}
	if err := f.svc.Revoke(f.ctx, withAdmin, s.ID); err != nil {
		t.Fatal(err)
	}

	// A session of the same admin is unaffected (only tokens carry scopes).
	s2, _ := f.create(f.P(f.alice), core.ShareInput{NodeID: file.ID})
	session := &core.Principal{UserID: "usr_admin", Username: "root", Role: core.RoleAdmin,
		Via: core.ViaSession, AuthLevel: core.AuthLevelFull}
	if _, err := f.svc.Get(f.ctx, session, s2.ID); err != nil {
		t.Fatalf("admin session: %v", err)
	}
}

// TestPasswordPolicy pins the policy applied when a password is set, and that
// verification keeps accepting passwords that predate it.
func TestPasswordPolicy(t *testing.T) {
	f := setup(t)
	alice := f.P(f.alice)
	file := f.PutFile(f.aliceRoot, "x.txt", []byte("x"))
	for _, pw := range []string{"", "x", "pw", "1234567", "aaaaaaaa", "12121212"} {
		if err := validPassword(pw); !errors.Is(err, core.ErrInvalid) {
			t.Fatalf("validPassword(%q) = %v, want invalid", pw, err)
		}
	}
	for _, pw := range []string{"open sesame", "correct horse battery", "12345678x"} {
		if err := validPassword(pw); err != nil {
			t.Fatalf("validPassword(%q) = %v", pw, err)
		}
	}
	s, tok := f.create(alice, core.ShareInput{NodeID: file.ID, Password: "open sesame"})
	_, err := f.svc.Update(f.ctx, alice, s.ID, core.ShareUpdate{Password: ptr("short")})
	wantCode(t, err, core.ErrInvalid)

	// A password stored before the policy still opens its share.
	weak, err := f.svc.hashPassword("pw")
	if err != nil {
		t.Fatal(err)
	}
	f.Exec(`UPDATE shares SET password_hash = ? WHERE id = ?`, weak, s.ID)
	cur, _, err := f.svc.Resolve(f.ctx, tok)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.svc.CheckPassword(f.ctx, cur, "pw", core.ReqMeta{}); err != nil {
		t.Fatalf("pre-policy password refused: %v", err)
	}
}

func TestUpdate(t *testing.T) {
	f := setup(t)
	alice := f.P(f.alice)
	folder := f.Mkdir(f.aliceRoot, "F")
	file := f.PutFile(folder, "x.txt", []byte("x"))
	s, _ := f.create(alice, core.ShareInput{NodeID: folder, Password: "first password"})

	u, err := f.svc.Update(f.ctx, alice, s.ID, core.ShareUpdate{
		Title: ptr("New"), Message: ptr("msg"), AllowDownload: ptr(false), AllowUpload: ptr(true),
		RequireUploaderName: ptr(true), UploadMaxFileBytes: core.Some(int64(10)), UploadQuotaBytes: core.Some(int64(20)),
		MaxDownloads: core.Some(int64(2)), NotifyOwner: ptr(true), Password: ptr("second password"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if u.Title != "New" || u.Message != "msg" || u.AllowDownload || !u.AllowUpload || !u.RequireUploaderName ||
		*u.UploadMaxFileBytes != 10 || *u.UploadQuotaBytes != 20 || *u.MaxDownloads != 2 || !u.NotifyOwner || !u.HasPassword {
		t.Fatalf("updated = %+v", u)
	}
	if v := f.Int(`SELECT password_version FROM shares WHERE id = ?`, s.ID); v != 2 {
		t.Fatalf("password_version = %d", v)
	}
	e, _ := f.Audit.Find(core.ActShareUpdate)
	if d, _ := e.Details.(map[string]any); d == nil || strings.Contains(strings.Join(d["fields"].([]string), ","), "password_hash") {
		t.Fatalf("audit details %+v", e.Details)
	}
	// Clearing limits and the password.
	u, err = f.svc.Update(f.ctx, alice, s.ID, core.ShareUpdate{MaxDownloads: core.Null[int64](), Password: ptr(""),
		UploadQuotaBytes: core.Null[int64]()})
	if err != nil || u.MaxDownloads != nil || u.HasPassword || u.UploadQuotaBytes != nil {
		t.Fatalf("cleared = %+v %v", u, err)
	}
	if v := f.Int(`SELECT password_version FROM shares WHERE id = ?`, s.ID); v != 3 {
		t.Fatalf("password_version after removal = %d", v)
	}
	// Invalid updates.
	fs, _ := f.create(alice, core.ShareInput{NodeID: file.ID})
	_, err = f.svc.Update(f.ctx, alice, fs.ID, core.ShareUpdate{AllowUpload: ptr(true)})
	wantCode(t, err, core.ErrInvalid)
	_, err = f.svc.Update(f.ctx, alice, fs.ID, core.ShareUpdate{MaxDownloads: core.Some(int64(0))})
	wantCode(t, err, core.ErrInvalid)
	_, err = f.svc.Update(f.ctx, alice, fs.ID, core.ShareUpdate{Title: ptr("\x00")})
	wantCode(t, err, core.ErrInvalid)
	f.Settings.Put(SettingRequirePassword, true)
	_, err = f.svc.Update(f.ctx, alice, fs.ID, core.ShareUpdate{Password: ptr("")})
	wantCode(t, err, core.ErrInvalid)
	f.Settings.Put(SettingRequirePassword, false)
	// An empty update changes nothing.
	before := f.Int(`SELECT updated_at FROM shares WHERE id = ?`, fs.ID)
	f.Clock.Advance(time.Minute)
	if _, err := f.svc.Update(f.ctx, alice, fs.ID, core.ShareUpdate{}); err != nil {
		t.Fatal(err)
	}
	if after := f.Int(`SELECT updated_at FROM shares WHERE id = ?`, fs.ID); after != before {
		t.Fatal("empty update touched the row")
	}
	// Disable and enable.
	d, _ := f.svc.Update(f.ctx, alice, fs.ID, core.ShareUpdate{Disabled: ptr(true)})
	if d.Status != core.ShareDisabled || d.DisabledAt == nil {
		t.Fatalf("disabled = %+v", d)
	}
	d, _ = f.svc.Update(f.ctx, alice, fs.ID, core.ShareUpdate{Disabled: ptr(false)})
	if d.Status != core.ShareActive || d.DisabledAt != nil {
		t.Fatalf("enabled = %+v", d)
	}
}

// TestUpdateAfterLosingManage pins that editing a link is sharing: a
// creator who lost the right to share the item (a group manager demoted to
// member, a user demoted to guest) can no longer re-open, widen or re-enable
// the link, but can still disable and delete it.
func TestUpdateAfterLosingManage(t *testing.T) {
	f := setup(t)
	team := f.Mkdir(f.bobRoot, "Team")
	f.Files.Grant(f.alice, team, core.PermManage)
	alice := f.P(f.alice)
	s, _ := f.create(alice, core.ShareInput{NodeID: team, Password: "team secret"})
	if _, err := f.svc.Update(f.ctx, alice, s.ID, core.ShareUpdate{Disabled: ptr(true)}); err != nil {
		t.Fatal(err)
	}
	f.Files.Grant(f.alice, team, core.PermEdit) // demoted to member

	for name, in := range map[string]core.ShareUpdate{
		"remove the password": {Password: ptr("")},
		"allow uploads":       {AllowUpload: ptr(true)},
		"re-enable":           {Disabled: ptr(false)},
		"drop the expiry":     {ExpiresAt: core.Null[time.Time]()},
		"retitle":             {Title: ptr("Team")},
	} {
		_, err := f.svc.Update(f.ctx, alice, s.ID, in)
		if !errors.Is(err, core.ErrForbidden) {
			t.Errorf("%s after losing manage: %v, want forbidden", name, err)
		}
	}
	if got, err := f.svc.Get(f.ctx, alice, s.ID); err != nil || !got.HasPassword || got.AllowUpload ||
		got.Status != core.ShareDisabled || got.ExpiresAt == nil || got.Title != "" {
		t.Fatalf("link changed by refused edits: %+v %v", got, err)
	}
	// Shutting the link off stays possible.
	if _, err := f.svc.Update(f.ctx, alice, s.ID, core.ShareUpdate{Disabled: ptr(true)}); err != nil {
		t.Fatalf("disable after losing manage: %v", err)
	}
	// Losing access to the item altogether reads as forbidden too: the
	// share itself is still the creator's.
	f.Files.Grant(f.alice, team, core.PermNone)
	_, err := f.svc.Update(f.ctx, alice, s.ID, core.ShareUpdate{Title: ptr("x")})
	wantCode(t, err, core.ErrForbidden)
	if err := f.svc.Revoke(f.ctx, alice, s.ID); err != nil {
		t.Fatalf("revoke after losing access: %v", err)
	}

	// A guest keeps Manage but sharing.allow_guests_share was turned off
	// (the next request's principal no longer holds shares.links).
	f.Files.Grant(f.alice, team, core.PermManage)
	gs, _ := f.create(asGuest(f.P(f.alice), true), core.ShareInput{NodeID: team, Password: "guest secret"})
	guest := asGuest(f.P(f.alice), false)
	_, err = f.svc.Update(f.ctx, guest, gs.ID, core.ShareUpdate{Password: ptr("")})
	wantCode(t, err, core.ErrForbidden)
	if _, err := f.svc.Update(f.ctx, guest, gs.ID, core.ShareUpdate{Disabled: ptr(true)}); err != nil {
		t.Fatalf("guest disable: %v", err)
	}
	guest = asGuest(guest, true)
	if _, err := f.svc.Update(f.ctx, guest, gs.ID, core.ShareUpdate{Password: ptr(""), Disabled: ptr(false)}); err != nil {
		t.Fatalf("guest edit with sharing allowed: %v", err)
	}
}

func TestRevoke(t *testing.T) {
	f := setup(t)
	alice := f.P(f.alice)
	folder := f.Mkdir(f.aliceRoot, "Inbox")
	s, tok := f.create(alice, core.ShareInput{Kind: core.ShareRequest, NodeID: folder})
	now := db.Ms(f.Clock.Now())
	f.Exec(`INSERT INTO upload_batches (id, user_id, share_id, folder_id, mode, conflict, state, created_at, updated_at, expires_at)
		VALUES ('upb_open', ?, ?, ?, 'files', 'rename', 'open', ?, ?, ?)`, f.alice, s.ID, folder, now, now, now+1000)
	f.Exec(`INSERT INTO upload_batches (id, user_id, share_id, folder_id, mode, conflict, state, created_at, updated_at, expires_at)
		VALUES ('upb_done', ?, ?, ?, 'files', 'rename', 'done', ?, ?, ?)`, f.alice, s.ID, folder, now, now, now+1000)
	f.svc.RecordAccess(f.ctx, s, core.ShareAccess{Action: core.AccessView})

	if err := f.svc.Revoke(f.ctx, alice, s.ID); err != nil {
		t.Fatal(err)
	}
	if len(f.uploads.aborted) != 1 || f.uploads.aborted[0] != s.ID+"/upb_open" {
		t.Fatalf("aborted = %v", f.uploads.aborted)
	}
	if n := f.Int(`SELECT COUNT(*) FROM shares WHERE id = ?`, s.ID); n != 0 {
		t.Fatal("share not deleted")
	}
	if n := f.Int(`SELECT COUNT(*) FROM share_access_log WHERE share_id = ?`, s.ID); n != 0 {
		t.Fatal("access log not deleted")
	}
	if _, _, err := f.svc.Resolve(f.ctx, tok); !errors.Is(err, core.ErrNotFound) {
		t.Fatalf("revoked token resolves: %v", err)
	}
	if e, ok := f.Audit.Find(core.ActShareRevoke); !ok || e.TargetID != s.ID {
		t.Fatalf("audit %+v", e)
	}
	wantCode(t, f.svc.Revoke(f.ctx, alice, s.ID), core.ErrNotFound)
}

// ---------- resolve ----------

func TestResolveUniformNotFound(t *testing.T) {
	f := setup(t)
	alice := f.P(f.alice)
	folder := f.Mkdir(f.aliceRoot, "F")
	file := f.PutFile(folder, "x.txt", []byte("x"))

	s, tok := f.create(alice, core.ShareInput{NodeID: file.ID})
	gotS, gotN, err := f.svc.Resolve(f.ctx, tok)
	if err != nil || gotS.ID != s.ID || gotN.ID != file.ID {
		t.Fatalf("resolve: %v", err)
	}

	_, _, base := f.svc.Resolve(f.ctx, ids.Token(16))
	if base == nil {
		t.Fatal("unknown token resolved")
	}
	msg := base.Error()
	check := func(name, token string) {
		t.Helper()
		_, _, err := f.svc.Resolve(f.ctx, token)
		if err == nil {
			t.Fatalf("%s: resolved", name)
		}
		ce := core.AsError(err)
		if ce == nil || ce.Code != core.ErrNotFound.Code || err.Error() != msg || ce.Status != 404 {
			t.Fatalf("%s: error %v differs from %v", name, err, base)
		}
	}
	check("empty", "")
	check("short", "abc")
	check("bad chars", strings.Repeat("-", 22))
	check("long", tok+"x")

	mk := func() (*core.Share, string) { return f.create(alice, core.ShareInput{NodeID: file.ID, NoExpiry: true}) }

	exp, expTok := mk()
	f.Exec(`UPDATE shares SET expires_at = ? WHERE id = ?`, db.Ms(f.Clock.Now()), exp.ID)
	check("expired", expTok)

	dis, disTok := mk()
	if _, err := f.svc.Update(f.ctx, alice, dis.ID, core.ShareUpdate{Disabled: ptr(true)}); err != nil {
		t.Fatal(err)
	}
	check("disabled", disTok)

	ex, exTok := mk()
	f.Exec(`UPDATE shares SET max_downloads = 1, download_count = 1 WHERE id = ?`, ex.ID)
	check("exhausted", exTok)

	_, linkTok := mk()
	f.Settings.Put(SettingLinksEnabled, false)
	check("links disabled", linkTok)
	f.Settings.Put(SettingLinksEnabled, true)

	_, reqTok := f.create(alice, core.ShareInput{Kind: core.ShareRequest, NodeID: folder})
	f.Settings.Put(SettingRequestsEnabled, false)
	check("requests disabled", reqTok)
	f.Settings.Put(SettingRequestsEnabled, true)
	if _, _, err := f.svc.Resolve(f.ctx, reqTok); err != nil {
		t.Fatalf("request: %v", err)
	}

	// Trashed node.
	tf := f.PutFile(folder, "t.txt", []byte("t"))
	_, trTok := f.create(alice, core.ShareInput{NodeID: tf.ID})
	if err := f.Files.Trash(f.ctx, alice, []string{tf.ID}); err != nil {
		t.Fatal(err)
	}
	check("trashed", trTok)

	// The creator lost access to the node.
	team := f.Mkdir(f.bobRoot, "Team")
	f.Files.Grant(f.alice, team, core.PermManage)
	_, grTok := f.create(alice, core.ShareInput{NodeID: team})
	if _, _, err := f.svc.Resolve(f.ctx, grTok); err != nil {
		t.Fatalf("granted: %v", err)
	}
	f.Files.Grant(f.alice, team, core.PermNone)
	check("owner lost access", grTok)

	// Disabled creator.
	f.Exec(`UPDATE users SET status = 'disabled' WHERE id = ?`, f.alice)
	check("owner disabled", tok)
	f.Exec(`UPDATE users SET status = 'active' WHERE id = ?`, f.alice)
	if _, _, err := f.svc.Resolve(f.ctx, tok); err != nil {
		t.Fatalf("re-enabled owner: %v", err)
	}
}

// ---------- password, cookie, downloads ----------

func TestPasswordAndCookie(t *testing.T) {
	f := setup(t)
	alice := f.P(f.alice)
	file := f.PutFile(f.aliceRoot, "x.txt", []byte("x"))
	s, tok := f.create(alice, core.ShareInput{NodeID: file.ID, Password: "correct horse"})
	rs, _, err := f.svc.Resolve(f.ctx, tok)
	if err != nil {
		t.Fatal(err)
	}
	meta := core.ReqMeta{IP: netip.MustParseAddr("198.51.100.9"), UserAgent: "UA", RequestID: "r1"}
	req := httptest.NewRequest(http.MethodGet, "/s/"+tok, nil)
	if f.svc.HasAccess(req, rs) {
		t.Fatal("access without cookie")
	}
	err = f.svc.CheckPassword(f.ctx, rs, "wrong", meta)
	wantCode(t, err, core.ErrUnauthorized)
	if e, ok := f.Audit.Find(core.ActSharePasswordFail); !ok || e.TargetID != s.ID || e.IP != "198.51.100.9" || e.Outcome != core.OutcomeFailure {
		t.Fatalf("audit %+v", e)
	}
	if err := f.svc.CheckPassword(f.ctx, rs, "correct horse", meta); err != nil {
		t.Fatal(err)
	}
	acts := f.Str(`SELECT group_concat(action, ',') FROM (SELECT action FROM share_access_log WHERE share_id = ? ORDER BY id)`, s.ID)
	if acts != "password_fail,password_ok" {
		t.Fatalf("access log %q", acts)
	}

	c, err := f.svc.AccessCookie(rs)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(c.Name, "__Host-fp_s_") || c.Name != CookieName(s.ID) || !c.Secure || !c.HttpOnly ||
		c.Path != "/" || c.Domain != "" || c.SameSite != http.SameSiteLaxMode || c.MaxAge != 12*3600 {
		t.Fatalf("cookie %+v", c)
	}
	withCookie := func(c *http.Cookie) *http.Request {
		r := httptest.NewRequest(http.MethodGet, "/s/"+tok, nil)
		r.AddCookie(c)
		return r
	}
	if !f.svc.HasAccess(withCookie(c), rs) {
		t.Fatal("valid cookie refused")
	}
	// Tampering, wrong share, wrong name.
	raw, _ := base64.RawURLEncoding.DecodeString(c.Value)
	bad := append([]byte(nil), raw...)
	bad[len(bad)-1] ^= 1
	if f.svc.HasAccess(withCookie(&http.Cookie{Name: c.Name, Value: base64.RawURLEncoding.EncodeToString(bad)}), rs) {
		t.Fatal("tampered MAC accepted")
	}
	longer := append([]byte(nil), raw...)
	binary.BigEndian.PutUint64(longer[:8], binary.BigEndian.Uint64(raw[:8])+3600)
	if f.svc.HasAccess(withCookie(&http.Cookie{Name: c.Name, Value: base64.RawURLEncoding.EncodeToString(longer)}), rs) {
		t.Fatal("extended expiry accepted")
	}
	if f.svc.HasAccess(withCookie(&http.Cookie{Name: c.Name, Value: "garbage"}), rs) {
		t.Fatal("garbage accepted")
	}
	other, otherTok := f.create(alice, core.ShareInput{NodeID: file.ID, Password: "correct horse"})
	ro, _, _ := f.svc.Resolve(f.ctx, otherTok)
	if f.svc.HasAccess(withCookie(&http.Cookie{Name: CookieName(other.ID), Value: c.Value}), ro) {
		t.Fatal("cookie of another share accepted")
	}
	if CookieName(s.ID) == CookieName(other.ID) {
		t.Fatal("cookie names collide")
	}
	// Expiry after 12 hours.
	f.Clock.Advance(12*time.Hour - time.Second)
	if !f.svc.HasAccess(withCookie(c), rs) {
		t.Fatal("cookie expired early")
	}
	f.Clock.Advance(2 * time.Second)
	if f.svc.HasAccess(withCookie(c), rs) {
		t.Fatal("expired cookie accepted")
	}
	// Bound to password_version: changing the password invalidates cookies.
	c2, _ := f.svc.AccessCookie(rs)
	if _, err := f.svc.Update(f.ctx, alice, s.ID, core.ShareUpdate{Password: ptr("battery staple")}); err != nil {
		t.Fatal(err)
	}
	rs2, _, _ := f.svc.Resolve(f.ctx, tok)
	if f.svc.HasAccess(withCookie(c2), rs2) {
		t.Fatal("cookie survived a password change")
	}
	// Keys locked: no cookie can be issued or verified.
	f.Keys.Locked.Store(true)
	if _, err := f.svc.AccessCookie(rs2); !errors.Is(err, core.ErrKeysLocked) {
		t.Fatalf("locked: %v", err)
	}
	f.Keys.Locked.Store(false)
	// Shares without a password need no cookie.
	open, openTok := f.create(alice, core.ShareInput{NodeID: file.ID})
	ro2, _, _ := f.svc.Resolve(f.ctx, openTok)
	if !f.svc.HasAccess(req, ro2) || f.svc.CheckPassword(f.ctx, ro2, "", meta) != nil || open.HasPassword {
		t.Fatal("open share requires a password")
	}
}

func TestPasswordRateLimit(t *testing.T) {
	f := setup(t)
	// The password buckets follow the sign-in rate, not the generic (much
	// larger) share request rate.
	f.Limiter.Configure(ratelimit.BucketShare, 1000, 1000)
	f.Settings.Put("ratelimit.login_per_min", 3)
	file := f.PutFile(f.aliceRoot, "x.txt", []byte("x"))
	_, tok := f.create(f.P(f.alice), core.ShareInput{NodeID: file.ID, Password: "rate limited"})
	s, _, _ := f.svc.Resolve(f.ctx, tok)
	m1 := core.ReqMeta{IP: netip.MustParseAddr("203.0.113.1")}
	m2 := core.ReqMeta{IP: netip.MustParseAddr("203.0.113.2")}
	for range 3 {
		wantCode(t, f.svc.CheckPassword(f.ctx, s, "nope", m1), core.ErrUnauthorized)
	}
	// Even the right password is refused while limited.
	wantCode(t, f.svc.CheckPassword(f.ctx, s, "rate limited", m1), core.ErrRateLimited)
	if n := f.Int(`SELECT COUNT(*) FROM share_access_log WHERE action = 'blocked'`); n != 1 {
		t.Fatalf("blocked rows = %d", n)
	}
	// Other clients are not affected.
	if err := f.svc.CheckPassword(f.ctx, s, "rate limited", m2); err != nil {
		t.Fatal(err)
	}
	f.Clock.Advance(time.Minute)
	if err := f.svc.CheckPassword(f.ctx, s, "rate limited", m1); err != nil {
		t.Fatalf("after a minute: %v", err)
	}
	// Other shares are not affected by the limit of this one (m1 has two of
	// its three attempts on s left).
	_, tok2 := f.create(f.P(f.alice), core.ShareInput{NodeID: file.ID, Password: "another one"})
	s2, _, _ := f.svc.Resolve(f.ctx, tok2)
	for range 2 {
		wantCode(t, f.svc.CheckPassword(f.ctx, s, "nope", m1), core.ErrUnauthorized)
	}
	wantCode(t, f.svc.CheckPassword(f.ctx, s, "rate limited", m1), core.ErrRateLimited)
	if err := f.svc.CheckPassword(f.ctx, s2, "another one", m1); err != nil {
		t.Fatalf("other share: %v", err)
	}
}

// TestPasswordRateLimitAcrossAddresses pins the per-share cap: guessing
// from many addresses (an IPv6 prefix, a botnet) is bounded too, while
// correct passwords never use the cap up.
func TestPasswordRateLimitAcrossAddresses(t *testing.T) {
	f := setup(t)
	f.Settings.Put("ratelimit.login_per_min", 2) // per share and IP; 20 wrong ones per share
	file := f.PutFile(f.aliceRoot, "x.txt", []byte("x"))
	_, tok := f.create(f.P(f.alice), core.ShareInput{NodeID: file.ID, Password: "many addresses"})
	s, _, _ := f.svc.Resolve(f.ctx, tok)
	ip := func(i int) core.ReqMeta {
		return core.ReqMeta{IP: netip.AddrFrom16([16]byte{0x20, 0x01, 0x0d, 0xb8, 15: byte(i)})}
	}
	// Right passwords from many addresses cost the cap nothing.
	for i := range 30 {
		if err := f.svc.CheckPassword(f.ctx, s, "many addresses", ip(i)); err != nil {
			t.Fatalf("visitor %d: %v", i, err)
		}
	}
	// 20 wrong ones from ten addresses (each within its own allowance) ...
	for i := range 20 {
		wantCode(t, f.svc.CheckPassword(f.ctx, s, "guess", ip(100+i/2)), core.ErrUnauthorized)
	}
	// ... exhaust the share: a fresh address is refused, even with the right
	// password, and no verification runs.
	verified := 0
	verify := f.svc.verifyPassword
	f.svc.verifyPassword = func(ctx context.Context, phc, pw string) (bool, bool, error) {
		verified++
		return verify(ctx, phc, pw)
	}
	wantCode(t, f.svc.CheckPassword(f.ctx, s, "many addresses", ip(200)), core.ErrRateLimited)
	if verified != 0 {
		t.Fatal("a refused attempt ran the password verification")
	}
	if n := f.Int(`SELECT COUNT(*) FROM share_access_log WHERE share_id = ? AND action = 'blocked'`, s.ID); n != 1 {
		t.Fatalf("blocked rows = %d", n)
	}
	f.Clock.Advance(time.Minute)
	if err := f.svc.CheckPassword(f.ctx, s, "many addresses", ip(200)); err != nil {
		t.Fatalf("after a minute: %v", err)
	}
}

func TestRealArgon2(t *testing.T) {
	f := setup(t)
	f.svc.hashPassword = crypt.HashPassword
	file := f.PutFile(f.aliceRoot, "x.txt", []byte("x"))
	_, tok := f.create(f.P(f.alice), core.ShareInput{NodeID: file.ID, Password: "real one"})
	s, _, _ := f.svc.Resolve(f.ctx, tok)
	if !strings.HasPrefix(s.PasswordHash, "$argon2id$v=19$m=65536") {
		t.Fatalf("hash %q", s.PasswordHash)
	}
	if err := f.svc.CheckPassword(f.ctx, s, "real one", core.ReqMeta{}); err != nil {
		t.Fatal(err)
	}
}

// TestPasswordCheckBusy: a password that could not be checked (too many
// argon2 checks queued) is "busy, try again", never a wrong password — no
// password_fail access row, no audit entry, no share-wide failure token.
func TestPasswordCheckBusy(t *testing.T) {
	f := setup(t)
	file := f.PutFile(f.aliceRoot, "x.txt", []byte("x"))
	_, tok := f.create(f.P(f.alice), core.ShareInput{NodeID: file.ID, Password: "correct horse"})
	s, _, _ := f.svc.Resolve(f.ctx, tok)
	verify := f.svc.verifyPassword
	f.svc.verifyPassword = func(context.Context, string, string) (bool, bool, error) {
		return false, false, crypt.ErrArgonBusy
	}
	meta := core.ReqMeta{IP: netip.MustParseAddr("198.51.100.9")}
	wantCode(t, f.svc.CheckPassword(f.ctx, s, "correct horse", meta), core.ErrUnavailable)
	if n := f.Int(`SELECT COUNT(*) FROM share_access_log WHERE share_id = ?`, s.ID); n != 0 {
		t.Fatalf("%d access rows for an attempt that was not checked", n)
	}
	if e, ok := f.Audit.Find(core.ActSharePasswordFail); ok {
		t.Fatalf("share.password_fail audited for a busy check: %+v", e)
	}
	f.svc.verifyPassword = verify
	if err := f.svc.CheckPassword(f.ctx, s, "correct horse", meta); err != nil {
		t.Fatal(err)
	}
}

func TestCountDownloadConcurrent(t *testing.T) {
	f := setup(t)
	file := f.PutFile(f.aliceRoot, "x.txt", []byte("x"))
	s, tok := f.create(f.P(f.alice), core.ShareInput{NodeID: file.ID, MaxDownloads: ptr(int64(5))})
	var ok, denied atomic.Int32
	var wg sync.WaitGroup
	for range 40 {
		wg.Go(func() {
			rs, _, err := f.svc.Resolve(f.ctx, tok)
			if err != nil {
				denied.Add(1) // exhausted before resolving
				return
			}
			switch err := f.svc.CountDownload(f.ctx, rs); {
			case err == nil:
				ok.Add(1)
			case errors.Is(err, core.ErrForbidden):
				denied.Add(1)
			default:
				t.Error(err)
			}
		})
	}
	wg.Wait()
	if ok.Load() != 5 || denied.Load() != 35 {
		t.Fatalf("ok %d denied %d", ok.Load(), denied.Load())
	}
	if n := f.Int(`SELECT download_count FROM shares WHERE id = ?`, s.ID); n != 5 {
		t.Fatalf("download_count = %d", n)
	}
	if _, _, err := f.svc.Resolve(f.ctx, tok); !errors.Is(err, core.ErrNotFound) {
		t.Fatal("exhausted share still resolves")
	}
	// Unlimited shares count without limit.
	u, utok := f.create(f.P(f.alice), core.ShareInput{NodeID: file.ID})
	ru, _, _ := f.svc.Resolve(f.ctx, utok)
	for range 10 {
		if err := f.svc.CountDownload(f.ctx, ru); err != nil {
			t.Fatal(err)
		}
	}
	if n := f.Int(`SELECT download_count FROM shares WHERE id = ?`, u.ID); n != 10 {
		t.Fatalf("unlimited count = %d", n)
	}
}

// TestCountDownloadOnRevokedShare pins the two zero-row causes apart: a
// share revoked between Resolve and the count is gone, not exhausted, and
// must get the uniform not-found (the visitor would otherwise be told a
// deleted link "reached its download limit").
func TestCountDownloadOnRevokedShare(t *testing.T) {
	f := setup(t)
	alice := f.P(f.alice)
	file := f.PutFile(f.aliceRoot, "x.txt", []byte("x"))
	s, tok := f.create(alice, core.ShareInput{NodeID: file.ID, MaxDownloads: ptr(int64(2))})
	rs, _, err := f.svc.Resolve(f.ctx, tok)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.svc.Revoke(f.ctx, alice, s.ID); err != nil {
		t.Fatal(err)
	}
	err = f.svc.CountDownload(f.ctx, rs)
	wantCode(t, err, core.ErrNotFound)
	if strings.Contains(err.Error(), "download limit") {
		t.Fatalf("a deleted share reports a limit: %v", err)
	}
	// A share that really reached its limit still answers forbidden.
	_, tok2 := f.create(alice, core.ShareInput{NodeID: file.ID, MaxDownloads: ptr(int64(1))})
	r2, _, _ := f.svc.Resolve(f.ctx, tok2)
	if err := f.svc.CountDownload(f.ctx, r2); err != nil {
		t.Fatal(err)
	}
	wantCode(t, f.svc.CountDownload(f.ctx, r2), core.ErrForbidden)
}

// ---------- access log & notifications ----------

func TestRecordAccessAndNotify(t *testing.T) {
	f := setup(t)
	alice := f.P(f.alice)
	folder := f.Mkdir(f.aliceRoot, "Inbox")
	s, _ := f.create(alice, core.ShareInput{Kind: core.ShareRequest, NodeID: folder, NotifyOwner: true, Title: "Docs"})
	ch, unsub := f.Bus.Subscribe(events.TopicShareAccessed)
	defer unsub()

	f.svc.RecordAccess(f.ctx, s, core.ShareAccess{Action: core.AccessUpload, Bytes: 42, Uploader: "Eve", IP: "192.0.2.1",
		UserAgent: strings.Repeat("u", 600)})
	f.svc.RecordAccess(f.ctx, s, core.ShareAccess{Action: "bogus"})  // ignored
	f.svc.RecordAccess(f.ctx, nil, core.ShareAccess{Action: "view"}) // ignored
	select {
	case ev := <-ch:
		se := ev.Data.(core.ShareAccessedEvent)
		if ev.UserID != f.alice || se.Access.Action != core.AccessUpload || se.Share.ID != s.ID {
			t.Fatalf("event %+v", se)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("no share.accessed event")
	}
	_ = f.svc.Close() // waits for the notification goroutine
	sent := f.Notify.Sent()
	if len(sent) != 1 || sent[0].Tmpl != NotifyTemplate || sent[0].To[0] != "alice@example.test" {
		t.Fatalf("sent %+v", sent)
	}
	n := sent[0].Data.(UploadNotice)
	if n.Uploader != "Eve" || n.Bytes != 42 || n.Folder != "Inbox" || n.Title != "Docs" || n.OwnerName != "Alice" {
		t.Fatalf("notice %+v", n)
	}
	page, err := f.svc.AccessLog(f.ctx, alice, s.ID, core.PageReq{})
	if err != nil || len(page.Items) != 1 {
		t.Fatalf("log %+v %v", page, err)
	}
	a := page.Items[0]
	if a.Action != core.AccessUpload || a.Uploader != "Eve" || a.Bytes != 42 || len(a.UserAgent) != 512 || a.IP != "192.0.2.1" {
		t.Fatalf("row %+v", a)
	}
	if got, _ := f.svc.Get(f.ctx, alice, s.ID); got.LastAccessAt == nil {
		t.Fatal("last_access_at not set")
	}

	// No mail without notify_owner, when notify is off, or when notify.events excludes uploads.
	quiet, _ := f.create(alice, core.ShareInput{Kind: core.ShareRequest, NodeID: folder})
	f.svc.RecordAccess(f.ctx, quiet, core.ShareAccess{Action: core.AccessUpload})
	f.Settings.Put(settingNotifyEvents, []string{"security"})
	f.svc.RecordAccess(f.ctx, s, core.ShareAccess{Action: core.AccessUpload})
	f.Settings.Put(settingNotifyEvents, []string{NotifyTemplate})
	f.Notify.On = false
	f.svc.RecordAccess(f.ctx, s, core.ShareAccess{Action: core.AccessUpload})
	_ = f.svc.Close()
	if len(f.Notify.Sent()) != 1 {
		t.Fatalf("unexpected mails: %+v", f.Notify.Sent())
	}

	// Access log pagination.
	for range 5 {
		f.svc.RecordAccess(f.ctx, s, core.ShareAccess{Action: core.AccessView})
	}
	var seen int
	cursor := ""
	for {
		pg, err := f.svc.AccessLog(f.ctx, alice, s.ID, core.PageReq{Limit: 2, Cursor: cursor})
		if err != nil {
			t.Fatal(err)
		}
		seen += len(pg.Items)
		if pg.NextCursor == "" {
			break
		}
		cursor = pg.NextCursor
	}
	if seen != 8 {
		t.Fatalf("paged %d rows, want 8", seen)
	}
}

// TestUploadNoticeFolderLink pins the "Open the folder: …" line of the
// upload e-mail: the template declares a "url" field, so the notice must
// carry the absolute link of the request's folder — and nothing when
// server.public_url is unset, where a relative path would be useless.
func TestUploadNoticeFolderLink(t *testing.T) {
	f := setup(t)
	alice := f.P(f.alice)
	folder := f.Mkdir(f.aliceRoot, "Inbox")
	s, _ := f.create(alice, core.ShareInput{Kind: core.ShareRequest, NodeID: folder, NotifyOwner: true})

	f.svc.RecordAccess(f.ctx, s, core.ShareAccess{Action: core.AccessUpload, Bytes: 10})
	_ = f.svc.Close()
	sent := f.Notify.Sent()
	if len(sent) != 1 {
		t.Fatalf("sent %+v", sent)
	}
	if got := sent[0].Data.(UploadNotice).URL; got != "" {
		t.Fatalf("url without server.public_url = %q", got)
	}

	f.Env.Env.Config.Server.PublicURL = "https://files.example.test/"
	f.svc.RecordAccess(f.ctx, s, core.ShareAccess{Action: core.AccessUpload, Bytes: 10})
	_ = f.svc.Close()
	sent = f.Notify.Sent()
	if len(sent) != 2 {
		t.Fatalf("sent %+v", sent)
	}
	if got, want := sent[1].Data.(UploadNotice).URL, "https://files.example.test/files/"+folder; got != want {
		t.Fatalf("url = %q, want %q", got, want)
	}
}

func TestCookieNameAndStatus(t *testing.T) {
	if got := CookieName("shr_01j8zzzzzzzzzzzzzzabcdefgh"); got != "__Host-fp_s_abcdefgh" {
		t.Fatalf("cookie name %q", got)
	}
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	past, future := now.Add(-time.Second), now.Add(time.Hour)
	two := int64(2)
	cases := []struct {
		s    core.Share
		want string
	}{
		{core.Share{}, core.ShareActive},
		{core.Share{ExpiresAt: &future}, core.ShareActive},
		{core.Share{ExpiresAt: &past}, core.ShareExpired},
		{core.Share{ExpiresAt: &now}, core.ShareExpired},
		{core.Share{DisabledAt: &past, ExpiresAt: &past}, core.ShareDisabled},
		{core.Share{MaxDownloads: &two, DownloadCount: 1}, core.ShareActive},
		{core.Share{MaxDownloads: &two, DownloadCount: 2}, core.ShareExhausted},
	}
	for i, c := range cases {
		if got := status(&c.s, now); got != c.want {
			t.Errorf("case %d: %s, want %s", i, got, c.want)
		}
	}
}

// An active link whose item is in the trash, or whose owner is disabled,
// answers "not found": Get/List must say so instead of reporting it as active.
func TestUnavailableShare(t *testing.T) {
	f := setup(t)
	alice := f.P(f.alice)
	file := f.PutFile(f.aliceRoot, "u.txt", []byte("u"))
	s, tok := f.create(alice, core.ShareInput{NodeID: file.ID})

	state := func(what string) (string, bool) {
		t.Helper()
		got, err := f.svc.Get(f.ctx, alice, s.ID)
		if err != nil {
			t.Fatalf("%s: get: %v", what, err)
		}
		pg, err := f.svc.List(f.ctx, alice, core.ShareQuery{})
		if err != nil {
			t.Fatalf("%s: list: %v", what, err)
		}
		for _, l := range pg.Items {
			if l.ID == s.ID && l.Unavailable != got.Unavailable {
				t.Fatalf("%s: list says unavailable=%v, get says %v", what, l.Unavailable, got.Unavailable)
			}
		}
		return got.Status, got.Unavailable
	}

	if st, un := state("fresh"); st != core.ShareActive || un {
		t.Fatalf("fresh share: status %q unavailable %v", st, un)
	}
	if err := f.Files.Trash(f.ctx, alice, []string{file.ID}); err != nil {
		t.Fatal(err)
	}
	if st, un := state("trashed"); st != core.ShareActive || !un {
		t.Fatalf("trashed item: status %q unavailable %v, want active + unavailable", st, un)
	}
	if _, _, err := f.svc.Resolve(f.ctx, tok); err == nil {
		t.Fatal("a share of a trashed item still resolves")
	}
	// uploadtest.Files has no Restore; untrash the row directly.
	f.Exec(`UPDATE nodes SET trashed_at = NULL WHERE id = ?`, file.ID)
	if st, un := state("restored"); st != core.ShareActive || un {
		t.Fatalf("restored item: status %q unavailable %v", st, un)
	}

	f.Exec(`UPDATE users SET status = 'disabled' WHERE id = ?`, f.alice)
	if st, un := state("owner disabled"); st != core.ShareActive || !un {
		t.Fatalf("disabled owner: status %q unavailable %v, want active + unavailable", st, un)
	}
	f.Exec(`UPDATE users SET status = 'active' WHERE id = ?`, f.alice)
	if st, un := state("owner re-enabled"); st != core.ShareActive || un {
		t.Fatalf("re-enabled owner: status %q unavailable %v", st, un)
	}
}
