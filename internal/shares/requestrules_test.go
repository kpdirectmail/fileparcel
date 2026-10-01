package shares

import (
	"errors"
	"testing"

	"fileparcel/internal/core"
)

// A file request never shows the folder's files: create and edit refuse
// allow_download / allow_preview, and turning its uploads off. Stored rows
// from before the rule do not open the folder either.
func TestRequestStaysUploadOnly(t *testing.T) {
	f := setup(t)
	alice := f.P(f.alice)
	inbox := f.Mkdir(f.aliceRoot, "Inbox")
	for field, in := range map[string]core.ShareInput{
		"allow_download": {Kind: core.ShareRequest, NodeID: inbox, AllowDownload: ptr(true)},
		"allow_preview":  {Kind: core.ShareRequest, NodeID: inbox, AllowPreview: ptr(true)},
	} {
		_, _, err := f.svc.Create(f.ctx, alice, in)
		if ce := core.AsError(err); !errors.Is(err, core.ErrInvalid) || ce.Field != field {
			t.Errorf("create with %s: %v", field, err)
		}
	}
	// Saying false is fine.
	s, tok := f.create(alice, core.ShareInput{Kind: core.ShareRequest, NodeID: inbox, AllowDownload: ptr(false), AllowPreview: ptr(false)})
	for field, in := range map[string]core.ShareUpdate{
		"allow_download": {AllowDownload: ptr(true)},
		"allow_preview":  {AllowPreview: ptr(true)},
		"allow_upload":   {AllowUpload: ptr(false)},
	} {
		_, err := f.svc.Update(f.ctx, alice, s.ID, in)
		if ce := core.AsError(err); !errors.Is(err, core.ErrInvalid) || ce.Field != field {
			t.Errorf("edit %s: %v", field, err)
		}
	}
	if got, err := f.svc.Update(f.ctx, alice, s.ID, core.ShareUpdate{AllowDownload: ptr(false), AllowUpload: ptr(true), Title: ptr("Drop")}); err != nil ||
		got.AllowDownload || got.AllowPreview || !got.AllowUpload || got.Title != "Drop" {
		t.Fatalf("harmless edit: %+v %v", got, err)
	}
	// A row written before the rule: the public side still hides the folder.
	f.Exec(`UPDATE shares SET allow_download = 1, allow_preview = 1 WHERE id = ?`, s.ID)
	rs, _, err := f.svc.Resolve(f.ctx, tok)
	if err != nil || rs.AllowDownload || rs.AllowPreview || !rs.AllowUpload {
		t.Fatalf("resolved legacy request: %+v %v", rs, err)
	}
	// Links keep their choice.
	l, _ := f.create(alice, core.ShareInput{NodeID: inbox, AllowUpload: true, AllowDownload: ptr(false)})
	if got, err := f.svc.Update(f.ctx, alice, l.ID, core.ShareUpdate{AllowDownload: ptr(true), AllowUpload: ptr(false)}); err != nil ||
		!got.AllowDownload || got.AllowUpload {
		t.Fatalf("link edit: %+v %v", got, err)
	}
}

// Turning uploads on through an edit needs files:write on an API token,
// exactly as creating a share that accepts uploads does.
func TestUpdateAllowUploadNeedsFilesWrite(t *testing.T) {
	f := setup(t)
	folder := f.Mkdir(f.aliceRoot, "Projects")
	tok := f.P(f.alice)
	tok.Via, tok.Scopes = core.ViaToken, []string{core.ScopeFilesRead, core.ScopeShares}
	_, _, err := f.svc.Create(f.ctx, tok, core.ShareInput{NodeID: folder, AllowUpload: true})
	wantCode(t, err, core.ErrForbidden)
	s, _ := f.create(tok, core.ShareInput{NodeID: folder})
	_, err = f.svc.Update(f.ctx, tok, s.ID, core.ShareUpdate{AllowUpload: ptr(true)})
	if !errors.Is(err, core.ErrForbidden) || core.AsError(err).Message != `token lacks scope "files:write"` {
		t.Fatalf("enable uploads with a read-only token: %v", err)
	}
	// Other edits, and turning uploads off, still work with it.
	if _, err := f.svc.Update(f.ctx, tok, s.ID, core.ShareUpdate{Title: ptr("Projects"), AllowUpload: ptr(false)}); err != nil {
		t.Fatalf("other edits: %v", err)
	}
	tok.Scopes = append(tok.Scopes, core.ScopeFilesWrite)
	if got, err := f.svc.Update(f.ctx, tok, s.ID, core.ShareUpdate{AllowUpload: ptr(true)}); err != nil || !got.AllowUpload {
		t.Fatalf("with files:write: %+v %v", got, err)
	}
}

// Titles and messages refuse text-direction overrides, as names do.
func TestShareTextsRefuseBidiControls(t *testing.T) {
	f := setup(t)
	alice := f.P(f.alice)
	file := f.PutFile(f.aliceRoot, "invoice.pdf", []byte("x"))
	for field, in := range map[string]core.ShareInput{
		"title":   {NodeID: file.ID, Title: "invoice\u202etxt.exe"},
		"message": {NodeID: file.ID, Message: "see \u2066attached\u2069"},
	} {
		_, _, err := f.svc.Create(f.ctx, alice, in)
		if ce := core.AsError(err); !errors.Is(err, core.ErrInvalid) || ce.Field != field {
			t.Errorf("%s: %v", field, err)
		}
	}
	s, _ := f.create(alice, core.ShareInput{NodeID: file.ID, Title: "\u200fשלום"}) // an implicit mark stays allowed
	if _, err := f.svc.Update(f.ctx, alice, s.ID, core.ShareUpdate{Title: ptr("a\u202eb")}); !errors.Is(err, core.ErrInvalid) {
		t.Fatalf("edit title: %v", err)
	}
}

// A creator who lost access to the item sees the share as unavailable, and
// a file request whose creator can no longer add files does not resolve.
func TestUnavailableWhenCreatorLostAccess(t *testing.T) {
	f := setup(t)
	projects := f.Mkdir(f.bobRoot, "Projects")
	f.Files.Grant(f.alice, projects, core.PermManage)
	alice := f.P(f.alice)
	link, linkTok := f.create(alice, core.ShareInput{NodeID: projects})
	req, reqTok := f.create(alice, core.ShareInput{Kind: core.ShareRequest, NodeID: projects})
	unavailable := func(what string, id string) bool {
		t.Helper()
		got, err := f.svc.Get(f.ctx, alice, id)
		if err != nil {
			t.Fatalf("%s: get: %v", what, err)
		}
		pg, err := f.svc.List(f.ctx, alice, core.ShareQuery{})
		if err != nil {
			t.Fatal(err)
		}
		for _, s := range pg.Items {
			if s.ID == id && s.Unavailable != got.Unavailable {
				t.Fatalf("%s: list %v, get %v", what, s.Unavailable, got.Unavailable)
			}
		}
		return got.Unavailable
	}
	if unavailable("fresh link", link.ID) || unavailable("fresh request", req.ID) {
		t.Fatal("fresh shares unavailable")
	}
	// Reduced to viewer: the link works, the request does not.
	f.Files.Grant(f.alice, projects, core.PermView)
	if unavailable("viewer link", link.ID) || !unavailable("viewer request", req.ID) {
		t.Fatal("viewer: the link should work, the request not")
	}
	if _, _, err := f.svc.Resolve(f.ctx, linkTok); err != nil {
		t.Fatalf("link with a viewer creator: %v", err)
	}
	if _, _, err := f.svc.Resolve(f.ctx, reqTok); !errors.Is(err, core.ErrNotFound) {
		t.Fatalf("request with a viewer creator: %v", err)
	}
	// No access at all: both unavailable.
	f.Files.Grant(f.alice, projects, core.PermNone)
	if !unavailable("no access link", link.ID) || !unavailable("no access request", req.ID) {
		t.Fatal("no access: both should be unavailable")
	}
	// An administrator's list says the same.
	pg, err := f.svc.ListAll(core.WithPrincipal(f.ctx, core.SystemPrincipal(core.ViaSocket)), core.ShareQuery{})
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range pg.Items {
		if (s.ID == link.ID || s.ID == req.ID) && !s.Unavailable {
			t.Errorf("admin list: %s available", s.ID)
		}
	}
}
