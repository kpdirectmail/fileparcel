package sharesapi

import (
	"bytes"
	"context"
	"testing"

	"fileparcel/internal/core"
)

// TestFileRequestRefusesZipPassword pins that a file request never makes a
// password-protected .zip (the owner could not open it): either zip field
// is 422 on that field, before anything is recorded, and the answer never
// echoes the password.
func TestFileRequestRefusesZipPassword(t *testing.T) {
	f := setup(t)
	inbox := f.Mkdir(f.root, "Inbox")
	_, tok := f.share(f.alice, core.ShareInput{Kind: core.ShareRequest, NodeID: inbox})
	path := "/s/" + tok + "/api/upload-batches"
	const pw = "correct horse battery staple"
	files := []map[string]any{{"client_ref": "a", "rel_path": "a.txt", "size": 1}}
	for _, c := range []struct {
		name  string
		body  map[string]any
		field string
	}{
		{"password", map[string]any{"uploader": "Eve", "mode": "zip", "files": files, "zip_password": pw}, "zip_password"},
		{"both", map[string]any{"uploader": "Eve", "mode": "zip", "files": files, "zip_password": pw,
			"zip_encryption": "zipcrypto"}, "zip_password"},
		{"encryption only", map[string]any{"uploader": "Eve", "mode": "zip", "files": files, "zip_encryption": "aes256"},
			"zip_encryption"},
		{"files mode", map[string]any{"uploader": "Eve", "files": files, "zip_password": pw}, "zip_password"},
	} {
		t.Run(c.name, func(t *testing.T) {
			r := f.do(req{method: "POST", path: path, json: c.body})
			r.wantErr(t, 422, "invalid")
			var e apiErr
			r.json(t, &e)
			if e.Error.Field != c.field || e.Error.Message != "password-protected .zip files are not available for file requests" {
				t.Fatalf("error %+v", e.Error)
			}
			if bytes.Contains(r.body, []byte(pw)) {
				t.Fatalf("the answer echoes the password: %s", r.body)
			}
		})
	}
	if n := f.Int(`SELECT COUNT(*) FROM upload_batches`); n != 0 {
		t.Fatalf("%d batches recorded", n)
	}
	// The same request without the fields works.
	if r := f.do(req{method: "POST", path: path, json: map[string]any{"uploader": "Eve", "mode": "zip", "files": files}}); r.StatusCode != 201 {
		t.Fatalf("plain zip request: %d %s", r.StatusCode, r.body)
	}
}

// TestPublicNodeKeepsZipEncryption pins that a link recipient learns that a
// .zip needs a password (the one thing about protection a visitor may see).
func TestPublicNodeKeepsZipEncryption(t *testing.T) {
	f := setup(t)
	folder := f.Mkdir(f.root, "Out")
	w, err := f.Blobs.Create(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	_, _ = w.Write([]byte("PK"))
	info, err := w.Commit(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	z, err := f.Files.CommitFile(context.Background(), f.P(f.alice), folder, "Q3.zip", info,
		core.FileMeta{MIME: "application/zip", ZipEncryption: core.ZipEncZipCrypto}, core.ConflictFail)
	if err != nil {
		t.Fatal(err)
	}
	f.PutFile(folder, "plain.txt", []byte("plain"))

	if got := publicNode(*z, &core.Share{NodeID: z.ID}); got.ZipEncryption != core.ZipEncZipCrypto {
		t.Fatalf("publicNode dropped zip_encryption: %+v", got)
	}
	_, fileTok := f.share(f.alice, core.ShareInput{Kind: core.ShareLink, NodeID: z.ID})
	var pi core.PublicShareInfo
	f.do(req{method: "GET", path: "/s/" + fileTok + "/api"}).json(t, &pi)
	if pi.Node == nil || pi.Node.ZipEncryption != core.ZipEncZipCrypto {
		t.Fatalf("file link node %+v", pi.Node)
	}
	_, dirTok := f.share(f.alice, core.ShareInput{Kind: core.ShareLink, NodeID: folder})
	pi = core.PublicShareInfo{}
	f.do(req{method: "GET", path: "/s/" + dirTok + "/api"}).json(t, &pi)
	seen := map[string]string{}
	for _, n := range pi.Items {
		seen[n.Name] = n.ZipEncryption
	}
	if len(seen) != 2 || seen["Q3.zip"] != core.ZipEncZipCrypto || seen["plain.txt"] != "" {
		t.Fatalf("folder link items %v", seen)
	}
}
