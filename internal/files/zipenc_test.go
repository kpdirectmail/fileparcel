package files

import (
	"encoding/json"
	"strings"
	"testing"

	"fileparcel/internal/core"
)

// commitZip commits data as the file rel below parent, recorded with the
// zip protection enc (what the upload.zip job does).
func (e *testEnv) commitZip(p *user, parent, rel, data, enc string, c core.ConflictPolicy) *core.Node {
	e.t.Helper()
	n, err := e.svc.CommitFile(e.ctx, p.Principal, parent, rel, e.blobs.put(e.t, []byte(data)),
		core.FileMeta{MIME: "application/zip", ZipEncryption: enc}, c)
	if err != nil {
		e.t.Fatalf("commit %q (%s): %v", rel, enc, err)
	}
	return n
}

// versionEncs returns the zip protection of every version of id, newest first.
func (e *testEnv) versionEncs(p *user, id string) []string {
	e.t.Helper()
	vs, err := e.svc.Versions(e.ctx, p.Principal, id)
	if err != nil {
		e.t.Fatalf("versions: %v", err)
	}
	out := make([]string, len(vs))
	for i, v := range vs {
		out[i] = v.ZipEncryption
	}
	return out
}

// zipEncOf returns the zip protection of the node id as Get reports it.
func (e *testEnv) zipEncOf(p *user, id string) string {
	e.t.Helper()
	n, err := e.svc.Get(e.ctx, p.Principal, id)
	if err != nil {
		e.t.Fatalf("get %s: %v", id, err)
	}
	return n.ZipEncryption
}

// findNode returns the node named name in ns (nil when absent).
func findNode(ns []core.Node, name string) *core.Node {
	for i := range ns {
		if ns[i].Name == name {
			return &ns[i]
		}
	}
	return nil
}

// TestZipEncryptionRoundTrip pins that the protection recorded by
// CommitFile (file_versions.zip_encryption) reaches every node payload of
// the current version and every version row, and nothing else.
func TestZipEncryptionRoundTrip(t *testing.T) {
	e := newEnv(t)
	u := e.user("alice", core.RoleMember)
	docs := e.mkdir(u, u.rootID, "Docs")
	z := e.commitZip(u, docs.ID, "secret bundle.zip", "PK-aes", core.ZipEncAES256, core.ConflictFail)
	plain := e.file(u, docs.ID, "plain.txt", "hello")

	if z.ZipEncryption != core.ZipEncAES256 || plain.ZipEncryption != "" {
		t.Fatalf("commit: zip %q, plain %q", z.ZipEncryption, plain.ZipEncryption)
	}
	if got := e.zipEncOf(u, z.ID); got != core.ZipEncAES256 {
		t.Fatalf("get: %q", got)
	}
	var stored string
	if err := e.db.QueryRow(e.ctx, `SELECT zip_encryption FROM file_versions WHERE id = ?`, z.VersionID).Scan(&stored); err != nil ||
		stored != core.ZipEncAES256 {
		t.Fatalf("version row: %q %v", stored, err)
	}
	if n := e.count(`SELECT COUNT(*) FROM file_versions WHERE node_id = ? AND zip_encryption IS NULL`, plain.ID); n != 1 {
		t.Fatalf("unprotected version stores NULL: %d rows", n)
	}

	// The JSON of the node carries it; an unprotected node has no key.
	for _, c := range []struct {
		n    *core.Node
		want bool
	}{{z, true}, {plain, false}} {
		b, err := json.Marshal(c.n)
		if err != nil {
			t.Fatal(err)
		}
		if got := strings.Contains(string(b), `"zip_encryption":"aes256"`); got != c.want {
			t.Fatalf("json of %s: %s", c.n.Name, b)
		}
		if !c.want && strings.Contains(string(b), "zip_encryption") {
			t.Fatalf("unprotected json has the key: %s", b)
		}
	}

	// Listings, search, recent, starred, trash.
	page, err := e.svc.List(e.ctx, u.Principal, docs.ID, core.ListQuery{})
	if err != nil {
		t.Fatal(err)
	}
	if n := findNode(page.Items, z.Name); n == nil || n.ZipEncryption != core.ZipEncAES256 {
		t.Fatalf("list: %+v", n)
	}
	if n := findNode(page.Items, plain.Name); n == nil || n.ZipEncryption != "" {
		t.Fatalf("list plain: %+v", n)
	}
	sp, err := e.svc.Search(e.ctx, u.Principal, core.SearchQuery{Q: "secret"})
	if err != nil {
		t.Fatal(err)
	}
	if n := findNode(sp.Items, z.Name); n == nil || n.ZipEncryption != core.ZipEncAES256 {
		t.Fatalf("search: %+v", sp.Items)
	}
	rec, err := e.svc.Recent(e.ctx, u.Principal, 10)
	if err != nil {
		t.Fatal(err)
	}
	if n := findNode(rec, z.Name); n == nil || n.ZipEncryption != core.ZipEncAES256 {
		t.Fatalf("recent: %+v", rec)
	}
	if err := e.svc.Star(e.ctx, u.Principal, z.ID, true); err != nil {
		t.Fatal(err)
	}
	st, err := e.svc.Starred(e.ctx, u.Principal, core.ListQuery{})
	if err != nil {
		t.Fatal(err)
	}
	if n := findNode(st.Items, z.Name); n == nil || n.ZipEncryption != core.ZipEncAES256 {
		t.Fatalf("starred: %+v", st.Items)
	}
	if vs := e.versionEncs(u, z.ID); len(vs) != 1 || vs[0] != core.ZipEncAES256 {
		t.Fatalf("versions: %v", vs)
	}
	var walked string
	if err := e.svc.Walk(e.ctx, u.Principal, []string{docs.ID}, func(w core.WalkEntry) error {
		if w.Node.ID == z.ID {
			walked = w.Node.ZipEncryption
		}
		return nil
	}); err != nil || walked != core.ZipEncAES256 {
		t.Fatalf("walk: %q %v", walked, err)
	}
	if err := e.svc.Trash(e.ctx, u.Principal, []string{z.ID}); err != nil {
		t.Fatal(err)
	}
	tp, err := e.svc.ListTrash(e.ctx, u.Principal, core.ListQuery{})
	if err != nil {
		t.Fatal(err)
	}
	if n := findNode(tp.Items, z.Name); n == nil || n.ZipEncryption != core.ZipEncAES256 {
		t.Fatalf("trash: %+v", tp.Items)
	}
	if _, err := e.svc.Restore(e.ctx, u.Principal, []string{z.ID}); err != nil {
		t.Fatal(err)
	}
	if got := e.zipEncOf(u, z.ID); got != core.ZipEncAES256 {
		t.Fatalf("after restore from trash: %q", got)
	}

	// The upload audit entry names the protection.
	last := e.audit.all(core.ActFileUpload)
	var seen bool
	for _, a := range last {
		d, _ := a.Details.(map[string]any)
		if a.TargetID == z.ID {
			seen = d["zip_encryption"] == core.ZipEncAES256
		} else if _, ok := d["zip_encryption"]; ok {
			t.Fatalf("unprotected upload audited with zip_encryption: %+v", a)
		}
	}
	if !seen {
		t.Fatalf("file.upload of the zip lacks zip_encryption: %+v", last)
	}
}

// TestZipEncryptionVersions pins that the protection belongs to a version:
// a replacement is protected only when its own bytes are, and a restore
// brings back the protection of the restored version.
func TestZipEncryptionVersions(t *testing.T) {
	e := newEnv(t)
	u := e.user("alice", core.RoleMember)
	first := e.commitZip(u, u.rootID, "Q3.zip", "PK-one", core.ZipEncAES256, core.ConflictFail)

	// Replace with an unprotected upload: new version unprotected, the old
	// one keeps its value.
	second := e.commitZip(u, u.rootID, "Q3.zip", "PK-two", "", core.ConflictReplace)
	if second.ID != first.ID || second.ZipEncryption != "" {
		t.Fatalf("replace with plain: %+v", second)
	}
	if got := e.versionEncs(u, first.ID); len(got) != 2 || got[0] != "" || got[1] != core.ZipEncAES256 {
		t.Fatalf("versions after plain replace: %v", got)
	}
	// Replace with a ZipCrypto zip.
	third := e.commitZip(u, u.rootID, "Q3.zip", "PK-three", core.ZipEncZipCrypto, core.ConflictReplace)
	if third.ZipEncryption != core.ZipEncZipCrypto {
		t.Fatalf("replace with zipcrypto: %+v", third)
	}
	if got := e.versionEncs(u, first.ID); len(got) != 3 || got[0] != core.ZipEncZipCrypto || got[1] != "" ||
		got[2] != core.ZipEncAES256 {
		t.Fatalf("versions after zipcrypto replace: %v", got)
	}
	d, _ := e.audit.last(core.ActFileUpload).Details.(map[string]any)
	if d["zip_encryption"] != core.ZipEncZipCrypto || d["new_version"] != true {
		t.Fatalf("addVersion audit: %+v", d)
	}

	// Restore the first (AES) version: the badge follows.
	restored, err := e.svc.RestoreVersion(e.ctx, u.Principal, first.ID, first.VersionID)
	if err != nil || restored.ZipEncryption != core.ZipEncAES256 {
		t.Fatalf("restore aes: %+v %v", restored, err)
	}
	d, _ = e.audit.last(core.ActFileVersionRestore).Details.(map[string]any)
	if d["zip_encryption"] != core.ZipEncAES256 || d["restored_version_id"] != first.VersionID {
		t.Fatalf("restore audit: %+v", d)
	}
	// Restore the unprotected one: the badge goes away.
	restored, err = e.svc.RestoreVersion(e.ctx, u.Principal, first.ID, second.VersionID)
	if err != nil || restored.ZipEncryption != "" {
		t.Fatalf("restore plain: %+v %v", restored, err)
	}
	if got := e.zipEncOf(u, first.ID); got != "" {
		t.Fatalf("get after plain restore: %q", got)
	}
	d, _ = e.audit.last(core.ActFileVersionRestore).Details.(map[string]any)
	if _, ok := d["zip_encryption"]; ok {
		t.Fatalf("plain restore audited with zip_encryption: %+v", d)
	}
	if got := e.versionEncs(u, first.ID); got[0] != "" {
		t.Fatalf("current version after plain restore: %v", got)
	}
}

// TestZipEncryptionCopy pins that every copy path keeps the protection:
// a single file, a folder containing the zip (copyChildren) and a copy
// that replaces an existing file.
func TestZipEncryptionCopy(t *testing.T) {
	e := newEnv(t)
	u := e.user("alice", core.RoleMember)
	src := e.mkdir(u, u.rootID, "Src")
	deep := e.mkdir(u, src.ID, "Deep")
	z := e.commitZip(u, deep.ID, "inner.zip", "PK-inner", core.ZipEncZipCrypto, core.ConflictFail)
	top := e.commitZip(u, src.ID, "top.zip", "PK-top", core.ZipEncAES256, core.ConflictFail)
	e.file(u, deep.ID, "plain.txt", "plain")
	dst := e.mkdir(u, u.rootID, "Dst")

	// A single file.
	out, err := e.svc.Copy(e.ctx, u.Principal, []string{top.ID}, dst.ID, "")
	if err != nil || len(out) != 1 || out[0].ID == top.ID || out[0].ZipEncryption != core.ZipEncAES256 {
		t.Fatalf("copy file: %+v %v", out, err)
	}
	if got := e.versionEncs(u, out[0].ID); len(got) != 1 || got[0] != core.ZipEncAES256 {
		t.Fatalf("copied file versions: %v", got)
	}

	// A folder: its children are copied by copyChildren.
	out, err = e.svc.Copy(e.ctx, u.Principal, []string{src.ID}, dst.ID, "")
	if err != nil || len(out) != 1 {
		t.Fatalf("copy folder: %+v %v", out, err)
	}
	page, err := e.svc.List(e.ctx, u.Principal, out[0].ID, core.ListQuery{})
	if err != nil {
		t.Fatal(err)
	}
	if n := findNode(page.Items, "top.zip"); n == nil || n.ZipEncryption != core.ZipEncAES256 {
		t.Fatalf("copied folder, top.zip: %+v", n)
	}
	deepCopy := findNode(page.Items, "Deep")
	if deepCopy == nil {
		t.Fatalf("copied folder lacks Deep: %v", nodeNames(page.Items))
	}
	page, err = e.svc.List(e.ctx, u.Principal, deepCopy.ID, core.ListQuery{})
	if err != nil {
		t.Fatal(err)
	}
	if n := findNode(page.Items, "inner.zip"); n == nil || n.ID == z.ID || n.ZipEncryption != core.ZipEncZipCrypto {
		t.Fatalf("copied folder, inner.zip: %+v", n)
	}
	if n := findNode(page.Items, "plain.txt"); n == nil || n.ZipEncryption != "" {
		t.Fatalf("copied folder, plain.txt: %+v", n)
	}

	// Copy with replace: the existing file gets a protected version.
	target := e.file(u, u.rootID, "inner.zip", "old plain bytes")
	out, err = e.svc.Copy(e.ctx, u.Principal, []string{z.ID}, u.rootID, core.ConflictReplace)
	if err != nil || len(out) != 1 || out[0].ID != target.ID || out[0].ZipEncryption != core.ZipEncZipCrypto {
		t.Fatalf("copy replace: %+v %v", out, err)
	}
	if got := e.versionEncs(u, target.ID); len(got) != 2 || got[0] != core.ZipEncZipCrypto || got[1] != "" {
		t.Fatalf("copy replace versions: %v", got)
	}
	d, _ := e.audit.last(core.ActFileCopy).Details.(map[string]any)
	if d["zip_encryption"] != core.ZipEncZipCrypto {
		t.Fatalf("copy replace audit: %+v", d)
	}
}

// TestZipEncryptionInvalid pins that CommitFile refuses a value the
// database would refuse (422 on zip_encryption) and records nothing.
func TestZipEncryptionInvalid(t *testing.T) {
	e := newEnv(t)
	u := e.user("alice", core.RoleMember)
	for _, enc := range []string{"bogus", "AES256", "aes128", " aes256"} {
		_, err := e.svc.CommitFile(e.ctx, u.Principal, u.rootID, "x.zip", e.blobs.put(t, []byte("PK")),
			core.FileMeta{ZipEncryption: enc}, "")
		ce := core.AsError(err)
		if ce == nil || ce.Code != "invalid" || ce.Field != "zip_encryption" {
			t.Fatalf("%q: %v", enc, err)
		}
	}
	if n := e.count(`SELECT COUNT(*) FROM nodes WHERE name = 'x.zip'`); n != 0 {
		t.Fatalf("a refused commit stored %d nodes", n)
	}
}
