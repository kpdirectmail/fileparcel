package backup

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"filippo.io/age"
	"github.com/klauspost/compress/zstd"

	"fileparcel/internal/core"
	"fileparcel/internal/db"
)

// craftMember is one member of a hand-made archive.
type craftMember struct {
	name     string
	typ      byte // 0 = regular
	data     []byte
	linkname string
}

// craftArchive writes an age(zstd(tar)) archive with exactly the given
// members (no validation), for adversarial tests.
func craftArchive(t *testing.T, r age.Recipient, members []craftMember) []byte {
	t.Helper()
	var out bytes.Buffer
	aw, err := age.Encrypt(&out, r)
	if err != nil {
		t.Fatal(err)
	}
	zw, err := zstd.NewWriter(aw)
	if err != nil {
		t.Fatal(err)
	}
	tw := tar.NewWriter(zw)
	for _, m := range members {
		typ := m.typ
		if typ == 0 {
			typ = tar.TypeReg
		}
		h := &tar.Header{Typeflag: typ, Name: m.name, Mode: 0o600, ModTime: time.Unix(1, 0), Linkname: m.linkname, Format: tar.FormatPAX}
		if typ == tar.TypeReg {
			h.Size = int64(len(m.data))
		}
		if err := tw.WriteHeader(h); err != nil {
			t.Fatal(err)
		}
		if typ == tar.TypeReg {
			if _, err := tw.Write(m.data); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := aw.Close(); err != nil {
		t.Fatal(err)
	}
	return out.Bytes()
}

func testHeader(schema int) Header {
	return Header{Format: FormatName, Version: FormatVersion, BackupID: "bak_00000000000000000000000000", AppVersion: "vtest",
		SchemaVersion: schema, Scope: core.BackupMetadata, InstallID: "0123456789abcdef", CreatedAt: time.Unix(1700000000, 0).UTC(),
		Encryption: core.BackupX25519}
}

// validMembers returns a consistent member list (header, db, config, key,
// extra, manifest) — mutate returns a modified list before the manifest is
// computed; extra members are appended after the manifest.
func validMembers(t *testing.T, hdr Header, mutate func([]craftMember) []craftMember, trailing ...craftMember) []craftMember {
	t.Helper()
	hb, _ := json.Marshal(hdr)
	ms := []craftMember{
		{name: memberHeader, data: hb},
		{name: memberDB, data: []byte("not really a database")},
		{name: memberConfig, data: []byte("install_id = \"x\"\n")},
		{name: memberMasterKy, data: []byte(`{"v":1}`)},
	}
	if mutate != nil {
		ms = mutate(ms)
	}
	m := Manifest{Header: hdr}
	for _, x := range ms {
		if x.typ != 0 && x.typ != tar.TypeReg {
			continue
		}
		sum := sha256.Sum256(x.data)
		m.Members = append(m.Members, Member{Name: x.name, Size: int64(len(x.data)), SHA256: hex.EncodeToString(sum[:])})
	}
	mb, _ := json.Marshal(m)
	ms = append(ms, craftMember{name: memberManifest, data: mb})
	return append(ms, trailing...)
}

func TestWalkArchiveRejectsHostileArchives(t *testing.T) {
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	ids := []age.Identity{id}
	schema := db.LatestVersion()
	hdr := testHeader(schema)
	withMember := func(m craftMember) func([]craftMember) []craftMember {
		return func(ms []craftMember) []craftMember { return append(ms, m) }
	}
	hb, _ := json.Marshal(hdr)
	tests := []struct {
		name    string
		members []craftMember
		code    *core.Error
		msg     string
	}{
		{"valid", validMembers(t, hdr, nil), nil, ""},
		{"empty", nil, core.ErrCorrupt, "empty archive"},
		{"no header first", validMembers(t, hdr, func(ms []craftMember) []craftMember { return ms[1:] }), core.ErrCorrupt, "missing header"},
		{"traversal", validMembers(t, hdr, withMember(craftMember{name: "../../evil", data: []byte("x")})), core.ErrCorrupt, "unexpected member"},
		{"absolute", validMembers(t, hdr, withMember(craftMember{name: "/tmp/evil", data: []byte("x")})), core.ErrCorrupt, "unexpected member"},
		{"cert traversal", validMembers(t, hdr, withMember(craftMember{name: "certs/../../evil", data: []byte("x")})), core.ErrCorrupt, "unexpected member"},
		{"unknown top level", validMembers(t, hdr, withMember(craftMember{name: "bin/fileparcel", data: []byte("x")})), core.ErrCorrupt, "unexpected member"},
		{"symlink", validMembers(t, hdr, withMember(craftMember{name: "certs/link", typ: tar.TypeSymlink, linkname: "/etc/passwd"})), core.ErrCorrupt, "not a regular file"},
		{"hardlink", validMembers(t, hdr, withMember(craftMember{name: "certs/hl", typ: tar.TypeLink, linkname: "keys/master.key"})), core.ErrCorrupt, "not a regular file"},
		{"directory", validMembers(t, hdr, withMember(craftMember{name: "certs/dir/", typ: tar.TypeDir})), core.ErrCorrupt, "unexpected member"},
		{"blob fan-out mismatch", validMembers(t, hdr, withMember(craftMember{name: "data/blobs/00/00/" + strings.Repeat("ab", 16), data: []byte("x")})), core.ErrCorrupt, "unexpected member"},
		{"duplicate", validMembers(t, hdr, withMember(craftMember{name: memberConfig, data: []byte("again")})), core.ErrCorrupt, "duplicate member"},
		{"second header", validMembers(t, hdr, withMember(craftMember{name: memberHeader, data: hb})), core.ErrCorrupt, "unexpected member"},
		{"oversized config", validMembers(t, hdr, func(ms []craftMember) []craftMember {
			ms[2].data = bytes.Repeat([]byte("#"), maxConfigSize+1)
			return ms
		}), core.ErrCorrupt, "too large"},
		{"data after manifest", validMembers(t, hdr, nil, craftMember{name: "certs/late", data: []byte("x")}), core.ErrCorrupt, "after the manifest"},
		{"no manifest", validMembers(t, hdr, nil)[:4], core.ErrCorrupt, "manifest missing"},
		{"missing database", validMembers(t, hdr, func(ms []craftMember) []craftMember { return append(ms[:1], ms[2:]...) }), core.ErrCorrupt, "database snapshot missing"},
		{"missing key", validMembers(t, hdr, func(ms []craftMember) []craftMember { return ms[:3] }), core.ErrCorrupt, "master key missing"},
		{"wrong format", func() []craftMember {
			h := hdr
			h.Format = "tarball"
			return validMembers(t, h, nil)
		}(), core.ErrCorrupt, "not a FileParcel backup"},
		{"future format version", func() []craftMember {
			h := hdr
			h.Version = FormatVersion + 1
			return validMembers(t, h, nil)
		}(), core.ErrInvalid, "not supported"},
		{"bad scope", func() []craftMember {
			h := hdr
			h.Scope = "partial"
			return validMembers(t, h, nil)
		}(), core.ErrCorrupt, "unknown scope"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data := craftArchive(t, id.Recipient(), tt.members)
			_, err := walkArchive(context.Background(), bytes.NewReader(data), ids, nil, nil)
			if tt.code == nil {
				if err != nil {
					t.Fatalf("valid archive rejected: %v", err)
				}
				return
			}
			if !errors.Is(err, tt.code) || !strings.Contains(err.Error(), tt.msg) {
				t.Fatalf("got %v, want %s containing %q", err, tt.code.Code, tt.msg)
			}
		})
	}

	// Manifest tampering: a member's checksum, a header mismatch, a missing entry.
	good := validMembers(t, hdr, nil)
	var m Manifest
	_ = json.Unmarshal(good[len(good)-1].data, &m)
	tamper := func(f func(*Manifest)) []craftMember {
		mm := m
		mm.Members = append([]Member(nil), m.Members...)
		f(&mm)
		b, _ := json.Marshal(mm)
		out := append([]craftMember(nil), good...)
		out[len(out)-1] = craftMember{name: memberManifest, data: b}
		return out
	}
	for name, ms := range map[string][]craftMember{
		"checksum":        tamper(func(mm *Manifest) { mm.Members[1].SHA256 = strings.Repeat("0", 64) }),
		"size":            tamper(func(mm *Manifest) { mm.Members[1].Size++ }),
		"header mismatch": tamper(func(mm *Manifest) { mm.BackupID = "bak_other" }),
		"missing entry":   tamper(func(mm *Manifest) { mm.Members = mm.Members[1:] }),
		"renamed entry":   tamper(func(mm *Manifest) { mm.Members[1].Name = "certs/other" }),
		"garbage": func() []craftMember {
			out := append([]craftMember(nil), good...)
			out[len(out)-1] = craftMember{name: memberManifest, data: []byte("{not json")}
			return out
		}(),
	} {
		data := craftArchive(t, id.Recipient(), ms)
		if _, err := walkArchive(context.Background(), bytes.NewReader(data), ids, nil, nil); !errors.Is(err, core.ErrCorrupt) {
			t.Errorf("manifest %s: %v", name, err)
		}
	}

	// Not age at all / wrong identity / no identity.
	if _, err := walkArchive(context.Background(), strings.NewReader("hello"), ids, nil, nil); !errors.Is(err, core.ErrCorrupt) {
		t.Errorf("plain text: %v", err)
	}
	other, _ := age.GenerateX25519Identity()
	data := craftArchive(t, id.Recipient(), good)
	if _, err := walkArchive(context.Background(), bytes.NewReader(data), []age.Identity{other}, nil, nil); !errors.Is(err, core.ErrForbidden) {
		t.Errorf("wrong identity: %v", err)
	}
	if _, err := walkArchive(context.Background(), bytes.NewReader(data), nil, nil, nil); !errors.Is(err, core.ErrInvalid) {
		t.Errorf("no identity: %v", err)
	}
	// Canceled context.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := walkArchive(ctx, bytes.NewReader(data), ids, nil, nil); err == nil {
		t.Error("canceled walk succeeded")
	}
}

// TestRestoreRejectsHostileArchive: a traversal member aborts the restore
// before anything in the home changes, and nothing is written outside the
// staging directory.
func TestRestoreRejectsHostileArchive(t *testing.T) {
	te := newTestEnv(t)
	ctx := context.Background()
	id, _ := age.GenerateX25519Identity()
	hdr := testHeader(db.LatestVersion())
	evil := filepath.Join(filepath.Dir(te.h.Dir()), "evil")
	members := validMembers(t, hdr, func(ms []craftMember) []craftMember {
		return append(ms, craftMember{name: "certs/../../evil", data: []byte("pwned")})
	})
	path := filepath.Join(t.TempDir(), "hostile.fpbak")
	if err := os.WriteFile(path, craftArchive(t, id.Recipient(), members), 0o600); err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(te.h.KeysFile())
	err := te.svc.RestoreOffline(ctx, path, core.RestoreCreds{Identity: id.String()}, core.RestoreOpts{})
	if !errors.Is(err, core.ErrCorrupt) {
		t.Fatalf("hostile restore: %v", err)
	}
	if _, err := os.Stat(evil); err == nil {
		t.Fatal("file written outside the home")
	}
	after, _ := os.ReadFile(te.h.KeysFile())
	if !bytes.Equal(before, after) {
		t.Fatal("home changed")
	}
	if !te.audit.has(core.ActBackupRestore, core.OutcomeFailure) {
		t.Fatal("failed restore not audited")
	}

	// A backup from a newer FileParcel (schema) is refused.
	newer := validMembers(t, testHeader(db.LatestVersion()+1), nil)
	if err := os.WriteFile(path, craftArchive(t, id.Recipient(), newer), 0o600); err != nil {
		t.Fatal(err)
	}
	err = te.svc.RestoreOffline(ctx, path, core.RestoreCreds{Identity: id.String()}, core.RestoreOpts{DryRun: true})
	if !errors.Is(err, core.ErrInvalid) || !strings.Contains(err.Error(), "newer FileParcel") {
		t.Fatalf("newer schema: %v", err)
	}
	// A consistent archive whose "database" is not SQLite fails the checks.
	if err := os.WriteFile(path, craftArchive(t, id.Recipient(), validMembers(t, hdr, nil)), 0o600); err != nil {
		t.Fatal(err)
	}
	err = te.svc.RestoreOffline(ctx, path, core.RestoreCreds{Identity: id.String()}, core.RestoreOpts{})
	if !errors.Is(err, core.ErrCorrupt) {
		t.Fatalf("garbage database: %v", err)
	}
	if ents, _ := os.ReadDir(te.h.TmpDir("restore")); len(ents) != 0 {
		t.Fatalf("staging left behind: %v", ents)
	}
	// A missing file.
	if err := te.svc.RestoreOffline(ctx, path+".nope", core.RestoreCreds{Identity: id.String()}, core.RestoreOpts{}); !errors.Is(err, core.ErrNotFound) {
		t.Fatalf("missing file: %v", err)
	}
}

func TestDecryptErrorMapping(t *testing.T) {
	if decryptError(nil) != nil {
		t.Fatal("nil")
	}
	if err := decryptError(&age.NoIdentityMatchError{}); !errors.Is(err, core.ErrForbidden) {
		t.Fatalf("no match: %v", err)
	}
	if err := decryptError(age.ErrIncorrectIdentity); !errors.Is(err, core.ErrForbidden) {
		t.Fatalf("incorrect: %v", err)
	}
	if err := decryptError(core.Invalid("x", "y")); !errors.Is(err, core.ErrInvalid) {
		t.Fatalf("core error kept: %v", err)
	}
	if err := decryptError(io.ErrUnexpectedEOF); !errors.Is(err, core.ErrCorrupt) {
		t.Fatalf("other: %v", err)
	}
	for in, want := range map[int64]string{0: "0 B", 2048: "2.0 KiB", 3 << 30: "3.0 GiB"} {
		if got := humanBytes(in); got != want {
			t.Errorf("humanBytes(%d) = %q", in, got)
		}
	}
	for in, want := range map[string]string{"0123456789abcdef": "01234567", "AB-cd": "abcd", "": "unknown", "!!": "unknown"} {
		if got := install8(in); got != want {
			t.Errorf("install8(%q) = %q", in, got)
		}
	}
}

// readMember returns one member of an archive, straight from the tar.
func readMember(t *testing.T, path string, ids []age.Identity, name string) []byte {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	tr, closeZ, err := openPlain(context.Background(), f, ids)
	if err != nil {
		t.Fatal(err)
	}
	defer closeZ()
	for {
		th, err := tr.Next()
		if err != nil {
			t.Fatalf("member %s not found: %v", name, err)
		}
		if th.Name != name {
			continue
		}
		b, err := io.ReadAll(tr)
		if err != nil {
			t.Fatal(err)
		}
		if int64(len(b)) != th.Size {
			t.Fatalf("member %s: tar declares %d bytes, holds %d", name, th.Size, len(b))
		}
		return b
	}
}

// TestManifestIsStreamed checks the manifest the writer produces: it is
// spliced together from a spilled member list, so its JSON, its declared
// size and its member order have to come out exactly as a reader expects.
func TestManifestIsStreamed(t *testing.T) {
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "out.fpbak")
	out, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	spill := filepath.Join(dir, "spill")
	aw, err := newArchiveWriter(context.Background(), out, []age.Recipient{id.Recipient()}, time.Unix(1700000000, 0), spill)
	if err != nil {
		t.Fatal(err)
	}
	hdr := testHeader(db.LatestVersion())
	hdr.MKID, hdr.DBSize = "mk_stream", 21
	hb, _ := json.Marshal(hdr)
	names := []string{memberHeader, memberDB, memberConfig, memberMasterKy}
	for _, m := range []struct{ name, data string }{
		{memberHeader, string(hb)},
		{memberDB, "not really a database"},
		{memberConfig, "install_id = \"x\"\n"},
		{memberMasterKy, `{"v":1,"mk_id":"mk_stream"}`},
	} {
		if err := aw.addBytes(m.name, []byte(m.data)); err != nil {
			t.Fatal(err)
		}
	}
	m := &Manifest{Header: hdr}
	m.Counts.DBSize = 21
	m.MissingBlobs = []string{"0123456789abcdef0123456789abcdef"}
	if _, _, err := aw.finish(m); err != nil {
		t.Fatal(err)
	}
	if err := out.Close(); err != nil {
		t.Fatal(err)
	}
	// The spilled member list is gone.
	if ents, _ := os.ReadDir(spill); len(ents) != 0 {
		t.Fatalf("temporary files left behind: %v", ents)
	}

	// The manifest as written: valid JSON, members in archive order.
	var got Manifest
	raw := readMember(t, path, []age.Identity{id}, memberManifest)
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatalf("manifest: %v\n%s", err, raw)
	}
	if len(got.Members) != len(names) {
		t.Fatalf("manifest lists %d members, want %d: %s", len(got.Members), len(names), raw)
	}
	for i, n := range names {
		if got.Members[i].Name != n {
			t.Fatalf("member %d = %q, want %q (archive order)", i, got.Members[i].Name, n)
		}
		if got.Members[i].Size == 0 || len(got.Members[i].SHA256) != 64 {
			t.Fatalf("member %d = %+v", i, got.Members[i])
		}
	}
	if got.Counts.Members != len(names) || got.Counts.DBSize != 21 || len(got.MissingBlobs) != 1 || !got.Header.equal(hdr) {
		t.Fatalf("manifest %+v", got)
	}

	// And it walks back clean.
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	wr, err := walkArchive(context.Background(), f, []age.Identity{id}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if wr.Members != int64(len(names)) || wr.MissingBlobs != 1 || wr.Header.MKID != "mk_stream" {
		t.Fatalf("walk: members %d missing %d header %+v", wr.Members, wr.MissingBlobs, wr.Header)
	}
	if wr.Manifest.Counts.Members != len(names) || wr.Manifest.Counts.DBSize != 21 {
		t.Fatalf("counts %+v", wr.Manifest.Counts)
	}
}

// TestWalkArchiveRejectsAForeignKeyFile: a master key rotation between the
// database snapshot and the key file leaves an archive whose keys/master.key
// does not belong to its database. Restoring it produces a server that
// refuses to start, so the walk (every verify, restore and import) must
// reject it instead.
func TestWalkArchiveRejectsAForeignKeyFile(t *testing.T) {
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	hdr := testHeader(db.LatestVersion())
	hdr.MKID = "mk_01snapshot"
	ms := validMembers(t, hdr, func(ms []craftMember) []craftMember {
		ms[3].data = []byte(`{"v":1,"mk_id":"mk_01rotated","mode":"plain","key":"AAAA"}`)
		return ms
	})
	_, err = walkArchive(context.Background(), bytes.NewReader(craftArchive(t, id.Recipient(), ms)), []age.Identity{id}, nil, nil)
	if !errors.Is(err, core.ErrCorrupt) || !strings.Contains(err.Error(), "cannot be restored") {
		t.Fatalf("foreign key file accepted: %v", err)
	}
	// The same archive with a matching key file is fine.
	ms = validMembers(t, hdr, func(ms []craftMember) []craftMember {
		ms[3].data = []byte(`{"v":1,"mk_id":"mk_01snapshot","mode":"plain","key":"AAAA"}`)
		return ms
	})
	if _, err := walkArchive(context.Background(), bytes.NewReader(craftArchive(t, id.Recipient(), ms)),
		[]age.Identity{id}, nil, nil); err != nil {
		t.Fatalf("matching key file rejected: %v", err)
	}
}

// TestArchiveMemberBookkeepingIsBounded pins the memory cost of the member
// list: neither writing nor walking an archive may hold per-member state on
// the heap. At about 900 bytes per member (a Member struct, its JSON and a
// map entry) a full backup of a million files needed ~0.9 GiB on both sides,
// above the default GOMEMLIMIT, and a 1 MB crafted archive cost 260 MB. The
// budget below leaves room for the constant buffers (an 8 MiB zstd window
// among them) and still fails at a tenth of the old cost.
func TestArchiveMemberBookkeepingIsBounded(t *testing.T) {
	if testing.Short() {
		t.Skip("allocation measurement")
	}
	const members = 100_000
	// Both sides keep only constant buffers now (a zstd window among them);
	// before, the member list alone cost ~90 MiB at this size.
	const writeBudget = 32 << 20
	const readBudget = 24 << 20
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "many.fpbak")
	out, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	hdr := testHeader(db.LatestVersion())
	aw, err := newArchiveWriter(context.Background(), out, []age.Recipient{id.Recipient()}, time.Unix(1700000000, 0), dir)
	if err != nil {
		t.Fatal(err)
	}
	hb, _ := json.Marshal(hdr)
	for _, m := range []struct{ name, data string }{
		{memberHeader, string(hb)},
		{memberDB, "not really a database"},
		{memberConfig, "install_id = \"x\"\n"},
		{memberMasterKy, `{"v":1}`},
	} {
		if err := aw.addBytes(m.name, []byte(m.data)); err != nil {
			t.Fatal(err)
		}
	}
	base := heapInUse()
	for i := range members {
		if err := aw.addBytes(blobMemberName(fmt.Sprintf("%032x", i)), nil); err != nil {
			t.Fatal(err)
		}
	}
	if grew := heapInUse() - base; grew > writeBudget {
		t.Errorf("writing kept %d bytes of per-member state for %d members (%d per member)", grew, members, grew/members)
	}
	if _, _, err := aw.finish(&Manifest{Header: hdr}); err != nil {
		t.Fatal(err)
	}
	if err := out.Close(); err != nil {
		t.Fatal(err)
	}

	// Walking it back must not grow with the member count either: measured
	// at the last member, while the walk still runs.
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	var peak int64
	seen := 0
	base = heapInUse()
	wr, err := walkArchive(context.Background(), f, []age.Identity{id}, nil,
		func(m memberInfo, r io.Reader) error {
			if seen++; seen == members {
				peak = heapInUse() - base
			}
			return nil
		})
	if err != nil {
		t.Fatal(err)
	}
	if wr.Members != members+4 {
		t.Fatalf("walked %d members", wr.Members)
	}
	if peak > readBudget {
		t.Errorf("walking kept %d bytes of per-member state for %d members (%d per member)", peak, members, peak/members)
	}
}

// heapInUse returns the live heap after a collection.
func heapInUse() int64 {
	runtime.GC()
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	return int64(ms.HeapAlloc)
}

// TestManifestSizeIsBoundedByTheMembersRead: the manifest is the last member
// and is read as a stream, but its size still has to be bounded by what the
// archive actually holds — otherwise a tiny crafted archive can declare a
// gigabyte of member list (or of missing blob ids) and make `backup verify`
// allocate it. Unknown fields must be skipped rather than buffered, so a
// newer FileParcel's manifest still reads.
func TestManifestSizeIsBoundedByTheMembersRead(t *testing.T) {
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	ids := []age.Identity{id}
	hdr := testHeader(db.LatestVersion())
	good := validMembers(t, hdr, nil)
	var raw map[string]any
	if err := json.Unmarshal(good[len(good)-1].data, &raw); err != nil {
		t.Fatal(err)
	}
	withField := func(v any) []craftMember {
		raw["something_new"] = v
		b, err := json.Marshal(raw)
		if err != nil {
			t.Fatal(err)
		}
		out := append([]craftMember(nil), good...)
		out[len(out)-1] = craftMember{name: memberManifest, data: b}
		return out
	}
	// A four-member archive may not hand us an eight megabyte manifest.
	huge := withField(strings.Repeat("A", 8<<20))
	_, err = walkArchive(context.Background(), bytes.NewReader(craftArchive(t, id.Recipient(), huge)), ids, nil, nil)
	if !errors.Is(err, core.ErrCorrupt) || !strings.Contains(err.Error(), "too large") {
		t.Fatalf("oversized manifest: %v", err)
	}
	// A small unknown field is skipped: an archive from a newer version reads.
	ok := withField(map[string]any{"nested": []any{1, "two", nil, true}})
	if _, err := walkArchive(context.Background(), bytes.NewReader(craftArchive(t, id.Recipient(), ok)), ids, nil, nil); err != nil {
		t.Fatalf("unknown manifest field rejected: %v", err)
	}
}

// TestManifestWithManyMissingBlobsReads: blobs deleted while a full backup
// runs are listed in the manifest's missing_blobs, not archived. That list
// is not made of members, so a budget counted from the members alone
// refused the manifest of a backup that had lost some 30,000 blobs — an
// archive recorded "ready" that no verify, restore or import could read.
// Every missing id is a ready row of the archived database, so the database
// member bounds it; a tiny database still cannot carry a huge list.
func TestManifestWithManyMissingBlobsReads(t *testing.T) {
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	build := func(dbSize, missing int) []byte {
		t.Helper()
		var out bytes.Buffer
		aw, err := newArchiveWriter(context.Background(), &out, []age.Recipient{id.Recipient()}, time.Unix(1700000000, 0), t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		hdr := testHeader(db.LatestVersion())
		hdr.Scope = core.BackupFull
		hb, _ := json.Marshal(hdr)
		for _, m := range []struct {
			name string
			data []byte
		}{
			{memberHeader, hb},
			{memberDB, bytes.Repeat([]byte{'d'}, dbSize)},
			{memberConfig, []byte("install_id = \"x\"\n")},
			{memberMasterKy, []byte(`{"v":1}`)},
		} {
			if err := aw.addBytes(m.name, m.data); err != nil {
				t.Fatal(err)
			}
		}
		for i := range 3 {
			if err := aw.addBytes(blobMemberName(fmt.Sprintf("%032x", i)), []byte("blob")); err != nil {
				t.Fatal(err)
			}
		}
		m := &Manifest{Header: hdr}
		for i := range missing {
			m.MissingBlobs = append(m.MissingBlobs, fmt.Sprintf("%032x", 1_000_000+i))
		}
		if _, _, err := aw.finish(m); err != nil {
			t.Fatal(err)
		}
		return out.Bytes()
	}
	// 40,000 missing ids (1.4 MB of manifest) next to a database that holds
	// their rows (at least 64 bytes each).
	wr, err := walkArchive(context.Background(), bytes.NewReader(build(40_000*64, 40_000)), []age.Identity{id}, nil, nil)
	if err != nil {
		t.Fatalf("archive with many missing blobs rejected: %v", err)
	}
	if wr.MissingBlobs != 40_000 {
		t.Fatalf("missing blobs %d", wr.MissingBlobs)
	}
	// The same list next to a database of a few bytes is still refused.
	_, err = walkArchive(context.Background(), bytes.NewReader(build(16, 40_000)), []age.Identity{id}, nil, nil)
	if !errors.Is(err, core.ErrCorrupt) || !strings.Contains(err.Error(), "too large") {
		t.Fatalf("huge missing_blobs next to a tiny database: %v", err)
	}
}
