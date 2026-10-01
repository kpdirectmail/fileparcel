// Package docs_test pins statements the prose documentation makes about the
// encryption-at-rest design against the code that implements it.
//
// The generated parts of docs/COMMANDS.md and docs/FILEPARCEL.md are covered
// by scripts/gen-cli-docs.sh --check and scripts/gen-settings-docs.sh --check.
// Everything here is hand-written prose in docs/DESIGN.md,
// docs/ENCRYPTION.md and docs/FILEPARCEL.md, which nothing else checks: a
// wrong bound or a rotation that no longer asks for what the manual says it
// asks for is only found by reading both sides, so the interesting facts are
// derived from the code here and looked up in the documents.
package docs_test

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"fileparcel/internal/core"
	"fileparcel/internal/crypt"
)

// repoRoot walks up from the test's directory to the module root.
func repoRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("go.mod not found above the test directory")
		}
		dir = parent
	}
}

func read(t *testing.T, rel string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(repoRoot(t), rel))
	if err != nil {
		t.Fatalf("read %s: %v", rel, err)
	}
	return string(b)
}

// mustContain fails when doc does not contain want.
func mustContain(t *testing.T, name, doc, want, why string) {
	t.Helper()
	if !strings.Contains(doc, want) {
		t.Errorf("%s does not say %q\n%s", name, want, why)
	}
}

// mustNotContain fails when doc still contains bad.
func mustNotContain(t *testing.T, name, doc, bad, why string) {
	t.Helper()
	if strings.Contains(doc, bad) {
		t.Errorf("%s still says %q\n%s", name, bad, why)
	}
}

// TestKeyFileKDFBoundDocumented: the upper bound docs/ENCRYPTION.md gives for
// the argon2 memory of a key file must be the bound internal/keys enforces,
// which is the process-wide argon2 budget (crypt.Argon2BudgetKiB). An admin
// who edits keys/master.key to a documented-but-rejected m_kib ends up with a
// server that cannot start.
func TestKeyFileKDFBoundDocumented(t *testing.T) {
	// The same constant internal/keys uses for maxKDFMKiB.
	const kiBPerMiB = 1024
	wantMiB := crypt.Argon2BudgetKiB / kiBPerMiB
	want := fmt.Sprintf("m ≤ %d MiB", wantMiB)

	enc := read(t, "docs/ENCRYPTION.md")
	mustContain(t, "docs/ENCRYPTION.md", enc, want,
		"internal/keys/keyfile.go bounds a key file's argon2 memory by crypt.Argon2BudgetKiB;\n"+
			"a larger documented bound invites an unstartable server.")
	// Guard against the bound drifting back to a figure the code rejects.
	for _, bad := range []string{"m ≤ 2 GiB", "m ≤ 1 GiB", "m ≤ 512 MiB"} {
		mustNotContain(t, "docs/ENCRYPTION.md", enc, bad,
			"the enforced bound is crypt.Argon2BudgetKiB = "+fmt.Sprint(wantMiB)+" MiB.")
	}
	// DESIGN.md states the same budget in §18.12; keep the two in step.
	mustContain(t, "docs/DESIGN.md", read(t, "docs/DESIGN.md"),
		fmt.Sprintf("%d MiB process-wide budget", wantMiB),
		"DESIGN and ENCRYPTION must agree on the argon2 budget.")
}

// TestEscrowDocumented: keys/master.key carries an `escrow` object whose
// contents decide whether a master rotation can keep the passphrase and the
// recovery key. As long as internal/keys writes it, the design documents must
// describe it -- an operator cannot reason about a field no document mentions.
func TestEscrowDocumented(t *testing.T) {
	code := read(t, "internal/keys/keyfile.go")
	const aadPrefix = "fp-mk-escrow|"
	if !strings.Contains(code, aadPrefix) {
		t.Skipf("internal/keys no longer writes an escrow object (%q gone); drop this test with it", aadPrefix)
	}
	for _, doc := range []string{"docs/DESIGN.md", "docs/ENCRYPTION.md"} {
		// As rendered: a pipe in a table's code span is written \| (TestTableCodeSpansEscapePipes).
		body := strings.ReplaceAll(read(t, doc), `\|`, "|")
		mustContain(t, doc, body, "escrow",
			"internal/keys/keyfile.go writes an `escrow` object into keys/master.key.")
		for _, what := range []string{"pass", "recovery"} {
			mustContain(t, doc, body, aadPrefix+what+"|",
				"the escrow AADs are part of the on-disk format and must be documented.")
		}
	}
}

// TestMasterRotationPassphrase: core.Keys.RotateMaster takes no passphrase and
// the CLI help says the passphrase stays, so no document may promise that the
// rotation asks for it.
func TestMasterRotationPassphrase(t *testing.T) {
	m, ok := reflect.TypeOf((*core.Keys)(nil)).Elem().MethodByName("RotateMaster")
	if !ok {
		t.Fatal("core.Keys has no RotateMaster")
	}
	// An interface method type has no receiver: in(0) is the context.
	if got := m.Type.NumIn(); got != 1 || m.Type.In(0) != reflect.TypeOf((*context.Context)(nil)).Elem() {
		t.Fatalf("RotateMaster%v: this test assumes RotateMaster(ctx) only; "+
			"if it now takes a passphrase, the documents below may say so again", m.Type)
	}
	for _, doc := range []string{"docs/DESIGN.md", "docs/ENCRYPTION.md", "docs/FILEPARCEL.md"} {
		body := read(t, doc)
		for _, bad := range []string{
			"sealed mode needs the passphrase",
			"sealed: asks the passphrase",
			"asks for the passphrase",
		} {
			mustNotContain(t, doc, body, bad,
				"core.Keys.RotateMaster(ctx) takes no passphrase and never prompts;\n"+
					"it re-seals MK2 under the escrowed passphrase key instead.")
		}
	}
}

// TestNextRecoveryUsesMKID: internal/keys/rotate.go picks up an interrupted
// master rotation by comparing mk_id, not meta.mk_check -- mk_check is
// HMAC(MK, ...) and cannot be computed for a sealed file without the
// passphrase, so the documented algorithm has to be the implementable one.
func TestNextRecoveryUsesMKID(t *testing.T) {
	code := read(t, "internal/keys/rotate.go")
	if !strings.Contains(code, "kf.MKID == metaID") {
		t.Fatal("internal/keys/rotate.go no longer selects master.key.next by mk_id; " +
			"re-check what docs/DESIGN.md §7.6 and docs/ENCRYPTION.md §9 should say")
	}
	for _, doc := range []string{"docs/DESIGN.md", "docs/ENCRYPTION.md"} {
		body := read(t, doc)
		mustNotContain(t, doc, body, "matches `meta.mk_check`",
			"recoverNext compares mk_id; mk_check needs the MK, which a sealed .next does not give up.")
		mustNotContain(t, doc, body, "file matches `meta.mk_check` is kept",
			"recoverNext compares mk_id, not mk_check.")
		mustContain(t, doc, body, "`mk_id` equals `meta.mk_id`",
			"the crash-recovery rule for master.key.next is an mk_id comparison.")
	}
}

// TestMetadataOnlyScope: --metadata-only keeps the blobs but still replaces
// keys/, certs/ and fileparcel.toml (internal/backup/restore.go: MetadataOnly
// only sets skipBlobs, and swapIn moves every restoredItem aside). The manual
// must not promise that only the database is touched.
//
// This covers the hand-written manual. The same sentence in the generated CLI
// reference comes from the cobra long help in internal/cli/cmd_restore.go and
// is checked by scripts/gen-cli-docs.sh --check once that help is corrected.
func TestMetadataOnlyScope(t *testing.T) {
	restore := read(t, "internal/backup/restore.go")
	if !strings.Contains(restore, "skipBlobs := o.MetadataOnly || o.DryRun") {
		t.Fatal("internal/backup/restore.go no longer derives skipBlobs from MetadataOnly alone; " +
			"re-check what the manual should say about --metadata-only")
	}
	prose := manualProse(t)
	mustNotContain(t, "docs/FILEPARCEL.md (prose)", prose, "`--metadata-only` restores only\n  the database",
		"a metadata-only restore also replaces keys/, certs/ and fileparcel.toml.")
	mustContain(t, "docs/FILEPARCEL.md (prose)", prose,
		"`--metadata-only` restores the\n  database, the keys, the certificates and the configuration, keeping the current file data",
		"the flag's real scope: everything but the blobs.")
}
