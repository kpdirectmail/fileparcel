package cli

// Tests of "files put --zip" with a password (zip-password-final §9) and
// the Protection row of "files info", against the fake API.

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"fileparcel/internal/core"
)

// zipSource writes a small folder to upload.
func zipSource(t *testing.T) string {
	t.Helper()
	src := filepath.Join(t.TempDir(), "contracts")
	writeTree(t, src, map[string]int{"a.pdf": 10, "b/c.pdf": 20})
	return src
}

// batchInput decodes the last POST /upload-batches body.
func batchInput(t *testing.T, f *fakeAPI) (core.BatchInput, string) {
	t.Helper()
	raw := f.body("POST /api/v1/upload-batches")
	var in core.BatchInput
	if err := json.Unmarshal(raw, &in); err != nil {
		t.Fatalf("batch body %s: %v", raw, err)
	}
	return in, string(raw)
}

// onlyBatchCarries fails when any request body but the batch creation
// carries the password.
func onlyBatchCarries(t *testing.T, f *fakeAPI, pw string) {
	t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()
	for key, body := range f.bodies {
		if key != "POST /api/v1/upload-batches" && strings.Contains(string(body), pw) {
			t.Errorf("%s carries the password: %s", key, body)
		}
	}
}

func TestZipPasswordFlags(t *testing.T) {
	fastBackoff(t)
	f := newFakeAPI(t)
	src := zipSource(t)
	pwFile := filepath.Join(t.TempDir(), "pw")
	if err := os.WriteFile(pwFile, []byte("file-password-123\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	// Usage errors, before anything is sent.
	for _, tc := range []struct {
		args []string
		want string
	}{
		{[]string{"--zip-password-stdin"}, "--zip-password-stdin needs --zip NAME (a password protects the .zip that --zip builds)"},
		{[]string{"--zip-encryption", "zipcrypto"}, "--zip-encryption needs --zip NAME"},
		{[]string{"--zip", "x.zip", "--zip-encryption", "zipcrypto"}, "--zip-encryption needs a password flag"},
		{[]string{"--zip", "x.zip", "--zip-password-stdin", "--zip-generate-password"}, "use only one of"},
		{[]string{"--zip", "x.zip", "--zip-generate-password", "--zip-encryption", "des"}, "--zip-encryption must be aes256 or zipcrypto"},
		{[]string{"--zip", "x.zip", "--zip-password-stdin", "--passphrase-stdin"}, "cannot both read standard input"},
	} {
		before := len(f.requests)
		res := f.run(t, "pw-from-stdin-1\n", append([]string{"files", "put", src, "/My files"}, tc.args...)...)
		if res.code != ExitUsage || !strings.Contains(res.stderr, tc.want) || len(f.requests) != before {
			t.Errorf("%v: %+v", tc.args, res)
		}
	}

	// --zip-password-stdin: only the batch creation carries it, with aes256;
	// the output never shows it.
	res := f.run(t, "stdin-password-1\n", "--json", "files", "put", src, "/My files", "--zip", "c.zip", "--zip-password-stdin")
	if res.code != 0 || strings.Contains(res.stdout+res.stderr, "stdin-password-1") || strings.Contains(res.stdout, "zip_password") {
		t.Fatalf("--zip-password-stdin: %+v", res)
	}
	in, raw := batchInput(t, f)
	if in.ZipPassword.Reveal() != "stdin-password-1" || in.ZipEncryption != core.ZipEncAES256 || !strings.Contains(raw, `"zip_encryption":"aes256"`) {
		t.Fatalf("batch body %s", raw)
	}
	onlyBatchCarries(t, f, "stdin-password-1")
	var out map[string]any
	if json.Unmarshal([]byte(res.stdout), &out) != nil || out["zip_encryption"] != core.ZipEncAES256 {
		t.Errorf("--json output %s", res.stdout)
	}
	if n := f.lookup(f.myRoot(), "c.zip"); n == nil || n.ZipEncryption != core.ZipEncAES256 {
		t.Fatal("the protected zip was not created")
	}

	// --zip-password-file, and zipcrypto with its warning.
	res = f.run(t, "", "files", "put", src, "/My files", "--zip", "d.zip", "--zip-password-file", pwFile, "--zip-encryption", "ZipCrypto")
	if in, _ = batchInput(t, f); res.code != 0 || in.ZipPassword.Reveal() != "file-password-123" || in.ZipEncryption != core.ZipEncZipCrypto ||
		!strings.Contains(res.stderr, "ZipCrypto is weak") ||
		!strings.Contains(res.stdout, "as d.zip (password-protected, ZipCrypto, weak) into /My files") {
		t.Fatalf("--zip-password-file zipcrypto: %+v", res)
	}
	// --zip-password asks twice (a scripted terminal here).
	res = f.run(t, "typed-password-1\ntyped-password-1\n", "files", "put", src, "/My files", "--zip", "e.zip", "--zip-password")
	if in, _ = batchInput(t, f); res.code != 0 || in.ZipPassword.Reveal() != "typed-password-1" ||
		!strings.Contains(res.stdout, "(password-protected, AES-256)") || !strings.HasPrefix(res.stderr, "Zip password: \nRepeat: ") {
		t.Fatalf("--zip-password: %+v", res)
	}

	// Generated: 22 characters, printed once (stdout) before the upload; in
	// JSON mode only in the result.
	res = f.run(t, "", "files", "put", src, "/My files", "--zip", "g.zip", "--zip-generate-password")
	in, _ = batchInput(t, f)
	pw := in.ZipPassword.Reveal()
	if res.code != 0 || len(pw) != 22 || strings.Count(res.stdout, pw) != 1 || !strings.HasPrefix(res.stdout, "Zip password: "+pw+"\n") ||
		!strings.Contains(res.stderr, "shown only once; FileParcel does not keep it") {
		t.Fatalf("--zip-generate-password: %+v", res)
	}
	onlyBatchCarries(t, f, pw)
	res = f.run(t, "", "--json", "files", "put", src, "/My files", "--zip", "h.zip", "--zip-generate-password")
	var gen struct {
		ID          string `json:"id"`
		ZipPassword string `json:"zip_password"`
	}
	if in, _ = batchInput(t, f); res.code != 0 || json.Unmarshal([]byte(res.stdout), &gen) != nil || len(gen.ZipPassword) != 22 ||
		gen.ZipPassword != in.ZipPassword.Reveal() || gen.ID == "" || strings.Contains(res.stderr, gen.ZipPassword) {
		t.Fatalf("--zip-generate-password --json: %+v", res)
	}

	// The server's refusals.
	res = f.run(t, "short\n", "files", "put", src, "/My files", "--zip", "i.zip", "--zip-password-stdin")
	if res.code != ExitUsage || !strings.Contains(res.stderr, "zip password rejected by the server: the password must be at least 12") ||
		strings.Contains(res.stderr, "short\n") {
		t.Errorf("short password: %+v", res)
	}
	f.zipUnknown = true
	res = f.run(t, "old-server-pass-1\n", "files", "put", src, "/My files", "--zip", "j.zip", "--zip-password-stdin")
	if res.code != ExitFailure || !strings.Contains(res.stderr, "this server does not support password-protected .zip files (upgrade it)") {
		t.Errorf("old server: %+v", res)
	}
	f.zipUnknown = false
	if err := zipBatchError(&core.Error{Code: core.ErrInvalid.Code, Status: 422, Field: "zip_encryption", Message: "bad"}); err == nil ||
		err.Error() != "zip encryption rejected by the server: bad" {
		t.Errorf("zip_encryption refusal: %v", err)
	}

	// A failure after the complete call in JSON mode still tells the
	// generated password: the zip may be built anyway.
	f.zipJobStates = []string{core.JobFailed}
	res = f.run(t, "", "--json", "files", "put", src, "/My files", "--zip", "k.zip", "--zip-generate-password")
	in, _ = batchInput(t, f)
	if res.code != ExitFailure || !strings.Contains(res.stderr, "(the .zip may still be created; its password is "+in.ZipPassword.Reveal()+")") {
		t.Fatalf("late failure: %+v", res)
	}
	f.zipJobStates = nil
	// In human mode it was printed before the upload already.
	f.zipJobStates = []string{core.JobFailed}
	res = f.run(t, "", "files", "put", src, "/My files", "--zip", "l.zip", "--zip-generate-password")
	in, _ = batchInput(t, f)
	if res.code != ExitFailure || strings.Contains(res.stderr, in.ZipPassword.Reveal()) || strings.Count(res.stdout, in.ZipPassword.Reveal()) != 1 {
		t.Fatalf("late failure, human: %+v", res)
	}
	f.zipJobStates = nil

	// files info shows the protection.
	res = f.run(t, "", "files", "info", "/My files/d.zip")
	if res.code != 0 || !strings.Contains(res.stdout, "Protection:      password (ZipCrypto, weak)\n") {
		t.Fatalf("files info d.zip:\n%s", res.stdout)
	}
	if res := f.run(t, "", "files", "info", "/My files/c.zip"); !strings.Contains(res.stdout, "password (AES-256)") {
		t.Errorf("files info c.zip:\n%s", res.stdout)
	}
	f.addFile(f.myRoot(), "plain.zip", []byte("PK"))
	if res := f.run(t, "", "files", "info", "/My files/plain.zip"); res.code != 0 || strings.Contains(res.stdout, "Protection") {
		t.Errorf("an unprotected file has no protection row: %+v", res)
	}
}
