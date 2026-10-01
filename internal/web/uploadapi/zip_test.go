package uploadapi

import (
	"bytes"
	"io"
	"net/http"
	"strings"
	"testing"

	"fileparcel/internal/core"
)

// TestProtectedZipOverHTTP pins the HTTP surface of password-protected
// zips: the password goes in once and never comes back, the zip fields are
// validated at creation, unknown fields are still refused, and a batch whose
// sealed password is gone cannot be completed.
func TestProtectedZipOverHTTP(t *testing.T) {
	f := setup(t)
	const pw = "correct horse battery staple"
	body := func(extra string) io.Reader {
		return strings.NewReader(`{"folder_id":"` + f.root + `","mode":"zip","zip_name":"Q3",` +
			`"files":[{"client_ref":"a","rel_path":"a.txt","size":1}]` + extra + `}`)
	}
	hdr := map[string]string{"Content-Type": "application/json"}

	var b core.UploadBatch
	resp := f.do("POST", "/api/v1/upload-batches", f.alice, body(`,"zip_encryption":"aes256","zip_password":"`+pw+`"`), hdr, &b)
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusCreated || b.ZipEncryption != core.ZipEncAES256 {
		t.Fatalf("create: %d %s", resp.StatusCode, raw)
	}
	if bytes.Contains(raw, []byte(pw)) || bytes.Contains(raw, []byte("zip_password")) {
		t.Fatalf("the answer carries the password: %s", raw)
	}
	var got core.UploadBatch
	resp = f.do("GET", "/api/v1/upload-batches/"+b.ID, f.alice, nil, nil, &got)
	raw, _ = io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK || got.ZipEncryption != core.ZipEncAES256 || bytes.Contains(raw, []byte(pw)) {
		t.Fatalf("get: %d %s", resp.StatusCode, raw)
	}

	// A password alone means AES-256.
	resp = f.do("POST", "/api/v1/upload-batches", f.alice, body(`,"zip_password":"`+pw+`"`), hdr, &b)
	if resp.StatusCode != http.StatusCreated || b.ZipEncryption != core.ZipEncAES256 {
		t.Fatalf("password only: %d %+v", resp.StatusCode, b)
	}

	// Refusals: the rules (422 on the field), unknown fields as before.
	for _, c := range []struct{ extra, field string }{
		{`,"zip_password":"short"`, "zip_password"},
		{`,"zip_encryption":"aes128","zip_password":"` + pw + `"`, "zip_encryption"},
		{`,"zip_encryption":"zipcrypto"`, "zip_password"},
		{`,"zip_passphrase":"` + pw + `"`, ""},
	} {
		var e apiErr
		resp := f.do("POST", "/api/v1/upload-batches", f.alice, body(c.extra), hdr, &e)
		if resp.StatusCode != http.StatusUnprocessableEntity || e.Error.Code != "invalid" ||
			(c.field != "" && e.Error.Field != c.field) {
			t.Fatalf("%s: %d %+v", c.extra, resp.StatusCode, e.Error)
		}
		if strings.Contains(e.Error.Message, pw) {
			t.Fatalf("%s: the message contains the password", c.extra)
		}
	}

	// Complete: a batch whose sealed password is gone stays open (412).
	put := f.do("PUT", "/api/v1/upload-batches/"+b.ID+"/small?ref=a", f.alice, strings.NewReader("a"),
		map[string]string{HeaderSHA256: sum([]byte("a"))}, nil)
	if put.StatusCode != http.StatusOK {
		t.Fatalf("small: %d", put.StatusCode)
	}
	f.Exec(`UPDATE upload_batches SET zip_password_enc = NULL WHERE id = ?`, b.ID)
	f.wantErr(f.do("POST", "/api/v1/upload-batches/"+b.ID+"/complete", f.alice, nil, nil, nil),
		http.StatusPreconditionFailed, "precondition_failed")
	f.Exec(`UPDATE upload_batches SET zip_password_enc = 'v1:x:00' WHERE id = ?`, b.ID)
	f.wantErr(f.do("POST", "/api/v1/upload-batches/"+b.ID+"/complete", f.alice, nil, nil, nil),
		http.StatusInternalServerError, "corrupt")
	if st := f.Str(`SELECT state FROM upload_batches WHERE id = ?`, b.ID); st != core.BatchOpen {
		t.Fatalf("state %s", st)
	}
}
