package core

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"testing"
)

// The Secret cases of zip-password-final §13.3: a password never reaches
// fmt or slog output, but JSON (the CLI's request body) carries it.
func TestSecretRedacted(t *testing.T) {
	const pw = "correct horse battery staple"
	s := Secret(pw)
	for _, verb := range []string{"%v", "%+v", "%#v", "%s", "%q", "%x", "%d"} {
		if got := fmt.Sprintf(verb, s); got != "[redacted]" {
			t.Errorf("Sprintf(%s) = %q", verb, got)
		}
	}
	if s.Reveal() != pw || fmt.Sprint(s) != "[redacted]" || fmt.Sprintln(s) != "[redacted]\n" {
		t.Fatal("Reveal / Sprint")
	}
	in := BatchInput{FolderID: "nod_1", Mode: UploadModeZip, ZipName: "Trip", ZipEncryption: ZipEncAES256, ZipPassword: s,
		Files: []UploadFileInput{{ClientRef: "a", RelPath: "a.jpg", Size: 1}, {ClientRef: "b", RelPath: "b.jpg", Size: 2}}}
	for _, verb := range []string{"%v", "%+v", "%#v"} {
		if out := fmt.Sprintf(verb, in); strings.Contains(out, pw) || !strings.Contains(out, "[redacted]") {
			t.Errorf("Sprintf(%s, BatchInput) = %s", verb, out)
		}
	}
	if out := fmt.Sprintf("%+v", &in); strings.Contains(out, pw) {
		t.Errorf("pointer: %s", out)
	}
	// JSON keeps the value: the CLI sends it in the request body.
	b, err := json.Marshal(in)
	if err != nil || !strings.Contains(string(b), `"zip_password":"`+pw+`"`) || !strings.Contains(string(b), `"zip_encryption":"aes256"`) {
		t.Fatalf("json: %s %v", b, err)
	}
	var back BatchInput
	if err := json.Unmarshal(b, &back); err != nil || back.ZipPassword.Reveal() != pw {
		t.Fatalf("json round trip: %v", err)
	}
	if b, _ := json.Marshal(BatchInput{}); strings.Contains(string(b), "zip_") {
		t.Fatalf("unset zip fields must be omitted: %s", b)
	}
	// slog: the Secret alone, and the whole batch (text and JSON handlers).
	for _, h := range []func(*bytes.Buffer) slog.Handler{
		func(w *bytes.Buffer) slog.Handler { return slog.NewTextHandler(w, nil) },
		func(w *bytes.Buffer) slog.Handler { return slog.NewJSONHandler(w, nil) },
	} {
		var buf bytes.Buffer
		l := slog.New(h(&buf))
		l.Info("create", "pw", s, "batch", in, "ptr", &in)
		out := buf.String()
		if strings.Contains(out, pw) {
			t.Fatalf("slog leaks the password: %s", out)
		}
		for _, want := range []string{"[redacted]", "zip_password_set", "nod_1", "zip_encryption"} {
			if !strings.Contains(out, want) {
				t.Errorf("slog output lacks %q: %s", want, out)
			}
		}
	}
	// LogValue: the files as a count, the password as a flag.
	attrs := map[string]slog.Value{}
	for _, a := range in.LogValue().Group() {
		attrs[a.Key] = a.Value
	}
	if attrs["files"].Int64() != 2 || !attrs["zip_password_set"].Bool() || attrs["zip_encryption"].String() != "aes256" ||
		attrs["mode"].String() != "zip" || attrs["folder_id"].String() != "nod_1" || attrs["zip_name"].String() != "Trip" {
		t.Fatalf("LogValue %v", attrs)
	}
	if _, ok := attrs["zip_password"]; ok {
		t.Fatal("LogValue has the password")
	}
	if (BatchInput{}).LogValue().Group()[7].Value.Bool() {
		t.Fatal("zip_password_set without a password")
	}
	// FileMeta.ZipEncryption never comes from (or goes to) JSON.
	var m FileMeta
	if err := json.Unmarshal([]byte(`{"mime":"application/zip","ZipEncryption":"aes256"}`), &m); err != nil || m.ZipEncryption != "" {
		t.Fatalf("FileMeta %+v %v", m, err)
	}
}
