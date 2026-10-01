package cli

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/spf13/cobra"

	"fileparcel/internal/core"
	"fileparcel/internal/ids"
)

func TestParseExpiry(t *testing.T) {
	now := time.Date(2026, 9, 19, 12, 0, 0, 0, time.UTC)
	for _, tc := range []struct {
		in    string
		want  time.Duration // from now; -1 = nil
		never bool
		err   bool
	}{
		{in: "", want: -1},
		{in: "never", want: -1, never: true},
		{in: "NONE", want: -1, never: true},
		{in: "7d", want: 7 * 24 * time.Hour},
		{in: "12h", want: 12 * time.Hour},
		{in: "2w", want: 14 * 24 * time.Hour},
		{in: "1d12h", want: 36 * time.Hour},
		{in: "2026-09-20T12:00:00Z", want: 24 * time.Hour},
		{in: "2020-01-01T00:00:00Z", err: true},
		{in: "2020-01-01", err: true},
		{in: "soon", err: true},
		{in: "0s", err: true},
		{in: "-5h", err: true},
	} {
		got, never, err := parseExpiry(tc.in, now, true)
		switch {
		case tc.err:
			if err == nil {
				t.Errorf("%q: want error", tc.in)
			}
		case err != nil:
			t.Errorf("%q: %v", tc.in, err)
		case never != tc.never:
			t.Errorf("%q: never = %v", tc.in, never)
		case tc.want < 0 && got != nil:
			t.Errorf("%q: want nil, got %v", tc.in, got)
		case tc.want >= 0 && (got == nil || got.Sub(now) != tc.want):
			t.Errorf("%q: got %v", tc.in, got)
		}
	}
	// A date means the end of that local day.
	future := now.AddDate(0, 1, 0).Local().Format("2006-01-02")
	got, _, err := parseExpiry(future, now, true)
	if err != nil || got == nil || got.Local().Format("15:04:05") != "23:59:59" {
		t.Fatalf("date expiry %v %v", got, err)
	}
	// Where things must expire, "never" is a usage error that says so; the
	// other forms are unchanged.
	for _, in := range []string{"never", "NONE", "no"} {
		if _, _, err := parseExpiry(in, now, false); !isUsage(err) || !strings.Contains(err.Error(), "must expire") {
			t.Errorf("%q with allowNever=false: %v", in, err)
		}
	}
	if got, never, err := parseExpiry("7d", now, false); err != nil || never || got == nil {
		t.Errorf("7d with allowNever=false: %v %v %v", got, never, err)
	}
	if _, _, err := parseExpiry("soon", now, false); err == nil || strings.Contains(err.Error(), "never") {
		t.Errorf("the examples of a refused expiry must not offer never: %v", err)
	}
}

// isUsage reports whether err exits with the usage status.
func isUsage(err error) bool {
	var ee *ExitCodeError
	return errors.As(err, &ee) && ee.Code == ExitUsage
}

func TestParseUserQuotaRoleScopes(t *testing.T) {
	for in, want := range map[string]core.Opt[int64]{
		"default":   core.Null[int64](),
		"unlimited": core.Some[int64](0),
		"0":         core.Some[int64](0),
		"10G":       core.Some[int64](10 << 30),
		"500M":      core.Some[int64](500 << 20),
		"1.5GiB":    core.Some[int64](3 << 29),
	} {
		got, err := parseUserQuota(in)
		if err != nil || got != want {
			t.Errorf("parseUserQuota(%q) = %+v, %v", in, got, err)
		}
	}
	if _, err := parseUserQuota("lots"); err == nil {
		t.Error("parseUserQuota(lots) accepted")
	}
	if quotaText(nil) != "default" || quotaText(new(int64)) != "unlimited" {
		t.Error("quotaText")
	}
	// Built-in words resolve without a request (the client is not used).
	for _, r := range []string{"owner", "ADMIN", " member ", "guest"} {
		if ref, err := resolveRole(context.Background(), nil, r); err != nil || !ref.Builtin ||
			ref.ID != strings.ToLower(strings.TrimSpace(r)) {
			t.Errorf("resolveRole(%q): %+v, %v", r, ref, err)
		}
	}
	if _, err := resolveRole(context.Background(), nil, " "); err == nil {
		t.Error("resolveRole of an empty name accepted")
	}
	got, err := parseScopes([]string{"files:read, files:write", "SHARES", "files:read"})
	if err != nil || strings.Join(got, ",") != "files:read,files:write,shares" {
		t.Errorf("parseScopes: %v %v", got, err)
	}
	for _, bad := range [][]string{nil, {""}, {"elevated"}, {"files:delete"}} {
		if _, err := parseScopes(bad); err == nil {
			t.Errorf("parseScopes(%v) accepted", bad)
		}
	}
}

func TestParseSettingValue(t *testing.T) {
	for _, tc := range []struct{ typ, in, want string }{
		{"int", "30", "30"},
		{"int", " 7 ", "7"},
		{"bool", "yes", "true"},
		{"bool", "OFF", "false"},
		{"bool", "true", "true"},
		{"string", "Family Files", `"Family Files"`},
		{"string", ` padded `, `" padded "`},
		{"string", `"quoted"`, `"quoted"`},
		{"string", "123", `"123"`},
		{"enum", " allowlist ", `"allowlist"`},
		{"duration", "15m", `"15m"`},
		{"cron", "0 3 * * *", `"0 3 * * *"`},
		{"strings", "a, b,,c", `["a","b","c"]`},
		{"strings", `["x","y"]`, `["x","y"]`},
		{"strings", "", `[]`},
		{"cidrs", "192.168.1.0/24,100.64.0.0/10", `["192.168.1.0/24","100.64.0.0/10"]`},
		{"", "42", "42"},
		{"", `{"a":1}`, `{"a":1}`},
		{"", "plain text", `"plain text"`},
		{"url", "https://x.example", `"https://x.example"`},
	} {
		got, err := parseSettingValue(tc.typ, tc.in)
		if err != nil || string(got) != tc.want {
			t.Errorf("parseSettingValue(%q, %q) = %s, %v; want %s", tc.typ, tc.in, got, err, tc.want)
		}
	}
	for _, tc := range []struct{ typ, in string }{{"int", "3.5"}, {"int", "x"}, {"bool", "maybe"}, {"strings", `["a",1]`}} {
		if _, err := parseSettingValue(tc.typ, tc.in); err == nil {
			t.Errorf("parseSettingValue(%q, %q) accepted", tc.typ, tc.in)
		}
	}
	for raw, want := range map[string]string{`"x"`: "x", `""`: `""`, `["a","b"]`: "a,b", `[]`: "[]", `7`: "7", `null`: "",
		`{"a": 1}`: `{"a":1}`, `true`: "true"} {
		if got := jsonText(json.RawMessage(raw)); got != want {
			t.Errorf("jsonText(%s) = %q, want %q", raw, got, want)
		}
	}
	sec := &core.SettingView{Secret: true, IsSet: true}
	if settingValueText(sec) != "(set)" {
		t.Error("secret masking")
	}
}

func TestNetworkHelpers(t *testing.T) {
	for in, want := range map[string]string{
		"192.168.1.0/24": "192.168.1.0/24", "192.168.1.77/24": "192.168.1.0/24", " 10.0.0.1 ": "10.0.0.1",
		"fd7a:115c:a1e0::/48": "fd7a:115c:a1e0::/48", "::1": "::1",
	} {
		if got, err := normalizeCIDR(in); err != nil || got != want {
			t.Errorf("normalizeCIDR(%q) = %q, %v", in, got, err)
		}
	}
	for _, bad := range []string{"", "300.1.1.1", "10.0.0.0/33", "example.com"} {
		if _, err := normalizeCIDR(bad); err == nil {
			t.Errorf("normalizeCIDR(%q) accepted", bad)
		}
	}
	if !samePrefix("192.168.1.0/24", "192.168.1.9/24") || samePrefix("10.0.0.0/8", "10.0.0.0/16") {
		t.Error("samePrefix")
	}
	for _, ok := range []string{"files.example.lan", "*.example.com", "10.8.0.1", "::1", "a-b.c", "FILES.LOCAL."} {
		if !validSAN(ok) {
			t.Errorf("validSAN(%q) = false", ok)
		}
	}
	for _, bad := range []string{"", "-a.com", "a_b.com", "a..b", "x y", strings.Repeat("a", 64) + ".com"} {
		if validSAN(bad) {
			t.Errorf("validSAN(%q) = true", bad)
		}
	}
}

func TestParseTimeFlag(t *testing.T) {
	now := time.Date(2026, 9, 19, 12, 0, 0, 0, time.UTC)
	if got, err := parseTimeFlag("since", "24h", now); err != nil || !got.Equal(now.Add(-24*time.Hour)) {
		t.Errorf("24h: %v %v", got, err)
	}
	if got, err := parseTimeFlag("since", "7d", now); err != nil || !got.Equal(now.Add(-7*24*time.Hour)) {
		t.Errorf("7d: %v %v", got, err)
	}
	if got, err := parseTimeFlag("since", "2026-09-01T00:00:00Z", now); err != nil || got.Day() != 1 {
		t.Errorf("rfc3339: %v %v", got, err)
	}
	if got, err := parseTimeFlag("since", "", now); err != nil || got != nil {
		t.Errorf("empty: %v %v", got, err)
	}
	if _, err := parseTimeFlag("since", "yesterday", now); err == nil {
		t.Error("yesterday accepted")
	}
}

func TestAgeIdentityAndCAFingerprint(t *testing.T) {
	id := "AGE-SECRET-KEY-1QQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQ"
	got, err := parseAgeIdentity(strings.NewReader("# created: 2026\n# public key: age1xyz\n\n  "+id+"\n"), "f")
	if err != nil || got != id {
		t.Fatalf("parseAgeIdentity: %q %v", got, err)
	}
	if _, err := parseAgeIdentity(strings.NewReader("age1public\n"), "f"); err == nil {
		t.Fatal("a recipient is not an identity")
	}
	// The file "backup identity generate" prints: the new identity, then the
	// previous ones for older backups. Every one of them is passed on.
	prev := "AGE-SECRET-KEY-1PPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPP"
	got, err = parseAgeIdentity(strings.NewReader("# FileParcel backup identity\n"+id+"\n# previous identities (decrypt older backups only)\n"+prev+"\n"), "f")
	if err != nil || got != id+"\n"+prev {
		t.Fatalf("identity file with a previous identity: %q %v", got, err)
	}

	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Test CA"}, NotBefore: time.Now(),
		NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	pemData := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	fp, err := caFingerprint(pemData)
	sum := sha256.Sum256(der)
	if err != nil || fp != colonHex(sum[:]) || len(fp) != 95 || strings.ToUpper(fp) != fp {
		t.Fatalf("fingerprint %q %v", fp, err)
	}
	if _, err := caFingerprint([]byte("junk")); err == nil {
		t.Fatal("junk accepted")
	}
	if colonHex([]byte{0xab, 0x01}) != "AB:01" {
		t.Fatal("colonHex")
	}
}

func TestTrustInstructions(t *testing.T) {
	tc := trustContext{Origin: "https://fileparcel.local:8443", Fingerprint: "AB:CD"}
	for _, o := range trustOSes {
		s := trustInstructions(o, tc)
		if s == "" || trustTitle(o) == "" || !strings.Contains(s, "https://fileparcel.local:8443/trust") {
			t.Errorf("%s: %q", o, s)
		}
	}
	for o, want := range map[string]string{
		"ios": "Certificate Trust Settings", "android": "CA certificate", "macos": "Always Trust",
		"windows": "certutil -addstore", "linux": "update-ca-certificates", "firefox": "Authorities",
	} {
		if !strings.Contains(trustInstructions(o, tc), want) {
			t.Errorf("%s instructions lack %q", o, want)
		}
	}
	// Linux tools need the PEM form.
	if !strings.Contains(trustInstructions("linux", tc), "/trust/ca.pem") {
		t.Error("linux must download the PEM certificate")
	}
	if !strings.Contains(trustInstructions("ios", trustContext{}), "https://<server>:8443") {
		t.Error("placeholder origin")
	}
	res := runArgs(t, "", "--home", t.TempDir(), "ca", "trust-help", "--os", "mac")
	if res.code != 0 || !strings.Contains(res.stdout, "macOS") || strings.Contains(res.stdout, "Windows") {
		t.Fatalf("trust-help --os mac: %+v", res)
	}
	res = runArgs(t, "", "--home", t.TempDir(), "--json", "ca", "trust-help")
	var out struct {
		Instructions map[string]string `json:"instructions"`
	}
	if res.code != 0 || json.Unmarshal([]byte(res.stdout), &out) != nil || len(out.Instructions) != len(trustOSes) {
		t.Fatalf("trust-help --json: %+v", res)
	}
	if res := runArgs(t, "", "ca", "trust-help", "--os", "beos"); res.code != ExitUsage {
		t.Fatalf("bad os: %+v", res)
	}
}

func TestKeyVerifyChecks(t *testing.T) {
	good := &core.KeyStatus{State: core.KeyStateUnlocked, Mode: core.KeyModeSealed, RecoveryConfigured: true, KEKs: []core.KEKInfo{
		{ID: "kek_1", Purpose: core.KEKBlob, State: core.KEKActive}, {ID: "kek_2", Purpose: core.KEKField, State: core.KEKActive},
		{ID: "kek_3", Purpose: core.KEKMAC, State: core.KEKActive}, {ID: "kek_0", Purpose: core.KEKBlob, State: core.KEKRetired},
	}}
	for _, c := range verifyKeyStatus(good) {
		if !c.OK {
			t.Errorf("good status: %+v", c)
		}
	}
	bad := *good
	bad.RecoveryConfigured = false
	bad.KEKs = append([]core.KEKInfo{{ID: "kek_9", Purpose: core.KEKField, State: core.KEKRetired, Refs: 3}}, good.KEKs[:2]...)
	failed := map[string]bool{}
	for _, c := range verifyKeyStatus(&bad) {
		if !c.OK {
			failed[c.Check] = true
		}
	}
	for _, want := range []string{"one active mac KEK", "no retired KEK still in use", "recovery key configured"} {
		if !failed[want] {
			t.Errorf("check %q should fail (%v)", want, failed)
		}
	}
}

func TestDecodeListAndQuery(t *testing.T) {
	items, next, err := decodeList[int](json.RawMessage(`{"items":[1,2],"next_cursor":"c2"}`))
	if err != nil || len(items) != 2 || next != "c2" {
		t.Fatalf("page: %v %v %v", items, next, err)
	}
	items, next, err = decodeList[int](json.RawMessage(` [3] `))
	if err != nil || len(items) != 1 || next != "" {
		t.Fatalf("array: %v %v", items, err)
	}
	if items, _, err := decodeList[int](json.RawMessage(`null`)); err != nil || items != nil {
		t.Fatalf("null: %v %v", items, err)
	}
	if _, _, err := decodeList[int](json.RawMessage(`{"items":"x"}`)); err == nil {
		t.Fatal("bad page accepted")
	}
	if got := api("/admin/users", "q", "a b", "role", "", "limit", "5"); got != "/api/v1/admin/users?limit=5&q=a+b" {
		t.Fatalf("api() = %q", got)
	}
	if got := withQuery("/x?a=1", "b", "2"); got != "/x?a=1&b=2" {
		t.Fatalf("withQuery = %q", got)
	}
	if limitParam(0) != "500" || limitParam(10) != "10" || limitParam(9999) != "500" {
		t.Fatal("limitParam")
	}
	if jobResultBackupID(json.RawMessage(`{"backup_id":"bak_x"}`)) != "bak_x" ||
		jobResultBackupID(json.RawMessage(`{"backup":{"id":"bak_y"}}`)) != "bak_y" ||
		jobResultBackupID(json.RawMessage(`{"id":"`+ids.New(ids.PrefixBackup)+`"}`)) == "" ||
		jobResultBackupID(json.RawMessage(`{"id":"job_z"}`)) != "" || jobResultBackupID(nil) != "" {
		t.Fatal("jobResultBackupID")
	}
	if jobRefFrom(json.RawMessage(`{"job_id":"job_1"}`)) != "job_1" || jobRefFrom(json.RawMessage(`{"state":"x"}`)) != "" {
		t.Fatal("jobRefFrom")
	}
}

func TestExplainError(t *testing.T) {
	G = Globals{}
	for code, want := range map[string]string{
		core.ErrElevationRequired.Code: "admin socket is always elevated",
		core.ErrKeysLocked.Code:        "fileparcel keys unlock",
		core.ErrQuota.Code:             "user set-quota",
		core.ErrCorrupt.Code:           "doctor",
		core.ErrRateLimited.Code:       "wait a minute",
	} {
		err := explainError(&core.Error{Code: code, Status: 400, Message: "m"})
		if !strings.Contains(err.Error(), want) || !strings.Contains(err.Error(), "hint:") {
			t.Errorf("%s: %v", code, err)
		}
		if ce := core.AsError(err); ce == nil || ce.Code != code {
			t.Errorf("%s: code lost through the hint wrapper", code)
		}
	}
	// Space held by unfinished uploads (a killed upload keeps its reservation): the hint says how to free it.
	if err := explainError(&core.Error{Code: core.ErrQuota.Code, Status: 413, Message: "not enough storage space: the upload " +
		"needs 286.1 MiB, 165.7 MiB are available (unfinished uploads hold 858.3 MiB until they finish, are cancelled or expire)"}); !strings.Contains(err.Error(), "cancel the unfinished uploads") {
		t.Errorf("reserved quota: %v", err)
	}
	plain := &core.Error{Code: core.ErrNotFound.Code, Message: "nope"}
	if err := explainError(plain); err != error(plain) {
		t.Errorf("not_found must stay unchanged: %v", err)
	}
	if err := explainError(core.ErrUnauthorized); strings.Contains(err.Error(), "hint") {
		t.Errorf("unauthorized locally needs no token hint: %v", err)
	}
	G.Server = "https://x"
	if err := explainError(core.ErrUnauthorized); !strings.Contains(err.Error(), "API token") {
		t.Errorf("remote unauthorized: %v", err)
	}
	G = Globals{}
	if err := explainError(ErrNotInteractive); !strings.Contains(err.Error(), "-y/--yes") || !errors.Is(err, ErrNotInteractive) {
		t.Errorf("not interactive: %v", err)
	}
	usage := UsageError("bad")
	if explainError(usage) != usage || explainError(nil) != nil {
		t.Error("usage errors and nil pass through")
	}

	// isRetryable.
	for err, want := range map[error]bool{
		core.ErrUnavailable: true, core.ErrRateLimited: true, core.ErrInternal: true, errors.New("connection reset"): true,
		core.ErrQuota: false, core.ErrKeysLocked: false, core.ErrCorrupt: false, core.ErrNotImplemented: false,
		core.ErrNotFound: false, core.ErrConflict: false, fatalf("changed"): false, nil: false,
		UsageError("x"): false, fmt.Errorf("wrapped: %w", core.ErrUnavailable): true,
	} {
		if got := isRetryable(err); got != want {
			t.Errorf("isRetryable(%v) = %v", err, got)
		}
	}
}

func TestDecodeIssued(t *testing.T) {
	p12 := []byte{0x30, 0x82, 0x01, 0x02}
	for _, tc := range []struct {
		name, ctype, body string
		hdr               map[string]string
		wantID, wantPW    string
	}{
		{name: "securityapi shape", ctype: "application/json",
			body:   `{"client_cert":{"id":"ccr_1","name":"x"},"p12":"MIIBAg==","password":"pw1","filename":"a.p12","download_url":"/x"}`,
			wantID: "ccr_1", wantPW: "pw1"},
		{name: "alt keys", ctype: "application/json; charset=utf-8", body: `{"cert":{"id":"ccr_2"},"p12_base64":"MIIBAg"}`, wantID: "ccr_2"},
		{name: "raw", ctype: "application/x-pkcs12", body: string(p12), hdr: map[string]string{"X-FP-Cert-ID": "ccr_3", "X-FP-P12-Password": "pw3"},
			wantID: "ccr_3", wantPW: "pw3"},
	} {
		resp := &http.Response{Header: http.Header{"Content-Type": {tc.ctype}}, Body: io.NopCloser(strings.NewReader(tc.body))}
		for k, v := range tc.hdr {
			resp.Header.Set(k, v)
		}
		got, err := decodeIssued(resp)
		if err != nil || !bytes.Equal(got.P12, p12) || got.Cert == nil || got.Cert.ID != tc.wantID || got.Password != tc.wantPW {
			t.Errorf("%s: %+v %v", tc.name, got, err)
		}
	}
	resp := &http.Response{Header: http.Header{"Content-Type": {"application/json"}}, Body: io.NopCloser(strings.NewReader(`{"client_cert":{"id":"x"}}`))}
	if _, err := decodeIssued(resp); err == nil {
		t.Error("missing p12 accepted")
	}
	if safeFileName("Alice's phone / 2") != "Alice-s-phone-2" || safeFileName("...") != "client" {
		t.Errorf("safeFileName %q", safeFileName("Alice's phone / 2"))
	}
}

func TestShareUpdateFromFlags(t *testing.T) {
	build := func(args ...string) (core.ShareUpdate, bool, error) {
		var got core.ShareUpdate
		var changed bool
		var gerr error
		cmd := newShareEditCmd()
		cmd.RunE = func(c *cobra.Command, _ []string) error {
			f := c.Flags()
			str := func(n string) string { v, _ := f.GetString(n); return v }
			bl := func(n string) bool { v, _ := f.GetBool(n); return v }
			got, changed, gerr = shareUpdateFromFlags(c, shareFlagValues{
				title: str("title"), message: str("message"), expires: str("expires"), maxDownloads: str("max-downloads"),
				download: bl("download"), preview: bl("preview"), upload: bl("upload"), notify: bl("notify"),
				disable: bl("disable"), enable: bl("enable"), noPassword: bl("no-password"),
				password: &secretInput{Stdin: bl("password-stdin"), File: str("password-file"), Prompt: bl("password"),
					name: "password", what: "link password"},
			})
			return nil
		}
		cmd.SetArgs(append([]string{"shr_x"}, args...))
		cmd.SetIn(strings.NewReader("secret-pass\n"))
		cmd.SetOut(io.Discard)
		cmd.SetErr(io.Discard)
		if err := cmd.Execute(); err != nil {
			return got, false, err
		}
		return got, changed, gerr
	}
	in, changed, err := build("--download=false", "--max-downloads", "none", "--expires", "never", "--title", "T")
	if err != nil || !changed || in.AllowDownload == nil || *in.AllowDownload || !in.MaxDownloads.Null || !in.ExpiresAt.Null ||
		in.Title == nil || *in.Title != "T" || in.AllowPreview != nil {
		t.Fatalf("update %+v %v %v", in, changed, err)
	}
	body, _ := json.Marshal(in)
	if !strings.Contains(string(body), `"max_downloads":null`) || strings.Contains(string(body), "upload_quota_bytes") {
		t.Fatalf("PATCH body %s", body)
	}
	in, _, err = build("--max-downloads", "5", "--disable", "--password-stdin")
	if err != nil || in.MaxDownloads.V != 5 || in.Disabled == nil || !*in.Disabled || in.Password == nil || *in.Password != "secret-pass" {
		t.Fatalf("update2 %+v %v", in, err)
	}
	in, _, err = build("--no-password")
	if err != nil || in.Password == nil || *in.Password != "" {
		t.Fatalf("no-password %+v %v", in, err)
	}
	if _, changed, err := build(); err != nil || changed {
		t.Fatalf("no flags: changed=%v %v", changed, err)
	}
	for _, bad := range [][]string{{"--max-downloads", "0"}, {"--disable", "--enable"}, {"--no-password", "--password-stdin"}, {"--expires", "x"}} {
		if _, _, err := build(bad...); err == nil {
			t.Errorf("%v accepted", bad)
		}
	}
}

func TestSecretFrom(t *testing.T) {
	cmd := &cobra.Command{}
	cmd.SetIn(strings.NewReader("pw-from-stdin\nignored\n"))
	if s, err := secretFrom(cmd, true, "", "password", true); err != nil || s != "pw-from-stdin" {
		t.Fatalf("stdin: %q %v", s, err)
	}
	if _, err := secretFrom(cmd, true, "x", "password", false); err == nil {
		t.Fatal("stdin and file together accepted")
	}
	cmd.SetIn(strings.NewReader("new1\nnew1\n"))
	cmd.SetErr(io.Discard)
	if s, err := secretFrom(cmd, false, "", "password", true); err != nil || s != "new1" {
		t.Fatalf("prompt twice: %q %v", s, err)
	}
}
