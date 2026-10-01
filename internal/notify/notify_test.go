package notify

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"mime"
	"mime/quotedprintable"
	"net"
	"net/mail"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"fileparcel/internal/core"
)

// ---------- fakes ----------

type fakeSettings struct {
	core.Settings
	mu sync.Mutex
	m  map[string]any
}

func (f *fakeSettings) get(k string) any {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.m[k]
}
func (f *fakeSettings) set(k string, v any) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.m[k] = v
}
func (f *fakeSettings) Int(k string) int64 {
	switch v := f.get(k).(type) {
	case int:
		return int64(v)
	case int64:
		return v
	}
	return 0
}
func (f *fakeSettings) Bool(k string) bool        { b, _ := f.get(k).(bool); return b }
func (f *fakeSettings) String(k string) string    { s, _ := f.get(k).(string); return s }
func (f *fakeSettings) Strings(k string) []string { s, _ := f.get(k).([]string); return s }
func (f *fakeSettings) Secret(k string) (string, error) {
	if f.get("fail_secret") != nil {
		return "", core.ErrKeysLocked
	}
	return f.String(k), nil
}

// smtpServer is a minimal SMTP server for tests.
type smtpServer struct {
	t        *testing.T
	ln       net.Listener
	tlsCfg   *tls.Config // STARTTLS offered when set
	implicit bool        // TLS from the first byte
	user     string      // AUTH PLAIN offered (over TLS) when set
	pass     string
	// failRcpt makes the next N RCPT commands fail with this code.
	failCode  atomic.Int32
	failCount atomic.Int32
	msgs      chan received
	conns     atomic.Int32
}

type received struct {
	from, to string
	data     []byte
	tls      bool
	authed   bool
}

func newSMTPServer(t *testing.T, tlsCfg *tls.Config, implicit bool) *smtpServer {
	t.Helper()
	var ln net.Listener
	var err error
	if implicit {
		ln, err = tls.Listen("tcp", "127.0.0.1:0", tlsCfg)
	} else {
		ln, err = net.Listen("tcp", "127.0.0.1:0")
	}
	if err != nil {
		t.Fatal(err)
	}
	s := &smtpServer{t: t, ln: ln, tlsCfg: tlsCfg, implicit: implicit, msgs: make(chan received, 16)}
	go s.serve()
	t.Cleanup(func() { _ = ln.Close() })
	return s
}

func (s *smtpServer) port() int { return s.ln.Addr().(*net.TCPAddr).Port }

func (s *smtpServer) serve() {
	for {
		c, err := s.ln.Accept()
		if err != nil {
			return
		}
		s.conns.Add(1)
		go s.handle(c)
	}
}

func (s *smtpServer) handle(c net.Conn) {
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(10 * time.Second))
	isTLS := s.implicit
	r := bufio.NewReader(c)
	w := bufio.NewWriter(c)
	reply := func(format string, a ...any) {
		fmt.Fprintf(w, format+"\r\n", a...)
		_ = w.Flush()
	}
	reply("220 fake ESMTP")
	var cur received
	authed := false
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			return
		}
		line = strings.TrimRight(line, "\r\n")
		cmd := strings.ToUpper(line)
		switch {
		case strings.HasPrefix(cmd, "EHLO"), strings.HasPrefix(cmd, "HELO"):
			ext := []string{"250-fake"}
			if s.tlsCfg != nil && !isTLS {
				ext = append(ext, "250-STARTTLS")
			}
			if s.user != "" && isTLS {
				ext = append(ext, "250-AUTH PLAIN LOGIN")
			}
			ext = append(ext, "250 8BITMIME")
			reply("%s", strings.Join(ext, "\r\n"))
		case cmd == "STARTTLS":
			reply("220 go ahead")
			tc := tls.Server(c, s.tlsCfg)
			if err := tc.Handshake(); err != nil {
				return
			}
			c, isTLS = tc, true
			r, w = bufio.NewReader(tc), bufio.NewWriter(tc)
		case strings.HasPrefix(cmd, "AUTH PLAIN"):
			parts := strings.Fields(line)
			b, _ := base64.StdEncoding.DecodeString(parts[len(parts)-1])
			f := strings.Split(string(b), "\x00")
			if len(f) == 3 && f[1] == s.user && f[2] == s.pass {
				authed = true
				reply("235 ok")
			} else {
				reply("535 bad credentials")
			}
		case strings.HasPrefix(cmd, "MAIL FROM:"):
			if s.user != "" && !authed {
				reply("530 auth required")
				continue
			}
			cur = received{from: strings.Trim(line[len("MAIL FROM:"):], "<> "), tls: isTLS, authed: authed}
			if i := strings.Index(cur.from, " "); i > 0 {
				cur.from = strings.Trim(cur.from[:i], "<>")
			}
			reply("250 ok")
		case strings.HasPrefix(cmd, "RCPT TO:"):
			if s.failCount.Load() > 0 {
				s.failCount.Add(-1)
				reply("%d try later", s.failCode.Load())
				continue
			}
			cur.to = strings.Trim(line[len("RCPT TO:"):], "<> ")
			reply("250 ok")
		case cmd == "DATA":
			reply("354 go")
			var buf bytes.Buffer
			for {
				l, err := r.ReadString('\n')
				if err != nil {
					return
				}
				if l == ".\r\n" {
					break
				}
				buf.WriteString(strings.TrimPrefix(l, "."))
			}
			cur.data = buf.Bytes()
			s.msgs <- cur
			reply("250 queued")
		case cmd == "RSET", cmd == "NOOP":
			reply("250 ok")
		case cmd == "QUIT":
			reply("221 bye")
			return
		default:
			reply("502 unknown")
		}
	}
}

func (s *smtpServer) wait(t *testing.T) received {
	t.Helper()
	select {
	case m := <-s.msgs:
		return m
	case <-time.After(10 * time.Second):
		t.Fatal("no message received")
	}
	return received{}
}

func (s *smtpServer) none(t *testing.T, d time.Duration) {
	t.Helper()
	select {
	case m := <-s.msgs:
		t.Fatalf("unexpected message to %s", m.to)
	case <-time.After(d):
	}
}

// testCert returns a server TLS config for 127.0.0.1 and a pool trusting it.
func testCert(t *testing.T) (*tls.Config, *x509.CertPool) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "fake smtp"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, DNSNames: []string{"localhost"},
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true, IsCA: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	return &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}}, pool
}

type testEnv struct {
	svc      *Service
	settings *fakeSettings
}

func newTestEnv(t *testing.T, port int, mode string) *testEnv {
	t.Helper()
	st := &fakeSettings{m: map[string]any{
		SettingHost: "127.0.0.1", SettingPort: int64(port), SettingTLS: mode, SettingFrom: "files@example.com",
		SettingEvents: []string{EventShareUpload, EventSecurity}, instanceSetting: "Test Parcel",
	}}
	env := &core.Env{Settings: st, Log: slog.New(slog.NewTextHandler(io.Discard, nil)),
		Clock: core.ClockFunc(func() time.Time { return time.Date(2026, 9, 19, 10, 30, 0, 0, time.UTC) })}
	svc, err := New(env)
	if err != nil {
		t.Fatal(err)
	}
	svc.delays = []time.Duration{10 * time.Millisecond, 10 * time.Millisecond}
	t.Cleanup(func() { _ = svc.Close() })
	return &testEnv{svc: svc, settings: st}
}

// parseMsg parses a received message and decodes its quoted-printable body.
func parseMsg(t *testing.T, data []byte) (*mail.Message, string) {
	t.Helper()
	m, err := mail.ReadMessage(bytes.NewReader(data))
	if err != nil {
		t.Fatalf("parse message: %v\n%s", err, data)
	}
	body, err := io.ReadAll(quotedprintable.NewReader(m.Body))
	if err != nil {
		t.Fatal(err)
	}
	return m, strings.ReplaceAll(string(body), "\r\n", "\n")
}

// ---------- tests ----------

func TestDisabled(t *testing.T) {
	te := newTestEnv(t, 25, TLSNone)
	te.settings.set(SettingHost, "")
	if te.svc.Enabled() {
		t.Fatal("enabled without host")
	}
	if err := te.svc.Send(context.Background(), []string{"a@example.com"}, TemplateTest, nil); !errors.Is(err, core.ErrUnavailable) {
		t.Fatalf("send: %v", err)
	}
	if err := te.svc.Test(context.Background(), "a@example.com"); !errors.Is(err, core.ErrUnavailable) {
		t.Fatalf("test: %v", err)
	}
	var nilEnv Service
	nilEnv.env = &core.Env{}
	if nilEnv.Enabled() {
		t.Fatal("enabled without settings")
	}
}

func TestSendPlainDelivers(t *testing.T) {
	srv := newSMTPServer(t, nil, false)
	te := newTestEnv(t, srv.port(), TLSNone)
	ctx := context.Background()
	err := te.svc.Send(ctx, []string{"owner@example.com", "OWNER@example.com", "second@example.com"}, TemplateShareUpload, map[string]any{
		"share_title": "Holiday\r\nBcc: evil@example.com", "owner": "Olga", "uploader": "Uwe", "files": 3, "bytes": 1536,
		"folder": "Uploads", "url": "https://files.example.com/files/nod_1", "file_names": []string{"a.jpg", "b.jpg"},
	})
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]received{}
	for i := 0; i < 2; i++ { // deduplicated case-insensitively; one message per recipient
		m := srv.wait(t)
		got[m.to] = m
	}
	srv.none(t, 100*time.Millisecond)
	m, ok := got["owner@example.com"]
	if !ok || m.from != "files@example.com" || m.tls {
		t.Fatalf("envelope %+v", got)
	}
	msg, body := parseMsg(t, m.data)
	subj, err := new(mime.WordDecoder).DecodeHeader(msg.Header.Get("Subject"))
	if err != nil {
		t.Fatal(err)
	}
	if subj != `New upload to "Holiday Bcc: evil@example.com"` {
		t.Fatalf("subject %q", subj)
	}
	if msg.Header.Get("Bcc") != "" || len(msg.Header["Subject"]) != 1 {
		t.Fatalf("header injection: %v", msg.Header)
	}
	from, _ := mail.ParseAddress(msg.Header.Get("From"))
	if from.Address != "files@example.com" || from.Name != "Test Parcel" {
		t.Fatalf("from %+v", from)
	}
	if msg.Header.Get("To") != "<owner@example.com>" || msg.Header.Get("Content-Type") != `text/plain; charset="utf-8"` ||
		msg.Header.Get("Auto-Submitted") != "auto-generated" || !strings.HasSuffix(msg.Header.Get("Message-ID"), "@example.com>") {
		t.Fatalf("headers %v", msg.Header)
	}
	if _, err := msg.Header.Date(); err != nil {
		t.Fatalf("date: %v", err)
	}
	for _, want := range []string{"Hello Olga,", "Uwe uploaded 3 file(s) (1.5 KiB)", `into the folder "Uploads"`,
		"Files: a.jpg, b.jpg", "Open the folder: https://files.example.com/files/nod_1", "Test Parcel"} {
		if !strings.Contains(body, want) {
			t.Errorf("body lacks %q:\n%s", want, body)
		}
	}
}

func TestCategoriesAndValidation(t *testing.T) {
	srv := newSMTPServer(t, nil, false)
	te := newTestEnv(t, srv.port(), TLSNone)
	ctx := context.Background()
	te.settings.set(SettingEvents, []string{EventSecurity})
	if err := te.svc.Send(ctx, []string{"a@example.com"}, TemplateShareUpload, nil); err != nil {
		t.Fatalf("disabled category: %v", err)
	}
	srv.none(t, 100*time.Millisecond)

	cases := []struct {
		name  string
		to    []string
		tmpl  string
		data  any
		field string
	}{
		{"no recipients", nil, TemplateTest, nil, "to"},
		{"bad address", []string{"nope"}, TemplateTest, nil, "to"},
		{"display name", []string{"Eve <eve@example.com>"}, TemplateTest, nil, "to"},
		{"header injection", []string{"a@example.com\r\nBcc: x@example.com"}, TemplateTest, nil, "to"},
		{"too many", make([]string, MaxRecipients+1), TemplateTest, nil, "to"},
		{"unknown template", []string{"a@example.com"}, "nope", nil, "template"},
		{"invite without url", []string{"a@example.com"}, TemplateInvite, map[string]any{"inviter": "x"}, "url"},
		{"data not an object", []string{"a@example.com"}, TemplateInvite, []string{"x"}, "data"},
		{"data not serializable", []string{"a@example.com"}, TemplateInvite, map[string]any{"c": make(chan int)}, "data"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := te.svc.Send(ctx, tc.to, tc.tmpl, tc.data)
			ce := core.AsError(err)
			if !errors.Is(err, core.ErrInvalid) || ce.Field != tc.field {
				t.Fatalf("got %v", err)
			}
		})
	}
	srv.none(t, 50*time.Millisecond)
}

func TestTemplatesRender(t *testing.T) {
	common := map[string]string{"instance": "FP", "time": "2026-09-19T10:30:00Z"}
	cases := []struct {
		tmpl      string
		data      any
		subject   string
		bodyWants []string
	}{
		{TemplateInvite, map[string]any{"url": "https://x/invite/T", "inviter": "Ada", "role": "member",
			"expires_at": "2026-09-26T10:30:00Z", "note": "Welcome!\nSee you"},
			"Ada invited you to FP", []string{"Ada has invited you to join FP as member.", "https://x/invite/T",
				"expires on Sat, 26 Sep 2026 10:30 UTC", "Welcome!\nSee you"}},
		{TemplateInvite, struct {
			URL string `json:"url"`
		}{"https://x/i"}, "Your invitation to FP", []string{"You have been invited to join FP.", "https://x/i"}},
		{TemplateSecurityAlert, map[string]any{"kind": AlertLockout, "username": "bob", "locked_until": "2026-09-19T10:45:00Z", "ip": "192.0.2.1"},
			"Security alert: account temporarily locked", []string{"Hello bob,", "(until Sat, 19 Sep 2026 10:45 UTC)", "IP address: 192.0.2.1",
				"Time: Sat, 19 Sep 2026 10:30 UTC"}},
		{TemplateSecurityAlert, map[string]any{"kind": AlertPasskeyAdded, "name": "YubiKey"},
			"Security alert: new passkey added", []string{`A new passkey "YubiKey" was added`}},
		{TemplateSecurityAlert, map[string]any{"kind": AlertTOTPAdded},
			"Security alert: authenticator app added", []string{"An authenticator app was set up for two-factor sign-in"}},
		{TemplateSecurityAlert, map[string]any{"kind": AlertTokenCreated, "name": "backup"},
			"Security alert: new API token created", []string{`A new API token "backup" was created`}},
		{TemplateSecurityAlert, map[string]any{"kind": AlertMFAReset, "actor": "root", "time": "2026-01-01T00:00:00Z"},
			"Security alert: two-factor authentication reset", []string{"The administrator root removed", "Time: Thu, 01 Jan 2026 00:00 UTC"}},
		{TemplateSecurityAlert, map[string]any{"kind": AlertPasswordReset},
			"Security alert: password reset by an administrator", []string{"An administrator set a new password"}},
		{TemplateSecurityAlert, map[string]any{"kind": AlertEmailChanged, "name": "n***@example.org"},
			"Security alert: e-mail address changed", []string{"account was changed to n***@example.org.", "no longer sent to this address"}},
		{TemplateSecurityAlert, map[string]any{"kind": AlertEmailChanged},
			"Security alert: e-mail address changed", []string{"account was removed."}},
		{TemplateSecurityAlert, map[string]any{"kind": "weird", "detail": "Something\x07 happened"},
			"Security alert: account activity", []string{"Something happened"}},
		{TemplateShareUpload, map[string]any{}, "New upload", []string{"Someone uploaded files through your file request."}},
		{TemplateShareUpload, map[string]any{"share_title": "Photos", "owner": "Ada", "uploader": "Bob", "files": 3,
			"bytes": 1572864, "folder": "Inbox", "url": "https://x/files/f", "file_names": []string{"a.jpg", "b.jpg"}},
			`New upload to "Photos"`, []string{"Hello Ada,", `Bob uploaded 3 file(s) (1.5 MiB) through your file request "Photos" into the folder "Inbox".`,
				"Files: a.jpg, b.jpg", "Open the folder: https://x/files/f"}},
		// The shape and template name the shares service sends (shares.UploadNotice, "share.upload").
		{EventShareUpload, struct {
			ShareID   string    `json:"share_id"`
			Title     string    `json:"title"`
			Folder    string    `json:"folder"`
			Uploader  string    `json:"uploader"`
			Bytes     int64     `json:"bytes"`
			Files     int       `json:"files"`
			At        time.Time `json:"at"`
			OwnerName string    `json:"owner_name"`
			URL       string    `json:"url"`
		}{"shr_1", "Tax papers", "2026", "Carol", 2048, 2, time.Date(2026, 9, 18, 8, 0, 0, 0, time.UTC), "Dave", "https://x/files/nod_1"},
			`New upload to "Tax papers"`, []string{"Hello Dave,", `Carol uploaded 2 file(s) (2.0 KiB) through your file request "Tax papers" into the folder "2026".`,
				"Open the folder: https://x/files/nod_1"}},
		{TemplateTest, nil, "Test e-mail from FP", []string{"sent at Sat, 19 Sep 2026 10:30 UTC"}},
	}
	for _, tc := range cases {
		t.Run(tc.tmpl+"/"+tc.subject, func(t *testing.T) {
			r, err := render(tc.tmpl, tc.data, common)
			if err != nil {
				t.Fatal(err)
			}
			if r.subject != tc.subject {
				t.Fatalf("subject %q", r.subject)
			}
			for _, w := range tc.bodyWants {
				if !strings.Contains(r.body, w) {
					t.Errorf("body lacks %q:\n%s", w, r.body)
				}
			}
			if strings.Contains(r.body, "<no value>") || strings.ContainsAny(r.subject, "\r\n") {
				t.Fatalf("bad render %q / %q", r.subject, r.body)
			}
		})
	}
	// Instance cannot be overridden by data; long subjects are cut.
	r, err := render(TemplateShareUpload, map[string]any{"instance": "Evil", "share_title": strings.Repeat("x", 500)}, common)
	if err != nil || strings.Contains(r.body, "Evil") || len([]rune(r.subject)) != maxSubjectLen {
		t.Fatalf("render %v %q", err, r.subject)
	}
}

func TestHelpers(t *testing.T) {
	for in, want := range map[string]string{"0": "0 B", "1023": "1023 B", "1024": "1.0 KiB", "1572864": "1.5 MiB", "x": "x", "-1": "-1"} {
		if got := humanBytes(in); got != want {
			t.Errorf("humanBytes(%s) = %s", in, got)
		}
	}
	if got := humanTime("not a time"); got != "not a time" {
		t.Errorf("humanTime %q", got)
	}
	for _, c := range []struct {
		v    any
		ok   bool
		name string
	}{{"mail.example.com", true, ""}, {"10.0.0.1", true, ""}, {"::1", true, ""}, {"", true, ""},
		{"smtp://x", false, ""}, {"host:25", false, ""}, {"-bad", false, ""}, {"a..b", false, ""}, {"a b", false, ""}} {
		if err := validateHost(c.v); (err == nil) != c.ok {
			t.Errorf("validateHost(%v) = %v", c.v, err)
		}
	}
	if validateFrom("FileParcel <f@example.com>") != nil || validateFrom("f@example.com") != nil || validateFrom("nope") == nil ||
		validateFrom("a@b.c\nBcc: x") == nil {
		t.Error("validateFrom")
	}
	if validateEvents([]string{EventSecurity}) != nil || validateEvents([]string{"bogus"}) == nil {
		t.Error("validateEvents")
	}
	if domainOf("x") != "localhost" || domainOf("a@b.c") != "b.c" {
		t.Error("domainOf")
	}
}

func TestStartTLSWithAuth(t *testing.T) {
	cfg, pool := testCert(t)
	srv := newSMTPServer(t, cfg, false)
	srv.user, srv.pass = "mailer", "s3cret pass"
	te := newTestEnv(t, srv.port(), TLSStartTLS)
	te.svc.rootCAs = pool
	te.settings.set(SettingUsername, "mailer")
	te.settings.set(SettingPassword, "s3cret pass")
	if err := te.svc.Test(context.Background(), "admin@example.com"); err != nil {
		t.Fatal(err)
	}
	m := srv.wait(t)
	if !m.tls || !m.authed || m.to != "admin@example.com" {
		t.Fatalf("message %+v", m)
	}
	_, body := parseMsg(t, m.data)
	if !strings.Contains(body, "e-mail notifications are configured correctly") {
		t.Fatalf("body %s", body)
	}
	// Wrong password: a clear error, no message.
	te.settings.set(SettingPassword, "wrong")
	err := te.svc.Test(context.Background(), "admin@example.com")
	if !errors.Is(err, core.ErrUnavailable) || !strings.Contains(err.Error(), "authentication") || strings.Contains(err.Error(), "wrong") {
		t.Fatalf("bad password: %v", err)
	}
	// Untrusted certificate is refused.
	te.svc.rootCAs = nil
	te.settings.set(SettingPassword, "s3cret pass")
	if err := te.svc.Test(context.Background(), "admin@example.com"); err == nil {
		t.Fatal("untrusted certificate accepted")
	}
}

func TestImplicitTLS(t *testing.T) {
	cfg, pool := testCert(t)
	srv := newSMTPServer(t, cfg, true)
	te := newTestEnv(t, srv.port(), TLSImplicit)
	te.svc.rootCAs = pool
	if err := te.svc.Send(context.Background(), []string{"u@example.com"}, TemplateSecurityAlert, map[string]any{"kind": AlertLockout}); err != nil {
		t.Fatal(err)
	}
	if m := srv.wait(t); !m.tls {
		t.Fatal("not TLS")
	}
}

func TestStartTLSRequired(t *testing.T) {
	srv := newSMTPServer(t, nil, false) // no STARTTLS offered
	te := newTestEnv(t, srv.port(), TLSStartTLS)
	err := te.svc.Test(context.Background(), "a@example.com")
	if err == nil || !strings.Contains(err.Error(), "STARTTLS") {
		t.Fatalf("downgrade not refused: %v", err)
	}
	// Authentication without TLS is refused before connecting.
	te2 := newTestEnv(t, srv.port(), TLSNone)
	te2.settings.set(SettingUsername, "u")
	before := srv.conns.Load()
	if err := te2.svc.Test(context.Background(), "a@example.com"); !errors.Is(err, core.ErrInvalid) {
		t.Fatalf("auth over plain: %v", err)
	}
	if srv.conns.Load() != before {
		t.Fatal("connected although auth over plain text is refused")
	}
	// A missing sender is a configuration error.
	te3 := newTestEnv(t, srv.port(), TLSNone)
	te3.settings.set(SettingFrom, "")
	if err := te3.svc.Test(context.Background(), "a@example.com"); !errors.Is(err, core.ErrInvalid) {
		t.Fatalf("no from: %v", err)
	}
	te3.settings.set(SettingUsername, "")
}

func TestRetryTransientNotPermanent(t *testing.T) {
	srv := newSMTPServer(t, nil, false)
	te := newTestEnv(t, srv.port(), TLSNone)
	srv.failCode.Store(451)
	srv.failCount.Store(2)
	if err := te.svc.Send(context.Background(), []string{"a@example.com"}, TemplateTest, nil); err != nil {
		t.Fatal(err)
	}
	if m := srv.wait(t); m.to != "a@example.com" {
		t.Fatalf("to %s", m.to)
	}
	// 5xx: dropped after one attempt.
	srv.failCode.Store(550)
	srv.failCount.Store(1)
	if err := te.svc.Send(context.Background(), []string{"b@example.com"}, TemplateTest, nil); err != nil {
		t.Fatal(err)
	}
	srv.none(t, 200*time.Millisecond)
	if srv.failCount.Load() != 0 {
		t.Fatal("not attempted")
	}
}

func TestQueueFullAndClose(t *testing.T) {
	st := &fakeSettings{m: map[string]any{SettingHost: "127.0.0.1", SettingPort: int64(1), SettingTLS: TLSNone,
		SettingFrom: "f@example.com", SettingEvents: []string{}}}
	env := &core.Env{Settings: st, Log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	// A service without a running worker, to fill the queue deterministically.
	s := &Service{env: env, log: env.Log, queue: make(chan *message, 2), stop: make(chan struct{}), done: make(chan struct{})}
	close(s.done)
	ctx := context.Background()
	if err := s.Send(ctx, []string{"a@example.com", "b@example.com"}, TemplateTest, nil); err != nil {
		t.Fatal(err)
	}
	if err := s.Send(ctx, []string{"c@example.com"}, TemplateTest, nil); !errors.Is(err, core.ErrUnavailable) {
		t.Fatalf("full queue: %v", err)
	}
	_ = s.Close()
	if err := s.Send(ctx, []string{"c@example.com"}, TemplateTest, nil); !errors.Is(err, core.ErrUnavailable) {
		t.Fatalf("after close: %v", err)
	}

	// Close delivers what is queued.
	srv := newSMTPServer(t, nil, false)
	te := newTestEnv(t, srv.port(), TLSNone)
	for i := 0; i < 3; i++ {
		if err := te.svc.Send(ctx, []string{"q" + strconv.Itoa(i) + "@example.com"}, TemplateTest, nil); err != nil {
			t.Fatal(err)
		}
	}
	if err := te.svc.Close(); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		srv.wait(t)
	}
	if err := te.svc.Close(); err != nil { // idempotent
		t.Fatal(err)
	}
}

func TestPermanent(t *testing.T) {
	if permanent(errors.New("x")) || !permanent(core.Invalid("a", "b")) || permanent(core.ErrUnavailable) {
		t.Fatal("permanent")
	}
}
