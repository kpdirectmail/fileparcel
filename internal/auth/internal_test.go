package auth

import (
	"context"
	"encoding/base32"
	"encoding/json"
	"errors"
	"net/http/httptest"
	"net/netip"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/pquerna/otp/hotp"

	"fileparcel/internal/config"
	"fileparcel/internal/core"
	"fileparcel/internal/ids"
)

// rfcSecret is the RFC 6238 SHA-1 test key "12345678901234567890".
var rfcSecret = base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString([]byte("12345678901234567890"))

func TestTOTPRFC6238Vectors(t *testing.T) {
	// RFC 6238 Appendix B (SHA-1, 8 digits); the 6-digit code is the last 6.
	vectors := []struct {
		unix int64
		code string
	}{
		{59, "94287082"},
		{1111111109, "07081804"},
		{1111111111, "14050471"},
		{1234567890, "89005924"},
		{2000000000, "69279037"},
		{20000000000, "65353130"},
	}
	for _, v := range vectors {
		now := time.Unix(v.unix, 0)
		step, ok := matchTOTPStep(rfcSecret, v.code[2:], now, 0)
		if !ok || step != v.unix/30 {
			t.Errorf("T=%d code %s: ok=%v step=%d, want step %d", v.unix, v.code[2:], ok, step, v.unix/30)
		}
	}
}

func codeAt(t *testing.T, step int64) string {
	t.Helper()
	c, err := hotp.GenerateCodeCustom(rfcSecret, uint64(step), totpOpts)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestTOTPSkewAndReplay(t *testing.T) {
	now := time.Unix(1_800_000_015, 0)
	cur := totpStep(now)
	tests := []struct {
		name     string
		step     int64
		last     int64
		wantOK   bool
		wantStep int64
	}{
		{"current", cur, 0, true, cur},
		{"previous step (skew)", cur - 1, 0, true, cur - 1},
		{"next step (skew)", cur + 1, 0, true, cur + 1},
		{"two steps old", cur - 2, 0, false, 0},
		{"two steps ahead", cur + 2, 0, false, 0},
		{"replay of the used step", cur, cur, false, 0},
		{"older than the last used step", cur - 1, cur, false, 0},
		{"newer than the last used step", cur + 1, cur, true, cur + 1},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			step, ok := matchTOTPStep(rfcSecret, codeAt(t, tc.step), now, tc.last)
			if ok != tc.wantOK || step != tc.wantStep {
				t.Fatalf("got (%d,%v), want (%d,%v)", step, ok, tc.wantStep, tc.wantOK)
			}
		})
	}
	if _, ok := matchTOTPStep(rfcSecret, "000000", now, 0); ok && codeAt(t, cur) != "000000" {
		t.Fatal("wrong code accepted")
	}
}

func TestNormalizeTOTP(t *testing.T) {
	for in, want := range map[string]string{"123456": "123456", "123 456": "123456", " 12-34-56 ": "123456"} {
		if got, ok := normalizeTOTP(in); !ok || got != want {
			t.Errorf("normalizeTOTP(%q) = %q,%v", in, got, ok)
		}
	}
	for _, in := range []string{"", "12345", "1234567", "12a456", "١٢٣٤٥٦"} {
		if _, ok := normalizeTOTP(in); ok {
			t.Errorf("normalizeTOTP(%q) accepted", in)
		}
	}
}

func TestRecoveryCodes(t *testing.T) {
	seen := map[string]bool{}
	for range 200 {
		c := newRecoveryCode()
		if len(c) != 9 || c[4] != '-' {
			t.Fatalf("bad format %q", c)
		}
		n, ok := normalizeRecovery(c)
		if !ok || len(n) != 8 {
			t.Fatalf("own code %q does not normalize", c)
		}
		seen[n] = true
	}
	if len(seen) < 195 {
		t.Fatalf("codes repeat too often: %d distinct of 200", len(seen))
	}
	tests := map[string]string{
		"abcd-efgh": "ABCD-EFGH", "ABCDEFGH": "ABCDEFGH", " ab cd ef gh ": "ABCDEFGH",
		"o0il-1234": "0011-1234", // look-alikes
	}
	for in, want := range tests {
		got, ok := normalizeRecovery(in)
		want = strings.ReplaceAll(want, "-", "")
		if !ok || got != want {
			t.Errorf("normalizeRecovery(%q) = %q,%v want %q", in, got, ok, want)
		}
	}
	for _, in := range []string{"", "ABC", "ABCD-EFGHJ", "ABCD-EFGU", "ABCD_EFGH", "ÄBCD-EFGH"} {
		if _, ok := normalizeRecovery(in); ok {
			t.Errorf("normalizeRecovery(%q) accepted", in)
		}
	}
}

func TestParseToken(t *testing.T) {
	id := ids.New(ids.PrefixToken)
	good := newTokenSecret(id)
	if got, ok := parseToken(good); !ok || got != id {
		t.Fatalf("parseToken(%q) = %q,%v want %q", good, got, ok, id)
	}
	suffix := strings.TrimPrefix(id, "tok_")
	secret := strings.TrimPrefix(good, "fpt_"+suffix+"_")
	bad := []string{
		"", "fpt_", "fpt__" + secret, "fpx_" + suffix + "_" + secret,
		"fpt_" + suffix + secret, // missing separator
		"fpt_" + suffix + "_" + secret[:len(secret)-1],
		"fpt_" + suffix + "_" + secret[:len(secret)-1] + "!",
		"fpt_" + strings.ToUpper(suffix) + "_" + secret,
		"fpt_" + suffix[:25] + "_" + secret,
	}
	for _, b := range bad {
		if _, ok := parseToken(b); ok {
			t.Errorf("parseToken(%q) accepted", b)
		}
	}
}

func TestDecodeScopes(t *testing.T) {
	sc, el := decodeScopes(`["files:read","admin","elevated","bogus"]`)
	if !slices.Equal(sc, []string{"files:read", "admin"}) || !el {
		t.Fatalf("got %v %v", sc, el)
	}
	sc, el = decodeScopes("files:read shares")
	if !slices.Equal(sc, []string{"files:read", "shares"}) || el {
		t.Fatalf("legacy form: got %v %v", sc, el)
	}
	if _, err := normalizeScopes([]string{" Files:Read ", "files:read", "shares"}); err != nil {
		t.Fatal(err)
	}
	if got, _ := normalizeScopes([]string{"admin", "files:read"}); !slices.Equal(got, []string{"files:read", "admin"}) {
		t.Fatalf("order: %v", got)
	}
	for _, in := range [][]string{nil, {""}, {"elevated"}, {"files:delete"}} {
		if _, err := normalizeScopes(in); err == nil {
			t.Errorf("normalizeScopes(%v) accepted", in)
		}
	}
}

// TestCommonPasswords checks the wrapper around crypt.IsCommonPassword
// (the list and its size/affix tests live in internal/crypt).
func TestCommonPasswords(t *testing.T) {
	common := []string{"password", "Password", "PASSWORD2024!", "p@ssw0rd", "P4ssw0rd99", "Summer2024", "123password",
		"iloveyou!!", "qwertyuiop", "1q2w3e4r", "football1", "baseball#1"}
	for _, pw := range common {
		if !IsCommonPassword(pw) {
			t.Errorf("%q should be common", pw)
		}
	}
	fine := []string{"correct horse battery staple", "Tr4mpoline-Galaxy", "my cat eats 3 socks", "x9$Lq!2vRm#8"}
	for _, pw := range fine {
		if IsCommonPassword(pw) {
			t.Errorf("%q should not be common", pw)
		}
	}
}

func TestCSRFAndCookie(t *testing.T) {
	sec := []byte("0123456789abcdef0123456789abcdef")
	a, b := csrfFor(sec, "ses_a"), csrfFor(sec, "ses_b")
	if a == "" || a == b || a != csrfFor(sec, "ses_a") || strings.ContainsAny(a, "+/=") {
		t.Fatalf("csrf tokens: %q %q", a, b)
	}
	if csrfFor(nil, "x") != "" || csrfFor(sec, "") != "" {
		t.Fatal("empty inputs must give empty token")
	}
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	s := &Service{env: &core.Env{Clock: core.ClockFunc(func() time.Time { return now })}}
	c := s.SessionCookie("tok", time.Time{})
	if c.Name != CookieName || !c.Secure || !c.HttpOnly || c.Path != "/" || c.Domain != "" || c.MaxAge != 0 || !c.Expires.IsZero() {
		t.Fatalf("session cookie: %+v", c)
	}
	c = s.SessionCookie("tok", now.Add(time.Hour))
	if c.MaxAge != 3600 || !c.Expires.Equal(now.Add(time.Hour)) {
		t.Fatalf("persistent cookie: %+v", c)
	}
	if c = s.SessionCookie("", time.Time{}); c.MaxAge >= 0 || c.Value != "" {
		t.Fatalf("delete cookie: %+v", c)
	}
}

func TestClientIP(t *testing.T) {
	cfg := config.Default("x")
	cfg.Server.TrustedProxies = []string{"10.0.0.0/8", "::1"}
	s := &Service{env: &core.Env{Config: cfg}}
	tests := []struct {
		remote, xff, want string
	}{
		{"192.0.2.7:4000", "", "192.0.2.7"},
		{"192.0.2.7:4000", "203.0.113.9", "192.0.2.7"}, // untrusted peer: header ignored
		{"10.1.2.3:4000", "203.0.113.9", "203.0.113.9"},
		{"10.1.2.3:4000", "198.51.100.1, 203.0.113.9, 10.9.9.9", "203.0.113.9"},
		{"10.1.2.3:4000", "garbage", "10.1.2.3"},
		{"[::ffff:192.0.2.8]:80", "", "192.0.2.8"},
		{"@", "", "::1"},
	}
	for _, tc := range tests {
		r := httptest.NewRequest("GET", "/", nil)
		r.RemoteAddr = tc.remote
		if tc.xff != "" {
			r.Header.Set("X-Forwarded-For", tc.xff)
		}
		if got := s.clientIP(r); got != netip.MustParseAddr(tc.want) {
			t.Errorf("%s / %q: got %s want %s", tc.remote, tc.xff, got, tc.want)
		}
	}
}

func TestFormatAAGUIDAndNames(t *testing.T) {
	if formatAAGUID(make([]byte, 16)) != "" || formatAAGUID([]byte{1}) != "" {
		t.Fatal("zero/short aaguid must be empty")
	}
	b := []byte{0xad, 0xce, 0x00, 0x02, 0x35, 0xbc, 0xc6, 0x0a, 0x64, 0x8b, 0x0b, 0x25, 0xf1, 0xf0, 0x55, 0x03}
	if got := formatAAGUID(b); got != "adce0002-35bc-c60a-648b-0b25f1f05503" {
		t.Fatalf("aaguid %q", got)
	}
	if n, err := cleanName("name", "  Laptop  "); err != nil || n != "Laptop" {
		t.Fatalf("cleanName: %q %v", n, err)
	}
	for _, bad := range []string{"", "   ", strings.Repeat("x", 65), "a\x00b", "tab\there"} {
		if _, err := cleanName("name", bad); err == nil {
			t.Errorf("cleanName(%q) accepted", bad)
		}
	}
}

// mapSettings is a tiny core.Settings for the RP configuration test.
type mapSettings map[string]any

func (m mapSettings) Raw(k string) (json.RawMessage, error) {
	if v, ok := m[k]; ok {
		return json.Marshal(v)
	}
	return nil, core.ErrNotFound
}
func (m mapSettings) Int(k string) int64 {
	if v, ok := m[k].(int); ok {
		return int64(v)
	}
	return 0
}
func (m mapSettings) Bool(k string) bool        { v, _ := m[k].(bool); return v }
func (m mapSettings) String(k string) string    { v, _ := m[k].(string); return v }
func (m mapSettings) Strings(k string) []string { v, _ := m[k].([]string); return v }
func (m mapSettings) Duration(string) time.Duration {
	return 0
}
func (m mapSettings) Secret(string) (string, error) { return "", nil }
func (m mapSettings) Set(context.Context, *core.Principal, map[string]json.RawMessage) (*core.SettingsResult, error) {
	return nil, errors.New("unsupported")
}
func (m mapSettings) Reset(context.Context, *core.Principal, string) error { return nil }
func (m mapSettings) Catalog(context.Context) ([]core.SettingView, error)  { return nil, nil }

// fixedMDNS is a core.MDNS with a constant status.
type fixedMDNS struct{ st core.MDNSStatus }

func (m fixedMDNS) Status() core.MDNSStatus         { return m.st }
func (m fixedMDNS) Name() string                    { return m.st.Name }
func (m fixedMDNS) Republish(context.Context) error { return nil }
func (m fixedMDNS) Start(context.Context) error     { return nil }
func (m fixedMDNS) Stop() error                     { return nil }

func TestRPConfig(t *testing.T) {
	cfg := config.Default("x")
	cfg.Server.Name, cfg.Server.HTTPSPort = "files", 8443
	tests := []struct {
		name        string
		set         mapSettings
		publicURL   string
		mdns        *core.MDNSStatus
		wantRP      string
		wantOrigins []string
	}{
		{"defaults from config", mapSettings{}, "", nil, "files.local", []string{"https://files.local:8443", "https://files.local"}},
		{"published mdns name wins over the settings", mapSettings{"mdns.name": "files"}, "",
			&core.MDNSStatus{Name: "files-2.local", State: core.MDNSPublished},
			"files-2.local", []string{"https://files-2.local:8443", "https://files-2.local"}},
		{"mdns off falls back to the settings", mapSettings{"mdns.name": "Home"}, "",
			&core.MDNSStatus{Name: "home.local", State: core.MDNSOff},
			"home.local", []string{"https://home.local:8443", "https://home.local"}},
		{"explicit rp id beats the published name", mapSettings{"auth.webauthn_rp_id": "example.com"}, "",
			&core.MDNSStatus{Name: "files-2.local", State: core.MDNSPublished},
			"example.com", []string{"https://example.com:8443", "https://example.com"}},
		{"mdns name wins", mapSettings{"mdns.name": "Home"}, "", nil, "home.local", []string{"https://home.local:8443", "https://home.local"}},
		{"explicit rp id + extra origins", mapSettings{"auth.webauthn_rp_id": "Example.COM.", "server.https_port": 443,
			"auth.webauthn_origins": []string{"https://files.example.com:9443", "not an origin"}}, "", nil,
			"example.com", []string{"https://example.com", "https://files.example.com:9443"}},
		{"public url under the rp id", mapSettings{"auth.webauthn_rp_id": "example.com"}, "https://Files.Example.com", nil,
			"example.com", []string{"https://example.com:8443", "https://example.com", "https://files.example.com"}},
		{"public url elsewhere ignored", mapSettings{}, "https://other.example.org", nil, "files.local",
			[]string{"https://files.local:8443", "https://files.local"}},
		// Every name this server serves under the RP ID must work: the UI
		// offers the passkey button on any subdomain of it (DESIGN §18.1).
		// Wildcards, IPs and foreign names stay out.
		{"served names under the rp id", mapSettings{"auth.webauthn_rp_id": "example.com",
			"tls.extra_sans":      []string{"files.example.com", "*.example.com", "10.0.0.5", "other.example.org"},
			"network.extra_hosts": []string{"EXAMPLE.COM."}, "acme.domains": []string{"share.example.com"}}, "", nil,
			"example.com", []string{"https://example.com:8443", "https://example.com",
				"https://files.example.com:8443", "https://files.example.com",
				"https://share.example.com:8443", "https://share.example.com"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			c := *cfg
			c.Server.PublicURL = tc.publicURL
			s := &Service{env: &core.Env{Config: &c, Settings: tc.set}}
			if tc.mdns != nil {
				if err := s.Bind(&core.Services{MDNS: fixedMDNS{st: *tc.mdns}}); err != nil {
					t.Fatal(err)
				}
			}
			rp, origins := s.rpConfig()
			if rp != tc.wantRP || !slices.Equal(origins, tc.wantOrigins) {
				t.Fatalf("got %q %v, want %q %v", rp, origins, tc.wantRP, tc.wantOrigins)
			}
		})
	}
}

func TestRequires2FA(t *testing.T) {
	staff := core.MemberCaps.With(core.CapAuditView) // a member-based role with a server permission
	shares := core.NewCapSet(core.CapShareLinks)     // a guest-based role with user permissions only
	for _, tc := range []struct {
		policy string
		role   core.Role
		caps   core.CapSet
		want   bool
	}{
		{"off", core.RoleOwner, core.AllCaps, false}, {"admins", core.RoleOwner, core.AllCaps, true},
		{"admins", core.RoleAdmin, core.AllCaps, true}, {"admins", core.RoleMember, core.MemberCaps, false},
		{"all", core.RoleGuest, 0, true}, {"", core.RoleAdmin, core.AllCaps, true},
		// "admins" covers every staff account: a role with a server permission,
		// whatever its base; user permissions alone do not count.
		{"admins", core.RoleMember, staff, true}, {"admins", core.RoleGuest, core.NewCapSet(core.CapSystemView), true},
		{"admins", core.RoleGuest, shares, false}, {"off", core.RoleMember, staff, false},
		{"all", core.RoleMember, core.MemberCaps, true},
	} {
		s := &Service{env: &core.Env{Settings: mapSettings{"auth.require_2fa": tc.policy}}}
		if got := s.requires2FA(tc.role, tc.caps); got != tc.want {
			t.Errorf("%s/%s/%s: got %v", tc.policy, tc.role, tc.caps, got)
		}
	}
}

func TestFlowsSingleUseAndSweep(t *testing.T) {
	now := time.Date(2026, 9, 19, 12, 0, 0, 0, time.UTC)
	s := &Service{env: &core.Env{Clock: core.ClockFunc(func() time.Time { return now })}, flows: map[string]*flow{}}
	id, err := s.putFlow(&flow{kind: flowLogin, userID: "usr_a"})
	if err != nil {
		t.Fatal(err)
	}
	if s.takeFlow(id, flowRegister) != nil {
		t.Fatal("a login flow must not finish a registration")
	}
	if s.takeFlow(id, flowLogin) != nil {
		t.Fatal("flows are single use (even after a wrong kind)")
	}
	stale, _ := s.putFlow(&flow{kind: flowLogin})
	now = now.Add(FlowTTL)
	if s.takeFlow(stale, flowLogin) != nil {
		t.Fatal("expired flow accepted")
	}
	for range 3 {
		_, _ = s.putFlow(&flow{kind: flowRegister})
	}
	now = now.Add(FlowTTL + time.Second)
	fresh, _ := s.putFlow(&flow{kind: flowRegister}) // sweeps the expired ones
	if len(s.flows) != 1 || s.flows[fresh] == nil {
		t.Fatalf("expired flows kept: %d", len(s.flows))
	}
}

func TestValidateSettings(t *testing.T) {
	for _, tc := range []struct {
		v  string
		ok bool
	}{
		{"", true}, {"fileparcel.local", true}, {"files.example.com", true}, {"xn--bcher-kva.example", true},
		{"192.168.1.10", false}, {"[::1]", false}, {"https://files.example.com", false}, {"files.example.com:8443", false},
		{"a..b", false}, {"-bad.example", false}, {"bad-.example", false}, {strings.Repeat("a", 64) + ".example", false},
		{"under_score.example", false},
	} {
		if err := validateRPID(tc.v); (err == nil) != tc.ok {
			t.Errorf("validateRPID(%q) = %v, want ok=%v", tc.v, err, tc.ok)
		}
	}
	if err := validateOrigins([]string{"https://files.example.com:8443", "https://a.example/"}); err != nil {
		t.Errorf("valid origins: %v", err)
	}
	for _, bad := range []string{"http://files.example.com", "https://files.example.com/path", "https://user@x.example", "files.example.com", "https://x.example?q=1"} {
		if err := validateOrigins([]string{bad}); err == nil {
			t.Errorf("origin %q accepted", bad)
		}
	}
}
