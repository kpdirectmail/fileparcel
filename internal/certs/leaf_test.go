package certs

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"fileparcel/internal/core"
	"fileparcel/internal/events"
	"fileparcel/internal/settings"
)

// settingsEvent builds a settings.changed event for keys.
func settingsEvent(keys ...string) events.Event {
	return events.Event{Topic: events.TopicSettingsChanged, Data: core.SettingsChangedEvent{Keys: keys}}
}

// A leaf whose configured validity is shorter than the fixed 30-day renewal
// window used to be "expiring" the moment it was signed: certs.renew_check
// runs twice a day, so the server rotated its TLS key and certificate for ever
// (three reissues in ten seconds in the reported repro). The renewal window
// now scales with the certificate's own lifetime.
func TestShortLeafDaysDoesNotChurn(t *testing.T) {
	te := newTestEnv(t)
	te.settings.set(KeyLeafDays, 7)
	svc := te.initService(t)
	first := svc.snapshot().leaf.Leaf

	if need, why := svc.leafNeedsRenewal(svc.snapshot(), false); need {
		t.Fatalf("a freshly issued 7-day leaf already needs renewal (%s)", why)
	}
	for i := range 3 {
		if err := svc.renewCheck(context.Background()); err != nil {
			t.Fatal(err)
		}
		if got := svc.snapshot().leaf.Leaf; !got.Equal(first) {
			t.Fatalf("renew check %d reissued the leaf (serial %v → %v)", i+1, first.SerialNumber, got.SerialNumber)
		}
	}
	// It must still renew before it actually expires.
	te.clock.add(5 * 24 * time.Hour)
	if need, why := svc.leafNeedsRenewal(svc.snapshot(), false); !need || why != "expiring" {
		t.Fatalf("2 days before expiry: need=%v why=%q, want expiring", need, why)
	}
	// The default validity keeps the documented 30-day window.
	if got := renewBefore(397 * 24 * time.Hour); got != leafRenewBefore {
		t.Fatalf("renewBefore(397d) = %v, want %v", got, leafRenewBefore)
	}
}

// tls.leaf_days only ever reached the certificate through issueLeaf, so a
// change sat unapplied until something else happened to reissue the leaf — up
// to 13 months with the default validity, while the settings page showed the
// new value as active.
func TestLeafDaysChangeReissues(t *testing.T) {
	te := newTestEnv(t)
	svc := te.initService(t)
	before := svc.snapshot().leaf.Leaf
	if span := before.NotAfter.Sub(before.NotBefore); span != 397*24*time.Hour {
		t.Fatalf("initial span %v", span)
	}

	te.settings.set(KeyLeafDays, 90)
	need, why := svc.leafNeedsRenewal(svc.snapshot(), false)
	if !need || why != "validity_changed" {
		t.Fatalf("after changing tls.leaf_days: need=%v why=%q", need, why)
	}
	if err := svc.RenewLocal(context.Background(), false); err != nil {
		t.Fatal(err)
	}
	after := svc.snapshot().leaf.Leaf
	if span := after.NotAfter.Sub(after.NotBefore); span != 90*24*time.Hour {
		t.Fatalf("validity span after the change: %v, want 90d", span)
	}
	// Converged: the next check must not reissue again.
	if need, why := svc.leafNeedsRenewal(svc.snapshot(), false); need {
		t.Fatalf("leaf reissued repeatedly (%s)", why)
	}
	// The settings watcher has to ask for the check in the first place.
	var p pending
	svc.classify(settingsEvent(KeyLeafDays), &p)
	if !p.leaf {
		t.Fatal("settings.changed{tls.leaf_days} does not request a leaf check")
	}
}

// Names the local CA may not sign are dropped from the leaf. That is correct,
// but it used to happen in complete silence: leafNeedsRenewal compares the
// already-filtered set, so nothing is reissued and the warning inside
// issueLeaf is never reached.
func TestUncoveredNamesAreReported(t *testing.T) {
	te := newTestEnv(t)
	svc := te.initService(t)
	te.settings.set(KeyExtraSANs, []string{"files.example.com", "extra.local"})

	if err := svc.RenewLocal(context.Background(), false); err != nil {
		t.Fatal(err)
	}
	sans := sansOf(svc.snapshot().leaf.Leaf).strings()
	if slices.Contains(sans, "files.example.com") {
		t.Fatalf("a name outside the CA's constraints must not be in the leaf: %v", sans)
	}
	if got := svc.UncoveredNames(); !slices.Contains(got, "files.example.com") {
		t.Fatalf("UncoveredNames() = %v, want it to name files.example.com", got)
	}
	if got := svc.UnsignableNames([]string{"files.example.com", "ok.local", "198.51.100.7"}); !slices.Equal(got,
		[]string{"198.51.100.7", "files.example.com"}) {
		t.Fatalf("UnsignableNames() = %v", got)
	}
	if got := svc.UnsignableNames([]string{"ok.local"}); len(got) != 0 {
		t.Fatalf("a permitted name was reported as unsignable: %v", got)
	}
}

// An unbounded name list is a valid PATCH that locks the server out of HTTPS:
// 12 000 names produced a 228 KB certificate and every client failed the
// handshake with "excessive message size".
func TestNameListsAreBounded(t *testing.T) {
	def, ok := settings.Lookup(KeyExtraSANs)
	if !ok || def.Validate == nil {
		t.Fatal("tls.extra_sans has no validation")
	}
	many := make([]string, maxExtraSANs+1)
	for i := range many {
		many[i] = fmt.Sprintf("s%05d.local", i)
	}
	if err := def.Validate(many); err == nil {
		t.Fatalf("%d names in tls.extra_sans accepted", len(many))
	}
	if err := def.Validate(many[:maxExtraSANs]); err != nil {
		t.Fatalf("%d names refused: %v", maxExtraSANs, err)
	}
	dom, _ := settings.Lookup(KeyACMEDomains)
	big := make([]string, maxACMEDomains+1)
	for i := range big {
		big[i] = fmt.Sprintf("d%05d.example.org", i)
	}
	if err := dom.Validate(big); err == nil {
		t.Fatalf("%d acme.domains accepted", len(big))
	}

	// Belt and braces: whatever the settings allow, the assembled SAN set is
	// capped and the excess is reported instead of signed.
	te := newTestEnv(t)
	names := make([]string, 0, maxLeafDNS+50)
	for i := range cap(names) {
		names = append(names, fmt.Sprintf("h%05d.local", i))
	}
	te.net.setNames(names...)
	svc := te.initService(t)
	leaf := svc.snapshot().leaf.Leaf
	if len(leaf.DNSNames) > maxLeafDNS {
		t.Fatalf("leaf has %d DNS names, more than the %d cap", len(leaf.DNSNames), maxLeafDNS)
	}
	if len(svc.UncoveredNames()) == 0 {
		t.Fatal("the names left out by the cap are not reported")
	}
	if !slices.Contains(leaf.DNSNames, "localhost") {
		t.Fatalf("the cap dropped a name of this server itself: %v", leaf.DNSNames)
	}
}

// The leaf key and certificate used to be replaced by two separate renames.
// A crash between them left a key next to a certificate it does not belong
// to: no leaf at the next start, so a sealed server could not even serve
// /unlock. The new key is now staged as leaf.key.next and the certificate
// rename is the commit point.
func TestLeafSwapSurvivesACrash(t *testing.T) {
	read := func(t *testing.T, svc *Service, rel string) []byte {
		t.Helper()
		b, err := os.ReadFile(svc.path(rel))
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	write := func(t *testing.T, svc *Service, rel string, b []byte) {
		t.Helper()
		if err := os.WriteFile(svc.path(rel), b, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	serves := func(t *testing.T, svc *Service, want *x509.Certificate) {
		t.Helper()
		st := svc.snapshot()
		if st.leaf == nil || !st.leaf.Leaf.Equal(want) {
			t.Fatal("the expected leaf was not loaded")
		}
		if _, err := handshake(t, svc, &tls.Config{ServerName: "fileparcel.local", RootCAs: caPool(st.ca)}); err != nil {
			t.Fatalf("handshake: %v", err)
		}
	}
	matches := func(t *testing.T, svc *Service) {
		t.Helper()
		if _, err := tls.X509KeyPair(read(t, svc, fileLeafCert), read(t, svc, fileLeafKey)); err != nil {
			t.Fatalf("leaf.crt and leaf.key do not match: %v", err)
		}
		if _, err := os.Stat(svc.path(fileLeafKeyNext)); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("%s left behind: %v", fileLeafKeyNext, err)
		}
	}
	// setup issues a leaf, reissues it and returns the old and new files.
	setup := func(t *testing.T) (te *testEnv, svc *Service, oldCrt, oldKey, newCrt, newKey []byte, newLeaf *x509.Certificate) {
		te = newTestEnv(t)
		svc = te.initService(t)
		oldCrt, oldKey = read(t, svc, fileLeafCert), read(t, svc, fileLeafKey)
		if err := svc.RenewLocal(context.Background(), true); err != nil {
			t.Fatal(err)
		}
		matches(t, svc) // a completed swap leaves no staged key
		return te, svc, oldCrt, oldKey, read(t, svc, fileLeafCert), read(t, svc, fileLeafKey), svc.snapshot().leaf.Leaf
	}

	t.Run("after the commit", func(t *testing.T) {
		te, svc, _, oldKey, _, newKey, newLeaf := setup(t)
		write(t, svc, fileLeafKey, oldKey)
		write(t, svc, fileLeafKeyNext, newKey)
		te.keys.setState(core.KeyStateLocked) // sealed: nothing can be reissued
		svc2 := te.service(t)
		serves(t, svc2, newLeaf)
		// The next swap first completes the interrupted one.
		te.keys.setState(core.KeyStateUnlocked)
		if err := svc2.RenewLocal(context.Background(), true); err != nil {
			t.Fatal(err)
		}
		matches(t, svc2)
	})
	t.Run("before the commit", func(t *testing.T) {
		te, svc, _, _, _, newKey, newLeaf := setup(t)
		stray := strayKeyPEM(t)
		write(t, svc, fileLeafKeyNext, stray) // staged, never committed
		te.keys.setState(core.KeyStateLocked)
		svc2 := te.service(t)
		serves(t, svc2, newLeaf)
		te.keys.setState(core.KeyStateUnlocked)
		if err := svc2.RenewLocal(context.Background(), true); err != nil {
			t.Fatal(err)
		}
		matches(t, svc2)
		if bytes.Equal(read(t, svc2, fileLeafKey), newKey) {
			t.Fatal("the forced renewal did not replace the key")
		}
	})
	t.Run("mismatch without a staged key", func(t *testing.T) {
		te, svc, oldCrt, _, _, _, _ := setup(t)
		write(t, svc, fileLeafCert, oldCrt) // new key, old certificate
		te.keys.setState(core.KeyStateLocked)
		svc2 := te.service(t)
		if svc2.snapshot().leaf != nil {
			t.Fatal("a mismatched pair was loaded")
		}
		te.keys.setState(core.KeyStateUnlocked)
		if err := svc2.Init(context.Background()); err != nil || svc2.snapshot().leaf == nil {
			t.Fatalf("the leaf was not reissued: %v", err)
		}
		matches(t, svc2)
	})
}

// strayKeyPEM returns a fresh private key that belongs to no certificate.
func strayKeyPEM(t *testing.T) []byte {
	t.Helper()
	k, err := newKey()
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(k)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
}

// The ACME settings refuse what an ACME CA can never issue for or what
// would only fail later: IP literals and local names as domains, credentials
// that fit neither DNS provider, an over-long account e-mail.
func TestACMESettingsValidation(t *testing.T) {
	dom, _ := settings.Lookup(KeyACMEDomains)
	for _, bad := range []string{"192.168.1.1", "10.0.0.5", "2001:db8::1", "[::1]", "1.2.3", "files.local", "box.localhost",
		"localhost", "bad name!"} {
		if err := dom.Validate([]string{bad}); err == nil {
			t.Errorf("acme.domains %q accepted", bad)
		}
	}
	for _, good := range []string{"files.example.org", "*.example.org", "a-1.example.co.uk", "files.example.org."} {
		if err := dom.Validate([]string{good}); err != nil {
			t.Errorf("acme.domains %q: %v", good, err)
		}
	}
	creds, _ := settings.Lookup(KeyACMECreds)
	for _, bad := range []string{`{}`, `{"foo":1}`, `{"api_token":1}`, `{"api_token":""}`, `{"zone_token":"z"}`,
		`{"server":"ns1:53","key_name":"k."}`, `{"api_token":"t","server":"ns1:53"}`, `[]`, `"x"`, `null`} {
		if err := creds.Validate(bad); err == nil {
			t.Errorf("acme.dns_credentials %s accepted", bad)
		}
	}
	for _, good := range []string{``, `{"api_token":"cf"}`, `{"api_token":"cf","zone_token":"z"}`,
		`{"server":"ns1.example.com:53","key_name":"fp.","key":"c2VjcmV0"}`,
		`{"server":"ns1:53","key_name":"fp.","key_alg":"hmac-sha512.","key":"c2VjcmV0"}`} {
		if err := creds.Validate(good); err != nil {
			t.Errorf("acme.dns_credentials %s: %v", good, err)
		}
	}
	email, _ := settings.Lookup(KeyACMEEmail)
	if err := email.Validate(strings.Repeat("x", 65) + "@example.com"); err == nil {
		t.Error("a 65-character local part accepted")
	}
	if err := email.Validate(strings.Repeat("x", 64) + "@" + strings.Repeat("d", 200) + ".example.com"); err == nil {
		t.Error("a 270-character address accepted")
	}
	if err := email.Validate(strings.Repeat("x", 64) + "@example.com"); err != nil {
		t.Errorf("64-character local part: %v", err)
	}
}
