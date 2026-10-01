package certs

import (
	"context"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"fileparcel/internal/core"
	"fileparcel/internal/events"
)

// acmeReady fills the acme.* settings with a configuration readACMEConfig
// accepts.
func acmeReady(te *testEnv) {
	te.settings.set(KeyACMEEnabled, true)
	te.settings.set(KeyACMEDomains, []string{"files.example.org"})
	te.settings.set(KeyACMEChallenge, ChallengeDNS)
	te.settings.set(KeyACMEProvider, ProviderCloudflare)
	te.settings.set(KeyACMECreds, `{"api_token":"t0ken"}`)
}

// On a sealed server readACMEConfig cannot read acme.dns_credentials, so
// ApplyACME fails at start and certmagic is never created. The unlock event
// only ever re-loaded the custom key and a pending leaf renewal, so DNS-01
// stayed unconfigured until the 12-hourly renew check — up to ~12 h with no
// ACME management at all on a server that boots locked.
func TestACMERetriedAfterUnlock(t *testing.T) {
	te := newTestEnv(t)
	acmeReady(te)
	svc := te.initService(t)

	// Sealed: the credential read fails and nothing is configured.
	te.settings.lockSecrets(true)
	if err := svc.ApplyACME(context.Background()); !errors.Is(err, core.ErrKeysLocked) {
		t.Fatalf("ApplyACME while sealed: %v", err)
	}
	if svc.acme.Load() != nil {
		t.Fatal("ACME configured although the keys were locked")
	}
	te.settings.lockSecrets(false)

	before := te.settings.secretReads()
	svc.apply(context.Background(), pending{unlock: true})
	if te.settings.secretReads() == before {
		t.Fatal("the keys were unlocked but ACME was not retried")
	}
	// Tailscale too: its certificate needs the same unlock to be fetched.
	te.settings.set(KeyTailscaleCert, true)
	var p pending
	svc.classify(events.Event{Topic: events.TopicKeysState,
		Data: core.KeysStateEvent{State: core.KeyStateUnlocked}}, &p)
	if !p.unlock {
		t.Fatal("keys.state{unlocked} does not request work")
	}
}

// Clearing acme.domains (or the credentials) while acme.enabled stays true
// makes readACMEConfig fail, and ApplyACME used to return before stopping the
// previous configuration: certmagic kept managing and answering SNI for the
// removed domain while the admin saw a 422 and assumed nothing was running.
func TestACMEStoppedWhenConfigurationBecomesInvalid(t *testing.T) {
	te := newTestEnv(t)
	acmeReady(te)
	svc := te.initService(t)
	svc.acme.Store(&acmeState{domains: []string{"files.example.org"}, key: "old"})

	te.settings.set(KeyACMEDomains, []string{})
	if err := svc.ApplyACME(context.Background()); !errors.Is(err, core.ErrInvalid) {
		t.Fatalf("ApplyACME without domains: %v", err)
	}
	if st := svc.acme.Load(); st != nil {
		t.Fatalf("the previous ACME state is still managing %v", st.domains)
	}
	if got := loadString(&svc.acmeErr); got == "" {
		t.Fatal("the error is not reported in the status")
	}

	// A merely unavailable configuration (sealed keys) is transient: keep
	// managing what is already running and retry on unlock.
	te.settings.set(KeyACMEDomains, []string{"files.example.org"})
	svc.acme.Store(&acmeState{domains: []string{"files.example.org"}, key: "old"})
	te.settings.lockSecrets(true)
	if err := svc.ApplyACME(context.Background()); !errors.Is(err, core.ErrKeysLocked) {
		t.Fatalf("ApplyACME while sealed: %v", err)
	}
	if svc.acme.Load() == nil {
		t.Fatal("locked keys stopped a running ACME configuration")
	}
}

// Every tailscaled socket and the `tailscale cert` fallback quote the same
// refusal, so the status line, GET /admin/certs and the admin UI showed one
// sentence three times over (~700 characters).
func TestTailscaleErrorNotRepeated(t *testing.T) {
	te := newTestEnv(t)
	te.net.ts = &core.TailscaleInfo{Running: true, DNSName: "files.tail1234.ts.net."}
	te.settings.set(KeyTailscaleCert, true)
	te.settings.set(KeyTailscaleName, "nosuch.tail1234.ts.net")
	svc := te.initService(t)

	const complaint = `invalid domain "nosuch.tail1234.ts.net"; must be one of ["files.tail1234.ts.net"]`
	deny := func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(complaint))
	}
	// Two socket paths for the same daemon (/var/run is a symlink to /run),
	// plus the CLI, which asks that very daemon and prints the same sentence.
	sock1, sock2 := fakeTailscaled(t, deny), fakeTailscaled(t, deny)
	cli := filepath.Join(t.TempDir(), "tailscale")
	if err := os.WriteFile(cli, []byte("#!/bin/sh\necho '"+complaint+"' >&2\nexit 1\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	withTailscale(t, []string{sock1, sock2}, cli)

	err := svc.FetchTailscale(context.Background())
	if err == nil {
		t.Fatal("fetching a certificate for an unknown domain must fail")
	}
	st, _ := svc.Status(context.Background())
	if n := strings.Count(st.TailscaleError, complaint); n != 1 {
		t.Fatalf("the same complaint appears %d times in\n%s", n, st.TailscaleError)
	}
	// Genuinely different failures are still all reported (tslocal's
	// TestJoinDistinct).
}
