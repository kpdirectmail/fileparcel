package certs

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	pkcs12 "software.sslmate.com/src/go-pkcs12"

	"fileparcel/internal/core"
)

const (
	aliceID = "usr_0000000000000000000000alic"
	bobID   = "usr_00000000000000000000000bob"
)

func issue(t *testing.T, svc *Service, in core.ClientCertInput) (*core.ClientCert, *x509.Certificate, []*x509.Certificate) {
	t.Helper()
	cc, p12, err := svc.IssueClient(context.Background(), core.SystemPrincipal(core.ViaSocket), in)
	if err != nil {
		t.Fatal(err)
	}
	key, leaf, chain, err := pkcs12.DecodeChain(p12, in.Password)
	if err != nil {
		t.Fatalf("p12 does not decode: %v", err)
	}
	if key == nil {
		t.Fatal("p12 without key")
	}
	return cc, leaf, chain
}

func TestIssueClientP12RoundTrip(t *testing.T) {
	te := newTestEnv(t)
	te.addUser(t, aliceID, "alice", "active")
	svc := te.initService(t)
	for _, legacy := range []bool{false, true} {
		cc, leaf, chain := issue(t, svc, core.ClientCertInput{UserID: aliceID, Name: "Alice's phone", Password: "s3cret-pass", Legacy: legacy, Days: 30})
		if leaf.Subject.CommonName != "alice" || !slices.Equal(leaf.ExtKeyUsage, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}) {
			t.Fatalf("leaf subject/EKU: %v %v", leaf.Subject, leaf.ExtKeyUsage)
		}
		if len(leaf.URIs) != 1 || leaf.URIs[0].String() != ClientURIPrefix+aliceID {
			t.Fatalf("SAN URI %v", leaf.URIs)
		}
		// Android and Windows install a CA found in a .p12 as a trusted root.
		if len(chain) != 0 {
			t.Fatal("p12 must not carry the client CA (it would be installed as a trusted root on Android/Windows)")
		}
		if _, err := leaf.Verify(x509.VerifyOptions{Roots: svc.snapshot().clientPool, CurrentTime: te.clock.Now(),
			KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err != nil {
			t.Fatalf("client leaf does not verify: %v", err)
		}
		if _, err := leaf.Verify(x509.VerifyOptions{Roots: poolOf(svc.snapshot().ca), CurrentTime: te.clock.Now(),
			KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err == nil {
			t.Fatal("client certificate must not chain to the server CA")
		}
		if d := leaf.NotAfter.Sub(te.clock.Now()); d != 30*24*time.Hour {
			t.Fatalf("validity %v", d)
		}
		if cc.Serial != serialHex(leaf) || cc.FingerprintSHA256 != fingerprint(leaf.Raw) || cc.Username != "alice" ||
			cc.Name != "Alice's phone" || cc.IssuedBy != "system" {
			t.Fatalf("record %+v", cc)
		}
	}
	if n := len(te.audit.find(core.ActClientCertIssue)); n != 2 {
		t.Fatalf("client_cert.issue audits: %d", n)
	}
}

func TestIssueClientValidation(t *testing.T) {
	te := newTestEnv(t)
	te.addUser(t, aliceID, "alice", "active")
	te.addUser(t, bobID, "bob", "disabled")
	svc := te.initService(t)
	tests := []struct {
		name string
		in   core.ClientCertInput
		want *core.Error
	}{
		{"short password", core.ClientCertInput{UserID: aliceID, Password: "abc"}, core.ErrInvalid},
		{"three umlauts", core.ClientCertInput{UserID: aliceID, Password: "äöü"}, core.ErrInvalid}, // 6 bytes, 3 characters
		{"129 characters", core.ClientCertInput{UserID: aliceID, Password: strings.Repeat("a", 129)}, core.ErrInvalid},
		{"emoji password", core.ClientCertInput{UserID: aliceID, Password: "pass😀word"}, core.ErrInvalid},
		{"NUL in password", core.ClientCertInput{UserID: aliceID, Password: "pass\x00word"}, core.ErrInvalid},
		{"long name", core.ClientCertInput{UserID: aliceID, Password: "password", Name: strings.Repeat("x", 101)}, core.ErrInvalid},
		{"control char", core.ClientCertInput{UserID: aliceID, Password: "password", Name: "a\nb"}, core.ErrInvalid},
		{"days too many", core.ClientCertInput{UserID: aliceID, Password: "password", Days: 4000}, core.ErrInvalid},
		{"negative days", core.ClientCertInput{UserID: aliceID, Password: "password", Days: -1}, core.ErrInvalid},
		{"no user", core.ClientCertInput{Password: "password"}, core.ErrInvalid},
		{"unknown user", core.ClientCertInput{UserID: "usr_nobody", Password: "password"}, core.ErrNotFound},
		{"disabled user", core.ClientCertInput{UserID: bobID, Password: "password"}, core.ErrConflict},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if _, _, err := svc.IssueClient(context.Background(), nil, tc.in); !errors.Is(err, tc.want) {
				t.Fatalf("got %v, want %v", err, tc.want.Code)
			}
		})
	}
	// The limits count characters, not bytes: 100 CJK characters are 300 bytes.
	issue(t, svc, core.ClientCertInput{UserID: aliceID, Password: strings.Repeat("中", 100)})
	te.keys.setState(core.KeyStateLocked)
	if _, _, err := svc.IssueClient(context.Background(), nil, core.ClientCertInput{UserID: aliceID, Password: "password"}); !errors.Is(err, core.ErrKeysLocked) {
		t.Fatalf("issue while locked: %v", err)
	}
}

// The client CA signs client certificates only. It must never be able to
// vouch for a server, should its key leak (or should a device have trusted
// it from an older .p12 that carried it).
func TestClientCAIsClientAuthOnly(t *testing.T) {
	te := newTestEnv(t)
	te.addUser(t, aliceID, "alice", "active")
	svc := te.initService(t)
	cca := svc.snapshot().clientCA
	if !slices.Equal(cca.ExtKeyUsage, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}) {
		t.Fatalf("client CA EKU %v", cca.ExtKeyUsage)
	}
	if len(cca.PermittedDNSDomains)+len(cca.PermittedURIDomains)+len(cca.ExcludedIPRanges) != 0 {
		t.Fatal("name constraints on the client CA reject the fileparcel:user: SAN URI")
	}
	key, err := svc.openSealedKey(fileClientCAKey, aadClientCAKey)
	if err != nil {
		t.Fatal(err)
	}
	k, _ := newKey()
	serial, _ := newSerial()
	der, err := x509.CreateCertificate(rand.Reader, &x509.Certificate{SerialNumber: serial, DNSNames: []string{"www.example.com"},
		NotBefore: te.clock.Now().Add(-time.Hour), NotAfter: te.clock.Now().Add(time.Hour),
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}, cca, k.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	srv, _ := x509.ParseCertificate(der)
	if _, err := srv.Verify(x509.VerifyOptions{Roots: poolOf(cca), CurrentTime: te.clock.Now(), DNSName: "www.example.com"}); err == nil {
		t.Fatal("a server certificate signed by the client CA verifies")
	}
	// A certificate from the chain-less .p12 still passes a real handshake
	// in required mode and CheckClient.
	te.settings.set(KeyMTLSMode, MTLSRequired)
	te.settings.set(KeyMTLSExempt, false)
	cc, p12, err := svc.IssueClient(context.Background(), nil, core.ClientCertInput{UserID: aliceID, Password: "password"})
	if err != nil {
		t.Fatal(err)
	}
	pk, leaf, chain, err := pkcs12.DecodeChain(p12, "password")
	if err != nil || len(chain) != 0 {
		t.Fatalf("p12: %v, chain %d", err, len(chain))
	}
	if _, err := handshake(t, svc, &tls.Config{ServerName: "fileparcel.local", RootCAs: caPool(svc.snapshot().ca),
		Certificates: []tls.Certificate{{Certificate: [][]byte{leaf.Raw}, PrivateKey: pk, Leaf: leaf}}}); err != nil {
		t.Fatalf("handshake with the chain-less client certificate: %v", err)
	}
	got, err := svc.CheckClient(context.Background(), &tls.ConnectionState{PeerCertificates: []*x509.Certificate{leaf}})
	if err != nil || got.ID != cc.ID {
		t.Fatalf("CheckClient with the leaf alone: %v", err)
	}
}

// A revoke reason is cut to 200 bytes; slicing bytes split a multi-byte
// character and stored invalid UTF-8 (shown as U+FFFD by the API).
func TestRevokeReasonIsValidUTF8(t *testing.T) {
	te := newTestEnv(t)
	te.addUser(t, aliceID, "alice", "active")
	svc := te.initService(t)
	ctx := context.Background()
	for _, tc := range []struct{ in, want string }{
		{strings.Repeat("端", 100), strings.Repeat("端", 66)}, // 300 bytes → 198
		{"lost \xffphone", "lost �phone"},
	} {
		cc, _, _ := issue(t, svc, core.ClientCertInput{UserID: aliceID, Password: "password"})
		if err := svc.RevokeClient(ctx, nil, cc.ID, tc.in); err != nil {
			t.Fatal(err)
		}
		var got string
		if err := te.env.DB.QueryRow(ctx, `SELECT revoke_reason FROM client_certs WHERE id = ?`, cc.ID).Scan(&got); err != nil {
			t.Fatal(err)
		}
		if !utf8.ValidString(got) || len(got) > revokeReasonMax || got != tc.want {
			t.Fatalf("stored reason %q, want %q", got, tc.want)
		}
		e := te.audit.find(core.ActClientCertRevoke)
		if r := e[len(e)-1].Details.(map[string]any)["reason"]; r != tc.want {
			t.Fatalf("audited reason %q", r)
		}
	}
}

// Administrators may not manage an owner's credentials (auth.authorizeFor,
// the users API); revoking an owner's client certificates was the exception,
// and locks the owner out while mtls.mode is required.
func TestOwnerClientCertsNeedAnOwner(t *testing.T) {
	const ownerID, owner2ID, adminID = "usr_000000000000000000000owner", "usr_00000000000000000000owner2", "usr_000000000000000000000admin"
	te := newTestEnv(t)
	te.addUser(t, ownerID, "olivia", "active")
	te.addUser(t, owner2ID, "oscar", "active")
	te.addUser(t, adminID, "adam", "active")
	te.addUser(t, aliceID, "alice", "active")
	ctx := context.Background()
	for _, id := range []string{ownerID, owner2ID} {
		if _, err := te.env.DB.Exec(ctx, `UPDATE users SET role = 'owner' WHERE id = ?`, id); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := te.env.DB.Exec(ctx, `UPDATE users SET role = 'admin' WHERE id = ?`, adminID); err != nil {
		t.Fatal(err)
	}
	svc := te.initService(t)
	admin := &core.Principal{UserID: adminID, Username: "adam", Role: core.RoleAdmin}
	owner2 := &core.Principal{UserID: owner2ID, Username: "oscar", Role: core.RoleOwner}
	self := &core.Principal{UserID: ownerID, Username: "olivia", Role: core.RoleMember} // /me narrows the role

	in := core.ClientCertInput{UserID: ownerID, Password: "password"}
	if _, _, err := svc.IssueClient(ctx, admin, in); !errors.Is(err, core.ErrForbidden) {
		t.Fatalf("admin issuing for an owner: %v", err)
	}
	for _, by := range []*core.Principal{owner2, core.SystemPrincipal(core.ViaSocket), self, nil} {
		if _, _, err := svc.IssueClient(ctx, by, in); err != nil {
			t.Fatalf("issue for an owner by %+v: %v", by, err)
		}
	}

	cc, leaf, _ := issue(t, svc, in)
	if err := svc.RevokeClient(ctx, admin, cc.ID, "x"); !errors.Is(err, core.ErrForbidden) {
		t.Fatalf("admin revoking an owner's certificate: %v", err)
	}
	if _, err := svc.CheckClient(ctx, &tls.ConnectionState{PeerCertificates: []*x509.Certificate{leaf}}); err != nil {
		t.Fatalf("the refused revoke took effect: %v", err)
	}
	for _, by := range []*core.Principal{owner2, core.SystemPrincipal(core.ViaSocket), self, nil} {
		cc, _, _ := issue(t, svc, in)
		if err := svc.RevokeClient(ctx, by, cc.ID, ""); err != nil {
			t.Fatalf("revoke of an owner's certificate by %+v: %v", by, err)
		}
	}
	// Members' and admins' certificates stay manageable by an admin.
	for _, uid := range []string{aliceID, adminID} {
		cc, _, _ := issue(t, svc, core.ClientCertInput{UserID: uid, Password: "password"})
		if err := svc.RevokeClient(ctx, admin, cc.ID, ""); err != nil {
			t.Fatalf("admin revoking %s: %v", uid, err)
		}
		if _, _, err := svc.IssueClient(ctx, admin, core.ClientCertInput{UserID: uid, Password: "password"}); err != nil {
			t.Fatalf("admin issuing for %s: %v", uid, err)
		}
	}
}

// RevokeClient resets the cache after its commit, but a CheckClient that had
// read the row before could put its "not revoked" result back afterwards —
// and its last_seen_at write queues behind the revoke on the single writer,
// so it usually did: the revoked certificate passed the mTLS gate for 30 s.
func TestClientCacheDropsResultsFromBeforeAReset(t *testing.T) {
	var c clientCache
	now := time.Now()
	_, gen, _ := c.get("fp", now) // CheckClient: miss, then the row is read…
	c.reset()                     // …RevokeClient commits and resets…
	c.put("fp", core.ClientCert{ID: "x"}, now, gen)
	if _, _, ok := c.get("fp", now); ok {
		t.Fatal("a result read before the reset was cached")
	}
	_, gen, _ = c.get("fp", now)
	c.put("fp", core.ClientCert{ID: "x"}, now, gen)
	if _, _, ok := c.get("fp", now); !ok {
		t.Fatal("a current result was not cached")
	}
}

// The same race end to end: CheckClient reads the row, then waits for the
// writer (last_seen_at) behind the revoke.
func TestRevokeRacingCheckClient(t *testing.T) {
	te := newTestEnv(t)
	te.addUser(t, aliceID, "alice", "active")
	svc := te.initService(t)
	ctx := context.Background()
	w := te.env.DB.Writer()
	waiters := func(n int64) {
		t.Helper()
		deadline := time.Now().Add(5 * time.Second)
		for w.Stats().WaitCount < n {
			if time.Now().After(deadline) {
				t.Fatalf("timeout waiting for %d writer waiters", n)
			}
			time.Sleep(time.Millisecond)
		}
	}
	for i := range 10 {
		cc, leaf, _ := issue(t, svc, core.ClientCertInput{UserID: aliceID, Password: "password"})
		cs := &tls.ConnectionState{PeerCertificates: []*x509.Certificate{leaf}}
		held, release := make(chan struct{}), make(chan struct{})
		go func() {
			_ = te.env.DB.Tx(ctx, func(*sql.Tx) error { close(held); <-release; return nil })
		}()
		<-held
		base := w.Stats().WaitCount
		checked := make(chan error, 1)
		go func() { _, err := svc.CheckClient(ctx, cs); checked <- err }()
		waiters(base + 1)
		revoked := make(chan error, 1)
		go func() { revoked <- svc.RevokeClient(ctx, nil, cc.ID, "lost") }()
		waiters(base + 2)
		close(release)
		if err := <-revoked; err != nil {
			t.Fatal(err)
		}
		<-checked // accepted or not: it was in flight
		if _, err := svc.CheckClient(ctx, cs); err == nil || !strings.Contains(err.Error(), "revoked") {
			t.Fatalf("iteration %d: revoked certificate accepted: %v", i, err)
		}
	}
}

func TestCheckClientAndRevoke(t *testing.T) {
	te := newTestEnv(t)
	te.addUser(t, aliceID, "alice", "active")
	te.addUser(t, bobID, "bob", "active")
	svc := te.initService(t)
	cc, leaf, chain := issue(t, svc, core.ClientCertInput{UserID: aliceID, Password: "password"})
	cs := &tls.ConnectionState{PeerCertificates: append([]*x509.Certificate{leaf}, chain...)}
	ctx := context.Background()

	got, err := svc.CheckClient(ctx, cs)
	if err != nil || got.ID != cc.ID || got.UserID != aliceID || got.LastSeenAt == nil {
		t.Fatalf("CheckClient: %+v %v", got, err)
	}
	var seen int64
	if err := te.env.DB.QueryRow(ctx, `SELECT last_seen_at FROM client_certs WHERE id = ?`, cc.ID).Scan(&seen); err != nil || seen == 0 {
		t.Fatalf("last_seen_at not recorded: %v", err)
	}

	// Missing / foreign certificates.
	if _, err := svc.CheckClient(ctx, &tls.ConnectionState{}); !errors.Is(err, core.ErrUnauthorized) {
		t.Fatalf("no certificate: %v", err)
	}
	if _, err := svc.CheckClient(ctx, nil); !errors.Is(err, core.ErrUnauthorized) {
		t.Fatalf("nil state: %v", err)
	}
	foreign := newTestCA(t, "foreign")
	_, _, fleaf := foreign.leaf(t, leafOpts{names: []string{"x.example.com"}, eku: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}})
	if _, err := svc.CheckClient(ctx, &tls.ConnectionState{PeerCertificates: []*x509.Certificate{fleaf}}); !errors.Is(err, core.ErrUnauthorized) {
		t.Fatalf("foreign certificate: %v", err)
	}
	// The server leaf (wrong CA and EKU) is refused.
	if _, err := svc.CheckClient(ctx, &tls.ConnectionState{PeerCertificates: []*x509.Certificate{svc.snapshot().leaf.Leaf}}); err == nil {
		t.Fatal("server certificate accepted as client certificate")
	}

	// Only the owner (or an admin) may revoke.
	bob := &core.Principal{UserID: bobID, Username: "bob", Role: core.RoleMember}
	if err := svc.RevokeClient(ctx, bob, cc.ID, ""); !errors.Is(err, core.ErrNotFound) {
		t.Fatalf("foreign revoke: %v", err)
	}
	alice := &core.Principal{UserID: aliceID, Username: "alice", Role: core.RoleMember}
	if err := svc.RevokeClient(ctx, alice, strings.ToLower(cc.Serial), "lost phone"); err != nil {
		t.Fatalf("revoke by serial: %v", err)
	}
	if _, err := svc.CheckClient(ctx, cs); err == nil || !strings.Contains(err.Error(), "revoked") {
		t.Fatalf("revoked certificate accepted: %v", err)
	}
	if err := svc.RevokeClient(ctx, nil, cc.ID, ""); err != nil {
		t.Fatalf("second revoke: %v", err)
	}
	e := te.audit.find(core.ActClientCertRevoke)
	if len(e) != 1 || e[0].Details.(map[string]any)["reason"] != "lost phone" {
		t.Fatalf("revoke audit %+v", e)
	}
	if err := svc.RevokeClient(ctx, nil, "ccr_unknown", ""); !errors.Is(err, core.ErrNotFound) {
		t.Fatalf("unknown id: %v", err)
	}
}

func TestCheckClientDisabledUserAndCache(t *testing.T) {
	te := newTestEnv(t)
	te.addUser(t, aliceID, "alice", "active")
	svc := te.initService(t)
	_, leaf, chain := issue(t, svc, core.ClientCertInput{UserID: aliceID, Password: "password"})
	cs := &tls.ConnectionState{PeerCertificates: append([]*x509.Certificate{leaf}, chain...)}
	ctx := context.Background()
	if _, err := svc.CheckClient(ctx, cs); err != nil {
		t.Fatal(err)
	}
	if _, err := te.env.DB.Exec(ctx, `UPDATE users SET status = 'disabled' WHERE id = ?`, aliceID); err != nil {
		t.Fatal(err)
	}
	// Cached for clientCacheTTL…
	if _, err := svc.CheckClient(ctx, cs); err != nil {
		t.Fatalf("cached result: %v", err)
	}
	// …then re-checked.
	te.clock.add(clientCacheTTL + time.Second)
	if _, err := svc.CheckClient(ctx, cs); err == nil {
		t.Fatal("certificate of a disabled user accepted")
	}
	// Expired certificates fail verification.
	te.clock.add(400 * 24 * time.Hour)
	if _, err := te.env.DB.Exec(ctx, `UPDATE users SET status = 'active' WHERE id = ?`, aliceID); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.CheckClient(ctx, cs); err == nil {
		t.Fatal("expired certificate accepted")
	}
}

func TestListClientPagination(t *testing.T) {
	te := newTestEnv(t)
	te.addUser(t, aliceID, "alice", "active")
	te.addUser(t, bobID, "bob", "active")
	svc := te.initService(t)
	var ids []string
	for i := range 5 {
		uid := aliceID
		if i == 2 {
			uid = bobID
		}
		cc, _, err := svc.IssueClient(context.Background(), nil, core.ClientCertInput{UserID: uid, Password: "password"})
		if err != nil {
			t.Fatal(err)
		}
		ids = append(ids, cc.ID)
		te.clock.add(time.Second)
	}
	var got []string
	cursor := ""
	for {
		page, err := svc.ListClient(context.Background(), core.PageReq{Limit: 2, Cursor: cursor}, "")
		if err != nil {
			t.Fatal(err)
		}
		for _, c := range page.Items {
			got = append(got, c.ID)
			if c.Username == "" {
				t.Fatal("username not joined")
			}
		}
		if page.NextCursor == "" {
			break
		}
		cursor = page.NextCursor
	}
	want := slices.Clone(ids)
	slices.Reverse(want)
	if !slices.Equal(got, want) {
		t.Fatalf("order %v, want %v", got, want)
	}
	page, err := svc.ListClient(context.Background(), core.PageReq{}, bobID)
	if err != nil || len(page.Items) != 1 || page.Items[0].ID != ids[2] {
		t.Fatalf("filter by user: %+v %v", page, err)
	}
	if _, err := svc.ListClient(context.Background(), core.PageReq{Cursor: "!!"}, ""); !errors.Is(err, core.ErrInvalid) {
		t.Fatalf("bad cursor: %v", err)
	}
}

func TestClientCALazilyCreated(t *testing.T) {
	te := newTestEnv(t)
	te.addUser(t, aliceID, "alice", "active")
	svc := te.initService(t)
	// Simulate a home created before the client CA existed.
	next := svc.snapshot().clone()
	next.clientCA, next.clientPool = nil, nil
	svc.state.Store(next)
	if _, _, err := svc.IssueClient(context.Background(), nil, core.ClientCertInput{UserID: aliceID, Password: "password"}); err != nil {
		t.Fatal(err)
	}
	if svc.snapshot().clientCA == nil {
		t.Fatal("client CA not created")
	}
}
