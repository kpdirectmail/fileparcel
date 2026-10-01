package certs

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"

	pkcs12 "software.sslmate.com/src/go-pkcs12"

	"fileparcel/internal/core"
	"fileparcel/internal/db"
	"fileparcel/internal/ids"
)

// Client certificate limits.
const (
	clientNameMax     = 100
	clientPasswordMin = 6
	clientPasswordMax = 128
	clientCacheTTL    = 30 * time.Second
	clientCacheMax    = 1024
	clientSeenEvery   = time.Minute
	// ClientURIPrefix prefixes the SAN URI naming the user of a client
	// certificate ("fileparcel:user:<id>").
	ClientURIPrefix = "fileparcel:user:"
)

// clientCache memoizes successful CheckClient results per certificate
// fingerprint for clientCacheTTL (the mTLS gate runs on every request).
//
// gen counts invalidations. A CheckClient that read its row before a revoke
// committed may reach put only after RevokeClient's reset (its last_seen_at
// write queues behind the revoke on the single writer); it takes the
// generation before the read, and put drops the result when a reset happened
// in between, so a revoked certificate is never re-cached.
type clientCache struct {
	mu  sync.Mutex
	gen uint64
	m   map[string]clientEntry
}

type clientEntry struct {
	cc  core.ClientCert
	exp time.Time
}

// get returns the cached entry for fp and, hit or miss, the current
// generation to hand to put.
func (c *clientCache) get(fp string, now time.Time) (*core.ClientCert, uint64, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.m[fp]
	if !ok || now.After(e.exp) {
		return nil, c.gen, false
	}
	cc := e.cc
	return &cc, c.gen, true
}

// put stores cc unless the cache was reset since gen was taken.
func (c *clientCache) put(fp string, cc core.ClientCert, now time.Time, gen uint64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if gen != c.gen {
		return
	}
	if c.m == nil || len(c.m) >= clientCacheMax {
		c.m = map[string]clientEntry{}
	}
	c.m[fp] = clientEntry{cc: cc, exp: now.Add(clientCacheTTL)}
}

// reset drops every entry and invalidates results still being computed. It
// must run after the change that caused it has committed.
func (c *clientCache) reset() {
	c.mu.Lock()
	c.m = nil
	c.gen++
	c.mu.Unlock()
}

// clientUser is the part of a users row needed for client certificates.
type clientUser struct {
	ID, Username, Status, Role string
}

func (svc *Service) lookupUser(ctx context.Context, id string) (*clientUser, error) {
	if svc.env.DB == nil {
		return nil, core.ErrUnavailable
	}
	var u clientUser
	err := svc.env.DB.QueryRow(ctx, `SELECT id, username, status, role FROM users WHERE id = ?`, id).Scan(&u.ID, &u.Username, &u.Status, &u.Role)
	if db.IsNoRows(err) {
		return nil, core.NotFoundf("user not found")
	}
	if err != nil {
		return nil, err
	}
	return &u, nil
}

// validClientName trims and checks a client certificate name.
func validClientName(name string) (string, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		name = "Client certificate"
	}
	if utf8.RuneCountInString(name) > clientNameMax || !utf8.ValidString(name) {
		return "", core.Invalid("name", fmt.Sprintf("the name must be at most %d characters", clientNameMax))
	}
	for _, r := range name {
		if unicode.IsControl(r) {
			return "", core.Invalid("name", "the name must not contain control characters")
		}
	}
	return name, nil
}

// validP12Password checks a PKCS#12 password before any key is unsealed:
// 6–128 characters (not bytes), all in the Basic Multilingual Plane, since
// PKCS#12 encodes the password as a UCS-2 BMPString (an emoji used to pass
// here and fail in the encoder as an internal error), and no control
// characters (a NUL would cut the zero-terminated BMPString short).
func validP12Password(pw string) error {
	n := utf8.RuneCountInString(pw)
	if !utf8.ValidString(pw) || n < clientPasswordMin || n > clientPasswordMax {
		return core.Invalid("password", fmt.Sprintf("the PKCS#12 password must be %d–%d characters", clientPasswordMin, clientPasswordMax))
	}
	for _, r := range pw {
		if r > 0xFFFF {
			return core.Invalid("password", "the PKCS#12 password must not contain emoji or other characters outside the Basic Multilingual Plane")
		}
		if unicode.IsControl(r) {
			return core.Invalid("password", "the PKCS#12 password must not contain control characters")
		}
	}
	return nil
}

// ownerRule applies the owner rule of credential management (as
// auth.authorizeFor and the users API do): the client certificates of an
// owner may be issued or revoked only by that owner, another owner or the
// system principal (admin socket, offline CLI), not by an administrator —
// revoking them locks the owner out while mtls.mode is required. by == nil
// (a trusted in-process caller) is not restricted.
func ownerRule(by *core.Principal, userID, userRole string) error {
	if by == nil || by.UserID == userID || by.IsSystem() || by.Role == core.RoleOwner {
		return nil
	}
	if core.Role(userRole) == core.RoleOwner {
		return core.Errorf(core.ErrForbidden, "only an owner can manage the client certificates of an owner")
	}
	return nil
}

// revokeReasonMax bounds the stored revoke reason (bytes).
const revokeReasonMax = 200

// clipReason makes a revoke reason valid UTF-8 (the query string can decode
// to arbitrary bytes), trims it and cuts it to revokeReasonMax bytes on a
// rune boundary.
func clipReason(s string) string {
	s = strings.TrimSpace(strings.ToValidUTF8(s, "�"))
	if len(s) <= revokeReasonMax {
		return s
	}
	n := revokeReasonMax
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	return strings.TrimSpace(s[:n])
}

// ensureClientCA returns the client CA, creating it when it is missing.
func (svc *Service) ensureClientCA(ctx context.Context) (*x509.Certificate, error) {
	if c := svc.snapshot().clientCA; c != nil {
		return c, nil
	}
	svc.opMu.Lock()
	defer svc.opMu.Unlock()
	st := svc.snapshot()
	if st.clientCA != nil {
		return st.clientCA, nil
	}
	cca, err := svc.createClientCA(ctx)
	if err != nil {
		return nil, err
	}
	next := st.clone()
	next.clientCA, next.clientPool = cca, poolOf(cca)
	svc.state.Store(next)
	return cca, nil
}

// IssueClient implements core.Certs: issues an mTLS client certificate for
// in.UserID signed by the client CA (EKU clientAuth, CN = username, SAN URI
// fileparcel:user:<id>) and returns it as PKCS#12 protected by in.Password
// (required here; the API generates one when the client sends none). The
// PKCS#12 holds only the key and the certificate, never the client CA:
// Android and Windows install a CA found in an imported .p12 as a trusted
// root, and the server verifies against its own pool anyway.
// in.Legacy selects the LegacyDES encoder for old Android/macOS versions.
// An owner's certificates are subject to the owner rule (ownerRule).
func (svc *Service) IssueClient(ctx context.Context, by *core.Principal, in core.ClientCertInput) (*core.ClientCert, []byte, error) {
	name, err := validClientName(in.Name)
	if err != nil {
		return nil, nil, err
	}
	if err := validP12Password(in.Password); err != nil {
		return nil, nil, err
	}
	days := in.Days
	if days == 0 {
		days = defaultClientDay
	}
	if days < 1 || days > maxClientDays {
		return nil, nil, core.Invalid("days", fmt.Sprintf("days must be between 1 and %d", maxClientDays))
	}
	if in.UserID == "" {
		return nil, nil, core.Invalid("user_id", "the user is required")
	}
	u, err := svc.lookupUser(ctx, in.UserID)
	if err != nil {
		return nil, nil, err
	}
	if err := ownerRule(by, u.ID, u.Role); err != nil {
		return nil, nil, err
	}
	if u.Status != core.UserActive {
		return nil, nil, core.Errorf(core.ErrConflict, "user %s is disabled", u.Username)
	}
	if !svc.keysUnlocked() {
		return nil, nil, core.ErrKeysLocked
	}
	ca, err := svc.ensureClientCA(ctx)
	if err != nil {
		return nil, nil, err
	}
	caKey, err := svc.openSealedKey(fileClientCAKey, aadClientCAKey)
	if err != nil {
		return nil, nil, err
	}
	if !publicKeysEqual(ca.PublicKey, caKey.Public()) {
		return nil, nil, errKeyMismatch("client CA")
	}
	key, err := newKey()
	if err != nil {
		return nil, nil, err
	}
	serial, err := newSerial()
	if err != nil {
		return nil, nil, err
	}
	now := svc.env.Now()
	notAfter := now.Add(time.Duration(days) * 24 * time.Hour)
	if notAfter.After(ca.NotAfter) {
		notAfter = ca.NotAfter
	}
	uri := &url.URL{Scheme: "fileparcel", Opaque: "user:" + u.ID}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: u.Username, Organization: []string{"FileParcel"}, OrganizationalUnit: []string{name}},
		NotBefore:    now.Add(-backdate),
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		URIs:         []*url.URL{uri},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca, key.Public(), caKey)
	if err != nil {
		return nil, nil, fmt.Errorf("certs: sign client certificate: %w", err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, nil, err
	}
	enc := pkcs12.Modern2023
	if in.Legacy {
		enc = pkcs12.LegacyDES
	}
	p12, err := enc.Encode(key, leaf, nil, in.Password)
	if err != nil {
		return nil, nil, fmt.Errorf("certs: encode PKCS#12: %w", err)
	}
	cc := &core.ClientCert{
		ID:                ids.New(ids.PrefixClientCert),
		UserID:            u.ID,
		Username:          u.Username,
		Name:              name,
		Serial:            serialHex(leaf),
		FingerprintSHA256: fingerprint(leaf.Raw),
		NotBefore:         leaf.NotBefore.UTC(),
		NotAfter:          leaf.NotAfter.UTC(),
		IssuedAt:          now.UTC(),
	}
	if by != nil {
		cc.IssuedBy = by.UserID
		if cc.IssuedBy == "" {
			cc.IssuedBy = by.Username
		}
	}
	err = svc.env.DB.Tx(ctx, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, `INSERT INTO client_certs (id, user_id, name, serial, fingerprint_sha256,
			not_before, not_after, issued_by, issued_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			cc.ID, cc.UserID, cc.Name, cc.Serial, cc.FingerprintSHA256, db.Ms(cc.NotBefore), db.Ms(cc.NotAfter),
			db.NullString(cc.IssuedBy), db.Ms(cc.IssuedAt)); err != nil {
			return err
		}
		if svc.env.Audit == nil {
			return nil
		}
		return svc.env.Audit.RecordTx(ctx, tx, core.AuditEntry{Action: core.ActClientCertIssue, TargetType: "client_cert",
			TargetID: cc.ID, TargetName: cc.Name, Details: map[string]any{"user_id": u.ID, "username": u.Username,
				"serial": cc.Serial, "not_after": cc.NotAfter.Format(time.RFC3339), "legacy": in.Legacy}})
	})
	if err != nil {
		if db.IsForeignKey(err) {
			return nil, nil, core.NotFoundf("user not found")
		}
		return nil, nil, fmt.Errorf("certs: store client certificate: %w", err)
	}
	svc.log.Info("client certificate issued", "id", cc.ID, "user", u.Username, "serial", cc.Serial)
	return cc, p12, nil
}

// serialHex formats a certificate serial as upper-case hex (the form stored
// in client_certs.serial and shown in CertInfo).
func serialHex(c *x509.Certificate) string { return strings.ToUpper(c.SerialNumber.Text(16)) }

// clientCursor is the keyset position of ListClient (issued_at DESC, id DESC).
type clientCursor struct {
	At int64  `json:"a"`
	ID string `json:"i"`
}

const clientCols = `c.id, c.user_id, COALESCE(u.username, ''), c.name, c.serial, c.fingerprint_sha256, c.not_before,
	c.not_after, COALESCE(c.issued_by, ''), c.issued_at, c.revoked_at, COALESCE(c.revoke_reason, ''), c.last_seen_at`

type rowScanner interface{ Scan(dest ...any) error }

// scanClient scans the clientCols columns followed by extra destinations.
func scanClient(r rowScanner, extra ...any) (*core.ClientCert, error) {
	var (
		cc             core.ClientCert
		nb, na, issued int64
		revoked, seen  sql.NullInt64
	)
	dest := append([]any{&cc.ID, &cc.UserID, &cc.Username, &cc.Name, &cc.Serial, &cc.FingerprintSHA256, &nb, &na,
		&cc.IssuedBy, &issued, &revoked, &cc.RevokeReason, &seen}, extra...)
	if err := r.Scan(dest...); err != nil {
		return nil, err
	}
	cc.NotBefore, cc.NotAfter, cc.IssuedAt = db.FromMs(nb), db.FromMs(na), db.FromMs(issued)
	cc.RevokedAt, cc.LastSeenAt = db.FromNullMs(revoked), db.FromNullMs(seen)
	return &cc, nil
}

// ListClient implements core.Certs: issued client certificates, newest
// first; userID "" lists every user's certificates. The cursor is opaque.
func (svc *Service) ListClient(ctx context.Context, q core.PageReq, userID string) (core.Page[core.ClientCert], error) {
	limit := q.Limit
	if limit <= 0 {
		limit = 100
	}
	limit = min(limit, 500)
	query := `SELECT ` + clientCols + ` FROM client_certs c LEFT JOIN users u ON u.id = c.user_id WHERE 1=1`
	var args []any
	if userID != "" {
		query += ` AND c.user_id = ?`
		args = append(args, userID)
	}
	if q.Cursor != "" {
		var cur clientCursor
		if err := decodeCursor(q.Cursor, &cur); err != nil {
			return core.Page[core.ClientCert]{}, core.Invalid("cursor", "invalid cursor")
		}
		query += ` AND (c.issued_at < ? OR (c.issued_at = ? AND c.id < ?))`
		args = append(args, cur.At, cur.At, cur.ID)
	}
	query += ` ORDER BY c.issued_at DESC, c.id DESC LIMIT ?`
	args = append(args, limit+1)
	rows, err := svc.env.DB.Query(ctx, query, args...)
	if err != nil {
		return core.Page[core.ClientCert]{}, fmt.Errorf("certs: list client certificates: %w", err)
	}
	defer rows.Close()
	items := []core.ClientCert{}
	for rows.Next() {
		cc, err := scanClient(rows)
		if err != nil {
			return core.Page[core.ClientCert]{}, fmt.Errorf("certs: list client certificates: %w", err)
		}
		items = append(items, *cc)
	}
	if err := rows.Err(); err != nil {
		return core.Page[core.ClientCert]{}, fmt.Errorf("certs: list client certificates: %w", err)
	}
	next := ""
	if len(items) > limit {
		items = items[:limit]
		last := items[len(items)-1]
		next = encodeCursor(clientCursor{At: db.Ms(last.IssuedAt), ID: last.ID})
	}
	return core.Page[core.ClientCert]{Items: items, NextCursor: next}, nil
}

// getClient loads one client certificate by id or serial, with the role of
// its user ("" when the user row is gone).
func (svc *Service) getClient(ctx context.Context, idOrSerial string) (*core.ClientCert, string, error) {
	row := svc.env.DB.QueryRow(ctx, `SELECT `+clientCols+`, COALESCE(u.role, '') FROM client_certs c
		LEFT JOIN users u ON u.id = c.user_id WHERE c.id = ? OR c.serial = ?`, idOrSerial, strings.ToUpper(idOrSerial))
	var role string
	cc, err := scanClient(row, &role)
	if db.IsNoRows(err) {
		return nil, "", core.NotFoundf("client certificate not found")
	}
	return cc, role, err
}

// RevokeClient implements core.Certs: revokes a client certificate (by id
// or serial). Holders of certs.manage (owners, admins and delegates; API
// tokens need the admin scope) may revoke any certificate except an owner's
// (the owner rule, ownerRule), other users only their own (others are
// reported as not found). Revoking twice is a no-op.
func (svc *Service) RevokeClient(ctx context.Context, by *core.Principal, id, reason string) error {
	cc, role, err := svc.getClient(ctx, strings.TrimSpace(id))
	if err != nil {
		return err
	}
	if by != nil && !by.Can(core.CapCertsManage) && by.UserID != cc.UserID {
		return core.NotFoundf("client certificate not found")
	}
	if err := ownerRule(by, cc.UserID, role); err != nil {
		return err
	}
	if cc.RevokedAt != nil {
		return nil
	}
	reason = clipReason(reason)
	now := svc.env.Now()
	err = svc.env.DB.Tx(ctx, func(tx *sql.Tx) error {
		res, err := tx.ExecContext(ctx, `UPDATE client_certs SET revoked_at = ?, revoke_reason = ? WHERE id = ? AND revoked_at IS NULL`,
			db.Ms(now), db.NullString(reason), cc.ID)
		if err != nil {
			return err
		}
		if n, _ := res.RowsAffected(); n == 0 || svc.env.Audit == nil {
			return nil
		}
		return svc.env.Audit.RecordTx(ctx, tx, core.AuditEntry{Action: core.ActClientCertRevoke, TargetType: "client_cert",
			TargetID: cc.ID, TargetName: cc.Name, Details: map[string]any{"user_id": cc.UserID, "serial": cc.Serial, "reason": reason}})
	})
	if err != nil {
		return fmt.Errorf("certs: revoke client certificate: %w", err)
	}
	svc.clients.reset()
	svc.log.Info("client certificate revoked", "id", cc.ID, "serial", cc.Serial)
	return nil
}

// Errors of CheckClient (all 401 unauthorized).
var (
	errClientMissing = core.Wrap(core.ErrUnauthorized, "a client certificate is required", nil)
	errClientInvalid = core.Wrap(core.ErrUnauthorized, "the client certificate is not valid for this server", nil)
	errClientRevoked = core.Wrap(core.ErrUnauthorized, "the client certificate has been revoked", nil)
)

// CheckClient implements core.Certs: validates the peer certificate of a TLS
// connection — chain to the current client CA, clientAuth usage, validity,
// a matching client_certs row that is not revoked and whose user is active
// (DESIGN §10.4). Results are cached for 30 s; last_seen_at is updated at
// most once a minute.
func (svc *Service) CheckClient(ctx context.Context, cs *tls.ConnectionState) (*core.ClientCert, error) {
	if cs == nil || len(cs.PeerCertificates) == 0 {
		return nil, errClientMissing
	}
	leaf := cs.PeerCertificates[0]
	st := svc.snapshot()
	if st.clientCA == nil {
		return nil, errClientInvalid
	}
	now := svc.env.Now()
	fp := fingerprint(leaf.Raw)
	cached, gen, ok := svc.clients.get(fp, now) // gen before the row is read
	if ok {
		return cached, nil
	}
	inter := x509.NewCertPool()
	for _, c := range cs.PeerCertificates[1:] {
		inter.AddCert(c)
	}
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: st.clientPool, Intermediates: inter, CurrentTime: now,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err != nil {
		return nil, core.Wrap(core.ErrUnauthorized, errClientInvalid.Error(), err)
	}
	var (
		cc     *core.ClientCert
		status string
	)
	row := svc.env.DB.QueryRow(ctx, `SELECT `+clientCols+`, COALESCE(u.status, '') FROM client_certs c
		LEFT JOIN users u ON u.id = c.user_id WHERE c.fingerprint_sha256 = ?`, fp)
	cc, err := scanClient(row, &status)
	if db.IsNoRows(err) {
		return nil, errClientInvalid
	}
	if err != nil {
		return nil, fmt.Errorf("certs: check client certificate: %w", err)
	}
	switch {
	case cc.Serial != serialHex(leaf):
		return nil, errClientInvalid
	case cc.RevokedAt != nil:
		return nil, errClientRevoked
	case status != core.UserActive:
		return nil, core.Wrap(core.ErrUnauthorized, "the account of this client certificate is disabled", nil)
	}
	if cc.LastSeenAt == nil || now.Sub(*cc.LastSeenAt) >= clientSeenEvery {
		seen := now
		cc.LastSeenAt = &seen
		wctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		err := svc.env.DB.Tx(wctx, func(tx *sql.Tx) error {
			_, err := tx.ExecContext(wctx, `UPDATE client_certs SET last_seen_at = ? WHERE id = ?`, db.Ms(now), cc.ID)
			return err
		})
		cancel()
		if err != nil {
			svc.log.Warn("cannot record client certificate use", "id", cc.ID, "err", err)
		}
	}
	svc.clients.put(fp, *cc, now, gen)
	return cc, nil
}

// encodeCursor / decodeCursor implement opaque base64url JSON cursors (the
// same scheme as httpx, which service packages must not import).
func encodeCursor(v any) string {
	b, _ := json.Marshal(v)
	return base64.RawURLEncoding.EncodeToString(b)
}

func decodeCursor(s string, v any) error {
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return err
	}
	if len(b) > 512 {
		return errors.New("cursor too long")
	}
	return json.Unmarshal(b, v)
}
