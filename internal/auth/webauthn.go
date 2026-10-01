package auth

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"

	"fileparcel/internal/core"
	"fileparcel/internal/db"
	"fileparcel/internal/ids"
)

// webAuthnConfig is the go-webauthn relying party built from the settings.
type webAuthnConfig struct {
	wa   *webauthn.WebAuthn
	rpID string
}

// flow kinds.
const (
	flowRegister = iota + 1
	flowLogin
)

// flow is a pending WebAuthn ceremony (kept in memory for FlowTTL).
type flow struct {
	kind       int
	userID     string // register: the owner; login: the expected user ("" = discoverable)
	expectName string // discoverable login begun with a username
	data       webauthn.SessionData
	expires    time.Time
}

func credentialAAD(id string) string { return "webauthn_credentials.credential_enc|" + id }

// RPID returns the WebAuthn relying party ID (auth.webauthn_rp_id, else the
// effective mDNS name, else "<mdns.name or server.name>.local").
func (s *Service) RPID() string {
	id, _ := s.rpConfig()
	return id
}

// rpConfig derives the RP ID and the allowed origins from the settings:
// https://<rpid>:<https_port>, https://<rpid>, the origin of
// server.public_url when its host is the RP ID or a subdomain of it, and
// auth.webauthn_origins.
//
// Without an explicit auth.webauthn_rp_id the RP ID is the *effective* mDNS
// FQDN (fileparcel-2.local after a §10.5 collision rename), the same name
// netinfo.mdnsName feeds into the certificate SANs — the RP ID must never
// name a host the leaf does not cover, or the browser refuses every passkey
// ceremony. It falls back to the configured name when mDNS is off or not
// bound yet.
func (s *Service) rpConfig() (string, []string) {
	rpID := strings.ToLower(strings.TrimSuffix(s.settingString("auth.webauthn_rp_id"), "."))
	if rpID == "" {
		if ref := s.mdns.Load(); ref != nil && ref.m != nil {
			if st := ref.m.Status(); st.Name != "" && st.State != core.MDNSOff {
				rpID = strings.ToLower(strings.TrimSuffix(st.Name, "."))
			}
		}
	}
	if rpID == "" {
		name := s.settingString("mdns.name")
		if name == "" {
			name = s.settingString("server.name")
		}
		if name == "" && s.env.Config != nil {
			name = s.env.Config.Server.Name
		}
		if name == "" {
			name = "fileparcel"
		}
		rpID = strings.ToLower(name) + ".local"
	}
	port := s.settingInt("server.https_port", 0)
	if port == 0 && s.env.Config != nil {
		port = int64(s.env.Config.Server.HTTPSPort)
	}
	var origins []string
	add := func(o string) {
		if o != "" && !slices.Contains(origins, o) {
			origins = append(origins, o)
		}
	}
	if port > 0 && port != 443 {
		add("https://" + rpID + ":" + strconv.FormatInt(port, 10))
	}
	add("https://" + rpID)
	pub := s.settingString("server.public_url")
	if pub == "" && s.env.Config != nil {
		pub = s.env.Config.Server.PublicURL
	}
	if u, err := url.Parse(pub); err == nil && u.Scheme == "https" && u.Host != "" {
		if h := strings.ToLower(u.Hostname()); h == rpID || strings.HasSuffix(h, "."+rpID) {
			add("https://" + strings.ToLower(u.Host))
		}
	}
	// The other names this server answers to (the same sources as the host
	// allowlist, mw.knownNames) that belong to this RP ID. A deployment with
	// rp_id example.com served at files.example.com is the normal shape, the
	// browser sends that origin, and the UI offers the passkey button on
	// every subdomain of the RP ID — so the ceremony has to work there
	// instead of failing with "the passkey could not be verified". Wildcard
	// patterns are skipped on purpose: accepting "*.rpID" as an origin would
	// let any host under the domain relay ceremonies to us.
	if s.env.Settings != nil {
		for _, k := range []string{"network.extra_hosts", "tls.extra_sans", "acme.domains"} {
			for _, n := range s.env.Settings.Strings(k) {
				h := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(n), "."))
				if h == "" || strings.ContainsAny(h, "*:/ ") || net.ParseIP(h) != nil {
					continue
				}
				if h != rpID && !strings.HasSuffix(h, "."+rpID) {
					continue
				}
				if port > 0 && port != 443 {
					add("https://" + h + ":" + strconv.FormatInt(port, 10))
				}
				add("https://" + h)
			}
		}
		for _, o := range s.env.Settings.Strings("auth.webauthn_origins") {
			if n, err := normalizeOrigin(o); err == nil {
				add(n)
			}
		}
	}
	return rpID, origins
}

// webAuthn returns the relying party for the current settings, rebuilding it
// whenever the RP ID, the origins or the instance name changed (so
// settings.changed takes effect on the next ceremony).
func (s *Service) webAuthn() (*webAuthnConfig, error) {
	rpID, origins := s.rpConfig()
	name := s.instanceName()
	key := rpID + "\x00" + strings.Join(origins, " ") + "\x00" + name
	s.waMu.Lock()
	defer s.waMu.Unlock()
	if s.wa != nil && s.waKey == key {
		return s.wa, nil
	}
	wa, err := webauthn.New(&webauthn.Config{
		RPID:                  rpID,
		RPDisplayName:         name,
		RPOrigins:             origins,
		AttestationPreference: protocol.PreferNoAttestation,
		AuthenticatorSelection: protocol.AuthenticatorSelection{
			ResidentKey:        protocol.ResidentKeyRequirementPreferred,
			RequireResidentKey: protocol.ResidentKeyNotRequired(),
			UserVerification:   protocol.VerificationPreferred,
		},
		Timeouts: webauthn.TimeoutsConfig{
			Login:        webauthn.TimeoutConfig{Timeout: FlowTTL, TimeoutUVD: FlowTTL},
			Registration: webauthn.TimeoutConfig{Timeout: FlowTTL, TimeoutUVD: FlowTTL},
		},
	})
	if err != nil {
		s.log.Error("webauthn configuration invalid", "rp_id", rpID, "err", err)
		return nil, core.Wrap(core.ErrUnavailable, "passkeys are not configured correctly (check auth.webauthn_rp_id)", err)
	}
	if s.wa != nil && s.wa.rpID != rpID {
		// Credentials are stored and looked up per rp_id, so a rename
		// orphans the passkeys enrolled under the old name (DESIGN §19.1).
		s.log.Warn("webauthn rp id changed; passkeys enrolled under the old name must be re-enrolled (pin auth.webauthn_rp_id to avoid this)",
			"old", s.wa.rpID, "new", rpID)
	}
	s.wa, s.waKey = &webAuthnConfig{wa: wa, rpID: rpID}, key
	return s.wa, nil
}

// ---------- flows ----------

func (s *Service) putFlow(f *flow) (string, error) {
	now := s.now()
	f.expires = now.Add(FlowTTL)
	id := ids.Token(24)
	s.flowMu.Lock()
	defer s.flowMu.Unlock()
	// Abandoned ceremonies are dropped lazily: at most once per FlowTTL, or
	// when the table is full.
	if len(s.flows) >= maxFlows || now.Sub(s.flowSweep) >= FlowTTL {
		s.flowSweep = now
		for k, v := range s.flows {
			if !now.Before(v.expires) {
				delete(s.flows, k)
			}
		}
		if len(s.flows) >= maxFlows {
			return "", core.Errorf(core.ErrRateLimited, "too many pending passkey requests; try again in a few minutes")
		}
	}
	s.flows[id] = f
	return id, nil
}

// takeFlow removes and returns a live flow of the given kind (single use).
func (s *Service) takeFlow(id string, kind int) *flow {
	s.flowMu.Lock()
	defer s.flowMu.Unlock()
	f, ok := s.flows[id]
	if !ok {
		return nil
	}
	delete(s.flows, id)
	if f.kind != kind || !s.now().Before(f.expires) {
		return nil
	}
	return f
}

// ---------- WebAuthn users ----------

// waUser adapts a user to webauthn.User.
type waUser struct {
	id          string
	handle      []byte
	name        string
	display     string
	creds       []webauthn.Credential
	rowByCredID map[string]string // credential id (raw) → webauthn_credentials.id
}

func (u *waUser) WebAuthnID() []byte                         { return u.handle }
func (u *waUser) WebAuthnName() string                       { return u.name }
func (u *waUser) WebAuthnDisplayName() string                { return u.display }
func (u *waUser) WebAuthnCredentials() []webauthn.Credential { return u.creds }

// loadWAUser loads the handle and the credentials (for rpID) of u.
func (s *Service) loadWAUser(ctx context.Context, u *core.User, rpID string) (*waUser, error) {
	wu := &waUser{id: u.ID, name: u.Username, display: u.DisplayName, rowByCredID: map[string]string{}}
	if wu.display == "" {
		wu.display = u.Username
	}
	wu.handle = u.WebAuthnHandle
	if len(wu.handle) == 0 {
		if err := s.env.DB.QueryRow(ctx, `SELECT webauthn_handle FROM users WHERE id = ?`, u.ID).Scan(&wu.handle); err != nil {
			return nil, err
		}
	}
	if len(wu.handle) == 0 || len(wu.handle) > 64 {
		return nil, core.Errorf(core.ErrUnavailable, "this account has no valid passkey handle")
	}
	k, err := s.keys()
	if err != nil {
		return nil, err
	}
	rows, err := s.env.DB.Query(ctx, `SELECT id, credential_enc, sign_count FROM webauthn_credentials
		WHERE user_id = ? AND rp_id = ? ORDER BY created_at, id`, u.ID, rpID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var id, enc string
		var count int64
		if err := rows.Scan(&id, &enc, &count); err != nil {
			return nil, err
		}
		plain, err := k.OpenField(credentialAAD(id), enc)
		if err != nil {
			s.log.Error("passkey credential cannot be decrypted", "passkey", id, "err", err)
			continue
		}
		var c webauthn.Credential
		if err := json.Unmarshal(plain, &c); err != nil {
			s.log.Error("passkey credential is corrupt", "passkey", id, "err", err)
			continue
		}
		c.Authenticator.SignCount = uint32(count)
		wu.creds = append(wu.creds, c)
		wu.rowByCredID[string(c.ID)] = id
	}
	return wu, rows.Err()
}

// ---------- registration ----------

// PasskeyRegisterBegin implements core.Auth: starts registering a passkey
// for the principal's account (requires an open step-up window). It returns
// the creation options ({"publicKey": …}) and the flow id for
// PasskeyRegisterFinish.
//
// Step-up, because a passkey is more than a second factor: it signs in on
// its own (passwordless), satisfies Elevate, and survives a password change.
// Without it a hijacked session could plant one and keep — and elevate —
// its way back in. A user who still has to enroll (EnrollRequired) elevates
// with the password first.
func (s *Service) PasskeyRegisterBegin(ctx context.Context, p *core.Principal) (json.RawMessage, string, error) {
	if !s.passkeysEnabled() {
		return nil, "", core.Errorf(core.ErrForbidden, "passkeys are turned off on this server")
	}
	u, err := s.requireUser(ctx, p)
	if err != nil {
		return nil, "", err
	}
	if !p.Elevated(s.now()) {
		return nil, "", core.ErrElevationRequired
	}
	rp, err := s.webAuthn()
	if err != nil {
		return nil, "", err
	}
	wu, err := s.loadWAUser(ctx, u, rp.rpID)
	if err != nil {
		return nil, "", err
	}
	creation, data, err := rp.wa.BeginRegistration(wu, webauthn.WithExclusions(webauthn.Credentials(wu.creds).CredentialDescriptors()))
	if err != nil {
		return nil, "", core.Wrap(core.ErrUnavailable, "could not start the passkey registration", err)
	}
	flowID, err := s.putFlow(&flow{kind: flowRegister, userID: u.ID, data: *data})
	if err != nil {
		return nil, "", err
	}
	opts, err := json.Marshal(creation)
	if err != nil {
		return nil, "", err
	}
	return opts, flowID, nil
}

// PasskeyRegisterFinish implements core.Auth: verifies the attestation
// response and stores the credential (field-encrypted). Like
// PasskeyRegisterBegin it requires an open step-up window, checked before
// the flow is taken so that a window that closed during the ceremony can be
// reopened and the same request retried.
func (s *Service) PasskeyRegisterFinish(ctx context.Context, p *core.Principal, flowID string, resp []byte, name string) (*core.Passkey, error) {
	if !s.passkeysEnabled() {
		return nil, core.Errorf(core.ErrForbidden, "passkeys are turned off on this server")
	}
	u, err := s.requireUser(ctx, p)
	if err != nil {
		return nil, err
	}
	if !p.Elevated(s.now()) {
		return nil, core.ErrElevationRequired
	}
	if strings.TrimSpace(name) == "" {
		name = "Passkey"
	}
	if name, err = cleanName("name", name); err != nil {
		return nil, err
	}
	f := s.takeFlow(flowID, flowRegister)
	if f == nil || f.userID != u.ID {
		return nil, core.Invalid("flow_id", "the passkey registration expired; please try again")
	}
	rp, err := s.webAuthn()
	if err != nil {
		return nil, err
	}
	parsed, err := protocol.ParseCredentialCreationResponseBytes(resp)
	if err != nil {
		s.log.Debug("passkey registration response rejected", "err", err)
		return nil, core.Invalid("credential", "the passkey response is malformed")
	}
	wu, err := s.loadWAUser(ctx, u, f.data.GetRelyingPartyID(rp.rpID))
	if err != nil {
		return nil, err
	}
	cred, err := rp.wa.CreateCredential(wu, f.data, parsed)
	if err != nil {
		s.log.Info("passkey registration failed verification", "user", u.ID, "err", err)
		return nil, core.Invalid("credential", "the passkey could not be verified")
	}
	k, err := s.keys()
	if err != nil {
		return nil, err
	}
	pk := &core.Passkey{
		ID: ids.New(ids.PrefixPasskey), UserID: u.ID, Name: name, CredentialID: cred.ID,
		AAGUID: formatAAGUID(cred.Authenticator.AAGUID), SignCount: cred.Authenticator.SignCount,
		BackupEligible: cred.Flags.BackupEligible, BackupState: cred.Flags.BackupState,
		RPID: f.data.GetRelyingPartyID(rp.rpID), CreatedAt: s.now(),
	}
	plain, err := json.Marshal(cred)
	if err != nil {
		return nil, err
	}
	sealed, err := k.SealField(credentialAAD(pk.ID), plain)
	if err != nil {
		return nil, err
	}
	err = s.env.DB.Tx(ctx, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `INSERT INTO webauthn_credentials (id, user_id, credential_id, name, credential_enc,
			aaguid, sign_count, backup_eligible, backup_state, rp_id, created_at)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			pk.ID, pk.UserID, pk.CredentialID, pk.Name, sealed, nullBytes(cred.Authenticator.AAGUID), pk.SignCount,
			db.Bool(pk.BackupEligible), db.Bool(pk.BackupState), pk.RPID, db.Ms(pk.CreatedAt))
		if err != nil {
			if db.IsUnique(err) {
				return core.Errorf(core.ErrConflict, "this passkey is already registered")
			}
			return err
		}
		return s.recordTx(ctx, tx, core.AuditEntry{Action: core.ActPasskeyAdd, TargetType: "passkey", TargetID: pk.ID, TargetName: pk.Name,
			Details: map[string]any{"user_id": u.ID, "aaguid": pk.AAGUID, "backup_eligible": pk.BackupEligible}})
	})
	if err != nil {
		return nil, err
	}
	return pk, nil
}

func nullBytes(b []byte) any {
	if len(b) == 0 {
		return nil
	}
	return b
}

// formatAAGUID renders a 16-byte AAGUID as a UUID ("" for none/zero).
func formatAAGUID(b []byte) string {
	if len(b) != 16 || bytes.Equal(b, make([]byte, 16)) {
		return ""
	}
	h := hex.EncodeToString(b)
	return h[0:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:32]
}

// ---------- login / assertion ----------

// PasskeyLoginBegin implements core.Auth. When the context carries a
// signed-in or password-verified principal (second factor, elevation) and
// username is empty or its own, the options list that user's credentials
// (user verification is required for an already fully authenticated session,
// i.e. step-up, and preferred for the second factor after a password).
// Otherwise the ceremony is discoverable (passwordless; user verification
// required) and username, if given, only restricts which account may finish
// it — the options never reveal whether the account exists.
func (s *Service) PasskeyLoginBegin(ctx context.Context, username string) (json.RawMessage, string, error) {
	if !s.passkeysEnabled() {
		return nil, "", core.Errorf(core.ErrForbidden, "passkeys are turned off on this server")
	}
	rp, err := s.webAuthn()
	if err != nil {
		return nil, "", err
	}
	username = strings.TrimSpace(username)
	f := &flow{kind: flowLogin}
	var assertion *protocol.CredentialAssertion
	var data *webauthn.SessionData
	if p := core.PrincipalFrom(ctx); p != nil && p.UserID != "" && p.Via == core.ViaSession &&
		(username == "" || strings.EqualFold(username, p.Username)) {
		u, err := s.activeUser(ctx, p.UserID)
		if err != nil {
			return nil, "", err
		}
		wu, err := s.loadWAUser(ctx, u, rp.rpID)
		if err != nil {
			return nil, "", err
		}
		if len(wu.creds) == 0 {
			return nil, "", core.NotFoundf("no passkey is registered for your account on %s", rp.rpID)
		}
		f.userID = u.ID
		// Second factor after the password: presence is enough. Step-up on
		// an already full session: require the PIN / biometric check, and
		// ask for it at begin time so the browser prompts for it instead of
		// failing the ceremony afterwards (Elevate re-checks it).
		uv := protocol.VerificationPreferred
		if p.AuthLevel >= core.AuthLevelFull {
			uv = protocol.VerificationRequired
		}
		assertion, data, err = rp.wa.BeginLogin(wu, webauthn.WithUserVerification(uv))
		if err != nil {
			return nil, "", core.Wrap(core.ErrUnavailable, "could not start the passkey sign-in", err)
		}
	} else {
		f.expectName = clip(username, 256)
		assertion, data, err = rp.wa.BeginDiscoverableLogin(webauthn.WithUserVerification(protocol.VerificationRequired))
		if err != nil {
			return nil, "", core.Wrap(core.ErrUnavailable, "could not start the passkey sign-in", err)
		}
	}
	f.data = *data
	flowID, err := s.putFlow(f)
	if err != nil {
		return nil, "", err
	}
	opts, err := json.Marshal(assertion)
	if err != nil {
		return nil, "", err
	}
	return opts, flowID, nil
}

// assertionResult is a verified passkey assertion.
type assertionResult struct {
	user   *core.User
	rowID  string // webauthn_credentials.id
	cred   *webauthn.Credential
	uv     bool // user verified
	sealed string
}

// verifyAssertion validates a login assertion for flow f. It returns the
// user and the updated credential (not yet stored; see storeAssertion).
func (s *Service) verifyAssertion(ctx context.Context, f *flow, resp []byte) (*assertionResult, error) {
	rp, err := s.webAuthn()
	if err != nil {
		return nil, err
	}
	parsed, err := protocol.ParseCredentialRequestResponseBytes(resp)
	if err != nil {
		return nil, errPasskeyFailed
	}
	rpID := f.data.GetRelyingPartyID(rp.rpID)
	res := &assertionResult{}
	var wu *waUser
	if f.userID != "" {
		if res.user, err = s.activeUser(ctx, f.userID); err != nil {
			return nil, errPasskeyFailed
		}
		if wu, err = s.loadWAUser(ctx, res.user, rpID); err != nil {
			return nil, err
		}
		if res.cred, err = rp.wa.ValidateLogin(wu, f.data, parsed); err != nil {
			s.log.Info("passkey assertion rejected", "user", f.userID, "err", err)
			return nil, errPasskeyFailed
		}
	} else {
		var lookupErr error
		handler := func(rawID, userHandle []byte) (webauthn.User, error) {
			var userID string
			err := s.env.DB.QueryRow(ctx, `SELECT c.user_id FROM webauthn_credentials c JOIN users u ON u.id = c.user_id
				WHERE c.credential_id = ? AND u.webauthn_handle = ?`, rawID, userHandle).Scan(&userID)
			if err != nil {
				lookupErr = err
				return nil, errors.New("unknown credential")
			}
			if res.user, err = s.activeUser(ctx, userID); err != nil {
				lookupErr = err
				return nil, errors.New("inactive user")
			}
			if wu, err = s.loadWAUser(ctx, res.user, rpID); err != nil {
				lookupErr = err
				return nil, errors.New("user unavailable")
			}
			return wu, nil
		}
		if _, res.cred, err = rp.wa.ValidatePasskeyLogin(handler, f.data, parsed); err != nil {
			if lookupErr != nil && !db.IsNoRows(lookupErr) && !errors.Is(lookupErr, core.ErrUnauthorized) {
				return nil, lookupErr
			}
			s.log.Info("passkey assertion rejected", "err", err)
			return nil, errPasskeyFailed
		}
		if f.expectName != "" && !strings.EqualFold(f.expectName, res.user.Username) {
			return nil, errPasskeyFailed
		}
	}
	if res.cred.Authenticator.CloneWarning {
		s.log.Warn("passkey sign counter went backwards (possible cloned authenticator); sign-in refused", "user", res.user.ID)
		return nil, errPasskeyFailed
	}
	res.rowID = wu.rowByCredID[string(res.cred.ID)]
	if res.rowID == "" {
		return nil, errPasskeyFailed
	}
	res.uv = parsed.Response.AuthenticatorData.Flags.HasUserVerified()
	k, err := s.keys()
	if err != nil {
		return nil, err
	}
	plain, err := json.Marshal(res.cred)
	if err != nil {
		return nil, err
	}
	if res.sealed, err = k.SealField(credentialAAD(res.rowID), plain); err != nil {
		return nil, err
	}
	return res, nil
}

// storeAssertion writes the new sign count, flags and last use of a
// credential inside tx.
func storeAssertion(ctx context.Context, tx *sql.Tx, a *assertionResult, now time.Time) error {
	_, err := tx.ExecContext(ctx, `UPDATE webauthn_credentials SET sign_count = ?, backup_state = ?, credential_enc = ?,
		last_used_at = ? WHERE id = ?`,
		int64(a.cred.Authenticator.SignCount), db.Bool(a.cred.Flags.BackupState), a.sealed, db.Ms(now), a.rowID)
	return err
}

// PasskeyLoginFinish implements core.Auth. When p is the password-verified
// (AuthLevel 1) session of the passkey's owner, the passkey completes that
// login as its second factor (remember is ignored: that session keeps the
// choice made at the password step); otherwise it is a passwordless sign-in,
// which requires user verification (PIN / biometrics) and creates a new
// session — remembered ("keep me signed in") when remember is set.
func (s *Service) PasskeyLoginFinish(ctx context.Context, flowID string, resp []byte, remember bool, p *core.Principal, meta core.ReqMeta) (*core.LoginResult, error) {
	if !s.passkeysEnabled() {
		return nil, core.Errorf(core.ErrForbidden, "passkeys are turned off on this server")
	}
	if err := s.failAllowed(meta.IP); err != nil {
		return nil, err
	}
	f := s.takeFlow(flowID, flowLogin)
	if f == nil {
		s.failed(meta.IP)
		return nil, core.Errorf(core.ErrUnauthorized, "the passkey request expired; please try again")
	}
	a, err := s.verifyAssertion(ctx, f, resp)
	if err != nil {
		if errors.Is(err, errPasskeyFailed) {
			s.passkeyFailed(ctx, f.userID, meta)
		}
		return nil, err
	}
	u := a.user
	if u.Locked(s.now()) {
		s.passkeyFailed(ctx, "", meta)
		return nil, errPasskeyFailed
	}
	store := func(tx *sql.Tx) error { return storeAssertion(ctx, tx, a, s.now()) }
	if p != nil && p.Via == core.ViaSession && p.SessionID != "" && p.AuthLevel < core.AuthLevelFull && p.UserID == u.ID {
		return s.completeMFA(ctx, p, u, core.MFAPasskey, meta, store)
	}
	if !a.uv {
		s.passkeyFailed(ctx, u.ID, meta)
		return nil, core.Errorf(core.ErrUnauthorized, "signing in with a passkey needs its PIN or biometric check")
	}
	res, err := s.startSession(ctx, u, sessionSpec{userID: u.ID, level: core.AuthLevelFull, method: core.MFAPasskey, remember: remember, meta: meta},
		map[string]any{"method": "passkey"}, store)
	if err != nil {
		return nil, err
	}
	res.EnrollRequired = false // a passkey is a second factor
	return res, nil
}

// passkeyFailed counts a failed passkey attempt (per IP, and against the
// account when it is known).
func (s *Service) passkeyFailed(ctx context.Context, userID string, meta core.ReqMeta) {
	s.failed(meta.IP)
	e := core.AuditEntry{Action: core.ActAuthLogin, Outcome: core.OutcomeFailure, ActorVia: string(core.ViaSession),
		Details: map[string]any{"method": "passkey"}}
	if userID != "" {
		if u, err := s.users.Get(ctx, userID); err == nil {
			e = asUser(e, u, core.ViaSession)
			s.countFailure(ctx, u, meta)
		}
	}
	s.record(ctx, withMeta(e, meta))
}

// ---------- management ----------

// PasskeyOnlyAccounts counts the active accounts whose only usable second
// factor is a passkey: a passkey, no confirmed authenticator app and no
// unused recovery code. Turning auth.passkeys off leaves every one of them
// with a password-only session it can never complete (methods() drops
// "passkey", and there is nothing else), recoverable only with "fileparcel
// user reset-mfa" over the admin socket — so the settings handler asks
// before it happens, the way the network access policy does.
func (s *Service) PasskeyOnlyAccounts(ctx context.Context) (int, error) {
	var n int
	err := s.env.DB.Read(ctx, func(tx *sql.Tx) error {
		return tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM users u
			WHERE u.status = 'active'
			  AND EXISTS (SELECT 1 FROM webauthn_credentials w WHERE w.user_id = u.id)
			  AND NOT EXISTS (SELECT 1 FROM totp_secrets t WHERE t.user_id = u.id AND t.confirmed_at IS NOT NULL)
			  AND NOT EXISTS (SELECT 1 FROM recovery_codes r WHERE r.user_id = u.id AND r.used_at IS NULL)`).Scan(&n)
	})
	return n, err
}

const passkeyColumns = `id, user_id, credential_id, name, aaguid, sign_count, backup_eligible, backup_state, rp_id, created_at, last_used_at`

func scanPasskey(sc rowScanner) (*core.Passkey, error) {
	var pk core.Passkey
	var aaguid []byte
	var count, be, bs, created int64
	var used sql.NullInt64
	if err := sc.Scan(&pk.ID, &pk.UserID, &pk.CredentialID, &pk.Name, &aaguid, &count, &be, &bs, &pk.RPID, &created, &used); err != nil {
		return nil, err
	}
	pk.AAGUID = formatAAGUID(aaguid)
	pk.SignCount = uint32(count)
	pk.BackupEligible, pk.BackupState = be != 0, bs != 0
	pk.CreatedAt, pk.LastUsedAt = db.FromMs(created), db.FromNullMs(used)
	return &pk, nil
}

// ListPasskeys implements core.Auth (oldest first; credentials not decrypted).
func (s *Service) ListPasskeys(ctx context.Context, userID string) ([]core.Passkey, error) {
	rows, err := s.env.DB.Query(ctx, `SELECT `+passkeyColumns+` FROM webauthn_credentials WHERE user_id = ?
		ORDER BY created_at, id`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []core.Passkey{}
	for rows.Next() {
		pk, err := scanPasskey(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *pk)
	}
	return out, rows.Err()
}

// ownedPasskey returns the owner of passkey id if p may manage it: its own
// passkeys only, except over the admin socket (ownCredentialsOnly).
func (s *Service) ownedPasskey(ctx context.Context, p *core.Principal, id string) (string, error) {
	var owner, name string
	err := s.env.DB.QueryRow(ctx, `SELECT user_id, name FROM webauthn_credentials WHERE id = ?`, id).Scan(&owner, &name)
	if err != nil {
		if db.IsNoRows(err) {
			return "", core.NotFoundf("passkey not found")
		}
		return "", err
	}
	if err := s.authorizeFor(ctx, ownCredentialsOnly(p), owner, ""); err != nil {
		if errors.Is(err, core.ErrForbidden) || errors.Is(err, core.ErrNotFound) {
			return "", core.NotFoundf("passkey not found")
		}
		return "", err
	}
	return owner, nil
}

// RenamePasskey implements core.Auth.
func (s *Service) RenamePasskey(ctx context.Context, p *core.Principal, id, name string) error {
	name, err := cleanName("name", name)
	if err != nil {
		return err
	}
	if _, err := s.ownedPasskey(ctx, p, id); err != nil {
		return err
	}
	_, err = s.env.DB.Exec(ctx, `UPDATE webauthn_credentials SET name = ? WHERE id = ?`, name, id)
	return err
}

// DeletePasskey implements core.Auth (requires an open step-up window).
// Recovery codes are removed when no second factor remains.
func (s *Service) DeletePasskey(ctx context.Context, p *core.Principal, id string) error {
	owner, err := s.ownedPasskey(ctx, p, id)
	if err != nil {
		return err
	}
	if !p.Elevated(s.now()) {
		return core.ErrElevationRequired
	}
	return s.env.DB.Tx(ctx, func(tx *sql.Tx) error {
		res, err := tx.ExecContext(ctx, `DELETE FROM webauthn_credentials WHERE id = ? AND user_id = ?`, id, owner)
		if err != nil {
			return err
		}
		if n, _ := res.RowsAffected(); n == 0 {
			return core.NotFoundf("passkey not found")
		}
		if err := dropOrphanRecovery(ctx, tx, owner); err != nil {
			return err
		}
		return s.recordTx(ctx, tx, core.AuditEntry{Action: core.ActPasskeyRemove, TargetType: "passkey", TargetID: id,
			Details: map[string]any{"user_id": owner}})
	})
}
