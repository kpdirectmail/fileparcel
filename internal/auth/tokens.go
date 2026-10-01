package auth

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"slices"
	"strings"
	"time"

	"fileparcel/internal/core"
	"fileparcel/internal/db"
	"fileparcel/internal/ids"
)

// parseToken splits "fpt_<id suffix>_<secret>" and returns the token id.
func parseToken(tok string) (string, bool) {
	rest, ok := strings.CutPrefix(tok, TokenPrefix)
	if !ok {
		return "", false
	}
	suffix, secret, ok := strings.Cut(rest, "_")
	if !ok || len(secret) != ids.TokenLen(apiSecretBytes) || !ids.ValidToken(secret) {
		return "", false
	}
	id := ids.PrefixToken + "_" + suffix
	if !ids.Valid(ids.PrefixToken, id) {
		return "", false
	}
	return id, true
}

// newTokenSecret returns the secret string of token id.
func newTokenSecret(id string) string {
	return TokenPrefix + strings.TrimPrefix(id, ids.PrefixToken+"_") + "_" + ids.Token(apiSecretBytes)
}

const tokenColumns = `k.id, k.user_id, k.name, k.scopes, k.created_at, k.expires_at, k.last_used_at, COALESCE(k.last_used_ip, ''), k.revoked_at`

func scanToken(sc rowScanner, extra ...any) (*core.APIToken, error) {
	var t core.APIToken
	var scopes string
	var created int64
	var expires, used, revoked sql.NullInt64
	if err := sc.Scan(append([]any{&t.ID, &t.UserID, &t.Name, &scopes, &created, &expires, &used, &t.LastUsedIP, &revoked}, extra...)...); err != nil {
		return nil, err
	}
	t.Scopes, t.Elevated = decodeScopes(scopes)
	t.CreatedAt = db.FromMs(created)
	t.ExpiresAt, t.LastUsedAt, t.RevokedAt = db.FromNullMs(expires), db.FromNullMs(used), db.FromNullMs(revoked)
	return &t, nil
}

// decodeScopes parses the scopes column (JSON array; ScopeElevated marks
// --elevated tokens).
func decodeScopes(s string) ([]string, bool) {
	var list []string
	if err := json.Unmarshal([]byte(s), &list); err != nil {
		list = strings.Fields(s)
	}
	out := make([]string, 0, len(list))
	elevated := false
	for _, v := range list {
		switch {
		case v == core.ScopeElevated:
			elevated = true
		case slices.Contains(core.AllScopes, v):
			out = append(out, v)
		}
	}
	return out, elevated
}

// authenticateToken resolves "Authorization: Bearer fpt_…".
func (s *Service) authenticateToken(r *http.Request, header string) (*core.Principal, error) {
	scheme, cred, ok := strings.Cut(strings.TrimSpace(header), " ")
	cred = strings.TrimSpace(cred)
	if !ok || !strings.EqualFold(scheme, "Bearer") {
		return nil, errBadToken
	}
	id, ok := parseToken(cred)
	if !ok {
		return nil, errBadToken
	}
	ctx := r.Context()
	var hash []byte
	var username, role, status string
	var hasMFA bool
	var roleID, roleName, perms sql.NullString
	row := s.env.DB.QueryRow(ctx, `SELECT `+tokenColumns+`, k.token_hash, u.username, u.role, u.status,
		(EXISTS (SELECT 1 FROM totp_secrets ts WHERE ts.user_id = u.id AND ts.confirmed_at IS NOT NULL)
		 OR EXISTS (SELECT 1 FROM webauthn_credentials wc WHERE wc.user_id = u.id)), `+principalRoleCols+`
		FROM api_tokens k JOIN users u ON u.id = k.user_id`+principalRoleJoin+` WHERE k.id = ?`, id)
	t, err := scanToken(row, &hash, &username, &role, &status, &hasMFA, &roleID, &roleName, &perms)
	if err != nil {
		if db.IsNoRows(err) {
			return nil, errBadToken
		}
		return nil, err
	}
	now := s.now()
	if !ids.EqualBytes(hash, ids.HashToken(cred)) || t.RevokedAt != nil ||
		(t.ExpiresAt != nil && !now.Before(*t.ExpiresAt)) || status != core.UserActive {
		return nil, errBadToken
	}
	ip := s.clientIP(r)
	if t.LastUsedAt == nil || now.Sub(*t.LastUsedAt) >= touchInterval || t.LastUsedIP != ip.String() {
		if _, err := s.env.DB.Exec(ctx, `UPDATE api_tokens SET last_used_at = ?, last_used_ip = ? WHERE id = ?`,
			db.Ms(now), ip.String(), t.ID); err != nil {
			s.log.Warn("token touch failed", "token", t.ID, "err", err)
		}
	}
	p := &core.Principal{
		UserID: t.UserID, Username: username, Role: core.Role(role), Via: core.ViaToken, TokenID: t.ID,
		Scopes: t.Scopes, AuthLevel: core.AuthLevelFull, IP: ip, UserAgent: r.UserAgent(),
	}
	// The role's capabilities; Principal.Can applies the scopes (server
	// permissions need the admin scope).
	s.setRoleCaps(p, roleID, roleName, perms)
	// --elevated admin tokens count as step-up elevated until they expire,
	// while their owner is staff (a demoted owner's token stops counting).
	if t.Elevated && t.ExpiresAt != nil && p.Staff() && slices.Contains(t.Scopes, core.ScopeAdmin) {
		p.ElevatedUntil = *t.ExpiresAt
	}
	p.EnrollRequired = !hasMFA && s.requires2FA(p.Role, p.RoleCaps())
	return p, nil
}

// normalizeScopes validates and orders the requested scopes.
func normalizeScopes(in []string) ([]string, error) {
	var out []string
	for _, v := range in {
		v = strings.ToLower(strings.TrimSpace(v))
		if v == "" {
			continue
		}
		if !slices.Contains(core.AllScopes, v) {
			return nil, core.Invalid("scopes", "unknown scope "+v+" (valid: "+strings.Join(core.AllScopes, ", ")+")")
		}
		if !slices.Contains(out, v) {
			out = append(out, v)
		}
	}
	if len(out) == 0 {
		return nil, core.Invalid("scopes", "choose at least one scope")
	}
	slices.SortFunc(out, func(a, b string) int { return slices.Index(core.AllScopes, a) - slices.Index(core.AllScopes, b) })
	return out, nil
}

// CreateToken implements core.Auth. Rules:
//   - the token's owner must hold tokens.create (403 "the role of <username>
//     does not allow API tokens"; also for tokens made for others and on the
//     admin socket — built-in Guests do not have it);
//   - in.UserID (another user) needs the system principal or a caller who may
//     manage that account's credentials (authorizeFor), elevated;
//   - the admin scope needs a staff owner (a built-in owner/admin or a role
//     with a server permission; 422 on scopes otherwise) and an elevated
//     caller;
//   - a token principal can only mint tokens with a subset of its own
//     scopes, never --elevated ones, and never ones that expire after
//     itself (no expiry = the caller token's expiry);
//   - --elevated needs the admin scope and an expiry within 30 days (an
//     expiry up to elevatedExpirySkew later — a client clock running ahead —
//     is clamped to 30 days).
//
// The secret ("fpt_…") is returned once.
func (s *Service) CreateToken(ctx context.Context, p *core.Principal, in core.TokenInput) (*core.APIToken, string, error) {
	if p == nil {
		return nil, "", core.ErrUnauthorized
	}
	now := s.now()
	ownerID := p.UserID
	if in.UserID != "" && in.UserID != p.UserID {
		if err := s.authorizeFor(ctx, p, in.UserID, core.ActTokenCreate); err != nil {
			return nil, "", err
		}
		if !p.Elevated(now) {
			return nil, "", core.ErrElevationRequired
		}
		ownerID = in.UserID
	}
	if ownerID == "" {
		return nil, "", core.Invalid("user_id", "choose the user the token belongs to")
	}
	owner, err := s.users.Get(ctx, ownerID)
	if err != nil {
		return nil, "", err
	}
	if owner.Status != core.UserActive {
		return nil, "", core.Invalid("user_id", "the account is disabled")
	}
	if !owner.Permissions.Has(core.CapTokensCreate) {
		return nil, "", core.Errorf(core.ErrForbidden, "the role of %s does not allow API tokens", owner.Username)
	}
	name, err := cleanName("name", in.Name)
	if err != nil {
		return nil, "", err
	}
	scopes, err := normalizeScopes(in.Scopes)
	if err != nil {
		return nil, "", err
	}
	admin := slices.Contains(scopes, core.ScopeAdmin)
	if admin && !owner.Role.IsAdmin() && owner.Permissions.Server() == 0 {
		return nil, "", core.Invalid("scopes", "the admin scope needs an account with server permissions")
	}
	if p.Via == core.ViaToken {
		for _, sc := range scopes {
			if !slices.Contains(p.Scopes, sc) {
				return nil, "", core.Errorf(core.ErrForbidden, "an API token cannot create a token with more scopes than its own")
			}
		}
		if in.Elevated {
			return nil, "", core.Errorf(core.ErrForbidden, "elevated tokens can only be created from a browser session or the admin socket")
		}
	}
	if admin && !p.Elevated(now) {
		return nil, "", core.ErrElevationRequired
	}
	var exp *time.Time
	if in.ExpiresAt != nil {
		e := in.ExpiresAt.UTC().Truncate(time.Millisecond)
		if !e.After(now.Add(time.Minute)) {
			return nil, "", core.Invalid("expires_at", "the expiry must be in the future")
		}
		exp = &e
	}
	if p.Via == core.ViaToken {
		// A token cannot outlive the token that mints it: without an expiry
		// the new one inherits the caller's, a later one is refused.
		// Otherwise a leaked short-lived token — or an --elevated admin
		// token, capped at 30 days — could swap itself for a permanent one
		// that also survives its revocation.
		parent, err := s.tokenExpiry(ctx, p.TokenID)
		if err != nil {
			return nil, "", err
		}
		switch {
		case parent == nil:
		case exp == nil:
			exp = parent
		case exp.After(*parent):
			return nil, "", core.Invalid("expires_at", "a token created with an API token cannot outlive it (it expires "+
				parent.UTC().Format(time.RFC3339)+")")
		}
	}
	if in.Elevated {
		maxExp := now.Add(MaxElevatedTokenTTL).Truncate(time.Millisecond)
		switch {
		case !admin:
			return nil, "", core.Invalid("elevated", "elevated tokens need the admin scope")
		case exp == nil || exp.After(maxExp.Add(elevatedExpirySkew)):
			return nil, "", core.Invalid("expires_at", "elevated tokens must expire within 30 days")
		case exp.After(maxExp):
			exp = &maxExp // "30 days" by a client clock slightly ahead of ours: clamp, do not refuse
		}
	}
	t := &core.APIToken{ID: ids.New(ids.PrefixToken), UserID: owner.ID, Name: name, Scopes: scopes, Elevated: in.Elevated,
		CreatedAt: now.Truncate(time.Millisecond), ExpiresAt: exp}
	secret := newTokenSecret(t.ID)
	stored := slices.Clone(scopes)
	if in.Elevated {
		stored = append(stored, core.ScopeElevated)
	}
	storedJSON, _ := json.Marshal(stored)
	err = s.env.DB.Tx(ctx, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, `INSERT INTO api_tokens (id, user_id, name, token_hash, scopes, created_at, expires_at)
			VALUES (?, ?, ?, ?, ?, ?, ?)`, t.ID, t.UserID, t.Name, ids.HashToken(secret), string(storedJSON),
			db.Ms(now), db.NullMs(exp)); err != nil {
			return err
		}
		return s.recordTx(ctx, tx, core.AuditEntry{Action: core.ActTokenCreate, TargetType: "token", TargetID: t.ID, TargetName: t.Name,
			Details: map[string]any{"user_id": t.UserID, "scopes": scopes, "elevated": in.Elevated, "expires_at": exp}})
	})
	if err != nil {
		return nil, "", err
	}
	return t, secret, nil
}

// tokenExpiry returns the expiry of API token id (nil = never). An unknown
// id is errBadToken: the caller's own token is gone.
func (s *Service) tokenExpiry(ctx context.Context, id string) (*time.Time, error) {
	var exp sql.NullInt64
	if err := s.env.DB.QueryRow(ctx, `SELECT expires_at FROM api_tokens WHERE id = ?`, id).Scan(&exp); err != nil {
		if db.IsNoRows(err) {
			return nil, errBadToken
		}
		return nil, err
	}
	return db.FromNullMs(exp), nil
}

// ListTokens implements core.Auth: every token of userID (including revoked
// and expired ones), newest first.
func (s *Service) ListTokens(ctx context.Context, userID string) ([]core.APIToken, error) {
	rows, err := s.env.DB.Query(ctx, `SELECT `+tokenColumns+` FROM api_tokens k WHERE k.user_id = ?
		ORDER BY k.created_at DESC, k.id DESC LIMIT 1000`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []core.APIToken{}
	for rows.Next() {
		t, err := scanToken(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *t)
	}
	return out, rows.Err()
}

// revokeUserTokens revokes the live API tokens of userID except exceptID
// (the caller's own token, when it authenticated with one). It is the
// token-side counterpart of revokeUserSessions: an operator resetting a
// compromised account's credentials must cut off its non-interactive
// credentials too, not only its browser sessions.
func revokeUserTokens(ctx context.Context, tx *sql.Tx, userID, exceptID string, now time.Time) (int64, error) {
	res, err := tx.ExecContext(ctx, `UPDATE api_tokens SET revoked_at = ? WHERE user_id = ? AND id != ? AND revoked_at IS NULL`,
		db.Ms(now), userID, exceptID)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// RevokeToken implements core.Auth: the owner revokes a token (an
// administrator may revoke other users' tokens only over the admin socket or
// the offline CLI, see ownCredentialsOnly). Revoking a revoked token is a
// no-op; tokens of other users are 404. A token principal may revoke itself
// and the tokens it could have minted (a subset of its scopes, not
// --elevated), never a wider one: a leaked files:read token must not be able
// to cut off the owner's other integrations, admin tokens included.
func (s *Service) RevokeToken(ctx context.Context, p *core.Principal, id string) error {
	var owner, name, scopes string
	var revoked sql.NullInt64
	err := s.env.DB.QueryRow(ctx, `SELECT user_id, name, scopes, revoked_at FROM api_tokens WHERE id = ?`, id).
		Scan(&owner, &name, &scopes, &revoked)
	if err != nil {
		if db.IsNoRows(err) {
			return core.NotFoundf("token not found")
		}
		return err
	}
	if err := s.authorizeFor(ctx, ownCredentialsOnly(p), owner, ""); err != nil {
		if errors.Is(err, core.ErrForbidden) || errors.Is(err, core.ErrNotFound) {
			return core.NotFoundf("token not found")
		}
		return err
	}
	if p != nil && p.Via == core.ViaToken && id != p.TokenID {
		target, elevated := decodeScopes(scopes)
		wider := elevated
		for _, sc := range target {
			wider = wider || !slices.Contains(p.Scopes, sc)
		}
		if wider {
			return core.Errorf(core.ErrForbidden, "an API token cannot revoke a token with more scopes than its own")
		}
	}
	if revoked.Valid {
		return nil
	}
	now := s.now()
	return s.env.DB.Tx(ctx, func(tx *sql.Tx) error {
		res, err := tx.ExecContext(ctx, `UPDATE api_tokens SET revoked_at = ? WHERE id = ? AND revoked_at IS NULL`, db.Ms(now), id)
		if err != nil {
			return err
		}
		if n, _ := res.RowsAffected(); n == 0 {
			return nil
		}
		return s.recordTx(ctx, tx, core.AuditEntry{Action: core.ActTokenRevoke, TargetType: "token", TargetID: id, TargetName: name,
			Details: map[string]any{"user_id": owner}})
	})
}
