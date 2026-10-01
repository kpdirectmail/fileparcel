package auth

import (
	"context"
	"crypto/hmac"
	"crypto/subtle"
	"database/sql"
	"strings"
	"time"

	"github.com/pquerna/otp"
	"github.com/pquerna/otp/hotp"
	"github.com/pquerna/otp/totp"

	"fileparcel/internal/core"
	"fileparcel/internal/crypt"
	"fileparcel/internal/db"
	"fileparcel/internal/ids"
	"fileparcel/internal/qr"
)

// TOTP parameters (RFC 6238 defaults understood by every authenticator app).
const (
	totpPeriod     = 30
	totpDigits     = otp.DigitsSix
	totpSkew       = 1 // accept the previous and the next time step
	totpSecretSize = 20
)

var totpOpts = hotp.ValidateOpts{Digits: totpDigits, Algorithm: otp.AlgorithmSHA1}

func totpAAD(userID string) string { return "totp_secrets.secret_enc|" + userID }

func randomSecret() []byte { return crypt.RandomBytes(csrfSecretBytes) }

func (s *Service) keys() (core.Keys, error) {
	if s.env.Keys == nil || s.env.Keys.State() != core.KeyStateUnlocked {
		return nil, core.ErrKeysLocked
	}
	return s.env.Keys, nil
}

// totpStep returns the RFC 6238 time step of t.
func totpStep(t time.Time) int64 { return t.Unix() / totpPeriod }

// normalizeTOTP strips spaces and dashes; the result must be 6 digits.
func normalizeTOTP(code string) (string, bool) {
	code = strings.Map(func(r rune) rune {
		if r == ' ' || r == '-' || r == '\t' {
			return -1
		}
		return r
	}, code)
	if len(code) != totpDigits.Length() {
		return "", false
	}
	for _, c := range code {
		if c < '0' || c > '9' {
			return "", false
		}
	}
	return code, true
}

// matchTOTPStep returns the time step (now-skew … now+skew) whose code equals
// code and that is newer than lastStep. Comparisons are constant-time.
func matchTOTPStep(secret, code string, now time.Time, lastStep int64) (int64, bool) {
	code, ok := normalizeTOTP(code)
	if !ok {
		return 0, false
	}
	cur := totpStep(now)
	steps := []int64{cur}
	for i := int64(1); i <= totpSkew; i++ {
		steps = append(steps, cur-i, cur+i)
	}
	found, hit := int64(0), 0
	for _, st := range steps {
		want, err := hotp.GenerateCodeCustom(secret, uint64(st), totpOpts)
		if err != nil {
			return 0, false
		}
		if subtle.ConstantTimeCompare([]byte(want), []byte(code)) == 1 && st > lastStep && hit == 0 {
			found, hit = st, 1
		}
	}
	return found, hit == 1
}

// checkTOTP verifies code against the user's TOTP secret (confirmed only,
// or pending only). It does not consume the step; consumeTOTPStep does.
func (s *Service) checkTOTP(ctx context.Context, userID, code string, confirmed bool) (int64, bool, error) {
	var enc string
	var confirmedAt sql.NullInt64
	var last int64
	err := s.env.DB.QueryRow(ctx, `SELECT secret_enc, confirmed_at, last_step FROM totp_secrets WHERE user_id = ?`, userID).
		Scan(&enc, &confirmedAt, &last)
	if err != nil {
		if db.IsNoRows(err) {
			return 0, false, nil
		}
		return 0, false, err
	}
	if confirmedAt.Valid != confirmed {
		return 0, false, nil
	}
	k, err := s.keys()
	if err != nil {
		return 0, false, err
	}
	secret, err := k.OpenField(totpAAD(userID), enc)
	if err != nil {
		return 0, false, err
	}
	defer crypt.Zero(secret)
	step, ok := matchTOTPStep(string(secret), code, s.now(), last)
	return step, ok, nil
}

// consumeTOTPStep records step as used (replay protection). It fails with
// errFactorConsumed when the step (or a later one) was used concurrently.
func consumeTOTPStep(ctx context.Context, tx *sql.Tx, userID string, step int64) error {
	res, err := tx.ExecContext(ctx, `UPDATE totp_secrets SET last_step = ?
		WHERE user_id = ? AND confirmed_at IS NOT NULL AND last_step < ?`, step, userID, step)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n != 1 {
		return errFactorConsumed
	}
	return nil
}

// TOTPBegin implements core.Auth: creates (or replaces) a pending TOTP
// secret and returns it with the otpauth:// URI and a QR code. ErrConflict
// when an authenticator is already active. Enrolling needs an open step-up
// window (TOTPConfirm too): a confirmed authenticator satisfies Elevate, so
// a hijacked session must not be able to add its own (see
// PasskeyRegisterBegin).
func (s *Service) TOTPBegin(ctx context.Context, p *core.Principal) (*core.TOTPEnrollment, error) {
	u, err := s.requireUser(ctx, p)
	if err != nil {
		return nil, err
	}
	if !p.Elevated(s.now()) {
		return nil, core.ErrElevationRequired
	}
	k, err := s.keys()
	if err != nil {
		return nil, err
	}
	raw := crypt.RandomBytes(totpSecretSize)
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      strings.NewReplacer(":", " ", "/", " ").Replace(s.instanceName()),
		AccountName: u.Username,
		Period:      totpPeriod,
		SecretSize:  totpSecretSize,
		Secret:      raw,
		Digits:      totpDigits,
		Algorithm:   otp.AlgorithmSHA1,
	})
	crypt.Zero(raw)
	if err != nil {
		return nil, err
	}
	sealed, err := k.SealField(totpAAD(u.ID), []byte(key.Secret()))
	if err != nil {
		return nil, err
	}
	now := s.now()
	err = s.env.DB.Tx(ctx, func(tx *sql.Tx) error {
		res, err := tx.ExecContext(ctx, `INSERT INTO totp_secrets (user_id, secret_enc, confirmed_at, last_step, created_at)
			VALUES (?, ?, NULL, 0, ?)
			ON CONFLICT (user_id) DO UPDATE SET secret_enc = excluded.secret_enc, last_step = 0, created_at = excluded.created_at
			WHERE totp_secrets.confirmed_at IS NULL`, u.ID, sealed, db.Ms(now))
		if err != nil {
			return err
		}
		if n, _ := res.RowsAffected(); n != 1 {
			return core.Errorf(core.ErrConflict, "an authenticator app is already set up; turn it off first")
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	out := &core.TOTPEnrollment{Secret: key.Secret(), OTPAuthURI: key.URL()}
	if out.QRDataURI, err = qr.DataURI(out.OTPAuthURI); err != nil {
		s.log.Warn("totp qr code", "err", err) // manual entry still works
	}
	return out, nil
}

// TOTPConfirm implements core.Auth: verifies the first code of a pending
// secret (requires an open step-up window) and activates it. It returns the
// account's first recovery codes (shown once) when it has no unused code
// left, and nil otherwise: like EnsureRecoveryCodes it never invalidates
// codes the user may already have written down (e.g. from enrolling a
// passkey) — only RegenerateRecovery replaces them.
func (s *Service) TOTPConfirm(ctx context.Context, p *core.Principal, code string) ([]string, error) {
	u, err := s.requireUser(ctx, p)
	if err != nil {
		return nil, err
	}
	if !p.Elevated(s.now()) {
		return nil, core.ErrElevationRequired
	}
	m, err := s.loadMFA(ctx, u.ID)
	if err != nil {
		return nil, err
	}
	switch {
	case m.totp:
		return nil, core.Errorf(core.ErrConflict, "an authenticator app is already set up")
	case !m.totpPending:
		return nil, core.Errorf(core.ErrConflict, "start the authenticator setup first")
	}
	step, ok, err := s.checkTOTP(ctx, u.ID, code, false)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, core.Invalid("code", "that code is not valid; check the time on your device and try again")
	}
	codes, macs, err := s.newRecoveryCodes(u.ID)
	if err != nil {
		return nil, err
	}
	now := s.now()
	minted := false
	err = s.env.DB.Tx(ctx, func(tx *sql.Tx) error {
		minted = false // the transaction may be retried
		res, err := tx.ExecContext(ctx, `UPDATE totp_secrets SET confirmed_at = ?, last_step = ?
			WHERE user_id = ? AND confirmed_at IS NULL AND last_step < ?`, db.Ms(now), step, u.ID, step)
		if err != nil {
			return err
		}
		if n, _ := res.RowsAffected(); n != 1 {
			return core.Errorf(core.ErrConflict, "the authenticator setup changed; start again")
		}
		if minted, err = mintFirstRecovery(ctx, tx, u.ID, macs, now); err != nil {
			return err
		}
		return s.recordTx(ctx, tx, core.AuditEntry{Action: core.ActMFATOTPEnable, TargetType: "user", TargetID: u.ID, TargetName: u.Username,
			Details: map[string]any{"recovery_codes_minted": minted}})
	})
	if err != nil || !minted {
		return nil, err
	}
	return codes, nil
}

// TOTPDisable implements core.Auth: removes the authenticator of userID.
// by must be the user or may manage their credentials (authorizeFor), and
// elevated. Recovery codes go too when no passkey remains. ErrNotFound when
// no authenticator is set up.
func (s *Service) TOTPDisable(ctx context.Context, by *core.Principal, userID string) error {
	if err := s.authorizeFor(ctx, by, userID, core.ActMFATOTPDisable); err != nil {
		return err
	}
	if !by.Elevated(s.now()) {
		return core.ErrElevationRequired
	}
	return s.env.DB.Tx(ctx, func(tx *sql.Tx) error {
		res, err := tx.ExecContext(ctx, `DELETE FROM totp_secrets WHERE user_id = ?`, userID)
		if err != nil {
			return err
		}
		if n, _ := res.RowsAffected(); n == 0 {
			return core.NotFoundf("no authenticator app is set up")
		}
		if err := dropOrphanRecovery(ctx, tx, userID); err != nil {
			return err
		}
		return s.recordTx(ctx, tx, core.AuditEntry{Action: core.ActMFATOTPDisable, TargetType: "user", TargetID: userID})
	})
}

// dropOrphanRecovery deletes the recovery codes of userID when no second
// factor remains (they would be useless).
func dropOrphanRecovery(ctx context.Context, tx *sql.Tx, userID string) error {
	_, err := tx.ExecContext(ctx, `DELETE FROM recovery_codes WHERE user_id = ?
		AND NOT EXISTS (SELECT 1 FROM totp_secrets WHERE user_id = ? AND confirmed_at IS NOT NULL)
		AND NOT EXISTS (SELECT 1 FROM webauthn_credentials WHERE user_id = ?)`, userID, userID, userID)
	return err
}

// RegenerateRecovery implements core.Auth: replaces the recovery codes of
// the principal's account (requires an active second factor and an open
// step-up window).
func (s *Service) RegenerateRecovery(ctx context.Context, p *core.Principal) ([]string, error) {
	u, err := s.requireUser(ctx, p)
	if err != nil {
		return nil, err
	}
	if !p.Elevated(s.now()) {
		return nil, core.ErrElevationRequired
	}
	m, err := s.loadMFA(ctx, u.ID)
	if err != nil {
		return nil, err
	}
	if !m.enabled() {
		return nil, core.Errorf(core.ErrConflict, "set up an authenticator app or a passkey first")
	}
	codes, macs, err := s.newRecoveryCodes(u.ID)
	if err != nil {
		return nil, err
	}
	now := s.now()
	err = s.env.DB.Tx(ctx, func(tx *sql.Tx) error {
		if err := replaceRecovery(ctx, tx, u.ID, macs, now); err != nil {
			return err
		}
		return s.recordTx(ctx, tx, core.AuditEntry{Action: core.ActMFARecoveryRegenerate, TargetType: "user", TargetID: u.ID, TargetName: u.Username})
	})
	if err != nil {
		return nil, err
	}
	return codes, nil
}

// EnsureRecoveryCodes mints the recovery codes of the principal's account
// when it has a second factor but no unused code left, and returns them
// (shown once); it returns nil when codes already exist or the account has
// no second factor at all.
//
// Enrolling a passkey goes through here. A passkey is not an out-of-band
// factor: TOTPConfirm hands out recovery codes, passkey registration used to
// hand out nothing, so an account whose only second factor was a passkey
// could not sign in at all once auth.passkeys was turned off (or the
// authenticator was lost) — only "fileparcel user reset-2fa" over the admin
// socket could bring it back. Unlike RegenerateRecovery this needs no
// step-up: it never invalidates a code the user may already have written
// down, it only ever creates the first set.
func (s *Service) EnsureRecoveryCodes(ctx context.Context, p *core.Principal) ([]string, error) {
	u, err := s.requireUser(ctx, p)
	if err != nil {
		return nil, err
	}
	m, err := s.loadMFA(ctx, u.ID)
	if err != nil {
		return nil, err
	}
	if !m.enabled() || m.recoveryLeft > 0 {
		return nil, nil
	}
	codes, macs, err := s.newRecoveryCodes(u.ID)
	if err != nil {
		return nil, err
	}
	now := s.now()
	minted := false
	err = s.env.DB.Tx(ctx, func(tx *sql.Tx) error {
		var err error
		if minted, err = mintFirstRecovery(ctx, tx, u.ID, macs, now); err != nil || !minted {
			return err
		}
		return s.recordTx(ctx, tx, core.AuditEntry{Action: core.ActMFARecoveryRegenerate, TargetType: "user", TargetID: u.ID,
			TargetName: u.Username, Details: map[string]any{"reason": "second_factor_enrolled"}})
	})
	if err != nil || !minted {
		return nil, err
	}
	return codes, nil
}

// mintFirstRecovery stores macs as the recovery codes of userID inside tx,
// but only when the account has no unused code left, and reports whether it
// did. Enrolling a second factor goes through here, so it never invalidates
// codes the user may already have written down. The count is read inside
// the write transaction: two enrolments at once must not each hand out a
// set, one of which is dead on arrival.
func mintFirstRecovery(ctx context.Context, tx *sql.Tx, userID string, macs [][]byte, now time.Time) (bool, error) {
	var left int
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM recovery_codes WHERE user_id = ? AND used_at IS NULL`,
		userID).Scan(&left); err != nil {
		return false, err
	}
	if left > 0 {
		return false, nil
	}
	if err := replaceRecovery(ctx, tx, userID, macs, now); err != nil {
		return false, err
	}
	return true, nil
}

// ---------- recovery codes ----------

// recoveryAlphabet is Crockford base32 (no I, L, O, U).
const recoveryAlphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"

// newRecoveryCode returns "XXXX-XXXX" (40 random bits).
func newRecoveryCode() string {
	b := crypt.RandomBytes(8)
	out := make([]byte, 0, 9)
	for i, c := range b {
		if i == 4 {
			out = append(out, '-')
		}
		out = append(out, recoveryAlphabet[c&31])
	}
	return string(out)
}

// normalizeRecovery uppercases, drops separators and maps look-alikes
// (O→0, I/L→1). The result must be 8 alphabet characters.
func normalizeRecovery(code string) (string, bool) {
	var b strings.Builder
	for _, r := range strings.ToUpper(code) {
		switch r {
		case '-', ' ', '\t':
			continue
		case 'O':
			r = '0'
		case 'I', 'L':
			r = '1'
		}
		if r > 127 || !strings.ContainsRune(recoveryAlphabet, r) {
			return "", false
		}
		b.WriteRune(r)
	}
	if b.Len() != 8 {
		return "", false
	}
	return b.String(), true
}

// recoveryMAC is MAC("recovery", user_id, normalized code) (DESIGN §7.5).
func (s *Service) recoveryMAC(userID, normalized string) ([]byte, error) {
	k, err := s.keys()
	if err != nil {
		return nil, err
	}
	mac := k.MAC("recovery", []byte(userID), []byte(normalized))
	if len(mac) == 0 {
		return nil, core.ErrKeysLocked
	}
	return mac, nil
}

// newRecoveryCodes returns RecoveryCodeCount codes and their MACs.
func (s *Service) newRecoveryCodes(userID string) ([]string, [][]byte, error) {
	codes := make([]string, 0, RecoveryCodeCount)
	macs := make([][]byte, 0, RecoveryCodeCount)
	seen := map[string]bool{}
	for len(codes) < RecoveryCodeCount {
		c := newRecoveryCode()
		n, _ := normalizeRecovery(c)
		if seen[n] {
			continue
		}
		seen[n] = true
		mac, err := s.recoveryMAC(userID, n)
		if err != nil {
			return nil, nil, err
		}
		codes, macs = append(codes, c), append(macs, mac)
	}
	return codes, macs, nil
}

// replaceRecovery replaces the recovery codes of userID inside tx.
func replaceRecovery(ctx context.Context, tx *sql.Tx, userID string, macs [][]byte, now time.Time) error {
	if _, err := tx.ExecContext(ctx, `DELETE FROM recovery_codes WHERE user_id = ?`, userID); err != nil {
		return err
	}
	for _, mac := range macs {
		if _, err := tx.ExecContext(ctx, `INSERT INTO recovery_codes (id, user_id, code_mac, used_at, created_at)
			VALUES (?, ?, ?, NULL, ?)`, ids.New(ids.PrefixRecoveryCode), userID, mac, db.Ms(now)); err != nil {
			return err
		}
	}
	return nil
}

// matchRecovery returns the id of the unused recovery code of userID equal
// to code ("" when none). Every stored code is compared (constant time).
func (s *Service) matchRecovery(ctx context.Context, userID, code string) (string, error) {
	norm, ok := normalizeRecovery(code)
	if !ok {
		return "", nil
	}
	mac, err := s.recoveryMAC(userID, norm)
	if err != nil {
		return "", err
	}
	rows, err := s.env.DB.Query(ctx, `SELECT id, code_mac FROM recovery_codes WHERE user_id = ? AND used_at IS NULL`, userID)
	if err != nil {
		return "", err
	}
	defer rows.Close()
	found := ""
	for rows.Next() {
		var id string
		var stored []byte
		if err := rows.Scan(&id, &stored); err != nil {
			return "", err
		}
		if hmac.Equal(stored, mac) && found == "" {
			found = id
		}
	}
	return found, rows.Err()
}

// consumeRecovery marks a recovery code used (errFactorConsumed when it was
// used concurrently).
func consumeRecovery(ctx context.Context, tx *sql.Tx, id string, now time.Time) error {
	res, err := tx.ExecContext(ctx, `UPDATE recovery_codes SET used_at = ? WHERE id = ? AND used_at IS NULL`, db.Ms(now), id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n != 1 {
		return errFactorConsumed
	}
	return nil
}
