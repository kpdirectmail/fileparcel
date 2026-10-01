package users

import (
	"context"
	"database/sql"
	"time"

	"fileparcel/internal/core"
	"fileparcel/internal/db"
)

// lockoutPolicy returns the lockout threshold and base duration (settings
// auth.lockout_threshold / auth.lockout_base_min).
func (s *Service) lockoutPolicy() (threshold int, base time.Duration) {
	threshold, baseMin := defaultLockoutThreshold, int64(defaultLockoutBaseMin)
	if st := s.env.Settings; st != nil {
		if v := st.Int(settingLockoutThreshold); v > 0 {
			threshold = int(v)
		}
		if v := st.Int(settingLockoutBaseMin); v > 0 {
			baseMin = v
		}
	}
	return threshold, time.Duration(baseMin) * time.Minute
}

// lockDuration is base × 2^level, capped at 24 h.
func lockDuration(base time.Duration, level int) time.Duration {
	d := base
	for i := 0; i < level && d < maxLockout; i++ {
		d *= 2
	}
	return min(d, maxLockout)
}

// RecordLoginFailure counts a failed sign-in (DESIGN §9.3). When the count
// reaches auth.lockout_threshold the account is locked for
// auth.lockout_base_min × 2^lock_level (at most 24 h), the counter restarts
// and the level increases; auth.lockout is audited and a security alert is
// e-mailed to the user (when enabled). lockedUntil is non-nil while the
// account is locked (including a lock that was already active; then nothing
// changes).
func (s *Service) RecordLoginFailure(ctx context.Context, id string) (*time.Time, error) {
	threshold, base := s.lockoutPolicy()
	now := s.now()
	var lockedUntil *time.Time
	var newLock bool
	var username, email string
	err := s.env.DB.Tx(ctx, func(tx *sql.Tx) error {
		lockedUntil, newLock = nil, false
		var failed, level int
		var until sql.NullInt64
		var em sql.NullString
		err := tx.QueryRowContext(ctx, `SELECT username, email, failed_logins, lock_level, locked_until FROM users WHERE id = ?`, id).
			Scan(&username, &em, &failed, &level, &until)
		if db.IsNoRows(err) {
			return errUserNotFound()
		}
		if err != nil {
			return err
		}
		email = em.String
		if t := db.FromNullMs(until); t != nil && now.Before(*t) {
			lockedUntil = t
			return nil
		}
		failed++
		if failed < threshold {
			_, err := tx.ExecContext(ctx, `UPDATE users SET failed_logins = ? WHERE id = ?`, failed, id)
			return err
		}
		d := lockDuration(base, level)
		t := now.Add(d)
		lockedUntil, newLock = &t, true
		if _, err := tx.ExecContext(ctx, `UPDATE users SET failed_logins = 0, lock_level = ?, locked_until = ? WHERE id = ?`,
			min(level+1, 16), db.Ms(t), id); err != nil {
			return err
		}
		return s.auditTx(ctx, tx, core.AuditEntry{
			Action: core.ActAuthLockout, Outcome: core.OutcomeDenied, TargetType: "user", TargetID: id, TargetName: username,
			Details: map[string]any{"locked_until": t.UTC().Format(time.RFC3339), "duration_s": int64(d / time.Second),
				"lock_level": level + 1, "failed_logins": failed},
		})
	})
	if err != nil {
		return nil, err
	}
	if newLock && email != "" {
		if n := s.notifier(); n != nil {
			data := map[string]any{"kind": "lockout", "username": username, "locked_until": lockedUntil.UTC().Format(time.RFC3339)}
			if p := core.PrincipalFrom(ctx); p != nil && p.IP.IsValid() {
				data["ip"] = p.IP.String()
			}
			if err := n.Send(ctx, []string{email}, "security_alert", data); err != nil {
				s.log.Warn("users: lockout alert not sent", "user", id, "err", err)
			}
		}
	}
	return lockedUntil, nil
}

// RecordLoginSuccess resets the failure counter, the lock level and any lock,
// and records the time and IP of the sign-in.
func (s *Service) RecordLoginSuccess(ctx context.Context, id string, meta core.ReqMeta) error {
	ip := ""
	if meta.IP.IsValid() {
		ip = meta.IP.String()
	}
	res, err := s.env.DB.Exec(ctx, `UPDATE users SET failed_logins = 0, lock_level = 0, locked_until = NULL,
		last_login_at = ?, last_login_ip = ? WHERE id = ?`, db.Ms(s.now()), db.NullString(ip), id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return errUserNotFound()
	}
	return nil
}

// Unlock clears a lockout and the failure counter (users.manage and
// core.CheckManage: owners only for owner accounts, delegates only for the
// accounts their role may manage; a refused escalation is audited as
// denied). Audited as user.unlock when something changed.
func (s *Service) Unlock(ctx context.Context, by *core.Principal, id string) error {
	if err := requireCap(by, core.CapUsersManage); err != nil {
		return err
	}
	var cur *core.User
	err := s.env.DB.Tx(ctx, func(tx *sql.Tx) error {
		var err error
		if cur, err = getUser(ctx, tx, id); err != nil {
			return err
		}
		if err := core.CheckManage(by, cur, core.CapUsersManage); err != nil {
			return err
		}
		if cur.FailedLogins == 0 && cur.LockLevel == 0 && cur.LockedUntil == nil {
			return nil
		}
		if _, err := tx.ExecContext(ctx, `UPDATE users SET failed_logins = 0, lock_level = 0, locked_until = NULL,
			updated_at = ? WHERE id = ?`, db.Ms(s.now()), id); err != nil {
			return err
		}
		return s.auditByTx(ctx, tx, by, core.AuditEntry{
			Action: core.ActUserUnlock, TargetType: "user", TargetID: id, TargetName: cur.Username,
			Details: map[string]any{"was_locked": cur.Locked(s.now()), "failed_logins": cur.FailedLogins},
		})
	})
	if err != nil {
		s.auditDeniedUser(ctx, by, core.ActUserUnlock, cur, err)
	}
	return err
}
