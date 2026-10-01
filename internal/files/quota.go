package files

import (
	"context"
	"database/sql"

	"fileparcel/internal/core"
	"fileparcel/internal/db"
)

// Storage settings owned by this package (settings.go).
const (
	settingDefaultQuotaGB = "storage.default_quota_gb"
	settingMaxFileGB      = "storage.max_file_gb"
	settingTrashDays      = "storage.trash_days"
	settingVersionsKeep   = "storage.versions_keep"
	settingZipCompression = "storage.zip_compression"
	settingThumbnails     = "storage.thumbnails"
)

// gb converts a GB setting to bytes (0 stays 0 = unlimited).
func gb(n int64) int64 {
	if n <= 0 {
		return 0
	}
	if n > 1<<23 {
		n = 1 << 23
	}
	return n << 30
}

// userQuota resolves users.quota_bytes (NULL = storage.default_quota_gb,
// 0 = unlimited) to bytes (0 = unlimited).
func (svc *Service) userQuota(q sql.NullInt64) int64 {
	if !q.Valid {
		return gb(svc.settingInt(settingDefaultQuotaGB, 0))
	}
	if q.Int64 < 0 {
		return 0
	}
	return q.Int64
}

// spaceUsage is the accounting state of a space.
type spaceUsage struct {
	kind  string
	used  int64
	quota int64 // effective quota in bytes, 0 = unlimited
}

// spaceQuota loads the usage and the effective quota of a space: the
// smaller of spaces.quota_bytes and (personal spaces) the owner's quota.
func (svc *Service) spaceQuota(ctx context.Context, q querier, spaceID string) (*spaceUsage, error) {
	var su spaceUsage
	var sq, uq sql.NullInt64
	var hasUser bool
	err := q.QueryRowContext(ctx, `SELECT s.kind, s.used_bytes, s.quota_bytes, u.quota_bytes, u.id IS NOT NULL
		FROM spaces s LEFT JOIN users u ON s.kind = 'user' AND u.id = s.owner_user_id WHERE s.id = ?`, spaceID).
		Scan(&su.kind, &su.used, &sq, &uq, &hasUser)
	if db.IsNoRows(err) {
		return nil, core.NotFoundf("space not found")
	}
	if err != nil {
		return nil, err
	}
	if sq.Valid && sq.Int64 > 0 {
		su.quota = sq.Int64
	}
	if su.kind == core.SpaceUser && hasUser {
		if lim := svc.userQuota(uq); lim > 0 && (su.quota == 0 || lim < su.quota) {
			su.quota = lim
		}
	}
	return &su, nil
}

// charge adds delta bytes to the usage of a space. Positive deltas are
// checked against the effective quota (ErrQuota) when check is set.
func (o *op) charge(spaceID string, delta int64, check bool) error {
	if delta == 0 {
		return nil
	}
	if delta > 0 && check {
		su, err := o.svc.spaceQuota(o.ctx, o.q, spaceID)
		if err != nil {
			return err
		}
		if su.quota > 0 && su.used+delta > su.quota {
			return core.Wrap(core.ErrQuota, "not enough storage space left in this space", nil)
		}
	}
	_, err := o.q.ExecContext(o.ctx, `UPDATE spaces SET used_bytes = MAX(0, used_bytes + ?) WHERE id = ?`, delta, spaceID)
	return err
}

// checkMaxFile enforces storage.max_file_gb.
func (svc *Service) checkMaxFile(size int64) error {
	if lim := gb(svc.settingInt(settingMaxFileGB, 0)); lim > 0 && size > lim {
		return core.Wrap(core.ErrTooLarge, "the file is larger than the maximum file size", nil)
	}
	return nil
}
