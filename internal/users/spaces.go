package users

import (
	"context"
	"database/sql"
	"fmt"

	"fileparcel/internal/core"
	"fileparcel/internal/db"
	"fileparcel/internal/ids"
	"fileparcel/internal/names"
)

// insertSpace creates a space and its root folder inside tx and returns the
// space id. Exactly one of ownerUserID / groupID is set.
func insertSpace(ctx context.Context, tx *sql.Tx, kind, ownerUserID, groupID, name string, quota *int64, actor string, now int64) (string, error) {
	nfc, key, err := names.Clean(name)
	if err != nil {
		return "", err
	}
	spaceID := ids.New(ids.PrefixSpace)
	if _, err := tx.ExecContext(ctx, `INSERT INTO spaces (id, kind, owner_user_id, group_id, name, quota_bytes, used_bytes, created_at)
		VALUES (?, ?, ?, ?, ?, ?, 0, ?)`,
		spaceID, kind, db.NullString(ownerUserID), db.NullString(groupID), nfc, db.NullInt64(quota), now); err != nil {
		return "", fmt.Errorf("users: insert space: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO nodes (id, space_id, parent_id, kind, name, name_key, size,
		created_at, updated_at, created_by, updated_by) VALUES (?, ?, NULL, 'folder', ?, ?, 0, ?, ?, ?, ?)`,
		ids.New(ids.PrefixNode), spaceID, nfc, key, now, now, db.NullString(actor), db.NullString(actor)); err != nil {
		return "", fmt.Errorf("users: insert space root: %w", err)
	}
	return spaceID, nil
}

// createPersonalSpace creates the personal space ("My files") of userID.
func createPersonalSpace(ctx context.Context, tx *sql.Tx, userID string, quota *int64, actor string, now int64) (string, error) {
	return insertSpace(ctx, tx, core.SpaceUser, userID, "", PersonalSpaceName, quota, actor, now)
}

// personalSpace returns the personal space and root node ids of userID
// ("" when the user has none, e.g. guests).
func personalSpace(ctx context.Context, q queryer, userID string) (spaceID, rootID string, err error) {
	err = q.QueryRowContext(ctx, `SELECT s.id, COALESCE(n.id, '') FROM spaces s
		LEFT JOIN nodes n ON n.space_id = s.id AND n.parent_id IS NULL
		WHERE s.owner_user_id = ? AND s.kind = 'user'`, userID).Scan(&spaceID, &rootID)
	if db.IsNoRows(err) {
		return "", "", nil
	}
	if err == nil && rootID == "" {
		err = fmt.Errorf("users: space %s has no root folder: %w", spaceID, core.ErrCorrupt)
	}
	return spaceID, rootID, err
}

// groupSpace returns the space and root node ids of a group.
func groupSpace(ctx context.Context, q queryer, groupID string) (spaceID, rootID string, err error) {
	err = q.QueryRowContext(ctx, `SELECT s.id, COALESCE(n.id, '') FROM spaces s
		LEFT JOIN nodes n ON n.space_id = s.id AND n.parent_id IS NULL
		WHERE s.group_id = ? AND s.kind = 'group'`, groupID).Scan(&spaceID, &rootID)
	if db.IsNoRows(err) {
		return "", "", nil
	}
	return spaceID, rootID, err
}

// removeEmptyPersonalSpace deletes the personal space of userID when it holds
// nothing but its root (live or trashed). It returns ErrConflict otherwise.
func removeEmptyPersonalSpace(ctx context.Context, tx *sql.Tx, userID string) error {
	spaceID, rootID, err := personalSpace(ctx, tx, userID)
	if err != nil || spaceID == "" {
		return err
	}
	var n int
	if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM nodes WHERE space_id = ? AND id <> ?`, spaceID, rootID).Scan(&n); err != nil {
		return err
	}
	if n > 0 {
		return conflictField("role", "the user still has personal files: move them or delete them (including the trash) before making the user a guest or giving them a role based on guest")
	}
	_, err = tx.ExecContext(ctx, `DELETE FROM spaces WHERE id = ?`, spaceID)
	return err
}

// followBase keeps the personal space of userID consistent with a change of
// the base role from → to: a move to guest removes the (empty) space —
// ErrConflict while it holds files —, a move from guest creates one with the
// account's quota. Custom roles have the personal space of their base.
func followBase(ctx context.Context, tx *sql.Tx, userID string, from, to core.Role, quota *int64, actor string, now int64) error {
	switch {
	case to == core.RoleGuest && from != core.RoleGuest:
		return removeEmptyPersonalSpace(ctx, tx, userID)
	case from == core.RoleGuest && to != core.RoleGuest:
		spaceID, _, err := personalSpace(ctx, tx, userID)
		if err != nil || spaceID != "" {
			return err
		}
		_, err = createPersonalSpace(ctx, tx, userID, quota, actor, now)
		return err
	}
	return nil
}

// transferFiles moves everything below the source root into a new folder
// "From <username>" in the destination root, re-homes the moved subtree to the
// destination space and recomputes the destination's used_bytes. It returns
// the new folder id ("" when there was nothing to move) and the number of
// moved nodes.
func transferFiles(ctx context.Context, tx *sql.Tx, srcRoot, dstSpace, dstRoot, fromUsername, actor string, now int64) (string, int64, error) {
	var children int
	if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM nodes WHERE parent_id = ?`, srcRoot).Scan(&children); err != nil {
		return "", 0, err
	}
	if children == 0 {
		return "", 0, nil
	}
	base, _, err := names.Clean("From " + fromUsername)
	if err != nil {
		return "", 0, err
	}
	name, key := "", ""
	for n := 0; ; n++ {
		if n > 10000 {
			return "", 0, core.Errorf(core.ErrConflict, "cannot find a free folder name for the transferred files")
		}
		name = names.Numbered(base, n, true)
		key = names.Key(name)
		var exists int
		err := tx.QueryRowContext(ctx, `SELECT 1 FROM nodes WHERE parent_id = ? AND name_key = ? AND trashed_at IS NULL`, dstRoot, key).Scan(&exists)
		if db.IsNoRows(err) {
			break
		}
		if err != nil {
			return "", 0, err
		}
	}
	folderID := ids.New(ids.PrefixNode)
	if _, err := tx.ExecContext(ctx, `INSERT INTO nodes (id, space_id, parent_id, kind, name, name_key, size,
		created_at, updated_at, created_by, updated_by) VALUES (?, ?, ?, 'folder', ?, ?, 0, ?, ?, ?, ?)`,
		folderID, dstSpace, dstRoot, name, key, now, now, db.NullString(actor), db.NullString(actor)); err != nil {
		return "", 0, fmt.Errorf("users: create transfer folder: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `UPDATE nodes SET parent_id = ? WHERE parent_id = ?`, folderID, srcRoot); err != nil {
		return "", 0, fmt.Errorf("users: move files: %w", err)
	}
	res, err := tx.ExecContext(ctx, `WITH RECURSIVE sub(id) AS (
			SELECT id FROM nodes WHERE parent_id = ?
			UNION ALL
			SELECT n.id FROM nodes n JOIN sub ON n.parent_id = sub.id)
		UPDATE nodes SET space_id = ? WHERE id IN (SELECT id FROM sub)`, folderID, dstSpace)
	if err != nil {
		return "", 0, fmt.Errorf("users: re-home files: %w", err)
	}
	moved, _ := res.RowsAffected()
	if err := recomputeUsed(ctx, tx, dstSpace); err != nil {
		return "", 0, err
	}
	return folderID, moved, nil
}

// recomputeUsed sets spaces.used_bytes with the files service's accounting
// rule: the sum of the sizes of all versions of all nodes of the space, live
// and trashed.
func recomputeUsed(ctx context.Context, tx *sql.Tx, spaceID string) error {
	_, err := tx.ExecContext(ctx, `UPDATE spaces SET used_bytes = COALESCE((SELECT SUM(v.size) FROM file_versions v
		JOIN nodes n ON n.id = v.node_id WHERE n.space_id = ?1), 0) WHERE id = ?1`, spaceID)
	return err
}
