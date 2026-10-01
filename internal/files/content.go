package files

import (
	"cmp"
	"context"
	"database/sql"

	"fileparcel/internal/core"
	"fileparcel/internal/db"
	"fileparcel/internal/ids"
	"fileparcel/internal/names"
)

// openBlob opens the content of a file version, cross-checking its size.
func (svc *Service) openBlob(ctx context.Context, blobID string, size int64) (core.BlobReader, error) {
	if svc.blobs == nil {
		return nil, core.Wrap(core.ErrUnavailable, "blob storage unavailable", nil)
	}
	if blobID == "" {
		return nil, core.Wrap(core.ErrCorrupt, "the file has no content", nil)
	}
	r, err := svc.blobs.Open(ctx, blobID)
	if err != nil {
		return nil, err
	}
	if size >= 0 && r.Size() != size {
		r.Close()
		return nil, core.Wrap(core.ErrCorrupt, "the stored content does not match the file size", nil)
	}
	return r, nil
}

// Open implements core.Files: the node and a reader of its content
// (PermView; files in the trash included). versionID "" is the current
// version; for another version the returned node carries that version's
// VersionID, Size, ContentHash, (as UpdatedAt) its creation time and
// names.OctetStream as MIME — nothing records the type an older version was
// stored with, and the node's current one may be a different (and more
// permissive) type than the bytes about to be served. The caller closes the
// reader, and audits downloads (never for HEAD).
func (svc *Service) Open(ctx context.Context, p *core.Principal, id, versionID string) (*core.Node, core.BlobReader, error) {
	var out *nodeRow
	err := svc.read(ctx, p, func(o *op) error {
		n, err := o.authorize(id, core.PermView, authOpt{allowTrashed: true})
		if err != nil {
			return err
		}
		if n.IsDir() {
			return core.Invalid("id", "folders have no content (download them as an archive)")
		}
		if versionID != "" && versionID != n.VersionID {
			if err := o.useVersion(n, versionID); err != nil {
				return err
			}
		}
		out = n
		return nil
	})
	if err != nil {
		return nil, nil, err
	}
	r, err := svc.openBlob(ctx, out.BlobID, out.Size)
	if err != nil {
		return nil, nil, err
	}
	return &out.Node, r, nil
}

// useVersion switches n to one of its older versions. nodes.mime describes
// the current version only: file_versions has no type of its own, so an
// older version is delivered as application/octet-stream (an attachment,
// whatever inline the caller asked for). Serving it under the node's type
// would hand HTML stored as "text/html" back as the "application/pdf" the
// file later became — an inline type that names.DetectMIME had refused for
// exactly those bytes, with the weaker sandbox headers that inline PDFs get.
func (o *op) useVersion(n *nodeRow, versionID string) error {
	if !ids.Valid(ids.PrefixVersion, versionID) {
		return core.NotFoundf("version not found")
	}
	var created int64
	err := o.q.QueryRowContext(o.ctx, `SELECT blob_id, size, COALESCE(content_hash, ''), created_at FROM file_versions
		WHERE id = ? AND node_id = ?`, versionID, n.ID).Scan(&n.BlobID, &n.Size, &n.ContentHash, &created)
	if db.IsNoRows(err) {
		return core.NotFoundf("version not found")
	}
	if err != nil {
		return err
	}
	n.VersionID = versionID
	n.UpdatedAt = db.FromMs(created)
	n.MIME = names.OctetStream
	return nil
}

// Thumbnail implements core.Files: a reader of the node's thumbnail (JPEG
// or PNG; PermView). 404 when there is none (yet).
func (svc *Service) Thumbnail(ctx context.Context, p *core.Principal, id string) (core.BlobReader, error) {
	var thumb string
	err := svc.read(ctx, p, func(o *op) error {
		n, err := o.authorize(id, core.PermView, authOpt{allowTrashed: true})
		if err != nil {
			return err
		}
		thumb = n.ThumbBlobID
		return nil
	})
	if err != nil {
		return nil, err
	}
	if thumb == "" {
		return nil, core.NotFoundf("no thumbnail")
	}
	return svc.openBlob(ctx, thumb, -1)
}

// ---------- system-level helpers (shares, uploads, jobs) ----------

// GetSys implements core.Files: the node id without permission checks
// (trashed nodes included: check TrashedAt). Perm is PermView.
func (svc *Service) GetSys(ctx context.Context, id string) (*core.Node, error) {
	var out *nodeRow
	err := svc.readSys(ctx, func(o *op) error {
		n, err := o.mustNode(id)
		if err != nil {
			return err
		}
		n.Perm = core.PermView
		out = n
		return o.decorate([]*nodeRow{n})
	})
	if err != nil {
		return nil, err
	}
	return &out.Node, nil
}

// IsWithin implements core.Files: whether id is ancestorID or lies below it.
func (svc *Service) IsWithin(ctx context.Context, ancestorID, id string) (bool, error) {
	if !ids.Valid(ids.PrefixNode, ancestorID) || !ids.Valid(ids.PrefixNode, id) {
		return false, nil
	}
	var in bool
	err := svc.readSys(ctx, func(o *op) error {
		var err error
		in, err = o.isWithin(ancestorID, id)
		return err
	})
	return in, err
}

// ListSys implements core.Files: the live children of a live folder without
// permission checks (public share listings). Perm is PermView.
func (svc *Service) ListSys(ctx context.Context, folderID string, q core.ListQuery) (core.Page[core.Node], error) {
	var page core.Page[core.Node]
	err := svc.readSys(ctx, func(o *op) error {
		f, err := o.mustNode(folderID)
		if err != nil {
			return err
		}
		if f.TrashedAt != nil {
			return notFound()
		}
		if !f.IsDir() {
			return core.Invalid("id", "not a folder")
		}
		f.Perm = core.PermView
		page, err = o.listChildren(f, q)
		return err
	})
	return page, err
}

// OpenSys implements core.Files: a live file and a reader of its current
// content without permission checks. The caller closes the reader.
func (svc *Service) OpenSys(ctx context.Context, id string) (*core.Node, core.BlobReader, error) {
	n, err := svc.GetSys(ctx, id)
	if err != nil {
		return nil, nil, err
	}
	if n.TrashedAt != nil {
		return nil, nil, notFound()
	}
	if n.IsDir() {
		return nil, nil, core.Invalid("id", "folders have no content")
	}
	r, err := svc.openBlob(ctx, n.BlobID, n.Size)
	if err != nil {
		return nil, nil, err
	}
	return n, r, nil
}

// SysPrincipalFor implements core.Files: a principal acting as userID for
// public share operations (Via share, full auth level) with the role and
// capabilities of the account, exactly as a session of that user would
// carry them. Disabled users get 403, unknown ones 404.
func (svc *Service) SysPrincipalFor(ctx context.Context, userID string) (*core.Principal, error) {
	return svc.principalFor(ctx, userID, core.ViaShare)
}

// settingGuestsShare is registered by package shares and read by name.
const settingGuestsShare = "sharing.allow_guests_share"

func (svc *Service) principalFor(ctx context.Context, userID string, via core.AuthVia) (*core.Principal, error) {
	if !ids.Valid(ids.PrefixUser, userID) {
		return nil, core.NotFoundf("user not found")
	}
	var p core.Principal
	var status string
	var roleID, roleName, perms sql.NullString
	err := svc.env.DB.QueryRow(ctx, `SELECT u.id, u.username, u.role, u.status, u.role_id, r.name, r.permissions
		FROM users u LEFT JOIN roles r ON r.id = u.role_id WHERE u.id = ?`, userID).
		Scan(&p.UserID, &p.Username, &p.Role, &status, &roleID, &roleName, &perms)
	if db.IsNoRows(err) {
		return nil, core.NotFoundf("user not found")
	}
	if err != nil {
		return nil, err
	}
	if status != core.UserActive {
		return nil, core.Errorf(core.ErrForbidden, "the account is disabled")
	}
	p.RoleID = cmp.Or(roleID.String, string(p.Role))
	p.RoleName = cmp.Or(roleName.String, core.BuiltinRoleName(p.Role))
	p.SetCaps(core.EffectiveRoleCaps(p.Role, p.RoleID, core.DecodeStoredCaps(perms.String),
		svc.settingBool(settingGuestsShare, false)))
	p.Via = via
	p.AuthLevel = core.AuthLevelFull
	return &p, nil
}

// shareRow is the part of a share the archive code needs.
type shareRow struct {
	id, nodeID string
}

// activeShare loads a share that may be downloaded from: not disabled, not
// expired, downloads allowed (404 otherwise, like every public share error).
func (svc *Service) activeShare(ctx context.Context, shareID string) (*shareRow, error) {
	if !ids.Valid(ids.PrefixShare, shareID) {
		return nil, core.NotFoundf("share not found")
	}
	var s shareRow
	var allow bool
	var disabled, expires sql.NullInt64
	err := svc.env.DB.QueryRow(ctx, `SELECT id, node_id, allow_download, disabled_at, expires_at FROM shares WHERE id = ?`,
		shareID).Scan(&s.id, &s.nodeID, &allow, &disabled, &expires)
	if db.IsNoRows(err) {
		return nil, core.NotFoundf("share not found")
	}
	if err != nil {
		return nil, err
	}
	if disabled.Valid || (expires.Valid && expires.Int64 <= db.Ms(svc.env.Now())) {
		return nil, core.NotFoundf("share not found")
	}
	if !allow {
		return nil, core.Errorf(core.ErrForbidden, "downloads are disabled for this link")
	}
	return &s, nil
}
