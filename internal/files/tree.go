package files

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"time"

	"fileparcel/internal/core"
	"fileparcel/internal/db"
	"fileparcel/internal/ids"
	"fileparcel/internal/names"
	"fileparcel/internal/thumbs"
)

// conflictField is a 409 conflict naming the offending input field.
func conflictField(field, msg string) error {
	return &core.Error{Code: core.ErrConflict.Code, Status: core.ErrConflict.Status, Message: msg, Field: field}
}

func existsMsg(name string) string { return "“" + name + "” already exists in this folder" }

// uid is the created_by/updated_by value of the actor (NULL for the system).
func (o *op) uid() any { return db.NullString(o.a.userID) }

// withPerm computes and sets the actor's effective permission on r.
func (o *op) withPerm(r *nodeRow) (*nodeRow, error) {
	_, eff, err := o.perms(r)
	if err != nil {
		return nil, err
	}
	r.Perm = eff
	return r, nil
}

// reload loads id again (after a change) with the actor's permission.
func (o *op) reload(id string) (*nodeRow, error) {
	r, err := o.mustNode(id)
	if err != nil {
		return nil, err
	}
	return o.withPerm(r)
}

// insertFolder creates a live folder.
func (o *op) insertFolder(spaceID, parentID, name, key string) (string, error) {
	id := ids.New(ids.PrefixNode)
	_, err := o.q.ExecContext(o.ctx, `INSERT INTO nodes
		(id, space_id, parent_id, kind, name, name_key, size, created_at, updated_at, created_by, updated_by)
		VALUES (?, ?, ?, 'folder', ?, ?, 0, ?, ?, ?, ?)`,
		id, spaceID, parentID, name, key, o.ms, o.ms, o.uid(), o.uid())
	if db.IsUnique(err) {
		return "", conflictField("name", existsMsg(name))
	}
	return id, err
}

// freeName returns the first "name (n)" variant not used by a live child.
func (o *op) freeName(parentID, name string, isDir bool) (string, string, error) {
	for n := 1; n <= maxNumbered; n++ {
		cand := names.Numbered(name, n, isDir)
		key := names.Key(cand)
		c, err := o.child(parentID, key)
		if err != nil {
			return "", "", err
		}
		if c == nil {
			return cand, key, nil
		}
	}
	return "", "", conflictField("name", "no free name for “"+name+"”")
}

// ensureDir returns the live folder name under parentID, creating it when
// missing. A file with that name is never touched: the first free
// "name (n)" folder is used instead (the same one for later calls).
func (o *op) ensureDir(spaceID, parentID, name string) (string, error) {
	for n := 0; n <= maxNumbered; n++ {
		cand := names.Numbered(name, n, true)
		key := names.Key(cand)
		c, err := o.child(parentID, key)
		if err != nil {
			return "", err
		}
		if c == nil {
			id, err := o.insertFolder(spaceID, parentID, cand, key)
			if err != nil {
				return "", err
			}
			o.audit(core.AuditEntry{Action: core.ActFolderCreate, TargetType: "node", TargetID: id, TargetName: cand,
				Details: map[string]any{"parent_id": parentID}})
			return id, nil
		}
		if c.kind == core.KindFolder {
			return c.id, nil
		}
	}
	return "", conflictField("rel_path", "no free folder name for “"+name+"”")
}

// Mkdir implements core.Files: creates the folder name in parentID
// (PermEdit; 409 when the name is taken).
func (svc *Service) Mkdir(ctx context.Context, p *core.Principal, parentID, name string) (*core.Node, error) {
	nfc, key, err := names.Clean(name)
	if err != nil {
		return nil, err
	}
	var out *nodeRow
	err = svc.write(ctx, p, func(o *op) error {
		parent, err := o.authorize(parentID, core.PermEdit, authOpt{})
		if err != nil {
			return err
		}
		if !parent.IsDir() {
			return core.Invalid("parent_id", "not a folder")
		}
		if c, err := o.child(parent.ID, key); err != nil {
			return err
		} else if c != nil {
			return conflictField("name", existsMsg(c.name))
		}
		id, err := o.insertFolder(parent.SpaceID, parent.ID, nfc, key)
		if err != nil {
			return err
		}
		if out, err = o.reload(id); err != nil {
			return err
		}
		o.audit(nodeAudit(core.ActFolderCreate, &out.Node, map[string]any{"parent_id": parent.ID}))
		return nil
	})
	if err != nil {
		return nil, err
	}
	return &out.Node, nil
}

// MkdirAll implements core.Files: creates every missing folder of relPath
// ("a/b/c", upload rules of names.SplitRelPath) below parentID and returns
// the deepest one. Existing folders are reused; a file in the way is left
// alone and "name (n)" is used instead.
func (svc *Service) MkdirAll(ctx context.Context, p *core.Principal, parentID, relPath string) (*core.Node, error) {
	segs, err := names.SplitRelPath(relPath)
	if err != nil {
		return nil, err
	}
	var out *nodeRow
	err = svc.write(ctx, p, func(o *op) error {
		parent, err := o.authorize(parentID, core.PermEdit, authOpt{})
		if err != nil {
			return err
		}
		if !parent.IsDir() {
			return core.Invalid("parent_id", "not a folder")
		}
		cur := parent.ID
		for _, s := range segs {
			if cur, err = o.ensureDir(parent.SpaceID, cur, s); err != nil {
				return err
			}
		}
		out, err = o.reload(cur)
		return err
	})
	if err != nil {
		return nil, err
	}
	return &out.Node, nil
}

// blobRow is a committed blob as recorded in the blobs table, plus the
// zip protection of the version that is about to use it (zipEnc,
// file_versions.zip_encryption; "" = not a protected zip).
type blobRow struct {
	id, hash string
	size     int64
	zipEnc   string
}

// validZipEnc reports whether enc is a value of file_versions.zip_encryption
// ("" = not protected).
func validZipEnc(enc string) bool {
	return enc == "" || enc == core.ZipEncAES256 || enc == core.ZipEncZipCrypto
}

// versionDetails returns the audit details of a new version, with its zip
// protection when it has one.
func versionDetails(blob *blobRow, d map[string]any) map[string]any {
	if blob.zipEnc != "" {
		d["zip_encryption"] = blob.zipEnc
	}
	return d
}

// blobInfo loads a ready blob (422 when unknown or not committed).
func (o *op) blobInfo(id string) (*blobRow, error) {
	b := blobRow{id: id}
	var state string
	err := o.q.QueryRowContext(o.ctx, `SELECT size, COALESCE(content_hash, ''), state FROM blobs WHERE id = ?`, id).
		Scan(&b.size, &b.hash, &state)
	if db.IsNoRows(err) {
		return nil, core.Invalid("blob", "unknown blob")
	}
	if err != nil {
		return nil, err
	}
	if state != "ready" {
		return nil, core.Invalid("blob", "the blob is not committed")
	}
	return &b, nil
}

// readHead returns the first bytes of a blob for MIME sniffing ([]byte{}
// for an empty blob, nil when it cannot be read).
func (svc *Service) readHead(ctx context.Context, blobID string, size int64) []byte {
	if size == 0 {
		return []byte{}
	}
	if svc.blobs == nil || blobID == "" {
		return nil
	}
	r, err := svc.blobs.Open(ctx, blobID)
	if err != nil {
		svc.log.Warn("mime sniff: open blob", "blob", blobID, "err", err)
		return nil
	}
	defer r.Close()
	buf := make([]byte, names.SniffLen)
	n, err := r.ReadAt(buf, 0)
	if err != nil && !errors.Is(err, io.EOF) {
		svc.log.Warn("mime sniff: read blob", "blob", blobID, "err", err)
		if n == 0 {
			return nil
		}
	}
	return buf[:n]
}

// thumbFor queues a thumbnail job for a new current version when enabled.
func (o *op) thumbFor(nodeID, versionID, mime string, size int64) {
	if size <= 0 || size > thumbs.MaxSourceBytes || !thumbs.Supported(mime) || o.svc.jobs == nil ||
		!o.svc.settingBool(settingThumbnails, true) {
		return
	}
	o.thumbQueue = append(o.thumbQueue, thumbParams{NodeID: nodeID, VersionID: versionID})
}

// CommitFile implements core.Files: it records the committed blob b as the
// file relPath (e.g. "Trip/day1/a.jpg"; missing folders are created, see
// MkdirAll) below parentID, which needs PermEdit. The stored MIME type is
// derived from the name, m.MIME (a hint for unknown extensions) and a sniff
// of the content (names.DetectMIME). The size and content hash are taken
// from the blobs table. The space's quota and storage.max_file_gb apply.
//
// Conflict policies for an existing entry with the same name: rename (the
// default) stores "name (n).ext"; replace adds a new version to an existing
// file (409 for a folder); fail returns 409; skip changes nothing and
// returns the existing node unchanged — its BlobID then differs from b.ID,
// which tells the caller that b was not used (and should be deleted).
//
// m.ZipEncryption records the new version as a password-protected zip
// (only the upload.zip job sets it; 422 for an unknown value).
func (svc *Service) CommitFile(ctx context.Context, p *core.Principal, parentID, relPath string, b *core.BlobInfo, m core.FileMeta, c core.ConflictPolicy) (*core.Node, error) {
	if b == nil || !ids.ValidBlobID(b.ID) {
		return nil, core.Invalid("blob", "a committed blob is required")
	}
	if c == "" {
		c = core.ConflictRename
	}
	if !c.Valid() {
		return nil, core.Invalid("conflict", "unknown conflict policy")
	}
	if !validZipEnc(m.ZipEncryption) {
		return nil, core.Invalid("zip_encryption", "unknown zip encryption")
	}
	segs, err := names.SplitRelPath(relPath)
	if err != nil {
		return nil, err
	}
	if err := svc.checkMaxFile(b.Size); err != nil {
		return nil, err
	}
	fileName := segs[len(segs)-1]
	mimeType := names.DetectMIME(fileName, m.MIME, svc.readHead(ctx, b.ID, b.Size))

	var out *nodeRow
	err = svc.write(ctx, p, func(o *op) error {
		parent, err := o.authorize(parentID, core.PermEdit, authOpt{})
		if err != nil {
			return err
		}
		if !parent.IsDir() {
			return core.Invalid("parent_id", "not a folder")
		}
		blob, err := o.blobInfo(b.ID)
		if err != nil {
			return err
		}
		blob.zipEnc = m.ZipEncryption
		if err := o.svc.checkMaxFile(blob.size); err != nil {
			return err
		}
		dirID := parent.ID
		for _, d := range segs[:len(segs)-1] {
			if dirID, err = o.ensureDir(parent.SpaceID, dirID, d); err != nil {
				return err
			}
		}
		out, err = o.commit(parent.SpaceID, dirID, fileName, blob, mimeType, m.ClientMtime, c)
		return err
	})
	if err != nil {
		return nil, err
	}
	return &out.Node, nil
}

// commit stores blob as the file name in folder dirID with policy c.
func (o *op) commit(spaceID, dirID, name string, blob *blobRow, mime string, mtime *time.Time, c core.ConflictPolicy) (*nodeRow, error) {
	key := names.Key(name)
	ex, err := o.child(dirID, key)
	if err != nil {
		return nil, err
	}
	if ex != nil {
		switch c {
		case core.ConflictFail:
			return nil, conflictField("name", existsMsg(ex.name))
		case core.ConflictSkip:
			return o.reload(ex.id)
		case core.ConflictReplace:
			if ex.kind != core.KindFile {
				return nil, conflictField("name", "“"+ex.name+"” is a folder and cannot be replaced by a file")
			}
			// Byte-identical content (same content hash and protection)
			// adds no version: sending a file again must not store, and
			// charge the quota for, a second copy of it. The existing node
			// is returned unchanged; the caller drops the unused blob.
			cur, err := o.mustNode(ex.id)
			if err != nil {
				return nil, err
			}
			if blob.hash != "" && cur.ContentHash == blob.hash && cur.ZipEncryption == blob.zipEnc {
				return o.withPerm(cur)
			}
			return o.addVersion(ex.id, blob, mime, mtime, core.ActFileUpload)
		default:
			if name, key, err = o.freeName(dirID, name, false); err != nil {
				return nil, err
			}
		}
	}
	if err := o.charge(spaceID, blob.size, true); err != nil {
		return nil, err
	}
	nodeID, verID := ids.New(ids.PrefixNode), ids.New(ids.PrefixVersion)
	_, err = o.q.ExecContext(o.ctx, `INSERT INTO nodes (id, space_id, parent_id, kind, name, name_key, size, mime,
		version_id, content_hash, client_mtime, created_at, updated_at, created_by, updated_by)
		VALUES (?, ?, ?, 'file', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		nodeID, spaceID, dirID, name, key, blob.size, db.NullString(mime), verID, db.NullString(blob.hash),
		db.NullMs(mtime), o.ms, o.ms, o.uid(), o.uid())
	if db.IsUnique(err) {
		return nil, conflictField("name", existsMsg(name))
	}
	if err != nil {
		return nil, err
	}
	if err := o.insertVersion(verID, nodeID, blob); err != nil {
		return nil, err
	}
	r, err := o.reload(nodeID)
	if err != nil {
		return nil, err
	}
	o.audit(nodeAudit(core.ActFileUpload, &r.Node, versionDetails(blob,
		map[string]any{"size": blob.size, "version_id": verID, "parent_id": dirID})))
	o.thumbFor(nodeID, verID, mime, blob.size)
	return r, nil
}

// insertVersion inserts the file_versions row verID of nodeID for blob
// (with its zip protection).
func (o *op) insertVersion(verID, nodeID string, blob *blobRow) error {
	_, err := o.q.ExecContext(o.ctx, `INSERT INTO file_versions
		(id, node_id, blob_id, size, content_hash, created_at, created_by, zip_encryption)
		VALUES (?, ?, ?, ?, ?, ?, ?, NULLIF(?, ''))`,
		verID, nodeID, blob.id, blob.size, db.NullString(blob.hash), o.ms, o.uid(), blob.zipEnc)
	return err
}

// addVersion makes blob the new current version of the file nodeID
// (quota checked), resets its thumbnail and prunes old versions. action is
// the audit action (file.upload, file.copy or file.version_restore).
func (o *op) addVersion(nodeID string, blob *blobRow, mime string, mtime *time.Time, action string) (*nodeRow, error) {
	n, err := o.mustNode(nodeID)
	if err != nil {
		return nil, err
	}
	verID := ids.New(ids.PrefixVersion)
	if err := o.insertVersion(verID, nodeID, blob); err != nil {
		return nil, err
	}
	if n.ThumbBlobID != "" {
		o.blobCheck = append(o.blobCheck, n.ThumbBlobID)
	}
	if _, err := o.q.ExecContext(o.ctx, `UPDATE nodes SET size = ?, mime = ?, version_id = ?, content_hash = ?,
		client_mtime = ?, updated_at = ?, updated_by = ?, thumb_blob_id = NULL WHERE id = ?`,
		blob.size, db.NullString(mime), verID, db.NullString(blob.hash), db.NullMs(mtime), o.ms, o.uid(), nodeID); err != nil {
		return nil, err
	}
	if err := o.pruneVersions(n.SpaceID, nodeID, verID, o.svc.versionsKeep()); err != nil {
		return nil, err
	}
	// Charged after the prune: the quota applies to what the transaction
	// commits, so a version that pushes an old one out needs room only for
	// the difference (a failure rolls the insert and the prune back).
	if err := o.charge(n.SpaceID, blob.size, true); err != nil {
		return nil, err
	}
	r, err := o.reload(nodeID)
	if err != nil {
		return nil, err
	}
	o.audit(nodeAudit(action, &r.Node, versionDetails(blob,
		map[string]any{"size": blob.size, "version_id": verID, "new_version": true})))
	o.thumbFor(nodeID, verID, mime, blob.size)
	return r, nil
}

// Rename implements core.Files (PermEdit; space roots cannot be renamed; a
// case-only rename is allowed). When the extension changes, the MIME type is
// derived again from the new name and the content.
func (svc *Service) Rename(ctx context.Context, p *core.Principal, id, name string) (*core.Node, error) {
	nfc, key, err := names.Clean(name)
	if err != nil {
		return nil, err
	}
	// Authorize first, then sniff the content outside any transaction.
	var pre *nodeRow
	if err := svc.read(ctx, p, func(o *op) error {
		var err error
		pre, err = o.authorize(id, core.PermEdit, authOpt{})
		return err
	}); err != nil {
		return nil, err
	}
	newMIME := ""
	if pre.Kind == core.KindFile && names.MIMEFromName(nfc) != names.MIMEFromName(pre.Name) {
		newMIME = names.DetectMIME(nfc, "", svc.readHead(ctx, pre.BlobID, pre.Size))
	}

	var out *nodeRow
	err = svc.write(ctx, p, func(o *op) error {
		n, err := o.authorize(id, core.PermEdit, authOpt{})
		if err != nil {
			return err
		}
		if n.ParentID == "" {
			return forbiddenf("the root folder of a space cannot be renamed")
		}
		if n.Name == nfc {
			out = n
			return nil
		}
		if c, err := o.child(n.ParentID, key); err != nil {
			return err
		} else if c != nil && c.id != n.ID {
			return conflictField("name", existsMsg(c.name))
		}
		mime := n.MIME
		if newMIME != "" && n.VersionID == pre.VersionID {
			mime = newMIME
		}
		if _, err := o.q.ExecContext(o.ctx, `UPDATE nodes SET name = ?, name_key = ?, mime = ?, updated_at = ?, updated_by = ?
			WHERE id = ?`, nfc, key, db.NullString(mime), o.ms, o.uid(), n.ID); err != nil {
			if db.IsUnique(err) {
				return conflictField("name", existsMsg(nfc))
			}
			return err
		}
		if n.Kind == core.KindFile && mime != n.MIME && n.ThumbBlobID == "" {
			o.thumbFor(n.ID, n.VersionID, mime, n.Size)
		}
		o.audit(nodeAudit(core.ActFileRename, &n.Node, map[string]any{"from": n.Name, "to": nfc}))
		out, err = o.reload(n.ID)
		return err
	})
	if err != nil {
		return nil, err
	}
	return &out.Node, nil
}

// destFolder authorizes a move/copy destination (a live folder, PermEdit).
func (o *op) destFolder(dest string) (*nodeRow, error) {
	d, err := o.authorize(dest, core.PermEdit, authOpt{})
	if err != nil {
		if errors.Is(err, core.ErrNotFound) {
			return nil, core.NotFoundf("destination folder not found")
		}
		return nil, err
	}
	if !d.IsDir() {
		return nil, core.Invalid("dest", "the destination is not a folder")
	}
	return d, nil
}

// Move implements core.Files: moves ids into dest (all or nothing, one
// transaction). Needs PermEdit on each item and on dest; moving an item to
// another space additionally needs PermOwner (PermManage in group spaces)
// on it and charges its versions to the destination's quota. Space roots
// cannot be moved; moving a folder into itself or a descendant is rejected.
// Conflicts (default fail): rename → "name (n)"; skip → item left in place
// (omitted from the result); replace → an existing file is moved to the
// trash first (folders cannot be replaced). An item that lies inside another
// item of the request moves with it (and is omitted from the result).
func (svc *Service) Move(ctx context.Context, p *core.Principal, idList []string, dest string, c core.ConflictPolicy) ([]core.Node, error) {
	list, err := checkIDs("ids", idList)
	if err != nil {
		return nil, err
	}
	if c == "" {
		c = core.ConflictFail
	}
	if !c.Valid() {
		return nil, core.Invalid("conflict", "unknown conflict policy")
	}
	var out []core.Node
	err = svc.write(ctx, p, func(o *op) error {
		out = out[:0]
		d, err := o.destFolder(dest)
		if err != nil {
			return err
		}
		items, err := o.outermost(list)
		if err != nil {
			return err
		}
		for _, id := range items {
			r, err := o.moveOne(d, id, c)
			if err != nil {
				return err
			}
			if r != nil {
				out = append(out, r.Node)
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (o *op) moveOne(d *nodeRow, id string, c core.ConflictPolicy) (*nodeRow, error) {
	n, err := o.authorize(id, core.PermEdit, authOpt{})
	if err != nil {
		return nil, err
	}
	if n.ParentID == "" {
		return nil, forbiddenf("the root folder of a space cannot be moved")
	}
	if in, err := o.isWithin(n.ID, d.ID); err != nil {
		return nil, err
	} else if in {
		return nil, core.Invalid("dest", "a folder cannot be moved into itself or one of its subfolders")
	}
	cross := n.SpaceID != d.SpaceID
	if cross {
		need := transferPerm(n.spaceKind)
		if n.Perm < need {
			return nil, forbiddenf("moving “%s” to another space needs %s permission", n.Name, need)
		}
		if err := o.auditTransfer(n, need); err != nil {
			return nil, err
		}
	}
	if n.ParentID == d.ID {
		return n, nil
	}
	name, key := n.Name, n.NameKey
	ex, err := o.child(d.ID, key)
	if err != nil {
		return nil, err
	}
	if ex != nil {
		switch c {
		case core.ConflictFail:
			return nil, conflictField("name", existsMsg(ex.name))
		case core.ConflictSkip:
			return nil, nil
		case core.ConflictReplace:
			if ex.kind != core.KindFile || n.Kind != core.KindFile {
				return nil, conflictField("name", "“"+ex.name+"” cannot be replaced (only files replace files)")
			}
			old, err := o.mustNode(ex.id)
			if err != nil {
				return nil, err
			}
			if err := o.trashOne(old); err != nil {
				return nil, err
			}
		default:
			if name, key, err = o.freeName(d.ID, n.Name, n.IsDir()); err != nil {
				return nil, err
			}
		}
	}
	if cross {
		var total int64
		if err := o.q.QueryRowContext(o.ctx, subtreeSQL+` SELECT COALESCE(SUM(v.size), 0)
			FROM file_versions v JOIN sub ON v.node_id = sub.id`, n.ID).Scan(&total); err != nil {
			return nil, err
		}
		if err := o.charge(d.SpaceID, total, true); err != nil {
			return nil, err
		}
		if err := o.charge(n.SpaceID, -total, false); err != nil {
			return nil, err
		}
		if _, err := o.q.ExecContext(o.ctx, subtreeSQL+` UPDATE nodes SET space_id = ?2 WHERE id IN (SELECT id FROM sub)`,
			n.ID, d.SpaceID); err != nil {
			return nil, err
		}
	}
	if _, err := o.q.ExecContext(o.ctx, `UPDATE nodes SET parent_id = ?, name = ?, name_key = ?, updated_at = ?, updated_by = ?
		WHERE id = ?`, d.ID, name, key, o.ms, o.uid(), n.ID); err != nil {
		if db.IsUnique(err) {
			return nil, conflictField("name", existsMsg(name))
		}
		return nil, err
	}
	o.audit(nodeAudit(core.ActFileMove, &n.Node, map[string]any{"from": n.ParentID, "to": d.ID, "name": name,
		"to_space": d.SpaceID, "cross_space": cross}))
	return o.reload(n.ID)
}

// Copy implements core.Files: copies ids (with their live subtrees) into
// dest in one transaction. Needs PermView on each item and PermEdit on
// dest. Copies share the blobs of the current versions (nothing is
// re-encrypted), but their sizes are charged to the destination's quota.
// Conflicts (default rename): skip → omitted; fail → 409; replace → the
// copied file becomes a new version of the existing file (folders cannot
// be replaced). Copying a folder into itself or a descendant is rejected.
// An item that lies inside another item of the request is copied with it
// only once. One call copies at most maxCopyNodes nodes in total (413).
func (svc *Service) Copy(ctx context.Context, p *core.Principal, idList []string, dest string, c core.ConflictPolicy) ([]core.Node, error) {
	list, err := checkIDs("ids", idList)
	if err != nil {
		return nil, err
	}
	if c == "" {
		c = core.ConflictRename
	}
	if !c.Valid() {
		return nil, core.Invalid("conflict", "unknown conflict policy")
	}
	var out []core.Node
	err = svc.write(ctx, p, func(o *op) error {
		out = out[:0]
		d, err := o.destFolder(dest)
		if err != nil {
			return err
		}
		items, err := o.outermost(list)
		if err != nil {
			return err
		}
		budget := maxCopyNodes // for the whole call: it is one transaction
		for _, id := range items {
			r, err := o.copyOne(d, id, c, &budget)
			if err != nil {
				return err
			}
			if r != nil {
				out = append(out, r.Node)
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// copySrc is a node being copied (zipEnc: the zip protection of its
// current version, which the copy keeps).
type copySrc struct {
	id, kind, name, key, mime, hash, thumb, blob, zipEnc string
	size                                                 int64
	mtime                                                *time.Time
}

func (o *op) copyOne(d *nodeRow, id string, c core.ConflictPolicy, budget *int64) (*nodeRow, error) {
	n, err := o.authorize(id, core.PermView, authOpt{})
	if err != nil {
		return nil, err
	}
	if in, err := o.isWithin(n.ID, d.ID); err != nil {
		return nil, err
	} else if in {
		return nil, core.Invalid("dest", "a folder cannot be copied into itself or one of its subfolders")
	}
	name, key := n.Name, n.NameKey
	ex, err := o.child(d.ID, key)
	if err != nil {
		return nil, err
	}
	if ex != nil {
		switch c {
		case core.ConflictFail:
			return nil, conflictField("name", existsMsg(ex.name))
		case core.ConflictSkip:
			return nil, nil
		case core.ConflictReplace:
			if ex.kind != core.KindFile || n.Kind != core.KindFile {
				return nil, conflictField("name", "“"+ex.name+"” cannot be replaced (only files replace files)")
			}
			if ex.id == n.ID {
				return n, nil
			}
			if n.BlobID == "" {
				return nil, core.Wrap(core.ErrCorrupt, "the file has no content", nil)
			}
			blob := &blobRow{id: n.BlobID, size: n.Size, hash: n.ContentHash, zipEnc: n.ZipEncryption}
			return o.addVersion(ex.id, blob, n.MIME, n.ClientMtime, core.ActFileCopy)
		default:
			if name, key, err = o.freeName(d.ID, n.Name, n.IsDir()); err != nil {
				return nil, err
			}
		}
	}
	var count, total int64
	if err := o.q.QueryRowContext(o.ctx, liveSubtreeSQL+` SELECT COUNT(*), COALESCE(SUM(CASE WHEN n.kind = 'file' THEN n.size END), 0)
		FROM nodes n JOIN sub ON n.id = sub.id`, n.ID).Scan(&count, &total); err != nil {
		return nil, err
	}
	if count > *budget {
		return nil, core.Wrap(core.ErrTooLarge, fmt.Sprintf("too many items to copy at once (at most %d files and folders in one copy); copy them in parts", maxCopyNodes), nil)
	}
	*budget -= count
	if err := o.charge(d.SpaceID, total, true); err != nil {
		return nil, err
	}
	src := &copySrc{id: n.ID, kind: n.Kind, name: name, key: key, mime: n.MIME, hash: n.ContentHash,
		thumb: n.ThumbBlobID, blob: n.BlobID, zipEnc: n.ZipEncryption, size: n.Size, mtime: n.ClientMtime}
	newID, err := o.copyNode(src, d.SpaceID, d.ID)
	if err != nil {
		return nil, err
	}
	if n.IsDir() {
		type pair struct{ src, dst string }
		queue := []pair{{n.ID, newID}}
		for len(queue) > 0 {
			cur := queue[0]
			queue = queue[1:]
			kids, err := o.copyChildren(cur.src)
			if err != nil {
				return nil, err
			}
			for _, k := range kids {
				id, err := o.copyNode(k, d.SpaceID, cur.dst)
				if err != nil {
					return nil, err
				}
				if k.kind == core.KindFolder {
					queue = append(queue, pair{k.id, id})
				}
			}
		}
	}
	r, err := o.reload(newID)
	if err != nil {
		return nil, err
	}
	o.audit(nodeAudit(core.ActFileCopy, &r.Node, map[string]any{"source_id": n.ID, "dest": d.ID, "items": count, "bytes": total}))
	return r, nil
}

// copyChildren reads the live children of a folder being copied.
func (o *op) copyChildren(parentID string) ([]*copySrc, error) {
	rows, err := o.q.QueryContext(o.ctx, `SELECT n.id, n.kind, n.name, n.name_key, COALESCE(n.mime, ''),
		COALESCE(n.content_hash, ''), COALESCE(n.thumb_blob_id, ''),
		COALESCE((SELECT v.blob_id FROM file_versions v WHERE v.id = n.version_id), ''),
		COALESCE((SELECT v.zip_encryption FROM file_versions v WHERE v.id = n.version_id), ''), n.size, n.client_mtime
		FROM nodes n WHERE n.parent_id = ? AND n.trashed_at IS NULL`, parentID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*copySrc
	for rows.Next() {
		var s copySrc
		var mt sql.NullInt64
		if err := rows.Scan(&s.id, &s.kind, &s.name, &s.key, &s.mime, &s.hash, &s.thumb, &s.blob, &s.zipEnc, &s.size, &mt); err != nil {
			return nil, err
		}
		s.mtime = db.FromNullMs(mt)
		out = append(out, &s)
	}
	return out, rows.Err()
}

// copyNode inserts a copy of s below parentID and returns its id. Files get
// one new version sharing the source blob and its zip protection (and
// thumbnail; a copy of an image whose thumbnail is not there yet gets its
// own thumbnail job).
func (o *op) copyNode(s *copySrc, spaceID, parentID string) (string, error) {
	if s.kind == core.KindFolder {
		return o.insertFolder(spaceID, parentID, s.name, s.key)
	}
	if s.blob == "" {
		return "", core.Wrap(core.ErrCorrupt, "“"+s.name+"” has no content", nil)
	}
	id, ver := ids.New(ids.PrefixNode), ids.New(ids.PrefixVersion)
	if _, err := o.q.ExecContext(o.ctx, `INSERT INTO nodes (id, space_id, parent_id, kind, name, name_key, size, mime,
		version_id, content_hash, client_mtime, created_at, updated_at, created_by, updated_by, thumb_blob_id)
		VALUES (?, ?, ?, 'file', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		id, spaceID, parentID, s.name, s.key, s.size, db.NullString(s.mime), ver, db.NullString(s.hash),
		db.NullMs(s.mtime), o.ms, o.ms, o.uid(), o.uid(), db.NullString(s.thumb)); err != nil {
		if db.IsUnique(err) {
			return "", conflictField("name", existsMsg(s.name))
		}
		return "", err
	}
	if err := o.insertVersion(ver, id, &blobRow{id: s.blob, hash: s.hash, size: s.size, zipEnc: s.zipEnc}); err != nil {
		return "", err
	}
	if s.thumb == "" {
		o.thumbFor(id, ver, s.mime, s.size)
	}
	return id, nil
}
