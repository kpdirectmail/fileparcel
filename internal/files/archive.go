package files

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"strings"
	"time"
	"unicode/utf8"

	"fileparcel/internal/core"
	"fileparcel/internal/db"
	"fileparcel/internal/ids"
	"fileparcel/internal/names"
	"fileparcel/internal/ziputil"
)

// ---------- walk ----------

// Walk implements core.Files: a depth-first walk over rootIDs (each needs
// PermView; trashed items are skipped) calling fn for every live node,
// parents before children, siblings ordered by name. Children are read in
// keyset pages of 256 rows, so memory is bounded by depth × page size and
// no transaction is held while fn runs. fn may return fs.SkipDir for a
// folder to skip its contents; any other error stops the walk. The walk
// stops when ctx is canceled.
func (svc *Service) Walk(ctx context.Context, p *core.Principal, rootIDs []string, fn func(core.WalkEntry) error) error {
	list, err := checkIDs("node_ids", rootIDs)
	if err != nil {
		return err
	}
	var roots []*nodeRow
	if err := svc.read(ctx, p, func(o *op) error {
		roots = roots[:0]
		for _, id := range list {
			n, err := o.authorize(id, core.PermView, authOpt{})
			if err != nil {
				return err
			}
			roots = append(roots, n)
		}
		return nil
	}); err != nil {
		return err
	}
	return svc.walk(ctx, roots, fn)
}

// walkFrame is one folder being walked.
type walkFrame struct {
	id      string
	path    string
	depth   int
	perm    core.Perm
	page    []*nodeRow
	idx     int
	lastKey string
	lastID  string
	started bool
	done    bool
}

// walk visits roots and their live subtrees (see Walk).
func (svc *Service) walk(ctx context.Context, roots []*nodeRow, fn func(core.WalkEntry) error) error {
	for _, root := range roots {
		if err := ctx.Err(); err != nil {
			return err
		}
		err := fn(core.WalkEntry{Node: root.Node, Path: root.Name, Depth: 0})
		if errors.Is(err, fs.SkipDir) {
			continue
		}
		if err != nil {
			return err
		}
		if !root.IsDir() {
			continue
		}
		stack := []*walkFrame{{id: root.ID, path: root.Name, perm: root.Perm}}
		for len(stack) > 0 {
			if err := ctx.Err(); err != nil {
				return err
			}
			f := stack[len(stack)-1]
			if f.idx >= len(f.page) {
				if f.done {
					stack = stack[:len(stack)-1]
					continue
				}
				if err := svc.walkPage(ctx, f); err != nil {
					return err
				}
				continue
			}
			child := f.page[f.idx]
			f.idx++
			child.Perm = max(child.Perm, f.perm)
			err := fn(core.WalkEntry{Node: child.Node, Path: f.path + "/" + child.Name, Depth: f.depth + 1})
			if errors.Is(err, fs.SkipDir) {
				continue
			}
			if err != nil {
				return err
			}
			if child.IsDir() {
				stack = append(stack, &walkFrame{id: child.ID, path: f.path + "/" + child.Name, depth: f.depth + 1, perm: f.perm})
			}
		}
	}
	return nil
}

// walkPage loads the next page of f's live children.
func (svc *Service) walkPage(ctx context.Context, f *walkFrame) error {
	q := selectNodes + ` WHERE n.parent_id = ? AND n.trashed_at IS NULL`
	args := []any{f.id}
	if f.started {
		q += ` AND (n.name_key > ? OR (n.name_key = ? AND n.id > ?))`
		args = append(args, f.lastKey, f.lastKey, f.lastID)
	}
	q += ` ORDER BY n.name_key, n.id LIMIT ?`
	args = append(args, walkPage)
	rows, err := collectNodes(svc.env.DB.Query(ctx, q, args...))
	if err != nil {
		return err
	}
	f.started = true
	f.page, f.idx = rows, 0
	if len(rows) < walkPage {
		f.done = true
	}
	if len(rows) > 0 {
		last := rows[len(rows)-1]
		f.lastKey, f.lastID = last.NameKey, last.ID
	}
	return nil
}

// ---------- archive tickets ----------

var errTicket = core.NotFoundf("this download link has expired or was already used")

// archiveName builds the download file name: the given name, else the name
// of the single item, else "download", plus ".zip" / ".tar".
func archiveName(given string, itemNames []string, format string) string {
	base := strings.TrimSpace(given)
	for _, ext := range []string{".zip", ".tar"} {
		if len(base) > len(ext) && strings.EqualFold(base[len(base)-len(ext):], ext) {
			base = base[:len(base)-len(ext)]
		}
	}
	if base == "" && len(itemNames) == 1 {
		base = itemNames[0]
	}
	ext := "." + format
	fit := func(s string) string {
		for len(s)+len(ext) > names.MaxNameBytes {
			_, size := utf8.DecodeLastRuneInString(s)
			s = s[:len(s)-size]
		}
		return s
	}
	nfc, _, err := names.Clean(fit(strings.ToValidUTF8(base, "")))
	if err != nil {
		nfc = "download"
	}
	return fit(nfc) + ext
}

// CreateArchiveTicket implements core.Files: a single-use ticket (valid
// for 60 s, stored hashed) for downloading in.NodeIDs as one zip or tar.
// With shareID "" the ticket is bound to the principal, who needs PermView
// on every item; with a share id (public share archive), every item must
// lie within the share's node and the share must allow downloads (p is
// ignored and may be nil).
func (svc *Service) CreateArchiveTicket(ctx context.Context, p *core.Principal, shareID string, in core.ArchiveInput) (string, error) {
	list, err := checkIDs("node_ids", in.NodeIDs)
	if err != nil {
		return "", err
	}
	format := in.Format
	if format == "" {
		format = core.ArchiveZip
	}
	if format != core.ArchiveZip && format != core.ArchiveTar {
		return "", core.Invalid("format", "format must be zip or tar")
	}
	var itemNames []string
	var userID string
	if shareID == "" {
		if err := svc.read(ctx, p, func(o *op) error {
			itemNames = itemNames[:0]
			for _, id := range list {
				n, err := o.authorize(id, core.PermView, authOpt{})
				if err != nil {
					return err
				}
				itemNames = append(itemNames, n.Name)
			}
			userID = o.a.userID
			return nil
		}); err != nil {
			return "", err
		}
	} else {
		sh, err := svc.activeShare(ctx, shareID)
		if err != nil {
			return "", err
		}
		for _, id := range list {
			n, err := svc.GetSys(ctx, id)
			if err != nil {
				return "", err
			}
			in, err := svc.IsWithin(ctx, sh.nodeID, id)
			if err != nil {
				return "", err
			}
			if !in || n.TrashedAt != nil {
				return "", notFound()
			}
			itemNames = append(itemNames, n.Name)
		}
	}
	nodeIDs, err := json.Marshal(list)
	if err != nil {
		return "", err
	}
	ticket := ids.Token(32)
	now := svc.env.Now()
	err = svc.env.DB.Tx(ctx, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, `DELETE FROM archive_tickets WHERE expires_at < ?`,
			db.Ms(now.Add(-time.Hour))); err != nil {
			return err
		}
		_, err := tx.ExecContext(ctx, `INSERT INTO archive_tickets
			(id_hash, user_id, share_id, node_ids, format, name, created_at, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
			ids.HashToken(ticket), db.NullString(userID), db.NullString(shareID), string(nodeIDs), format,
			archiveName(in.Name, itemNames, format), db.Ms(now), db.Ms(now.Add(ticketTTL)))
		return err
	})
	if err != nil {
		return "", err
	}
	return ticket, nil
}

// validTicketSyntax rejects anything that cannot be a ticket before
// touching the database.
func validTicketSyntax(t string) bool {
	return len(t) >= 20 && len(t) <= 128 && ids.ValidToken(t)
}

const ticketCols = `COALESCE(user_id, ''), COALESCE(share_id, ''), node_ids, format, name, created_at, expires_at, used_at`

func scanTicket(sc scanner, now time.Time) (*core.ArchiveTicket, error) {
	var t core.ArchiveTicket
	var nodeIDs string
	var created, expires int64
	var used sql.NullInt64
	err := sc.Scan(&t.UserID, &t.ShareID, &nodeIDs, &t.Format, &t.Name, &created, &expires, &used)
	if db.IsNoRows(err) {
		return nil, errTicket
	}
	if err != nil {
		return nil, err
	}
	if used.Valid || expires <= db.Ms(now) {
		return nil, errTicket
	}
	if err := json.Unmarshal([]byte(nodeIDs), &t.NodeIDs); err != nil {
		return nil, core.Wrap(core.ErrCorrupt, "", err)
	}
	t.CreatedAt, t.ExpiresAt = db.FromMs(created), db.FromMs(expires)
	return &t, nil
}

// ConsumeArchiveTicket implements core.Files: validates the ticket and marks
// it used (single use, atomically). Unknown, expired and used tickets are
// all 404.
func (svc *Service) ConsumeArchiveTicket(ctx context.Context, ticket string) (*core.ArchiveTicket, error) {
	if !validTicketSyntax(ticket) {
		return nil, errTicket
	}
	hash := ids.HashToken(ticket)
	var out *core.ArchiveTicket
	err := svc.env.DB.Tx(ctx, func(tx *sql.Tx) error {
		now := svc.env.Now()
		t, err := scanTicket(tx.QueryRowContext(ctx, `SELECT `+ticketCols+` FROM archive_tickets WHERE id_hash = ?`, hash), now)
		if err != nil {
			return err
		}
		res, err := tx.ExecContext(ctx, `UPDATE archive_tickets SET used_at = ? WHERE id_hash = ? AND used_at IS NULL`,
			db.Ms(now), hash)
		if err != nil {
			return err
		}
		if n, _ := res.RowsAffected(); n != 1 {
			return errTicket
		}
		out = t
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// PeekArchiveTicket validates a ticket without consuming it (for HEAD
// requests, which must not burn the single use). It is not part of
// core.Files; handlers use it through an interface assertion.
func (svc *Service) PeekArchiveTicket(ctx context.Context, ticket string) (*core.ArchiveTicket, error) {
	if !validTicketSyntax(ticket) {
		return nil, errTicket
	}
	return scanTicket(svc.env.DB.QueryRow(ctx, `SELECT `+ticketCols+` FROM archive_tickets WHERE id_hash = ?`,
		ids.HashToken(ticket)), svc.env.Now())
}

// WriteArchive implements core.Files: streams the ticket's items as a zip
// (storage.zip_compression) or tar archive to w, walking the tree with
// bounded memory. Permissions are checked again: a user ticket walks as
// that user (PermView on every item; disabled users get 403), a share
// ticket requires an active share containing every item. Folders become
// directory entries (so empty folders survive), names are sanitized and
// de-duplicated by ziputil. Stops on ctx cancellation or write errors (the
// archive is then incomplete: callers must abort the response).
func (svc *Service) WriteArchive(ctx context.Context, t *core.ArchiveTicket, w io.Writer) (err error) {
	if t == nil {
		return core.Invalid("ticket", "missing ticket")
	}
	list, err := checkIDs("node_ids", t.NodeIDs)
	if err != nil {
		return err
	}
	var roots []*nodeRow
	var actorP *core.Principal
	entry := core.AuditEntry{Action: core.ActArchiveDownload, TargetType: "archive", TargetName: t.Name}
	switch {
	case t.ShareID != "":
		sh, err := svc.activeShare(ctx, t.ShareID)
		if err != nil {
			return err
		}
		entry.ActorName, entry.ActorVia = "anonymous", string(core.ViaShare)
		entry.TargetType, entry.TargetID = "share", sh.id
		if err := svc.readSys(ctx, func(o *op) error {
			for _, id := range list {
				n, err := o.mustNode(id)
				if err != nil {
					return err
				}
				in, err := o.isWithin(sh.nodeID, id)
				if err != nil {
					return err
				}
				if !in || n.TrashedAt != nil {
					return notFound()
				}
				n.Perm = core.PermView
				roots = append(roots, n)
			}
			return nil
		}); err != nil {
			return err
		}
	default:
		p := core.SystemPrincipal(core.ViaOffline)
		if t.UserID != "" {
			if p, err = svc.principalFor(ctx, t.UserID, core.AuthVia("ticket")); err != nil {
				return err
			}
		}
		actorP = p
		if err := svc.read(ctx, p, func(o *op) error {
			roots = roots[:0]
			for _, id := range list {
				n, err := o.authorize(id, core.PermView, authOpt{})
				if err != nil {
					return err
				}
				roots = append(roots, n)
			}
			return nil
		}); err != nil {
			return err
		}
	}

	opts := ziputil.Options{Format: ziputil.Format(t.Format),
		Compression: ziputil.Compression(svc.settingString(settingZipCompression, "auto"))}
	aw, err := ziputil.New(w, opts)
	if err != nil {
		opts.Compression = ziputil.CompressionAuto
		if aw, err = ziputil.New(w, opts); err != nil {
			return core.Invalid("format", err.Error())
		}
	}
	var files, bytes int64
	defer func() {
		entry.Details = map[string]any{"node_ids": list, "format": t.Format, "files": files, "bytes": bytes,
			"archive_bytes": aw.Written()}
		if err != nil {
			entry.Outcome = core.OutcomeFailure
		}
		svc.record(context.WithoutCancel(ctx), actorP, entry)
	}()
	err = svc.walk(ctx, roots, func(e core.WalkEntry) error {
		mod := e.Node.UpdatedAt
		if e.Node.ClientMtime != nil {
			mod = *e.Node.ClientMtime
		}
		if e.Node.IsDir() {
			return aw.AddDir(e.Path, mod)
		}
		if e.Node.Size == 0 && e.Node.BlobID == "" {
			files++
			return aw.AddFile(e.Path, mod, 0, strings.NewReader(""))
		}
		r, err := svc.openBlob(ctx, e.Node.BlobID, e.Node.Size)
		if err != nil {
			return err
		}
		defer r.Close()
		if err := aw.AddFile(e.Path, mod, e.Node.Size, r); err != nil {
			return err
		}
		files++
		bytes += e.Node.Size
		return nil
	})
	if err != nil {
		return err
	}
	return aw.Close()
}
