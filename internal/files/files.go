// Package files implements the node tree, the permission model, trash,
// versions, FTS search, stars, grants, walk and archives (DESIGN §6, §8.2).
// Owned by unit D. May import ziputil and thumbs.
//
// # Permissions (DESIGN §6)
//
// A principal's permission on a node is the maximum of
//
//   - the space permission: the owner of a personal space → PermOwner; group
//     manager → PermManage, group member → PermEdit on the group space, the
//     membership being direct or given by the account's custom role
//     (effective_group_members; manager wins);
//   - grants (node_grants) on the node or any ancestor to the user, one of
//     their groups or their custom role (viewer → PermView, editor →
//     PermEdit, manager → PermManage; expired grants are ignored), resolved
//     with a recursive CTE that reads the role from the users row, so role
//     changes apply to the next request;
//   - for the built-in owner/admin roles, PermManage everywhere — but only
//     when auth.admin_can_access_files is on (custom roles never); every
//     access that needs this override is audited as admin.file_access.
//
// The system principal without a user (admin socket, offline CLI) has
// PermOwner everywhere. API tokens additionally need the files:read scope
// for reads and files:write for changes. A node the principal cannot see at
// all is reported as 404 (no existence leak); a visible node with an
// insufficient permission as 403.
//
// Levels: PermView lists, downloads, previews, stars and archives;
// PermEdit uploads, creates folders, renames, moves within a space, trashes
// and restores; PermManage manages grants (and shares); PermOwner purges and
// moves out of a space. In group spaces nobody holds PermOwner, so there
// PermManage (group managers, manager grants in their subtree) is enough to
// purge and to move out; grants never give PermOwner.
//
// # Trash
//
// Trashing marks the node (trash_root = 1) and its live descendants
// (trash_root = 0) with the same trashed_at. Restoring brings back exactly
// the nodes trashed together (a recursive walk that stops at nested trash
// roots) to the original parent, or to the space root when the parent is in
// the trash itself; name conflicts are resolved with " (n)". Purging deletes
// the whole subtree, its versions, grants, stars and shares, releases the
// quota and deletes blobs that are no longer referenced.
//
// # Storage accounting
//
// spaces.used_bytes is the sum of the sizes of all versions of all nodes of
// the space, live and trashed. Copies share blobs (no bytes are copied) but
// are charged to the destination space. A personal space is limited by the
// owner's quota (users.quota_bytes; NULL = storage.default_quota_gb) and
// spaces.quota_bytes, whichever is smaller; 0 means unlimited.
//
// Blobs are reference counted through file_versions (thumbnails through
// nodes.thumb_blob_id, staged uploads through upload_files of open batches):
// after a version or node is deleted the blob is deleted as soon as nothing
// references it; the daily maintenance.blob_gc job catches anything missed.
//
// Writes run in one short transaction each (BEGIN IMMEDIATE on the single
// writer); blob I/O (MIME sniffing, thumbnails, archives, deletes) always
// happens outside transactions.
package files

import (
	"context"
	"database/sql"
	"errors"
	"log/slog"
	"time"

	"fileparcel/internal/core"
	"fileparcel/internal/db"
)

// Service implements core.Files.
type Service struct {
	env   *core.Env
	blobs core.BlobStore
	jobs  core.Jobs
	log   *slog.Logger
}

var _ core.Files = (*Service)(nil)

// Limits.
const (
	// maxBatch bounds the number of ids of one move/copy/trash/restore/purge
	// request and of one archive.
	maxBatch = 1000
	// maxNumbered bounds the " (n)" search of the rename conflict policy.
	maxNumbered = 10_000
	// walkPage is the keyset page size of Walk.
	walkPage = 256
	// ticketTTL is the lifetime of an archive ticket.
	ticketTTL = 60 * time.Second
)

// maxPurgeNodes bounds the number of nodes one purge transaction deletes. A
// larger subtree is purged over several transactions: the writer pool is a
// single connection (DESIGN §6), so an unbounded delete — plus the fts5
// delete trigger fired per row — would block every other write for as long
// as it runs. A variable so the tests can shrink it.
var maxPurgeNodes = 20_000

// maxCopyNodes bounds the total number of nodes one Copy call inserts —
// summed over all its items, since the whole call is one transaction on the
// single writer connection, with a node insert (plus its fts5 trigger and,
// for a file, a version insert) per copied node. Same order as
// maxPurgeNodes; a variable so the tests can shrink it.
var maxCopyNodes int64 = 20_000

// New creates the service (constructor signature fixed by DESIGN §5.2) and
// registers the job kinds it owns (thumbs.generate, maintenance.trash,
// maintenance.versions and — unless the blob store registers its own GC job,
// see registerJobs — maintenance.blob_gc) with their daily schedules.
func New(env *core.Env, blobs core.BlobStore, jobs core.Jobs) (*Service, error) {
	if env == nil || env.DB == nil {
		return nil, errors.New("files: env with a database required")
	}
	log := env.Log
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	svc := &Service{env: env, blobs: blobs, jobs: jobs, log: log.With("svc", "files")}
	if jobs != nil {
		svc.registerJobs(jobs)
	}
	return svc, nil
}

// ---------- errors ----------

var errNodeNotFound = core.NotFoundf("file or folder not found")

func notFound() error { return errNodeNotFound }

func forbiddenf(format string, a ...any) error { return core.Errorf(core.ErrForbidden, format, a...) }

// ---------- settings ----------

func (svc *Service) settingInt(key string, def int64) int64 {
	if svc.env.Settings == nil {
		return def
	}
	if _, err := svc.env.Settings.Raw(key); err != nil {
		return def
	}
	return svc.env.Settings.Int(key)
}

func (svc *Service) settingBool(key string, def bool) bool {
	if svc.env.Settings == nil {
		return def
	}
	if _, err := svc.env.Settings.Raw(key); err != nil {
		return def
	}
	return svc.env.Settings.Bool(key)
}

func (svc *Service) settingString(key, def string) string {
	if svc.env.Settings == nil {
		return def
	}
	if _, err := svc.env.Settings.Raw(key); err != nil {
		return def
	}
	if v := svc.env.Settings.String(key); v != "" {
		return v
	}
	return def
}

// ---------- operations ----------

// querier is satisfied by *sql.Tx and *sql.DB.
type querier interface {
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
}

// op is the state of one service call: the actor, the transaction (or read
// snapshot) and the side effects to run after it (audit entries, blob
// deletions, thumbnail jobs). A new op is created for every attempt of a
// retried transaction, so side effects are never duplicated.
type op struct {
	svc *Service
	ctx context.Context
	q   querier
	a   *actor
	now time.Time
	ms  int64

	audits     []core.AuditEntry // recorded after a successful commit
	always     []core.AuditEntry // recorded whatever the outcome (admin.file_access)
	blobCheck  []string          // blobs to delete after commit when unreferenced
	thumbQueue []thumbParams     // thumbnail jobs to enqueue after commit
}

func (svc *Service) newOp(ctx context.Context, q querier, a *actor) *op {
	now := svc.env.Now()
	return &op{svc: svc, ctx: ctx, q: q, a: a, now: now, ms: db.Ms(now)}
}

// write runs fn in a write transaction as p.
func (svc *Service) write(ctx context.Context, p *core.Principal, fn func(o *op) error) error {
	var last *op
	err := svc.env.DB.Tx(ctx, func(tx *sql.Tx) error {
		a, err := svc.newActor(ctx, tx, p)
		if err != nil {
			return err
		}
		last = svc.newOp(ctx, tx, a)
		return fn(last)
	})
	if last != nil {
		last.finish(err == nil)
	}
	return err
}

// writeSys runs fn in a write transaction as the system.
func (svc *Service) writeSys(ctx context.Context, fn func(o *op) error) error {
	var last *op
	err := svc.env.DB.Tx(ctx, func(tx *sql.Tx) error {
		last = svc.newOp(ctx, tx, systemActor())
		return fn(last)
	})
	if last != nil {
		last.finish(err == nil)
	}
	return err
}

// read runs fn on a read-only snapshot as p.
func (svc *Service) read(ctx context.Context, p *core.Principal, fn func(o *op) error) error {
	var last *op
	err := svc.env.DB.Read(ctx, func(tx *sql.Tx) error {
		a, err := svc.newActor(ctx, tx, p)
		if err != nil {
			return err
		}
		last = svc.newOp(ctx, tx, a)
		return fn(last)
	})
	if last != nil {
		last.finish(err == nil)
	}
	return err
}

// readSys runs fn on a read-only snapshot as the system.
func (svc *Service) readSys(ctx context.Context, fn func(o *op) error) error {
	return svc.env.DB.Read(ctx, func(tx *sql.Tx) error {
		return fn(svc.newOp(ctx, tx, systemActor()))
	})
}

// finish runs the deferred side effects.
func (o *op) finish(ok bool) {
	ctx := context.WithoutCancel(o.ctx)
	for _, e := range o.always {
		o.svc.record(ctx, o.a.p, e)
	}
	if !ok {
		return
	}
	for _, e := range o.audits {
		o.svc.record(ctx, o.a.p, e)
	}
	if len(o.blobCheck) > 0 {
		o.svc.deleteUnreferenced(ctx, o.blobCheck)
	}
	for _, t := range o.thumbQueue {
		o.svc.enqueueThumb(ctx, t)
	}
}

// audit queues an audit entry for after the commit.
func (o *op) audit(e core.AuditEntry) { o.audits = append(o.audits, e) }

// record writes an audit entry, filling the actor from p.
func (svc *Service) record(ctx context.Context, p *core.Principal, e core.AuditEntry) {
	if svc.env.Audit == nil {
		return
	}
	if p != nil && e.ActorID == "" && e.ActorName == "" {
		e.ActorID = p.UserID
		e.ActorName = p.Username
		e.ActorVia = string(p.Via)
		if p.IP.IsValid() {
			e.IP = p.IP.String()
		}
		e.UserAgent = p.UserAgent
		e.RequestID = p.RequestID
	}
	svc.env.Audit.Record(ctx, e)
}

// nodeAudit builds an audit entry for a node.
func nodeAudit(action string, n *core.Node, details any) core.AuditEntry {
	return core.AuditEntry{Action: action, TargetType: "node", TargetID: n.ID, TargetName: n.Name, Details: details}
}

// ---------- blob reference counting ----------

// blobReferenced reports whether anything still references blob id: a file
// version, a thumbnail, or a file of an upload batch that is still open or
// finalizing (the same rule as the blob store's GC; rows of finished batches
// only keep the id for the record).
func blobReferenced(ctx context.Context, q querier, id string) (bool, error) {
	var ref bool
	err := q.QueryRowContext(ctx, `SELECT
		EXISTS(SELECT 1 FROM file_versions WHERE blob_id = ?1)
		OR EXISTS(SELECT 1 FROM nodes WHERE thumb_blob_id = ?1)
		OR EXISTS(SELECT 1 FROM upload_files uf JOIN upload_batches ub ON ub.id = uf.batch_id
			WHERE uf.blob_id = ?1 AND ub.state IN ('open', 'finalizing'))`, id).Scan(&ref)
	return ref, err
}

// deleteUnreferenced deletes the blobs of ids that nothing references any
// more. Once a blob's last reference is gone no new reference can appear
// (references are only ever created to fresh blobs or copied from existing
// references), so check-then-delete is safe. Errors are logged; the daily
// maintenance.blob_gc job retries.
func (svc *Service) deleteUnreferenced(ctx context.Context, ids []string) {
	if svc.blobs == nil {
		return
	}
	seen := map[string]bool{}
	for _, id := range ids {
		if id == "" || seen[id] {
			continue
		}
		seen[id] = true
		ref, err := blobReferenced(ctx, svc.env.DB.Reader(), id)
		if err != nil {
			svc.log.Warn("blob reference check failed", "blob", id, "err", err)
			continue
		}
		if ref {
			continue
		}
		if err := svc.blobs.Delete(ctx, id); err != nil && !errors.Is(err, core.ErrNotFound) {
			svc.log.Warn("blob delete failed (maintenance.blob_gc will retry)", "blob", id, "err", err)
		}
	}
}
