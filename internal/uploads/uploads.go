// Package uploads implements the parted upload protocol of DESIGN §8.1:
// upload batches with path validation and quota reservation, parted and
// small-file transfers into the encrypted blob store, per-file and per-batch
// completion (mode=files commits one node per file; mode=zip bundles the
// staged blobs into a single .zip through the upload.zip job, optionally
// password-protected: zippassword.go), aborts and the hourly
// maintenance.uploads expiry job. Public file requests use the
// same service with an UploadActor carrying the share id. Owned by unit E.
// May import ziputil.
//
// Invariants:
//   - a batch belongs to its quota owner (user_id) or, for file requests, to
//     its share (share_id); every call re-checks that the actor owns the
//     batch and answers 404 otherwise (no existence leak);
//   - write transactions never span blob or network I/O: data is streamed
//     into the blob store first, the outcome is recorded in a short tx;
//   - an in-process keyed lock serialises the state machine of one upload
//     file (blob creation, completion, abort) and duplicate sends of one
//     part, while different parts of a file are written in parallel; the
//     file lock is never held while a request body is read, so a slow
//     client cannot stall an abort or the expiry job;
//   - reserved_bytes of a batch is the declared size of its files that are
//     neither committed nor released (in mode=zip plus a bound of the zip
//     format's overhead: the .zip is what gets stored); quota checks count
//     every open reservation of the destination space (and of the share for
//     requests) inside the inserting transaction, so concurrent batches
//     cannot over-commit.
package uploads

import (
	"context"
	"crypto/subtle"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"mime"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"fileparcel/internal/core"
	"fileparcel/internal/db"
	"fileparcel/internal/ids"
	"fileparcel/internal/names"
)

// Protocol constants (DESIGN §8.1).
const (
	// SmallMax is the largest file (in bytes) sent with the small-file path
	// (PUT /upload-batches/{id}/small); larger files are sent in parts.
	SmallMax = 8 << 20
	// MaxFilesPerCall bounds the entries of one CreateBatch / AddFiles call
	// (the browser sends chunks of 1000).
	MaxFilesPerCall = 5000
	// MaxFilesPerBatch bounds the entries of one batch; batches of public
	// file requests are capped lower (MaxFilesPerShareBatch: every entry is
	// a row and possibly an empty folder in the owner's space, and the
	// browser client sends requests in batches of 1000).
	MaxFilesPerBatch      = 100_000
	MaxFilesPerShareBatch = 10_000
	// MaxOpenBatchesPerUser is the per-user cap of open (or finalizing) batches.
	MaxOpenBatchesPerUser = 20
	// MaxOpenBatchesPerShareClient caps open batches of one file request per
	// client IP; MaxOpenBatchesPerShare caps them per file request.
	MaxOpenBatchesPerShareClient = 20
	MaxOpenBatchesPerShare       = 200
	// MaxUploaderName is the longest uploader name of a file request (runes).
	MaxUploaderName = 100
	// MaxPartCount is the most parts one upload may have; the part-number
	// parsers of the HTTP routes refuse any part number beyond it
	// (uploadapi.MaxPartCount mirrors it).
	MaxPartCount = 1 << 20
	// MaxDeclaredFileBytes bounds a single declared file size when no
	// smaller limit applies (storage.max_file_gb, the file request's own
	// per-file limit): 8 TiB, the largest file MaxPartCount parts can
	// carry — a larger one would be accepted, then fail at its part
	// 2^20. It also keeps the declared total of a batch inside int64
	// (MaxFilesPerBatch × 2^43 < 2^60): without a bound, a client could
	// declare sizes whose sum wraps negative, and every guard that skips a
	// non-positive amount (space quota, share quota, free disk) would wave
	// the upload through — and leave a negative reservation behind that
	// under-counts the quota of the whole space.
	MaxDeclaredFileBytes = int64(MaxPartCount) * core.PartSize
	// visitorMark separates the client IP from the visitor id inside the
	// actor_session of a file-request batch ("ip:<addr>|vis:<id>").
	visitorMark = "|vis:"
	// finishedRetention is how long finished batch rows are kept.
	finishedRetention = 7 * 24 * time.Hour
	maxClientRef      = 128
	gib               = int64(1) << 30
	// Disk headroom: refuse uploads that would leave less than 1 GiB or 2 %.
	minFreeBytes = gib
	minFreePct   = 2
)

// Service implements core.Uploads.
type Service struct {
	env   *core.Env
	files core.Files
	blobs core.BlobStore
	jobs  core.Jobs
	log   *slog.Logger

	// shares is bound late (Bind): share access log and owner notification
	// for completed file-request batches. Optional.
	shares core.Shares

	locks keyLock
	// diskFree reports free/total bytes of the blob store's file system
	// (replaceable in tests).
	diskFree func(path string) (free, total uint64, err error)
}

var _ core.Uploads = (*Service)(nil)

// New creates the service (constructor signature fixed by DESIGN §5.2) and
// registers the upload.zip job and the hourly maintenance.uploads schedule.
func New(env *core.Env, files core.Files, blobs core.BlobStore, jobs core.Jobs) (*Service, error) {
	if env == nil || env.DB == nil {
		return nil, errors.New("uploads: env with a database required")
	}
	log := env.Log
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	svc := &Service{env: env, files: files, blobs: blobs, jobs: jobs, log: log.With("svc", "uploads"), diskFree: diskFree}
	if jobs != nil {
		jobs.Register(core.JobUploadZip, svc.runZipJob, core.JobOptions{MaxConcurrent: 2})
		jobs.Register(core.JobMaintUploads, svc.runExpireJob,
			core.JobOptions{Exclusive: core.JobMaintUploads, Timeout: time.Hour, Hidden: true})
		if err := jobs.Schedule(core.JobMaintUploads, "17 * * * *", core.JobMaintUploads, nil); err != nil {
			return nil, fmt.Errorf("uploads: schedule %s: %w", core.JobMaintUploads, err)
		}
	}
	return svc, nil
}

// Bind implements core.Binder: it picks up the shares service (file-request
// access log and owner notification).
func (svc *Service) Bind(s *core.Services) error {
	if s != nil {
		svc.shares = s.Shares
	}
	return nil
}

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

func (svc *Service) parallel() int {
	return int(min(max(svc.settingInt(SettingParallel, DefaultParallel), 1), 16))
}

func (svc *Service) expiry() time.Duration {
	h := svc.settingInt(SettingExpiryHours, DefaultExpiryHours)
	if h <= 0 {
		h = DefaultExpiryHours
	}
	return time.Duration(h) * time.Hour
}

// maxFileBytes is storage.max_file_gb in bytes (0 = unlimited).
func (svc *Service) maxFileBytes() int64 {
	gb := svc.settingInt(settingMaxFileGB, 0)
	if gb <= 0 {
		return 0
	}
	return gb * gib
}

// ---------- rows ----------

type scanner interface{ Scan(dest ...any) error }

type querier interface {
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
}

// batchCols are the columns of a batch as the API shows it. The sealed .zip
// password (zip_password_enc) is never among them: only openZipPassword
// reads it.
const batchCols = `id, user_id, share_id, uploader, actor_session, folder_id, mode, zip_name, zip_encryption, conflict,
	declared_files, declared_bytes, reserved_bytes, state, job_id, result_node_id, error,
	created_at, updated_at, expires_at`

func scanBatch(sc scanner) (*core.UploadBatch, error) {
	var (
		b                                                         core.UploadBatch
		shareID, uploader, actor, zipName, zipEnc, job, res, errS sql.NullString
		conflict                                                  string
		created, updated, expires                                 int64
	)
	if err := sc.Scan(&b.ID, &b.UserID, &shareID, &uploader, &actor, &b.FolderID, &b.Mode, &zipName, &zipEnc, &conflict,
		&b.DeclaredFiles, &b.DeclaredBytes, &b.ReservedBytes, &b.State, &job, &res, &errS,
		&created, &updated, &expires); err != nil {
		return nil, err
	}
	b.ShareID, b.Uploader, b.ActorSession = shareID.String, uploader.String, actor.String
	b.ZipName, b.ZipEncryption = zipName.String, zipEnc.String
	b.JobID, b.ResultNodeID, b.Error = job.String, res.String, errS.String
	b.Conflict = core.ConflictPolicy(conflict)
	b.CreatedAt, b.UpdatedAt, b.ExpiresAt = db.FromMs(created), db.FromMs(updated), db.FromMs(expires)
	return &b, nil
}

// fileRow is an upload_files row.
type fileRow struct {
	core.UploadFileState
	ClientMtime *time.Time
	MIME        string
}

const fileCols = `id, batch_id, client_ref, rel_path, kind, size, client_mtime, mime, blob_id,
	part_count, state, node_id, error, updated_at`

func scanFile(sc scanner) (*fileRow, error) {
	var (
		f                       fileRow
		mtime                   sql.NullInt64
		mimeT, blob, node, errS sql.NullString
		updated                 int64
	)
	if err := sc.Scan(&f.ID, &f.BatchID, &f.ClientRef, &f.RelPath, &f.Kind, &f.Size, &mtime, &mimeT, &blob,
		&f.PartCount, &f.State, &node, &errS, &updated); err != nil {
		return nil, err
	}
	f.ClientMtime = db.FromNullMs(mtime)
	f.MIME, f.BlobID, f.NodeID, f.Error = mimeT.String, blob.String, node.String, errS.String
	f.UpdatedAt = db.FromMs(updated)
	f.PartsDone = []int{}
	return &f, nil
}

// state returns the API view of f.
func (f *fileRow) state() *core.UploadFileState {
	s := f.UploadFileState
	if s.PartsDone == nil {
		s.PartsDone = []int{}
	}
	return &s
}

// decorate fills the protocol parameters of b.
func (svc *Service) decorate(b *core.UploadBatch) *core.UploadBatch {
	b.PartSize = core.PartSize
	b.Parallel = svc.parallel()
	b.SmallMax = SmallMax
	return b
}

func (svc *Service) batchByID(ctx context.Context, q querier, id string) (*core.UploadBatch, error) {
	b, err := scanBatch(q.QueryRowContext(ctx, `SELECT `+batchCols+` FROM upload_batches WHERE id = ?`, id))
	if db.IsNoRows(err) {
		return nil, core.NotFoundf("upload batch not found")
	}
	return b, err
}

func (svc *Service) fileByID(ctx context.Context, q querier, id string) (*fileRow, error) {
	f, err := scanFile(q.QueryRowContext(ctx, `SELECT `+fileCols+` FROM upload_files WHERE id = ?`, id))
	if db.IsNoRows(err) {
		return nil, core.NotFoundf("upload not found")
	}
	return f, err
}

// owns reports whether actor a may use batch b: a file-request visitor owns
// the batches its own client opened in that share, users own their own
// non-share batches. An actor without a principal is an internal caller
// (shares.Revoke aborting what is left of a request), which owns every batch
// of its share.
func owns(a core.UploadActor, b *core.UploadBatch) bool {
	if a.ShareID != "" {
		if b.ShareID != a.ShareID {
			return false
		}
		if a.P == nil {
			return true
		}
		return sameVisitor(b.ActorSession, actorSession(a))
	}
	return a.P != nil && a.P.UserID != "" && b.ShareID == "" && b.UserID == a.P.UserID
}

// sameVisitor reports whether the actor session of a request identifies the
// client that opened the batch. Everyone visiting a file request acts as the
// same principal (the share owner), so without this every visitor would own
// every batch of the share and could read or abort the uploads of another
// visitor. Batches opened by a client that keeps its visitor cookie carry a
// "|vis:<id>" suffix and are bound to it; rows without one (a client that
// sends no cookies, or a row written before the cookie existed) keep the
// share-wide behaviour, since there is nothing better to compare.
func sameVisitor(batch, actor string) bool {
	id, ok := visitorOf(batch)
	if !ok {
		return true
	}
	cur, _ := visitorOf(actor)
	return subtle.ConstantTimeCompare([]byte(id), []byte(cur)) == 1
}

// visitorOf returns the visitor id part of an actor session ("…|vis:<id>").
func visitorOf(session string) (string, bool) {
	_, id, ok := strings.Cut(session, visitorMark)
	return id, ok
}

// loadBatch returns the batch if a owns it (404 otherwise).
func (svc *Service) loadBatch(ctx context.Context, a core.UploadActor, id string) (*core.UploadBatch, error) {
	if !ids.Valid(ids.PrefixUploadBatch, id) {
		return nil, core.NotFoundf("upload batch not found")
	}
	b, err := svc.batchByID(ctx, svc.env.DB.Reader(), id)
	if err != nil {
		return nil, err
	}
	if !owns(a, b) {
		return nil, core.NotFoundf("upload batch not found")
	}
	return b, nil
}

// loadFile returns an upload file and its batch if a owns the batch.
func (svc *Service) loadFile(ctx context.Context, a core.UploadActor, id string) (*fileRow, *core.UploadBatch, error) {
	if !ids.Valid(ids.PrefixUploadFile, id) {
		return nil, nil, core.NotFoundf("upload not found")
	}
	f, err := svc.fileByID(ctx, svc.env.DB.Reader(), id)
	if err != nil {
		return nil, nil, err
	}
	b, err := svc.batchByID(ctx, svc.env.DB.Reader(), f.BatchID)
	if err != nil {
		return nil, nil, err
	}
	if !owns(a, b) {
		return nil, nil, core.NotFoundf("upload not found")
	}
	return f, b, nil
}

// partsDone returns the received part numbers of the given uploads.
func (svc *Service) partsDone(ctx context.Context, batchID, uploadID string) (map[string][]int, error) {
	var rows *sql.Rows
	var err error
	if uploadID != "" {
		rows, err = svc.env.DB.Query(ctx, `SELECT upload_id, n FROM upload_parts WHERE upload_id = ? ORDER BY n`, uploadID)
	} else {
		rows, err = svc.env.DB.Query(ctx, `SELECT p.upload_id, p.n FROM upload_parts p
			JOIN upload_files f ON f.id = p.upload_id WHERE f.batch_id = ? ORDER BY p.upload_id, p.n`, batchID)
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string][]int{}
	for rows.Next() {
		var id string
		var n int
		if err := rows.Scan(&id, &n); err != nil {
			return nil, err
		}
		out[id] = append(out[id], n)
	}
	return out, rows.Err()
}

// fileState returns the current API state of one upload file.
func (svc *Service) fileState(ctx context.Context, id string) (*core.UploadFileState, error) {
	f, err := svc.fileByID(ctx, svc.env.DB.Reader(), id)
	if err != nil {
		return nil, err
	}
	parts, err := svc.partsDone(ctx, "", id)
	if err != nil {
		return nil, err
	}
	s := f.state()
	if p := parts[id]; p != nil {
		s.PartsDone = p
	}
	return s, nil
}

// ---------- validation ----------

// entry is a validated UploadFileInput.
type entry struct {
	id        string
	ref       string
	relPath   string
	kind      string
	size      int64
	mtime     sql.NullInt64
	mime      string
	partCount int
	skipped   bool // declared "skipped": its name is taken and the policy keeps the existing file (preflight)
}

// limits are the per-file limits of a batch.
type limits struct {
	maxFile      int64 // storage.max_file_gb (0 = none)
	shareMaxFile int64 // shares.upload_max_file_bytes (0 = none)
}

func (l limits) check(field string, size int64) error {
	if l.shareMaxFile > 0 && size > l.shareMaxFile {
		return &core.Error{Code: core.ErrTooLarge.Code, Status: core.ErrTooLarge.Status, Field: field,
			Message: fmt.Sprintf("the file is larger than this request allows (%d bytes)", l.shareMaxFile)}
	}
	if l.maxFile > 0 && size > l.maxFile {
		return &core.Error{Code: core.ErrTooLarge.Code, Status: core.ErrTooLarge.Status, Field: field,
			Message: fmt.Sprintf("the file is larger than the maximum file size (%d bytes)", l.maxFile)}
	}
	if size > MaxDeclaredFileBytes {
		return &core.Error{Code: core.ErrTooLarge.Code, Status: core.ErrTooLarge.Status, Field: field,
			Message: fmt.Sprintf("the file is larger than an upload can be (at most %d bytes)", MaxDeclaredFileBytes)}
	}
	return nil
}

// checkZip applies the per-file limits to the single file a zip-mode batch
// is stored as; size bounds that zip (its declared data and the format
// overhead, zipEntryOverhead). Checking only each entry would let a batch
// whose zip cannot be stored upload everything first and then fail — and
// a failed zip deletes every staged file.
func (l limits) checkZip(size int64) error {
	if l.shareMaxFile > 0 && size > l.shareMaxFile {
		return &core.Error{Code: core.ErrTooLarge.Code, Status: core.ErrTooLarge.Status, Field: "files",
			Message: fmt.Sprintf("the .zip of this upload would be larger than this request allows (%d bytes)", l.shareMaxFile)}
	}
	if l.maxFile > 0 && size > l.maxFile {
		return &core.Error{Code: core.ErrTooLarge.Code, Status: core.ErrTooLarge.Status, Field: "files",
			Message: fmt.Sprintf("the .zip of this upload would be larger than the maximum file size (%d bytes)", l.maxFile)}
	}
	return nil
}

// maxMtime is 9999-12-31 in Unix milliseconds.
const maxMtime = 253402300799000

func validClientRef(s string) bool {
	if s == "" || len(s) > maxClientRef || !utf8.ValidString(s) {
		return false
	}
	for _, r := range s {
		if unicode.IsControl(r) {
			return false
		}
	}
	return true
}

func cleanMIME(s string) string {
	if s == "" || len(s) > 127 {
		return ""
	}
	mt, _, err := mime.ParseMediaType(s)
	if err != nil || !strings.Contains(mt, "/") {
		return ""
	}
	return mt
}

// validateEntries checks and normalises file declarations. seen holds the
// client refs already used in this call.
func validateEntries(in []core.UploadFileInput, lim limits) ([]entry, int64, error) {
	if len(in) > MaxFilesPerCall {
		return nil, 0, core.Invalid("files", fmt.Sprintf("at most %d entries per request", MaxFilesPerCall))
	}
	out := make([]entry, 0, len(in))
	seen := make(map[string]bool, len(in))
	var total int64
	for i, f := range in {
		field := func(name string) string { return fmt.Sprintf("files[%d].%s", i, name) }
		if !validClientRef(f.ClientRef) {
			return nil, 0, core.Invalid(field("client_ref"), "client_ref must be 1–128 printable characters")
		}
		if seen[f.ClientRef] {
			return nil, 0, core.Invalid(field("client_ref"), "duplicate client_ref")
		}
		seen[f.ClientRef] = true
		kind := f.Kind
		if kind == "" {
			kind = core.UploadKindFile
		}
		if kind != core.UploadKindFile && kind != core.UploadKindDir {
			return nil, 0, core.Invalid(field("kind"), `kind must be "file" or "dir"`)
		}
		segs, err := names.SplitRelPath(f.RelPath)
		if err != nil {
			msg := "invalid path"
			if ce := core.AsError(err); ce != nil {
				msg = ce.Message
			}
			return nil, 0, core.Invalid(field("rel_path"), msg)
		}
		e := entry{id: ids.New(ids.PrefixUploadFile), ref: f.ClientRef, relPath: strings.Join(segs, "/"), kind: kind, size: f.Size}
		switch {
		case f.Size < 0:
			return nil, 0, core.Invalid(field("size"), "size must not be negative")
		case kind == core.UploadKindDir && f.Size != 0:
			return nil, 0, core.Invalid(field("size"), "directories have size 0")
		}
		if kind == core.UploadKindFile {
			if err := lim.check(field("size"), f.Size); err != nil {
				return nil, 0, err
			}
			if total > math.MaxInt64-f.Size { // never let the batch total wrap
				return nil, 0, core.Invalid(field("size"),
					"the declared sizes of this batch add up to more than the server can store")
			}
			e.partCount = partCount(f.Size)
			total += f.Size
		}
		if f.MTime > 0 && f.MTime <= maxMtime {
			e.mtime = sql.NullInt64{Int64: f.MTime, Valid: true}
		}
		e.mime = cleanMIME(f.MIME)
		out = append(out, e)
	}
	return out, total, nil
}

// cleanUploader validates a file-request uploader name ("" allowed).
func cleanUploader(s string) (string, error) {
	s = strings.TrimSpace(s)
	if !utf8.ValidString(s) {
		return "", core.Invalid("uploader", "the name is not valid UTF-8")
	}
	if utf8.RuneCountInString(s) > MaxUploaderName {
		return "", core.Invalid("uploader", fmt.Sprintf("the name is longer than %d characters", MaxUploaderName))
	}
	for _, r := range s {
		if unicode.IsControl(r) {
			return "", core.Invalid("uploader", "the name must not contain control characters")
		}
		// The name is shown to the owner (access log, audit log, upload
		// notifications): an override such as U+202E would let a visitor
		// make it read as something else (the rule of file names).
		if names.IsBidiControl(r) {
			return "", core.Invalid("uploader", "the name must not contain text-direction control characters")
		}
	}
	return s, nil
}

// cleanZipName validates the zip-on-upload file name and adds ".zip".
func cleanZipName(s string, now time.Time) (string, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		s = "Upload " + now.UTC().Format("2006-01-02 15.04.05")
	}
	if !strings.HasSuffix(strings.ToLower(s), ".zip") {
		s += ".zip"
	}
	nfc, _, err := names.Clean(s)
	if err != nil {
		msg := "invalid name"
		if ce := core.AsError(err); ce != nil {
			msg = ce.Message
		}
		return "", core.Invalid("zip_name", msg)
	}
	return nfc, nil
}

// ---------- share (file request) context ----------

// shareCtx is what uploads needs to know about the share of a file request.
type shareCtx struct {
	ID          string
	NodeID      string
	Owner       string
	RequireName bool
	MaxFile     int64 // 0 = none
	Quota       int64 // 0 = none
	NotifyOwner bool
	Title       string
}

// loadShare returns the share of a file-request actor if it currently
// accepts uploads (identical 404 otherwise).
func (svc *Service) loadShare(ctx context.Context, q querier, id string) (*shareCtx, error) {
	var (
		s                         shareCtx
		allowUpload, reqName, nfy bool
		maxFile, quota, exp, dis  sql.NullInt64
		title                     sql.NullString
		ownerStatus               sql.NullString
	)
	err := q.QueryRowContext(ctx, `SELECT s.id, s.node_id, s.created_by, s.allow_upload, s.require_uploader_name,
			s.upload_max_file_bytes, s.upload_quota_bytes, s.notify_owner, s.title, s.expires_at, s.disabled_at, u.status
		FROM shares s LEFT JOIN users u ON u.id = s.created_by WHERE s.id = ?`, id).
		Scan(&s.ID, &s.NodeID, &s.Owner, &allowUpload, &reqName, &maxFile, &quota, &nfy, &title, &exp, &dis, &ownerStatus)
	notFound := core.NotFoundf("share not found")
	if db.IsNoRows(err) {
		return nil, notFound
	}
	if err != nil {
		return nil, err
	}
	now := svc.env.Now()
	if !allowUpload || dis.Valid || (exp.Valid && exp.Int64 <= db.Ms(now)) || ownerStatus.String != core.UserActive {
		return nil, notFound
	}
	s.RequireName, s.NotifyOwner, s.Title = reqName, nfy, title.String
	if maxFile.Valid && maxFile.Int64 > 0 {
		s.MaxFile = maxFile.Int64
	}
	if quota.Valid && quota.Int64 > 0 {
		s.Quota = quota.Int64
	}
	return &s, nil
}

// ---------- quota ----------

// spaceQuota returns the effective quota (0 = unlimited) and the used bytes
// of a space. Personal spaces use Files.Usage of the owner when available
// (the files service defines usage); otherwise, and for group spaces, the
// spaces/users columns are used (users.quota_bytes NULL = the
// storage.default_quota_gb default, 0 = unlimited).
func (svc *Service) spaceQuota(ctx context.Context, spaceID string) (limit, used int64, err error) {
	var (
		kind            string
		owner           sql.NullString
		spQuota, uQuota sql.NullInt64
		spUsed          int64
	)
	err = svc.env.DB.QueryRow(ctx, `SELECT s.kind, s.owner_user_id, s.quota_bytes, s.used_bytes, u.quota_bytes
		FROM spaces s LEFT JOIN users u ON u.id = s.owner_user_id WHERE s.id = ?`, spaceID).
		Scan(&kind, &owner, &spQuota, &spUsed, &uQuota)
	if db.IsNoRows(err) {
		return 0, 0, core.NotFoundf("folder not found")
	}
	if err != nil {
		return 0, 0, err
	}
	used = spUsed
	if kind == core.SpaceUser && owner.Valid {
		if u, uerr := svc.files.Usage(ctx, owner.String); uerr == nil && u != nil {
			limit, used = u.QuotaBytes, u.UsedBytes
		} else {
			switch {
			case !uQuota.Valid:
				if gb := svc.settingInt(settingDefaultQuotaGB, 0); gb > 0 {
					limit = gb * gib
				}
			case uQuota.Int64 > 0:
				limit = uQuota.Int64
			}
		}
	}
	if spQuota.Valid && spQuota.Int64 > 0 && (limit <= 0 || spQuota.Int64 < limit) {
		limit = spQuota.Int64
	}
	return max(limit, 0), max(used, 0), nil
}

// errBadDeclaredSize is the answer of the quota and disk guards to a
// negative amount. They used to treat one as "nothing to check"; a size that
// can only come from a bug or from an overflow must close them, not open
// them.
var errBadDeclaredSize = core.Errorf(core.ErrQuota, "the declared size of this upload is not valid")

// checkSpaceQuota verifies inside tx that adding bytes to the reservations
// of space keeps it within its quota. shareID is the file request the upload
// arrives through, if any: the refusal then names what the upload needs but
// not how much of the owner's quota is left, exactly as checkDisk reasons,
// because httpx.Error returns the message verbatim to the visitor.
func (svc *Service) checkSpaceQuota(ctx context.Context, tx *sql.Tx, spaceID, shareID string, limit, used, add int64) error {
	if add < 0 {
		return errBadDeclaredSize
	}
	if limit <= 0 || add == 0 {
		return nil
	}
	// MAX(…, 0) per row: a reservation that somehow went negative must never
	// buy room for another batch.
	var reserved int64
	if err := tx.QueryRowContext(ctx, `SELECT COALESCE(SUM(MAX(b.reserved_bytes, 0)), 0) FROM upload_batches b
		JOIN nodes n ON n.id = b.folder_id WHERE n.space_id = ? AND b.state IN ('open','finalizing')`, spaceID).
		Scan(&reserved); err != nil {
		return err
	}
	if used+reserved+add > limit {
		avail := max(limit-used-reserved, 0)
		if shareID != "" {
			// The admin keeps every number in the log; the visitor only
			// learns that their own declared size does not fit.
			svc.log.Warn("upload refused: space quota exceeded", "share", shareID, "space", spaceID,
				"need", add, "available", avail)
			return core.Errorf(core.ErrQuota,
				"not enough storage space: this upload needs %s and the file request cannot take it right now",
				humanBytes(add))
		}
		msg := fmt.Sprintf("not enough storage space: the upload needs %s, %s %s available", humanBytes(add),
			humanBytes(avail), isAre(avail))
		if reserved > 0 {
			// A killed CLI upload or a closed tab keeps its reservation until
			// the batch is cancelled or expires: say so, or the refusal of an
			// empty-looking space makes no sense.
			msg += fmt.Sprintf(" (unfinished uploads hold %s until they finish, are cancelled or expire)",
				humanBytes(reserved))
		}
		return core.Errorf(core.ErrQuota, "%s", msg)
	}
	return nil
}

// isAre is the verb of "<size> are available": "1 B is".
func isAre(n int64) string {
	if n == 1 {
		return "is"
	}
	return "are"
}

// checkShareQuota verifies inside tx the upload quota of a file request.
func checkShareQuota(ctx context.Context, tx *sql.Tx, shareID string, add int64) error {
	var quota sql.NullInt64
	var used, reserved int64
	err := tx.QueryRowContext(ctx, `SELECT upload_quota_bytes, upload_used_bytes FROM shares WHERE id = ?`, shareID).Scan(&quota, &used)
	if db.IsNoRows(err) {
		return core.NotFoundf("share not found")
	}
	if err != nil {
		return err
	}
	if add < 0 {
		return errBadDeclaredSize
	}
	if !quota.Valid || quota.Int64 <= 0 || add == 0 {
		return nil
	}
	if err := tx.QueryRowContext(ctx, `SELECT COALESCE(SUM(MAX(reserved_bytes, 0)), 0) FROM upload_batches
		WHERE share_id = ? AND state IN ('open','finalizing')`, shareID).Scan(&reserved); err != nil {
		return err
	}
	if used+reserved+add > quota.Int64 {
		return core.Errorf(core.ErrQuota, "this file request cannot take %s more (%s left)",
			humanBytes(add), humanBytes(max(quota.Int64-used-reserved, 0)))
	}
	return nil
}

// checkDisk refuses uploads that would leave less than 1 GiB or 2 % of the
// blob store's file system free.
func (svc *Service) checkDisk(need int64) error {
	if need < 0 {
		return errBadDeclaredSize
	}
	if need == 0 || svc.diskFree == nil || svc.env.Home == nil {
		return nil
	}
	free, total, err := svc.diskFree(svc.env.Home.BlobsDir())
	if err != nil {
		svc.log.Debug("free-space check skipped", "err", err)
		return nil
	}
	reserve := max(minFreeBytes, int64(total/100*minFreePct))
	if int64(free)-need < reserve {
		// The admin needs every number to tell the reserve floor from a
		// genuinely full disk; the message itself is returned verbatim to
		// anonymous file-request visitors (httpx.Error), so it names what
		// the upload needs and the floor the server keeps, but not how
		// much room is actually left.
		svc.log.Warn("upload refused: not enough free disk space",
			"need", need, "free", free, "total", total, "reserve", reserve)
		return core.Errorf(core.ErrQuota,
			"not enough free disk space: this upload needs %s of disk space and the server always keeps %s free",
			humanBytes(need), humanBytes(reserve))
	}
	return nil
}

// hoursText renders a whole number of hours ("48 hours", "1 hour").
func hoursText(d time.Duration) string {
	if h := int64(d / time.Hour); h != 1 {
		return fmt.Sprintf("%d hours", h)
	}
	return "1 hour"
}

// humanBytes renders a byte count with IEC units ("1.5 GiB").
func humanBytes(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(unit), 0
	for m := n / unit; m >= unit; m /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(n)/float64(div), "KMGTPE"[exp])
}

// checkOpenCap enforces the concurrent open batch caps inside tx. The
// per-user cap is 409, not 429: waiting a minute does not free a slot, and
// clients retry a 429 by themselves. expiry is storage.upload_expiry_hours,
// which the refusal names.
func checkOpenCap(ctx context.Context, tx *sql.Tx, userID, shareID, actor string, expiry time.Duration) error {
	var n int
	if shareID == "" {
		if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM upload_batches
			WHERE user_id = ? AND share_id IS NULL AND state IN ('open','finalizing')`, userID).Scan(&n); err != nil {
			return err
		}
		if n >= MaxOpenBatchesPerUser {
			return core.Errorf(core.ErrConflict, "too many unfinished uploads (at most %d); cancel the ones you no "+
				"longer need (the upload panel of the web interface lists them) or wait until they expire, %s after they started",
				MaxOpenBatchesPerUser, hoursText(expiry))
		}
		return nil
	}
	// The per-client cap counts by the IP part of the actor session, not by
	// the whole value: a visitor must not be able to reset it by dropping the
	// visitor cookie. The visitor mark is part of the compared prefix, so
	// "ip:198.51.100.9" does not match "ip:198.51.100.99".
	client, _, _ := strings.Cut(actor, visitorMark)
	prefix := client + visitorMark
	var mine int
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*), COALESCE(SUM(actor_session = ? OR substr(actor_session, 1, ?) = ?), 0)
		FROM upload_batches WHERE share_id = ? AND state IN ('open','finalizing')`,
		client, len(prefix), prefix, shareID).Scan(&n, &mine); err != nil {
		return err
	}
	if mine >= MaxOpenBatchesPerShareClient || n >= MaxOpenBatchesPerShare {
		return core.Errorf(core.ErrRateLimited, "too many unfinished uploads to this request; please try again later")
	}
	return nil
}

// actorSession identifies the client of a batch (session, token or, for file
// requests, the client IP and, when the visitor keeps cookies, the id of the
// visitor cookie the share routes issue: "ip:<addr>|vis:<id>"). The IP stays
// the prefix because the per-client concurrency cap counts on it, which
// clearing a cookie must not reset; the visitor id binds the batch to one
// client (owns).
func actorSession(a core.UploadActor) string {
	switch {
	case a.P == nil:
		return ""
	case a.ShareID != "":
		s := "ip:unknown"
		if a.P.IP.IsValid() {
			s = "ip:" + a.P.IP.String()
		}
		if a.P.SessionID != "" {
			s += visitorMark + a.P.SessionID
		}
		return s
	case a.P.SessionID != "":
		return "ses:" + a.P.SessionID
	case a.P.TokenID != "":
		return "tok:" + a.P.TokenID
	}
	return string(a.P.Via)
}

// ---------- batches ----------

// CreateBatch implements core.Uploads: it validates the destination
// (PermEdit on a folder) and every path, reserves quota for the declared
// bytes and records the batch and its files. A zip-mode batch may carry a
// .zip password (zippassword.go): it is validated before anything else is
// recorded and stored only sealed, in the same transaction as the batch.
func (svc *Service) CreateBatch(ctx context.Context, a core.UploadActor, in core.BatchInput) (*core.UploadBatch, error) {
	if a.P == nil || a.P.UserID == "" {
		return nil, core.ErrUnauthorized
	}
	now := svc.env.Now()
	b := &core.UploadBatch{
		ID: ids.New(ids.PrefixUploadBatch), UserID: a.P.UserID, FolderID: in.FolderID,
		Mode: in.Mode, Conflict: in.Conflict, State: core.BatchOpen,
		CreatedAt: now, UpdatedAt: now, ExpiresAt: now.Add(svc.expiry()),
		ActorSession: actorSession(a),
	}
	if b.Mode == "" {
		b.Mode = core.UploadModeFiles
	}
	if b.Mode != core.UploadModeFiles && b.Mode != core.UploadModeZip {
		return nil, core.Invalid("mode", `mode must be "files" or "zip"`)
	}
	if b.Conflict == "" {
		b.Conflict = core.ConflictRename
	}
	if !b.Conflict.Valid() {
		return nil, core.Invalid("conflict", "conflict must be rename, replace, skip or fail")
	}
	lim := limits{maxFile: svc.maxFileBytes()}

	var share *shareCtx
	if a.ShareID != "" {
		var err error
		if share, err = svc.loadShare(ctx, svc.env.DB.Reader(), a.ShareID); err != nil {
			return nil, err
		}
		if in.FolderID != "" && in.FolderID != share.NodeID {
			return nil, core.Invalid("folder_id", "uploads to this request go to its folder")
		}
		if a.P.UserID != share.Owner {
			return nil, core.ErrForbidden // file-request actors act as the share owner
		}
		b.FolderID, b.ShareID, b.UserID = share.NodeID, share.ID, share.Owner
		b.Conflict = core.ConflictRename // DESIGN §8.1: file requests always rename
		name, err := cleanUploader(firstNonEmpty(in.Uploader, a.Uploader))
		if err != nil {
			return nil, err
		}
		if share.RequireName && name == "" {
			return nil, core.Invalid("uploader", "please enter your name")
		}
		b.Uploader = name
		lim.shareMaxFile = share.MaxFile
	} else if in.Uploader != "" {
		return nil, core.Invalid("uploader", "uploader is only used by file requests")
	}
	if b.FolderID == "" {
		return nil, core.Invalid("folder_id", "folder_id is required")
	}
	if b.Mode == core.UploadModeZip {
		zn, err := cleanZipName(in.ZipName, now)
		if err != nil {
			return nil, err
		}
		b.ZipName = zn
	} else if in.ZipName != "" {
		return nil, core.Invalid("zip_name", "zip_name is only used with mode zip")
	}
	enc, err := svc.zipProtection(in, b.Mode, a.ShareID != "")
	if err != nil {
		return nil, err
	}
	b.ZipEncryption = enc

	folder, err := svc.files.Authorize(ctx, a.P, b.FolderID, core.PermEdit)
	if err != nil {
		return nil, err
	}
	if !folder.IsDir() {
		return nil, core.Invalid("folder_id", "the destination is not a folder")
	}
	entries, total, err := validateEntries(in.Files, lim)
	if err != nil {
		return nil, err
	}
	if capN := batchCap(b.ShareID); len(entries) > capN {
		return nil, core.Invalid("files", fmt.Sprintf("a batch holds at most %d entries", capN))
	}
	// Taken names, before anything is reserved or sent (preflight.go).
	zipSkipped, err := svc.preflight(ctx, b, entries, false)
	if err != nil {
		return nil, err
	}
	need := sendBytes(entries)
	limit, used, err := svc.spaceQuota(ctx, folder.SpaceID)
	if err != nil {
		return nil, err
	}
	// reserve is what the batch will store: its declared data or, in
	// mode=zip, the bound of the one .zip it becomes — that single file must
	// fit the per-file limits and the space quota, not only each entry. A
	// file declared skipped stores nothing, nor does a skipped .zip.
	reserve, diskNeed := need, need
	if b.Mode == core.UploadModeZip && !zipSkipped {
		reserve = addSat(addSat(need, zipOverhead(entries)), zipEndOverhead)
		if err := lim.checkZip(reserve); err != nil {
			return nil, err
		}
		diskNeed = addSat(need, reserve) // staged parts + the zip, until the job deletes the parts
	}
	if err := svc.checkDisk(diskNeed); err != nil {
		return nil, err
	}
	b.DeclaredFiles, b.DeclaredBytes, b.ReservedBytes = len(entries), total, reserve
	sealed := ""
	if enc != "" {
		if sealed, err = svc.sealZipPassword(b.ID, in.ZipPassword.Reveal()); err != nil {
			return nil, err
		}
	}

	err = svc.env.DB.Tx(ctx, func(tx *sql.Tx) error {
		if err := checkOpenCap(ctx, tx, b.UserID, b.ShareID, b.ActorSession, svc.expiry()); err != nil {
			return err
		}
		if err := svc.checkSpaceQuota(ctx, tx, folder.SpaceID, b.ShareID, limit, used, reserve); err != nil {
			return err
		}
		if share != nil {
			if err := checkShareQuota(ctx, tx, share.ID, need); err != nil {
				return err
			}
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO upload_batches (id, user_id, share_id, uploader, actor_session,
				folder_id, mode, zip_name, zip_encryption, zip_password_enc, conflict, declared_files, declared_bytes,
				reserved_bytes, state, created_at, updated_at, expires_at)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'open', ?, ?, ?)`,
			b.ID, b.UserID, db.NullString(b.ShareID), db.NullString(b.Uploader), db.NullString(b.ActorSession),
			b.FolderID, b.Mode, db.NullString(b.ZipName), db.NullString(b.ZipEncryption), db.NullString(sealed),
			string(b.Conflict), b.DeclaredFiles, b.DeclaredBytes, b.ReservedBytes, db.Ms(now), db.Ms(now),
			db.Ms(b.ExpiresAt)); err != nil {
			return err
		}
		return insertEntries(ctx, tx, b.ID, entries, now)
	})
	if err != nil {
		return nil, err
	}
	b.Files = make([]core.UploadFileState, 0, len(entries))
	for _, e := range entries {
		b.Files = append(b.Files, e.state(b.ID, now))
	}
	svc.log.Debug("upload batch created", "batch", b.ID, "files", len(entries), "bytes", total, "mode", b.Mode,
		"zip_encryption", b.ZipEncryption)
	return svc.decorate(b), nil
}

// batchCap is the maximum number of entries of a batch.
func batchCap(shareID string) int {
	if shareID != "" {
		return MaxFilesPerShareBatch
	}
	return MaxFilesPerBatch
}

func firstNonEmpty(s ...string) string {
	for _, v := range s {
		if v != "" {
			return v
		}
	}
	return ""
}

func (e *entry) state(batchID string, now time.Time) core.UploadFileState {
	return core.UploadFileState{
		ID: e.id, BatchID: batchID, ClientRef: e.ref, RelPath: e.relPath, Kind: e.kind, Size: e.size,
		PartCount: e.partCount, PartsDone: []int{}, State: e.initialState(), UpdatedAt: now,
	}
}

// initialState is the state an entry is declared in.
func (e *entry) initialState() string {
	if e.skipped {
		return core.UploadSkipped
	}
	return core.UploadPending
}

func insertEntries(ctx context.Context, tx *sql.Tx, batchID string, entries []entry, now time.Time) error {
	if len(entries) == 0 {
		return nil
	}
	stmt, err := tx.PrepareContext(ctx, `INSERT INTO upload_files (id, batch_id, client_ref, rel_path, kind, size,
		client_mtime, mime, part_count, state, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
	if err != nil {
		return err
	}
	defer stmt.Close()
	for _, e := range entries {
		if _, err := stmt.ExecContext(ctx, e.id, batchID, e.ref, e.relPath, e.kind, e.size, e.mtime,
			db.NullString(e.mime), e.partCount, e.initialState(), db.Ms(now), db.Ms(now)); err != nil {
			if db.IsUnique(err) {
				return core.Errorf(core.ErrConflict, "client_ref %q is already used in this batch", e.ref)
			}
			return err
		}
	}
	return nil
}

// AddFiles implements core.Uploads: more entries for an open batch (the
// browser streams large selections in chunks). Re-sending an entry with the
// same client_ref, rel_path, kind and size is idempotent; a different
// declaration for a used client_ref is 409.
func (svc *Service) AddFiles(ctx context.Context, a core.UploadActor, batchID string, in []core.UploadFileInput) ([]core.UploadFileState, error) {
	if a.P == nil {
		return nil, core.ErrUnauthorized
	}
	b, err := svc.loadBatch(ctx, a, batchID)
	if err != nil {
		return nil, err
	}
	if b.State != core.BatchOpen {
		return nil, core.Errorf(core.ErrConflict, "the upload batch is %s", b.State)
	}
	lim := limits{maxFile: svc.maxFileBytes()}
	if b.ShareID != "" {
		share, err := svc.loadShare(ctx, svc.env.DB.Reader(), b.ShareID)
		if err != nil {
			return nil, err
		}
		lim.shareMaxFile = share.MaxFile
	}
	folder, err := svc.files.Authorize(ctx, a.P, b.FolderID, core.PermEdit)
	if err != nil {
		return nil, err
	}
	entries, _, err := validateEntries(in, lim)
	if err != nil {
		return nil, err
	}
	// Taken names, as in CreateBatch; a zip batch that skips its .zip
	// (every file declared skipped) skips the new files too.
	zipSkipped := false
	if b.Mode == core.UploadModeZip {
		var n int
		if err := svc.env.DB.QueryRow(ctx, `SELECT COUNT(*) FROM upload_files WHERE batch_id = ? AND kind = 'file'
			AND state = 'skipped'`, b.ID).Scan(&n); err != nil {
			return nil, err
		}
		zipSkipped = n > 0
	}
	if zipSkipped, err = svc.preflight(ctx, b, entries, zipSkipped); err != nil {
		return nil, err
	}
	need := sendBytes(entries)
	limit, used, err := svc.spaceQuota(ctx, folder.SpaceID)
	if err != nil {
		return nil, err
	}
	diskNeed := need
	if b.Mode == core.UploadModeZip && !zipSkipped {
		diskNeed = addSat(twice(need), zipOverhead(entries)) // staged parts + the zip, as in CreateBatch
	}
	if err := svc.checkDisk(diskNeed); err != nil {
		return nil, err
	}
	now := svc.env.Now()
	out := make([]core.UploadFileState, len(entries))
	var fresh []entry
	var freshIdx []int
	var add, declared, reserve int64
	err = svc.env.DB.Tx(ctx, func(tx *sql.Tx) error {
		fresh, freshIdx, add, declared, reserve = fresh[:0], freshIdx[:0], 0, 0, 0
		var state string
		var files int
		var reserved int64
		if err := tx.QueryRowContext(ctx, `SELECT state, declared_files, reserved_bytes FROM upload_batches WHERE id = ?`, b.ID).
			Scan(&state, &files, &reserved); err != nil {
			return err
		}
		if state != core.BatchOpen {
			return core.Errorf(core.ErrConflict, "the upload batch is %s", state)
		}
		for i := range entries {
			e := &entries[i]
			f, err := scanFile(tx.QueryRowContext(ctx, `SELECT `+fileCols+` FROM upload_files WHERE batch_id = ? AND client_ref = ?`, b.ID, e.ref))
			switch {
			case db.IsNoRows(err):
				fresh = append(fresh, *e)
				freshIdx = append(freshIdx, i)
				if e.kind == core.UploadKindFile {
					declared += e.size
					if !e.skipped {
						add += e.size
					}
				}
			case err != nil:
				return err
			case f.RelPath != e.relPath || f.Kind != e.kind || f.Size != e.size:
				return core.Errorf(core.ErrConflict, "client_ref %q is already used for a different file", e.ref)
			default:
				out[i] = *f.state()
			}
		}
		if capN := batchCap(b.ShareID); files+len(fresh) > capN {
			return core.Invalid("files", fmt.Sprintf("a batch holds at most %d entries", capN))
		}
		reserve = add
		if b.Mode == core.UploadModeZip && len(fresh) > 0 && !zipSkipped {
			// The reservation of an open zip batch is the bound of its .zip
			// (CreateBatch; an aborted file gives back only its data, so it
			// stays an upper bound): the new entries add their data and
			// their share of the zip format.
			reserve = addSat(add, zipOverhead(fresh))
			if err := lim.checkZip(addSat(max(reserved, 0), reserve)); err != nil {
				return err
			}
		}
		if err := svc.checkSpaceQuota(ctx, tx, folder.SpaceID, b.ShareID, limit, used, reserve); err != nil {
			return err
		}
		if b.ShareID != "" {
			if err := checkShareQuota(ctx, tx, b.ShareID, add); err != nil {
				return err
			}
		}
		if err := insertEntries(ctx, tx, b.ID, fresh, now); err != nil {
			return err
		}
		_, err := tx.ExecContext(ctx, `UPDATE upload_batches SET declared_files = declared_files + ?,
			declared_bytes = declared_bytes + ?, reserved_bytes = reserved_bytes + ?, updated_at = ? WHERE id = ?`,
			len(fresh), declared, reserve, db.Ms(now), b.ID)
		return err
	})
	if err != nil {
		return nil, err
	}
	for j, e := range fresh {
		out[freshIdx[j]] = e.state(b.ID, now)
	}
	// Existing entries: fill their received parts.
	if len(fresh) < len(entries) {
		parts, err := svc.partsDone(ctx, b.ID, "")
		if err != nil {
			return nil, err
		}
		for i := range out {
			if p := parts[out[i].ID]; p != nil {
				out[i].PartsDone = p
			}
		}
	}
	return out, nil
}

// GetBatch implements core.Uploads (with every file and its received parts).
func (svc *Service) GetBatch(ctx context.Context, a core.UploadActor, batchID string) (*core.UploadBatch, error) {
	b, err := svc.loadBatch(ctx, a, batchID)
	if err != nil {
		return nil, err
	}
	rows, err := svc.env.DB.Query(ctx, `SELECT `+fileCols+` FROM upload_files WHERE batch_id = ? ORDER BY rowid`, b.ID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	b.Files = []core.UploadFileState{}
	for rows.Next() {
		f, err := scanFile(rows)
		if err != nil {
			return nil, err
		}
		b.Files = append(b.Files, *f.state())
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	parts, err := svc.partsDone(ctx, b.ID, "")
	if err != nil {
		return nil, err
	}
	for i := range b.Files {
		if p := parts[b.Files[i].ID]; p != nil {
			b.Files[i].PartsDone = p
		}
	}
	return svc.decorate(b), nil
}

// ListBatches implements core.Uploads: the user's own unfinished batches
// (open or finalizing, not those of file requests), newest first, without
// their files. A batch left behind by a closed tab, another device or a
// killed CLI holds its reservation and one of the MaxOpenBatchesPerUser
// slots until it expires; this lets the user find and cancel it.
func (svc *Service) ListBatches(ctx context.Context, a core.UploadActor) ([]core.UploadBatch, error) {
	if a.P == nil || a.P.UserID == "" {
		return nil, core.ErrUnauthorized
	}
	if a.ShareID != "" {
		return nil, core.ErrForbidden
	}
	rows, err := svc.env.DB.Query(ctx, `SELECT `+batchCols+` FROM upload_batches
		WHERE user_id = ? AND share_id IS NULL AND state IN ('open','finalizing')
		ORDER BY created_at DESC, id`, a.P.UserID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []core.UploadBatch{}
	for rows.Next() {
		b, err := scanBatch(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *svc.decorate(b))
	}
	return out, rows.Err()
}

// Status implements core.Uploads: the state of one file with its received
// parts (resume).
func (svc *Service) Status(ctx context.Context, a core.UploadActor, uploadID string) (*core.UploadFileState, error) {
	if _, _, err := svc.loadFile(ctx, a, uploadID); err != nil {
		return nil, err
	}
	return svc.fileState(ctx, uploadID)
}
