// Package shares implements public share links and file requests (DESIGN
// §9.4 sharesapi, §8.1 file requests): creation with 128-bit tokens (stored
// as SHA-256 plus a field-encrypted copy so owners can show the link
// again), optional argon2id passwords with a version that invalidates
// access cookies, expiry, download limits (atomic counting), disabling,
// resolution for the public routes (identical not-found errors for every
// invalid state), rate-limited password checks, the access cookie, the
// access log and owner notifications. Owned by unit E.
package shares

import (
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"

	"fileparcel/internal/core"
	"fileparcel/internal/crypt"
	"fileparcel/internal/db"
	"fileparcel/internal/ids"
	"fileparcel/internal/names"
	"fileparcel/internal/ratelimit"
)

// Limits and parameters.
const (
	// TokenBytes is the entropy of share tokens (base62, 22 characters).
	TokenBytes = 16
	// MaxTitle and MaxMessage bound the share texts (runes).
	MaxTitle   = 200
	MaxMessage = 2000
	// MaxPassword bounds share passwords (bytes).
	MaxPassword = 1024
	// MinPassword is the shortest password a new share link or file request
	// may be given (runes). It applies when a password is set, never when
	// one is verified.
	MinPassword = 8
	// minDistinctRunes rejects passwords like "aaaaaaaa" or "12121212".
	minDistinctRunes = 4
	// CookieTTL is the lifetime of the share access cookie.
	CookieTTL = 12 * time.Hour
	// CookiePrefix starts the name of share access cookies.
	CookiePrefix = "__Host-fp_s_"
	// VisitorCookiePrefix starts the name of the per-visitor cookie of a
	// file request (sharesapi issues it; it binds upload batches to the
	// visitor who opened them).
	VisitorCookiePrefix = "__Host-fp_uv_"
	// NotifyTemplate is the notify template for file-request uploads.
	NotifyTemplate = "share.upload"
	notifyTimeout  = 30 * time.Second
)

// Service implements core.Shares.
type Service struct {
	env     *core.Env
	files   core.Files
	limiter *ratelimit.Registry
	log     *slog.Logger

	// Bound late (Bind); optional.
	notify  core.Notify
	uploads core.Uploads
	ingress core.Ingress // Tailscale Funnel: the internet base URL of links

	// hashPassword / verifyPassword are replaceable in tests (cheap params).
	hashPassword   func(string) (string, error)
	verifyPassword func(ctx context.Context, phc, pw string) (ok, rehash bool, err error)

	pwMu   sync.Mutex
	pwRate int64 // attempts per minute currently configured for bucketPwIP

	bg sync.WaitGroup // notification goroutines
}

var _ core.Shares = (*Service)(nil)

// New creates the service (constructor signature fixed by DESIGN §5.2).
func New(env *core.Env, files core.Files, limiter *ratelimit.Registry) (*Service, error) {
	if env == nil || env.DB == nil {
		return nil, errors.New("shares: env with a database required")
	}
	log := env.Log
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	return &Service{env: env, files: files, limiter: limiter, log: log.With("svc", "shares"),
		hashPassword: crypt.HashPassword, verifyPassword: crypt.VerifyPasswordContext}, nil
}

// Bind implements core.Binder: Notify (owner notifications), Uploads (open
// file-request batches are aborted when a share is revoked) and Ingress
// (links use the Tailscale Funnel address while Funnel is active).
func (svc *Service) Bind(s *core.Services) error {
	if s != nil {
		svc.notify, svc.uploads, svc.ingress = s.Notify, s.Uploads, s.Ingress
	}
	return nil
}

// IsPublicCookie reports whether a cookie belongs to the public share
// routes: a share access cookie (CookiePrefix) or a file-request visitor
// cookie (VisitorCookiePrefix). Over Tailscale Funnel "shares" mode these
// are the only cookies a request keeps (mw.IngressGate).
func IsPublicCookie(name string) bool {
	return strings.HasPrefix(name, CookiePrefix) || strings.HasPrefix(name, VisitorCookiePrefix)
}

// Close implements io.Closer: it waits (bounded) for pending notifications.
func (svc *Service) Close() error {
	done := make(chan struct{})
	go func() { svc.bg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(notifyTimeout):
	}
	return nil
}

// ---------- settings ----------

func (svc *Service) boolSetting(key string, def bool) bool {
	if svc.env.Settings == nil {
		return def
	}
	if _, err := svc.env.Settings.Raw(key); err != nil {
		return def
	}
	return svc.env.Settings.Bool(key)
}

func (svc *Service) intSetting(key string, def int64) int64 {
	if svc.env.Settings == nil {
		return def
	}
	if _, err := svc.env.Settings.Raw(key); err != nil {
		return def
	}
	return svc.env.Settings.Int(key)
}

// ---------- rows ----------

type scanner interface{ Scan(dest ...any) error }

const shareCols = `s.id, s.kind, s.node_id, s.created_by, s.token_hash, s.token_enc, s.title, s.message,
	s.password_hash, s.password_version, s.allow_download, s.allow_preview, s.allow_upload, s.require_uploader_name,
	s.upload_max_file_bytes, s.upload_quota_bytes, s.upload_used_bytes, s.max_downloads, s.download_count,
	s.expires_at, s.notify_owner, s.disabled_at, s.created_at, s.updated_at, s.last_access_at,
	n.name, n.kind, n.trashed_at, u.username, u.display_name, u.status`

const shareFrom = ` FROM shares s LEFT JOIN nodes n ON n.id = s.node_id LEFT JOIN users u ON u.id = s.created_by`

// row is a share with the columns that are not part of core.Share.
type row struct {
	s           *core.Share
	tokenEnc    string
	nodeTrashed bool
	ownerStatus string
}

func scanShare(sc scanner) (*row, error) {
	var (
		s                                         core.Share
		r                                         = row{s: &s}
		title, message, pw                        sql.NullString
		maxFile, quota, maxDl, exp, dis, lastAcc  sql.NullInt64
		created, updated                          int64
		nodeName, nodeKind, uname, dname, ustatus sql.NullString
		trashed                                   sql.NullInt64
	)
	if err := sc.Scan(&s.ID, &s.Kind, &s.NodeID, &s.CreatedBy, &s.TokenHash, &r.tokenEnc, &title, &message,
		&pw, &s.PasswordVersion, &s.AllowDownload, &s.AllowPreview, &s.AllowUpload, &s.RequireUploaderName,
		&maxFile, &quota, &s.UploadUsedBytes, &maxDl, &s.DownloadCount,
		&exp, &s.NotifyOwner, &dis, &created, &updated, &lastAcc,
		&nodeName, &nodeKind, &trashed, &uname, &dname, &ustatus); err != nil {
		return nil, err
	}
	s.Title, s.Message, s.PasswordHash = title.String, message.String, pw.String
	s.UploadMaxFileBytes, s.UploadQuotaBytes, s.MaxDownloads = db.FromNullInt64(maxFile), db.FromNullInt64(quota), db.FromNullInt64(maxDl)
	s.ExpiresAt, s.DisabledAt, s.LastAccessAt = db.FromNullMs(exp), db.FromNullMs(dis), db.FromNullMs(lastAcc)
	s.CreatedAt, s.UpdatedAt = db.FromMs(created), db.FromMs(updated)
	s.HasPassword = s.PasswordHash != ""
	s.NodeName, s.NodeKind = nodeName.String, nodeKind.String
	s.CreatedByName = dname.String
	if s.CreatedByName == "" {
		s.CreatedByName = uname.String
	}
	r.nodeTrashed = trashed.Valid
	r.ownerStatus = ustatus.String
	return &r, nil
}

// status derives the share status at now.
func status(s *core.Share, now time.Time) string {
	switch {
	case s.DisabledAt != nil:
		return core.ShareDisabled
	case s.ExpiresAt != nil && !s.ExpiresAt.After(now):
		return core.ShareExpired
	case s.MaxDownloads != nil && s.DownloadCount >= *s.MaxDownloads:
		return core.ShareExhausted
	}
	return core.ShareActive
}

func tokenAAD(id string) string { return "shares.token_enc|" + id }

// url returns the share link for an owner/admin view ("" when the token
// cannot be decrypted, e.g. keys locked).
func (svc *Service) url(r *row) string {
	if svc.env.Keys == nil || r.tokenEnc == "" {
		return ""
	}
	tok, err := svc.env.Keys.OpenField(tokenAAD(r.s.ID), r.tokenEnc)
	if err != nil {
		if !errors.Is(err, core.ErrKeysLocked) {
			svc.log.Warn("open share token", "share", r.s.ID, "err", err)
		}
		return ""
	}
	return svc.linkFor(string(tok))
}

// linkFor builds the public link of a token: "/s/<token>", absolute on
// server.public_url when that is configured, else on the Tailscale Funnel
// address while Funnel (shares or app) is active — the link then works from
// the internet, and its QR code carries that address.
func (svc *Service) linkFor(token string) string {
	p := "/s/" + token
	if svc.env.Config != nil {
		if base := strings.TrimRight(svc.env.Config.Server.PublicURL, "/"); base != "" {
			return base + p
		}
	}
	if svc.ingress != nil {
		if base := strings.TrimRight(svc.ingress.PublicBaseURL(), "/"); base != "" {
			return base + p
		}
	}
	return p
}

// folderLink is the absolute in-app link of a folder ("/files/{id}", the
// SPA route), "" when server.public_url is not configured: a relative path
// is useless in an e-mail.
func (svc *Service) folderLink(nodeID string) string {
	if nodeID == "" || svc.env.Config == nil {
		return ""
	}
	base := strings.TrimRight(svc.env.Config.Server.PublicURL, "/")
	if base == "" {
		return ""
	}
	return base + "/files/" + url.PathEscape(nodeID)
}

// finish fills the derived fields; withURL decrypts the link.
func (svc *Service) finish(r *row, withURL bool) *core.Share {
	s := r.s
	s.Status = status(s, svc.env.Now())
	// The same two facts Resolve refuses on (internal/shares/public.go): an
	// otherwise active link that answers "not found" is reported as
	// unavailable rather than silently as active. The third, the creator's
	// access to the item, needs a query: markUnavailable.
	s.Unavailable = r.nodeTrashed || r.ownerStatus != core.UserActive
	if withURL {
		s.URL = svc.url(r)
	}
	return s
}

// markUnavailable sets Unavailable on an active share whose creator no
// longer holds what Resolve demands of them on its node (creatorNeeds: view
// for a link, edit for a file request — a removed or reduced grant, a group
// left): visitors get "not found", so the creator's list must not say
// active. owners caches the creators' principals (nil: none can be built).
// Errors other than a refusal leave the share as it is.
func (svc *Service) markUnavailable(ctx context.Context, s *core.Share, owners map[string]*core.Principal) {
	if s.Unavailable || s.Status != core.ShareActive || svc.files == nil || s.CreatedBy == "" {
		return
	}
	owner, ok := owners[s.CreatedBy]
	if !ok {
		p, err := svc.files.SysPrincipalFor(ctx, s.CreatedBy)
		switch {
		case err == nil:
			owner = p
		case errors.Is(err, core.ErrNotFound) || errors.Is(err, core.ErrForbidden):
			owner = nil
		default:
			return
		}
		owners[s.CreatedBy] = owner
	}
	if owner == nil {
		s.Unavailable = true
		return
	}
	if _, err := svc.files.Authorize(ctx, owner, s.NodeID, creatorNeeds(s)); err != nil &&
		(errors.Is(err, core.ErrNotFound) || errors.Is(err, core.ErrForbidden)) {
		s.Unavailable = true
	}
}

// adminScoped reports whether p may manage everyone's shares: the
// shares.manage permission ("Manage everyone's links"; owners and admins
// hold it), which API tokens hold only with the "admin" scope.
// mw.RequireCap(shares.manage) guards GET /admin/shares with exactly this
// check, so a token that may not list every share there may not reach one
// through GET /shares/{id} either. Non-token channels (session, admin
// socket, offline CLI) need no scope.
func adminScoped(p *core.Principal) bool { return p.Can(core.CapSharesManage) }

// canSeeURL reports whether p may see the link of a share created by owner:
// the creator always; a built-in owner/admin holding the admin scope only
// with auth.admin_can_access_files (the link would otherwise bypass the
// "admins cannot browse user files" rule). shares.manage alone never shows
// a link: custom roles do not get the file-access override.
func (svc *Service) canSeeURL(p *core.Principal, owner string) bool {
	if p == nil {
		return false
	}
	if p.UserID != "" && p.UserID == owner {
		return true
	}
	return p.IsAdmin() && p.HasScope(core.ScopeAdmin) && svc.boolSetting(settingAdminFiles, false)
}

func (svc *Service) byID(ctx context.Context, id string) (*row, error) {
	if !ids.Valid(ids.PrefixShare, id) {
		return nil, core.NotFoundf("share not found")
	}
	r, err := scanShare(svc.env.DB.QueryRow(ctx, `SELECT `+shareCols+shareFrom+` WHERE s.id = ?`, id))
	if db.IsNoRows(err) {
		return nil, core.NotFoundf("share not found")
	}
	return r, err
}

// visible loads a share that p created, or any share when p holds
// shares.manage (adminScoped: a token without the admin scope sees only its
// own shares, exactly as it does on /admin/shares). The denial is the
// uniform 404, so nothing leaks about other users' shares.
func (svc *Service) visible(ctx context.Context, p *core.Principal, id string) (*row, error) {
	if p == nil {
		return nil, core.ErrUnauthorized
	}
	r, err := svc.byID(ctx, id)
	if err != nil {
		return nil, err
	}
	if r.s.CreatedBy != p.UserID && !adminScoped(p) {
		return nil, core.NotFoundf("share not found")
	}
	return r, nil
}

// ---------- validation ----------

func cleanText(field, s string, maxRunes int, multiline bool) (string, error) {
	s = strings.TrimSpace(s)
	if !utf8.ValidString(s) {
		return "", core.Invalid(field, "must be valid UTF-8")
	}
	if utf8.RuneCountInString(s) > maxRunes {
		return "", core.Invalid(field, fmt.Sprintf("must be at most %d characters", maxRunes))
	}
	for _, r := range s {
		if unicode.IsControl(r) && !(multiline && (r == '\n' || r == '\r' || r == '\t')) {
			return "", core.Invalid(field, "must not contain control characters")
		}
		// Titles and messages are shown to visitors and in the owner's
		// lists: an override such as U+202E would make "invoice\u202Etxt.exe"
		// read as "invoiceexe.txt" (the rule of file names, names.Clean).
		if names.IsBidiControl(r) {
			return "", core.Invalid(field, "must not contain text-direction control characters")
		}
	}
	return s, nil
}

func positive(field string, v *int64) error {
	if v != nil && *v < 1 {
		return core.Invalid(field, "must be at least 1 (or omitted for no limit)")
	}
	return nil
}

// validPassword checks a password being set on a share. Link passwords are
// often the only access control on the content behind a public URL, and the
// public /s/{token}/api/password route allows every client IP the sign-in
// rate of attempts (see CheckPassword), so a 1-2 character password (or a
// 4-digit PIN) is guessable in hours: new passwords must be at least
// MinPassword characters and must not be trivially repetitive. Verification
// (public.go CheckPassword) deliberately does not apply this policy — shares
// created before it keep working.
func validPassword(pw string) error {
	if len(pw) > MaxPassword {
		return core.Invalid("password", fmt.Sprintf("must be at most %d bytes", MaxPassword))
	}
	if !utf8.ValidString(pw) {
		return core.Invalid("password", "must be valid UTF-8")
	}
	for _, r := range pw {
		if unicode.IsControl(r) {
			return core.Invalid("password", "must not contain control characters")
		}
	}
	if utf8.RuneCountInString(pw) < MinPassword {
		return core.Invalid("password", fmt.Sprintf("must be at least %d characters", MinPassword))
	}
	if distinctRunes(pw) < minDistinctRunes {
		return core.Invalid("password", fmt.Sprintf("must use at least %d different characters", minDistinctRunes))
	}
	return nil
}

// distinctRunes counts the different characters of s (case-insensitively).
func distinctRunes(s string) int {
	seen := map[rune]struct{}{}
	for _, r := range strings.ToLower(s) {
		seen[r] = struct{}{}
	}
	return len(seen)
}

// expiry resolves the expiry of a share. exp wins; noExpiry asks for none;
// otherwise (create only) the default applies. sharing.max_expiry_days caps
// every value against now — at creation that is the share's whole lifetime;
// on update the caller additionally clamps against the creation time (see
// Update), so repeated edits cannot renew a link for ever.
func (svc *Service) expiry(exp *time.Time, noExpiry, useDefault bool, now time.Time) (*time.Time, error) {
	maxDays := svc.intSetting(SettingMaxExpiryDays, DefaultMaxExpiryDays)
	var limit time.Time
	if maxDays > 0 {
		limit = now.Add(time.Duration(maxDays) * 24 * time.Hour)
	}
	switch {
	case exp != nil:
		t := exp.UTC().Truncate(time.Millisecond)
		if !t.After(now) {
			return nil, core.Invalid("expires_at", "the expiry must be in the future")
		}
		if maxDays > 0 && t.After(limit) {
			return nil, core.Invalid("expires_at", fmt.Sprintf("links may last at most %d days", maxDays))
		}
		return &t, nil
	case noExpiry:
		if maxDays > 0 {
			return nil, core.Invalid("expires_at", fmt.Sprintf("links must expire within %d days", maxDays))
		}
		return nil, nil
	case !useDefault:
		return nil, nil
	}
	days := svc.intSetting(SettingDefaultExpiryDays, DefaultDefaultExpiryDays)
	if days <= 0 {
		if maxDays > 0 {
			return &limit, nil
		}
		return nil, nil
	}
	t := now.Add(time.Duration(days) * 24 * time.Hour)
	if maxDays > 0 && t.After(limit) {
		t = limit
	}
	return &t, nil
}

// ---------- CRUD ----------

// Create implements core.Shares. It requires PermManage on the node,
// sharing.links_enabled (links) or sharing.requests_enabled (requests) and
// the permission of the kind in the creator's role (shareCapRefusal:
// shares.links or shares.requests; built-in guests hold them only while
// sharing.allow_guests_share is on, which package auth folds into the
// principal); an API token needs the shares and files:read scopes, and
// files:write as well for a share that accepts uploads (file requests,
// links with uploads). File requests need a folder and default to
// upload-only (no listing, no downloads). The token is returned once; the
// link can be shown again to the owner (field-encrypted copy).
func (svc *Service) Create(ctx context.Context, p *core.Principal, in core.ShareInput) (*core.Share, string, error) {
	if p == nil || p.UserID == "" {
		return nil, "", core.ErrUnauthorized
	}
	if !p.HasScope(core.ScopeShares) {
		return nil, "", core.Errorf(core.ErrForbidden, "token lacks scope %q", core.ScopeShares)
	}
	kind := in.Kind
	if kind == "" {
		kind = core.ShareLink
	}
	switch kind {
	case core.ShareLink:
		if !svc.boolSetting(SettingLinksEnabled, true) {
			return nil, "", core.Errorf(core.ErrForbidden, "share links are disabled on this server")
		}
	case core.ShareRequest:
		if !svc.boolSetting(SettingRequestsEnabled, true) {
			return nil, "", core.Errorf(core.ErrForbidden, "file requests are disabled on this server")
		}
	default:
		return nil, "", core.Invalid("kind", `kind must be "link" or "request"`)
	}
	if why := shareCapRefusal(p, kind); why != "" {
		return nil, "", core.Errorf(core.ErrForbidden, "%s", why)
	}
	if in.NodeID == "" {
		return nil, "", core.Invalid("node_id", "node_id is required")
	}
	node, err := svc.files.Authorize(ctx, p, in.NodeID, core.PermManage)
	if err != nil {
		return nil, "", err
	}
	isRequest := kind == core.ShareRequest
	if isRequest && !node.IsDir() {
		return nil, "", core.Invalid("node_id", "file requests need a folder")
	}
	title, err := cleanText("title", in.Title, MaxTitle, false)
	if err != nil {
		return nil, "", err
	}
	message, err := cleanText("message", in.Message, MaxMessage, true)
	if err != nil {
		return nil, "", err
	}
	allowDownload, allowPreview := !isRequest, !isRequest
	if in.AllowDownload != nil {
		allowDownload = *in.AllowDownload
	}
	if in.AllowPreview != nil {
		allowPreview = *in.AllowPreview
	}
	if isRequest {
		if err := requestFlags(&allowDownload, &allowPreview, nil); err != nil {
			return nil, "", err
		}
	}
	allowUpload := in.AllowUpload || isRequest
	if allowUpload && !node.IsDir() {
		return nil, "", core.Invalid("allow_upload", "uploads need a folder")
	}
	// Visitors of a share that accepts uploads write into the folder, so a
	// token needs files:write for it (files.Authorize asks only files:read
	// for sharing).
	if allowUpload && !p.HasScope(core.ScopeFilesWrite) {
		return nil, "", core.Errorf(core.ErrForbidden, "token lacks scope %q", core.ScopeFilesWrite)
	}
	for f, v := range map[string]*int64{"upload_max_file_bytes": in.UploadMaxFileBytes,
		"upload_quota_bytes": in.UploadQuotaBytes, "max_downloads": in.MaxDownloads} {
		if err := positive(f, v); err != nil {
			return nil, "", err
		}
	}
	var pwHash string
	pwVersion := 0
	switch {
	case in.Password != "":
		if err := validPassword(in.Password); err != nil {
			return nil, "", err
		}
		if pwHash, err = svc.hashPassword(in.Password); err != nil {
			return nil, "", err
		}
		pwVersion = 1
	case svc.boolSetting(SettingRequirePassword, false):
		return nil, "", core.Invalid("password", "this server requires a password on new links and file requests")
	}
	now := svc.env.Now()
	exp, err := svc.expiry(in.ExpiresAt, in.NoExpiry, true, now)
	if err != nil {
		return nil, "", err
	}
	if svc.env.Keys == nil {
		return nil, "", core.ErrKeysLocked
	}
	id := ids.New(ids.PrefixShare)
	token := ids.Token(TokenBytes)
	enc, err := svc.env.Keys.SealField(tokenAAD(id), []byte(token))
	if err != nil {
		return nil, "", err
	}
	err = svc.env.DB.Tx(ctx, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, `INSERT INTO shares (id, kind, node_id, created_by, token_hash, token_enc, title,
				message, password_hash, password_version, allow_download, allow_preview, allow_upload,
				require_uploader_name, upload_max_file_bytes, upload_quota_bytes, max_downloads, expires_at,
				notify_owner, created_at, updated_at)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			id, kind, node.ID, p.UserID, ids.HashToken(token), enc, db.NullString(title), db.NullString(message),
			db.NullString(pwHash), pwVersion, allowDownload, allowPreview, allowUpload,
			in.RequireUploaderName && allowUpload, db.NullInt64(in.UploadMaxFileBytes), db.NullInt64(in.UploadQuotaBytes),
			db.NullInt64(in.MaxDownloads), db.NullMs(exp), in.NotifyOwner, db.Ms(now), db.Ms(now)); err != nil {
			return err
		}
		return svc.auditTx(ctx, tx, core.AuditEntry{Action: core.ActShareCreate, TargetType: "share", TargetID: id,
			TargetName: node.Name, Details: map[string]any{"kind": kind, "node": node.ID, "password": pwHash != "",
				"expires_at": exp, "max_downloads": in.MaxDownloads, "allow_upload": allowUpload}})
	})
	if err != nil {
		return nil, "", err
	}
	r, err := svc.byID(ctx, id)
	if err != nil {
		return nil, "", err
	}
	s := svc.finish(r, false)
	s.URL = svc.linkFor(token)
	return s, token, nil
}

func (svc *Service) auditTx(ctx context.Context, tx *sql.Tx, e core.AuditEntry) error {
	if svc.env.Audit == nil {
		return nil
	}
	return svc.env.Audit.RecordTx(ctx, tx, e)
}

// Get implements core.Shares: the creator's share, or any share for a
// holder of shares.manage (the link only when canSeeURL).
func (svc *Service) Get(ctx context.Context, p *core.Principal, id string) (*core.Share, error) {
	r, err := svc.visible(ctx, p, id)
	if err != nil {
		return nil, err
	}
	sh := svc.finish(r, svc.canSeeURL(p, r.s.CreatedBy))
	svc.markUnavailable(ctx, sh, map[string]*core.Principal{})
	return sh, nil
}

// Update implements core.Shares. The creator may change every field; an
// admin may only disable or enable other users' shares. Changing a link in
// any way other than disabling it is sharing, so the creator must still be
// allowed to share the item — what Create requires: PermManage on the node
// and the permission of the kind (shares.links or shares.requests).
// Disabling (like Revoke) needs neither, so a creator who lost that right
// can always shut the link off.
// Changing or removing the password bumps password_version, which
// invalidates existing access cookies.
func (svc *Service) Update(ctx context.Context, p *core.Principal, id string, in core.ShareUpdate) (*core.Share, error) {
	r, err := svc.visible(ctx, p, id)
	if err != nil {
		return nil, err
	}
	if !p.HasScope(core.ScopeShares) {
		return nil, core.Errorf(core.ErrForbidden, "token lacks scope %q", core.ScopeShares)
	}
	s := r.s
	owner := s.CreatedBy == p.UserID
	onlyDisable := in.Title == nil && in.Message == nil && in.Password == nil && in.AllowDownload == nil &&
		in.AllowPreview == nil && in.AllowUpload == nil && in.RequireUploaderName == nil && !in.UploadMaxFileBytes.Set &&
		!in.UploadQuotaBytes.Set && !in.MaxDownloads.Set && !in.ExpiresAt.Set && in.NotifyOwner == nil
	if !owner && !onlyDisable {
		return nil, core.Errorf(core.ErrForbidden, "administrators may only disable or enable other users' shares")
	}
	if owner && !(onlyDisable && (in.Disabled == nil || *in.Disabled)) {
		if err := svc.canStillShare(ctx, p, s.Kind, s.NodeID); err != nil {
			return nil, err
		}
	}
	now := svc.env.Now()
	var sets []string
	var args []any
	var changed []string
	set := func(col string, v any) {
		sets = append(sets, col+" = ?")
		args = append(args, v)
		changed = append(changed, col)
	}
	if in.Title != nil {
		t, err := cleanText("title", *in.Title, MaxTitle, false)
		if err != nil {
			return nil, err
		}
		set("title", db.NullString(t))
	}
	if in.Message != nil {
		m, err := cleanText("message", *in.Message, MaxMessage, true)
		if err != nil {
			return nil, err
		}
		set("message", db.NullString(m))
	}
	if in.Password != nil {
		if *in.Password == "" {
			if svc.boolSetting(SettingRequirePassword, false) {
				return nil, core.Invalid("password", "links must have a password on this server")
			}
			set("password_hash", nil)
		} else {
			if err := validPassword(*in.Password); err != nil {
				return nil, err
			}
			h, err := svc.hashPassword(*in.Password)
			if err != nil {
				return nil, err
			}
			set("password_hash", h)
		}
		sets = append(sets, "password_version = password_version + 1")
	}
	isDir := s.NodeKind == core.KindFolder
	if s.Kind == core.ShareRequest {
		if err := requestFlags(in.AllowDownload, in.AllowPreview, in.AllowUpload); err != nil {
			return nil, err
		}
	}
	if in.AllowDownload != nil {
		set("allow_download", *in.AllowDownload)
	}
	if in.AllowPreview != nil {
		set("allow_preview", *in.AllowPreview)
	}
	if in.AllowUpload != nil {
		if *in.AllowUpload && !isDir {
			return nil, core.Invalid("allow_upload", "uploads need a folder")
		}
		// Visitors of a share that accepts uploads write into the folder:
		// a token needs files:write to turn uploads on, as it does to
		// create such a share.
		if *in.AllowUpload && !s.AllowUpload && !p.HasScope(core.ScopeFilesWrite) {
			return nil, core.Errorf(core.ErrForbidden, "token lacks scope %q", core.ScopeFilesWrite)
		}
		set("allow_upload", *in.AllowUpload)
	}
	if in.RequireUploaderName != nil {
		set("require_uploader_name", *in.RequireUploaderName)
	}
	for _, o := range []struct {
		col string
		v   core.Opt[int64]
	}{{"upload_max_file_bytes", in.UploadMaxFileBytes}, {"upload_quota_bytes", in.UploadQuotaBytes}, {"max_downloads", in.MaxDownloads}} {
		if !o.v.Set {
			continue
		}
		if err := positive(o.col, o.v.Ptr()); err != nil {
			return nil, err
		}
		set(o.col, db.NullInt64(o.v.Ptr()))
	}
	if in.ExpiresAt.Set {
		exp, err := svc.expiry(in.ExpiresAt.Ptr(), in.ExpiresAt.Null, false, now)
		if err != nil {
			return nil, err
		}
		// sharing.max_expiry_days is a lifetime cap: an edit may not push a
		// link past maxDays from its creation, otherwise repeated edits renew
		// it for ever. Shortening is always allowed (a share without expiry
		// counts as the latest possible one), so lowering the setting later
		// never freezes an existing share's expiry.
		if maxDays := svc.intSetting(SettingMaxExpiryDays, DefaultMaxExpiryDays); maxDays > 0 && exp != nil {
			life := s.CreatedAt.Add(time.Duration(maxDays) * 24 * time.Hour)
			if exp.After(life) && s.ExpiresAt != nil && exp.After(*s.ExpiresAt) {
				return nil, core.Invalid("expires_at", fmt.Sprintf("links may last at most %d days from creation", maxDays))
			}
		}
		set("expires_at", db.NullMs(exp))
	}
	if in.NotifyOwner != nil {
		set("notify_owner", *in.NotifyOwner)
	}
	if in.Disabled != nil {
		switch {
		case *in.Disabled && s.DisabledAt == nil:
			set("disabled_at", db.Ms(now))
		case !*in.Disabled && s.DisabledAt != nil:
			set("disabled_at", nil)
		}
	}
	if len(sets) > 0 {
		sets = append(sets, "updated_at = ?")
		args = append(args, db.Ms(now), s.ID)
		fields := changed
		if in.Password != nil {
			fields = append(fields, "password_version")
		}
		// kind and disabled let the activity feeds say "Closed the file
		// request" rather than "Changed the link" (web components/activity.js).
		details := map[string]any{"fields": maskFields(fields), "owner": s.CreatedBy, "kind": s.Kind}
		if slices.Contains(changed, "disabled_at") {
			details["disabled"] = *in.Disabled
		}
		err = svc.env.DB.Tx(ctx, func(tx *sql.Tx) error {
			if _, err := tx.ExecContext(ctx, `UPDATE shares SET `+strings.Join(sets, ", ")+` WHERE id = ?`, args...); err != nil {
				return err
			}
			return svc.auditTx(ctx, tx, core.AuditEntry{Action: core.ActShareUpdate, TargetType: "share", TargetID: s.ID,
				TargetName: s.NodeName, Details: details})
		})
		if err != nil {
			return nil, err
		}
	}
	return svc.Get(ctx, p, id)
}

// canStillShare re-checks, for an edit of an existing share of kind, what
// Create requires of its creator: a demoted group manager (or a user whose
// role lost the permission of the kind) must not re-open, widen or
// re-enable a link they could no longer create. The share itself stays
// visible to its creator, so losing access to the node is reported as
// forbidden rather than as a missing node.
func (svc *Service) canStillShare(ctx context.Context, p *core.Principal, kind, nodeID string) error {
	if why := shareCapRefusal(p, kind); why != "" {
		return core.Errorf(core.ErrForbidden, "%s; the link can only be disabled or deleted", why)
	}
	if _, err := svc.files.Authorize(ctx, p, nodeID, core.PermManage); err != nil {
		if errors.Is(err, core.ErrNotFound) {
			return core.Errorf(core.ErrForbidden, "you can no longer share this item; the link can only be disabled or deleted")
		}
		return err
	}
	return nil
}

// requestFlags enforces what a file request is (DESIGN §8.1): visitors add
// files to the folder but never see what is already there, so downloads and
// previews stay off and uploads on. A nil flag is not being set. It answers
// 422 on the field that asks for something else.
func requestFlags(download, preview, upload *bool) error {
	switch {
	case download != nil && *download:
		return core.Invalid("allow_download", "a file request never shows the folder's files; create a link to share them")
	case preview != nil && *preview:
		return core.Invalid("allow_preview", "a file request never shows the folder's files; create a link to share them")
	case upload != nil && !*upload:
		return core.Invalid("allow_upload", "a file request always accepts files; disable it to stop uploads")
	}
	return nil
}

// maskFields renames secret columns for the audit log.
func maskFields(cols []string) []string {
	out := make([]string, 0, len(cols))
	for _, c := range cols {
		if c == "password_hash" {
			c = "password"
		}
		out = append(out, c)
	}
	return out
}

// Revoke implements core.Shares: the share is deleted (with its access log);
// open file-request uploads are aborted first. Creator or admin.
func (svc *Service) Revoke(ctx context.Context, p *core.Principal, id string) error {
	r, err := svc.visible(ctx, p, id)
	if err != nil {
		return err
	}
	if !p.HasScope(core.ScopeShares) {
		return core.Errorf(core.ErrForbidden, "token lacks scope %q", core.ScopeShares)
	}
	if svc.uploads != nil {
		// Aborting the open batches is best effort — the share row is deleted
		// either way — but a read that fails must be logged, not mistaken for
		// "nothing to abort": the batches would be left orphaned without a
		// trace of why.
		rows, err := svc.env.DB.Query(ctx, `SELECT id FROM upload_batches WHERE share_id = ? AND state = 'open'`, id)
		if err != nil {
			svc.log.Warn("list file-request uploads to abort", "share", id, "err", err)
		} else {
			var batches []string
			for rows.Next() {
				var b string
				if err := rows.Scan(&b); err != nil {
					svc.log.Warn("list file-request uploads to abort", "share", id, "err", err)
					break
				}
				batches = append(batches, b)
			}
			if err := rows.Err(); err != nil {
				svc.log.Warn("list file-request uploads to abort", "share", id, "err", err)
			}
			rows.Close()
			for _, b := range batches {
				if err := svc.uploads.AbortBatch(ctx, core.UploadActor{ShareID: id}, b); err != nil {
					svc.log.Warn("abort file-request upload", "share", id, "batch", b, "err", err)
				}
			}
		}
	}
	return svc.env.DB.Tx(ctx, func(tx *sql.Tx) error {
		res, err := tx.ExecContext(ctx, `DELETE FROM shares WHERE id = ?`, id)
		if err != nil {
			return err
		}
		if n, err := res.RowsAffected(); err != nil || n == 0 {
			if err == nil {
				err = core.NotFoundf("share not found")
			}
			return err
		}
		return svc.auditTx(ctx, tx, core.AuditEntry{Action: core.ActShareRevoke, TargetType: "share", TargetID: id,
			TargetName: r.s.NodeName, Details: map[string]any{"kind": r.s.Kind, "node": r.s.NodeID, "owner": r.s.CreatedBy}})
	})
}

// ---------- lists ----------

type listCursor struct {
	T  int64  `json:"t"`
	ID string `json:"id"`
}

func encodeCursor(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		return ""
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

func decodeCursor(s string, v any) error {
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil || len(b) == 0 || json.Unmarshal(b, v) != nil {
		return core.Invalid("cursor", "invalid cursor")
	}
	return nil
}

// List implements core.Shares: the principal's own shares, newest first.
func (svc *Service) List(ctx context.Context, p *core.Principal, q core.ShareQuery) (core.Page[core.Share], error) {
	if p == nil || p.UserID == "" {
		return core.Page[core.Share]{}, core.ErrUnauthorized
	}
	q.UserID = p.UserID
	return svc.list(ctx, p, q)
}

// ListAll implements core.Shares (admin view; q.UserID filters by creator).
// Links are included only where canSeeURL allows it for the context
// principal.
func (svc *Service) ListAll(ctx context.Context, q core.ShareQuery) (core.Page[core.Share], error) {
	return svc.list(ctx, core.PrincipalFrom(ctx), q)
}

func (svc *Service) list(ctx context.Context, p *core.Principal, q core.ShareQuery) (core.Page[core.Share], error) {
	var where []string
	var args []any
	if q.UserID != "" {
		where = append(where, "s.created_by = ?")
		args = append(args, q.UserID)
	}
	switch q.Kind {
	case "":
	case core.ShareLink, core.ShareRequest:
		where = append(where, "s.kind = ?")
		args = append(args, q.Kind)
	default:
		return core.Page[core.Share]{}, core.Invalid("kind", `kind must be "link" or "request"`)
	}
	if q.NodeID != "" {
		where = append(where, "s.node_id = ?")
		args = append(args, q.NodeID)
	}
	now := db.Ms(svc.env.Now())
	const active = `(s.disabled_at IS NULL AND (s.expires_at IS NULL OR s.expires_at > ?)
		AND (s.max_downloads IS NULL OR s.download_count < s.max_downloads))`
	switch q.Status {
	case "":
	case core.ShareActive:
		where = append(where, active)
		args = append(args, now)
	case "inactive":
		where = append(where, "NOT "+active)
		args = append(args, now)
	default:
		return core.Page[core.Share]{}, core.Invalid("status", `status must be "active" or "inactive"`)
	}
	if q.Cursor != "" {
		var c listCursor
		if err := decodeCursor(q.Cursor, &c); err != nil {
			return core.Page[core.Share]{}, err
		}
		where = append(where, "(s.created_at < ? OR (s.created_at = ? AND s.id < ?))")
		args = append(args, c.T, c.T, c.ID)
	}
	query := `SELECT ` + shareCols + shareFrom
	if len(where) > 0 {
		query += " WHERE " + strings.Join(where, " AND ")
	}
	limit := q.EffectiveLimit()
	query += " ORDER BY s.created_at DESC, s.id DESC LIMIT ?"
	args = append(args, limit+1)
	rows, err := svc.env.DB.Query(ctx, query, args...)
	if err != nil {
		return core.Page[core.Share]{}, err
	}
	defer rows.Close()
	var out []core.Share
	next := ""
	for rows.Next() {
		r, err := scanShare(rows)
		if err != nil {
			return core.Page[core.Share]{}, err
		}
		if len(out) == limit {
			last := out[len(out)-1]
			next = encodeCursor(listCursor{T: db.Ms(last.CreatedAt), ID: last.ID})
			break
		}
		out = append(out, *svc.finish(r, svc.canSeeURL(p, r.s.CreatedBy)))
	}
	if err := rows.Err(); err != nil {
		return core.Page[core.Share]{}, err
	}
	rows.Close() // the checks below read through the same pool
	owners := map[string]*core.Principal{}
	for i := range out {
		svc.markUnavailable(ctx, &out[i], owners)
	}
	return core.NewPage(out, next), nil
}

// AccessLog implements core.Shares: newest first (creator or admin). Rows
// older than sharing.access_log_days are pruned by maintenance.db_optimize.
func (svc *Service) AccessLog(ctx context.Context, p *core.Principal, id string, q core.PageReq) (core.Page[core.ShareAccess], error) {
	if _, err := svc.visible(ctx, p, id); err != nil {
		return core.Page[core.ShareAccess]{}, err
	}
	args := []any{id}
	query := `SELECT id, share_id, at, action, node_id, bytes, ip, user_agent, uploader FROM share_access_log WHERE share_id = ?`
	if q.Cursor != "" {
		var c struct {
			ID int64 `json:"id"`
		}
		if err := decodeCursor(q.Cursor, &c); err != nil {
			return core.Page[core.ShareAccess]{}, err
		}
		query += " AND id < ?"
		args = append(args, c.ID)
	}
	limit := q.EffectiveLimit()
	query += " ORDER BY id DESC LIMIT ?"
	args = append(args, limit+1)
	rows, err := svc.env.DB.Query(ctx, query, args...)
	if err != nil {
		return core.Page[core.ShareAccess]{}, err
	}
	defer rows.Close()
	var out []core.ShareAccess
	next := ""
	for rows.Next() {
		var (
			a                   core.ShareAccess
			at                  int64
			node, ip, ua, upldr sql.NullString
			bytes               sql.NullInt64
		)
		if err := rows.Scan(&a.ID, &a.ShareID, &at, &a.Action, &node, &bytes, &ip, &ua, &upldr); err != nil {
			return core.Page[core.ShareAccess]{}, err
		}
		if len(out) == limit {
			next = encodeCursor(struct {
				ID int64 `json:"id"`
			}{out[len(out)-1].ID})
			break
		}
		a.At = db.FromMs(at)
		a.NodeID, a.Bytes, a.IP, a.UserAgent, a.Uploader = node.String, bytes.Int64, ip.String, ua.String, upldr.String
		out = append(out, a)
	}
	if err := rows.Err(); err != nil {
		return core.Page[core.ShareAccess]{}, err
	}
	return core.NewPage(out, next), nil
}
