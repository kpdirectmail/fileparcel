package shares

import (
	"context"
	"crypto/hmac"
	"database/sql"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"net/http"
	"slices"
	"strconv"
	"time"
	"unicode/utf8"

	"fileparcel/internal/core"
	"fileparcel/internal/crypt"
	"fileparcel/internal/db"
	"fileparcel/internal/events"
	"fileparcel/internal/ids"
	"fileparcel/internal/ratelimit"
)

// errNotFound is the single error of Resolve for every invalid token or
// share state (no oracle).
func errNotFound() error { return core.NotFoundf("share not found") }

// ValidToken reports whether tok has the shape of a share token (22 base62
// characters). Anything else can be rejected without a database lookup.
func ValidToken(tok string) bool {
	return len(tok) == ids.TokenLen(TokenBytes) && ids.ValidToken(tok)
}

// Resolve implements core.Shares: it maps a public token to its share and
// node and validates everything — token shape, not disabled, not expired,
// download limit not reached, links / requests enabled, the creator still
// active and still allowed to see the node (a file request: to add files to
// it, PermEdit — otherwise its page would open and every upload fail), the
// node not trashed. Every failure returns the same not-found error. A file
// request never shows the folder's contents, whatever its stored flags say
// (rows written before Create and Update enforced it): AllowDownload and
// AllowPreview are false on the returned share.
func (svc *Service) Resolve(ctx context.Context, token string) (*core.Share, *core.Node, error) {
	if !ValidToken(token) {
		return nil, nil, errNotFound()
	}
	r, err := scanShare(svc.env.DB.QueryRow(ctx, `SELECT `+shareCols+shareFrom+` WHERE s.token_hash = ?`, ids.HashToken(token)))
	if db.IsNoRows(err) {
		return nil, nil, errNotFound()
	}
	if err != nil {
		return nil, nil, err
	}
	s := svc.finish(r, false)
	switch {
	case s.Status != core.ShareActive, r.nodeTrashed, r.ownerStatus != core.UserActive:
		return nil, nil, errNotFound()
	case s.Kind == core.ShareLink && !svc.boolSetting(SettingLinksEnabled, true):
		return nil, nil, errNotFound()
	case s.Kind == core.ShareRequest && !svc.boolSetting(SettingRequestsEnabled, true):
		return nil, nil, errNotFound()
	}
	node, err := svc.files.GetSys(ctx, s.NodeID)
	if err != nil {
		if errors.Is(err, core.ErrNotFound) {
			return nil, nil, errNotFound()
		}
		return nil, nil, err
	}
	if node.TrashedAt != nil {
		return nil, nil, errNotFound()
	}
	// The link stops working when its creator loses access to the node.
	owner, err := svc.files.SysPrincipalFor(ctx, s.CreatedBy)
	if err != nil {
		if errors.Is(err, core.ErrNotFound) || errors.Is(err, core.ErrForbidden) {
			return nil, nil, errNotFound()
		}
		return nil, nil, err
	}
	if _, err := svc.files.Authorize(ctx, owner, s.NodeID, creatorNeeds(s)); err != nil {
		if errors.Is(err, core.ErrNotFound) || errors.Is(err, core.ErrForbidden) {
			return nil, nil, errNotFound()
		}
		return nil, nil, err
	}
	if s.Kind == core.ShareRequest {
		s.AllowDownload, s.AllowPreview = false, false
	}
	return s, node, nil
}

// creatorNeeds is the permission the creator of s must still hold on its
// node for the share to work: PermEdit for a file request (visitors add
// files as the creator), PermView for a link. A link that also accepts
// uploads keeps working for downloads with PermView; its uploads then fail
// (sharesapi refuses them as "does not accept uploads").
func creatorNeeds(s *core.Share) core.Perm {
	if s.Kind == core.ShareRequest {
		return core.PermEdit
	}
	return core.PermView
}

// Share password throttling. The generic entry limit of the public routes
// (bucket "share", ratelimit.share_per_min per IP) only bounds the request
// volume — it is spent by page views too and is far too generous for
// password guesses — so attempts have buckets of their own:
//
//   - bucketPwIP: every attempt on one share from one client IP
//     ("<share>|<ip>"), at ratelimit.login_per_min per minute (the sign-in
//     allowance). Consumed up front, so concurrent attempts cannot overshoot.
//   - bucketPwShare: wrong passwords on one share from all addresses
//     together ("<share>"), at pwShareFactor times that rate, so guessing
//     from many addresses (an IPv6 prefix, a botnet) is bounded as well.
//     Only failures count: visitors who know the password never use it up,
//     and a visitor holding the access cookie never asks again.
//
// Over Tailscale Funnel (meta.Ingress) the client address in bucketPwIP is
// core.IPLimitKey's (an IPv6 client counts per /64: an internet client
// holds a whole /64), and every wrong password also takes a token from
// ratelimit.BucketFunnelSharePW ("<share>", burst 20, 20 an hour): while it
// is empty, attempts on that share from the internet are refused like any
// other blocked attempt, and attempts over the LAN or the tailnet are
// unaffected. Someone on the internet can thereby block a share's password
// form over Funnel for up to an hour (documented).
//
// A refused attempt runs no argon2id verification.
const (
	bucketPwIP    = "share_pw"
	bucketPwShare = "share_pw_all"
	pwShareFactor = 10
)

// configurePwBuckets (re)configures the password buckets from
// ratelimit.login_per_min when the setting changed.
func (svc *Service) configurePwBuckets() {
	rate := svc.intSetting(settingLoginPerMin, ratelimit.DefaultLoginPerMin)
	if rate <= 0 {
		rate = ratelimit.DefaultLoginPerMin
	}
	svc.pwMu.Lock()
	defer svc.pwMu.Unlock()
	if rate == svc.pwRate {
		return
	}
	svc.pwRate = rate
	svc.limiter.Configure(bucketPwIP, float64(rate), int(rate))
	svc.limiter.Configure(bucketPwShare, float64(rate*pwShareFactor), int(rate*pwShareFactor))
}

// CheckPassword implements core.Shares. Attempts are rate limited per share
// and client IP, and wrong ones per share (bucketPwIP, bucketPwShare); a
// refused attempt is logged as "blocked". Failures are logged in the access
// log and audited (share.password_fail). A share without password always
// passes.
func (svc *Service) CheckPassword(ctx context.Context, s *core.Share, pw string, meta core.ReqMeta) error {
	if s == nil {
		return errNotFound()
	}
	if s.PasswordHash == "" {
		return nil
	}
	acc := core.ShareAccess{IP: ipString(meta), UserAgent: meta.UserAgent}
	funnel := meta.Ingress == core.IngressFunnel
	if svc.limiter != nil {
		svc.configurePwBuckets()
		allowed := svc.limiter.Tokens(bucketPwShare, s.ID) >= 1
		if allowed && funnel {
			allowed = svc.limiter.Tokens(ratelimit.BucketFunnelSharePW, s.ID) >= 1
		}
		if allowed {
			allowed, _ = svc.limiter.Allow(bucketPwIP, s.ID+"|"+pwClientKey(meta))
		}
		if !allowed {
			acc.Action = core.AccessBlocked
			svc.RecordAccess(ctx, s, acc)
			return core.Errorf(core.ErrRateLimited, "too many password attempts; please wait a minute")
		}
	}
	ok := false
	if len(pw) <= MaxPassword && utf8.ValidString(pw) {
		var err error
		if ok, _, err = svc.verifyPassword(ctx, s.PasswordHash, pw); err != nil {
			// Not checked (too many argon2 checks queued, or the client
			// left): neither a failed attempt nor an access.
			if errors.Is(err, crypt.ErrArgonBusy) {
				return core.Errorf(core.ErrUnavailable, "the server is busy checking passwords; try again in a moment")
			}
			return err
		}
	}
	if !ok {
		if svc.limiter != nil {
			svc.limiter.Allow(bucketPwShare, s.ID)
			if funnel {
				svc.limiter.Allow(ratelimit.BucketFunnelSharePW, s.ID)
			}
		}
		acc.Action = core.AccessPasswordFail
		svc.RecordAccess(ctx, s, acc)
		if svc.env.Audit != nil {
			svc.env.Audit.Record(ctx, core.AuditEntry{Action: core.ActSharePasswordFail, Outcome: core.OutcomeFailure,
				TargetType: "share", TargetID: s.ID, ActorName: "anonymous", ActorVia: string(core.ViaShare),
				IP: acc.IP, UserAgent: meta.UserAgent, RequestID: meta.RequestID})
		}
		return &core.Error{Code: core.ErrUnauthorized.Code, Status: core.ErrUnauthorized.Status,
			Message: "the password is not correct", Field: "password"}
	}
	acc.Action = core.AccessPasswordOK
	svc.RecordAccess(ctx, s, acc)
	return nil
}

func ipString(m core.ReqMeta) string {
	if m.IP.IsValid() {
		return m.IP.String()
	}
	return ""
}

// pwClientKey is the client part of a bucketPwIP key: the address, or over
// Tailscale Funnel core.IPLimitKey's (an IPv6 client's /64).
func pwClientKey(m core.ReqMeta) string {
	if !m.IP.IsValid() {
		return ""
	}
	return core.IPLimitKey(m.IP, m.Ingress == core.IngressFunnel)
}

// CookieName returns the name of the access cookie of a share:
// "__Host-fp_s_" + the last 8 characters of the share id (the random part
// of the UUIDv7-based id; the leading characters encode the creation time
// and would collide between shares created in the same second).
func CookieName(shareID string) string {
	suffix := shareID
	if len(suffix) > 8 {
		suffix = suffix[len(suffix)-8:]
	}
	return CookiePrefix + suffix
}

// cookieMAC is MAC("share", share_id, password_version, exp).
func (svc *Service) cookieMAC(s *core.Share, exp []byte) []byte {
	if svc.env.Keys == nil {
		return nil
	}
	return svc.env.Keys.MAC("share", []byte(s.ID), []byte(strconv.Itoa(s.PasswordVersion)), exp)
}

// AccessCookie implements core.Shares: the cookie proving that the share
// password was entered, valid for 12 hours and bound to the share and its
// password_version: base64url(exp || MAC("share", id, version, exp)) with
// exp as 8-byte big-endian Unix seconds. Secure, HttpOnly, SameSite=Lax,
// Path=/ (__Host- prefix).
func (svc *Service) AccessCookie(s *core.Share) (*http.Cookie, error) {
	exp := svc.env.Now().Add(CookieTTL).Truncate(time.Second)
	var eb [8]byte
	binary.BigEndian.PutUint64(eb[:], uint64(exp.Unix()))
	mac := svc.cookieMAC(s, eb[:])
	if mac == nil {
		return nil, core.ErrKeysLocked
	}
	return &http.Cookie{
		Name:     CookieName(s.ID),
		Value:    base64.RawURLEncoding.EncodeToString(append(eb[:], mac...)),
		Path:     "/",
		Expires:  exp,
		MaxAge:   int(CookieTTL / time.Second),
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	}, nil
}

// HasAccess implements core.Shares: true for shares without password, else
// when the request carries a valid, unexpired access cookie for the
// current password_version.
func (svc *Service) HasAccess(r *http.Request, s *core.Share) bool {
	if s == nil {
		return false
	}
	if s.PasswordHash == "" {
		return true
	}
	now := svc.env.Now()
	for _, c := range r.CookiesNamed(CookieName(s.ID)) {
		raw, err := base64.RawURLEncoding.DecodeString(c.Value)
		if err != nil || len(raw) != 8+32 {
			continue
		}
		exp := int64(binary.BigEndian.Uint64(raw[:8]))
		if exp <= now.Unix() || exp > now.Add(CookieTTL+time.Minute).Unix() {
			continue
		}
		if want := svc.cookieMAC(s, raw[:8]); want != nil && hmac.Equal(raw[8:], want) {
			return true
		}
	}
	return false
}

// CountDownload implements core.Shares: it atomically increments the
// download counter unless max_downloads is reached (ErrForbidden then). A
// share that no longer exists (revoked, or cascaded away with its node or
// owner, between Resolve and here) gets the uniform not-found instead, like
// every other unusable share state.
func (svc *Service) CountDownload(ctx context.Context, s *core.Share) error {
	if s == nil {
		return errNotFound()
	}
	now := db.Ms(svc.env.Now())
	var n int64
	var gone bool
	err := svc.env.DB.Tx(ctx, func(tx *sql.Tx) error {
		res, err := tx.ExecContext(ctx, `UPDATE shares SET download_count = download_count + 1, last_access_at = ?
			WHERE id = ? AND (max_downloads IS NULL OR download_count < max_downloads)`, now, s.ID)
		if err != nil {
			return err
		}
		if n, err = res.RowsAffected(); err != nil || n > 0 {
			return err
		}
		// No row updated: either the limit is reached, or the share is gone.
		// Only the first is a 403.
		var one int
		err = tx.QueryRowContext(ctx, `SELECT 1 FROM shares WHERE id = ?`, s.ID).Scan(&one)
		if db.IsNoRows(err) {
			gone, err = true, nil
		}
		return err
	})
	if err != nil {
		return err
	}
	switch {
	case gone:
		return errNotFound()
	case n == 0:
		return core.Errorf(core.ErrForbidden, "the download limit of this link has been reached")
	}
	s.DownloadCount++
	return nil
}

var accessActions = []string{core.AccessView, core.AccessPreview, core.AccessDownload, core.AccessZip,
	core.AccessUpload, core.AccessPasswordOK, core.AccessPasswordFail, core.AccessBlocked}

// RecordAccess implements core.Shares: one share_access_log row (never
// fails the caller), last_access_at, a share.accessed event for the owner
// and, for uploads to shares with notify_owner, an e-mail to the owner.
func (svc *Service) RecordAccess(ctx context.Context, s *core.Share, a core.ShareAccess) {
	if s == nil || s.ID == "" || !slices.Contains(accessActions, a.Action) {
		return
	}
	ctx = context.WithoutCancel(ctx)
	a.ShareID = s.ID
	if a.At.IsZero() {
		a.At = svc.env.Now()
	}
	a.UserAgent = clip(a.UserAgent, 512)
	a.Uploader = clip(a.Uploader, 200)
	a.IP = clip(a.IP, 64)
	err := svc.env.DB.Tx(ctx, func(tx *sql.Tx) error {
		res, err := tx.ExecContext(ctx, `INSERT INTO share_access_log (share_id, at, action, node_id, bytes, ip, user_agent, uploader)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?)`, s.ID, db.Ms(a.At), a.Action, db.NullString(a.NodeID),
			sql.NullInt64{Int64: a.Bytes, Valid: a.Bytes > 0}, db.NullString(a.IP), db.NullString(a.UserAgent), db.NullString(a.Uploader))
		if err != nil {
			return err
		}
		a.ID, _ = res.LastInsertId()
		_, err = tx.ExecContext(ctx, `UPDATE shares SET last_access_at = ? WHERE id = ?`, db.Ms(a.At), s.ID)
		return err
	})
	if err != nil {
		if !db.IsForeignKey(err) { // the share was deleted meanwhile
			svc.log.Warn("record share access", "share", s.ID, "action", a.Action, "err", err)
		}
		return
	}
	owner := s.CreatedBy
	if svc.env.Bus != nil && owner != "" {
		pub := *s
		svc.env.Bus.Publish(events.Event{Topic: events.TopicShareAccessed, UserID: owner,
			Data: core.ShareAccessedEvent{Share: &pub, Access: a, User: owner}})
	}
	if a.Action == core.AccessUpload {
		svc.notifyUpload(ctx, s.ID, a)
	}
}

func clip(s string, n int) string {
	if len(s) <= n {
		return s
	}
	s = s[:n]
	for !utf8.ValidString(s) && len(s) > 0 {
		s = s[:len(s)-1]
	}
	return s
}

// UploadNotice is the data of the "share.upload" notification template.
type UploadNotice struct {
	ShareID   string    `json:"share_id"`
	Title     string    `json:"title"`    // share title ("" = none)
	Folder    string    `json:"folder"`   // name of the request's folder
	Uploader  string    `json:"uploader"` // "" when anonymous
	Bytes     int64     `json:"bytes"`    // bytes received in this upload
	Files     int       `json:"files,omitempty"`
	At        time.Time `json:"at"` // time of the upload
	OwnerName string    `json:"owner_name"`
	// URL is the in-app link of the request's folder, "" when
	// server.public_url is not configured (a relative path is useless in an
	// e-mail). The template shows it as "Open the folder: …".
	URL string `json:"url,omitempty"`
}

// notifyUpload e-mails the owner of a share with notify_owner after an
// upload (asynchronously; failures are logged). It respects notify.events
// ("share.upload") when that setting exists.
func (svc *Service) notifyUpload(ctx context.Context, shareID string, a core.ShareAccess) {
	if svc.notify == nil || !svc.notify.Enabled() {
		return
	}
	if svc.env.Settings != nil {
		if _, err := svc.env.Settings.Raw(settingNotifyEvents); err == nil &&
			!slices.Contains(svc.env.Settings.Strings(settingNotifyEvents), NotifyTemplate) {
			return
		}
	}
	var (
		notifyOwner            bool
		title, folder, nodeID  sql.NullString
		email, uname, dispName sql.NullString
	)
	err := svc.env.DB.QueryRow(ctx, `SELECT s.notify_owner, s.title, s.node_id, n.name, u.email, u.username, u.display_name
		FROM shares s LEFT JOIN nodes n ON n.id = s.node_id LEFT JOIN users u ON u.id = s.created_by WHERE s.id = ?`, shareID).
		Scan(&notifyOwner, &title, &nodeID, &folder, &email, &uname, &dispName)
	if err != nil || !notifyOwner || email.String == "" {
		return
	}
	// The request's own folder, not a.NodeID: a zip upload records the
	// extracted node, which may be deeper in the tree.
	data := UploadNotice{ShareID: shareID, Title: title.String, Folder: folder.String, Uploader: a.Uploader,
		Bytes: a.Bytes, Files: a.Files, At: a.At, OwnerName: dispName.String, URL: svc.folderLink(nodeID.String)}
	if data.OwnerName == "" {
		data.OwnerName = uname.String
	}
	to := []string{email.String}
	svc.bg.Add(1)
	go func() {
		defer svc.bg.Done()
		sctx, cancel := context.WithTimeout(ctx, notifyTimeout)
		defer cancel()
		if err := svc.notify.Send(sctx, to, NotifyTemplate, data); err != nil {
			svc.log.Warn("notify share owner", "share", shareID, "err", err)
		}
	}()
}
