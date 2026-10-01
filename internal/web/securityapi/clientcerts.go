package securityapi

import (
	"bytes"
	"encoding/base64"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/go-chi/chi/v5"

	"fileparcel/internal/core"
	"fileparcel/internal/ids"
	"fileparcel/internal/web/httpx"
	"fileparcel/internal/web/mw"
)

// ClientCertIssued is the response of POST /admin/client-certs and
// POST /me/client-certs. P12 (standard base64) and Password (only when the
// server generated it) are shown once; DownloadURL is a single-use link to
// the same .p12 file, valid for 10 minutes and only for the issuing user.
// It lives in core (the API contract); this alias keeps the short name.
type ClientCertIssued = core.ClientCertIssued

// Self-service limits.
const (
	selfServiceMaxDays   = 365
	selfServiceMaxActive = 25
	generatedPasswordLen = 15 // bytes of entropy → 21 base62 characters
	mimePKCS12           = "application/x-pkcs12"
	keyMTLSSelfService   = "mtls.self_service"
)

// ---------- one-time .p12 downloads ----------

const (
	p12TTL        = 10 * time.Minute
	p12MaxEntries = 64
)

type p12Entry struct {
	data     []byte
	filename string
	owner    string
	exp      time.Time
}

// p12Store keeps freshly issued PKCS#12 files for one download each. Keys
// are SHA-256 hashes of the tickets; entries are bound to the issuing
// principal and zeroed when consumed or evicted.
type p12Store struct {
	mu sync.Mutex
	m  map[string]*p12Entry
}

func newP12Store() *p12Store { return &p12Store{m: map[string]*p12Entry{}} }

func (s *p12Store) put(data []byte, filename, owner string, now time.Time) string {
	tok := ids.Token(32)
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pruneLocked(now)
	if len(s.m) >= p12MaxEntries {
		var oldestKey string
		var oldest time.Time
		for k, e := range s.m {
			if oldestKey == "" || e.exp.Before(oldest) {
				oldestKey, oldest = k, e.exp
			}
		}
		clear(s.m[oldestKey].data)
		delete(s.m, oldestKey)
	}
	s.m[string(ids.HashToken(tok))] = &p12Entry{data: append([]byte(nil), data...), filename: filename, owner: owner, exp: now.Add(p12TTL)}
	return tok
}

// take returns the entry for tok when owner matches; consume removes it.
func (s *p12Store) take(tok, owner string, now time.Time, consume bool) ([]byte, string, bool) {
	if !ids.ValidToken(tok) || len(tok) > 64 {
		return nil, "", false
	}
	key := string(ids.HashToken(tok))
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pruneLocked(now)
	e, ok := s.m[key]
	if !ok || !ids.Equal(e.owner, owner) {
		return nil, "", false
	}
	data := append([]byte(nil), e.data...)
	if consume {
		clear(e.data)
		delete(s.m, key)
	}
	return data, e.filename, true
}

func (s *p12Store) pruneLocked(now time.Time) {
	for k, e := range s.m {
		if now.After(e.exp) {
			clear(e.data)
			delete(s.m, k)
		}
	}
}

// ownerKey identifies the principal a download is bound to.
func ownerKey(p *core.Principal) string {
	if p == nil {
		return ""
	}
	if p.UserID != "" {
		return "u:" + p.UserID
	}
	return "sys:" + string(p.Via)
}

// ---------- handlers ----------

// p12Filename builds "<username>-<name>.p12" from safe characters.
func p12Filename(cc *core.ClientCert) string {
	clean := func(s string) string {
		var b strings.Builder
		for _, r := range strings.ToLower(s) {
			switch {
			case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
				b.WriteRune(r)
			case r == '-' || r == '_' || r == '.' || r == ' ':
				b.WriteByte('-')
			}
		}
		return strings.Trim(b.String(), "-.")
	}
	name := clean(cc.Username)
	if n := clean(cc.Name); n != "" {
		if name != "" {
			name += "-"
		}
		name += n
	}
	if len(name) > 80 {
		name = name[:80]
	}
	if name == "" {
		name = "client-certificate"
	}
	return name + ".p12"
}

// issue runs IssueClient and builds the one-time response.
func (a *api) issue(w http.ResponseWriter, r *http.Request, in core.ClientCertInput, downloadPath string) {
	c, err := a.certs()
	if err != nil {
		httpx.Error(w, r, err)
		return
	}
	generated := ""
	if in.Password == "" {
		generated = ids.Token(generatedPasswordLen)
		in.Password = generated
	}
	p := mw.Principal(r)
	cc, p12, err := c.IssueClient(r.Context(), p, in)
	if err != nil {
		httpx.Error(w, r, err)
		return
	}
	defer clear(p12)
	name := p12Filename(cc)
	tok := a.p12.put(p12, name, ownerKey(p), a.d.Now())
	httpx.JSON(w, http.StatusCreated, ClientCertIssued{
		ClientCert:  cc,
		P12:         base64.StdEncoding.EncodeToString(p12),
		Password:    generated,
		Filename:    name,
		DownloadURL: "/api/v1" + downloadPath + "?ticket=" + url.QueryEscape(tok),
	})
}

// resolveUser accepts a user id or a username in ClientCertInput.UserID
// (the CLI passes usernames).
func (a *api) resolveUser(r *http.Request, ref string) (string, error) {
	ref = strings.TrimSpace(ref)
	if ref == "" {
		return "", core.Invalid("user_id", "the user is required")
	}
	if ids.Valid(ids.PrefixUser, ref) || a.d.Users == nil {
		return ref, nil
	}
	u, err := a.d.Users.GetByUsername(r.Context(), ref)
	if err != nil {
		if errors.Is(err, core.ErrNotFound) {
			return "", core.NotFoundf("user %q not found", ref)
		}
		return "", err
	}
	return u.ID, nil
}

// adminClientIssue is POST /admin/client-certs (Adm, E).
func (a *api) adminClientIssue(w http.ResponseWriter, r *http.Request) {
	in, err := httpx.Decode[core.ClientCertInput](r, maxSmallBody)
	if err != nil {
		httpx.Error(w, r, err)
		return
	}
	if in.UserID, err = a.resolveUser(r, in.UserID); err != nil {
		httpx.Error(w, r, err)
		return
	}
	a.issue(w, r, in, "/admin/client-certs/download")
}

// adminClientList is GET /admin/client-certs[?user_id=].
func (a *api) adminClientList(w http.ResponseWriter, r *http.Request) {
	c, err := a.certs()
	if err != nil {
		httpx.Error(w, r, err)
		return
	}
	userID := r.URL.Query().Get("user_id")
	if userID != "" {
		if userID, err = a.resolveUser(r, userID); err != nil {
			httpx.Error(w, r, err)
			return
		}
	}
	page, err := c.ListClient(r.Context(), httpx.PageReq(r), userID)
	if err != nil {
		httpx.Error(w, r, err)
		return
	}
	httpx.JSON(w, http.StatusOK, page)
}

// adminClientRevoke is DELETE /admin/client-certs/{id}[?reason=].
func (a *api) adminClientRevoke(w http.ResponseWriter, r *http.Request) {
	a.revoke(w, r)
}

func (a *api) revoke(w http.ResponseWriter, r *http.Request) {
	c, err := a.certs()
	if err == nil {
		err = c.RevokeClient(r.Context(), mw.Principal(r), chi.URLParam(r, "id"), r.URL.Query().Get("reason"))
	}
	if err != nil {
		httpx.Error(w, r, err)
		return
	}
	httpx.NoContent(w)
}

// meUser returns the user id of the requester (socket/offline callers must
// act as a user with X-FP-As).
func meUser(r *http.Request) (string, error) {
	p := mw.Principal(r)
	if p == nil || p.UserID == "" {
		return "", core.Errorf(core.ErrInvalid, "this endpoint needs a user account (use --as USER)")
	}
	return p.UserID, nil
}

// meClientList is GET /me/client-certs.
func (a *api) meClientList(w http.ResponseWriter, r *http.Request) {
	uid, err := meUser(r)
	if err != nil {
		httpx.Error(w, r, err)
		return
	}
	c, err := a.certs()
	if err != nil {
		httpx.Error(w, r, err)
		return
	}
	page, err := c.ListClient(r.Context(), httpx.PageReq(r), uid)
	if err != nil {
		httpx.Error(w, r, err)
		return
	}
	httpx.JSON(w, http.StatusOK, page)
}

// meClientIssue is POST /me/client-certs (F; only with mtls.self_service).
func (a *api) meClientIssue(w http.ResponseWriter, r *http.Request) {
	uid, err := meUser(r)
	if err != nil {
		httpx.Error(w, r, err)
		return
	}
	if a.d.Settings == nil || !a.d.Settings.Bool(keyMTLSSelfService) {
		httpx.Error(w, r, core.Errorf(core.ErrForbidden, "self-service client certificates are disabled (mtls.self_service)"))
		return
	}
	in, err := httpx.Decode[core.ClientCertInput](r, maxSmallBody)
	if err != nil {
		httpx.Error(w, r, err)
		return
	}
	if in.UserID != "" && in.UserID != uid {
		httpx.Error(w, r, core.Invalid("user_id", "you can only issue certificates for yourself"))
		return
	}
	in.UserID = uid
	if in.Days > selfServiceMaxDays {
		httpx.Error(w, r, core.Invalid("days", "self-service certificates are valid for at most 365 days"))
		return
	}
	if n, err := a.activeCount(r, uid); err != nil {
		httpx.Error(w, r, err)
		return
	} else if n >= selfServiceMaxActive {
		httpx.Error(w, r, core.Errorf(core.ErrConflict, "you already have %d active client certificates; revoke unused ones first", n))
		return
	}
	a.issue(w, r, in, "/me/client-certs/download")
}

// activeCount counts the user's unrevoked, unexpired client certificates.
func (a *api) activeCount(r *http.Request, uid string) (int, error) {
	c, err := a.certs()
	if err != nil {
		return 0, err
	}
	now := a.d.Now()
	n, cursor := 0, ""
	for range 10 {
		page, err := c.ListClient(r.Context(), core.PageReq{Cursor: cursor, Limit: 500}, uid)
		if err != nil {
			return 0, err
		}
		for _, cc := range page.Items {
			if cc.RevokedAt == nil && now.Before(cc.NotAfter) {
				n++
			}
		}
		if page.NextCursor == "" {
			break
		}
		cursor = page.NextCursor
	}
	return n, nil
}

// meClientRevoke is DELETE /me/client-certs/{id}: own certificates only —
// also for admins and holders of certs.manage, whose principal is narrowed
// (no certs.manage, not an administrator) so that Certs.RevokeClient applies
// the ownership check.
func (a *api) meClientRevoke(w http.ResponseWriter, r *http.Request) {
	if _, err := meUser(r); err != nil {
		httpx.Error(w, r, err)
		return
	}
	by := mw.Principal(r).Clone()
	by.Role, by.RoleID = core.RoleMember, string(core.RoleMember)
	by.SetCaps(mw.Principal(r).RoleCaps().Without(core.CapCertsManage))
	c, err := a.certs()
	if err == nil {
		err = c.RevokeClient(r.Context(), by, chi.URLParam(r, "id"), r.URL.Query().Get("reason"))
	}
	if err != nil {
		httpx.Error(w, r, err)
		return
	}
	httpx.NoContent(w)
}

// clientDownload is GET /admin|me/client-certs/download?ticket=: the
// single-use .p12 download of a fresh issuance (HEAD does not consume it).
func (a *api) clientDownload(w http.ResponseWriter, r *http.Request) {
	consume := r.Method != http.MethodHead
	data, name, ok := a.p12.take(r.URL.Query().Get("ticket"), ownerKey(mw.Principal(r)), a.d.Now(), consume)
	if !ok {
		httpx.Error(w, r, core.NotFoundf("the download link is invalid, expired or was already used"))
		return
	}
	defer clear(data)
	h := w.Header()
	h.Set("Content-Type", mimePKCS12)
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Cache-Control", "no-store")
	httpx.Attachment(w, name, false)
	http.ServeContent(w, r, name, time.Time{}, bytes.NewReader(data))
}
