// Package pages renders the server-side HTML shells (html/template over
// webassets.FS templates/) and owns the root page routes (DESIGN §9.4
// pages/static): the "/" redirect, the SPA shell routes, the public pages
// (/login, /setup, /unlock, /trust, /invite/{token}), the generated root
// files (/theme.css, /sw.js, /manifest.webmanifest, /favicon.ico,
// /robots.txt, /.well-known/security.txt) and the health checks (/healthz,
// /readyz).
//
// Templates: web/templates/<page>.html, executed with PageData. Files named
// web/templates/_*.html and web/templates/partials/*.html are parsed into
// every page (for {{template "name" .}} partials). Template funcs:
// asset "path" → "/static/<hash>/path".
//
// The page's boot data (Boot) is emitted by the templates as
// <script type="application/json" id="fp-boot">{{.Boot}}</script>;
// html/template JSON-encodes it in that context and escapes "<", ">", "&",
// U+2028 and U+2029, so user-controlled strings (display names, share
// titles) can never terminate the script element.
//
// Owned by unit I. Render (DESIGN §9.4: pages.Render(w, r, "share", data)),
// RenderTitled, RenderStatus and NotFound are used by other web packages
// (e.g. sharesapi renders the "share" page). They take the services from the
// request context (mw.Deps), so they only work behind the root router (they
// degrade to safe defaults without it).
package pages

import (
	"bytes"
	"encoding/json"
	"errors"
	"html/template"
	"io/fs"
	"log/slog"
	"net/http"
	"regexp"
	"strings"
	"sync"

	webassets "fileparcel/web"

	"fileparcel/internal/app"
	"fileparcel/internal/core"
	"fileparcel/internal/web/httpx"
	"fileparcel/internal/web/mw"
	"fileparcel/internal/web/static"
)

// PageData is the data passed to every page template.
type PageData struct {
	Title    string // page title without the instance name (may be empty)
	Page     string // page id (template name), e.g. "login", "app"
	Instance string // ui.instance_name
	Asset    string // "/static/<hash>" (no trailing slash)
	Theme    string // "light" | "dark" | "system"
	Lang     string // BCP 47, e.g. "en"
	Boot     any    // Boot, JSON-encoded by html/template inside <script type="application/json" id="fp-boot">
	// PublicOnly marks a page served to an internet visitor over Tailscale
	// Funnel "shares" mode: the template leaves out everything that leads
	// into the app (sign-in links, navigation). NewPageData sets it from
	// publicOnly (features_ingress.go).
	PublicOnly bool
}

// Boot is the #fp-boot JSON object read by web/static/js/core/dom.js boot().
type Boot struct {
	AssetBase string          `json:"asset_base"`
	Instance  string          `json:"instance"`
	CSRF      string          `json:"csrf"`
	User      *BootUser       `json:"user"`
	KeysState core.KeyState   `json:"keys_state"`
	Features  map[string]bool `json:"features"`
	RPID      string          `json:"rp_id"`
	Version   string          `json:"version"`
	Page      string          `json:"page"`
	UI        BootUI          `json:"ui"`
	Data      any             `json:"data"`
	// Limits are numeric limits the forms need before the first API call
	// (e.g. zip_password_min); always an object.
	Limits map[string]int64 `json:"limits"`
	// Ingress is the Tailscale ingress the page was requested through
	// (core.IngressFunnel or core.IngressServe; omitted for a direct connection).
	Ingress string `json:"ingress,omitempty"`
}

// BootUser is the user object embedded in Boot (nil for anonymous visitors).
// While MFAPending it carries only the id, the username and the flags: the
// profile, the role and its permissions stay withheld until the second
// factor, as in GET /me.
type BootUser struct {
	ID          string    `json:"id"`
	Username    string    `json:"username"`
	DisplayName string    `json:"display_name,omitempty"`
	Email       string    `json:"email,omitempty"`
	Role        core.Role `json:"role,omitempty"` // the built-in base role
	// RoleID is the role: owner|admin|member|guest|rol_… (DESIGN §6a).
	RoleID   string `json:"role_id,omitempty"`
	RoleName string `json:"role_name,omitempty"`
	// Permissions is what the role allows (catalog names; [] when nothing).
	Permissions *core.CapSet `json:"permissions,omitempty"`
	// Staff reports whether the session can use a server permission
	// (Principal.ServerAccess, like core.Me.Staff).
	Staff bool `json:"staff,omitempty"`
	// SpaceID is the personal space ("" for guest-based roles).
	SpaceID            string          `json:"space_id,omitempty"`
	MustChangePassword bool            `json:"must_change_password,omitempty"`
	MFAPending         bool            `json:"mfa_pending,omitempty"`     // password ok, second factor pending
	EnrollRequired     bool            `json:"enroll_required,omitempty"` // 2FA policy requires enrollment
	Prefs              json.RawMessage `json:"prefs,omitempty"`
}

// BootUI carries the general (ui.*) settings the shells need before the
// first API call.
type BootUI struct {
	DefaultTheme string `json:"default_theme"` // light | dark | system
	DefaultView  string `json:"default_view"`  // list | grid
}

var (
	tmplMu    sync.Mutex
	tmplCache = map[string]*template.Template{}
)

var pageNameRe = regexp.MustCompile(`^[a-z][a-z0-9_-]{0,63}$`)

// templatesFS is the template source (tests replace it).
var templatesFS fs.FS = webassets.FS

func loadTemplate(page string) (*template.Template, error) {
	if !pageNameRe.MatchString(page) {
		return nil, errors.New("pages: invalid page name")
	}
	tmplMu.Lock()
	defer tmplMu.Unlock()
	if t, ok := tmplCache[page]; ok {
		return t, nil
	}
	src, err := fs.ReadFile(templatesFS, "templates/"+page+".html")
	if err != nil {
		return nil, err
	}
	t := template.New(page).Funcs(template.FuncMap{"asset": static.Asset})
	if _, err := t.Parse(string(src)); err != nil {
		return nil, err
	}
	for _, pattern := range []string{"templates/_*.html", "templates/partials/*.html"} {
		matches, _ := fs.Glob(templatesFS, pattern)
		for _, m := range matches {
			b, err := fs.ReadFile(templatesFS, m)
			if err != nil {
				return nil, err
			}
			name := strings.TrimSuffix(m[strings.LastIndexByte(m, '/')+1:], ".html")
			if _, err := t.New(name).Parse(string(b)); err != nil {
				return nil, err
			}
		}
	}
	tmplCache[page] = t
	return t, nil
}

// resetTemplates clears the template cache (tests).
func resetTemplates() {
	tmplMu.Lock()
	defer tmplMu.Unlock()
	clear(tmplCache)
}

// DefaultTitles are the page titles used by Render (without the instance name).
var DefaultTitles = map[string]string{
	"login":  "Sign in",
	"setup":  "Set up",
	"unlock": "Unlock",
	"trust":  "Trust this server",
	"invite": "Invitation",
	"share":  "Shared files",
	"error":  "Error",
}

// Render executes web/templates/<page>.html with status 200 and the default
// title of the page (DefaultTitles). data becomes Boot.data ({} when nil).
// If the template is missing or fails, a plain-text 500 is written.
func Render(w http.ResponseWriter, r *http.Request, page string, data any) {
	RenderStatus(w, r, http.StatusOK, page, DefaultTitles[page], data)
}

// RenderTitled is Render with an explicit title (e.g. the share's title).
func RenderTitled(w http.ResponseWriter, r *http.Request, page, title string, data any) {
	RenderStatus(w, r, http.StatusOK, page, title, data)
}

// RenderStatus is RenderTitled with an explicit HTTP status. The response
// is never cached (it may carry a CSRF token) and is marked noindex; an
// X-Robots-Tag already set by an outer middleware is kept (the public share
// group adds noarchive in sharesapi.publicHeaders).
func RenderStatus(w http.ResponseWriter, r *http.Request, status int, page, title string, data any) {
	d := mw.Deps(r)
	t, err := loadTemplate(page)
	if err != nil {
		logger(d).Error("pages: template unavailable", "page", page, "err", err)
		plainError(w, http.StatusInternalServerError, "500 internal error: page unavailable")
		return
	}
	pd := NewPageData(r, page, title, data)
	var buf bytes.Buffer
	if err := t.Execute(&buf, pd); err != nil {
		logger(d).Error("pages: render failed", "page", page, "err", err)
		plainError(w, http.StatusInternalServerError, "500 internal error: page failed to render")
		return
	}
	h := w.Header()
	h.Set("Content-Type", "text/html; charset=utf-8")
	h.Set("Cache-Control", mw.CacheNoStore)
	if h.Get("X-Robots-Tag") == "" { // keep a stricter outer value (public shares add noarchive)
		h.Set("X-Robots-Tag", "noindex, nofollow")
	}
	h.Del("Content-Length")
	w.WriteHeader(status)
	_, _ = w.Write(buf.Bytes())
}

// NotFound renders the generic "error" page with 404 (used for unknown pages
// and invalid share/invite tokens — the same page every time, no oracle).
func NotFound(w http.ResponseWriter, r *http.Request) {
	RenderError(w, r, http.StatusNotFound, core.ErrNotFound.Code, "This page does not exist or is no longer available.")
}

// MaintenanceNotice renders the maintenance notice (DESIGN §20): the generic
// error page with 503 and the operator's maintenance.message. It is the
// handler mw.Maintenance shows for page navigations — the gate lives in mw,
// which cannot import this package, so web/router.go passes it in.
func MaintenanceNotice(w http.ResponseWriter, r *http.Request) {
	RenderError(w, r, http.StatusServiceUnavailable, "maintenance", mw.MaintenanceMessage(mw.Deps(r)))
}

// RenderError renders the generic "error" page with status, a machine code
// and a message safe to show (boot data {status, code, message, request_id}).
func RenderError(w http.ResponseWriter, r *http.Request, status int, code, message string) {
	title := http.StatusText(status)
	if title == "" {
		title = "Error"
	}
	RenderStatus(w, r, status, "error", title, map[string]any{
		"status": status, "code": code, "message": message, "request_id": httpx.RequestID(r.Context()),
	})
}

func plainError(w http.ResponseWriter, status int, msg string) {
	h := w.Header()
	h.Set("Content-Type", "text/plain; charset=utf-8")
	h.Set("Cache-Control", mw.CacheNoStore)
	h.Del("Content-Length")
	w.WriteHeader(status)
	_, _ = w.Write([]byte(msg + "\n"))
}

func logger(d *app.Deps) *slog.Logger {
	if hasEnv(d) && d.Log != nil {
		return d.Log
	}
	return slog.Default()
}

func hasEnv(d *app.Deps) bool { return d != nil && d.Env != nil }

// NewPageData builds the template data (and Boot) for a request; the
// services come from the request context (mw.Deps). extra becomes
// Boot.data ({} when nil).
func NewPageData(r *http.Request, page, title string, extra any) PageData {
	d := mw.Deps(r)
	p := mw.Principal(r)
	inst := instanceName(d)
	b := Boot{
		AssetBase: static.AssetBase(),
		Instance:  inst,
		KeysState: keysState(d),
		RPID:      rpID(d),
		Page:      page,
		UI:        BootUI{DefaultTheme: defaultTheme(d), DefaultView: enumSetting(d, KeyDefaultView, "list", "list", "grid")},
		Data:      extra,
	}
	if hasEnv(d) {
		b.Version = d.Build.Version
	}
	if b.Data == nil {
		b.Data = map[string]any{}
	}
	theme := b.UI.DefaultTheme
	if p != nil && p.UserID != "" {
		bu := bootUser(r, d, p)
		b.User = bu
		if t := prefTheme(bu.Prefs); t != "" {
			theme = t
		}
		if hasEnv(d) && d.Auth != nil && p.Via == core.ViaSession {
			b.CSRF = d.Auth.CSRFToken(p)
		}
	}
	// The same principal as the boot user's role and permissions (bootUser).
	b.Features = Features(d, p)
	b.Limits = bootLimits(d)
	if in := core.IngressFrom(r.Context()); in != nil {
		b.Ingress = in.Kind
	}
	return PageData{Title: title, Page: page, Instance: inst, Asset: static.AssetBase(), Theme: theme, Lang: "en", Boot: b,
		PublicOnly: publicOnly(d, r)}
}

// bootUser describes the principal, enriched from Users.Get when available.
// The role and its permissions come from the principal (auth resolves them
// from the row that authenticated this request), so the boot user always
// agrees with the feature flags; the profile comes from the account.
func bootUser(r *http.Request, d *app.Deps, p *core.Principal) *BootUser {
	bu := &BootUser{ID: p.UserID, Username: p.Username,
		MFAPending: p.AuthLevel < core.AuthLevelFull, EnrollRequired: p.EnrollRequired}
	if bu.MFAPending {
		// A password-only session gets no profile: the login page needs none,
		// and neither the role (nor the role-derived feature flags) nor the
		// address may leak before the second factor (see the same rule in
		// internal/web/meapi).
		return bu
	}
	caps := p.RoleCaps()
	bu.Role, bu.RoleID, bu.RoleName = p.Role, p.RoleID, p.RoleName
	if bu.RoleID == "" { // a principal built without its role id: a built-in role
		bu.RoleID = string(p.Role)
	}
	if bu.RoleName == "" && !core.IsCustomRoleID(bu.RoleID) {
		bu.RoleName = core.BuiltinRoleName(p.Role)
	}
	bu.Permissions, bu.Staff = &caps, p.ServerAccess()
	if hasEnv(d) && d.Users != nil {
		if u, err := d.Users.Get(r.Context(), p.UserID); err == nil && u != nil {
			bu.Username, bu.DisplayName, bu.Email = u.Username, u.DisplayName, u.Email
			bu.MustChangePassword = u.MustChangePassword
			bu.SpaceID = u.SpaceID
			if len(u.Prefs) > 0 && json.Valid(u.Prefs) {
				bu.Prefs = u.Prefs
			}
		}
	}
	return bu
}

// prefTheme returns the "theme" of a user's prefs object when valid.
func prefTheme(prefs json.RawMessage) string {
	if len(prefs) == 0 {
		return ""
	}
	var p struct {
		Theme string `json:"theme"`
	}
	if json.Unmarshal(prefs, &p) != nil {
		return ""
	}
	switch p.Theme {
	case "light", "dark", "system":
		return p.Theme
	}
	return ""
}

func instanceName(d *app.Deps) string {
	if hasEnv(d) && d.Settings != nil {
		if s := strings.TrimSpace(d.Settings.String(KeyInstanceName)); s != "" && validateInstanceName(s) == nil {
			return s
		}
	}
	return DefaultInstanceName
}

func keysState(d *app.Deps) core.KeyState {
	if hasEnv(d) && d.Keys != nil {
		return d.Keys.State()
	}
	return core.KeyStateUninitialized
}

// boolSetting reads a bool setting; def when the key is not registered.
func boolSetting(d *app.Deps, key string, def bool) bool {
	if !hasEnv(d) || d.Settings == nil {
		return def
	}
	if _, err := d.Settings.Raw(key); err != nil {
		return def
	}
	return d.Settings.Bool(key)
}

// intSetting reads an integer setting; def when the key is not registered
// (shared by the feature files, e.g. storage.zip_password_min for bootLimits).
func intSetting(d *app.Deps, key string, def int64) int64 {
	if !hasEnv(d) || d.Settings == nil {
		return def
	}
	if _, err := d.Settings.Raw(key); err != nil {
		return def
	}
	return d.Settings.Int(key)
}

// enumSetting reads a string setting restricted to allowed values (def otherwise).
func enumSetting(d *app.Deps, key, def string, allowed ...string) string {
	if !hasEnv(d) || d.Settings == nil {
		return def
	}
	v := d.Settings.String(key)
	for _, a := range allowed {
		if v == a {
			return v
		}
	}
	return def
}

func defaultTheme(d *app.Deps) string {
	return enumSetting(d, KeyDefaultTheme, "system", "light", "dark", "system")
}

// rpID is the WebAuthn relying-party ID the page is told to use. It must be
// normalised exactly as auth.Service.rpConfig and authapi.RPID normalise it
// (lower case, no trailing root dot): the client compares it against
// location.hostname, which a browser always lower-cases, so a mixed-case
// auth.webauthn_rp_id would switch the whole passkey UI off at an address
// that in fact matches.
func rpID(d *app.Deps) string {
	if hasEnv(d) && d.Settings != nil {
		if s := strings.TrimSpace(d.Settings.String("auth.webauthn_rp_id")); s != "" {
			return normalizeRPID(s)
		}
	}
	if d != nil && d.MDNS != nil {
		if n := d.MDNS.Name(); n != "" {
			return normalizeRPID(n)
		}
	}
	name := "fileparcel"
	if hasEnv(d) && d.Config != nil && d.Config.Server.Name != "" {
		name = d.Config.Server.Name
	}
	return normalizeRPID(name) + ".local"
}

// normalizeRPID lower-cases a host name and drops a trailing root dot.
func normalizeRPID(s string) string {
	return strings.ToLower(strings.TrimSuffix(strings.TrimSpace(s), "."))
}
