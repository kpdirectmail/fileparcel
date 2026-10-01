package mw

import (
	"errors"
	"net/http"
	"strings"
	"unicode"
	"unicode/utf8"

	"fileparcel/internal/app"
	"fileparcel/internal/core"
	"fileparcel/internal/settings"
	"fileparcel/internal/web/httpx"
)

// Setting keys of maintenance mode (DESIGN §11.2, section "general"). They
// are registered here, next to the gate that enforces them, so the two can
// never drift apart; `fileparcel maintenance on|off|status` (§12) reads and
// writes exactly these keys.
const (
	KeyMaintenanceEnabled = "maintenance.enabled"
	KeyMaintenanceMessage = "maintenance.message"
)

// MaxMaintenanceMessage bounds maintenance.message.
const MaxMaintenanceMessage = 2000

// DefaultMaintenanceMessage is shown when maintenance.message is empty.
const DefaultMaintenanceMessage = "The server is down for maintenance. Please try again shortly."

func init() {
	settings.Register(settings.Def{Key: KeyMaintenanceEnabled, Section: "general", Order: 60, Type: settings.TypeBool,
		Default: false, Label: "Maintenance mode",
		Description: "Keep users out while you work on the server: the web UI shows a notice and requests for " +
			"files, shares and uploads are answered with 503. Administrators (and roles allowed to operate the " +
			"server), this server's own CLI, signing in and every user's own account settings (profile, password, " +
			"two-factor, sessions, tokens) keep working; invitations cannot be accepted until it is switched off again."})
	settings.Register(settings.Def{Key: KeyMaintenanceMessage, Section: "general", Order: 70, Type: settings.TypeString,
		Default: "", Label: "Maintenance notice",
		Description: "Text shown while maintenance mode is on (plain text; a default is used when empty).",
		Validate:    validateMaintenanceMessage})
}

func validateMaintenanceMessage(v any) error {
	s, _ := v.(string)
	switch {
	case utf8.RuneCountInString(s) > MaxMaintenanceMessage:
		return errors.New("must be at most 2000 characters")
	case strings.IndexFunc(s, func(r rune) bool { return unicode.IsControl(r) && r != '\n' && r != '\r' && r != '\t' }) >= 0:
		return errors.New("must not contain control characters")
	}
	return nil
}

// maintenanceExact lists the paths that stay reachable while maintenance mode
// is on (DESIGN §20): health checks, the sign-in and unlock pages and the
// small root files those pages load.
var maintenanceExact = map[string]bool{
	"/healthz": true, "/readyz": true,
	"/login": true, "/unlock": true,
	"/favicon.ico": true, "/robots.txt": true, "/sw.js": true,
	"/manifest.webmanifest": true, "/theme.css": true, "/.well-known/security.txt": true,
}

// maintenanceTrees lists the subtrees that stay reachable (the path itself and
// everything under it): the static assets, the CA downloads, the admin SPA and
// the API groups an administrator — and the sign-in flow — needs. They are
// open to everyone, so signed-in members keep their own account routes
// (/api/v1/me*: profile, password, 2FA, sessions, tokens) too.
//
// /settings is the visitor's own account UI (profile, security, sessions,
// tokens; DESIGN §13.2) and talks only to /api/v1/me*, which is open anyway.
// It has to stay reachable because that is where the SPA sends an
// administrator who still has to enrol a second factor
// (403 mfa_enroll_required → /settings/security?enroll=1) — without it an
// unenrolled owner could not reach the admin UI to turn maintenance off.
var maintenanceTrees = []string{
	"/static", "/trust", "/admin", "/settings",
	"/api/v1/auth", "/api/v1/me", "/api/v1/system", "/api/v1/admin",
}

// maintenanceClosed lists subtrees of maintenanceTrees that stay closed:
// accepting an invitation creates an account, which is what maintenance mode
// keeps out (the /invite/{token} page is closed as well).
var maintenanceClosed = []string{"/api/v1/auth/invite"}

// MaintenanceAllowed reports whether path is reachable while maintenance mode
// is on, for anyone, administrator or not.
func MaintenanceAllowed(path string) bool {
	if maintenanceExact[path] {
		return true
	}
	for _, p := range maintenanceClosed {
		if inTree(path, p) {
			return false
		}
	}
	for _, p := range maintenanceTrees {
		if inTree(path, p) {
			return true
		}
	}
	return false
}

// inTree reports whether path is tree or lies under it. Whole path segments
// only: "/adminish" is not the admin SPA.
func inTree(path, tree string) bool {
	return path == tree || strings.HasPrefix(path, tree+"/")
}

// MaintenanceOn reports whether maintenance.enabled is set.
func MaintenanceOn(d *app.Deps) bool {
	return hasEnv(d) && d.Settings != nil && d.Settings.Bool(KeyMaintenanceEnabled)
}

// MaintenanceMessage returns the configured notice, or the default when it is
// empty.
func MaintenanceMessage(d *app.Deps) string {
	if hasEnv(d) && d.Settings != nil {
		if m := strings.TrimSpace(d.Settings.String(KeyMaintenanceMessage)); m != "" {
			return m
		}
	}
	return DefaultMaintenanceMessage
}

// Maintenance gates the server while maintenance.enabled is on (DESIGN §20):
// API requests (isAPIPath, which includes the public share JSON routes
// /s/{token}/api…) get 503 unavailable with Retry-After and the notice text
// as message, page navigations get notice (a 503 page rendered by the pages
// package — mw must not import it, so the handler is passed in). Everything
// on MaintenanceAllowed passes, and so do administrators, holders of
// system.manage and trusted in-process callers (the admin socket and the
// offline CLI, which is how maintenance mode is switched off again).
//
// The gate sits in the root chain, before authentication, so it resolves the
// principal itself — but only while maintenance is on, which costs nothing in
// the normal state.
func Maintenance(notice http.Handler) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			d := Deps(r)
			if !MaintenanceOn(d) || MaintenanceAllowed(r.URL.Path) || trusted(r) || maintenanceAdmin(r, d) {
				next.ServeHTTP(w, r)
				return
			}
			w.Header().Set("Retry-After", "300")
			if isAPIPath(r.URL.Path) || notice == nil {
				httpx.Error(w, r, core.Wrap(core.ErrUnavailable, MaintenanceMessage(d), nil))
				return
			}
			notice.ServeHTTP(w, r)
		})
	}
}

// maintenanceAdmin reports whether the request carries the credentials of
// an administrator or of a role holding system.manage ("Operate the
// server": it switches maintenance mode and keeps working during it) at full
// authentication level. A principal already in the context (in-process
// callers) wins; otherwise the session cookie or Bearer token is resolved
// the way Authenticate does. A failure simply means "not an administrator"
// — this gate never answers 401, that is Authenticate's job.
//
// The resolved principal is deliberately NOT stored in the request context:
// Authenticate treats a principal it finds there as in-process and therefore
// trusted, and honours the X-FP-As header for it. Putting a
// network-authenticated principal there would hand every signed-in user the
// ability to act as anyone else.
func maintenanceAdmin(r *http.Request, d *app.Deps) bool {
	if p := core.PrincipalFrom(r.Context()); p != nil {
		return p.IsAdmin() || p.Can(core.CapSystemManage)
	}
	if !hasEnv(d) || d.Auth == nil {
		return false
	}
	// Nothing to resolve without credentials — and no lookup for the flood of
	// anonymous requests that maintenance mode is there to turn away.
	if r.Header.Get("Authorization") == "" && r.Header.Get("Cookie") == "" {
		return false
	}
	p, err := d.Auth.Authenticate(r)
	return err == nil && (p.IsAdmin() || p.Can(core.CapSystemManage)) && p.AuthLevel == core.AuthLevelFull
}
