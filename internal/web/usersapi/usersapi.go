// Package usersapi owns /api/v1/admin/users*, /admin/invites*, /admin/groups*,
// /admin/roles*, /admin/capabilities, /groups, /users/lookup, /roles and
// /activity (DESIGN §9.4, unit C). Guards: Cap(x) = mw.RequireCap(x) (full
// authentication and the permission x; owners and admins hold every
// permission; API tokens need the admin scope for these server permissions),
// Adm = mw.RequireAdmin (built-in owners and admins), E = elevated, F = full:
//
//	GET               /admin/users                       Cap(users.view)
//	POST              /admin/users                       Cap(users.manage) (a staff role: E)
//	GET               /admin/users/{id}                  Cap(users.view)
//	PATCH             /admin/users/{id}                  Cap(users.manage) (a role change, a new own e-mail: E)
//	DELETE            /admin/users/{id}                  Cap(users.manage), E
//	GET               /admin/users/{id}/access           Cap(users.view)
//	POST              /admin/users/{id}/password         Cap(users.credentials), E
//	POST              /admin/users/{id}/unlock           Cap(users.manage)
//	POST              /admin/users/{id}/reset-mfa        Cap(users.credentials), E
//	POST              /admin/users/{id}/disable|enable   Cap(users.manage)
//	GET/DELETE        /admin/users/{id}/sessions         Cap(users.credentials)
//	GET/DELETE        /admin/invites[/{id}]              Cap(invites.manage) (url of staff invites in GET: E)
//	POST              /admin/invites                     Cap(invites.manage) (a staff invite: E)
//	GET               /admin/groups[/{id}]               Cap(users.view)
//	POST/PATCH/DELETE /admin/groups[/{id}]               Cap(groups.manage)
//	GET               /admin/groups/{id}/members         Cap(users.view)
//	PUT               /admin/groups/{id}/members/{userId} {role}  Cap(groups.manage)
//	DELETE            /admin/groups/{id}/members/{userId}         Cap(groups.manage)
//	GET               /admin/roles[/{id}]                Cap(users.view)
//	POST              /admin/roles                       Adm, E
//	PATCH/DELETE      /admin/roles/{id}                  Adm, E
//	GET               /admin/roles/{id}/groups           Cap(users.view)
//	PUT/DELETE        /admin/roles/{id}/groups/{groupId} Cap(groups.manage)
//	GET               /admin/capabilities                Cap(users.view)
//	GET               /groups                            (F) my groups
//	GET               /users/lookup?q=                   (F) min 2 chars; id, username, display_name
//	GET               /roles                             (F) custom roles for the pickers
//	GET               /activity                          (F) own audit events
//
// The route guard only admits the kind of action; which accounts a caller
// may act on and which roles it may give is decided by the services
// (core.CheckManage, core.CheckAssign: only owners touch owners, and a
// delegate — a non-admin holding one of these permissions — only accounts
// and roles its own role covers; DESIGN §6a). A staff role is owner, admin
// or a custom role with a server permission: giving one (create, invite) and
// every role change need step-up, like the link of a staff invitation.
// Creating, editing and deleting roles stays with built-in owners and
// admins; the users service audits every role change and announces it with
// authz.changed after commit.
//
// Bodies: POST /admin/users core.NewUser → 201 core.UserCreated; PATCH
// /admin/users/{id} core.UserUpdate → core.User; DELETE /admin/users/{id}
// takes ?transfer_to=<user id>; GET …/access → core.UserAccess; POST
// …/password core.PasswordResetInput → core.PasswordReset; POST
// /admin/invites core.InviteInput → 201 core.InviteCreated; POST/PATCH
// /admin/groups core.GroupInput → core.Group; PUT …/members/{userId}
// core.RoleInput → 204; GET /admin/roles/{id} → core.RoleDef (built-in
// words work); POST /admin/roles core.RoleDefInput → 201 core.RoleDef; PATCH
// /admin/roles/{id} core.RoleDefUpdate → core.RoleDef; DELETE
// /admin/roles/{id} takes ?reassign_to=<member|guest|rol_…> → 204; PUT
// /admin/roles/{id}/groups/{groupId} core.RoleGroupInput → core.RoleGroup;
// GET /admin/capabilities → core.CapabilityCatalog. Lists are core.Page
// values ({"items":[…],"next_cursor":"…"}; the roles, role groups and /roles
// lists have no cursor); GET /admin/users accepts
// ?q=&role=<base>&role_id=<built-in word or rol_…>&status=
// &sort=username|created|last_login&desc=; POST /admin/users, PATCH
// /admin/users/{id} and POST /admin/invites take role_id next to role (role
// is the base); GET /activity
// accepts ?action=&outcome=&since=&until= (RFC 3339)&target_type=&target_id=
// &sort=newest|oldest.
//
// Generated passwords (generate_password / generate) are 22 random base62
// characters (auth.password_min when that is longer; they pass the password
// policy for the account like a typed one), returned once, and force a
// password change at the next login: until then the session is limited to
// /me* (Principal.MustChangePassword, mw.RequireFull).
// The credential routes (password, MFA reset, and both verbs of …/sessions —
// listing an owner's sessions exposes their addresses and step-up window)
// check core.CheckManage with users.credentials before they act: only owners
// act on owner accounts, and a refused escalation is audited as denied — the
// auth service enforces the same rule.
package usersapi

import (
	"errors"
	"net/http"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/go-chi/chi/v5"

	"fileparcel/internal/app"
	"fileparcel/internal/core"
	"fileparcel/internal/ids"
	"fileparcel/internal/notify"
	"fileparcel/internal/web/httpx"
	"fileparcel/internal/web/mw"
)

// generatedPasswordBytes is the entropy of generated passwords (22 base62 chars).
const generatedPasswordBytes = 16

// Mount registers this package's routes on the /api/v1 router, grouped by
// the permission they need (chi allows one path pattern in several groups
// with different methods).
func Mount(api chi.Router, d *app.Deps) {
	h := &handlers{d: d}
	api.Group(func(r chi.Router) {
		r.Use(mw.RequireCap(core.CapUsersView), mw.NoStore)
		r.Get("/admin/users", h.listUsers)
		r.Get("/admin/users/{id}", h.getUser)
		r.Get("/admin/users/{id}/access", h.userAccess)
		r.Get("/admin/groups", h.listGroups)
		r.Get("/admin/groups/{id}", h.getGroup)
		r.Get("/admin/groups/{id}/members", h.listMembers)
		r.Get("/admin/roles", h.listRoles)
		r.Get("/admin/roles/{id}", h.getRole)
		r.Get("/admin/roles/{id}/groups", h.roleGroups)
		r.Get("/admin/capabilities", h.capabilities)
	})
	api.Group(func(r chi.Router) {
		r.Use(mw.RequireCap(core.CapUsersManage), mw.NoStore)
		r.Post("/admin/users", h.createUser)
		r.Patch("/admin/users/{id}", h.updateUser)
		r.Post("/admin/users/{id}/unlock", h.unlockUser)
		r.Post("/admin/users/{id}/disable", h.setStatus(core.UserDisabled))
		r.Post("/admin/users/{id}/enable", h.setStatus(core.UserActive))
		r.With(mw.RequireElevated).Delete("/admin/users/{id}", h.deleteUser)
	})
	api.Group(func(r chi.Router) {
		r.Use(mw.RequireCap(core.CapUsersCredentials), mw.NoStore)
		r.Get("/admin/users/{id}/sessions", h.listSessions)
		r.Delete("/admin/users/{id}/sessions", h.revokeSessions)
		r.Group(func(r chi.Router) {
			r.Use(mw.RequireElevated)
			r.Post("/admin/users/{id}/password", h.setPassword)
			r.Post("/admin/users/{id}/reset-mfa", h.resetMFA)
		})
	})
	api.Group(func(r chi.Router) {
		r.Use(mw.RequireCap(core.CapInvitesManage), mw.NoStore)
		r.Get("/admin/invites", h.listInvites)
		r.Post("/admin/invites", h.createInvite)
		r.Delete("/admin/invites/{id}", h.revokeInvite)
	})
	api.Group(func(r chi.Router) {
		r.Use(mw.RequireCap(core.CapGroupsManage), mw.NoStore)
		r.Post("/admin/groups", h.createGroup)
		r.Patch("/admin/groups/{id}", h.updateGroup)
		r.Delete("/admin/groups/{id}", h.deleteGroup)
		r.Put("/admin/groups/{id}/members/{userId}", h.setMember)
		r.Delete("/admin/groups/{id}/members/{userId}", h.removeMember)
		r.Put("/admin/roles/{id}/groups/{groupId}", h.setRoleGroup)
		r.Delete("/admin/roles/{id}/groups/{groupId}", h.removeRoleGroup)
	})
	// Whoever edits roles can grant anything: built-in owners and admins
	// only, with step-up (never delegable).
	api.Group(func(r chi.Router) {
		r.Use(mw.RequireAdmin, mw.RequireElevated, mw.NoStore)
		r.Post("/admin/roles", h.createRole)
		r.Patch("/admin/roles/{id}", h.updateRole)
		r.Delete("/admin/roles/{id}", h.deleteRole)
	})
	api.Group(func(r chi.Router) {
		r.Use(mw.RequireFull)
		r.Get("/groups", h.myGroups)
		r.Get("/users/lookup", h.lookup)
		r.Get("/roles", h.lookupRoles)
		r.Get("/activity", h.activity)
	})
}

type handlers struct{ d *app.Deps }

// deps returns the services (the injected ones win, for in-process callers).
func (h *handlers) deps(r *http.Request) *app.Deps {
	if d := mw.Deps(r); d != nil && d.Env != nil {
		return d
	}
	return h.d
}

func (h *handlers) now(r *http.Request) time.Time {
	if d := h.deps(r); d != nil && d.Env != nil {
		return d.Now()
	}
	return time.Now()
}

// users returns the users service or an error.
func (h *handlers) users(r *http.Request) (core.Users, error) {
	d := h.deps(r)
	if d == nil || d.Users == nil {
		return nil, core.Errorf(core.ErrUnavailable, "user management is unavailable")
	}
	return d.Users, nil
}

func (h *handlers) auth(r *http.Request) (core.Auth, error) {
	d := h.deps(r)
	if d == nil || d.Auth == nil {
		return nil, core.Errorf(core.ErrUnavailable, "authentication service unavailable")
	}
	return d.Auth, nil
}

// requireElevated fails unless the principal's step-up window is open.
func (h *handlers) requireElevated(r *http.Request) error {
	if p := mw.Principal(r); p == nil || !p.Elevated(h.now(r)) {
		return core.ErrElevationRequired
	}
	return nil
}

// staffRole reports whether the role a request names — roleID (a built-in
// word or "rol_…"), else the built-in role — is a staff role: owner, admin,
// or a custom role with a server permission. It fails closed: a custom role
// that cannot be read counts as staff, except an unknown one, which the
// users service refuses anyway.
func (h *handlers) staffRole(r *http.Request, us core.Users, role core.Role, roleID string) bool {
	roleID = strings.TrimSpace(roleID)
	switch {
	case roleID == "":
		return role.IsAdmin()
	case !core.IsCustomRoleID(roleID):
		return core.Role(roleID).IsAdmin()
	}
	rd, err := us.GetRole(r.Context(), nil, roleID)
	if err != nil {
		return !errors.Is(err, core.ErrNotFound)
	}
	return rd.Staff
}

// target loads the account named by {id} and checks that the caller may act
// on it with the permission need (core.CheckManage: only owners act on owner
// accounts; a delegate only on accounts its role could manage). A refusal by
// the escalation rules is audited as action with outcome denied (action ""
// for reads: nothing is attempted).
func (h *handlers) target(r *http.Request, need core.Capability, action string) (*core.User, error) {
	us, err := h.users(r)
	if err != nil {
		return nil, err
	}
	u, err := us.Get(r.Context(), chi.URLParam(r, "id"))
	if err != nil {
		return nil, err
	}
	if err := core.CheckManage(mw.Principal(r), u, need); err != nil {
		h.auditDenied(r, action, u, err)
		return nil, err
	}
	return u, nil
}

// auditDenied records a refused escalation (an error carrying a
// *core.EscalationError) as action with outcome denied and details
// {"reason", "missing"}; the actor comes from the request context.
func (h *handlers) auditDenied(r *http.Request, action string, u *core.User, err error) {
	esc := core.AsEscalation(err)
	d := h.deps(r)
	if esc == nil || action == "" || d == nil || d.Env == nil || d.Audit == nil {
		return
	}
	details := map[string]any{"reason": esc.Reason}
	if len(esc.Missing) > 0 {
		details["missing"] = esc.Missing
	}
	d.Audit.Record(r.Context(), core.AuditEntry{Action: action, Outcome: core.OutcomeDenied, TargetType: "user",
		TargetID: u.ID, TargetName: u.Username, Details: details})
}

// generateAttempts bounds the retries of generatePassword (a random string
// rarely contains the username or the e-mail local part).
const generateAttempts = 8

// randomPassword returns n random base62 characters (a variable for tests).
var randomPassword = func(n int) string {
	b := generatedPasswordBytes
	for ids.TokenLen(b) < n {
		b++
	}
	return ids.Token(b)[:n] // uniform characters: cutting keeps them uniform
}

// generatePassword returns a random password for the account u that passes
// the password policy the same way a typed one must (AdminSetPassword checks
// it again): 22 base62 characters (≈131 bits), or auth.password_min when
// that is longer, drawn again when it happens to contain the username or the
// e-mail local part.
func (h *handlers) generatePassword(r *http.Request, au core.Auth, u *core.User) (string, error) {
	n := ids.TokenLen(generatedPasswordBytes)
	if d := h.deps(r); d != nil && d.Env != nil && d.Settings != nil {
		if m := d.Settings.Int("auth.password_min"); m > int64(n) {
			n = int(m)
		}
	}
	var err error
	for range generateAttempts {
		pw := randomPassword(n)
		if err = au.CheckPasswordPolicy(pw, u); err == nil {
			return pw, nil
		}
	}
	return "", err
}

// alert e-mails a security alert to u (best effort; security category).
func (h *handlers) alert(r *http.Request, u *core.User, kind string) {
	if u != nil {
		h.alertTo(r, u, u.Email, kind, "")
	}
}

// alertTo e-mails a security alert about u to the address to (best effort):
// the alert about a changed e-mail address goes to the previous one. name is
// the template's "name" (the masked new address for email_changed).
func (h *handlers) alertTo(r *http.Request, u *core.User, to, kind, name string) {
	d := h.deps(r)
	if d == nil || d.Notify == nil || u == nil || to == "" || !d.Notify.Enabled() {
		return
	}
	p := mw.Principal(r)
	data := map[string]any{"kind": kind, "username": u.Username, "time": h.now(r).UTC().Format(time.RFC3339)}
	if name != "" {
		data["name"] = name
	}
	if p != nil {
		data["actor"] = p.Username
	}
	if err := d.Notify.Send(r.Context(), []string{to}, "security_alert", data); err != nil && d.Log != nil {
		d.Log.Warn("usersapi: security alert not sent", "user", u.ID, "kind", kind, "err", err)
	}
}

// ---------- users ----------

func (h *handlers) listUsers(w http.ResponseWriter, r *http.Request) {
	us, err := h.users(r)
	if err != nil {
		httpx.Error(w, r, err)
		return
	}
	q := r.URL.Query()
	page, err := us.List(r.Context(), core.UserQuery{
		PageReq: httpx.PageReq(r), Q: q.Get("q"), Role: core.Role(q.Get("role")), RoleID: q.Get("role_id"),
		Status: q.Get("status"),
	})
	if err != nil {
		httpx.Error(w, r, err)
		return
	}
	httpx.OK(w, page)
}

func (h *handlers) createUser(w http.ResponseWriter, r *http.Request) {
	in, err := httpx.Decode[core.NewUser](r, 0)
	if err != nil {
		httpx.Error(w, r, err)
		return
	}
	res, err := h.doCreateUser(r, in)
	if err != nil {
		httpx.Error(w, r, err)
		return
	}
	httpx.Created(w, res)
}

func (h *handlers) doCreateUser(r *http.Request, in core.NewUser) (*core.UserCreated, error) {
	us, err := h.users(r)
	if err != nil {
		return nil, err
	}
	au, err := h.auth(r)
	if err != nil {
		return nil, err
	}
	if in.SetupToken != "" {
		return nil, core.Invalid("setup_token", "unknown field")
	}
	if h.staffRole(r, us, in.Role, in.RoleID) {
		if err := h.requireElevated(r); err != nil {
			return nil, err
		}
	}
	pw, generated := in.Password, ""
	probe := &core.User{Username: in.Username, DisplayName: in.DisplayName, Email: in.Email, Role: in.Role}
	switch {
	case in.GeneratePassword && in.Password != "":
		return nil, core.Invalid("password", "send either a password or generate_password, not both")
	case in.GeneratePassword:
		if pw, err = h.generatePassword(r, au, probe); err != nil {
			return nil, err
		}
		generated = pw
		in.MustChangePassword = true
	case pw == "":
		return nil, core.Invalid("password", "a password is required (or set generate_password)")
	default:
		if err := au.CheckPasswordPolicy(pw, probe); err != nil {
			return nil, err
		}
	}
	phc, err := au.HashPassword(pw)
	if err != nil {
		return nil, err
	}
	in.Password, in.GeneratePassword, in.PasswordHash = "", false, phc
	u, err := us.Create(r.Context(), mw.Principal(r), in)
	if err != nil {
		return nil, err
	}
	return &core.UserCreated{User: u, Password: generated}, nil
}

func (h *handlers) getUser(w http.ResponseWriter, r *http.Request) {
	us, err := h.users(r)
	if err != nil {
		httpx.Error(w, r, err)
		return
	}
	u, err := us.Get(r.Context(), chi.URLParam(r, "id"))
	if err != nil {
		httpx.Error(w, r, err)
		return
	}
	httpx.OK(w, u)
}

func (h *handlers) updateUser(w http.ResponseWriter, r *http.Request) {
	in, err := httpx.Decode[core.UserUpdate](r, 0)
	if err != nil {
		httpx.Error(w, r, err)
		return
	}
	us, err := h.users(r)
	if err != nil {
		httpx.Error(w, r, err)
		return
	}
	id := chi.URLParam(r, "id")
	if in.Role != nil || in.RoleID != nil {
		// Any role change needs step-up: the role requested (role_id, else
		// role — which also removes a custom role) differs from the current one.
		cur, err := us.Get(r.Context(), id)
		if err != nil {
			httpx.Error(w, r, err)
			return
		}
		requested := ""
		if in.Role != nil {
			requested = string(*in.Role)
		}
		if in.RoleID != nil {
			requested = strings.TrimSpace(*in.RoleID)
		}
		if requested != cur.RoleID {
			if err := h.requireElevated(r); err != nil {
				httpx.Error(w, r, err)
				return
			}
		}
	}
	// Changing one's own e-mail address here follows the rules of PATCH
	// /me/profile (DESIGN §9.3): the address receives the security alerts,
	// so it needs step-up and the previous address is told — every role
	// with "Manage accounts" reaches this route for its own account too.
	// Only a real change counts (users.Update ignores a change of case).
	p := mw.Principal(r)
	// Also as there, neither one's own address nor display name (what the
	// share and grant pickers show) changes with an API token: a leaked
	// token could otherwise redirect the very alerts that would reveal it.
	if p != nil && p.Via == core.ViaToken && p.UserID != "" && p.UserID == id && (in.Email != nil || in.DisplayName != nil) {
		httpx.Error(w, r, core.Errorf(core.ErrForbidden,
			"changing the e-mail address or display name is not available with API tokens; use the web interface or the admin socket"))
		return
	}
	oldEmail, selfEmail := "", false
	if in.Email != nil && p != nil && p.UserID != "" && p.UserID == id {
		cur, err := us.Get(r.Context(), id)
		if err != nil {
			httpx.Error(w, r, err)
			return
		}
		if !strings.EqualFold(strings.TrimSpace(*in.Email), cur.Email) {
			if err := h.requireElevated(r); err != nil {
				httpx.Error(w, r, err)
				return
			}
			oldEmail, selfEmail = cur.Email, true
		}
	}
	u, err := us.Update(r.Context(), p, id, in)
	if err != nil {
		httpx.Error(w, r, err)
		return
	}
	if selfEmail && u != nil && oldEmail != "" && !strings.EqualFold(oldEmail, u.Email) {
		h.alertTo(r, u, oldEmail, notify.AlertEmailChanged, maskEmail(u.Email))
	}
	httpx.OK(w, u)
}

// maskEmail shortens an address for the alert sent to the previous one, as
// meapi does: enough to recognise it ("p***@example.org"); "" stays "" (the
// address was removed).
func maskEmail(s string) string {
	local, domain, ok := strings.Cut(s, "@")
	if !ok || local == "" {
		return ""
	}
	first, _ := utf8.DecodeRuneInString(local)
	return string(first) + "***@" + domain
}

func (h *handlers) deleteUser(w http.ResponseWriter, r *http.Request) {
	us, err := h.users(r)
	if err != nil {
		httpx.Error(w, r, err)
		return
	}
	if err := us.Delete(r.Context(), mw.Principal(r), chi.URLParam(r, "id"), r.URL.Query().Get("transfer_to")); err != nil {
		httpx.Error(w, r, err)
		return
	}
	httpx.NoContent(w)
}

func (h *handlers) setPassword(w http.ResponseWriter, r *http.Request) {
	in, err := httpx.Decode[core.PasswordResetInput](r, 0)
	if err != nil {
		httpx.Error(w, r, err)
		return
	}
	u, err := h.target(r, core.CapUsersCredentials, core.ActUserPasswordReset)
	if err != nil {
		httpx.Error(w, r, err)
		return
	}
	au, err := h.auth(r)
	if err != nil {
		httpx.Error(w, r, err)
		return
	}
	pw, generated, mustChange := in.Password, "", in.MustChange
	switch {
	case in.Generate && in.Password != "":
		httpx.Error(w, r, core.Invalid("password", "send either a password or generate, not both"))
		return
	case in.Generate:
		if pw, err = h.generatePassword(r, au, u); err != nil {
			httpx.Error(w, r, err)
			return
		}
		generated, mustChange = pw, true
	case pw == "":
		httpx.Error(w, r, core.Invalid("password", "a password is required (or set generate)"))
		return
	}
	if err := au.AdminSetPassword(r.Context(), mw.Principal(r), u.ID, pw, mustChange); err != nil {
		httpx.Error(w, r, err)
		return
	}
	if p := mw.Principal(r); p == nil || p.UserID != u.ID {
		h.alert(r, u, "password_reset")
	}
	httpx.OK(w, core.PasswordReset{Password: generated})
}

func (h *handlers) unlockUser(w http.ResponseWriter, r *http.Request) {
	us, err := h.users(r)
	if err != nil {
		httpx.Error(w, r, err)
		return
	}
	if err := us.Unlock(r.Context(), mw.Principal(r), chi.URLParam(r, "id")); err != nil {
		httpx.Error(w, r, err)
		return
	}
	httpx.NoContent(w)
}

func (h *handlers) resetMFA(w http.ResponseWriter, r *http.Request) {
	u, err := h.target(r, core.CapUsersCredentials, core.ActUserMFAReset)
	if err != nil {
		httpx.Error(w, r, err)
		return
	}
	au, err := h.auth(r)
	if err != nil {
		httpx.Error(w, r, err)
		return
	}
	if err := au.ResetMFA(r.Context(), mw.Principal(r), u.ID); err != nil {
		httpx.Error(w, r, err)
		return
	}
	h.alert(r, u, "mfa_reset")
	httpx.NoContent(w)
}

func (h *handlers) setStatus(status string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		us, err := h.users(r)
		if err != nil {
			httpx.Error(w, r, err)
			return
		}
		if err := us.SetStatus(r.Context(), mw.Principal(r), chi.URLParam(r, "id"), status); err != nil {
			httpx.Error(w, r, err)
			return
		}
		httpx.NoContent(w)
	}
}

func (h *handlers) listSessions(w http.ResponseWriter, r *http.Request) {
	// h.target (not a bare Get): the owner rule covers both verbs of this
	// route — a session list exposes the owner's addresses, user agents and
	// step-up window, so it is acting on the account, not plain viewing.
	u, err := h.target(r, core.CapUsersCredentials, "")
	if err != nil {
		httpx.Error(w, r, err)
		return
	}
	au, err := h.auth(r)
	if err != nil {
		httpx.Error(w, r, err)
		return
	}
	list, err := au.ListSessions(r.Context(), u.ID)
	if err != nil {
		httpx.Error(w, r, err)
		return
	}
	if p := mw.Principal(r); p != nil {
		for i := range list {
			list[i].Current = p.SessionID != "" && list[i].ID == p.SessionID
		}
	}
	httpx.OK(w, core.NewPage(list, ""))
}

func (h *handlers) revokeSessions(w http.ResponseWriter, r *http.Request) {
	u, err := h.target(r, core.CapUsersCredentials, core.ActSessionRevoke)
	if err != nil {
		httpx.Error(w, r, err)
		return
	}
	au, err := h.auth(r)
	if err != nil {
		httpx.Error(w, r, err)
		return
	}
	p := mw.Principal(r)
	except := ""
	if p != nil && p.UserID == u.ID {
		except = p.SessionID // never sign the caller out of the session making the request
	}
	if err := au.RevokeAllSessions(r.Context(), p, u.ID, except); err != nil {
		httpx.Error(w, r, err)
		return
	}
	httpx.NoContent(w)
}

// ---------- invites ----------

func (h *handlers) listInvites(w http.ResponseWriter, r *http.Request) {
	us, err := h.users(r)
	if err != nil {
		httpx.Error(w, r, err)
		return
	}
	page, err := us.ListInvites(r.Context(), mw.Principal(r), httpx.PageReq(r))
	if err != nil {
		httpx.Error(w, r, err)
		return
	}
	// A staff invite link creates an account with server permissions and a
	// password of the holder's choosing, so it is as sensitive as creating
	// one: like POST of a staff invite it needs step-up. Without it the link
	// is left out (the invite is still listed and can be revoked).
	if h.requireElevated(r) != nil {
		staff := map[string]bool{}
		for i := range page.Items {
			inv := &page.Items[i]
			if inv.URL == "" {
				continue
			}
			known, ok := staff[inv.RoleID]
			if !ok {
				known = h.staffRole(r, us, inv.Role, inv.RoleID)
				staff[inv.RoleID] = known
			}
			if known {
				inv.URL = ""
			}
		}
	}
	httpx.OK(w, page)
}

func (h *handlers) createInvite(w http.ResponseWriter, r *http.Request) {
	in, err := httpx.Decode[core.InviteInput](r, 0)
	if err != nil {
		httpx.Error(w, r, err)
		return
	}
	us, err := h.users(r)
	if err != nil {
		httpx.Error(w, r, err)
		return
	}
	// Owners cannot be invited at all: the service answers that (422)
	// whatever the step-up window.
	owner := in.Role == core.RoleOwner || strings.TrimSpace(in.RoleID) == string(core.RoleOwner)
	if !owner && h.staffRole(r, us, in.Role, in.RoleID) {
		if err := h.requireElevated(r); err != nil {
			httpx.Error(w, r, err)
			return
		}
	}
	inv, token, err := us.CreateInvite(r.Context(), mw.Principal(r), in)
	if err != nil {
		httpx.Error(w, r, err)
		return
	}
	url := inv.URL
	if url == "" {
		url = "/invite/" + token
		inv.URL = url
	}
	httpx.Created(w, core.InviteCreated{Invite: inv, URL: url})
}

func (h *handlers) revokeInvite(w http.ResponseWriter, r *http.Request) {
	us, err := h.users(r)
	if err != nil {
		httpx.Error(w, r, err)
		return
	}
	if err := us.RevokeInvite(r.Context(), mw.Principal(r), chi.URLParam(r, "id")); err != nil {
		httpx.Error(w, r, err)
		return
	}
	httpx.NoContent(w)
}

// ---------- groups ----------

func (h *handlers) listGroups(w http.ResponseWriter, r *http.Request) {
	us, err := h.users(r)
	if err != nil {
		httpx.Error(w, r, err)
		return
	}
	page, err := us.ListGroups(r.Context(), httpx.PageReq(r))
	if err != nil {
		httpx.Error(w, r, err)
		return
	}
	httpx.OK(w, page)
}

func (h *handlers) createGroup(w http.ResponseWriter, r *http.Request) {
	in, err := httpx.Decode[core.GroupInput](r, 0)
	if err != nil {
		httpx.Error(w, r, err)
		return
	}
	us, err := h.users(r)
	if err != nil {
		httpx.Error(w, r, err)
		return
	}
	g, err := us.CreateGroup(r.Context(), mw.Principal(r), in)
	if err != nil {
		httpx.Error(w, r, err)
		return
	}
	httpx.Created(w, g)
}

func (h *handlers) getGroup(w http.ResponseWriter, r *http.Request) {
	us, err := h.users(r)
	if err != nil {
		httpx.Error(w, r, err)
		return
	}
	g, err := us.GetGroup(r.Context(), chi.URLParam(r, "id"))
	if err != nil {
		httpx.Error(w, r, err)
		return
	}
	httpx.OK(w, g)
}

func (h *handlers) updateGroup(w http.ResponseWriter, r *http.Request) {
	in, err := httpx.Decode[core.GroupInput](r, 0)
	if err != nil {
		httpx.Error(w, r, err)
		return
	}
	us, err := h.users(r)
	if err != nil {
		httpx.Error(w, r, err)
		return
	}
	g, err := us.UpdateGroup(r.Context(), mw.Principal(r), chi.URLParam(r, "id"), in)
	if err != nil {
		httpx.Error(w, r, err)
		return
	}
	httpx.OK(w, g)
}

func (h *handlers) deleteGroup(w http.ResponseWriter, r *http.Request) {
	us, err := h.users(r)
	if err != nil {
		httpx.Error(w, r, err)
		return
	}
	if err := us.DeleteGroup(r.Context(), mw.Principal(r), chi.URLParam(r, "id")); err != nil {
		httpx.Error(w, r, err)
		return
	}
	httpx.NoContent(w)
}

func (h *handlers) listMembers(w http.ResponseWriter, r *http.Request) {
	us, err := h.users(r)
	if err != nil {
		httpx.Error(w, r, err)
		return
	}
	list, err := us.Members(r.Context(), chi.URLParam(r, "id"))
	if err != nil {
		httpx.Error(w, r, err)
		return
	}
	httpx.OK(w, core.NewPage(list, ""))
}

func (h *handlers) setMember(w http.ResponseWriter, r *http.Request) {
	in, err := httpx.Decode[core.RoleInput](r, 0)
	if err != nil {
		httpx.Error(w, r, err)
		return
	}
	us, err := h.users(r)
	if err != nil {
		httpx.Error(w, r, err)
		return
	}
	if err := us.SetMember(r.Context(), mw.Principal(r), chi.URLParam(r, "id"), chi.URLParam(r, "userId"), in.Role); err != nil {
		httpx.Error(w, r, err)
		return
	}
	httpx.NoContent(w)
}

func (h *handlers) removeMember(w http.ResponseWriter, r *http.Request) {
	us, err := h.users(r)
	if err != nil {
		httpx.Error(w, r, err)
		return
	}
	if err := us.RemoveMember(r.Context(), mw.Principal(r), chi.URLParam(r, "id"), chi.URLParam(r, "userId")); err != nil {
		httpx.Error(w, r, err)
		return
	}
	httpx.NoContent(w)
}

// ---------- self-service (F) ----------

func (h *handlers) myGroups(w http.ResponseWriter, r *http.Request) {
	us, err := h.users(r)
	if err != nil {
		httpx.Error(w, r, err)
		return
	}
	list, err := us.MyGroups(r.Context(), mw.Principal(r))
	if err != nil {
		httpx.Error(w, r, err)
		return
	}
	httpx.OK(w, core.NewPage(list, ""))
}

func (h *handlers) lookup(w http.ResponseWriter, r *http.Request) {
	us, err := h.users(r)
	if err != nil {
		httpx.Error(w, r, err)
		return
	}
	list, err := us.Lookup(r.Context(), mw.Principal(r), r.URL.Query().Get("q"))
	if err != nil {
		httpx.Error(w, r, err)
		return
	}
	httpx.OK(w, core.NewPage(list, ""))
}

// activity lists the caller's own audit events (actor = the caller).
func (h *handlers) activity(w http.ResponseWriter, r *http.Request) {
	p := mw.Principal(r)
	if p == nil || p.UserID == "" {
		// The system principal has no own events (and must never see everyone's here).
		httpx.OK(w, core.NewPage[core.AuditRecord](nil, ""))
		return
	}
	d := h.deps(r)
	if d == nil || d.Env == nil || d.Audit == nil {
		httpx.Error(w, r, core.Errorf(core.ErrUnavailable, "the activity log is unavailable"))
		return
	}
	q, err := activityQuery(r)
	if err != nil {
		httpx.Error(w, r, err)
		return
	}
	q.ActorID = p.UserID
	page, err := d.Audit.Query(r.Context(), q)
	if err != nil {
		httpx.Error(w, r, err)
		return
	}
	httpx.OK(w, page)
}

// activityQuery parses ?action=&outcome=&since=&until=&target_type=
// &target_id=&sort=&cursor=&limit= (the item filter is what the details
// panel's Activity tab uses; the caller still only sees their own events).
func activityQuery(r *http.Request) (core.AuditQuery, error) {
	v := r.URL.Query()
	q := core.AuditQuery{
		PageReq:    httpx.PageReq(r),
		Action:     strings.TrimSpace(v.Get("action")),
		Outcome:    v.Get("outcome"),
		TargetType: strings.TrimSpace(v.Get("target_type")),
		TargetID:   strings.TrimSpace(v.Get("target_id")),
	}
	parse := func(field string) (*time.Time, error) {
		s := strings.TrimSpace(v.Get(field))
		if s == "" {
			return nil, nil
		}
		t, err := time.Parse(time.RFC3339, s)
		if err != nil {
			return nil, core.Invalid(field, "expected an RFC 3339 time such as 2026-01-02T15:04:05Z")
		}
		return &t, nil
	}
	var err error
	if q.Since, err = parse("since"); err != nil {
		return q, err
	}
	if q.Until, err = parse("until"); err != nil {
		return q, err
	}
	return q, nil
}
