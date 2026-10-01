package usersapi

import (
	"net/http"
	"slices"

	"github.com/go-chi/chi/v5"

	"fileparcel/internal/core"
	"fileparcel/internal/web/httpx"
	"fileparcel/internal/web/mw"
)

// settingAdminFiles is auth.admin_can_access_files (registered by package
// auth, read by name like package files does).
const settingAdminFiles = "auth.admin_can_access_files"

// userAccess answers GET /admin/users/{id}/access (core.UserAccess): the
// effective-access preview of one account (DESIGN §6a) — its role and
// permissions, its group memberships and where they come from, and the live
// grants to it, its groups and its custom role. Grants on items the caller
// may not see are only counted (hidden_grants; the files service decides,
// as for GET /admin/grants, so API tokens also need files:read). The number
// of live admin-scope API tokens is filled only for callers holding
// users.credentials (the ones who could revoke them), and manageable says
// whether the caller may act on the account (core.CheckManage with
// users.manage).
func (h *handlers) userAccess(w http.ResponseWriter, r *http.Request) {
	us, err := h.users(r)
	if err != nil {
		httpx.Error(w, r, err)
		return
	}
	ctx, p := r.Context(), mw.Principal(r)
	u, err := us.Get(ctx, chi.URLParam(r, "id"))
	if err != nil {
		httpx.Error(w, r, err)
		return
	}
	d := h.deps(r)
	if d == nil || d.Files == nil {
		httpx.Error(w, r, core.Errorf(core.ErrUnavailable, "the file service is not available"))
		return
	}
	role, err := us.GetRole(ctx, p, u.RoleID)
	if err != nil {
		httpx.Error(w, r, err)
		return
	}
	groups, err := us.GroupsOf(ctx, u.ID)
	if err != nil {
		httpx.Error(w, r, err)
		return
	}
	grants, err := d.Files.SubjectGrants(ctx, p, core.SubjectGrantQuery{SubjectType: core.SubjectUser, SubjectID: u.ID, Expand: true})
	if err != nil {
		httpx.Error(w, r, err)
		return
	}
	out := core.UserAccess{
		User:          core.UserRef{ID: u.ID, Username: u.Username, DisplayName: u.DisplayName},
		Role:          *role,
		Permissions:   u.Permissions,
		Staff:         u.Role.IsAdmin() || u.Permissions.Server() != 0,
		FilesOverride: u.Role.IsAdmin() && d.Env != nil && d.Settings != nil && d.Settings.Bool(settingAdminFiles),
		PersonalSpace: u.SpaceID != "",
		Groups:        groups,
		Grants:        grants.Items,
		HiddenGrants:  grants.Hidden,
		Manageable:    core.CheckManage(p, u, core.CapUsersManage) == nil,
	}
	if out.Groups == nil {
		out.Groups = []core.AccessGroup{}
	}
	if out.Grants == nil {
		out.Grants = []core.Grant{}
	}
	if p.Can(core.CapUsersCredentials) {
		if out.AdminTokens, err = h.adminTokens(r, u.ID); err != nil {
			httpx.Error(w, r, err)
			return
		}
	}
	httpx.OK(w, out)
}

// adminTokens counts the live API tokens of userID that carry the admin
// scope (not revoked, not expired).
func (h *handlers) adminTokens(r *http.Request, userID string) (int, error) {
	au, err := h.auth(r)
	if err != nil {
		return 0, err
	}
	list, err := au.ListTokens(r.Context(), userID)
	if err != nil {
		return 0, err
	}
	now, n := h.now(r), 0
	for _, t := range list {
		if t.RevokedAt == nil && (t.ExpiresAt == nil || t.ExpiresAt.After(now)) && slices.Contains(t.Scopes, core.ScopeAdmin) {
			n++
		}
	}
	return n, nil
}
