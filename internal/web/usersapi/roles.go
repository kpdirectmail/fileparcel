package usersapi

import (
	"net/http"

	"github.com/go-chi/chi/v5"

	"fileparcel/internal/core"
	"fileparcel/internal/web/httpx"
	"fileparcel/internal/web/mw"
)

// Roles (DESIGN §6a): the handlers only decode and encode. The users service
// decides what the caller may do — roles CRUD is for built-in owners and
// admins (the route guard is Adm, the service checks again), role → group
// memberships need groups.manage, the role list needs users.view (route) and
// the custom-role directory users.lookup or users.view (service) — and it
// audits the changes and announces them with authz.changed.

// listRoles answers GET /admin/roles: {"items":[core.RoleDef]}, the four
// built-in roles and then the custom roles by name, with the caller's
// editable/assignable flags.
func (h *handlers) listRoles(w http.ResponseWriter, r *http.Request) {
	us, err := h.users(r)
	if err != nil {
		httpx.Error(w, r, err)
		return
	}
	list, err := us.ListRoles(r.Context(), mw.Principal(r))
	if err != nil {
		httpx.Error(w, r, err)
		return
	}
	httpx.OK(w, core.NewPage(list, ""))
}

// getRole answers GET /admin/roles/{id}: a built-in word (owner, admin,
// member, guest) or a custom role id → core.RoleDef; 404 otherwise.
func (h *handlers) getRole(w http.ResponseWriter, r *http.Request) {
	us, err := h.users(r)
	if err != nil {
		httpx.Error(w, r, err)
		return
	}
	rd, err := us.GetRole(r.Context(), mw.Principal(r), chi.URLParam(r, "id"))
	if err != nil {
		httpx.Error(w, r, err)
		return
	}
	httpx.OK(w, rd)
}

// capabilities answers GET /admin/capabilities: the permission catalog
// (core.CapabilityCatalog) the role editor and the CLI show.
func (h *handlers) capabilities(w http.ResponseWriter, _ *http.Request) {
	httpx.OK(w, core.Catalog())
}

// createRole answers POST /admin/roles: core.RoleDefInput → 201 core.RoleDef.
func (h *handlers) createRole(w http.ResponseWriter, r *http.Request) {
	in, err := httpx.Decode[core.RoleDefInput](r, 0)
	if err != nil {
		httpx.Error(w, r, err)
		return
	}
	us, err := h.users(r)
	if err != nil {
		httpx.Error(w, r, err)
		return
	}
	rd, err := us.CreateRole(r.Context(), mw.Principal(r), in)
	if err != nil {
		httpx.Error(w, r, err)
		return
	}
	httpx.Created(w, rd)
}

// updateRole answers PATCH /admin/roles/{id}: core.RoleDefUpdate →
// core.RoleDef (built-in roles: 422).
func (h *handlers) updateRole(w http.ResponseWriter, r *http.Request) {
	in, err := httpx.Decode[core.RoleDefUpdate](r, 0)
	if err != nil {
		httpx.Error(w, r, err)
		return
	}
	us, err := h.users(r)
	if err != nil {
		httpx.Error(w, r, err)
		return
	}
	rd, err := us.UpdateRole(r.Context(), mw.Principal(r), chi.URLParam(r, "id"), in)
	if err != nil {
		httpx.Error(w, r, err)
		return
	}
	httpx.OK(w, rd)
}

// deleteRole answers DELETE /admin/roles/{id}?reassign_to=: 204. The
// holders move to reassign_to (member, guest or another custom role), which
// is required while the role has holders (409).
func (h *handlers) deleteRole(w http.ResponseWriter, r *http.Request) {
	us, err := h.users(r)
	if err != nil {
		httpx.Error(w, r, err)
		return
	}
	if err := us.DeleteRole(r.Context(), mw.Principal(r), chi.URLParam(r, "id"), r.URL.Query().Get("reassign_to")); err != nil {
		httpx.Error(w, r, err)
		return
	}
	httpx.NoContent(w)
}

// roleGroups answers GET /admin/roles/{id}/groups: {"items":[core.RoleGroup]}
// (built-in roles are members of no group; 404 for an unknown role).
func (h *handlers) roleGroups(w http.ResponseWriter, r *http.Request) {
	us, err := h.users(r)
	if err != nil {
		httpx.Error(w, r, err)
		return
	}
	list, err := us.RoleGroups(r.Context(), chi.URLParam(r, "id"))
	if err != nil {
		httpx.Error(w, r, err)
		return
	}
	httpx.OK(w, core.NewPage(list, ""))
}

// setRoleGroup answers PUT /admin/roles/{id}/groups/{groupId}:
// core.RoleGroupInput {member_role} → core.RoleGroup. Every holder of the
// custom role becomes a member (or manager) of the group.
func (h *handlers) setRoleGroup(w http.ResponseWriter, r *http.Request) {
	in, err := httpx.Decode[core.RoleGroupInput](r, 0)
	if err != nil {
		httpx.Error(w, r, err)
		return
	}
	us, err := h.users(r)
	if err != nil {
		httpx.Error(w, r, err)
		return
	}
	rg, err := us.SetRoleGroup(r.Context(), mw.Principal(r), chi.URLParam(r, "id"), chi.URLParam(r, "groupId"), in.MemberRole)
	if err != nil {
		httpx.Error(w, r, err)
		return
	}
	httpx.OK(w, rg)
}

// removeRoleGroup answers DELETE /admin/roles/{id}/groups/{groupId}: 204
// (404 when the role is not a member of the group).
func (h *handlers) removeRoleGroup(w http.ResponseWriter, r *http.Request) {
	us, err := h.users(r)
	if err != nil {
		httpx.Error(w, r, err)
		return
	}
	if err := us.RemoveRoleGroup(r.Context(), mw.Principal(r), chi.URLParam(r, "id"), chi.URLParam(r, "groupId")); err != nil {
		httpx.Error(w, r, err)
		return
	}
	httpx.NoContent(w)
}

// lookupRoles answers GET /roles: the custom roles as {"items":[core.RoleRef]}
// (id, name, description) for the share and grant pickers, with the same
// check as the user directory (users.lookup or users.view, else 403).
func (h *handlers) lookupRoles(w http.ResponseWriter, r *http.Request) {
	us, err := h.users(r)
	if err != nil {
		httpx.Error(w, r, err)
		return
	}
	list, err := us.LookupRoles(r.Context(), mw.Principal(r))
	if err != nil {
		httpx.Error(w, r, err)
		return
	}
	httpx.OK(w, core.NewPage(list, ""))
}
