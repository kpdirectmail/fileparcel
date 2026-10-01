"""Roles and permissions for the Playwright tests (rbac-final §17.2): set-up through the REST API.

Everything here acts as the test server's owner (``RolesAdmin``), which steps up on demand: creating, changing and
deleting roles, giving someone a role with server permissions, role changes, staff invitations and deleting accounts
are step-up routes (DESIGN §9.3). What a module creates is removed again when it ends, so the rest of the suite (the
admin pages render every role and group there is) sees the same server as before.

Fixtures (import them into the test module):
    roles_admin      module: the owner over the API, with cleanup
    helpdesk_role    module: a custom role based on Member with "Manage accounts" and "Reset sign-in"
    helpdesk_state   a new account with that role (``Holder``: its session as a browser storage state)

A role with server permissions ("staff") falls under ``auth.require_2fa = admins`` (the default), so ``role_holder``
sets up an authenticator app for its account before the role is given; the account's session stays signed in.
Names get a random suffix: role and group names are unique on the server and the session-scoped server is shared
by every test module.
"""

from __future__ import annotations

import secrets
from dataclasses import dataclass

import pytest
from conftest import ApiClient, Response, Server, cookie_state

# core.MemberCaps: what the built-in Member role may do (a new role based on Member starts with these).
MEMBER_PERMISSIONS = ["shares.links", "shares.requests", "users.lookup", "tokens.create"]

# core.Capabilities with Server == true (web/static/js/core/perms.js SERVER_PERMISSIONS).
SERVER_PERMISSIONS = [
    "users.view", "users.manage", "users.credentials", "invites.manage", "groups.manage", "shares.manage",
    "settings.manage", "network.manage", "certs.manage", "backups.run", "system.view", "system.manage", "audit.view",
]

# The page shown for a route the account's role does not include (web/static/js/routes.js `forbidden`).
FORBIDDEN_HEADING = "Your role does not include this page"


def unique(prefix: str) -> str:
    """A name that no other test run on the shared server has used ("Helpdesk 3fa9c1")."""
    return f"{prefix} {secrets.token_hex(3)}"


def _error_code(r: Response) -> str:
    try:
        return ((r.json() or {}).get("error") or {}).get("code") or ""
    except ValueError:
        return ""


def is_staff(role: dict) -> bool:
    """Whether a role (core.RoleDef) opens part of the Admin area: owner, admin or a server permission."""
    return role.get("id") in ("owner", "admin") or any(p in SERVER_PERMISSIONS for p in role.get("permissions") or [])


class RolesAdmin:
    """The server's owner over the REST API. ``call`` steps up when a route asks for it and signs in again when the
    session was rotated (a browser that shares it confirmed its identity), and remembers what it created."""

    def __init__(self, server: Server) -> None:
        self.server = server
        self.api: ApiClient = server.client()
        self._login()
        self.users: list[str] = []
        self.roles: list[str] = []
        self.groups: list[str] = []
        self.invites: list[str] = []

    def _login(self) -> None:
        s = self.server
        self.api.login(s.admin, s.admin_password, s.admin_totp, s.clock)

    def request(self, method: str, path: str, body=None) -> Response:
        """One request; a step-up or a new sign-in when the server asks for it, then the request once more."""
        r = self.api.request(method, path, body)
        if r.status == 403 and _error_code(r) == "elevation_required":
            assert self.api.elevate(self.server.admin_password), "step-up as the owner failed"
            r = self.api.request(method, path, body)
        elif r.status == 401:
            self._login()
            r = self.api.request(method, path, body)
            if r.status == 403 and _error_code(r) == "elevation_required":
                assert self.api.elevate(self.server.admin_password), "step-up as the owner failed"
                r = self.api.request(method, path, body)
        return r

    def call(self, method: str, path: str, body=None):
        """request() that must succeed; returns the decoded JSON (None for 204)."""
        r = self.request(method, path, body)
        assert 200 <= r.status < 300, f"{method} {path}: HTTP {r.status} {r.body[:300]!r}"
        return r.json() if r.body else None

    def elevated_state(self) -> dict:
        """A browser storage state sharing this session, with a fresh step-up window (10 minutes by default): pages
        that save roles or change someone's role then need no prompt, and the browser never rotates the session."""
        assert self.api.elevate(self.server.admin_password), "step-up as the owner failed"
        return cookie_state(self.server, self.api)

    def fresh_state(self) -> dict:
        """A new session of the owner in a browser storage state, without step-up (the web app will ask for it)."""
        other = self.server.client()
        s = self.server
        other.login(s.admin, s.admin_password, s.admin_totp, s.clock)
        return cookie_state(s, other)

    # ---------------------------------------------------------------------------------------------- objects
    def new_user(self, prefix: str = "u", role_id: str = "member", display_name: str | None = None) -> tuple[dict, str]:
        """A new account (removed when the module ends) → (core.User, password)."""
        name = f"{prefix}{secrets.token_hex(4)}"
        pw = "Ui-" + secrets.token_hex(12)
        res = self.call("POST", "/api/v1/admin/users", {"username": name, "password": pw, "role_id": role_id,
                                                        "display_name": display_name or name})
        user = res["user"]
        self.users.append(user["id"])
        return user, pw

    def set_role(self, user_id: str, role_id: str) -> dict:
        """Gives an account a role (PATCH {role_id}; a role change is a step-up route) → core.User."""
        return self.call("PATCH", f"/api/v1/admin/users/{user_id}", {"role_id": role_id})

    def create_group(self, prefix: str = "Group") -> dict:
        """A new group with its team folder (deleted when the module ends) → core.Group."""
        g = self.call("POST", "/api/v1/admin/groups", {"name": unique(prefix)})
        self.groups.append(g["id"])
        return g

    def add_member(self, group_id: str, user_id: str, role: str = "member") -> None:
        self.call("PUT", f"/api/v1/admin/groups/{group_id}/members/{user_id}", {"role": role})

    def role_to_group(self, role_id: str, group_id: str, member_role: str = "member") -> dict:
        """Makes everyone with a custom role a member (or manager) of a group → core.RoleGroup."""
        return self.call("PUT", f"/api/v1/admin/roles/{role_id}/groups/{group_id}", {"member_role": member_role})

    def cleanup(self) -> None:
        """Best effort: accounts first (a role with holders cannot be deleted without moving them), then roles,
        groups (their team folders go with them) and invitations."""
        for uid in self.users:
            self.request("DELETE", f"/api/v1/admin/users/{uid}")
        for rid in self.roles:
            self.request("DELETE", f"/api/v1/admin/roles/{rid}?reassign_to=member")
        for gid in self.groups:
            self.request("DELETE", f"/api/v1/admin/groups/{gid}")
        for iid in self.invites:
            self.request("DELETE", f"/api/v1/admin/invites/{iid}")


def create_role(admin: RolesAdmin, name: str, base: str = "member", perms: list[str] | None = None,
                delegable: bool = False, description: str = "") -> dict:
    """Creates a custom role (POST /admin/roles, step-up) and returns its core.RoleDef. `perms` is the complete list
    (what a permission implies is added by the server); None keeps the base's defaults (Member's four, or none for
    Guest). The role is deleted when the module ends."""
    body: dict = {"name": name, "base": base, "delegable": delegable}
    if description:
        body["description"] = description
    if perms is not None:
        body["permissions"] = perms
    role = admin.call("POST", "/api/v1/admin/roles", body)
    admin.roles.append(role["id"])
    return role


def enroll_totp(api: ApiClient, password: str, clock) -> str:
    """Sets up an authenticator app on the account of `api` (step-up first) and returns its secret."""
    assert api.elevate(password), "step-up before setting up the authenticator app"
    secret = api.ok("POST", "/api/v1/me/totp/begin")["secret"]
    api.ok("POST", "/api/v1/me/totp/confirm", {"code": clock.code(secret)})
    api.refresh_csrf()
    return secret


def team_root(api: ApiClient, group_id: str) -> str:
    """The root folder of a group's team folder, as the account of `api` sees it."""
    spaces = api.ok("GET", "/api/v1/spaces")
    root = next((s["root_id"] for s in spaces if s["kind"] == "group" and s.get("group_id") == group_id), None)
    assert root, f"the team folder of {group_id} is not among the spaces of this account: {[s['name'] for s in spaces]}"
    return root


@dataclass
class Holder:
    """An account that holds a role, signed in: `state` is its session as a browser storage state and `api` the same
    session over the REST API."""

    user: dict
    password: str
    api: ApiClient
    state: dict
    totp_secret: str | None = None

    @property
    def id(self) -> str:
        return self.user["id"]

    @property
    def username(self) -> str:
        return self.user["username"]


def role_holder(admin: RolesAdmin, role: dict, prefix: str = "r") -> Holder:
    """A new account with `role`, signed in. It starts as a Member so that it can sign in and, for a role with server
    permissions, set up the second factor the default 2FA policy asks for; then the owner gives it the role."""
    user, pw = admin.new_user(prefix)
    api = admin.server.client()
    api.login(user["username"], pw)
    secret = enroll_totp(api, pw, admin.server.clock) if is_staff(role) else None
    if role["id"] != "member":
        user = admin.set_role(user["id"], role["id"])
    return Holder(user=user, password=pw, api=api, state=cookie_state(admin.server, api), totp_secret=secret)


# ---------------------------------------------------------------------------------------------------- fixtures
@pytest.fixture(scope="module")
def roles_admin(server):
    """The owner over the REST API (see RolesAdmin); removes what the module created at its end."""
    admin = RolesAdmin(server)
    yield admin
    admin.cleanup()


@pytest.fixture(scope="module")
def helpdesk_role(roles_admin):
    """A custom role based on Member for people who look after accounts: Member's permissions plus "Manage accounts"
    and "Reset sign-in" ("View people" comes with them). Not delegable."""
    return create_role(roles_admin, unique("Helpdesk"), "member", MEMBER_PERMISSIONS + ["users.manage", "users.credentials"],
                       description="Looks after accounts: creates them, resets passwords and two-factor authentication.")


@pytest.fixture
def helpdesk_state(roles_admin, helpdesk_role) -> Holder:
    """A new account with the Helpdesk role, signed in (a Holder; `.state` for new_page(storage_state=…))."""
    return role_holder(roles_admin, helpdesk_role, "helpdesk")
