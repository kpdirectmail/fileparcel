"""Several features together in the web app (implementation plan §12.2): roles and permissions (rbac-final), Tailscale
Funnel (funnel-vpn-final) and password-protected zips (zip-password-final) on one server with a fake tailscaled.

- A custom role "netops" (Member + network.manage) sees Admin → Network & VPN with the Funnel card and the network
  settings sections, nothing else of the Admin area; the switches that weaken sign-in over Funnel are disabled for it
  and say why (built-in owners and administrators only; the server answers 403 as well).
- A Contractors role (based on Guest, no permission) with an editor grant on a team folder uploads a
  password-protected .zip there and sees the lock badge.
- The same pages at 320 px, light and dark: no horizontal overflow, 44 px touch targets.

Every test fails on console errors and CSP / Trusted Types violations (watch.assert_clean()). Set-up goes through
the REST API (helpers_roles.RolesAdmin on the Funnel server); the module removes what it created at its end.
"""

from __future__ import annotations

import re
import secrets
from dataclasses import dataclass

import pytest
from conftest import MOBILE_DEVICES, assert_no_overflow, assert_tap_targets, cookie_state, shot
from helpers_roles import (
    FORBIDDEN_HEADING,
    MEMBER_PERMISSIONS,
    Holder,
    RolesAdmin,
    create_role,
    role_holder,
    team_root,
    unique,
)
from playwright.sync_api import expect
from test_zip_password import AES_LABEL, confirm_input, file_row, open_upload_dialog, password_input, protect, submit, wait_ready

SCHEMES = ["light", "dark"]
NO_WEAKEN = "Only an owner or administrator can change this"
WEAKEN_NOTE = "Only an owner or administrator can allow administration over Funnel or turn off two-factor sign-in."
# The Admin area of netops: the Dashboard, the settings sections network.manage opens, and the Network page.
NETOPS_AREAS = ["Dashboard", "Settings", "Network & VPN"]
OTHER_ADMIN_ROUTES = ["/admin/users", "/admin/invites", "/admin/groups", "/admin/roles", "/admin/certificates",
                      "/admin/encryption", "/admin/backups", "/admin/audit", "/admin/jobs", "/admin/system",
                      "/admin/settings/general", "/admin/settings/auth", "/admin/settings/tailscale"]


@dataclass
class V4:
    admin: RolesAdmin
    netops: Holder
    contractor: Holder
    folder: dict  # /Team/X, shared with the Contractors role for editing


@pytest.fixture(scope="module")
def v4(funnel_server):
    """netops and a Contractors holder on the Funnel server, the team folder X shared with Contractors, and Funnel
    publishing the whole app (turned on by the administrator)."""
    fs = funnel_server
    admin = RolesAdmin(fs.server)
    netops_role = create_role(admin, unique("netops"), "member", MEMBER_PERMISSIONS + ["network.manage"],
                              description="Runs the network, the VPNs and Tailscale Funnel.")
    contractors = create_role(admin, unique("Contractors"), "guest", [])
    netops = role_holder(admin, netops_role, "netops")
    contractor = role_holder(admin, contractors, "contractor")
    team = admin.create_group("Team")
    mel, mel_pw = admin.new_user("mel")
    admin.add_member(team["id"], mel["id"], "manager")
    mel_api = fs.server.client()
    mel_api.login(mel["username"], mel_pw)
    folder = mel_api.ok("POST", f"/api/v1/nodes/{team_root(mel_api, team['id'])}/folders", {"name": "X"})
    mel_api.ok("POST", f"/api/v1/nodes/{folder['id']}/grants",
               {"subject_type": "role", "subject_id": contractors["id"], "role": "editor"})
    fs.admin_api().ok("PUT", "/api/v1/admin/network/funnel", {"mode": "app", "confirm": "public"})
    try:
        yield V4(admin, netops, contractor, folder)
    finally:
        fs.admin_api().request("PUT", "/api/v1/admin/network/funnel", {"mode": "off"})
        admin.cleanup()


def admin_group(page):
    """The Admin group of the sidebar (desktop)."""
    return page.locator("#fp-sidebar").get_by_role("group", name="Admin")


def weaken_switches(card):
    return (card.get_by_role("switch", name="Allow administration over Funnel"),
            card.get_by_role("switch", name="Require two-factor sign-in over Funnel"))


def test_netops_sees_network_only(funnel_server, funnel_page, v4, request):
    page, watch = funnel_page(storage_state=v4.netops.state)
    refused: list[str] = []
    page.on("response", lambda r: refused.append(f"{r.status} {r.url}") if r.status == 403 else None)
    page.goto("/admin")
    expect(admin_group(page).get_by_role("link")).to_have_text(NETOPS_AREAS)

    page.goto("/admin/network")
    card = page.locator("#funnel")
    expect(card.get_by_text("Internet access (Tailscale Funnel)")).to_be_visible()
    expect(card.locator(".badge").first).to_have_text("Active")
    # The mode is theirs to change; weakening sign-in is not, and the card says so.
    expect(card.locator("input[name='fp-funnel-mode'][value='shares']")).to_be_enabled()
    card.get_by_text("Advanced", exact=True).click()
    allow, require2fa = weaken_switches(card)
    expect(allow).not_to_be_checked()
    expect(require2fa).to_be_checked()
    for switch in (allow, require2fa):
        expect(switch).to_be_disabled()
        expect(switch).to_have_attribute("title", NO_WEAKEN)
    expect(card.get_by_text(WEAKEN_NOTE)).to_be_visible()
    shot(page, request, "netops-funnel")

    # The settings sections of network.manage, nothing else.
    page.goto("/admin/settings/funnel")
    expect(page.locator("code", has_text="funnel.backend_port")).to_be_visible()
    for route in OTHER_ADMIN_ROUTES:
        page.goto(route)
        expect(page.get_by_role("heading", name=FORBIDDEN_HEADING)).to_be_visible()
    page.wait_for_load_state("networkidle")
    assert not refused, f"the pages of netops asked for what the role does not include: {refused}"
    watch.assert_clean()


def test_admin_may_weaken(funnel_server, funnel_page, v4, request):
    """The same card for the built-in administrator: the switches are enabled and there is no note."""
    fs = funnel_server
    s = fs.server
    api = s.client()
    api.login(s.admin, s.admin_password, s.admin_totp, s.clock)
    page, watch = funnel_page(storage_state=cookie_state(s, api))
    page.goto("/admin/network")
    card = page.locator("#funnel")
    expect(card.locator(".badge").first).to_have_text("Active")
    card.get_by_text("Advanced", exact=True).click()
    allow, require2fa = weaken_switches(card)
    expect(allow).to_be_enabled()
    expect(allow).not_to_have_attribute("title", NO_WEAKEN)
    expect(card.get_by_text(WEAKEN_NOTE)).to_have_count(0)
    # Turning 2FA off is blocked by "administration over Funnel" only, never by the role.
    expect(require2fa).to_be_enabled()
    watch.assert_clean()


def test_contractor_uploads_protected_zip(funnel_server, funnel_page, v4, request, tmp_path):
    page, watch = funnel_page(storage_state=v4.contractor.state)
    page.goto("/shared")
    expect(page.get_by_text("X", exact=True).first).to_be_visible()
    page.goto(f"/files/{v4.folder['id']}")
    brief = tmp_path / "brief.txt"
    brief.write_bytes(b"Scope of work for the contractors.\n" * 40)
    name = f"brief-{secrets.token_hex(3)}.zip"
    dlg = open_upload_dialog(page, [brief])
    protect(dlg, name)
    secret = "Contractor-" + secrets.token_hex(8)
    password_input(dlg).fill(secret)
    confirm_input(dlg).fill(secret)
    submit(dlg)
    expect(dlg).to_be_hidden()
    wait_ready(page, name)
    badge = file_row(page, name).locator(".fv-badge--lock")
    expect(badge).to_have_attribute("title", AES_LABEL)
    shot(page, request, "contractor-zip")

    # The server agrees: the node is a protected zip in X, and the role gives no share links.
    node = next(n for n in v4.contractor.api.ok("GET", f"/api/v1/nodes/{v4.folder['id']}/children")["items"]
                if n["name"] == name)
    assert node.get("zip_encryption") == "aes256", node
    r = v4.contractor.api.request("POST", "/api/v1/shares", {"kind": "link", "node_id": node["id"]})
    assert r.status == 403, (r.status, r.body[:200])
    features = v4.contractor.api.ok("GET", "/api/v1/me")["features"]
    assert features["internet_links"] and not features["links"], features
    watch.assert_clean()


@pytest.mark.parametrize("scheme", SCHEMES)
def test_v4_pages_at_320px(funnel_server, funnel_page, v4, request, scheme):
    """The pages above on a 320 px phone: no horizontal overflow and 44 px touch targets, light and dark."""
    profile = MOBILE_DEVICES[0]
    for who, routes in ((v4.netops, ["/admin", "/admin/network", "/admin/settings/funnel", "/admin/users"]),
                        (v4.contractor, ["/shared", f"/files/{v4.folder['id']}"])):
        page, watch = funnel_page(profile=profile, scheme=scheme, storage_state=who.state,
                                  viewport={"width": 320, "height": 640})
        for route in routes:
            page.goto(route)
            page.wait_for_load_state("networkidle")
            if route == "/admin/network":
                card = page.locator("#funnel")
                expect(card.locator(".badge").first).to_have_text("Active")
                card.get_by_text("Advanced", exact=True).click()
                note = card.get_by_text(WEAKEN_NOTE)
                expect(note).to_be_visible()
                note.evaluate("el => el.scrollIntoView({block: 'center'})")
                page.wait_for_timeout(100)
            assert_no_overflow(page)
            assert_tap_targets(page, 44, ignore=())
            label = re.sub(r"[^a-z0-9]+", "-", route.strip("/")).strip("-") or "root"
            shot(page, request, f"{label}-{scheme}")
        watch.assert_clean()
