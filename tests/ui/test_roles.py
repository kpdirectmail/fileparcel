"""Roles and permissions in the web app (rbac-final §17.2, DESIGN §13.2, §13.5): administrators create roles and give
them to people, delegates see exactly their part of the Admin area, roles open team folders and shared folders, the
Access card explains what an account can reach, a role change applies to an open page at once, and the roles pages
work on phones at 320 px in light and dark mode.

Set-up goes through the REST API as the owner (helpers_roles.RolesAdmin); every test also fails on console errors
and CSP / Trusted Types violations (watch.assert_clean()).
"""

from __future__ import annotations

import re
import secrets
from dataclasses import dataclass

import pytest
from conftest import (
    MOBILE_DEVICES,
    SEL,
    assert_no_overflow,
    assert_tap_targets,
    confirm_identity,
    cookie_state,
    pick_files,
    shot,
    start_upload,
)
from helpers_roles import (  # noqa: F401 - roles_admin, helpdesk_role and helpdesk_state are pytest fixtures
    FORBIDDEN_HEADING,
    MEMBER_PERMISSIONS,
    SERVER_PERMISSIONS,
    Holder,
    create_role,
    helpdesk_role,
    helpdesk_state,
    role_holder,
    roles_admin,
    team_root,
    unique,
)
from playwright.sync_api import expect

# Keeps every EventSource of the page reachable, so a test can wait until the live event stream is open.
SSE_SCRIPT = """
(() => {
  const Native = window.EventSource;
  if (!Native) return;
  window.__fpEventSources = [];
  window.EventSource = class extends Native {
    constructor(...args) { super(...args); window.__fpEventSources.push(this); }
  };
})();
"""


def admin_group(page):
    """The Admin group of the sidebar (desktop)."""
    return page.locator("#fp-sidebar").get_by_role("group", name="Admin")


def perm_switch(page, perm: str):
    """The switch of one permission on the role page, and the label that gives it its 44 px hit area."""
    row = page.locator(f".perm-row[data-perm='{perm}']")
    return row.get_by_role("switch"), row.locator("label.perm-switch")


def watch_403(page) -> list:
    """Collects the requests the page gets a 403 for, as (method, path) (see forgive_step_ups)."""
    seen: list = []
    page.on("response", lambda r: seen.append((r.request.method, re.sub(r"^https://[^/]+|\?.*$", "", r.url)))
            if r.status == 403 else None)
    return seen


def forgive_step_ups(watch, seen: list, step_up: list[tuple[str, str]]) -> None:
    """A step-up action's first request answers 403 elevation_required, which the browser logs as a failed resource,
    and is repeated once the identity is confirmed. Drops exactly those console errors; a 403 for any request but
    the listed step-up ones (method, path regex) fails."""
    other = [x for x in seen if not any(x[0] == m and re.fullmatch(p, x[1]) for m, p in step_up)]
    assert not other, f"requests refused with 403: {other}"
    for _ in seen:
        hit = next((e for e in watch.errors if "status of 403" in e), None)
        if hit:
            watch.errors.remove(hit)


def open_share_dialog(page, name: str):
    page.get_by_text(name, exact=True).first.click(button="right")
    page.get_by_role("menuitem", name=re.compile(r"^Share", re.I)).first.click()
    return page.get_by_role("dialog", name=re.compile("Share", re.I))


@dataclass
class Finance:
    """A custom role with access through a group and through a folder share (the rbac-final §1 example): everyone
    with it is a member of the group `group`, and may edit `reports`, a folder in the team folder of `company`."""

    role: dict
    group: dict
    company: dict
    reports: str
    holder: Holder


@pytest.fixture(scope="module")
def finance(server, roles_admin) -> Finance:
    role = create_role(roles_admin, unique("Finance"), "member", description="Accounting: the Finance team folder and the reports.")
    group = roles_admin.create_group("Finance")
    roles_admin.role_to_group(role["id"], group["id"], "member")
    # a folder in another group's team folder, shared with the role by a manager of that group
    company = roles_admin.create_group("Company")
    mgr_user, mgr_pw = roles_admin.new_user("mgr")
    roles_admin.add_member(company["id"], mgr_user["id"], "manager")
    mgr = server.client()
    mgr.login(mgr_user["username"], mgr_pw)
    reports = unique("Reports")
    folder = mgr.ok("POST", f"/api/v1/nodes/{team_root(mgr, company['id'])}/folders", {"name": reports})
    mgr.ok("POST", f"/api/v1/nodes/{folder['id']}/grants", {"subject_type": "role", "subject_id": role["id"], "role": "editor"})
    return Finance(role=role, group=group, company=company, reports=reports, holder=role_holder(roles_admin, role, "fin"))


# ---------------------------------------------------------------------------------------------------- desktop
def test_admin_creates_role_and_assigns(new_page, server, roles_admin, request):
    """Admin → Roles → New role, turn on a permission (what it needs comes along), save, give it to someone."""
    target, _ = roles_admin.new_user("assignee")
    name = unique("Helpdesk")
    # a session of its own: the first change asks for step-up, which gives the session a new token
    page, watch = new_page(storage_state=roles_admin.fresh_state())
    refused = watch_403(page)
    page.goto("/admin/roles")
    expect(page.get_by_role("heading", name="Roles", exact=True)).to_be_visible()
    page.get_by_role("button", name="New role").first.click()
    dlg = page.get_by_role("dialog", name="New role")
    dlg.get_by_label("Name").fill(name)
    expect(dlg.locator("input[type=radio][value=member]")).to_be_checked()
    dlg.get_by_role("button", name="Create role").click()
    confirm_identity(page, server.admin_password)  # creating a role is a step-up action
    page.wait_for_url(re.compile(r"/admin/roles/rol_[^/?]+\?tab=permissions$"))
    role_id = re.search(r"/admin/roles/(rol_[^/?]+)", page.url).group(1)
    roles_admin.roles.append(role_id)
    expect(page.get_by_role("heading", name=name)).to_be_visible()

    manage, manage_label = perm_switch(page, "users.manage")
    view, _ = perm_switch(page, "users.view")
    expect(manage).not_to_be_checked()
    expect(view).not_to_be_checked()
    manage_label.click()
    expect(manage).to_be_checked()
    # "View people" is needed by "Manage accounts": turned on, and locked while "Manage accounts" is on
    expect(page.get_by_text("Also turned on: View people (needed by Manage accounts)")).to_be_visible()
    expect(view).to_be_checked()
    expect(view).to_be_disabled()
    expect(page.locator(".perm-row[data-perm='users.view'] .perm-why")).to_have_text("Included with Manage accounts")
    bar = page.get_by_role("region", name="Unsaved changes")
    expect(bar).to_contain_text("2 changes")
    shot(page, request, "permissions")
    bar.get_by_role("button", name="Save changes").click()
    confirm = page.get_by_role("dialog", name=re.compile("Save changes to"))
    # what is added, the high-impact warning included
    expect(confirm.get_by_text("Manage accounts", exact=True)).to_be_visible()
    expect(confirm.get_by_text("Can delete accounts together with their personal files", exact=False)).to_be_visible()
    confirm.get_by_role("button", name="Save changes").click()
    expect(page.get_by_text("Role saved")).to_be_visible()
    expect(bar).to_be_hidden()
    saved = roles_admin.call("GET", f"/api/v1/admin/roles/{role_id}")
    assert sorted(saved["permissions"]) == sorted(MEMBER_PERMISSIONS + ["users.view", "users.manage"]), saved["permissions"]
    assert saved["staff"] is True

    # People → Add people → the new account
    page.get_by_role("tab", name=re.compile(r"^People")).click()
    page.get_by_role("button", name="Add people").click()
    add = page.get_by_role("dialog", name=re.compile("Give people the role"))
    add.get_by_role("combobox", name=re.compile("Person")).fill(target["username"])
    add.get_by_role("option", name=re.compile(re.escape(target["username"]))).click()
    add.get_by_role("button", name="Give role").click()
    sure = page.get_by_role("dialog", name=re.compile(r"^Give .* the role " + re.escape(name)))
    expect(sure.get_by_text("They will see the Admin area.", exact=False)).to_be_visible()
    sure.get_by_role("button", name="Change role").click()
    expect(page.get_by_text(f"now has the role {name}")).to_be_visible()
    add.get_by_role("button", name="Cancel").click()  # the dialog stays open for the next person
    expect(page.locator("#role-panel-people").get_by_text(target["username"]).first).to_be_visible()

    page.goto(f"/admin/users/{target['id']}")
    expect(page.locator("main").get_by_text(name, exact=True).first).to_be_visible()
    assert roles_admin.call("GET", f"/api/v1/admin/users/{target['id']}")["role_id"] == role_id
    shot(page, request, "user")
    assert refused, "creating the role did not ask for step-up"
    forgive_step_ups(watch, refused, [("POST", "/api/v1/admin/roles")])
    watch.assert_clean()


def test_delegate_sees_only_their_areas(new_page, server, roles_admin, helpdesk_role, helpdesk_state, request):
    """A Helpdesk (Manage accounts, Reset sign-in) sees Dashboard, Users, Groups and Roles, and nothing else."""
    contractors = create_role(roles_admin, unique("Contractors"), "guest", ["shares.requests"], delegable=True)
    auditors = create_role(roles_admin, unique("Auditors"), "guest", ["audit.view", "system.view"], delegable=True)
    finance = create_role(roles_admin, unique("Finance"), "member")  # not delegable
    administrator, _ = roles_admin.new_user("adm", role_id="admin")
    member, _ = roles_admin.new_user("plain")

    page, watch = new_page(storage_state=helpdesk_state.state)
    admin_calls: list[str] = []
    page.on("request", lambda r: admin_calls.append(r.url) if "/api/v1/admin/" in r.url else None)
    page.goto("/admin")
    expect(page.get_by_role("heading", name="Your admin areas")).to_be_visible()
    expect(admin_group(page).get_by_role("link")).to_have_text(["Dashboard", "Users", "Groups", "Roles"])
    page.wait_for_load_state("networkidle")
    assert not admin_calls, f"'Your admin areas' asked the server: {admin_calls}"
    shot(page, request, "admin-areas")

    # outside the role: the "not allowed" page, without a request that could only fail
    page.goto("/admin/settings/general")
    expect(page.get_by_role("heading", name=FORBIDDEN_HEADING)).to_be_visible()
    page.wait_for_load_state("networkidle")
    assert not [u for u in admin_calls if "/admin/settings" in u], admin_calls

    # an administrator's account: shown, but nothing to change, and the page says why
    page.goto(f"/admin/users/{administrator['id']}")
    expect(page.get_by_text("This account has server permissions or a role you can’t manage.")).to_be_visible()
    expect(page.get_by_role("button", name="Reset password")).to_have_count(0)
    expect(page.get_by_role("heading", name="Danger zone")).to_have_count(0)
    expect(page.locator("select[name=role_id]")).to_have_count(0)
    shot(page, request, "admin-account")
    # a plain member's account: the Helpdesk manages it
    page.goto(f"/admin/users/{member['id']}")
    expect(page.get_by_role("button", name="Reset password")).to_be_visible()
    expect(page.get_by_role("heading", name="Danger zone")).to_be_visible()
    expect(page.locator("select[name=role_id]")).to_be_enabled()

    # New user: Member, Guest and the roles an administrator lets account managers give (with no server permission
    # the Helpdesk lacks); the others are listed but cannot be chosen, and say why
    page.goto("/admin/users")
    page.get_by_role("button", name="New user").click()
    dlg = page.get_by_role("dialog", name="New user")
    options = dlg.locator("select[name=role_id] option").evaluate_all(
        "els => els.map(o => ({value: o.value, text: o.textContent, disabled: o.disabled}))")
    by_value = {o["value"]: o for o in options}
    assert "admin" not in by_value and "owner" not in by_value, options
    assert not by_value["member"]["disabled"] and not by_value["guest"]["disabled"], options
    roles = {r["id"]: r for r in roles_admin.call("GET", "/api/v1/admin/roles")["items"]}
    mine = set(helpdesk_role["permissions"])
    for o in options:
        role = roles.get(o["value"])
        if o["disabled"] or not role or role["builtin"]:
            continue
        missing = [p for p in role["permissions"] if p in SERVER_PERMISSIONS and p not in mine]
        assert role["delegable"] and not missing, f"the Helpdesk may choose {role['name']} ({missing or 'not delegable'})"
    assert not by_value[contractors["id"]]["disabled"], by_value[contractors["id"]]
    assert by_value[finance["id"]]["disabled"] and "only administrators can give it" in by_value[finance["id"]]["text"]
    assert by_value[auditors["id"]]["disabled"] and "needs permissions you don’t have" in by_value[auditors["id"]]["text"]
    assert by_value[helpdesk_role["id"]]["disabled"], "the Helpdesk role is not delegable"
    shot(page, request, "new-user")
    dlg.get_by_role("button", name="Cancel").click()
    watch.assert_clean()


def test_role_group_membership(new_page, server, admin_state, finance, request, tmp_path):
    """A role that is a member of a group gives its people the group's team folder, where they can upload."""
    page, watch = new_page(storage_state=finance.holder.state)
    page.goto("/files")
    team = page.locator("#fp-sidebar").get_by_role("link", name=finance.group["name"])
    expect(team).to_be_visible()
    team.click()
    root = team_root(finance.holder.api, finance.group["id"])
    page.wait_for_url(re.compile(rf"/files/{re.escape(root)}$"))
    report = tmp_path / f"budget-{secrets.token_hex(2)}.txt"
    report.write_text("Q3 budget\n")
    pick_files(page, lambda: page.get_by_role("button", name=SEL["upload_button"], exact=True).click(), [report])
    start_upload(page)
    expect(page.get_by_text(report.name, exact=True).first).to_be_visible(timeout=30000)
    listed = finance.holder.api.ok("GET", f"/api/v1/nodes/{root}/children")
    items = listed["items"] if isinstance(listed, dict) else listed
    assert any(n["name"] == report.name for n in items), f"{report.name} is not in the team folder: {items}"
    shot(page, request, "team-folder")
    watch.assert_clean()

    # what an administrator sees: the role on the group's page, where the holder's membership comes from, and the
    # holder under the role's filter on Admin → Users
    admin, admin_watch = new_page(storage_state=admin_state)
    admin.goto(f"/admin/groups/{finance.group['id']}")
    roles_card = admin.locator(".card", has=admin.get_by_role("heading", name="Roles in this group (1)"))
    expect(roles_card.get_by_role("link", name=finance.role["name"], exact=True)).to_be_visible()
    member = admin.locator("tr", has_text=finance.holder.username)
    expect(member.get_by_text(f"Role: {finance.role['name']}", exact=True)).to_be_visible()
    expect(member.get_by_role("button", name=f"Remove {finance.holder.username} from the group")).to_be_disabled()
    shot(admin, request, "group")
    admin.goto(f"/admin/users?role_id={finance.role['id']}")
    expect(admin.locator("tbody tr")).to_have_count(1)
    expect(admin.locator("tbody tr").first).to_contain_text(finance.holder.username)
    admin_watch.assert_clean()


def test_share_folder_with_role(new_page, server, roles_admin, request):
    """A member shares a folder with a role ("Can manage"); someone with the role finds it and may share it on."""
    role = create_role(roles_admin, unique("Reviewers"), "member")
    holder = role_holder(roles_admin, role, "rev")
    sharer_user, sharer_pw = roles_admin.new_user("sharer")
    sharer = server.client()
    sharer.login(sharer_user["username"], sharer_pw)
    folder = unique("Briefs")
    sharer.ok("POST", f"/api/v1/nodes/{sharer.root_id()}/folders", {"name": folder})

    page, watch = new_page(storage_state=cookie_state(server, sharer))
    page.goto("/files")
    dlg = open_share_dialog(page, folder)
    dlg.locator(".grant-add select").select_option("manager")
    expect(dlg.get_by_text("Can manage: can also share this item and create links for it.")).to_be_visible()
    box = dlg.get_by_role("combobox", name="Add people, groups or roles")
    box.fill(role["name"])
    option = dlg.get_by_role("option", name=re.compile(re.escape(role["name"])))
    expect(option).to_contain_text("Role · everyone with this role")
    expect(option.locator(".avatar[data-type=role] svg")).to_have_count(1)  # the shield
    shot(page, request, "role-option")
    option.click()
    expect(page.get_by_text(f"Shared with {role['name']}")).to_be_visible()
    row = dlg.locator(".grant-row", has_text=role["name"])
    expect(row.locator(".avatar[data-type=role]")).to_be_visible()
    expect(row.locator("small")).to_have_text("Role")
    expect(row.get_by_role("combobox", name=f"Access for {role['name']}")).to_have_value("manager")
    watch.assert_clean()

    page2, watch2 = new_page(storage_state=holder.state)
    page2.goto("/shared")
    expect(page2.get_by_text(folder, exact=True).first).to_be_visible()
    dlg2 = open_share_dialog(page2, folder)
    # "Can manage": the holder may share it further
    expect(dlg2.get_by_role("combobox", name="Add people, groups or roles")).to_be_visible()
    expect(dlg2.get_by_text("Only people who manage this item", exact=False)).to_have_count(0)
    shot(page2, request, "holder-share")
    watch2.assert_clean()


@pytest.mark.parametrize("profile", ["desktop", "Pixel 7"])
def test_user_access_card(new_page, server, admin_state, finance, request, profile):
    """The Access card lists the role, the groups through the role and the folders shared with the role."""
    page, watch = new_page(profile=profile, storage_state=admin_state)
    page.goto(f"/admin/users/{finance.holder.id}")
    card = page.locator(".card", has=page.get_by_role("heading", name="Access", exact=True))
    expect(card).to_be_visible()
    rid, rname = finance.role["id"], finance.role["name"]
    expect(card.locator(".badge", has_text=rname).first).to_be_visible()
    expect(card.get_by_role("link", name="What can this role do?")).to_have_attribute("href", f"/admin/roles/{rid}")
    expect(card.get_by_text("Nothing on the server — a regular account.")).to_be_visible()
    group = card.locator(".access-row", has=page.get_by_role("link", name=finance.group["name"], exact=True))
    expect(group).to_contain_text("Through role")
    expect(group.get_by_role("link", name=rname, exact=True)).to_have_attribute("href", f"/admin/roles/{rid}")
    expect(group).to_contain_text("Member")
    shared = card.locator(".access-row", has_text=finance.reports)
    expect(shared).to_contain_text("Can edit")
    expect(shared).to_contain_text(f"Role {rname}")
    card.scroll_into_view_if_needed()
    assert_no_overflow(page)
    if profile != "desktop":
        assert_tap_targets(page, 44, ignore=())  # before the screenshot (a full-page shot ends the touch emulation)
    shot(page, request, "access-card")
    watch.assert_clean()


def test_live_demotion(new_page, server, roles_admin, helpdesk_state, request):
    """An administrator takes the Helpdesk role away while the delegate has an admin page open."""
    page, watch = new_page(storage_state=helpdesk_state.state)
    page.add_init_script(SSE_SCRIPT)
    page.goto("/admin/users")
    expect(page.get_by_role("heading", name="Users", exact=True)).to_be_visible()
    expect(admin_group(page)).to_be_visible()
    page.wait_for_function("() => (window.__fpEventSources || []).some((es) => es.readyState === EventSource.OPEN)")

    roles_admin.set_role(helpdesk_state.id, "member")
    expect(page.get_by_text("Your access was changed by an administrator.")).to_be_visible(timeout=5000)
    expect(admin_group(page)).to_have_count(0, timeout=5000)
    # the page on screen is no longer allowed
    expect(page.get_by_role("heading", name=FORBIDDEN_HEADING)).to_be_visible()
    shot(page, request, "demoted")
    page.reload()
    expect(page.get_by_role("heading", name=FORBIDDEN_HEADING)).to_be_visible()
    expect(admin_group(page)).to_have_count(0)
    watch.assert_clean()


def test_invite_link_hidden_for_delegate(new_page, server, roles_admin, admin_state, request):
    """Someone who may invite people does not get the link of an administrator's invitation; an administrator gets the
    link of an invitation for a role with server permissions only after step-up."""
    inviters = create_role(roles_admin, unique("Inviters"), "member", MEMBER_PERMISSIONS + ["invites.manage"])
    holder = role_holder(roles_admin, inviters, "inviter")
    email = f"new-admin-{secrets.token_hex(3)}@example.com"
    made = roles_admin.call("POST", "/api/v1/admin/invites", {"role_id": "admin", "email": email, "max_uses": 1})
    roles_admin.invites.append(made["invite"]["id"])
    assert made["url"], "the administrator gets the link of their own invitation"

    page, watch = new_page(storage_state=holder.state)
    with page.expect_response(lambda r: "/api/v1/admin/invites" in r.url and r.request.method == "GET") as info:
        page.goto("/admin/invites")
    listed = next(i for i in info.value.json()["items"] if i["id"] == made["invite"]["id"])
    assert not listed.get("url"), f"the delegate was sent the link: {listed}"
    row = page.locator("tr", has_text=email)
    expect(row.get_by_text("Link hidden: only administrators can see it")).to_be_visible()
    expect(row.get_by_role("button", name="Copy link")).to_have_count(0)
    row.get_by_role("button", name="Invitation actions").click()
    menu = [t.strip() for t in page.get_by_role("menuitem").all_inner_texts()]
    assert not [m for m in menu if m.startswith("Show link")], menu
    page.keyboard.press("Escape")
    shot(page, request, "invites")
    watch.assert_clean()

    # an invitation for the (staff) custom role, seen by an administrator without step-up: no link yet, but the
    # "Show link" action that asks for it
    staff_email = f"new-inviter-{secrets.token_hex(3)}@example.com"
    staff = roles_admin.call("POST", "/api/v1/admin/invites", {"role_id": inviters["id"], "email": staff_email, "max_uses": 1})
    roles_admin.invites.append(staff["invite"]["id"])
    admin, admin_watch = new_page(storage_state=admin_state)
    admin.goto("/admin/invites")
    row = admin.locator("tr", has_text=staff_email)
    expect(row.locator(".badge:visible", has_text=inviters["name"])).to_have_count(1)  # the Role column
    expect(row.get_by_role("button", name="Copy link")).to_have_count(0)
    expect(row.get_by_text("Link hidden", exact=False)).to_have_count(0)
    row.get_by_role("button", name="Invitation actions").click()
    expect(admin.get_by_role("menuitem", name="Show link (confirm it’s you)")).to_be_visible()
    admin.keyboard.press("Escape")
    admin_watch.assert_clean()


# ---------------------------------------------------------------------------------------------------- phones
@pytest.fixture(params=MOBILE_DEVICES)
def device(request):
    return request.param


@pytest.mark.parametrize("scheme", ["light", "dark"])
def test_roles_mobile(new_page, server, roles_admin, finance, request, device, scheme):
    """/admin/roles, a role's every tab and the New role sheet at 320 × 640: nothing overflows, every target is at
    least 44 px, and the save bar sits fully above the tab bar and saves."""
    page, watch = new_page(profile=device, scheme=scheme, storage_state=roles_admin.elevated_state(),
                           viewport={"width": 320, "height": 640})

    def check(name: str) -> None:
        page.wait_for_load_state("networkidle")
        assert_no_overflow(page)
        assert_tap_targets(page, 44, ignore=())  # before the screenshot (a full-page shot ends the touch emulation)
        shot(page, request, f"{name}-{scheme}")

    page.goto("/admin/roles")
    expect(page.get_by_role("link", name=finance.role["name"]).first).to_be_visible()
    check("roles")
    page.reload()  # the screenshot ended the touch emulation; a navigation brings it back
    page.get_by_role("button", name="New role").first.click()
    sheet = page.get_by_role("dialog", name="New role")
    expect(sheet).to_be_visible()
    check("new-role")
    sheet.get_by_role("button", name="Cancel").click()
    expect(sheet).to_be_hidden()

    rid = finance.role["id"]
    shows = {"permissions": "Manage accounts", "people": finance.holder.username, "folders": finance.reports,
             "groups": finance.group["name"]}
    for tab, text in shows.items():
        page.goto(f"/admin/roles/{rid}?tab={tab}")
        expect(page.locator(f"#role-panel-{tab}").get_by_text(text, exact=True).first).to_be_visible()
        check(f"role-{tab}")

    # an unsaved change: the save bar is above the tab bar, and Save saves
    page.goto(f"/admin/roles/{rid}?tab=permissions")
    switch, label = perm_switch(page, "tokens.create")
    was = switch.is_checked()
    label.click()
    bar = page.get_by_role("region", name="Unsaved changes")
    expect(bar).to_be_visible()
    box, tabbar = bar.bounding_box(), page.locator(SEL["tabbar"]).bounding_box()
    assert box and tabbar, (box, tabbar)
    assert box["y"] >= 0 and box["y"] + box["height"] <= tabbar["y"] + 0.5, f"the save bar {box} is not above the tab bar {tabbar}"
    assert_no_overflow(page)
    assert_tap_targets(page, 44, ignore=())
    shot(page, request, f"savebar-{scheme}")
    bar.get_by_role("button", name="Save changes").click()
    page.get_by_role("dialog", name=re.compile("Save changes to")).get_by_role("button", name="Save changes").click()
    expect(page.get_by_text("Role saved")).to_be_visible()
    expect(bar).to_be_hidden()
    now = roles_admin.call("GET", f"/api/v1/admin/roles/{rid}")["permissions"]
    assert ("tokens.create" in now) is (not was), now
    watch.assert_clean()
