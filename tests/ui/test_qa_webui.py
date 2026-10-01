"""v4 QA pass, area "webui": regression tests for the web UI findings.

Each test names the finding it pins. Set-up goes through the REST API as the owner (helpers_roles.RolesAdmin), which
removes what the module created when it ends.
"""

from __future__ import annotations

import base64
import json
import re
import secrets

import pytest
from conftest import SEL, add_virtual_authenticator, assert_no_overflow, pick_files, shot
from helpers_roles import (  # noqa: F401 - fixtures
    MEMBER_PERMISSIONS,
    create_role,
    helpdesk_role,
    helpdesk_state,
    role_holder,
    roles_admin,
    unique,
)
from playwright.sync_api import expect

LONG_URL = "https://wiki.example.org/handbook/it/accounts/onboarding/contractors-and-temporary-staff-procedures-2026"

def app_module_eval(page, rel: str, body: str, arg=None):
    """Runs `body` (the text of an async function of (m, arg), m being the module js/<rel>) in the page."""
    return page.evaluate(
        f"""async ([rel, arg]) => {{
          const src = document.querySelector('script[type=module][src$="/js/app.js"]').src;
          const m = await import(src.replace(/js\\/app\\.js$/, 'js/' + rel));
          return (async (m, arg) => {{ {body} }})(m, arg);
        }}""", [rel, arg])


@pytest.fixture(scope="module")
def owner_state(roles_admin) -> dict:
    """The owner's session with a step-up window, once per module: /auth/elevate is rate limited per account
    (ratelimit.login_per_min), and the window (10 minutes) outlasts the module."""
    return roles_admin.elevated_state()


def me_id(admin) -> str:
    return admin.call("GET", "/api/v1/me")["user"]["id"]


# ------------------------------------------------------------------------------------------------ admin user page
def test_own_profile_is_read_only_on_the_admin_user_page(new_page, roles_admin, owner_state, request):
    """Finding: changing your own e-mail via Admin → Users → (yourself) skipped step-up and the old-address alert.
    The page now points to Settings → Profile; the server asks for step-up on that route too (usersapi test)."""
    page, watch = new_page(storage_state=owner_state)
    page.goto(f"/admin/users/{me_id(roles_admin)}")
    profile = page.locator("section.card", has=page.get_by_role("heading", name="Profile", exact=True))
    expect(profile.get_by_role("link", name="Settings → Profile")).to_be_visible()
    expect(profile.get_by_role("textbox")).to_have_count(0)
    expect(profile.get_by_role("button", name="Save")).to_have_count(0)
    watch.assert_clean()


def test_reset_sign_in_role_gets_no_refused_buttons(new_page, roles_admin, request):
    """Finding: a role with "Reset sign-in" but not "Manage accounts" was offered resets on an account whose custom
    role is not delegable, which the server always refuses."""
    pw_reset = create_role(roles_admin, unique("PwReset"), "member", MEMBER_PERMISSIONS + ["users.view", "users.credentials"])
    contractor = create_role(roles_admin, unique("Contractor"), "member")  # not delegable
    target, _ = roles_admin.new_user("tgt")
    roles_admin.set_role(target["id"], contractor["id"])
    holder = role_holder(roles_admin, pw_reset, "pwr")
    page, watch = new_page(storage_state=holder.state)
    page.goto(f"/admin/users/{target['id']}")
    expect(page.get_by_text("Your role can’t reset the sign-in of this account.")).to_be_visible()
    for name in ("Reset password", "Reset two-factor", "Sign out everywhere"):
        expect(page.get_by_role("button", name=name)).to_have_count(0)
    watch.assert_clean()


# ------------------------------------------------------------------------------------------------ role page
def test_role_page_tabs_follow_save_and_counts(new_page, roles_admin, owner_state, request):
    """Findings: Ctrl+S with an empty name left the tab strip on the old tab (which then stopped working); saving
    dropped focus to <body>; the Folders/Groups counters did not follow changes."""
    role = create_role(roles_admin, unique("Tabs"), "member")
    group = roles_admin.create_group("Tabs group")
    page, watch = new_page(storage_state=owner_state)
    page.goto(f"/admin/roles/{role['id']}")
    tab = lambda name: page.get_by_role("tab", name=re.compile(f"^{name}"))  # noqa: E731
    name = page.get_by_role("textbox", name=re.compile("^Name"))
    name.fill("")
    tab("People").click()
    expect(page.locator("#role-panel-people")).to_be_visible()
    page.keyboard.press("Control+s")
    expect(tab("Permissions")).to_have_attribute("aria-selected", "true")
    expect(tab("People")).to_have_attribute("aria-selected", "false")
    expect(page.locator("#role-panel-permissions")).to_be_visible()
    assert "tab=permissions" in page.url
    tab("People").click()  # the tab that used to look selected opens its panel again
    expect(page.locator("#role-panel-people")).to_be_visible()
    expect(page.locator("#role-panel-permissions")).to_be_hidden()

    # save: focus lands on the selected tab, not on <body>
    tab("Permissions").click()
    name.fill(role["name"] + " x")
    page.locator(".perm-row[data-perm='audit.view'] label.perm-switch").click()
    page.locator(".savebar").get_by_role("button", name="Save changes").click()
    page.get_by_role("dialog").get_by_role("button", name="Save changes").click()
    expect(page.get_by_text("Role saved")).to_be_visible()
    active = page.evaluate("() => [document.activeElement.getAttribute('role'), document.activeElement.getAttribute('aria-selected')]")
    assert active == ["tab", "true"], f"focus after saving: {active}"

    # the Groups counter follows "Add to a group" at once
    tab("Groups").click()
    page.get_by_role("button", name="Add to a group").click()
    dlg = page.get_by_role("dialog", name=re.compile("Add .* to a group"))
    dlg.get_by_role("combobox", name="Group").select_option(group["id"])
    dlg.get_by_role("button", name="Add to group").click()
    expect(page.locator("#role-panel-groups").get_by_text(group["name"])).to_be_visible()
    expect(tab("Groups").locator(".badge")).to_have_text("1")
    watch.assert_clean()


def test_role_people_menu_follows_the_manage_rules(new_page, roles_admin, helpdesk_state, request):
    """Finding: the People tab offered "Change role…" on accounts the caller may not manage (an owner, for a
    helpdesk delegate), whose submit always failed with 403."""
    page, watch = new_page(storage_state=helpdesk_state.state)
    page.goto("/admin/roles/owner?tab=people")
    page.locator("#role-panel-people button[aria-haspopup=menu]").first.click()
    items = page.get_by_role("menuitem")
    expect(items.first).to_be_visible()
    assert "Change role…" not in items.all_inner_texts()
    watch.assert_clean()


def test_long_role_description_wraps_at_320(new_page, roles_admin, owner_state, request):
    """Finding: a role description with a long URL widened the user page (and role-picker dialogs) at 320 px."""
    role = create_role(roles_admin, unique("Wiki"), "member", MEMBER_PERMISSIONS, description=f"See {LONG_URL}")
    user, _ = roles_admin.new_user("wrap")
    roles_admin.set_role(user["id"], role["id"])
    page, watch = new_page(profile="Pixel 7", storage_state=owner_state, viewport={"width": 320, "height": 640})
    page.goto(f"/admin/users/{user['id']}")
    expect(page.locator(".role-help-text", has_text="wiki.example.org")).to_be_visible()
    assert_no_overflow(page)
    shot(page, request, "user")
    watch.assert_clean()


def test_selected_role_tab_is_scrolled_into_view(new_page, roles_admin, owner_state, request):
    """Finding: /admin/roles/<custom>?tab=groups on a small phone left the selected tab outside the strip."""
    role = create_role(roles_admin, unique("A long role name"), "member")
    page, watch = new_page(profile="Pixel 7", storage_state=owner_state, viewport={"width": 320, "height": 568})
    page.goto(f"/admin/roles/{role['id']}?tab=groups")
    selected = page.get_by_role("tab", name=re.compile("^Groups"))
    expect(selected).to_have_attribute("aria-selected", "true")
    page.wait_for_timeout(200)
    box = selected.evaluate("""(t) => { const s = t.parentElement.getBoundingClientRect(), r = t.getBoundingClientRect();
      return [r.left - s.left, s.right - r.right]; }""")
    assert box[0] >= -1 and box[1] >= -1, f"the selected tab is outside the strip: {box}"
    watch.assert_clean()


# ------------------------------------------------------------------------------------------------ audit wording
def test_failed_sign_in_reads_as_failed(new_page, server, roles_admin, owner_state, request):
    """Findings: the audit list used the success verb for failed and denied entries ("bob signed in bob · failure")
    and named the actor twice."""
    user, _ = roles_admin.new_user("aud")
    r = server.client().request("POST", "/api/v1/auth/login", {"username": user["username"], "password": "wrong password"})
    assert r.status == 401, r.status
    page, watch = new_page(storage_state=owner_state)
    page.goto("/admin/audit?outcome=failure")
    row = page.locator(".audit-line", has_text=user["username"]).first
    expect(row).to_have_text(f"{user['username']} failed to sign in")
    phrases = app_module_eval(page, "pages/admin/common.js", """return [
        m.actionText('auth.login'), m.actionText('auth.mfa', 'failure'), m.actionText('invite.create', 'denied'),
        m.actionText('file.purge', 'failure'), m.actionText('user.password_change', 'failure')];""")
    assert phrases == ["signed in", "failed two-step verification", "was not allowed to create an invitation",
                       "failed to permanently delete", "failed to change their password"], phrases
    watch.assert_clean()


def test_activity_names_file_requests(new_page, roles_admin, owner_state, request):
    """Finding: the Activity page called a file request "a link" and a visitor's upload the owner's own."""
    page, watch = new_page(storage_state=owner_state)
    page.goto("/files")
    texts = app_module_eval(page, "components/activity.js", """return [
        m.describe({action: 'share.create', target_name: 'Inbox', details: {kind: 'request'}}).text,
        m.describe({action: 'share.update', target_name: 'Inbox', details: {kind: 'request', disabled: true}}).text,
        m.describe({action: 'share.update', target_name: 'Inbox', details: {kind: 'request', disabled: false}}).text,
        m.describe({action: 'share.update', target_name: 'x.txt', details: {kind: 'link', disabled: true}}).text,
        m.describe({action: 'share.create', target_name: 'x.txt', details: {kind: 'link'}}).text,
        m.describe({action: 'file.upload', target_name: 'small.txt', actor_via: 'share'}).text,
        m.describe({action: 'file.upload', target_name: 'small.txt', actor_via: 'session'}).text];""")
    assert texts == ["Created a file request for “Inbox”", "Closed the file request for “Inbox”",
                     "Reopened the file request for “Inbox”", "Paused the link for “x.txt”",
                     "Created a link for “x.txt”", "Received “small.txt” through a public upload link",
                     "Uploaded “small.txt”"], texts
    watch.assert_clean()


# ------------------------------------------------------------------------------------------------ small helpers
def test_text_preview_and_upload_retry_helpers(new_page, roles_admin, owner_state, request):
    """Findings: a text preview cut inside a UTF-8 character ended with U+FFFD and Latin-1 text showed as mojibake;
    the public upload page retried a final 507 quota_exceeded for half a minute."""
    page, watch = new_page(storage_state=owner_state)
    page.goto("/files")
    dec = app_module_eval(page, "preview/text.js", """
        const latin1 = m.decodeText(new Uint8Array([0x63, 0x61, 0x66, 0xe9, 0x20, 0x6e, 0x61, 0xef, 0x76, 0x65]), false);
        const utf8 = new TextEncoder().encode('xé');
        const cut = m.decodeText(utf8.subarray(0, utf8.length - 1), true);
        const whole = m.decodeText(new TextEncoder().encode('naïve ✓'), false);
        return [latin1.text, latin1.encoding, cut.text, cut.encoding, whole.text, whole.encoding];""")
    assert dec == ["café naïve", "windows-1252", "x", "utf-8", "naïve ✓", "utf-8"], dec
    retry = app_module_eval(page, "public/share-upload.js", """return [
        m.transientError({status: 507, code: 'quota_exceeded'}), m.transientError({status: 413, code: 'quota_exceeded'}),
        m.transientError({status: 501, code: 'not_implemented'}), m.transientError({status: 503, code: 'unavailable'}),
        m.transientError({status: 0, code: 'network'}), m.transientError({status: 429, code: 'rate_limited'})];""")
    assert retry == [False, False, False, True, True, True], retry
    watch.assert_clean()


def test_invite_page_offers_a_retry_on_429(new_page, request):
    """Finding: a rate-limited invitation look-up was a dead end ("Invitation not available") and said
    "1 seconds"."""
    page, watch = new_page()
    page.route(re.compile(r"/api/v1/auth/invite/"), lambda route: route.fulfill(
        status=429, headers={"Retry-After": "1", "Content-Type": "application/json"},
        body=json.dumps({"error": {"code": "rate_limited", "message": "too many requests"}})))
    page.goto(f"/invite/{secrets.token_urlsafe(24)}")
    expect(page.get_by_text("Please wait 1 second and try again.")).to_be_visible()
    expect(page.get_by_role("button", name="Try again")).to_be_visible()
    watch.errors = [e for e in watch.errors if "429" not in e]  # the refusal itself
    watch.assert_clean()


def test_refused_passkey_sign_in_does_not_claim_it_is_unregistered(new_page, request):
    """Finding: a passkey sign-in the server refused (a temporarily locked account among others) said "That passkey is
    not registered for an account here". The server answers every refused passkey sign-in alike (DESIGN §9.3), so the
    page no longer guesses which it was. Here the authenticator holds a passkey the server has never seen."""
    page, watch = new_page()
    cdp, auth_id = add_virtual_authenticator(page)
    page.goto("/login")
    rp = page.evaluate("() => JSON.parse(document.getElementById('fp-boot').textContent).rp_id || location.hostname")
    key = page.evaluate("""async () => {
        const k = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign']);
        const b = new Uint8Array(await crypto.subtle.exportKey('pkcs8', k.privateKey));
        return btoa(String.fromCharCode(...b)); }""")
    cdp.send("WebAuthn.addCredential", {"authenticatorId": auth_id, "credential": {
        "credentialId": base64.b64encode(secrets.token_bytes(16)).decode(), "isResidentCredential": True, "rpId": rp,
        "privateKey": key, "userHandle": base64.b64encode(secrets.token_bytes(16)).decode(), "signCount": 0}})
    with page.expect_response(re.compile(r"/api/v1/auth/passkey/finish$")) as info:
        page.get_by_role("button", name="Sign in with a passkey").click()
    assert info.value.status == 401, info.value.status
    expect(page.get_by_text(re.compile("^Signing in with this passkey didn’t work"))).to_be_visible()
    expect(page.get_by_text("That passkey is not registered for an account here.")).to_have_count(0)
    watch.errors = [e for e in watch.errors if "401" not in e]  # the refusal itself
    watch.assert_clean()


# ------------------------------------------------------------------------------------------------ roles without sharing
def test_pages_of_features_the_role_lacks(new_page, roles_admin, request):
    """Findings: /requests offered "New file request" to a role without file requests (then 403), /links suggested
    "My files" to a guest, and the share dialog blamed the server for links the role cannot create and searched
    people (403 on every keystroke) for a role without the directory."""
    contractor = create_role(roles_admin, unique("Contractor"), "guest", [])
    holder = role_holder(roles_admin, contractor, "ctr")
    page, watch = new_page(storage_state=holder.state)
    page.goto("/requests")
    expect(page.get_by_text("Your role can’t create file requests.").first).to_be_visible()
    expect(page.get_by_role("button", name="New file request")).to_have_count(0)
    page.goto("/links")
    expect(page.get_by_text("Your role can’t create public links.").first).to_be_visible()
    expect(page.get_by_role("link", name="Go to My files")).to_have_count(0)

    # the share dialog of a folder the role manages
    owner = roles_admin.server.client()
    member, pw = roles_admin.new_user("own")
    owner.login(member["username"], pw)
    folder = owner.ok("POST", f"/api/v1/nodes/{owner.root_id()}/folders", {"name": f"Briefs {secrets.token_hex(3)}"})
    owner.ok("POST", f"/api/v1/nodes/{folder['id']}/grants", {"subject_type": "role", "subject_id": contractor["id"], "role": "manager"})
    lookups = []
    page.on("request", lambda r: lookups.append(r.url) if "/api/v1/users/lookup" in r.url else None)
    page.goto("/shared")
    page.locator(f"[role=option][data-id][aria-label^='{folder['name']},']").first.click(button="right")
    page.get_by_role("menuitem", name=re.compile(r"^Share", re.I)).first.click()
    share = page.get_by_role("dialog", name=re.compile("Share", re.I))
    expect(share.get_by_text("Your role can’t create public links. Ask an administrator if you need one.")).to_be_visible()
    combo = share.get_by_role("combobox", name="Add one of your groups")
    expect(combo).to_have_attribute("placeholder", "Add one of your groups")
    combo.fill("al")
    expect(share.get_by_text(re.compile("Your role can’t search for people or roles"))).to_be_visible()
    assert not lookups, f"searched the people directory without the permission: {lookups}"
    watch.assert_clean()


def test_file_request_limits_are_in_mib(new_page, roles_admin, owner_state, request):
    """Finding: "Maximum file size in MB" was converted as MiB, and 0.001 passed its declared minimum of 1."""
    page, watch = new_page(storage_state=owner_state)
    page.goto("/requests")
    page.get_by_role("button", name="New file request").first.click()
    dlg = page.get_by_role("dialog", name=re.compile("New file request", re.I))
    size = dlg.get_by_label(re.compile(r"^Maximum file size in MiB"))
    expect(size).to_be_visible()
    expect(dlg.get_by_label(re.compile(r"^Total upload limit in GiB"))).to_be_visible()
    size.fill("0.001")
    dlg.get_by_role("button", name="Create request").click()
    expect(dlg.get_by_text("Enter at least 1 MiB, or leave it empty.")).to_be_visible()
    dlg.get_by_role("button", name="Cancel").click()
    watch.assert_clean()


def test_links_only_staff_learn_where_to_manage_links(new_page, roles_admin, request):
    """Finding: a role whose only server permission is "Manage everyone's links" got an Admin area saying there is
    nothing to manage."""
    role = create_role(roles_admin, unique("Links"), "member", MEMBER_PERMISSIONS + ["shares.manage"])
    holder = role_holder(roles_admin, role, "lnk")
    page, watch = new_page(storage_state=holder.state)
    page.goto("/admin")
    expect(page.get_by_role("heading", name="Manage everyone’s links")).to_be_visible()
    expect(page.get_by_text("fileparcel share list --all-users")).to_be_visible()
    expect(page.get_by_text("Nothing to manage here")).to_have_count(0)
    watch.assert_clean()


# ------------------------------------------------------------------------------------------------ maintenance mode
def test_maintenance_mode_is_announced(new_page, roles_admin, owner_state, request):
    """Finding: with maintenance mode on, administrators saw no sign of it anywhere, and the sign-in page said
    nothing before members signed in."""
    roles_admin.call("PATCH", "/api/v1/admin/settings", {"maintenance.enabled": True})
    try:
        anon, anon_watch = new_page()
        anon.goto("/login")
        expect(anon.get_by_text(re.compile("FileParcel is in maintenance mode"))).to_be_visible()
        anon_watch.assert_clean()

        page, watch = new_page(storage_state=owner_state)
        page.goto("/admin")
        banner = page.locator(".app-banners .alert", has_text="Maintenance mode is on")
        expect(banner).to_be_visible()
        expect(page.get_by_text("Maintenance mode", exact=True).first).to_be_visible()  # the health check
        banner.get_by_role("button", name="Turn off").click()
        expect(banner).to_have_count(0)
        views = roles_admin.call("GET", "/api/v1/admin/settings?section=general")
        items = views.get("items", views) if isinstance(views, dict) else views
        assert next(v for v in items if v["key"] == "maintenance.enabled")["value"] is False
        watch.assert_clean()
    finally:
        roles_admin.request("PATCH", "/api/v1/admin/settings", {"maintenance.enabled": False})


# ------------------------------------------------------------------------------------------------ phones
KEYBOARD_JS = """async (px) => {
  const vv = window.visualViewport;
  const frame = () => new Promise((r) => requestAnimationFrame(() => requestAnimationFrame(r)));
  Object.defineProperty(vv, 'height', { configurable: true, get: () => innerHeight - px });
  vv.dispatchEvent(new Event('resize'));
  await frame();
  await new Promise((r) => setTimeout(r, 350));
  const sheet = document.querySelector('dialog[open]');
  const focused = document.activeElement;
  const field = focused.closest('.field') || focused;
  const actions = sheet.querySelector('.dialog-actions');
  const res = { kb: sheet.style.getPropertyValue('--fp-kb'), flag: sheet.hasAttribute('data-kb'), limit: innerHeight - px,
    bottom: sheet.getBoundingClientRect().bottom, sheetTop: sheet.getBoundingClientRect().top,
    fieldTop: field.getBoundingClientRect().top, fieldBottom: field.getBoundingClientRect().bottom,
    actions: actions ? getComputedStyle(actions).flexDirection : null };
  // the submit button: in the sheet's footer, or at the end of a form that scrolls inside the sheet
  const body = sheet.querySelector('.dialog-body');
  body.scrollTop = body.scrollHeight;
  await frame();
  const primary = [...sheet.querySelectorAll(actions ? '.dialog-actions .btn' : '.form-actions .btn')].pop();
  res.primaryTop = primary.getBoundingClientRect().top;
  res.primaryBottom = primary.getBoundingClientRect().bottom;
  delete vv.height;
  vv.dispatchEvent(new Event('resize'));
  await frame();
  res.reset = sheet.style.getPropertyValue('--fp-kb');
  res.flagAfter = sheet.hasAttribute('data-kb');
  return res;
}"""


def check_keyboard(res: dict) -> None:
    assert res["kb"] == "260px" and res["flag"], res
    assert res["bottom"] <= res["limit"] + 1, f"the sheet stays under the keyboard: {res}"
    assert res["fieldTop"] >= res["sheetTop"] - 1 and res["fieldBottom"] <= res["limit"] + 1, f"the field is hidden: {res}"
    assert res["primaryTop"] >= res["sheetTop"] - 1 and res["primaryBottom"] <= res["limit"] + 1, f"the submit button is out of reach: {res}"
    assert res["actions"] in (None, "row"), f"the actions stay stacked while the keyboard is open: {res}"
    assert res["reset"] == "0px" and not res["flagAfter"], res


def test_form_sheets_ride_above_the_keyboard(new_page, roles_admin, owner_state, request):
    """Findings: bottom sheets other than the upload dialog stayed under the on-screen keyboard (New group, New role,
    Confirm your identity), and a small phone kept too little of the form visible between the head and the stacked
    buttons."""
    page, watch = new_page(profile="Pixel 7", storage_state=owner_state, viewport={"width": 320, "height": 568})
    page.goto("/admin/groups")
    assert page.evaluate("() => matchMedia('(pointer: coarse)').matches"), "not emulating a touch device"
    page.get_by_role("button", name=re.compile("New group")).first.click()
    dlg = page.get_by_role("dialog", name=re.compile("New group"))
    dlg.get_by_label(re.compile("^Description")).focus()
    check_keyboard(page.evaluate(KEYBOARD_JS, 260))
    shot(page, request, "new-group")
    dlg.get_by_role("button", name="Cancel").click()

    # a dialog with a footer (prompt): the buttons sit side by side while the keyboard is open
    page.goto("/files")
    page.locator("button[aria-label='Upload or create']").click()
    page.get_by_role("dialog", name="New").get_by_role("button", name="New folder").click()
    folder = page.get_by_role("dialog", name=re.compile("folder", re.I))
    expect(folder.get_by_role("textbox")).to_be_focused()
    res = page.evaluate(KEYBOARD_JS, 260)
    check_keyboard(res)
    assert res["actions"] == "row", res
    shot(page, request, "new-folder")
    folder.get_by_role("button", name="Cancel").click()
    watch.assert_clean()


def test_upload_sheet_keeps_the_field_label_above_the_keyboard(new_page, roles_admin, owner_state, request, tmp_path):
    """Finding: on a 320×568 phone with the keyboard open, the upload dialog's head and stacked full-width buttons
    left 65 px for the form: the password field's label, strength meter and errors were cut off, and "Password" and
    "Confirm password" looked the same."""
    page, watch = new_page(profile="Pixel 7", storage_state=owner_state, viewport={"width": 320, "height": 568})
    page.goto("/files")
    files = []
    for i in range(3):
        f = tmp_path / f"keyboard-{i}.txt"
        f.write_text("from a small phone\n")
        files.append(f)

    def opener():
        page.locator(SEL["fab"]).click()
        page.get_by_role("dialog", name="New").get_by_role("button", name="Upload files").click()

    pick_files(page, opener, files)
    dlg = page.get_by_role("dialog", name=re.compile(r"^Upload"))
    dlg.get_by_text(re.compile(r"bundle into a single", re.I)).first.click()
    dlg.get_by_text("Protect the .zip with a password", exact=True).click()
    for name in ("zip-password", "zip-password-confirm"):
        dlg.locator(f"input[name='{name}']").focus()
        res = page.evaluate(KEYBOARD_JS, 260)
        check_keyboard(res)
        assert res["actions"] == "row", res
        assert res["fieldBottom"] - res["fieldTop"] > 60, f"the field's label is missing: {res}"
    shot(page, request, "upload-password")
    dlg.get_by_role("button", name="Cancel").click()
    watch.assert_clean()


def test_public_folder_rows_give_the_name_the_width(new_page, server, roles_admin, request):
    """Finding: at 320 px the name column of a shared folder was 60 px wide, so similar names could not be told
    apart."""
    member, pw = roles_admin.new_user("pub")
    api = server.client()
    api.login(member["username"], pw)
    folder = api.ok("POST", f"/api/v1/nodes/{api.root_id()}/folders", {"name": f"Holiday {secrets.token_hex(3)}"})
    for i in (1, 2):
        api.upload_small(folder["id"], f"holiday-photo-{i} with a rather long file name.txt", b"x" * 10)
    url = api.ok("POST", "/api/v1/shares", {"kind": "link", "node_id": folder["id"]})["url"]
    page, watch = new_page(profile="Pixel 7", viewport={"width": 320, "height": 640})
    page.goto(url)
    name = page.locator(".share-row-name").first
    expect(name).to_be_visible()
    width = name.evaluate("(el) => el.getBoundingClientRect().width")
    assert width >= 110, f"the name column is only {width} px wide"  # 60 px before
    assert_no_overflow(page)
    shot(page, request, "folder")
    watch.assert_clean()


# ------------------------------------------------------------------------------------------------ admin pages
def test_backup_recipients_name_the_servers_own_key(new_page, roles_admin, owner_state, request):
    """Finding: with backup.recipients empty the Backups page said "none — backups cannot be created", while every
    backup is encrypted to the stored identity's key."""
    before = roles_admin.call("GET", "/api/v1/admin/backups/config")
    roles_admin.call("PATCH", "/api/v1/admin/settings", {"backup.recipients": []})
    try:
        cfg = roles_admin.call("GET", "/api/v1/admin/backups/config")
        page, watch = new_page(storage_state=owner_state)
        page.goto("/admin/backups")
        # init stores a backup identity: its public key is listed, as every backup is encrypted to it
        assert cfg["recipients"] == [] and cfg.get("has_identity") and cfg.get("identity_recipient", "").startswith("age1"), cfg
        expect(page.locator(".chip", has_text=cfg["identity_recipient"])).to_be_visible()
        expect(page.get_by_text("The server’s own backup key (the stored identity): every backup is encrypted to it.")).to_be_visible()
        expect(page.get_by_text("backups cannot be created")).to_have_count(0)
        watch.assert_clean()
    finally:
        roles_admin.request("PATCH", "/api/v1/admin/settings", {"backup.recipients": before.get("recipients") or []})


def test_email_settings_send_a_test_email(new_page, roles_admin, owner_state, request):
    """Finding: nothing in the web app called POST /admin/settings/email/test."""
    page, watch = new_page(storage_state=owner_state)
    page.goto("/admin/settings/email")
    page.get_by_role("button", name="Send test e-mail…").click()
    dlg = page.get_by_role("dialog", name="Send a test e-mail")
    dlg.get_by_label("Send it to").fill("qa@example.org")
    with page.expect_response(re.compile(r"/api/v1/admin/settings/email/test$")) as info:
        dlg.get_by_role("button", name="Send").click()
    # no SMTP server on the test server: the answer is shown, whatever it is
    if info.value.status == 204:
        expect(page.get_by_text(re.compile("Test e-mail sent to qa@example.org"))).to_be_visible()
    else:
        expect(page.get_by_text(re.compile("The test e-mail could not be sent: "))).to_be_visible()
        watch.errors = [e for e in watch.errors if "Failed to load resource" not in e]
    watch.assert_clean()


def test_folder_picker_says_why_a_folder_cannot_be_shared(new_page, server, roles_admin, owner_state, request):
    """Finding: "Give folder access" said "You can't add items to this folder" for a folder the caller may edit
    but not manage."""
    role = create_role(roles_admin, unique("Picker"), "member")
    member, pw = roles_admin.new_user("pick")
    api = server.client()
    api.login(member["username"], pw)
    folder = api.ok("POST", f"/api/v1/nodes/{api.root_id()}/folders", {"name": f"Edit only {secrets.token_hex(3)}"})
    api.ok("POST", f"/api/v1/nodes/{folder['id']}/grants", {"subject_type": "user", "subject_id": me_id(roles_admin), "role": "editor"})
    page, watch = new_page(storage_state=owner_state)
    page.goto(f"/admin/roles/{role['id']}?tab=folders")
    page.get_by_role("button", name="Give folder access").click()
    picker = page.get_by_role("dialog", name=re.compile("Folder for"))
    picker.locator(".fp-picker-row", has_text=folder["name"]).click()
    expect(picker.get_by_text("You don’t manage this folder, so you can’t share it with a role")).to_be_visible()
    expect(picker.get_by_text("You can’t add items to this folder.")).to_have_count(0)
    expect(picker.get_by_role("button", name="Choose this folder")).to_be_disabled()
    picker.get_by_role("button", name="Cancel").click()
    watch.assert_clean()
