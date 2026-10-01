"""Tailscale Funnel and Serve in the web UI (DESIGN §10.6, §13.8) against a fake tailscaled.

The module's server (conftest `funnel_server`) talks to fake_tailscaled.FakeTailscaled only; the fake also plays
tailscaled towards FileParcel (it dials the ingress socket with the proxy headers of an internet visitor). The
tests run in file order: the Funnel is turned on in one test and used by the next ones.
"""

from __future__ import annotations

import hashlib
import json
import os
import re

import pytest
from conftest import api_storage_state, confirm_identity, cookie_state, shot
from fake_tailscaled import FUNNEL_PORTS_CAP, NODE_NAME
from playwright.sync_api import expect

# Another program's entry on this device: FileParcel must leave it as it is.
FOREIGN = {"TCP": {"10000": {"HTTPS": True}},
           "Web": {f"{NODE_NAME}:10000": {"Handlers": {"/": {"Proxy": "http://127.0.0.1:3000"}}}}}


@pytest.fixture(scope="module")
def admin_plain(funnel_server):
    """The administrator's session without step-up (the UI asks for it)."""
    s = funnel_server.server
    return api_storage_state(s, s.admin, s.admin_password, s.admin_totp)


@pytest.fixture(scope="module")
def admin_elevated(funnel_server):
    """The administrator's session with an open step-up window (the Funnel routes need it)."""
    s = funnel_server.server
    api = s.client()
    api.login(s.admin, s.admin_password, s.admin_totp, s.clock)
    assert api.elevate(s.admin_password)
    return cookie_state(s, api)


@pytest.fixture(scope="module")
def alice(funnel_server):
    api = funnel_server.server.client()
    api.login("alice", funnel_server.server.users["alice"])
    return api


def funnel_card(page):
    card = page.locator("#funnel")
    expect(card).to_be_visible()
    return card


def set_funnel(fs, mode: str) -> dict:
    """Turns Funnel on (shares/app) or off through the API."""
    body = {"mode": mode}
    if mode != "off":
        body["confirm"] = "public"
    return fs.admin_api().ok("PUT", "/api/v1/admin/network/funnel", body)


def refresh_status(fs) -> dict:
    """Reads tailscaled again (the status is cached for up to 30 s otherwise)."""
    return fs.admin_api().ok("GET", "/api/v1/admin/network/tailscale?refresh=1")


# ---------------------------------------------------------------- 1. checklist
def test_funnel_card_checklist_and_fix_link(funnel_server, funnel_page, admin_plain, request):
    fs = funnel_server
    fs.fake.set_caps(["https", FUNNEL_PORTS_CAP])  # the tailnet policy does not allow Funnel here
    fs.fake.set_query_feature({"Complete": False, "Text": "Funnel is not enabled",
                               "URL": "https://login.tailscale.com/f/funnel?node=nTESTNODE1CNTRL"})
    try:
        page, watch = funnel_page(storage_state=admin_plain)
        page.goto("/admin/network")
        card = funnel_card(page)
        expect(card.get_by_text("Internet access (Tailscale Funnel)")).to_be_visible()
        expect(card.locator(".badge").first).to_have_text("Off")
        # "Test again" reads tailscaled afresh (the page shows a status up to 30 s old) and asks it where Funnel
        # can be enabled for this device (the link of the failing check; tailscale.com/s/no-funnel otherwise).
        card.get_by_role("button", name="Test again").click()
        row = card.locator("[data-check='tailscale.funnel_attr']")
        expect(row).to_have_attribute("data-status", "fail")
        expect(row).to_contain_text("nodeAttrs")
        fix = row.get_by_role("link", name="How to fix")
        expect(fix).to_have_attribute("href", "https://login.tailscale.com/f/funnel?node=nTESTNODE1CNTRL")
        expect(fix).to_have_attribute("rel", "noopener noreferrer")
        expect(fix).to_have_attribute("target", "_blank")
        # The rest of the prerequisites hold.
        for check in ("tailscale.running", "tailscale.magicdns", "tailscale.https"):
            expect(card.locator(f"[data-check='{check}']")).to_have_attribute("data-status", "ok")
        shot(page, request, "funnel-checklist")
        watch.assert_clean()
    finally:
        fs.fake.set_caps(["https", "funnel", FUNNEL_PORTS_CAP])
        fs.fake.set_query_feature({"Complete": True})
        refresh_status(fs)


# ---------------------------------------------------------------- 2. enable
def test_enable_share_links_only(funnel_server, funnel_page, admin_plain, request):
    fs = funnel_server
    fs.fake.set_config(FOREIGN)
    refresh_status(fs)
    page, watch = funnel_page(storage_state=admin_plain)
    page.goto("/admin/network")
    card = funnel_card(page)
    card.get_by_text("Share links only", exact=True).click()
    card.get_by_role("button", name="Save", exact=True).click()
    dlg = page.get_by_role("dialog", name="Publish on the internet?")
    expect(dlg).to_contain_text(f"https://{NODE_NAME}/")
    shot(page, request, "funnel-publish-confirm")
    dlg.get_by_role("button", name="Publish", exact=True).click()
    confirm_identity(page, fs.server.admin_password)
    expect(card.locator(".badge").first).to_have_text("Active", timeout=20000)
    expect(card.locator(".remote-address input")).to_have_value(f"https://{NODE_NAME}/")
    expect(card.get_by_text("No public request yet", exact=False)).to_be_visible()
    # The access addresses do not list Funnel's share-links-only address (there is no app there).
    expect(page.locator(".url-list")).not_to_contain_text(f"https://{NODE_NAME}/")
    # tailscaled got FileParcel's entry next to the foreign one, written with If-Match.
    cfg = fs.fake.get_config()
    sock = os.path.join(fs.home, "run", "ts-funnel.sock")
    assert cfg["Web"][f"{NODE_NAME}:443"] == {"Handlers": {"/": {"Proxy": f"unix:{sock}"}}}, cfg
    assert cfg["AllowFunnel"] == {f"{NODE_NAME}:443": True}, cfg
    assert cfg["TCP"] == {"443": {"HTTPS": True}, "10000": {"HTTPS": True}}, cfg
    assert cfg["Web"][f"{NODE_NAME}:10000"] == FOREIGN["Web"][f"{NODE_NAME}:10000"], cfg
    assert fs.fake.posts and all(p["if_match"] for p in fs.fake.posts), fs.fake.posts
    shot(page, request, "funnel-active")
    # the first PUT answers 403 elevation_required (the browser logs it); the step-up retries it
    watch.errors = [e for e in watch.errors if "403" not in e]
    watch.assert_clean()


# ---------------------------------------------------------------- 3. share dialog
def test_share_dialog_announces_internet_links(funnel_server, funnel_page, request):
    fs = funnel_server
    if fs.admin_api().ok("GET", "/api/v1/admin/network/tailscale")["funnel"]["state"] != "active":
        set_funnel(fs, "shares")
    page, watch = funnel_page(storage_state=api_storage_state(fs.server, "alice", fs.server.users["alice"]))
    page.goto("/files")
    page.get_by_text("hello.txt", exact=True).first.click(button="right")
    page.get_by_role("menuitem", name=re.compile(r"^Share", re.I)).first.click()
    dlg = page.get_by_role("dialog", name=re.compile("Share", re.I))
    dlg.get_by_role("button", name=re.compile(r"^Create link", re.I)).first.click()
    form = page.get_by_role("dialog", name=re.compile("Create a public link", re.I))
    with page.expect_response(re.compile(r"/api/v1/shares$")) as info:
        form.get_by_role("button", name="Create link", exact=True).click()
    assert info.value.status == 201
    done = page.get_by_role("dialog", name=re.compile("Link created", re.I))
    expect(done.get_by_text("Anyone with this link can open it from the internet (Tailscale Funnel).")).to_be_visible()
    link = done.locator("input[readonly]").first.input_value()
    assert link.startswith(f"https://{NODE_NAME}/s/"), link
    shot(page, request, "share-internet-link")
    watch.assert_clean()


# ---------------------------------------------------------------- 4. last public request
def test_last_public_request(funnel_server, funnel_page, admin_elevated, request):
    fs = funnel_server
    page, watch = funnel_page(storage_state=admin_elevated)
    page.goto("/admin/network")
    card = funnel_card(page)
    expect(card.locator(".badge").first).to_have_text("Active")
    status, _, _ = fs.fake.forward(fs.home, "GET", "/s/" + "A" * 22)  # an unknown link is a public request too
    assert status == 404
    # ingress.changed reloads the card (with the server-sent events of package A; else "Test again" does).
    note = card.get_by_text(re.compile(r"Last public request: just now"))
    try:
        expect(note).to_be_visible(timeout=4000)
    except AssertionError:
        card.get_by_role("button", name="Test again").click()
        expect(note).to_be_visible()
    shot(page, request, "funnel-last-request")
    watch.assert_clean()


# ---------------------------------------------------------------- 5. file request over Funnel
def test_file_request_keeps_the_visitor_cookie(funnel_server, alice):
    fs = funnel_server
    root = alice.root_id()
    share = alice.ok("POST", "/api/v1/shares", {"kind": "request", "node_id": root, "title": "Over the internet",
                                                "allow_upload": True})
    share = share.get("share", share)
    assert share["url"].startswith(f"https://{NODE_NAME}/s/"), share["url"]
    token = share["url"].rstrip("/").rsplit("/", 1)[-1]

    status, hdr, _ = fs.fake.forward(fs.home, "GET", f"/s/{token}/api")
    assert status == 200, status
    cookie = next((c.split(";", 1)[0] for c in hdr.get("set-cookie", "").split("\n") if c.startswith("__Host-fp_uv_")), "")
    assert cookie, f"no visitor cookie: {hdr}"
    # The cookie reaches the server over Funnel: it is not issued again.
    status, hdr, _ = fs.fake.forward(fs.home, "GET", f"/s/{token}/api", headers={"Cookie": cookie})
    assert status == 200 and "__Host-fp_uv_" not in hdr.get("set-cookie", ""), hdr

    data = b"sent over Tailscale Funnel\n"
    body = json.dumps({"mode": "files", "files": [{"client_ref": "u1", "rel_path": "over-funnel.txt", "size": len(data)}]})
    status, _, raw = fs.fake.forward(fs.home, "POST", f"/s/{token}/api/upload-batches", body=body.encode(),
                                     headers={"Cookie": cookie, "Content-Type": "application/json"})
    assert status == 201, raw
    batch = json.loads(raw)["id"]
    status, _, raw = fs.fake.forward(fs.home, "PUT", f"/s/{token}/api/upload-batches/{batch}/small?ref=u1", body=data,
                                     headers={"Cookie": cookie, "Content-Type": "application/octet-stream",
                                              "X-FP-SHA256": hashlib.sha256(data).hexdigest()})
    assert status == 200, raw
    status, _, raw = fs.fake.forward(fs.home, "POST", f"/s/{token}/api/upload-batches/{batch}/complete",
                                     headers={"Cookie": cookie})
    assert status in (200, 202), raw
    # The batch is bound to the visitor: without the cookie it is someone else's.
    status, _, _ = fs.fake.forward(fs.home, "GET", f"/s/{token}/api/upload-batches/{batch}")
    assert status != 200, "the batch answered a visitor without the cookie"
    status, _, _ = fs.fake.forward(fs.home, "GET", f"/s/{token}/api/upload-batches/{batch}", headers={"Cookie": cookie})
    assert status == 200
    kids = alice.ok("GET", f"/api/v1/nodes/{root}/children")["items"]
    assert "over-funnel.txt" in [k["name"] for k in kids], [k["name"] for k in kids]
    log = alice.ok("GET", f"/api/v1/shares/{share['id']}/log")["items"]
    assert any(e.get("ip") == "203.0.113.9" and e.get("action") == "upload" for e in log), log


# ---------------------------------------------------------------- 6. disable
def test_disable_restores_tailscaled(funnel_server, funnel_page, admin_elevated, request):
    fs = funnel_server
    page, watch = funnel_page(storage_state=admin_elevated)
    page.goto("/admin/network")
    card = funnel_card(page)
    expect(card.locator(".badge").first).to_have_text("Active")
    card.get_by_text("Off", exact=True).click()
    card.get_by_role("button", name="Save", exact=True).click()
    dlg = page.get_by_role("dialog", name="Turn Funnel off?")
    dlg.get_by_role("button", name="Turn off", exact=True).click()
    expect(card.locator(".badge").first).to_have_text("Off")
    assert fs.fake.get_config() == FOREIGN, fs.fake.get_config()
    assert not os.path.exists(os.path.join(fs.home, "run", "ts-funnel.sock"))
    shot(page, request, "funnel-off")
    watch.assert_clean()


# ---------------------------------------------------------------- 7. bypass
def test_bypass_entries_are_reported(funnel_server, funnel_page, admin_elevated, request):
    fs = funnel_server
    port = fs.server.port
    fs.fake.set_config({
        "TCP": {"8443": {"HTTPS": True}},
        "Web": {f"{NODE_NAME}:8443": {"Handlers": {"/": {"Proxy": f"https+insecure://localhost:{port}"}}}},
        "AllowFunnel": {f"{NODE_NAME}:8443": True},
        "Foreground": {"session1": {"TCP": {"10000": {"HTTPS": True}},
                                    "Web": {f"{NODE_NAME}:10000": {"Handlers": {"/": {"Proxy": f"http://127.0.0.1:{port}"}}}}}},
    })
    try:
        refresh_status(fs)
        page, watch = funnel_page(storage_state=admin_elevated)
        page.goto("/admin/network")
        alerts = page.locator(".alert--danger", has_text="Tailscale forwards to FileParcel directly")
        expect(alerts).to_have_count(2)
        expect(alerts.first).to_contain_text(f"https+insecure://localhost:{port}")
        expect(alerts.last).to_contain_text("runs in the foreground")
        card = funnel_card(page)
        card.get_by_text(re.compile(r"Other Tailscale Serve and Funnel entries")).click()
        expect(card.get_by_text("Reaches FileParcel directly")).to_have_count(2)
        shot(page, request, "funnel-bypass")

        page.goto("/admin/system")
        row = page.locator(".health-row", has_text="Tailscale forwarding to FileParcel").first
        expect(row).to_be_visible()
        expect(row).to_have_attribute("data-status", "fail")
        shot(page, request, "funnel-bypass-doctor")
        watch.assert_clean()
    finally:
        fs.fake.set_config(FOREIGN)
        refresh_status(fs)


# ---------------------------------------------------------------- 8. saved sign-in rules
def test_full_app_with_saved_admin_switch_asks(funnel_server, funnel_page, admin_elevated, request):
    """"Allow administration over Funnel" stays saved while Funnel is off; publishing the full app again brings it back,
    so the publish dialog lists the admin pages and the typed confirmation is asked (the server treats it as weakening
    sign-in: owners and administrators only)."""
    fs = funnel_server
    api = fs.admin_api()
    api.ok("PUT", "/api/v1/admin/network/funnel", {"mode": "app", "allow_admin": True, "confirm": "public"})
    api.ok("PUT", "/api/v1/admin/network/funnel", {"mode": "off"})
    try:
        page, watch = funnel_page(storage_state=admin_elevated)
        page.goto("/admin/network")
        card = funnel_card(page)
        expect(card.locator(".badge").first).to_have_text("Off")
        card.get_by_text("Full app, sign-in required", exact=True).click()
        card.get_by_role("button", name="Save", exact=True).click()
        dlg = page.get_by_role("dialog", name="Publish on the internet?")
        expect(dlg).to_contain_text("the admin pages")
        dlg.get_by_role("button", name="Publish", exact=True).click()
        typed = page.get_by_role("dialog", name="Weaken sign-in over the internet?")
        expect(typed).to_contain_text("The admin pages will be reachable over the internet address.")
        shot(page, request, "funnel-saved-admin-switch")
        typed.get_by_role("button", name="Cancel", exact=True).click()
        expect(card.locator(".badge").first).to_have_text("Off")
        watch.assert_clean()
    finally:
        api.ok("PUT", "/api/v1/admin/network/funnel", {"mode": "off", "allow_admin": False})
        refresh_status(fs)


# ---------------------------------------------------------------- 9. accounts without two-factor authentication
def test_account_without_2fa_over_funnel(funnel_server):
    """Bug report: a new account (no second factor) could not sign in over Funnel and only read "invalid username or
    password"; signed in at FileParcel's own port, the same session then reached the Funnel address (cookies ignore
    ports). Sign-ins over Funnel still need two-factor authentication, but every failure there now explains it (one
    answer for all failures: it says nothing about the password), and such a session is told it has to set up a
    second factor (it reaches no files until then)."""
    fs = funnel_server
    set_funnel(fs, "app")
    try:
        admin = fs.admin_api()
        name, pw = "newbie" + os.urandom(3).hex(), "Ui-" + os.urandom(12).hex()
        admin.ok("POST", "/api/v1/admin/users", {"username": name, "password": pw, "role": "member"})

        def funnel_login(user, password):
            body = json.dumps({"username": user, "password": password}).encode()
            status, _, raw = fs.fake.forward(fs.home, "POST", "/api/v1/auth/login", body=body,
                                             headers={"Content-Type": "application/json"})
            return status, json.loads(raw)["error"]["message"]

        right = funnel_login(name, pw)
        wrong = funnel_login(name, pw + "x")
        assert right[0] == 401 and right == wrong, f"the answers differ: {right} / {wrong}"
        assert "two-factor authentication" in right[1] and "Settings → Security" in right[1], right

        # signed in at FileParcel's own port, then over the Funnel address with the same cookie
        api = fs.server.client()
        api.login(name, pw)
        cookie = "; ".join(f"{k}={v}" for k, v in api.cookies.items())
        status, _, raw = fs.fake.forward(fs.home, "GET", "/api/v1/me/mfa", headers={"Cookie": cookie})
        mfa = json.loads(raw)
        assert status == 200 and mfa["enroll_required"] and mfa["funnel_required"] and not mfa["required"], mfa
        status, _, raw = fs.fake.forward(fs.home, "GET", "/api/v1/spaces", headers={"Cookie": cookie})
        assert status == 403 and json.loads(raw)["error"]["code"] == "mfa_enroll_required", raw
        # at FileParcel's own port the account works as before
        assert api.ok("GET", "/api/v1/me/mfa")["enroll_required"] is False
        assert api.request("GET", "/api/v1/spaces").status == 200

        # Someone invited by link signs up over the Funnel address: the invitation proves the person, so the sign-in
        # after the account is created is not refused; the session goes straight to setting up a second factor.
        inv = admin.ok("POST", "/api/v1/admin/invites", {"role": "member", "max_uses": 1})
        token = inv["url"].rstrip("/").rsplit("/", 1)[-1]
        invited = "remote" + os.urandom(3).hex()
        body = json.dumps({"username": invited, "password": "Ui-" + os.urandom(12).hex()}).encode()
        status, hdr, raw = fs.fake.forward(fs.home, "POST", f"/api/v1/auth/invite/{token}/accept", body=body,
                                          headers={"Content-Type": "application/json"})
        assert status == 201, raw
        session = "; ".join(c.split(";", 1)[0] for c in hdr.get("set-cookie", "").split("\n") if c.startswith("__Host-"))
        assert session, f"no session after the invitation over Funnel: {hdr}"
        status, _, raw = fs.fake.forward(fs.home, "GET", "/api/v1/me/mfa", headers={"Cookie": session})
        assert status == 200 and json.loads(raw)["enroll_required"], raw
        status, _, raw = fs.fake.forward(fs.home, "GET", "/api/v1/spaces", headers={"Cookie": session})
        assert status == 403 and json.loads(raw)["error"]["code"] == "mfa_enroll_required", raw

        # A shared, multi-use link is no proof of the person: the account is created, but its first sign-in over the
        # Funnel address is refused like any password-only sign-in (it signs in at home or over the VPN first).
        shared = admin.ok("POST", "/api/v1/admin/invites", {"role": "member", "max_uses": 5})
        token = shared["url"].rstrip("/").rsplit("/", 1)[-1]
        body = json.dumps({"username": "shared" + os.urandom(3).hex(), "password": "Ui-" + os.urandom(12).hex()}).encode()
        status, hdr, raw = fs.fake.forward(fs.home, "POST", f"/api/v1/auth/invite/{token}/accept", body=body,
                                          headers={"Content-Type": "application/json"})
        assert status == 201, raw
        assert not any(c.startswith("__Host-fp_session=") for c in hdr.get("set-cookie", "").split("\n")), hdr
    finally:
        set_funnel(fs, "off")
