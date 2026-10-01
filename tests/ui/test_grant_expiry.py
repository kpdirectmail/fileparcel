"""The share dialog keeps a grant's expiry when its subject is added again (t-sharing QA): POST /nodes/{id}/grants
replaces the grant, expiry included, so re-adding a person through "Add people, groups or roles" to change their
access level must send the current expiry along instead of making temporary access permanent."""

from __future__ import annotations

import datetime as dt
import re

from conftest import cookie_state
from helpers_roles import roles_admin, unique  # noqa: F401 - roles_admin is a pytest fixture
from playwright.sync_api import expect


def test_readding_keeps_expiry(new_page, server, roles_admin):
    sharer_user, sharer_pw = roles_admin.new_user("sharer")
    guest_user, _ = roles_admin.new_user("dave", display_name=unique("Dave "))
    sharer = server.client()
    sharer.login(sharer_user["username"], sharer_pw)
    folder = unique("Inbox")
    node = sharer.ok("POST", f"/api/v1/nodes/{sharer.root_id()}/folders", {"name": folder})
    until = (dt.datetime.now(dt.timezone.utc) + dt.timedelta(days=2)).replace(microsecond=0)
    sharer.ok("POST", f"/api/v1/nodes/{node['id']}/grants", {"subject_type": "user", "subject_id": guest_user["id"],
                                                             "role": "viewer", "expires_at": until.isoformat()})

    page, watch = new_page(storage_state=cookie_state(server, sharer))
    page.goto("/files")
    page.get_by_text(folder, exact=True).first.click(button="right")
    page.get_by_role("menuitem", name=re.compile(r"^Share", re.I)).first.click()
    dlg = page.get_by_role("dialog", name=re.compile("Share", re.I))
    row = dlg.locator(".grant-row", has_text=guest_user["display_name"])
    expect(row.locator("small")).to_contain_text("until")
    dlg.locator(".grant-add select").select_option("editor")
    dlg.get_by_role("combobox", name="Add people, groups or roles").fill(guest_user["display_name"][:6])
    dlg.get_by_role("option", name=re.compile(re.escape(guest_user["display_name"]))).click()
    expect(page.get_by_text(f"Shared with {guest_user['display_name']}")).to_be_visible()
    expect(row.get_by_role("combobox", name=f"Access for {guest_user['display_name']}")).to_have_value("editor")
    expect(row.locator("small")).to_contain_text("until")

    grants = sharer.ok("GET", f"/api/v1/nodes/{node['id']}/grants")
    items = grants["items"] if isinstance(grants, dict) else grants
    mine = [g for g in items if g["subject_id"] == guest_user["id"]]
    assert len(mine) == 1 and mine[0]["role"] == "editor", mine
    assert mine[0].get("expires_at"), f"the expiry was dropped: {mine[0]}"
    got = dt.datetime.fromisoformat(mine[0]["expires_at"].replace("Z", "+00:00"))
    assert abs((got - until).total_seconds()) < 1, (got, until)
    watch.assert_clean()
