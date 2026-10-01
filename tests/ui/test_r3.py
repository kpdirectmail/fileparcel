"""Regression tests for the round-3 frontend fixes (DESIGN §13).

Each test pins one bug that shipped in v2:
  · a part upload that fails permanently left the batch stuck in "Uploading…" (no /complete, no Retry/Skip)
  · "Pause all" left per-file rows offering Pause and showing upload progress
  · in-app navigation left modal dialogs and the preview overlay open over the new page
  · ui.default_view / the account preference never reached the file browser
  · a toast raised before a modal opened stayed behind its backdrop (claimToasts() was never called)
  · sign-out left the previous account's unfinished-upload records in localStorage
  · rate-limit messages ignored the Retry-After header and always said "a minute"
  · My links / File requests showed a load error with no way to retry
"""

from __future__ import annotations

import re

from conftest import SEL, api_storage_state, confirm_identity, login, pick_files, start_upload
from playwright.sync_api import expect

BIG = 12 * 1024 * 1024  # > storage.upload_small_max (8 MiB): two parts, the parted path


def _asset_base(page) -> str:
    return page.evaluate("() => JSON.parse(document.getElementById('fp-boot').textContent).asset_base")


def _big_file(tmp_path, name: str = "big.bin"):
    p = tmp_path / name
    with open(p, "wb") as f:
        f.write(b"\0" * BIG)
    return p


# --------------------------------------------------------------------------------------------- uploads
def test_failed_part_ends_the_batch(new_page, server, alice_state, tmp_path):
    """A permanently failing part must settle the batch ("attention"), not hang it for ever."""
    page, watch = new_page(storage_state=alice_state)
    page.goto("/files")
    page.route("**/parts/0", lambda route: route.fulfill(
        status=400, content_type="application/json",
        body='{"error":{"code":"invalid","message":"nope","request_id":"test"}}'))
    pick_files(page, lambda: page.get_by_role("button", name=SEL["upload_button"], exact=True).click(),
               [_big_file(tmp_path)])
    start_upload(page)
    # the batch reaches 'attention': both recovery actions appear and the engine stops being busy
    expect(page.get_by_role("button", name="Skip the failed files and finish")).to_be_visible(timeout=60000)
    expect(page.get_by_role("button", name="Retry failed files")).to_be_visible()
    base = _asset_base(page)
    busy = page.evaluate("(base) => import(base + '/js/upload/engine.js').then((m) => m.engine.busy)", base)
    assert busy is False, "the engine stayed busy (wake lock and the beforeunload guard are held)"


def test_pause_all_marks_every_row_paused(new_page, server, alice_state, tmp_path):
    """Batch pause must show the files as paused, not as uploading with a Pause button."""
    page, watch = new_page(storage_state=alice_state)
    page.goto("/files")
    page.route("**/parts/*", lambda route: None)  # the part never answers: the batch stays busy
    pick_files(page, lambda: page.get_by_role("button", name=SEL["upload_button"], exact=True).click(),
               [_big_file(tmp_path, "paused.bin")])
    start_upload(page)
    page.get_by_role("button", name="Pause this upload").click()
    expect(page.locator(".upq-item .upq-item-meta", has_text="Paused").first).to_be_visible(timeout=15000)
    assert page.get_by_role("button", name="Pause paused.bin").count() == 0, \
        "a paused batch still offered to pause one of its files"
    # the batch paused it, so the batch's "Resume this upload" resumes it (a per-file Resume would do nothing)
    assert page.get_by_role("button", name="Resume paused.bin").count() == 0, \
        "a file paused by its batch offered a per-file Resume"
    expect(page.get_by_role("button", name="Resume this upload")).to_be_visible()
    base = _asset_base(page)
    states = page.evaluate(
        "(base) => import(base + '/js/upload/engine.js')"
        ".then((m) => m.engine.batches.map((b) => b.items.map((it) => [it.state, it.paused])))", base)
    assert states and all(s == "paused" and not user for s, user in states[0]), \
        f"items of a paused batch: {states}"
    page.get_by_role("button", name="Cancel this upload").click()


def test_batch_resume_keeps_user_paused_files_paused(new_page, server, alice_state, tmp_path):
    """Resuming a paused batch must not restart a file the user paused on its own."""
    page, watch = new_page(storage_state=alice_state)
    page.goto("/files")
    page.route("**/parts/*", lambda route: None)  # parts never answer: the batch stays busy
    pick_files(page, lambda: page.get_by_role("button", name=SEL["upload_button"], exact=True).click(),
               [_big_file(tmp_path, "a.bin"), _big_file(tmp_path, "b.bin")])
    start_upload(page)
    page.get_by_role("button", name="Pause a.bin").click(timeout=15000)
    expect(page.get_by_role("button", name="Resume a.bin")).to_be_visible()
    page.get_by_role("button", name="Pause this upload").click()
    page.get_by_role("button", name="Resume this upload").click()
    base = _asset_base(page)
    items_js = ("(base) => import(base + '/js/upload/engine.js').then((m) => Object.fromEntries("
                "m.engine.batches.flatMap((b) => b.items).map((it) => [it.relPath, [it.state, it.paused]])))")
    items = page.evaluate(items_js, base)
    assert items["a.bin"] == ["paused", True], f"a file the user paused after the batch resumed: {items}"
    assert items["b.bin"][0] != "paused" and items["b.bin"][1] is False, f"the rest of the batch: {items}"
    page.get_by_role("button", name="Resume a.bin").click()
    items = page.evaluate(items_js, base)
    assert items["a.bin"][0] != "paused" and items["a.bin"][1] is False, f"per-file Resume: {items}"
    page.get_by_role("button", name="Cancel this upload").click()


# ----------------------------------------------------------------------------------------- navigation
def _palette_to(page, name: str) -> None:
    """Ctrl+K (registered global, so it fires over a modal) → pick a destination."""
    page.keyboard.press("Control+k")
    box = page.get_by_role("combobox", name="Type a command or search")
    expect(box).to_be_visible()
    box.fill(name)
    page.get_by_role("option", name=re.compile(name, re.I)).first.click()


def test_navigation_closes_the_preview(new_page, server, sample_state):
    page, watch = new_page(storage_state=sample_state)
    page.goto("/files")
    page.get_by_text("blue.png", exact=True).first.dblclick()
    expect(page.locator("dialog.pv")).to_be_visible()
    _palette_to(page, "Trash")
    page.wait_for_url(re.compile(r"/trash$"))
    expect(page.get_by_role("heading", name="Trash")).to_be_visible()
    assert page.locator("dialog[open]").count() == 0, "the preview stayed open over the new page"
    # nothing inert in front of the page any more
    top = page.evaluate("() => (document.elementFromPoint(innerWidth / 2, innerHeight / 2) || {}).className || ''")
    assert "pv" not in str(top), f"the preview still covers the page: {top}"
    watch.assert_clean()


def test_navigation_closes_a_modal_dialog(new_page, server, sample_state):
    page, watch = new_page(storage_state=sample_state)
    page.goto("/files")
    page.locator(SEL["upload_more"]).click()
    page.get_by_role("menuitem", name="New folder").click()
    expect(page.get_by_role("dialog")).to_be_visible()
    _palette_to(page, "Trash")
    page.wait_for_url(re.compile(r"/trash$"))
    assert page.locator("dialog[open]").count() == 0, "a modal dialog stayed open over the new page"
    watch.assert_clean()


# ------------------------------------------------------------------------------------- default view
def test_default_file_view_follows_the_server_setting(new_page, server, alice_state):
    api = server.client()
    api.login(server.admin, server.admin_password, server.admin_totp, server.clock)
    api.elevate(server.admin_password)
    api.ok("PATCH", "/api/v1/admin/settings", {"ui.default_view": "grid"})
    try:
        page, watch = new_page(storage_state=alice_state)  # a fresh context: no fp:files-view yet
        page.goto("/files")
        expect(page.locator('.fv[data-mode="grid"]')).to_be_visible(timeout=15000)
        # the toolbar toggle still wins, and only a real choice is stored
        page.get_by_role("button", name=re.compile(r"list view", re.I)).first.click()
        expect(page.locator('.fv[data-mode="list"]')).to_be_visible()
        assert page.evaluate("() => localStorage.getItem('fp:files-view')") == '"list"'
        watch.assert_clean()
    finally:
        api.elevate(server.admin_password)
        api.request("PATCH", "/api/v1/admin/settings", {"ui.default_view": "list"})


# -------------------------------------------------------------------------------------------- toasts
def test_a_toast_stays_clickable_over_a_modal(new_page, server, sample_state):
    page, watch = new_page(storage_state=sample_state)
    page.goto("/files")
    base = _asset_base(page)
    page.evaluate("(base) => import(base + '/js/components/toast.js')"
                  ".then((m) => m.toast.info('still here', {timeout: 0}))", base)
    expect(page.get_by_text("still here")).to_be_visible()
    page.locator(SEL["upload_more"]).click()
    page.get_by_role("menuitem", name="New folder").click()
    expect(page.get_by_role("dialog")).to_be_visible()
    host = page.evaluate("() => document.querySelector('.toasts').parentElement.tagName")
    assert host == "DIALOG", f"the toast region stayed in {host}: it is inert behind the modal backdrop"
    dismiss = page.get_by_role("button", name="Dismiss").first
    box = dismiss.bounding_box()
    hit = page.evaluate("(p) => { const el = document.elementFromPoint(p.x, p.y); return !!el?.closest('.toast'); }",
                        {"x": box["x"] + box["width"] / 2, "y": box["y"] + box["height"] / 2})
    assert hit, "the toast is covered by the modal backdrop"
    dismiss.click()
    page.keyboard.press("Escape")
    watch.assert_clean()


# ------------------------------------------------------------------------------------------ sign-out
def test_sign_out_drops_unfinished_upload_records(new_page, server):
    # its own session: signing out revokes it, and the shared alice_state must keep working
    page, watch = new_page(storage_state=api_storage_state(server, "alice", server.users["alice"]))
    page.goto("/files")
    page.evaluate("""() => localStorage.setItem('fp:uploads', JSON.stringify([{
      key: 'b1', id: 'upb_test', uid: 'nod_someone', apiBase: '/api/v1', folderId: 'nod_x', folderName: 'My files',
      mode: 'files', conflict: 'rename', createdAt: Date.now(), bytes: 30 * 1024 * 1024,
      files: [{relPath: 'secret-plans.bin', size: 30 * 1024 * 1024, mtime: 0, ref: 'f0', id: 'upf_x'}], dirs: []}]))""")
    page.get_by_role("button", name="Account menu").click()
    page.get_by_role("menuitem", name="Sign out").click()
    page.wait_for_url(re.compile(r"/login"))
    left = page.evaluate("() => localStorage.getItem('fp:uploads')")
    assert left is None, f"the previous account's uploads survived the sign-out: {left}"


def test_another_account_never_sees_a_foreign_resume_card(new_page, server, alice_state):
    """Even without a sign-out (an expired session, a second account): records of another user are dropped."""
    page, watch = new_page(storage_state=alice_state)
    page.goto("/files")
    page.evaluate("""() => localStorage.setItem('fp:uploads', JSON.stringify([{
      key: 'b1', id: 'upb_test', uid: 'usr_someone_else', apiBase: '/api/v1', folderId: 'nod_x',
      folderName: 'My files', mode: 'files', conflict: 'rename', createdAt: Date.now(), bytes: 1024,
      files: [{relPath: 'secret-plans.bin', size: 1024, mtime: 0, ref: 'f0', id: 'upf_x'}], dirs: []}]))""")
    page.reload()
    expect(page.get_by_text("Interrupted upload")).to_have_count(0)
    page.wait_for_function("() => localStorage.getItem('fp:uploads') === null")


# ---------------------------------------------------------------------------------------- rate limits
def test_rate_limit_message_uses_retry_after(new_page, server):
    page, watch = new_page()
    page.goto("/login")
    page.route("**/api/v1/auth/login", lambda route: route.fulfill(
        status=429, headers={"Retry-After": "600"}, content_type="application/json",
        body='{"error":{"code":"rate_limited","message":"too many requests, slow down","request_id":"test"}}'))
    page.get_by_label(SEL["login_user"]).fill("alice")
    page.locator(SEL["login_password"]).first.fill("whatever")
    page.get_by_role("button", name=SEL["login_submit"], exact=True).click()
    expect(page.locator("[role=alert], .alert").first).to_contain_text(re.compile(r"10 minutes"))


# --------------------------------------------------------------------------------------------- shares
def test_links_list_can_be_retried(new_page, server, alice_state):
    page, watch = new_page(storage_state=alice_state)
    failing = [True]

    def handler(route):
        if failing[0]:
            route.fulfill(status=500, content_type="application/json",
                          body='{"error":{"code":"internal","message":"something broke","request_id":"test"}}')
        else:
            route.continue_()

    page.route("**/api/v1/shares?**", handler)
    page.goto("/links")
    alert = page.locator("[role=alert]").first
    expect(alert).to_contain_text("Could not load the list")
    retry = alert.get_by_role("button", name="Retry")
    expect(retry).to_be_visible()
    failing[0] = False
    retry.click()
    expect(page.locator("[role=alert]")).to_have_count(0, timeout=15000)


# ------------------------------------------------------------------------------------------ SSE
def test_events_stream_waits_for_the_2fa_enrolment(new_page, server, fresh_user):
    """/api/v1/events is behind RequireFull: opening it while 2FA enrolment is pending polls a 403 for ever."""
    api = server.client()
    api.login(server.admin, server.admin_password, server.admin_totp, server.clock)
    api.elevate(server.admin_password)
    api.ok("PATCH", "/api/v1/admin/settings", {"auth.require_2fa": "all"})
    try:
        name, password = fresh_user("enroll")
        page, watch = new_page()
        hits = []
        page.on("request", lambda r: hits.append(r.url) if "/api/v1/events" in r.url else None)
        login(page, server, name, password)
        page.wait_for_url(re.compile(r"/settings/security"))
        page.wait_for_timeout(4000)  # the old code retried after 2 s, then every 4 s, …
        assert not hits, f"the SPA opened the event stream while 2FA enrolment was pending: {hits}"
        # finishing the enrolment opens it, without a reload
        with page.expect_response(lambda r: r.url.endswith("/api/v1/me/totp/begin") and r.status == 200) as info:
            page.get_by_role("button", name=re.compile(r"authenticator|two-factor|TOTP|set up", re.I)).first.click()
            confirm_identity(page, password)  # enrolling users step up with the password
        secret = info.value.json()["secret"]
        page.locator("input[autocomplete=one-time-code], input[inputmode=numeric]").first.fill(server.clock.code(secret))
        expect(page.get_by_text(re.compile(r"recovery code", re.I)).first).to_be_visible(timeout=15000)
        # the page refreshes /me only once the recovery codes are acknowledged
        page.get_by_role("checkbox", name=re.compile(r"stored it somewhere safe", re.I)).check()
        page.get_by_role("button", name="I have stored it safely").click()
        for _ in range(40):
            if hits:
                break
            page.wait_for_timeout(250)
        assert hits, "the event stream never opened after the second factor was set up"
    finally:
        api.elevate(server.admin_password)
        api.request("PATCH", "/api/v1/admin/settings", {"auth.require_2fa": "admins"})


# --------------------------------------------------------------- round-4 frontend fixes
def test_tracked_job_that_is_already_finished_resolves(new_page, server, admin_state):
    """jobs.subscribe() delivers synchronously: a job that is already terminal must still settle trackJob()."""
    page, watch = new_page(storage_state=admin_state)
    page.goto("/admin/jobs")
    res = page.evaluate("""async (base) => {
      const store = await import(base + '/js/core/store.js');
      const common = await import(base + '/js/pages/admin/common.js');
      const id = 'job_done_' + Math.random().toString(36).slice(2);
      const m = new Map(store.jobs.peek());
      m.set(id, {id, kind: 'backup.create', state: 'succeeded', progress_done: 5, progress_total: 5, updated: Date.now()});
      store.jobs.value = m;
      const t0 = Date.now();
      const out = await Promise.race([
        common.trackJob(id).then((j) => ({outcome: 'resolved', state: j.state}),
                                 (e) => ({outcome: 'rejected', state: String(e && e.message || e)})),
        new Promise((r) => setTimeout(() => r({outcome: 'pending', state: ''}), 8000)),
      ]);
      return {...out, ms: Date.now() - t0};
    }""", _asset_base(page))
    assert res["outcome"] == "resolved" and res["state"] == "succeeded", res
    assert res["ms"] < 500, res
    watch.assert_clean()


def test_appearance_preselects_the_effective_default_view(new_page, server, fresh_user):
    """The radio group must show the value in effect (account preference, else ui.default_view)."""
    api = server.client()
    api.login(server.admin, server.admin_password, server.admin_totp, server.clock)
    api.elevate(server.admin_password)
    api.ok("PATCH", "/api/v1/admin/settings", {"ui.default_view": "grid"})
    try:
        name, pw = fresh_user("view")
        page, watch = new_page(storage_state=api_storage_state(server, name, pw))
        page.goto("/settings/appearance")
        page.wait_for_selector("input[type=radio][value=grid]", state="attached")
        radios = page.evaluate("""() => [...document.querySelectorAll('input[type=radio]')]
            .filter((r) => ['list','grid'].includes(r.value)).map((r) => [r.value, r.checked])""")
        assert [v for v, on in radios if on] == ["grid"], radios
        watch.assert_clean()
    finally:
        api.elevate(server.admin_password)
        api.request("PATCH", "/api/v1/admin/settings", {"ui.default_view": "list"})


def test_required_password_is_visible_in_the_link_dialog(new_page, server, sample_state):
    """sharing.require_password: the toggle arrives on and locked, and a missing password is reported on the field."""
    api = server.client()
    api.login(server.admin, server.admin_password, server.admin_totp, server.clock)
    api.elevate(server.admin_password)
    api.ok("PATCH", "/api/v1/admin/settings", {"sharing.require_password": True})
    try:
        page, watch = new_page(storage_state=sample_state)
        page.goto("/files")
        page.evaluate("""async (base) => {
          const {api, itemsOf} = await import(base + '/js/core/api.js');
          const {spaces} = await import(base + '/js/core/nodes.js');
          const sd = await import(base + '/js/components/share-dialog.js');
          const sp = await spaces();
          const kids = itemsOf(await api.get('/nodes/' + sp[0].root_id + '/children'));
          sd.linkDialog({node: kids.find((n) => n.kind === 'file')});
        }""", _asset_base(page))
        page.wait_for_selector("dialog[open]")
        pw = page.locator("dialog[open] input[type=password]")
        expect(pw).to_be_visible()
        page.get_by_role("button", name="Create link", exact=True).last.click()
        err = page.locator("dialog[open] .field-error, dialog[open] .form-error").filter(
            has_text=re.compile("password", re.I)).first
        expect(err).to_be_visible()
        expect(pw).to_be_visible()
    finally:
        api.elevate(server.admin_password)
        api.request("PATCH", "/api/v1/admin/settings", {"sharing.require_password": False})


def test_forced_password_banner_clears_without_a_reload(new_page, server, fresh_user):
    """The "Please choose a new password" banner must disappear when the flag clears."""
    import secrets

    api = server.client()
    api.login(server.admin, server.admin_password, server.admin_totp, server.clock)
    name, _pw = fresh_user("forced")
    api.elevate(server.admin_password)
    uid = next(u["id"] for u in api.ok("GET", f"/api/v1/admin/users?q={name}")["items"] if u["username"] == name)
    first = "Ui-" + secrets.token_hex(12)
    api.ok("POST", f"/api/v1/admin/users/{uid}/password", {"password": first, "must_change": True})
    page, watch = new_page(storage_state=api_storage_state(server, name, first))
    page.goto("/files")
    expect(page.get_by_text("Please choose a new password")).to_be_visible()
    final = "Ui-" + secrets.token_hex(12)
    boxes = page.locator("input[type=password]")
    boxes.nth(0).fill(first)
    boxes.nth(1).fill(final)
    boxes.nth(2).fill(final)
    page.get_by_role("button", name="Change password", exact=True).last.click()
    expect(page.get_by_text(re.compile("Password changed"))).to_be_visible()
    expect(page.get_by_text("Please choose a new password")).to_have_count(0)
    watch.assert_clean()


def test_instance_rename_applies_to_the_open_session(new_page, server, admin_state):
    """ui.instance_name is not restart-flagged, so the session that saved it must rebrand in place."""
    import secrets

    api = server.client()
    api.login(server.admin, server.admin_password, server.admin_totp, server.clock)
    page, watch = new_page(storage_state=admin_state)
    page.goto("/admin/settings/general")
    name = "Sweep Cloud " + secrets.token_hex(2)
    try:
        page.get_by_label(re.compile("Instance name", re.I)).first.fill(name)
        page.get_by_role("button", name=re.compile(r"^Save", re.I)).first.click()
        expect(page.get_by_text("Settings saved")).to_be_visible()
        expect(page.locator(".brand-name")).to_have_text(name)
        assert name in page.title(), page.title()
        watch.assert_clean()
    finally:
        api.elevate(server.admin_password)
        api.request("DELETE", "/api/v1/admin/settings/ui.instance_name")


def test_a_guest_without_a_destination_is_not_offered_upload(new_page, server):
    """A guest with nowhere to write must not be offered Upload; one with an editor grant keeps it."""
    import secrets

    api = server.client()
    api.login(server.admin, server.admin_password, server.admin_totp, server.clock)
    gname, gpw = "g" + secrets.token_hex(4), "Ui-" + secrets.token_hex(12)
    api.ok("POST", "/api/v1/admin/users",
           {"username": gname, "password": gpw, "role": "guest", "display_name": "Guest"})
    page, watch = new_page(storage_state=api_storage_state(server, gname, gpw))
    page.goto("/shared")
    expect(page.locator(".topbar-upload")).to_be_hidden()
    expect(page.get_by_role("button", name=SEL["upload_button"], exact=True)).to_have_count(0)
    # control: a guest WITH an editable shared folder keeps it
    gid = api.ok("GET", f"/api/v1/admin/users?q={gname}")["items"][0]["id"]
    owner = server.client()
    owner.login("alice", server.users["alice"])
    folder = owner.ok("POST", f"/api/v1/nodes/{owner.root_id()}/folders", {"name": "Drop box " + secrets.token_hex(2)})
    owner.ok("POST", f"/api/v1/nodes/{folder['id']}/grants",
             {"subject_type": "user", "subject_id": gid, "role": "editor"})
    page2, watch2 = new_page(storage_state=api_storage_state(server, gname, gpw))
    page2.goto("/shared")
    expect(page2.locator(".topbar-upload")).to_be_visible()
    watch.assert_clean()
    watch2.assert_clean()
