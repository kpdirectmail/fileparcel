"""Upload fixes of the v4 QA pass (area "zip"; DESIGN §8.1, §13.6).

  · a folder of many small files ran into the per-IP API rate limit and hundreds of files ended up failed: a 429
    now holds the whole engine for Retry-After, spaces requests out and does not use up a file's tries
  · batches left open elsewhere (another device, cleared site data, a killed CLI upload) were invisible: the panel
    lists them with Discard
  · a bundle with "Replace" onto a folder of the same name was uploaded in full before it failed (twice announced):
    the name is checked when the batch is declared
  · the "ready" toast and the queue named the requested .zip, not the one stored ("name (1).zip")
  · the files of a batch refused as a whole (the quota) still said "Waiting"; the quota message used raw bytes
  · the pre-upload dialog under-counted the folders of nested empty folders
"""

from __future__ import annotations

import re
import secrets
import time

import pytest
from conftest import SEL, cookie_state, pick_files, start_upload
from playwright.sync_api import expect


@pytest.fixture(scope="module")
def admin_api(server):
    api = server.client()
    api.login(server.admin, server.admin_password, server.admin_totp, server.clock)
    return api


@pytest.fixture(scope="module")
def member(server, admin_api):
    """A throw-away member: (user id, api, storage state)."""
    name = "upq" + secrets.token_hex(4)
    pw = "Ui-" + secrets.token_hex(12)
    user = admin_api.ok("POST", "/api/v1/admin/users", {"username": name, "password": pw, "role": "member",
                                                        "display_name": name.title()})
    api = server.client()
    api.login(name, pw)
    yield user["user"]["id"], api, cookie_state(server, api)
    if admin_api.elevate(server.admin_password):
        admin_api.request("DELETE", f"/api/v1/admin/users/{user['user']['id']}")


def upload_button(page):
    return lambda: page.get_by_role("button", name=SEL["upload_button"], exact=True).click()


def upload_menu(page, label):
    """Opens the Upload split button's menu and returns a click for one item."""
    def click():
        page.locator(SEL["upload_more"]).click()
        page.get_by_role("menuitem", name=label, exact=True).click()
    return click


def children(api, folder_id: str) -> dict[str, dict]:
    return {n["name"]: n for n in api.ok("GET", f"/api/v1/nodes/{folder_id}/children?limit=500")["items"]}


def toasts(page, text):
    return page.locator("[aria-label='Notifications']").get_by_text(text)


def goto_files(page):
    """Opens /files once the upload manager is installed: its install() asks for the unfinished batches. Before that
    the Upload button falls back to the basic uploader (no pre-upload dialog), so a quick test would race it."""
    with page.expect_response(lambda r: r.url.endswith("/api/v1/upload-batches") and r.request.method == "GET"):
        page.goto("/files")


def test_rate_limited_upload_waits_for_the_server(new_page, server, member, tmp_path):
    """Every file's first send and seven sends of one file (more than the 6 tries a file has) answer 429: the whole
    engine waits for Retry-After instead of moving on to the next file, and every file arrives."""
    _, api, state = member
    page, watch = new_page(storage_state=state)
    goto_files(page)
    folder = tmp_path / f"many-{secrets.token_hex(3)}"
    folder.mkdir()
    for i in range(8):
        (folder / f"n{i}.txt").write_text(f"file {i}\n")

    seen: set[str] = set()
    arrivals: list[float] = []
    limited: list[float] = []
    stubborn = {"n": 0}
    body = '{"error":{"code":"rate_limited","message":"too many requests, slow down"}}'

    def handle(route):
        ref = re.search(r"[?&]ref=([^&]+)", route.request.url).group(1)
        arrivals.append(time.monotonic())
        first = ref not in seen
        seen.add(ref)
        if first or (ref == "f0" and stubborn["n"] < 7):
            if ref == "f0":
                stubborn["n"] += 1
            limited.append(time.monotonic())
            route.fulfill(status=429, headers={"Retry-After": "1"}, content_type="application/json", body=body)
            return
        route.continue_()

    page.route(re.compile(r"/api/v1/upload-batches/[^/]+/small\?"), handle)
    pick_files(page, upload_menu(page, "Upload folder"), folder, folder=True)
    start_upload(page)
    expect(toasts(page, re.compile(r"Uploaded 8 files"))).to_be_visible(timeout=60000)
    expect(page.get_by_text(re.compile(r"need(s)? attention"))).to_have_count(0)
    assert stubborn["n"] == 7, stubborn
    # held: only the sends already in flight (4 at most) reached the server before the Retry-After of the first 429
    early = [t for t in arrivals if t < limited[0] + 0.9]
    assert len(early) <= 4, f"{len(early)} sends within 0.9 s of the first 429"
    root = api.root_id()
    stored = children(api, children(api, root)[folder.name]["id"])
    assert sorted(stored) == [f"n{i}.txt" for i in range(8)], sorted(stored)
    watch.errors = [e for e in watch.errors if "status of 429" not in e]
    watch.assert_clean()


def test_unfinished_uploads_from_elsewhere_can_be_discarded(new_page, server, admin_api, tmp_path):
    """A batch this browser never saw (declared over the API, like a killed CLI upload) holds most of the quota: the
    refusal says so, the panel lists that batch with Discard, and after discarding it the upload goes through."""
    name = "orph" + secrets.token_hex(4)
    pw = "Ui-" + secrets.token_hex(12)
    uid = admin_api.ok("POST", "/api/v1/admin/users", {"username": name, "password": pw, "role": "member"})["user"]["id"]
    admin_api.ok("PATCH", f"/api/v1/admin/users/{uid}", {"quota_bytes": 10000})
    api = server.client()
    api.login(name, pw)
    try:
        b = api.ok("POST", "/api/v1/upload-batches", {"folder_id": api.root_id(), "mode": "files",
                                                      "files": [{"client_ref": "a", "rel_path": "orphan.bin", "size": 9000}]})
        listed = api.ok("GET", "/api/v1/upload-batches")["items"]
        assert [x["id"] for x in listed] == [b["id"]] and listed[0]["reserved_bytes"] == 9000, listed
        page, watch = new_page(storage_state=cookie_state(server, api))
        goto_files(page)
        card = page.locator(f".upq-resume-card[data-server='{b['id']}']")
        page.wait_for_timeout(500)
        expect(card).to_have_count(0)  # on page load a recent batch is left alone: it may still be running elsewhere
        f = tmp_path / "wanted.bin"
        f.write_bytes(bytes(5000))
        pick_files(page, upload_button(page), [f])
        start_upload(page)
        expect(toasts(page, re.compile(r"unfinished uploads hold 8\.8 KiB"))).to_be_visible(timeout=20000)
        expect(card).to_contain_text("Unfinished upload: 1 file")
        expect(card).to_contain_text("not in this browser")
        card.get_by_role("button", name=re.compile(r"^Discard")).click()
        expect(card).to_have_count(0)
        assert api.ok("GET", "/api/v1/upload-batches")["items"] == []
        page.get_by_role("button", name="Retry this upload").click()
        expect(toasts(page, re.compile(r"^Uploaded “wanted\.bin”"))).to_be_visible(timeout=20000)
        watch.errors = [e for e in watch.errors if "status of 507" not in e]
        watch.assert_clean()
    finally:
        if admin_api.elevate(server.admin_password):
            admin_api.request("DELETE", f"/api/v1/admin/users/{uid}")


def test_bundle_replace_onto_folder_refused_before_upload(new_page, server, member, tmp_path):
    """"Replace" onto a folder of the .zip's name is refused when the batch is declared: nothing is sent, one toast."""
    _, api, state = member
    name = f"folderzip-{secrets.token_hex(3)}.zip"
    api.ok("POST", f"/api/v1/nodes/{api.root_id()}/folders", {"name": name})
    page, watch = new_page(storage_state=state)
    goto_files(page)
    puts = []
    page.on("request", lambda r: puts.append(r.url) if r.method == "PUT" else None)
    f = tmp_path / "one.txt"
    f.write_text("one\n")
    pick_files(page, upload_button(page), [f])
    dlg = page.get_by_role("dialog")
    dlg.get_by_text(re.compile(r"bundle into a single", re.I)).first.click()
    dlg.get_by_label(re.compile(r"name of the .zip", re.I)).fill(name)
    dlg.get_by_label(re.compile(r"if a .zip with that name exists", re.I)).select_option("replace")
    with page.expect_response(lambda r: r.url.endswith("/api/v1/upload-batches") and r.request.method == "POST") as info:
        start_upload(page)
    assert info.value.status == 409
    msg = f"“{name}” is a folder and cannot be replaced by a file"
    expect(toasts(page, msg)).to_have_count(1)
    time.sleep(1)
    expect(toasts(page, msg)).to_have_count(1)
    assert not puts, puts
    watch.errors = [e for e in watch.errors if "status of 409" not in e]
    watch.assert_clean()


def test_zip_ready_names_the_stored_zip(new_page, server, member, tmp_path):
    """"Keep both" numbers the .zip: the toast and the queue name "name (1).zip", ready *in* the folder."""
    _, api, state = member
    name = f"bundle-{secrets.token_hex(3)}.zip"
    api.upload_small(api.root_id(), name, b"an older file of that name")
    page, watch = new_page(storage_state=state)
    goto_files(page)
    f = tmp_path / "one.txt"
    f.write_text("one\n")
    pick_files(page, upload_button(page), [f])
    dlg = page.get_by_role("dialog")
    dlg.get_by_text(re.compile(r"bundle into a single", re.I)).first.click()
    dlg.get_by_label(re.compile(r"name of the .zip", re.I)).fill(name)
    dlg.get_by_label(re.compile(r"if a .zip with that name exists", re.I)).select_option("rename")
    start_upload(page)
    stored = name[:-4] + " (1).zip"
    expect(toasts(page, re.compile(rf"^“{re.escape(stored)}” is ready in “"))).to_be_visible(timeout=60000)
    expect(page.locator(".upq-batch-title", has_text=stored)).to_be_visible()
    watch.assert_clean()


def test_quota_refusal_reads_sizes_and_rows_say_not_uploaded(new_page, server, admin_api, tmp_path):
    """A batch the quota refuses: the message uses readable sizes, and its files say "Not uploaded", not "Waiting"."""
    name = "quota" + secrets.token_hex(4)
    pw = "Ui-" + secrets.token_hex(12)
    user = admin_api.ok("POST", "/api/v1/admin/users", {"username": name, "password": pw, "role": "member"})
    uid = user["user"]["id"]
    admin_api.ok("PATCH", f"/api/v1/admin/users/{uid}", {"quota_bytes": 1000})
    api = server.client()
    api.login(name, pw)
    try:
        page, watch = new_page(storage_state=cookie_state(server, api))
        goto_files(page)
        files = []
        for i in range(2):
            p = tmp_path / f"big{i}.bin"
            p.write_bytes(bytes(2500))
            files.append(p)
        pick_files(page, upload_button(page), files)
        start_upload(page)
        expect(toasts(page, "Upload failed: not enough storage space: the upload needs 4.9 KiB, 1000 B are available")).to_be_visible(timeout=20000)
        rows = page.locator(".upq-item")
        expect(rows).to_have_count(2)
        for i in range(2):
            expect(rows.nth(i).locator(".upq-item-meta")).to_have_text("Not uploaded")
        expect(page.locator(".upq-item-meta", has_text="Waiting")).to_have_count(0)
        watch.errors = [e for e in watch.errors if "status of 507" not in e]
        watch.assert_clean()
    finally:
        if admin_api.elevate(server.admin_password):
            admin_api.request("DELETE", f"/api/v1/admin/users/{uid}")


def test_dialog_counts_every_folder(new_page, server, member, tmp_path):
    """Nested folders that only held system files count with their parents: dropped, nest, nest/inner, junkonly, sub."""
    _, api, state = member
    page, watch = new_page(storage_state=state)
    goto_files(page)
    tree = tmp_path / f"dropped-{secrets.token_hex(3)}"
    (tree / "nest" / "inner").mkdir(parents=True)
    (tree / "nest" / "inner" / ".DS_Store").write_bytes(b"\0")
    (tree / "junkonly").mkdir()
    (tree / "junkonly" / ".DS_Store").write_bytes(b"\0")
    (tree / "sub").mkdir()
    (tree / "sub" / "b.bin").write_bytes(b"b")
    (tree / "a.txt").write_text("a\n")
    pick_files(page, upload_menu(page, "Upload folder"), tree, folder=True)
    dlg = page.get_by_role("dialog")
    expect(dlg.locator(".up-summary")).to_contain_text("2 files · 5 folders")
    start_upload(page)
    expect(toasts(page, re.compile(r"Uploaded 2 files"))).to_be_visible(timeout=30000)
    top = children(api, children(api, api.root_id())[tree.name]["id"])
    assert sorted(top) == ["a.txt", "junkonly", "nest", "sub"], sorted(top)
    assert list(children(api, top["nest"]["id"])) == ["inner"]
    watch.assert_clean()
