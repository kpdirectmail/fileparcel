"""Regression tests for the public pages and the upload scanner (review round 4).

  · ?next= after sign-in / unlock left the site for "/.//evil.example" (dot segments → protocol-relative path)
  · a dropped or picked folder that only held system files (.DS_Store) vanished from the upload
  · the invite page never named the inviter, and the password forms always demanded 12 characters,
    whatever auth.password_min said
  · a second sign-in step with no usable method showed an "Authentication code" box nothing could satisfy
  · a .zip upload skipped by the "Skip the new file" policy was announced as "<name>.zip is ready"
"""

from __future__ import annotations

import json
import re
import secrets
import urllib.parse

from conftest import SEL, pick_files, start_upload
from playwright.sync_api import expect


def _asset_base(page) -> str:
    return page.evaluate("() => JSON.parse(document.getElementById('fp-boot').textContent).asset_base")


def test_next_param_never_leaves_the_site(new_page, server):
    page, watch = new_page()
    page.goto("/login")
    expect(page.get_by_role("button", name="Sign in", exact=True)).to_be_visible()
    cases = ["/.//evil.example/x", "/..//evil.example", "/%2e//evil.example", "/%2e%2e//evil.example",
             "/./\\evil.example", "/a/..//evil.example", "//evil.example", "/\t/evil.example", "/./login", "/api/v1/me"]
    got = page.evaluate("""([base, cases]) => import(base + '/js/public/common.js').then((m) => {
        const out = {};
        for (const c of [...cases, '/files/a?b=c#d']) {
          history.replaceState(null, '', '/login?next=' + encodeURIComponent(c));
          out[c] = m.nextPath('/files');
        }
        history.replaceState(null, '', '/login');
        return out;
      })""", [_asset_base(page), cases])
    for c in cases:
        assert got[c] == "/files", f"next={c!r} → {got[c]!r}"
    kept = urllib.parse.urlsplit(got["/files/a?b=c#d"])
    assert (kept.netloc, kept.path, kept.query, kept.fragment) == (urllib.parse.urlsplit(server.base).netloc, "/files/a", "b=c", "d")
    watch.assert_clean()


def test_folders_of_skipped_system_files_are_kept(new_page, server):
    page, watch = new_page()
    page.goto("/login")
    expect(page.get_by_role("button", name="Sign in", exact=True)).to_be_visible()
    got = page.evaluate("""(base) => Promise.all([import(base + '/js/upload/scan.js'), import(base + '/js/public/share-upload.js')])
      .then(async ([scan, share]) => {
        const file = (name) => ({ isFile: true, isDirectory: false, name, file: (ok) => ok(new File(['x'], name)) });
        const dir = (name, kids) => {
          let read = false;
          return { isFile: false, isDirectory: true, name,
            createReader: () => ({ readEntries: (ok) => { ok(read ? [] : kids); read = true; } }) };
        };
        const drop = (root) => ({ items: [{ kind: 'file', webkitGetAsEntry: () => root }] });
        const tree = dir('Project', [file('a.txt'), dir('assets', [file('.DS_Store')]),
          dir('deep', [dir('inner', [file('Thumbs.db')])]), dir('empty', [])]);
        const s1 = await scan.entriesFromDataTransfer(drop(tree));
        const s2 = await scan.entriesFromDataTransfer(drop(dir('Folder', [file('.DS_Store')])));
        const picked = (rel) => { const f = new File(['y'], rel.split('/').pop()); Object.defineProperty(f, 'webkitRelativePath', { value: rel }); return f; };
        const s3 = scan.entriesFromFiles([picked('Trip/a.jpg'), picked('Trip/assets/.DS_Store')]);
        const s4 = share.entriesFromFiles([picked('Trip/assets/.DS_Store')]);
        return {
          s1: [s1.files.map((f) => f.relPath), [...s1.dirs].sort(), [...s1.skipped].sort()],
          s2: [s2.dirs, s2.roots],
          s3: [s3.files.map((f) => f.relPath), s3.dirs],
          s4: s4.entries.map((e) => [e.relPath, e.kind]),
        };
      })""", _asset_base(page))
    assert got["s1"] == [["Project/a.txt"], ["Project/assets", "Project/deep/inner", "Project/empty"],
                         ["Project/assets/.DS_Store", "Project/deep/inner/Thumbs.db"]], got
    assert got["s2"] == [["Folder"], ["Folder"]], got
    assert got["s3"] == [["Trip/a.jpg"], ["Trip/assets"]], got
    assert got["s4"] == [["Trip/assets", "dir"]], got
    watch.assert_clean()


def test_invite_names_the_inviter_and_follows_password_min(new_page, server):
    api = server.client()
    api.login(server.admin, server.admin_password, server.admin_totp, server.clock)
    api.elevate(server.admin_password)
    inviter = api.ok("GET", "/api/v1/me")["user"]["display_name"]
    path = urllib.parse.urlsplit(api.ok("POST", "/api/v1/admin/invites", {"role": "member"})["url"]).path
    short = "k7Rq2mXv9T"  # 10 random characters: fine for auth.password_min = 8, too short for the default 12

    page, watch = new_page()
    page.goto(path)
    expect(page.get_by_text(re.compile(r"Invited by\s*" + re.escape(inviter)))).to_be_visible()
    page.locator("input[name=password]").fill(short)
    expect(page.locator(".pw-meter")).to_contain_text("Use at least 12 characters")

    api.ok("PATCH", "/api/v1/admin/settings", {"auth.password_min": 8})
    try:
        page.reload()
        page.locator("input[name=username]").fill("inv" + secrets.token_hex(4))
        page.locator("input[name=password]").fill(short)
        page.locator("input[name=confirm]").fill(short)
        expect(page.locator(".pw-meter")).not_to_contain_text("Too short")
        page.get_by_role("button", name="Create account").click()
        page.wait_for_url(re.compile(r"/(files|shared|settings)"))
    finally:
        api.request("DELETE", "/api/v1/admin/settings/auth.password_min")
    watch.assert_clean()


def test_second_step_never_falls_back_to_a_dead_code_form(new_page, server):
    """A sign-in whose only usable second factor is missing here gets an explanation, not an "Authentication code" box."""
    page, watch = new_page()
    state = {"instance": "FileParcel", "setup_needed": False, "passkeys": True, "rp_id": "elsewhere.example",
             "keys_state": "unlocked", "login_message": "", "password_min": 12}
    page.route("**/api/v1/auth/state", lambda r: r.fulfill(status=200, content_type="application/json", body=json.dumps(state)))

    def second_step(result: dict) -> None:
        page.unroute("**/api/v1/auth/login")
        page.route("**/api/v1/auth/login", lambda r: r.fulfill(status=200, content_type="application/json",
                                                                 body=json.dumps({"mfa_required": True, "csrf": "x", **result})))
        page.goto("/login")
        page.get_by_label("Username").fill("someone")
        page.locator("input[type=password]").first.fill("whatever-password")
        page.get_by_role("button", name="Sign in", exact=True).click()

    # no methods at all (passkey-only account, passkeys turned off): the field is omitted from the JSON
    second_step({})
    expect(page.get_by_text("This account cannot be signed in right now")).to_be_visible()
    assert page.locator("input[autocomplete=one-time-code]").count() == 0
    # only a passkey, and this page is not on the RP ID: say where it works
    second_step({"methods": ["passkey"]})
    expect(page.get_by_text("Use your passkey to finish signing in")).to_be_visible()
    assert page.locator("input[autocomplete=one-time-code]").count() == 0
    expect(page.get_by_role("link", name="elsewhere.example")).to_have_attribute("href", re.compile(r"^https://elsewhere\.example[:/]"))
    # recovery codes left: the form, plus the hint before a one-time code is spent
    second_step({"methods": ["recovery", "passkey"]})
    expect(page.get_by_label("Recovery code")).to_be_visible()
    expect(page.get_by_role("link", name="elsewhere.example")).to_be_visible()
    watch.assert_clean()


def test_skipped_zip_is_not_reported_as_ready(new_page, server, alice_state, tmp_path):
    page, watch = new_page(storage_state=alice_state)
    page.goto("/files")
    one = tmp_path / "one.txt"
    one.write_text("one\n")
    name = f"skip-{secrets.token_hex(3)}.zip"

    def upload_zip(conflict: str) -> None:
        pick_files(page, lambda: page.get_by_role("button", name=SEL["upload_button"], exact=True).click(), [one])
        dlg = page.get_by_role("dialog")
        dlg.get_by_text(re.compile(r"bundle into a single", re.I)).first.click()
        dlg.get_by_label(re.compile(r"name of the .zip", re.I)).fill(name)
        dlg.get_by_label(re.compile(r"if a .zip with that name exists", re.I)).select_option(conflict)
        start_upload(page)

    upload_zip("rename")
    expect(page.get_by_text(f"“{name}” is ready").first).to_be_visible(timeout=60000)
    upload_zip("skip")
    expect(page.get_by_text(re.compile(rf"A file named .{re.escape(name)}. already exists.*skipped")).first).to_be_visible(timeout=60000)
    expect(page.get_by_text(re.compile(rf"Skipped . .{re.escape(name)}. already exists")).first).to_be_visible()
    assert page.get_by_text(f"“{name}” is ready").count() <= 1, "the skipped .zip was announced as ready"
    watch.assert_clean()
