"""Password-protected .zip on upload (zip-password-final §8, §13.4; DESIGN §8.1, §13.6).

The pre-upload dialog's "Protect the .zip with a password" block: the AES-256 /
ZipCrypto choice (only while storage.zip_legacy_encryption allows ZipCrypto),
the client-side rules, the generator with its "I've saved this password" tick,
a server refusal re-opening the dialog, nothing of the password in web storage,
the lock badges, the share notes, and the phone bottom sheet (320 px, 44 px
targets, 16 px fields, lifted above the on-screen keyboard).

The archives the UI produces are checked byte by byte: the local headers with
`struct` (method 99 + 0x9901 for AES-256, the ZipCrypto flag and version 20),
then extracted with 7-Zip (and Info-ZIP unzip for ZipCrypto) and compared with
the uploaded files; a wrong password must fail. The fixtures and helpers of
this module stay here (plan R33: conftest.py is not C's).
"""

from __future__ import annotations

import contextlib
import hashlib
import io
import re
import secrets
import shutil
import struct
import subprocess
import time
import zipfile

import pytest
from conftest import (
    MOBILE_DEVICES,
    SEL,
    TAP_TARGETS_JS,
    assert_no_overflow,
    cookie_state,
    long_press,
    make_png,
    pick_files,
    shot,
)
from playwright.sync_api import expect

SCHEMES = ["light", "dark"]
AES_LABEL = "Password-protected .zip (AES-256)"
ZIPCRYPTO_LABEL = "Password-protected .zip (ZipCrypto, weak)"
LEGACY_KEY = "storage.zip_legacy_encryption"


# ---------------------------------------------------------------- fixtures
@pytest.fixture(params=MOBILE_DEVICES)
def device(request):
    return request.param


@pytest.fixture(scope="module")
def admin_api(server):
    """One admin session for the whole module (each sign-in spends a TOTP time step)."""
    api = server.client()
    api.login(server.admin, server.admin_password, server.admin_totp, server.clock)
    return api


@pytest.fixture(scope="module")
def zipper(server, admin_api):
    """A throw-away member whose files are only this module's uploads: (username, password, api, storage state)."""
    name = "zip" + secrets.token_hex(4)
    pw = "Ui-" + secrets.token_hex(12)
    user = admin_api.ok("POST", "/api/v1/admin/users", {"username": name, "password": pw, "role": "member",
                                                        "display_name": "Zoë Zipper"})
    api = server.client()
    api.login(name, pw)
    yield name, pw, api, cookie_state(server, api)
    if admin_api.elevate(server.admin_password):
        admin_api.request("DELETE", f"/api/v1/admin/users/{user['user']['id']}")


@contextlib.contextmanager
def setting(api, key: str, value):
    """Changes an admin setting (storage.* needs no step-up) and restores its default afterwards."""
    api.ok("PATCH", "/api/v1/admin/settings", {key: value})
    try:
        yield
    finally:
        api.request("DELETE", f"/api/v1/admin/settings/{key}")


# ---------------------------------------------------------------- helpers
def _uploader_ready(r) -> bool:
    return r.url.endswith("/api/v1/upload-batches") and r.request.method == "GET"


def goto_files(page, path: str = "/files"):
    """Opens `path` once the upload manager is installed: its install() asks for the unfinished batches. Before that
    the Upload button falls back to the basic uploader (no pre-upload dialog), so a quick test would race it (as in
    test_upload_fixes.py)."""
    with page.expect_response(_uploader_ready):
        page.goto(path)


def reload_files(page):
    """page.reload(), waiting for the upload manager like goto_files()."""
    with page.expect_response(_uploader_ready):
        page.reload()


def open_upload_dialog(page, files):
    """Picks `files` with the Upload button (desktop) and returns the pre-upload dialog."""
    pick_files(page, lambda: page.get_by_role("button", name=SEL["upload_button"], exact=True).click(), files)
    dlg = page.get_by_role("dialog", name=re.compile(r"^Upload"))
    expect(dlg).to_be_visible()
    return dlg


def protect(dlg, name: str | None = None):
    """Turns on "Bundle into a single .zip" (optionally naming it) and "Protect the .zip with a password"."""
    dlg.get_by_text(re.compile(r"bundle into a single", re.I)).first.click()
    if name:
        dlg.get_by_label(re.compile(r"name of the .zip", re.I)).fill(name)
    dlg.get_by_text("Protect the .zip with a password", exact=True).click()
    expect(password_input(dlg)).to_be_visible()


def password_input(dlg):
    return dlg.locator("input[name='zip-password']")


def confirm_input(dlg):
    return dlg.locator("input[name='zip-password-confirm']")


def submit(dlg):
    dlg.get_by_role("button", name="Upload", exact=True).click()


def field_error(dlg, input_name: str):
    """The inline error of a components/field.js control."""
    return dlg.locator(f".field:has(input[name='{input_name}']) .field-error")


def file_row(page, name: str):
    return page.locator(f"[role=option][data-id][aria-label^='{name},']")


def wait_ready(page, name: str, protected: bool = True):
    suffix = " (password-protected)" if protected else ""
    expect(page.get_by_text(f"“{name}” is ready{suffix}").first).to_be_visible(timeout=60000)
    expect(file_row(page, name)).to_have_count(1, timeout=15000)


def seven_zip() -> str | None:
    return shutil.which("7z") or shutil.which("7zz")


def extras(buf: bytes) -> dict[int, bytes]:
    out, i = {}, 0
    while i + 4 <= len(buf):
        hid, ln = struct.unpack("<HH", buf[i:i + 4])
        out[hid] = buf[i + 4:i + 4 + ln]
        i += 4 + ln
    return out


def local_headers(data: bytes):
    """(name, version needed, flags, method, extra fields) of every local file header, found through the central
    directory and parsed with struct (zipfile only reads the central directory here)."""
    out = []
    with zipfile.ZipFile(io.BytesIO(data)) as zf:
        for info in zf.infolist():
            off = info.header_offset
            sig, ver, flags, method, _tm, _dt, _crc, _cs, _us, nlen, xlen = struct.unpack("<IHHHHHIIIHH", data[off:off + 30])
            assert sig == 0x04034B50, f"no local header at {off}"
            name = data[off + 30:off + 30 + nlen].decode("utf-8")
            out.append((name, ver, flags, method, extras(data[off + 30 + nlen:off + 30 + nlen + xlen])))
    return out


def check_aes_headers(data: bytes, names: set[str]) -> None:
    seen = set()
    for name, ver, flags, method, ex in local_headers(data):
        seen.add(name)
        assert method == 99, f"{name}: method {method}, want 99 (WinZip AES)"
        assert flags & 1, f"{name}: the encrypted flag is not set"
        assert not flags & 8, f"{name}: a data descriptor instead of a complete local header"
        assert ver == 51, f"{name}: version needed {ver}, want 51"
        ae = ex.get(0x9901)
        assert ae and len(ae) == 7, f"{name}: no AES extra field 0x9901"
        vendor_version, vendor, strength = struct.unpack("<H2sB", ae[:5])
        assert (vendor_version, vendor, strength) == (2, b"AE", 3), f"{name}: 0x9901 is {ae!r}, want AE-2 AES-256"
    assert seen == names, f"entries {seen}, want {names}"


def check_zipcrypto_headers(data: bytes, names: set[str]) -> None:
    seen = set()
    for name, ver, flags, method, ex in local_headers(data):
        seen.add(name)
        assert method in (0, 8), f"{name}: method {method}, want Store or Deflate"
        assert flags & 1, f"{name}: the encrypted flag is not set"
        assert ver == 20, f"{name}: version needed {ver}, want 20"
        assert 0x9901 not in ex, f"{name}: a ZipCrypto entry has the AES extra field"
    assert seen == names, f"entries {seen}, want {names}"


def extract_and_compare(tmp_path, zip_path, password: str, originals: dict[str, bytes], zipcrypto: bool = False) -> None:
    """Extracts with 7-Zip (and unzip for ZipCrypto) and compares every file byte for byte; a wrong password fails.
    `7z t` alone is not enough: AE-2 has no CRC and its MAC covers the ciphertext, so a wrong keystream would pass."""
    tools = []
    seven = seven_zip()
    if seven:
        tools.append(("7z", [seven, "x", "-y", f"-p{password}"], lambda out: [f"-o{out}", str(zip_path)],
                      [seven, "t", "-pwrong-password-123", str(zip_path)]))
    if zipcrypto and shutil.which("unzip"):
        tools.append(("unzip", ["unzip", "-q", "-P", password], lambda out: ["-d", str(out), str(zip_path)],
                      ["unzip", "-tq", "-P", "wrong-password-123", str(zip_path)]))
    if not tools:
        pytest.skip("neither 7z nor unzip is installed: the archive cannot be extracted")
    for tool, cmd, target, wrong in tools:
        out = tmp_path / f"x-{tool}-{secrets.token_hex(3)}"
        out.mkdir()
        r = subprocess.run(cmd + target(out), capture_output=True, text=True, timeout=120)
        assert r.returncode == 0, f"{tool} could not extract the .zip: {r.stdout[-800:]} {r.stderr[-800:]}"
        got = {p.relative_to(out).as_posix(): p.read_bytes() for p in out.rglob("*") if p.is_file()}
        assert set(got) == set(originals), f"{tool} extracted {sorted(got)}, want {sorted(originals)}"
        for name, data in originals.items():
            assert hashlib.sha256(got[name]).digest() == hashlib.sha256(data).digest(), f"{tool}: {name} differs"
        r = subprocess.run(wrong, capture_output=True, text=True, timeout=120)
        assert r.returncode != 0, f"{tool} accepted a wrong password"


def download_row(page, name: str, dest):
    """Downloads a file of the list through its context menu (the <a download> of core/nodes.js)."""
    file_row(page, name).first.click(button="right")
    with page.expect_download() as info:
        page.get_by_role("menuitem", name="Download", exact=True).first.click()
    path = dest / name
    info.value.save_as(str(path))
    return path


def api_protected_zip(api, folder_id: str, name: str, files: dict[str, bytes], password: str, enc: str = "aes256") -> str:
    """Creates a password-protected .zip over the API (POST /upload-batches with the zip fields) and returns its node."""
    batch = api.ok("POST", "/api/v1/upload-batches", {
        "folder_id": folder_id, "mode": "zip", "zip_name": name, "conflict": "rename",
        "zip_encryption": enc, "zip_password": password,
        "files": [{"client_ref": f"f{i}", "rel_path": n, "size": len(d)} for i, (n, d) in enumerate(files.items())]})
    assert "zip_password" not in batch and batch.get("zip_encryption") == enc, batch
    for i, data in enumerate(files.values()):
        api.ok("PUT", f"/api/v1/upload-batches/{batch['id']}/small?ref=f{i}", raw=data,
               headers={"Content-Type": "application/octet-stream", "X-FP-SHA256": hashlib.sha256(data).hexdigest()})
    job_id = api.ok("POST", f"/api/v1/upload-batches/{batch['id']}/complete")["job_id"]
    deadline = time.time() + 60
    while time.time() < deadline:
        job = api.ok("GET", f"/api/v1/jobs/{job_id}")
        if job["state"] in ("succeeded", "failed", "canceled"):
            break
        time.sleep(0.3)
    assert job["state"] == "succeeded", job
    assert password not in str(job), "the job carries the password"
    return job["result"]["node_id"]


SETTLE_JS = """() => Promise.race([
  Promise.allSettled(document.getAnimations()
    .filter((a) => Number.isFinite(a.effect ? a.effect.getComputedTiming().endTime : Infinity))
    .map((a) => a.finished)),
  new Promise((resolve) => { setTimeout(resolve, 2000); })])"""


def settle(page) -> None:
    """Waits for the running (finite) animations - a sheet sliding in - before measuring or taking a screenshot.
    page.evaluate has no timeout of its own, so spinners (infinite) are left out and 2 s is the upper bound."""
    page.evaluate(SETTLE_JS)


def storage_leaks(page, password: str) -> list[str]:
    """Every place of the page's web storage, cookies or form fields that holds `password`."""
    found = page.evaluate("""async (pw) => {
      const found = [];
      for (const [label, st] of [['localStorage', localStorage], ['sessionStorage', sessionStorage]]) {
        for (let i = 0; i < st.length; i += 1) {
          const k = st.key(i) || '';
          if (k.includes(pw) || (st.getItem(k) || '').includes(pw)) found.push(`${label}[${k}]`);
        }
      }
      if (document.cookie.includes(pw)) found.push('document.cookie');
      for (const el of document.querySelectorAll('input, textarea')) {
        if (el.value && el.value.includes(pw)) found.push(`field ${el.name || el.id || el.type}`);
      }
      if (indexedDB.databases) {
        const dbs = await indexedDB.databases();
        if (dbs.length) found.push(`IndexedDB ${dbs.map((d) => d.name).join(', ')}`);
      }
      return found;
    }""", password)
    found += [f"cookie {c['name']}" for c in page.context.cookies() if password in c["value"]]
    return found


# ------------------------------------------------------------------ tests
def test_zip_password_upload(new_page, server, zipper, request, tmp_path):
    """Rules, Enter to the confirmation, the generator and its saved tick; the result is a real AES-256 archive."""
    _, _, _, state = zipper
    page, watch = new_page(storage_state=state)
    page.context.grant_permissions(["clipboard-read", "clipboard-write"], origin=server.base)
    goto_files(page)
    notes = tmp_path / "notes.txt"
    notes.write_bytes(b"Quarterly numbers, very compressible. " * 400)
    photo = make_png(tmp_path / "photo.png", rgb=(12, 120, 200))
    originals = {"notes.txt": notes.read_bytes(), "photo.png": photo.read_bytes()}
    name = f"protected-{secrets.token_hex(3)}.zip"

    dlg = open_upload_dialog(page, [notes, photo])
    expect(dlg.get_by_text("Protect the .zip with a password", exact=True)).to_be_hidden()  # bundle is off
    protect(dlg, name)
    expect(dlg.get_by_role("radio", name=re.compile(r"^AES-256"))).to_be_checked()
    expect(dlg.get_by_role("radio", name=re.compile(r"^ZipCrypto"))).not_to_be_checked()
    pw, pw2 = password_input(dlg), confirm_input(dlg)
    for el in (pw, pw2):  # the FileParcel sign-in must not be offered or overwritten here
        expect(el).to_have_attribute("autocomplete", "new-password")
        expect(el).to_have_attribute("data-1p-ignore", "")
        expect(el).to_have_attribute("data-lpignore", "true")

    # the client rules (the server has the last word)
    pw.fill("Correct-horse-42")
    pw2.fill("Correct-horse-43")
    submit(dlg)
    expect(field_error(dlg, "zip-password-confirm")).to_contain_text("The passwords don’t match.")
    pw.fill("short-1!")
    pw2.fill("short-1!")
    submit(dlg)
    expect(field_error(dlg, "zip-password")).to_contain_text("Use at least 12 characters.")
    # Enter in the first field moves to the confirmation instead of submitting
    pw.fill("Correct-horse-42")
    pw.press("Enter")
    expect(pw2).to_be_focused()
    expect(dlg).to_be_visible()

    # the generator fills both fields; the upload waits until the password is saved
    dlg.get_by_role("button", name="Generate a strong password").click()
    generated = dlg.get_by_label("Generated password")
    expect(generated).to_be_visible()
    secret = generated.input_value()
    assert len(secret) >= 20 and re.fullmatch(r"[\x21-\x7e]+", secret), secret
    assert pw.input_value() == secret and pw2.input_value() == secret
    saved = dlg.get_by_label("I’ve saved this password")
    expect(saved).not_to_be_checked()
    submit(dlg)
    expect(dlg.get_by_text("Save the generated password first (copy it, or tick the box).")).to_be_visible()
    dlg.get_by_role("button", name="Copy password").click()
    expect(page.get_by_text("Password copied to clipboard").first).to_be_visible()
    expect(saved).to_be_checked()
    assert page.evaluate("() => navigator.clipboard.readText()") == secret
    shot(page, request, "dialog")

    submit(dlg)
    expect(dlg).to_be_hidden()
    wait_ready(page, name)
    badge = file_row(page, name).locator(".fv-badge--lock")
    expect(badge).to_have_attribute("title", AES_LABEL)
    expect(badge.get_by_role("img", name=AES_LABEL)).to_have_count(1)
    expect(file_row(page, name)).to_have_attribute("aria-label", re.compile(re.escape(AES_LABEL) + "$"))

    # details: the protection row and the lock of the version
    file_row(page, name).first.click(button="right")
    page.get_by_role("menuitem", name="Details", exact=True).click()
    expect(page.get_by_text("Password · AES-256").first).to_be_visible()
    page.get_by_role("tab", name="Versions").first.click()
    expect(page.locator(".version-lock").first).to_be_visible()
    shot(page, request, "details")

    zip_path = download_row(page, name, tmp_path)
    data = zip_path.read_bytes()
    check_aes_headers(data, set(originals))
    extract_and_compare(tmp_path, zip_path, secret, originals)
    watch.assert_clean()


def test_zip_password_zipcrypto_option(new_page, server, zipper, admin_api, request, tmp_path):
    """ZipCrypto is opt-in with a warning, really produces ZipCrypto, and disappears when the admin turns it off."""
    _, _, api, state = zipper
    page, watch = new_page(storage_state=state)
    goto_files(page)
    doc = tmp_path / "letter.txt"
    doc.write_bytes(b"Dear reader,\n" * 200)
    name = f"legacy-{secrets.token_hex(3)}.zip"
    password = "Legacy-archive-" + secrets.token_hex(4)

    dlg = open_upload_dialog(page, [doc])
    protect(dlg, name)
    warning = dlg.get_by_text(re.compile(r"ZipCrypto only keeps casual eyes out"))
    expect(warning).to_be_hidden()
    dlg.get_by_text("ZipCrypto", exact=True).click()
    expect(dlg.get_by_role("radio", name=re.compile(r"^ZipCrypto"))).to_be_checked()
    expect(warning).to_be_visible()
    dlg.get_by_text("Which apps can open it?").click()
    expect(dlg.get_by_text("File Explorer")).to_be_visible()
    shot(page, request, "zipcrypto")
    password_input(dlg).fill(password)
    confirm_input(dlg).fill(password)
    submit(dlg)
    wait_ready(page, name)
    expect(file_row(page, name).locator(".fv-badge--lock")).to_have_attribute("title", ZIPCRYPTO_LABEL)
    file_row(page, name).first.click(button="right")
    page.get_by_role("menuitem", name="Details", exact=True).click()
    expect(page.get_by_text("Password · ZipCrypto (weak)").first).to_be_visible()

    node_id = file_row(page, name).first.get_attribute("data-id")
    r = api.request("GET", f"/api/v1/nodes/{node_id}/content")
    assert r.status == 200, r.status
    check_zipcrypto_headers(r.body, {"letter.txt"})
    zip_path = tmp_path / name
    zip_path.write_bytes(r.body)
    extract_and_compare(tmp_path, zip_path, password, {"letter.txt": doc.read_bytes()}, zipcrypto=True)

    with setting(admin_api, LEGACY_KEY, False):
        reload_files(page)
        dlg = open_upload_dialog(page, [doc])
        protect(dlg)
        expect(dlg.get_by_role("radio")).to_have_count(0)
        expect(dlg.get_by_text("ZipCrypto", exact=True)).to_have_count(0)
        expect(dlg.get_by_text("Which apps can open it?")).to_be_visible()
        dlg.get_by_role("button", name="Cancel").click()
        expect(dlg).to_be_hidden()
    watch.assert_clean()


def test_zip_password_not_persisted(new_page, server, zipper, request, tmp_path):
    """The password never reaches web storage, cookies or IndexedDB; the resume record keeps the method only."""
    _, _, _, state = zipper
    page, watch = new_page(storage_state=state)
    goto_files(page)
    f = tmp_path / "private.txt"
    f.write_text("private\n")
    name = f"private-{secrets.token_hex(3)}.zip"
    password = "Never-stored-" + secrets.token_hex(6)

    held = []
    page.route(re.compile(r"/api/v1/upload-batches/[^/]+/complete$"), lambda route: held.append(route))
    dlg = open_upload_dialog(page, [f])
    protect(dlg, name)
    password_input(dlg).fill(password)
    confirm_input(dlg).fill(password)
    submit(dlg)
    expect(dlg).to_be_hidden()
    # the batch is declared and waits for /complete: the resume record is written, without the password
    page.wait_for_function("() => (localStorage.getItem('fp:uploads') || '').includes('zipEncryption')", timeout=20000)
    records = page.evaluate("() => JSON.parse(localStorage.getItem('fp:uploads'))")
    rec = next(r for r in records if r.get("zipName") == name)
    assert rec["zipEncryption"] == "aes256", rec
    assert not any("password" in k.lower() for k in rec), rec
    assert not storage_leaks(page, password), storage_leaks(page, password)
    for route in held:
        route.continue_()
    page.unroute(re.compile(r"/api/v1/upload-batches/[^/]+/complete$"))
    wait_ready(page, name)
    assert not storage_leaks(page, password), storage_leaks(page, password)
    assert name not in (page.evaluate("() => localStorage.getItem('fp:uploads') || ''") or "")

    # a new dialog starts empty (nothing is remembered, not even the method)
    dlg = open_upload_dialog(page, [f])
    protect(dlg)
    expect(password_input(dlg)).to_have_value("")
    expect(confirm_input(dlg)).to_have_value("")
    expect(dlg.get_by_role("radio", name=re.compile(r"^AES-256"))).to_be_checked()
    dlg.get_by_role("button", name="Cancel").click()
    expect(dlg).to_be_hidden()
    assert not storage_leaks(page, password)
    watch.assert_clean()


def test_zip_password_rejected_reopens_dialog(new_page, server, zipper, request, tmp_path):
    """A password only the server refuses (common-password list) re-opens the dialog with every choice kept."""
    _, _, _, state = zipper
    page, watch = new_page(storage_state=state)
    goto_files(page)
    f = tmp_path / "report.txt"
    f.write_text("report\n")
    name = f"report-{secrets.token_hex(3)}.zip"

    dlg = open_upload_dialog(page, [f])
    protect(dlg, name)
    dlg.get_by_label(re.compile(r"if a .zip with that name exists", re.I)).select_option("replace")
    password_input(dlg).fill("Password1234!")  # passes the client rules; "password" after affix stripping
    confirm_input(dlg).fill("Password1234!")
    with page.expect_response(lambda r: r.url.endswith("/api/v1/upload-batches") and r.request.method == "POST") as info:
        submit(dlg)
    assert info.value.status == 422
    again = page.get_by_role("dialog", name=re.compile(r"^Upload"))
    expect(again).to_be_visible()
    expect(field_error(again, "zip-password")).to_contain_text(re.compile(r"this password is too common", re.I))
    expect(again.get_by_label(re.compile(r"name of the .zip", re.I))).to_have_value(name)
    expect(again.get_by_role("switch", name="Protect the .zip with a password")).to_be_checked()
    expect(again.get_by_role("switch", name="Bundle into a single .zip")).to_be_checked()
    expect(again.get_by_label(re.compile(r"if a .zip with that name exists", re.I))).to_have_value("replace")
    expect(password_input(again)).to_have_value("")
    expect(password_input(again)).to_be_focused()
    expect(page.get_by_text(re.compile(r"Upload failed"))).to_have_count(0)
    expect(page.locator(".upq-batch")).to_have_count(0)
    shot(page, request, "refused")

    good = "Better-" + secrets.token_hex(6)
    password_input(again).fill(good)
    confirm_input(again).fill(good)
    submit(again)
    expect(again).to_be_hidden()
    wait_ready(page, name)
    watch.errors = [e for e in watch.errors if "status of 422" not in e]  # the refusal itself
    watch.assert_clean()


def test_zip_encryption_rejected_hides_zipcrypto(new_page, server, zipper, admin_api, request, tmp_path):
    """Stale boot data: ZipCrypto was turned off after the page loaded → the dialog comes back with AES-256 only."""
    _, _, _, state = zipper
    page, watch = new_page(storage_state=state)
    goto_files(page)
    f = tmp_path / "old.txt"
    f.write_text("old\n")
    dlg = open_upload_dialog(page, [f])
    protect(dlg, f"old-{secrets.token_hex(3)}.zip")
    expect(dlg.get_by_role("radio", name=re.compile(r"^ZipCrypto"))).to_have_count(1)
    with setting(admin_api, LEGACY_KEY, False):
        dlg.get_by_text("ZipCrypto", exact=True).click()
        password = "Stale-boot-" + secrets.token_hex(5)
        password_input(dlg).fill(password)
        confirm_input(dlg).fill(password)
        submit(dlg)
        again = page.get_by_role("dialog", name=re.compile(r"^Upload"))
        expect(again.get_by_text("ZipCrypto is turned off on this server; use AES-256.")).to_be_visible()
        expect(again.get_by_role("radio", name=re.compile(r"^AES-256"))).to_be_checked()
        expect(again.get_by_role("radio", name=re.compile(r"^ZipCrypto"))).to_have_count(0)
        expect(page.get_by_text(re.compile(r"Upload failed"))).to_have_count(0)
        shot(page, request, "zipcrypto-refused")
        again.get_by_role("button", name="Cancel").click()
        expect(again).to_be_hidden()
        # later dialogs of this page no longer offer ZipCrypto either
        dlg = open_upload_dialog(page, [f])
        protect(dlg)
        expect(dlg.get_by_role("radio")).to_have_count(0)
        dlg.get_by_role("button", name="Cancel").click()
    watch.errors = [e for e in watch.errors if "status of 422" not in e]  # the refusal itself
    watch.assert_clean()


DIALOG_TAP_TARGETS_JS = TAP_TARGETS_JS.replace(
    "document.querySelectorAll(sel)", "document.querySelector('dialog[open]').querySelectorAll(sel)")


@pytest.mark.parametrize("scheme", SCHEMES)
def test_mobile_zip_password_dialog(new_page, server, zipper, request, device, scheme, tmp_path):
    """Phone bottom sheet at 320 px: no overflow, 44 px targets, 16 px fields, lifted above the keyboard."""
    _, _, _, state = zipper
    page, watch = new_page(profile=device, scheme=scheme, storage_state=state, viewport={"width": 320, "height": 640})
    goto_files(page)
    assert page.evaluate("() => matchMedia('(pointer: coarse)').matches"), "not emulating a touch device"
    f = tmp_path / "phone.txt"
    f.write_text("from a phone\n")

    def opener():
        page.locator(SEL["fab"]).click()
        page.get_by_role("dialog", name="New").get_by_role("button", name="Upload files").click()

    pick_files(page, opener, [f])
    dlg = page.get_by_role("dialog", name=re.compile(r"^Upload"))
    expect(dlg).to_be_visible()
    protect(dlg)
    if dlg.get_by_role("radio").count():
        dlg.get_by_text("ZipCrypto", exact=True).click()  # the warning is part of the layout under test
    dlg.get_by_text("Which apps can open it?").click()
    dlg.get_by_role("button", name="Generate a strong password").click()
    expect(dlg.get_by_label("Generated password")).to_be_visible()
    settle(page)
    assert_no_overflow(page)
    overflow = page.evaluate("""() => [...document.querySelectorAll('dialog[open] *')]
      .filter((el) => el.getBoundingClientRect().right > innerWidth + 1 && getComputedStyle(el).position !== 'fixed')
      .map((el) => `${el.tagName.toLowerCase()}.${el.className}`).slice(0, 10)""")
    assert not overflow, f"sticks out of the 320 px sheet: {overflow}"

    # every target of the sheet, scrolled through from top to bottom
    bad: set[str] = set()
    body = dlg.locator(".dialog-body")
    height = body.evaluate("(el) => el.scrollHeight")
    for top in range(0, height + 1, 200):
        body.evaluate("(el, top) => { el.scrollTop = top; }", top)
        bad.update(page.evaluate(DIALOG_TAP_TARGETS_JS, 44))
    assert not bad, "tap targets smaller than 44 px:\n" + "\n".join(sorted(bad))

    # iOS zooms into fields under 16 px
    for loc in (password_input(dlg), confirm_input(dlg), dlg.get_by_label(re.compile(r"name of the .zip", re.I)),
                dlg.locator("select"), dlg.get_by_label("Generated password")):
        size = loc.first.evaluate("(el) => parseFloat(getComputedStyle(el).fontSize)")
        assert size >= 16, f"{loc}: font-size {size}px"

    # the on-screen keyboard: visualViewport shrinks by 300 px → the sheet rides above it, the field stays in view
    lifted = page.evaluate("""async () => {
      const sheet = document.querySelector('dialog.up-dialog');
      const field = sheet.querySelector("input[name='zip-password']");
      const frame = () => new Promise((r) => requestAnimationFrame(() => requestAnimationFrame(r)));
      const before = sheet.getBoundingClientRect().bottom;
      const vv = window.visualViewport;
      Object.defineProperty(vv, 'height', { configurable: true, get: () => innerHeight - 300 });
      field.focus();
      vv.dispatchEvent(new Event('resize'));
      await frame();
      const res = { before, kb: sheet.style.getPropertyValue('--fp-kb'), after: sheet.getBoundingClientRect().bottom,
                    fieldBottom: field.getBoundingClientRect().bottom, fieldTop: field.getBoundingClientRect().top,
                    limit: innerHeight - 300 };
      delete vv.height;
      vv.dispatchEvent(new Event('resize'));
      await frame();
      res.reset = sheet.style.getPropertyValue('--fp-kb');
      res.back = sheet.getBoundingClientRect().bottom;
      return res;
    }""")
    assert lifted["kb"] == "300px", lifted
    assert abs(lifted["before"] - 300 - lifted["after"]) <= 2, f"the sheet did not move up by the keyboard: {lifted}"
    assert lifted["fieldBottom"] <= lifted["limit"] + 1 and lifted["fieldTop"] >= 0, f"the field is hidden: {lifted}"
    assert lifted["reset"] == "0px" and abs(lifted["back"] - lifted["before"]) <= 2, lifted
    shot(page, request, "sheet")
    dlg.get_by_role("button", name="Cancel").click()
    expect(dlg).to_be_hidden()
    watch.assert_clean()


def test_share_link_protected_zip_note(new_page, server, zipper, request):
    """The link dialog says the .zip has its own password; the public page shows the lock and whom to ask."""
    _, _, api, state = zipper
    root = api.root_id()
    folder = api.ok("POST", f"/api/v1/nodes/{root}/folders", {"name": f"Shared zips {secrets.token_hex(3)}"})
    name = f"for-you-{secrets.token_hex(3)}.zip"
    api_protected_zip(api, folder["id"], name, {"a.txt": b"alpha\n", "b.txt": b"beta\n"},
                             "Share-me-" + secrets.token_hex(5))

    page, watch = new_page(storage_state=state)
    page.goto(f"/files/{folder['id']}")
    file_row(page, name).first.click(button="right")
    page.get_by_role("menuitem", name=re.compile(r"^Share", re.I)).first.click()
    share = page.get_by_role("dialog", name=re.compile("Share", re.I))
    share.get_by_role("button", name=re.compile(r"^Create link", re.I)).first.click()
    form = page.get_by_role("dialog", name=re.compile("Create a public link", re.I))
    note = form.get_by_text(re.compile(r"This \.zip has its own password\. People need it after downloading"))
    expect(note).to_be_visible()
    expect(form.get_by_text(re.compile(r"“Require a password” below is a different lock"))).to_be_visible()
    settle(page)
    shot(page, request, "link-dialog")
    with page.expect_response(re.compile(r"/api/v1/shares$")) as info:
        form.get_by_role("button", name="Create link", exact=True).click()
    assert info.value.status == 201
    done = page.get_by_role("dialog", name=re.compile("Link created", re.I))
    link = done.locator("input[readonly], input[type=url]").first.input_value()
    watch.assert_clean()

    # the public page of the file
    anon, anon_watch = new_page()
    anon.goto(link)
    expect(anon.get_by_role("img", name=AES_LABEL).first).to_be_visible()
    expect(anon.get_by_text("This .zip is password-protected. Ask Zoë Zipper for the password.")).to_be_visible()
    assert_no_overflow(anon)
    shot(anon, request, "public-file")

    # a folder link lists it with the lock
    folder_link = api.ok("POST", "/api/v1/shares", {"kind": "link", "node_id": folder["id"]})["url"]
    anon.goto(folder_link)
    row = anon.locator(".share-row", has_text=name)
    expect(row.get_by_role("img", name=AES_LABEL)).to_be_visible()
    shot(anon, request, "public-folder")
    anon_watch.assert_clean()


@pytest.mark.parametrize("scheme", SCHEMES)
def test_mobile_zip_badges(new_page, server, zipper, request, device, scheme):
    """The locks and notes on a 320 px phone, light and dark: file list, details sheet, versions, public page."""
    _, _, api, state = zipper
    root = api.root_id()
    folder = api.ok("POST", f"/api/v1/nodes/{root}/folders", {"name": f"Phone zips {secrets.token_hex(3)}"})
    # the longest badge ("Password · ZipCrypto (weak)") next to a name that has to wrap
    name = f"quarterly-report-with-a-rather-long-name-{secrets.token_hex(3)}.zip"
    node = api_protected_zip(api, folder["id"], name, {"report.txt": b"numbers\n"},
                             "Phone-zip-" + secrets.token_hex(5), enc="zipcrypto")

    page, watch = new_page(profile=device, scheme=scheme, storage_state=state, viewport={"width": 320, "height": 640})
    page.goto(f"/files/{folder['id']}")
    row = file_row(page, name).first
    expect(row.locator(".fv-badge--lock")).to_have_attribute("title", ZIPCRYPTO_LABEL)
    expect(row.get_by_role("img", name=ZIPCRYPTO_LABEL)).to_be_visible()
    assert_no_overflow(page)
    shot(page, request, "list")

    long_press(page, row)
    page.get_by_role("menuitem", name="Details").or_(page.get_by_role("button", name="Details")).first.click()
    details = page.get_by_role("dialog", name="Details")
    expect(details.get_by_text("Password · ZipCrypto (weak)")).to_be_visible()
    settle(page)
    assert_no_overflow(page)
    # a badge clips its text (overflow: hidden) instead of overflowing the page, so measure it directly
    clipped = details.locator(".badge").evaluate_all(
        "(els) => els.filter((b) => b.scrollWidth > b.clientWidth + 1).map((b) => b.textContent)")
    assert not clipped, f"badge text cut off at 320 px: {clipped}"
    shot(page, request, "details")
    details.get_by_role("tab", name="Versions").click()
    expect(details.locator(".version-lock").first).to_be_visible()
    assert_no_overflow(page)
    page.keyboard.press("Escape")
    watch.assert_clean()

    link = api.ok("POST", "/api/v1/shares", {"kind": "link", "node_id": node})["url"]
    anon, anon_watch = new_page(profile=device, scheme=scheme, viewport={"width": 320, "height": 640})
    anon.goto(link)
    expect(anon.get_by_role("img", name=ZIPCRYPTO_LABEL).first).to_be_visible()
    expect(anon.get_by_text("This .zip is password-protected. Ask Zoë Zipper for the password.")).to_be_visible()
    assert_no_overflow(anon)
    shot(anon, request, "public")
    anon_watch.assert_clean()


def test_zip_password_long_paste_refused(new_page, server, zipper, request, tmp_path):
    """QA: a pasted password over the limit is refused with a message, never cut (the fields have no maxlength, which
    silently dropped the rest of a 150-character paste); the longest accepted password, 99 characters (7-Zip refuses
    longer AES passwords), makes a .zip 7-Zip opens."""
    _, _, _, state = zipper
    page, watch = new_page(storage_state=state)
    goto_files(page)
    f = tmp_path / "long.txt"
    f.write_text("protected with a long password\n")
    name = f"long-{secrets.token_hex(3)}.zip"
    dlg = open_upload_dialog(page, [f])
    protect(dlg, name)
    pw, pw2 = password_input(dlg), confirm_input(dlg)
    for el in (pw, pw2):
        assert not el.evaluate("(el) => el.hasAttribute('maxlength')"), "a maxlength cuts pasted passwords"
    posts = []
    page.on("request", lambda r: posts.append(r.url) if r.method == "POST" and r.url.endswith("/api/v1/upload-batches") else None)
    pasted = "Kx7-" + secrets.token_hex(73)  # 150 characters, as a password manager might fill in
    pw.click()
    page.keyboard.insert_text(pasted)
    expect(field_error(dlg, "zip-password")).to_contain_text("Use at most 99 characters.")  # at once
    confirm_input(dlg).click()
    page.keyboard.insert_text(pasted)
    assert len(pw.input_value()) == 150 and len(pw2.input_value()) == 150
    submit(dlg)
    expect(dlg).to_be_visible()
    expect(field_error(dlg, "zip-password")).to_contain_text("Use at most 99 characters.")
    assert not posts, "an over-long password was sent"

    longest = ("Kx7-" + secrets.token_hex(50))[:99]
    pw.fill(longest)
    expect(field_error(dlg, "zip-password")).not_to_contain_text("at most")
    pw2.fill(longest)
    submit(dlg)
    expect(dlg).to_be_hidden()
    wait_ready(page, name)
    zip_path = download_row(page, name, tmp_path)
    check_aes_headers(zip_path.read_bytes(), {"long.txt"})
    extract_and_compare(tmp_path, zip_path, longest, {"long.txt": f.read_bytes()})
    watch.assert_clean()


def test_zip_password_min_raised_after_load(new_page, server, zipper, admin_api, request, tmp_path):
    """QA: storage.zip_password_min raised while the page is open. The refusal names the new minimum, and the
    re-opened dialog (help text, checks, generator) and later dialogs of the page use it, instead of generating
    20-character passwords the server refuses again and again."""
    _, _, _, state = zipper
    page, watch = new_page(storage_state=state)
    goto_files(page)
    f = tmp_path / "min.txt"
    f.write_text("minimum\n")
    name = f"min-{secrets.token_hex(3)}.zip"
    dlg = open_upload_dialog(page, [f])
    protect(dlg, name)
    expect(dlg.get_by_text(re.compile(r"At least 12 characters"))).to_be_visible()
    with setting(admin_api, "storage.zip_password_min", 30):
        dlg.get_by_role("button", name="Generate a strong password").click()
        assert len(dlg.get_by_label("Generated password").input_value()) == 20
        dlg.get_by_label("I’ve saved this password").check()
        with page.expect_response(lambda r: r.url.endswith("/api/v1/upload-batches") and r.request.method == "POST") as info:
            submit(dlg)
        assert info.value.status == 422
        again = page.get_by_role("dialog", name=re.compile(r"^Upload"))
        expect(field_error(again, "zip-password")).to_contain_text("at least 30 characters")
        expect(again.get_by_text(re.compile(r"At least 30 characters"))).to_be_visible()
        again.get_by_role("button", name="Generate a strong password").click()
        secret = again.get_by_label("Generated password").input_value()
        assert len(secret) >= 30, secret
        again.get_by_label("I’ve saved this password").check()
        submit(again)
        expect(again).to_be_hidden()
        wait_ready(page, name)
        # later dialogs of this page keep the server's minimum
        dlg = open_upload_dialog(page, [f])
        protect(dlg)
        expect(dlg.get_by_text(re.compile(r"At least 30 characters"))).to_be_visible()
        dlg.get_by_role("button", name="Cancel").click()
        expect(dlg).to_be_hidden()
    watch.errors = [e for e in watch.errors if "status of 422" not in e]  # the refusal itself
    watch.assert_clean()
