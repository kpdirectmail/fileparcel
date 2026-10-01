"""Desktop UI flows (DESIGN §17): login, TOTP enrollment, passkeys, folders,
uploads, previews, sharing, and every admin page - in light and dark mode at
1440x900. Each test fails on console errors and CSP / Trusted Types
violations."""

from __future__ import annotations

import pathlib
import re
import secrets
import shutil
import subprocess

import pytest
from conftest import (
    ADMIN_ROUTES,
    SEL,
    USER_ROUTES,
    add_virtual_authenticator,
    assert_no_overflow,
    confirm_identity,
    login,
    make_png,
    dismiss_uploads,
    pick_files,
    shot,
    start_upload,
)
from playwright.sync_api import Error as PlaywrightError
from playwright.sync_api import expect

SCHEMES = ["light", "dark"]


@pytest.mark.parametrize("scheme", SCHEMES)
def test_login_page(new_page, server, request, scheme):
    page, watch = new_page(scheme=scheme)
    page.goto("/login")
    expect(page.get_by_label(SEL["login_user"])).to_be_visible()
    expect(page.locator(SEL["login_password"]).first).to_be_visible()
    assert page.evaluate("window.isSecureContext"), "the page is not a secure context (SPKI pin not applied?)"
    assert_no_overflow(page)
    shot(page, request, "login")
    watch.assert_clean()


def test_wrong_password_is_rejected(new_page, server):
    page, watch = new_page()
    page.goto("/login")
    page.get_by_label(SEL["login_user"]).fill("alice")
    page.locator(SEL["login_password"]).first.fill("definitely-wrong")
    page.get_by_role("button", name=SEL["login_submit"], exact=True).click()
    expect(page.locator("[role=alert], .field-error, .alert").first).to_be_visible()
    assert "/login" in page.url
    # the failed login answers 401; the page reports it without console errors
    watch.errors = [e for e in watch.errors if "401" not in e]
    watch.assert_clean()


def test_admin_login_with_totp(new_page, server, request):
    page, watch = new_page()
    login(page, server, server.admin, server.admin_password, server.admin_totp)
    expect(page).to_have_url(re.compile(r"/(files|admin)"))
    shot(page, request, "after-login")
    watch.assert_clean()


def test_totp_enrollment_shows_qr(new_page, server, fresh_user, request):
    page, watch = new_page()
    name, password = fresh_user("totp")
    login(page, server, name, password)
    page.goto("/settings/security")
    with page.expect_response(lambda r: r.url.endswith("/api/v1/me/totp/begin") and r.status == 200) as info:
        page.get_by_role("button", name=re.compile(r"authenticator|two-factor|TOTP|set up", re.I)).first.click()
        confirm_identity(page, password)  # setting up a second factor needs step-up
    secret = info.value.json()["secret"]
    qr = page.locator("img[src^='data:image/svg+xml'], img[src*='qr.svg']").first
    expect(qr).to_be_visible()
    box = qr.bounding_box()
    assert box and box["width"] >= 120, "the QR code is too small to scan"
    shot(page, request, "totp-qr")
    page.locator("input[autocomplete=one-time-code], input[inputmode=numeric]").first.fill(server.clock.code(secret))
    # the code field submits itself once six digits are in; the button is a fallback
    try:
        page.get_by_role("button", name=re.compile(r"verify|confirm|enable", re.I)).first.click(timeout=2500)
    except PlaywrightError:
        pass
    expect(page.get_by_text(re.compile(r"recovery code", re.I)).first).to_be_visible()
    shot(page, request, "recovery-codes")
    # the first /me/totp/begin answers 403 elevation_required (the browser logs it); the step-up retries it
    watch.errors = [e for e in watch.errors if "403" not in e]
    watch.assert_clean()


def test_passkey_register_and_sign_in(new_page, server, fresh_user, request):
    page, watch = new_page()
    add_virtual_authenticator(page)
    name, password = fresh_user("pk")
    login(page, server, name, password)
    page.goto("/settings/security")
    page.get_by_role("button", name=re.compile(r"add (a )?passkey|passkey", re.I)).first.click()
    confirm_identity(page, password)  # registering a passkey needs step-up
    name_field = page.get_by_label(re.compile(r"name", re.I))
    try:  # the name prompt follows the step-up round trip
        name_field.first.wait_for(state="visible", timeout=5000)
    except PlaywrightError:
        pass
    if name_field.count() and name_field.first.is_visible():
        name_field.first.fill("Virtual authenticator")
        page.get_by_role("button", name=re.compile(r"save|add|continue|create", re.I)).last.click()
    expect(page.get_by_text(re.compile(r"Virtual authenticator|Passkey", re.I)).first).to_be_visible()
    shot(page, request, "passkey-added")
    # sign out, then sign in with the passkey (same browser context = same authenticator)
    page.context.clear_cookies()
    page.goto("/login")
    # login.js starts a conditional-mediation ("autofill") request on load; the
    # virtual authenticator auto-approves it, so the page may sign in by itself.
    # Otherwise use the explicit button.
    btn = page.get_by_role("button", name=SEL["passkey_login"])
    try:
        btn.click(timeout=4000)
    except PlaywrightError:
        pass
    page.wait_for_url(re.compile(r"^(?!.*/login).*$"))
    assert page.evaluate("async () => (await fetch('/api/v1/me', {headers: {Accept: 'application/json'}})).status") == 200
    shot(page, request, "passkey-signed-in")
    watch.assert_clean()


def test_create_folder(new_page, server, alice_state, request):
    page, watch = new_page(storage_state=alice_state)
    page.goto("/files")
    name = f"Holiday photos {secrets.token_hex(2)}"
    page.locator(SEL["upload_more"]).click()
    page.get_by_role("menuitem", name="New folder").click()
    page.get_by_role("dialog").get_by_role("textbox").fill(name)
    page.get_by_role("dialog").get_by_role("button", name=re.compile(r"create|ok|save", re.I)).click()
    expect(page.get_by_text(name, exact=True).first).to_be_visible()
    shot(page, request, "folder-created")
    watch.assert_clean()


def _upload_menu(page, label):
    """Opens the Upload split button's menu and returns a click for one item."""
    page.locator(SEL["upload_more"]).click()
    return lambda: page.get_by_role("menuitem", name=label, exact=True).click()


def test_upload_files_and_folder(new_page, server, alice_state, request, tmp_path):
    page, watch = new_page(storage_state=alice_state)
    page.goto("/files")
    a = tmp_path / "notes.txt"
    a.write_text("some notes\n")
    b = make_png(tmp_path / "green.png", rgb=(22, 163, 74))
    pick_files(page, lambda: page.get_by_role("button", name=SEL["upload_button"], exact=True).click(), [a, b])
    start_upload(page)
    expect(page.get_by_text("notes.txt", exact=True).first).to_be_visible(timeout=30000)
    expect(page.get_by_text("green.png", exact=True).first).to_be_visible()
    # a directory with nested and empty sub-directories
    tree = tmp_path / "Album"
    (tree / "2026" / "summer").mkdir(parents=True)
    (tree / "empty").mkdir()
    (tree / "2026" / "summer" / "beach.txt").write_text("sand\n")
    (tree / "readme.txt").write_text("album\n")
    pick_files(page, _upload_menu(page, "Upload folder"), tree, folder=True)
    start_upload(page)
    expect(page.get_by_text("Album", exact=True).first).to_be_visible(timeout=30000)
    shot(page, request, "uploaded")
    watch.assert_clean()


def test_zip_on_upload(new_page, server, alice_state, request, tmp_path):
    """"Bundle into a single .zip" packs the selection into one .zip server-side."""
    page, watch = new_page(storage_state=alice_state)
    page.goto("/files")
    a = tmp_path / "one.txt"
    a.write_text("one\n")
    b = make_png(tmp_path / "two.png", rgb=(190, 80, 40))
    pick_files(page, lambda: page.get_by_role("button", name=SEL["upload_button"], exact=True).click(), [a, b])
    dlg = page.get_by_role("dialog")
    dlg.get_by_text(re.compile(r"bundle into a single", re.I)).first.click()
    name = f"bundle-{secrets.token_hex(3)}.zip"
    dlg.get_by_label(re.compile(r"name of the .zip", re.I)).fill(name)
    shot(page, request, "zip-dialog")
    start_upload(page)
    expect(page.get_by_text(name, exact=True).first).to_be_visible(timeout=60000)
    shot(page, request, "zip-uploaded")
    watch.assert_clean()


def test_image_preview(new_page, server, sample_state, request):
    page, watch = new_page(storage_state=sample_state)
    page.goto("/files")
    page.get_by_text("blue.png", exact=True).first.dblclick()
    # the preview is a native <dialog class="pv">; "[role=dialog]" is a CSS
    # attribute selector and would never match it.
    img = page.locator(".pv-stage img").first
    expect(img).to_be_visible()
    assert page.evaluate("(el) => el.naturalWidth > 0", img.element_handle()), "the preview image did not load"
    shot(page, request, "image-preview")
    page.keyboard.press("Escape")
    watch.assert_clean()


def test_text_preview(new_page, server, sample_state, request, tmp_path):
    page, watch = new_page(storage_state=sample_state)
    page.goto("/files")
    page.get_by_text("hello.txt", exact=True).first.dblclick()
    stage = page.locator('.pv-stage[data-kind="text"]')
    expect(stage).to_be_visible()
    expect(stage.locator("pre.pv-code")).to_contain_text("Hello from the UI tests")
    shot(page, request, "text-preview")
    page.keyboard.press("Escape")
    watch.assert_clean()


@pytest.mark.skipif(shutil.which("ffmpeg") is None, reason="ffmpeg is needed to generate a test video")
def test_video_preview(new_page, server, alice_state, request, tmp_path):
    video = tmp_path / "clip.webm"
    subprocess.run(["ffmpeg", "-loglevel", "error", "-f", "lavfi", "-i", "testsrc=duration=2:size=320x240:rate=15",
                    "-c:v", "libvpx-vp9", str(video)], check=True)
    page, watch = new_page(storage_state=alice_state)
    page.goto("/files")
    pick_files(page, lambda: page.get_by_role("button", name=SEL["upload_button"], exact=True).click(), video)
    start_upload(page)
    expect(page.get_by_text("clip.webm", exact=True).first).to_be_visible(timeout=30000)
    dismiss_uploads(page)  # the queue card and the toast float over the list
    page.get_by_text("clip.webm", exact=True).first.dblclick()
    v = page.locator("video").first
    expect(v).to_be_visible()
    page.wait_for_function("(el) => el.readyState >= 1", arg=v.element_handle())
    shot(page, request, "video-preview")
    watch.assert_clean()


def _open_share_dialog(page, name):
    page.get_by_text(name, exact=True).first.click(button="right")
    page.get_by_role("menuitem", name=re.compile(r"^Share", re.I)).first.click()
    return page.get_by_role("dialog", name=re.compile("Share", re.I))


def test_share_dialog_qr_and_public_page(new_page, server, sample_state, request):
    page, watch = new_page(storage_state=sample_state)
    page.goto("/files")
    dlg = _open_share_dialog(page, "hello.txt")
    expect(dlg.get_by_text("Public links", exact=True)).to_be_visible()
    shot(page, request, "share-dialog")
    dlg.get_by_role("button", name=re.compile(r"^Create link", re.I)).first.click()
    form = page.get_by_role("dialog", name=re.compile("Create a public link", re.I))
    expect(form).to_be_visible()
    shot(page, request, "share-create")
    with page.expect_response(re.compile(r"/api/v1/shares$")) as info:
        form.get_by_role("button", name="Create link", exact=True).click()
    assert info.value.status == 201, f"creating the link answered {info.value.status}"
    done = page.get_by_role("dialog", name=re.compile("Link created", re.I))
    expect(done).to_be_visible()
    qr = done.locator("img[src^='data:image/svg+xml'], img[src*='qr']").first
    expect(qr).to_be_visible()
    box = qr.bounding_box()
    assert box and box["width"] >= 120, f"the QR code is too small to scan: {box}"
    link = done.locator("input[readonly], input[type=url]").first.input_value()
    assert "/s/" in link, f"no share link in the dialog: {link!r}"
    shot(page, request, "share-link-created")
    watch.assert_clean()

    # the public page, in a fresh context without any session
    anon, anon_watch = new_page()
    anon.goto(link)
    expect(anon.get_by_text("hello.txt").first).to_be_visible()
    expect(anon.get_by_role("link", name=re.compile(r"download", re.I)).or_(
        anon.get_by_role("button", name=re.compile(r"download", re.I))).first).to_be_visible()
    assert_no_overflow(anon)
    shot(anon, request, "share-page")
    # the preview opens without a session
    anon.get_by_role("button", name=re.compile("preview", re.I)).first.click()
    expect(anon.get_by_role("dialog").first).to_be_visible()
    shot(anon, request, "share-page-preview")
    anon_watch.assert_clean()


def _new_file_request(page, title):
    page.goto("/requests")
    page.get_by_role("button", name="New file request", exact=True).first.click()
    dlg = page.get_by_role("dialog", name=re.compile("New file request", re.I))
    dlg.get_by_role("button", name=re.compile("choose a folder", re.I)).first.click()
    picker = page.get_by_role("dialog", name=re.compile("Where should uploads go", re.I))
    picker.get_by_text("My files", exact=True).first.click()
    picker.get_by_role("button", name="Use this folder", exact=True).click()
    dlg.get_by_label(re.compile(r"^Title", re.I)).first.fill(title)
    with page.expect_response(re.compile(r"/api/v1/shares$")) as info:
        dlg.get_by_role("button", name=re.compile("create request", re.I)).click()
    assert info.value.status == 201, f"creating the request answered {info.value.status}"
    done = page.get_by_role("dialog", name=re.compile("File request created", re.I))
    expect(done).to_be_visible()
    link = done.locator("input[readonly], input[type=url]").first.input_value()
    return done, link


def test_file_request_drop_zone(new_page, server, sample_state, request, tmp_path):
    """Create a file request, then upload into it from an anonymous browser."""
    page, watch = new_page(storage_state=sample_state)
    title = f"Send me your photos {secrets.token_hex(2)}"
    done, link = _new_file_request(page, title)
    qr = done.locator("img[src^='data:image/svg+xml'], img[src*='qr']").first
    expect(qr).to_be_visible()
    shot(page, request, "request-created")
    assert "/s/" in link, f"no request link: {link!r}"
    watch.assert_clean()

    anon, anon_watch = new_page()
    anon.goto(link)
    drop = anon.locator(".share-drop, [data-dropzone]").first
    expect(drop).to_be_visible()
    expect(drop).to_contain_text(re.compile(r"drag files", re.I))
    anon.get_by_label(re.compile("your name", re.I)).first.fill("Dana Tester")
    a = tmp_path / "from-dana.txt"
    a.write_text("thanks\n")
    b = make_png(tmp_path / "from-dana.png", rgb=(120, 60, 200))
    pick_files(anon, lambda: anon.get_by_role("button", name="Choose files", exact=True).click(), [a, b])
    expect(anon.get_by_text("from-dana.txt", exact=True).first).to_be_visible()
    assert_no_overflow(anon)
    shot(anon, request, "request-ready")
    anon.get_by_role("button", name=re.compile(r"^Send \d", re.I)).click()
    expect(anon.get_by_text(re.compile(r"thank you", re.I)).first).to_be_visible(timeout=60000)
    shot(anon, request, "request-done")
    anon_watch.assert_clean()

    # the files really landed in the owner's folder
    page.goto("/files")
    expect(page.get_by_text("from-dana.txt", exact=True).first).to_be_visible(timeout=30000)


@pytest.mark.parametrize("scheme", SCHEMES)
def test_user_pages_render(new_page, server, alice_state, request, scheme):
    page, watch = new_page(scheme=scheme, storage_state=alice_state)
    for route in USER_ROUTES:
        page.goto(route)
        page.wait_for_load_state("networkidle")
        expect(page.locator(SEL["page_title"]).first).to_be_visible()
        assert_no_overflow(page)
        shot(page, request, route.strip("/").replace("/", "_").replace("?", "_") or "root")
    watch.assert_clean()


@pytest.mark.parametrize("scheme", SCHEMES)
def test_admin_pages_render(new_page, server, admin_state, request, scheme):
    page, watch = new_page(scheme=scheme, storage_state=admin_state)
    for route in ADMIN_ROUTES:
        page.goto(route)
        page.wait_for_load_state("networkidle")
        expect(page.locator(SEL["page_title"]).first).to_be_visible()
        assert "/login" not in page.url, f"{route} redirected to the login page"
        assert_no_overflow(page)
        shot(page, request, route.strip("/").replace("/", "_"))
    watch.assert_clean()


def test_trust_page(new_page, server, request):
    page, watch = new_page()
    page.goto("/trust")
    # the fingerprint sits in a read-only copy field, so it is a value, not text
    fp = page.get_by_label(re.compile(r"CA fingerprint", re.I)).first
    expect(fp).to_be_visible()
    assert re.match(r"^([0-9A-F]{2}:){31}[0-9A-F]{2}$", fp.input_value()), fp.input_value()
    with page.expect_download() as dl:
        page.get_by_role("link", name=re.compile(r"(download|certificate).*", re.I)).first.click()
    path = pathlib.Path(dl.value.path())
    assert path.read_bytes().startswith((b"-----BEGIN CERTIFICATE", b"0\x82")), "not a certificate"
    shot(page, request, "trust")
    watch.assert_clean()


# --------------------------------------------------------------- regressions
# These pin defects found in verification round 1: each asserts the behaviour
# the design asks for, so it flips from xfail to xpass once the fix lands.

def test_pdf_fallback_card_is_centred(new_page, server, alice_state, request, tmp_path):
    """Browsers without a built-in PDF viewer (Chrome on Android, headless) get
    the fallback card; it must look like the one other unpreviewable types get."""
    page, watch = new_page(storage_state=alice_state)
    page.goto("/files")
    pdf = tmp_path / f"fallback-{secrets.token_hex(3)}.pdf"
    pdf.write_bytes(b"%PDF-1.4\n1 0 obj<</Type/Catalog>>endobj\ntrailer<</Root 1 0 R>>\n")
    pick_files(page, lambda: page.get_by_role("button", name=SEL["upload_button"], exact=True).click(), pdf)
    start_upload(page)
    expect(page.get_by_text(pdf.name, exact=True).first).to_be_visible(timeout=30000)
    dismiss_uploads(page)
    page.get_by_text(pdf.name, exact=True).first.dblclick()
    card = page.locator(".pv-fallback")
    expect(card).to_be_visible()
    box = page.evaluate("""() => {
      const s = document.querySelector('.pv-stage').getBoundingClientRect();
      const c = document.querySelector('.pv-fallback').getBoundingClientRect();
      return {stageW: s.width, stageH: s.height, cardH: c.height,
              offCentre: Math.abs((c.x + c.width / 2) - (s.x + s.width / 2))};
    }""")
    shot(page, request, "pdf-fallback")
    assert box["offCentre"] < 2, f"the fallback card is not centred: {box}"
    assert box["cardH"] < box["stageH"] * 0.9, f"the fallback card is stretched to the full height: {box}"
    watch.assert_clean()


def test_share_dialog_opens_without_an_empty_suggestion_popup(new_page, server, sample_state, request):
    page, watch = new_page(storage_state=sample_state)
    page.goto("/files")
    dlg = _open_share_dialog(page, "hello.txt")
    expect(dlg).to_be_visible()
    page.wait_for_timeout(500)
    popup = page.evaluate("""() => {
      const d = document.querySelector('dialog.share-dialog');
      const list = d && d.querySelector('.subject-list');
      if (!list || !list.offsetHeight) return null;
      return {text: list.innerText.trim().slice(0, 60), options: list.querySelectorAll('[role=option]').length};
    }""")
    shot(page, request, "share-dialog-open")
    assert not popup, f"an empty suggestion popup covers the dialog on open: {popup}"


def test_dashboard_and_health_agree_about_disk_space(new_page, server, admin_state, request):
    page, watch = new_page(storage_state=admin_state)
    page.goto("/admin")
    page.wait_for_load_state("networkidle")
    lines = page.evaluate("""() => [...document.querySelectorAll('*')]
      .filter(e => e.children.length === 0 && /free of/.test(e.textContent || ''))
      .map(e => e.textContent.trim())""")
    shot(page, request, "dashboard-disk")
    assert len(lines) >= 2, f"expected the storage tile and the health check: {lines}"
    pcts = [re.search(r"\((\d+)%", t) for t in lines]
    assert all(pcts), f"no percentage in {lines}"
    values = {m.group(1) for m in pcts}
    assert len(values) == 1, f"the same disk is reported as two different percentages: {lines}"
    units = {re.search(r"free of [\d.]+ (\w+)", t).group(1) for t in lines}
    assert len(units) == 1, f"the same disk is reported in two different units: {lines}"
