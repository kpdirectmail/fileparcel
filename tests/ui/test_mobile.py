"""Mobile UI (DESIGN §13.5, §17): Pixel 7 and iPhone 14 viewports (Chromium
emulation) in light and dark mode - bottom tab bar, Upload FAB, the "More"
sheet, long-press file actions, no horizontal overflow (also at 320 px) and
tap targets of at least 40 px.

The phone tests use the `sample_state` account (exactly two files) so the rows
they look for are inside the first screenful of the virtualized list.
"""

from __future__ import annotations

import re

import pytest
from conftest import (
    MOBILE_DEVICES,
    SEL,
    api_storage_state,
    assert_no_overflow,
    assert_tap_targets,
    long_press,
    shot,
)
from playwright.sync_api import expect

SCHEMES = ["light", "dark"]


@pytest.fixture(params=MOBILE_DEVICES)
def device(request):
    return request.param


@pytest.mark.parametrize("scheme", SCHEMES)
def test_mobile_login_page(new_page, server, request, device, scheme):
    page, watch = new_page(profile=device, scheme=scheme)
    page.goto("/login")
    expect(page.get_by_label(SEL["login_user"])).to_be_visible()
    assert_no_overflow(page)
    assert_tap_targets(page)
    shot(page, request, "login")
    watch.assert_clean()


@pytest.mark.parametrize("scheme", SCHEMES)
def test_mobile_files_bottom_nav(new_page, server, sample_state, request, device, scheme):
    page, watch = new_page(profile=device, scheme=scheme, storage_state=sample_state)
    page.goto("/files")
    tabbar = page.locator(SEL["tabbar"])
    expect(tabbar).to_be_visible()
    for label in ("Files", "Shared", "Links", "More"):
        expect(tabbar.get_by_text(label, exact=True)).to_be_visible()
    expect(page.locator(SEL["fab"])).to_be_visible()
    # the sidebar is not shown on phones
    expect(page.locator("#fp-sidebar")).not_to_be_in_viewport()
    expect(page.get_by_text("hello.txt", exact=True).first).to_be_visible()
    assert_no_overflow(page)
    assert_tap_targets(page)
    shot(page, request, "files")
    watch.assert_clean()


def test_mobile_more_sheet(new_page, server, sample_state, request, device):
    page, watch = new_page(profile=device, storage_state=sample_state)
    page.goto("/files")
    page.locator(SEL["tabbar"]).get_by_text("More", exact=True).click()
    sheet = page.get_by_role("dialog")
    expect(sheet).to_be_visible()
    expect(sheet.get_by_text("Trash").first).to_be_visible()
    assert_tap_targets(page)
    shot(page, request, "more-sheet")
    page.keyboard.press("Escape")
    expect(sheet).to_be_hidden()
    watch.assert_clean()


def test_mobile_fab_menu(new_page, server, sample_state, request, device):
    page, watch = new_page(profile=device, storage_state=sample_state)
    page.goto("/files")
    page.locator(SEL["fab"]).click()
    # the same labels exist in the (hidden) page-header menu, so scope to the sheet
    sheet = page.get_by_role("dialog", name="New")
    expect(sheet).to_be_visible()
    expect(sheet.get_by_role("button", name="Upload files")).to_be_visible()
    expect(sheet.get_by_role("button", name="New folder")).to_be_visible()
    expect(sheet.get_by_role("button", name="New file request")).to_be_visible()
    if device.startswith("iPhone"):
        # iOS cannot pick folders; the option is hidden (the emulated UA says iPhone)
        expect(sheet.get_by_role("button", name="Upload folder")).to_have_count(0)
    else:
        expect(sheet.get_by_role("button", name="Upload folder")).to_be_visible()
    shot(page, request, "fab-menu")
    watch.assert_clean()


def test_mobile_long_press_actions(new_page, server, sample_state, request, device):
    page, watch = new_page(profile=device, storage_state=sample_state)
    page.goto("/files")
    row = page.get_by_text("hello.txt", exact=True).first
    expect(row).to_be_visible()
    long_press(page, row)
    sheet = page.get_by_role("dialog").or_(page.get_by_role("menu")).first
    expect(sheet).to_be_visible()
    expect(sheet.get_by_text("Download").first).to_be_visible()
    expect(sheet.get_by_text("Move to trash").first).to_be_visible()
    assert_tap_targets(page)
    shot(page, request, "long-press")
    watch.assert_clean()


@pytest.mark.parametrize("route", ["/files", "/shared", "/links", "/trash", "/settings/profile", "/settings/security"])
def test_320px_no_overflow(new_page, server, sample_state, request, route):
    page, watch = new_page(profile="Pixel 7", storage_state=sample_state, viewport={"width": 320, "height": 640})
    page.goto(route)
    page.wait_for_load_state("networkidle")
    assert_no_overflow(page)
    shot(page, request, route.strip("/").replace("/", "_"))
    watch.assert_clean()


@pytest.mark.parametrize("route", ["/admin", "/admin/users", "/admin/roles", "/admin/settings/general", "/admin/network",
                                   "/admin/audit", "/admin/system"])
def test_320px_admin_no_overflow(new_page, server, admin_state, request, route):
    page, watch = new_page(profile="Pixel 7", storage_state=admin_state, viewport={"width": 320, "height": 640})
    page.goto(route)
    page.wait_for_load_state("networkidle")
    assert_no_overflow(page)
    shot(page, request, route.strip("/").replace("/", "_"))
    watch.assert_clean()


def test_320px_public_pages(new_page, server, request):
    page, watch = new_page(profile="Pixel 7", viewport={"width": 320, "height": 640})
    for route in ("/login", "/trust"):
        page.goto(route)
        page.wait_for_load_state("networkidle")
        assert_no_overflow(page)
        shot(page, request, route.strip("/"))
    watch.assert_clean()


# --------------------------------------------------------------- regressions
# Each of these pins a defect found in verification round 1. They assert the
# behaviour the design asks for, so they turn from xfail into xpass once the
# fix lands - remove the marker then.

def test_settings_tabs_scroll_active_into_view(new_page, server, sample_state, device):
    """DESIGN §13.5: on a phone the strip must show which settings page you are on."""
    page, watch = new_page(profile=device, storage_state=sample_state)
    hidden = []
    for route in ("/settings/profile", "/settings/security", "/settings/sessions",
                  "/settings/tokens", "/settings/appearance", "/settings/devices"):
        page.goto(route)
        page.wait_for_load_state("networkidle")
        state = page.evaluate("""() => {
          const strip = document.querySelector('.settings-tabs');
          const tab = strip && strip.querySelector('[aria-selected="true"], [aria-current="page"]');
          if (!tab) return null;
          const s = strip.getBoundingClientRect();
          const t = tab.getBoundingClientRect();
          return {label: tab.textContent.trim(), visible: t.left >= s.left - 1 && t.right <= s.right + 1};
        }""")
        assert state, f"{route}: no selected tab"
        if not state["visible"]:
            hidden.append(f"{route}: {state['label']!r} is scrolled out of the tab strip")
    assert not hidden, "\n".join(hidden)


@pytest.mark.parametrize("route", ["/files", "/admin/settings/sharing", "/admin/network", "/admin/roles"])
def test_touch_targets_are_44px(new_page, server, admin_state, sample_state, route):
    """DESIGN §13.5 asks for >= 44 px touch targets on coarse pointers."""
    state = sample_state if route == "/files" else admin_state
    page, watch = new_page(profile="Pixel 7", storage_state=state)
    page.goto(route)
    page.wait_for_load_state("networkidle")
    assert page.evaluate("() => matchMedia('(pointer: coarse)').matches"), "not emulating a touch device"
    assert_tap_targets(page, 44, ignore=())


def test_admin_users_names_are_readable_on_a_phone(new_page, server, admin_state):
    page, watch = new_page(profile="Pixel 7", storage_state=admin_state)
    page.goto("/admin/users")
    page.wait_for_load_state("networkidle")
    clipped = page.evaluate("""() => [...document.querySelectorAll('.user-cell-name, .user-cell-sub')]
      .filter(e => e.scrollWidth > e.clientWidth + 1)
      .map(e => `${e.textContent.trim()} (${e.clientWidth}px of ${e.scrollWidth}px)`)""")
    assert not clipped, "user names are cut off:\n" + "\n".join(clipped)


def test_share_meta_separator_never_ends_a_line(new_page, server, fresh_user, request):
    """The public share header joins its meta entries with "\u00b7"; when the line wraps on a
    phone the separator must travel with the entry it introduces, never dangle at a line end."""
    name, password = fresh_user("share")
    api = server.client()
    api.login(name, password)
    node = api.upload_small(api.root_id(), "holiday-photos.zip", b"not really a zip\n")
    share = api.ok("POST", "/api/v1/shares", {"kind": "link", "node_id": node})
    assert share.get("url"), f"the share has no public URL: {share}"

    page, watch = new_page(profile="Pixel 7", viewport={"width": 320, "height": 640})
    page.goto(share["url"])
    meta = page.locator(".share-meta")
    expect(meta).to_be_visible()
    seps = page.evaluate("""() => [...document.querySelectorAll('.share-meta-sep')].map((sep) => {
      const host = sep.parentElement, r = document.createRange();
      r.setStartAfter(sep);
      r.setEnd(host, host.childNodes.length);
      const after = [...r.getClientRects()][0], s = sep.getBoundingClientRect();
      return {line: host.textContent.trim(),
              follows: !!after && Math.abs(after.top - s.top) < 4 && after.left >= s.right - 1};
    })""")
    wrapped = page.evaluate("""() => {const p = document.querySelector('.share-meta');
      return p.getBoundingClientRect().height > parseFloat(getComputedStyle(p).lineHeight) * 1.4;}""")
    shot(page, request, "share-meta")
    assert seps, "the share header shows no meta separator, so this test proves nothing"
    assert wrapped, "the meta line no longer wraps at 320 px, so this test proves nothing"
    assert all(x["follows"] for x in seps), f"a separator was left at the end of a line: {seps}"
    assert_no_overflow(page)
    watch.assert_clean()


@pytest.mark.parametrize("scheme", SCHEMES)
def test_320px_funnel_card_with_advanced_open(funnel_server, funnel_page, request, scheme):
    """/admin/network with Tailscale Funnel on and the Funnel card's "Advanced" open (port, sign-in switches and the
    connection settings): no horizontal overflow at 320 px and 44 px touch targets, light and dark."""
    fs = funnel_server
    api = fs.admin_api()
    if api.ok("GET", "/api/v1/admin/network/tailscale")["funnel"]["state"] != "active":
        api.ok("PUT", "/api/v1/admin/network/funnel", {"mode": "app", "confirm": "public"})
    s = fs.server
    state = api_storage_state(s, s.admin, s.admin_password, s.admin_totp)
    page, watch = funnel_page(profile="Pixel 7", scheme=scheme, storage_state=state, viewport={"width": 320, "height": 640})
    page.goto("/admin/network#funnel")
    card = page.locator("#funnel")
    expect(card.locator(".badge").first).to_have_text("Active")
    card.get_by_text("Advanced", exact=True).click()
    expect(card.get_by_label("Public port")).to_be_visible()
    expect(card.locator(".remote-connection .setting-row").first).to_be_visible()
    page.wait_for_load_state("networkidle")
    assert_no_overflow(page)
    # The card is several screens tall and only what is on screen is measured: walk through it (and the Serve
    # card below it), measuring before the screenshot (a full-page shot drops the touch emulation).
    for part in (card.locator(".card-head"), card.locator(".remote-address"), card.locator(".choice-grid"),
                 card.get_by_label("Public port"), card.locator(".toggle").first, card.locator(".toggle").last,
                 card.locator(".remote-connection .setting-row").first, card.locator(".remote-connection form button").last,
                 card.locator(".remote-checks-ok"), card.locator(".btn-row").last, page.locator("#serve")):
        part.evaluate("el => el.scrollIntoView({block: 'center', inline: 'nearest'})")
        page.wait_for_timeout(100)
        assert_tap_targets(page, 44, ignore=())
    # A mode's name and its "Recommended" badge stay readable: the name keeps one line.
    head = card.locator(".choice-card", has_text="Share links only").locator(".choice-card-label")
    box = head.bounding_box()
    assert box and box["height"] < 40, f"the mode name wraps: {box}"
    shot(page, request, f"funnel-advanced-{scheme}")
    watch.assert_clean()


# Fake a visual viewport `loss` px shorter than the layout viewport, as a browser's bottom toolbar (Safari's and
# Brave's, the floating bar of iOS 26), pinch zoom or an on-screen keyboard leave it, and report where the open
# bottom sheet sits and how much of its body shows.
SHEET_UNDER_LOSS_JS = """async ({loss, focus}) => {
  const vv = window.visualViewport;
  const frame = () => new Promise((r) => requestAnimationFrame(() => requestAnimationFrame(r)));
  const real = Object.getOwnPropertyDescriptor(VisualViewport.prototype, 'height').get;
  Object.defineProperty(vv, 'height', { configurable: true, get: () => real.call(vv) - loss });
  const sheet = document.querySelector('dialog[open]');
  await Promise.all(sheet.getAnimations().map((a) => a.finished.catch(() => {})));  // the slide-in
  if (focus) sheet.querySelector(focus).focus(); else document.activeElement?.blur();
  vv.dispatchEvent(new Event('resize'));
  await frame();
  const body = sheet.querySelector('.dialog-body');
  const r = sheet.getBoundingClientRect();
  const res = { kb: sheet.style.getPropertyValue('--fp-kb'), flag: sheet.hasAttribute('data-kb'),
                gap: Math.round(innerHeight - r.bottom), height: Math.round(r.height),
                body: body.clientHeight, content: body.scrollHeight };
  delete vv.height;
  vv.dispatchEvent(new Event('resize'));
  await frame();
  return res;
}"""


def test_sheets_ignore_toolbar_viewport_loss(new_page, server, sample_state, request, device):
    """Bug report (iPhone, Brave): the Move, Share and Upload sheets were squeezed to a sliver, their content hidden
    behind the buttons. A browser toolbar or zoom leaves the visual viewport shorter than the layout viewport with no
    keyboard open, and dialog.js lifted and shrank the sheet by that difference. Only a keyboard-sized loss while a
    text field of the sheet has the focus may move it; everything else keeps the sheet at the bottom, full size."""
    page, watch = new_page(profile=device, storage_state=sample_state)
    page.goto("/files")
    expect(page.get_by_text("hello.txt", exact=True).first).to_be_visible()
    page.locator(".fv-row", has_text="hello.txt").locator(".fv-more").first.click()
    page.get_by_role("dialog").or_(page.get_by_role("menu")).first.get_by_text("Move to…").first.click()
    dlg = page.get_by_role("dialog", name=re.compile("^Move", re.I))
    expect(dlg).to_be_visible()
    # The body must size from its content: iOS WebKit resolves `flex: 1` (a 0% basis) to 0 in the sheet, whose height
    # comes from its content, which drew the head and the buttons with the body squeezed to nothing between them.
    # Chromium and desktop WebKit resolve it to the content height, so check the rule itself.
    basis = dlg.locator(".dialog-body").evaluate("(el) => getComputedStyle(el).flexBasis")
    assert basis == "auto", f"the sheet's body has flex-basis {basis}: iPhones collapse it"

    for loss in (60, 140, 190):  # collapsed and expanded toolbars, zoom: none of them is a keyboard
        res = page.evaluate(SHEET_UNDER_LOSS_JS, {"loss": loss, "focus": None})
        assert res["kb"] == "0px" and not res["flag"], f"a {loss} px toolbar was taken for a keyboard: {res}"
        assert abs(res["gap"]) <= 1, f"the sheet left the bottom of the screen: {res}"
        assert res["body"] >= res["content"] - 1, f"the sheet's content is squeezed: {res}"
    shot(page, request, "move-sheet-toolbar")
    dlg.get_by_role("button", name="Cancel").click()
    expect(dlg).to_be_hidden()

    # the Share sheet: a toolbar while its people field has the focus (a hardware keyboard) moves nothing either,
    # a real keyboard lifts it and keeps the field in view
    page.locator(".fv-row", has_text="hello.txt").locator(".fv-more").first.click()
    page.get_by_role("dialog").or_(page.get_by_role("menu")).first.get_by_text("Share…").first.click()
    share = page.get_by_role("dialog", name=re.compile("^Share", re.I))
    expect(share).to_be_visible()
    field = "input[type=text], input:not([type])"
    res = page.evaluate(SHEET_UNDER_LOSS_JS, {"loss": 140, "focus": field})
    assert res["kb"] == "0px" and abs(res["gap"]) <= 1, f"a toolbar lifted the sheet while a field had the focus: {res}"
    res = page.evaluate(SHEET_UNDER_LOSS_JS, {"loss": 300, "focus": field})
    assert res["kb"] == "300px" and res["flag"] and abs(res["gap"] - 300) <= 1, f"the keyboard did not lift the sheet: {res}"
    res = page.evaluate(SHEET_UNDER_LOSS_JS, {"loss": 300, "focus": None})
    assert res["kb"] == "0px" and not res["flag"], f"the sheet stayed lifted after the field lost the focus: {res}"
    share.get_by_role("button", name="Done").click()
    expect(share).to_be_hidden()
    watch.assert_clean()
