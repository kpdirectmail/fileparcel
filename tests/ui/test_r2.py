"""Verification round 2 regressions (DESIGN §13.5 touch targets, §17 Playwright).

Every test here reproduces a defect found in round 2; they are expected to be
red until the fix lands. Each docstring says what is wrong and where.
"""

from __future__ import annotations

import re
import secrets

import pytest
from conftest import (
    assert_tap_targets,
    cookie_state,
    png_bytes,
    shot,
)
from playwright.sync_api import expect

PHONES = ["Pixel 7", "iPhone 14"]


# ------------------------------------------------------------------ helpers
def _member(server, prefix="r2"):
    """A throw-away member account plus a signed-in API client."""
    adm = server.client()
    adm.login(server.admin, server.admin_password, server.admin_totp, server.clock)
    name = f"{prefix}{secrets.token_hex(4)}"
    pw = "Ui-" + secrets.token_hex(12)
    adm.ok("POST", "/api/v1/admin/users",
           {"username": name, "password": pw, "role": "member", "display_name": name})
    api = server.client()
    api.login(name, pw)
    return api, name, pw


def _row_state(page):
    return page.evaluate("""() => [...document.querySelectorAll('.fv-row, .fv-cell')].map((r) => ({
        name: (r.querySelector('.fv-name-label, .fv-cell-name') || {}).textContent,
        selected: r.getAttribute('aria-selected') === 'true',
        checked: !!r.querySelector('.fv-check input')?.checked,
      }))""")


# ---------------------------------------------------- selection checkboxes
@pytest.mark.parametrize("mode", ["list", "grid"])
def test_clicking_a_row_checkbox_ticks_it(new_page, server, request, mode):
    """components/file-view.js: the click handler for `.fv-check` calls
    `e.preventDefault()` *before* `emit()` -> `syncRows()` sets `cb.checked`.
    Chromium restores a cancelled checkbox click's pre-click checkedness after
    the listener returns, so the box that was just clicked stays empty while
    the row shows as selected. Ctrl-clicking the row or "Select all" are fine.
    """
    api, *_ = _member(server, "cb")
    root = api.root_id()
    api.upload_small(root, "one.txt", b"one\n")
    api.upload_small(root, "two.png", png_bytes())
    page, watch = new_page(storage_state=cookie_state(server, api))
    page.goto("/files")
    page.wait_for_load_state("networkidle")
    if mode == "grid":
        page.locator("button[aria-label='Grid view']").click()
    check = page.locator(".fv-row .fv-check, .fv-cell .fv-check").first
    expect(check).to_be_visible()
    check.click()
    page.wait_for_timeout(500)
    rows = _row_state(page)
    shot(page, request, f"checkbox-{mode}")
    assert rows[0]["selected"], "clicking the checkbox did not select the row"
    assert rows[0]["checked"], (
        f"the row is selected but its checkbox is not ticked ({mode} view): {rows}")
    # ... and clicking it again must clear both (the native toggle must not win over `selected`).
    check.click()
    page.wait_for_timeout(500)
    rows = _row_state(page)
    assert not rows[0]["selected"] and not rows[0]["checked"], (
        f"clicking the checkbox again left row and box out of sync ({mode} view): {rows}")
    watch.assert_clean()


# --------------------------------------------------------- breadcrumb trail
@pytest.mark.parametrize("device", PHONES)
def test_deep_breadcrumbs_leave_room_for_the_file_list(new_page, server, request, device):
    """components.css: at `@media (pointer: coarse)` every breadcrumb link gets
    `min-height/line-height: 44px` while `.breadcrumbs a` keeps `max-width: 24ch;
    white-space: nowrap`, so on a phone only one crumb fits per 46 px line. Six
    levels deep the header eats 63 % (Pixel 7) to 79 % (iPhone 14) of the
    viewport before the first file row. The trail needs to collapse
    ("… / parent / current") or scroll horizontally instead of stacking.
    """
    api, *_ = _member(server, "crumb")
    node = api.root_id()
    for i in range(6):
        node = api.ok("POST", f"/api/v1/nodes/{node}/folders",
                      {"name": f"Level {i + 1} folder with a fairly long name"})["id"]
    api.upload_small(node, "deepest.txt", b"deep\n")
    page, watch = new_page(profile=device, storage_state=cookie_state(server, api))
    page.goto(f"/files/{node}")
    page.wait_for_load_state("networkidle")
    expect(page.locator(".fv-row").first).to_be_visible()
    m = page.evaluate("""() => {
        const c = document.querySelector('.breadcrumbs');
        const row = document.querySelector('.fv-row');
        return {vh: innerHeight, crumbs: Math.round(c.getBoundingClientRect().height),
                firstRow: Math.round(row.getBoundingClientRect().top),
                overflow: Math.round(document.documentElement.scrollWidth - innerWidth)};
      }""")
    shot(page, request, "deep-breadcrumbs")
    assert m["crumbs"] <= 100, f"the breadcrumb trail is {m['crumbs']} px tall on {device}: {m}"
    assert m["firstRow"] < m["vh"] * 0.55, (
        f"the first file row starts at {m['firstRow']} of {m['vh']} px on {device}: {m}")
    # A trail that scrolls must scroll inside its own nav, never widen the page (DESIGN §13.5).
    assert m["overflow"] <= 1, f"the deep trail overflows the page by {m['overflow']} px on {device}: {m}"
    watch.assert_clean()


# ------------------------------------------------------------ admin groups
def test_admin_group_rows_are_touch_sized(new_page, server, admin_state, request):
    """pages/admin.css: `.row-link` (the group name in the identity cell) has no
    height of its own, so on a phone it is a 20 px tap target (39 px when the
    name wraps to two lines) - well under the 44 px floor DESIGN §13.5 puts on
    every interactive element. The 56 px row around it is clickable and
    keyboard-activatable to the same URL; what is asserted here is the floor on
    the anchor itself. Round 1 could not see this because /admin/groups had no
    groups, so the page rendered no rows at all.
    """
    adm = server.client()
    adm.login(server.admin, server.admin_password, server.admin_totp, server.clock)
    for name in ("Design team", f"A group with a really quite long name {secrets.token_hex(2)}"):
        adm.request("POST", "/api/v1/admin/groups", {"name": name})
    page, watch = new_page(profile="Pixel 7", storage_state=admin_state)
    page.goto("/admin/groups")
    page.wait_for_load_state("networkidle")
    expect(page.get_by_text("Design team", exact=True).first).to_be_visible()
    shot(page, request, "admin-groups")
    assert_tap_targets(page, 44, ignore=())
    watch.assert_clean()


# ------------------------------------------------- share summary separators
def test_share_summary_separator_never_ends_a_line(new_page, server, request):
    """components/share-dialog.js `shareSummary()` joins its parts with a plain
    " · " string. On /links and /requests it is rendered into the narrow
    `.share-cell-mobile` line, so at phone widths the separator wraps to the end
    of a line ("Expires in 7 days ·" / "0 downloads ·"). Round 1 fixed exactly
    this on the public share page (public/share.js `.share-meta-sep`); the same
    treatment is missing here.
    """
    api, *_ = _member(server, "sep")
    root = api.root_id()
    nid = api.upload_small(root, "report.pdf", b"%PDF-1.4\n%%EOF\n")
    api.ok("POST", "/api/v1/shares", {"node_id": nid, "kind": "link", "max_downloads": 3})
    folder = api.ok("POST", f"/api/v1/nodes/{root}/folders", {"name": "Deliverables"})["id"]
    api.ok("POST", "/api/v1/shares", {"node_id": folder, "kind": "link", "password": "pw-12345678"})
    page, watch = new_page(profile="Pixel 7", storage_state=cookie_state(server, api))
    page.goto("/links")
    page.wait_for_load_state("networkidle")
    expect(page.get_by_text("report.pdf").first).to_be_visible()
    # Split every meta line into its rendered lines with Range rectangles. The summary is built from
    # several text nodes (each separator rides in its own <span>), so walk all of them in order.
    lines = page.evaluate(r"""() => {
        const out = [];
        for (const el of document.querySelectorAll('.share-cell-mobile')) {
          const walk = document.createTreeWalker(el, NodeFilter.SHOW_TEXT);
          const r = document.createRange();
          let prevTop = null, buf = '';
          for (let node = walk.nextNode(); node; node = walk.nextNode()) {
            const text = node.textContent;
            for (let i = 0; i < text.length; i += 1) {
              r.setStart(node, i); r.setEnd(node, i + 1);
              const top = Math.round(r.getBoundingClientRect().top);
              if (prevTop !== null && top !== prevTop) { out.push(buf); buf = ''; }
              prevTop = top; buf += text[i];
            }
          }
          if (buf) out.push(buf);
        }
        return out.map((s) => s.trim()).filter(Boolean);
      }""")
    shot(page, request, "links-meta")
    assert any("·" in ln for ln in lines), (
        f"the meta line shows no separator at all, so this test proves nothing: {lines}")
    dangling = [ln for ln in lines if ln.endswith("·")]
    assert not dangling, f"a separator ends a wrapped line: {dangling} (all lines: {lines})"
    watch.assert_clean()


# ----------------------------------------------------- mobile preview tools
@pytest.mark.parametrize("device", PHONES)
def test_mobile_preview_can_download_and_share(new_page, server, request, device):
    """pages/preview.css:52 hides every `.pv-tool` except the info button below
    640 px, and the mobile info panel only offers "More details" (which closes
    the preview). A phone user looking at a photo therefore cannot download or
    share it without leaving the preview. Swipe still handles prev/next.
    """
    api, *_ = _member(server, "pv")
    api.upload_small(api.root_id(), "photo.png", png_bytes())
    page, watch = new_page(profile=device, storage_state=cookie_state(server, api))
    page.goto("/files")
    page.wait_for_load_state("networkidle")
    page.get_by_text("photo.png", exact=True).first.tap()
    stage = page.locator(".pv-stage img").first
    expect(stage).to_be_visible()
    shot(page, request, "mobile-preview")
    tools = page.evaluate("""() => [...document.querySelectorAll('.pv button, .pv a[href]')]
        .filter((e) => e.getClientRects().length)
        .map((e) => (e.getAttribute('aria-label') || e.textContent || '').trim())""")
    assert any(re.search(r"download", t, re.I) for t in tools), f"no Download in the preview: {tools}"
    assert any(re.search(r"share", t, re.I) for t in tools), f"no Share in the preview: {tools}"
    watch.assert_clean()


# ----------------------------------------------------- appearance card hue
@pytest.mark.parametrize("scheme", ["light", "dark"])
def test_selected_choice_card_uses_the_brand_hue(new_page, server, alice_state, request, scheme):
    """pages/settings.css:175 paints the selected choice card with
    `color-mix(in oklch, var(--fp-primary) 5%, var(--fp-surface))`. In light mode
    `--fp-surface` is `oklch(1 0 0)` - an explicit hue of 0 - so the hue
    interpolates the short way from 0 towards 255 *backwards* and lands on
    ~354.75deg: the selected Theme / Density / Default-view card gets a rose
    wash that clashes with its blue border, blue tick and blue focus ring.
    Dark mode is fine because `--fp-surface` already carries hue 255.
    """
    page, watch = new_page(scheme=scheme, storage_state=alice_state)
    page.goto("/settings/appearance")
    page.wait_for_load_state("networkidle")
    card = page.locator(".choice-card:has(input:checked)").first
    expect(card).to_be_visible()
    hues = page.evaluate("""() => {
        const hue = (s) => { const m = /oklch\\(\\s*[\\d.]+\\s+([\\d.]+)\\s+([\\d.]+)/.exec(s);
                             return m ? {c: parseFloat(m[1]), h: parseFloat(m[2])} : null; };
        const d = document.createElement('div'); document.body.appendChild(d);
        d.style.color = 'var(--fp-primary)';
        const primary = hue(getComputedStyle(d).color); d.remove();
        const card = document.querySelector('.choice-card:has(input:checked)');
        return {primary, card: hue(getComputedStyle(card).backgroundColor)};
      }""")
    shot(page, request, "choice-card")
    assert hues["card"], f"could not read the card colour: {hues}"
    if hues["card"]["c"] < 0.002:
        return  # a neutral fill is fine; only a *tinted* one must match the brand
    delta = abs(hues["card"]["h"] - hues["primary"]["h"])
    delta = min(delta, 360 - delta)
    assert delta <= 30, (
        f"the selected card is tinted {hues['card']['h']}deg, the brand hue is "
        f"{hues['primary']['h']}deg ({scheme} mode): {hues}")
    watch.assert_clean()
