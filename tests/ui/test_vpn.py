"""VPN detection on Admin → Network (DESIGN §10.1, §10.3, §13.8): the interfaces grouped by role, the role menu
(network.iface_roles), the VPN quick-add buttons of the policy editor, the exposure warnings, the Tailscale card's
certificate warning and the dashboard's VPN chip.

Which interfaces the test server has depends on the machine, so GET /admin/network is answered with a fixed overview
(page.route) that holds every role; the rest of the page, the settings requests of the role menu (with the step-up
they need) and the stored setting are the real server's.
"""

from __future__ import annotations

import copy
import json
import re

import pytest
from conftest import api_storage_state, assert_no_overflow, assert_tap_targets, confirm_identity, shot
from playwright.sync_api import expect

HEADSCALE_NOTE = ("custom Headscale prefixes: add them with `fileparcel network allow add <prefix>` "
                  "(see `prefixes` in headscale's config)")


def iface(name, kind, label, role, addrs, **kw):
    d = {"name": name, "kind": kind, "label": label, "up": True, "addrs": addrs, "mtu": 1420, "is_vpn": kind not in
         ("lan", "wifi", "loopback", "container"), "role": role, "role_source": "auto"}
    d.update(kw)
    return d


INTERFACES = [
    iface("lo", "loopback", "Loopback", "none", ["127.0.0.1/8", "::1/128"], mtu=65536),
    iface("eth0", "lan", "LAN", "local", ["192.168.77.6/24"], mtu=1500),
    iface("tailscale0", "headscale", "Headscale", "mesh", ["10.99.0.3/32"], mtu=1280),
    iface("zt0", "zerotier", "ZeroTier", "mesh", ["10.147.17.5/24"], mtu=2800),
    iface("wg1", "wireguard", "WireGuard", "unknown", ["10.8.0.2/24"]),
    iface("wg2", "wireguard", "WireGuard", "unknown", ["10.9.0.2/32"]),
    iface("ygg0", "yggdrasil", "Yggdrasil", "overlay", ["201:1:2::3/7"]),
    iface("nordlynx", "exitvpn", "NordVPN", "egress", ["10.5.0.2/16"], provider="nordvpn"),
    iface("wg0-mullvad", "exitvpn", "Mullvad VPN", "egress", ["10.64.1.2/32"], provider="mullvad",
          detail="carries the default route", default_route=True),
    iface("gpd0", "corpvpn", "GlobalProtect", "access", ["10.200.0.9/24"], provider="paloalto"),
    iface("docker0", "container", "Container", "none", ["172.17.0.1/16"], mtu=1500),
]


def vpn(id_, kind, label, role, ifaces, ranges, allowed, can_allow, recommended, **kw):
    d = {"id": id_, "kind": kind, "label": label, "role": role, "role_source": "auto", "interfaces": ifaces,
         "ranges": ranges, "allowed": allowed, "can_allow": can_allow, "needs_force": False, "recommended": recommended}
    d.update(kw)
    return d


VPNS = [
    vpn("headscale", "headscale", "Headscale (self-hosted control server?)", "mesh", ["tailscale0"], [], "no", False, False,
        note=HEADSCALE_NOTE),
    vpn("zerotier", "zerotier", "ZeroTier", "mesh", ["zt0"], ["10.147.17.0/24"], "no", True, True),
    vpn("wg1", "wireguard", "WireGuard (wg1)", "unknown", ["wg1"], ["10.8.0.0/24"], "yes", True, True),
    vpn("wg2", "wireguard", "WireGuard (wg2)", "unknown", ["wg2"], [], "no", False, False,
        note="host-only address: add its network with `fileparcel network allow add CIDR`"),
    vpn("yggdrasil", "yggdrasil", "Yggdrasil", "overlay", ["ygg0"], ["200::/7"], "no", True, False, needs_force=True,
        warning="public overlay: anyone on the Yggdrasil network"),
    vpn("paloalto", "corpvpn", "GlobalProtect", "access", ["gpd0"], [], "no", False, False),
    vpn("nordvpn", "exitvpn", "NordVPN", "egress", ["nordlynx"], [], "no", False, False),
    vpn("mullvad", "exitvpn", "Mullvad VPN", "egress", ["wg0-mullvad"], [], "no", False, False),
]

EXPOSURES = [{"id": "tailscale.userspace", "severity": "warn",
              "message": "Tailscale runs without a TUN device: tailnet connections reach FileParcel from 127.0.0.1 and bypass the access policy.",
              "hint": "Run tailscaled with a TUN device, or use Tailscale Serve (fileparcel network tailscale-serve enable), which keeps the real tailnet address."}]

TAILSCALE = {"running": True, "kind": "headscale", "kind_guessed": True, "backend_state": "Running",
             "dns_name": "box.hs.example.org", "ips": ["10.99.0.3"], "installed": True, "cert_capable": False,
             "userspace": True, "shields_up": False, "can_configure": False, "funnel_capable": False}


class FakeOverview:
    """Serves GET /admin/network from the real answer (read once over the API) with the interfaces, VPNs,
    exposures, policy and Tailscale status above; a PATCH of network.iface_roles through the page is applied to the
    fake interfaces (the request itself goes on to the server)."""

    def __init__(self, page, real: dict, interfaces=None, vpns=None, policy=None):
        self.roles: dict[str, str] = {}
        self.patched: list[list[str]] = []
        self.real = real
        self.interfaces = INTERFACES if interfaces is None else interfaces
        self.vpns = VPNS if vpns is None else vpns
        self.policy = policy or {"mode": "allowlist", "allow": ["192.168.77.0/24", "10.8.0.0/16"], "deny": []}
        page.route("**/api/v1/admin/network", self._overview)
        page.route("**/api/v1/admin/settings", self._settings)
        page.route("**/api/v1/admin/certs", lambda route: route.fulfill(
            status=200, content_type="application/json", body=json.dumps({"uncovered_names": ["box.hs.example.org"]})))

    def _overview(self, route):
        if route.request.method != "GET":
            route.continue_()
            return
        real = copy.deepcopy(self.real)
        ifs = copy.deepcopy(self.interfaces)
        for i in ifs:
            if i["name"] in self.roles:
                i["role"], i["role_source"] = self.roles[i["name"]], "override"
        real.update({"interfaces": ifs, "vpns": self.vpns, "exposures": EXPOSURES, "tailscale": TAILSCALE,
                     "policy": self.policy})
        route.fulfill(status=200, content_type="application/json", body=json.dumps(real))

    def _settings(self, route):
        if route.request.method == "PATCH":
            body = route.request.post_data_json or {}
            if "network.iface_roles" in body:
                entries = body["network.iface_roles"]
                self.patched.append(entries)
                self.roles = dict(e.split("=", 1) for e in entries)
        route.continue_()


def group(page, title):
    """The interfaces card's section with this title (an open <div> or a collapsed <details>)."""
    return page.locator(".iface-group").filter(has=page.locator(".iface-group-title, summary", has_text=title))


def row(page, name):
    return page.locator(".iface-row").filter(has=page.locator("strong", has_text=name)).first


@pytest.fixture(scope="module")
def admin_api(server):
    """One administrator API session for the module (every sign-in waits for a fresh TOTP step)."""
    api = server.client()
    api.login(server.admin, server.admin_password, server.admin_totp, server.clock)
    return api


@pytest.fixture(scope="module")
def real_overview(admin_api):
    """The server's own GET /admin/network, the base of the fixed overview."""
    return admin_api.ok("GET", "/api/v1/admin/network")


@pytest.fixture
def reset_roles(server, admin_api):
    """Removes network.iface_roles again (the session server is shared)."""
    yield
    assert admin_api.elevate(server.admin_password)
    admin_api.ok("DELETE", "/api/v1/admin/settings/network.iface_roles")


def stored_roles(api) -> list[str]:
    views = api.ok("GET", "/api/v1/admin/settings?section=network")
    views = views.get("items", views) if isinstance(views, dict) else views
    return next(v["value"] for v in views if v["key"] == "network.iface_roles")


def test_interfaces_grouped_by_role(new_page, admin_state, real_overview, request):
    page, watch = new_page(storage_state=admin_state)
    FakeOverview(page, real_overview)
    page.goto("/admin/network")
    reach = group(page, "VPNs that reach this server")
    expect(reach).to_be_visible()
    for name in ("tailscale0", "zt0", "wg1", "wg2"):
        expect(reach.locator(".iface-row strong", has_text=name)).to_be_visible()
    expect(group(page, "Local networks").locator(".iface-row strong", has_text="eth0")).to_be_visible()
    overlay = group(page, "Public overlay")
    expect(overlay.locator(".alert")).to_contain_text("Anyone on this network can try to connect")
    expect(overlay.locator(".iface-row strong", has_text="ygg0")).to_be_visible()

    # Outgoing-only VPNs are folded away with the reason.
    out = group(page, "Outgoing-only VPNs (3)")
    expect(out).to_be_visible()
    expect(out.locator(".iface-row").first).to_be_hidden()
    out.locator("summary").click()
    expect(out).to_contain_text("Other devices cannot reach this server through these")
    for name in ("nordlynx", "wg0-mullvad", "gpd0"):
        expect(out.locator(".iface-row strong", has_text=name)).to_be_visible()
    expect(row(page, "wg0-mullvad")).to_contain_text("carries the default route")
    expect(row(page, "gpd0")).to_contain_text("by Palo Alto Networks")
    expect(row(page, "nordlynx")).not_to_contain_text("by NordVPN")  # the label already says it

    # The VPN's policy state and note.
    expect(row(page, "zt0").locator(".badge", has_text="Not allowed")).to_be_visible()
    expect(row(page, "wg1").locator(".badge", has_text="Allowed")).to_be_visible()
    expect(row(page, "tailscale0").locator("code", has_text="fileparcel network allow add <prefix>")).to_be_visible()
    expect(page.locator(".iface-row").filter(has=page.locator("strong", has_text="lo")).first.locator("button")).to_have_count(0)

    # Exposures and the Tailscale card: a guessed Headscale whose name the local certificate does not cover.
    expect(page.locator(".alert", has_text="Tailscale runs without a TUN device")).to_be_visible()
    ts_card = page.locator(".card", has=page.locator(".card-title", has_text=re.compile(r"^Tailscale$")))
    expect(ts_card.locator(".badge", has_text="Headscale (self-hosted control server?)")).to_be_visible()
    expect(ts_card.locator(".alert", has_text="does not cover the MagicDNS name")).to_contain_text("fileparcel ca regenerate")
    shot(page, request, "network-vpns")
    watch.assert_clean()


def test_policy_editor_offers_the_vpns(new_page, admin_state, real_overview):
    page, watch = new_page(storage_state=admin_state)
    FakeOverview(page, real_overview)
    page.goto("/admin/network")
    policy = page.locator(".card", has=page.locator(".card-title", has_text="Who can connect"))
    allow = policy.get_by_label("Allowed networks")
    expect(allow).to_have_value("192.168.77.0/24\n10.8.0.0/16")
    # One button per VPN devices come in through that is not fully allowed; never an outgoing VPN.
    zt = policy.get_by_role("button", name="ZeroTier")
    expect(zt).to_have_attribute("title", "Allow 10.147.17.0/24")
    for absent in ("WireGuard (wg1)", "NordVPN", "Mullvad VPN", "GlobalProtect", "Headscale"):
        expect(policy.get_by_role("button", name=absent)).to_have_count(0)
    notes = policy.locator(".vpn-notes")
    expect(notes).to_contain_text("Yggdrasil: public overlay: anyone on the Yggdrasil network")
    expect(notes.locator("code", has_text="fileparcel network allow add <prefix>")).to_be_visible()
    expect(notes).to_contain_text("WireGuard (wg2): host-only address")
    zt.click()
    expect(allow).to_have_value("192.168.77.0/24\n10.8.0.0/16\n10.147.17.0/24")

    # A public overlay asks first.
    policy.get_by_role("button", name="Yggdrasil").click()
    dlg = page.get_by_role("dialog", name="Allow Yggdrasil?")
    expect(dlg).to_contain_text("public overlay network")
    dlg.get_by_role("button", name="Cancel").click()
    expect(allow).not_to_have_value("200::/7")
    policy.get_by_role("button", name="Yggdrasil").click()
    page.get_by_role("dialog", name="Allow Yggdrasil?").get_by_role("button", name="Allow").click()
    expect(allow).to_have_value("192.168.77.0/24\n10.8.0.0/16\n10.147.17.0/24\n200::/7")
    watch.assert_clean()


def test_role_menu_sets_and_clears_an_override(new_page, server, admin_api, real_overview, reset_roles):
    # Its own session: the step-up rotates the session token, which would sign out the shared admin_state.
    state = api_storage_state(server, server.admin, server.admin_password, server.admin_totp)
    page, watch = new_page(storage_state=state)
    fake = FakeOverview(page, real_overview)
    page.goto("/admin/network")
    wg1 = row(page, "wg1")
    wg1.get_by_role("button", name="How FileParcel treats wg1").click()
    page.get_by_role("menuitem", name="Outgoing only").click()
    confirm_identity(page, server.admin_password)  # the network section is step-up protected
    expect(page.get_by_text("wg1 is now treated as outgoing only")).to_be_visible()
    out = group(page, "Outgoing-only VPNs (4)")
    expect(out).to_be_visible()
    out.locator("summary").click()
    expect(row(page, "wg1").locator(".badge", has_text="Override")).to_be_visible()
    assert stored_roles(admin_api) == ["wg1=egress"]

    # The current choice is marked; "Automatic" removes the entry again.
    row(page, "wg1").get_by_role("button", name="How FileParcel treats wg1").click()
    expect(page.get_by_role("menuitem", name="Outgoing only")).to_be_disabled()
    page.get_by_role("menuitem", name="Automatic").click()
    expect(page.get_by_text("wg1 is classified automatically again")).to_be_visible()
    expect(group(page, "VPNs that reach this server").locator(".iface-row strong", has_text="wg1")).to_be_visible()
    expect(row(page, "wg1").locator(".badge", has_text="Override")).to_have_count(0)
    assert stored_roles(admin_api) == []
    assert fake.patched[-1] == []
    # the first PATCH answered 403 elevation_required (the browser logs it); the page asked for the password
    watch.errors = [e for e in watch.errors if "403" not in e]
    watch.assert_clean()


def test_dashboard_vpn_chip_counts_incoming_vpns(new_page, admin_state, real_overview):
    page, watch = new_page(storage_state=admin_state)
    FakeOverview(page, real_overview)
    page.goto("/admin")
    tile = page.locator(".stat", has=page.locator(".stat-label", has_text="Network"))
    expect(tile).to_contain_text("VPN: Headscale, ZeroTier, WireGuard")
    for absent in ("NordVPN", "Mullvad", "GlobalProtect", "Yggdrasil"):
        expect(tile).not_to_contain_text(absent)
    watch.assert_clean()


# A cloud VM (eth0 on the provider's public network, with a global IPv6 prefix and link-local addresses), a private
# second interface with a ULA host address, and a Mac's always-present utun0/utun1 (link-local only).
CLOUD_INTERFACES = [
    iface("lo", "loopback", "Loopback", "none", ["127.0.0.1/8", "::1/128"], mtu=65536),
    iface("eth0", "lan", "LAN", "local", ["203.0.113.45/24", "2001:db8:5::45/64", "fe80::1/64", "169.254.3.4/16"], mtu=1500),
    iface("ens4", "lan", "LAN", "local", ["10.20.0.5/24", "fd00:20::5/128"], mtu=1500),
    iface("utun0", "vpn", "VPN", "unknown", ["fe80::a/64"], mtu=1380),
    iface("utun1", "vpn", "VPN", "unknown", ["fe80::b/64"], mtu=2000),
    iface("zt0", "zerotier", "ZeroTier", "mesh", ["10.147.17.5/24"], mtu=2800),
]
CLOUD_VPNS = [vpn("zerotier", "zerotier", "ZeroTier", "mesh", ["zt0"], ["10.147.17.0/24"], "no", True, True)]


def test_policy_editor_local_suggestions_follow_the_installer(new_page, admin_state, real_overview):
    """The quick-add buttons for local networks follow the installer's allowlist rule: never the provider's public
    subnet or the global IPv6 prefix next to a public IPv4 address, never link-local ranges, host addresses stay
    host addresses."""
    page, watch = new_page(storage_state=admin_state)
    FakeOverview(page, real_overview, interfaces=CLOUD_INTERFACES, vpns=CLOUD_VPNS,
                 policy={"mode": "allowlist", "allow": [], "deny": []})
    page.goto("/admin/network")
    policy = page.locator(".card", has=page.locator(".card-title", has_text="Who can connect"))
    for name in ("10.20.0.0/24", "fd00:20::5/128", "ZeroTier"):
        expect(policy.get_by_role("button", name=name, exact=True)).to_be_visible()
    for name in ("203.0.113.0/24", "2001:db8:5::/64", "169.254.0.0/16", "fd00:20::/64", "fe80::/64"):
        expect(policy.get_by_role("button", name=name, exact=True)).to_have_count(0)
    watch.assert_clean()


def test_linklocal_vpn_interfaces_are_not_listed_as_vpns(new_page, admin_state, real_overview):
    """macOS's utun0–utun3 (link-local only) are not "VPNs that reach this server" and not in the dashboard's chip."""
    page, watch = new_page(storage_state=admin_state)
    FakeOverview(page, real_overview, interfaces=CLOUD_INTERFACES, vpns=CLOUD_VPNS)
    page.goto("/admin/network")
    reach = group(page, "VPNs that reach this server")
    expect(reach.locator(".iface-row strong", has_text="zt0")).to_be_visible()
    expect(reach.locator(".iface-row strong", has_text="utun0")).to_have_count(0)
    other = group(page, "Other")
    other.locator("summary").click()
    for name in ("utun0", "utun1"):
        expect(other.locator(".iface-row strong", has_text=name)).to_be_visible()
    page.goto("/admin")
    tile = page.locator(".stat", has=page.locator(".stat-label", has_text="Network"))
    expect(tile).to_contain_text("VPN: ZeroTier")
    expect(tile).not_to_contain_text("VPN: VPN")
    expect(tile).not_to_contain_text("ZeroTier, VPN")
    watch.assert_clean()


@pytest.mark.parametrize("scheme", ["light", "dark"])
def test_320px_network_vpns(new_page, admin_state, real_overview, request, scheme):
    """/admin/network with every role at 320 px: no horizontal overflow, 44 px touch targets (the role menus and
    the quick-add buttons), the role menu as a bottom sheet."""
    page, watch = new_page(profile="Pixel 7", scheme=scheme, storage_state=admin_state, viewport={"width": 320, "height": 640})
    FakeOverview(page, real_overview)
    page.goto("/admin/network")
    expect(group(page, "VPNs that reach this server")).to_be_visible()
    for title in ("Outgoing-only VPNs", "Other"):
        group(page, title).locator("summary").click()
    page.wait_for_load_state("networkidle")
    assert_no_overflow(page)
    for part in (group(page, "VPNs that reach this server"), group(page, "Public overlay"), group(page, "Outgoing-only VPNs"),
                 page.locator(".vpn-notes"), page.get_by_role("button", name="ZeroTier")):
        part.evaluate("el => el.scrollIntoView({block: 'center', inline: 'nearest'})")
        page.wait_for_timeout(100)
        assert_tap_targets(page, 44, ignore=())
    row(page, "zt0").get_by_role("button", name="How FileParcel treats zt0").click()
    expect(page.get_by_role("button", name="Outgoing only")).to_be_visible()  # the bottom sheet's rows
    shot(page, request, f"network-vpns-{scheme}")
    page.keyboard.press("Escape")
    watch.assert_clean()
