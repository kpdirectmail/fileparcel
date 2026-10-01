// @ts-check
/**
 * Admin → Network & VPN (/admin/network): how to reach the server (access URLs with copy + QR), remote access through
 * Tailscale Funnel and Serve (network-remote.js; cards #funnel and #serve), the network interfaces grouped by role
 * (VPNs that reach this server, local networks, public overlays, outgoing-only VPNs, other; DESIGN §10.1) with a
 * role menu per interface, the access policy editor (private / allowlist / any, allow + deny CIDRs) with a client-side
 * lockout preview and quick-add buttons for the local subnets and the detected VPNs, Tailscale details and the mDNS
 * (.local name) status with "republish".
 *   GET /admin/network                                  → NetworkOverview {interfaces, urls, policy, tailscale, client_ip,
 *                                                         ingress, vpns, exposures}
 *   PUT /admin/network/policy {mode, allow, deny, force} (E) → PolicyResult {policy, warnings}; 409 = would lock you out
 *   GET /admin/settings?section=network, PATCH /admin/settings {"network.iface_roles": […]} (E) → the role menu
 *   GET /admin/certs (certs.manage; optional) → whether the local certificate covers a Headscale MagicDNS name
 *   GET /admin/mdns → MDNSStatus · POST /admin/mdns/republish
 * The warnings on top list the exposures (ways around the access policy) and a public Funnel app.
 * Refreshes on network.changed / mdns.changed / ingress.changed.
 * Owned by unit J2.
 * @module pages/admin/network
 */
import { h, icon, replace, append } from '../../core/dom.js';
import { api, ApiError, itemsOf } from '../../core/api.js';
import { button, iconButton } from '../../components/button.js';
import { badge } from '../../components/badge.js';
import { card } from '../../components/card.js';
import { toast } from '../../components/toast.js';
import { dialog, confirm } from '../../components/dialog.js';
import { menu } from '../../components/menu.js';
import { field } from '../../components/field.js';
import { copyText, copyField } from '../../components/copy-field.js';
import { qrImage, qrURL } from '../../components/qr-image.js';
import { skeleton } from '../../components/progress.js';
import { can } from '../../core/store.js';
import { pathAllowed } from '../../routes.js';
import { adminHeader, errorPanel, alertEl, kv, chips, stateBadge, ipAllowed, parseCIDR, PRIVATE_CIDRS, onEvents, debounce } from './common.js';
import { remoteAccessCards } from './network-remote.js';

export const title = 'Network & VPN';

/** Interface kinds: fallback label (the server sends one) and icon. Unknown kinds get the network icon. */
const KIND_INFO = /** @type {Record<string, {label: string, icon: string}>} */ ({
  tailscale: { label: 'Tailscale', icon: 'tailscale' },
  headscale: { label: 'Headscale', icon: 'tailscale' },
  zerotier: { label: 'ZeroTier', icon: 'vpn' },
  netbird: { label: 'NetBird', icon: 'vpn' },
  nebula: { label: 'Nebula', icon: 'vpn' },
  husarnet: { label: 'Husarnet', icon: 'vpn' },
  netmaker: { label: 'Netmaker', icon: 'vpn' },
  innernet: { label: 'innernet', icon: 'vpn' },
  tinc: { label: 'tinc', icon: 'vpn' },
  wireguard: { label: 'WireGuard', icon: 'vpn' },
  openvpn: { label: 'OpenVPN', icon: 'vpn' },
  ipsec: { label: 'IPsec', icon: 'vpn' },
  softether: { label: 'SoftEther VPN', icon: 'vpn' },
  vpn: { label: 'VPN', icon: 'vpn' },
  yggdrasil: { label: 'Yggdrasil', icon: 'globe' },
  exitvpn: { label: 'Exit VPN', icon: 'shield' },
  warp: { label: 'Cloudflare WARP', icon: 'shield' },
  firezone: { label: 'Firezone', icon: 'shield' },
  twingate: { label: 'Twingate', icon: 'shield' },
  corpvpn: { label: 'Corporate VPN', icon: 'shield' },
  lan: { label: 'Ethernet / LAN', icon: 'network' },
  wifi: { label: 'Wi-Fi', icon: 'wifi' },
  loopback: { label: 'Loopback', icon: 'server' },
  container: { label: 'Containers & VMs', icon: 'package' },
});

/** The interfaces card's groups, by role (DESIGN §10.1), in display order. */
const ROLE_GROUPS = [
  { roles: ['mesh', 'unknown'], title: 'VPNs that reach this server' },
  { roles: ['local'], title: 'Local networks' },
  { roles: ['overlay'], title: 'Public overlay',
    warning: 'Anyone on this network can try to connect. Its addresses are not offered, and allowing it needs a confirmation.' },
  { roles: ['egress', 'access'], title: 'Outgoing-only VPNs', collapsed: true,
    text: 'Other devices cannot reach this server through these, so they are not offered as addresses or allowed networks.' },
  { roles: ['none'], title: 'Other', collapsed: true },
];

/** Providers of branded VPNs, for the interface rows. */
const PROVIDERS = /** @type {Record<string, string>} */ ({
  nordvpn: 'NordVPN', mullvad: 'Mullvad', proton: 'Proton', cloudflare: 'Cloudflare', twingate: 'Twingate',
  firezone: 'Firezone', cisco: 'Cisco', paloalto: 'Palo Alto Networks',
});

/** VPNInfo.allowed → badge. */
const ALLOWED = /** @type {Record<string, [string, 'success' | 'warning' | 'neutral']>} */ ({
  yes: ['Allowed', 'success'], partly: ['Partly allowed', 'warning'], no: ['Not allowed', 'neutral'],
});

/** Exposure IDs → alert titles (the rest: "Access policy bypass"). */
const EXPOSURE_TITLES = /** @type {Record<string, string>} */ ({
  'tailscale.bypass': 'Tailscale forwards to FileParcel directly',
  'proxy.local_unconfigured': 'An unconfigured proxy forwards to FileParcel',
  'tailscale.userspace': 'Tailscale runs without a TUN device',
  'tailscale.shields_up': 'Tailscale shields-up is on',
  cloudflared: 'A Cloudflare Tunnel forwards to FileParcel',
});

/**
 * The role of an interface (NetworkOverview.interfaces[].role); older servers send none: LAN/Wi-Fi are local,
 * loopback and containers none, VPNs unknown.
 * @param {any} i
 */
function roleOf(i) {
  if (i.role) return String(i.role);
  if (i.kind === 'lan' || i.kind === 'wifi') return 'local';
  if (i.kind === 'loopback' || i.kind === 'container') return 'none';
  return i.is_vpn ? 'unknown' : 'local';
}

/**
 * @param {HTMLElement} root
 * @param {import('../../core/router.js').PageContext} ctx
 */
export async function mount(root, ctx) {
  adminHeader(root, {
    title,
    subtitle: 'Addresses to reach FileParcel, network interfaces and who is allowed to connect.',
    actions: button({ label: 'Refresh', icon: 'refresh', variant: 'ghost', onClick: () => load() }),
  });
  const warnSlot = h('div', { class: 'stack-sm' });
  const urlsBody = h('div', { class: 'stack' }, skeleton(3));
  const policyBody = h('div', { class: 'stack' }, skeleton(4));
  const ifBody = h('div', { class: 'stack' }, skeleton(4));
  const tsBody = h('div', { class: 'stack-sm' }, skeleton(2));
  const mdnsBody = h('div', { class: 'stack-sm' }, skeleton(2));
  const remote = remoteAccessCards(ctx, { getNet: () => net, reload: () => refresh() });
  append(root, warnSlot,
    card({ title: 'Access addresses', body: urlsBody }),
    remote.funnel,
    remote.serve,
    h('div', { class: 'settings-grid' },
      h('div', { class: 'stack' }, card({ title: 'Who can connect', body: policyBody }), card({ title: 'Local name (mDNS)', body: mdnsBody, headerActions: h('a', { class: 'btn btn--ghost btn--sm', href: '/admin/settings/mdns' }, icon('sliders'), h('span', { text: 'Settings' })) })),
      h('div', { class: 'stack' }, card({ title: 'Interfaces', body: ifBody }), card({ title: 'Tailscale', body: tsBody }))));

  /** @type {any} */
  let net = null;
  let policyDirty = false;

  const load = async () => {
    const [n, m] = await Promise.allSettled([
      api.get('/admin/network', { signal: ctx.signal }),
      api.get('/admin/mdns', { signal: ctx.signal, handle: false }),
    ]);
    if (ctx.signal.aborted) return;
    if (n.status === 'fulfilled') {
      net = n.value || {};
      drawUrls();
      remote.draw(net);
      if (!policyDirty) drawPolicy();
      drawInterfaces();
      drawTailscale();
      drawWarnings();
    } else {
      if (n.reason instanceof ApiError && n.reason.aborted) return;
      replace(urlsBody, errorPanel(n.reason, load));
      remote.draw(null);
      replace(policyBody);
      replace(ifBody);
      replace(tsBody);
    }
    if (m.status === 'fulfilled') drawMDNS(m.value || {});
    else replace(mdnsBody, errorPanel(m.reason, load));
  };

  const drawWarnings = () => {
    const items = [];
    if (net.policy?.mode === 'any') {
      items.push(alertEl('warning', 'FileParcel accepts connections from anywhere', 'If this machine is reachable from the internet, anyone can reach the sign-in page. Prefer “Private networks” or an allowlist plus a VPN such as Tailscale.'));
    }
    const fun = net.ingress?.funnel;
    if (fun?.state === 'active' && fun.mode === 'app') {
      items.push(alertEl('warning', 'The whole app is on the internet',
        `Anyone can open the sign-in page at ${fun.url || 'the Funnel address'}. ${net.ingress.allow_admin ? 'Administration is allowed there too.' : 'Administration is not.'}`));
    }
    // Ways around the access policy (hand-made proxies, Tailscale without a TUN device, …), most severe first.
    const rank = /** @type {Record<string, number>} */ ({ fail: 0, warn: 1, info: 2 });
    const exposures = [...(Array.isArray(net.exposures) ? net.exposures : [])].sort((a, b) => (rank[a.severity] ?? 3) - (rank[b.severity] ?? 3));
    for (const e of exposures) {
      const kind = e.severity === 'fail' ? 'danger' : e.severity === 'warn' ? 'warning' : 'info';
      const title = EXPOSURE_TITLES[e.id] || 'Access policy bypass';
      items.push(alertEl(kind, title, h('span', { class: 'remote-exposure' }, h('span', { text: e.message }), e.hint ? h('span', { class: 'remote-exposure-hint', text: e.hint }) : null)));
    }
    replace(warnSlot, ...items);
  };

  // ------------------------------------------------------------------------------------------ URLs
  const drawUrls = () => {
    /** @type {any[]} */
    const urls = [...(net.urls || [])].sort((a, b) => Number(!!b.recommended) - Number(!!a.recommended) || Number(!!b.trusted) - Number(!!a.trusted));
    if (!urls.length) {
      replace(urlsBody, h('p', { class: 'muted', text: 'No addresses were detected. Check that the server has an active network interface.' }));
      return;
    }
    replace(urlsBody, 
      h('p', { class: 'muted text-sm', text: 'Open one of these on another device. .local names work on the same network; VPN names and addresses work wherever that VPN is connected.' }),
      h('ul', { class: 'url-list', attrs: { role: 'list' } }, urls.map((u) => h('li', { class: 'url-row' },
        h('span', { class: 'url-row-icon', attrs: { 'aria-hidden': 'true' } }, icon(urlIcon(u))),
        h('div', { class: 'url-row-main' },
          h('a', { class: 'url-row-link mono', href: u.url, attrs: { target: '_blank', rel: 'noopener noreferrer', 'data-native': true }, text: u.url }),
          h('span', { class: 'cluster' },
            h('span', { class: 'muted text-xs', text: [u.label, u.interface ? `via ${u.interface}` : ''].filter(Boolean).join(' · ') }),
            u.recommended ? badge({ text: 'Recommended', kind: 'primary', icon: 'star' }) : null,
            u.trusted ? badge({ text: 'Trusted certificate', kind: 'success', icon: 'shield-check' }) : null)),
        h('span', { class: 'cluster nowrap' },
          iconButton({ icon: 'copy', label: `Copy ${u.url}`, size: 'sm', onClick: () => copyText(u.url, 'Address') }),
          iconButton({ icon: 'qr', label: `QR code for ${u.url}`, size: 'sm', onClick: () => showQR(u) })))),
      ),
      net.client_ip ? h('p', { class: 'subtle text-xs' }, 'You are connected from ', h('span', { class: 'mono', text: net.client_ip }), '.') : null);
  };

  /** @param {any} u */
  const showQR = (u) => {
    dialog({
      title: u.label || 'Open on your phone',
      size: 'sm',
      body: h('div', { class: 'stack invite-link' },
        h('p', { class: 'muted text-sm', text: 'Scan with the phone’s camera. If the browser warns about the certificate, set up trust first (the /trust page).' }),
        String(u.url).length <= 512 ? h('div', { class: 'invite-qr' }, qrImage({ src: qrURL(u.url), alt: `QR code for ${u.url}`, size: 220 })) : null,
        copyField({ label: 'Address', value: u.url, what: 'Address' }),
        h('p', { class: 'text-sm' }, 'Certificate guide for this address: ', h('a', { href: new URL('/trust', u.url).href, attrs: { target: '_blank', rel: 'noopener noreferrer', 'data-native': true }, text: new URL('/trust', u.url).href }))),
      actions: [{ label: 'Done', variant: 'primary' }],
    }).open();
  };

  // ------------------------------------------------------------------------------------------ policy
  const drawPolicy = () => {
    const pol = net.policy || { mode: 'allowlist', allow: [], deny: [] };
    const clientIP = String(net.client_ip || '');
    let mode = pol.mode || 'allowlist';
    const modes = [
      { id: 'private', label: 'Private networks', text: 'Home and office networks, VPNs (incl. Tailscale 100.64/10), this machine and any extra networks you list below. Recommended.' },
      { id: 'allowlist', label: 'Allowlist', text: 'Only the networks and addresses you list below (plus this machine).' },
      { id: 'any', label: 'Everyone', text: 'Any address, including the internet. Only for servers behind your own firewall or proxy.' },
    ];
    const radios = h('div', { class: 'choice-grid choice-grid--stack', attrs: { role: 'radiogroup', 'aria-label': 'Access mode' } }, modes.map((m) => {
      const input = h('input', { class: 'sr-only', attrs: { type: 'radio', name: 'fp-access-mode', value: m.id }, checked: m.id === mode });
      input.addEventListener('change', () => {
        if (!input.checked) return;
        mode = m.id;
        policyDirty = true;
        syncMode();
        preview();
      });
      return h('label', { class: 'choice-card', dataset: { value: m.id } },
        input,
        h('span', { class: 'choice-card-head' }, icon(m.id === 'any' ? 'globe' : m.id === 'private' ? 'home' : 'filter'), h('span', { class: 'choice-card-label', text: m.label }), h('span', { class: 'choice-card-check', attrs: { 'aria-hidden': 'true' } }, icon('check-circle'))),
        h('span', { class: 'choice-card-text', text: m.text }));
    }));
    const allow = field({
      label: 'Allowed networks',
      name: 'allow',
      type: 'textarea',
      rows: 5,
      value: (pol.allow || []).join('\n'),
      help: 'One CIDR or address per line, e.g. 192.168.1.0/24, 100.64.0.0/10, fd7a:115c:a1e0::/48.',
      attrs: { spellcheck: 'false', autocapitalize: 'off' },
    });
    const deny = field({
      label: 'Always blocked',
      name: 'deny',
      type: 'textarea',
      rows: 3,
      value: (pol.deny || []).join('\n'),
      help: 'Blocked in every mode; wins over allowed networks.',
      attrs: { spellcheck: 'false', autocapitalize: 'off' },
    });
    const suggestions = h('div', { class: 'cluster' });
    // what the VPN suggestions want the admin to know (shared ranges, custom Headscale prefixes, …)
    const vpnNotes = h('div', { class: 'vpn-notes' });
    /** @type {{ranges: string[], btn: HTMLElement}[]} */
    let suggBtns = [];
    const status = h('div', { attrs: { 'aria-live': 'polite' } });
    const saveBtn = button({ label: 'Save access policy', icon: 'check', variant: 'primary', onClick: () => save() });
    const resetBtn = button({ label: 'Discard changes', variant: 'ghost', onClick: () => { policyDirty = false; drawPolicy(); } });

    const lines = (/** @type {string} */ v) => String(v).split(/[\n,]+/).map((x) => x.trim()).filter(Boolean);
    const allowLabel = allow.el.querySelector('.field-label');
    const allowHelp = allow.el.querySelector('.field-help');
    // The allow list applies in "allowlist" and, on top of the private ranges, in "private" mode (§10.3); only
    // "any" ignores it. Private mode does not offer networks the private ranges already cover.
    const coveredByPrivate = (/** @type {string[]} */ ranges) => ranges.every((s) => ipAllowed(s.split('/')[0], { mode: 'private' }) === true);
    const syncMode = () => {
      const priv = mode === 'private';
      allow.el.hidden = mode === 'any';
      vpnNotes.hidden = mode === 'any';
      if (allowLabel) allowLabel.textContent = priv ? 'Additional allowed networks' : 'Allowed networks';
      if (allowHelp) {
        allowHelp.textContent = priv
          ? 'Admitted in addition to the private ranges, e.g. your LAN’s global IPv6 prefix or a public office address. One CIDR or address per line.'
          : 'One CIDR or address per line, e.g. 192.168.1.0/24, 100.64.0.0/10, fd7a:115c:a1e0::/48.';
      }
      let shown = 0;
      for (const x of suggBtns) {
        x.btn.hidden = shown >= 8 || (priv && coveredByPrivate(x.ranges));
        if (!x.btn.hidden) shown += 1;
      }
      suggestions.hidden = mode === 'any' || !shown;
    };
    const preview = () => {
      const bad = [...lines(allow.input.value), ...lines(deny.input.value)].filter((c) => !parseCIDR(c));
      allow.setError(null);
      deny.setError(null);
      if (bad.length) {
        (lines(allow.input.value).some((c) => bad.includes(c)) ? allow : deny).setError(`Not a valid address or CIDR: ${bad.slice(0, 3).join(', ')}`);
      }
      const policy = { mode, allow: lines(allow.input.value), deny: lines(deny.input.value) };
      const ok = clientIP ? ipAllowed(clientIP, policy) : null;
      replace(status, 
        ok === false ? alertEl('danger', 'This would lock you out', `Your address ${clientIP} would not be allowed. Add it (or its network) to the allowed networks, or keep a terminal on the server ready to change it back (fileparcel network mode private).`)
          : ok === true && clientIP ? alertEl('success', 'You keep access', `Your address ${clientIP} stays allowed.`) : null,
        mode === 'any' ? alertEl('warning', 'Public exposure', 'Everyone who can reach this machine can open the sign-in page. Make sure strong passwords and two-factor authentication are required.') : null);
      saveBtn.disabled = bad.length > 0;
    };
    allow.input.addEventListener('input', () => { policyDirty = true; preview(); });
    deny.input.addEventListener('input', () => { policyDirty = true; preview(); });

    // quick-add suggestions: the local (LAN/Wi-Fi) subnets, the VPNs devices come in through (NetworkOverview.vpns:
    // one button per VPN adds all its ranges) and the client address
    const current = new Set(lines(allow.input.value));
    /** @type {{ranges: string[], label: string, vpn?: any}[]} */
    const sugg = [];
    const suggested = new Set();
    for (const i of net.interfaces || []) {
      if (!i.up || roleOf(i) !== 'local' || i.kind === 'loopback') continue;
      for (const netStr of localNetworks(i)) {
        if (!current.has(netStr) && !suggested.has(netStr)) {
          suggested.add(netStr);
          sugg.push({ ranges: [netStr], label: netStr });
        }
      }
    }
    /** @type {HTMLElement[]} */
    const notes = [];
    for (const v of Array.isArray(net.vpns) ? net.vpns : []) {
      const label = String(v.label || v.id || '');
      const ranges = (v.ranges || []).map(String).filter((/** @type {string} */ r) => !current.has(r));
      if (v.can_allow && v.allowed !== 'yes' && ranges.length) {
        sugg.push({ ranges, label, vpn: v });
        if (v.warning) notes.push(h('p', { class: 'subtle text-xs' }, `${label}: `, ...codeText(String(v.warning))));
      } else if (!v.can_allow && v.note && (v.role === 'mesh' || v.role === 'unknown')) {
        notes.push(h('p', { class: 'subtle text-xs' }, `${label}: `, ...codeText(String(v.note))));
      }
    }
    if (clientIP && parseCIDR(clientIP) && !current.has(clientIP) && !suggested.has(clientIP)) sugg.push({ ranges: [clientIP], label: `${clientIP} (you)` });
    // at most 8 are shown at a time (syncMode hides the ones the current mode does not need)
    suggBtns = sugg.map((x) => ({
      ranges: x.ranges,
      btn: button({
        label: x.label,
        title: x.vpn ? `Allow ${x.ranges.join(', ')}` : undefined,
        size: 'sm',
        variant: 'ghost',
        icon: x.vpn ? 'vpn' : 'plus',
        onClick: async () => {
          if (x.vpn?.needs_force) {
            const ok = await confirm({
              title: `Allow ${x.label}?`,
              message: `${x.label} is a public overlay network: once it is allowed, anyone on it can open the sign-in page. Prefer allowing single addresses of your own devices.`,
              confirmLabel: 'Allow',
              danger: true,
            });
            if (!ok) return;
          }
          const have = lines(allow.input.value);
          allow.input.value = [...have, ...x.ranges.filter((r) => !have.includes(r))].join('\n');
          policyDirty = true;
          preview();
        },
      }),
    }));
    replace(suggestions, sugg.length ? h('span', { class: 'muted text-xs', text: 'Add:' }) : null, ...suggBtns.map((x) => x.btn));
    replace(vpnNotes, ...notes);

    const save = async (force = false) => {
      const body = { mode, allow: lines(allow.input.value), deny: lines(deny.input.value), force };
      if (!force && clientIP && ipAllowed(clientIP, body) === false) {
        const ok = await confirm({
          title: 'Lock yourself out?',
          message: `Your current address ${clientIP} would no longer be allowed. You will be disconnected and need a terminal on the server (or another allowed device) to undo this.`,
          confirmLabel: 'Save anyway',
          danger: true,
        });
        if (!ok) return;
        body.force = true;
      }
      try {
        /** @type {any} */
        const res = await api.put('/admin/network/policy', body);
        policyDirty = false;
        const warnings = Array.isArray(res?.warnings) ? res.warnings.filter(Boolean) : [];
        toast.success('Access policy saved');
        if (res?.policy) net.policy = res.policy;
        else net.policy = { mode: body.mode, allow: body.allow, deny: body.deny };
        drawPolicy();
        drawWarnings();
        if (warnings.length) policyBody.prepend(alertEl('warning', 'Saved with warnings', h('ul', { class: 'hint-list' }, warnings.map((/** @type {string} */ w) => h('li', { text: w })))));
      } catch (err) {
        if (err instanceof ApiError && err.status === 409 && !body.force) {
          const ok = await confirm({
            title: 'The server says this would lock you out',
            message: `${err.message}. Save anyway?`,
            confirmLabel: 'Save anyway',
            danger: true,
          });
          if (ok) await save(true);
          return;
        }
        if (err instanceof ApiError && err.field === 'allow') allow.setError(err.message);
        else if (err instanceof ApiError && err.field === 'deny') deny.setError(err.message);
        else toast.error(err);
      }
    };

    replace(policyBody, 
      radios,
      allow.el,
      suggestions,
      vpnNotes,
      deny.el,
      status,
      h('p', { class: 'subtle text-xs', text: `This machine (127.0.0.1, ::1) is always allowed. Private ranges: ${PRIVATE_CIDRS.join(', ')}.` }),
      h('div', { class: 'btn-row' }, resetBtn, saveBtn));
    syncMode();
    preview();
  };

  // ------------------------------------------------------------------------------------------ interfaces
  const drawInterfaces = () => {
    /** @type {any[]} */
    const list = net.interfaces || [];
    if (!list.length) {
      replace(ifBody, h('p', { class: 'muted', text: 'No interfaces reported.' }));
      return;
    }
    /** @type {Map<string, any>} interface name → its VPN (NetworkOverview.vpns) */
    const vpnOf = new Map();
    for (const v of Array.isArray(net.vpns) ? net.vpns : []) for (const n of v.interfaces || []) vpnOf.set(String(n), v);
    // A VPN interface without a usable address (the always-present macOS utun0–utun3 with only fe80::) reaches
    // nothing: it is listed under "Other", like the server's VPN list leaves it out.
    const groupRole = (/** @type {any} */ i) => (['mesh', 'unknown'].includes(roleOf(i)) && !hasUsableAddr(i) ? 'none' : roleOf(i));
    const sections = ROLE_GROUPS.map((g) => {
      const items = list.filter((i) => g.roles.includes(groupRole(i)));
      if (!items.length) return null;
      const content = h('ul', { class: 'iface-list', attrs: { role: 'list' } }, items.map((i) => ifaceRow(i, vpnOf.get(i.name), setRole)));
      const intro = [
        g.text ? h('p', { class: 'muted text-sm', text: g.text }) : null,
        g.warning ? alertEl('warning', null, g.warning) : null,
      ];
      return g.collapsed
        ? h('details', { class: 'auth-details iface-group' }, h('summary', { text: `${g.title} (${items.length})` }), h('div', { class: 'stack-sm' }, ...intro, content))
        : h('div', { class: 'stack-sm iface-group' }, h('h3', { class: 'iface-group-title', text: g.title }), ...intro, content);
    });
    const anyVPN = list.some((i) => hasUsableAddr(i) && (i.is_vpn || ['mesh', 'unknown', 'overlay', 'egress', 'access'].includes(roleOf(i))));
    replace(ifBody, ...sections,
      !anyVPN ? h('p', { class: 'muted text-sm', text: 'No VPN interface found. Tailscale, Headscale, WireGuard, ZeroTier, NetBird, Nebula, Netmaker, innernet, Husarnet, tinc, OpenVPN and IPsec are detected automatically; exit VPNs (NordVPN, Mullvad, Proton VPN, Cloudflare WARP) and corporate clients are recognised as outgoing only.' }) : null);
  };

  /**
   * Sets (or with role null removes) an interface's entry in network.iface_roles: read-modify-write of the setting
   * (other interfaces' entries, also of interfaces that are down now, are kept). Step-up is asked for by core/api.js.
   * @param {any} i the interface
   * @param {string | null} role
   */
  const setRole = async (i, role) => {
    const name = String(i.name);
    try {
      const views = itemsOf(await api.get('/admin/settings', { query: { section: 'network' } }));
      const cur = views.find((/** @type {any} */ v) => v.key === 'network.iface_roles');
      const entries = (Array.isArray(cur?.value) ? cur.value : []).map(String)
        .filter((/** @type {string} */ e) => e.split('=')[0].trim() !== name);
      if (role) entries.push(`${name}=${role}`);
      await api.patch('/admin/settings', { 'network.iface_roles': entries });
      toast.success(role ? `${name} is now treated as ${role === 'egress' ? 'outgoing only' : 'reaching this server'}` : `${name} is classified automatically again`);
      await load();
    } catch (err) {
      if (err instanceof ApiError && (err.aborted || err.code === 'elevation_required')) return;
      toast.error(err);
    }
  };

  // ------------------------------------------------------------------------------------------ tailscale
  const drawTailscale = () => {
    const ts = net.tailscale;
    // installed: a tailscaled socket or tailscale CLI exists; without one the server still reports
    // {running: false, error: "…not installed…"}, which is not a problem to warn about
    if (!ts || !ts.installed) {
      replace(tsBody, h('p', { class: 'muted text-sm', text: 'Tailscale is not installed or not running on this machine.' }));
      return;
    }
    const opHint = /operator|access denied|permission/i.test(String(ts.error || ''));
    // a MagicDNS name outside .ts.net (Headscale) is covered by the local certificate only if it existed when the CA
    // was created: ask the certificate status (needs certs.manage; nothing is shown without it)
    const uncovered = h('div');
    const name = String(ts.dns_name || '').toLowerCase();
    if (name && !name.endsWith('.ts.net') && can('certs.manage')) {
      api.get('/admin/certs', { signal: ctx.signal, handle: false }).then((/** @type {any} */ st) => {
        if (!(st?.uncovered_names || []).map(String).includes(name)) return;
        replace(uncovered, alertEl('warning', 'The local certificate does not cover the MagicDNS name',
          h('span', null, 'The local CA was created before ', h('span', { class: 'mono break', text: name }),
            ' existed, so browsers warn there. Regenerate the CA (every device must then trust the new one): ',
            h('code', { text: 'fileparcel ca regenerate' }), ' — or reach the server by its IP address.')));
      }).catch(() => {});
    }
    const kindText = ts.kind === 'headscale' ? (ts.kind_guessed ? 'Headscale (self-hosted control server?)' : 'Headscale') : 'Tailscale';
    replace(tsBody, 
      h('div', { class: 'cluster' },
        stateBadge(ts.running ? 'running' : 'off', ts.running ? 'Connected' : 'Not running'),
        ts.kind ? badge({ text: kindText, kind: 'info' }) : null,
        ts.cert_capable ? badge({ text: 'HTTPS certificates available', kind: 'success' }) : null),
      kv([
        ['MagicDNS name', ts.dns_name ? h('span', { class: 'mono break', text: ts.dns_name }) : null],
        ['Tailnet', ts.tailnet || null],
        ['State', ts.backend_state || null],
        ['Addresses', (ts.ips || []).length ? chips(ts.ips) : null],
        ['Control server', ts.control_url ? h('span', { class: 'mono break', text: ts.control_url }) : null],
      ]),
      ts.error ? alertEl('warning', 'Tailscale reported a problem', ts.error) : null,
      uncovered,
      opHint || (ts.running && !ts.cert_capable && ts.kind !== 'headscale')
        ? alertEl('info', 'Let FileParcel use Tailscale certificates',
          h('span', null, 'Enable HTTPS for your tailnet in the Tailscale admin console and allow this user to request certificates: ',
            h('code', { text: 'sudo tailscale set --operator=$USER' })))
        : null,
      ts.kind === 'headscale' ? h('p', { class: 'muted text-sm', text: 'Headscale cannot issue ts.net certificates; the local CA covers the MagicDNS name instead if the machine was on Headscale when the CA was created (otherwise Admin → Certificates lists it as not covered: regenerate the CA).' }) : null,
      pathAllowed('/admin/certificates')
        ? h('div', { class: 'btn-row btn-row--start' }, h('a', { class: 'btn btn--secondary btn--sm', href: '/admin/certificates#tailscale' }, icon('certificate'), h('span', { text: 'Tailscale certificate' })))
        : null);
  };

  // ------------------------------------------------------------------------------------------ mDNS
  /** @param {any} m */
  const drawMDNS = (m) => {
    replace(mdnsBody, 
      h('div', { class: 'cluster' }, stateBadge(m.state), m.name ? h('span', { class: 'mono', text: m.name }) : null),
      kv([
        ['Mode', m.mode || null],
        ['Backend', m.backend || null],
        ['Interfaces', (m.interfaces || []).length ? chips(m.interfaces) : null],
      ]),
      m.state === 'collision' ? alertEl('warning', 'Name conflict', 'Another device on the network already uses this name, so a numbered name was chosen. Pick a unique name in the mDNS settings.') : null,
      m.configured && m.name && m.configured !== m.name
        ? alertEl('warning', 'Published under a different name',
          `The configured name ${m.configured} is taken on this network, so ${m.name} is announced instead. Links and the certificate follow the published name.`)
        : null,
      m.error ? alertEl('danger', 'mDNS error', m.error) : null,
      m.state === 'off' ? h('p', { class: 'muted text-sm', text: 'mDNS is turned off, so no .local name is announced. Devices can still use IP addresses or VPN names.' }) : null,
      h('p', { class: 'subtle text-xs', text: '.local names only work on the same local network; they do not cross VPNs like Tailscale or WireGuard.' }),
      h('div', { class: 'btn-row btn-row--start' }, button({
        label: 'Republish',
        icon: 'refresh',
        size: 'sm',
        disabled: m.state === 'off',
        onClick: async () => {
          try {
            await api.post('/admin/mdns/republish', {});
            toast.success('Announcing the name again');
            setTimeout(() => load(), 1500);
          } catch (err) {
            toast.error(err);
          }
        },
      })));
  };

  const refresh = debounce(() => load(), 600);
  const off = onEvents(['network.changed', 'mdns.changed', 'ingress.changed'], refresh);
  await load();
  // /admin/network#funnel (doctor links): show that card once it has content
  if (location.hash) document.getElementById(location.hash.slice(1))?.scrollIntoView({ block: 'start' });
  return () => {
    off();
    refresh.cancel();
  };
}

/** Role menu choices (DESIGN §10.1, network.iface_roles). */
const ROLE_CHOICES = [
  { role: 'mesh', label: 'Devices can reach this server through it', icon: 'vpn' },
  { role: 'egress', label: 'Outgoing only', icon: 'shield' },
  { role: null, label: 'Automatic', icon: 'refresh' },
];

/**
 * One interface: name, label, provider and detail, the role override, its VPN's policy state and note, and the role
 * menu.
 * @param {any} i
 * @param {any} vpn its entry of NetworkOverview.vpns (undefined when it is not a VPN)
 * @param {(i: any, role: string | null) => void} onRole
 */
function ifaceRow(i, vpn, onRole) {
  const info = KIND_INFO[i.kind] || { label: i.kind || 'Interface', icon: 'network' };
  const label = String(i.label || info.label);
  const role = roleOf(i);
  const override = i.role_source === 'override';
  const provider = PROVIDERS[i.provider] && !label.includes(PROVIDERS[i.provider]) ? `by ${PROVIDERS[i.provider]}` : '';
  const incoming = role === 'mesh' || role === 'unknown';
  const allowed = incoming && vpn ? ALLOWED[vpn.allowed] : null;
  const current = override ? ROLE_CHOICES.find((c) => c.role === role) : ROLE_CHOICES[2];
  /** @type {HTMLButtonElement} */
  const menuBtn = /** @type {HTMLButtonElement} */ (iconButton({
    icon: 'more-vertical',
    label: `How FileParcel treats ${i.name}`,
    size: 'sm',
    attrs: { 'aria-haspopup': 'menu', 'aria-expanded': 'false' },
    onClick: () => menu({
      anchor: menuBtn,
      title: `How FileParcel treats ${i.name}`,
      align: 'end',
      items: [
        override && !current ? { header: `Set to “${role}” (fileparcel network vpn role)` } : null,
        ...ROLE_CHOICES.map((c) => ({
          label: c.label,
          icon: c === current ? 'check' : c.icon,
          disabled: c === current,
          onClick: () => onRole(i, c.role),
        })),
      ].filter(Boolean),
    }),
  }));
  return h('li', { class: 'iface-row', dataset: { up: i.up ? '' : null, menu: i.kind === 'loopback' ? null : '' } },
    h('span', { class: 'iface-icon', attrs: { 'aria-hidden': 'true' } }, icon(info.icon)),
    h('div', { class: 'iface-main' },
      h('span', { class: 'iface-title' },
        h('strong', { class: 'mono', text: i.name }),
        badge({ text: label, kind: i.is_vpn ? 'primary' : 'neutral' }),
        override ? badge({ text: 'Override', kind: 'info', icon: 'edit', title: 'Set by an administrator (network.iface_roles)' }) : null,
        allowed ? badge({ text: allowed[0], kind: allowed[1], title: (vpn.ranges || []).join(', ') || undefined }) : null,
        i.up ? null : badge({ text: 'down', kind: 'neutral' })),
      provider || i.detail ? h('span', { class: 'subtle text-xs', text: [provider, i.detail].filter(Boolean).join(' · ') }) : null,
      chips((i.addrs || []).map(String), { empty: 'no addresses', max: 6 }),
      incoming && vpn?.note ? h('span', { class: 'subtle text-xs' }, ...codeText(String(vpn.note))) : null,
      i.mtu ? h('span', { class: 'subtle text-xs', text: `MTU ${i.mtu}` }) : null),
    i.kind === 'loopback' ? null : menuBtn);
}

/**
 * Text with `code` spans (the server's notes quote commands in backticks).
 * @param {string} text
 * @returns {(string | HTMLElement)[]}
 */
function codeText(text) {
  return text.split('`').map((part, k) => (k % 2 ? h('code', { text: part }) : part)).filter((x) => x !== '');
}

/** @param {any} u */
function urlIcon(u) {
  return { mdns: 'radio', hostname: 'home', magicdns: 'tailscale', tailscale_serve: 'tailscale', funnel: 'globe', public: 'globe', extra: 'globe', ip: 'network' }[u.kind] || 'link';
}

/** Link-local ranges: on-link only, never a network to allow or an address to offer. */
const LINK_LOCAL = ['169.254.0.0/16', 'fe80::/10'];
/** IPv4 ranges that are not public (RFC 1918 and the shared/CGNAT space, also the tailnet range). */
const PRIVATE_V4 = ['10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16', '100.64.0.0/10'];

/** @param {string} ip @param {string[]} cidrs */
const inRanges = (ip, cidrs) => ipAllowed(ip, { mode: 'allowlist', allow: cidrs }) === true;

/**
 * Whether an interface has an address other devices could use (not link-local, not loopback) — like the server's
 * VPN list, which leaves the others out.
 * @param {any} i
 */
function hasUsableAddr(i) {
  return (i.addrs || []).some((/** @type {any} */ a) => {
    const ip = String(a).split('/')[0];
    return !!parseCIDR(ip) && !inRanges(ip, [...LINK_LOCAL, '127.0.0.0/8', '::1/128']);
  });
}

/**
 * The networks of a local interface the policy editor suggests, by the rule of the installer's allowlist
 * (netinfo.DefaultAllowlist): the subnet of each address, without link-local ones; an interface that has a public IPv4
 * address sits on its provider's network (a cloud VM: other tenants), so its public IPv4 subnets and global IPv6
 * prefixes are left out. Host addresses stay host addresses.
 * @param {any} i
 * @returns {string[]}
 */
function localNetworks(i) {
  const addrs = (i.addrs || []).map(String).filter((/** @type {string} */ a) => parseCIDR(a));
  const v4 = (/** @type {string} */ ip) => parseCIDR(ip)?.v === 4;
  const publicV4 = (/** @type {string} */ ip) => v4(ip) && !inRanges(ip, [...PRIVATE_V4, ...LINK_LOCAL, '127.0.0.0/8']);
  const onPublic = addrs.some((/** @type {string} */ a) => publicV4(a.split('/')[0]));
  const out = [];
  for (const a of addrs) {
    const ip = a.split('/')[0];
    if (inRanges(ip, LINK_LOCAL)) continue;
    if (onPublic && (publicV4(ip) || (!v4(ip) && !inRanges(ip, ['fc00::/7'])))) continue;
    const n = networkOf(a);
    if (n && !out.includes(n)) out.push(n);
  }
  return out;
}

/**
 * Network address of an interface prefix ("192.168.1.10/24" → "192.168.1.0/24"). An IPv6 address without a prefix
 * length is shown as its /64; a /128 stays a host address.
 * @param {string} prefix
 */
function networkOf(prefix) {
  const [addr, len] = prefix.split('/');
  const c = parseCIDR(prefix.includes('/') ? prefix : `${prefix}/${addr.includes(':') ? 64 : 32}`);
  if (!c) return '';
  if (c.v === 4) {
    const n = c.net;
    return `${[24n, 16n, 8n, 0n].map((s) => String((n >> s) & 255n)).join('.')}/${c.bits}`;
  }
  const bits = len ? c.bits : 64;
  const shift = BigInt(128 - bits);
  const n = (c.net >> shift) << shift;
  const groups = [];
  for (let k = 7; k >= 0; k -= 1) groups.push(((n >> BigInt(k * 16)) & 0xffffn).toString(16));
  // compress the longest run of zero groups
  const s = groups.join(':').replace(/(^|:)0(:0)+(:|$)/, '::').replace(/:{3,}/, '::');
  return `${s}/${bits}`;
}

