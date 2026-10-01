// @ts-check
/**
 * Admin → Network & VPN: the remote-access cards (DESIGN §10.6, §13.8), mounted by network.js after "Access
 * addresses":
 *   Internet access (Tailscale Funnel)          mode off / share links only / full app, port, sign-in rules
 *   Tailnet address without port (Tailscale Serve)
 * Each card shows its state, the address (copy + QR), the prerequisite checklist with fix links, and saves through
 *   PUT  /admin/network/funnel {mode, port, allow_admin, require_2fa, confirm} (E) → IngressStatus
 *   PUT  /admin/network/serve {enabled, port} (E)                                  → IngressStatus
 *   POST /admin/network/tailscale/reapply (E)                                     → IngressStatus  ("Re-apply")
 *   GET  /admin/network/tailscale?refresh=1                                        → IngressStatus  ("Test again")
 * The status arrives with GET /admin/network (NetworkOverview.ingress); network.js reloads on ingress.changed and
 * calls draw(net). Widening what the internet reaches asks first ("Publish"); weakening sign-in over Funnel needs
 * the word "public" typed (and a built-in owner or administrator: delegates see those switches disabled). Step-up
 * is asked for by core/api.js when the server wants it.
 * @module pages/admin/network-remote
 */
import { h, icon, replace } from '../../core/dom.js';
import { api, ApiError, errorMessage } from '../../core/api.js';
import { relTime } from '../../core/format.js';
import { button, iconButton } from '../../components/button.js';
import { badge } from '../../components/badge.js';
import { toast } from '../../components/toast.js';
import { dialog, confirm } from '../../components/dialog.js';
import { field, select, toggle } from '../../components/field.js';
import { copyField } from '../../components/copy-field.js';
import { qrImage, qrURL } from '../../components/qr-image.js';
import { settingsForm } from '../../components/settings-form.js';
import { alertEl, confirmTyped, me } from './common.js';

/** The ports Tailscale Funnel supports. */
const FUNNEL_PORTS = [443, 8443, 10000];

/** Card state: badge text and kind per IngressEntry.state. */
const STATES = /** @type {Record<string, [string, 'neutral' | 'success' | 'warning' | 'danger']>} */ ({
  off: ['Off', 'neutral'],
  active: ['Active', 'success'],
  stopped: ['Stopped', 'neutral'],
  drift: ['Needs attention', 'warning'],
  conflict: ['Needs attention', 'warning'],
  error: ['Needs attention', 'danger'],
  unavailable: ['Unavailable', 'warning'],
  paused: ['Paused', 'warning'],
});

/** Check status → icon. */
const CHECK_ICONS = /** @type {Record<string, string>} */ ({ ok: 'check-circle', warn: 'alert-triangle', fail: 'x-circle', skip: 'minus' });

/** Funnel modes (choice cards). */
const MODES = [
  { id: 'off', label: 'Off', icon: 'x-circle', text: 'Nothing of FileParcel is reachable from the internet.' },
  { id: 'shares', label: 'Share links only', icon: 'link', recommended: true,
    text: 'Only links you share and file requests work from the internet; everything else answers “not found”.' },
  { id: 'app', label: 'Full app, sign-in required', icon: 'globe',
    text: 'The whole app, with its sign-in page.',
    warning: 'Anyone can reach the sign-in page. Only accounts with two-factor authentication can sign in over this address.' },
];

/**
 * @typedef {Object} RemoteCards
 * @property {HTMLElement} funnel the Funnel card (id="funnel")
 * @property {HTMLElement} serve the Serve card (id="serve")
 * @property {(net: any) => void} draw show the Funnel/Serve part of a NetworkOverview
 */

/**
 * Build the two cards. `getNet()` returns the last NetworkOverview; `reload()` fetches the whole page again (after a
 * change the access addresses and warnings change too).
 * @param {import('../../core/router.js').PageContext} ctx
 * @param {{getNet: () => any, reload: () => void}} o
 * @returns {RemoteCards}
 */
export function remoteAccessCards(ctx, o) {
  /** @type {any} the last IngressStatus */
  let st = null;
  /** @type {Env} */
  const env = {
    signal: ctx.signal,
    getSt: () => st,
    dnsName: () => {
      const n = o.getNet();
      return String(st?.funnel?.url || st?.serve?.url || '').replace(/^https:\/\/([^/:]+).*$/, '$1') ||
        String(n?.tailscale?.dns_name || '').replace(/\.$/, '').toLowerCase();
    },
    // A write or "Test again" answered the status: the card that asked resets its controls to it, the other one
    // keeps unsaved edits; the page reloads (access addresses and warnings change with it).
    done: (next, from) => {
      if (next && typeof next === 'object') st = next;
      funnel.draw(from === 'funnel');
      serve.draw(from === 'serve');
      o.reload();
    },
  };
  const funnel = funnelCard(env);
  const serve = serveCard(env);

  return {
    funnel: funnel.el,
    serve: serve.el,
    draw(net) {
      st = net && net.ingress ? net.ingress : null;
      funnel.draw(false);
      serve.draw(false);
    },
  };
}

// ---------------------------------------------------------------------------------------------------------------
// shared pieces
// ---------------------------------------------------------------------------------------------------------------

/**
 * What the cards share.
 * @typedef {Object} Env
 * @property {AbortSignal} signal the page's
 * @property {() => any} getSt the last IngressStatus (null before the first load)
 * @property {() => string} dnsName the device's MagicDNS name ('' when unknown)
 * @property {(st: any, from: 'funnel' | 'serve') => void} done a card received a new status
 */

/** Whether the signed-in account is a built-in owner or administrator (who may weaken sign-in over Funnel). */
function builtinAdmin() {
  const role = String(/** @type {any} */ (me())?.role || '');
  return role === 'owner' || role === 'admin';
}

/**
 * The card frame: a section with an icon title, a state badge slot and a body.
 * @param {{id: string, title: string, icon: string}} o
 */
function frame(o) {
  const badgeSlot = h('span', { class: 'remote-badge' });
  const body = h('div', { class: 'card-body stack' });
  const el = h('section', { class: 'card remote-card', id: o.id, attrs: { 'aria-labelledby': `${o.id}-title` } },
    h('div', { class: 'card-head' },
      h('h2', { class: 'card-title remote-title', id: `${o.id}-title` }, icon(o.icon), h('span', { text: o.title })),
      badgeSlot),
    body);
  return { el, body, badgeSlot };
}

/**
 * The state badge of an entry.
 * @param {any} e IngressEntry
 */
function stateBadgeFor(e) {
  const [text, kind] = STATES[String(e?.state || 'off')] || [String(e?.state || 'unknown'), 'neutral'];
  return badge({ text, kind, icon: e?.state === 'active' ? 'check-circle' : undefined });
}

/**
 * The address of an active entry: copy field + QR button.
 * @param {string} url
 * @param {string} label
 */
function addressRow(url, label) {
  return h('div', { class: 'remote-address' },
    h('div', { class: 'remote-url' }, copyField({ value: url, label, what: 'Address' })),
    url.length <= 512 ? iconButton({ icon: 'qr', label: `QR code for ${url}`, onClick: () => showQR(url, label) }) : null);
}

/**
 * @param {string} url
 * @param {string} label
 */
function showQR(url, label) {
  dialog({
    title: label,
    size: 'sm',
    body: h('div', { class: 'stack invite-link' },
      h('div', { class: 'invite-qr' }, qrImage({ src: qrURL(url), alt: `QR code for ${url}`, size: 220 })),
      copyField({ value: url, label: 'Address', what: 'Address' })),
    actions: [{ label: 'Done', variant: 'primary' }],
  }).open();
}

/**
 * The prerequisite checklist of an entry: the problems (failing and warning checks) in view, the checks that pass
 * or were skipped folded away. Rows carry data-check=<id> (a 412 answer names the failing one) and the fix link
 * (only https, never fetched by the page).
 * @param {any[]} checks
 * @param {string} [highlight] check id to mark
 */
function checkList(checks, highlight) {
  if (!Array.isArray(checks) || !checks.length) return null;
  const problems = checks.filter((c) => c.status === 'fail' || c.status === 'warn');
  const rest = checks.filter((c) => c.status !== 'fail' && c.status !== 'warn');
  const passed = rest.filter((c) => c.status === 'ok').length;
  return h('div', { class: 'stack-sm' },
    problems.length ? checkRows(problems, highlight, 'Problems') : null,
    rest.length
      ? h('details', { class: 'auth-details remote-checks-ok' },
        h('summary', null, icon(problems.length ? 'check' : 'check-circle', { size: 16 }),
          h('span', { text: problems.length ? `${passed} of ${checks.length} checks passed` : `All ${passed} checks passed` })),
        h('div', null, checkRows(rest, highlight, 'Passed checks')))
      : null);
}

/**
 * @param {any[]} checks
 * @param {string | undefined} highlight
 * @param {string} label
 */
function checkRows(checks, highlight, label) {
  return h('ul', { class: 'check-list remote-checks', attrs: { role: 'list', 'aria-label': label } }, checks.map((c) => {
    const status = ['ok', 'warn', 'fail', 'skip'].includes(c.status) ? c.status : 'skip';
    const fix = typeof c.fix_url === 'string' && c.fix_url.startsWith('https://') && c.fix_url.length <= 512 ? c.fix_url : '';
    return h('li', { class: 'remote-check', dataset: { status, check: c.id, highlight: c.id === highlight ? '' : null } },
      h('span', { class: 'remote-check-icon', attrs: { 'aria-hidden': 'true' } }, icon(CHECK_ICONS[status])),
      h('span', { class: 'remote-check-text' },
        h('span', { class: 'remote-check-label' }, h('span', { text: c.label || c.id }), h('span', { class: 'sr-only', text: ` (${status})` })),
        c.message ? h('span', { class: 'remote-check-msg', text: c.message }) : null,
        c.hint && status !== 'ok' ? h('span', { class: 'remote-check-hint', text: c.hint }) : null),
      fix && status !== 'ok'
        ? h('a', { class: 'btn btn--secondary btn--sm', href: fix, attrs: { target: '_blank', rel: 'noopener noreferrer', 'data-native': true } },
          icon('external'), h('span', { text: 'How to fix' }))
        : null);
  }));
}

/**
 * An error of a write route, in the card: 412 names a check (its row is highlighted), others are shown as they are.
 * Nothing for an aborted request or a step-up the user cancelled (core/api.js asked; the change was not sent).
 * @param {unknown} err
 */
function writeError(err) {
  if (err instanceof ApiError && (err.aborted || err.code === 'elevation_required')) return null;
  if (err instanceof ApiError && err.status === 412) return alertEl('danger', 'A requirement is not met', err.message);
  if (err instanceof ApiError && err.status === 409) return alertEl('danger', 'The port is taken', err.message);
  if (err instanceof ApiError && err.status === 403) return alertEl('danger', 'Not allowed', err.message);
  if (err instanceof ApiError && err.status === 503) return alertEl('danger', 'Tailscale did not answer', err.message);
  return alertEl('danger', 'The change was not made', errorMessage(err));
}

/**
 * The toast after a write: an entry left in "error" (e.g. FileParcel stopped serving but tailscaled kept its entry) is a
 * warning with the entry's message; "stopped" means stored while the server does not run.
 * @param {any} e the IngressEntry the write answered
 * @param {string} done the success text
 */
function announce(e, done) {
  if (e?.state === 'error') toast.warning(e.message || 'Tailscale reported an error.');
  else if (e?.state === 'stopped') toast.success('Saved. FileParcel publishes it on Tailscale when the server starts.');
  else toast.success(done);
}

/**
 * "Test again" and "Re-apply" buttons of a card.
 * @param {Env} env
 * @param {'funnel' | 'serve'} kind
 * @param {HTMLElement} errSlot
 */
function statusButtons(env, kind, errSlot) {
  const test = button({
    label: 'Test again',
    icon: 'refresh',
    variant: 'ghost',
    // button() keeps the button busy while the returned promise runs
    onClick: async () => {
      try {
        env.done(await api.get('/admin/network/tailscale', { query: { refresh: 1 }, signal: env.signal }), kind);
      } catch (err) {
        if (!(err instanceof ApiError && err.aborted)) toast.error(err);
      }
    },
  });
  const reapply = button({
    label: 'Re-apply',
    icon: 'rotate',
    variant: 'secondary',
    onClick: async () => {
      replace(errSlot);
      try {
        env.done(await api.post('/admin/network/tailscale/reapply', {}), kind);
        toast.success('Written to Tailscale again');
      } catch (err) {
        replace(errSlot, writeError(err));
      }
    },
  });
  const sync = () => {
    reapply.hidden = !['drift', 'error', 'conflict'].includes(String(env.getSt()?.[kind]?.state || ''));
  };
  return { test, reapply, sync };
}

// ---------------------------------------------------------------------------------------------------------------
// Funnel
// ---------------------------------------------------------------------------------------------------------------

/** @param {Env} env */
function funnelCard(env) {
  const getSt = env.getSt;
  const f = frame({ id: 'funnel', title: 'Internet access (Tailscale Funnel)', icon: 'globe' });
  const statusSlot = h('div', { class: 'stack-sm' });
  const errSlot = h('div', { attrs: { 'aria-live': 'polite' } });
  const checksSlot = h('div', { class: 'stack-sm' });
  const footSlot = h('div', { class: 'remote-notes' });
  let dirty = false;
  let highlight = '';
  /** @type {'off' | 'shares' | 'app'} */
  let mode = 'off';

  // mode radios
  const radios = MODES.map((m) => {
    const input = h('input', { class: 'sr-only', attrs: { type: 'radio', name: 'fp-funnel-mode', value: m.id } });
    input.addEventListener('change', () => {
      if (!input.checked) return;
      mode = /** @type {any} */ (m.id);
      dirty = true;
      syncControls();
    });
    const label = h('label', { class: 'choice-card', dataset: { value: m.id } },
      input,
      h('span', { class: 'choice-card-head' },
        icon(m.icon),
        h('span', { class: 'choice-card-label', text: m.label }),
        m.recommended ? badge({ text: 'Recommended', kind: 'primary', icon: 'star' }) : null,
        h('span', { class: 'choice-card-check', attrs: { 'aria-hidden': 'true' } }, icon('check-circle'))),
      h('span', { class: 'choice-card-text', text: m.text }),
      m.warning ? h('span', { class: 'choice-card-text remote-warning' }, icon('alert-triangle', { size: 16 }), h('span', { text: m.warning })) : null);
    return { m, input, label };
  });
  const modeGroup = h('div', { class: 'choice-grid choice-grid--stack', attrs: { role: 'radiogroup', 'aria-label': 'Tailscale Funnel' } },
    radios.map((r) => r.label));

  // Advanced
  const port = select({ label: 'Public port', options: [], help: 'The port of the internet address. 443 needs no port in links.' });
  port.input.addEventListener('change', () => { dirty = true; port.setError(null); });
  const allowAdmin = toggle({
    label: 'Allow administration over Funnel',
    help: 'Admin pages over the internet address (full app only; needs two-factor sign-in). Off is safer: administer from your tailnet.',
    onChange: () => { dirty = true; allowAdmin.setError(null); syncControls(); },
  });
  const require2fa = toggle({
    label: 'Require two-factor sign-in over Funnel',
    help: 'Only accounts with an authenticator app or a passkey can sign in over the internet address.',
    onChange: () => { dirty = true; syncControls(); },
  });
  const adminWarn = h('div');
  const connection = h('div', { class: 'stack-sm' });
  const advanced = h('details', { class: 'auth-details remote-advanced' },
    h('summary', { text: 'Advanced' }),
    h('div', { class: 'stack' }, port.el, allowAdmin.el, require2fa.el, adminWarn,
      h('div', { class: 'stack-sm remote-connection' },
        h('h3', { class: 'remote-subtitle', text: 'How Tailscale reaches FileParcel' }),
        h('p', { class: 'text-sm', text: 'Keep “auto” unless a check suggests otherwise. These settings apply to Funnel and Serve and are saved on their own.' }),
        connection)));
  advanced.addEventListener('toggle', () => {
    if (advanced.open && !connection.childElementCount) {
      connection.append(settingsForm({ section: 'funnel', keys: ['funnel.backend', 'funnel.backend_port'] }));
    }
  });

  const tests = statusButtons(env, 'funnel', errSlot);
  const saveBtn = button({ label: 'Save', icon: 'check', variant: 'primary', onClick: () => save() });
  const actions = h('div', { class: 'btn-row' }, tests.test, tests.reapply, saveBtn);

  f.body.append(statusSlot, errSlot, modeGroup, advanced, checksSlot, actions, footSlot);

  /** Enable/disable the controls for the chosen mode and the signed-in account. */
  const syncControls = () => {
    const s = getSt();
    const app = mode === 'app';
    const admin = builtinAdmin();
    const noWeaken = 'Only an owner or administrator can change this';
    for (const r of radios) r.input.checked = r.m.id === mode;
    const unavailable = !s || (!s.available && String(s.funnel?.mode || 'off') === 'off');
    for (const r of radios) r.input.disabled = unavailable && r.m.id !== 'off';
    port.input.disabled = mode === 'off';
    // Switching administration on and 2FA off weakens sign-in: built-in owners/administrators only (server: 403).
    allowAdmin.input.disabled = !app || !require2fa.input.checked || (!admin && !s?.allow_admin);
    allowAdmin.input.title = !admin && !s?.allow_admin ? noWeaken : '';
    require2fa.input.disabled = !app || allowAdmin.input.checked || (!admin && !!s?.require_2fa);
    require2fa.input.title = !admin && s?.require_2fa ? noWeaken : '';
    // The title is invisible on touch screens: say it next to the switches as well.
    const locked = app && !admin && (!s?.allow_admin || !!s?.require_2fa);
    // The saved switches take effect when the full app gets published: a delegate has to
    // switch them to the safe side first (the server refuses otherwise).
    const inherited = app && !admin && String(s?.funnel?.mode || 'off') !== 'app'
      && (allowAdmin.input.checked || !require2fa.input.checked);
    replace(adminWarn,
      locked
        ? h('p', { class: 'text-sm muted', dataset: { reason: 'weaken' }, text: 'Only an owner or administrator can allow administration over Funnel or turn off two-factor sign-in.' })
        : null,
      inherited
        ? h('p', { class: 'text-sm', dataset: { reason: 'inherited' }, text: 'The saved settings allow administration over Funnel or sign-in without two-factor authentication. Switch that to the safe side before publishing the full app, or ask an owner or administrator.' })
        : null,
      app && allowAdmin.input.checked
        ? alertEl('warning', 'Admin pages on the internet', 'Anyone who gets hold of an administrator’s password and second factor can administer FileParcel from anywhere.')
        : null,
      app && !require2fa.input.checked
        ? alertEl('danger', 'Password-only sign-in on the internet', 'Anyone who guesses a password can sign in over Funnel.')
        : null);
    saveBtn.disabled = unavailable && mode !== 'off';
  };

  /** Reset the controls to the server's state. */
  const resetControls = () => {
    const s = getSt();
    const e = s?.funnel || {};
    mode = /** @type {any} */ (['off', 'shares', 'app'].includes(e.mode) ? e.mode : 'off');
    const usable = Array.isArray(s?.funnel_ports) ? s.funnel_ports : [];
    const cap = Array.isArray(s?.tailscale?.funnel_ports) ? s.tailscale.funnel_ports : null;
    const servePort = s?.serve?.mode === 'app' ? Number(s?.serve?.port) : 0;
    const current = Number(e.port) || 443;
    port.setOptions(FUNNEL_PORTS.map((p) => {
      let why = '';
      if (p === servePort) why = 'used by Tailscale Serve';
      else if (cap && !cap.includes(p)) why = 'not allowed for this device';
      else if (!usable.includes(p) && (cap || usable.length)) why = 'used by FileParcel itself';
      return { value: String(p), label: why ? `${p} (${why})` : String(p), disabled: !!why && p !== current };
    }), String(current));
    allowAdmin.input.checked = !!s?.allow_admin;
    require2fa.input.checked = s ? s.require_2fa !== false : true;
    port.setError(null);
    allowAdmin.setError(null);
    dirty = false;
  };

  const draw = (/** @type {boolean} */ fromWrite) => {
    const s = getSt();
    const e = s?.funnel || null;
    replace(f.badgeSlot, e ? stateBadgeFor(e) : null);
    if (!dirty || fromWrite) resetControls();
    syncControls();
    tests.sync();
    if (!s) {
      replace(statusSlot, h('p', { class: 'muted text-sm', text: 'The Tailscale Funnel status is not available.' }));
      replace(checksSlot);
      replace(footSlot);
      return;
    }
    // status
    const items = [];
    if (e && e.state === 'active' && e.url) {
      items.push(addressRow(e.url, 'Internet address'));
      items.push(h('p', { class: 'muted text-sm', text: e.mode === 'app'
        ? 'The whole app is public at this address; sign-in needs two-factor authentication.'
        : 'Share links and file requests are public at this address; new links use it.' }));
    }
    // An active entry's only message is the public DNS delay, which the footer states already.
    if (e && e.message && e.state !== 'off' && e.state !== 'active') {
      items.push(h('p', { class: e.state === 'stopped' ? 'muted text-sm' : 'text-sm', text: e.message }));
    }
    if (!s.available && (!e || e.mode === 'off')) {
      items.push(h('p', { class: 'muted text-sm' },
        h('span', { text: `${s.reason || 'Tailscale Funnel is not available on this machine.'} ` }),
        h('span', { text: 'Alternatives: use Tailscale’s control server (Funnel is not available with Headscale), or a reverse proxy with an ACME certificate and ' }),
        h('code', { text: 'server.trusted_proxies' }),
        h('span', { text: '.' })));
    }
    replace(statusSlot, ...items);
    // checks
    replace(checksSlot,
      h('h3', { class: 'remote-subtitle', text: 'Checks' }),
      checkList(e?.checks || [], highlight));
    // footer
    const notes = [];
    if (e && e.state === 'active') {
      notes.push(h('p', { text: e.last_public_request_at
        ? `Last public request: ${relTime(e.last_public_request_at)}.`
        : 'No public request yet — public DNS can take up to 10 minutes.' }));
      notes.push(h('p', { text: 'The reachability test runs over your tailnet; it cannot prove that public DNS is ready.' }));
    }
    notes.push(h('p', { text: 'No router or firewall change is needed: the traffic reaches FileParcel through Tailscale.' }));
    notes.push(foreignList(s.foreign));
    replace(footSlot, ...notes);
  };

  const save = async () => {
    const s = getSt();
    const cur = s?.funnel || {};
    const curMode = String(cur.mode || 'off');
    const nextPort = Number(port.value()) || Number(cur.port) || 443;
    const app = mode === 'app';
    /** @type {Record<string, any>} */
    const body = { mode };
    if (mode !== 'off' && nextPort !== Number(cur.port)) body.port = nextPort;
    if (app && allowAdmin.input.checked !== !!s?.allow_admin) body.allow_admin = allowAdmin.input.checked;
    if (app && require2fa.input.checked !== (s?.require_2fa !== false)) body.require_2fa = require2fa.input.checked;
    if (mode === curMode && body.port === undefined && body.allow_admin === undefined && body.require_2fa === undefined) {
      toast.info('No changes to save.');
      return;
    }
    // Weakening sign-in over the internet is judged on what takes effect: the stored
    // "allow administration" / "two-factor off" apply as soon as the full app is published
    // (they stay stored while Funnel is off or shares only). The server decides the same way.
    const adminNow = curMode === 'app' && !!s?.allow_admin;
    const passwordOnlyNow = curMode === 'app' && s?.require_2fa === false;
    const adminNext = app && allowAdmin.input.checked;
    const passwordOnlyNext = app && !require2fa.input.checked;
    const weakenAdmin = adminNext && !adminNow;
    const weaken2fa = passwordOnlyNext && !passwordOnlyNow;
    const widen = (curMode === 'off' && mode !== 'off') || (curMode === 'shares' && mode === 'app');
    const weaken = weakenAdmin || weaken2fa;
    const url = `https://${env.dnsName() || '<this device>.ts.net'}${nextPort === 443 ? '' : `:${nextPort}`}/`;
    if (widen) {
      const ok = await confirm({
        title: 'Publish on the internet?',
        danger: true,
        confirmLabel: 'Publish',
        message: h('div', { class: 'stack-sm' },
          h('p', null, 'Anyone on the internet can reach ', h('strong', { class: 'remote-url', text: url }), ':'),
          h('ul', { class: 'hint-list' }, (mode === 'app'
            ? ['the sign-in page and, after sign-in, the whole app',
              adminNext ? 'the admin pages' : '',
              passwordOnlyNext ? 'sign-in with a password alone (two-factor sign-in is off)' : '',
              'every active share link and file request'].filter(Boolean)
            : ['every active share link and file request (with their passwords, expiry dates and limits)'])
            .map((t) => h('li', { text: t }))),
          h('p', { class: 'muted text-sm', text: 'Everything else answers “not found”. You can turn it off here at any time.' })),
      });
      if (!ok) return;
    }
    if (weaken) {
      const ok = await confirmTyped({
        title: 'Weaken sign-in over the internet?',
        message: [
          weakenAdmin ? 'The admin pages will be reachable over the internet address.' : '',
          weaken2fa ? 'Accounts without two-factor authentication will be able to sign in over the internet address with a password alone.' : '',
        ].filter(Boolean).join(' '),
        expected: 'public',
        confirmLabel: 'Change it',
      });
      if (!ok) return;
    }
    if (mode === 'off' && curMode !== 'off') {
      const ok = await confirm({ title: 'Turn Funnel off?', message: 'Share links stop working from the internet. They keep working on your network and tailnet.', confirmLabel: 'Turn off' });
      if (!ok) return;
    }
    if (widen || weaken) body.confirm = 'public';
    replace(errSlot);
    highlight = '';
    try {
      /** @type {any} */
      const res = await api.put('/admin/network/funnel', body);
      dirty = false;
      env.done(res, 'funnel');
      announce(res?.funnel, mode === 'off' ? 'Funnel is off' : 'Funnel is on');
    } catch (err) {
      if (err instanceof ApiError && (err.status === 409 || err.status === 422) && err.field === 'port') {
        port.setError(err.message);
        advanced.open = true;
      } else if (err instanceof ApiError && err.status === 422 && err.field === 'allow_admin') {
        allowAdmin.setError(err.message);
        advanced.open = true;
      } else if (err instanceof ApiError && err.status === 412 && err.field) {
        highlight = err.field;
        replace(errSlot, writeError(err));
        draw(false);
        checksSlot.querySelector(`[data-check="${CSS.escape(err.field)}"]`)?.scrollIntoView({ block: 'nearest' });
      } else {
        replace(errSlot, writeError(err));
      }
    }
  };

  return { el: f.el, draw };
}

/**
 * The serve entries of other programs on this device (FileParcel leaves them alone); those that reach FileParcel
 * directly are flagged (the page's warnings explain how to remove them).
 * @param {any[]} foreign
 */
function foreignList(foreign) {
  if (!Array.isArray(foreign) || !foreign.length) return null;
  return h('details', { class: 'auth-details remote-foreign' },
    h('summary', { text: `Other Tailscale Serve and Funnel entries on this device (${foreign.length})` }),
    h('ul', { class: 'remote-foreign-list', attrs: { role: 'list' } }, foreign.map((x) => h('li', null,
      h('span', { class: 'mono remote-url', text: `${x.host_port || ''}${x.mount && x.mount !== '/' ? x.mount : ''} → ${x.target || ''}` }),
      h('span', { class: 'cluster' },
        x.funnel ? badge({ text: 'Funnel', kind: 'info' }) : badge({ text: 'Serve', kind: 'neutral' }),
        x.foreground ? badge({ text: 'Foreground', kind: 'neutral' }) : null,
        x.service ? badge({ text: x.service, kind: 'neutral' }) : null,
        x.bypass ? badge({ text: 'Reaches FileParcel directly', kind: 'danger', icon: 'alert-circle' }) : null)))));
}

// ---------------------------------------------------------------------------------------------------------------
// Serve
// ---------------------------------------------------------------------------------------------------------------

/** @param {Env} env */
function serveCard(env) {
  const getSt = env.getSt;
  const f = frame({ id: 'serve', title: 'Tailnet address without port (Tailscale Serve)', icon: 'tailscale' });
  const statusSlot = h('div', { class: 'stack-sm' });
  const errSlot = h('div', { attrs: { 'aria-live': 'polite' } });
  const checksSlot = h('div', { class: 'stack-sm' });
  let dirty = false;
  let highlight = '';
  const enabled = toggle({
    label: 'Publish on the tailnet',
    help: 'Devices on your tailnet open FileParcel with Tailscale’s trusted certificate and without a port. The access policy still applies to them.',
    onChange: () => { dirty = true; sync(); },
  });
  const port = field({ label: 'Tailnet port', type: 'number', min: 1, max: 65535, inputmode: 'numeric',
    help: 'The HTTPS port on the tailnet address; 443 needs none in the address.' });
  port.input.addEventListener('input', () => { dirty = true; });
  const tests = statusButtons(env, 'serve', errSlot);
  const saveBtn = button({ label: 'Save', icon: 'check', variant: 'primary', onClick: () => save() });
  f.body.append(statusSlot, errSlot, enabled.el, port.el, checksSlot, h('div', { class: 'btn-row' }, tests.test, tests.reapply, saveBtn));

  const sync = () => {
    const s = getSt();
    const unavailable = !s || (!s.available && s.serve?.mode !== 'app');
    enabled.input.disabled = unavailable && !enabled.input.checked;
    port.input.disabled = !enabled.input.checked;
    saveBtn.disabled = unavailable && enabled.input.checked;
  };

  const draw = (/** @type {boolean} */ fromWrite) => {
    const s = getSt();
    const e = s?.serve || null;
    replace(f.badgeSlot, e ? stateBadgeFor(e) : null);
    if (!dirty || fromWrite) {
      enabled.input.checked = e?.mode === 'app';
      port.input.value = String(e?.port || 443);
      port.setError(null);
      dirty = false;
    }
    sync();
    tests.sync();
    if (!s) {
      replace(statusSlot, h('p', { class: 'muted text-sm', text: 'The Tailscale Serve status is not available.' }));
      replace(checksSlot);
      return;
    }
    const items = [];
    if (e && e.state === 'active' && e.url) items.push(addressRow(e.url, 'Tailnet address'));
    if (e && e.message && e.state !== 'off') items.push(h('p', { class: 'text-sm', text: e.message }));
    if (!s.available && e?.mode !== 'app') {
      items.push(h('p', { class: 'muted text-sm', text: s.reason || 'Tailscale Serve is not available on this machine.' }));
    }
    replace(statusSlot, ...items);
    replace(checksSlot, h('h3', { class: 'remote-subtitle', text: 'Checks' }), checkList(e?.checks || [], highlight));
  };

  const save = async () => {
    const s = getSt();
    const cur = s?.serve || {};
    const on = enabled.input.checked;
    const p = Number(port.value());
    if (on && (!Number.isInteger(p) || p < 1 || p > 65535)) {
      port.setError('Enter a port between 1 and 65535.');
      return;
    }
    const wasOn = cur.mode === 'app';
    if (on === wasOn && (!on || p === Number(cur.port))) {
      toast.info('No changes to save.');
      return;
    }
    if (on && !wasOn) {
      const ok = await confirm({ title: 'Publish on your tailnet?', message: 'Every device on your tailnet that the access policy admits can open FileParcel at this address.', confirmLabel: 'Publish' });
      if (!ok) return;
    }
    replace(errSlot);
    highlight = '';
    try {
      /** @type {any} */
      const res = await api.put('/admin/network/serve', on ? { enabled: true, port: p } : { enabled: false });
      dirty = false;
      env.done(res, 'serve');
      announce(res?.serve, on ? 'Tailscale Serve is on' : 'Tailscale Serve is off');
    } catch (err) {
      if (err instanceof ApiError && (err.status === 409 || err.status === 422) && err.field === 'port') {
        port.setError(err.message);
      } else if (err instanceof ApiError && err.status === 412 && err.field) {
        highlight = err.field;
        replace(errSlot, writeError(err));
        draw(false);
      } else {
        replace(errSlot, writeError(err));
      }
    }
  };

  return { el: f.el, draw };
}
