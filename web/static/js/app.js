// @ts-check
/**
 * FileParcel web app — entry module of the SPA shell (web/templates/app.html).
 *
 * ════════════════════════════════════════════════ READ ME FIRST ════════════════════════════════════════════════
 *
 * No build step, no npm: plain ES modules served from /static/<buildhash>/… (immutable caching). Relative imports
 * inherit the hash prefix, so never hard-code "/static/…" — use asset('path') from core/dom.js.
 *
 * Module map (web/static/js)
 *   app.js            boot: #fp-boot → GET /api/v1/me → shell → router → SSE → shortcuts → service worker
 *   routes.js         route table (§13.2); every page is a lazy import()
 *   nav.js            shell: sidebar / rail / drawer / bottom tabs / top bar, Upload split button + FAB hooks
 *   core/dom.js       h(), svg(), icon(), clear(), qs(), boot(), asset(), focus trap, announce(), scriptURL()
 *   core/api.js       api.get/post/put/patch/del/raw, ApiError, CSRF header, 401/403/503 handling
 *   core/router.js    start(), navigate(), link(), current(), route & pageTitle signals
 *   core/store.js     signal/computed/effect/batch, session (GET /me), jobs (SSE), events bus
 *   core/format.js    bytes, date, dateTime, relTime, duration, pct, fileIcon …
 *   core/keys.js      keyboard shortcut registry ("mod+k", "g f", "?")
 *   core/webauthn.js  passkey JSON ↔ WebAuthn API helpers
 *   components/*.js   UI kit — frozen API listed in components/index.js (import from there)
 *   upload/*.js       uploader (basic.js = foundation fallback; J1 replaces with queue/worker version)
 *   pages/**          page modules: `export const title` + `export async function mount(root, ctx)` → cleanup?
 *   public/*.js       modules for the server-rendered public pages (login, invite, setup, unlock, trust, share, error)
 *
 * CSP & Trusted Types (enforced by the server: script-src 'self'; style-src 'self';
 * require-trusted-types-for 'script'; trusted-types …) — these are HARD rules:
 *   ✗ innerHTML / outerHTML / insertAdjacentHTML / document.write / DOMParser-to-DOM / srcdoc
 *   ✗ eval / new Function / setTimeout("string") / javascript: URLs
 *   ✗ inline event handler attributes (onclick="…") and element.onxxx = … assignments (use addEventListener / h(…, {on}))
 *   ✗ style="…" attributes or setAttribute('style', …) — use classes or el.style.setProperty() (CSSOM is allowed)
 *   ✗ inline <script>/<style> in templates; the only inline script is the non-executed JSON #fp-boot block
 *   ✓ Build DOM with h()/svg() and textContent; user data is ALWAYS text, never markup.
 *   ✓ Workers / service worker URLs go through `await scriptURL(url)` — the app's single Trusted Types policy "fp"
 *     (CSP `trusted-types fp`) only accepts same-origin URLs under the asset base or exactly /sw.js. It resolves null
 *     for any other URL (never create the worker then); the policy never creates HTML or script.
 *   ✓ QR codes come from the server as SVG images (<img src="/api/v1/qr.svg?data=…"> or data: URIs).
 *   ✓ blob: URLs only for client-generated downloads (downloadBlob()).
 * scripts in tests/ scan for violations; the browser tests fail on any CSP/TT console error.
 *
 * Page contract: mount(root, ctx) with ctx = {params, query, me, signal, url}. Pass ctx.signal to api calls so
 * requests abort when the user navigates away; return a cleanup function for timers/listeners/effects.
 * In-app events: events.on('files.changed' | 'job.done' | …, fn) (core/store.js); SSE topics are re-emitted as-is.
 * Permissions: routes carry their guard (routes.js: admin / staff / perm), checked here before a page mounts and by
 * nav.js for the navigation; pages ask core/store.js can('…') / isAdmin() for single controls. An administrator's
 * change to this account's role arrives as authz.changed: /me is read again and the shell follows.
 * ════════════════════════════════════════════════════════════════════════════════════════════════════════════════
 * @module app
 */
import { h, boot, qs, buildHash, scriptURL, applyTheme, applyDensity, announce } from './core/dom.js';
import { api, setCsrf, ApiError } from './core/api.js';
import { start, navigate, current, reload } from './core/router.js';
import {
  session, events, can, isAdmin, isStaff, isFullSession, refreshMe, effect, untracked, jobs, upsertJob, forgetJob, isFinishedJob,
} from './core/store.js';
import { register } from './core/keys.js';
import { routes, forbidden, routeAllowed } from './routes.js';
import { renderShell, openCommandPalette, triggerUpload, dispatchUpload, canUpload, adminItems } from './nav.js';
import { toast } from './components/toast.js';
import { showShortcuts } from './components/palette.js';

/**
 * SSE topics published by the server (§5.3 events topics). The server sends each account only the topics its role
 * may see (opsapi/sse.go); a topic missing here never reaches the in-app bus.
 */
const SSE_TOPICS = [
  'settings.changed', 'network.changed', 'certs.changed', 'keys.state', 'mdns.changed',
  'job.progress', 'job.done', 'upload.batch_done', 'share.accessed', 'backup.finished',
  'authz.changed', 'ingress.changed',
];

/**
 * Accept both {user, csrf, …} and a bare User object from GET /me.
 * @param {any} res
 * @returns {import('./core/store.js').Me}
 */
function normalizeMe(res) {
  if (res && res.user) return res;
  if (res && res.id && res.username) return { user: res };
  throw new ApiError(500, 'bad_response', 'Unexpected response from /api/v1/me');
}

/** Apply theme & density from local choice → user prefs → server default (<html data-theme>). */
function applyAppearance() {
  const me = session.peek();
  const prefs = me?.prefs || me?.user?.prefs || boot().user?.prefs || {};
  let local = '';
  try { local = localStorage.getItem('fp:theme') || ''; } catch { /* ignore */ }
  const theme = local || prefs.theme || document.documentElement.dataset.theme || 'system';
  applyTheme(theme);
  applyDensity(prefs.density || '');
}

let sseOpen = false;

/** Subscribe to /api/v1/events (Server-Sent Events) and re-emit every topic on the in-app bus. */
function connectEvents() {
  if (!('EventSource' in window) || sseOpen) return;
  sseOpen = true;
  let retry = 2000;
  /** @type {EventSource | null} */
  let es = null;
  let reopenTimer = 0;

  /** @param {string} topic @param {string} raw */
  const deliver = (topic, raw) => {
    let data = null;
    try { data = raw ? JSON.parse(raw) : null; } catch { data = raw; }
    events.emit(topic, data);
  };

  const open = () => {
    es = new EventSource('/api/v1/events');
    for (const t of SSE_TOPICS) es.addEventListener(t, (e) => deliver(t, /** @type {MessageEvent} */ (e).data));
    // unnamed events may carry {topic, data}
    es.addEventListener('message', (e) => {
      try {
        const m = JSON.parse(e.data);
        if (m && typeof m.topic === 'string') events.emit(m.topic, m.data ?? null);
      } catch { /* heartbeat or unknown payload */ }
    });
    es.addEventListener('open', () => {
      retry = 2000;
      events.emit('sse.open', null);
    });
    es.addEventListener('error', () => {
      // EventSource reconnects by itself while CONNECTING; when CLOSED (HTTP error) back off and retry.
      if (es && es.readyState === EventSource.CLOSED) {
        es.close();
        es = null;
        reopenTimer = window.setTimeout(open, retry);
        retry = Math.min(retry * 2, 60_000);
      }
    });
  };
  open();
  window.addEventListener('pagehide', () => {
    clearTimeout(reopenTimer); // a queued reopen would otherwise still fire on a frozen/bfcached page
    es?.close();
    es = null;
  });
  // Restored from the back/forward cache: the stream was closed on pagehide and nothing else reopens it.
  window.addEventListener('pageshow', (e) => {
    if (e.persisted && !es) open();
  });
}

/**
 * Job events published while no stream was open are gone: the server does not replay them, and it ends every stream
 * after about 30 minutes (a sleeping laptop or a network drop does the same). On every (re)connect, re-read the jobs
 * the store still counts as queued or running, so a lost job.done cannot leave the top-bar indicator pulsing until a
 * reload. GET /jobs/{id} serves the creator and administrators — exactly whose jobs the stream delivers.
 */
function reconcileJobs() {
  for (const j of jobs.peek().values()) {
    if (isFinishedJob(j)) continue;
    api.get(`/jobs/${encodeURIComponent(j.id)}`, { handle: false })
      .then((job) => upsertJob(job))
      .catch((err) => { if (err instanceof ApiError && err.status === 404) forgetJob(j.id); });
  }
}

/** App-wide reactions to server events. */
function wireServerEvents(/** @type {ReturnType<typeof renderShell>} */ shell) {
  events.on('keys.state', (d) => {
    const state = d?.state || d;
    shell.setStatus(String(state));
    if (state === 'locked') location.assign(`/unlock?next=${encodeURIComponent(location.pathname + location.search)}`);
  });
  events.on('settings.changed', (d) => {
    const keys = Array.isArray(d?.keys) ? d.keys : [];
    if (keys.some((k) => String(k).startsWith('ui.'))) {
      const link = /** @type {HTMLLinkElement | null} */ (qs('link[href^="/theme.css"]'));
      if (link) link.href = `/theme.css?t=${Date.now()}`;
    }
    // features.maintenance (the maintenance banner, accountBanners)
    if (keys.includes('maintenance.enabled')) refreshMe();
  });
  events.on('upload.batch_done', () => {
    events.emit('files.changed', {});
    shell.refreshUsage();
  });
  events.on('job.done', (d) => {
    const job = d?.job || d;
    if (job?.state === 'failed' && (job.created_by === session.peek()?.user?.id || can('system.view'))) {
      toast.error(`${job.kind || 'Job'} failed${job.error ? `: ${job.error}` : ''}`);
    }
  });
  events.on('authz.changed', (d) => { onAuthzChanged(d, shell); });
  events.on('files.changed', () => shell.refreshUsage());
  events.on('sse.open', reconcileJobs);
  // One sticky warning while offline, closed again when the connection returns (it would otherwise stay next to
  // "Back online", one more for every blip).
  /** @type {{close: () => void, el: HTMLElement} | null} */
  let offlineToast = null;
  window.addEventListener('offline', () => {
    if (offlineToast?.el.isConnected) return;
    offlineToast = toast.warning('You are offline. Changes will fail until the connection is back.', { timeout: 0 });
  });
  window.addEventListener('online', () => {
    offlineToast?.close();
    offlineToast = null;
    toast.success('Back online', { timeout: 2500 });
  });
}

/** Whether the page on screen is the "not allowed" page the route guard put in place of the route's own page. */
let guardBlocked = false;

/**
 * Route guard (router.js start()): the "not allowed" page for a route this account may not open (routes.js).
 * @param {import('./core/router.js').Route} r
 */
function guard(r) {
  guardBlocked = !routeAllowed(r);
  return guardBlocked ? forbidden : null;
}

/**
 * authz.changed (core.AuthzChangedEvent {user_ids?, role_id?, reason}): an administrator gave an account another
 * role, changed or deleted a role, or changed a role's groups. The server applies it to every request at once, so
 * read /me again — the navigation follows the session store — and re-check the page on screen: one that is no
 * longer allowed gives way to the "not allowed" page, and a "not allowed" page that now is allowed shows the page
 * itself. Staff who merely look at roles get the event too; the toast and the refresh of team folders and files are
 * for the accounts it names (by id, or by the role they held). The server ends the event stream of those accounts
 * right after, and EventSource reconnects with their new rights. Reason "role_details" (only the role's name,
 * description or "delegable" flag changed) changes nothing the holders may do: /me is read again for the new name,
 * without the toast, and the stream stays open. The role lists of the admin pages drop their cache on the same event
 * (pages/admin/common.js).
 * @param {any} d
 * @param {ReturnType<typeof renderShell>} shell
 */
async function onAuthzChanged(d, shell) {
  const before = session.peek()?.user;
  const ids = Array.isArray(d?.user_ids) ? d.user_ids : [];
  const mine = !!before && (ids.includes(before.id) || (!!d?.role_id && d.role_id === before.role_id));
  await refreshMe();
  const r = current().route;
  if (r && routeAllowed(r) === guardBlocked) reload();
  if (!mine || d?.reason === 'role_details') return;
  toast.info('Your access was changed by an administrator.');
  shell.refreshTeams(); // team folders come and go with roles and their groups
  events.emit('files.changed', {});
}

/** Global keyboard shortcuts (page modules register their own and unregister in cleanup). */
function registerShortcuts() {
  register('mod+k', openCommandPalette, { description: 'Search & command palette', group: 'General', global: true });
  register('/', openCommandPalette, { description: 'Search', group: 'General' });
  register('?', showShortcuts, { description: 'Show keyboard shortcuts', group: 'General' });
  register('u', () => triggerUpload('files'), { description: 'Upload files', group: 'Files', when: () => canUpload.peek() });
  register('shift+n', () => triggerUpload('new-folder'), { description: 'New folder', group: 'Files', when: () => canUpload.peek() });
  const go = /** @type {[string, string, string][]} */ ([
    ['g f', '/files', 'Go to My files'],
    ['g s', '/shared', 'Go to Shared with me'],
    ['g l', '/links', 'Go to My links'],
    ['g r', '/recent', 'Go to Recent'],
    ['g *', '/starred', 'Go to Starred'],
    ['g t', '/trash', 'Go to Trash'],
    ['g p', '/settings/profile', 'Go to Settings'],
  ]);
  for (const [combo, path, label] of go) register(combo, () => navigate(path), { description: label, group: 'Navigation' });
  // the first admin page this account may open (the Dashboard, or "Your admin areas" for a delegate)
  register('g a', () => navigate(adminItems()[0]?.href || '/admin'), { description: 'Go to Admin', group: 'Navigation', when: () => isStaff() });
}

/**
 * Register /sw.js — only in secure contexts over HTTPS (browsers refuse service workers on untrusted certificates;
 * /settings/devices explains how to trust the local CA). Under Trusted Types the URL comes from the "fp" policy
 * (core/dom.js scriptURL()).
 */
async function registerServiceWorker() {
  if (!('serviceWorker' in navigator) || !window.isSecureContext || location.protocol !== 'https:') return;
  const url = await scriptURL(`/sw.js?v=${encodeURIComponent(buildHash() || 'dev')}`);
  if (url === null) return;
  try {
    await navigator.serviceWorker.register(url, { scope: '/', updateViaCache: 'none' });
  } catch (err) {
    console.info('Service worker not registered (untrusted certificate or unsupported):', /** @type {any} */ (err)?.message || err);
  }
}

/** sw.js handleShareTarget(): the share carried no files (a link or text), so nothing was parked. */
const SHARE_NO_FILES = 'none';

/**
 * The installed app's one-shot launch parameters: ?share-target=<id> (sw.js parked shared files) and ?upload=1 (the
 * manifest's Upload shortcut, or POST /share-target without a service worker). They are read, and taken out of the
 * address, before the router mounts a page: a page's own redirect — a guest's /files → /shared, the password-change
 * and 2FA enrolment gates — would otherwise drop them before the hand-off runs.
 */
function takeLaunchParams() {
  const params = new URLSearchParams(location.search);
  const shareId = params.get('share-target') || '';
  const upload = params.get('upload') === '1';
  if (params.has('share-target') || upload) {
    params.delete('share-target');
    if (upload) params.delete('upload');
    const rest = params.toString();
    // not navigate(): the router has not started yet, and navigate() would load the page again
    history.replaceState(history.state, '', location.pathname + (rest ? `?${rest}` : '') + location.hash);
  }
  return { shareId, upload };
}

/**
 * PWA share target: the service worker parked shared files in memory; fetch them and start an upload.
 * @param {string} id from ?share-target=
 */
async function shareTargetHandoff(id) {
  if (id === SHARE_NO_FILES) {
    toast.warning('Only files can be shared to FileParcel, not links or text.');
    return;
  }
  const sw = navigator.serviceWorker?.controller;
  /** @type {File[]} */
  const files = !sw ? [] : await new Promise((resolve) => {
    const ch = new MessageChannel();
    const timer = setTimeout(() => resolve([]), 5000);
    ch.port1.addEventListener('message', (e) => {
      clearTimeout(timer);
      resolve(Array.isArray(e.data?.files) ? e.data.files : []);
    });
    ch.port1.start();
    sw.postMessage({ type: 'share-target:get', id }, [ch.port2]);
  });
  if (files.length) dispatchUpload('files', { files });
  else toast.warning('The shared files are no longer available. Please share them again.');
}

/** PWA shortcut /files?upload=1: pickers need a user gesture, so offer a one-tap action. */
function uploadShortcut() {
  toast.show({ message: 'Ready to upload.', kind: 'info', timeout: 0, action: { label: 'Choose files', onClick: () => triggerUpload('files') } });
}

/**
 * Banners for account states that need attention. Rendered from a `session` subscription, so the banner disappears
 * the moment the condition clears (settings/common.js updates the store after a successful password change) instead
 * of sitting there until the next reload.
 */
function accountBanners(/** @type {HTMLElement} */ banners) {
  /** @type {HTMLElement | null} */
  let pwBanner = null;
  /** @type {HTMLElement | null} */
  let maintBanner = null;
  effect(() => {
    const me = session.value;
    // `session` must stay this effect's only dependency: navigate() renders a page, which touches other signals.
    untracked(() => {
      if (!me) return;
      // Maintenance mode keeps everyone out except administrators and "Operate the server" (mw.Maintenance): the
      // people who can still use the app are the ones who must not forget to switch it off.
      const maint = !!me.features?.maintenance && (isAdmin(me) || can('system.manage', me));
      if (maint && !maintBanner) {
        maintBanner = h('div', { class: 'alert alert--warning', attrs: { role: 'status' } },
          h('div', { class: 'alert-body' },
            h('strong', { text: 'Maintenance mode is on' }),
            h('span', { text: 'Only administrators and roles that operate the server can use FileParcel. Everyone else sees the maintenance notice, and shares and uploads are paused.' })),
          can('system.manage', me) ? h('button', {
            class: 'btn btn--secondary btn--sm',
            attrs: { type: 'button' },
            text: 'Turn off',
            on: {
              click: async (e) => {
                const btn = /** @type {HTMLButtonElement} */ (e.currentTarget);
                btn.disabled = true;
                try {
                  await api.patch('/admin/settings', { 'maintenance.enabled': false });
                  toast.success('Maintenance mode is off');
                  await refreshMe();
                } catch (err) {
                  toast.error(err);
                } finally {
                  btn.disabled = false;
                }
              },
            },
          }) : null);
        banners.prepend(maintBanner);
      } else if (!maint && maintBanner) {
        maintBanner.remove();
        maintBanner = null;
      }
      if (me.user?.must_change_password) {
        if (!pwBanner) {
          pwBanner = h('div', { class: 'alert alert--warning', attrs: { role: 'status' } },
            h('div', { class: 'alert-body' },
              h('strong', { text: 'Please choose a new password' }),
              h('span', { text: 'Your password was set by an administrator or generated at install time.' })),
            h('a', { class: 'btn btn--secondary btn--sm', href: '/settings/security?must_change=1', text: 'Change password' }));
          banners.appendChild(pwBanner);
        }
        if (!location.pathname.startsWith('/settings/security')) navigate('/settings/security?must_change=1', { replace: true });
      } else if (pwBanner) {
        pwBanner.remove();
        pwBanner = null;
      }
      const mfa = me.mfa;
      if (mfa && mfa.enroll_required && !location.pathname.startsWith('/settings/security')) {
        navigate('/settings/security?enroll=1', { replace: true });
      }
    });
  });
}

/**
 * The password-change and 2FA-enrolment gates, applied before the router mounts the first page: everything but
 * /me* sits behind mw.RequireFull for such a session (403 password_change_required / mfa_enroll_required), so
 * mounting the requested page (/files loads /nodes/…) and redirecting afterwards would only fire requests that fail.
 * The address is pointed at the gate instead; accountBanners() keeps enforcing it from then on.
 * @param {import('./core/store.js').Me | null} me
 */
function applyAccountGate(me) {
  if (!me || location.pathname.startsWith('/settings/security')) return;
  const u = /** @type {any} */ (me.user) || {};
  let target = '';
  if (u.must_change_password) target = '/settings/security?must_change=1';
  else if (me.mfa?.enroll_required || u.enroll_required) target = '/settings/security?enroll=1';
  // not navigate(): the router has not started yet
  if (target) history.replaceState(history.state, '', target);
}

async function main() {
  const b = boot();
  const root = document.getElementById('fp-app') || document.body.appendChild(h('div', { id: 'fp-app' }));
  applyAppearance();

  /** @type {import('./core/store.js').Me | null} */
  let me = null;
  try {
    me = normalizeMe(await api.get('/me'));
  } catch (err) {
    if (err instanceof ApiError && (err.status === 401 || err.code === 'keys_locked')) return; // api.js redirected
    if (b.user) {
      // /me unavailable (older backend / transient error): continue with the boot user
      console.warn('GET /api/v1/me failed; using boot data', err);
      me = { user: b.user, csrf: b.csrf, prefs: b.user.prefs };
    } else {
      location.assign(`/login?next=${encodeURIComponent(location.pathname + location.search)}`);
      return;
    }
  }
  if (me.csrf) setCsrf(me.csrf);
  session.value = me;
  applyAppearance();

  const shell = renderShell(root);
  wireServerEvents(shell);
  registerShortcuts();
  // upload manager: claims fp:upload events, the drop overlay, paste, the queue panel and resume cards (§8.1)
  const uploads = import('./upload/manager.js').then((m) => m.install()).catch((err) => console.error('upload manager failed to load', err));

  const launch = takeLaunchParams();
  applyAccountGate(me);
  await start(routes, shell.outlet, { guard });

  accountBanners(shell.banners);
  // The event stream and the shell's bootstrap fetches all sit behind mw.RequireFull, so in the required-2FA
  // enrolment gate they would only produce 403s. They start at once for a normal session and otherwise wait until
  // /me reports enroll_required:false (refreshMe() in pages/settings/security.js after the TOTP confirm or a
  // passkey registration).
  let bootstrapped = false;
  effect(() => {
    if (!isFullSession(session.value)) return;
    connectEvents();
    if (bootstrapped) return;
    bootstrapped = true;
    shell.refreshUsage();
    shell.refreshTeams();
  });
  registerServiceWorker();
  await uploads; // the share-target hand-off and the upload shortcut need the manager to claim fp:upload
  if (launch.shareId) shareTargetHandoff(launch.shareId);
  if (launch.upload) uploadShortcut();
  announce(`${b.instance} loaded`);
}

main().catch((err) => {
  console.error('FileParcel failed to start', err);
  const root = document.getElementById('fp-app') || document.body;
  root.replaceChildren(h('div', { class: 'public-shell' }, h('main', { class: 'public-main' },
    h('div', { class: 'auth-card', attrs: { role: 'alert' } },
      h('h1', { text: 'FileParcel could not start' }),
      h('p', { class: 'muted', text: err instanceof Error ? err.message : String(err) }),
      h('button', { class: 'btn btn--primary', attrs: { type: 'button' }, on: { click: () => location.reload() }, text: 'Reload' })))));
});
