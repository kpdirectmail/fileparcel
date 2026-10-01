// @ts-check
/**
 * Shared helpers for the server-rendered public pages (login, invite, setup, unlock, trust, share, error).
 * Templates provide <main id="fp-root" class="public-main"> (with a loading spinner) and
 * <div id="fp-header-actions"> in the header. Owned by unit J2.
 *
 *   initAppearance()            theme from localStorage + the theme toggle in the header
 *   publicRoot()                the <main> with the loading placeholder removed
 *   authCard({title, subtitle, body, footer, size})
 *   alertBox(kind, content)     inline alert
 *   authState()                 GET /api/v1/auth/state (cached; {} on failure)
 *   nextPath(fallback)          safe same-origin ?next= target
 * @module public/common
 */
import { h, icon, asset, boot, applyTheme, replace } from '../core/dom.js';
import { api, ApiError } from '../core/api.js';

/** Apply the locally chosen theme (the server already set <html data-theme> from ui.default_theme / prefs). */
export function initAppearance() {
  try {
    const t = localStorage.getItem('fp:theme');
    if (t) applyTheme(t);
  } catch { /* storage unavailable */ }
  const slot = document.getElementById('fp-header-actions');
  if (slot && !slot.childElementCount) slot.appendChild(themeToggle());
}

/** Small button cycling system → light → dark. */
export function themeToggle() {
  const order = ['system', 'light', 'dark'];
  const icons = { system: 'monitor', light: 'sun', dark: 'moon' };
  const btn = h('button', { class: 'icon-btn', attrs: { type: 'button' } });
  const sync = () => {
    const cur = document.documentElement.dataset.theme || 'system';
    replace(btn, icon(/** @type {any} */ (icons)[cur] || 'monitor'));
    btn.setAttribute('aria-label', `Theme: ${cur}. Change theme`);
    btn.title = `Theme: ${cur}`;
  };
  btn.addEventListener('click', () => {
    const cur = document.documentElement.dataset.theme || 'system';
    const next = order[(order.indexOf(cur) + 1) % order.length];
    applyTheme(next);
    try { localStorage.setItem('fp:theme', next); } catch { /* ignore */ }
    sync();
  });
  sync();
  return btn;
}

/**
 * The page root with the loading placeholder removed.
 * @returns {HTMLElement}
 */
export function publicRoot() {
  const root = document.getElementById('fp-root') || document.body.appendChild(h('main', { id: 'fp-root', class: 'public-main' }));
  replace(root);
  root.removeAttribute('aria-busy');
  return root;
}

/**
 * Card with the logo, a title and optional subtitle.
 * @param {{title: string, subtitle?: import('../core/dom.js').Child, body?: import('../core/dom.js').Child,
 *   footer?: import('../core/dom.js').Child, size?: 'md' | 'lg', logo?: boolean, icon?: string, class?: string}} opts
 *   icon: show a sprite icon in a tinted circle instead of the logo
 * @returns {HTMLElement}
 */
export function authCard(opts) {
  let mark = null;
  if (opts.icon) mark = h('span', { class: 'auth-card-icon', attrs: { 'aria-hidden': 'true' } }, icon(opts.icon, { size: 28 }));
  else if (opts.logo !== false) mark = h('img', { class: 'brand-logo', src: asset('icons/logo.svg'), alt: '', attrs: { width: 52, height: 52 } });
  return h('section', { class: ['auth-card', opts.class || ''], dataset: { size: opts.size === 'lg' ? 'lg' : null }, attrs: { 'aria-labelledby': 'fp-card-title' } },
    h('div', { class: 'auth-card-head' },
      mark,
      h('h1', { id: 'fp-card-title', attrs: { tabindex: '-1' }, text: opts.title }),
      opts.subtitle ? h('p', null, opts.subtitle) : null),
    opts.body,
    opts.footer ? h('div', { class: 'auth-links' }, opts.footer) : null);
}

/**
 * Safe post-login redirect target from ?next= (same-origin path only).
 * The value is resolved with the URL parser — the same one location.assign() uses — and the resulting origin is
 * compared, because string prefix checks miss parser normalisation (e.g. "/\t/evil.example" loses the tab and
 * becomes the protocol-relative "//evil.example"). The origin check alone is not enough either: dot-segment
 * removal keeps the empty segment after it, so "/.//evil.example" (or "/..//", "/%2e//", "/./\evil.example")
 * resolves to the same origin with the pathname "//evil.example", which a browser reads as protocol-relative once
 * it is returned as a bare path. Such pathnames are rejected, and the result is the absolute same-origin URL, so
 * it can never be read relative to anything else.
 * @param {string} [fallback]
 */
export function nextPath(fallback = '/files') {
  const n = new URLSearchParams(location.search).get('next') || '';
  if (!n.startsWith('/')) return fallback;
  /** @type {URL} */
  let u;
  try {
    u = new URL(n, location.origin);
  } catch {
    return fallback;
  }
  if (u.origin !== location.origin || u.pathname.startsWith('//') ||
    /^\/(login|setup|unlock|invite|api)(\/|$)/.test(u.pathname)) return fallback;
  return u.href;
}

/**
 * Alert box.
 * @param {'info' | 'success' | 'warning' | 'danger'} kind
 * @param {import('../core/dom.js').Child} content
 * @param {string} [title] bold first line
 */
export function alertBox(kind, content, title) {
  const ic = { info: 'info', success: 'check-circle', warning: 'alert-triangle', danger: 'alert-circle' }[kind];
  return h('div', { class: `alert alert--${kind}`, attrs: { role: kind === 'danger' ? 'alert' : 'status' } },
    icon(ic), h('div', { class: 'alert-body' }, title ? h('strong', { text: title }) : null, h('span', null, content)));
}

/** Instance name from boot data. */
export function instanceName() {
  return boot().instance || 'FileParcel';
}

/** Focus the card heading (after swapping steps) for screen readers. */
export function focusHeading() {
  /** @type {HTMLElement | null} */ (document.getElementById('fp-card-title'))?.focus({ preventScroll: true });
}

/**
 * @typedef {Object} AuthState
 * @property {string} [instance]
 * @property {boolean} [setup_needed]
 * @property {boolean} [passkeys]
 * @property {string} [rp_id]
 * @property {string} [keys_state] uninitialized|locked|unlocked
 * @property {string} [login_message]
 * @property {number} [password_min] auth.password_min (see password-strength.js passwordMin())
 */

/** @type {Promise<AuthState> | null} */
let statePromise = null;

/**
 * GET /api/v1/auth/state (public). Cached for the page lifetime; resolves {} when unavailable.
 * @returns {Promise<AuthState>}
 */
export function authState() {
  if (!statePromise) {
    statePromise = api.get('/auth/state', { handle: false }).then((s) => (s && typeof s === 'object' ? s : {})).catch(() => ({}));
  }
  return statePromise;
}

/**
 * Human-readable message for a rate-limit (429) error, using the Retry-After header when the server sent one.
 * @param {unknown} err
 * @param {string} [what] e.g. "sign-in attempts"
 */
export function rateLimitMessage(err, what = 'attempts') {
  const d = err instanceof ApiError ? err.details?.error : null;
  const secs = Number((err instanceof ApiError && err.retryAfter) || d?.retry_after || d?.retry_after_seconds || 0);
  const n = secs >= 90 ? Math.ceil(secs / 60) : Math.ceil(secs);
  const wait = secs > 0 ? `${n} ${secs >= 90 ? 'minute' : 'second'}${n === 1 ? '' : 's'}` : 'a minute';
  return `Too many ${what}. Please wait ${wait} and try again.`;
}

/**
 * True for requests cancelled with an AbortController.
 * @param {unknown} err
 */
export function isAborted(err) {
  return err instanceof ApiError && err.aborted;
}
