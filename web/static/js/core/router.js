// @ts-check
/**
 * History-API router for the SPA shell.
 *
 *   start(routes, outlet, {notFound, guard});
 *   navigate('/files/nod_x');                 // pushState + render
 *   navigate('/search?q=cat', {replace: true, render: false});   // update the URL only
 *   el.addEventListener('click', link('/trash'));
 *   current() → {path, params, query, route}
 *   const o = pushOverlay(closePreview, {url: '?preview=…'}); … o.done();   // Back button closes the overlay
 *   const off = dismissOnNavigate(close); … off();            // navigating away closes the modal (no history entry)
 *
 * Page modules export `title` and `mount(root, ctx)`; `ctx = {params, query, me, signal, url}`. `mount` may be async
 * and may return a cleanup function; `ctx.signal` aborts when the user navigates away (pass it to api calls).
 * Same-origin <a href> clicks whose path matches a route are intercepted automatically (opt out with
 * `data-native`, `download` or a target).
 * @module core/router
 */
import { h, clear, announce, boot } from './dom.js';
import { signal, session } from './store.js';

/**
 * @typedef {Object} PageContext
 * @property {Record<string, string>} params decoded path params
 * @property {Record<string, string>} query query string (first value per key)
 * @property {import('./store.js').Me | null} me current /me payload
 * @property {AbortSignal} signal aborted on navigation away
 * @property {URL} url full URL
 */

/**
 * @typedef {Object} PageModule
 * @property {string} [title]
 * @property {(root: HTMLElement, ctx: PageContext) => (void | (() => void) | Promise<void | (() => void)>)} mount
 */

/** @typedef {() => Promise<PageModule>} Loader */

/**
 * @typedef {Object} Route
 * @property {string} path pattern: "/files", "/files/:nodeId", "/admin/settings/:section", "*"
 * @property {Loader} load lazy page module import
 * @property {string} [nav] id of the navigation item to highlight
 * @property {boolean} [admin] requires owner/admin role
 * @property {string} [title] fallback title before the module loads
 */

/**
 * @typedef {Object} RouteMatch
 * @property {string} path
 * @property {Record<string, string>} params
 * @property {Record<string, string>} query
 * @property {Route | null} route
 */

/** Current route (reactive). @type {import('./store.js').Signal<RouteMatch>} */
export const route = signal(/** @type {RouteMatch} */ ({ path: location.pathname, params: {}, query: {}, route: null }));

/** Current page title (reactive; nav shows it in the mobile top bar). */
export const pageTitle = signal('');

/** @type {{route: Route, re: RegExp, keys: string[]}[]} */
let compiled = [];
/** @type {HTMLElement | null} */
let outletEl = null;
/** @type {{notFound?: Loader, guard?: (r: Route, m: RouteMatch) => Loader | null | undefined}} */
let options = {};
let navId = 0;
/** @type {AbortController | null} */
let controller = null;
/** @type {(() => void) | null} */
let cleanup = null;
let started = false;
/** @type {Set<(to: string) => boolean | Promise<boolean>>} */
const beforeHooks = new Set();

/** @param {string} pattern */
function compile(pattern) {
  if (pattern === '*') return { re: /^.*$/, keys: [] };
  /** @type {string[]} */
  const keys = [];
  const src = pattern
    .replace(/\/+$/, '')
    .split('/')
    .map((seg) => {
      if (seg.startsWith(':')) {
        keys.push(seg.slice(1));
        return '([^/]+)';
      }
      if (seg === '*') {
        keys.push('rest');
        return '(.*)';
      }
      return seg.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    })
    .join('/');
  return { re: new RegExp(`^${src || ''}/?$`), keys };
}

/**
 * Find the route for a pathname.
 * @param {string} pathname
 * @returns {{route: Route, params: Record<string, string>} | null}
 */
export function match(pathname) {
  for (const c of compiled) {
    if (c.route.path === '*') continue;
    const m = c.re.exec(pathname);
    if (!m) continue;
    /** @type {Record<string, string>} */
    const params = {};
    c.keys.forEach((k, i) => {
      try {
        params[k] = decodeURIComponent(m[i + 1]);
      } catch {
        params[k] = m[i + 1];
      }
    });
    return { route: c.route, params };
  }
  return null;
}

/** @param {URLSearchParams} sp */
function queryObject(sp) {
  /** @type {Record<string, string>} */
  const q = {};
  for (const [k, v] of sp) if (!(k in q)) q[k] = v;
  return q;
}

/** @returns {RouteMatch} */
export function current() {
  return route.peek();
}

/**
 * Register a hook called before every navigation; return false (or a Promise of false) to cancel.
 * @param {(to: string) => boolean | Promise<boolean>} fn
 * @returns {() => void}
 */
export function beforeNavigate(fn) {
  beforeHooks.add(fn);
  return () => beforeHooks.delete(fn);
}

/**
 * Set the document title (and the mobile top-bar title).
 * @param {string} title
 */
export function setTitle(title) {
  pageTitle.value = title;
  const inst = boot().instance || 'FileParcel';
  document.title = title ? `${title} · ${inst}` : inst;
}

/**
 * Navigate to an in-app path.
 * @param {string} to path (+ query/hash)
 * @param {{replace?: boolean, render?: boolean, state?: any}} [opts]
 */
export async function navigate(to, opts = {}) {
  const url = new URL(to, location.href);
  if (url.origin !== location.origin) {
    location.assign(url.href);
    return;
  }
  // Paths outside the SPA (/login, /trust, /s/…, downloads) always get a real page load.
  if (!started || !match(url.pathname)) {
    location.assign(url.href);
    return;
  }
  for (const fn of beforeHooks) {
    if ((await fn(url.pathname + url.search)) === false) return;
  }
  saveScroll();
  const target = url.pathname + url.search + url.hash;
  const state = { ...(opts.state || {}), key: Math.random().toString(36).slice(2) };
  if (opts.replace) history.replaceState(state, '', target);
  else history.pushState(state, '', target);
  if (opts.render === false) {
    const m = match(url.pathname);
    route.value = { path: url.pathname, params: m ? m.params : {}, query: queryObject(url.searchParams), route: m ? m.route : null };
    return;
  }
  await render({ scroll: opts.replace ? 'keep' : 'top', focus: true });
}

// ---------------------------------------------------------------------------------------------------------------
// Overlays closed by the Back button (preview, details sheet): each pushes a history entry for the same page (or a
// variant URL such as ?preview=<id>); popping it closes the overlay instead of re-rendering the page.
// ---------------------------------------------------------------------------------------------------------------

/** @type {{key: string, close: () => void}[]} */
const overlays = [];
let ignorePops = 0;

/**
 * Register an overlay that the browser/phone Back button should close. Pushes a history entry (optionally with a
 * different URL of the same page, e.g. `?preview=<id>`). Returns `done()`, to call when the overlay closes by
 * itself (Esc, × button): it removes the entry again with history.back().
 * @param {() => void} close called when the user navigates back
 * @param {{url?: string}} [opts]
 * @returns {{done: () => void, replaceURL: (url: string) => void}}
 */
export function pushOverlay(close, opts = {}) {
  const key = Math.random().toString(36).slice(2);
  history.pushState({ ...(history.state || {}), overlay: key }, '', opts.url || location.href);
  overlays.push({ key, close });
  return {
    done() {
      const i = overlays.findIndex((o) => o.key === key);
      if (i < 0) return;
      overlays.splice(i, 1);
      if (history.state && history.state.overlay === key) {
        ignorePops += 1;
        history.back();
      }
    },
    /** Update the URL of the overlay entry (e.g. the previewed file changed). @param {string} url */
    replaceURL(url) {
      if (history.state && history.state.overlay === key) history.replaceState(history.state, '', url);
    },
  };
}

/**
 * popstate while overlays are open: close the top-most overlay whose entry was left; true when handled.
 * @returns {boolean}
 */
function popOverlay() {
  if (ignorePops > 0) {
    ignorePops -= 1;
    return true;
  }
  if (!overlays.length) return false;
  const cur = history.state && history.state.overlay;
  let handled = false;
  while (overlays.length && overlays[overlays.length - 1].key !== cur) {
    const o = /** @type {{key: string, close: () => void}} */ (overlays.pop());
    handled = true;
    try { o.close(); } catch (err) { console.error(err); }
  }
  return handled;
}

/** @type {Set<() => void>} */
const modals = new Set();

/**
 * Register a modal (dialog, sheet) so that navigating away closes it. Unlike pushOverlay() this pushes no history
 * entry, so Escape and the Back button keep their meaning. Returns an unregister function for the modal's own close.
 * @param {() => void} close
 * @returns {() => void}
 */
export function dismissOnNavigate(close) {
  modals.add(close);
  return () => modals.delete(close);
}

/** Close every open overlay and modal: the page they belong to is going away. */
function closeOverlays() {
  // pop first: close() calls done(), which must not rewind the entry we are navigating away from
  while (overlays.length) {
    const o = /** @type {{key: string, close: () => void}} */ (overlays.pop());
    try { o.close(); } catch (err) { console.error('overlay close failed', err); }
  }
  for (const close of [...modals]) {
    modals.delete(close);
    try { close(); } catch (err) { console.error('modal close failed', err); }
  }
  // belt and braces for anything that opened a <dialog> without registering (the registered ones are gone by now)
  for (const d of document.querySelectorAll('dialog[open]')) /** @type {HTMLDialogElement} */ (d).close();
}

/**
 * Click handler that navigates in-app (respects modifier keys / middle click).
 * @param {string} href
 * @returns {(e: MouseEvent) => void}
 */
export function link(href) {
  return (e) => {
    if (e.defaultPrevented || e.button !== 0 || e.metaKey || e.ctrlKey || e.shiftKey || e.altKey) return;
    e.preventDefault();
    navigate(href);
  };
}

/** Re-render the current route (e.g. after a role change). */
export function reload() {
  return render({ scroll: 'keep', focus: false });
}

function saveScroll() {
  try {
    history.replaceState({ ...(history.state || {}), scroll: window.scrollY }, '');
  } catch { /* ignore */ }
}

/** @param {MouseEvent} e */
function onDocumentClick(e) {
  if (e.defaultPrevented || e.button !== 0 || e.metaKey || e.ctrlKey || e.shiftKey || e.altKey) return;
  const target = /** @type {Element | null} */ (e.target instanceof Element ? e.target : null);
  const a = /** @type {HTMLAnchorElement | null} */ (target?.closest('a[href]') || null);
  if (!a) return;
  if ((a.target && a.target !== '_self') || a.hasAttribute('download') || a.hasAttribute('data-native')) return;
  const url = new URL(a.href, location.href);
  if (url.origin !== location.origin || !match(url.pathname)) return;
  e.preventDefault();
  if (url.pathname === location.pathname && url.search === location.search && url.hash) {
    history.pushState(history.state, '', url.hash);
    document.getElementById(url.hash.slice(1))?.scrollIntoView();
    return;
  }
  navigate(url.pathname + url.search + url.hash);
}

/**
 * @param {{scroll: 'top' | 'keep' | 'restore', focus: boolean}} how
 */
async function render(how) {
  if (!outletEl) return;
  const id = ++navId;
  const url = new URL(location.href);
  const m = match(url.pathname);
  /** @type {RouteMatch} */
  const rm = { path: url.pathname, params: m ? m.params : {}, query: queryObject(url.searchParams), route: m ? m.route : null };

  if (controller) controller.abort();
  closeOverlays(); // the page is going away: close its overlays and modals with it
  if (cleanup) {
    try { cleanup(); } catch (err) { console.error('page cleanup failed', err); }
    cleanup = null;
  }
  const ctrl = new AbortController();
  controller = ctrl;
  route.value = rm;

  /** @type {Loader | undefined} */
  let loader = m ? m.route.load : options.notFound;
  if (m && options.guard) loader = options.guard(m.route, rm) || loader;
  if (!loader) return;
  if (m?.route.title) setTitle(m.route.title);

  const outlet = outletEl;
  outlet.setAttribute('aria-busy', 'true');
  /** @type {PageModule} */
  let mod;
  try {
    mod = await loader();
  } catch (err) {
    if (id !== navId) return;
    console.error('page load failed', err);
    showError(outlet, 'This page could not be loaded', 'Check your connection and try again. If you just updated FileParcel, reload the page.');
    return;
  }
  if (id !== navId) return;

  clear(outlet);
  delete outlet.dataset.wide;
  const root = h('div', { class: 'page', dataset: { route: m ? m.route.path : '*' } });
  outlet.appendChild(root);
  setTitle(mod.title || m?.route.title || '');

  /** @type {PageContext} */
  const ctx = { params: rm.params, query: rm.query, me: session.peek(), signal: ctrl.signal, url };
  try {
    const c = await mod.mount(root, ctx);
    if (id !== navId || ctrl.signal.aborted) {
      if (typeof c === 'function') c();
      return;
    }
    cleanup = typeof c === 'function' ? c : null;
  } catch (err) {
    if (id !== navId || /** @type {any} */ (err)?.code === 'aborted') return;
    console.error('page mount failed', err);
    showError(root, 'Something went wrong', /** @type {any} */ (err)?.message || 'The page failed to render.');
  } finally {
    if (id === navId) outlet.removeAttribute('aria-busy');
  }

  if (how.scroll === 'top') window.scrollTo(0, 0);
  else if (how.scroll === 'restore') {
    const y = history.state && typeof history.state.scroll === 'number' ? history.state.scroll : 0;
    requestAnimationFrame(() => window.scrollTo(0, y));
  }
  if (how.focus) {
    const heading = /** @type {HTMLElement | null} */ (root.querySelector('h1'));
    if (heading) {
      if (!heading.hasAttribute('tabindex')) heading.setAttribute('tabindex', '-1');
      heading.focus({ preventScroll: true });
    }
    announce(document.title);
  }
}

/**
 * Minimal inline error block (kept dependency-free so the router works even if components fail to load).
 * @param {HTMLElement} el
 * @param {string} title
 * @param {string} text
 */
function showError(el, title, text) {
  clear(el);
  el.removeAttribute('aria-busy');
  el.appendChild(
    h('div', { class: 'empty', attrs: { role: 'alert' } },
      h('div', { class: 'empty-title', text: title }),
      h('p', { class: 'empty-text', text }),
      h('button', { class: 'btn btn--secondary', attrs: { type: 'button' }, on: { click: () => location.reload() }, text: 'Reload' })),
  );
}

/**
 * Start routing: renders the current URL into `outlet` and listens for navigation.
 * @param {Route[]} routes
 * @param {HTMLElement} outlet
 * @param {{notFound?: Loader, guard?: (r: Route, m: RouteMatch) => Loader | null | undefined}} [opts]
 */
export function start(routes, outlet, opts = {}) {
  compiled = routes.map((r) => ({ route: r, ...compile(r.path) }));
  const star = routes.find((r) => r.path === '*');
  options = { notFound: star ? star.load : undefined, ...opts };
  outletEl = outlet;
  if (!started) {
    started = true;
    if ('scrollRestoration' in history) history.scrollRestoration = 'manual';
    window.addEventListener('popstate', () => {
      if (popOverlay()) return;
      render({ scroll: 'restore', focus: true });
    });
    document.addEventListener('click', onDocumentClick);
  }
  return render({ scroll: 'keep', focus: false });
}
