// @ts-check
/**
 * DOM helpers. The ONLY sanctioned way to build DOM in FileParcel (CSP + Trusted Types forbid HTML strings).
 *
 *   h('button', {class: 'btn', attrs: {type: 'button'}, on: {click: fn}, text: 'Save'})
 *   h('ul', null, items.map((it) => h('li', {text: it.name})))
 *   icon('folder', {size: 20, label: 'Folder'})
 *
 * Rules enforced here (throws in development-visible ways rather than silently allowing):
 *   - attribute names starting with "on" are rejected (inline handlers are TT sinks; use `on:`)
 *   - the `style` attribute is rejected (CSP style-src 'self'); use `style: {prop: value}` (CSSOM is allowed)
 *   - `javascript:` URLs are rejected for href/src/action/formaction/xlink:href
 * @module core/dom
 */

/** @typedef {Node | string | number | boolean | null | undefined | Child[]} Child */

/**
 * @typedef {Object} HProps
 * @property {string | string[] | Record<string, boolean | undefined | null>} [class] class names
 * @property {Record<string, string | number | boolean | null | undefined>} [attrs] attributes (true → "", false/null → omitted)
 * @property {Record<string, string | number | boolean | null | undefined>} [dataset] data-* attributes
 * @property {Record<string, EventListener | [EventListener, AddEventListenerOptions]>} [on] event listeners
 * @property {Record<string, string | number | null | undefined>} [style] CSS properties set via CSSOM (custom props allowed)
 * @property {string | number} [text] textContent (set before children are appended)
 * @property {(el: any) => void} [ref] called with the created element
 * @property {any} [value] DOM property (inputs)
 * @property {boolean} [checked] DOM property
 * @property {boolean} [disabled] DOM property
 * @property {boolean} [hidden] DOM property
 * @property {boolean} [selected] DOM property
 * @property {string} [id] shorthand attribute
 * @property {string} [type] shorthand attribute
 * @property {string} [href] shorthand attribute
 * @property {string} [title] shorthand attribute
 * @property {string} [role] shorthand attribute
 * @property {string} [name] shorthand attribute
 * @property {string} [for] shorthand attribute (htmlFor)
 * @property {string} [src] shorthand attribute
 * @property {string} [alt] shorthand attribute
 * @property {string} [placeholder] shorthand attribute
 * @property {number} [tabindex] shorthand attribute
 */

const URL_ATTRS = new Set(['href', 'src', 'action', 'formaction', 'xlink:href', 'poster', 'data']);
const PROPS = new Set(['value', 'checked', 'disabled', 'hidden', 'selected', 'indeterminate', 'multiple', 'readOnly', 'required']);
const RESERVED = new Set(['class', 'attrs', 'dataset', 'on', 'style', 'text', 'ref']);

/**
 * @param {string} name
 * @param {unknown} value
 */
function assertSafeAttr(name, value) {
  const n = name.toLowerCase();
  if (n.startsWith('on')) throw new TypeError(`dom: inline handler attribute "${name}" is forbidden; use {on: {…}}`);
  if (n === 'style') throw new TypeError('dom: style attribute is forbidden by CSP; use {style: {prop: value}}');
  if (n === 'srcdoc') throw new TypeError('dom: srcdoc is forbidden');
  if (URL_ATTRS.has(n) && typeof value === 'string' && /^\s*(javascript|vbscript|data:text\/html)/i.test(value)) {
    throw new TypeError(`dom: unsafe URL in ${name}`);
  }
}

/**
 * Set (or remove) one attribute safely.
 * @param {Element} el
 * @param {string} name
 * @param {string | number | boolean | null | undefined} value
 */
export function setAttr(el, name, value) {
  assertSafeAttr(name, value);
  if (value === false || value === null || value === undefined) el.removeAttribute(name);
  else el.setAttribute(name, value === true ? '' : String(value));
}

/**
 * @param {HProps['class']} c
 * @returns {string}
 */
function classString(c) {
  if (!c) return '';
  if (typeof c === 'string') return c;
  if (Array.isArray(c)) return c.filter(Boolean).join(' ');
  return Object.keys(c).filter((k) => c[k]).join(' ');
}

/**
 * Append children (flattening arrays, skipping null/undefined/false, stringifying primitives).
 * @param {Node} parent
 * @param {Child[]} children
 */
export function append(parent, ...children) {
  for (const c of children) {
    if (c === null || c === undefined || c === false || c === true) continue;
    if (Array.isArray(c)) append(parent, ...c);
    else if (c instanceof Node) parent.appendChild(c);
    else parent.appendChild(document.createTextNode(String(c)));
  }
  return parent;
}

/**
 * @param {Element} el
 * @param {HProps | null | undefined} props
 */
function applyProps(el, props) {
  if (!props) return;
  const cls = classString(props.class);
  if (cls) el.setAttribute('class', cls);
  if (props.attrs) for (const [k, v] of Object.entries(props.attrs)) setAttr(el, k, v);
  if (props.dataset && 'dataset' in el) {
    for (const [k, v] of Object.entries(props.dataset)) {
      if (v === null || v === undefined || v === false) delete /** @type {HTMLElement} */ (el).dataset[k];
      else /** @type {HTMLElement} */ (el).dataset[k] = v === true ? '' : String(v);
    }
  }
  if (props.style) {
    const st = /** @type {HTMLElement} */ (el).style;
    for (const [k, v] of Object.entries(props.style)) {
      if (v === null || v === undefined || v === '') st.removeProperty(k);
      else st.setProperty(k.startsWith('--') ? k : k.replace(/[A-Z]/g, (m) => '-' + m.toLowerCase()), String(v));
    }
  }
  if (props.on) {
    for (const [ev, fn] of Object.entries(props.on)) {
      if (Array.isArray(fn)) el.addEventListener(ev, fn[0], fn[1]);
      else if (typeof fn === 'function') el.addEventListener(ev, fn);
    }
  }
  for (const [k, v] of Object.entries(props)) {
    if (RESERVED.has(k) || PROPS.has(k)) continue;
    setAttr(el, k, /** @type {any} */ (v));
  }
  if (props.text !== undefined && props.text !== null) el.textContent = String(props.text);
}

/**
 * DOM properties (value, checked, …) are applied after children so that e.g. a <select>'s value can match an option.
 * @param {Element} el
 * @param {HProps | null | undefined} props
 */
function applyDomProps(el, props) {
  if (!props) return;
  for (const k of PROPS) {
    const v = /** @type {any} */ (props)[k];
    if (v !== undefined) /** @type {any} */ (el)[k] = v;
  }
}

/**
 * Create an HTML element.
 * @template {keyof HTMLElementTagNameMap} K
 * @param {K} tag
 * @param {HProps | null} [props]
 * @param {...Child} children
 * @returns {HTMLElementTagNameMap[K]}
 */
export function h(tag, props, ...children) {
  const el = document.createElement(tag);
  applyProps(el, props);
  append(el, ...children);
  applyDomProps(el, props);
  if (props && typeof props.ref === 'function') props.ref(el);
  return el;
}

const SVG_NS = 'http://www.w3.org/2000/svg';

/**
 * Create an SVG element. `attrs` are plain attributes (the same safety rules apply).
 * @param {string} tag
 * @param {Record<string, string | number | boolean | null | undefined>} [attrs]
 * @param {...Child} children
 * @returns {SVGElement}
 */
export function svg(tag, attrs, ...children) {
  const el = /** @type {SVGElement} */ (document.createElementNS(SVG_NS, tag));
  if (attrs) for (const [k, v] of Object.entries(attrs)) {
    if (k === 'class') el.setAttribute('class', String(v));
    else setAttr(el, k, v);
  }
  append(el, ...children);
  return el;
}

/**
 * Sprite icon: <svg class="icon"><use href="<asset>/icons/sprite.svg#name"></svg>.
 * Decorative (aria-hidden) unless `label` is given (then role=img + aria-label).
 * @param {string} name symbol id in icons/sprite.svg
 * @param {{size?: number, label?: string, class?: string}} [opts]
 * @returns {SVGElement}
 */
export function icon(name, opts = {}) {
  const size = opts.size || 20;
  const el = svg('svg', {
    class: opts.class ? `icon ${opts.class}` : 'icon',
    width: size,
    height: size,
    viewBox: '0 0 24 24',
    fill: 'none',
    stroke: 'currentColor',
    'stroke-width': 2,
    'stroke-linecap': 'round',
    'stroke-linejoin': 'round',
    focusable: 'false',
  });
  if (opts.size) {
    el.style.setProperty('width', `${size}px`);
    el.style.setProperty('height', `${size}px`);
  }
  if (opts.label) {
    el.setAttribute('role', 'img');
    el.setAttribute('aria-label', opts.label);
    append(el, svg('title', {}, opts.label));
  } else {
    el.setAttribute('aria-hidden', 'true');
  }
  append(el, svg('use', { href: `${asset('icons/sprite.svg')}#${name}` }));
  return el;
}

/**
 * Remove all children.
 * @template {Node} T
 * @param {T} el
 * @returns {T}
 */
export function clear(el) {
  while (el.firstChild) el.removeChild(el.firstChild);
  return el;
}

/**
 * Replace all children of `el`.
 * @param {Node} el
 * @param {...Child} children
 */
export function replace(el, ...children) {
  clear(el);
  return append(el, ...children);
}

/**
 * querySelector shorthand.
 * @template {Element} [E=HTMLElement]
 * @param {string} sel
 * @param {ParentNode} [root]
 * @returns {E | null}
 */
export function qs(sel, root = document) {
  return /** @type {E | null} */ (root.querySelector(sel));
}

/**
 * querySelectorAll shorthand returning an array.
 * @template {Element} [E=HTMLElement]
 * @param {string} sel
 * @param {ParentNode} [root]
 * @returns {E[]}
 */
export function qsa(sel, root = document) {
  return /** @type {E[]} */ (Array.from(root.querySelectorAll(sel)));
}

/**
 * @typedef {Object} BootUser
 * @property {string} id
 * @property {string} username
 * @property {string} [display_name]
 * @property {string} [email]
 * @property {string} [role] owner|admin|member|guest: the built-in base role (absent while the second factor is pending)
 * @property {string} [role_id] the role: owner|admin|member|guest|rol_…
 * @property {string} [role_name] the role's display name
 * @property {string[]} [permissions] permission names, catalog order
 * @property {boolean} [staff] can use at least one server permission
 * @property {string} [space_id] personal space ("" or absent: none)
 * @property {boolean} [must_change_password]
 * @property {Record<string, any>} [prefs]
 */

/**
 * @typedef {Object} Boot
 * @property {string} asset_base "/static/<hash>" (no trailing slash)
 * @property {string} instance instance name
 * @property {string} csrf CSRF token ("" when anonymous)
 * @property {BootUser | null} user
 * @property {string} keys_state uninitialized|locked|unlocked
 * @property {{passkeys?: boolean, links?: boolean, requests?: boolean, thumbnails?: boolean, mtls_self_service?: boolean,
 *   share_password_required?: boolean, directory?: boolean, tokens?: boolean, zip_legacy_encryption?: boolean,
 *   internet_links?: boolean, funnel_2fa?: boolean, maintenance?: boolean}} features the same map as GET /me features
 *   (pages.Features)
 * @property {string} rp_id WebAuthn RP ID
 * @property {string} version
 * @property {{default_theme: string, default_view: 'list' | 'grid'}} ui server-wide appearance defaults (ui.*)
 * @property {string} page
 * @property {Record<string, any>} data page-specific
 * @property {Record<string, number>} limits numeric limits for forms (e.g. zip_password_min; {} when none)
 * @property {string} ingress Tailscale ingress of the page: 'funnel' | 'serve' | '' (direct connection)
 */

/** @type {Boot | null} */
let bootCache = null;

/** Asset base derived from this module's URL (…/static/<hash>/js/core/dom.js → …/static/<hash>). */
function assetBaseFromModule() {
  try {
    const u = new URL('../../', import.meta.url);
    return u.pathname.replace(/\/$/, '');
  } catch {
    return '/static';
  }
}

/**
 * Parsed #fp-boot JSON (cached). Missing/invalid boot data yields safe defaults.
 * @returns {Boot}
 */
export function boot() {
  if (bootCache) return bootCache;
  /** @type {any} */
  let data = {};
  const el = document.getElementById('fp-boot');
  if (el && el.textContent) {
    try {
      data = JSON.parse(el.textContent) || {};
    } catch (err) {
      console.error('fp-boot: invalid JSON', err);
    }
  }
  if (typeof data !== 'object' || data === null) data = {};
  bootCache = {
    asset_base: typeof data.asset_base === 'string' && data.asset_base ? data.asset_base.replace(/\/$/, '') : assetBaseFromModule(),
    instance: data.instance || 'FileParcel',
    csrf: data.csrf || '',
    user: data.user || null,
    keys_state: data.keys_state || 'unlocked',
    features: Object.assign({ passkeys: false, links: true, requests: true }, data.features || {}),
    rp_id: data.rp_id || '',
    version: data.version || '',
    ui: {
      default_theme: typeof (data.ui || {}).default_theme === 'string' ? data.ui.default_theme : 'system',
      default_view: (data.ui || {}).default_view === 'grid' ? 'grid' : 'list',
    },
    page: data.page || document.documentElement.dataset.page || '',
    data: data.data && typeof data.data === 'object' ? data.data : {},
    limits: data.limits && typeof data.limits === 'object' ? data.limits : {},
    ingress: typeof data.ingress === 'string' ? data.ingress : '',
  };
  return bootCache;
}

/**
 * Absolute URL path of a static asset: asset('icons/logo.svg') → "/static/<hash>/icons/logo.svg".
 * @param {string} path relative to web/static
 */
export function asset(path) {
  return `${boot().asset_base}/${path.replace(/^\//, '')}`;
}

/** Build hash from the asset base ("/static/ab12cd" → "ab12cd"); "" when unknown. */
export function buildHash() {
  const m = /\/static\/([^/]+)$/.exec(boot().asset_base);
  return m ? m[1] : '';
}

let uid = 0;
/**
 * Unique DOM id.
 * @param {string} [prefix]
 */
export function uniqueId(prefix = 'fp') {
  uid += 1;
  return `${prefix}-${uid}`;
}

/**
 * Elements that can receive keyboard focus inside `root`, in DOM order.
 * @param {ParentNode} root
 * @returns {HTMLElement[]}
 */
export function focusable(root) {
  const sel = 'a[href], area[href], button:not([disabled]), input:not([disabled]):not([type="hidden"]), select:not([disabled]), textarea:not([disabled]), iframe, [tabindex]:not([tabindex="-1"]), [contenteditable="true"]';
  return qsa(sel, root).filter((el) => !el.hasAttribute('inert') && el.getClientRects().length > 0 && getComputedStyle(el).visibility !== 'hidden');
}

/**
 * Trap Tab/Shift+Tab focus within `root`. Returns a function that removes the trap.
 * @param {HTMLElement} root
 */
export function trapFocus(root) {
  /** @param {KeyboardEvent} e */
  const onKey = (e) => {
    if (e.key !== 'Tab') return;
    const items = focusable(root);
    if (items.length === 0) {
      e.preventDefault();
      return;
    }
    const first = items[0];
    const last = items[items.length - 1];
    const active = /** @type {HTMLElement | null} */ (document.activeElement);
    if (e.shiftKey && (active === first || !root.contains(active))) {
      e.preventDefault();
      last.focus();
    } else if (!e.shiftKey && (active === last || !root.contains(active))) {
      e.preventDefault();
      first.focus();
    }
  };
  root.addEventListener('keydown', onKey);
  return () => root.removeEventListener('keydown', onKey);
}

/**
 * Where transient UI (menus, toasts, live regions) must be attached so it stays interactive: the top-most open
 * modal <dialog> (showModal() makes everything outside it inert), or <body> when no modal is open.
 * Dialogs are appended to <body> when opened, so DOM order equals stacking order.
 * @param {Element | null} [except] a dialog to ignore (e.g. one that is closing)
 * @returns {HTMLElement}
 */
export function overlayHost(except = null) {
  const open = qsa('dialog[open]').filter((d) => {
    if (d === except) return false;
    try {
      return d.matches(':modal');
    } catch {
      return true; // :modal unsupported → treat every open dialog as modal (all of ours are)
    }
  });
  return open.length ? open[open.length - 1] : document.body;
}

/**
 * Announce a message to screen readers via a shared live region (kept inside the top-most modal dialog, because
 * live regions in inert content are not announced).
 * @param {string} message
 * @param {'polite' | 'assertive'} [politeness]
 */
export function announce(message, politeness = 'polite') {
  const host = overlayHost();
  let region = /** @type {HTMLElement | null} */ (host.querySelector(`:scope > [data-live="${politeness}"]`));
  if (!region) {
    region = h('div', { class: 'sr-only', dataset: { live: politeness }, attrs: { 'aria-live': politeness, 'aria-atomic': 'true' } });
    host.appendChild(region);
  }
  region.textContent = '';
  const r = region;
  setTimeout(() => { r.textContent = message; }, 30);
}

/**
 * Policy names allowed by the `trusted-types` directives of a CSP header value (diagnostics and tests; the app itself
 * no longer sniffs its CSP — the server always sends `trusted-types fp`, §9.2).
 * `restricted` is false when no directive restricts names; `allows(name)` checks a name against every restricting
 * policy ('*' = any). A header may carry several comma-separated policies; all of them apply.
 * @param {string} header
 * @returns {{restricted: boolean, allows: (name: string) => boolean, required: boolean}}
 */
export function parseTrustedTypesCSP(header) {
  /** @type {string[][]} */
  const lists = [];
  let required = false;
  for (const policy of header.split(',')) {
    for (const directive of policy.split(';')) {
      const [name, ...values] = directive.trim().split(/\s+/);
      const n = (name || '').toLowerCase();
      if (n === 'trusted-types') lists.push(values);
      else if (n === 'require-trusted-types-for' && values.includes("'script'")) required = true;
    }
  }
  return {
    restricted: lists.length > 0,
    required,
    allows: (policyName) => lists.every((vals) => vals.includes('*') || (vals.includes(policyName) && !vals.includes("'none'"))),
  };
}

/**
 * The app's single Trusted Types policy "fp" (CSP `require-trusted-types-for 'script'; trusted-types fp`, §9.2).
 * undefined = not created yet, false = Trusted Types unsupported (plain strings are accepted by the sinks),
 * null = the browser refused to create it (a misconfigured CSP) — then no worker is created and callers fall back.
 * @type {any}
 */
let ttPolicyCache;

/**
 * Whether `url` may be used as a script URL: same-origin and either exactly "/sw.js" (query allowed) or a path under
 * the hashed asset base ("/static/<hash>/…"). Everything else is rejected — the policy never creates HTML or script.
 * @param {string} input
 * @returns {string} the normalised absolute URL
 */
export function checkScriptURL(input) {
  const u = new URL(String(input), location.href);
  if (u.origin !== location.origin) throw new TypeError('fp policy: cross-origin script URL');
  if (u.username || u.password || u.hash) throw new TypeError('fp policy: unexpected URL parts');
  const base = `${boot().asset_base}/`;
  if (u.pathname === '/sw.js') return u.href;
  if (base.startsWith('/static/') && u.pathname.startsWith(base) && !u.pathname.includes('/../') && !u.search) return u.href;
  throw new TypeError('fp policy: script URL outside the asset base');
}

/** @returns {any} the "fp" policy, false (no Trusted Types) or null (refused) */
function ttPolicy() {
  if (ttPolicyCache !== undefined) return ttPolicyCache;
  const tt = /** @type {any} */ (globalThis).trustedTypes;
  if (!tt || typeof tt.createPolicy !== 'function') {
    ttPolicyCache = false;
    return ttPolicyCache;
  }
  try {
    ttPolicyCache = tt.createPolicy('fp', { createScriptURL: checkScriptURL });
  } catch (err) {
    console.warn('Trusted Types policy "fp" is not allowed here; workers are disabled.', err);
    ttPolicyCache = null;
  }
  return ttPolicyCache;
}

/**
 * Script URL for `new Worker()` / `navigator.serviceWorker.register()` that satisfies Trusted Types.
 *
 * Creates the "fp" policy on first use (createScriptURL only; it accepts same-origin "/sw.js" and URLs under the
 * hashed asset base and rejects everything else). Resolves to a TrustedScriptURL, to the checked plain string when the
 * browser has no Trusted Types, or to **null** when the URL is not allowed (or the policy could not be created) —
 * callers must then skip the worker and use a fallback. Async for API stability (§13.3 contract notes); it performs
 * no request.
 * @param {string} url
 * @returns {Promise<any | null>}
 */
export async function scriptURL(url) {
  const p = ttPolicy();
  try {
    if (p === false) return checkScriptURL(url);
    if (!p) return null;
    return p.createScriptURL(url);
  } catch (err) {
    console.warn('scriptURL rejected', url, err);
    return null;
  }
}

/**
 * Trigger a download of client-generated data (e.g. recovery codes). Uses a blob: URL (§13.1).
 * @param {string} filename
 * @param {BlobPart | Blob} content
 * @param {string} [type]
 */
export function downloadBlob(filename, content, type = 'text/plain;charset=utf-8') {
  const blob = content instanceof Blob ? content : new Blob([content], { type });
  const url = URL.createObjectURL(blob);
  const a = h('a', { attrs: { href: url, download: filename }, class: 'hidden' });
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 10_000);
}

/** Page background per scheme (tokens.css --fp-bg) for the browser bar; the templates render the same. */
const THEME_COLOR = { light: '#fbf9f5', dark: '#101419' };

/**
 * Apply a theme to <html data-theme>. "system" follows the OS. The theme-color metas (one per
 * prefers-color-scheme) follow too: a forced theme gives both its colour, so the browser bar
 * matches the page rather than the OS.
 * @param {string} theme light|dark|system
 */
export function applyTheme(theme) {
  const t = theme === 'light' || theme === 'dark' ? theme : 'system';
  document.documentElement.dataset.theme = t;
  for (const m of document.querySelectorAll('meta[name="theme-color"]')) {
    const own = /dark/.test(m.getAttribute('media') || '') ? 'dark' : 'light';
    m.setAttribute('content', THEME_COLOR[t === 'system' ? own : t]);
  }
}

/**
 * Apply density to <html data-density>.
 * @param {string} density comfortable|compact
 */
export function applyDensity(density) {
  if (density === 'compact') document.documentElement.dataset.density = 'compact';
  else delete document.documentElement.dataset.density;
}

/** @returns {boolean} true when the platform uses ⌘ as the primary modifier. */
export function isMac() {
  const p = /** @type {any} */ (navigator).userAgentData?.platform || navigator.platform || navigator.userAgent;
  return /mac|iphone|ipad|ipod/i.test(p);
}

/** @returns {boolean} true when the viewport is in the mobile layout (< 640 px). */
export function isMobile() {
  return window.matchMedia('(max-width: 639px)').matches;
}
