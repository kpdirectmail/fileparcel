// @ts-check
/**
 * App shell & navigation (§13.5): collapsible sidebar (desktop ≥ 1024 px), icon rail + slide-over drawer (tablet),
 * top app bar + bottom tab bar with a centre Upload FAB and a "More" sheet (mobile < 640 px).
 *
 *   const shell = renderShell(document.getElementById('fp-app'));  // → {outlet, banners, refreshUsage()}
 *   triggerUpload('files' | 'folder' | 'new-folder' | 'new-request')
 *
 * Upload hooks: the split button / FAB call triggerUpload(action). For 'files' and 'folder' the shell opens its hidden
 * file pickers synchronously (inside the user gesture) and then dispatches a cancelable CustomEvent on `document`:
 *   'fp:upload'  detail = {action, files?: File[], folderId?: string}
 * A handler (js/upload/*, the files page) calls event.preventDefault() to claim it. If nobody claims it, the shell's
 * fallback runs (basic uploader for files, prompt for new folder, navigation to /requests for new requests).
 * Pages set `currentFolder.value = {id, name}` so uploads land in the folder being viewed.
 *
 * Permission-driven navigation (DESIGN §13.5): an item is shown when the route table allows its link for the signed-in
 * account (routes.js routeAllowed(): built-in admin, staff or a permission of the role), so the sidebar, the rail,
 * the "More" sheet and the command palette offer exactly the pages the route guard lets through. The Admin group
 * appears as soon as one of its items is visible — for a delegate, only their own areas.
 * @module nav
 */
import { h, icon, clear, replace, boot, asset, applyTheme, isMobile } from './core/dom.js';
import { api, itemsOf, ApiError, errorMessage } from './core/api.js';
import { navigate, route, pageTitle, setTitle } from './core/router.js';
import { session, isFullSession, can, hasSpace, jobs, activeJobCount, effect, signal, persisted, events } from './core/store.js';
import { bytes, pct, initials } from './core/format.js';
import { can as canNode } from './core/nodes.js';
import { pathAllowed } from './routes.js';
import { menu } from './components/menu.js';
import { sheet, sheetList } from './components/sheet.js';
import { toast } from './components/toast.js';
import { dialog } from './components/dialog.js';
import { openPalette, showShortcuts } from './components/palette.js';

/**
 * @typedef {Object} NavItem
 * @property {string} id
 * @property {string} label
 * @property {string} icon
 * @property {string} href an exact route path: the route's guard (routes.js) decides whether the item shows
 * @property {string} [feature] boot.features flag that must be true
 * @property {boolean} [needsSpace] hidden without a personal space (roles based on Guest)
 * @property {string} [keywords] extra words the command palette matches
 */

/**
 * @typedef {Object} NavGroup
 * @property {string} id
 * @property {string} [label]
 * @property {NavItem[]} items
 */

/**
 * Folder currently shown by the files page (upload destination); `perm` is the user's permission there
 * (none|view|edit|manage|owner) so the upload UI can refuse read-only folders up front.
 * @type {import('./core/store.js').Signal<{id: string, name?: string, perm?: string | number} | null>}
 */
export const currentFolder = signal(/** @type {{id: string, name?: string, perm?: string | number} | null} */ (null));

/** Optional nav highlight override (e.g. 'team:<spaceId>' while browsing a team folder). */
export const navOverride = signal('');

/** Team (group) spaces for the sidebar. @type {import('./core/store.js').Signal<{id: string, name: string, href: string}[]>} */
export const teamFolders = signal(/** @type {{id: string, name: string, href: string}[]} */ ([]));

/**
 * Whether this user has anywhere to upload to: a space they may write to, or a folder shared with them with at
 * least "edit". Accounts without a personal space (roles based on Guest) may have nowhere (GET /spaces → []), and
 * offering them Upload only walks them through a file picker into a destination dialog that says "No folders are
 * available". It starts from hasSpace() so the button never flickers for an ordinary user while /spaces is in flight
 * (refreshTeams() settles it either way).
 */
export const canUpload = signal(hasSpace());

/** The instance name as this session shows it (a signal, so an admin rename applies without a reload). */
export const instanceName = signal(boot().instance || 'FileParcel');

/**
 * Apply a new instance name to the open session — /admin/settings/general promises that changes apply immediately
 * unless they are marked "Restart required", and ui.instance_name is not. Updates the cached boot data (read by
 * setTitle(), the About dialog and the help menu), the shell brand and the current document title.
 * @param {string} name
 */
export function setInstanceName(name) {
  const v = String(name || '').trim();
  if (!v || v === instanceName.peek()) return;
  boot().instance = v;
  instanceName.value = v;
  setTitle(pageTitle.peek()); // re-compose "<page> · <instance>"
}

/** @type {NavGroup[]} */
export const NAV = [
  {
    id: 'workspace',
    label: 'Workspace',
    items: [
      { id: 'files', label: 'My files', icon: 'folder', href: '/files', needsSpace: true },
      { id: 'shared', label: 'Shared with me', icon: 'folder-shared', href: '/shared' },
      { id: 'starred', label: 'Starred', icon: 'star', href: '/starred' },
      { id: 'recent', label: 'Recent', icon: 'clock', href: '/recent' },
    ],
  },
  {
    id: 'sharing',
    label: 'Sharing',
    items: [
      { id: 'links', label: 'My links', icon: 'link', href: '/links', feature: 'links' },
      { id: 'requests', label: 'File requests', icon: 'inbox', href: '/requests', feature: 'requests' },
    ],
  },
  {
    id: 'more',
    items: [
      { id: 'trash', label: 'Trash', icon: 'trash', href: '/trash', needsSpace: true },
      { id: 'activity', label: 'Activity', icon: 'activity', href: '/activity' },
    ],
  },
  {
    id: 'admin',
    label: 'Admin',
    items: [
      { id: 'admin', label: 'Dashboard', icon: 'dashboard', href: '/admin' },
      { id: 'admin-users', label: 'Users', icon: 'users', href: '/admin/users' },
      { id: 'admin-groups', label: 'Groups', icon: 'user-circle', href: '/admin/groups' },
      { id: 'admin-roles', label: 'Roles', icon: 'shield', href: '/admin/roles', keywords: 'classes permissions' },
      { id: 'admin-invites', label: 'Invites', icon: 'mail', href: '/admin/invites' },
      // the page opens the first section this account may change
      { id: 'admin-settings', label: 'Settings', icon: 'sliders', href: '/admin/settings' },
      { id: 'admin-network', label: 'Network & VPN', icon: 'network', href: '/admin/network' },
      { id: 'admin-certificates', label: 'Certificates', icon: 'certificate', href: '/admin/certificates' },
      { id: 'admin-encryption', label: 'Encryption', icon: 'key', href: '/admin/encryption' },
      { id: 'admin-backups', label: 'Backups', icon: 'archive', href: '/admin/backups' },
      { id: 'admin-audit', label: 'Audit log', icon: 'scroll', href: '/admin/audit' },
      { id: 'admin-jobs', label: 'Jobs', icon: 'jobs', href: '/admin/jobs' },
      { id: 'admin-system', label: 'System', icon: 'server', href: '/admin/system' },
    ],
  },
];

/** Settings pages (avatar menu, More sheet, palette). */
export const SETTINGS_NAV = [
  { id: 'settings-profile', label: 'Profile', icon: 'user', href: '/settings/profile' },
  { id: 'settings-security', label: 'Security', icon: 'shield', href: '/settings/security' },
  { id: 'settings-sessions', label: 'Sessions', icon: 'laptop', href: '/settings/sessions' },
  { id: 'settings-tokens', label: 'API tokens', icon: 'terminal', href: '/settings/tokens' },
  { id: 'settings-appearance', label: 'Appearance', icon: 'palette', href: '/settings/appearance' },
  { id: 'settings-devices', label: 'Devices & app', icon: 'smartphone', href: '/settings/devices' },
];

/**
 * Bottom tab bar candidates (mobile), in priority order. The first three the user may see are shown (the FAB sits
 * between the 2nd and 3rd; "More" is last), so a hidden destination (no "My files" without a personal space; links
 * may be disabled) is replaced by the next one instead of leaving a dead tab.
 * @type {NavItem[]}
 */
const TAB_CANDIDATES = [
  { id: 'files', label: 'Files', icon: 'folder', href: '/files', needsSpace: true },
  { id: 'shared', label: 'Shared', icon: 'folder-shared', href: '/shared' },
  { id: 'links', label: 'Links', icon: 'link', href: '/links', feature: 'links' },
  { id: 'recent', label: 'Recent', icon: 'clock', href: '/recent' },
  { id: 'starred', label: 'Starred', icon: 'star', href: '/starred' },
];

/** Tabs currently shown in the bottom bar. */
function visibleTabs() {
  return TAB_CANDIDATES.filter(visible).slice(0, 3);
}

/** Top-level destinations (no back button on mobile). */
const TOP_LEVEL = new Set(['/files', '/shared', '/links', '/requests', '/starred', '/recent', '/trash', '/activity', '/search', '/admin']);

/** @param {NavItem} it */
function visible(it) {
  const b = boot();
  const features = { ...(b.features || {}), ...(session.peek()?.features || {}) };
  if (it.feature && /** @type {any} */ (features)[it.feature] === false) return false;
  if (it.needsSpace && !hasSpace()) return false;
  return pathAllowed(it.href);
}

/** Visible groups for the current user (a group without a visible item is left out). */
export function navGroups() {
  return NAV.map((g) => ({ ...g, items: g.items.filter(visible) })).filter((g) => g.items.length);
}

/**
 * The admin pages this account may open, in navigation order (the Dashboard included). Empty for accounts without
 * any server permission.
 * @returns {NavItem[]}
 */
export function adminItems() {
  return navGroups().find((g) => g.id === 'admin')?.items || [];
}

/**
 * Which nav item is active for the current route.
 * @returns {string}
 */
function activeId() {
  if (navOverride.peek()) return navOverride.peek();
  const r = route.peek();
  if (r.route?.nav) return r.route.nav;
  const p = r.path;
  let best = '';
  let bestLen = -1;
  for (const g of NAV) {
    for (const it of g.items) {
      if ((p === it.href || p.startsWith(`${it.href}/`)) && it.href.length > bestLen) {
        best = it.id;
        bestLen = it.href.length;
      }
    }
  }
  return best;
}

// -----------------------------------------------------------------------------------------------------------------
// Upload hooks
// -----------------------------------------------------------------------------------------------------------------

/** @type {HTMLInputElement | null} */
let filePicker = null;
/** @type {HTMLInputElement | null} */
let folderPicker = null;

function ensurePickers() {
  if (filePicker) return;
  filePicker = h('input', { class: 'hidden', attrs: { type: 'file', multiple: true, tabindex: '-1', 'aria-hidden': 'true' } });
  folderPicker = h('input', { class: 'hidden', attrs: { type: 'file', multiple: true, webkitdirectory: true, tabindex: '-1', 'aria-hidden': 'true' } });
  for (const [inp, action] of /** @type {[HTMLInputElement, string][]} */ ([[filePicker, 'files'], [folderPicker, 'folder']])) {
    inp.addEventListener('change', () => {
      const files = Array.from(inp.files || []);
      inp.value = '';
      if (files.length) dispatchUpload(action, { files });
    });
  }
  document.body.append(filePicker, folderPicker);
}

/**
 * Does this user have a destination for an upload? The same rule the destination picker applies (folder-picker.js:
 * spaces first, then folders shared with the user), so the Upload button is offered exactly when "Upload here" can
 * be enabled. The extra request is only made for a user with no writable space of their own — a guest.
 * @param {any[]} spaceList GET /spaces
 * @returns {Promise<boolean>}
 */
async function hasUploadTarget(spaceList) {
  if (spaceList.some((s) => (s.root_id || s.root_node_id) && canNode({ perm: s.perm }, 'edit'))) return true;
  try {
    const shared = itemsOf(await api.get('/shared-with-me', { query: { kind: 'folder', limit: 100 }, handle: false }));
    return shared.some((n) => n && n.kind === 'folder' && canNode(n, 'edit'));
  } catch {
    return false;
  }
}

/** True when the browser supports folder picking (not iOS). */
export function folderPickSupported() {
  const i = document.createElement('input');
  return 'webkitdirectory' in i && !/iPad|iPhone|iPod/.test(navigator.userAgent);
}

/**
 * Dispatch an fp:upload event; runs the fallback when no handler claims it.
 * @param {string} action
 * @param {Record<string, any>} [extra]
 */
export function dispatchUpload(action, extra = {}) {
  const detail = { action, folderId: currentFolder.peek()?.id || '', ...extra };
  const ev = new CustomEvent('fp:upload', { detail, cancelable: true });
  const unclaimed = document.dispatchEvent(ev);
  if (unclaimed) fallbackUpload(detail);
}

/**
 * Upload entry point for the split button, FAB, palette and shortcuts.
 * @param {'files' | 'folder' | 'new-folder' | 'new-request'} action
 */
export function triggerUpload(action) {
  ensurePickers();
  if (action === 'files') filePicker?.click();
  else if (action === 'folder') folderPicker?.click();
  else dispatchUpload(action);
}

/**
 * Default behaviour when no page/upload module handled the event.
 * @param {{action: string, files?: File[], folderId?: string}} d
 */
async function fallbackUpload(d) {
  if (d.action === 'new-request') {
    navigate('/requests?new=1');
    return;
  }
  if (d.action === 'files' || d.action === 'folder' || d.action === 'new-folder') {
    try {
      const mod = await import('./upload/basic.js');
      if (d.action === 'new-folder') await mod.newFolder(d.folderId);
      else await mod.uploadFiles(d.files || [], d.folderId);
    } catch (err) {
      console.error(err);
      toast.error(err);
    }
  }
}

/** @param {HTMLElement} anchor */
function openUploadMenu(anchor) {
  const up = canUpload.peek(); // no writable destination (a guest): the upload/create entries would all dead-end
  const items = [
    up ? { label: 'Upload files', icon: 'upload', onClick: () => triggerUpload('files') } : null,
    up && folderPickSupported() ? { label: 'Upload folder', icon: 'folder-up', onClick: () => triggerUpload('folder') } : null,
    up ? { divider: true } : null,
    up ? { label: 'New folder', icon: 'folder-plus', onClick: () => triggerUpload('new-folder') } : null,
    boot().features.requests !== false && up ? { label: 'New file request', icon: 'inbox', onClick: () => triggerUpload('new-request') } : null,
  ].filter(Boolean);
  if (!items.length) items.push(/** @type {any} */ ({ header: 'You have no folder you can upload to.' }));
  menu({ anchor, items: /** @type {any} */ (items), title: 'New' });
}

// -----------------------------------------------------------------------------------------------------------------
// Shell
// -----------------------------------------------------------------------------------------------------------------

const collapsed = persisted('nav-collapsed', false);

/**
 * @param {NavItem} it
 * @param {() => void} [onNavigate]
 */
function navLink(it, onNavigate) {
  const a = h('a', {
    class: 'nav-item',
    href: it.href,
    title: it.label,
    attrs: { 'aria-label': it.label },
    dataset: { nav: it.id },
    on: { click: () => onNavigate?.() },
  }, icon(it.icon), h('span', { class: 'nav-label', text: it.label }));
  return a;
}

/** Palette commands for every destination the user can reach. */
export function navCommands() {
  /** @type {import('./components/palette.js').Command[]} */
  const cmds = [];
  for (const g of navGroups()) {
    for (const it of g.items) cmds.push({ id: it.id, label: it.label, icon: it.icon, hint: g.label || '', keywords: it.keywords, run: () => navigate(it.href) });
  }
  for (const t of teamFolders.peek()) cmds.push({ id: `team-${t.id}`, label: t.name, icon: 'users', hint: 'Team folder', run: () => navigate(t.href) });
  for (const it of SETTINGS_NAV) cmds.push({ id: it.id, label: it.label, icon: it.icon, hint: 'Settings', run: () => navigate(it.href) });
  if (canUpload.peek()) {
    cmds.push(
      { id: 'upload-files', label: 'Upload files', icon: 'upload', hint: 'Action', run: () => triggerUpload('files') },
      { id: 'new-folder', label: 'New folder', icon: 'folder-plus', hint: 'Action', run: () => triggerUpload('new-folder') });
  }
  cmds.push(
    { id: 'theme-light', label: 'Theme: light', icon: 'sun', hint: 'Appearance', run: () => setTheme('light') },
    { id: 'theme-dark', label: 'Theme: dark', icon: 'moon', hint: 'Appearance', run: () => setTheme('dark') },
    { id: 'theme-system', label: 'Theme: system', icon: 'monitor', hint: 'Appearance', run: () => setTheme('system') },
    { id: 'shortcuts', label: 'Keyboard shortcuts', icon: 'keyboard', hint: 'Help', run: () => showShortcuts() },
    { id: 'sign-out', label: 'Sign out', icon: 'logout', hint: 'Account', run: () => signOut() },
  );
  return cmds;
}

export function openCommandPalette() {
  openPalette(navCommands, { onSearch: (q) => navigate(`/search?q=${encodeURIComponent(q)}`) });
}

/**
 * Apply + persist the theme (local immediately; best-effort to the profile prefs).
 * @param {string} theme
 */
export function setTheme(theme) {
  applyTheme(theme);
  try { localStorage.setItem('fp:theme', theme); } catch { /* ignore */ }
  const me = session.peek();
  if (me) {
    const prefs = { ...(me.prefs || me.user?.prefs || {}), theme };
    // PATCH /me/profile replaces the whole prefs object and savePrefs() (settings/common.js) merges into the store's
    // copy: update the store first (as savePrefs does), or the next density/view save sends the old theme back.
    session.value = { ...me, prefs, user: { ...me.user, prefs } };
    api.patch('/me/profile', { prefs }, { handle: false }).catch(() => { /* stored locally only */ });
  }
}

/**
 * Sign out: POST /auth/logout, then /login. Only a success or a 401 (the session is already gone) leaves the page —
 * on any other failure (offline, 503 keys_locked, 429, a proxy's 502) the session cookie is still valid, and /login
 * would just send a signed-in browser back to /files (or show the offline or unlock page) as if it had worked, so the
 * user is told and stays to try again.
 */
export async function signOut() {
  try {
    await api.post('/auth/logout', {}, { handle: false });
  } catch (err) {
    if (!(err instanceof ApiError && err.status === 401)) {
      toast.error(err instanceof ApiError && err.code === 'keys_locked'
        ? 'Could not sign out: the server is locked. Try again once it is unlocked.'
        : `Could not sign out: ${errorMessage(err).replace(/[.!?]?$/, '.')} Try again.`);
      return;
    }
  }
  try {
    const regs = await navigator.serviceWorker?.getRegistrations?.();
    regs?.forEach((r) => r.active?.postMessage({ type: 'logout' }));
  } catch { /* ignore */ }
  // Unfinished uploads are this user's data (file names, sizes, destination): drop them now instead of leaving them
  // in storage for whoever uses this browser next. The literal key is upload/manager.js STORE_KEY — importing it
  // here would be a cycle (manager.js imports currentFolder from this module).
  try { localStorage.removeItem('fp:uploads'); } catch { /* ignore */ }
  location.assign('/login');
}

function showAbout() {
  const b = boot();
  dialog({
    title: `About ${b.instance}`,
    size: 'sm',
    body: h('div', { class: 'stack' },
      h('div', { class: 'cluster' }, h('img', { src: asset('icons/logo.svg'), alt: '', attrs: { width: 48, height: 48 } }),
        h('div', null, h('strong', { text: 'FileParcel' }), h('div', { class: 'muted text-sm', text: b.version || 'development build' }))),
      h('p', { class: 'muted text-sm', text: 'Self-hosted, encrypted file sharing for your home and team.' }),
      h('a', { href: '/trust', attrs: { 'data-native': true }, text: 'Install this server’s certificate on your devices' })),
    actions: [{ label: 'Close', variant: 'primary' }],
  }).open();
}

/**
 * Toggle `data-heading-visible` on the top bar while the current page's first <h1> is visible below it (phones use it
 * to swap the bar title for the brand). Pages mount asynchronously, so the heading is re-discovered whenever the
 * outlet's children change.
 * @param {HTMLElement} outlet
 * @param {HTMLElement} topbar
 */
function watchPageHeading(outlet, topbar) {
  if (typeof IntersectionObserver === 'undefined') return;
  /** @type {Element | null} */
  let watched = null;
  /** @type {IntersectionObserver | null} */
  let io = null;
  const observe = () => {
    const heading = outlet.querySelector('h1');
    if (heading === watched) return;
    io?.disconnect();
    watched = heading;
    if (!heading) {
      topbar.removeAttribute('data-heading-visible');
      return;
    }
    const barH = topbar.getBoundingClientRect().height || 60;
    io = new IntersectionObserver((entries) => {
      const e = entries[entries.length - 1];
      topbar.toggleAttribute('data-heading-visible', e.isIntersecting);
    }, { rootMargin: `-${Math.round(barH)}px 0px 0px 0px`, threshold: 0 });
    io.observe(heading);
  };
  let queued = false;
  new MutationObserver(() => {
    if (queued) return;
    queued = true;
    requestAnimationFrame(() => {
      queued = false;
      observe();
    });
  }).observe(outlet, { childList: true, subtree: true });
  observe();
}

/**
 * Build the app shell into `root`.
 * @param {HTMLElement} root
 * @returns {{outlet: HTMLElement, banners: HTMLElement, refreshUsage: () => Promise<void>, refreshTeams: () => Promise<void>, setStatus: (keysState: string) => void}}
 */
export function renderShell(root) {
  const b = boot();
  clear(root);
  root.classList.add('app');
  ensurePickers();

  // ---- sidebar ----
  const navEl = h('nav', { class: 'sidebar-nav', attrs: { 'aria-label': 'Main' } });
  const usageEl = h('div', { class: 'meter', hidden: true });
  const statusDot = h('span', { class: 'status-dot', attrs: { 'aria-hidden': 'true' } });
  const statusText = h('span', { text: 'Encrypted storage' });
  const statusRow = h('div', { class: 'sidebar-status', attrs: { title: 'Server status' } }, statusDot, statusText);
  const collapseBtn = h('button', {
    class: 'icon-btn icon-btn--sm sidebar-collapse',
    attrs: { type: 'button', 'aria-label': 'Collapse sidebar', title: 'Collapse sidebar' },
    on: { click: () => { collapsed.value = !collapsed.peek(); } },
  }, icon('chevrons-left'));

  const brandName = h('span', { class: 'brand-name', text: instanceName.peek() });
  const brandLink = h('a', { class: 'brand', href: '/files', title: instanceName.peek() },
    h('img', { class: 'brand-logo', src: asset('icons/logo.svg'), alt: '', attrs: { width: 32, height: 32 } }),
    brandName);
  const sidebar = h('aside', { class: 'app-sidebar', id: 'fp-sidebar', attrs: { 'aria-label': 'Sidebar' } },
    h('div', { class: 'sidebar-head' }, brandLink, collapseBtn),
    navEl,
    h('div', { class: 'sidebar-foot' },
      usageEl,
      statusRow,
      h('div', { class: 'sidebar-version subtle', text: b.version ? `FileParcel ${b.version}` : 'FileParcel' })));

  const scrim = h('div', { class: 'app-scrim', hidden: true, on: { click: () => setDrawer(false) } });

  // ---- top bar ----
  const menuBtn = h('button', {
    class: 'icon-btn topbar-menu',
    attrs: { type: 'button', 'aria-label': 'Open navigation', 'aria-controls': 'fp-sidebar', 'aria-expanded': 'false' },
    on: { click: () => setDrawer(root.dataset.drawer !== 'open') },
  }, icon('menu'));
  const backBtn = h('button', {
    class: 'icon-btn topbar-back',
    hidden: true,
    attrs: { type: 'button', 'aria-label': 'Back', title: 'Back' },
    on: { click: goBack },
  }, icon('arrow-left'));
  // Phones: a "large title" pattern — while the page's own <h1> is on screen the bar shows the brand; once the heading
  // scrolls under the bar, the bar shows the page title instead (so the title is never shown twice).
  const titleText = h('span', { class: 'topbar-title-text' });
  const topbarBrandName = h('span', { text: instanceName.peek() });
  const titleBrand = h('span', { class: 'topbar-title-brand' },
    h('img', { class: 'brand-logo', src: asset('icons/logo.svg'), alt: '', attrs: { width: 28, height: 28 } }),
    topbarBrandName);
  const titleEl = h('div', { class: 'topbar-title', attrs: { 'aria-hidden': 'true' } }, titleBrand, titleText);
  const mac = /mac|iphone|ipad/i.test(navigator.platform || navigator.userAgent);
  const searchBtn = h('button', {
    class: 'topbar-search',
    attrs: { type: 'button', 'aria-label': 'Search and commands', 'aria-keyshortcuts': mac ? 'Meta+K' : 'Control+K' },
    on: { click: openCommandPalette },
  }, icon('search', { size: 18 }), h('span', { text: 'Search files and commands…' }), h('kbd', { text: mac ? '⌘K' : 'Ctrl K' }));
  const searchIconBtn = h('a', { class: 'icon-btn topbar-search-icon', href: '/search', attrs: { 'aria-label': 'Search', title: 'Search' } }, icon('search'));

  const uploadMain = h('button', { class: 'btn btn--primary', attrs: { type: 'button' }, on: { click: () => triggerUpload('files') } },
    icon('upload'), h('span', { text: 'Upload' }));
  const uploadMore = h('button', {
    class: 'btn btn--primary',
    attrs: { type: 'button', 'aria-label': 'More upload options', 'aria-haspopup': 'menu', 'aria-expanded': 'false' },
    on: { click: (e) => openUploadMenu(/** @type {HTMLElement} */ (e.currentTarget)) },
  }, icon('chevron-down'));
  const uploadSplit = h('div', { class: 'split-btn topbar-upload', attrs: { role: 'group', 'aria-label': 'Upload' } }, uploadMain, uploadMore);

  const jobsCount = h('span', { class: 'count', hidden: true });
  const jobsBtn = h('button', {
    class: 'icon-btn jobs-indicator',
    attrs: { type: 'button', 'aria-label': 'Background jobs', title: 'Background jobs', 'aria-haspopup': 'menu' },
    on: { click: (e) => openJobsMenu(/** @type {HTMLElement} */ (e.currentTarget)) },
  }, icon('activity'), jobsCount);
  const helpBtn = h('button', {
    class: 'icon-btn topbar-help',
    attrs: { type: 'button', 'aria-label': 'Help', title: 'Help', 'aria-haspopup': 'menu' },
    on: {
      click: (e) => menu({
        anchor: /** @type {HTMLElement} */ (e.currentTarget),
        title: 'Help',
        items: [
          { label: 'Keyboard shortcuts', icon: 'keyboard', onClick: () => showShortcuts() },
          { label: 'Trust this server on your devices', icon: 'certificate', onClick: () => location.assign('/trust') },
          { label: `About ${b.instance}`, icon: 'info', onClick: showAbout },
        ],
      }),
    },
  }, icon('help'));
  const avatarEl = h('span', { class: 'avatar', attrs: { 'aria-hidden': 'true' } });
  const avatarBtn = h('button', {
    class: 'avatar-btn',
    attrs: { type: 'button', 'aria-label': 'Account menu', 'aria-haspopup': 'menu', 'aria-expanded': 'false' },
    on: { click: (e) => openAccountMenu(/** @type {HTMLElement} */ (e.currentTarget)) },
  }, avatarEl);

  const topbar = h('header', { class: 'app-topbar' },
    menuBtn, backBtn, titleEl, searchBtn, h('div', { class: 'topbar-spacer' }),
    h('div', { class: 'topbar-actions' }, uploadSplit, searchIconBtn, jobsBtn, helpBtn, avatarBtn));

  // ---- main ----
  const banners = h('div', { class: 'app-banners' });
  const outlet = h('div', { class: 'app-outlet', id: 'fp-outlet' });
  const main = h('main', { class: 'app-main', id: 'main', attrs: { tabindex: '-1' } }, banners, outlet);

  // ---- mobile tab bar ----
  const fab = h('button', {
    class: 'fab',
    attrs: { type: 'button', 'aria-label': 'Upload or create', 'aria-haspopup': 'menu' },
    on: { click: (e) => openUploadMenu(/** @type {HTMLElement} */ (e.currentTarget)) },
  }, icon('plus', { size: 26 }));
  const moreBtn = h('button', {
    class: 'tab-item',
    attrs: { type: 'button', 'aria-haspopup': 'dialog' },
    dataset: { nav: 'more' },
    on: { click: openMoreSheet },
  }, icon('menu'), h('span', { text: 'More' }));
  const fabSlot = h('div', { class: 'tab-fab-slot' }, fab);
  const tabbar = h('nav', { class: 'app-tabbar', attrs: { 'aria-label': 'Primary' } });
  /** @type {NavItem[]} */
  let tabs = [];
  /** (Re)build the bottom tabs for the current role/features. */
  const renderTabs = () => {
    tabs = visibleTabs();
    const links = tabs.map((t) => h('a', { class: 'tab-item', href: t.href, dataset: { nav: t.id } }, icon(t.icon), h('span', { text: t.label })));
    // keep 2 destinations before the FAB so it stays centred
    tabbar.replaceChildren(links[0] || h('span'), links[1] || h('span'), fabSlot, links[2] || h('span'), moreBtn);
  };

  root.append(h('a', { class: 'skip-link', href: '#main', attrs: { 'data-native': true }, on: { click: (e) => { e.preventDefault(); main.focus(); } } }, 'Skip to content'),
    sidebar, scrim, topbar, main, tabbar);

  // ---- behaviour ----
  /**
   * Open/close the slide-over drawer (tablet). While open, everything but the sidebar and the scrim is `inert`, so
   * Tab stays in the drawer (a modal-like pattern without moving the sidebar into a <dialog>); on close, focus
   * returns to the menu button when it was inside the drawer.
   * @param {boolean} open
   */
  function setDrawer(open) {
    if (open) {
      root.dataset.drawer = 'open';
      scrim.hidden = false;
      menuBtn.setAttribute('aria-expanded', 'true');
      for (const c of root.children) if (c !== sidebar && c !== scrim) /** @type {HTMLElement} */ (c).inert = true;
      /** @type {HTMLElement | null} */ (sidebar.querySelector('.nav-item'))?.focus();
    } else if (root.dataset.drawer === 'open') {
      const hadFocus = sidebar.contains(document.activeElement);
      delete root.dataset.drawer;
      scrim.hidden = true;
      menuBtn.setAttribute('aria-expanded', 'false');
      for (const c of root.children) /** @type {HTMLElement} */ (c).inert = false;
      if (hadFocus && menuBtn.getClientRects().length) menuBtn.focus({ preventScroll: true });
    }
  }
  document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape' && root.dataset.drawer === 'open') setDrawer(false);
  });
  window.matchMedia('(min-width: 1024px)').addEventListener('change', () => setDrawer(false));

  function goBack() {
    if (history.state && history.state.key && history.length > 1) history.back();
    else {
      const parts = location.pathname.split('/').filter(Boolean);
      parts.pop();
      navigate(parts.length ? `/${parts.join('/')}` : '/files');
    }
  }

  const renderNav = () => {
    const groups = navGroups();
    const teams = teamFolders.value; // tracked: the session effect re-renders when team folders load
    navEl.replaceChildren(...groups.map((g) => {
      const items = g.items.map((it) => h('li', null, navLink(it, () => setDrawer(false))));
      if (g.id === 'workspace' && teams.length) {
        items.splice(1, 0, ...teams.map((t) => h('li', null,
          navLink({ id: `team:${t.id}`, label: t.name, icon: 'users', href: t.href }, () => setDrawer(false)))));
      }
      const labelId = `nav-g-${g.id}`;
      return h('div', { class: 'nav-group', attrs: { role: 'group', 'aria-labelledby': g.label ? labelId : null } },
        g.label ? h('h2', { class: 'nav-group-label', id: labelId, text: g.label }) : null,
        h('ul', { attrs: { role: 'list' } }, items));
    }));
    syncActive();
  };

  const syncActive = () => {
    const id = activeId();
    for (const a of root.querySelectorAll('[data-nav]')) {
      const n = /** @type {HTMLElement} */ (a).dataset.nav;
      const on = n === id || (n === 'more' && !tabs.some((t) => t.id === id) && id !== '');
      if (on) a.setAttribute('aria-current', 'page');
      else a.removeAttribute('aria-current');
    }
    backBtn.hidden = TOP_LEVEL.has(route.peek().path);
  };

  function openMoreSheet() {
    const s = sheet({ title: 'More', content: null });
    const id = activeId();
    /** @type {import('./components/sheet.js').SheetItem[]} */
    const items = [];
    for (const g of navGroups()) {
      if (g.label) items.push({ section: g.label });
      for (const it of g.items) {
        if (tabs.some((t) => t.id === it.id)) continue;
        items.push({ label: it.label, icon: it.icon, href: it.href, current: it.id === id });
      }
      if (g.id === 'workspace') for (const t of teamFolders.peek()) items.push({ label: t.name, icon: 'users', href: t.href });
    }
    items.push({ section: 'Account' });
    for (const it of SETTINGS_NAV) items.push({ label: it.label, icon: it.icon, href: it.href, current: route.peek().path === it.href });
    items.push({ divider: true }, { label: 'Sign out', icon: 'logout', onClick: signOut, danger: true });
    s.body.appendChild(sheetList(items, () => s.close()));
    s.open();
  }

  /** @param {HTMLElement} anchor */
  function openAccountMenu(anchor) {
    const me = session.peek();
    const u = me?.user;
    menu({
      anchor,
      title: u?.display_name || u?.username || 'Account',
      align: 'end',
      items: [
        { header: [u?.display_name || u?.username || '', u?.email || ''].filter(Boolean).join(' · ') },
        ...SETTINGS_NAV.map((it) => ({ label: it.label, icon: it.icon, href: it.href })),
        { divider: true },
        { label: 'Light theme', icon: 'sun', onClick: () => setTheme('light') },
        { label: 'Dark theme', icon: 'moon', onClick: () => setTheme('dark') },
        { label: 'System theme', icon: 'monitor', onClick: () => setTheme('system') },
        { divider: true },
        { label: 'Sign out', icon: 'logout', danger: true, onClick: signOut },
      ],
    });
  }

  /** @param {HTMLElement} anchor */
  function openJobsMenu(anchor) {
    const list = [...jobs.peek().values()].sort((a, b) => b.updated - a.updated).slice(0, 8);
    menu({
      anchor,
      align: 'end',
      title: 'Background jobs',
      items: list.length
        ? list.map((j) => ({
          label: `${j.kind || 'Job'} — ${j.state || 'running'}${j.progress_total ? ` (${pct(j.progress_done || 0, j.progress_total)})` : ''}`,
          icon: j.state === 'failed' ? 'alert-circle' : j.state === 'succeeded' ? 'check-circle' : 'loader',
          onClick: () => { if (can('system.view')) navigate('/admin/jobs'); },
        }))
        : [{ header: 'No background jobs right now.' }],
    });
  }

  // reactive bindings
  effect(() => {
    const me = session.value;
    const u = me?.user || b.user;
    avatarEl.textContent = initials(u?.display_name || u?.username || '?');
    avatarBtn.title = u ? `${u.display_name || u.username} (${u.role_name || u.role})` : 'Account';
    renderTabs();
    renderNav();
  });
  effect(() => {
    route.value;
    navOverride.value;
    syncActive();
    if (isMobile()) setDrawer(false);
  });
  effect(() => {
    const name = instanceName.value;
    brandName.textContent = name;
    brandLink.title = name;
    topbarBrandName.textContent = name;
  });
  effect(() => {
    // Nowhere to upload to (a guest): hide the entry points instead of sending the user through a file picker into
    // a destination dialog with no folders in it.
    const ok = canUpload.value;
    uploadSplit.hidden = !ok;
    fab.hidden = !ok;
  });
  effect(() => {
    titleText.textContent = pageTitle.value || instanceName.value;
  });
  watchPageHeading(outlet, topbar);
  effect(() => {
    root.toggleAttribute('data-collapsed', !!collapsed.value);
    collapseBtn.setAttribute('aria-label', collapsed.value ? 'Expand sidebar' : 'Collapse sidebar');
    collapseBtn.title = collapsed.value ? 'Expand sidebar' : 'Collapse sidebar';
    collapseBtn.setAttribute('aria-expanded', String(!collapsed.value));
  });
  effect(() => {
    const n = activeJobCount.value;
    jobsCount.hidden = n === 0;
    jobsCount.textContent = n > 9 ? '9+' : String(n);
    jobsBtn.toggleAttribute('data-active', n > 0);
    jobsBtn.setAttribute('aria-label', n ? `Background jobs (${n} running)` : 'Background jobs');
  });

  // ---- lock/cert status dot (§13.5) ----
  // Keys state comes from boot data and SSE keys.state (everyone); certificate health from GET /admin/certs
  // (accounts with the Certificates permission, refreshed on SSE certs.changed). Most severe wins: keys locked (danger) > certificate problem
  // (warning) > OK. A local-CA certificate is the normal home setup and is not a warning; problems are an expired or
  // soon-expiring served certificate (< 14 days: renewal is failing — it renews at 30; the local leaf renews when
  // less than min(30 days, a third of its lifetime) is left, so it warns at half that, at most 14 days, like the
  // dashboard and doctor — a healthy 7-day leaf is not "expiring") or an ACME/Tailscale error.
  let keysState = b.keys_state || 'unlocked';
  /** @type {{level: '' | 'warning' | 'danger', text: string, detail: string}} */
  let certState = { level: '', text: '', detail: '' };
  const renderStatus = () => {
    let level = '';
    let text = 'Encrypted at rest';
    const details = [keysState === 'locked' ? 'Encryption keys: locked' : 'Encryption keys: unlocked'];
    if (certState.detail) details.push(certState.detail);
    if (keysState === 'locked') {
      level = 'danger';
      text = 'Keys locked';
    } else if (certState.level) {
      level = certState.level;
      text = certState.text;
    }
    if (level) statusDot.dataset.state = level;
    else delete statusDot.dataset.state;
    statusText.textContent = text;
    statusRow.title = details.join(' · ');
  };
  const setStatus = (/** @type {string} */ state) => {
    keysState = state || 'unlocked';
    renderStatus();
  };

  /** @param {any} st CertStatus */
  const certHealth = (st) => {
    const now = Date.now();
    const DAY = 86_400_000;
    /** @type {any[]} */
    const certs = [st?.custom, st?.tailscale, ...(Array.isArray(st?.acme) ? st.acme : []), st?.leaf].filter(Boolean);
    /** @param {any} c */
    const warnMs = (c) => {
      if (c !== st?.leaf) return 14 * DAY;
      const span = Date.parse(c.not_after || '') - Date.parse(c.not_before || '');
      return Math.min(14 * DAY, (span > 0 ? Math.min(30 * DAY, span / 3) : 30 * DAY) / 2);
    };
    let soonest = Infinity;
    let warnAt = Infinity; // soonest expiry of a certificate inside its warning window
    for (const c of certs) {
      const t = Date.parse(c.not_after || '');
      if (!Number.isFinite(t)) continue;
      soonest = Math.min(soonest, t);
      if (t - now < warnMs(c)) warnAt = Math.min(warnAt, t);
    }
    const days = Math.floor((warnAt - now) / DAY);
    const trust = st?.publicly_trusted ? 'publicly trusted certificate' : 'local CA certificate';
    const detail = Number.isFinite(soonest) ? `TLS: ${trust}, next expiry ${new Date(soonest).toLocaleDateString()}` : `TLS: ${trust}`;
    if (Number.isFinite(soonest) && soonest <= now) return { level: /** @type {const} */ ('danger'), text: 'Certificate expired', detail };
    if (Number.isFinite(warnAt)) {
      const text = days < 1 ? 'Certificate expires today' : `Certificate expires in ${days} day${days === 1 ? '' : 's'}`;
      return { level: /** @type {const} */ ('warning'), text, detail };
    }
    if (st?.acme_error || st?.tailscale_error) {
      return { level: /** @type {const} */ ('warning'), text: 'Certificate problem', detail: `${detail} · ${st.acme_error || st.tailscale_error}` };
    }
    return { level: /** @type {const} */ (''), text: '', detail };
  };
  const refreshCerts = async () => {
    if (!can('certs.manage')) return;
    try {
      certState = certHealth(await api.get('/admin/certs', { handle: false }));
    } catch {
      certState = { level: '', text: '', detail: '' }; // endpoint unavailable: say nothing rather than guess
    }
    renderStatus();
  };
  events.on('certs.changed', () => { refreshCerts(); });
  renderStatus();
  // /admin/certs sits behind mw.RequireFull like the rest of the API: asking for it while the session is still in
  // the required-2FA enrolment gate only produces a 403 in the console. Wait until the session is full. A role
  // change (authz.changed → a new /me) can grant or take away the permission: ask then, or forget what was shown.
  let certsAsked = false;
  effect(() => {
    const me = session.value;
    if (!isFullSession(me)) return;
    if (!can('certs.manage', me)) {
      if (certsAsked) {
        certsAsked = false;
        certState = { level: '', text: '', detail: '' };
        renderStatus();
      }
      return;
    }
    if (certsAsked) return;
    certsAsked = true;
    refreshCerts();
  });

  const refreshUsage = async () => {
    try {
      const u = await api.get('/me/usage', { handle: false });
      const used = Number(u?.used_bytes ?? u?.used ?? 0);
      const quota = Number(u?.quota_bytes ?? u?.quota ?? 0);
      const bar = h('progress', { attrs: { max: quota || 1, 'aria-label': 'Storage used' }, value: quota ? Math.min(used, quota) : 0 });
      replace(usageEl,
        h('div', { class: 'meter-text sidebar-meter-text' },
          h('span', { text: 'Storage' }),
          h('span', { class: 'tabular', text: quota ? `${bytes(used)} of ${bytes(quota)}` : `${bytes(used)} used` })),
        quota ? h('div', { class: 'progress progress--sm', dataset: { kind: quota && used / quota > 0.9 ? 'danger' : null } }, bar) : null);
      usageEl.hidden = false;
      usageEl.title = quota ? `${pct(used, quota)} of your quota used` : `${bytes(used)} used`;
    } catch {
      usageEl.hidden = true;
    }
  };

  const refreshTeams = async () => {
    try {
      const spaces = itemsOf(await api.get('/spaces', { handle: false }));
      teamFolders.value = spaces
        .filter((s) => s.kind === 'group')
        .map((s) => {
          const rootId = s.root_id || s.root_node_id || s.root?.id || '';
          return { id: s.id, name: s.name || 'Team folder', href: rootId ? `/files/${encodeURIComponent(rootId)}` : '/files' };
        });
      canUpload.value = await hasUploadTarget(spaces);
    } catch {
      teamFolders.value = [];
    }
  };

  return { outlet, banners, refreshUsage, refreshTeams, setStatus };
}
