// @ts-check
/**
 * Shared helpers for the admin pages (pages/admin/*) and the personal settings pages (pages/settings/*).
 * Not a page module itself (routes.js never loads it directly). Owned by unit J2.
 *
 *   adminHeader(root, {title, subtitle, actions, crumbs})   page header with "Admin ›" breadcrumbs
 *   errorPanel(err, retry)                                   inline error with a retry button
 *   kv([[label, value], …])                                  <dl class="kv">
 *   alertEl(kind, title, text, action)                       inline alert
 *   stateBadge / roleBadge / expiryBadge / timeEl / userCell / chips / jsonBlock / moreMenu
 *   roleSelect({label, roles, value, …})                     role picker with Built-in / Custom roles groups (sends role_id)
 *   permissionChips(perms, catalog, {max})                   permissions as grouped chips, high-impact ones highlighted
 *   loadRoles({force}) / loadCatalog() / clearRoleCache()    GET /admin/roles (cached 60 s), /admin/capabilities
 *   loadRolesOrBuiltins() / builtinRoles()                   the same for pickers, the built-in roles when unreadable
 *   rolesSupported()                                         the server has roles (and their API)
 *   mayManageAccount(u, {need, role})                        client-side mirror of who may act on an account
 *   confirmRoleChange(u, role) / grantLocation(grant)        role change confirmation; "Team · Design / Reports"
 *   formDialog({title, fields, onSubmit})                    form in a modal; resolves onSubmit's result
 *   confirmTyped({title, message, expected})                 destructive confirmation that needs typing a word
 *   userPicker({label, name})                                search-as-you-type user combobox (admin)
 *   quotaField({label, value})                               default / unlimited / custom size control
 *   ensureElevated()                                         step-up now (before long uploads / navigations)
 *   elevatedDownload(url)                                    HEAD-probe (elevation) then native download
 *   showSecretOnce({…})                                      "shown once" dialog with copy / download / acknowledgement
 *   trackJob(id, {onUpdate, signal})                         SSE + polling until a job finishes
 *   jobProgress(id, {…})                                     progress element bound to a job
 *   restartServer()                                          confirm → POST /admin/system/restart → wait → reload
 *   waitForRestart({before})                                 progress dialog + polling for a restart already under way
 *   infiniteScroll(sentinel, loadMore)                       IntersectionObserver helper
 *   ipAllowed(ip, policy)                                    client-side mirror of the access-policy matcher (§10.3)
 * @module pages/admin/common
 */
import { h, icon, downloadBlob, boot, uniqueId, replace, append } from '../../core/dom.js';
import { api, ApiError, errorMessage, setCsrf, itemsOf, errorFrom } from '../../core/api.js';
import { jobs, session, events, isAdmin, can } from '../../core/store.js';
import { PERMISSION_LABELS, isServerPermission } from '../../core/perms.js';
import { pathAllowed } from '../../routes.js';
import { pageHeader } from '../../components/page-header.js';
import { button, iconButton } from '../../components/button.js';
import { dialog, confirm } from '../../components/dialog.js';
import { promptElevation } from '../../components/elevation.js';
import { toast } from '../../components/toast.js';
import { copyField, copyText } from '../../components/copy-field.js';
import { badge } from '../../components/badge.js';
import { progress, spinner } from '../../components/progress.js';
import { checkbox, field, select } from '../../components/field.js';
import { form } from '../../components/form.js';
import { menu } from '../../components/menu.js';
import { duration, number, relTime, dateTime, toDate, initials, bytes } from '../../core/format.js';

/**
 * @typedef {import('../../components/page-header.js').Crumb} Crumb
 * @typedef {import('../../core/dom.js').Child} Child
 * @typedef {'neutral' | 'primary' | 'info' | 'success' | 'warning' | 'danger' | 'kraft'} BadgeKind
 */

/**
 * Page header for admin pages.
 * @param {HTMLElement} root
 * @param {{title: string, subtitle?: Child, actions?: Child, crumbs?: Crumb[], admin?: boolean}} o
 *   crumbs: intermediate crumbs between "Admin" and the page; admin: false for settings pages
 * @returns {HTMLElement}
 */
export function adminHeader(root, o) {
  const first = o.admin === false ? { label: 'Settings', href: '/settings/profile' } : { label: 'Admin', href: '/admin' };
  const el = pageHeader({ title: o.title, subtitle: o.subtitle, actions: o.actions, breadcrumbs: [first, ...(o.crumbs || []), { label: o.title }] });
  root.appendChild(el);
  return el;
}

/**
 * Inline error panel with an optional retry.
 * @param {unknown} err
 * @param {() => void} [retry]
 * @param {string} [title]
 */
export function errorPanel(err, retry, title = 'This could not be loaded') {
  const notReady = err instanceof ApiError && (err.status === 501 || err.code === 'not_implemented');
  const missing = err instanceof ApiError && err.status === 404 && err.code === 'not_found' && /not found$/i.test(err.message) && err.message.length < 12;
  return h('div', { class: 'alert alert--danger', attrs: { role: 'alert' } },
    icon('alert-circle'),
    h('div', { class: 'alert-body' },
      h('strong', { text: notReady || missing ? 'Not available on this server yet' : title }),
      h('span', { text: notReady || missing ? 'The server you are connected to does not provide this feature (yet).' : errorMessage(err) }),
      err instanceof ApiError && err.requestId ? h('span', { class: 'text-xs mono', text: `Request ${err.requestId}` }) : null),
    retry ? button({ label: 'Retry', size: 'sm', icon: 'refresh', onClick: () => retry() }) : null);
}

/**
 * Inline alert.
 * @param {'info' | 'success' | 'warning' | 'danger' | 'kraft'} kind
 * @param {string} title
 * @param {Child} [text]
 * @param {Child} [action]
 */
export function alertEl(kind, title, text, action) {
  const ic = { info: 'info', success: 'check-circle', warning: 'alert-triangle', danger: 'alert-circle', kraft: 'package' }[kind];
  return h('div', { class: `alert alert--${kind}`, attrs: { role: kind === 'danger' ? 'alert' : 'status' } },
    icon(ic),
    h('div', { class: 'alert-body' }, title ? h('strong', { text: title }) : null, text !== undefined && text !== null ? h('span', null, text) : null),
    action || null);
}

/**
 * Description list.
 * @param {[string, Child][]} pairs rows with null/undefined/'' values are skipped
 */
export function kv(pairs) {
  return h('dl', { class: 'kv' }, pairs.filter(([, v]) => v !== null && v !== undefined && v !== '').map(([k, v]) => [h('dt', { text: k }), h('dd', null, v)]));
}

/** @type {Record<string, BadgeKind>} */
const STATE_KINDS = {
  active: 'success', ready: 'success', succeeded: 'success', success: 'success', unlocked: 'success', published: 'success', ok: 'success',
  running: 'info', queued: 'neutral', publishing: 'info', pending: 'neutral', finalizing: 'info',
  failed: 'danger', failure: 'danger', error: 'danger', denied: 'warning', collision: 'warning', locked: 'warning',
  disabled: 'neutral', revoked: 'neutral', expired: 'neutral', used: 'neutral', canceled: 'neutral', off: 'neutral', exhausted: 'neutral',
  warn: 'warning', warning: 'warning', fail: 'danger', uninitialized: 'warning', retired: 'neutral',
};

/**
 * Badge for a state/status word.
 * @param {string | null | undefined} state
 * @param {string} [text] label override
 */
export function stateBadge(state, text) {
  const s = String(state || 'unknown');
  return badge({ text: text || s.replace(/_/g, ' '), kind: STATE_KINDS[s] || 'neutral' });
}

/** @type {Record<string, BadgeKind>} */
const ROLE_KINDS = { owner: 'kraft', admin: 'primary', member: 'neutral', guest: 'info', system: 'warning' };

// ---------------------------------------------------------------------------------------------------------------
// roles (DESIGN §6a): every account has one role — a built-in word (owner, admin, member, guest) or a custom role
// "rol_…" based on member or guest. In the API `role` is the base and `role_id` the role.
// ---------------------------------------------------------------------------------------------------------------

/** Display names of the built-in roles (core.BuiltinRoleName). @type {Record<string, string>} */
export const BUILTIN_ROLE_NAMES = { owner: 'Owner', admin: 'Admin', member: 'Member', guest: 'Guest', system: 'System' };

/**
 * Descriptions of the built-in roles (core.BuiltinRoles), for role pickers when GET /admin/roles cannot be read.
 * Pinned to the Go text by internal/web/static/perms_test.go: keep one entry per line, as a string literal
 * ("…" when the text has an apostrophe).
 * @type {Readonly<Record<string, string>>}
 */
export const BUILTIN_ROLE_DESCRIPTIONS = Object.freeze({
  owner: 'Full control, including other owners. At least one active owner must remain.',
  admin: "Runs the server: people, roles, settings, network, certificates, encryption and backups. Cannot change owners, and cannot open other people's files unless “Administrators can access all files” is on.",
  member: 'Has “My files”, uses the team folders of their groups, shares, creates links and file requests, finds people and creates API tokens.',
  guest: 'No personal space; works only in folders shared with them or their role. Creates links and file requests only when Settings → Sharing allows guests to share.',
});

/** Role name an invitation shows when its custom role was deleted (users service). */
const DELETED_ROLE = 'Deleted role';

/**
 * Whether `id` names a custom role (core.IsCustomRoleID).
 * @param {string | null | undefined} id
 */
export function isCustomRoleId(id) {
  return String(id || '').startsWith('rol_');
}

/**
 * "Based on Member" / "Based on Guest" for a custom role (core.RoleDef); '' for the built-in roles.
 * @param {any} r
 */
export function roleBaseText(r) {
  if (!r || !isCustomRoleId(r.id)) return '';
  return `Based on ${BUILTIN_ROLE_NAMES[r.base] || r.base || 'Member'}`;
}

/**
 * Whether a role (core.RoleDef) carries server permissions, i.e. opens part of the Admin area.
 * @param {any} r
 */
export function roleIsStaff(r) {
  return !!r && (r.staff === true || (Array.isArray(r.permissions) && r.permissions.some(isServerPermission)));
}

/**
 * Badge for a role. Accepts a built-in word ("admin"; older callers), a user or an invitation (role_id, role_name
 * and `role`, the base) or a role (core.RoleDef). The text is the role's name (the word for a bare word); owners are
 * kraft, admins primary, custom roles with server permissions primary with a shield, members neutral, guests (and
 * roles based on Guest) info, a deleted role neutral.
 * @param {string | any} x
 */
export function roleBadge(x) {
  if (!x || typeof x !== 'object') {
    const r = String(x || 'member');
    return badge({ text: r, kind: ROLE_KINDS[r] || 'neutral' });
  }
  const def = typeof x.builtin === 'boolean' && !('username' in x);
  const id = String((def ? x.id : x.role_id) || x.role || 'member');
  const name = String((def ? x.name : x.role_name) || BUILTIN_ROLE_NAMES[id] || id);
  if (!isCustomRoleId(id)) return badge({ text: name, kind: ROLE_KINDS[id] || 'neutral' });
  if (!def && name === DELETED_ROLE) return badge({ text: name, kind: 'neutral', title: 'This role no longer exists' });
  const base = def ? x.base : x.role;
  const title = `Custom role · based on ${BUILTIN_ROLE_NAMES[base] || base || 'Member'}`;
  if (roleIsStaff(x)) return badge({ text: name, kind: 'primary', icon: 'shield', title: `${title} · server access` });
  return badge({ text: name, kind: base === 'guest' ? 'info' : 'neutral', title });
}

/** Cached GET /admin/roles. @type {{at: number, p: Promise<any[]>} | null} */
let rolesCache = null;
/** Cached GET /admin/capabilities (for the session). @type {Promise<any> | null} */
let catalogCache = null;
const ROLES_TTL_MS = 60_000;

/**
 * The roles (core.RoleDef: built-ins owner, admin, member, guest, then custom roles by name) with the caller's
 * `editable` / `assignable`. Cached for 60 s; `force` reloads.
 * @param {{force?: boolean}} [o]
 * @returns {Promise<any[]>}
 */
export function loadRoles(o = {}) {
  if (!o.force && rolesCache && Date.now() - rolesCache.at < ROLES_TTL_MS) return rolesCache.p;
  const entry = { at: Date.now(), p: api.get('/admin/roles').then(itemsOf) };
  rolesCache = entry;
  entry.p.catch(() => { if (rolesCache === entry) rolesCache = null; });
  return entry.p;
}

/**
 * The permission catalog (core.CapabilityCatalog {items, groups}), loaded once per page load.
 * @returns {Promise<{items: any[], groups: any[]}>}
 */
export function loadCatalog() {
  if (!catalogCache) {
    const p = api.get('/admin/capabilities').then((c) => ({ items: itemsOf(c), groups: Array.isArray(c?.groups) ? c.groups : [] }));
    catalogCache = p;
    p.catch(() => { if (catalogCache === p) catalogCache = null; });
  }
  return catalogCache;
}

/** Forget the cached roles and catalog: after changing a role, and whenever the server says roles changed. */
export function clearRoleCache() {
  rolesCache = null;
  catalogCache = null;
}
events.on('authz.changed', clearRoleCache);

/**
 * The four built-in roles as core.RoleDef-like objects (no counts, nothing about the caller).
 * @returns {any[]}
 */
export function builtinRoles() {
  return ['owner', 'admin', 'member', 'guest'].map((id) => ({
    id, name: BUILTIN_ROLE_NAMES[id], description: BUILTIN_ROLE_DESCRIPTIONS[id], builtin: true, base: id, staff: id === 'owner' || id === 'admin',
  }));
}

/**
 * Whether the server has roles: one that does names the role of every account in /me (`role_id`); a server that
 * predates roles does not, and has no roles API (the pages then offer the built-in roles and leave out what needs it).
 */
export function rolesSupported() {
  return !!me()?.role_id;
}

/**
 * loadRoles() for role pickers and filters: when the roles cannot be read (a server without roles, or a failure
 * the picker should not block on) the built-in roles stand in. The server still decides what may be given.
 * @returns {Promise<any[]>}
 */
export function loadRolesOrBuiltins() {
  if (!rolesSupported()) return Promise.resolve(builtinRoles());
  return loadRoles().then((list) => (list.length ? list : builtinRoles())).catch(() => builtinRoles());
}

/**
 * Whether a user (core.User) can use the Admin area: an owner or admin, or a role with a server permission.
 * @param {any} u
 */
export function userIsStaff(u) {
  return u?.role === 'owner' || u?.role === 'admin' || (Array.isArray(u?.permissions) && u.permissions.some(isServerPermission));
}

/**
 * Whether the signed-in account may act on account `u` with the permission `need` — the client-side mirror of the
 * server's rules (DESIGN §6a, core.CheckManage), used to offer or hide controls; the server decides. Owners and admins
 * act on everyone but owners (owners too, for an owner); anyone else holding `need` acts on members, guests and the
 * holders of roles an administrator allowed (`roleDef.delegable`) whose server permissions they hold themselves, never
 * on their own account.
 * @param {any} u core.User
 * @param {{need?: 'users.manage' | 'users.credentials', role?: any}} [o] role: the RoleDef of u's custom role, when known
 */
export function mayManageAccount(u, o = {}) {
  const self = me();
  if (!u || !self || !can(o.need || 'users.manage')) return false;
  if (u.role === 'owner' && self.role !== 'owner') return false;
  if (isAdmin()) return true;
  if (u.id === self.id || u.role === 'admin' || u.role === 'owner') return false;
  if (isCustomRoleId(u.role_id) && o.role && o.role.delegable === false) return false;
  return (Array.isArray(u.permissions) ? u.permissions : []).filter(isServerPermission).every((p) => can(p));
}

/**
 * Ask before giving account `u` the role `to` (a RoleDef): what they lose, and what changes with the base (the
 * personal space) and with server permissions (the Admin area, two-factor authentication).
 * @param {any} u core.User
 * @param {any} to core.RoleDef
 * @returns {Promise<boolean>}
 */
export function confirmRoleChange(u, to) {
  const who = u.display_name || u.username;
  const from = u.role_name || BUILTIN_ROLE_NAMES[u.role_id || u.role] || u.role || 'Member';
  const fromBase = u.role;
  const toBase = to.base || to.id;
  const lines = [`They lose their current role ${from}.`];
  if (fromBase === 'guest' && toBase !== 'guest') lines.push('They get a personal “My files” space and can create share links.');
  const losesSpace = fromBase !== 'guest' && toBase === 'guest';
  if (losesSpace) lines.push('They lose their personal “My files” space. This only works while it is empty: move or delete their files (including the trash) first.');
  const nowStaff = to.id === 'owner' || to.id === 'admin' || roleIsStaff(to);
  if (!userIsStaff(u) && nowStaff) lines.push('They will see the Admin area. Two-factor authentication may be required.');
  if (userIsStaff(u) && !nowStaff) lines.push('They will no longer see the Admin area.');
  return confirm({
    title: `Give ${who} the role ${to.name}?`,
    message: h('div', { class: 'stack-sm' }, lines.map((l) => h('p', { text: l }))),
    confirmLabel: 'Change role',
    danger: losesSpace,
  });
}

/**
 * Where a shared item lives: "Team · Design / Reports" (the folders above it, starting with the team folder or the
 * personal space it is in). core.Grant with the derived node fields of GET /admin/grants and the Access card.
 * @param {any} g
 */
export function grantLocation(g) {
  const parts = String(g.node_path || '').split('/').filter(Boolean);
  parts.pop(); // the item itself
  const kind = g.space_kind === 'group' ? 'Team' : g.space_kind === 'user' ? 'Personal files' : '';
  return [kind, parts.join(' / ')].filter(Boolean).join(' · ') || g.space_name || '';
}

/** Access levels of a share with a person, group or role (core.Grant role) → labels. @type {Record<string, string>} */
export const GRANT_LEVELS = { viewer: 'Can view', editor: 'Can edit', manager: 'Can manage' };

/**
 * Role picker for giving someone a role: a select() control with the groups *Built-in* (Member and Guest; Admin for
 * owners and admins; Owner for owners) and *Custom roles* ("Finance · based on Member"). Roles the caller may not
 * give (RoleDef.assignable false) stay listed but disabled, with the reason. Below it the chosen role's description
 * and a link to what it can do. value() is the role id — send it as `role_id`.
 * @param {{label: string, name?: string, value?: string | null, roles: any[], help?: string, required?: boolean,
 *   placeholder?: string, exclude?: string[], builtins?: string[], disabled?: boolean, hideLabel?: boolean,
 *   onChange?: (id: string, role: any) => void}} o
 *   placeholder: an empty first option (a required choice without a default); exclude: role ids to leave out;
 *   builtins: the built-in roles offered (default: member, guest and what the caller's own role allows)
 * @returns {import('../../components/field.js').Control & {input: HTMLSelectElement, selected: () => any}}
 */
export function roleSelect(o) {
  const self = me();
  const offered = new Set(o.builtins || ['member', 'guest', ...(isAdmin() ? ['admin'] : []), ...(self?.role === 'owner' ? ['owner'] : [])]);
  const exclude = new Set(o.exclude || []);
  const byId = new Map((o.roles || []).map((r) => [String(r.id), r]));
  const value = o.value ?? '';
  /** Why the caller cannot give `r` ('' when they can). @param {any} r */
  const blockedBy = (r) => {
    const custom = isCustomRoleId(r.id);
    if (!custom && !offered.has(String(r.id))) return r.id === 'owner' ? 'only owners can give it' : 'only administrators can give it';
    if (r.assignable === false) return custom && !r.delegable ? 'only administrators can give it' : 'needs permissions you don’t have';
    return '';
  };
  /** @param {any} r */
  const option = (r) => {
    const name = isCustomRoleId(r.id) ? `${r.name} · ${roleBaseText(r).toLowerCase()}` : r.name || BUILTIN_ROLE_NAMES[r.id] || r.id;
    const why = blockedBy(r);
    return { value: String(r.id), label: why ? `${name} — ${why}` : name, disabled: !!why };
  };
  // the current value stays visible even when the caller could not give it (an owner seen by an admin)
  const builtins = ['member', 'guest', 'admin', 'owner'].filter((id) => !exclude.has(id) && (offered.has(id) || id === value))
    .map((id) => option(byId.get(id) || { id, name: BUILTIN_ROLE_NAMES[id], builtin: true, base: id }));
  const customs = (o.roles || []).filter((r) => isCustomRoleId(r.id) && !exclude.has(r.id)).map(option);
  /** @type {any[]} */
  const options = [
    ...(o.placeholder ? [{ value: '', label: o.placeholder }] : []),
    { label: 'Built-in', options: builtins },
    ...(customs.length ? [{ label: 'Custom roles', options: customs }] : []),
  ];
  const c = select({
    label: o.label,
    name: o.name,
    options,
    value,
    required: o.required,
    disabled: o.disabled,
    hideLabel: o.hideLabel,
    help: ' ', // filled below: the fixed help, the chosen role's description and a link to it
    onChange: (id) => {
      describe();
      o.onChange?.(id, byId.get(id) || null);
    },
  });
  const helpP = /** @type {HTMLElement} */ (c.el.querySelector('.field-help'));
  helpP.classList.add('role-help');
  const describe = () => {
    const r = byId.get(c.input.value);
    replace(helpP,
      o.help ? h('span', { class: 'role-help-text', text: o.help }) : null,
      r?.description ? h('span', { class: 'role-help-text', text: r.description }) : null,
      r && can('users.view') ? h('a', { class: 'role-help-link', href: `/admin/roles/${encodeURIComponent(r.id)}`, attrs: { target: '_blank', rel: 'noopener' }, text: 'What can this role do?' }) : null);
    helpP.hidden = !helpP.childElementCount;
  };
  describe();
  return { ...c, selected: () => byId.get(c.input.value) || null };
}

/**
 * Permissions as chips grouped like the catalog; high-impact ones are warning badges. Labels, groups and impact come
 * from `catalog` (GET /admin/capabilities); without it (pages that cannot load the catalog, or before it arrives)
 * the labels come from core/perms.js and the chips fall into two groups, account and server.
 * @param {string[]} perms permission names
 * @param {any} [catalog] core.CapabilityCatalog
 * @param {{max?: number, empty?: string}} [o] max: chips shown before a "+N more" chip
 */
export function permissionChips(perms, catalog, o = {}) {
  const list = (perms || []).map(String);
  if (!list.length) return h('span', { class: 'subtle', text: o.empty || 'No permissions' });
  /** @type {Map<string, any>} */
  const info = new Map((catalog?.items || []).map((/** @type {any} */ i) => [i.name, i]));
  /** @type {{id: string, label: string}[]} */
  const groups = catalog?.groups?.length ? catalog.groups : [{ id: 'account', label: 'Sharing & account' }, { id: 'server', label: 'Server' }];
  /** @param {string} p */
  const groupOf = (p) => {
    const g = info.get(p)?.group;
    if (g && groups.some((x) => x.id === g)) return g;
    if (catalog?.groups?.length) return 'other';
    return isServerPermission(p) ? 'server' : 'account';
  };
  const order = [...groups, { id: 'other', label: 'Other' }];
  const max = o.max || 0;
  let shown = 0;
  /** @type {string[]} */
  const rest = [];
  const out = h('div', { class: 'perm-chips' });
  for (const g of order) {
    const inGroup = list.filter((p) => groupOf(p) === g.id);
    if (!inGroup.length) continue;
    const chipsEl = h('ul', { class: 'perm-chip-list', attrs: { role: 'list' } });
    for (const p of inGroup) {
      const it = info.get(p);
      const label = it?.label || PERMISSION_LABELS[p] || p;
      if (max && shown >= max) {
        rest.push(label);
        continue;
      }
      shown += 1;
      chipsEl.appendChild(h('li', null, badge({ text: label, kind: it?.high_impact ? 'warning' : 'neutral', icon: it?.high_impact ? 'alert-triangle' : undefined, title: it?.high_impact ? `High impact: ${it.warning || it.description || ''}` : it?.description })));
    }
    if (chipsEl.childElementCount) out.appendChild(h('div', { class: 'perm-chip-group' }, h('span', { class: 'perm-chip-group-label', text: g.label }), chipsEl));
  }
  if (rest.length) out.appendChild(h('span', { class: 'chip chip--more', text: `+${rest.length} more`, title: rest.join(', ') }));
  return out;
}

/**
 * Days until `ts` (negative when past); null when unknown.
 * @param {string | number | Date | null | undefined} ts
 */
export function daysLeft(ts) {
  const d = toDate(ts);
  if (!d) return null;
  return Math.floor((d.getTime() - Date.now()) / 86_400_000);
}

/**
 * Badge describing an expiry ("expired", "12 days left", "expires in 11 months").
 * @param {string | number | Date | null | undefined} ts
 * @param {number} [warnDays] warning below this many days
 */
export function expiryBadge(ts, warnDays = 30) {
  const n = daysLeft(ts);
  if (n === null) return badge({ text: 'no expiry', kind: 'neutral' });
  if (n < 0) return badge({ text: 'expired', kind: 'danger', icon: 'alert-circle', title: dateTime(ts) });
  if (n < warnDays) return badge({ text: n === 0 ? 'expires today' : `${n} day${n === 1 ? '' : 's'} left`, kind: n < 7 ? 'danger' : 'warning', icon: 'clock', title: dateTime(ts) });
  return badge({ text: `valid ${relTime(ts).replace(/^in /, 'for ')}`, kind: 'success', title: dateTime(ts) });
}

/**
 * <time> with a relative label and the absolute date as tooltip.
 * @param {string | number | Date | null | undefined} ts
 * @param {{absolute?: boolean}} [o]
 */
export function timeEl(ts, o = {}) {
  const d = toDate(ts);
  if (!d) return h('span', { class: 'subtle', text: '—' });
  return h('time', { attrs: { datetime: d.toISOString(), title: dateTime(d, { seconds: true }) }, text: o.absolute ? dateTime(d) : relTime(d) });
}

/**
 * Display name for a user-ish object.
 * @param {any} u
 */
export function userLabel(u) {
  if (!u) return '—';
  return u.display_name ? `${u.display_name} (${u.username})` : u.username || u.id || '—';
}

/**
 * Round initials avatar.
 * @param {any} u user-ish {display_name, username}
 * @param {number} [size]
 */
export function avatarEl(u, size = 32) {
  const el = h('span', { class: 'user-avatar', attrs: { 'aria-hidden': 'true' }, text: initials(u?.display_name || u?.username || '?') });
  el.style.setProperty('--avatar-size', `${size}px`);
  // stable hue per user so avatars are distinguishable
  let hash = 0;
  for (const ch of String(u?.id || u?.username || '')) hash = (hash * 31 + ch.charCodeAt(0)) >>> 0;
  el.style.setProperty('--avatar-hue', String(hash % 360));
  return el;
}

/**
 * Avatar + name + secondary line.
 * @param {any} u
 * @param {Child} [secondary] defaults to "@username · email"
 */
export function userCell(u, secondary) {
  const name = u?.display_name || u?.username || '—';
  // Each entry carries its own leading "·" (one element), so when the line wraps on a phone the separator
  // travels with the entry it introduces instead of dangling at the end of a line — see admin.css.
  const parts = [u?.display_name ? `@${u.username}` : '', u?.email || ''].filter(Boolean);
  const sub = secondary !== undefined ? secondary : (parts.length
    ? parts.map((p, i) => h('span', { class: 'user-cell-sub-item' },
      i ? h('span', { class: 'user-cell-sub-sep', attrs: { 'aria-hidden': 'true' }, text: '·' }) : null,
      h('span', { text: p })))
    : '');
  return h('span', { class: 'user-cell' },
    avatarEl(u),
    h('span', { class: 'user-cell-text' },
      h('span', { class: 'user-cell-name', text: name }),
      sub && (!Array.isArray(sub) || sub.length) ? h('span', { class: 'user-cell-sub' }, sub) : null));
}

/**
 * List of monospace chips (SANs, CIDRs, scopes, …).
 * @param {(string | null | undefined)[]} list
 * @param {{empty?: string, max?: number}} [o]
 */
export function chips(list, o = {}) {
  const items = (list || []).filter(Boolean).map(String);
  if (!items.length) return h('span', { class: 'subtle', text: o.empty || 'none' });
  const max = o.max || 0;
  const shown = max && items.length > max ? items.slice(0, max) : items;
  return h('ul', { class: 'chip-list', attrs: { role: 'list' } },
    shown.map((s) => h('li', { class: 'chip', text: s })),
    shown.length < items.length ? h('li', { class: 'chip chip--more', text: `+${items.length - shown.length} more`, title: items.slice(shown.length).join(', ') }) : null);
}

/**
 * Pretty-printed JSON block (details, params, results).
 * @param {any} v
 */
export function jsonBlock(v) {
  let text = '';
  try {
    text = typeof v === 'string' ? v : JSON.stringify(v, null, 2);
  } catch {
    text = String(v);
  }
  return h('pre', { class: 'json-block', attrs: { tabindex: '0' } }, h('code', { text: text || '{}' }));
}

/**
 * "⋮" button that opens a menu.
 * @param {import('../../components/menu.js').MenuItem[] | (() => import('../../components/menu.js').MenuItem[])} items
 * @param {string} [label]
 */
export function moreMenu(items, label = 'More actions') {
  return iconButton({
    icon: 'more-vertical',
    label,
    size: 'sm',
    attrs: { 'aria-haspopup': 'menu' },
    onClick: (e) => {
      menu({ anchor: /** @type {Element} */ (e.currentTarget), items: typeof items === 'function' ? items() : items, align: 'end', title: label });
    },
  });
}

/** @param {number} ms */
export const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

/**
 * Debounce a function.
 * @template {(...a: any[]) => void} F
 * @param {F} fn
 * @param {number} ms
 * @returns {F & {cancel: () => void}}
 */
export function debounce(fn, ms) {
  let t = 0;
  const d = /** @type {any} */ ((/** @type {any[]} */ ...args) => {
    window.clearTimeout(t);
    t = window.setTimeout(() => fn(...args), ms);
  });
  d.cancel = () => window.clearTimeout(t);
  return d;
}

/**
 * Subscribe to server events; returns one function that unsubscribes all.
 * @param {string[]} topics
 * @param {(data: any, topic: string) => void} fn
 */
export function onEvents(topics, fn) {
  const offs = topics.map((t) => events.on(t, fn));
  return () => offs.forEach((off) => off());
}

/**
 * A form in a modal dialog. Resolves with the value returned by onSubmit (true when it returned undefined), or
 * undefined when the dialog was cancelled. onSubmit may return false to keep the dialog open; thrown ApiErrors are
 * shown inline (field errors via ApiError.field) by form().
 * @param {{title: string, intro?: Child, fields: any[], submitLabel?: string, submitIcon?: string,
 *   submitVariant?: 'primary' | 'danger', size?: 'sm' | 'md' | 'lg', onSubmit: (values: Record<string, any>) => any,
 *   onOpen?: (f: ReturnType<typeof form>) => void}} o
 * @returns {Promise<any>}
 */
export function formDialog(o) {
  return new Promise((resolve) => {
    /** @type {ReturnType<typeof form>} */
    const f = form({
      fields: o.fields,
      submitLabel: o.submitLabel,
      submitIcon: o.submitIcon,
      submitVariant: o.submitVariant,
      cancel: () => d.close(undefined),
      onSubmit: async (v) => {
        const r = await o.onSubmit(v);
        if (r === false) return;
        d.close(r === undefined ? true : r);
      },
    });
    const d = dialog({
      title: o.title,
      size: o.size || 'md',
      body: h('div', { class: 'stack' }, typeof o.intro === 'string' ? h('p', { class: 'muted', text: o.intro }) : o.intro ?? null, f.el),
      onClose: (v) => resolve(v),
    });
    d.open();
    o.onOpen?.(f);
  });
}

/**
 * Confirmation for destructive, hard-to-undo operations: the user must type `expected`.
 * @param {{title: string, message: Child, expected: string, confirmLabel?: string, danger?: boolean}} o
 * @returns {Promise<boolean>}
 */
export function confirmTyped(o) {
  return new Promise((resolve) => {
    const input = field({
      label: `Type “${o.expected}” to confirm`,
      name: 'confirm',
      autocomplete: 'off',
      attrs: { spellcheck: 'false', autocapitalize: 'off' },
    });
    const go = button({ label: o.confirmLabel || 'Confirm', variant: o.danger === false ? 'primary' : 'danger', disabled: true, onClick: () => d.close(true) });
    input.input.addEventListener('input', () => {
      go.disabled = input.input.value.trim() !== o.expected;
    });
    input.input.addEventListener('keydown', (e) => {
      if (/** @type {KeyboardEvent} */ (e).key === 'Enter' && !go.disabled) {
        e.preventDefault();
        d.close(true);
      }
    });
    const d = dialog({
      title: o.title,
      size: 'sm',
      body: h('div', { class: 'stack' }, typeof o.message === 'string' ? h('p', { text: o.message }) : o.message, input.el),
      actions: [{ label: 'Cancel', variant: 'ghost', value: false }, go],
      onClose: (v) => resolve(v === true),
    });
    d.open();
    input.input.focus();
  });
}

/**
 * Search-as-you-type user picker (admin pages): GET /admin/users?q= with "View people", else (and on a 403)
 * GET /users/lookup?q=.
 * Behaves like a form control: value() is the selected user id ('' when nothing is picked).
 * @param {{label: string, name?: string, help?: string, required?: boolean, exclude?: string[], placeholder?: string,
 *   onPick?: (u: any) => void}} o
 * @returns {import('../../components/field.js').Control & {selected: () => any, clear: () => void}}
 */
export function userPicker(o) {
  const listId = uniqueId('users');
  /** @type {any} */
  let picked = null;
  /** @type {any[]} */
  let results = [];
  let active = -1;
  let seq = 0;
  const c = field({
    label: o.label,
    name: o.name,
    type: 'search',
    help: o.help || 'Type at least 2 letters of a name, username or email.',
    required: o.required,
    autocomplete: 'off',
    placeholder: o.placeholder || 'Search users…',
    attrs: { role: 'combobox', 'aria-autocomplete': 'list', 'aria-expanded': 'false', 'aria-controls': listId, spellcheck: 'false', autocapitalize: 'off' },
  });
  const input = /** @type {HTMLInputElement} */ (c.input);
  const list = h('ul', { class: 'picker-list', id: listId, hidden: true, attrs: { role: 'listbox', 'aria-label': o.label } });
  const chosen = h('div', { class: 'picker-chosen', hidden: true });
  c.el.classList.add('picker');
  append(c.el, list, chosen);

  const close = () => {
    list.hidden = true;
    input.setAttribute('aria-expanded', 'false');
    input.removeAttribute('aria-activedescendant');
    active = -1;
  };
  const setActive = (/** @type {number} */ i) => {
    const opts = [...list.querySelectorAll('[role="option"]')];
    if (!opts.length) return;
    active = (i + opts.length) % opts.length;
    opts.forEach((el, j) => el.setAttribute('aria-selected', String(j === active)));
    input.setAttribute('aria-activedescendant', opts[active].id);
    opts[active].scrollIntoView({ block: 'nearest' });
  };
  const pick = (/** @type {any} */ u) => {
    picked = u;
    input.value = u.display_name ? `${u.display_name} (${u.username})` : u.username;
    input.setCustomValidity('');
    c.setError(null);
    close();
    chosen.hidden = false;
    replace(chosen, userCell(u), button({ label: 'Change', size: 'sm', variant: 'ghost', onClick: () => clear(true) }));
    input.hidden = true;
    o.onPick?.(u);
  };
  const clear = (/** @type {boolean} */ focus) => {
    picked = null;
    input.hidden = false;
    input.value = '';
    input.setCustomValidity('');
    chosen.hidden = true;
    replace(chosen);
    if (focus) input.focus();
  };
  const render = () => {
    const exclude = new Set(o.exclude || []);
    const rows = results.filter((u) => u && u.id && !exclude.has(u.id)).slice(0, 12);
    if (!rows.length) {
      replace(list, h('li', { class: 'picker-empty', attrs: { role: 'presentation' }, text: 'No matching users.' }));
    } else {
      replace(list, ...rows.map((u, i) => h('li', {
        id: `${listId}-${i}`,
        class: 'picker-option',
        attrs: { role: 'option', 'aria-selected': 'false' },
        on: {
          mousedown: (e) => e.preventDefault(), // keep focus in the input
          click: () => pick(u),
        },
      }, userCell(u))));
    }
    list.hidden = false;
    input.setAttribute('aria-expanded', 'true');
    active = -1;
  };
  const search = debounce(async () => {
    const q = input.value.trim();
    const mine = ++seq;
    if (q.length < 2) {
      close();
      return;
    }
    try {
      // the account list needs "View people"; the directory search is what everyone else may use
      const lookup = () => api.get('/users/lookup', { query: { q }, handle: false });
      /** @type {any} */
      let res;
      if (!can('users.view')) {
        res = await lookup();
      } else {
        try {
          res = await api.get('/admin/users', { query: { q, limit: 12 }, handle: false });
        } catch (err) {
          if (!(err instanceof ApiError) || err.status !== 403) throw err;
          res = await lookup();
        }
      }
      if (mine !== seq) return;
      results = itemsOf(res);
      render();
    } catch (err) {
      if (mine !== seq) return;
      replace(list, h('li', { class: 'picker-empty', attrs: { role: 'presentation' }, text: errorMessage(err) }));
      list.hidden = false;
    }
  }, 200);
  input.addEventListener('input', () => {
    picked = null;
    // Typed text is not a choice: value() stays '' until an option is picked, so an optional picker would
    // otherwise submit "nobody" while showing a name. Native validation (form.js) stops the submit instead.
    input.setCustomValidity(input.value.trim() ? 'Pick a person from the list, or clear this field.' : '');
    search();
  });
  input.addEventListener('keydown', (e) => {
    const k = /** @type {KeyboardEvent} */ (e).key;
    if (k === 'ArrowDown') { e.preventDefault(); if (list.hidden) search(); else setActive(active + 1); }
    else if (k === 'ArrowUp') { e.preventDefault(); setActive(active - 1); }
    else if (k === 'Enter' && !list.hidden) {
      // Enter picks the highlighted option, or the only one shown
      const opts = list.querySelectorAll('[role="option"]');
      const i = active >= 0 ? active : opts.length === 1 ? 0 : -1;
      if (i >= 0) {
        e.preventDefault();
        /** @type {HTMLElement | null} */ (opts[i])?.click();
      }
    } else if (k === 'Escape' && !list.hidden) { e.preventDefault(); e.stopPropagation(); close(); }
  });
  input.addEventListener('blur', () => setTimeout(close, 150));

  return {
    el: c.el,
    input,
    name: o.name,
    setError: (msg) => {
      if (input.hidden && msg) clear(false);
      c.setError(msg);
    },
    value: () => (picked ? picked.id : ''),
    selected: () => picked,
    clear: () => clear(false),
  };
}

/**
 * Quota control: "Default" / "Unlimited" / "Custom size". value() → null (default), 0 (unlimited), bytes, or NaN
 * (invalid custom size; the size input then reports a validation error).
 * @param {{label: string, name?: string, value?: number | null, help?: string, defaultLabel?: string, allowDefault?: boolean}} o
 * @returns {import('../../components/field.js').Control}
 */
export function quotaField(o) {
  const allowDefault = o.allowDefault !== false;
  const initial = o.value === undefined || o.value === null ? (allowDefault ? 'default' : 'unlimited') : o.value === 0 ? 'unlimited' : 'custom';
  const size = field({
    label: 'Size',
    hideLabel: true,
    value: o.value && o.value > 0 ? sizeInput(o.value) : '',
    placeholder: 'e.g. 50 GB',
    attrs: { inputmode: 'decimal', spellcheck: 'false' },
  });
  const mode = select({
    label: o.label,
    name: o.name ? `${o.name}_mode` : undefined,
    help: o.help,
    value: initial,
    options: [
      ...(allowDefault ? [{ value: 'default', label: o.defaultLabel || 'Server default' }] : []),
      { value: 'unlimited', label: 'Unlimited' },
      { value: 'custom', label: 'Custom size…' },
    ],
    onChange: () => sync(),
  });
  const input = /** @type {HTMLInputElement} */ (size.input);
  const sync = () => {
    const custom = mode.input.value === 'custom';
    size.el.hidden = !custom;
    input.required = custom;
    if (custom && !size.el.dataset.touched) {
      size.el.dataset.touched = '1';
      setTimeout(() => input.focus(), 0);
    }
  };
  const validate = () => {
    if (mode.input.value !== 'custom') {
      input.setCustomValidity('');
      return;
    }
    const n = parseSize(input.value);
    input.setCustomValidity(n === null ? 'Enter a size such as 50 GB.' : Number.isNaN(n) || n <= 0 ? 'Use a number with an optional unit (KB, MB, GB, TB).' : '');
  };
  input.addEventListener('input', validate);
  size.el.dataset.touched = initial === 'custom' ? '1' : '';
  sync();
  const el = h('div', { class: 'quota-field' }, mode.el, size.el);
  return {
    el,
    input,
    name: o.name,
    setError: (m) => (mode.input.value === 'custom' ? size.setError(m) : mode.setError(m)),
    value: () => {
      validate();
      const m = mode.input.value;
      if (m === 'default') return null;
      if (m === 'unlimited') return 0;
      const n = parseSize(input.value);
      return n === null || Number.isNaN(n) ? Number.NaN : n;
    },
  };
}

/**
 * Human text for a quota value (see quotaField).
 * @param {number | null | undefined} q
 * @param {string} [dflt]
 */
export function quotaText(q, dflt = 'Server default') {
  if (q === null || q === undefined) return dflt;
  if (q === 0) return 'Unlimited';
  return bytes(q);
}

/**
 * Current user (from the session store or boot data).
 * @returns {any}
 */
export function me() {
  return session.peek()?.user || boot().user || null;
}

/**
 * Make sure the session is elevated (step-up) — for operations whose request cannot simply be retried by api.js
 * (streamed uploads, browser-navigation downloads). Resolves false when the user cancelled.
 * @param {number} [marginMs] require at least this much remaining elevation time
 * @returns {Promise<boolean>}
 */
export async function ensureElevated(marginMs = 60_000) {
  try {
    const m = await api.get('/me', { handle: false });
    if (m && typeof m.csrf === 'string' && m.csrf) setCsrf(m.csrf);
    const until = m?.elevated_until ? new Date(m.elevated_until).getTime() : 0;
    if (until - Date.now() > marginMs) return true;
    if (m?.via && m.via !== 'session') return true; // tokens/socket cannot elevate interactively
  } catch { /* fall through to the prompt */ }
  return promptElevation();
}

/**
 * Download a file that sits behind RequireElevated with a plain browser navigation (keeps native progress and
 * streaming): probe with HEAD first (HEAD reaches GET handlers without side effects), prompt for elevation when the
 * server asks for it, then navigate.
 * @param {string} url absolute path, e.g. "/api/v1/admin/backups/bak_x/download"
 * @returns {Promise<boolean>}
 */
export async function elevatedDownload(url) {
  for (let attempt = 0; attempt < 2; attempt += 1) {
    /** @type {Response} */
    let res;
    try {
      res = await api.raw(url, { method: 'HEAD' });
    } catch {
      toast.error('Cannot reach the server.');
      return false;
    }
    if (res.ok) {
      nativeDownload(url);
      return true;
    }
    if (res.status === 403 && attempt === 0) {
      // HEAD has no body: assume elevation is what is missing (the only 403 an admin gets here)
      if (!(await promptElevation())) return false;
      continue;
    }
    toast.error(res.status === 404 ? 'That file is no longer available.' : `Download failed (${res.status}).`);
    return false;
  }
  return false;
}

/**
 * Start a browser download of a same-origin URL (native progress, streaming).
 * @param {string} url
 */
export function nativeDownload(url) {
  const a = h('a', { href: url, class: 'hidden', attrs: { download: '', 'data-native': true } });
  document.body.appendChild(a);
  a.click();
  a.remove();
}

/**
 * A secret that is shown exactly once (recovery key, token, generated password, age identity, …).
 * The dialog cannot be dismissed until the user confirms they stored it.
 * @param {{title: string, intro?: Child, secret: string, label?: string, filename?: string,
 *   warning?: string, warningTitle?: string, multiline?: boolean, extra?: Child, what?: string, fileContent?: string}} o
 *   fileContent: what the .txt download contains (defaults to the secret); warningTitle: for secrets the server
 *   can show again (default "Shown only once")
 * @returns {Promise<void>}
 */
export function showSecretOnce(o) {
  return new Promise((resolve) => {
    const done = button({ label: 'I have stored it safely', variant: 'primary', icon: 'check', disabled: true, onClick: () => d.close(true) });
    const ack = checkbox({ label: 'I copied or downloaded this and stored it somewhere safe.', onChange: (on) => { done.disabled = !on; } });
    const lines = o.secret.split('\n');
    // short one-per-line secrets (recovery codes) are laid out in columns
    const columns = o.multiline && lines.length >= 4 && lines.every((l) => l.length <= 24);
    const secretEl = o.multiline
      ? h('pre', { class: ['secret-block', columns && 'secret-block--columns'], attrs: { tabindex: '0', 'aria-label': o.label || 'Secret' } }, h('code', { text: o.secret }))
      : copyField({ label: o.label || 'Secret', value: o.secret, what: o.what || o.label });
    const tools = [
      o.multiline ? button({ label: 'Copy', icon: 'copy', size: 'sm', onClick: () => copyText(o.secret, o.what || o.label || 'Secret') }) : null,
      o.filename ? button({ label: 'Download as .txt', icon: 'download', size: 'sm', onClick: () => downloadBlob(/** @type {string} */ (o.filename), o.fileContent ?? `${o.secret}\n`) }) : null,
    ].filter(Boolean);
    const d = dialog({
      title: o.title,
      size: 'md',
      dismissible: false,
      body: h('div', { class: 'stack' },
        o.intro ? (typeof o.intro === 'string' ? h('p', { text: o.intro }) : o.intro) : null,
        alertEl('warning', o.warningTitle || 'Shown only once', o.warning || 'FileParcel does not keep a readable copy. If you lose it you will have to create a new one.'),
        secretEl,
        tools.length ? h('div', { class: 'cluster' }, tools) : null,
        o.extra || null,
        ack.el),
      actions: [done],
      onClose: () => resolve(),
    });
    d.open();
  });
}

/**
 * @typedef {Object} JobLike
 * @property {string} id
 * @property {string} [kind]
 * @property {string} [state]
 * @property {number} [progress_done]
 * @property {number} [progress_total]
 * @property {string} [note]
 * @property {string} [error]
 * @property {any} [result]
 */

const FINISHED = new Set(['succeeded', 'failed', 'canceled']);

/** @param {string | null | undefined} state */
export function jobFinished(state) {
  return FINISHED.has(String(state || ''));
}

/**
 * Follow a job until it finishes: SSE updates (core/store jobs) plus polling of GET /admin/jobs/{id}, or of
 * GET /jobs/{id} (the caller's own jobs) for non-admin pages and for roles without "Server status".
 * Resolves with the final job; rejects when `signal` aborts.
 * @param {string} jobId
 * @param {{onUpdate?: (j: JobLike) => void, signal?: AbortSignal, admin?: boolean, interval?: number}} [o]
 * @returns {Promise<JobLike>}
 */
export function trackJob(jobId, o = {}) {
  const own = o.admin === false || !can('system.view');
  const path = own ? `/jobs/${encodeURIComponent(jobId)}` : `/admin/jobs/${encodeURIComponent(jobId)}`;
  return new Promise((resolve, reject) => {
    let finished = false;
    let timer = 0;
    let lastSSE = 0;
    let failures = 0;
    // `jobs.subscribe()` below delivers the current map SYNCHRONOUSLY (core/store effect → obs.run()), so `handle()`
    // can run before the rest of this closure exists. A job that is already in a terminal state at that moment would
    // then hit the temporal dead zone of `cleanup`/`onAbort` (ReferenceError swallowed by effect()), the promise
    // would never settle and the subscription would leak. Everything `handle()` reaches is therefore either a
    // hoisted function declaration or assigned before the subscribe call.
    /** @type {() => void} */
    let off = () => {};
    /** @param {JobLike} j */
    function handle(j) {
      if (finished || !j) return;
      o.onUpdate?.(j);
      if (FINISHED.has(j.state || '')) {
        finished = true;
        cleanup();
        resolve(j);
      }
    }
    function cleanup() {
      off();
      window.clearTimeout(timer);
      o.signal?.removeEventListener('abort', onAbort);
    }
    function onAbort() {
      if (finished) return;
      finished = true;
      cleanup();
      reject(new ApiError(0, 'aborted', 'aborted'));
    }
    const poll = async () => {
      if (finished) return;
      if (Date.now() - lastSSE > 3000) {
        try {
          const j = await api.get(path, { handle: false, signal: o.signal });
          failures = 0;
          handle(j);
        } catch (err) {
          if (err instanceof ApiError && err.aborted) return;
          failures += 1;
          if ((err instanceof ApiError && err.status === 404) || failures > 40) {
            finished = true;
            cleanup();
            reject(err);
            return;
          }
        }
      }
      if (!finished) timer = window.setTimeout(poll, Math.min(10_000, (o.interval || 1500) * (failures ? 2 : 1)));
    };
    off = jobs.subscribe((map) => {
      const j = map.get(jobId);
      if (j) {
        lastSSE = Date.now();
        handle(/** @type {JobLike} */ (j));
      }
    });
    if (finished) {
      off(); // settled during the synchronous first delivery, when `off` was still the placeholder
      return;
    }
    o.signal?.addEventListener('abort', onAbort);
    poll();
  });
}

/**
 * Human label for a job kind ("backup.create" → "Backup").
 * @param {string} kind
 */
export function jobKindLabel(kind) {
  /** @type {Record<string, string>} */
  const names = {
    'upload.zip': 'Zip upload', 'thumbs.generate': 'Thumbnails', 'backup.create': 'Backup', 'backup.verify': 'Backup verification',
    'backup.prune': 'Backup pruning', 'keys.rotate_kek': 'Key rotation', 'keys.reencrypt': 'Data re-encryption',
    'maintenance.sessions': 'Session cleanup', 'maintenance.uploads': 'Upload cleanup', 'maintenance.trash': 'Trash cleanup',
    'maintenance.blob_gc': 'Storage garbage collection', 'maintenance.audit_prune': 'Audit log pruning',
    'maintenance.db_optimize': 'Database optimisation', 'maintenance.versions': 'Old versions cleanup', 'certs.renew_check': 'Certificate renewal check',
  };
  return names[kind] || kind || 'Job';
}

/**
 * Maintenance jobs an admin may start by hand (POST /admin/jobs/run {kind}), with explanations. These are exactly the
 * parameterless kinds the server accepts there (backups are started from the Backups page).
 * @type {{kind: string, label: string, text: string}[]}
 */
export const MAINTENANCE_JOBS = [
  { kind: 'maintenance.sessions', label: 'Clean up sessions', text: 'Removes expired sessions, download tickets and sign-in flows.' },
  { kind: 'maintenance.uploads', label: 'Expire stale uploads', text: 'Aborts unfinished uploads older than the upload expiry and frees their space.' },
  { kind: 'maintenance.trash', label: 'Empty old trash', text: 'Permanently deletes items that have been in the trash longer than the retention period.' },
  { kind: 'maintenance.versions', label: 'Prune old versions', text: 'Keeps only the configured number of versions per file.' },
  { kind: 'maintenance.blob_gc', label: 'Collect unused storage', text: 'Deletes encrypted blobs nothing refers to any more.' },
  { kind: 'maintenance.audit_prune', label: 'Prune audit log', text: 'Removes audit entries older than the retention period.' },
  { kind: 'maintenance.db_optimize', label: 'Optimise database', text: 'Runs SQLite optimisation and compacts the write-ahead log.' },
  { kind: 'certs.renew_check', label: 'Check certificates', text: 'Renews certificates that expire soon or whose names changed.' },
  { kind: 'backup.prune', label: 'Prune backups', text: 'Applies the backup retention policy now.' },
];

/**
 * Progress element that follows a job. `onDone(job)` runs once when it finishes.
 * @param {string} jobId
 * @param {{label?: string, onDone?: (j: JobLike) => void, signal?: AbortSignal}} [o]
 * @returns {HTMLElement}
 */
export function jobProgress(jobId, o = {}) {
  const bar = progress({ label: o.label || 'Working…', showValue: true });
  const note = h('span', { class: 'text-xs muted', attrs: { 'aria-live': 'polite' } });
  const el = h('div', { class: 'job-progress', dataset: { job: jobId } }, bar.el, note);
  const started = Date.now();
  trackJob(jobId, {
    signal: o.signal,
    onUpdate: (j) => {
      const total = Number(j.progress_total) || 0;
      const done = Number(j.progress_done) || 0;
      const label = `${o.label || jobKindLabel(j.kind || '')}${j.state === 'queued' ? ' — queued' : ''}`;
      bar.set(total > 0 ? done : null, total > 0 ? total : undefined, label);
      const elapsed = Date.now() - started;
      note.textContent = [j.note || '', total > 0 ? `${number(done)} of ${number(total)}` : '', elapsed > 3000 ? duration(elapsed) : ''].filter(Boolean).join(' · ');
    },
  }).then((j) => {
    el.dataset.state = j.state || '';
    if (j.state === 'succeeded') {
      bar.set(1, 1, `${o.label || jobKindLabel(j.kind || '')} — done`);
      note.textContent = j.note || '';
    } else {
      note.textContent = j.error ? `${j.state}: ${j.error}` : String(j.state);
    }
    o.onDone?.(j);
  }).catch((err) => {
    if (err instanceof ApiError && err.aborted) return;
    note.textContent = errorMessage(err);
  });
  return el;
}

/**
 * Restart the server (POST /admin/system/restart, elevated) and wait for it to come back.
 * The process exits with code 75 and the supervisor starts it again; without one (offline CLI) the server
 * answers 409. The page reloads when the new process answers, or goes to /unlock when it comes back sealed.
 * @param {{skipConfirm?: boolean, reason?: string}} [o]
 * @returns {Promise<boolean>}
 */
export async function restartServer(o = {}) {
  if (!o.skipConfirm) {
    const ok = await confirm({
      title: 'Restart FileParcel?',
      message: o.reason || 'Uploads and downloads in progress will be interrupted for a few seconds. Everyone stays signed in.',
      confirmLabel: 'Restart now',
    });
    if (!ok) return false;
  }
  /** @type {any} */
  let before = null;
  try { before = await api.get('/admin/system', { handle: false }); } catch { /* ignore */ }
  try {
    await api.post('/admin/system/restart', {});
  } catch (err) {
    if (err instanceof ApiError && err.status === 409) {
      toast.error('This server has no supervisor that could start it again. Restart it from the terminal (fileparcel service restart).');
    } else if (!(err instanceof ApiError && err.aborted)) {
      toast.error(err);
    }
    return false;
  }
  return waitForRestart({ before });
}

/**
 * Wait for a restart that is already under way (after POST /admin/system/restart, or a restore, which restarts
 * the server by itself), with a non-dismissible progress dialog. The page reloads when a new process answers,
 * goes to /unlock when it comes back sealed and to /login when this session is no longer valid (e.g. after a
 * restore).
 * @param {{before?: any, title?: string, startText?: string, timeoutMs?: number}} [o]
 *   before: GET /admin/system taken before the restart began (pid / started_at tell the new process apart)
 * @returns {Promise<boolean>}
 */
export async function waitForRestart(o = {}) {
  const before = o.before || null;
  const timeoutMs = o.timeoutMs || 180_000;
  const status = h('p', { class: 'muted', attrs: { 'aria-live': 'polite' }, text: o.startText || 'Waiting for the server to stop…' });
  const d = dialog({
    title: o.title || 'Restarting FileParcel',
    size: 'sm',
    dismissible: false,
    body: h('div', { class: 'stack restart-wait' }, spinner({ size: 'lg', label: 'Restarting' }), status),
  });
  d.open();
  const t0 = Date.now();
  let sawDown = false;
  while (Date.now() - t0 < timeoutMs) {
    await sleep(1500);
    try {
      const res = await fetch('/api/v1/admin/system', { credentials: 'same-origin', cache: 'no-store', headers: { Accept: 'application/json' } });
      if (res.status === 503) {
        const body = await res.json().catch(() => null);
        if (body?.error?.code === 'keys_locked') {
          location.assign(`/unlock?next=${encodeURIComponent(location.pathname)}`);
          return true;
        }
        sawDown = true;
        status.textContent = 'Starting up…';
        continue;
      }
      if (res.ok) {
        const info = await res.json().catch(() => null);
        const restarted = sawDown || (before && info && (info.pid !== before.pid || info.started_at !== before.started_at));
        if (restarted) {
          status.textContent = 'Back online. Reloading…';
          location.reload();
          return true;
        }
        status.textContent = 'Waiting for the server to stop…';
        continue;
      }
      if (res.status === 401) {
        location.assign(`/login?next=${encodeURIComponent(location.pathname)}`);
        return true;
      }
      sawDown = true;
    } catch {
      sawDown = true;
      status.textContent = 'Server is restarting…';
    }
  }
  const mins = Math.round(timeoutMs / 60_000);
  status.textContent = `The server did not come back within ${mins} minute${mins === 1 ? '' : 's'}. Check the service status on the machine (fileparcel status).`;
  d.actions.appendChild(button({ label: 'Reload page', variant: 'primary', onClick: () => location.reload() }));
  d.el.appendChild(d.actions);
  return false;
}

/**
 * Restart banner (for settings changes that need a restart). The "Restart now" button needs "Operate the server".
 * @param {string[]} keys
 */
export function restartBanner(keys) {
  if (!keys || !keys.length) return null;
  const mayRestart = can('system.manage');
  return alertEl('warning', 'Restart required',
    `Changes to ${keys.join(', ')} take effect after a restart.${mayRestart ? '' : ' Ask an administrator to restart the server.'}`,
    mayRestart ? button({ label: 'Restart now', icon: 'refresh', size: 'sm', onClick: () => restartServer() }) : null);
}

/**
 * Call `loadMore` when `sentinel` scrolls into view. Returns a disconnect function.
 * @param {Element} sentinel
 * @param {() => any} loadMore
 */
export function infiniteScroll(sentinel, loadMore) {
  let busy = false;
  const io = new IntersectionObserver(async (entries) => {
    if (busy || !entries.some((e) => e.isIntersecting)) return;
    busy = true;
    try {
      await loadMore();
    } finally {
      busy = false;
    }
  }, { rootMargin: '600px 0px' });
  io.observe(sentinel);
  return () => io.disconnect();
}

/**
 * Parse a size like "10 GB", "500m", "1.5t" into bytes (binary units). Empty → null; invalid → NaN.
 * @param {string} s
 * @returns {number | null}
 */
export function parseSize(s) {
  const v = String(s || '').trim().toLowerCase().replace(/,/g, '.');
  if (!v) return null;
  const m = /^(\d+(?:\.\d+)?)\s*([kmgtp]?)(?:i?b)?$/.exec(v);
  if (!m) return Number.NaN;
  const mult = { '': 1, k: 1024, m: 1024 ** 2, g: 1024 ** 3, t: 1024 ** 4, p: 1024 ** 5 }[/** @type {'' | 'k' | 'm' | 'g' | 't' | 'p'} */ (m[2])];
  return Math.round(Number(m[1]) * mult);
}

/**
 * Format bytes as an editable size string ("10 GB"), '' for null.
 * @param {number | null | undefined} n
 */
export function sizeInput(n) {
  if (n === null || n === undefined) return '';
  if (n === 0) return '0';
  const units = ['B', 'KB', 'MB', 'GB', 'TB', 'PB'];
  let i = 0;
  let v = n;
  while (v >= 1024 && i < units.length - 1 && Number.isInteger((v / 1024) * 100)) {
    v /= 1024;
    i += 1;
  }
  return `${Math.round(v * 100) / 100} ${units[i]}`;
}

/**
 * Local date-time input value ("2026-09-19T14:30") for a Date/ISO string.
 * @param {Date | string | number | null | undefined} d
 */
export function toLocalInput(d) {
  if (!d) return '';
  const x = new Date(d);
  if (Number.isNaN(x.getTime())) return '';
  const pad = (/** @type {number} */ n) => String(n).padStart(2, '0');
  return `${x.getFullYear()}-${pad(x.getMonth() + 1)}-${pad(x.getDate())}T${pad(x.getHours())}:${pad(x.getMinutes())}`;
}

/**
 * RFC 3339 string for a local date-time input value ('' → null).
 * @param {string} v
 */
export function fromLocalInput(v) {
  if (!v) return null;
  const d = new Date(v);
  return Number.isNaN(d.getTime()) ? null : d.toISOString();
}

/**
 * RFC 3339 timestamp `days` days from now.
 * @param {number} days
 */
export function daysFromNow(days) {
  return new Date(Date.now() + days * 86_400_000).toISOString();
}

/**
 * Describe a user agent string briefly ("Firefox on Linux").
 * @param {string | null | undefined} ua
 */
export function describeUA(ua) {
  const s = String(ua || '');
  if (!s) return 'Unknown device';
  if (/^fileparcel|Go-http-client/i.test(s)) return 'FileParcel CLI';
  if (/curl\//i.test(s)) return 'curl';
  const browser = /Edg\//.test(s) ? 'Edge' : /OPR\//.test(s) ? 'Opera' : /Brave/.test(s) ? 'Brave' : /Firefox\//.test(s) ? 'Firefox'
    : /Chrome\//.test(s) ? 'Chrome' : /Safari\//.test(s) ? 'Safari' : 'Browser';
  const os = /iPhone/.test(s) ? 'iPhone' : /iPad/.test(s) ? 'iPad' : /Android/.test(s) ? 'Android' : /Windows/.test(s) ? 'Windows'
    : /Mac OS X|Macintosh/.test(s) ? 'macOS' : /CrOS/.test(s) ? 'ChromeOS' : /Linux/.test(s) ? 'Linux' : '';
  return os ? `${browser} on ${os}` : browser;
}

/**
 * Device icon for a user agent.
 * @param {string | null | undefined} ua
 */
export function uaIcon(ua) {
  const s = String(ua || '');
  if (/iPhone|Android.*Mobile/.test(s)) return 'smartphone';
  if (/^fileparcel|curl|Go-http-client/i.test(s)) return 'terminal';
  if (/Windows|Macintosh|Linux|CrOS/.test(s)) return 'laptop';
  return 'monitor';
}

// ---------------------------------------------------------------------------------------------------------------
// IP / CIDR matching (client-side preview of the §10.3 access policy; the server is authoritative)
// ---------------------------------------------------------------------------------------------------------------

/**
 * Parse an IPv4/IPv6 address into {v: 4|6, n: BigInt}. IPv4-mapped IPv6 addresses are unmapped (§18.16).
 * Zone ids ("%eth0") and brackets are ignored. Returns null when invalid.
 * @param {string} s
 * @returns {{v: 4 | 6, n: bigint} | null}
 */
export function parseIP(s) {
  let str = String(s || '').trim().replace(/^\[|\]$/g, '').replace(/%.*$/, '');
  if (!str) return null;
  const v4 = (/** @type {string} */ x) => {
    const parts = x.split('.');
    if (parts.length !== 4) return null;
    let n = 0n;
    for (const p of parts) {
      if (!/^\d{1,3}$/.test(p) || Number(p) > 255) return null;
      n = (n << 8n) + BigInt(Number(p));
    }
    return n;
  };
  if (!str.includes(':')) {
    const n = v4(str);
    return n === null ? null : { v: 4, n };
  }
  // IPv6 (with optional trailing dotted IPv4)
  let tail = /** @type {bigint | null} */ (null);
  const lastColon = str.lastIndexOf(':');
  if (str.slice(lastColon + 1).includes('.')) {
    tail = v4(str.slice(lastColon + 1));
    if (tail === null) return null;
    str = `${str.slice(0, lastColon + 1)}${((tail >> 16n) & 0xffffn).toString(16)}:${(tail & 0xffffn).toString(16)}`;
  }
  const halves = str.split('::');
  if (halves.length > 2) return null;
  const head = halves[0] ? halves[0].split(':') : [];
  const rest = halves.length === 2 && halves[1] ? halves[1].split(':') : [];
  const missing = 8 - head.length - rest.length;
  if ((halves.length === 1 && missing !== 0) || missing < 0) return null;
  const groups = [...head, ...Array(halves.length === 2 ? missing : 0).fill('0'), ...rest];
  let n = 0n;
  for (const g of groups) {
    if (!/^[0-9a-f]{1,4}$/i.test(g)) return null;
    n = (n << 16n) + BigInt(parseInt(g, 16));
  }
  if (n >> 32n === 0xffffn) return { v: 4, n: n & 0xffffffffn }; // ::ffff:a.b.c.d
  return { v: 6, n };
}

/**
 * Parse a CIDR ("10.0.0.0/8", "fd7a:115c:a1e0::/48") or a single address.
 * @param {string} s
 * @returns {{v: 4 | 6, net: bigint, bits: number} | null}
 */
export function parseCIDR(s) {
  const [addr, len] = String(s || '').trim().split('/');
  const ip = parseIP(addr);
  if (!ip) return null;
  // "::ffff:10.0.0.0/104" style prefixes: the address was unmapped to IPv4, so drop the 96 mapping bits
  const mapped = ip.v === 4 && addr.includes(':');
  const written = mapped ? 128 : ip.v === 4 ? 32 : 128;
  let bits = len === undefined ? written : Number(len);
  if (!Number.isInteger(bits) || bits < 0 || bits > written) return null;
  if (mapped) bits = Math.max(0, bits - 96);
  const max = ip.v === 4 ? 32 : 128;
  const shift = BigInt(max - bits);
  return { v: ip.v, net: (ip.n >> shift) << shift, bits };
}

/**
 * @param {{v: 4 | 6, n: bigint}} ip
 * @param {{v: 4 | 6, net: bigint, bits: number}} c
 */
function inCIDR(ip, c) {
  if (ip.v !== c.v) return false;
  const shift = BigInt((ip.v === 4 ? 32 : 128) - c.bits);
  return (ip.n >> shift) << shift === c.net;
}

/** Private ranges of access mode "private" (§10.3). */
export const PRIVATE_CIDRS = ['127.0.0.0/8', '10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16', '169.254.0.0/16', '100.64.0.0/10', 'fc00::/7', 'fe80::/10', '::1/128'];

/**
 * Would `ip` be allowed by `policy`? Loopback is always allowed; deny wins (§10.3); mode "private" admits the
 * private ranges plus the allow list (like the server's matcher). null when `ip` is unknown.
 * @param {string} ip
 * @param {{mode: string, allow?: string[], deny?: string[]}} policy
 * @returns {boolean | null}
 */
export function ipAllowed(ip, policy) {
  const a = parseIP(ip);
  if (!a) return null;
  const loop = a.v === 4 ? inCIDR(a, /** @type {any} */ (parseCIDR('127.0.0.0/8'))) : a.n === 1n;
  if (loop) return true;
  for (const d of policy.deny || []) {
    const c = parseCIDR(d);
    if (c && inCIDR(a, c)) return false;
  }
  if (policy.mode === 'any') return true;
  const list = policy.mode === 'private' ? [...PRIVATE_CIDRS, ...(policy.allow || [])] : policy.allow || [];
  return list.some((x) => {
    const c = parseCIDR(x);
    return !!c && inCIDR(a, c);
  });
}

// ---------------------------------------------------------------------------------------------------------------
// raw requests with elevation, PKCS#12 downloads
// ---------------------------------------------------------------------------------------------------------------

/**
 * api.raw() with the automatic step-up of core/api.js: on 403 elevation_required prompt once and retry.
 * Throws an ApiError for non-2xx responses. Only for bodies that can be re-sent (not streams).
 * @param {string} path
 * @param {RequestInit} init
 * @returns {Promise<Response>}
 */
export async function rawElevated(path, init) {
  for (let attempt = 0; ; attempt += 1) {
    /** @type {Response} */
    let res;
    try {
      res = await api.raw(path, init);
    } catch {
      throw new ApiError(0, 'network', 'Cannot reach the server. Check your connection.');
    }
    if (res.ok) return res;
    const err = await errorFrom(res);
    if (attempt === 0 && res.status === 403 && err.code === 'elevation_required' && (await promptElevation())) continue;
    throw err;
  }
}

/**
 * Decode base64 (standard or URL alphabet) to bytes.
 * @param {string} s
 */
export function b64ToBytes(s) {
  const b64 = String(s || '').replace(/-/g, '+').replace(/_/g, '/').replace(/\s+/g, '');
  const bin = atob(b64 + '='.repeat((4 - (b64.length % 4)) % 4));
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i += 1) out[i] = bin.charCodeAt(i);
  return out;
}

/**
 * File name from a Content-Disposition header (RFC 6266 filename* preferred).
 * @param {string | null} cd
 * @param {string} fallback
 */
export function dispositionName(cd, fallback) {
  if (!cd) return fallback;
  const star = /filename\*\s*=\s*UTF-8''([^;]+)/i.exec(cd);
  if (star) {
    try { return decodeURIComponent(star[1].trim()); } catch { /* fall through */ }
  }
  const plain = /filename\s*=\s*"?([^";]+)"?/i.exec(cd);
  return plain ? plain[1].trim() : fallback;
}

/**
 * Issue a client certificate (POST /admin/client-certs or /me/client-certs with core.ClientCertInput) and save the
 * PKCS#12 file it returns exactly once. Accepts either a binary application/x-pkcs12 response or JSON
 * {cert|client_cert, p12|p12_base64|data, password?, filename?}.
 * @param {string} path
 * @param {{user_id?: string, name: string, days?: number, password: string, legacy?: boolean}} body
 * @returns {Promise<{cert: any, filename: string, password: string}>}
 */
export async function issueClientCert(path, body) {
  const res = await rawElevated(path, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', Accept: 'application/x-pkcs12, application/json' },
    body: JSON.stringify(body),
  });
  const ct = res.headers.get('Content-Type') || '';
  const safe = String(body.name || 'client').replace(/[^\w.-]+/g, '_').slice(0, 60) || 'client';
  let filename = dispositionName(res.headers.get('Content-Disposition'), `${safe}.p12`);
  let password = body.password;
  /** @type {any} */
  let cert = null;
  /** @type {Blob} */
  let blob;
  if (ct.includes('json')) {
    const j = await res.json();
    cert = j?.cert || j?.client_cert || null;
    if (typeof j?.password === 'string' && j.password) password = j.password;
    if (typeof j?.filename === 'string' && j.filename) filename = j.filename;
    const b64 = j?.p12 || j?.p12_base64 || j?.data || '';
    if (!b64) throw new ApiError(500, 'bad_response', 'The server did not return the certificate file.');
    blob = new Blob([b64ToBytes(b64)], { type: 'application/x-pkcs12' });
  } else {
    blob = await res.blob();
  }
  downloadBlob(filename, blob, 'application/x-pkcs12');
  return { cert, filename, password };
}

/**
 * After issuing a client certificate: show the import password once, with per-platform hints.
 * @param {{filename: string, password: string}} r
 */
export function showP12Password(r) {
  return showSecretOnce({
    title: 'Certificate downloaded',
    intro: h('div', { class: 'stack-sm' },
      h('p', null, 'The file ', h('strong', { class: 'break', text: r.filename }), ' was saved to your downloads. Import it with this password:'),
      h('ul', { class: 'hint-list' },
        h('li', { text: 'Windows / macOS: double-click the file and enter the password (macOS: add it to the “login” keychain).' }),
        h('li', { text: 'iPhone / Android: open the file (e.g. from Files or Downloads) and install it as a user / VPN & app certificate.' }),
        h('li', { text: 'Firefox: Settings → Privacy & Security → Certificates → View Certificates → Your Certificates → Import.' }))),
    secret: r.password,
    label: 'Import password',
    what: 'Password',
    warning: 'The certificate file and this password are shown only once. Store the file safely; anyone who has both can sign in as its owner.',
  });
}

// ---------------------------------------------------------------------------------------------------------------
// health checks (GET /admin/system/doctor) and audit action labels — used by the dashboard, system and audit pages
// ---------------------------------------------------------------------------------------------------------------

/**
 * @typedef {Object} Check
 * @property {string} name
 * @property {'ok' | 'warn' | 'fail' | 'info'} status
 * @property {string} message
 * @property {string} hint
 * @property {{href: string, label: string} | null} link
 */

/**
 * Normalise the doctor response: an array or {checks|items|results: […]} of objects with
 * {name|id|check|title, status|state|level|result|ok, message|detail|details|summary, hint|fix|remedy|action, link|href}.
 * @param {any} res
 * @returns {Check[]}
 */
export function doctorChecks(res) {
  const list = Array.isArray(res) ? res : res?.checks || res?.items || res?.results || [];
  if (!Array.isArray(list)) return [];
  return list.filter((c) => c && typeof c === 'object').map((c) => {
    const raw = String(c.status ?? c.state ?? c.level ?? c.result ?? (c.ok === true ? 'ok' : c.ok === false ? 'fail' : 'info')).toLowerCase();
    /** @type {Check['status']} */
    const status = /^(ok|pass|passed|good|success|healthy)$/.test(raw) ? 'ok'
      : /^(warn|warning|degraded)$/.test(raw) ? 'warn'
        : /^(fail|failed|error|critical|bad|down)$/.test(raw) ? 'fail' : 'info';
    const name = String(c.title || c.name || c.check || c.id || 'Check');
    const message = String(c.message || c.detail || c.summary || (typeof c.details === 'string' ? c.details : '') || '');
    const hint = String(c.hint || c.fix || c.remedy || c.action || '');
    const href = typeof c.link === 'string' && c.link.startsWith('/') ? c.link : typeof c.href === 'string' && c.href.startsWith('/') ? c.href : '';
    const target = href ? { href, label: 'Open' } : linkFor(`${c.id || ''} ${name} ${message}`);
    // a delegate with system.view sees every check, but gets a button only to the pages their role includes
    const link = target && pathAllowed(target.href) ? target : null;
    return { name, status, message, hint, link };
  });
}

/**
 * One health check row.
 * @param {Check} c
 */
export function healthRow(c) {
  const ic = { ok: 'check-circle', warn: 'alert-triangle', fail: 'x-circle', info: 'info' }[c.status];
  return h('li', { class: 'health-row', dataset: { status: c.status } },
    h('span', { class: 'health-icon', attrs: { 'aria-hidden': 'true' } }, icon(ic)),
    h('span', { class: 'health-text' },
      h('span', { class: 'health-name', text: c.name }),
      c.message ? h('span', { class: 'health-msg', text: c.message }) : null,
      c.hint && c.status !== 'ok' ? h('span', { class: 'health-hint', text: c.hint }) : null),
    c.link && c.status !== 'ok' ? h('a', { class: 'btn btn--secondary btn--sm', href: c.link.href, text: c.link.label }) : h('span', { class: 'sr-only', text: c.status }));
}

/**
 * The admin page that fixes a problem described by `text` (heuristic keyword match).
 * @param {string} text
 * @returns {{href: string, label: string} | null}
 */
export function linkFor(text) {
  const t = String(text || '').toLowerCase();
  /** @type {[RegExp, string, string][]} */
  const rules = [
    [/backup/, '/admin/backups', 'Backups'],
    [/cert|tls|acme|https|ca\b|expir/, '/admin/certificates', 'Certificates'],
    [/key|seal|unlock|encrypt|recovery/, '/admin/encryption', 'Encryption'],
    [/network|firewall|ufw|allowlist|interface|mdns|avahi|tailscale|vpn|port/, '/admin/network', 'Network'],
    [/disk|space|storage|database|\bdb\b|sqlite|log/, '/admin/system', 'System'],
    [/audit/, '/admin/audit', 'Audit log'],
    [/job|schedule/, '/admin/jobs', 'Jobs'],
    [/2fa|mfa|password|owner|admin user|users?\b/, '/admin/users', 'Users'],
    [/smtp|email|mail/, '/admin/settings/email', 'Email settings'],
  ];
  for (const [re, href, label] of rules) if (re.test(t)) return { href, label };
  return null;
}

/** Icons of single actions that differ from their area's icon (actionIcon). @type {Record<string, string>} */
const ACTION_ICONS = { 'network.funnel': 'globe' };

/** @param {string} action */
export function actionIcon(action) {
  if (ACTION_ICONS[action]) return ACTION_ICONS[action];
  const p = String(action || '').split('.')[0];
  return { auth: 'login', user: 'user', mfa: 'shield', passkey: 'passkey', token: 'key', session: 'laptop', invite: 'mail', group: 'users', role: 'shield', file: 'file', folder: 'folder', grant: 'share', archive: 'file-zip', share: 'link', request: 'inbox', settings: 'sliders', network: 'network', cert: 'certificate', ca: 'certificate', client_cert: 'certificate', keys: 'key', backup: 'archive', system: 'server', admin: 'shield', job: 'jobs', audit: 'scroll' }[p] || 'activity';
}

/** Readable verb phrase for an audit action ("share.create" → "created a share link"). */
const ACTIONS = /** @type {Record<string, string>} */ ({
  'auth.login': 'signed in', 'auth.logout': 'signed out', 'auth.mfa': 'completed two-step verification', 'auth.lockout': 'was locked out',
  'auth.elevate': 'confirmed their identity', 'auth.setup': 'set up the server', 'user.create': 'created user', 'user.update': 'updated user',
  'user.delete': 'deleted user', 'user.disable': 'disabled user', 'user.enable': 'enabled user', 'user.unlock': 'unlocked user',
  'user.password_change': 'changed their password', 'user.password_reset': 'reset the password of', 'user.mfa_reset': 'reset two-factor authentication of',
  'mfa.totp_enable': 'turned on the authenticator app', 'mfa.totp_disable': 'turned off the authenticator app', 'mfa.recovery_regenerate': 'created new recovery codes',
  'passkey.add': 'added a passkey', 'passkey.remove': 'removed a passkey', 'token.create': 'created an API token', 'token.revoke': 'revoked an API token',
  'session.revoke': 'signed out a session', 'invite.create': 'created an invitation', 'invite.revoke': 'revoked an invitation', 'invite.accept': 'accepted an invitation',
  'group.create': 'created group', 'group.update': 'updated group', 'group.delete': 'deleted group', 'group.member_set': 'changed membership in', 'group.member_remove': 'removed a member from',
  'group.role_set': 'made a role a member of a group', 'group.role_remove': 'removed a role from a group',
  'role.create': 'created role', 'role.update': 'changed role', 'role.delete': 'deleted role',
  'file.upload': 'uploaded', 'file.download': 'downloaded', 'file.rename': 'renamed', 'file.move': 'moved', 'file.copy': 'copied', 'file.trash': 'moved to trash',
  'file.restore': 'restored', 'file.purge': 'permanently deleted', 'file.version_restore': 'restored a version of', 'folder.create': 'created folder',
  'grant.set': 'shared', 'grant.remove': 'stopped sharing', 'archive.download': 'downloaded an archive', 'share.create': 'created a share for', 'share.update': 'updated the share for',
  'share.revoke': 'revoked the share for', 'share.password_fail': 'entered a wrong share password for', 'request.upload': 'uploaded to a file request',
  'settings.change': 'changed setting', 'network.policy': 'changed the network access policy',
  'network.funnel': 'changed Tailscale Funnel', 'network.serve': 'changed Tailscale Serve', 'cert.renew': 'renewed the certificate', 'cert.custom_set': 'installed a custom certificate',
  'cert.custom_clear': 'removed the custom certificate', 'cert.acme': 'requested an ACME certificate', 'cert.tailscale': 'fetched the Tailscale certificate', 'ca.regenerate': 'regenerated the CA',
  'client_cert.issue': 'issued a client certificate', 'client_cert.revoke': 'revoked a client certificate', 'keys.unlock': 'unlocked the server', 'keys.lock': 'locked the server',
  'keys.seal': 'sealed the master key', 'keys.unseal': 'unsealed the master key', 'keys.passphrase': 'changed the key passphrase', 'keys.rotate': 'rotated keys',
  'keys.recovery_export': 'exported a recovery key', 'backup.create': 'created a backup', 'backup.verify': 'verified a backup', 'backup.delete': 'deleted a backup',
  'backup.download': 'downloaded a backup', 'backup.import': 'imported a backup', 'backup.restore': 'scheduled a restore', 'system.start': 'started the server',
  'system.stop': 'stopped the server', 'system.restart': 'restarted the server', 'admin.file_access': 'accessed files of',
  'job.run': 'started a job', 'audit.reseal': 'sealed audit entries written while the keys were locked',
});

/** Phrases of refused and failed entries that do not follow the "failed to <verb>" pattern. @type {Record<string, string>} */
const FAILED_ACTIONS = { 'auth.login': 'failed to sign in', 'auth.mfa': 'failed two-step verification', 'auth.elevate': 'failed to confirm their identity' };
/** Past-tense first words of the ACTIONS phrases → their base form ("created an invitation" → "create an invitation"). */
const BASE_VERBS = /** @type {Record<string, string>} */ ({
  signed: 'sign', completed: 'complete', confirmed: 'confirm', set: 'set', created: 'create', updated: 'update', deleted: 'delete',
  disabled: 'disable', enabled: 'enable', unlocked: 'unlock', changed: 'change', reset: 'reset', turned: 'turn', added: 'add',
  removed: 'remove', revoked: 'revoke', accepted: 'accept', made: 'make', uploaded: 'upload', downloaded: 'download', renamed: 'rename',
  moved: 'move', copied: 'copy', restored: 'restore', shared: 'share', stopped: 'stop', entered: 'enter',
  installed: 'install', requested: 'request', fetched: 'fetch', regenerated: 'regenerate', issued: 'issue', locked: 'lock', sealed: 'seal',
  unsealed: 'unseal', rotated: 'rotate', exported: 'export', verified: 'verify', imported: 'import', scheduled: 'schedule', started: 'start',
  restarted: 'restart', accessed: 'access',
});

/**
 * Readable verb phrase of an audit entry, after the actor's name: "signed in", and for an entry whose outcome is
 * "failure" or "denied" what was attempted — "failed to sign in", "was not allowed to create an invitation" — never
 * the success phrase next to a small badge.
 * @param {string} action
 * @param {string} [outcome] success (default) | failure | denied
 */
export function actionText(action, outcome) {
  const done = ACTIONS[action] || String(action || '').replace(/[._]/g, ' ');
  if (outcome !== 'failure' && outcome !== 'denied') return done;
  if (outcome === 'failure' && FAILED_ACTIONS[action]) return FAILED_ACTIONS[action];
  const [first, ...rest] = done.split(' ');
  const adverb = first === 'permanently'; // "permanently deleted" → "permanently delete"
  const verb = BASE_VERBS[adverb ? rest[0] : first];
  if (!verb) return outcome === 'denied' ? `was refused: ${done}` : `failed: ${done}`;
  const base = (adverb ? ['permanently', verb, ...rest.slice(1)] : [verb, ...rest]).join(' ');
  return outcome === 'denied' ? `was not allowed to ${base}` : `failed to ${base}`;
}

/**
 * Whether an audit entry names its actor again as the target ("bob signed in bob"): the list shows the target only
 * when it is someone or something else.
 * @param {any} a core.AuditRecord
 */
export function targetIsActor(a) {
  return !!a.target_id && a.target_id === a.actor_id;
}

