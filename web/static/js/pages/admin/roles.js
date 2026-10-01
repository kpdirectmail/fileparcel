// @ts-check
/**
 * Admin → Roles (/admin/roles): what each kind of account may do. Every account has exactly one role — a built-in
 * one (Owner, Admin, Member, Guest; fixed) or a custom role an administrator made ("classes" in the owner's words),
 * based on Member or Guest, with its own permissions and access to folders and groups (DESIGN §6a).
 *   GET    /admin/roles                     → {items: [RoleDef]} built-ins, then custom roles by name
 *   POST   /admin/roles (admins, E)         RoleDefInput {name, description, base, copy_from} → RoleDef
 *   DELETE /admin/roles/{id}?reassign_to=   (admins, E) → 204; 409 reassign_to (holders, or their personal files)
 *   GET    /admin/invites                   (delete dialog: open invitations that give the role)
 * Everyone with "View people" sees the list; creating, duplicating and deleting are for administrators.
 * newRoleDialog() and deleteRoleFlow() are shared with the role page (pages/admin/role.js).
 * @module pages/admin/roles
 */
import { h, icon, replace, append, uniqueId } from '../../core/dom.js';
import { api, ApiError, getAll } from '../../core/api.js';
import { navigate } from '../../core/router.js';
import { isAdmin } from '../../core/store.js';
import { isServerPermission } from '../../core/perms.js';
import { plural } from '../../core/format.js';
import { button } from '../../components/button.js';
import { badge } from '../../components/badge.js';
import { card } from '../../components/card.js';
import { table } from '../../components/table.js';
import { tabs } from '../../components/tabs.js';
import { field, select } from '../../components/field.js';
import { emptyState } from '../../components/empty-state.js';
import { toast } from '../../components/toast.js';
import {
  adminHeader, errorPanel, moreMenu, debounce, formDialog, confirmTyped, alertEl, roleSelect, roleBaseText, roleIsStaff,
  isCustomRoleId, loadRoles, clearRoleCache, BUILTIN_ROLE_NAMES,
} from './common.js';

export const title = 'Roles';

/** List filters (pills). */
const FILTERS = [{ id: 'all', label: 'All' }, { id: 'builtin', label: 'Built-in' }, { id: 'custom', label: 'Custom' }];

/**
 * @param {HTMLElement} root
 * @param {import('../../core/router.js').PageContext} ctx
 */
export async function mount(root, ctx) {
  const admin = isAdmin();
  adminHeader(root, {
    title,
    subtitle: 'What each kind of account may do. Roles are also called classes. Built-in roles are fixed; create your own for anything in between.',
    actions: admin ? button({ label: 'New role', icon: 'plus', variant: 'primary', onClick: () => create() }) : null,
  });

  let filter = FILTERS.some((f) => f.id === ctx.query.show) ? ctx.query.show : 'all';
  const q = field({ label: 'Filter roles', hideLabel: true, type: 'search', placeholder: 'Filter roles', autocomplete: 'off', value: ctx.query.q || '', maxlength: 100 });
  const pills = tabs({ items: FILTERS, active: filter, variant: 'pill', label: 'Show roles', onChange: (id) => { filter = id; draw(); } });
  const count = h('span', { class: 'muted text-sm', attrs: { 'aria-live': 'polite' } });
  const noticeSlot = h('div', { class: 'stack-sm' });
  append(root, noticeSlot, h('div', { class: 'admin-toolbar' }, h('div', { class: 'admin-toolbar-search' }, q.el), pills.el, count));

  /** @type {any[]} */
  let roles = [];
  const t = table({
    caption: 'Roles',
    loading: true,
    onRowClick: (r) => navigate(roleHref(r)),
    columns: [
      { key: 'role', label: 'Role', render: (r) => roleCell(r) },
      { key: 'base', label: 'Based on', hideBelow: 'sm', render: (r) => (isCustomRoleId(r.id) ? BUILTIN_ROLE_NAMES[r.base] || r.base : '—') },
      { key: 'perms', label: 'Permissions', hideBelow: 'md', render: (r) => h('span', { class: 'tabular nowrap', text: permissionSummary(r) }) },
      {
        key: 'people',
        label: 'People',
        // phones show the count in the Role column's second line (and "View people" in the row menu)
        hideBelow: 'sm',
        render: (r) => h('a', { class: 'tabular nowrap', href: `/admin/users?role_id=${encodeURIComponent(r.id)}`, text: plural(Number(r.user_count) || 0, 'person', 'people') }),
      },
      { key: 'access', label: 'Access', hideBelow: 'md', render: (r) => h('span', { class: 'tabular nowrap', text: accessSummary(r) }) },
      {
        key: 'actions',
        label: 'Actions',
        srOnlyLabel: true,
        class: 'cell-actions',
        render: (r) => moreMenu(() => [
          { label: 'Open', icon: 'shield', href: roleHref(r) },
          admin ? { label: 'Duplicate', icon: 'copy', onClick: () => create(r) } : null,
          { label: 'View people', icon: 'users', href: `/admin/users?role_id=${encodeURIComponent(r.id)}` },
          admin && isCustomRoleId(r.id) ? { label: 'Delete', icon: 'trash', danger: true, onClick: () => del(r) } : null,
        ].filter(Boolean), `Actions for ${r.name}`),
      },
    ],
    empty: emptyState({
      icon: 'shield',
      title: 'No matching roles',
      text: admin ? 'Create a role for anything between Member and Admin, for example a helpdesk that may reset passwords.' : 'Try another filter.',
      action: admin ? { label: 'New role', icon: 'plus', onClick: () => create() } : undefined,
    }),
  });
  const slot = h('div', null, t.el);
  append(root, slot, howRolesWork());

  const draw = () => {
    if (ctx.signal.aborted) return; // a debounced call after the user left: the address is no longer ours
    const needle = String(q.input.value).trim().toLowerCase();
    const rows = roles.filter((r) => (filter === 'all' || (filter === 'custom') === isCustomRoleId(r.id))
      && (!needle || String(r.name).toLowerCase().includes(needle) || String(r.description || '').toLowerCase().includes(needle)));
    t.setRows(rows);
    const custom = roles.filter((r) => isCustomRoleId(r.id)).length;
    count.textContent = `${plural(roles.length, 'role')} · ${custom} custom`;
    // keep the filters in the URL (shareable, survives reload)
    const params = new URLSearchParams();
    if (filter !== 'all') params.set('show', filter);
    if (needle) params.set('q', String(q.input.value).trim());
    const s = params.toString();
    history.replaceState(history.state, '', `/admin/roles${s ? `?${s}` : ''}`);
  };
  q.input.addEventListener('input', debounce(draw, 120));

  const load = async (force = false) => {
    try {
      roles = await loadRoles({ force });
      if (ctx.signal.aborted) return;
      // a failed earlier load replaced the table with an error panel: put it back
      if (t.el.parentNode !== slot) replace(slot, t.el);
      draw();
    } catch (err) {
      if (err instanceof ApiError && err.aborted) return;
      replace(slot, errorPanel(err, () => load(true)));
    }
  };

  /** @param {any} [from] role to duplicate */
  const create = async (from) => {
    const r = await newRoleDialog({ copyFrom: from, roles });
    if (!r || !r.id) return;
    toast.success(`Role “${r.name}” created`);
    navigate(`${roleHref(r)}?tab=permissions`);
  };

  /** @param {any} r */
  const del = async (r) => {
    replace(noticeSlot);
    const res = await deleteRoleFlow(r);
    if (res.error) replace(noticeSlot, errorPanel(res.error, undefined, `“${r.name}” was not deleted`));
    if (res.deleted) await load(true);
  };

  await load();
}

/** @param {any} r */
function roleHref(r) {
  return `/admin/roles/${encodeURIComponent(r.id)}`;
}

/**
 * The Role column: name, badges, description; on phones also the columns that are hidden there.
 * @param {any} r core.RoleDef
 */
function roleCell(r) {
  const all = r.id === 'owner' || r.id === 'admin';
  const server = (r.permissions || []).filter(isServerPermission).length;
  const sub = [
    all ? 'Every permission' : roleBaseText(r),
    plural(Number(r.user_count) || 0, 'person', 'people'),
    all || !server ? '' : plural(server, 'server permission'),
  ].filter(Boolean).join(' · ');
  return h('a', { class: 'row-link role-cell', href: roleHref(r) },
    h('span', { class: 'role-cell-title' },
      h('strong', { text: r.name }),
      r.builtin ? badge({ text: 'Built-in', kind: 'neutral' }) : null,
      roleIsStaff(r) ? badge({ text: 'Server access', kind: 'primary', icon: 'shield' }) : null),
    r.description ? h('span', { class: 'role-cell-desc', text: r.description }) : null,
    h('span', { class: 'role-cell-sub only-sm', text: sub }));
}

/**
 * "Everything" for owners and admins, else "Sharing 4 · Server 2" (account and server permissions).
 * @param {any} r
 */
function permissionSummary(r) {
  if (r.id === 'owner' || r.id === 'admin') return 'Everything';
  const list = r.permissions || [];
  const server = list.filter(isServerPermission).length;
  const account = list.length - server;
  return [account ? `Sharing ${account}` : '', server ? `Server ${server}` : ''].filter(Boolean).join(' · ') || 'None';
}

/**
 * Folders and groups a custom role gives access to ("2 folders · 1 group"); "—" for built-in roles.
 * @param {any} r
 */
function accessSummary(r) {
  if (!isCustomRoleId(r.id)) return '—';
  const grants = Number(r.grant_count) || 0;
  const groups = Number(r.group_count) || 0;
  return [grants ? plural(grants, 'folder') : '', groups ? plural(groups, 'group') : ''].filter(Boolean).join(' · ') || 'None';
}

/** The "How roles work" card under the list. */
function howRolesWork() {
  return card({
    title: 'How roles work',
    class: 'roles-how',
    body: h('ul', { class: 'hint-list' },
      h('li', { text: 'Every account has exactly one role. It decides what the account may do; which files it can open follows from its own files, its groups and what is shared with it or its role.' }),
      h('li', { text: 'Built-in roles are fixed. Owners and admins can do everything; Member and Guest are for ordinary accounts, with and without a personal “My files” space.' }),
      h('li', { text: 'Custom roles start from Member or Guest. They can add permissions for parts of the Admin area, and give everyone who has them access to folders and groups.' }),
      h('li', { text: 'People who manage accounts can only give Member, Guest and the custom roles an administrator allows them to give — never more server permissions than they have.' })),
  });
}

/**
 * "Based on" as two radio cards: a form() control named "base" (value() → member | guest).
 * @param {string} value
 * @param {(v: string) => void} onPick
 */
function baseChoice(value, onPick) {
  const name = uniqueId('role-base');
  const errId = `${name}-error`;
  const err = h('p', { class: 'field-error', id: errId });
  /** @type {Record<string, HTMLInputElement>} */
  const inputs = {};
  const choices = [
    { v: 'member', label: 'Member', text: 'Has a personal “My files” space.', ic: 'folder' },
    { v: 'guest', label: 'Guest', text: 'No personal space; sees only what is shared with them or their role.', ic: 'folder-shared' },
  ];
  const cards = choices.map((c) => {
    const input = h('input', { class: 'sr-only', attrs: { type: 'radio', name, value: c.v, 'aria-describedby': errId }, checked: c.v === value });
    input.addEventListener('change', () => { if (input.checked) onPick(c.v); });
    inputs[c.v] = input;
    return h('label', { class: 'choice-card radio-card', dataset: { value: c.v } },
      input,
      h('span', { class: 'choice-card-head' }, icon(c.ic), h('span', { class: 'choice-card-label', text: c.label }),
        h('span', { class: 'choice-card-check', attrs: { 'aria-hidden': 'true' } }, icon('check-circle'))),
      h('span', { class: 'choice-card-text', text: c.text }));
  });
  const el = h('fieldset', { class: 'choice-fieldset role-base' },
    h('legend', { class: 'field-label', text: 'Based on' }),
    h('div', { class: 'choice-grid radio-cards', attrs: { role: 'radiogroup', 'aria-label': 'Based on' } }, cards),
    h('p', { class: 'field-help', text: 'Decides whether people with the role get their own “My files”. It cannot be changed later; duplicate the role instead.' }),
    err);
  return {
    el,
    input: inputs.member,
    name: 'base',
    value: () => (inputs.guest.checked ? 'guest' : 'member'),
    /** @param {string | null | undefined} msg */
    setError: (msg) => {
      err.replaceChildren(...(msg ? [icon('alert-circle'), document.createTextNode(msg)] : []));
    },
    /** @param {string} v */
    set: (v) => { if (inputs[v]) inputs[v].checked = true; },
  };
}

/**
 * The base a copy of role `r` gets (owner/admin copies are based on Member).
 * @param {any} r
 */
function baseOf(r) {
  return r && r.base === 'guest' ? 'guest' : 'member';
}

/**
 * "New role" dialog (administrators; a bottom sheet on phones). With `copyFrom` it duplicates that role's
 * permissions and description. Resolves with the created RoleDef, or undefined when cancelled.
 * @param {{copyFrom?: any, roles?: any[]}} [o]
 * @returns {Promise<any>}
 */
export async function newRoleDialog(o = {}) {
  let roles = o.roles || [];
  if (!roles.length) {
    try { roles = await loadRoles(); } catch { /* "Start from" then offers the built-in roles only */ }
  }
  const src = o.copyFrom || null;
  const byId = new Map(roles.map((r) => [String(r.id), r]));
  let baseTouched = false;
  const name = field({
    label: 'Name', name: 'name', required: true, maxlength: 64, autocomplete: 'off', value: src ? `${src.name} (copy)` : '',
    help: 'How the role appears everywhere, for example “Helpdesk” or “Contractors”.',
  });
  const description = field({ label: 'Description', name: 'description', type: 'textarea', rows: 2, maxlength: 500, value: src?.description || '' });
  const base = baseChoice(baseOf(src), () => { baseTouched = true; });
  const customs = roles.filter((r) => isCustomRoleId(r.id));
  const start = select({
    label: 'Start from',
    name: 'copy_from',
    // a copy of Owner is a copy of Admin: the same permissions, and "Start from" offers only the latter
    value: src ? (src.id === 'owner' ? 'admin' : String(src.id)) : '',
    help: 'The permissions the role starts with. You turn single permissions on or off next.',
    options: [
      { value: '', label: 'Recommended defaults (Member’s permissions, or none for Guest)' },
      {
        label: 'Built-in',
        options: [
          { value: 'member', label: 'Member' },
          { value: 'guest', label: 'Guest' },
          { value: 'admin', label: 'Admin — all permissions a custom role can have' },
        ],
      },
      ...(customs.length ? [{ label: 'Custom roles', options: customs.map((r) => ({ value: String(r.id), label: r.name })) }] : []),
    ],
    onChange: (id) => {
      // follow the copied role's base until the base was chosen by hand
      if (!baseTouched && id) base.set(baseOf(byId.get(id) || { base: id }));
    },
  });
  return formDialog({
    title: src ? `Duplicate “${src.name}”` : 'New role',
    intro: src ? 'The copy starts with the same permissions. Access to folders and groups, and whether account managers may give it, are not copied.' : undefined,
    fields: [name, description, base, start],
    submitLabel: 'Create role',
    submitIcon: 'plus',
    onSubmit: async (v) => {
      /** @type {Record<string, any>} */
      const body = { name: String(v.name).trim(), base: v.base };
      const desc = String(v.description).trim();
      if (desc) body.description = desc;
      if (v.copy_from) body.copy_from = v.copy_from;
      try {
        const r = await api.post('/admin/roles', body);
        clearRoleCache();
        return r;
      } catch (err) {
        if (err instanceof ApiError && err.status === 409) throw new ApiError(409, err.code, 'A role with this name already exists.', 'name');
        throw err;
      }
    },
  });
}

/**
 * Delete a custom role (administrators): the people who have it move to another role (required when there are any),
 * its open invitations are revoked, its folder shares and group memberships removed. Asks for the role to move them
 * to, then for the name. Resolves {deleted: true}, {error} (the server refused, e.g. 409 because some of the people
 * still have personal files and the new role has no personal space), or {} when cancelled.
 * @param {any} role core.RoleDef
 * @returns {Promise<{deleted?: boolean, error?: unknown}>}
 */
export async function deleteRoleFlow(role) {
  const people = Number(role.user_count) || 0;
  /** @type {any[]} */
  let roles = [];
  let invites = 0;
  try {
    [roles, invites] = await Promise.all([
      people ? loadRoles() : Promise.resolve([]),
      getAll('/admin/invites', { max: 5000, handle: false })
        .then((list) => list.filter((i) => i.role_id === role.id && (i.status || 'active') === 'active').length)
        .catch(() => 0), // the count is a courtesy; the server revokes them either way
    ]);
  } catch (err) {
    toast.error(err);
    return {};
  }
  const lines = [
    invites ? `${plural(invites, 'open invitation')} for this role will be revoked.` : '',
    role.grant_count ? `${plural(Number(role.grant_count), 'folder share')} with this role will be removed.` : '',
    role.group_count ? `It is removed from ${plural(Number(role.group_count), 'group')}.` : '',
  ].filter(Boolean);
  const consequences = lines.length ? h('ul', { class: 'hint-list' }, lines.map((l) => h('li', { text: l }))) : null;

  let reassignTo = '';
  if (people) {
    const target = roleSelect({
      label: `Move its ${plural(people, 'account')} to`,
      name: 'reassign_to',
      roles,
      exclude: [role.id],
      builtins: ['member', 'guest'],
      placeholder: 'Choose a role…',
      required: true,
      help: role.base === 'member' ? 'Moving them to a role based on Guest takes away their “My files”; it only works while those are empty.' : undefined,
    });
    const chosen = await formDialog({
      title: `Delete “${role.name}”`,
      intro: h('div', { class: 'stack-sm' },
        h('p', { text: `${plural(people, 'account has', 'accounts have')} this role. Choose the role they get instead.` }),
        consequences),
      fields: [target],
      submitLabel: 'Continue',
      submitVariant: 'danger',
      onSubmit: (v) => {
        if (!v.reassign_to) throw new ApiError(422, 'invalid', 'Choose a role for them.', 'reassign_to');
        return v.reassign_to;
      },
    });
    if (typeof chosen !== 'string' || !chosen) return {};
    reassignTo = chosen;
  }
  const toRole = reassignTo ? (roles.find((r) => r.id === reassignTo)?.name || BUILTIN_ROLE_NAMES[reassignTo] || reassignTo) : '';
  const ok = await confirmTyped({
    title: `Delete “${role.name}”?`,
    message: h('div', { class: 'stack-sm' },
      alertEl('danger', 'This cannot be undone', people
        ? `${plural(people, 'account')} will have the role ${toRole} from now on.`
        : 'Nobody has this role.'),
      consequences),
    expected: role.name,
    confirmLabel: 'Delete role',
  });
  if (!ok) return {};
  try {
    await api.del(`/admin/roles/${encodeURIComponent(role.id)}`, undefined, reassignTo ? { query: { reassign_to: reassignTo } } : undefined);
  } catch (err) {
    if (err instanceof ApiError && err.aborted) return {};
    if (err instanceof ApiError && err.status === 409) return { error: err };
    toast.error(err);
    return {};
  }
  clearRoleCache();
  toast.success(`Role “${role.name}” deleted`);
  return { deleted: true };
}
