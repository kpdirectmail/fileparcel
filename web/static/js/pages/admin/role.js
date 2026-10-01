// @ts-check
/**
 * Admin → Role detail (/admin/roles/:id): one role in tabs (the active one is kept in the address as ?tab=):
 *   Permissions  the catalog in one card per group, a switch per permission. Changes collect in a save bar
 *                (Ctrl/Cmd+S) and are confirmed with what they add and remove and whom they affect.
 *   People       the accounts that have the role; give it to more people, or change someone's role
 *   Folders      custom roles: folders and files shared with everyone who has the role
 *   Groups       custom roles: groups everyone with the role belongs to
 * Built-in roles are read-only; custom roles are changed by administrators only (step-up). Folder access needs
 * "manage" on the folder, group memberships the "Manage groups" permission, giving the role "Manage accounts".
 *   GET    /admin/roles/{id}                           → RoleDef (built-in words work)
 *   GET    /admin/capabilities                         → CapabilityCatalog {items, groups}
 *   PATCH  /admin/roles/{id} (admins, E)               RoleDefUpdate {name, description, delegable, add_permissions,
 *                                                      remove_permissions} → RoleDef
 *   GET    /admin/users?role_id=                       → Page[User];  PATCH /admin/users/{id} {role_id}
 *   GET    /admin/grants?subject_type=role&subject_id= → SubjectGrants {items: [Grant], hidden}
 *   POST   /nodes/{id}/grants {subject_type: "role", subject_id, role, expires_at};  DELETE /nodes/{id}/grants/{gid}
 *   GET    /admin/roles/{id}/groups                    → {items: [RoleGroup]}
 *   PUT    /admin/roles/{id}/groups/{groupId} {member_role};  DELETE /admin/roles/{id}/groups/{groupId}
 *   GET    /admin/groups                               (choices of "Add to a group")
 *   GET    /admin/settings?section=auth                (save confirmation: does the 2FA policy cover staff?)
 * @module pages/admin/role
 */
import { h, icon, replace, append, uniqueId } from '../../core/dom.js';
import { api, ApiError, itemsOf, getAll } from '../../core/api.js';
import { navigate, setTitle, beforeNavigate } from '../../core/router.js';
import { isAdmin, can, events } from '../../core/store.js';
import { register } from '../../core/keys.js';
import { isServerPermission, permissionLabel } from '../../core/perms.js';
import { plural } from '../../core/format.js';
import { button, iconButton } from '../../components/button.js';
import { badge } from '../../components/badge.js';
import { card } from '../../components/card.js';
import { table } from '../../components/table.js';
import { tabs } from '../../components/tabs.js';
import { field, select, toggle } from '../../components/field.js';
import { confirm } from '../../components/dialog.js';
import { toast } from '../../components/toast.js';
import { skeleton, spinner } from '../../components/progress.js';
import { emptyState } from '../../components/empty-state.js';
import { pickFolder } from '../../components/folder-picker.js';
import {
  adminHeader, errorPanel, alertEl, kv, timeEl, userCell, moreMenu, formDialog, userPicker, roleSelect, expiryBadge,
  loadRoles, loadCatalog, clearRoleCache, roleBaseText, roleIsStaff, isCustomRoleId, me as currentUser, confirmRoleChange,
  grantLocation, mayManageAccount,
} from './common.js';
import { newRoleDialog, deleteRoleFlow } from './roles.js';

export const title = 'Role';

/** Tab ids → labels. @type {Record<string, string>} */
const TAB_LABELS = { permissions: 'Permissions', people: 'People', folders: 'Folders', groups: 'Groups' };

/** Access levels of a folder share (core.Grant role) as the Folders tab offers them. */
const LEVELS = [
  { value: 'viewer', label: 'View', text: 'Open and download.' },
  { value: 'editor', label: 'Edit', text: 'Also upload, rename, move and delete.' },
  { value: 'manager', label: 'Manage', text: 'Also share it with others and create links.' },
];

/** @param {any} u a user */
const userHref = (u) => `/admin/users/${encodeURIComponent(u.id)}`;

/**
 * Status badges of an account row (as on Admin → Users).
 * @param {any} u
 */
function statusBadges(u) {
  const locked = !!u.locked_until && new Date(u.locked_until).getTime() > Date.now();
  return h('span', { class: 'cluster' },
    u.status === 'disabled' ? badge({ text: 'Disabled', kind: 'neutral' }) : locked ? badge({ text: 'Locked', kind: 'warning', icon: 'lock' }) : badge({ text: 'Active', kind: 'success' }),
    u.mfa_enabled ? badge({ text: '2FA', kind: 'info', icon: 'shield-check', title: 'Two-factor authentication on' }) : null);
}

/**
 * @param {HTMLElement} root
 * @param {import('../../core/router.js').PageContext} ctx
 */
export async function mount(root, ctx) {
  const id = ctx.params.id;
  const path = `/admin/roles/${encodeURIComponent(id)}`;
  const admin = isAdmin();
  const self = currentUser();
  const headerSlot = h('div');
  const noticeSlot = h('div', { class: 'stack-sm' });
  const body = h('div', { class: 'stack' }, skeleton(8));
  append(root, headerSlot, noticeSlot, body);

  /** @type {any} core.RoleDef */
  let role = null;
  /** @type {{items: any[], groups: any[]} | null} */
  let catalog = null;
  /** @type {unknown} */
  let catalogErr = null;
  let tab = String(ctx.query.tab || 'permissions');
  /** @type {Map<string, HTMLElement>} built tab panels (kept, so switching tabs keeps unsaved edits) */
  const panels = new Map();
  const panelsEl = h('div', { class: 'role-panels' });
  /** @type {ReturnType<typeof tabs> | null} the tab strip of the last draw() (show() keeps it in step) */
  let bar = null;

  // ---------------------------------------------------------------------------------------- edit state + save bar
  /** @type {Set<string>} the permissions as edited */
  let perms = new Set();
  let draft = { name: '', description: '', delegable: false };
  let saving = false;
  /** @type {HTMLInputElement | HTMLTextAreaElement | null} */
  let nameInput = null;

  const editable = () => !!role && isCustomRoleId(role.id) && (role.editable ?? admin) === true;
  /** @param {string[]} list */
  const inCatalogOrder = (list) => {
    const order = (catalog?.items || []).map((i) => i.name);
    return [...list].sort((a, b) => (order.indexOf(a) + 1 || 999) - (order.indexOf(b) + 1 || 999));
  };
  const diff = () => {
    const orig = new Set(role?.permissions || []);
    const name = draft.name.trim();
    const description = draft.description.trim();
    const d = {
      added: inCatalogOrder([...perms].filter((p) => !orig.has(p))),
      removed: inCatalogOrder([...orig].filter((p) => !perms.has(p))),
      name: name !== role?.name ? name : null,
      description: description !== (role?.description || '') ? description : null,
      delegable: draft.delegable !== !!role?.delegable ? draft.delegable : null,
      count: 0,
    };
    d.count = d.added.length + d.removed.length + Number(d.name !== null) + Number(d.description !== null) + Number(d.delegable !== null);
    return d;
  };
  const dirty = () => editable() && diff().count > 0;

  const savebarText = h('span', { class: 'savebar-text', attrs: { 'aria-live': 'polite' } });
  const saveBtn = button({ label: 'Save changes', icon: 'check', variant: 'primary', onClick: () => save() });
  const savebar = h('div', { class: 'savebar', hidden: true, attrs: { role: 'region', 'aria-label': 'Unsaved changes' } },
    savebarText,
    h('span', { class: 'savebar-actions' }, button({ label: 'Discard', variant: 'ghost', onClick: () => discard() }), saveBtn));
  append(root, savebar);

  const syncSavebar = () => {
    const d = role ? diff() : { count: 0 };
    savebar.hidden = !editable() || d.count === 0;
    savebarText.textContent = `${plural(d.count, 'change')} · affects ${plural(Number(role?.user_count) || 0, 'person', 'people')}`;
    // toasts stack above the bar instead of covering its buttons (css: .toasts uses --fp-savebar-h)
    if (savebar.hidden) document.documentElement.style.removeProperty('--fp-savebar-h');
    else document.documentElement.style.setProperty('--fp-savebar-h', `${Math.ceil(savebar.getBoundingClientRect().height) + 8}px`);
  };

  const resetDraft = () => {
    perms = new Set(role.permissions || []);
    draft = { name: role.name || '', description: role.description || '', delegable: !!role.delegable };
  };

  const discard = () => {
    resetDraft();
    rebuild('permissions');
    syncSavebar();
  };

  // ------------------------------------------------------------------------------------------------ load + draw
  const load = async () => {
    try {
      const [r, c] = await Promise.all([
        api.get(path, { signal: ctx.signal }),
        loadCatalog().then((x) => { catalogErr = null; return x; }, (err) => { catalogErr = err; return null; }),
      ]);
      role = r;
      catalog = c;
    } catch (err) {
      if (err instanceof ApiError && err.aborted) return;
      replace(headerSlot);
      adminHeader(headerSlot, { title: 'Role', crumbs: [{ label: 'Roles', href: '/admin/roles' }] });
      replace(body, errorPanel(err, load, err instanceof ApiError && err.status === 404 ? 'This role does not exist' : undefined));
      return;
    }
    if (ctx.signal.aborted) return;
    resetDraft();
    draw();
  };

  const draw = () => {
    setTitle(role.name);
    const custom = isCustomRoleId(role.id);
    replace(headerSlot);
    adminHeader(headerSlot, {
      title: role.name,
      crumbs: [{ label: 'Roles', href: '/admin/roles' }],
      subtitle: h('span', { class: 'cluster' },
        role.builtin ? badge({ text: 'Built-in', kind: 'neutral' }) : badge({ text: 'Custom role', kind: 'neutral' }),
        roleIsStaff(role) ? badge({ text: 'Server access', kind: 'primary', icon: 'shield' }) : null,
        roleBaseText(role) || null,
        h('a', { class: 'role-people-link', href: `/admin/users?role_id=${encodeURIComponent(role.id)}`, text: plural(Number(role.user_count) || 0, 'person', 'people') })),
      actions: [
        admin ? button({ label: 'Duplicate', icon: 'copy', onClick: duplicate }) : null,
        admin && custom ? button({ label: 'Delete', icon: 'trash', variant: 'danger', onClick: del }) : null,
      ],
    });
    const ids = custom ? ['permissions', 'people', 'folders', 'groups'] : ['permissions', 'people'];
    if (!ids.includes(tab)) tab = 'permissions';
    bar = tabs({
      label: 'Role sections',
      active: tab,
      items: ids.map((t) => ({ id: t, label: TAB_LABELS[t], panelId: `role-panel-${t}`, badge: tabCount(t) })),
      onChange: (t) => show(t),
    });
    panels.clear();
    replace(panelsEl);
    replace(body, noticeFor(), bar.el, panelsEl);
    show(tab);
    syncSavebar();
  };

  /** The count on a tab (people, folders, groups of the role); undefined for none. @param {string | undefined} t */
  const tabCount = (t) => Number(t === 'people' ? role.user_count : t === 'folders' ? role.grant_count : t === 'groups' ? role.group_count : 0) || undefined;

  /** Put the role's current counts on the tabs of the strip on screen (without redrawing the panels). */
  const syncTabCounts = () => {
    for (const b of /** @type {NodeListOf<HTMLElement>} */ (bar?.el.querySelectorAll('[role="tab"]') || [])) {
      const n = tabCount(b.dataset.id);
      let el = b.querySelector('.badge');
      if (n && !el) el = b.appendChild(h('span', { class: 'badge' }));
      if (n && el) el.textContent = String(n);
      else el?.remove();
    }
  };

  /** Focus the selected tab (after a redraw replaced the element that had focus). */
  const focusTab = () => {
    /** @type {HTMLElement | null | undefined} */ (bar?.el.querySelector('[role="tab"][aria-selected="true"]'))?.focus();
  };

  /** The alert above the tabs: why nothing can be changed here. */
  const noticeFor = () => {
    if (role.builtin) {
      const all = role.id === 'owner' || role.id === 'admin';
      return alertEl('info', 'Built-in roles can’t be changed', all
        ? 'Owners and admins always have every permission, plus the administrator-only areas: roles, security, e-mail, backup and server settings, encryption keys, custom certificates, backup restore and access to everyone’s files.'
        : 'Duplicate this one to make an adjustable copy.');
    }
    if (!editable()) return alertEl('info', 'Only administrators can change roles', 'You can see what this role allows, who has it and what it gives access to.');
    return null;
  };

  /** @param {string} t */
  const show = (t) => {
    tab = t;
    // the strip, the panel on screen and ?tab= always agree (save() opens Permissions for an empty name)
    bar?.setActive(t);
    if (!ctx.signal.aborted) history.replaceState(history.state, '', `${location.pathname}?tab=${encodeURIComponent(t)}`);
    for (const [k, el] of panels) el.hidden = k !== t;
    if (!panels.has(t)) {
      const el = h('section', { class: 'role-panel', id: `role-panel-${t}`, attrs: { role: 'tabpanel', 'aria-label': TAB_LABELS[t] } }, BUILD[t]());
      panels.set(t, el);
      panelsEl.appendChild(el);
    }
  };

  /** @param {string} t */
  const rebuild = (t) => {
    const el = panels.get(t);
    if (el) replace(el, BUILD[t]());
  };

  // ------------------------------------------------------------------------------------------------ permissions
  const permissionsPanel = () => {
    if (!catalog) {
      return errorPanel(catalogErr, async () => {
        try {
          catalog = await loadCatalog();
          rebuild('permissions');
        } catch (err) {
          toast.error(err);
        }
      }, 'The list of permissions could not be loaded');
    }
    const cat = catalog;
    const canEdit = editable();
    const reason = role.builtin ? 'Built-in roles can’t be changed.' : canEdit ? '' : 'Only administrators can change roles.';
    const summary = h('p', { class: 'role-perm-summary', attrs: { 'aria-live': 'polite' } });
    /** @type {Map<string, {row: HTMLElement, input: HTMLInputElement, why: HTMLElement}>} */
    const rows = new Map();
    /** @param {string} name the label of the checked permission that includes `name` ('' when none) */
    const includedBy = (name) => cat.items.find((i) => i.name !== name && perms.has(i.name) && (i.implies || []).includes(name))?.label || '';

    /** @param {any} it CapabilityInfo @param {boolean} on */
    const flip = (it, on) => {
      if (on) {
        perms.add(it.name);
        // what it implies comes along (the server applies the same closure on save)
        /** @type {string[]} */
        const also = [];
        const queue = [...(it.implies || [])];
        while (queue.length) {
          const n = /** @type {string} */ (queue.shift());
          if (perms.has(n)) continue;
          perms.add(n);
          also.push(n);
          queue.push(...(cat.items.find((i) => i.name === n)?.implies || []));
        }
        if (also.length) {
          const labels = also.map((n) => cat.items.find((i) => i.name === n)?.label || permissionLabel(n));
          toast.info(`Also turned on: ${labels.join(', ')} (needed by ${it.label})`);
        }
      } else {
        perms.delete(it.name);
      }
      sync();
    };

    const sync = () => {
      for (const [name, r] of rows) {
        const by = includedBy(name);
        r.input.checked = perms.has(name);
        r.input.disabled = !canEdit || !!by;
        r.row.setAttribute('aria-disabled', String(r.input.disabled));
        r.why.textContent = by ? `Included with ${by}` : '';
        r.why.hidden = !by;
      }
      const list = [...perms];
      const all = role.id === 'owner' || role.id === 'admin';
      const server = list.some(isServerPermission) || all;
      summary.textContent = [all ? 'Every permission' : list.length ? plural(list.length, 'permission') : 'No permissions', server ? 'Server access' : ''].filter(Boolean).join(' · ');
      syncSavebar();
    };

    // a permission of a group this page does not know (a newer server) still gets a row, under "Other"
    const known = new Set(cat.groups.map((g) => g.id));
    const groups = [...cat.groups, ...(cat.items.some((i) => !known.has(i.group)) ? [{ id: '', label: 'Other' }] : [])];
    const groupCards = groups.map((g) => {
      const items = cat.items.filter((i) => (g.id ? i.group === g.id : !known.has(i.group)));
      if (!items.length) return null;
      const reasonId = uniqueId('perm-reason');
      const list = h('div', { class: 'perm-list' }, items.map((it) => {
        const idc = uniqueId('perm');
        const input = h('input', {
          id: idc,
          attrs: { type: 'checkbox', role: 'switch', 'aria-describedby': `${idc}-desc ${idc}-why${reason ? ` ${reasonId}` : ''}`, title: reason || null },
          on: { change: () => flip(it, input.checked) },
        });
        const why = h('p', { class: 'perm-why', id: `${idc}-why`, hidden: true });
        const row = h('div', { class: 'perm-row', dataset: { perm: it.name } },
          h('div', { class: 'perm-text' },
            h('label', { class: 'perm-label', for: idc },
              h('span', { text: it.label }),
              it.high_impact ? badge({ text: 'High impact', kind: 'warning', icon: 'alert-triangle', title: it.warning || undefined }) : null),
            h('p', { class: 'perm-desc', id: `${idc}-desc`, text: it.description }),
            why),
          // the switch's own label gives it a 44 × 44 px hit area; its name comes from .perm-label
          h('label', { class: 'toggle perm-switch', for: idc }, input));
        rows.set(it.name, { row, input, why });
        return row;
      }));
      const guestNote = role.id === 'guest' && g.id === 'sharing'
        ? alertEl('info', '', 'Sharing for guests follows Settings → Sharing → Allow guests to share.',
          can('settings.manage') ? h('a', { class: 'btn btn--secondary btn--sm', href: '/admin/settings/sharing', text: 'Open' }) : null)
        : null;
      return card({
        title: g.label,
        class: 'perm-card',
        body: h('div', { class: 'stack-sm' }, reason ? h('p', { class: 'muted text-sm', id: reasonId, text: reason }) : null, guestNote, list),
      });
    });
    sync();
    return h('div', { class: 'stack' }, detailsCard(), summary, groupCards);
  };

  /** Name, description and "delegable" of a custom role (editable fields join the save bar). */
  const detailsCard = () => {
    if (!isCustomRoleId(role.id)) return null;
    if (!editable()) {
      return card({
        title: 'Details',
        body: kv([
          ['Name', role.name],
          ['Description', role.description || '—'],
          ['Account managers', role.delegable ? 'Can give this role and manage its accounts' : 'Cannot give this role; only administrators can'],
        ]),
      });
    }
    const nameF = field({ label: 'Name', name: 'name', required: true, maxlength: 64, autocomplete: 'off', value: draft.name, onInput: (v) => { draft.name = v; syncSavebar(); } });
    nameInput = nameF.input;
    const descF = field({ label: 'Description', name: 'description', type: 'textarea', rows: 2, maxlength: 500, value: draft.description, onInput: (v) => { draft.description = v; syncSavebar(); } });
    const deleg = toggle({
      label: 'Account managers can give this role and manage its accounts',
      checked: draft.delegable,
      help: 'People with Manage accounts, Reset sign-in or Invite people can then give this role — and its folders and groups — to accounts, including accounts they create, and reset the sign-in of its holders.',
      onChange: (on) => { draft.delegable = on; syncSavebar(); },
    });
    return card({ title: 'Details', body: h('div', { class: 'stack' }, nameF.el, descF.el, deleg.el) });
  };

  /**
   * How many people with this role have no second factor while auth.require_2fa covers staff ("admins"): they must
   * set one up once the role gains a server permission. 0 when unknown.
   */
  const countWithout2FA = async () => {
    try {
      const auth = itemsOf(await api.get('/admin/settings', { query: { section: 'auth' }, handle: false }));
      if (auth.find((s) => s.key === 'auth.require_2fa')?.value !== 'admins') return 0;
      const people = await getAll('/admin/users', { query: { role_id: role.id }, handle: false, max: 5000 });
      return people.filter((u) => !u.mfa_enabled && u.status !== 'disabled').length;
    } catch {
      return 0;
    }
  };

  /**
   * The save confirmation: added permissions (high-impact ones with their warning), removed ones, the other
   * changes, and who is affected.
   * @param {ReturnType<typeof diff>} d
   */
  const confirmSave = async (d) => {
    /** @param {string} p */
    const info = (p) => catalog?.items.find((i) => i.name === p);
    const people = Number(role.user_count) || 0;
    const becomesStaff = !roleIsStaff(role) && [...perms].some(isServerPermission);
    const without2FA = becomesStaff && people ? await countWithout2FA() : 0;
    /** @param {string} p @param {boolean} add */
    const change = (p, add) => {
      const it = info(p);
      const warn = add && it?.high_impact && it.warning;
      return h('li', { class: 'role-change' },
        badge({ text: it?.label || permissionLabel(p), kind: add ? (it?.high_impact ? 'warning' : 'success') : 'neutral', icon: add ? 'plus' : 'minus' }),
        warn ? h('span', { class: 'role-change-warning', text: it.warning }) : null);
    };
    const message = h('div', { class: 'stack-sm' },
      d.name !== null ? h('p', null, 'New name: ', h('strong', { text: d.name })) : null,
      d.description !== null ? h('p', { text: d.description ? 'The description changes.' : 'The description is removed.' }) : null,
      d.delegable !== null ? h('p', { text: d.delegable ? 'Account managers may give this role and manage the accounts that have it.' : 'Only administrators may give this role and manage the accounts that have it.' }) : null,
      d.added.length ? h('div', { class: 'stack-sm' }, h('h3', { class: 'role-change-title', text: 'Adds' }), h('ul', { class: 'role-change-list', attrs: { role: 'list' } }, d.added.map((p) => change(p, true)))) : null,
      d.removed.length ? h('div', { class: 'stack-sm' }, h('h3', { class: 'role-change-title', text: 'Removes' }), h('ul', { class: 'role-change-list', attrs: { role: 'list' } }, d.removed.map((p) => change(p, false)))) : null,
      h('p', { text: people ? `Changes apply immediately to ${plural(people, 'person', 'people')}.` : 'Nobody has this role yet.' }),
      d.removed.some((p) => p === 'shares.links' || p === 'shares.requests') ? h('p', { class: 'muted', text: 'Existing public links and file requests stay active.' }) : null,
      without2FA ? alertEl('warning', '', `${plural(without2FA, 'person', 'people')} without two-factor authentication will have to set it up.`) : null);
    return confirm({ title: `Save changes to “${role.name}”?`, message, confirmLabel: 'Save changes' });
  };

  const save = async () => {
    if (saving || !dirty()) return;
    const d = diff();
    if (d.name === '') {
      toast.error('The role needs a name.');
      if (tab !== 'permissions') show('permissions');
      nameInput?.focus();
      return;
    }
    saving = true;
    try {
      if (!(await confirmSave(d))) return;
      /** @type {Record<string, any>} */
      const patch = {};
      if (d.name !== null) patch.name = d.name;
      if (d.description !== null) patch.description = d.description;
      if (d.delegable !== null) patch.delegable = d.delegable;
      if (d.added.length) patch.add_permissions = d.added;
      if (d.removed.length) patch.remove_permissions = d.removed;
      /** @type {any} */
      let res;
      try {
        res = await api.patch(path, patch);
      } catch (err) {
        if (err instanceof ApiError && err.status === 409) toast.error('A role with this name already exists.');
        else toast.error(err);
        return;
      }
      role = res && res.id ? res : await api.get(path, { signal: ctx.signal });
      clearRoleCache();
      resetDraft();
      toast.success('Role saved');
      draw();
      // draw() replaced the panels and hid the save bar, so the focused control is gone: continue from the tab
      focusTab();
    } finally {
      saving = false;
    }
  };

  // ------------------------------------------------------------------------------------------------ people
  const peoplePanel = () => {
    const canGive = can('users.manage') && role.assignable !== false;
    const canChange = can('users.manage');
    /** @type {any[]} */
    let rows = [];
    let cursor = '';
    const t = table({
      caption: `People with the role ${role.name}`,
      loading: true,
      rowKey: 'id',
      onRowClick: (u) => navigate(userHref(u)),
      empty: emptyState({ icon: 'users', title: 'Nobody has this role yet', text: canGive ? 'Give it to people with “Add people”.' : undefined }),
      columns: [
        { key: 'user', label: 'Person', render: (u) => h('a', { class: 'row-link', href: userHref(u) }, userCell(u)) },
        { key: 'status', label: 'Status', render: (u) => statusBadges(u) },
        { key: 'last', label: 'Last sign-in', hideBelow: 'sm', render: (u) => (u.last_login_at ? timeEl(u.last_login_at) : h('span', { class: 'subtle', text: 'Never' })) },
        {
          key: 'actions',
          label: 'Actions',
          srOnlyLabel: true,
          class: 'cell-actions',
          render: (u) => moreMenu(() => [
            // the rule of Admin → Users: only accounts the caller may manage (an owner, an admin, or a role that is
            // not delegable stay with administrators)
            canChange && u.id !== self?.id && mayManageAccount(u, { role: isCustomRoleId(u.role_id) && u.role_id === role.id ? role : undefined })
              ? { label: 'Change role…', icon: 'shield', onClick: () => changeRole(u) } : null,
            { label: 'Open', icon: 'user', href: userHref(u) },
          ].filter(Boolean), `Actions for ${u.username}`),
        },
      ],
    });
    const more = button({ label: 'Load more', icon: 'chevron-down', variant: 'ghost', onClick: () => page(true) });
    more.hidden = true;
    const slot = h('div', { class: 'stack-sm' }, t.el, h('div', { class: 'load-more' }, more));

    /** @param {boolean} next */
    const page = async (next) => {
      try {
        const res = await api.get('/admin/users', { signal: ctx.signal, query: { role_id: role.id, limit: 100, cursor: next ? cursor : undefined } });
        rows = next ? rows.concat(itemsOf(res)) : itemsOf(res);
        cursor = res?.next_cursor || '';
        if (t.el.parentNode !== slot) replace(slot, t.el, h('div', { class: 'load-more' }, more));
        t.setRows(rows);
        more.hidden = !cursor;
      } catch (err) {
        if (err instanceof ApiError && err.aborted) return;
        if (next) toast.error(err);
        else replace(slot, errorPanel(err, () => page(false)));
      }
    };

    const addPeople = async () => {
      const exclude = [...rows.map((u) => u.id), ...(self?.id ? [self.id] : [])];
      const picker = userPicker({ label: 'Person', name: 'user_id', required: true, exclude, help: 'Type at least 2 letters of a name, username or email. You cannot change your own role.' });
      let changed = false;
      await formDialog({
        title: `Give people the role ${role.name}`,
        intro: 'Pick someone and confirm. You can add several people one after another.',
        fields: [picker],
        submitLabel: 'Give role',
        submitIcon: 'user-plus',
        onSubmit: async (v) => {
          const uid = String(v.user_id || '');
          const who = picker.selected();
          if (!uid || !who) throw new ApiError(422, 'invalid', 'Search for a person and pick them from the list.', 'user_id');
          if (!(await confirmRoleChange(who, role))) return false;
          await api.patch(`/admin/users/${encodeURIComponent(uid)}`, { role_id: role.id });
          toast.success(`${who.display_name || who.username} now has the role ${role.name}`);
          changed = true;
          exclude.push(uid);
          picker.clear();
          return false; // keep the dialog open for the next person
        },
      });
      if (changed) await refreshRole();
    };

    /** @param {any} u */
    const changeRole = async (u) => {
      /** @type {any[]} */
      let roles;
      try {
        roles = await loadRoles();
      } catch (err) {
        toast.error(err);
        return;
      }
      const sel = roleSelect({ label: 'New role', name: 'role_id', roles, value: u.role_id || role.id, required: true });
      const done = await formDialog({
        title: `Change the role of ${u.display_name || u.username}`,
        fields: [sel],
        submitLabel: 'Change role',
        submitIcon: 'shield',
        onSubmit: async (v) => {
          const to = sel.selected();
          if (!to || v.role_id === (u.role_id || role.id)) return true;
          if (!(await confirmRoleChange(u, to))) return false;
          await api.patch(`/admin/users/${encodeURIComponent(u.id)}`, { role_id: v.role_id });
          return to;
        },
      });
      if (!done || done === true) return;
      toast.success(`${u.display_name || u.username} now has the role ${done.name}`);
      await refreshRole();
    };

    page(false);
    return h('div', { class: 'stack' },
      canGive ? h('div', { class: 'tab-actions' }, button({ label: 'Add people', icon: 'user-plus', variant: 'primary', onClick: addPeople })) : null,
      role.id === 'member' || role.id === 'guest'
        ? h('p', { class: 'muted text-sm', text: `People with a custom role based on ${role.name} are listed under their own role.` })
        : null,
      slot);
  };

  // ------------------------------------------------------------------------------------------------ folders
  const foldersPanel = () => {
    const listEl = h('ul', { class: 'access-list', attrs: { role: 'list' } }, h('li', null, spinner()));
    const hiddenNote = h('p', { class: 'muted text-sm', hidden: true });

    /** @param {any} g core.Grant */
    const row = (g) => {
      const manage = g.caller_perm === 'manage' || g.caller_perm === 'owner';
      const name = g.node_name || 'Untitled';
      const level = h('select', {
        class: 'access-level',
        attrs: { 'aria-label': `Access to ${name}` },
        disabled: !manage,
        on: {
          change: async () => {
            try {
              const saved = await api.post(`/nodes/${encodeURIComponent(g.node_id)}/grants`, { subject_type: 'role', subject_id: role.id, role: level.value, expires_at: g.expires_at || undefined });
              g.role = saved?.role || level.value;
              toast.success(`${role.name} can now ${LEVELS.find((l) => l.value === g.role)?.label.toLowerCase() || 'open'} “${name}”`);
            } catch (err) {
              level.value = g.role;
              toast.error(err);
            }
          },
        },
      }, LEVELS.map((l) => h('option', { attrs: { value: l.value }, text: `Can ${l.label.toLowerCase()}`, selected: l.value === g.role })));
      return h('li', { class: 'access-row' },
        h('span', { class: 'access-icon', attrs: { 'aria-hidden': 'true' } }, icon(g.node_kind === 'folder' ? 'folder' : 'file')),
        h('span', { class: 'access-main' },
          g.node_kind === 'folder' ? h('a', { class: 'access-name', href: `/files/${encodeURIComponent(g.node_id)}`, text: name }) : h('span', { class: 'access-name', text: name }),
          h('span', { class: 'access-sub' }, h('span', { text: grantLocation(g) }), g.expires_at ? expiryBadge(g.expires_at, 7) : null)),
        h('span', { class: 'access-actions' },
          level,
          manage
            ? iconButton({ icon: 'x', label: `Stop sharing “${name}” with ${role.name}`, size: 'sm', onClick: () => remove(g) })
            : h('span', { class: 'access-nomanage', title: 'Only people who manage it can change this share.' }, icon('lock', { size: 16, label: 'You do not manage this item' }))));
    };

    const load = async () => {
      try {
        const res = await api.get('/admin/grants', { signal: ctx.signal, query: { subject_type: 'role', subject_id: role.id } });
        const items = itemsOf(res);
        const n = Number(res?.hidden) || 0;
        replace(listEl, ...(items.length ? items.map(row)
          : [h('li', { class: 'muted text-sm', text: n ? 'Nothing you can open is shared with this role.' : 'No folders are shared with this role yet.' })]));
        hiddenNote.hidden = !n;
        hiddenNote.textContent = `${n === 1 ? '1 more item' : `${n} more items`} you cannot open, such as someone’s personal files (not shown).`;
      } catch (err) {
        if (err instanceof ApiError && err.aborted) return;
        replace(listEl, h('li', null, errorPanel(err, load)));
      }
    };

    /** @param {any} g */
    const remove = async (g) => {
      const ok = await confirm({
        title: `Stop sharing “${g.node_name}”?`,
        message: `Everyone with the role ${role.name} loses this access, unless they have it some other way.`,
        confirmLabel: 'Stop sharing',
        danger: true,
      });
      if (!ok) return;
      try {
        await api.del(`/nodes/${encodeURIComponent(g.node_id)}/grants/${encodeURIComponent(g.id)}`);
        toast.success(`${role.name} no longer has access to “${g.node_name}”`);
        await Promise.all([load(), refreshCounts()]);
      } catch (err) {
        toast.error(err);
      }
    };

    const add = async () => {
      const node = await pickFolder({
        need: 'manage', title: `Folder for ${role.name}`, confirmLabel: 'Choose this folder', help: 'Pick a folder you manage.',
        blockedText: 'You don’t manage this folder, so you can’t share it with a role (that needs “Can manage”).',
      });
      if (!node) return;
      const levelCtl = levelChoice('viewer');
      const today = new Date();
      const until = field({
        label: 'Until', name: 'until', type: 'date', help: 'Optional. The access ends at the end of this day.',
        min: `${today.getFullYear()}-${String(today.getMonth() + 1).padStart(2, '0')}-${String(today.getDate()).padStart(2, '0')}`,
      });
      const done = await formDialog({
        title: `Give ${role.name} access to “${node.name}”`,
        fields: [levelCtl, until],
        submitLabel: 'Give access',
        submitIcon: 'folder-plus',
        onSubmit: async (v) => {
          /** @type {Record<string, any>} */
          const bodyIn = { subject_type: 'role', subject_id: role.id, role: v.level };
          if (v.until) {
            const end = new Date(`${v.until}T23:59:59`);
            if (Number.isNaN(end.getTime()) || end.getTime() <= Date.now()) throw new ApiError(422, 'invalid', 'Choose a day in the future.', 'until');
            bodyIn.expires_at = end.toISOString();
          }
          await api.post(`/nodes/${encodeURIComponent(node.id)}/grants`, bodyIn);
          return true;
        },
      });
      if (!done) return;
      toast.success(`Everyone with the role ${role.name} can now open “${node.name}”`);
      await Promise.all([load(), refreshCounts()]);
    };

    load();
    return h('div', { class: 'stack' },
      h('div', { class: 'tab-actions' }, button({ label: 'Give folder access', icon: 'folder-plus', variant: 'primary', onClick: add })),
      h('p', { class: 'muted text-sm', text: 'Everyone with this role gets this access — including people who get the role later. You can only choose folders you manage.' }),
      listEl,
      hiddenNote);
  };

  // ------------------------------------------------------------------------------------------------ groups
  const groupsPanel = () => {
    const manage = can('groups.manage');
    const listEl = h('ul', { class: 'access-list', attrs: { role: 'list' } }, h('li', null, spinner()));
    /** @type {any[]} */
    let items = [];

    /** @param {any} g core.RoleGroup */
    const row = (g) => {
      const sel = h('select', {
        class: 'access-level',
        attrs: { 'aria-label': `Role of ${role.name} in ${g.group_name}` },
        disabled: !manage,
        on: {
          change: async () => {
            try {
              await api.put(`${path}/groups/${encodeURIComponent(g.group_id)}`, { member_role: sel.value });
              g.member_role = sel.value;
              toast.success(sel.value === 'manager' ? `Everyone with the role now manages “${g.group_name}”` : `Everyone with the role is now a member of “${g.group_name}”`);
            } catch (err) {
              sel.value = g.member_role;
              toast.error(err);
            }
          },
        },
      }, [['member', 'Member'], ['manager', 'Manager']].map(([v, l]) => h('option', { attrs: { value: v }, text: l, selected: v === g.member_role })));
      return h('li', { class: 'access-row' },
        h('span', { class: 'access-icon', attrs: { 'aria-hidden': 'true' } }, icon('users')),
        h('span', { class: 'access-main' },
          can('users.view') ? h('a', { class: 'access-name', href: `/admin/groups/${encodeURIComponent(g.group_id)}`, text: g.group_name }) : h('span', { class: 'access-name', text: g.group_name }),
          h('span', { class: 'access-sub' }, 'Added ', timeEl(g.added_at))),
        h('span', { class: 'access-actions' },
          sel,
          manage ? iconButton({ icon: 'x', label: `Remove ${role.name} from ${g.group_name}`, size: 'sm', onClick: () => remove(g) }) : null));
    };

    const load = async () => {
      try {
        items = itemsOf(await api.get(`${path}/groups`, { signal: ctx.signal }));
        replace(listEl, ...(items.length ? items.map(row) : [h('li', { class: 'muted text-sm', text: 'This role is not a member of any group.' })]));
      } catch (err) {
        if (err instanceof ApiError && err.aborted) return;
        replace(listEl, h('li', null, errorPanel(err, load)));
      }
    };

    /** @param {any} g */
    const remove = async (g) => {
      const ok = await confirm({
        title: `Remove ${role.name} from “${g.group_name}”?`,
        message: 'People with this role lose the team folder of the group, unless they are members themselves.',
        confirmLabel: 'Remove',
        danger: true,
      });
      if (!ok) return;
      try {
        await api.del(`${path}/groups/${encodeURIComponent(g.group_id)}`);
        toast.success(`${role.name} was removed from “${g.group_name}”`);
        await Promise.all([load(), refreshCounts()]);
      } catch (err) {
        toast.error(err);
      }
    };

    const add = async () => {
      /** @type {any[]} */
      let groups;
      try {
        groups = await getAll('/admin/groups');
      } catch (err) {
        toast.error(err);
        return;
      }
      const taken = new Set(items.map((g) => g.group_id));
      const choices = groups.filter((g) => !taken.has(g.id)).sort((a, b) => String(a.name).localeCompare(String(b.name)));
      if (!choices.length) {
        toast.info(groups.length ? 'This role is already a member of every group.' : 'There are no groups yet. Create one under Admin → Groups.');
        return;
      }
      const group = select({ label: 'Group', name: 'group_id', required: true, value: choices[0].id, options: choices.map((g) => ({ value: g.id, label: g.name })) });
      const managers = toggle({ label: 'Managers of the group (can share its team folder)', name: 'manager', checked: false });
      const done = await formDialog({
        title: `Add ${role.name} to a group`,
        intro: 'Everyone with this role becomes a member of the group and sees its team folder.',
        fields: [group, managers],
        submitLabel: 'Add to group',
        submitIcon: 'users',
        onSubmit: async (v) => {
          await api.put(`${path}/groups/${encodeURIComponent(v.group_id)}`, { member_role: v.manager ? 'manager' : 'member' });
          return choices.find((g) => g.id === v.group_id) || true;
        },
      });
      if (!done) return;
      toast.success(`${role.name} was added to “${done.name || 'the group'}”`);
      await Promise.all([load(), refreshCounts()]);
    };

    load();
    return h('div', { class: 'stack' },
      manage ? h('div', { class: 'tab-actions' }, button({ label: 'Add to a group', icon: 'users', variant: 'primary', onClick: add })) : null,
      h('p', { class: 'muted text-sm', text: 'Everyone with this role is a member of these groups and sees their team folders. Individual memberships are kept.' }),
      listEl);
  };

  /** @type {Record<string, () => Node>} */
  const BUILD = { permissions: permissionsPanel, people: peoplePanel, folders: foldersPanel, groups: groupsPanel };

  // ------------------------------------------------------------------------------------------------ actions
  /** Re-read the role (its counts) after changes made from another tab of this page. */
  const refreshRole = async () => {
    clearRoleCache();
    try {
      const r = await api.get(path, { signal: ctx.signal });
      if (dirty()) {
        role = { ...role, user_count: r.user_count, group_count: r.group_count, grant_count: r.grant_count };
        syncTabCounts();
        syncSavebar();
        return;
      }
      role = r;
      resetDraft();
      draw();
    } catch (err) {
      if (!(err instanceof ApiError && err.aborted)) toast.error(err);
    }
  };

  /**
   * Re-read only the counts of the role after a folder or group change and show them on the tabs; the panel that
   * changed reloads its own list, and unsaved permission edits stay.
   */
  const refreshCounts = async () => {
    clearRoleCache();
    try {
      const r = await api.get(path, { signal: ctx.signal, handle: false });
      role = { ...role, user_count: r.user_count, group_count: r.group_count, grant_count: r.grant_count };
      syncTabCounts();
    } catch { /* the counts stay as they were; the lists are current */ }
  };

  const duplicate = async () => {
    const r = await newRoleDialog({ copyFrom: role });
    if (!r || !r.id) return;
    toast.success(`Role “${r.name}” created`);
    navigate(`/admin/roles/${encodeURIComponent(r.id)}?tab=permissions`);
  };

  const del = async () => {
    replace(noticeSlot);
    const res = await deleteRoleFlow(role);
    if (res.error) replace(noticeSlot, errorPanel(res.error, undefined, `“${role.name}” was not deleted`));
    if (res.deleted) {
      resetDraft(); // nothing left to save: do not ask about leaving
      navigate('/admin/roles');
    }
  };

  // ------------------------------------------------------------------------------------------------ lifecycle
  // Another administrator changed or deleted this role while it is open.
  const offEvents = events.on('authz.changed', async (d) => {
    if (!role || d?.role_id !== role.id || saving) return;
    if (d.reason === 'role_deleted') {
      replace(noticeSlot, alertEl('warning', 'This role was deleted', 'Someone deleted it while you had it open.', h('a', { class: 'btn btn--secondary btn--sm', href: '/admin/roles', text: 'All roles' })));
      resetDraft();
      syncSavebar();
      return;
    }
    if (d.reason === 'role_groups') {
      if (panels.has('groups')) rebuild('groups');
      return;
    }
    /** @type {any} */
    let r;
    try {
      r = await api.get(path, { signal: ctx.signal, handle: false });
    } catch {
      return;
    }
    if (r.updated_at === role.updated_at) return; // our own save
    if (dirty()) {
      replace(noticeSlot, alertEl('warning', 'Someone else changed this role', 'Your unsaved changes are based on the earlier version. Discard them to see the new one.',
        button({ label: 'Discard and reload', size: 'sm', onClick: () => { replace(noticeSlot); role = r; resetDraft(); draw(); } })));
      return;
    }
    role = r;
    resetDraft();
    draw();
  });
  const offNav = beforeNavigate(async () => !dirty() || confirm({
    title: 'Discard unsaved changes?',
    message: `Your changes to “${role.name}” are not saved.`,
    confirmLabel: 'Discard changes',
    danger: true,
  }));
  /** @param {BeforeUnloadEvent} e */
  const onUnload = (e) => {
    if (dirty()) e.preventDefault();
  };
  window.addEventListener('beforeunload', onUnload);
  const offKey = register('mod+s', () => { save(); }, { description: 'Save the role', group: 'Role', allowInInput: true, when: () => dirty() && !saving });

  await load();
  return () => {
    offEvents();
    offNav();
    offKey();
    window.removeEventListener('beforeunload', onUnload);
    document.documentElement.style.removeProperty('--fp-savebar-h');
  };
}

/**
 * Access level as radio cards (View / Edit / Manage): a form() control named "level".
 * @param {string} value
 */
function levelChoice(value) {
  const name = uniqueId('level');
  /** @type {HTMLInputElement[]} */
  const inputs = [];
  const cards = LEVELS.map((l) => {
    const input = h('input', { class: 'sr-only', attrs: { type: 'radio', name, value: l.value }, checked: l.value === value });
    inputs.push(input);
    return h('label', { class: 'choice-card level-card', dataset: { value: l.value } },
      input,
      h('span', { class: 'choice-card-head' }, h('span', { class: 'choice-card-label', text: l.label }),
        h('span', { class: 'choice-card-check', attrs: { 'aria-hidden': 'true' } }, icon('check-circle'))),
      h('span', { class: 'choice-card-text', text: l.text }));
  });
  const el = h('fieldset', { class: 'choice-fieldset' },
    h('legend', { class: 'field-label', text: 'Access' }),
    h('div', { class: 'choice-grid level-cards', attrs: { role: 'radiogroup', 'aria-label': 'Access' } }, cards));
  return {
    el,
    input: inputs[0],
    name: 'level',
    value: () => inputs.find((i) => i.checked)?.value || value,
    setError: () => {},
  };
}
