// @ts-check
/**
 * Admin → Groups (/admin/groups): every group owns a "Team folder"; members can edit it, managers can also share it.
 * Custom roles can be members of groups too (everyone with the role then is); the Roles column counts them.
 * Creating a group needs "Manage groups".
 *   GET  /admin/groups               → Page[Group] {id, name, description, member_count, role_count, created_at}
 *   POST /admin/groups {name, description} → Group
 * Owned by unit J2.
 * @module pages/admin/groups
 */
import { h, replace, append } from '../../core/dom.js';
import { api, ApiError, itemsOf } from '../../core/api.js';
import { navigate } from '../../core/router.js';
import { can } from '../../core/store.js';
import { plural } from '../../core/format.js';
import { button } from '../../components/button.js';
import { table } from '../../components/table.js';
import { field } from '../../components/field.js';
import { emptyState } from '../../components/empty-state.js';
import { toast } from '../../components/toast.js';
import { adminHeader, errorPanel, timeEl, formDialog, debounce } from './common.js';

export const title = 'Groups';

/**
 * @param {HTMLElement} root
 * @param {import('../../core/router.js').PageContext} ctx
 */
export async function mount(root, ctx) {
  const mayManage = can('groups.manage');
  adminHeader(root, {
    title,
    subtitle: 'Groups share a team folder. Members can add and edit files there; managers can also share it.',
    actions: mayManage ? button({ label: 'New group', icon: 'plus', variant: 'primary', onClick: () => create() }) : null,
  });
  const q = field({ label: 'Filter groups', hideLabel: true, type: 'search', placeholder: 'Filter groups', autocomplete: 'off' });
  append(root, h('div', { class: 'admin-toolbar' }, h('div', { class: 'admin-toolbar-search' }, q.el)));

  /** @type {any[]} */
  let groups = [];
  const t = table({
    caption: 'Groups',
    loading: true,
    onRowClick: (g) => navigate(`/admin/groups/${encodeURIComponent(g.id)}`),
    columns: [
      {
        key: 'name',
        label: 'Group',
        render: (g) => h('a', { class: 'row-link stack-sm gap-1', href: `/admin/groups/${encodeURIComponent(g.id)}` },
          h('strong', { text: g.name }),
          g.description ? h('span', { class: 'muted text-xs', text: g.description }) : null),
      },
      { key: 'members', label: 'Members', render: (g) => h('span', { class: 'tabular', text: plural(Number(g.member_count) || 0, 'member') }) },
      {
        key: 'roles',
        label: 'Roles',
        hideBelow: 'md',
        render: (g) => (Number(g.role_count) ? h('span', { class: 'tabular', text: plural(Number(g.role_count), 'role') }) : h('span', { class: 'subtle', text: '—' })),
      },
      { key: 'created', label: 'Created', hideBelow: 'sm', render: (g) => timeEl(g.created_at) },
    ],
    empty: emptyState({
      icon: 'users',
      title: 'No groups yet',
      text: mayManage
        ? 'Create a group for your family, team or project to give everyone a shared folder.'
        : 'Groups give their members a shared team folder. Creating one needs the “Manage groups” permission.',
      action: mayManage ? { label: 'New group', icon: 'plus', onClick: () => create() } : undefined,
    }),
  });
  const slot = h('div', null, t.el);
  append(root, slot);

  const draw = () => {
    const needle = String(q.input.value).trim().toLowerCase();
    t.setRows(groups
      .filter((g) => !needle || String(g.name).toLowerCase().includes(needle) || String(g.description || '').toLowerCase().includes(needle))
      .sort((a, b) => String(a.name).localeCompare(String(b.name))));
  };
  q.input.addEventListener('input', debounce(draw, 120));

  const load = async () => {
    try {
      groups = itemsOf(await api.get('/admin/groups', { signal: ctx.signal, query: { limit: 500 } }));
      // a failed earlier load replaced the table with an error panel: put it back
      if (t.el.parentNode !== slot) replace(slot, t.el);
      draw();
    } catch (err) {
      if (err instanceof ApiError && err.aborted) return;
      replace(slot, errorPanel(err, load));
    }
  };

  const create = async () => {
    const g = await groupDialog();
    if (!g || g === true) {
      if (g === true) await load();
      return;
    }
    toast.success(`Group “${g.name}” created`);
    navigate(`/admin/groups/${encodeURIComponent(g.id)}`);
  };

  await load();
}

/**
 * Create (no `group`) or edit a group. Resolves with the saved Group (or true when the server returned no body).
 * @param {any} [group]
 * @returns {Promise<any>}
 */
export function groupDialog(group) {
  const name = field({ label: 'Name', name: 'name', required: true, maxlength: 64, value: group?.name || '', autocomplete: 'off', help: 'Also the name of the team folder.' });
  const description = field({ label: 'Description', name: 'description', type: 'textarea', rows: 3, maxlength: 500, value: group?.description || '' });
  return formDialog({
    title: group ? 'Edit group' : 'New group',
    fields: [name, description],
    submitLabel: group ? 'Save' : 'Create group',
    submitIcon: group ? 'check' : 'plus',
    onSubmit: async (v) => {
      const body = { name: String(v.name).trim(), description: String(v.description).trim() };
      try {
        const res = group
          ? await api.patch(`/admin/groups/${encodeURIComponent(group.id)}`, body)
          : await api.post('/admin/groups', body);
        return res && res.id ? res : group ? { ...group, ...body } : true;
      } catch (err) {
        if (err instanceof ApiError && err.status === 409) throw new ApiError(409, err.code, 'A group with this name already exists.', 'name');
        throw err;
      }
    },
  });
}
