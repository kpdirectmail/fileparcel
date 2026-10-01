// @ts-check
/**
 * Admin → Group detail (/admin/groups/:id): name/description, members with the manager toggle and where each
 * membership comes from (direct, or through a custom role that is a member of the group), the roles in the group,
 * add/remove members and roles, delete the group (and its team folder). Changing anything needs "Manage groups";
 * without it the page is read-only. Memberships that come from a role are changed on the role (or here, in "Roles in
 * this group"), never per person.
 *   GET    /admin/groups/{id}                          → Group (+ roles: RoleGroup[])
 *   PATCH  /admin/groups/{id} {name, description}      → Group
 *   DELETE /admin/groups/{id}
 *   GET    /admin/groups/{id}/members                  → GroupMember[] (role = effective; direct, direct_role, via_roles)
 *   PUT    /admin/groups/{id}/members/{userId} {role: member|manager}
 *   DELETE /admin/groups/{id}/members/{userId}
 *   PUT    /admin/roles/{roleId}/groups/{id} {member_role: member|manager} → RoleGroup
 *   DELETE /admin/roles/{roleId}/groups/{id}
 *   GET    /admin/roles                                (Add a role: the custom roles)
 * Owned by unit J2.
 * @module pages/admin/group
 */
import { h, icon, replace, append } from '../../core/dom.js';
import { api, ApiError, itemsOf } from '../../core/api.js';
import { navigate, setTitle } from '../../core/router.js';
import { can } from '../../core/store.js';
import { plural } from '../../core/format.js';
import { button, iconButton } from '../../components/button.js';
import { badge } from '../../components/badge.js';
import { card } from '../../components/card.js';
import { table } from '../../components/table.js';
import { select, toggle } from '../../components/field.js';
import { toast } from '../../components/toast.js';
import { confirm } from '../../components/dialog.js';
import { skeleton } from '../../components/progress.js';
import { emptyState } from '../../components/empty-state.js';
import {
  adminHeader, errorPanel, timeEl, userCell, formDialog, userPicker, confirmTyped, alertEl, loadRoles, clearRoleCache, isCustomRoleId,
  roleBaseText, rolesSupported,
} from './common.js';
import { groupDialog } from './groups.js';

export const title = 'Group';

/**
 * The roles through which a member belongs to the group ("Finance", "Finance and Helpdesk").
 * @param {any} m core.GroupMember
 * @returns {any[]} core.RoleRef
 */
const viaRoles = (m) => (Array.isArray(m.via_roles) ? m.via_roles : []);

/** @param {any[]} roles core.RoleRef */
const roleNames = (roles) => roles.map((r) => r.name || 'a role').join(', ');

/**
 * @param {HTMLElement} root
 * @param {import('../../core/router.js').PageContext} ctx
 */
export async function mount(root, ctx) {
  const id = ctx.params.id;
  const path = `/admin/groups/${encodeURIComponent(id)}`;
  const mayManage = can('groups.manage');
  const headerSlot = h('div');
  const body = h('div', { class: 'stack' }, skeleton(6));
  append(root, headerSlot, body);

  /** @type {any} */
  let group = null;
  /** @type {any[]} */
  let members = [];

  const t = table({
    caption: 'Members',
    rowKey: 'user_id',
    columns: [
      {
        key: 'user',
        label: 'Member',
        render: (m) => h('a', { class: 'row-link', href: `/admin/users/${encodeURIComponent(m.user_id)}` }, userCell({ id: m.user_id, username: m.username, display_name: m.display_name })),
      },
      {
        key: 'source',
        label: 'Source',
        hideBelow: 'sm',
        render: (m) => h('span', { class: 'cluster' },
          // a server without roles sends no "direct": every membership is direct there
          // "(manager)" only where a role could also make them one; otherwise the Manager column says it
          m.direct !== false ? badge({ text: m.direct_role === 'manager' && viaRoles(m).length ? 'Direct (manager)' : 'Direct', kind: 'neutral', icon: 'user' }) : null,
          viaRoles(m).map((r) => badge({ text: `Role: ${r.name || 'a role'}${r.member_role === 'manager' ? ' (manager)' : ''}`, kind: 'primary', icon: 'shield' }))),
      },
      {
        key: 'role',
        label: 'Manager',
        render: (m) => {
          const via = viaRoles(m);
          const direct = m.direct !== false;
          // A role that makes them a manager decides; an individual change could not undo it.
          const roleManager = via.filter((r) => r.member_role === 'manager');
          const why = !direct ? `Set by the role ${roleNames(via)} — change it on the role`
            : roleManager.length ? `Manager through the role ${roleNames(roleManager)} — change it on the role`
              : !mayManage ? 'Changing managers needs the “Manage groups” permission' : '';
          const input = h('input', {
            attrs: { type: 'checkbox', role: 'switch', 'aria-label': `${m.display_name || m.username} is a manager`, title: why || null },
            checked: m.role === 'manager',
            disabled: !!why,
            on: { change: () => setRole(m, input.checked ? 'manager' : 'member', input) },
          });
          return h('label', { class: 'check-hit switch-cell', attrs: { title: why || null } }, input);
        },
      },
      { key: 'added', label: 'Added', hideBelow: 'sm', render: (m) => timeEl(m.added_at) },
      {
        key: 'actions', label: 'Actions', srOnlyLabel: true, class: 'cell-actions',
        render: (m) => {
          if (!mayManage) return null;
          if (m.direct === false) {
            return iconButton({ icon: 'x', label: `Remove ${m.username} from the group`, size: 'sm', disabled: true, attrs: { title: `Set by the role ${roleNames(viaRoles(m))} — change it on the role` } });
          }
          return iconButton({ icon: 'x', label: `Remove ${m.username} from the group`, size: 'sm', onClick: () => remove(m) });
        },
      },
    ],
    empty: emptyState({ icon: 'users', title: 'No members yet', text: mayManage ? 'Add people or a role so they can use the team folder.' : 'Nobody uses this team folder yet.' }),
  });

  const load = async () => {
    try {
      const [g, m] = await Promise.all([api.get(path, { signal: ctx.signal }), api.get(`${path}/members`, { signal: ctx.signal })]);
      group = g;
      members = itemsOf(m).sort((a, b) => Number(b.role === 'manager') - Number(a.role === 'manager') || String(a.username).localeCompare(String(b.username)));
    } catch (err) {
      if (err instanceof ApiError && err.aborted) return;
      replace(headerSlot);
      adminHeader(headerSlot, { title: 'Group', crumbs: [{ label: 'Groups', href: '/admin/groups' }] });
      replace(body, errorPanel(err, load, err instanceof ApiError && err.status === 404 ? 'This group does not exist' : undefined));
      return;
    }
    draw();
  };

  const draw = () => {
    setTitle(group.name);
    replace(headerSlot);
    adminHeader(headerSlot, {
      title: group.name,
      subtitle: group.description || `${plural(members.length, 'member')} · created ${new Date(group.created_at).toLocaleDateString()}`,
      crumbs: [{ label: 'Groups', href: '/admin/groups' }],
      actions: mayManage ? [
        button({ label: 'Edit', icon: 'edit', onClick: edit }),
        button({ label: 'Add members', icon: 'user-plus', variant: 'primary', onClick: add }),
      ] : null,
    });
    t.setRows(members);
    const viaRoleOnly = members.filter((m) => m.direct === false).length;
    replace(body,
      mayManage ? null : alertEl('info', 'Read-only', 'Changing groups, their members and roles needs the “Manage groups” permission.'),
      h('section', { class: 'page-section' },
        h('div', { class: 'split' }, h('h2', { class: 'text-lg', text: `Members (${members.length})` })),
        h('p', { class: 'muted text-sm', text: 'Members can upload, edit and delete files in the team folder. Managers can also share it with others and create links.' }),
        viaRoleOnly ? h('p', { class: 'muted text-sm', text: `${plural(viaRoleOnly, 'member')} ${viaRoleOnly === 1 ? 'belongs' : 'belong'} to the group through a role; change those on the role.` }) : null,
        t.el),
      rolesCard(),
      mayManage ? h('section', { class: 'card danger-zone' },
        h('h2', { class: 'card-title', text: 'Danger zone' }),
        h('div', { class: 'danger-row' },
          h('div', { class: 'stack-sm gap-1' },
            h('strong', { text: 'Delete this group' }),
            h('span', { class: 'muted text-sm', text: 'The group and its team folder — including every file in it — are deleted.' })),
          button({ label: 'Delete group', icon: 'trash', variant: 'danger', onClick: del }))) : null);
  };

  // ------------------------------------------------------------------------------------------ roles in the group
  /** The custom roles that are members of the group (core.RoleGroup). */
  const groupRoles = () => (Array.isArray(group?.roles) ? group.roles : []);

  const rolesCard = () => {
    // a server without roles has no role memberships
    if (!rolesSupported()) return null;
    const list = groupRoles();
    /** @param {any} rg core.RoleGroup */
    const row = (rg) => {
      const sel = h('select', {
        class: 'access-level',
        attrs: { 'aria-label': `Role of everyone with ${rg.role_name} in ${group.name}` },
        disabled: !mayManage,
        on: {
          change: async () => {
            try {
              await api.put(`/admin/roles/${encodeURIComponent(rg.role_id)}/groups/${encodeURIComponent(group.id)}`, { member_role: sel.value });
              rg.member_role = sel.value;
              toast.success(sel.value === 'manager' ? `Everyone with the role ${rg.role_name} now manages the group` : `Everyone with the role ${rg.role_name} is now a member`);
              await load();
            } catch (err) {
              sel.value = rg.member_role;
              toast.error(err);
            }
          },
        },
      }, [['member', 'Member'], ['manager', 'Manager']].map(([v, l]) => h('option', { attrs: { value: v }, text: l, selected: v === rg.member_role })));
      return h('li', { class: 'access-row' },
        h('span', { class: 'access-icon', attrs: { 'aria-hidden': 'true' } }, icon('shield')),
        h('span', { class: 'access-main' },
          h('a', { class: 'access-name', href: `/admin/roles/${encodeURIComponent(rg.role_id)}`, text: rg.role_name || 'Role' }),
          h('span', { class: 'access-sub' }, 'Added ', timeEl(rg.added_at))),
        h('span', { class: 'access-actions' },
          sel,
          mayManage ? iconButton({ icon: 'x', label: `Remove the role ${rg.role_name} from the group`, size: 'sm', onClick: () => removeRole(rg) }) : null));
    };
    return card({
      title: `Roles in this group (${list.length})`,
      headerActions: mayManage ? button({ label: 'Add a role', icon: 'shield', size: 'sm', variant: 'secondary', onClick: addRole }) : null,
      body: h('div', { class: 'stack-sm' },
        h('p', { class: 'muted text-sm', text: 'Everyone with one of these roles is a member of the group and sees its team folder — including people who get the role later. Individual memberships are kept.' }),
        list.length
          ? h('ul', { class: 'access-list', attrs: { role: 'list' } }, list.map(row))
          : h('p', { class: 'muted text-sm', text: 'No role is a member of this group.' })),
    });
  };

  const addRole = async () => {
    /** @type {any[]} */
    let roles;
    try {
      roles = await loadRoles();
    } catch (err) {
      toast.error(err);
      return;
    }
    const taken = new Set(groupRoles().map((rg) => rg.role_id));
    // built-in roles are never group members: a group of "all members" would be every account
    const choices = roles.filter((r) => isCustomRoleId(r.id) && !taken.has(r.id));
    if (!choices.length) {
      toast.info(roles.some((r) => isCustomRoleId(r.id)) ? 'Every custom role is already a member of this group.' : 'There are no custom roles yet. An administrator can create them under Admin → Roles.');
      return;
    }
    const role = select({
      label: 'Role',
      name: 'role_id',
      required: true,
      value: choices[0].id,
      options: choices.map((r) => ({ value: String(r.id), label: `${r.name} · ${roleBaseText(r).toLowerCase()}` })),
    });
    const managers = toggle({ label: 'Managers of the group (can share its team folder)', name: 'manager', checked: false });
    const done = await formDialog({
      title: `Add a role to ${group.name}`,
      intro: 'Everyone with the role becomes a member of the group and sees its team folder.',
      fields: [role, managers],
      submitLabel: 'Add role',
      submitIcon: 'shield',
      onSubmit: async (v) => {
        await api.put(`/admin/roles/${encodeURIComponent(String(v.role_id))}/groups/${encodeURIComponent(group.id)}`, { member_role: v.manager ? 'manager' : 'member' });
        return choices.find((r) => r.id === v.role_id) || true;
      },
    });
    if (!done) return;
    toast.success(done.name ? `The role ${done.name} was added to “${group.name}”` : `The role was added to “${group.name}”`);
    clearRoleCache();
    await load();
  };

  /** @param {any} rg core.RoleGroup */
  const removeRole = async (rg) => {
    const ok = await confirm({
      title: `Remove the role ${rg.role_name} from “${group.name}”?`,
      message: 'People with this role lose the team folder of the group, unless they are members themselves.',
      confirmLabel: 'Remove',
      danger: true,
    });
    if (!ok) return;
    try {
      await api.del(`/admin/roles/${encodeURIComponent(rg.role_id)}/groups/${encodeURIComponent(group.id)}`);
      toast.success(`The role ${rg.role_name} was removed from “${group.name}”`);
      clearRoleCache();
      await load();
    } catch (err) {
      toast.error(err);
    }
  };

  // ------------------------------------------------------------------------------------------ members
  const edit = async () => {
    const g = await groupDialog(group);
    if (!g) return;
    toast.success('Group saved');
    await load();
  };

  const add = async () => {
    // people who are members only through a role can still be added directly (they then stay when the role goes)
    const exclude = members.filter((m) => m.direct !== false).map((m) => m.user_id);
    const picker = userPicker({ label: 'Person', name: 'user_id', required: true, exclude });
    const role = select({
      label: 'Role in the group',
      name: 'role',
      value: 'member',
      options: [{ value: 'member', label: 'Member — use the team folder' }, { value: 'manager', label: 'Manager — also share it' }],
    });
    let addedAny = false;
    await formDialog({
      title: `Add people to ${group.name}`,
      intro: 'Pick someone and add them. You can add several people one after another.',
      fields: [picker, role],
      submitLabel: 'Add',
      submitIcon: 'user-plus',
      onSubmit: async (v) => {
        const uid = String(v.user_id || '');
        if (!uid) throw new ApiError(422, 'invalid', 'Search for a person and pick them from the list.', 'user_id');
        await api.put(`${path}/members/${encodeURIComponent(uid)}`, { role: v.role });
        const who = picker.selected();
        toast.success(`${who?.display_name || who?.username || 'User'} added`);
        addedAny = true;
        picker.clear();
        exclude.push(uid);
        return false; // keep the dialog open for the next person
      },
    });
    if (addedAny) await load();
  };

  /**
   * @param {any} m
   * @param {'member' | 'manager'} r
   * @param {HTMLInputElement} input
   */
  const setRole = async (m, r, input) => {
    input.disabled = true;
    try {
      await api.put(`${path}/members/${encodeURIComponent(m.user_id)}`, { role: r });
      m.role = r;
      m.direct_role = r;
      toast.success(`${m.display_name || m.username} is now a ${r}`);
    } catch (err) {
      input.checked = m.role === 'manager';
      toast.error(err);
    } finally {
      input.disabled = false;
    }
  };

  /** @param {any} m */
  const remove = async (m) => {
    const via = viaRoles(m);
    const ok = await confirm({
      title: `Remove ${m.display_name || m.username}?`,
      message: via.length
        ? `Their own membership ends, but they stay in “${group.name}” through the role ${roleNames(via)}.`
        : `They lose access to the “${group.name}” team folder. Files they added stay in the folder.`,
      confirmLabel: 'Remove',
      danger: !via.length,
    });
    if (!ok) return;
    try {
      await api.del(`${path}/members/${encodeURIComponent(m.user_id)}`);
      toast.success('Member removed');
      await load();
    } catch (err) {
      toast.error(err);
    }
  };

  const del = async () => {
    const roles = groupRoles().length;
    const ok = await confirmTyped({
      title: `Delete “${group.name}”?`,
      message: h('div', { class: 'stack-sm' },
        alertEl('danger', 'Every file in the team folder is deleted', 'This cannot be undone. Move files you want to keep to someone’s personal folder first.'),
        h('p', { text: `${plural(members.length, 'member')} will lose access.${roles ? ` ${plural(roles, 'role')} ${roles === 1 ? 'is' : 'are'} removed from it.` : ''}` })),
      expected: group.name,
      confirmLabel: 'Delete group',
    });
    if (!ok) return;
    try {
      await api.del(path);
      toast.success(`Group “${group.name}” deleted`);
      clearRoleCache();
      navigate('/admin/groups');
    } catch (err) {
      toast.error(err);
    }
  };

  await load();
}
