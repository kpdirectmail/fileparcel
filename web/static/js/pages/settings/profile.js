// @ts-check
/**
 * Settings → Profile (/settings/profile): display name, email, password, storage usage and group memberships, with a
 * summary of the account's role and "What can I do?" (the role's permissions, labelled from core/perms.js — the
 * catalog itself needs "View people").
 *   PATCH /me/profile {display_name, email}   (core.ProfileUpdate; "" clears the email)
 *   POST  /me/password                        (see settings/common.js passwordForm)
 *   GET   /me/usage                           (core.Usage)
 * Owned by unit J2.
 * @module pages/settings/profile
 */
import { h, replace, append } from '../../core/dom.js';
import { api, ApiError } from '../../core/api.js';
import { session, can, hasSpace, isAdmin, isStaff } from '../../core/store.js';
import { PERMISSION_LABELS } from '../../core/perms.js';
import { bytes, pct, date, relTime } from '../../core/format.js';
import { card } from '../../components/card.js';
import { form } from '../../components/form.js';
import { field } from '../../components/field.js';
import { toast } from '../../components/toast.js';
import { progress, skeleton } from '../../components/progress.js';
import { badge } from '../../components/badge.js';
import { button } from '../../components/button.js';
import { sheet } from '../../components/sheet.js';
import { settingsHeader, refreshMe, passwordForm } from './common.js';
import { kv, roleBadge, avatarEl, errorPanel, timeEl, permissionChips, isCustomRoleId, BUILTIN_ROLE_NAMES } from '../admin/common.js';

export const title = 'Profile';

/** What the built-in roles mean for the account holder. @type {Record<string, string>} */
const ROLE_HELP = {
  owner: 'You own this server and can change everything, including other administrators.',
  admin: 'You can manage users, groups and server settings.',
  member: 'You have your own files and can share them.',
  guest: 'You can open files and folders that others share with you.',
};

/**
 * One line about the account's role: the built-in role's meaning, or for a custom role what it is based on (the
 * description of a custom role is not part of /me).
 * @param {any} user BootUser
 */
function roleHelp(user) {
  if (!isCustomRoleId(user.role_id)) return ROLE_HELP[user.role_id || user.role] || '';
  const base = BUILTIN_ROLE_NAMES[user.role] || user.role || 'Member';
  return `Custom role · based on ${base}${isStaff() ? ' · opens parts of the Admin area' : ''}`;
}

/**
 * "What can I do?": the permissions of the account's role, grouped (sharing and account, server).
 * @param {any} user BootUser
 */
function openPermissions(user) {
  // Every permission name the role grants: the /me list, and for a server without role lists what can() derives.
  const known = Object.keys(PERMISSION_LABELS).filter((p) => can(p));
  const extra = (Array.isArray(user.permissions) ? user.permissions : []).filter((p) => !(p in PERMISSION_LABELS));
  const perms = [...known, ...extra];
  sheet({
    title: 'What can I do?',
    content: h('div', { class: 'stack role-perms-sheet' },
      h('p', { class: 'cluster' }, 'Your role: ', roleBadge(user)),
      isAdmin()
        ? h('p', { class: 'text-sm', text: 'Owners and admins have every permission, plus the administrator-only areas: roles, security, e-mail, backup and server settings, encryption keys, custom certificates, backup restore and access to everyone’s files.' })
        : permissionChips(perms, null, { empty: 'Nothing beyond your own files and what is shared with you.' }),
      !isAdmin() && isStaff() ? h('p', { class: 'muted text-sm' }, 'Your server permissions open parts of the ', h('a', { href: '/admin', text: 'Admin area' }), '.') : null,
      h('p', { class: 'muted text-sm', text: hasSpace()
        ? 'On top of this you use your own files, the team folders of your groups and everything shared with you.'
        : 'You have no personal space: you work in the team folders of your groups and in what is shared with you or your role.' }),
      isAdmin() ? null : h('p', { class: 'muted text-sm', text: 'Your role is set by an administrator. Ask them if you need something else.' })),
  }).open();
}

/**
 * @param {HTMLElement} root
 * @param {import('../../core/router.js').PageContext} ctx
 */
export async function mount(root, ctx) {
  settingsHeader(root, { id: 'settings-profile', title, subtitle: 'Your name, email address and password.' });
  const me = (await refreshMe(ctx.signal)) || session.peek();
  if (ctx.signal.aborted) return;
  const user = /** @type {any} */ (me?.user || {});

  // ---- account ----
  const display = field({ label: 'Display name', name: 'display_name', value: user.display_name || '', autocomplete: 'name', maxlength: 100, help: 'Shown to people you share files with.' });
  const email = field({ label: 'Email', name: 'email', type: 'email', value: user.email || '', autocomplete: 'email', maxlength: 254, help: 'Used for notifications. Leave empty to remove it.' });
  const profileForm = form({
    fields: [display, email],
    submitLabel: 'Save profile',
    submitIcon: 'check',
    onSubmit: async (v) => {
      const body = { display_name: String(v.display_name).trim(), email: String(v.email).trim() };
      const res = await api.patch('/me/profile', body);
      const cur = /** @type {any} */ (session.peek());
      if (cur) session.value = { ...cur, user: { ...cur.user, ...(res && res.id ? res : body) } };
      display.input.defaultValue = body.display_name;
      email.input.defaultValue = body.email;
      toast.success('Profile saved');
      head.replaceWith(head = accountHead(/** @type {any} */ (session.peek())?.user || user));
    },
  });

  let head = accountHead(user);
  const accountCard = card({ title: 'Account', body: h('div', { class: 'stack' }, head, profileForm.el) });

  // ---- password ----
  const pwCard = card({
    title: 'Password',
    body: h('div', { class: 'stack' },
      user.password_changed_at ? h('p', { class: 'muted text-sm' }, 'Last changed ', timeEl(user.password_changed_at), '.') : null,
      passwordForm().el),
  });
  pwCard.id = 'password';

  // ---- storage ----
  const usageBody = h('div', { class: 'stack-sm' }, skeleton(2));
  const usageCard = card({ title: 'Storage', body: usageBody });

  // ---- groups ----
  const groups = Array.isArray(me?.groups) ? me.groups : [];
  const groupsCard = card({
    title: 'Groups',
    body: groups.length
      ? h('ul', { class: 'plain-list', attrs: { role: 'list' } }, groups.map((g) => h('li', { class: 'split' },
        h('span', { class: 'stack-sm gap-1' }, h('strong', { text: g.name }), g.description ? h('span', { class: 'muted text-sm', text: g.description }) : null),
        badge({ text: g.my_role === 'manager' ? 'Manager' : 'Member', kind: g.my_role === 'manager' ? 'primary' : 'neutral' }))))
      : h('p', { class: 'muted', text: 'You are not in any group. Groups give you access to shared team folders.' }),
  });

  append(root, h('div', { class: 'settings-grid' },
    h('div', { class: 'stack' }, accountCard, pwCard),
    h('div', { class: 'stack' }, usageCard, groupsCard)));

  if (location.hash === '#password') {
    pwCard.scrollIntoView({ block: 'start' });
    /** @type {HTMLInputElement | null} */ (pwCard.querySelector('input[type="password"]'))?.focus({ preventScroll: true });
  }

  if (!hasSpace(me)) {
    replace(usageBody, h('p', { class: 'muted', text: 'Your role has no personal storage. You can still upload into folders that are shared with you for editing.' }));
    return;
  }
  try {
    const u = await api.get('/me/usage', { signal: ctx.signal });
    replace(usageBody, usageView(u));
  } catch (err) {
    if (err instanceof ApiError && err.aborted) return;
    replace(usageBody, errorPanel(err));
  }
}

/**
 * Avatar, name and role summary.
 * @param {any} user
 */
function accountHead(user) {
  return h('div', { class: 'profile-head' },
    avatarEl(user, 56),
    h('div', { class: 'stack-sm gap-1' },
      h('strong', { class: 'text-md', text: user.display_name || user.username || '' }),
      h('span', { class: 'muted text-sm' }, `@${user.username || ''}`, user.created_at ? ` · member since ${date(user.created_at)}` : ''),
      h('span', { class: 'cluster' }, roleBadge(user), user.mfa_enabled ? badge({ text: '2FA on', kind: 'success', icon: 'shield-check' }) : null),
      roleHelp(user) ? h('span', { class: 'subtle text-xs', text: roleHelp(user) }) : null,
      h('span', null, button({ label: 'What can I do?', icon: 'shield', size: 'sm', variant: 'ghost', onClick: () => openPermissions(user) })),
      user.last_login_at ? h('span', { class: 'subtle text-xs', text: `Last sign-in ${relTime(user.last_login_at)}${user.last_login_ip ? ` from ${user.last_login_ip}` : ''}` }) : null));
}

/**
 * Usage meter.
 * @param {any} u core.Usage
 */
function usageView(u) {
  const used = Number(u?.used_bytes) || 0;
  const quota = Number(u?.quota_bytes) || 0;
  const trash = Number(u?.trash_bytes) || 0;
  const reserved = Number(u?.reserved_bytes) || 0;
  const ratio = quota > 0 ? used / quota : 0;
  const bar = progress({ value: quota > 0 ? used : null, max: quota > 0 ? quota : 1, label: quota > 0 ? `${bytes(used)} of ${bytes(quota)} used` : `${bytes(used)} used`, kind: ratio > 0.95 ? 'danger' : ratio > 0.8 ? 'warning' : 'primary' });
  if (quota <= 0) bar.el.querySelector('progress')?.remove();
  return h('div', { class: 'stack-sm' },
    bar.el,
    kv([
      ['Quota', quota > 0 ? `${bytes(quota)} (${pct(used, quota)} used)` : 'Unlimited'],
      ['In trash', trash ? `${bytes(trash)} (counts towards your quota until the trash is emptied)` : 'Nothing'],
      ['Uploading', reserved ? `${bytes(reserved)} reserved for uploads in progress` : null],
    ]));
}
