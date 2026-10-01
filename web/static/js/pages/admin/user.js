// @ts-check
/**
 * Admin → User detail (/admin/users/:id): profile, role, quota, status, what the account can reach (the Access card:
 * server permissions, groups and team folders with where the membership comes from, items shared with them), sign-in
 * security (password reset, 2FA reset, unlock), sessions and deletion with file transfer.
 * Controls follow the caller's role (DESIGN §6a): editing needs "Manage accounts" and an account the caller may
 * manage (UserAccess.manageable), the sign-in controls "Reset sign-in"; everything else is shown read-only.
 *   GET    /admin/users/{id}                 → User
 *   GET    /admin/users/{id}/access          → UserAccess {role, permissions, groups, grants, hidden_grants, manageable, …}
 *   PATCH  /admin/users/{id}                 UserUpdate {display_name, email, role_id (E), quota_bytes (null|0|n), must_change_password}
 *   POST   /admin/users/{id}/password (E)    PasswordResetInput {password | generate, must_change} → PasswordReset {password?}
 *   POST   /admin/users/{id}/reset-mfa (E) · /unlock · /disable · /enable
 *   GET    /admin/users/{id}/sessions        → Session[]      DELETE /admin/users/{id}/sessions (sign out everywhere)
 *   DELETE /admin/users/{id}?transfer_to=    (E) — personal files move to that user, else they are deleted
 *   GET    /admin/roles, /admin/capabilities (role picker, permission labels)
 * Owned by unit J2.
 * @module pages/admin/user
 */
import { h, icon, replace, append } from '../../core/dom.js';
import { api, ApiError, itemsOf, errorMessage } from '../../core/api.js';
import { navigate, setTitle } from '../../core/router.js';
import { isAdmin, can } from '../../core/store.js';
import { isServerPermission } from '../../core/perms.js';
import { dateTime, plural } from '../../core/format.js';
import { card } from '../../components/card.js';
import { button } from '../../components/button.js';
import { badge } from '../../components/badge.js';
import { form } from '../../components/form.js';
import { field, toggle, checkbox } from '../../components/field.js';
import { toast } from '../../components/toast.js';
import { confirm } from '../../components/dialog.js';
import { skeleton } from '../../components/progress.js';
import {
  adminHeader, errorPanel, roleBadge, kv, timeEl, avatarEl, alertEl, formDialog, confirmTyped, userPicker, quotaField, quotaText,
  showSecretOnce, describeUA, uaIcon, userLabel, me as currentUser, roleSelect, loadRolesOrBuiltins, loadCatalog, permissionChips,
  mayManageAccount, confirmRoleChange, grantLocation, isCustomRoleId, GRANT_LEVELS, rolesSupported,
} from './common.js';
import { strengthMeter, generatePassword, estimate } from '../../public/password-strength.js';
import { signOut } from '../../nav.js';

export const title = 'User';

/**
 * @param {HTMLElement} root
 * @param {import('../../core/router.js').PageContext} ctx
 */
export async function mount(root, ctx) {
  const id = ctx.params.id;
  const path = `/admin/users/${encodeURIComponent(id)}`;
  const self = currentUser();
  const headerSlot = h('div');
  const body = h('div', { class: 'stack' }, skeleton(8));
  append(root, headerSlot, body);

  /** @type {any} */
  let user = null;
  /** What the account can reach (core.UserAccess); null when it could not be read (accessErr says why). @type {any} */
  let access = null;
  /** @type {unknown} */
  let accessErr = null;
  /** Roles for the picker (core.RoleDef; the built-in roles when they cannot be read). @type {any[]} */
  let roles = [];
  /** The permission catalog (labels and groups of the Access card); null when it cannot be read. @type {any} */
  let catalog = null;
  /** The Access card needs a server with roles (GET …/access, /admin/capabilities). */
  const withAccess = rolesSupported();

  const load = async () => {
    /** @type {any[]} */
    let got;
    try {
      got = await Promise.all([
        api.get(path, { signal: ctx.signal }),
        // the Access card only: its failure (a permission, a hiccup) must not hide the rest of the page
        withAccess ? api.get(`${path}/access`, { signal: ctx.signal, handle: false }).then((ok) => ({ ok }), (err) => ({ err })) : {},
        // the role picker, and whether the account's custom role may be managed by a delegate (customRole())
        (can('users.manage') || can('users.credentials')) && !roles.length ? loadRolesOrBuiltins().then((r) => { roles = r; }) : null,
        !withAccess || catalog ? null : loadCatalog().then((c) => { catalog = c; }, () => {}),
      ]);
    } catch (err) {
      if (err instanceof ApiError && err.aborted) return;
      replace(headerSlot);
      adminHeader(headerSlot, { title: 'User', crumbs: [{ label: 'Users', href: '/admin/users' }] });
      replace(body, errorPanel(err, load, err instanceof ApiError && err.status === 404 ? 'This user does not exist' : undefined));
      return;
    }
    if (got[1].err instanceof ApiError && got[1].err.aborted) return;
    [user] = got;
    access = got[1].ok || null;
    accessErr = got[1].err || null;
    draw();
  };

  const isSelf = () => !!self && user?.id === self.id;
  const locked = () => !!user?.locked_until && new Date(user.locked_until).getTime() > Date.now();
  /**
   * The custom role of the account (core.RoleDef): from the roles list, else from the Access card (UserAccess.role),
   * so its `delegable` flag is known even when the roles could not be listed.
   */
  const customRole = () => {
    if (!isCustomRoleId(user?.role_id)) return undefined;
    return roles.find((r) => r.id === user.role_id) || (access?.role?.id === user.role_id ? access.role : undefined);
  };
  /**
   * Whether the caller may change this account (profile, role, quota, status, deletion): "Manage accounts" and an
   * account their role may manage — the server's answer (UserAccess.manageable) when it gave one.
   */
  const manageable = () => can('users.manage') && (access ? !!access.manageable : mayManageAccount(user, { role: customRole() }));
  /**
   * Whether the caller may reset the sign-in of this account (password, 2FA, sessions) here. On their own account
   * only administrators may; everyone else uses their own settings pages.
   */
  const credentials = () => mayManageAccount(user, { need: 'users.credentials', role: customRole() });

  const draw = () => {
    const name = user.display_name || user.username;
    setTitle(name);
    replace(headerSlot);
    adminHeader(headerSlot, {
      title: name,
      crumbs: [{ label: 'Users', href: '/admin/users' }],
      subtitle: h('span', { class: 'cluster' }, `@${user.username}`, roleBadge(user),
        user.status === 'disabled' ? badge({ text: 'Disabled', kind: 'neutral' }) : badge({ text: 'Active', kind: 'success' }),
        locked() ? badge({ text: 'Locked', kind: 'warning', icon: 'lock' }) : null,
        user.mfa_enabled ? badge({ text: '2FA on', kind: 'info', icon: 'shield-check' }) : badge({ text: '2FA off', kind: 'neutral' })),
      actions: isSelf() ? h('a', { class: 'btn btn--secondary', href: '/settings/profile' }, icon('user'), h('span', { text: 'Your profile' })) : null,
    });
    const creds = credentials();
    const sessionsBody = h('div', { class: 'stack-sm' }, creds ? skeleton(2)
      : isSelf() ? h('p', { class: 'muted text-sm' }, 'Your own sessions are under ', h('a', { href: '/settings/sessions', text: 'Settings → Sessions' }), '.')
        : h('p', { class: 'muted text-sm', text: user.role === 'owner' && self?.role !== 'owner'
          ? 'Only an owner can see or revoke the sessions of an owner account.'
          : 'Your role can’t see or end the sessions of this account.' }));
    const manage = manageable();
    replace(body, 
      isSelf() ? alertEl('info', 'This is your own account', 'Some actions (disabling, deleting, changing your own role) are not available here.') : null,
      user.status === 'disabled' ? alertEl('warning', 'This account is disabled', 'The user cannot sign in and their share links do not work.',
        isSelf() || !manage ? null : button({ label: 'Enable account', size: 'sm', icon: 'check-circle', onClick: () => simple('enable', 'Account enabled') })) : null,
      locked() ? alertEl('warning', 'Sign-in is locked', `Too many failed sign-in attempts. Locked until ${dateTime(user.locked_until)}.`,
        manage ? button({ label: 'Unlock now', size: 'sm', icon: 'unlock', onClick: () => simple('unlock', 'Sign-in unlocked') }) : null) : null,
      h('div', { class: 'settings-grid' },
        h('div', { class: 'stack' }, profileCard(), roleCard(), accessCard()),
        h('div', { class: 'stack' }, securityCard(),
          can('users.credentials') ? card({ title: 'Sessions', body: sessionsBody, headerActions: creds ? signOutAllBtn() : null }) : null)),
      dangerCard());
    if (creds) loadSessions(sessionsBody);
  };

  // ------------------------------------------------------------------------------------------ profile
  const profileCard = () => {
    const head = h('div', { class: 'profile-head' }, avatarEl(user, 48), kv([
      ['Username', h('span', { class: 'mono', text: user.username })],
      ['Created', h('span', null, timeEl(user.created_at), creatorEl())],
      ['Last sign-in', user.last_login_at ? h('span', null, timeEl(user.last_login_at), user.last_login_ip ? h('span', { class: 'mono', text: ` from ${user.last_login_ip}` }) : null) : 'Never'],
    ]));
    // The name and address of someone else's account need "Manage accounts" on it. Your own are changed under
    // Settings → Profile, which asks you to confirm your identity for a new address and alerts the previous one.
    if (isSelf() || !can('users.manage') || !manageable()) {
      return card({
        title: 'Profile',
        body: h('div', { class: 'stack' }, head, kv([
          ['Display name', user.display_name || h('span', { class: 'subtle', text: 'Not set' })],
          ['Email', user.email ? h('span', { class: 'break', text: user.email }) : h('span', { class: 'subtle', text: 'Not set' })],
        ]), isSelf() ? h('p', { class: 'muted text-sm' }, 'Change your own name and e-mail address under ',
          h('a', { href: '/settings/profile', text: 'Settings → Profile' }), '.') : null),
      });
    }
    const display = field({ label: 'Display name', name: 'display_name', value: user.display_name || '', maxlength: 100, autocomplete: 'off' });
    const email = field({ label: 'Email', name: 'email', type: 'email', value: user.email || '', maxlength: 254, autocomplete: 'off', help: 'Leave empty to remove it.' });
    const f = form({
      fields: [display, email],
      submitLabel: 'Save',
      submitIcon: 'check',
      onSubmit: async (v) => {
        user = await patch({ display_name: String(v.display_name).trim(), email: String(v.email).trim() });
        toast.success('Profile saved');
        draw();
      },
    });
    return card({ title: 'Profile', body: h('div', { class: 'stack' }, head, f.el) });
  };

  /**
   * " by <name>" for the account that created this user. users.created_by holds a user id (no foreign key, so the
   * creator may be gone): resolve it once and never show the raw id.
   * @type {{id: string, req: Promise<any>} | null}
   */
  let creator = null;
  const creatorEl = () => {
    const cid = user.created_by;
    if (!cid) return null;
    const slot = h('span');
    if (!creator || creator.id !== cid) {
      creator = {
        id: cid,
        // null = deleted account, undefined = could not be looked up (show nothing)
        req: api.get(`/admin/users/${encodeURIComponent(cid)}`, { signal: ctx.signal, handle: false })
          .catch((err) => (err instanceof ApiError && err.status === 404 ? null : undefined)),
      };
    }
    creator.req.then((u) => {
      if (u === undefined) return;
      replace(slot, ' by ', u?.id ? h('a', { href: `/admin/users/${encodeURIComponent(u.id)}`, text: userLabel(u) }) : 'an account that was deleted');
    });
    return slot;
  };

  // ------------------------------------------------------------------------------------------ role & quota
  const roleCard = () => {
    const quotaNow = h('p', { class: 'muted text-sm' }, 'Current quota: ', h('strong', { text: quotaText(user.quota_bytes) }));
    if (!manageable()) {
      const ownerOnly = user.role === 'owner' && self?.role !== 'owner';
      const why = !can('users.manage') ? null
        : isSelf() ? alertEl('info', 'Your own account', 'Ask an administrator to change your role, quota or password rules.')
          : ownerOnly ? alertEl('info', 'Owner account', 'Only an owner can change an owner account.')
            : alertEl('info', 'You can’t change this account', 'This account has server permissions or a role you can’t manage.');
      return card({
        title: 'Role & storage',
        body: h('div', { class: 'stack' }, why, kv([
          ['Role', roleBadge(user)],
          ['Storage quota', quotaText(user.quota_bytes)],
          ['New password at next sign-in', user.must_change_password ? 'Required' : 'Not required'],
        ])),
      });
    }
    const current = String(user.role_id || user.role || 'member');
    const role = roleSelect({
      label: 'Role',
      name: 'role_id',
      value: current,
      roles,
      disabled: isSelf(),
      help: isSelf() ? 'You cannot change your own role.' : 'Changing the role asks you to confirm your identity.',
    });
    const quota = quotaField({ label: 'Storage quota', name: 'quota_bytes', value: user.quota_bytes ?? null, help: 'Includes files in the trash.' });
    const mustChange = toggle({ label: 'Require a new password at next sign-in', name: 'must_change_password', checked: !!user.must_change_password });
    const f = form({
      fields: [role, quota, mustChange],
      submitLabel: 'Save access',
      submitIcon: 'check',
      onSubmit: async (v) => {
        /** @type {Record<string, any>} */
        const changes = {};
        const to = role.selected();
        if (!isSelf() && to && String(v.role_id) !== current) {
          if (!(await confirmRoleChange(user, to))) return;
          changes.role_id = to.id;
        }
        const q = quota.value();
        if (Number.isNaN(q)) throw new ApiError(422, 'invalid', 'Enter a size such as 50 GB.', 'quota_bytes');
        if (q !== (user.quota_bytes ?? null)) changes.quota_bytes = q;
        if (!!v.must_change_password !== !!user.must_change_password) changes.must_change_password = !!v.must_change_password;
        if (!Object.keys(changes).length) {
          toast.info('Nothing changed.');
          return;
        }
        user = await patch(changes);
        toast.success('Access updated');
        // a new role changes what the account can reach
        if (changes.role_id) await load();
        else draw();
      },
    });
    return card({ title: 'Role & storage', body: h('div', { class: 'stack' }, quotaNow, f.el) });
  };

  // ------------------------------------------------------------------------------------------ access
  const accessCard = () => {
    if (!withAccess) return null;
    if (!access) {
      return card({
        title: 'Access',
        body: accessErr ? errorPanel(accessErr, () => load(), 'What this account can reach could not be loaded') : skeleton(3),
      });
    }
    const a = access;
    const roleDef = a.role || {};
    const server = (Array.isArray(a.permissions) ? a.permissions : []).filter(isServerPermission);
    const onServer = user.role === 'owner' ? h('p', { class: 'text-sm', text: 'Everything, including owner accounts.' })
      : user.role === 'admin' ? h('p', { class: 'text-sm', text: 'Everything, except changing owner accounts.' })
        : server.length ? permissionChips(server, catalog)
          : h('p', { class: 'muted text-sm', text: 'Nothing on the server — a regular account.' });
    const roleId = String(roleDef.id || user.role_id || user.role || '');
    return card({
      title: 'Access',
      body: h('div', { class: 'stack' },
        a.files_override ? alertEl('warning', 'Can open everyone’s files (audited)', 'Owners and admins may manage every space while “Administrators can access all files” is on in Settings → Sign-in & security.') : null,
        kv([
          ['Role', h('span', { class: 'cluster' }, roleBadge(roleDef.id ? roleDef : user),
            roleId ? h('a', { class: 'role-help-link', href: `/admin/roles/${encodeURIComponent(roleId)}`, text: 'What can this role do?' }) : null)],
          ['My files', a.personal_space ? 'Has a personal “My files” space' : 'No personal space'],
          // counted only for callers who may see other people's tokens
          ['API tokens with admin access', can('users.credentials') ? String(Number(a.admin_tokens) || 0) : null],
        ]),
        h('div', { class: 'access-section' }, h('h3', { class: 'access-section-title', text: 'On the server' }), onServer),
        h('div', { class: 'access-section' }, h('h3', { class: 'access-section-title', text: 'Groups & team folders' }), accessGroups(a.groups)),
        h('div', { class: 'access-section' }, h('h3', { class: 'access-section-title', text: 'Shared with them' }), accessGrants(a.grants, Number(a.hidden_grants) || 0))),
    });
  };

  /**
   * Group memberships (core.AccessGroup), with where each comes from: "Direct" and/or "Through role Finance".
   * @param {any[] | undefined} groups
   */
  const accessGroups = (groups) => {
    const list = Array.isArray(groups) ? groups : [];
    if (!list.length) return h('p', { class: 'muted text-sm', text: 'Not in any group.' });
    return h('ul', { class: 'access-list', attrs: { role: 'list' } }, list.map((g) => {
      const via = Array.isArray(g.via_roles) ? g.via_roles : [];
      const sources = [
        g.direct ? h('span', { class: 'access-source', text: g.direct_role === 'manager' ? 'Direct (manager)' : 'Direct' }) : null,
        ...via.map((r) => h('span', { class: 'access-source' }, 'Through role ',
          h('a', { href: `/admin/roles/${encodeURIComponent(r.id)}`, text: r.name || 'a role' }),
          r.member_role === 'manager' ? ' (manager)' : '')),
      ];
      return h('li', { class: 'access-row' },
        h('span', { class: 'access-icon', attrs: { 'aria-hidden': 'true' } }, icon('users')),
        h('span', { class: 'access-main' },
          h('a', { class: 'access-name', href: `/admin/groups/${encodeURIComponent(g.group_id)}`, text: g.name || 'Group' }),
          h('span', { class: 'access-sub' }, sources)),
        h('span', { class: 'access-actions' }, badge({ text: g.role === 'manager' ? 'Manager' : 'Member', kind: g.role === 'manager' ? 'primary' : 'neutral' })));
    }));
  };

  /**
   * Items shared with the account (core.Grant with the derived node fields): directly, with one of their groups or
   * with their role. `hidden` counts shares on items the caller may not see.
   * @param {any[] | undefined} grants
   * @param {number} hidden
   */
  const accessGrants = (grants, hidden) => {
    const list = Array.isArray(grants) ? grants : [];
    /** @param {any} g */
    const via = (g) => (g.subject_type === 'group' ? `Group ${g.subject_name || ''}`.trim()
      : g.subject_type === 'role' ? `Role ${g.subject_name || ''}`.trim() : 'Person');
    return h('div', { class: 'stack-sm' },
      list.length
        ? h('ul', { class: 'access-list', attrs: { role: 'list' } }, list.map((g) => h('li', { class: 'access-row' },
          h('span', { class: 'access-icon', attrs: { 'aria-hidden': 'true' } }, icon(g.node_kind === 'folder' ? 'folder' : 'file')),
          h('span', { class: 'access-main' },
            h('span', { class: 'access-name', text: g.node_name || 'Untitled' }),
            h('span', { class: 'access-sub' }, h('span', { text: grantLocation(g) }), g.expires_at ? h('span', { text: `until ${dateTime(g.expires_at)}` }) : null)),
          h('span', { class: 'access-actions access-actions--badges' },
            badge({ text: GRANT_LEVELS[g.role] || g.role || 'Can view', kind: g.role === 'manager' ? 'primary' : 'neutral' }),
            badge({ text: via(g), kind: 'neutral', icon: g.subject_type === 'group' ? 'users' : g.subject_type === 'role' ? 'shield' : 'user' })))))
        : hidden ? null : h('p', { class: 'muted text-sm', text: 'Nothing is shared with them.' }),
      hidden ? h('p', { class: 'muted text-sm', text: `+ ${plural(hidden, 'private share')} not shown (items you cannot open, such as someone’s personal files).` }) : null);
  };

  // ------------------------------------------------------------------------------------------ security
  const securityCard = () => {
    const creds = credentials();
    const actions = [
      creds ? button({ label: 'Reset password', icon: 'key', onClick: resetPassword }) : null,
      creds && user.mfa_enabled ? button({ label: 'Reset two-factor', icon: 'shield', onClick: resetMFA }) : null,
      locked() && manageable() ? button({ label: 'Unlock sign-in', icon: 'unlock', onClick: () => simple('unlock', 'Sign-in unlocked') }) : null,
    ].filter(Boolean);
    return card({
      title: 'Sign-in security',
      body: h('div', { class: 'stack' },
        kv([
          ['Password', user.password_changed_at ? h('span', null, 'changed ', timeEl(user.password_changed_at)) : 'never changed'],
          ['Two-factor', user.mfa_enabled ? 'on (authenticator app or passkey)' : 'off'],
          ['Failed sign-ins', String(user.failed_logins ?? 0)],
          ['Lockouts', user.lock_level ? `${user.lock_level} (each doubles the lock time)` : 'none'],
        ]),
        actions.length ? h('div', { class: 'btn-row btn-row--start' }, actions)
          : isSelf() ? h('p', { class: 'muted text-sm' }, 'Change your own password under ', h('a', { href: '/settings/profile#password', text: 'Settings → Profile' }),
            ' and two-factor authentication under ', h('a', { href: '/settings/security', text: 'Settings → Security' }), '.')
            : h('p', { class: 'muted text-sm', text: can('users.credentials')
              ? 'Your role can’t reset the sign-in of this account.'
              : 'Resetting passwords and two-factor authentication needs the “Reset sign-in” permission.' })),
    });
  };

  const resetPassword = async () => {
    const generate = toggle({ label: 'Generate a temporary password', name: 'generate', checked: true, help: 'Shown once so you can pass it on. They must choose their own password when they sign in.' });
    const pw = field({ label: 'New password', name: 'password', type: 'password', autocomplete: 'new-password', minlength: 8, maxlength: 1024 });
    const meter = strengthMeter(/** @type {HTMLInputElement} */ (pw.input), { userInputs: () => [user.username, user.display_name, user.email] });
    append(pw.el, meter.el, h('div', { class: 'cluster' }, button({
      label: 'Suggest one', size: 'sm', variant: 'ghost', icon: 'refresh',
      onClick: () => { pw.input.value = generatePassword(20); /** @type {HTMLInputElement} */ (pw.input).type = 'text'; meter.update(); },
    })));
    // a generated password always has to be changed at the next sign-in (the server forces it)
    const mustChange = checkbox({ label: 'Ask for a new password at next sign-in', name: 'must_change', checked: true });
    const sync = () => {
      pw.el.hidden = generate.input.checked;
      /** @type {HTMLInputElement} */ (pw.input).required = !generate.input.checked;
      mustChange.el.hidden = generate.input.checked;
    };
    generate.input.addEventListener('change', sync);
    sync();
    // The reset always revokes the user's sessions and API tokens (except the caller's own session), so say so
    // rather than offer a choice the server does not have.
    const res = await formDialog({
      title: `Reset password for ${user.username}`,
      intro: isSelf()
        ? 'You are resetting your own password. Your other sessions end and your API tokens are revoked; this browser stays signed in.'
        : 'The current password stops working immediately. They are signed out everywhere and their API tokens are revoked, so scripts and apps using them need a new token.',
      fields: [generate, pw, mustChange],
      submitLabel: 'Reset password',
      submitIcon: 'key',
      onSubmit: async (v) => {
        /** @type {Record<string, any>} */
        const bodyIn = {};
        if (generate.input.checked) {
          bodyIn.generate = true;
          bodyIn.must_change = true;
        } else {
          const est = estimate(String(v.password), { userInputs: [user.username, user.display_name, user.email] });
          if (est.score < 2) throw new ApiError(422, 'invalid', est.warning || 'Please choose a stronger password.', 'password');
          bodyIn.password = v.password;
          bodyIn.must_change = !!v.must_change;
        }
        const r = await api.post(`${path}/password`, bodyIn);
        return r || {};
      },
    });
    if (!res) return;
    if (res.password) {
      await showSecretOnce({
        title: `New password for ${user.username}`,
        intro: 'Give it to them in a safe way. They will be asked to choose their own password when they sign in.',
        secret: res.password,
        label: 'Temporary password',
        what: 'Password',
      });
    } else {
      toast.success('Password reset');
    }
    await load();
  };

  const resetMFA = async () => {
    const ok = await confirmTyped({
      title: `Reset two-factor authentication for ${user.username}?`,
      message: h('div', { class: 'stack-sm' },
        h('p', { text: 'This removes their authenticator app, recovery codes and passkeys. Only do this after verifying who is asking — for example in person or by phone.' }),
        h('p', { class: 'muted text-sm', text: isSelf()
          ? 'Your other sessions end and your API tokens are revoked as well.'
          : 'They are signed out everywhere and their API tokens are revoked as well; scripts using those tokens need new ones.' }),
        h('p', { class: 'muted text-sm', text: 'If two-factor authentication is required, they must set it up again at their next sign-in.' })),
      expected: user.username,
      confirmLabel: 'Reset two-factor',
    });
    if (!ok) return;
    await simple('reset-mfa', 'Two-factor authentication was reset');
  };

  // ------------------------------------------------------------------------------------------ sessions
  const signOutAllBtn = () => button({
    label: 'Sign out everywhere',
    size: 'sm',
    variant: 'ghost',
    icon: 'logout',
    onClick: async () => {
      const ok = await confirm({ title: `Sign ${user.username} out everywhere?`, message: isSelf() ? 'This includes this browser — you will have to sign in again.' : 'Every browser session ends immediately. API tokens keep working.', confirmLabel: 'Sign out', danger: true });
      if (!ok) return;
      try {
        await api.del(`${path}/sessions`);
        // The server keeps the session making the request, so for your own account end this browser's session
        // explicitly — the dialog promised it (same cleanup as the regular sign-out, then /login).
        if (isSelf()) {
          await signOut();
          return;
        }
        toast.success('All sessions were signed out');
        await load();
      } catch (err) {
        toast.error(err);
      }
    },
  });

  /** @param {HTMLElement} slot */
  const loadSessions = async (slot) => {
    /** @type {any[]} */
    let list;
    try {
      list = itemsOf(await api.get(`${path}/sessions`, { signal: ctx.signal })).filter((s) => !s.revoked_at);
    } catch (err) {
      if (err instanceof ApiError && err.aborted) return;
      // Administrators may not act on owner accounts, and a role only on the accounts it may manage (the API
      // answers 403): that is a rule, not a failure, so explain it instead of an error panel.
      if (err instanceof ApiError && err.status === 403) {
        replace(slot, h('p', { class: 'muted text-sm', text: user.role === 'owner'
          ? 'Only an owner can see or revoke the sessions of an owner account.'
          : `You can’t see the sessions of this account: ${errorMessage(err)}` }));
        return;
      }
      replace(slot, errorPanel(err));
      return;
    }
    if (!list.length) {
      replace(slot, h('p', { class: 'muted text-sm', text: 'Not signed in anywhere.' }));
      return;
    }
    list.sort((a, b) => String(b.last_seen_at).localeCompare(String(a.last_seen_at)));
    replace(slot, h('ul', { class: 'item-list', attrs: { role: 'list' } }, list.map((s) => h('li', { class: 'item-row' },
      h('span', { class: 'item-row-icon', attrs: { 'aria-hidden': 'true' } }, icon(uaIcon(s.user_agent))),
      h('div', { class: 'item-row-main' },
        h('span', { class: 'item-row-title' }, describeUA(s.user_agent), s.current ? badge({ text: 'This session', kind: 'success' }) : null),
        h('span', { class: 'item-row-sub' }, s.ip ? h('span', { class: 'mono', text: s.ip }) : 'unknown address', ' · active ', timeEl(s.last_seen_at), ' · since ', timeEl(s.created_at)))))));
  };

  // ------------------------------------------------------------------------------------------ danger zone
  const dangerCard = () => {
    if (isSelf() || !manageable()) return null;
    return h('section', { class: 'card danger-zone' },
      h('h2', { class: 'card-title', text: 'Danger zone' }),
      h('div', { class: 'danger-row' },
        h('div', { class: 'stack-sm gap-1' },
          h('strong', { text: user.status === 'disabled' ? 'Enable this account' : 'Disable this account' }),
          h('span', { class: 'muted text-sm', text: user.status === 'disabled' ? 'Allow them to sign in again.' : 'Blocks sign-in and pauses their share links. Nothing is deleted.' })),
        user.status === 'disabled'
          ? button({ label: 'Enable', icon: 'check-circle', onClick: () => simple('enable', 'Account enabled') })
          : button({ label: 'Disable', icon: 'x-circle', variant: 'secondary', onClick: disableUser })),
      h('div', { class: 'danger-row' },
        h('div', { class: 'stack-sm gap-1' },
          h('strong', { text: 'Delete this account' }),
          h('span', { class: 'muted text-sm', text: 'Removes the account, its sessions, tokens and share links. You can hand their files to someone else.' })),
        button({ label: 'Delete user', icon: 'trash', variant: 'danger', onClick: deleteUser })));
  };

  const disableUser = async () => {
    const ok = await confirm({ title: `Disable ${user.username}?`, message: 'They are signed out everywhere and cannot sign in. Their files are kept.', confirmLabel: 'Disable', danger: true });
    if (ok) await simple('disable', 'Account disabled');
  };

  const deleteUser = async () => {
    // moving someone's files to another account opens them to that account: besides administrators, only roles
    // that may also reset sign-in (and so could open them anyway) may do it
    const mayTransfer = isAdmin() || can('users.credentials');
    const transfer = mayTransfer
      ? userPicker({ label: 'Give their files to', name: 'transfer_to', exclude: [user.id], help: 'Optional. Their “My files” folder is moved into this person’s files. Leave empty to delete the files.' })
      : null;
    const confirmName = field({ label: `Type “${user.username}” to confirm`, name: 'confirm', required: true, autocomplete: 'off', attrs: { spellcheck: 'false', autocapitalize: 'off' } });
    const done = await formDialog({
      title: `Delete ${user.username}?`,
      intro: alertEl('danger', 'This cannot be undone', mayTransfer
        ? 'The account, its sessions, API tokens and share links are removed. Files are deleted unless you transfer them.'
        : 'The account, its sessions, API tokens, share links and personal files are removed. Only an administrator can hand the files to someone else instead.'),
      fields: [transfer, confirmName].filter(Boolean),
      submitLabel: 'Delete user',
      submitIcon: 'trash',
      submitVariant: 'danger',
      onSubmit: async (v) => {
        if (String(v.confirm).trim() !== user.username) throw new ApiError(422, 'invalid', 'The name does not match.', 'confirm');
        const to = String(v.transfer_to || '');
        // a typed but unpicked name must never turn into "delete the files" (the picker also blocks this)
        if (transfer && !to && transfer.input.value.trim()) {
          throw new ApiError(422, 'invalid', 'Pick the person from the list, or clear the field to delete their files.', 'transfer_to');
        }
        await api.del(`${path}${to ? `?transfer_to=${encodeURIComponent(to)}` : ''}`);
        return to ? 'transferred' : 'deleted';
      },
    });
    if (!done) return;
    toast.success(done === 'transferred' ? `${user.username} was deleted and their files were transferred.` : `${user.username} was deleted.`);
    navigate('/admin/users');
  };

  // ------------------------------------------------------------------------------------------ helpers
  /** @param {Record<string, any>} changes */
  const patch = async (changes) => {
    const res = await api.patch(path, changes);
    return res && res.id ? res : { ...user, ...changes };
  };

  /**
   * POST /admin/users/{id}/{what}
   * @param {string} what
   * @param {string} done
   */
  const simple = async (what, done) => {
    try {
      await api.post(`${path}/${what}`, {});
      toast.success(done);
      await load();
    } catch (err) {
      toast.error(err);
    }
  };

  await load();
}
