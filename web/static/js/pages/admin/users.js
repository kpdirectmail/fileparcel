// @ts-check
/**
 * Admin → Users (/admin/users): searchable, filterable account list and "new user" dialog (with a generated password
 * that is shown once). The role filter lists the built-in and the custom roles (?role_id= in the address, which the
 * roles pages link to). Creating, disabling and unlocking accounts needs "Manage accounts"; the rows offer them only
 * for accounts the role may manage (DESIGN §6a).
 *   GET  /admin/users?q=&role_id=&status=&cursor=&limit=  → Page[User]
 *   GET  /admin/roles → {items: [RoleDef]} (filter and role picker; the built-in roles when it cannot be read)
 *   POST /admin/users  NewUser {username, display_name, email, role_id, password | generate_password,
 *                               must_change_password, quota_bytes, group_ids} → UserCreated {user, password?}
 *   GET  /admin/groups → Page[Group] (initial memberships; needs "Manage groups")
 *   POST /admin/users/{id}/disable|enable|unlock
 * Owned by unit J2.
 * @module pages/admin/users
 */
import { h, icon, replace, append } from '../../core/dom.js';
import { api, ApiError, itemsOf } from '../../core/api.js';
import { navigate } from '../../core/router.js';
import { can } from '../../core/store.js';
import { button } from '../../components/button.js';
import { badge } from '../../components/badge.js';
import { table } from '../../components/table.js';
import { toast } from '../../components/toast.js';
import { confirm } from '../../components/dialog.js';
import { field, select, toggle, checkbox } from '../../components/field.js';
import {
  adminHeader, errorPanel, roleBadge, userCell, timeEl, moreMenu, debounce, formDialog, quotaField, showSecretOnce, quotaText, me as currentUser,
  loadRolesOrBuiltins, builtinRoles, roleSelect, mayManageAccount, isCustomRoleId,
} from './common.js';
import { strengthMeter, generatePassword, estimate } from '../../public/password-strength.js';

export const title = 'Users';

/**
 * @param {HTMLElement} root
 * @param {import('../../core/router.js').PageContext} ctx
 */
export async function mount(root, ctx) {
  adminHeader(root, {
    title,
    subtitle: 'Accounts, roles, quotas and sign-in security.',
    actions: [
      can('invites.manage') ? h('a', { class: 'btn btn--secondary', href: '/admin/invites' }, icon('mail'), h('span', { text: 'Invite people' })) : null,
      can('users.manage') ? button({ label: 'New user', icon: 'user-plus', variant: 'primary', onClick: () => createUser() }) : null,
    ],
  });

  const q = field({ label: 'Search', hideLabel: true, name: 'q', type: 'search', placeholder: 'Search name, username or email', value: ctx.query.q || '', autocomplete: 'off', maxlength: 200 });
  // ?role= is the filter of older links (a built-in role); the roles pages link with ?role_id=.
  const roleWanted = ctx.query.role_id || ctx.query.role || '';
  const role = select({
    label: 'Role', hideLabel: true, name: 'role_id', value: roleWanted,
    options: roleFilterOptions(builtinRoles(), roleWanted),
    onChange: () => reload(),
  });
  /** The roles (core.RoleDef) by id, for the filter and for who may manage which row. @type {Map<string, any>} */
  let roleById = new Map();
  const rolesReady = loadRolesOrBuiltins().then((list) => {
    roleById = new Map(list.map((r) => [String(r.id), r]));
    role.setOptions(roleFilterOptions(list, role.input.value), role.input.value);
  });
  const status = select({
    label: 'Status', hideLabel: true, name: 'status', value: ctx.query.status || '',
    options: [{ value: '', label: 'Any status' }, { value: 'active', label: 'Active' }, { value: 'disabled', label: 'Disabled' }],
    onChange: () => reload(),
  });
  q.input.addEventListener('input', debounce(() => reload(), 250));
  const count = h('span', { class: 'muted text-sm', attrs: { 'aria-live': 'polite' } });
  append(root, h('div', { class: 'admin-toolbar' }, h('div', { class: 'admin-toolbar-search' }, q.el), role.el, status.el, count));

  const self = currentUser();
  const t = table({
    caption: 'Users',
    loading: true,
    rowKey: 'id',
    onRowClick: (u) => navigate(`/admin/users/${encodeURIComponent(u.id)}`),
    empty: 'No users match these filters.',
    columns: [
      {
        key: 'user',
        label: 'User',
        render: (u) => h('a', { class: 'row-link', href: `/admin/users/${encodeURIComponent(u.id)}` }, userCell(u)),
      },
      // hidden on phones: the identity column needs the width (admin.css floors it), and the role is still
      // reachable through the "All roles" filter and the user's own page.
      { key: 'role', label: 'Role', hideBelow: 'sm', render: (u) => roleBadge(u) },
      {
        key: 'status',
        label: 'Status',
        render: (u) => h('span', { class: 'cluster' },
          u.status === 'disabled' ? badge({ text: 'Disabled', kind: 'neutral' }) : isLocked(u) ? badge({ text: 'Locked', kind: 'warning', icon: 'lock', title: `Until ${new Date(u.locked_until).toLocaleString()}` }) : badge({ text: 'Active', kind: 'success' }),
          u.mfa_enabled ? badge({ text: '2FA', kind: 'info', icon: 'shield-check', title: 'Two-factor authentication on' }) : null,
          u.must_change_password ? badge({ text: 'Must change password', kind: 'warning' }) : null),
      },
      { key: 'quota', label: 'Quota', hideBelow: 'md', render: (u) => h('span', { class: 'muted', text: quotaText(u.quota_bytes, 'Default') }) },
      { key: 'last', label: 'Last sign-in', hideBelow: 'sm', render: (u) => (u.last_login_at ? timeEl(u.last_login_at) : h('span', { class: 'subtle', text: 'Never' })) },
      {
        key: 'actions',
        label: 'Actions',
        srOnlyLabel: true,
        class: 'cell-actions',
        render: (u) => moreMenu(() => {
          const manage = mayManageAccount(u, { role: roleById.get(String(u.role_id)) });
          return [
            { label: 'Open', icon: 'user', href: `/admin/users/${encodeURIComponent(u.id)}` },
            manage && isLocked(u) ? { label: 'Unlock sign-in', icon: 'unlock', onClick: () => action(u, 'unlock', `${u.username} can sign in again.`) } : null,
            !manage || u.id === self?.id ? null
              : u.status === 'disabled'
                ? { label: 'Enable account', icon: 'check-circle', onClick: () => action(u, 'enable', `${u.username} was enabled.`) }
                : { label: 'Disable account', icon: 'x-circle', danger: true, onClick: () => disable(u) },
          ].filter(Boolean);
        }, `Actions for ${u.username}`),
      },
    ],
  });
  const more = button({ label: 'Load more', icon: 'chevron-down', variant: 'ghost', onClick: () => loadMore() });
  more.hidden = true;
  const moreRow = h('div', { class: 'load-more' }, more);
  const listSlot = h('div', { class: 'stack' }, t.el, moreRow);
  append(root, listSlot);

  /** @type {any[]} */
  let rows = [];
  let cursor = '';
  let seq = 0;

  const query = () => ({ q: String(q.input.value).trim() || undefined, role_id: role.input.value || undefined, status: status.input.value || undefined, limit: 100 });

  const reload = async () => {
    const mine = ++seq;
    try {
      const res = await api.get('/admin/users', { signal: ctx.signal, query: query() });
      if (mine !== seq) return;
      rows = itemsOf(res);
      cursor = res?.next_cursor || '';
      // a failed earlier load replaced the table with an error panel: put it back
      if (t.el.parentNode !== listSlot) replace(listSlot, t.el, moreRow);
      t.setRows(rows);
      more.hidden = !cursor;
      count.textContent = `${rows.length}${cursor ? '+' : ''} user${rows.length === 1 ? '' : 's'}`;
      // keep filters in the URL (shareable, survives reload)
      const params = new URLSearchParams();
      const qq = query();
      if (qq.q) params.set('q', qq.q);
      if (qq.role_id) params.set('role_id', qq.role_id);
      if (qq.status) params.set('status', qq.status);
      const s = params.toString();
      history.replaceState(history.state, '', `/admin/users${s ? `?${s}` : ''}`);
    } catch (err) {
      if (err instanceof ApiError && err.aborted) return;
      if (mine !== seq) return; // a newer load already answered
      replace(listSlot, errorPanel(err, () => reload()));
    }
  };

  const loadMore = async () => {
    if (!cursor) return;
    try {
      const res = await api.get('/admin/users', { signal: ctx.signal, query: { ...query(), cursor } });
      rows = rows.concat(itemsOf(res));
      cursor = res?.next_cursor || '';
      t.setRows(rows);
      more.hidden = !cursor;
      count.textContent = `${rows.length}${cursor ? '+' : ''} users`;
    } catch (err) {
      toast.error(err);
    }
  };

  /**
   * @param {any} u
   * @param {'unlock' | 'enable' | 'disable'} what
   * @param {string} done
   */
  const action = async (u, what, done) => {
    try {
      await api.post(`/admin/users/${encodeURIComponent(u.id)}/${what}`, {});
      toast.success(done);
      await reload();
    } catch (err) {
      toast.error(err);
    }
  };

  /** @param {any} u */
  const disable = async (u) => {
    const ok = await confirm({
      title: `Disable ${u.username}?`,
      message: 'They are signed out everywhere and cannot sign in until an administrator enables the account again. Their files and share links are kept, but links stop working while the account is disabled.',
      confirmLabel: 'Disable',
      danger: true,
    });
    if (ok) await action(u, 'disable', `${u.username} was disabled.`);
  };

  const createUser = async () => {
    const res = await newUserDialog();
    if (!res) return;
    await reload();
    if (res.password) {
      await showSecretOnce({
        title: `Account created for ${res.user?.username || 'the new user'}`,
        intro: 'Give these sign-in details to the person in a safe way (in person or through a password manager). They will be asked to choose their own password when they first sign in.',
        secret: res.password,
        label: 'Temporary password',
        what: 'Password',
        extra: h('p', { class: 'text-sm' }, 'Sign-in page: ', h('span', { class: 'mono break', text: `${location.origin}/login` }), ' · Username: ', h('strong', { text: res.user?.username || '' })),
      });
    } else {
      toast.success(`Account created for ${res.user?.username || 'the new user'}`);
    }
    if (res.user?.id) navigate(`/admin/users/${encodeURIComponent(res.user.id)}`);
  };

  await Promise.all([reload(), rolesReady]);
}

/**
 * Options of the role filter: every role, built-in roles as plural words, custom roles by name. A role the list
 * does not contain (a deleted role in an old link) stays selectable so the filter still shows what it filters on.
 * @param {any[]} roles core.RoleDef
 * @param {string} current
 * @returns {any[]}
 */
function roleFilterOptions(roles, current) {
  /** @type {Record<string, string>} */
  const plural = { owner: 'Owners', admin: 'Admins', member: 'Members', guest: 'Guests' };
  const customs = roles.filter((r) => isCustomRoleId(r.id)).map((r) => ({ value: String(r.id), label: String(r.name || r.id) }));
  if (current && !plural[current] && !customs.some((o) => o.value === current)) customs.push({ value: current, label: isCustomRoleId(current) ? 'Deleted role' : current });
  return [
    { value: '', label: 'All roles' },
    { label: 'Built-in', options: Object.entries(plural).map(([value, label]) => ({ value, label })) },
    ...(customs.length ? [{ label: 'Custom', options: customs }] : []),
  ];
}

/** @param {any} u */
function isLocked(u) {
  return !!u.locked_until && new Date(u.locked_until).getTime() > Date.now();
}

/**
 * The server's username rule (internal/users/validate.go usernameRe) as an input pattern: browsers anchor it
 * and compile it with the v flag, so the hyphen in the class is escaped.
 */
const USERNAME_PATTERN = '[A-Za-z0-9](?:[A-Za-z0-9._\\-]{0,62}[A-Za-z0-9])?';

/**
 * "New user" dialog. Resolves with core.UserCreated or undefined.
 * @returns {Promise<any>}
 */
export async function newUserDialog() {
  const [roles, groups] = await Promise.all([
    loadRolesOrBuiltins(),
    // initial memberships need "Manage groups" (the server refuses group_ids without it)
    can('groups.manage')
      ? api.get('/admin/groups', { query: { limit: 500 }, handle: false }).then(itemsOf).catch(() => [])
      : Promise.resolve([]),
  ]);

  const username = field({ label: 'Username', name: 'username', required: true, maxlength: 64, autocomplete: 'off', help: 'Used to sign in. Letters, numbers, dots, dashes and underscores; starts and ends with a letter or number.', attrs: { autocapitalize: 'off', spellcheck: 'false', pattern: USERNAME_PATTERN } });
  const display = field({ label: 'Full name', name: 'display_name', maxlength: 100, autocomplete: 'off' });
  const email = field({ label: 'Email', name: 'email', type: 'email', maxlength: 254, autocomplete: 'off', help: 'Optional. Used for notifications.' });
  const role = roleSelect({
    label: 'Role',
    name: 'role_id',
    value: 'member',
    roles,
    required: true,
    help: 'Roles with server permissions ask you to confirm your identity.',
  });
  const generate = toggle({ label: 'Generate a temporary password', name: 'generate', checked: true, help: 'Shown once after the account is created. The user must change it at first sign-in.' });
  const password = field({ label: 'Password', name: 'password', type: 'password', autocomplete: 'new-password', minlength: 8, maxlength: 1024 });
  const meter = strengthMeter(/** @type {HTMLInputElement} */ (password.input), { userInputs: () => [username.input.value, display.input.value, email.input.value] });
  append(password.el, meter.el, h('div', { class: 'cluster' }, button({
    label: 'Suggest one', size: 'sm', variant: 'ghost', icon: 'refresh',
    onClick: () => {
      password.input.value = generatePassword(20);
      /** @type {HTMLInputElement} */ (password.input).type = 'text';
      meter.update();
    },
  })));
  const mustChange = checkbox({ label: 'Ask for a new password at first sign-in', name: 'must_change_password', checked: true });
  const quota = quotaField({ label: 'Storage quota', name: 'quota_bytes', value: null, help: 'Server default comes from Settings → Storage.' });
  const groupBoxes = groups.map((g) => ({ g, c: checkbox({ label: g.name, checked: false }) }));
  const groupsEl = groups.length
    ? h('fieldset', { class: 'fieldset' }, h('legend', { class: 'fieldset-legend', text: 'Groups' }), h('div', { class: 'check-grid' }, groupBoxes.map((x) => x.c.el)))
    : null;
  const sync = () => {
    const gen = generate.input.checked;
    password.el.hidden = gen;
    /** @type {HTMLInputElement} */ (password.input).required = !gen;
    mustChange.el.hidden = gen;
  };
  generate.input.addEventListener('change', sync);
  sync();

  return formDialog({
    title: 'New user',
    size: 'md',
    fields: [username, display, email, role, generate, password, mustChange, quota, groupsEl].filter(Boolean),
    submitLabel: 'Create user',
    submitIcon: 'user-plus',
    onSubmit: async (v) => {
      const q = quota.value();
      if (Number.isNaN(q)) throw new ApiError(422, 'invalid', 'Enter a size such as 50 GB.', 'quota_bytes');
      /** @type {Record<string, any>} */
      const body = {
        username: String(v.username).trim(),
        display_name: String(v.display_name).trim() || undefined,
        email: String(v.email).trim() || undefined,
        role_id: v.role_id,
        group_ids: groupBoxes.filter((x) => x.c.input.checked).map((x) => x.g.id),
      };
      if (q !== null) body.quota_bytes = q;
      if (generate.input.checked) {
        body.generate_password = true;
        body.must_change_password = true;
      } else {
        const est = estimate(String(v.password), { userInputs: [body.username, body.display_name || '', body.email || ''] });
        if (est.score < 2) throw new ApiError(422, 'invalid', est.warning || 'Please choose a stronger password.', 'password');
        body.password = v.password;
        body.must_change_password = !!v.must_change_password;
      }
      if (!body.group_ids.length) delete body.group_ids;
      try {
        return await api.post('/admin/users', body);
      } catch (err) {
        if (err instanceof ApiError && err.status === 409) throw new ApiError(409, err.code, err.message && err.message !== 'conflict' ? err.message : 'That username or email is already taken.', err.field || 'username');
        throw err;
      }
    },
  });
}

