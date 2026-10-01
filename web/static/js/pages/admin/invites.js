// @ts-check
/**
 * Admin → Invites (/admin/invites): invitation links that let people create their own account, with any role the
 * caller may give (DESIGN §6a). Invitations for roles with server access (Admin, or a custom role with a server
 * permission) ask for step-up, can be used once and expire within 7 days. A link is listed only to those who may see
 * it (administrators, its creator, and whoever could create the same invitation); other rows say so.
 *   GET    /admin/invites          → Page[Invite] (status active|used|expired|revoked; role_id, role_name; url when
 *                                    visible — for admin invites only after step-up)
 *   POST   /admin/invites          InviteInput {email, role_id, group_ids, quota_bytes, max_uses, expires_at, note, send}
 *                                  → InviteCreated {invite, url}; invite.email_error says why a requested
 *                                    e-mail was not queued (the invitation exists anyway)
 *   DELETE /admin/invites/{id}     revoke
 *   GET    /admin/roles · /admin/groups   role picker (the built-in roles when unreadable), group names
 * The new link is shown with copy, QR code and the system share sheet.
 * Owned by unit J2.
 * @module pages/admin/invites
 */
import { h, icon, replace, append } from '../../core/dom.js';
import { api, ApiError, itemsOf } from '../../core/api.js';
import { can, isAdmin } from '../../core/store.js';
import { dateTime } from '../../core/format.js';
import { button } from '../../components/button.js';
import { badge } from '../../components/badge.js';
import { table } from '../../components/table.js';
import { toast } from '../../components/toast.js';
import { confirm, dialog } from '../../components/dialog.js';
import { field, select, toggle, checkbox } from '../../components/field.js';
import { copyField, copyText } from '../../components/copy-field.js';
import { qrImage, qrURL } from '../../components/qr-image.js';
import { emptyState } from '../../components/empty-state.js';
import {
  adminHeader, errorPanel, roleBadge, stateBadge, timeEl, moreMenu, formDialog, quotaField, fromLocalInput, toLocalInput, daysFromNow, alertEl,
  ensureElevated, roleSelect, roleIsStaff, loadRolesOrBuiltins, me as currentUser,
} from './common.js';

export const title = 'Invites';

/** Longest life of an invitation for a role with server access (the server refuses a later expires_at). */
const STAFF_INVITE_DAYS = 7;

/**
 * @param {HTMLElement} root
 * @param {import('../../core/router.js').PageContext} ctx
 */
export async function mount(root, ctx) {
  const mayInvite = can('invites.manage');
  adminHeader(root, {
    title,
    subtitle: 'Send someone a link so they can create their own account.',
    actions: mayInvite ? button({ label: 'New invitation', icon: 'mail', variant: 'primary', onClick: () => create() }) : null,
    // the Users page needs "View people" (every inviter has it; the server implies it)
    crumbs: can('users.view') ? [{ label: 'Users', href: '/admin/users' }] : [],
  });
  const filter = select({
    label: 'Show', hideLabel: true, value: 'active',
    options: [{ value: 'active', label: 'Active invitations' }, { value: 'all', label: 'All invitations' }],
    onChange: () => draw(),
  });
  append(root, h('div', { class: 'admin-toolbar' }, filter.el));

  /** @type {any[]} */
  let invites = [];
  /** @type {any[]} */
  let groups = [];
  /** The roles (core.RoleDef; the built-in roles when they cannot be read) by id. @type {Map<string, any>} */
  let roleById = new Map();
  const self = currentUser();

  /**
   * Whether an invitation creates an account with server access (Admin, or a custom role with a server permission).
   * @param {any} i core.Invite
   */
  const staffInvite = (i) => i.role === 'admin' || i.role_id === 'admin' || roleIsStaff(roleById.get(String(i.role_id)));
  /**
   * Whether the server lists the link of `i` to the caller (the mirror of its rule): administrators, the invitation's
   * creator, and whoever could create the same invitation — may give its role, and it adds no groups or they hold
   * "Manage groups".
   * @param {any} i
   */
  const maySee = (i) => isAdmin() || i.created_by === self?.id
    || (roleById.get(String(i.role_id))?.assignable !== false && (!(i.group_ids || []).length || can('groups.manage')));
  /**
   * Why an active invitation is listed without its link: the caller may not see it, or nobody can while the server's
   * keys are locked. (Links of invitations for roles with server access also need step-up: the "Show link" action.)
   * @param {any} i
   */
  const hiddenLinkText = (i) => (maySee(i)
    ? 'Link unavailable right now (the server’s keys may be locked)'
    : 'Link hidden: only administrators can see it');
  /** Whether confirming the caller's identity may reveal the link of `i`. @param {any} i */
  const revealable = (i) => staffInvite(i) && maySee(i);

  const t = table({
    caption: 'Invitations',
    loading: true,
    columns: [
      {
        key: 'who',
        label: 'Invitation',
        render: (i) => h('span', { class: 'stack-sm gap-1' },
          h('strong', { class: 'break', text: i.email || i.note || 'Open invitation' }),
          i.email && i.note ? h('span', { class: 'muted text-xs', text: i.note }) : null,
          groupNames(i.group_ids).length ? h('span', { class: 'muted text-xs', text: `Groups: ${groupNames(i.group_ids).join(', ')}` }) : null,
          // phones: the Role and Status columns are hidden, their badges sit here
          h('span', { class: 'cluster only-sm' }, roleBadge(i), stateBadge(i.status)),
          i.status === 'active' && !i.url && !revealable(i)
            ? h('span', { class: 'invite-link-hidden muted text-xs' }, icon('lock', { size: 14 }), h('span', { text: hiddenLinkText(i) }))
            : null),
      },
      { key: 'role', label: 'Role', hideBelow: 'sm', render: (i) => roleBadge(i) },
      { key: 'uses', label: 'Used', hideBelow: 'sm', render: (i) => h('span', { class: 'tabular', text: `${i.uses ?? 0} / ${i.max_uses ?? 1}` }) },
      { key: 'expires', label: 'Expires', hideBelow: 'sm', render: (i) => timeEl(i.expires_at) },
      { key: 'status', label: 'Status', hideBelow: 'sm', render: (i) => stateBadge(i.status) },
      {
        key: 'actions', label: 'Actions', srOnlyLabel: true, class: 'cell-actions',
        render: (i) => (i.status === 'active'
          ? h('span', { class: 'cluster nowrap' },
            i.url ? button({ label: 'Copy link', size: 'sm', icon: 'copy', variant: 'ghost', onClick: () => copyText(absolute(i.url), 'Invitation link') }) : null,
            moreMenu([
              i.url ? { label: 'Show link & QR code', icon: 'qr', onClick: () => showLink(absolute(i.url), i) } : null,
              !i.url && revealable(i) ? { label: 'Show link (confirm it’s you)', icon: 'lock', onClick: () => revealLink(i) } : null,
              { label: 'Revoke', icon: 'x-circle', danger: true, onClick: () => revoke(i) },
            ].filter(Boolean), 'Invitation actions'))
          : null),
      },
    ],
    empty: emptyState({ icon: 'mail', title: 'No invitations', text: 'Invite people by sending them a link. They choose their own username and password.', action: mayInvite ? { label: 'New invitation', icon: 'mail', onClick: () => create() } : undefined }),
  });
  const slot = h('div', null, t.el);
  append(root, slot);

  /** @param {string[] | undefined} ids */
  const groupNames = (ids) => (ids || []).map((id) => groups.find((g) => g.id === id)?.name).filter(Boolean);

  const load = async () => {
    try {
      const [inv, grp, roles] = await Promise.all([
        api.get('/admin/invites', { signal: ctx.signal, query: { limit: 500 } }),
        // group names of the rows (and the Groups field); "View people" comes with "Invite people"
        api.get('/admin/groups', { signal: ctx.signal, query: { limit: 500 }, handle: false }).catch(() => []),
        loadRolesOrBuiltins(),
      ]);
      invites = itemsOf(inv);
      groups = itemsOf(grp);
      roleById = new Map(roles.map((r) => [String(r.id), r]));
      // a failed earlier load replaced the table with an error panel: put it back
      if (t.el.parentNode !== slot) replace(slot, t.el);
      draw();
    } catch (err) {
      if (err instanceof ApiError && err.aborted) return;
      replace(slot, errorPanel(err, load));
    }
  };

  const draw = () => {
    const all = filter.input.value === 'all';
    const rows = invites
      .filter((i) => all || i.status === 'active' || !i.status)
      .sort((a, b) => String(b.created_at).localeCompare(String(a.created_at)));
    t.setRows(rows);
  };

  /**
   * The server leaves out the link of an invitation for a role with server access until the session is elevated (it
   * creates an account that can use the Admin area).
   * @param {any} i
   */
  const revealLink = async (i) => {
    if (!(await ensureElevated())) return;
    await load();
    const again = invites.find((x) => x.id === i.id);
    if (again?.url) showLink(absolute(again.url), again);
    else toast.error(isAdmin() ? 'The link is not available right now (the server’s keys may be locked).' : 'The link is not available: only administrators can see it.');
  };

  /** @param {any} i */
  const revoke = async (i) => {
    const ok = await confirm({ title: 'Revoke this invitation?', message: `The link${i.email ? ` for ${i.email}` : ''} stops working immediately. Accounts already created with it are not affected.`, confirmLabel: 'Revoke', danger: true });
    if (!ok) return;
    try {
      await api.del(`/admin/invites/${encodeURIComponent(i.id)}`);
      toast.success('Invitation revoked');
      await load();
    } catch (err) {
      toast.error(err);
    }
  };

  const create = async () => {
    // An invitation that names an address creates the account with it, so the
    // server refuses max_uses > 1 for it (internal/users/invites.go). Pin the
    // count to 1 here so the admin sees the rule before submitting; values()
    // reads control.value(), so a disabled input still submits "1".
    const email = field({
      label: 'Email', name: 'email', type: 'email', maxlength: 254, autocomplete: 'off',
      help: 'Optional. The new account is created with this address, so the link can only be used once.',
      onInput: () => syncRules(),
    });
    // Initial memberships need "Manage groups" (the server refuses group_ids without it).
    const groupBoxes = can('groups.manage') ? groups.map((g) => ({ g, c: checkbox({ label: g.name }) })) : [];
    const groupsEl = groupBoxes.length
      ? h('fieldset', { class: 'fieldset' }, h('legend', { class: 'fieldset-legend', text: 'Add to groups' }), h('div', { class: 'check-grid' }, groupBoxes.map((x) => x.c.el)))
      : null;
    const EXPIRY = [
      { value: '1', label: 'In 24 hours' }, { value: '3', label: 'In 3 days' }, { value: '7', label: 'In 7 days' },
      { value: '14', label: 'In 14 days' }, { value: '30', label: 'In 30 days' }, { value: 'custom', label: 'On a specific date…' },
    ];
    const expires = select({
      label: 'Link expires', name: 'expires', value: '7', options: EXPIRY,
      onChange: () => { custom.el.hidden = expires.input.value !== 'custom'; },
    });
    const custom = field({ label: 'Expiry date', name: 'expires_at', type: 'datetime-local', value: toLocalInput(daysFromNow(7)), attrs: { min: toLocalInput(new Date()) } });
    custom.el.hidden = true;
    const uses = field({ label: 'How many people can use it', name: 'max_uses', type: 'number', value: 1, min: 1, max: 1000, required: true, inputmode: 'numeric', help: 'Use more than 1 for a link you post in a group chat (leave the email empty).' });
    const staffNote = alertEl('info', 'Server access', 'Invitations for roles with server access can be used once and expire within 7 days. Creating one asks you to confirm your identity.');
    const role = roleSelect({
      label: 'Role',
      name: 'role_id',
      value: 'member',
      roles: [...roleById.values()],
      // owners cannot be invited (invite an admin and change the role later)
      builtins: ['member', 'guest', ...(isAdmin() ? ['admin'] : [])],
      required: true,
      onChange: () => syncRules(),
    });
    /** The chosen role opens the Admin area. */
    const staff = () => {
      const r = role.selected();
      return !!r && (r.id === 'admin' || r.id === 'owner' || roleIsStaff(r));
    };
    // An address or a role with server access limits the link to one use, and server access to 7 days: the fields
    // show the rule before the server would refuse (values() reads control.value(), so a disabled input still submits).
    const syncRules = () => {
      const one = String(email.input.value).trim() !== '' || staff();
      uses.input.disabled = one;
      if (one) uses.input.value = '1';
      staffNote.hidden = !staff();
      const cur = expires.input.value;
      const options = staff() ? EXPIRY.filter((o) => o.value === 'custom' || Number(o.value) <= STAFF_INVITE_DAYS) : EXPIRY;
      expires.setOptions(options, options.some((o) => o.value === cur) ? cur : String(STAFF_INVITE_DAYS));
      if (staff()) custom.input.setAttribute('max', toLocalInput(daysFromNow(STAFF_INVITE_DAYS)));
      else custom.input.removeAttribute('max');
    };
    syncRules();
    // A quota needs "Manage accounts", as on an account (the server refuses it otherwise): without it the new account
    // gets the server's default quota.
    const quota = can('users.manage') ? quotaField({ label: 'Storage quota', name: 'quota_bytes', value: null }) : null;
    const note = field({ label: 'Note', name: 'note', maxlength: 500, type: 'textarea', rows: 2, help: 'Shown to the invited person on the sign-up page.' });
    const send = toggle({ label: 'Email the link', name: 'send', help: 'Needs an email address and email (SMTP) settings.' });
    let sentTo = '';
    const res = await formDialog({
      title: 'New invitation',
      size: 'md',
      fields: [email, role, staffNote, groupsEl, expires, custom, uses, quota, note, send].filter(Boolean),
      submitLabel: 'Create link',
      submitIcon: 'link',
      onSubmit: async (v) => {
        const q = quota ? quota.value() : null;
        if (Number.isNaN(q)) throw new ApiError(422, 'invalid', 'Enter a size such as 50 GB.', 'quota_bytes');
        const expiresAt = expires.input.value === 'custom' ? fromLocalInput(String(v.expires_at)) : daysFromNow(Number(expires.input.value));
        if (!expiresAt || new Date(expiresAt).getTime() <= Date.now()) throw new ApiError(422, 'invalid', 'Pick a date in the future.', 'expires_at');
        if (staff() && new Date(expiresAt).getTime() > Date.now() + STAFF_INVITE_DAYS * 86_400_000) {
          throw new ApiError(422, 'invalid', 'Invitations for roles with server access expire within 7 days.', 'expires_at');
        }
        const mail = String(v.email).trim();
        if (v.send && !mail) throw new ApiError(422, 'invalid', 'Enter the email address to send the invitation to.', 'email');
        /** @type {Record<string, any>} */
        const body = {
          role_id: v.role_id,
          max_uses: staff() ? 1 : Math.max(1, Number(v.max_uses) || 1),
          expires_at: expiresAt,
        };
        if (mail) body.email = mail;
        const gids = groupBoxes.filter((x) => x.c.input.checked).map((x) => x.g.id);
        if (gids.length) body.group_ids = gids;
        if (q !== null) body.quota_bytes = q;
        const n = String(v.note).trim();
        if (n) body.note = n;
        if (v.send) body.send = true;
        const r = await api.post('/admin/invites', body);
        sentTo = v.send ? mail : '';
        return r;
      },
    });
    if (!res || res === true) return;
    await load();
    const url = absolute(res.url || res.invite?.url || '');
    if (url) showLink(url, res.invite || {}, true, sentTo);
    else toast.success('Invitation created');
  };

  await load();
}

/**
 * Absolute URL for an invite link (the server may return a root-relative path).
 * @param {string} u
 */
function absolute(u) {
  if (!u) return '';
  try {
    return new URL(u, location.origin).href;
  } catch {
    return u;
  }
}

/**
 * Dialog with the invite link, QR code and share button.
 * @param {string} url
 * @param {any} invite
 * @param {boolean} [fresh]
 * @param {string} [sentTo] email address the link was to be sent to (invite.email_error: it was not)
 */
function showLink(url, invite, fresh = false, sentTo = '') {
  const canShare = typeof navigator.share === 'function';
  dialog({
    title: fresh ? 'Invitation ready' : 'Invitation link',
    size: 'sm',
    body: h('div', { class: 'stack invite-link' },
      fresh && sentTo
        ? (invite.email_error
          ? alertEl('warning', 'Email not sent', `The link could not be sent to ${sentTo}: ${invite.email_error}. Copy the link below and send it yourself.`)
          : alertEl('success', 'Email sent', `The link was sent to ${sentTo}.`))
        : null,
      h('p', { class: 'muted text-sm' }, 'Anyone with this link can create an account with the role ', roleBadge(invite),
        invite.max_uses > 1 ? ` (up to ${invite.max_uses} people)` : '', invite.expires_at ? ` until ${dateTime(invite.expires_at)}.` : '.'),
      url.length <= 512 ? h('div', { class: 'invite-qr' }, qrImage({ src: qrURL(url), alt: 'QR code of the invitation link', size: 200 })) : null,
      copyField({ label: 'Invitation link', value: url, what: 'Invitation link' }),
      badge({ text: 'Treat it like a password until it is used', kind: 'warning', icon: 'lock' })),
    actions: [
      canShare ? {
        label: 'Share…',
        icon: 'share',
        close: false,
        onClick: async () => {
          try {
            await navigator.share({ title: 'Your FileParcel invitation', text: 'Create your account:', url });
          } catch { /* cancelled */ }
        },
      } : null,
      { label: 'Copy link', icon: 'copy', variant: 'primary', close: false, onClick: () => { copyText(url, 'Invitation link'); } },
    ].filter(Boolean).map((a) => /** @type {any} */ (a)),
  }).open();
}

