// @ts-check
/**
 * Settings → API tokens (/settings/tokens): personal access tokens for the CLI (`fileparcel --server URL --token …`),
 * scripts and integrations. The secret is shown exactly once.
 *   GET    /me/tokens            → APIToken[]
 *   POST   /me/tokens            TokenInput {name, scopes, expires_at?, elevated?} → TokenCreated {token, secret}
 *   DELETE /me/tokens/{id}
 * Scopes (§9.3): files:read, files:write, shares, admin (accounts with server permissions: the token may use the
 * role's server permissions). An admin-scoped token may act as "elevated" (step-up at creation, at most 30 days;
 * elevated only while its owner has server permissions). Creating tokens needs the role's "Create API tokens"
 * permission (DESIGN §6a; built-in Guests do not have it); existing tokens stay listed and can be revoked. A token
 * never acts beyond its owner's own role and grants; a pending 2FA enrollment blocks it (mw.enrollAllowed).
 * Owned by unit J2.
 * @module pages/settings/tokens
 */
import { h, icon, replace, append } from '../../core/dom.js';
import { api, ApiError, itemsOf } from '../../core/api.js';
import { can, isStaff } from '../../core/store.js';
import { dateTime } from '../../core/format.js';
import { button } from '../../components/button.js';
import { badge } from '../../components/badge.js';
import { toast } from '../../components/toast.js';
import { confirm } from '../../components/dialog.js';
import { field, select, checkbox, toggle } from '../../components/field.js';
import { skeleton } from '../../components/progress.js';
import { emptyState } from '../../components/empty-state.js';
import { settingsHeader } from './common.js';
import { errorPanel, timeEl, formDialog, showSecretOnce, expiryBadge, fromLocalInput, toLocalInput, daysFromNow, alertEl } from '../admin/common.js';

export const title = 'API tokens';

/** @type {{scope: string, label: string, text: string, admin?: boolean}[]} */
const SCOPES = [
  { scope: 'files:read', label: 'Read files', text: 'List, search and download your files.' },
  { scope: 'files:write', label: 'Change files', text: 'Upload, rename, move and delete files and folders.' },
  { scope: 'shares', label: 'Share links', text: 'Create and manage share links and file requests (with Read files; file requests and upload links also need Change files).' },
  { scope: 'admin', label: 'Administration', text: 'Lets the token use your role’s server permissions (the admin API).', admin: true },
];

/**
 * @param {HTMLElement} root
 * @param {import('../../core/router.js').PageContext} ctx
 */
export async function mount(root, ctx) {
  const mayCreate = can('tokens.create');
  const createBtn = mayCreate ? button({ label: 'New token', icon: 'plus', variant: 'primary', onClick: () => create() }) : null;
  settingsHeader(root, {
    id: 'settings-tokens',
    title,
    subtitle: 'Tokens let the command-line client and scripts use FileParcel on your behalf.',
    actions: createBtn,
  });
  const body = h('div', { class: 'stack' }, skeleton(3, { rows: true }));
  append(root,
    mayCreate ? null : alertEl('info', 'Your role can’t create API tokens.', 'Tokens you already have keep working until you revoke them. Ask an administrator if you need a new one.'),
    body, h('section', { class: 'card stack-sm' },
    h('h2', { class: 'card-title', text: 'Using a token' }),
    h('p', { class: 'muted text-sm', text: 'Send it as a bearer token. Tokens never need the CSRF header and cannot confirm sensitive actions unless created as “elevated”.' }),
    h('pre', { class: 'json-block' }, h('code', { text: `curl -H "Authorization: Bearer fpt_…" ${location.origin}/api/v1/me\n\nfileparcel --server ${location.origin} --token fpt_… files ls` }))));

  /** @type {any[]} */
  let tokens = [];

  const load = async () => {
    try {
      tokens = itemsOf(await api.get('/me/tokens', { signal: ctx.signal }));
    } catch (err) {
      if (err instanceof ApiError && err.aborted) return;
      replace(body, errorPanel(err, load));
      return;
    }
    draw();
  };

  const draw = () => {
    const live = tokens.filter((t) => !t.revoked_at).sort((a, b) => String(b.created_at).localeCompare(String(a.created_at)));
    if (!live.length) {
      replace(body, emptyState({
        icon: 'terminal',
        title: 'No API tokens',
        text: mayCreate ? 'Create a token to use FileParcel from the command line or a script.' : 'You have no API tokens.',
        action: mayCreate ? { label: 'New token', icon: 'plus', onClick: () => create() } : undefined,
      }));
      return;
    }
    replace(body, h('ul', { class: 'item-list card card--flush', attrs: { role: 'list', 'aria-label': 'API tokens' } }, live.map((t) => {
      const expired = t.expires_at && new Date(t.expires_at).getTime() < Date.now();
      return h('li', { class: 'item-row', dataset: { state: expired ? 'expired' : null } },
        h('span', { class: 'item-row-icon', attrs: { 'aria-hidden': 'true' } }, icon('key')),
        h('div', { class: 'item-row-main' },
          h('span', { class: 'item-row-title' }, t.name || 'Token',
            t.elevated ? badge({ text: 'Elevated', kind: 'warning', icon: 'shield' }) : null,
            t.expires_at ? expiryBadge(t.expires_at, 7) : badge({ text: 'Never expires', kind: 'neutral' })),
          h('span', { class: 'cluster' }, (t.scopes || []).filter((/** @type {string} */ s) => s !== 'elevated').map((/** @type {string} */ s) => badge({ text: s, kind: s === 'admin' ? 'primary' : 'neutral' }))),
          h('span', { class: 'item-row-sub' },
            'Created ', timeEl(t.created_at),
            ' · ', t.last_used_at ? ['last used ', timeEl(t.last_used_at), t.last_used_ip ? h('span', { class: 'mono', text: ` from ${t.last_used_ip}` }) : null] : 'never used')),
        button({ label: 'Revoke', size: 'sm', variant: 'secondary', onClick: () => revoke(t) }));
    })));
  };

  const create = async () => {
    // the admin scope needs an account with server permissions (the server refuses it otherwise)
    const admin = isStaff();
    const name = field({ label: 'Name', name: 'name', required: true, maxlength: 64, placeholder: 'e.g. Laptop CLI, Backup script', help: 'Helps you recognise the token later.' });
    const scopeBoxes = SCOPES.filter((s) => !s.admin || admin).map((s) => ({ s, c: checkbox({ label: `${s.label} — ${s.text}`, checked: s.scope !== 'admin' && s.scope !== 'shares' }) }));
    const scopeError = h('p', { class: 'field-error', attrs: { role: 'alert' } });
    const scopesEl = h('fieldset', { class: 'fieldset' },
      h('legend', { class: 'fieldset-legend', text: 'Permissions' }),
      h('div', { class: 'stack-sm' }, scopeBoxes.map((x) => x.c.el)),
      scopeError);
    const expiry = select({
      label: 'Expires',
      name: 'expiry',
      value: '90',
      options: [
        { value: '7', label: 'In 7 days' },
        { value: '30', label: 'In 30 days' },
        { value: '90', label: 'In 90 days' },
        { value: '365', label: 'In 1 year' },
        { value: 'custom', label: 'On a specific date…' },
        { value: 'never', label: 'Never' },
      ],
      onChange: () => syncExpiry(),
    });
    const customDate = field({ label: 'Expiry date', name: 'expires_at', type: 'datetime-local', value: toLocalInput(daysFromNow(30)), attrs: { min: toLocalInput(new Date()) } });
    const elevated = admin
      ? toggle({ label: 'Elevated', name: 'elevated', help: 'Lets the token perform sensitive admin actions (those that ask you to confirm your identity) without a password prompt. Needs the Administration permission and expires within 30 days.' })
      : null;
    const warn = h('div');
    const syncExpiry = () => {
      customDate.el.hidden = expiry.input.value !== 'custom';
      replace(warn, expiry.input.value === 'never' ? alertEl('warning', 'Tokens without expiry are risky', 'If it leaks it works until you revoke it. Prefer an expiry and create a new token when it runs out.') : null);
    };
    syncExpiry();

    const res = await formDialog({
      title: 'New API token',
      size: 'md',
      fields: [name, scopesEl, expiry, customDate, warn, elevated].filter(Boolean),
      submitLabel: 'Create token',
      submitIcon: 'key',
      onSubmit: async (v) => {
        scopeError.textContent = '';
        const scopes = scopeBoxes.filter((x) => x.c.input.checked).map((x) => x.s.scope);
        if (!scopes.length) {
          scopeError.textContent = 'Choose at least one permission.';
          throw new ApiError(422, 'invalid', 'Choose at least one permission.');
        }
        /** @type {Record<string, any>} */
        const body = { name: String(v.name).trim(), scopes };
        const exp = expiry.input.value;
        if (exp === 'custom') {
          const at = fromLocalInput(String(v.expires_at));
          if (!at || new Date(at).getTime() <= Date.now()) throw new ApiError(422, 'invalid', 'Pick a date in the future.', 'expires_at');
          body.expires_at = at;
        } else if (exp !== 'never') {
          body.expires_at = daysFromNow(Number(exp));
        }
        if (elevated && elevated.input.checked) {
          if (!scopes.includes('admin')) throw new ApiError(422, 'invalid', 'Elevated tokens need the Administration permission.', 'elevated');
          const max = Date.now() + 30 * 86_400_000 + 60_000;
          if (!body.expires_at || new Date(body.expires_at).getTime() > max) body.expires_at = daysFromNow(30);
          body.elevated = true;
        }
        return api.post('/me/tokens', body);
      },
    });
    if (!res || res === true) return;
    const secret = String(res.secret || '');
    await load();
    if (!secret) return;
    await showSecretOnce({
      title: 'Your new token',
      intro: `Copy the token “${res.token?.name || ''}” now and store it in your password manager or the tool that uses it.`,
      secret,
      label: 'Token',
      what: 'Token',
      extra: h('pre', { class: 'json-block' }, h('code', { text: `curl -H "Authorization: Bearer ${secret}" ${location.origin}/api/v1/me` })),
      warning: 'The token is shown only once. If you lose it, revoke it and create a new one.',
    });
  };

  /** @param {any} t */
  const revoke = async (t) => {
    const ok = await confirm({
      title: `Revoke “${t.name || 'token'}”?`,
      message: `Anything using this token stops working immediately.${t.last_used_at ? ` It was last used ${dateTime(t.last_used_at)}.` : ''}`,
      confirmLabel: 'Revoke',
      danger: true,
    });
    if (!ok) return;
    try {
      await api.del(`/me/tokens/${encodeURIComponent(t.id)}`);
      toast.success('Token revoked');
      await load();
    } catch (err) {
      toast.error(err);
    }
  };

  await load();
}
