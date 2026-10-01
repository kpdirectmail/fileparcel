// @ts-check
/**
 * Settings → Sessions (/settings/sessions): every browser session of the current user with device, IP address and
 * activity; sign out a single session or all others.
 *   GET    /me/sessions                 → Session[] (current: true marks this browser)
 *   DELETE /me/sessions/{id}
 *   POST   /me/sessions/revoke-others
 * Owned by unit J2.
 * @module pages/settings/sessions
 */
import { h, icon, replace, append } from '../../core/dom.js';
import { api, ApiError, itemsOf } from '../../core/api.js';
import { dateTime } from '../../core/format.js';
import { button } from '../../components/button.js';
import { badge } from '../../components/badge.js';
import { toast } from '../../components/toast.js';
import { confirm } from '../../components/dialog.js';
import { skeleton } from '../../components/progress.js';
import { emptyState } from '../../components/empty-state.js';
import { signOut } from '../../nav.js';
import { settingsHeader } from './common.js';
import { errorPanel, timeEl, describeUA, uaIcon } from '../admin/common.js';

export const title = 'Sessions';

/**
 * @param {HTMLElement} root
 * @param {import('../../core/router.js').PageContext} ctx
 */
export async function mount(root, ctx) {
  const othersBtn = button({ label: 'Sign out other sessions', icon: 'logout', variant: 'secondary', onClick: () => revokeOthers() });
  settingsHeader(root, {
    id: 'settings-sessions',
    title,
    subtitle: 'Where you are signed in. Sign out anything you don’t recognise and change your password.',
    actions: othersBtn,
  });
  const body = h('div', { class: 'stack' }, skeleton(4, { rows: true }));
  append(root, body);

  /** @type {any[]} */
  let sessions = [];

  const load = async () => {
    try {
      sessions = itemsOf(await api.get('/me/sessions', { signal: ctx.signal }));
    } catch (err) {
      if (err instanceof ApiError && err.aborted) return;
      replace(body, errorPanel(err, load));
      return;
    }
    // current first, then most recently active
    sessions.sort((a, b) => Number(!!b.current) - Number(!!a.current) || String(b.last_seen_at).localeCompare(String(a.last_seen_at)));
    draw();
  };

  const draw = () => {
    const live = sessions.filter((s) => !s.revoked_at);
    othersBtn.disabled = live.filter((s) => !s.current).length === 0;
    if (!live.length) {
      replace(body, emptyState({ icon: 'laptop', title: 'No active sessions', text: 'Sessions appear here when you sign in from a browser.' }));
      return;
    }
    replace(body, 
      h('ul', { class: 'item-list card card--flush', attrs: { role: 'list', 'aria-label': 'Active sessions' } }, live.map((s) => h('li', { class: 'item-row' },
        h('span', { class: 'item-row-icon', attrs: { 'aria-hidden': 'true' } }, icon(uaIcon(s.user_agent))),
        h('div', { class: 'item-row-main' },
          h('span', { class: 'item-row-title' },
            describeUA(s.user_agent),
            s.current ? badge({ text: 'This device', kind: 'success' }) : null,
            s.remember ? badge({ text: 'Remembered', kind: 'neutral', title: 'Signed in with “Keep me signed in”' }) : null,
            s.client_cert_serial ? badge({ text: 'Client certificate', kind: 'info', icon: 'certificate' }) : null),
          h('span', { class: 'item-row-sub' },
            s.ip ? h('span', { class: 'mono', text: s.ip }) : 'Unknown address',
            ' · active ', timeEl(s.last_seen_at),
            ' · signed in ', timeEl(s.created_at)),
          h('span', { class: 'item-row-sub subtle', text: `Expires ${dateTime(s.expires_at)}${s.mfa_method ? ` · verified with ${mfaLabel(s.mfa_method)}` : ''}` })),
        s.current
          ? button({ label: 'Sign out', size: 'sm', variant: 'ghost', icon: 'logout', onClick: () => signOutHere() })
          : button({ label: 'Sign out', size: 'sm', variant: 'secondary', onClick: () => revoke(s) })))),
      h('p', { class: 'muted text-sm', text: 'Sessions end after a period of inactivity or when they expire. Changing your password signs out every other session.' }));
  };

  /** @param {any} s */
  const revoke = async (s) => {
    const ok = await confirm({ title: 'Sign out this session?', message: `${describeUA(s.user_agent)}${s.ip ? ` at ${s.ip}` : ''} will be signed out immediately.`, confirmLabel: 'Sign out', danger: true });
    if (!ok) return;
    try {
      await api.del(`/me/sessions/${encodeURIComponent(s.id)}`);
      toast.success('Session signed out');
      await load();
    } catch (err) {
      toast.error(err);
    }
  };

  const revokeOthers = async () => {
    const n = sessions.filter((s) => !s.current && !s.revoked_at).length;
    const ok = await confirm({
      title: 'Sign out all other sessions?',
      message: `${n} other session${n === 1 ? '' : 's'} will be signed out. This browser stays signed in.`,
      confirmLabel: 'Sign out others',
      danger: true,
    });
    if (!ok) return;
    try {
      await api.post('/me/sessions/revoke-others', {});
      toast.success('All other sessions were signed out');
      await load();
    } catch (err) {
      toast.error(err);
    }
  };

  const signOutHere = async () => {
    const ok = await confirm({ title: 'Sign out of this browser?', message: 'You will need your password (and second factor) to sign in again.', confirmLabel: 'Sign out' });
    if (ok) await signOut();
  };

  await load();
}

/** @param {string} m */
function mfaLabel(m) {
  return { totp: 'authenticator app', recovery: 'a recovery code', passkey: 'a passkey' }[m] || m;
}
