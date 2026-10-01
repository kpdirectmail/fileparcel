// @ts-check
/**
 * Admin → Audit log (/admin/audit): tamper-evident (HMAC-chained) record of security-relevant actions, with filters,
 * infinite scroll, details, chain verification and export.
 *   GET /admin/audit?since=&until=&actor_id=&action=&outcome=&target_type=&target_id=&q=&cursor=&limit=  → Page[AuditRecord]
 *   GET /admin/audit/verify                       → AuditVerify {ok, checked, first_seq, last_seq, broken_at, message}
 *   GET /admin/audit/export?format=csv|jsonl&…    → file download (same filters)
 * `action` matches exactly, or as a prefix when it ends with "." ("auth." = every sign-in event).
 * Filters live in the URL query so a filtered view can be bookmarked.
 * Owned by unit J2.
 * @module pages/admin/audit
 */
import { h, icon, replace, append } from '../../core/dom.js';
import { api, ApiError, itemsOf, apiUrl } from '../../core/api.js';
import { navigate } from '../../core/router.js';
import { dateTime, number } from '../../core/format.js';
import { button } from '../../components/button.js';
import { dialog } from '../../components/dialog.js';
import { field, select } from '../../components/field.js';
import { menu } from '../../components/menu.js';
import { toast } from '../../components/toast.js';
import { spinner } from '../../components/progress.js';
import { emptyState } from '../../components/empty-state.js';
import {
  adminHeader, errorPanel, alertEl, kv, stateBadge, timeEl, jsonBlock, infiniteScroll, debounce, fromLocalInput, toLocalInput,
  actionIcon, actionText, targetIsActor, describeUA, nativeDownload,
} from './common.js';

export const title = 'Audit log';

/** Action filter presets (prefix match). */
const ACTION_GROUPS = [
  { value: '', label: 'All actions' },
  { value: 'auth.', label: 'Sign-in' },
  { value: 'user.', label: 'Users' },
  { value: 'role.', label: 'Roles' },
  { value: 'mfa.', label: 'Two-factor' },
  { value: 'passkey.', label: 'Passkeys' },
  { value: 'token.', label: 'API tokens' },
  { value: 'session.', label: 'Sessions' },
  { value: 'invite.', label: 'Invitations' },
  { value: 'group.', label: 'Groups' },
  { value: 'file.', label: 'Files' },
  { value: 'folder.', label: 'Folders' },
  { value: 'grant.', label: 'Sharing with people' },
  { value: 'share.', label: 'Share links' },
  { value: 'request.', label: 'File requests' },
  { value: 'settings.', label: 'Settings' },
  { value: 'network.', label: 'Network' },
  { value: 'cert.', label: 'Certificates' },
  { value: 'ca.', label: 'Certificate authority' },
  { value: 'client_cert.', label: 'Client certificates' },
  { value: 'keys.', label: 'Encryption keys' },
  { value: 'backup.', label: 'Backups' },
  { value: 'system.', label: 'System' },
  { value: 'admin.', label: 'Admin file access' },
];

/**
 * @param {HTMLElement} root
 * @param {import('../../core/router.js').PageContext} ctx
 */
export async function mount(root, ctx) {
  const verifyBtn = button({ label: 'Verify integrity', icon: 'shield-check', onClick: () => verify() });
  const exportBtn = button({
    label: 'Export',
    icon: 'download',
    iconEnd: 'chevron-down',
    attrs: { 'aria-haspopup': 'menu' },
    onClick: (e) => menu({
      anchor: /** @type {Element} */ (e.currentTarget),
      align: 'end',
      items: [
        { label: 'CSV (spreadsheets)', icon: 'file-text', onClick: () => exportAs('csv') },
        { label: 'JSON Lines (tools, SIEM)', icon: 'file-code', onClick: () => exportAs('jsonl') },
      ],
    }),
  });
  adminHeader(root, { title, subtitle: 'Who did what, when and from where. Entries are chained so tampering is detectable.', actions: [verifyBtn, exportBtn] });

  const q = field({ label: 'Search', hideLabel: true, type: 'search', placeholder: 'Search people and items', value: ctx.query.q || '', autocomplete: 'off' });
  const action = select({ label: 'Action', hideLabel: true, value: ctx.query.action || '', options: ACTION_GROUPS.some((a) => a.value === (ctx.query.action || '')) ? ACTION_GROUPS : [...ACTION_GROUPS, { value: ctx.query.action, label: ctx.query.action }], onChange: () => apply() });
  const outcome = select({
    label: 'Outcome', hideLabel: true, value: ctx.query.outcome || '',
    options: [{ value: '', label: 'Any outcome' }, { value: 'success', label: 'Succeeded' }, { value: 'failure', label: 'Failed' }, { value: 'denied', label: 'Denied' }],
    onChange: () => apply(),
  });
  const since = field({ label: 'From', type: 'datetime-local', value: ctx.query.since ? toLocalInput(ctx.query.since) : '' });
  const until = field({ label: 'To', type: 'datetime-local', value: ctx.query.until ? toLocalInput(ctx.query.until) : '' });
  since.input.addEventListener('change', () => apply());
  until.input.addEventListener('change', () => apply());
  q.input.addEventListener('input', debounce(() => apply(), 300));
  const resetBtn = button({ label: 'Clear filters', variant: 'ghost', size: 'sm', icon: 'x', onClick: () => { q.input.value = ''; action.input.value = ''; outcome.input.value = ''; since.input.value = ''; until.input.value = ''; apply(); } });
  const actorNote = h('div');
  append(root, h('div', { class: 'admin-toolbar admin-toolbar--wrap' },
    h('div', { class: 'admin-toolbar-search' }, q.el), action.el, outcome.el,
    h('div', { class: 'audit-range' }, since.el, until.el), resetBtn), actorNote);

  const verifySlot = h('div');
  const list = h('ol', { class: 'audit-list', attrs: { 'aria-label': 'Audit entries' } });
  const sentinel = h('div', { class: 'audit-sentinel' });
  const status = h('div', { class: 'load-more', attrs: { 'aria-live': 'polite' } });
  const listSlot = h('div', { class: 'stack' }, list, sentinel, status);
  append(root, verifySlot, listSlot);

  let cursor = '';
  let loading = false;
  let done = false;
  let seq = 0;
  let total = 0;
  const actorId = ctx.query.actor_id || '';
  const targetType = ctx.query.target_type || '';
  const targetId = ctx.query.target_id || '';
  if (actorId || targetId) {
    replace(actorNote, alertEl('info', 'Filtered', `${actorId ? `Only actions by ${actorId}` : ''}${actorId && targetId ? ' and ' : ''}${targetId ? `only entries about ${targetType || 'item'} ${targetId}` : ''}.`,
      button({ label: 'Show everything', size: 'sm', onClick: () => navigate('/admin/audit') })));
  }

  const filters = () => {
    /** @type {Record<string, string | undefined>} */
    const f = {
      q: String(q.input.value).trim() || undefined,
      action: action.input.value || undefined,
      outcome: outcome.input.value || undefined,
      since: fromLocalInput(since.input.value) || undefined,
      until: fromLocalInput(until.input.value) || undefined,
      actor_id: actorId || undefined,
      target_type: targetType || undefined,
      target_id: targetId || undefined,
    };
    return f;
  };

  const apply = () => {
    const f = filters();
    const params = new URLSearchParams();
    for (const [k, v] of Object.entries(f)) if (v) params.set(k, v);
    const s = params.toString();
    history.replaceState(history.state, '', `/admin/audit${s ? `?${s}` : ''}`);
    reset();
  };

  const reset = () => {
    seq += 1;
    cursor = '';
    done = false;
    loading = false;
    total = 0;
    replace(list);
    replace(status);
    loadMore();
  };

  const loadMore = async () => {
    if (loading || done) return;
    loading = true;
    const mine = seq;
    replace(status, spinner({ label: 'Loading entries' }));
    try {
      const res = await api.get('/admin/audit', { signal: ctx.signal, query: { ...filters(), cursor: cursor || undefined, limit: 100 } });
      if (mine !== seq) return;
      const items = itemsOf(res);
      cursor = res?.next_cursor || '';
      done = !cursor;
      total += items.length;
      append(list, ...items.map(row));
      if (!total) {
        replace(status, emptyState({ icon: 'scroll', title: 'No entries', text: Object.values(filters()).some(Boolean) ? 'Nothing matches these filters.' : 'Nothing has been recorded yet.' }));
      } else {
        replace(status, done ? h('p', { class: 'subtle text-xs', text: `${number(total)} entr${total === 1 ? 'y' : 'ies'} · end of log` }) : button({ label: 'Load more', variant: 'ghost', icon: 'chevron-down', onClick: () => loadMore() }));
      }
    } catch (err) {
      if (err instanceof ApiError && err.aborted) return;
      if (mine !== seq) return;
      replace(status, errorPanel(err, () => loadMore()));
    } finally {
      if (mine === seq) loading = false;
    }
  };

  /** @param {any} a */
  const row = (a) => h('li', { class: 'audit-row', dataset: { outcome: a.outcome || 'success' } },
    h('button', { class: 'audit-row-btn', attrs: { type: 'button', 'aria-label': `Details of ${a.action} at ${dateTime(a.at)}` }, on: { click: () => details(a) } },
      h('span', { class: 'audit-icon', attrs: { 'aria-hidden': 'true' } }, icon(actionIcon(a.action))),
      h('span', { class: 'audit-main' },
        h('span', { class: 'audit-line' },
          h('strong', { text: a.actor_name || viaLabel(a.actor_via) }),
          ` ${actionText(a.action, a.outcome)}`,
          a.target_name && !targetIsActor(a) ? h('span', { class: 'audit-target', text: ` ${a.target_name}` }) : null),
        h('span', { class: 'audit-meta' },
          h('code', { class: 'audit-action', text: a.action }),
          a.ip ? h('span', { class: 'mono', text: a.ip }) : null,
          a.actor_via && a.actor_via !== 'session' ? h('span', { text: `via ${a.actor_via}` }) : null)),
      h('span', { class: 'audit-side' },
        a.outcome && a.outcome !== 'success' ? stateBadge(a.outcome) : null,
        timeEl(a.at))));

  /** @param {any} a */
  const details = (a) => {
    let det = a.details;
    if (typeof det === 'string') {
      try { det = JSON.parse(det); } catch { /* keep string */ }
    }
    const hasDetails = det && (typeof det !== 'object' || Object.keys(det).length > 0);
    dialog({
      title: actionText(a.action, a.outcome).replace(/^./, (c) => c.toUpperCase()),
      size: 'md',
      body: h('div', { class: 'stack' },
        kv([
          ['When', dateTime(a.at, { seconds: true })],
          ['Action', h('code', { text: a.action })],
          ['Outcome', stateBadge(a.outcome || 'success')],
          ['Who', a.actor_name ? `${a.actor_name}${a.actor_id ? ` (${a.actor_id})` : ''}` : viaLabel(a.actor_via)],
          ['Via', a.actor_via || null],
          ['Address', a.ip ? h('span', { class: 'mono', text: a.ip }) : null],
          ['Device', a.user_agent ? h('span', { title: a.user_agent, text: describeUA(a.user_agent) }) : null],
          ['Target', a.target_type || a.target_id ? `${a.target_type || ''} ${a.target_name || ''}${a.target_id ? ` (${a.target_id})` : ''}`.trim() : null],
          ['Request', a.request_id ? h('span', { class: 'mono text-xs', text: a.request_id }) : null],
          ['Sequence', a.seq ? `#${a.seq}` : null],
        ]),
        hasDetails ? h('div', { class: 'stack-sm' }, h('strong', { class: 'text-sm', text: 'Details' }), jsonBlock(det)) : null),
      actions: [
        a.actor_id ? { label: 'All by this person', icon: 'user', onClick: () => navigate(`/admin/audit?actor_id=${encodeURIComponent(a.actor_id)}`) } : null,
        a.target_id ? { label: 'All about this item', icon: 'filter', onClick: () => navigate(`/admin/audit?target_type=${encodeURIComponent(a.target_type || '')}&target_id=${encodeURIComponent(a.target_id)}`) } : null,
        { label: 'Close', variant: 'primary' },
      ].filter(Boolean).map((x) => /** @type {any} */ (x)),
    }).open();
  };

  const verify = async () => {
    replace(verifySlot, h('div', { class: 'card cluster' }, spinner({ label: 'Verifying' }), h('span', { text: 'Checking every entry of the hash chain…' })));
    try {
      const r = await api.get('/admin/audit/verify', { signal: ctx.signal });
      replace(verifySlot, r?.ok
        ? alertEl('success', 'The audit log is intact', `${number(r.checked || 0)} entries checked (#${r.first_seq ?? '?'} – #${r.last_seq ?? '?'}). None was changed or removed.`)
        : alertEl('danger', 'The audit log was tampered with', `${r?.message || 'The hash chain is broken.'}${r?.broken_at ? ` First bad entry: #${r.broken_at}.` : ''} Entries before it are trustworthy; investigate how the database was modified.`));
    } catch (err) {
      if (err instanceof ApiError && err.aborted) return;
      replace(verifySlot, errorPanel(err, verify, 'Verification failed'));
    }
  };

  /** @param {'csv' | 'jsonl'} format */
  const exportAs = (format) => {
    const url = apiUrl('/admin/audit/export', { ...filters(), format });
    nativeDownload(url);
    toast.info('Preparing the export…', { timeout: 3000 });
  };

  const disconnect = infiniteScroll(sentinel, () => loadMore());
  reset();
  return () => disconnect();
}

/** @param {string} via */
function viaLabel(via) {
  return { socket: 'Command line', offline: 'Command line (offline)', share: 'Share visitor', token: 'API token' }[via] || 'Anonymous';
}

