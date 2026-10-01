// @ts-check
/**
 * sharesPage(root, ctx, {kind}) — the "My links" (kind=link) and "File requests" (kind=request) pages:
 * GET /shares?kind=&status=&cursor= → table with status, limits, last activity and per-share actions
 * (copy link, QR code, edit, access log, pause/resume, delete, open the item).
 * @module components/shares-page
 */
import { h, icon, boot } from '../core/dom.js';
import { api, itemsOf, errorMessage, ApiError } from '../core/api.js';
import { navigate } from '../core/router.js';
import { persisted, session, can, hasSpace } from '../core/store.js';
import { relTime, dateTime, bytes, number } from '../core/format.js';
import { pageHeader } from './page-header.js';
import { table } from './table.js';
import { tabs } from './tabs.js';
import { button, iconButton } from './button.js';
import { menu } from './menu.js';
import { emptyState } from './empty-state.js';
import { toast } from './toast.js';
import { copyText } from './copy-field.js';
import { shareURL, shareStatus, shareSummary, shareSummaryNodes, linkDialog, requestDialog, shareQRDialog, accessLogDialog, revokeShare } from './share-dialog.js';

/**
 * @typedef {import('./share-dialog.js').Share} Share
 */

/**
 * @param {HTMLElement} root
 * @param {import('../core/router.js').PageContext} ctx
 * @param {{kind: 'link' | 'request', title: string, subtitle: string}} o
 * @returns {() => void}
 */
export function sharesPage(root, ctx, o) {
  const isReq = o.kind === 'request';
  // features.links / features.requests (the server setting and the role's permission, pages.Features): without it
  // the page still lists the links that exist (they keep working and can be closed or deleted) but offers no new one
  // and says why — the role, or the server.
  const flag = isReq ? 'requests' : 'links';
  const available = (session.peek()?.features?.[flag] ?? boot().features?.[flag]) !== false;
  const roleMay = can(isReq ? 'shares.requests' : 'shares.links');
  const unavailableText = roleMay
    ? (isReq ? 'File requests are turned off on this server.' : 'Public links are turned off on this server.')
    : (isReq ? 'Your role can’t create file requests. Ask an administrator if you need one.' : 'Your role can’t create public links. Ask an administrator if you need one.');
  // roles based on Guest have no "My files" (/files sends them to Shared with me)
  const hasHome = hasSpace();
  const filterPref = persisted(`shares-filter-${o.kind}`, 'active');
  let status = filterPref.peek() === 'all' ? '' : 'active';
  /** @type {Share[]} */
  let rows = [];
  let cursor = '';
  let seq = 0;

  // /files/<file id> redirects to the file's own folder with ?preview=<id> (pages/files.js start), so a linked file
  // opens among its siblings wherever it lives — not over the home root's list.
  const open = (/** @type {Share} */ s) => navigate(`/files/${encodeURIComponent(s.node_id)}`);

  const edit = async (/** @type {Share} */ s) => {
    const updated = isReq ? await requestDialog({ share: s }) : await linkDialog({ share: s });
    if (updated) load(false);
  };

  const setDisabled = async (/** @type {Share} */ s, /** @type {boolean} */ on) => {
    try {
      await api.patch(`/shares/${encodeURIComponent(s.id)}`, { disabled: on });
      toast.success(on ? (isReq ? 'File request closed' : 'Link paused') : (isReq ? 'File request reopened' : 'Link resumed'));
      load(false);
    } catch (err) {
      toast.error(err);
    }
  };

  /** @param {Share} s @param {HTMLElement} anchor */
  const moreMenu = (s, anchor) => {
    const disabled = !!s.disabled_at || s.status === 'disabled';
    menu({
      anchor,
      title: s.title || s.node_name || (isReq ? 'File request' : 'Link'),
      // editing and re-enabling need the same right as creating (FILEPARCEL.md "Share links"); pausing and deleting
      // do not
      items: [
        available ? { label: 'Edit…', icon: 'edit', onClick: () => edit(s) } : null,
        { label: 'Show QR code', icon: 'qr', onClick: () => shareQRDialog(s) },
        { label: 'Access log', icon: 'scroll', onClick: () => accessLogDialog(s) },
        { label: isReq ? 'Open folder' : s.node_kind === 'folder' ? 'Open folder' : 'Open file', icon: 'folder-open', onClick: () => open(s) },
        { divider: true },
        disabled
          ? (available ? { label: isReq ? 'Reopen request' : 'Resume link', icon: 'play', onClick: () => setDisabled(s, false) } : null)
          : { label: isReq ? 'Close request' : 'Pause link', icon: 'pause', onClick: () => setDisabled(s, true) },
        { label: isReq ? 'Delete request' : 'Delete link', icon: 'trash', danger: true, onClick: async () => { if (await revokeShare(s)) load(false); } },
      ],
    });
  };

  const t = table({
    caption: o.title,
    rowKey: 'id',
    loading: true,
    columns: [
      {
        key: 'name',
        label: isReq ? 'Request' : 'Shared item',
        render: (s) => h('div', { class: 'share-cell' },
          h('span', { class: 'share-cell-icon', dataset: { kind: isReq ? 'request' : s.node_kind || 'file' } }, icon(isReq ? 'inbox' : s.node_kind === 'folder' ? 'folder' : 'file', { size: 18 })),
          h('span', { class: 'share-cell-text' },
            h('span', { class: 'share-cell-title truncate', text: isReq ? s.title || s.node_name || 'File request' : s.title || s.node_name || 'Link' }),
            h('small', { class: 'muted truncate', text: isReq ? `into ${s.node_name || 'a folder'}` : s.title && s.node_name ? s.node_name : s.node_kind === 'folder' ? 'Folder' : 'File' }),
            h('small', { class: 'muted share-cell-mobile', attrs: { title: shareSummary(s) } }, shareSummaryNodes(s)))),
      },
      { key: 'status', label: 'Status', render: (s) => h('span', { class: 'cluster' }, shareStatus(s), s.has_password ? icon('lock', { size: 14, label: 'Password protected' }) : null) },
      isReq
        ? { key: 'received', label: 'Received', hideBelow: 'sm', render: (s) => `${bytes(s.upload_used_bytes || 0)}${s.upload_quota_bytes ? ` of ${bytes(s.upload_quota_bytes)}` : ''}` }
        : { key: 'downloads', label: 'Downloads', hideBelow: 'sm', align: 'end', render: (s) => (s.max_downloads ? `${number(s.download_count)} / ${number(s.max_downloads)}` : number(s.download_count || 0)) },
      { key: 'expires', label: 'Expires', hideBelow: 'md', render: (s) => (s.expires_at ? h('span', { attrs: { title: dateTime(s.expires_at) }, text: relTime(s.expires_at) }) : 'Never') },
      // last_access_at moves on every recorded access (page view, password attempt, block, upload, download), so it
      // is labelled as activity — for a request it is not the time files last arrived ("Received" shows whether any did).
      { key: 'last', label: 'Last activity', hideBelow: 'md', render: (s) => (s.last_access_at ? h('span', { attrs: { title: dateTime(s.last_access_at) }, text: relTime(s.last_access_at) }) : 'Never') },
      {
        key: 'actions',
        label: 'Actions',
        srOnlyLabel: true,
        class: 'cell-actions',
        render: (s) => h('div', { class: 'share-actions' },
          shareURL(s) ? iconButton({ icon: 'copy', label: 'Copy link', size: 'sm', onClick: () => copyText(shareURL(s), 'Link') }) : null,
          iconButton({ icon: 'qr', label: 'QR code', size: 'sm', class: 'hide-sm', onClick: () => shareQRDialog(s) }),
          iconButton({ icon: 'more-vertical', label: 'More actions', size: 'sm', attrs: { 'aria-haspopup': 'menu' }, onClick: (e) => moreMenu(s, /** @type {HTMLElement} */ (e.currentTarget)) })),
      },
    ],
    onRowClick: (s) => (available ? edit(s) : open(s)),
  });
  // shown instead of the table when the list is empty (an empty state inside a table cell looks boxed in)
  const emptySlot = h('div', { hidden: true });
  const renderEmpty = () => {
    if (!available) {
      emptySlot.replaceChildren(emptyState({
        icon: isReq ? 'inbox' : 'link',
        title: isReq ? 'File requests are not available' : 'Public links are not available',
        text: unavailableText,
        action: hasHome ? { label: 'Go to My files', icon: 'folder', href: '/files' } : { label: 'Go to Shared with me', icon: 'folder-shared', href: '/shared' },
      }));
      return;
    }
    emptySlot.replaceChildren(emptyState(isReq
      ? {
        icon: 'inbox',
        title: status ? 'No open file requests' : 'No file requests yet',
        text: 'A file request is a link that lets anyone upload files into one of your folders — without an account.',
        action: { label: 'New file request', icon: 'plus', onClick: () => create() },
      }
      : {
        icon: 'link',
        title: status ? 'No active links' : 'No links yet',
        text: 'Share a file or folder (⋮ → Share…) and create a public link. Your links are listed here.',
        action: hasHome ? { label: 'Go to My files', icon: 'folder', href: '/files' } : { label: 'Go to Shared with me', icon: 'folder-shared', href: '/shared' },
      }));
  };

  const filter = tabs({
    items: [{ id: 'active', label: 'Active' }, { id: 'all', label: 'All' }],
    active: status ? 'active' : 'all',
    variant: 'pill',
    label: 'Filter',
    onChange: (id) => {
      status = id === 'active' ? 'active' : '';
      filterPref.value = id;
      load(false);
    },
  });
  const more = button({ label: 'Load more', variant: 'secondary', size: 'sm', onClick: () => load(true) });
  more.hidden = true;
  const errorSlot = h('div');

  const create = async () => {
    const s = await requestDialog({});
    if (s) load(false);
  };

  root.append(
    pageHeader({
      title: o.title,
      subtitle: o.subtitle,
      actions: isReq && available ? button({ label: 'New file request', icon: 'plus', variant: 'primary', onClick: () => create() }) : undefined,
    }),
    available ? null : h('div', { class: 'alert alert--info', attrs: { role: 'status' } }, icon('info'),
      h('div', { class: 'alert-body' }, h('strong', { text: isReq ? 'You can’t create file requests' : 'You can’t create public links' }),
        h('span', { text: `${unavailableText} Existing ones are listed below; you can still close or delete them.` }))),
    h('div', { class: 'files-toolbar' }, filter.el),
    errorSlot,
    t.el,
    emptySlot,
    h('div', { class: 'cluster load-more' }, more));

  /** @param {boolean} append */
  async function load(append) {
    const my = ++seq;
    errorSlot.replaceChildren();
    try {
      const res = await api.get('/shares', { query: { kind: o.kind, status: status || undefined, limit: 100, cursor: append ? cursor || undefined : undefined }, signal: ctx.signal });
      if (my !== seq) return;
      const list = /** @type {Share[]} */ (itemsOf(res));
      rows = append ? rows.concat(list) : list;
      cursor = Array.isArray(res) ? '' : res?.next_cursor || '';
      t.setRows(rows);
      more.hidden = !cursor;
      t.el.hidden = rows.length === 0;
      emptySlot.hidden = rows.length > 0;
      if (!rows.length) renderEmpty();
    } catch (err) {
      if (err instanceof ApiError && err.aborted) return;
      if (my !== seq) return; // a newer load is already on its way
      t.setRows([]);
      t.el.hidden = true;
      emptySlot.hidden = true;
      more.hidden = true;
      // load(false), not load(true): the rows were just cleared, so a retry starts from the first page
      errorSlot.replaceChildren(h('div', { class: 'alert alert--danger', attrs: { role: 'alert' } }, icon('alert-circle'),
        h('div', { class: 'alert-body' }, h('strong', { text: 'Could not load the list' }), h('span', { text: errorMessage(err) })),
        button({ label: 'Retry', size: 'sm', onClick: () => load(false) })));
    }
  }

  load(false);
  if (isReq && ctx.query.new === '1') {
    navigate('/requests', { replace: true, render: false });
    if (available) create();
  }
  return () => { seq += 1; };
}
