// @ts-check
/**
 * nodeDetails(target, opts) → {el, destroy()}
 *
 * The details panel of the file browser (§13.5: info, versions, sharing, activity). `target` is one node, several
 * nodes (a summary with the total size) or null (nothing selected). The files page shows it as a side panel on wide
 * screens and in a dialog/sheet otherwise (openDetailsDialog).
 *   Info      type, protection (password-protected .zip), size (folders: GET /nodes/{id}/stats), location, dates,
 *             access level, content hash
 *   Versions  GET /nodes/{id}/versions (a lock on protected ones); download (content?version=) or restore
 *             (POST …/versions/{vid}/restore)
 *   Sharing   components/share-dialog.js sharingPanel (grants + public links)
 *   Activity  GET /activity?target_type=node&target_id=… (the user's own events for this item)
 * @module components/details-panel
 */
import { h, icon } from '../core/dom.js';
import { api, itemsOf, errorMessage } from '../core/api.js';
import { bytes, dateTime, relTime, number, fileIcon } from '../core/format.js';
import { can, contentURL, thumbURL, typeLabel, triggerDownload, permLevel, spaces, spaceLabel, downloadNodes, zipProtectionLabel } from '../core/nodes.js';
import { tabs } from './tabs.js';
import { button, iconButton } from './button.js';
import { confirm, dialog } from './dialog.js';
import { toast } from './toast.js';
import { spinner } from './progress.js';
import { badge } from './badge.js';
import { copyText } from './copy-field.js';
import { activityRow } from './activity.js';

/**
 * @typedef {import('../core/nodes.js').Node} Node
 * @typedef {'info' | 'versions' | 'sharing' | 'activity'} DetailsTab
 */

/**
 * @typedef {Object} DetailsOpts
 * @property {DetailsTab} [tab]
 * @property {(node: Node) => void} [onChanged] a version was restored / sharing changed
 * @property {(node: Node) => void} [onShare] open the share dialog
 * @property {(node: Node, on: boolean) => void} [onStar]
 * @property {() => void} [onClose] shows a close button when given
 * @property {string} [emptyText]
 */

const PERM_TEXT = ['No access', 'Can view', 'Can edit', 'Can manage', 'Owner'];

/** @param {string} k @param {import('../core/dom.js').Child} v */
const kv = (k, v) => [h('dt', { text: k }), h('dd', null, v)];

/**
 * @param {Node | Node[] | null} target
 * @param {DetailsOpts} [opts]
 */
export function nodeDetails(target, opts = {}) {
  const ctrl = new AbortController();
  const closeBtn = opts.onClose ? iconButton({ icon: 'x', label: 'Close details', size: 'sm', onClick: () => opts.onClose?.() }) : null;

  if (!target || (Array.isArray(target) && target.length === 0)) {
    return {
      el: h('div', { class: 'details details--empty' },
        closeBtn ? h('div', { class: 'details-close' }, closeBtn) : null,
        h('div', { class: 'details-empty' }, icon('info', { size: 28 }), h('p', { text: opts.emptyText || 'Select a file or folder to see its details.' }))),
      destroy() {},
    };
  }

  if (Array.isArray(target) && target.length > 1) {
    const files = target.filter((n) => n.kind === 'file');
    const folders = target.length - files.length;
    const total = files.reduce((s, n) => s + (n.size || 0), 0);
    return {
      el: h('div', { class: 'details' },
        h('div', { class: 'details-head' },
          h('div', { class: 'details-icon details-icon--multi' }, icon('copy', { size: 32 })),
          h('div', { class: 'details-title' }, h('h2', { class: 'details-name', text: `${number(target.length)} items selected` }),
            h('p', { class: 'muted text-sm', text: [files.length ? `${number(files.length)} file${files.length === 1 ? '' : 's'} (${bytes(total)})` : '', folders ? `${number(folders)} folder${folders === 1 ? '' : 's'}` : ''].filter(Boolean).join(' · ') })),
          closeBtn),
        h('div', { class: 'details-actions' },
          button({ label: 'Download as .zip', icon: 'download', size: 'sm', onClick: () => downloadNodes(target, { format: 'zip' }).catch((e) => toast.error(e)) }))),
      destroy() {},
    };
  }

  const node = /** @type {Node} */ (Array.isArray(target) ? target[0] : target);
  const isFile = node.kind === 'file';
  const items = [{ id: 'info', label: 'Info' }];
  if (isFile) items.push({ id: 'versions', label: 'Versions' });
  items.push({ id: 'sharing', label: 'Sharing' }, { id: 'activity', label: 'Activity' });
  let active = /** @type {DetailsTab} */ (items.some((i) => i.id === opts.tab) ? opts.tab : 'info');
  const panel = h('div', { class: 'details-panel', attrs: { role: 'tabpanel' } });

  const t = tabs({ items, active, label: 'Details', onChange: (id) => { active = /** @type {DetailsTab} */ (id); renderTab(); } });

  const preview = h('div', { class: 'details-icon', dataset: { kind: node.kind, type: fileIcon(node) } });
  if (node.has_thumb) {
    const img = h('img', { src: thumbURL(node), alt: '', attrs: { decoding: 'async' } });
    img.addEventListener('error', () => img.replaceWith(icon(fileIcon(node), { size: 36 })), { once: true });
    preview.append(img);
    preview.dataset.thumb = '';
  } else {
    preview.append(icon(fileIcon(node), { size: 36 }));
  }

  const starBtn = opts.onStar
    ? iconButton({
      icon: 'star',
      label: node.starred ? 'Remove from starred' : 'Add to starred',
      size: 'sm',
      pressed: !!node.starred,
      onClick: () => {
        node.starred = !node.starred;
        starBtn?.setAttribute('aria-pressed', String(node.starred));
        starBtn?.setAttribute('aria-label', node.starred ? 'Remove from starred' : 'Add to starred');
        opts.onStar?.(node, !!node.starred);
      },
    })
    : null;

  const el = h('div', { class: 'details' },
    h('div', { class: 'details-head' },
      preview,
      h('div', { class: 'details-title' },
        h('h2', { class: 'details-name', attrs: { title: node.name }, text: node.name }),
        h('p', { class: 'muted text-sm', text: isFile ? `${typeLabel(node)} · ${bytes(node.size)}` : 'Folder' })),
      h('div', { class: 'details-head-actions' }, starBtn, closeBtn)),
    h('div', { class: 'details-actions' },
      button({ label: 'Download', icon: 'download', size: 'sm', onClick: () => downloadNodes([node]).catch((e) => toast.error(e)) }),
      opts.onShare && can(node, 'manage') ? button({ label: 'Share', icon: 'share', size: 'sm', onClick: () => opts.onShare?.(node) }) : null),
    t.el,
    panel);

  const renderTab = () => {
    panel.replaceChildren();
    if (active === 'info') panel.append(infoTab(node, ctrl.signal));
    else if (active === 'versions') panel.append(versionsTab(node, opts, ctrl.signal));
    else if (active === 'sharing') import('./share-dialog.js').then((m) => { if (active === 'sharing') panel.replaceChildren(m.sharingPanel(node, { onChange: () => opts.onChanged?.(node) })); });
    else panel.append(activityTab(node, ctrl.signal));
  };
  renderTab();

  return {
    el,
    destroy: () => ctrl.abort(),
  };
}

/**
 * The Protection value of a password-protected .zip: "Password · AES-256", or the warning "Password · ZipCrypto
 * (weak)". Unlike other badges it wraps, so the whole text stays readable in the narrow value column of a phone.
 * @param {Node} node
 */
function protectionBadge(node) {
  const zc = node.zip_encryption === 'zipcrypto';
  const b = badge({ text: zc ? 'Password · ZipCrypto (weak)' : 'Password · AES-256', kind: zc ? 'warning' : 'primary', icon: 'lock', title: zipProtectionLabel(node) });
  b.classList.add('details-zip-badge');
  return b;
}

/**
 * @param {Node} node
 * @param {AbortSignal} signal
 */
function infoTab(node, signal) {
  const sizeDd = h('span', { text: node.kind === 'file' ? `${bytes(node.size)}${node.size >= 1024 ? ` (${node.size.toLocaleString()} bytes)` : ''}` : '…' });
  const locDd = h('span', { class: 'break', text: node.path || '…' });
  const level = permLevel(node.perm);
  const dl = h('dl', { class: 'kv details-kv' },
    kv('Type', typeLabel(node)),
    node.kind === 'file' && node.zip_encryption ? kv('Protection', protectionBadge(node)) : null,
    kv(node.kind === 'file' ? 'Size' : 'Contents', sizeDd),
    kv('Location', locDd),
    kv('Modified', h('span', { attrs: { title: dateTime(node.updated_at) }, text: `${dateTime(node.updated_at)} (${relTime(node.updated_at)})` })),
    kv('Created', dateTime(node.created_at)),
    node.client_mtime ? kv('Original date', dateTime(node.client_mtime)) : null,
    kv('Your access', badge({ text: PERM_TEXT[level] || 'Can view', kind: level >= 3 ? 'primary' : 'neutral' })),
    node.content_hash
      ? kv('Checksum', h('button', {
        class: 'details-hash mono',
        attrs: { type: 'button', title: 'Copy checksum' },
        on: { click: () => copyText(String(node.content_hash), 'Checksum') },
      }, String(node.content_hash)))
      : null);
  if (node.kind === 'folder') {
    api.get(`/nodes/${encodeURIComponent(node.id)}/stats`, { signal, handle: false })
      .then((s) => {
        const parts = [];
        if (s?.folders) parts.push(`${number(s.folders)} folder${s.folders === 1 ? '' : 's'}`);
        parts.push(`${number(s?.files || 0)} file${s?.files === 1 ? '' : 's'}`);
        sizeDd.textContent = `${parts.join(', ')} · ${bytes(s?.bytes || 0)}`;
      })
      .catch(() => { sizeDd.textContent = typeof node.child_count === 'number' ? `${number(node.child_count)} items` : '—'; });
  }
  if (!node.path) {
    api.get(`/nodes/${encodeURIComponent(node.id)}/breadcrumbs`, { signal, handle: false })
      .then(async (crumbs) => {
        const list = itemsOf(crumbs).filter((c) => c.id !== node.id);
        const sp = await spaces().catch(() => []);
        const names = list.map((c, i) => {
          if (i === 0 && !c.parent_id) return spaceLabel(sp.find((s) => s.id === c.space_id));
          return c.name;
        });
        locDd.textContent = names.length ? names.join(' › ') : spaceLabel(sp.find((s) => s.id === node.space_id));
      })
      .catch(() => { locDd.textContent = '—'; });
  }
  return dl;
}

/**
 * @param {Node} node
 * @param {DetailsOpts} opts
 * @param {AbortSignal} signal
 */
function versionsTab(node, opts, signal) {
  const list = h('ul', { class: 'version-list', attrs: { role: 'list' } }, h('li', { class: 'details-loading' }, spinner()));
  const load = async () => {
    try {
      const versions = itemsOf(await api.get(`/nodes/${encodeURIComponent(node.id)}/versions`, { signal }));
      versions.sort((a, b) => (Date.parse(b.created_at) || 0) - (Date.parse(a.created_at) || 0));
      list.replaceChildren(...versions.map((v) => {
        const current = v.current || v.id === node.version_id;
        return h('li', { class: 'version-row', dataset: { current: current ? '' : null } },
          h('span', { class: 'version-dot', attrs: { 'aria-hidden': 'true' } }),
          h('span', { class: 'version-text' },
            h('span', { class: 'cluster' }, h('span', { attrs: { title: dateTime(v.created_at) }, text: dateTime(v.created_at) }), current ? badge({ text: 'Current', kind: 'primary' }) : null,
              v.zip_encryption ? h('span', { class: 'version-lock', attrs: { title: zipProtectionLabel(v) } }, icon('lock', { size: 14, label: 'Password-protected' })) : null),
            // no "first version" mark: a restore makes an old version current again and pruning drops the oldest,
            // so the last row of the list is not necessarily the original upload
            h('small', { class: 'muted', text: [bytes(v.size), v.created_by_name || ''].filter(Boolean).join(' · ') })),
          h('span', { class: 'version-actions' },
            iconButton({ icon: 'download', label: `Download the version from ${dateTime(v.created_at)}`, size: 'sm', onClick: () => triggerDownload(contentURL(node, { version: v.id }), node.name) }),
            !current && can(node, 'edit')
              ? iconButton({
                icon: 'rotate-ccw',
                label: `Restore the version from ${dateTime(v.created_at)}`,
                size: 'sm',
                onClick: async () => {
                  const ok = await confirm({
                    title: 'Restore this version?',
                    message: `The version from ${dateTime(v.created_at)} becomes the current one. The current content is kept as a version, so nothing is lost.`,
                    confirmLabel: 'Restore',
                  });
                  if (!ok) return;
                  try {
                    const updated = await api.post(`/nodes/${encodeURIComponent(node.id)}/versions/${encodeURIComponent(v.id)}/restore`, {});
                    toast.success('Version restored');
                    Object.assign(node, updated || {});
                    opts.onChanged?.(node);
                    await load();
                  } catch (err) {
                    toast.error(err);
                  }
                },
              })
              : null));
      }));
      if (!versions.length) list.replaceChildren(h('li', { class: 'muted text-sm', text: 'No earlier versions.' }));
    } catch (err) {
      if (/** @type {any} */ (err)?.code === 'aborted') return;
      list.replaceChildren(h('li', { class: 'danger-text text-sm', text: errorMessage(err) }));
    }
  };
  load();
  return h('div', { class: 'stack-sm' },
    h('p', { class: 'muted text-xs', text: 'Uploading a file with the same name (Replace) keeps the previous content as a version.' }),
    list);
}

/**
 * @param {Node} node
 * @param {AbortSignal} signal
 */
function activityTab(node, signal) {
  const list = h('ul', { class: 'act-list act-list--compact', attrs: { role: 'list' } }, h('li', { class: 'details-loading' }, spinner()));
  // GET /activity lists the user's own events; target_type/target_id narrow it to this item on the server (so its
  // history is found however many other events came after it). The rows are checked here as well, defensively.
  api.get('/activity', { query: { target_type: 'node', target_id: node.id, limit: 200 }, signal, handle: false })
    .then((res) => {
      const rows = itemsOf(res).filter((r) => r.target_id === node.id);
      list.replaceChildren(...rows.map((r) => activityRow(r, { compact: true })));
      if (!rows.length) list.replaceChildren(h('li', { class: 'muted text-sm', text: 'No recorded activity for this item yet.' }));
    })
    .catch((err) => {
      if (err?.code === 'aborted') return;
      list.replaceChildren(h('li', { class: 'muted text-sm', text: 'Activity is not available right now.' }));
    });
  return list;
}

/**
 * Details in a dialog (tablet/mobile, or from the preview).
 * @param {Node | Node[]} target
 * @param {DetailsOpts} [opts]
 */
export function openDetailsDialog(target, opts = {}) {
  /** @type {{el: HTMLElement, destroy: () => void} | null} */
  let view = null;
  const d = dialog({
    title: 'Details',
    size: 'md',
    class: 'details-dialog',
    body: null,
    onClose: () => view?.destroy(),
  });
  view = nodeDetails(target, { ...opts, onClose: undefined });
  d.body.append(view.el);
  d.open();
  return d;
}
