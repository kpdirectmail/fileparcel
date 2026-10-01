// @ts-check
/**
 * /s/{token} — public share viewer (kind "link") and file-request drop zone (kind "request"). A folder link with
 * allow_upload shows the viewer plus the same upload area (files go to the folder being viewed); one that allows
 * neither downloads nor previews is laid out like a file request (the server does not list it either).
 *
 * API (sharesapi, §9.4 public root; no session, CrossOriginProtection on POST/PUT):
 *   GET  /s/{t}/api                  → PublicShareInfo {share, password_required?, node, items, next_cursor}
 *   GET  /s/{t}/api/list?node=&cursor= → Page[Node] (sub-folders of a shared folder)
 *   POST /s/{t}/api/password {password} (sets the share access cookie; 401/422 wrong, 429 rate limited)
 *   GET  /s/{t}/dl/{nodeId}[?inline=1] · GET /s/{t}/thumb/{nodeId}
 *   POST /s/{t}/api/archive {node_ids, format} → {ticket, url} (single-use; navigate to url)
 *   uploads (requests, links with allow_upload): see public/share-upload.js
 * Invalid / expired / disabled tokens render the generic 404 page server-side; if a share stops working while the
 * page is open the API answers 404 and we show the same neutral message. A password-protected .zip (node
 * zip_encryption, DESIGN §8.1) carries a labelled lock, and a link to one says whom to ask for its password.
 * Owned by unit J2.
 * @module public/share
 */
import { h, icon, boot, replace } from '../core/dom.js';
import { api, ApiError, itemsOf, errorMessage } from '../core/api.js';
import { bytes, date, dateTime, relTime, fileIcon, speed, duration, plural } from '../core/format.js';
import { zipProtectionLabel } from '../core/nodes.js';
import { field } from '../components/field.js';
import { form } from '../components/form.js';
import { button, iconButton } from '../components/button.js';
import { progress } from '../components/progress.js';
import { emptyState } from '../components/empty-state.js';
import { dialog } from '../components/dialog.js';
import { menu } from '../components/menu.js';
import { toast } from '../components/toast.js';
import { breadcrumbs } from '../components/page-header.js';
import { publicRoot, authCard, alertBox, initAppearance, rateLimitMessage, instanceName } from './common.js';
import { ShareUpload, entriesFromDataTransfer, entriesFromFiles } from './share-upload.js';

initAppearance();
const b = boot();
const token = String(b.data.token || safeDecode(location.pathname.split('/')[2] || ''));
const base = `/s/${encodeURIComponent(token)}`;
const root = publicRoot();
load();

/** @param {string} s */
function safeDecode(s) {
  try { return decodeURIComponent(s); } catch { return s; }
}

/** @param {string} title */
function setDocTitle(title) {
  document.title = title ? `${title} · ${instanceName()}` : instanceName();
}

async function load() {
  replace(root, h('div', { class: 'loading-block' }, h('span', { class: 'spinner spinner--lg', attrs: { role: 'status', 'aria-label': 'Loading' } })));
  /** @type {any} */
  let info;
  try {
    info = await api.get(`${base}/api`, { handle: false });
  } catch (err) {
    if (err instanceof ApiError && (err.code === 'password_required' || err.details?.password_required)) {
      renderPassword(err.details?.share || null);
      return;
    }
    renderGone(err);
    return;
  }
  if (info?.password_required) {
    renderPassword(info.share || null);
    return;
  }
  const share = info?.share || {};
  if (share.kind === 'request' || dropBox(share)) renderRequest(info);
  else renderLink(info);
}

/**
 * A folder link that accepts uploads but allows neither downloads nor previews (`share create --upload --no-download
 * --no-preview`) works like a file request: visitors can add files, and the server does not list the folder.
 * @param {any} share
 */
function dropBox(share) {
  return share.kind === 'link' && share.allow_upload === true && share.allow_download === false && share.allow_preview === false;
}

/** @param {unknown} err */
function renderGone(err) {
  const status = err instanceof ApiError ? err.status : 0;
  setDocTitle('Not available');
  replace(root, authCard({
    title: status === 429 ? 'Slow down a little' : status >= 500 || status === 0 ? 'Temporarily unavailable' : 'This link is not available',
    icon: status === 429 ? 'clock' : 'link',
    body: alertBox(status === 429 || status >= 500 || status === 0 ? 'warning' : 'info',
      status === 429 ? rateLimitMessage(err, 'requests')
        : status >= 500 || status === 0 ? 'The server could not open this link right now. Please try again in a moment.'
          : 'The link may have expired, reached its download limit, or been turned off by its owner. Ask them for a new one.'),
    footer: status >= 500 || status === 0 || status === 429
      ? [h('button', { class: 'btn btn--secondary btn--sm', attrs: { type: 'button' }, text: 'Try again', on: { click: () => load() } })]
      : undefined,
  }));
}

/** @param {any} share */
function renderPassword(share) {
  setDocTitle(share?.title || 'Password required');
  const pw = field({ label: 'Password', name: 'password', type: 'password', autocomplete: 'off', required: true, autofocus: true });
  const f = form({
    fields: [pw],
    submitLabel: 'Open',
    submitIcon: 'unlock',
    stretchActions: true,
    onSubmit: async (v) => {
      try {
        await api.post(`${base}/api/password`, { password: v.password }, { handle: false });
      } catch (err) {
        pw.input.select();
        if (err instanceof ApiError && err.status === 429) throw new ApiError(429, err.code, rateLimitMessage(err, 'attempts'));
        if (err instanceof ApiError && err.status === 404) {
          renderGone(err);
          return;
        }
        throw new ApiError(401, 'unauthorized', 'That password is not correct.', 'password');
      }
      load();
    },
  });
  replace(root, authCard({
    title: share?.title || 'Password required',
    icon: 'lock',
    subtitle: share?.kind === 'request' ? 'Enter the password you received to send files.' : 'The owner protected these files with a password.',
    body: f.el,
  }));
  pw.input.focus();
}

// ---------------------------------------------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------------------------------------------

/**
 * @param {string} nodeId
 * @param {boolean} [inline]
 */
const dlURL = (nodeId, inline = false) => `${base}/dl/${encodeURIComponent(nodeId)}${inline ? '?inline=1' : ''}`;
/** @param {string} nodeId */
const thumbURL = (nodeId) => `${base}/thumb/${encodeURIComponent(nodeId)}`;

// What the server shows inline — a copy of httpx.ContentType (internal/web/httpx/httpx.go: inlineMedia, textLike);
// keep the two in sync. Only the stored MIME type counts, never the file name: a ?inline=1 request for any other
// type is served as an attachment, so it counts against max_downloads (and is refused on a preview-only link).
const IMAGE = /^image\/(png|jpeg|gif|webp|avif|bmp)$/;
const VIDEO = /^video\/(mp4|webm|ogg|quicktime)$/;
const NEVER_INLINE = /html|xml|javascript|ecmascript|jscript/;
const TEXT_LIKE = new Set([
  'application/json', 'application/x-ndjson', 'application/yaml', 'application/x-yaml', 'application/toml',
  'application/x-toml', 'application/sql', 'application/x-sh', 'application/x-shellscript', 'application/x-csh',
  'application/x-python', 'application/x-perl', 'application/x-ruby', 'application/x-php', 'application/x-httpd-php',
  'application/x-tex', 'application/x-latex', 'application/typescript', 'application/x-subrip', 'application/x-go',
]);
const TEXT_MAX = 256 * 1024;

/**
 * How a node can be previewed inline ('' = not previewable).
 * @param {any} n
 */
function previewKind(n) {
  if (!n || n.kind !== 'file') return '';
  const m = String(n.mime || '').toLowerCase().split(';')[0].trim();
  const [type, sub = ''] = m.split('/');
  if (!type || NEVER_INLINE.test(sub) || sub === 'svg') return '';
  if (IMAGE.test(m)) return 'image';
  if (VIDEO.test(m)) return 'video';
  if (type === 'audio') return 'audio';
  if (m === 'application/pdf') return 'pdf';
  if (type === 'text' || TEXT_LIKE.has(m) || sub.endsWith('+json')) return 'text';
  return '';
}

/**
 * Start a single-use archive download.
 * @param {string[]} ids
 * @param {'zip' | 'tar'} format
 * @param {string} [name]
 */
async function downloadArchive(ids, format, name) {
  try {
    /** @type {Record<string, any>} */
    const body = { node_ids: ids, format };
    if (name) body.name = name;
    const res = await api.post(`${base}/api/archive`, body, { handle: false });
    const url = res?.url || (res?.ticket ? `${base}/zip/${encodeURIComponent(res.ticket)}` : '');
    if (!url) throw new Error('The server did not return a download link.');
    const a = h('a', { href: url, class: 'hidden', attrs: { download: '', 'data-native': true } });
    document.body.appendChild(a);
    a.click();
    a.remove();
    toast.info(format === 'zip' ? 'Preparing your .zip download…' : 'Preparing your .tar download…', { timeout: 4000 });
  } catch (err) {
    if (err instanceof ApiError && err.status === 429) toast.error(rateLimitMessage(err, 'downloads'));
    else if (err instanceof ApiError && err.status === 403) toast.error('Downloading is not allowed for this link, or its download limit was reached.');
    else toast.error(err);
  }
}

/**
 * "Download" split control: zip by default, tar in the menu (for macOS Archive Utility users).
 * @param {string} label
 * @param {() => string[]} ids
 * @param {() => string | undefined} [name]
 * @param {'primary' | 'secondary'} [variant]
 */
function archiveButton(label, ids, name, variant = 'primary') {
  const main = button({ label, icon: 'download', variant, onClick: () => downloadArchive(ids(), 'zip', name?.()) });
  const more = h('button', {
    class: `btn btn--${variant}`,
    attrs: { type: 'button', 'aria-label': 'More download formats', 'aria-haspopup': 'menu', title: 'More formats' },
    on: {
      click: (e) => menu({
        anchor: /** @type {Element} */ (e.currentTarget),
        align: 'end',
        items: [
          { label: 'Download as .zip', icon: 'file-zip', onClick: () => downloadArchive(ids(), 'zip', name?.()) },
          { label: 'Download as .tar (macOS)', icon: 'archive', onClick: () => downloadArchive(ids(), 'tar', name?.()) },
        ],
      }),
    },
  }, icon('chevron-down'));
  return h('div', { class: 'split-btn' }, main, more);
}

/**
 * Expiry text + whether it is close.
 * @param {string | null | undefined} expiresAt
 */
function expiryInfo(expiresAt) {
  if (!expiresAt) return { text: '', soon: false };
  const t = new Date(expiresAt).getTime();
  if (!Number.isFinite(t)) return { text: '', soon: false };
  const left = t - Date.now();
  return { text: `Available until ${dateTime(expiresAt)} (${relTime(expiresAt)})`, soon: left < 48 * 3600_000 };
}

/**
 * Share hero header.
 * @param {{icon: string, title: string, meta: (string | Node | null)[], message?: string, actions?: Node | null, notice?: Node | null}} o
 */
function hero(o) {
  return h('header', { class: 'share-hero card' },
    h('div', { class: 'share-hero-main' },
      h('span', { class: 'share-hero-icon', attrs: { 'aria-hidden': 'true' } }, icon(o.icon, { size: 28 })),
      h('div', { class: 'share-hero-text' },
        h('h1', { id: 'fp-card-title', attrs: { tabindex: '-1' }, text: o.title }),
        h('p', { class: 'share-meta' }, o.meta.filter(Boolean).map((m, i) => (i
          ? h('span', { class: 'share-meta-item' }, h('span', { class: 'share-meta-sep', attrs: { 'aria-hidden': 'true' }, text: '·' }), m)
          : m)))),
      o.actions ? h('div', { class: 'share-hero-actions' }, o.actions) : null),
    o.message ? h('div', { class: 'auth-message', text: o.message }) : null,
    o.notice || null);
}

// ---------------------------------------------------------------------------------------------------------------
// preview overlay
// ---------------------------------------------------------------------------------------------------------------

/**
 * Open the preview dialog for `list[index]`, with previous/next among previewable files.
 * @param {any[]} list previewable nodes
 * @param {number} index
 * @param {any} share
 */
function openPreview(list, index, share) {
  let i = index;
  const stage = h('div', { class: 'share-preview-stage' });
  const counter = h('span', { class: 'muted text-sm tabular' });
  const prevBtn = iconButton({ icon: 'chevron-left', label: 'Previous file', onClick: () => go(-1) });
  const nextBtn = iconButton({ icon: 'chevron-right', label: 'Next file', onClick: () => go(1) });
  const dlSlot = h('span');
  /** @type {AbortController | null} */
  let textCtrl = null;

  const render = () => {
    const n = list[i];
    textCtrl?.abort();
    textCtrl = null;
    d.setTitle(n.name);
    counter.textContent = list.length > 1 ? `${i + 1} / ${list.length}` : '';
    prevBtn.disabled = i === 0;
    nextBtn.disabled = i === list.length - 1;
    prevBtn.hidden = nextBtn.hidden = list.length < 2;
    replace(dlSlot, share.allow_download !== false
      ? h('a', { class: 'btn btn--primary btn--sm', href: dlURL(n.id), attrs: { download: '', 'data-native': true } }, icon('download'), h('span', { text: `Download (${bytes(n.size)})` }))
      : h('span', { class: 'muted text-sm', text: 'Downloading is turned off for this link.' }));
    const kind = previewKind(n);
    const src = dlURL(n.id, true);
    if (kind === 'image') {
      replace(stage, h('img', { class: 'share-preview-media', src, alt: n.name, attrs: { decoding: 'async' } }));
    } else if (kind === 'video') {
      replace(stage, h('video', { class: 'share-preview-media', src, attrs: { controls: true, preload: 'metadata', playsinline: true } }));
    } else if (kind === 'audio') {
      replace(stage, h('div', { class: 'share-preview-audio' }, icon('music', { size: 48 }), h('audio', { src, attrs: { controls: true, preload: 'metadata' } })));
    } else if (kind === 'pdf') {
      replace(stage, 
        h('iframe', { class: 'share-preview-frame', src, title: n.name, attrs: { loading: 'lazy', referrerpolicy: 'no-referrer' } }),
        h('p', { class: 'text-center text-sm' }, h('a', { href: src, attrs: { target: '_blank', rel: 'noopener noreferrer', 'data-native': true }, text: 'Open the PDF in a new tab' })));
    } else if (kind === 'text') {
      const pre = h('pre', { class: 'share-preview-text', attrs: { tabindex: '0' } }, h('code', { text: 'Loading…' }));
      replace(stage, pre);
      const ctrl = new AbortController();
      textCtrl = ctrl;
      fetch(src, { credentials: 'same-origin', cache: 'no-store', headers: { Range: `bytes=0-${TEXT_MAX - 1}` }, signal: ctrl.signal })
        .then(async (res) => {
          if (!res.ok) throw new Error(`Preview failed (${res.status})`);
          const text = await res.text();
          const range = res.headers.get('Content-Range') || '';
          const total = Number(range.split('/')[1] || 0);
          replace(pre, h('code', { text }));
          if ((res.status === 206 && total > TEXT_MAX) || n.size > TEXT_MAX) {
            stage.appendChild(h('p', { class: 'muted text-sm text-center', text: `Showing the first ${bytes(TEXT_MAX)} of ${bytes(n.size)}.` }));
          }
        })
        .catch((err) => {
          if (err?.name === 'AbortError') return;
          replace(stage, emptyState({ icon: 'alert-triangle', title: 'Preview unavailable', text: err instanceof Error ? err.message : String(err) }));
        });
    } else {
      replace(stage, emptyState({ icon: fileIcon(n), title: 'No preview for this file', text: `${n.mime || 'Unknown type'} · ${bytes(n.size)}` }));
    }
  };

  /** @param {number} delta */
  const go = (delta) => {
    const j = i + delta;
    if (j < 0 || j >= list.length) return;
    i = j;
    render();
  };

  const d = dialog({
    title: list[i].name,
    size: 'xl',
    class: 'share-preview',
    body: [stage, h('div', { class: 'share-preview-bar' }, h('div', { class: 'cluster' }, prevBtn, counter, nextBtn), dlSlot)],
    onClose: () => textCtrl?.abort(),
  });
  d.el.addEventListener('keydown', (e) => {
    const t = /** @type {HTMLElement} */ (e.target);
    if (t.closest('video, audio, pre, iframe')) return;
    if (e.key === 'ArrowLeft') { e.preventDefault(); go(-1); }
    if (e.key === 'ArrowRight') { e.preventDefault(); go(1); }
  });
  render();
  d.open();
}

// ---------------------------------------------------------------------------------------------------------------
// link shares
// ---------------------------------------------------------------------------------------------------------------

/**
 * The lock of a password-protected .zip, next to its name (before it in the one-line rows, so no ellipsis hides it).
 * @param {string} label zipProtectionLabel()
 */
function zipLock(label) {
  return h('span', { class: 'share-zip-lock', attrs: { title: label } }, icon('lock', { size: 14, label }));
}

/** @param {any} info */
function renderLink(info) {
  const share = info.share || {};
  const rootNode = info.node || { id: share.node_id, name: share.node_name, kind: share.node_kind };
  const title = share.title || rootNode.name || 'Shared with you';
  setDocTitle(title);
  const exp = expiryInfo(share.expires_at);
  const notice = exp.soon ? alertBox('warning', `This link expires ${relTime(share.expires_at)}. Download what you need before then.`) : null;
  const canDownload = share.allow_download !== false;
  const canPreview = share.allow_preview !== false;

  if (rootNode.kind === 'file') {
    const kind = canPreview ? previewKind(rootNode) : '';
    const locked = zipProtectionLabel(rootNode);
    const actions = canDownload
      ? h('a', { class: 'btn btn--primary', href: dlURL(rootNode.id), attrs: { download: '', 'data-native': true } }, icon('download'), h('span', { text: 'Download' }))
      : null;
    const body = h('section', { class: 'share-single card' },
      h('div', { class: 'share-single-file' },
        h('span', { class: 'share-file-icon', attrs: { 'aria-hidden': 'true' } }, icon(fileIcon(rootNode), { size: 32 })),
        h('div', { class: 'stack-sm' },
          h('strong', { class: 'break' }, locked ? zipLock(locked) : null, rootNode.name),
          h('span', { class: 'muted text-sm', text: [bytes(rootNode.size), rootNode.updated_at ? `updated ${date(rootNode.updated_at)}` : ''].filter(Boolean).join(' · ') })),
        kind ? button({ label: 'Preview', icon: 'eye', variant: 'secondary', onClick: () => openPreview([rootNode], 0, share) }) : null),
      kind === 'image' ? h('button', { class: 'share-single-thumb', attrs: { type: 'button', 'aria-label': `Preview ${rootNode.name}` }, on: { click: () => openPreview([rootNode], 0, share) } },
        h('img', { src: dlURL(rootNode.id, true), alt: '', attrs: { loading: 'lazy', decoding: 'async' } })) : null,
      locked ? alertBox('info', `This .zip is password-protected. Ask ${share.owner_name || 'the sender'} for the password.`) : null,
      !canDownload && !kind ? alertBox('info', 'The owner turned off downloads for this link.') : null);
    replace(root, h('div', { class: 'share-page' },
      hero({
        icon: fileIcon(rootNode),
        title,
        meta: [share.owner_name ? h('span', null, 'Shared by ', h('strong', { text: share.owner_name })) : null, exp.text || null],
        message: share.message,
        actions,
        notice,
      }),
      body));
    return;
  }

  // ---- folder ----
  const canUpload = share.allow_upload === true;
  const rootName = rootNode.name || title;
  /** @type {{id: string, name: string}[]} */
  let trail = [{ id: rootNode.id, name: rootName }];
  /** @type {any[]} */
  let items = itemsOf(info);
  let cursor = info.next_cursor || '';
  let loading = false;
  /** Bumped by every openFolder() call: a reply for an older navigation is dropped. */
  let nav = 0;
  /** @type {Set<string>} */
  const selected = new Set();
  let view = 'list';
  try { view = localStorage.getItem('fp:share-view') === 'grid' ? 'grid' : 'list'; } catch { /* ignore */ }

  const crumbsSlot = h('div', { class: 'share-crumbs' });
  const listSlot = h('div', { class: 'share-list-slot' });
  const moreSlot = h('div', { class: 'share-more' });
  const selBar = h('div', { class: 'share-selbar', hidden: true, attrs: { role: 'region', 'aria-label': 'Selection' } });
  const viewList = iconButton({ icon: 'list', label: 'List view', pressed: view === 'list', onClick: () => setView('list') });
  const viewGrid = iconButton({ icon: 'grid', label: 'Grid view', pressed: view === 'grid', onClick: () => setView('grid') });

  /** @param {string} v */
  const setView = (v) => {
    view = v;
    try { localStorage.setItem('fp:share-view', v); } catch { /* ignore */ }
    viewList.setAttribute('aria-pressed', String(v === 'list'));
    viewGrid.setAttribute('aria-pressed', String(v === 'grid'));
    draw();
  };

  // A folder link that accepts uploads (`share create --upload`): files go to the folder being viewed. The server only
  // takes the shared folder as the batch folder, so a sub-folder is expressed as the path of the entries below it.
  const destLabel = h('p', { class: 'muted text-sm' });
  const upload = canUpload ? uploadArea(share, {
    folderId: share.node_id || rootNode.id,
    link: true,
    dest: () => ({ path: trail.slice(1).map((c) => c.name).join('/'), name: trail[trail.length - 1].name }),
    onDelivered: () => openFolder(trail, false, true),
  }) : null;

  const drawCrumbs = () => {
    destLabel.textContent = `Files you add go to “${trail[trail.length - 1].name}”, the folder shown above.`;
    replace(crumbsSlot, breadcrumbs(trail.map((c, i) => ({ label: c.name, href: i === trail.length - 1 ? undefined : `#${c.id}` }))));
    crumbsSlot.querySelectorAll('a').forEach((a, i) => a.addEventListener('click', (e) => {
      e.preventDefault();
      openFolder(trail.slice(0, i + 1), true);
    }));
  };

  const drawSelection = () => {
    selBar.hidden = selected.size === 0;
    if (!selected.size) {
      replace(selBar);
      return;
    }
    replace(selBar, 
      h('span', { class: 'bold', text: `${plural(selected.size, 'item')} selected` }),
      h('div', { class: 'cluster' },
        archiveButton('Download selected', () => [...selected], undefined, 'primary'),
        button({ label: 'Clear', variant: 'ghost', size: 'sm', onClick: () => { selected.clear(); draw(); } })));
  };

  /** @param {any} n */
  const activate = (n) => {
    if (n.kind === 'folder') {
      openFolder([...trail, { id: n.id, name: n.name }], true);
      return;
    }
    const previewable = canPreview ? items.filter((x) => previewKind(x)) : [];
    const idx = previewable.findIndex((x) => x.id === n.id);
    if (idx >= 0) openPreview(previewable, idx, share);
    else if (canDownload) location.assign(dlURL(n.id));
    else toast.info('This file can’t be previewed and downloads are turned off.');
  };

  /** @param {any} n */
  const checkboxFor = (n) => canDownload
    ? h('label', { class: 'check-hit share-check' }, h('input', {
      attrs: { type: 'checkbox', 'aria-label': `Select ${n.name}` },
      checked: selected.has(n.id),
      on: { change: (e) => { if (/** @type {HTMLInputElement} */ (e.currentTarget).checked) selected.add(n.id); else selected.delete(n.id); drawSelection(); markSelected(); } },
    }))
    : null;

  const markSelected = () => {
    listSlot.querySelectorAll('[data-id]').forEach((el) => {
      const id = /** @type {HTMLElement} */ (el).dataset.id || '';
      el.toggleAttribute('data-selected', selected.has(id));
    });
  };

  /** @param {any} n */
  const thumbOrIcon = (n, size = 20) => {
    const ic = h('span', { class: 'share-item-icon', dataset: { kind: n.kind } }, icon(fileIcon(n), { size }));
    if (!n.has_thumb || !canPreview) return ic;
    const img = h('img', { class: 'share-item-thumb', src: thumbURL(n.id), alt: '', attrs: { loading: 'lazy', decoding: 'async' } });
    img.addEventListener('error', () => img.replaceWith(ic));
    return img;
  };

  /** @param {any} n */
  const row = (n) => {
    const isFolder = n.kind === 'folder';
    return h('li', { class: 'share-row', dataset: { id: n.id, selected: selected.has(n.id) || null } },
      checkboxFor(n),
      h('button', {
        class: 'share-row-main',
        attrs: { type: 'button', title: n.name },
        on: { click: () => activate(n) },
      },
      thumbOrIcon(n),
      h('span', { class: 'share-row-name' }, zipProtectionLabel(n) ? zipLock(zipProtectionLabel(n)) : null, n.name),
      h('span', { class: 'share-row-meta', text: isFolder ? (n.child_count != null ? plural(Number(n.child_count), 'item') : 'Folder') : bytes(n.size) }),
      h('span', { class: 'share-row-meta hide-sm', text: n.updated_at ? relTime(n.updated_at) : '' })),
      !isFolder && canDownload
        ? h('a', { class: 'icon-btn', href: dlURL(n.id), attrs: { download: '', 'data-native': true, 'aria-label': `Download ${n.name}`, title: 'Download' } }, icon('download'))
        : h('span', { class: 'share-row-pad' }));
  };

  /** @param {any} n */
  const tile = (n) => h('li', { class: 'share-tile', dataset: { id: n.id, selected: selected.has(n.id) || null } },
    h('button', { class: 'share-tile-main', attrs: { type: 'button', title: n.name }, on: { click: () => activate(n) } },
      h('span', { class: 'share-tile-visual' }, thumbOrIcon(n, 36)),
      h('span', { class: 'share-tile-name' }, zipProtectionLabel(n) ? zipLock(zipProtectionLabel(n)) : null, n.name),
      h('span', { class: 'share-tile-meta', text: n.kind === 'folder' ? 'Folder' : bytes(n.size) })),
    checkboxFor(n));

  const draw = () => {
    drawSelection();
    if (!items.length) {
      replace(listSlot, emptyState({ icon: 'folder-open', title: 'This folder is empty',
        text: canUpload ? 'Nothing has been added yet. You can add files below.' : 'There is nothing to download here.' }));
    } else if (view === 'grid') {
      replace(listSlot, h('ul', { class: 'share-grid', attrs: { role: 'list', 'aria-label': 'Shared files' } }, items.map(tile)));
    } else {
      replace(listSlot, h('ul', { class: 'share-list', attrs: { role: 'list', 'aria-label': 'Shared files' } }, items.map(row)));
    }
    replace(moreSlot, cursor ? button({ label: 'Load more', icon: 'chevron-down', onClick: () => more() }) : null);
    if (cursor) observer.observe(moreSlot);
  };

  /**
   * @param {{id: string, name: string}[]} nextTrail
   * @param {boolean} push add a history entry
   * @param {boolean} [reload] re-list the folder on screen (after an upload), keeping the focus where it is
   */
  const openFolder = async (nextTrail, push, reload = false) => {
    const my = ++nav;
    const target = nextTrail[nextTrail.length - 1];
    listSlot.setAttribute('aria-busy', 'true');
    try {
      /** @type {any} */
      const res = target.id === rootNode.id && nextTrail.length === 1 && !push && !reload
        ? await api.get(`${base}/api`, { handle: false })
        : await api.get(`${base}/api/list`, { handle: false, query: { node: target.id } });
      if (my !== nav) return; // the visitor went somewhere else meanwhile
      items = itemsOf(res);
      cursor = res?.next_cursor || '';
      trail = [...nextTrail]; // always a new array: a load-more still in flight for the old listing drops its page
      loading = false;
      selected.clear();
      if (push) history.pushState({ fpShareTrail: trail }, '', `#${encodeURIComponent(target.id)}`);
      drawCrumbs();
      draw();
      if (!reload) /** @type {HTMLElement | null} */ (listSlot.querySelector('button'))?.focus({ preventScroll: true });
    } catch (err) {
      if (my !== nav) return;
      if (err instanceof ApiError && err.status === 401) { load(); return; }
      if (err instanceof ApiError && err.status === 404 && trail.length > 1) toast.error('That folder is not available any more.');
      else if (err instanceof ApiError && err.status === 404) renderGone(err);
      else toast.error(err);
    } finally {
      if (my === nav) listSlot.removeAttribute('aria-busy');
    }
  };

  const more = async () => {
    if (loading || !cursor) return;
    const at = trail;
    loading = true;
    try {
      const res = await api.get(`${base}/api/list`, { handle: false, query: { node: at[at.length - 1].id, cursor } });
      if (trail !== at) return; // another folder was opened meanwhile: this page belongs to the old listing
      items = items.concat(itemsOf(res));
      cursor = res?.next_cursor || '';
      draw();
    } catch (err) {
      if (trail === at) toast.error(err);
    } finally {
      if (trail === at) loading = false;
    }
  };

  const observer = new IntersectionObserver((entries) => {
    if (entries.some((e) => e.isIntersecting)) more();
  }, { rootMargin: '400px' });

  window.addEventListener('popstate', (e) => {
    const t = e.state && Array.isArray(e.state.fpShareTrail) ? e.state.fpShareTrail : [{ id: rootNode.id, name: rootNode.name || title }];
    openFolder(t, false);
  });
  if (location.hash) history.replaceState(null, '', location.pathname + location.search);

  const currentName = () => trail[trail.length - 1].name;
  replace(root, h('div', { class: 'share-page' },
    hero({
      icon: 'folder-shared',
      title,
      meta: [share.owner_name ? h('span', null, 'Shared by ', h('strong', { text: share.owner_name })) : null, exp.text || null],
      message: share.message,
      actions: canDownload ? archiveButton('Download all', () => [trail[trail.length - 1].id], currentName) : null,
      notice,
    }),
    h('section', { class: 'share-browser', attrs: { 'aria-labelledby': 'fp-card-title' } },
      h('div', { class: 'share-toolbar' },
        crumbsSlot,
        h('div', { class: 'cluster share-view-toggle', attrs: { role: 'group', 'aria-label': 'View' } }, viewList, viewGrid)),
      selBar,
      listSlot,
      moreSlot,
      !canDownload ? alertBox('info', canPreview ? 'The owner allows previews only — downloads are turned off.' : 'The owner turned off downloads and previews for this link.') : null),
    upload ? h('section', { class: 'card share-request', attrs: { 'aria-labelledby': 'fp-share-add' } },
      h('div', { class: 'stack-sm' }, h('h2', { id: 'fp-share-add', text: 'Add files' }), destLabel),
      upload.nameField ? upload.nameField.el : null,
      upload.drop,
      upload.stageSlot,
      upload.statusSlot) : null));
  drawCrumbs();
  draw();
}

// ---------------------------------------------------------------------------------------------------------------
// uploads: file requests, and folder links that accept uploads
// ---------------------------------------------------------------------------------------------------------------

/** @typedef {import('./share-upload.js').UploadEntry} UploadEntry */

/** True when the browser can pick whole folders (not iOS). */
function folderPickSupported() {
  const i = document.createElement('input');
  return 'webkitdirectory' in i && !/iPad|iPhone|iPod/.test(navigator.userAgent);
}

/**
 * The upload area of a file request, or of a folder link that accepts uploads: the uploader-name field, the drop zone
 * (dropping anywhere on the page adds to it), the staged list, the progress and the result.
 * @param {any} share
 * @param {{folderId: string, link?: boolean, dest?: () => {path: string, name: string}, onDelivered?: () => void}} o
 *   folderId: the shared folder (the only one the server accepts); link: wording for a link; dest: where in the shared
 *   folder the files go (a link: the folder being viewed, its path below the shared folder and its name);
 *   onDelivered: called after a run that delivered something
 */
function uploadArea(share, o) {
  const owner = share.owner_name || '';
  const maxFile = Number(share.upload_max_file_bytes) || 0;
  const nameField = share.require_uploader_name
    ? field({ label: 'Your name', name: 'uploader', autocomplete: 'name', required: true, maxlength: 100,
      help: o.link ? 'So the owner knows who added the files.' : 'So the recipient knows who sent the files.' })
    : null;

  /** @type {UploadEntry[]} */
  let staged = [];
  /** Picked or dropped items left out (OS junk files, names the server would reject) since the list was cleared. */
  let skipped = 0;
  /** @type {ShareUpload | null} */
  let current = null;
  /** @type {any} */
  let wakeLock = null;

  const filePicker = h('input', { class: 'hidden', attrs: { type: 'file', multiple: true, tabindex: '-1', 'aria-hidden': 'true' } });
  const folderPicker = h('input', { class: 'hidden', attrs: { type: 'file', multiple: true, webkitdirectory: true, tabindex: '-1', 'aria-hidden': 'true' } });
  const stageSlot = h('div', { class: 'stack-sm' });
  const statusSlot = h('div', { class: 'stack', attrs: { 'aria-live': 'polite' } });

  // Phones and tablets can neither drag files in nor, on iOS, pick a folder: say only what works there.
  const touchOnly = matchMedia('(hover: none) and (pointer: coarse)').matches;
  const folders = !touchOnly || folderPickSupported();
  const drop = h('div', { class: 'share-drop', attrs: { role: 'group', 'aria-label': 'Add files' } },
    icon('cloud-upload'),
    h('strong', { class: 'share-drop-title', text: touchOnly ? 'Choose the files to send' : 'Drag files or folders here' }),
    h('span', { class: 'muted text-sm', text: `${maxFile ? `Up to ${bytes(maxFile)} per file.` : 'Any size and type.'}${folders ? ' Folders keep their structure.' : ''}` }),
    h('div', { class: 'cluster share-drop-actions' },
      button({ label: 'Choose files', icon: 'file-plus', variant: 'primary', onClick: () => filePicker.click() }),
      folderPickSupported() ? button({ label: 'Choose a folder', icon: 'folder-up', variant: 'secondary', onClick: () => folderPicker.click() }) : null),
    filePicker, folderPicker);

  const guard = (/** @type {BeforeUnloadEvent} */ e) => { e.preventDefault(); };

  /**
   * The same file picked or dropped again collapses into one entry; a different file that only shares its name (from
   * another folder, or another pick) is kept — the server renames it on arrival.
   * @param {UploadEntry} e
   */
  const keyOf = (e) => (e.kind === 'dir' ? `dir:${e.relPath}` : `file:${e.relPath}\u0000${e.size}\u0000${e.file?.lastModified ?? 0}`);

  /** @param {import('./share-upload.js').Picked} picked */
  const addEntries = (picked) => {
    if (current) return;
    const seen = new Set(staged.map(keyOf));
    for (const e of picked.entries) {
      const k = keyOf(e);
      if (!seen.has(k)) {
        staged.push(e);
        seen.add(k);
      }
    }
    skipped += picked.skipped.length;
    if (!picked.entries.length && picked.skipped.length) toast.warning('Nothing to send: system files and names that aren’t allowed are left out.');
    drawStaged();
  };

  const tooBig = (/** @type {UploadEntry} */ e) => maxFile > 0 && e.kind === 'file' && e.size > maxFile;

  const drawStaged = () => {
    replace(statusSlot);
    if (!staged.length) {
      replace(stageSlot);
      return;
    }
    const files = staged.filter((e) => e.kind === 'file');
    const total = files.reduce((n, e) => n + e.size, 0);
    const bad = staged.filter(tooBig);
    const shown = staged.slice(0, 200);
    replace(stageSlot,
      h('div', { class: 'split' },
        h('strong', { text: `${plural(files.length, 'file')} · ${bytes(total)}` }),
        button({ label: 'Clear', variant: 'ghost', size: 'sm', icon: 'x', onClick: () => { staged = []; skipped = 0; drawStaged(); } })),
      h('ul', { class: 'share-upload-list', attrs: { role: 'list' } },
        shown.map((e) => h('li', { class: 'share-upload-item', dataset: { state: tooBig(e) ? 'failed' : null } },
          icon(e.kind === 'dir' ? 'folder' : fileIcon({ kind: 'file', name: e.relPath, mime: e.file?.type }), { size: 18 }),
          h('span', { class: 'share-upload-name', title: e.relPath, text: e.relPath }),
          h('span', { class: 'share-upload-meta', text: e.kind === 'dir' ? 'empty folder' : tooBig(e) ? `too large (${bytes(e.size)})` : bytes(e.size) }),
          iconButton({ icon: 'x', label: `Remove ${e.relPath}`, size: 'sm', onClick: () => { staged = staged.filter((x) => x !== e); drawStaged(); } }))),
        staged.length > shown.length ? h('li', { class: 'muted text-sm', text: `…and ${staged.length - shown.length} more` }) : null),
      bad.length ? alertBox('warning', `${plural(bad.length, 'file is', 'files are')} larger than the ${bytes(maxFile)} limit and will be left out.`) : null,
      skipped ? alertBox('warning', `${plural(skipped, 'item')} can’t be sent (system files or names that aren’t allowed) and ${skipped === 1 ? 'was' : 'were'} left out.`) : null,
      h('div', { class: 'btn-row' },
        button({ label: files.length - bad.length > 0 ? `Send ${plural(files.length - bad.length, 'file')}` : 'Send', icon: 'send', variant: 'primary', disabled: files.length - bad.length <= 0 && !staged.some((e) => e.kind === 'dir'), onClick: () => send() })));
  };

  const send = async () => {
    if (current) return;
    const uploader = nameField ? String(nameField.value()).trim() : '';
    if (nameField && !uploader) {
      nameField.setError('Please tell the recipient who you are.');
      nameField.input.focus();
      return;
    }
    const entries = staged.filter((e) => !tooBig(e));
    if (!entries.length) return;
    const dest = o.dest ? o.dest() : null;
    skipped = 0;
    drop.hidden = true;
    replace(stageSlot);
    if (nameField) nameField.input.disabled = true;

    const overall = progress({ value: 0, max: 1, label: 'Preparing…', showValue: true });
    const stats = h('p', { class: 'muted text-sm tabular' });
    const rows = new Map();
    const list = h('ul', { class: 'share-upload-list', attrs: { role: 'list' } },
      entries.filter((e) => e.kind === 'file').slice(0, 200).map((e) => {
        const bar = progress({ value: 0, max: Math.max(1, e.size), size: 'sm', label: e.relPath });
        const meta = h('span', { class: 'share-upload-meta', text: 'Waiting' });
        const li = h('li', { class: 'share-upload-item share-upload-item--progress' },
          icon(fileIcon({ kind: 'file', name: e.relPath, mime: e.file?.type }), { size: 18 }),
          h('span', { class: 'share-upload-name', title: e.relPath, text: e.relPath }),
          meta, bar.el);
        rows.set(e, { li, bar, meta });
        return li;
      }));
    const cancelBtn = button({ label: 'Cancel', variant: 'ghost', icon: 'x', onClick: () => current?.cancel() });
    replace(statusSlot, h('div', { class: 'stack' }, h('div', { class: 'split' }, h('strong', { text: 'Uploading…' }), cancelBtn), overall.el, stats, list));

    window.addEventListener('beforeunload', guard);
    try { wakeLock = await /** @type {any} */ (navigator).wakeLock?.request('screen'); } catch { /* optional */ }

    const up = new ShareUpload({
      apiBase: `${base}/api`,
      folderId: o.folderId,
      subPath: dest?.path || '',
      uploader,
      onUpdate: (s) => {
        overall.set(s.sent, Math.max(1, s.total), `${s.files} of ${plural(s.fileCount, 'file')} · ${bytes(s.sent)} of ${bytes(s.total)}`);
        stats.textContent = s.bytesPerSecond > 0
          ? `${speed(s.bytesPerSecond)}${s.etaSeconds >= 0 ? ` · about ${duration(s.etaSeconds * 1000)} left` : ''}`
          : '';
        for (const p of s.entries) {
          const r = rows.get(p.entry);
          if (!r) continue;
          r.bar.set(p.sent, Math.max(1, p.entry.size));
          r.li.dataset.state = p.state;
          r.meta.textContent = p.state === 'done' ? 'Delivered'
            : p.state === 'failed' ? (p.error || 'Failed')
              : p.state === 'skipped' ? 'Skipped'
                : p.state === 'hashing' ? 'Preparing…'
                  : p.state === 'uploading' ? `${bytes(p.sent)} of ${bytes(p.entry.size)}` : 'Waiting';
        }
      },
    });
    current = up;
    /** @type {import('./share-upload.js').UploadSnapshot | null} */
    let result = null;
    /** @type {unknown} */
    let failure = null;
    try {
      result = await up.run(entries);
    } catch (err) {
      failure = err;
    } finally {
      current = null;
      window.removeEventListener('beforeunload', guard);
      try { await wakeLock?.release(); } catch { /* ignore */ }
      wakeLock = null;
      if (nameField) nameField.input.disabled = false;
    }

    // what arrived, also when the run failed or was cancelled part-way
    const settled = up.progress.filter((p) => p.state === 'done' || p.state === 'skipped');
    const delivered = settled.filter((p) => p.entry.kind === 'file').length;
    if (settled.length) o.onDelivered?.();

    if (failure) {
      const aborted = failure instanceof ApiError && failure.aborted;
      // Delivered files stay delivered: only the rest goes back on the list, so sending again does not store them
      // a second time ("name (1)").
      const sent = new Set(settled.map((p) => p.entry));
      staged = staged.filter((e) => !sent.has(e));
      drop.hidden = false;
      replace(statusSlot, alertBox(aborted ? 'info' : 'danger', aborted
        ? 'Upload cancelled. Files that finished before you cancelled were delivered.'
        : `${errorMessage(failure)}${delivered ? ` ${plural(delivered, 'file was', 'files were')} delivered before that.` : ''}`));
      drawStagedKeepStatus();
      return;
    }
    const failed = (result?.entries || []).filter((p) => p.state === 'failed');
    staged = failed.map((p) => p.entry);
    showThanks(delivered, failed, dest);
  };

  /** Re-draw the staged list without clearing the status message. */
  const drawStagedKeepStatus = () => {
    const keep = [...statusSlot.childNodes];
    drawStaged();
    replace(statusSlot, ...keep);
  };

  /**
   * @param {number} delivered
   * @param {import('./share-upload.js').EntryProgress[]} failed
   * @param {{path: string, name: string} | null} dest
   */
  const showThanks = (delivered, failed, dest) => {
    drop.hidden = true;
    replace(stageSlot);
    const where = o.link ? (dest?.name ? ` to “${dest.name}”` : '') : (owner ? ` to ${owner}` : '');
    replace(statusSlot, h('div', { class: 'share-thanks' },
      h('span', { class: 'share-thanks-icon', attrs: { 'aria-hidden': 'true' } }, icon(failed.length ? 'alert-triangle' : 'check-circle', { size: 40 })),
      h('h2', { attrs: { tabindex: '-1' }, text: failed.length ? 'Some files could not be sent' : o.link ? 'Files added' : 'Thank you!' }),
      h('p', { class: 'muted', text: delivered
        ? `${plural(delivered, 'file was', 'files were')} ${o.link ? 'added' : 'delivered'}${where}. ${failed.length || o.link ? '' : 'You can close this page.'}`
        : 'No files were delivered.' }),
      failed.length ? h('ul', { class: 'share-upload-list', attrs: { role: 'list' } }, failed.slice(0, 50).map((p) => h('li', { class: 'share-upload-item', dataset: { state: 'failed' } },
        icon('alert-circle', { size: 18 }), h('span', { class: 'share-upload-name', text: p.entry.relPath }), h('span', { class: 'share-upload-meta', text: p.error || 'Failed' })))) : null,
      h('div', { class: 'cluster' },
        failed.length ? button({ label: 'Retry failed files', icon: 'refresh', variant: 'primary', onClick: () => send() }) : null,
        button({ label: o.link ? 'Add more files' : 'Send more files', icon: 'plus', variant: failed.length ? 'secondary' : 'primary', onClick: () => { if (!failed.length) staged = []; drop.hidden = false; drawStaged(); } }))));
    /** @type {HTMLElement | null} */ (statusSlot.querySelector('h2'))?.focus({ preventScroll: false });
  };

  filePicker.addEventListener('change', () => {
    const files = Array.from(filePicker.files || []);
    filePicker.value = '';
    addEntries(entriesFromFiles(files));
  });
  folderPicker.addEventListener('change', () => {
    const files = Array.from(folderPicker.files || []);
    folderPicker.value = '';
    addEntries(entriesFromFiles(files));
  });
  // Page-wide drop target. The listeners outlive a re-render (load() after a password, a share that stopped
  // working): a drop zone no longer in the page ignores everything.
  let depth = 0;
  const hasFiles = (/** @type {DragEvent} */ e) => drop.isConnected && Array.from(e.dataTransfer?.types || []).includes('Files');
  document.addEventListener('dragenter', (e) => {
    if (!hasFiles(e) || current || drop.hidden) return;
    depth += 1;
    drop.dataset.over = '';
  });
  document.addEventListener('dragleave', () => {
    depth = Math.max(0, depth - 1);
    if (!depth) delete drop.dataset.over;
  });
  document.addEventListener('dragover', (e) => {
    if (!hasFiles(e)) return;
    e.preventDefault();
    if (e.dataTransfer) e.dataTransfer.dropEffect = current || drop.hidden ? 'none' : 'copy';
  });
  document.addEventListener('drop', async (e) => {
    if (!hasFiles(e)) return;
    e.preventDefault();
    depth = 0;
    delete drop.dataset.over;
    if (current || drop.hidden || !e.dataTransfer) return;
    try {
      addEntries(await entriesFromDataTransfer(e.dataTransfer));
    } catch (err) {
      toast.error(`Could not read the dropped items: ${errorMessage(err)}`);
    }
  });

  return { nameField, drop, stageSlot, statusSlot };
}

/**
 * A file request, or a folder link that accepts uploads but shows nothing (see dropBox).
 * @param {any} info
 */
function renderRequest(info) {
  const share = info.share || {};
  const isRequest = share.kind === 'request';
  const owner = share.owner_name || '';
  const title = share.title || (owner ? `Send files to ${owner}` : 'Send files');
  setDocTitle(title);
  const maxFile = Number(share.upload_max_file_bytes) || 0;
  const exp = expiryInfo(share.expires_at);
  const area = uploadArea(share, { folderId: share.node_id || info.node?.id || '' });

  const limits = [
    maxFile ? h('li', null, icon('file', { size: 16 }), `Up to ${bytes(maxFile)} per file`) : null,
    exp.text ? h('li', null, icon('clock', { size: 16 }), exp.text) : null,
    h('li', null, icon('lock', { size: 16 }), 'Encrypted when stored. Only the recipient can see what you send.'),
  ];

  replace(root, h('div', { class: 'share-page share-page--request' },
    hero({
      icon: 'inbox',
      title,
      meta: [owner ? h('span', null, isRequest ? 'Requested by ' : 'Shared by ', h('strong', { text: owner })) : null],
      message: share.message,
      notice: exp.soon ? alertBox('warning', `This ${isRequest ? 'request closes' : 'link expires'} ${relTime(share.expires_at)}.`) : null,
    }),
    h('section', { class: 'card share-request', attrs: { 'aria-label': 'Send files' } },
      area.nameField ? area.nameField.el : null,
      area.drop,
      area.stageSlot,
      area.statusSlot,
      h('ul', { class: 'share-limits', attrs: { role: 'list' } }, limits))));
}
