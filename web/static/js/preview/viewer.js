// @ts-check
/**
 * Preview overlay (§13.5): a full-screen modal <dialog> showing one file at a time with previous/next navigation.
 *
 *   openPreview({items: files, index, onShare, onChanged}) → {close()}
 *
 * Renderers: image (zoom/pan/pinch) · video/audio (native controls, Range seeking) · PDF (iframe) · text/code (≤ 2 MiB,
 * line numbers) · anything else → a details card with a download button.
 * Keyboard (unmodified keys only — Ctrl/⌘/Alt combinations are left to the browser): ←/→ previous/next (they scroll
 * a focused text preview instead) · Esc close · +/−/0/1 zoom (images) · i info panel · d download.
 * Touch: swipe left/right to change file (not while zoomed), swipe down to close.
 * The Back button closes the preview (core/router.js pushOverlay; the URL carries ?preview=<id> so it can be shared
 * or reloaded).
 * @module preview/viewer
 */
import { h, icon, trapFocus, announce } from '../core/dom.js';
import { pushOverlay } from '../core/router.js';
import { claimToasts, releaseToasts } from '../components/toast.js';
import { bytes, dateTime, relTime, fileIcon } from '../core/format.js';
import { contentURL, previewKind, opensInline, typeLabel, triggerDownload, can } from '../core/nodes.js';
import { imageRenderer } from './image.js';
import { videoRenderer, audioRenderer, pdfRenderer } from './media.js';
import { textRenderer } from './text.js';

/**
 * @typedef {import('../core/nodes.js').Node} Node
 * @typedef {import('./image.js').Renderer} Renderer
 */

/**
 * @typedef {Object} PreviewOpts
 * @property {Node[]} items files to page through (folders are skipped)
 * @property {number} [index] start index into `items`
 * @property {string} [startId] alternatively the id of the first file
 * @property {(node: Node) => void} [onShare] shows a Share button when given (and the user may manage the file)
 * @property {(node: Node) => void} [onDetails] shows a Details button when given
 * @property {(node: Node) => void} [onClose] called with the last shown file
 * @property {boolean} [history] push a history entry (?preview=<id>) so Back closes the viewer (default true)
 */

/** @type {{close: () => void} | null} */
let openViewer = null;

/**
 * @param {PreviewOpts} opts
 */
export function openPreview(opts) {
  openViewer?.close();
  const files = opts.items.filter((n) => n && n.kind === 'file');
  if (!files.length) return { close() {} };
  const found = opts.startId ? files.findIndex((n) => n.id === opts.startId) : -1;
  // A start file that is not among `items` must not silently become the first file (Share/Download would then act
  // on something else): the caller passes the file itself in that case (components/file-actions.js preview).
  if (opts.startId && found < 0) return { close() {} };
  let index = opts.startId ? found : Math.max(0, Math.min(files.length - 1, opts.index ?? 0));
  if (opts.index !== undefined && !opts.startId && opts.items[opts.index]) {
    const i = files.indexOf(opts.items[opts.index]);
    if (i >= 0) index = i;
  }
  /** @type {Renderer | null} */
  let renderer = null;
  let closed = false;
  const returnFocus = document.activeElement;

  const titleEl = h('h2', { class: 'pv-title', id: 'pv-title' });
  const counter = h('span', { class: 'pv-counter tabular', attrs: { 'aria-live': 'polite' } });
  const tools = h('div', { class: 'pv-tools' });
  const stage = h('div', { class: 'pv-stage' });
  const info = h('aside', { class: 'pv-info', hidden: true, attrs: { 'aria-label': 'File information' } });

  /** @param {string} ic @param {string} label @param {() => void} onClick @param {string} [cls] */
  const tool = (ic, label, onClick, cls = '') => h('button', {
    class: `icon-btn pv-tool ${cls}`,
    attrs: { type: 'button', 'aria-label': label, title: label },
    on: { click: onClick },
  }, icon(ic));

  const prevBtn = h('button', { class: 'pv-nav pv-nav--prev', attrs: { type: 'button', 'aria-label': 'Previous file', title: 'Previous (←)' }, on: { click: () => go(-1) } }, icon('chevron-left', { size: 28 }));
  const nextBtn = h('button', { class: 'pv-nav pv-nav--next', attrs: { type: 'button', 'aria-label': 'Next file', title: 'Next (→)' }, on: { click: () => go(1) } }, icon('chevron-right', { size: 28 }));
  const infoBtn = tool('info', 'File information (i)', () => toggleInfo(), 'pv-info-btn');
  infoBtn.setAttribute('aria-pressed', 'false');
  const downloadBtn = tool('download', 'Download (d)', () => triggerDownload(contentURL(files[index]), files[index].name));
  // .pv-tab-btn is the hook preview.css uses to drop this one tool on phones (Share and Download stay).
  const openTabBtn = tool('external', 'Open in new tab', () => window.open(contentURL(files[index], { inline: true }), '_blank', 'noopener'), 'pv-tab-btn');
  const shareBtn = opts.onShare ? tool('share', 'Share', () => opts.onShare?.(files[index])) : null;
  const closeBtn = tool('x', 'Close (Esc)', () => close(), 'pv-close');

  const el = h('dialog', { class: 'pv', attrs: { 'aria-labelledby': 'pv-title', 'aria-modal': 'true' } },
    h('header', { class: 'pv-top' },
      closeBtn,
      h('div', { class: 'pv-heading' }, titleEl, counter),
      tools,
      h('div', { class: 'pv-actions' }, shareBtn, openTabBtn, downloadBtn, infoBtn)),
    h('div', { class: 'pv-body' }, stage, info, prevBtn, nextBtn));

  const untrap = trapFocus(el);

  /** @param {string} msg */
  const fallbackCard = (msg) => {
    const n = files[index];
    return h('div', { class: 'pv-fallback' },
      h('div', { class: 'pv-fallback-icon', dataset: { kind: fileIcon(n) } }, icon(fileIcon(n), { size: 48 })),
      h('div', { class: 'pv-fallback-name', text: n.name }),
      h('div', { class: 'pv-fallback-meta', text: `${typeLabel(n)} · ${bytes(n.size)} · Modified ${relTime(n.updated_at)}` }),
      h('p', { class: 'pv-fallback-text', text: msg }),
      h('div', { class: 'cluster pv-fallback-actions' },
        h('button', { class: 'btn btn--primary', attrs: { type: 'button' }, on: { click: () => triggerDownload(contentURL(n), n.name) } }, icon('download'), h('span', { text: 'Download' })),
        previewKind(n) === 'pdf'
          ? h('a', { class: 'btn btn--secondary', href: contentURL(n, { inline: true }), attrs: { target: '_blank', rel: 'noopener', 'data-native': true } }, icon('external'), h('span', { text: 'Open' }))
          : null));
  };

  /** @param {{zoomIn: () => void, zoomOut: () => void, reset: () => void, actual: () => void}} c */
  const zoomControls = (c) => h('div', { class: 'pv-zoom', attrs: { role: 'group', 'aria-label': 'Zoom' } },
    tool('zoom-out', 'Zoom out (−)', c.zoomOut),
    tool('zoom-in', 'Zoom in (+)', c.zoomIn),
    h('button', { class: 'btn btn--ghost btn--sm pv-fit', attrs: { type: 'button', title: 'Fit to screen (0)' }, text: 'Fit', on: { click: c.reset } }));

  const show = () => {
    const n = files[index];
    renderer?.destroy();
    renderer = null;
    titleEl.textContent = n.name;
    titleEl.title = n.name;
    counter.textContent = files.length > 1 ? `${index + 1} / ${files.length}` : '';
    prevBtn.hidden = files.length < 2;
    nextBtn.hidden = files.length < 2;
    prevBtn.disabled = index === 0;
    nextBtn.disabled = index === files.length - 1;
    const kind = previewKind(n);
    openTabBtn.hidden = !kind || !opensInline(n); // HTML/SVG/XML/JS are previewed as text but never served inline
    if (shareBtn) shareBtn.hidden = !can(n, 'manage');
    const ctx = {
      onError: (/** @type {string} */ msg) => {
        if (files[index] !== n) return;
        renderer?.destroy();
        renderer = { el: fallbackCard(msg), destroy() {} };
        stage.replaceChildren(renderer.el);
        tools.replaceChildren();
      },
      fallback: fallbackCard,
      zoomControls,
    };
    switch (kind) {
      case 'image': renderer = imageRenderer(n, ctx); break;
      case 'video': renderer = videoRenderer(n, ctx); break;
      case 'audio': renderer = audioRenderer(n, ctx); break;
      case 'pdf': renderer = pdfRenderer(n, ctx); break;
      case 'text': renderer = textRenderer(n, ctx); break;
      default: renderer = { el: fallbackCard('There is no preview for this type of file.'), destroy() {} };
    }
    stage.dataset.kind = kind || 'none';
    stage.replaceChildren(renderer.el);
    tools.replaceChildren(...(renderer.toolbar ? [renderer.toolbar] : []));
    if (!info.hidden) renderInfo();
    overlay?.replaceURL(urlFor(n));
    preloadNeighbours();
  };

  const renderInfo = () => {
    const n = files[index];
    /** @param {string} k @param {string} v */
    const row = (k, v) => [h('dt', { text: k }), h('dd', { text: v })];
    info.replaceChildren(
      h('h3', { class: 'pv-info-title', text: 'Details' }),
      h('dl', { class: 'kv pv-kv' },
        row('Name', n.name),
        row('Type', typeLabel(n)),
        row('Size', `${bytes(n.size)}${n.size >= 1024 ? ` (${n.size.toLocaleString()} bytes)` : ''}`),
        row('Modified', dateTime(n.updated_at)),
        row('Created', dateTime(n.created_at)),
        n.client_mtime ? row('Original date', dateTime(n.client_mtime)) : null,
        n.path ? row('Location', n.path) : null),
      opts.onDetails ? h('button', { class: 'btn btn--secondary btn--sm', attrs: { type: 'button' }, on: { click: () => { const f = files[index]; close(); opts.onDetails?.(f); } } }, icon('info'), h('span', { text: 'More details' })) : null);
  };

  const toggleInfo = () => {
    info.hidden = !info.hidden;
    infoBtn.setAttribute('aria-pressed', String(!info.hidden));
    if (!info.hidden) renderInfo();
  };

  /** Warm the cache for the next/previous image. */
  const preloadNeighbours = () => {
    for (const j of [index + 1, index - 1]) {
      const n = files[j];
      if (n && previewKind(n) === 'image' && n.size < 25 * 1024 * 1024) {
        const img = new Image();
        img.decoding = 'async';
        img.src = contentURL(n, { inline: true });
      }
    }
  };

  /** @param {number} d */
  const go = (d) => {
    const j = index + d;
    if (j < 0 || j >= files.length) return;
    index = j;
    show();
    announce(`${files[index].name}, ${index + 1} of ${files.length}`);
  };

  // ---- keyboard
  el.addEventListener('keydown', (e) => {
    if (e.defaultPrevented) return;
    // Browser/OS shortcuts (Ctrl/⌘ +/−/0 page zoom, tab switching…) pass through — renderers included. Not Shift:
    // "+" and "_" need it on many layouts.
    if (e.ctrlKey || e.metaKey || e.altKey) return;
    if (renderer?.onKey && renderer.onKey(e)) {
      if (e.target !== el.querySelector('video, audio')) e.preventDefault();
      return;
    }
    const inField = e.target instanceof HTMLElement && /^(INPUT|TEXTAREA|SELECT)$/.test(e.target.tagName);
    if (inField) return;
    // A focused text/code preview scrolls its long lines with ←/→ (like the touch swipe exemption below).
    if ((e.key === 'ArrowLeft' || e.key === 'ArrowRight') && e.target instanceof Element && e.target.closest('.pv-text-scroll')) return;
    if (e.key === 'ArrowLeft') { e.preventDefault(); go(-1); }
    else if (e.key === 'ArrowRight') { e.preventDefault(); go(1); }
    else if (e.key === 'i') { e.preventDefault(); toggleInfo(); }
    else if (e.key === 'd') { e.preventDefault(); downloadBtn.click(); }
  });
  el.addEventListener('cancel', (e) => {
    e.preventDefault();
    close();
  });

  // ---- touch swipes: horizontal → prev/next, down → close
  let sx = 0;
  let sy = 0;
  let st = 0;
  let tracking = false;
  stage.addEventListener('touchstart', (e) => {
    tracking = e.touches.length === 1 && !(renderer?.busy && renderer.busy());
    if (!tracking) return;
    sx = e.touches[0].clientX;
    sy = e.touches[0].clientY;
    st = Date.now();
  }, { passive: true });
  stage.addEventListener('touchend', (e) => {
    if (!tracking || (renderer?.busy && renderer.busy())) return;
    tracking = false;
    const t = e.changedTouches[0];
    const dx = t.clientX - sx;
    const dy = t.clientY - sy;
    if (Date.now() - st > 800) return;
    const target = /** @type {Element} */ (e.target);
    if (target.closest('.pv-text-scroll, video, audio, iframe')) return; // those scroll/seek themselves
    if (Math.abs(dx) > 60 && Math.abs(dx) > Math.abs(dy) * 1.5) go(dx < 0 ? 1 : -1);
    else if (dy > 90 && Math.abs(dy) > Math.abs(dx) * 1.5) close();
  }, { passive: true });

  /** @param {Node} n */
  const urlFor = (n) => {
    const u = new URL(location.href);
    u.searchParams.set('preview', n.id);
    return u.pathname + u.search;
  };

  function close() {
    if (closed) return;
    closed = true;
    const last = files[index];
    renderer?.destroy();
    renderer = null;
    untrap();
    if (el.open) el.close();
    releaseToasts(el); // hand visible toasts back before this modal is removed with them inside
    el.remove();
    document.documentElement.classList.remove('pv-open');
    overlay?.done();
    if (openViewer === handle) openViewer = null;
    if (returnFocus instanceof HTMLElement && returnFocus.isConnected) returnFocus.focus({ preventScroll: true });
    opts.onClose?.(last);
  }

  document.body.appendChild(el);
  el.showModal();
  document.documentElement.classList.add('pv-open');
  const overlay = opts.history === false ? null : pushOverlay(() => close(), { url: urlFor(files[index]) });
  show();
  closeBtn.focus();
  claimToasts(); // after showModal()/focus(): a toast raised just before the preview must not end up behind it
  const handle = { close };
  openViewer = handle;
  return handle;
}
