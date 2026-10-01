// @ts-check
/**
 * Video / audio / PDF previewers. Media elements stream GET /nodes/{id}/content?inline=1, which supports Range
 * requests (http.ServeContent over the encrypted blob, §8.2), so seeking works without downloading the file.
 * PDFs load in an <iframe> (the content response keeps `frame-ancestors 'self'` for application/pdf); browsers
 * without a built-in PDF viewer (most phones) get an "Open" / "Download" card instead.
 * @module preview/media
 */
import { h, icon } from '../core/dom.js';
import { contentURL } from '../core/nodes.js';
import { bytes } from '../core/format.js';

/**
 * @typedef {import('./image.js').Renderer} Renderer
 * @typedef {import('../core/nodes.js').Node} Node
 */

/**
 * @param {Node} node
 * @param {{onError: (msg: string) => void}} ctx
 * @returns {Renderer}
 */
export function videoRenderer(node, ctx) {
  const video = h('video', {
    class: 'pv-video',
    src: contentURL(node, { inline: true }),
    attrs: { controls: true, playsinline: true, preload: 'metadata', 'aria-label': node.name },
  });
  video.addEventListener('error', () => ctx.onError('This video can’t be played in your browser. Download it to watch it with another app.'));
  const el = h('div', { class: 'pv-media' }, video);
  return {
    el,
    // arrow keys seek while the player has focus; the viewer then leaves them alone
    onKey: (e) => (e.target === video && (e.key === 'ArrowLeft' || e.key === 'ArrowRight' || e.key === ' ')),
    destroy() {
      video.pause();
      video.removeAttribute('src');
      video.load();
    },
  };
}

/**
 * @param {Node} node
 * @param {{onError: (msg: string) => void}} ctx
 * @returns {Renderer}
 */
export function audioRenderer(node, ctx) {
  const audio = h('audio', {
    class: 'pv-audio',
    src: contentURL(node, { inline: true }),
    attrs: { controls: true, preload: 'metadata', 'aria-label': node.name },
  });
  audio.addEventListener('error', () => ctx.onError('This audio file can’t be played in your browser.'));
  const el = h('div', { class: 'pv-media pv-media--audio' },
    h('div', { class: 'pv-audio-card' },
      h('div', { class: 'pv-audio-art', attrs: { 'aria-hidden': 'true' } }, icon('music', { size: 56 })),
      h('div', { class: 'pv-audio-name', text: node.name }),
      h('div', { class: 'pv-audio-meta', text: bytes(node.size) }),
      audio));
  return {
    el,
    onKey: (e) => (e.target === audio && (e.key === 'ArrowLeft' || e.key === 'ArrowRight' || e.key === ' ')),
    destroy() {
      audio.pause();
      audio.removeAttribute('src');
      audio.load();
    },
  };
}

/** @returns {boolean} whether the browser shows PDFs inline */
export function pdfViewerAvailable() {
  const nav = /** @type {any} */ (navigator);
  if (typeof nav.pdfViewerEnabled === 'boolean') return nav.pdfViewerEnabled;
  return !/Android|iPhone|iPad|iPod/i.test(navigator.userAgent);
}

/**
 * @param {Node} node
 * @param {{fallback: (msg: string) => HTMLElement}} ctx
 * @returns {Renderer}
 */
export function pdfRenderer(node, ctx) {
  if (!pdfViewerAvailable()) {
    return { el: ctx.fallback('Your browser can’t show PDFs inside the page. Open it in a new tab or download it.'), destroy() {} };
  }
  const frame = h('iframe', {
    class: 'pv-pdf',
    src: contentURL(node, { inline: true }),
    title: node.name,
    attrs: { referrerpolicy: 'no-referrer' },
  });
  return {
    el: h('div', { class: 'pv-doc' }, frame),
    destroy() {
      frame.removeAttribute('src');
    },
  };
}
