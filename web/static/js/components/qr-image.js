// @ts-check
/**
 * qrImage({src, alt}) → HTMLImageElement
 * QR codes are rendered server-side as SVG (§13.1): pass `src` as "/api/v1/qr.svg?data=…" (see qrURL()) or a data: URI
 * from an API response. The image sits on a white tile so it scans in dark mode.
 * @module components/qr-image
 */
import { h } from '../core/dom.js';

/**
 * URL of the server QR renderer for `data` (≤ 512 chars).
 * @param {string} data
 */
export function qrURL(data) {
  return `/api/v1/qr.svg?data=${encodeURIComponent(data)}`;
}

/**
 * @param {{src: string, alt: string, size?: number}} opts
 * @returns {HTMLImageElement}
 */
export function qrImage(opts) {
  const src = /^(data:image\/(svg\+xml|png)[;,]|\/)/.test(opts.src) ? opts.src : '';
  const img = h('img', { class: 'qr', src, alt: opts.alt, attrs: { width: opts.size || 240, height: opts.size || 240, decoding: 'async', loading: 'lazy' } });
  if (opts.size) img.style.setProperty('width', `${opts.size}px`);
  return img;
}
