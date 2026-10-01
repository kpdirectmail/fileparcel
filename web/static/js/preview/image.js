// @ts-check
/**
 * Image previewer: fit-to-screen, zoom (buttons, +/-/0 keys, wheel/trackpad pinch around the cursor, double-click /
 * double-tap), pan by dragging when zoomed, two-finger pinch-zoom on touch. The image is served inline
 * (GET /nodes/{id}/content?inline=1; §8.2 allow-list: png, jpeg, gif, webp, avif, bmp).
 * Transforms are applied through CSSOM (el.style.setProperty) — never style attributes (CSP).
 * @module preview/image
 */
import { h } from '../core/dom.js';
import { contentURL } from '../core/nodes.js';

const MIN = 1;
const MAX = 8;

/**
 * @typedef {Object} Renderer
 * @property {HTMLElement} el
 * @property {() => void} destroy
 * @property {() => boolean} [busy] true while a gesture should not navigate (zoomed image, pinch in progress)
 * @property {(e: KeyboardEvent) => boolean} [onKey] return true when handled (the viewer never passes Ctrl/⌘/Alt
 *   combinations, so page zoom keeps working)
 * @property {HTMLElement} [toolbar] extra header controls
 */

/**
 * @param {import('../core/nodes.js').Node} node
 * @param {{onError: (msg: string) => void, zoomControls: (ctl: {zoomIn: () => void, zoomOut: () => void, reset: () => void, actual: () => void}) => HTMLElement}} ctx
 * @returns {Renderer}
 */
export function imageRenderer(node, ctx) {
  const img = h('img', {
    class: 'pv-img',
    alt: node.name,
    src: contentURL(node, { inline: true }),
    attrs: { draggable: 'false', decoding: 'async' },
  });
  const stage = h('div', { class: 'pv-img-stage', dataset: { loading: '' } }, img);
  let scale = 1;
  let tx = 0;
  let ty = 0;
  let fitW = 0;
  let fitH = 0;
  let natW = 0;
  let natH = 0;

  const apply = () => {
    clampPan();
    img.style.setProperty('transform', `translate(${tx}px, ${ty}px) scale(${scale})`);
    stage.toggleAttribute('data-zoomed', scale > 1.001);
  };

  /** The stage's content box (the image is centred inside the padding). */
  const box = () => {
    const cs = getComputedStyle(stage);
    const px = (/** @type {string} */ v) => parseFloat(v) || 0;
    return {
      w: stage.clientWidth - px(cs.paddingLeft) - px(cs.paddingRight),
      h: stage.clientHeight - px(cs.paddingTop) - px(cs.paddingBottom),
    };
  };

  const measure = () => {
    const r = box();
    if (!natW || r.w <= 0 || r.h <= 0) return;
    const k = Math.min(1, r.w / natW, r.h / natH); // never upscale small images beyond 100 %
    fitW = natW * k;
    fitH = natH * k;
    img.style.setProperty('width', `${fitW}px`);
    img.style.setProperty('height', `${fitH}px`);
    apply();
  };

  const clampPan = () => {
    const r = stage.getBoundingClientRect();
    const maxX = Math.max(0, (fitW * scale - r.width) / 2);
    const maxY = Math.max(0, (fitH * scale - r.height) / 2);
    tx = Math.max(-maxX, Math.min(maxX, tx));
    ty = Math.max(-maxY, Math.min(maxY, ty));
  };

  /**
   * Zoom to `next` keeping the point (cx, cy) (client coords) fixed.
   * @param {number} next @param {number} [cx] @param {number} [cy]
   */
  const zoomTo = (next, cx, cy) => {
    const r = stage.getBoundingClientRect();
    const ns = Math.max(MIN, Math.min(MAX, next));
    const px = (cx ?? r.left + r.width / 2) - (r.left + r.width / 2);
    const py = (cy ?? r.top + r.height / 2) - (r.top + r.height / 2);
    // keep the image point under the cursor stationary
    tx = px - ((px - tx) * ns) / scale;
    ty = py - ((py - ty) * ns) / scale;
    scale = ns;
    if (scale <= 1.001) {
      tx = 0;
      ty = 0;
    }
    apply();
  };
  const reset = () => {
    scale = 1;
    tx = 0;
    ty = 0;
    apply();
  };
  const actual = () => {
    if (!fitW) return;
    zoomTo(natW / fitW);
  };

  img.addEventListener('load', () => {
    natW = img.naturalWidth;
    natH = img.naturalHeight;
    delete stage.dataset.loading;
    measure();
  });
  img.addEventListener('error', () => ctx.onError('This image could not be displayed. It may be damaged or in a format your browser does not support.'));

  const ro = new ResizeObserver(() => measure());
  ro.observe(stage);

  // ---- wheel / trackpad pinch
  stage.addEventListener('wheel', (e) => {
    if (!natW) return;
    e.preventDefault();
    const factor = Math.exp(-e.deltaY * (e.ctrlKey ? 0.01 : 0.0022));
    zoomTo(scale * factor, e.clientX, e.clientY);
  }, { passive: false });

  // ---- double click / double tap
  let lastTap = 0;
  let lastTapX = 0;
  let lastTapY = 0;
  /** @param {number} x @param {number} y */
  const toggleZoom = (x, y) => {
    if (scale > 1.001) reset();
    else zoomTo(2.5, x, y);
  };
  stage.addEventListener('dblclick', (e) => {
    e.preventDefault();
    toggleZoom(e.clientX, e.clientY);
  });

  // ---- pointer pan + pinch
  /** @type {Map<number, {x: number, y: number}>} */
  const pts = new Map();
  let pinchDist = 0;
  let pinchScale = 1;
  let panning = false;
  let startX = 0;
  let startY = 0;
  let startTx = 0;
  let startTy = 0;

  stage.addEventListener('pointerdown', (e) => {
    pts.set(e.pointerId, { x: e.clientX, y: e.clientY });
    if (pts.size === 2) {
      const [a, b] = [...pts.values()];
      pinchDist = Math.hypot(a.x - b.x, a.y - b.y);
      pinchScale = scale;
      panning = false;
    } else if (pts.size === 1 && scale > 1.001) {
      panning = true;
      startX = e.clientX;
      startY = e.clientY;
      startTx = tx;
      startTy = ty;
      stage.setPointerCapture(e.pointerId);
      stage.dataset.panning = '';
    }
    if (e.pointerType === 'touch' && pts.size === 1) {
      const now = Date.now();
      if (now - lastTap < 300 && Math.hypot(e.clientX - lastTapX, e.clientY - lastTapY) < 30) {
        toggleZoom(e.clientX, e.clientY);
        lastTap = 0;
      } else {
        lastTap = now;
        lastTapX = e.clientX;
        lastTapY = e.clientY;
      }
    }
  });
  stage.addEventListener('pointermove', (e) => {
    if (!pts.has(e.pointerId)) return;
    pts.set(e.pointerId, { x: e.clientX, y: e.clientY });
    if (pts.size === 2 && pinchDist > 0) {
      const [a, b] = [...pts.values()];
      const d = Math.hypot(a.x - b.x, a.y - b.y);
      zoomTo(pinchScale * (d / pinchDist), (a.x + b.x) / 2, (a.y + b.y) / 2);
    } else if (panning) {
      tx = startTx + (e.clientX - startX);
      ty = startTy + (e.clientY - startY);
      apply();
    }
  });
  /** @param {PointerEvent} e */
  const end = (e) => {
    pts.delete(e.pointerId);
    if (pts.size < 2) pinchDist = 0;
    if (pts.size === 0) {
      panning = false;
      delete stage.dataset.panning;
    }
  };
  stage.addEventListener('pointerup', end);
  stage.addEventListener('pointercancel', end);

  const controls = ctx.zoomControls({ zoomIn: () => zoomTo(scale * 1.25), zoomOut: () => zoomTo(scale / 1.25), reset, actual });

  return {
    el: stage,
    toolbar: controls,
    busy: () => scale > 1.001 || pts.size > 1,
    onKey(e) {
      if (e.key === '+' || e.key === '=') zoomTo(scale * 1.25);
      else if (e.key === '-' || e.key === '_') zoomTo(scale / 1.25);
      else if (e.key === '0') reset();
      else if (e.key === '1') actual();
      else return false;
      return true;
    },
    destroy() {
      ro.disconnect();
      img.removeAttribute('src');
    },
  };
}
