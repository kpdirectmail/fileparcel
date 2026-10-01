// @ts-check
/**
 * virtualList({rowHeight, count, render, overscan}) → {el, setCount(n, {focusIndex}), refresh({focusIndex}), scrollToIndex(i),
 *                                                    nodeAt(i), destroy()}
 *
 * Renders only the visible rows of a long list. `render(index)` returns the Element for item `index`; it is absolutely
 * positioned (top/left/width set via CSSOM). Options:
 *   rowHeight  fixed row height in px (or a function returning it, re-read on refresh — e.g. for density changes)
 *   count      number of items
 *   overscan   extra rows above/below the viewport (default 6)
 *   columns    items per row for grid views (number or function of the container width)
 *   window     true → the page scrolls (list grows to full height); false (default) → the element is the scroller
 *              and needs a height from CSS
 *   role       ARIA role for the container (e.g. "listbox", "grid", "list")
 *   scrollMargin  {top, bottom} px hidden by sticky bars (or a function returning it) — used by scrollToIndex
 *   keep       () => index that stays rendered even outside the visible window (-1 = none), e.g. the roving-tabindex
 *              row of a listbox, so Tab can still enter the list after it was scrolled out of view
 * Keyboard focus survives re-renders: setCount()/refresh()/column changes re-create the rows and move focus to the
 * new node at the same index (clamped to the new count), so rename (F2) or loading more rows keeps the user's place.
 * A caller that tracks its items by id passes `{focusIndex}` to setCount()/refresh() instead: focus then goes to that
 * index (e.g. where the focused item moved after a re-sort or an insertion above it).
 * @module components/virtual-list
 */
import { h } from '../core/dom.js';

/**
 * @typedef {Object} VirtualListOpts
 * @property {number | (() => number)} rowHeight
 * @property {number} count
 * @property {(index: number) => HTMLElement} render
 * @property {number} [overscan]
 * @property {number | ((width: number) => number)} [columns]
 * @property {boolean} [window]
 * @property {string} [role]
 * @property {string} [label] aria-label
 * @property {string} [class]
 * @property {{top?: number, bottom?: number} | (() => {top?: number, bottom?: number})} [scrollMargin] space covered by
 *   sticky bars (scrollToIndex keeps items out from under them)
 * @property {() => number} [keep] index to keep rendered outside the visible window (-1 = none)
 */

/**
 * @param {VirtualListOpts} opts
 */
export function virtualList(opts) {
  let count = Math.max(0, opts.count | 0);
  const overscan = opts.overscan ?? 6;
  const useWindow = !!opts.window;
  /** @type {Map<number, HTMLElement>} */
  const rendered = new Map();
  let raf = 0;
  let destroyed = false;

  const spacer = h('div', { class: 'vlist-spacer' });
  const el = h('div', {
    class: ['vlist', useWindow && 'vlist--window', opts.class || ''],
    attrs: { role: opts.role || null, 'aria-label': opts.label || null },
  }, spacer);

  const rowH = () => (typeof opts.rowHeight === 'function' ? opts.rowHeight() : opts.rowHeight);
  const cols = () => {
    const c = typeof opts.columns === 'function' ? opts.columns(el.clientWidth || window.innerWidth) : opts.columns || 1;
    return Math.max(1, Math.floor(c));
  };

  const update = () => {
    raf = 0;
    if (destroyed) return;
    const rh = rowH();
    const nc = cols();
    const totalRows = Math.ceil(count / nc);
    spacer.style.setProperty('height', `${totalRows * rh}px`);
    let viewTop;
    let viewH;
    if (useWindow) {
      const r = el.getBoundingClientRect();
      viewTop = Math.max(0, -r.top);
      viewH = window.innerHeight;
    } else {
      viewTop = el.scrollTop;
      viewH = el.clientHeight || window.innerHeight;
    }
    const firstRow = Math.max(0, Math.floor(viewTop / rh) - overscan);
    const lastRow = Math.min(totalRows - 1, Math.ceil((viewTop + viewH) / rh) + overscan);
    const firstIdx = firstRow * nc;
    const lastIdx = Math.min(count - 1, (lastRow + 1) * nc - 1);

    const keep = opts.keep ? opts.keep() : -1;
    for (const [i, node] of rendered) {
      if (i < firstIdx || i > lastIdx) {
        // keep the focused row alive so keyboard focus is not lost while scrolling (and the `keep` row, see above)
        if (i === keep || node.contains(document.activeElement)) continue;
        node.remove();
        rendered.delete(i);
      }
    }
    for (let i = firstIdx; i <= lastIdx; i += 1) place(i, rh, nc);
    if (keep >= 0) place(keep, rh, nc);
  };

  /**
   * Render item `i` (if not rendered yet) at its absolute position.
   * @param {number} i @param {number} rh row height @param {number} nc columns
   */
  const place = (i, rh, nc) => {
    if (rendered.has(i) || i < 0 || i >= count) return;
    const node = opts.render(i);
    node.classList.add('vlist-row');
    const row = Math.floor(i / nc);
    const col = i % nc;
    const width = 100 / nc;
    node.style.setProperty('top', `${row * rh}px`);
    node.style.setProperty('height', `${rh}px`);
    if (nc > 1) {
      node.style.setProperty('left', `${col * width}%`);
      node.style.setProperty('width', `${width}%`);
      node.style.setProperty('right', 'auto');
    }
    node.dataset.index = String(i);
    spacer.appendChild(node);
    rendered.set(i, node);
  };

  /**
   * Drop every rendered row and render again synchronously, moving keyboard focus (if a row had it) to the row that
   * now sits at `focusIndex` — by default the previously focused index — clamped to the count. Without this, removing
   * the focused node drops focus to <body>.
   * @param {number} [focusIndex]
   */
  const rebuild = (focusIndex) => {
    const active = document.activeElement;
    let fi = -1;
    for (const [i, n] of rendered) {
      if (active && n.contains(active)) {
        fi = i;
        break;
      }
    }
    for (const n of rendered.values()) n.remove();
    rendered.clear();
    if (raf) {
      cancelAnimationFrame(raf);
      raf = 0;
    }
    update();
    if (fi < 0 || !count || destroyed) return;
    const want = focusIndex !== undefined && Number.isInteger(focusIndex) && focusIndex >= 0 ? focusIndex : fi;
    const target = Math.min(want, count - 1);
    place(target, rowH(), cols()); // keep it even when scrolled out of the rendered window
    const node = rendered.get(target);
    if (!node) return;
    const focusTarget = node.tabIndex >= 0 || node.hasAttribute('tabindex')
      ? node
      : /** @type {HTMLElement | null} */ (node.querySelector('a[href], button:not([disabled]), input:not([disabled]), [tabindex]'));
    focusTarget?.focus({ preventScroll: true });
  };

  const schedule = () => {
    if (!raf) raf = requestAnimationFrame(update);
  };

  const scrollTarget = useWindow ? window : el;
  scrollTarget.addEventListener('scroll', schedule, { passive: true });
  window.addEventListener('resize', schedule);
  let lastCols = 0;
  /** @type {ResizeObserver | null} */
  const ro = typeof ResizeObserver !== 'undefined' ? new ResizeObserver(() => {
    // Only a column-count change (width) needs a full re-layout; height changes (e.g. the spacer growing in window
    // mode) just need the visible window recomputed.
    const nc = cols();
    if (lastCols && nc !== lastCols) {
      lastCols = nc;
      rebuild();
    } else {
      lastCols = nc;
      schedule();
    }
  }) : null;
  ro?.observe(el);
  // first paint once attached
  requestAnimationFrame(update);

  return {
    el,
    /** @param {number} n @param {{focusIndex?: number}} [o] where keyboard focus goes if a row had it (see above) */
    setCount(n, o = {}) {
      count = Math.max(0, n | 0);
      rebuild(o.focusIndex);
    },
    /** Re-render every visible row (data changed). @param {{focusIndex?: number}} [o] */
    refresh(o = {}) {
      rebuild(o.focusIndex);
    },
    /**
     * Scroll the minimum distance that brings item `i` fully into view (respecting `scrollMargin`), render it even
     * when the scroll has not settled yet, and optionally focus it (keyboard navigation).
     * @param {number} i
     * @param {{focus?: boolean, center?: boolean}} [o] center: put the item in the middle (jump targets)
     */
    scrollToIndex(i, o = {}) {
      if (i < 0 || i >= count) return;
      const rh = rowH();
      const nc = cols();
      const row = Math.floor(i / nc);
      const top = row * rh;
      const m = typeof opts.scrollMargin === 'function' ? opts.scrollMargin() : opts.scrollMargin || { top: 0, bottom: 0 };
      if (useWindow) {
        const base = el.getBoundingClientRect().top + window.scrollY;
        const y = base + top;
        const viewTop = window.scrollY + (m.top || 0);
        const viewBottom = window.scrollY + window.innerHeight - (m.bottom || 0);
        let target = null;
        if (o.center) target = y - (window.innerHeight - rh) / 2;
        else if (y < viewTop) target = y - (m.top || 0);
        else if (y + rh > viewBottom) target = y + rh - window.innerHeight + (m.bottom || 0);
        if (target !== null) window.scrollTo({ top: Math.max(0, target), behavior: 'instant' });
      } else {
        const viewTop = el.scrollTop + (m.top || 0);
        const viewBottom = el.scrollTop + el.clientHeight - (m.bottom || 0);
        if (o.center) el.scrollTop = top - (el.clientHeight - rh) / 2;
        else if (top < viewTop) el.scrollTop = top - (m.top || 0);
        else if (top + rh > viewBottom) el.scrollTop = top + rh - el.clientHeight + (m.bottom || 0);
      }
      update();
      place(i, rh, nc);
      if (o.focus) rendered.get(i)?.focus({ preventScroll: true });
    },
    /** @param {number} i */
    nodeAt: (i) => rendered.get(i) || null,
    destroy() {
      destroyed = true;
      scrollTarget.removeEventListener('scroll', schedule);
      window.removeEventListener('resize', schedule);
      ro?.disconnect();
      if (raf) cancelAnimationFrame(raf);
    },
  };
}
