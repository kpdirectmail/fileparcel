// @ts-check
/**
 * sheet({title, content, onClose}) → {el, body, open(), close()}
 * Bottom sheet (mobile "More" menu, file actions on touch). Native modal <dialog>: inert background, Escape and
 * backdrop tap close it, Tab is trapped, focus returns to the opener; drag the handle down to dismiss
 * (dragToDismiss(), also exported for other bottom-sheet surfaces).
 * Helper: sheetList(items) renders menu-style rows [{label, icon, onClick, href, danger, disabled, divider, current}].
 * @module components/sheet
 */
import { h, append, icon, trapFocus, focusable, uniqueId } from '../core/dom.js';
import { claimToasts, releaseToasts } from './toast.js';
import { dismissOnNavigate } from '../core/router.js';

/**
 * @typedef {Object} SheetItem
 * @property {string} [label]
 * @property {string} [icon]
 * @property {() => void} [onClick]
 * @property {string} [href] in-app link (router intercepts it)
 * @property {boolean} [danger]
 * @property {boolean} [disabled]
 * @property {boolean} [divider]
 * @property {boolean} [current] marks the current page
 * @property {string} [section] renders a small section heading instead of an item
 */

/**
 * @param {{title: string, content?: import('../core/dom.js').Child, onClose?: () => void}} opts
 */
export function sheet(opts) {
  const titleId = uniqueId('sheet-title');
  const body = h('div', { class: 'sheet-body' });
  append(body, opts.content);
  /** @type {Element | null} */
  let returnFocus = null;
  /** @type {(() => void) | null} */
  let untrap = null;
  /** @type {(() => void) | null} */
  let offNav = null;
  let isOpen = false;

  const el = h('dialog', { class: 'sheet', attrs: { 'aria-labelledby': titleId, 'aria-modal': 'true' } },
    h('div', { class: 'sheet-handle', attrs: { 'aria-hidden': 'true' } }),
    h('div', { class: 'sheet-head' },
      h('h2', { class: 'sheet-title', id: titleId, text: opts.title }),
      h('button', { class: 'icon-btn icon-btn--sm', attrs: { type: 'button', 'aria-label': 'Close', title: 'Close' }, on: { click: () => api.close() } }, icon('x'))),
    body);

  el.addEventListener('cancel', (e) => {
    e.preventDefault();
    api.close();
  });
  el.addEventListener('click', (e) => {
    if (e.target !== el) return;
    const r = el.getBoundingClientRect();
    if (e.clientY < r.top || e.clientY > r.bottom || e.clientX < r.left || e.clientX > r.right) api.close();
  });
  // drag the handle/header (or the list when it is scrolled to the top) down to dismiss
  const detachDrag = dragToDismiss(el, { handles: '.sheet-handle, .sheet-head', scroller: body, onDismiss: () => api.close() });
  el.addEventListener('close', () => {
    if (!isOpen) return;
    isOpen = false;
    if (offNav) offNav();
    offNav = null;
    if (untrap) untrap();
    detachDrag.reset();
    releaseToasts(el);
    el.remove();
    if (returnFocus instanceof HTMLElement && returnFocus.isConnected) returnFocus.focus({ preventScroll: true });
    opts.onClose?.();
  });

  const api = {
    el,
    body,
    open() {
      if (isOpen) return api;
      isOpen = true;
      returnFocus = document.activeElement;
      offNav = dismissOnNavigate(() => api.close());
      document.body.appendChild(el);
      el.showModal();
      untrap = trapFocus(el);
      const first = focusable(body)[0] || focusable(el)[0];
      first?.focus();
      claimToasts(); // after showModal()/focus(): visible toasts move into this sheet instead of behind it
      return api;
    },
    close() {
      if (isOpen) el.close();
    },
  };
  return api;
}

/**
 * Drag-to-dismiss for bottom sheets (touch and pen): the panel follows the finger downwards and closes when released
 * past a distance/velocity threshold, otherwise it springs back. Gestures start on `handles`, or anywhere inside
 * `scroller` while it is scrolled to the top (so scrolling a long list up never closes the sheet).
 * @param {HTMLElement} el the panel (a <dialog>)
 * @param {{handles: string, scroller?: HTMLElement, onDismiss: () => void, threshold?: number, when?: () => boolean}} o
 *   when: extra predicate checked when a gesture starts (e.g. only in the phone layout)
 * @returns {{reset: () => void, detach: () => void}}
 */
export function dragToDismiss(el, o) {
  const threshold = o.threshold ?? 96;
  /** @type {{id: number, y0: number, t0: number, dy: number, last: number, lastT: number, active: boolean} | null} */
  let drag = null;
  const reset = () => {
    drag = null;
    el.removeAttribute('data-dragging');
    el.style.removeProperty('transform');
    el.style.removeProperty('transition');
  };
  /** @param {PointerEvent} e */
  const down = (e) => {
    if (e.pointerType === 'mouse' || !e.isPrimary || (o.when && !o.when())) return;
    const t = /** @type {Element} */ (e.target);
    const onHandle = !!t.closest(o.handles);
    const inScroller = !!(o.scroller && o.scroller.contains(t) && o.scroller.scrollTop <= 0);
    if (!onHandle && !inScroller) return;
    if (t.closest('input, textarea, select, [contenteditable="true"]')) return;
    drag = { id: e.pointerId, y0: e.clientY, t0: performance.now(), dy: 0, last: e.clientY, lastT: performance.now(), active: onHandle };
  };
  /** @param {PointerEvent} e */
  const move = (e) => {
    if (!drag || e.pointerId !== drag.id) return;
    const dy = e.clientY - drag.y0;
    if (!drag.active) {
      // content gestures: only a clear downward pull takes over (upward = normal scrolling)
      if (dy < -4) { drag = null; return; }
      if (dy < 10) return;
      drag.active = true;
    }
    drag.dy = Math.max(0, dy);
    drag.last = e.clientY;
    drag.lastT = performance.now();
    el.setAttribute('data-dragging', '');
    el.style.setProperty('transition', 'none');
    el.style.setProperty('transform', `translateY(${drag.dy}px)`);
  };
  /** @param {PointerEvent} e */
  const up = (e) => {
    if (!drag || e.pointerId !== drag.id) return;
    const d = drag;
    drag = null;
    if (!d.active) return;
    const dt = Math.max(1, performance.now() - d.t0);
    const velocity = d.dy / dt; // px per ms
    el.removeAttribute('data-dragging');
    if (e.type !== 'pointercancel' && (d.dy > threshold || (velocity > 0.6 && d.dy > 24))) {
      el.style.setProperty('transition', 'transform 160ms ease-in');
      el.style.setProperty('transform', 'translateY(100%)');
      window.setTimeout(() => o.onDismiss(), window.matchMedia('(prefers-reduced-motion: reduce)').matches ? 0 : 150);
    } else {
      el.style.setProperty('transition', 'transform 180ms cubic-bezier(0.2, 0.8, 0.2, 1)');
      el.style.setProperty('transform', 'translateY(0)');
      window.setTimeout(() => { if (!drag) { el.style.removeProperty('transform'); el.style.removeProperty('transition'); } }, 200);
    }
  };
  el.addEventListener('pointerdown', down);
  el.addEventListener('pointermove', move);
  el.addEventListener('pointerup', up);
  el.addEventListener('pointercancel', up);
  return {
    reset,
    detach() {
      reset();
      el.removeEventListener('pointerdown', down);
      el.removeEventListener('pointermove', move);
      el.removeEventListener('pointerup', up);
      el.removeEventListener('pointercancel', up);
    },
  };
}

/**
 * Menu-style list for sheets. Items close the sheet (pass `close`) after activation.
 * @param {SheetItem[]} items
 * @param {() => void} [close]
 */
export function sheetList(items, close) {
  return h('ul', { class: 'sheet-list', attrs: { role: 'list' } },
    items.map((it) => {
      if (it.divider) return h('li', { class: 'sheet-divider', attrs: { role: 'separator' } });
      if (it.section) return h('li', { class: 'sheet-section-label', text: it.section });
      const content = [it.icon ? icon(it.icon) : null, h('span', { text: it.label || '' })];
      const node = it.href
        ? h('a', {
          class: 'sheet-item',
          href: it.href,
          attrs: { 'aria-current': it.current ? 'page' : null },
          dataset: { danger: it.danger || null },
          on: { click: () => close?.() },
        }, content)
        : h('button', {
          class: 'sheet-item',
          attrs: { type: 'button' },
          dataset: { danger: it.danger || null },
          disabled: !!it.disabled,
          on: {
            click: () => {
              close?.();
              it.onClick?.();
            },
          },
        }, content);
      return h('li', null, node);
    }));
}
