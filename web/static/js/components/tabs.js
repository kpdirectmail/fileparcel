// @ts-check
/**
 * tabs({items: [{id, label}], active, onChange, variant}) → {el, setActive(id), active()}
 * WAI-ARIA tablist with roving tabindex (←/→/Home/End). The caller renders the panel for the active tab; pass
 * `panelId` on an item to wire aria-controls. `variant: 'pill'` renders a segmented control.
 * @module components/tabs
 */
import { h } from '../core/dom.js';

/**
 * @typedef {Object} TabItem
 * @property {string} id
 * @property {string} label
 * @property {string} [panelId]
 * @property {string | number} [badge]
 */

/**
 * @param {{items: TabItem[], active?: string, onChange?: (id: string) => void, variant?: 'line' | 'pill', label?: string}} opts
 */
export function tabs(opts) {
  let active = opts.active || opts.items[0]?.id || '';
  /** @type {HTMLButtonElement[]} */
  const buttons = [];
  const el = h('div', { class: ['tabs', opts.variant === 'pill' && 'tabs--pill'], attrs: { role: 'tablist', 'aria-label': opts.label || null } });

  const sync = () => {
    /** @type {HTMLButtonElement | null} */
    let cur = null;
    for (const b of buttons) {
      const sel = b.dataset.id === active;
      b.setAttribute('aria-selected', String(sel));
      b.tabIndex = sel ? 0 : -1;
      if (sel) cur = b;
    }
    // The strip scrolls horizontally when it does not fit (components.css .tabs) and hides its scrollbar, so keep
    // the selected tab in view. scrollLeft rather than scrollIntoView(), which would also scroll every scrollable
    // ancestor including the window. A no-op while `el` is still detached or not overflowing.
    if (cur && el.scrollWidth > el.clientWidth) {
      const s = el.getBoundingClientRect(), t = cur.getBoundingClientRect();
      el.scrollLeft += t.left - s.left - (el.clientWidth - t.width) / 2;
    }
  };

  /** @param {string} id @param {boolean} fire */
  const select = (id, fire) => {
    if (id === active) return;
    active = id;
    sync();
    if (fire && opts.onChange) opts.onChange(id);
  };

  for (const item of opts.items) {
    const b = h('button', {
      class: 'tab',
      id: `tab-${item.id}-${Math.random().toString(36).slice(2, 7)}`,
      attrs: { type: 'button', role: 'tab', 'aria-controls': item.panelId || null },
      dataset: { id: item.id },
      on: { click: () => select(item.id, true) },
    }, item.label, item.badge !== undefined ? h('span', { class: 'badge', text: String(item.badge) }) : null);
    buttons.push(b);
    el.appendChild(b);
  }

  el.addEventListener('keydown', (e) => {
    const i = buttons.findIndex((b) => b === document.activeElement);
    if (i < 0) return;
    let j = -1;
    if (e.key === 'ArrowRight') j = (i + 1) % buttons.length;
    else if (e.key === 'ArrowLeft') j = (i - 1 + buttons.length) % buttons.length;
    else if (e.key === 'Home') j = 0;
    else if (e.key === 'End') j = buttons.length - 1;
    if (j < 0) return;
    e.preventDefault();
    buttons[j].focus();
    select(buttons[j].dataset.id || '', true);
  });

  sync();
  // The strip is still detached here, so sync() could not scroll it: once the caller has mounted it, bring the
  // selected tab into view (a page opened on a later tab, e.g. ?tab=groups, on a narrow phone).
  requestAnimationFrame(() => { if (el.isConnected) sync(); });
  return {
    el,
    /** @param {string} id */
    setActive(id) {
      select(id, false);
    },
    active: () => active,
  };
}
