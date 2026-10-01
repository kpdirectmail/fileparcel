// @ts-check
/**
 * progress({value, max, label}) → {el, set(value, max?, label?)}   (value undefined → indeterminate)
 * skeleton(n) → HTMLElement      (n shimmering placeholder lines)
 * spinner() → HTMLElement        (role=status, labelled "Loading")
 * @module components/progress
 */
import { h } from '../core/dom.js';

/**
 * @param {{value?: number | null, max?: number, label?: string, showValue?: boolean, size?: 'sm' | 'md', kind?: 'primary' | 'warning' | 'danger'}} opts
 */
export function progress(opts = {}) {
  const bar = h('progress', { attrs: { max: opts.max || 100, 'aria-label': opts.label || 'Progress' } });
  const labelEl = h('span', { text: opts.label || '' });
  const valueEl = h('span', { class: 'tabular' });
  const head = opts.label || opts.showValue ? h('div', { class: 'progress-head' }, labelEl, opts.showValue ? valueEl : null) : null;
  const el = h('div', { class: ['progress', opts.size === 'sm' && 'progress--sm'], dataset: { kind: opts.kind && opts.kind !== 'primary' ? opts.kind : null } }, head, bar);

  /**
   * @param {number | null | undefined} value
   * @param {number} [max]
   * @param {string} [label]
   */
  const set = (value, max, label) => {
    if (max !== undefined && max > 0) bar.max = max;
    if (value === null || value === undefined || Number.isNaN(value)) bar.removeAttribute('value');
    else bar.value = Math.max(0, Math.min(value, bar.max));
    if (label !== undefined) {
      labelEl.textContent = label;
      bar.setAttribute('aria-label', label || 'Progress');
    }
    valueEl.textContent = bar.hasAttribute('value') ? `${Math.round((bar.value / bar.max) * 100)}%` : '';
  };
  set(opts.value, opts.max);
  return { el, set };
}

/**
 * @param {number} [n]
 * @param {{rows?: boolean}} [opts] rows: row-height blocks (tables/lists)
 * @returns {HTMLElement}
 */
export function skeleton(n = 3, opts = {}) {
  return h('div', { class: ['skeleton', opts.rows && 'skeleton--rows'], attrs: { 'aria-hidden': 'true' } },
    Array.from({ length: Math.max(1, n) }, () => h('div', { class: 'skeleton-line' })));
}

/**
 * @param {{size?: 'md' | 'lg', label?: string}} [opts]
 * @returns {HTMLElement}
 */
export function spinner(opts = {}) {
  return h('span', { class: ['spinner', opts.size === 'lg' && 'spinner--lg'], attrs: { role: 'status', 'aria-label': opts.label || 'Loading' } });
}

/**
 * Centered loading block (spinner) for page bodies.
 * @param {string} [label]
 * @returns {HTMLElement}
 */
export function loadingBlock(label = 'Loading') {
  return h('div', { class: 'loading-block' }, spinner({ size: 'lg', label }));
}
