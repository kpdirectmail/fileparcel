// @ts-check
/**
 * Buttons.
 *   button({label, icon, variant: 'primary'|'secondary'|'ghost'|'danger'|'kraft', size: 'sm'|'md', onClick, disabled, type, title})
 *   iconButton({icon, label, onClick, variant})
 * When `onClick` returns a Promise the button shows a busy spinner and ignores clicks until it settles.
 * @module components/button
 */
import { h, icon as iconEl } from '../core/dom.js';

/**
 * @typedef {Object} ButtonOpts
 * @property {string} [label]
 * @property {string} [icon] sprite id shown before the label
 * @property {string} [iconEnd] sprite id shown after the label
 * @property {'primary' | 'secondary' | 'ghost' | 'danger' | 'kraft'} [variant]
 * @property {'sm' | 'md'} [size]
 * @property {(e: MouseEvent) => any} [onClick]
 * @property {boolean} [disabled]
 * @property {'button' | 'submit' | 'reset'} [type]
 * @property {string} [title] tooltip (and accessible name when there is no label)
 * @property {boolean} [block] full width
 * @property {string} [class] extra classes
 * @property {Record<string, string | number | boolean | null | undefined>} [attrs] extra attributes
 */

/**
 * Show/clear the busy state of a button.
 * @param {HTMLButtonElement} btn
 * @param {boolean} busy
 */
export function setBusy(btn, busy) {
  if (busy) {
    btn.setAttribute('aria-busy', 'true');
    btn.dataset.wasDisabled = btn.disabled ? '1' : '';
    btn.disabled = true;
  } else {
    btn.removeAttribute('aria-busy');
    btn.disabled = btn.dataset.wasDisabled === '1';
    delete btn.dataset.wasDisabled;
  }
}

/**
 * @param {HTMLButtonElement} btn
 * @param {((e: MouseEvent) => any) | undefined} onClick
 */
function wireClick(btn, onClick) {
  if (!onClick) return;
  btn.addEventListener('click', (e) => {
    if (btn.getAttribute('aria-busy') === 'true') return;
    const r = onClick(e);
    if (r && typeof r.then === 'function') {
      setBusy(btn, true);
      Promise.resolve(r)
        .catch((err) => console.error(err))
        .finally(() => setBusy(btn, false));
    }
  });
}

/**
 * @param {ButtonOpts} opts
 * @returns {HTMLButtonElement}
 */
export function button(opts) {
  const variant = opts.variant || 'secondary';
  const btn = h('button', {
    class: ['btn', `btn--${variant}`, opts.size === 'sm' && 'btn--sm', opts.block && 'btn--block', opts.class || ''],
    attrs: {
      type: opts.type || 'button',
      title: opts.title || null,
      'aria-label': !opts.label && opts.title ? opts.title : null,
      ...(opts.attrs || {}),
    },
    disabled: !!opts.disabled,
  },
  opts.icon ? iconEl(opts.icon) : null,
  opts.label ? h('span', { text: opts.label }) : null,
  opts.iconEnd ? iconEl(opts.iconEnd) : null);
  wireClick(btn, opts.onClick);
  return btn;
}

/**
 * @typedef {Object} IconButtonOpts
 * @property {string} icon
 * @property {string} label accessible name + tooltip
 * @property {(e: MouseEvent) => any} [onClick]
 * @property {'ghost' | 'primary' | 'danger'} [variant]
 * @property {'sm' | 'md'} [size]
 * @property {boolean} [disabled]
 * @property {boolean} [pressed] toggle state (aria-pressed)
 * @property {string} [class]
 * @property {Record<string, string | number | boolean | null | undefined>} [attrs]
 */

/**
 * Square icon-only button with an accessible label.
 * @param {IconButtonOpts} opts
 * @returns {HTMLButtonElement}
 */
export function iconButton(opts) {
  const btn = h('button', {
    class: ['icon-btn', opts.variant && opts.variant !== 'ghost' && `icon-btn--${opts.variant}`, opts.size === 'sm' && 'icon-btn--sm', opts.class || ''],
    attrs: {
      type: 'button',
      'aria-label': opts.label,
      title: opts.label,
      'aria-pressed': opts.pressed === undefined ? null : String(!!opts.pressed),
      ...(opts.attrs || {}),
    },
    disabled: !!opts.disabled,
  }, iconEl(opts.icon));
  wireClick(btn, opts.onClick);
  return btn;
}
