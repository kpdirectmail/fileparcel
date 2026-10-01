// @ts-check
/**
 * emptyState({icon, title, text, action}) → HTMLElement
 * `action` is an Element or a button spec {label, icon, onClick, variant, href}.
 * @module components/empty-state
 */
import { h, icon as iconEl } from '../core/dom.js';
import { button } from './button.js';

/**
 * @param {{icon?: string, title: string, text?: import('../core/dom.js').Child,
 *   action?: Element | {label: string, icon?: string, onClick?: () => any, variant?: 'primary' | 'secondary' | 'ghost', href?: string}}} opts
 * @returns {HTMLElement}
 */
export function emptyState(opts) {
  /** @type {Element | null} */
  let action = null;
  if (opts.action instanceof Element) action = opts.action;
  else if (opts.action) {
    const a = opts.action;
    action = a.href
      ? h('a', { class: `btn btn--${a.variant || 'primary'}`, href: a.href }, a.icon ? iconEl(a.icon) : null, h('span', { text: a.label }))
      : button({ label: a.label, icon: a.icon, variant: a.variant || 'primary', onClick: a.onClick });
  }
  return h('div', { class: 'empty' },
    h('div', { class: 'empty-icon', attrs: { 'aria-hidden': 'true' } }, iconEl(opts.icon || 'package')),
    h('h2', { class: 'empty-title', text: opts.title }),
    opts.text ? h('p', { class: 'empty-text' }, opts.text) : null,
    action ? h('div', { class: 'empty-action' }, action) : null);
}
