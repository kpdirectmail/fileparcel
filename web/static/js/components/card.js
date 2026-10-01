// @ts-check
/**
 * card({title, body, actions}) → HTMLElement      (section.card with an optional heading and footer actions)
 * statTile({label, value, hint, icon}) → HTMLElement
 * @module components/card
 */
import { h, icon as iconEl } from '../core/dom.js';

/**
 * @param {{title?: string, body?: import('../core/dom.js').Child, actions?: import('../core/dom.js').Child,
 *   headerActions?: import('../core/dom.js').Child, class?: string, headingLevel?: 2 | 3}} opts
 * @returns {HTMLElement}
 */
export function card(opts) {
  const tag = opts.headingLevel === 3 ? 'h3' : 'h2';
  return h('section', { class: ['card', opts.class || ''] },
    opts.title || opts.headerActions
      ? h('div', { class: 'card-head' },
        opts.title ? h(tag, { class: 'card-title', text: opts.title }) : null,
        opts.headerActions ? h('div', { class: 'cluster' }, opts.headerActions) : null)
      : null,
    opts.body !== undefined ? h('div', { class: 'card-body' }, opts.body) : null,
    opts.actions ? h('div', { class: 'card-actions' }, opts.actions) : null);
}

/**
 * @param {{label: string, value: import('../core/dom.js').Child, hint?: import('../core/dom.js').Child, icon?: string, href?: string}} opts
 * @returns {HTMLElement}
 */
export function statTile(opts) {
  const children = [
    h('div', { class: 'stat-label', text: opts.label }),
    h('div', { class: 'stat-value' }, opts.value ?? '—'),
    opts.icon ? h('div', { class: 'stat-icon', attrs: { 'aria-hidden': 'true' } }, iconEl(opts.icon)) : null,
    opts.hint ? h('div', { class: 'stat-hint' }, opts.hint) : null,
  ];
  return opts.href
    ? h('a', { class: 'stat stat--link', href: opts.href }, children)
    : h('div', { class: 'stat' }, children);
}
