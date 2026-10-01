// @ts-check
/**
 * badge({text, kind}) → HTMLElement
 * kind: 'neutral' (default) | 'primary' | 'info' | 'success' | 'warning' | 'danger' | 'kraft'
 * @module components/badge
 */
import { h, icon } from '../core/dom.js';

/**
 * @param {{text: string, kind?: 'neutral' | 'primary' | 'info' | 'success' | 'warning' | 'danger' | 'kraft', icon?: string, title?: string}} opts
 * @returns {HTMLElement}
 */
export function badge(opts) {
  const kind = opts.kind && opts.kind !== 'neutral' ? `badge--${opts.kind}` : '';
  return h('span', { class: ['badge', kind], attrs: { title: opts.title || null } },
    opts.icon ? icon(opts.icon, { size: 12 }) : null,
    opts.text);
}
