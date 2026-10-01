// @ts-check
/**
 * pageHeader({title, subtitle, actions, breadcrumbs}) → HTMLElement
 * Renders <header class="page-header"> with an <h1 tabindex="-1"> (the router focuses it after navigation),
 * optional breadcrumbs [{label, href}] (last item = current page) and an actions area (Elements).
 * @module components/page-header
 */
import { h } from '../core/dom.js';

/**
 * @typedef {Object} Crumb
 * @property {string} label
 * @property {string} [href]
 */

/**
 * Breadcrumb navigation. The last crumb is rendered as the current page.
 * @param {Crumb[]} crumbs
 * @returns {HTMLElement}
 */
export function breadcrumbs(crumbs) {
  return h('nav', { class: 'breadcrumbs', attrs: { 'aria-label': 'Breadcrumb' } },
    h('ol', { attrs: { role: 'list' } },
      crumbs.map((c, i) => {
        const last = i === crumbs.length - 1;
        return h('li', null,
          last || !c.href
            ? h('span', { attrs: { 'aria-current': last ? 'page' : null }, text: c.label })
            : h('a', { href: c.href, title: c.label, text: c.label }));
      })));
}

/**
 * @param {{title: string, subtitle?: import('../core/dom.js').Child, actions?: import('../core/dom.js').Child, breadcrumbs?: Crumb[]}} opts
 * @returns {HTMLElement}
 */
export function pageHeader(opts) {
  return h('header', { class: 'page-header' },
    h('div', { class: 'page-header-text' },
      opts.breadcrumbs && opts.breadcrumbs.length ? breadcrumbs(opts.breadcrumbs) : null,
      h('h1', { class: 'page-title', attrs: { tabindex: '-1' }, text: opts.title }),
      opts.subtitle ? h('p', { class: 'page-subtitle' }, opts.subtitle) : null),
    opts.actions ? h('div', { class: 'page-actions' }, opts.actions) : null);
}
