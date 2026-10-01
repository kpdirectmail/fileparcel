// @ts-check
/**
 * placeholder(root, {title, subtitle, icon, text, breadcrumbs, action})
 *   "Coming soon" body for page modules that are not implemented yet (page header + empty state). Page owners
 *   replace the call with real content; the page-module contract stays:
 *     export const title = '…';
 *     export async function mount(root, ctx) { …; return () => cleanup; }
 * notFoundPage
 *   Ready-made page module ({title, mount}) used by routes.js for unknown paths (it lives here, in J1's
 *   components/, so it has an owner — §16). A route the account's role does not include renders routes.js
 *   `forbidden` instead.
 * @module components/placeholder
 */
import { h, append } from '../core/dom.js';
import { pageHeader } from './page-header.js';
import { emptyState } from './empty-state.js';

/**
 * @param {HTMLElement} root
 * @param {{title: string, subtitle?: string, icon?: string, text?: string, heading?: string,
 *   breadcrumbs?: import('./page-header.js').Crumb[], action?: any}} opts
 *   heading: empty-state title (default "Coming soon")
 */
export function placeholder(root, opts) {
  const heading = opts.heading || 'Coming soon';
  append(root,
    pageHeader({ title: opts.title, subtitle: opts.subtitle, breadcrumbs: opts.breadcrumbs }),
    emptyState({
      icon: opts.icon || 'package',
      title: heading,
      text: opts.text || 'This part of FileParcel is still being unpacked. Check back after the next update.',
      action: opts.action,
    }),
    opts.heading ? null : h('p', { class: 'sr-only', text: `${opts.title} is not available yet.` }),
  );
}

/**
 * Build a static status page module.
 * @param {{title: string, icon: string, heading: string, text: string}} o
 * @returns {import('../core/router.js').PageModule}
 */
function statusPage(o) {
  return {
    title: o.title,
    mount(root) {
      placeholder(root, { title: o.title, icon: o.icon, heading: o.heading, text: o.text, action: { label: 'Go to My files', icon: 'folder', href: '/files' } });
    },
  };
}

/** Page for unknown in-app paths (routes.js `*`). */
export const notFoundPage = statusPage({
  title: 'Page not found',
  icon: 'alert-triangle',
  heading: 'Nothing here',
  text: 'This page does not exist. It may have been moved or the link is incomplete.',
});
