// @ts-check
/**
 * Generic error page (404 for unknown pages and invalid share/invite tokens — deliberately identical so it is no
 * oracle — plus 403, 410, 429, 5xx …). Boot data: {status, code?, message?, request_id?}.
 * Owned by unit J2.
 * @module public/error
 */
import { h, boot, append } from '../core/dom.js';
import { publicRoot, authCard, initAppearance } from './common.js';

initAppearance();
const b = boot();
const status = Number(b.data.status) || 404;

/** @type {Record<number, {title: string, text: string, icon: string}>} */
const PAGES = {
  400: { title: 'That request did not look right', text: 'Please check the address and try again.', icon: 'alert-triangle' },
  401: { title: 'Please sign in', text: 'You need to sign in to see this page.', icon: 'lock' },
  403: { title: 'You don’t have access to this', text: 'Ask the owner or an administrator if you think you should.', icon: 'lock' },
  404: { title: 'Nothing here', text: 'This page does not exist or is no longer available. Links can expire or be turned off by their owner.', icon: 'package' },
  410: { title: 'This link has expired', text: 'Ask the person who shared it for a new link.', icon: 'clock' },
  429: { title: 'Slow down a little', text: 'Too many requests came from your network. Wait a minute and try again.', icon: 'clock' },
  500: { title: 'Something went wrong', text: 'The server hit an unexpected problem. Please try again in a moment.', icon: 'alert-circle' },
  503: { title: 'Temporarily unavailable', text: 'The server is starting, restarting or locked. Please try again shortly.', icon: 'server' },
};
const page = PAGES[status] || (status >= 500 ? PAGES[500] : PAGES[400]);
const message = typeof b.data.message === 'string' && b.data.message && status !== 404 ? b.data.message : page.text;
const requestId = typeof b.data.request_id === 'string' ? b.data.request_id : '';
// Over Tailscale Funnel "shares" mode only share links are reachable: no way into the app (error.html marks it).
const publicOnly = document.documentElement.hasAttribute('data-public-only');

const root = publicRoot();
append(root, authCard({
  title: page.title,
  icon: page.icon,
  subtitle: h('span', { class: 'mono text-xs', text: `Error ${status}` }),
  body: [
    h('p', { class: 'text-center muted', text: message }),
    requestId ? h('p', { class: 'text-center subtle text-xs' }, 'Reference: ', h('span', { class: 'mono', text: requestId })) : null,
  ],
  footer: footer([
    history.length > 1 ? h('button', { class: 'btn btn--ghost btn--sm', attrs: { type: 'button' }, text: 'Go back', on: { click: () => history.back() } }) : null,
    status >= 500 ? h('button', { class: 'btn btn--secondary btn--sm', attrs: { type: 'button' }, text: 'Try again', on: { click: () => location.reload() } }) : null,
    publicOnly ? null : h('a', { class: 'btn btn--primary btn--sm', href: '/', attrs: { 'data-native': true }, text: `Go to ${b.instance || 'FileParcel'}` }),
  ]),
}));

/**
 * The footer buttons, or null when there is none (no empty button row).
 * @param {(HTMLElement | null)[]} items
 */
function footer(items) {
  const els = items.filter((x) => x !== null);
  return els.length ? els : null;
}
