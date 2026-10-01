// @ts-check
/**
 * toast.show({message, kind: 'info'|'success'|'warning'|'error', action: {label, onClick}, timeout}) → {close()}
 * Shorthands: toast.info(msg), toast.success(msg), toast.warning(msg), toast.error(msgOrError).
 * `timeout` in ms (default 5 s, errors 8 s, 0 = sticky). Timers pause while hovered/focused.
 * Toasts live in a polite live region; errors use role="alert". The region is moved into the top-most open modal
 * <dialog> when a toast is shown (content outside a modal is inert: unclickable and hidden from screen readers);
 * dialog.js/sheet.js hand it back when they close.
 * @module components/toast
 */
import { h, icon, overlayHost } from '../core/dom.js';

const ICONS = { info: 'info', success: 'check-circle', warning: 'alert-triangle', error: 'alert-circle' };
const MAX = 4;

/** @type {HTMLElement | null} */
let region = null;

function ensureRegion() {
  if (!region) region = h('div', { class: 'toasts', attrs: { role: 'region', 'aria-label': 'Notifications' } });
  const host = overlayHost();
  if (region.parentElement !== host) host.appendChild(region);
  return region;
}

/**
 * Called by dialog/sheet when `dialogEl` closes: move the toast region (if it lives there) to the next host so that
 * visible toasts survive the dialog.
 * @param {HTMLElement} dialogEl
 */
export function releaseToasts(dialogEl) {
  if (region && region.parentElement === dialogEl) overlayHost(dialogEl).appendChild(region);
}

/**
 * Called by dialog/sheet right after a modal opened: visible toasts move into the new top-most modal so they are not
 * dimmed by its backdrop (and stay clickable).
 */
export function claimToasts() {
  if (region && region.childElementCount) ensureRegion();
}

/**
 * @typedef {Object} ToastOpts
 * @property {string} message
 * @property {'info' | 'success' | 'warning' | 'error'} [kind]
 * @property {{label: string, onClick: () => void}} [action]
 * @property {number} [timeout]
 */

/**
 * @param {ToastOpts} opts
 * @returns {{close: () => void, el: HTMLElement}}
 */
function show(opts) {
  const kind = opts.kind || 'info';
  const timeout = opts.timeout ?? (kind === 'error' ? 8000 : 5000);
  const root = ensureRegion();
  let timer = 0;
  let remaining = timeout;
  let started = 0;
  let closed = false;

  const close = () => {
    if (closed) return;
    closed = true;
    window.clearTimeout(timer);
    el.dataset.leaving = '';
    const done = () => el.remove();
    if (window.matchMedia('(prefers-reduced-motion: reduce)').matches) done();
    else setTimeout(done, 200);
  };

  const el = h('div', {
    class: ['toast', `toast--${kind}`],
    attrs: { role: kind === 'error' ? 'alert' : 'status', 'aria-live': kind === 'error' ? 'assertive' : 'polite', 'aria-atomic': 'true' },
  },
  icon(ICONS[kind] || 'info'),
  h('div', { class: 'toast-msg', text: opts.message }),
  opts.action
    ? h('button', {
      class: 'btn btn--ghost btn--sm',
      attrs: { type: 'button' },
      text: opts.action.label,
      on: { click: () => { opts.action?.onClick(); close(); } },
    })
    : null,
  h('button', { class: 'icon-btn icon-btn--sm', attrs: { type: 'button', 'aria-label': 'Dismiss', title: 'Dismiss' }, on: { click: close } }, icon('x')));

  const startTimer = () => {
    if (!timeout || closed) return;
    started = Date.now();
    timer = window.setTimeout(close, remaining);
  };
  const pause = () => {
    if (!timeout || !timer) return;
    window.clearTimeout(timer);
    timer = 0;
    remaining = Math.max(1000, remaining - (Date.now() - started));
  };
  el.addEventListener('mouseenter', pause);
  el.addEventListener('mouseleave', startTimer);
  el.addEventListener('focusin', pause);
  el.addEventListener('focusout', startTimer);

  root.appendChild(el);
  while (root.childElementCount > MAX) root.firstElementChild?.remove();
  startTimer();
  return { close, el };
}

export const toast = {
  show,
  /** @param {string} message @param {Partial<ToastOpts>} [o] */
  info: (message, o) => show({ ...o, message, kind: 'info' }),
  /** @param {string} message @param {Partial<ToastOpts>} [o] */
  success: (message, o) => show({ ...o, message, kind: 'success' }),
  /** @param {string} message @param {Partial<ToastOpts>} [o] */
  warning: (message, o) => show({ ...o, message, kind: 'warning' }),
  /**
   * @param {unknown} err message or Error/ApiError
   * @param {Partial<ToastOpts>} [o]
   */
  error: (err, o) => {
    if (/** @type {any} */ (err)?.code === 'aborted') return { close: () => {}, el: h('div') };
    const message = typeof err === 'string' ? err : err instanceof Error ? err.message : String(err);
    return show({ ...o, message, kind: 'error' });
  },
};
