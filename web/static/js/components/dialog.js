// @ts-check
/**
 * Modal dialogs on the native <dialog> element (top layer, inert background, Escape via the "cancel" event) plus an
 * explicit Tab focus trap and focus restoration.
 *
 *   const d = dialog({title, body, actions, size: 'sm'|'md'|'lg', onClose}); d.open(); … d.close();
 *   await confirm({title, message, danger, confirmLabel}) → boolean
 *   await prompt({title, label, value, confirmLabel})     → string | null
 *
 * `actions` items are Elements or specs {label, variant, icon, onClick, close = true, autofocus}. A spec's onClick may
 * return false (keep open) or a Promise (button busy until it settles; a rejected promise keeps the dialog open).
 * On phones (< 640 px) dialogs render as bottom sheets via CSS (dismissible ones can be dragged down by the header);
 * on touch screens an open dialog rides above the on-screen keyboard and keeps the focused field in view
 * (keyboardInset).
 * @module components/dialog
 */
import { h, append, trapFocus, focusable, icon, uniqueId, isMobile } from '../core/dom.js';
import { button } from './button.js';
import { claimToasts, releaseToasts } from './toast.js';
import { dragToDismiss } from './sheet.js';
import { dismissOnNavigate } from '../core/router.js';

/**
 * @typedef {Object} ActionSpec
 * @property {string} label
 * @property {'primary' | 'secondary' | 'ghost' | 'danger' | 'kraft'} [variant]
 * @property {string} [icon]
 * @property {(e: MouseEvent) => any} [onClick]
 * @property {boolean} [close] close after onClick (default true)
 * @property {boolean} [autofocus]
 * @property {any} [value] passed to onClose when this action closes the dialog
 * @property {'button' | 'submit'} [type]
 */

/**
 * @typedef {Object} DialogOpts
 * @property {string} title
 * @property {import('../core/dom.js').Child} [body]
 * @property {(Element | ActionSpec)[]} [actions]
 * @property {'sm' | 'md' | 'lg' | 'xl'} [size]
 * @property {(value: any) => void} [onClose]
 * @property {boolean} [dismissible] Escape / backdrop click / × close it (default true)
 * @property {string} [class]
 * @property {boolean} [hideClose] hide the × button
 */

/**
 * @typedef {Object} DialogHandle
 * @property {HTMLDialogElement} el
 * @property {HTMLElement} body
 * @property {HTMLElement} actions
 * @property {() => DialogHandle} open
 * @property {(value?: any) => void} close
 * @property {(title: string) => void} setTitle
 */

/**
 * The smallest loss of visual viewport that counts as an on-screen keyboard. Browser toolbars (Safari's and Brave's
 * bottom bar, the floating bar of iOS 26) and pinch zoom also leave the visual viewport shorter than the layout
 * viewport, by up to ~150 px; taken for a keyboard, that lifted every sheet off the bottom and squeezed its content
 * to a sliver on iPhones. Portrait phone keyboards are 250 px and taller (sheets are the < 640 px layout).
 */
const KEYBOARD_MIN = 200;

/** Input types that bring up no on-screen keyboard. */
const NO_KEYBOARD = new Set(['button', 'checkbox', 'color', 'file', 'hidden', 'image', 'radio', 'range', 'reset', 'submit']);

/**
 * @param {Element | null} el
 * @returns {boolean} whether focusing el brings up an on-screen keyboard
 */
function typesText(el) {
  if (el instanceof HTMLTextAreaElement) return !el.readOnly && !el.disabled;
  if (el instanceof HTMLInputElement) return !el.readOnly && !el.disabled && !NO_KEYBOARD.has(el.type);
  return el instanceof HTMLElement && el.isContentEditable;
}

/**
 * Keep an open bottom sheet above a phone's on-screen keyboard (DESIGN §13.6). No page sets `interactive-widget`, so
 * the keyboard overlays the fixed sheet and `dvh` does not change: the keyboard's height is what the visual viewport
 * lost at the bottom. It only counts while a text field of the sheet has the focus, the page is not zoomed and the
 * loss is keyboard-sized (KEYBOARD_MIN); then it is published on the dialog as `--fp-kb` (components.css lifts the
 * sheet by it and fits it into the visible height, `--fp-vvh`) and `data-kb` (the actions sit side by side, leaving
 * the form its room). Otherwise the sheet keeps its normal place and size. A field focused while the keyboard opens
 * is scrolled into view with its label, help and error once the viewport has settled. Coarse pointers only.
 * @param {HTMLElement} sheet the dialog element
 * @returns {() => void} removes the listeners
 */
function keyboardInset(sheet) {
  const vv = window.visualViewport;
  if (!vv || !matchMedia('(pointer: coarse)').matches) return () => {};
  const sync = () => {
    const loss = Math.round(window.innerHeight - vv.height - vv.offsetTop);
    const el = document.activeElement;
    const kb = loss >= KEYBOARD_MIN && vv.scale < 1.05 && sheet.contains(el) && typesText(el) ? loss : 0;
    sheet.style.setProperty('--fp-kb', `${kb}px`);
    sheet.style.setProperty('--fp-vvh', `${Math.round(vv.height)}px`);
    sheet.toggleAttribute('data-kb', kb > 0);
  };
  // focus leaving a field (iOS's ✓ blurs it) may come without a viewport resize; activeElement settles afterwards
  const onBlur = () => window.setTimeout(sync, 0);
  /** @type {Set<() => void>} pending "reveal the focused field" callbacks */
  const pending = new Set();
  /** @param {FocusEvent} e */
  const onFocus = (e) => {
    sync(); // a field focused while the keyboard is already up: no resize comes
    const t = e.target;
    if (!(t instanceof HTMLInputElement || t instanceof HTMLSelectElement || t instanceof HTMLTextAreaElement)) return;
    let timer = 0;
    const reveal = () => {
      if (!pending.delete(reveal)) return;
      vv.removeEventListener('resize', reveal);
      clearTimeout(timer);
      if (!t.isConnected || document.activeElement !== t) return;
      // the whole field (label, strength meter, error), then the control itself should the field not fit
      t.closest('.field')?.scrollIntoView({ block: 'nearest' });
      t.scrollIntoView({ block: 'nearest' });
    };
    pending.add(reveal);
    vv.addEventListener('resize', reveal); // after sync (registered first): the sheet has its new size
    timer = window.setTimeout(reveal, 300); // the keyboard was already open: no resize comes
  };
  vv.addEventListener('resize', sync);
  vv.addEventListener('scroll', sync);
  sheet.addEventListener('focusin', onFocus);
  sheet.addEventListener('focusout', onBlur);
  sync();
  return () => {
    vv.removeEventListener('resize', sync);
    vv.removeEventListener('scroll', sync);
    sheet.removeEventListener('focusin', onFocus);
    sheet.removeEventListener('focusout', onBlur);
    for (const fn of [...pending]) {
      pending.delete(fn);
      vv.removeEventListener('resize', fn);
    }
    sheet.style.removeProperty('--fp-kb');
    sheet.style.removeProperty('--fp-vvh');
    sheet.removeAttribute('data-kb');
  };
}

/**
 * @param {DialogOpts} opts
 * @returns {DialogHandle}
 */
export function dialog(opts) {
  const titleId = uniqueId('dlg-title');
  const dismissible = opts.dismissible !== false;
  /** @type {any} */
  let result;
  /** @type {Element | null} */
  let returnFocus = null;
  /** @type {(() => void) | null} */
  let untrap = null;
  /** @type {(() => void) | null} */
  let offNav = null;
  /** @type {(() => void) | null} */
  let stopInset = null;
  let isOpen = false;

  const titleEl = h('h2', { class: 'dialog-title', id: titleId, text: opts.title });
  const bodyEl = h('div', { class: 'dialog-body' });
  append(bodyEl, opts.body);
  const actionsEl = h('div', { class: 'dialog-actions' });

  const el = h('dialog', {
    class: ['dialog', `dialog--${opts.size || 'md'}`, opts.class || ''],
    // closedby="none": Chrome closes a modal on a second Escape without firing `cancel` (close-watcher abuse
    // protection), so preventDefault() alone cannot keep a non-dismissible dialog open.
    attrs: { 'aria-labelledby': titleId, 'aria-modal': 'true', closedby: dismissible ? null : 'none' },
    dataset: { dismissible: dismissible || null },
  },
  h('div', { class: 'dialog-head' },
    titleEl,
    dismissible && !opts.hideClose
      ? h('button', {
        class: 'icon-btn icon-btn--sm',
        attrs: { type: 'button', 'aria-label': 'Close', title: 'Close' },
        on: { click: () => handle.close(undefined) },
      }, icon('x'))
      : null),
  bodyEl);

  /** @type {HTMLElement | null} */
  let autoFocusBtn = null;
  for (const a of opts.actions || []) {
    if (a instanceof Element) {
      actionsEl.appendChild(a);
      continue;
    }
    const spec = a;
    const btn = button({
      label: spec.label,
      variant: spec.variant || 'secondary',
      icon: spec.icon,
      type: spec.type || 'button',
      onClick: async (e) => {
        if (!spec.onClick) {
          if (spec.close !== false) handle.close(spec.value);
          return;
        }
        let r;
        try {
          r = await spec.onClick(e);
        } catch (err) {
          console.error(err);
          return; // keep open on failure; the handler shows its own error
        }
        if (r !== false && spec.close !== false) handle.close(spec.value !== undefined ? spec.value : r);
      },
    });
    if (spec.autofocus) autoFocusBtn = btn;
    actionsEl.appendChild(btn);
  }
  if (actionsEl.childElementCount) el.appendChild(actionsEl);

  el.addEventListener('cancel', (e) => {
    e.preventDefault();
    if (dismissible) handle.close(undefined);
  });
  el.addEventListener('mousedown', (e) => {
    // backdrop click: the event target is the <dialog> itself (content is inside child elements)
    if (dismissible && e.target === el) {
      const r = el.getBoundingClientRect();
      const inside = e.clientX >= r.left && e.clientX <= r.right && e.clientY >= r.top && e.clientY <= r.bottom;
      if (!inside) handle.close(undefined);
    }
  });
  // phones show dialogs as bottom sheets: dragging the header down dismisses them like a sheet
  const drag = dismissible ? dragToDismiss(el, { handles: '.dialog-head', onDismiss: () => handle.close(undefined), when: isMobile }) : null;
  let closingByApi = false;
  el.addEventListener('close', () => {
    if (!isOpen) return;
    if (!dismissible && !closingByApi && el.isConnected) {
      // browsers without `closedby` support closed it on a repeated Escape: keep it open
      el.showModal();
      return;
    }
    closingByApi = false;
    isOpen = false;
    if (offNav) offNav();
    offNav = null;
    drag?.reset();
    stopInset?.();
    stopInset = null;
    if (untrap) untrap();
    untrap = null;
    releaseToasts(el);
    el.remove();
    if (returnFocus instanceof HTMLElement && returnFocus.isConnected) returnFocus.focus({ preventScroll: true });
    if (opts.onClose) {
      try {
        opts.onClose(result);
      } catch (err) {
        console.error(err);
      }
    }
  });

  /** @type {DialogHandle} */
  const handle = {
    el,
    body: bodyEl,
    actions: actionsEl,
    open() {
      if (isOpen) return handle;
      isOpen = true;
      result = undefined;
      returnFocus = document.activeElement;
      // close() (not el.close()) so a non-dismissible dialog is really closed and onClose still resolves
      offNav = dismissOnNavigate(() => handle.close(undefined));
      document.body.appendChild(el);
      el.showModal();
      stopInset = keyboardInset(el);
      untrap = trapFocus(el);
      const target = /** @type {HTMLElement | null} */ (
        el.querySelector('[autofocus]') ||
        autoFocusBtn ||
        bodyEl.querySelector('input:not([type=hidden]):not([disabled]), textarea, select') ||
        focusable(actionsEl).pop() ||
        focusable(el)[0] ||
        null
      );
      if (target) target.focus();
      claimToasts(); // after showModal()/focus(): the region must move into *this* dialog, and never take focus
      return handle;
    },
    close(value) {
      if (!isOpen) return;
      result = value;
      closingByApi = true;
      el.close();
    },
    setTitle(t) {
      titleEl.textContent = t;
    },
  };
  return handle;
}

/**
 * Yes/no confirmation. Resolves true when confirmed.
 * @param {{title: string, message?: import('../core/dom.js').Child, danger?: boolean, confirmLabel?: string, cancelLabel?: string}} opts
 * @returns {Promise<boolean>}
 */
export function confirm(opts) {
  return new Promise((resolve) => {
    const body = typeof opts.message === 'string' ? h('p', { text: opts.message }) : opts.message;
    dialog({
      title: opts.title,
      body,
      size: 'sm',
      onClose: (v) => resolve(v === true),
      actions: [
        { label: opts.cancelLabel || 'Cancel', variant: 'ghost', value: false, autofocus: !!opts.danger },
        { label: opts.confirmLabel || (opts.danger ? 'Delete' : 'Confirm'), variant: opts.danger ? 'danger' : 'primary', value: true, autofocus: !opts.danger },
      ],
    }).open();
  });
}

/**
 * Single-value text prompt. Resolves the trimmed string, or null when cancelled.
 * @param {{title: string, label: string, value?: string, confirmLabel?: string, placeholder?: string, help?: string,
 *   type?: string, required?: boolean, selectBaseName?: boolean, validate?: (v: string) => string | null}} opts
 *   selectBaseName: pre-select the name without its extension (rename dialogs)
 * @returns {Promise<string | null>}
 */
export function prompt(opts) {
  return new Promise((resolve) => {
    const id = uniqueId('prm');
    const input = h('input', {
      id,
      attrs: { type: opts.type || 'text', placeholder: opts.placeholder || null, autocomplete: 'off', spellcheck: 'false', required: opts.required !== false },
      value: opts.value || '',
    });
    const err = h('p', { class: 'field-error', id: `${id}-err`, attrs: { 'aria-live': 'polite' } });
    input.setAttribute('aria-describedby', `${id}-err`);
    const formEl = h('form', { class: 'field', attrs: { novalidate: true } },
      h('label', { class: 'field-label', for: id, text: opts.label }),
      input,
      opts.help ? h('p', { class: 'field-help', text: opts.help }) : null,
      err);

    const submit = () => {
      const v = input.value.trim();
      const msg = opts.required !== false && !v ? 'Please enter a value.' : opts.validate ? opts.validate(v) : null;
      if (msg) {
        err.textContent = msg;
        input.setAttribute('aria-invalid', 'true');
        input.focus();
        return false;
      }
      d.close(v);
      return true;
    };
    formEl.addEventListener('submit', (e) => {
      e.preventDefault();
      submit();
    });
    input.addEventListener('input', () => {
      err.textContent = '';
      input.removeAttribute('aria-invalid');
    });

    const d = dialog({
      title: opts.title,
      body: formEl,
      size: 'sm',
      onClose: (v) => resolve(typeof v === 'string' ? v : null),
      actions: [
        { label: 'Cancel', variant: 'ghost' },
        { label: opts.confirmLabel || 'OK', variant: 'primary', onClick: () => { submit(); return false; } },
      ],
    });
    d.open();
    input.focus();
    if (opts.selectBaseName && opts.value) {
      const dot = opts.value.lastIndexOf('.');
      input.setSelectionRange(0, dot > 0 ? dot : opts.value.length);
    } else {
      input.select();
    }
  });
}
