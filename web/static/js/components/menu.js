// @ts-check
/**
 * Popup menus.
 *   menu({anchor, items: [{label, icon, onClick, danger, disabled, divider}]}) → {el, close()}
 *   contextMenu(el, itemsFn) → detach()   // right-click, ContextMenu key / Shift+F10, long-press (500 ms) on touch
 * `anchor` is an Element (menu opens below it, flipping to fit) or a point {x, y}.
 * Keyboard: ↑/↓/Home/End move, Enter/Space activate, Escape closes and returns focus, typing a letter jumps
 * (global shortcuts are suppressed while focus is inside a role="menu", see core/keys.js).
 * The menu is attached to the top-most open modal <dialog> (or <body>), so it stays usable above modals.
 * On phones (< 640 px) the same items open as a bottom sheet.
 * contextMenu() adds the class `has-ctx` to `el` (CSS disables the iOS link callout / text selection on touch,
 * since iOS Safari fires no `contextmenu` event and a long-press would otherwise select text).
 * @module components/menu
 */
import { h, icon, isMobile, overlayHost } from '../core/dom.js';
import { sheet, sheetList } from './sheet.js';

/**
 * @typedef {Object} MenuItem
 * @property {string} [label]
 * @property {string} [icon]
 * @property {() => void} [onClick]
 * @property {boolean} [danger]
 * @property {boolean} [disabled]
 * @property {boolean} [divider]
 * @property {string} [href] in-app link
 * @property {string} [header] non-interactive caption row
 */

/** @type {{close: () => void} | null} */
let openMenu = null;

/**
 * @param {{anchor: Element | {x: number, y: number}, items: MenuItem[], title?: string, align?: 'start' | 'end'}} opts
 * @returns {{el: HTMLElement, close: () => void}}
 */
export function menu(opts) {
  if (openMenu) openMenu.close();
  const items = (opts.items || []).filter(Boolean);

  if (isMobile()) {
    const s = sheet({
      title: opts.title || (opts.anchor instanceof Element ? opts.anchor.getAttribute('aria-label') || 'Actions' : 'Actions'),
      content: null,
      onClose: () => {
        if (openMenu === handleM) openMenu = null;
        if (opts.anchor instanceof Element) opts.anchor.setAttribute('aria-expanded', 'false');
      },
    });
    s.body.appendChild(sheetList(items.map((i) => (i.header ? { section: i.header } : i)), () => s.close()));
    if (opts.anchor instanceof Element) opts.anchor.setAttribute('aria-expanded', 'true');
    s.open();
    const handleM = { el: /** @type {HTMLElement} */ (s.el), close: () => s.close() };
    openMenu = handleM;
    return handleM;
  }

  /** @type {HTMLButtonElement[]} */
  const buttons = [];
  const el = h('div', { class: 'menu', attrs: { role: 'menu', tabindex: '-1' } });
  if (opts.anchor instanceof Element && opts.anchor.id) el.setAttribute('aria-labelledby', opts.anchor.id);
  else if (opts.title) el.setAttribute('aria-label', opts.title);

  for (const it of items) {
    if (it.divider) {
      el.appendChild(h('div', { class: 'menu-divider', attrs: { role: 'separator' } }));
      continue;
    }
    if (it.header) {
      el.appendChild(h('div', { class: 'menu-header', attrs: { role: 'presentation' }, text: it.header }));
      continue;
    }
    const b = h('button', {
      class: 'menu-item',
      attrs: { type: 'button', role: 'menuitem', tabindex: '-1' },
      dataset: { danger: it.danger || null },
      disabled: !!it.disabled,
      on: {
        click: () => {
          close(true);
          if (it.href) {
            import('../core/router.js').then((r) => r.navigate(/** @type {string} */ (it.href)));
          } else {
            it.onClick?.();
          }
        },
      },
    }, it.icon ? icon(it.icon) : null, h('span', { text: it.label || '' }));
    buttons.push(b);
    el.appendChild(b);
  }

  const anchorEl = opts.anchor instanceof Element ? opts.anchor : null;
  let closed = false;

  /** @param {boolean} [restoreFocus] */
  function close(restoreFocus = false) {
    if (closed) return;
    closed = true;
    el.remove();
    document.removeEventListener('pointerdown', onOutside, true);
    window.removeEventListener('resize', onWindowChange);
    window.removeEventListener('scroll', onWindowChange, true);
    if (anchorEl) anchorEl.setAttribute('aria-expanded', 'false');
    if (restoreFocus && anchorEl instanceof HTMLElement) anchorEl.focus({ preventScroll: true });
    if (openMenu === handle) openMenu = null;
  }

  /** @param {PointerEvent} e */
  function onOutside(e) {
    const t = /** @type {Node} */ (e.target);
    if (el.contains(t)) return;
    if (anchorEl && anchorEl.contains(t)) {
      // clicking the anchor again toggles the menu closed; swallow the click that would re-open it
      e.stopPropagation();
      const swallow = (/** @type {Event} */ ev) => { ev.stopImmediatePropagation(); ev.preventDefault(); };
      anchorEl.addEventListener('click', swallow, { capture: true, once: true });
      setTimeout(() => anchorEl.removeEventListener('click', swallow, { capture: true }), 400);
    }
    close(false);
  }
  function onWindowChange(/** @type {Event} */ e) {
    if (e.type === 'scroll' && e.target instanceof Node && el.contains(e.target)) return;
    close(false);
  }

  /** @param {number} i */
  const focusAt = (i) => {
    const enabled = buttons.filter((b) => !b.disabled);
    if (!enabled.length) return;
    const j = ((i % enabled.length) + enabled.length) % enabled.length;
    enabled[j].focus();
  };
  const currentIndex = () => buttons.filter((b) => !b.disabled).indexOf(/** @type {any} */ (document.activeElement));

  el.addEventListener('keydown', (e) => {
    switch (e.key) {
      case 'ArrowDown': e.preventDefault(); focusAt(currentIndex() + 1); break;
      case 'ArrowUp': e.preventDefault(); focusAt(currentIndex() - 1); break;
      case 'Home': e.preventDefault(); focusAt(0); break;
      case 'End': e.preventDefault(); focusAt(-1); break;
      case 'Escape': e.preventDefault(); e.stopPropagation(); close(true); break;
      case 'Tab': close(true); break;
      default:
        if (e.key.length === 1 && /\S/.test(e.key) && !e.ctrlKey && !e.metaKey && !e.altKey) {
          const enabled = buttons.filter((b) => !b.disabled);
          const start = currentIndex() + 1;
          for (let k = 0; k < enabled.length; k += 1) {
            const b = enabled[(start + k) % enabled.length];
            if ((b.textContent || '').trim().toLowerCase().startsWith(e.key.toLowerCase())) {
              b.focus();
              break;
            }
          }
        }
    }
  });

  // Everything outside a modal <dialog> is inert, so a menu opened from inside one must live inside it.
  overlayHost().appendChild(el);
  position(el, opts.anchor, opts.align);
  if (anchorEl) {
    anchorEl.setAttribute('aria-expanded', 'true');
    if (!anchorEl.hasAttribute('aria-haspopup')) anchorEl.setAttribute('aria-haspopup', 'menu');
  }
  focusAt(0);
  // register listeners after the opening event finished propagating
  setTimeout(() => {
    if (closed) return;
    document.addEventListener('pointerdown', onOutside, true);
    window.addEventListener('resize', onWindowChange);
    window.addEventListener('scroll', onWindowChange, true);
  }, 0);

  const handle = { el, close: () => close(false) };
  openMenu = handle;
  return handle;
}

/**
 * Place a fixed-position menu next to an anchor, keeping it inside the viewport.
 * @param {HTMLElement} el
 * @param {Element | {x: number, y: number}} anchor
 * @param {'start' | 'end'} [align]
 */
function position(el, anchor, align) {
  const vw = document.documentElement.clientWidth;
  const vh = window.innerHeight;
  const m = el.getBoundingClientRect();
  const gap = 4;
  let x;
  let y;
  if (anchor instanceof Element) {
    const r = anchor.getBoundingClientRect();
    const rtl = getComputedStyle(anchor).direction === 'rtl';
    const alignEnd = align ? align === 'end' : rtl;
    x = alignEnd ? r.right - m.width : r.left;
    if (x + m.width > vw - 8) x = r.right - m.width;
    y = r.bottom + gap;
    if (y + m.height > vh - 8 && r.top - gap - m.height > 8) y = r.top - gap - m.height;
  } else {
    x = anchor.x;
    y = anchor.y;
    if (x + m.width > vw - 8) x = anchor.x - m.width;
    if (y + m.height > vh - 8) y = Math.max(8, anchor.y - m.height);
  }
  x = Math.max(8, Math.min(x, vw - m.width - 8));
  y = Math.max(8, Math.min(y, vh - m.height - 8));
  el.style.setProperty('left', `${Math.round(x)}px`);
  el.style.setProperty('top', `${Math.round(y)}px`);
}

/**
 * Swallow the click that a touch long-press produces when the finger lifts (it would otherwise land on whatever the
 * menu/sheet put under the finger, e.g. the sheet backdrop, and close it at once). Listens on `document` in the
 * capture phase; the listener is dropped after one click, when a new gesture starts (next pointerdown — some
 * browsers send no click after a long-press) or after a safety timeout.
 */
function swallowNextClick() {
  /** @param {Event} ev */
  const swallow = (ev) => {
    ev.preventDefault();
    ev.stopImmediatePropagation();
    off();
  };
  const off = () => {
    document.removeEventListener('click', swallow, true);
    document.removeEventListener('pointerdown', off, true);
    window.clearTimeout(timer);
  };
  document.addEventListener('click', swallow, true);
  document.addEventListener('pointerdown', off, true);
  const timer = window.setTimeout(off, 3000);
}

/**
 * Attach a context menu to `el`. `itemsFn(event)` returns the items (or null for no menu).
 * `opts.title(event)` names the menu (the bottom-sheet heading on phones), e.g. the file that was long-pressed; it is
 * called after itemsFn.
 * @param {HTMLElement} el
 * @param {(e: Event) => MenuItem[] | null | undefined} itemsFn
 * @param {{title?: (e: Event) => string}} [opts]
 * @returns {() => void} detach
 */
export function contextMenu(el, itemsFn, opts = {}) {
  let timer = 0;
  let startX = 0;
  let startY = 0;
  let longPressAt = 0;
  let pressing = false; // a touch/pen pointer is down on `el`
  el.classList.add('has-ctx');

  /** @param {Event} e @param {Element | {x: number, y: number}} anchor */
  const open = (e, anchor) => {
    const items = itemsFn(e);
    if (!items || !items.length) return false;
    menu({ anchor, items, title: opts.title ? opts.title(e) : undefined });
    return true;
  };

  const cancel = () => {
    window.clearTimeout(timer);
    timer = 0;
  };

  /** @param {MouseEvent} e */
  const onContext = (e) => {
    // the long-press timer already opened the menu for this gesture
    if (Date.now() - longPressAt < 800) {
      e.preventDefault();
      return;
    }
    // Android fires `contextmenu` for a touch long-press (~400 ms), before our 500 ms timer: open once, here.
    const touch = pressing || /** @type {any} */ (e).pointerType === 'touch' || /** @type {any} */ (e).pointerType === 'pen';
    cancel();
    if (open(e, { x: e.clientX, y: e.clientY })) {
      e.preventDefault();
      if (touch) {
        longPressAt = Date.now();
        swallowNextClick();
      }
    }
  };
  /** @param {PointerEvent} e */
  const onDown = (e) => {
    if (e.pointerType !== 'touch' && e.pointerType !== 'pen') return;
    pressing = true;
    startX = e.clientX;
    startY = e.clientY;
    cancel();
    timer = window.setTimeout(() => {
      timer = 0;
      longPressAt = Date.now();
      if (open(e, { x: startX, y: startY })) swallowNextClick();
    }, 500);
  };
  /** @param {PointerEvent} e */
  const onMove = (e) => {
    if (timer && (Math.abs(e.clientX - startX) > 10 || Math.abs(e.clientY - startY) > 10)) cancel();
  };
  const onUp = () => {
    pressing = false;
    cancel();
  };
  /** @param {KeyboardEvent} e */
  const onKey = (e) => {
    if (e.key === 'ContextMenu' || (e.key === 'F10' && e.shiftKey)) {
      const target = e.target instanceof Element ? e.target : el;
      if (open(e, target)) e.preventDefault();
    }
  };

  el.addEventListener('contextmenu', onContext);
  el.addEventListener('pointerdown', onDown);
  el.addEventListener('pointermove', onMove);
  el.addEventListener('pointerup', onUp);
  el.addEventListener('pointercancel', onUp);
  el.addEventListener('pointerleave', onUp);
  el.addEventListener('keydown', onKey);
  return () => {
    cancel();
    el.classList.remove('has-ctx');
    el.removeEventListener('contextmenu', onContext);
    el.removeEventListener('pointerdown', onDown);
    el.removeEventListener('pointermove', onMove);
    el.removeEventListener('pointerup', onUp);
    el.removeEventListener('pointercancel', onUp);
    el.removeEventListener('pointerleave', onUp);
    el.removeEventListener('keydown', onKey);
  };
}
