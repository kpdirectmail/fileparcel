// @ts-check
/**
 * fileView(opts) → FileView — the virtualised file list/grid used by My files, Shared with me, Starred, Recent,
 * Search and Trash (§13.5 "File view").
 *
 *   const fv = fileView({mode: 'list', columns: ['size', 'updated'], sort: {key: 'name', desc: false},
 *                        onSort, onOpen, menuItems, onDelete, onRename, onDrop, onSelectionChange, empty});
 *   fv.setItems(nodes);  fv.selected();  fv.select([id]);  fv.focusItem(id);  fv.setMode('grid');  fv.destroy();
 *
 * Interaction model
 *   mouse     click selects one · Ctrl/⌘-click toggles · Shift-click selects a range · double-click opens ·
 *             the checkbox (hover) toggles · ⋮ opens the actions menu · right-click opens the context menu ·
 *             middle-click opens a folder in a new tab · drag rows onto a folder row (or any `acceptNodeDrop` target)
 *             to move them (desktop pointers only)
 *   touch     tap opens · ⋮ opens the actions sheet · a long-press opens it too and starts selection mode (as does
 *             the sheet's "Select" entry), in which taps toggle items (the page shows a sticky selection bar)
 *   keyboard  ↑/↓ (and ←/→ in the grid) move and select · Shift+arrows extend · Ctrl+arrows move without selecting ·
 *             Space toggles · Home/End/PageUp/PageDown · Enter opens · Delete trashes · F2 renames · Ctrl/⌘+A selects
 *             all · Esc clears · Shift+F10 / ContextMenu key opens the actions menu
 * The list is an ARIA listbox (aria-multiselectable) with a roving tabindex; only the visible rows exist in the DOM
 * (components/virtual-list.js, window scrolling). Thumbnails come from GET /nodes/{id}/thumb (lazy <img>).
 * @module components/file-view
 */
import { h, icon, uniqueId } from '../core/dom.js';
import { bytes, relTime, dateTime, fileIcon, number } from '../core/format.js';
import { thumbURL, locationLabel, typeLabel, zipProtectionLabel } from '../core/nodes.js';
import { virtualList } from './virtual-list.js';
import { contextMenu, menu } from './menu.js';

/** MIME type used for in-app drags of nodes (never "Files", so the upload drop overlay ignores them). */
export const NODE_DRAG_TYPE = 'application/x-fp-nodes';

/**
 * @typedef {import('../core/nodes.js').Node} Node
 * @typedef {import('./menu.js').MenuItem} MenuItem
 * @typedef {'location' | 'size' | 'updated' | 'trashed'} ColumnId
 */

/**
 * @typedef {Object} FileViewOpts
 * @property {'list' | 'grid'} [mode]
 * @property {ColumnId[]} [columns] list columns after the name (default size, updated)
 * @property {{key: string, desc: boolean} | null} [sort] current sort (header indicator)
 * @property {(key: string, desc: boolean) => void} [onSort] header sort clicks (omit to disable header sorting)
 * @property {(node: Node, index: number, e: Event | null) => void} [onOpen]
 * @property {(nodes: Node[]) => MenuItem[]} [menuItems] actions for the selection (⋮, right-click, long-press)
 * @property {() => MenuItem[] | null} [backgroundMenu] context menu on empty space
 * @property {(nodes: Node[]) => void} [onDelete] Delete key
 * @property {(node: Node) => void} [onRename] F2
 * @property {(nodes: Node[], folder: Node) => void} [onDrop] drag-to-move onto a folder row
 * @property {(nodes: Node[]) => void} [onSelectionChange]
 * @property {() => Element} [empty] shown when there are no items
 * @property {string} [label] accessible name of the listbox
 * @property {() => import('../core/nodes.js').Space[]} [spaces] for the location column
 * @property {boolean} [selectable] default true
 */

/** @param {string} prop @param {HTMLElement} el @param {number} fallback */
function cssPx(prop, el, fallback) {
  const v = parseFloat(getComputedStyle(el).getPropertyValue(prop));
  return Number.isFinite(v) && v > 0 ? v : fallback;
}

const COLUMN_LABELS = { location: 'Location', size: 'Size', updated: 'Modified', trashed: 'Deleted' };
const SORT_KEYS = { name: 'name', size: 'size', updated: 'updated', trashed: 'trashed' };

/** True for the primary pointer being coarse (phones/tablets). */
const coarse = () => window.matchMedia('(pointer: coarse)').matches;

/**
 * @param {FileViewOpts} opts
 */
export function fileView(opts) {
  let mode = opts.mode === 'grid' ? 'grid' : 'list';
  const columns = /** @type {ColumnId[]} */ (opts.columns || ['size', 'updated']);
  let sort = opts.sort || null;
  const selectable = opts.selectable !== false;
  /** @type {Node[]} */
  let items = [];
  /** @type {Map<string, number>} */
  let indexOf = new Map();
  /** @type {Set<string>} */
  const selected = new Set();
  let anchor = -1;
  let cursor = 0;
  let loading = true;
  let selecting = false; // touch selection mode
  let lastPointer = 'mouse';
  const hintId = uniqueId('fv-hint');

  const el = h('div', { class: 'fv', dataset: { mode, cols: columns.join(' ') } });
  const head = h('div', { class: 'fv-head', attrs: { role: 'presentation' } });
  const emptySlot = h('div', { class: 'fv-empty', hidden: true });
  const loadingEl = h('div', { class: 'fv-loading', attrs: { 'aria-hidden': 'true' } },
    Array.from({ length: 6 }, () => h('div', { class: 'fv-skel' }, h('span', { class: 'fv-skel-icon' }), h('span', { class: 'fv-skel-line' }))));
  const hint = h('p', { class: 'sr-only', id: hintId, text: 'Use arrow keys to move, Space to select, Enter to open, Shift+F10 for actions.' });

  const gridCols = () => {
    const w = el.clientWidth;
    const min = cssPx('--fv-cell-min', el, 168);
    return Math.max(2, Math.floor((w || window.innerWidth) / min));
  };
  const rowHeight = () => (mode === 'grid' ? cssPx('--fv-cell-h', el, 212) : cssPx('--fv-row-h', el, 52));

  /** @type {ReturnType<typeof virtualList>} */
  const vl = virtualList({
    rowHeight,
    count: 0,
    overscan: 8,
    window: true,
    role: 'listbox',
    label: opts.label || 'Files',
    class: 'fv-list',
    columns: () => (mode === 'grid' ? gridCols() : 1),
    render: renderItem,
    // The cursor row is the listbox's only tab stop (roving tabindex): keep it rendered while it is scrolled out of
    // view, or Tab/Shift+Tab would skip the whole list.
    keep: () => (items.length ? cursor : -1),
    scrollMargin: () => ({
      top: cssPx('--fp-topbar-h', el, 60) + (mode === 'list' ? head.offsetHeight : 0) + 8,
      bottom: (window.matchMedia('(max-width: 639px)').matches ? cssPx('--fp-tabbar-h', el, 64) : 0) + 72,
    }),
  });
  vl.el.setAttribute('aria-multiselectable', 'true');
  vl.el.setAttribute('aria-describedby', hintId);
  vl.el.setAttribute('aria-busy', 'true');
  el.append(hint, head, loadingEl, vl.el, emptySlot);

  // ---------------------------------------------------------------- header (list mode)
  /** @type {HTMLInputElement | null} */
  let checkAll = null;
  function renderHead() {
    head.replaceChildren();
    if (mode !== 'list') {
      head.hidden = true;
      return;
    }
    head.hidden = false;
    if (selectable) {
      checkAll = h('input', {
        attrs: { type: 'checkbox', 'aria-label': 'Select all' },
        on: { change: () => (checkAll?.checked ? selectAll() : clearSelection()) },
      });
      head.appendChild(h('label', { class: 'check-hit fv-check' }, checkAll));
    } else {
      head.appendChild(h('span'));
    }
    head.appendChild(sortButton('name', 'Name', 'fv-hname'));
    for (const c of columns) head.appendChild(sortButton(SORT_KEYS[c] || '', COLUMN_LABELS[c], `fv-col fv-col--${c}`, c === 'location'));
    head.appendChild(h('span', { class: 'fv-hmore' }));
    syncHead();
  }

  /**
   * @param {string} key @param {string} label @param {string} cls @param {boolean} [noSort]
   */
  function sortButton(key, label, cls, noSort = false) {
    if (!opts.onSort || noSort || !key) return h('span', { class: `fv-hcell ${cls}`, text: label });
    const active = sort && sort.key === key;
    return h('button', {
      class: `fv-hcell fv-sort ${cls}`,
      attrs: {
        type: 'button',
        'aria-label': `Sort by ${label.toLowerCase()}${active ? (sort?.desc ? ', currently descending' : ', currently ascending') : ''}`,
      },
      dataset: { key, active: active ? '' : null },
      on: {
        click: () => {
          const desc = sort && sort.key === key ? !sort.desc : key === 'updated' || key === 'size' || key === 'trashed';
          sort = { key, desc };
          renderHead();
          opts.onSort?.(key, desc);
        },
      },
    }, h('span', { text: label }), active ? icon(sort?.desc ? 'arrow-down' : 'arrow-up', { size: 14 }) : null);
  }

  function syncHead() {
    if (!checkAll) return;
    checkAll.checked = items.length > 0 && selected.size === items.length;
    checkAll.indeterminate = selected.size > 0 && selected.size < items.length;
  }

  // ---------------------------------------------------------------- rows
  /** @param {Node} n @param {number} size icon size (px) when there is no thumbnail */
  function thumbOrIcon(n, size) {
    const wrap = h('span', { class: 'fv-icon', dataset: { kind: n.kind, type: fileIcon(n) } });
    if (n.has_thumb) {
      const img = h('img', {
        class: 'fv-thumb-img',
        src: thumbURL(n),
        alt: '',
        attrs: { loading: 'lazy', decoding: 'async', draggable: 'false' },
      });
      img.addEventListener('error', () => img.replaceWith(icon(fileIcon(n), { size })), { once: true });
      wrap.dataset.thumb = '';
      wrap.appendChild(img);
    } else {
      wrap.appendChild(icon(fileIcon(n), { size }));
    }
    return wrap;
  }

  /** @param {Node} n */
  function sizeText(n) {
    if (n.kind === 'folder') {
      const c = n.child_count;
      return typeof c === 'number' ? (c === 1 ? '1 item' : `${number(c)} items`) : '—';
    }
    return bytes(n.size);
  }

  /** @param {Node} n @param {ColumnId} c */
  function columnCell(n, c) {
    if (c === 'size') return h('span', { class: 'fv-col fv-col--size tabular', text: sizeText(n) });
    if (c === 'updated') return h('span', { class: 'fv-col fv-col--updated', attrs: { title: dateTime(n.updated_at) }, text: relTime(n.updated_at) });
    if (c === 'trashed') return h('span', { class: 'fv-col fv-col--trashed', attrs: { title: dateTime(n.trashed_at) }, text: relTime(n.trashed_at) });
    const loc = locationLabel(n, opts.spaces ? opts.spaces() : []);
    return h('span', { class: 'fv-col fv-col--location', attrs: { title: loc }, text: loc });
  }

  /** Secondary line under the name (narrow layouts) @param {Node} n */
  function metaLine(n) {
    const parts = [];
    if (columns.includes('location')) parts.push(locationLabel(n, opts.spaces ? opts.spaces() : []));
    if (columns.includes('trashed') && n.trashed_at) parts.push(`Deleted ${relTime(n.trashed_at)}`);
    else parts.push(relTime(n.updated_at));
    if (n.kind === 'file') parts.unshift(bytes(n.size));
    else if (typeof n.child_count === 'number') parts.unshift(sizeText(n));
    return parts.join(' · ');
  }

  /** @param {Node} n */
  function checkbox(n) {
    if (!selectable) return null;
    return h('label', { class: 'check-hit fv-check', attrs: { 'aria-hidden': 'true' } },
      h('input', { attrs: { type: 'checkbox', tabindex: '-1' }, checked: selected.has(n.id) }));
  }

  /** @param {Node} n */
  function moreButton(n) {
    return h('button', {
      class: 'icon-btn icon-btn--sm fv-more',
      attrs: { type: 'button', tabindex: '-1', 'aria-hidden': 'true', title: `Actions for ${n.name}` },
    }, icon('more-vertical'));
  }

  /** @param {number} i */
  function renderItem(i) {
    const n = items[i];
    const isSel = selected.has(n.id);
    /** @type {HTMLElement} */
    let row;
    const lock = zipProtectionLabel(n);
    const badges = [
      n.starred ? h('span', { class: 'fv-badge fv-badge--star', attrs: { title: 'Starred' } }, icon('star', { size: 14, label: 'Starred' })) : null,
      lock ? h('span', { class: 'fv-badge fv-badge--lock', attrs: { title: lock } }, icon('lock', { size: 14, label: lock })) : null,
    ];
    if (mode === 'grid') {
      row = h('div', { class: 'fv-cell' },
        h('div', { class: 'fv-card' },
          h('div', { class: 'fv-cell-thumb', dataset: { kind: n.kind } }, thumbOrIcon(n, 44), checkbox(n), moreButton(n)),
          h('div', { class: 'fv-cell-text' },
            h('span', { class: 'fv-cell-name', attrs: { title: n.name } }, badges, h('span', { class: 'truncate', text: n.name })),
            h('span', { class: 'fv-cell-meta', text: n.kind === 'folder' ? (typeof n.child_count === 'number' ? sizeText(n) : 'Folder') : `${bytes(n.size)} · ${relTime(n.updated_at)}` }))));
    } else {
      row = h('div', { class: 'fv-row' },
        checkbox(n) || h('span'),
        h('span', { class: 'fv-name' },
          thumbOrIcon(n, 22),
          h('span', { class: 'fv-name-text' },
            h('span', { class: 'fv-name-main' }, h('span', { class: 'fv-name-label', attrs: { title: n.name }, text: n.name }), badges),
            h('span', { class: 'fv-name-meta', text: metaLine(n) }))),
        columns.map((c) => columnCell(n, c)),
        moreButton(n));
    }
    row.id = `${hintId}-o${i}`;
    row.setAttribute('role', 'option');
    row.setAttribute('aria-selected', String(isSel));
    row.setAttribute('aria-setsize', String(items.length));
    row.setAttribute('aria-posinset', String(i + 1));
    row.setAttribute('aria-label', `${n.name}, ${n.kind === 'folder' ? 'folder' : `${typeLabel(n)}, ${bytes(n.size)}`}${lock ? `, ${lock}` : ''}`);
    row.tabIndex = i === cursor ? 0 : -1;
    row.dataset.id = n.id;
    row.dataset.kind = n.kind;
    if (opts.onDrop && !coarse()) row.draggable = true;
    return row;
  }

  /** Re-sync selection attributes of the rendered rows (no re-render). */
  function syncRows() {
    for (let i = 0; i < items.length; i += 1) {
      const row = vl.nodeAt(i);
      if (!row) continue;
      const on = selected.has(items[i].id);
      row.setAttribute('aria-selected', String(on));
      row.tabIndex = i === cursor ? 0 : -1;
      const cb = /** @type {HTMLInputElement | null} */ (row.querySelector('.fv-check input'));
      if (cb) cb.checked = on;
    }
    syncHead();
    // Selection mode starts only explicitly (the checkbox, a long-press, setSelecting — the sheet's "Select"): a
    // selection made by ⋮, fv.select() or the keyboard on a touch device must not turn taps into toggles.
    selecting = selected.size > 0 && selecting;
    el.toggleAttribute('data-selecting', selecting);
    el.toggleAttribute('data-has-selection', selected.size > 0);
  }

  function emit() {
    syncRows();
    opts.onSelectionChange?.(selectedNodes());
  }

  /** @returns {Node[]} */
  function selectedNodes() {
    return items.filter((n) => selected.has(n.id));
  }

  /** @param {number} i @param {{focus?: boolean}} [o] */
  function setCursor(i, o = {}) {
    if (!items.length) return;
    const prev = cursor;
    cursor = Math.max(0, Math.min(items.length - 1, i));
    const old = vl.nodeAt(prev);
    if (old) old.tabIndex = -1;
    vl.scrollToIndex(cursor, { focus: o.focus !== false });
    const cur = vl.nodeAt(cursor);
    if (cur) cur.tabIndex = 0;
  }

  function selectAll() {
    for (const n of items) selected.add(n.id);
    emit();
  }

  function clearSelection() {
    if (!selected.size) return;
    selected.clear();
    anchor = -1;
    emit();
  }

  /** @param {number} a @param {number} b @param {boolean} additive */
  function selectRange(a, b, additive) {
    if (!additive) selected.clear();
    const [lo, hi] = a < b ? [a, b] : [b, a];
    for (let k = Math.max(0, lo); k <= hi && k < items.length; k += 1) selected.add(items[k].id);
  }

  /** @param {number} i */
  function toggle(i) {
    const id = items[i]?.id;
    if (!id) return;
    if (selected.has(id)) selected.delete(id);
    else selected.add(id);
    anchor = i;
  }

  /** @param {number} i */
  function selectOnly(i) {
    selected.clear();
    if (items[i]) selected.add(items[i].id);
    anchor = i;
  }

  /** @param {Event} e @returns {number} */
  function indexFromEvent(e) {
    const t = e.target instanceof Element ? e.target.closest('[role="option"]') : null;
    if (!t || !vl.el.contains(t)) return -1;
    const i = Number(/** @type {HTMLElement} */ (t).dataset.index);
    return Number.isInteger(i) ? i : -1;
  }

  /** Actions menu for the selection (selecting `i` first when it is not part of it). @param {number} i */
  function ensureSelected(i) {
    if (i >= 0 && !selected.has(items[i].id)) {
      selectOnly(i);
      cursor = i;
      emit();
    }
  }

  // ---------------------------------------------------------------- pointer
  vl.el.addEventListener('pointerdown', (e) => {
    lastPointer = e.pointerType === 'touch' || e.pointerType === 'pen' ? 'touch' : 'mouse';
  }, { passive: true });

  vl.el.addEventListener('click', (e) => {
    const i = indexFromEvent(e);
    if (i < 0) return;
    const t = /** @type {Element} */ (e.target);
    const touch = lastPointer === 'touch';
    if (t.closest('.fv-more')) {
      e.preventDefault();
      ensureSelected(i);
      cursor = i;
      openMenu(/** @type {HTMLElement} */ (t.closest('.fv-more')));
      return;
    }
    if (t.closest('.fv-check')) {
      // Cancel only the <label>'s default (it forwards a synthetic click to the input); state is
      // driven by `selected`. Cancelling a click on the <input> itself would make the browser run
      // the canceled-activation steps *after* this listener and restore the pre-click checkedness,
      // undoing the `cb.checked` that syncRows() sets — the row would look selected with an empty box.
      if (!(t instanceof HTMLInputElement)) e.preventDefault();
      if (!selectable) return;
      if (touch) selecting = true;
      if (e.shiftKey && anchor >= 0) selectRange(anchor, i, true);
      else toggle(i);
      cursor = i;
      emit();
      return;
    }
    if (touch) {
      if (selecting && selectable) {
        toggle(i);
        cursor = i;
        emit();
      } else {
        opts.onOpen?.(items[i], i, e);
      }
      return;
    }
    if (!selectable) {
      cursor = i;
      syncRows();
      return;
    }
    if (e.shiftKey && anchor >= 0) {
      selectRange(anchor, i, e.ctrlKey || e.metaKey);
    } else if (e.ctrlKey || e.metaKey) {
      toggle(i);
    } else {
      selectOnly(i);
    }
    cursor = i;
    emit();
  });

  vl.el.addEventListener('dblclick', (e) => {
    if (lastPointer === 'touch') return;
    const i = indexFromEvent(e);
    if (i < 0 || /** @type {Element} */ (e.target).closest('.fv-more, .fv-check')) return;
    opts.onOpen?.(items[i], i, e);
  });

  vl.el.addEventListener('auxclick', (e) => {
    if (e.button !== 1) return;
    const i = indexFromEvent(e);
    if (i < 0 || items[i].kind !== 'folder') return;
    e.preventDefault();
    window.open(`/files/${encodeURIComponent(items[i].id)}`, '_blank', 'noopener');
  });

  // context menu: right-click / long-press / ContextMenu key / Shift+F10
  const detachCtx = contextMenu(vl.el, (e) => {
    const i = indexFromEvent(e);
    if (i < 0) return opts.backgroundMenu ? opts.backgroundMenu() : null;
    ensureSelected(i);
    cursor = i;
    // A long-press also starts selection mode (Shift+F10 / the ContextMenu key on a tablet's keyboard does not).
    if (lastPointer === 'touch' && selectable && !(e instanceof KeyboardEvent)) selecting = true;
    syncRows();
    return opts.menuItems ? opts.menuItems(selectedNodes()) : null;
  }, {
    title: (e) => {
      if (indexFromEvent(e) < 0) return 'This folder';
      const sel = selectedNodes();
      return sel.length === 1 ? sel[0].name : `${number(sel.length)} items`;
    },
  });

  /** @param {HTMLElement} anchorEl */
  function openMenu(anchorEl) {
    const list = opts.menuItems ? opts.menuItems(selectedNodes()) : [];
    if (list.length) menu({ anchor: anchorEl, items: list, title: selected.size === 1 ? selectedNodes()[0]?.name : `${selected.size} items` });
  }

  // ---------------------------------------------------------------- keyboard
  vl.el.addEventListener('keydown', (e) => {
    const i = indexFromEvent(e);
    if (i < 0 || !items.length) return;
    const n = items[i];
    const mod = e.ctrlKey || e.metaKey;
    const cols = mode === 'grid' ? gridCols() : 1;
    const page = Math.max(1, Math.floor((window.innerHeight - 160) / rowHeight())) * cols;
    /** @type {number | null} */
    let target = null;
    switch (e.key) {
      case 'ArrowDown': target = i + cols; break;
      case 'ArrowUp': target = i - cols; break;
      case 'ArrowRight': if (mode === 'grid') target = i + 1; break;
      case 'ArrowLeft': if (mode === 'grid') target = i - 1; break;
      case 'Home': target = 0; break;
      case 'End': target = items.length - 1; break;
      case 'PageDown': target = i + page; break;
      case 'PageUp': target = i - page; break;
      case 'Enter':
        e.preventDefault();
        opts.onOpen?.(n, i, e);
        return;
      case ' ':
      case 'Spacebar':
        e.preventDefault();
        if (!selectable) return;
        if (e.shiftKey && anchor >= 0) selectRange(anchor, i, true);
        else toggle(i);
        emit();
        return;
      case 'Delete':
        if (opts.onDelete) {
          e.preventDefault();
          ensureSelected(i);
          opts.onDelete(selectedNodes());
        }
        return;
      case 'Backspace':
        if (mod && opts.onDelete) {
          e.preventDefault();
          ensureSelected(i);
          opts.onDelete(selectedNodes());
        }
        return;
      case 'F2':
        if (opts.onRename) {
          e.preventDefault();
          opts.onRename(n);
        }
        return;
      case 'Escape':
        if (selected.size) {
          e.preventDefault();
          e.stopPropagation();
          clearSelection();
        }
        return;
      default:
        if (mod && (e.key === 'a' || e.key === 'A') && selectable) {
          e.preventDefault();
          selectAll();
        }
        return;
    }
    if (target === null) return;
    e.preventDefault();
    target = Math.max(0, Math.min(items.length - 1, target));
    if (selectable && !mod) {
      if (e.shiftKey) {
        if (anchor < 0) anchor = i;
        const a = anchor;
        selectRange(a, target, false);
        anchor = a;
      } else {
        selectOnly(target);
      }
    }
    setCursor(target);
    if (selectable && !mod) emit();
    else syncRows();
  });

  // Focus entering the listbox lands on the cursor row (roving tabindex): virtualList keeps that row rendered (`keep`)
  // even when it is scrolled out of view, so it survives the rows being recycled.
  vl.el.addEventListener('focusin', (e) => {
    const i = indexFromEvent(e);
    if (i >= 0 && i !== cursor) {
      const old = vl.nodeAt(cursor);
      if (old) old.tabIndex = -1;
      cursor = i;
      /** @type {HTMLElement} */ (vl.nodeAt(i)).tabIndex = 0;
    }
  });

  // ---------------------------------------------------------------- drag to move (desktop)
  /** @type {HTMLElement | null} */
  let ghost = null;
  vl.el.addEventListener('dragstart', (e) => {
    const i = indexFromEvent(e);
    if (i < 0 || !opts.onDrop || !e.dataTransfer) return;
    ensureSelected(i);
    const nodes = selectedNodes();
    e.dataTransfer.effectAllowed = 'move';
    e.dataTransfer.setData(NODE_DRAG_TYPE, JSON.stringify(nodes.map((x) => x.id)));
    e.dataTransfer.setData('text/plain', nodes.map((x) => x.name).join('\n'));
    ghost = h('div', { class: 'fv-drag-ghost' }, icon(nodes.length === 1 ? fileIcon(nodes[0]) : 'copy', { size: 16 }),
      h('span', { text: nodes.length === 1 ? nodes[0].name : `${nodes.length} items` }));
    document.body.appendChild(ghost);
    e.dataTransfer.setDragImage(ghost, 14, 14);
    el.setAttribute('data-dragging', '');
  });
  vl.el.addEventListener('dragend', () => {
    ghost?.remove();
    ghost = null;
    el.removeAttribute('data-dragging');
    for (const x of vl.el.querySelectorAll('[data-drop-target]')) x.removeAttribute('data-drop-target');
  });
  vl.el.addEventListener('dragover', (e) => {
    const i = indexFromEvent(e);
    if (i < 0 || !isNodeDrag(e) || items[i].kind !== 'folder' || selected.has(items[i].id)) return;
    e.preventDefault();
    if (e.dataTransfer) e.dataTransfer.dropEffect = 'move';
    const row = /** @type {HTMLElement} */ (vl.nodeAt(i));
    row?.setAttribute('data-drop-target', '');
  });
  vl.el.addEventListener('dragleave', (e) => {
    const t = e.target instanceof Element ? e.target.closest('[data-drop-target]') : null;
    if (t && !t.contains(/** @type {Node | null} */ (/** @type {any} */ (e).relatedTarget))) t.removeAttribute('data-drop-target');
  });
  vl.el.addEventListener('drop', (e) => {
    const i = indexFromEvent(e);
    if (i < 0 || !isNodeDrag(e) || items[i].kind !== 'folder') return;
    e.preventDefault();
    const ids = readDraggedIds(e);
    const moving = ids.map((id) => items[indexOf.get(id) ?? -1]).filter(Boolean);
    vl.nodeAt(i)?.removeAttribute('data-drop-target');
    if (moving.length && !ids.includes(items[i].id)) opts.onDrop?.(moving, items[i]);
  });

  // grid: a column-count change is handled by virtualList; a width change within the same count needs no work
  renderHead();

  // ---------------------------------------------------------------- API
  const api = {
    el,
    /**
     * Replace the items. Selection is kept for ids that are still present (e.g. after a refresh).
     * @param {Node[]} next
     * @param {{keepCursor?: boolean}} [o]
     */
    setItems(next, o = {}) {
      const prevCursor = cursor;
      const prevId = items[cursor]?.id;
      items = next || [];
      indexOf = new Map(items.map((n, i) => [n.id, i]));
      for (const id of [...selected]) if (!indexOf.has(id)) selected.delete(id);
      if (o.keepCursor && prevId && indexOf.has(prevId)) cursor = /** @type {number} */ (indexOf.get(prevId));
      else if (!o.keepCursor) cursor = 0;
      cursor = Math.max(0, Math.min(cursor, items.length - 1));
      if (anchor >= items.length) anchor = -1;
      loading = false;
      loadingEl.hidden = true;
      vl.el.removeAttribute('aria-busy');
      const empty = items.length === 0;
      emptySlot.hidden = !empty;
      vl.el.hidden = empty;
      head.hidden = empty || mode !== 'list';
      if (empty && opts.empty) emptySlot.replaceChildren(opts.empty());
      // If the list had keyboard focus, it follows the cursor — i.e. the same item when keepCursor found it — not
      // whatever now sits at the old position (Delete/F2/Enter act on the focused row).
      vl.setCount(items.length, { focusIndex: cursor });
      if (cursor !== prevCursor && items.length && vl.el.contains(document.activeElement)) vl.scrollToIndex(cursor);
      emit();
    },
    /** @returns {Node[]} */
    items: () => items,
    /** Show the loading skeleton (until the next setItems). */
    setLoading() {
      loading = true;
      loadingEl.hidden = false;
      emptySlot.hidden = true;
      vl.el.setAttribute('aria-busy', 'true');
    },
    get loading() {
      return loading;
    },
    /** @param {'list' | 'grid'} m */
    setMode(m) {
      if (m === mode) return;
      mode = m;
      el.dataset.mode = m;
      renderHead();
      head.hidden = items.length === 0 || mode !== 'list';
      vl.refresh();
    },
    /** @param {string} key @param {boolean} desc */
    setSort(key, desc) {
      sort = { key, desc };
      renderHead();
    },
    selected: selectedNodes,
    /** @param {string[]} ids @param {{focus?: boolean}} [o] */
    select(ids, o = {}) {
      selected.clear();
      for (const id of ids) if (indexOf.has(id)) selected.add(id);
      const first = ids.map((id) => indexOf.get(id)).find((x) => x !== undefined);
      if (first !== undefined) {
        anchor = first;
        cursor = first;
        vl.scrollToIndex(first, { focus: !!o.focus, center: true });
      }
      emit();
    },
    selectAll,
    clearSelection,
    /** Focus the cursor row (or item `id`). @param {string} [id] */
    focusItem(id) {
      const i = id ? indexOf.get(id) : cursor;
      if (i === undefined || !items.length) return;
      setCursor(i);
    },
    /**
     * Replace one node in place (e.g. after star/rename) and re-render it.
     * @param {Node} node
     */
    update(node) {
      const i = indexOf.get(node.id);
      if (i === undefined) return;
      items[i] = { ...items[i], ...node };
      vl.refresh();
    },
    /** Enter/leave touch selection mode. @param {boolean} on */
    setSelecting(on) {
      selecting = on;
      lastPointer = on ? 'touch' : lastPointer;
      el.toggleAttribute('data-selecting', on);
      if (!on) clearSelection();
    },
    get selecting() {
      return selecting;
    },
    /** Scroll to the top of the list. */
    scrollTop() {
      window.scrollTo({ top: 0, behavior: 'instant' });
    },
    destroy() {
      detachCtx();
      vl.destroy();
      ghost?.remove();
    },
  };
  return api;
}

/** @param {DragEvent} e */
export function isNodeDrag(e) {
  return !!e.dataTransfer && Array.from(e.dataTransfer.types || []).includes(NODE_DRAG_TYPE);
}

/** @param {DragEvent} e @returns {string[]} */
export function readDraggedIds(e) {
  try {
    const ids = JSON.parse(e.dataTransfer?.getData(NODE_DRAG_TYPE) || '[]');
    return Array.isArray(ids) ? ids.filter((x) => typeof x === 'string') : [];
  } catch {
    return [];
  }
}

/**
 * Make `el` (a breadcrumb, a sidebar entry…) accept dragged nodes.
 * @param {HTMLElement} el
 * @param {(ids: string[], e: DragEvent) => void} onDrop
 * @returns {() => void} detach
 */
export function acceptNodeDrop(el, onDrop) {
  /** @param {DragEvent} e */
  const over = (e) => {
    if (!isNodeDrag(e)) return;
    e.preventDefault();
    if (e.dataTransfer) e.dataTransfer.dropEffect = 'move';
    el.setAttribute('data-drop-target', '');
  };
  const leave = () => el.removeAttribute('data-drop-target');
  /** @param {DragEvent} e */
  const drop = (e) => {
    if (!isNodeDrag(e)) return;
    e.preventDefault();
    leave();
    const ids = readDraggedIds(e);
    if (ids.length) onDrop(ids, e);
  };
  el.addEventListener('dragover', over);
  el.addEventListener('dragleave', leave);
  el.addEventListener('drop', drop);
  return () => {
    el.removeEventListener('dragover', over);
    el.removeEventListener('dragleave', leave);
    el.removeEventListener('drop', drop);
  };
}
