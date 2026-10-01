// @ts-check
/**
 * Building blocks shared by the file-browser pages (My files, Shared with me, Starred, Recent, Search, Trash):
 *   selectionBar({actions, context, onClear, extra})  → {el, update(nodes)}   sticky bar for the current selection
 *   viewToggle(mode, onChange)                        → element   list / grid segmented control
 *   sortButton(sort, keys, onChange)                  → element   "Sort: Name ↑" menu button
 *   nodeListPage(root, ctx, spec)                     → cleanup   a complete page around fileView()
 * @module components/node-list
 */
import { h, icon, isMobile, append, boot } from '../core/dom.js';
import { api, itemsOf, errorMessage, ApiError } from '../core/api.js';
import { events, persisted, session } from '../core/store.js';
import { register } from '../core/keys.js';
import { plural, number, bytes } from '../core/format.js';
import { can, sortNodes, spaces as loadSpaces } from '../core/nodes.js';
import { fileView } from './file-view.js';
import { fileActions } from './file-actions.js';
import { menu } from './menu.js';
import { pageHeader } from './page-header.js';
import { emptyState } from './empty-state.js';
import { button } from './button.js';
import { toast } from './toast.js';

/**
 * @typedef {import('../core/nodes.js').Node} Node
 * @typedef {ReturnType<typeof fileActions>} Actions
 */

/**
 * Starting view for a device whose user has not used the toggle yet: account preference → the server's
 * ui.default_view → list. The boot user's prefs are the synchronous fallback, because this module may be imported
 * before GET /me has resolved (#fp-boot already carries them).
 * @returns {'list' | 'grid'}
 */
export function defaultView() {
  const me = session.peek();
  const prefs = me?.prefs || me?.user?.prefs || boot().user?.prefs || {};
  const v = prefs.view === 'list' || prefs.view === 'grid' ? prefs.view : boot().ui.default_view;
  return v === 'grid' ? 'grid' : 'list';
}

/** Persisted view preference (per device; seeded from the account preference / the server default). */
export const viewPref = persisted('files-view', defaultView());

const SORT_LABELS = /** @type {Record<string, string>} */ ({ name: 'Name', updated: 'Modified', size: 'Size', kind: 'Kind', trashed: 'Deleted' });

/**
 * @param {{key: string, desc: boolean}} sort
 * @param {string[]} keys
 * @param {(key: string, desc: boolean) => void} onChange
 */
export function sortButton(sort, keys, onChange) {
  const labelEl = h('span', { class: 'sort-btn-label' });
  const dirIcon = h('span', { class: 'sort-btn-dir' });
  const sync = () => {
    labelEl.textContent = SORT_LABELS[sort.key] || sort.key;
    dirIcon.replaceChildren(icon(sort.desc ? 'arrow-down' : 'arrow-up', { size: 14 }));
    btn.setAttribute('aria-label', `Sort by ${labelEl.textContent.toLowerCase()}, ${sort.desc ? 'descending' : 'ascending'}`);
  };
  const btn = h('button', {
    class: 'btn btn--ghost btn--sm sort-btn',
    attrs: { type: 'button', 'aria-haspopup': 'menu' },
    on: {
      click: () => menu({
        anchor: btn,
        title: 'Sort by',
        items: [
          ...keys.map((k) => ({ label: `${SORT_LABELS[k] || k}${sort.key === k ? ' ✓' : ''}`, icon: k === 'name' ? 'sort' : k === 'size' ? 'hard-drive' : k === 'kind' ? 'file' : 'clock', onClick: () => set(k, sort.key === k ? sort.desc : k !== 'name' && k !== 'kind') })),
          { divider: true },
          { label: `Ascending${sort.desc ? '' : ' ✓'}`, icon: 'arrow-up', onClick: () => set(sort.key, false) },
          { label: `Descending${sort.desc ? ' ✓' : ''}`, icon: 'arrow-down', onClick: () => set(sort.key, true) },
        ],
      }),
    },
  }, icon('sort', { size: 16 }), labelEl, dirIcon);
  /** @param {string} k @param {boolean} d */
  const set = (k, d) => {
    sort.key = k;
    sort.desc = d;
    sync();
    onChange(k, d);
  };
  sync();
  return Object.assign(btn, { sync });
}

/**
 * @param {'list' | 'grid'} mode
 * @param {(m: 'list' | 'grid') => void} onChange
 */
export function viewToggle(mode, onChange) {
  /** @param {'list' | 'grid'} m @param {string} ic @param {string} label */
  const b = (m, ic, label) => h('button', {
    class: 'icon-btn icon-btn--sm',
    attrs: { type: 'button', 'aria-label': label, title: label, 'aria-pressed': String(mode === m) },
    dataset: { mode: m },
    on: {
      click: () => {
        mode = m;
        for (const x of el.children) x.setAttribute('aria-pressed', String(/** @type {HTMLElement} */ (x).dataset.mode === m));
        onChange(m);
      },
    },
  }, icon(ic, { size: 18 }));
  const el = h('div', { class: 'seg', attrs: { role: 'group', 'aria-label': 'View' } }, b('list', 'list', 'List view'), b('grid', 'grid', 'Grid view'));
  return el;
}

/**
 * Drop leading, trailing and repeated dividers from a menu.
 * @param {import('./menu.js').MenuItem[]} items
 */
export function tidy(items) {
  return items.filter((it, i, arr) => !(it.divider && (i === 0 || i === arr.length - 1 || arr[i - 1].divider)));
}

/**
 * Selection bar: count + the most common actions; the rest in a "More" menu. Hidden when nothing is selected.
 * @param {{actions: Actions, context: import('./file-actions.js').ActionsContext['context'], onClear: () => void}} o
 */
export function selectionBar(o) {
  const count = h('span', { class: 'selbar-count', attrs: { 'aria-live': 'polite' } });
  const btns = h('div', { class: 'selbar-actions' });
  const clearBtn = h('button', { class: 'icon-btn icon-btn--sm', attrs: { type: 'button', 'aria-label': 'Clear selection', title: 'Clear selection (Esc)' }, on: { click: () => o.onClear() } }, icon('x'));
  const el = h('div', { class: 'selbar', hidden: true, attrs: { role: 'toolbar', 'aria-label': 'Selection actions' } }, clearBtn, count, btns);
  /** @type {Node[]} */
  let current = [];

  /** @param {string} ic @param {string} label @param {() => void} fn @param {{danger?: boolean}} [x] */
  const act = (ic, label, fn, x = {}) => h('button', {
    class: ['btn btn--ghost btn--sm selbar-btn', x.danger && 'selbar-btn--danger'],
    attrs: { type: 'button', title: label, 'aria-label': label },
    on: { click: fn },
  }, icon(ic, { size: 18 }), h('span', { class: 'selbar-label', text: label }));

  /** @param {Node[]} nodes */
  const update = (nodes) => {
    current = nodes;
    el.hidden = nodes.length === 0;
    document.documentElement.toggleAttribute('data-selbar', nodes.length > 0);
    if (!nodes.length) return;
    const files = nodes.filter((n) => n.kind === 'file');
    const size = files.reduce((s, n) => s + (n.size || 0), 0);
    count.textContent = `${number(nodes.length)} selected${files.length && !isMobile() ? ` · ${bytes(size)}` : ''}`;
    const a = o.actions;
    const one = nodes.length === 1 ? nodes[0] : null;
    /** @type {HTMLElement[]} */
    const list = [];
    if (o.context === 'trash') {
      list.push(act('rotate-ccw', 'Restore', () => a.restore(current)));
      list.push(act('trash', 'Delete forever', () => a.purge(current), { danger: true }));
    } else {
      list.push(act('download', 'Download', () => a.download(current)));
      if (one && can(one, 'manage')) list.push(act('share', 'Share', () => a.share(/** @type {Node} */ (one))));
      if (nodes.every((n) => can(n, 'edit'))) list.push(act('move', 'Move', () => a.move(current)));
      if (nodes.every((n) => can(n, 'edit'))) list.push(act('trash', 'Trash', () => a.trash(current), { danger: true }));
      const more = h('button', {
        class: 'icon-btn icon-btn--sm selbar-more',
        attrs: { type: 'button', 'aria-label': 'More actions', title: 'More actions', 'aria-haspopup': 'menu' },
        on: { click: () => menu({ anchor: more, items: tidy(a.menuItems(current).filter((it) => !it.label || !/^(Select|Download|Download as \.zip|Share…|Move to…|Move to trash)$/.test(it.label))), title: `${plural(current.length, 'item')}` }) },
      }, icon('more-horizontal'));
      list.push(more);
    }
    btns.replaceChildren(...list);
  };
  return { el, update };
}

/**
 * @typedef {Object} ListPageSpec
 * @property {string} title
 * @property {string} [subtitle]
 * @property {import('./file-actions.js').ActionsContext['context']} context
 * @property {(opts: {sort: {key: string, desc: boolean}, cursor: string, signal: AbortSignal}) => Promise<{items: Node[], next?: string}>} fetch
 * @property {import('./file-view.js').ColumnId[]} columns
 * @property {{key: string, desc: boolean}} sort default sort
 * @property {string[]} sortKeys
 * @property {boolean} [clientSort] sort the loaded items in the browser (endpoints without server sort)
 * @property {() => Element} empty
 * @property {(ctl: {reload: () => void, actions: Actions}) => Element[]} [headerActions]
 * @property {(ctl: {reload: () => void}) => Element} [controls] extra controls between the header and the toolbar
 * @property {boolean} [loadAll] follow next_cursor until the end (default true)
 * @property {() => boolean} [ready] false = don't fetch (e.g. empty search query); the empty state shows instead
 */

/**
 * A complete node-list page (header, toolbar, virtualised list, selection bar, details via dialog).
 * @param {HTMLElement} root
 * @param {import('../core/router.js').PageContext} ctx
 * @param {ListPageSpec} spec
 * @returns {() => void} cleanup
 */
export function nodeListPage(root, ctx, spec) {
  const sortPref = persisted(`sort-${spec.context}`, spec.sort);
  const sort = { ...spec.sort, ...(sortPref.peek() || {}) };
  if (!spec.sortKeys.includes(sort.key)) Object.assign(sort, spec.sort);
  /** @type {Node[]} */
  let items = [];
  /** @type {import('../core/nodes.js').Space[]} */
  let spaceList = [];
  let seq = 0;
  /** @type {(() => void)[]} */
  const cleanups = [];

  const actions = fileActions({
    context: spec.context,
    items: () => items,
    refresh: () => load(true),
    onRemoved: (ids) => {
      const gone = new Set(ids);
      items = items.filter((n) => !gone.has(n.id));
      fv.setItems(items, { keepCursor: true });
    },
    onUpdated: (n) => {
      items = items.map((x) => (x.id === n.id ? { ...x, ...n } : x));
      fv.update(n);
    },
    onSelectMode: (nodes) => {
      fv.select(nodes.map((n) => n.id));
      fv.setSelecting(true);
    },
  });

  const countEl = h('span', { class: 'files-count muted text-sm', attrs: { 'aria-live': 'polite' } });
  const sortBtn = sortButton(sort, spec.sortKeys, (k, d) => {
    sortPref.value = { key: k, desc: d };
    fv.setSort(k, d);
    load(false);
  });
  const toggle = viewToggle(viewPref.peek(), (m) => {
    viewPref.value = m;
    fv.setMode(m);
  });
  const selbar = selectionBar({ actions, context: spec.context, onClear: () => fv.setSelecting(false) });

  const fv = fileView({
    mode: viewPref.peek(),
    columns: spec.columns,
    sort,
    label: spec.title,
    spaces: () => spaceList,
    onSort: (k, d) => {
      sort.key = k;
      sort.desc = d;
      sortPref.value = { key: k, desc: d };
      sortBtn.sync();
      load(false);
    },
    onOpen: (n) => {
      if (spec.context === 'trash') {
        actions.details(n, 'info');
        return;
      }
      actions.open(n);
    },
    menuItems: (nodes) => actions.menuItems(nodes),
    onDelete: (nodes) => (spec.context === 'trash' ? actions.purge(nodes) : actions.trash(nodes)),
    onRename: spec.context === 'trash' ? undefined : (n) => { if (can(n, 'edit')) actions.rename(n); },
    onSelectionChange: (nodes) => selbar.update(nodes),
    empty: spec.empty,
  });

  const header = pageHeader({
    title: spec.title,
    subtitle: spec.subtitle,
    actions: spec.headerActions ? spec.headerActions({ reload: () => load(true), actions }) : undefined,
  });
  const errorSlot = h('div');
  append(root,
    header,
    spec.controls ? spec.controls({ reload: () => load(false) }) : null,
    h('div', { class: 'files-toolbar' }, countEl, h('div', { class: 'grow' }), sortBtn, toggle),
    errorSlot,
    fv.el,
    selbar.el);

  /** @param {boolean} keep keep selection/cursor (refresh) */
  async function load(keep) {
    const my = ++seq;
    if (spec.ready && !spec.ready()) {
      errorSlot.replaceChildren();
      items = [];
      fv.setItems([]);
      countEl.textContent = '';
      return;
    }
    if (!keep) {
      errorSlot.replaceChildren();
      fv.setLoading();
    }
    /** @param {Node[]} all @param {boolean} more @param {boolean} keepCursor */
    const show = (all, more, keepCursor) => {
      items = spec.clientSort ? sortNodes(all, sort.key, sort.desc) : all;
      fv.setItems(items, { keepCursor });
      countEl.textContent = more ? `${number(items.length)}+ items` : plural(items.length, 'item');
    };
    try {
      /** @type {Node[]} */
      let all = [];
      let cursor = '';
      let first = true;
      do {
        const res = await spec.fetch({ sort, cursor, signal: ctx.signal });
        if (my !== seq) return;
        all = all.concat(res.items);
        cursor = res.next || '';
        // A fresh load streams pages into the list; a refresh swaps the list once, when it is complete (as
        // pages/files.js does): a partial first page would prune the selection and the cursor beyond it for good.
        if (!keep) show(all, !!cursor, !first);
        first = false;
      } while (cursor && spec.loadAll !== false && all.length < 20000);
      errorSlot.replaceChildren();
      if (keep) show(all, !!cursor, true);
    } catch (err) {
      if (err instanceof ApiError && err.aborted) return;
      if (my !== seq) return;
      // A failed background refresh keeps the list (and the selection) that is on screen.
      if (keep) {
        toast.error(err);
        return;
      }
      items = [];
      fv.setItems([]);
      countEl.textContent = '';
      errorSlot.replaceChildren(h('div', { class: 'alert alert--danger', attrs: { role: 'alert' } }, icon('alert-circle'),
        h('div', { class: 'alert-body' }, h('strong', { text: 'Could not load this list' }), h('span', { text: errorMessage(err) })),
        button({ label: 'Retry', size: 'sm', onClick: () => load(false) })));
    }
  }

  loadSpaces().then((s) => {
    spaceList = s;
    if (items.length) fv.setItems(items, { keepCursor: true });
  }).catch(() => {});

  let refreshTimer = 0;
  cleanups.push(events.on('files.changed', () => {
    clearTimeout(refreshTimer);
    refreshTimer = window.setTimeout(() => load(true), 250);
  }));
  cleanups.push(register('v', () => {
    const m = viewPref.peek() === 'grid' ? 'list' : 'grid';
    viewPref.value = m;
    fv.setMode(m);
    for (const x of toggle.children) x.setAttribute('aria-pressed', String(/** @type {HTMLElement} */ (x).dataset.mode === m));
  }, { description: 'Switch between list and grid', group: 'Files' }));

  load(false);
  return () => {
    clearTimeout(refreshTimer);
    for (const c of cleanups) c();
    fv.destroy();
    document.documentElement.removeAttribute('data-selbar');
  };
}

/**
 * Fetch helper for Page[Node] endpoints ({items, next_cursor}) or bare arrays.
 * @param {string} path
 * @param {Record<string, any>} query
 * @param {AbortSignal} signal
 */
export async function fetchPage(path, query, signal) {
  const res = await api.get(path, { query, signal });
  return { items: /** @type {Node[]} */ (itemsOf(res)), next: Array.isArray(res) ? '' : res?.next_cursor || '' };
}

/**
 * Standard empty state.
 * @param {string} ic @param {string} title @param {string} text @param {any} [action]
 */
export function emptyView(ic, title, text, action) {
  return () => emptyState({ icon: ic, title, text, action });
}
