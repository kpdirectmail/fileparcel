// @ts-check
/**
 * table({columns, rows, onSort, selectable, empty, rowKey, onRowClick}) → {el, setRows(rows), getSelected(), clearSelection(), setSort(key, desc)}
 *
 * columns: [{key, label, render?: (row) => Node|string, sortable?, align?: 'start'|'end'|'center', class?, hideBelow?: 'sm'|'md', width?}]
 * rows: objects; rowKey: property name or (row) => string (default "id")
 * onSort(key, desc) — the caller re-fetches/re-sorts and calls setRows(); the header shows aria-sort.
 * selectable: adds a checkbox column (+ select all); onSelect(keys) is called on every change.
 * empty: Node or string shown when there are no rows.
 * onRowClick(row, event): row activation by click or Enter (clicks on buttons/links/inputs inside the row are ignored).
 * @module components/table
 */
import { h, icon, append } from '../core/dom.js';

/**
 * @typedef {Object} Column
 * @property {string} key
 * @property {string} label
 * @property {(row: any, index: number) => import('../core/dom.js').Child} [render]
 * @property {boolean} [sortable]
 * @property {'start' | 'end' | 'center'} [align]
 * @property {string} [class]
 * @property {'sm' | 'md'} [hideBelow]
 * @property {string} [width] CSS width, e.g. "120px"
 * @property {boolean} [srOnlyLabel] visually hide the header text (e.g. actions column)
 */

/**
 * @typedef {Object} TableOpts
 * @property {Column[]} columns
 * @property {any[]} [rows]
 * @property {(key: string, desc: boolean) => void} [onSort]
 * @property {{key: string, desc: boolean}} [sort] initial sort indicator
 * @property {boolean} [selectable]
 * @property {(keys: string[]) => void} [onSelect]
 * @property {import('../core/dom.js').Child} [empty]
 * @property {string | ((row: any) => string)} [rowKey]
 * @property {(row: any, e: Event) => void} [onRowClick]
 * @property {string} [caption] accessible caption (visually hidden)
 * @property {boolean} [loading] render skeleton rows until setRows() is called
 */

/**
 * @param {TableOpts} opts
 */
export function table(opts) {
  const keyOf = typeof opts.rowKey === 'function'
    ? opts.rowKey
    : (/** @type {any} */ row) => String(row?.[/** @type {string} */ (opts.rowKey || 'id')] ?? '');
  /** @type {any[]} */
  let rows = opts.rows || [];
  /** @type {Set<string>} */
  const selected = new Set();
  let sort = opts.sort ? { ...opts.sort } : null;

  const tbody = h('tbody');
  /** @type {HTMLInputElement | null} */
  let selectAll = null;
  /** @type {HTMLTableCellElement[]} */
  const ths = [];

  /** @param {Column} c */
  const cellClass = (c) => [c.align === 'end' && 'align-end', c.align === 'center' && 'align-center', c.hideBelow && `hide-${c.hideBelow}`, c.class || ''];

  const headRow = h('tr');
  if (opts.selectable) {
    selectAll = h('input', {
      attrs: { type: 'checkbox', 'aria-label': 'Select all rows' },
      on: {
        change: () => {
          if (selectAll?.checked) rows.forEach((r) => selected.add(keyOf(r)));
          else selected.clear();
          syncSelection();
          opts.onSelect?.([...selected]);
        },
      },
    });
    // the <label> fills the cell so the hit target is ≥ 44 px on touch (the checkbox itself is 18 px)
    headRow.appendChild(h('th', { class: 'col-check', attrs: { scope: 'col' } }, h('label', { class: 'check-hit' }, selectAll)));
  }
  for (const c of opts.columns) {
    const th = h('th', { class: cellClass(c), attrs: { scope: 'col' }, dataset: { key: c.key } });
    if (c.width) th.style.setProperty('width', c.width);
    if (c.sortable && opts.onSort) {
      th.appendChild(h('button', {
        class: 'th-sort',
        attrs: { type: 'button' },
        on: {
          click: () => {
            const desc = sort && sort.key === c.key ? !sort.desc : false;
            sort = { key: c.key, desc };
            syncSort();
            opts.onSort?.(c.key, desc);
          },
        },
      }, h('span', { text: c.label }), icon('chevron-down')));
    } else {
      th.appendChild(h('span', { class: c.srOnlyLabel ? 'sr-only' : '', text: c.label }));
    }
    ths.push(th);
    headRow.appendChild(th);
  }

  const syncSort = () => {
    for (const th of ths) {
      const k = th.dataset.key;
      if (sort && k === sort.key) {
        th.setAttribute('aria-sort', sort.desc ? 'descending' : 'ascending');
        const ic = th.querySelector('.icon');
        if (ic) ic.replaceWith(icon(sort.desc ? 'chevron-down' : 'chevron-up'));
      } else {
        th.removeAttribute('aria-sort');
      }
    }
  };

  const syncSelection = () => {
    for (const tr of /** @type {HTMLTableRowElement[]} */ ([...tbody.rows])) {
      const k = tr.dataset.key || '';
      const on = selected.has(k);
      if (opts.selectable) tr.setAttribute('aria-selected', String(on));
      const cb = /** @type {HTMLInputElement | null} */ (tr.querySelector('.col-check input'));
      if (cb) cb.checked = on;
    }
    if (selectAll) {
      selectAll.checked = rows.length > 0 && selected.size === rows.length;
      selectAll.indeterminate = selected.size > 0 && selected.size < rows.length;
    }
  };

  const colCount = opts.columns.length + (opts.selectable ? 1 : 0);

  const render = () => {
    tbody.replaceChildren();
    if (!rows.length) {
      const td = h('td', { class: 'table-empty', attrs: { colspan: colCount } });
      append(td, opts.empty ?? 'Nothing here yet.');
      tbody.appendChild(h('tr', null, td));
      syncSelection();
      return;
    }
    rows.forEach((row, i) => {
      const k = keyOf(row);
      const tr = h('tr', { dataset: { key: k, clickable: opts.onRowClick ? '' : null } });
      if (opts.selectable) {
        tr.appendChild(h('td', { class: 'col-check' }, h('label', { class: 'check-hit' }, h('input', {
          attrs: { type: 'checkbox', 'aria-label': 'Select row' },
          checked: selected.has(k),
          on: {
            change: (e) => {
              const cb = /** @type {HTMLInputElement} */ (e.currentTarget);
              if (cb.checked) selected.add(k);
              else selected.delete(k);
              syncSelection();
              opts.onSelect?.([...selected]);
            },
          },
        }))));
      }
      for (const c of opts.columns) {
        const td = h('td', { class: cellClass(c) });
        const v = c.render ? c.render(row, i) : row?.[c.key];
        append(td, v === null || v === undefined || v === '' ? '—' : v);
        tr.appendChild(td);
      }
      if (opts.onRowClick) {
        const fn = opts.onRowClick;
        tr.tabIndex = 0;
        tr.addEventListener('click', (e) => {
          const t = /** @type {Element} */ (e.target);
          if (t.closest('button, a, input, select, textarea, label')) return;
          fn(row, e);
        });
        tr.addEventListener('keydown', (e) => {
          if (e.key === 'Enter' && e.target === tr) fn(row, e);
        });
      }
      tbody.appendChild(tr);
    });
    syncSelection();
  };

  const tableEl = h('table', { class: 'table' },
    opts.caption ? h('caption', { class: 'sr-only', text: opts.caption }) : null,
    h('thead', null, headRow),
    tbody);
  const el = h('div', { class: 'table-wrap' }, tableEl);

  if (opts.loading && !rows.length) {
    tbody.replaceChildren(...Array.from({ length: 4 }, () => h('tr', null,
      h('td', { attrs: { colspan: colCount } }, h('div', { class: 'skeleton-line' })))));
  } else {
    render();
  }
  syncSort();

  return {
    el,
    /** @param {any[]} next */
    setRows(next) {
      rows = next || [];
      const keys = new Set(rows.map(keyOf));
      for (const k of [...selected]) if (!keys.has(k)) selected.delete(k);
      render();
    },
    getSelected: () => [...selected],
    getSelectedRows: () => rows.filter((r) => selected.has(keyOf(r))),
    clearSelection() {
      selected.clear();
      syncSelection();
      opts.onSelect?.([]);
    },
    /** @param {string} key @param {boolean} desc */
    setSort(key, desc) {
      sort = { key, desc };
      syncSort();
    },
  };
}
