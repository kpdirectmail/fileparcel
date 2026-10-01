// @ts-check
/**
 * Search — /search?q=&kind=&space= (§13.2, GET /search). Name search across every space the user can see
 * (FTS5 trigram for ≥ 3 characters, prefix/LIKE for shorter queries — server side). Typing updates the URL
 * (history.replaceState) and re-runs the query after a short pause; filters narrow by kind and space.
 * @module pages/search
 */
import { h, icon } from '../core/dom.js';
import { navigate } from '../core/router.js';
import { spaces, spaceLabel } from '../core/nodes.js';
import { nodeListPage, fetchPage } from '../components/node-list.js';
import { select } from '../components/field.js';
import { emptyState } from '../components/empty-state.js';

export const title = 'Search';

/**
 * @param {HTMLElement} root
 * @param {import('../core/router.js').PageContext} ctx
 */
export function mount(root, ctx) {
  const state = { q: (ctx.query.q || '').trim(), kind: ctx.query.kind || '', space: ctx.query.space || '' };
  /** @type {() => void} */
  let reload = () => {};
  let timer = 0;

  const syncURL = () => {
    const p = new URLSearchParams();
    if (state.q) p.set('q', state.q);
    if (state.kind) p.set('kind', state.kind);
    if (state.space) p.set('space', state.space);
    const qs = p.toString();
    navigate(`/search${qs ? `?${qs}` : ''}`, { replace: true, render: false });
  };

  const input = h('input', {
    class: 'search-input',
    attrs: { type: 'search', placeholder: 'Search files and folders by name', 'aria-label': 'Search files and folders', autocomplete: 'off', spellcheck: 'false', enterkeyhint: 'search', maxlength: 200 },
    value: state.q,
  });
  input.addEventListener('input', () => {
    clearTimeout(timer);
    timer = window.setTimeout(() => {
      const v = input.value.trim();
      if (v === state.q) return;
      state.q = v;
      syncURL();
      reload();
    }, 250);
  });
  input.addEventListener('keydown', (e) => {
    if (e.key === 'Enter') {
      clearTimeout(timer);
      state.q = input.value.trim();
      syncURL();
      reload();
    }
  });
  const kindSel = select({
    label: 'Type',
    hideLabel: true,
    options: [{ value: '', label: 'All types' }, { value: 'file', label: 'Files' }, { value: 'folder', label: 'Folders' }],
    value: state.kind,
    onChange: (v) => { state.kind = v; syncURL(); reload(); },
  });
  const spaceSel = select({
    label: 'Location',
    hideLabel: true,
    options: [{ value: '', label: 'All locations' }],
    value: state.space,
    onChange: (v) => { state.space = v; syncURL(); reload(); },
  });
  spaces().then((list) => {
    spaceSel.setOptions([{ value: '', label: 'All locations' }, ...list.map((s) => ({ value: s.id, label: spaceLabel(s) }))], state.space);
  }).catch(() => {});

  const cleanup = nodeListPage(root, ctx, {
    title,
    context: 'search',
    columns: ['location', 'size', 'updated'],
    sort: { key: 'name', desc: false },
    sortKeys: ['name', 'updated', 'size', 'kind'],
    clientSort: true,
    ready: () => state.q.length > 0,
    controls: (ctl) => {
      reload = ctl.reload;
      return h('div', { class: 'search-controls' },
        h('div', { class: 'search-box' }, icon('search'), input),
        h('div', { class: 'search-filters' }, kindSel.el, spaceSel.el));
    },
    fetch: ({ cursor, signal }) => fetchPage('/search', { q: state.q, kind: state.kind || undefined, space: state.space || undefined, cursor: cursor || undefined, limit: 200 }, signal),
    empty: () => (state.q
      ? emptyState({ icon: 'search', title: 'No matches', text: `Nothing is named like “${state.q}”. Try fewer letters or another location.` })
      : emptyState({ icon: 'search', title: 'Find anything', text: 'Type part of a file or folder name. Search looks through everything you have access to.' })),
  });
  if (!state.q) requestAnimationFrame(() => input.focus());
  return () => {
    clearTimeout(timer);
    cleanup();
  };
}
