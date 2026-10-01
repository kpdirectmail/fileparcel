// @ts-check
/**
 * Command palette (Ctrl/Cmd+K) and keyboard-shortcut help ("?").
 *   openPalette(commands, {onSearch}) — commands: [{id, label, icon, hint, keywords, run}]
 *   showShortcuts()
 * The palette is an ARIA combobox (input + listbox, aria-activedescendant). Typing filters by subsequence match;
 * when `onSearch` is given a final "Search files for …" entry is offered.
 * @module components/palette
 */
import { h, icon, uniqueId } from '../core/dom.js';
import { list as listShortcuts } from '../core/keys.js';
import { dialog } from './dialog.js';

/**
 * @typedef {Object} Command
 * @property {string} id
 * @property {string} label
 * @property {string} [icon]
 * @property {string} [hint] secondary text (e.g. group)
 * @property {string} [keywords]
 * @property {() => void} run
 */

/**
 * Subsequence score (lower is better; -1 = no match).
 * @param {string} q
 * @param {string} text
 */
function score(q, text) {
  const t = text.toLowerCase();
  const idx = t.indexOf(q);
  if (idx >= 0) return idx;
  let pos = 0;
  let gaps = 0;
  for (const ch of q) {
    const j = t.indexOf(ch, pos);
    if (j < 0) return -1;
    gaps += j - pos;
    pos = j + 1;
  }
  return 100 + gaps;
}

let open = false;

/**
 * @param {Command[] | (() => Command[])} commands
 * @param {{onSearch?: (q: string) => void, placeholder?: string}} [opts]
 */
export function openPalette(commands, opts = {}) {
  if (open) return;
  open = true;
  const all = typeof commands === 'function' ? commands() : commands;
  const listId = uniqueId('pal-list');
  const input = h('input', {
    attrs: {
      type: 'text',
      role: 'combobox',
      'aria-expanded': 'true',
      'aria-controls': listId,
      'aria-autocomplete': 'list',
      'aria-label': 'Type a command or search',
      placeholder: opts.placeholder || 'Jump to… or search files',
      autocomplete: 'off',
      spellcheck: 'false',
    },
  });
  const listEl = h('ul', { class: 'palette-list', id: listId, attrs: { role: 'listbox', 'aria-label': 'Commands' } });
  /** @type {Command[]} */
  let visible = [];
  let active = 0;

  const render = () => {
    const q = input.value.trim().toLowerCase();
    visible = q
      ? all
        .map((c) => ({ c, s: score(q, `${c.label} ${c.keywords || ''} ${c.hint || ''}`) }))
        .filter((x) => x.s >= 0)
        .sort((a, b) => a.s - b.s)
        .map((x) => x.c)
      : all.slice();
    if (q && opts.onSearch) {
      const raw = input.value.trim();
      visible.push({ id: '__search', label: `Search files for “${raw}”`, icon: 'search', run: () => opts.onSearch?.(raw) });
    }
    active = Math.min(active, Math.max(0, visible.length - 1));
    listEl.replaceChildren(...visible.map((c, i) => h('li', {
      class: 'palette-item',
      id: `${listId}-${i}`,
      attrs: { role: 'option', 'aria-selected': String(i === active) },
      on: {
        click: () => choose(i),
        mousemove: () => {
          if (active !== i) {
            active = i;
            sync();
          }
        },
      },
    }, icon(c.icon || 'arrow-right'), h('span', { text: c.label }), c.hint ? h('small', { text: c.hint }) : null)));
    if (!visible.length) listEl.appendChild(h('li', { class: 'palette-empty', attrs: { role: 'presentation' }, text: 'No matches' }));
    sync();
  };

  const sync = () => {
    [...listEl.children].forEach((li, i) => {
      if (li.getAttribute('role') === 'option') li.setAttribute('aria-selected', String(i === active));
    });
    if (visible.length) {
      input.setAttribute('aria-activedescendant', `${listId}-${active}`);
      document.getElementById(`${listId}-${active}`)?.scrollIntoView({ block: 'nearest' });
    } else {
      input.removeAttribute('aria-activedescendant');
    }
  };

  /** @param {number} i */
  const choose = (i) => {
    const c = visible[i];
    if (!c) return;
    d.close();
    setTimeout(() => c.run(), 0);
  };

  input.addEventListener('input', () => {
    active = 0;
    render();
  });
  input.addEventListener('keydown', (e) => {
    if (e.key === 'ArrowDown') {
      e.preventDefault();
      active = visible.length ? (active + 1) % visible.length : 0;
      sync();
    } else if (e.key === 'ArrowUp') {
      e.preventDefault();
      active = visible.length ? (active - 1 + visible.length) % visible.length : 0;
      sync();
    } else if (e.key === 'Enter') {
      e.preventDefault();
      choose(active);
    }
  });

  const d = dialog({
    title: 'Command palette',
    size: 'md',
    class: 'palette',
    hideClose: true,
    body: [h('div', { class: 'palette-input' }, icon('search'), input, h('kbd', { text: 'Esc' })), listEl],
    onClose: () => { open = false; },
  });
  d.el.querySelector('.dialog-head')?.classList.add('sr-only');
  render();
  d.open();
  input.focus();
}

/** Show the registered keyboard shortcuts. */
export function showShortcuts() {
  const groups = listShortcuts();
  const body = groups.length
    ? groups.map((g) => h('section', { class: 'stack-sm' },
      h('h3', { class: 'text-sm muted', text: g.group }),
      h('div', { class: 'shortcut-list' },
        g.items.map((it) => [
          h('span', { text: it.description }),
          h('span', { class: 'shortcut-keys' },
            it.keys.map((chord, i) => [i > 0 ? h('span', { class: 'muted text-xs', text: 'then' }) : null, chord.map((k) => h('kbd', { text: k }))])),
        ]))))
    : h('p', { text: 'No shortcuts registered.' });
  dialog({ title: 'Keyboard shortcuts', body, size: 'md', actions: [{ label: 'Close', variant: 'primary' }] }).open();
}
