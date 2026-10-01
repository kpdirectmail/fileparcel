// @ts-check
/**
 * Keyboard shortcut registry.
 *
 *   const off = register('mod+k', openPalette, {description: 'Command palette', group: 'General', global: true});
 *   register('g f', () => navigate('/files'), {description: 'Go to My files', group: 'Navigation'});
 *   register('?', showHelp, {description: 'Keyboard shortcuts'});
 *
 * Combos: modifiers `mod` (⌘ on Apple, Ctrl elsewhere), `ctrl`, `meta`, `alt`, `shift` joined with "+";
 * sequences are space separated ("g f", pressed within 1.2 s). Keys use KeyboardEvent.key names
 * ("k", "Enter", "Escape", "ArrowDown", "Delete", "F2", "?", "/").
 * By default shortcuts are ignored while typing in a field, while a modal dialog is open, and while focus is inside
 * a widget that handles letter keys itself (role="menu"/"menubar" — menus jump to items by typed letter — or any
 * element marked `data-own-keys`); pass `{global: true}` to fire anyway, or `{allowInInput: true}` for fields only.
 * @module core/keys
 */
import { isMac } from './dom.js';

/**
 * @typedef {Object} ShortcutOpts
 * @property {string} [description] shown in the "?" help dialog (omit to hide)
 * @property {string} [group] help dialog section
 * @property {boolean} [allowInInput] fire while focus is in an input/textarea/select/contenteditable
 * @property {boolean} [global] fire everywhere (inputs and open dialogs)
 * @property {() => boolean} [when] extra predicate
 * @property {boolean} [preventDefault] default true
 */

/**
 * @typedef {Object} Chord
 * @property {string} key lower-cased key
 * @property {boolean} ctrl
 * @property {boolean} meta
 * @property {boolean} alt
 * @property {boolean} shift
 */

/**
 * @typedef {Object} Shortcut
 * @property {string} combo
 * @property {Chord[]} chords
 * @property {(e: KeyboardEvent) => void} handler
 * @property {ShortcutOpts} opts
 */

/** @type {Shortcut[]} */
const shortcuts = [];
/** @type {Chord[]} */
let pendingSeq = [];
let seqTimer = 0;
let installed = false;
const MAC = typeof navigator !== 'undefined' && isMac();

/**
 * @param {string} token e.g. "mod+shift+k"
 * @returns {Chord}
 */
function parseChord(token) {
  const parts = token.split('+');
  // a literal "+" key is written as "shift+=" / "plus"
  const key = parts.pop() || '';
  /** @type {Chord} */
  const c = { key: normKey(key === 'plus' ? '+' : key), ctrl: false, meta: false, alt: false, shift: false };
  for (const p of parts.map((x) => x.toLowerCase())) {
    if (p === 'mod') {
      if (MAC) c.meta = true;
      else c.ctrl = true;
    } else if (p === 'ctrl' || p === 'control') c.ctrl = true;
    else if (p === 'meta' || p === 'cmd') c.meta = true;
    else if (p === 'alt' || p === 'option') c.alt = true;
    else if (p === 'shift') c.shift = true;
  }
  return c;
}

/** @param {string} k */
function normKey(k) {
  if (k === ' ') return 'space';
  if (k === 'Esc') return 'escape';
  return k.length === 1 ? k.toLowerCase() : k.toLowerCase();
}

/**
 * @param {Chord} c
 * @param {KeyboardEvent} e
 */
function chordMatches(c, e) {
  const key = normKey(e.key);
  if (key !== c.key) return false;
  // Shift is implied by symbols like "?" – only compare it for letters/named keys or when the combo requests it.
  const symbol = c.key.length === 1 && !/[a-z0-9]/.test(c.key);
  if (!symbol && e.shiftKey !== c.shift) return false;
  if (symbol && c.shift && !e.shiftKey) return false;
  return e.ctrlKey === c.ctrl && e.metaKey === c.meta && e.altKey === c.alt;
}

/** @param {EventTarget | null} t */
function isEditable(t) {
  if (!(t instanceof HTMLElement)) return false;
  if (t.isContentEditable) return true;
  const tag = t.tagName;
  if (tag === 'TEXTAREA' || tag === 'SELECT') return true;
  if (tag === 'INPUT') {
    const type = /** @type {HTMLInputElement} */ (t).type;
    return !['checkbox', 'radio', 'button', 'submit', 'reset', 'range', 'color', 'file'].includes(type);
  }
  return false;
}

function modalOpen() {
  return !!document.querySelector('dialog[open]');
}

/**
 * Focus is inside a composite widget with its own key handling (menu typeahead: "u" jumps to "Upload files" and
 * must not also trigger the global "u" shortcut). Listboxes/grids are deliberately NOT included: the file list uses
 * page shortcuts (Delete, F2, Ctrl+A) while it has focus.
 * @param {EventTarget | null} t
 */
function inOwnKeysWidget(t) {
  return t instanceof Element && !!t.closest('[role="menu"], [role="menubar"], [data-own-keys]');
}

/** @param {KeyboardEvent} e */
function onKeyDown(e) {
  if (e.isComposing || e.key === 'Dead' || e.key === 'Unidentified') return;
  if (['Shift', 'Control', 'Alt', 'Meta'].includes(e.key)) return;
  const editable = isEditable(e.target);
  const modal = modalOpen();
  const widget = inOwnKeysWidget(e.target);
  /** @param {Shortcut} s */
  const allowed = (s) => {
    if (s.opts.when && !s.opts.when()) return false;
    if (s.opts.global) return true;
    if (editable && !s.opts.allowInInput) return false;
    if (modal || widget) return false;
    return true;
  };

  // continue a pending sequence
  if (pendingSeq.length) {
    const seq = [...pendingSeq];
    for (const s of shortcuts) {
      if (s.chords.length !== seq.length + 1 || !allowed(s)) continue;
      if (seq.every((c, i) => sameChord(c, s.chords[i])) && chordMatches(s.chords[seq.length], e)) {
        resetSeq();
        fire(s, e);
        return;
      }
    }
    resetSeq();
  }

  // single-chord shortcuts (last registered wins)
  for (let i = shortcuts.length - 1; i >= 0; i -= 1) {
    const s = shortcuts[i];
    if (s.chords.length === 1 && allowed(s) && chordMatches(s.chords[0], e)) {
      fire(s, e);
      return;
    }
  }

  // start a sequence if any multi-chord shortcut begins with this chord
  const starter = shortcuts.find((s) => s.chords.length > 1 && allowed(s) && chordMatches(s.chords[0], e));
  if (starter) {
    pendingSeq = [starter.chords[0]];
    window.clearTimeout(seqTimer);
    seqTimer = window.setTimeout(resetSeq, 1200);
  }
}

/**
 * @param {Chord} a
 * @param {Chord} b
 */
function sameChord(a, b) {
  return a.key === b.key && a.ctrl === b.ctrl && a.meta === b.meta && a.alt === b.alt && a.shift === b.shift;
}

function resetSeq() {
  pendingSeq = [];
  window.clearTimeout(seqTimer);
}

/**
 * @param {Shortcut} s
 * @param {KeyboardEvent} e
 */
function fire(s, e) {
  if (s.opts.preventDefault !== false) e.preventDefault();
  try {
    s.handler(e);
  } catch (err) {
    console.error(`shortcut ${s.combo} failed`, err);
  }
}

/** Install the global keydown listener (idempotent; register() calls it). */
export function startKeys() {
  if (installed) return;
  installed = true;
  document.addEventListener('keydown', onKeyDown);
}

/**
 * Register a shortcut. Returns an unregister function.
 * @param {string} combo
 * @param {(e: KeyboardEvent) => void} handler
 * @param {ShortcutOpts} [opts]
 * @returns {() => void}
 */
export function register(combo, handler, opts = {}) {
  startKeys();
  /** @type {Shortcut} */
  const s = { combo, chords: combo.trim().split(/\s+/).map(parseChord), handler, opts };
  shortcuts.push(s);
  return () => {
    const i = shortcuts.indexOf(s);
    if (i >= 0) shortcuts.splice(i, 1);
  };
}

/**
 * Registered shortcuts that have a description (for the help dialog), grouped.
 * @returns {{group: string, items: {combo: string, keys: string[][], description: string}[]}[]}
 */
export function list() {
  /** @type {Map<string, {combo: string, keys: string[][], description: string}[]>} */
  const groups = new Map();
  const seen = new Set();
  for (const s of shortcuts) {
    if (!s.opts.description || seen.has(s.combo)) continue;
    seen.add(s.combo);
    const g = s.opts.group || 'General';
    if (!groups.has(g)) groups.set(g, []);
    groups.get(g)?.push({ combo: s.combo, keys: formatCombo(s.combo), description: s.opts.description });
  }
  return [...groups].map(([group, items]) => ({ group, items }));
}

/**
 * Display labels for a combo: "mod+k" → [["⌘","K"]] on Apple, [["Ctrl","K"]] elsewhere; "g f" → [["G"],["F"]].
 * @param {string} combo
 * @returns {string[][]}
 */
export function formatCombo(combo) {
  return combo.trim().split(/\s+/).map((tok) =>
    tok.split('+').map((p) => {
      const l = p.toLowerCase();
      if (l === 'mod') return MAC ? '⌘' : 'Ctrl';
      if (l === 'meta' || l === 'cmd') return MAC ? '⌘' : 'Meta';
      if (l === 'ctrl') return MAC ? '⌃' : 'Ctrl';
      if (l === 'alt') return MAC ? '⌥' : 'Alt';
      if (l === 'shift') return MAC ? '⇧' : 'Shift';
      if (l === 'escape') return 'Esc';
      if (l === 'arrowup') return '↑';
      if (l === 'arrowdown') return '↓';
      if (l === 'arrowleft') return '←';
      if (l === 'arrowright') return '→';
      if (l === 'enter') return '↵';
      if (l === 'delete') return 'Del';
      if (l === 'plus') return '+';
      return p.length === 1 ? p.toUpperCase() : p;
    }),
  );
}
