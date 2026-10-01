// @ts-check
/**
 * copyField({value, label}) → HTMLElement
 * Read-only input with a copy button (Clipboard API, falling back to select + execCommand for non-secure contexts).
 * Also exports copyText(text) → Promise<boolean>.
 * @module components/copy-field
 */
import { h, icon, uniqueId, overlayHost } from '../core/dom.js';
import { toast } from './toast.js';

/**
 * Copy text to the clipboard; shows a toast. Resolves true on success.
 * @param {string} text
 * @param {string} [what] e.g. "Link"
 * @returns {Promise<boolean>}
 */
export async function copyText(text, what = 'Text') {
  try {
    if (navigator.clipboard && window.isSecureContext) {
      await navigator.clipboard.writeText(text);
    } else {
      // inside a modal dialog <body> is inert (cannot be selected) → use the top-most dialog
      const prev = document.activeElement;
      const ta = h('textarea', { class: 'sr-only', attrs: { readonly: true }, value: text });
      overlayHost().appendChild(ta);
      ta.select();
      const ok = document.execCommand('copy');
      ta.remove();
      if (prev instanceof HTMLElement && prev.isConnected) prev.focus({ preventScroll: true });
      if (!ok) throw new Error('copy failed');
    }
    toast.success(`${what} copied to clipboard`, { timeout: 2500 });
    return true;
  } catch {
    toast.error('Could not copy automatically — select the text and copy it manually.');
    return false;
  }
}

/**
 * @param {{value: string, label: string, hideLabel?: boolean, help?: string, what?: string}} opts
 * @returns {HTMLElement}
 */
export function copyField(opts) {
  const id = uniqueId('copy');
  const input = h('input', {
    id,
    attrs: { type: 'text', readonly: true, spellcheck: 'false', autocomplete: 'off' },
    value: opts.value,
    on: { focus: (e) => /** @type {HTMLInputElement} */ (e.currentTarget).select() },
  });
  const btn = h('button', {
    class: 'icon-btn icon-btn--sm input-action',
    attrs: { type: 'button', 'aria-label': `Copy ${opts.label}`, title: 'Copy' },
    on: {
      click: async () => {
        if (await copyText(input.value, opts.what || opts.label)) {
          btn.replaceChildren(icon('check'));
          setTimeout(() => btn.replaceChildren(icon('copy')), 1500);
        }
      },
    },
  }, icon('copy'));
  return h('div', { class: 'field copy-field' },
    h('label', { class: ['field-label', opts.hideLabel && 'sr-only'], for: id, text: opts.label }),
    h('div', { class: 'input-wrap' }, input, btn),
    opts.help ? h('p', { class: 'field-help', text: opts.help }) : null);
}
