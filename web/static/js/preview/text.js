// @ts-check
/**
 * Text / code previewer. Previews the first 2 MiB of the file (a Range request for larger files), decodes it as UTF-8
 * (windows-1252 when it is not valid UTF-8, e.g. Latin-1 text; decodeText) and shows it with line numbers. The
 * content is ALWAYS inserted as text (textContent), never as markup — HTML, SVG and scripts are shown as source.
 * Binary files (NUL bytes in the first 8 KiB) fall back to the details card.
 * @module preview/text
 */
import { h, icon } from '../core/dom.js';
import { raw } from '../core/api.js';
import { contentURL } from '../core/nodes.js';
import { bytes } from '../core/format.js';
import { persisted } from '../core/store.js';

/** Maximum bytes shown in the preview. */
export const TEXT_LIMIT = 2 * 1024 * 1024;

const wrapPref = persisted('preview-wrap', false);

/**
 * Read at most `limit` bytes of a response body.
 * @param {Response} res
 * @param {number} limit
 * @param {AbortSignal} signal
 */
async function readCapped(res, limit, signal) {
  if (!res.body) return new Uint8Array(await res.arrayBuffer()).subarray(0, limit);
  const reader = res.body.getReader();
  const chunks = [];
  let n = 0;
  try {
    while (n < limit) {
      if (signal.aborted) throw new DOMException('aborted', 'AbortError');
      const { done, value } = await reader.read();
      if (done) break;
      chunks.push(value);
      n += value.length;
    }
  } finally {
    reader.cancel().catch(() => {});
  }
  const out = new Uint8Array(Math.min(n, limit));
  let off = 0;
  for (const c of chunks) {
    const take = Math.min(c.length, out.length - off);
    out.set(c.subarray(0, take), off);
    off += take;
    if (off >= out.length) break;
  }
  return out;
}

/**
 * Decode the bytes of a text preview. UTF-8 when they are valid UTF-8, else windows-1252 (a superset of Latin-1, what
 * legacy "text/plain" files from Windows editors are), so "café" saved as ISO-8859-1 does not turn into "caf�".
 * `truncated`: `buf` is the start of a longer file, so a multi-byte character cut in half at the end is dropped
 * instead of becoming U+FFFD (and does not count as invalid UTF-8).
 * @param {Uint8Array} buf
 * @param {boolean} truncated
 * @returns {{text: string, encoding: 'utf-8' | 'windows-1252'}}
 */
export function decodeText(buf, truncated) {
  try {
    return { text: new TextDecoder('utf-8', { fatal: true }).decode(buf, { stream: truncated }), encoding: 'utf-8' };
  } catch {
    return { text: new TextDecoder('windows-1252').decode(buf), encoding: 'windows-1252' };
  }
}

/**
 * @param {import('../core/nodes.js').Node} node
 * @param {{onError: (msg: string) => void, fallback: (msg: string) => HTMLElement}} ctx
 * @returns {import('./image.js').Renderer}
 */
export function textRenderer(node, ctx) {
  const ctrl = new AbortController();
  const gutter = h('pre', { class: 'pv-gutter', attrs: { 'aria-hidden': 'true' } });
  const code = h('pre', { class: 'pv-code', attrs: { tabindex: '0', 'aria-label': `Contents of ${node.name}` } });
  const note = h('p', { class: 'pv-text-note', hidden: true });
  const scroller = h('div', { class: 'pv-text-scroll' }, gutter, code);
  const el = h('div', { class: 'pv-text', dataset: { loading: '' } }, note, scroller, h('div', { class: 'pv-text-spinner' }, h('span', { class: 'spinner spinner--lg', attrs: { role: 'status', 'aria-label': 'Loading' } })));

  const wrapBtn = h('button', {
    class: 'icon-btn pv-tool',
    attrs: { type: 'button', 'aria-pressed': String(!!wrapPref.peek()), title: 'Wrap long lines', 'aria-label': 'Wrap long lines' },
    on: {
      click: () => {
        wrapPref.value = !wrapPref.peek();
        wrapBtn.setAttribute('aria-pressed', String(wrapPref.value));
        el.toggleAttribute('data-wrap', !!wrapPref.value);
      },
    },
  }, icon('wrap-text'));
  el.toggleAttribute('data-wrap', !!wrapPref.peek());

  (async () => {
    try {
      const big = node.size > TEXT_LIMIT;
      const res = await raw(contentURL(node), { headers: big ? { Range: `bytes=0-${TEXT_LIMIT - 1}` } : {}, signal: ctrl.signal });
      if (!res.ok && res.status !== 206) throw new Error(res.status === 404 ? 'This file no longer exists.' : `The file could not be loaded (${res.status}).`);
      // One byte past the limit tells "exactly TEXT_LIMIT bytes" (all of it shown) from "more than that" — a file that
      // grew since the listing (no Range sent), or a server that ignored the Range and sent the whole body.
      const all = await readCapped(res, TEXT_LIMIT + 1, ctrl.signal);
      const truncated = big || all.length > TEXT_LIMIT;
      const buf = all.subarray(0, TEXT_LIMIT);
      const head = buf.subarray(0, 8192);
      if (head.includes(0)) {
        el.replaceWith(ctx.fallback('This file looks like binary data, so there is no text preview.'));
        return;
      }
      let { text } = decodeText(buf, truncated);
      if (truncated) {
        const cut = text.lastIndexOf('\n');
        if (cut > 0) text = text.slice(0, cut + 1);
        note.hidden = false;
        // node.size is stale when the file grew past the limit after the listing: then there is no total to quote.
        note.textContent = `Showing the first ${bytes(TEXT_LIMIT)}${big ? ` of ${bytes(node.size)}` : ''}. Download the file to see all of it.`;
      }
      if (text.endsWith('\n')) text = text.slice(0, -1);
      const lines = text.split('\n').length;
      const nums = new Array(lines);
      for (let i = 0; i < lines; i += 1) nums[i] = i + 1;
      gutter.textContent = nums.join('\n');
      code.textContent = text;
      el.style.setProperty('--pv-gutter-ch', String(String(lines).length + 1));
      delete el.dataset.loading;
    } catch (err) {
      if (/** @type {any} */ (err)?.name === 'AbortError') return;
      ctx.onError(err instanceof Error ? err.message : String(err));
    }
  })();

  return {
    el,
    toolbar: wrapBtn,
    destroy: () => ctrl.abort(),
  };
}
