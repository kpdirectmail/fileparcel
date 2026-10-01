// @ts-check
/**
 * Basic uploader — the foundation's fallback for the Upload button until unit J1 ships js/upload/* (queue panel,
 * hash worker, parallel parts, pause/resume, drop zone). It implements the §8.1 protocol sequentially:
 *   POST /upload-batches → per file: PUT …/small (≤ small_max) or PUT /uploads/{id}/parts/{n} + POST …/complete
 *   → POST /upload-batches/{id}/complete
 * Per-part SHA-256 (X-FP-SHA256) is computed on the main thread with crypto.subtle (HTTPS only).
 * After success it emits the in-app event 'files.changed' {folderId}.
 *
 *   uploadFiles(files, folderId?)  newFolder(parentId?)  resolveHomeFolder()
 *   uploadWithProtocol({apiBase, files, folderId, uploader, onProgress, isCancelled}) — also used by public/share.js
 * @module upload/basic
 */
import { h, icon } from '../core/dom.js';
import { api, raw, errorFrom, itemsOf, ApiError } from '../core/api.js';
import { events } from '../core/store.js';
import { bytes, speed } from '../core/format.js';
import { toast } from '../components/toast.js';
import { prompt } from '../components/dialog.js';
import { progress } from '../components/progress.js';

const MiB = 1024 * 1024;

/**
 * Root folder id of the user's personal space (upload default).
 * @returns {Promise<string>}
 */
export async function resolveHomeFolder() {
  const spaces = itemsOf(await api.get('/spaces'));
  const mine = spaces.find((s) => s.kind === 'user') || spaces[0];
  const id = mine && (mine.root_id || mine.root_node_id || mine.root?.id);
  if (!id) throw new Error('No destination folder is available for your account.');
  return id;
}

/**
 * SHA-256 hex of a blob.
 * @param {Blob} blob
 */
async function sha256Hex(blob) {
  if (!crypto?.subtle) throw new Error('Uploading needs a secure (HTTPS) connection.');
  const digest = await crypto.subtle.digest('SHA-256', await blob.arrayBuffer());
  return Array.from(new Uint8Array(digest), (b) => b.toString(16).padStart(2, '0')).join('');
}

/**
 * @param {Response} res
 */
async function ensureOk(res) {
  if (!res.ok) throw await errorFrom(res);
}

/**
 * Create a folder (prompting for its name) inside `parentId` (default: My files root).
 * @param {string} [parentId]
 */
export async function newFolder(parentId) {
  const name = await prompt({ title: 'New folder', label: 'Folder name', value: 'New folder', confirmLabel: 'Create' });
  if (!name) return null;
  const parent = parentId || (await resolveHomeFolder());
  try {
    const node = await api.post(`/nodes/${encodeURIComponent(parent)}/folders`, { name });
    toast.success(`Folder “${name}” created`);
    events.emit('files.changed', { folderId: parent, node });
    return node;
  } catch (err) {
    toast.error(err);
    return null;
  }
}

/**
 * @typedef {Object} ProtocolOpts
 * @property {string} apiBase "/api/v1" (signed-in) or "/s/<token>/api" (public file request)
 * @property {File[]} files
 * @property {string} folderId destination folder (for file requests: the share's folder)
 * @property {string} [uploader] uploader name (file requests with require_uploader_name)
 * @property {'rename' | 'replace' | 'skip' | 'fail'} [conflict]
 * @property {(sent: number, total: number, label: string) => void} [onProgress]
 * @property {() => boolean} [isCancelled]
 * @property {(batchId: string) => void} [onBatch] called once the batch exists (for cancellation)
 */

/**
 * Run the §8.1 upload protocol sequentially. Throws ApiError on failure (code "aborted" when cancelled).
 * @param {ProtocolOpts} o
 * @returns {Promise<{batchId: string}>}
 */
export async function uploadWithProtocol(o) {
  const base = o.apiBase.replace(/\/$/, '');
  const files = o.files;
  const total = files.reduce((n, f) => n + f.size, 0);
  let sent = 0;
  const cancelled = () => !!o.isCancelled?.();
  const progressTo = (/** @type {string} */ label) => o.onProgress?.(sent, total, label);

  const entries = files.map((f, i) => ({
    client_ref: `f${i}`,
    rel_path: /** @type {any} */ (f).webkitRelativePath || /** @type {any} */ (f).relativePath || f.name,
    size: f.size,
    mtime: f.lastModified || undefined,
    kind: 'file',
  }));
  /** @type {Record<string, any>} */
  const input = { folder_id: o.folderId, mode: 'files', conflict: o.conflict || 'rename', files: entries.slice(0, 1000) };
  if (o.uploader) input.uploader = o.uploader;
  const batch = await api.post(`${base}/upload-batches`, input, { handle: base.startsWith('/api/') });
  const batchId = batch.id;
  o.onBatch?.(batchId);
  /** @type {any[]} */
  const states = [...(batch.files || [])];
  for (let i = 1000; i < entries.length; i += 1000) {
    const more = await api.post(`${base}/upload-batches/${encodeURIComponent(batchId)}/files`, entries.slice(i, i + 1000));
    const got = Array.isArray(more) ? more : more?.files || more?.items || [];
    states.push(...got);
  }
  const partSize = batch.part_size || 8 * MiB;
  const smallMax = batch.small_max ?? 8 * MiB;
  const byRef = new Map(states.map((s) => [s.client_ref, s]));

  for (let i = 0; i < files.length; i += 1) {
    if (cancelled()) throw new ApiError(0, 'aborted', 'Upload cancelled');
    const f = files[i];
    const ref = `f${i}`;
    const label = `${f.name} (${i + 1}/${files.length})`;
    progressTo(label);
    if (f.size <= smallMax) {
      const sha = await sha256Hex(f);
      const res = await raw(`${base}/upload-batches/${encodeURIComponent(batchId)}/small`, {
        method: 'PUT', query: { ref }, body: f, headers: { 'X-FP-SHA256': sha, 'Content-Type': 'application/octet-stream' },
      });
      await ensureOk(res);
      sent += f.size;
      continue;
    }
    const st = byRef.get(ref);
    if (!st?.id) throw new Error(`The server did not accept ${f.name}.`);
    const parts = st.part_count || Math.ceil(f.size / partSize);
    const done = new Set(Array.isArray(st.parts_done) ? st.parts_done : []);
    for (let n = 0; n < parts; n += 1) {
      if (cancelled()) throw new ApiError(0, 'aborted', 'Upload cancelled');
      const chunk = f.slice(n * partSize, Math.min(f.size, (n + 1) * partSize));
      if (!done.has(n)) {
        const sha = await sha256Hex(chunk);
        let attempt = 0;
        for (;;) {
          try {
            const res = await raw(`${base}/uploads/${encodeURIComponent(st.id)}/parts/${n}`, {
              method: 'PUT', body: chunk, headers: { 'X-FP-SHA256': sha, 'Content-Type': 'application/octet-stream' },
            });
            await ensureOk(res);
            break;
          } catch (err) {
            attempt += 1;
            const status = err instanceof ApiError ? err.status : 0;
            if (cancelled() || attempt >= 6 || (status >= 400 && status < 500 && status !== 408 && status !== 429)) throw err;
            await new Promise((r) => setTimeout(r, Math.min(30_000, 1000 * 2 ** (attempt - 1))));
          }
        }
      }
      sent += chunk.size;
      progressTo(label);
    }
    await api.post(`${base}/uploads/${encodeURIComponent(st.id)}/complete`, {}, { handle: base.startsWith('/api/') });
  }
  await api.post(`${base}/upload-batches/${encodeURIComponent(batchId)}/complete`, {}, { handle: base.startsWith('/api/') });
  progressTo('Done');
  return { batchId };
}

/**
 * Upload files (from a picker or drop) into `folderId` with a small progress panel.
 * @param {File[]} files
 * @param {string} [folderId]
 */
export async function uploadFiles(files, folderId) {
  if (!files.length) return;
  const folder = folderId || (await resolveHomeFolder());
  const total = files.reduce((n, f) => n + f.size, 0);
  let cancelled = false;
  let batchId = '';
  const started = Date.now();

  const bar = progress({ value: 0, max: Math.max(total, 1), label: 'Preparing…', showValue: true });
  const title = h('strong', { text: `Uploading ${files.length === 1 ? files[0].name : `${files.length} files`}` });
  const meta = h('small', { text: bytes(total) });
  const cancelBtn = h('button', {
    class: 'icon-btn icon-btn--sm',
    attrs: { type: 'button', 'aria-label': 'Cancel upload', title: 'Cancel upload' },
    on: {
      click: () => {
        cancelled = true;
        if (batchId) api.del(`/upload-batches/${encodeURIComponent(batchId)}`, undefined, { handle: false }).catch(() => {});
      },
    },
  }, icon('x'));
  const panel = h('section', { class: 'upload-panel', attrs: { 'aria-label': 'Upload progress', role: 'region' } },
    h('div', { class: 'upload-panel-head' }, icon('cloud-upload'), h('div', { class: 'upload-panel-title' }, title, meta), cancelBtn),
    h('div', { class: 'upload-panel-body' }, bar.el));
  document.body.appendChild(panel);
  const guard = (/** @type {BeforeUnloadEvent} */ e) => { e.preventDefault(); };
  window.addEventListener('beforeunload', guard);
  /** @type {any} */
  let wakeLock = null;
  try { wakeLock = await /** @type {any} */ (navigator).wakeLock?.request('screen'); } catch { /* optional */ }

  try {
    await uploadWithProtocol({
      apiBase: '/api/v1',
      files,
      folderId: folder,
      isCancelled: () => cancelled,
      onBatch: (id) => { batchId = id; },
      onProgress: (sent, tot, label) => {
        const secs = (Date.now() - started) / 1000;
        bar.set(sent, Math.max(tot, 1), label);
        meta.textContent = `${bytes(sent)} of ${bytes(tot)} · ${speed(secs > 0 ? sent / secs : 0)}`;
      },
    });
    toast.success(files.length === 1 ? `Uploaded ${files[0].name}` : `Uploaded ${files.length} files`);
  } catch (err) {
    if (err instanceof ApiError && err.aborted) toast.info('Upload cancelled');
    else toast.error(err);
    if (batchId && !cancelled) api.del(`/upload-batches/${encodeURIComponent(batchId)}`, undefined, { handle: false }).catch(() => {});
  } finally {
    events.emit('files.changed', { folderId: folder });
    window.removeEventListener('beforeunload', guard);
    try { await wakeLock?.release(); } catch { /* ignore */ }
    setTimeout(() => panel.remove(), 1200);
  }
}
