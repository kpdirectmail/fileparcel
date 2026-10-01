// @ts-check
/**
 * Compact upload client for public file requests and folder links that accept uploads (/s/{token}), implementing the
 * §8.1 protocol against the share endpoints under /s/{token}/api (no session, no CSRF token; CrossOriginProtection
 * only):
 *   POST /s/{t}/api/upload-batches {folder_id, mode: "files", conflict: "rename", uploader?, files: [...]}
 *     → UploadBatch {id, part_size, parallel, small_max, files: [UploadFileState]}
 *   PUT  /s/{t}/api/upload-batches/{id}/small?ref=<client_ref>   raw body + X-FP-SHA256   (files ≤ small_max)
 *   PUT  /s/{t}/api/uploads/{upf}/parts/{n}                        raw body + X-FP-SHA256   (larger files)
 *   POST /s/{t}/api/uploads/{upf}/complete · POST /s/{t}/api/upload-batches/{id}/complete
 *   DELETE /s/{t}/api/uploads/{upf}         (a file that failed for good, so the rest of its batch can complete;
 *                                            a 409 is checked with GET /s/{t}/api/uploads/{upf}: stored after all?)
 *   DELETE /s/{t}/api/upload-batches/{id}   (best effort on cancel, or when a run fails: releases the reservation)
 * Selections larger than 1000 entries are sent as consecutive batches of at most 1000 entries (each is created,
 * uploaded and completed before the next one starts, so a very large drop never holds one huge reservation).
 * Parts are hashed with crypto.subtle (SHA-256 of the part plaintext) and sent with up to `parallel` requests in
 * flight; failed requests are retried with exponential backoff (1 s → 30 s, 6 tries) unless the error is final, and
 * a stalled request (no progress for 60 s) is aborted and retried.
 * XMLHttpRequest is used for the data requests because fetch() cannot report upload progress.
 * Picked and dropped items skip OS junk files and names the server would reject (upload/scan.js skipReason); a
 * folder left with nothing but skipped entries is sent as an empty directory (emptiedFolders).
 * Owned by unit J2 (J1's js/upload/* targets the signed-in API and is being reworked concurrently).
 * @module public/share-upload
 */
import { api, ApiError } from '../core/api.js';
import { skipReason, emptiedFolders } from '../upload/scan.js';

const MiB = 1024 * 1024;
const BATCH_MAX = 1000;
const RETRIES = 6;
const STALL_MS = 60_000;

/**
 * @typedef {Object} UploadEntry
 * @property {string} relPath "Trip/day1/a.jpg" (no leading slash)
 * @property {'file' | 'dir'} kind
 * @property {File} [file] for kind "file"
 * @property {number} size
 */

/**
 * @typedef {Object} Picked
 * @property {UploadEntry[]} entries
 * @property {string[]} skipped relative paths left out (OS junk files, names the server would reject)
 */

/**
 * @typedef {Object} EntryProgress
 * @property {UploadEntry} entry
 * @property {number} sent bytes acknowledged by the server (plus the in-flight part's progress)
 * @property {'queued' | 'hashing' | 'uploading' | 'done' | 'failed' | 'skipped'} state
 * @property {string} [error]
 */

/**
 * @typedef {Object} UploadSnapshot
 * @property {number} sent
 * @property {number} total
 * @property {number} files files done
 * @property {number} fileCount
 * @property {number} bytesPerSecond smoothed
 * @property {number} etaSeconds -1 when unknown
 * @property {EntryProgress[]} entries
 */

/**
 * SHA-256 hex digest of a blob.
 * @param {Blob} blob
 */
export async function sha256Hex(blob) {
  if (!globalThis.crypto?.subtle) throw new ApiError(0, 'insecure', 'Uploading needs a secure (HTTPS) connection.');
  const digest = await crypto.subtle.digest('SHA-256', await blob.arrayBuffer());
  let hex = '';
  for (const b of new Uint8Array(digest)) hex += b.toString(16).padStart(2, '0');
  return hex;
}

/** @param {number} ms @param {AbortSignal} [signal] */
function sleep(ms, signal) {
  return new Promise((resolve, reject) => {
    const t = setTimeout(resolve, ms);
    signal?.addEventListener('abort', () => {
      clearTimeout(t);
      reject(new ApiError(0, 'aborted', 'Upload cancelled'));
    }, { once: true });
  });
}

/**
 * Parse an XHR error response into an ApiError.
 * @param {XMLHttpRequest} xhr
 */
function xhrError(xhr) {
  /** @type {any} */
  let body = null;
  try { body = JSON.parse(xhr.responseText || 'null'); } catch { /* not JSON */ }
  const e = body && body.error ? body.error : {};
  const status = xhr.status;
  let message = e.message || '';
  if (!message) {
    if (status === 413) message = 'That file is larger than this request allows.';
    else if (status === 507) message = 'The recipient has no storage space left for this upload.';
    else if (status === 429) message = 'Too many uploads at once. Retrying…';
    else if (status >= 500) message = 'The server had a problem receiving the file.';
    else message = `Upload failed (${status}).`;
  }
  const err = new ApiError(status, e.code || `http_${status}`, message, e.field, e.request_id, body);
  const ra = Number(xhr.getResponseHeader('Retry-After')); // same as core/api.js errorFrom()
  if (Number.isFinite(ra) && ra > 0) err.retryAfter = ra;
  return err;
}

/**
 * PUT a body with upload progress.
 * @param {string} url
 * @param {Blob} body
 * @param {Record<string, string>} headers
 * @param {(loaded: number) => void} onProgress
 * @param {AbortSignal} signal
 * @returns {Promise<any>} parsed JSON response (or null)
 */
function xhrPut(url, body, headers, onProgress, signal) {
  return new Promise((resolve, reject) => {
    if (signal.aborted) {
      reject(new ApiError(0, 'aborted', 'Upload cancelled'));
      return;
    }
    const xhr = new XMLHttpRequest();
    // A connection that dies without an error (NAT state dropped, a Wi-Fi → mobile hand-over) never fires 'error'
    // until the OS gives up minutes later: abort a request that made no progress for STALL_MS, as a retryable
    // network error (not 'aborted', which withRetry treats as the visitor's cancel), so withRetry sends it again.
    let last = Date.now();
    let stalled = false;
    const watchdog = setInterval(() => {
      if (Date.now() - last > STALL_MS) {
        stalled = true;
        xhr.abort();
      }
    }, 5000);
    const onAbort = () => xhr.abort();
    const cleanup = () => {
      clearInterval(watchdog);
      signal.removeEventListener('abort', onAbort);
    };
    xhr.open('PUT', url);
    xhr.withCredentials = true;
    for (const [k, v] of Object.entries(headers)) xhr.setRequestHeader(k, v);
    xhr.upload.addEventListener('progress', (e) => {
      last = Date.now();
      onProgress(e.loaded);
    });
    signal.addEventListener('abort', onAbort, { once: true });
    xhr.addEventListener('load', () => {
      cleanup();
      if (xhr.status >= 200 && xhr.status < 300) {
        let data = null;
        try { data = xhr.responseText ? JSON.parse(xhr.responseText) : null; } catch { /* 204 */ }
        resolve(data);
      } else {
        reject(xhrError(xhr));
      }
    });
    const onError = () => {
      cleanup();
      reject(new ApiError(0, 'network', 'The connection was interrupted.'));
    };
    xhr.addEventListener('error', onError);
    xhr.addEventListener('timeout', onError);
    xhr.addEventListener('abort', () => {
      cleanup();
      reject(stalled ? new ApiError(0, 'network', 'The connection stalled.') : new ApiError(0, 'aborted', 'Upload cancelled'));
    });
    xhr.send(body);
  });
}

/**
 * Whether a failed request may succeed when sent again: no answer, a timeout, a rate limit or a server error — but
 * not 507 quota_exceeded (the request has no room left) or 501/505, which are final answers.
 * @param {ApiError} e
 */
export function transientError(e) {
  if (e.code === 'quota_exceeded' || e.status === 501 || e.status === 505 || e.status === 507) return false;
  return e.status === 0 || e.status === 408 || e.status === 429 || e.status >= 500;
}

/**
 * Retry `fn` on transient failures (transientError).
 * @template T
 * @param {() => Promise<T>} fn
 * @param {AbortSignal} signal
 * @param {(attempt: number, err: ApiError) => void} [onRetry]
 * @returns {Promise<T>}
 */
async function withRetry(fn, signal, onRetry) {
  for (let attempt = 1; ; attempt += 1) {
    try {
      return await fn();
    } catch (err) {
      const e = err instanceof ApiError ? err : new ApiError(0, 'network', err instanceof Error ? err.message : String(err));
      if (e.aborted || signal.aborted || !transientError(e) || e.code === 'insecure' || attempt >= RETRIES) throw e;
      onRetry?.(attempt, e);
      await sleep(Math.min(30_000, 1000 * 2 ** (attempt - 1)), signal);
    }
  }
}

/** @param {string} rel */
const cleanRel = (rel) => rel.replace(/^\/+/, '').normalize('NFC');

/**
 * Add a file to `out`, or to its skipped list (junk file or a name the server would reject: one such name would
 * otherwise make the server refuse the whole batch).
 * @param {Picked} out
 * @param {File} file
 * @param {string} rel
 */
function addFile(out, file, rel) {
  const path = cleanRel(rel);
  if (skipReason(path)) out.skipped.push(path);
  else out.entries.push({ relPath: path, kind: 'file', file, size: file.size });
}

/**
 * Keep a folder whose children were all skipped (e.g. it only held a .DS_Store) as an empty directory, like a
 * folder that really is empty.
 * @param {Picked} out
 */
function keepEmptied(out) {
  if (!out.skipped.length) return;
  for (const d of emptiedFolders(out.entries.map((e) => e.relPath), out.skipped)) out.entries.push({ relPath: d, kind: 'dir', size: 0 });
}

/**
 * Collect upload entries from a drop (files and folders, including empty folders).
 * @param {DataTransfer} dt
 * @returns {Promise<Picked>}
 */
export async function entriesFromDataTransfer(dt) {
  /** @type {Picked} */
  const out = { entries: [], skipped: [] };
  const items = Array.from(dt.items || []).filter((i) => i.kind === 'file');
  const roots = items.map((i) => (typeof i.webkitGetAsEntry === 'function' ? i.webkitGetAsEntry() : null));
  if (!roots.length || roots.some((r) => !r)) {
    for (const f of Array.from(dt.files || [])) addFile(out, f, f.name);
    return out;
  }
  /** @param {any} entry */
  const walk = async (entry) => {
    const rel = cleanRel(String(entry.fullPath || entry.name));
    if (entry.isFile) {
      if (skipReason(rel)) {
        out.skipped.push(rel);
        return;
      }
      /** @type {File} */
      const file = await new Promise((resolve, reject) => entry.file(resolve, reject));
      out.entries.push({ relPath: rel, kind: 'file', file, size: file.size });
      return;
    }
    if (!entry.isDirectory) return;
    const reader = entry.createReader();
    /** @type {any[]} */
    const children = [];
    for (;;) {
      /** @type {any[]} */
      const batch = await new Promise((resolve, reject) => reader.readEntries(resolve, reject));
      if (!batch.length) break;
      children.push(...batch);
    }
    if (!children.length) {
      if (skipReason(rel, true)) out.skipped.push(rel);
      else out.entries.push({ relPath: rel, kind: 'dir', size: 0 });
    }
    for (const c of children) await walk(c);
  };
  for (const r of roots) await walk(r);
  keepEmptied(out);
  return out;
}

/**
 * Upload entries from a file picker (folder pickers set webkitRelativePath).
 * @param {FileList | File[]} files
 * @returns {Picked}
 */
export function entriesFromFiles(files) {
  /** @type {Picked} */
  const out = { entries: [], skipped: [] };
  for (const f of Array.from(files)) addFile(out, f, /** @type {any} */ (f).webkitRelativePath || f.name);
  keepEmptied(out);
  return out;
}

/**
 * One upload run (one or more batches).
 */
export class ShareUpload {
  /**
   * @param {{apiBase: string, folderId: string, subPath?: string, uploader?: string, onUpdate?: (s: UploadSnapshot) => void}} opts
   *   folderId is the shared folder (the server takes no other); subPath ("Photos/2024") puts the entries below one
   *   of its sub-folders instead — rel_path folders are created or reused on arrival.
   */
  constructor(opts) {
    this.base = opts.apiBase.replace(/\/$/, '');
    this.folderId = opts.folderId;
    this.subPath = (opts.subPath || '').replace(/^\/+|\/+$/g, '');
    this.uploader = opts.uploader || '';
    this.onUpdate = opts.onUpdate || (() => {});
    this.ctrl = new AbortController();
    /** @type {EntryProgress[]} */
    this.progress = [];
    /** @type {string[]} */
    this.openBatches = [];
    this.startedAt = 0;
    this.rate = 0;
    this.lastTick = 0;
    this.lastSent = 0;
    this.raf = 0;
    /** First batch-wide failure (quota, share gone); set when the run was stopped because of it. @type {ApiError | null} */
    this.fatal = null;
  }

  /** Cancel everything in flight and abort open batches (best effort). */
  cancel() {
    if (this.ctrl.signal.aborted) return;
    this.ctrl.abort();
    this.abortOpenBatches();
  }

  /**
   * Abort the batches still open on the server (best effort): their unfinished files are dropped and the
   * reservation is released now instead of when the batch expires. Files already delivered stay.
   */
  abortOpenBatches() {
    const ids = this.openBatches;
    this.openBatches = [];
    for (const id of ids) {
      api.del(`${this.base}/upload-batches/${encodeURIComponent(id)}`, undefined, { handle: false }).catch(() => {});
    }
  }

  get cancelled() {
    return this.ctrl.signal.aborted;
  }

  /** @returns {UploadSnapshot} */
  snapshot() {
    let sent = 0;
    let total = 0;
    let files = 0;
    let fileCount = 0;
    for (const p of this.progress) {
      if (p.entry.kind !== 'file') continue;
      fileCount += 1;
      total += p.entry.size;
      sent += Math.min(p.sent, p.entry.size);
      if (p.state === 'done' || p.state === 'skipped') files += 1;
    }
    const now = performance.now();
    if (!this.lastTick) {
      this.lastTick = now;
      this.lastSent = sent;
    } else if (now - this.lastTick >= 500) {
      const inst = ((sent - this.lastSent) * 1000) / (now - this.lastTick);
      this.rate = this.rate ? this.rate * 0.7 + inst * 0.3 : inst;
      this.lastTick = now;
      this.lastSent = sent;
    }
    const eta = this.rate > 1 ? (total - sent) / this.rate : -1;
    return { sent, total, files, fileCount, bytesPerSecond: Math.max(0, this.rate), etaSeconds: eta, entries: this.progress };
  }

  /** Coalesce UI updates to one per animation frame. */
  notify() {
    if (this.raf) return;
    this.raf = requestAnimationFrame(() => {
      this.raf = 0;
      this.onUpdate(this.snapshot());
    });
  }

  /**
   * Upload all entries. Resolves with the final snapshot; rejects with ApiError (code "aborted" when cancelled).
   * Per-file failures that are final (retries used up, an unreadable file, a name the server rejects) mark that
   * entry failed and continue: the file is released on the server before its batch completes, and the returned
   * snapshot lists it. When the run fails or is cancelled, `progress` still tells which entries were delivered
   * ('done' / 'skipped'; an empty folder only once its batch completed).
   * @param {UploadEntry[]} entries
   * @returns {Promise<UploadSnapshot>}
   */
  async run(entries) {
    this.progress = entries.map((entry) => ({ entry, sent: 0, state: /** @type {EntryProgress['state']} */ ('queued') }));
    this.startedAt = performance.now();
    this.notify();
    try {
      for (let i = 0; i < this.progress.length; i += BATCH_MAX) {
        if (this.cancelled) throw new ApiError(0, 'aborted', 'Upload cancelled');
        await this.runBatch(this.progress.slice(i, i + BATCH_MAX));
      }
    } catch (err) {
      this.abortOpenBatches();
      throw this.fatal || err;
    }
    const snap = this.snapshot();
    this.onUpdate(snap);
    return snap;
  }

  /**
   * @param {EntryProgress[]} items
   */
  async runBatch(items) {
    const signal = this.ctrl.signal;
    /** @type {Record<string, any>} */
    const input = {
      folder_id: this.folderId,
      mode: 'files',
      conflict: 'rename',
      files: items.map((p, i) => ({
        client_ref: `r${i}`,
        rel_path: this.subPath ? `${this.subPath}/${p.entry.relPath}` : p.entry.relPath,
        size: p.entry.kind === 'dir' ? 0 : p.entry.size,
        kind: p.entry.kind,
        mtime: p.entry.file?.lastModified || undefined,
        mime: p.entry.file?.type || undefined,
      })),
    };
    if (this.uploader) input.uploader = this.uploader;
    const batch = await withRetry(() => api.post(`${this.base}/upload-batches`, input, { handle: false, signal }), signal);
    const batchId = String(batch?.id || '');
    if (!batchId) throw new ApiError(500, 'bad_response', 'The server did not start the upload.');
    this.openBatches.push(batchId);
    const partSize = Number(batch.part_size) || 8 * MiB;
    const smallMax = Number(batch.small_max ?? 8 * MiB);
    const parallel = Math.max(1, Math.min(8, Number(batch.parallel) || 4));
    /** @type {Map<string, any>} */
    const states = new Map((batch.files || []).map((/** @type {any} */ s) => [s.client_ref, s]));

    /** @typedef {{run: () => Promise<void>}} Task */
    /** @type {Task[]} */
    const tasks = [];
    items.forEach((p, i) => {
      const ref = `r${i}`;
      if (p.entry.kind === 'dir') return; // created by the batch /complete below
      const st = states.get(ref);
      if (st && (st.state === 'committed' || st.state === 'skipped')) {
        p.state = st.state === 'skipped' ? 'skipped' : 'done';
        p.sent = p.entry.size;
        return;
      }
      const file = /** @type {File} */ (p.entry.file);
      if (p.entry.size <= smallMax) {
        tasks.push({ run: () => this.uploadSmall(batchId, ref, p, file) });
        return;
      }
      if (!st?.id) {
        p.state = 'failed';
        p.error = 'The server did not accept this file.';
        return;
      }
      const parts = Number(st.part_count) || Math.ceil(p.entry.size / partSize);
      const done = new Set(Array.isArray(st.parts_done) ? st.parts_done : []);
      /** @type {number[]} */
      const partSent = Array.from({ length: parts }, (_, n) => (done.has(n) ? Math.min(partSize, p.entry.size - n * partSize) : 0));
      let remaining = parts - done.size;
      let failed = false;
      const recompute = () => { p.sent = partSent.reduce((a, b) => a + b, 0); this.notify(); };
      recompute();
      const complete = async () => {
        await withRetry(() => api.post(`${this.base}/uploads/${encodeURIComponent(st.id)}/complete`, {}, { handle: false, signal }), signal);
        p.state = 'done';
        p.sent = p.entry.size;
        this.notify();
      };
      if (remaining === 0) {
        tasks.push({ run: () => complete().catch((err) => this.fail(p, err)) });
        return;
      }
      for (let n = 0; n < parts; n += 1) {
        if (done.has(n)) continue;
        tasks.push({
          run: async () => {
            if (failed) return;
            const start = n * partSize;
            const chunk = file.slice(start, Math.min(p.entry.size, start + partSize));
            try {
              if (p.state === 'queued') p.state = 'hashing';
              this.notify();
              const sha = await sha256Hex(chunk);
              if (failed) return; // another part failed meanwhile: the entry stays 'failed' and is released before /complete
              p.state = 'uploading';
              await withRetry(() => xhrPut(
                `${this.base}/uploads/${encodeURIComponent(st.id)}/parts/${n}`,
                chunk,
                { 'X-FP-SHA256': sha, 'Content-Type': 'application/octet-stream' },
                (loaded) => { partSent[n] = Math.min(loaded, chunk.size); recompute(); },
                signal,
              ), signal, () => { partSent[n] = 0; recompute(); });
              partSent[n] = chunk.size;
              recompute();
              remaining -= 1;
              if (remaining === 0) await complete();
            } catch (err) {
              failed = true;
              this.fail(p, err);
            }
          },
        });
      }
    });

    // worker pool
    let next = 0;
    const worker = async () => {
      while (next < tasks.length) {
        if (signal.aborted) return;
        const t = tasks[next];
        next += 1;
        await t.run();
      }
    };
    await Promise.all(Array.from({ length: Math.min(parallel, Math.max(1, tasks.length)) }, worker));
    if (signal.aborted) throw new ApiError(0, 'aborted', 'Upload cancelled');
    // A file that failed for good is still pending on the server, and the batch /complete refuses a batch with
    // unfinished files (409). Abort those files first (every task has settled, so nothing of theirs is in flight):
    // that releases their reservation and lets the delivered files complete; they stay 'failed' here, so "Retry
    // failed files" sends only them again.
    for (const [i, p] of items.entries()) {
      const st = states.get(`r${i}`);
      if (p.state !== 'failed' || !st?.id) continue;
      try {
        await withRetry(() => api.del(`${this.base}/uploads/${encodeURIComponent(st.id)}`, undefined, { handle: false, signal }), signal);
      } catch (err) {
        if (!(err instanceof ApiError && err.status === 409)) throw err;
        // 409: either the file was stored after all (its last response was lost: it must not be sent again), or
        // the batch is no longer open (the batch /complete below reports that)
        /** @type {any} */
        const cur = await api.get(`${this.base}/uploads/${encodeURIComponent(st.id)}`, { handle: false, signal }).catch(() => null);
        if (cur?.state === 'committed' || cur?.state === 'skipped') {
          p.state = cur.state === 'skipped' ? 'skipped' : 'done';
          p.error = undefined;
          p.sent = p.entry.size;
        }
      }
    }
    await withRetry(() => api.post(`${this.base}/upload-batches/${encodeURIComponent(batchId)}/complete`, {}, { handle: false, signal }), signal);
    this.openBatches = this.openBatches.filter((id) => id !== batchId);
    for (const p of items) if (p.entry.kind === 'dir') p.state = 'done';
    this.notify();
  }

  /**
   * @param {string} batchId
   * @param {string} ref
   * @param {EntryProgress} p
   * @param {File} file
   */
  async uploadSmall(batchId, ref, p, file) {
    const signal = this.ctrl.signal;
    try {
      p.state = 'hashing';
      this.notify();
      const sha = await sha256Hex(file);
      p.state = 'uploading';
      const res = await withRetry(() => xhrPut(
        `${this.base}/upload-batches/${encodeURIComponent(batchId)}/small?ref=${encodeURIComponent(ref)}`,
        file,
        { 'X-FP-SHA256': sha, 'Content-Type': 'application/octet-stream' },
        (loaded) => { p.sent = Math.min(loaded, p.entry.size); this.notify(); },
        signal,
      ), signal, () => { p.sent = 0; this.notify(); });
      p.state = res && res.state === 'skipped' ? 'skipped' : 'done';
      p.sent = p.entry.size;
      this.notify();
    } catch (err) {
      this.fail(p, err);
    }
  }

  /**
   * Record a per-file failure. Cancellation and batch-wide problems (quota, expiry) propagate.
   * @param {EntryProgress} p
   * @param {unknown} err
   */
  fail(p, err) {
    const e = err instanceof ApiError ? err : new ApiError(0, 'error', err instanceof Error ? err.message : String(err));
    if (e.aborted) return;
    p.state = 'failed';
    p.error = e.message;
    this.notify();
    // problems that affect every remaining file: stop the run
    if (!this.fatal && (e.status === 507 || e.code === 'quota_exceeded' || e.status === 404 || e.status === 410 || e.code === 'insecure')) {
      this.fatal = e.status === 404 || e.status === 410
        ? new ApiError(e.status, e.code, 'This upload link is no longer accepting files.')
        : e;
      this.cancel();
    }
  }
}
