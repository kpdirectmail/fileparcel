// @ts-check
/**
 * Upload engine — the browser side of the parted upload protocol (§8.1), independent of any UI. Used by the SPA upload
 * manager (upload/manager.js) and, through upload/basic.js uploadWithProtocol(), by the public file-request page.
 *
 *   const b = engine.add({apiBase: '/api/v1', folderId, files: [{file, relPath}], dirs: ['Trip/empty'],
 *                         mode: 'files'|'zip', zipName, conflict: 'rename', zipEncryption: ''|'aes256'|'zipcrypto',
 *                         zipPassword});
 *   engine.subscribe(() => render(engine.batches));      // called (coalesced) after every state change
 *   b.pause(); b.resume(); b.cancel(); b.items[3].pause(); b.items[3].retry();
 *
 * Protocol per batch: POST {apiBase}/upload-batches (first 1000 entries) → POST …/{id}/files for the rest (chunks of
 * 1000) → per file PUT …/upload-batches/{id}/small?ref= (size ≤ small_max, incl. 0-byte files) or
 * PUT {apiBase}/uploads/{upf}/parts/{n} + POST …/uploads/{upf}/complete → POST …/upload-batches/{id}/complete
 * (mode=zip answers {state: "finalizing", job_id} and the job is followed via SSE job.* events and GET /jobs/{id}).
 * Every PUT carries X-FP-SHA256 (hex SHA-256 of the body, computed by upload/hasher.js in a Web Worker).
 *
 * Password-protected zips (DESIGN §8.1, §13.6): the password travels once, in the body of POST /upload-batches, and
 * the batch drops its copy as soon as that body is built (only a refused request, 429/503, is sent again with it).
 * It is never persisted, a failed batch is never declared again without the dialog, and a resumed batch needs none
 * (the server keeps it sealed). `b.declared` settles with that first POST; a 422 on
 * zip_password/zip_encryption sets `b.needsZipPassword` and `b.errorField`, so the caller can ask again.
 *
 * Scheduling: at most `parallel` (server-provided, default 4) requests in flight across all batches; parts are
 * uploaded with XMLHttpRequest for byte-level progress; retries use exponential backoff 1 s → 30 s, 6 tries, for
 * network errors, 408 and 5xx; a stalled request (no progress for 60 s) is aborted and retried. A 429 (the server's
 * per-IP rate limit, which a folder of many small files reaches quickly) is not a failure of the file: the whole
 * engine waits for its Retry-After, spaces its requests out from then on (the gap shrinks back towards none while
 * requests succeed) and the file is sent again without being charged a try. The batch calls
 * …/files and …/complete are retried the same way (idempotent); POST /upload-batches only when the server refused it
 * outright (429, 503 + Retry-After). A batch that still fails as a whole offers a manual retry (Batch.retryable).
 * Pausing a file aborts its in-flight parts (they restart from the part boundary on resume); done parts are never
 * re-sent.
 * @module upload/engine
 */
import { request, getCsrf, refreshCsrf, ApiError } from '../core/api.js';
import { events } from '../core/store.js';
import { sha256Hex } from './hasher.js';

const MiB = 1024 * 1024;
const DECLARE_CHUNK = 1000;
const MAX_TRIES = 6;
const STALL_MS = 60_000;

/** @typedef {'queued' | 'hashing' | 'uploading' | 'paused' | 'done' | 'skipped' | 'failed' | 'canceled' | 'missing'} ItemState */
/** @typedef {'preparing' | 'uploading' | 'paused' | 'finishing' | 'bundling' | 'attention' | 'done' | 'failed' | 'canceled'} BatchState */

/**
 * @typedef {Object} FileSpec
 * @property {File | null} file the file (null for resumed items that still need re-selecting)
 * @property {string} relPath path relative to the destination folder ("Trip/day1/a.jpg")
 * @property {number} [size] defaults to file.size
 * @property {number} [mtime] Unix ms, defaults to file.lastModified
 * @property {string} [ref] client_ref (generated when omitted)
 * @property {string} [id] server upload id (resume)
 */

/**
 * @typedef {Object} BatchOptions
 * @property {string} [apiBase] "/api/v1" (default) or "/s/<token>/api"
 * @property {string} folderId destination folder
 * @property {string} [folderName] for display
 * @property {FileSpec[]} files
 * @property {string[]} [dirs] empty directories to create (relative paths)
 * @property {'files' | 'zip'} [mode]
 * @property {string} [zipName] name of the bundle (mode zip)
 * @property {'rename' | 'replace' | 'skip' | 'fail'} [conflict]
 * @property {string} [uploader] uploader name (file requests)
 * @property {'' | 'aes256' | 'zipcrypto'} [zipEncryption] mode zip: protect the .zip with zipPassword (resume: the
 *   method only)
 * @property {string} [zipPassword] write-only: sent in POST /upload-batches, then dropped
 * @property {boolean} [handle] automatic 401/403/503 handling of core/api.js (default: apiBase starts with /api/)
 * @property {string} [key] local id (resume)
 * @property {string} [id] server batch id (resume)
 * @property {number} [createdAt]
 * @property {string} [expiresAt] server expiry of the batch (resume; kept when the record is saved again)
 */

/** Error type raised for a failed upload request. */
export class UploadError extends Error {
  /**
   * @param {string} message
   * @param {{status?: number, code?: string, retryable?: boolean, fatal?: boolean}} [o]
   */
  constructor(message, o = {}) {
    super(message);
    this.name = 'UploadError';
    this.status = o.status || 0;
    this.code = o.code || '';
    this.retryable = !!o.retryable;
    /** the whole batch cannot continue (session gone, batch expired) */
    this.fatal = !!o.fatal;
    /** seconds from a 429/503 Retry-After header (0: none) */
    this.retryAfter = 0;
  }
}

/**
 * Whether a batch that failed with `err` can succeed when tried again: a transient failure, or one the user can clear
 * (sign in again, unlock the server, free up space) — not a refusal of the request itself, nor a batch that is gone.
 * @param {unknown} err
 */
function recoverable(err) {
  return err instanceof UploadError && (err.retryable || (err.fatal && err.status !== 404));
}

/**
 * Minimal XHR PUT with upload progress, abort and a stall watchdog.
 * @param {string} url
 * @param {Blob} body
 * @param {Record<string, string>} headers
 * @param {(loaded: number) => void} onProgress
 * @param {(abort: () => void) => void} onStart receives an abort function
 * @returns {Promise<{status: number, text: string, contentType: string, retryAfter: number, aborted: boolean,
 *   stalled: boolean}>}
 */
function xhrPut(url, body, headers, onProgress, onStart) {
  return new Promise((resolve) => {
    const xhr = new XMLHttpRequest();
    let aborted = false;
    let stalled = false;
    let last = Date.now();
    const watchdog = setInterval(() => {
      if (Date.now() - last > STALL_MS) {
        stalled = true;
        xhr.abort();
      }
    }, 5000);
    const done = () => {
      clearInterval(watchdog);
      const ra = Number(xhr.getResponseHeader('Retry-After')); // seconds; an HTTP-date gives NaN → 0
      resolve({
        status: aborted || stalled ? 0 : xhr.status,
        text: xhr.responseText || '',
        contentType: xhr.getResponseHeader('Content-Type') || '',
        retryAfter: Number.isFinite(ra) && ra > 0 ? ra : 0,
        aborted,
        stalled,
      });
    };
    xhr.open('PUT', url, true);
    xhr.withCredentials = true;
    for (const [k, v] of Object.entries(headers)) xhr.setRequestHeader(k, v);
    xhr.upload.addEventListener('progress', (e) => {
      last = Date.now();
      onProgress(e.loaded);
    });
    xhr.addEventListener('load', done);
    xhr.addEventListener('error', done);
    xhr.addEventListener('abort', done);
    xhr.addEventListener('timeout', done);
    onStart(() => {
      aborted = true;
      xhr.abort();
    });
    xhr.send(body);
  });
}

/**
 * Parse an error body from an XHR response.
 * @param {{status: number, text: string, contentType: string, retryAfter?: number}} res
 */
function xhrError(res) {
  let code = '';
  let message = '';
  if (res.contentType.includes('json')) {
    try {
      const b = JSON.parse(res.text);
      code = b?.error?.code || '';
      message = b?.error?.message || '';
    } catch { /* ignore */ }
  }
  const e = classify(res.status, code, message);
  e.retryAfter = res.retryAfter || 0;
  return e;
}

/**
 * Turn an HTTP status into an UploadError with retry semantics.
 * @param {number} status
 * @param {string} code
 * @param {string} message
 */
function classify(status, code, message) {
  if (status === 0) return new UploadError(message || 'Connection lost', { retryable: true, code: 'network' });
  if (status === 408 || status === 429 || status >= 500) {
    if (status === 507 || code === 'quota_exceeded') return new UploadError(message || 'Storage quota exceeded', { status, code, fatal: true });
    if (code === 'keys_locked') return new UploadError(message || 'The server is locked', { status, code, fatal: true });
    return new UploadError(message || `Server error (${status})`, { status, code, retryable: true });
  }
  if (status === 401) return new UploadError('Your session expired. Sign in again to continue.', { status, code, fatal: true });
  if (status === 404) return new UploadError(message || 'The upload no longer exists (it may have expired).', { status, code, fatal: true });
  if (status === 413) return new UploadError(message || 'This file is too large for the server.', { status, code });
  if (status === 409) return new UploadError(message || 'The file changed while it was uploading.', { status, code });
  return new UploadError(message || `Upload failed (${status})`, { status, code });
}

/** Wrap a JSON API call so network/HTTP failures become UploadErrors. */
async function call(/** @type {Batch} */ b, /** @type {string} */ method, /** @type {string} */ path, /** @type {any} */ body) {
  try {
    return await request(method, `${b.apiBase}${path}`, body, { handle: b.handle });
  } catch (err) {
    if (err instanceof ApiError) {
      const e = classify(err.status, err.code, err.message);
      /** @type {any} */ (e).field = err.field;
      e.retryAfter = err.retryAfter || 0;
      throw e;
    }
    throw err;
  }
}

/**
 * call() with the backoff of the data requests (1 s → 30 s, MAX_TRIES tries, or the server's Retry-After) for the
 * batch calls: /files and /complete are idempotent, so every retryable failure is tried again; `when` narrows that
 * for a call that is not (creating a batch). Gives up once the batch is cancelled.
 * @param {Batch} b
 * @param {string} method
 * @param {string} path
 * @param {any} body
 * @param {(e: UploadError) => boolean} [when]
 */
async function callRetry(b, method, path, body, when = (e) => e.retryable) {
  for (let tries = 1; ; tries += 1) {
    try {
      return await call(b, method, path, body);
    } catch (err) {
      if (!(err instanceof UploadError) || !when(err) || tries >= MAX_TRIES || b.state === 'canceled') throw err;
      const delay = err.retryAfter > 0 ? Math.min(60, err.retryAfter) * 1000 : Math.min(30_000, 1000 * 2 ** (tries - 1));
      await new Promise((resolve) => { setTimeout(resolve, delay); });
      if (b.state === 'canceled') throw err;
    }
  }
}

/**
 * Retry rule for POST /upload-batches: it has no idempotency key, so a request whose answer was lost (network error,
 * 502/504) may have created a batch that holds a reservation; only refusals that created nothing are tried again.
 * @param {UploadError} e
 */
const createRefused = (e) => !e.fatal && (e.status === 429 || (e.status === 503 && e.retryAfter > 0));

let keySeq = 0;

/** One file (or empty directory) of a batch. */
export class Item {
  /**
   * @param {Batch} batch
   * @param {FileSpec & {kind?: 'file' | 'dir'}} spec
   * @param {number} index
   */
  constructor(batch, spec, index) {
    this.batch = batch;
    /** @type {'file' | 'dir'} */
    this.kind = spec.kind || 'file';
    /** @type {File | null} */
    this.file = spec.file || null;
    this.relPath = spec.relPath;
    this.name = spec.relPath.split('/').pop() || spec.relPath;
    this.size = this.kind === 'dir' ? 0 : spec.size ?? this.file?.size ?? 0;
    this.mtime = spec.mtime ?? this.file?.lastModified ?? 0;
    this.ref = spec.ref || `${this.kind === 'dir' ? 'd' : 'f'}${index}`;
    /** server upload id (upf_…) */
    this.id = spec.id || '';
    /** @type {ItemState} */
    this.state = this.kind === 'dir' ? 'done' : this.file ? 'queued' : 'missing';
    this.error = '';
    this.nodeId = '';
    this.paused = false;
    this.partCount = 0;
    /** @type {Set<number>} */
    this.done = new Set();
    /** @type {Map<number, {loaded: number, abort: (() => void) | null}>} */
    this.inflight = new Map();
    /** @type {Map<number, string>} part → hex digest (kept for retries) */
    this.hashes = new Map();
    this.tries = 0;
    this.cooldownUntil = 0;
    this.completing = false;
  }

  /** Terminal = no more work for this item. */
  get terminal() {
    return this.state === 'done' || this.state === 'skipped' || this.state === 'canceled';
  }

  /** Small path (single PUT to /small)? */
  get small() {
    return this.size <= this.batch.smallMax;
  }

  /** Byte length of part n. */
  partLen(/** @type {number} */ n) {
    if (this.small) return this.size;
    return Math.min(this.batch.partSize, this.size - n * this.batch.partSize);
  }

  /** Bytes acknowledged + in flight. */
  get sent() {
    if (this.state === 'done' || this.state === 'skipped') return this.size;
    let s = 0;
    for (const n of this.done) s += this.partLen(n);
    for (const r of this.inflight.values()) s += r.loaded;
    return Math.min(s, this.size);
  }

  /** Pause this file (in-flight parts are aborted and resent from their start later). */
  pause() {
    if (this.terminal || this.state === 'failed' || this.state === 'missing') return;
    this.paused = true;
    this.state = 'paused';
    this.abortInflight();
    this.batch.engine.changed();
  }

  /** Undo pause(). In a paused batch the file then waits for the batch's own resume (it stays 'paused'). */
  resume() {
    if (!this.paused) return;
    this.paused = false;
    this.state = this.batch.state === 'paused' ? 'paused' : 'queued';
    this.batch.engine.changed();
    this.batch.engine.pump();
  }

  /** Retry after a failure. */
  retry() {
    if (this.state !== 'failed') return;
    this.state = this.file ? 'queued' : 'missing';
    this.error = '';
    this.tries = 0;
    this.cooldownUntil = 0;
    this.completing = false;
    if (this.batch.state === 'attention' || this.batch.state === 'failed') this.batch.state = 'uploading';
    this.batch.engine.changed();
    this.batch.engine.pump();
  }

  /** Cancel this file (the rest of the batch continues). */
  async cancel() {
    if (this.terminal) return;
    this.abortInflight();
    this.state = 'canceled';
    this.paused = false;
    this.batch.engine.changed();
    if (this.id && this.batch.id) {
      try { await call(this.batch, 'DELETE', `/uploads/${encodeURIComponent(this.id)}`); } catch { /* best effort */ }
    }
    this.batch.checkFinished();
  }

  /**
   * Attach a re-selected file (resume after reload).
   * @param {File} file
   */
  attach(file) {
    this.file = file;
    if (this.state === 'missing') this.state = 'queued';
    this.hashes.clear();
  }

  abortInflight() {
    for (const r of this.inflight.values()) r.abort?.();
  }
}

/** One upload batch (one pick / drop / share-target hand-off). */
export class Batch {
  /**
   * @param {Engine} engine
   * @param {BatchOptions} o
   */
  constructor(engine, o) {
    this.engine = engine;
    this.key = o.key || `b${Date.now().toString(36)}${(++keySeq).toString(36)}`;
    this.apiBase = (o.apiBase || '/api/v1').replace(/\/$/, '');
    this.handle = o.handle ?? this.apiBase.startsWith('/api/');
    this.folderId = o.folderId;
    this.folderName = o.folderName || '';
    /** @type {'files' | 'zip'} */
    this.mode = o.mode === 'zip' ? 'zip' : 'files';
    this.zipName = o.zipName || '';
    this.conflict = o.conflict || 'rename';
    this.uploader = o.uploader || '';
    /** @type {'' | 'aes256' | 'zipcrypto'} */
    this.zipEncryption = this.mode === 'zip' ? (o.zipEncryption || '') : '';
    /** write-only; dropped as soon as the create request body is built */
    this.zipPassword = this.zipEncryption ? (o.zipPassword || '') : '';
    /** POST /upload-batches refused the .zip password or method (422): the caller asks for it again */
    this.needsZipPassword = false;
    /** the field of that refusal: 'zip_password' | 'zip_encryption' */
    this.errorField = '';
    /** the finished job encrypted the .zip ('aes256' | 'zipcrypto'; '' also for a protected batch without files) */
    this.resultEncryption = '';
    /** @type {(ok: boolean) => void} */
    this.resolveDeclared = () => {};
    /** @type {Promise<boolean>} settles when the first POST /upload-batches settles (true: the batch exists) */
    this.declared = new Promise((resolve) => { this.resolveDeclared = resolve; });
    this.id = o.id || '';
    if (this.id) this.resolveDeclared(true); // resumed batch
    this.createdAt = o.createdAt || Date.now();
    /** @type {BatchState} */
    this.state = 'preparing';
    this.error = '';
    this.jobId = '';
    /** @type {{done: number, total: number, note: string} | null} */
    this.job = null;
    this.resultNodeId = '';
    /** zip mode: the name the .zip was stored under (conflict "rename" may have numbered it) */
    this.resultName = '';
    /** zip mode: the job succeeded without storing the .zip (conflict "skip": a file of that name exists) */
    this.skipped = false;
    this.partSize = 8 * MiB;
    this.smallMax = 8 * MiB;
    this.expiresAt = o.expiresAt || '';
    this.finishing = false;
    /** start() is declaring the batch (POST /upload-batches, then …/files chunks) */
    this.declaring = false;
    /** the DELETE of the server batch was sent (cancel) */
    this.abortSent = false;
    /** 'failed' for a reason that may pass (a server hiccup, the session, the quota): the panel offers a retry */
    this.retryable = false;
    /** resumeSaved() found the saved batch unusable (finished, expired, gone): nothing to resume any more */
    this.resumeFailed = false;
    let i = 0;
    /** @type {Item[]} */
    this.items = [];
    for (const d of o.dirs || []) this.items.push(new Item(this, { file: null, relPath: d, kind: 'dir' }, i++));
    for (const f of o.files) this.items.push(new Item(this, f, i++));
    /** first index that may still have work (scheduler cursor) */
    this.cursor = 0;
    this.startedAt = Date.now();
    this.finishedAt = 0;
  }

  get files() {
    return this.items.filter((it) => it.kind === 'file');
  }

  /** Aggregate progress. */
  get progress() {
    let total = 0;
    let sent = 0;
    let done = 0;
    let skipped = 0;
    let failed = 0;
    let missing = 0;
    let count = 0;
    for (const it of this.items) {
      if (it.kind === 'dir') continue;
      count += 1;
      if (it.state === 'canceled') continue;
      total += it.size;
      sent += it.sent;
      if (it.state === 'done' || it.state === 'skipped') done += 1;
      else if (it.state === 'failed') failed += 1;
      else if (it.state === 'missing') missing += 1;
      if (it.state === 'skipped') skipped += 1;
    }
    // done counts skipped files too (nothing left to do for them); skipped: conflict "skip" kept the existing file
    return { total, sent, done, skipped, failed, missing, count };
  }

  /** True while the batch still needs this browser tab. */
  get active() {
    return this.state === 'preparing' || this.state === 'uploading' || this.state === 'finishing';
  }

  get finished() {
    return this.state === 'done' || this.state === 'canceled';
  }

  /** Declare the batch and its files on the server. */
  async declare() {
    const entries = this.items.map((it) => {
      /** @type {Record<string, any>} */
      const e = { client_ref: it.ref, rel_path: it.relPath, size: it.size, kind: it.kind };
      if (it.mtime > 0) e.mtime = Math.round(it.mtime);
      return e;
    });
    /** @type {Record<string, any>} */
    const input = { folder_id: this.folderId, mode: this.mode, conflict: this.conflict, files: entries.slice(0, DECLARE_CHUNK) };
    if (this.mode === 'zip') input.zip_name = this.zipName;
    if (this.uploader) input.uploader = this.uploader;
    if (this.zipEncryption) {
      // a re-declare (retry, resume without an id) has no password any more: only the dialog can ask for it
      if (!this.zipPassword) throw new UploadError('Start the upload again to enter the .zip password.', { fatal: true });
      input.zip_encryption = this.zipEncryption;
      input.zip_password = this.zipPassword;
      this.zipPassword = '';
    }
    const res = await callRetry(this, 'POST', '/upload-batches', input, createRefused);
    this.resolveDeclared(true);
    const id = String(res.id);
    this.id = id;
    if (this.state === 'canceled') return; // cancelled while this was in flight: start() releases the batch
    this.applyParams(res);
    this.applyStates(res.files || []);
    await this.abortCanceled(res.files || []);
    this.engine.persist(this);
    for (let i = DECLARE_CHUNK; i < entries.length; i += DECLARE_CHUNK) {
      if (this.state === 'canceled') return;
      const more = await callRetry(this, 'POST', `/upload-batches/${encodeURIComponent(id)}/files`, entries.slice(i, i + DECLARE_CHUNK));
      const states = Array.isArray(more) ? more : more?.files || more?.items || [];
      this.applyStates(states);
      await this.abortCanceled(states);
    }
  }

  /**
   * Abort on the server the files removed while they were being declared: Item.cancel() had no id to send then, and
   * the server holds them as pending, so the batch /complete would refuse the whole batch (409).
   * @param {any[]} states the server states of the files just declared
   */
  async abortCanceled(states) {
    if (this.state === 'canceled') return; // the whole batch goes
    const byRef = new Map(this.items.map((it) => [it.ref, it]));
    for (const st of states) {
      const it = byRef.get(st.client_ref);
      if (!it || it.kind !== 'file' || it.state !== 'canceled' || !it.id || st.state === 'aborted') continue;
      try { await call(this, 'DELETE', `/uploads/${encodeURIComponent(it.id)}`); } catch { /* best effort */ }
    }
  }

  /** @param {any} res UploadBatch */
  applyParams(res) {
    if (res.part_size > 0) this.partSize = res.part_size;
    if (typeof res.small_max === 'number' && res.small_max >= 0) this.smallMax = res.small_max;
    if (res.parallel > 0) this.engine.parallel = Math.max(1, Math.min(8, res.parallel));
    if (res.expires_at) this.expiresAt = res.expires_at;
  }

  /** Merge server file states (create / resume). @param {any[]} states */
  applyStates(states) {
    const byRef = new Map(this.items.map((it) => [it.ref, it]));
    for (const st of states) {
      const it = byRef.get(st.client_ref);
      if (!it) continue;
      if (st.id) it.id = st.id;
      if (st.part_count) it.partCount = st.part_count;
      for (const n of Array.isArray(st.parts_done) ? st.parts_done : []) it.done.add(n);
      if (st.node_id) it.nodeId = st.node_id;
      if (it.kind === 'dir') continue;
      if (st.state === 'committed' || st.state === 'uploaded') it.state = 'done';
      else if (st.state === 'skipped') it.state = 'skipped';
      else if (st.state === 'aborted') it.state = 'canceled';
    }
    for (const it of this.items) {
      if (!it.partCount) it.partCount = it.small ? 1 : Math.max(1, Math.ceil(it.size / this.partSize));
    }
  }

  pause() {
    if (!this.active || this.state === 'finishing') return;
    this.state = 'paused';
    for (const it of this.items) {
      it.abortInflight();
      // Only the state, never it.paused: that flag keeps meaning "the user paused this one file",
      // so resuming the batch does not have to remember which rows it silenced.
      if (it.state === 'uploading' || it.state === 'queued') it.state = 'paused';
    }
    this.engine.changed();
  }

  resume() {
    if (this.state !== 'paused') return;
    for (const it of this.items) {
      // files the user paused one by one stay paused (Item.resume() is theirs)
      if (it.state !== 'paused' || it.paused) continue;
      it.state = 'queued';
    }
    if (this.declaring) {
      // paused while being declared: the start() still running carries on from 'preparing' (starting it again
      // would declare a second server batch, and uploading now would reach files the server does not know yet)
      this.state = 'preparing';
      this.engine.changed();
      return;
    }
    this.state = this.id ? 'uploading' : 'preparing';
    this.engine.changed();
    if (!this.id) {
      this.engine.start(this);
      return;
    }
    // Work that settled while the batch was paused (a file cancelled, a file /complete answered) checked nothing
    // then (checkFinished() waits for 'uploading'): when that was the last of it, no task is left to do it now.
    this.checkFinished();
    this.engine.pump();
  }

  /** Cancel the whole batch (server-side staged data is removed). */
  async cancel() {
    if (this.finished) return;
    this.zipPassword = '';
    this.resolveDeclared(false);
    const was = this.state;
    this.state = 'canceled';
    for (const it of this.items) {
      it.abortInflight();
      if (!it.terminal) it.state = 'canceled';
    }
    this.finishedAt = Date.now();
    this.engine.changed();
    this.engine.persist(this);
    // Without an id (cancelled during the first POST /upload-batches) start() sends the DELETE once the id is known.
    if (this.id && was !== 'done' && was !== 'bundling') {
      this.abortSent = true;
      try { await call(this, 'DELETE', `/upload-batches/${encodeURIComponent(this.id)}`); } catch { /* best effort */ }
    }
    this.engine.batchEnded(this);
  }

  /** Retry every failed file, or the whole batch when it failed as a whole (declaring, completing, a fatal error). */
  retryFailed() {
    this.retryable = false;
    this.finishedAt = 0;
    for (const it of this.items) if (it.state === 'failed') it.retry();
    if (this.state === 'failed' && !this.id) {
      this.state = 'preparing';
      this.error = '';
      this.engine.start(this);
    } else if (this.state === 'failed' || this.state === 'attention') {
      this.state = 'uploading';
      this.error = '';
      this.checkFinished();
      this.engine.pump();
    }
    this.engine.changed();
  }

  /** Skip failed/missing files and finish with the rest. */
  async skipFailed() {
    const list = this.items.filter((it) => it.state === 'failed' || it.state === 'missing');
    for (const it of list) await it.cancel();
    if (this.state === 'attention') this.state = 'uploading';
    this.checkFinished();
  }

  /** Complete the batch once every file is settled. */
  checkFinished() {
    if (this.state !== 'uploading' || this.finishing) return;
    const files = this.files;
    if (files.some((it) => !it.terminal && it.state !== 'failed' && it.state !== 'missing')) return;
    if (files.some((it) => it.state === 'failed' || it.state === 'missing')) {
      this.state = 'attention';
      this.engine.changed();
      this.engine.persist(this);
      return;
    }
    if (files.length && files.every((it) => it.state === 'canceled') && !this.items.some((it) => it.kind === 'dir')) {
      this.cancel();
      return;
    }
    this.finish();
  }

  async finish() {
    this.finishing = true;
    this.state = 'finishing';
    this.engine.changed();
    try {
      const res = await callRetry(this, 'POST', `/upload-batches/${encodeURIComponent(this.id)}/complete`, {});
      if (this.state === 'canceled') return; // cancelled meanwhile: cancel() has settled the batch
      if (res?.job_id && (res.state === 'finalizing' || this.mode === 'zip')) {
        this.jobId = res.job_id;
        this.state = 'bundling';
        this.job = { done: 0, total: 0, note: '' };
        this.engine.changed();
        this.engine.persist(this);
        await this.engine.watchJob(this);
      } else {
        if (res?.result_node_id) this.resultNodeId = res.result_node_id;
        // a .zip whose name was taken under conflict "skip" when the batch was declared: no job, no .zip
        else if (this.mode === 'zip') this.skipped = true;
        this.state = 'done';
      }
    } catch (err) {
      if (this.state === 'canceled') return;
      this.state = 'failed';
      this.error = err instanceof Error ? err.message : String(err);
      this.retryable = recoverable(err);
    } finally {
      this.finishing = false;
    }
    this.finishedAt = Date.now();
    this.engine.changed();
    this.engine.persist(this);
    this.engine.batchEnded(this);
  }
}

/** The scheduler shared by all batches of the page. */
export class Engine {
  constructor() {
    /** @type {Batch[]} */
    this.batches = [];
    this.parallel = 4;
    this.inflight = 0;
    /** @type {Set<() => void>} */
    this.listeners = new Set();
    /** @type {Set<(b: Batch) => void>} */
    this.endListeners = new Set();
    /** @type {(b: Batch) => void} */
    this.persistHook = () => {};
    this.notifyQueued = false;
    this.retryTimer = 0;
    /** after a 429: no data request of any batch starts before this time (ms since the epoch) */
    this.holdUntil = 0;
    /** after a 429: the least time between the starts of two data requests (ms; 0 = none) */
    this.gap = 0;
    /** when the last data request started (ms since the epoch) */
    this.lastStart = 0;
    /** bytes moved (monotonic; progress deltas) and samples for the speed estimate */
    this.moved = 0;
    /** @type {[number, number][]} */
    this.samples = [];
    this.paused = false;
  }

  /**
   * Queue a new batch and start it.
   * @param {BatchOptions} o
   * @returns {Batch}
   */
  add(o) {
    const b = new Batch(this, o);
    this.batches.push(b);
    this.changed();
    this.start(b);
    return b;
  }

  /**
   * Resume a batch after a page reload with re-selected files, matched by rel_path + size + mtime (§8.1 step 3).
   * @param {BatchOptions & {id: string, files: FileSpec[]}} saved
   * @param {File[]} picked
   * @returns {Promise<Batch>}
   */
  async resumeSaved(saved, picked) {
    const b = new Batch(this, { ...saved, files: saved.files.map((f) => ({ ...f, file: null })) });
    attachFiles(b, picked);
    this.batches.push(b);
    this.changed();
    try {
      const res = await call(b, 'GET', `/upload-batches/${encodeURIComponent(b.id)}`, undefined);
      if (res?.state && res.state !== 'open') {
        throw new UploadError(res.state === 'done' ? 'This upload already finished.' : `This upload can no longer be resumed (${res.state}).`, { fatal: true });
      }
      b.applyParams(res || {});
      b.applyStates(res?.files || []);
      if (b.mode === 'zip' && res?.zip_encryption) b.zipEncryption = res.zip_encryption; // the server's word, for the queue's lock
      b.state = 'uploading';
      this.changed();
      b.checkFinished();
      this.pump();
    } catch (err) {
      b.state = 'failed';
      b.error = err instanceof Error ? err.message : String(err);
      b.resumeFailed = true; // the saved record is of no use any more (manager.js persist forgets it)
      this.changed();
      this.batchEnded(b);
    }
    return b;
  }

  /** Declare a batch on the server, then start uploading it. @param {Batch} b */
  async start(b) {
    if (b.declaring) return; // already running (a resume() while 'preparing' leaves it to that run)
    b.declaring = true;
    let ok = false;
    /** @type {unknown} */
    let failure;
    try {
      await b.declare();
      ok = true;
    } catch (err) {
      failure = err;
      b.zipPassword = '';
      if (err instanceof UploadError && err.status === 422 && /^zip_(password|encryption)$/.test(/** @type {any} */ (err).field || '')) {
        b.needsZipPassword = true;
        b.errorField = /** @type {any} */ (err).field;
      }
      b.resolveDeclared(false); // a no-op when the first POST succeeded and a later chunk failed
    } finally {
      b.declaring = false;
    }
    if (b.state === 'canceled') {
      // cancel() during the first POST had no id to abort: release the server batch (its reservation and one of the
      // open-batch slots) now instead of when it expires
      if (b.id && !b.abortSent) {
        b.abortSent = true;
        try { await call(b, 'DELETE', `/upload-batches/${encodeURIComponent(b.id)}`); } catch { /* best effort */ }
      }
      return;
    }
    if (!ok) {
      b.state = 'failed';
      b.error = failure instanceof Error ? failure.message : String(failure);
      // a protected batch cannot be declared again without its password (it is gone): only a new upload can
      b.retryable = recoverable(failure) && !b.zipEncryption;
      this.changed();
      if (b.id) {
        try { await call(b, 'DELETE', `/upload-batches/${encodeURIComponent(b.id)}`); } catch { /* ignore */ }
        b.id = '';
      }
      this.batchEnded(b);
      return;
    }
    if (b.state === 'paused') return;
    b.state = 'uploading';
    this.changed();
    b.checkFinished();
    this.pump();
  }

  /** Remove finished batches from the list. */
  clearFinished() {
    this.batches = this.batches.filter((b) => !b.finished && b.state !== 'failed');
    this.changed();
  }

  /** @param {Batch} b */
  remove(b) {
    b.zipPassword = '';
    b.resolveDeclared(false);
    this.batches = this.batches.filter((x) => x !== b);
    this.changed();
  }

  pauseAll() {
    for (const b of this.batches) b.pause();
  }

  resumeAll() {
    for (const b of this.batches) b.resume();
  }

  cancelAll() {
    return Promise.all(this.batches.map((b) => b.cancel()));
  }

  /** True while any batch still needs this tab (beforeunload guard, wake lock). */
  get busy() {
    return this.batches.some((b) => b.active || b.state === 'paused');
  }

  /**
   * Overall progress of the batches that still need this tab (active or paused, as `busy` and the panel's file
   * count): a failed batch or one waiting for attention moves no bytes until the user acts.
   */
  get progress() {
    let total = 0;
    let sent = 0;
    for (const b of this.batches) {
      if (!b.active && b.state !== 'paused') continue;
      const p = b.progress;
      total += p.total;
      sent += p.sent;
    }
    return { total, sent };
  }

  /** Bytes per second over the last ~5 s. */
  get speed() {
    const now = performance.now();
    this.samples = this.samples.filter(([t]) => now - t < 5000);
    if (this.samples.length < 2) return 0;
    const [t0, b0] = this.samples[0];
    const dt = (now - t0) / 1000;
    return dt > 0.5 ? (this.moved - b0) / dt : 0;
  }

  /** Seconds remaining for the active batches (paused ones wait; Infinity when unknown). */
  get eta() {
    const s = this.speed;
    if (!(s > 0)) return Infinity;
    let rem = 0;
    for (const b of this.batches) {
      if (!b.active) continue;
      const p = b.progress;
      rem += p.total - p.sent;
    }
    return rem / s;
  }

  /** @param {() => void} fn @returns {() => void} */
  subscribe(fn) {
    this.listeners.add(fn);
    return () => this.listeners.delete(fn);
  }

  /** @param {(b: Batch) => void} fn */
  onBatchEnd(fn) {
    this.endListeners.add(fn);
    return () => this.endListeners.delete(fn);
  }

  /** Coalesced change notification. */
  changed() {
    if (this.notifyQueued) return;
    this.notifyQueued = true;
    queueMicrotask(() => {
      this.notifyQueued = false;
      for (const fn of [...this.listeners]) {
        try { fn(); } catch (err) { console.error(err); }
      }
    });
  }

  /** @param {Batch} b */
  persist(b) {
    try { this.persistHook(b); } catch (err) { console.warn('upload persist failed', err); }
  }

  /** @param {Batch} b */
  batchEnded(b) {
    for (const fn of [...this.endListeners]) {
      try { fn(b); } catch (err) { console.error(err); }
    }
  }

  /** @param {number} delta */
  addMoved(delta) {
    if (delta <= 0) return;
    this.moved += delta;
    const now = performance.now();
    const last = this.samples[this.samples.length - 1];
    if (!last || now - last[0] > 250) this.samples.push([now, this.moved]);
  }

  /** Start as many tasks as the parallelism allows. */
  pump() {
    let wait = Infinity;
    while (this.inflight < this.parallel) {
      const t = this.next();
      if (!t) break;
      if ('wait' in t) {
        wait = Math.min(wait, t.wait);
        break;
      }
      this.inflight += 1;
      this.lastStart = Date.now();
      this.run(t).finally(() => {
        this.inflight -= 1;
        this.pump();
      });
    }
    if (wait !== Infinity && !this.retryTimer) {
      this.retryTimer = window.setTimeout(() => {
        this.retryTimer = 0;
        this.pump();
      }, Math.max(50, wait - Date.now()));
    }
  }

  /**
   * Pick the next unit of work.
   * @returns {{b: Batch, it: Item, part: number | 'complete'} | {wait: number} | null}
   */
  next() {
    const now = Date.now();
    // the server's rate limit answered 429: every batch waits, then requests are spaced out
    const gate = Math.max(this.holdUntil, this.gap ? this.lastStart + this.gap : 0);
    if (gate > now && this.batches.some((b) => b.state === 'uploading')) return { wait: gate };
    let wait = Infinity;
    for (const b of this.batches) {
      if (b.state !== 'uploading') continue;
      for (let i = b.cursor; i < b.items.length; i += 1) {
        const it = b.items[i];
        if (it.kind === 'dir' || it.terminal) {
          if (i === b.cursor) b.cursor += 1;
          continue;
        }
        if (it.paused || it.state === 'failed' || it.state === 'missing' || it.completing || !it.file) continue;
        if (it.cooldownUntil > now) {
          wait = Math.min(wait, it.cooldownUntil);
          continue;
        }
        if (it.small) {
          if (it.inflight.size === 0) return { b, it, part: 0 };
          continue;
        }
        for (let n = 0; n < it.partCount; n += 1) {
          if (!it.done.has(n) && !it.inflight.has(n)) return { b, it, part: n };
        }
        if (it.inflight.size === 0 && it.done.size >= it.partCount) return { b, it, part: 'complete' };
      }
    }
    return wait !== Infinity ? { wait } : null;
  }

  /**
   * @param {{b: Batch, it: Item, part: number | 'complete'}} t
   */
  async run(t) {
    const { b, it } = t;
    if (t.part === 'complete') {
      it.completing = true;
      try {
        const st = await call(b, 'POST', `/uploads/${encodeURIComponent(it.id)}/complete`, {});
        if (st?.node_id) it.nodeId = st.node_id;
        it.state = st?.state === 'skipped' ? 'skipped' : 'done';
        it.tries = 0;
        this.eased();
        this.persist(b);
      } catch (err) {
        this.fail(it, err);
      } finally {
        it.completing = false;
      }
      this.changed();
      b.checkFinished();
      return;
    }

    const n = t.part;
    const file = /** @type {File} */ (it.file);
    const blob = it.small ? file : file.slice(n * b.partSize, n * b.partSize + it.partLen(n));
    /** @type {{loaded: number, abort: (() => void) | null}} */
    const rec = { loaded: 0, abort: null };
    let cancelled = false;
    rec.abort = () => { cancelled = true; };
    it.inflight.set(n, rec);
    if (it.state === 'queued' || it.state === 'paused') it.state = 'uploading';
    this.changed();
    try {
      if (blob.size !== it.partLen(n)) throw new UploadError('The file changed on disk. Select it again to upload it.');
      let hex = it.hashes.get(n);
      if (!hex) {
        hex = await sha256Hex(blob);
        it.hashes.set(n, hex);
      }
      if (cancelled || b.state !== 'uploading' || it.paused || it.terminal) return;
      const url = it.small
        ? `${b.apiBase}/upload-batches/${encodeURIComponent(b.id)}/small?ref=${encodeURIComponent(it.ref)}`
        : `${b.apiBase}/uploads/${encodeURIComponent(it.id)}/parts/${n}`;
      /** @type {Record<string, string>} */
      const headers = { 'X-FP-SHA256': hex, 'Content-Type': 'application/octet-stream' };
      const csrf = getCsrf();
      if (csrf) headers['X-FP-CSRF'] = csrf;
      const res = await xhrPut(url, blob, headers, (loaded) => {
        this.addMoved(loaded - rec.loaded);
        rec.loaded = loaded;
        this.changed();
      }, (abort) => { rec.abort = abort; if (cancelled) abort(); });
      if (res.aborted) return;
      if (res.stalled) throw new UploadError('The connection stalled', { retryable: true });
      if (res.status >= 200 && res.status < 300) {
        it.done.add(n);
        it.tries = 0;
        this.eased();
        if (it.small) {
          let st = null;
          try { st = res.text ? JSON.parse(res.text) : null; } catch { /* 204 */ }
          if (st?.node_id) it.nodeId = st.node_id;
          if (st?.id) it.id = st.id;
          it.state = st?.state === 'skipped' ? 'skipped' : 'done';
          this.persist(b);
        }
      } else {
        const e = xhrError(res);
        // a sign-in in another tab replaced the session and its CSRF token: re-read it, the backoff sends the part again
        if (e.code === 'csrf_invalid' && await refreshCsrf()) e.retryable = true;
        throw e;
      }
    } catch (err) {
      this.fail(it, err);
    } finally {
      it.inflight.delete(n);
      this.changed();
    }
    // Every finished task re-checks the batch, not just the small-file ones: a parted file that fails
    // permanently here is the last thing that can settle the batch, and without this the batch stays
    // 'uploading' forever (no /complete, no Retry/Skip, the resume record and the wake lock leak).
    // checkFinished() is a no-op unless every file is terminal/failed/missing, so it cannot finish early.
    b.checkFinished();
  }

  /** A data request succeeded: the gap a 429 set shrinks by 2 % (gone below 2 ms), back towards full speed. */
  eased() {
    if (this.gap) this.gap = this.gap > 2 ? this.gap * 0.98 : 0;
  }

  /**
   * Handle a task failure: back off and retry, fail the file, or stop the batch.
   * @param {Item} it
   * @param {unknown} err
   */
  fail(it, err) {
    const e = err instanceof UploadError ? err : new UploadError(err instanceof Error ? err.message : String(err), { retryable: false });
    if (e.fatal) {
      const b = it.batch;
      b.state = 'failed';
      b.error = e.message;
      b.retryable = recoverable(e);
      for (const x of b.items) x.abortInflight();
      this.changed();
      this.persist(b);
      this.batchEnded(b);
      return;
    }
    if (e.status === 429) {
      // The rate limit counts every request of this client, so backing off one file only moves the next one into
      // it (a folder of small files failed by the hundred that way): the whole engine waits for Retry-After (1 s
      // when none came), spaces its requests out from now on, and the file keeps its tries: it failed nothing.
      const wait = (e.retryAfter > 0 ? Math.min(60, e.retryAfter) : 1) * 1000;
      this.holdUntil = Math.max(this.holdUntil, Date.now() + wait);
      this.gap = Math.min(1000, Math.max(25, this.gap * 2));
      it.cooldownUntil = this.holdUntil;
      it.error = `The server is busy — continuing in ${Math.max(1, Math.round((this.holdUntil - Date.now()) / 1000))} s`;
      return;
    }
    it.tries += 1;
    if (e.retryable && it.tries < MAX_TRIES) {
      const delay = Math.min(30_000, 1000 * 2 ** (it.tries - 1));
      it.cooldownUntil = Date.now() + delay;
      it.error = `${e.message} — retrying in ${Math.round(delay / 1000)} s`;
      return;
    }
    it.state = 'failed';
    it.error = e.message;
    it.abortInflight();
    this.persist(it.batch);
  }

  /**
   * Follow a zip bundling job until it ends: SSE job.progress / job.done (core/store.js events) plus polling
   * GET /jobs/{id} every 2 s as a fallback.
   * @param {Batch} b
   */
  watchJob(b) {
    return new Promise((resolve) => {
      let over = false;
      /** @param {any} j */
      const apply = (j) => {
        if (!j || over) return;
        b.job = { done: Number(j.progress_done || 0), total: Number(j.progress_total || 0), note: j.note || '' };
        if (j.state === 'succeeded') {
          b.state = 'done';
          try {
            const r = typeof j.result === 'string' ? JSON.parse(j.result) : j.result;
            if (r?.encryption) b.resultEncryption = String(r.encryption);
            if (r?.name) b.resultName = String(r.name);
            if (r?.node_id) b.resultNodeId = r.node_id;
            // an upload.zip result without node_id: conflict "skip" kept the existing file and dropped the .zip
            else if (b.mode === 'zip' && r && typeof r === 'object') b.skipped = true;
          } catch { /* ignore */ }
          end();
        } else if (j.state === 'failed' || j.state === 'canceled') {
          b.state = 'failed';
          b.error = j.error || 'Creating the .zip failed.';
          end();
        }
        this.changed();
      };
      /** @param {any} d */
      const onEvent = (d) => {
        const j = d?.job && typeof d.job === 'object' ? d.job : d;
        if (j?.id === b.jobId) apply(j);
      };
      const off1 = events.on('job.progress', onEvent);
      const off2 = events.on('job.done', onEvent);
      const poll = async () => {
        if (over) return;
        try {
          apply(await request('GET', `/api/v1/jobs/${encodeURIComponent(b.jobId)}`, undefined, { handle: false }));
        } catch { /* keep waiting for SSE */ }
        if (!over) timer = window.setTimeout(poll, 2000);
      };
      let timer = window.setTimeout(poll, 1200);
      const end = () => {
        over = true;
        off1();
        off2();
        window.clearTimeout(timer);
        resolve(undefined);
      };
    });
  }
}

/**
 * Attach picked files to the items of a (resumed) batch, each picked file to at most one item: first by
 * rel_path + size + mtime, then by rel_path + size. A folder re-picked from inside, or files picked without their
 * folder (a plain file picker), have no usable path: those match by file name + size + mtime, and only when that is
 * unambiguous — exactly one waiting item and one picked file share it —, so a file never stands in for another one
 * with the same name elsewhere in the tree. Paths and names compare in NFC, as upload/scan.js stores them.
 * @param {Batch} b
 * @param {File[]} picked
 * @returns {number} number of items that got a file
 */
export function attachFiles(b, picked) {
  /** @template V @param {Map<string, V[]>} m @param {string} k @param {V} v */
  const add = (m, k, v) => {
    const list = m.get(k);
    if (list) list.push(v);
    else m.set(k, [v]);
  };
  /** @type {Map<string, File[]>} rel_path + size */
  const byPath = new Map();
  /** @type {Map<string, File[]>} name + size + mtime */
  const byName = new Map();
  for (const f of picked) {
    add(byPath, `${relPathOf(f)}\u0000${f.size}`, f);
    add(byName, `${f.name.normalize('NFC')}\u0000${f.size}\u0000${f.lastModified}`, f);
  }
  /** @type {Set<File>} */
  const used = new Set();
  const waiting = () => b.items.filter((it) => it.kind !== 'dir' && !it.file && !it.terminal);
  let n = 0;
  /** @param {Item} it @param {File | undefined} f */
  const attach = (it, f) => {
    if (!f) return;
    it.attach(f);
    used.add(f);
    n += 1;
  };
  for (const it of waiting()) attach(it, byPath.get(`${it.relPath}\u0000${it.size}`)?.find((f) => !used.has(f) && f.lastModified === it.mtime));
  for (const it of waiting()) attach(it, byPath.get(`${it.relPath}\u0000${it.size}`)?.find((f) => !used.has(f)));
  /** @type {Map<string, Item[]>} */
  const left = new Map();
  for (const it of waiting()) add(left, `${it.name}\u0000${it.size}\u0000${it.mtime}`, it);
  for (const [k, items] of left) {
    const files = (byName.get(k) || []).filter((f) => !used.has(f));
    if (items.length === 1 && files.length === 1) attach(items[0], files[0]);
  }
  b.engine.changed();
  return n;
}

/**
 * Relative path of a File (NFC): drops set `fpRelPath` (upload/scan.js), folder pickers set webkitRelativePath.
 * @param {File} f
 */
export function relPathOf(f) {
  const any = /** @type {any} */ (f);
  const p = any.fpRelPath || any.webkitRelativePath || any.relativePath || f.name;
  return String(p).replace(/^\/+/, '').normalize('NFC');
}

/** The page-wide engine. */
export const engine = new Engine();
