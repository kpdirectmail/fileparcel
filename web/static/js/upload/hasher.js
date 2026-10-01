// @ts-check
/**
 * SHA-256 of upload parts (§8.1: X-FP-SHA256 = hex SHA-256 of the part plaintext), computed in a small pool of Web
 * Workers (upload/hash-worker.js). The worker URL goes through the Trusted Types policy "fp" (core/dom.js
 * scriptURL()). Browsers without Workers (or when the policy is refused) hash on the main thread with the same
 * crypto.subtle digest.
 *
 *   const hex = await sha256Hex(file.slice(0, 8 << 20));
 * @module upload/hasher
 */
import { asset, scriptURL } from '../core/dom.js';

/**
 * @typedef {Object} PoolWorker
 * @property {Worker} worker
 * @property {number} busy pending jobs
 */

/** @type {Map<number, {resolve: (hex: string) => void, reject: (err: Error) => void, w: PoolWorker}>} */
const pending = new Map();
/** @type {PoolWorker[] | null} */
let pool = null;
/** @type {Promise<PoolWorker[]> | null} */
let poolPromise = null;
let seq = 0;

/** Hex string of a digest. @param {ArrayBuffer} buf */
export function toHex(buf) {
  return Array.from(new Uint8Array(buf), (b) => b.toString(16).padStart(2, '0')).join('');
}

/**
 * Main-thread SHA-256 (fallback, and for tiny blobs where a worker round-trip costs more than the hash).
 * @param {Blob} blob
 * @returns {Promise<string>}
 */
export async function sha256Main(blob) {
  if (!globalThis.crypto?.subtle) throw new Error('Uploading needs a secure (HTTPS) connection.');
  return toHex(await crypto.subtle.digest('SHA-256', await blob.arrayBuffer()));
}

/** @returns {Promise<PoolWorker[]>} an empty array when workers are unavailable */
function getPool() {
  if (pool) return Promise.resolve(pool);
  if (poolPromise) return poolPromise;
  poolPromise = (async () => {
    /** @type {PoolWorker[]} */
    const list = [];
    if (typeof Worker === 'undefined') return (pool = list);
    const url = await scriptURL(asset('js/upload/hash-worker.js'));
    if (url === null) return (pool = list);
    const size = Math.max(1, Math.min(3, (navigator.hardwareConcurrency || 2) - 1));
    for (let i = 0; i < size; i += 1) {
      try {
        const worker = new Worker(url, { name: `fp-hash-${i}` });
        /** @type {PoolWorker} */
        const pw = { worker, busy: 0 };
        worker.addEventListener('message', (e) => {
          const { id, hex, error } = /** @type {MessageEvent} */ (e).data || {};
          const job = pending.get(id);
          if (!job) return;
          pending.delete(id);
          job.w.busy -= 1;
          if (error) job.reject(new Error(error));
          else job.resolve(hex);
        });
        worker.addEventListener('error', (e) => {
          // a broken worker (e.g. blocked script): fail its jobs over to the main thread and retire it
          e.preventDefault();
          retire(pw);
        });
        list.push(pw);
      } catch (err) {
        console.warn('hash worker unavailable, hashing on the main thread', err);
        break;
      }
    }
    pool = list;
    return list;
  })();
  return poolPromise;
}

/** @param {PoolWorker} pw */
function retire(pw) {
  if (pool) pool = pool.filter((x) => x !== pw);
  try { pw.worker.terminate(); } catch { /* ignore */ }
  for (const [id, job] of pending) {
    if (job.w !== pw) continue;
    pending.delete(id);
    job.reject(Object.assign(new Error('hash worker failed'), { retryMain: true }));
  }
}

/**
 * SHA-256 (lower-case hex) of a Blob.
 * @param {Blob} blob
 * @returns {Promise<string>}
 */
export async function sha256Hex(blob) {
  if (blob.size <= 64 * 1024) return sha256Main(blob);
  const list = await getPool();
  if (!list.length) return sha256Main(blob);
  let w = list[0];
  for (const x of list) if (x.busy < w.busy) w = x;
  const id = ++seq;
  w.busy += 1;
  try {
    return await new Promise((resolve, reject) => {
      pending.set(id, { resolve, reject, w });
      w.worker.postMessage({ id, blob });
    });
  } catch (err) {
    if (/** @type {any} */ (err)?.retryMain) return sha256Main(blob);
    throw err;
  }
}

/** Terminate the workers (tests / page unload). */
export function shutdownHasher() {
  for (const pw of pool || []) pw.worker.terminate();
  pool = null;
  poolPromise = null;
}
