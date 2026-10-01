// @ts-check
/**
 * Hash worker (classic Web Worker, created by upload/hasher.js through the Trusted Types policy "fp").
 * Computes the SHA-256 of one Blob (an upload part: `file.slice(start, end)`, ≤ 8 MiB) with crypto.subtle, off the
 * main thread (§8.1). Blobs are passed by reference (structured clone of a Blob does not copy the data); the worker
 * reads it, digests it and drops the buffer.
 *
 *   in:  {id: number, blob: Blob}
 *   out: {id: number, hex: string} | {id: number, error: string}
 */
'use strict';

/** @param {ArrayBuffer} buf */
function toHex(buf) {
  const b = new Uint8Array(buf);
  let s = '';
  for (let i = 0; i < b.length; i += 1) s += (b[i] < 16 ? '0' : '') + b[i].toString(16);
  return s;
}

self.addEventListener('message', (e) => {
  const msg = /** @type {MessageEvent} */ (e).data || {};
  const id = msg.id;
  (async () => {
    try {
      if (!self.crypto || !self.crypto.subtle) throw new Error('SHA-256 needs a secure (HTTPS) connection.');
      const blob = /** @type {Blob} */ (msg.blob);
      const buf = await blob.arrayBuffer();
      const digest = await self.crypto.subtle.digest('SHA-256', buf);
      self.postMessage({ id, hex: toHex(digest) });
    } catch (err) {
      self.postMessage({ id, error: String((err && /** @type {any} */ (err).message) || err) });
    }
  })();
});
