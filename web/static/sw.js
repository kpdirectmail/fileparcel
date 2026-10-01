/* FileParcel service worker (§13.7). Served from /sw.js with Cache-Control: no-cache.
 *
 * Build hash: from the registration URL (/sw.js?v=<hash>, set by js/app.js) or the placeholder below, which
 * internal/web/static replaces when serving /sw.js (__FP_ASSET_HASH__ → "<hash>", __FP_ASSET_BASE__ → "/static/<hash>").
 * A "__BUILD__" placeholder is honoured as well for servers that template that name instead.
 *
 * Strategy:
 *   /static/<hash>/…      cache-first (immutable, content-addressed); old build caches are deleted on activate
 *   page navigations       network-first; offline → a small built-in offline page (never a cached app shell, since
 *                          shells embed a CSRF token)
 *   /api/, /s/, downloads never cached — the worker does not touch them
 *   POST /share-target     Web Share Target: files are parked in memory and handed to the page via postMessage
 *                          (only files: a share without any, a link or text, lands on ?share-target=none)
 *
 * CSP: this file runs as a worker; no eval, no importScripts of foreign origins.
 */
'use strict';

/** @param {string} v */
const real = (v) => (v && v.indexOf('__') !== 0 ? v : '');
const QUERY_HASH = new URL(self.location.href).searchParams.get('v') || '';
const BUILD = real(QUERY_HASH) || real('__FP_ASSET_HASH__') || real('__BUILD__') || 'dev';
const ASSET_BASE = real('__FP_ASSET_BASE__') || `/static/${BUILD}`;
const STATIC_CACHE = `fp-static-${BUILD}`;
const PRECACHE = [
  'css/app.css', 'css/reset.css', 'css/tokens.css', 'css/base.css', 'css/layout.css', 'css/components.css', 'css/utilities.css',
  'css/pages/files.css', 'css/pages/auth.css', 'css/pages/share.css', 'css/pages/settings.css', 'css/pages/admin.css',
  'js/app.js', 'js/routes.js', 'js/nav.js',
  'js/core/dom.js', 'js/core/api.js', 'js/core/router.js', 'js/core/store.js', 'js/core/format.js', 'js/core/keys.js',
  'js/components/index.js', 'icons/sprite.svg', 'icons/logo.svg',
].map((p) => `${ASSET_BASE}/${p}`);

/** Files shared into the app via the Web Share Target, keyed by a random id (memory only). */
const shared = new Map();

self.addEventListener('install', (event) => {
  event.waitUntil((async () => {
    if (BUILD !== 'dev') {
      const cache = await caches.open(STATIC_CACHE);
      // best effort: a missing file must not break installation
      await Promise.all(PRECACHE.map((u) => cache.add(new Request(u, { credentials: 'same-origin' })).catch(() => undefined)));
    }
    await self.skipWaiting();
  })());
});

self.addEventListener('activate', (event) => {
  event.waitUntil((async () => {
    const names = await caches.keys();
    await Promise.all(names.filter((n) => n.startsWith('fp-static-') && n !== STATIC_CACHE).map((n) => caches.delete(n)));
    await self.clients.claim();
  })());
});

self.addEventListener('message', (event) => {
  const msg = event.data || {};
  if (msg.type === 'share-target:get') {
    const files = shared.get(msg.id) || [];
    shared.delete(msg.id);
    const port = event.ports && event.ports[0];
    if (port) port.postMessage({ files });
  } else if (msg.type === 'logout') {
    shared.clear();
  } else if (msg.type === 'skip-waiting') {
    self.skipWaiting();
  }
});

self.addEventListener('fetch', (event) => {
  const req = event.request;
  const url = new URL(req.url);
  if (url.origin !== self.location.origin) return;

  if (req.method === 'POST' && url.pathname === '/share-target') {
    event.respondWith(handleShareTarget(req));
    return;
  }
  if (req.method !== 'GET') return;
  if (url.pathname.startsWith('/api/') || url.pathname.startsWith('/s/') || url.pathname.startsWith('/trust/')) return;

  if (url.pathname.startsWith('/static/')) {
    event.respondWith(cacheFirst(req));
    return;
  }
  if (req.mode === 'navigate') {
    event.respondWith(networkFirstPage(req));
  }
});

/** @param {Request} req */
async function cacheFirst(req) {
  const cache = await caches.open(STATIC_CACHE);
  const hit = await cache.match(req);
  if (hit) return hit;
  const res = await fetch(req);
  if (res.ok && res.type === 'basic') {
    cache.put(req, res.clone()).catch(() => undefined);
  }
  return res;
}

/** @param {Request} req */
async function networkFirstPage(req) {
  try {
    return await fetch(req);
  } catch (err) {
    return offlinePage();
  }
}

function offlinePage() {
  const css = `${ASSET_BASE}/css/app.css`;
  const logo = `${ASSET_BASE}/icons/logo.svg`;
  const body = [
    '<!doctype html><html lang="en" data-theme="system"><head><meta charset="utf-8">',
    '<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">',
    '<title>Offline · FileParcel</title>',
    `<link rel="stylesheet" href="${css}">`,
    '</head><body><div class="public-shell"><header class="public-header"></header>',
    '<main class="public-main"><section class="auth-card"><div class="auth-card-head">',
    `<img class="brand-logo" src="${logo}" alt="" width="52" height="52">`,
    '<h1>You are offline</h1><p>FileParcel cannot reach the server right now. Check your Wi-Fi or VPN connection.</p>',
    '</div><a class="btn btn--primary" href="">Try again</a></section></main>',
    '<footer class="public-footer">FileParcel</footer></div></body></html>',
  ].join('');
  return new Response(body, {
    status: 503,
    headers: {
      'Content-Type': 'text/html; charset=utf-8',
      'Cache-Control': 'no-store',
      'Content-Security-Policy': "default-src 'none'; style-src 'self'; img-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'",
    },
  });
}

/** @param {Request} req */
async function handleShareTarget(req) {
  try {
    const data = await req.formData();
    const files = data.getAll('files').filter((f) => typeof f === 'object' && f && 'size' in f);
    // A link or text share (Android offers the app for text/plain too, since files accept */*) has no files: say so
    // (js/app.js SHARE_NO_FILES) instead of parking nothing, which would read as an expired hand-off.
    if (!files.length) return Response.redirect('/files?share-target=none', 303);
    const id = Math.random().toString(36).slice(2) + Date.now().toString(36);
    shared.set(id, files);
    // forget unclaimed hand-offs after 5 minutes
    setTimeout(() => shared.delete(id), 5 * 60 * 1000);
    return Response.redirect(`/files?share-target=${encodeURIComponent(id)}`, 303);
  } catch (err) {
    return Response.redirect('/files', 303);
  }
}
