// @ts-check
/**
 * JSON API client for /api/v1 (and the public /s/{token}/api endpoints).
 *
 *   const me = await api.get('/me');                        // → /api/v1/me
 *   await api.post('/nodes/nod_x/folders', {name: 'Docs'});
 *   const res = await api.raw('/api/v1/uploads/upf_x/parts/0', {method: 'PUT', body: blob});
 *
 * Paths starting with "/api/" or "/s/" (or absolute URLs) are used as-is; any other path is prefixed with "/api/v1".
 * Every request is same-origin with cookies; unsafe methods carry `X-FP-CSRF`.
 *
 * Automatic handling (disable per request with `{handle: false}`, e.g. on public pages / login forms):
 *   401 unauthorized          → location.assign('/login?next=<current path>')
 *   403 elevation_required    → promptElevation() then retry the request once
 *   403 mfa_enroll_required   → navigate('/settings/security?enroll=1', {replace}) unless already there
 *   403 password_change_required → navigate('/settings/security?must_change=1', {replace}) unless already there
 *   503 keys_locked           → location.assign('/unlock?next=…')
 * Always (even with `{handle: false}`, since nothing is shown):
 *   403 csrf_invalid          → refreshCsrf() (the session changed in another tab) then retry the request once
 * Errors are thrown as ApiError {status, code, message, field, requestId}.
 * @module core/api
 */
import { boot } from './dom.js';

export class ApiError extends Error {
  /**
   * @param {number} status HTTP status (0 = network error)
   * @param {string} code error code from §5.1 ("not_found", "invalid", …) or "network"/"http_<status>"
   * @param {string} message human readable message
   * @param {string} [field] offending field for 422 invalid
   * @param {string} [requestId] X-Request-ID for support
   * @param {any} [details] raw error body
   */
  constructor(status, code, message, field, requestId, details) {
    super(message || code || `HTTP ${status}`);
    this.name = 'ApiError';
    /** @type {number} */
    this.status = status;
    /** @type {string} */
    this.code = code;
    /** @type {string | undefined} */
    this.field = field || undefined;
    /** @type {string | undefined} */
    this.requestId = requestId || undefined;
    /** @type {any} */
    this.details = details;
    /** @type {number} seconds from the Retry-After header of a 429/503 (0 when the server sent none) */
    this.retryAfter = 0;
  }

  /** True for aborted requests (AbortController). */
  get aborted() {
    return this.code === 'aborted';
  }
}

/**
 * @typedef {Object} ApiOpts
 * @property {Record<string, string | number | boolean | null | undefined | (string | number)[]>} [query] query string params (null/undefined skipped)
 * @property {AbortSignal} [signal]
 * @property {Record<string, string>} [headers]
 * @property {boolean} [handle] automatic 401/403/503 handling (default true)
 * @property {'json' | 'text' | 'blob' | 'response'} [as] response parsing (default: JSON when the response is JSON)
 * @property {boolean} [keepalive]
 * @property {boolean} [csrfRetried] internal: this is the replay after a refreshCsrf()
 */

let csrfToken = '';
try {
  csrfToken = boot().csrf || '';
} catch { /* no DOM (worker) */ }

/**
 * Update the CSRF token (after login, /me, elevation – tokens rotate with the session).
 * @param {string} token
 */
export function setCsrf(token) {
  if (typeof token === 'string') csrfToken = token;
}

/** @returns {string} */
export function getCsrf() {
  return csrfToken;
}

/** @type {Promise<boolean> | null} */
let csrfRefresh = null;

/**
 * Re-read the CSRF token after a 403 csrf_invalid. The token is bound to the session and every sign-in starts a new
 * one: once the user signs in again in another tab, this tab's cookie names the new session while the page still
 * sends the old session's token, so every change would fail until a reload. GET /me (one request, shared by
 * concurrent callers) returns the current token. Resolves true when the failed request may be sent again with it:
 * the session still belongs to the account this page was loaded for. For another account — or a page loaded signed
 * out — the page reloads instead: a change made as one user is never replayed as another, and the page would show
 * the wrong account anyway.
 * @returns {Promise<boolean>}
 */
export function refreshCsrf() {
  csrfRefresh ??= (async () => {
    const res = await raw('/me', { headers: { Accept: 'application/json' } });
    if (!res.ok) return false;
    const me = await res.json();
    if (typeof me?.csrf !== 'string' || !me.csrf) return false;
    let loadedAs = '';
    try { loadedAs = boot().user?.id || ''; } catch { /* no boot data */ }
    if (!loadedAs || me.user?.id !== loadedAs) {
      location.reload();
      return false;
    }
    csrfToken = me.csrf;
    return true;
  })().catch(() => false).finally(() => { csrfRefresh = null; });
  return csrfRefresh;
}

/**
 * @typedef {Object} ApiHooks
 * @property {(err: ApiError) => void} onUnauthorized
 * @property {() => Promise<boolean>} onElevation resolve true when the user elevated
 * @property {(err: ApiError) => void} onEnrollRequired
 * @property {(err: ApiError) => void} onPasswordChangeRequired
 * @property {(err: ApiError) => void} onKeysLocked
 */

/** @returns {string} current path + query for ?next= */
function here() {
  return location.pathname + location.search;
}

/** @type {ApiHooks} */
const hooks = {
  onUnauthorized() {
    if (location.pathname === '/login') return;
    location.assign(`/login?next=${encodeURIComponent(here())}`);
  },
  async onElevation() {
    const mod = await import('../components/elevation.js');
    return mod.promptElevation();
  },
  async onEnrollRequired() {
    // The security page itself may call full-auth-only endpoints (e.g. GET /me/passkeys): re-navigating there would
    // remount it and loop, pushing history each time. Stay put; elsewhere replace the entry instead of pushing.
    if (location.pathname === '/settings/security') return;
    const { navigate } = await import('./router.js');
    navigate('/settings/security?enroll=1', { replace: true });
  },
  async onPasswordChangeRequired() {
    // A password set by an administrator or the installer: only /me* works until it is changed (same loop guard).
    if (location.pathname === '/settings/security') return;
    const { navigate } = await import('./router.js');
    navigate('/settings/security?must_change=1', { replace: true });
  },
  onKeysLocked() {
    if (location.pathname === '/unlock') return;
    location.assign(`/unlock?next=${encodeURIComponent(here())}`);
  },
};

/**
 * Override automatic error handlers (app.js may, e.g., show a toast before redirecting).
 * @param {Partial<ApiHooks>} h
 */
export function configureApi(h) {
  Object.assign(hooks, h);
}

/**
 * Resolve an API path to a URL string with query parameters.
 * @param {string} path
 * @param {ApiOpts['query']} [query]
 */
export function apiUrl(path, query) {
  let url = path;
  if (!/^(https?:)?\/\//.test(path) && !path.startsWith('/api/') && !path.startsWith('/s/')) {
    url = `/api/v1${path.startsWith('/') ? '' : '/'}${path}`;
  }
  if (query) {
    const qs = new URLSearchParams();
    for (const [k, v] of Object.entries(query)) {
      if (v === null || v === undefined || v === '') continue;
      if (Array.isArray(v)) v.forEach((x) => qs.append(k, String(x)));
      else qs.set(k, String(v));
    }
    const s = qs.toString();
    if (s) url += (url.includes('?') ? '&' : '?') + s;
  }
  return url;
}

const SAFE = new Set(['GET', 'HEAD', 'OPTIONS']);

/**
 * Low-level fetch with credentials + CSRF header; no error handling. Returns the Response.
 * @param {string} path
 * @param {RequestInit & {query?: ApiOpts['query']}} [init]
 * @returns {Promise<Response>}
 */
export function raw(path, init = {}) {
  const { query, ...rest } = init;
  const method = (rest.method || 'GET').toUpperCase();
  const headers = new Headers(rest.headers || {});
  if (!SAFE.has(method) && csrfToken && !headers.has('X-FP-CSRF')) headers.set('X-FP-CSRF', csrfToken);
  /** @type {RequestInit & {duplex?: string}} */
  const extra = {};
  // streaming request bodies require duplex: 'half' (fetch throws a TypeError without it)
  if (typeof ReadableStream !== 'undefined' && rest.body instanceof ReadableStream) extra.duplex = 'half';
  return fetch(apiUrl(path, query), { credentials: 'same-origin', cache: 'no-store', ...rest, ...extra, method, headers });
}

/**
 * Parse an error response into an ApiError.
 * @param {Response} res
 * @returns {Promise<ApiError>}
 */
export async function errorFrom(res) {
  let body = null;
  try {
    const ct = res.headers.get('Content-Type') || '';
    body = ct.includes('json') ? await res.json() : null;
  } catch { /* not JSON */ }
  const e = body && body.error ? body.error : {};
  const code = e.code || `http_${res.status}`;
  const message = e.message || defaultMessage(res.status);
  const err = new ApiError(res.status, code, message, e.field, e.request_id || res.headers.get('X-Request-ID') || undefined, body);
  // The wait of a rate limit lives in the header, never in the §5.1 error envelope. FileParcel always sends whole
  // seconds; an RFC 9110 HTTP-date would yield NaN and simply leave retryAfter at 0.
  const ra = Number(res.headers.get('Retry-After'));
  if (Number.isFinite(ra) && ra > 0) err.retryAfter = ra;
  return err;
}

/** @param {number} status */
function defaultMessage(status) {
  switch (status) {
    case 400: return 'The request was not valid.';
    case 401: return 'Please sign in again.';
    case 403: return 'You do not have permission to do that.';
    case 404: return 'Not found.';
    case 409: return 'That conflicts with the current state.';
    case 413: return 'That is too large.';
    case 422: return 'Please check the highlighted fields.';
    case 429: return 'Too many requests. Please wait a moment.';
    case 501: return 'This feature is not available yet.';
    case 503: return 'The server is temporarily unavailable.';
    default: return status >= 500 ? 'Something went wrong on the server.' : `Request failed (${status}).`;
  }
}

/**
 * @param {any} body
 * @returns {body is BodyInit}
 */
function isRawBody(body) {
  return (
    body instanceof FormData || body instanceof Blob || body instanceof ArrayBuffer || ArrayBuffer.isView(body) ||
    body instanceof URLSearchParams || (typeof ReadableStream !== 'undefined' && body instanceof ReadableStream) ||
    typeof body === 'string'
  );
}

/**
 * Perform a request and parse the JSON response.
 * @param {string} method
 * @param {string} path
 * @param {any} [body]
 * @param {ApiOpts} [opts]
 * @param {boolean} [retried]
 * @returns {Promise<any>}
 */
export async function request(method, path, body, opts = {}, retried = false) {
  /** @type {Record<string, string>} */
  const headers = { Accept: 'application/json', ...(opts.headers || {}) };
  /** @type {BodyInit | undefined} */
  let payload;
  if (body !== undefined && body !== null) {
    if (isRawBody(body)) payload = body;
    else {
      payload = JSON.stringify(body);
      headers['Content-Type'] = 'application/json';
    }
  }
  /** @type {Response} */
  let res;
  try {
    res = await raw(path, { method, body: payload, headers, signal: opts.signal, query: opts.query, keepalive: opts.keepalive });
  } catch (err) {
    if (/** @type {any} */ (err)?.name === 'AbortError') throw new ApiError(0, 'aborted', 'Request aborted');
    throw new ApiError(0, 'network', 'Cannot reach the server. Check your connection.');
  }

  if (!res.ok) {
    const err = await errorFrom(res);
    if (res.status === 403 && err.code === 'csrf_invalid' && !opts.csrfRetried && !(payload instanceof ReadableStream) && await refreshCsrf()) {
      return request(method, path, body, { ...opts, csrfRetried: true }, retried);
    }
    const handle = opts.handle !== false;
    if (handle) {
      if (res.status === 401) {
        // unauthorized, or mfa_required (half-finished login): the login page resumes the flow
        hooks.onUnauthorized(err);
      } else if (res.status === 403 && err.code === 'elevation_required' && !retried && !(payload instanceof ReadableStream)) {
        const ok = await hooks.onElevation();
        if (ok) return request(method, path, body, opts, true);
      } else if (res.status === 403 && err.code === 'mfa_enroll_required') {
        hooks.onEnrollRequired(err);
      } else if (res.status === 403 && err.code === 'password_change_required') {
        hooks.onPasswordChangeRequired(err);
      } else if (res.status === 503 && err.code === 'keys_locked') {
        hooks.onKeysLocked(err);
      }
    }
    throw err;
  }

  if (opts.as === 'response') return res;
  if (res.status === 204 || method === 'HEAD') return null;
  if (opts.as === 'blob') return res.blob();
  if (opts.as === 'text') return res.text();
  const ct = res.headers.get('Content-Type') || '';
  if (opts.as === 'json' || ct.includes('json')) {
    const text = await res.text();
    return text ? JSON.parse(text) : null;
  }
  return res.text();
}

export const api = {
  /** @param {string} path @param {ApiOpts} [opts] */
  get: (path, opts) => request('GET', path, undefined, opts),
  /** @param {string} path @param {any} [body] @param {ApiOpts} [opts] */
  post: (path, body, opts) => request('POST', path, body ?? {}, opts),
  /** @param {string} path @param {any} [body] @param {ApiOpts} [opts] */
  put: (path, body, opts) => request('PUT', path, body ?? {}, opts),
  /** @param {string} path @param {any} [body] @param {ApiOpts} [opts] */
  patch: (path, body, opts) => request('PATCH', path, body ?? {}, opts),
  /** @param {string} path @param {any} [body] @param {ApiOpts} [opts] */
  del: (path, body, opts) => request('DELETE', path, body, opts),
  raw,
  url: apiUrl,
};

/**
 * Fetch every page of a cursor-paginated list endpoint ({items, next_cursor}).
 * @param {string} path
 * @param {ApiOpts & {max?: number}} [opts] max = safety cap on items (default 5000)
 * @returns {Promise<any[]>}
 */
export async function getAll(path, opts = {}) {
  const max = opts.max ?? 5000;
  /** @type {any[]} */
  const out = [];
  let cursor = '';
  do {
    const page = await api.get(path, { ...opts, query: { ...(opts.query || {}), cursor: cursor || undefined, limit: opts.query?.limit ?? 500 } });
    const items = Array.isArray(page) ? page : page?.items || [];
    out.push(...items);
    cursor = Array.isArray(page) ? '' : page?.next_cursor || '';
  } while (cursor && out.length < max);
  return out;
}

/**
 * Normalise a list response to an array (accepts `[...]` or `{items: [...]}`).
 * @param {any} res
 * @returns {any[]}
 */
export function itemsOf(res) {
  if (Array.isArray(res)) return res;
  if (res && Array.isArray(res.items)) return res.items;
  return [];
}

/**
 * Human-readable message for any thrown value.
 * @param {unknown} err
 */
export function errorMessage(err) {
  if (err instanceof ApiError) return err.message;
  if (err instanceof Error) return err.message;
  return String(err);
}
