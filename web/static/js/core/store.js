// @ts-check
/**
 * Tiny reactive store: signals with automatic dependency tracking, computed values and effects, plus the app-wide
 * stores (session, jobs) and a topic event bus fed by the SSE stream (/api/v1/events).
 * The session helpers answer what the signed-in account's role allows (isAdmin, can, canAny, isStaff, hasSpace);
 * they only shape the UI — the server authorizes every request on its own.
 *
 *   const count = signal(0);
 *   const double = computed(() => count.value * 2);
 *   const stop = effect(() => console.log(double.value));   // runs now and on every change
 *   count.value++;                                             // logs 2
 *   stop();
 *
 * Effects may return a cleanup function (run before the next run and on dispose).
 * Writes inside `batch(fn)` notify once at the end.
 * @module core/store
 */
import { boot } from './dom.js';
import { api, setCsrf } from './api.js';
import { MEMBER_PERMISSIONS } from './perms.js';

/**
 * @typedef {Object} Observer
 * @property {() => void} run
 * @property {Set<Signal<any>>} deps
 * @property {boolean} disposed
 */

/** @type {Observer | null} */
let currentObserver = null;
let batchDepth = 0;
/** @type {Set<Observer>} */
const pending = new Set();

/** @template T */
export class Signal {
  /** @param {T} value */
  constructor(value) {
    /** @type {T} */
    this._value = value;
    /** @type {Set<Observer>} */
    this._subs = new Set();
  }

  /** Current value (tracked when read inside an effect/computed). */
  get value() {
    if (currentObserver && !currentObserver.disposed) {
      this._subs.add(currentObserver);
      currentObserver.deps.add(this);
    }
    return this._value;
  }

  set value(v) {
    if (Object.is(v, this._value)) return;
    this._value = v;
    this._notify();
  }

  /** Read without tracking. */
  peek() {
    return this._value;
  }

  /**
   * Update from the previous value. For objects/arrays, return a new value (or mutate and call `touch()`).
   * @param {(prev: T) => T} fn
   */
  update(fn) {
    this.value = fn(this._value);
  }

  /** Force subscribers to re-run (after in-place mutation). */
  touch() {
    this._notify();
  }

  /**
   * Subscribe to changes; `fn` is called immediately and on every change. Returns an unsubscribe function.
   * @param {(value: T) => void} fn
   */
  subscribe(fn) {
    return effect(() => {
      const v = this.value;
      untracked(() => fn(v));
    });
  }

  _notify() {
    for (const obs of [...this._subs]) {
      if (obs.disposed) {
        this._subs.delete(obs);
        continue;
      }
      if (batchDepth > 0) pending.add(obs);
      else obs.run();
    }
  }
}

/**
 * Create a signal.
 * @template T
 * @param {T} value
 * @returns {Signal<T>}
 */
export function signal(value) {
  return new Signal(value);
}

/**
 * Run `fn` without tracking dependencies.
 * @template R
 * @param {() => R} fn
 * @returns {R}
 */
export function untracked(fn) {
  const prev = currentObserver;
  currentObserver = null;
  try {
    return fn();
  } finally {
    currentObserver = prev;
  }
}

/**
 * Run `fn` now and again whenever a signal it read changes. Returns a dispose function.
 * @param {() => (void | (() => void))} fn
 * @returns {() => void}
 */
export function effect(fn) {
  /** @type {(() => void) | void} */
  let cleanup;
  let running = false;
  /** @type {Observer} */
  const obs = {
    deps: new Set(),
    disposed: false,
    run() {
      if (obs.disposed || running) return;
      running = true;
      if (typeof cleanup === 'function') {
        try { cleanup(); } catch (err) { console.error(err); }
      }
      for (const d of obs.deps) d._subs.delete(obs);
      obs.deps.clear();
      const prev = currentObserver;
      currentObserver = obs;
      try {
        cleanup = fn();
      } catch (err) {
        console.error('effect error', err);
      } finally {
        currentObserver = prev;
        running = false;
      }
    },
  };
  obs.run();
  return () => {
    obs.disposed = true;
    for (const d of obs.deps) d._subs.delete(obs);
    obs.deps.clear();
    if (typeof cleanup === 'function') {
      try { cleanup(); } catch (err) { console.error(err); }
    }
  };
}

/**
 * Derived read-only signal. (Eager: recomputed when a dependency changes.)
 * @template T
 * @param {() => T} fn
 * @returns {Signal<T>}
 */
export function computed(fn) {
  /** @type {Signal<T>} */
  const s = new Signal(/** @type {T} */ (/** @type {unknown} */ (undefined)));
  effect(() => {
    s.value = fn();
  });
  return s;
}

/**
 * Group writes; subscribers run once after `fn` returns.
 * @param {() => void} fn
 */
export function batch(fn) {
  batchDepth += 1;
  try {
    fn();
  } finally {
    batchDepth -= 1;
    if (batchDepth === 0) {
      const list = [...pending];
      pending.clear();
      for (const obs of list) obs.run();
    }
  }
}

// ---------------------------------------------------------------------------------------------------------------
// Event bus (SSE topics and in-app events)
// ---------------------------------------------------------------------------------------------------------------

/** @typedef {(data: any, topic: string) => void} TopicHandler */

/** @type {Map<string, Set<TopicHandler>>} */
const topicHandlers = new Map();

export const events = {
  /**
   * Subscribe to a topic ("job.progress", "settings.changed", … or "*" for everything). Returns an unsubscribe fn.
   * @param {string} topic
   * @param {TopicHandler} fn
   */
  on(topic, fn) {
    let set = topicHandlers.get(topic);
    if (!set) {
      set = new Set();
      topicHandlers.set(topic, set);
    }
    set.add(fn);
    return () => set?.delete(fn);
  },
  /**
   * Subscribe for a single delivery.
   * @param {string} topic
   * @param {TopicHandler} fn
   */
  once(topic, fn) {
    const off = events.on(topic, (d, t) => {
      off();
      fn(d, t);
    });
    return off;
  },
  /**
   * Publish locally (the SSE client calls this for every server event).
   * @param {string} topic
   * @param {any} [data]
   */
  emit(topic, data) {
    for (const key of [topic, '*']) {
      const set = topicHandlers.get(key);
      if (!set) continue;
      for (const fn of [...set]) {
        try {
          fn(data, topic);
        } catch (err) {
          console.error(`event handler for ${topic} failed`, err);
        }
      }
    }
  },
};

// ---------------------------------------------------------------------------------------------------------------
// Session (GET /api/v1/me)
// ---------------------------------------------------------------------------------------------------------------

/**
 * GET /me (core.Me). `user.permissions` lists what the account's role allows (catalog names, core/perms.js),
 * `user.role` is the built-in base (owner|admin|member|guest) and `user.role_id` the role itself
 * (owner|admin|member|guest|rol_…).
 * @typedef {Object} Me
 * @property {import('./dom.js').BootUser} user
 * @property {string} [csrf]
 * @property {any} [mfa]
 * @property {Record<string, any>} [prefs]
 * @property {Record<string, boolean>} [features]
 * @property {any[]} [spaces]
 * @property {any[]} [groups]
 * @property {string} [space_id] the personal space ("" or absent: none)
 * @property {boolean} [staff] the session can use at least one server permission (owners and admins included)
 * @property {string} [via] session|token|socket|offline
 */

/** The current /me payload, or null when signed out / not yet loaded. @type {Signal<Me | null>} */
export const session = signal(/** @type {Me | null} */ (null));

/** @returns {import('./dom.js').BootUser | null} */
export function currentUser() {
  const s = session.peek();
  return s ? s.user : null;
}

/**
 * True for the built-in owner and admin roles (full administrators: the administrator-only areas — roles, security,
 * e-mail, backup and server settings, encryption keys, custom certificates, backup restore — stay with them).
 * A custom role never counts, whatever its permissions: its `role` is its base, member or guest.
 * @param {Me | null} [me]
 */
export function isAdmin(me = session.peek()) {
  const role = me?.user?.role;
  return role === 'owner' || role === 'admin';
}

/**
 * The account a check looks at: the /me payload, or the boot data before /me has loaded.
 * @param {Me | null | undefined} me
 * @returns {import('./dom.js').BootUser | null}
 */
function accountOf(me) {
  return me ? me.user || null : boot().user;
}

/**
 * Whether the signed-in account's role grants the permission `perm` (a catalog name such as "users.view", see
 * core/perms.js). Owners and admins hold every permission — their list is complete, and the role check also covers
 * one this page does not know yet.
 * @param {string} perm
 * @param {Me | null} [me]
 */
export function can(perm, me = session.peek()) {
  const u = accountOf(me);
  if (!u) return false;
  if (u.role === 'owner' || u.role === 'admin') return true;
  // Every account of a server with roles names its role (role_id); without one the payload predates roles, and the
  // built-in Member role allows what it always did.
  if (!u.role_id) return u.role === 'member' && MEMBER_PERMISSIONS.includes(perm);
  return Array.isArray(u.permissions) && u.permissions.includes(perm);
}

/**
 * Whether the role grants at least one of `perms`.
 * @param {string[]} perms
 * @param {Me | null} [me]
 */
export const canAny = (perms, me) => perms.some((p) => can(p, me));

/**
 * Whether the account can use at least one server permission ("staff": owners and admins, or a role with a server
 * permission). Decides whether the Admin area shows at all.
 * @param {Me | null} [me]
 */
export function isStaff(me = session.peek()) {
  const u = accountOf(me);
  if (!u) return false;
  if (u.role === 'owner' || u.role === 'admin') return true;
  return !!(me?.staff ?? u.staff);
}

/**
 * Whether the account has a personal "My files" space (roles based on Guest have none).
 * @param {Me | null} [me]
 */
export function hasSpace(me = session.peek()) {
  const u = accountOf(me);
  if (!u) return false;
  if (u.space_id || me?.space_id) return true;
  // A payload without role_id comes from a server that predates roles, and may not name the space: there, exactly
  // the guests have none.
  return u.role_id === undefined && !!u.role && u.role !== 'guest';
}

/**
 * Re-read GET /me into the session store (and the CSRF token, which rotates with the session). The navigation,
 * the route guard and every check above follow the store.
 * @param {AbortSignal} [signal]
 * @returns {Promise<any>} the /me payload (null on failure)
 */
export async function refreshMe(signal) {
  try {
    const res = await api.get('/me', { signal, handle: false });
    const me = res && res.user ? res : res && res.id ? { user: res } : null;
    if (me) {
      if (typeof me.csrf === 'string' && me.csrf) setCsrf(me.csrf);
      session.value = { ...(session.peek() || {}), ...me };
    }
    return me;
  } catch {
    return null;
  }
}

/**
 * True when the session may call the API proper. A session with a pending second factor, an unfinished required
 * 2FA enrolment or a password it must change first sits behind mw.RequireFull: every ordinary endpoint (/events,
 * /spaces, /admin/*) answers 403 until enrolment or the password change finishes, so the app must not fire its
 * bootstrap requests or open the event stream — the console would otherwise fill with 403s on a perfectly normal
 * screen. Accepts both payload shapes (core.Me and the pages.BootUser fallback).
 * @param {Me | null} [me]
 */
export function isFullSession(me = session.peek()) {
  if (!me) return false;
  const any = /** @type {any} */ (me);
  const u = any.user || {};
  if (any.mfa_pending || u.mfa_pending || u.must_change_password) return false;
  return !(me.mfa?.enroll_required || u.enroll_required);
}

// ---------------------------------------------------------------------------------------------------------------
// Jobs (fed by SSE job.progress / job.done, and re-read from GET /jobs/{id} whenever the event stream (re)connects —
// app.js reconcileJobs(): events published while no stream was open are never replayed)
// ---------------------------------------------------------------------------------------------------------------

/**
 * @typedef {Object} JobState
 * @property {string} id
 * @property {string} [kind]
 * @property {string} [state] queued|running|succeeded|failed|canceled
 * @property {number} [progress_done]
 * @property {number} [progress_total]
 * @property {string} [note]
 * @property {string} [error]
 * @property {any} [result]
 * @property {number} updated client timestamp (ms)
 */

/** Map of job id → state (a new Map on every change). @type {Signal<Map<string, JobState>>} */
export const jobs = signal(new Map());

const FINISHED = new Set(['succeeded', 'failed', 'canceled']);

/**
 * True once a job has ended (succeeded, failed or canceled).
 * @param {{state?: string} | null | undefined} job
 */
export function isFinishedJob(job) {
  return FINISHED.has(job?.state || '');
}

/**
 * Merge a job update. Accepts a Job object, or SSE data shaped {job: <Job|id>, …}.
 * @param {any} data
 * @param {string} [topic]
 */
export function upsertJob(data, topic) {
  if (!data) return;
  const src = data.job && typeof data.job === 'object' ? data.job : data;
  const id = typeof data.job === 'string' ? data.job : src.id || src.job_id;
  if (!id) return;
  const next = new Map(jobs.peek());
  const prev = next.get(id) || { id, updated: 0 };
  // A finished job never runs again (a re-run is a new job): a GET /jobs/{id} that read "running" and answers after
  // the job.done must not bring it back.
  const incoming = typeof data.job === 'string' ? data.state : src.state;
  if (isFinishedJob(prev) && incoming && !FINISHED.has(incoming)) return;
  /** @type {JobState} */
  const merged = { ...prev, ...src, id, updated: Date.now() };
  if (typeof data.job === 'string') {
    for (const k of ['kind', 'state', 'progress_done', 'progress_total', 'note', 'error', 'result', 'done', 'total']) {
      if (k in data) /** @type {any} */ (merged)[k] = data[k];
    }
  }
  if (merged.progress_done === undefined && typeof /** @type {any} */ (merged).done === 'number') merged.progress_done = /** @type {any} */ (merged).done;
  if (merged.progress_total === undefined && typeof /** @type {any} */ (merged).total === 'number') merged.progress_total = /** @type {any} */ (merged).total;
  if (topic === 'job.done' && !FINISHED.has(merged.state || '')) merged.state = merged.error ? 'failed' : 'succeeded';
  if (topic === 'job.progress' && !merged.state) merged.state = 'running';
  next.set(id, merged);
  // keep the map small: drop finished jobs older than 10 minutes
  const cutoff = Date.now() - 10 * 60_000;
  for (const [k, j] of next) if (FINISHED.has(j.state || '') && j.updated < cutoff) next.delete(k);
  jobs.value = next;
}

/**
 * Drop a job from the store (GET /jobs/{id} answered 404: it was pruned, so it can no longer finish on screen).
 * @param {string} id
 */
export function forgetJob(id) {
  if (!jobs.peek().has(id)) return;
  const next = new Map(jobs.peek());
  next.delete(id);
  jobs.value = next;
}

/** Number of queued/running jobs. */
export const activeJobCount = computed(() => {
  let n = 0;
  for (const j of jobs.value.values()) if (!FINISHED.has(j.state || '')) n += 1;
  return n;
});

events.on('job.progress', (d, t) => upsertJob(d, t));
events.on('job.done', (d, t) => upsertJob(d, t));

// ---------------------------------------------------------------------------------------------------------------
// Small persisted UI preferences (localStorage; per device)
// ---------------------------------------------------------------------------------------------------------------

/**
 * A signal persisted in localStorage under "fp:<key>". Only real changes are stored: `initial` may be a default
 * derived from the account preferences or a server setting, and writing it back would pin it on this device for
 * good (a later change of that default could never reach it again).
 * @template T
 * @param {string} key
 * @param {T} initial
 * @returns {Signal<T>}
 */
export function persisted(key, initial) {
  let v = initial;
  try {
    const raw = localStorage.getItem(`fp:${key}`);
    if (raw !== null) v = JSON.parse(raw);
  } catch { /* storage unavailable */ }
  const s = signal(v);
  let seeded = true; // subscribe() fires immediately with the initial value: that is a default, not a choice
  s.subscribe((val) => {
    if (seeded) {
      seeded = false;
      return;
    }
    try {
      localStorage.setItem(`fp:${key}`, JSON.stringify(val));
    } catch { /* ignore quota / private mode */ }
  });
  return s;
}
