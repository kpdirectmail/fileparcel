// @ts-check
/**
 * Shared pieces of the personal settings pages (/settings/*). Not a page module (routes.js never loads it).
 *
 *   settingsHeader(root, {id, title, subtitle, actions})   page header + the settings section tabs
 *   refreshMe()                                            GET /me → session store + CSRF token (core/store.js)
 *   savePrefs(patch)                                       merge into the user's prefs (PATCH /me/profile {prefs})
 *   passwordForm({onDone})                                 change password (POST /me/password)
 * Owned by unit J2.
 * @module pages/settings/common
 */
import { h, icon, append } from '../../core/dom.js';
import { api, setCsrf, ApiError } from '../../core/api.js';
import { session, refreshMe } from '../../core/store.js';
import { pageHeader } from '../../components/page-header.js';
import { field } from '../../components/field.js';
import { form } from '../../components/form.js';
import { toast } from '../../components/toast.js';
import { SETTINGS_NAV } from '../../nav.js';
import { strengthMeter, estimate, passwordMin } from '../../public/password-strength.js';

/**
 * Header with the section tabs of the personal settings.
 * @param {HTMLElement} root
 * @param {{id: string, title: string, subtitle?: import('../../core/dom.js').Child, actions?: import('../../core/dom.js').Child}} o
 *   id: SETTINGS_NAV id of the current page ("settings-profile", …)
 */
export function settingsHeader(root, o) {
  const strip = h('nav', { class: 'tabs settings-tabs', attrs: { 'aria-label': 'Settings pages' } },
    SETTINGS_NAV.map((it) => h('a', {
      class: 'tab',
      href: it.href,
      attrs: { 'aria-current': it.id === o.id ? 'page' : null },
    }, icon(it.icon, { size: 16 }), h('span', { text: it.label }))));
  append(root, pageHeader({ title: o.title, subtitle: o.subtitle, actions: o.actions }), strip);
  // The strip scrolls horizontally on phones (components.css .tabs) and its scrollbar is hidden, so centre the
  // current page in it — otherwise the later sections show no active tab at all. The router appends `root` before
  // it calls mount(), so the strip is connected and these measurements are valid.
  // scrollLeft rather than scrollIntoView(): the latter also scrolls every scrollable ancestor (and the window),
  // which would fight the router's own scroll restore. The browser clamps, so the first/last tabs sit at the ends.
  const cur = /** @type {HTMLElement | null} */ (strip.querySelector('[aria-current="page"]'));
  if (cur) {
    const s = strip.getBoundingClientRect(), t = cur.getBoundingClientRect();
    strip.scrollLeft += t.left - s.left - (strip.clientWidth - t.width) / 2;
  }
}

// refreshMe() lives in core/store.js (the shell calls it on authz.changed); re-exported for the settings pages.
export { refreshMe };

/** Current preferences object (never null). @returns {Record<string, any>} */
export function currentPrefs() {
  const me = /** @type {any} */ (session.peek());
  const p = me?.prefs || me?.user?.prefs;
  return p && typeof p === 'object' && !Array.isArray(p) ? { ...p } : {};
}

/** The last save in progress: savePrefs() runs one save at a time. @type {Promise<unknown>} */
let saveChain = Promise.resolve();

/**
 * Merge `patch` into the user's preferences and save them (PATCH /me/profile replaces the whole prefs object, so
 * the merged object is sent). Updates the session store.
 * Saves run one after the other, each merging into the prefs the previous one left in the store: two overlapping
 * saves (a debounced change while the last one is still in flight) would otherwise each send the other's key at its
 * old value, and whichever landed last would win.
 * Known keys: theme (light|dark|system), density (comfortable|compact), view (list|grid).
 * @param {Record<string, any>} patch
 * @returns {Promise<Record<string, any>>} the saved prefs
 */
export function savePrefs(patch) {
  const run = saveChain.catch(() => {}).then(async () => {
    const prefs = { ...currentPrefs(), ...patch };
    for (const [k, v] of Object.entries(prefs)) if (v === undefined || v === null || v === '') delete prefs[k];
    const res = await api.patch('/me/profile', { prefs });
    const me = /** @type {any} */ (session.peek());
    if (me) {
      const user = res && res.id ? { ...me.user, ...res, prefs } : { ...me.user, prefs };
      session.value = { ...me, prefs, user };
    }
    return prefs;
  });
  saveChain = run;
  return run;
}

/**
 * Password change form (POST /me/password {current_password, new_password}). Changing the password signs out every
 * other session and rotates this one (the CSRF token is refreshed afterwards).
 * @param {{onDone?: () => void, autofocus?: boolean}} [o]
 * @returns {ReturnType<typeof form>}
 */
export function passwordForm(o = {}) {
  const user = /** @type {any} */ (session.peek())?.user || {};
  const current = field({ label: 'Current password', name: 'current_password', type: 'password', autocomplete: 'current-password', required: true, autofocus: !!o.autofocus });
  const next = field({
    label: 'New password',
    name: 'new_password',
    type: 'password',
    autocomplete: 'new-password',
    required: true,
    minlength: 8,
    maxlength: 1024,
    help: 'Use a long password. A short sentence of random words is strong and easy to remember.',
  });
  // name the server's minimum (auth.password_min, 8–128) once it is known
  passwordMin().then((n) => {
    const help = next.el.querySelector('.field-help');
    if (help) help.textContent = `At least ${n} characters. A short sentence of random words is strong and easy to remember.`;
  });
  const meter = strengthMeter(/** @type {HTMLInputElement} */ (next.input), { userInputs: () => [user.username, user.display_name, user.email] });
  append(next.el, meter.el);
  const again = field({ label: 'Repeat new password', name: 'confirm', type: 'password', autocomplete: 'new-password', required: true });
  // a hidden username field lets password managers attach the new password to the right account
  const hiddenUser = h('input', { class: 'sr-only', attrs: { type: 'text', autocomplete: 'username', tabindex: '-1', 'aria-hidden': 'true', readonly: true }, value: user.username || '' });

  const f = form({
    fields: [hiddenUser, current, next, again],
    submitLabel: 'Change password',
    submitIcon: 'key',
    onSubmit: async (v) => {
      if (v.new_password !== v.confirm) throw new ApiError(422, 'invalid', 'The passwords do not match.', 'confirm');
      if (v.new_password === v.current_password) throw new ApiError(422, 'invalid', 'Choose a password that is different from the current one.', 'new_password');
      const est = estimate(v.new_password, { userInputs: [user.username, user.display_name, user.email] });
      if (est.score < 2) throw new ApiError(422, 'invalid', est.warning || 'Please choose a stronger password.', 'new_password');
      /** @type {any} */
      let res;
      try {
        // handle: false — a wrong current password may be answered with 401, which must not bounce to /login
        res = await api.post('/me/password', { current_password: v.current_password, new_password: v.new_password }, { handle: false });
      } catch (err) {
        if (err instanceof ApiError && (err.status === 401 || err.status === 403) && !err.field) {
          throw new ApiError(err.status, err.code, 'Your current password is not correct.', 'current_password');
        }
        if (err instanceof ApiError && err.field === 'password') throw new ApiError(err.status, err.code, err.message, 'new_password');
        throw err;
      }
      if (res && typeof res.csrf === 'string' && res.csrf) setCsrf(res.csrf);
      f.reset();
      meter.update();
      await refreshMe();
      const me = /** @type {any} */ (session.peek());
      if (me?.user) session.value = { ...me, user: { ...me.user, must_change_password: false } };
      toast.success('Password changed. Your other sessions were signed out.');
      o.onDone?.();
    },
  });
  return f;
}
