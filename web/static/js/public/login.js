// @ts-check
/**
 * /login — username + password (+ "keep me signed in"), then — when the account has a second factor — a TOTP,
 * recovery-code or passkey step. Passkey sign-in (explicit button and conditional-mediation autofill on the username
 * field) is offered when passkeys are enabled and the page is served on the WebAuthn RP ID (§18.1).
 *
 * API (§9.4 authapi): GET /auth/state → AuthState {instance, setup_needed, passkeys, rp_id, keys_state, login_message,
 *   password_min}
 *   POST /auth/login {username, password, remember} → LoginResult {user} | {mfa_required, methods}
 *   POST /auth/totp {code} · POST /auth/recovery {code}
 *   POST /auth/passkey/begin {username?} → {options, flow_id} · POST /auth/passkey/finish {flow_id, credential, remember}
 *   (remember: the "keep me signed in" box, for a passwordless sign-in; ignored as the second factor)
 *   GET /me (A) → {mfa_pending, mfa} to resume a half-finished sign-in after a reload.
 * LoginResult may carry csrf, must_change_password and enroll_required.
 * Opened over Tailscale Funnel (boot ingress "funnel"), the page says that only accounts with two-factor
 * authentication can sign in there (features.funnel_2fa) and leaves out the /trust link.
 * Owned by unit J2.
 * @module public/login
 */
import { h, boot, replace, append } from '../core/dom.js';
import { api, setCsrf, ApiError, errorMessage } from '../core/api.js';
import { field, checkbox } from '../components/field.js';
import { form } from '../components/form.js';
import { button } from '../components/button.js';
import { publicRoot, authCard, nextPath, alertBox, instanceName, initAppearance, focusHeading, authState, rateLimitMessage } from './common.js';
import { passkeysAvailable, toGetOptions, credentialToJSON, conditionalMediationAvailable } from '../core/webauthn.js';

const b = boot();
/** Over Tailscale Funnel (the server's public internet address) only accounts with a second factor can sign in. */
const funnel2fa = b.ingress === 'funnel' && !!b.features.funnel_2fa;
const FUNNEL_HOW = 'This internet address only lets in accounts with two-factor authentication. New here, or no ' +
  'authenticator app yet? Sign in once at the address you use at home or over your VPN, set it up under Settings → ' +
  'Security, then sign in here.';
/** Pending conditional-mediation (autofill) passkey request. @type {AbortController | null} */
let conditional = null;
/** Failed password attempts in this page view (for the lockout hint). */
let failures = 0;
/** The "keep me signed in" box of the password form, read when a passkey sign-in finishes (the autofill request
 * starts before the user can tick it). @type {HTMLInputElement | null} */
let rememberInput = null;

initAppearance();
start();

async function start() {
  const state = await authState();
  if (state.keys_state === 'locked') {
    location.replace(`/unlock?next=${encodeURIComponent(`/login${location.search}`)}`);
    return;
  }
  if (b.data.setup_needed || state.setup_needed) {
    location.replace('/setup');
    return;
  }
  const passkeys = passkeysOn(state);
  if (b.user) {
    // A session exists: either fully signed in (go on) or waiting for the second factor (resume that step).
    try {
      const me = await api.get('/me', { handle: false });
      if (me && typeof me.csrf === 'string') setCsrf(me.csrf);
      if (me?.mfa_pending) {
        renderMFA(methodsFromStatus(me.mfa, !!(state.passkeys ?? b.features.passkeys)), state);
        return;
      }
      location.replace(nextPath((me?.user?.role || b.user.role) === 'guest' ? '/shared' : '/files'));
      return;
    } catch { /* stale cookie: sign in again */ }
  }
  renderPassword(state);
  if (passkeys) startConditionalPasskey();
}

/**
 * Passkeys are usable on this page: enabled on the server, supported by the browser, and the hostname is the RP ID.
 * @param {import('./common.js').AuthState} state
 */
function passkeysOn(state) {
  const enabled = state.passkeys ?? b.features.passkeys;
  return !!enabled && passkeysAvailable(state.rp_id || b.rp_id);
}

/**
 * "Passkeys work at <rp>" note when passkeys are enabled but this page is not served on the RP ID (e.g. opened by IP
 * address or by another host name), or null.
 * @param {import('./common.js').AuthState} state
 * @returns {HTMLElement | null}
 */
function passkeyElsewhere(state) {
  const rp = state.rp_id || b.rp_id;
  if (passkeysOn(state) || !(state.passkeys ?? b.features.passkeys) || !rp || typeof window.PublicKeyCredential === 'undefined' || location.hostname === rp) return null;
  const next = new URLSearchParams(location.search).get('next');
  const href = `https://${rp}${location.port ? `:${location.port}` : ''}/login${next ? `?next=${encodeURIComponent(next)}` : ''}`;
  return h('p', { class: 'auth-note' }, 'Passkeys work at ', h('a', { href, attrs: { 'data-native': true }, text: rp }), '.');
}

/**
 * Second-factor methods derived from GET /me's MFAStatus (when resuming after a reload), as the server's login
 * result lists them: renderMFA() decides what this page can use.
 * @param {any} mfa
 * @param {boolean} passkeys passkeys enabled on the server (auth.passkeys)
 */
function methodsFromStatus(mfa, passkeys) {
  if (!mfa) return ['totp', 'recovery']; // status unavailable: offer the code forms
  const m = [];
  if (mfa.totp_enabled) m.push('totp');
  if (mfa.recovery_codes_left > 0) m.push('recovery');
  if (passkeys && mfa.passkey_count > 0) m.push('passkey');
  return m;
}

/** "Start over": ends the half-finished sign-in. */
function startOver() {
  return h('a', {
    href: '/login',
    attrs: { 'data-native': true },
    text: 'Start over',
    on: { click: (e) => { e.preventDefault(); api.post('/auth/logout', {}, { handle: false }).catch(() => {}).finally(() => location.assign('/login')); } },
  });
}

/**
 * Where to go after a completed login.
 * @param {any} res LoginResult
 */
function finish(res) {
  conditional?.abort();
  if (res && typeof res.csrf === 'string') setCsrf(res.csrf);
  if (res?.must_change_password || res?.user?.must_change_password) location.assign('/settings/security?must_change=1');
  else if (res?.enroll_required) location.assign('/settings/security?enroll=1');
  else location.assign(nextPath(res?.user?.role === 'guest' ? '/shared' : '/files')); // guests have no "My files"
}

/**
 * Map sign-in errors to friendly, non-revealing messages. Returns the error to throw (form shows it).
 * @param {unknown} err
 */
function loginError(err) {
  if (!(err instanceof ApiError)) return err;
  if (err.code === 'keys_locked') {
    location.assign('/unlock?next=/login');
    return err;
  }
  if (err.status === 429) return new ApiError(429, err.code, rateLimitMessage(err, 'sign-in attempts'));
  if (err.code === 'locked' || err.status === 423 || /\blocked\b/i.test(err.message)) {
    return new ApiError(err.status, err.code, 'This account is temporarily locked after too many failed attempts. Try again later, or ask an administrator to unlock it.');
  }
  if (err.status === 403 && /disabled/i.test(err.message)) return new ApiError(403, err.code, 'This account is disabled. Please contact an administrator.');
  if (err.status === 401 || err.status === 403 || err.status === 422) {
    failures += 1;
    // Over Funnel (2FA required there) the server gives every failure this one answer, so it says nothing about the
    // password: a new account, or one without two-factor authentication yet, learns what to do.
    const base = funnel2fa
      ? 'Wrong username or password — or this account has no two-factor authentication yet. ' + FUNNEL_HOW
      : 'Invalid username or password.';
    return new ApiError(err.status, err.code, failures >= 3
      ? `${base} After repeated failures the account is locked for a while. If you forgot your password, ask an administrator to reset it.`
      : base);
  }
  return err;
}

/** @param {import('./common.js').AuthState} state */
function renderPassword(state) {
  const root = publicRoot();
  const passkeys = passkeysOn(state);
  const user = field({
    label: 'Username',
    name: 'username',
    autocomplete: passkeys ? 'username webauthn' : 'username',
    required: true,
    autofocus: true,
    attrs: { autocapitalize: 'off', spellcheck: 'false' },
  });
  const pass = field({ label: 'Password', name: 'password', type: 'password', autocomplete: 'current-password', required: true });
  const remember = checkbox({ label: 'Keep me signed in on this device', name: 'remember' });
  rememberInput = remember.input;
  const prefill = new URLSearchParams(location.search).get('username');
  if (prefill) user.input.value = prefill;

  const f = form({
    fields: [user, pass, remember],
    submitLabel: 'Sign in',
    submitIcon: 'login',
    stretchActions: true,
    onSubmit: async (v) => {
      conditional?.abort();
      /** @type {any} */
      let res;
      try {
        res = await api.post('/auth/login', { username: String(v.username).trim(), password: v.password, remember: !!v.remember }, { handle: false });
      } catch (err) {
        if (err instanceof ApiError && err.code === 'mfa_required') {
          await refreshCsrf();
          renderMFA(err.details?.error?.methods || err.details?.methods || ['totp', 'recovery'], state);
          return;
        }
        pass.input.value = '';
        pass.input.focus();
        throw loginError(err);
      }
      if (res?.mfa_required) {
        if (typeof res.csrf === 'string' && res.csrf) setCsrf(res.csrf);
        else await refreshCsrf();
        // methods is left out when there are none (omitempty): that is the "cannot be signed in" case, not TOTP
        renderMFA(Array.isArray(res.methods) ? res.methods : [], state);
        return;
      }
      finish(res);
    },
  });

  const message = typeof state.login_message === 'string' && state.login_message.trim()
    ? h('div', { class: 'auth-message', text: state.login_message })
    : null;
  const passkeyBtn = passkeys
    ? button({ label: 'Sign in with a passkey', icon: 'passkey', variant: 'secondary', block: true, onClick: () => passkeyLogin(String(user.input.value).trim(), false) })
    : null;
  const elsewhere = passkeyElsewhere(state);
  // Over Tailscale Funnel (the server's public internet address) only accounts with a second factor can sign in; the
  // server gives every failure there the same answer, so say it up front, with what a new account has to do. The
  // address carries a publicly trusted certificate, and /trust is not served there.
  const funnel = b.ingress === 'funnel';
  const funnelNote = funnel2fa ? alertBox('info', FUNNEL_HOW) : null;
  // Maintenance mode (features.maintenance): signing in works, but only administrators get further — say so before
  // anyone types a password and then meets the maintenance page.
  const maintNote = b.features.maintenance
    ? alertBox('warning', 'FileParcel is in maintenance mode. Only administrators can use it until the maintenance is over; everyone else sees the maintenance notice after signing in.')
    : null;

  append(root, authCard({
    title: `Sign in to ${state.instance || instanceName()}`,
    subtitle: 'Your private parcel of files.',
    body: [maintNote, funnelNote, message, f.el, passkeyBtn ? h('div', { class: 'auth-divider', text: 'or' }) : null, passkeyBtn, elsewhere],
    footer: funnel ? null : [h('a', { href: '/trust', attrs: { 'data-native': true }, text: 'Trust this server’s certificate' })],
  }));
  (prefill ? pass.input : user.input).focus();
}

/** After the password step the session exists at level 1; fetch the CSRF token for the second-factor POST. */
async function refreshCsrf() {
  try {
    const me = await api.get('/me', { handle: false });
    if (me && typeof me.csrf === 'string') setCsrf(me.csrf);
  } catch { /* the endpoint may not need it */ }
}

/**
 * Second-factor step.
 * @param {string[]} methods
 * @param {import('./common.js').AuthState} state
 */
function renderMFA(methods, state) {
  conditional?.abort();
  const root = publicRoot();
  if (!methods.length) {
    // The account's only second factor is a passkey and passkeys are turned
    // off on this server: there is nothing this form could accept, so say so
    // instead of showing an "Authentication code" box that can never be
    // satisfied. Only an administrator can clear it.
    append(root, authCard({
      title: 'This account cannot be signed in right now',
      icon: 'lock',
      subtitle: 'Its only second factor is a passkey, and passkeys are turned off on this server.',
      body: h('p', { class: 'muted text-sm', text: 'Ask an administrator to reset the two-factor authentication of this account (fileparcel user reset-2fa <username>), then sign in again and set up an authenticator app.' }),
      footer: [startOver()],
    }));
    focusHeading();
    return;
  }
  const canPasskey = methods.includes('passkey') && passkeysOn(state);
  // a passkey the account has but this page cannot use (another host name than the RP ID, no WebAuthn here)
  const offHost = methods.includes('passkey') && !canPasskey;
  let mode = methods.includes('totp') ? 'totp' : methods.includes('recovery') ? 'recovery' : canPasskey ? 'passkey' : '';
  if (!mode) {
    // Only the passkey is left and this page cannot use it: point to where it works instead of an
    // "Authentication code" box that can never be satisfied.
    const rp = state.rp_id || b.rp_id;
    append(root, authCard({
      title: 'Use your passkey to finish signing in',
      icon: 'passkey',
      subtitle: 'This account’s second step is a passkey, and it can’t be used on this page.',
      body: passkeyElsewhere(state) || h('p', { class: 'muted text-sm',
        text: `Open ${rp ? `https://${rp}` : 'this server by its own name'} in a browser that supports passkeys and sign in there.` }),
      footer: [startOver()],
    }));
    focusHeading();
    return;
  }
  const card = h('div', { class: 'auth-card-slot' });
  append(root, card);

  const draw = () => {
    /** @type {any[]} */
    const links = [];
    const switcher = (/** @type {string} */ label, /** @type {string} */ to) => h('button', {
      class: 'btn btn--ghost btn--sm', attrs: { type: 'button' }, text: label, on: { click: () => { mode = to; draw(); } },
    });
    if (mode !== 'totp' && methods.includes('totp')) links.push(switcher('Use your authenticator app', 'totp'));
    if (mode !== 'recovery' && methods.includes('recovery')) links.push(switcher('Use a recovery code', 'recovery'));
    if (mode !== 'passkey' && canPasskey) links.push(switcher('Use a passkey', 'passkey'));
    links.push(startOver());

    if (mode === 'passkey') {
      const status = h('div', { attrs: { 'aria-live': 'polite' } });
      replace(card, authCard({
        title: 'Confirm with your passkey',
        icon: 'passkey',
        subtitle: 'Use the passkey saved on this device, a security key or your phone.',
        body: [status, button({ label: 'Continue with passkey', icon: 'passkey', variant: 'primary', block: true, onClick: () => passkeyLogin('', false, status) })],
        footer: links,
      }));
      focusHeading();
      return;
    }

    const isTotp = mode === 'totp';
    const code = field({
      label: isTotp ? 'Authentication code' : 'Recovery code',
      name: 'code',
      autocomplete: 'one-time-code',
      inputmode: isTotp ? 'numeric' : 'text',
      code: true,
      // recovery codes are "XXXX-XXXX" (internal/auth/totp.go newRecoveryCode); maxlength leaves room for a
      // pasted code with a trailing space or a space instead of the dash (normalizeRecovery tolerates both)
      maxlength: isTotp ? 10 : 12,
      required: true,
      placeholder: isTotp ? '123 456' : 'xxxx-xxxx',
      help: isTotp ? 'Open your authenticator app and enter the 6-digit code for this account.' : 'Each recovery code works only once.',
    });
    const f = form({
      fields: [code],
      submitLabel: 'Verify',
      submitIcon: 'shield-check',
      stretchActions: true,
      onSubmit: async (v) => {
        const value = String(v.code).replace(/\s+/g, '');
        if (isTotp && !/^\d{6,8}$/.test(value)) throw new ApiError(422, 'invalid', 'Enter the 6-digit code from your app.', 'code');
        try {
          const res = await api.post(isTotp ? '/auth/totp' : '/auth/recovery', { code: value }, { handle: false });
          finish(res);
        } catch (err) {
          code.input.select();
          if (err instanceof ApiError) {
            if (err.status === 429) throw new ApiError(429, err.code, rateLimitMessage(err, 'attempts'));
            if (err.code === 'unauthorized' && /session|expired|sign in/i.test(err.message)) {
              renderPassword(state);
              document.getElementById('fp-root')?.prepend(alertBox('warning', 'Your sign-in took too long. Please start again.'));
              return;
            }
            if (err.status === 401 || err.status === 403 || err.status === 422) {
              throw new ApiError(err.status, err.code, isTotp ? 'That code is not valid. Wait for the next code and try again.' : 'That recovery code is not valid or was already used.', 'code');
            }
          }
          throw loginError(err);
        }
      },
    });
    // auto-submit once 6 digits were typed/pasted
    if (isTotp) {
      code.input.addEventListener('input', () => {
        const v = code.input.value.replace(/\s+/g, '');
        if (/^\d{6}$/.test(v)) f.submit();
      });
    }
    replace(card, authCard({
      title: 'Two-step verification',
      icon: 'shield-check',
      subtitle: 'One more step to keep your files safe.',
      // before a one-time recovery code is spent: the passkey works at the RP host
      body: [f.el, offHost ? passkeyElsewhere(state) : null],
      footer: links,
    }));
    focusHeading();
    code.input.focus();
  };
  draw();
}

/**
 * Passkey sign-in (explicit button, conditional autofill, or the second-factor step).
 * @param {string} username
 * @param {boolean} isConditional
 * @param {HTMLElement} [statusEl] where to show errors (defaults to the top of the card)
 */
async function passkeyLogin(username, isConditional, statusEl) {
  if (!isConditional) conditional?.abort();
  const ctrl = new AbortController();
  if (isConditional) conditional = ctrl;
  try {
    const begin = await api.post('/auth/passkey/begin', username ? { username } : {}, { handle: false });
    const flowId = begin?.flow_id || begin?.flowId || '';
    const cred = await navigator.credentials.get(toGetOptions(begin?.options || begin, { conditional: isConditional, signal: ctrl.signal }));
    if (!cred) return;
    const res = await api.post('/auth/passkey/finish', { flow_id: flowId, credential: credentialToJSON(cred), remember: !!rememberInput?.checked }, { handle: false });
    finish(res);
  } catch (err) {
    const name = /** @type {any} */ (err)?.name;
    if (isConditional || name === 'AbortError') return;
    let msg;
    if (name === 'NotAllowedError') msg = 'The passkey request was cancelled or timed out.';
    else if (name === 'SecurityError') msg = 'Passkeys need a trusted certificate and the server’s own name in the address bar.';
    else if (err instanceof ApiError && err.status === 429) msg = rateLimitMessage(err, 'sign-in attempts');
    // The server answers every refused passkey sign-in alike (an unknown passkey, a disabled or temporarily locked
    // account; DESIGN §9.3 "responses are uniform"), so do not guess which one it was.
    else if (err instanceof ApiError && (err.status === 401 || err.status === 403 || err.status === 422)) {
      msg = 'Signing in with this passkey didn’t work. Try again or use your password. If it keeps failing, the passkey may have been removed or the account may be locked for a while after failed sign-ins — ask an administrator.';
    }
    else msg = errorMessage(err);
    const box = alertBox('danger', msg);
    if (statusEl) replace(statusEl, box);
    else {
      const card = document.querySelector('#fp-root .auth-card');
      card?.querySelector(':scope > .alert')?.remove();
      card?.querySelector('.auth-card-head')?.after(box);
    }
  }
}

async function startConditionalPasskey() {
  if (!(await conditionalMediationAvailable())) return;
  passkeyLogin('', true);
}
