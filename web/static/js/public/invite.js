// @ts-check
/**
 * /invite/{token} — accept an invitation and create an account.
 *   GET  /auth/invite/{token}                → invite details (role, role_id, role_name, email, expires_at, note,
 *                                              invited_by, …) or 404
 *   POST /auth/invite/{token}/accept {username, password, display_name, email}
 *        → LoginResult (the new user is signed in; may carry csrf / enroll_required) or the created User.
 * When no session results, the user is sent to /login with the username prefilled.
 * Owned by unit J2.
 * @module public/invite
 */
import { h, boot, append } from '../core/dom.js';
import { api, setCsrf, ApiError } from '../core/api.js';
import { field } from '../components/field.js';
import { form } from '../components/form.js';
import { date, relTime } from '../core/format.js';
import { publicRoot, authCard, alertBox, instanceName, initAppearance, rateLimitMessage } from './common.js';
import { strengthMeter, estimate } from './password-strength.js';

initAppearance();
const b = boot();
const token = String(b.data.token || safeDecode(location.pathname.split('/')[2] || ''));
main();

/** @param {string} s */
function safeDecode(s) {
  try { return decodeURIComponent(s); } catch { return s; }
}

/** @type {Record<string, string>} */
const ROLE_TEXT = {
  admin: 'an administrator',
  member: 'a member',
  guest: 'a guest (you can open what others share with you)',
};

/**
 * What the invitation makes the new account: a custom role by its name ("Helpdesk"; `role` is its base), a
 * built-in role in words.
 * @param {any} invite core.Invite
 */
function roleText(invite) {
  const name = String(invite.role_name || '');
  if (String(invite.role_id || '').startsWith('rol_') && name && name !== 'Deleted role') {
    return invite.role === 'guest' ? `${name} (you can open what others share with you or your role)` : name;
  }
  return ROLE_TEXT[String(invite.role || '')] || '';
}

async function main() {
  const root = publicRoot();
  /** @type {any} */
  let invite = null;
  try {
    const res = await api.get(`/auth/invite/${encodeURIComponent(token)}`, { handle: false });
    invite = res?.invite || res || {};
  } catch (err) {
    const status = err instanceof ApiError ? err.status : 0;
    // A rate limit or a server hiccup says nothing about the invitation itself: offer to check it again.
    const retry = status === 429 || status >= 500 || status === 0;
    append(root, authCard({
      title: retry ? 'Invitation not checked yet' : 'Invitation not available',
      icon: 'mail',
      body: alertBox('warning', status === 429
        ? rateLimitMessage(err, 'requests')
        : retry
          ? 'The server could not check this invitation right now. Please try again in a moment.'
          : 'This invitation link is invalid, was already used, or has expired. Ask the person who invited you for a new one.'),
      footer: [
        retry ? h('button', { class: 'btn btn--primary btn--sm', attrs: { type: 'button' }, text: 'Try again', on: { click: () => location.reload() } }) : null,
        h('a', { href: '/login', attrs: { 'data-native': true }, text: 'Go to sign in' }),
      ],
    }));
    return;
  }
  if (invite.status && invite.status !== 'active') {
    append(root, authCard({
      title: invite.status === 'expired' ? 'This invitation has expired' : 'Invitation not available',
      icon: 'mail',
      body: alertBox('warning', 'Ask the person who invited you for a new link.'),
      footer: [h('a', { href: '/login', attrs: { 'data-native': true }, text: 'Go to sign in' })],
    }));
    return;
  }

  const username = field({
    label: 'Username', name: 'username', autocomplete: 'username', required: true, autofocus: true, maxlength: 64,
    help: 'Letters, numbers, dots, dashes or underscores. You sign in with it.',
    attrs: { autocapitalize: 'off', spellcheck: 'false' },
  });
  const display = field({ label: 'Your name', name: 'display_name', autocomplete: 'name', maxlength: 100, help: 'Shown to people you share files with.' });
  const email = field({ label: 'Email (optional)', name: 'email', type: 'email', autocomplete: 'email', value: invite.email || '', maxlength: 254 });
  const pw = field({ label: 'Password', name: 'password', type: 'password', autocomplete: 'new-password', required: true, minlength: 8, maxlength: 1024 });
  const meter = strengthMeter(/** @type {HTMLInputElement} */ (pw.input), { userInputs: () => [username.input.value, display.input.value, email.input.value || invite.email || ''] });
  append(pw.el, meter.el);
  const pw2 = field({ label: 'Repeat password', name: 'confirm', type: 'password', autocomplete: 'new-password', required: true });

  const f = form({
    fields: [username, display, email, pw, pw2],
    submitLabel: 'Create account',
    submitIcon: 'user-plus',
    stretchActions: true,
    onSubmit: async (v) => {
      const name = String(v.username).trim();
      if (v.password !== v.confirm) throw new ApiError(422, 'invalid', 'The passwords do not match.', 'confirm');
      const est = estimate(v.password, { userInputs: [name, v.display_name, v.email || invite.email || ''] });
      if (est.score < 2) throw new ApiError(422, 'invalid', est.warning || 'Please choose a stronger password.', 'password');
      /** @type {any} */
      let res;
      try {
        res = await api.post(`/auth/invite/${encodeURIComponent(token)}/accept`, {
          username: name,
          password: v.password,
          display_name: String(v.display_name).trim(),
          email: String(v.email).trim(),
        }, { handle: false });
      } catch (err) {
        if (err instanceof ApiError && err.status === 409) throw new ApiError(409, err.code, err.message && err.message !== 'conflict' ? err.message : 'That username or email is already taken.', err.field || 'username');
        if (err instanceof ApiError && err.status === 429) throw new ApiError(429, err.code, rateLimitMessage(err, 'attempts'));
        if (err instanceof ApiError && err.status === 404) throw new ApiError(404, err.code, 'This invitation is no longer valid.');
        throw err;
      }
      if (res && typeof res.csrf === 'string') setCsrf(res.csrf);
      try {
        const me = await api.get('/me', { handle: false });
        if (me?.mfa?.enroll_required || res?.enroll_required) location.assign('/settings/security?enroll=1');
        else location.assign((me?.user?.role || res?.user?.role || invite.role) === 'guest' ? '/shared' : '/files');
      } catch {
        location.assign(`/login?username=${encodeURIComponent(name)}`);
      }
    },
  });

  const who = String(invite.invited_by || ''); // the creator's display name ('' for invites made from the CLI)
  const role = roleText(invite);
  const details = h('ul', { class: 'invite-facts', attrs: { role: 'list' } },
    role ? h('li', null, 'You will join as ', h('strong', { text: role })) : null,
    who ? h('li', null, 'Invited by ', h('strong', { text: who })) : null,
    invite.expires_at ? h('li', { title: date(invite.expires_at) }, `This link expires ${relTime(invite.expires_at)}.`) : null);

  append(root, authCard({
    title: `Join ${instanceName()}`,
    subtitle: 'Create your account to start sharing files.',
    body: [details.childElementCount ? details : null, invite.note ? h('div', { class: 'auth-message', text: invite.note }) : null, f.el],
    footer: [h('a', { href: '/login', attrs: { 'data-native': true }, text: 'Already have an account? Sign in' })],
  }));
  username.input.focus();
}
