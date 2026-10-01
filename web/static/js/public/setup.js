// @ts-check
/**
 * /setup — first-run owner account. The one-time setup token is printed in the server log / terminal when
 * FileParcel starts without any users (`fileparcel logs` shows it); it may also arrive as ?token=.
 *   POST /auth/setup {setup_token, username, password, email} → LoginResult (signed in; may carry csrf,
 *   enroll_required). Only works while no users exist; otherwise 409/404.
 * Owned by unit J2.
 * @module public/setup
 */
import { h, boot, append } from '../core/dom.js';
import { api, setCsrf, ApiError } from '../core/api.js';
import { field } from '../components/field.js';
import { form } from '../components/form.js';
import { publicRoot, authCard, alertBox, initAppearance, authState, rateLimitMessage } from './common.js';
import { strengthMeter, estimate } from './password-strength.js';

initAppearance();
main();

async function main() {
  const b = boot();
  const state = await authState();
  if (state.keys_state === 'locked') {
    location.replace('/unlock?next=/setup');
    return;
  }
  const root = publicRoot();
  const needed = b.data.setup_needed ?? state.setup_needed;
  if (needed === false) {
    append(root, authCard({
      title: 'Already set up',
      icon: 'check-circle',
      body: alertBox('info', 'This server already has an owner account. Sign in to continue.'),
      footer: [h('a', { class: 'btn btn--primary btn--sm', href: '/login', attrs: { 'data-native': true }, text: 'Go to sign in' })],
    }));
    return;
  }

  const params = new URLSearchParams(location.search);
  const tokenField = field({
    label: 'Setup token',
    name: 'setup_token',
    required: true,
    autocomplete: 'off',
    help: 'Shown in the terminal and the server log when FileParcel starts without any users.',
    value: params.get('token') || '',
    attrs: { spellcheck: 'false', autocapitalize: 'off' },
  });
  if (params.has('token')) {
    // keep the token out of the address bar / history once read
    history.replaceState(null, '', location.pathname);
  }
  const username = field({ label: 'Owner username', name: 'username', autocomplete: 'username', required: true, value: 'admin', maxlength: 64, attrs: { autocapitalize: 'off', spellcheck: 'false' } });
  const email = field({ label: 'Email (optional)', name: 'email', type: 'email', autocomplete: 'email', maxlength: 254, help: 'Used for notifications if you configure email later.' });
  const pw = field({ label: 'Password', name: 'password', type: 'password', autocomplete: 'new-password', required: true, minlength: 8, maxlength: 1024 });
  const meter = strengthMeter(/** @type {HTMLInputElement} */ (pw.input), { userInputs: () => [username.input.value, email.input.value] });
  append(pw.el, meter.el);
  const pw2 = field({ label: 'Repeat password', name: 'confirm', type: 'password', autocomplete: 'new-password', required: true });

  const f = form({
    fields: [tokenField, username, email, pw, pw2],
    submitLabel: 'Create owner account',
    submitIcon: 'check',
    stretchActions: true,
    onSubmit: async (v) => {
      if (v.password !== v.confirm) throw new ApiError(422, 'invalid', 'The passwords do not match.', 'confirm');
      const est = estimate(v.password, { userInputs: [v.username, v.email] });
      if (est.score < 2) throw new ApiError(422, 'invalid', est.warning || 'Please choose a stronger password — this account controls the whole server.', 'password');
      /** @type {Record<string, string>} */
      const body = { setup_token: String(v.setup_token).trim(), username: String(v.username).trim(), password: v.password };
      const mail = String(v.email).trim();
      if (mail) body.email = mail;
      /** @type {any} */
      let res;
      try {
        res = await api.post('/auth/setup', body, { handle: false });
      } catch (err) {
        if (err instanceof ApiError) {
          if (err.status === 429) throw new ApiError(429, err.code, rateLimitMessage(err, 'attempts'));
          if ((err.status === 401 || err.status === 403 || err.status === 422) && (!err.field || err.field === 'setup_token')) {
            throw new ApiError(err.status, err.code, 'That setup token is not valid. Copy it again from the server log.', 'setup_token');
          }
          if (err.status === 409 || err.status === 404) {
            throw new ApiError(err.status, err.code, 'Setup was already completed. Sign in instead.');
          }
        }
        throw err;
      }
      if (res && typeof res.csrf === 'string') setCsrf(res.csrf);
      location.assign(res?.enroll_required ? '/settings/security?enroll=1' : '/admin');
    },
  });

  append(root, authCard({
    title: 'Welcome to FileParcel',
    subtitle: 'Create the owner account for this server. You can invite everyone else afterwards.',
    body: [
      f.el,
      h('details', { class: 'auth-details' },
        h('summary', { text: 'Where do I find the setup token?' }),
        h('div', { class: 'stack-sm' },
          h('p', null, 'It is printed when the server starts without accounts. On the server run ', h('code', { text: 'fileparcel logs -n 200' }), ' and look for “setup token”.'),
          h('p', null, 'Or skip this page and create the owner from a terminal: ', h('code', { text: 'fileparcel user create admin --role owner --generate-password' }), '.'))),
    ],
    footer: [h('a', { href: '/trust', attrs: { 'data-native': true }, text: 'Trust this server on your devices' })],
  }));
  (tokenField.input.value ? username.input : tokenField.input).focus();
}
