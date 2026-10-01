// @ts-check
/**
 * promptElevation() → Promise<boolean>
 * Step-up ("sudo mode", §9.3): confirm with the password, an authenticator code or a passkey, then
 * POST /api/v1/auth/elevate with exactly one of (core.ElevateInput):
 *   {password} · {totp} · {passkey: <assertion JSON>, flow_id}
 * The passkey assertion is obtained like a login: POST /auth/passkey/begin {username} → {options, flow_id},
 * navigator.credentials.get(), then the credential goes to /auth/elevate instead of /auth/passkey/finish
 * (flow agreed with unit B through core.ElevateInput.FlowID).
 * Elevation rotates the session (§9.3), so the CSRF token is refreshed afterwards: from the response's `csrf`, or
 * else from GET /me.
 * Concurrent callers share one dialog. core/api.js calls this automatically on 403 elevation_required and retries
 * the request once.
 * @module components/elevation
 */
import { h, boot } from '../core/dom.js';
import { api, setCsrf, ApiError } from '../core/api.js';
import { session } from '../core/store.js';
import { passkeysAvailable, toGetOptions, credentialToJSON } from '../core/webauthn.js';
import { dialog } from './dialog.js';
import { field } from './field.js';
import { tabs } from './tabs.js';
import { button } from './button.js';

/** @type {Promise<boolean> | null} */
let pending = null;

/**
 * Refresh the CSRF token after the session rotated.
 * @param {any} res elevate response
 */
async function refreshCsrf(res) {
  if (res && typeof res.csrf === 'string' && res.csrf) {
    setCsrf(res.csrf);
    return;
  }
  try {
    const me = await api.get('/me', { handle: false });
    if (me && typeof me.csrf === 'string') setCsrf(me.csrf);
  } catch { /* keep the old token; the retried request reports any problem */ }
}

/** @returns {Promise<boolean>} */
export function promptElevation() {
  if (pending) return pending;
  pending = new Promise((resolve) => {
    const me = session.peek();
    const mfa = /** @type {any} */ (me?.mfa);
    const b = boot();
    const hasTotp = !!(mfa && (mfa.totp === true || mfa.totp_enabled === true || (typeof mfa.totp === 'object' && mfa.totp?.enabled)));
    const hasPasskey = !!(mfa && Number(mfa.passkey_count) > 0) && b.features.passkeys !== false && passkeysAvailable(b.rp_id);
    let method = 'password';

    const pw = field({ label: 'Password', name: 'password', type: 'password', autocomplete: 'current-password', required: true });
    const code = field({ label: 'Authenticator code', name: 'totp', type: 'text', inputmode: 'numeric', autocomplete: 'one-time-code', code: true, maxlength: 10, placeholder: '123 456' });
    const errBox = h('p', { class: 'form-error', attrs: { role: 'alert' } });

    /** @type {Promise<boolean> | null} */
    let passkeyRun = null;
    const passkeyBtn = button({ label: 'Use a passkey', icon: 'passkey', variant: 'secondary', block: true, onClick: () => { submit(); } });
    const passkeyPanel = h('div', { class: 'stack-sm' },
      h('p', { class: 'muted', text: 'Confirm with the passkey on this device or your phone.' }),
      passkeyBtn);

    const panel = h('div', { class: 'stack' }, pw.el);
    const panels = { password: pw.el, totp: code.el, passkey: passkeyPanel };

    const items = [{ id: 'password', label: 'Password' }];
    if (hasTotp) items.push({ id: 'totp', label: 'Authenticator app' });
    if (hasPasskey) items.push({ id: 'passkey', label: 'Passkey' });
    const methodTabs = items.length > 1
      ? tabs({
        items,
        active: 'password',
        variant: 'pill',
        label: 'Confirmation method',
        onChange: (id) => {
          method = id;
          errBox.textContent = '';
          panel.replaceChildren(/** @type {any} */ (panels)[id]);
          if (id === 'totp') code.input.focus();
          else if (id === 'password') pw.input.focus();
          else passkeyBtn.focus();
        },
      })
      : null;

    /** @returns {Promise<boolean>} */
    const elevateWithPasskey = async () => {
      const begin = await api.post('/auth/passkey/begin', me?.user?.username ? { username: me.user.username } : {}, { handle: false });
      const flowId = begin?.flow_id || begin?.flowId || '';
      const cred = await navigator.credentials.get(toGetOptions(begin?.options || begin));
      if (!cred) throw new Error('No passkey was selected.');
      const res = await api.post('/auth/elevate', { passkey: credentialToJSON(cred), flow_id: flowId }, { handle: false });
      await refreshCsrf(res);
      return true;
    };

    /** @returns {Promise<boolean>} */
    const submit = async () => {
      errBox.textContent = '';
      if (method === 'passkey') {
        if (passkeyRun) return passkeyRun;
        passkeyRun = (async () => {
          try {
            const ok = await elevateWithPasskey();
            if (ok) d.close(true);
            return ok;
          } catch (err) {
            const name = /** @type {any} */ (err)?.name;
            errBox.textContent = name === 'NotAllowedError' || name === 'AbortError'
              ? 'The passkey request was cancelled or timed out.'
              : err instanceof ApiError && (err.status === 401 || err.status === 403 || err.status === 422)
                ? 'That passkey could not be verified.'
                : err instanceof Error ? err.message : String(err);
            return false;
          } finally {
            passkeyRun = null;
          }
        })();
        return passkeyRun;
      }
      const body = method === 'totp' ? { totp: String(code.value()).replace(/\s+/g, '') } : { password: String(pw.value()) };
      const empty = method === 'totp' ? !body.totp : !body.password;
      if (empty) {
        (method === 'totp' ? code : pw).setError('Required');
        return false;
      }
      try {
        const res = await api.post('/auth/elevate', body, { handle: false });
        await refreshCsrf(res);
        return true;
      } catch (err) {
        const msg = err instanceof ApiError && (err.status === 401 || err.status === 403 || err.status === 422)
          ? (method === 'totp' ? 'That code is not valid.' : 'That password is not correct.')
          : err instanceof Error ? err.message : String(err);
        errBox.textContent = msg;
        (method === 'totp' ? code.input : pw.input).select();
        return false;
      }
    };

    const formEl = h('form', { class: 'stack', attrs: { novalidate: true } },
      h('p', { class: 'muted', text: 'For your security, please confirm it’s you before continuing.' }),
      methodTabs ? methodTabs.el : null,
      panel,
      errBox);
    formEl.addEventListener('submit', async (e) => {
      e.preventDefault();
      if (method === 'passkey') {
        await submit(); // closes the dialog itself on success
        return;
      }
      if (await submit()) d.close(true);
    });

    const d = dialog({
      title: 'Confirm your identity',
      body: formEl,
      size: 'sm',
      onClose: (v) => {
        pending = null;
        resolve(v === true);
      },
      actions: [
        { label: 'Cancel', variant: 'ghost', value: false },
        {
          label: 'Confirm',
          variant: 'primary',
          icon: 'shield-check',
          onClick: async () => {
            if (method === 'passkey') {
              await submit();
              return false; // submit() closed the dialog on success
            }
            return (await submit()) ? true : false;
          },
        },
      ],
    });
    d.open();
    pw.input.focus();
  });
  return pending;
}
