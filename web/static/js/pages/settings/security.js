// @ts-check
/**
 * Settings → Security (/settings/security[?must_change=1|?enroll=1]).
 * Password (forced change after an admin reset / generated install password), two-factor authentication with an
 * authenticator app (TOTP: QR + manual key + confirm → recovery codes shown once), recovery-code regeneration,
 * passkeys (add / rename / delete) and the "2FA required" enrollment flow (§9.3 auth.require_2fa).
 *
 * API (meapi, §9.4):
 *   GET    /me/mfa                     → MFAStatus {totp_enabled, totp_pending, recovery_codes_left, passkey_count, required, enroll_required}
 *   POST   /me/totp/begin              (E) → TOTPEnrollment {secret, otpauth_uri, qr_data_uri}
 *   POST   /me/totp/confirm {code}     (E) → RecoveryCodes {recovery_codes} (empty when unused codes already exist)
 *   DELETE /me/totp                    (E)
 *   POST   /me/recovery-codes          (E) → RecoveryCodes
 *   GET    /me/passkeys                → Passkey[]
 *   POST   /me/passkeys/begin          (E) → PasskeyBegin {options, flow_id}
 *   POST   /me/passkeys/finish {flow_id, credential, name} (E) → Passkey
 *   PATCH  /me/passkeys/{id} {name} · DELETE /me/passkeys/{id} (E)
 * Elevation (E) is prompted by core/api.js automatically; adding a passkey steps up first (ensureElevated), so that no
 * dialog and fewer round trips sit between the last click and navigator.credentials.create().
 * Owned by unit J2.
 * @module pages/settings/security
 */
import { h, icon, boot, replace, append } from '../../core/dom.js';
import { api, ApiError, errorMessage, itemsOf } from '../../core/api.js';
import { navigate } from '../../core/router.js';
import { session } from '../../core/store.js';
import { card } from '../../components/card.js';
import { form } from '../../components/form.js';
import { field } from '../../components/field.js';
import { button } from '../../components/button.js';
import { badge } from '../../components/badge.js';
import { qrImage } from '../../components/qr-image.js';
import { copyField } from '../../components/copy-field.js';
import { toast } from '../../components/toast.js';
import { skeleton } from '../../components/progress.js';
import { confirm, prompt } from '../../components/dialog.js';
import { passkeysAvailable, toCreateOptions, credentialToJSON } from '../../core/webauthn.js';
import { settingsHeader, refreshMe, passwordForm } from './common.js';
import { alertEl, errorPanel, showSecretOnce, timeEl, describeUA, moreMenu, ensureElevated } from '../admin/common.js';

export const title = 'Security';

/**
 * @typedef {Object} MFAStatus
 * @property {boolean} [totp_enabled]
 * @property {boolean} [totp_pending]
 * @property {number} [recovery_codes_left]
 * @property {number} [passkey_count]
 * @property {boolean} [required]
 * @property {boolean} [enroll_required]
 * @property {boolean} [funnel_required] over Tailscale Funnel, where only accounts with a second factor get in
 */

/**
 * @param {HTMLElement} root
 * @param {import('../../core/router.js').PageContext} ctx
 */
export async function mount(root, ctx) {
  const b = boot();
  const initialMe = /** @type {any} */ (session.peek());
  let mustChange = ctx.query.must_change === '1' || !!initialMe?.user?.must_change_password;
  settingsHeader(root, { id: 'settings-security', title, subtitle: 'Password, two-factor authentication and passkeys.' });

  const banners = h('div', { class: 'stack-sm settings-banners' });
  const passwordSlot = h('div', { class: 'settings-slot' });
  const overviewSlot = h('div', { class: 'settings-slot' });
  const totpBody = h('div', { class: 'stack' }, skeleton(3));
  const recoveryBody = h('div', { class: 'stack' }, skeleton(2));
  const passkeyBody = h('div', { class: 'stack' }, skeleton(3));
  const totpCard = card({ title: 'Authenticator app', body: totpBody });
  const recoveryCard = card({ title: 'Recovery codes', body: recoveryBody });
  const passkeyCard = card({ title: 'Passkeys', body: passkeyBody });
  append(root, banners, passwordSlot, overviewSlot, h('div', { class: 'settings-grid' },
    h('div', { class: 'stack' }, totpCard, recoveryCard),
    h('div', { class: 'stack' }, passkeyCard)));

  /** @type {MFAStatus} */
  let mfa = {};
  /** @type {any[]} */
  let passkeys = [];
  let enrollingTotp = false;

  const rpId = b.rp_id;
  const passkeysOn = b.features.passkeys !== false && /** @type {any} */ (initialMe)?.features?.passkeys !== false;
  const canUsePasskeys = passkeysOn && passkeysAvailable(rpId);

  // ------------------------------------------------------------------------------------------ password
  const drawPassword = () => {
    if (mustChange) {
      replace(passwordSlot, card({
        title: 'Choose a new password',
        class: 'card--kraft',
        body: h('div', { class: 'stack' },
          alertEl('warning', 'A new password is required', 'Your current password was generated at install time or set by an administrator. Choose one that only you know.'),
          passwordForm({
            autofocus: true,
            onDone: () => {
              mustChange = false;
              drawPassword();
              drawBanners();
            },
          }).el),
      }));
      return;
    }
    const user = /** @type {any} */ (session.peek())?.user || {};
    replace(passwordSlot, h('section', { class: 'card settings-row-card' },
      h('div', { class: 'split' },
        h('div', { class: 'stack-sm gap-1' },
          h('h2', { class: 'card-title', text: 'Password' }),
          h('p', { class: 'muted text-sm' }, user.password_changed_at ? ['Last changed ', timeEl(user.password_changed_at), '. '] : null,
            'Changing it signs you out everywhere else.')),
        h('a', { class: 'btn btn--secondary', href: '/settings/profile#password' }, icon('key'), h('span', { text: 'Change password' })))));
  };

  // ------------------------------------------------------------------------------------------ banners + overview
  const drawBanners = () => {
    const items = [];
    if (mfa.funnel_required && !mfaOn()) {
      // over Tailscale Funnel the requirement is the address's (funnel.require_2fa); passkeys may belong to the home
      // address's name, an authenticator app works everywhere
      items.push(alertEl('warning', 'Two-factor authentication is needed on this address',
        'You are using FileParcel’s internet address, which only lets in accounts with two-factor authentication. Set up an authenticator app below — the rest of FileParcel unlocks as soon as you finish.' +
        (mfa.required ? '' : ' At your home or VPN address everything works without it.')));
    } else if (mfa.enroll_required || (ctx.query.enroll === '1' && !mfaOn())) {
      items.push(alertEl('warning', 'Two-factor authentication is required',
        'Your administrator requires a second sign-in step. Set up an authenticator app or add a passkey below — the rest of FileParcel unlocks as soon as you finish.'));
    } else if (ctx.query.enroll === '1' && mfaOn()) {
      items.push(alertEl('success', 'You are all set', 'Two-factor authentication is on for your account.',
        button({ label: 'Continue to your files', icon: 'arrow-right', size: 'sm', variant: 'primary', onClick: () => navigate('/files') })));
    }
    replace(banners, ...items);
  };

  const mfaOn = () => !!mfa.totp_enabled || Number(mfa.passkey_count) > 0;

  const drawOverview = () => {
    const on = mfaOn();
    replace(overviewSlot, h('div', { class: ['security-summary', on ? 'is-on' : 'is-off'] },
      h('span', { class: 'security-summary-icon', attrs: { 'aria-hidden': 'true' } }, icon(on ? 'shield-check' : 'shield', { size: 28 })),
      h('div', { class: 'stack-sm gap-1' },
        h('strong', { text: on ? 'Two-factor authentication is on' : 'Two-factor authentication is off' }),
        h('span', { class: 'muted text-sm', text: on
          ? `Your sign-in is protected by ${[mfa.totp_enabled ? 'an authenticator app' : '', Number(mfa.passkey_count) > 0 ? `${mfa.passkey_count} passkey${mfa.passkey_count === 1 ? '' : 's'}` : ''].filter(Boolean).join(' and ')}.`
          : 'A stolen password is enough to get into your account. Add an authenticator app or a passkey.' }),
        mfa.required ? h('span', { class: 'subtle text-xs', text: 'Required for your account by the server policy.' }) : null)));
  };

  // ------------------------------------------------------------------------------------------ TOTP
  const drawTotp = () => {
    if (enrollingTotp) return;
    const on = !!mfa.totp_enabled;
    replace(totpBody, 
      h('div', { class: 'cluster' },
        badge({ text: on ? 'On' : 'Off', kind: on ? 'success' : 'neutral', icon: on ? 'check' : undefined }),
        mfa.totp_pending && !on ? badge({ text: 'Setup not finished', kind: 'warning' }) : null),
      h('p', { class: 'muted text-sm', text: on
        ? 'After your password, sign-in asks for the 6-digit code from your authenticator app.'
        : 'Use an app such as 1Password, Bitwarden, Aegis, Google or Microsoft Authenticator to generate sign-in codes — works offline and on every device.' }),
      h('div', { class: 'btn-row btn-row--start' },
        on
          ? button({ label: 'Turn off', icon: 'x', variant: 'ghost', onClick: disableTotp })
          : button({ label: mfa.totp_pending ? 'Continue setup' : 'Set up authenticator app', icon: 'smartphone', variant: 'primary', onClick: startTotp })));
  };

  const startTotp = async () => {
    /** @type {any} */
    let e;
    try {
      e = await api.post('/me/totp/begin', {});
    } catch (err) {
      toast.error(err);
      return;
    }
    enrollingTotp = true;
    const code = field({
      label: 'Code from your app',
      name: 'code',
      inputmode: 'numeric',
      autocomplete: 'one-time-code',
      code: true,
      maxlength: 10,
      required: true,
      placeholder: '123 456',
    });
    const f = form({
      fields: [code],
      submitLabel: 'Verify and turn on',
      submitIcon: 'shield-check',
      cancel: () => {
        enrollingTotp = false;
        drawTotp();
      },
      onSubmit: async (v) => {
        const value = String(v.code).replace(/\s+/g, '');
        if (!/^\d{6,8}$/.test(value)) throw new ApiError(422, 'invalid', 'Enter the 6-digit code shown in your app.', 'code');
        /** @type {any} */
        let res;
        try {
          res = await api.post('/me/totp/confirm', { code: value });
        } catch (err) {
          if (err instanceof ApiError && (err.status === 401 || (err.status === 403 && err.code !== 'elevation_required') || (err.status === 422 && (!err.field || err.field === 'code')))) {
            throw new ApiError(422, 'invalid', 'That code did not match. Check that the time on your phone is correct and try the next code.', 'code');
          }
          throw err;
        }
        enrollingTotp = false;
        const codes = Array.isArray(res) ? res : res?.recovery_codes || [];
        toast.success('Authenticator app connected');
        if (codes.length) await showRecoveryCodes(codes, 'Save your recovery codes');
        await reload();
      },
    });
    code.input.addEventListener('input', () => {
      if (/^\d{6}$/.test(code.input.value.replace(/\s+/g, ''))) f.submit();
    });
    const secret = String(e?.secret || '');
    const grouped = secret.replace(/(.{4})/g, '$1 ').trim();
    replace(totpBody, 
      h('ol', { class: 'setup-steps' },
        h('li', null, h('strong', { text: 'Open your authenticator app' }), h('span', { class: 'muted text-sm', text: 'Any app that supports time-based codes (TOTP) works.' })),
        h('li', null,
          h('strong', { text: 'Scan this QR code' }),
          e?.qr_data_uri ? h('div', { class: 'totp-qr' }, qrImage({ src: e.qr_data_uri, alt: 'QR code to add FileParcel to your authenticator app', size: 200 })) : null,
          e?.otpauth_uri && /^otpauth:\/\//.test(e.otpauth_uri)
            ? h('a', { class: 'btn btn--secondary btn--sm only-sm', href: e.otpauth_uri, attrs: { 'data-native': true } }, icon('external'), h('span', { text: 'Open in authenticator app' }))
            : null,
          secret ? h('details', { class: 'auth-details' },
            h('summary', { text: 'Can’t scan it? Enter the key manually' }),
            h('div', { class: 'stack-sm' },
              copyField({ label: 'Setup key', value: grouped, what: 'Setup key' }),
              h('p', { class: 'text-xs muted', text: 'Type: time-based · 6 digits · 30 seconds' }))) : null),
        h('li', null, h('strong', { text: 'Enter the 6-digit code' }), f.el)));
    code.input.focus();
  };

  const disableTotp = async () => {
    const onlyFactor = !(Number(mfa.passkey_count) > 0);
    const ok = await confirm({
      title: 'Turn off the authenticator app?',
      message: h('div', { class: 'stack-sm' },
        // The server only drops the recovery codes when nothing is left (internal/auth/totp.go dropOrphanRecovery):
        // with a passkey still registered they stay valid, so never tell the user to throw their printed copy away.
        h('p', { text: onlyFactor
          ? 'Sign-in will no longer ask for a code from your app. Your recovery codes stop working too.'
          : `Sign-in will no longer ask for a code from your app. Your recovery codes keep working as a backup for your ${Number(mfa.passkey_count) === 1 ? 'passkey' : 'passkeys'}.` }),
        mfa.required && onlyFactor ? alertEl('warning', 'Two-factor authentication is required', 'You will have to set up a second factor again before you can use FileParcel.') : null),
      confirmLabel: 'Turn off',
      danger: true,
    });
    if (!ok) return;
    try {
      await api.del('/me/totp');
      toast.success('Authenticator app turned off');
      await reload();
    } catch (err) {
      toast.error(err);
    }
  };

  // ------------------------------------------------------------------------------------------ recovery codes
  /**
   * @param {string[]} codes
   * @param {string} heading
   */
  const showRecoveryCodes = (codes, heading) => {
    const user = /** @type {any} */ (session.peek())?.user || {};
    const inst = b.instance || 'FileParcel';
    const text = [
      `${inst} recovery codes for ${user.username || 'your account'}`,
      `Created ${new Date().toISOString()}`,
      '',
      'Each code can be used once instead of an authenticator code.',
      '',
      ...codes,
      '',
    ].join('\n');
    return showSecretOnce({
      title: heading,
      intro: 'If you lose your phone, each of these codes lets you sign in once. Keep them somewhere safe — a password manager or printed on paper.',
      secret: codes.join('\n'),
      label: 'Recovery codes',
      what: 'Recovery codes',
      multiline: true,
      filename: `${inst.toLowerCase().replace(/[^a-z0-9]+/g, '-')}-recovery-codes.txt`,
      fileContent: text,
      warning: 'These codes are shown only once. Any codes you saved before no longer work.',
    });
  };

  const drawRecovery = () => {
    const on = mfaOn();
    const left = Number(mfa.recovery_codes_left) || 0;
    if (!on) {
      replace(recoveryBody, h('p', { class: 'muted text-sm', text: 'You get recovery codes when you turn on two-factor authentication. Each one lets you sign in once if you lose your second factor.' }));
      return;
    }
    replace(recoveryBody, 
      h('div', { class: 'cluster' },
        badge({ text: `${left} left`, kind: left === 0 ? 'danger' : left < 4 ? 'warning' : 'neutral' })),
      left < 4 ? alertEl(left === 0 ? 'danger' : 'warning', left === 0 ? 'No recovery codes left' : 'Running low on recovery codes', 'Create a new set so you can still get in if you lose your second factor.') : null,
      h('p', { class: 'muted text-sm', text: 'Creating new codes replaces all existing ones.' }),
      h('div', { class: 'btn-row btn-row--start' },
        button({
          label: 'Create new recovery codes',
          icon: 'refresh',
          variant: left < 4 ? 'primary' : 'secondary',
          onClick: async () => {
            const ok = await confirm({ title: 'Create new recovery codes?', message: 'Your current recovery codes will stop working immediately.', confirmLabel: 'Create new codes' });
            if (!ok) return;
            try {
              const res = await api.post('/me/recovery-codes', {});
              const codes = Array.isArray(res) ? res : res?.recovery_codes || [];
              if (codes.length) await showRecoveryCodes(codes, 'Your new recovery codes');
              await reload();
            } catch (err) {
              toast.error(err);
            }
          },
        })));
  };

  // ------------------------------------------------------------------------------------------ passkeys
  const drawPasskeys = () => {
    /** @type {any[]} */
    const rows = passkeys;
    const list = rows.length
      ? h('ul', { class: 'item-list', attrs: { role: 'list' } }, rows.map((pk) => {
        const foreign = rpId && pk.rp_id && pk.rp_id !== rpId;
        return h('li', { class: 'item-row' },
          h('span', { class: 'item-row-icon', attrs: { 'aria-hidden': 'true' } }, icon('passkey')),
          h('div', { class: 'item-row-main' },
            h('span', { class: 'item-row-title', text: pk.name || 'Passkey' }),
            h('span', { class: 'item-row-sub' },
              'Added ', timeEl(pk.created_at),
              pk.last_used_at ? [' · last used ', timeEl(pk.last_used_at)] : ' · never used'),
            h('span', { class: 'cluster' },
              pk.backup_state ? badge({ text: 'Synced', kind: 'info', icon: 'refresh', title: 'Backed up by your password manager or platform (e.g. iCloud Keychain, Google Password Manager)' }) : null,
              foreign ? badge({ text: `For ${pk.rp_id}`, kind: 'warning', icon: 'alert-triangle', title: 'This passkey was created for a different server name and does not work with the current one.' }) : null)),
          moreMenu([
            { label: 'Rename', icon: 'edit', onClick: () => renamePasskey(pk) },
            { label: 'Remove', icon: 'trash', danger: true, onClick: () => removePasskey(pk) },
          ], `Actions for ${pk.name || 'passkey'}`));
      }))
      : h('p', { class: 'muted text-sm', text: 'No passkeys yet. A passkey signs you in with your fingerprint, face or device PIN — nothing to type and nothing to phish.' });

    /** @type {Node | null} */
    let adder = null;
    if (!passkeysOn) {
      adder = alertEl('info', 'Passkeys are turned off', 'An administrator disabled passkeys on this server.');
    } else if (!canUsePasskeys) {
      const secure = window.isSecureContext && typeof window.PublicKeyCredential !== 'undefined';
      const target = rpId ? `https://${rpId}${location.port ? `:${location.port}` : ''}/settings/security` : '';
      adder = alertEl('info', 'Passkeys are not available at this address',
        h('span', null,
          !secure
            ? 'Your browser does not support passkeys here — they need a secure connection with a trusted certificate. '
            : `Passkeys are tied to the server name ${rpId || '(not configured)'}, and this page is open at ${location.hostname}. `,
          target ? h('a', { href: target, attrs: { 'data-native': true }, text: `Open ${rpId}` }) : null,
          target ? ' to add one, or ' : '',
          h('a', { href: '/trust', attrs: { 'data-native': true }, text: 'trust this server’s certificate' }),
          ' first.'));
    } else {
      adder = h('div', { class: 'btn-row btn-row--start' }, button({ label: 'Add a passkey', icon: 'plus', variant: rows.length ? 'secondary' : 'primary', onClick: addPasskey }));
    }
    replace(passkeyBody, list, adder);
  };

  const addPasskey = async () => {
    if (!(await ensureElevated(2 * 60_000))) return;
    const name = await prompt({
      title: 'Add a passkey',
      label: 'Name',
      value: describeUA(navigator.userAgent),
      help: 'So you can recognise it later, e.g. “Work laptop” or “iPhone”.',
      confirmLabel: 'Continue',
      validate: (v) => (v.length > 64 ? 'Use at most 64 characters.' : null),
    });
    if (name === null) return;
    try {
      const begin = await api.post('/me/passkeys/begin', {});
      const flowId = begin?.flow_id || '';
      const cred = await navigator.credentials.create(toCreateOptions(begin?.options || begin));
      if (!cred) return;
      const res = await api.post('/me/passkeys/finish', { flow_id: flowId, credential: credentialToJSON(cred), name: name || 'Passkey' });
      toast.success('Passkey added');
      // The FIRST passkey of an account also mints recovery codes (they are
      // the only way back in if auth.passkeys is ever turned off); they are
      // returned once, exactly like POST /me/totp/confirm.
      const codes = res?.recovery_codes || [];
      if (codes.length) await showRecoveryCodes(codes, 'Save your recovery codes');
      await reload();
    } catch (err) {
      const n = /** @type {any} */ (err)?.name;
      if (n === 'NotAllowedError' || n === 'AbortError') toast.info('Passkey setup was cancelled.');
      else if (n === 'InvalidStateError') toast.warning('This device already has a passkey for your account.');
      else if (n === 'SecurityError') toast.error('The browser refused: passkeys need a trusted certificate and the server’s own name in the address bar.');
      else toast.error(errorMessage(err));
    }
  };

  /** @param {any} pk */
  const renamePasskey = async (pk) => {
    const name = await prompt({ title: 'Rename passkey', label: 'Name', value: pk.name || '', confirmLabel: 'Rename', validate: (v) => (v.length > 64 ? 'Use at most 64 characters.' : null) });
    if (!name || name === pk.name) return;
    try {
      await api.patch(`/me/passkeys/${encodeURIComponent(pk.id)}`, { name });
      toast.success('Passkey renamed');
      await reload();
    } catch (err) {
      toast.error(err);
    }
  };

  /** @param {any} pk */
  const removePasskey = async (pk) => {
    const last = passkeys.length === 1 && !mfa.totp_enabled;
    const ok = await confirm({
      title: `Remove “${pk.name || 'Passkey'}”?`,
      message: h('div', { class: 'stack-sm' },
        h('p', { text: 'You will no longer be able to sign in with it. Also delete it from your device or password manager afterwards.' }),
        last && mfa.required ? alertEl('warning', 'This is your only second factor', 'Two-factor authentication is required, so you will have to set up another one.') : null),
      confirmLabel: 'Remove',
      danger: true,
    });
    if (!ok) return;
    try {
      await api.del(`/me/passkeys/${encodeURIComponent(pk.id)}`);
      toast.success('Passkey removed');
      await reload();
    } catch (err) {
      toast.error(err);
    }
  };

  // ------------------------------------------------------------------------------------------ load
  // A failed request leaves its error panel (with Retry) in place of the cards it feeds: drawing them from empty or
  // stale state would claim "two-factor authentication is off" or "no passkeys yet" and hide the failure.
  const reload = async () => {
    /** @type {unknown} */
    let mfaErr = null;
    /** @type {unknown} */
    let pkErr = null;
    try {
      mfa = (await api.get('/me/mfa', { signal: ctx.signal })) || {};
    } catch (err) {
      if (err instanceof ApiError && err.aborted) return;
      mfa = {}; // stale values must not outrank the fresh status from /me below
      mfaErr = err;
    }
    try {
      passkeys = itemsOf(await api.get('/me/passkeys', { signal: ctx.signal }));
    } catch (err) {
      if (err instanceof ApiError && err.aborted) return;
      passkeys = [];
      // pending 2FA enrollment: there are no passkeys yet by definition, so the empty list (with "Add a passkey") is right
      if (!(err instanceof ApiError && err.code === 'mfa_enroll_required')) pkErr = err;
    }
    const me = await refreshMe(ctx.signal);
    if (me?.mfa) {
      mfa = { ...me.mfa, ...mfa };
      mfaErr = null; // GET /me carries the same MFAStatus
    }
    if (ctx.signal.aborted) return;
    drawBanners();
    if (mfaErr) {
      replace(overviewSlot, errorPanel(mfaErr, () => {
        if (!enrollingTotp) replace(totpBody, skeleton(3));
        replace(recoveryBody, skeleton(2));
        reload();
      }, 'Two-factor status is unavailable'));
      if (!enrollingTotp) replace(totpBody);
      replace(recoveryBody);
    } else {
      drawOverview();
      drawTotp();
      drawRecovery();
    }
    if (pkErr) {
      replace(passkeyBody, errorPanel(pkErr, () => {
        replace(passkeyBody, skeleton(3));
        reload();
      }));
    } else {
      drawPasskeys();
    }
    if (ctx.query.enroll === '1' && !mfaErr && !mfaOn() && !mfa.totp_enabled && !enrollingTotp && !mfa.totp_pending && !canUsePasskeys && !started) {
      started = true;
      startTotp();
    }
  };
  let started = false;

  drawPassword();
  await reload();
}
