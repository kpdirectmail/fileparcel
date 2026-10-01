// @ts-check
/**
 * /unlock — the server runs in sealed mode and its keys are locked (§7.2): nothing can be read until someone enters
 * the passphrase or the recovery key (FPRK-…).
 *   GET  /system/status → {state: locked|unlocked|uninitialized, setup_needed, web_unlock: allowed|off|network}
 *   POST /system/unlock {passphrase}   (rate limited; allowed networks per keys.web_unlock = lan|any|off)
 * While web unlock is off, or not allowed from this client's network, the page says so and shows the command for the
 * server instead of asking for a passphrase it would refuse.
 * Owned by unit J2.
 * @module public/unlock
 */
import { h, replace, append } from '../core/dom.js';
import { api, ApiError } from '../core/api.js';
import { field } from '../components/field.js';
import { form } from '../components/form.js';
import { tabs } from '../components/tabs.js';
import { publicRoot, authCard, alertBox, nextPath, instanceName, initAppearance, rateLimitMessage, focusHeading } from './common.js';

initAppearance();
main();

async function main() {
  const root = publicRoot();
  /** @type {any} */
  let st = null;
  try {
    st = await api.get('/system/status', { handle: false });
  } catch { /* show the form anyway */ }
  if (st?.state === 'unlocked') {
    location.replace(nextPath(st.setup_needed ? '/setup' : '/'));
    return;
  }
  if (st?.state === 'uninitialized') {
    append(root, authCard({
      title: 'Not initialised yet',
      icon: 'key',
      body: [
        alertBox('warning', 'This server has no encryption keys yet, so it cannot store files.'),
        h('p', { class: 'muted text-sm' }, 'On the server, run ', h('code', { text: 'fileparcel init --home DIR' }), ' (or reinstall with ', h('code', { text: 'install.sh' }), '), then reload this page.'),
      ],
      footer: [h('button', { class: 'btn btn--secondary btn--sm', attrs: { type: 'button' }, text: 'Reload', on: { click: () => location.reload() } })],
    }));
    return;
  }

  if (st?.web_unlock === 'off' || st?.web_unlock === 'network') {
    append(root, authCard({
      title: `${instanceName()} is locked`,
      icon: 'lock',
      subtitle: 'Files are encrypted at rest and the key is sealed with a passphrase.',
      body: [
        alertBox('info', st.web_unlock === 'off'
          ? 'Unlocking over the web is turned off on this server.'
          : 'Unlocking over the web is only allowed from the local network, and this device is not on it.'),
        h('p', { class: 'muted text-sm' }, 'Someone with access to the server can unlock it there: ', h('code', { text: 'fileparcel keys unlock' }), '.'),
        h('p', { class: 'muted text-sm', text: 'An administrator can change where the server may be unlocked from under Settings → Encryption (keys.web_unlock).' }),
      ],
      footer: [h('button', { class: 'btn btn--secondary btn--sm', attrs: { type: 'button' }, text: 'Reload', on: { click: () => location.reload() } })],
    }));
    focusHeading();
    return;
  }

  let mode = 'passphrase';
  const slot = h('div', { class: 'stack' });
  const t = tabs({
    items: [{ id: 'passphrase', label: 'Passphrase' }, { id: 'recovery', label: 'Recovery key' }],
    active: mode,
    variant: 'pill',
    label: 'Unlock with',
    onChange: (id) => { mode = id; draw(); },
  });

  const draw = () => {
    const isRecovery = mode === 'recovery';
    const input = field({
      label: isRecovery ? 'Recovery key' : 'Passphrase',
      name: 'passphrase',
      type: isRecovery ? 'text' : 'password',
      autocomplete: isRecovery ? 'off' : 'current-password',
      required: true,
      placeholder: isRecovery ? 'FPRK-XXXX-XXXX-…' : undefined,
      help: isRecovery
        ? 'The recovery key was shown once when the server was sealed. Spaces and case do not matter.'
        : 'The passphrase chosen when encryption was sealed. It is never stored on the server.',
      attrs: { spellcheck: 'false', autocapitalize: isRecovery ? 'characters' : 'off' },
    });
    const f = form({
      fields: [input],
      submitLabel: 'Unlock server',
      submitIcon: 'unlock',
      stretchActions: true,
      onSubmit: async (v) => {
        let secret = String(v.passphrase);
        if (isRecovery) secret = secret.toUpperCase().replace(/\s+/g, '');
        try {
          await api.post('/system/unlock', { passphrase: secret }, { handle: false });
        } catch (err) {
          input.input.select();
          if (err instanceof ApiError) {
            if (err.status === 429) throw new ApiError(429, err.code, rateLimitMessage(err, 'unlock attempts'));
            if (err.status === 403) {
              throw new ApiError(403, err.code, 'Unlocking from this network is not allowed. On the server run “fileparcel keys unlock”, or ask an administrator to allow web unlock.');
            }
            if (err.status === 409) {
              // already unlocked (someone else was faster)
              location.assign(nextPath('/'));
              return;
            }
            if (err.status === 401 || err.status === 422 || err.code === 'corrupt') {
              throw new ApiError(err.status, err.code, isRecovery ? 'That recovery key is not correct.' : 'That passphrase is not correct.', 'passphrase');
            }
          }
          throw err;
        }
        replace(slot, alertBox('success', 'Unlocked. Taking you to FileParcel…'));
        location.assign(nextPath('/'));
      },
    });
    replace(slot, f.el);
    input.input.focus();
  };
  draw();

  append(root, authCard({
    title: `${instanceName()} is locked`,
    icon: 'lock',
    subtitle: 'Files are encrypted at rest and the key is sealed with a passphrase.',
    body: [
      h('details', { class: 'auth-details' },
        h('summary', { text: 'Why am I seeing this?' }),
        h('div', { class: 'stack-sm' },
          h('p', { text: 'This server runs in sealed mode: its master key is protected by a passphrase and is not kept on disk in usable form. After every restart somebody who knows the passphrase has to unlock it.' }),
          h('p', { text: 'Until then nobody — including administrators and anyone with access to the disk — can open files, and sign-in is paused.' }),
          h('p', null, 'You can also unlock from a terminal on the server: ', h('code', { text: 'fileparcel keys unlock' }), '.'))),
      t.el,
      slot,
      st === null ? alertBox('warning', 'Could not read the server status. You can still try to unlock.') : null,
    ],
    footer: [h('a', { href: '/trust', attrs: { 'data-native': true }, text: 'Trust this server’s certificate' })],
  }));
  focusHeading();
  /** @type {HTMLElement | null} */ (slot.querySelector('input'))?.focus();
}
