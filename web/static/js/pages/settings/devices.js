// @ts-check
/**
 * Settings → Devices & app (/settings/devices): is this device trusting the server's certificate, install the web app
 * (PWA; needs a trusted certificate), open FileParcel on another device (access URLs + QR), and self-service mTLS
 * client certificates when the administrator allows them (§10.4, §13.7).
 *   GET  /network/urls        → AccessURL[]
 *   GET  /me/client-certs     → ClientCert[] (or a page)
 *   POST /me/client-certs     ClientCertInput {name, days, password, legacy} → PKCS#12 (once; only if mtls.self_service)
 *   DELETE /me/client-certs/{id}  revoke one of your own certificates (lost device)
 * Owned by unit J2.
 * @module pages/settings/devices
 */
import { h, icon, boot, replace, append } from '../../core/dom.js';
import { api, ApiError, itemsOf, errorMessage } from '../../core/api.js';
import { card } from '../../components/card.js';
import { button } from '../../components/button.js';
import { badge } from '../../components/badge.js';
import { toast } from '../../components/toast.js';
import { confirm } from '../../components/dialog.js';
import { select, field, toggle } from '../../components/field.js';
import { qrImage, qrURL } from '../../components/qr-image.js';
import { copyField } from '../../components/copy-field.js';
import { skeleton } from '../../components/progress.js';
import { passkeysAvailable } from '../../core/webauthn.js';
import { settingsHeader } from './common.js';
import { alertEl, errorPanel, timeEl, expiryBadge, formDialog, issueClientCert, showP12Password } from '../admin/common.js';
import { generatePassword } from '../../public/password-strength.js';

export const title = 'Devices & app';

/** Deferred `beforeinstallprompt` event (Chromium) — captured while this page is open. @type {any} */
let installEvent = null;

/**
 * @param {HTMLElement} root
 * @param {import('../../core/router.js').PageContext} ctx
 */
export async function mount(root, ctx) {
  const b = boot();
  settingsHeader(root, { id: 'settings-devices', title, subtitle: 'Trust this server on your devices, install the app and connect from your phone.' });

  const trustBody = h('div', { class: 'stack' }, skeleton(2));
  const appBody = h('div', { class: 'stack' });
  const urlsBody = h('div', { class: 'stack' }, skeleton(3));
  const certsCard = h('div');
  append(root, h('div', { class: 'settings-grid' },
    h('div', { class: 'stack' },
      card({ title: 'This device', body: trustBody }),
      card({ title: 'Install the app', body: appBody })),
    h('div', { class: 'stack' },
      card({ title: 'Open on another device', body: urlsBody }),
      certsCard)));

  // ------------------------------------------------------------------------------ certificate trust (heuristic)
  const drawTrust = async () => {
    const https = location.protocol === 'https:';
    /** @type {'trusted' | 'untrusted' | 'unknown'} */
    let trust = 'unknown';
    if (!https) trust = 'untrusted';
    else if ('serviceWorker' in navigator && window.isSecureContext) {
      // browsers refuse to register service workers on pages with certificate errors
      try {
        const reg = await navigator.serviceWorker.getRegistration('/');
        trust = reg ? 'trusted' : 'unknown';
      } catch {
        trust = 'unknown';
      }
    }
    const passkeys = b.features.passkeys !== false && passkeysAvailable(b.rp_id);
    replace(trustBody, 
      h('div', { class: 'status-line' },
        h('span', { class: 'status-dot', dataset: { state: trust === 'trusted' ? null : trust === 'untrusted' ? 'danger' : 'warning' } }),
        h('strong', { text: trust === 'trusted' ? 'Certificate trusted' : trust === 'untrusted' ? 'Not a secure connection' : 'Certificate may not be trusted' })),
      h('p', { class: 'muted text-sm', text: trust === 'trusted'
        ? 'This browser accepts the server’s certificate, so the app, offline shell and passkeys can work.'
        : trust === 'untrusted'
          ? 'This page is not served over HTTPS. Open FileParcel with https:// to protect your files in transit.'
          : 'If your browser shows a warning when you open FileParcel, install the server’s certificate authority on this device. It takes a minute and removes the warnings for good.' }),
      h('ul', { class: 'check-list', attrs: { role: 'list' } },
        checkItem(https, 'Encrypted connection (HTTPS)'),
        checkItem(trust === 'trusted', 'Certificate trusted (needed for the app and offline mode)', trust === 'unknown'),
        checkItem(passkeys, `Passkeys available at this address${b.rp_id ? ` (${b.rp_id})` : ''}`, !passkeys && location.hostname !== b.rp_id)),
      h('div', { class: 'btn-row btn-row--start' },
        h('a', { class: `btn ${trust === 'trusted' ? 'btn--secondary' : 'btn--primary'}`, href: '/trust', attrs: { 'data-native': true } }, icon('shield-check'), h('span', { text: 'Certificate setup guide' }))));
  };

  // ------------------------------------------------------------------------------ PWA install
  const standalone = window.matchMedia('(display-mode: standalone)').matches || /** @type {any} */ (navigator).standalone === true;
  const drawApp = () => {
    if (standalone) {
      replace(appBody, alertEl('success', 'You are using the installed app', 'FileParcel runs in its own window with an icon on your home screen or dock.'));
      return;
    }
    const ua = navigator.userAgent;
    const ios = /iPhone|iPad|iPod/.test(ua) || (/Macintosh/.test(ua) && navigator.maxTouchPoints > 1);
    const android = /Android/.test(ua);
    const firefox = /Firefox\//.test(ua);
    const safari = /Safari\//.test(ua) && !/Chrome\/|Chromium\/|Edg\//.test(ua);
    /** @type {string} */
    let how;
    if (ios) how = 'In Safari, tap the Share button, then “Add to Home Screen”.';
    else if (android) how = 'In Chrome, open the ⋮ menu and choose “Install app” (or “Add to Home screen”).';
    else if (firefox) how = 'Firefox on desktop cannot install web apps. Use Chrome, Edge or Safari, or pin the tab.';
    else if (safari) how = 'In Safari on macOS, choose File → Add to Dock.';
    else how = 'Click the install icon at the end of the address bar, or use the browser menu → “Install FileParcel”.';
    replace(appBody, 
      h('p', { class: 'muted text-sm', text: 'Install FileParcel as an app for a full-screen window, a home-screen icon and “Share to FileParcel” from other apps on your phone.' }),
      installEvent
        ? h('div', { class: 'btn-row btn-row--start' }, button({
          label: 'Install app',
          icon: 'download',
          variant: 'primary',
          onClick: async () => {
            const ev = installEvent;
            installEvent = null;
            try {
              ev.prompt();
              const choice = await ev.userChoice;
              if (choice?.outcome === 'accepted') toast.success('FileParcel is being installed');
            } catch { /* prompt can only be used once */ }
            drawApp();
          },
        }))
        : h('p', { class: 'text-sm' }, h('strong', { text: 'How: ' }), how),
      location.protocol !== 'https:' ? alertEl('warning', 'Needs a trusted certificate', 'Browsers only install web apps from servers with a trusted HTTPS certificate.') : null);
  };
  /** @param {Event} e */
  const onInstallable = (e) => {
    e.preventDefault();
    installEvent = e;
    drawApp();
  };
  const onInstalled = () => {
    installEvent = null;
    toast.success('FileParcel was installed');
    drawApp();
  };
  window.addEventListener('beforeinstallprompt', onInstallable);
  window.addEventListener('appinstalled', onInstalled);

  // ------------------------------------------------------------------------------ access URLs + QR
  const drawUrls = async () => {
    /** @type {any[]} */
    let urls = [];
    try {
      urls = itemsOf(await api.get('/network/urls', { signal: ctx.signal }));
    } catch (err) {
      if (err instanceof ApiError && err.aborted) return;
      urls = [];
    }
    if (!urls.length) urls = [{ url: `${location.origin}/`, label: 'This address', kind: 'current', recommended: true }];
    const sorted = [...urls].sort((a, b) => Number(!!b.recommended) - Number(!!a.recommended) || Number(!!b.trusted) - Number(!!a.trusted));
    let current = sorted[0];
    const qrSlot = h('div', { class: 'device-qr' });
    const drawQR = () => {
      const target = String(current.url || '');
      replace(qrSlot, 
        target.length <= 512 ? qrImage({ src: qrURL(target), alt: `QR code for ${target}`, size: 180 }) : null,
        copyField({ label: 'Address', value: target, hideLabel: true, what: 'Address' }));
    };
    const picker = select({
      label: 'Address to open',
      options: sorted.map((u, i) => ({ value: String(i), label: `${u.label || u.kind || 'Address'} — ${u.url}` })),
      value: '0',
      onChange: (v) => {
        current = sorted[Number(v)] || sorted[0];
        drawQR();
      },
    });
    drawQR();
    replace(urlsBody, 
      h('p', { class: 'muted text-sm', text: 'Scan the code with your phone’s camera to open FileParcel there. Names ending in .local work on the same Wi-Fi; VPN addresses work from anywhere on your VPN.' }),
      sorted.length > 1 ? picker.el : null,
      qrSlot,
      h('p', { class: 'subtle text-xs' }, 'New device? Set up the certificate first: ', h('a', { href: '/trust', attrs: { 'data-native': true }, text: 'certificate guide' }), '.'));
  };

  // ------------------------------------------------------------------------------ client certificates (mTLS)
  const drawCerts = async () => {
    /** @type {any[]} */
    let certs;
    try {
      certs = itemsOf(await api.get('/me/client-certs', { signal: ctx.signal, handle: false }));
    } catch (err) {
      if (err instanceof ApiError && err.aborted) return;
      // 403/404: client certificates are not offered to this account
      if (err instanceof ApiError && (err.status === 403 || err.status === 404 || err.status === 501)) {
        replace(certsCard);
        return;
      }
      replace(certsCard, card({ title: 'Client certificates', body: errorPanel(err, drawCerts) }));
      return;
    }
    // mtls.self_service is exposed through the page boot features (GET /me does not carry it)
    const selfService = !!(/** @type {any} */ (b.features).mtls_self_service || /** @type {any} */ (ctx.me)?.features?.mtls_self_service);
    const live = certs.filter((c) => !c.revoked_at);
    if (!live.length && !selfService) {
      replace(certsCard);
      return;
    }
    replace(certsCard, card({
      title: 'Client certificates',
      body: h('div', { class: 'stack' },
        h('p', { class: 'muted text-sm', text: 'A client certificate proves that a device belongs to you before the connection is even accepted. Your administrator may require one.' }),
        live.length
          ? h('ul', { class: 'item-list', attrs: { role: 'list' } }, live.map((c) => h('li', { class: 'item-row' },
            h('span', { class: 'item-row-icon', attrs: { 'aria-hidden': 'true' } }, icon('certificate')),
            h('div', { class: 'item-row-main' },
              h('span', { class: 'item-row-title' }, c.name || 'Certificate', expiryBadge(c.not_after)),
              h('span', { class: 'item-row-sub' }, 'Issued ', timeEl(c.issued_at), c.last_seen_at ? [' · last used ', timeEl(c.last_seen_at)] : ' · not used yet'),
              h('span', { class: 'item-row-sub mono text-xs break', text: `Serial ${c.serial}` })),
            button({ label: 'Revoke', size: 'sm', variant: 'secondary', onClick: () => revoke(c) }))))
          : h('p', { class: 'text-sm', text: 'You have no client certificates.' }),
        selfService ? h('div', { class: 'btn-row btn-row--start' }, button({ label: 'Get a certificate for this device', icon: 'plus', onClick: issue })) : null,
        h('p', { class: 'subtle text-xs', text: 'Lost a device? Revoke its certificate here so it can no longer connect.' })),
    }));
  };

  /** @param {any} c */
  const revoke = async (c) => {
    const ok = await confirm({
      title: `Revoke “${c.name || 'certificate'}”?`,
      message: 'The device that uses it can no longer connect with it. This cannot be undone — you can create a new certificate later.',
      confirmLabel: 'Revoke',
      danger: true,
    });
    if (!ok) return;
    try {
      await api.del(`/me/client-certs/${encodeURIComponent(c.id)}`);
      toast.success('Certificate revoked');
      drawCerts();
    } catch (err) {
      toast.error(err);
    }
  };

  const issue = async () => {
    const name = field({ label: 'Device name', name: 'name', required: true, maxlength: 64, value: guessDevice(), help: 'Shown in the certificate list.' });
    const days = select({
      label: 'Valid for',
      name: 'days',
      value: '365',
      // self-service certificates are valid for at most 365 days (server rule)
      options: [{ value: '90', label: '3 months' }, { value: '180', label: '6 months' }, { value: '365', label: '1 year' }],
    });
    const legacy = toggle({ label: 'Compatibility mode', name: 'legacy', help: 'Use older encryption for the file so that old Android and macOS versions can import it.' });
    const r = await formDialog({
      title: 'New client certificate',
      intro: 'A .p12 file is downloaded once. Import it on the device that should be allowed to connect.',
      fields: [name, days, legacy],
      submitLabel: 'Create and download',
      submitIcon: 'download',
      onSubmit: async (v) => {
        const password = generatePassword(16);
        return issueClientCert('/me/client-certs', { name: String(v.name).trim(), days: Number(v.days) || 365, password, legacy: !!v.legacy });
      },
    });
    if (!r || r === true) return;
    await showP12Password(r);
    drawCerts();
  };

  drawTrust();
  drawApp();
  drawUrls();
  drawCerts().catch((err) => toast.error(errorMessage(err)));

  return () => {
    window.removeEventListener('beforeinstallprompt', onInstallable);
    window.removeEventListener('appinstalled', onInstalled);
  };
}

/**
 * @param {boolean} ok
 * @param {string} text
 * @param {boolean} [unknown]
 */
function checkItem(ok, text, unknown = false) {
  return h('li', { class: 'check-item', dataset: { state: ok ? 'ok' : unknown ? 'unknown' : 'no' } },
    icon(ok ? 'check-circle' : unknown ? 'help' : 'x-circle'),
    h('span', { text }),
    ok ? null : unknown ? badge({ text: 'unknown', kind: 'neutral' }) : null);
}

/** Best-effort device name for a new certificate. */
function guessDevice() {
  const ua = navigator.userAgent;
  if (/iPhone/.test(ua)) return 'iPhone';
  if (/iPad/.test(ua)) return 'iPad';
  if (/Android/.test(ua)) return 'Android phone';
  if (/Windows/.test(ua)) return 'Windows PC';
  if (/Macintosh/.test(ua)) return 'Mac';
  if (/Linux/.test(ua)) return 'Linux computer';
  return 'My device';
}
