// @ts-check
/**
 * /trust — install and trust this server's local certificate authority on each device (§10.4).
 * Downloads (root, public): /trust/ca.crt (DER), /trust/ca.pem, /trust/ca.mobileconfig (iOS/macOS profile).
 * Boot data: {fingerprint} — SHA-256 of the CA certificate for out-of-band verification — and optionally
 * {qr: data URI of a QR code for this page, urls: [AccessURL]} when the server provides them. Signed-in visitors
 * get the QR code from /api/v1/qr.svg.
 * Owned by unit J2.
 * @module public/trust
 */
import { h, icon, boot, replace, append } from '../core/dom.js';
import { tabs } from '../components/tabs.js';
import { copyField } from '../components/copy-field.js';
import { qrImage, qrURL } from '../components/qr-image.js';
import { publicRoot, authCard, alertBox, instanceName, initAppearance } from './common.js';

initAppearance();
const b = boot();

/**
 * @typedef {Object} Platform
 * @property {string} label
 * @property {string} icon
 * @property {string} file
 * @property {string} fileLabel
 * @property {(string | Node)[]} steps
 * @property {string} [note]
 */

/** @param {string} text */
const code = (text) => h('code', { class: 'break', text });

/** @type {Record<string, Platform>} */
const PLATFORMS = {
  ios: {
    label: 'iPhone & iPad',
    icon: 'smartphone',
    file: '/trust/ca.mobileconfig',
    fileLabel: 'Download profile',
    steps: [
      'Open this page in Safari, tap “Download profile” and confirm with “Allow”.',
      'Open the Settings app: tap “Profile Downloaded” near the top (or General → VPN & Device Management), select the FileParcel profile and tap “Install”.',
      'Go to Settings → General → About → Certificate Trust Settings and switch on full trust for the FileParcel CA. Without this step Safari still shows warnings.',
    ],
    note: 'Passkeys and “Add to Home Screen” work once the certificate is trusted.',
  },
  android: {
    label: 'Android',
    icon: 'smartphone',
    file: '/trust/ca.crt',
    fileLabel: 'Download certificate',
    steps: [
      'Tap “Download certificate”. Android does not install it when you open the file — keep going.',
      'Open Settings → Security & privacy → More security settings → Encryption & credentials → Install a certificate → CA certificate (names vary by manufacturer; search Settings for “CA certificate”).',
      'Confirm “Install anyway”, choose the downloaded file and unlock your phone when asked.',
      'Restart Chrome. Firefox for Android needs “Use third party CA certificates” in Settings → About Firefox (tap the logo 5× for the secret settings).',
    ],
  },
  macos: {
    label: 'macOS',
    icon: 'laptop',
    file: '/trust/ca.crt',
    fileLabel: 'Download certificate',
    steps: [
      'Download the certificate and double-click it. Keychain Access opens — add it to the “System” keychain.',
      'In Keychain Access, double-click “FileParcel Local CA”, expand “Trust” and set “When using this certificate” to “Always Trust”.',
      'Close the window and confirm with your password. Safari and Chrome pick it up immediately.',
      h('span', null, 'Terminal alternative: ', code('sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain ca.crt')),
    ],
  },
  windows: {
    label: 'Windows',
    icon: 'monitor',
    file: '/trust/ca.crt',
    fileLabel: 'Download certificate',
    steps: [
      'Download and open the certificate, then click “Install Certificate…”.',
      'Choose “Local Machine” (or “Current User”), then “Place all certificates in the following store” → Browse → “Trusted Root Certification Authorities”.',
      'Finish the wizard and confirm the security warning. Restart Edge or Chrome.',
      h('span', null, 'Administrator terminal alternative: ', code('certutil -addstore -f Root ca.crt')),
    ],
  },
  linux: {
    label: 'Linux',
    icon: 'terminal',
    file: '/trust/ca.pem',
    fileLabel: 'Download PEM',
    steps: [
      h('span', null, 'Debian / Ubuntu (system tools like curl): ', code('sudo cp ca.pem /usr/local/share/ca-certificates/fileparcel.crt && sudo update-ca-certificates')),
      h('span', null, 'Fedora / RHEL / Arch: ', code('sudo trust anchor --store ca.pem')),
      h('span', null, 'Chrome, Chromium, Brave and Edge use their own store: ', code('certutil -d sql:$HOME/.pki/nssdb -A -t "C,," -n FileParcel -i ca.pem'), ' (package libnss3-tools / nss-tools).'),
      'Firefox has its own store as well — see the Firefox tab.',
    ],
  },
  firefox: {
    label: 'Firefox',
    icon: 'globe',
    file: '/trust/ca.crt',
    fileLabel: 'Download certificate',
    steps: [
      'Download the certificate.',
      'Open Settings → Privacy & Security → Certificates → View Certificates… → Authorities → Import…',
      'Pick the downloaded file, tick “Trust this CA to identify websites” and confirm.',
      h('span', null, 'On Windows and macOS you can instead let Firefox use the system store: set ', code('security.enterprise_roots.enabled'), ' to true in about:config.'),
    ],
  },
};

/** Best guess of the visitor's platform. */
function detect() {
  const ua = navigator.userAgent;
  if (/iPhone|iPad|iPod/.test(ua) || (/Macintosh/.test(ua) && navigator.maxTouchPoints > 1)) return 'ios';
  if (/Android/.test(ua)) return 'android';
  if (/Firefox\//.test(ua)) return 'firefox';
  if (/Mac OS X|Macintosh/.test(ua)) return 'macos';
  if (/Windows/.test(ua)) return 'windows';
  return 'linux';
}

/** URL a phone should open: this page, or the recommended access URL when browsing via localhost. */
function phoneURL() {
  const local = /^(localhost|127\.|\[?::1\]?$)/.test(location.hostname);
  if (local && Array.isArray(b.data.urls)) {
    const pick = b.data.urls.find((/** @type {any} */ u) => u && u.recommended && u.kind !== 'ip') || b.data.urls.find((/** @type {any} */ u) => u && u.recommended) || b.data.urls[0];
    if (pick && typeof pick.url === 'string') return new URL('/trust', pick.url).href;
  }
  return `${location.origin}/trust`;
}

const root = publicRoot();
let current = detect();
const panelId = 'trust-panel';
const panel = h('div', { class: 'stack', id: panelId, attrs: { role: 'tabpanel', tabindex: '0' } });

const draw = () => {
  const p = PLATFORMS[current];
  panel.setAttribute('aria-label', `${p.label} instructions`);
  replace(panel, 
    h('ol', { class: 'trust-steps' }, p.steps.map((s) => h('li', null, s))),
    p.note ? h('p', { class: 'muted text-sm', text: p.note }) : null,
    h('div', { class: 'btn-row btn-row--start' },
      h('a', { class: 'btn btn--primary', href: p.file, attrs: { download: '', 'data-native': true } }, icon('download'), h('span', { text: p.fileLabel }))));
};

const t = tabs({
  items: Object.entries(PLATFORMS).map(([id, p]) => ({ id, label: p.label, panelId })),
  active: current,
  onChange: (id) => { current = id; draw(); },
  label: 'Your device',
});
draw();

const fp = typeof b.data.fingerprint === 'string' ? b.data.fingerprint : '';
const target = phoneURL();
/** @type {string} */
let qrSrc = '';
if (typeof b.data.qr === 'string' && b.data.qr.startsWith('data:image/')) qrSrc = b.data.qr;
else if (typeof b.data.qr_data_uri === 'string' && b.data.qr_data_uri.startsWith('data:image/')) qrSrc = b.data.qr_data_uri;
else if (b.user && target.length <= 512) qrSrc = qrURL(target);

const qrBlock = qrSrc
  ? h('div', { class: 'trust-qr' },
    (() => {
      const img = qrImage({ src: qrSrc, alt: `QR code that opens ${target}`, size: 168 });
      img.addEventListener('error', () => img.closest('.trust-qr')?.remove());
      return img;
    })(),
    h('div', { class: 'stack-sm' },
      h('h2', { class: 'text-md', text: 'Set up your phone' }),
      h('p', { class: 'muted text-sm', text: 'Scan this code with the camera to open this page on your phone, then follow the steps for iPhone or Android.' }),
      h('span', { class: 'mono text-xs break', text: target })))
  : h('div', { class: 'stack-sm' },
    h('h2', { class: 'text-md', text: 'Set up your phone' }),
    h('p', { class: 'muted text-sm', text: 'Open this address on your phone, then follow the steps for iPhone or Android:' }),
    copyField({ label: 'Address of this page', value: target, hideLabel: true, what: 'Address' }));

append(root, h('div', { class: 'trust-layout' },
  authCard({
    title: `Trust ${instanceName()}`,
    size: 'lg',
    icon: 'shield-check',
    subtitle: 'FileParcel uses its own certificate authority so connections are encrypted on your home network and VPN. Install it once per device to remove browser warnings and to enable passkeys and the app.',
    body: [t.el, panel],
    footer: [h('a', { href: '/', attrs: { 'data-native': true }, text: 'Continue to FileParcel' })],
  }),
  h('aside', { class: 'trust-side stack' },
    h('section', { class: 'card' }, qrBlock),
    h('section', { class: 'card stack-sm' },
      h('h2', { class: 'text-md', text: 'Downloads' }),
      h('div', { class: 'trust-downloads' },
        h('a', { class: 'btn btn--secondary btn--sm', href: '/trust/ca.crt', attrs: { download: '', 'data-native': true } }, icon('certificate'), h('span', { text: 'ca.crt (DER)' })),
        h('a', { class: 'btn btn--secondary btn--sm', href: '/trust/ca.pem', attrs: { download: '', 'data-native': true } }, icon('file-text'), h('span', { text: 'ca.pem' })),
        h('a', { class: 'btn btn--secondary btn--sm', href: '/trust/ca.mobileconfig', attrs: { download: '', 'data-native': true } }, icon('smartphone'), h('span', { text: 'Apple profile' })))),
    fp ? h('section', { class: 'card stack-sm' },
      h('h2', { class: 'text-md', text: 'Verify the fingerprint' }),
      h('p', { class: 'muted text-sm' }, 'Before trusting it, compare this SHA-256 fingerprint with the output of ', code('fileparcel ca fingerprint'), ' on the server, or with ', code('openssl x509 -in ca.pem -noout -fingerprint -sha256'), '.'),
      copyField({ label: 'CA fingerprint (SHA-256)', value: fp, hideLabel: true, what: 'Fingerprint' })) : null,
    alertBox('info', 'Only install certificates from servers you run or trust. By default this CA can only vouch for local names (.local, your tailnet) and private addresses.'))));
