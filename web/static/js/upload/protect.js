// @ts-check
/**
 * The "Protect the .zip with a password" block of the pre-upload dialog (upload/manager.js, DESIGN §13.6): the
 * encryption choice (only while the server allows ZipCrypto), password and confirmation with a strength meter, a
 * generator whose result must be saved before the upload starts, and the notes about what the password does and
 * which apps open the result.
 *
 *   const prot = protectFields({min: 12, legacy: true});
 *   form.append(prot.el);
 *   if (!prot.validate()) return;          // the client rules; the server has the last word (422 zip_password)
 *   send(prot.method(), prot.password());
 *   prot.clear();
 *   prot.setServerError('zip_password', message);   // a rejected attempt, shown when the dialog re-opens
 *
 * The password only ever lives in the inputs of this block: clear() empties them, and nothing is written to web
 * storage. Vendor "ignore" hints keep password managers from offering to save it as the FileParcel sign-in.
 * @module upload/protect
 */
import { h, icon, announce } from '../core/dom.js';
import { field, checkbox } from '../components/field.js';
import { button, iconButton } from '../components/button.js';
import { badge } from '../components/badge.js';
import { copyText } from '../components/copy-field.js';
import { strengthMeter, generatePassword } from '../public/password-strength.js';

/**
 * Longest password the server accepts (ziputil.MaxPasswordLen): 7-Zip and the apps built on it refuse longer AES
 * passwords. The fields have no maxlength: a browser would silently cut a longer paste, and the .zip would be
 * encrypted with a password nobody saved. A longer value is refused with a message instead.
 */
const MAX_LEN = 99;

/**
 * @typedef {'aes256' | 'zipcrypto'} ZipMethod
 */

/** @type {{id: ZipMethod, icon: string, label: string, recommended?: boolean, text: string}[]} */
const METHODS = [
  {
    id: 'aes256',
    icon: 'shield-check',
    label: 'AES-256',
    recommended: true,
    text: 'Strong. Opens with 7-Zip, WinRAR, WinZip, Keka, The Unarchiver and most phone unzip apps — not with the unzip built into Windows or macOS.',
  },
  {
    id: 'zipcrypto',
    icon: 'shield',
    label: 'ZipCrypto',
    text: 'Opens with the unzip built into Windows and macOS, but can usually be cracked without the password.',
  },
];

/** Apps that open each kind of archive (DESIGN §8.2 reader compatibility), per platform. */
const APPS = {
  aes256: [
    ['Windows', '7-Zip or WinRAR'],
    ['macOS', 'Keka or The Unarchiver'],
    ['Linux', '7z or File Roller'],
    ['Android', 'ZArchiver'],
    ['iPhone', 'a zip app from the App Store'],
  ],
  zipcrypto: [
    ['Windows', 'File Explorer'],
    ['macOS', 'Archive Utility'],
    ['Linux', 'unzip'],
    ['Phones', 'most zip apps'],
  ],
};

/**
 * Keeps password managers from filling in or saving the FileParcel sign-in here; `autocorrect` matters once "Show
 * password" turns the field into type=text.
 */
const PM_IGNORE = { autocorrect: 'off', 'data-1p-ignore': '', 'data-lpignore': 'true', 'data-bwignore': '', 'data-form-type': 'other' };

/**
 * The server's field messages are lower-case fragments ("this password is too common; …"): show them as sentences,
 * like the client's own.
 * @param {string} msg
 */
function sentence(msg) {
  const s = String(msg || '').trim();
  if (!s) return s;
  const t = s[0].toUpperCase() + s.slice(1);
  return /[.!?]$/.test(t) ? t : `${t}.`;
}

/**
 * The password rules of the server (DESIGN §8.1) except the common-password list, which only the server has.
 * @param {string} v
 * @param {number} min
 * @returns {string} the problem, '' when none
 */
function ruleError(v, min) {
  if (!v) return 'Enter a password.';
  if (!/^[\x20-\x7e]+$/.test(v)) return 'Use only letters, digits, spaces and the symbols on a US keyboard.';
  if (v.length < min) return `Use at least ${min} characters.`;
  if (v.length > MAX_LEN) return `Use at most ${MAX_LEN} characters.`;
  if (v[0] === ' ' || v[v.length - 1] === ' ') return 'The password can’t start or end with a space.';
  if (new Set(v.toLowerCase()).size < 4) return 'Use more different characters.';
  return '';
}

/**
 * @param {{min: number, legacy: boolean, method?: ZipMethod}} o min: storage.zip_password_min; legacy: ZipCrypto
 *   may be chosen (storage.zip_legacy_encryption); method: the one to pre-select (a re-opened dialog only — the
 *   choice is never remembered)
 * @returns {{el: HTMLElement, method: () => ZipMethod, password: () => string, validate: () => boolean,
 *   setServerError: (field: string, message: string) => void, clear: () => void, focus: () => void}}
 */
export function protectFields(o) {
  const min = o.min;
  /** The value Generate put into both fields ('' when none, or when it was edited since). */
  let generated = '';

  // ---- encryption choice (only when ZipCrypto may be chosen)
  /** @type {Map<ZipMethod, {card: HTMLElement, input: HTMLInputElement}>} */
  const cards = new Map();
  const weakNote = h('p', {
    class: 'alert alert--warning',
    hidden: true,
    attrs: { 'aria-live': 'polite' },
    text: 'ZipCrypto only keeps casual eyes out: the files can usually be recovered in minutes without the password. Don’t use it for sensitive files.',
  });
  const encError = h('p', { class: 'field-error', attrs: { 'aria-live': 'polite' } });
  const appsList = h('ul', { class: 'up-pw-apps-list', attrs: { role: 'list' } });
  /** @type {HTMLElement | null} */
  let choice = null;
  if (o.legacy) {
    const initial = o.method === 'zipcrypto' ? 'zipcrypto' : 'aes256';
    const grid = h('div', { class: 'choice-grid choice-grid--stack', attrs: { role: 'radiogroup', 'aria-label': 'Encryption' } }, METHODS.map((m) => {
      const input = h('input', { class: 'sr-only', attrs: { type: 'radio', name: 'fp-zip-enc', value: m.id }, checked: m.id === initial });
      input.addEventListener('change', () => {
        if (!input.checked) return;
        encError.replaceChildren();
        syncMethod();
      });
      const card = h('label', { class: 'choice-card', dataset: { value: m.id } },
        input,
        h('span', { class: 'choice-card-head' },
          icon(m.icon),
          h('span', { class: 'choice-card-label' }, m.label, m.recommended ? [' ', badge({ text: 'Recommended', kind: 'primary' })] : null),
          h('span', { class: 'choice-card-check', attrs: { 'aria-hidden': 'true' } }, icon('check-circle'))),
        h('span', { class: 'choice-card-text', text: m.text }));
      cards.set(m.id, { card, input });
      return card;
    }));
    choice = h('fieldset', { class: 'choice-fieldset' }, h('legend', { class: 'field-label', text: 'Encryption' }), grid);
  }

  /** @returns {ZipMethod} */
  const method = () => (cards.get('zipcrypto')?.input.checked ? 'zipcrypto' : 'aes256');

  const syncMethod = () => {
    const m = method();
    weakNote.hidden = m !== 'zipcrypto';
    appsList.replaceChildren(...APPS[m].map(([where, apps]) => h('li', null, h('strong', { text: `${where}: ` }), apps)));
  };

  // ---- password, confirmation, meter
  const pw = field({
    label: 'Password',
    name: 'zip-password',
    type: 'password',
    autocomplete: 'new-password',
    minlength: min,
    help: `At least ${min} characters. Don’t reuse your FileParcel password.`,
    attrs: { ...PM_IGNORE, enterkeyhint: 'next' },
  });
  const pw2 = field({
    label: 'Confirm password',
    name: 'zip-password-confirm',
    type: 'password',
    autocomplete: 'new-password',
    attrs: { ...PM_IGNORE, enterkeyhint: 'done' },
  });
  const meter = strengthMeter(pw.input, { min });
  // Enter in the first field moves on: submitting from there would only report "don't match".
  pw.input.addEventListener('keydown', (e) => {
    if (/** @type {KeyboardEvent} */ (e).key !== 'Enter' || /** @type {KeyboardEvent} */ (e).isComposing) return;
    e.preventDefault();
    pw2.input.focus();
  });

  // ---- generator: the result must be copied or ticked as saved before the upload starts
  const genErr = h('p', { class: 'field-error', attrs: { 'aria-live': 'polite' } });
  /** @param {string} msg */
  const setGenError = (msg) => {
    genErr.replaceChildren();
    if (msg) genErr.append(icon('alert-circle'), document.createTextNode(msg));
  };
  const saved = checkbox({ label: 'I’ve saved this password', onChange: () => setGenError('') });
  const copyBtn = iconButton({
    icon: 'copy',
    label: 'Copy password',
    size: 'sm',
    onClick: async () => {
      if (generated && await copyText(generated, 'Password')) {
        saved.input.checked = true;
        setGenError('');
      }
    },
  });
  const genField = field({ label: 'Generated password', readonly: true, suffix: copyBtn, attrs: { ...PM_IGNORE, autocomplete: 'off' } });
  genField.input.classList.add('mono');
  const genSlot = h('div', { class: 'up-pw-gen', hidden: true }, genField.el, saved.el, genErr);

  const dropGenerated = () => {
    generated = '';
    genField.input.value = '';
    saved.input.checked = false;
    setGenError('');
    genSlot.hidden = true;
  };
  // Too long is said at once (a pasted or filled-in password is never cut); the other rules wait for Upload.
  const tooLong = `Use at most ${MAX_LEN} characters.`;
  let longShown = false;
  pw.input.addEventListener('input', () => {
    if (generated && pw.input.value !== generated) dropGenerated();
    const long = pw.input.value.length > MAX_LEN;
    if (long) pw.setError(tooLong);
    else if (longShown) pw.setError(null);
    longShown = long;
  });

  const generate = () => {
    // 20 of 61 symbols ≈ 118 bits; longer when the server asks for more (storage.zip_password_min ≤ 64)
    const len = Math.max(20, min);
    let g = generatePassword(len);
    while (ruleError(g, min)) g = generatePassword(len); // practically never: fewer than 4 distinct characters
    generated = g;
    pw.input.value = g;
    pw2.input.value = g;
    pw.setError(null);
    pw2.setError(null);
    longShown = false;
    meter.update();
    genField.input.value = g;
    saved.input.checked = false;
    setGenError('');
    genSlot.hidden = false;
    announce('Password generated. Copy it now: FileParcel can’t show it again.');
  };

  const el = h('fieldset', { class: 'up-protect' },
    h('legend', { class: 'sr-only', text: 'Password protection' }),
    choice,
    weakNote,
    encError,
    pw.el,
    meter.el,
    pw2.el,
    h('div', { class: 'up-pw-actions' }, button({ label: 'Generate a strong password', icon: 'key', variant: 'secondary', onClick: generate })),
    genSlot,
    h('p', { class: 'muted text-sm', text: 'FileParcel doesn’t keep this password. If it’s lost, nobody can open the .zip. File and folder names inside the .zip stay visible.' }),
    h('details', { class: 'auth-details up-pw-apps' },
      h('summary', { text: 'Which apps can open it?' }),
      h('div', null, appsList)));
  syncMethod();

  return {
    el,
    method,
    password: () => pw.input.value,
    validate() {
      const v = pw.input.value;
      const err = ruleError(v, min);
      if (err) {
        pw.setError(err);
        longShown = err === tooLong;
        pw.input.focus();
        return false;
      }
      if (pw2.input.value !== v) {
        pw2.setError('The passwords don’t match.');
        pw2.input.focus();
        return false;
      }
      if (generated && v === generated && !saved.input.checked) {
        setGenError('Save the generated password first (copy it, or tick the box).');
        saved.input.focus();
        return false;
      }
      return true;
    },
    setServerError(fieldName, message) {
      if (fieldName === 'zip_encryption') {
        // ZipCrypto was refused (turned off since the page loaded): AES-256 is the only choice left
        encError.replaceChildren(icon('alert-circle'), document.createTextNode(sentence(message)));
        const aes = cards.get('aes256');
        if (aes) aes.input.checked = true;
        cards.get('zipcrypto')?.card.remove();
        cards.delete('zipcrypto');
        syncMethod();
        return;
      }
      pw.setError(sentence(message));
      longShown = false;
    },
    clear() {
      pw.input.value = '';
      pw2.input.value = '';
      dropGenerated();
      meter.update();
      pw.setError(null);
      pw2.setError(null);
      longShown = false;
      encError.replaceChildren();
    },
    focus: () => pw.input.focus(),
  };
}
