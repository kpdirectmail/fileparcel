// @ts-check
/**
 * Password strength estimate + live meter, shared by the public pages (setup, invite) and the signed-in settings /
 * admin pages. The estimate is advisory only — the server enforces `auth.password_min` and its own policy
 * (Auth.CheckPasswordPolicy) and answers 422 {field: "password"} when a password is rejected. The length rule
 * follows `auth.password_min` as GET /auth/state reports it (passwordMin(); a meter without an explicit `min` loads
 * it), and 12, its default, until that is known.
 *
 *   const m = strengthMeter(input, {userInputs: () => [username]});
 *   parent.append(m.el);             // updates on every input event
 *   estimate('correct horse battery staple') → {score: 4, label: 'Strong', bits: 71, warning: '', tips: []}
 *
 * No dictionary download: a small list of very common passwords/words plus pattern checks (repeats, sequences,
 * keyboard rows, dates, the user's own name) keeps the module tiny and CSP-friendly.
 * @module public/password-strength
 */
import { h } from '../core/dom.js';
import { authState } from './common.js';

/** Default of auth.password_min. */
const DEFAULT_MIN = 12;
/** auth.password_min from GET /auth/state, once loaded (0 until then, or when unavailable). */
let serverMin = 0;

/**
 * The server's minimum password length (auth.password_min from GET /auth/state, cached; 12 when unavailable). Once
 * resolved it is also the default `min` of estimate() and strengthMeter().
 * @returns {Promise<number>}
 */
export function passwordMin() {
  return authState().then((s) => {
    const n = Number(s.password_min);
    if (Number.isInteger(n) && n > 0) serverMin = n;
    return serverMin || DEFAULT_MIN;
  });
}

/** Very common passwords / fragments (lower case). A hit caps the score. */
const COMMON = new Set([
  'password', 'passw0rd', 'p@ssword', 'p@ssw0rd', '123456', '1234567', '12345678', '123456789', '1234567890', 'qwerty',
  'qwertyuiop', 'asdfgh', 'asdfghjkl', 'zxcvbn', 'letmein', 'welcome', 'admin', 'administrator', 'root', 'iloveyou',
  'monkey', 'dragon', 'football', 'baseball', 'master', 'shadow', 'sunshine', 'princess', 'trustno1', 'abc123',
  'changeme', 'secret', 'fileparcel', 'default', 'login', 'hello', 'freedom', 'whatever', 'superman', 'batman',
  'starwars', 'passwort', 'motdepasse', 'contraseña', 'qwerty123', 'password1', 'password123', '111111', '000000',
  '123123', '654321', 'azerty', 'test', 'guest', 'summer', 'winter', 'spring', 'autumn',
]);

const SEQUENCES = ['abcdefghijklmnopqrstuvwxyz', '0123456789', 'qwertyuiop', 'asdfghjkl', 'zxcvbnm', '1qaz2wsx3edc'];

/**
 * @typedef {Object} Estimate
 * @property {0 | 1 | 2 | 3 | 4} score 0 very weak … 4 strong
 * @property {string} label
 * @property {number} bits rough entropy estimate
 * @property {string} warning main problem ('' when none)
 * @property {string[]} tips suggestions
 */

/**
 * Size of the character pool used by `pw`.
 * @param {string} pw
 */
function poolSize(pw) {
  let pool = 0;
  if (/[a-z]/.test(pw)) pool += 26;
  if (/[A-Z]/.test(pw)) pool += 26;
  if (/[0-9]/.test(pw)) pool += 10;
  if (/[^a-zA-Z0-9\s]/.test(pw)) pool += 33;
  if (/\s/.test(pw)) pool += 1;
  if (/[^\u0000-\u007f]/.test(pw)) pool += 100;
  return Math.max(pool, 1);
}

/**
 * Length of `s` after collapsing runs of a repeated character or repeated short chunk ("abcabcabc" → 3).
 * @param {string} s
 */
function effectiveLength(s) {
  const chars = [...s];
  let n = chars.length;
  // repeated chunk (e.g. "abab", "123123123")
  for (let size = 1; size <= Math.floor(chars.length / 2); size += 1) {
    if (chars.length % size !== 0) continue;
    const chunk = chars.slice(0, size).join('');
    if (chunk.repeat(chars.length / size) === s) {
      n = Math.min(n, size + Math.log2(chars.length / size));
      break;
    }
  }
  // runs of the same character count once (+1)
  let runs = 0;
  for (let i = 1; i < chars.length; i += 1) if (chars[i] === chars[i - 1]) runs += 1;
  return Math.max(1, Math.min(n, chars.length - runs * 0.75));
}

/**
 * Number of characters of `s` that are part of ascending/descending sequences of length ≥ 3.
 * @param {string} s
 */
function sequenceChars(s) {
  const lower = s.toLowerCase();
  let hit = 0;
  for (const seq of SEQUENCES) {
    const rev = [...seq].reverse().join('');
    for (const src of [seq, rev]) {
      for (let len = Math.min(src.length, lower.length); len >= 3; len -= 1) {
        let found = false;
        for (let i = 0; i + len <= src.length; i += 1) {
          if (lower.includes(src.slice(i, i + len))) {
            hit = Math.max(hit, len);
            found = true;
            break;
          }
        }
        if (found) break;
      }
    }
  }
  return hit;
}

/**
 * Estimate the strength of a password.
 * @param {string} pw
 * @param {{min?: number, userInputs?: string[]}} [opts] min: required length (default: auth.password_min, see
 *   passwordMin()); userInputs: username, name, email … (penalised when contained)
 * @returns {Estimate}
 */
export function estimate(pw, opts = {}) {
  const min = opts.min || serverMin || DEFAULT_MIN;
  /** @type {string[]} */
  const tips = [];
  if (!pw) return { score: 0, label: 'Too short', bits: 0, warning: '', tips: [`Use at least ${min} characters.`] };

  const lower = pw.toLowerCase();
  let bits = effectiveLength(pw) * Math.log2(poolSize(pw));
  let warning = '';

  const seq = sequenceChars(pw);
  if (seq >= 3) {
    bits -= seq * 2.5;
    warning = warning || 'Avoid sequences like “abc” or “1234”.';
  }
  const leet = lower.replace(/[@4]/g, 'a').replace(/3/g, 'e').replace(/[1!|]/g, 'i').replace(/0/g, 'o').replace(/[$5]/g, 's').replace(/7/g, 't');
  for (const w of COMMON) {
    if (w.length >= 4 && (lower.includes(w) || leet.includes(w))) {
      bits -= w.length * 3;
      warning = lower === w || leet === w ? 'This is one of the most common passwords.' : 'Avoid common words and passwords.';
      break;
    }
  }
  for (const u of opts.userInputs || []) {
    const v = String(u || '').toLowerCase().trim();
    if (v.length >= 3 && (lower.includes(v) || leet.includes(v))) {
      bits -= v.length * 3;
      warning = warning || 'Don’t include your name or username.';
    }
  }
  if (/(19|20)\d\d/.test(pw)) {
    bits -= 6;
    if (!warning) warning = 'Years and dates are easy to guess.';
  }
  if (/^(.)\1+$/.test(pw)) {
    bits = Math.min(bits, 4);
    warning = 'Repeated characters are easy to guess.';
  }
  bits = Math.max(0, Math.round(bits));

  const length = [...pw].length;
  /** @type {0 | 1 | 2 | 3 | 4} */
  let score;
  if (bits < 28) score = 0;
  else if (bits < 40) score = 1;
  else if (bits < 56) score = 2;
  else if (bits < 72) score = 3;
  else score = 4;
  if (length < min) {
    score = /** @type {0 | 1} */ (Math.min(score, 1));
    tips.push(`Use at least ${min} characters (${length} so far).`);
  }
  if (score < 3 && length < 16) tips.push('A short sentence of 4–5 random words is strong and easy to remember.');
  if (score < 3 && poolSize(pw) <= 26) tips.push('Mixing in numbers or symbols helps a little; length helps more.');
  const labels = ['Very weak', 'Weak', 'Fair', 'Good', 'Strong'];
  return { score, label: length < min ? 'Too short' : labels[score], bits, warning, tips };
}

/**
 * Live strength meter bound to a password input. Without `min` it loads the server's minimum (passwordMin()) and
 * re-evaluates once that is known.
 * @param {HTMLInputElement | HTMLTextAreaElement} input
 * @param {{min?: number, userInputs?: () => string[]}} [opts]
 * @returns {{el: HTMLElement, update: () => Estimate}}
 */
export function strengthMeter(input, opts = {}) {
  const bars = Array.from({ length: 4 }, () => h('span', { class: 'pw-meter-bar' }));
  const label = h('span', { class: 'pw-meter-label' });
  const hint = h('span', { class: 'pw-meter-hint' });
  const el = h('div', { class: 'pw-meter', dataset: { score: 'none' }, attrs: { 'aria-live': 'polite' } },
    h('div', { class: 'pw-meter-bars', attrs: { 'aria-hidden': 'true' } }, bars),
    h('div', { class: 'pw-meter-text' }, label, hint));

  const update = () => {
    const pw = input.value;
    const est = estimate(pw, { min: opts.min, userInputs: opts.userInputs ? opts.userInputs() : [] });
    if (!pw) {
      el.dataset.score = 'none';
      label.textContent = '';
      hint.textContent = '';
      return est;
    }
    el.dataset.score = String(est.score);
    bars.forEach((b, i) => b.classList.toggle('is-on', i < Math.max(1, est.score)));
    label.textContent = `Strength: ${est.label}`;
    hint.textContent = est.warning || est.tips[0] || '';
    return est;
  };
  input.addEventListener('input', update);
  update();
  if (!opts.min) passwordMin().then(() => { if (input.value) update(); });
  return { el, update };
}

/**
 * Generate a random, readable password (for admins creating accounts). Uses crypto.getRandomValues.
 * @param {number} [length]
 */
export function generatePassword(length = 20) {
  const alphabet = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789-_.!';
  // rejection sampling: no modulo bias
  const limit = Math.floor(0x100000000 / alphabet.length) * alphabet.length;
  /** @type {string[]} */
  const out = [];
  const buf = new Uint32Array(length);
  while (out.length < length) {
    crypto.getRandomValues(buf);
    for (const v of buf) {
      if (v < limit) out.push(alphabet[v % alphabet.length]);
      if (out.length === length) break;
    }
  }
  return out.join('');
}
