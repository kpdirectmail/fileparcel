// @ts-check
/**
 * Settings → Appearance (/settings/appearance): theme (system / light / dark), density (comfortable / compact) and
 * the default file view (list / grid). Changes apply instantly and are saved to the account preferences
 * (PATCH /me/profile {prefs}, merged — the endpoint replaces the whole object), so they follow the user to other
 * devices. The theme is also kept in localStorage ("fp:theme") like the theme switch in the avatar menu, which makes
 * it apply before the page has loaded /me.
 * Preference keys: theme, density, view (read by app.js and the file pages).
 * Owned by unit J2.
 * @module pages/settings/appearance
 */
import { h, icon, applyTheme, applyDensity, append } from '../../core/dom.js';
import { errorMessage } from '../../core/api.js';
import { settingsHeader, currentPrefs, savePrefs } from './common.js';
import { viewPref, defaultView } from '../../components/node-list.js';

export const title = 'Appearance';

/**
 * @typedef {Object} Choice
 * @property {string} value
 * @property {string} label
 * @property {string} icon
 * @property {string} text
 */

/**
 * @param {HTMLElement} root
 * @param {import('../../core/router.js').PageContext} ctx
 */
export function mount(root, ctx) {
  void ctx;
  settingsHeader(root, { id: 'settings-appearance', title, subtitle: 'Make FileParcel look the way you like. Changes are saved automatically.' });
  const prefs = currentPrefs();
  let localTheme = '';
  try { localTheme = localStorage.getItem('fp:theme') || ''; } catch { /* storage unavailable */ }
  const status = h('p', { class: 'save-status', attrs: { role: 'status', 'aria-live': 'polite' } });

  /** @type {ReturnType<typeof setTimeout> | 0} */
  let timer = 0;
  /** @type {Record<string, any>} */
  let pending = {};
  let saves = 0;
  const save = (/** @type {Record<string, any>} */ patch) => {
    pending = { ...pending, ...patch };
    status.textContent = 'Saving…';
    status.dataset.state = 'saving';
    clearTimeout(timer);
    timer = setTimeout(async () => {
      const p = pending;
      pending = {};
      const n = ++saves;
      // savePrefs() queues saves; only the newest one, with no change waiting behind it, reports
      const latest = () => n === saves && !Object.keys(pending).length;
      try {
        await savePrefs(p);
        if (!latest()) return;
        status.textContent = 'Saved to your account';
        status.dataset.state = 'saved';
      } catch (err) {
        if (!latest()) return;
        status.textContent = `Saved on this device only — ${errorMessage(err)}`;
        status.dataset.state = 'error';
      }
    }, 400);
  };

  const theme = choiceGroup({
    legend: 'Theme',
    name: 'theme',
    value: localTheme || prefs.theme || document.documentElement.dataset.theme || 'system',
    choices: [
      { value: 'system', label: 'System', icon: 'monitor', text: 'Follows your device’s light or dark setting.' },
      { value: 'light', label: 'Light', icon: 'sun', text: 'Warm paper tones.' },
      { value: 'dark', label: 'Dark', icon: 'moon', text: 'Easy on the eyes at night.' },
    ],
    onChange: (v) => {
      applyTheme(v);
      try { localStorage.setItem('fp:theme', v); } catch { /* ignore */ }
      save({ theme: v });
    },
    preview: true,
  });

  const density = choiceGroup({
    legend: 'Density',
    name: 'density',
    value: prefs.density === 'compact' ? 'compact' : 'comfortable',
    choices: [
      { value: 'comfortable', label: 'Comfortable', icon: 'list', text: 'Roomy rows, easy to tap.' },
      { value: 'compact', label: 'Compact', icon: 'menu', text: 'More files on screen (touch screens keep large targets).' },
    ],
    onChange: (v) => {
      applyDensity(v);
      save({ density: v });
    },
  });

  const view = choiceGroup({
    legend: 'Default file view',
    name: 'view',
    // No account preference yet → show the value that is actually in effect (the server's ui.default_view), never an
    // empty radio group.
    value: prefs.view === 'grid' ? 'grid' : prefs.view === 'list' ? 'list' : defaultView(),
    choices: [
      { value: 'list', label: 'List', icon: 'list', text: 'Names, sizes and dates in rows.' },
      { value: 'grid', label: 'Grid', icon: 'grid', text: 'Large thumbnails — great for photos.' },
    ],
    onChange: (v) => {
      viewPref.value = v === 'grid' ? 'grid' : 'list'; // apply it on this device too, like theme and density
      save({ view: v });
    },
  });

  append(root, h('div', { class: 'stack-lg appearance' },
    h('section', { class: 'card' }, theme),
    h('section', { class: 'card' }, density),
    h('section', { class: 'card' }, view, h('p', { class: 'muted text-sm', text: 'Folders remember the view you pick with the toggle in the file toolbar; this is the starting point.' })),
    status));

  return () => {
    clearTimeout(timer);
    if (Object.keys(pending).length) savePrefs(pending).catch(() => {});
  };
}

/**
 * Radio group rendered as selectable cards.
 * @param {{legend: string, name: string, value: string, choices: Choice[], onChange: (v: string) => void, preview?: boolean}} o
 */
function choiceGroup(o) {
  const group = h('div', { class: 'choice-grid' }, o.choices.map((c) => {
    const input = h('input', { class: 'sr-only', attrs: { type: 'radio', name: `fp-${o.name}`, value: c.value }, checked: c.value === o.value });
    input.addEventListener('change', () => {
      if (input.checked) o.onChange(c.value);
    });
    return h('label', { class: 'choice-card', dataset: { value: c.value } },
      input,
      o.preview ? h('span', { class: 'theme-preview', dataset: { theme: c.value }, attrs: { 'aria-hidden': 'true' } },
        h('span', { class: 'theme-preview-bar' }), h('span', { class: 'theme-preview-line' }), h('span', { class: 'theme-preview-line short' })) : null,
      h('span', { class: 'choice-card-head' }, icon(c.icon), h('span', { class: 'choice-card-label', text: c.label }), h('span', { class: 'choice-card-check', attrs: { 'aria-hidden': 'true' } }, icon('check-circle'))),
      h('span', { class: 'choice-card-text', text: c.text }));
  }));
  return h('fieldset', { class: 'choice-fieldset' }, h('legend', { class: 'card-title', text: o.legend }), group);
}
