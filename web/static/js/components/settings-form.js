// @ts-check
/**
 * settingsForm({section}) → HTMLElement
 *
 * Auto-generated editor for one section of the runtime settings catalog (GET /api/v1/admin/settings, §11.2).
 * Each catalog entry (SettingView) is expected to look like:
 *   {key, section, order, type, label, description, value, default, restart, secret, is_set, enum, min, max, overridden_by_env}
 * Types (§5.3): bool, int, string, strings, duration, enum, cidrs, secret, cron, color, email, url.
 * Free-text notices that may span lines (MULTILINE) are edited in a <textarea>, other strings in an <input>.
 * Saving sends only changed keys with PATCH /admin/settings {key: value} (elevation is prompted automatically for
 * sensitive sections) and shows a "Restart now" banner for keys listed in `restart_required`.
 * "Reset" issues DELETE /admin/settings/{key}; for secrets (whose values are never sent to the browser) the same
 * call is offered as "Clear" whenever a value is stored (`is_set`). Env-overridden keys are read-only, and so are
 * managed keys (`managed`: another route owns them, e.g. Tailscale Funnel's on the Network page, which is linked).
 * A change a server guard refuses with 409 conflict (turning auth.passkeys off, or moving the passkey domain, while
 * accounts rely on a passkey alone) is explained in a confirmation and, when confirmed, sent again with ?force=1.
 * @module components/settings-form
 */
import { h, icon } from '../core/dom.js';
import { api, itemsOf, errorMessage, ApiError } from '../core/api.js';
import { button, setBusy } from './button.js';
import { field, select, toggle } from './field.js';
import { badge } from './badge.js';
import { toast } from './toast.js';
import { skeleton } from './progress.js';
import { confirm } from './dialog.js';

/**
 * @typedef {Object} SettingView
 * @property {string} key
 * @property {string} [section]
 * @property {number} [order]
 * @property {string} type
 * @property {string} [label]
 * @property {string} [description]
 * @property {any} [value]
 * @property {any} [default]
 * @property {boolean} [restart]
 * @property {boolean} [secret]
 * @property {boolean} [is_set]
 * @property {any[]} [enum]
 * @property {number} [min]
 * @property {number} [max]
 * @property {string | boolean} [overridden_by_env] env var name when overridden
 * @property {string} [managed] the route that owns the key ("PUT /api/v1/admin/network/funnel"); read-only here
 */

/** @param {string} t */
function normType(t) {
  const s = String(t || 'string').toLowerCase().replace(/^type/, '');
  return s;
}

/**
 * Free-text string settings that may span lines (their validators allow \n; the sign-in page shows them with
 * `white-space: pre-line`), so they get a <textarea>: an <input> drops the line breaks from its value.
 */
const MULTILINE = new Set(['ui.login_message', 'maintenance.message']);

/**
 * Whether the admin edited a text control. It compares with the value the control was built with (`defaultValue`,
 * see field()), not with the stored setting: an <input> strips line breaks from what it is given and a <textarea>
 * turns CRLF into LF, so a stored value the control cannot hold as-is must not count as a change (and be sent back
 * altered) whenever an unrelated setting is saved.
 * @param {import('./field.js').Control} c
 */
const textEdited = (c) => c.input.value !== /** @type {HTMLInputElement | HTMLTextAreaElement} */ (c.input).defaultValue;

/**
 * Where a managed key is changed: the Network page's Funnel or Serve card.
 * @param {SettingView} s
 */
function managedLink(s) {
  const serve = /\/serve$/.test(String(s.managed || ''));
  return { href: serve ? '/admin/network#serve' : '/admin/network#funnel', label: serve ? 'Change in Tailscale Serve' : 'Change in Tailscale Funnel' };
}

/** @param {any} v */
function display(v) {
  if (v === null || v === undefined || v === '') return '(empty)';
  if (Array.isArray(v)) return v.length ? v.join(', ') : '(none)';
  if (typeof v === 'boolean') return v ? 'On' : 'Off';
  return String(v);
}

/**
 * Build an editor control for one setting.
 * @param {SettingView} s
 * @returns {{el: HTMLElement, read: () => {changed: boolean, value?: any, error?: string}, setError: (m: string | null) => void}}
 */
function controlFor(s) {
  const type = normType(s.type);
  const label = s.label || s.key;
  const disabled = !!s.overridden_by_env || !!s.managed;
  const help = s.description || undefined;

  if (type === 'bool') {
    const c = toggle({ label, checked: !!s.value, help, disabled });
    return { el: c.el, setError: c.setError, read: () => ({ changed: c.input.checked !== !!s.value, value: c.input.checked }) };
  }
  if (type === 'enum' && Array.isArray(s.enum) && s.enum.length) {
    const options = s.enum.map((o) => (typeof o === 'object' ? { value: String(o.value), label: String(o.label ?? o.value) } : { value: String(o), label: String(o) }));
    const c = select({ label, options, value: String(s.value ?? s.default ?? ''), help, disabled });
    return { el: c.el, setError: c.setError, read: () => ({ changed: c.input.value !== String(s.value ?? ''), value: c.input.value }) };
  }
  if (type === 'int') {
    const c = field({ label, type: 'number', value: s.value ?? '', help, min: s.min, max: s.max, disabled, inputmode: 'numeric' });
    return {
      el: c.el,
      setError: c.setError,
      read: () => {
        const raw = String(c.input.value).trim();
        if (raw === '') return { changed: false };
        const n = Number(raw);
        if (!Number.isInteger(n)) return { changed: true, error: 'Enter a whole number.' };
        if (s.min !== undefined && s.min !== null && n < s.min) return { changed: true, error: `Minimum is ${s.min}.` };
        if (s.max !== undefined && s.max !== null && s.max !== 0 && n > s.max) return { changed: true, error: `Maximum is ${s.max}.` };
        return { changed: n !== Number(s.value), value: n };
      },
    };
  }
  if (type === 'strings' || type === 'cidrs') {
    const list = Array.isArray(s.value) ? s.value : [];
    const c = field({ label, type: 'textarea', rows: Math.min(8, Math.max(3, list.length + 1)), value: list.join('\n'), help: `${help ? `${help} ` : ''}One per line.`, disabled, attrs: { spellcheck: 'false' } });
    return {
      el: c.el,
      setError: c.setError,
      read: () => {
        const v = String(c.input.value).split(/[\n,]+/).map((x) => x.trim()).filter(Boolean);
        return { changed: JSON.stringify(v) !== JSON.stringify(list), value: v };
      },
    };
  }
  if (type === 'secret') {
    const c = field({
      label,
      type: 'password',
      value: '',
      help,
      disabled,
      autocomplete: 'new-password',
      placeholder: s.is_set ? '•••••••• (saved — type to replace)' : 'Not set',
    });
    return {
      el: c.el,
      setError: c.setError,
      read: () => {
        const v = String(c.input.value);
        return v ? { changed: true, value: v } : { changed: false };
      },
    };
  }
  if (type === 'string' && MULTILINE.has(s.key)) {
    const c = field({ label, type: 'textarea', rows: 3, value: s.value ?? '', help, disabled });
    return { el: c.el, setError: c.setError, read: () => ({ changed: textEdited(c), value: String(c.input.value).trim() }) };
  }
  const inputType = type === 'email' ? 'email' : type === 'url' ? 'url' : type === 'color' ? 'text' : 'text';
  const c = field({
    label,
    type: inputType,
    value: s.value ?? '',
    help,
    disabled,
    placeholder: type === 'duration' ? 'e.g. 15m, 12h' : type === 'cron' ? 'e.g. 0 3 * * *' : type === 'color' ? '#2563eb' : undefined,
    attrs: { spellcheck: 'false' },
  });
  return { el: c.el, setError: c.setError, read: () => ({ changed: textEdited(c), value: String(c.input.value).trim() }) };
}

/**
 * @param {{section: string, keys?: string[], onSaved?: (res: any, changes: Record<string, any>) => void}} opts
 *   `onSaved` also receives the keys that were just sent, so a page can apply a live-effective setting to the open
 *   session (e.g. ui.instance_name → the shell brand).
 * @returns {HTMLElement}
 */
export function settingsForm(opts) {
  const root = h('div', { class: 'settings-section' }, skeleton(6));
  /** @type {{s: SettingView, c: ReturnType<typeof controlFor>}[]} */
  let rows = [];

  const banner = h('div', { class: 'app-banners' });

  const load = async () => {
    let catalog;
    try {
      catalog = itemsOf(await api.get('/admin/settings'));
    } catch (err) {
      root.replaceChildren(h('div', { class: 'alert alert--danger', attrs: { role: 'alert' } }, icon('alert-circle'), h('div', { class: 'alert-body', text: errorMessage(err) })));
      return;
    }
    /** @type {SettingView[]} */
    const list = catalog
      .filter((s) => (s.section || String(s.key).split('.')[0]) === opts.section)
      .filter((s) => !opts.keys || opts.keys.includes(s.key))
      .sort((a, b) => (a.order ?? 0) - (b.order ?? 0) || String(a.key).localeCompare(String(b.key)));
    render(list);
  };

  /** @param {SettingView[]} list */
  const render = (list) => {
    rows = list.map((s) => ({ s, c: controlFor(s) }));
    if (!rows.length) {
      root.replaceChildren(h('p', { class: 'muted', text: 'There are no settings in this section.' }));
      return;
    }
    const saveBtn = button({ label: 'Save changes', icon: 'check', variant: 'primary', type: 'submit' });
    // Nothing to save when every key is read-only here.
    saveBtn.hidden = rows.every(({ s }) => s.overridden_by_env || s.managed);
    const formEl = h('form', { class: 'stack', attrs: { novalidate: true } },
      banner,
      rows.map(({ s, c }) => {
        // secrets: the value is masked, so offer "Clear" whenever one is stored; others: "Reset" when not the default
        const resettable = s.secret ? !!s.is_set : s.default !== undefined && JSON.stringify(s.value) !== JSON.stringify(s.default);
        const link = s.managed ? managedLink(s) : null;
        return h('div', { class: 'setting-row', dataset: { key: s.key, managed: s.managed ? '' : null } },
          c.el,
          h('div', { class: 'setting-meta' },
            h('code', { text: s.key }),
            s.restart ? badge({ text: 'Restart required', kind: 'warning', icon: 'refresh' }) : null,
            s.overridden_by_env
              ? badge({ text: typeof s.overridden_by_env === 'string' ? `Set by ${s.overridden_by_env}` : 'Set by environment', kind: 'info', icon: 'lock' })
              : null,
            link ? badge({ text: 'Managed on the Network page', kind: 'info', icon: 'lock' }) : null,
            link ? h('a', { class: 'btn btn--ghost btn--sm', href: link.href }, icon('external'), h('span', { text: link.label })) : null,
            !s.secret && s.default !== undefined ? h('span', { text: `Default: ${display(s.default)}` }) : null,
            resettable && !s.overridden_by_env && !s.managed
              ? button({ label: s.secret ? 'Clear' : 'Reset', size: 'sm', variant: 'ghost', icon: s.secret ? 'x' : 'rotate-ccw', onClick: () => reset(s) })
              : null));
      }),
      h('div', { class: 'form-actions' }, saveBtn));
    formEl.addEventListener('submit', async (e) => {
      e.preventDefault();
      setBusy(saveBtn, true);
      try {
        await save();
      } finally {
        setBusy(saveBtn, false);
      }
    });
    root.replaceChildren(formEl);
  };

  const save = async () => {
    /** @type {Record<string, any>} */
    const changes = {};
    let invalid = false;
    for (const { s, c } of rows) {
      c.setError(null);
      if (s.overridden_by_env || s.managed) continue;
      const r = c.read();
      if (r.error) {
        c.setError(r.error);
        invalid = true;
      } else if (r.changed) {
        changes[s.key] = r.value;
      }
    }
    if (invalid) return;
    if (!Object.keys(changes).length) {
      toast.info('No changes to save.');
      return;
    }
    try {
      const res = await api.patch('/admin/settings', changes).catch(async (err) => {
        if (!(await confirmForce(err))) throw err;
        return api.patch('/admin/settings', changes, { query: { force: 1 } });
      });
      toast.success('Settings saved');
      showRestart(res?.restart_required || []);
      // The server may accept a value and still have something to say about it
      // (a tls.extra_sans name the local CA may not sign, for instance). The
      // banner node is reused by render(), so this survives the reload below.
      const warnings = Array.isArray(res?.warnings) ? res.warnings.filter(Boolean) : [];
      if (warnings.length) {
        banner.appendChild(h('div', { class: 'alert alert--warning', attrs: { role: 'status' } },
          icon('alert-triangle'),
          h('div', { class: 'alert-body' },
            h('strong', { text: 'Saved with warnings' }),
            h('ul', { class: 'hint-list' }, warnings.map((/** @type {string} */ w) => h('li', { text: w }))))));
      }
      opts.onSaved?.(res, changes);
      await load();
    } catch (err) {
      if (err instanceof ApiError && err.field) {
        const row = rows.find((r) => r.s.key === err.field);
        if (row) {
          row.c.setError(err.message);
          return;
        }
      }
      toast.error(err);
    }
  };

  /**
   * Asks whether to override a guard's 409 conflict; its message says who would be shut out and how to avoid it.
   * Resolves false for any other error.
   * @param {unknown} err
   * @returns {Promise<boolean>}
   */
  const confirmForce = async (err) => err instanceof ApiError && err.status === 409 && err.code === 'conflict' &&
    confirm({ title: 'Make this change anyway?', message: err.message, confirmLabel: 'Change anyway', danger: true });

  /** @param {SettingView} s */
  const reset = async (s) => {
    const ok = s.secret
      ? await confirm({ title: 'Clear the saved value?', message: `The stored ${s.label || s.key} will be removed.`, confirmLabel: 'Clear', danger: true })
      : await confirm({ title: 'Reset to default?', message: `${s.label || s.key} will go back to ${display(s.default)}.`, confirmLabel: 'Reset' });
    if (!ok) return;
    const path = `/admin/settings/${encodeURIComponent(s.key)}`;
    try {
      await api.del(path).catch(async (err) => {
        if (!(await confirmForce(err))) throw err;
        return api.del(path, undefined, { query: { force: 1 } });
      });
      toast.success(s.secret ? 'Saved value cleared' : 'Setting reset');
      if (s.restart) showRestart([s.key]);
      await load();
    } catch (err) {
      toast.error(err);
    }
  };

  /** @param {string[]} keys */
  const showRestart = (keys) => {
    banner.replaceChildren();
    if (!keys.length) return;
    banner.appendChild(h('div', { class: 'alert alert--warning', attrs: { role: 'status' } },
      icon('refresh'),
      h('div', { class: 'alert-body' },
        h('strong', { text: 'Restart required' }),
        h('span', { text: `Changes to ${keys.join(', ')} take effect after a restart.` })),
      button({
        label: 'Restart now',
        size: 'sm',
        variant: 'secondary',
        onClick: async () => {
          try {
            await api.post('/admin/system/restart', {});
            toast.info('Restarting… the page will reconnect in a few seconds.');
          } catch (err) {
            toast.error(err);
          }
        },
      })));
  };

  load();
  return root;
}
