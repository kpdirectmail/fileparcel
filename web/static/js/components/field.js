// @ts-check
/**
 * Form controls. Every control returns a "control object" that form() understands:
 *   field({label, name, type, value, help, required, autocomplete, placeholder, min, max}) → {el, input, setError(msg), value()}
 *   select({label, name, options: [{value, label}], value, onChange})                    → {el, input, setError(msg), value()}
 *     options may also hold groups {label, options: [...]}, rendered as <optgroup>
 *   toggle({label, checked, help, onChange})                                              → {el, input, setError(msg), value()}
 * `type: 'textarea'` renders a <textarea>; `type: 'password'` adds a show/hide button; `type: 'number'` makes
 * value() return a number (or null when empty). Labels are real <label for>, help/error are wired via aria-describedby.
 * Initial values are also set as the controls' *default* values (defaultValue / defaultChecked / defaultSelected),
 * so a native form reset (form().reset()) restores them instead of blanking the fields.
 * @module components/field
 */
import { h, icon, uniqueId } from '../core/dom.js';

/**
 * @typedef {Object} Control
 * @property {HTMLElement} el wrapper to insert into the page
 * @property {HTMLInputElement | HTMLTextAreaElement | HTMLSelectElement} input the native control
 * @property {(msg?: string | null) => void} setError show/clear an inline error
 * @property {() => any} value current value
 * @property {string} [name]
 */

/**
 * @typedef {Object} FieldOpts
 * @property {string} label
 * @property {string} [name]
 * @property {string} [type] text|email|password|number|url|search|tel|date|datetime-local|textarea|…
 * @property {string | number | null} [value]
 * @property {string} [help]
 * @property {boolean} [required]
 * @property {string} [autocomplete]
 * @property {string} [placeholder]
 * @property {number | string} [min]
 * @property {number | string} [max]
 * @property {number | string} [step]
 * @property {number} [minlength]
 * @property {number} [maxlength]
 * @property {string} [pattern]
 * @property {string} [inputmode]
 * @property {number} [rows] textarea rows
 * @property {boolean} [disabled]
 * @property {boolean} [readonly]
 * @property {boolean} [autofocus]
 * @property {boolean} [hideLabel] visually hide the label (still accessible)
 * @property {boolean} [code] monospace, centred (OTP codes)
 * @property {Node} [suffix] element placed inside the input on the right (e.g. an iconButton)
 * @property {(value: string, e: Event) => void} [onInput]
 * @property {Record<string, string | number | boolean | null | undefined>} [attrs] extra input attributes
 */

/**
 * @param {string} id
 * @param {string} [help]
 */
function helpEl(id, help) {
  return help ? h('p', { class: 'field-help', id: `${id}-help`, text: help }) : null;
}

/**
 * Wire aria-describedby + error rendering.
 * @param {HTMLElement} input
 * @param {string} id
 * @param {boolean} hasHelp
 */
function errorSupport(input, id, hasHelp) {
  const err = h('p', { class: 'field-error', id: `${id}-error` });
  const describe = () => {
    const ids = [hasHelp ? `${id}-help` : '', err.textContent ? `${id}-error` : ''].filter(Boolean).join(' ');
    if (ids) input.setAttribute('aria-describedby', ids);
    else input.removeAttribute('aria-describedby');
  };
  describe();
  /** @param {string | null | undefined} msg */
  const setError = (msg) => {
    err.replaceChildren();
    if (msg) {
      err.append(icon('alert-circle'), document.createTextNode(msg));
      input.setAttribute('aria-invalid', 'true');
    } else {
      input.removeAttribute('aria-invalid');
    }
    describe();
  };
  input.addEventListener('input', () => {
    if (input.getAttribute('aria-invalid') === 'true') setError(null);
  });
  return { err, setError };
}

/**
 * Text-like input field.
 * @param {FieldOpts} opts
 * @returns {Control}
 */
export function field(opts) {
  const id = uniqueId('fld');
  const type = opts.type || 'text';
  const common = {
    id,
    name: opts.name || undefined,
    attrs: {
      required: !!opts.required,
      autocomplete: opts.autocomplete || null,
      placeholder: opts.placeholder || null,
      minlength: opts.minlength ?? null,
      maxlength: opts.maxlength ?? null,
      readonly: !!opts.readonly,
      autofocus: !!opts.autofocus,
      spellcheck: type === 'password' || type === 'email' || opts.code ? 'false' : null,
      ...(opts.attrs || {}),
    },
    disabled: !!opts.disabled,
  };
  /** @type {HTMLInputElement | HTMLTextAreaElement} */
  let input;
  if (type === 'textarea') {
    input = h('textarea', { ...common, attrs: { ...common.attrs, rows: opts.rows || 4 }, value: opts.value ?? '' });
  } else {
    input = h('input', {
      ...common,
      attrs: {
        ...common.attrs,
        type,
        min: opts.min ?? null,
        max: opts.max ?? null,
        step: opts.step ?? null,
        pattern: opts.pattern || null,
        inputmode: opts.inputmode || null,
        autocapitalize: type === 'email' || type === 'password' || type === 'url' || opts.code ? 'off' : null,
      },
      value: opts.value === null || opts.value === undefined ? '' : String(opts.value),
    });
  }
  input.defaultValue = input.value; // form reset → back to the initial value
  if (opts.onInput) {
    const fn = opts.onInput;
    input.addEventListener('input', (e) => fn(input.value, e));
  }

  /** @type {Node | null} */
  let action = opts.suffix || null;
  if (type === 'password' && !action && input instanceof HTMLInputElement) {
    const inp = input;
    const eye = icon('eye');
    const btn = h('button', {
      class: 'icon-btn icon-btn--sm input-action',
      attrs: { type: 'button', 'aria-label': 'Show password', title: 'Show password', 'aria-pressed': 'false', 'aria-controls': id },
      on: {
        click: () => {
          const show = inp.type === 'password';
          inp.type = show ? 'text' : 'password';
          btn.setAttribute('aria-pressed', String(show));
          btn.setAttribute('aria-label', show ? 'Hide password' : 'Show password');
          btn.title = show ? 'Hide password' : 'Show password';
          btn.replaceChildren(icon(show ? 'eye-off' : 'eye'));
        },
      },
    }, eye);
    action = btn;
  }
  if (action instanceof HTMLElement) action.classList.add('input-action');

  const { err, setError } = errorSupport(input, id, !!opts.help);
  const el = h('div', { class: ['field', opts.code && 'field-code'] },
    h('label', { class: ['field-label', opts.hideLabel && 'sr-only'], for: id },
      opts.label, opts.required ? h('span', { class: 'req', attrs: { 'aria-hidden': 'true' }, text: '*' }) : null),
    action ? h('div', { class: 'input-wrap' }, input, action) : input,
    helpEl(id, opts.help),
    err);

  return {
    el,
    input,
    setError,
    name: opts.name,
    value() {
      if (type === 'number') {
        const v = input.value.trim();
        return v === '' ? null : Number(v);
      }
      return input.value;
    },
  };
}

/**
 * @typedef {{value: string, label: string, disabled?: boolean} | string} SelectOption
 */

/**
 * A labelled group of options (<optgroup>). Groups do not nest.
 * @typedef {{label: string, options: SelectOption[], disabled?: boolean}} SelectGroup
 */

/**
 * @typedef {Object} SelectOpts
 * @property {string} label
 * @property {string} [name]
 * @property {(SelectOption | SelectGroup)[]} options
 * @property {string | null} [value]
 * @property {(value: string, e: Event) => void} [onChange]
 * @property {string} [help]
 * @property {boolean} [required]
 * @property {boolean} [disabled]
 * @property {boolean} [hideLabel]
 */

/**
 * Native <select>.
 * @param {SelectOpts} opts
 * @returns {Control & {input: HTMLSelectElement, setOptions: (options: SelectOpts['options'], value?: string) => void}}
 */
export function select(opts) {
  const id = uniqueId('sel');
  const input = h('select', { id, name: opts.name || undefined, attrs: { required: !!opts.required }, disabled: !!opts.disabled });
  /** @param {SelectOption} o */
  const optionEl = (o) => {
    const opt = typeof o === 'string' ? { value: o, label: o } : o;
    return h('option', { attrs: { value: opt.value }, disabled: !!opt.disabled, text: opt.label });
  };
  /** @param {SelectOpts['options']} options @param {string | null | undefined} value */
  const setOptions = (options, value) => {
    input.replaceChildren(...options.map((o) => (typeof o !== 'string' && 'options' in o
      ? h('optgroup', { attrs: { label: o.label }, disabled: !!o.disabled }, o.options.map(optionEl))
      : optionEl(o))));
    if (value !== undefined && value !== null) {
      input.value = String(value);
      // mark it as the default so a form reset keeps it
      for (const o of input.options) o.defaultSelected = o.value === String(value);
    }
  };
  setOptions(opts.options, opts.value);
  if (opts.onChange) {
    const fn = opts.onChange;
    input.addEventListener('change', (e) => fn(input.value, e));
  }
  const { err, setError } = errorSupport(input, id, !!opts.help);
  const el = h('div', { class: 'field' },
    h('label', { class: ['field-label', opts.hideLabel && 'sr-only'], for: id, text: opts.label }),
    input,
    helpEl(id, opts.help),
    err);
  return { el, input, setError, setOptions, name: opts.name, value: () => input.value };
}

/**
 * @typedef {Object} ToggleOpts
 * @property {string} label
 * @property {string} [name]
 * @property {boolean} [checked]
 * @property {string} [help]
 * @property {boolean} [disabled]
 * @property {(checked: boolean, e: Event) => void} [onChange]
 */

/**
 * Switch (checkbox with role="switch").
 * @param {ToggleOpts} opts
 * @returns {Control & {input: HTMLInputElement}}
 */
export function toggle(opts) {
  const id = uniqueId('tgl');
  const input = h('input', {
    id,
    name: opts.name || undefined,
    attrs: { type: 'checkbox', role: 'switch' },
    checked: !!opts.checked,
    disabled: !!opts.disabled,
  });
  input.defaultChecked = !!opts.checked;
  if (opts.onChange) {
    const fn = opts.onChange;
    input.addEventListener('change', (e) => fn(input.checked, e));
  }
  const { err, setError } = errorSupport(input, id, !!opts.help);
  const el = h('div', { class: 'toggle' },
    h('div', { class: 'toggle-text' },
      h('label', { class: 'toggle-label', for: id, text: opts.label }),
      helpEl(id, opts.help)),
    input,
    err);
  return { el, input, setError, name: opts.name, value: () => input.checked };
}

/**
 * Plain checkbox with an inline label.
 * @param {{label: string, name?: string, checked?: boolean, disabled?: boolean, onChange?: (checked: boolean, e: Event) => void}} opts
 * @returns {Control & {input: HTMLInputElement}}
 */
export function checkbox(opts) {
  const input = h('input', { name: opts.name || undefined, attrs: { type: 'checkbox' }, checked: !!opts.checked, disabled: !!opts.disabled });
  input.defaultChecked = !!opts.checked;
  if (opts.onChange) {
    const fn = opts.onChange;
    input.addEventListener('change', (e) => fn(input.checked, e));
  }
  const el = h('label', { class: 'check' }, input, h('span', { text: opts.label }));
  return { el, input, setError: () => {}, name: opts.name, value: () => input.checked };
}
