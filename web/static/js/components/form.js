// @ts-check
/**
 * form({fields, submitLabel, onSubmit: async (values) => {}, cancel}) → {el, reset(), controls, setError(msg), submit()}
 *
 * `fields` items are either control objects from field()/select()/toggle() (anything with {el, value(), name})
 * or plain specs that are turned into controls:
 *   {name, label, type: 'text'|'email'|'password'|'number'|'textarea'|'select'|'toggle'|'checkbox', options, value, checked, help, …}
 * or arbitrary DOM nodes (headings, notes) which are inserted as-is.
 * On submit, `values` maps each control's name to value(). If onSubmit throws an ApiError with `field`, that field
 * shows the message inline; any other error is shown in the form-level alert. The submit button is busy meanwhile.
 * `cancel` may be a function or {label, onClick}.
 * @module components/form
 */
import { h, icon } from '../core/dom.js';
import { ApiError } from '../core/api.js';
import { button, setBusy } from './button.js';
import { field, select, toggle, checkbox } from './field.js';

/**
 * @typedef {import('./field.js').Control} Control
 */

/**
 * @typedef {Object} FormOpts
 * @property {(Control | Record<string, any> | Node)[]} fields
 * @property {string} [submitLabel]
 * @property {string} [submitIcon]
 * @property {'primary' | 'danger'} [submitVariant]
 * @property {(values: Record<string, any>) => any} onSubmit
 * @property {(() => void) | {label?: string, onClick: () => void}} [cancel]
 * @property {boolean} [stretchActions] full-width buttons (auth cards)
 * @property {boolean} [resetOnSuccess]
 * @property {string} [class]
 */

/**
 * @param {any} spec
 * @returns {Control}
 */
function controlFromSpec(spec) {
  switch (spec.type) {
    case 'select': return select(spec);
    case 'toggle':
    case 'switch': return toggle(spec);
    case 'checkbox': return checkbox(spec);
    default: return field(spec);
  }
}

/**
 * @param {FormOpts} opts
 */
export function form(opts) {
  /** @type {Control[]} */
  const controls = [];
  /** @type {Node[]} */
  const nodes = [];
  for (const f of opts.fields) {
    if (f instanceof Node) {
      nodes.push(f);
    } else if (f && typeof f === 'object' && 'el' in f && typeof f.value === 'function') {
      controls.push(/** @type {Control} */ (f));
      nodes.push(/** @type {Control} */ (f).el);
    } else {
      const c = controlFromSpec(f);
      if (!c.name && /** @type {any} */ (f).name) c.name = /** @type {any} */ (f).name;
      controls.push(c);
      nodes.push(c.el);
    }
  }

  const errorBox = h('div', { class: 'form-error', attrs: { role: 'alert' } });
  const submitBtn = button({
    label: opts.submitLabel || 'Save',
    icon: opts.submitIcon,
    variant: opts.submitVariant || 'primary',
    type: 'submit',
  });
  /** @type {HTMLButtonElement | null} */
  let cancelBtn = null;
  if (opts.cancel) {
    const c = opts.cancel;
    const onClick = typeof c === 'function' ? c : c.onClick;
    cancelBtn = button({ label: typeof c === 'function' ? 'Cancel' : c.label || 'Cancel', variant: 'ghost', onClick: () => onClick() });
  }

  const el = h('form', { class: ['form', opts.class || ''], attrs: { novalidate: true } },
    errorBox,
    nodes,
    h('div', { class: ['form-actions', opts.stretchActions && 'form-actions--stretch'] }, cancelBtn, submitBtn));

  /** @param {string | null} msg */
  const setError = (msg) => {
    errorBox.replaceChildren();
    if (msg) errorBox.append(icon('alert-circle'), h('span', { text: msg }));
  };

  const values = () => {
    /** @type {Record<string, any>} */
    const out = {};
    for (const c of controls) if (c.name) out[c.name] = c.value();
    return out;
  };

  let busy = false;
  const submit = async () => {
    if (busy) return;
    setError(null);
    for (const c of controls) c.setError(null);
    // native constraint validation (required, type=email, min/max, pattern) with inline messages
    let firstInvalid = null;
    for (const c of controls) {
      const inp = c.input;
      if (inp && typeof inp.checkValidity === 'function' && !inp.checkValidity()) {
        c.setError(inp.validationMessage);
        firstInvalid = firstInvalid || inp;
      }
    }
    if (firstInvalid) {
      firstInvalid.focus();
      return;
    }
    busy = true;
    setBusy(submitBtn, true);
    try {
      await opts.onSubmit(values());
      if (opts.resetOnSuccess) reset();
    } catch (err) {
      if (err instanceof ApiError && err.aborted) return;
      const msg = err instanceof Error ? err.message : String(err);
      const target = err instanceof ApiError && err.field ? controls.find((c) => c.name === err.field) : undefined;
      if (target) {
        target.setError(msg);
        target.input?.focus();
      } else {
        setError(msg);
      }
    } finally {
      busy = false;
      setBusy(submitBtn, false);
    }
  };

  el.addEventListener('submit', (e) => {
    e.preventDefault();
    submit();
  });

  const reset = () => {
    el.reset();
    setError(null);
    for (const c of controls) c.setError(null);
  };

  /** @type {Record<string, Control>} */
  const byName = {};
  for (const c of controls) if (c.name) byName[c.name] = c;

  return { el, reset, controls: byName, setError, submit, values, submitButton: submitBtn };
}
