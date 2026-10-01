// @ts-check
/**
 * Sharing UI (§9.4 filesapi grants + sharesapi):
 *
 *   openShareDialog(node)                 dialog with people/group access + public links for one node
 *   sharingPanel(node, {onChange})        the same content as an element (details panel "Sharing" tab)
 *   linkDialog({node, share})             create / edit a public link → Promise<Share | null>
 *   requestDialog({folder, share})        create / edit a file request (public upload link) → Promise<Share | null>
 *   shareQRDialog(share)                  QR code + copyable URL (+ native share sheet)
 *   accessLogDialog(share)                GET /shares/{id}/log
 *   shareURL(share) · shareStatus(share) · revokeShare(share)
 *
 * Grants: GET/POST /nodes/{id}/grants, DELETE /nodes/{id}/grants/{gid}; subjects come from GET /users/lookup?q=
 * (≥ 2 characters), the user's groups (GET /groups; with "View people" also GET /admin/groups) and the custom roles
 * (GET /roles, when features.directory: everyone with the role gets the access). Grants inherited from a parent
 * folder are listed but can only be changed on that folder.
 * Links: GET /shares?node_id=&kind=link, POST /shares, PATCH /shares/{id}, DELETE /shares/{id},
 * GET /shares/{id}/qr.svg. The link URL (/s/<token>) is shown to the owner only.
 * @module components/share-dialog
 */
import { h, icon, uniqueId } from '../core/dom.js';
import { api, itemsOf, errorMessage, getAll } from '../core/api.js';
import { canAny, session } from '../core/store.js';
import { bytes, dateTime, relTime, date as fmtDate, number, initials, toDate } from '../core/format.js';
import { can, spaces, spaceLabel } from '../core/nodes.js';
import { dialog, confirm } from './dialog.js';
import { button, iconButton } from './button.js';
import { field, select, toggle } from './field.js';
import { badge } from './badge.js';
import { toast } from './toast.js';
import { copyText, copyField } from './copy-field.js';
import { qrImage } from './qr-image.js';
import { spinner } from './progress.js';
import { table } from './table.js';
import { pickFolder } from './folder-picker.js';
import { boot } from '../core/dom.js';

/**
 * A feature flag (pages.Features): GET /me's copy, which is fresher, else the page boot's.
 * @param {string} name
 * @returns {boolean | undefined}
 */
function feature(name) {
  return session.peek()?.features?.[name] ?? boot().features?.[name];
}

/**
 * @typedef {import('../core/nodes.js').Node} Node
 * @typedef {Object} Share
 * @property {string} id
 * @property {'link' | 'request'} kind
 * @property {string} node_id
 * @property {string} [title]
 * @property {string} [message]
 * @property {boolean} allow_download
 * @property {boolean} allow_preview
 * @property {boolean} allow_upload
 * @property {boolean} require_uploader_name
 * @property {number | null} upload_max_file_bytes
 * @property {number | null} upload_quota_bytes
 * @property {number} upload_used_bytes
 * @property {number | null} max_downloads
 * @property {number} download_count
 * @property {string | null} expires_at
 * @property {boolean} notify_owner
 * @property {string} [disabled_at]
 * @property {string} created_at
 * @property {string} [last_access_at]
 * @property {boolean} has_password
 * @property {string} status active|expired|disabled|exhausted
 * @property {boolean} [unavailable] active, but the item is trashed, the owner disabled or without access to it (view
 *   for a link, edit for a file request): the link answers "not found"
 * @property {string} [url]
 * @property {string} [node_name]
 * @property {string} [node_kind]
 */

/**
 * Absolute URL of a share ("" when the server did not include it).
 * @param {Share} s
 */
export function shareURL(s) {
  if (!s || !s.url) return '';
  try {
    return new URL(s.url, location.origin).href;
  } catch {
    return s.url;
  }
}

const STATUS = {
  active: { text: 'Active', kind: 'success' },
  expired: { text: 'Expired', kind: 'neutral' },
  disabled: { text: 'Disabled', kind: 'neutral' },
  exhausted: { text: 'Limit reached', kind: 'warning' },
};

/**
 * Status badge for a share.
 * @param {Share} s
 */
export function shareStatus(s) {
  const st = /** @type {any} */ (STATUS)[s.status] || { text: s.status || 'Unknown', kind: 'neutral' };
  if (s.kind === 'request' && s.status === 'disabled') return badge({ text: 'Closed', kind: 'neutral' });
  if (s.unavailable) {
    return badge({
      text: 'Unavailable',
      kind: 'warning',
      title: s.kind === 'request'
        ? 'The folder is in the trash, its owner is disabled, or they can no longer add files to it — uploaders get a "not found" page.'
        : 'The shared item is in the trash, its owner is disabled, or they can no longer open it — visitors get a "not found" page.',
    });
  }
  return badge({ text: st.text, kind: st.kind });
}

/**
 * The parts of a share's one-line summary ("Expires in 6 days", "3 of 10 downloads", "Password").
 * @param {Share} s
 * @returns {string[]}
 */
function shareSummaryParts(s) {
  const parts = [];
  if (s.expires_at) {
    const past = Date.parse(s.expires_at) < Date.now();
    parts.push(past ? `Expired ${relTime(s.expires_at)}` : `Expires ${relTime(s.expires_at)}`);
  } else {
    parts.push('No expiry');
  }
  if (s.kind === 'link') {
    parts.push(s.max_downloads ? `${number(s.download_count)} of ${number(s.max_downloads)} downloads` : `${number(s.download_count || 0)} downloads`);
    if (!s.allow_download) parts.push(s.allow_preview ? 'View only' : 'No downloads');
  } else {
    parts.push(`${bytes(s.upload_used_bytes || 0)} received${s.upload_quota_bytes ? ` of ${bytes(s.upload_quota_bytes)}` : ''}`);
  }
  if (s.has_password) parts.push('Password');
  return parts;
}

/**
 * One-line summary of a share's limits as plain text ("Expires in 6 days · 3 of 10 downloads ·
 * Password"), for `title`/aria strings. Use shareSummaryNodes() for anything that is rendered.
 * @param {Share} s
 */
export function shareSummary(s) {
  return shareSummaryParts(s).join(' · ');
}

/**
 * The same summary as nodes: each separator rides with the entry it introduces (one flex item), so a
 * wrap never leaves a dangling "·" at the end of a line. The container needs `display: flex` +
 * `flex-wrap: wrap` and a column gap (`.share-meta`, or `.share-cell-mobile` on phones).
 * @param {Share} s
 * @returns {import('../core/dom.js').Child[]}
 */
export function shareSummaryNodes(s) {
  return shareSummaryParts(s).map((p, i) => (i
    ? h('span', { class: 'share-meta-item' },
      h('span', { class: 'share-meta-sep', attrs: { 'aria-hidden': 'true' }, text: '·' }), p)
    : p));
}

/**
 * Revoke (delete) a share after confirmation. Resolves true when revoked.
 * @param {Share} s
 */
export async function revokeShare(s) {
  const what = s.kind === 'request' ? 'file request' : 'link';
  const ok = await confirm({
    title: `Delete this ${what}?`,
    message: `Anyone with the ${what} will lose access immediately. This can’t be undone — you can create a new ${what} later.`,
    danger: true,
    confirmLabel: `Delete ${what}`,
  });
  if (!ok) return false;
  try {
    await api.del(`/shares/${encodeURIComponent(s.id)}`);
    toast.success(s.kind === 'request' ? 'File request deleted' : 'Link deleted');
    return true;
  } catch (err) {
    toast.error(err);
    return false;
  }
}

// ---------------------------------------------------------------------------------------------------------------
// Expiry control
// ---------------------------------------------------------------------------------------------------------------

/**
 * A date as the YYYY-MM-DD a date input holds, in the browser's time zone. A custom expiry is stored as 23:59:59
 * local time on the chosen day (read() below), i.e. usually the next day in UTC, so toISOString().slice(0, 10)
 * would pre-fill (and bound) the picker a day off anywhere but UTC.
 * @param {Date} d
 */
function localISODate(d) {
  return `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, '0')}-${String(d.getDate()).padStart(2, '0')}`;
}

/**
 * Expiry chooser: server default / 1 / 7 / 30 days / custom date / never.
 * @param {{value?: string | null, isNew: boolean}} o
 */
function expiryControl(o) {
  const presets = [
    ...(o.isNew ? [{ value: 'default', label: 'Default for this server' }] : [{ value: 'keep', label: o.value ? `Keep (${fmtDate(o.value)})` : 'Keep (no expiry)' }]),
    { value: '1', label: 'In 1 day' },
    { value: '7', label: 'In 7 days' },
    { value: '30', label: 'In 30 days' },
    { value: 'custom', label: 'On a date…' },
    { value: 'never', label: 'Never' },
  ];
  const sel = select({ label: 'Expires', options: presets, value: o.isNew ? 'default' : 'keep' });
  const cur = toDate(o.value);
  const dateInput = field({ label: 'Expiry date', type: 'date', hideLabel: true, value: cur ? localISODate(cur) : '' });
  dateInput.el.hidden = true;
  dateInput.input.setAttribute('min', localISODate(new Date()));
  sel.input.addEventListener('change', () => {
    dateInput.el.hidden = sel.value() !== 'custom';
    if (!dateInput.el.hidden) dateInput.input.focus();
  });
  const el = h('div', { class: 'stack-sm' }, sel.el, dateInput.el);
  return {
    el,
    /**
     * @returns {{set: false} | {set: true, value: string | null, never?: boolean}} value = RFC 3339 or null (no expiry)
     */
    read() {
      const v = sel.value();
      if (v === 'default' || v === 'keep') return { set: false };
      if (v === 'never') return { set: true, value: null, never: true };
      if (v === 'custom') {
        const d = dateInput.input.value;
        if (!d) throw Object.assign(new Error('Choose a date.'), { field: 'expires_at' });
        const end = new Date(`${d}T23:59:59`);
        if (end.getTime() <= Date.now()) throw Object.assign(new Error('The date must be in the future.'), { field: 'expires_at' });
        return { set: true, value: end.toISOString() };
      }
      return { set: true, value: new Date(Date.now() + Number(v) * 86_400_000).toISOString() };
    },
    setError: (/** @type {string | null} */ m) => (sel.value() === 'custom' ? dateInput.setError(m) : sel.setError(m)),
  };
}

/**
 * Whether a number input holds text the browser could not parse ("1e", or "1,000" in Firefox/Safari). Its `.value`
 * then reads as "" — indistinguishable from an empty field, i.e. "no limit" — so callers must reject it first.
 * @param {HTMLInputElement | HTMLTextAreaElement | HTMLSelectElement} inp
 */
const badNumber = (inp) => !!(/** @type {HTMLInputElement} */ (inp).validity?.badInput);

/**
 * Read a size limit typed in `unit`s (MiB or GiB, the binary units every size in the app is shown in) as bytes;
 * null = empty (no limit). The field's `min` attribute is enforced (the form is `novalidate`).
 * @param {HTMLInputElement | HTMLTextAreaElement | HTMLSelectElement} inp @param {number} unit
 */
function parseSize(inp, unit) {
  const msg = 'Enter a positive number or leave it empty.';
  if (badNumber(inp)) throw Object.assign(new Error(msg), { bad: true });
  const s = String(inp.value ?? '').trim();
  if (!s) return null;
  const n = Number(s);
  if (!Number.isFinite(n) || n <= 0) throw Object.assign(new Error(msg), { bad: true });
  const min = Number(/** @type {HTMLInputElement} */ (inp).min);
  if (min > 0 && n < min) {
    throw Object.assign(new Error(`Enter at least ${min} ${unit >= 1073741824 ? 'GiB' : 'MiB'}, or leave it empty.`), { bad: true });
  }
  return Math.round(n * unit);
}

/**
 * A stored byte limit in the dialog's unit, for display only: ≥ 1 unit with up to 3 decimals, below that with
 * 3 significant digits, so a small limit never shows as a misleading "0". It is not exact, which is why the edit
 * dialog only sends a limit whose field the user actually changed.
 * @param {number} b @param {number} unit
 */
function sizeInUnit(b, unit) {
  const v = b / unit;
  return v >= 1 ? +v.toFixed(3) : +v.toPrecision(3);
}

/**
 * Put a server-side field error where the user can actually see it.
 *
 * The obvious `map[err.field].setError(…)` swallows the message whenever that control is hidden — the password field
 * is hidden while "Require a password" is off, which is exactly the state that provokes
 * `sharing.require_password` → 422 {field: "password"}. Such a control is revealed first when the caller knows how
 * (`reveal`), and anything still invisible falls back to the dialog's always-visible error box.
 * @param {HTMLElement} errBox
 * @param {Record<string, {el: HTMLElement, setError: (msg?: string | null) => void, reveal?: () => void} | undefined>} map
 * @param {unknown} err
 */
function reportFieldError(errBox, map, err) {
  const msg = errorMessage(err);
  const target = map[String(/** @type {any} */ (err)?.field || '')];
  if (target) {
    if (target.el.hidden) target.reveal?.();
    if (!target.el.hidden) {
      target.setError(msg);
      /** @type {HTMLElement | null} */ (target.el.querySelector('input, textarea, select'))?.focus();
      return;
    }
  }
  errBox.replaceChildren(icon('alert-circle'), h('span', { text: msg }));
}

/**
 * Show the created link with copy + QR.
 * @param {Share} s
 * @param {string} heading
 */
function linkReadyBody(s, heading) {
  const url = shareURL(s);
  // Tailscale Funnel publishes share links on the internet (features.internet_links; /me is fresher than the boot).
  const internet = url && !!(session.peek()?.features?.internet_links ?? boot().features.internet_links);
  return h('div', { class: 'share-ready' },
    h('div', { class: 'share-ready-head' }, h('span', { class: 'share-ready-icon' }, icon('check-circle')), h('strong', { text: heading })),
    url ? copyField({ value: url, label: 'Link', what: 'Link' }) : h('p', { class: 'muted', text: 'The link was created. Open “My links” to copy it.' }),
    internet ? h('p', { class: 'alert alert--info share-internet', attrs: { role: 'note' } }, icon('globe'),
      h('span', { text: 'Anyone with this link can open it from the internet (Tailscale Funnel).' })) : null,
    url ? h('div', { class: 'share-ready-qr' }, qrImage({ src: `/api/v1/shares/${encodeURIComponent(s.id)}/qr.svg`, alt: 'QR code for the link', size: 180 }),
      h('p', { class: 'muted text-sm', text: 'Scan with a phone camera to open the link.' })) : null);
}

// ---------------------------------------------------------------------------------------------------------------
// Link dialog (create / edit)
// ---------------------------------------------------------------------------------------------------------------

/**
 * @param {{node?: Node | null, share?: Share | null}} o
 * @returns {Promise<Share | null>}
 */
export function linkDialog(o) {
  const edit = o.share || null;
  const isNew = !edit;
  return new Promise((resolve) => {
    /** @type {Share | null} */
    let result = null;
    const title = field({ label: 'Title (optional)', value: edit?.title || '', placeholder: o.node?.name || '', maxlength: 200, help: 'Shown to visitors instead of the file name.' });
    const message = field({ label: 'Message (optional)', type: 'textarea', rows: 2, value: edit?.message || '', maxlength: 2000 });
    const expiry = expiryControl({ value: edit?.expires_at, isNew });
    const pwToggle = toggle({ label: 'Require a password', checked: !!edit?.has_password, help: edit?.has_password ? 'A password is set. Enter a new one to change it.' : 'Visitors must enter it before they see anything.' });
    const pw = field({ label: 'Password', type: 'password', autocomplete: 'new-password', hideLabel: true, placeholder: edit?.has_password ? 'Leave empty to keep the current password' : 'Password' });
    // sharing.require_password: the server rejects a new link without one, so
    // say so here instead of letting the user submit and read a 422.
    const pwRequired = !edit && !!boot().features.share_password_required;
    if (pwRequired) {
      pwToggle.input.checked = true;
      pwToggle.input.disabled = true;
    }
    pw.el.hidden = !pwToggle.input.checked;
    pwToggle.input.addEventListener('change', () => {
      pw.el.hidden = !pwToggle.input.checked;
      if (!pw.el.hidden) pw.input.focus();
    });
    // The server may demand a password (sharing.require_password): turn the option on so its error is visible and
    // the user can act on it without hunting for the toggle.
    const revealPassword = () => {
      pwToggle.input.checked = true;
      pw.el.hidden = false;
    };
    const maxDl = field({ label: 'Download limit (optional)', type: 'number', min: 1, value: edit?.max_downloads ?? '', placeholder: 'Unlimited', inputmode: 'numeric', help: 'Counts downloads only; previews do not count.' });
    const allowDl = toggle({ label: 'Allow downloads', checked: edit ? edit.allow_download : true });
    const allowPv = toggle({ label: 'Allow previews', checked: edit ? edit.allow_preview : true, help: 'Visitors can view images, videos and documents in the browser.' });
    const disabled = edit ? toggle({ label: 'Link enabled', checked: !edit.disabled_at && edit.status !== 'disabled', help: 'Turn off to pause the link without deleting it.' }) : null;
    const errBox = h('div', { class: 'form-error', attrs: { role: 'alert' } });
    const formEl = h('form', { class: 'form', attrs: { novalidate: true } },
      errBox, title.el, message.el, expiry.el, pwToggle.el, pw.el, maxDl.el, allowDl.el, allowPv.el, disabled ? disabled.el : null);
    const body = h('div', { class: 'stack' },
      o.node ? h('div', { class: 'share-target' }, icon(o.node.kind === 'folder' ? 'folder' : 'file'), h('span', { class: 'truncate', text: o.node.name })) : null,
      o.node?.zip_encryption ? h('p', { class: 'alert alert--info', text: 'This .zip has its own password. People need it after downloading, so send it separately (not in the same message as the link). “Require a password” below is a different lock, for opening the link.' }) : null,
      formEl);

    const submit = async () => {
      errBox.replaceChildren();
      for (const c of [title, message, pw, maxDl]) c.setError(null);
      expiry.setError(null);
      /** @type {Record<string, any>} */
      const input = {};
      try {
        const exp = expiry.read();
        // Text the browser cannot parse reads as "" (= no limit): reject it instead of silently lifting the limit.
        const md = badNumber(maxDl.input) ? NaN : maxDl.value();
        if (md !== null && (!Number.isInteger(md) || md < 1)) {
          maxDl.setError('Enter a whole number, or leave it empty for no limit.');
          return false;
        }
        if (isNew) {
          Object.assign(input, { kind: 'link', node_id: o.node?.id, allow_download: allowDl.value(), allow_preview: allowPv.value() });
          if (String(title.value()).trim()) input.title = String(title.value()).trim();
          if (String(message.value()).trim()) input.message = String(message.value()).trim();
          if (md !== null) input.max_downloads = md;
          if (exp.set) {
            if (exp.never) input.no_expiry = true;
            else input.expires_at = exp.value;
          }
          if (pwToggle.value()) {
            if (!String(pw.value())) {
              pw.setError(pwRequired ? 'This server requires a password.' : 'Enter a password, or turn the option off.');
              return false;
            }
            input.password = String(pw.value());
          }
        } else {
          const e = /** @type {Share} */ (edit);
          if ((e.title || '') !== String(title.value()).trim()) input.title = String(title.value()).trim();
          if ((e.message || '') !== String(message.value()).trim()) input.message = String(message.value()).trim();
          if (e.allow_download !== allowDl.value()) input.allow_download = allowDl.value();
          if (e.allow_preview !== allowPv.value()) input.allow_preview = allowPv.value();
          if ((e.max_downloads ?? null) !== md) input.max_downloads = md;
          if (exp.set) input.expires_at = exp.value;
          if (pwToggle.value() && String(pw.value())) input.password = String(pw.value());
          else if (!pwToggle.value() && e.has_password) input.password = '';
          else if (pwToggle.value() && !e.has_password && !String(pw.value())) {
            pw.setError('Enter a password, or turn the option off.');
            return false;
          }
          if (disabled && disabled.value() === (!!e.disabled_at || e.status === 'disabled')) input.disabled = !disabled.value();
        }
      } catch (err) {
        if (/** @type {any} */ (err).field === 'expires_at') expiry.setError(/** @type {Error} */ (err).message);
        else errBox.append(icon('alert-circle'), h('span', { text: errorMessage(err) }));
        return false;
      }
      try {
        if (isNew) {
          result = await api.post('/shares', input);
          d.setTitle('Link created');
          body.replaceChildren(linkReadyBody(/** @type {Share} */ (result), 'Anyone with this link can open it.'));
          d.actions.replaceChildren(
            button({ label: 'Copy link', icon: 'copy', variant: 'secondary', onClick: () => copyText(shareURL(/** @type {Share} */ (result)), 'Link') }),
            button({ label: 'Done', variant: 'primary', onClick: () => d.close(result) }));
          /** @type {HTMLElement | null} */ (d.actions.lastElementChild)?.focus();
          return false;
        }
        result = Object.keys(input).length ? await api.patch(`/shares/${encodeURIComponent(/** @type {Share} */ (edit).id)}`, input) : edit;
        toast.success('Link updated');
        return true;
      } catch (err) {
        const f = /** @type {any} */ (err)?.field;
        if (f === 'expires_at' || f === 'no_expiry') expiry.setError(errorMessage(err));
        else reportFieldError(errBox, { title, message, password: { el: pw.el, setError: pw.setError, reveal: revealPassword }, max_downloads: maxDl }, err);
        return false;
      }
    };
    formEl.addEventListener('submit', (e) => {
      e.preventDefault();
      submit().then((ok) => { if (ok) d.close(result); });
    });
    const d = dialog({
      title: isNew ? 'Create a public link' : 'Edit link',
      size: 'md',
      body,
      onClose: () => resolve(result),
      actions: [
        { label: 'Cancel', variant: 'ghost' },
        { label: isNew ? 'Create link' : 'Save', variant: 'primary', icon: isNew ? 'link' : undefined, onClick: async () => ((await submit()) ? result : false) },
      ],
    });
    d.open();
    title.input.focus();
  });
}

// ---------------------------------------------------------------------------------------------------------------
// File request dialog (create / edit)
// ---------------------------------------------------------------------------------------------------------------

/**
 * @param {{folder?: Node | null, share?: Share | null}} o
 * @returns {Promise<Share | null>}
 */
export function requestDialog(o) {
  const edit = o.share || null;
  const isNew = !edit;
  return new Promise((resolve) => {
    /** @type {Share | null} */
    let result = null;
    /** @type {Node | null} */
    let folder = o.folder && o.folder.kind === 'folder' ? o.folder : null;
    const folderName = h('span', { class: 'truncate', text: folder ? folder.name : edit?.node_name || 'Choose a folder…' });
    const folderBtn = isNew
      ? h('button', {
        class: 'btn btn--secondary share-folder-btn',
        attrs: { type: 'button' },
        on: {
          click: async () => {
            const f = await pickFolder({ title: 'Where should uploads go?', confirmLabel: 'Use this folder', start: folder, need: 'manage' });
            if (f) {
              folder = f;
              folderName.textContent = f.name;
              folderErr.textContent = '';
            }
          },
        },
      }, icon('folder'), folderName, icon('chevron-right'))
      : h('div', { class: 'share-target' }, icon('folder'), folderName);
    const folderErr = h('p', { class: 'field-error', attrs: { 'aria-live': 'polite' } });
    const title = field({ label: 'Title', value: edit?.title || '', placeholder: 'e.g. Photos from the wedding', maxlength: 200, required: isNew });
    const message = field({ label: 'Message for uploaders (optional)', type: 'textarea', rows: 3, value: edit?.message || '', maxlength: 2000 });
    const requireName = toggle({ label: 'Ask for the uploader’s name', checked: edit ? edit.require_uploader_name : true });
    const maxFile = field({ label: 'Maximum file size in MiB (optional)', type: 'number', min: 1, step: 'any', inputmode: 'decimal', placeholder: 'No limit', value: edit?.upload_max_file_bytes ? sizeInUnit(edit.upload_max_file_bytes, 1048576) : '' });
    const quota = field({ label: 'Total upload limit in GiB (optional)', type: 'number', min: 0.1, step: 'any', inputmode: 'decimal', placeholder: 'No limit', value: edit?.upload_quota_bytes ? sizeInUnit(edit.upload_quota_bytes, 1073741824) : '' });
    const expiry = expiryControl({ value: edit?.expires_at, isNew });
    const notify = toggle({ label: 'Email me when files arrive', checked: edit ? edit.notify_owner : false, help: 'Needs e-mail to be configured by the administrator.' });
    const pwToggle = toggle({ label: 'Require a password', checked: !!edit?.has_password });
    const pw = field({ label: 'Password', type: 'password', autocomplete: 'new-password', hideLabel: true, placeholder: edit?.has_password ? 'Leave empty to keep the current password' : 'Password' });
    // sharing.require_password: the server rejects a new link without one, so
    // say so here instead of letting the user submit and read a 422.
    const pwRequired = !edit && !!boot().features.share_password_required;
    if (pwRequired) {
      pwToggle.input.checked = true;
      pwToggle.input.disabled = true;
    }
    pw.el.hidden = !pwToggle.input.checked;
    pwToggle.input.addEventListener('change', () => { pw.el.hidden = !pwToggle.input.checked; });
    // See the link dialog: sharing.require_password rejects a request without one, so the hidden field is revealed
    // before its error is shown.
    const revealPassword = () => {
      pwToggle.input.checked = true;
      pw.el.hidden = false;
    };
    const open = edit ? toggle({ label: 'Accepting uploads', checked: !edit.disabled_at && edit.status !== 'disabled', help: 'Turn off to close the request without deleting it.' }) : null;
    const errBox = h('div', { class: 'form-error', attrs: { role: 'alert' } });
    const formEl = h('form', { class: 'form', attrs: { novalidate: true } },
      errBox,
      h('div', { class: 'field' }, h('span', { class: 'field-label', text: 'Destination folder' }), folderBtn, folderErr),
      title.el, message.el, requireName.el, h('div', { class: 'grid-2 share-limits' }, maxFile.el, quota.el), expiry.el, pwToggle.el, pw.el, notify.el, open ? open.el : null,
      h('p', { class: 'muted text-xs', text: 'Uploaders can only add files. They can’t see, download or change anything in the folder.' }));
    const body = h('div', { class: 'stack' }, formEl);

    const submit = async () => {
      errBox.replaceChildren();
      folderErr.textContent = '';
      for (const c of [title, maxFile, quota, pw]) c.setError(null);
      expiry.setError(null);
      /** @type {Record<string, any>} */
      const input = {};
      // The edit form shows the stored byte limits rounded to MiB/GiB, so an untouched field is never re-parsed
      // (undefined = leave the limit alone): saving an unrelated change must not move a limit, and a small limit
      // shown approximately must not block the save. `defaultValue` is the value the field was built with.
      /** @param {import('./field.js').Control} c */
      const edited = (c) => isNew || badNumber(c.input) || c.input.value !== /** @type {HTMLInputElement} */ (c.input).defaultValue;
      /** @type {number | null | undefined} */
      let mf;
      /** @type {number | null | undefined} */
      let qt;
      try {
        try { if (edited(maxFile)) mf = parseSize(maxFile.input, 1048576); } catch (e) { maxFile.setError(/** @type {Error} */ (e).message); return false; }
        try { if (edited(quota)) qt = parseSize(quota.input, 1073741824); } catch (e) { quota.setError(/** @type {Error} */ (e).message); return false; }
        const exp = expiry.read();
        if (isNew) {
          if (!folder) {
            folderErr.textContent = 'Choose the folder that will receive the files.';
            return false;
          }
          if (!String(title.value()).trim()) {
            title.setError('Give the request a title so uploaders know what it is for.');
            return false;
          }
          Object.assign(input, {
            kind: 'request',
            node_id: folder.id,
            title: String(title.value()).trim(),
            allow_upload: true,
            allow_download: false,
            allow_preview: false,
            require_uploader_name: requireName.value(),
            notify_owner: notify.value(),
          });
          if (String(message.value()).trim()) input.message = String(message.value()).trim();
          if (mf != null) input.upload_max_file_bytes = mf;
          if (qt != null) input.upload_quota_bytes = qt;
          if (exp.set) {
            if (exp.never) input.no_expiry = true;
            else input.expires_at = exp.value;
          }
          if (pwToggle.value()) {
            if (!String(pw.value())) {
              pw.setError(pwRequired ? 'This server requires a password.' : 'Enter a password, or turn the option off.');
              return false;
            }
            input.password = String(pw.value());
          }
        } else {
          const e = /** @type {Share} */ (edit);
          if ((e.title || '') !== String(title.value()).trim()) input.title = String(title.value()).trim();
          if ((e.message || '') !== String(message.value()).trim()) input.message = String(message.value()).trim();
          if (e.require_uploader_name !== requireName.value()) input.require_uploader_name = requireName.value();
          if (e.notify_owner !== notify.value()) input.notify_owner = notify.value();
          if (mf !== undefined && (e.upload_max_file_bytes ?? null) !== mf) input.upload_max_file_bytes = mf;
          if (qt !== undefined && (e.upload_quota_bytes ?? null) !== qt) input.upload_quota_bytes = qt;
          if (exp.set) input.expires_at = exp.value;
          if (pwToggle.value() && String(pw.value())) input.password = String(pw.value());
          else if (!pwToggle.value() && e.has_password) input.password = '';
          else if (pwToggle.value() && !e.has_password && !String(pw.value())) {
            pw.setError('Enter a password, or turn the option off.');
            return false;
          }
          if (open && open.value() === (!!e.disabled_at || e.status === 'disabled')) input.disabled = !open.value();
        }
      } catch (err) {
        if (/** @type {any} */ (err).field === 'expires_at') expiry.setError(/** @type {Error} */ (err).message);
        else errBox.append(icon('alert-circle'), h('span', { text: errorMessage(err) }));
        return false;
      }
      try {
        if (isNew) {
          result = await api.post('/shares', input);
          d.setTitle('File request created');
          body.replaceChildren(linkReadyBody(/** @type {Share} */ (result), 'Send this link to the people who should upload files.'));
          d.actions.replaceChildren(
            button({ label: 'Copy link', icon: 'copy', variant: 'secondary', onClick: () => copyText(shareURL(/** @type {Share} */ (result)), 'Link') }),
            button({ label: 'Done', variant: 'primary', onClick: () => d.close(result) }));
          /** @type {HTMLElement | null} */ (d.actions.lastElementChild)?.focus();
          return false;
        }
        result = Object.keys(input).length ? await api.patch(`/shares/${encodeURIComponent(/** @type {Share} */ (edit).id)}`, input) : edit;
        toast.success('File request updated');
        return true;
      } catch (err) {
        const f = /** @type {any} */ (err)?.field;
        if (f === 'node_id') folderErr.textContent = errorMessage(err);
        else if (f === 'expires_at' || f === 'no_expiry') expiry.setError(errorMessage(err));
        else {
          reportFieldError(errBox, {
            title, upload_max_file_bytes: maxFile, upload_quota_bytes: quota,
            password: { el: pw.el, setError: pw.setError, reveal: revealPassword },
          }, err);
        }
        return false;
      }
    };
    formEl.addEventListener('submit', (e) => {
      e.preventDefault();
      submit().then((ok) => { if (ok) d.close(result); });
    });
    const d = dialog({
      title: isNew ? 'New file request' : 'Edit file request',
      size: 'md',
      body,
      onClose: () => resolve(result),
      actions: [
        { label: 'Cancel', variant: 'ghost' },
        { label: isNew ? 'Create request' : 'Save', variant: 'primary', icon: isNew ? 'inbox' : undefined, onClick: async () => ((await submit()) ? result : false) },
      ],
    });
    d.open();
    (isNew && !folder ? /** @type {HTMLElement} */ (folderBtn) : title.input).focus();
  });
}

// ---------------------------------------------------------------------------------------------------------------
// QR + access log
// ---------------------------------------------------------------------------------------------------------------

/**
 * @param {Share} s
 */
export function shareQRDialog(s) {
  const url = shareURL(s);
  const nav = /** @type {any} */ (navigator);
  const canShare = typeof nav.share === 'function' && window.isSecureContext;
  dialog({
    title: s.title || s.node_name || (s.kind === 'request' ? 'File request' : 'Link'),
    size: 'sm',
    body: h('div', { class: 'share-qr' },
      qrImage({ src: `/api/v1/shares/${encodeURIComponent(s.id)}/qr.svg`, alt: `QR code for ${url || 'the link'}`, size: 220 }),
      url ? copyField({ value: url, label: 'Link', what: 'Link' }) : null,
      h('p', { class: 'muted text-sm share-meta' }, shareSummaryNodes(s))),
    actions: [
      canShare && url ? { label: 'Share…', icon: 'share', variant: 'secondary', close: false, onClick: () => { nav.share({ title: s.title || s.node_name || 'FileParcel', url }).catch(() => {}); } } : null,
      url ? h('a', { class: 'btn btn--secondary', href: url, attrs: { target: '_blank', rel: 'noopener', 'data-native': true } }, icon('external'), h('span', { text: 'Open' })) : null,
      { label: 'Close', variant: 'primary' },
    ].filter(Boolean),
  }).open();
}

const ACTION_LABELS = {
  view: 'Opened', preview: 'Previewed', download: 'Downloaded', zip: 'Downloaded as archive', upload: 'Uploaded',
  password_ok: 'Entered the password', password_fail: 'Wrong password', blocked: 'Blocked',
};

/** Short browser/OS summary of a user agent string. @param {string} ua */
export function shortUA(ua) {
  if (!ua) return '—';
  const os = /iPhone|iPad/.test(ua) ? 'iOS' : /Android/.test(ua) ? 'Android' : /Mac OS X|Macintosh/.test(ua) ? 'macOS' : /Windows/.test(ua) ? 'Windows' : /Linux/.test(ua) ? 'Linux' : '';
  const br = /Edg\//.test(ua) ? 'Edge' : /Firefox\//.test(ua) ? 'Firefox' : /Chrome\//.test(ua) ? 'Chrome' : /Safari\//.test(ua) ? 'Safari' : /curl|wget/i.test(ua) ? ua.split(' ')[0] : 'Browser';
  return os ? `${br} on ${os}` : br;
}

/**
 * @param {Share} s
 */
export function accessLogDialog(s) {
  const t = table({
    caption: 'Access log',
    columns: [
      { key: 'at', label: 'When', render: (r) => h('span', { attrs: { title: dateTime(r.at) }, text: relTime(r.at) }) },
      {
        key: 'action',
        label: 'What',
        render: (r) => h('span', { class: r.action === 'password_fail' || r.action === 'blocked' ? 'danger-text' : '' },
          /** @type {any} */ (ACTION_LABELS)[r.action] || r.action, r.uploader ? ` · ${r.uploader}` : '', r.bytes ? ` · ${bytes(r.bytes)}` : ''),
      },
      { key: 'ip', label: 'IP address', class: 'mono', hideBelow: 'sm' },
      { key: 'user_agent', label: 'Device', hideBelow: 'sm', render: (r) => h('span', { attrs: { title: r.user_agent || '' }, text: shortUA(r.user_agent || '') }) },
    ],
    loading: true,
    rowKey: (r) => String(r.id ?? `${r.at}-${r.action}`),
    empty: 'Nobody has used this link yet.',
  });
  const more = button({ label: 'Load more', variant: 'secondary', size: 'sm', onClick: () => load() });
  more.hidden = true;
  /** @type {any[]} */
  let rows = [];
  let cursor = '';
  const load = async () => {
    try {
      const page = await api.get(`/shares/${encodeURIComponent(s.id)}/log`, { query: { limit: 100, cursor: cursor || undefined } });
      rows = rows.concat(itemsOf(page));
      cursor = page?.next_cursor || '';
      t.setRows(rows);
      more.hidden = !cursor;
    } catch (err) {
      t.setRows([]);
      toast.error(err);
    }
  };
  dialog({
    title: `Access log — ${s.title || s.node_name || 'link'}`,
    size: 'lg',
    body: h('div', { class: 'stack' }, h('p', { class: 'muted text-sm share-meta' }, shareSummaryNodes(s)), t.el, h('div', { class: 'cluster' }, more)),
    actions: [{ label: 'Close', variant: 'primary' }],
  }).open();
  load();
}

// ---------------------------------------------------------------------------------------------------------------
// Grants (people & groups)
// ---------------------------------------------------------------------------------------------------------------

/**
 * @typedef {{type: 'user' | 'group' | 'role', id: string, name: string, sub?: string}} Subject
 */

/** @type {Promise<Subject[]> | null} */
let groupCache = null;
/** @returns {Promise<Subject[]>} */
function groupSubjects() {
  if (!groupCache) {
    groupCache = (async () => {
      /** @type {Map<string, Subject>} */
      const out = new Map();
      try {
        for (const g of itemsOf(await api.get('/groups', { handle: false }))) out.set(g.id, { type: 'group', id: g.id, name: g.name, sub: `${number(g.member_count || 0)} members` });
      } catch { /* none */ }
      // every group, not only your own, for roles that see people ("View people")
      if (canAny(['users.view'])) {
        try {
          for (const g of await getAll('/admin/groups', { handle: false, max: 1000 })) out.set(g.id, { type: 'group', id: g.id, name: g.name, sub: `${number(g.member_count || 0)} members` });
        } catch { /* not allowed */ }
      }
      return [...out.values()].sort((a, b) => a.name.localeCompare(b.name));
    })();
    setTimeout(() => { groupCache = null; }, 60_000);
  }
  return groupCache;
}

/** @type {Promise<Subject[]> | null} */
let roleCache = null;
/**
 * The custom roles as share subjects (GET /roles, core.RoleRef). The list needs the user directory
 * (features.directory: "Find people and roles" or "View people"); built-in roles are never subjects (share with a
 * group instead).
 * @returns {Promise<Subject[]>}
 */
function roleSubjects() {
  const directory = session.peek()?.features?.directory ?? boot().features?.directory;
  if (!directory) return Promise.resolve([]);
  if (!roleCache) {
    roleCache = api.get('/roles', { handle: false })
      .then((res) => itemsOf(res).map((r) => ({ type: /** @type {const} */ ('role'), id: r.id, name: r.name, sub: 'Role · everyone with this role' })))
      .catch(() => [])
      .then((list) => list.sort((a, b) => a.name.localeCompare(b.name)));
    setTimeout(() => { roleCache = null; }, 60_000);
  }
  return roleCache;
}

/**
 * Avatar of a share subject: initials for a person, an icon for a group or a role.
 * @param {'user' | 'group' | 'role' | string} type
 * @param {string} name
 */
function subjectAvatar(type, name) {
  return h('span', { class: 'avatar avatar--sm', dataset: { type } },
    type === 'group' ? icon('users', { size: 14 }) : type === 'role' ? icon('shield', { size: 14 }) : initials(name));
}

/**
 * Accessible autocomplete for users (GET /users/lookup) and groups.
 * @param {(s: Subject) => void} onPick
 */
function subjectPicker(onPick) {
  const id = uniqueId('subj');
  const listId = `${id}-list`;
  // People and roles need the user directory ("Find people and roles" or "View people"); without it GET /users/lookup
  // and GET /roles answer 403, so only the caller's own groups are offered.
  const directory = feature('directory') !== false;
  const input = h('input', {
    id,
    attrs: {
      type: 'text', role: 'combobox', 'aria-expanded': 'false', 'aria-controls': listId, 'aria-autocomplete': 'list',
      placeholder: directory ? 'Add people, groups or roles' : 'Add one of your groups', autocomplete: 'off', spellcheck: 'false',
    },
  });
  const listEl = h('ul', { class: 'subject-list', id: listId, attrs: { role: 'listbox', 'aria-label': 'Suggestions' }, hidden: true });
  /** @type {Subject[]} */
  let options = [];
  let active = -1;
  let timer = 0;
  let seq = 0;

  const close = () => {
    listEl.hidden = true;
    input.setAttribute('aria-expanded', 'false');
    input.removeAttribute('aria-activedescendant');
    active = -1;
  };
  const render = () => {
    listEl.replaceChildren(...options.map((o, i) => h('li', {
      id: `${listId}-${i}`,
      class: 'subject-option',
      attrs: { role: 'option', 'aria-selected': String(i === active) },
      on: { mousedown: (e) => e.preventDefault(), click: () => choose(i) },
    }, subjectAvatar(o.type, o.name),
    h('span', { class: 'subject-text' }, h('span', { class: 'truncate', text: o.name }), o.sub ? h('small', { class: 'muted truncate', text: o.sub }) : null))));
    if (!options.length) {
      listEl.appendChild(h('li', { class: 'subject-empty muted', attrs: { role: 'presentation' }, text: !directory
        ? 'No matching group. Your role can’t search for people or roles, only the groups you belong to.'
        : input.value.trim().length < 2 ? 'Type at least 2 characters' : 'No matches' }));
    }
    listEl.hidden = false;
    input.setAttribute('aria-expanded', 'true');
    if (active >= 0) input.setAttribute('aria-activedescendant', `${listId}-${active}`);
    else input.removeAttribute('aria-activedescendant');
  };
  /** @param {number} i */
  const choose = (i) => {
    const o = options[i];
    if (!o) return;
    input.value = '';
    close();
    onPick(o);
  };
  /** @param {boolean} [auto] true when triggered by focus rather than by typing or the arrow keys */
  const search = async (auto = false) => {
    const q = input.value.trim();
    const my = ++seq;
    const [allGroups, allRoles] = await Promise.all([groupSubjects(), roleSubjects()]);
    const groups = allGroups.filter((g) => g.name.toLowerCase().includes(q.toLowerCase()));
    const roles = allRoles.filter((r) => r.name.toLowerCase().includes(q.toLowerCase()));
    /** @type {Subject[]} */
    let users = [];
    if (q.length >= 2 && directory) {
      try {
        const me = session.peek()?.user?.id;
        users = itemsOf(await api.get('/users/lookup', { query: { q }, handle: false }))
          .filter((u) => u.id !== me)
          .map((u) => ({ type: /** @type {const} */ ('user'), id: u.id, name: u.display_name || u.username, sub: u.display_name ? `@${u.username}` : '' }));
      } catch { /* keep groups */ }
    }
    if (my !== seq) return;
    // Focus left while the lookup was in flight (the blur close already ran): nothing would close a popup opened
    // now, and it would sit over the access list below with live options.
    if (document.activeElement !== input) { close(); return; }
    options = [...users, ...(q ? groups : groups.slice(0, 8)), ...(q ? roles : roles.slice(0, 4))].slice(0, 20);
    active = options.length ? 0 : -1;
    // The dialog autofocuses this combobox: with nothing to suggest yet, an open popup would only say
    // "Type at least 2 characters" while covering the access text behind it. Typing or ArrowDown still opens it.
    if (auto && !options.length) { close(); return; }
    render();
  };
  input.addEventListener('input', () => {
    clearTimeout(timer);
    timer = window.setTimeout(() => search(), 180);
  });
  input.addEventListener('focus', () => { if (!input.value) search(true); });
  input.addEventListener('blur', () => {
    clearTimeout(timer); // a debounced search still pending must not start once focus has gone
    setTimeout(close, 120);
  });
  input.addEventListener('keydown', (e) => {
    if (listEl.hidden && (e.key === 'ArrowDown' || e.key === 'ArrowUp')) { search(); return; }
    if (e.key === 'ArrowDown') { e.preventDefault(); active = options.length ? (active + 1) % options.length : -1; render(); }
    else if (e.key === 'ArrowUp') { e.preventDefault(); active = options.length ? (active - 1 + options.length) % options.length : -1; render(); }
    else if (e.key === 'Enter') { if (!listEl.hidden && active >= 0) { e.preventDefault(); choose(active); } }
    else if (e.key === 'Escape' && !listEl.hidden) { e.preventDefault(); e.stopPropagation(); close(); }
  });
  return {
    el: h('div', { class: 'subject-picker' }, h('label', { class: 'sr-only', for: id, text: directory ? 'Add people, groups or roles' : 'Add one of your groups' }), icon('user-plus', { class: 'subject-picker-icon' }), input, listEl),
    input,
  };
}

/**
 * @param {Node} node
 * @param {{onChange?: () => void}} [o]
 */
function grantsSection(node, o = {}) {
  const canManage = can(node, 'manage');
  const listEl = h('ul', { class: 'grant-list', attrs: { role: 'list' } }, h('li', { class: 'grant-loading' }, spinner()));
  const roleOptions = [{ value: 'viewer', label: 'Can view' }, { value: 'editor', label: 'Can edit' }, { value: 'manager', label: 'Can manage' }];
  /** @type {Record<string, string>} */
  const granted = { viewer: 'can now view', editor: 'can now edit', manager: 'can now manage' };
  /** @type {Record<string, string>} */
  const subjectKind = { user: 'Person', group: 'Group', role: 'Role' };

  /** @param {any} g */
  const grantRow = (g) => {
    const inherited = g.node_id && g.node_id !== node.id;
    const name = g.subject_name || g.subject_id;
    const roleSel = h('select', {
      class: 'grant-role',
      attrs: { 'aria-label': `Access for ${name}` },
      disabled: !canManage || inherited,
      on: {
        change: async () => {
          try {
            const saved = await api.post(`/nodes/${encodeURIComponent(node.id)}/grants`, { subject_type: g.subject_type, subject_id: g.subject_id, role: roleSel.value, expires_at: g.expires_at || undefined });
            // Remember the role the server now holds: a later failed change reverts the select to it, not to the
            // role this row was built with.
            g.role = saved?.role || roleSel.value;
            toast.success(`${name} ${granted[roleSel.value] || 'can now view'}`);
            o.onChange?.();
          } catch (err) {
            roleSel.value = g.role;
            toast.error(err);
          }
        },
      },
    }, roleOptions.map((r) => h('option', { attrs: { value: r.value }, text: r.label, selected: r.value === g.role })));
    return h('li', { class: 'grant-row' },
      subjectAvatar(g.subject_type, name),
      h('span', { class: 'grant-text' },
        h('span', { class: 'truncate', text: name }),
        h('small', { class: 'muted', text: [subjectKind[g.subject_type] || 'Person', inherited ? 'inherited from a parent folder' : '', g.expires_at ? `until ${fmtDate(g.expires_at)}` : ''].filter(Boolean).join(' · ') })),
      roleSel,
      canManage && !inherited
        ? iconButton({
          icon: 'x',
          label: `Remove ${name}`,
          size: 'sm',
          onClick: async () => {
            try {
              await api.del(`/nodes/${encodeURIComponent(node.id)}/grants/${encodeURIComponent(g.id)}`);
              toast.success(`Removed ${name}`);
              await load();
              o.onChange?.();
            } catch (err) {
              toast.error(err);
            }
          },
        })
        : h('span'));
  };

  /** @type {any[]} the grants listed last (the picker keeps the expiry of a subject that already has one here) */
  let current = [];
  const load = async () => {
    try {
      const grants = itemsOf(await api.get(`/nodes/${encodeURIComponent(node.id)}/grants`));
      current = grants;
      listEl.replaceChildren(...grants.map(grantRow));
      if (!grants.length) listEl.appendChild(h('li', { class: 'grant-empty muted text-sm', text: 'Only you (and the members of this space) have access.' }));
    } catch (err) {
      listEl.replaceChildren(h('li', { class: 'danger-text text-sm', text: errorMessage(err) }));
    }
  };

  const roleSel = select({ label: 'Access', hideLabel: true, options: roleOptions, value: 'viewer' });
  const picker = subjectPicker(async (s) => {
    try {
      // Adding someone who already has a grant here changes its level. POST replaces the grant, expiry included, so
      // send the current expiry along: re-adding a person must not turn temporary access into permanent access.
      const existing = current.find((g) => g.node_id === node.id && g.subject_type === s.type && g.subject_id === s.id);
      await api.post(`/nodes/${encodeURIComponent(node.id)}/grants`, { subject_type: s.type, subject_id: s.id, role: roleSel.value(), expires_at: existing?.expires_at || undefined });
      toast.success(`Shared with ${s.name}`);
      await load();
      o.onChange?.();
    } catch (err) {
      toast.error(err);
    }
  });
  // Listing grants needs manage permission too (§6 permission model: PermManage = grants + shares), so like the links
  // section below, everyone else gets a note instead of a request that can only fail with 403.
  if (canManage) load();
  return h('section', { class: 'share-section' },
    h('h3', { class: 'share-section-title' }, icon('users', { size: 18 }), h('span', { text: 'People, groups and roles' })),
    canManage ? h('div', { class: 'grant-add' }, picker.el, roleSel.el) : h('p', { class: 'muted text-sm', text: 'Only people who manage this item can see and change who has access.' }),
    canManage ? h('p', { class: 'muted text-xs grant-help', text: 'Can manage: can also share this item and create links for it.' }) : null,
    canManage ? listEl : null);
}

/**
 * @param {Node} node
 * @param {{onChange?: () => void}} [o]
 */
function linksSection(node, o = {}) {
  const enabled = feature('links') !== false;
  // features.links is off when the server setting is off or when the role lacks "Create share links": say which
  const roleMay = canAny(['shares.links']);
  const canManage = can(node, 'manage');
  const listEl = h('ul', { class: 'link-list', attrs: { role: 'list' } }, h('li', { class: 'grant-loading' }, spinner()));
  /** @param {Share} s */
  const linkRow = (s) => {
    const url = shareURL(s);
    return h('li', { class: 'link-row', dataset: { status: s.status } },
      h('span', { class: 'link-row-icon' }, icon('link', { size: 18 })),
      h('span', { class: 'link-row-text' },
        h('span', { class: 'cluster link-row-title' }, h('span', { class: 'truncate', text: s.title || 'Public link' }), shareStatus(s)),
        h('small', { class: 'muted share-meta' }, shareSummaryNodes(s))),
      h('span', { class: 'link-row-actions' },
        url ? iconButton({ icon: 'copy', label: 'Copy link', size: 'sm', onClick: () => copyText(url, 'Link') }) : null,
        iconButton({ icon: 'qr', label: 'Show QR code', size: 'sm', onClick: () => shareQRDialog(s) }),
        canManage ? iconButton({ icon: 'edit', label: 'Edit link', size: 'sm', onClick: async () => { if (await linkDialog({ node, share: s })) { await load(); o.onChange?.(); } } }) : null,
        canManage ? iconButton({ icon: 'trash', label: 'Delete link', size: 'sm', variant: 'danger', onClick: async () => { if (await revokeShare(s)) { await load(); o.onChange?.(); } } }) : null));
  };
  const load = async () => {
    try {
      const list = /** @type {Share[]} */ (itemsOf(await api.get('/shares', { query: { node_id: node.id, kind: 'link', limit: 100 } })));
      listEl.replaceChildren(...list.map(linkRow));
      if (!list.length) listEl.appendChild(h('li', { class: 'grant-empty muted text-sm', text: 'No public links yet.' }));
    } catch (err) {
      listEl.replaceChildren(h('li', { class: 'danger-text text-sm', text: errorMessage(err) }));
    }
  };
  if (enabled && canManage) load();
  return h('section', { class: 'share-section' },
    h('div', { class: 'split' },
      h('h3', { class: 'share-section-title' }, icon('link', { size: 18 }), h('span', { text: 'Public links' })),
      enabled && canManage ? button({ label: 'Create link', icon: 'plus', size: 'sm', variant: 'secondary', onClick: async () => { if (await linkDialog({ node })) { await load(); o.onChange?.(); } } }) : null),
    !enabled
      ? h('p', { class: 'muted text-sm', text: roleMay ? 'Public links are turned off on this server.' : 'Your role can’t create public links. Ask an administrator if you need one.' })
      : !canManage
        ? h('p', { class: 'muted text-sm', text: 'Only people who manage this item can create links.' })
        : h('p', { class: 'muted text-sm', text: 'Anyone with a link can open it — no account needed.' }),
    enabled && canManage ? listEl : null);
}

/**
 * Sharing content for one node (grants + public links).
 * @param {Node} node
 * @param {{onChange?: () => void}} [o]
 */
export function sharingPanel(node, o = {}) {
  return h('div', { class: 'sharing-panel' }, grantsSection(node, o), linksSection(node, o));
}

/**
 * Share dialog for one node.
 * @param {Node} node
 * @param {{onChange?: () => void}} [o]
 */
export async function openShareDialog(node, o = {}) {
  let location = '';
  try {
    const sp = await spaces();
    const s = sp.find((x) => x.id === node.space_id);
    if (s) location = spaceLabel(s);
  } catch { /* ignore */ }
  dialog({
    title: `Share “${node.name}”`,
    size: 'md',
    class: 'share-dialog',
    body: h('div', { class: 'stack' },
      location ? h('p', { class: 'muted text-sm', text: `In ${location}. ${node.kind === 'folder' ? 'Access applies to everything inside this folder.' : ''}` }) : null,
      sharingPanel(node, o)),
    actions: [{ label: 'Done', variant: 'primary' }],
  }).open();
}
