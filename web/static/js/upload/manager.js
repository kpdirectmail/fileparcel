// @ts-check
/**
 * Upload manager — the SPA's upload UX (§8.1 browser client, §13.6), on top of upload/engine.js:
 *   · claims the shell's `fp:upload` events (Upload files / Upload folder / New folder / New file request, the FAB,
 *     the PWA share target) — see nav.js
 *   · full-window drop overlay accepting mixed files and folders (upload/scan.js), and paste of files/screenshots
 *   · pre-upload dialog: destination (folder picker), "Bundle into a single .zip" + name, "Protect the .zip with a
 *     password" (upload/protect.js; re-opened with the server's message when the password is refused), conflict
 *     policy; on phones the bottom sheet is lifted above the on-screen keyboard
 *   · queue panel: floating card on desktop, bottom sheet on phones; overall + per-file progress, speed, ETA,
 *     pause/resume/cancel/retry per file, per batch and globally; zip bundling progress (job via SSE)
 *   · navigator.wakeLock while uploading, a beforeunload warning, and a "resume" card after a reload that asks the
 *     user to re-select the files (matched by rel_path + size + mtime)
 *
 *   install()   once, from app.js
 *   startUpload(scan, folderId?)   programmatic entry (scan from upload/scan.js)
 * @module upload/manager
 */
import { h, icon, isMobile, boot } from '../core/dom.js';
import { api, errorMessage, itemsOf } from '../core/api.js';
import { navigate } from '../core/router.js';
import { events, session, effect, untracked, isFullSession } from '../core/store.js';
import { bytes, speed, duration, plural, number, relTime, pct } from '../core/format.js';
import { can, homeSpace, spaceLabel, spaces } from '../core/nodes.js';
import { engine, attachFiles } from './engine.js';
import { entriesFromFiles, entriesFromDataTransfer, renamePasted, isFileDrag } from './scan.js';
import { dialog } from '../components/dialog.js';
import { toast } from '../components/toast.js';
import { field, select, toggle } from '../components/field.js';
import { pickFolder } from '../components/folder-picker.js';
import { currentFolder } from '../nav.js';
import { protectFields } from './protect.js';

/**
 * @typedef {import('./engine.js').Batch} Batch
 * @typedef {import('./engine.js').Item} Item
 * @typedef {import('./scan.js').Scan} Scan
 * @typedef {{id: string, name: string, perm?: any, space_id?: string}} Dest space_id: the space it belongs to (quota)
 * @typedef {'' | 'aes256' | 'zipcrypto'} ZipEncryption
 * @typedef {{dest: Dest, mode: 'files' | 'zip', zipName: string, conflict: string, zipEncryption: ZipEncryption,
 *   zipPassword: string}} UploadChoice what the pre-upload dialog returns (zipPassword: handed to the engine at once)
 * @typedef {{dest: Dest, mode: 'files' | 'zip', zipName: string, conflict: string, zipEncryption: ZipEncryption,
 *   error: {field: string, message: string}}} RefusedAttempt a protected upload the server refused (no password)
 */

const STORE_KEY = 'fp:uploads';
const CONFLICT_KEY = 'fp:upload-conflict';
let installed = false;
/**
 * The server refused ZipCrypto although the page's boot data allowed it (the admin turned it off since): later
 * dialogs of this page offer AES-256 only.
 */
let legacyRefused = false;
/**
 * The shortest .zip password the server asked for in a refusal ("… at least N characters long"), 0 when none: it
 * replaces the page's boot value (storage.zip_password_min may have been raised since) in later dialogs, so the help
 * text, the checks and the generator follow the server.
 */
let refusedMin = 0;

// ---------------------------------------------------------------------------------------------------------------
// Persistence (resume after reload)
// ---------------------------------------------------------------------------------------------------------------

/** @returns {any[]} saved batches */
function loadSaved() {
  try {
    const v = JSON.parse(localStorage.getItem(STORE_KEY) || '[]');
    return Array.isArray(v) ? v : [];
  } catch {
    return [];
  }
}

/** @param {any[]} list */
function writeSaved(list) {
  try {
    if (list.length) localStorage.setItem(STORE_KEY, JSON.stringify(list));
    else localStorage.removeItem(STORE_KEY);
  } catch { /* quota / private mode: resume is best effort */ }
}

/** @param {string} key */
function forget(key) {
  writeSaved(loadSaved().filter((s) => s.key !== key));
}

/** @type {Map<string, number>} */
const persistTimers = new Map();

/**
 * A batch no reload can resume: settled; handed to the server's zip job ('bundling' needs nothing more from this
 * browser, and a zip job that failed has deleted the staged data); never declared; or one whose resume already
 * found it finished, expired or gone.
 * @param {Batch} b
 */
const unresumable = (b) => b.state === 'done' || b.state === 'canceled' || b.state === 'bundling'
  || (b.state === 'failed' && (!b.id || !!b.jobId || b.resumeFailed));

/**
 * Snapshot an unfinished batch (throttled per batch).
 * @param {Batch} b
 */
function persist(b) {
  if (b.apiBase !== '/api/v1') return;
  if (unresumable(b)) {
    clearTimeout(persistTimers.get(b.key));
    persistTimers.delete(b.key);
    forget(b.key);
    return;
  }
  if (!b.id || persistTimers.has(b.key)) return;
  persistTimers.set(b.key, window.setTimeout(() => {
    persistTimers.delete(b.key);
    if (unresumable(b)) return;
    const files = b.items.filter((it) => it.kind === 'file');
    if (files.length > 20000) return; // too big for localStorage; the server still expires it
    const rec = {
      // uid: the owner of the batch. Another account signing in on this browser must not see (or resume) it.
      key: b.key, id: b.id, uid: session.peek()?.user?.id || '', apiBase: b.apiBase, folderId: b.folderId, folderName: b.folderName, mode: b.mode, zipName: b.zipName,
      // the method only: the server keeps the sealed password, so resuming never asks for it again
      zipEncryption: b.zipEncryption || undefined,
      conflict: b.conflict, createdAt: b.createdAt, expiresAt: b.expiresAt, bytes: files.reduce((s, it) => s + it.size, 0),
      files: files.map((it) => ({ relPath: it.relPath, size: it.size, mtime: it.mtime, ref: it.ref, id: it.id })),
      dirs: b.items.filter((it) => it.kind === 'dir').map((it) => it.relPath),
    };
    const list = loadSaved().filter((s) => s.key !== b.key);
    list.push(rec);
    writeSaved(list);
  }, 1500));
}

// ---------------------------------------------------------------------------------------------------------------
// Destination & pre-upload dialog
// ---------------------------------------------------------------------------------------------------------------

/**
 * Resolve the upload destination: the given folder, the folder being viewed, or My files.
 * @param {string} [folderId]
 * @returns {Promise<Dest | null>}
 */
async function destination(folderId) {
  const cur = currentFolder.peek();
  if (cur && (!folderId || cur.id === folderId)) return { id: cur.id, name: cur.name || 'this folder', perm: /** @type {any} */ (cur).perm, space_id: /** @type {any} */ (cur).space_id };
  if (folderId) {
    try {
      const n = await api.get(`/nodes/${encodeURIComponent(folderId)}`, { handle: false });
      if (n?.kind === 'folder') return { id: n.id, name: n.parent_id ? n.name : spaceLabel((await spaces()).find((s) => s.id === n.space_id)), perm: n.perm, space_id: n.space_id };
    } catch { /* fall back to home */ }
  }
  const home = await homeSpace().catch(() => null);
  if (home?.root_id) return { id: home.root_id, name: spaceLabel(home), perm: home.perm ?? 'owner', space_id: home.id };
  return null;
}

/** Default name for a bundled upload. @param {Scan} scan */
function defaultZipName(scan) {
  if (scan.roots.length === 1 && (scan.files.some((f) => f.relPath.includes('/')) || scan.dirs.length)) return `${scan.roots[0]}.zip`;
  const d = new Date();
  const p = (/** @type {number} */ n) => String(n).padStart(2, '0');
  return `Upload ${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())} ${p(d.getHours())}.${p(d.getMinutes())}.zip`;
}

/**
 * The pre-upload dialog. `prev` re-opens it for a protected upload the server refused (DESIGN §13.6): every choice
 * is restored and the server's message is shown under the field it names; the password itself was never kept.
 * @param {Scan} scan
 * @param {Dest} dest
 * @param {RefusedAttempt | null} [prev]
 * @returns {Promise<UploadChoice | null>}
 */
function preUploadDialog(scan, dest, prev = null) {
  return new Promise((resolve) => {
    let chosen = prev ? prev.dest : dest;
    /** @type {UploadChoice | null} */
    let result = null;
    // every folder the upload creates: the ancestors of the files, and each empty folder with its own ancestors
    const folders = new Set();
    for (const f of scan.files) {
      const parts = f.relPath.split('/');
      for (let i = 1; i < parts.length; i += 1) folders.add(parts.slice(0, i).join('/'));
    }
    for (const d of scan.dirs) {
      const parts = d.split('/');
      for (let i = 1; i <= parts.length; i += 1) folders.add(parts.slice(0, i).join('/'));
    }
    const summary = [plural(scan.files.length, 'file'), folders.size ? plural(folders.size, 'folder') : '', bytes(scan.bytes)].filter(Boolean).join(' · ');
    const names = scan.roots.slice(0, 4);

    const destName = h('span', { class: 'truncate', text: chosen.name });
    const destWarn = h('p', { class: 'field-error', attrs: { 'aria-live': 'polite' } });
    const syncDest = () => {
      destName.textContent = chosen.name;
      const ok = can({ perm: chosen.perm }, 'edit');
      destWarn.textContent = ok ? '' : 'You can’t add files to this folder. Choose another one.';
      uploadBtn.disabled = !ok;
      checkQuota();
    };
    const destBtn = h('button', {
      class: 'btn btn--secondary up-dest',
      attrs: { type: 'button', 'aria-label': 'Change destination folder' },
      on: {
        click: async () => {
          const f = await pickFolder({ title: 'Upload to…', confirmLabel: 'Upload here', start: { id: chosen.id, name: chosen.name, kind: 'folder', perm: chosen.perm, space_id: chosen.space_id || '', size: 0, created_at: '', updated_at: '' } });
          if (f) {
            chosen = { id: f.id, name: f.parent_id ? f.name : spaceLabel((await spaces()).find((s) => s.id === f.space_id)), perm: f.perm, space_id: f.space_id };
            syncDest();
          }
        },
      },
    }, icon('folder'), destName, h('span', { class: 'up-dest-change', text: 'Change' }));

    // Only files are encrypted (folder entries are not), so a bundle of empty folders has nothing to protect.
    const canProtect = scan.files.length > 0;
    const bundle = toggle({
      label: 'Bundle into a single .zip',
      help: `The server packs everything into one .zip file in the destination folder after the upload.${canProtect ? ' You can protect it with a password.' : ''}`,
    });
    const zipName = field({ label: 'Name of the .zip file', value: prev?.zipName || defaultZipName(scan), maxlength: 255 });
    zipName.el.hidden = true;
    // ZipCrypto is offered while the server allows it (boot data, or, once refused, never again on this page). A
    // re-opened dialog whose ZipCrypto was just refused still builds the choice, so that setServerError() can show
    // AES-256 selected next to the reason.
    const refusedNow = prev?.error.field === 'zip_encryption';
    const legacy = !!boot().features.zip_legacy_encryption && (!legacyRefused || refusedNow);
    const min = Math.min(64, Math.max(8, refusedMin || Number(boot().limits?.zip_password_min) || 12));
    const protect = toggle({ label: 'Protect the .zip with a password', help: 'People who get the .zip need this password to open the files in it.' });
    const prot = protectFields({ min, legacy, method: prev?.zipEncryption || undefined });
    const syncProtect = () => {
      protect.el.hidden = !bundle.input.checked || !canProtect;
      prot.el.hidden = protect.el.hidden || !protect.input.checked;
    };
    const syncBundle = () => {
      zipName.el.hidden = !bundle.input.checked;
      conflict.el.querySelector('label')?.replaceChildren(document.createTextNode(bundle.input.checked ? 'If a .zip with that name exists' : 'If a file with the same name exists'));
      if (!bundle.input.checked && protect.input.checked) {
        protect.input.checked = false;
        prot.clear();
      }
      syncProtect();
    };
    bundle.input.addEventListener('change', () => {
      syncBundle();
      if (bundle.input.checked) {
        zipName.input.focus();
        const v = zipName.input.value;
        zipName.input.setSelectionRange(0, v.toLowerCase().endsWith('.zip') ? v.length - 4 : v.length);
      }
    });
    protect.input.addEventListener('change', () => {
      if (!protect.input.checked) prot.clear();
      syncProtect();
      if (protect.input.checked) prot.focus();
    });
    let saved = 'rename';
    try { saved = localStorage.getItem(CONFLICT_KEY) || 'rename'; } catch { /* ignore */ }
    if (prev) saved = prev.conflict;
    const conflict = select({
      label: 'If a file with the same name exists',
      options: [
        { value: 'rename', label: 'Keep both (add a number to the new one)' },
        { value: 'replace', label: 'Replace it (the old one is kept as a version)' },
        { value: 'skip', label: 'Skip the new file' },
      ],
      value: ['rename', 'replace', 'skip'].includes(saved) ? saved : 'rename',
    });
    const quotaNote = h('p', { class: 'alert alert--warning up-quota', hidden: true });
    let quotaSeq = 0;
    // Advisory (the server checks when the batch is declared), against the space the files go to: the personal
    // space (GET /me/usage: its quota minus what is stored and reserved by open uploads), or a team or shared space
    // (GET /spaces: its own effective quota; null = unlimited, not listed = unknown). Re-run on every destination.
    const checkQuota = async () => {
      const seq = ++quotaSeq;
      quotaNote.hidden = true;
      let msg = '';
      try {
        const dest = chosen;
        // the folder being viewed comes without its space: look it up once
        if (!dest.space_id) dest.space_id = (await api.get(`/nodes/${encodeURIComponent(dest.id)}`, { handle: false }))?.space_id || '';
        const u = await api.get('/me/usage', { handle: false });
        if (!dest.space_id || dest.space_id === u?.space_id) {
          const quota = Number(u?.quota_bytes || 0);
          const free = quota - Number(u?.used_bytes || 0) - Number(u?.reserved_bytes || 0);
          if (quota && scan.bytes > free) msg = `This upload (${bytes(scan.bytes)}) is larger than your free space (${bytes(Math.max(0, free))}). It will fail unless you free up space or upload to a team folder.`;
        } else {
          /** @type {any} */
          const sp = itemsOf(await api.get('/spaces', { handle: false })).find((s) => s.id === dest.space_id);
          const quota = Number(sp?.quota_bytes || 0);
          const free = quota - Number(sp?.used_bytes || 0);
          if (quota && scan.bytes > free) msg = `This upload (${bytes(scan.bytes)}) is larger than the free space in “${spaceLabel(sp)}” (${bytes(Math.max(0, free))}). It will fail unless space is freed there.`;
        }
      } catch { /* advisory only */ }
      if (seq !== quotaSeq || !msg) return;
      quotaNote.textContent = msg;
      quotaNote.hidden = false;
    };

    const uploadBtn = h('button', { class: 'btn btn--primary', attrs: { type: 'submit', form: 'up-form' } }, icon('upload'), h('span', { text: 'Upload' }));
    const form = h('form', { class: 'form up-form', id: 'up-form', attrs: { novalidate: true } },
      h('div', { class: 'up-summary' },
        h('span', { class: 'up-summary-icon' }, icon(folders.size ? 'folder-up' : 'upload', { size: 22 })),
        h('div', { class: 'up-summary-text' },
          h('strong', { text: summary }),
          h('span', { class: 'muted text-sm truncate', text: names.join(', ') + (scan.roots.length > names.length ? ` and ${number(scan.roots.length - names.length)} more` : '') }))),
      scan.skipped.length ? h('p', { class: 'alert alert--warning', text: `${plural(scan.skipped.length, 'item')} can’t be uploaded (system files or names that aren’t allowed) and will be skipped.` }) : null,
      h('div', { class: 'field' }, h('span', { class: 'field-label', text: 'Upload to' }), destBtn, destWarn),
      bundle.el, zipName.el, protect.el, prot.el, conflict.el, quotaNote);
    form.addEventListener('submit', (e) => {
      e.preventDefault();
      if (uploadBtn.disabled) return;
      let zn = String(zipName.value()).trim();
      if (bundle.input.checked) {
        if (!zn) {
          zipName.setError('Enter a name for the .zip file.');
          zipName.input.focus();
          return;
        }
        if (!zn.toLowerCase().endsWith('.zip')) zn += '.zip';
        if (/[/\\]/.test(zn)) {
          zipName.setError('The name can’t contain / or \\.');
          return;
        }
      }
      /** @type {ZipEncryption} */
      let zipEncryption = '';
      let zipPassword = '';
      if (bundle.input.checked && protect.input.checked && canProtect) {
        if (!prot.validate()) return;
        zipEncryption = prot.method();
        zipPassword = prot.password();
      }
      try { localStorage.setItem(CONFLICT_KEY, String(conflict.value())); } catch { /* ignore */ }
      result = { dest: chosen, mode: bundle.input.checked ? 'zip' : 'files', zipName: zn, conflict: conflict.value(), zipEncryption, zipPassword };
      prot.clear(); // the password now lives only in `result`, which startUpload() hands to the engine at once
      d.close(true);
    });
    const d = dialog({
      title: scan.files.length === 1 && !folders.size ? `Upload “${scan.files[0].relPath}”` : 'Upload files',
      size: 'md',
      class: 'up-dialog',
      body: form,
      actions: [{ label: 'Cancel', variant: 'ghost' }, uploadBtn],
      onClose: () => {
        prot.clear(); // Escape, Cancel, drag-down and submit alike: nothing about the password stays in the page
        resolve(result);
      },
    });
    if (prev) {
      bundle.input.checked = prev.mode === 'zip';
      protect.input.checked = true;
      prot.setServerError(prev.error.field, prev.error.message);
    }
    syncBundle();
    syncDest();
    d.open();
    if (prev) prot.focus();
    else uploadBtn.focus();
  });
}

/**
 * Start an upload from a scan (asks for confirmation/options first). A protected upload whose password (or method)
 * the server refuses re-opens the dialog with the reason; nothing was uploaded then.
 * @param {Scan} scan
 * @param {string} [folderId]
 */
export async function startUpload(scan, folderId) {
  if (!scan.files.length && !scan.dirs.length) {
    toast.warning(scan.skipped.length ? 'None of these items can be uploaded (system files or names that aren’t allowed).' : 'There is nothing to upload.');
    return null;
  }
  let dest = await destination(folderId);
  if (!dest) {
    const f = await pickFolder({ title: 'Where should the files go?', confirmLabel: 'Upload here' });
    if (!f) return null;
    dest = { id: f.id, name: f.name, perm: f.perm, space_id: f.space_id };
  }
  /** @type {RefusedAttempt | null} */
  let prev = null;
  for (;;) {
    const opts = await preUploadDialog(scan, dest, prev);
    if (!opts) return null;
    const b = engine.add({
      apiBase: '/api/v1',
      folderId: opts.dest.id,
      folderName: opts.dest.name,
      files: scan.files,
      dirs: scan.dirs,
      mode: opts.mode,
      zipName: opts.zipName,
      conflict: /** @type {any} */ (opts.conflict),
      zipEncryption: opts.zipEncryption,
      zipPassword: opts.zipPassword,
    });
    opts.zipPassword = '';
    panel.show(true); // immediate feedback while the batch is declared
    if (!b.zipEncryption || (await b.declared) || !b.needsZipPassword) return b;
    engine.remove(b); // refused before anything was created on the server
    if (b.errorField === 'zip_encryption') legacyRefused = true; // stale boot data: the admin turned ZipCrypto off
    const atLeast = b.errorField === 'zip_password' && /\bat least (\d+) characters\b/.exec(b.error);
    if (atLeast) refusedMin = Number(atLeast[1]); // stale boot data: the admin raised storage.zip_password_min
    prev = {
      dest: opts.dest, mode: opts.mode, zipName: opts.zipName, conflict: opts.conflict, zipEncryption: b.zipEncryption,
      error: { field: b.errorField, message: b.error },
    };
    dest = opts.dest;
  }
}

// ---------------------------------------------------------------------------------------------------------------
// Queue panel
// ---------------------------------------------------------------------------------------------------------------

/**
 * A file its failed batch left unsent (not failed itself, not missing, not finished).
 * @param {Item} it
 */
function halted(it) {
  return it.batch.state === 'failed' && !it.terminal && it.state !== 'failed' && it.state !== 'missing';
}

/** @param {Item} it */
function itemStatus(it) {
  const now = Date.now();
  if (halted(it)) return 'Not uploaded';
  switch (it.state) {
    case 'queued': return it.cooldownUntil > now && it.error ? it.error : 'Waiting';
    case 'uploading': {
      if (it.cooldownUntil > now && it.error) return it.error;
      const done = it.sent;
      return it.size ? `${pct(done, it.size)} · ${bytes(done)} of ${bytes(it.size)}` : 'Uploading';
    }
    case 'paused': return 'Paused';
    case 'done': return it.kind === 'dir' ? 'Folder' : `Done · ${bytes(it.size)}`;
    case 'skipped': return 'Skipped — a file with this name already exists';
    case 'failed': return it.error || 'Failed';
    case 'canceled': return 'Cancelled';
    case 'missing': return 'Select this file again to continue';
    default: return it.state;
  }
}

const ITEM_ICONS = { queued: 'clock', uploading: 'upload', paused: 'pause', done: 'check-circle', skipped: 'minus', failed: 'alert-circle', canceled: 'x-circle', missing: 'alert-triangle' };

/** @param {Batch} b */
function batchTitle(b) {
  const files = b.files.length;
  if (b.mode === 'zip') return b.resultName || b.zipName || 'Archive';
  if (files === 1) return b.files[0].name;
  return `${plural(files, 'file')}`;
}

/** @param {Batch} b */
function batchStatus(b) {
  const p = b.progress;
  switch (b.state) {
    case 'preparing': return `Preparing ${plural(p.count, 'file')}…`;
    case 'uploading': return `${pct(p.sent, p.total)} · ${bytes(p.sent)} of ${bytes(p.total)}`;
    case 'paused': return `Paused · ${pct(p.sent, p.total)}`;
    case 'finishing': return 'Finishing…';
    case 'bundling': {
      const j = b.job;
      return `Creating ${b.zipName || 'the .zip'}${b.zipEncryption ? ' (encrypting)' : ''}…${j && j.total ? ` ${pct(j.done, j.total)}` : ''}`;
    }
    case 'attention': return `${plural(p.failed + p.missing, 'file')} need${p.failed + p.missing === 1 ? 's' : ''} attention`;
    case 'done':
      if (b.skipped) return `Skipped — “${b.zipName}” already exists`;
      if (p.skipped) return `Done · ${number(p.done - p.skipped)} uploaded, ${number(p.skipped)} skipped`;
      return p.count - p.done > 0 ? `Done · ${number(p.done)} of ${number(p.count)} uploaded` : `Done · ${bytes(p.total)}`;
    case 'failed': return b.error || 'Upload failed';
    case 'canceled': return 'Cancelled';
    default: return b.state;
  }
}

const panel = (() => {
  /** @type {HTMLElement | null} */
  let el = null;
  /** @type {HTMLElement} */
  let titleEl;
  /** @type {HTMLElement} */
  let metaEl;
  /** @type {HTMLProgressElement} */
  let bar;
  /** @type {HTMLElement} */
  let listEl;
  /** @type {HTMLElement} */
  let resumeEl;
  /** @type {HTMLButtonElement} */
  let pauseAllBtn;
  /** @type {HTMLButtonElement} */
  let toggleBtn;
  let expanded = true;
  let raf = 0;
  let lastRender = 0;
  /** @type {WeakMap<Item, {el: HTMLElement, meta: HTMLElement, bar: HTMLProgressElement, ic: string, actions: HTMLElement, state: string}>} */
  const rows = new WeakMap();
  /** @type {WeakMap<Batch, {el: HTMLElement, title: HTMLElement, lock: HTMLElement, status: HTMLElement, bar: HTMLProgressElement, actions: HTMLElement, list: HTMLElement, more: HTMLElement, sig: string}>} */
  const sections = new WeakMap();

  /** @param {string} ic @param {string} label @param {() => void} fn @param {string} [cls] */
  const tool = (ic, label, fn, cls = '') => h('button', {
    class: `icon-btn icon-btn--sm ${cls}`,
    attrs: { type: 'button', 'aria-label': label, title: label },
    on: { click: (e) => { e.stopPropagation(); fn(); } },
  }, icon(ic, { size: 16 }));

  function build() {
    titleEl = h('strong', { class: 'upq-title' });
    metaEl = h('small', { class: 'upq-meta tabular' });
    bar = h('progress', { class: 'upq-bar', attrs: { max: 1, 'aria-label': 'Overall upload progress' } });
    listEl = h('div', { class: 'upq-list' });
    resumeEl = h('div', { class: 'upq-resume' });
    pauseAllBtn = tool('pause', 'Pause all', () => {
      const anyActive = engine.batches.some((b) => b.active);
      if (anyActive) engine.pauseAll();
      else engine.resumeAll();
    });
    toggleBtn = tool('chevron-down', 'Collapse', () => setExpanded(!expanded), 'upq-toggle');
    const closeBtn = tool('x', 'Close', () => close());
    const head = h('div', { class: 'upq-head', on: { click: () => { if (isMobile() && !expanded) setExpanded(true); } } },
      h('span', { class: 'upq-head-icon' }, icon('cloud-upload', { size: 20 })),
      h('div', { class: 'upq-heading' }, titleEl, metaEl),
      pauseAllBtn, toggleBtn, closeBtn);
    el = h('section', { class: 'upq', attrs: { 'aria-label': 'Uploads', role: 'region' }, dataset: { expanded: '' } },
      head,
      h('div', { class: 'upq-progress' }, bar),
      h('div', { class: 'upq-body' }, resumeEl, listEl));
    document.body.appendChild(el);
    // toasts stack above the panel (css: .toasts uses --fp-upq-h)
    const panelEl = el;
    const ro = new ResizeObserver(() => {
      if (!panelEl.isConnected) {
        ro.disconnect();
        document.documentElement.style.removeProperty('--fp-upq-h');
        return;
      }
      document.documentElement.style.setProperty('--fp-upq-h', `${Math.ceil(panelEl.getBoundingClientRect().height) + 8}px`);
    });
    ro.observe(panelEl);
    if (isMobile()) setExpanded(false);
  }

  /** Remove the panel (and the toast offset it reserved). */
  function destroy() {
    el?.remove();
    el = null;
    document.documentElement.style.removeProperty('--fp-upq-h');
  }

  /** @param {boolean} on */
  function setExpanded(on) {
    expanded = on;
    if (!el) return;
    el.toggleAttribute('data-expanded', on);
    toggleBtn.setAttribute('aria-label', on ? 'Collapse' : 'Expand');
    toggleBtn.title = on ? 'Collapse' : 'Expand';
    toggleBtn.setAttribute('aria-expanded', String(on));
  }

  function close() {
    if (engine.batches.some((b) => b.active || b.state === 'paused' || b.state === 'bundling')) {
      setExpanded(false);
      toast.info('Uploads continue in the background.', { timeout: 2500 });
      return;
    }
    engine.clearFinished(); // batches that still need a decision ("attention") stay listed
    if (!engine.batches.length && !resumeEl.childElementCount) {
      destroy();
    } else {
      setExpanded(false);
    }
  }

  /** @param {Item} it */
  function itemRow(it) {
    let r = rows.get(it);
    if (!r) {
      const meta = h('small', { class: 'upq-item-meta' });
      const pbar = h('progress', { class: 'upq-item-bar', attrs: { max: Math.max(1, it.size) } });
      const actions = h('span', { class: 'upq-item-actions' });
      const ic = h('span', { class: 'upq-item-icon' });
      const row = h('li', { class: 'upq-item' },
        ic,
        h('span', { class: 'upq-item-text' }, h('span', { class: 'upq-item-name', attrs: { title: it.relPath }, text: it.name }), meta, pbar),
        actions);
      r = { el: row, meta, bar: pbar, ic: '', actions, state: '' };
      rows.set(it, r);
    }
    // a batch that failed as a whole (declaring it, the quota, the session) leaves its waiting files behind: they
    // show as not uploaded, without actions, until the batch is retried
    const stopped = halted(it);
    const state = stopped ? 'failed' : it.state;
    r.el.dataset.state = state;
    const icName = /** @type {any} */ (ITEM_ICONS)[state] || 'file';
    if (r.ic !== icName) {
      r.el.firstElementChild?.replaceChildren(icon(icName, { size: 16 }));
      r.ic = icName;
    }
    r.meta.textContent = itemStatus(it);
    r.bar.hidden = state !== 'uploading' && state !== 'paused';
    if (!r.bar.hidden) r.bar.value = it.sent;
    const sig = `${state}|${it.paused}|${stopped}`;
    if (r.state !== sig) {
      r.state = sig;
      /** @type {HTMLElement[]} */
      const acts = [];
      if (!stopped) { // a stopped file goes with its batch (Retry this upload, Remove from the list)
        if (state === 'uploading' || state === 'queued') acts.push(tool('pause', `Pause ${it.name}`, () => it.pause()));
        // only a file the user paused: one paused by its batch resumes with the batch ("Resume this upload")
        if (state === 'paused' && it.paused) acts.push(tool('play', `Resume ${it.name}`, () => it.resume()));
        if (state === 'failed') acts.push(tool('refresh', `Retry ${it.name}`, () => it.retry()));
        if (!it.terminal) acts.push(tool('x', `Cancel ${it.name}`, () => it.cancel()));
      }
      r.actions.replaceChildren(...acts);
    }
    return r.el;
  }

  /** @param {Batch} b */
  function section(b) {
    let s = sections.get(b);
    if (!s) {
      const title = h('span', { class: 'upq-batch-title truncate' });
      const lock = h('span', { class: 'upq-batch-lock', hidden: true }, icon('lock', { size: 14, label: 'Password-protected' }));
      const status = h('small', { class: 'upq-batch-status' });
      const pbar = h('progress', { class: 'upq-batch-bar', attrs: { max: 1 } });
      const actions = h('span', { class: 'upq-batch-actions' });
      const list = h('ul', { class: 'upq-items', attrs: { role: 'list' } });
      const more = h('p', { class: 'upq-more muted text-xs' });
      const secEl = h('div', { class: 'upq-batch' },
        h('div', { class: 'upq-batch-head' },
          h('span', { class: 'upq-batch-icon' }, icon(b.mode === 'zip' ? 'file-zip' : 'folder', { size: 18 })),
          h('span', { class: 'upq-batch-text' }, h('span', { class: 'upq-batch-name' }, title, lock), h('small', { class: 'upq-batch-dest muted truncate', text: `to ${b.folderName || 'your files'}` }), status),
          actions),
        pbar, list, more);
      s = { el: secEl, title, lock, status, bar: pbar, actions, list, more, sig: '' };
      sections.set(b, s);
    }
    const p = b.progress;
    s.el.dataset.state = b.state;
    s.title.textContent = batchTitle(b);
    s.lock.hidden = !b.zipEncryption;
    s.status.textContent = batchStatus(b);
    s.bar.hidden = b.state === 'done' || b.state === 'canceled' || b.state === 'failed';
    if (b.state === 'bundling') {
      if (b.job && b.job.total) {
        s.bar.max = b.job.total;
        s.bar.value = b.job.done;
      } else s.bar.removeAttribute('value');
    } else {
      s.bar.max = Math.max(1, p.total);
      s.bar.value = p.sent;
    }
    const sig = `${b.state}|${p.failed}|${p.missing}|${b.retryable}`;
    if (s.sig !== sig) {
      s.sig = sig;
      /** @type {HTMLElement[]} */
      const acts = [];
      if (b.state === 'uploading' || b.state === 'preparing') acts.push(tool('pause', 'Pause this upload', () => b.pause()));
      if (b.state === 'paused') acts.push(tool('play', 'Resume this upload', () => b.resume()));
      if (p.missing) acts.push(tool('folder-plus', 'Select the missing files', () => pickMissing(b)));
      if (b.state === 'attention' || (b.state === 'failed' && (b.id || b.retryable))) {
        // b.retryable: the batch failed as a whole (declaring it, completing it, the session or quota) and no file
        // is 'failed' — retrying the batch picks up where it stopped
        if (p.failed || b.retryable) acts.push(tool('refresh', p.failed ? 'Retry failed files' : 'Retry this upload', () => b.retryFailed()));
        if (b.state === 'attention') acts.push(tool('minus', 'Skip the failed files and finish', () => b.skipFailed()));
      }
      if (b.state === 'done') {
        acts.push(tool('folder-open', 'Show in folder', () => {
          navigate(b.resultNodeId ? `/files/${encodeURIComponent(b.folderId)}?select=${encodeURIComponent(b.resultNodeId)}` : `/files/${encodeURIComponent(b.folderId)}`);
        }));
      }
      if (!b.finished && b.state !== 'bundling') acts.push(tool('x', 'Cancel this upload', () => b.cancel()));
      if (b.finished || b.state === 'failed') acts.push(tool('trash', 'Remove from the list', () => engine.remove(b)));
      s.actions.replaceChildren(...acts);
    }
    // show the files that matter: active, failed, missing, paused, then a few queued
    const files = b.files;
    const small = files.length <= 60;
    /** @type {Item[]} */
    const show = [];
    let queued = 0;
    let doneCount = 0;
    for (const it of files) {
      if (small) { show.push(it); continue; }
      if (it.state === 'done' || it.state === 'skipped' || it.state === 'canceled') { doneCount += 1; continue; }
      if (it.state === 'queued') {
        queued += 1;
        if (queued > 12) continue;
      }
      show.push(it);
      if (show.length >= 120) break;
    }
    const expandedList = b.state !== 'done' || files.length <= 10 || p.failed > 0;
    s.list.hidden = !expandedList || b.state === 'bundling';
    if (!s.list.hidden) s.list.replaceChildren(...show.map(itemRow));
    s.more.hidden = small || !expandedList;
    if (!small) s.more.textContent = [doneCount ? `${number(doneCount)} finished` : '', queued > 12 ? `${number(queued - 12)} more waiting` : ''].filter(Boolean).join(' · ');
    return s.el;
  }

  function render() {
    raf = 0;
    lastRender = performance.now();
    if (!el) {
      if (!engine.batches.length && !resumeEl?.childElementCount) return;
      build();
    }
    const list = engine.batches;
    const active = list.filter((b) => b.active || b.state === 'paused');
    const attention = list.filter((b) => b.state === 'attention' || b.state === 'failed');
    const bundling = list.filter((b) => b.state === 'bundling');
    const prog = engine.progress;
    const files = active.reduce((n, b) => n + b.progress.count - b.progress.done, 0);
    if (active.some((b) => b.active)) {
      titleEl.textContent = `Uploading ${plural(files, 'file')}`;
      const sp = engine.speed;
      const eta = engine.eta;
      metaEl.textContent = [pct(prog.sent, prog.total), sp > 0 ? speed(sp) : '', Number.isFinite(eta) && eta > 0 ? `${duration(eta * 1000)} left` : ''].filter(Boolean).join(' · ');
      bar.max = Math.max(1, prog.total);
      bar.value = prog.sent;
      bar.hidden = false;
    } else if (active.length) {
      titleEl.textContent = 'Uploads paused';
      metaEl.textContent = `${pct(prog.sent, prog.total)} · ${bytes(prog.total - prog.sent)} left`;
      bar.max = Math.max(1, prog.total);
      bar.value = prog.sent;
      bar.hidden = false;
    } else if (bundling.length) {
      titleEl.textContent = 'Creating .zip…';
      metaEl.textContent = 'Your files are uploaded; the server is packing them.';
      bar.removeAttribute('value');
      bar.hidden = false;
    } else if (attention.length) {
      titleEl.textContent = 'Some uploads need attention';
      metaEl.textContent = attention.some((b) => b.state === 'attention')
        ? 'Retry, skip or cancel the failed files below.'
        : 'See below what went wrong.';
      bar.hidden = true;
    } else if (list.length) {
      const done = list.filter((b) => b.state === 'done');
      // files actually stored (conflict "skip" left some out, or the whole .zip)
      const n = done.reduce((s, b) => s + (b.skipped ? 0 : b.progress.done - b.progress.skipped), 0);
      titleEl.textContent = done.length ? 'Uploads complete' : 'Uploads';
      metaEl.textContent = done.length ? `${plural(n, 'file')} uploaded` : '';
      bar.hidden = true;
    } else {
      titleEl.textContent = 'Unfinished uploads';
      metaEl.textContent = resumeEl.querySelector('.upq-resume-card:not([data-server])')
        ? 'Select the files again to continue.'
        : 'Started elsewhere. Discard the ones you no longer need.';
      bar.hidden = true;
    }
    const anyActive = list.some((b) => b.active);
    pauseAllBtn.hidden = !active.length;
    pauseAllBtn.replaceChildren(icon(anyActive ? 'pause' : 'play', { size: 16 }));
    pauseAllBtn.setAttribute('aria-label', anyActive ? 'Pause all' : 'Resume all');
    pauseAllBtn.title = anyActive ? 'Pause all' : 'Resume all';
    el?.toggleAttribute('data-attention', attention.length > 0 && !active.length);
    el?.toggleAttribute('data-done', !active.length && !attention.length && !bundling.length && list.length > 0);
    listEl.replaceChildren(...[...list].reverse().map(section));
    if (!list.length && !resumeEl.childElementCount) destroy();
  }

  function schedule() {
    if (raf) return;
    const wait = Math.max(0, 200 - (performance.now() - lastRender));
    raf = window.setTimeout(() => requestAnimationFrame(render), wait);
  }

  return {
    schedule,
    /** @param {boolean} [expand] */
    show(expand) {
      if (!el) build();
      if (expand && !isMobile()) setExpanded(true);
      schedule();
    },
    /** @returns {HTMLElement} */
    resumeArea() {
      if (!el) build();
      return resumeEl;
    },
  };
})();

// ---------------------------------------------------------------------------------------------------------------
// Resume after reload
// ---------------------------------------------------------------------------------------------------------------

/**
 * Open a transient file picker (inside the click that called it) and resolve the chosen files.
 * @param {boolean} folder
 * @returns {Promise<File[]>}
 */
function pickFiles(folder) {
  return new Promise((resolve) => {
    const input = h('input', { class: 'hidden', attrs: { type: 'file', multiple: true, webkitdirectory: folder || null, tabindex: '-1', 'aria-hidden': 'true' } });
    input.addEventListener('change', () => {
      resolve(Array.from(input.files || []));
      input.remove();
    });
    input.addEventListener('cancel', () => {
      resolve([]);
      input.remove();
    });
    document.body.appendChild(input);
    input.click();
  });
}

/** Re-select missing files of a running batch. @param {Batch} b */
async function pickMissing(b) {
  const folder = b.items.some((it) => it.state === 'missing' && it.relPath.includes('/'));
  const files = await pickFiles(folder && folderPickSupported());
  if (!files.length) return;
  const n = attachFiles(b, files);
  if (!n) {
    toast.warning('None of the selected files match the missing ones (same name, size and date are needed).');
    return;
  }
  toast.success(`Found ${plural(n, 'file')} — continuing.`);
  if (b.state === 'attention') b.state = 'uploading';
  engine.changed();
  engine.pump();
  b.checkFinished();
}

function folderPickSupported() {
  const i = document.createElement('input');
  return 'webkitdirectory' in i && !/iPad|iPhone|iPod/.test(navigator.userAgent);
}

/** Render the "resume" cards for batches saved before a reload. */
function renderResumeCards() {
  const uid = session.peek()?.user?.id || '';
  const now = Date.now();
  const all = loadSaved();
  // Keep only this user's unexpired batches, and erase the rest: after a sign-out the next account on this browser
  // must not see the previous user's file names, sizes and destination folder (records written before `uid`
  // existed have none and are dropped by the same rule).
  const mine = all.filter((s) => s.uid === uid && (!s.expiresAt || Date.parse(s.expiresAt) > now));
  if (mine.length !== all.length) writeSaved(mine);
  const live = mine.filter((s) => s.apiBase === '/api/v1' && s.id && !engine.batches.some((b) => b.key === s.key));
  if (!live.length) return;
  const area = panel.resumeArea();
  area.replaceChildren(...area.querySelectorAll('[data-server]'), ...live.map((s) => {
    const hasFolders = (s.files || []).some((/** @type {any} */ f) => String(f.relPath).includes('/'));
    const card = h('div', { class: 'upq-resume-card' },
      h('div', { class: 'upq-resume-text' },
        h('strong', { text: `Interrupted upload: ${plural((s.files || []).length, 'file')}${s.bytes ? ` (${bytes(s.bytes)})` : ''}` },
          s.zipEncryption ? icon('lock', { size: 14, label: 'Password-protected .zip' }) : null),
        h('small', { class: 'muted', text: `to ${s.folderName || 'a folder'} · started ${relTime(s.createdAt)}. Select the same files again to continue where it stopped.` })),
      h('div', { class: 'cluster upq-resume-actions' },
        h('button', {
          class: 'btn btn--primary btn--sm',
          attrs: { type: 'button' },
          on: { click: () => resume(s, false, card) },
        }, icon('upload', { size: 16 }), h('span', { text: 'Select files' })),
        hasFolders && folderPickSupported()
          ? h('button', { class: 'btn btn--secondary btn--sm', attrs: { type: 'button' }, on: { click: () => resume(s, true, card) } }, icon('folder-up', { size: 16 }), h('span', { text: 'Select folder' }))
          : null,
        h('button', {
          class: 'btn btn--ghost btn--sm',
          attrs: { type: 'button' },
          on: {
            click: () => {
              forget(s.key);
              card.remove();
              api.del(`/upload-batches/${encodeURIComponent(s.id)}`, undefined, { handle: false }).catch(() => {});
              panel.schedule();
            },
          },
        }, h('span', { text: 'Discard' }))));
    return card;
  }));
  panel.schedule();
}

let serverSeq = 0;
/** On page load, a batch from elsewhere is offered for discarding once it has been idle this long. */
const ORPHAN_IDLE_MS = 60 * 60_000;
/**
 * Cards for the user's unfinished batches this browser has no record of (GET /upload-batches): started in another
 * browser or device, a tab whose site data was cleared, or a command-line upload that was killed. Each holds its
 * reserved space and one of the 20 open-batch slots until it expires, so the card offers Discard. They cannot be
 * continued here (the browser would need the files and their upload ids). On page load only batches idle for an
 * hour are shown (one may still be running on another device); after a batch could not be declared (the quota or
 * the batch cap, which exactly these may hold) every one is.
 * @param {number} idleMs the least time since a batch's last activity (updated_at)
 */
async function renderServerCards(idleMs) {
  const seq = ++serverSeq;
  /** @type {any[]} */
  let list;
  try {
    list = itemsOf(await api.get('/upload-batches', { handle: false }));
  } catch {
    return; // an older server, no session, locked keys: nothing to show
  }
  if (seq !== serverSeq) return;
  const known = new Set([...loadSaved().map((s) => s.id), ...engine.batches.map((b) => b.id)].filter(Boolean));
  // a batch of this tab that is still being declared has no id here yet: leave recent batches alone meanwhile
  const declaring = engine.batches.some((b) => b.declaring);
  const now = Date.now();
  const orphans = list.filter((b) => b && b.state === 'open' && b.id && !known.has(b.id) &&
    now - Date.parse(b.updated_at || b.created_at) >= idleMs &&
    !(declaring && now - Date.parse(b.created_at) < 120_000));
  const area = orphans.length ? panel.resumeArea() : null;
  document.querySelectorAll('.upq-resume-card[data-server]').forEach((el) => el.remove());
  if (!area) {
    panel.schedule();
    return;
  }
  /** @type {Map<string, Promise<string>>} */
  const names = new Map();
  const folderName = (/** @type {string} */ id) => {
    if (!names.has(id)) {
      names.set(id, api.get(`/nodes/${encodeURIComponent(id)}`, { handle: false })
        .then((/** @type {any} */ n) => (n?.parent_id ? String(n.name || '') : 'your files'))
        .catch(() => ''));
    }
    return /** @type {Promise<string>} */ (names.get(id));
  };
  for (const b of orphans) {
    const what = b.mode === 'zip' && b.zip_name ? `“${b.zip_name}”` : plural(Number(b.declared_files) || 0, 'file');
    const sub = h('small', { class: 'muted' });
    const setSub = (/** @type {string} */ folder) => {
      sub.textContent = `${folder ? `to ${folder} · ` : ''}started ${relTime(b.created_at)}, not in this browser. It holds ${bytes(Number(b.reserved_bytes) || 0)} of your space until it expires ${relTime(b.expires_at)}.`;
    };
    setSub('');
    folderName(String(b.folder_id || '')).then(setSub);
    const card = h('div', { class: 'upq-resume-card', dataset: { server: b.id } },
      h('div', { class: 'upq-resume-text' },
        h('strong', { text: `Unfinished upload: ${what}${b.declared_bytes ? ` (${bytes(Number(b.declared_bytes))})` : ''}` },
          b.zip_encryption ? icon('lock', { size: 14, label: 'Password-protected .zip' }) : null),
        sub),
      h('div', { class: 'cluster upq-resume-actions' },
        h('button', {
          class: 'btn btn--ghost btn--sm',
          attrs: { type: 'button', 'aria-label': `Discard the unfinished upload ${what}` },
          on: {
            click: async (e) => {
              const btn = /** @type {HTMLButtonElement} */ (e.currentTarget);
              btn.disabled = true;
              try {
                await api.del(`/upload-batches/${encodeURIComponent(b.id)}`, undefined, { handle: false });
              } catch (err) {
                btn.disabled = false;
                toast.error(`Could not discard the upload: ${errorMessage(err)}`);
                return;
              }
              card.remove();
              panel.schedule();
            },
          },
        }, h('span', { text: 'Discard' }))));
    area.append(card);
  }
  panel.show();
}

/**
 * @param {any} saved
 * @param {boolean} folder
 * @param {HTMLElement} card
 */
async function resume(saved, folder, card) {
  const files = await pickFiles(folder);
  if (!files.length) return;
  card.remove();
  const b = await engine.resumeSaved({
    ...saved,
    files: (saved.files || []).map((/** @type {any} */ f) => ({ file: null, relPath: f.relPath, size: f.size, mtime: f.mtime, ref: f.ref, id: f.id })),
    dirs: saved.dirs || [],
  }, files);
  if (b.state === 'failed') {
    forget(saved.key);
    toast.error(b.error || 'This upload can no longer be resumed.');
  } else {
    const missing = b.progress.missing;
    if (missing === b.progress.count - b.progress.done && missing > 0) toast.warning('None of the selected files match this upload. Select the same files you chose before.');
    else if (missing) toast.info(`${plural(missing, 'file')} still need${missing === 1 ? 's' : ''} to be selected.`);
  }
  panel.show(true);
}

// ---------------------------------------------------------------------------------------------------------------
// Drop overlay & paste
// ---------------------------------------------------------------------------------------------------------------

function installDrop() {
  /** @type {HTMLElement | null} */
  let overlay = null;
  let hideTimer = 0;
  const modalOpen = () => !!document.querySelector('dialog[open]');
  const target = () => {
    const cur = currentFolder.peek();
    return { name: cur?.name || 'My files', ok: !cur || can({ perm: /** @type {any} */ (cur).perm }, 'edit') };
  };
  const show = () => {
    clearTimeout(hideTimer);
    hideTimer = window.setTimeout(hide, 400); // no dragover for a while → the drag left or was cancelled
    if (overlay) return;
    const t = target();
    overlay = h('div', { class: 'drop-overlay', dataset: { denied: t.ok ? null : '' }, attrs: { 'aria-hidden': 'true' } },
      h('div', { class: 'drop-overlay-card' },
        icon(t.ok ? 'cloud-upload' : 'lock'),
        h('strong', { text: t.ok ? `Drop to upload to “${t.name}”` : 'You can’t upload to this folder' }),
        h('span', { text: t.ok ? 'Files and whole folders are welcome.' : 'Open a folder you can edit, then try again.' })));
    document.body.appendChild(overlay);
  };
  const hide = () => {
    clearTimeout(hideTimer);
    overlay?.remove();
    overlay = null;
  };
  window.addEventListener('dragenter', (e) => {
    if (!isFileDrag(e) || modalOpen()) return;
    e.preventDefault();
    show();
  });
  window.addEventListener('dragover', (e) => {
    if (!isFileDrag(e)) return;
    e.preventDefault(); // never let the browser open the dropped file
    if (modalOpen()) {
      if (e.dataTransfer) e.dataTransfer.dropEffect = 'none';
      return;
    }
    if (e.dataTransfer) e.dataTransfer.dropEffect = target().ok ? 'copy' : 'none';
    show();
  });
  window.addEventListener('dragleave', (e) => {
    if (!isFileDrag(e)) return;
    if (!e.relatedTarget) hide();
  });
  window.addEventListener('drop', (e) => {
    if (!isFileDrag(e) || !e.dataTransfer) return;
    e.preventDefault();
    hide();
    if (modalOpen()) return;
    if (!target().ok) {
      toast.warning('You can’t upload to this folder.');
      return;
    }
    let slowToast = /** @type {{close: () => void} | null} */ (null);
    const timer = setTimeout(() => { slowToast = toast.info('Reading the dropped folders…', { timeout: 0 }); }, 600);
    entriesFromDataTransfer(e.dataTransfer, (n) => {
      if (slowToast) slowToast.close();
      slowToast = toast.info(`Reading the dropped folders… ${number(n)} files so far`, { timeout: 0 });
    })
      .then((scan) => {
        clearTimeout(timer);
        slowToast?.close();
        return startUpload(scan, currentFolder.peek()?.id);
      })
      .catch((err) => {
        clearTimeout(timer);
        slowToast?.close();
        toast.error(`Could not read the dropped items: ${errorMessage(err)}`);
      });
  });
}

function installPaste() {
  document.addEventListener('paste', (e) => {
    const t = e.target;
    if (t instanceof HTMLElement && (t.isContentEditable || /^(INPUT|TEXTAREA|SELECT)$/.test(t.tagName))) return;
    if (document.querySelector('dialog[open]')) return;
    const files = Array.from(e.clipboardData?.files || []);
    if (!files.length) return;
    e.preventDefault();
    startUpload(entriesFromFiles(renamePasted(files)), currentFolder.peek()?.id);
  });
}

// ---------------------------------------------------------------------------------------------------------------
// Wake lock & unload guard
// ---------------------------------------------------------------------------------------------------------------

/** @type {any} */
let wakeLock = null;
/** In-flight request (`wakeLock` is still null while it runs). @type {Promise<any> | null} */
let wakeLockPending = null;
let wantLock = false;
async function syncWakeLock() {
  const busy = engine.batches.some((b) => b.active);
  wantLock = busy;
  const wl = /** @type {any} */ (navigator).wakeLock;
  // Guard on the pending request, not only on the resolved sentinel: syncWakeLock() runs on every engine change,
  // and two overlapping requests would leak the first sentinel (nothing ever releases it → the screen stays awake).
  if (busy && !wakeLock && !wakeLockPending && wl && document.visibilityState === 'visible') {
    try {
      wakeLockPending = wl.request('screen');
      const l = await wakeLockPending;
      l.addEventListener('release', () => { if (wakeLock === l) wakeLock = null; });
      if (wantLock) wakeLock = l;
      else l.release().catch(() => {}); // the uploads finished while the request was in flight
    } catch { /* denied (battery saver) — uploads continue anyway */
    } finally {
      wakeLockPending = null;
    }
  } else if (!busy && wakeLock) {
    const l = wakeLock;
    wakeLock = null;
    l.release().catch(() => {});
  }
}

// ---------------------------------------------------------------------------------------------------------------
// fp:upload hooks (nav.js) & install
// ---------------------------------------------------------------------------------------------------------------

/** @param {CustomEvent} e */
async function onUploadEvent(e) {
  const d = e.detail || {};
  if (d.action === 'files' || d.action === 'folder') {
    e.preventDefault();
    startUpload(entriesFromFiles(d.files || []), d.folderId || undefined);
  } else if (d.action === 'new-folder') {
    e.preventDefault();
    const dest = await destination(d.folderId || undefined);
    if (!dest) {
      toast.warning('Open a folder first.');
      return;
    }
    const { fileActions } = await import('../components/file-actions.js');
    const acts = fileActions({ context: 'folder', items: () => [], refresh: () => {} });
    const node = await acts.newFolder({ id: dest.id, name: dest.name, perm: dest.perm, kind: 'folder', space_id: '', size: 0, created_at: '', updated_at: '' });
    if (node) events.emit('files.changed', { folderId: dest.id, created: node.id });
  } else if (d.action === 'new-request') {
    e.preventDefault();
    const cur = currentFolder.peek();
    const { requestDialog } = await import('../components/share-dialog.js');
    const folder = cur && can({ perm: /** @type {any} */ (cur).perm }, 'manage')
      ? { id: cur.id, name: cur.name || 'this folder', perm: /** @type {any} */ (cur).perm, kind: /** @type {'folder'} */ ('folder'), space_id: '', size: 0, created_at: '', updated_at: '' }
      : null;
    const s = await requestDialog({ folder });
    if (s) events.emit('shares.changed', { kind: 'request' });
  }
}

/** Install the upload manager (idempotent). */
export function install() {
  if (installed) return;
  installed = true;
  document.addEventListener('fp:upload', /** @type {EventListener} */ ((e) => { onUploadEvent(/** @type {CustomEvent} */ (e)); }));
  installDrop();
  installPaste();
  engine.persistHook = persist;
  engine.subscribe(() => {
    panel.schedule();
    syncWakeLock();
  });
  engine.onBatchEnd((b) => {
    persist(b);
    panel.schedule();
    // the server refused the .zip password or method: startUpload() re-opens the dialog with the reason instead
    if (b.state === 'failed' && b.needsZipPassword) return;
    const p = b.progress;
    if (b.state === 'done' && (b.skipped || (p.skipped > 0 && p.skipped === p.done))) {
      // conflict "skip" and nothing was stored: the .zip, or every file, has a namesake there already
      const where = b.folderName ? ` in “${b.folderName}”` : '';
      const one = b.skipped ? b.zipName : p.skipped === 1 ? b.files.find((it) => it.state === 'skipped')?.name : '';
      toast.info(one
        ? `A file named “${one}” already exists${where}, so it was skipped.`
        : `All ${number(p.skipped)} files already exist${where}, so they were skipped.`);
    } else if (b.state === 'done') {
      const where = b.folderName ? ` to “${b.folderName}”` : '';
      const uploaded = p.done - p.skipped;
      const msg = b.mode === 'zip'
        // the stored name: "Keep both" may have numbered it
        ? `“${b.resultName || b.zipName}” is ready${b.resultEncryption ? ' (password-protected)' : ''}${b.folderName ? ` in “${b.folderName}”` : ''}`
        : p.count === 1 ? `Uploaded “${b.files[0]?.name}”${where}`
          : `Uploaded ${plural(uploaded, 'file')}${where}${p.skipped ? `, ${number(p.skipped)} skipped (the names already exist)` : ''}`;
      const onFolder = currentFolder.peek()?.id === b.folderId;
      toast.success(msg, onFolder ? {} : {
        action: {
          label: 'Show',
          onClick: () => navigate(b.resultNodeId ? `/files/${encodeURIComponent(b.folderId)}?select=${encodeURIComponent(b.resultNodeId)}` : `/files/${encodeURIComponent(b.folderId)}`),
        },
      });
    } else if (b.state === 'failed') {
      if (!b.resumeFailed) toast.error(`Upload failed: ${b.error || 'unknown error'}`); // resume() says why itself
      // refused before it existed (the quota, the cap of unfinished uploads): show what holds them
      if (!b.id && !b.resumeFailed) renderServerCards(0);
    } else if (b.state === 'canceled') {
      toast.info('Upload cancelled', { timeout: 2500 });
    }
    events.emit('files.changed', { folderId: b.folderId });
    syncWakeLock();
  });
  window.addEventListener('beforeunload', (e) => {
    if (!engine.busy) return;
    e.preventDefault();
    e.returnValue = ''; // legacy browsers need a value to show the prompt
  });
  document.addEventListener('visibilitychange', () => {
    if (document.visibilityState === 'visible') syncWakeLock();
  });
  renderResumeCards();
  // GET /upload-batches sits behind mw.RequireFull, like the event stream (app.js): while a second factor, a required
  // 2FA enrolment or a password change is pending it answers 403, so the list is read once the session is complete.
  let serverCardsShown = false;
  effect(() => {
    if (serverCardsShown || !isFullSession(session.value)) return;
    serverCardsShown = true;
    untracked(() => { renderServerCards(ORPHAN_IDLE_MS); });
  });
}
