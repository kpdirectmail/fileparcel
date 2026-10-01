// @ts-check
/**
 * Admin → Backups (/admin/backups): encrypted backups (tar → zstd → age) of the database and, for full backups, all
 * file data. Create (full / metadata) with job progress, verify (quick / deep), download, delete, restore (with
 * credentials, confirmation and restart), import an archive, schedule & retention, and the backup identity.
 *   GET    /admin/backups                 → Page[Backup]
 *   POST   /admin/backups {scope, note}   → JobRef
 *   GET    /admin/backups/{id}            · DELETE /admin/backups/{id} (E)
 *   POST   /admin/backups/{id}/verify {deep} → JobRef
 *   GET    /admin/backups/{id}/download   (E) — browser download after a HEAD probe
 *   POST   /admin/backups/{id}/restore    RestoreCreds {identity | passphrase} (E) → RestoreScheduled {scheduled, restarting}
 *   POST   /admin/backups/import          raw archive body (E, streaming) → Backup
 *   GET/PUT /admin/backups/config         BackupConfig (PUT: E)
 *   POST   /admin/backups/identity        (E) → BackupIdentity {recipient, identity} (a new key pair)
 *   POST   /admin/backups/identity/export (E) → BackupIdentity (the stored identity file again)
 * Refreshes on backup.finished.
 * The page needs "Run backups" (list, create, verify; the schedule is shown read-only). Downloading, restoring,
 * deleting and importing backups, the schedule and the backup keys stay with administrators (DESIGN §6a: a backup
 * holds everything, and a restore brings back an older database).
 * Owned by unit J2.
 * @module pages/admin/backups
 */
import { h, boot, replace, append } from '../../core/dom.js';
import { api, ApiError, itemsOf, getCsrf, errorMessage } from '../../core/api.js';
import { isAdmin } from '../../core/store.js';
import { bytes, dateTime, speed } from '../../core/format.js';
import { button } from '../../components/button.js';
import { badge } from '../../components/badge.js';
import { card } from '../../components/card.js';
import { table } from '../../components/table.js';
import { toast } from '../../components/toast.js';
import { confirm, dialog } from '../../components/dialog.js';
import { field, select, toggle } from '../../components/field.js';
import { menu } from '../../components/menu.js';
import { form } from '../../components/form.js';
import { progress, skeleton } from '../../components/progress.js';
import {
  adminHeader, errorPanel, alertEl, kv, stateBadge, timeEl, moreMenu, formDialog, showSecretOnce, jobProgress, elevatedDownload,
  ensureElevated, waitForRestart, onEvents, debounce, chips,
} from './common.js';

export const title = 'Backups';

/** Cron presets for the schedule editor. */
const CRON_PRESETS = [
  { value: '', label: 'Off' },
  { value: '0 3 * * *', label: 'Every day at 03:00' },
  { value: '0 2 * * *', label: 'Every day at 02:00' },
  { value: '0 */6 * * *', label: 'Every 6 hours' },
  { value: '0 4 * * 0', label: 'Every Sunday at 04:00' },
  { value: '0 4 * * 6', label: 'Every Saturday at 04:00' },
  { value: '0 4 1 * *', label: 'On the 1st of every month at 04:00' },
];

/**
 * @param {HTMLElement} root
 * @param {import('../../core/router.js').PageContext} ctx
 */
export async function mount(root, ctx) {
  const admin = isAdmin();
  const importPicker = h('input', { class: 'hidden', attrs: { type: 'file', accept: '.fpbak,.age,application/octet-stream', tabindex: '-1', 'aria-hidden': 'true' } });
  const createBtn = button({
    label: 'Back up now',
    icon: 'archive',
    variant: 'primary',
    iconEnd: 'chevron-down',
    attrs: { 'aria-haspopup': 'menu' },
    onClick: (e) => menu({
      anchor: /** @type {Element} */ (e.currentTarget),
      align: 'end',
      items: [
        { label: 'Full backup (database + all files)', icon: 'archive', onClick: () => create('full') },
        { label: 'Metadata only (database, keys, settings)', icon: 'database', onClick: () => create('metadata') },
      ],
    }),
  });
  adminHeader(root, {
    title,
    subtitle: 'Encrypted backups of the database and your files. Keep at least one copy on another disk or machine.',
    actions: admin ? [button({ label: 'Import…', icon: 'upload', variant: 'secondary', onClick: () => importPicker.click() }), createBtn, importPicker] : createBtn,
  });
  const jobsSlot = h('div', { class: 'stack-sm' });
  const listBody = h('div', { class: 'stack' }, skeleton(4, { rows: true }));
  const configBody = h('div', { class: 'stack' }, skeleton(5));
  const identityBody = h('div', { class: 'stack' }, skeleton(2));
  append(root, jobsSlot, h('section', { class: 'page-section' }, listBody),
    h('div', { class: 'settings-grid' },
      card({ title: 'Schedule & retention', body: configBody }),
      card({ title: 'Encryption & restore key', body: identityBody })));

  /** @type {any[]} */
  let backups = [];
  /** @type {any} */
  let config = null;

  const t = table({
    caption: 'Backups',
    loading: true,
    columns: [
      {
        key: 'created',
        label: 'Created',
        render: (b) => h('span', { class: 'stack-sm gap-1' },
          h('strong', null, timeEl(b.created_at)),
          h('span', { class: 'muted text-xs', text: `${triggerLabel(b.trigger)}${b.note ? ` · ${b.note}` : ''}` })),
      },
      { key: 'scope', label: 'Contents', render: (b) => badge({ text: b.scope === 'metadata' ? 'Metadata' : 'Full', kind: b.scope === 'metadata' ? 'neutral' : 'primary' }) },
      { key: 'size', label: 'Size', align: 'end', hideBelow: 'sm', render: (b) => (b.size ? bytes(b.size) : '—') },
      {
        key: 'state',
        label: 'Status',
        render: (b) => h('span', { class: 'cluster' },
          stateBadge(b.state),
          b.verify_ok === true ? badge({ text: 'Verified', kind: 'success', icon: 'check', title: b.verified_at ? `Verified ${dateTime(b.verified_at)}` : '' }) : null,
          b.verify_ok === false ? badge({ text: 'Verification failed', kind: 'danger', icon: 'alert-circle' }) : null),
      },
      { key: 'enc', label: 'Encryption', hideBelow: 'md', render: (b) => (b.encryption === 'passphrase' ? 'Passphrase' : 'Key (age)') },
      {
        key: 'actions', label: 'Actions', srOnlyLabel: true, class: 'cell-actions',
        render: (b) => moreMenu(() => [
          { label: 'Details', icon: 'info', onClick: () => details(b) },
          admin && b.state === 'ready' ? { label: 'Download', icon: 'download', onClick: () => elevatedDownload(`/api/v1/admin/backups/${encodeURIComponent(b.id)}/download`) } : null,
          b.state === 'ready' ? { label: 'Verify', icon: 'shield-check', onClick: () => verify(b, false) } : null,
          b.state === 'ready' && b.scope === 'full' ? { label: 'Deep verify (decrypt every file)', icon: 'shield-check', onClick: () => verify(b, true) } : null,
          admin && b.state === 'ready' ? { divider: true } : null,
          admin && b.state === 'ready' ? { label: 'Restore…', icon: 'rotate-ccw', danger: true, onClick: () => restore(b) } : null,
          admin ? { label: 'Delete', icon: 'trash', danger: true, onClick: () => del(b) } : null,
        ].filter(Boolean), 'Backup actions'),
      },
    ],
    empty: 'No backups yet. Create one now — it takes a moment for the database and longer for file data.',
  });

  const loadList = async () => {
    try {
      const res = await api.get('/admin/backups', { signal: ctx.signal, query: { limit: 200 } });
      backups = itemsOf(res).sort((a, b) => String(b.created_at).localeCompare(String(a.created_at)));
      t.setRows(backups);
      // Like the dashboard and doctor: imported archives (possibly from another server, dated at import) and backups
      // that failed verification are not this server's last good backup.
      const newest = backups.find((b) => b.state === 'ready' && b.trigger !== 'import' && b.verify_ok !== false);
      const age = newest ? (Date.now() - new Date(newest.created_at).getTime()) / 86_400_000 : Infinity;
      replace(listBody, 
        age > 8 ? alertEl('warning', newest ? `The last good backup is ${Math.floor(age)} days old`
          : backups.some((b) => b.state === 'ready') ? 'There is no good backup of this server yet' : 'There is no backup yet', 'Create one now and check that the schedule is on.') : null,
        t.el);
    } catch (err) {
      if (err instanceof ApiError && err.aborted) return;
      replace(listBody, errorPanel(err, loadList));
    }
  };

  const loadConfig = async () => {
    try {
      config = (await api.get('/admin/backups/config', { signal: ctx.signal })) || {};
    } catch (err) {
      if (err instanceof ApiError && err.aborted) return;
      replace(configBody, errorPanel(err, loadConfig));
      replace(identityBody);
      return;
    }
    drawConfig();
    drawIdentity();
  };

  // ------------------------------------------------------------------------------------------ actions
  /** @param {'full' | 'metadata'} scope */
  const create = async (scope) => {
    const note = field({ label: 'Note (optional)', name: 'note', maxlength: 200, placeholder: scope === 'full' ? 'e.g. before upgrading' : '' });
    const ok = await formDialog({
      title: scope === 'full' ? 'Create a full backup' : 'Create a metadata backup',
      intro: scope === 'full'
        ? 'Includes the database, keys, settings, certificates and every stored file. Needs free space for the compressed archive.'
        : 'Includes the database, keys, settings and certificates, but not file contents. Small and quick — good before configuration changes.',
      fields: [note],
      submitLabel: 'Start backup',
      submitIcon: 'archive',
      onSubmit: async (v) => {
        const res = await api.post('/admin/backups', { scope, note: String(v.note).trim() || undefined });
        return res || true;
      },
    });
    if (!ok) return;
    const jobId = ok?.job_id;
    if (jobId) followJob(jobId, scope === 'full' ? 'Full backup' : 'Metadata backup');
    else toast.success('Backup started');
    await loadList();
  };

  /**
   * @param {string} jobId
   * @param {string} label
   */
  const followJob = (jobId, label) => {
    const box = h('div', { class: 'card' }, jobProgress(jobId, {
      label,
      signal: ctx.signal,
      onDone: (j) => {
        if (j.state === 'succeeded') toast.success(`${label} finished`);
        else if (j.state === 'failed') toast.error(`${label} failed${j.error ? `: ${j.error}` : ''}`);
        loadList();
        setTimeout(() => box.remove(), 8000);
      },
    }));
    jobsSlot.prepend(box);
  };

  /**
   * @param {any} b
   * @param {boolean} deep
   */
  const verify = async (b, deep) => {
    try {
      const res = await api.post(`/admin/backups/${encodeURIComponent(b.id)}/verify`, { deep });
      if (res?.job_id) followJob(res.job_id, deep ? 'Deep verification' : 'Verification');
      else {
        toast.success('Verification started');
        await loadList();
      }
    } catch (err) {
      toast.error(err);
    }
  };

  /** @param {any} b */
  const del = async (b) => {
    const ok = await confirm({
      title: 'Delete this backup?',
      message: `The ${b.scope === 'metadata' ? 'metadata' : 'full'} backup from ${dateTime(b.created_at)}${b.size ? ` (${bytes(b.size)})` : ''} is deleted from the server. Copies elsewhere are not affected.`,
      confirmLabel: 'Delete',
      danger: true,
    });
    if (!ok) return;
    try {
      await api.del(`/admin/backups/${encodeURIComponent(b.id)}`);
      toast.success('Backup deleted');
      await loadList();
    } catch (err) {
      toast.error(err);
    }
  };

  /** @param {any} b */
  const details = (b) => {
    dialog({
      title: `Backup from ${dateTime(b.created_at)}`,
      size: 'md',
      body: kv([
        ['ID', h('span', { class: 'mono text-xs', text: b.id })],
        ['File', h('span', { class: 'mono text-xs break', text: b.file_name })],
        ['Contents', b.scope === 'metadata' ? 'Metadata only' : 'Full (database + files)'],
        ['State', stateBadge(b.state)],
        ['Size', b.size ? bytes(b.size) : null],
        ['Files', b.blob_count ? `${b.blob_count} (${bytes(b.blob_bytes)})` : null],
        ['Database', b.db_size ? bytes(b.db_size) : null],
        ['Encryption', b.encryption === 'passphrase' ? 'Passphrase' : 'age key'],
        ['Recipients', (b.recipients || []).length ? chips(b.recipients) : null],
        ['SHA-256', b.sha256 ? h('span', { class: 'mono text-xs break', text: b.sha256 }) : null],
        ['App version', b.app_version || null],
        ['Schema', b.schema_version ? String(b.schema_version) : null],
        ['Trigger', triggerLabel(b.trigger)],
        ['Finished', b.finished_at ? dateTime(b.finished_at) : null],
        ['Verified', b.verified_at ? `${dateTime(b.verified_at)} — ${b.verify_ok ? 'OK' : 'FAILED'}` : 'never'],
        ['Copied to', b.copied_to || null],
        ['Error', b.error ? h('span', { class: 'danger-text', text: b.error }) : null],
        ['Note', b.note || null],
      ]),
      actions: [{ label: 'Close', variant: 'primary' }],
    }).open();
  };

  /** @param {any} b */
  const restore = async (b) => {
    const passMode = b.encryption === 'passphrase';
    const secret = passMode
      ? field({ label: 'Backup passphrase', name: 'passphrase', type: 'password', autocomplete: 'off', help: 'Leave empty to use the passphrase saved in the backup settings.' })
      : field({ label: 'Backup identity (AGE-SECRET-KEY-…)', name: 'identity', type: 'textarea', rows: 3, autocomplete: 'off', help: 'Leave empty to use the identity stored on this server. Paste it when restoring after the server’s keys were lost.', attrs: { spellcheck: 'false', autocapitalize: 'off', class: 'mono' } });
    const typed = field({ label: 'Type “restore” to confirm', name: 'confirm', required: true, autocomplete: 'off', attrs: { spellcheck: 'false', autocapitalize: 'off' } });
    /** @type {any} */
    let before = null;
    /** @type {any} */
    const ok = await formDialog({
      title: 'Restore this backup?',
      size: 'md',
      intro: h('div', { class: 'stack-sm' },
        alertEl('danger', 'Everything changes back', `All accounts, settings${b.scope === 'full' ? ', files' : ''} and share links return to the state of ${dateTime(b.created_at)}. Changes made since then are lost.`),
        b.scope === 'metadata' ? alertEl('warning', 'Metadata-only backup', 'File contents are not in this backup; the current file data is kept. Files uploaded after it was made are not part of the restored state: their data stays in the pre-restore folder on the server until you delete it.') : null,
        h('p', { class: 'text-sm', text: 'FileParcel moves the current data to a pre-restore folder on the server and restarts right away to restore. Everyone is signed out and signs in again with the accounts from the backup.' })),
      fields: [secret, typed],
      submitLabel: 'Restore',
      submitIcon: 'rotate-ccw',
      submitVariant: 'danger',
      onSubmit: async (v) => {
        if (String(v.confirm).trim().toLowerCase() !== 'restore') throw new ApiError(422, 'invalid', 'Type “restore” to confirm.', 'confirm');
        /** @type {Record<string, string>} */
        const creds = {};
        if (passMode && String(v.passphrase)) creds.passphrase = String(v.passphrase);
        if (!passMode && String(v.identity).trim()) {
          const id = String(v.identity).trim();
          // shape only (X25519 or post-quantum hybrid); the server parses it
          if (!/^AGE-SECRET-KEY-(PQ-)?1[0-9A-Z]+$/.test(id.split(/\s+/).find((l) => l.startsWith('AGE-SECRET-KEY-')) || '')) {
            throw new ApiError(422, 'invalid', 'An age identity starts with AGE-SECRET-KEY-1 or AGE-SECRET-KEY-PQ-1.', 'identity');
          }
          creds.identity = id;
        }
        // pid / started_at before the server goes down, so the wait below can tell the new process apart
        before = await api.get('/admin/system', { handle: false }).catch(() => null);
        /** @type {any} */
        const res = await api.post(`/admin/backups/${encodeURIComponent(b.id)}/restore`, creds);
        return res || { scheduled: true, restarting: false };
      },
    });
    if (!ok) return;
    // The server restarts by itself as soon as the restore is scheduled (restarting: true): only wait for it.
    // The restored database has other sessions, so this usually ends on the sign-in page.
    if (ok.restarting) {
      await waitForRestart({ before, title: 'Restoring backup', startText: 'Restoring the backup and restarting…', timeoutMs: 10 * 60_000 });
    } else {
      toast.info('The restore will run the next time the server starts.');
    }
  };

  // ------------------------------------------------------------------------------------------ import
  importPicker.addEventListener('change', async () => {
    const file = importPicker.files?.[0];
    importPicker.value = '';
    if (!file) return;
    const ok = await confirm({
      title: 'Import this backup?',
      message: `${file.name} (${bytes(file.size)}) is uploaded to the server and added to the backup list. Nothing is restored until you choose “Restore”.`,
      confirmLabel: 'Upload',
    });
    if (!ok) return;
    if (!(await ensureElevated(5 * 60_000))) return;
    const bar = progress({ value: 0, max: file.size || 1, label: `Uploading ${file.name}`, showValue: true });
    const rate = h('span', { class: 'text-xs muted' });
    const cancelBtn = button({ label: 'Cancel', size: 'sm', variant: 'ghost' });
    const box = h('div', { class: 'card stack-sm' }, bar.el, h('div', { class: 'split' }, rate, cancelBtn));
    jobsSlot.prepend(box);
    const xhr = new XMLHttpRequest();
    cancelBtn.addEventListener('click', () => xhr.abort());
    const started = performance.now();
    const onBeforeUnload = (/** @type {BeforeUnloadEvent} */ e) => e.preventDefault();
    window.addEventListener('beforeunload', onBeforeUnload);
    try {
      /** @type {any} */
      const res = await new Promise((resolve, reject) => {
        xhr.open('POST', '/api/v1/admin/backups/import');
        xhr.withCredentials = true;
        xhr.setRequestHeader('Content-Type', 'application/octet-stream');
        xhr.setRequestHeader('Accept', 'application/json');
        xhr.setRequestHeader('X-FP-CSRF', getCsrf());
        xhr.setRequestHeader('X-FP-Filename', encodeURIComponent(file.name));
        xhr.upload.addEventListener('progress', (e) => {
          bar.set(e.loaded, file.size || 1);
          const secs = (performance.now() - started) / 1000;
          if (secs > 1) rate.textContent = `${bytes(e.loaded)} of ${bytes(file.size)} · ${speed(e.loaded / secs)}`;
        });
        xhr.addEventListener('load', () => {
          if (xhr.status >= 200 && xhr.status < 300) {
            try { resolve(xhr.responseText ? JSON.parse(xhr.responseText) : null); } catch { resolve(null); }
            return;
          }
          /** @type {any} */
          let body = null;
          try { body = JSON.parse(xhr.responseText); } catch { /* not JSON */ }
          reject(new ApiError(xhr.status, body?.error?.code || `http_${xhr.status}`, body?.error?.message || `Upload failed (${xhr.status})`));
        });
        xhr.addEventListener('error', () => reject(new ApiError(0, 'network', 'The connection was interrupted.')));
        xhr.addEventListener('abort', () => reject(new ApiError(0, 'aborted', 'Upload cancelled')));
        xhr.send(file);
      });
      toast.success(`Imported backup${res?.file_name ? ` ${res.file_name}` : ''}`);
      box.remove();
      await loadList();
    } catch (err) {
      box.remove();
      if (err instanceof ApiError && err.aborted) toast.info('Import cancelled');
      else toast.error(`Import failed: ${errorMessage(err)}`);
    } finally {
      window.removeEventListener('beforeunload', onBeforeUnload);
    }
  });

  // ------------------------------------------------------------------------------------------ config
  /** The schedule and retention as text, for roles that may run backups but not configure them. */
  const drawConfigReadOnly = () => {
    const c = config;
    /** @param {string} v */
    const when = (v) => (v ? CRON_PRESETS.find((p) => p.value === v)?.label || h('span', { class: 'mono', text: v }) : 'Off');
    /** @param {number} n @param {string} unit */
    const keep = (n, unit) => (Number(n) > 0 ? `${n} ${unit}` : null);
    const rules = [keep(c.keep_last, 'newest'), keep(c.keep_daily, 'daily'), keep(c.keep_weekly, 'weekly'), keep(c.keep_monthly, 'monthly')].filter(Boolean);
    replace(configBody,
      !c.enabled ? alertEl('warning', 'Scheduled backups are off', 'Only manual backups are made.') : null,
      kv([
        ['Scheduled backups', c.enabled ? 'On' : 'Off'],
        ['Metadata backups', when(c.schedule_meta || '')],
        ['Full backups', when(c.schedule_full || '')],
        ['Keep', rules.length ? rules.join(' · ') : 'Everything (retention is off)'],
        ['Also copy to', c.copy_to ? h('span', { class: 'mono text-xs break', text: c.copy_to }) : null],
      ]),
      h('p', { class: 'muted text-sm', text: 'Only administrators can change the schedule and retention.' }));
  };

  const drawConfig = () => {
    if (!admin) {
      drawConfigReadOnly();
      return;
    }
    const c = config;
    const enabled = toggle({ label: 'Scheduled backups', name: 'enabled', checked: !!c.enabled, help: 'Runs the schedules below. Manual backups always work.' });
    const meta = cronField('Metadata backups', 'schedule_meta', c.schedule_meta || '');
    const full = cronField('Full backups', 'schedule_full', c.schedule_full || '');
    // max: the registered limits of backup.keep_* (internal/backup/settings.go)
    const keep = (/** @type {string} */ label, /** @type {string} */ name, /** @type {number} */ v, /** @type {string} */ help, /** @type {number} */ max) => field({ label, name, type: 'number', value: v ?? 0, min: 0, max, inputmode: 'numeric', help });
    const kLast = keep('Keep the newest', 'keep_last', c.keep_last, 'backups, whatever their age', 1000);
    const kDaily = keep('Daily', 'keep_daily', c.keep_daily, 'one per day for this many days', 3650);
    const kWeekly = keep('Weekly', 'keep_weekly', c.keep_weekly, 'one per week for this many weeks', 520);
    const kMonthly = keep('Monthly', 'keep_monthly', c.keep_monthly, 'one per month for this many months', 1200);
    const copyTo = field({ label: 'Also copy to', name: 'copy_to', value: c.copy_to || '', placeholder: '/mnt/usb/fileparcel-backups', help: 'Optional folder outside the FileParcel directory (e.g. a USB disk or network share mounted on the server).', attrs: { spellcheck: 'false' } });
    const f = form({
      fields: [
        enabled, meta, full,
        h('fieldset', { class: 'fieldset' }, h('legend', { class: 'fieldset-legend', text: 'Retention' }),
          h('p', { class: 'muted text-sm', text: 'Only scheduled backups are pruned; 0 turns a rule off. With all four at 0 retention is off and nothing is pruned.' }),
          h('div', { class: 'grid-keep' }, kLast.el, kDaily.el, kWeekly.el, kMonthly.el)),
        copyTo,
        // the retention inputs are laid out inside the fieldset above; these placeholder controls (hidden element,
        // real input) register them with form() so values, native validation and inline field errors still work
      ].concat([kLast, kDaily, kWeekly, kMonthly].map((x) => /** @type {any} */ ({ ...x, el: h('span', { hidden: true }) }))),
      submitLabel: 'Save schedule',
      submitIcon: 'check',
      onSubmit: async (v) => {
        const body = {
          ...config,
          enabled: !!v.enabled,
          schedule_meta: meta.value(),
          schedule_full: full.value(),
          keep_last: Number(v.keep_last) || 0,
          keep_daily: Number(v.keep_daily) || 0,
          keep_weekly: Number(v.keep_weekly) || 0,
          keep_monthly: Number(v.keep_monthly) || 0,
          copy_to: String(v.copy_to).trim(),
        };
        delete body.has_identity;
        delete body.identity_recipient;
        delete body.has_passphrase;
        delete body.passphrase;
        await api.put('/admin/backups/config', body);
        toast.success('Backup schedule saved');
        await loadConfig();
      },
    });
    replace(configBody, 
      !c.enabled ? alertEl('warning', 'Scheduled backups are off', 'Only manual backups are made.') : null,
      f.el);
  };

  // ------------------------------------------------------------------------------------------ identity / encryption
  const drawIdentity = () => {
    const c = config;
    const passMode = c.encryption === 'passphrase';
    // The server's own backup key (the public key of the stored identity) is a recipient of every backup, whatever
    // backup.recipients lists, and a backup with no recipient at all first generates that identity (internal/backup
    // encryptionPlan) — an empty list never means that backups cannot be made. identity_recipient is that key (unknown
    // while the keys are locked); it is listed once, on its own line.
    const own = String(c.identity_recipient || '');
    const listed = (c.recipients || []).filter((/** @type {string} */ r) => !own || !String(r).split(/\s+/).includes(own));
    const ownNote = own
      ? h('div', { class: 'stack-sm' }, chips([own]),
        h('span', { class: 'muted text-sm', text: 'The server’s own backup key (the stored identity): every backup is encrypted to it.' }))
      : c.has_identity
        ? h('span', { class: listed.length ? 'muted text-sm' : 'muted', text: listed.length
          ? 'plus the server’s own backup key (the stored identity), which is always added'
          : 'the server’s own backup key (the stored identity)' })
        : null;
    const recipients = listed.length || ownNote
      ? h('div', { class: 'stack-sm' }, listed.length ? chips(listed) : null, ownNote)
      : h('span', { class: 'muted', text: 'none yet — the next backup generates a backup identity; export it afterwards and keep it safe' });
    replace(identityBody, 
      kv([
        ['Encrypted with', passMode ? 'A passphrase' : 'age public keys (recipients)'],
        ['Recipients', !passMode ? recipients : null],
        ['Restore key on server', passMode ? (c.has_passphrase ? 'Passphrase saved' : 'No passphrase saved') : c.has_identity ? 'Identity saved (restores work without pasting it)' : 'No identity saved'],
      ]),
      h('p', { class: 'muted text-sm', text: passMode
        ? 'Every backup is encrypted with the passphrase. You need it to restore on a new machine.'
        : 'Backups are encrypted to the recipients’ public keys; only the matching secret identities can decrypt them. Keep a copy of the identity somewhere other than this server — without it, backups cannot be restored after a disk failure.' }),
      !admin ? h('p', { class: 'muted text-sm', text: 'Only administrators can export or change the backup keys.' }) : h('div', { class: 'btn-row btn-row--start' },
        !passMode && c.has_identity ? button({ label: 'Export identity…', icon: 'download', variant: 'secondary', onClick: exportIdentity }) : null,
        !passMode ? button({ label: c.has_identity ? 'Generate a new identity…' : 'Generate identity…', icon: 'key', variant: c.has_identity ? 'secondary' : 'primary', onClick: generateIdentity }) : null,
        button({ label: 'Change encryption…', icon: 'lock', variant: 'ghost', onClick: changeEncryption })));
  };

  const generateIdentity = async () => {
    const ok = await confirm({
      title: 'Generate a new backup identity?',
      message: 'A new key pair is created and its public key is used for future backups. Existing backups still need the previous identity — keep it.',
      confirmLabel: 'Generate',
    });
    if (!ok) return;
    try {
      const res = await api.post('/admin/backups/identity', {});
      const id = String(res?.identity || '');
      if (!id) throw new ApiError(500, 'bad_response', 'The server did not return an identity.');
      const inst = boot().instance || 'FileParcel';
      await showSecretOnce({
        title: 'Backup identity',
        intro: h('div', { class: 'stack-sm' },
          h('p', { text: 'This secret key decrypts your backups. Store it in a password manager or print it — somewhere that survives the loss of this server.' }),
          res?.recipient ? h('p', { class: 'text-sm' }, 'Public key: ', h('span', { class: 'mono text-xs break', text: res.recipient })) : null),
        secret: id,
        label: 'Identity',
        what: 'Identity',
        multiline: true,
        filename: `${inst.toLowerCase().replace(/[^a-z0-9]+/g, '-')}-backup-identity.txt`,
        fileContent: `# ${inst} backup identity (age)\n# created: ${new Date().toISOString()}\n# public key: ${res?.recipient || ''}\n${id}\n`,
        warningTitle: 'Keep it secret',
        warning: 'Anyone with this identity can decrypt your backups. You can export it again from this page while it is stored on the server.',
      });
      await loadConfig();
    } catch (err) {
      toast.error(err);
    }
  };

  const exportIdentity = async () => {
    const ok = await confirm({
      title: 'Show the backup identity?',
      message: 'The secret key that decrypts your backups is shown so you can store a copy away from this server. Anyone with it can decrypt your backups. The export is recorded in the audit log.',
      confirmLabel: 'Show identity',
    });
    if (!ok) return;
    try {
      const res = await api.post('/admin/backups/identity/export', {});
      const id = String(res?.identity || '').trim();
      if (!id) throw new ApiError(500, 'bad_response', 'The server did not return an identity.');
      const inst = boot().instance || 'FileParcel';
      await showSecretOnce({
        title: 'Backup identity',
        intro: h('div', { class: 'stack-sm' },
          h('p', { text: 'This secret key decrypts your backups. Store it in a password manager or print it — somewhere that survives the loss of this server.' }),
          /^# previous identities/m.test(id) ? h('p', { class: 'text-sm', text: 'The file also holds the previous identities, for backups made before the key was last changed.' }) : null,
          res?.recipient ? h('p', { class: 'text-sm' }, 'Public key: ', h('span', { class: 'mono text-xs break', text: res.recipient })) : null),
        secret: id,
        label: 'Identity',
        what: 'Identity',
        multiline: true,
        filename: `${inst.toLowerCase().replace(/[^a-z0-9]+/g, '-')}-backup-identity.txt`,
        fileContent: `# ${inst} backup identity (age), exported ${new Date().toISOString()}\n${id}\n`,
        warningTitle: 'Keep it secret',
        warning: 'Anyone with this identity can decrypt your backups.',
      });
      await loadConfig();
    } catch (err) {
      toast.error(err);
    }
  };

  const changeEncryption = async () => {
    const c = config;
    const mode = select({
      label: 'Encrypt backups with', name: 'encryption', value: c.encryption || 'x25519',
      options: [{ value: 'x25519', label: 'age public keys (recommended — no secret on the server needed)' }, { value: 'passphrase', label: 'A passphrase' }],
      onChange: () => sync(),
    });
    const recipients = field({
      label: 'Recipients (public keys)', name: 'recipients', type: 'textarea', rows: 3, value: (c.recipients || []).join('\n'),
      help: 'One age public key (age1…) per line. Add a key whose identity you keep offline.', attrs: { spellcheck: 'false', autocapitalize: 'off', class: 'mono' },
    });
    const pass = field({ label: 'Passphrase', name: 'passphrase', type: 'password', autocomplete: 'new-password', placeholder: c.has_passphrase ? '•••••••• (saved — leave empty to keep)' : '', help: 'At least 12 characters. Stored encrypted on the server so scheduled backups can use it.' });
    const sync = () => {
      recipients.el.hidden = mode.input.value !== 'x25519';
      pass.el.hidden = mode.input.value !== 'passphrase';
    };
    sync();
    const ok = await formDialog({
      title: 'Backup encryption',
      fields: [mode, recipients, pass],
      submitLabel: 'Save',
      submitIcon: 'check',
      onSubmit: async (v) => {
        /** @type {Record<string, any>} */
        const body = { ...c, encryption: v.encryption };
        delete body.has_identity;
        delete body.identity_recipient;
        delete body.has_passphrase;
        delete body.passphrase;
        if (v.encryption === 'x25519') {
          const list = String(v.recipients).split(/[\s,]+/).map((x) => x.trim()).filter(Boolean);
          // shape only (X25519 age1… or post-quantum age1pq1…); the server parses every key
          const bad = list.find((r) => !/^age1[0-9a-z]+$/.test(r));
          if (bad) throw new ApiError(422, 'invalid', `“${bad.slice(0, 24)}…” is not an age public key.`, 'recipients');
          if (!list.length && !c.has_identity) throw new ApiError(422, 'invalid', 'Add at least one recipient or generate an identity.', 'recipients');
          body.recipients = list;
        } else {
          const p = String(v.passphrase);
          if (p && p.length < 12) throw new ApiError(422, 'invalid', 'Use at least 12 characters.', 'passphrase');
          if (!p && !c.has_passphrase) throw new ApiError(422, 'invalid', 'Enter a passphrase.', 'passphrase');
          if (p) body.passphrase = p;
        }
        await api.put('/admin/backups/config', body);
        return true;
      },
    });
    if (!ok) return;
    toast.success('Backup encryption saved');
    await loadConfig();
  };

  const refresh = debounce(() => loadList(), 600);
  const off = onEvents(['backup.finished'], refresh);
  await Promise.all([loadList(), loadConfig()]);
  return () => {
    off();
    refresh.cancel();
  };
}

/** @param {string} t */
function triggerLabel(t) {
  return { manual: 'Manual', schedule: 'Scheduled', 'pre-upgrade': 'Before upgrade', final: 'Before uninstall', import: 'Imported' }[t] || t || 'Manual';
}

/**
 * Cron schedule control: preset select + custom 5-field expression.
 * @param {string} label
 * @param {string} name
 * @param {string} value
 * @returns {import('../../components/field.js').Control}
 */
function cronField(label, name, value) {
  const preset = CRON_PRESETS.some((p) => p.value === value) ? value : 'custom';
  const sel = select({
    label,
    name: `${name}_preset`,
    value: preset,
    options: [...CRON_PRESETS, { value: 'custom', label: 'Custom (cron expression)…' }],
    onChange: () => sync(),
  });
  const expr = field({ label: 'Cron expression', hideLabel: true, name, value: preset === 'custom' ? value : '', placeholder: 'minute hour day month weekday, e.g. 30 1 * * *', attrs: { spellcheck: 'false', autocapitalize: 'off', class: 'mono' } });
  const input = /** @type {HTMLInputElement} */ (expr.input);
  const validate = () => {
    const v = input.value.trim();
    input.setCustomValidity(sel.input.value === 'custom' && !/^(\S+\s+){4}\S+$/.test(v) ? 'Use five fields: minute hour day month weekday.' : '');
  };
  const sync = () => {
    expr.el.hidden = sel.input.value !== 'custom';
    input.required = sel.input.value === 'custom';
    validate();
  };
  input.addEventListener('input', validate);
  sync();
  return {
    el: h('div', { class: 'cron-field' }, sel.el, expr.el),
    input,
    name,
    setError: (m) => expr.setError(m),
    value: () => (sel.input.value === 'custom' ? input.value.trim().replace(/\s+/g, ' ') : sel.input.value),
  };
}

