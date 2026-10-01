// @ts-check
/**
 * Admin → Encryption (/admin/encryption): master key state and mode (plain = unlocks automatically at start /
 * sealed = a passphrase is needed after every restart), seal / unseal / change passphrase / lock, key rotation
 * (blob and field KEKs, master key, full data re-encryption) with job progress, and the recovery key (shown once).
 *   GET  /admin/keys                         → KeyStatus
 *   POST /admin/keys/seal {passphrase}       (E)   plain → sealed
 *   POST /admin/keys/unseal {passphrase}     (E)   sealed → plain
 *   POST /admin/keys/passphrase {current_passphrase, new_passphrase} (E)
 *   POST /admin/keys/lock                    (E)   sealed only; everything stops until someone unlocks
 *   POST /admin/keys/rotate {target: kek|master|data, purpose?} (E) → JobRef | 204
 *   POST /admin/keys/recovery                (E) → RecoveryKey {recovery_key} (shown once)
 * Owned by unit J2.
 * @module pages/admin/encryption
 */
import { h, boot, replace, append } from '../../core/dom.js';
import { api, ApiError } from '../../core/api.js';
import { button } from '../../components/button.js';
import { badge } from '../../components/badge.js';
import { card } from '../../components/card.js';
import { table } from '../../components/table.js';
import { toast } from '../../components/toast.js';
import { confirm } from '../../components/dialog.js';
import { field } from '../../components/field.js';
import { skeleton } from '../../components/progress.js';
import {
  adminHeader, errorPanel, alertEl, kv, stateBadge, timeEl, formDialog, confirmTyped, showSecretOnce, jobProgress, onEvents, debounce,
} from './common.js';
import { strengthMeter, estimate } from '../../public/password-strength.js';

export const title = 'Encryption';

/**
 * @param {HTMLElement} root
 * @param {import('../../core/router.js').PageContext} ctx
 */
export async function mount(root, ctx) {
  adminHeader(root, {
    title,
    subtitle: 'Every file is encrypted at rest. Manage the master key that protects them.',
  });
  const statusBody = h('div', { class: 'stack' }, skeleton(4));
  const modeBody = h('div', { class: 'stack' }, skeleton(3));
  const rotateBody = h('div', { class: 'stack' }, skeleton(4));
  const recoveryBody = h('div', { class: 'stack' }, skeleton(2));
  const jobsSlot = h('div', { class: 'stack-sm' });
  append(root, 
    jobsSlot,
    h('div', { class: 'settings-grid' },
      h('div', { class: 'stack' }, card({ title: 'Status', body: statusBody }), card({ title: 'Recovery key', body: recoveryBody })),
      h('div', { class: 'stack' }, card({ title: 'Unlock mode', body: modeBody }))),
    card({ title: 'Key rotation', body: rotateBody }));

  /** @type {any} */
  let ks = {};

  const load = async () => {
    try {
      ks = (await api.get('/admin/keys', { signal: ctx.signal })) || {};
    } catch (err) {
      if (err instanceof ApiError && err.aborted) return;
      replace(statusBody, errorPanel(err, load));
      for (const b of [modeBody, rotateBody, recoveryBody]) replace(b);
      return;
    }
    drawStatus();
    drawMode();
    drawRotate();
    drawRecovery();
  };

  const sealed = () => ks.mode === 'sealed';

  const drawStatus = () => {
    replace(statusBody, 
      h('div', { class: 'cluster' },
        stateBadge(ks.state),
        badge({ text: sealed() ? 'Sealed with a passphrase' : 'Unlocks automatically', kind: sealed() ? 'primary' : 'neutral', icon: sealed() ? 'lock' : 'unlock' })),
      kv([
        ['Cipher for new files', ks.cipher_name || String(ks.cipher || '—')],
        ['Master key ID', ks.mk_id ? h('span', { class: 'mono text-xs', text: ks.mk_id }) : null],
        ['Memory protection', ks.mlocked ? 'Key kept in locked memory (never swapped)' : 'Standard memory (mlock unavailable)'],
        ['Recovery key', ks.recovery_configured ? 'Configured' : 'Not configured'],
        ['Unlock from the web', { lan: 'From local networks', any: 'From anywhere', off: 'Off — only from the server’s terminal' }[String(ks.web_unlock)] || ks.web_unlock || null],
      ]),
      h('p', { class: 'muted text-sm', text: 'File contents, thumbnails, backups, two-factor secrets, passkeys and share tokens are encrypted. File names, sizes and dates are not — use full-disk encryption for those.' }));
  };

  // ------------------------------------------------------------------------------------------ mode
  const drawMode = () => {
    if (sealed()) {
      replace(modeBody, 
        h('p', { class: 'text-sm', text: 'The master key is sealed with a passphrase. After every restart FileParcel stays locked until someone enters it on the unlock page or runs “fileparcel keys unlock”.' }),
        alertEl('info', 'Keep the passphrase and recovery key safe', 'Without either of them the files cannot be decrypted — not even by an administrator.'),
        h('div', { class: 'btn-row btn-row--start' },
          button({ label: 'Change passphrase', icon: 'key', onClick: changePassphrase }),
          button({ label: 'Lock now', icon: 'lock', variant: 'secondary', onClick: lockNow }),
          button({ label: 'Switch to automatic unlock', icon: 'unlock', variant: 'ghost', onClick: unseal })),
        h('a', { class: 'text-sm', href: '/admin/settings/keys', text: 'Who may unlock from the web…' }));
      return;
    }
    replace(modeBody, 
      h('p', { class: 'text-sm', text: 'The master key is stored unsealed next to the data, so FileParcel starts unattended. This protects backups and copied blob files, but not someone who has the whole disk — use full-disk encryption, or seal the key with a passphrase.' }),
      h('ul', { class: 'hint-list' },
        h('li', { text: 'Sealed: strongest protection. Needs the passphrase after every restart or power cut.' }),
        h('li', { text: 'Automatic: convenient for home servers with an encrypted disk (LUKS, FileVault).' })),
      h('div', { class: 'btn-row btn-row--start' }, button({ label: 'Seal with a passphrase…', icon: 'lock', variant: 'primary', onClick: seal })));
  };

  /**
   * Passphrase + confirmation fields with a strength meter.
   * @param {string} label
   * @param {string} name
   */
  const passFields = (label, name) => {
    const p = field({ label, name, type: 'password', autocomplete: 'new-password', required: true, minlength: 12, maxlength: 1024, help: 'At least 12 characters; a sentence of 5–6 random words is ideal.' });
    const meter = strengthMeter(/** @type {HTMLInputElement} */ (p.input), { min: 12 });
    append(p.el, meter.el);
    const again = field({ label: 'Repeat passphrase', name: `${name}_again`, type: 'password', autocomplete: 'new-password', required: true });
    return [p, again];
  };

  /**
   * @param {Record<string, any>} v
   * @param {string} name
   */
  const checkPass = (v, name) => {
    if (v[name] !== v[`${name}_again`]) throw new ApiError(422, 'invalid', 'The passphrases do not match.', `${name}_again`);
    const est = estimate(String(v[name]), { min: 12 });
    if (est.score < 3) throw new ApiError(422, 'invalid', est.warning || 'Choose a longer, less predictable passphrase — it is the only protection of the key.', name);
  };

  const seal = async () => {
    const [p, again] = passFields('New passphrase', 'passphrase');
    const ack = h('label', { class: 'check' }, h('input', { attrs: { type: 'checkbox', required: true, name: 'ack' } }), h('span', { text: 'I understand that FileParcel stays locked after each restart until the passphrase is entered.' }));
    const ok = await formDialog({
      title: 'Seal the master key',
      intro: alertEl('warning', 'Unattended restarts stop working', 'After a reboot or update nobody can use FileParcel until you unlock it. Scheduled backups and share links pause meanwhile.'),
      fields: [p, again, ack],
      submitLabel: 'Seal',
      submitIcon: 'lock',
      onSubmit: async (v) => {
        checkPass(v, 'passphrase');
        if (!/** @type {HTMLInputElement} */ (ack.querySelector('input')).checked) throw new ApiError(422, 'invalid', 'Please confirm that you understand.');
        await api.post('/admin/keys/seal', { passphrase: v.passphrase });
        return true;
      },
    });
    if (!ok) return;
    toast.success('Master key sealed');
    await load();
    if (!ks.recovery_configured) {
      const yes = await confirm({ title: 'Create a recovery key now?', message: 'If the passphrase is ever forgotten, the recovery key is the only way to unlock the server.', confirmLabel: 'Create recovery key' });
      if (yes) await exportRecovery(true);
    }
  };

  const unseal = async () => {
    const p = field({ label: 'Current passphrase', name: 'passphrase', type: 'password', autocomplete: 'current-password', required: true });
    const ok = await formDialog({
      title: 'Switch to automatic unlock?',
      intro: 'The master key is stored unsealed so FileParcel can start without you. Anyone who copies the whole server directory can then decrypt the files.',
      fields: [p],
      submitLabel: 'Unseal',
      submitIcon: 'unlock',
      submitVariant: 'danger',
      onSubmit: async (v) => {
        try {
          await api.post('/admin/keys/unseal', { passphrase: v.passphrase });
        } catch (err) {
          if (err instanceof ApiError && (err.status === 401 || err.status === 422 || err.code === 'corrupt') && !err.field) throw new ApiError(422, 'invalid', 'That passphrase is not correct.', 'passphrase');
          throw err;
        }
        return true;
      },
    });
    if (!ok) return;
    toast.success('FileParcel now unlocks automatically');
    await load();
  };

  const changePassphrase = async () => {
    const cur = field({ label: 'Current passphrase', name: 'current_passphrase', type: 'password', autocomplete: 'current-password', required: true });
    const [p, again] = passFields('New passphrase', 'new_passphrase');
    const ok = await formDialog({
      title: 'Change the passphrase',
      fields: [cur, p, again],
      submitLabel: 'Change passphrase',
      submitIcon: 'key',
      onSubmit: async (v) => {
        checkPass(v, 'new_passphrase');
        try {
          await api.post('/admin/keys/passphrase', { current_passphrase: v.current_passphrase, new_passphrase: v.new_passphrase });
        } catch (err) {
          if (err instanceof ApiError && (err.status === 401 || err.code === 'corrupt') && !err.field) throw new ApiError(422, 'invalid', 'The current passphrase is not correct.', 'current_passphrase');
          throw err;
        }
        return true;
      },
    });
    if (ok) toast.success('Passphrase changed. The recovery key still works.');
  };

  const lockNow = async () => {
    const ok = await confirmTyped({
      title: 'Lock FileParcel now?',
      message: h('div', { class: 'stack-sm' },
        h('p', { text: 'The master key is wiped from memory. Nobody — including you — can open files, sign in or use share links until someone unlocks the server with the passphrase or the recovery key.' }),
        h('p', { class: 'muted text-sm', text: 'Use this if you suspect the server is compromised or before leaving it unattended.' })),
      expected: 'lock',
      confirmLabel: 'Lock server',
    });
    if (!ok) return;
    try {
      await api.post('/admin/keys/lock', {});
    } catch (err) {
      toast.error(err);
      return;
    }
    location.assign(`/unlock?next=${encodeURIComponent('/admin/encryption')}`);
  };

  // ------------------------------------------------------------------------------------------ rotation
  const drawRotate = () => {
    /** @type {any[]} */
    const keks = ks.keks || [];
    const t = table({
      caption: 'Key-encryption keys',
      rows: [...keks].sort((a, b) => String(a.purpose).localeCompare(String(b.purpose)) || Number(a.state !== 'active') - Number(b.state !== 'active')),
      columns: [
        { key: 'purpose', label: 'Protects', render: (k) => ({ blob: 'File keys', field: 'Secrets in the database', mac: 'Integrity (MAC)' }[k.purpose] || k.purpose) },
        { key: 'state', label: 'State', render: (k) => stateBadge(k.state) },
        { key: 'created', label: 'Created', hideBelow: 'sm', render: (k) => timeEl(k.created_at) },
        { key: 'refs', label: 'Still used by', hideBelow: 'sm', render: (k) => h('span', { class: 'tabular', text: k.state === 'active' ? '—' : `${k.refs ?? 0} item${k.refs === 1 ? '' : 's'}` }) },
        { key: 'id', label: 'ID', hideBelow: 'md', render: (k) => h('span', { class: 'mono text-xs', text: k.id }) },
      ],
      empty: 'No keys reported.',
    });
    replace(rotateBody, 
      h('p', { class: 'muted text-sm', text: 'Rotating replaces a key with a new one. It is routine hygiene, and important if you think a key or an old backup of the key file leaked — then also change the passphrase and export a new recovery key, because an old copy of the key file still yields both. Files stay available the whole time.' }),
      t.el,
      h('div', { class: 'rotate-grid' },
        rotateItem('File keys', 'Re-wraps the key of every file with a new key-encryption key. Fast: only the database changes.', 'Rotate file keys', () => rotate({ target: 'kek', purpose: 'blob' }, 'File key rotation')),
        rotateItem('Database secrets', 'Re-encrypts two-factor secrets, passkeys, tokens, secret settings and the CA key.', 'Rotate secret keys', () => rotate({ target: 'kek', purpose: 'field' }, 'Secret key rotation')),
        rotateItem('Master key', 'Replaces the master key that protects all other keys. The passphrase and recovery key keep working, so after a suspected leak change them too.', 'Rotate master key', () => rotate({ target: 'master' }, 'Master key rotation', true)),
        rotateItem('Re-encrypt all data', 'Decrypts and re-encrypts every file with brand-new keys. Slow — reads and writes all data — but removes any dependency on old keys.', 'Re-encrypt data', () => rotate({ target: 'data' }, 'Data re-encryption', true))));
  };

  /**
   * @param {string} name
   * @param {string} text
   * @param {string} label
   * @param {() => any} onClick
   */
  const rotateItem = (name, text, label, onClick) => h('div', { class: 'rotate-item' },
    h('strong', { text: name }),
    h('p', { class: 'muted text-sm', text }),
    h('div', null, button({ label, icon: 'rotate', size: 'sm', onClick })));

  /**
   * @param {{target: string, purpose?: string}} body
   * @param {string} label
   * @param {boolean} [heavy]
   */
  const rotate = async (body, label, heavy = false) => {
    const ok = await confirm({
      title: `${label}?`,
      message: heavy
        ? (body.target === 'data'
          ? 'This rewrites every stored file and can take hours on large servers. Uploads keep working. Make sure there is enough free disk space for the largest file.'
          : 'A new master key is generated and every key-encryption key is re-wrapped. Create a backup first.')
        : 'Runs in the background. You can keep working.',
      confirmLabel: 'Start',
    });
    if (!ok) return;
    try {
      const res = await api.post('/admin/keys/rotate', body);
      const jobId = res?.job_id;
      if (jobId) {
        jobsSlot.prepend(h('div', { class: 'card' }, jobProgress(jobId, { label, signal: ctx.signal, onDone: (j) => {
          if (j.state === 'succeeded') toast.success(`${label} finished`);
          load();
        } })));
      } else {
        toast.success(`${label} done`);
        await load();
      }
    } catch (err) {
      toast.error(err);
    }
  };

  // ------------------------------------------------------------------------------------------ recovery key
  const drawRecovery = () => {
    replace(recoveryBody, 
      h('div', { class: 'cluster' }, ks.recovery_configured ? badge({ text: 'Configured', kind: 'success', icon: 'check' }) : badge({ text: 'Not configured', kind: sealed() ? 'warning' : 'neutral' })),
      h('p', { class: 'muted text-sm', text: 'A recovery key (FPRK-…) unlocks the server when the passphrase is lost. It is also needed to restore an offline copy of the key file.' }),
      sealed() && !ks.recovery_configured ? alertEl('warning', 'No recovery key', 'If the passphrase is forgotten, every file is lost. Create a recovery key and store it offline.') : null,
      h('div', { class: 'btn-row btn-row--start' }, button({ label: ks.recovery_configured ? 'Create a new recovery key' : 'Create recovery key', icon: 'key', onClick: () => exportRecovery(false) })));
  };

  /** @param {boolean} skipConfirm */
  const exportRecovery = async (skipConfirm) => {
    if (!skipConfirm && ks.recovery_configured) {
      const ok = await confirm({ title: 'Create a new recovery key?', message: 'The previous recovery key stops working. Store the new one before closing the dialog.', confirmLabel: 'Create new key' });
      if (!ok) return;
    }
    try {
      const res = await api.post('/admin/keys/recovery', {});
      const key = String(res?.recovery_key || '');
      if (!key) throw new ApiError(500, 'bad_response', 'The server did not return a recovery key.');
      const inst = boot().instance || 'FileParcel';
      await showSecretOnce({
        title: 'Your recovery key',
        intro: 'Print it or store it in a password manager — somewhere that does not depend on this server.',
        secret: key,
        label: 'Recovery key',
        what: 'Recovery key',
        filename: `${inst.toLowerCase().replace(/[^a-z0-9]+/g, '-')}-recovery-key.txt`,
        fileContent: `${inst} recovery key\nCreated ${new Date().toISOString()}\n\n${key}\n\nUse it on the unlock page or with: fileparcel keys unlock\n`,
        warning: 'Anyone with this key and a copy of the server’s data can decrypt every file. FileParcel cannot show it again.',
      });
      await load();
    } catch (err) {
      toast.error(err);
    }
  };

  const refresh = debounce(() => load(), 600);
  const off = onEvents(['keys.state'], refresh);
  await load();
  return () => {
    off();
    refresh.cancel();
  };
}

