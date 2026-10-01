// @ts-check
/**
 * Human-readable audit events (§9.6 actions) for the Activity page and the details panel.
 *   activityRow(record, {compact}) → <li>      describe(record) → {icon, text, tone}
 * Records are core.AuditRecord ({at, actor_name, action, outcome, target_type, target_id, target_name, details}).
 * Everything is rendered as text.
 * @module components/activity
 */
import { h, icon } from '../core/dom.js';
import { relTime, dateTime, time } from '../core/format.js';
import { session } from '../core/store.js';

/** action → [icon, verb phrase with {t} for the target] */
const ACTIONS = /** @type {Record<string, [string, string]>} */ ({
  'auth.login': ['login', 'Signed in'],
  'auth.logout': ['logout', 'Signed out'],
  'auth.mfa': ['shield-check', 'Completed two-step verification'],
  'auth.lockout': ['lock', 'Account locked after failed sign-ins'],
  'auth.elevate': ['shield', 'Confirmed identity for a sensitive action'],
  'auth.setup': ['zap', 'Set up FileParcel'],
  'user.update': ['user', 'Updated profile'],
  'user.password_change': ['key', 'Changed password'],
  'user.password_reset': ['key', 'Password was reset'],
  'user.mfa_reset': ['shield', 'Two-step verification was reset'],
  'mfa.totp_enable': ['shield-check', 'Turned on authenticator app'],
  'mfa.totp_disable': ['shield', 'Turned off authenticator app'],
  'mfa.recovery_regenerate': ['key', 'Generated new recovery codes'],
  'passkey.add': ['passkey', 'Added a passkey'],
  'passkey.remove': ['passkey', 'Removed a passkey'],
  'token.create': ['terminal', 'Created API token {t}'],
  'token.revoke': ['terminal', 'Revoked API token {t}'],
  'session.revoke': ['laptop', 'Signed out a session'],
  'invite.accept': ['user-plus', 'Joined via an invitation'],
  'file.upload': ['upload', 'Uploaded {t}'],
  'file.download': ['download', 'Downloaded {t}'],
  'file.rename': ['edit', 'Renamed {t}'],
  'file.move': ['move', 'Moved {t}'],
  'file.copy': ['copy', 'Copied {t}'],
  'file.trash': ['trash', 'Moved {t} to the trash'],
  'file.restore': ['rotate-ccw', 'Restored {t}'],
  'file.purge': ['trash', 'Permanently deleted {t}'],
  'file.version_restore': ['history', 'Restored an earlier version of {t}'],
  'folder.create': ['folder-plus', 'Created folder {t}'],
  'grant.set': ['users', 'Shared {t}'],
  'grant.remove': ['users', 'Removed access to {t}'],
  'archive.download': ['file-zip', 'Downloaded an archive'],
  'share.create': ['link', 'Created a link for {t}'],
  'share.update': ['link', 'Changed the link for {t}'],
  'share.revoke': ['link', 'Deleted the link for {t}'],
  'share.password_fail': ['alert-triangle', 'Someone entered a wrong password for {t}'],
  'request.upload': ['inbox', 'Received files through {t}'],
  'role.create': ['shield', 'Created role {t}'],
  'role.update': ['shield', 'Changed role {t}'],
  'role.delete': ['shield', 'Deleted role {t}'],
  'group.role_set': ['users', 'Made a role a member of {t}'],
  'group.role_remove': ['users', 'Removed a role from {t}'],
  'network.funnel': ['globe', 'Changed Tailscale Funnel'],
  'network.serve': ['network', 'Changed Tailscale Serve'],
});

/**
 * The phrase of an entry whose wording depends on its details: file requests are share rows of kind "request"
 * (share.* details.kind; share.update details.disabled when it was closed or reopened, paused or resumed), and a
 * file.upload made through a public link runs as its owner with actor_via "share" — a visitor's upload, not the
 * owner's own. Undefined: the plain ACTIONS phrase.
 * @param {any} rec
 * @returns {[string, string] | undefined}
 */
function variant(rec) {
  let d = rec.details;
  if (typeof d === 'string') {
    try { d = JSON.parse(d); } catch { d = null; }
  }
  const req = d?.kind === 'request';
  switch (rec.action) {
    case 'share.create':
      return req ? ['inbox', 'Created a file request for {t}'] : undefined;
    case 'share.update':
      if (d?.disabled === true) return req ? ['inbox', 'Closed the file request for {t}'] : ['link', 'Paused the link for {t}'];
      if (d?.disabled === false) return req ? ['inbox', 'Reopened the file request for {t}'] : ['link', 'Resumed the link for {t}'];
      return req ? ['inbox', 'Changed the file request for {t}'] : undefined;
    case 'share.revoke':
      return req ? ['inbox', 'Deleted the file request for {t}'] : undefined;
    case 'file.upload':
      return rec.actor_via === 'share' ? ['inbox', 'Received {t} through a public upload link'] : undefined;
    default:
      return undefined;
  }
}

/**
 * @param {any} rec AuditRecord
 * @returns {{icon: string, text: string, tone: '' | 'danger' | 'warning'}}
 */
export function describe(rec) {
  const target = rec.target_name || '';
  const def = variant(rec) || ACTIONS[rec.action];
  let text;
  let ic = 'activity';
  if (def) {
    ic = def[0];
    text = def[1].includes('{t}') ? def[1].replace('{t}', target ? `“${target}”` : 'an item').replace(/\s+$/, '') : def[1];
  } else {
    const [area, verb] = String(rec.action || 'event').split('.');
    text = `${area.charAt(0).toUpperCase()}${area.slice(1)}: ${(verb || '').replace(/_/g, ' ')}${target ? ` “${target}”` : ''}`;
  }
  /** @type {'' | 'danger' | 'warning'} */
  let tone = '';
  if (rec.outcome === 'failure') {
    tone = 'danger';
    text = `${text} — failed`;
  } else if (rec.outcome === 'denied') {
    tone = 'warning';
    text = `${text} — denied`;
  }
  if (rec.action === 'share.password_fail' || rec.action === 'auth.lockout') tone = 'warning';
  return { icon: ic, text, tone };
}

/**
 * One activity entry.
 * @param {any} rec
 * @param {{compact?: boolean}} [o]
 */
export function activityRow(rec, o = {}) {
  const d = describe(rec);
  const me = session.peek()?.user?.id;
  const actor = rec.actor_id && rec.actor_id !== me ? rec.actor_name || 'Someone' : '';
  const meta = [o.compact ? relTime(rec.at) : time(rec.at), rec.ip && !o.compact ? rec.ip : ''].filter(Boolean).join(' · ');
  return h('li', { class: 'act-row', dataset: { tone: d.tone || null } },
    h('span', { class: 'act-icon', attrs: { 'aria-hidden': 'true' } }, icon(d.icon, { size: 16 })),
    h('span', { class: 'act-text' },
      h('span', { class: 'act-what', text: actor ? `${actor}: ${d.text}` : d.text }),
      h('small', { class: 'act-meta', attrs: { title: dateTime(rec.at) }, text: meta })));
}
