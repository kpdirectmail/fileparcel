// @ts-check
/**
 * Admin → Dashboard (/admin): stat tiles (users, storage, files, shares, jobs, backups, certificate expiry, keys,
 * network), server warnings, health checks with links to the page that fixes them, and recent activity.
 *   GET /admin/dashboard       → core.Dashboard
 *   GET /admin/system/doctor   → health checks (array or {checks: […]}; tolerant parsing, see doctorChecks())
 *   GET /admin/network         → core.NetworkOverview (network tile)
 * Refreshes on job/backup/certificate/key/network events.
 * The dashboard needs the "Server status" permission; the parts that need more (the audit log, the network, the
 * last backup) show only with their own permission, and tiles link only to pages the account may open. Staff
 * without "Server status" (a delegate who manages people, say) get "Your admin areas" instead: a card per admin page
 * their role opens, without any API call.
 * Owned by unit J2.
 * @module pages/admin/dashboard
 */
import { h, icon, boot, replace, append } from '../../core/dom.js';
import { api, ApiError } from '../../core/api.js';
import { can } from '../../core/store.js';
import { setTitle } from '../../core/router.js';
import { bytes, number, relTime, pct, dateTime } from '../../core/format.js';
import { statTile } from '../../components/card.js';
import { button } from '../../components/button.js';
import { card } from '../../components/card.js';
import { skeleton } from '../../components/progress.js';
import { emptyState } from '../../components/empty-state.js';
import { adminHeader, alertEl, errorPanel, stateBadge, timeEl, daysLeft, debounce, onEvents, doctorChecks, healthRow, linkFor, actionIcon, actionText, targetIsActor } from './common.js';
import { adminItems } from '../../nav.js';
import { pathAllowed } from '../../routes.js';

/** @typedef {import('./common.js').Check} Check */

export const title = 'Dashboard';

/** What each admin page is for ("Your admin areas"), by navigation id. @type {Record<string, string>} */
const AREA_TEXT = {
  'admin-users': 'Accounts, their roles and sign-in security.',
  'admin-groups': 'Groups and their team folders.',
  'admin-roles': 'What each kind of account may do.',
  'admin-invites': 'Invitation links for new accounts.',
  'admin-settings': 'The server settings your role may change.',
  'admin-network': 'Who may connect, the local name and VPNs.',
  'admin-certificates': 'TLS certificates and client certificates.',
  'admin-encryption': 'The master key and recovery.',
  'admin-backups': 'Start and verify backups.',
  'admin-audit': 'Who did what, and the server log.',
  'admin-jobs': 'Background jobs and their schedules.',
  'admin-system': 'Server status, health checks and restarts.',
};

/**
 * "Your admin areas": the admin pages this account's role opens, as cards.
 * @param {HTMLElement} root
 */
function adminAreas(root) {
  setTitle('Your admin areas');
  adminHeader(root, { title: 'Your admin areas', subtitle: 'The parts of the Admin area your role includes.' });
  const items = adminItems().filter((it) => it.href !== '/admin');
  // "Manage everyone's links" has no page of its own: the web app lists only your own links (DESIGN §6a)
  const links = can('shares.manage')
    ? card({
      title: 'Manage everyone’s links',
      body: h('div', { class: 'stack-sm' },
        h('p', { class: 'text-sm', text: 'Your role may list every share link and file request, see their access logs, and disable, re-enable or delete them. There is no page for this in the web app, which lists only your own links under My links.' }),
        h('p', { class: 'muted text-sm' }, 'Use ', h('code', { text: 'fileparcel share list --all-users' }), ' and ',
          h('code', { text: 'fileparcel request list --all-users' }), ' on the server, or the API (', h('code', { text: 'GET /api/v1/admin/shares' }), ').')),
    })
    : null;
  append(root, items.length
    ? h('ul', { class: 'admin-areas', attrs: { role: 'list' } }, items.map((it) => h('li', null,
      h('a', { class: 'admin-area', href: it.href },
        h('span', { class: 'admin-area-icon', attrs: { 'aria-hidden': 'true' } }, icon(it.icon)),
        h('span', { class: 'admin-area-text' },
          h('span', { class: 'admin-area-label', text: it.label }),
          AREA_TEXT[it.id] ? h('span', { class: 'admin-area-desc', text: AREA_TEXT[it.id] }) : null),
        icon('chevron-right', { class: 'admin-area-go' })))))
    : links ? null
      : emptyState({ icon: 'shield', title: 'Nothing to manage here', text: 'Your role includes no admin pages right now.', action: { label: 'Go to My files', icon: 'folder', href: '/files' } }),
  links);
}

/**
 * @param {HTMLElement} root
 * @param {import('../../core/router.js').PageContext} ctx
 */
export async function mount(root, ctx) {
  if (!can('system.view')) {
    adminAreas(root);
    return undefined;
  }
  const refreshBtn = button({ label: 'Refresh', icon: 'refresh', variant: 'ghost', onClick: () => load() });
  adminHeader(root, { title, subtitle: `${boot().instance || 'FileParcel'} at a glance.`, actions: refreshBtn });
  const warnSlot = h('div', { class: 'stack-sm' });
  const tiles = h('div', { class: 'admin-tiles' }, Array.from({ length: 8 }, () => h('div', { class: 'stat' }, skeleton(2))));
  const healthBody = h('div', { class: 'stack-sm' }, skeleton(4));
  const activityBody = h('div', { class: 'stack-sm' }, skeleton(5));
  const audit = can('audit.view');
  append(root, warnSlot, tiles, h('div', { class: 'admin-dash-cols' },
    card({ title: 'Health', body: healthBody, headerActions: h('a', { class: 'btn btn--ghost btn--sm', href: '/admin/system' }, h('span', { text: 'System' }), icon('chevron-right')) }),
    audit ? card({ title: 'Recent activity', body: activityBody, headerActions: h('a', { class: 'btn btn--ghost btn--sm', href: '/admin/audit' }, h('span', { text: 'Audit log' }), icon('chevron-right')) }) : null));

  let loading = false;
  const load = async () => {
    if (loading) return;
    loading = true;
    try {
      const [dash, doctor, net] = await Promise.allSettled([
        api.get('/admin/dashboard', { signal: ctx.signal }),
        api.get('/admin/system/doctor', { signal: ctx.signal, handle: false }),
        // the network tile needs "Network & VPN"; without it the tile says "—" instead of asking for a 403
        can('network.manage') ? api.get('/admin/network', { signal: ctx.signal, handle: false }) : Promise.resolve(null),
      ]);
      if (ctx.signal.aborted) return;
      if (dash.status === 'fulfilled') {
        drawTiles(dash.value || {}, net.status === 'fulfilled' ? net.value : null);
        drawWarnings(dash.value?.warnings || []);
        drawActivity(dash.value?.recent_audit || []);
      } else {
        if (dash.reason instanceof ApiError && dash.reason.aborted) return;
        replace(tiles, errorPanel(dash.reason, load, 'The dashboard could not be loaded'));
        replace(activityBody, h('p', { class: 'muted', text: 'Unavailable.' }));
      }
      if (doctor.status === 'fulfilled') drawHealth(doctorChecks(doctor.value));
      else replace(healthBody, errorPanel(doctor.reason, load, 'Health checks are unavailable'));
    } finally {
      loading = false;
    }
  };

  /**
   * @param {any} d core.Dashboard
   * @param {any} net core.NetworkOverview | null
   */
  const drawTiles = (d, net) => {
    const diskUsed = (Number(d.disk_size_bytes) || 0) - (Number(d.disk_free_bytes) || 0);
    const certDays = d.cert ? daysLeft(d.cert.not_after) : null;
    // The local leaf renews when less than min(30 days, a third of its lifetime) is left; only an overdue renewal
    // (half that, at most 14 days — opsapi.leafWarn) is red, so a healthy short-lived leaf is not flagged.
    const certSpan = d.cert ? (Date.parse(d.cert.not_after) - Date.parse(d.cert.not_before)) / 86_400_000 : 0;
    const certRenewDays = certSpan > 0 ? Math.min(30, certSpan / 3) : 30;
    const certWarnDays = Math.min(14, certRenewDays / 2);
    const lb = d.last_backup;
    // extra.backup_unavailable: the backup list could not be read — unknown, not "never".
    const backupUnknown = !lb && !!d.extra?.backup_unavailable;
    const backupAge = lb ? (Date.now() - new Date(lb.created_at).getTime()) / 86_400_000 : Infinity;
    // A VPN interface with only link-local addresses (the macOS system utun0–utun3) reaches nothing: not counted.
    const usable = (/** @type {any} */ i) => (i.addrs || []).some((/** @type {any} */ a) => !/^(fe80:|169\.254\.|127\.|::1\/)/i.test(String(a)));
    const vpn = net ? (net.interfaces || []).filter((/** @type {any} */ i) => i.up && usable(i) && (i.role ? i.role === 'mesh' || i.role === 'unknown' : i.is_vpn)).map((/** @type {any} */ i) => i.label || i.kind) : [];
    const recommended = net ? (net.urls || []).find((/** @type {any} */ u) => u.recommended) : null;
    // the dashboard reports the last backup only to accounts that may run backups
    const backups = can('backups.run');
    /** @param {string} href */
    const link = (href) => (pathAllowed(href) ? href : undefined);
    replace(tiles, 
      statTile({ label: 'Users', value: number(d.users), hint: `${number(d.groups || 0)} group${d.groups === 1 ? '' : 's'}`, icon: 'users', href: link('/admin/users') }),
      statTile({
        label: 'Storage',
        value: bytes(d.stored_bytes),
        hint: d.disk_size_bytes ? `${bytes(d.disk_free_bytes)} free of ${bytes(d.disk_size_bytes)} (${pct(diskUsed, d.disk_size_bytes)} used)` : 'Encrypted file data',
        icon: 'hard-drive',
        href: link('/admin/system'),
      }),
      statTile({ label: 'Files', value: number(d.files), hint: `${number(d.folders || 0)} folders`, icon: 'file' }),
      statTile({ label: 'Active shares', value: number(d.active_shares), hint: d.active_uploads ? `${number(d.active_uploads)} upload${d.active_uploads === 1 ? '' : 's'} in progress` : 'Links and file requests', icon: 'link' }),
      statTile({
        label: 'Jobs',
        value: d.running_jobs ? `${number(d.running_jobs)} running` : 'Idle',
        hint: d.failed_jobs_24h ? h('span', { class: 'danger-text', text: `${number(d.failed_jobs_24h)} failed in the last 24 h` }) : 'No failures in the last 24 h',
        icon: 'jobs',
        href: link('/admin/jobs'),
      }),
      statTile({
        label: 'Last backup',
        value: !backups ? '—' : lb ? relTime(lb.created_at) : backupUnknown ? 'Unknown' : 'Never',
        hint: !backups ? 'Not part of your role'
          : lb ? h('span', { class: lb.state === 'failed' || backupAge > 8 ? 'warning-text' : '' }, `${lb.scope === 'metadata' ? 'Metadata' : 'Full'} · ${lb.state}${lb.size ? ` · ${bytes(lb.size)}` : ''}`)
            : h('span', { class: 'warning-text', text: backupUnknown ? 'The backup list could not be read' : 'Create your first backup' }),
        icon: 'archive',
        href: link('/admin/backups'),
      }),
      statTile({
        label: 'Certificate',
        value: certDays === null ? '—' : certDays < 0 ? 'Expired' : `${certDays} days`,
        hint: d.cert ? h('span', { class: certDays !== null && certDays < certWarnDays ? 'danger-text' : certDays !== null && certDays < certRenewDays ? 'warning-text' : '' }, `${certSourceLabel(d.cert.source)} · until ${dateTime(d.cert.not_after)}`) : 'No certificate information',
        icon: 'certificate',
        href: link('/admin/certificates'),
      }),
      statTile({
        label: 'Encryption',
        value: d.keys_state === 'unlocked' ? 'Unlocked' : d.keys_state === 'locked' ? 'Locked' : String(d.keys_state || '—'),
        hint: 'Files are encrypted at rest',
        icon: d.keys_state === 'unlocked' ? 'unlock' : 'lock',
        href: link('/admin/encryption'),
      }),
      statTile({
        label: 'Network',
        value: net ? policyLabel(net.policy?.mode) : '—',
        hint: net ? [vpn.length ? `VPN: ${[...new Set(vpn)].join(', ')}` : 'No VPN interface', recommended ? ` · ${recommended.url}` : ''].join('') : 'Unavailable',
        icon: 'network',
        href: link('/admin/network'),
      }),
    );
  };

  /** @param {string[]} warnings */
  const drawWarnings = (warnings) => {
    replace(warnSlot, ...(warnings || []).filter(Boolean).map((w) => {
      const link = linkFor(w);
      return alertEl('warning', w, undefined, link && pathAllowed(link.href) ? h('a', { class: 'btn btn--secondary btn--sm', href: link.href, text: link.label }) : undefined);
    }));
  };

  /** @param {any[]} list */
  const drawActivity = (list) => {
    if (!list.length) {
      replace(activityBody, h('p', { class: 'muted', text: 'Nothing recorded yet.' }));
      return;
    }
    replace(activityBody, h('ul', { class: 'activity-list', attrs: { role: 'list' } }, list.slice(0, 12).map((a) => h('li', { class: 'activity-row', dataset: { outcome: a.outcome } },
      h('span', { class: 'activity-icon', attrs: { 'aria-hidden': 'true' } }, icon(actionIcon(a.action))),
      h('span', { class: 'activity-text' },
        h('strong', { text: a.actor_name || (a.actor_via === 'socket' || a.actor_via === 'offline' ? 'Command line' : 'Someone') }),
        ` ${actionText(a.action, a.outcome)}`,
        a.target_name && !targetIsActor(a) ? h('span', { class: 'activity-target', text: ` ${a.target_name}` }) : null,
        a.outcome && a.outcome !== 'success' ? [' ', stateBadge(a.outcome)] : null),
      h('span', { class: 'activity-time' }, timeEl(a.at))))));
  };

  /** @param {Check[]} checks */
  const drawHealth = (checks) => {
    if (!checks.length) {
      replace(healthBody, h('p', { class: 'muted', text: 'No health checks reported.' }));
      return;
    }
    const order = { fail: 0, warn: 1, info: 2, ok: 3 };
    const sorted = [...checks].sort((a, b) => order[a.status] - order[b.status]);
    const problems = sorted.filter((c) => c.status === 'fail' || c.status === 'warn').length;
    replace(healthBody, 
      problems ? null : alertEl('success', 'Everything looks good', `${checks.length} checks passed.`),
      h('ul', { class: 'health-list', attrs: { role: 'list' } }, sorted.map((c) => healthRow(c))));
  };

  const refresh = debounce(() => load(), 800);
  const off = onEvents(['job.done', 'backup.finished', 'certs.changed', 'keys.state', 'network.changed', 'mdns.changed'], refresh);
  const timer = window.setInterval(() => { if (document.visibilityState === 'visible') load(); }, 60_000);
  await load();
  return () => {
    off();
    refresh.cancel();
    window.clearInterval(timer);
  };
}

/** @param {string} source */
function certSourceLabel(source) {
  return { local: 'Local CA', acme: 'Let’s Encrypt / ACME', tailscale: 'Tailscale', custom: 'Custom' }[source] || 'Certificate';
}

/** @param {string} mode */
function policyLabel(mode) {
  return { private: 'Private', allowlist: 'Allowlist', any: 'Public' }[mode] || mode || '—';
}

