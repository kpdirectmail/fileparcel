// @ts-check
/**
 * Admin → System (/admin/system): version and build, uptime, host, storage (disk, database, blobs), key state,
 * supervisor, pending restarts, health checks, a log viewer (tail with filter / follow / download) and restart.
 *   GET  /admin/system            → SystemInfo + {mode, stats_unavailable?, maintenance?, blob_count, goroutines, num_cpu,
 *                                    memory: {…}} (maintenance mode itself: the app banner, app.js accountBanners)
 *   GET  /admin/system/doctor     → health checks (tolerant parsing, see common.doctorChecks)
 *   GET  /admin/system/logs?n=    → {file, lines: [], truncated, missing, file_logging} (also accepts string[] or text/plain)
 *   POST /admin/system/restart    (E)
 * The page needs "Server status"; the log viewer also needs "Audit and server logs" (the log shows names and
 * addresses from everyone's activity) and restarting "Operate the server" — without them those parts are left out.
 * Owned by unit J2.
 * @module pages/admin/system
 */
import { h, downloadBlob, boot, replace, append } from '../../core/dom.js';
import { api, ApiError, errorMessage } from '../../core/api.js';
import { can } from '../../core/store.js';
import { bytes, dateTime, duration, pct, number } from '../../core/format.js';
import { button } from '../../components/button.js';
import { badge } from '../../components/badge.js';
import { card } from '../../components/card.js';
import { field, select, toggle } from '../../components/field.js';
import { progress, skeleton } from '../../components/progress.js';
import { copyText } from '../../components/copy-field.js';
import {
  adminHeader, errorPanel, alertEl, kv, stateBadge, restartServer, restartBanner, doctorChecks, healthRow, debounce,
} from './common.js';

export const title = 'System';

/**
 * @param {HTMLElement} root
 * @param {import('../../core/router.js').PageContext} ctx
 */
export async function mount(root, ctx) {
  const logsAllowed = can('audit.view');
  adminHeader(root, {
    title,
    subtitle: logsAllowed ? 'Version, resources, health and logs of this FileParcel server.' : 'Version, resources and health of this FileParcel server.',
    actions: can('system.manage') ? button({ label: 'Restart…', icon: 'power', onClick: () => restartServer() }) : null,
  });
  const restartSlot = h('div');
  const infoBody = h('div', { class: 'stack' }, skeleton(6));
  const storageBody = h('div', { class: 'stack' }, skeleton(3));
  const healthBody = h('div', { class: 'stack-sm' }, skeleton(4));
  const logsBody = h('div', { class: 'stack' });
  append(root, restartSlot,
    h('div', { class: 'settings-grid' },
      h('div', { class: 'stack' }, card({ title: 'Server', body: infoBody })),
      h('div', { class: 'stack' }, card({ title: 'Storage', body: storageBody }), card({ title: 'Health', body: healthBody, headerActions: button({ label: 'Re-check', icon: 'refresh', size: 'sm', variant: 'ghost', onClick: () => loadHealth() }) }))),
    logsAllowed ? card({ title: 'Logs', body: logsBody }) : null);

  /** @type {any} */
  let info = null;
  let uptimeTimer = 0;

  const loadInfo = async () => {
    try {
      info = (await api.get('/admin/system', { signal: ctx.signal })) || {};
    } catch (err) {
      if (err instanceof ApiError && err.aborted) return;
      replace(infoBody, errorPanel(err, loadInfo));
      replace(storageBody);
      return;
    }
    const uptime = h('span', { class: 'tabular' });
    const tick = () => {
      const started = info.started_at ? new Date(info.started_at).getTime() : Date.now() - (Number(info.uptime_seconds) || 0) * 1000;
      uptime.textContent = duration(Date.now() - started);
    };
    tick();
    window.clearInterval(uptimeTimer);
    uptimeTimer = window.setInterval(tick, 1000);
    const commit = info.commit ? String(info.commit).slice(0, 12) : '';
    // stats_unavailable: a database read failed, so schema_version, blob_count and blobs_bytes are zero because
    // nothing could be read, not because there is nothing (the flag is coarse: any failed query sets it)
    const statsGone = !!info.stats_unavailable;
    const unavailable = () => h('span', { class: 'muted', text: 'Unavailable' });
    replace(infoBody, 
      kv([
        ['Version', h('span', { class: 'cluster' }, h('strong', { text: info.version || boot().version || 'dev' }), commit ? h('span', { class: 'mono text-xs muted', text: commit }) : null)],
        ['Built', info.build_date ? dateTime(info.build_date) : null],
        ['Go', info.go_version || null],
        ['Platform', [info.os, info.arch].filter(Boolean).join('/') || null],
        ['Host name', info.hostname || null],
        ['Uptime', h('span', null, uptime, info.started_at ? h('span', { class: 'muted text-xs', text: ` (since ${dateTime(info.started_at)})` }) : null)],
        ['Process', info.pid ? `PID ${info.pid}` : null],
        ['Managed by', supervisorLabel(info.supervisor)],
        ['Encryption keys', h('span', { class: 'cluster' }, stateBadge(info.keys_state), info.key_mode ? badge({ text: info.key_mode === 'sealed' ? 'sealed' : 'automatic unlock', kind: 'neutral' }) : null)],
        ['Database schema', info.schema_version ? `v${info.schema_version}` : statsGone ? unavailable() : null],
        ['Install directory', info.home ? h('span', { class: 'cluster' }, h('span', { class: 'mono text-xs break', text: info.home }), button({ label: 'Copy', size: 'sm', variant: 'ghost', icon: 'copy', onClick: () => copyText(info.home, 'Path') })) : null],
        ['Memory', memoryText(info)],
        ['Runtime', runtimeText(info)],
        ['Mode', info.mode === 'offline' ? 'Offline (command line, no network listeners)' : null],
      ]),
      !info.supervisor ? alertEl('info', 'Not running as a service', 'A restart relaunches the process itself, but FileParcel will not start again after a reboot or crash. Install the service (fileparcel service install) so it is supervised and starts at boot.') : null);
    const size = Number(info.disk_size_bytes) || 0;
    const free = Number(info.disk_free_bytes) || 0;
    const used = size - free;
    const ratio = size ? used / size : 0;
    const disk = progress({ value: size ? used : null, max: size || 1, label: size ? `Disk: ${bytes(used)} of ${bytes(size)} used (${pct(used, size)})` : 'Disk usage unknown', kind: ratio > 0.95 ? 'danger' : ratio > 0.85 ? 'warning' : 'primary' });
    replace(storageBody, 
      disk.el,
      kv([
        ['Free space', size ? `${bytes(free)} free` : null],
        ['File data (encrypted)', statsGone && !info.blob_count && !info.blobs_bytes ? unavailable()
          : `${bytes(info.blobs_bytes)}${info.blob_count ? ` in ${number(info.blob_count)} blobs` : ''}`],
        ['Database', bytes(info.db_bytes)],
      ]),
      statsGone ? alertEl('warning', 'Some figures could not be read', 'The database did not answer in time or returned an error, so the file data total and the schema version are not shown. See the health checks below and the log.') : null,
      free && free < 5 * 1024 ** 3 ? alertEl('warning', 'Low disk space', 'Uploads are refused when less than 1 GB or 2% of the disk would remain. Empty the trash, prune old versions or backups, or add space.') : null);
    replace(restartSlot, restartBanner(Array.isArray(info.restart_required) ? info.restart_required : []) || '');
  };

  const loadHealth = async () => {
    replace(healthBody, skeleton(3));
    try {
      const checks = doctorChecks(await api.get('/admin/system/doctor', { signal: ctx.signal }));
      const problems = checks.filter((c) => c.status === 'fail' || c.status === 'warn').length;
      const order = { fail: 0, warn: 1, info: 2, ok: 3 };
      replace(healthBody, 
        !checks.length ? h('p', { class: 'muted', text: 'No health checks reported.' })
          : problems ? alertEl('warning', `${problems} problem${problems === 1 ? '' : 's'} found`, 'Follow the hints below, or run “fileparcel doctor --fix” on the server.')
            : alertEl('success', 'All checks passed', `${checks.length} checks.`),
        h('ul', { class: 'health-list', attrs: { role: 'list' } }, [...checks].sort((a, b) => order[a.status] - order[b.status]).map(healthRow)));
    } catch (err) {
      if (err instanceof ApiError && err.aborted) return;
      replace(healthBody, errorPanel(err, loadHealth));
    }
  };

  // ------------------------------------------------------------------------------------------ logs
  const lines = select({ label: 'Lines', hideLabel: true, value: '200', options: [{ value: '100', label: 'Last 100 lines' }, { value: '200', label: 'Last 200 lines' }, { value: '500', label: 'Last 500 lines' }, { value: '1000', label: 'Last 1000 lines' }, { value: '5000', label: 'Last 5000 lines' }], onChange: () => loadLogs() });
  const level = select({ label: 'Level', hideLabel: true, value: '', options: [{ value: '', label: 'All levels' }, { value: 'warn', label: 'Warnings and errors' }, { value: 'error', label: 'Errors only' }], onChange: () => drawLogs() });
  const filter = field({ label: 'Filter', hideLabel: true, type: 'search', placeholder: 'Filter lines', autocomplete: 'off' });
  filter.input.addEventListener('input', debounce(() => drawLogs(), 150));
  const follow = toggle({ label: 'Follow', help: 'Refresh every 5 seconds', onChange: (on) => { if (on) loadLogs(); } });
  const wrap = toggle({ label: 'Wrap lines', checked: true, onChange: (on) => pre.classList.toggle('log-nowrap', !on) });
  const pre = h('pre', { class: 'log-view', attrs: { tabindex: '0', 'aria-label': 'Server log', 'aria-live': 'off' } });
  const meta = h('p', { class: 'subtle text-xs', attrs: { 'aria-live': 'polite' } });
  /** @type {string[]} */
  let logLines = [];
  let logFile = '';
  let logTruncated = false;
  let logMissing = false; // logs/fileparcel.log does not exist
  let fileLogging = true; // log.file of the running server
  replace(logsBody, 
    h('div', { class: 'admin-toolbar admin-toolbar--wrap' }, lines.el, level.el, h('div', { class: 'admin-toolbar-search' }, filter.el), follow.el, wrap.el,
      h('div', { class: 'cluster' },
        button({ label: 'Refresh', size: 'sm', icon: 'refresh', variant: 'ghost', onClick: () => loadLogs() }),
        button({ label: 'Copy', size: 'sm', icon: 'copy', variant: 'ghost', onClick: () => copyText(visible().join('\n'), 'Log lines') }),
        button({ label: 'Download', size: 'sm', icon: 'download', variant: 'ghost', onClick: () => downloadBlob(`fileparcel-${new Date().toISOString().replace(/[:.]/g, '-')}.log`, `${logLines.join('\n')}\n`) }))),
    pre,
    meta);

  const levelOf = (/** @type {string} */ l) => {
    const m = /\blevel=(\w+)|"level":"(\w+)"|\b(DEBUG|INFO|WARN(?:ING)?|ERROR)\b/i.exec(l);
    const v = (m && (m[1] || m[2] || m[3]) || '').toLowerCase();
    return v.startsWith('warn') ? 'warn' : v === 'error' ? 'error' : v === 'debug' ? 'debug' : 'info';
  };
  const visible = () => {
    const needle = String(filter.input.value).trim().toLowerCase();
    const lv = level.input.value;
    return logLines.filter((l) => {
      const k = levelOf(l);
      if (lv === 'error' && k !== 'error') return false;
      if (lv === 'warn' && k !== 'warn' && k !== 'error') return false;
      return !needle || l.toLowerCase().includes(needle);
    });
  };
  const drawLogs = () => {
    const atBottom = pre.scrollHeight - pre.scrollTop - pre.clientHeight < 40;
    const rows = visible();
    replace(pre, ...rows.map((l) => h('span', { class: 'log-line', dataset: { level: levelOf(l) }, text: `${l}\n` })));
    if (!rows.length) {
      const empty = !fileLogging ? loggingOffText(info?.supervisor) : logMissing ? 'The server has not written a log file yet.' : 'The log is empty.';
      replace(pre, h('span', { class: 'subtle', text: logLines.length ? 'No lines match the filter.' : empty }));
    }
    meta.textContent = [
      `${rows.length} of ${logLines.length} lines`,
      !fileLogging && logLines.length ? 'file logging is off (log.file = false): these lines are from before it was turned off' : '',
      logTruncated ? 'older lines are in the log file' : '',
      logFile ? `from ${logFile}` : '',
      `updated ${new Date().toLocaleTimeString()}`,
    ].filter(Boolean).join(' · ');
    if (atBottom || !pre.dataset.scrolled) {
      pre.scrollTop = pre.scrollHeight;
      pre.dataset.scrolled = '1';
    }
  };
  let logsBusy = false;
  const loadLogs = async () => {
    if (logsBusy) return;
    logsBusy = true;
    try {
      /** @type {Response} */
      const res = await api.get('/admin/system/logs', { signal: ctx.signal, query: { n: lines.input.value }, as: 'response' });
      const ct = res.headers.get('Content-Type') || '';
      if (ct.includes('json')) {
        const body = await res.json();
        const arr = Array.isArray(body) ? body : body?.lines || body?.items || [];
        logFile = typeof body?.file === 'string' ? body.file : '';
        logTruncated = !!body?.truncated;
        logMissing = !!body?.missing;
        fileLogging = body?.file_logging !== false;
        logLines = arr.map((/** @type {any} */ l) => (typeof l === 'string' ? l : JSON.stringify(l)));
      } else {
        logLines = (await res.text()).split('\n').filter((l, i, a) => l !== '' || i < a.length - 1);
      }
      drawLogs();
    } catch (err) {
      if (err instanceof ApiError && err.aborted) return;
      replace(pre, h('span', { class: 'danger-text', text: `Could not load the log: ${errorMessage(err)}` }));
    } finally {
      logsBusy = false;
    }
  };
  const logTimer = window.setInterval(() => {
    if (logsAllowed && follow.input.checked && document.visibilityState === 'visible') loadLogs();
  }, 5000);

  await Promise.all([loadInfo(), loadHealth(), logsAllowed ? loadLogs() : null]);
  return () => {
    window.clearInterval(uptimeTimer);
    window.clearInterval(logTimer);
  };
}

/** @param {string} s */
function supervisorLabel(s) {
  if (!s) return 'Nothing (foreground process)';
  return { systemd: 'systemd', launchd: 'launchd', docker: 'Docker', external: 'External supervisor (FILEPARCEL_SUPERVISED)' }[s] || s;
}

/**
 * Where the log goes with log.file = false (GET /admin/system/logs → file_logging false).
 * @param {string | undefined} supervisor
 */
function loggingOffText(supervisor) {
  const where = {
    systemd: 'the journal (journalctl --user -u fileparcel, or journalctl -u fileparcel for a system service)',
    launchd: 'launchd\'s log file (<HOME>/logs/launchd.err.log)',
    docker: 'the container log (docker logs)',
  }[supervisor || ''] || 'its service manager (journalctl -u fileparcel, <HOME>/logs/launchd.err.log on macOS, or docker logs)';
  return `File logging is off (log.file = false): the server logs to ${where}.`;
}

/**
 * Go runtime memory summary (GET /admin/system → memory {heap_alloc, heap_inuse, sys, num_gc, mem_limit, total_alloc}).
 * @param {any} info
 */
function memoryText(info) {
  const m = info.memory || {};
  const sys = Number(m.sys) || 0;
  const heap = Number(m.heap_inuse || m.heap_alloc) || 0;
  const limit = Number(m.mem_limit) || 0;
  // math.MaxInt64 (no limit) is reported as a huge number: only show real limits
  const parts = [sys ? `${bytes(sys)} from the OS` : '', heap ? `${bytes(heap)} heap` : '', limit > 0 && limit < 2 ** 50 ? `soft limit ${bytes(limit)}` : ''].filter(Boolean);
  return parts.length ? parts.join(' · ') : null;
}

/**
 * CPU / goroutine summary.
 * @param {any} info
 */
function runtimeText(info) {
  const parts = [info.num_cpu ? `${number(info.num_cpu)} CPU${info.num_cpu === 1 ? '' : 's'}` : '', info.goroutines ? `${number(info.goroutines)} goroutines` : ''].filter(Boolean);
  return parts.length ? parts.join(' · ') : null;
}
