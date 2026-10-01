// @ts-check
/**
 * Admin → Jobs (/admin/jobs): background work (backups, key rotation, zip uploads, thumbnails, maintenance) with live
 * progress, filters, details, cancel, and "run maintenance now".
 *   GET  /admin/jobs?state=&kind=&cursor=&limit=  → Page[Job]
 *   GET  /admin/jobs/{id}                         → Job
 *   POST /admin/jobs/{id}/cancel
 *   POST /admin/jobs/run {kind}                   → JobRef
 * Live updates come from the SSE job.progress / job.done events (core/store jobs) plus a slow refresh.
 * Seeing jobs needs "Server status"; starting or cancelling one needs the permission of its kind (jobPermission:
 * backups "Run backups", everything else "Operate the server"), so each control shows only where it would work.
 * Owned by unit J2.
 * @module pages/admin/jobs
 */
import { h, replace, append } from '../../core/dom.js';
import { api, ApiError, itemsOf } from '../../core/api.js';
import { jobs as jobStore, can } from '../../core/store.js';
import { dateTime, duration, number } from '../../core/format.js';
import { button } from '../../components/button.js';
import { dialog, confirm } from '../../components/dialog.js';
import { select } from '../../components/field.js';
import { menu } from '../../components/menu.js';
import { table } from '../../components/table.js';
import { toast } from '../../components/toast.js';
import { progress } from '../../components/progress.js';
import {
  adminHeader, errorPanel, kv, stateBadge, timeEl, jsonBlock, jobKindLabel, jobFinished, MAINTENANCE_JOBS, debounce, onEvents, userLabel,
} from './common.js';

export const title = 'Jobs';

/**
 * The permission that starts or cancels a job of `kind` (opsapi jobCap): backup jobs need "Run backups", every other
 * kind "Operate the server".
 * @param {string} kind
 */
const jobPermission = (kind) => (String(kind || '').startsWith('backup.') ? 'backups.run' : 'system.manage');

/**
 * @param {HTMLElement} root
 * @param {import('../../core/router.js').PageContext} ctx
 */
export async function mount(root, ctx) {
  const runnable = MAINTENANCE_JOBS.filter((m) => can(jobPermission(m.kind)));
  const runBtn = runnable.length ? button({
    label: 'Run maintenance',
    icon: 'play',
    iconEnd: 'chevron-down',
    attrs: { 'aria-haspopup': 'menu' },
    onClick: (e) => menu({
      anchor: /** @type {Element} */ (e.currentTarget),
      align: 'end',
      title: 'Run maintenance',
      items: runnable.map((m) => ({ label: m.label, icon: 'play', onClick: () => run(m) })),
    }),
  }) : null;
  adminHeader(root, { title, subtitle: 'Background work: backups, key rotation, zip uploads, thumbnails and scheduled maintenance.', actions: runBtn });

  const state = select({
    label: 'State', hideLabel: true, value: ctx.query.state || '',
    options: [{ value: '', label: 'All states' }, { value: 'running', label: 'Running' }, { value: 'queued', label: 'Queued' }, { value: 'succeeded', label: 'Succeeded' }, { value: 'failed', label: 'Failed' }, { value: 'canceled', label: 'Canceled' }],
    onChange: () => reload(),
  });
  const kinds = Object.keys({
    'backup.create': 1, 'backup.verify': 1, 'backup.prune': 1, 'upload.zip': 1, 'thumbs.generate': 1, 'keys.rotate_kek': 1, 'keys.reencrypt': 1,
    'maintenance.sessions': 1, 'maintenance.uploads': 1, 'maintenance.trash': 1, 'maintenance.blob_gc': 1, 'maintenance.audit_prune': 1,
    'maintenance.db_optimize': 1, 'maintenance.versions': 1, 'certs.renew_check': 1,
  });
  const kind = select({
    label: 'Kind', hideLabel: true, value: ctx.query.kind || '',
    options: [{ value: '', label: 'All kinds' }, ...kinds.map((k) => ({ value: k, label: jobKindLabel(k) }))],
    onChange: () => reload(),
  });
  append(root, h('div', { class: 'admin-toolbar' }, state.el, kind.el));

  /** @type {Map<string, any>} */
  const byId = new Map();
  /** @type {string[]} */
  let order = [];
  let cursor = '';

  const t = table({
    caption: 'Jobs',
    loading: true,
    onRowClick: (j) => details(j),
    columns: [
      {
        key: 'kind',
        label: 'Job',
        render: (j) => h('span', { class: 'stack-sm gap-1' },
          h('strong', { text: jobKindLabel(j.kind) }),
          h('span', { class: 'muted text-xs', text: [origin(j), j.note || ''].filter(Boolean).join(' · ') })),
      },
      { key: 'state', label: 'State', render: (j) => stateBadge(j.state) },
      {
        key: 'progress',
        label: 'Progress',
        hideBelow: 'sm',
        render: (j) => {
          if (j.state === 'running') {
            const total = Number(j.progress_total) || 0;
            const p = progress({ value: total > 0 ? Number(j.progress_done) || 0 : null, max: total > 0 ? total : 1, size: 'sm', label: `${jobKindLabel(j.kind)} progress` });
            return h('span', { class: 'job-cell-progress' }, p.el, total > 0 ? h('span', { class: 'text-xs muted tabular', text: `${number(j.progress_done || 0)} / ${number(total)}` }) : null);
          }
          if (j.state === 'failed') return h('span', { class: 'danger-text text-xs truncate', title: j.error || '', text: j.error || 'Failed' });
          return j.finished_at && j.started_at ? h('span', { class: 'muted text-xs', text: `took ${duration(new Date(j.finished_at).getTime() - new Date(j.started_at).getTime())}` }) : '';
        },
      },
      { key: 'created', label: 'Started', hideBelow: 'md', render: (j) => timeEl(j.started_at || j.created_at) },
      {
        key: 'actions', label: 'Actions', srOnlyLabel: true, class: 'cell-actions',
        render: (j) => (!jobFinished(j.state) && can(jobPermission(j.kind)) ? button({ label: 'Cancel', size: 'sm', variant: 'ghost', onClick: () => cancel(j) }) : null),
      },
    ],
    empty: 'No jobs match these filters.',
  });
  const more = button({ label: 'Load more', variant: 'ghost', icon: 'chevron-down', onClick: () => loadMore() });
  more.hidden = true;
  const moreRow = h('div', { class: 'load-more' }, more);
  const slot = h('div', { class: 'stack' }, t.el, moreRow);
  append(root, slot);

  const draw = () => t.setRows(order.map((id) => byId.get(id)).filter(Boolean));
  const redraw = debounce(draw, 250);

  const query = () => ({ state: state.input.value || undefined, kind: kind.input.value || undefined, limit: 100 });

  let seq = 0;
  const reload = async () => {
    const mine = ++seq;
    try {
      const res = await api.get('/admin/jobs', { signal: ctx.signal, query: query() });
      if (mine !== seq) return; // the poll, job.done and filter changes can overlap
      // a failed earlier load replaced the table with an error panel: put it back
      if (t.el.parentNode !== slot) replace(slot, t.el, moreRow);
      byId.clear();
      order = [];
      for (const j of itemsOf(res)) {
        byId.set(j.id, j);
        order.push(j.id);
      }
      cursor = res?.next_cursor || '';
      more.hidden = !cursor;
      draw();
      const params = new URLSearchParams();
      if (state.input.value) params.set('state', state.input.value);
      if (kind.input.value) params.set('kind', kind.input.value);
      const s = params.toString();
      history.replaceState(history.state, '', `/admin/jobs${s ? `?${s}` : ''}`);
    } catch (err) {
      if (err instanceof ApiError && err.aborted) return;
      if (mine !== seq) return;
      replace(slot, errorPanel(err, () => reload()));
    }
  };

  const loadMore = async () => {
    if (!cursor) return;
    try {
      const res = await api.get('/admin/jobs', { signal: ctx.signal, query: { ...query(), cursor } });
      for (const j of itemsOf(res)) {
        if (!byId.has(j.id)) order.push(j.id);
        byId.set(j.id, j);
      }
      cursor = res?.next_cursor || '';
      more.hidden = !cursor;
      draw();
    } catch (err) {
      toast.error(err);
    }
  };

  // live updates from SSE (merged into the rows we show; new jobs appear on the next refresh)
  const offStore = jobStore.subscribe((map) => {
    let changed = false;
    for (const [id, j] of map) {
      const cur = byId.get(id);
      if (cur) {
        byId.set(id, { ...cur, ...j });
        changed = true;
      }
    }
    if (changed) redraw();
  });
  const refresh = debounce(() => reload(), 1500);
  const offEvents = onEvents(['job.done'], refresh);
  const timer = window.setInterval(() => {
    if (document.visibilityState === 'visible' && [...byId.values()].some((j) => !jobFinished(j.state))) reload();
  }, 5000);

  /** @param {any} j */
  const cancel = async (j) => {
    const ok = await confirm({ title: `Cancel “${jobKindLabel(j.kind)}”?`, message: 'The job stops at the next safe point. Work already done is kept or rolled back, depending on the job.', confirmLabel: 'Cancel job', cancelLabel: 'Keep running', danger: true });
    if (!ok) return;
    try {
      await api.post(`/admin/jobs/${encodeURIComponent(j.id)}/cancel`, {});
      toast.success('Cancellation requested');
      await reload();
    } catch (err) {
      toast.error(err);
    }
  };

  /** @param {{kind: string, label: string, text: string}} m */
  const run = async (m) => {
    const ok = await confirm({ title: `${m.label}?`, message: `${m.text} It runs in the background.`, confirmLabel: 'Run now' });
    if (!ok) return;
    try {
      const res = await api.post('/admin/jobs/run', { kind: m.kind });
      toast.success(`${m.label} started`);
      await reload();
      if (res?.job_id && !byId.has(res.job_id)) {
        try {
          const j = await api.get(`/admin/jobs/${encodeURIComponent(res.job_id)}`, { handle: false });
          if (j?.id) {
            byId.set(j.id, j);
            order.unshift(j.id);
            draw();
          }
        } catch { /* shows up on the next refresh */ }
      }
    } catch (err) {
      toast.error(err);
    }
  };

  /** @param {any} j */
  const details = async (j) => {
    // who started it (created_by is a user id; accounts need "View people"): false = that account was deleted,
    // null = unknown
    const who = j.created_by && can('users.view')
      ? api.get(`/admin/users/${encodeURIComponent(j.created_by)}`, { handle: false })
        .catch((err) => (err instanceof ApiError && err.status === 404 ? false : null))
      : Promise.resolve(null);
    /** @type {any} */
    let full = j;
    try { full = (await api.get(`/admin/jobs/${encodeURIComponent(j.id)}`, { handle: false })) || j; } catch { /* use the row */ }
    /** @type {any} */
    const by = await who;
    const hasParams = full.params && typeof full.params === 'object' && Object.keys(full.params).length;
    const hasResult = full.result !== undefined && full.result !== null && !(typeof full.result === 'object' && !Object.keys(full.result).length);
    dialog({
      title: jobKindLabel(full.kind),
      size: 'md',
      body: h('div', { class: 'stack' },
        kv([
          ['State', stateBadge(full.state)],
          ['Kind', h('code', { text: full.kind })],
          ['ID', h('span', { class: 'mono text-xs', text: full.id })],
          ['Created', dateTime(full.created_at)],
          ['Started', full.started_at ? dateTime(full.started_at) : null],
          ['Finished', full.finished_at ? dateTime(full.finished_at) : null],
          ['Progress', full.progress_total ? `${number(full.progress_done || 0)} / ${number(full.progress_total)}` : null],
          ['Note', full.note || null],
          ['Schedule', full.schedule || null],
          ['Started by', by?.id ? h('a', { href: `/admin/users/${encodeURIComponent(by.id)}`, text: userLabel(by) }) : by === false ? 'an account that was deleted' : null],
          ['Attempts', full.attempts ? String(full.attempts) : null],
          ['Error', full.error ? h('span', { class: 'danger-text break', text: full.error }) : null],
        ]),
        hasParams ? h('div', { class: 'stack-sm' }, h('strong', { class: 'text-sm', text: 'Parameters' }), jsonBlock(full.params)) : null,
        hasResult ? h('div', { class: 'stack-sm' }, h('strong', { class: 'text-sm', text: 'Result' }), jsonBlock(full.result)) : null),
      actions: [
        !jobFinished(full.state) && can(jobPermission(full.kind)) ? { label: 'Cancel job', variant: 'danger', onClick: () => cancel(full) } : null,
        { label: 'Close', variant: 'primary' },
      ].filter(Boolean).map((x) => /** @type {any} */ (x)),
    }).open();
  };

  await reload();
  return () => {
    offStore();
    offEvents();
    refresh.cancel();
    redraw.cancel();
    window.clearInterval(timer);
  };
}

/**
 * Where a job came from, for the list. created_by is set for jobs started by hand (admin pages, CLI) and for
 * zip uploads, which any member or share upload starts; the details dialog names the person.
 * @param {any} j
 */
function origin(j) {
  if (j.schedule) return `scheduled (${j.schedule})`;
  if (!j.created_by) return 'system';
  return j.kind === 'upload.zip' ? 'started by an upload' : 'started by hand';
}
