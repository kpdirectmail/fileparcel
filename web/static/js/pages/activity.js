// @ts-check
/**
 * Activity — /activity (§13.2, GET /activity): the user's own audit events (sign-ins, uploads, renames, shares, …)
 * grouped by day, newest first, with "Load more" paging. Failed or denied events are highlighted.
 * @module pages/activity
 */
import { h, icon } from '../core/dom.js';
import { api, itemsOf, errorMessage, ApiError } from '../core/api.js';
import { date as fmtDate, toDate } from '../core/format.js';
import { pageHeader } from '../components/page-header.js';
import { tabs } from '../components/tabs.js';
import { button } from '../components/button.js';
import { emptyState } from '../components/empty-state.js';
import { skeleton } from '../components/progress.js';
import { activityRow } from '../components/activity.js';
import { toast } from '../components/toast.js';

export const title = 'Activity';

// Categories span several action prefixes (§9.6) while GET /activity filters by one, so they are applied here.
const FILTERS = [
  { id: 'all', label: 'Everything', prefixes: [] },
  { id: 'files', label: 'Files', prefixes: ['file.', 'folder.', 'archive.'] },
  { id: 'sharing', label: 'Sharing', prefixes: ['share.', 'grant.', 'request.'] },
  { id: 'security', label: 'Security', prefixes: ['auth.', 'user.', 'mfa.', 'passkey.', 'token.', 'session.'] },
];

const PAGE = 100; // events per request
const WANT = 20; // with a category: keep reading until this many match…
const MAX_PAGES = 5; // …or this many pages were read for one click

/** @param {any} r @param {typeof FILTERS[number]} f */
const matches = (r, f) => !f.prefixes.length || f.prefixes.some((p) => String(r.action || '').startsWith(p));

/** "Today" / "Yesterday" / date. @param {Date} d */
function dayLabel(d) {
  const today = new Date();
  const start = (/** @type {Date} */ x) => new Date(x.getFullYear(), x.getMonth(), x.getDate()).getTime();
  const diff = Math.round((start(today) - start(d)) / 86_400_000);
  if (diff === 0) return 'Today';
  if (diff === 1) return 'Yesterday';
  if (diff < 7) return new Intl.DateTimeFormat(undefined, { weekday: 'long' }).format(d);
  return fmtDate(d);
}

/**
 * @param {HTMLElement} root
 * @param {import('../core/router.js').PageContext} ctx
 */
export function mount(root, ctx) {
  /** @type {any[]} */
  let rows = [];
  let cursor = '';
  let seq = 0;
  let filter = FILTERS[0];

  const listEl = h('div', { class: 'act-days' }, skeleton(6, { rows: true }));
  const more = button({ label: 'Load more', variant: 'secondary', size: 'sm', onClick: () => load(true) });
  more.hidden = true;
  const t = tabs({
    items: FILTERS.map((f) => ({ id: f.id, label: f.label })),
    active: 'all',
    variant: 'pill',
    label: 'Show',
    onChange: (id) => {
      filter = FILTERS.find((f) => f.id === id) || FILTERS[0];
      load(false);
    },
  });

  root.append(
    pageHeader({ title, subtitle: 'What happened in your account recently. Only you can see this list.' }),
    h('div', { class: 'files-toolbar' }, t.el),
    listEl,
    h('div', { class: 'cluster load-more' }, more));

  const render = () => {
    /** @type {Map<string, any[]>} */
    const groups = new Map();
    for (const r of rows) {
      const d = toDate(r.at);
      const key = d ? dayLabel(d) : 'Earlier';
      if (!groups.has(key)) groups.set(key, []);
      groups.get(key)?.push(r);
    }
    listEl.replaceChildren(...[...groups].map(([label, list]) => h('section', { class: 'act-day' },
      h('h2', { class: 'act-day-label', text: label }),
      h('ul', { class: 'act-list', attrs: { role: 'list' } }, list.map((r) => activityRow(r))))));
    if (!rows.length) {
      // with a cursor left only the recent history was searched: older events may still be in this category
      const partial = filter.prefixes.length > 0 && !!cursor;
      listEl.replaceChildren(emptyState({
        icon: 'activity',
        title: filter.id === 'all' ? 'No activity yet' : partial ? 'Nothing in this category recently' : 'Nothing in this category',
        text: partial ? 'None of your recent events are of this kind. Use “Load more” to look further back.' : 'Uploads, changes, shares and sign-ins will show up here.',
      }));
    }
  };

  /** @param {boolean} append */
  async function load(append) {
    const my = ++seq;
    if (!append) listEl.replaceChildren(skeleton(6, { rows: true }));
    const f = filter;
    try {
      // A category is filtered page by page, so one page may match nothing while older events do (a busy file
      // history hides the last share): read on, within limits, before showing "nothing".
      let next = append ? cursor : '';
      /** @type {any[]} */
      let found = [];
      for (let pages = 1; ; pages++) {
        const res = await api.get('/activity', { query: { limit: PAGE, cursor: next || undefined }, signal: ctx.signal });
        if (my !== seq) return;
        found = found.concat(itemsOf(res).filter((r) => matches(r, f)));
        next = Array.isArray(res) ? '' : res?.next_cursor || '';
        if (!f.prefixes.length || !next || found.length >= WANT || pages >= MAX_PAGES) break;
      }
      rows = append ? rows.concat(found) : found;
      cursor = next;
      more.hidden = !cursor;
      render();
      if (append && !found.length) toast.info(cursor ? 'No older events of this kind yet. “Load more” looks further back.' : 'No older events of this kind.');
    } catch (err) {
      if (err instanceof ApiError && err.aborted) return;
      listEl.replaceChildren(h('div', { class: 'alert alert--danger', attrs: { role: 'alert' } }, icon('alert-circle'),
        h('div', { class: 'alert-body' }, h('strong', { text: 'Could not load your activity' }), h('span', { text: errorMessage(err) })),
        button({ label: 'Retry', size: 'sm', onClick: () => load(false) })));
    }
  }

  load(false);
  return () => { seq += 1; };
}
