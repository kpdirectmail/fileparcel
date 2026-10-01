// @ts-check
/**
 * Formatting helpers (locale-aware via Intl, using the document language).
 *   bytes(1536) → "1.5 KiB"     date(ts) → "19 Sep 2026"      relTime(ts) → "5 minutes ago"
 *   duration(95000) → "1m 35s"  pct(1, 3) → "33%"             dateTime(ts) → "19 Sep 2026, 14:03"
 * Timestamps may be RFC 3339 strings (API), Date objects or Unix milliseconds.
 * @module core/format
 */

const LOCALE = (typeof document !== 'undefined' && document.documentElement.lang) || undefined;

/** @typedef {string | number | Date | null | undefined} TimeLike */

/**
 * @param {TimeLike} ts
 * @returns {Date | null}
 */
export function toDate(ts) {
  if (ts === null || ts === undefined || ts === '') return null;
  const d = ts instanceof Date ? ts : new Date(ts);
  if (Number.isNaN(d.getTime()) || d.getTime() <= 0) return null;
  return d;
}

// IEC suffixes: the values are 1024-based, and every other byte formatter in
// the product (the API's doctor messages, the CLI, backups, notifications)
// prints KiB/MiB/GiB too, so the same byte count never appears twice in two
// spellings. Size *entry* stays lenient: parseSize() in pages/admin/common.js
// accepts "50 GB" as well as "50 GiB".
const UNITS = ['B', 'KiB', 'MiB', 'GiB', 'TiB', 'PiB'];

/**
 * Human-readable size using binary multiples (1 KiB = 1024 B), matching what file managers show.
 * @param {number | null | undefined} n
 * @param {{digits?: number}} [opts]
 */
export function bytes(n, opts = {}) {
  if (n === null || n === undefined || !Number.isFinite(n)) return '—';
  if (n < 0) return `-${bytes(-n, opts)}`;
  // Whole bytes: speed() passes fractional rates ("624.6153846153846 B/s"). Floor, so 1023.7 never reads "1,024 B"
  // (and `|| 0` turns -0 into 0, which Intl would print as "-0").
  if (n < 1024) return `${new Intl.NumberFormat(LOCALE).format(Math.floor(n) || 0)} B`;
  let i = 0;
  let v = n;
  while (v >= 1024 && i < UNITS.length - 1) {
    v /= 1024;
    i += 1;
  }
  const digits = opts.digits ?? (v >= 100 ? 0 : v >= 10 ? 1 : 2);
  return `${new Intl.NumberFormat(LOCALE, { maximumFractionDigits: digits }).format(v)} ${UNITS[i]}`;
}

/**
 * Integer with grouping separators.
 * @param {number | null | undefined} n
 */
export function number(n) {
  if (n === null || n === undefined || !Number.isFinite(n)) return '—';
  return new Intl.NumberFormat(LOCALE).format(n);
}

/**
 * Date only ("19 Sep 2026").
 * @param {TimeLike} ts
 */
export function date(ts) {
  const d = toDate(ts);
  if (!d) return '—';
  return new Intl.DateTimeFormat(LOCALE, { year: 'numeric', month: 'short', day: 'numeric' }).format(d);
}

/**
 * Date and time ("19 Sep 2026, 14:03").
 * @param {TimeLike} ts
 * @param {{seconds?: boolean}} [opts]
 */
export function dateTime(ts, opts = {}) {
  const d = toDate(ts);
  if (!d) return '—';
  return new Intl.DateTimeFormat(LOCALE, {
    year: 'numeric', month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit', second: opts.seconds ? '2-digit' : undefined,
  }).format(d);
}

/**
 * Time only ("14:03").
 * @param {TimeLike} ts
 */
export function time(ts) {
  const d = toDate(ts);
  if (!d) return '—';
  return new Intl.DateTimeFormat(LOCALE, { hour: '2-digit', minute: '2-digit' }).format(d);
}

/**
 * Relative time ("just now", "5 minutes ago", "in 3 days"); falls back to date() beyond ~11 months.
 * @param {TimeLike} ts
 * @param {number} [now]
 */
export function relTime(ts, now = Date.now()) {
  const d = toDate(ts);
  if (!d) return '—';
  const diff = d.getTime() - now;
  const abs = Math.abs(diff);
  if (abs < 45_000) return diff <= 0 ? 'just now' : 'in a moment';
  const rtf = new Intl.RelativeTimeFormat(LOCALE, { numeric: 'auto' });
  /** @type {[number, Intl.RelativeTimeFormatUnit][]} */
  const steps = [
    [60_000, 'second'],
    [3_600_000, 'minute'],
    [86_400_000, 'hour'],
    [7 * 86_400_000, 'day'],
    [30 * 86_400_000, 'week'],
    [335 * 86_400_000, 'month'],
  ];
  const div = { second: 1000, minute: 60_000, hour: 3_600_000, day: 86_400_000, week: 7 * 86_400_000, month: 30 * 86_400_000 };
  for (const [limit, unit] of steps) {
    if (abs < limit) return rtf.format(Math.round(diff / /** @type {any} */ (div)[unit]), unit);
  }
  return date(d);
}

/**
 * Compact duration ("1h 5m", "3m 20s", "850 ms").
 * @param {number | null | undefined} ms
 */
export function duration(ms) {
  if (ms === null || ms === undefined || !Number.isFinite(ms)) return '—';
  if (ms < 0) ms = 0;
  if (ms < 1000) return `${Math.round(ms)} ms`;
  let s = Math.round(ms / 1000);
  const d = Math.floor(s / 86400);
  s -= d * 86400;
  const hh = Math.floor(s / 3600);
  s -= hh * 3600;
  const mm = Math.floor(s / 60);
  s -= mm * 60;
  if (d) return `${d}d ${hh}h`;
  if (hh) return `${hh}h ${mm}m`;
  if (mm) return `${mm}m ${s}s`;
  return `${s}s`;
}

/**
 * Percentage a/b ("0%" when b is 0).
 * @param {number} a
 * @param {number} b
 * @param {number} [digits]
 */
export function pct(a, b, digits = 0) {
  if (!b || !Number.isFinite(a) || !Number.isFinite(b)) return '0%';
  const v = Math.max(0, Math.min(100, (a / b) * 100));
  return `${v.toFixed(v > 0 && v < 1 && digits === 0 ? 1 : digits)}%`;
}

/**
 * Transfer speed ("12.3 MiB/s").
 * @param {number} bytesPerSecond
 */
export function speed(bytesPerSecond) {
  if (!Number.isFinite(bytesPerSecond) || bytesPerSecond <= 0) return '—';
  return `${bytes(bytesPerSecond)}/s`;
}

/**
 * "1 file" / "3 files".
 * @param {number} n
 * @param {string} one
 * @param {string} [many]
 */
export function plural(n, one, many = `${one}s`) {
  return `${number(n)} ${n === 1 ? one : many}`;
}

/**
 * Initials for avatars ("Ada Lovelace" → "AL").
 * @param {string | null | undefined} name
 */
export function initials(name) {
  const parts = String(name || '?').trim().split(/[\s._-]+/).filter(Boolean);
  if (parts.length === 0) return '?';
  const first = [...parts[0]][0] || '';
  const last = parts.length > 1 ? [...parts[parts.length - 1]][0] || '' : '';
  return (first + last).toUpperCase();
}

/**
 * Icon id for a node (folder / mime type / extension).
 * @param {{kind?: string, mime?: string, name?: string} | null | undefined} node
 */
export function fileIcon(node) {
  if (!node) return 'file';
  if (node.kind === 'folder') return 'folder';
  const mime = node.mime || '';
  const ext = (node.name || '').toLowerCase().split('.').pop() || '';
  if (mime.startsWith('image/')) return 'image';
  if (mime.startsWith('video/')) return 'video';
  if (mime.startsWith('audio/')) return 'music';
  if (mime === 'application/pdf' || ext === 'pdf') return 'file-pdf';
  if (/^(zip|7z|rar|gz|tgz|bz2|xz|zst|tar)$/.test(ext) || /zip|compressed|x-tar/.test(mime)) return 'file-zip';
  if (/^(js|mjs|ts|go|py|rb|rs|c|h|cpp|java|kt|swift|sh|json|yaml|yml|toml|xml|html|css|sql)$/.test(ext)) return 'file-code';
  if (mime.startsWith('text/') || /^(txt|md|csv|log|doc|docx|odt|rtf)$/.test(ext)) return 'file-text';
  return 'file';
}
