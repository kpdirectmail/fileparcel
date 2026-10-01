// @ts-check
/**
 * File-tree helpers shared by the file browser, previews, uploads and the sharing UI (§8.2, §9.4 filesapi).
 *
 *   contentURL(node, {inline: true})     → "/api/v1/nodes/<id>/content?inline=1"
 *   thumbURL(node)                        → "/api/v1/nodes/<id>/thumb?v=<version>"
 *   can(node, 'edit')                     → permission check against Node.perm (none|view|edit|manage|owner)
 *   previewKind(node)                     → 'image' | 'video' | 'audio' | 'pdf' | 'text' | ''
 *   downloadNodes(nodes)                  → single file: content download; otherwise a zip via POST /archives
 *   spaces()                              → cached GET /spaces (refreshed on demand)
 *   zipProtectionLabel(node)              → "Password-protected .zip (AES-256)" or '' (lock badges)
 * Every URL is same-origin; downloads use a hidden <a download> so an error page never replaces the app.
 * @module core/nodes
 */
import { h } from './dom.js';
import { api, itemsOf } from './api.js';
import { session } from './store.js';

/**
 * @typedef {Object} Node
 * @property {string} id
 * @property {string} space_id
 * @property {string} [parent_id]
 * @property {'folder' | 'file'} kind
 * @property {string} name
 * @property {number} size
 * @property {string} [mime]
 * @property {string} [version_id]
 * @property {string} [content_hash]
 * @property {string} [client_mtime]
 * @property {string} created_at
 * @property {string} updated_at
 * @property {string} [created_by]
 * @property {string} [updated_by]
 * @property {string} [trashed_at]
 * @property {boolean} [trash_root]
 * @property {boolean} [has_thumb]
 * @property {boolean} [starred]
 * @property {string | number} [perm]
 * @property {string} [path]
 * @property {number} [child_count]
 * @property {'aes256' | 'zipcrypto'} [zip_encryption] a .zip the upload made password-protected (current version)
 */

/**
 * @typedef {Object} Space
 * @property {string} id
 * @property {'user' | 'group'} kind
 * @property {string} [owner_user_id]
 * @property {string} [group_id]
 * @property {string} name
 * @property {number | null} [quota_bytes]
 * @property {number} [used_bytes]
 * @property {string} root_id
 * @property {string | number} [perm]
 */

/** Permission levels (core.Perm; JSON uses the names). */
export const PERM = Object.freeze({ none: 0, view: 1, edit: 2, manage: 3, owner: 4 });

/**
 * Numeric permission level of a Perm value (name or number); unknown → none.
 * @param {string | number | null | undefined} p
 */
export function permLevel(p) {
  if (typeof p === 'number') return Math.max(0, Math.min(4, p | 0));
  if (typeof p === 'string' && p in PERM) return /** @type {any} */ (PERM)[p];
  return 0;
}

/**
 * Whether the principal has at least `need` on `node`. A missing perm field is treated as "view" (the server only
 * returns nodes the user can see) so read-only actions stay available; mutations are enforced server-side anyway.
 * @param {{perm?: string | number} | null | undefined} node
 * @param {'view' | 'edit' | 'manage' | 'owner'} need
 */
export function can(node, need) {
  if (!node) return false;
  const have = node.perm === undefined || node.perm === null || node.perm === '' ? PERM.view : permLevel(node.perm);
  return have >= PERM[need];
}

/** @param {{kind?: string} | null | undefined} n */
export function isFolder(n) {
  return !!n && n.kind === 'folder';
}

/**
 * Lower-case extension without the dot ("" when none).
 * @param {string} name
 */
export function ext(name) {
  const i = name.lastIndexOf('.');
  return i > 0 && i < name.length - 1 ? name.slice(i + 1).toLowerCase() : '';
}

/**
 * Base name without the extension ("report.pdf" → "report"). Only for file names: it cannot tell a folder from a
 * file, and a folder such as "2024.09.23" must keep its full name.
 * @param {string} name
 */
export function baseName(name) {
  const i = name.lastIndexOf('.');
  return i > 0 ? name.slice(0, i) : name;
}

/**
 * Validation mirroring the server's name rules (§6: 1–255 bytes, no / \\ NUL, control or text-direction
 * control characters, not . or ..; internal/names).
 * Returns an error message or null.
 * @param {string} name
 */
export function nameError(name) {
  if (!name) return 'Please enter a name.';
  if (name === '.' || name === '..') return 'This name is reserved.';
  if (/[/\\]/.test(name)) return 'Names can’t contain / or \\.';
  // eslint-disable-next-line no-control-regex
  if (/[\u0000-\u001f\u007f-\u009f]/.test(name)) return 'Names can’t contain control characters.';
  // Bidi embeddings, overrides and isolates: "invoice\u202efdp.exe" would display as "invoiceexe.pdf".
  if (/[\u202a-\u202e\u2066-\u2069]/.test(name)) return 'Names can’t contain text-direction control characters.';
  if (new TextEncoder().encode(name).length > 255) return 'This name is too long.';
  if (name !== trimName(name)) return 'Names can’t start or end with a space.';
  return null;
}

/**
 * A name as the server stores it: names.Clean trims U+0020 at both ends (only that space — a no-break or other
 * Unicode space is kept) instead of rejecting it, so " a.txt" from a user's disk uploads as "a.txt".
 * @param {string} name
 */
export function trimName(name) {
  return name.replace(/^ +| +$/g, '');
}

/**
 * GET /nodes/{id}/content URL.
 * @param {{id: string} | string} node
 * @param {{inline?: boolean, version?: string}} [opts]
 */
export function contentURL(node, opts = {}) {
  const id = typeof node === 'string' ? node : node.id;
  const q = new URLSearchParams();
  if (opts.version) q.set('version', opts.version);
  if (opts.inline) q.set('inline', '1');
  const s = q.toString();
  return `/api/v1/nodes/${encodeURIComponent(id)}/content${s ? `?${s}` : ''}`;
}

/**
 * GET /nodes/{id}/thumb URL; the version is appended so a new version never shows a stale cached thumbnail.
 * @param {Node} node
 */
export function thumbURL(node) {
  const v = node.version_id || node.updated_at || '';
  return `/api/v1/nodes/${encodeURIComponent(node.id)}/thumb${v ? `?v=${encodeURIComponent(v)}` : ''}`;
}

/** Normalised MIME type (no parameters, lower case). @param {string | undefined} mime */
export function baseMime(mime) {
  return String(mime || '').split(';')[0].trim().toLowerCase();
}

const IMAGE_INLINE = new Set(['image/png', 'image/jpeg', 'image/gif', 'image/webp', 'image/avif', 'image/bmp']);
const IMAGE_EXT = new Set(['png', 'jpg', 'jpeg', 'gif', 'webp', 'avif', 'bmp']);
const VIDEO_INLINE = new Set(['video/mp4', 'video/webm', 'video/ogg', 'video/quicktime']);
const VIDEO_EXT = new Set(['mp4', 'm4v', 'webm', 'ogv', 'mov']);
const AUDIO_EXT = new Set(['mp3', 'm4a', 'aac', 'wav', 'ogg', 'oga', 'opus', 'flac', 'weba']);
/** Text-like files shown as source (fetched as bytes, rendered with textContent — never interpreted). */
const TEXT_EXT = new Set([
  'txt', 'text', 'md', 'markdown', 'rst', 'adoc', 'csv', 'tsv', 'log', 'ini', 'cfg', 'conf', 'env', 'properties', 'toml', 'yaml', 'yml',
  'json', 'jsonc', 'json5', 'ndjson', 'xml', 'html', 'htm', 'xhtml', 'svg', 'css', 'scss', 'sass', 'less', 'js', 'mjs', 'cjs', 'ts', 'tsx',
  'jsx', 'vue', 'svelte', 'go', 'mod', 'sum', 'py', 'rb', 'rs', 'c', 'h', 'cc', 'cpp', 'hpp', 'cs', 'java', 'kt', 'kts', 'swift', 'm', 'php',
  'pl', 'lua', 'r', 'dart', 'scala', 'sh', 'bash', 'zsh', 'fish', 'ps1', 'bat', 'cmd', 'sql', 'graphql', 'proto', 'tf', 'hcl', 'nix',
  'dockerfile', 'makefile', 'gitignore', 'gitattributes', 'editorconfig', 'diff', 'patch', 'srt', 'vtt', 'tex', 'bib', 'lock',
]);
const TEXT_NAMES = new Set(['dockerfile', 'makefile', 'readme', 'license', 'changelog', 'authors', 'notice', 'copying', 'todo']);

/**
 * Which previewer can show `node` (§8.2 inline allow-list; text is fetched and shown as plain text).
 * @param {Node | null | undefined} node
 * @returns {'image' | 'video' | 'audio' | 'pdf' | 'text' | ''}
 */
export function previewKind(node) {
  if (!node || node.kind !== 'file') return '';
  const mime = baseMime(node.mime);
  const e = ext(node.name);
  if (IMAGE_INLINE.has(mime) || (!mime && IMAGE_EXT.has(e)) || (mime === 'application/octet-stream' && IMAGE_EXT.has(e))) return 'image';
  if (VIDEO_INLINE.has(mime) || ((!mime || mime === 'application/octet-stream') && VIDEO_EXT.has(e))) return 'video';
  if (mime.startsWith('audio/') || ((!mime || mime === 'application/octet-stream') && AUDIO_EXT.has(e))) return 'audio';
  if (mime === 'application/pdf' || e === 'pdf') return 'pdf';
  if (mime.startsWith('text/') || /(json|xml|yaml|toml|javascript|x-sh|x-shellscript|sql|x-go|x-python)/.test(mime)) return 'text';
  if (TEXT_EXT.has(e) || TEXT_NAMES.has(node.name.toLowerCase())) return 'text';
  return '';
}

/** Non-text/* types the server shows inline as plain text (httpx textLike). */
const TEXT_LIKE = new Set([
  'application/json', 'application/x-ndjson', 'application/yaml', 'application/x-yaml', 'application/toml', 'application/x-toml',
  'application/sql', 'application/x-sh', 'application/x-shellscript', 'application/x-csh', 'application/x-python', 'application/x-perl',
  'application/x-ruby', 'application/x-php', 'application/x-httpd-php', 'application/x-tex', 'application/x-latex',
  'application/typescript', 'application/x-subrip', 'application/x-go',
]);

/**
 * Whether GET …/content?inline=1 is really served inline, mirroring httpx.ContentType (§8.2): HTML, SVG, any XML
 * and any JavaScript — and anything off the allow-list — always come back as attachments, even when previewKind()
 * can show them (the text previewer reads the bytes). "Open in new tab" is only offered when this is true.
 * @param {Node | null | undefined} node
 */
export function opensInline(node) {
  if (!node || node.kind !== 'file') return false;
  const mime = baseMime(node.mime);
  const [typ, sub = ''] = mime.split('/');
  if (/html|xml|javascript|ecmascript|jscript/.test(sub) || sub === 'svg') return false;
  return IMAGE_INLINE.has(mime) || VIDEO_INLINE.has(mime) || mime === 'application/pdf' || typ === 'audio' || typ === 'text'
    || TEXT_LIKE.has(mime) || sub.endsWith('+json');
}

/**
 * Human-readable type ("PDF document", "Folder", "PNG image", …).
 * @param {Node} node
 */
export function typeLabel(node) {
  if (node.kind === 'folder') return 'Folder';
  const e = ext(node.name);
  const kind = previewKind(node);
  const up = e ? e.toUpperCase() : '';
  switch (kind) {
    case 'image': return `${up || 'Image'} image`;
    case 'video': return `${up || 'Video'} video`;
    case 'audio': return `${up || 'Audio'} audio`;
    case 'pdf': return 'PDF document';
    case 'text': return up ? `${up} file` : 'Text file';
    default: return up ? `${up} file` : baseMime(node.mime) || 'File';
  }
}

/**
 * Accessible description of a password-protected .zip (the lock badges); '' when the node is not one.
 * @param {{zip_encryption?: string}} n
 * @returns {string}
 */
export function zipProtectionLabel(n) {
  return n.zip_encryption === 'zipcrypto' ? 'Password-protected .zip (ZipCrypto, weak)'
    : n.zip_encryption ? 'Password-protected .zip (AES-256)' : '';
}

/**
 * Start a browser download of `url` without leaving the page (hidden <a download>; the router ignores it).
 * @param {string} url
 * @param {string} [filename] suggested name (the server's Content-Disposition wins)
 */
export function triggerDownload(url, filename = '') {
  const a = h('a', { href: url, class: 'hidden', attrs: { download: filename, 'data-native': true, rel: 'noopener' } });
  document.body.appendChild(a);
  a.click();
  setTimeout(() => a.remove(), 0);
}

/**
 * Create a single-use archive ticket (POST /archives) and start the streamed download.
 * @param {string[]} ids
 * @param {{format?: 'zip' | 'tar', name?: string}} [opts]
 */
export async function downloadArchive(ids, opts = {}) {
  /** @type {Record<string, any>} */
  const body = { node_ids: ids, format: opts.format || 'zip' };
  if (opts.name) body.name = opts.name;
  const res = await api.post('/archives', body);
  const url = res?.url || (res?.ticket ? `/api/v1/archives/${encodeURIComponent(res.ticket)}` : '');
  if (!url) throw new Error('The server did not return a download link.');
  triggerDownload(url);
}

/**
 * Download nodes: one file → its content; a folder or several items → one zip (or tar) archive.
 * @param {Node[]} nodes
 * @param {{format?: 'zip' | 'tar', name?: string}} [opts]
 */
export async function downloadNodes(nodes, opts = {}) {
  if (!nodes.length) return;
  if (nodes.length === 1 && nodes[0].kind === 'file' && !opts.format) {
    triggerDownload(contentURL(nodes[0]), nodes[0].name);
    return;
  }
  const one = nodes[0];
  const name = opts.name || (nodes.length === 1 ? (one.kind === 'file' ? baseName(one.name) : one.name) : `${nodes.length} items`);
  await downloadArchive(nodes.map((n) => n.id), { format: opts.format, name });
}

// ---------------------------------------------------------------------------------------------------------------
// Spaces (GET /spaces) — cached; the sidebar, breadcrumbs, pickers and uploads all need them.
// ---------------------------------------------------------------------------------------------------------------

/** @type {Promise<Space[]> | null} */
let spacesPromise = null;
let spacesAt = 0;

/**
 * The spaces the user can see (personal space first, then team folders), cached for 60 s.
 * @param {{fresh?: boolean}} [opts]
 * @returns {Promise<Space[]>}
 */
export function spaces(opts = {}) {
  if (!spacesPromise || opts.fresh || Date.now() - spacesAt > 60_000) {
    spacesAt = Date.now();
    spacesPromise = api.get('/spaces', { handle: true })
      .then((res) => {
        const list = /** @type {Space[]} */ (itemsOf(res)).map((s) => ({ ...s, root_id: s.root_id || /** @type {any} */ (s).root_node_id || '' }));
        const me = session.peek()?.user?.id;
        list.sort((a, b) => rankSpace(a, me) - rankSpace(b, me) || a.name.localeCompare(b.name));
        return list;
      })
      .catch((err) => {
        spacesPromise = null;
        throw err;
      });
  }
  return spacesPromise;
}

/** @param {Space} s @param {string | undefined} me */
function rankSpace(s, me) {
  if (s.kind === 'user' && (!me || s.owner_user_id === me || !s.owner_user_id)) return 0;
  if (s.kind === 'group') return 1;
  return 2;
}

/**
 * The personal space ("My files"), or null for guests.
 * @returns {Promise<Space | null>}
 */
export async function homeSpace() {
  const me = session.peek();
  const list = await spaces();
  const byId = me && /** @type {any} */ (me).space_id ? list.find((s) => s.id === /** @type {any} */ (me).space_id) : null;
  return byId || list.find((s) => s.kind === 'user' && (!me?.user?.id || s.owner_user_id === me.user.id || !s.owner_user_id)) || null;
}

/**
 * Display name for a space root: "My files" for the personal space, the team name otherwise.
 * @param {Space | null | undefined} space
 */
export function spaceLabel(space) {
  if (!space) return 'Files';
  const me = session.peek()?.user?.id;
  if (space.kind === 'user' && (!space.owner_user_id || space.owner_user_id === me)) return 'My files';
  return space.name || 'Team folder';
}

/**
 * In-app URL that opens a node: folders → /files/<id>; files → their folder with the preview open.
 * @param {Node} node
 */
export function nodeHref(node) {
  if (node.kind === 'folder') return `/files/${encodeURIComponent(node.id)}`;
  if (node.parent_id) return `/files/${encodeURIComponent(node.parent_id)}?preview=${encodeURIComponent(node.id)}`;
  return `/files?preview=${encodeURIComponent(node.id)}`;
}

/**
 * In-app URL of the folder containing `node`, with the node highlighted.
 * @param {Node} node
 */
export function showInFolderHref(node) {
  if (!node.parent_id) return nodeHref(node);
  return `/files/${encodeURIComponent(node.parent_id)}?select=${encodeURIComponent(node.id)}`;
}

/**
 * Parent path of a node for "Location" columns ("/Photos/2024" → "Photos › 2024"; root → space label).
 * @param {Node} node
 * @param {Space[]} [spaceList]
 */
export function locationLabel(node, spaceList = []) {
  const space = spaceList.find((s) => s.id === node.space_id);
  const root = space ? spaceLabel(space) : '';
  const p = String(node.path || '');
  const parts = p.split('/').filter(Boolean);
  parts.pop(); // the node itself
  return [root, ...parts].filter(Boolean).join(' › ') || root || '—';
}

/**
 * The server's name_key, approximately (internal/names.Key: NFC of the full Unicode case fold): upper- then
 * lower-casing folds "ß" to "ss" and "ﬁ" to "fi" as full case folding does.
 * @param {string} name
 */
function nameKey(name) {
  return String(name || '').normalize('NFC').toUpperCase().toLowerCase().normalize('NFC');
}

/**
 * Sort nodes client-side (the lists sorted here rather than by the server: recent, starred, shared, search, trash) by
 * the server's ListQuery rule (internal/files runList), so a sort order means the same on every page:
 * folders before files, except for "trashed"; "kind" only groups (files first when descending) and orders by name
 * inside each group, never by extension; names compare by their name_key, code point by code point ("file10" before
 * "file2", as in My files). Ties are broken by name, then id.
 * @param {Node[]} list
 * @param {string} key name|size|updated|kind|trashed
 * @param {boolean} desc
 */
export function sortNodes(list, key, desc) {
  const dir = desc ? -1 : 1;
  /** @param {string} x @param {string} y */
  const cmp = (x, y) => (x < y ? -1 : x > y ? 1 : 0);
  /** @param {Node} n */
  const t = (n) => Date.parse(key === 'trashed' ? n.trashed_at || '' : n.updated_at || '') || 0;
  /** @param {Node} n */
  const group = (n) => (n.kind === 'folder' ? 0 : 1);
  const rows = list.map((n) => ({ n, k: nameKey(n.name) }));
  rows.sort(({ n: a, k: ka }, { n: b, k: kb }) => {
    if (key === 'kind') return (group(a) - group(b)) * dir || cmp(ka, kb) || cmp(a.id, b.id);
    if (key !== 'trashed' && group(a) !== group(b)) return group(a) - group(b);
    let r = 0;
    if (key === 'size') r = (a.size || 0) - (b.size || 0);
    else if (key === 'updated' || key === 'trashed') r = t(a) - t(b);
    return (r || cmp(ka, kb) || cmp(a.id, b.id)) * dir;
  });
  return rows.map((r) => r.n);
}
