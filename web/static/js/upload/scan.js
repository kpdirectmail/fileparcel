// @ts-check
/**
 * Turn what the user picked, dropped or pasted into upload entries (§8.1 browser client):
 *   entriesFromFiles(files)            file picker / folder picker (webkitRelativePath) / paste / share target
 *   entriesFromDataTransfer(dt, onProgress)  drag & drop of mixed files and folders via webkitGetAsEntry(), looping
 *                                      readEntries() until it returns nothing and keeping empty directories
 * Every file gets a `fpRelPath` property (its path relative to the drop) that upload/engine.js uses to match files
 * again after a reload. Names the server would reject (§6 name rules, > 64 levels, > 4096 bytes) and OS junk files
 * (.DS_Store, Thumbs.db, desktop.ini) are skipped and counted; a folder left with nothing but skipped entries is kept
 * as an empty directory. skipReason() and emptiedFolders() are the same rules for the public file-request page
 * (public/share-upload.js).
 * @module upload/scan
 */
import { nameError, trimName } from '../core/nodes.js';

/**
 * @typedef {import('./engine.js').FileSpec} FileSpec
 * @typedef {Object} Scan
 * @property {FileSpec[]} files
 * @property {string[]} dirs empty directories (relative paths)
 * @property {number} bytes total size
 * @property {string[]} skipped relative paths that were left out
 * @property {string[]} roots top-level names (for the default .zip name)
 */

const JUNK = new Set(['.ds_store', 'thumbs.db', 'desktop.ini', '.localized']);
const MAX_DEPTH = 64;
const MAX_PATH = 4096;
const enc = new TextEncoder();

/** @param {string} rel @returns {string | null} reason to skip */
function invalid(rel) {
  const parts = rel.split('/');
  if (parts.length > MAX_DEPTH) return 'too deep';
  if (enc.encode(rel).length > MAX_PATH) return 'path too long';
  // each segment as names.SplitRelPath checks it: after trimming U+0020, which the server does rather than reject
  for (const p of parts) if (nameError(trimName(p))) return 'invalid name';
  return null;
}

/**
 * Why a relative path is left out of an upload (an OS junk file, or a path the server would reject), or null.
 * @param {string} rel NFC-normalised path without a leading slash
 * @param {boolean} [dir] an (empty) directory entry: the junk names only apply to files
 * @returns {string | null}
 */
export function skipReason(rel, dir = false) {
  const name = rel.split('/').pop() || rel;
  if (!dir && JUNK.has(name.toLowerCase())) return 'system file';
  return invalid(rel);
}

/** @returns {Scan} */
function emptyScan() {
  return { files: [], dirs: [], bytes: 0, skipped: [], roots: [] };
}

/**
 * @param {Scan} scan
 * @param {File} file
 * @param {string} rel
 */
function addFile(scan, file, rel) {
  const clean = rel.replace(/^\/+/, '').normalize('NFC');
  if (skipReason(clean)) {
    scan.skipped.push(clean);
    return;
  }
  try {
    Object.defineProperty(file, 'fpRelPath', { value: clean, configurable: true });
  } catch { /* frozen File: engine falls back to webkitRelativePath/name */ }
  scan.files.push({ file, relPath: clean });
  scan.bytes += file.size;
  addRoot(scan, clean);
}

/** @param {Scan} scan @param {string} rel */
function addRoot(scan, rel) {
  const root = rel.split('/')[0];
  if (!scan.roots.includes(root)) scan.roots.push(root);
}

/**
 * The folders to keep as empty directories because everything in them was skipped (an OS junk file such as the
 * .DS_Store Finder puts into most folders, a name the server rejects, an unreadable entry): §8.1 preserves empty
 * directories, and such a folder would otherwise vanish from the upload. Only the deepest folder left without
 * content is returned — its parents are implied by it.
 * @param {Iterable<string>} kept relative paths of the files and directories that are uploaded
 * @param {Iterable<string>} skipped relative paths that were left out
 * @returns {string[]}
 */
export function emptiedFolders(kept, skipped) {
  /** @type {Set<string>} every kept path and its ancestors */
  const covered = new Set();
  /** @param {string} rel */
  const cover = (rel) => {
    let p = '';
    for (const part of rel.split('/')) {
      p = p ? `${p}/${part}` : part;
      covered.add(p);
    }
  };
  for (const rel of kept) cover(rel);
  /** @type {Set<string>} */
  const parents = new Set();
  for (const rel of skipped) {
    const parts = rel.normalize('NFC').split('/');
    for (let i = parts.length - 1; i > 0; i--) parents.add(parts.slice(0, i).join('/'));
  }
  /** @type {string[]} */
  const out = [];
  // deepest first, so a folder is only added when none of its sub-folders was
  for (const d of [...parents].sort((a, b) => b.split('/').length - a.split('/').length)) {
    if (covered.has(d) || skipReason(d, true)) continue;
    out.push(d);
    cover(d);
  }
  return out;
}

/** Add the folders that only held skipped entries to the scan as empty directories. @param {Scan} scan */
function keepEmptied(scan) {
  if (!scan.skipped.length) return;
  for (const d of emptiedFolders([...scan.files.map((f) => f.relPath), ...scan.dirs], scan.skipped)) {
    scan.dirs.push(d);
    addRoot(scan, d);
  }
}

/**
 * Entries from a FileList / File[] (pickers, paste, share target). The folder picker sets webkitRelativePath
 * ("Trip/day1/a.jpg"); empty folders are not reported by browsers in that case, but a folder whose only files are
 * skipped (Trip/assets/.DS_Store) is kept.
 * @param {ArrayLike<File> | Iterable<File>} files
 * @returns {Scan}
 */
export function entriesFromFiles(files) {
  const scan = emptyScan();
  for (const f of Array.from(files)) {
    const any = /** @type {any} */ (f);
    addFile(scan, f, any.fpRelPath || any.webkitRelativePath || f.name);
  }
  keepEmptied(scan);
  return scan;
}

/**
 * Read all children of a directory (readEntries returns batches of ~100 until it returns an empty array).
 * @param {any} dirEntry FileSystemDirectoryEntry
 * @returns {Promise<any[]>}
 */
async function readAll(dirEntry) {
  const reader = dirEntry.createReader();
  /** @type {any[]} */
  const out = [];
  for (;;) {
    /** @type {any[]} */
    const batch = await new Promise((resolve, reject) => reader.readEntries(resolve, reject));
    if (!batch.length) break;
    out.push(...batch);
  }
  return out;
}

/**
 * @param {any} fileEntry FileSystemFileEntry
 * @returns {Promise<File>}
 */
function entryFile(fileEntry) {
  return new Promise((resolve, reject) => fileEntry.file(resolve, reject));
}

/**
 * Entries from a drop. Call synchronously from the `drop` handler: DataTransfer items are only readable during the
 * event, so the entries are captured first and traversed afterwards.
 * @param {DataTransfer} dt
 * @param {(found: number) => void} [onProgress] number of entries found so far (large folder drops)
 * @returns {Promise<Scan>}
 */
export function entriesFromDataTransfer(dt, onProgress) {
  /** @type {any[]} */
  const entries = [];
  /** @type {File[]} */
  const loose = [];
  const items = dt.items ? Array.from(dt.items) : [];
  for (const it of items) {
    if (it.kind !== 'file') continue;
    const entry = typeof it.webkitGetAsEntry === 'function' ? it.webkitGetAsEntry() : null;
    if (entry) entries.push(entry);
    else {
      const f = it.getAsFile();
      if (f) loose.push(f);
    }
  }
  if (!items.length && dt.files) loose.push(...Array.from(dt.files));

  return (async () => {
    const scan = emptyScan();
    for (const f of loose) addFile(scan, f, f.name);
    /** @type {{entry: any, rel: string}[]} */
    const fileEntries = [];
    let found = 0;
    /** @param {any} entry @param {string} prefix */
    const walk = async (entry, prefix) => {
      const rel = prefix + entry.name;
      if (entry.isFile) {
        fileEntries.push({ entry, rel });
        found += 1;
        if (found % 250 === 0) onProgress?.(found);
        return;
      }
      if (!entry.isDirectory) return;
      let children = [];
      try {
        children = await readAll(entry);
      } catch {
        scan.skipped.push(rel);
        return;
      }
      if (!children.length) {
        if (invalid(rel)) scan.skipped.push(rel);
        else {
          const d = rel.normalize('NFC');
          scan.dirs.push(d);
          addRoot(scan, d);
        }
        return;
      }
      for (const c of children) await walk(c, `${rel}/`);
    };
    for (const e of entries) await walk(e, '');
    // resolve File objects in parallel (each entry.file() is an async round-trip)
    const CONC = 32;
    for (let i = 0; i < fileEntries.length; i += CONC) {
      const chunk = fileEntries.slice(i, i + CONC);
      const files = await Promise.all(chunk.map((x) => entryFile(x.entry).catch(() => null)));
      files.forEach((f, j) => {
        if (f) addFile(scan, f, chunk[j].rel);
        else scan.skipped.push(chunk[j].rel);
      });
    }
    keepEmptied(scan); // a folder whose children were all skipped (e.g. only a .DS_Store) stays as an empty one
    return scan;
  })();
}

/**
 * Pasted files: screenshots arrive as "image.png" — give them a descriptive, unique name.
 * @param {File[]} files
 * @returns {File[]}
 */
export function renamePasted(files) {
  const stamp = new Date().toISOString().slice(0, 19).replace('T', ' ').replace(/:/g, '.');
  return files.map((f, i) => {
    if (!/^image\.(png|jpe?g|gif|webp)$/i.test(f.name)) return f;
    const ext = f.name.split('.').pop();
    const suffix = files.length > 1 ? ` (${i + 1})` : '';
    return new File([f], `Pasted image ${stamp}${suffix}.${ext}`, { type: f.type, lastModified: f.lastModified || Date.now() });
  });
}

/**
 * True when a drag carries files from outside the page (not an in-app node drag).
 * @param {DragEvent} e
 */
export function isFileDrag(e) {
  const types = Array.from(e.dataTransfer?.types || []);
  return types.includes('Files') && !types.includes('application/x-fp-nodes');
}
