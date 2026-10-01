// @ts-check
/**
 * pickFolder({title, confirmLabel, start, exclude, need}) → Promise<Node | null>
 *
 * Destination chooser for Move / Copy / upload destination / new file requests. The dialog browses one folder at a
 * time (the confirm button acts on the folder being shown, like most file managers): a top level with the user's
 * spaces (My files, team folders) and folders shared with them, then sub-folders via
 * GET /nodes/{id}/children?kind=folder. Folders in `exclude` (the items being moved) cannot be entered, so a folder
 * can never be moved into itself or a descendant. Folders the user may not write to (`need`, default "edit") can be
 * browsed but not chosen. "New folder" creates a sub-folder in place.
 * @module components/folder-picker
 */
import { h, icon } from '../core/dom.js';
import { api, getAll, errorMessage } from '../core/api.js';
import { spaces, spaceLabel, can } from '../core/nodes.js';
import { dialog, prompt } from './dialog.js';
import { button } from './button.js';
import { toast } from './toast.js';
import { spinner } from './progress.js';

/**
 * @typedef {import('../core/nodes.js').Node} Node
 * @typedef {{id: string, name: string, node: Node | null}} Crumb
 */

/** Why a folder that fails `need` cannot be chosen (the picker's status line). */
const BLOCKED = {
  view: 'You can’t open this folder.',
  edit: 'You can’t add items to this folder.',
  manage: 'You need “Can manage” on this folder to share it or send uploads to it.',
};

/**
 * @param {{title?: string, confirmLabel?: string, start?: Node | null, exclude?: string[],
 *   need?: 'view' | 'edit' | 'manage', help?: string, blockedText?: string}} [opts]
 *   blockedText: the status line for a folder that fails `need` (default: a reason that matches `need`)
 * @returns {Promise<Node | null>}
 */
export function pickFolder(opts = {}) {
  const need = opts.need || 'edit';
  const blocked = opts.blockedText || BLOCKED[need] || BLOCKED.edit;
  const exclude = new Set(opts.exclude || []);
  return new Promise((resolve) => {
    /** @type {Crumb[]} */
    let trail = [];
    /** @type {Node | null} */
    let current = null;
    let seq = 0;

    const crumbsEl = h('nav', { class: 'fp-picker-crumbs', attrs: { 'aria-label': 'Location' } });
    const listEl = h('ul', { class: 'fp-picker-list', attrs: { role: 'list' } });
    const status = h('p', { class: 'fp-picker-status muted text-sm', attrs: { 'aria-live': 'polite' } });
    const newBtn = button({ label: 'New folder', icon: 'folder-plus', variant: 'ghost', size: 'sm', onClick: () => createHere() });
    const confirmBtn = button({ label: opts.confirmLabel || 'Choose', variant: 'primary', onClick: () => d.close(current) });

    const body = h('div', { class: 'fp-picker' },
      opts.help ? h('p', { class: 'muted text-sm', text: opts.help }) : null,
      h('div', { class: 'fp-picker-bar' }, crumbsEl, newBtn),
      listEl,
      status);

    const d = dialog({
      title: opts.title || 'Choose a folder',
      size: 'md',
      class: 'fp-picker-dialog',
      body,
      actions: [{ label: 'Cancel', variant: 'ghost' }, confirmBtn],
      onClose: (v) => resolve(v && typeof v === 'object' ? v : null),
    });

    const syncConfirm = () => {
      const ok = !!current && can(current, need) && !exclude.has(current.id);
      confirmBtn.disabled = !ok;
      newBtn.disabled = !current || !can(current, 'edit');
      if (current && !can(current, need)) status.textContent = blocked;
      else if (current && exclude.has(current.id)) status.textContent = 'Choose a different folder.';
    };

    const renderCrumbs = () => {
      const all = [{ id: '', name: 'All locations', node: null }, ...trail];
      crumbsEl.replaceChildren(h('ol', { attrs: { role: 'list' } }, all.map((c, i) => h('li', null,
        i === all.length - 1
          ? h('span', { attrs: { 'aria-current': 'location' }, text: c.name })
          : h('button', { class: 'fp-picker-crumb', attrs: { type: 'button' }, text: c.name, on: { click: () => (c.id ? openAt(i - 1) : showTop()) } })))));
    };

    /** @param {HTMLElement[]} rows */
    const setRows = (rows) => {
      listEl.replaceChildren(...rows);
      const first = /** @type {HTMLElement | null} */ (listEl.querySelector('button:not([disabled])'));
      if (first && d.el.contains(document.activeElement) && document.activeElement?.closest('.fp-picker-list, .fp-picker-crumbs')) first.focus();
    };

    /**
     * @param {string} label @param {string} ic @param {() => void} onClick @param {{disabled?: boolean, hint?: string}} [o]
     */
    const row = (label, ic, onClick, o = {}) => h('li', null, h('button', {
      class: 'fp-picker-row',
      attrs: { type: 'button' },
      disabled: !!o.disabled,
      on: { click: onClick },
    }, icon(ic), h('span', { class: 'truncate', text: label }), o.hint ? h('small', { class: 'muted', text: o.hint }) : null, icon('chevron-right', { class: 'fp-picker-chev' })));

    async function showTop() {
      const my = ++seq;
      trail = [];
      current = null;
      renderCrumbs();
      syncConfirm();
      status.textContent = '';
      listEl.replaceChildren(h('li', { class: 'fp-picker-loading' }, spinner()));
      try {
        const [sp, shared] = await Promise.all([
          spaces(),
          getAll('/shared-with-me', { query: { kind: 'folder' }, handle: false, max: 1000 }).catch(() => []),
        ]);
        if (my !== seq) return;
        /** @type {HTMLElement[]} */
        const rows = [];
        for (const s of sp) {
          if (!s.root_id) continue;
          rows.push(row(spaceLabel(s), s.kind === 'group' ? 'users' : 'folder', () => enterRoot(s.root_id, spaceLabel(s), s.perm)));
        }
        const sharedFolders = shared.filter((n) => n.kind === 'folder');
        for (const n of sharedFolders) rows.push(row(n.name, 'folder-shared', () => enter(n), { hint: 'Shared with you', disabled: exclude.has(n.id) }));
        if (!rows.length) rows.push(h('li', { class: 'muted text-sm fp-picker-empty', text: 'No folders are available.' }));
        setRows(rows);
      } catch (err) {
        if (my === seq) listEl.replaceChildren(h('li', { class: 'danger-text text-sm fp-picker-empty', text: errorMessage(err) }));
      }
    }

    /** @param {string} id @param {string} label @param {any} perm */
    async function enterRoot(id, label, perm) {
      try {
        const node = await api.get(`/nodes/${encodeURIComponent(id)}`, { handle: false });
        trail = [{ id, name: label, node: { ...node, perm: node.perm ?? perm } }];
        await show(trail[0].node);
      } catch (err) {
        toast.error(err);
      }
    }

    /** @param {Node} n */
    async function enter(n) {
      if (exclude.has(n.id)) return;
      trail = [...trail, { id: n.id, name: n.name, node: n }];
      await show(n);
    }

    /** @param {number} i index into trail */
    async function openAt(i) {
      trail = trail.slice(0, i + 1);
      const c = trail[trail.length - 1];
      if (c.node) await show(c.node);
    }

    /** @param {Node} folder */
    async function show(folder) {
      const my = ++seq;
      current = folder;
      renderCrumbs();
      status.textContent = '';
      syncConfirm();
      listEl.replaceChildren(h('li', { class: 'fp-picker-loading' }, spinner()));
      try {
        const kids = await getAll(`/nodes/${encodeURIComponent(folder.id)}/children`, { query: { kind: 'folder', sort: 'name' }, handle: false, max: 2000 });
        if (my !== seq) return;
        const folders = kids.filter((n) => n.kind === 'folder');
        setRows(folders.length
          ? folders.map((n) => row(n.name, 'folder', () => enter({ ...n, perm: n.perm ?? folder.perm }), { disabled: exclude.has(n.id), hint: exclude.has(n.id) ? 'Selected' : '' }))
          : [h('li', { class: 'muted text-sm fp-picker-empty', text: 'No sub-folders.' })]);
      } catch (err) {
        if (my === seq) listEl.replaceChildren(h('li', { class: 'danger-text text-sm fp-picker-empty', text: errorMessage(err) }));
      }
    }

    async function createHere() {
      if (!current) return;
      const name = await prompt({ title: 'New folder', label: 'Folder name', value: 'New folder', confirmLabel: 'Create' });
      if (!name || !current) return;
      try {
        const node = await api.post(`/nodes/${encodeURIComponent(current.id)}/folders`, { name });
        await enter({ ...node, perm: node.perm ?? current.perm });
      } catch (err) {
        toast.error(err);
      }
    }

    d.open();
    if (opts.start && opts.start.kind === 'folder') {
      // open at the start folder with a breadcrumb trail from GET /nodes/{id}/breadcrumbs
      (async () => {
        try {
          const crumbs = /** @type {Node[]} */ (await api.get(`/nodes/${encodeURIComponent(/** @type {Node} */ (opts.start).id)}/breadcrumbs`, { handle: false }) || []);
          const list = Array.isArray(crumbs) ? crumbs : [];
          if (!list.length || list[list.length - 1].id !== opts.start?.id) list.push(/** @type {Node} */ (opts.start));
          const sp = await spaces();
          trail = list.map((n, i) => {
            const space = i === 0 && !n.parent_id ? sp.find((s) => s.id === n.space_id) : null;
            return { id: n.id, name: space ? spaceLabel(space) : n.name, node: n };
          });
          const last = trail[trail.length - 1].node;
          if (last) await show({ ...last, perm: last.perm ?? opts.start?.perm });
        } catch {
          await showTop();
        }
      })();
    } else {
      showTop();
    }
  });
}
