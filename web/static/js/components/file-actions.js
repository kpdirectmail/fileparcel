// @ts-check
/**
 * fileActions(ctx) → actions — every file/folder operation of the file browser, with confirmation, conflict
 * handling, undo and toasts (§9.4 filesapi):
 *   open · preview · download (file, or .zip/.tar via POST /archives) · share · rename (PATCH /nodes/{id}) ·
 *   move / copy (POST /nodes/move|copy; 409 → "keep both / replace / skip") · star (PUT/DELETE /nodes/{id}/star) ·
 *   trash (POST /nodes/trash, with Undo → POST /trash/restore) · restore · purge (POST /trash/purge) · empty trash ·
 *   new folder (POST /nodes/{id}/folders) · details
 * menuItems(nodes) builds the context menu / action sheet for a selection, filtered by the user's permission.
 * After a change the page's `refresh()` runs and the in-app event "files.changed" is emitted.
 * @module components/file-actions
 */
import { h } from '../core/dom.js';
import { api, errorMessage, ApiError, itemsOf } from '../core/api.js';
import { navigate } from '../core/router.js';
import { events } from '../core/store.js';
import { plural } from '../core/format.js';
import { can, previewKind, opensInline, contentURL, downloadNodes, showInFolderHref, isFolder, nameError } from '../core/nodes.js';

export { nameError };
import { dialog, confirm, prompt } from './dialog.js';
import { toast } from './toast.js';
import { pickFolder } from './folder-picker.js';

/**
 * @typedef {import('../core/nodes.js').Node} Node
 * @typedef {import('./menu.js').MenuItem} MenuItem
 */

/**
 * @typedef {Object} ActionsContext
 * @property {'folder' | 'shared' | 'starred' | 'recent' | 'search' | 'trash'} context
 * @property {() => Node[]} items the current list (preview navigation)
 * @property {() => (Node | null)} [folder] the folder being shown
 * @property {() => any} refresh reload the list
 * @property {(ids: string[]) => void} [onRemoved] optimistic removal (trash/move out)
 * @property {(node: Node) => void} [onUpdated] optimistic update (rename/star)
 * @property {(node: Node) => void} [onCreated] a folder was created (select it)
 * @property {(node: Node, tab: import('./details-panel.js').DetailsTab) => void} [onDetails] show details (default: dialog)
 * @property {(nodes: Node[]) => void} [onSelectMode] touch: "Select" entry that starts selection mode
 */

/**
 * Ask how to resolve a name conflict. Resolves the policy or null (cancel).
 * @param {string} message server message
 * @param {{allowReplace: boolean, verb: string}} o
 * @returns {Promise<'rename' | 'replace' | 'skip' | null>}
 */
export function conflictDialog(message, o) {
  return new Promise((resolve) => {
    dialog({
      title: 'Some items already exist',
      size: 'sm',
      body: h('div', { class: 'stack-sm' },
        h('p', { text: message || 'An item with the same name already exists in the destination.' }),
        h('p', { class: 'muted text-sm', text: o.allowReplace
          ? `Choose what to do for every conflicting item. Replace only puts a file in place of a file: if a folder is involved, nothing is ${o.verb === 'copy' ? 'copied' : 'moved'} and you are asked again.`
          : 'Choose what to do for every conflicting item:' })),
      onClose: (v) => resolve(v || null),
      actions: [
        { label: 'Cancel', variant: 'ghost', value: null },
        { label: 'Skip', variant: 'secondary', value: 'skip' },
        o.allowReplace ? { label: 'Replace', variant: 'secondary', value: 'replace' } : null,
        { label: 'Keep both', variant: 'primary', value: 'rename', autofocus: true },
      ].filter(Boolean),
    }).open();
  });
}

/**
 * @param {ActionsContext} ctx
 */
export function fileActions(ctx) {
  const changed = (/** @type {any} */ detail = {}) => {
    events.emit('files.changed', { folderId: ctx.folder?.()?.id || '', ...detail });
  };
  const refresh = async () => {
    try { await ctx.refresh(); } catch { /* the page shows its own error */ }
  };

  /** @param {Node} node */
  const open = (node) => {
    if (isFolder(node)) navigate(`/files/${encodeURIComponent(node.id)}`);
    else preview(node);
  };

  /** @param {Node} node */
  const preview = async (node) => {
    const m = await import('../preview/viewer.js');
    // Page through the current list — unless the file is not in it (a ?preview=<id> deep link to a file elsewhere),
    // where the viewer shows just that file.
    const list = ctx.items();
    m.openPreview({
      items: list.some((n) => n.id === node.id) ? list : [node],
      startId: node.id,
      onShare: (n) => share(n),
      onDetails: (n) => details(n, 'info'),
    });
  };

  /** @param {Node[]} nodes @param {'zip' | 'tar'} [format] */
  const download = async (nodes, format) => {
    try {
      await downloadNodes(nodes, format ? { format } : {});
      if (nodes.length > 1 || isFolder(nodes[0]) || format) toast.info('Preparing your download… it starts in a moment.', { timeout: 3500 });
    } catch (err) {
      toast.error(err);
    }
  };

  /** @param {Node} node */
  const share = async (node) => {
    const m = await import('./share-dialog.js');
    m.openShareDialog(node, { onChange: () => refresh() });
  };

  /** @param {Node} node @param {import('./details-panel.js').DetailsTab} [tab] */
  const details = async (node, tab = 'info') => {
    if (ctx.onDetails) {
      ctx.onDetails(node, tab);
      return;
    }
    const m = await import('./details-panel.js');
    m.openDetailsDialog(node, { tab, onShare: share, onStar: (n, on) => star([n], on), onChanged: () => refresh() });
  };

  /** @param {Node} node */
  const rename = async (node) => {
    let value = node.name;
    for (;;) {
      const name = await prompt({
        title: node.kind === 'folder' ? 'Rename folder' : 'Rename file',
        label: 'New name',
        value,
        confirmLabel: 'Rename',
        selectBaseName: node.kind !== 'folder',
        validate: nameError,
      });
      if (!name || name === node.name) return;
      try {
        const updated = await api.patch(`/nodes/${encodeURIComponent(node.id)}`, { name });
        toast.success(`Renamed to “${updated?.name || name}”`);
        ctx.onUpdated?.({ ...node, ...(updated || { name }) });
        changed();
        refresh();
        return;
      } catch (err) {
        toast.error(err);
        if (!(err instanceof ApiError) || (err.status !== 409 && err.status !== 422)) return;
        value = name; // let the user fix it
      }
    }
  };

  /**
   * Move or copy with conflict resolution.
   * @param {'move' | 'copy'} kind @param {Node[]} nodes @param {Node} dest
   */
  const transfer = async (kind, nodes, dest) => {
    if (kind === 'move' && nodes.every((n) => n.parent_id === dest.id)) {
      toast.info(nodes.length === 1 ? `“${nodes[0].name}” is already in “${dest.name}”.` : 'These items are already there.');
      return false;
    }
    let conflict = kind === 'move' ? 'fail' : 'rename';
    for (;;) {
      try {
        await api.post(`/nodes/${kind}`, { ids: nodes.map((n) => n.id), dest: dest.id, conflict });
        const what = nodes.length === 1 ? `“${nodes[0].name}”` : plural(nodes.length, 'item');
        toast.success(`${kind === 'move' ? 'Moved' : 'Copied'} ${what} to “${dest.name}”`, {
          action: { label: 'Open folder', onClick: () => navigate(`/files/${encodeURIComponent(dest.id)}`) },
        });
        if (kind === 'move') ctx.onRemoved?.(nodes.filter((n) => n.parent_id !== dest.id).map((n) => n.id));
        changed({ dest: dest.id });
        refresh();
        return true;
      } catch (err) {
        // A name conflict: ask. Replace only replaces files with files, so a batch in which a folder conflicts fails
        // as a whole (409, nothing moved) — ask again then, without Replace (Skip and Keep both never answer 409).
        if (err instanceof ApiError && err.status === 409 && (conflict === 'fail' || conflict === 'replace')) {
          const choice = await conflictDialog(err.message, {
            allowReplace: conflict === 'fail' && nodes.some((n) => n.kind === 'file'),
            verb: kind,
          });
          if (!choice) return false;
          conflict = choice;
          continue;
        }
        toast.error(err);
        return false;
      }
    }
  };

  /** @param {Node[]} nodes */
  const move = async (nodes) => {
    const dest = await pickFolder({
      title: nodes.length === 1 ? `Move “${nodes[0].name}”` : `Move ${plural(nodes.length, 'item')}`,
      confirmLabel: 'Move here',
      start: ctx.folder?.() || null,
      exclude: nodes.filter(isFolder).map((n) => n.id),
    });
    if (dest) await transfer('move', nodes, dest);
  };

  /** @param {Node[]} nodes */
  const copy = async (nodes) => {
    const dest = await pickFolder({
      title: nodes.length === 1 ? `Copy “${nodes[0].name}”` : `Copy ${plural(nodes.length, 'item')}`,
      confirmLabel: 'Copy here',
      start: ctx.folder?.() || null,
      exclude: nodes.filter(isFolder).map((n) => n.id),
    });
    if (dest) await transfer('copy', nodes, dest);
  };

  /** @param {Node[]} nodes @param {boolean} on */
  const star = async (nodes, on) => {
    const results = await Promise.allSettled(nodes.map((n) => (on
      ? api.put(`/nodes/${encodeURIComponent(n.id)}/star`, {})
      : api.del(`/nodes/${encodeURIComponent(n.id)}/star`))));
    const failed = results.filter((r) => r.status === 'rejected');
    // Only the requests that succeeded change anything: a row whose unstar failed stays on the Starred page.
    const ok = nodes.filter((_, i) => results[i].status === 'fulfilled');
    ok.forEach((n) => ctx.onUpdated?.({ ...n, starred: on }));
    if (failed.length) toast.error(errorMessage(/** @type {PromiseRejectedResult} */ (failed[0]).reason));
    else toast.success(on ? (nodes.length === 1 ? 'Added to starred' : `Starred ${plural(nodes.length, 'item')}`) : 'Removed from starred', { timeout: 2500 });
    if (!ok.length) return;
    if (ctx.context === 'starred' && !on) ctx.onRemoved?.(ok.map((n) => n.id));
    events.emit('files.starred', { ids: ok.map((n) => n.id), on });
  };

  /** @param {Node[]} nodes @returns {Promise<boolean>} whether the items went to the trash */
  const trash = async (nodes) => {
    const editable = nodes.filter((n) => can(n, 'edit'));
    if (!editable.length) {
      toast.warning('You don’t have permission to delete these items.');
      return false;
    }
    const ids = editable.map((n) => n.id);
    try {
      await api.post('/nodes/trash', { ids });
      ctx.onRemoved?.(ids);
      changed();
      refresh();
      const what = editable.length === 1 ? `“${editable[0].name}”` : plural(editable.length, 'item');
      toast.show({
        kind: 'success',
        message: `Moved ${what} to the trash`,
        timeout: 8000,
        action: {
          label: 'Undo',
          onClick: async () => {
            try {
              await api.post('/trash/restore', { ids });
              toast.success('Restored', { timeout: 2500 });
              changed();
              refresh();
            } catch (err) {
              toast.error(err);
            }
          },
        },
      });
      return true;
    } catch (err) {
      toast.error(err);
      return false;
    }
  };

  /** @param {Node[]} nodes */
  const restore = async (nodes) => {
    try {
      const restored = await api.post('/trash/restore', { ids: nodes.map((n) => n.id) });
      ctx.onRemoved?.(nodes.map((n) => n.id));
      const first = Array.isArray(restored) ? restored[0] : restored?.items?.[0];
      toast.success(nodes.length === 1 ? `Restored “${nodes[0].name}”` : `Restored ${plural(nodes.length, 'item')}`, {
        action: first ? { label: 'Show', onClick: () => navigate(showInFolderHref(first)) } : undefined,
      });
      changed();
      refresh();
    } catch (err) {
      toast.error(err);
    }
  };

  /** @param {Node[]} nodes */
  const purge = async (nodes) => {
    const ok = await confirm({
      title: nodes.length === 1 ? `Delete “${nodes[0].name}” forever?` : `Delete ${plural(nodes.length, 'item')} forever?`,
      message: 'This permanently removes the items and their versions. It can’t be undone.',
      danger: true,
      confirmLabel: 'Delete forever',
    });
    if (!ok) return;
    try {
      await api.post('/trash/purge', { ids: nodes.map((n) => n.id) });
      ctx.onRemoved?.(nodes.map((n) => n.id));
      toast.success(nodes.length === 1 ? 'Deleted forever' : `Deleted ${plural(nodes.length, 'item')} forever`);
      changed();
      refresh();
    } catch (err) {
      toast.error(err);
    }
  };

  const emptyTrash = async () => {
    const ok = await confirm({
      title: 'Empty the trash?',
      message: 'Everything in the trash that you may delete permanently is deleted, including earlier versions. Items from '
        + 'group folders you don’t manage, or that you deleted in someone else’s folders, stay until their owner or a group '
        + 'manager deletes them. This can’t be undone.',
      danger: true,
      confirmLabel: 'Empty trash',
    });
    if (!ok) return false;
    try {
      await api.del('/trash');
    } catch (err) {
      toast.error(err);
      return false;
    }
    // The server deletes only what you may delete permanently (your own space, group folders you manage) and the trash
    // lists only items you may restore: whatever it still lists needs the space owner or a group manager.
    let left = 0;
    let more = false;
    try {
      const res = await api.get('/trash', { query: { limit: 500 } });
      left = itemsOf(res).length;
      more = !!res?.next_cursor;
    } catch { /* the refresh below shows the list (or its error) */ }
    if (left) {
      toast.warning(`Deleted what you may delete. ${more ? 'More than ' : ''}${plural(left, 'item')} ${left === 1 && !more ? 'stays' : 'stay'} `
        + 'in the trash: deleting them needs the space owner or a group manager.');
    } else {
      toast.success('Trash emptied');
    }
    changed();
    refresh();
    return true;
  };

  /** @param {Node} parent */
  const newFolder = async (parent) => {
    if (!can(parent, 'edit')) {
      toast.warning('You can’t create folders here.');
      return null;
    }
    let value = 'New folder';
    for (;;) {
      const name = await prompt({ title: 'New folder', label: 'Folder name', value, confirmLabel: 'Create', validate: nameError });
      if (!name) return null;
      try {
        const node = await api.post(`/nodes/${encodeURIComponent(parent.id)}/folders`, { name });
        toast.success(`Created “${node?.name || name}”`, { timeout: 2500 });
        changed({ folderId: parent.id });
        await refresh();
        if (node) ctx.onCreated?.(node);
        return node;
      } catch (err) {
        toast.error(err);
        if (!(err instanceof ApiError) || (err.status !== 409 && err.status !== 422)) return null;
        value = name;
      }
    }
  };

  /**
   * Context menu / action sheet entries for a selection.
   * @param {Node[]} nodes
   * @returns {MenuItem[]}
   */
  const menuItems = (nodes) => {
    if (!nodes.length) return [];
    const one = nodes.length === 1 ? nodes[0] : null;
    /** @type {MenuItem[]} */
    const items = [];
    if (ctx.onSelectMode && window.matchMedia('(pointer: coarse)').matches) {
      items.push({ label: 'Select', icon: 'square-check', onClick: () => ctx.onSelectMode?.(nodes) }, { divider: true });
    }
    if (ctx.context === 'trash') {
      const canEdit = nodes.every((n) => can(n, 'edit'));
      items.push(
        { label: 'Restore', icon: 'rotate-ccw', onClick: () => restore(nodes), disabled: !canEdit },
        { divider: true },
        { label: 'Delete forever', icon: 'trash', danger: true, onClick: () => purge(nodes), disabled: !nodes.every((n) => can(n, 'owner') || can(n, 'manage')) },
      );
      return items;
    }
    const allEdit = nodes.every((n) => can(n, 'edit'));
    if (one) {
      if (isFolder(one)) items.push({ label: 'Open', icon: 'folder-open', onClick: () => open(one) });
      else items.push({ label: previewKind(one) ? 'Preview' : 'Open', icon: 'eye', onClick: () => preview(one) });
      // Only for types the server really serves inline — HTML, SVG, XML and JavaScript would just download.
      if (one.kind === 'file' && previewKind(one) && opensInline(one)) {
        items.push({ label: 'Open in new tab', icon: 'external', onClick: () => window.open(contentURL(one, { inline: true }), '_blank', 'noopener') });
      }
    }
    items.push({ label: one && one.kind === 'file' ? 'Download' : 'Download as .zip', icon: 'download', onClick: () => download(nodes) });
    if (!one || isFolder(one)) items.push({ label: 'Download as .tar', icon: 'file-zip', onClick: () => download(nodes, 'tar') });
    if (one && can(one, 'manage')) items.push({ label: 'Share…', icon: 'share', onClick: () => share(one) });
    if (one && ctx.context !== 'folder' && one.parent_id) items.push({ label: 'Show in folder', icon: 'folder', onClick: () => navigate(showInFolderHref(one)) });
    items.push({ divider: true });
    if (one && can(one, 'edit')) items.push({ label: 'Rename…', icon: 'edit', onClick: () => rename(one) });
    if (allEdit) items.push({ label: 'Move to…', icon: 'move', onClick: () => move(nodes) });
    items.push({ label: 'Copy to…', icon: 'copy', onClick: () => copy(nodes) });
    const allStarred = nodes.every((n) => n.starred);
    items.push({ label: allStarred ? 'Remove from starred' : 'Add to starred', icon: 'star', onClick: () => star(nodes, !allStarred) });
    items.push({ divider: true });
    if (one && one.kind === 'file') items.push({ label: 'Versions', icon: 'history', onClick: () => details(one, 'versions') });
    if (one) items.push({ label: 'Details', icon: 'info', onClick: () => details(one, 'info') });
    if (allEdit) items.push({ divider: true }, { label: 'Move to trash', icon: 'trash', danger: true, onClick: () => trash(nodes) });
    // no dangling dividers
    return items.filter((it, i, arr) => !(it.divider && (i === 0 || i === arr.length - 1 || arr[i - 1].divider)));
  };

  return { open, preview, download, share, details, rename, move, copy, transfer, star, trash, restore, purge, emptyTrash, newFolder, menuItems };
}
