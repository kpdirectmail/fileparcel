// @ts-check
/**
 * My files / team folders / shared folders — /files and /files/:nodeId (§13.2, §13.5 "File view").
 *
 *   /files                      the personal space root (guests, who have none, go to /shared)
 *   /files/<folderId>           any folder the user can see
 *   ?preview=<fileId>           opens the preview overlay for a file in the folder
 *   ?select=<id>                selects and scrolls to an item ("Show in folder")
 *   /files/<fileId>             redirects to its folder with the preview open
 *
 * Data: GET /nodes/{id}, GET /nodes/{id}/breadcrumbs, GET /nodes/{id}/children?sort=&desc=&cursor= (all pages,
 * streamed into the virtual list as they arrive). Mutations go through components/file-actions.js; uploads land here
 * through nav.js `currentFolder` (upload/manager.js reads it). Refreshes on the in-app "files.changed" event.
 * Layout: breadcrumbs + title + actions, toolbar (count, sort, list/grid, details), selection bar, the list, and a
 * details side panel on wide screens (a dialog elsewhere). Drag rows onto a folder or a breadcrumb to move them.
 * @module pages/files
 */
import { h, icon, replace } from '../core/dom.js';
import { api, itemsOf, errorMessage, ApiError } from '../core/api.js';
import { navigate, setTitle } from '../core/router.js';
import { events, persisted, session } from '../core/store.js';
import { register } from '../core/keys.js';
import { plural, number } from '../core/format.js';
import { can, spaces as loadSpaces, spaceLabel, homeSpace, nodeHref } from '../core/nodes.js';
import { fileView, acceptNodeDrop } from '../components/file-view.js';
import { fileActions } from '../components/file-actions.js';
import { nodeDetails, openDetailsDialog } from '../components/details-panel.js';
import { selectionBar, sortButton, viewToggle, viewPref } from '../components/node-list.js';
import { emptyState } from '../components/empty-state.js';
import { button, iconButton } from '../components/button.js';
import { menu } from '../components/menu.js';
import { toast } from '../components/toast.js';
import { skeleton } from '../components/progress.js';
import { currentFolder, navOverride, triggerUpload } from '../nav.js';

export const title = 'My files';

/**
 * @typedef {import('../core/nodes.js').Node} Node
 * @typedef {import('../core/nodes.js').Space} Space
 */

const sortPref = persisted('sort-folder', { key: 'name', desc: false });
const detailsPref = persisted('files-details', false);
const WIDE = '(min-width: 1200px)';

/**
 * @param {HTMLElement} root
 * @param {import('../core/router.js').PageContext} ctx
 */
export async function mount(root, ctx) {
  const { signal } = ctx;
  /** @type {(() => void)[]} */
  const cleanups = [];
  const sort = { key: 'name', desc: false, ...(sortPref.peek() || {}) };
  if (!['name', 'updated', 'size', 'kind'].includes(sort.key)) Object.assign(sort, { key: 'name', desc: false });

  /** @type {Node | null} */
  let folder = null;
  /** @type {Node[]} */
  let crumbs = [];
  /** @type {Node[]} */
  let items = [];
  /** @type {Space[]} */
  let spaceList = [];
  /** @type {Space | null} */
  let space = null;
  let seq = 0;
  let complete = false;
  let pendingSelect = '';
  /** @type {{el: HTMLElement, destroy: () => void} | null} */
  let detailsView = null;
  let detailsTimer = 0;

  root.classList.add('files-page');
  const crumbsEl = h('nav', { class: 'breadcrumbs files-crumbs', attrs: { 'aria-label': 'Folder path' } });
  const titleEl = h('h1', { class: 'page-title files-title', attrs: { tabindex: '-1' } });
  const headActions = h('div', { class: 'page-actions files-head-actions' });
  const countEl = h('span', { class: 'files-count muted text-sm', attrs: { 'aria-live': 'polite' } });
  const aside = h('aside', { class: 'files-aside', attrs: { 'aria-label': 'Details' }, hidden: true });
  const errorSlot = h('div');
  const wideMq = window.matchMedia(WIDE);

  // ---------------------------------------------------------------- actions
  const actions = fileActions({
    context: 'folder',
    items: () => items,
    folder: () => folder,
    refresh: () => loadChildren(true),
    onRemoved: (ids) => {
      const gone = new Set(ids);
      items = items.filter((n) => !gone.has(n.id));
      fv.setItems(items, { keepCursor: true });
      updateCount();
    },
    onUpdated: (n) => {
      items = items.map((x) => (x.id === n.id ? { ...x, ...n } : x));
      fv.update(n);
      scheduleDetails();
    },
    onCreated: (n) => fv.select([n.id], { focus: true }),
    onDetails: (n, tab) => openDetails(n, tab),
    onSelectMode: (nodes) => {
      fv.select(nodes.map((n) => n.id));
      fv.setSelecting(true);
    },
  });

  const selbar = selectionBar({ actions, context: 'folder', onClear: () => fv.setSelecting(false) });

  const fv = fileView({
    mode: viewPref.peek(),
    columns: ['size', 'updated'],
    sort,
    label: 'Folder contents',
    onSort: (k, d) => {
      sort.key = k;
      sort.desc = d;
      sortPref.value = { key: k, desc: d };
      sortBtn.sync();
      loadChildren(false);
    },
    onOpen: (n) => actions.open(n),
    menuItems: (nodes) => actions.menuItems(nodes),
    backgroundMenu: () => (folder ? folderMenuItems(true) : null),
    onDelete: (nodes) => actions.trash(nodes),
    onRename: (n) => { if (can(n, 'edit')) actions.rename(n); },
    onDrop: (nodes, dest) => { actions.transfer('move', nodes, dest); },
    onSelectionChange: (nodes) => {
      selbar.update(nodes);
      scheduleDetails();
    },
    empty: () => emptyFolder(),
  });

  const sortBtn = sortButton(sort, ['name', 'updated', 'size', 'kind'], (k, d) => {
    sortPref.value = { key: k, desc: d };
    fv.setSort(k, d);
    loadChildren(false);
  });
  const toggle = viewToggle(viewPref.peek(), (m) => {
    viewPref.value = m;
    fv.setMode(m);
  });
  const detailsBtn = iconButton({
    icon: 'info',
    label: 'Details (i)',
    size: 'sm',
    pressed: !!detailsPref.peek(),
    class: 'files-details-btn hide-sm',
    onClick: () => toggleDetails(),
  });

  const head = h('header', { class: 'page-header files-head' },
    h('div', { class: 'page-header-text' }, crumbsEl, titleEl),
    headActions);
  const toolbar = h('div', { class: 'files-toolbar' }, countEl, h('div', { class: 'grow' }), sortBtn, toggle, detailsBtn);
  const body = h('div', { class: 'files-body' }, h('div', { class: 'files-main' }, errorSlot, fv.el), aside);
  root.append(head, toolbar, body, selbar.el);
  titleEl.replaceChildren(skeleton(1));
  const outletEl = /** @type {HTMLElement | null} */ (root.closest('.app-outlet'));
  if (outletEl) outletEl.dataset.wide = ''; // the file browser uses the full width (details panel)

  // ---------------------------------------------------------------- header
  /** Label for a crumb: the space name for a space root. @param {Node} n */
  const crumbLabel = (n) => {
    if (!n.parent_id) {
      const sp = spaceList.find((s) => s.id === n.space_id);
      if (sp) return spaceLabel(sp);
    }
    return n.name;
  };

  const renderHeader = () => {
    if (!folder) return;
    const f = folder;
    const isRoot = !f.parent_id;
    const name = crumbLabel(f);
    titleEl.textContent = name;
    setTitle(name);
    const list = crumbs.filter((c) => c.id !== f.id);
    const shared = space ? !isMine(space) && space.kind === 'user' : false;
    /** @type {HTMLElement[]} */
    const lis = [];
    if (shared) lis.push(h('li', null, h('a', { href: '/shared', text: 'Shared with me' })));
    for (const c of list) {
      const a = h('a', { href: `/files/${encodeURIComponent(c.id)}`, title: crumbLabel(c), text: crumbLabel(c) });
      if (can(c, 'edit') || c.perm === undefined) {
        cleanups.push(acceptNodeDrop(a, (ids) => {
          const nodes = ids.map((id) => items.find((x) => x.id === id)).filter(Boolean);
          if (nodes.length) actions.transfer('move', /** @type {Node[]} */ (nodes), c);
        }));
      }
      lis.push(h('li', null, a));
    }
    lis.push(h('li', null, h('span', { attrs: { 'aria-current': 'page' }, text: name })));
    crumbsEl.replaceChildren(h('ol', { attrs: { role: 'list' } }, lis));
    crumbsEl.hidden = lis.length < 2;
    crumbsEl.scrollLeft = crumbsEl.scrollWidth; // phones scroll the trail: show its end (this folder and its parents)

    const editable = can(f, 'edit');
    replace(headActions,
      editable ? button({ label: 'New folder', icon: 'folder-plus', variant: 'secondary', class: 'hide-sm', onClick: () => actions.newFolder(f) }) : null,
      can(f, 'manage') && !isRoot ? button({ label: 'Share', icon: 'share', variant: 'secondary', class: 'hide-sm', onClick: () => actions.share(f) }) : null,
      iconButton({
        icon: 'more-vertical',
        label: 'Folder actions',
        attrs: { 'aria-haspopup': 'menu' },
        onClick: (e) => menu({ anchor: /** @type {HTMLElement} */ (e.currentTarget), title: name, items: folderMenuItems(false) }),
      }));
    if (!editable) headActions.prepend(h('span', { class: 'badge files-ro', attrs: { title: 'You can view and download, but not change this folder' } }, icon('eye', { size: 12 }), 'View only'));
  };

  /** @param {Space} s */
  const isMine = (s) => s.kind === 'group' || !s.owner_user_id || s.owner_user_id === session.peek()?.user?.id;

  /**
   * Actions for the current folder (header ⋮ and right-click on empty space).
   * @param {boolean} background
   * @returns {import('../components/menu.js').MenuItem[]}
   */
  function folderMenuItems(background) {
    const f = /** @type {Node} */ (folder);
    const editable = can(f, 'edit');
    const isRoot = !f.parent_id;
    /** @type {import('../components/menu.js').MenuItem[]} */
    const list = [];
    if (editable) {
      list.push(
        { label: 'Upload files', icon: 'upload', onClick: () => triggerUpload('files') },
        { label: 'New folder', icon: 'folder-plus', onClick: () => actions.newFolder(f) },
      );
      if (can(f, 'manage')) list.push({ label: 'New file request here', icon: 'inbox', onClick: () => triggerUpload('new-request') });
      list.push({ divider: true });
    }
    if (background) {
      list.push({ label: 'Select all', icon: 'square-check', onClick: () => fv.selectAll(), disabled: !items.length });
      list.push({ label: 'Refresh', icon: 'refresh', onClick: () => loadChildren(true) });
      return list;
    }
    list.push(
      { label: 'Download as .zip', icon: 'download', onClick: () => actions.download([f]) },
      { label: 'Download as .tar', icon: 'file-zip', onClick: () => actions.download([f], 'tar') },
    );
    if (can(f, 'manage')) list.push({ label: 'Share…', icon: 'share', onClick: () => actions.share(f) });
    if (!isRoot && editable) {
      list.push({ divider: true }, { label: 'Rename…', icon: 'edit', onClick: () => actions.rename(f) }, { label: 'Move to…', icon: 'move', onClick: () => actions.move([f]) });
    }
    list.push({ label: 'Details', icon: 'info', onClick: () => openDetails(f, 'info') });
    if (!isRoot && editable) list.push({ divider: true }, { label: 'Move to trash', icon: 'trash', danger: true, onClick: () => trashCurrent() });
    return list;
  }

  async function trashCurrent() {
    const f = /** @type {Node} */ (folder);
    const up = parentHref();
    if ((await actions.trash([f])) && up) navigate(up, { replace: true });
  }

  /**
   * Where "up" leads: the previous crumb. The trail of a folder reached through a grant starts at the highest granted
   * folder, whose parent_id names the owner's folder the viewer cannot open — "up" from there is Shared with me.
   * @returns {string} '' at a space root
   */
  function parentHref() {
    const f = folder;
    if (!f?.parent_id) return '';
    const i = crumbs.findIndex((c) => c.id === f.id);
    if (i > 0) return `/files/${encodeURIComponent(crumbs[i - 1].id)}`;
    if (i === 0) return '/shared';
    return `/files/${encodeURIComponent(f.parent_id)}`; // no trail (GET …/breadcrumbs failed): best effort
  }

  function emptyFolder() {
    const f = folder;
    if (!f) return emptyState({ icon: 'folder', title: 'Nothing here' });
    if (!can(f, 'edit')) return emptyState({ icon: 'folder-open', title: 'This folder is empty', text: 'Nothing has been added here yet.' });
    return h('div', { class: 'files-empty' },
      emptyState({
        icon: 'cloud-upload',
        title: 'Drop files here',
        text: 'Drag files or folders anywhere on this page, or use the buttons below. Everything is encrypted before it is stored.',
        action: h('div', { class: 'cluster files-empty-actions' },
          button({ label: 'Upload files', icon: 'upload', variant: 'primary', onClick: () => triggerUpload('files') }),
          button({ label: 'New folder', icon: 'folder-plus', variant: 'secondary', onClick: () => actions.newFolder(f) })),
      }));
  }

  const updateCount = () => {
    const folders = items.filter((n) => n.kind === 'folder').length;
    const files = items.length - folders;
    const parts = [];
    if (folders) parts.push(plural(folders, 'folder'));
    if (files || !folders) parts.push(plural(files, 'file'));
    countEl.textContent = complete ? parts.join(', ') : `${number(items.length)}…`;
  };

  // ---------------------------------------------------------------- details panel
  /** @param {Node | Node[] | null} target @param {import('../components/details-panel.js').DetailsTab} [tab] */
  const renderDetails = (target, tab) => {
    detailsView?.destroy();
    detailsView = nodeDetails(target, {
      tab,
      onClose: () => toggleDetails(false),
      onShare: (n) => actions.share(n),
      onStar: (n, on) => actions.star([n], on),
      onChanged: () => loadChildren(true),
      emptyText: 'Select a file or folder to see its details, versions and sharing.',
    });
    aside.replaceChildren(detailsView.el);
  };
  const scheduleDetails = () => {
    if (aside.hidden) return;
    clearTimeout(detailsTimer);
    detailsTimer = window.setTimeout(() => {
      const sel = fv.selected();
      renderDetails(sel.length ? (sel.length === 1 ? sel[0] : sel) : folder);
    }, 120);
  };
  /** @param {boolean} [on] */
  const toggleDetails = (on) => {
    const next = on ?? aside.hidden;
    if (!wideMq.matches) {
      if (next) {
        const sel = fv.selected();
        openDetailsDialog(sel.length ? (sel.length === 1 ? sel[0] : sel) : /** @type {Node} */ (folder), {
          onShare: (n) => actions.share(n),
          onStar: (n, on2) => actions.star([n], on2),
          onChanged: () => loadChildren(true),
        });
      }
      return;
    }
    detailsPref.value = next;
    aside.hidden = !next;
    body.toggleAttribute('data-details', next);
    detailsBtn.setAttribute('aria-pressed', String(next));
    if (next) scheduleDetails();
    else {
      detailsView?.destroy();
      detailsView = null;
      aside.replaceChildren();
    }
  };
  /** @param {Node} n @param {import('../components/details-panel.js').DetailsTab} tab */
  function openDetails(n, tab) {
    if (wideMq.matches) {
      if (aside.hidden) toggleDetails(true);
      clearTimeout(detailsTimer);
      renderDetails(n, tab);
    } else {
      openDetailsDialog(n, { tab, onShare: (x) => actions.share(x), onStar: (x, on) => actions.star([x], on), onChanged: () => loadChildren(true) });
    }
  }
  const onWide = () => {
    if (wideMq.matches && detailsPref.peek()) toggleDetails(true);
    else if (!wideMq.matches && !aside.hidden) {
      aside.hidden = true;
      body.removeAttribute('data-details');
    }
  };
  wideMq.addEventListener('change', onWide);
  cleanups.push(() => wideMq.removeEventListener('change', onWide));

  // ---------------------------------------------------------------- loading
  /** @param {unknown} err */
  const showError = (err) => {
    const notFound = err instanceof ApiError && (err.status === 404 || err.status === 403);
    titleEl.textContent = notFound ? 'Folder not found' : 'Something went wrong';
    setTitle(titleEl.textContent);
    crumbsEl.hidden = true;
    headActions.replaceChildren();
    toolbar.hidden = true;
    fv.el.hidden = true;
    errorSlot.replaceChildren(emptyState({
      icon: notFound ? 'folder' : 'alert-triangle',
      title: notFound ? 'This folder doesn’t exist or you don’t have access' : 'Could not open this folder',
      text: notFound ? 'It may have been moved, deleted or unshared.' : errorMessage(err),
      action: notFound ? { label: 'Go to My files', icon: 'folder', href: '/files' } : { label: 'Try again', icon: 'refresh', onClick: () => start() },
    }));
  };

  /** @param {boolean} keep */
  async function loadChildren(keep) {
    if (!folder) return;
    const my = ++seq;
    const id = folder.id;
    if (!keep) {
      fv.setLoading();
      complete = false;
      countEl.textContent = '';
    }
    try {
      /** @type {Node[]} */
      let all = [];
      let cursor = '';
      let first = true;
      do {
        const res = await api.get(`/nodes/${encodeURIComponent(id)}/children`, {
          query: { sort: sort.key, desc: sort.desc ? 1 : undefined, limit: first ? 200 : 500, cursor: cursor || undefined },
          signal,
        });
        if (my !== seq) return;
        all = all.concat(itemsOf(res));
        cursor = Array.isArray(res) ? '' : res?.next_cursor || '';
        complete = !cursor;
        // a fresh load streams pages into the list; a refresh swaps the list once, when it is complete
        if (!keep) {
          items = all;
          fv.setItems(items, { keepCursor: !first });
          updateCount();
        }
        first = false;
      } while (cursor);
      if (my !== seq) return;
      items = all;
      fv.setItems(items, { keepCursor: true });
      updateCount();
      if (pendingSelect && items.some((n) => n.id === pendingSelect)) fv.select([pendingSelect], { focus: true });
      pendingSelect = '';
      scheduleDetails();
    } catch (err) {
      if (err instanceof ApiError && err.aborted) return;
      if (my !== seq) return;
      if (!keep) showError(err);
      else toast.error(err);
    }
  }

  async function start() {
    errorSlot.replaceChildren();
    toolbar.hidden = false;
    fv.el.hidden = false;
    try {
      spaceList = await loadSpaces();
      let id = ctx.params.nodeId || '';
      if (!id) {
        const home = await homeSpace();
        if (!home || !home.root_id) {
          navigate('/shared', { replace: true });
          return;
        }
        id = home.root_id;
      }
      const [node, bc] = await Promise.all([
        api.get(`/nodes/${encodeURIComponent(id)}`, { signal }),
        api.get(`/nodes/${encodeURIComponent(id)}/breadcrumbs`, { signal }).catch(() => []),
      ]);
      if (signal.aborted) return;
      if (node.kind === 'file') {
        navigate(nodeHref(node), { replace: true });
        return;
      }
      folder = node;
      crumbs = itemsOf(bc);
      space = spaceList.find((s) => s.id === node.space_id) || null;
      currentFolder.value = { id: node.id, name: crumbLabel(node), perm: node.perm };
      navOverride.value = space && space.kind === 'group' ? `team:${space.id}` : space && !isMine(space) ? 'shared' : !space ? 'shared' : '';
      renderHeader();
      if (detailsPref.peek() && wideMq.matches) toggleDetails(true);
      await loadChildren(false);
      afterLoad();
    } catch (err) {
      if (err instanceof ApiError && err.aborted) return;
      showError(err);
    }
  }

  /** Apply ?preview= / ?select= once the list is there. */
  function afterLoad() {
    const q = new URLSearchParams(location.search);
    const sel = q.get('select');
    const pv = q.get('preview');
    if (sel || pv) {
      q.delete('select');
      q.delete('preview');
      const rest = q.toString();
      history.replaceState(history.state, '', location.pathname + (rest ? `?${rest}` : ''));
    }
    if (sel) {
      if (items.some((n) => n.id === sel)) fv.select([sel], { focus: true });
      else toast.info('That item is no longer in this folder.');
    }
    if (pv) {
      const n = items.find((x) => x.id === pv);
      if (n) actions.preview(n);
      else {
        api.get(`/nodes/${encodeURIComponent(pv)}`, { signal, handle: false })
          .then((node) => { if (node?.kind === 'file') actions.preview(node); })
          .catch(() => toast.info('That file is no longer available.'));
      }
    }
  }

  // ---------------------------------------------------------------- events & shortcuts
  let refreshTimer = 0;
  cleanups.push(events.on('files.changed', (d) => {
    const fid = d?.folderId || '';
    // another folder changed: our list is unaffected (items moved away were already removed optimistically)
    if (fid && folder && fid !== folder.id && d?.dest !== folder.id) return;
    if (d?.created) pendingSelect = d.created;
    clearTimeout(refreshTimer);
    refreshTimer = window.setTimeout(() => loadChildren(true), 200);
  }));
  cleanups.push(events.on('upload.batch_done', (d) => {
    const b = d?.batch || d;
    if (!folder || (b?.folder_id && b.folder_id !== folder.id)) return;
    clearTimeout(refreshTimer);
    refreshTimer = window.setTimeout(() => loadChildren(true), 200);
  }));
  cleanups.push(register('v', () => {
    const m = viewPref.peek() === 'grid' ? 'list' : 'grid';
    viewPref.value = m;
    fv.setMode(m);
    for (const x of toggle.children) x.setAttribute('aria-pressed', String(/** @type {HTMLElement} */ (x).dataset.mode === m));
  }, { description: 'Switch between list and grid', group: 'Files' }));
  cleanups.push(register('i', () => toggleDetails(), { description: 'Show or hide details', group: 'Files' }));
  cleanups.push(register('alt+ArrowUp', () => {
    const up = parentHref();
    if (up) navigate(up);
  }, { description: 'Go to the parent folder', group: 'Files' }));
  cleanups.push(register('Backspace', () => {
    const up = parentHref();
    if (up) navigate(up);
  }, { group: 'Files' }));
  cleanups.push(register('mod+a', () => fv.selectAll(), { group: 'Files' }));
  cleanups.push(register('Escape', () => fv.setSelecting(false), { when: () => fv.selected().length > 0 }));

  await start();

  return () => {
    seq += 1;
    clearTimeout(refreshTimer);
    clearTimeout(detailsTimer);
    for (const c of cleanups) c();
    detailsView?.destroy();
    fv.destroy();
    currentFolder.value = null;
    navOverride.value = '';
    document.documentElement.removeAttribute('data-selbar');
  };
}
