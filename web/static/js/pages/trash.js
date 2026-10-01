// @ts-check
/**
 * Trash — /trash (§13.2): items moved to the trash (GET /trash, Page[Node] with `path`), newest first. Restore
 * (POST /trash/restore), delete forever (POST /trash/purge) or empty the trash (DELETE /trash). Items are purged
 * automatically after the retention period set by the administrator (storage.trash_days).
 * @module pages/trash
 */
import { nodeListPage, fetchPage, emptyView } from '../components/node-list.js';
import { button } from '../components/button.js';

export const title = 'Trash';

/**
 * @param {HTMLElement} root
 * @param {import('../core/router.js').PageContext} ctx
 */
export function mount(root, ctx) {
  return nodeListPage(root, ctx, {
    title,
    subtitle: 'Deleted items stay here for a while before they are removed for good.',
    context: 'trash',
    columns: ['location', 'size', 'trashed'],
    sort: { key: 'trashed', desc: true },
    sortKeys: ['trashed', 'name', 'size'],
    clientSort: true,
    fetch: ({ cursor, signal }) => fetchPage('/trash', { cursor: cursor || undefined, limit: 500 }, signal),
    empty: emptyView('trash', 'The trash is empty', 'Deleted files and folders appear here. You can restore them until the trash is emptied.'),
    headerActions: ({ actions }) => [
      button({ label: 'Empty trash', icon: 'trash', variant: 'danger', onClick: () => actions.emptyTrash() }),
    ],
  });
}
