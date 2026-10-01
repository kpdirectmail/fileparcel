// @ts-check
/**
 * Starred — /starred (§13.2): the user's starred files and folders (GET /starred, Page[Node]). Un-starring removes
 * the item from the list.
 * @module pages/starred
 */
import { nodeListPage, fetchPage, emptyView } from '../components/node-list.js';

export const title = 'Starred';

/**
 * @param {HTMLElement} root
 * @param {import('../core/router.js').PageContext} ctx
 */
export function mount(root, ctx) {
  return nodeListPage(root, ctx, {
    title,
    subtitle: 'Quick access to the files and folders you use most.',
    context: 'starred',
    columns: ['location', 'size', 'updated'],
    sort: { key: 'name', desc: false },
    sortKeys: ['name', 'updated', 'size', 'kind'],
    clientSort: true,
    fetch: ({ sort, cursor, signal }) => fetchPage('/starred', { sort: sort.key, desc: sort.desc ? 1 : undefined, cursor: cursor || undefined, limit: 500 }, signal),
    empty: emptyView('star', 'No starred items', 'Star files and folders from their menu (⋮) to find them here quickly.'),
  });
}
