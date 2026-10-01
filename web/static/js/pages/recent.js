// @ts-check
/**
 * Recent — /recent (§13.2): recently changed files across the user's spaces (GET /recent, a bare Node[] list,
 * newest first). "Show in folder" jumps to the item in its folder.
 * @module pages/recent
 */
import { nodeListPage, fetchPage, emptyView } from '../components/node-list.js';

export const title = 'Recent';

/**
 * @param {HTMLElement} root
 * @param {import('../core/router.js').PageContext} ctx
 */
export function mount(root, ctx) {
  return nodeListPage(root, ctx, {
    title,
    subtitle: 'Files you and your teams changed lately.',
    context: 'recent',
    columns: ['location', 'size', 'updated'],
    sort: { key: 'updated', desc: true },
    sortKeys: ['updated', 'name', 'size', 'kind'],
    clientSort: true,
    loadAll: false,
    fetch: ({ signal }) => fetchPage('/recent', { limit: 200 }, signal),
    empty: emptyView('clock', 'Nothing recent', 'Files you upload or change will appear here.'),
  });
}
