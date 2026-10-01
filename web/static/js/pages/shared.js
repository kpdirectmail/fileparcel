// @ts-check
/**
 * Shared with me — /shared (§13.2). Files and folders other people shared with the user through grants
 * (GET /shared-with-me, Page[Node]). Folders open in /files/<id> (with a "Shared with me" breadcrumb); files open in
 * the preview. The user's access level decides which actions are offered.
 * @module pages/shared
 */
import { nodeListPage, fetchPage, emptyView } from '../components/node-list.js';

export const title = 'Shared with me';

/**
 * @param {HTMLElement} root
 * @param {import('../core/router.js').PageContext} ctx
 */
export function mount(root, ctx) {
  return nodeListPage(root, ctx, {
    title,
    subtitle: 'Files and folders that other people have shared with you.',
    context: 'shared',
    columns: ['size', 'updated'],
    sort: { key: 'updated', desc: true },
    sortKeys: ['name', 'updated', 'size', 'kind'],
    clientSort: true,
    fetch: ({ sort, cursor, signal }) => fetchPage('/shared-with-me', { sort: sort.key, desc: sort.desc ? 1 : undefined, cursor: cursor || undefined, limit: 500 }, signal),
    empty: emptyView('folder-shared', 'Nothing shared with you yet', 'When someone gives you access to a file or folder, it shows up here.'),
  });
}
