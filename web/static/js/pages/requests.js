// @ts-check
/**
 * File requests — /requests (§13.2): public upload links into one of the user's folders (GET /shares?kind=request).
 * Create (folder, title, message, size limits, expiry, password, uploader name), copy/QR, access log, close/reopen and
 * delete. /requests?new=1 opens the create dialog (Upload menu → "New file request").
 * @module pages/requests
 */
import { sharesPage } from '../components/shares-page.js';

export const title = 'File requests';

/**
 * @param {HTMLElement} root
 * @param {import('../core/router.js').PageContext} ctx
 */
export function mount(root, ctx) {
  return sharesPage(root, ctx, {
    kind: 'request',
    title,
    subtitle: 'Collect files from anyone — they upload straight into a folder you choose, without an account.',
  });
}
