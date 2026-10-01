// @ts-check
/**
 * My links — /links (§13.2): public links the user created (GET /shares?kind=link). Copy, QR code, edit (expiry,
 * password, download limit, previews), access log, pause/resume and delete. Links are created from the Share action
 * of a file or folder.
 * @module pages/links
 */
import { sharesPage } from '../components/shares-page.js';

export const title = 'My links';

/**
 * @param {HTMLElement} root
 * @param {import('../core/router.js').PageContext} ctx
 */
export function mount(root, ctx) {
  return sharesPage(root, ctx, {
    kind: 'link',
    title,
    subtitle: 'Public links to your files and folders. Anyone with a link can open it until it expires.',
  });
}
