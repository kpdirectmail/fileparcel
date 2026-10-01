// @ts-check
/**
 * Route map (§13.2). Every page is a lazily imported module exporting `title` and `mount(root, ctx)`.
 * `nav` is the sidebar item highlighted for the route. Admin routes say who may open them (DESIGN §13.5):
 *   admin: true            built-in owners and admins only (the administrator-only areas)
 *   staff: true            anyone with a server permission (the Admin landing page)
 *   perm: 'x' | ['x', 'y'] a role holding any of these permissions (owners and admins hold them all)
 * Everyone else gets the "not allowed" page (app.js guard); the navigation shows exactly the routes that pass
 * (nav.js asks routeAllowed() for each admin item). The server enforces authorization independently.
 * Public pages (/login, /invite/:token, /setup, /unlock, /trust, /s/:token) are server templates with their own
 * modules in js/public/ and are NOT part of this SPA.
 * @module routes
 */
import { isAdmin, isStaff, canAny } from './core/store.js';

/**
 * @typedef {import('./core/router.js').Route & {perm?: string | string[], staff?: boolean}} AppRoute
 */

/** Settings sections a delegate may reach: one of these permissions opens GET /admin/settings. */
const SETTINGS_PERMS = ['settings.manage', 'network.manage', 'certs.manage', 'system.manage'];

/** @type {AppRoute[]} */
export const routes = [
  // ---- workspace ----
  { path: '/files', nav: 'files', title: 'My files', load: () => import('./pages/files.js') },
  { path: '/files/:nodeId', nav: 'files', title: 'Files', load: () => import('./pages/files.js') },
  { path: '/shared', nav: 'shared', title: 'Shared with me', load: () => import('./pages/shared.js') },
  { path: '/links', nav: 'links', title: 'My links', load: () => import('./pages/links.js') },
  { path: '/requests', nav: 'requests', title: 'File requests', load: () => import('./pages/requests.js') },
  { path: '/starred', nav: 'starred', title: 'Starred', load: () => import('./pages/starred.js') },
  { path: '/recent', nav: 'recent', title: 'Recent', load: () => import('./pages/recent.js') },
  { path: '/trash', nav: 'trash', title: 'Trash', load: () => import('./pages/trash.js') },
  { path: '/activity', nav: 'activity', title: 'Activity', load: () => import('./pages/activity.js') },
  { path: '/search', nav: 'search', title: 'Search', load: () => import('./pages/search.js') },

  // ---- personal settings ----
  { path: '/settings', nav: 'settings-profile', title: 'Profile', load: () => import('./pages/settings/profile.js') },
  { path: '/settings/profile', nav: 'settings-profile', title: 'Profile', load: () => import('./pages/settings/profile.js') },
  { path: '/settings/security', nav: 'settings-security', title: 'Security', load: () => import('./pages/settings/security.js') },
  { path: '/settings/sessions', nav: 'settings-sessions', title: 'Sessions', load: () => import('./pages/settings/sessions.js') },
  { path: '/settings/tokens', nav: 'settings-tokens', title: 'API tokens', load: () => import('./pages/settings/tokens.js') },
  { path: '/settings/appearance', nav: 'settings-appearance', title: 'Appearance', load: () => import('./pages/settings/appearance.js') },
  { path: '/settings/devices', nav: 'settings-devices', title: 'Devices & app', load: () => import('./pages/settings/devices.js') },

  // ---- administration ----
  { path: '/admin', nav: 'admin', staff: true, title: 'Dashboard', load: () => import('./pages/admin/dashboard.js') },
  { path: '/admin/users', nav: 'admin-users', perm: 'users.view', title: 'Users', load: () => import('./pages/admin/users.js') },
  { path: '/admin/users/:id', nav: 'admin-users', perm: 'users.view', title: 'User', load: () => import('./pages/admin/user.js') },
  { path: '/admin/invites', nav: 'admin-invites', perm: 'invites.manage', title: 'Invites', load: () => import('./pages/admin/invites.js') },
  { path: '/admin/groups', nav: 'admin-groups', perm: 'users.view', title: 'Groups', load: () => import('./pages/admin/groups.js') },
  { path: '/admin/groups/:id', nav: 'admin-groups', perm: 'users.view', title: 'Group', load: () => import('./pages/admin/group.js') },
  { path: '/admin/roles', nav: 'admin-roles', perm: 'users.view', title: 'Roles', load: () => import('./pages/admin/roles.js') },
  { path: '/admin/roles/:id', nav: 'admin-roles', perm: 'users.view', title: 'Role', load: () => import('./pages/admin/role.js') },
  { path: '/admin/settings', nav: 'admin-settings', perm: SETTINGS_PERMS, title: 'Settings', load: () => import('./pages/admin/settings.js') },
  { path: '/admin/settings/:section', nav: 'admin-settings', perm: SETTINGS_PERMS, title: 'Settings', load: () => import('./pages/admin/settings.js') },
  { path: '/admin/network', nav: 'admin-network', perm: 'network.manage', title: 'Network & VPN', load: () => import('./pages/admin/network.js') },
  { path: '/admin/certificates', nav: 'admin-certificates', perm: 'certs.manage', title: 'Certificates', load: () => import('./pages/admin/certificates.js') },
  { path: '/admin/encryption', nav: 'admin-encryption', admin: true, title: 'Encryption', load: () => import('./pages/admin/encryption.js') },
  { path: '/admin/backups', nav: 'admin-backups', perm: 'backups.run', title: 'Backups', load: () => import('./pages/admin/backups.js') },
  { path: '/admin/audit', nav: 'admin-audit', perm: 'audit.view', title: 'Audit log', load: () => import('./pages/admin/audit.js') },
  { path: '/admin/jobs', nav: 'admin-jobs', perm: 'system.view', title: 'Jobs', load: () => import('./pages/admin/jobs.js') },
  { path: '/admin/system', nav: 'admin-system', perm: 'system.view', title: 'System', load: () => import('./pages/admin/system.js') },

  // ---- fallback ----
  { path: '*', title: 'Page not found', load: () => import('./components/placeholder.js').then((m) => m.notFoundPage) },
];

/**
 * Whether the signed-in account may open a route (see the module comment). Routes without a guard are open to
 * every signed-in account.
 * @param {AppRoute | import('./core/router.js').Route | null | undefined} r
 */
export function routeAllowed(r) {
  const x = /** @type {AppRoute | null | undefined} */ (r);
  if (!x) return true;
  if (x.admin && !isAdmin()) return false;
  if (x.staff && !isStaff()) return false;
  if (x.perm && !canAny(/** @type {string[]} */ ([]).concat(x.perm))) return false;
  return true;
}

/**
 * routeAllowed() for an in-app link ("/admin/users"). Only exact route paths are looked up, which is what the
 * navigation links are; any other path counts as allowed (the page itself decides).
 * @param {string} href
 */
export function pathAllowed(href) {
  const path = href.split(/[?#]/)[0];
  return routeAllowed(routes.find((r) => r.path === path));
}

/**
 * Page shown for a route the account may not open. It speaks of the role rather than of "administrator access": the
 * Admin area also serves accounts whose role holds only some permissions.
 */
export const forbidden = () => import('./components/placeholder.js').then((m) => ({
  title: 'Not allowed',
  /** @param {HTMLElement} root */
  mount(root) {
    m.placeholder(root, {
      title: 'Not allowed',
      icon: 'lock',
      heading: 'Your role does not include this page',
      text: 'You do not have permission to open this page. Ask an administrator if you think this is a mistake.',
      action: { label: 'Go to My files', icon: 'folder', href: '/files' },
    });
  },
}));
