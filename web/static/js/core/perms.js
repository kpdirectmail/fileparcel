// @ts-check
/**
 * Permission names and labels of the role catalog (DESIGN §6a; internal/core/roles.go Capabilities) for the places
 * that do not load the full catalog (GET /admin/capabilities needs "View people"): the profile page, permission
 * chips before the catalog has loaded, route guards.
 *
 *   PERMISSION_LABELS['users.view']   → "View people"
 *   SERVER_PERMISSIONS                → the 13 names that open parts of the Admin area
 *   MEMBER_PERMISSIONS                → what the built-in Member role allows
 *   permissionLabel('audit.view')     → "Audit and server logs" (the name itself when unknown)
 *
 * The lists follow the catalog order and are pinned to the Go catalog by internal/web/static/perms_test.go
 * (TestJSPermissionNamesMatchCore): keep one entry per line, as string literals.
 * @module core/perms
 */

/** Every permission name → its catalog label, in catalog order. @type {Readonly<Record<string, string>>} */
export const PERMISSION_LABELS = Object.freeze({
  'shares.links': 'Create share links',
  'shares.requests': 'Create file requests',
  'users.lookup': 'Find people and roles',
  'tokens.create': 'Create API tokens',
  'users.view': 'View people',
  'users.manage': 'Manage accounts',
  'users.credentials': 'Reset sign-in',
  'invites.manage': 'Invite people',
  'groups.manage': 'Manage groups',
  'shares.manage': "Manage everyone's links",
  'settings.manage': 'General settings',
  'network.manage': 'Network & VPN',
  'certs.manage': 'Certificates',
  'backups.run': 'Run backups',
  'system.view': 'Server status',
  'system.manage': 'Operate the server',
  'audit.view': 'Audit and server logs',
});

/**
 * Server permissions: each opens part of the Admin area, and an account whose role holds one counts as staff.
 * @type {readonly string[]}
 */
export const SERVER_PERMISSIONS = Object.freeze([
  'users.view',
  'users.manage',
  'users.credentials',
  'invites.manage',
  'groups.manage',
  'shares.manage',
  'settings.manage',
  'network.manage',
  'certs.manage',
  'backups.run',
  'system.view',
  'system.manage',
  'audit.view',
]);

/**
 * What the built-in Member role allows (core.MemberCaps). A server that predates roles sends no permission list, and
 * its members hold exactly these (core/store.js can()).
 * @type {readonly string[]}
 */
export const MEMBER_PERMISSIONS = Object.freeze([
  'shares.links',
  'shares.requests',
  'users.lookup',
  'tokens.create',
]);

/**
 * Label of a permission name (the name itself for a permission this page does not know, e.g. one added by a newer
 * server).
 * @param {string} name
 */
export function permissionLabel(name) {
  return PERMISSION_LABELS[name] || name;
}

/**
 * Whether `name` is a server permission.
 * @param {string} name
 */
export function isServerPermission(name) {
  return SERVER_PERMISSIONS.includes(name);
}
