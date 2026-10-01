// @ts-check
/**
 * Admin → Settings (/admin/settings/:section): every runtime setting of the catalog (§11.2), grouped by section,
 * edited with the auto-generated settingsForm() plus section-specific panels (links to the pages that manage the
 * same area with more context, warnings about side effects). A page-level banner offers "Restart now" while
 * settings that need a restart are pending (GET /admin/system → restart_required; refreshed on settings.changed).
 *   GET    /admin/settings            → SettingView[]
 *   PATCH  /admin/settings {key: v}   (E for auth|network|tls|acme|mtls|keys|backup|server|mdns|email) → SettingsResult
 *   DELETE /admin/settings/{key}      reset
 *   POST   /admin/settings/email/test {to}   (owners and admins) the Email section's "Send test e-mail…" → 204
 * A 409 from the passkey guard (turning passkeys off, or renaming the passkey domain, while accounts rely on a
 * passkey alone) is confirmed in settingsForm() and retried with ?force=1.
 * The network access policy keys (network.access_mode / allow_cidrs / deny_cidrs) are edited on the Network page,
 * which applies the lockout guard (PUT /admin/network/policy); they are not repeated here.
 * GET /admin/settings lists only the keys the caller may change (DESIGN §6a: a role with "General settings",
 * "Network & VPN", "Certificates" or "Operate the server" sees its sections; administrators see everything), so the
 * section list is the sections present; /admin/settings opens the first one, and a known section the role does not
 * include renders the "not allowed" page.
 * Owned by unit J2.
 * @module pages/admin/settings
 */
import { h, icon, replace, append } from '../../core/dom.js';
import { api, itemsOf, ApiError, errorMessage } from '../../core/api.js';
import { navigate, setTitle } from '../../core/router.js';
import { isAdmin, can, currentUser } from '../../core/store.js';
import { prompt } from '../../components/dialog.js';
import { button } from '../../components/button.js';
import { toast } from '../../components/toast.js';
import { setInstanceName } from '../../nav.js';
import { forbidden, pathAllowed } from '../../routes.js';
import { settingsForm } from '../../components/settings-form.js';
import { emptyState } from '../../components/empty-state.js';
import { skeleton } from '../../components/progress.js';
import { adminHeader, errorPanel, alertEl, restartBanner, onEvents, debounce } from './common.js';

export const title = 'Settings';

/** Display names, icons and order for known sections (§11.2); unknown sections are appended alphabetically. */
const SECTIONS = /** @type {[string, string, string][]} */ ([
  ['general', 'General', 'sliders'], ['auth', 'Sign-in & security', 'shield'], ['sharing', 'Sharing', 'link'], ['storage', 'Storage', 'hard-drive'],
  ['network', 'Network', 'network'], ['mdns', 'Local name (mDNS)', 'radio'], ['tls', 'TLS', 'lock'], ['acme', 'ACME certificates', 'certificate'],
  ['tailscale', 'Tailscale', 'tailscale'], ['funnel', 'Tailscale Funnel', 'globe'], ['mtls', 'Client certificates', 'certificate'],
  ['ratelimit', 'Rate limits', 'gauge'], ['keys', 'Encryption', 'key'], ['backup', 'Backups', 'archive'], ['email', 'Email', 'mail'],
  ['audit', 'Audit', 'scroll'], ['server', 'Server', 'server'],
]);

/** Keys managed on another page (never shown in the generic form). */
const MANAGED_ELSEWHERE = new Set(['network.access_mode', 'network.allow_cidrs', 'network.deny_cidrs']);

/** Sections whose changes require step-up (§9.3; settingsapi.SensitiveSections). */
const SENSITIVE = new Set(['auth', 'network', 'tls', 'acme', 'mtls', 'keys', 'backup', 'server', 'mdns', 'email', 'tailscale', 'funnel']);

/**
 * Extra panel shown above the form of a section.
 * @param {string} section
 * @returns {Node | null}
 */
function sectionPanel(section) {
  /**
   * A button to the page that does the rest, left out when the account's role does not include that page.
   * @param {string} href @param {string} label @param {string} ic
   */
  const link = (href, label, ic) => (pathAllowed(href) ? h('a', { class: 'btn btn--secondary btn--sm', href }, icon(ic), h('span', { text: label })) : null);
  switch (section) {
    case 'network':
      return alertEl('info', 'Access policy', 'Who may connect (private networks, an allowlist or everyone) is set on the Network & VPN page, which checks that you do not lock yourself out.', link('/admin/network', 'Network & VPN', 'network'));
    case 'funnel':
      return alertEl('info', 'Tailscale Funnel and Serve', 'Turn Funnel and Serve on or off, and choose what the internet may reach, on the Network & VPN page: it checks the tailnet first. Values set there are shown read-only here.', link('/admin/network#funnel', 'Network & VPN', 'network'));
    case 'mdns':
      return h('div', { class: 'stack' },
        alertEl('warning', 'Renaming affects passkeys', 'Unless a passkey domain (RP ID) is set under Sign-in & security, the local name is also the domain passkeys are bound to: changing it makes every existing passkey stop working. The certificate is reissued for the new name.'),
        alertEl('info', 'Status and republishing', 'The current mDNS state, backend and conflicts are shown on the Network & VPN page.', link('/admin/network', 'Network & VPN', 'network')));
    case 'tls':
    case 'acme':
    case 'tailscale':
    case 'mtls':
      return alertEl('info', 'Certificates', section === 'acme'
        ? 'Use the guided setup on the Certificates page to request a certificate after saving these settings.'
        : section === 'mtls'
          ? 'Issue and revoke client certificates on the Certificates page. Requiring certificates blocks every device without one — issue yours first.'
          : 'Renew certificates, download the CA and fetch Tailscale certificates on the Certificates page.', link('/admin/certificates', 'Certificates', 'certificate'));
    case 'keys':
      return alertEl('info', 'Master key', 'Seal, unseal, rotate keys and export a recovery key on the Encryption page.', link('/admin/encryption', 'Encryption', 'key'));
    case 'backup':
      return alertEl('info', 'Backups', 'The Backups page has the schedule editor, backup identity and restore.', link('/admin/backups', 'Backups', 'archive'));
    case 'auth':
      return alertEl('warning', 'Careful with the passkey server name', 'Changing the WebAuthn RP ID makes every existing passkey stop working. Users can still sign in with their password and authenticator app.');
    case 'server':
      return alertEl('info', 'Stored in fileparcel.toml', 'These values live in the bootstrap configuration file. Ports, bind addresses and the public URL take effect after a restart. Without an mDNS name, the server name is also the local name and so the passkey domain: renaming it makes existing passkeys stop working, and the new <name>.local is announced at once — the certificate keeps the old name until the restart, after which the old <name>.local address stops working.');
    case 'storage':
      return alertEl('info', 'Quotas', 'Per-user quotas are set on each user’s page; this is the default for everyone else.', link('/admin/users', 'Users', 'users'));
    case 'email':
      // POST /admin/settings/email/test is for owners and admins (the settings it uses are theirs to change)
      return isAdmin()
        ? alertEl('info', 'Check the settings', 'Send a test e-mail with the saved settings before a real notification depends on them. Save your changes first.',
          button({ label: 'Send test e-mail…', icon: 'mail', size: 'sm', variant: 'secondary', onClick: sendTestEmail }))
        : null;
    default:
      return null;
  }
}

/** Ask for a recipient (your own address by default) and send a test e-mail with the stored SMTP settings. */
async function sendTestEmail() {
  const to = await prompt({
    title: 'Send a test e-mail',
    label: 'Send it to',
    type: 'email',
    value: String(/** @type {any} */ (currentUser())?.email || ''),
    placeholder: 'you@example.org',
    help: 'Uses the saved settings of this section.',
    confirmLabel: 'Send',
    validate: (v) => (/^[^\s@]+@[^\s@]+$/.test(v) ? null : 'Enter an e-mail address.'),
  });
  if (!to) return;
  try {
    await api.post('/admin/settings/email/test', { to });
    toast.success(`Test e-mail sent to ${to}. If it does not arrive, check the spam folder and the server log.`);
  } catch (err) {
    // 503 carries the SMTP server's answer, 422 a bad address
    toast.error(`The test e-mail could not be sent: ${errorMessage(err)}`);
  }
}

/**
 * @param {HTMLElement} root
 * @param {import('../../core/router.js').PageContext} ctx
 */
export async function mount(root, ctx) {
  root.classList.add('admin-settings');
  const header = h('div');
  const restartSlot = h('div');
  const layout = h('div', { class: 'settings-layout' });
  const nav = h('nav', { class: 'settings-nav', attrs: { 'aria-label': 'Settings sections' } });
  const body = h('div', { class: 'stack settings-main' }, skeleton(6));
  append(layout, nav, body);
  append(root, header, restartSlot, layout);

  /** @type {any[]} */
  let catalog;
  try {
    catalog = itemsOf(await api.get('/admin/settings', { signal: ctx.signal }));
  } catch (err) {
    if (err instanceof ApiError && err.aborted) return;
    adminHeader(header, { title });
    replace(body, errorPanel(err, () => location.reload(), 'Settings are unavailable'));
    return;
  }
  const sectionOf = (/** @type {any} */ s) => s.section || String(s.key).split('.')[0];
  const present = new Set(catalog.map(sectionOf));
  const known = SECTIONS.filter(([id]) => present.has(id));
  const extra = [...present].filter((id) => !SECTIONS.some(([k]) => k === id)).sort()
    .map((id) => /** @type {[string, string, string]} */ ([id, id[0].toUpperCase() + id.slice(1), 'sliders']));
  const sections = [...known, ...extra];

  let section = ctx.params.section || sections[0]?.[0] || 'general';
  if (!ctx.params.section && sections.length) navigate(`/admin/settings/${section}`, { replace: true, render: false });
  if (!sections.some(([id]) => id === section) && !isAdmin() && (sections.length || SECTIONS.some(([id]) => id === section))) {
    // a section this role includes no key of (administrators see every section, so for them it does not exist)
    root.classList.remove('admin-settings');
    replace(root);
    const page = await forbidden();
    setTitle(page.title);
    page.mount(root);
    return;
  }
  if (sections.length && !sections.some(([id]) => id === section)) {
    adminHeader(header, { title, crumbs: [] });
    replace(body, emptyState({ icon: 'sliders', title: 'Unknown settings section', text: `There is no section called “${section}”.`, action: { label: 'All settings', href: '/admin/settings' } }));
    return;
  }
  const label = sections.find(([id]) => id === section)?.[1] || section;
  setTitle(`${label} settings`);

  adminHeader(header, {
    title: label,
    subtitle: SENSITIVE.has(section)
      ? 'Changes apply immediately unless marked “Restart required”. Saving asks you to confirm your identity.'
      : 'Changes apply immediately unless marked “Restart required”.',
    crumbs: [{ label: 'Settings', href: '/admin/settings' }],
  });
  const select = h('select', { class: 'settings-nav-select', attrs: { 'aria-label': 'Settings section' } },
    sections.map(([id, text]) => h('option', { attrs: { value: id }, selected: id === section, text })));
  select.addEventListener('change', () => navigate(`/admin/settings/${select.value}`));
  replace(nav, 
    h('ul', { class: 'settings-nav-list', attrs: { role: 'list' } }, sections.map(([id, text, ic]) => h('li', null,
      h('a', { class: 'settings-nav-item', href: `/admin/settings/${id}`, attrs: { 'aria-current': id === section ? 'page' : null } }, icon(ic, { size: 18 }), h('span', { text }))))),
    select);

  if (!sections.length) {
    replace(body, emptyState({ icon: 'sliders', title: 'No settings registered', text: 'The server did not report any settings.' }));
    return;
  }

  const keys = catalog.filter((s) => sectionOf(s) === section && !MANAGED_ELSEWHERE.has(s.key)).map((s) => String(s.key));
  const refreshRestart = async () => {
    // pending restarts come from GET /admin/system ("Server status")
    if (!can('system.view')) return;
    try {
      const info = await api.get('/admin/system', { signal: ctx.signal, handle: false });
      replace(restartSlot, restartBanner(Array.isArray(info?.restart_required) ? info.restart_required : []) || '');
    } catch { /* keep the current banner */ }
  };
  const panel = sectionPanel(section);
  replace(body, 
    panel,
    keys.length
      ? h('div', { class: 'card' }, settingsForm({
        section,
        keys,
        onSaved: (res, changes) => {
          const rr = Array.isArray(res?.restart_required) ? res.restart_required : [];
          if (rr.length) replace(restartSlot, restartBanner(rr) || '');
          // ui.instance_name is not restart-flagged, so the promise above ("changes apply immediately") has to hold
          // for the page that is already open: rebrand the shell and the document title in place.
          if (changes && typeof changes['ui.instance_name'] === 'string') {
            setInstanceName(changes['ui.instance_name']);
            setTitle(`${label} settings`);
          }
          refreshRestart();
        },
      }))
      : h('p', { class: 'muted', text: 'Everything in this section is managed on its own page.' }));

  const refresh = debounce(refreshRestart, 500);
  const off = onEvents(['settings.changed'], refresh);
  refreshRestart();
  return () => {
    off();
    refresh.cancel();
    root.classList.remove('admin-settings');
  };
}
