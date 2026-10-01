// @ts-check
/**
 * Admin → Certificates (/admin/certificates): which certificates serve HTTPS, the local server certificate (SANs,
 * expiry, renew), the local CA (download, fingerprint, name constraints, regenerate), a custom certificate
 * (upload/remove), ACME / Let's Encrypt (guided setup + request), Tailscale certificates (toggle, fetch, operator hint)
 * and client certificates for mTLS (mode, issue a one-time .p12, list, revoke).
 *
 *   GET    /admin/certs                    → CertStatus
 *   POST   /admin/certs/renew {force}      renew the local leaf
 *   POST   /admin/certs/ca/regenerate {unconstrained?} (E)
 *   PUT    /admin/certs/custom {cert_pem, key_pem} (E) · DELETE /admin/certs/custom (E)
 *   POST   /admin/certs/acme/apply (E)     · POST /admin/certs/tailscale/fetch
 *   GET    /admin/client-certs             → Page[ClientCert]
 *   POST   /admin/client-certs (E)         ClientCertInput → PKCS#12 once (see common.issueClientCert)
 *   DELETE /admin/client-certs/{id}?reason=
 *   GET/PATCH /admin/settings              acme.*, tailscale.*, mtls.*, tls.* values
 *   GET    /trust/ca.crt|ca.pem|ca.mobileconfig (root, public)
 * Refreshes on certs.changed.
 * The page needs "Certificates"; uploading or removing a custom certificate stays with administrators (whoever
 * uploads one knows the private key of the served certificate), so a role sees it read-only.
 * Owned by unit J2.
 * @module pages/admin/certificates
 */
import { h, icon, replace, append } from '../../core/dom.js';
import { api, ApiError, itemsOf, errorMessage } from '../../core/api.js';
import { isAdmin } from '../../core/store.js';
import { dateTime } from '../../core/format.js';
import { button } from '../../components/button.js';
import { badge } from '../../components/badge.js';
import { card } from '../../components/card.js';
import { table } from '../../components/table.js';
import { toast } from '../../components/toast.js';
import { confirm, prompt } from '../../components/dialog.js';
import { field, select, toggle } from '../../components/field.js';
import { copyField } from '../../components/copy-field.js';
import { skeleton } from '../../components/progress.js';
import {
  adminHeader, errorPanel, alertEl, kv, chips, expiryBadge, timeEl, formDialog, userPicker, issueClientCert, showP12Password,
  moreMenu, onEvents, debounce,
} from './common.js';
import { generatePassword } from '../../public/password-strength.js';

export const title = 'Certificates';

/**
 * @param {HTMLElement} root
 * @param {import('../../core/router.js').PageContext} ctx
 */
export async function mount(root, ctx) {
  adminHeader(root, {
    title,
    subtitle: 'HTTPS certificates for the server and client certificates for devices.',
    actions: [
      h('a', { class: 'btn btn--secondary', href: '/trust', attrs: { 'data-native': true, target: '_blank', rel: 'noopener' } }, icon('external'), h('span', { text: 'Trust page' })),
      button({ label: 'Refresh', icon: 'refresh', variant: 'ghost', onClick: () => load() }),
    ],
  });
  const overviewBody = h('div', { class: 'stack' }, skeleton(3));
  const leafBody = h('div', { class: 'stack' }, skeleton(4));
  const caBody = h('div', { class: 'stack' }, skeleton(4));
  const customBody = h('div', { class: 'stack' }, skeleton(2));
  const acmeBody = h('div', { class: 'stack' }, skeleton(3));
  const tsBody = h('div', { class: 'stack' }, skeleton(2));
  const mtlsBody = h('div', { class: 'stack' }, skeleton(4));
  const tsCard = card({ title: 'Tailscale certificate', body: tsBody });
  tsCard.id = 'tailscale';
  const mtlsCard = card({ title: 'Client certificates (mTLS)', body: mtlsBody });
  mtlsCard.id = 'client-certificates';
  append(root, 
    card({ title: 'Overview', body: overviewBody }),
    h('div', { class: 'settings-grid' },
      h('div', { class: 'stack' }, card({ title: 'Server certificate (local CA)', body: leafBody }), card({ title: 'Custom certificate', body: customBody }), tsCard),
      h('div', { class: 'stack' }, card({ title: 'Certificate authority', body: caBody }), card({ title: 'Let’s Encrypt / ACME', body: acmeBody }))),
    mtlsCard);

  /** @type {any} */
  let st = {};
  /** @type {Record<string, any>} */
  let settings = {};

  const load = async () => {
    const [s, cat] = await Promise.allSettled([
      api.get('/admin/certs', { signal: ctx.signal }),
      api.get('/admin/settings', { signal: ctx.signal, handle: false }),
    ]);
    if (ctx.signal.aborted) return;
    if (cat.status === 'fulfilled') {
      settings = {};
      for (const v of itemsOf(cat.value)) settings[v.key] = v;
    }
    if (s.status === 'rejected') {
      if (s.reason instanceof ApiError && s.reason.aborted) return;
      replace(overviewBody, errorPanel(s.reason, load, 'Certificate status is unavailable'));
      for (const b of [leafBody, caBody, customBody, acmeBody, tsBody]) replace(b);
    } else {
      st = s.value || {};
      drawOverview();
      drawLeaf();
      drawCA();
      drawCustom();
      drawACME();
      drawTailscale();
    }
    drawMTLS();
  };

  /** @param {string} key */
  const setting = (key) => settings[key]?.value;

  /**
   * PATCH /admin/settings (elevation is prompted automatically for sensitive sections).
   * @param {Record<string, any>} changes
   */
  const saveSettings = async (changes) => {
    const res = await api.patch('/admin/settings', changes);
    const rr = Array.isArray(res?.restart_required) ? res.restart_required : [];
    if (rr.length) toast.warning(`Restart required for ${rr.join(', ')}`);
    return res;
  };

  // ------------------------------------------------------------------------------------------ overview
  const drawOverview = () => {
    /** @type {[string, any, string, string][]} */
    const sources = [['Local CA', st.leaf, 'local', 'Covers .local names, IP addresses and VPN names. Browsers trust it after the CA is installed.']];
    if (st.custom) sources.push(['Custom', st.custom, 'custom', `Used for ${(st.custom.dns_names || []).join(', ') || 'its names'}.`]);
    for (const a of st.acme || []) sources.push(['ACME', a, 'acme', `Publicly trusted certificate for ${(a.dns_names || []).join(', ')}.`]);
    if (st.tailscale) sources.push(['Tailscale', st.tailscale, 'tailscale', `Publicly trusted certificate for ${(st.tailscale.dns_names || []).join(', ')}.`]);
    replace(overviewBody, 
      h('div', { class: 'cluster' },
        st.publicly_trusted ? badge({ text: 'Publicly trusted', kind: 'success', icon: 'shield-check' }) : badge({ text: 'Local CA — install on devices', kind: 'info', icon: 'shield' }),
        badge({ text: st.hsts ? 'HSTS on' : 'HSTS off', kind: st.hsts ? 'success' : 'neutral', title: 'Strict-Transport-Security' }),
        badge({ text: `Client certificates: ${st.mtls_mode || 'off'}`, kind: st.mtls_mode === 'required' ? 'warning' : 'neutral', icon: 'certificate' })),
      h('ul', { class: 'item-list', attrs: { role: 'list' } }, sources.filter(([, c]) => c).map(([label, c, kind, text]) => h('li', { class: 'item-row' },
        h('span', { class: 'item-row-icon', attrs: { 'aria-hidden': 'true' } }, icon(kind === 'tailscale' ? 'tailscale' : 'certificate')),
        h('div', { class: 'item-row-main' },
          h('span', { class: 'item-row-title' }, label, expiryBadge(c.not_after)),
          h('span', { class: 'item-row-sub', text }))))),
      h('p', { class: 'subtle text-xs', text: 'For each connection the server picks the certificate that matches the name in the address bar: ACME and custom names first, then the Tailscale name, then the local certificate.' }));
  };

  // ------------------------------------------------------------------------------------------ leaf
  const drawLeaf = () => {
    const l = st.leaf;
    if (!l) {
      replace(leafBody, alertEl('warning', 'No local server certificate', 'Run “fileparcel init” or renew below.'), renewBtn());
      return;
    }
    replace(leafBody, 
      h('div', { class: 'cluster' }, expiryBadge(l.not_after)),
      kv([
        ['Subject', l.subject],
        ['Names', chips(l.dns_names, { max: 12 })],
        ['Addresses', chips(l.ips, { max: 12 })],
        ['Valid', `${dateTime(l.not_before)} – ${dateTime(l.not_after)}`],
        ['Serial', h('span', { class: 'mono text-xs break', text: l.serial })],
        ['SHA-256', h('span', { class: 'mono text-xs break', text: l.fingerprint })],
      ]),
      h('p', { class: 'muted text-sm', text: 'Renewed automatically 30 days before it expires and whenever the server’s names or addresses change.' }),
      h('div', { class: 'btn-row btn-row--start' },
        renewBtn(),
        h('a', { class: 'btn btn--ghost', href: '/admin/settings/tls' }, icon('plus'), h('span', { text: 'Extra names' }))));
  };

  const renewBtn = () => button({
    label: 'Renew now',
    icon: 'refresh',
    onClick: async () => {
      try {
        await api.post('/admin/certs/renew', { force: true });
        toast.success('Server certificate renewed');
        await load();
      } catch (err) {
        toast.error(err);
      }
    },
  });

  // ------------------------------------------------------------------------------------------ CA
  const drawCA = () => {
    const ca = st.ca;
    if (!ca) {
      replace(caBody, alertEl('warning', 'No local CA', 'The certificate authority is created by “fileparcel init”.'));
      return;
    }
    replace(caBody, 
      h('div', { class: 'cluster' }, expiryBadge(ca.not_after, 180),
        st.ca_constrained ? badge({ text: 'Restricted to local names', kind: 'success', icon: 'lock' }) : badge({ text: 'Unrestricted', kind: 'warning', icon: 'alert-triangle' })),
      kv([
        ['Name', ca.subject],
        ['Valid until', dateTime(ca.not_after)],
        ['Allowed names', st.ca_constrained ? chips(st.permitted_dns, { max: 10 }) : 'any'],
        ['Allowed addresses', st.ca_constrained ? chips(st.permitted_ips, { max: 10 }) : 'any'],
        // Names the CA may not sign are stored but left out of the leaf; say so
        // here instead of leaving the drop to the server log (GET /admin/certs
        // → uncovered_names).
        ...(Array.isArray(st.uncovered_names) && st.uncovered_names.length
          ? [['Not covered by the certificate', chips(st.uncovered_names, { max: 10 })]]
          : []),
      ]),
      copyField({ label: 'SHA-256 fingerprint', value: ca.fingerprint || '', what: 'Fingerprint', help: 'Compare it on each device before trusting the CA.' }),
      h('div', { class: 'btn-row btn-row--start' },
        h('a', { class: 'btn btn--secondary btn--sm', href: '/trust/ca.crt', attrs: { download: '', 'data-native': true } }, icon('download'), h('span', { text: 'ca.crt' })),
        h('a', { class: 'btn btn--secondary btn--sm', href: '/trust/ca.pem', attrs: { download: '', 'data-native': true } }, icon('download'), h('span', { text: 'ca.pem' })),
        h('a', { class: 'btn btn--secondary btn--sm', href: '/trust/ca.mobileconfig', attrs: { download: '', 'data-native': true } }, icon('smartphone'), h('span', { text: 'Apple profile' }))),
      h('details', { class: 'auth-details' },
        h('summary', { text: 'Regenerate the certificate authority' }),
        h('div', { class: 'stack-sm' },
          h('p', { text: 'Creates a new CA and server certificate. Every device that trusted the old CA shows warnings until the new one is installed. Do this only if the CA key may have leaked.' }),
          h('div', null, button({ label: 'Regenerate CA…', icon: 'rotate', variant: 'danger', size: 'sm', onClick: regenerateCA })))));
  };

  const regenerateCA = async () => {
    const constrained = toggle({
      label: 'Restrict to local names (recommended)',
      name: 'constrained',
      checked: st.ca_constrained !== false,
      help: 'The CA can then only vouch for .local, localhost, ts.net, this host and private addresses — even if its key leaked, it could not impersonate other websites.',
    });
    const typed = field({ label: 'Type “regenerate” to confirm', name: 'confirm', required: true, autocomplete: 'off', attrs: { spellcheck: 'false', autocapitalize: 'off' } });
    const ok = await formDialog({
      title: 'Regenerate the certificate authority?',
      intro: alertEl('danger', 'All devices must trust the new CA', 'Phones, laptops and the CLI (--ca-file / --fingerprint) will reject the server until the new CA is installed.'),
      fields: [constrained, typed],
      submitLabel: 'Regenerate',
      submitIcon: 'rotate',
      submitVariant: 'danger',
      onSubmit: async (v) => {
        if (String(v.confirm).trim().toLowerCase() !== 'regenerate') throw new ApiError(422, 'invalid', 'Type “regenerate” to confirm.', 'confirm');
        if (!v.constrained) {
          const sure = await confirm({ title: 'Create an unrestricted CA?', message: 'An unrestricted CA can vouch for any website. Devices that trust it are at risk if its key ever leaks.', confirmLabel: 'Create unrestricted CA', danger: true });
          if (!sure) return false;
        }
        await api.post('/admin/certs/ca/regenerate', v.constrained ? {} : { unconstrained: true });
        return true;
      },
    });
    if (!ok) return;
    toast.success('New certificate authority created. Install it on your devices again.');
    await load();
  };

  // ------------------------------------------------------------------------------------------ custom
  const drawCustom = () => {
    const c = st.custom;
    replace(customBody, 
      c
        ? h('div', { class: 'stack-sm' },
          h('div', { class: 'cluster' }, expiryBadge(c.not_after)),
          kv([['Subject', c.subject], ['Issuer', c.issuer], ['Names', chips(c.dns_names)], ['Valid until', dateTime(c.not_after)]]))
        : h('p', { class: 'muted text-sm', text: 'Use a certificate from your own CA or a commercial one for your domain. FileParcel serves it for the names it covers.' }),
      !isAdmin() ? h('p', { class: 'muted text-sm', text: 'Only administrators can upload or remove a custom certificate.' }) : h('div', { class: 'btn-row btn-row--start' },
        button({ label: c ? 'Replace…' : 'Upload certificate…', icon: 'upload', onClick: uploadCustom }),
        c ? button({
          label: 'Remove',
          icon: 'trash',
          variant: 'ghost',
          onClick: async () => {
            const ok = await confirm({ title: 'Remove the custom certificate?', message: 'Its names fall back to the local certificate (or ACME/Tailscale when they cover them).', confirmLabel: 'Remove', danger: true });
            if (!ok) return;
            try {
              await api.del('/admin/certs/custom');
              toast.success('Custom certificate removed');
              await load();
            } catch (err) {
              toast.error(err);
            }
          },
        }) : null));
  };

  const uploadCustom = async () => {
    const certF = pemField('Certificate chain (PEM)', 'cert_pem', 'Leaf certificate first, then intermediates. -----BEGIN CERTIFICATE-----…', '.pem,.crt,.cer');
    const keyF = pemField('Private key (PEM)', 'key_pem', '-----BEGIN PRIVATE KEY-----…', '.pem,.key');
    const ok = await formDialog({
      title: 'Upload a custom certificate',
      size: 'lg',
      intro: 'The key is encrypted with the master key before it is stored. Both files are checked: the key must match and the certificate must not be expired.',
      fields: [certF, keyF],
      submitLabel: 'Install certificate',
      submitIcon: 'upload',
      onSubmit: async (v) => {
        const cert = String(v.cert_pem).trim();
        const key = String(v.key_pem).trim();
        if (!/-----BEGIN CERTIFICATE-----/.test(cert)) throw new ApiError(422, 'invalid', 'This does not look like a PEM certificate.', 'cert_pem');
        if (!/-----BEGIN [A-Z ]*PRIVATE KEY-----/.test(key)) throw new ApiError(422, 'invalid', 'This does not look like a PEM private key.', 'key_pem');
        if (/ENCRYPTED/.test(key)) throw new ApiError(422, 'invalid', 'The key is password-protected. Export it without a password (e.g. openssl pkey -in key.pem -out plain.pem).', 'key_pem');
        await api.put('/admin/certs/custom', { cert_pem: `${cert}\n`, key_pem: `${key}\n` });
        return true;
      },
    });
    if (!ok) return;
    toast.success('Custom certificate installed');
    await load();
  };

  // ------------------------------------------------------------------------------------------ ACME
  const drawACME = () => {
    const enabled = !!st.acme_enabled || !!setting('acme.enabled');
    const certs = st.acme || [];
    const ca = String(setting('acme.ca') || 'staging');
    replace(acmeBody, 
      h('div', { class: 'cluster' },
        badge({ text: enabled ? 'Enabled' : 'Off', kind: enabled ? 'success' : 'neutral' }),
        enabled ? badge({ text: ca === 'production' ? 'Production' : ca === 'staging' ? 'Staging (test certificates)' : 'Custom CA', kind: ca === 'staging' ? 'warning' : 'info' }) : null),
      !enabled ? h('p', { class: 'muted text-sm', text: 'Get a publicly trusted certificate for a domain you own (for example files.example.com), so no device needs the local CA. Home servers usually use the DNS challenge because they are not reachable from the internet.' }) : null,
      certs.length ? h('ul', { class: 'item-list', attrs: { role: 'list' } }, certs.map((/** @type {any} */ c) => h('li', { class: 'item-row' },
        h('span', { class: 'item-row-icon', attrs: { 'aria-hidden': 'true' } }, icon('certificate')),
        h('div', { class: 'item-row-main' },
          h('span', { class: 'item-row-title' }, (c.dns_names || []).join(', ') || c.subject, expiryBadge(c.not_after)),
          h('span', { class: 'item-row-sub', text: `Issued by ${c.issuer || 'ACME CA'}` }))))) : null,
      st.acme_error ? alertEl('danger', 'The last request failed', st.acme_error) : null,
      ca === 'staging' && enabled ? alertEl('info', 'Staging certificates are not trusted by browsers', 'Staging is for testing the setup without hitting Let’s Encrypt rate limits. Switch to production once it works.') : null,
      h('div', { class: 'btn-row btn-row--start' },
        button({ label: enabled ? 'Change setup…' : 'Set up…', icon: 'sliders', variant: enabled ? 'secondary' : 'primary', onClick: acmeWizard }),
        enabled ? button({ label: 'Request now', icon: 'refresh', onClick: applyACME }) : null,
        enabled ? button({
          label: 'Turn off',
          variant: 'ghost',
          onClick: async () => {
            const ok = await confirm({ title: 'Turn off ACME?', message: 'The domain names fall back to the local certificate. Existing ACME certificates are not revoked.', confirmLabel: 'Turn off' });
            if (!ok) return;
            try {
              await saveSettings({ 'acme.enabled': false });
              toast.success('ACME turned off');
              await load();
            } catch (err) {
              toast.error(err);
            }
          },
        }) : null),
      h('p', { class: 'subtle text-xs', text: 'Note: publicly trusted certificates are listed in public Certificate Transparency logs, which reveals the domain name.' }));
  };

  const applyACME = async () => {
    try {
      await api.post('/admin/certs/acme/apply', {});
      toast.success('Certificate requested. This can take a minute (DNS changes need time to propagate).');
      setTimeout(() => load(), 5000);
    } catch (err) {
      toast.error(err);
    }
  };

  const acmeWizard = async () => {
    const email = field({ label: 'Contact email', name: 'email', type: 'email', required: true, value: setting('acme.email') || '', help: 'The certificate authority sends expiry warnings here.' });
    const domains = field({
      label: 'Domain names', name: 'domains', type: 'textarea', rows: 3, required: true, value: (setting('acme.domains') || []).join('\n'),
      help: 'One per line, e.g. files.example.com. The names must point to this server (DNS) or be verifiable with the DNS challenge.',
      attrs: { spellcheck: 'false', autocapitalize: 'off' },
    });
    const curCA = String(setting('acme.ca') || 'staging');
    const caSel = select({
      label: 'Certificate authority', name: 'ca',
      value: curCA === 'staging' || curCA === 'production' ? curCA : 'custom',
      options: [
        { value: 'staging', label: 'Let’s Encrypt staging (test first)' },
        { value: 'production', label: 'Let’s Encrypt production' },
        { value: 'custom', label: 'Another ACME server…' },
      ],
      onChange: () => sync(),
    });
    const caURL = field({ label: 'ACME directory URL', name: 'ca_url', type: 'url', value: curCA.startsWith('http') ? curCA : '', placeholder: 'https://acme.example.com/directory' });
    const challenge = select({
      label: 'How to prove you own the domain', name: 'challenge', value: String(setting('acme.challenge') || 'dns'),
      options: [
        { value: 'dns', label: 'DNS record (works behind a firewall — recommended)' },
        { value: 'http', label: 'HTTP on port 80 (server must be reachable from the internet)' },
        { value: 'tls-alpn', label: 'TLS on port 443 (server must be reachable from the internet)' },
      ],
      onChange: () => sync(),
    });
    const provider = select({
      label: 'DNS provider', name: 'provider', value: String(setting('acme.dns_provider') || 'cloudflare'),
      options: [{ value: 'cloudflare', label: 'Cloudflare' }, { value: 'rfc2136', label: 'RFC 2136 (BIND, PowerDNS, Knot, …)' }],
      onChange: () => sync(),
    });
    // acme.dns_credentials is one secret JSON value: it cannot be shown or pre-filled, and "leave empty to keep"
    // only works while the provider stays the one it was saved for
    const credsSet = !!settings['acme.dns_credentials']?.is_set;
    const savedProvider = String(setting('acme.dns_provider') || 'cloudflare');
    const kept = (/** @type {string} */ p) => credsSet && savedProvider === p;
    const cfToken = field({ label: 'Cloudflare API token', name: 'cf_token', type: 'password', autocomplete: 'off', placeholder: kept('cloudflare') ? '•••••••• (saved — leave empty to keep)' : '', help: 'Create a token with “Zone → DNS → Edit” permission for the zone.' });
    const rfcServer = field({ label: 'DNS server', name: 'rfc_server', placeholder: 'ns1.example.com:53', attrs: { spellcheck: 'false' } });
    const rfcKeyName = field({ label: 'TSIG key name', name: 'rfc_key_name', placeholder: 'fileparcel.', attrs: { spellcheck: 'false' } });
    // DNS-style algorithm names (trailing dot) as expected by the RFC 2136 provider
    const rfcAlg = select({
      label: 'TSIG algorithm', name: 'rfc_key_alg', value: 'hmac-sha256.',
      options: [{ value: 'hmac-sha256.', label: 'HMAC-SHA256' }, { value: 'hmac-sha512.', label: 'HMAC-SHA512' }, { value: 'hmac-sha1.', label: 'HMAC-SHA1 (legacy)' }],
    });
    const rfcSecret = field({
      label: 'TSIG secret (base64)', name: 'rfc_key', type: 'password', autocomplete: 'off',
      placeholder: kept('rfc2136') ? '•••••••• (saved — leave empty to keep)' : '',
      help: kept('rfc2136') ? 'The saved RFC 2136 settings are stored encrypted and not shown. Leave the server, key name and secret empty to keep them; to change the server, key name or algorithm, fill in every field, including the secret.' : undefined,
    });
    const rfcFields = [rfcServer, rfcKeyName, rfcAlg, rfcSecret];
    const hint = h('div');
    const sync = () => {
      caURL.el.hidden = caSel.input.value !== 'custom';
      const dns = challenge.input.value === 'dns';
      provider.el.hidden = !dns;
      cfToken.el.hidden = !dns || provider.input.value !== 'cloudflare';
      for (const f of rfcFields) f.el.hidden = !dns || provider.input.value !== 'rfc2136';
      replace(hint, dns ? null : alertEl('warning', 'Needs public reachability', `The CA connects to port ${challenge.input.value === 'http' ? '80' : '443'} of your domain from the internet. Forward that port to this machine and open the firewall, or use the DNS challenge.`));
    };
    sync();
    const request = toggle({ label: 'Request the certificate right away', name: 'apply', checked: true });
    const ok = await formDialog({
      title: 'Let’s Encrypt / ACME setup',
      size: 'lg',
      fields: [email, domains, caSel, caURL, challenge, hint, provider, cfToken, ...rfcFields, request],
      submitLabel: 'Save',
      submitIcon: 'check',
      onSubmit: async (v) => {
        const list = String(v.domains).split(/[\s,]+/).map((d) => d.trim().toLowerCase()).filter(Boolean);
        if (!list.length) throw new ApiError(422, 'invalid', 'Enter at least one domain name.', 'domains');
        const badName = list.find((d) => !/^(\*\.)?([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/.test(d));
        if (badName) throw new ApiError(422, 'invalid', `“${badName}” is not a valid domain name.`, 'domains');
        if (list.some((d) => d.endsWith('.local'))) throw new ApiError(422, 'invalid', '.local names cannot get public certificates.', 'domains');
        let ca = String(v.ca);
        if (ca === 'custom') {
          ca = String(v.ca_url).trim();
          if (!/^https:\/\//.test(ca)) throw new ApiError(422, 'invalid', 'Enter the https:// directory URL of the ACME server.', 'ca_url');
        }
        /** @type {Record<string, any>} */
        const changes = {
          'acme.enabled': true,
          'acme.email': String(v.email).trim(),
          'acme.domains': list,
          'acme.ca': ca,
          'acme.challenge': v.challenge,
        };
        if (v.challenge === 'dns') {
          changes['acme.dns_provider'] = v.provider;
          // The saved credentials may only be kept for the provider they were saved for, and only unedited:
          // anything else would pair the provider with the other one's credentials, or drop the edits silently.
          const missing = credsSet
            ? 'Enter the credentials of the new DNS provider (the saved ones belong to the other provider).'
            : 'Enter the DNS provider credentials.';
          if (v.provider === 'cloudflare') {
            const token = String(v.cf_token).trim();
            if (token) changes['acme.dns_credentials'] = JSON.stringify({ api_token: token });
            else if (!kept('cloudflare')) throw new ApiError(422, 'invalid', missing, 'cf_token');
          } else {
            const server = String(v.rfc_server).trim();
            const keyName = String(v.rfc_key_name).trim();
            const key = String(v.rfc_key).trim();
            if (key) {
              if (!server) throw new ApiError(422, 'invalid', 'Enter the DNS server that accepts updates.', 'rfc_server');
              if (!keyName) throw new ApiError(422, 'invalid', 'Enter the TSIG key name.', 'rfc_key_name');
              changes['acme.dns_credentials'] = JSON.stringify({ server, key_name: keyName, key_alg: v.rfc_key_alg, key });
            } else if (!kept('rfc2136')) {
              throw new ApiError(422, 'invalid', missing, 'rfc_key');
            } else if (server || keyName) {
              throw new ApiError(422, 'invalid', 'Enter the TSIG secret too: the saved RFC 2136 settings are stored as one encrypted value, so changing the server or key name needs all fields.', 'rfc_key');
            }
          }
        }
        try {
          await saveSettings(changes);
        } catch (err) {
          if (err instanceof ApiError && err.field) {
            const map = /** @type {Record<string, string>} */ ({ 'acme.email': 'email', 'acme.domains': 'domains', 'acme.ca': 'ca_url', 'acme.dns_credentials': v.provider === 'cloudflare' ? 'cf_token' : 'rfc_key' });
            if (map[err.field]) throw new ApiError(err.status, err.code, err.message, map[err.field]);
          }
          throw err;
        }
        return { apply: !!v.apply };
      },
    });
    if (!ok) return;
    toast.success('ACME settings saved');
    if (ok.apply) await applyACME();
    else await load();
  };

  // ------------------------------------------------------------------------------------------ Tailscale
  const drawTailscale = () => {
    const enabled = !!setting('tailscale.cert_enabled');
    const c = st.tailscale;
    const err = String(st.tailscale_error || '');
    const opHint = /operator|access denied|permission|not allowed/i.test(err);
    replace(tsBody, 
      h('div', { class: 'cluster' }, badge({ text: enabled ? 'Enabled' : 'Off', kind: enabled ? 'success' : 'neutral' }), c ? expiryBadge(c.not_after, 14) : null),
      c ? kv([['Name', chips(c.dns_names)], ['Valid until', dateTime(c.not_after)], ['Issuer', c.issuer]]) : null,
      !enabled && !c ? h('p', { class: 'muted text-sm', text: 'On a tailnet with HTTPS enabled, Tailscale can issue a publicly trusted certificate for this machine’s MagicDNS name (…ts.net). Nobody needs to install the local CA for that name.' }) : null,
      err ? alertEl('warning', 'Tailscale could not issue a certificate', err) : null,
      opHint || (enabled && !c)
        ? alertEl('info', 'Allow FileParcel to request certificates',
          h('span', null, 'Enable HTTPS certificates for the tailnet in the Tailscale admin console (DNS page), then on the server run ',
            h('code', { text: 'sudo tailscale set --operator=$USER' }), ' so the FileParcel user may talk to tailscaled.'))
        : null,
      h('div', { class: 'btn-row btn-row--start' },
        button({
          label: enabled ? 'Turn off' : 'Turn on',
          icon: enabled ? 'x' : 'check',
          variant: enabled ? 'ghost' : 'primary',
          onClick: async () => {
            try {
              await saveSettings({ 'tailscale.cert_enabled': !enabled });
              toast.success(enabled ? 'Tailscale certificates turned off' : 'Tailscale certificates turned on');
              if (!enabled) await fetchTS(false);
              await load();
            } catch (e) {
              toast.error(e);
            }
          },
        }),
        enabled ? button({ label: 'Fetch now', icon: 'download', onClick: () => fetchTS(true) }) : null,
        h('a', { class: 'btn btn--ghost', href: '/admin/settings/tailscale' }, icon('sliders'), h('span', { text: 'Settings' }))),
      h('p', { class: 'subtle text-xs', text: 'Tailscale names appear in public Certificate Transparency logs. Headscale cannot issue these certificates.' }));
  };

  /** @param {boolean} reload */
  const fetchTS = async (reload) => {
    try {
      await api.post('/admin/certs/tailscale/fetch', {});
      toast.success('Tailscale certificate fetched');
    } catch (err) {
      toast.error(`Tailscale: ${errorMessage(err)}`);
    }
    if (reload) await load();
  };

  // ------------------------------------------------------------------------------------------ mTLS
  const drawMTLS = async () => {
    const mode = String(setting('mtls.mode') || st.mtls_mode || 'off');
    const modeSel = select({
      label: 'Require client certificates',
      value: mode,
      options: [
        { value: 'off', label: 'Off — passwords and passkeys only' },
        { value: 'optional', label: 'Optional — ask for a certificate, allow devices without one' },
        { value: 'required', label: 'Required — only devices with a valid certificate may connect' },
      ],
    });
    const exempt = toggle({ label: 'Share links work without a certificate', checked: setting('mtls.exempt_shares') !== false, help: 'Lets people outside your organisation open public links and file requests.' });
    const self = toggle({ label: 'Users may create certificates for their own devices', checked: !!setting('mtls.self_service'), help: 'From Settings → Devices & app.' });
    const saveBtn = button({
      label: 'Save',
      icon: 'check',
      variant: 'primary',
      onClick: async () => {
        /** @type {Record<string, any>} */
        const changes = {};
        if (modeSel.input.value !== mode) changes['mtls.mode'] = modeSel.input.value;
        if (exempt.input.checked !== (setting('mtls.exempt_shares') !== false)) changes['mtls.exempt_shares'] = exempt.input.checked;
        if (self.input.checked !== !!setting('mtls.self_service')) changes['mtls.self_service'] = self.input.checked;
        if (!Object.keys(changes).length) {
          toast.info('Nothing changed.');
          return;
        }
        if (changes['mtls.mode'] === 'required') {
          const ok = await confirm({
            title: 'Require client certificates?',
            message: 'Every browser, phone and CLI without a valid certificate is rejected — including this one if it has none. Make sure your own device has a certificate installed first.',
            confirmLabel: 'Require certificates',
            danger: true,
          });
          if (!ok) return;
        }
        try {
          await saveSettings(changes);
          toast.success('Client certificate settings saved');
          await load();
        } catch (err) {
          toast.error(err);
        }
      },
    });

    /** @type {any[]} */
    let certs = [];
    /** @type {Node | null} */
    let listErr = null;
    try {
      certs = itemsOf(await api.get('/admin/client-certs', { signal: ctx.signal, query: { limit: 500 }, handle: false }));
    } catch (err) {
      if (err instanceof ApiError && err.aborted) return;
      listErr = errorPanel(err, drawMTLS);
    }
    const t = table({
      caption: 'Client certificates',
      columns: [
        { key: 'name', label: 'Certificate', render: (c) => h('span', { class: 'stack-sm gap-1' }, h('strong', { text: c.name || 'Certificate' }), h('span', { class: 'muted text-xs', text: c.username || c.user_id })) },
        { key: 'serial', label: 'Serial', hideBelow: 'md', render: (c) => h('span', { class: 'mono text-xs', text: shortSerial(c.serial), title: c.serial }) },
        { key: 'valid', label: 'Valid until', render: (c) => (c.revoked_at ? badge({ text: 'Revoked', kind: 'neutral', title: c.revoke_reason || '' }) : expiryBadge(c.not_after)) },
        { key: 'seen', label: 'Last used', hideBelow: 'sm', render: (c) => (c.last_seen_at ? timeEl(c.last_seen_at) : h('span', { class: 'subtle', text: 'Never' })) },
        {
          key: 'actions', label: 'Actions', srOnlyLabel: true, class: 'cell-actions',
          render: (c) => (c.revoked_at ? null : moreMenu([{ label: 'Revoke', icon: 'x-circle', danger: true, onClick: () => revoke(c) }], `Actions for ${c.name}`)),
        },
      ],
      rows: certs.sort((a, b) => Number(!!a.revoked_at) - Number(!!b.revoked_at) || String(b.issued_at).localeCompare(String(a.issued_at))),
      empty: 'No client certificates issued yet.',
    });
    replace(mtlsBody, 
      h('p', { class: 'muted text-sm', text: 'Client certificates identify devices during the TLS handshake — before anyone can even see the sign-in page. They complement passwords, they do not replace them.' }),
      h('div', { class: 'grid-2' }, h('div', { class: 'stack-sm' }, modeSel.el, exempt.el, self.el, h('div', null, saveBtn)),
        h('div', { class: 'stack-sm' },
          mode === 'required' ? alertEl('warning', 'Certificates are required', 'Devices without a valid certificate cannot connect.') : null,
          st.client_ca ? kv([['Client CA', st.client_ca.subject], ['Valid until', dateTime(st.client_ca.not_after)]]) : null)),
      h('div', { class: 'split' }, h('h3', { class: 'text-md', text: 'Issued certificates' }), button({ label: 'Issue certificate', icon: 'plus', onClick: issue })),
      listErr || t.el);
  };

  const issue = async () => {
    const who = userPicker({ label: 'For user', name: 'user_id', required: true });
    const name = field({ label: 'Device name', name: 'name', required: true, maxlength: 64, placeholder: 'e.g. Anna’s iPhone' });
    const days = select({ label: 'Valid for', name: 'days', value: '365', options: [{ value: '90', label: '3 months' }, { value: '365', label: '1 year' }, { value: '730', label: '2 years' }, { value: '1095', label: '3 years' }] });
    const legacy = toggle({ label: 'Compatibility mode', name: 'legacy', help: 'Older encryption for the .p12 file (old Android and macOS versions).' });
    const r = await formDialog({
      title: 'Issue a client certificate',
      intro: 'A .p12 file with the certificate and its private key is downloaded once. A random import password is shown afterwards.',
      fields: [who, name, days, legacy],
      submitLabel: 'Issue and download',
      submitIcon: 'download',
      onSubmit: async (v) => {
        const uid = String(v.user_id || '');
        if (!uid) throw new ApiError(422, 'invalid', 'Pick the user the certificate belongs to.', 'user_id');
        return issueClientCert('/admin/client-certs', { user_id: uid, name: String(v.name).trim(), days: Number(v.days) || 365, password: generatePassword(16), legacy: !!v.legacy });
      },
    });
    if (!r || r === true) return;
    await showP12Password(r);
    await drawMTLS();
  };

  /** @param {any} c */
  const revoke = async (c) => {
    const reason = await prompt({ title: `Revoke “${c.name}”?`, label: 'Reason (optional)', required: false, placeholder: 'e.g. device lost', confirmLabel: 'Revoke' });
    if (reason === null) return;
    try {
      const q = reason ? `?reason=${encodeURIComponent(reason)}` : '';
      await api.del(`/admin/client-certs/${encodeURIComponent(c.id)}${q}`);
      toast.success('Certificate revoked. The device can no longer connect with it.');
      await drawMTLS();
    } catch (err) {
      toast.error(err);
    }
  };

  const refresh = debounce(() => load(), 800);
  const off = onEvents(['certs.changed'], refresh);
  await load();
  if (location.hash) document.getElementById(location.hash.slice(1))?.scrollIntoView({ block: 'start' });
  return () => {
    off();
    refresh.cancel();
  };
}

/**
 * PEM textarea with a "load from file" button.
 * @param {string} label
 * @param {string} name
 * @param {string} placeholder
 * @param {string} accept
 */
function pemField(label, name, placeholder, accept) {
  const f = field({ label, name, type: 'textarea', rows: 6, required: true, placeholder, attrs: { spellcheck: 'false', autocapitalize: 'off', class: 'mono' } });
  const picker = h('input', { class: 'hidden', attrs: { type: 'file', accept, tabindex: '-1', 'aria-hidden': 'true' } });
  picker.addEventListener('change', async () => {
    const file = picker.files?.[0];
    picker.value = '';
    if (!file) return;
    if (file.size > 256 * 1024) {
      f.setError('That file is too large for a PEM certificate or key.');
      return;
    }
    f.input.value = await file.text();
    f.setError(null);
  });
  append(f.el, picker, h('div', { class: 'cluster' }, button({ label: 'Load from file…', size: 'sm', variant: 'ghost', icon: 'upload', onClick: () => picker.click() })));
  return f;
}

/** @param {string} s */
function shortSerial(s) {
  const v = String(s || '');
  return v.length > 20 ? `${v.slice(0, 8)}…${v.slice(-8)}` : v;
}
