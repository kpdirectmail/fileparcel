# FileParcel Security

This document describes FileParcel's threat model, the security controls it implements, the residual
risks operators should know about, a hardening checklist, and how to report vulnerabilities. The
cryptographic formats are specified in [ENCRYPTION.md](ENCRYPTION.md); day-to-day operation is covered in
the [user manual](FILEPARCEL.md), installing and upgrading in [Installing FileParcel](INSTALL.md).

## Contents

- [Scope and assumptions](#scope-and-assumptions)
- [Assets](#assets)
- [Adversaries](#adversaries)
- [Trust boundaries](#trust-boundaries)
- [Controls](#controls)
- [Residual risks and limitations](#residual-risks-and-limitations)
- [Hardening checklist](#hardening-checklist)
- [Supported versions and updates](#supported-versions-and-updates)
- [Reporting a vulnerability](#reporting-a-vulnerability)
- [Delegated administration (roles)](#delegated-administration-roles)
- [Password-protected zip files](#password-protected-zip-files)
- [Tailscale Funnel, Serve and VPNs](#tailscale-funnel-serve-and-vpns)

## Scope and assumptions

FileParcel is a self-hosted file sharing server for homes and small offices, typically reachable on a LAN
and over VPNs (Tailscale/Headscale, WireGuard, ZeroTier, NetBird, Nebula, OpenVPN), optionally from the
internet. One process serves the web app, the REST API, public share links and file requests, and an admin
socket for the local CLI. Everything it stores lives in one directory (`<HOME>`).

Assumptions:

- The operating system, its kernel and the account FileParcel runs as are not compromised. Anyone who
  controls that account (or root) controls FileParcel: they can read the master key from the key file
  (plain mode) or from process memory, and they can use the admin socket.
- Devices that trust FileParcel's local certificate authority are the operator's own or users' own devices.
- Administrators are trusted to administer, but — by default — not to read other users' files.

## Assets

| Asset | Where |
|---|---|
| File contents, versions, thumbnails | `data/blobs` (encrypted) |
| File metadata (names, sizes, dates, folder structure), users, groups, shares | `data/fileparcel.db` (not encrypted) |
| Credentials: password hashes, TOTP secrets, passkeys, recovery-code MACs, session/token hashes | database (secrets field-encrypted, tokens hashed) |
| Keys: master key, keyring, CA and client-CA keys, custom certificate key | `keys/`, database, `certs/` (encrypted except as noted in ENCRYPTION.md §1) |
| Share-link and invitation tokens | database (hashed + field-encrypted copy) |
| Backups | `backups/*.fpbak` and copies (age-encrypted) |
| Audit log | database (HMAC-chained), optional `logs/audit.jsonl` |
| Availability of the service | the process, the disk |

## Adversaries

1. **Network outsiders** — hosts on the internet or on networks outside the access policy.
2. **Network insiders** — other devices on the LAN or VPN (possibly compromised IoT devices, guests on the
   Wi-Fi) who can reach the port but have no account.
3. **Anonymous visitors of share links and file requests**, including people a link was forwarded to.
4. **Authenticated users** (guests, members) trying to access other users' data or escalate privileges.
5. **Malicious web sites** visited by a signed-in user (CSRF, DNS rebinding, clickjacking, cross-origin
   leaks).
6. **Malicious content**: uploaded files crafted to attack viewers (HTML/SVG/script, decompression and image
   bombs, path traversal in names and archives).
7. **Local attackers without the server account**: other users on the machine, a thief with the disk or a
   backup copy, a cloud or NAS provider holding backups.
8. **Administrators** trying to read users' files without that being visible.

Out of scope: an attacker with root or the server's account on the running machine, hardware attacks,
compromised client devices (a compromised browser can do whatever its user can), and denial of service by
an adversary with far more bandwidth than the server.

## Trust boundaries

```
 internet / other networks ──X──► listener (access policy: allowlist before TLS)
 LAN / VPN clients ────────────► TLS ─► HTTP router ─► security headers, host check, sealed gate
                                          ├─ public: /login, /s/<token>, /invite/<token>, /trust, /unlock, health
                                          └─ /api/v1: body limits → rate limit → authenticate → CSRF → per-route guards
 local CLI ──── admin socket (same uid or root, peer credentials) ──► same API as the system principal
 disk ◄── encrypted blobs, encrypted secrets, key file (plain or sealed), backups (age)
```

## Controls

### Network

- **Access policy** enforced at `Accept()`, before any TLS or HTTP processing: `allowlist` (default:
  loopback plus the LAN/VPN networks detected at installation), `private` (all private and VPN ranges
  plus the allow list) or `any`. A deny list always wins; loopback is always allowed. IPv4-mapped IPv6
  addresses are normalised before matching. The matcher is swapped atomically when the policy changes;
  open connections are checked again before every request and every 2 s, and those whose peer is no
  longer allowed are closed (with their event streams).
- **Lockout guard**: a policy change that would lock out the administrator's current address is refused
  unless explicitly forced.
- **Strict Host check** (`network.strict_host`) rejects requests for unknown host names, defeating DNS
  rebinding.
- `X-Forwarded-For` is honoured only from configured `server.trusted_proxies`. The client address it
  resolves must pass the access policy as well (checked per request, 403): the listener only sees the
  proxy, and a proxy on the same machine connects from loopback, which is always allowed.
- The HTTP port only redirects (and answers ACME HTTP-01 challenges); it never serves content.
- mDNS publishes only the `.local` name and an `_https._tcp` service on LAN/Wi-Fi interfaces, never on VPNs
  or container bridges (ZeroTier only on request).

### Transport security

- HTTPS only; TLS 1.2 minimum (1.3 optional), AEAD cipher suites only, HTTP/2, X25519MLKEM768 hybrid key
  exchange preferred by Go's TLS stack.
- **Local CA** with critical **name constraints** (local names, `.ts.net`, configured names, private IP
  ranges; a name that is itself a public suffix such as a TLD is never added) and the serverAuth EKU, so the
  CA cannot mint certificates for public domains — nor code-signing or S/MIME certificates — even if its key
  leaked. The client CA is clientAuth-only and is not included in exported `.p12` files. The CA key is
  encrypted with the master key and only unsealed while signing. Leaf certificates follow Apple's
  requirements for certificates from user-trusted CAs (validity `tls.leaf_days`: default 397 days, at
  most 825; SAN; serverAuth EKU) and are reissued automatically when names change.
- ACME (Let's Encrypt, DNS-01/HTTP-01/TLS-ALPN-01), Tailscale certificates and custom certificates are
  supported and selected per SNI name.
- `Strict-Transport-Security` only when the served certificate is publicly trusted (`tls.hsts = auto`),
  avoiding HSTS lock-outs on local-CA names.
- **Optional mTLS** with a separate client CA; certificates are checked against the database on every
  request (immediate revocation); share links, `/trust` and health checks can be exempted. A certificate
  admits a device, not an account (see the residual risks).

### Authentication

- Passwords: argon2id (PHC format, automatic rehash), minimum length (default 12), rejection of common
  passwords and passwords containing the username; argon2 memory bounded by a process-wide semaphore,
  whose queue is capped for sign-ins and share passwords (beyond it: "busy, try again", not a failure).
- Login failures are uniform ("invalid credentials") and timing-equalised with a dummy hash; per-IP rate
  limits (`ratelimit.login_per_min`; the sign-in, share and unlock limits also cap each remote IPv6 /64
  at 8 times the per-address allowance, so rotating through the addresses of one /64 gains nothing,
  while LAN, tailnet and link-local clients keep per-address limits); per-account lockout with
  exponential backoff (15 min doubling to 24 h)
  after consecutive failures (sign-in, step-up, current password); while locked, a signed-in user's step-up and
  password change are refused with a message naming the lock, before any credential is checked.
- Second factors: TOTP (RFC 6238, ±1 step, replay of a used step rejected), 10 single-use recovery codes
  stored as MACs, passkeys (WebAuthn, user verification, sign-counter tracking). 2FA is required by default
  for administrators and every account whose role has a server permission (`auth.require_2fa = admins`);
  users in scope must enroll before anything else
  (their API tokens are refused until then).
- **Step-up**: sensitive operations (role changes, deleting users, resetting others' passwords or 2FA, key
  and certificate operations, network policy, backup restore/download/delete, security-relevant settings,
  removing one's own 2FA, adding an authenticator app or a passkey, admin-scope tokens) require
  re-authentication within `auth.stepup_min` minutes. Adding a factor needs it because a new factor itself
  satisfies step-up (and a passkey signs in on its own): a hijacked session cannot plant one to keep or
  widen its access. Adding one e-mails the account owner a security alert, like creating an API token.
  The e-mail address receives those alerts, so changing one's own needs step-up too, and the previous
  address is told.
- First-run setup requires a one-time setup token printed on the server; no default credentials exist.
  Installer-generated admin passwords, and passwords an administrator generates or sets with "must
  change", must be changed at first sign-in: the server refuses everything but the account's own settings
  (`/me*`) and sign-out to such a session until the password is changed (`password_change_required`).

### Sessions, tokens and CSRF

- Session cookie `__Host-fp_session`: 256-bit random, `Secure`, `HttpOnly`, `SameSite=Lax`, `Path=/`; only
  its SHA-256 is stored. Rotated on sign-in completion, elevation and password change (fixation-safe).
  Idle timeout and absolute lifetime; password changes revoke other sessions; users can revoke sessions.
- CSRF: `http.CrossOriginProtection` (Fetch metadata / Origin) **and** a per-session token
  (`X-FP-CSRF`, an HMAC of the session) on every unsafe cookie-authenticated request. Bearer tokens and
  the admin socket are not cookie-based and therefore exempt.
- API tokens `fpt_…`: random secrets (≥ 128 bits) stored as hashes, scopes (`files:read`, `files:write`, `shares`,
  `admin`), expiry, last use recorded; cannot perform step-up unless created elevated (with step-up,
  max. 30 days). A token can create tokens only with a subset of its scopes and expiring no later than
  itself, revoke only itself and tokens no wider than itself, and cannot list or end browser sessions.
  Over the network, users (administrators included) revoke only their own tokens and passkeys;
  other accounts' credentials are reset through the user administration or the admin socket. The remote
  CLI reads a token from `$FILEPARCEL_TOKEN` or `--token-file`; `--token` is accepted too, but an argument
  is visible to other local users in the process list.
- Only `Authorization: Bearer fpt_…` is a credential; other `Authorization` headers (e.g. a reverse proxy's
  Basic gate) are ignored, so they neither authenticate nor sign a cookie session out.
- Archive (zip) tickets are single-use, expire after 60 s, are bound to the user or share and stored
  hashed. HEAD requests never consume tickets or count downloads.

### Authorization

- Every file operation is authorised per node (inherited grants via the ancestor chain): owner, group
  manager/member (directly or through a role that is a member of the group), viewer/editor/manager grants
  to users, groups or roles with optional expiry. Items a principal cannot see answer 404 (no
  existence oracle); visible but insufficient access answers 403.
- Administrators have **no** access to users' content unless `auth.admin_can_access_files = true`, in which
  case every access is audited (`admin.file_access`; for a share link an admin creates this way, once at
  creation, while its visits go to the link's access log).
- Admin routes require the admin role, or the permission a custom role delegates for that area (see
  [Delegated administration (roles)](#delegated-administration-roles)); route-table sweeps in the test suite
  check that non-public routes reject anonymous access and cross-site requests.
- Share links: ≥ 128-bit tokens; invalid, expired, disabled and exhausted links all return the same generic
  404 page; optional password (argon2id), attempts rate limited per visitor address and link (the sign-in
  rate) and wrong ones per link across all addresses, failures logged; access cookies
  (`__Host-fp_s_<last 8 of share id>`, 12 h) are bound to the share and its password version (changing the
  password revokes them); download limits are counted atomically.
- File requests: uploads land only in the request's folder, cannot list existing content, are bounded by
  per-file (a zip-mode upload is checked as the one file it becomes) and total quotas and charged to the
  owner's quota. A random visitor cookie (`__Host-fp_uv_<last 8 of share id>`, 31 days, no identity) binds
  each upload batch to the browser that opened it, so one visitor cannot read or cancel another's upload.

### Web application hardening

- Content Security Policy for pages: `default-src 'self'`, no inline scripts or styles, no `eval`,
  `object-src 'none'`, `base-uri 'none'`, `form-action 'self'`, `frame-ancestors 'none'`,
  `require-trusted-types-for 'script'` with a single Trusted Types policy (`fp`) that only creates
  same-origin script URLs for the Web Worker and the service worker. The frontend never uses `innerHTML`
  or similar sinks; all text is set with `textContent`.
- No third-party scripts, styles, fonts, analytics or CDNs; zero npm dependencies.
- `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer`,
  `Cross-Origin-Opener-Policy: same-origin`, `Cross-Origin-Resource-Policy: same-origin`, a restrictive
  `Permissions-Policy`; `Cache-Control: no-store` for HTML and API responses.
- `robots.txt` disallows everything; share and invitation tokens are not written to the logs (access,
  error and panic lines name the path with the token replaced by "…").

### Handling user content

- Downloads are `Content-Disposition: attachment` by default. Inline display is allowed only for an
  allow-list (common images, audio/video, PDF, and text served as `text/plain`). HTML, SVG, XML and
  JavaScript are always attachments with `application/octet-stream`.
- Every content response carries `nosniff`, `Cross-Origin-Resource-Policy: same-origin` and a sandboxing CSP
  (`default-src 'none'; … sandbox`; PDFs omit `sandbox` for the browser's viewer but keep `default-src 'none'`).
- MIME types are sniffed; the sniffed type wins when an extension claims a dangerous inline type.
- File names are validated (NFC, length, no separators, control characters or bidi override/isolate
  characters that could fake an extension, no `.`/`..`) and never used
  as file-system paths; blobs are addressed by random ids through `os.Root`. Upload paths are validated per
  segment (no `..`, no absolute paths, depth and length limits). Zip/tar names are sanitised and
  de-duplicated.
- Thumbnails: image dimensions (≤ 50 megapixels) and the memory the decoder will allocate for them
  (≤ 256 MiB, from the image headers) are checked before decoding, with bounded workers and
  timeouts. Zip creation is streaming with bounded memory.
- Upload parts are verified with SHA-256; quotas and free disk space are checked before accepting data;
  request bodies are size-limited per route; per-user concurrent batch limits.

### Data at rest

See [ENCRYPTION.md](ENCRYPTION.md): per-blob keys wrapped by a key hierarchy under a master key that is
either stored in a 0600 file (plain) or sealed with an argon2id-derived key (sealed; the server boots locked);
authenticated 64 KiB segments with random nonces; row-bound field encryption of secrets; HMAC-protected
recovery codes, cookies and audit chain; KEK, master-key and data rotation; age-encrypted backups; key files
overwritten before deletion on purge.

### Accountability and logging

- HMAC-chained audit log of all security-relevant actions (sign-ins, failures and lockouts, 2FA changes,
  users, groups, invitations, sessions, tokens, file operations incl. downloads, shares and share password
  failures, settings, network policy, certificates, keys, backups, system start/stop/restart), verifiable
  with `fileparcel audit verify`, with authenticated checkpoints across pruning.
- Logs never contain passwords, tokens, keys, share passwords or TOTP secrets; request ids tie log lines to
  audit entries.

### Process and platform

- Runs unprivileged with `umask 077`; refuses to run as root unless `--allow-root`; restrictive modes on
  every directory (keys and data 0700, key file 0600).
- The admin socket lives in a 0700 directory and checks the peer's uid (`SO_PEERCRED`/`LOCAL_PEERCRED`):
  only the same user or root.
- A single-instance lock (`flock`) prevents two processes from using one home; the offline CLI takes the
  same lock.
- systemd system units add `ProtectSystem=strict`, `ReadWritePaths=<HOME>`, `PrivateTmp`, `PrivateDevices`,
  `ProtectKernel*`, `RestrictAddressFamilies`, `RestrictNamespaces`, `LockPersonality`,
  `MemoryDenyWriteExecute`, `SystemCallFilter=@system-service`, `NoNewPrivileges`, and
  `CAP_NET_BIND_SERVICE` only for ports below 1024.
- On system installations (systemd and launchd) what root runs stays out of the service account's reach:
  `bin/` and `uninstall.sh` are root-owned and HOME itself is `root:<service group>` mode `1770`, so the
  account can write in HOME but not rename or replace them. Root never takes the service account or the
  account to delete from `installed.json`, which that account can write. An admin command run as root
  with the server stopped gives what it wrote back to that account the same way the installer does:
  a walk that never follows a symlink and leaves `bin/` and `uninstall.sh` to root.
- The Docker image is distroless (no shell), runs as uid 65532, and the compose file uses a read-only root
  file system, drops all capabilities and sets `no-new-privileges`.
- The installer never modifies the firewall or anything outside the installation directory except what it
  records in `service/installed.json` (service registration, symlink, lingering, system account); the
  uninstaller removes exactly those.

### Supply chain and releases

- Pure Go (`CGO_ENABLED=0`), static binaries, a small set of well-known modules pinned in `go.sum`
  ([THIRD_PARTY.md](THIRD_PARTY.md)); `govulncheck` and `staticcheck` in the development workflow.
- Release zips contain `SHA256SUMS` for all binaries and scripts, a `.sha256` for the zip itself, and the
  exact source tree of the tagged commit (`src/`) so builds can be reproduced (`-trimpath`, fixed
  timestamps). `install.sh` refuses binaries whose checksum does not match; `fileparcel upgrade` verifies
  releases the same way and rolls back automatically when the new version does not become healthy.

## Residual risks and limitations

- **Metadata is not encrypted at rest** (names, sizes, dates, users, audit log). Use full-disk encryption.
- **Plain key mode** stores the master key on the same disk as the data: it protects backups and copies of
  the data directory that do not include `keys/`, not a stolen disk. Use sealed mode (or full-disk
  encryption) against disk theft; note that a sealed server needs a manual unlock after every restart.
- **Backups include `keys/master.key`**: a backup plus its age identity or passphrase gives access to all
  data (plus the passphrase/recovery key in sealed mode). Keep the backup identity offline and separate.
  Whoever opened a copied key file also keeps the passphrase-derived key and the recovery key's hash it
  carries, and a master rotation keeps both: after a suspected leak change the passphrase and make a new
  recovery key (`fileparcel keys recovery-key`) as well as rotating (see the manual,
  [Rotate the encryption keys](FILEPARCEL.md#rotate-the-encryption-keys)).
- **Trusting the local CA** on a device lets the CA's holder issue TLS server certificates for the
  constrained names (`.local`, `.ts.net`, the host name, private IPs). Name constraints prevent misuse for
  public domains; only trust CAs of servers you control, and verify the fingerprint. CAs created before
  these limits (serverAuth EKU, no public-suffix constraints) keep their old profile until
  `fileparcel ca regenerate`; `.p12` files issued before the client CA was left out of them carried it, so a
  device that imported one may list "FileParcel Client CA" as trusted — remove it there.
- **Cookies are not isolated by port**: other HTTPS services on the same host name could receive the session
  cookie. Do not run untrusted web applications on the same host name.
- **`100.64.0.0/10` overlaps with ISP carrier-grade NAT**: if the server has a CGNAT address from its
  provider, narrow the allowlist to the tailnet's actual addresses.
- **`.ts.net` and ACME certificate names are published** in Certificate Transparency logs.
- **Overwriting key files on purge** is not reliable on SSDs and copy-on-write file systems; full-disk
  encryption covers this.
- **Public exposure** (`network.access_mode = any`) makes the login page and share links reachable by
  everyone; rate limits and lockouts slow down guessing but cannot stop a distributed attack on weak
  passwords — require 2FA for all users when exposing FileParcel.
- **Administrators with access to the server account** can read everything (including by enabling
  `auth.admin_can_access_files`, which is audited, or by reading the database and keys directly, which is
  not). The audit log detects tampering only by those who do not hold the keys.
- **Audit entries written while the keys are unavailable** (sealed mode before the unlock, offline
  commands) are not authenticated: anyone who can write the database then can add entries that the next
  unlock seals. Entries the sealing server process did not write itself are named by an `audit.reseal`
  entry, which `fileparcel audit verify` reports; it cannot tell who wrote them.
- Passkeys require a trusted certificate and a host name matching the passkey domain; changing the domain
  orphans existing passkeys.
- **Client certificates are not bound to the signed-in account.** With `mtls.mode = required` any valid,
  unrevoked client certificate of an active user is accepted, whoever then signs in on that connection:
  mTLS keeps unknown devices out, and the account is still decided by the sign-in. Revoke the certificate of
  a lost device at once.
- **Not yet run against the real services:** ACME has only been tested without a real certificate
  authority, Tailscale Funnel, Serve and certificates only against a stand-in for tailscaled, and the macOS
  `dns-sd` mDNS backend only against a stand-in for `dns-sd` (see
  [Known limitations](FILEPARCEL.md#known-limitations)).

## Hardening checklist

- [ ] Keep `network.access_mode` at `allowlist` (or `private`); allow only the networks you need.
- [ ] Open the host firewall only for those networks (`fileparcel doctor` prints the rules; see
      [Open the firewall](INSTALL.md#open-the-firewall)).
- [ ] Prefer a VPN (Tailscale, WireGuard) over port forwarding for remote access.
- [ ] Verify the CA fingerprint on every device you trust it on; or use a Tailscale/ACME certificate.
- [ ] Require 2FA for everyone (`auth.require_2fa = all`) if users access FileParcel from outside the LAN.
- [ ] Use full-disk encryption; consider sealed mode on portable or shared machines.
- [ ] Export the backup identity and (sealed mode) the recovery key; store them offline.
- [ ] Configure `backup.copy_to` to another disk and test a restore (`fileparcel backup restore --dry-run`). On a
      Linux system installation allow the directory with a `ReadWritePaths=` drop-in first (see
      [Backups and restore](FILEPARCEL.md#backups-and-restore)).
- [ ] Enable `network.strict_host` if you only use known names.
- [ ] Consider `mtls.mode = required` for small, fixed sets of devices.
- [ ] Give custom roles only the server permissions they need, read the warnings the role editor shows, and
      make sure staff accounts use a second factor (`fileparcel doctor`, *Two-factor authentication for staff
      accounts*).
- [ ] With Tailscale Funnel, publish share links only (`shares` mode) unless the whole app must be public;
      keep *Require two-factor sign-in over Funnel* on and *Allow administration over Funnel* off.
- [ ] Review the audit log regularly (`fileparcel audit list --outcome failure`, `audit verify`).
- [ ] Keep FileParcel updated; run `fileparcel doctor` after changes.

## Supported versions and updates

FileParcel releases are numbered `v1`, `v2`, … and published on the
[Releases page](https://github.com/kpdirectmail/fileparcel/releases). Security fixes are made in the newest
release; upgrade with `./install.sh` from the new release or `fileparcel upgrade fileparcel-vN.zip` (automatic
backup and rollback; see [Upgrade to a new version](INSTALL.md#upgrade-to-a-new-version)). There are no
separate long-term branches.

## Reporting a vulnerability

Please report security problems **privately** — not in a public issue, discussion, chat or forum. Use
GitHub's private vulnerability reporting:
**[Report a vulnerability](https://github.com/kpdirectmail/fileparcel/security/advisories/new)** (on the
repository: *Security* → *Report a vulnerability*). Only you and the maintainers can see the report.
Please allow reasonable time for a fix before you disclose the problem.

If you only use a FileParcel instance run by someone else, report problems with that instance to its
administrator (see `https://<server>/.well-known/security.txt`); report it here only if the problem is in
FileParcel itself.

A good report contains:

- the FileParcel version (`fileparcel version`) and platform (operating system, processor, user, system or
  Docker installation),
- the affected component (web app, API route, share links, CLI, installer, …) and the relevant
  configuration,
- steps to reproduce or a proof of concept, and the impact you expect,
- whether the issue is already public.

Leave out real passwords, keys, backup identities and personal data; a throw-away installation is enough
to show a problem.

Please do not access other people's data, degrade others' service or run automated scans against
instances you do not own.

**What to expect.** FileParcel is a volunteer project, so handling is best effort: the maintainers aim to
acknowledge a report within a few days, keep you informed while they investigate, fix confirmed problems
in a new release, and publish an advisory with it. Reporters are credited in the advisory if they wish.
There is no bug bounty.

## Delegated administration (roles)

Administrators can create custom roles that open parts of the administration to other accounts — for
example a helpdesk that resets passwords, or someone who reads the audit log — and give roles access to
folders and groups ([DESIGN.md §6a](DESIGN.md#6a-roles-and-permissions)). An administration route
therefore requires either a named permission of the caller's role or, for the surfaces listed below,
the built-in owner or admin role (see also
[Authorization](#authorization)). The design aims at one property: a delegate can never end up with more
power than administrators deliberately gave them.

- **Fail closed by construction.** A custom role is always based on the built-in Member or Guest role,
  never on Admin: every check that looks for an administrator — including one a future change forgets
  to convert — treats its holders as members or guests. A principal with a custom role whose permissions
  could not be resolved holds none; permission names the server does not know are ignored when read from
  the database; a settings section without a declared permission is administrator-only; and every
  administration route declares its guard, which the test suite checks against the running router for
  every built-in role and for a role holding each permission.
- **No escalation through delegation.** Someone who may manage accounts, reset sign-in or invite people
  acts only on, and hands out only, the built-in Member and Guest roles and custom roles an administrator
  marked as delegable, and only when the role's server permissions are a subset of their own. They never
  act on owners or administrators, never change their own role, quota or password policy, need the group
  permission to put people into groups, never see invitation links for roles they could not give, and
  need the reset-sign-in permission to move a deleted account's files to someone else. A non-delegable
  role also shields its holders: only administrators can reset their password or change their account.
  All of this is checked inside the write transaction against the current database rows.
- **Role management is administrator-only, with step-up.** Creating, editing or deleting a role is
  reserved to built-in owners and administrators, because whoever edits roles can grant anything. The
  same holds for sign-in, rate-limit, audit, e-mail, backup and server settings, encryption keys, custom
  certificates, backup download, restore and configuration, opening everyone's files, and seeing other
  people's share-link URLs. Giving a role with server permissions, changing anyone's role and creating
  an invitation for such a role require step-up.
- **Implied powers are stated, not hidden.** Several permissions reach further than their name
  suggests — managing accounts allows deleting accounts with their files, resetting sign-in allows
  signing in as the accounts one manages, managing groups allows joining any group's team folder. Each
  such permission carries a warning that the role editor shows before saving and the manual lists.
- **Changes apply immediately.** Permissions are resolved from the database on every request, for
  sessions and API tokens alike; step-up windows are closed when an account's role changes or its role
  gains server permissions; open event streams of affected accounts are closed so the web app reloads
  its permissions. Existing API tokens are not revoked by a role change: they lose whatever the new role
  does not allow on their next request.
- **API tokens.** Server permissions work on a token only with its `admin` scope, which can be minted
  only for an account with server permissions, and only after step-up. An `--elevated` token counts as
  elevated only while its account still has server permissions, and the token's account must be allowed
  to create tokens at all (guests are not).
- **No existence leaks.** Listings of who has access to what name only the items the caller could open
  (the rest are counted); the list of roles offered by the share dialog shows names and descriptions
  only to people who may search the user directory — so role descriptions must not contain secrets; and
  nothing about the role reaches a browser before the second factor.
- **Invitations.** Invitations for a role with server permissions (including Admin) need step-up, are
  single-use and expire within 7 days. An invitation for a custom role stops working when the role is
  deleted (deleting a role revokes its open invitations) or no longer matches; invitations are revoked
  when their creator loses the right to invite; and delegates never see the link of an invitation they
  could not have created.
- **Accountability.** Every role change, assignment, role grant and role group membership is audited,
  and so is every refused escalation attempt (`outcome: denied`, with the reason and the missing
  permissions).

Residual risks: permissions are coarse by design (managing accounts covers every delegable account, not
a chosen subset), an open event stream learns about changes that publish no event only when it
reconnects (at most 30 minutes; no data depends on it), and the limits of staff invitations are checked
when an invitation is created — revoke older multi-use invitations after giving their role server
permissions.

## Password-protected zip files

A "Bundle into a single .zip" upload can be protected with a password (DESIGN §8.1, §8.2): every file entry
of the .zip is encrypted with WinZip AES-256 (AE-2, the default) or, when chosen and allowed, the legacy
ZipCrypto. The zip password protects the file **after** it has left FileParcel; at rest the .zip is
encrypted like every other file as well (two independent layers, [ENCRYPTION.md §6](ENCRYPTION.md)).

**Lifecycle of the password.**

- It is sent once, in the JSON body of `POST /api/v1/upload-batches` (over TLS or the peer-checked admin
  socket; never in a URL), validated there before any data moves, and sealed at once with the field KEK
  into `upload_batches.zip_password_enc`, bound to the batch id by the AAD (a value copied to another row
  does not open). Resuming an upload never sends it again.
- The `upload.zip` job opens it right before it builds the .zip. The statement that moves the batch out of
  *open*/*finalizing* (done, failed, cancelled, expired) sets the column to NULL, and the hourly
  `maintenance.uploads` run clears any value left on an ended batch. It therefore lives at most
  `storage.upload_expiry_hours` while the upload is open and, while the .zip is being built, until the batch
  ends — a job interrupted by a restart or by locked keys is run again for up to the same time.
- It never appears in job parameters, results or errors, audit details (only `zip_encryption`), events, logs
  (`core.Secret` and `BatchInput.LogValue` redact it for `fmt` and `slog`), API answers, or the browser's web
  storage, cookies and IndexedDB (the web app keeps it only in the dialog's fields and the request body;
  `autocomplete="new-password"` and the password managers' ignore hints keep it from being saved as the
  FileParcel sign-in). Key rotation re-seals it; a backup taken while a batch is in flight contains the
  sealed value (as encrypted as the rest of the archive).
- Memory: derived keys, the opened value, the keystream and the plaintext buffers of the zip writer are
  cleared; Go strings (the decoded request, the password handed to the writer) cannot be, so the password
  is in memory briefly, like an account password at sign-in.

**Trust model.** The server sees the password and the plaintext files while it builds the .zip: this is
not end-to-end encryption. Whoever controls the server account (or a server with unlocked keys) during that
window can read the password. After the batch has ended FileParcel has no way to open the .zip, and a lost
password cannot be recovered.

**Strength of the format.**

- AE-2 derives its key with PBKDF2-HMAC-SHA1 and 1000 iterations, fixed by the format: an attacker with the
  .zip can test tens of millions of passwords per second on a GPU. The defences are the length (at least
  `storage.zip_password_min`, 12 by default, up to 99, because 7-Zip cannot open an AES-256 .zip with a
  longer password), the common-password list (shared with account
  passwords, also after stripping digits and symbols around a word), at least 4 different characters, the
  one-click generator (≈ 118 bits in the web app, ≈ 131 bits from the CLI) and the advice not to reuse the
  FileParcel password. Only printable ASCII is accepted, because unzip programs encode other characters
  differently.
- **ZipCrypto is broken**: a known-plaintext attack (Biham–Kocher, `bkcrack`) with about 12 known bytes
  recovers the keys, and the Store policy keeps exactly the files whose first bytes are well known (PNG,
  JPEG, PDF, ZIP, DOCX…). It only keeps casual eyes out. It is opt-in per upload, warned about, never
  remembered, and `storage.zip_legacy_encryption = false` removes it.
- **Metadata is not protected**: file and folder names, the folder structure, sizes (and so how well each
  file compresses), times and the number of entries are readable without the password.
- **Scope of the MAC**: AE-2 authenticates each entry's ciphertext on its own. Entries can be renamed,
  dropped, reordered or moved between archives that share a password without a reader noticing, and a
  ZipCrypto entry has only its CRC. Do not rely on the .zip to prove that its set of files is complete.
- Fresh random salts per entry (a repeated salt would repeat the AES keystream); `Options.Rand` exists for
  tests only and cannot be reached from the API.

**Who can create one.** Anyone who may upload into the destination folder (edit permission; `files:write`
for API tokens) — no extra permission. File requests are refused (422): an anonymous visitor would lock the
owner out of the upload and could fill the owner's quota with unreadable data. The lock badge
(`zip_encryption` on the file version) is set only by the zip job; no request can set or forge it.

**Command line.** The CLI never takes the password as a value on the command line: `--zip-password` asks
twice without echo, `--zip-password-stdin` and `--zip-password-file` read it for scripts, and
`--zip-generate-password` prints a generated one once. A word typed right after `--zip-password` is refused
before anything is sent, and flag errors never echo such a value.

**Denial of service.** Key derivation costs about a millisecond per entry, bounded by the batch limits, the
two concurrent `upload.zip` jobs, the quota and the free-disk checks; the second pass over a large entry is
cancellable (a job cancel stops inside the entry).

## Tailscale Funnel, Serve and VPNs

Tailscale Funnel adds a new adversary: **anyone on the internet** can reach the published address, without
passing the access policy's allowlist. Tailscale Serve and the VPN detection change what the tailnet and the
VPNs see. This section refines the controls above for them (design: DESIGN §10.1, §10.3, §10.6).

**Trust boundaries.**

```
 internet ─TLS─► Funnel relay ─► tailscaled ─HTTP/1.1─► run/ts-funnel.sock (0600, peer uid checked) ─► ingress checks ─► IngressGate ─► router
 tailnet  ─TLS─► tailscaled (Serve) ─────────HTTP/1.1─► run/ts-serve.sock  (0600, peer uid checked) ─► ingress checks ─► IngressGate ─► router
 LAN/VPN  ─TLS─► main listener (allowlist before TLS; refuses Tailscale-Funnel-Request)
 local CLI ───── admin socket (refuses proxied requests)
```

**Controls.**

1. **Separate listeners.** Funnel and Serve never target the main listener or the admin socket: each kind has
   its own listener, a Unix socket in the 0700 `run/` directory (mode 0600), or `127.0.0.1` with the peer's uid
   checked on Linux. Only root, the owner of tailscaled's socket and the server's own account may connect. A
   request on the Funnel listener is public whatever its headers say; with the policy off, the listener fails
   closed (404).
2. **Proxy headers are trusted only there.** `X-Forwarded-For` must be one valid, non-loopback address; the
   client-controlled `X-Forwarded-Host` must be the machine's MagicDNS name (and port); both become the
   request's client address and host, then every forwarding header, every `Tailscale-*` header and the CLI's
   `X-FP-As` are removed. The Funnel marker header can only restrict.
3. **Hand-made proxies are refused.** A request carrying `Tailscale-Funnel-Request` on the main listener is
   refused with 403 from any peer: it can only come from a `tailscale funnel` pointed at FileParcel's own port
   (on this machine or another tailnet node), which would make every visitor look like one allowed address.
   The admin socket refuses requests with forwarding or `Tailscale-*` headers, so `tailscale serve
   unix:<HOME>/run/admin.sock` cannot hand visitors the system principal. Foreign serve entries that target the
   main port or the admin socket fail the doctor (`network.funnel_bypass`); unconfigured local proxies
   (nginx, cloudflared, `tailscale serve localhost:8443`) are detected at runtime and reported.
4. **What the internet reaches.** *Share links only* is an allow-list of paths (`/s/<token>…` and the static
   files its page loads) with path hygiene; everything else is the same 404 as an unknown share token, and
   credentials (cookies but the public share cookies, `Authorization`, the CSRF header) are removed. *Full
   app* blocks setup, unlock, `/trust` and — unless explicitly allowed — administration.
5. **Sign-in over Funnel.** Only accounts with a second factor can sign in (others get the uniform
   invalid-credentials answer, so the password is not confirmed); sessions and tokens of accounts without one
   can only enrol a second factor. Failed attempts over Funnel never feed the persistent lockout (an internet
   attacker cannot lock accounts out of the LAN); they are limited per account over Funnel instead, and share
   passwords per share.
6. **Access policy and limits.** The deny list applies to the real client address over Funnel; Serve applies
   the full policy to the real tailnet address. Internet clients are rate-limited per address (IPv6 per /64)
   and globally, with in-flight caps per kind and per client. Changing the deny list does not cut an already
   open Funnel event stream (the policy is checked per request).
7. **Who can publish.** Reading the Funnel/Serve state needs the `network.manage` permission; changing it also
   step-up. Widening what the internet reaches needs a typed confirmation; weakening sign-in over Funnel
   (two-factor off, administration on) additionally needs a built-in owner or administrator. Every change is
   audited (`network.funnel`, `network.serve`).
8. **Binding to a device.** The Funnel settings record the Tailscale node they were enabled on, and a marker
   file records what FileParcel wrote: a restored backup or a copied installation never publishes on its own,
   and entries removed by an administrator are reported, not re-added.
9. **tailscaled is changed surgically.** Only FileParcel's own entries change; every write carries `If-Match`;
   FileParcel never runs `sudo` and never edits the tailnet policy. When Funnel is turned off, the listener is
   closed before the entry is removed, so nothing is served even if the removal fails. Tests cannot reach the
   real tailscaled.
10. **VPN roles.** Exit and privacy VPNs, corporate and zero-trust clients and public overlays are never
    offered as addresses, put into the certificate, announced over mDNS, added to the installation's
    allowlist, opened in firewall hints or counted as local for `keys.web_unlock = lan`: their address ranges
    belong to the provider, not to the operator's devices. Only strong signals (product names, product address ranges, the interface type, the default
    route) exclude an interface; `network.iface_roles` (step-up) corrects mistakes. Existing allow lists are
    never rewritten; the doctor reports allowed networks of outgoing VPNs and allowed public overlays.

**Residual risks.**

- **TCP backend.** When tailscaled does not accept socket targets for FileParcel's account, FileParcel listens
  on `127.0.0.1`. While FileParcel is stopped another local program could take that port and receive the
  Funnel traffic: FileParcel removes its entries on every clean stop, but they remain after a crash. On
  systems other than Linux the peer uid is not checked; a local user who connects there gains nothing
  (loopback is always allowed on the main port anyway).
- **Tailscale in userspace mode** (no TUN device) delivers tailnet connections from `127.0.0.1`, which is
  always allowed: the access policy does not apply to tailnet peers there. Reported as an exposure; use Serve.
- **Unconfigured reverse proxies and Cloudflare Tunnels** to FileParcel's port make every visitor look like
  the proxy; they are detected and reported, not blocked (blocking would break existing setups). Set
  `server.trusted_proxies` so the policy applies to the forwarded addresses.
- **Shared address ranges.** 100.64.0.0/10 is used by Tailscale, NetBird, NordVPN Meshnet, Cloudflare WARP and
  carrier-grade NAT; allowing it admits all of them on interfaces that carry it.
- **Share links are bearer secrets** and, with Funnel on, reachable from the internet; use passwords, expiry
  and download limits. An attacker can block one share's password form over Funnel for up to an hour.
- **`ts.net` is on the Public Suffix List**: every machine of the tailnet (and its Funnel) is same-site with
  FileParcel; the `__Host-` cookies and the CSRF checks handle it.
- **Event streams over Funnel.** In *full app* mode without administration over Funnel, a staff account's
  event stream still carries the server notifications its permissions receive (setting and network changes,
  job progress); no administration route is reachable.
- **Tailscale's side**: TLS for Funnel and Serve ends in tailscaled on this machine and Funnel traffic passes
  Tailscale's relays; Funnel has bandwidth limits and public DNS can take minutes to appear. Headscale has no
  Funnel.
