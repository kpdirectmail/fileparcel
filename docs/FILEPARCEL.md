# FileParcel User Manual

FileParcel is a self-hosted, self-contained file sharing server for your home or small office. One program runs the web app, the public share links and the admin command line; one directory
holds everything it needs. Files are encrypted at rest, the web app works on phones and desktops, and
every function is available both in the browser and on the command line.

This manual covers using, administering and running FileParcel: files and sharing, people and roles, the
network, certificates, encryption, backups, every setting and a troubleshooting FAQ. Two companion guides
cover the rest:

- [Installing FileParcel](INSTALL.md) — installing, the firewall, trusting the certificate, the first
  sign-in, VPNs and Tailscale, upgrading, moving and uninstalling.
- [The fileparcel command](COMMANDS.md) — the command line: how it reaches the server, remote use,
  scripting, recipes and the reference of every command and flag.

All three are shipped in every release (`docs/`) and copied into the installation directory
(`<HOME>/docs/`).

> **Conventions.** `<HOME>` is the FileParcel installation directory (for example
> `~/.local/share/fileparcel`). Commands starting with `fileparcel` are run on the server machine as the
> user that installed FileParcel (or with `sudo` for a system-wide installation). `sudo` is shown only
> where it is really needed.

## Table of contents

- [Overview](#overview)
- [Quick start](#quick-start)
- [Installation](#installation)
- [Using FileParcel](#using-fileparcel)
  - [Files and folders](#files-and-folders)
  - [Upload files and folders](#upload-files-and-folders)
  - [Password-protecting the .zip](#password-protecting-the-zip)
  - [Download files and folders](#download-files-and-folders)
  - [Preview files](#preview-files)
  - [Go back to an older version](#go-back-to-an-older-version)
  - [Get things back from the trash](#get-things-back-from-the-trash)
  - [Find files: search, recent and starred](#find-files-search-recent-and-starred)
  - [Share with people, groups and roles](#share-with-people-groups-and-roles)
  - [Share with a link](#share-with-a-link)
  - [Collect files with a file request](#collect-files-with-a-file-request)
  - [Use it on phones and tablets, or as an app](#use-it-on-phones-and-tablets-or-as-an-app)
  - [Keyboard shortcuts](#keyboard-shortcuts)
  - [Manage your account and security](#manage-your-account-and-security)
- [Administration](#administration)
  - [Roles and permissions](#roles-and-permissions)
  - [Manage user accounts](#manage-user-accounts)
  - [Invite people](#invite-people)
  - [Set up groups and team folders](#set-up-groups-and-team-folders)
  - [Confirming your identity (step-up)](#confirming-your-identity-step-up)
  - [The admin settings pages](#the-admin-settings-pages)
  - [Send e-mail (invitations and notifications)](#send-e-mail-invitations-and-notifications)
- [Network, VPNs and the access policy](#network-vpns-and-the-access-policy)
  - [Access over a VPN](#access-over-a-vpn)
  - [.local names and mDNS](#local-names-and-mdns)
  - [Share links on the internet (Tailscale Funnel)](#share-links-on-the-internet-tailscale-funnel)
  - [Tailnet address without a port (Tailscale Serve)](#tailnet-address-without-a-port-tailscale-serve)
- [Certificates and TLS](#certificates-and-tls)
- [Encryption at rest](#encryption-at-rest)
- [Backups and restore](#backups-and-restore)
- [Audit log](#audit-log)
- [Watch background jobs](#watch-background-jobs)
- [System, logs and maintenance](#system-logs-and-maintenance)
- [Upgrading](#upgrading)
- [Uninstalling](#uninstalling)
- [The installation directory](#the-installation-directory)
- [Command-line interface](#command-line-interface)
- [Configuration reference](#configuration-reference)
- [Security model](#security-model)
- [Packages used](#packages-used)
- [Known limitations](#known-limitations)
- [Troubleshooting and FAQ](#troubleshooting-and-faq)
- [License](#license)

---

## Overview

**What FileParcel does**

- **Your files, in your browser.** A personal space ("My files") for every user and a team folder for
  every group. Upload single files, many files or whole folders (drag and drop, with nested and empty
  folders), optionally bundled into one `.zip` while uploading — and that `.zip` protected with a
  password (AES-256) if it is going to travel. Uploads are resumable, run in parallel and survive flaky
  Wi-Fi.
- **Sharing.** Share with other users, groups and roles (view, edit or manage), or create **share links**
  for anyone — with password, expiry date, download limit, preview-only mode and a QR code. **File
  requests** let people without an account upload into one of your folders.
- **Roles and permissions.** Every account has a role: Owner, Admin, Member, Guest, or one you create
  ("classes"). A custom role can open parts of the administration (people, groups, settings, network,
  certificates, backups, monitoring) and get folders and groups of its own; account managers can never give
  more than they have.
- **Previews, versions, trash and search.** Image, video, audio, PDF and text previews; the last versions
  of every file; a trash with configurable retention; fast name search (substring).
- **Security by default.** HTTPS only, with a local certificate authority created at install time
  (or Let's Encrypt, a Tailscale certificate or your own certificate). Two-factor authentication
  (authenticator app, passkeys, recovery codes), required by default for admins and every role with
  server permissions. Sessions, API tokens,
  optional client certificates (mTLS), rate limits, account lockout, a strict Content Security Policy with
  Trusted Types and a tamper-evident audit log.
- **Encryption at rest.** Every file, thumbnail and backup is encrypted (AES-256-GCM, or
  ChaCha20-Poly1305 on CPUs without AES instructions). Secrets in the database are encrypted too. The
  master key can be kept in a file (automatic start) or sealed with a passphrase (the server starts
  locked until you unlock it).
- **Private by network.** An access policy decides which networks may connect at all: by default your
  local network(s) and the VPNs that reach the server (Tailscale/Headscale, WireGuard, ZeroTier, NetBird,
  Nebula, NordVPN Meshnet, OpenVPN and more; outgoing-only VPNs such as NordVPN or Mullvad are recognised
  and left out). Connections from anywhere else are closed before TLS starts. Share links can be put on
  the internet with **Tailscale Funnel** when you choose to.
- **Found on the network.** The server announces itself as `fileparcel.local` (mDNS/Bonjour) and shows
  every URL it can be reached at — with QR codes for phones.
- **Backups.** Scheduled, encrypted (age), compressed backups with retention rules, verification and
  one-command restore.
- **Self-contained.** Binary, configuration, database, encrypted files, keys, certificates, backups, logs
  and the admin socket all live in one directory. Uninstalling removes the service and keeps your data
  unless you ask it to delete everything (`--purge`); the whole installation can be moved to another disk
  or machine ([Move FileParcel](INSTALL.md#move-fileparcel)).
- **Everything from the command line.** The same binary is the admin CLI. It talks to the running
  server over a local socket, works directly on the directory while the server is stopped, and can
  manage a remote server with an API token.
- **Runs almost anywhere.** Linux (x86-64, ARM64, ARMv7 — including every Raspberry Pi from the Pi 2 on)
  and macOS (Intel and Apple silicon), as a systemd or launchd service, or in Docker. No database
  server, no runtime, no dependencies.

**How it fits together**

```
  phones / laptops / browsers                     fileparcel (one process)
  ─────────────────────────────                   ──────────────────────────────────────────────
   https://fileparcel.local:8443  ──┐   allow?    ┌ listener: access policy (LAN/VPN allowlist)
   https://192.168.1.10:8443       ──┼──────────►  │ TLS (local CA / ACME / Tailscale / custom)
   https://host.tailnet.ts.net    ──┘             │ web app + REST API + public share links
                                                  │ jobs: thumbnails, zips, backups, cleanup
  fileparcel CLI ── admin socket (run/admin.sock) ┤ SQLite database (metadata)
                                                  └ encrypted blob store (file contents)
                                                        │
                                            <HOME>/  (config, data, keys, certs, backups, logs)
```

**Where to find what**

| To… | Read |
|---|---|
| Install FileParcel, open the firewall, trust its certificate and sign in for the first time | [Installing FileParcel](INSTALL.md) |
| Reach it from phones, over a VPN, or put share links on the internet | [Reach FileParcel from other devices](INSTALL.md#reach-fileparcel-from-other-devices); the details are under [Network, VPNs and the access policy](#network-vpns-and-the-access-policy) here |
| Upgrade, move to another disk or machine, or uninstall | [Upgrade](INSTALL.md#upgrade-to-a-new-version), [move](INSTALL.md#move-fileparcel) or [uninstall](INSTALL.md#uninstall-fileparcel) in the installation guide |
| Work with files, share them and collect uploads in the web app | [Using FileParcel](#using-fileparcel) |
| Manage people, roles, groups and settings | [Administration](#administration) |
| Understand certificates, encryption, backups and the audit log | the chapters from [Certificates and TLS](#certificates-and-tls) on |
| Manage FileParcel from a terminal or a script | [The fileparcel command](COMMANDS.md) |
| Look up every command and flag | [Command reference](COMMANDS.md#command-reference) |
| Look up every setting | [Configuration reference](#configuration-reference) |
| Fix a problem | [Fix installation problems](INSTALL.md#fix-installation-problems) and [Troubleshooting and FAQ](#troubleshooting-and-faq) |
| Read the security design | [SECURITY.md](SECURITY.md) and [ENCRYPTION.md](ENCRYPTION.md) |

---

## Quick start

Download the release zip `fileparcel-vN.zip` from the
[Releases page](https://github.com/kpdirectmail/fileparcel/releases/latest), unpack it and run the installer
as your normal user (no `sudo` needed):

```sh
unzip fileparcel-v1.zip
cd fileparcel-v1
./install.sh
```

Press Enter to accept the suggested answers, or run `./install.sh -y` to skip the questions. The installer
installs FileParcel into `~/.local/share/fileparcel` (on a Mac: `~/Library/Application Support/FileParcel`),
starts it as a service and prints a summary. Then:

1. **Save the admin password and the backup identity** from the summary: both are shown only once.
2. **Open the firewall** if the summary prints commands for it:
   [Open the firewall](INSTALL.md#open-the-firewall).
3. **Trust the certificate** on each device, starting at `https://<server>:8443/trust`:
   [Trust FileParcel's certificate on your devices](INSTALL.md#trust-fileparcels-certificate-on-your-devices).
4. **Sign in** as `admin`, choose a new password and set up two-factor authentication:
   [Sign in for the first time](INSTALL.md#sign-in-for-the-first-time).
5. **Invite people** (Admin → Invites, or `fileparcel invite create`) and start uploading.

With Docker instead: [Run FileParcel in Docker](INSTALL.md#run-fileparcel-in-docker).

---

## Installation

[Installing FileParcel](INSTALL.md) is the complete guide to installing and running the server:

| Topic | In the installation guide |
|---|---|
| Requirements, and which way to install | [Before you start](INSTALL.md#before-you-start) |
| Downloading and checking a release; building from source | [Download FileParcel](INSTALL.md#download-fileparcel) |
| Every `install.sh` option, the installer's questions and what it does | [Choose installer options](INSTALL.md#choose-installer-options) |
| User service, system service or no service | [Run it as a user or a system service](INSTALL.md#run-it-as-a-user-or-a-system-service) |
| Debian, Raspberry Pi, Fedora, Arch, Alpine, macOS and Windows | [Notes for your operating system](INSTALL.md#notes-for-your-operating-system) |
| Docker and Docker Compose | [Run FileParcel in Docker](INSTALL.md#run-fileparcel-in-docker) |
| ufw, firewalld, nftables, pf and the macOS firewall | [Open the firewall](INSTALL.md#open-the-firewall) |
| Trusting the local certificate authority on each device | [Trust FileParcel's certificate on your devices](INSTALL.md#trust-fileparcels-certificate-on-your-devices) |
| The first sign-in and what to set up first | [Sign in for the first time](INSTALL.md#sign-in-for-the-first-time) |
| `.local` names, the access policy, VPNs, Tailscale Serve and Funnel | [Reach FileParcel from other devices](INSTALL.md#reach-fileparcel-from-other-devices) |
| Upgrading, moving and uninstalling | [Upgrade](INSTALL.md#upgrade-to-a-new-version), [Move](INSTALL.md#move-fileparcel), [Uninstall](INSTALL.md#uninstall-fileparcel) |
| Problems while installing or connecting | [Fix installation problems](INSTALL.md#fix-installation-problems) |

This manual explains what lies behind those steps: how FileParcel classifies VPNs
([Access over a VPN](#access-over-a-vpn)), how it announces its `.local` name
([.local names and mDNS](#local-names-and-mdns)) and what its certificate authority may vouch for
([The local certificate authority](#the-local-certificate-authority)).

---

## Using FileParcel

The web app works in every current browser (Chrome, Edge, Firefox, Safari, Brave, Samsung Internet) on
desktops, tablets and phones. Everything described here can also be done on the command line
(`fileparcel files …`, `fileparcel access …` for sharing with people, groups and roles,
`fileparcel share …` for links, `fileparcel request …` for file requests; see
[Files & sharing](COMMANDS.md#files--sharing) and [access](COMMANDS.md#access--give-users-groups-or-roles-access-to-folders)
in the command guide).

### Files and folders

- **My files** is your personal space. Guests (and roles based on Guest) have no personal space; they only see
  what is shared with them or their role.
- **Team folders** belong to groups; the sidebar lists each one under *Workspace* by the group's name.
  Every member can add and change files; group managers can also share them and manage access.
- **Shared with me** lists files and folders other users shared with you.
- Folders open with a click (or Enter); files open a preview. Select several items with Ctrl/⌘-click,
  Shift-click or the checkboxes; on touch screens a long press starts selecting. Right-click (or the ⋮
  button, or a long press on phones) opens the actions: download, share, rename (F2), move, copy, star,
  versions, details, move to trash (Del).
- Drag items onto a folder to move them (desktop). **Copy** is instant, even for huge files: the copy
  shares the stored (encrypted) data until one of them changes. One copy takes at most 20,000 files and
  folders in total; copy larger trees in parts.
- **Names**: up to 255 bytes, no `/`, `\`, control characters or text-direction overrides (which
  can disguise an `.exe` file as a `.pdf`), not `.` or `..`, no leading or
  trailing spaces. Names are compared case-insensitively (`Report.pdf` and `report.pdf` cannot be in the
  same folder) and stored in Unicode NFC, so names typed on macOS and Linux match. Trailing dots are
  allowed but trigger a warning because Windows cannot handle them.
- **Name conflicts** (uploading, moving or copying an item with an existing name): *keep both* adds
  ` (1)`, ` (2)`, … before the extension; *replace*, when uploading or copying, makes the new file the
  current version of the existing one (the old content stays available under Versions); when moving, it
  moves the existing file to the trash (with its versions, shares and links, which stop working while it
  is there; restore it from the trash until the trash retention deletes it) and puts the moved file in its
  place; *skip* leaves the existing item alone. *Replace* only puts a file in place of a file: when a
  folder is among the conflicting items, nothing is moved and you are asked again, without *replace*.
- The details panel (`i`) shows size, type, dates, who changed it, the versions, the shares and the
  activity. Folder details include the total size and number of items.
- **Quotas**: your storage usage (including older versions and the trash) is shown in the sidebar;
  administrators can set per-user quotas and a default quota.

### Upload files and folders

- **Upload files** (the *Upload* button, `u`, or the ⊕ button on phones), **Upload folder** (keeps the
  folder structure, including empty sub-folders; not available on iPhone/iPad because iOS cannot pick
  folders), or simply **drag and drop** files and folders anywhere onto the window — mixed files and
  folders work. System files (`.DS_Store`, `Thumbs.db`, `desktop.ini`) are left out; a folder that held
  nothing else is still created, empty.
- Before the upload starts a dialog lets you choose the destination, the conflict policy (with "apply to
  all") and **"Bundle into a single .zip"**: the uploaded files and folders are packed into one zip file
  (with the paths preserved) on the server. Zipping runs as a background job after the upload; its
  progress is shown in the jobs indicator. If the server restarts while it zips, the zipping starts over
  within the hour — the uploaded files are kept until it is done. The .zip can also be
  [protected with a password](#password-protecting-the-zip). Existing names are checked before anything
  is sent: with *skip*, files whose names are taken are not uploaded at all, and a .zip whose name is
  taken is not built; *replace* onto a folder of the .zip's name is refused at once.
- Large files are sent in 8 MiB parts, four at a time, each checked with SHA-256; failed parts are
  retried automatically with a growing delay. When a folder of many small files reaches the server's
  request rate limit, the whole upload waits as the server asks and then continues more slowly, without
  failing any file. You can pause, resume and cancel single files or the whole
  queue; a file you paused on its own stays paused when you resume the whole upload. The queue shows speed
  and remaining time, keeps the screen awake while uploading and warns before you close the tab.
- **Resuming after a reload or crash:** unfinished uploads are listed in a *resume* card. Browsers cannot
  remember the files themselves, so select the same files again; FileParcel matches them by path, size and
  modification time and only sends the missing parts. Unfinished uploads are discarded after
  `storage.upload_expiry_hours` (48 h). The list belongs to the signed-in account and is dropped at sign-out,
  so another account on the same browser never sees it. Unfinished uploads of your account that this
  browser does not know — started on another device, in a browser whose site data was cleared, or by a
  command-line upload that was killed — are listed too, with a **Discard** button, once they have been
  idle for an hour, and at once when an upload is refused for lack of space or for the limit of 20
  unfinished uploads per account: until they are discarded or expire, they hold the space they reserved
  and count towards that limit.
- **Limits:** the maximum file size (`storage.max_file_gb`, unlimited by default; 8 TiB per uploaded file
  in any case), your quota, and free disk space — FileParcel refuses uploads that would leave less than
  1 GiB or 2 % of the disk free. A "Bundle into a single .zip" upload is one file: the zip, a little larger
  than the files in it, must fit the maximum file size and your quota, which is checked before anything is sent.
- Uploads from the command line: `fileparcel files put ~/Pictures/Trip "/My files/Photos" -p` (folders are
  uploaded recursively; `-p` creates `/My files/Photos` if it does not exist yet; `--zip Trip.zip` bundles
  them).

### Password-protecting the .zip

A "Bundle into a single .zip" upload can be protected with a password, so that whoever gets the .zip — by
download, a share link, e-mail or a USB stick — needs that password to open the files in it.

1. Choose the files, turn on **Bundle into a single .zip**, then **Protect the .zip with a password**.
2. Pick the encryption: **AES-256** (recommended, and the only choice when the administrator has turned
   ZipCrypto off) or **ZipCrypto** (see the warning below).
3. Type the password twice, or press **Generate a strong password**: the password appears in a field of
   its own; copy it (the copy button also ticks the box) or tick **I've saved this password** — the upload
   does not start before that. Keep it in a password manager.
4. **Upload.** The files are sent as usual; the server builds the encrypted .zip afterwards.

The password must have at least `storage.zip_password_min` characters (12 unless the administrator changed
it) and at most 99 (7-Zip and the apps built on it cannot open an AES-256 .zip with a longer password),
only letters, digits, spaces and the symbols of a US keyboard (unzip apps encode other characters
differently, so an `é` or `€` could make the .zip impossible to open), no space at the start or
the end, at least 4 different characters, and it must not be a common password. The dialog checks most of
this as you type (a longer pasted password is refused, never cut); if the server still refuses the
password (a common one, say, or one shorter than a minimum the administrator raised after the page was
loaded — the dialog and its generator then use the new minimum), the dialog opens again with the reason
under the field — nothing was uploaded yet, and your other choices are kept. Do not reuse
your FileParcel password.

Every file in the .zip is encrypted; **file and folder names, sizes and dates stay visible** to anyone who
has the .zip (the zip format cannot hide them). The .zip gets a lock in the file list, *Protection:
Password · AES-256* (or *ZipCrypto (weak)*) in its details, and a lock on its versions; its job in Admin →
Jobs (and `fileparcel jobs show`) names the encryption. A link to it tells visitors that the .zip is
password-protected and whom to ask for the password.

**Which apps can open it**

| App | AES-256 | ZipCrypto |
|---|---|---|
| 7-Zip / `7z` / `7zz` (Windows, Linux, macOS) | yes | yes |
| WinRAR, WinZip, PeaZip, Bandizip | yes | yes |
| Windows File Explorer | no | yes (asks for the password) |
| macOS Archive Utility (double-click) | no ("Unable to expand") | yes (asks for the password) |
| Keka, The Unarchiver, BetterZip (macOS) | yes | yes |
| Info-ZIP `unzip` (Linux, macOS Terminal) | no (skips the files: unsupported method) | yes (`unzip -P` or a prompt) |
| `bsdtar` built with a crypto library | yes | yes |
| Android: ZArchiver, RAR | yes | yes |
| iOS Files, the file managers built into Android | not reliable — use a zip app | not reliable |
| Python `zipfile` | no | yes |

**Things to know**

- **ZipCrypto is weak.** It is there only because the unzip built into Windows and macOS opens nothing
  else. Anyone with a little time can usually recover the files without the password (in minutes when the
  .zip holds pictures, PDFs or Office documents, whose first bytes are well known). Use it to keep casual
  eyes out, never for sensitive files. An administrator can turn it off.
- **FileParcel does not keep the password.** It holds it, encrypted, only while the upload is in
  progress — until the .zip is built, the upload is cancelled or it expires — and cannot show it again.
  A lost password cannot be recovered, by you, an administrator or anyone else: upload the files again
  with a new one.
- **Send the password separately** — not in the same e-mail or chat message as the link or the file, and
  preferably over another channel. A share link's *Require a password* is a different lock: it protects
  opening the link, while the .zip's password protects the file after it has been downloaded.
- **The clipboard.** The copy button puts the password on the clipboard, where clipboard history or
  sync between devices may keep it; clear it when you are done.
- **Resuming** an interrupted upload never asks for the password again: the server already has it.
- The protection belongs to that version of the file: replacing the .zip with an unprotected upload, or
  restoring an unprotected version, removes the lock; copies keep it. **File requests** cannot produce
  password-protected .zips (the visitor would hold a password the owner does not know).
- From the command line: `fileparcel files put` with `--zip NAME.zip` and `--zip-password` (asks twice),
  `--zip-password-file FILE`, `--zip-password-stdin` or `--zip-generate-password`; `--zip-encryption
  zipcrypto` chooses the weak method.

Administrators set the rules in Admin → Settings → Storage: `storage.zip_password_min` (minimum length,
default 12, 8–64) and `storage.zip_legacy_encryption` (whether ZipCrypto may be chosen, default on).
Batches created before a change keep the rules they were created with.

**Troubleshooting**

- *Windows says the .zip is invalid, or opens it but shows nothing / asks for no password* — it is an
  AES-256 .zip, which File Explorer cannot open: use 7-Zip (or WinRAR), or upload it again with ZipCrypto
  if the recipient cannot install anything.
- *macOS says "Unable to expand"* — the same for Archive Utility: use Keka or The Unarchiver (free), or
  `7zz x file.zip` in Terminal.
- *"This password is too common"* — it is on the common-password list, also with numbers or symbols
  added around it (`Password1234!`); choose something less predictable or generate one.
- *"ZipCrypto is turned off on this server"* — the administrator turned it off after the page was loaded;
  the dialog now offers AES-256 only.
- *I lost the password* — it cannot be recovered; FileParcel never stored it in a readable form.

### Download files and folders

- Download a file with a click on *Download* (or from the preview). Downloads can be resumed by the
  browser or a download manager (HTTP range requests are supported).
- Several items or folders are downloaded as one **.zip** that is streamed while it is being created — no
  waiting, no temporary copy on the server. Already compressed files (photos, videos, archives, office
  documents, PDFs) are stored without compressing them again, everything else is compressed
  (`storage.zip_compression`). Empty folders and non-ASCII names are preserved.
- On macOS, choose **.tar** instead of zip for very large folders (Archive Utility has problems with some
  streamed zip64 files).
- Command line: `fileparcel files get "/My files/Report.pdf"`, `fileparcel files get "/My files/Photos" --zip`.

### Preview files

Images (PNG, JPEG, GIF, WebP, AVIF, BMP) with zoom, videos (MP4, WebM, Ogg, QuickTime) and audio with
seeking, PDFs, and text and source code files open in a preview overlay; use the arrow keys to move to
the next or previous file (while the text of a file has the focus, ← and → scroll it instead).
Thumbnails of images up to 50 megapixels are generated in the background and stored encrypted (formats
that take more memory to decode, such as progressive or CMYK JPEGs, get one up to a lower size).

For your safety, types that could run code in the browser (HTML, SVG, XML, JavaScript) are **never**
displayed — they are always downloaded, and every preview is served with a sandboxing Content Security
Policy. Whether a video plays depends on the codecs your browser supports.

### Go back to an older version

When a file is replaced (upload with *replace*, or saved again by a sync tool), the previous content is
kept as a **version**. Details → Versions lists them with date, size and author; download any of them or
**restore** one: it moves to the top of the list as the current version, and the content it replaces stays
as a version — nothing is lost, and a restore never pushes another version out. Its file type is detected
again from its content. The number of versions kept per file is `storage.versions_keep` (10, including the
current one): when a new version goes over it, the oldest one is deleted at once, and a daily job
applies a lowered limit to existing files. Versions count towards the quota (a replacement that pushes the
oldest version out needs room only for the difference). Uploading exactly the same content again with
*replace* adds no version: the file already is up to date, and no second copy is charged. Command line:
`fileparcel files versions "/My files/budget.xlsx"`.

An older version is always delivered as a download, never shown in the browser: nothing records the file
type a past version was stored with, and the current type must not be assumed to describe it. Restore the
version first if you want to view it.

### Get things back from the trash

Deleted items go to the **Trash**, where they can be restored (to their original folder, renamed if the
name is taken meanwhile) or deleted forever. An item whose folder is in the trash too goes back to the top
folder of its space — if you may add items there; otherwise (you work in a folder someone shared with you)
restore the folder first, or together with the item. The trash is emptied automatically after
`storage.trash_days` (30 days; 0 = never). *Empty trash* deletes at once everything you may delete
permanently: the trash of your own space and of the team folders you manage. Items from other team
folders, or that you deleted in folders shared with you, stay until the owner or a group manager deletes
them (or the retention period ends); the app tells you how many are left. Deleting a very large
folder forever is done in batches, so it does not hold up everything else writing to the database; an
interrupted purge leaves part of the folder behind and the next purge (or the daily clean-up) continues
where it stopped. The stored data of permanently deleted files is removed by a daily clean-up job;
because each file has its own encryption key and the key lives only in the database, deleting the
database row makes the data unrecoverable even before the file on disk is removed.

### Find files: search, recent and starred

- **Search** (Ctrl/⌘+K or `/`) finds files and folders by any part of their name (case-insensitive, the
  way names are compared: `strasse` finds `Straße.txt`; terms of three or more characters use a fast
  index) in your spaces and in what is shared with you. Filter by space and by type. File contents are not
  indexed. An administrator with `auth.admin_can_access_files` searches another user's space by choosing
  it as the location (recorded as `admin.file_access`); *All locations* and **Recent** cover only their
  own spaces and what is shared with them.
- **Recent** shows what changed lately in your spaces; **Starred** lists items you starred.
- **Activity** shows your own recent actions (sign-ins, uploads, shares, …).

### Share with people, groups and roles

*Share* (or Details → Sharing) → *Add people, groups or roles*: choose a person, a group or a custom role (shown
with a shield: everyone who has the role, including people who get it later) and the access. On the command
line this is an **access grant**, for example `fileparcel access grant /Team/Design --user bob --level edit`
([access](COMMANDS.md#access--give-users-groups-or-roles-access-to-folders)); the audit log records it as
`grant.set`.

| Access | Can |
|---|---|
| **Can view** (viewer) | see, preview and download the item (and everything inside a shared folder) |
| **Can edit** (editor) | additionally upload, create folders, rename, move within, trash and restore |
| **Can manage** (manager) | additionally share it with others, change who has access and create links and file requests for it; in someone's personal files, deleting forever and moving out stay with the owner |

An optional expiry date ends the access automatically; someone whose access to an item comes from an
expiring share cannot share it with a group or role they belong to for longer than their own access lasts
(so they cannot make their own access permanent). Shared items appear under *Shared with me* for the
recipients. Only people who can manage an item (the owner of the personal space, a manager of the
group whose team folder it is, or someone it was shared with at *Can manage*) can share it. People you did not
share an item with cannot even see that it exists. Finding people and roles to share with needs *Find people and
roles*, which Members have; built-in roles cannot be chosen (share with a group instead). See
[Roles and permissions](#roles-and-permissions).

### Share with a link

A **share link** (`https://<server>/s/<random token>`) gives anyone with the link access to a file or
folder, without an account. Create one from the *Share* dialog (it also shows a **QR code** for phones)
or with `fileparcel share create "/My files/Holiday" --expires 7d --qr`.

Options:

| Option | Meaning |
|---|---|
| Password | Visitors must enter it first (they get a 12-hour access cookie). Attempts are rate-limited (each address gets the sign-in allowance, `ratelimit.login_per_min`, per link; wrong ones are also capped per link across all addresses) and logged. Changing the password logs out everyone who used the old one. |
| Expiry | The link stops working at this date. New links expire after `sharing.default_expiry_days` (7) by default; administrators can set a maximum (`sharing.max_expiry_days`), counted from the creation of the link: an owner can shorten the expiry but not extend a link beyond it. |
| Download limit | The link stops working after N downloads (previews do not count; a download resumed after an interruption may count again). Turn off *Allow previews* if every access must count. |
| Allow download / preview | Turn off downloads for a preview-only link, or previews for a download-only link. |
| Title and message | Shown to visitors. |

The share page lists folder contents, previews files and offers single downloads and a zip of
everything.

A folder link made with `fileparcel share create --upload` (or `share edit --upload`) also has an **Add
files** area: visitors can upload into the folder they are looking at (files with a name that is taken are
renamed). A link that accepts uploads but allows neither downloads nor previews works as a drop box:
visitors see only the upload area, never the folder's contents. (A [file request](#collect-files-with-a-file-request)
is the dedicated way to collect files; it never shows the folder at all.)

**When a link stops working.** A link is marked *unavailable* and shows a "not found" page while:

- the shared item is in the trash (until it is restored),
- its owner's account is disabled (until it is enabled again), or
- its owner can no longer open the item, because a share or a group membership was taken away (until the
  access is given back). A file request also needs its owner to be able to add files to the folder.

Invalid, expired and deleted links show the same "not found" page, so nobody can probe which links exist.

**My links** lists your links with their state (active, expired, exhausted, disabled), download counts and
an **access log** (views, downloads, wrong passwords, with IP address and time; entries older than
`sharing.access_log_days`, 365 by default, are deleted daily). You can edit, disable (reversible) or delete a
link at any time. Editing or re-enabling it needs the same right as creating it (*manage* on the item, and
`sharing.allow_guests_share` for guests); disabling and deleting it do not.

Administrators can disable share links entirely (`sharing.links_enabled`), require passwords
(`sharing.require_password`), and see every user's links and file requests with
`fileparcel share list --all-users` / `fileparcel request list --all-users` (API:
`GET /api/v1/admin/shares`; the web app lists only your own links, and the Admin dashboard shows the
number of active ones). An administrator can disable, re-enable (`fileparcel share disable <id>` /
`share enable <id>`) or delete another user's link, but cannot change anything else about it. With
`sharing.require_password` on, the *New link* and *New file request* dialogs arrive with **Require a
password** already switched on and locked, and a link rejected for a missing or unusable password shows
the server's reason on the password field itself rather than failing without a visible message.

`fileparcel share list --all-users` / `request list --all-users` show another user's link URL only when
`auth.admin_can_access_files` is on; otherwise the URL column is left out entirely and the command says
why.

### Collect files with a file request

A **file request** is a public upload link for one of your folders: people without an account can upload
files (and folders) into it, but cannot see what is already there — a request cannot be switched to allow
downloads or previews (use a link for that), and it stops working when you can no longer add files to the
folder yourself. Create one from the folder's *Share*
menu → *New file request* or with:

```sh
fileparcel files mkdir "/My files/Inbox"
fileparcel request create "/My files/Inbox" --title "Photos from the party" --expires 14d --max-size 2G --quota 20G --require-name --qr
```

Options: title and message, password, expiry, maximum file size, total upload quota, "ask for the
uploader's name" (the name is recorded in the request's access log and the audit log, and appears in the
upload notification; files from all uploaders land in the same folder), and e-mail notification
to you on every upload (when [e-mail is set up](#send-e-mail-invitations-and-notifications)). Uploads count against **your** quota; name conflicts are
resolved by keeping both. `fileparcel request close <id>` stops accepting uploads (reversible).

### Use it on phones and tablets, or as an app

The web app adapts to the screen: a sidebar on desktops, an icon rail on tablets, and on phones a bottom
tab bar (Files, Shared, the ⊕ upload button, Links, More), bottom sheets for actions and large touch
targets. On phones, long-press an item for its actions.

FileParcel can be **installed as an app** (PWA): Chrome/Edge/Android → *Install app* / *Add to home
screen*; Safari on iOS → Share → *Add to Home Screen*. The installed app can receive files (not links or
text) from other apps' *Share* menu (Android). Installing needs a trusted certificate (see
[Trust FileParcel's certificate on your devices](INSTALL.md#trust-fileparcels-certificate-on-your-devices)); Settings →
Devices explains the steps for the current device.

### Keyboard shortcuts

Press `?` to see all shortcuts.

| Keys | Action |
|---|---|
| Ctrl/⌘+K, `/` | Search and command palette |
| `?` | Show the keyboard shortcuts |
| `u` | Upload files |
| Shift+N | New folder |
| `g` then `f` / `s` / `l` / `r` / `*` / `t` / `p` / `a` | Go to My files / Shared with me / My links / Recent / Starred / Trash / Settings / Admin |
| `v` | Switch between list and grid |
| `i` | Show or hide the details panel |
| Alt+↑, Backspace | Parent folder (*Shared with me* from the top of a folder shared with you) |
| ↑ ↓, Enter | Move the selection, open |
| Ctrl/⌘+A, Esc | Select all, clear the selection |
| F2 | Rename |
| Del | Move to trash |

### Manage your account and security

Settings (the avatar menu) has these pages:

- **Profile**: display name, e-mail address, language-neutral preferences. Changing the e-mail address
  (where security alerts go) needs [step-up](#confirming-your-identity-step-up), and the previous address
  gets a security alert about it. The page also names your [role](#roles-and-permissions); **What can I do?**
  lists its permissions.
- **Security**:
  - **Password** — changing it signs out all your other sessions. Passwords must have at least
    `auth.password_min` (12) characters; very common passwords and passwords containing your username are
    refused.
  - **Authenticator app (TOTP)** — scan the QR code (or type the secret) in any authenticator app, confirm
    with a code. You then receive **10 single-use recovery codes**: store them offline. Each code works
    once in place of an authenticator code; generate new ones any time (the old ones stop working). If you
    still have unused codes (from your first passkey), they stay valid and no new ones are shown.
  - **Passkeys** — sign in with Face ID, Touch ID, Windows Hello, Android screen lock or a security key.
    Passkeys are bound to the server's name (by default `fileparcel.local`), so they work on the URLs with
    that name and need a trusted certificate. Several passkeys can be registered and renamed. Your **first**
    passkey also hands out the 10 recovery codes, shown once, if you do not have any yet: they are the way
    back in if an administrator ever turns passkeys off.
  - Adding an authenticator app or a passkey, and removing your second factor, need
    [step-up](#confirming-your-identity-step-up): a new factor can itself confirm your identity (and a
    passkey signs you in on its own), so someone who got hold of a signed-in browser must not add their own.
    Adding one also e-mails you a security alert. If administrators require 2FA (`auth.require_2fa`), you
    must set it up at your next sign-in before you can do anything else (confirm with your password first).
- **Sessions**: every signed-in browser with device, IP address and last activity; sign out one or all
  others (from the web interface only: API tokens cannot see or end sessions). Sessions end after 12 hours of inactivity (`auth.session_idle_min`); "Remember me" sessions last
  up to 30 days (`auth.session_max_days`), others end with the browser (at most 24 hours). *Keep me signed
  in* on the sign-in page applies to a sign-in with a passkey alone too.
- **API tokens**: personal tokens (`fpt_…`) for scripts and the remote CLI, with scopes (`files:read`,
  `files:write`, `shares`, `admin`) and an expiry. Creating a share link needs `shares` and `files:read`;
  a file request or a link that accepts uploads needs `files:write` as well, and so does turning uploads on
  for an existing link. Listing who has access to an
  item needs `files:read`. The secret is shown once. A token is refused while its
  owner still has to set up two-factor authentication (`auth.require_2fa`). Tokens use
  `Authorization: Bearer fpt_…` and cannot confirm your identity; admin-scope tokens need step-up when
  they are created. A token can create further tokens (the remote CLI's `token create`) only with a subset
  of its scopes and never outliving itself: without an expiry the new token expires with the one that
  created it. A token can revoke itself and tokens with no more scopes than its own, not wider ones.
  Revoke a leaked token's children too — they are listed with your other tokens. The
  settings page manages your own tokens and passkeys only, also for administrators. Creating tokens needs the
  *Create API tokens* permission of your role (Members have it, Guests do not; existing tokens keep working and can
  be revoked), and the `admin` scope is offered only when your role has server permissions.
- **Appearance**: light, dark or system theme, list or grid, compact density. *Default file view* starts on
  the value that is actually in effect — your own choice if you made one, otherwise the server's
  `ui.default_view` — instead of on no choice at all.
- **Devices**: how to install the CA and the app on this device; your client certificates when
  [mTLS](#client-certificates-mtls) is used.

**Signing in** uses your username and password, then your authenticator code, a recovery
code or a passkey. A passkey alone can also sign you in (the *Sign in with a passkey* button, or the
browser's passkey suggestion in the username field). After `auth.lockout_threshold` (10) wrong passwords
in a row (wrong second factors, step-up confirmations and current passwords count too; a correct one
starts the count over), the account is locked for 15 minutes, doubling with each further lockout up to
24 hours; administrators can unlock it (`fileparcel user unlock <name>`). While it is locked, a browser
that is still signed in cannot confirm your identity or change the password either, and says so. Error
messages at sign-in never reveal whether a username exists.

---

## Administration

Owners and administrators see an **Admin** section: Dashboard, Users, Groups, Roles, Invites, Settings, Network &
VPN, Certificates, Encryption, Backups, Audit log, Jobs and System. The dashboard shows users, files, storage and
free disk space, active shares and uploads, running and failed jobs, the key state, the certificate, the
last backup, recent audit entries and warnings (expiring certificate, no recent backup, …). Accounts whose
[role](#roles-and-permissions) has server permissions see the same section with only the pages those permissions
open; without *Server status* their Admin page is **Your admin areas**, a card for each of those pages.

### Roles and permissions

Every account has exactly one **role**. The role decides what the account may do; which files and folders it can
open follows from its own files, its groups and what is shared with it — or with its role. There are four
**built-in roles**, and administrators can add **custom roles** (also called *classes*) for anything in between: a
helpdesk that resets passwords, auditors who read the audit log, contractors who see one folder. Admin → Roles lists
them all with how many people have each (`fileparcel role list`).

#### Built-in roles

| Role | Permissions | Description |
|---|---|---|
| **Owner** | every permission, plus what only administrators can do | The first account, created at installation. Everything an admin can do, including managing other owners; admins cannot change, demote or delete an owner. At least one active owner must remain. |
| **Admin** | every permission, plus what only administrators can do | Runs the server: people, roles, groups, invitations, settings, network, certificates, encryption, backups, jobs and the audit log. Cannot change owners. |
| **Member** | the four *Sharing & account* permissions | The role of new accounts and invitations. Has a personal space (*My files*), uses the team folders of their groups, shares, creates links and file requests (when enabled), finds people and roles, and creates API tokens. |
| **Guest** | none | No personal space; only sees what others share with them or their role. Creates links and file requests only while `sharing.allow_guests_share` is on. A guest with no folder they may write to is not offered the Upload button, the mobile upload button or the "Upload files" / "New folder" commands; a guest who has been granted **Editor** on a shared folder gets them back. |

Built-in roles cannot be changed or deleted; **Duplicate** on a built-in role's page makes an adjustable copy. A
permission that a later version adds reaches owners and admins automatically.

**Administrators cannot see other users' files** by default. If you need that (for example in a small
company), set `auth.admin_can_access_files` to `true`: admins then get *manage* access to every space,
and every such access is recorded in the audit log (`admin.file_access`). Search reaches another user's
space only when the admin picks it as the search location. A share link an admin creates this
way is recorded once, when it is created; its visits appear in the link's access log. Only built-in owners and
admins get this access, never a custom role.

Access to files is decided per item, inherited by everything inside a folder:

| Level | Who has it | Allows |
|---|---|---|
| View | *Can view* shares (with a person, a group or a role) | list, preview, download |
| Edit | group members (directly or through their role), *Can edit* shares | + upload, create folders, rename, move within, trash, restore |
| Manage | group managers (directly or through their role), *Can manage* shares | + share with people, groups and roles, create links and file requests |
| Owner | the owner of a personal space | + delete forever, transfer |

#### Custom roles (classes)

A custom role has a name, a description, a set of permissions and a **base**:

- **Based on Member**: the people who have it get their own *My files*.
- **Based on Guest**: no personal space; they see only what is shared with them or with the role.

The base decides nothing else, and it cannot be changed later (that would create or delete the personal space of
everyone with the role): duplicate the role instead. A custom role is never based on Admin. Its power on the server
comes only from the permissions it is given, so an account with a custom role is never treated as an administrator
— not even by a check that does not know about roles.

**Creating a role:** Admin → Roles → **New role** (a bottom sheet on phones; asks you to
[confirm your identity](#confirming-your-identity-step-up)): name, description, *Based on*, and *Start from* — the
recommended defaults (Member's four permissions, or none for a role based on Guest), a built-in role or another
custom role (*Admin* starts with every permission a custom role can have). The role's page then opens on its tabs:

- **Permissions** — a switch per permission, in the groups of the table below, with a *High impact* badge on the
  risky ones. Turning a permission on also turns on what it needs (*Manage accounts* brings *View people*, which
  stays on while it is needed). Changes collect in a bar at the bottom: **Save changes** (or Ctrl/⌘+S) shows what
  is added — the high-impact permissions with their warning — and removed, and how many people it affects, and
  applies it at once, also to people who are signed in. Leaving the page with unsaved changes asks first. The
  *Details* card holds the name, the description and whether account managers may give the role (below).
- **People** — who has the role. **Add people** gives it to more accounts, one after another (each confirmed:
  they lose their current role); *Change role…* in a person's ⋮ menu moves them to another role.
- **Folders** and **Groups** — see [Giving a role access to folders and groups](#giving-a-role-access-to-folders-and-groups).

**Deleting a role** (its page, or ⋮ on Admin → Roles; step-up) asks for the role its people get instead —
required while anyone has it — and then for the role's name. Its open invitations are revoked, its folder shares
removed and it leaves its groups. Moving its people to a role based on Guest takes their *My files* away, so that
works only while those are empty.

Examples:

| Role | Based on | Permissions | Access |
|---|---|---|---|
| Helpdesk | Member | Member's four + *Manage accounts*, *Reset sign-in* (they bring *View people*) | – |
| Auditors | Guest | *Audit and server logs*, *Server status* | – |
| Finance | Member | Member's four | group Finance (manager), folder `/Team/Company/Reports` (edit) |
| Contractors | Guest | *Create file requests* | folder `/Team/Design/Briefs` (view) |
| Staff without public links | Member | Member's four without *Create share links* | – |
| Operator | Member | Member's four + *Operate the server*, *Run backups*, *Audit and server logs* | – |

On the command line:

```sh
fileparcel role create helpdesk --from member --add users.manage,users.credentials --description "Resets passwords"
fileparcel role create contractors --base guest --add shares.requests
fileparcel role edit helpdesk --remove users.credentials
fileparcel role show helpdesk          # permissions with their warnings, people, groups, folders
fileparcel role permissions            # every permission and what it allows
fileparcel user set-role bob helpdesk
fileparcel role members helpdesk
fileparcel role delete contractors --reassign-to guest
```

Role names have 1–64 characters, are unique regardless of case, do not start with `rol_` (the ids of custom roles),
contain no invisible characters such as a zero-width space (which would let a second "Finance" look like the
first; group and display names refuse them too) and are none of `owner`, `admin`, `administrator`, `member`,
`guest`, `system`, `everyone`, `all` and `none`;
descriptions have at most 500 characters; a server has at most 200 custom roles. Everyone who may search the user
directory (*Find people and roles*) sees the names and descriptions of the custom roles when sharing: keep secrets
out of them.

#### Permissions

The Permissions tab groups them: *Sharing & account* (the first four) shapes an ordinary account; *People*,
*Content*, *Server* and *Monitoring* hold the **server permissions**, which open parts of the Admin area. An account
whose role has at least one server permission is **staff**. Some permissions come with another one they need; the
risky ones are marked *High impact*, and their warning is shown before a role with them is saved and by
`fileparcel role show`.

| Permission | In the web app | Allows | Opens |
|---|---|---|---|
| `shares.links` | Create share links | Create public links to files and folders they manage (only while share links are enabled in Settings → Sharing). | *Create link* in the Share dialog, *My links* |
| `shares.requests` | Create file requests | Create upload links that let anyone add files to a folder they manage (only while file requests are enabled). | *New file request*, *File requests* |
| `users.lookup` | Find people and roles | Search the user directory and the list of roles when sharing. | people and roles to choose from in the Share dialog |
| `tokens.create` | Create API tokens | Create personal access tokens for the command line and scripts. Removing this stops new tokens; existing tokens keep working until they are revoked. | *New token* in Settings → API tokens |
| `users.view` | View people | See accounts (including e-mail addresses and last sign-in), groups, roles and who has access to what. | Admin → Users, Groups and Roles to look at, the Access card |
| `users.manage` | Manage accounts | Create, edit, disable, enable, unlock and delete accounts and give them roles: Member, Guest and the roles an administrator allows — never accounts or roles with server permissions this role does not have. Comes with *View people*. **High impact:** Can delete accounts together with their personal files, and create accounts with a password they choose. | *New user*, the account forms and actions on Admin → Users |
| `users.credentials` | Reset sign-in | Reset passwords and two-factor authentication, see and end sessions, and manage other people's passkeys and API tokens, for the accounts they may manage. Comes with *View people*. **High impact:** Can reset passwords, and so sign in as the accounts they manage and open their files. | *Reset password*, *Reset two-factor* and *Sessions* on a user's page |
| `invites.manage` | Invite people | Create, list and revoke invitation links for the roles they may give. Comes with *View people*. | Admin → Invites |
| `groups.manage` | Manage groups | Create, rename and delete groups and their team folders, change members and managers, and make roles members of groups. Comes with *View people*. **High impact:** Can add themselves to any group and open its team folder; deleting a group deletes its team folder. | the changes on Admin → Groups and on a role's *Groups* tab |
| `shares.manage` | Manage everyone's links | List every share link and file request, see their access logs, disable, enable and revoke them. The links themselves stay hidden. | `fileparcel share list --all-users` and the API (the web app lists only your own links; Admin → Dashboard says where to go) |
| `settings.manage` | General settings | Change Settings → General (except maintenance mode), Storage and Sharing. **High impact:** Can change quotas and upload limits, how long deleted files and old versions are kept, and the rules for public links. | Admin → Settings → General, Storage and Sharing |
| `network.manage` | Network & VPN | Change the network access policy, mDNS, VPN and Tailscale Serve/Funnel settings. **High impact:** Can make the server reachable from the internet, or lock everyone out. | Admin → Network & VPN, and the Network and Local name (mDNS) settings |
| `certs.manage` | Certificates | Renew and configure TLS certificates (ACME, Tailscale, the local certificate authority) and mTLS, and issue and revoke client certificates. Uploading a custom certificate stays with administrators. **High impact:** Can replace the local certificate authority (every device must trust it again) and require client certificates. | Admin → Certificates, and the TLS, ACME certificates, Tailscale and Client certificates settings |
| `backups.run` | Run backups | List, start and verify backups (not download, restore, delete or configure them). | Admin → Backups (*Back up now*, verify) |
| `system.view` | Server status | See the dashboard, system information, health checks and background jobs. | Admin → Dashboard, Jobs and System |
| `system.manage` | Operate the server | Restart the server, turn maintenance mode on or off (and keep working during it), change the log level, and run or cancel maintenance jobs. Comes with *Server status*. **High impact:** Can restart the server and put it into maintenance mode. | *Restart*, *Run maintenance*, cancelling jobs, and the maintenance and log settings |
| `audit.view` | Audit and server logs | Search, verify and export the audit log and read the server log. Both show names and addresses from everyone's activity. | Admin → Audit log, and the log on Admin → System |

#### What only administrators can do

These are never part of a custom role; only built-in owners and admins can:

- create, change and delete roles (whoever edits roles can give anything to anyone);
- change the settings Sign-in & security, Rate limits, Audit, Email, Backups, Encryption and Server (except the
  log level and the memory limit, which come with *Operate the server*), and every future section not assigned to a
  permission, and send a test e-mail;
- manage the encryption keys (Admin → Encryption), and upload or remove a custom certificate;
- download, restore, delete and import backups and change the backup schedule, keys and settings (*Run backups* only
  lists, starts and verifies them);
- open everyone's files (`auth.admin_can_access_files`) and see the addresses of other people's share links;
- change administrator accounts, and give the admin role (changing owner accounts and giving the owner role is for
  owners only).

#### Letting account managers give a role

People with *Manage accounts*, *Reset sign-in* or *Invite people* who are not administrators — account managers —
may give roles (creating accounts, changing roles, inviting) and manage accounts only within these limits:

- they may give, and manage the accounts of, Member, Guest and the custom roles an administrator marked
  **Account managers can give this role and manage its accounts** (the role's *Details* card;
  `fileparcel role edit helpdesk --delegable`), and only while all of that role's server permissions are ones they
  have themselves;
- never owners or administrators, and never an account whose role has server permissions they lack;
- never their own role, quota or password rule (their own profile, password, sessions and API tokens stay theirs to
  change in Settings);
- adding people to groups when creating accounts or invitations needs *Manage groups*, and giving an invitation a
  storage quota needs *Manage accounts*; moving a deleted account's files to someone else needs *Reset sign-in*
  (and never into their own account);
- their open invitations stop working once they could no longer create them (the role is no longer allowed for
  account managers, or has server permissions they lack).

New roles are not given out by account managers until an administrator allows it: a custom role can carry folders
and groups, so handing it out — or resetting the password of someone who has it — is access to those folders. To
keep a group of people (the finance director, say) out of every account manager's reach, give them a custom role
that account managers may not give. Role pickers list the roles you may not give as well, disabled, with the reason.

#### Giving a role access to folders and groups

What a role gives access to applies to everyone who has the role, including people who get it later, and ends for
whoever loses it. It adds to what people have through their own files, their groups and shares with them personally.

- **Folders and files.** Open *Share* on a folder or file you manage, type the role's name — it is listed with a
  shield as "Role · everyone with this role" — and choose *Can view*, *Can edit* or *Can manage*. Or, on the role's
  **Folders** tab, **Give folder access**: pick a folder you manage, the access and an optional last day. The tab
  lists the role's folders with where they are; items in someone's personal files that you cannot open are only
  counted. On the command line: `fileparcel access grant /Team/Company/Reports --role finance --level edit`
  (`access list`, `access revoke … --role finance`). Built-in roles cannot be shared with: use a group.
- **Groups.** On the role's **Groups** tab, **Add to a group** makes everyone with the role a member of the group
  (with *Managers of the group* on, a manager), so they see its team folder:
  `fileparcel role add-group finance Finance --manager`. The group's page lists those roles under **Roles in this
  group** (they can be added, changed and removed there too) and shows for each member whether they are there
  directly or through a role; a membership that comes from a role is changed on the role, or by changing the
  person's role. Individual memberships are kept. Changing the groups of a role needs *Manage groups*.

#### Checking who can open what

The **Access** card on a user's page (Admin → Users) shows what the account can reach: its role (with *What can this
role do?*), whether it has *My files*, the role's server permissions (or "Nothing on the server — a regular
account."), its groups and team folders — directly or through the role — and what is shared with the account,
one of its groups or its role, with the level and the end date. Items you cannot open yourself, such as someone's
personal files, are only counted. With *Reset sign-in* the card also counts the account's API tokens with the
`admin` scope; an owner or admin while `auth.admin_can_access_files` is on is flagged as able to open everyone's
files. On the server, `fileparcel access check bob /Team/Company/Reports` explains what one account may do with one
item, and why. Everyone sees their own role in Settings → Profile, where **What can I do?** lists its permissions.

#### Delegated administration, step-up and two-factor authentication

- Staff who are not administrators see only the Admin pages their permissions open, and the buttons their role does
  not allow are left out. A page outside the role — a link someone sent, say — shows "Your role does not include
  this page". The server checks every request on its own; the web app only leaves out what would fail.
- They [confirm their identity](#confirming-your-identity-step-up) for the same actions as administrators.
- `auth.require_2fa = admins` (the default) covers every account whose role has a server permission, not only
  administrators: someone who gets such a role sets up two-factor authentication at their next sign-in.
  `fileparcel doctor` lists staff accounts without it.
- API tokens: creating one needs *Create API tokens*. The `admin` scope is offered only to staff, and server
  permissions work on a token only with it. A role change never revokes tokens; they lose on their next request
  whatever the new role does not allow.
- A role change takes effect at once, in every session: the navigation and the page on screen follow ("Your access
  was changed by an administrator."), and a page that is no longer allowed gives way to the "not allowed" page.
- The audit log records every role change (`role.create`, `role.update`, `role.delete`), every role given to an
  account (`user.update`), folder shares with a role (`grant.set`) and role memberships of groups
  (`group.role_set`, `group.role_remove`). Attempts to give a role or manage an account beyond one's own role are
  recorded as *denied*.

#### Troubleshooting roles

- **"this needs the “Audit and server logs” permission"** (or another permission), **"Your role does not include
  this page"** — the account's role does not include it. An administrator adds the permission to the role on
  Admin → Roles, or gives the account another role; the change applies immediately.
- **"administrators have not allowed account managers to give the role “Finance”"** — an administrator turns on
  *Account managers can give this role and manage its accounts* on the role's page, or gives the role themselves.
- **"you can only give roles whose server permissions you have yourself (missing: …)"**, **"this account has server
  permissions you do not have (…)"**, **"accounts with the role “Finance” can only be managed by an
  administrator"** — account managers cannot give or manage more than their own role allows; ask an administrator.
- **"ask an administrator to change this on your own account"** — only an administrator changes an account
  manager's own role, quota or password rule.
- **"1 account has this role: choose a role to move it to"** when deleting a role — choose the role its people get
  instead (`--reassign-to` on the command line).
- **"… still has personal files (…): move or delete them first, or reassign to a member-based role"** — moving
  people to a role based on Guest removes their *My files*, which must be empty first (the trash included).
- **"“bob” is a member through the role “Finance”; remove the role from the group or change their role"** — a
  membership that comes from a role cannot be removed on the group's page.
- **Someone lost a team folder after a role change** — they were in the group through their old role: add them to
  the group directly, or add their new role to the group.
- **"invitations for roles with server permissions can be used once"**, **"invitations for roles with server
  permissions expire within 7 days"** — such an invitation creates staff, see [Invite people](#invite-people).

### Manage user accounts

Admin → Users (or `fileparcel user …`) lists the accounts with their role; the role filter (also by custom role,
kept in the address) is what the people counts of Admin → Roles open. With *View people* the pages are there to
look at; *Manage accounts* and *Reset sign-in* add the controls below, for the accounts the role may manage (see
[Letting account managers give a role](#letting-account-managers-give-a-role)); administrators have them all.

- **Add** a user with a role, e-mail, quota and either a password you set, a generated password (shown
  once) or "must change at first sign-in". Usernames are case-insensitive. Generated passwords are 22
  random letters and digits, or `auth.password_min` if that is longer. A user who must change the
  password can use nothing but their own settings until they have (their older API tokens keep working).
- **Edit** display name, e-mail, role (needs step-up) and **quota** (`fileparcel user set-quota alice 50G`,
  `unlimited`, `default`). Without an individual quota, `storage.default_quota_gb` applies.
- **Role** — the role picker lists the built-in roles and the custom roles with their base; the roles you may not
  give are listed too, disabled, with the reason. Changing the role says what changes before it is saved: the person
  loses their current role, gets or loses *My files* (losing it works only while it is empty) and starts or stops
  seeing the Admin area, which may ask them to set up two-factor authentication. It applies to their open sessions
  at once (`fileparcel user set-role bob helpdesk`).
- **Access** — the card that shows what the account can reach, see
  [Checking who can open what](#checking-who-can-open-what).
- **Reset password** (step-up; generated or chosen), **unlock** a locked account, **reset 2FA** (removes
  the authenticator, recovery codes and passkeys; step-up) when someone lost their phone. A password or 2FA
  reset also signs the user out everywhere and revokes their API tokens.
- **Disable / enable** — a disabled user cannot sign in, their sessions and tokens stop working and their
  links stop working; nothing is deleted. The active invitations they created are revoked, and enabling
  the account does not restore them. Demoting an owner or admin to member or guest does the same, and so does
  taking *Invite people* away from someone (a role change, or a change to their role).
- **Sessions** — see and revoke a user's sessions.
- **Delete** (step-up) — removes the account and its personal space. With `--transfer-to USER`
  (`fileparcel user delete bob --transfer-to alice`) the files are moved into a folder in the other
  user's space first (for account managers this also needs *Reset sign-in*). The active invitations they created
  are revoked.

### Invite people

An invitation is a link (`https://<server>/invite/<token>`) that lets someone create their own account
with a preset role, groups and quota. Admin → Invites → *New invitation*, or:

```sh
fileparcel invite create --role member --group Family --expires 7d --uses 1 --email bob@example.com --send
fileparcel invite create --role contractors --expires 3d --uses 5
```

`--send` e-mails the link ([e-mail must be set up](#send-e-mail-invitations-and-notifications)); otherwise
copy it (it is also shown as a QR code). If the e-mail cannot be sent, the invitation is still created and you
get a warning: pass the link on yourself.

- **Expiry and uses.** Invites expire (default 7 days), can be used a limited number of times and can be
  revoked. An invitation that names an e-mail address creates one account with that address, so it can only
  be used once, and it cannot be created while an account already uses the address; leave the address empty
  for a link several people may use.
- **Role.** Any role but Owner, custom roles included; the sign-up page says which role the person will join
  as. An invitation for a role with server permissions — Admin, or a custom role with a server permission —
  creates an account that can use the Admin area, so it can be used once, expires within 7 days, and
  creating it, and seeing its link again in the list, needs step-up.
- **Groups and quota.** Adding the new account to groups needs *Manage groups*, and giving it a storage quota
  other than the default needs *Manage accounts*.
- **Checked again when used.** If its role has since gained a server permission, the invitation must still be
  single-use and at most 7 days old; if an account manager created it, they must still be able to create it
  today (the role still allowed for account managers, its server permissions still theirs). Otherwise the link
  says it is invalid — and a role change or role edit that has this effect revokes such invitations at once, so
  the list shows them as revoked. Deleting a role revokes its open invitations.
- **Who sees the link.** Administrators and the invitation's creator see its link in the list; other people
  with *Invite people* see it only when they could create the same invitation (they may give its role, and it
  adds no groups or they have *Manage groups*) — otherwise the row says "Link hidden: only administrators can
  see it".
- **The note** (`--note`) is a message to the invited person: it is shown on the sign-up page to anyone who
  opens the link and included in the e-mail, so keep private remarks out of it.

### Set up groups and team folders

Every group has a **team folder**, which its members see in the sidebar under *Workspace*, by the group's
name (for example *Family*). Members can edit;
**managers** can additionally share its contents and create links. Create groups in Admin → Groups or with
`fileparcel group create Family`, then `fileparcel group add-member Family alice --manager`. Group names
are unique regardless of case (`Équipe` and `équipe` are the same name). Deleting a group deletes its team
folder (move files out first).

A **role** can be a member of a group too: everyone with the role is then a member — or a manager — of the group
and sees its team folder, including people who get the role later
([details](#giving-a-role-access-to-folders-and-groups); `fileparcel role add-group finance Finance`). Admin →
Groups shows how many roles each group has; the group's page lists them under **Roles in this group** and shows
for each member where the membership comes from (*Direct*, or *Role: Finance*). A membership that comes only from a
role is changed on the role, not on the group's page; someone who is a member both ways stays in the group when you
remove them. Changing members, managers and roles needs *Manage groups*; with *View people* the pages are read-only.

### Confirming your identity (step-up)

Sensitive actions require that you confirmed your identity within the last `auth.stepup_min` minutes (10):
changing roles or deleting users, resetting others' passwords or 2FA, key and certificate operations,
changing the network policy, turning Tailscale Funnel or Serve on or off (or changing them), restoring, deleting or
downloading backups, changing settings in the *auth, network, tls, acme, tailscale, funnel, mtls, keys, backup, server,
mdns* and *email* sections, adding an authenticator app or a passkey,
removing your own second factor, changing your own e-mail address, creating admin-scope API tokens, and creating admin
invitations or showing their links. The web app asks
for your password, an authenticator code or a passkey when needed. The local CLI (admin socket) is always
trusted, because it requires access to the server account.

With [roles](#roles-and-permissions), "changing roles" covers creating, changing and deleting roles, giving an
account a different role, and creating an account with a role that has server permissions; the admin invitations
above are all invitations for a role with server permissions. Account managers and other staff who are not
administrators confirm their identity for the same actions as administrators.

### The admin settings pages

Admin → Settings groups all runtime settings into sections. Each field shows its default; changed values
can be reset. A few settings need a restart; a banner then offers **Restart now**. Settings overridden by
an environment variable are shown as such and cannot be changed in the web app.

A saved value that the server accepts but cannot fully apply — a `tls.extra_sans` or `network.extra_hosts`
name the local CA is not allowed to sign, for instance — is reported as *"Saved with warnings"* on the form
instead of taking effect silently. Changing the instance name takes effect in the session that saved it
straight away (the sidebar, the browser title and the About dialog); other open sessions pick it up on
their next reload.

While some accounts have no second factor other than a passkey, turning passkeys off or moving the passkey
domain — the RP ID, or while that is empty the mDNS name or the server name — would shut them out, so the
form asks for confirmation first and says how many accounts are affected (on the command line, add
`--force` to `fileparcel config set`/`unset` or `fileparcel network mdns name`). Having those users add an
authenticator app, or resetting their two-factor authentication, avoids the question.

| Section | What it controls |
|---|---|
| General | Instance name, accent colour, default theme and view, sign-in message |
| Sign-in & security | Password length, 2FA requirement, passkeys, session lifetimes, lockout, step-up window, admin file access |
| Sharing | Share links, file requests, password requirement, expiry limits, guest sharing |
| Storage | Quotas, maximum file size, trash and version retention, uploads, zip compression, .zip passwords (minimum length, ZipCrypto), cipher, thumbnails, fsync |
| Network | Strict Host check, extra host names (the access mode and the allowed and denied networks are set on Admin → Network & VPN, which guards against locking yourself out) |
| Local name (mDNS) | Publishing mode, `.local` name, interfaces, ZeroTier |
| TLS | Extra certificate names, HSTS, minimum TLS version, certificate lifetime |
| ACME certificates | Let's Encrypt (or another ACME CA): domains, challenge, DNS provider and credentials |
| Tailscale | Tailscale HTTPS certificates |
| Tailscale Funnel | Tailscale Funnel and Serve: mode, ports, administration and two-factor sign-in over Funnel, the device, how tailscaled reaches FileParcel (turned on and off on Admin → Network & VPN; the values set there are read-only here) |
| Client certificates | Client-certificate (mTLS) requirement, share-link exemption, self-service |
| Rate limits | Sign-in, API, share and unlock rates |
| Encryption | Where the sealed server may be unlocked from |
| Backups | Schedules, retention, encryption, recipients, identity, copy destination |
| Email | SMTP server and which notifications are sent; *Send test e-mail…* checks the saved settings (owners and admins; `fileparcel config test-email --to ADDRESS` on the command line) |
| Audit | Retention, JSON-lines mirror |
| Server | Name, ports, listen addresses, public URL, trusted proxies, log level, memory limit (stored in `fileparcel.toml`) |

Every setting, its default and its meaning is listed in the
[Configuration reference](#runtime-settings). The same settings are available on the command line:
`fileparcel config list`, `fileparcel config get auth.require_2fa`,
`fileparcel config set storage.trash_days 60`, `fileparcel config unset storage.trash_days`.

### Send e-mail (invitations and notifications)

FileParcel sends e-mail through a mail server (SMTP) you already use: your e-mail provider's or your
company's. It needs one for:

- invitations you send by e-mail (*Email the link* in the invitation dialog, `fileparcel invite create --send`);
- notifications about uploads through your [file requests](#collect-files-with-a-file-request);
- security alerts to the person concerned (lockouts, new passkeys or API tokens, two-factor resets).

Without it everything else works: you pass invitation links on yourself, and nobody gets notifications.

**Set it up in the web app:** Admin → Settings → Email (owners and admins). Fill in:

| Field | Typical value |
|---|---|
| SMTP server (`smtp.host`) | your provider's mail server, for example `smtp.example.com` |
| SMTP port (`smtp.port`) | `587` (the default), or `465` |
| SMTP encryption (`smtp.tls`) | `starttls` for port 587 (the default), `tls` for port 465 |
| SMTP username and password | your mail account; many providers want an *app password* here |
| Sender address (`smtp.from`) | for example `FileParcel <files@example.com>` (without it: the username, when that is an e-mail address) |

Save, then press *Send test e-mail…*. If sending fails, it shows the mail server's answer. *Notifications*
(`notify.events`) chooses which notifications are sent.

**Or on the command line** (the password is read from standard input and never shown):

```sh
fileparcel config set smtp.host smtp.example.com
fileparcel config set smtp.username files@example.com
printf '%s' "$SMTP_PASSWORD" | fileparcel config set smtp.password
fileparcel config set smtp.from "FileParcel <files@example.com>"
fileparcel config test-email --to you@example.com
```

**Links in e-mails.** An invitation e-mail links to `server.public_url` when it is set, otherwise to the
server's recommended address (its `.local` name or LAN address). An upload notification links to the folder
only when `server.public_url` is set. If the people you write to reach FileParcel under another name, set
`server.public_url` (see the [fileparcel.toml](#fileparceltoml) table: it also changes share links and the
passkey domain).

---

## Network, VPNs and the access policy

FileParcel listens on all interfaces (`server.bind = ["::"]`, IPv4 and IPv6) but only talks to clients
the **access policy** allows. The check happens when a connection is accepted — a refused client gets no
TLS handshake, no page, nothing. A policy change also applies to devices that are already connected: an
open connection from an address that is no longer allowed is closed at its next request, and within
two seconds at the latest (which also ends its live updates).

| Mode (`network.access_mode`) | Who may connect |
|---|---|
| `allowlist` (default) | Loopback plus the networks in `network.allow_cidrs`, which the installer fills (see below). |
| `private` | Loopback and all private and VPN ranges: `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `169.254.0.0/16`, `100.64.0.0/10`, `fc00::/7`, `fe80::/10`, plus the allowlist. |
| `any` | Every address. Only for servers deliberately exposed to the internet (the admin pages then show a warning). |

What the installer puts into the allowlist:

- the private subnets of your LAN and Wi-Fi interfaces, and their IPv6 prefixes (a network with a public
  IPv4 address, such as a cloud server's, is left out with a note: add the networks that should connect
  with `--allow`);
- the ranges of the VPNs other devices come in through: the Tailscale ranges (`100.64.0.0/10`,
  `fd7a:115c:a1e0::/48`) when Tailscale or Headscale is present, and the subnets of WireGuard, ZeroTier and
  other VPN interfaces — never an outgoing-only VPN's ([Access over a VPN](#access-over-a-vpn)).

`network.deny_cidrs` always wins; loopback (`127.0.0.1`, `::1`) is always allowed so that the local CLI and
recovery always work.

```sh
fileparcel network                        # URLs, interfaces and the policy
fileparcel network urls --qr              # every URL with a QR code
fileparcel network interfaces             # how each interface was classified
fileparcel network allow add 10.8.0.0/24  # allow a network
fileparcel network deny add 192.168.1.66  # block one device
fileparcel network mode private
```

**Lockout guard.** A policy change in the web app that would lock out the address you are connected from
is refused unless you confirm it; on the command line, add `--force`. From the server itself you can always
repair the policy with the CLI.

**Access URLs.** For every address of a LAN/Wi-Fi interface or a VPN devices come in through (not container
bridges, outgoing-only VPNs or link-local IPv6) FileParcel lists `https://<ip>:<port>/`, plus `https://<name>.local:<port>/` when mDNS is active, the MagicDNS name,
`server.public_url` and names from `network.extra_hosts`/`tls.extra_sans`. Each URL shows whether the
certificate covers it and whether it is publicly trusted.

**Strict Host check** (`network.strict_host`) makes FileParcel answer only requests addressed to its own
names and IPs — protection against DNS-rebinding attacks from malicious web pages. Add names you use with
`network.extra_hosts`.

**Behind a reverse proxy.** FileParcel is designed to terminate TLS itself. If you nevertheless put it
behind a proxy (Caddy, nginx, Traefik): proxy to `https://<server>:8443` (verify with the local CA), set
`server.trusted_proxies` to the proxy's address so that `X-Forwarded-For` is honoured for the client IP,
and set `server.public_url` to the external URL (used in links, invitations and for passkeys). That URL is
scheme, host and port only: FileParcel is served from the root of its host, so give it a host name of its
own on the proxy rather than a sub-path such as `/files`. The access
policy then applies twice: to the proxy's own address when it connects (allow it; a proxy on the same
machine connects from loopback, which is always allowed) and to the client address the proxy forwards,
on every request (refused with 403). So the deny list and the allow list keep working for the clients
behind the proxy; for a proxy that serves the internet, use access mode `any` (the deny list still
applies). The proxy must set `X-Forwarded-For` (Caddy does it by default; nginx:
`proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;`): without it every request looks like the proxy.

**Changing ports and names.** `fileparcel config set server.https_port 9443` (or `server.http_port`,
`server.bind`, `server.name`) — these are stored in `fileparcel.toml` and need a restart
(`fileparcel service restart`). Ports below 1024 need a system installation. On a Linux system
installation, moving to or from a port below 1024 also changes the service unit (it gets
`CAP_NET_BIND_SERVICE` only for such a port): apply the change with `sudo fileparcel service install --start`,
which rewrites `/etc/systemd/system/fileparcel.service` for the configured ports and restarts the service,
instead of `service restart` or **Restart now** — otherwise the server cannot bind the new port and keeps
failing to start. Renaming the server changes the `.local` name, the local certificate and the passkey
domain (existing passkeys stop working). The new `<name>.local` is announced at once; the certificate
keeps the old name as well until the restart, so the address you use right now keeps working until then.

### Access over a VPN

Setting up a VPN step by step is described under [Over a VPN](INSTALL.md#over-a-vpn) in the installation
guide. This section is the reference: how FileParcel classifies each VPN, and what follows from that.

FileParcel recognises VPN interfaces and decides for each one whether other devices can reach the
server through it. Those VPNs get their addresses in the access URLs and in the local certificate,
their address ranges in the allowlist created at installation, and firewall rules in the printed hints.
VPNs that only carry this machine's *outgoing* traffic get none of that.

| Role | Typical interfaces | Addresses offered, in the certificate | Allowed at installation | Firewall hint |
|---|---|---|---|---|
| **Reaches this server** (`mesh`) | Tailscale, Headscale, ZeroTier, NetBird, Nebula, Netmaker, innernet, Husarnet, NordVPN Meshnet | yes | yes | yes |
| **Tunnel of unknown kind** (`unknown`) | WireGuard, OpenVPN, IPsec, tinc, SoftEther, other TUN/TAP devices | yes | its subnet | yes |
| **Outgoing only** (`egress`) | NordVPN, Mullvad, Proton VPN, Cloudflare WARP, any tunnel that carries your default route, a PPPoE uplink | no | no | no |
| **Outgoing only** (`access`) | Cisco Secure Client, GlobalProtect, Twingate, the Firezone client | no | no | no |
| **Public overlay** (`overlay`) | Yggdrasil | no | no (allowing asks first) | no |
| LAN / Wi-Fi (`local`) | Ethernet, Wi-Fi | yes, plus the `.local` name | its subnets | yes |

**Why exit VPNs are not offered.** An exit or privacy VPN (NordVPN, Mullvad, Proton VPN, WARP) sends your
traffic out to the internet; nobody connects *in* through it, and its address range belongs to the VPN
provider, not to your devices. Allowing that range would admit strangers who share the provider's network,
and announcing the server there (addresses, `.local` name) serves no one. The same goes for corporate
and zero-trust clients (Cisco Secure Client, GlobalProtect, Twingate, Firezone): they let this machine
reach company resources, not the other way round. A WireGuard or OpenVPN tunnel of unknown kind counts
as outgoing only while it carries the machine's default route ("carries the default route" on the
Network page); a Tailscale exit node or ZeroTier's global routes do not change Tailscale's or ZeroTier's
role — their peers still reach the server.

| VPN | Detected as | Notes |
|---|---|---|
| **Tailscale** | `tailscale0`, or the interface carrying the node's Tailscale address (macOS: a `utun*`; one with a 100.64.0.0/10 address only while tailscaled cannot be asked and Tailscale is installed) | Allowed ranges `100.64.0.0/10` and `fd7a:115c:a1e0::/48` (the first is shared with NetBird, NordVPN Meshnet, Cloudflare WARP and some internet providers' carrier-grade NAT: narrow it to your devices if your server has such an address). The MagicDNS name (`host.tailnet.ts.net`) is listed and put into the local certificate. Publicly trusted certificates: [Tailscale certificates](#tailscale-certificates); an address without a port: [Tailscale Serve](#tailnet-address-without-a-port-tailscale-serve); share links on the internet: [Tailscale Funnel](#share-links-on-the-internet-tailscale-funnel). |
| **Headscale** | as Tailscale; labelled with its control server ("Headscale (hs.example.org)") — or "Headscale (self-hosted control server?)" when tailscaled's settings cannot be read and the MagicDNS name is not under `.ts.net` | With Headscale's default `prefixes` the Tailscale ranges are allowed. With **custom prefixes** nothing is guessed: `fileparcel network vpn list` notes it, add yours with `fileparcel network allow add <prefix>` (see `prefixes` in Headscale's `config.yaml`). Headscale issues no `ts.net` certificates and has no Funnel; its MagicDNS names are under your own `base_domain`. The local CA covers the MagicDNS name only if the machine was already on Headscale when the CA was created (at installation); otherwise `fileparcel doctor` and the Network page say "not covered": run `fileparcel ca regenerate` (every device must then trust the new CA) or use the IP address. |
| **WireGuard** | `wg*`, or any interface of type WireGuard | Its subnet is allowed at installation; use the server's tunnel IP. Add a DNS name with `fileparcel config set network.extra_hosts files.vpn.example` if your VPN DNS has one; a name added after installation is outside the local CA's allowed names (unless it ends in `.local` or `.ts.net`), so run `fileparcel ca regenerate` afterwards. A tunnel with a host-only address (`/32`) has no subnet to allow: add its network with `fileparcel network allow add`. |
| **ZeroTier** | `zt*` (macOS: `feth*` when `zerotier-cli` is installed) | ZeroTier is a layer-2 network, so mDNS can work across it: `fileparcel config set mdns.zerotier true`. |
| **NetBird** | `wt*`, `nb-*`, `netbird*` | NetBird uses 100.64.0.0/10 addresses like Tailscale; its subnet is allowed. |
| **Nebula, Netmaker, innernet, Husarnet, tinc** | `nebula*`; `netmaker` or `nm-*` WireGuard interfaces; innernet and tinc networks (from their configuration); `hnet*` or `fc94::/16` | Their subnets (Husarnet: `fc94::/16`, every device you allowed in your Husarnet dashboard) are allowed. |
| **NordVPN** | `nordlynx`, `nordtun` | Outgoing only — except **Meshnet**: while `nordlynx` carries a 100.64.0.0/10 Meshnet address, only that address is offered and 100.64.0.0/10 may be allowed. |
| **Mullvad, Proton VPN, Cloudflare WARP** | `*-mullvad`; `proton0` (and its kill-switch interfaces); `CloudflareWARP` | Outgoing only. WARP in a Zero Trust organisation with peer-to-peer uses 100.96.0.0/12: set its role to mesh if you use that. |
| **Corporate and zero-trust clients** | `cscotun*` (Cisco Secure Client), `gpd*` (GlobalProtect), `sdwan0` with Twingate installed, `tun-firezone` | Outgoing only. On a Firezone Gateway, allow the Firezone client range manually. |
| **Yggdrasil** | `ygg*`, a Yggdrasil node address (`200::/8`), or a tunnel device with an address in `200::/7` (a LAN or Wi-Fi interface that only got a `300:…` subnet address from a Yggdrasil router stays your LAN) | A public overlay: anyone on it can try to connect. Not allowed at installation; `fileparcel network vpn allow yggdrasil` asks first. Prefer allowing single addresses of your own devices. |
| **OpenVPN, IPsec and others** | `ovpn*`, `as0t*` and OpenVPN's data-channel devices; `ipsec*`, `xfrm*`, `vti*`; `tun*`, `tap*`, `ppp*`, other `utun*`, any Linux TUN/TAP device | Its subnet is allowed; outgoing only while it carries the default route. |

Container and virtual-machine bridges (`docker*`, `br-*`, `veth*`, `virbr*`, `cni*`, `podman*`, `vnet*`, a VM's
tap device, …) are never listed, allowlisted or put into certificates.

```sh
fileparcel network interfaces             # every interface with its kind and role
fileparcel network vpn list               # the VPNs, their ranges and whether they may connect
fileparcel network vpn allow tailscale    # let the devices of a VPN connect (adds its ranges)
fileparcel network vpn remove wg0         # stop allowing a VPN's networks
```

In the web app, Admin → Network & VPN lists the interfaces grouped by role, shows for each VPN whether the
access policy admits it, and offers a button per VPN under the allowed networks.

**Correcting a role.** Detection relies on product names, address ranges, the interface type and the
default route; a tunnel with an unusual name may land in the wrong group. Fix it with

```sh
fileparcel network vpn role wg0 mesh      # devices can reach this server through wg0
fileparcel network vpn role tun3 egress   # outgoing only
fileparcel network vpn role wg0 auto      # back to automatic detection
```

or with the ⋮ menu of the interface on Admin → Network & VPN ("Devices can reach this server through it",
"Outgoing only", "Automatic"). The roles are stored in `network.iface_roles` (entries `interface=role`,
roles `mesh`, `unknown`, `local`, `egress`, `access`, `overlay`, `none`); a change needs step-up and applies at
once to the URLs, the certificate, the `.local` announcements and the firewall hints. Existing allow lists
are never changed by detection; `fileparcel doctor` points out allowed networks that belong to an outgoing
VPN (`network.exit_vpn_allowed`) and a public overlay in the allow list (`network.overlay`).

mDNS (`.local` names) does not cross routed VPNs (Tailscale, WireGuard, NetBird, Nebula, OpenVPN): use
the MagicDNS name or the tunnel IP there. `fileparcel network urls --qr` shows every URL with a QR code.
After adding a VPN later, the certificate is reissued automatically when the server's addresses change.

### .local names and mDNS

FileParcel announces `https://fileparcel.local:8443/` (the label is the server name) and an
`_https._tcp` service ("FileParcel on <hostname>") on your LAN and Wi-Fi interfaces:

- **Linux with Avahi** (most desktops, Raspberry Pi OS): published through Avahi over D-Bus, so it
  coexists with the system's responder.
- **macOS**: published with the system's `dns-sd`.
- **Otherwise** a built-in responder is used (UDP 5353 must be allowed by the firewall; see
  [The mDNS port](INSTALL.md#the-mdns-port)).
- On a name collision (another `fileparcel.local` on the network) FileParcel automatically uses
  `fileparcel-2.local` and reissues its certificate. A second FileParcel on the *same* machine only
  renames its service entry ("FileParcel on <host> (2)") and keeps `<name>.local`. The certificate
  always covers the configured `<name>.local`, even while a rename is in effect, and Admin → Network & VPN,
  `fileparcel status` and `fileparcel doctor` say when the published name is not the configured one.

Which devices resolve `.local`: macOS, iOS, iPadOS, Windows 10/11, Linux with `nss-mdns` (most
desktops) and Android 12+ in most browsers. Older Android versions and some apps do not; use the IP
address (the QR codes in the summary and in Admin → Network & VPN contain the IP URLs too).

Commands: `fileparcel network mdns status`, `fileparcel network mdns name files` (→ `files.local`),
`fileparcel network mdns disable`, `fileparcel network mdns mode avahi|dnssd|builtin|auto|off`. The
responder re-publishes in the background, so for a few seconds after a change `network mdns status` shows
both what is configured and what is still running (`auto (running; "off" configured, republishing)`) instead of
contradicting the command that just succeeded.

### Share links on the internet (Tailscale Funnel)

[Tailscale Funnel](https://tailscale.com/kb/1223/funnel) publishes FileParcel on your machine's Tailscale
name — `https://<machine>.<tailnet>.ts.net/` — on the whole internet: no port forwarding on your router, no
firewall rule, a certificate every browser trusts, and your home address stays hidden behind Tailscale's
relays. FileParcel configures tailscaled itself and only touches its own entries. It is off until you turn
it on.

**Setting it up** — what Funnel needs in Tailscale, choosing the mode, and the commands to turn it on and
off — is described step by step under
[Put share links on the internet](INSTALL.md#put-share-links-on-the-internet-tailscale-funnel) in the
installation guide. This section is the reference: what each mode lets through, the ports, the security
details and every check.

**What each mode lets through.**

- **Share links only** (recommended; `--mode shares`): the share links and file requests you create
  (`/s/…`) and the files their pages load. Every other address — the sign-in page, the API, the admin
  pages — answers "not found", and no sign-in is possible there: cookies and tokens are removed from those
  requests.
- **Full app, sign-in required** (`--mode app`): the whole app with its sign-in page, except setup,
  unlocking, the certificate page (`/trust`) and — unless you allow it — the admin pages. Only accounts
  with two-factor authentication (authenticator app or passkey) can sign in over this address; others get
  the ordinary "wrong username or password" answer.

**Turning it on in the web app.** Admin → Network & VPN → *Internet access (Tailscale Funnel)*: pick the
mode and *Save*. Widening what the internet reaches asks you first ("Publish on the internet?"), and every
change needs step-up. When the server is stopped, `fileparcel network funnel enable` only saves the choice
("Saved. FileParcel publishes it on Tailscale when the server starts."). The public name can take **up to
10 minutes** to work on the internet; the card shows the last public request, and its reachability test
(over your tailnet) confirms that tailscaled reaches FileParcel — it cannot prove that public DNS is ready.

**Ports.** 443 (the first time, `https://<name>/`), 8443 or 10000 — only those the tailnet policy allows for
the machine, and never FileParcel's own port (Tailscale would take that port over on the Tailscale address
and cut off your normal tailnet access). With FileParcel on its default port 8443, that leaves 443 and
10000: `fileparcel network funnel enable --mode app --port 10000` publishes the whole app on port 10000. A
later `enable` keeps the current port unless `--port` says otherwise. With Funnel on 443, the tailnet keeps
using `https://<name>:8443/`.

**Share links.** While Funnel is on, new share links use the Funnel address (unless `server.public_url` is
set), so their QR codes work anywhere; the share dialog says "Anyone with this link can open it from the
internet". Links stay bearer secrets: anyone who has one can open it, as before — use passwords, expiry and
download limits for sensitive files. Tailnet devices that open the Funnel address see the same restricted
view as the internet.

**Security over Funnel.**
- The access policy's **deny list** applies to the visitors' real addresses; the allow list and access
  mode do not (Funnel is public by design). Visitors from the internet are rate-limited per address (IPv6
  per /64) and in total (`ratelimit.funnel_per_min`, `ratelimit.funnel_global_per_min`).
- In *Full app* mode, failed sign-ins over Funnel never lock the account on your LAN; they only slow down
  further attempts for that account over Funnel (10 at once, then 2 per hour). Wrong share passwords over
  Funnel are limited per share (20 at once, then 20 per hour). Sessions of accounts without two-factor
  authentication (a browser signed in on your LAN, API tokens) can only set up a second factor over Funnel.
  A password sign-in of such an account over Funnel is refused. The message names the missing second factor
  and where to set it up; a wrong password gets the very same message, so it reveals nothing. Someone you
  invite with a single-use link can accept the invitation over Funnel and is then taken straight to setting
  up an authenticator app (audited as `auth.login` with `after_invite`); a shared multi-use link is no proof
  of the person, so that account signs in at home or over the VPN first.
- *Allow administration over Funnel* and turning off *Require two-factor sign-in over Funnel* (card →
  Advanced, or `--allow-admin` / `--no-require-2fa`) weaken sign-in: they need a built-in owner or
  administrator and the typed confirmation `public`. Administration needs two-factor sign-in. Both switches
  stay saved while Funnel is off or *Share links only*, where they do nothing; switching to *Full app* while
  they are saved that way counts as weakening too (the card and the command ask about it, and other
  accounts with the network permission have to switch them to the safe side first).
- **Passkeys and the Tailscale address.** A passkey only works on the domain it was registered for — by
  default the server's `.local` name — so an account whose only second factor is a passkey cannot sign in
  at `https://<machine>.<tailnet>.ts.net` (Funnel's *Full app* and Tailscale Serve); accounts with an
  authenticator app can. The `passkeys` check says so. To use passkeys there, set `auth.webauthn_rp_id` to
  the Tailscale name and add the address with its port (`https://<name>:10000`, unless the port is 443) to
  `auth.webauthn_origins`; passkeys registered for the old domain then stop working and have to be added
  again.
- Search engines are asked not to index anything (`X-Robots-Tag`).

**Never publish FileParcel with `tailscale funnel` yourself** (for example `tailscale funnel
https+insecure://localhost:8443`, the example of `tailscale funnel --help`, or a Funnel on another tailnet
machine pointed at this one): every visitor would look like that machine, bypassing the access policy and
the rate limits. FileParcel refuses such requests (403 with the removal command) and `fileparcel doctor`
reports the entry (`network.funnel_bypass`; a request counts only when it comes from this machine or a
Tailscale address, so nobody else can raise the alarm with a forged header). How to remove just that entry:
[Do not use `tailscale funnel` yourself](INSTALL.md#do-not-use-tailscale-funnel-yourself) in the
installation guide. The same applies to a Cloudflare Tunnel or nginx forwarding to FileParcel without
`server.trusted_proxies`: the Network page and the doctor warn about them.

**How it works, and turning it off.** tailscaled handles HTTPS and passes the requests to a private socket
in `<HOME>/run/` (`ts-funnel.sock`; FileParcel falls back to `127.0.0.1:18443` when tailscaled does not allow
socket targets for your user, and removes that entry on every clean stop). As long as Tailscale may still
send requests to such a 127.0.0.1 port — Funnel turned off but the entry could not be removed yet, or the
connection moved to another port — FileParcel keeps the port bound (answering "not found") so no other
program on the machine can take it, and retries the removal. FileParcel remembers its entries
in `<HOME>/service/tailscale.json` and never re-adds one that you removed with `tailscale serve reset`: the
card then says *Needs attention* and *Re-apply* (`fileparcel network funnel reapply`) publishes again. A
restored backup or a copied installation does not publish anything on its own (Re-apply); a copy made next
to a running installation (for example to try an upgrade) never takes over or removes that installation's
entries — it reports them as another program's (`port.free`), and uninstalling the copy leaves them alone. `disable`, and
uninstalling FileParcel, remove FileParcel's entries from tailscaled; if that fails, the message prints the
`tailscale serve --yes --https=<port> --set-path=/ off` command to run. Advanced settings (card →
Advanced): `funnel.backend` (`auto`, `unix` or `tcp`) and `funnel.backend_port`. The Funnel settings
(`funnel.mode`, `funnel.port`, …) are managed by the Network page and `fileparcel network funnel`;
`fileparcel config set` refuses them.

**Troubleshooting** — the checks by ID (`fileparcel network funnel status --refresh`, the Funnel card, and
`fileparcel doctor` rows `network.funnel`, `network.serve`, `network.funnel_bypass`, `tailscale.key_expiry`):

| Check | What to do |
|---|---|
| `tailscale.running` | Install and start Tailscale, then sign in: `sudo tailscale up`. |
| `tailscale.magicdns` | Enable MagicDNS in the Tailscale admin console (DNS). |
| `tailscale.https` | Enable HTTPS certificates in the admin console (DNS). Not available with Headscale. |
| `tailscale.funnel_attr` | Add the `funnel` node attribute in Access controls (the snippet is under [What Funnel needs](INSTALL.md#what-funnel-needs)); *How to fix* opens the page Tailscale suggests. |
| `tailscale.funnel_port` | The tailnet policy does not allow this port for the machine: pick another (443, 8443, 10000) or widen `funnel-ports`. |
| `tailscale.cli_port` | FileParcel talks to Tailscale through its command line here (no LocalAPI socket, e.g. the macOS app), which can only enable Funnel when 443 is allowed. |
| `tailscale.shields_up` | `sudo tailscale set --shields-up=false` (Funnel cannot work with shields up; Serve's tailnet devices cannot connect). |
| `tailscale.operator` | `sudo tailscale set --operator=<the user FileParcel runs as>`. |
| `tailscale.config_locked` | tailscaled runs from a configuration file (`--config`): add the entry there, or run tailscaled without it. |
| `tailscale.key_expiry` | The machine's Tailscale key expires soon: disable key expiry for it in the admin console. |
| `container` | Run FileParcel outside the container, or use a reverse proxy. |
| `port.fileparcel` | Choose a port FileParcel itself does not use. |
| `port.free` | Another program's serve or funnel entry uses that port (`tailscale serve status`): remove it, or pick another port. |
| `port.shadow` | Another program listens on that port; Tailscale takes the port over on the Tailscale address. |
| `mtls` | Client certificates cannot pass through Tailscale's HTTPS: use *Share links only* with `mtls.exempt_shares`, or `mtls.mode` optional. |
| `node` | Funnel was turned on on another Tailscale machine (restored backup, copied installation): enable it again here. |
| `backend`, `backend.tcp` | Tailscale does not let FileParcel's account use a private socket, so FileParcel uses a local port instead (`backend.tcp` says which): nothing to do, or set `funnel.backend` to `tcp`. If another Tailscale Serve or Funnel entry on the machine is in the way (`backend` names it), remove that entry, or set `funnel.backend_port`, then press *Re-apply*. |
| `passkeys` | Passkeys do not work at the Tailscale address (see *Security over Funnel*); accounts with an authenticator app can sign in. |
| `reachable` | tailscaled could not reach FileParcel: a sandboxed or other-user tailscaled cannot open the socket — set `funnel.backend` to `tcp`; "not trusted yet" clears once Tailscale's certificate is issued. |

### Tailnet address without a port (Tailscale Serve)

Tailscale Serve gives the devices of your tailnet `https://<machine>.<tailnet>.ts.net/` — no port number,
a certificate every browser trusts, the whole web app. Only tailnet devices can use it, and the full access
policy applies to their real tailnet addresses (unlike a tailnet connection to `:8443` from a Tailscale
without TUN device, which arrives from 127.0.0.1). How to turn it on, on the command line or with the
*Tailnet address without port (Tailscale Serve)* card on Admin → Network & VPN:
[Tailscale Serve](INSTALL.md#give-your-tailnet-an-address-without-a-port-tailscale-serve) in the
installation guide.

The requirements are those of Funnel without the Funnel attribute (Tailscale running, MagicDNS, HTTPS
certificates, the operator permission), and the same checks apply. Serve and Funnel cannot share a port: to have both, use Serve on
443 and Funnel on 10000 (`https://<name>:10000/s/…`). If somebody turns on Funnel for Serve's port with the
`tailscale` command, FileParcel turns it off again and refuses those requests. While Serve is on, its address
is the recommended access URL.

---

## Certificates and TLS

FileParcel always uses HTTPS (TLS 1.2 or 1.3; `tls.min_version` can require 1.3) with modern ciphers only,
HTTP/2, and X25519MLKEM768 post-quantum key exchange where the client supports it. Plain-HTTP requests —
on the HTTPS port itself or on the optional HTTP port — are answered with a permanent redirect to HTTPS.
The certificate is chosen per requested name (SNI): an ACME certificate for its domains, the Tailscale
certificate for the `ts.net` name, your custom certificate for its names, and the local certificate for
everything else.

```sh
fileparcel cert status        # every certificate, its names and expiry
fileparcel cert renew         # reissue the local certificate now (--force even if not due)
fileparcel cert sans add files.home.arpa 10.0.0.5
```

### The local certificate authority

Created at installation: an ECDSA P-256 CA valid for 10 years, named
"FileParcel Local CA (<name> <install id>)". It is **name-constrained** (a critical X.509 extension that
clients enforce): it can only issue certificates for `.local`, `localhost`, `.ts.net`, the machine's host
name, the server's other names at the time the CA is created (a Headscale MagicDNS name,
`network.extra_hosts`), the names in `tls.extra_sans` and `server.public_url`, and for private IP ranges
and the host's IPv6 prefixes. A name that is itself a public suffix — a machine called `dev` or `app` (both are
top-level domains), or `*.com` — is not added, since that would cover the whole domain; use
`<host>.local` for such a machine. The CA can also only issue server (TLS) certificates. Even if its key
leaked, it could not be used to impersonate a public web site. Its private key is stored encrypted with
the master key and only decrypted while issuing. A CA created by an older version keeps its old limits
until `fileparcel ca regenerate` (the server logs a warning at startup if it covers a whole top-level domain).

The server certificate ("leaf") is issued by this CA for all of the server's names and addresses
(`<name>.local`, host name, MagicDNS name, every non-container IP address, `localhost`, extra names),
valid for `tls.leaf_days` (default 397 days, configurable 7–825; Apple devices accept at most 825). It is
renewed automatically 30 days before it expires — or, for a `tls.leaf_days` shorter than 90 days, once a third of its validity is left,
so a short-lived certificate is not permanently "expiring" — and **reissued automatically when the set of
names changes** (new IP address, new VPN, renamed server, changed `tls.extra_sans`) or when
`tls.leaf_days` itself changes; devices that trust the CA never notice.

A name the CA may not issue for is stored but left out of the certificate. The names the CA is allowed to
sign are fixed when the CA is created, so adding a name outside them needs a new CA. Dropped names are
listed by `fileparcel cert status` ("Not covered"), on Admin → Certificates, and in the response to the
settings change that added them; `tls.extra_sans` and `acme.domains` take at most 64 entries each.

- `fileparcel ca show` / `ca fingerprint` / `ca export --format pem|der|mobileconfig`
- `fileparcel ca regenerate` creates a new CA (every device must then trust the new one; step-up).
  `--unconstrained` drops the name constraints — only needed for names outside the list above; prefer
  adding the name to `tls.extra_sans` **before** regenerating.
- The `/trust` page serves the CA as `.crt`, `.pem` and an iOS/macOS configuration profile. How to trust
  it on each kind of device:
  [Trust FileParcel's certificate on your devices](INSTALL.md#trust-fileparcels-certificate-on-your-devices).

### Let's Encrypt and other ACME CAs

For publicly trusted certificates on your own domain (no CA installation on devices):

```sh
# DNS challenge with Cloudflare (works without opening any port to the internet)
printf '%s' '{"api_token":"<cloudflare token with Zone.DNS edit>"}' | \
  fileparcel cert acme enable --email you@example.com --domain files.example.com \
    --challenge dns --dns-provider cloudflare --credentials-stdin
# test against Let's Encrypt staging first (the default), then switch to production:
fileparcel cert acme enable ... --production
```

- **Challenges:** `dns` (recommended for home servers; supports wildcards) with Cloudflare
  (`{"api_token": "…"}`) or any RFC 2136 server (`{"server":"ns.example.com:53","key_name":"…",
  "key_alg":"hmac-sha256.","key":"<base64>"}`); `http` needs port 80 on the internet forwarded to the HTTP
  port; `tls-alpn` needs port 443 forwarded to the HTTPS port.
- The domain's DNS must point to an address your clients reach (for example the server's LAN or tailnet
  IP in your own DNS). The access policy still applies.
- `acme.ca` = `staging` (default, not trusted — for testing), `production` (Let's Encrypt) or the
  directory URL of another ACME CA. Certificates are renewed automatically.
- HSTS (`tls.hsts = auto`) is switched on automatically once a publicly trusted certificate is served.
- Certificate names become public in Certificate Transparency logs.

### Tailscale certificates

Tailscale can issue publicly trusted certificates for your machine's MagicDNS name
(`host.tailnet.ts.net`). Requirements: *HTTPS certificates* enabled in the Tailscale admin console
(DNS page), and tailscaled must let FileParcel's user fetch them:
`sudo tailscale set --operator=$USER` (for a system installation, the account FileParcel runs as:
`fileparcel` on Linux, `_fileparcel` on a Mac). Then:

```sh
fileparcel cert tailscale enable      # fetches now and renews automatically (14 days before expiry)
```

Open `https://host.tailnet.ts.net:8443/` from any device in your tailnet — no CA installation needed, and
passkeys work there too (set `auth.webauthn_rp_id` to the ts.net name if that is the name you use).
Headscale cannot issue these certificates; the local CA covers the MagicDNS name instead, if the machine
was on Headscale when the CA was created — otherwise run `fileparcel ca regenerate`
([details](#the-local-certificate-authority)). The `ts.net`
name appears in public Certificate Transparency logs. When the machine or the tailnet is renamed, a
certificate for the new name is fetched automatically. `fileparcel cert tailscale disable` stops serving
the certificate; it and any fetch error then no longer appear in the certificate status.

### Your own certificate

```sh
fileparcel cert upload --cert fullchain.pem --key privkey.pem     # validated; the key is stored encrypted
fileparcel cert clear-custom
```

The certificate must match the key, must not be expired and must be in chain order (leaf first). It is
used for the names it contains.

### Client certificates (mTLS)

For extra protection, FileParcel can require a **client certificate** from its own client CA on every
device:

1. Issue one per user and device: `fileparcel client-cert issue alice --name "Alice's phone" --expires 365d
   -o alice-phone.p12`. (A certificate lets a device connect; it is not tied to the account that signs in
   on it: see [Known limitations](#known-limitations).) The `.p12` file is protected with a generated password that is printed once
   (or your own with `--password-stdin`: 6–128 characters, no emoji); `--legacy` produces a file that old
   Android and macOS versions can read. Admins can also issue them in Admin → Certificates (an owner's
   certificates can only be issued or revoked by an owner, or with the local CLI);
   users can issue their own on Settings → Devices when `mtls.self_service` is on.
2. Install the `.p12` file on the device (double-click on desktops; Settings → Security → Install
   certificate → *VPN & app user certificate* on Android; AirDrop/mail to iOS and install the profile).
   The file holds only the device's key and certificate. Files issued by older versions also contained
   the "FileParcel Client CA", which Android and Windows may have added to the trusted CAs: remove it
   there (Android: Settings → Security → Trusted credentials → User; Windows: `certmgr.msc` → Trusted
   Root Certification Authorities).
3. Set `mtls.mode`: `optional` (certificates are checked and recorded when presented) or `required`
   (connections without a valid certificate from this server are refused). With `mtls.exempt_shares`
   (default on), public share links, `/trust` and the health checks keep working without a certificate.
   Without it, the local health check of the installer, upgrades, `service start` and `fileparcel
   healthcheck` takes the server's refusal of its certificate-less connection as the sign that it is up.
4. Revoke a lost device's certificate: `fileparcel client-cert revoke <id|serial>` (effective
   immediately).

Test with one device in `optional` mode before switching to `required`, and keep a certificate on the
admin's devices — the server's local CLI always keeps working.

---

## Encryption at rest

FileParcel encrypts file contents, thumbnails and backups, and sensitive database values, with a
three-level key hierarchy:

```
master key (32 bytes, keys/master.key — plain, or sealed with your passphrase)
 ├── blob key-encryption key   → wraps one random key per stored file (AES-256-GCM or ChaCha20-Poly1305)
 ├── field key-encryption key  → encrypts TOTP secrets, passkeys, link/invite tokens, secret settings, CA keys
 └── MAC key                   → integrity keys (audit chain, recovery codes, share cookies)
```

Every stored file has its own random key, stored (wrapped) only in the database. Files are split into
64 KiB segments that are encrypted and authenticated separately, so downloads can start anywhere
(resume, video seeking) and any modification, truncation or swapping of stored data is detected. The
exact formats are documented for auditors in [`ENCRYPTION.md`](ENCRYPTION.md).

**What is not encrypted at rest:** file and folder names, sizes and dates, user names and e-mail
addresses, the audit log, the database structure, the TLS server key (needed to serve the unlock page),
and ACME/Tailscale certificate keys. Use full-disk encryption (LUKS, FileVault, BitLocker) to protect
these too.

### Plain and sealed master key

| | Plain (default) | Sealed |
|---|---|---|
| `keys/master.key` holds | the master key itself (file mode 0600) | the master key encrypted with a key derived from your passphrase (argon2id, 128 MiB) |
| After a restart or power cut | the server starts normally | the server starts **locked**: only the unlock page, `/trust` and health checks work, everything else answers "locked". The local admin socket keeps working on metadata, so the server can still be inspected and administered from the machine itself |
| Protects against | a stolen backup or disk copy **without** the key file; other users on the machine | additionally a stolen disk or machine (the passphrase is not on it) |
| Good for | unattended servers, especially with full-disk encryption | laptops and servers where someone can unlock after each boot |

**Unlocking a sealed server:** open `https://<server>:8443/unlock` and enter the passphrase (allowed from
networks per `keys.web_unlock`: `lan` (default: private addresses, plus the global IPv6 subnets of the
server's own LAN, Wi-Fi and VPN interfaces — not those of an outgoing or access VPN, see
[Access over a VPN](#access-over-a-vpn)), `any` or `off`; 5 attempts per minute), or on the server
run `fileparcel keys unlock`. Where web unlock is off, or not allowed from the device's network, the unlock
page says so and shows that command instead of asking for a passphrase it would refuse. For automated setups, `fileparcel serve --passphrase-file F` (or the global
`--passphrase-stdin`) unlocks at start (keep the file on a separate, protected medium). Offline commands on
a sealed home take the same two global flags instead of asking at a terminal. Lock a running server again
with `fileparcel keys lock`; the web UI and the remote API then stop until it is unlocked, while the local
admin socket keeps working on metadata.

**Switching modes and passphrases** (step-up in the web app, Admin → Encryption):

```sh
fileparcel keys status
fileparcel keys seal              # plain → sealed (asks for a new passphrase)
fileparcel keys unseal            # sealed → plain
fileparcel keys passphrase        # change the passphrase
fileparcel keys recovery-key      # new recovery key (shown once; replaces the previous one)
```

**The recovery key** (`FPRK-XXXX-XXXX-…`, 256 bits) unlocks the server in place of the passphrase. A
sealed installation creates one at initialisation and shows it once; `keys seal` on a plain installation
does not, so run `keys recovery-key` right after sealing. Print it or write it down and keep
it offline. **If you lose both the passphrase and the recovery key, the data is lost** — nobody, including
the FileParcel developers, can recover it.

### Rotate the encryption keys

```sh
fileparcel keys rotate --kek --purpose blob    # new blob KEK; re-wraps every per-file key (fast, DB only)
fileparcel keys rotate --kek --purpose field   # new field KEK; re-encrypts every sealed value
fileparcel keys rotate --master                # new master key; re-wraps the keyring (the passphrase stays)
fileparcel keys rotate --data                  # background job: re-encrypts every file with a fresh key
fileparcel keys verify                         # one active key per purpose, no retired key still in use, and (sealed mode) a recovery key
```

A master rotation does **not** ask for the passphrase and does not change it: the new master key is sealed
under the passphrase you already use, and your current recovery key keeps working. The one exception is a
server that was unlocked with the *recovery key* and whose key file predates this (written by hand or by an
older version): the rotation then refuses with "set a new passphrase first" — run `fileparcel keys
passphrase` (the recovery key is accepted as the current passphrase) and rotate afterwards.

A rotation and a backup never overlap on the key material. While a backup is copying the database and the
`keys/` and `certs/` directories, `keys rotate --master` and `keys rotate --kek --purpose field` refuse
with *"a backup is copying the key material right now; start the rotation again when it has finished"*;
start the rotation again once the backup has passed that phase, which happens early — copying
the file data afterwards does not block any rotation. `keys rotate --kek --purpose blob` is never blocked. In
the other direction a backup that would end up with a database and key files from different rotations
fails instead of writing an archive that cannot be restored. The same two rotations also exclude each
other: while one runs, the other refuses with *"another key rotation is changing the key material right
now; start this one again when it has finished"*. `keys rotate --data` does not refuse: while a full
backup copies the file data it pauses (the job shows *"waiting for a running backup"*) and continues
afterwards, because each file it re-encrypts replaces a file the backup is about to copy. A field-key
rotation (and `keys status`) reports an error while `certs/`, or a directory or `*.enc` key file below it,
is a symbolic link: the key files behind it cannot be tracked, and a rotation could otherwise delete the
key they need. Move the real directory there, or use a bind mount.

Rotation is crash-safe: an interrupted master rotation is completed or rolled back automatically at the
next start. Rotate the data if a per-file key may have leaked, and make a full backup afterwards: a data
rotation gives every file new stored data, so metadata backups taken before it no longer match the files
(restoring one reports them as missing).

**If the key file (or a backup containing it) may have been copied**, a master rotation alone is not
enough: whoever can open the copy (a plain one, or a sealed one whose passphrase they know) also gets the
passphrase-derived key and the recovery key's hash from it (its escrow, see [ENCRYPTION.md](ENCRYPTION.md)
§3), and a rotation keeps both, so they would open the new key file too. Run, in any order:

```sh
fileparcel keys passphrase        # sealed: a new passphrase (and salt); on a plain server: keys seal
fileparcel keys recovery-key      # a new recovery key; the leaked one stops working
fileparcel keys rotate --master   # a new master key
```

If the database may have been copied as well, also run `keys rotate --kek --purpose blob`, `keys rotate
--kek --purpose field` and `keys rotate --data`: a master rotation re-wraps the key-encryption keys
without changing them.

`storage.cipher` (`auto`, `aes-gcm`, `chacha20-poly1305`) chooses the cipher for new files; existing files
keep theirs until re-encrypted.

---

## Backups and restore

A backup is one encrypted file, `<HOME>/backups/fp-<install>-<date>-<scope>.fpbak`:

| Scope | Contains | Typical size |
|---|---|---|
| `metadata` | a consistent snapshot of the database, `fileparcel.toml`, `keys/master.key` and `certs/` — everything except file contents | small (MB) |
| `full` | the metadata plus every stored (already encrypted) file | the size of your data |

The archive is `tar`, compressed with zstd and encrypted with [age](https://age-encryption.org):

- **X25519 mode** (default): encrypted to one or more public keys (`backup.recipients`; the server's own
  backup key is always included, also when the list is empty — Admin → Backups and
  `fileparcel backup identity show` list it with the others). Scheduled backups need no secret at all; to
  restore you need the matching **identity** (secret key). Keep a copy of the identity offline —
  Admin → Backups → *Export identity*, or `fileparcel backup identity generate` for a new key pair.
- **Passphrase mode** (`backup.encryption = passphrase`): encrypted with `backup.passphrase` (age scrypt).

Because backups contain `keys/master.key`, anyone who has a backup **and** its identity/passphrase can read
your files — protect the identity like the data itself. (With a sealed master key, the backup contains the
sealed key; restoring then also needs the passphrase or the recovery key to unlock.)

A backup is a standard age file; it can be inspected without FileParcel:
`age -d -i identity.txt fp-….fpbak | zstd -d | tar -t`.

**Schedules and retention** (Admin → Backups, or `fileparcel backup schedule` / `backup config`):

- metadata backup daily at 03:00 (`backup.schedule_meta`, cron syntax, local time), full backup on Sundays
  at 04:00 (`backup.schedule_full`); `backup.enabled` pauses both.
- Retention keeps the last 7, plus the newest of each of the last 7 days, 4 weeks and 6 months
  (`backup.keep_last|keep_daily|keep_weekly|keep_monthly`), per scope. Only scheduled backups are
  pruned: manual, imported, pre-upgrade and final backups are kept until they are deleted by hand. With
  all four values at 0 retention is off and no backup is pruned at all. (The records of backups that
  failed are removed after a week either way; a failed backup that left a complete archive is kept.)
- `backup.copy_to` copies every new backup to another directory (a mounted NAS or USB disk). It must lie
  outside the FileParcel directory (a copy there would be lost together with the backup; the Backups page
  and `fileparcel backup config set --copy-to` refuse it, and a backup reports it as a failed copy). Always
  keep at least one copy on a different disk or machine. On a Linux **system installation** the server's
  sandbox lets it write only inside the installation directory (and `/tmp` is private to it), so allow
  the copy directory once and make it writable by the service account:

  ```sh
  sudo install -d -o fileparcel -g fileparcel -m 0700 /mnt/nas/fileparcel
  sudo systemctl edit fileparcel     # add:  [Service]
                                     #       ReadWritePaths=/mnt/nas/fileparcel
  sudo systemctl restart fileparcel
  ```

  The drop-in survives upgrades and `service install`. Without it every copy fails with "read-only file
  system" (the backup itself is kept and the error is recorded with it).

**Manual backups and checks:**

```sh
fileparcel backup create --scope full --note "before moving house" --wait
fileparcel backup list
fileparcel backup verify <id> --deep        # decrypts everything and checks every file
fileparcel backup export <id> /mnt/usb/     # copy the archive somewhere else
fileparcel backup import /mnt/usb/fp-….fpbak
fileparcel backup prune
```

When the master key in a backup is sealed with a passphrase, a deep verification cannot decrypt the
files: it checks the archive, its checksums and the database only, and its result says so.

The "last backup" of the dashboard, the doctor and the Backups page is the newest backup this server made
that has not failed verification: imported archives (which may come from another installation, or be
dated at their import when this server cannot decrypt them) never count, and a backup whose verification
failed is reported as a warning of its own.

**Restore.** A restore replaces the database, keys, certificates and configuration (and with a full
backup the stored files) of the installation. The previous state is moved to
`<HOME>/pre-restore-<date>/` first, so a restore can be undone by hand (`RESTORE-INFO.txt` in that
directory says how). A restore that keeps the current file data (a metadata backup, or `--metadata-only`)
leaves hard links to that data in `pre-restore-<date>/data/blobs`, at no extra space: files the restored
database does not know (uploaded after the backup was made) are removed by the restored server's nightly
clean-up, but their data stays there, for an undo, until the directory is deleted. After a restore the
backup list shows the archives that are in `<HOME>/backups`; entries of the restored database whose file
is not there (a new machine, or pruned since) are dropped.

A restore therefore needs room for two copies: the archive is unpacked under `<HOME>/tmp/restore` before
anything is swapped in (what an interrupted restore leaves there is removed at the next start), and the
replaced data then stays in `pre-restore-<date>/`. Keep roughly **twice the restored data size** free on
the installation's file system. The restore checks this before it extracts anything and refuses with
*"not enough free disk space to restore this backup (needs about X in the installation directory, Y
free)"* rather than failing after a long extraction. `--dry-run` and `--metadata-only` only need room for
the database, the keys and the certificates.

- From the web app: Admin → Backups → *Restore* (step-up) checks that the backup decrypts and that the
  disk has room for it, schedules the restore and restarts the server; it is applied before the database
  is opened. The server is unreachable until the archive is extracted, which takes a while for a large
  full backup (`systemctl status fileparcel` shows *Applying the scheduled restore*; the service
  manager's start timeout is extended meanwhile).
- From the command line (the server must be stopped):

  ```sh
  fileparcel service stop
  fileparcel backup restore <backup-id|file.fpbak> --identity-file ~/backup-identity.txt [--dry-run] [--metadata-only]
  fileparcel service start
  ```

  On a system installation run the three with `sudo`: the restored files are given to the `fileparcel`
  account.

  `--dry-run` decrypts and checks the archive without changing anything; `--metadata-only` restores the
  database, the keys, the certificates and the configuration, keeping the current file data. (The keys
  come along because the restored database refers to the backup's keyring; the current `keys/`, `certs/`
  and `fileparcel.toml` are moved to `<HOME>/pre-restore-<date>/` like everything else.) A restore that
  keeps the file data warns — in a dry run too, and as `missing_blobs` in `--json` — when stored files
  the restored database lists have no data in this installation: re-encrypted by `keys rotate --data` or
  deleted after the backup was made, or a backup of another installation. Those files cannot be opened
  after the restore; restore a full backup instead.

  When the current installation cannot be opened at all (a damaged database or master key, or a
  database already migrated by a newer version), the restore still works, but the backup identity
  stored in that database cannot be read: pass `--identity-file` (or `--passphrase-file`/`--passphrase-stdin`),
  and the archive's path (`<HOME>/backups/fp-….fpbak`) if its id cannot be looked up.

**Disaster recovery on a new machine:** install FileParcel there, stop it, restore a full backup with
`--identity-file`, and start it again — the steps are under
[Move it to a new machine](INSTALL.md#move-it-to-a-new-machine) in the installation guide. The CA and the
server's identity come back with the backup, so devices that trusted the old server trust the new one (the
leaf certificate is reissued for the new machine's addresses).

---

## Audit log

Security-relevant actions are recorded with time, actor, IP address, request id, target and outcome
(`success`, `failure`, `denied`): sign-ins and lockouts, second-factor changes, sessions and tokens, user,
group and invitation changes, file uploads, downloads, renames, moves, deletions and restores, shares and
share password failures, file-request uploads, settings, network policy, certificate, key and backup
operations, and system start/stop/restart. Secrets are never recorded.

Every entry is chained to the previous one with an HMAC, so deleting or editing entries is detected:

```sh
fileparcel audit list --since 24h
fileparcel audit list --user alice --action auth. --follow
fileparcel audit verify
fileparcel audit export --format jsonl -o audit.jsonl --since 30d
```

Entries recorded while the server is locked (sealed mode before the unlock) are chained without the key
and sealed at the next unlock. Such entries prove nothing about their origin: those the unlocking server did
not write itself (an earlier run that was never unlocked, an offline command, or someone writing the database
directly) are named by an `audit.reseal` entry, and `audit verify` reports them.

Entries older than `audit.retention_days` (365) are pruned daily (skipped while the server is locked); the
chain keeps an authenticated anchor so verification still works. `audit.mirror_jsonl` additionally appends
every entry to `<HOME>/logs/audit.jsonl` for log shippers. A restore from a backup takes the log back to the
backup's last entry, so the next entries reuse numbers the file already has: at the next start the server
moves the file aside as `audit.jsonl.pre-restore-<time>` and starts a new one, so no file holds two entries
with the same `seq`. Admin → Audit log offers filters and CSV/JSON-lines export;
every user sees their own recent events under *Activity*.

---

## Watch background jobs

Long-running work runs as jobs with progress (Admin → Jobs, `fileparcel jobs list|show|cancel|run`).
Only the kinds listed by `fileparcel jobs run --help` can be started by hand; the others are started by
the operation that needs them. Hand-started runs are recorded in the audit log as `job.run`.

| Job | When | What it does |
|---|---|---|
| `upload.zip` | after a zip-on-upload | packs the uploaded files into one zip |
| `thumbs.generate` | after image uploads | creates thumbnails |
| `backup.create`, `backup.verify`, `backup.prune` | schedule / manual | backups |
| `keys.rotate_kek`, `keys.reencrypt` | started by *Rotate keys* | key rotation, data re-encryption |
| `maintenance.sessions` | hourly | removes expired sessions, archive tickets and sign-in flows |
| `maintenance.uploads` | hourly | expires unfinished uploads |
| `maintenance.trash` | daily | deletes trash items older than `storage.trash_days` |
| `maintenance.versions` | daily | keeps `storage.versions_keep` versions per file |
| `maintenance.blob_gc` | daily | removes stored data that nothing references any more |
| `maintenance.audit_prune` | daily | applies `audit.retention_days` |
| `maintenance.db_optimize` | daily | optimises and checkpoints the database; prunes old job rows and share access-log entries (`sharing.access_log_days`) |
| `certs.renew_check` | every 12 h | renews certificates that are due |

`fileparcel jobs run maintenance.blob_gc` starts a job immediately; `fileparcel gc --dry-run` shows what the
garbage collection would remove.

The job list leaves out the routine runs of the busiest kinds (`maintenance.sessions`,
`maintenance.uploads`, `certs.renew_check`, `thumbs.generate`), but always shows one that **failed** or
that somebody started by hand — so a failure counted on the dashboard or by the doctor can always be
opened. `maintenance.db_optimize` records a note when the write-ahead log could not be truncated because
readers were active; run it again when the server is idle.

A cron schedule that parses but can never match a date (`0 3 30 2 *`, `0 0 31 4 *`) is refused when it is
set, instead of being stored as a schedule that never runs. A schedule stored by an older version that is
in that state is reported by `fileparcel doctor` and Admin → System → *Run checks*.

---

## System, logs and maintenance

- **Status and health:** `fileparcel status` (version, uptime, key state, service, ports, URLs,
  certificate, storage, last backup, jobs); Admin → System shows the same plus build information,
  database and storage sizes and settings waiting for a restart. `/healthz` answers `ok` while the process
  runs; `/readyz` answers 200 only when the database works and the keys are unlocked.
- **Doctor:** `fileparcel doctor` checks permissions and file ownership, database, keys, certificates, service and boot,
  ports, firewall, mDNS, disk space, backups and stale jobs, and prints a fix for every problem;
  `--fix` repairs the safe ones. Admin → System → *Run checks* shows the same.
- **Logs:** `<HOME>/logs/fileparcel.log`, rotated at `log.max_size_mb` (50) keeping `log.max_files` (5);
  `fileparcel logs -f` follows it. The service manager's log has the same: `journalctl --user -u fileparcel`
  (systemd user service), `sudo journalctl -u fileparcel` (system service), `<HOME>/logs/launchd.err.log`
  (macOS).
  `fileparcel config set log.level debug` changes the level immediately. Logs contain no passwords,
  tokens or keys; share-link and invitation URLs are logged without their tokens.
- **Restart:** `fileparcel service restart`, or Admin → System → *Restart* (the process exits with code
  75 and the service manager starts it again).
- **Maintenance mode:** `fileparcel maintenance on --message "Back at 14:00"` keeps users out while you
  work on the server: the web app shows the notice, and requests for files, shares and uploads are
  answered with "503 unavailable". Administrators and the local CLI keep working; so do signing in and
  every user's own account settings (profile, password, two-factor, sessions, tokens). Invitations
  cannot be accepted until it is off again. `maintenance off` ends it, `maintenance status` shows it.
  While it is on, administrators (and roles with *Operate the server*) see a banner on every page of the
  web app with a *Turn off* button, the health checks (Admin dashboard, `fileparcel doctor`) warn about it,
  `fileparcel status` shows a *Maintenance* line, and the sign-in page tells everyone before they sign in.
- **Database:** `fileparcel db check` (integrity), `db stats` (sizes and row counts), `db vacuum`
  (compact; server stopped), `db migrate` (apply schema migrations; normally automatic at start). A newer
  database is never opened by an older binary.

---

## Upgrading

Upgrades keep all files, accounts and settings, and the database is updated automatically when the new
version starts. Run the new release's `install.sh`, or `fileparcel upgrade fileparcel-vN.zip`; a
*pre-upgrade* backup is made first, and if the new version does not come up, the previous one is put back
and started again by itself. The steps, rolling back by hand and Docker are described under
[Upgrade to a new version](INSTALL.md#upgrade-to-a-new-version); read
[Before you upgrade](INSTALL.md#before-you-upgrade) and the release notes of the new version first.

---

## Uninstalling

`<HOME>/uninstall.sh` (or `fileparcel uninstall`) removes the service and the command link and keeps your
data; `--purge` also destroys the keys and deletes the installation directory, and
`--final-backup --backup-to DIR` makes a last backup outside it first. Every option, what is left behind
and how to remove the certificate from your devices: [Uninstall FileParcel](INSTALL.md#uninstall-fileparcel).

---

## The installation directory

Everything FileParcel stores — configuration, database, encrypted files, keys, certificates, backups, logs
and the admin socket — lives in one directory, `<HOME>`. Its layout with the permissions, the few things
outside it and how commands find it: [The installation directory](INSTALL.md#the-installation-directory).
Moving it to another disk or machine: [Move FileParcel](INSTALL.md#move-fileparcel).

---

## Command-line interface

The `fileparcel` program is both the server and the tool to manage it. On the server every command works
right away, with full admin rights and no password; from another computer it works with an API token.
[The fileparcel command](COMMANDS.md) explains how commands reach the server, remote use, output and
scripting, and shows every command with examples and step-by-step recipes; its
[Command reference](COMMANDS.md#command-reference) lists every flag. In the terminal,
`fileparcel --help`, `fileparcel <command> --help` and `fileparcel help <topic>` show the same help.

---

## Configuration reference

FileParcel has two kinds of settings:

- **Bootstrap settings** in `<HOME>/fileparcel.toml` — what the server needs before it can open its
  database: ports, listen addresses, name, logging. `server.name`, `server.https_port`, `server.http_port`,
  `server.bind`, `server.public_url`, `server.trusted_proxies`, `log.level` and `runtime.gomemlimit_mb` are
  also shown and editable in Admin → Settings → Server and with `fileparcel config set server.https_port 9443`;
  most of them need a restart. The other keys (`server.same_port_redirect`, `log.format`, `log.file`,
  `log.max_size_mb`, `log.max_files`, `admin_socket.enabled`) are changed with `fileparcel config edit` or
  a `FILEPARCEL_<SECTION>_<KEY>` environment variable. A change made in the web app or with `config set`
  rewrites the file atomically and keeps any edits made to it meanwhile, but of your comments only the
  block at the top of the file survives (other comments, between keys or at the end of a line, are
  replaced by the standard ones): keep notes in that top block, separated from the first key by a blank
  line.
- **Runtime settings** stored in the database — everything else. They are validated, audited and applied
  immediately by the running server (unless marked *restart*).

`fileparcel config list [--section S] [--all]` shows the current values; `config get KEY`,
`config set KEY VALUE`, `config unset KEY` (back to the default), `config path` and `config edit`
(opens a copy of `fileparcel.toml` in `$VISUAL`/`$EDITOR`, validates it and only then saves it). Values are JSON when they parse as
JSON (`true`, `30`, `["a","b"]`), otherwise strings; lists also accept `a,b,c`. Secret settings are read
from standard input or a no-echo prompt, never from the command line, and are never displayed.

### fileparcel.toml

The file also marks a directory as a FileParcel home. A freshly installed one looks like this:

```toml
install_id = "5f0c…"           # generated at installation (random, 16 bytes hex); do not change

[server]
name = "fileparcel"            # mDNS label, CA name, default WebAuthn RP ID base
https_port = 8443
http_port = 8080               # 0 = no redirect listener
bind = ["::"]                  # dual-stack all interfaces; the allowlist does the filtering
same_port_redirect = true
public_url = ""                # optional canonical URL for links / WebAuthn
trusted_proxies = []

[log]
level = "info"                 # debug|info|warn|error
format = "text"                # text|json
file = true                    # also write logs/fileparcel.log (size-rotated)
max_size_mb = 50
max_files = 5

[admin_socket]
enabled = true

[runtime]
gomemlimit_mb = 0              # 0 = auto (min(1 GiB, 25% RAM))
```

| Key | Default | Meaning |
|---|---|---|
| `install_id` | random | Identifies the installation (CA name, backup file names). Not overridable. |
| `server.name` | `fileparcel` | DNS label for `<name>.local`, the local CA name and the default passkey domain. Lowercase letters, digits and `-`. Renaming orphans existing passkeys. |
| `server.https_port` | `8443` | HTTPS port. Ports below 1024 need root or `CAP_NET_BIND_SERVICE`. *Restart.* |
| `server.http_port` | `8080` | Plain-HTTP port that only redirects to HTTPS and answers ACME HTTP-01 challenges; `0` disables it. *Restart.* |
| `server.bind` | `["::"]` | Listen addresses. `::` listens on every interface (IPv4 and IPv6); the access policy does the filtering. `::` and `0.0.0.0` each cover every address, so list them alone: the admin pages and `config set` refuse a list that repeats an address or adds one next to them, and such entries in the file or an environment override are ignored with a warning. *Restart.* |
| `server.same_port_redirect` | `true` | Answer plain-HTTP requests that arrive on the HTTPS port with a redirect to HTTPS. *`config edit` only.* |
| `server.public_url` | `""` | Canonical external URL (reverse proxy, own domain) used in links, invitations and for passkeys. Scheme, host and port only, such as `https://files.example.com` or `https://files.example.com:9443/`: a user name or password (it would be in every link you send), a path (the web app is served from the root of its host), a query, a fragment or a port outside 1-65535 is refused, by `config set` and the admin pages as well as at start. Passkeys and the offline app need `https://`. *Restart.* |
| `server.trusted_proxies` | `[]` | Addresses/CIDRs whose `X-Forwarded-For` header is trusted for the client IP. |
| `log.level` | `info` | `debug`, `info`, `warn` or `error`; applied immediately. |
| `log.format` | `text` | `text` or `json`. *`config edit` only.* |
| `log.file` | `true` | Also write `<HOME>/logs/fileparcel.log` (the log always goes to standard error / the journal too). *`config edit` only.* |
| `log.max_size_mb` | `50` | Rotate the log file at this size. *`config edit` only.* |
| `log.max_files` | `5` | Number of rotated log files to keep. *`config edit` only.* |
| `admin_socket.enabled` | `true` | Serve the local admin socket `<HOME>/run/admin.sock` used by the CLI. *`config edit` only.* |
| `runtime.gomemlimit_mb` | `0` | Soft memory limit for the Go runtime; `0` = automatic (the smaller of 1 GiB and 25 % of RAM). |

### Environment variables

| Variable | Meaning |
|---|---|
| `FILEPARCEL_HOME` | The installation directory (instead of `--home`). |
| `FILEPARCEL_<SECTION>_<KEY>` | Overrides a `fileparcel.toml` value, e.g. `FILEPARCEL_SERVER_HTTPS_PORT=9443`, `FILEPARCEL_LOG_LEVEL=debug`, `FILEPARCEL_SERVER_BIND="127.0.0.1,::1"` (lists are comma-separated). Overridden settings are marked as such in the admin pages. `install_id` cannot be overridden. |
| `FILEPARCEL_TOKEN` | API token for `--server` (remote CLI). |
| `FILEPARCEL_ADMIN_USER`, `FILEPARCEL_ADMIN_EMAIL`, `FILEPARCEL_ADMIN_PASSWORD_FILE` | Admin account (username, optional e-mail address, file with the password) created by `fileparcel serve --init-if-missing` (Docker). |
| `FILEPARCEL_TAILSCALE_SOCKET` | Path of tailscaled's LocalAPI socket, for a tailscaled started with a non-default `--socket`. FileParcel then uses only that socket (never the `tailscale` command, which could reach another daemon). The UI, end-to-end and smoke tests point it at a missing path so that test servers never reach the machine's real tailscaled. |
| `FILEPARCEL_SUPERVISED=1` | Declares that a supervisor restarts the process (Docker restart policy, runit, …): a restart request then exits with code 75 instead of re-executing in place. systemd and launchd are detected automatically. |
| `NO_COLOR`, `TERM=dumb` | Disable colours in the CLI output. |
| `VISUAL`, `EDITOR` | Editor for `fileparcel config edit`. |
| `XDG_DATA_HOME` | Changes the default user installation directory (`$XDG_DATA_HOME/fileparcel`). |

### Runtime settings

All runtime settings with their defaults. *Restart* marks settings that take effect after a restart;
*secret* settings are stored encrypted and never shown. In the web app they are grouped into the same
sections (Admin → Settings → *section*).

<!-- BEGIN GENERATED SETTINGS REFERENCE -->
<!-- Regenerate with scripts/gen-settings-docs.sh; edit the setting labels and descriptions in the owning package (settings.Register) instead. -->

#### General

| Key | Default | Description |
|---|---|---|
| `ui.instance_name` | `FileParcel` | **Instance name.** Shown in the browser title, the sign-in page, the installed app and e-mails. |
| `ui.accent_color` | `#2b7ad6` | **Accent colour.** Brand colour of buttons and links (#rrggbb). A lighter variant is derived for dark mode. |
| `ui.default_theme` | `system` | **Default theme.** Theme for visitors and users who have not chosen one (system follows the device). One of: `light`, `dark`, `system`. |
| `ui.login_message` | `""` | **Sign-in message.** Optional notice shown on the sign-in page (plain text). |
| `ui.default_view` | `list` | **Default file view.** Initial layout of folder listings for users who have not chosen one. One of: `list`, `grid`. |
| `maintenance.enabled` | `false` | **Maintenance mode.** Keep users out while you work on the server: the web UI shows a notice and requests for files, shares and uploads are answered with 503. Administrators (and roles allowed to operate the server), this server's own CLI, signing in and every user's own account settings (profile, password, two-factor, sessions, tokens) keep working; invitations cannot be accepted until it is switched off again. |
| `maintenance.message` | `""` | **Maintenance notice.** Text shown while maintenance mode is on (plain text; a default is used when empty). |

#### Network

| Key | Default | Description |
|---|---|---|
| `network.access_mode` | `allowlist` | **Access mode.** Which client addresses may connect. private: loopback and private/VPN ranges (10/8, 172.16/12, 192.168/16, 169.254/16, 100.64/10, fc00::/7, fe80::/10) plus the allow list; allowlist: loopback and the allow list only; any: every address (public exposure). The deny list always wins; loopback is always allowed. One of: `private`, `allowlist`, `any`. |
| `network.allow_cidrs` | `[]` | **Allowed networks.** CIDRs or single IP addresses allowed to connect (e.g. 192.168.1.0/24, 100.64.0.0/10). List of CIDRs/IPs. |
| `network.deny_cidrs` | `[]` | **Denied networks.** CIDRs or single IP addresses that are always refused, whatever the access mode. List of CIDRs/IPs. |
| `network.strict_host` | `false` | **Strict Host check.** Only answer requests whose Host header names this server (its addresses, .local and MagicDNS names, the public URL and the extra host names). Defeats DNS-rebinding attacks from web pages. |
| `network.extra_hosts` | `[]` | **Extra host names.** Additional DNS names this server answers to (e.g. a name in your own DNS). They are added to the local certificate and the access URLs. "*.example.org" matches one label. List. |
| `network.iface_roles` | `[]` | **Interface roles.** Corrects how FileParcel treats a network interface, one "<interface>=<role>" entry each (e.g. wg0=mesh). mesh: devices of that network can reach this server (its addresses are offered); unknown: the same, for a tunnel of unknown kind; local: a LAN, also announced over mDNS; egress: an outgoing VPN or internet uplink and access: a corporate or zero-trust client (not offered); overlay: a public overlay network (not offered); none: ignored. Later entries win; at most 64. List. |

#### Local name (mDNS)

| Key | Default | Description |
|---|---|---|
| `mdns.mode` | `auto` | **mDNS publishing.** How <name>.local and the _https._tcp service are announced on the local network. auto: Avahi (Linux, via D-Bus) when it runs, dns-sd on macOS, else the builtin responder; off disables publishing. One of: `auto`, `avahi`, `dnssd`, `builtin`, `off`. |
| `mdns.name` | `""` | **mDNS name.** Label published as <name>.local. Empty uses the server name. Lowercase letters, digits and '-'. On a name collision "-2", "-3", … is appended automatically. While the passkey domain (auth.webauthn_rp_id) is empty, <name>.local is also the domain passkeys are bound to: changing it makes existing passkeys unusable. |
| `mdns.interfaces` | `lan` | **mDNS interfaces.** "lan" publishes on every local interface (LAN and Wi-Fi, never an exit VPN or an unknown tunnel; network.iface_roles can set an interface to local); or list interface names separated by commas (e.g. "eth0, wlan0"), including "lan" to add them to the LAN set (e.g. "lan, br0"). mDNS does not cross routed VPNs (Tailscale, WireGuard): use MagicDNS or the IP there. |
| `mdns.zerotier` | `false` | **Publish on ZeroTier.** Also publish on ZeroTier interfaces (a layer-2 VPN where multicast works) when mDNS interfaces includes "lan". |

#### TLS

| Key | Default | Description |
|---|---|---|
| `tls.extra_sans` | `[]` | **Extra certificate names.** Additional DNS names or IP addresses for the local certificate (e.g. a DNS name pointing at this server). Names outside the local CA's name constraints require regenerating the CA. List. |
| `tls.hsts` | `auto` | **HSTS.** Strict-Transport-Security: auto sends it only while the served certificate is publicly trusted. One of: `auto`, `on`, `off`. |
| `tls.min_version` | `1.2` | **Minimum TLS version.** Oldest TLS version accepted: 1.2 (default) or 1.3. One of: `1.2`, `1.3`. |
| `tls.leaf_days` | `397` | **Local certificate validity (days).** Validity of the server certificate issued by the local CA (Apple devices accept at most 825 days). Range 7–825. |

#### ACME certificates

| Key | Default | Description |
|---|---|---|
| `acme.enabled` | `false` | **Use ACME (Let's Encrypt).** Obtain publicly trusted certificates for the ACME domains. |
| `acme.email` | `""` | **ACME account e-mail.** Account e-mail for the ACME CA (expiry notices). |
| `acme.domains` | `[]` | **ACME domains.** Public DNS names to obtain certificates for (wildcards need the dns challenge). List. |
| `acme.ca` | `staging` | **ACME CA.** "staging" (Let's Encrypt staging, not trusted), "production" (Let's Encrypt) or an ACME directory URL. |
| `acme.challenge` | `dns` | **ACME challenge.** dns works without public reachability; http needs port 80 forwarded to the HTTP port, tls-alpn needs port 443 forwarded to the HTTPS port. The validation requests are admitted even from addresses outside the access policy (they reach nothing but the challenge). One of: `dns`, `http`, `tls-alpn`. |
| `acme.dns_provider` | `cloudflare` | **DNS provider.** DNS provider for the dns challenge: cloudflare or rfc2136. One of: `cloudflare`, `rfc2136`. |
| `acme.dns_credentials` | *(secret, unset)* | **DNS provider credentials.** JSON object. Cloudflare: {"api_token":"…"} (optionally "zone_token"); RFC 2136: {"server":"ns.example.com:53","key_name":"…","key_alg":"hmac-sha256.","key":"<base64>"}. *Secret.* |

#### Tailscale

| Key | Default | Description |
|---|---|---|
| `tailscale.cert_enabled` | `false` | **Use Tailscale HTTPS certificate.** Fetch a certificate for the MagicDNS name from tailscaled (needs HTTPS enabled for the tailnet and operator permission). |
| `tailscale.domain` | `""` | **Tailscale certificate name.** MagicDNS name to fetch a certificate for (empty = this machine's MagicDNS name). |

#### Tailscale Funnel

| Key | Default | Description |
|---|---|---|
| `funnel.mode` | `off` | **Tailscale Funnel.** Publish FileParcel on the internet through Tailscale Funnel. shares: only share links and file requests; app: the whole app with sign-in (two-factor accounts only). Changed on the Network page or with "fileparcel network funnel". One of: `off`, `shares`, `app`. |
| `funnel.port` | `443` | **Funnel port.** Public HTTPS port of the Funnel address: 443, 8443 or 10000 (as far as the tailnet policy allows it). Range 1–65535. |
| `funnel.allow_admin` | `false` | **Administration over Funnel.** Allow the admin pages over the public Funnel address (mode app only; needs two-factor sign-in). |
| `funnel.require_2fa` | `true` | **Two-factor sign-in over Funnel.** Over the public Funnel address only accounts with two-factor authentication can sign in. |
| `funnel.serve` | `false` | **Tailscale Serve.** Publish FileParcel on the tailnet with Tailscale's HTTPS certificate and without a port (https://<device>.<tailnet>.ts.net/). Changed on the Network page or with "fileparcel network tailscale-serve". |
| `funnel.serve_port` | `443` | **Serve port.** Tailnet HTTPS port of Tailscale Serve. Range 1–65535. |
| `funnel.node` | `""` | **Tailscale device.** The Tailscale device (stable node ID) Funnel and Serve were turned on for. A restored backup or a copied home publishes nothing on another device. |
| `funnel.backend` | `auto` | **Connection from Tailscale.** How tailscaled reaches FileParcel. unix: a private socket in the run directory; tcp: 127.0.0.1 on funnel.backend_port; auto: the socket where tailscaled allows it (Linux), otherwise tcp. One of: `auto`, `unix`, `tcp`. |
| `funnel.backend_port` | `0` | **Local port for Tailscale.** First of the two 127.0.0.1 ports of the tcp connection (Funnel, then Serve); 0 = chosen at first use. Range 0–65534. |

#### Client certificates

| Key | Default | Description |
|---|---|---|
| `mtls.mode` | `off` | **Client certificates (mTLS).** required: only devices with a client certificate issued by this server can use it. One of: `off`, `optional`, `required`. |
| `mtls.exempt_shares` | `true` | **Exempt public share links.** In required mode, share links, the trust page and health checks work without a client certificate. |
| `mtls.self_service` | `false` | **Users may issue their own client certificates.** Users may issue client certificates for their own devices (Settings → Devices). |

#### Sign-in & security

| Key | Default | Description |
|---|---|---|
| `auth.password_min` | `12` | **Minimum password length.** Minimum number of characters of new passwords. Common passwords and passwords containing the username are always rejected. Range 8–128. |
| `auth.require_2fa` | `admins` | **Require two-factor authentication.** Users in scope must set up an authenticator app or a passkey before they can use FileParcel. "admins" covers owners, admins and every role with a server permission. One of: `off`, `admins`, `all`. |
| `auth.passkeys` | `true` | **Passkeys.** Allow signing in and confirming your identity with passkeys (WebAuthn). Passkeys need a trusted certificate. Turning this off shuts out accounts whose only second factor is a passkey until an administrator resets their two-factor authentication, so while such accounts exist it has to be confirmed. |
| `auth.webauthn_rp_id` | `""` | **Passkey domain (RP ID).** Domain passkeys are bound to. Empty = <mDNS name>.local. Changing it makes existing passkeys unusable. |
| `auth.webauthn_origins` | `[]` | **Extra passkey origins.** Additional https:// origins allowed for passkeys. Empty = the passkey domain, the public URL and the other names this server serves under that domain (extra hosts, extra SANs, ACME domains), at the HTTPS port. Add an origin for a reverse proxy on another name or port. List. |
| `auth.session_idle_min` | `720` | **Session idle timeout (minutes).** Browser sessions end after this much inactivity. Range 5–525600. |
| `auth.session_max_days` | `30` | **Remembered session lifetime (days).** Absolute lifetime of sessions created with "remember me"; other sessions end with the browser or after 24 hours. Range 1–365. |
| `auth.lockout_threshold` | `10` | **Lockout threshold.** Consecutive failed sign-ins before an account is temporarily locked. Range 3–1000. |
| `auth.lockout_base_min` | `15` | **Lockout duration (minutes).** First lockout duration; it doubles with every further lockout, up to 24 hours. Range 1–1440. |
| `auth.stepup_min` | `10` | **Identity confirmation window (minutes).** How long sensitive actions stay unlocked after confirming your identity. Range 1–120. |
| `auth.admin_can_access_files` | `false` | **Administrators can access all files.** Lets owners and admins manage every space; every such access is audited. Custom roles never get this. |

#### Rate limits

| Key | Default | Description |
|---|---|---|
| `ratelimit.login_per_min` | `10` | **Sign-in attempts per minute (per IP).** Login, second-factor, passkey, setup and invitation requests allowed per minute from one IP address; starting a passkey sign-in and opening an invitation, which the sign-in pages do on every load, get four times as many. Also the password attempts one IP address may make on a share link. Range 1–10000. |
| `ratelimit.api_rps` | `50` | **API requests per second (per IP).** Sustained rate of /api/v1 requests allowed from one IP address. Range 1–100000. |
| `ratelimit.api_burst` | `200` | **API burst (per IP).** Number of API requests one IP address may send in a quick burst. Range 1–1000000. |
| `ratelimit.share_per_min` | `120` | **Public share requests per minute (per IP).** Requests to public share links and file requests allowed per minute from one IP address. Range 1–100000. |
| `ratelimit.unlock_per_min` | `5` | **Unlock attempts per minute (per IP).** Web unlock attempts of a sealed server allowed per minute from one IP address. Range 1–1000. |
| `ratelimit.funnel_per_min` | `1200` | **Tailscale Funnel requests per minute (per client).** Requests one internet client may send per minute over Tailscale Funnel (IPv6 clients: per /64 network). The other limits apply as well. Range 1–100000. |
| `ratelimit.funnel_global_per_min` | `12000` | **Tailscale Funnel requests per minute (all clients).** Requests all internet clients together may send per minute over Tailscale Funnel. Range 1–1000000. |

#### Storage

| Key | Default | Description |
|---|---|---|
| `storage.default_quota_gb` | `0` | **Default user quota (GB).** Storage quota of users without an individual quota, counting all versions of their files (including the trash). 0 = unlimited. Range 0–8388608. |
| `storage.max_file_gb` | `0` | **Maximum file size (GB).** Largest single file that can be stored (a zip-on-upload counts as one file; an upload is limited to 8 TiB per file anyway). 0 = unlimited. Range 0–8388608. |
| `storage.trash_days` | `30` | **Trash retention (days).** Items in the trash are deleted permanently after this many days (daily job). 0 = keep until emptied. Range 0–3650. |
| `storage.versions_keep` | `10` | **Versions to keep.** Number of versions kept per file, including the current one. Older versions are deleted. Range 1–1000. |
| `storage.upload_parallel` | `4` | **Parallel upload parts.** How many 8 MiB parts a browser uploads at the same time. Range 1–16. |
| `storage.upload_expiry_hours` | `48` | **Unfinished upload expiry (hours).** Uploads that are not completed within this time are cancelled and their partial data is deleted by the hourly maintenance job. Range 1–720. |
| `storage.zip_compression` | `auto` | **Zip compression.** Compression of folder downloads and zip-on-upload: auto stores already-compressed types (photos, videos, archives, office files) and deflates the rest. One of: `auto`, `store`, `deflate`. |
| `storage.zip_password_min` | `12` | **Minimum .zip password length.** Shortest password accepted for a password-protected .zip created on upload. The .zip format's key derivation is fast (PBKDF2-SHA1, 1000 rounds), so short passwords can be guessed offline. Range 8–64. |
| `storage.zip_legacy_encryption` | `true` | **Allow ZipCrypto for protected .zip files.** ZipCrypto opens in the unzip built into Windows and macOS but can usually be broken without the password. AES-256 is always available. Turning this off does not affect uploads already started. |
| `storage.thumbnails` | `true` | **Image thumbnails.** Generate thumbnails (at most 320 px, stored encrypted) for JPEG, PNG, GIF, WebP and BMP images up to 50 megapixels. |
| `storage.cipher` | `auto` | **Blob cipher.** Cipher for newly written files. auto picks AES-256-GCM on CPUs with AES instructions and ChaCha20-Poly1305 otherwise (e.g. Raspberry Pi 4). Existing files keep their cipher. One of: `auto`, `aes-gcm`, `chacha20-poly1305`. |
| `storage.fsync` | `true` | **Flush file data to disk.** fsync every uploaded part and committed file before acknowledging it. Turning it off is faster but a power loss may lose recently uploaded files. |

#### Sharing

| Key | Default | Description |
|---|---|---|
| `sharing.links_enabled` | `true` | **Allow share links.** Users may create public links to files and folders they manage. Turning this off disables existing links too. |
| `sharing.require_password` | `false` | **Require a password for new links.** New share links and file requests must be protected by a password. |
| `sharing.max_expiry_days` | `0` | **Maximum link lifetime (days).** Counted from the creation of a link: owners may shorten the expiry but never extend it beyond this. 0 = links may be created without expiry. Range 0–3650. |
| `sharing.default_expiry_days` | `7` | **Default link lifetime (days).** Expiry proposed for new links; 0 = no expiry by default (capped by the maximum). Range 0–3650. |
| `sharing.requests_enabled` | `true` | **Allow file requests.** Users may create public upload links (file requests) for folders they manage. |
| `sharing.allow_guests_share` | `false` | **Guests may share.** Allow accounts with the built-in Guest role to create share links and file requests. Custom roles use their own permissions. |
| `sharing.access_log_days` | `365` | **Access log retention (days).** Access-log entries of share links and file requests (with the visitors' IP addresses) older than this are deleted daily. 0 = keep them as long as the link exists. Range 0–3650. |

#### Encryption

| Key | Default | Description |
|---|---|---|
| `keys.web_unlock` | `lan` | **Web unlock.** Where the sealed server may be unlocked from the /unlock page: lan (local and VPN networks), any, or off (only with "fileparcel keys unlock" on the server). One of: `lan`, `any`, `off`. |

#### Backups

| Key | Default | Description |
|---|---|---|
| `backup.enabled` | `true` | **Scheduled backups.** Run the metadata and full backup schedules below. Manual backups are always possible. |
| `backup.schedule_meta` | `0 3 * * *` | **Metadata backup schedule.** Cron schedule (local time) of metadata backups: database, configuration, keys and certificates, without file contents. Empty = off. Cron expression (5 fields). |
| `backup.schedule_full` | `0 4 * * 0` | **Full backup schedule.** Cron schedule (local time) of full backups, which also contain every (already encrypted) file. Empty = off. Cron expression (5 fields). |
| `backup.keep_last` | `7` | **Keep last.** Retention: always keep this many most recent scheduled backups (per scope). 0 = ignore this rule; with all four keep_* values at 0 retention is off and no backup is pruned. Only scheduled backups are pruned; manual, imported, pre-upgrade and final backups are kept until they are deleted by hand. Range 0–1000. |
| `backup.keep_daily` | `7` | **Keep daily.** Retention: keep the newest backup of each of this many most recent days. 0 = ignore this rule (see Keep last). Only scheduled backups are pruned; manual, imported, pre-upgrade and final backups are kept until they are deleted by hand. Range 0–3650. |
| `backup.keep_weekly` | `4` | **Keep weekly.** Retention: keep the newest backup of each of this many most recent ISO weeks. 0 = ignore this rule (see Keep last). Only scheduled backups are pruned; manual, imported, pre-upgrade and final backups are kept until they are deleted by hand. Range 0–520. |
| `backup.keep_monthly` | `6` | **Keep monthly.** Retention: keep the newest backup of each of this many most recent months. 0 = ignore this rule (see Keep last). Only scheduled backups are pruned; manual, imported, pre-upgrade and final backups are kept until they are deleted by hand. Range 0–1200. |
| `backup.encryption` | `x25519` | **Backup encryption.** x25519: encrypt to age public keys (scheduled backups need no secret). passphrase: encrypt with the backup passphrase (age scrypt). One of: `x25519`, `passphrase`. |
| `backup.recipients` | `[]` | **Backup recipients.** age public keys (age1…) that can decrypt backups. The recipient of the backup identity is added automatically. Post-quantum (age1pq1…) and classic keys can't be mixed. List. |
| `backup.identity` | *(secret, unset)* | **Backup identity.** The age secret key used to verify and restore backups. Generate it on the Backups page and store a copy offline. *Secret.* |
| `backup.passphrase` | *(secret, unset)* | **Backup passphrase.** Passphrase for passphrase-encrypted backups (at least 12 characters). *Secret.* |
| `backup.copy_to` | `""` | **Copy backups to.** Optional absolute directory outside the FileParcel directory (e.g. a mounted NAS or USB disk) that receives a copy of every new backup. |

#### Email

| Key | Default | Description |
|---|---|---|
| `smtp.host` | `""` | **SMTP server.** Host name or IP address of the mail server. Leave empty to disable e-mail notifications. |
| `smtp.port` | `587` | **SMTP port.** 587 for STARTTLS (submission), 465 for implicit TLS, 25 for plain SMTP. Range 1–65535. |
| `smtp.tls` | `starttls` | **SMTP encryption.** starttls upgrades the connection (and fails if the server cannot), tls encrypts from the start, none sends in clear text (no login possible). One of: `starttls`, `tls`, `none`. |
| `smtp.username` | `""` | **SMTP username.** User name for SMTP authentication (AUTH PLAIN, only over TLS). Leave empty if the server needs no login. |
| `smtp.password` | *(secret, unset)* | **SMTP password.** Password for SMTP authentication (stored encrypted). *Secret.* |
| `smtp.from` | `""` | **Sender address.** From address of notification e-mails, e.g. "FileParcel <files@example.com>". Defaults to the SMTP username when that is an e-mail address. |
| `notify.events` | `["share.upload", "security"]` | **Notifications.** Which notifications are e-mailed: "share.upload" (uploads through file requests, to the request owner) and "security" (lockouts, new passkeys or tokens, two-factor resets, to the affected user). Invitations are always sent when requested. List. |

#### Audit

| Key | Default | Description |
|---|---|---|
| `audit.retention_days` | `365` | **Audit log retention (days).** Audit entries older than this are pruned daily (the hash chain keeps an authenticated anchor). 0 keeps entries forever. Range 0–36500. |
| `audit.mirror_jsonl` | `false` | **Mirror audit log to logs/audit.jsonl.** Append every audit entry as one JSON line to logs/audit.jsonl (rotated like the server log), e.g. for log shippers. |

#### Server (stored in fileparcel.toml)

| Key | Default | Description |
|---|---|---|
| `server.name` | `fileparcel` | **Server name.** DNS label used for <name>.local (mDNS, applied live), the local CA name and the default WebAuthn RP ID. Lowercase letters, digits and '-'. Changing it orphans passkeys registered for the old name. *Restart.* |
| `server.https_port` | `8443` | **HTTPS port.** TCP port of the HTTPS listener. Ports below 1024 need root or CAP_NET_BIND_SERVICE. Range 1–65535. *Restart.* |
| `server.http_port` | `8080` | **HTTP redirect port.** Plain-HTTP port that redirects to HTTPS and answers ACME HTTP-01 challenges; 0 disables it. Range 0–65535. *Restart.* |
| `server.bind` | `["::"]` | **Listen addresses.** IP addresses to listen on. "::" listens on every interface (IPv4 and IPv6), so list it alone; the access policy does the filtering. List. *Restart.* |
| `server.public_url` | `""` | **Public URL.** Optional canonical URL (e.g. behind a reverse proxy) used in links, invitations and for WebAuthn: scheme, host and port only, such as https://files.example.com. *Restart.* |
| `server.trusted_proxies` | `[]` | **Trusted reverse proxies.** Addresses or CIDRs whose X-Forwarded-For header is trusted for the client IP (access policy, rate limits, audit). List of CIDRs/IPs. |
| `log.level` | `info` | **Log level.** Minimum level written to the log (applied immediately). One of: `debug`, `info`, `warn`, `error`. |
| `runtime.gomemlimit_mb` | `0` | **Go memory limit (MiB).** Soft limit for the Go heap, applied at start. 0 = automatic (the smaller of 1 GiB and a quarter of the memory available to the process). An explicit $GOMEMLIMIT wins. Range 0–1048576. *Restart.* |

<!-- END GENERATED SETTINGS REFERENCE -->

---

## Security model

FileParcel's security design in brief; the full threat model, the list of controls and how to report a
vulnerability are in [`SECURITY.md`](SECURITY.md), the cryptographic formats in
[`ENCRYPTION.md`](ENCRYPTION.md).

- **Network first.** The access policy (loopback + your LAN/VPN ranges by default) is enforced before TLS;
  other addresses cannot even start a handshake. The admin socket accepts only the server's own user or
  root (kernel peer credentials).
- **Internet exposure is opt-in.** Nothing is public by default.
  [Tailscale Funnel](#share-links-on-the-internet-tailscale-funnel) publishes through listeners of its own:
  share links only (every other path is "not found" and no session gets through), or the whole app with
  sign-in limited to accounts with a second factor and administration blocked unless allowed. Weakening that needs a built-in owner or administrator; hand-made
  `tailscale funnel` setups pointed at FileParcel's port are refused.
- **Transport.** HTTPS only (TLS 1.2+, modern AEAD ciphers, HTTP/2, post-quantum key exchange where
  supported); plain HTTP only redirects. A name-constrained local CA, or ACME/Tailscale/custom
  certificates. Optional client certificates (mTLS). HSTS once a publicly trusted certificate is used.
- **Authentication.** argon2id password hashes; uniform, timing-equalised failures; per-IP rate limits
  (remote IPv6 clients also per /64) and exponential account lockout; TOTP with replay protection, single-use recovery codes, passkeys
  (WebAuthn); 2FA required by default for administrators and every role with server permissions; step-up
  for sensitive actions; sessions in `__Host-` cookies (`Secure`, `HttpOnly`, `SameSite=Lax`) stored only as hashes, rotated on sign-in and
  privilege changes, with idle and absolute timeouts; scoped, expiring API tokens stored as hashes.
- **Authorization.** Every request is checked per item (no enumeration: items you cannot see answer
  "not found"); every account has one role, and the parts of the Admin area open per permission (custom roles
  are never administrators, and account managers cannot give more than they have); administrators do not see
  users' files unless explicitly configured, and then every access is audited; share links and archive tickets are unguessable (≥ 128-bit) and stored hashed.
- **Web hardening.** A strict Content Security Policy without inline scripts or styles, with **Trusted
  Types** enforced; no third-party code, fonts or CDNs; CSRF protection by origin checks *and* a per-session
  token; `X-Frame-Options: DENY`, `nosniff`, `Referrer-Policy: no-referrer`, COOP/CORP. User content is
  served as attachments or with a sandboxing CSP; HTML, SVG and scripts are never rendered.
- **Data at rest.** Per-file keys, authenticated segment encryption, encrypted secrets, a plain or
  passphrase-sealed master key, key rotation, encrypted backups. Names and metadata are not encrypted —
  use full-disk encryption as well. A [password-protected .zip](#password-protecting-the-zip) (AES-256) keeps
  files protected after they leave the server; its password is sealed while the zip is built and then
  forgotten.
- **Accountability.** A hash-chained audit log of security-relevant actions; logs never contain secrets.
- **Least privilege at runtime.** Runs as an unprivileged user with `umask 077`, refuses to run as root,
  confines all file access to its directory (traversal-proof `os.Root` for stored data); the system
  service adds systemd sandboxing; the Docker image is distroless, read-only and without capabilities.
- **Supply chain.** A single static Go binary, a small set of well-known Go modules (listed below), no
  JavaScript dependencies, reproducible release zips with checksums and the full source included.

**Your part:** keep the server updated; trust the local CA only on your own devices and compare the
fingerprint; require 2FA; keep `network.access_mode` at `allowlist` or `private`; use full-disk
encryption; store the backup identity and (sealed mode) the recovery key offline; keep backups on another
disk; open the firewall only for the networks you need.

---

## Packages used

FileParcel is written in Go and compiled into one static binary (`CGO_ENABLED=0`). The web app is plain
JavaScript modules and CSS written for FileParcel — **no npm packages, frameworks, fonts or CDNs**. The
icons are derived from [Lucide](https://lucide.dev) (ISC license). The complete list of every linked
module with its license (including indirect dependencies) is in [`THIRD_PARTY.md`](THIRD_PARTY.md);
`NOTICE` contains the notices required by their licenses.

| Module | Version | License | Used for |
|---|---|---|---|
| [Go standard library](https://go.dev) | 1.27.1 | BSD-3-Clause | HTTP/2 server, TLS (incl. X25519MLKEM768), crypto (AES-GCM, ECDSA, HKDF, SHA-2), `os.Root`, embedded time zones |
| [github.com/go-chi/chi/v5](https://github.com/go-chi/chi) | v5.3.2 | MIT | HTTP router |
| [modernc.org/sqlite](https://gitlab.com/cznic/sqlite) | v1.59.0 | BSD-3-Clause (SQLite: public domain) | Embedded pure-Go SQLite database with FTS5 search |
| [golang.org/x/crypto](https://pkg.go.dev/golang.org/x/crypto) | v0.57.0 | BSD-3-Clause | argon2id, ChaCha20-Poly1305 |
| [golang.org/x/sys](https://pkg.go.dev/golang.org/x/sys) | v0.48.0 | BSD-3-Clause | File locking, peer credentials, `mlock`, disk space, CPU feature detection |
| [golang.org/x/term](https://pkg.go.dev/golang.org/x/term) | v0.46.0 | BSD-3-Clause | Password prompts without echo |
| [golang.org/x/time](https://pkg.go.dev/golang.org/x/time) | v0.16.0 | BSD-3-Clause | Rate limiting (token buckets) |
| [golang.org/x/net](https://pkg.go.dev/golang.org/x/net) | v0.59.0 | BSD-3-Clause | IPv4/IPv6 multicast sockets for mDNS |
| [golang.org/x/text](https://pkg.go.dev/golang.org/x/text) | v0.42.0 | BSD-3-Clause | Unicode normalisation and case folding of file names |
| [golang.org/x/image](https://pkg.go.dev/golang.org/x/image) | v0.46.0 | BSD-3-Clause | WebP/BMP decoding and high-quality scaling for thumbnails |
| [github.com/spf13/cobra](https://github.com/spf13/cobra) | v1.10.2 | Apache-2.0 | Command-line interface |
| [github.com/spf13/pflag](https://github.com/spf13/pflag) | v1.0.9 | BSD-3-Clause | Command-line flags (used with cobra) |
| [github.com/pelletier/go-toml/v2](https://github.com/pelletier/go-toml) | v2.4.3 | MIT | `fileparcel.toml` |
| [github.com/pquerna/otp](https://github.com/pquerna/otp) | v1.5.0 | Apache-2.0 | TOTP (authenticator apps) |
| [github.com/boombuler/barcode](https://github.com/boombuler/barcode) | v1.1.0 | MIT | QR code matrices (rendered to SVG and the terminal by FileParcel) |
| [github.com/go-webauthn/webauthn](https://github.com/go-webauthn/webauthn) | v0.18.1 | BSD-3-Clause | Passkeys (WebAuthn) |
| [filippo.io/age](https://github.com/FiloSottile/age) | v1.3.2 | BSD-3-Clause | Backup encryption |
| [github.com/klauspost/compress](https://github.com/klauspost/compress) | v1.20.0 | BSD-3-Clause (parts Apache-2.0, MIT) | zstd for backups and static assets, fast Deflate for zips |
| [software.sslmate.com/src/go-pkcs12](https://github.com/SSLMate/go-pkcs12) | v0.7.3 | BSD-3-Clause | Client certificates as `.p12` files |
| [github.com/caddyserver/certmagic](https://github.com/caddyserver/certmagic) | v0.25.4 | Apache-2.0 | ACME certificates (Let's Encrypt) and renewal |
| [github.com/libdns/cloudflare](https://github.com/libdns/cloudflare) | v0.2.2 | MIT | ACME DNS challenge via Cloudflare |
| [github.com/libdns/rfc2136](https://github.com/libdns/rfc2136) | v1.0.1 | MIT | ACME DNS challenge via RFC 2136 (BIND, Knot, PowerDNS, …) |
| [go.uber.org/zap](https://github.com/uber-go/zap) | v1.27.1 | MIT | Logging interface certmagic writes to (its records go into the FileParcel log) |
| [github.com/pion/mdns/v2](https://github.com/pion/mdns) | v2.2.1 | MIT | Built-in mDNS responder |
| [github.com/godbus/dbus/v5](https://github.com/godbus/dbus) | v5.2.2 | BSD-2-Clause | Publishing `.local` names through Avahi on Linux |

Development tools (never part of the binary): `staticcheck`, `govulncheck`, `shellcheck`; the UI tests use
Playwright for Python and pytest.

---

## Known limitations

These parts of FileParcel pass the automated tests, but have not yet run against the real services they
talk to. Try them on your own setup before you depend on them:

- **Let's Encrypt and other ACME CAs.** The settings, the DNS providers and the challenges are tested, but
  never against a real certificate authority. Start with the staging CA (the default of
  `fileparcel cert acme enable`) and check `fileparcel cert status`.
- **Tailscale** (Funnel, Serve and Tailscale certificates). Tested only against a stand-in for tailscaled.
  After turning one on, check it with `fileparcel network funnel status --refresh` (or
  `network tailscale-serve status --refresh`), and open a share link from a phone outside your network.
- **`.local` names on a Mac.** Publishing with the Mac's own `dns-sd` is tested only with a stand-in for it.

And one limit of the design:

- **Client certificates are not tied to an account.** With `mtls.mode = required`, a device connects with
  any valid, unrevoked client certificate of an active user; it does not have to be a certificate of the
  account that then signs in there. The certificate keeps unknown devices out, the sign-in decides who you
  are. Revoke the certificate of a lost device at once.

---

## Troubleshooting and FAQ

Start with `fileparcel doctor` on the server: it checks the installation, the running server and the
service, and says what to do about each problem (`--fix` repairs the safe ones). Problems with installing,
connecting and starting the server are answered in the installation guide, under
[Fix installation problems](INSTALL.md#fix-installation-problems):

- [The browser warns that the connection is not private](INSTALL.md#the-browser-warns-that-the-connection-is-not-private)
- [Other devices cannot connect (timeout, "connection refused" or "reset")](INSTALL.md#other-devices-cannot-connect-timeout-connection-refused-or-reset)
- [`fileparcel: command not found`](INSTALL.md#fileparcel-command-not-found)
- [`fileparcel.local` does not resolve](INSTALL.md#fileparcellocal-does-not-resolve)
- ["address already in use" / the installer says a port is in use](INSTALL.md#the-installer-says-a-port-is-in-use)
- [The service does not start](INSTALL.md#the-service-does-not-start)
- [It stops when I log out, or does not start at boot](INSTALL.md#it-stops-when-i-log-out-or-does-not-start-at-boot-linux-user-service)
- [`systemctl --user` says "Failed to connect to bus"](INSTALL.md#systemctl---user-says-failed-to-connect-to-bus)
- [The server is locked, or pages show an unlock screen](INSTALL.md#the-server-is-locked-or-pages-show-an-unlock-screen)
- [The upgrade was rolled back](INSTALL.md#the-upgrade-was-rolled-back)
- [I forgot the admin password](INSTALL.md#i-forgot-the-admin-password)
- [Tailscale certificates, Serve or Funnel do not work](INSTALL.md#tailscale-certificates-serve-or-funnel-do-not-work)

**Passkeys are not offered / fail.**
Passkeys need a trusted certificate and a host name (never an IP address) that matches the passkey domain
(`auth.webauthn_rp_id`, default `<name>.local`) or is a name below it. Open FileParcel via
`https://fileparcel.local:8443` (or your ts.net/own domain and set the passkey domain accordingly). Names
you serve under the passkey domain — extra host names, extra certificate names and ACME domains — are
accepted automatically; for a reverse proxy on another name or port add it to `auth.webauthn_origins`.
Authenticator apps (TOTP) always work.

**I lost my phone with the authenticator app.**
Sign in with one of your recovery codes, then set up the new phone. Without recovery codes an administrator
resets your second factor (`fileparcel user reset-2fa <name>`). If you are the only admin, run that command
on the server itself.

**Uploads fail or stop.**
Check free disk space (FileParcel keeps at least 1 GiB / 2 % free), your quota, `storage.max_file_gb`, and
the log. Uploads resume automatically after network interruptions; after closing the tab, select the same
files again to resume. Behind a reverse proxy, raise its request body limit (parts are 8 MiB) and timeouts.

**"the home … is locked by another process but its admin socket is not answering" / the CLI cannot connect.**
The server holds the installation's lock but its admin socket does not answer — it may be hanging or
starting. `fileparcel doctor` explains; `fileparcel service restart` usually helps. Never delete
`run/fileparcel.lock` while a server runs. A second `fileparcel serve` reports "another FileParcel process
is using <HOME>" instead: a server (or an offline admin command) is already running — see
`fileparcel status`, and stop it with `fileparcel service stop` if needed.

**Let's Encrypt fails.** Test with staging first (the default). For the DNS challenge, check the API token
permissions (Cloudflare: Zone → DNS → Edit for the zone). HTTP/TLS-ALPN challenges need the ports reachable
from the internet. Details are in the log (`fileparcel logs -n 100`).

**Windows says a downloaded zip is invalid / macOS Archive Utility fails on a big zip.**
Very large streamed zips use zip64; use 7-Zip on Windows, or download as `.tar` on macOS.

**How much space do versions and the trash use?** The sidebar shows your usage (versions and the trash
count); admins see every user's usage in Admin → Users. Lower `storage.versions_keep` or `storage.trash_days`, or empty the trash.

**Can I move FileParcel to another disk or machine?** Yes — see
[Move FileParcel](INSTALL.md#move-fileparcel) in the installation guide: to another folder or disk on the
same machine, or to a new machine with a full backup.

**Can I share links with people outside my network?** Yes: use Tailscale Funnel in *Share links only*
mode. It puts just your share links and file requests on the internet, with no router port and no
firewall rule ([Put share links on the internet](INSTALL.md#put-share-links-on-the-internet-tailscale-funnel)).
Your own devices reach the whole app over a VPN such as Tailscale.

**Can I expose the whole app to the internet?** It is designed for private networks and VPNs; Funnel's
*Full app* mode (sign-in with two-factor authentication only) is the safer way. As a last resort for a
public server of your own: use a publicly trusted certificate (ACME), `network.access_mode = any`, require
2FA for everyone (`auth.require_2fa = all`), consider mTLS, keep it updated, and watch the audit log.

**Where are my files on disk?** In `<HOME>/data/blobs/`, encrypted, under random names. They can only be
read through FileParcel (or after a restore from a backup). Use downloads, `fileparcel files get` or a
backup to get them out.

**How do I report a bug or a security problem?** Bugs: open an issue on
[GitHub](https://github.com/kpdirectmail/fileparcel/issues/new/choose) and include `fileparcel version`,
`fileparcel doctor` output and the relevant log lines (they contain no passwords or keys, but remove host
names and addresses you do not want to publish). Security problems: report them privately, as described in
[`SECURITY.md`](SECURITY.md#reporting-a-vulnerability).

---

## License

FileParcel is licensed under the [Apache License, Version 2.0](../LICENSE). Copyright 2026 The FileParcel
Authors. Third-party components are listed in [`THIRD_PARTY.md`](THIRD_PARTY.md) and [`NOTICE`](../NOTICE).
(`LICENSE` and `NOTICE` are at the top of the release zip; the copy of these documents in an installation's
`docs/` folder does not include them.)
