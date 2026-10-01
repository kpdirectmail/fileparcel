# The fileparcel command

`fileparcel` is one program that does two jobs: it **is** the FileParcel server, and it is the tool you use to
manage that server. Everything you can do in the web app's admin pages, and quite a bit more, you can also do
from a terminal with it.

This guide explains how the command works and shows, command by command, how to do everyday jobs with it:
adding people, sharing files, backups, certificates and more. The [Recipes](#recipes) section has complete
worked examples for the most common tasks. The [Command reference](#command-reference) at the end lists every
flag of every command.

Not installed yet? Start with [Installing FileParcel](INSTALL.md), then come back here. Using the web app,
roles, the network, certificates, backups and every setting are explained in the [user manual](FILEPARCEL.md).

## Contents

- [How the command works](#how-the-command-works)
  - [Run it on the server](#run-it-on-the-server)
  - [How a command reaches the server](#how-a-command-reaches-the-server)
  - [Act as another user](#act-as-another-user)
  - [Use the command from another computer](#use-the-command-from-another-computer)
  - [Flags for every command](#flags-for-every-command)
  - [Environment variables](#environment-variables)
  - [Paths, names and values](#paths-names-and-values)
  - [Output: tables, JSON and files](#output-tables-json-and-files)
  - [Exit codes and scripting](#exit-codes-and-scripting)
  - [Getting help](#getting-help)
- [Getting started](#getting-started)
- [Files & sharing](#files--sharing)
- [People & access](#people--access)
- [Server & network](#server--network)
- [Security](#security)
- [Backups & maintenance](#backups--maintenance)
- [Install & service](#install--service)
- [Recipes](#recipes)
  - [Add a user](#add-a-user)
  - [Invite someone with a QR code](#invite-someone-with-a-qr-code)
  - [Create a group and its team folder](#create-a-group-and-its-team-folder)
  - [Create a limited admin role (helpdesk, netops)](#create-a-limited-admin-role-helpdesk-netops)
  - [Let a group or a role see a folder](#let-a-group-or-a-role-see-a-folder)
  - [Upload a folder as a password-protected zip](#upload-a-folder-as-a-password-protected-zip)
  - [Share a file with a link that expires](#share-a-file-with-a-link-that-expires)
  - [Collect files with a file request](#collect-files-with-a-file-request)
  - [Put share links on the internet with Tailscale Funnel](#put-share-links-on-the-internet-with-tailscale-funnel)
  - [Back up now, on a schedule, and restore](#back-up-now-on-a-schedule-and-restore)
  - [Rotate the encryption keys](#rotate-the-encryption-keys)
  - [Renew or replace the HTTPS certificate](#renew-or-replace-the-https-certificate)
  - [Move FileParcel to a new machine](#move-fileparcel-to-a-new-machine)
  - [Find and fix problems with doctor](#find-and-fix-problems-with-doctor)
- [Shell completion](#shell-completion)
- [Renamed commands](#renamed-commands)
- [Command reference](#command-reference)

**About the examples.** Ids such as `shr_01j9zq3x4k6m8p0r2t4v6x8z0b` are placeholders: use the ids your own
list commands print (`fileparcel share list`, `fileparcel backup list`, …). The same goes for names like
`alice`, `Design` or `192.168.1.0/24`, and for addresses like `https://fileparcel.local:8443`: use the ones
`fileparcel status` shows for your server.

**`<HOME>`** stands for the *installation directory*: the one folder that holds everything FileParcel
stores, by default `~/.local/share/fileparcel` (`/opt/fileparcel` for a system installation). It is not your
own home folder. The command help calls it the "home directory".

## How the command works

### Run it on the server

Most of the time you run `fileparcel` on the machine where FileParcel is installed. There it has full admin
rights and needs no password. The installer links the command as `~/.local/bin/fileparcel` (or
`/usr/local/bin/fileparcel` when installed as root), so on most systems you can type it in any folder.

```sh
# Is the server running, and at which addresses?
fileparcel status
```

If you installed FileParcel as a **system service** (with `sudo`), the server runs as its own `fileparcel`
account (`_fileparcel` on macOS). Put `sudo` in front of the commands there:

```sh
sudo fileparcel status
```

### How a command reaches the server

A command tries three ways, in this order:

1. **The admin socket.** While the server runs, commands talk to it through the file `<HOME>/run/admin.sock`.
   Only the same system user (or root) can use it. It has full admin rights: no password, no second factor,
   and changes apply at once.
2. **Offline.** While the server is stopped, commands open the installation directly and do the work
   themselves. `--offline` forces this (and refuses while the server runs). If the master key is sealed with
   a passphrase, you are asked for it, or you pass `--passphrase-stdin` / `--passphrase-file`. `status`,
   `doctor` and `healthcheck` always look at the installation on this machine.
3. **Remote.** From another computer, add `--server` and an API token. See
   [Use the command from another computer](#use-the-command-from-another-computer).

If the server is running but its admin socket does not answer, a command never opens the database behind
the server's back: it stops and suggests `fileparcel doctor`. If the admin socket is turned off
(`admin_socket.enabled = false` in `fileparcel.toml`), it says that instead.

**Which installation?** The one named with `--home DIR`, else the one in `$FILEPARCEL_HOME`, else the
installation the program itself lives in (`<HOME>/bin/fileparcel`, also when you run it through the link).
On a normal install you never need `--home`.

```sh
# Look at another installation on this machine
fileparcel --home /opt/fileparcel status
# Change a setting while the server is stopped
fileparcel --offline config set storage.trash_days 14
```

### Act as another user

On the server, `files`, `share`, `request` and `token` commands work in the **first owner's** files, unless
you name someone else with `--as USER`. `access` commands have full rights over team folders and ids, and
need `--as` only to know whose `/My files` you mean. Every other command acts as the server itself.

Remotely, every command acts as the token's user, with that user's role and access.

```sh
# List alice's own files
fileparcel --as alice files ls
# Show who commands act as and what they may do
fileparcel whoami
```

### Use the command from another computer

Copy the `fileparcel` program to the other computer, then give it the server's address and a personal API
token. The release zip has one program for each system in its `bin/` folder: `fileparcel-linux-amd64`,
`fileparcel-linux-arm64`, `fileparcel-linux-arm` (32-bit Raspberry Pi), `fileparcel-darwin-amd64` (Intel Mac)
and `fileparcel-darwin-arm64` (Apple silicon). Install the right one as `fileparcel`, for example on a 64-bit
ARM Linux computer, in the unpacked zip:

```sh
install -m 755 bin/fileparcel-linux-arm64 ~/.local/bin/fileparcel
```

(`~/.local/bin` must be on your `PATH`; see
[fileparcel: command not found](INSTALL.md#fileparcel-command-not-found). On a Mac, if macOS refuses to open
the program, run `xattr -d com.apple.quarantine ~/.local/bin/fileparcel` once.) Then:

1. On the server, create a token for the account that should act. The secret (`fpt_…`) is printed once:

   ```sh
   fileparcel token create laptop --user alice --expires 90d
   ```

2. On the server, save the certificate authority (CA) the server's HTTPS certificate comes from:

   ```sh
   fileparcel ca export -o fileparcel-ca.pem
   ```

3. On the other computer, put the `fpt_…` line into a file only you can read (for example
   `~/.fileparcel-token`, `chmod 600`), copy `fileparcel-ca.pem` next to it, and run commands with `--server`:

   ```sh
   fileparcel --server https://fileparcel.local:8443 --token-file ~/.fileparcel-token --ca-file fileparcel-ca.pem whoami
   fileparcel --server https://fileparcel.local:8443 --token-file ~/.fileparcel-token --ca-file fileparcel-ca.pem files ls
   ```

Good to know:

- **Keep the token out of the command line.** `--token fpt_…` works, but other users of the computer can see
  it in the process list. Use `--token-file`, or put it in the environment variable `FILEPARCEL_TOKEN`.
- **Check the certificate.** With a certificate from FileParcel's own CA, pass `--ca-file` (the CA file) or
  `--fingerprint` (the fingerprint `fileparcel ca fingerprint` prints; the server certificate's own
  fingerprint works too). With both, the pinned certificate must be part of the chain the CA file checks.
  The address must start with `https://`; plain `http://` is only accepted for a loopback address such as
  the end of an SSH tunnel.
- **Scopes.** A new token may read and write files and create links (`files:read`, `files:write`,
  `shares`). Admin commands need a token with the `admin` scope and an account whose role allows the action.
- **Sensitive admin actions** (keys, roles, the network policy, backups and similar) also need an
  **elevated** token, which may last at most 30 days. This one is for the first owner (add `--user NAME` for
  another administrator): `fileparcel token create ops --scopes admin --elevated --expires 7d`. On the server
  itself none of this is needed. A token stops being elevated when its account's role gains a server
  permission or the account gets another role (it keeps working otherwise): make a new one after confirming
  your identity in the web app again.
- **What a token may do.** `fileparcel whoami` shows it, and a refused command says which of the three is
  missing: the scope, the role's permission or the elevation.
- **Two-factor sign-in.** The token's account must meet the two-factor rule (`auth.require_2fa`; by default
  it covers owners, admins and everyone whose role has a server permission). Such an account sets up an
  authenticator app or a passkey in the web app first; until then every remote command is refused with
  `mfa_enroll_required`.

### Flags for every command

These work with every command, before or after it (`fileparcel --json user list` and
`fileparcel user list --json` are the same).

| Flag | What it does |
|---|---|
| `--home DIR` | Use the installation in DIR (default: `$FILEPARCEL_HOME`, else the one the program lives in). |
| `--json` | Print JSON instead of tables (errors too). |
| `-y`, `--yes` | Answer yes to every question; never prompt. |
| `--no-color` | No colours (also `NO_COLOR=1` or `TERM=dumb`). |
| `--offline` | Work on the data directly; the server must be stopped. |
| `--as USER` | Act as USER (on the server only). |
| `--server URL` | Talk to a server on another machine (`https://host:port`, needs a token). |
| `--token TOKEN` | API token for `--server`. Prefer `$FILEPARCEL_TOKEN` or `--token-file`. |
| `--token-file FILE` | API token for `--server`, from the first line of FILE. |
| `--ca-file FILE` | Trust this CA certificate (PEM) for `--server`. |
| `--fingerprint SHA256` | Pin the server's certificate chain by its SHA-256 fingerprint (for `--server`). |
| `--passphrase-stdin` | Master-key passphrase from the first line of standard input (offline, sealed key). |
| `--passphrase-file FILE` | Master-key passphrase from the first line of FILE (offline, sealed key). |

A few commands have a `--passphrase-stdin` or `--passphrase-file` flag of their own (`init`, `install`,
`serve`, `backup restore`, `backup config set` and the `keys` commands); there the flag keeps that command's
meaning, which its `--help` explains.

### Environment variables

| Variable | What it does |
|---|---|
| `FILEPARCEL_HOME` | The installation directory (like `--home`). |
| `FILEPARCEL_TOKEN` | The API token for `--server`. |
| `FILEPARCEL_<SECTION>_<KEY>` | Overrides a value of `fileparcel.toml`, for example `FILEPARCEL_SERVER_HTTPS_PORT=9443`. |
| `NO_COLOR`, `TERM=dumb` | No colours. |
| `VISUAL`, `EDITOR` | The editor `fileparcel config edit` opens. |

The server reads a few more (for Docker, for supervisors such as runit and for Tailscale): see
[Environment variables](FILEPARCEL.md#environment-variables) in the user manual.

### Paths, names and values

**File and folder paths** (`fileparcel help paths`):

| Path | Means |
|---|---|
| `/My files/…` | Your own files. `/My files` is the default, so `Documents/a.pdf` means `/My files/Documents/a.pdf`. |
| `/Team/<group>/…` | The team folder of a group you belong to, or one shared with you as a whole. |
| `nod_…` | Any file or folder by its id, optionally followed by a path below it (`nod_…/sub/file.txt`). |
| `/` | The top level: your spaces. |

Put quotes around paths with spaces: `"/My files/Tax 2026"`.

**The same words everywhere.** `list` (also `ls`), `show`, `create`, `edit`, `delete` (also `rm`; it is
permanent), `add` and `remove` (entries of a list), `enable` and `disable`, `revoke` (credentials or access
someone else holds) and `status` mean the same in every command. Only `files` keeps the Unix names `ls`,
`mkdir`, `mv`, `cp` and `rm`, and there `rm` moves to the trash.

**Names and ids.** Users, groups and roles go by name or by id (`usr_…`, `grp_…`, `rol_…`). Everything else
goes by id: `shr_` (share links and file requests), `bak_` (backups), `job_`, `tok_` (API tokens), `inv_`
(invitations), `ccr_` (device certificates), `gnt_` (access grants), `nod_` (files and folders) and `ver_`
(file versions). The list commands and `--json` show them.

**Values** (`fileparcel help values`):

- Durations: `30m`, `12h`, `7d`, `2w`, `1d12h`.
- `--expires` takes a duration (`7d`), a date (`2026-12-31`, valid until the end of that day) or `never`
  where things may last forever (links, tokens, access grants).
- Sizes: `500M`, `10G`, `1.5T` (`10GB` and `10GiB` mean the same). Quotas also take `unlimited`.
- Lists: repeat the flag (`--group Design --group Marketing`). Flags whose help says "comma-separated" also
  take `a,b,c`.
- On/off: `--upload` turns an option on; `--no-upload` or `--upload=false` turns it off.
- Secrets never go on the command line: `--password` asks without showing what you type,
  `--password-stdin` reads the first line of standard input, `--password-file FILE` the first line of a file.

### Output: tables, JSON and files

- Tables and results go to **standard output**; questions, warnings, progress bars and notes go to
  **standard error**. So you can pipe the result and still see what is going on.
- `--json` prints one JSON document instead (one JSON object per line with `--follow`/`-f`). List commands
  print arrays, never `null`; `role permissions` and `cert sans list` print an object with named lists
  instead. Errors are then also JSON, on standard error:
  `{"error":{"code":…,"message":…,"hint":…}}`. The `code` is the server's for a refused request and `usage`
  for a wrong command line.
- In JSON, a `path` is always the full path (`/My files/photos/notes.txt`, `/Team/Design/notes.txt`), the
  same form `files info` prints and every command accepts back, `files search` and `files trash` included.
- Commands that write a file take `-o FILE` / `--output FILE`: `files get`, `backup create`, `audit export`,
  `ca export` and `client-cert issue`. They never replace an existing file unless you add `-f` / `--force`.
  For `files get`, `backup create` and `ca export`, `-o -` writes to standard output.

```sh
# Just the usernames, one per line (needs jq)
fileparcel --json user list | jq -r '.[].username'
# Save the last 30 days of the audit log as JSON lines
fileparcel audit export --format jsonl -o audit.jsonl --since 30d
# Show a text file without saving it
fileparcel files get "/My files/notes.txt" -
```

### Exit codes and scripting

| Exit status | Meaning |
|---|---|
| `0` | Success. |
| `1` | Something failed (also "aborted", and a question asked without a terminal). |
| `2` | Wrong usage or invalid input (a typo in a command or flag, a missing argument). |
| `75` | The server asks its service manager for a restart (only `fileparcel serve`). |

Checks exit with status 1 when a check fails: `doctor` (warnings alone do not count), `healthcheck`,
`db check`, `keys verify`, `audit verify`, `backup verify` and `jobs show --wait`. `backup create --wait`
also exits with status 1 when the archive is ready but part of the work failed — in practice the copy to
`backup.copy_to`. The backup id and the reason go to standard error, so a cron job does not take a failed
off-site copy for a clean run.

For scripts and cron jobs:

- Add `-y` so nothing waits for an answer. Without `-y` and without a terminal, a question is an error
  (exit 1) instead of a hang. The exceptions are `install` and `upgrade` (and `./install.sh`): without a
  terminal they go ahead without asking, as with `-y`.
- Commands that start a background job take `--wait` or `--no-wait`; each command's `--help` says which is
  its default (`backup create` returns at once, `backup verify` and `keys rotate` wait).
- Pass secrets with the `--…-stdin` or `--…-file` flags. Only one flag of a command can read standard input.

```sh
# Create an account with a password from a variable
printf '%s\n' "$PASS" | fileparcel user create bob --password-stdin
# Back up and wait for the result (a cron job gets exit status 1 when it fails)
fileparcel -y backup create --wait --json
# React when the server does not answer
fileparcel healthcheck || echo "FileParcel is not answering"
```

**The REST API.** Everything the web app does goes through the REST API under `/api/v1` (JSON; lists are
paged with `?cursor=&limit=`). A script can use it directly with a personal API token:

```sh
# The token's own account, as the API sees it
curl --cacert fileparcel-ca.pem -H "Authorization: Bearer $FILEPARCEL_TOKEN" https://fileparcel.local:8443/api/v1/me
```

### Getting help

```sh
# All commands, grouped, with common tasks
fileparcel --help
# One command: what it does, its flags and examples
fileparcel user create --help
# The same, the other way round
fileparcel help user create
# A topic that many commands share
fileparcel help paths
```

The help topics are `connect` (how commands reach the server), `flags` (global flags and environment
variables), `paths` (file and folder paths), `permissions` (roles, groups and folder access), `renamed` (old
command names), `scripting` (JSON output, exit codes, non-interactive use) and `values` (durations, dates,
sizes, lists and secrets).

A mistyped command gets a suggestion, and so do common words for a task: `fileparcel user lsit` suggests
`fileparcel user list`, and `fileparcel upload` suggests `fileparcel files put`.

## Getting started

### doctor — find and fix problems

Checks the installation: configuration, file permissions, the program, the running server, the service,
certificates, ports and the firewall. While the server runs, its own checks (keys, backups, disk, database,
jobs, …) are included. `--fix` applies the safe repairs: file and folder permissions, ownership (as root),
leftovers of a crashed server, and linger for a start-at-boot user service.

```sh
# Check everything
fileparcel doctor
# Check and apply the safe fixes
fileparcel doctor --fix
# The results as JSON, for monitoring
fileparcel doctor --json
```

### help — help about a command or topic

```sh
# Help about one command
fileparcel help share create
# How roles, groups and folder access add up
fileparcel help permissions
```

### open — open the web app

Opens the recommended address in your browser. Without a graphical session, or with `--qr` or `--no-browser`,
it prints the addresses instead; `--qr` adds a QR code of each recommended address for phones
(`fileparcel network urls --qr` shows one for every address).

```sh
# Open the web app in your browser
fileparcel open
# The addresses, with a QR code of the recommended ones to scan with a phone
fileparcel open --qr
# Only print the addresses
fileparcel open --no-browser
```

### status — is the server running, and where?

Shows the version, uptime, keys, certificates, addresses and storage of a running server. When the server is
stopped, it shows the state of the installation instead, without starting anything.

```sh
fileparcel status
# As JSON, for scripts
fileparcel status --json
```

## Files & sharing

### files — upload, download and organize files

Works with the files stored in FileParcel. Uploads are sent in verified parts, several at a time, and
retried on network errors; downloads resume where they stopped and are verified. See
[Paths, names and values](#paths-names-and-values) for how to write paths.

On the server these commands work as the first owner (or as the user you name with `--as`, see
[Act as another user](#act-as-another-user)). `/Team/<group>` paths work for the groups that user belongs to;
the examples below assume the first owner is a member of the Design group.

| Command | What it does |
|---|---|
| `files ls [path]` | List a folder (default `/My files`). |
| `files tree [path]` | Show a folder and everything in it as a tree. |
| `files info <path>` | Show the details of a file or folder: id, size, hash, times. |
| `files search <text>` | Find files and folders by name. |
| `files versions <path>` | List the older versions of a file, or restore one. |
| `files put <local>… <folder>` | Upload files and folders (optionally as one `.zip`, with a password). |
| `files get <path> [local]` | Download a file, or a folder as a `.zip` or `.tar` file. |
| `files mkdir <path>…` | Create folders. |
| `files mv <src>… <dest>` | Move or rename. |
| `files cp <src>… <dest>` | Copy (instant: the contents are shared, not duplicated). |
| `files rm <path>…` | Move to the trash (`--purge`: delete for good). |
| `files trash` | List the trash, or empty it with `--empty`. |
| `files restore <path>…` | Bring items back from the trash. |

```sh
# List your own files
fileparcel files ls
# List a folder with more columns, biggest files first
fileparcel files ls "/My files/Documents" -l --sort size --desc
# Everything below a folder, two levels deep
fileparcel files tree "/My files" --depth 2
# Details of one file
fileparcel files info "/My files/Documents/report.pdf"
# Find files by name, everywhere you have access
fileparcel files search report
# Only PDF files in one team folder
fileparcel files search .pdf --in /Team/Design --kind file
# The versions of a file
fileparcel files versions "/My files/Documents/report.pdf"
# Make an older version the current one again
fileparcel files versions "/My files/Documents/report.pdf" --restore ver_01j9zq3x4k6m8p0r2t4v6x8z0b
# Upload a file into a folder
fileparcel files put report.pdf "/My files/Documents"
# Upload a whole folder; -p creates the target folder when it is missing
fileparcel files put ./photos "/My files/Pictures" -p
# Upload a newer copy as a new version of the existing file
fileparcel files put report.pdf "/My files/Documents" --conflict replace
# Download a file into the current folder
fileparcel files get "/My files/Documents/report.pdf"
# Download a folder as one zip file
fileparcel files get "/My files/Pictures" -o pictures.zip
# Download an older version of a file
fileparcel files get "/My files/Documents/report.pdf" --version ver_01j9zq3x4k6m8p0r2t4v6x8z0b -o report-old.pdf
# Create a folder and any missing folders above it
fileparcel files mkdir -p "/My files/Projects/2026/Drafts"
# Rename a file
fileparcel files mv "/My files/Documents/report.pdf" "/My files/Documents/report-final.pdf"
# Move a file into another folder
fileparcel files mv "/My files/Documents/report-final.pdf" "/My files/Projects"
# Copy a file into a team folder
fileparcel files cp "/My files/Projects/report-final.pdf" /Team/Design
# Move a folder to the trash
fileparcel files rm "/My files/Projects/2026/Drafts"
# See what is in the trash
fileparcel files trash
# Bring the folder back
fileparcel files restore "/My files/Projects/2026/Drafts"
# Empty the trash for good (-y: do not ask)
fileparcel files trash --empty -y
```

`--conflict` decides what happens when a name already exists: `rename` (the default for `put` and `cp`:
`name (1).ext`), `replace` (for files: adds a new version), `skip` or `fail` (the default for `mv`).

### request — collect files with an upload link

A file request is a public link through which anyone can upload files into one of your folders, without
seeing what is already in it. Uploads count against your storage quota.

| Command | What it does |
|---|---|
| `request create <folder>` | Create an upload link into a folder. |
| `request list` | List your file requests (`--all-users`: everyone's, for admins). |
| `request show <id>` | Show a request, its counters and its link (`--qr` for phones). |
| `request log <id>` | Show who opened it and what was uploaded. |
| `request close <id>` | Stop accepting uploads for now. |
| `request reopen <id>` | Accept uploads again. |
| `request delete <id>` | Delete the request for good (the uploaded files stay). |

```sh
# An upload link into a folder, with a QR code for phones
fileparcel request create "/My files/Incoming" --title "Send me your photos" --qr
# Limit each file to 2 GB and the total to 20 GB, ask for the uploader's name
fileparcel request create "/My files/Incoming" --max-size 2G --quota 20G --require-name --expires 30d
# Your file requests
fileparcel request list
# One request with its link
fileparcel request show shr_01j9zq3x4k6m8p0r2t4v6x8z0b
# Who uploaded what, and when
fileparcel request log shr_01j9zq3x4k6m8p0r2t4v6x8z0b
# Stop uploads for now, and later accept them again
fileparcel request close shr_01j9zq3x4k6m8p0r2t4v6x8z0b
fileparcel request reopen shr_01j9zq3x4k6m8p0r2t4v6x8z0b
# Delete it for good
fileparcel request delete shr_01j9zq3x4k6m8p0r2t4v6x8z0b
```

### share — share files and folders with a link

A share link lets anyone who has it open a file or folder, without an account. Protect it with a password,
let it expire or limit the number of downloads. To give specific people or groups access instead, use
[`access`](#access--give-users-groups-or-roles-access-to-folders).

| Command | What it does |
|---|---|
| `share create <path>` | Create a link to a file or folder. |
| `share list` | List your links (`--inactive`: also expired and disabled ones; `--all-users`: everyone's). |
| `share show <id>` | Show a link with its settings and counters (`--qr` for phones). |
| `share edit <id>` | Change a link's settings. |
| `share disable <id>` | Turn a link off without deleting it. |
| `share enable <id>` | Turn a disabled link back on. |
| `share log <id>` | Show who opened or downloaded through a link. |
| `share delete <id>` | Delete a link for good (the files stay). |

```sh
# A link that expires in 3 days, with a QR code
fileparcel share create "/My files/Slides.pdf" --expires 3d --qr
# A folder link with a password (asked twice) that allows 10 downloads
fileparcel share create "/My files/Pictures" --password --max-downloads 10
# Let visitors watch, but not download
fileparcel share create "/My files/Video.mp4" --no-download --title "Preview only"
# Your links
fileparcel share list
# Every user's links (admins)
fileparcel share list --all-users
# One link with a QR code
fileparcel share show shr_01j9zq3x4k6m8p0r2t4v6x8z0b --qr
# Make a link valid for 30 days from now, and remove its download limit
fileparcel share edit shr_01j9zq3x4k6m8p0r2t4v6x8z0b --expires 30d --max-downloads none
# Turn a link off, and on again
fileparcel share disable shr_01j9zq3x4k6m8p0r2t4v6x8z0b
fileparcel share enable shr_01j9zq3x4k6m8p0r2t4v6x8z0b
# Who used the link
fileparcel share log shr_01j9zq3x4k6m8p0r2t4v6x8z0b
# Delete it for good
fileparcel share delete shr_01j9zq3x4k6m8p0r2t4v6x8z0b
```

Without `--expires`, a new link gets the server's default expiry (setting `sharing.default_expiry_days`).

## People & access

What someone may do is decided in three layers (`fileparcel help permissions`):

1. Their **role** decides what they may do on the server. Built-in roles: `owner`, `admin`, `member` (the
   default) and `guest` (no files of their own). You can create your own roles.
2. Their **groups** give them the team folders `/Team/<group>`.
3. **Access grants** give a user, a group or everyone with a role access to one folder or file: `view` (see
   and download), `edit` (also change, move and delete) or `manage` (also share it and change its access).

Access only adds up: nothing takes away what another layer gives.

### access — give users, groups or roles access to folders

| Command | What it does |
|---|---|
| `access grant <path>` | Give users (`--user`), groups (`--group`) or roles (`--role`) access. |
| `access list <path>` | Show who has access and why (also grants on the folders above). |
| `access check <user> <path>` | Explain what one user may do with a file or folder, and why. |
| `access revoke <path> [gnt_…]` | Take access back. |

```sh
# Let the Marketing group see the Design team folder
fileparcel access grant /Team/Design --group Marketing
# Let bob edit a folder in alice's own files for 30 days
fileparcel --as alice access grant "/My files/Taxes" --user bob --level edit --expires 30d
# Let everyone with the auditors role see the Finance team folder
fileparcel access grant /Team/Finance --role auditors
# Who has access to a folder, and why
fileparcel access list /Team/Design
# Why can (or can't) bob open this folder?
fileparcel access check bob /Team/Design
# Take the access back
fileparcel access revoke /Team/Design --group Marketing
```

Granting again changes the level; the expiry stays unless you pass `--expires` again. `access check` asks
the server as that user, so run it on the server.

### group — groups and their team folders

A group bundles users. Every group has a team folder, `/Team/<group>`, that all its members can open.
Group managers may also share the team folder and change who has access to it.

| Command | What it does |
|---|---|
| `group create <name>` | Create a group and its team folder. |
| `group list` | List groups. |
| `group show <group>` | Show a group, its team folder and its members. |
| `group members <group>` | List the members and how they became members. |
| `group add-member <group> <user>…` | Add people (`--manager`: as managers). |
| `group remove-member <group> <user>…` | Remove people (files they made in the team folder stay). |
| `group edit <group>` | Change the name or description. |
| `group rename <group> <new-name>` | Rename a group; its team folder follows. |
| `group delete <group>` | Delete a group **and its team folder with all files**. |

```sh
# A group and its team folder /Team/Design
fileparcel group create Design --description "Design team"
# All groups, one group, and its members
fileparcel group list
fileparcel group show Design
fileparcel group members Design
# Add two people, and make one of them a manager
fileparcel group add-member Design alice bob
fileparcel group add-member Design alice --manager
# Take someone out of the group
fileparcel group remove-member Design bob
# A new description, then a new name (the team folder is renamed too)
fileparcel group edit Design --description "Product design team"
fileparcel group rename Design "Product Design"
# Asks first; the team folder and its files go too
fileparcel group delete "Product Design"
```

### invite — let people create their own account

An invitation link lets someone create their own account: they choose the username and password, you choose
the role, groups and quota beforehand. Links expire after 7 days unless you say otherwise.

| Command | What it does |
|---|---|
| `invite create` | Create an invitation link (`--qr` for phones, `--send` to e-mail it). |
| `invite list` | List active invitations with their links (`--inactive`: also used and expired ones). |
| `invite revoke <id>` | Stop an invitation from working. |

```sh
# A one-time link for a new member of the Design group, with a QR code
fileparcel invite create --group Design --expires 3d --qr
# A link ten people can use, each with 5 GB of storage
fileparcel invite create --uses 10 --expires 14d --quota 5G --note "Welcome to the workshop"
# E-mail the link (needs e-mail set up: FILEPARCEL.md, "Send e-mail")
fileparcel invite create --email bob@example.com --send
# The invitations that still work, with their links
fileparcel invite list
# Stop one from working
fileparcel invite revoke inv_01j9zq3x4k6m8p0r2t4v6x8z0b
```

`--note` is shown on the sign-up page to anyone who opens the link, so keep private remarks out of it.

### role — roles and what they may do

A role decides what its users may do on the server. There are four built-in roles (`owner`, `admin`,
`member`, `guest`), and you can create your own: start from a copy of another role, then add or remove
permissions. Every user has exactly one role. Which folders people can open is not part of a role's
permissions; that comes from groups and access grants, which a role can also be given.

| Command | What it does |
|---|---|
| `role list` | List roles and how many people have each. |
| `role show <role>` | Show a role: permissions, people, groups and folders. |
| `role permissions` | List every permission a role can have, with warnings for the powerful ones. |
| `role create <name>` | Create a custom role. |
| `role edit <role>` | Change a custom role's name, description or permissions. |
| `role members <role>` | List the people who have a role. |
| `role add-group <role> <group>` | Make everyone with the role a member of a group. |
| `role remove-group <role> <group>` | Stop that again. |
| `role delete <role>` | Delete a custom role; its people move to the role you name. |

```sh
# All roles, and how many people have each
fileparcel role list
# Every permission, with what it allows
fileparcel role permissions
# What one role may do
fileparcel role show admin
# Members who may not create share links
fileparcel role create contractors --from member --remove shares.links
# Give the permission back later
fileparcel role edit contractors --add shares.links
# Who has the role
fileparcel role members contractors
# Everyone with the role becomes a member of the Design group, and stops being one
fileparcel role add-group contractors Design
fileparcel role remove-group contractors Design
# People with the role get the member role instead (asks first)
fileparcel role delete contractors --reassign-to member
```

`--base guest` makes a role for people without files of their own; it cannot be changed later. Without
`--base`, a new role gets the base of `--from` (member when `--from` is owner or admin, or not given), so
`--from guest` also makes a guest-based role. See the recipe
[Create a limited admin role](#create-a-limited-admin-role-helpdesk-netops).

### token — API tokens for scripts and remote use

A personal API token (`fpt_…`) lets a script, or `fileparcel` on another computer, act as a user. On the
server, tokens belong to `--user` (or `--as`), else to the first owner.

| Command | What it does |
|---|---|
| `token create <name>` | Create a token; the secret is shown once. |
| `token list` | List tokens (`--inactive`: also revoked and expired ones). |
| `token revoke <id>` | Revoke a token right away. |

```sh
# A token for alice's laptop, valid 90 days
fileparcel token create laptop --user alice --expires 90d
# A read-only token for a backup script
fileparcel token create backup-script --scopes files:read --expires 90d
# An elevated admin token for the first owner, for a week of remote administration
fileparcel token create ops --scopes admin --elevated --expires 7d
# alice's tokens, and revoking one of them
fileparcel token list --user alice
fileparcel token revoke tok_01j9zq3x4k6m8p0r2t4v6x8z0b --user alice
```

Scopes: `files:read`, `files:write`, `shares` (the three together are the default) and `admin`.

### user — user accounts

Every account signs in to the web app and has its own files (`/My files`; guests have none).

| Command | What it does |
|---|---|
| `user create <user>` | Create an account. |
| `user list` | List accounts with role, status, two-factor state and quota. |
| `user show <user>` | Show everything about one account. |
| `user edit <user>` | Change name, e-mail, role, quota or the password-change rule. |
| `user disable <user>` | Stop someone from signing in (their files stay). |
| `user enable <user>` | Let them sign in again. |
| `user delete <user>` | Delete an account and its files (or `--transfer-to` someone else). |
| `user set-role <user> <role>` | Change someone's role. |
| `user set-quota <user> <size>` | Set how much storage someone may use. |
| `user reset-password <user>` | Set a new password. |
| `user reset-2fa <user>` | Remove someone's second factors (lost phone or key). |
| `user unlock <user>` | Clear the lockout after too many failed sign-ins. |
| `user sessions <user>` | List where someone is signed in. |
| `user revoke-sessions <user>` | Sign someone out everywhere. |

```sh
# A new account with a generated password (shown once, changed at the first sign-in)
fileparcel user create bob --email bob@example.com --generate-password
# A guest: no files of their own, only what is shared with them
fileparcel user create visitor --role guest --generate-password
# All accounts, and only the admins
fileparcel user list
fileparcel user list --role admin
# Everything about one account
fileparcel user show bob
# A new display name and e-mail address
fileparcel user edit bob --display-name "Bob Builder" --email bob@example.org
# Keep bob out for a while, then let him back in
fileparcel user disable bob
fileparcel user enable bob
# Make bob an admin, and give him 50 GB of storage
fileparcel user set-role bob admin
fileparcel user set-quota bob 50G
# A new password: typed twice, or generated and shown once
fileparcel user reset-password bob
fileparcel user reset-password bob --generate-password
# After a lost phone: remove the authenticator app and passkeys (asks first)
fileparcel user reset-2fa bob
# After too many wrong passwords: let bob try again now
fileparcel user unlock bob
# Where bob is signed in, and signing him out everywhere
fileparcel user sessions bob
fileparcel user revoke-sessions bob
# Delete bob, but give his files to alice (-y: do not ask)
fileparcel user delete bob --transfer-to alice -y
```

### whoami — who commands act as

Shows the account commands act as, its role and permissions, its groups and, remotely, the token in use.

```sh
# On the server: the admin socket's full rights
fileparcel whoami
# What alice may do
fileparcel --as alice whoami
```

## Server & network

### config — settings

Reads and changes FileParcel's settings. A running server applies most changes at once and says when one
needs a restart. Secret settings (like `smtp.password`) are read from standard input or asked for, never
taken from the command line.

| Command | What it does |
|---|---|
| `config list` | List the settings you changed (`--all`: every setting). |
| `config get <key>` | Show one setting (`--json`: with its type, default and description). |
| `config set <key> [value]` | Change a setting. |
| `config unset <key>` | Put a setting back to its default. |
| `config edit` | Edit `fileparcel.toml` in your editor (checked before it is saved). |
| `config path` | Print where `fileparcel.toml` is. |
| `config test-email --to <address>` | Send a test e-mail with the saved SMTP settings. |

```sh
# The settings you changed
fileparcel config list
# Every storage setting with its default
fileparcel config list --all --section storage
# Read one setting, change it, and put it back to its default
fileparcel config get storage.trash_days
fileparcel config set storage.trash_days 14
fileparcel config unset storage.trash_days
# The name shown in the web app
fileparcel config set ui.instance_name "Family Files"
# A secret setting reads its value from standard input
printf '%s' "$SMTP_PASSWORD" | fileparcel config set smtp.password
# Where fileparcel.toml is, and editing it (restart the server afterwards)
fileparcel config path
fileparcel config edit
# Check the e-mail settings
fileparcel config test-email --to admin@example.org
```

Some settings are managed by their own command and refused here: for example, Tailscale Funnel by
`fileparcel network funnel`.

### logs — the server log

Prints the last lines of `<HOME>/logs/fileparcel.log`; `-f` keeps following it.

```sh
# The last 200 lines
fileparcel logs
# The last 50 lines, then keep watching (Ctrl-C stops)
fileparcel logs -n 50 -f
```

If file logging is turned off (`log.file = false`), read the service manager's log instead:
`journalctl --user -u fileparcel` for a user service.

### network — addresses and who may connect

Shows how the server can be reached and controls who may connect. The access policy has three modes:
`private` (this machine, home networks and VPNs), `allowlist` (this machine plus the networks you allow; the
default) and `any` (every address; only behind a firewall, with two-factor sign-in for everyone). The deny
list always wins, and this machine itself is always allowed. A change that would lock out your own
connection is refused unless you add `--force`.

| Command | What it does |
|---|---|
| `network` or `network status` | Addresses, policy, VPNs, Funnel and Serve at a glance. |
| `network urls` | The addresses the server can be reached at (`--qr` for phones). |
| `network interfaces` | This machine's network interfaces and how FileParcel uses them. |
| `network policy` | The access mode, the allow and deny lists and your own address. |
| `network mode <private\|allowlist\|any>` | Choose who may connect. |
| `network allow add\|list\|remove` | The networks allowed to connect. |
| `network deny add\|list\|remove` | The networks that may never connect. |
| `network vpn list\|allow\|remove\|role` | The VPNs on this machine and whether their devices may connect. |
| `network funnel status\|enable\|disable\|reapply` | Put share links (or the whole app) on the internet with Tailscale Funnel. |
| `network tailscale-serve status\|enable\|disable\|reapply` | A tailnet address without a port number (Tailscale Serve). |
| `network mdns status\|enable\|disable\|mode\|name\|republish` | The `.local` name on your home network. |

```sh
# Everything at a glance
fileparcel network
# The same overview as JSON, for scripts
fileparcel network status --json
# The addresses, with QR codes for phones
fileparcel network urls --qr
# This machine's network interfaces, and what FileParcel uses them for
fileparcel network interfaces
# Who may connect now
fileparcel network policy
# Only this machine and the allowed networks may connect (the default)
fileparcel network mode allowlist
# Allow your home network and one more address, list them, take one out again
fileparcel network allow add 192.168.1.0/24 10.8.0.5
fileparcel network allow list
fileparcel network allow remove 10.8.0.5
# Block one device, list the blocked ones, unblock it
fileparcel network deny add 192.168.1.66
fileparcel network deny list
fileparcel network deny remove 192.168.1.66
# The VPNs found on this machine, and whether their devices may connect
fileparcel network vpn list
# Let the devices on your tailnet connect, or stop that again
fileparcel network vpn allow tailscale
fileparcel network vpn remove tailscale
# Treat the interface wg0 as a VPN whose devices may connect (auto undoes it)
fileparcel network vpn role wg0 mesh
# Tailscale Funnel: what is needed, turn it on (asks first)
fileparcel network funnel status
fileparcel network funnel enable
# Write FileParcel's entries to Tailscale again after they were changed there
fileparcel network funnel reapply
# Take everything off the internet again
fileparcel network funnel disable
# Tailscale Serve: https://<machine>.<tailnet>.ts.net/ for the devices on your tailnet
fileparcel network tailscale-serve status
fileparcel network tailscale-serve enable
fileparcel network tailscale-serve reapply
fileparcel network tailscale-serve disable
# How the .local name is published
fileparcel network mdns status
# files.local instead of fileparcel.local
fileparcel network mdns name files
# Let FileParcel pick how to publish the name (Avahi, dns-sd or its own)
fileparcel network mdns mode auto
# Stop publishing the name, and start again
fileparcel network mdns disable
fileparcel network mdns enable
# Announce the name again, for example after a network change
fileparcel network mdns republish
```

The `.local` name only works on your home network, not through VPNs such as Tailscale or WireGuard. Tailscale
Funnel needs Tailscale signed in to tailscale.com (Headscale has no Funnel); `network funnel status` checks
everything it needs and says how to fix what is missing. See the recipe
[Put share links on the internet with Tailscale Funnel](#put-share-links-on-the-internet-with-tailscale-funnel).

## Security

### audit — the audit log

The audit log records who did what: sign-ins, changes to users and links, downloads, settings, keys and more.
Every entry is chained to the one before it, so `audit verify` notices entries that were changed or deleted.

| Command | What it does |
|---|---|
| `audit list` | Show entries, newest last (`--follow`: keep printing new ones). |
| `audit verify` | Check that nothing was changed or deleted (exit status 1 if so). |
| `audit export` | Save the log as CSV (the default) or JSON lines. |

```sh
# Failed actions in the last week
fileparcel audit list --since 7d --outcome failure
# What alice did with links, the last 20 entries
fileparcel audit list --user alice --action share. --limit 20
# Check that no entry was changed or deleted
fileparcel audit verify
# The last 30 days as a spreadsheet file
fileparcel audit export -o audit.csv --since 30d
```

### ca — the local certificate authority

FileParcel creates its own certificate authority (CA) and issues the server's HTTPS certificate from it.
Devices trust the server after installing the CA certificate once. By default the CA may only sign local
names and private addresses, so it cannot be misused to impersonate public web sites.

| Command | What it does |
|---|---|
| `ca show` | Show the CA: validity, fingerprint and the names it may sign (`--pem`: the certificate). |
| `ca fingerprint` | Print the CA's SHA-256 fingerprint. |
| `ca export` | Save the CA certificate for phones and computers (PEM, DER or `.mobileconfig`). |
| `ca trust-help` | Step-by-step instructions to trust the CA on each kind of device. |
| `ca regenerate` | Replace the CA; **every device must trust the new one**. |

```sh
# The CA's details, and just its fingerprint (compare it on your devices)
fileparcel ca show
fileparcel ca fingerprint
# For Linux (PEM)
fileparcel ca export -o fileparcel-ca.pem
# For Windows, Mac, Android and Firefox (DER)
fileparcel ca export --format der -o fileparcel-ca.crt
# For iPhone and iPad (a Mac can use it too)
fileparcel ca export --format mobileconfig -o fileparcel.mobileconfig
# How to trust it on an Android phone
fileparcel ca trust-help --os android
# A new CA (asks first; every device must trust the new one)
fileparcel ca regenerate
```

Devices on your network can also download the CA from `https://<server>/trust`.

### cert — HTTPS certificates

By default the server uses a certificate from its own CA. It can also use a Tailscale certificate for its
`ts.net` name, one from Let's Encrypt (or another ACME CA), or one you upload. `cert status` shows which one
is used for which name.

| Command | What it does |
|---|---|
| `cert status` | Show the certificates in use. |
| `cert renew` | Reissue the certificate from the local CA (also happens automatically). |
| `cert sans list\|add\|remove` | Show or change the extra names and addresses in the certificate. |
| `cert tailscale enable\|fetch\|disable` | Use a Tailscale (`ts.net`) certificate every browser trusts. |
| `cert acme enable\|disable` | Get certificates from Let's Encrypt or another ACME CA. |
| `cert upload --cert FILE --key FILE` | Use your own certificate. |
| `cert clear-custom` | Stop using the uploaded certificate. |

```sh
# Which certificates are in use
fileparcel cert status
# Reissue now, even if the current certificate is still fine
fileparcel cert renew --force
# Add a VPN address and another .local name, list the names, remove one
fileparcel cert sans add 10.8.0.1 nas.local
fileparcel cert sans list
fileparcel cert sans remove nas.local
# Tailscale certificate (needs HTTPS turned on for the tailnet and "sudo tailscale set --operator=$USER")
fileparcel cert tailscale enable
# Fetch it again now (it renews by itself), or stop using it
fileparcel cert tailscale fetch
fileparcel cert tailscale disable
# Let's Encrypt with the DNS challenge; cloudflare.json holds {"api_token":"…"} (chmod 600 it)
fileparcel cert acme enable --email me@example.com --domain files.example.com --credentials-file cloudflare.json --production
# Stop using Let's Encrypt
fileparcel cert acme disable
# Your own certificate chain and key (PEM), and back to the local CA's
fileparcel cert upload --cert fullchain.pem --key privkey.pem
fileparcel cert clear-custom
```

After `cert sans add` or `remove`, the server reissues its certificate a few seconds later. The local CA may
only sign `.local` and `.ts.net` names, this machine's own name and private addresses. Another DNS name (say
`files.home.arpa`) is stored by `cert sans add`, but it only gets into the certificate after you rebuild the
CA with `fileparcel ca regenerate`.

Without `--production`, `cert acme enable` uses the Let's Encrypt test CA (staging), whose certificates
browsers do not trust: try it there first. The DNS challenge (the default) works for servers that are not
reachable from the internet. Its provider is Cloudflare (the default) or `--dns-provider rfc2136`; see
`fileparcel cert acme enable --help` for the JSON each one needs.

### client-cert — device certificates

Device certificates (mutual TLS) let only enrolled phones and computers connect when the setting `mtls.mode`
is `optional` or `required`. They are saved as password-protected `.p12` files.

| Command | What it does |
|---|---|
| `client-cert issue <user>` | Issue a device certificate (`.p12`) for a user. |
| `client-cert list` | List device certificates (`--inactive`: also revoked and expired ones). |
| `client-cert revoke <id\|serial>` | Revoke one, for example when a device is lost. |

```sh
# The .p12 password is generated and printed once
fileparcel client-cert issue alice --name "Alice's phone" -o alice-phone.p12
# Valid for 90 days, with the older encryption old Android and macOS versions need
fileparcel client-cert issue alice --name "Old tablet" --expires 90d --legacy -o alice-tablet.p12
# alice's device certificates
fileparcel client-cert list --user alice
# A lost phone can no longer connect
fileparcel client-cert revoke ccr_01j9zq3x4k6m8p0r2t4v6x8z0b --reason "phone lost"
```

### keys — the encryption keys

All file contents and secrets are encrypted with keys that come from the master key (`keys/master.key`). In
**plain** mode that key file unlocks the server by itself. In **sealed** mode it is protected with a
passphrase, and the server starts locked after every restart until you unlock it (here, or on the `/unlock`
page).

| Command | What it does |
|---|---|
| `keys status` | Locked or not, plain or sealed, and which keys exist. |
| `keys verify` | Check the keys for problems (exit status 1 if there are any). |
| `keys seal` | Protect the master key with a passphrase. |
| `keys unseal` | Remove the passphrase: the server then starts unlocked (recommended only with full-disk encryption). |
| `keys unlock` | Unlock a sealed server after a restart, with the passphrase or the recovery key. |
| `keys lock` | Lock a sealed server now (wipes the key from memory). |
| `keys passphrase` | Change the passphrase. |
| `keys recovery-key` | Create a new recovery key; the old one stops working. |
| `keys rotate` | Replace keys (`--kek`, `--master` or `--data`). |

```sh
# Locked or not, plain or sealed, and the keys
fileparcel keys status
# Check the keys for problems
fileparcel keys verify
# Asks to confirm, then for the new passphrase twice
fileparcel keys seal
# After a restart of a sealed server: type the passphrase (or the recovery key)
fileparcel keys unlock
# Lock a sealed server right now (asks first)
fileparcel keys lock
# Change the passphrase: the current one, then the new one twice
fileparcel keys passphrase
# Store the printed FPRK-… key offline: it unlocks the server if the passphrase is lost
fileparcel keys recovery-key
# A new key-encryption key for the files' keys
fileparcel keys rotate --kek
# Back to plain mode (asks first, then for the passphrase)
fileparcel keys unseal
```

See the recipe [Rotate the encryption keys](#rotate-the-encryption-keys).

## Backups & maintenance

### backup — back up, verify and restore

A backup is one encrypted archive of the database, the settings, the master key, the certificates and (scope
`full`, the default) every stored file, kept in `<HOME>/backups`. Automatic backups run on a schedule, and old
ones are removed by the retention rules. Restoring needs the backup identity (the secret key printed once when
FileParcel was installed) or, on this machine, the copy the server keeps.

| Command | What it does |
|---|---|
| `backup create` | Back up now (`--wait` to wait for it). |
| `backup list` | List backups, newest first. |
| `backup show <backup>` | Show every detail of a backup. |
| `backup verify <backup>` | Check that a backup can be restored (`--deep`: every file too). |
| `backup restore <backup>` | Replace everything with a backup (stop the server first). |
| `backup delete <backup>` | Delete a backup. |
| `backup export <backup> <path>` | Copy a backup archive to a file or another disk. |
| `backup import <file>` | Add a backup archive from another disk or server. |
| `backup schedule show\|set\|enable\|disable` | When automatic backups run. |
| `backup prune` | Delete old automatic backups by the retention rules now. |
| `backup config show\|set` | How many backups are kept, how they are encrypted, where copies go. |
| `backup identity show\|generate` | The key pair backups are encrypted to. |

```sh
# Back up everything now and wait until it is done
fileparcel backup create --wait
# A small backup without file contents, with a note
fileparcel backup create --scope metadata --note "before upgrade" --wait
# Back up and copy the archive to a USB disk in one go
fileparcel backup create -o /mnt/usb/
# All backups, and every detail of one
fileparcel backup list
fileparcel backup show bak_01j9zq3x4k6m8p0r2t4v6x8z0b
# Check that a backup can be restored, every file included
fileparcel backup verify bak_01j9zq3x4k6m8p0r2t4v6x8z0b --deep
# Copy a backup to another disk, and add one from another disk
fileparcel backup export bak_01j9zq3x4k6m8p0r2t4v6x8z0b /mnt/usb/
fileparcel backup import /mnt/usb/fp-5f0c81d2-20260919-040000-full.fpbak
# Check the archive only, changing nothing (the server must be stopped, like for a real restore)
fileparcel backup restore bak_01j9zq3x4k6m8p0r2t4v6x8z0b --dry-run
# Delete a backup without being asked
fileparcel backup delete bak_01j9zq3x4k6m8p0r2t4v6x8z0b -y
# When automatic backups run
fileparcel backup schedule show
# Metadata backups every day at 02:30, full backups on Saturdays at 04:00
fileparcel backup schedule set --meta "30 2 * * *" --full "0 4 * * 6"
# Pause automatic backups, and resume them
fileparcel backup schedule disable
fileparcel backup schedule enable
# Delete old automatic backups by the retention rules now
fileparcel backup prune
# How many backups are kept, and where copies go
fileparcel backup config show
# Always keep the last 10, and one per month for a year
fileparcel backup config set --keep-last 10 --keep-monthly 12
# Also copy every backup to another disk (the folder must exist)
fileparcel backup config set --copy-to /mnt/nas/fileparcel
# The public key backups are encrypted to
fileparcel backup identity show
# A new key pair: store the printed identity file safely (it also opens backups of the previous identities)
(umask 077; fileparcel backup identity generate -y > fileparcel-backup-identity.txt)
```

Schedules use the 5-field cron format: minute, hour, day of month, month, weekday (`0` = Sunday). The
defaults are a metadata backup every day at 03:00 and a full backup on Sundays at 04:00. See the recipe
[Back up now, on a schedule, and restore](#back-up-now-on-a-schedule-and-restore).

### db — the database

Low-level care of the database (`<HOME>/data/fileparcel.db`). `check` and `stats` also work while the server
runs; `vacuum` needs it stopped. `migrate` applies upgrades only while the server is stopped (a running
server has already applied them when it started, and `migrate` just says so). The server tunes the database
by itself every day.

| Command | What it does |
|---|---|
| `db check` | Check the database for damage (exit status 1 if there is any). |
| `db stats` | Show the database size and the number of rows per table. |
| `db vacuum` | Compact the database (server stopped). |
| `db migrate` | Apply database upgrades (the server does this by itself when it starts). |

```sh
# Check the database, and see how big it is
fileparcel db check
fileparcel db stats
# With the server stopped: compact it, and apply upgrades by hand
fileparcel db vacuum
fileparcel db migrate
```

### gc — free disk space

Deletes stored file data that nothing uses any more. It also runs every day by itself; run it by hand after
deleting a lot.

```sh
# Only show what would be removed
fileparcel gc --dry-run
# Free the space now
fileparcel gc
```

### jobs — background jobs

Backups, backup checks, `.zip` files built on upload, thumbnails, key rotation and the regular upkeep run as
background jobs inside the server.

| Command | What it does |
|---|---|
| `jobs list` | List recent jobs with state, progress and errors. |
| `jobs show <job>` | Show one job (`--wait`: follow it to the end). |
| `jobs run <kind>` | Start a job now, for example an upkeep task outside its schedule. |
| `jobs cancel <job>` | Stop a queued or running job. |

```sh
# Recent jobs, and only the ones that failed
fileparcel jobs list
fileparcel jobs list --state failed
# Follow one job until it ends
fileparcel jobs show job_01j9zq3x4k6m8p0r2t4v6x8z0b --wait
# Empty old trash now instead of at night
fileparcel jobs run maintenance.trash --wait
# Stop a job that is queued or running
fileparcel jobs cancel job_01j9zq3x4k6m8p0r2t4v6x8z0b
```

`fileparcel jobs run --help` lists the job kinds you can start.

### maintenance — keep users out while you work

Maintenance mode shows users a notice and pauses files, links and uploads. Administrators and the commands
on the server keep working, and people can still sign in and change their own account settings.

| Command | What it does |
|---|---|
| `maintenance` or `maintenance status` | Show whether maintenance mode is on. |
| `maintenance on` | Keep users out (`--message`: the notice they see). |
| `maintenance off` | Let users back in. |

```sh
# Keep users out, with a notice
fileparcel maintenance on --message "Upgrading, back at 14:00"
# Is it on, and what do users see?
fileparcel maintenance status
# Let users back in
fileparcel maintenance off
```

## Install & service

### completion — tab completion for your shell

See [Shell completion](#shell-completion).

```sh
# Tab completion for Bash
mkdir -p ~/.local/share/bash-completion/completions
fileparcel completion bash > ~/.local/share/bash-completion/completions/fileparcel
```

### healthcheck — does the local server answer?

Asks the server on this machine for `/healthz`, checking its certificate against this installation's own
CA. Exit status 0 when it answers, 1 otherwise; for scripts and the Docker health check.

```sh
# Prints "ok" and exits 0 when the server answers
fileparcel healthcheck
# Another port, and give up sooner
fileparcel healthcheck --port 9443 --timeout 2s
```

### init — create an installation directory without a service

Creates a new installation directory: settings, database, master key, certificates, the network allowlist,
the owner account and a backup identity. It does not install a service; `install` does everything.

```sh
# The owner password is generated and shown once
fileparcel init --home ~/fileparcel
# Another port, and your own name for the owner account
fileparcel init --home ~/fileparcel --port 9443 --admin alice --admin-email alice@example.org
```

### install — install or upgrade

Installs FileParcel into one self-contained directory and registers it as a service. `./install.sh` from the
release zip runs this for you and asks a few questions; `-y` accepts every default. When the directory already
holds an installation, `install` upgrades it instead.

```sh
# Show what would happen, change nothing
fileparcel install --dry-run -y
# Another directory and port, and do not start at boot
fileparcel install -y --dir ~/fileparcel --port 9443 --no-boot
# A system service that runs as its own account
sudo fileparcel install -y --service system
```

The defaults: directory `~/.local/share/fileparcel` (as root `/opt/fileparcel`; on macOS
`~/Library/Application Support/FileParcel` or `/usr/local/fileparcel`), a user service (as root a system
service), HTTPS port 8443 with a redirect from 8080 (or the next free ports), start at boot, owner `admin`,
and the `allowlist` access mode with this machine's home networks and VPNs.

### serve — run the server in the foreground

This is the server itself. The service runs it for you; run it by hand for testing or in Docker.

```sh
# Run the installation in ~/fileparcel until Ctrl-C
fileparcel serve --home ~/fileparcel
# Docker: create the installation on first start
FILEPARCEL_HOME=/data fileparcel serve --init-if-missing
```

It refuses to run as root unless `--allow-root`, and a sealed server starts locked unless you pass
`--passphrase-file`.

### service — start, stop and register the background service

| Command | What it does |
|---|---|
| `service status` | Is the service registered and running? |
| `service start` / `stop` / `restart` | Start, stop or restart it (start and restart wait for the health check). |
| `service install` | Register the service (`--start` to start it now). |
| `service uninstall` | Stop and unregister the service; the data stays. |
| `service enable-boot` / `disable-boot` | Start at boot, or not. |
| `service print` | Show the systemd unit or launchd file without installing it. |

```sh
# Is the service registered and running?
fileparcel service status
# Restart it, for example after a setting that needs a restart
fileparcel service restart
# Stop it (for a restore, say), and start it again
fileparcel service stop
fileparcel service start
# Register the service and start it now
fileparcel service install --start
# Do not start at boot any more, or start at boot again
fileparcel service disable-boot
fileparcel service enable-boot
# Show the systemd unit (or launchd file) it would install
fileparcel service print
# Stop and unregister the service; the data stays
fileparcel service uninstall
```

A user service on Linux keeps running after you log out and starts at boot thanks to systemd's "linger",
which `service install` and `enable-boot` turn on.

### uninstall — remove FileParcel

Stops and unregisters the service, removes the command link and FileParcel's Tailscale Funnel and Serve
entries. Your data stays unless you add `--purge`, which destroys the keys and deletes the installation
directory. It asks first; `--purge` also asks you to type the directory's name.

```sh
# Show what would happen, change nothing
fileparcel uninstall --dry-run
# Remove the program, keep the data
fileparcel uninstall
# Make a last full backup outside the installation, then delete everything
fileparcel uninstall --final-backup --backup-to ~/fileparcel-final --purge
```

`install.sh --dir DIR` picks up data that was kept and sets the service up again.

### upgrade — upgrade to a new release

Upgrades from a release zip (or a program file) and rolls back by itself if the new version does not come
up healthy: it makes a metadata backup, stops the service, swaps the program, starts it again and checks it.

```sh
# Show the plan first, then upgrade (it asks before it starts; from a script it goes ahead without asking)
fileparcel upgrade --dry-run ~/Downloads/fileparcel-v2.zip
fileparcel upgrade ~/Downloads/fileparcel-v2.zip
```

### version — version information

```sh
# Version, commit, build date and platform
fileparcel version
# The same as JSON, for scripts
fileparcel version --json
```

## Recipes

Complete jobs from start to finish. Run them on the server (see
[Run it on the server](#run-it-on-the-server)).

### Add a user

1. Create the account. `--generate-password` prints a strong password once; the user must change it at the
   first sign-in:

   ```sh
   fileparcel user create alice --email alice@example.com --display-name "Alice Liddell" --generate-password
   ```

2. Optionally give them more (or less) storage and put them in a group:

   ```sh
   fileparcel user set-quota alice 50G
   fileparcel group add-member Design alice
   ```

3. Give them the password and one of the addresses from `fileparcel network urls --qr`. Check the result:

   ```sh
   fileparcel user show alice
   ```

To choose the password yourself, leave out `--generate-password`: the command asks for it twice.

### Invite someone with a QR code

An invitation lets someone pick their own username and password, for example on their phone:

```sh
fileparcel invite create --group Design --expires 3d --qr
```

Let them scan the QR code (or send them the link). The link works once and for three days. To stop it
early:

```sh
fileparcel invite list
fileparcel invite revoke inv_01j9zq3x4k6m8p0r2t4v6x8z0b
```

### Create a group and its team folder

```sh
# The group and its team folder /Team/Marketing
fileparcel group create Marketing --description "Marketing team"
# Add people; bob also manages the group
fileparcel group add-member Marketing alice bob
fileparcel group add-member Marketing bob --manager
# Put some files into the team folder, as bob
fileparcel --as bob files put ./brochures /Team/Marketing
fileparcel --as bob files ls /Team/Marketing
```

File commands on the server act as the first owner, who only sees the team folders of groups they belong to
themselves; that is why the last two lines act as bob. Every member now sees Marketing in the web app's
sidebar, under Workspace. People who are not members can be let in with an
[access grant](#let-a-group-or-a-role-see-a-folder).

### Create a limited admin role (helpdesk, netops)

A custom role can open parts of the administration to someone without making them a full admin.

1. See which permissions exist and what they allow:

   ```sh
   fileparcel role permissions
   ```

2. Create the role. A **helpdesk** that manages accounts and resets passwords and two-factor sign-in:

   ```sh
   fileparcel role create helpdesk --from member --add users.manage,users.credentials --description "Resets passwords and unlocks accounts"
   ```

   Or **netops**, who look after the network, the certificates and the server status:

   ```sh
   fileparcel role create netops --from member --add network.manage,certs.manage,system.view --description "Network and certificates"
   ```

3. Check what the role may do, and give it to someone:

   ```sh
   fileparcel role show helpdesk
   fileparcel user set-role carol helpdesk
   ```

People with such a role see the matching admin pages in the web app. Because the role has server
permissions, they must set up two-factor sign-in (the default `auth.require_2fa` rule). To use their role from
the command line on another computer, they need a token with the `admin` scope (see
[Use the command from another computer](#use-the-command-from-another-computer)).

### Let a group or a role see a folder

```sh
# Marketing may see and download from the Design team folder
fileparcel access grant /Team/Design --group Marketing
# Everyone with the netops role may also change files there, for 30 days
fileparcel access grant /Team/Design --role netops --level edit --expires 30d
# Check the result, and why one person has access
fileparcel access list /Team/Design
fileparcel access check alice /Team/Design
# Take one grant back
fileparcel access revoke /Team/Design --role netops
```

Levels are `view` (the default), `edit` and `manage`. A grant on a folder covers everything in it.

### Upload a folder as a password-protected zip

`--zip` bundles everything into one `.zip` file on the server; `--zip-password` protects it (you type the
password twice):

```sh
fileparcel files put ./contracts "/My files/Out" -p --zip contracts.zip --zip-password
```

Or let FileParcel make up a strong password and print it once:

```sh
fileparcel files put ./scans "/My files" --zip scans.zip --zip-generate-password
```

FileParcel does not keep the password: whoever downloads the file needs it from you. The password must have
at least 12 characters (setting `storage.zip_password_min`) and at most 99, using letters, digits, spaces and
the symbols of a US keyboard. The default encryption, AES-256, opens in 7-Zip, WinRAR, Keka, The Unarchiver
and most phone apps, but not in Windows Explorer, macOS Archive Utility or plain `unzip`.
`--zip-encryption zipcrypto` opens there too, but it is weak. File names inside the `.zip` stay readable.

To send it, share the `.zip` with a link and give the password separately:

```sh
fileparcel share create "/My files/Out/contracts.zip" --expires 7d
```

### Share a file with a link that expires

1. Create the link; it stops working after 3 days. `--qr` shows a QR code for phones:

   ```sh
   fileparcel share create "/My files/Slides.pdf" --expires 3d --qr
   ```

2. Add a password if you like (asked twice), or limit the number of downloads:

   ```sh
   fileparcel share edit shr_01j9zq3x4k6m8p0r2t4v6x8z0b --password
   fileparcel share edit shr_01j9zq3x4k6m8p0r2t4v6x8z0b --max-downloads 5
   ```

3. Later, see who used it, give it more time, or delete it:

   ```sh
   fileparcel share log shr_01j9zq3x4k6m8p0r2t4v6x8z0b
   fileparcel share edit shr_01j9zq3x4k6m8p0r2t4v6x8z0b --expires 2026-12-31
   fileparcel share delete shr_01j9zq3x4k6m8p0r2t4v6x8z0b
   ```

`share list` shows the ids of your links.

### Collect files with a file request

1. Make a folder for the uploads and create the upload link:

   ```sh
   fileparcel files mkdir -p "/My files/Incoming/Tax papers"
   fileparcel request create "/My files/Incoming/Tax papers" --title "Send me your tax papers" --max-size 500M --require-name --expires 14d --qr
   ```

2. Send the link (or show the QR code). Uploaders see only the upload page, never the folder's contents.

3. See what arrived, then close the request:

   ```sh
   fileparcel request log shr_01j9zq3x4k6m8p0r2t4v6x8z0b
   fileparcel files ls "/My files/Incoming/Tax papers"
   fileparcel request close shr_01j9zq3x4k6m8p0r2t4v6x8z0b
   ```

`--notify` e-mails you about new uploads (needs e-mail set up: see
[Send e-mail](FILEPARCEL.md#send-e-mail-invitations-and-notifications) in the user manual).

### Put share links on the internet with Tailscale Funnel

Tailscale Funnel makes share links and file requests reachable from anywhere at
`https://<machine>.<tailnet>.ts.net/`, without opening ports on your router. The rest of FileParcel stays
private.

1. Check that everything Funnel needs is in place. Each failed check says how to fix it (for example: turn
   on HTTPS certificates and allow Funnel in your tailnet's settings, or run
   `sudo tailscale set --operator=$USER`):

   ```sh
   fileparcel network funnel status
   ```

2. Turn it on. It asks before publishing anything:

   ```sh
   fileparcel network funnel enable
   ```

3. New share links now use the public address:

   ```sh
   fileparcel share create "/My files/Slides.pdf" --expires 7d
   ```

The public name can take up to 10 minutes to start working. To stop it:

```sh
fileparcel network funnel disable
```

`--mode app` publishes the whole web app instead of only the links; then two-factor sign-in is required over
Funnel and the admin pages stay blocked.

What Funnel needs and how to set it up in Tailscale:
[Put share links on the internet](INSTALL.md#put-share-links-on-the-internet-tailscale-funnel) in the
installation guide. The security details and every check:
[Share links on the internet](FILEPARCEL.md#share-links-on-the-internet-tailscale-funnel) in the user manual.

### Back up now, on a schedule, and restore

**Back up now**, wait for it, and check that the backup can be restored:

```sh
fileparcel backup create --wait
fileparcel backup list
fileparcel backup verify bak_01j9zq3x4k6m8p0r2t4v6x8z0b
```

**Schedule.** Automatic backups are on from the start. Change when they run and how many are kept, and send
a copy of each one to another disk:

```sh
# Metadata backups every day at 01:30, full backups on Sundays at 02:00
fileparcel backup schedule set --meta "30 1 * * *" --full "0 2 * * 0"
# Keep the last 7, one a day for two weeks, one a week for two months, one a month for a year
fileparcel backup config set --keep-last 7 --keep-daily 14 --keep-weekly 8 --keep-monthly 12
# Copy every new backup to a disk mounted at /mnt/usb (the folder must exist)
fileparcel backup config set --copy-to /mnt/usb/fileparcel-backups
```

**Keep the identity safe.** Backups are encrypted. The secret that opens them (the backup identity,
`AGE-SECRET-KEY-…`) was printed once when FileParcel was installed. The server keeps a copy, so restores on
this machine work without it, but if the disk dies you need your own copy. If you do not have one, make a
new key pair, store the file somewhere safe (not on the server) and make a new backup:

```sh
(umask 077; fileparcel backup identity generate -y > fileparcel-backup-identity.txt)
fileparcel backup create --wait
```

`umask 077` keeps the file readable only by you. New backups are then encrypted to the new key. The file also
holds up to five previous identities, so `backup restore --identity-file` with it opens older backups too;
keep an older identity file for backups made before that.

**Restore.** A restore replaces everything (files, users, settings and keys) with the backup; the current
data is moved to `<HOME>/pre-restore-<date>/` first. Stop the server, check the archive, restore, start
again:

```sh
fileparcel service stop
fileparcel backup restore bak_01j9zq3x4k6m8p0r2t4v6x8z0b --dry-run
fileparcel backup restore bak_01j9zq3x4k6m8p0r2t4v6x8z0b
fileparcel service start
```

### Rotate the encryption keys

Make a backup first, then rotate:

```sh
# A backup first
fileparcel backup create --wait
# A new key-encryption key for the files' keys (fast)
fileparcel keys rotate --kek
# The same for encrypted settings and secrets
fileparcel keys rotate --kek --purpose field
# A new master key
fileparcel keys rotate --master
# Check that all is well
fileparcel keys verify
```

If the key file may have been copied by someone, also change the passphrase (`keys passphrase`, sealed mode)
or seal the key (`keys seal`, plain mode), and make a new recovery key (`keys recovery-key`). If the
database may have leaked too, re-encrypt every file with new keys; this runs as a background job and can
take a while on large installations:

```sh
fileparcel keys rotate --data
```

Old keys that nothing uses any more are removed 15 minutes after a rotation, so `keys status` still lists
them for a moment.

### Renew or replace the HTTPS certificate

The certificate from the local CA renews itself. To look at it and renew it by hand:

```sh
fileparcel cert status
fileparcel cert renew --force
```

**A new address or `.local` name**, for example the address of a new VPN, goes into the certificate a few
seconds after you add it:

```sh
fileparcel cert sans add 10.8.0.1
```

**Another DNS name**, such as `files.home.arpa`: the local CA may only sign `.local` and `.ts.net` names, this
machine's own name and private addresses. Add the name, then create a new CA that includes it. Every device
then has to trust the new CA once:

```sh
fileparcel cert sans add files.home.arpa
fileparcel ca regenerate
fileparcel ca trust-help
```

**Your own certificate** (for example from your company's CA), as PEM files with the server certificate
first:

```sh
fileparcel cert upload --cert fullchain.pem --key privkey.pem
fileparcel cert status
# Back to the local CA's certificate
fileparcel cert clear-custom
```

**A certificate every browser trusts** without installing the CA: use Tailscale's
(`fileparcel cert tailscale enable`) or Let's Encrypt's (`fileparcel cert acme enable`); see
[cert](#cert--https-certificates).

**A new local CA**, for example if the old one may have leaked, is made the same way: `fileparcel ca regenerate`
(it asks first), then trust the new CA on every device.

### Move FileParcel to a new machine

A full backup holds everything: files, users, settings, keys and certificates. Moving means restoring it on
the new machine. The commands in short:

```sh
# On the old machine: keep users out, back up into a file, stop the server
fileparcel maintenance on --message "Moving to a new server"
fileparcel backup create -o fileparcel-move.fpbak
fileparcel service stop
# On the new machine, after installing FileParcel and copying the backup and the identity file over
fileparcel service stop
fileparcel backup restore fileparcel-move.fpbak --identity-file fileparcel-backup-identity.txt
fileparcel service start
fileparcel maintenance off
```

The step-by-step guide — getting the backup identity if you have no copy, turning Tailscale Funnel and Serve
off first, and what to check on the new machine afterwards (ports, allowed networks, the firewall) — is
[Move it to a new machine](INSTALL.md#move-it-to-a-new-machine) in the installation guide.

### Find and fix problems with doctor

```sh
# Check the installation, the running server and the service
fileparcel doctor
# Apply the safe fixes: file permissions, leftovers of a crashed server, linger
fileparcel doctor --fix
# Run it again: what --fix repaired is gone from the list
fileparcel doctor
```

Each line starts with `[ok  ]`, `[info]`, `[warn]` or `[FAIL]`, and anything that needs you comes with a line
starting with `→` that says what to do. For a system service, run it with `sudo` so it can also fix the
ownership of files. `fileparcel logs` shows what the server itself said.

## Shell completion

Tab completion completes commands, flags and the values of flags with fixed choices (`--level`, `--mode`,
`--format`, …). While the server runs — over the admin socket, or remotely with `--server` — it also completes
names and ids from it: users, groups, roles, permissions, setting keys, VPNs, links, tokens, backups, jobs and
remote paths, folder by folder. It never opens a stopped installation (no lock, no passphrase prompt), gives
up after a second and a half, and never completes a secret.

```sh
# Bash (needs the bash-completion package)
mkdir -p ~/.local/share/bash-completion/completions
fileparcel completion bash > ~/.local/share/bash-completion/completions/fileparcel
# Zsh: a folder of your own for completion functions
mkdir -p ~/.zfunc
fileparcel completion zsh > ~/.zfunc/_fileparcel
# Fish
mkdir -p ~/.config/fish/completions
fileparcel completion fish > ~/.config/fish/completions/fileparcel.fish
```

For Zsh, also add `fpath=(~/.zfunc $fpath)` to `~/.zshrc`, before the line
`autoload -U compinit; compinit` (add that line too if it is missing).

For PowerShell, add `fileparcel completion powershell | Out-String | Invoke-Expression` to your `$PROFILE`.
Start a new shell afterwards.

## Renamed commands

Some commands and flags have older names from before the command line was tidied up. The old names keep
working, so scripts that use them do not break, but this guide and the help use only the current ones
(`fileparcel help renamed` prints this list):

| Old | New |
|---|---|
| `fileparcel mdns …` | `fileparcel network mdns …` |
| `fileparcel restore …` | `fileparcel backup restore …` |
| `fileparcel keys export-recovery` | `fileparcel keys recovery-key` (it makes a new key; the old one stops working) |
| `fileparcel user add` | `fileparcel user create` |
| `fileparcel user passwd` | `fileparcel user reset-password` |
| `fileparcel user quota` | `fileparcel user set-quota` |
| `fileparcel share revoke` | `fileparcel share delete` |
| `fileparcel request close ID --reopen` | `fileparcel request reopen ID` |
| `fileparcel token create --name NAME` | `fileparcel token create NAME` |
| `fileparcel cert sans --add X` / `--remove X` | `fileparcel cert sans add X` / `remove X` |
| `--generate` (`user create`, `user reset-password`) | `--generate-password` |
| `--out` (`backup create`, `client-cert issue`) | `-o`, `--output` |
| `--all` (`share list`, `request list`) | `--all-users` |
| `--all` (`token list`, `invite list`, `client-cert list`) | `--inactive` |
| `--identity FILE` (`backup restore`) | `--identity-file FILE` |
| `--days N` (`client-cert issue`) | `--expires Nd` |

Using an old command name that the help no longer shows prints a one-line note when you run it in a
terminal. Old flag names keep working without a note.
Changes that scripts may notice in a new release are listed in its release notes
([Before you upgrade](INSTALL.md#before-you-upgrade)).

<!-- BEGIN GENERATED CLI REFERENCE -->
<!-- Regenerate with scripts/gen-cli-docs.sh; edit the command help texts in internal/cli instead. -->

## Command reference

<!-- Generated by `fileparcel docs --markdown`. Do not edit by hand. -->

Every `fileparcel` command, generated from the program itself. Run `fileparcel <command> --help` for the same information in the terminal.

### Contents

- [Global flags](#global-flags)
- [Help topics](#help-topics)

**Getting started**

- [`fileparcel doctor`](#fileparcel-doctor) — Check the installation and fix common problems
- [`fileparcel open`](#fileparcel-open) — Open the web app in your browser (or show QR codes for phones)
- [`fileparcel status`](#fileparcel-status) — Show whether the server is running and how to reach it

**Files \& sharing**

- [`fileparcel files`](#fileparcel-files) — Upload, download, browse and organize files
  - [`fileparcel files cp`](#fileparcel-files-cp) — Copy files and folders
  - [`fileparcel files get`](#fileparcel-files-get) — Download a file, or a folder as a zip or tar file
  - [`fileparcel files info`](#fileparcel-files-info) — Show details of a file or folder
  - [`fileparcel files ls`](#fileparcel-files-ls) — List the contents of a folder
  - [`fileparcel files mkdir`](#fileparcel-files-mkdir) — Create folders
  - [`fileparcel files mv`](#fileparcel-files-mv) — Move or rename files and folders
  - [`fileparcel files put`](#fileparcel-files-put) — Upload files and folders
  - [`fileparcel files restore`](#fileparcel-files-restore) — Bring files and folders back from the trash
  - [`fileparcel files rm`](#fileparcel-files-rm) — Move files and folders to the trash
  - [`fileparcel files search`](#fileparcel-files-search) — Find files and folders by name
  - [`fileparcel files trash`](#fileparcel-files-trash) — List or empty the trash
  - [`fileparcel files tree`](#fileparcel-files-tree) — Show a folder and everything in it as a tree
  - [`fileparcel files versions`](#fileparcel-files-versions) — List or restore older versions of a file
- [`fileparcel request`](#fileparcel-request) — Collect files from others with an upload link
  - [`fileparcel request close`](#fileparcel-request-close) — Stop accepting uploads (reopen later)
  - [`fileparcel request create`](#fileparcel-request-create) — Create an upload link into a folder
  - [`fileparcel request delete`](#fileparcel-request-delete) — Delete a file request for good
  - [`fileparcel request list`](#fileparcel-request-list) — List your file requests
  - [`fileparcel request log`](#fileparcel-request-log) — Show who uploaded through a file request
  - [`fileparcel request reopen`](#fileparcel-request-reopen) — Accept uploads again on a closed file request
  - [`fileparcel request show`](#fileparcel-request-show) — Show a file request and its link
- [`fileparcel share`](#fileparcel-share) — Share files and folders with a public link
  - [`fileparcel share create`](#fileparcel-share-create) — Create a share link for a file or folder
  - [`fileparcel share delete`](#fileparcel-share-delete) — Delete a share link for good
  - [`fileparcel share disable`](#fileparcel-share-disable) — Turn a share link off without deleting it
  - [`fileparcel share edit`](#fileparcel-share-edit) — Change a share link's settings
  - [`fileparcel share enable`](#fileparcel-share-enable) — Turn a disabled share link back on
  - [`fileparcel share list`](#fileparcel-share-list) — List your share links
  - [`fileparcel share log`](#fileparcel-share-log) — Show who opened or downloaded through a link
  - [`fileparcel share show`](#fileparcel-share-show) — Show a share link with its settings and counters

**People \& access**

- [`fileparcel access`](#fileparcel-access) — Give users, groups or roles access to folders
  - [`fileparcel access check`](#fileparcel-access-check) — Explain what a user may do with a file or folder
  - [`fileparcel access grant`](#fileparcel-access-grant) — Give users, groups or roles access to a file or folder
  - [`fileparcel access list`](#fileparcel-access-list) — Show who has access to a file or folder, and why
  - [`fileparcel access revoke`](#fileparcel-access-revoke) — Take back access to a file or folder
- [`fileparcel group`](#fileparcel-group) — Manage groups and their team folders
  - [`fileparcel group add-member`](#fileparcel-group-add-member) — Add users to a group (or make them managers)
  - [`fileparcel group create`](#fileparcel-group-create) — Create a group and its team folder
  - [`fileparcel group delete`](#fileparcel-group-delete) — Delete a group and its team folder with all files
  - [`fileparcel group edit`](#fileparcel-group-edit) — Change a group's name or description
  - [`fileparcel group list`](#fileparcel-group-list) — List groups
  - [`fileparcel group members`](#fileparcel-group-members) — List the members of a group
  - [`fileparcel group remove-member`](#fileparcel-group-remove-member) — Remove users from a group
  - [`fileparcel group rename`](#fileparcel-group-rename) — Rename a group (its team folder follows)
  - [`fileparcel group show`](#fileparcel-group-show) — Show a group, its team folder and its members
- [`fileparcel invite`](#fileparcel-invite) — Invite people to create their own account
  - [`fileparcel invite create`](#fileparcel-invite-create) — Create an invitation link
  - [`fileparcel invite list`](#fileparcel-invite-list) — List invitation links
  - [`fileparcel invite revoke`](#fileparcel-invite-revoke) — Stop an invitation link from working
- [`fileparcel role`](#fileparcel-role) — Create roles and choose what they may do
  - [`fileparcel role add-group`](#fileparcel-role-add-group) — Make everyone with a role a member of a group
  - [`fileparcel role create`](#fileparcel-role-create) — Create a custom role
  - [`fileparcel role delete`](#fileparcel-role-delete) — Delete a custom role (its people move to another role)
  - [`fileparcel role edit`](#fileparcel-role-edit) — Change a custom role's name, description or permissions
  - [`fileparcel role list`](#fileparcel-role-list) — List roles and how many people have each
  - [`fileparcel role members`](#fileparcel-role-members) — List the people who have a role
  - [`fileparcel role permissions`](#fileparcel-role-permissions) — List every permission a role can have
  - [`fileparcel role remove-group`](#fileparcel-role-remove-group) — Stop a role from making its people members of a group
  - [`fileparcel role show`](#fileparcel-role-show) — Show a role: permissions, people, groups and folders
- [`fileparcel token`](#fileparcel-token) — Create API tokens for scripts and remote use
  - [`fileparcel token create`](#fileparcel-token-create) — Create an API token (the secret is shown once)
  - [`fileparcel token list`](#fileparcel-token-list) — List API tokens
  - [`fileparcel token revoke`](#fileparcel-token-revoke) — Revoke an API token right away
- [`fileparcel user`](#fileparcel-user) — Create and manage user accounts
  - [`fileparcel user create`](#fileparcel-user-create) — Create a user account
  - [`fileparcel user delete`](#fileparcel-user-delete) — Delete an account and its files
  - [`fileparcel user disable`](#fileparcel-user-disable) — Stop a user from signing in (their files stay)
  - [`fileparcel user edit`](#fileparcel-user-edit) — Change a user's name, e-mail, role, quota or password rule
  - [`fileparcel user enable`](#fileparcel-user-enable) — Let a disabled user sign in again
  - [`fileparcel user list`](#fileparcel-user-list) — List user accounts
  - [`fileparcel user reset-2fa`](#fileparcel-user-reset-2fa) — Remove a user's second factors (lost phone or key)
  - [`fileparcel user reset-password`](#fileparcel-user-reset-password) — Set a new password for a user
  - [`fileparcel user revoke-sessions`](#fileparcel-user-revoke-sessions) — Sign a user out everywhere
  - [`fileparcel user sessions`](#fileparcel-user-sessions) — List where a user is signed in
  - [`fileparcel user set-quota`](#fileparcel-user-set-quota) — Set how much storage a user may use
  - [`fileparcel user set-role`](#fileparcel-user-set-role) — Change a user's role
  - [`fileparcel user show`](#fileparcel-user-show) — Show everything about one account
  - [`fileparcel user unlock`](#fileparcel-user-unlock) — Clear the lockout after too many failed sign-ins
- [`fileparcel whoami`](#fileparcel-whoami) — Show who you act as, your role and what you may do

**Server \& network**

- [`fileparcel config`](#fileparcel-config) — Show and change settings
  - [`fileparcel config edit`](#fileparcel-config-edit) — Edit fileparcel.toml in your editor
  - [`fileparcel config get`](#fileparcel-config-get) — Show one setting
  - [`fileparcel config list`](#fileparcel-config-list) — List settings (changed ones, or --all)
  - [`fileparcel config path`](#fileparcel-config-path) — Print the path of fileparcel.toml
  - [`fileparcel config set`](#fileparcel-config-set) — Change a setting
  - [`fileparcel config test-email`](#fileparcel-config-test-email) — Send a test e-mail with the saved SMTP settings
  - [`fileparcel config unset`](#fileparcel-config-unset) — Put a setting back to its default
- [`fileparcel logs`](#fileparcel-logs) — Show the server log
- [`fileparcel network`](#fileparcel-network) — Show addresses and control who may connect
  - [`fileparcel network allow`](#fileparcel-network-allow) — Manage the networks allowed to connect
    - [`fileparcel network allow add`](#fileparcel-network-allow-add) — Allow networks or addresses to connect
    - [`fileparcel network allow list`](#fileparcel-network-allow-list) — Show the allowed networks
    - [`fileparcel network allow remove`](#fileparcel-network-allow-remove) — Stop allowing networks or addresses
  - [`fileparcel network deny`](#fileparcel-network-deny) — Manage the networks that may never connect
    - [`fileparcel network deny add`](#fileparcel-network-deny-add) — Block networks or addresses
    - [`fileparcel network deny list`](#fileparcel-network-deny-list) — Show the blocked networks
    - [`fileparcel network deny remove`](#fileparcel-network-deny-remove) — Unblock networks or addresses
  - [`fileparcel network funnel`](#fileparcel-network-funnel) — Publish FileParcel on the internet with Tailscale Funnel
    - [`fileparcel network funnel disable`](#fileparcel-network-funnel-disable) — Stop publishing FileParcel on the internet
    - [`fileparcel network funnel enable`](#fileparcel-network-funnel-enable) — Publish share links (or the whole app) on the internet
    - [`fileparcel network funnel reapply`](#fileparcel-network-funnel-reapply) — Write FileParcel's Funnel and Serve entries to Tailscale again
    - [`fileparcel network funnel status`](#fileparcel-network-funnel-status) — Show whether Funnel is on, its address and what is missing
  - [`fileparcel network interfaces`](#fileparcel-network-interfaces) — List network interfaces (LAN, Wi-Fi, VPNs)
  - [`fileparcel network mdns`](#fileparcel-network-mdns) — Manage the .local name (mDNS / Bonjour)
    - [`fileparcel network mdns disable`](#fileparcel-network-mdns-disable) — Stop publishing the .local name
    - [`fileparcel network mdns enable`](#fileparcel-network-mdns-enable) — Publish the .local name
    - [`fileparcel network mdns mode`](#fileparcel-network-mdns-mode) — Choose how the .local name is published
    - [`fileparcel network mdns name`](#fileparcel-network-mdns-name) — Change the .local name
    - [`fileparcel network mdns republish`](#fileparcel-network-mdns-republish) — Announce the name again
    - [`fileparcel network mdns status`](#fileparcel-network-mdns-status) — Show how the .local name is published
  - [`fileparcel network mode`](#fileparcel-network-mode) — Choose who may connect
  - [`fileparcel network policy`](#fileparcel-network-policy) — Show who may connect (mode, allow and deny lists)
  - [`fileparcel network status`](#fileparcel-network-status) — Show addresses, policy, VPNs and Funnel at a glance
  - [`fileparcel network tailscale-serve`](#fileparcel-network-tailscale-serve) — Tailnet HTTPS address without a port (Tailscale Serve)
    - [`fileparcel network tailscale-serve disable`](#fileparcel-network-tailscale-serve-disable) — Remove the tailnet address without a port
    - [`fileparcel network tailscale-serve enable`](#fileparcel-network-tailscale-serve-enable) — Give the tailnet an HTTPS address without a port
    - [`fileparcel network tailscale-serve reapply`](#fileparcel-network-tailscale-serve-reapply) — Write FileParcel's Funnel and Serve entries to Tailscale again
    - [`fileparcel network tailscale-serve status`](#fileparcel-network-tailscale-serve-status) — Show whether Serve is on, its address and what is missing
  - [`fileparcel network urls`](#fileparcel-network-urls) — List the addresses the server can be reached at
  - [`fileparcel network vpn`](#fileparcel-network-vpn) — Show the VPNs on this machine and let their devices connect
    - [`fileparcel network vpn allow`](#fileparcel-network-vpn-allow) — Let the devices of a VPN connect (adds its ranges)
    - [`fileparcel network vpn list`](#fileparcel-network-vpn-list) — List the VPNs found and whether they may connect
    - [`fileparcel network vpn remove`](#fileparcel-network-vpn-remove) — Stop allowing a VPN's networks
    - [`fileparcel network vpn role`](#fileparcel-network-vpn-role) — Correct how FileParcel treats a network interface

**Security**

- [`fileparcel audit`](#fileparcel-audit) — Read, follow, verify and export the audit log
  - [`fileparcel audit export`](#fileparcel-audit-export) — Save the audit log as CSV or JSON lines
  - [`fileparcel audit list`](#fileparcel-audit-list) — Show audit log entries
  - [`fileparcel audit verify`](#fileparcel-audit-verify) — Check that the audit log was not tampered with
- [`fileparcel ca`](#fileparcel-ca) — Export and trust the local certificate authority
  - [`fileparcel ca export`](#fileparcel-ca-export) — Save the CA certificate for phones and computers
  - [`fileparcel ca fingerprint`](#fileparcel-ca-fingerprint) — Print the CA's SHA-256 fingerprint
  - [`fileparcel ca regenerate`](#fileparcel-ca-regenerate) — Replace the local CA (every device must trust it again)
  - [`fileparcel ca show`](#fileparcel-ca-show) — Show the local CA certificate
  - [`fileparcel ca trust-help`](#fileparcel-ca-trust-help) — Explain how to trust the CA on each device
- [`fileparcel cert`](#fileparcel-cert) — Manage HTTPS certificates (local CA, Tailscale, Let's Encrypt)
  - [`fileparcel cert acme`](#fileparcel-cert-acme) — Get certificates from Let's Encrypt (or another ACME CA)
    - [`fileparcel cert acme disable`](#fileparcel-cert-acme-disable) — Stop using ACME certificates
    - [`fileparcel cert acme enable`](#fileparcel-cert-acme-enable) — Get certificates from an ACME CA now and keep them renewed
  - [`fileparcel cert clear-custom`](#fileparcel-cert-clear-custom) — Stop using the uploaded certificate
  - [`fileparcel cert renew`](#fileparcel-cert-renew) — Reissue the certificate from the local CA
  - [`fileparcel cert sans`](#fileparcel-cert-sans) — Show or change the extra names in the certificate
    - [`fileparcel cert sans add`](#fileparcel-cert-sans-add) — Add DNS names or IP addresses to the certificate
    - [`fileparcel cert sans list`](#fileparcel-cert-sans-list) — List the names the certificate covers
    - [`fileparcel cert sans remove`](#fileparcel-cert-sans-remove) — Remove extra names from the certificate
  - [`fileparcel cert status`](#fileparcel-cert-status) — Show the certificates in use
  - [`fileparcel cert tailscale`](#fileparcel-cert-tailscale) — Use a Tailscale (ts.net) certificate
    - [`fileparcel cert tailscale disable`](#fileparcel-cert-tailscale-disable) — Stop using the Tailscale certificate
    - [`fileparcel cert tailscale enable`](#fileparcel-cert-tailscale-enable) — Use the Tailscale certificate
    - [`fileparcel cert tailscale fetch`](#fileparcel-cert-tailscale-fetch) — Fetch or renew the Tailscale certificate now
  - [`fileparcel cert upload`](#fileparcel-cert-upload) — Use your own certificate
- [`fileparcel client-cert`](#fileparcel-client-cert) — Issue device certificates for mutual TLS
  - [`fileparcel client-cert issue`](#fileparcel-client-cert-issue) — Issue a device certificate (.p12) for a user
  - [`fileparcel client-cert list`](#fileparcel-client-cert-list) — List device certificates
  - [`fileparcel client-cert revoke`](#fileparcel-client-cert-revoke) — Revoke a device certificate
- [`fileparcel keys`](#fileparcel-keys) — Lock, unlock and rotate the encryption keys
  - [`fileparcel keys lock`](#fileparcel-keys-lock) — Lock a sealed server now (wipes the key from memory)
  - [`fileparcel keys passphrase`](#fileparcel-keys-passphrase) — Change the master key passphrase
  - [`fileparcel keys recovery-key`](#fileparcel-keys-recovery-key) — Create a new recovery key (the old one stops working)
  - [`fileparcel keys rotate`](#fileparcel-keys-rotate) — Replace encryption keys
  - [`fileparcel keys seal`](#fileparcel-keys-seal) — Protect the master key with a passphrase
  - [`fileparcel keys status`](#fileparcel-keys-status) — Show whether the keys are locked and which keys exist
  - [`fileparcel keys unlock`](#fileparcel-keys-unlock) — Unlock a sealed server with its passphrase or recovery key
  - [`fileparcel keys unseal`](#fileparcel-keys-unseal) — Remove the passphrase from the master key
  - [`fileparcel keys verify`](#fileparcel-keys-verify) — Check the keyring for problems

**Backups \& maintenance**

- [`fileparcel backup`](#fileparcel-backup) — Back up, verify and restore your data
  - [`fileparcel backup config`](#fileparcel-backup-config) — Show or change retention, encryption and copies
    - [`fileparcel backup config set`](#fileparcel-backup-config-set) — Change backup settings
    - [`fileparcel backup config show`](#fileparcel-backup-config-show) — Show the backup settings
  - [`fileparcel backup create`](#fileparcel-backup-create) — Create a backup now
  - [`fileparcel backup delete`](#fileparcel-backup-delete) — Delete a backup
  - [`fileparcel backup export`](#fileparcel-backup-export) — Copy a backup archive to a file or disk
  - [`fileparcel backup identity`](#fileparcel-backup-identity) — Show or create the backup encryption key pair
    - [`fileparcel backup identity generate`](#fileparcel-backup-identity-generate) — Create a new backup key pair (the identity is shown once)
    - [`fileparcel backup identity show`](#fileparcel-backup-identity-show) — Show the public keys backups are encrypted to
  - [`fileparcel backup import`](#fileparcel-backup-import) — Add a backup archive from another disk or server
  - [`fileparcel backup list`](#fileparcel-backup-list) — List backups
  - [`fileparcel backup prune`](#fileparcel-backup-prune) — Delete old automatic backups by the retention rules
  - [`fileparcel backup restore`](#fileparcel-backup-restore) — Restore a backup (stop the server first)
  - [`fileparcel backup schedule`](#fileparcel-backup-schedule) — Show or change when backups run automatically
    - [`fileparcel backup schedule disable`](#fileparcel-backup-schedule-disable) — Pause automatic backups
    - [`fileparcel backup schedule enable`](#fileparcel-backup-schedule-enable) — Resume automatic backups
    - [`fileparcel backup schedule set`](#fileparcel-backup-schedule-set) — Change when automatic backups run
    - [`fileparcel backup schedule show`](#fileparcel-backup-schedule-show) — Show the backup schedule
  - [`fileparcel backup show`](#fileparcel-backup-show) — Show every detail of a backup
  - [`fileparcel backup verify`](#fileparcel-backup-verify) — Check that a backup can be restored
- [`fileparcel db`](#fileparcel-db) — Check, compact and inspect the database
  - [`fileparcel db check`](#fileparcel-db-check) — Check the database for corruption
  - [`fileparcel db migrate`](#fileparcel-db-migrate) — Apply database upgrades (server stopped)
  - [`fileparcel db stats`](#fileparcel-db-stats) — Show database size and table row counts
  - [`fileparcel db vacuum`](#fileparcel-db-vacuum) — Compact the database (server stopped)
- [`fileparcel gc`](#fileparcel-gc) — Free disk space used by deleted files
- [`fileparcel jobs`](#fileparcel-jobs) — List, follow and start background jobs
  - [`fileparcel jobs cancel`](#fileparcel-jobs-cancel) — Stop a queued or running job
  - [`fileparcel jobs list`](#fileparcel-jobs-list) — List recent jobs
  - [`fileparcel jobs run`](#fileparcel-jobs-run) — Start a background job now
  - [`fileparcel jobs show`](#fileparcel-jobs-show) — Show a job (and wait for it)
- [`fileparcel maintenance`](#fileparcel-maintenance) — Keep users out while you work on the server
  - [`fileparcel maintenance off`](#fileparcel-maintenance-off) — Let users back in
  - [`fileparcel maintenance on`](#fileparcel-maintenance-on) — Keep users out with a maintenance notice
  - [`fileparcel maintenance status`](#fileparcel-maintenance-status) — Show whether maintenance mode is on

**Install \& service**

- [`fileparcel completion`](#fileparcel-completion) — Set up tab completion for your shell
- [`fileparcel healthcheck`](#fileparcel-healthcheck) — Exit 0 when the local server answers (for scripts)
- [`fileparcel init`](#fileparcel-init) — Create a new FileParcel data directory (without a service)
- [`fileparcel install`](#fileparcel-install) — Install FileParcel or upgrade an existing installation
- [`fileparcel serve`](#fileparcel-serve) — Run the server in the foreground
- [`fileparcel service`](#fileparcel-service) — Start, stop and register the background service
  - [`fileparcel service disable-boot`](#fileparcel-service-disable-boot) — Do not start the service at boot
  - [`fileparcel service enable-boot`](#fileparcel-service-enable-boot) — Start the service at boot
  - [`fileparcel service install`](#fileparcel-service-install) — Register the service (and start it with --start)
  - [`fileparcel service print`](#fileparcel-service-print) — Show the unit file / plist without installing it
  - [`fileparcel service restart`](#fileparcel-service-restart) — Restart the service
  - [`fileparcel service start`](#fileparcel-service-start) — Start the service
  - [`fileparcel service status`](#fileparcel-service-status) — Show whether the service is registered and running
  - [`fileparcel service stop`](#fileparcel-service-stop) — Stop the service
  - [`fileparcel service uninstall`](#fileparcel-service-uninstall) — Stop and unregister the service (the data stays)
- [`fileparcel uninstall`](#fileparcel-uninstall) — Remove FileParcel (keeps your data unless --purge)
- [`fileparcel upgrade`](#fileparcel-upgrade) — Upgrade to a new release (with automatic rollback)
- [`fileparcel version`](#fileparcel-version) — Print version information

### Global flags

These flags are accepted by every command.

| Flag | Type | Default | Description |
|---|---|---|---|
| `--as` | string |  | act as USER (socket/offline only; file, share, request and token commands default to the first owner) |
| `--ca-file` | string |  | CA certificate (PEM) to trust for --server |
| `--fingerprint` | string |  | pin the server certificate chain by SHA-256 fingerprint (for --server) |
| `--home` | string |  | FileParcel home directory (default: $FILEPARCEL_HOME or the binary's install dir) |
| `--json` |  |  | print JSON instead of tables |
| `--no-color` |  |  | disable colours |
| `--offline` |  |  | operate in-process on the home (the server must not be running; status, doctor and healthcheck always inspect the home locally) |
| `--passphrase-file` | string |  | master-key passphrase, first line of this file (for commands that need the key on a sealed home with the server stopped) |
| `--passphrase-stdin` |  |  | master-key passphrase, first line of stdin (for commands that need the key on a sealed home with the server stopped) |
| `--server` | string |  | remote server URL, https://host:port (with --token; plain http:// only for loopback) |
| `--token` | string |  | API token for --server (visible to other local users in the process list: prefer $FILEPARCEL_TOKEN, the default, or --token-file) |
| `--token-file` | string |  | API token for --server, first line of this file |
| `-y, --yes` |  |  | assume yes / accept defaults; do not prompt |

### fileparcel access

Give users, groups or roles access to folders.

An access grant lets a user, a group or everyone with a role open a folder (or
a single file) they would not see otherwise, for example another group's team
folder or a folder in someone's own files. Levels: view (see and download),
edit (also add, change, move and delete) or manage (also share it and change
who has access). A grant on a folder covers everything in it. Grants only add
access; they never take away what someone has through their own files or their
groups.

On the server, access commands have full rights over team folders and ids;
for someone's "/My files" name them with --as USER. Remotely you need to
manage the folder yourself. Paths work like in "fileparcel files" (see
"fileparcel help paths").

**Usage**

```
fileparcel access [flags]
fileparcel access <command>
```

**Aliases:** `acl`

**Subcommands**

| Command | Description |
|---|---|
| [`check`](#fileparcel-access-check) | Explain what a user may do with a file or folder |
| [`grant`](#fileparcel-access-grant) | Give users, groups or roles access to a file or folder |
| [`list`](#fileparcel-access-list) | Show who has access to a file or folder, and why |
| [`revoke`](#fileparcel-access-revoke) | Take back access to a file or folder |

**Examples**

```sh
fileparcel access grant /Team/Design --group Marketing
fileparcel access list /Team/Design
fileparcel access revoke /Team/Design --group Marketing
fileparcel access check bob /Team/Design
```

#### fileparcel access check

Explain what a user may do with a file or folder.

Show what a user may do with a file or folder (nothing, view, edit or manage)
and why: their own files, the team folders of their groups, access grants to
them, their groups or their role, and administrators' access to all files.
"/My files" means the user's own files here, unless --as names somebody else.
It asks the server as that user, so it needs the admin socket or offline mode:
run it on the server.

Paths look like "/My files/Docs/a.pdf", "/Team/Design/…" or nod_…; put quotes
around paths with spaces. More: fileparcel help paths.

**Usage**

```
fileparcel access check <user> <path> [flags]
```

**Examples**

```sh
fileparcel access check bob /Team/Design
fileparcel --as alice access check bob "/My files/Taxes/2026.pdf" --json
```

#### fileparcel access grant

Give users, groups or roles access to a file or folder.

Give users (--user), groups (--group) or everyone with a custom role (--role)
access to a file or folder and everything in it. --level is view (see and
download; the default), edit (also add, change, move and delete) or manage
(also share it and change who has access). --expires ends the access after a
time (30d), at the end of a date (2026-12-31) or never (the default for a new
grant). Granting again changes the level; the expiry stays as it was unless
--expires is given.

Paths look like "/My files/Docs/a.pdf", "/Team/Design/…" or nod_…; put quotes
around paths with spaces. More: fileparcel help paths.

**Usage**

```
fileparcel access grant <path> [flags]
```

**Flags**

| Flag | Type | Default | Description |
|---|---|---|---|
| `--expires` | string |  | when the access ends: a duration (30d), a date (2026-12-31) or never (default: never for a new grant, unchanged for an existing one) |
| `--group` | strings |  | give access to this group (repeatable) |
| `--level` | string | `view` | view, edit or manage |
| `--role` | strings |  | give access to everyone with this custom role (repeatable) |
| `--user` | strings |  | give access to this user (repeatable) |

**Examples**

```sh
fileparcel access grant /Team/Design --group Marketing
fileparcel --as alice access grant "/My files/Taxes" --user bob --level edit --expires 30d
fileparcel access grant /Team/Finance --role auditors
```

#### fileparcel access list

Show who has access to a file or folder, and why.

Show the access grants on a file or folder, including the grants on the folders
above it (FROM names the folder a grant is on), and the space it belongs to:
someone's own files, or a group's team folder whose members can edit it.
--direct shows only the grants on this item.

Paths look like "/My files/Docs/a.pdf", "/Team/Design/…" or nod_…; put quotes
around paths with spaces. More: fileparcel help paths.

**Usage**

```
fileparcel access list <path> [flags]
```

**Aliases:** `ls`

**Flags**

| Flag | Type | Default | Description |
|---|---|---|---|
| `--direct` |  |  | only the grants on this item, not those on the folders above it |

**Examples**

```sh
fileparcel access list /Team/Design
fileparcel --as alice access list "/My files/Taxes"
fileparcel access list nod_01j9zq3x4k6m8p0r2t4v6x8z0b --json
```

#### fileparcel access revoke

Take back access to a file or folder.

Take back the access grants of users, groups or roles on a file or folder, or
one grant by its id (as "fileparcel access list" shows it). A grant on a folder
above the path is taken back on that folder: name it instead. Access through
someone's own files or their groups is not a grant. It does not ask first: a
grant can be made again at any time.

Paths look like "/My files/Docs/a.pdf", "/Team/Design/…" or nod_…; put quotes
around paths with spaces. More: fileparcel help paths.

**Usage**

```
fileparcel access revoke <path> [gnt_…] [flags]
```

**Flags**

| Flag | Type | Default | Description |
|---|---|---|---|
| `--group` | strings |  | take back the access of this group (repeatable) |
| `--role` | strings |  | take back the access of everyone with this custom role (repeatable) |
| `--user` | strings |  | take back the access of this user (repeatable) |

**Examples**

```sh
fileparcel access revoke /Team/Design --group Marketing
fileparcel --as alice access revoke "/My files/Taxes" --user bob
fileparcel access revoke /Team/Design gnt_01j9zq3x4k6m8p0r2t4v6x8z0b
```

### fileparcel audit

Read, follow, verify and export the audit log.

The audit log records who did what: sign-ins, changes to users and share
links, downloads, settings, key and certificate operations and more. Every
entry is chained to the one before it with an HMAC, so "fileparcel audit
verify" notices entries that were changed or deleted afterwards.

**Usage**

```
fileparcel audit [flags]
fileparcel audit <command>
```

**Subcommands**

| Command | Description |
|---|---|
| [`export`](#fileparcel-audit-export) | Save the audit log as CSV or JSON lines |
| [`list`](#fileparcel-audit-list) | Show audit log entries |
| [`verify`](#fileparcel-audit-verify) | Check that the audit log was not tampered with |

**Examples**

```sh
fileparcel audit list --since 24h
fileparcel audit list --user alice --action auth. --follow
fileparcel audit verify
fileparcel audit export --format jsonl -o audit.jsonl --since 30d
```

#### fileparcel audit export

Save the audit log as CSV or JSON lines.

Write the audit log, or the entries the filters select, as CSV or JSON lines
to a file (-o) or standard output. An existing file is replaced only with -f.

**Usage**

```
fileparcel audit export [flags]
```

**Flags**

| Flag | Type | Default | Description |
|---|---|---|---|
| `--action` | string |  | only this action ("auth.login") or prefix ("auth.") |
| `-f, --force` |  |  | overwrite an existing output file |
| `--format` | string | `csv` | csv or jsonl |
| `--outcome` | string |  | only success, failure or denied |
| `-o, --output` | string |  | output file (default: stdout) |
| `-q, --query` | string |  | free-text match on actor and target names |
| `--since` | string |  | only entries newer than a duration (24h, 7d) or time (RFC 3339 / 2006-01-02) |
| `--target` | string |  | only this target id |
| `--target-type` | string |  | only targets of this type (user, node, share, setting, …) |
| `--until` | string |  | only entries older than a duration or time |
| `--user` | string |  | only actions by this user (name or id) |

**Examples**

```sh
fileparcel audit export > audit.csv
fileparcel audit export --format jsonl -o audit.jsonl --since 30d
fileparcel audit export --action auth.login --outcome failure
```

#### fileparcel audit list

Show audit log entries.

Show the newest audit log entries (oldest first), optionally filtered.
--follow keeps printing new entries as they arrive (Ctrl-C to stop); with
--json, followed entries are printed as one JSON object per line.

**Usage**

```
fileparcel audit list [flags]
```

**Aliases:** `ls`

**Flags**

| Flag | Type | Default | Description |
|---|---|---|---|
| `--action` | string |  | only this action ("auth.login") or prefix ("auth.") |
| `-f, --follow` |  |  | keep printing new entries |
| `--interval` | duration | `2s` | polling interval for --follow |
| `--limit` | int | `50` | number of entries to show (the newest) |
| `--outcome` | string |  | only success, failure or denied |
| `-q, --query` | string |  | free-text match on actor and target names |
| `--since` | string |  | only entries newer than a duration (24h, 7d) or time (RFC 3339 / 2006-01-02) |
| `--target` | string |  | only this target id |
| `--target-type` | string |  | only targets of this type (user, node, share, setting, …) |
| `--until` | string |  | only entries older than a duration or time |
| `--user` | string |  | only actions by this user (name or id) |

**Examples**

```sh
fileparcel audit list
fileparcel audit list --since 7d --outcome failure
fileparcel audit list --user alice --action share. --limit 20
fileparcel audit list --follow --json
```

#### fileparcel audit verify

Check that the audit log was not tampered with.

Recompute the HMAC chain over the whole audit log and report whether every
entry is intact. Exits with status 1 when the chain is broken (an entry was
modified, deleted or inserted outside FileParcel). Entries written while the
keys were locked prove nothing about their origin: those the sealing server
process did not write itself are reported (see the audit.reseal entries).

**Usage**

```
fileparcel audit verify [flags]
```

**Examples**

```sh
fileparcel audit verify
fileparcel audit verify --json
```

### fileparcel backup

Back up, verify and restore your data.

A backup is one encrypted archive of the database, the settings, the master
key, the certificates and (scope "full", the default) every stored file, kept
in \<HOME>/backups. Automatic backups run on a schedule and old ones are
deleted by the retention rules. Backups are encrypted to a public key, so
restoring needs its secret identity (or the passphrase in passphrase mode):
keep that somewhere safe, away from the server.

Restore with "fileparcel backup restore" while the server is stopped.

**Usage**

```
fileparcel backup [flags]
fileparcel backup <command>
```

**Aliases:** `backups`

**Subcommands**

| Command | Description |
|---|---|
| [`config`](#fileparcel-backup-config) | Show or change retention, encryption and copies |
| [`create`](#fileparcel-backup-create) | Create a backup now |
| [`delete`](#fileparcel-backup-delete) | Delete a backup |
| [`export`](#fileparcel-backup-export) | Copy a backup archive to a file or disk |
| [`identity`](#fileparcel-backup-identity) | Show or create the backup encryption key pair |
| [`import`](#fileparcel-backup-import) | Add a backup archive from another disk or server |
| [`list`](#fileparcel-backup-list) | List backups |
| [`prune`](#fileparcel-backup-prune) | Delete old automatic backups by the retention rules |
| [`restore`](#fileparcel-backup-restore) | Restore a backup (stop the server first) |
| [`schedule`](#fileparcel-backup-schedule) | Show or change when backups run automatically |
| [`show`](#fileparcel-backup-show) | Show every detail of a backup |
| [`verify`](#fileparcel-backup-verify) | Check that a backup can be restored |

**Examples**

```sh
fileparcel backup create --wait
fileparcel backup list
fileparcel backup verify bak_01j9zq3x4k6m8p0r2t4v6x8z0b --deep
fileparcel backup restore bak_01j9zq3x4k6m8p0r2t4v6x8z0b
```

#### fileparcel backup config

Show or change retention, encryption and copies.

Show or change how many backups are kept, how they are encrypted and where a
copy of each goes (the backup.\* settings). Alone it shows them.

**Usage**

```
fileparcel backup config [flags]
fileparcel backup config <command>
```

**Subcommands**

| Command | Description |
|---|---|
| [`set`](#fileparcel-backup-config-set) | Change backup settings |
| [`show`](#fileparcel-backup-config-show) | Show the backup settings |

**Examples**

```sh
fileparcel backup config show
fileparcel backup config set --keep-last 10 --keep-monthly 12
fileparcel backup config set --copy-to /mnt/nas/fileparcel
```

##### fileparcel backup config set

Change backup settings.

Change backup settings; only the flags you pass are changed. --encryption
passphrase needs a passphrase (--passphrase-stdin / --passphrase-file or a
prompt); x25519 uses the recipients (see "fileparcel backup identity").

On the server this always works; remotely it needs an elevated admin token
(see "fileparcel help connect").

**Usage**

```
fileparcel backup config set [flags]
```

**Flags**

| Flag | Type | Default | Description |
|---|---|---|---|
| `--copy-to` | string |  | also copy every backup to this absolute directory ("" = off) |
| `--encryption` | string |  | x25519 (age recipients) or passphrase |
| `--keep-daily` | int |  | keep one backup per day for this many days (scheduled backups only) |
| `--keep-last` | int |  | always keep this many newest backups (scheduled backups only) |
| `--keep-monthly` | int |  | keep one backup per month for this many months (scheduled backups only) |
| `--keep-weekly` | int |  | keep one backup per week for this many weeks (scheduled backups only) |
| `--passphrase-file` | string |  | read the backup passphrase from a file |
| `--passphrase-stdin` |  |  | read the backup passphrase from stdin |
| `--recipient` | strings |  | age recipient (age1…); repeat for several; replaces the list |

**Examples**

```sh
fileparcel backup config set --keep-last 10 --keep-daily 14
fileparcel backup config set --encryption passphrase --passphrase-file /root/fp-backup.pass
fileparcel backup config set --recipient age1… --recipient age1…
fileparcel backup config set --copy-to ""
```

##### fileparcel backup config show

Show the backup settings.

Show the backup schedule, the retention rules, the encryption and where
copies go.

**Usage**

```
fileparcel backup config show [flags]
```

**Examples**

```sh
fileparcel backup config show
fileparcel backup config show --json
```

#### fileparcel backup create

Create a backup now.

Start a backup. Every backup holds the database, fileparcel.toml,
keys/master.key and certs/. Scope "full" (default) also includes every stored
file; "metadata" leaves the file contents out (small and fast; files are not
recoverable from it, but it does contain the master key).

By default the command returns once the backup job is queued; --wait follows it
to the end. -o/--output PATH also copies the finished archive to PATH (a file
or an existing directory; "-" writes it to standard output and nothing else),
which implies --wait. An existing file is only replaced with --force; this is
checked before the backup starts. When the server is stopped the backup runs
in-process and the command waits for it.

**Usage**

```
fileparcel backup create [flags]
```

**Flags**

| Flag | Type | Default | Description |
|---|---|---|---|
| `-f, --force` |  |  | overwrite an existing --output file |
| `--no-wait` |  |  | return at once (default) |
| `--note` | string |  | a note stored with the backup |
| `-o, --output` | string |  | also copy the finished backup to this file or directory, or - for standard output (implies --wait) |
| `--scope` | string | `full` | full (metadata + every stored file) or metadata (database, configuration, keys and certificates; no file contents) |
| `--wait` |  |  | wait until the backup is finished |

**Examples**

```sh
fileparcel backup create --wait
fileparcel backup create --scope metadata --note "before upgrade" --wait
fileparcel backup create -o /mnt/usb/
fileparcel backup create -o - | ssh backup-host 'cat > fp.fpbak'
```

#### fileparcel backup delete

Delete a backup.

Delete a backup archive and its entry for good.

It asks before doing it; -y skips the question.
On the server this always works; remotely it needs an elevated admin token
(see "fileparcel help connect").

**Usage**

```
fileparcel backup delete <backup> [flags]
```

**Aliases:** `rm`

**Examples**

```sh
fileparcel backup delete bak_01j9zq3x4k6m8p0r2t4v6x8z0b
fileparcel backup delete bak_01j9zq3x4k6m8p0r2t4v6x8z0b -y
```

#### fileparcel backup export

Copy a backup archive to a file or disk.

Download a backup archive to a local file or directory (or "-" for standard
output), for example to keep a copy on another disk. Its SHA-256 checksum is
verified. The archive stays encrypted; keep the backup identity or passphrase
somewhere else.

On the server this always works; remotely it needs an elevated admin token
(see "fileparcel help connect").

**Usage**

```
fileparcel backup export <backup> <path> [flags]
```

**Flags**

| Flag | Type | Default | Description |
|---|---|---|---|
| `-f, --force` |  |  | overwrite an existing file |

**Examples**

```sh
fileparcel backup export bak_01j9zq3x4k6m8p0r2t4v6x8z0b /mnt/usb/
fileparcel backup export bak_01j9zq3x4k6m8p0r2t4v6x8z0b - | ssh backup-host 'cat > fp.fpbak'
```

#### fileparcel backup identity

Show or create the backup encryption key pair.

Backups in x25519 mode are encrypted to age recipients (public keys); the
matching identity (secret key) is needed to restore them. "generate" creates a
new key pair: the identity is printed ONCE, so store it offline (password
manager, paper): backups cannot be restored without it. Alone it shows the
public keys.

**Usage**

```
fileparcel backup identity [flags]
fileparcel backup identity <command>
```

**Subcommands**

| Command | Description |
|---|---|
| [`generate`](#fileparcel-backup-identity-generate) | Create a new backup key pair (the identity is shown once) |
| [`show`](#fileparcel-backup-identity-show) | Show the public keys backups are encrypted to |

**Examples**

```sh
fileparcel backup identity show
fileparcel backup identity generate -y > /secure/fileparcel-backup-identity.txt
```

##### fileparcel backup identity generate

Create a new backup key pair (the identity is shown once).

Create a new age key pair for backups. New backups are encrypted to the new
recipient. The identity file is printed once on standard output: redirect it
to a safe place, readable only by you. Below the new identity it lists up to
five previous ones, so "backup restore --identity-file" with it also opens
older backups; keep an older identity file for backups made before that.

It asks before doing it; -y skips the question.
On the server this always works; remotely it needs an elevated admin token
(see "fileparcel help connect").

**Usage**

```
fileparcel backup identity generate [flags]
```

**Examples**

```sh
(umask 077; fileparcel backup identity generate -y > /secure/fileparcel-backup-identity.txt)
fileparcel backup identity generate --json
```

##### fileparcel backup identity show

Show the public keys backups are encrypted to.

Show the public age recipients backups are encrypted to and whether an
identity is stored on the server.

**Usage**

```
fileparcel backup identity show [flags]
```

**Examples**

```sh
fileparcel backup identity show
fileparcel backup identity show --json
```

#### fileparcel backup import

Add a backup archive from another disk or server.

Add a backup archive (.fpbak) made by this or another FileParcel installation
to \<HOME>/backups, so it can be checked and restored.

On the server this always works; remotely it needs an elevated admin token
(see "fileparcel help connect").

**Usage**

```
fileparcel backup import <file> [flags]
```

**Examples**

```sh
fileparcel backup import /mnt/usb/fp-5f0c81d2-20260919-040000-full.fpbak
fileparcel backup import ./old.fpbak --json
```

#### fileparcel backup list

List backups.

List backups, newest first, with scope, state, size, what started them and
the result of the last check ("fileparcel backup verify").

**Usage**

```
fileparcel backup list [flags]
```

**Aliases:** `ls`

**Flags**

| Flag | Type | Default | Description |
|---|---|---|---|
| `--limit` | int |  | maximum number of backups (0 = all) |

**Examples**

```sh
fileparcel backup list
fileparcel backup list --limit 5 --json
```

#### fileparcel backup prune

Delete old automatic backups by the retention rules.

Apply the retention rules now (backup.keep_last, keep_daily, keep_weekly,
keep_monthly; see "fileparcel backup config") and delete the automatic backups
they do not keep. Manual, imported, pre-upgrade and final backups stay until
you delete them. This also runs after every automatic backup.

**Usage**

```
fileparcel backup prune [flags]
```

**Examples**

```sh
fileparcel backup prune
fileparcel backup prune --json
```

#### fileparcel backup restore

Restore a backup (stop the server first).

Replaces everything in this installation (database, files, keys, settings)
with the backup. Stop the server first ("fileparcel service stop"); the old
data is moved to \<HOME>/pre-restore-\<date>/. The restore runs in this process;
start the server again afterwards. It asks before replacing anything; -y skips
the question.

The archive is a backup id (bak_…, from \<HOME>/backups) or a path to a .fpbak
file. Decryption uses --identity-file FILE (an age identity file: every
AGE-SECRET-KEY-… line in it is tried, so the file "backup identity generate"
prints also opens backups made with the identities it lists as previous),
--identity-stdin, --passphrase-stdin/--passphrase-file (passphrase mode), or
by default the identity/passphrase stored in the backup settings. When the
identity or passphrase is read from stdin, stdin cannot answer the
confirmation: pass -y.

When the current installation cannot be opened at all (a damaged database or
master key, or a database already migrated by a newer version), the restore
still works, but the stored identity cannot be read then: pass
--identity-file (or a passphrase flag), and the archive's path if its id
cannot be looked up.

--dry-run decrypts and checks the archive without changing anything.
--metadata-only keeps the current file data, but still restores the database,
the keys, the certificates and fileparcel.toml: the restored database refers to
the backup's keyring, so the keys must come with it. The replaced items are
moved to \<HOME>/pre-restore-\<date>/ like in a full restore.

**Usage**

```
fileparcel backup restore <backup> [flags]
```

**Flags**

| Flag | Type | Default | Description |
|---|---|---|---|
| `--dry-run` |  |  | decrypt and check the archive without changing anything |
| `--identity-file` | string |  | age identity file (AGE-SECRET-KEY-…) for x25519 backups |
| `--identity-stdin` |  |  | read the age identity from stdin |
| `--metadata-only` |  |  | restore the database, keys, certificates and configuration; keep the current file blobs |
| `--passphrase-file` | string |  | read the backup passphrase from a file (passphrase mode) |
| `--passphrase-stdin` |  |  | read the backup passphrase from stdin (passphrase mode) |

**Examples**

```sh
fileparcel service stop && fileparcel backup restore bak_01j9zq3x4k6m8p0r2t4v6x8z0b -y && fileparcel service start
fileparcel backup restore /mnt/usb/fp-5f0c81d2-20260919-040000-full.fpbak --identity-file ~/backup-identity.txt --dry-run
fileparcel backup restore old.fpbak --passphrase-stdin -y < /secure/backup.pass
```

#### fileparcel backup schedule

Show or change when backups run automatically.

Automatic backups: a metadata backup (default daily 03:00) and a full backup
(default Sundays 04:00), in 5-field cron syntax (minute hour day month
weekday). "disable" pauses them; manual backups always work. Alone it shows
the schedule.

**Usage**

```
fileparcel backup schedule [flags]
fileparcel backup schedule <command>
```

**Subcommands**

| Command | Description |
|---|---|
| [`disable`](#fileparcel-backup-schedule-disable) | Pause automatic backups |
| [`enable`](#fileparcel-backup-schedule-enable) | Resume automatic backups |
| [`set`](#fileparcel-backup-schedule-set) | Change when automatic backups run |
| [`show`](#fileparcel-backup-schedule-show) | Show the backup schedule |

**Examples**

```sh
fileparcel backup schedule show
fileparcel backup schedule set --meta "0 3 * * *" --full "0 4 * * 0"
fileparcel backup schedule disable
```

##### fileparcel backup schedule disable

Pause automatic backups.

Pause automatic backups (backup.enabled). Manual backups always work.

**Usage**

```
fileparcel backup schedule disable [flags]
```

**Examples**

```sh
fileparcel backup schedule disable
fileparcel backup schedule disable --json
```

##### fileparcel backup schedule enable

Resume automatic backups.

Resume automatic backups (backup.enabled). Manual backups always work.

**Usage**

```
fileparcel backup schedule enable [flags]
```

**Examples**

```sh
fileparcel backup schedule enable
fileparcel backup schedule enable --json
```

##### fileparcel backup schedule set

Change when automatic backups run.

Set the cron schedules of metadata and/or full backups ("" or "off" turns
one of them off).

**Usage**

```
fileparcel backup schedule set [flags]
```

**Flags**

| Flag | Type | Default | Description |
|---|---|---|---|
| `--full` | string |  | cron schedule of full backups ("off" disables) |
| `--meta` | string |  | cron schedule of metadata backups ("off" disables) |

**Examples**

```sh
fileparcel backup schedule set --meta "30 2 * * *"
fileparcel backup schedule set --full "0 4 * * 6" --meta off
```

##### fileparcel backup schedule show

Show the backup schedule.

Show whether automatic backups are on and when they run.

**Usage**

```
fileparcel backup schedule show [flags]
```

**Examples**

```sh
fileparcel backup schedule show
fileparcel backup schedule show --json
```

#### fileparcel backup show

Show every detail of a backup.

Show every detail of a backup: file, size, checksum, encryption, contents and
the result of the last check.

**Usage**

```
fileparcel backup show <backup> [flags]
```

**Examples**

```sh
fileparcel backup show bak_01j9zq3x4k6m8p0r2t4v6x8z0b
fileparcel backup show bak_01j9zq3x4k6m8p0r2t4v6x8z0b --json
```

#### fileparcel backup verify

Check that a backup can be restored.

Check a backup archive: decrypt and unpack it and check the database inside
(--deep also checks every stored file against its content hash). The backup
is a bak_… id or a local .fpbak file, which is added to the server's backup
list first. The command waits for the check unless --no-wait and exits with
status 1 when it fails.

**Usage**

```
fileparcel backup verify <backup> [flags]
```

**Flags**

| Flag | Type | Default | Description |
|---|---|---|---|
| `--deep` |  |  | also verify every file blob (slow for large backups) |
| `--no-wait` |  |  | return at once |
| `--wait` |  |  | wait until the verification is finished (default) |

**Examples**

```sh
fileparcel backup verify bak_01j9zq3x4k6m8p0r2t4v6x8z0b
fileparcel backup verify bak_01j9zq3x4k6m8p0r2t4v6x8z0b --deep
fileparcel backup verify /mnt/usb/fp-5f0c81d2-20260919-040000-full.fpbak
```

### fileparcel ca

Export and trust the local certificate authority.

FileParcel creates its own certificate authority (CA) when it is set up and
issues the server's certificate from it. Devices trust the server after
installing the CA certificate once ("fileparcel ca trust-help" explains how on
each device). By default the CA may only sign local names and private
addresses, so it cannot be abused to impersonate public web sites.

**Usage**

```
fileparcel ca [flags]
fileparcel ca <command>
```

**Subcommands**

| Command | Description |
|---|---|
| [`export`](#fileparcel-ca-export) | Save the CA certificate for phones and computers |
| [`fingerprint`](#fileparcel-ca-fingerprint) | Print the CA's SHA-256 fingerprint |
| [`regenerate`](#fileparcel-ca-regenerate) | Replace the local CA (every device must trust it again) |
| [`show`](#fileparcel-ca-show) | Show the local CA certificate |
| [`trust-help`](#fileparcel-ca-trust-help) | Explain how to trust the CA on each device |

**Examples**

```sh
fileparcel ca fingerprint
fileparcel ca export --format mobileconfig -o fileparcel.mobileconfig
fileparcel ca trust-help --os android
```

#### fileparcel ca export

Save the CA certificate for phones and computers.

Write the CA certificate as PEM (Linux, Firefox, Android), DER .crt (Windows,
Android) or an Apple configuration profile (.mobileconfig for iOS/macOS).
Without -o, PEM goes to standard output and the other formats to a file in the
current directory. Devices on the network can also download it from
https://\<server>/trust.

**Usage**

```
fileparcel ca export [flags]
```

**Flags**

| Flag | Type | Default | Description |
|---|---|---|---|
| `-f, --force` |  |  | overwrite an existing file |
| `--format` | string | `pem` | pem, der or mobileconfig |
| `-o, --output` | string |  | output file or directory ("-" = stdout) |

**Examples**

```sh
fileparcel ca export > fileparcel-ca.pem
fileparcel ca export --format der -o fileparcel-ca.crt
fileparcel ca export --format mobileconfig
```

#### fileparcel ca fingerprint

Print the CA's SHA-256 fingerprint.

Print the SHA-256 fingerprint of the local CA certificate. Compare it with the
fingerprint shown on a device (or on the /trust page) before trusting the CA,
and use it with "--fingerprint" for remote CLI access.

**Usage**

```
fileparcel ca fingerprint [flags]
```

**Examples**

```sh
fileparcel ca fingerprint
fileparcel ca fingerprint --json
```

#### fileparcel ca regenerate

Replace the local CA (every device must trust it again).

Create a new local CA and reissue the server certificate from it. Every
device that trusted the old CA shows certificate warnings until the new CA is
installed; passkeys keep working once it is trusted. --unconstrained lets the
CA sign any name (only needed for unusual host names; a leaked unconstrained
CA key could impersonate any web site for devices that trust it).

It asks before doing it; -y skips the question.
On the server this always works; remotely it needs an elevated admin token
(see "fileparcel help connect").

**Usage**

```
fileparcel ca regenerate [flags]
```

**Flags**

| Flag | Type | Default | Description |
|---|---|---|---|
| `--unconstrained` |  |  | create the CA without name constraints (not recommended) |

**Examples**

```sh
fileparcel ca regenerate
fileparcel ca regenerate --unconstrained -y
```

#### fileparcel ca show

Show the local CA certificate.

Show the local CA's subject, validity, fingerprint and the names it may sign;
--pem prints the certificate itself.

**Usage**

```
fileparcel ca show [flags]
```

**Flags**

| Flag | Type | Default | Description |
|---|---|---|---|
| `--pem` |  |  | print the CA certificate in PEM format |

**Examples**

```sh
fileparcel ca show
fileparcel ca show --pem > fileparcel-ca.pem
```

#### fileparcel ca trust-help

Explain how to trust the CA on each device.

Print step-by-step instructions for installing and trusting the FileParcel CA
certificate on iOS, Android, macOS, Windows, Linux and Firefox, with the
download address and the fingerprint to compare. Works without a running
server (then with placeholders).

**Usage**

```
fileparcel ca trust-help [flags]
```

**Aliases:** `trust`

**Flags**

| Flag | Type | Default | Description |
|---|---|---|---|
| `--os` | string |  | only this platform: ios, android, macos, windows, linux, firefox |

**Examples**

```sh
fileparcel ca trust-help
fileparcel ca trust-help --os ios
```

### fileparcel cert

Manage HTTPS certificates (local CA, Tailscale, Let's Encrypt).

FileParcel serves HTTPS with a certificate from its own local certificate
authority (CA) by default; devices trust it once ("fileparcel ca"). It can also
use a Tailscale certificate for its ts.net name, one from Let's Encrypt or
another ACME CA, or a certificate you upload. "fileparcel cert status" shows
which one is used for which name.

**Usage**

```
fileparcel cert [flags]
fileparcel cert <command>
```

**Aliases:** `certs`, `tls`

**Subcommands**

| Command | Description |
|---|---|
| [`acme`](#fileparcel-cert-acme) | Get certificates from Let's Encrypt (or another ACME CA) |
| [`clear-custom`](#fileparcel-cert-clear-custom) | Stop using the uploaded certificate |
| [`renew`](#fileparcel-cert-renew) | Reissue the certificate from the local CA |
| [`sans`](#fileparcel-cert-sans) | Show or change the extra names in the certificate |
| [`status`](#fileparcel-cert-status) | Show the certificates in use |
| [`tailscale`](#fileparcel-cert-tailscale) | Use a Tailscale (ts.net) certificate |
| [`upload`](#fileparcel-cert-upload) | Use your own certificate |

**Examples**

```sh
fileparcel cert status
fileparcel cert sans add files.example.lan
fileparcel cert tailscale enable
fileparcel cert acme enable --email me@example.com --domain files.example.com --challenge dns --dns-provider cloudflare --credentials-stdin
```

#### fileparcel cert acme

Get certificates from Let's Encrypt (or another ACME CA).

Get certificates every browser trusts with ACME (Let's Encrypt by default).
Home servers are rarely reachable from the internet, so the DNS challenge
(Cloudflare API token or RFC 2136 dynamic DNS) is the default; "http" and
"tls-alpn" need the server reachable from the internet on ports 80/443. The
Let's Encrypt test CA (staging) is used unless --production.

**Usage**

```
fileparcel cert acme [flags]
fileparcel cert acme <command>
```

**Subcommands**

| Command | Description |
|---|---|
| [`disable`](#fileparcel-cert-acme-disable) | Stop using ACME certificates |
| [`enable`](#fileparcel-cert-acme-enable) | Get certificates from an ACME CA now and keep them renewed |

**Examples**

```sh
echo '{"api_token":"…"}' | fileparcel cert acme enable --email me@example.com --domain files.example.com --credentials-stdin --production
fileparcel cert acme disable
```

##### fileparcel cert acme disable

Stop using ACME certificates.

Turn ACME off (acme.enabled=false). Certificates it got are no longer served
or renewed; the local CA's certificate takes over.

On the server this always works; remotely it needs an elevated admin token
(see "fileparcel help connect").

**Usage**

```
fileparcel cert acme disable [flags]
```

**Examples**

```sh
fileparcel cert acme disable
fileparcel cert acme disable --json
```

##### fileparcel cert acme enable

Get certificates from an ACME CA now and keep them renewed.

Store the ACME settings (acme.\*) and request the certificates now; they are
renewed automatically. The command waits up to 3 minutes for the first
certificate and fails when the CA refuses it (--no-wait returns at once; the
request then runs in the background: see "fileparcel cert status"). A request
still running after 3 minutes goes on in the background. With the server
stopped the settings are checked and used when it starts.

DNS credentials are JSON, read from standard input with --credentials-stdin or
from a file with --credentials-file FILE:
```text
cloudflare: {"api_token":"…"}  (optionally "zone_token")
rfc2136:    {"server":"ns1.example.com:53","key_name":"fileparcel.","key_alg":"hmac-sha256.","key":"<base64>"}
            ("key_alg" is optional; the default is hmac-sha256.)
```
They are checked for the provider's required keys before anything is saved,
and stored encrypted (acme.dns_credentials).

On the server this always works; remotely it needs an elevated admin token
(see "fileparcel help connect").

**Usage**

```
fileparcel cert acme enable [flags]
```

**Flags**

| Flag | Type | Default | Description |
|---|---|---|---|
| `--ca` | string |  | custom ACME directory URL (overrides --production) |
| `--challenge` | string | `dns` | challenge type: dns, http or tls-alpn |
| `--credentials-file` | string |  | read the DNS provider credentials (JSON) from `FILE` |
| `--credentials-stdin` |  |  | read the DNS provider credentials (JSON) from stdin |
| `--dns-provider` | string | `cloudflare` | DNS provider for the dns challenge: cloudflare or rfc2136 |
| `--domain` | strings |  | domain name to obtain a certificate for (repeatable) |
| `--email` | string |  | ACME account e-mail (expiry notices) |
| `--no-wait` |  |  | return at once |
| `--production` |  |  | use the Let's Encrypt production CA (default: staging) |
| `--wait` |  |  | wait until the first certificate is issued (up to 3 minutes) (default) |

**Examples**

```sh
echo '{"api_token":"…"}' | fileparcel cert acme enable --email me@example.com --domain files.example.com --credentials-stdin
fileparcel cert acme enable --email me@example.com --domain files.example.com --challenge http --production
```

#### fileparcel cert clear-custom

Stop using the uploaded certificate.

Remove the uploaded certificate and its key; the server falls back to the
other certificates.

On the server this always works; remotely it needs an elevated admin token
(see "fileparcel help connect").

**Usage**

```
fileparcel cert clear-custom [flags]
```

**Examples**

```sh
fileparcel cert clear-custom
fileparcel cert clear-custom --json
```

#### fileparcel cert renew

Reissue the certificate from the local CA.

Reissue the server certificate from the local CA if it expires within 30 days
or its names changed (--force: always). The server switches to it without a
restart. This happens automatically too.

**Usage**

```
fileparcel cert renew [flags]
```

**Flags**

| Flag | Type | Default | Description |
|---|---|---|---|
| `--force` |  |  | reissue even if the current certificate is still fine |

**Examples**

```sh
fileparcel cert renew
fileparcel cert renew --force
```

#### fileparcel cert sans

Show or change the extra names in the certificate.

Show the names the server certificate covers, or add and remove extra DNS
names and IP addresses (setting tls.extra_sans). Interface addresses, the
.local name, the host name and the Tailscale MagicDNS name are included
automatically. The certificate is reissued when the list changes.

A name the local CA's name constraints do not cover cannot go into the
certificate. It is still stored, but the certificate keeps its current names
until the CA is rebuilt for it with "fileparcel ca regenerate".

**Usage**

```
fileparcel cert sans [flags]
fileparcel cert sans <command>
```

**Aliases:** `names`

**Subcommands**

| Command | Description |
|---|---|
| [`add`](#fileparcel-cert-sans-add) | Add DNS names or IP addresses to the certificate |
| [`list`](#fileparcel-cert-sans-list) | List the names the certificate covers |
| [`remove`](#fileparcel-cert-sans-remove) | Remove extra names from the certificate |

**Examples**

```sh
fileparcel cert sans
fileparcel cert sans add files.home.arpa 10.8.0.1
fileparcel cert sans remove old.example.lan
```

##### fileparcel cert sans add

Add DNS names or IP addresses to the certificate.

Add extra DNS names or IP addresses to the server certificate
(tls.extra_sans); the certificate is reissued. A name the local CA's name
constraints do not cover is stored but stays out of the certificate until
"fileparcel ca regenerate".

**Usage**

```
fileparcel cert sans add <name|ip>... [flags]
```

**Examples**

```sh
fileparcel cert sans add files.home.arpa
fileparcel cert sans add files.home.arpa 10.8.0.1
```

##### fileparcel cert sans list

List the names the certificate covers.

List the DNS names and IP addresses of the server certificate and the extra
names you added (tls.extra_sans). "fileparcel cert sans" alone does the same.

**Usage**

```
fileparcel cert sans list [flags]
```

**Aliases:** `ls`

**Examples**

```sh
fileparcel cert sans list
fileparcel cert sans list --json
```

##### fileparcel cert sans remove

Remove extra names from the certificate.

Remove extra DNS names or IP addresses (tls.extra_sans); the certificate is
reissued. Names added automatically cannot be removed.

**Usage**

```
fileparcel cert sans remove <name|ip>... [flags]
```

**Aliases:** `rm`

**Examples**

```sh
fileparcel cert sans remove old.example.lan
fileparcel cert sans remove 10.8.0.1 old.example.lan
```

#### fileparcel cert status

Show the certificates in use.

Show the local CA, the server certificate it issued and any Tailscale, ACME or
uploaded certificate, with their names, validity and fingerprints.

**Usage**

```
fileparcel cert status [flags]
```

**Aliases:** `show`

**Examples**

```sh
fileparcel cert status
fileparcel cert status --json
```

#### fileparcel cert tailscale

Use a Tailscale (ts.net) certificate.

Serve a certificate every browser trusts for this machine's Tailscale
MagicDNS name (\<machine>.\<tailnet>.ts.net), fetched from the local tailscaled.
Needs HTTPS certificates turned on for the tailnet and operator permission for
this user ("sudo tailscale set --operator=$USER"). Headscale cannot issue
ts.net certificates.

For Funnel and Serve see "fileparcel network funnel" and "fileparcel network
tailscale-serve".

**Usage**

```
fileparcel cert tailscale [flags]
fileparcel cert tailscale <command>
```

**Subcommands**

| Command | Description |
|---|---|
| [`disable`](#fileparcel-cert-tailscale-disable) | Stop using the Tailscale certificate |
| [`enable`](#fileparcel-cert-tailscale-enable) | Use the Tailscale certificate |
| [`fetch`](#fileparcel-cert-tailscale-fetch) | Fetch or renew the Tailscale certificate now |

**Examples**

```sh
fileparcel cert tailscale enable
fileparcel cert tailscale fetch
fileparcel cert tailscale disable
```

##### fileparcel cert tailscale disable

Stop using the Tailscale certificate.

Turn tailscale.cert_enabled off; the local CA's certificate then covers the
ts.net name.

On the server this always works; remotely it needs an elevated admin token
(see "fileparcel help connect").

**Usage**

```
fileparcel cert tailscale disable [flags]
```

**Examples**

```sh
fileparcel cert tailscale disable
fileparcel cert tailscale disable --json
```

##### fileparcel cert tailscale enable

Use the Tailscale certificate.

Turn tailscale.cert_enabled on and fetch the certificate now. It is renewed
automatically when less than 14 days remain.

On the server this always works; remotely it needs an elevated admin token
(see "fileparcel help connect").

**Usage**

```
fileparcel cert tailscale enable [flags]
```

**Flags**

| Flag | Type | Default | Description |
|---|---|---|---|
| `--domain` | string |  | MagicDNS name to use (default: detected) |

**Examples**

```sh
fileparcel cert tailscale enable
fileparcel cert tailscale enable --domain box.tail1234.ts.net
```

##### fileparcel cert tailscale fetch

Fetch or renew the Tailscale certificate now.

Fetch the Tailscale certificate from tailscaled now; this normally happens
automatically.

**Usage**

```
fileparcel cert tailscale fetch [flags]
```

**Examples**

```sh
fileparcel cert tailscale fetch
fileparcel cert tailscale fetch --json
```

#### fileparcel cert upload

Use your own certificate.

Upload a certificate chain (PEM, server certificate first) and its private key
(PEM). The server checks that they match, are valid now and are usable for
HTTPS, then serves the certificate for the names it contains. The key is
stored encrypted. "fileparcel cert clear-custom" stops using it.

On the server this always works; remotely it needs an elevated admin token
(see "fileparcel help connect").

**Usage**

```
fileparcel cert upload --cert FILE --key FILE [flags]
```

**Flags**

| Flag | Type | Default | Description |
|---|---|---|---|
| `--cert` | string |  | certificate chain (PEM) |
| `--key` | string |  | private key (PEM) |

**Examples**

```sh
fileparcel cert upload --cert fullchain.pem --key privkey.pem
fileparcel cert upload --cert fullchain.pem --key privkey.pem --json
```

### fileparcel client-cert

Issue device certificates for mutual TLS.

Device certificates (mutual TLS) let only enrolled phones and computers
connect when mtls.mode is "optional" or "required". They are issued by a
separate client CA and saved as password-protected PKCS#12 (.p12) files that
phones and browsers import. Revoke one when a device is lost.

**Usage**

```
fileparcel client-cert [flags]
fileparcel client-cert <command>
```

**Aliases:** `client-certs`, `mtls`

**Subcommands**

| Command | Description |
|---|---|
| [`issue`](#fileparcel-client-cert-issue) | Issue a device certificate (.p12) for a user |
| [`list`](#fileparcel-client-cert-list) | List device certificates |
| [`revoke`](#fileparcel-client-cert-revoke) | Revoke a device certificate |

**Examples**

```sh
fileparcel client-cert issue alice --name "Alice's phone" -o alice-phone.p12
fileparcel client-cert list --user alice
fileparcel client-cert revoke ccr_01j9zq3x4k6m8p0r2t4v6x8z0b
```

#### fileparcel client-cert issue

Issue a device certificate (.p12) for a user.

Issue a device certificate for a user and save it as a PKCS#12 file (readable
only by you). The .p12 password is read from --password-stdin/--password-file
or generated by the server and printed once. --expires takes a duration
(365d, the default) or a date, at most 10 years ahead. --legacy uses the older
encryption that old Android and macOS versions need.

On the server this always works; remotely it needs an elevated admin token
(see "fileparcel help connect").

**Usage**

```
fileparcel client-cert issue <user> [flags]
```

**Aliases:** `create`

**Flags**

| Flag | Type | Default | Description |
|---|---|---|---|
| `--expires` | string | `365d` | validity: a duration (90d, 2w) or a date (2027-12-31); at most 10 years |
| `-f, --force` |  |  | overwrite an existing output file |
| `--legacy` |  |  | legacy PKCS#12 encryption for old Android/macOS |
| `--name` | string |  | a name for the device (default "\<user> device") |
| `-o, --output` | string |  | output .p12 file (default: \<user>-\<name>.p12) |
| `--password-file` | string |  | read the .p12 password from the first line of `FILE` |
| `--password-stdin` |  |  | read the .p12 password from the first line of standard input |

**Examples**

```sh
fileparcel client-cert issue alice --name "Alice's phone"
fileparcel client-cert issue bob --expires 90d -o bob.p12 --password-stdin < p12-pass.txt
fileparcel client-cert issue carol --legacy
```

#### fileparcel client-cert list

List device certificates.

List issued device certificates; revoked and expired ones only with --inactive.

**Usage**

```
fileparcel client-cert list [flags]
```

**Aliases:** `ls`

**Flags**

| Flag | Type | Default | Description |
|---|---|---|---|
| `--inactive` |  |  | include revoked and expired certificates |
| `--user` | string |  | only the certificates of this user |

**Examples**

```sh
fileparcel client-cert list
fileparcel client-cert list --user alice --inactive --json
```

#### fileparcel client-cert revoke

Revoke a device certificate.

Revoke a device certificate by id (ccr_…) or serial number; the device can no
longer connect while mutual TLS is required.

**Usage**

```
fileparcel client-cert revoke <id|serial> [flags]
```

**Flags**

| Flag | Type | Default | Description |
|---|---|---|---|
| `--reason` | string |  | reason recorded with the revocation |

**Examples**

```sh
fileparcel client-cert revoke ccr_01j9zq3x4k6m8p0r2t4v6x8z0b
fileparcel client-cert revoke 5f:3a:… --reason "phone lost"
```

### fileparcel completion

Set up tab completion for your shell.

Print a completion script for your shell to standard output. Tab then
completes commands, flags and the values of flags with fixed choices, and
while the server runs (admin socket or --server) also names and ids from it:
users, groups, roles, permissions, setting keys, links, backups, jobs and
remote paths. It never opens a stopped installation and never completes a
secret.

Bash (needs the bash-completion package):
```text
mkdir -p ~/.local/share/bash-completion/completions
fileparcel completion bash > ~/.local/share/bash-completion/completions/fileparcel
# system-wide: fileparcel completion bash | sudo tee /etc/bash_completion.d/fileparcel
```

Zsh (a folder of your own for completion functions):
```text
mkdir -p ~/.zfunc
fileparcel completion zsh > ~/.zfunc/_fileparcel
# and in ~/.zshrc, before "autoload -U compinit; compinit":
#   fpath=(~/.zfunc $fpath)
```

Fish:
```text
mkdir -p ~/.config/fish/completions
fileparcel completion fish > ~/.config/fish/completions/fileparcel.fish
```

PowerShell:
```text
fileparcel completion powershell | Out-String | Invoke-Expression
# permanently: add the line above to your $PROFILE
```

Start a new shell afterwards.

**Usage**

```
fileparcel completion <bash|zsh|fish|powershell>
```

**Examples**

```sh
mkdir -p ~/.local/share/bash-completion/completions && fileparcel completion bash > ~/.local/share/bash-completion/completions/fileparcel
mkdir -p ~/.zfunc && fileparcel completion zsh > ~/.zfunc/_fileparcel
mkdir -p ~/.config/fish/completions && fileparcel completion fish > ~/.config/fish/completions/fileparcel.fish
```

### fileparcel config

Show and change settings.

Read and change FileParcel's settings: the runtime settings stored in the
database (applied immediately by a running server) and the bootstrap settings
of fileparcel.toml that are also runtime settings (server name, ports, listen
addresses, public URL and trusted proxies, log.level, runtime.gomemlimit_mb;
most need a restart). Change the other keys of fileparcel.toml with
"fileparcel config edit".

Values are parsed as JSON when they are valid JSON (true, 30, ["a","b"]),
otherwise taken as a plain string; list settings also accept "a,b,c". Secret
settings are read from stdin (or a no-echo prompt), never from the command
line.

**Usage**

```
fileparcel config [flags]
fileparcel config <command>
```

**Aliases:** `settings`

**Subcommands**

| Command | Description |
|---|---|
| [`edit`](#fileparcel-config-edit) | Edit fileparcel.toml in your editor |
| [`get`](#fileparcel-config-get) | Show one setting |
| [`list`](#fileparcel-config-list) | List settings (changed ones, or --all) |
| [`path`](#fileparcel-config-path) | Print the path of fileparcel.toml |
| [`set`](#fileparcel-config-set) | Change a setting |
| [`test-email`](#fileparcel-config-test-email) | Send a test e-mail with the saved SMTP settings |
| [`unset`](#fileparcel-config-unset) | Put a setting back to its default |

**Examples**

```sh
fileparcel config list
fileparcel config get storage.trash_days
fileparcel config set storage.trash_days 14
fileparcel config set smtp.password < smtp-password.txt
```

#### fileparcel config edit

Edit fileparcel.toml in your editor.

Open fileparcel.toml in $VISUAL/$EDITOR (default vi). The file is edited as a
copy, validated when the editor exits and only then saved (atomically, keeping
its permissions and owner). An invalid copy can be edited again; with -y it is
discarded at once. Restart the server to apply the changes.

**Usage**

```
fileparcel config edit [flags]
```

**Examples**

```sh
fileparcel config edit
VISUAL=nano fileparcel config edit
```

#### fileparcel config get

Show one setting.

Print the value of a setting (plain text; lists comma-separated) or, with
--json, everything about it: type, default, allowed values and description.

**Usage**

```
fileparcel config get <key> [flags]
```

**Aliases:** `show`

**Examples**

```sh
fileparcel config get storage.trash_days
fileparcel config get network.allow_cidrs --json
```

#### fileparcel config list

List settings (changed ones, or --all).

List the settings that differ from their defaults (--all: every setting with
its default, type and whether a change needs a restart). Secrets are never
shown, only whether they are set.

**Usage**

```
fileparcel config list [flags]
```

**Aliases:** `ls`

**Flags**

| Flag | Type | Default | Description |
|---|---|---|---|
| `--all` |  |  | list every setting, including those with default values |
| `--section` | string |  | only this section (general, network, tls, auth, storage, sharing, backup, …) |

**Examples**

```sh
fileparcel config list
fileparcel config list --all --section storage
fileparcel config list --all --json
```

#### fileparcel config path

Print the path of fileparcel.toml.

Print the full path of fileparcel.toml, the start-up configuration of the
installation (see --home in "fileparcel help flags").

**Usage**

```
fileparcel config path [flags]
```

**Examples**

```sh
fileparcel config path
$EDITOR "$(fileparcel config path)"
```

#### fileparcel config set

Change a setting.

Change a setting. A running server applies it immediately (some settings
need a restart, which is reported). Offline, the change takes effect at the
next start. Settings shown as "managed" are changed by their own command
(e.g. funnel.\* by "fileparcel network funnel"). Sensitive sections need
elevation remotely.

Values are parsed according to the setting's type: JSON when valid, otherwise a
string; list settings accept "a,b,c"; booleans accept yes/no/on/off. Secret
settings take no value argument: the value is read from stdin (or prompted for
without echo).

Some changes are refused unless confirmed with --force: an access policy
(network.access_mode, network.allow_cidrs, network.deny_cidrs) that would
lock out the client making it, and turning auth.passkeys off or moving the
passkey domain (auth.webauthn_rp_id, mdns.name, server.name) while accounts
have no second factor other than a passkey ("fileparcel user reset-2fa"
lets such a user sign in again).

On the server this always works; remotely it needs an elevated admin token
(see "fileparcel help connect").

**Usage**

```
fileparcel config set <key> [value] [flags]
```

**Flags**

| Flag | Type | Default | Description |
|---|---|---|---|
| `--force` |  |  | apply a change the server refuses as unsafe (an access policy that locks you out; turning passkeys off or moving their domain while accounts rely on a passkey alone) |

**Examples**

```sh
fileparcel config set storage.trash_days 14
fileparcel config set sharing.require_password true
fileparcel config set ui.instance_name "Family Files"
printf '%s' "$SMTP_PASSWORD" | fileparcel config set smtp.password
```

#### fileparcel config test-email

Send a test e-mail with the saved SMTP settings.

Send a test e-mail to an address with the SMTP settings that are saved now
(smtp.\*), to check them before a real notification depends on them. When the
message cannot be sent, the answer of the mail server is shown.

**Usage**

```
fileparcel config test-email --to ADDRESS [flags]
```

**Flags**

| Flag | Type | Default | Description |
|---|---|---|---|
| `--to` | string |  | the address to send the test e-mail to |

**Examples**

```sh
fileparcel config test-email --to admin@example.org
fileparcel --json config test-email --to admin@example.org
```

#### fileparcel config unset

Put a setting back to its default.

Put a setting back to its default value (secrets are cleared). A reset the
server refuses as unsafe needs --force, as with "fileparcel config set".

**Usage**

```
fileparcel config unset <key> [flags]
```

**Aliases:** `reset`

**Flags**

| Flag | Type | Default | Description |
|---|---|---|---|
| `--force` |  |  | apply a change the server refuses as unsafe (an access policy that locks you out; turning passkeys off or moving their domain while accounts rely on a passkey alone) |

**Examples**

```sh
fileparcel config unset ui.login_message
fileparcel config unset storage.trash_days
```

### fileparcel db

Check, compact and inspect the database.

Low-level care of the SQLite database (\<HOME>/data/fileparcel.db). "check" and
"stats" also work while the server runs (they only read); "vacuum" and
"migrate" need the server stopped. The server tunes the database by itself
every day (the maintenance.db_optimize job).

**Usage**

```
fileparcel db [flags]
fileparcel db <command>
```

**Aliases:** `database`

**Subcommands**

| Command | Description |
|---|---|
| [`check`](#fileparcel-db-check) | Check the database for corruption |
| [`migrate`](#fileparcel-db-migrate) | Apply database upgrades (server stopped) |
| [`stats`](#fileparcel-db-stats) | Show database size and table row counts |
| [`vacuum`](#fileparcel-db-vacuum) | Compact the database (server stopped) |

**Examples**

```sh
fileparcel db check
fileparcel db stats
fileparcel service stop && fileparcel db vacuum && fileparcel service start
```

#### fileparcel db check

Check the database for corruption.

Run SQLite's integrity check (--quick: the faster quick_check), the foreign
key check and a schema version comparison; with the server stopped also the
full-text index check. Exits with status 1 when a problem is found.

**Usage**

```
fileparcel db check [flags]
```

**Flags**

| Flag | Type | Default | Description |
|---|---|---|---|
| `--quick` |  |  | use quick_check (faster, fewer checks) |

**Examples**

```sh
fileparcel db check
fileparcel db check --quick --json
```

#### fileparcel db migrate

Apply database upgrades (server stopped).

Apply the database upgrades (schema migrations) this program carries. The
server does this by itself at start; run it by hand after replacing the
program to see the result before starting. A database newer than the program
is never touched. Make a backup first ("fileparcel backup create --scope
metadata").

**Usage**

```
fileparcel db migrate [flags]
```

**Examples**

```sh
fileparcel db migrate
fileparcel --home /opt/fileparcel db migrate
```

#### fileparcel db stats

Show database size and table row counts.

Show the size of the database file and its write-ahead log, page usage, the
schema version and the number of rows per table. Works while the server runs
(it only reads).

**Usage**

```
fileparcel db stats [flags]
```

**Examples**

```sh
fileparcel db stats
fileparcel db stats --json
```

#### fileparcel db vacuum

Compact the database (server stopped).

Rebuild the database file to give free space back to the disk (VACUUM), empty
the write-ahead log and refresh the query planner statistics. Needs the server
stopped and, for a moment, free disk space of up to twice the database size.

**Usage**

```
fileparcel db vacuum [flags]
```

**Aliases:** `compact`

**Examples**

```sh
fileparcel service stop && fileparcel db vacuum && fileparcel service start
fileparcel --offline db vacuum
```

### fileparcel doctor

Check the installation and fix common problems.

Check the FileParcel installation: configuration, directory and key file
permissions, the binary, the running server (admin socket, health check), the
service registration and linger, certificates, the command link, ports and the
firewall. When the server is running its own checks (keys, certificates,
backups, disk, database, jobs, …) are included.

--fix applies the safe repairs: file and directory modes, ownership (as root:
files in the home that its account does not own), stale socket and PID files
of a crashed server, and linger for a start-at-boot user service.

Exit status 1 when a check failed.

**Usage**

```
fileparcel doctor [flags]
```

**Flags**

| Flag | Type | Default | Description |
|---|---|---|---|
| `--fix` |  |  | apply the safe fixes |

**Examples**

```sh
fileparcel doctor
fileparcel doctor --fix
fileparcel doctor --json
```

### fileparcel files

Upload, download, browse and organize files.

Work with the files stored in FileParcel from the command line: list,
upload (verified parts retried on network errors, parallel, optional zip
bundling), download (resumable, verified), create folders, move, copy, delete,
restore from trash, search and inspect versions.

On the server, file commands act as the first owner unless --as USER; remotely
they act as the token's user.

Paths look like "/My files/Docs/a.pdf", "/Team/Design/…" or nod_…; put quotes
around paths with spaces. More: fileparcel help paths.

**Usage**

```
fileparcel files [flags]
fileparcel files <command>
```

**Aliases:** `file`, `fs`

**Subcommands**

| Command | Description |
|---|---|
| [`cp`](#fileparcel-files-cp) | Copy files and folders |
| [`get`](#fileparcel-files-get) | Download a file, or a folder as a zip or tar file |
| [`info`](#fileparcel-files-info) | Show details of a file or folder |
| [`ls`](#fileparcel-files-ls) | List the contents of a folder |
| [`mkdir`](#fileparcel-files-mkdir) | Create folders |
| [`mv`](#fileparcel-files-mv) | Move or rename files and folders |
| [`put`](#fileparcel-files-put) | Upload files and folders |
| [`restore`](#fileparcel-files-restore) | Bring files and folders back from the trash |
| [`rm`](#fileparcel-files-rm) | Move files and folders to the trash |
| [`search`](#fileparcel-files-search) | Find files and folders by name |
| [`trash`](#fileparcel-files-trash) | List or empty the trash |
| [`tree`](#fileparcel-files-tree) | Show a folder and everything in it as a tree |
| [`versions`](#fileparcel-files-versions) | List or restore older versions of a file |

**Examples**

```sh
fileparcel files ls
fileparcel files put ./photos "/My files/Pictures"
fileparcel files get "/My files/Pictures/photos" --zip
fileparcel --as alice files ls /Team/Design
```

#### fileparcel files cp

Copy files and folders.

Copy remote files and folders into a folder, or copy a single one under a new
name. Copies are instant (file contents are shared, not duplicated).

```text
files cp SRC... DEST-FOLDER     copy into an existing folder
files cp SRC NEW-PATH           copy under a new name (NEW-PATH does not exist)
```

--conflict (default rename) decides what happens when a name already exists in
DEST-FOLDER: rename, replace (files only), skip or fail. It does not apply to
NEW-PATH.

Paths look like "/My files/Docs/a.pdf", "/Team/Design/…" or nod_…; put quotes
around paths with spaces. More: fileparcel help paths.

**Usage**

```
fileparcel files cp <src>... <dest> [flags]
```

**Aliases:** `copy`

**Flags**

| Flag | Type | Default | Description |
|---|---|---|---|
| `--conflict` | string | `rename` | when a name exists in the destination: rename, replace, skip or fail |

**Examples**

```sh
fileparcel files cp "/My files/report.pdf" /Team/Design
fileparcel files cp "/My files/template.docx" "/My files/Letters/2026-09.docx"
fileparcel files cp "/My files/Photos" "/My files/Backup"
fileparcel files cp "/My files/a.pdf" "/My files/b.pdf" /Team/Design --conflict skip
```

#### fileparcel files get

Download a file, or a folder as a zip or tar file.

Download a remote file, or a folder as a zip (default) or tar archive.

Files are written to "\<local>.fpart" first (a shortened name when that would
be too long) and renamed when complete; an interrupted download resumes where
it stopped when you run the same command again, unless the remote file changed
in between (then it starts over). The size and the server's content hash are
verified. "-" as local writes to standard output. Folders and --zip/--tar are
streamed (not resumable). --version ID downloads an older version of a file
(see "fileparcel files versions").

Paths look like "/My files/Docs/a.pdf", "/Team/Design/…" or nod_…; put quotes
around paths with spaces. More: fileparcel help paths.

**Usage**

```
fileparcel files get <remote> [local] [flags]
```

**Aliases:** `download`

**Flags**

| Flag | Type | Default | Description |
|---|---|---|---|
| `-f, --force` |  |  | overwrite an existing local file |
| `--no-progress` |  |  | do not draw a progress bar |
| `--no-resume` |  |  | start over instead of resuming a partial download |
| `-o, --output` | string |  | local file or directory (same as the second argument) |
| `--tar` |  |  | download as a tar archive (for macOS Archive Utility and tar users) |
| `--version` | string |  | download an older version (ver_… from "files versions") |
| `--zip` |  |  | download as a zip archive (default for folders) |

**Examples**

```sh
fileparcel files get "/My files/Documents/report.pdf"
fileparcel files get "/My files/Documents/report.pdf" ~/Downloads/
fileparcel files get /Team/Design/Assets --tar -o assets.tar
fileparcel files get "/My files/notes.txt" - | less
```

#### fileparcel files info

Show details of a file or folder.

Show the details of a remote file or folder: id, size, type, content hash,
times, your permission and, for folders, the number of files, folders and
bytes in it (all levels).

Paths look like "/My files/Docs/a.pdf", "/Team/Design/…" or nod_…; put quotes
around paths with spaces. More: fileparcel help paths.

**Usage**

```
fileparcel files info <path> [flags]
```

**Aliases:** `stat`, `show`

**Examples**

```sh
fileparcel files info "/My files/report.pdf"
fileparcel files info /Team/Design --json
fileparcel files info nod_01j9zq3x4k6m8p0r2t4v6x8z0b
```

#### fileparcel files ls

List the contents of a folder.

List the contents of a remote folder (default "/My files"). "/" lists the
top-level folders and "/Team" the team folders you can access. A file path
shows that file.

Paths look like "/My files/Docs/a.pdf", "/Team/Design/…" or nod_…; put quotes
around paths with spaces. More: fileparcel help paths.

**Usage**

```
fileparcel files ls [path] [flags]
```

**Aliases:** `list`

**Flags**

| Flag | Type | Default | Description |
|---|---|---|---|
| `--desc` |  |  | reverse the sort order |
| `-l, --long` |  |  | also show type, permission and version columns |
| `--sort` | string |  | sort by name, size, updated or kind (default: folders first, by name) |

**Examples**

```sh
fileparcel files ls
fileparcel files ls "/My files/Documents" --sort size --desc
fileparcel files ls /Team/Design -l
fileparcel files ls nod_01j9zq3x4k6m8p0r2t4v6x8z0b --json
```

#### fileparcel files mkdir

Create folders.

Create remote folders. With -p/--parents missing parent folders are created
too and existing folders are not an error.

Paths look like "/My files/Docs/a.pdf", "/Team/Design/…" or nod_…; put quotes
around paths with spaces. More: fileparcel help paths.

**Usage**

```
fileparcel files mkdir <path>... [flags]
```

**Flags**

| Flag | Type | Default | Description |
|---|---|---|---|
| `-p, --parents` |  |  | create missing parents; no error if the folder exists |

**Examples**

```sh
fileparcel files mkdir "/My files/Projects"
fileparcel files mkdir -p "/Team/Design/2026/Q3/Drafts"
```

#### fileparcel files mv

Move or rename files and folders.

Move remote files and folders into a folder, or rename a single one:

```text
files mv SRC... DEST-FOLDER     move into an existing folder
files mv SRC NEW-PATH           move and/or rename (NEW-PATH does not exist;
                                a change of case only, "a.txt" → "A.txt",
                                is a rename too)
```

--conflict (default fail) decides what happens when a name already exists in
DEST-FOLDER: rename, replace, skip or fail. It does not apply to NEW-PATH,
which is free by definition.

Paths look like "/My files/Docs/a.pdf", "/Team/Design/…" or nod_…; put quotes
around paths with spaces. More: fileparcel help paths.

**Usage**

```
fileparcel files mv <src>... <dest> [flags]
```

**Aliases:** `move`, `rename`

**Flags**

| Flag | Type | Default | Description |
|---|---|---|---|
| `--conflict` | string | `fail` | when a name exists in the destination: rename, replace, skip or fail |

**Examples**

```sh
fileparcel files mv "/My files/a.txt" "/My files/Archive"
fileparcel files mv "/My files/draft.docx" "/My files/final.docx"
fileparcel files mv "/My files/Photos" /Team/Design --conflict rename
```

#### fileparcel files put

Upload files and folders.

Upload local files and folders (recursively, keeping the structure and empty
folders) into a remote folder. As in the web UI, system files inside folders
(.DS_Store, Thumbs.db, desktop.ini, .localized) are left out and counted.
Large files are sent in 8 MiB parts, several in parallel, each verified with
SHA-256 and retried on network errors. An upload that is interrupted or fails
is cancelled on the server; running the command again starts over.

--conflict decides what happens when a name already exists: rename (default:
"name (1).ext"), replace (adds a new version), skip or fail.

--zip NAME bundles everything into one .zip file built on the server (it
needs the running server). To protect that .zip with a password add
--zip-password (asked twice), --zip-password-stdin, --zip-password-file FILE
or --zip-generate-password (a strong password of 22 letters and digits, or as
many as storage.zip_password_min requires, is printed once). The password
is sent to the server once, kept encrypted only until the .zip is built, and
then forgotten: nobody can recover it. It must be at least 12 characters
long (server setting storage.zip_password_min) and at most 99 (7-Zip cannot
open an AES-256 .zip with a longer one), and use only letters, digits,
spaces and the symbols of a US keyboard.

The default --zip-encryption aes256 opens in 7-Zip, WinRAR, Keka, The
Unarchiver and most phone apps, but not in Windows Explorer, macOS Archive
Utility or plain unzip. zipcrypto opens there too, but it is weak: anyone
with the file can usually recover its contents without the password. File
and folder names inside a protected .zip stay readable.

With a single local file, the remote path may also name the new file
("files put report.pdf "/My files/Docs/Q3 report.pdf""), or an existing
file together with --conflict: replace adds the local file as a new version
of it, whatever its local name.

Paths look like "/My files/Docs/a.pdf", "/Team/Design/…" or nod_…; put quotes
around paths with spaces. More: fileparcel help paths.

**Usage**

```
fileparcel files put <local>... <remote-folder> [flags]
```

**Aliases:** `upload`

**Flags**

| Flag | Type | Default | Description |
|---|---|---|---|
| `--conflict` | string | `rename` | when a name exists: rename, replace, skip or fail |
| `--no-progress` |  |  | do not draw a progress bar |
| `--parallel` | int |  | parts in flight (1-16; default: the server's storage.upload_parallel) |
| `-p, --parents` |  |  | create the remote folder (and missing parents) if needed |
| `--zip` | string |  | bundle everything into one zip file with this name on the server |
| `--zip-encryption` | string |  | encryption of the protected .zip: aes256 (default, strong) or zipcrypto (weak; for Windows Explorer and macOS Archive Utility) |
| `--zip-generate-password` |  |  | generate a strong .zip password and print it once |
| `--zip-password` |  |  | protect the .zip with a password (asked twice on the terminal) |
| `--zip-password-file` | string |  | read the .zip password from the first line of `FILE` |
| `--zip-password-stdin` |  |  | read the .zip password from the first line of standard input |

**Examples**

```sh
fileparcel files put report.pdf "/My files/Documents"
fileparcel files put ./photos ./videos /Team/Design/Assets --parallel 8
fileparcel files put ./contracts "/My files/Out" --zip contracts.zip --zip-password
fileparcel files put ./scans "/My files" --zip scans.zip --zip-generate-password
printf '%s\n' "$ZIP_PASSWORD" | fileparcel files put ./tax "/My files" --zip tax-2026.zip --zip-password-stdin
```

#### fileparcel files restore

Bring files and folders back from the trash.

Restore trashed files and folders to their original location. Items are
matched by id, by their original path ("/My files/Docs/report.pdf") or by name
when unambiguous. An item whose folder is in the trash too goes to the top of
its space ("/My files" or the team folder; restore the folder first to keep
it in place), and a name that is taken there gets " (1)". "fileparcel files
trash" lists what is in the trash.

**Usage**

```
fileparcel files restore <path|id|name>... [flags]
```

**Examples**

```sh
fileparcel files restore "/My files/Docs/report.pdf"
fileparcel files restore report.pdf
fileparcel files restore nod_01j9zq3x4k6m8p0r2t4v6x8z0b
```

#### fileparcel files rm

Move files and folders to the trash.

Move remote files and folders to the trash; "fileparcel files restore" brings
them back until the trash retention (storage.trash_days) ends. --purge deletes
them for good right away (it asks first; -y skips the question).

Paths look like "/My files/Docs/a.pdf", "/Team/Design/…" or nod_…; put quotes
around paths with spaces. More: fileparcel help paths.

**Usage**

```
fileparcel files rm <path>... [flags]
```

**Aliases:** `delete`, `trash-put`

**Flags**

| Flag | Type | Default | Description |
|---|---|---|---|
| `--purge` |  |  | delete permanently instead of moving to the trash |

**Examples**

```sh
fileparcel files rm "/My files/old.zip"
fileparcel files rm "/My files/tmp" "/My files/scratch.txt"
fileparcel files rm "/My files/secret.pdf" --purge -y
```

#### fileparcel files search

Find files and folders by name.

Search the names of all files and folders you can access (substring match,
case-insensitive). --in limits the search to one space ("/My files" or
"/Team/\<group>"); --kind to files or folders.

**Usage**

```
fileparcel files search <query> [flags]
```

**Aliases:** `find`

**Flags**

| Flag | Type | Default | Description |
|---|---|---|---|
| `--in` | string |  | search only this space ("/My files" or "/Team/\<group>") |
| `--kind` | string |  | only files or only folders (file, folder) |
| `--limit` | int | `100` | maximum number of results (0 = all) |

**Examples**

```sh
fileparcel files search invoice
fileparcel files search "2026 Q3" --in /Team/Finance --kind file
fileparcel files search .pdf --limit 20 --json
```

#### fileparcel files trash

List or empty the trash.

List the items in the trash (original path, size, deletion time) or, with
--empty, delete everything in it for good that you may delete: the trash of
your own files and of the team folders you manage (it asks first; -y skips the
question). What stays needs its owner or a manager of the group. Items are
deleted automatically after storage.trash_days.

**Usage**

```
fileparcel files trash [flags]
```

**Flags**

| Flag | Type | Default | Description |
|---|---|---|---|
| `--empty` |  |  | permanently delete everything in the trash that you may delete |

**Examples**

```sh
fileparcel files trash
fileparcel files trash --json
fileparcel files trash --empty -y
```

#### fileparcel files tree

Show a folder and everything in it as a tree.

Show the folders and files below a remote folder (default "/My files") as a
tree, with a summary of the number of folders, files and bytes. --json prints a
flat list of {node, path, depth} entries (parents before children).

Paths look like "/My files/Docs/a.pdf", "/Team/Design/…" or nod_…; put quotes
around paths with spaces. More: fileparcel help paths.

**Usage**

```
fileparcel files tree [path] [flags]
```

**Flags**

| Flag | Type | Default | Description |
|---|---|---|---|
| `--depth` | int |  | maximum depth (0 = unlimited) |
| `-d, --dirs-only` |  |  | show folders only |

**Examples**

```sh
fileparcel files tree
fileparcel files tree "/Team/Design" --depth 2
fileparcel files tree "/My files/Projects" --dirs-only --json
```

#### fileparcel files versions

List or restore older versions of a file.

List the stored versions of a file (uploads with --conflict replace create
new versions; storage.versions_keep limits how many are kept). --restore makes
an older version the current one (the current content becomes a version too).
Download an old version with "fileparcel files get PATH --version ID".

Paths look like "/My files/Docs/a.pdf", "/Team/Design/…" or nod_…; put quotes
around paths with spaces. More: fileparcel help paths.

**Usage**

```
fileparcel files versions <path> [flags]
```

**Flags**

| Flag | Type | Default | Description |
|---|---|---|---|
| `--restore` | string |  | make this version (ver_…) the current one |

**Examples**

```sh
fileparcel files versions "/My files/report.pdf"
fileparcel files versions "/My files/report.pdf" --restore ver_01j9zq3x4k6m8p0r2t4v6x8z0b
fileparcel files versions "/My files/report.pdf" --json
```

### fileparcel gc

Free disk space used by deleted files.

Delete stored file data that no file, version, thumbnail or upload uses any
more, abandoned upload data and stray files in the blob store. This runs daily
(maintenance.blob_gc); run it by hand after deleting a lot. --dry-run only
reports what would be removed (it only reads, so it is safe while the server
runs). --min-age is raised to at least 15 minutes, so data being written right
now is never touched.

**Usage**

```
fileparcel gc [flags]
```

**Aliases:** `cleanup`

**Flags**

| Flag | Type | Default | Description |
|---|---|---|---|
| `--dry-run` |  |  | only report what would be removed |
| `--min-age` | duration | `2d` | only collect data older than this, at least 15m (needs --offline or --dry-run) |

**Examples**

```sh
fileparcel gc --dry-run
fileparcel gc
fileparcel --offline gc --min-age 7d
```

### fileparcel group

Manage groups and their team folders.

A group bundles users. Every group has a team folder, "/Team/\<group>", that
all its members can open; managers of the group can also share it and change
who has access to it. Name groups by name or by id (grp_…).

To let another group or single users into a team folder without making them
members, see "fileparcel access".

**Usage**

```
fileparcel group [flags]
fileparcel group <command>
```

**Aliases:** `groups`

**Subcommands**

| Command | Description |
|---|---|
| [`add-member`](#fileparcel-group-add-member) | Add users to a group (or make them managers) |
| [`create`](#fileparcel-group-create) | Create a group and its team folder |
| [`delete`](#fileparcel-group-delete) | Delete a group and its team folder with all files |
| [`edit`](#fileparcel-group-edit) | Change a group's name or description |
| [`list`](#fileparcel-group-list) | List groups |
| [`members`](#fileparcel-group-members) | List the members of a group |
| [`remove-member`](#fileparcel-group-remove-member) | Remove users from a group |
| [`rename`](#fileparcel-group-rename) | Rename a group (its team folder follows) |
| [`show`](#fileparcel-group-show) | Show a group, its team folder and its members |

**Examples**

```sh
fileparcel group create Design --description "Design team"
fileparcel group add-member Design alice bob
fileparcel group show Design
```

#### fileparcel group add-member

Add users to a group (or make them managers).

Add users to a group as members, or as managers with --manager (managers may
also share the team folder and change who has access to it). Running it again
for someone already in the group changes their role in it.

The users are added in order; at the first error it stops and says which
users were added before it.

**Usage**

```
fileparcel group add-member <group> <user>... [flags]
```

**Flags**

| Flag | Type | Default | Description |
|---|---|---|---|
| `--manager` |  |  | make the users managers of the group |

**Examples**

```sh
fileparcel group add-member Design alice
fileparcel group add-member Design alice bob carol
fileparcel group add-member Design bob --manager
```

#### fileparcel group create

Create a group and its team folder.

Create a group. Its team folder is created at the same time and appears as
"/Team/\<name>". Add people with "fileparcel group add-member".

**Usage**

```
fileparcel group create <name> [flags]
```

**Flags**

| Flag | Type | Default | Description |
|---|---|---|---|
| `--description` | string |  | description of the group |

**Examples**

```sh
fileparcel group create Design
fileparcel group create "Finance 2026" --description "Accounting and invoices"
```

#### fileparcel group delete

Delete a group and its team folder with all files.

Delete a group, its memberships and its team folder with all files in it.
The members keep their accounts and their own files.

It asks before doing it; -y skips the question.

**Usage**

```
fileparcel group delete <group> [flags]
```

**Aliases:** `rm`

**Examples**

```sh
fileparcel group delete Design
fileparcel group delete Design -y
```

#### fileparcel group edit

Change a group's name or description.

Change a group's name, its description or both; only the flags you pass are
changed. A new name also renames the team folder; its files stay where they
are.

**Usage**

```
fileparcel group edit <group> [flags]
```

**Flags**

| Flag | Type | Default | Description |
|---|---|---|---|
| `--description` | string |  | new description ("" clears it) |
| `--name` | string |  | new name of the group (its team folder follows) |

**Examples**

```sh
fileparcel group edit Design --description "Product design team"
fileparcel group edit Design --name "Product Design"
```

#### fileparcel group list

List groups.

List all groups with their number of members and their description.

**Usage**

```
fileparcel group list [flags]
```

**Aliases:** `ls`

**Examples**

```sh
fileparcel group list
fileparcel group list --json
```

#### fileparcel group members

List the members of a group.

List the members of a group with their role in the group: member, or
manager (may also share the team folder and change who has access to it).
SOURCE says how they became members: "direct" when they were added, and
"role:\<name>" when a role makes its people members ("fileparcel role
add-group").

**Usage**

```
fileparcel group members <group> [flags]
```

**Examples**

```sh
fileparcel group members Design
fileparcel group members Design --json
```

#### fileparcel group remove-member

Remove users from a group.

Remove users from a group. Files they created in the team folder stay there.

This removes their own membership. Someone whose custom role makes them a
member ("role:\<name>" in "fileparcel group members") stays a member through
the role: the command says so, and "fileparcel role remove-group ROLE GROUP"
or another role ("fileparcel user set-role") ends that.

The users are removed in order; at the first error it stops and says which
users were removed before it.

**Usage**

```
fileparcel group remove-member <group> <user>... [flags]
```

**Examples**

```sh
fileparcel group remove-member Design alice
fileparcel group remove-member Design alice bob
```

#### fileparcel group rename

Rename a group (its team folder follows).

Rename a group. Its team folder keeps its contents and appears under the new
name. "fileparcel group edit" changes the description too.

**Usage**

```
fileparcel group rename <group> <new-name> [flags]
```

**Examples**

```sh
fileparcel group rename Design "Product Design"
fileparcel group rename grp_01j9zq3x4k6m8p0r2t4v6x8z0b Design
```

#### fileparcel group show

Show a group, its team folder and its members.

Show a group: its description, its team folder and everyone who is a member
of it, with their role in the group (member or manager).

**Usage**

```
fileparcel group show <group> [flags]
```

**Examples**

```sh
fileparcel group show Design
fileparcel group show grp_01j9zq3x4k6m8p0r2t4v6x8z0b --json
```

### fileparcel healthcheck

Exit 0 when the local server answers (for scripts).

Ask the server on this machine whether it answers: GET
https://127.0.0.1:\<port>/healthz (and [::1]), with the certificate checked
against this installation's local CA only. Exit status 0 when the server
answers 200, 1 otherwise. Used by the installer, upgrades and the Docker
HEALTHCHECK.

**Usage**

```
fileparcel healthcheck [flags]
```

**Flags**

| Flag | Type | Default | Description |
|---|---|---|---|
| `--port` | int |  | HTTPS port (default: server.https_port from fileparcel.toml) |
| `--timeout` | duration | `5s` | timeout per address |

**Examples**

```sh
fileparcel healthcheck
fileparcel healthcheck --port 9443 --timeout 2s
```

### fileparcel init

Create a new FileParcel data directory (without a service).

Create and initialise a FileParcel home in DIR (without installing a service):
the directory layout, fileparcel.toml, the database, the master key (plain, or
sealed with a passphrase), the local CA, client CA and server certificate, the
network allowlist (the private subnets of this machine's LAN/Wi-Fi
interfaces, the tailnet ranges and VPN subnets), the owner account and a
backup identity.

The owner password is generated (shown once, must be changed at the first
sign-in) unless one is given with --admin-password-stdin/--admin-password-file.
With --no-admin no account is created; the first account is then set up in the
browser at /setup with the one-time token the server prints when it starts.

Use "fileparcel install" for a complete installation with a service.

**Usage**

```
fileparcel init --home DIR [flags]
```

**Flags**

| Flag | Type | Default | Description |
|---|---|---|---|
| `--access` | string | `allowlist` | who may connect: private \| allowlist \| any |
| `--admin` | string | `admin` | username of the owner account |
| `--admin-email` | string |  | e-mail address of the owner |
| `--admin-password-file` | string |  | read the owner password from a file |
| `--admin-password-stdin` |  |  | read the owner password from standard input |
| `--allow` | strings |  | add a network (CIDR or IP) to the allowlist (repeatable) |
| `--generate-password` |  |  | generate the owner password (the default without a terminal) |
| `--http-port` | int | `8080` | HTTP port that redirects to HTTPS (0 = none) |
| `--name` | string | `fileparcel` | server name: NAME.local via mDNS, CA name |
| `--no-admin` |  |  | create no account; set up the first one in the browser at /setup |
| `--passphrase-file` | string |  | read the master-key passphrase from a file (with --sealed) |
| `--passphrase-stdin` |  |  | read the master-key passphrase from standard input (with --sealed) |
| `--port` | int | `8443` | HTTPS port |
| `--sealed` |  |  | seal the master key with a passphrase (unlock after every restart) |

**Examples**

```sh
fileparcel init --home ~/fileparcel
fileparcel init --home /srv/fp --port 9443 --admin alice --admin-email alice@example.org
printf '%s\n' "$PASS" | fileparcel init --home /srv/fp --admin-password-stdin -y
fileparcel init --home /srv/fp --sealed --passphrase-file /run/secrets/fp-passphrase
```

### fileparcel install

Install FileParcel or upgrade an existing installation.

Install FileParcel into a self-contained directory and register it as a
service. ./install.sh from the release zip runs this for you; it asks its
questions interactively, -y accepts every default (and so does a run without
a terminal, which has nobody to ask).

A fresh install copies this binary to \<dir>/bin/fileparcel (plus VERSION,
uninstall.sh and docs/ when found next to it), initialises the home (master
key, certificates, network allowlist, owner account with a generated password,
backup identity), links the "fileparcel" command, registers and starts the
service (systemd user/system unit or launchd agent/daemon; start at boot uses
linger for user units), checks /healthz and prints a summary: the URLs with QR
codes, the CA fingerprint, the credentials (shown only once) and the firewall
commands to allow access from your networks.

When \<dir> already contains an installation, install upgrades it to this
binary instead (pre-upgrade backup, binary swap with rollback, health check)
and repairs a missing service registration or command link. The options of
a fresh install (--port, --admin, --sealed, --access, --name, …) are then
ignored with a warning, and a --service other than the installed one is
refused.

--dry-run prints the plan without changing anything.

Defaults: dir ~/.local/share/fileparcel (root: /opt/fileparcel; macOS
~/Library/Application Support/FileParcel or /usr/local/fileparcel), service
user (root: system), ports 8443/8080 (the next free port is suggested), start
at boot, admin "admin", access allowlist (the detected private LAN/Wi-Fi
subnets, tailnet and VPN ranges).

**Usage**

```
fileparcel install [flags]
```

**Flags**

| Flag | Type | Default | Description |
|---|---|---|---|
| `--access` | string |  | who may connect: private \| allowlist \| any (default allowlist) |
| `--admin` | string |  | owner username (default admin) |
| `--admin-email` | string |  | owner e-mail address |
| `--admin-password-file` | string |  | read the owner password from a file |
| `--admin-password-stdin` |  |  | read the owner password from standard input |
| `--allow` | strings |  | add a network (CIDR or IP) to the allowlist (repeatable) |
| `--boot` |  |  | start at boot (default; user services enable linger) |
| `--dir` | string |  | install directory (default: see above; --home works too) |
| `--dry-run` |  |  | print the plan without changing anything |
| `--force` |  |  | replace a foreign command link or another home's service registration; upgrade even when the pre-upgrade backup fails |
| `--generate-password` |  |  | generate the owner password (default; shown once, must be changed at the first sign-in) |
| `--http-port` | int | `-1` | HTTP port that redirects to HTTPS, 0 = none (default 8080 or the next free port) |
| `--name` | string |  | server name: NAME.local via mDNS, CA name (default fileparcel) |
| `--no-boot` |  |  | do not start at boot |
| `--no-start` |  |  | register the service but do not start it now |
| `--no-symlink` |  |  | do not create the command link |
| `--passphrase-file` | string |  | read the master-key passphrase from a file (with --sealed) |
| `--passphrase-stdin` |  |  | read the master-key passphrase from standard input (with --sealed) |
| `--port` | int |  | HTTPS port (default 8443 or the next free port) |
| `--sealed` |  |  | seal the master key with a passphrase (the server starts locked after every restart) |
| `--service` | string |  | service kind: user \| system \| none (default: user; as root: system) |
| `--skip-backup` |  |  | upgrade without the pre-upgrade backup |
| `--symlink` | string |  | where to link the fileparcel command (default ~/.local/bin/fileparcel; root: /usr/local/bin/fileparcel) |
| `--upgrade` |  |  | only upgrade an existing installation (fail when there is none) |

**Examples**

```sh
fileparcel install
fileparcel install -y --dir ~/fileparcel --port 9443 --no-boot
fileparcel install -y --access private --admin alice --admin-email alice@example.org
sudo fileparcel install -y --service system
fileparcel install --dry-run -y
```

### fileparcel invite

Invite people to create their own account.

An invitation link lets someone create their own account: they choose the
username and password, you choose the role, groups and quota beforehand.
Links expire (after 7 days unless --expires) and can be limited to a number of
uses. Sending them by e-mail needs the SMTP settings.

**Usage**

```
fileparcel invite [flags]
fileparcel invite <command>
```

**Aliases:** `invites`

**Subcommands**

| Command | Description |
|---|---|
| [`create`](#fileparcel-invite-create) | Create an invitation link |
| [`list`](#fileparcel-invite-list) | List invitation links |
| [`revoke`](#fileparcel-invite-revoke) | Stop an invitation link from working |

**Examples**

```sh
fileparcel invite create --role member --group Design --expires 3d
fileparcel invite list
fileparcel invite revoke inv_01j9zq3x4k6m8p0r2t4v6x8z0b
```

#### fileparcel invite create

Create an invitation link.

Create an invitation link and print it. The link of an active invitation is
also shown by "fileparcel invite list". --send e-mails it to --email (needs the
SMTP settings); --qr prints a QR code for phones.

--note is a message to the invited person: it is shown on the sign-up page to
anyone who opens the link and included in the invitation e-mail, so do not put
private remarks in it.

Inviting an admin needs an elevated admin token remotely;
on the server this always works (see "fileparcel help connect").

**Usage**

```
fileparcel invite create [flags]
```

**Flags**

| Flag | Type | Default | Description |
|---|---|---|---|
| `--email` | string |  | e-mail address of the invitee |
| `--expires` | string | `7d` | validity: a duration (12h, 7d, 2w) or a date (2026-12-31) |
| `--group` | strings |  | add the new account to this group (repeatable) |
| `--note` | string |  | message to the invited person, shown on the sign-up page and in the invitation e-mail (not private) |
| `--qr` |  |  | also print the link as a QR code |
| `--quota` | string |  | storage quota of the new account (e.g. 10G, unlimited) |
| `--role` | string | `member` | role of the new account (default member; any role except owner, see "fileparcel role list") |
| `--send` |  |  | e-mail the link to --email (needs SMTP) |
| `--uses` | int | `1` | how many accounts the link may create (must be 1 with --email) |

**Examples**

```sh
fileparcel invite create
fileparcel invite create --role guest --expires 1d --qr
fileparcel invite create --email bob@example.com --send --group Design --uses 1
fileparcel invite create --uses 10 --expires 14d --quota 5G --note "Welcome to the workshop"
```

#### fileparcel invite list

List invitation links.

List invitation links. Only active ones are shown unless --inactive, which
adds used, expired and revoked ones. Active invitations show their link, except
while the server's keys are locked and, remotely without an elevated token, for
admin invitations.

**Usage**

```
fileparcel invite list [flags]
```

**Aliases:** `ls`

**Flags**

| Flag | Type | Default | Description |
|---|---|---|---|
| `--inactive` |  |  | include used, expired and revoked invites |

**Examples**

```sh
fileparcel invite list
fileparcel invite list --inactive --json
```

#### fileparcel invite revoke

Stop an invitation link from working.

Revoke an invitation link so it can no longer be used. Accounts already
created with it stay.

**Usage**

```
fileparcel invite revoke <id> [flags]
```

**Examples**

```sh
fileparcel invite revoke inv_01j9zq3x4k6m8p0r2t4v6x8z0b
fileparcel invite revoke inv_01j9zq3x4k6m8p0r2t4v6x8z0b --json
```

### fileparcel jobs

List, follow and start background jobs.

Background jobs run inside the server: backups and their checks, .zip files
built on upload, thumbnails, key rotation and the regular upkeep (removing old
sessions and unfinished uploads, emptying old trash, freeing disk space,
pruning the audit log, tuning the database, renewing certificates).

**Usage**

```
fileparcel jobs [flags]
fileparcel jobs <command>
```

**Aliases:** `job`

**Subcommands**

| Command | Description |
|---|---|
| [`cancel`](#fileparcel-jobs-cancel) | Stop a queued or running job |
| [`list`](#fileparcel-jobs-list) | List recent jobs |
| [`run`](#fileparcel-jobs-run) | Start a background job now |
| [`show`](#fileparcel-jobs-show) | Show a job (and wait for it) |

**Examples**

```sh
fileparcel jobs list
fileparcel jobs list --state failed
fileparcel jobs show job_01j9zq3x4k6m8p0r2t4v6x8z0b --wait
fileparcel jobs run maintenance.trash --wait
```

#### fileparcel jobs cancel

Stop a queued or running job.

Ask a queued or running job to stop. Jobs stop at the next safe point and
undo or clean up what they did.

**Usage**

```
fileparcel jobs cancel <job> [flags]
```

**Examples**

```sh
fileparcel jobs cancel job_01j9zq3x4k6m8p0r2t4v6x8z0b
fileparcel jobs cancel job_01j9zq3x4k6m8p0r2t4v6x8z0b --json
```

#### fileparcel jobs list

List recent jobs.

List background jobs, newest first, with state, progress, duration and error.

**Usage**

```
fileparcel jobs list [flags]
```

**Aliases:** `ls`

**Flags**

| Flag | Type | Default | Description |
|---|---|---|---|
| `--kind` | string |  | only jobs of this kind (e.g. backup.create) |
| `--limit` | int | `50` | maximum number of jobs (0 = all) |
| `--state` | string |  | only jobs in this state (queued, running, succeeded, failed, canceled) |

**Examples**

```sh
fileparcel jobs list
fileparcel jobs list --kind backup.create --limit 5
fileparcel jobs list --state running --json
```

#### fileparcel jobs run

Start a background job now.

Start a background job of the given kind now, for example an upkeep task
outside its schedule. Kinds:
```text
backup.create
backup.verify
backup.prune
maintenance.sessions
maintenance.uploads
maintenance.trash
maintenance.blob_gc
maintenance.audit_prune
maintenance.db_optimize
maintenance.versions
certs.renew_check
```

--params passes a JSON object to the job. The command returns at once unless
--wait, which follows the job to the end.

**Usage**

```
fileparcel jobs run <kind> [flags]
```

**Flags**

| Flag | Type | Default | Description |
|---|---|---|---|
| `--no-wait` |  |  | return at once (default) |
| `--params` | string |  | job parameters as a JSON object |
| `--wait` |  |  | wait until the job finishes |

**Examples**

```sh
fileparcel jobs run maintenance.trash --wait
fileparcel jobs run maintenance.db_optimize
fileparcel jobs run backup.create --params '{"scope":"metadata"}' --wait
```

#### fileparcel jobs show

Show a job (and wait for it).

Show the details of a job with its parameters and result; --wait follows it
until it finishes (exit status 1 if it fails).

**Usage**

```
fileparcel jobs show <job> [flags]
```

**Flags**

| Flag | Type | Default | Description |
|---|---|---|---|
| `--wait` |  |  | wait until the job finishes |

**Examples**

```sh
fileparcel jobs show job_01j9zq3x4k6m8p0r2t4v6x8z0b
fileparcel jobs show job_01j9zq3x4k6m8p0r2t4v6x8z0b --wait
```

### fileparcel keys

Lock, unlock and rotate the encryption keys.

All file contents and secrets are encrypted with keys derived from the master
key (keys/master.key). In "plain" mode the master key file unlocks the server
automatically; in "sealed" mode it is encrypted with a passphrase and the
server starts locked until "fileparcel keys unlock" (or the /unlock page).

Passphrases are read without echo from the terminal, or from
--passphrase-stdin / --passphrase-file for scripts. Keep the recovery key
("keys recovery-key") offline: it unlocks the server if the passphrase is
lost.

**Usage**

```
fileparcel keys [flags]
fileparcel keys <command>
```

**Subcommands**

| Command | Description |
|---|---|
| [`lock`](#fileparcel-keys-lock) | Lock a sealed server now (wipes the key from memory) |
| [`passphrase`](#fileparcel-keys-passphrase) | Change the master key passphrase |
| [`recovery-key`](#fileparcel-keys-recovery-key) | Create a new recovery key (the old one stops working) |
| [`rotate`](#fileparcel-keys-rotate) | Replace encryption keys |
| [`seal`](#fileparcel-keys-seal) | Protect the master key with a passphrase |
| [`status`](#fileparcel-keys-status) | Show whether the keys are locked and which keys exist |
| [`unlock`](#fileparcel-keys-unlock) | Unlock a sealed server with its passphrase or recovery key |
| [`unseal`](#fileparcel-keys-unseal) | Remove the passphrase from the master key |
| [`verify`](#fileparcel-keys-verify) | Check the keyring for problems |

**Examples**

```sh
fileparcel keys status
fileparcel keys unlock
fileparcel keys seal
fileparcel keys rotate --kek
```

#### fileparcel keys lock

Lock a sealed server now (wipes the key from memory).

Wipe the master key from the running server's memory (sealed mode only).
The web app and the remote API stop working until "fileparcel keys unlock",
and no encrypted content (file data, shares, encrypted settings) can be read.
The local admin socket keeps working on everything else, so the server can
still be inspected, administered and unlocked.

It asks before doing it; -y skips the question.
On the server this always works; remotely it needs an elevated admin token
(see "fileparcel help connect").

**Usage**

```
fileparcel keys lock [flags]
```

**Examples**

```sh
fileparcel keys lock
fileparcel keys lock -y
```

#### fileparcel keys passphrase

Change the master key passphrase.

Change the passphrase of a sealed master key. Both passphrases are asked for
without echo, or read from --current-file/--new-file, or from standard input
with --passphrase-stdin (first line: current, second line: new).

On the server this always works; remotely it needs an elevated admin token
(see "fileparcel help connect").

**Usage**

```
fileparcel keys passphrase [flags]
```

**Aliases:** `change-passphrase`

**Flags**

| Flag | Type | Default | Description |
|---|---|---|---|
| `--current-file` | string |  | read the current passphrase from a file |
| `--new-file` | string |  | read the new passphrase from a file |
| `--passphrase-stdin` |  |  | read the current and the new passphrase (two lines) from stdin |

**Examples**

```sh
fileparcel keys passphrase
fileparcel keys passphrase --current-file /secure/old --new-file /secure/new
printf '%s\n%s\n' "$OLD" "$NEW" | fileparcel keys passphrase --passphrase-stdin
```

#### fileparcel keys recovery-key

Create a new recovery key (the old one stops working).

Creates a NEW recovery key (FPRK-…) and prints it once; the previous recovery
key stops working. The recovery key unlocks the master key without the
passphrase: store it offline.

It asks before doing it; -y skips the question.
On the server this always works; remotely it needs an elevated admin token
(see "fileparcel help connect").

**Usage**

```
fileparcel keys recovery-key [flags]
```

**Examples**

```sh
fileparcel keys recovery-key
fileparcel keys recovery-key -y > /secure/fileparcel-recovery.txt
```

#### fileparcel keys rotate

Replace encryption keys.

Rotate keys:

```text
--kek     new key-encryption key; re-wraps every file key (purpose blob) or
          re-seals every encrypted setting/secret (purpose field). Fast.
--master  new master key; re-wraps the keyring (the passphrase stays).
--data    re-encrypt every file with fresh keys (slow; a background job).
```

A master rotation keeps the passphrase and the recovery key, and an old copy
of the key file still yields both. If the key file may have leaked, also run
"fileparcel keys passphrase" (sealed) or "fileparcel keys seal" (plain) and
"fileparcel keys recovery-key"; if the database may have leaked too, rotate
both key-encryption keys and use --data.

Retired keys nothing uses any more are removed 15 minutes after they were
retired, so "fileparcel keys status" still lists them right after a rotation.
Long operations run as background jobs; the command waits for them unless
--no-wait.

On the server this always works; remotely it needs an elevated admin token
(see "fileparcel help connect").

**Usage**

```
fileparcel keys rotate (--kek [--purpose blob|field] | --master | --data) [flags]
```

**Flags**

| Flag | Type | Default | Description |
|---|---|---|---|
| `--data` |  |  | re-encrypt all file data with new keys (background job) |
| `--kek` |  |  | rotate a key-encryption key |
| `--master` |  |  | rotate the master key |
| `--no-wait` |  |  | return at once |
| `--purpose` | string | `blob` | with --kek: blob (file keys) or field (settings and secrets) |
| `--wait` |  |  | wait until the background jobs finish (default) |

**Examples**

```sh
fileparcel keys rotate --kek
fileparcel keys rotate --kek --purpose field
fileparcel keys rotate --master
fileparcel keys rotate --data --no-wait
```

#### fileparcel keys seal

Protect the master key with a passphrase.

Switch from plain to sealed mode: the master key file is encrypted with a
passphrase (argon2id). From then on the server starts locked and needs
"fileparcel keys unlock" after every restart (also after reboots).

It asks before doing it; -y skips the question.
On the server this always works; remotely it needs an elevated admin token
(see "fileparcel help connect").

**Usage**

```
fileparcel keys seal [flags]
```

**Flags**

| Flag | Type | Default | Description |
|---|---|---|---|
| `--passphrase-file` | string |  | read the new passphrase from the first line of a file |
| `--passphrase-stdin` |  |  | read the new passphrase from the first line of stdin |

**Examples**

```sh
fileparcel keys seal
fileparcel keys seal --passphrase-file /secure/new-pass -y
```

#### fileparcel keys status

Show whether the keys are locked and which keys exist.

Show whether the keys are locked, the master key mode (plain or sealed), the
cipher for new files and the key-encryption keys with their use.

**Usage**

```
fileparcel keys status [flags]
```

**Examples**

```sh
fileparcel keys status
fileparcel keys status --json
```

#### fileparcel keys unlock

Unlock a sealed server with its passphrase or recovery key.

Unlock the running server's master key with the passphrase or the recovery
key (FPRK-…). Needed after every start in sealed mode; the /unlock page of the
web app does the same.

**Usage**

```
fileparcel keys unlock [flags]
```

**Flags**

| Flag | Type | Default | Description |
|---|---|---|---|
| `--passphrase-file` | string |  | read the passphrase or recovery key from the first line of a file |
| `--passphrase-stdin` |  |  | read the passphrase or recovery key from the first line of stdin |

**Examples**

```sh
fileparcel keys unlock
fileparcel keys unlock --passphrase-file /run/secrets/fileparcel
printf '%s\n' "$PASS" | fileparcel keys unlock --passphrase-stdin
```

#### fileparcel keys unseal

Remove the passphrase from the master key.

Switch from sealed to plain mode: the master key is stored unencrypted in
keys/master.key and the server unlocks itself at start. Only do this when the
disk itself is encrypted. It needs the current passphrase.

It asks before doing it; -y skips the question.
On the server this always works; remotely it needs an elevated admin token
(see "fileparcel help connect").

**Usage**

```
fileparcel keys unseal [flags]
```

**Flags**

| Flag | Type | Default | Description |
|---|---|---|---|
| `--passphrase-file` | string |  | read the current passphrase from the first line of a file |
| `--passphrase-stdin` |  |  | read the current passphrase from the first line of stdin |

**Examples**

```sh
fileparcel keys unseal
fileparcel keys unseal --passphrase-file /secure/pass
```

#### fileparcel keys verify

Check the keyring for problems.

Check the master key state and the keyring: exactly one active key per
purpose, no retired key still in use (an interrupted rotation: run
"fileparcel keys rotate --kek" again) and, in sealed mode, a recovery key.
Exits with status 1 when a check fails.

**Usage**

```
fileparcel keys verify [flags]
```

**Examples**

```sh
fileparcel keys verify
fileparcel keys verify --json
```

### fileparcel logs

Show the server log.

Print the last lines of \<HOME>/logs/fileparcel.log; -f keeps following it
(across log rotation) until interrupted. With --server the lines come from GET
/api/v1/admin/system/logs (no -f). When file logging is disabled
(log.file = false) use the service manager's log instead: journalctl --user -u
fileparcel for a user service, sudo journalctl -u fileparcel for a system
service, \<HOME>/logs/launchd.err.log on macOS.

With --json the tail is one object; with -f every line is printed as its own
JSON object as it arrives.

**Usage**

```
fileparcel logs [flags]
```

**Flags**

| Flag | Type | Default | Description |
|---|---|---|---|
| `-f, --follow` |  |  | keep printing new lines |
| `-n, --lines` | int | `200` | number of lines to show |

**Examples**

```sh
fileparcel logs
fileparcel logs -n 50 -f
fileparcel logs -f --json
```

### fileparcel maintenance

Keep users out while you work on the server.

Maintenance mode keeps users out while you work on the server: the web app
shows a maintenance notice and requests for files, shares and uploads are
answered with "503 unavailable". Administrators and the admin socket (this
command on the server) keep working, and so do signing in and every user's
own account settings (profile, password, two-factor, sessions, tokens);
invitations cannot be accepted until it is off again.

The state is the setting maintenance.enabled; --message sets the notice.
"fileparcel maintenance" alone shows the current state.

**Usage**

```
fileparcel maintenance [flags]
fileparcel maintenance <command>
```

**Subcommands**

| Command | Description |
|---|---|
| [`off`](#fileparcel-maintenance-off) | Let users back in |
| [`on`](#fileparcel-maintenance-on) | Keep users out with a maintenance notice |
| [`status`](#fileparcel-maintenance-status) | Show whether maintenance mode is on |

**Flags**

| Flag | Type | Default | Description |
|---|---|---|---|
| `--message` | string |  | notice shown to users while maintenance mode is on (with "on" only) |

**Examples**

```sh
fileparcel maintenance
fileparcel maintenance on --message "Upgrading, back at 14:00"
fileparcel maintenance off
```

#### fileparcel maintenance off

Let users back in.

Turn maintenance mode off: the web app, shares and uploads work again.

**Usage**

```
fileparcel maintenance off [flags]
```

**Aliases:** `disable`

**Inherited flags**

| Flag | Type | Default | Description |
|---|---|---|---|
| `--message` | string |  | notice shown to users while maintenance mode is on (with "on" only) |

**Examples**

```sh
fileparcel maintenance off
fileparcel maintenance off --json
```

#### fileparcel maintenance on

Keep users out with a maintenance notice.

Turn maintenance mode on. --message sets the notice users see; without it the
last notice (or a general one) is shown. "fileparcel maintenance off" lets
users back in.

**Usage**

```
fileparcel maintenance on [flags]
```

**Aliases:** `enable`

**Inherited flags**

| Flag | Type | Default | Description |
|---|---|---|---|
| `--message` | string |  | notice shown to users while maintenance mode is on (with "on" only) |

**Examples**

```sh
fileparcel maintenance on
fileparcel maintenance on --message "Back at 14:00"
```

#### fileparcel maintenance status

Show whether maintenance mode is on.

Show whether maintenance mode is on and the notice users see.

**Usage**

```
fileparcel maintenance status [flags]
```

**Inherited flags**

| Flag | Type | Default | Description |
|---|---|---|---|
| `--message` | string |  | notice shown to users while maintenance mode is on (with "on" only) |

**Examples**

```sh
fileparcel maintenance status
fileparcel maintenance status --json
```

### fileparcel network

Show addresses and control who may connect.

Shows how the server can be reached (addresses per network, with QR codes for
phones), the VPNs on this machine, whether Tailscale Funnel publishes it on
the internet, and the access policy that decides which addresses may connect
at all:

```text
private    this machine, home networks and VPNs (private address ranges)
allowlist  this machine plus the networks you allow (the default)
any        every address (only behind a firewall, with 2FA for everyone)
```

The deny list always wins; this machine (loopback) is always allowed. A change
that would lock out your own connection is refused unless --force.
"fileparcel network" alone shows everything at a glance.

**Usage**

```
fileparcel network [flags]
fileparcel network <command>
```

**Aliases:** `net`

**Subcommands**

| Command | Description |
|---|---|
| [`allow`](#fileparcel-network-allow) | Manage the networks allowed to connect |
| [`deny`](#fileparcel-network-deny) | Manage the networks that may never connect |
| [`funnel`](#fileparcel-network-funnel) | Publish FileParcel on the internet with Tailscale Funnel |
| [`interfaces`](#fileparcel-network-interfaces) | List network interfaces (LAN, Wi-Fi, VPNs) |
| [`mdns`](#fileparcel-network-mdns) | Manage the .local name (mDNS / Bonjour) |
| [`mode`](#fileparcel-network-mode) | Choose who may connect |
| [`policy`](#fileparcel-network-policy) | Show who may connect (mode, allow and deny lists) |
| [`status`](#fileparcel-network-status) | Show addresses, policy, VPNs and Funnel at a glance |
| [`tailscale-serve`](#fileparcel-network-tailscale-serve) | Tailnet HTTPS address without a port (Tailscale Serve) |
| [`urls`](#fileparcel-network-urls) | List the addresses the server can be reached at |
| [`vpn`](#fileparcel-network-vpn) | Show the VPNs on this machine and let their devices connect |

**Examples**

```sh
fileparcel network
fileparcel network urls --qr
fileparcel network allow add 192.168.1.0/24
fileparcel network funnel enable
```

#### fileparcel network allow

Manage the networks allowed to connect.

The addresses and address ranges that may connect in allowlist mode, and in
private mode in addition to the private ranges (network.allow_cidrs). This
machine (loopback) is always allowed.

**Usage**

```
fileparcel network allow [flags]
fileparcel network allow <command>
```

**Subcommands**

| Command | Description |
|---|---|
| [`add`](#fileparcel-network-allow-add) | Allow networks or addresses to connect |
| [`list`](#fileparcel-network-allow-list) | Show the allowed networks |
| [`remove`](#fileparcel-network-allow-remove) | Stop allowing networks or addresses |

**Examples**

```sh
fileparcel network allow list
fileparcel network allow add 192.168.1.0/24
fileparcel network allow remove 192.168.1.0/24
```

##### fileparcel network allow add

Allow networks or addresses to connect.

Add addresses or address ranges (192.168.1.0/24) to the allow list.
A change that would lock out your own connection is refused unless --force.

On the server this always works; remotely it needs an elevated admin token
(see "fileparcel help connect").

**Usage**

```
fileparcel network allow add <cidr|ip>... [flags]
```

**Flags**

| Flag | Type | Default | Description |
|---|---|---|---|
| `--force` |  |  | apply even if it locks out the client making the change |

**Examples**

```sh
fileparcel network allow add 192.168.1.0/24
fileparcel network allow add 10.8.0.0/24 192.168.1.20
```

##### fileparcel network allow list

Show the allowed networks.

Show the addresses and address ranges of the allow list (network.allow_cidrs).

**Usage**

```
fileparcel network allow list [flags]
```

**Aliases:** `ls`

**Examples**

```sh
fileparcel network allow list
fileparcel network allow list --json
```

##### fileparcel network allow remove

Stop allowing networks or addresses.

Remove addresses or address ranges (192.168.1.0/24) from the allow list.
A change that would lock out your own connection is refused unless --force.

On the server this always works; remotely it needs an elevated admin token
(see "fileparcel help connect").

**Usage**

```
fileparcel network allow remove <cidr|ip>... [flags]
```

**Aliases:** `rm`

**Flags**

| Flag | Type | Default | Description |
|---|---|---|---|
| `--force` |  |  | apply even if it locks out the client making the change |

**Examples**

```sh
fileparcel network allow remove 192.168.1.0/24
fileparcel network allow remove 10.8.0.0/24 --force
```

#### fileparcel network deny

Manage the networks that may never connect.

The addresses and address ranges that may never connect, in every mode
(network.deny_cidrs); the deny list wins over the allow list.

**Usage**

```
fileparcel network deny [flags]
fileparcel network deny <command>
```

**Subcommands**

| Command | Description |
|---|---|
| [`add`](#fileparcel-network-deny-add) | Block networks or addresses |
| [`list`](#fileparcel-network-deny-list) | Show the blocked networks |
| [`remove`](#fileparcel-network-deny-remove) | Unblock networks or addresses |

**Examples**

```sh
fileparcel network deny list
fileparcel network deny add 192.168.1.66
fileparcel network deny remove 192.168.1.66
```

##### fileparcel network deny add

Block networks or addresses.

Add addresses or address ranges (192.168.1.0/24) to the deny list.
A change that would lock out your own connection is refused unless --force.

On the server this always works; remotely it needs an elevated admin token
(see "fileparcel help connect").

**Usage**

```
fileparcel network deny add <cidr|ip>... [flags]
```

**Flags**

| Flag | Type | Default | Description |
|---|---|---|---|
| `--force` |  |  | apply even if it locks out the client making the change |

**Examples**

```sh
fileparcel network deny add 192.168.1.66
fileparcel network deny add 203.0.113.0/24 198.51.100.7
```

##### fileparcel network deny list

Show the blocked networks.

Show the addresses and address ranges of the deny list (network.deny_cidrs).

**Usage**

```
fileparcel network deny list [flags]
```

**Aliases:** `ls`

**Examples**

```sh
fileparcel network deny list
fileparcel network deny list --json
```

##### fileparcel network deny remove

Unblock networks or addresses.

Remove addresses or address ranges (192.168.1.0/24) from the deny list.
A change that would lock out your own connection is refused unless --force.

On the server this always works; remotely it needs an elevated admin token
(see "fileparcel help connect").

**Usage**

```
fileparcel network deny remove <cidr|ip>... [flags]
```

**Aliases:** `rm`

**Flags**

| Flag | Type | Default | Description |
|---|---|---|---|
| `--force` |  |  | apply even if it locks out the client making the change |

**Examples**

```sh
fileparcel network deny remove 192.168.1.66
fileparcel network deny remove 203.0.113.0/24
```

#### fileparcel network funnel

Publish FileParcel on the internet with Tailscale Funnel.

Tailscale Funnel makes FileParcel reachable from the whole internet at
https://\<machine>.\<tailnet>.ts.net, without opening ports on your router.
Tailscale handles HTTPS and passes the requests to FileParcel over a private
local connection.

Two modes:
```text
shares  only share links and file requests work from the internet;
        everything else answers "not found" (the default)
app     the whole web app; anyone can reach the sign-in page, two-factor
        sign-in is required over Funnel and admin pages stay blocked
        unless --allow-admin
```

It needs Tailscale signed in to tailscale.com (Headscale has no Funnel),
HTTPS certificates and Funnel allowed for this machine in the tailnet
policy; "fileparcel network funnel status" checks each of these and says how
to fix them. Public port: 443 (the first time), 8443 or 10000, never the port
FileParcel itself uses; a later "enable" keeps the port unless --port is
given. The public name can take up to 10 minutes to work.

It asks before doing it; -y skips the question.
On the server this always works; remotely it needs an elevated admin token
(see "fileparcel help connect").

**Usage**

```
fileparcel network funnel [flags]
fileparcel network funnel <command>
```

**Subcommands**

| Command | Description |
|---|---|
| [`disable`](#fileparcel-network-funnel-disable) | Stop publishing FileParcel on the internet |
| [`enable`](#fileparcel-network-funnel-enable) | Publish share links (or the whole app) on the internet |
| [`reapply`](#fileparcel-network-funnel-reapply) | Write FileParcel's Funnel and Serve entries to Tailscale again |
| [`status`](#fileparcel-network-funnel-status) | Show whether Funnel is on, its address and what is missing |

**Examples**

```sh
fileparcel network funnel
fileparcel network funnel enable
fileparcel network funnel enable --mode app --port 8443
fileparcel network funnel disable
```

##### fileparcel network funnel disable

Stop publishing FileParcel on the internet.

Turn Tailscale Funnel off: FileParcel's Funnel entry is removed from Tailscale
and nothing is reachable from the internet through it any more. Share links
keep working on your other addresses.

On the server this always works; remotely it needs an elevated admin token
(see "fileparcel help connect").

**Usage**

```
fileparcel network funnel disable [flags]
```

**Examples**

```sh
fileparcel network funnel disable
fileparcel network funnel disable --json
```

##### fileparcel network funnel enable

Publish share links (or the whole app) on the internet.

Turn Tailscale Funnel on, or change its mode or port. --mode shares (the
default when Funnel is off) publishes only share links and file requests;
--mode app the whole web app with its sign-in page. In app mode two-factor
sign-in is required over Funnel (--no-require-2fa lifts that) and admin pages
stay blocked (--allow-admin opens them); only an owner or administrator may
weaken these. Both are kept while Funnel is off or shares only, and come back
with --mode app. Whatever becomes reachable from the internet is asked about
first. The port stays as it is unless --port. With the server stopped the
change is saved and published when it starts.

It asks before doing it; -y skips the question.
On the server this always works; remotely it needs an elevated admin token
(see "fileparcel help connect").

**Usage**

```
fileparcel network funnel enable [flags]
```

**Flags**

| Flag | Type | Default | Description |
|---|---|---|---|
| `--allow-admin` |  |  | app mode: let admin pages be reached over Funnel (needs two-factor sign-in) |
| `--mode` | string |  | shares (share links and file requests only) or app (the whole web app); default: shares when Funnel is off, else the current mode |
| `--no-allow-admin` |  |  | app mode: block admin pages over Funnel (the default) |
| `--no-require-2fa` |  |  | app mode: let accounts without two-factor sign-in sign in over Funnel |
| `--port` | int |  | public port: 443, 8443 or 10000 (default: the current port, 443 the first time) |
| `--require-2fa` |  |  | app mode: only accounts with two-factor sign-in may sign in over Funnel (the default) |

**Examples**

```sh
fileparcel network funnel enable
fileparcel network funnel enable --mode app -y
```

##### fileparcel network funnel reapply

Write FileParcel's Funnel and Serve entries to Tailscale again.

Write FileParcel's Funnel and Serve entries to Tailscale again, for example
after "needs attention" (the entry was removed or changed in Tailscale), and
check them anew.

On the server this always works; remotely it needs an elevated admin token
(see "fileparcel help connect").

**Usage**

```
fileparcel network funnel reapply [flags]
```

**Examples**

```sh
fileparcel network funnel reapply
fileparcel network funnel reapply --json
```

##### fileparcel network funnel status

Show whether Funnel is on, its address and what is missing.

Show the state of Tailscale Funnel: whether it is on and in which mode, the
public address and port, how Tailscale reaches FileParcel, the last request
from the internet, and every check it needs (Tailscale running, HTTPS
certificates, Funnel allowed for this device, …) with how to fix a failing
one. --refresh reads Tailscale again instead of using what the server read
up to 30 seconds ago.

**Usage**

```
fileparcel network funnel status [flags]
```

**Flags**

| Flag | Type | Default | Description |
|---|---|---|---|
| `--refresh` |  |  | read the state of Tailscale again now |

**Examples**

```sh
fileparcel network funnel status
fileparcel network funnel status --refresh --json
```

#### fileparcel network interfaces

List network interfaces (LAN, Wi-Fi, VPNs).

List the network interfaces of this machine with their kind (LAN, Wi-Fi,
Tailscale, WireGuard, ZeroTier, …), their role, state and addresses. The role
says what FileParcel uses an interface for: mesh or unknown (a VPN whose
devices can connect), local (LAN, Wi-Fi), egress or access (outgoing only),
overlay (a public overlay) or none; "fileparcel network vpn role" corrects it.

**Usage**

```
fileparcel network interfaces [flags]
```

**Aliases:** `if`, `ifaces`

**Examples**

```sh
fileparcel network interfaces
fileparcel network interfaces --json
```

#### fileparcel network mdns

Manage the .local name (mDNS / Bonjour).

FileParcel announces \<name>.local and an _https._tcp service on the local
network through Avahi (Linux), dns-sd (macOS) or a built-in responder, so
phones and computers find it by name. The name does not reach through VPNs
such as Tailscale or WireGuard; use MagicDNS or the IP address there.

**Usage**

```
fileparcel network mdns [flags]
fileparcel network mdns <command>
```

**Aliases:** `bonjour`

**Subcommands**

| Command | Description |
|---|---|
| [`disable`](#fileparcel-network-mdns-disable) | Stop publishing the .local name |
| [`enable`](#fileparcel-network-mdns-enable) | Publish the .local name |
| [`mode`](#fileparcel-network-mdns-mode) | Choose how the .local name is published |
| [`name`](#fileparcel-network-mdns-name) | Change the .local name |
| [`republish`](#fileparcel-network-mdns-republish) | Announce the name again |
| [`status`](#fileparcel-network-mdns-status) | Show how the .local name is published |

**Examples**

```sh
fileparcel network mdns status
fileparcel network mdns name files
fileparcel network mdns mode builtin
fileparcel network mdns disable
```

##### fileparcel network mdns disable

Stop publishing the .local name.

Stop publishing the .local name (mdns.mode=off). Devices then reach the server
by IP address or another name.

On the server this always works; remotely it needs an elevated admin token
(see "fileparcel help connect").

**Usage**

```
fileparcel network mdns disable [flags]
```

**Examples**

```sh
fileparcel network mdns disable
fileparcel network mdns disable --json
```

##### fileparcel network mdns enable

Publish the .local name.

Publish the .local name with the best way this machine offers (mdns.mode=auto;
"fileparcel network mdns mode" picks one).

On the server this always works; remotely it needs an elevated admin token
(see "fileparcel help connect").

**Usage**

```
fileparcel network mdns enable [flags]
```

**Examples**

```sh
fileparcel network mdns enable
fileparcel network mdns enable --json
```

##### fileparcel network mdns mode

Choose how the .local name is published.

Choose how the .local name is published: auto (Avahi on Linux when available,
dns-sd on macOS, else built-in), avahi, dnssd, builtin (own responder on UDP
5353) or off.

On the server this always works; remotely it needs an elevated admin token
(see "fileparcel help connect").

**Usage**

```
fileparcel network mdns mode <auto|avahi|dnssd|builtin|off> [flags]
```

**Examples**

```sh
fileparcel network mdns mode auto
fileparcel network mdns mode builtin
```

##### fileparcel network mdns name

Change the .local name.

Set the label published as \<label>.local (mdns.name; "" = server.name). The
server certificate is reissued for the new name. Changing it breaks passkeys
that use the .local name as their relying party (unless auth.webauthn_rp_id
pins it); while accounts have no second factor other than a passkey, the
change is refused unless --force.

On the server this always works; remotely it needs an elevated admin token
(see "fileparcel help connect").

**Usage**

```
fileparcel network mdns name <label> [flags]
```

**Flags**

| Flag | Type | Default | Description |
|---|---|---|---|
| `--force` |  |  | rename even though accounts that rely on a passkey alone lose it |

**Examples**

```sh
fileparcel network mdns name files
fileparcel network mdns name ""
```

##### fileparcel network mdns republish

Announce the name again.

Withdraw and announce the .local name again, for example after network
changes or a name collision. Needs the running server.

**Usage**

```
fileparcel network mdns republish [flags]
```

**Examples**

```sh
fileparcel network mdns republish
fileparcel network mdns republish --json
```

##### fileparcel network mdns status

Show how the .local name is published.

Show the configured and effective backend, the published name, the state and
the interfaces. The responder re-publishes asynchronously, so right after
"network mdns mode"/"name"/"disable" the running values still lag the
settings; both are shown until they agree. A name already taken by another
device on the LAN is published as \<name>-2.local instead; the configured name
is then shown next to it.

**Usage**

```
fileparcel network mdns status [flags]
```

**Examples**

```sh
fileparcel network mdns status
fileparcel network mdns status --json
```

#### fileparcel network mode

Choose who may connect.

Choose who may connect (network.access_mode): private (this machine, home
networks and VPNs), allowlist (this machine plus the allow list) or any. "any"
lets every address that can reach the server connect: use it only behind a
firewall or with a public certificate and two-factor sign-in for everyone. A
change that would lock out your own connection is refused unless --force.

On the server this always works; remotely it needs an elevated admin token
(see "fileparcel help connect").

**Usage**

```
fileparcel network mode <private|allowlist|any> [flags]
```

**Flags**

| Flag | Type | Default | Description |
|---|---|---|---|
| `--force` |  |  | apply even if it locks out the client making the change |

**Examples**

```sh
fileparcel network mode allowlist
fileparcel network mode private
fileparcel network mode any --force
```

#### fileparcel network policy

Show who may connect (mode, allow and deny lists).

Show the access mode, the allow and deny lists and the address you connect from.

**Usage**

```
fileparcel network policy [flags]
```

**Examples**

```sh
fileparcel network policy
fileparcel network policy --json
```

#### fileparcel network status

Show addresses, policy, VPNs and Funnel at a glance.

Show how the server can be reached and who may connect: the addresses, the
access policy with your own address, remote access (Tailscale Funnel and
Serve, the VPNs on this machine), the Tailscale state and ways around the
access policy that need attention. "fileparcel network" alone prints the
same. --json prints the whole overview.

**Usage**

```
fileparcel network status [flags]
```

**Aliases:** `show`

**Examples**

```sh
fileparcel network status
fileparcel network status --json
```

#### fileparcel network tailscale-serve

Tailnet HTTPS address without a port (Tailscale Serve).

Tailscale Serve gives the devices on your tailnet the address
https://\<machine>.\<tailnet>.ts.net/ (no port number, a certificate every
browser trusts) for the whole web app. Only tailnet devices can use it, and
the access policy still applies. It cannot share port 443 with Funnel: use
Funnel on 8443 or 10000 when both are on.

On the server this always works; remotely it needs an elevated admin token
(see "fileparcel help connect").

**Usage**

```
fileparcel network tailscale-serve [flags]
fileparcel network tailscale-serve <command>
```

**Aliases:** `ts-serve`

**Subcommands**

| Command | Description |
|---|---|
| [`disable`](#fileparcel-network-tailscale-serve-disable) | Remove the tailnet address without a port |
| [`enable`](#fileparcel-network-tailscale-serve-enable) | Give the tailnet an HTTPS address without a port |
| [`reapply`](#fileparcel-network-tailscale-serve-reapply) | Write FileParcel's Funnel and Serve entries to Tailscale again |
| [`status`](#fileparcel-network-tailscale-serve-status) | Show whether Serve is on, its address and what is missing |

**Examples**

```sh
fileparcel network tailscale-serve
fileparcel network tailscale-serve enable
fileparcel network tailscale-serve disable
```

##### fileparcel network tailscale-serve disable

Remove the tailnet address without a port.

Turn Tailscale Serve off: FileParcel's Serve entry is removed from Tailscale.
The tailnet devices keep the other addresses ("fileparcel network urls").

On the server this always works; remotely it needs an elevated admin token
(see "fileparcel help connect").

**Usage**

```
fileparcel network tailscale-serve disable [flags]
```

**Examples**

```sh
fileparcel network tailscale-serve disable
fileparcel network tailscale-serve disable --json
```

##### fileparcel network tailscale-serve enable

Give the tailnet an HTTPS address without a port.

Turn Tailscale Serve on: the devices on your tailnet reach FileParcel at
https://\<machine>.\<tailnet>.ts.net/ (or :PORT with --port). It asks nothing
first: only tailnet devices can use it. With the server stopped the change is
saved and published when it starts.

On the server this always works; remotely it needs an elevated admin token
(see "fileparcel help connect").

**Usage**

```
fileparcel network tailscale-serve enable [flags]
```

**Flags**

| Flag | Type | Default | Description |
|---|---|---|---|
| `--port` | int |  | tailnet HTTPS port, 1-65535 (default: the current port, 443 the first time) |

**Examples**

```sh
fileparcel network tailscale-serve enable
fileparcel network tailscale-serve enable --port 8443
```

##### fileparcel network tailscale-serve reapply

Write FileParcel's Funnel and Serve entries to Tailscale again.

Write FileParcel's Funnel and Serve entries to Tailscale again, for example
after "needs attention" (the entry was removed or changed in Tailscale), and
check them anew.

On the server this always works; remotely it needs an elevated admin token
(see "fileparcel help connect").

**Usage**

```
fileparcel network tailscale-serve reapply [flags]
```

**Examples**

```sh
fileparcel network tailscale-serve reapply
fileparcel network tailscale-serve reapply --json
```

##### fileparcel network tailscale-serve status

Show whether Serve is on, its address and what is missing.

Show the state of Tailscale Serve: whether it is on, the tailnet address and
port, how Tailscale reaches FileParcel and every check it needs, with how to
fix a failing one. --refresh reads Tailscale again instead of using what the
server read up to 30 seconds ago.

**Usage**

```
fileparcel network tailscale-serve status [flags]
```

**Flags**

| Flag | Type | Default | Description |
|---|---|---|---|
| `--refresh` |  |  | read the state of Tailscale again now |

**Examples**

```sh
fileparcel network tailscale-serve status
fileparcel network tailscale-serve status --refresh --json
```

#### fileparcel network urls

List the addresses the server can be reached at.

List the HTTPS addresses of the server: one per network address, the .local
name, the Tailscale MagicDNS name and configured public names. --qr adds a QR
code per address for phones.

**Usage**

```
fileparcel network urls [flags]
```

**Flags**

| Flag | Type | Default | Description |
|---|---|---|---|
| `--qr` |  |  | print a QR code for each URL |
| `--recommended` |  |  | only the recommended URLs |

**Examples**

```sh
fileparcel network urls
fileparcel network urls --recommended --qr
```

#### fileparcel network vpn

Show the VPNs on this machine and let their devices connect.

FileParcel recognises the VPNs on this machine and whether other devices can
reach this server through them:

```text
mesh VPNs (their devices can connect): Tailscale and Headscale, ZeroTier,
  NetBird, Nebula, Netmaker, innernet, Husarnet, NordVPN Meshnet, and
  WireGuard, OpenVPN, IPsec, tinc or SoftEther tunnels
outgoing-only VPNs (nobody comes in through them): Mullvad, NordVPN,
  Proton VPN, Cloudflare WARP, Twingate, Firezone, and any tunnel that
  carries this machine's internet traffic
public overlays (anyone on them could connect): Yggdrasil
```

"list" shows each one with its interfaces, address ranges and whether the
access policy lets its devices in; "allow" adds a VPN's ranges to the allow
list and "remove" takes them out again.

**Usage**

```
fileparcel network vpn [flags]
fileparcel network vpn <command>
```

**Subcommands**

| Command | Description |
|---|---|
| [`allow`](#fileparcel-network-vpn-allow) | Let the devices of a VPN connect (adds its ranges) |
| [`list`](#fileparcel-network-vpn-list) | List the VPNs found and whether they may connect |
| [`remove`](#fileparcel-network-vpn-remove) | Stop allowing a VPN's networks |
| [`role`](#fileparcel-network-vpn-role) | Correct how FileParcel treats a network interface |

**Examples**

```sh
fileparcel network vpn
fileparcel network vpn allow tailscale
fileparcel network vpn remove wg0
```

##### fileparcel network vpn allow

Let the devices of a VPN connect (adds its ranges).

Add the address ranges of a VPN to the allow list (network.allow_cidrs), so its
devices may connect in allowlist mode. Name the VPN by its id or an interface
("network vpn list"). Outgoing-only VPNs are refused: nobody comes in through
them. A public overlay (Yggdrasil) asks first, since anyone on it could then
connect. A change that would lock out your own connection is refused unless
--force.

On the server this always works; remotely it needs an elevated admin token
(see "fileparcel help connect").

**Usage**

```
fileparcel network vpn allow <vpn|interface> [flags]
```

**Flags**

| Flag | Type | Default | Description |
|---|---|---|---|
| `--force` |  |  | apply even if it locks out the client making the change |

**Examples**

```sh
fileparcel network vpn allow tailscale
fileparcel network vpn allow wg0
```

##### fileparcel network vpn list

List the VPNs found and whether they may connect.

List the VPNs found on this machine: their interfaces, the address ranges
"network vpn allow" adds, their role (mesh: its devices can connect; egress or
access: outgoing only; overlay: public; "override" when set with "network vpn
role") and whether the access policy lets their devices in (yes, partly, no).

**Usage**

```
fileparcel network vpn list [flags]
```

**Aliases:** `ls`

**Examples**

```sh
fileparcel network vpn list
fileparcel network vpn list --json
```

##### fileparcel network vpn remove

Stop allowing a VPN's networks.

Take the address ranges of a VPN out of the allow list again. Its devices may
then connect only when other entries or the access mode let them in. A change
that would lock out your own connection is refused unless --force.

On the server this always works; remotely it needs an elevated admin token
(see "fileparcel help connect").

**Usage**

```
fileparcel network vpn remove <vpn|interface> [flags]
```

**Aliases:** `rm`

**Flags**

| Flag | Type | Default | Description |
|---|---|---|---|
| `--force` |  |  | apply even if it locks out the client making the change |

**Examples**

```sh
fileparcel network vpn remove zerotier
fileparcel network vpn remove wg0 --force
```

##### fileparcel network vpn role

Correct how FileParcel treats a network interface.

Correct how FileParcel treats a network interface when the automatic
detection is wrong (network.iface_roles): mesh (devices of that VPN can
connect), unknown (a tunnel treated like mesh), access or egress (outgoing
only: nobody comes in through it), overlay (a public overlay), local (LAN or
Wi-Fi; also gets the .local name) or none (not used). auto removes the
correction. The role decides which addresses are offered, the names in the
certificate and the VPN list.

On the server this always works; remotely it needs an elevated admin token
(see "fileparcel help connect").

**Usage**

```
fileparcel network vpn role <interface> <mesh|unknown|access|egress|overlay|local|none|auto> [flags]
```

**Examples**

```sh
fileparcel network vpn role wg0 mesh
fileparcel network vpn role wg0 auto
```

### fileparcel open

Open the web app in your browser (or show QR codes for phones).

Open the recommended address of the server in your default browser. Without
a graphical session, and with --qr or --no-browser, the addresses are printed
instead; --qr adds a QR code per recommended address that phones can scan.

**Usage**

```
fileparcel open [flags]
```

**Flags**

| Flag | Type | Default | Description |
|---|---|---|---|
| `--no-browser` |  |  | only print the URLs |
| `--qr` |  |  | print the URLs with terminal QR codes instead of opening a browser |

**Examples**

```sh
fileparcel open
fileparcel open --qr
fileparcel open --no-browser
```

### fileparcel request

Collect files from others with an upload link.

A file request is a public link through which anyone can upload files into
one of your folders, without seeing its contents. Limit the size per file and
the total, require an uploader name, and close the request when done.

Paths look like "/My files/Docs/a.pdf", "/Team/Design/…" or nod_…; put quotes
around paths with spaces. More: fileparcel help paths.

**Usage**

```
fileparcel request [flags]
fileparcel request <command>
```

**Aliases:** `requests`

**Subcommands**

| Command | Description |
|---|---|
| [`close`](#fileparcel-request-close) | Stop accepting uploads (reopen later) |
| [`create`](#fileparcel-request-create) | Create an upload link into a folder |
| [`delete`](#fileparcel-request-delete) | Delete a file request for good |
| [`list`](#fileparcel-request-list) | List your file requests |
| [`log`](#fileparcel-request-log) | Show who uploaded through a file request |
| [`reopen`](#fileparcel-request-reopen) | Accept uploads again on a closed file request |
| [`show`](#fileparcel-request-show) | Show a file request and its link |

**Examples**

```sh
fileparcel request create "/My files/Incoming" --title "Send me your photos" --max-size 2G --qr
fileparcel request list
fileparcel request close shr_01j9zq3x4k6m8p0r2t4v6x8z0b
```

#### fileparcel request close

Stop accepting uploads (reopen later).

Close a file request: the link stops accepting uploads but is kept, so it can
be opened again with "fileparcel request reopen". "fileparcel request delete"
removes it for good.

**Usage**

```
fileparcel request close <id> [flags]
```

**Examples**

```sh
fileparcel request close shr_01j9zq3x4k6m8p0r2t4v6x8z0b
fileparcel request close shr_01j9zq3x4k6m8p0r2t4v6x8z0b --json
```

#### fileparcel request create

Create an upload link into a folder.

Create a public upload link into a remote folder and print it. Uploaders
cannot see the folder's contents. Uploads count against your quota.

--max-size limits each file, --quota the total of all uploads; --require-name
asks uploaders for their name (recorded with each upload). --password asks
for a password uploaders must enter; scripts use --password-stdin or
--password-file.

Paths look like "/My files/Docs/a.pdf", "/Team/Design/…" or nod_…; put quotes
around paths with spaces. More: fileparcel help paths.

**Usage**

```
fileparcel request create <folder> [flags]
```

**Flags**

| Flag | Type | Default | Description |
|---|---|---|---|
| `--expires` | string |  | validity: duration (7d), date (2026-12-31) or never (default: server setting) |
| `--max-size` | string |  | maximum size per file (e.g. 500M, 2G) |
| `--message` | string |  | instructions shown on the upload page |
| `--notify` |  |  | e-mail me about new uploads (needs SMTP) |
| `--password` |  |  | protect the link with a password (asked twice on the terminal) |
| `--password-file` | string |  | read the link password from the first line of `FILE` |
| `--password-stdin` |  |  | read the link password from the first line of standard input |
| `--qr` |  |  | print the link as a QR code |
| `--quota` | string |  | maximum total size of all uploads (e.g. 20G) |
| `--require-name` |  |  | uploaders must enter their name |
| `--title` | string |  | title shown on the upload page |

**Examples**

```sh
fileparcel request create "/My files/Incoming"
fileparcel request create "/My files/Incoming/Wedding" --title "Wedding photos" --expires 30d --qr
fileparcel request create /Team/Design/Submissions --max-size 500M --quota 20G --require-name --notify
```

#### fileparcel request delete

Delete a file request for good.

Delete a file request for good: its link stops working at once and cannot be
opened again. Files uploaded through it stay in the folder. To stop uploads
for a while, use "fileparcel request close".

**Usage**

```
fileparcel request delete <id> [flags]
```

**Aliases:** `revoke`, `rm`

**Examples**

```sh
fileparcel request delete shr_01j9zq3x4k6m8p0r2t4v6x8z0b
fileparcel request delete shr_01j9zq3x4k6m8p0r2t4v6x8z0b --json
```

#### fileparcel request list

List your file requests.

List your file requests with status, limits and link. --inactive adds expired
and closed ones. Admins list every user's file requests with --all-users (and
--user USER for one user); another user's link is hidden there unless
auth.admin_can_access_files is on, and the URL column is then left out.

**Usage**

```
fileparcel request list [flags]
```

**Aliases:** `ls`

**Flags**

| Flag | Type | Default | Description |
|---|---|---|---|
| `--all-users` |  |  | admin: list the file requests of every user |
| `--inactive` |  |  | include expired and closed file requests |
| `--user` | string |  | with --all-users: only the file requests of this user |

**Examples**

```sh
fileparcel request list
fileparcel request list --inactive --json
fileparcel request list --all-users --user alice
```

#### fileparcel request log

Show who uploaded through a file request.

Show who used a file request: views, downloads, uploads and password attempts
with time, IP address and browser.

**Usage**

```
fileparcel request log <id> [flags]
```

**Flags**

| Flag | Type | Default | Description |
|---|---|---|---|
| `--limit` | int | `100` | maximum number of entries (0 = all) |

**Examples**

```sh
fileparcel request log shr_01j9zq3x4k6m8p0r2t4v6x8z0b
fileparcel request log shr_01j9zq3x4k6m8p0r2t4v6x8z0b --limit 20 --json
```

#### fileparcel request reopen

Accept uploads again on a closed file request.

Open a closed file request again: its link accepts uploads with the settings
it had. A request that has expired or used up its upload quota still refuses
uploads; create a new one with "fileparcel request create".

**Usage**

```
fileparcel request reopen <id> [flags]
```

**Examples**

```sh
fileparcel request reopen shr_01j9zq3x4k6m8p0r2t4v6x8z0b
fileparcel request reopen shr_01j9zq3x4k6m8p0r2t4v6x8z0b --json
```

#### fileparcel request show

Show a file request and its link.

Show the settings, counters and link of a file request; --qr adds a QR code of
the link for phones.

**Usage**

```
fileparcel request show <id> [flags]
```

**Flags**

| Flag | Type | Default | Description |
|---|---|---|---|
| `--qr` |  |  | print the link as a QR code |

**Examples**

```sh
fileparcel request show shr_01j9zq3x4k6m8p0r2t4v6x8z0b
fileparcel request show shr_01j9zq3x4k6m8p0r2t4v6x8z0b --qr
```

### fileparcel role

Create roles and choose what they may do.

A role decides what its users may do on the server. There are four built-in
roles (owner, admin, member, guest) and you can create your own, starting
from a copy of another role and adding or removing permissions. Every user
has exactly one role ("fileparcel user set-role"). Built-in roles cannot be
renamed or deleted.

Which folders people can open is not part of the permissions: see
"fileparcel group" and "fileparcel access", and "fileparcel help permissions"
for the big picture. Changing roles needs an admin; remotely also an elevated
token.

**Usage**

```
fileparcel role [flags]
fileparcel role <command>
```

**Aliases:** `roles`, `class`, `classes`

**Subcommands**

| Command | Description |
|---|---|
| [`add-group`](#fileparcel-role-add-group) | Make everyone with a role a member of a group |
| [`create`](#fileparcel-role-create) | Create a custom role |
| [`delete`](#fileparcel-role-delete) | Delete a custom role (its people move to another role) |
| [`edit`](#fileparcel-role-edit) | Change a custom role's name, description or permissions |
| [`list`](#fileparcel-role-list) | List roles and how many people have each |
| [`members`](#fileparcel-role-members) | List the people who have a role |
| [`permissions`](#fileparcel-role-permissions) | List every permission a role can have |
| [`remove-group`](#fileparcel-role-remove-group) | Stop a role from making its people members of a group |
| [`show`](#fileparcel-role-show) | Show a role: permissions, people, groups and folders |

**Examples**

```sh
fileparcel role list
fileparcel role create contractors --from member --remove shares.links
fileparcel role show contractors
fileparcel role members contractors
```

#### fileparcel role add-group

Make everyone with a role a member of a group.

Make everyone who has a custom role a member of a group (or, with --manager, a
manager of it), now and whoever gets the role later. Their memberships through
the role show as "role:\<name>" in "fileparcel group members".

**Usage**

```
fileparcel role add-group <role> <group> [flags]
```

**Flags**

| Flag | Type | Default | Description |
|---|---|---|---|
| `--manager` |  |  | make them managers of the group |

**Examples**

```sh
fileparcel role add-group contractors Design
fileparcel role add-group leads Design --manager
```

#### fileparcel role create

Create a custom role.

Create a custom role. It starts with the permissions of another role (--from;
default: the role of --base, else member; owner or admin give every
permission), which --add and --remove change, or --set replaces. Permissions
go by name ("fileparcel role permissions"); several at once with commas.

--base is the kind of account its people have: member (their own files) or
guest (no own files, only what is shared with them). Without it the role gets
the base of --from (member when --from is owner or admin, or not given), so
--from guest also makes a guest-based role. It cannot be changed later.
--delegable lets account managers who are not administrators
give the role and manage its people.

On the server this always works; remotely it needs an elevated admin token
(see "fileparcel help connect").

**Usage**

```
fileparcel role create <name> [flags]
```

**Flags**

| Flag | Type | Default | Description |
|---|---|---|---|
| `--add` | strings |  | give this permission too (repeatable; a,b works) |
| `--base` | string |  | member (own files) or guest (no own files); default: the base of --from, else member |
| `--delegable` |  |  | account managers who are not administrators may give this role and manage its people |
| `--description` | string |  | what the role is for |
| `--from` | string |  | start with the permissions of this role (default: --base, else member) |
| `--no-delegable` |  |  | only administrators may give this role and manage its people |
| `--remove` | strings |  | take this permission away (repeatable; a,b works) |
| `--set` | strings |  | exactly these permissions, instead of --add/--remove (comma-separated) |

**Examples**

```sh
fileparcel role create contractors --from member --remove shares.links
fileparcel role create helpdesk --from admin --set users.view,users.manage --description "Resets passwords"
fileparcel role create auditors --from guest --add audit.view
```

#### fileparcel role delete

Delete a custom role (its people move to another role).

Delete a custom role. Its access grants and group memberships go with it. The
people who have the role get the role of --reassign-to, which you must choose
while anyone has the role: nothing is picked for you, because another role can
give them more rights.

It asks before doing it; -y skips the question.
On the server this always works; remotely it needs an elevated admin token
(see "fileparcel help connect").

**Usage**

```
fileparcel role delete <role> [flags]
```

**Aliases:** `rm`

**Flags**

| Flag | Type | Default | Description |
|---|---|---|---|
| `--reassign-to` | string |  | the role its people get instead (needed while anyone has the role) |

**Examples**

```sh
fileparcel role delete contractors --reassign-to member
fileparcel role delete interns --reassign-to guest -y
```

#### fileparcel role edit

Change a custom role's name, description or permissions.

Change a custom role; only the flags you pass are changed. --add and --remove
change its permissions, --set replaces them all. The people who have the role
get the change at once (their open sessions and tokens included).

On the server this always works; remotely it needs an elevated admin token
(see "fileparcel help connect").

**Usage**

```
fileparcel role edit <role> [flags]
```

**Flags**

| Flag | Type | Default | Description |
|---|---|---|---|
| `--add` | strings |  | give this permission too (repeatable; a,b works) |
| `--delegable` |  |  | account managers who are not administrators may give this role and manage its people |
| `--description` | string |  | new description ("" clears it) |
| `--name` | string |  | new name of the role |
| `--no-delegable` |  |  | only administrators may give this role and manage its people |
| `--remove` | strings |  | take this permission away (repeatable; a,b works) |
| `--set` | strings |  | exactly these permissions, instead of --add/--remove (comma-separated) |

**Examples**

```sh
fileparcel role edit contractors --add shares.links
fileparcel role edit helpdesk --remove users.manage
fileparcel role edit contractors --name freelancers
```

#### fileparcel role list

List roles and how many people have each.

List the built-in roles and the custom roles with how many people have each
(for a built-in role: the people without a custom role), how many permissions
it gives and what it is based on.

**Usage**

```
fileparcel role list [flags]
```

**Aliases:** `ls`

**Examples**

```sh
fileparcel role list
fileparcel role list --json
```

#### fileparcel role members

List the people who have a role.

List the accounts that have a role. For a built-in role these are the accounts
without a custom role.

**Usage**

```
fileparcel role members <role> [flags]
```

**Aliases:** `people`

**Flags**

| Flag | Type | Default | Description |
|---|---|---|---|
| `--limit` | int |  | maximum number of people (0 = all) |

**Examples**

```sh
fileparcel role members contractors
fileparcel role members admin --json
```

#### fileparcel role permissions

List every permission a role can have.

List every permission a role can have, grouped as in the web app, with what it
allows and a warning for those with a high impact. Server permissions open
parts of the Admin area (API tokens need the "admin" scope to use them). Some
permissions need another one, which a role then gets as well.

**Usage**

```
fileparcel role permissions [flags]
```

**Aliases:** `perms`, `caps`

**Examples**

```sh
fileparcel role permissions
fileparcel role permissions --json
```

#### fileparcel role remove-group

Stop a role from making its people members of a group.

Stop a custom role from making its people members of a group. People who are
also members on their own stay members.

**Usage**

```
fileparcel role remove-group <role> <group> [flags]
```

**Examples**

```sh
fileparcel role remove-group contractors Design
fileparcel role remove-group leads Design --json
```

#### fileparcel role show

Show a role: permissions, people, groups and folders.

Show everything about a role: its permissions (with a warning for each one
that has a high impact), how many people have it, whether account managers
may give it (delegable), the groups it makes its people members of and the
folders it has access to. Name roles by name or by id (rol_…).

**Usage**

```
fileparcel role show <role> [flags]
```

**Examples**

```sh
fileparcel role show admin
fileparcel role show contractors --json
```

### fileparcel serve

Run the server in the foreground.

Run the FileParcel server on the home directory: HTTPS (with HTTP→HTTPS
redirects), the local admin socket, background jobs and mDNS.

The process refuses to run as root unless --allow-root is given, and holds the
home lock for its lifetime (only one server per home). A restore scheduled from
the web UI is applied before the database is opened.

When the master key is sealed the server starts locked: --passphrase-file (or
the global --passphrase-stdin) unlocks it at start; otherwise unlock it at
/unlock or with "fileparcel keys unlock". While no account exists the server
prints a one-time setup token for /setup.

--init-if-missing (Docker) initialises an empty home first, with the owner
account from $FILEPARCEL_ADMIN_USER (default admin), its e-mail address from
$FILEPARCEL_ADMIN_EMAIL (optional) and the password from the file named by
$FILEPARCEL_ADMIN_PASSWORD_FILE (default: generated and printed once, to be
changed at the first sign-in).

Exit status 75 asks the service manager for a restart (settings that need a
restart, restores); without a service manager the server re-executes itself.

**Usage**

```
fileparcel serve [flags]
```

**Flags**

| Flag | Type | Default | Description |
|---|---|---|---|
| `--allow-root` |  |  | allow running as root (not recommended) |
| `--dev` |  |  | development mode: log at debug level |
| `--foreground` |  |  | print a human-readable startup summary (default when stderr is a terminal) |
| `--init-if-missing` |  |  | initialise the home first when it does not exist yet (Docker) |
| `--passphrase-file` | string |  | unlock a sealed master key at start with the passphrase in this file |

**Examples**

```sh
fileparcel serve --home ~/fileparcel
fileparcel serve --home /srv/fp --passphrase-file /run/secrets/fp-passphrase
FILEPARCEL_HOME=/data fileparcel serve --init-if-missing
```

### fileparcel service

Start, stop and register the background service.

Run FileParcel as a background service that starts by itself: a systemd user
unit (linked from \<HOME>/service; start at boot keeps it running after you log
out), a systemd system unit (/etc/systemd/system, hardened, runs as
"fileparcel"), a launchd agent (~/Library/LaunchAgents) or a launchd daemon
(/Library/LaunchDaemons, runs as "_fileparcel"). What was set up is recorded
in \<HOME>/service/installed.json.

**Usage**

```
fileparcel service [flags]
fileparcel service <command>
```

**Subcommands**

| Command | Description |
|---|---|
| [`disable-boot`](#fileparcel-service-disable-boot) | Do not start the service at boot |
| [`enable-boot`](#fileparcel-service-enable-boot) | Start the service at boot |
| [`install`](#fileparcel-service-install) | Register the service (and start it with --start) |
| [`print`](#fileparcel-service-print) | Show the unit file / plist without installing it |
| [`restart`](#fileparcel-service-restart) | Restart the service |
| [`start`](#fileparcel-service-start) | Start the service |
| [`status`](#fileparcel-service-status) | Show whether the service is registered and running |
| [`stop`](#fileparcel-service-stop) | Stop the service |
| [`uninstall`](#fileparcel-service-uninstall) | Stop and unregister the service (the data stays) |

**Examples**

```sh
fileparcel service status
fileparcel service restart
fileparcel service install --start
```

#### fileparcel service disable-boot

Do not start the service at boot.

Stop FileParcel from starting by itself when the machine boots; a running
server keeps running. For a systemd user service, linger is turned off again
when FileParcel turned it on and no other user service needs it.

**Usage**

```
fileparcel service disable-boot [flags]
```

**Examples**

```sh
fileparcel service disable-boot
sudo fileparcel service disable-boot --home /opt/fileparcel
```

#### fileparcel service enable-boot

Start the service at boot.

Start FileParcel by itself when the machine boots. For a systemd user
service this also turns on linger, so the service runs without anyone being
logged in.

**Usage**

```
fileparcel service enable-boot [flags]
```

**Examples**

```sh
fileparcel service enable-boot
sudo fileparcel service enable-boot --home /opt/fileparcel
```

#### fileparcel service install

Register the service (and start it with --start).

Write and register the service for this installation; running it again is
harmless. Start at boot is the default (--no-boot turns it off); for systemd
user services it enables linger, so the server keeps running after you log
out and starts at boot. System services (run as root) create the "fileparcel"
account when needed and give the installation to it (the directory itself,
bin/ and uninstall.sh stay owned by root). --start (re)starts the service and
waits for its health check.

**Usage**

```
fileparcel service install [flags]
```

**Flags**

| Flag | Type | Default | Description |
|---|---|---|---|
| `--boot` |  |  | start at boot (default) |
| `--force` |  |  | replace a registration that belongs to another FileParcel home |
| `--no-boot` |  |  | do not start at boot |
| `--start` |  |  | start (or restart) the service now |
| `--system` |  |  | systemd system unit / launchd daemon (root; default for root) |
| `--user` |  |  | systemd user unit / launchd agent (default for non-root) |

**Examples**

```sh
fileparcel service install --start
sudo fileparcel service install --system --start --home /opt/fileparcel
fileparcel service install --no-boot
```

#### fileparcel service print

Show the unit file / plist without installing it.

Print the systemd unit or launchd property list that "fileparcel service
install" would register, without changing anything.

**Usage**

```
fileparcel service print [flags]
```

**Flags**

| Flag | Type | Default | Description |
|---|---|---|---|
| `--no-boot` |  |  | launchd: RunAtLoad false |
| `--system` |  |  | the system unit / launchd daemon |
| `--user` |  |  | the user unit / launchd agent |

**Examples**

```sh
fileparcel service print
fileparcel service print --system > fileparcel.service
```

#### fileparcel service restart

Restart the service.

Stops and starts FileParcel and waits for its health check. Use it after
settings that need a restart.

**Usage**

```
fileparcel service restart [flags]
```

**Flags**

| Flag | Type | Default | Description |
|---|---|---|---|
| `--no-wait` |  |  | return at once |
| `--wait` |  |  | wait until the health check passes (default) |

**Examples**

```sh
fileparcel service restart
fileparcel service restart --no-wait
```

#### fileparcel service start

Start the service.

Starts FileParcel through the service manager (systemd or launchd) and waits
until its health check passes (--no-wait returns at once). Does nothing if it
already runs.

**Usage**

```
fileparcel service start [flags]
```

**Flags**

| Flag | Type | Default | Description |
|---|---|---|---|
| `--no-wait` |  |  | return at once |
| `--wait` |  |  | wait until the health check passes (default) |

**Examples**

```sh
fileparcel service start
fileparcel service start --no-wait
```

#### fileparcel service status

Show whether the service is registered and running.

Shows the service manager's view: registered, running, start at boot, unit
file. For the server's own state (addresses, keys, storage) use
"fileparcel status".

**Usage**

```
fileparcel service status [flags]
```

**Examples**

```sh
fileparcel service status
fileparcel service status --json
```

#### fileparcel service stop

Stop the service.

Stops FileParcel. Web users are disconnected; uploads in progress resume
later. It still starts at the next boot if start at boot is on.

**Usage**

```
fileparcel service stop [flags]
```

**Examples**

```sh
fileparcel service stop
fileparcel service stop && fileparcel db vacuum && fileparcel service start
```

#### fileparcel service uninstall

Stop and unregister the service (the data stays).

Stop, disable and unregister the service of this installation. Linger is
turned off again when "fileparcel service install" or the installer turned it
on and no other user service needs it. The installation and its data are not
touched (see "fileparcel uninstall").

**Usage**

```
fileparcel service uninstall [flags]
```

**Examples**

```sh
fileparcel service uninstall
sudo fileparcel service uninstall --home /opt/fileparcel
```

### fileparcel share

Share files and folders with a public link.

A share link lets anyone who has it open a file or folder, without an account.
Protect it with a password, let it expire or limit the number of downloads;
turn it off for a while ("disable") or delete it for good. The link is printed,
and with --qr also shown as a QR code for phones.

To give specific people or groups access instead of a public link, see
"fileparcel access".

Paths look like "/My files/Docs/a.pdf", "/Team/Design/…" or nod_…; put quotes
around paths with spaces. More: fileparcel help paths.

**Usage**

```
fileparcel share [flags]
fileparcel share <command>
```

**Aliases:** `shares`, `link`, `links`

**Subcommands**

| Command | Description |
|---|---|
| [`create`](#fileparcel-share-create) | Create a share link for a file or folder |
| [`delete`](#fileparcel-share-delete) | Delete a share link for good |
| [`disable`](#fileparcel-share-disable) | Turn a share link off without deleting it |
| [`edit`](#fileparcel-share-edit) | Change a share link's settings |
| [`enable`](#fileparcel-share-enable) | Turn a disabled share link back on |
| [`list`](#fileparcel-share-list) | List your share links |
| [`log`](#fileparcel-share-log) | Show who opened or downloaded through a link |
| [`show`](#fileparcel-share-show) | Show a share link with its settings and counters |

**Examples**

```sh
fileparcel share create "/My files/Slides.pdf" --expires 3d --qr
fileparcel share list
fileparcel share disable shr_01j9zq3x4k6m8p0r2t4v6x8z0b
fileparcel share delete shr_01j9zq3x4k6m8p0r2t4v6x8z0b
```

#### fileparcel share create

Create a share link for a file or folder.

Create a public link to a remote file or folder and print it.

--expires takes a duration (12h, 7d, 2w), a date (2026-12-31) or "never"
(default: sharing.default_expiry_days). --password asks for a password on the
terminal; scripts use --password-stdin or --password-file. --upload also lets
visitors upload into a shared folder.

Paths look like "/My files/Docs/a.pdf", "/Team/Design/…" or nod_…; put quotes
around paths with spaces. More: fileparcel help paths.

**Usage**

```
fileparcel share create <path> [flags]
```

**Flags**

| Flag | Type | Default | Description |
|---|---|---|---|
| `--expires` | string |  | validity: duration (7d), date (2026-12-31) or never (default: server setting) |
| `--max-downloads` | int64 |  | disable the link after this many downloads |
| `--message` | string |  | message shown on the share page |
| `--no-download` |  |  | view/preview only, no downloads |
| `--no-preview` |  |  | no in-browser previews |
| `--notify` |  |  | e-mail me about uploads through the link (needs --upload and SMTP) |
| `--password` |  |  | protect the link with a password (asked twice on the terminal) |
| `--password-file` | string |  | read the link password from the first line of `FILE` |
| `--password-stdin` |  |  | read the link password from the first line of standard input |
| `--qr` |  |  | print the link as a QR code |
| `--title` | string |  | title shown on the share page |
| `--upload` |  |  | let visitors also upload into the shared folder |

**Examples**

```sh
fileparcel share create "/My files/Slides.pdf"
fileparcel share create "/My files/Holiday" --expires 14d --qr
echo 's3cret-pass' | fileparcel share create /Team/Design/Brand --password-stdin --max-downloads 10
fileparcel share create "/My files/Video.mp4" --no-download --title "Preview only"
```

#### fileparcel share delete

Delete a share link for good.

Delete a share link for good: it stops working at once and cannot be turned on
again. The shared files are not touched. To turn a link off for a while, use
"fileparcel share disable".

**Usage**

```
fileparcel share delete <id> [flags]
```

**Aliases:** `revoke`, `rm`

**Examples**

```sh
fileparcel share delete shr_01j9zq3x4k6m8p0r2t4v6x8z0b
fileparcel share delete shr_01j9zq3x4k6m8p0r2t4v6x8z0b --json
```

#### fileparcel share disable

Turn a share link off without deleting it.

The link stops working until "fileparcel share enable". Nothing else changes;
its counters and settings are kept.

**Usage**

```
fileparcel share disable <id> [flags]
```

**Examples**

```sh
fileparcel share disable shr_01j9zq3x4k6m8p0r2t4v6x8z0b
fileparcel share disable shr_01j9zq3x4k6m8p0r2t4v6x8z0b --json
```

#### fileparcel share edit

Change a share link's settings.

Change the settings of a share link; only the flags you pass are changed.
--download turns downloads on, --no-download (or --download=false) turns them
off; the same goes for --preview, --upload and --notify. --max-downloads and
--expires take "none"/"never" to remove the limit.

**Usage**

```
fileparcel share edit <id> [flags]
```

**Flags**

| Flag | Type | Default | Description |
|---|---|---|---|
| `--disable` |  |  | turn the link off (reversible with --enable) |
| `--download` |  |  | allow downloads |
| `--enable` |  |  | turn a disabled link back on |
| `--expires` | string |  | new validity: duration (7d), date or never |
| `--max-downloads` | string |  | download limit, or none |
| `--message` | string |  | new message |
| `--no-download` |  |  | turn off downloads |
| `--no-notify` |  |  | turn off e-mails to the owner about new uploads |
| `--no-password` |  |  | remove the password |
| `--no-preview` |  |  | turn off in-browser previews |
| `--no-upload` |  |  | turn off uploads into the shared folder |
| `--notify` |  |  | allow e-mails to the owner about new uploads |
| `--password` |  |  | protect the link with a password (asked twice on the terminal) |
| `--password-file` | string |  | read the link password from the first line of `FILE` |
| `--password-stdin` |  |  | read the link password from the first line of standard input |
| `--preview` |  |  | allow in-browser previews |
| `--title` | string |  | new title |
| `--upload` |  |  | allow uploads into the shared folder |

**Examples**

```sh
fileparcel share edit shr_01j9zq3x4k6m8p0r2t4v6x8z0b --expires 30d
fileparcel share edit shr_01j9zq3x4k6m8p0r2t4v6x8z0b --no-download --max-downloads none
fileparcel share edit shr_01j9zq3x4k6m8p0r2t4v6x8z0b --password
fileparcel share edit shr_01j9zq3x4k6m8p0r2t4v6x8z0b --no-password
```

#### fileparcel share enable

Turn a disabled share link back on.

The link works again with the settings and counters it had. A link that has
expired or reached its download limit stays unavailable; change that with
"fileparcel share edit".

**Usage**

```
fileparcel share enable <id> [flags]
```

**Examples**

```sh
fileparcel share enable shr_01j9zq3x4k6m8p0r2t4v6x8z0b
fileparcel share enable shr_01j9zq3x4k6m8p0r2t4v6x8z0b --json
```

#### fileparcel share list

List your share links.

List your share links with status, limits and link. --inactive adds expired,
disabled and used-up ones. Admins list every user's share links with
--all-users (and --user USER for one user); another user's link is hidden
there unless auth.admin_can_access_files is on, and the URL column is then
left out.

**Usage**

```
fileparcel share list [flags]
```

**Aliases:** `ls`

**Flags**

| Flag | Type | Default | Description |
|---|---|---|---|
| `--all-users` |  |  | admin: list the share links of every user |
| `--inactive` |  |  | include expired, disabled and exhausted share links |
| `--user` | string |  | with --all-users: only the share links of this user |

**Examples**

```sh
fileparcel share list
fileparcel share list --inactive --json
fileparcel share list --all-users --user alice
```

#### fileparcel share log

Show who opened or downloaded through a link.

Show who used a share link: views, downloads, uploads and password attempts
with time, IP address and browser.

**Usage**

```
fileparcel share log <id> [flags]
```

**Flags**

| Flag | Type | Default | Description |
|---|---|---|---|
| `--limit` | int | `100` | maximum number of entries (0 = all) |

**Examples**

```sh
fileparcel share log shr_01j9zq3x4k6m8p0r2t4v6x8z0b
fileparcel share log shr_01j9zq3x4k6m8p0r2t4v6x8z0b --limit 20 --json
```

#### fileparcel share show

Show a share link with its settings and counters.

Show the settings, counters and link of a share link; --qr adds a QR code of
the link for phones.

**Usage**

```
fileparcel share show <id> [flags]
```

**Flags**

| Flag | Type | Default | Description |
|---|---|---|---|
| `--qr` |  |  | print the link as a QR code |

**Examples**

```sh
fileparcel share show shr_01j9zq3x4k6m8p0r2t4v6x8z0b
fileparcel share show shr_01j9zq3x4k6m8p0r2t4v6x8z0b --qr
```

### fileparcel status

Show whether the server is running and how to reach it.

Show the state of FileParcel. When the server is running (on this machine,
or with --server), it reports its version, uptime, keys, certificates, .local
name, addresses, Tailscale Funnel and Serve (when on) and storage. Otherwise
the state of the installation is shown (installed version, ports, service
registration, whether a process holds the installation's lock, pending
restores) without starting anything.

**Usage**

```
fileparcel status [flags]
```

**Examples**

```sh
fileparcel status
fileparcel status --json
fileparcel --home /opt/fileparcel status
```

### fileparcel token

Create API tokens for scripts and remote use.

A personal API token ("fpt_…") lets scripts and the fileparcel command on
another computer act as a user: fileparcel --server URL --token-file FILE …,
or the token in $FILEPARCEL_TOKEN. Scopes limit what it may do: files:read,
files:write, shares and admin. Admin tokens made with --elevated count as a
recent identity confirmation for sensitive admin actions (at most 30 days).

On the server, tokens belong to --user (or --as), else to the first owner;
remotely they belong to the token's own user. See "fileparcel help connect".

**Usage**

```
fileparcel token [flags]
fileparcel token <command>
```

**Aliases:** `tokens`

**Subcommands**

| Command | Description |
|---|---|
| [`create`](#fileparcel-token-create) | Create an API token (the secret is shown once) |
| [`list`](#fileparcel-token-list) | List API tokens |
| [`revoke`](#fileparcel-token-revoke) | Revoke an API token right away |

**Examples**

```sh
fileparcel token create laptop
fileparcel token list --user alice
fileparcel token revoke tok_01j9zq3x4k6m8p0r2t4v6x8z0b
```

#### fileparcel token create

Create an API token (the secret is shown once).

Create a personal API token. The name tells you where the token is used. The
secret is printed once; store it safely.

--expires takes a duration (30d, 12h, 2w), a date (2026-12-31) or "never"
(default). --elevated (needs the admin scope) makes the token count as a
recent identity confirmation for sensitive admin actions; such tokens must
expire within 30 days. The admin scope needs an account with server
permissions (an administrator, or a role with such permissions: see
"fileparcel role show \<role>").

**Usage**

```
fileparcel token create <name> [flags]
```

**Flags**

| Flag | Type | Default | Description |
|---|---|---|---|
| `--elevated` |  |  | admin token that counts as step-up elevated (max 30 days) |
| `--expires` | string | `never` | lifetime: a duration (30d, 12h), a date (2026-12-31) or never |
| `--scopes` | strings | `[files:read,files:write,shares]` | comma-separated scopes: files:read, files:write, shares, admin |
| `--user` | string |  | create the token for this user (admin socket only; default --as or the first owner) |

**Examples**

```sh
fileparcel token create laptop
fileparcel token create backup-script --scopes files:read --expires 90d
fileparcel token create ops --user alice --scopes admin --elevated --expires 7d
```

#### fileparcel token list

List API tokens.

List the API tokens of a user; their secrets are never shown again. Revoked
and expired tokens are left out unless --inactive.

**Usage**

```
fileparcel token list [flags]
```

**Aliases:** `ls`

**Flags**

| Flag | Type | Default | Description |
|---|---|---|---|
| `--inactive` |  |  | include revoked and expired tokens |
| `--user` | string |  | list the tokens of this user (admin socket only; default --as or the first owner) |

**Examples**

```sh
fileparcel token list
fileparcel token list --user alice --inactive
```

#### fileparcel token revoke

Revoke an API token right away.

Revoke an API token right away; scripts using it stop working. On the server,
pass --user for the tokens of users other than the first owner.

**Usage**

```
fileparcel token revoke <id> [flags]
```

**Flags**

| Flag | Type | Default | Description |
|---|---|---|---|
| `--user` | string |  | the token's owner (admin socket only; default --as or the first owner) |

**Examples**

```sh
fileparcel token revoke tok_01j9zq3x4k6m8p0r2t4v6x8z0b
fileparcel token revoke tok_01j9zq3x4k6m8p0r2t4v6x8z0b --user alice
```

### fileparcel uninstall

Remove FileParcel (keeps your data unless --purge).

Uninstall FileParcel (called by uninstall.sh): stop, disable and unregister the
service, disable linger when the installer enabled it and no other user service
needs it, and remove the "fileparcel" command link when it points into the home.
FileParcel's Tailscale Funnel and Serve entries are removed from Tailscale too
(also with --keep-data); entries you made yourself stay.

--keep-data (default) leaves the home directory with all files, keys and
backups; "install.sh --dir DIR" picks it up again and registers the service and
the command link anew. --purge also overwrites the master key and the
CA/certificate keys (also the copies restores keep in pre-restore-\<date>/)
with random bytes and deletes the home
(guarded: only a directory containing fileparcel.toml, never a system or home
directory itself). On SSDs overwritten blocks may survive, but the data is
encrypted and unreadable without the destroyed master key.

--final-backup creates a full backup first; --backup-to DIR (outside the home,
created if missing) also copies it there. --final-backup together with --purge
needs --backup-to, since a backup left in the home would be deleted with it;
--purge alone makes no backup. The copy is made and checked by the
uninstaller; if it fails, nothing is removed.
With the service running the server makes the backup and uninstall waits as
long as it takes (Ctrl-C stops waiting; the backup job continues). With the
server stopped, a sealed master key is unlocked with the global
--passphrase-file/--passphrase-stdin or on the terminal; the backup needs it
only in passphrase encryption mode.
--remove-user deletes the system account the installer created.

It asks before doing it; -y skips the question. --dry-run prints the plan.

**Usage**

```
fileparcel uninstall [flags]
```

**Flags**

| Flag | Type | Default | Description |
|---|---|---|---|
| `--backup-to` | string |  | copy the final backup into DIR (outside the home, created if missing; implies --final-backup; needed when --final-backup is combined with --purge) |
| `--dry-run` |  |  | print the plan without changing anything |
| `--final-backup` |  |  | create a full backup before removing anything |
| `--keep-data` |  |  | keep the home directory and its data (default) |
| `--purge` |  |  | destroy the keys and delete the home directory with all data |
| `--remove-user` |  |  | delete the service account the installer created |

**Examples**

```sh
fileparcel uninstall
fileparcel uninstall --final-backup --backup-to ~/fileparcel-final --purge
sudo fileparcel uninstall -y --purge --remove-user --home /opt/fileparcel
```

### fileparcel upgrade

Upgrade to a new release (with automatic rollback).

Upgrade the installed FileParcel to a new release: a release zip
(fileparcel-vN.zip; the binary for this platform is checked against its
SHA256SUMS) or a binary (checked against a SHA256SUMS file next to it or one
directory up; --force accepts an unverified binary).

Steps: pre-upgrade metadata backup, stop the service, keep the current binary
as bin/fileparcel.prev, install the new one atomically, refresh VERSION, docs/
and uninstall.sh, start the service (database migrations run at start) and
check https://127.0.0.1:\<port>/healthz (pinned to the local CA) for 30 s. When
the new version is not healthy the previous binary is restored and restarted.

It asks before doing it; -y skips the question. Without a terminal (a script,
a cron job) there is nobody to ask and it goes ahead as with -y. --dry-run
prints the plan.

**Usage**

```
fileparcel upgrade <release.zip|binary> [flags]
```

**Flags**

| Flag | Type | Default | Description |
|---|---|---|---|
| `--dry-run` |  |  | print the plan without changing anything |
| `--force` |  |  | accept a binary without a SHA256SUMS entry; continue when the pre-upgrade backup fails |
| `--skip-backup` |  |  | do not create the pre-upgrade backup |

**Examples**

```sh
fileparcel upgrade ~/Downloads/fileparcel-v2.zip
fileparcel upgrade --dry-run fileparcel-v2.zip
fileparcel upgrade --force ./fileparcel-linux-amd64
```

### fileparcel user

Create and manage user accounts.

User accounts sign in to the web app and have their own files ("/My files").
Every account has one role that decides what it may do on the server: owner,
admin, member (the default), guest, or a custom role ("fileparcel role").
Guests have no personal files; they only see what is shared with them.

Name users by username or by id (usr_…). Access to more folders comes from
groups ("fileparcel group") and access grants ("fileparcel access").

**Usage**

```
fileparcel user [flags]
fileparcel user <command>
```

**Aliases:** `users`

**Subcommands**

| Command | Description |
|---|---|
| [`create`](#fileparcel-user-create) | Create a user account |
| [`delete`](#fileparcel-user-delete) | Delete an account and its files |
| [`disable`](#fileparcel-user-disable) | Stop a user from signing in (their files stay) |
| [`edit`](#fileparcel-user-edit) | Change a user's name, e-mail, role, quota or password rule |
| [`enable`](#fileparcel-user-enable) | Let a disabled user sign in again |
| [`list`](#fileparcel-user-list) | List user accounts |
| [`reset-2fa`](#fileparcel-user-reset-2fa) | Remove a user's second factors (lost phone or key) |
| [`reset-password`](#fileparcel-user-reset-password) | Set a new password for a user |
| [`revoke-sessions`](#fileparcel-user-revoke-sessions) | Sign a user out everywhere |
| [`sessions`](#fileparcel-user-sessions) | List where a user is signed in |
| [`set-quota`](#fileparcel-user-set-quota) | Set how much storage a user may use |
| [`set-role`](#fileparcel-user-set-role) | Change a user's role |
| [`show`](#fileparcel-user-show) | Show everything about one account |
| [`unlock`](#fileparcel-user-unlock) | Clear the lockout after too many failed sign-ins |

**Examples**

```sh
fileparcel user list
fileparcel user create alice --email alice@example.com --generate-password
fileparcel user set-role alice admin
fileparcel user set-quota alice 50G
```

#### fileparcel user create

Create a user account.

Create a user account and its personal files ("/My files"; guests have
none).

The password is read from --password-stdin or --password-file, generated with
--generate-password (printed once), or asked for on a terminal. Generated
passwords and --must-change make the user choose a new password at the first
sign-in.

Creating an owner or admin account needs an elevated admin token remotely;
on the server this always works (see "fileparcel help connect").

**Usage**

```
fileparcel user create <user> [flags]
```

**Aliases:** `add`

**Flags**

| Flag | Type | Default | Description |
|---|---|---|---|
| `--display-name` | string |  | display name (default: the username) |
| `--email` | string |  | e-mail address |
| `--generate-password` |  |  | generate a strong password (printed once; must be changed at the first sign-in) |
| `--group` | strings |  | add the user to this group (repeatable) |
| `--must-change` |  |  | require a password change at the first login |
| `--password-file` | string |  | read the password from the first line of `FILE` |
| `--password-stdin` |  |  | read the password from the first line of standard input |
| `--quota` | string |  | storage quota (e.g. 10G, 500M, unlimited; default: storage.default_quota_gb) |
| `--role` | string | `member` | role of the account: a built-in role or a custom one (see "fileparcel role list") |

**Examples**

```sh
fileparcel user create alice --email alice@example.com --generate-password
echo 'correct horse battery staple' | fileparcel user create bob --password-stdin --role admin
fileparcel user create carol --generate-password --quota 20G --group Design --group Marketing
fileparcel user create visitor --role guest --generate-password
```

#### fileparcel user delete

Delete an account and its files.

Delete a user account for good. Without --transfer-to the user's personal
files are deleted too; with --transfer-to they are moved into the other user's
files. To keep someone out for a while, use "fileparcel user disable" instead.

It asks before doing it; -y skips the question.
On the server this always works; remotely it needs an elevated admin token
(see "fileparcel help connect").

**Usage**

```
fileparcel user delete <user> [flags]
```

**Aliases:** `rm`

**Flags**

| Flag | Type | Default | Description |
|---|---|---|---|
| `--transfer-to` | string |  | move the user's files to this user instead of deleting them |

**Examples**

```sh
fileparcel user delete mallory
fileparcel user delete bob --transfer-to alice -y
```

#### fileparcel user disable

Stop a user from signing in (their files stay).

Stop a user from signing in: they are signed out everywhere, their API tokens
and share links stop working and the invitations they created are revoked.
Their files, groups and settings stay; "fileparcel user enable" lets them back
in.

**Usage**

```
fileparcel user disable <user> [flags]
```

**Examples**

```sh
fileparcel user disable mallory
fileparcel user disable usr_01j9zq3x4k6m8p0r2t4v6x8z0b
```

#### fileparcel user edit

Change a user's name, e-mail, role, quota or password rule.

Change one or more attributes of a user account; only the flags you pass are
changed. For one attribute there are shortcuts: "fileparcel user set-role" and
"fileparcel user set-quota".

Changing the role needs an elevated admin token remotely;
on the server this always works (see "fileparcel help connect").

**Usage**

```
fileparcel user edit <user> [flags]
```

**Flags**

| Flag | Type | Default | Description |
|---|---|---|---|
| `--display-name` | string |  | new display name |
| `--email` | string |  | new e-mail address ("" clears it) |
| `--must-change` |  |  | require (or with =false, stop requiring) a password change at the next login |
| `--quota` | string |  | new quota: a size (10G), unlimited, or default |
| `--role` | string |  | new role: a built-in role or a custom one (see "fileparcel role list") |

**Examples**

```sh
fileparcel user edit alice --display-name "Alice Liddell" --email alice@example.org
fileparcel user edit bob --role admin --quota unlimited
fileparcel user edit carol --must-change
```

#### fileparcel user enable

Let a disabled user sign in again.

Let a disabled user sign in again. Disabling signed them out everywhere, so
they sign in anew; their files, groups and share links are as before.

**Usage**

```
fileparcel user enable <user> [flags]
```

**Examples**

```sh
fileparcel user enable mallory
fileparcel user enable usr_01j9zq3x4k6m8p0r2t4v6x8z0b
```

#### fileparcel user list

List user accounts.

List user accounts with their role, status, two-factor state, quota and last
sign-in. The flags narrow the list; -q searches usernames, display names and
e-mail addresses.

**Usage**

```
fileparcel user list [flags]
```

**Aliases:** `ls`

**Flags**

| Flag | Type | Default | Description |
|---|---|---|---|
| `--limit` | int |  | maximum number of users (0 = all) |
| `-q, --query` | string |  | search username, display name and e-mail |
| `--role` | string |  | only users with this role (see "fileparcel role list") |
| `--status` | string |  | only users with this status (active, disabled) |

**Examples**

```sh
fileparcel user list
fileparcel user list --role admin
fileparcel user list --status disabled --json
fileparcel user list -q ali
```

#### fileparcel user reset-2fa

Remove a user's second factors (lost phone or key).

Remove a user's authenticator app secret, recovery codes and passkeys, for
example after they lost their phone or security key. Their sessions and API
tokens are revoked as well. If two-factor sign-in is required, the user sets
it up again at the next sign-in.

It asks before doing it; -y skips the question.
On the server this always works; remotely it needs an elevated admin token
(see "fileparcel help connect").

**Usage**

```
fileparcel user reset-2fa <user> [flags]
```

**Aliases:** `reset-mfa`

**Examples**

```sh
fileparcel user reset-2fa alice
fileparcel user reset-2fa alice -y
```

#### fileparcel user reset-password

Set a new password for a user.

Set a new password for a user, for example when they forgot theirs. The new
password is read from --password-stdin or --password-file, generated with
--generate-password (printed once), or asked for twice on a terminal. The
user's sessions and API tokens are revoked, so anything signed in as them has
to sign in again.

On the server this always works; remotely it needs an elevated admin token
(see "fileparcel help connect").

**Usage**

```
fileparcel user reset-password <user> [flags]
```

**Aliases:** `passwd`, `set-password`

**Flags**

| Flag | Type | Default | Description |
|---|---|---|---|
| `--generate-password` |  |  | generate a strong password (printed once) |
| `--must-change` |  |  | require a password change at the next login |
| `--password-file` | string |  | read the new password from the first line of `FILE` |
| `--password-stdin` |  |  | read the new password from the first line of standard input |

**Examples**

```sh
fileparcel user reset-password alice
fileparcel user reset-password alice --generate-password --must-change
printf '%s\n' "$NEW_PASSWORD" | fileparcel user reset-password bob --password-stdin
```

#### fileparcel user revoke-sessions

Sign a user out everywhere.

Revoke all of a user's browser sessions, so they have to sign in again. API
tokens are not affected (see "fileparcel token revoke").

**Usage**

```
fileparcel user revoke-sessions <user> [flags]
```

**Aliases:** `sign-out`

**Examples**

```sh
fileparcel user revoke-sessions alice
fileparcel user revoke-sessions alice --json
```

#### fileparcel user sessions

List where a user is signed in.

List a user's active browser sessions with IP address, browser and expiry.
"fileparcel user revoke-sessions" signs them out everywhere.

**Usage**

```
fileparcel user sessions <user> [flags]
```

**Examples**

```sh
fileparcel user sessions alice
fileparcel user sessions alice --json
```

#### fileparcel user set-quota

Set how much storage a user may use.

Set the storage quota of a user's personal files. Sizes use binary units
(500M, 10G, 1.5T). "unlimited" removes the limit; "default" falls back to the
server-wide default (storage.default_quota_gb).

**Usage**

```
fileparcel user set-quota <user> <size|unlimited|default> [flags]
```

**Aliases:** `quota`

**Examples**

```sh
fileparcel user set-quota alice 50G
fileparcel user set-quota bob unlimited
fileparcel user set-quota carol default
```

#### fileparcel user set-role

Change a user's role.

Give a user a built-in role (owner, admin, member, guest) or a custom role
made with "fileparcel role create". The role decides what the user may do on
the server; which folders they can open comes from their own files, their
groups and access grants. Only owners can make someone an owner.

On the server this always works; remotely it needs an elevated admin token
(see "fileparcel help connect").

**Usage**

```
fileparcel user set-role <user> <role> [flags]
```

**Examples**

```sh
fileparcel user set-role alice admin
fileparcel user set-role bob member
fileparcel user set-role carol contractors
```

#### fileparcel user show

Show everything about one account.

Show every detail of a user account: role and the permissions it gives,
status, quota, two-factor state, lockout, last sign-in and the id of their
personal files.

**Usage**

```
fileparcel user show <user> [flags]
```

**Examples**

```sh
fileparcel user show alice
fileparcel user show usr_01j9zq3x4k6m8p0r2t4v6x8z0b --json
```

#### fileparcel user unlock

Clear the lockout after too many failed sign-ins.

Clear the lockout that follows too many failed sign-ins
(auth.lockout_threshold) and reset the failure counter, so the user can try
again at once.

**Usage**

```
fileparcel user unlock <user> [flags]
```

**Examples**

```sh
fileparcel user unlock alice
fileparcel user unlock usr_01j9zq3x4k6m8p0r2t4v6x8z0b
```

### fileparcel version

Print version information.

Print the FileParcel version, commit, build date, Go version and platform
(--json for scripts).

**Usage**

```
fileparcel version [flags]
```

**Examples**

```sh
fileparcel version
fileparcel version --json
```

### fileparcel whoami

Show who you act as, your role and what you may do.

Show which account commands act as and what it may do: its role, the
permissions of that role, its groups and whether it signs in with a second
factor. Remotely it also shows the API token in use, its scopes and when it
expires.

On the server, commands without --as have the admin socket's full rights (or,
with the server stopped, work on the data directly with the same rights);
file, share, request and token commands then act as the first owner. With
--as USER they act as that user. Remotely every command acts as the token's
user. See "fileparcel help connect" and "fileparcel help permissions".

**Usage**

```
fileparcel whoami [flags]
```

**Examples**

```sh
fileparcel whoami
fileparcel --as alice whoami
fileparcel --server https://files.example.lan:8443 --token-file ~/.fileparcel-token whoami
```

### Help topics

#### fileparcel help connect

How commands reach the server (socket, offline, remote).

```text
Commands reach FileParcel in this order:

1. Admin socket. On the server machine, while the server runs, commands talk
   to it through <HOME>/run/admin.sock. Only the same system user (or root)
   can connect. It has full admin rights: no password, no second factor.
2. Offline. When the server is stopped, commands open the installation
   directly and run the same code in-process. --offline forces this (and fails
   while the server runs). A sealed master key needs its passphrase: typed at
   the prompt, or --passphrase-stdin / --passphrase-file.
3. Remote. --server https://HOST:8443 --token fpt_… (or $FILEPARCEL_TOKEN) uses
   the REST API with a personal API token ("fileparcel token create"). Check a
   certificate from the local CA with --ca-file ca.pem or --fingerprint SHA256.
   The token's account must meet the two-factor policy (auth.require_2fa).

Which installation: --home DIR, else $FILEPARCEL_HOME, else the directory the
fileparcel program is installed in.

Acting as a user: over the socket or offline, file, share, request and token
commands work as the first owner unless you pass --as USER; "access" commands
use the admin socket's full rights unless you pass --as USER. Remotely every
command acts as the token's user, with that user's role and access.
"fileparcel whoami" shows who a command acts as and what it may do.

Sensitive admin actions over the network need a recent identity confirmation;
use a token made with "fileparcel token create ops --scopes admin --elevated
--expires 7d". On the server itself this is never needed.

A system service runs as the "fileparcel" account ("_fileparcel" on macOS).
Run admin commands with sudo there: sudo fileparcel status (or
sudo -u fileparcel fileparcel status).

  fileparcel status
  fileparcel --as alice files ls
  fileparcel --server https://files.example.lan:8443 --token "$FILEPARCEL_TOKEN" user list
```

#### fileparcel help flags

Global flags and environment variables.

```text
Global flags work with every command:

  --home DIR           the installation directory (default: $FILEPARCEL_HOME or
                       the directory the program is installed in)
  --json               print JSON instead of tables (errors too)
  -y, --yes            answer yes to every question; never prompt
  --no-color           no colours (also: NO_COLOR=1 or TERM=dumb)
  --offline            work on the data directly; the server must be stopped
  --as USER            act as USER (admin socket and offline only)
  --server URL         talk to a remote server (needs --token)
  --token TOKEN        API token for --server; prefer $FILEPARCEL_TOKEN, because
                       other users of the machine can see command lines
  --token-file FILE    API token for --server, from the first line of FILE
  --ca-file FILE       trust this CA certificate for --server
  --fingerprint SHA256 pin the server certificate for --server
  --passphrase-stdin, --passphrase-file FILE
                       master-key passphrase for offline commands on a sealed
                       installation (commands with their own flag of that name
                       keep their own meaning)

Environment variables:
  FILEPARCEL_HOME      installation directory
  FILEPARCEL_TOKEN     API token for --server
  FILEPARCEL_<SECTION>_<KEY>  override a fileparcel.toml value, e.g.
                       FILEPARCEL_SERVER_HTTPS_PORT=9443
  FILEPARCEL_ADMIN_USER, FILEPARCEL_ADMIN_EMAIL, FILEPARCEL_ADMIN_PASSWORD_FILE
                       owner account for "serve --init-if-missing" (Docker)
  FILEPARCEL_SUPERVISED=1  a supervisor restarts the server (exit code 75)
  NO_COLOR, TERM=dumb  no colours
  VISUAL, EDITOR       editor for "fileparcel config edit"
```

#### fileparcel help paths

How to write file and folder paths.

```text
File commands take remote paths:

  /My files/…        your personal files ("My files" is the default, so
                     "Documents/a.pdf" means "/My files/Documents/a.pdf")
  /Team/<group>/…    the team folder of a group you belong to, or one
                     shared with you as a whole (a grant to you, one of
                     your groups or your role)
  nod_…[/sub/path]   any file or folder by id (also ones shared with you),
                     optionally followed by a path below it; "files info"
                     and --json output show ids
  /                  the top level: your spaces

Put quotes around paths with spaces: "/My files/Tax 2026".
Over the admin socket or offline, "/My files" is the first owner's, or that of
the user given with --as USER. Remotely it is the token user's.

  fileparcel files ls "/My files/Documents"
  fileparcel --as alice files ls /Team/Design
  fileparcel files info nod_01j9zq3x4k6m8p0r2t4v6x8z0b
```

#### fileparcel help permissions

Roles, groups and folder access explained.

```text
What someone may do is decided in three layers:

1. Their role decides what they may do on the server. Built-in roles: owner,
   admin, member (the default) and guest; you can create your own
   ("fileparcel role create"). See what a role allows with
   "fileparcel role show ROLE", and all permissions with
   "fileparcel role permissions".
2. Their groups give them the team folders "/Team/<group>"
   ("fileparcel group").
3. Access grants give a user, a group or everyone with a role access to one
   folder or file: view (see and download), edit (also change, move and
   delete), manage (also share it and change its access)
   ("fileparcel access grant").

Access only adds up; nothing takes away what another layer gives. To see why
someone can open a folder: fileparcel access check USER PATH

  fileparcel role list
  fileparcel user set-role bob contractors
  fileparcel access grant /Team/Design --role contractors
```

#### fileparcel help renamed

Old command names and what they are called now.

```text
These names were changed; the old ones keep working:

  fileparcel mdns …                        → fileparcel network mdns …
  fileparcel restore …                     → fileparcel backup restore …
  fileparcel keys export-recovery          → fileparcel keys recovery-key
  fileparcel user add                      → fileparcel user create
  fileparcel user passwd                   → fileparcel user reset-password
  fileparcel user quota                    → fileparcel user set-quota
  fileparcel share revoke                  → fileparcel share delete
  fileparcel request close ID --reopen     → fileparcel request reopen ID
  fileparcel token create --name NAME      → fileparcel token create NAME
  fileparcel cert sans --add X / --remove X → fileparcel cert sans add X / remove X
  --generate (user create, reset-password) → --generate-password
  --out (backup create, client-cert issue) → -o, --output
  --all (share, request list)              → --all-users
  --all (token, invite, client-cert list)  → --inactive
  --identity (backup restore)              → --identity-file
  --days N (client-cert issue)             → --expires Nd
```

#### fileparcel help scripting

JSON output, exit codes and non-interactive use.

```text
For scripts and cron jobs:

  --json        one JSON document on stdout (JSON lines with --follow/-f);
                errors are {"error":{"code":…,"message":…,"hint":…}} on stderr
  -y            never prompt; without -y and without a terminal a question
                is an error (exit 1) instead of a hang (install and upgrade
                go ahead as with -y instead)
  --wait        commands that start a background job can wait for it;
                --no-wait returns at once (each command says its default)
  Exit codes    0 success, 1 error, 2 wrong usage or invalid input,
                75 the server asks its supervisor for a restart
  Secrets       --X-stdin / --X-file flags, never arguments
  Output        tables and results on stdout; questions, warnings, progress
                and notes on stderr

  fileparcel --json user list
  fileparcel -y backup create --wait --json
  printf '%s\n' "$PASS" | fileparcel user create bob --password-stdin
```

#### fileparcel help values

Durations, dates, sizes, lists and secrets in flags.

```text
Durations  30m, 12h, 7d, 2w, 1d12h.
Expiry     --expires takes a duration (7d), a date (2026-12-31, until the end
           of that day) or "never" where things may last forever (links,
           tokens, access grants). --since/--until take a duration back from
           now or a time (2026-09-01, 2026-09-01T12:00:00Z).
Sizes      500M, 10G, 1.5T (binary units; 10GB and 10GiB mean the same).
           Quotas also take "unlimited"; user quotas also "default".
Lists      Repeat the flag: --group Design --group Marketing. Flags whose
           help says "comma-separated" also take a,b,c.
On/off     --upload turns an option on; --no-upload or --upload=false turns
           it off.
Secrets    Never on the command line. --password asks without echo;
           --password-stdin reads the first line of standard input;
           --password-file FILE reads the first line of a file (chmod 600).
           Only one flag of a command can read standard input.
Names      Users, groups and roles by name or id (usr_…, grp_…, rol_…).
           Other objects by id: shr_ (links and file requests), bak_
           (backups), job_, tok_, inv_, ccr_ (client certificates), gnt_
           (access grants), nod_ (files and folders), ver_ (file versions).
```


<!-- END GENERATED CLI REFERENCE -->
