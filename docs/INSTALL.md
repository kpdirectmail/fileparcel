# Installing FileParcel

This guide covers everything from downloading FileParcel to removing it again: installing it on
Linux, a Raspberry Pi, a Mac or in Docker, opening the firewall, trusting its certificate on your
devices, the first sign-in, reaching it from your phone, over a VPN or from the internet, and upgrading,
moving and uninstalling it.

You do not need to be an expert. Most people only need [Install in three commands](#install-in-three-commands),
[Trust FileParcel's certificate on your devices](#trust-fileparcels-certificate-on-your-devices) and
[Sign in for the first time](#sign-in-for-the-first-time). The rest is there when you need it.

> **Words used in this guide.** The *installation directory* is the one folder that holds everything
> FileParcel stores (by default `~/.local/share/fileparcel` on Linux). The *server* is the machine
> FileParcel runs on. Commands that start with `fileparcel` are run on the server, as the user who
> installed FileParcel. For a system-wide installation, put `sudo` in front of them.

## Contents

- [Before you start](#before-you-start)
  - [What you need](#what-you-need)
  - [Pick a way to install](#pick-a-way-to-install)
- [Download FileParcel](#download-fileparcel)
  - [Check the download](#check-the-download)
  - [What is in the zip](#what-is-in-the-zip)
  - [Install from source](#install-from-source)
- [Install in three commands](#install-in-three-commands)
  - [What the installer prints](#what-the-installer-prints)
- [Choose installer options](#choose-installer-options)
  - [All install.sh options](#all-installsh-options)
  - [Answer the installer's questions](#answer-the-installers-questions)
  - [What the installer does](#what-the-installer-does)
- [Run it as a user or a system service](#run-it-as-a-user-or-a-system-service)
  - [User service (the default)](#user-service-the-default)
  - [System service](#system-service)
  - [No service](#no-service)
  - [Start, stop and restart the service](#start-stop-and-restart-the-service)
- [Notes for your operating system](#notes-for-your-operating-system)
  - [Debian or Ubuntu](#install-on-debian-or-ubuntu) ·
    [Raspberry Pi](#install-on-a-raspberry-pi) ·
    [Fedora, RHEL, Rocky or AlmaLinux](#install-on-fedora-rhel-rocky-or-almalinux) ·
    [Arch or Manjaro](#install-on-arch-linux-or-manjaro) ·
    [Alpine and other systems without systemd](#install-on-alpine-or-another-system-without-systemd) ·
    [Mac](#install-on-a-mac) ·
    [Windows](#install-on-windows)
- [Run FileParcel in Docker](#run-fileparcel-in-docker)
- [Open the firewall](#open-the-firewall)
  - [ufw](#ufw-debian-ubuntu-raspberry-pi-os) · [firewalld](#firewalld-fedora-rhel) ·
    [nftables](#nftables) · [macOS application firewall](#macos-application-firewall) · [pf](#pf)
- [Trust FileParcel's certificate on your devices](#trust-fileparcels-certificate-on-your-devices)
  - [Windows](#trust-it-on-windows) · [Mac](#trust-it-on-a-mac) ·
    [iPhone and iPad](#trust-it-on-an-iphone-or-ipad) · [Android](#trust-it-on-android) ·
    [Linux](#trust-it-on-linux) · [Firefox](#trust-it-in-firefox)
- [Sign in for the first time](#sign-in-for-the-first-time)
- [Reach FileParcel from other devices](#reach-fileparcel-from-other-devices)
  - [On your home network](#on-your-home-network)
  - [Choose who may connect](#choose-who-may-connect)
  - [Over a VPN](#over-a-vpn)
  - [Give your tailnet an address without a port (Tailscale Serve)](#give-your-tailnet-an-address-without-a-port-tailscale-serve)
  - [Put share links on the internet (Tailscale Funnel)](#put-share-links-on-the-internet-tailscale-funnel)
- [Upgrade to a new version](#upgrade-to-a-new-version)
  - [Before you upgrade](#before-you-upgrade)
  - [Upgrade from a new release zip](#upgrade-from-a-new-release-zip)
  - [Upgrade with the fileparcel command](#upgrade-with-the-fileparcel-command)
  - [What happens during an upgrade](#what-happens-during-an-upgrade)
  - [Roll back by hand](#roll-back-by-hand)
  - [Upgrade a Docker installation](#upgrade-a-docker-installation)
- [Move FileParcel](#move-fileparcel)
  - [To another folder or disk](#move-it-to-another-folder-or-disk-on-the-same-machine)
  - [To a new machine](#move-it-to-a-new-machine)
- [Uninstall FileParcel](#uninstall-fileparcel)
  - [What is left behind](#what-is-left-behind)
  - [Remove the certificate from your devices](#remove-the-certificate-from-your-devices)
  - [Uninstall a Docker installation](#uninstall-a-docker-installation)
- [The installation directory](#the-installation-directory)
- [Fix installation problems](#fix-installation-problems)
- [More documentation](#more-documentation)

---

## Before you start

### What you need

| | |
|---|---|
| **Operating system** | Linux (any distribution; systemd is needed for the automatic service) or macOS on Intel or Apple silicon (any version supported by Go 1.27). On Windows, use Docker Desktop or WSL 2. |
| **Processor** | 64-bit PC (`amd64`), 64-bit ARM (`arm64`: Raspberry Pi 3, 4 and 5 with a 64-bit system, Apple silicon, ARM servers) or 32-bit ARMv7 (`arm`: Raspberry Pi 2, 3 and 4 with a 32-bit system). A Raspberry Pi Zero or Pi 1 (ARMv6) works too, but FileParcel has to be built from source for it. |
| **Memory** | 256 MiB free is enough for a family. 1 GiB or more is better for many uploads at once, big zips or thumbnails of large photos. |
| **Disk space** | A little more than the size of your files, plus room for backups. Bundling an upload into a `.zip` needs twice the upload's size for a while. |
| **Network** | One TCP port for HTTPS (8443 by default) and, if you want it, one for a plain-HTTP redirect (8080 by default). On Linux, ports below 1024 need a system installation (root). |
| **Tools** | `sh` and `unzip`, plus `sha256sum`, `shasum` or `openssl` so the installer can check the program. Building from source needs Go 1.26 or newer. |

FileParcel is a single program with no other dependencies: no database server, no web server, no runtime.

### Pick a way to install

| You want to… | Do this |
|---|---|
| Run FileParcel on your own Linux machine, Raspberry Pi or Mac, without `root` | `./install.sh` — a [user service](#user-service-the-default) |
| Start it at boot on a Mac before anyone logs in, give it its own system account, or use a port below 1024 | `sudo ./install.sh` — a [system service](#system-service) |
| Run it in a container | [Docker Compose](#run-fileparcel-in-docker) |
| Start it yourself (OpenRC, runit, s6, tmux, …) | `./install.sh --service none` — [no service](#no-service) |

---

## Download FileParcel

Releases are published on the project's GitHub page, under
[Releases](https://github.com/kpdirectmail/fileparcel/releases/latest). Each release is one zip file,
`fileparcel-vN.zip` (for example `fileparcel-v1.zip`), with a checksum file `fileparcel-vN.zip.sha256` next
to it. Download both into the same folder. The examples below use `fileparcel-v1.zip`; use the version you
downloaded.

### Check the download

Check that the zip arrived complete and unchanged. On Linux:

```sh
sha256sum -c fileparcel-v1.zip.sha256
```

On macOS:

```sh
shasum -a 256 -c fileparcel-v1.zip.sha256
```

Both print `fileparcel-v1.zip: OK` when the file is fine. If they print `FAILED`, download it again.

After unpacking you can also check every file inside against the release's `SHA256SUMS` (on macOS use
`shasum -a 256 -c SHA256SUMS`):

```sh
cd fileparcel-v1 && sha256sum -c SHA256SUMS
```

You do not have to: `install.sh` checks the program it installs against `SHA256SUMS` by itself and stops
if it does not match.

### What is in the zip

```
fileparcel-v1/
├── install.sh  uninstall.sh      the installer and the uninstaller
├── README.md  LICENSE  NOTICE  VERSION
├── SHA256SUMS                    checksums of everything except src/
├── docker-compose.yml            builds and runs the Docker image from src/
├── docs/                         this guide, the user manual and the other documents
├── bin/                          ready-made programs for every supported system:
│     fileparcel-linux-amd64  fileparcel-linux-arm64  fileparcel-linux-arm
│     fileparcel-darwin-amd64  fileparcel-darwin-arm64
└── src/                          the complete source code of this release
```

### Install from source

You can also install from the source code, for example from a clone of the repository:

```sh
git clone https://github.com/kpdirectmail/fileparcel
cd fileparcel
./install.sh
```

There is no `bin/` folder there, so `./install.sh` builds FileParcel for your machine first. That takes a
minute or two (much longer on a Raspberry Pi Zero), needs **internet access** to download the Go modules
FileParcel is built from, and needs Go 1.26 or newer. If you have no Go, or an older one, the repository's own helper
downloads Go into `~/sdk` and checks it against Go's official checksums:

```sh
sh scripts/get-go.sh 1.27.1          # in a git checkout
sh src/scripts/get-go.sh 1.27.1      # in an unpacked release zip
```

A Go installed this way is used even when an older one is on your `PATH`. In a release zip,
`./install.sh --from-source` builds from the zip's `src/` folder instead of using the ready-made program.

---

## Install in three commands

Unpack the zip, go into it and run the installer as your normal user (no `sudo` needed):

```sh
unzip fileparcel-v1.zip
cd fileparcel-v1
./install.sh
```

The installer asks a few questions; press Enter to accept the suggestion in brackets
([the questions](#answer-the-installers-questions)). To accept everything without questions, run
`./install.sh -y` instead.

If your unzip tool dropped the "executable" permission and `./install.sh` says *Permission denied*, run
it with `sh install.sh` instead.

The installer picks the right program for your computer, checks it, installs FileParcel into
`~/.local/share/fileparcel` (on a Mac: `~/Library/Application Support/FileParcel`), starts it as a
service (on Linux it also starts at boot; on a Mac whenever you log in), and prints a summary.

It also links the `fileparcel` command as `~/.local/bin/fileparcel`. If your shell then says
`fileparcel: command not found`, see [the fix](#fileparcel-command-not-found).

### What the installer prints

The summary looks like this (your addresses and names will differ):

```
FileParcel v1 is installed in /home/alice/.local/share/fileparcel
Service: systemd user service, running (start at boot: yes)

Open FileParcel at:
  https://pi.tail1234.ts.net:8443/  Tailscale MagicDNS tailscale0
  https://raspberrypi.local:8443/   Computer name (mDNS)
  https://192.168.1.20:8443/        LAN (eth0)  (recommended)
  https://100.81.12.34:8443/        Tailscale (tailscale0)

  https://192.168.1.20:8443/
  █▀▀▀▀▀█ ▄▀▄ █▀▀▀▀▀█      (a QR code your phone can scan)
  …

Trust the certificate on each device (once):
  https://192.168.1.20:8443/trust
  CA fingerprint (SHA-256): 3A:91:…:C4

Admin account (shown only once - store it in your password manager):
  username: admin
  password: Vq4…
  You must choose a new password at the first sign-in.

Backup identity (shown only once - keep it outside this machine; backups cannot be restored elsewhere without it):
  # FileParcel backup identity, created 2026-09-30T10:03:02Z
  # public key: age1…
  AGE-SECRET-KEY-1…

Command: /home/alice/.local/bin/fileparcel

Firewall: ufw is active; to allow access from your networks run:
  sudo ufw allow from 192.168.1.0/24 to any port 8443,8080 proto tcp
  sudo ufw allow in on tailscale0 to any port 8443 proto tcp

Tailscale:
  for a publicly trusted certificate on pi.tail1234.ts.net, allow FileParcel to use `tailscale cert`:
    sudo tailscale set --operator=alice   (and enable HTTPS certificates in the tailnet admin console)
    then: fileparcel cert tailscale enable
  Share links on the internet: fileparcel network funnel enable

Next steps:
  - open the recommended URL and sign in as admin (you will be asked to choose a new password)
  - install the local CA on each device from https://192.168.1.20:8443/trust to get rid of certificate warnings
  - check everything with "fileparcel doctor"; see "fileparcel --help" for administration from the command line
```

What to do with it:

1. **Save the admin password and the backup identity now**, for example in your password manager. Both
   are shown only this once. Without the backup identity, your backups cannot be restored on another
   machine. (With `--sealed` the summary also shows a *recovery key*: save that too.)
2. **Run the firewall commands** if the summary shows any. They let other devices on your networks
   connect. See [Open the firewall](#open-the-firewall).
3. **Trust the certificate** on each device: open the `/trust` address shown and follow
   [Trust FileParcel's certificate on your devices](#trust-fileparcels-certificate-on-your-devices).
4. **Sign in** at the recommended address: [Sign in for the first time](#sign-in-for-the-first-time).

The list shows the addresses known while installing. Once FileParcel is running it also announces
`fileparcel.local` on your network. To see every address again, with a QR code for each one:

```sh
fileparcel network urls --qr
```

---

## Choose installer options

`install.sh` picks the program for your machine and then runs `fileparcel install` with every option you
give it. Every option works together with `-y` for an installation without questions. You can preview any
installation with `--dry-run`: it shows the plan and changes nothing.

### All install.sh options

**Where and how**

| Option | What it does | Default |
|---|---|---|
| `--dir DIR` | The installation directory; everything FileParcel stores goes here. It must not be your home folder itself or a system folder. | Linux: `~/.local/share/fileparcel` (or `$XDG_DATA_HOME/fileparcel`); as root `/opt/fileparcel`. macOS: `~/Library/Application Support/FileParcel`; as root `/usr/local/fileparcel` |
| `--port N` | HTTPS port. | `8443`, or the next free port if it is taken |
| `--http-port N` | Plain-HTTP port that only redirects to HTTPS. `0` turns it off. | `8080`, or the next free port |
| `--name NAME` | Server name: used for `NAME.local`, the certificate authority's name and the passkey domain. Lowercase letters, digits and `-`. | `fileparcel` |
| `--service user\|system\|none` | Which kind of service to set up. `none` only installs the files. | `user`; `system` when run as root |
| `--boot` / `--no-boot` | Start FileParcel at boot (a Linux user service turns on "lingering" for this). | `--boot` |
| `--no-start` | Register the service but do not start it now. | starts it |
| `--symlink PATH` | Where to link the `fileparcel` command. | `~/.local/bin/fileparcel`; as root `/usr/local/bin/fileparcel` |
| `--no-symlink` | Do not link the `fileparcel` command. | |

**Admin account**

| Option | What it does | Default |
|---|---|---|
| `--admin USER` | Username of the first administrator, the *owner*. | `admin` |
| `--generate-password` | Generate the admin password. It is shown once and must be changed at the first sign-in. | yes, unless you give a password |
| `--admin-password-file F` | Read the admin password from a file. | |
| `--admin-password-stdin` | Read the admin password from standard input. | |
| `--admin-email EMAIL` | The admin's e-mail address, for notifications. | none |

**Security**

| Option | What it does | Default |
|---|---|---|
| `--sealed` | Protect the master key with a passphrase. The server then starts **locked** after every restart until someone unlocks it. | a plain key file (starts unlocked) |
| `--passphrase-file F` | Read that passphrase from a file (needed with `--sealed -y`). | asked |
| `--passphrase-stdin` | Read that passphrase from standard input. | |
| `--access MODE` | Who may connect: `allowlist`, `private` or `any` ([details](#choose-who-may-connect)). `any` lets in every address, including the internet if the port is reachable from there. | `allowlist`: this machine plus the LAN and VPN networks found |
| `--allow CIDR` | Add a network (or a single address) to the allow list. Repeat it for several. | |

**Which program to install**

| Option | What it does |
|---|---|
| `--binary PATH` | Install this `fileparcel` program instead of the bundled one. It is **not** checked against `SHA256SUMS`. |
| `--from-source` | Build FileParcel from the source code (needs Go 1.26 or newer), even when a bundled program exists. |

**Behaviour**

| Option | What it does |
|---|---|
| `-y`, `--yes`, `--non-interactive` | Never ask; use the defaults. |
| `--upgrade` | Only upgrade the installation in `--dir`; fail if there is none. (An existing installation is upgraded anyway.) |
| `--skip-backup` | Upgrade without the pre-upgrade backup. |
| `--force` | Replace a command link or a service registration that belongs to something else; upgrade even if the pre-upgrade backup fails; install an older release over a newer one. |
| `--dry-run` | Show the plan without changing anything. Your inputs are still checked. To preview a system installation, run it with `sudo` too (`sudo ./install.sh --dry-run`): without `sudo` the plan shows your own user's default directory and command link. |
| `-h`, `--help` | Show the help. |

Examples:

```sh
./install.sh                                          # ask the questions
./install.sh -y                                       # all defaults, no questions
./install.sh -y --dir ~/fileparcel --port 9443 --no-boot
./install.sh -y --access private --admin alice --admin-email alice@example.com
printf '%s\n' 'plum-kettle-harbor-47' | ./install.sh -y --admin-password-stdin
./install.sh -y --sealed --passphrase-file ~/fp-passphrase.txt
sudo ./install.sh -y --service system                 # system service with its own "fileparcel" account
./install.sh --dry-run                                # only show the plan
```

Every choice can be changed later: ports and the name with `fileparcel config set`, the access policy
with `fileparcel network`, the master key mode with `fileparcel keys seal` / `keys unseal`.

### Answer the installer's questions

Without `-y` the installer asks these questions. Press Enter to accept the value in brackets.

1. **Install directory** — where everything will live. Pick a disk with enough space for your files.
2. **HTTPS port** — `8443`, unless that port is in use (then the next free one is offered).
3. **HTTP port that redirects to HTTPS (0 = none)** — `8080`. This port only ever redirects to HTTPS; it
   never serves files.
4. **Start FileParcel automatically at boot?** — yes. (Not asked with `--service none`.)
5. **Admin username** — `admin`.
6. **Generate a secure password for admin?** — yes. Answer no to type your own (twice). It must have at
   least 12 characters and must not be a common password or contain the username.
7. **Master-key passphrase** — only with `--sealed`, typed twice.
8. The installer shows its plan (directory, ports, service, command link, access policy) and asks
   **Install now?**

The server name, the sealed mode and the access policy are not asked; set them with `--name`, `--sealed`
and `--access`/`--allow`.

### What the installer does

1. Finds out your operating system and processor, picks `bin/fileparcel-<os>-<arch>` from the zip and
   checks it against `SHA256SUMS` (or builds FileParcel from source when there is no ready-made program).
   On a Mac it also removes the download quarantine flag.
2. Creates the installation directory with tight permissions and sets it up: the master key, the
   database, the encryption keys, a local certificate authority (CA) and the server's certificate, the
   default settings, the network access policy (your LAN and VPN networks), the owner account and the
   backup key pair.
3. Copies the program, `uninstall.sh`, `docs/` and `VERSION` into it.
4. Links the `fileparcel` command into your `PATH`. It never replaces a file or link it did not create
   (unless you pass `--force`), and it warns you when the link's folder is not on your `PATH`.
5. Registers and starts the service, and waits until FileParcel answers.
6. Looks for a firewall (ufw, firewalld, nftables, the macOS application firewall) and prints the exact
   commands that open FileParcel's ports for your networks. **FileParcel never changes the firewall
   itself.**
7. Prints the [summary](#what-the-installer-prints).

Everything the installer set up outside the installation directory (the service, the command link,
lingering, a system account) is written down in `<installation directory>/service/installed.json`. The
uninstaller uses that list to remove exactly those things.

If something fails after step 2 (for example the service cannot be registered), the summary with the
password and the backup identity is still printed, because they cannot be shown again. Fix the problem
and run the installer again on the same directory: it finishes the job.

---

## Run it as a user or a system service

### User service (the default)

`./install.sh` without `sudo` sets up a service that runs as **you**:

- **Linux:** a *systemd user service*. With start at boot (the default), the installer runs
  `loginctl enable-linger` for your user, so FileParcel starts when the machine boots and keeps running
  after you log out. The unit file lives in the installation directory
  (`service/fileparcel.service`) and is linked into systemd.
- **macOS:** a *LaunchAgent* (`~/Library/LaunchAgents/com.fileparcel.server.plist`). A LaunchAgent only
  runs while you are logged in. For a Mac that should serve files before anyone logs in, use a system
  service. Without start at boot (`--no-boot`, or `fileparcel service disable-boot` later) the file is kept
  in `~/Library/Application Support/com.fileparcel.server/` instead, where macOS does not load it at login.
- The server runs as your user, with `umask 077`: other users on the machine cannot read what it writes.
- On Linux, FileParcel can only use ports 1024 and above.

### System service

`sudo ./install.sh` sets up a service for the whole machine:

- The default directory is `/opt/fileparcel` (macOS: `/usr/local/fileparcel`), and the command is linked
  as `/usr/local/bin/fileparcel`.
- **Linux:** FileParcel runs as its own system account, `fileparcel` (no login shell), from the unit
  `/etc/systemd/system/fileparcel.service`. The unit locks the service down with systemd's sandboxing
  (`ProtectSystem=strict`, `PrivateTmp`, `PrivateDevices`, `NoNewPrivileges`, a system-call filter and
  more): it can only write inside its installation directory. The program itself (`bin/`) and
  `uninstall.sh` stay owned by root. The installation directory belongs to `root:fileparcel` with mode
  `1770`: the service can write in it, but cannot replace root's files.
- Because of that sandbox, a backup copy folder outside the installation directory (the `backup.copy_to`
  setting) has to be allowed once with a systemd drop-in: see
  [Backups and restore](FILEPARCEL.md#backups-and-restore) in the user manual.
- **macOS:** a *LaunchDaemon* (`/Library/LaunchDaemons/com.fileparcel.server.plist`) running as the
  account `_fileparcel`. It starts at boot without anyone logging in.
- Ports below 1024 (such as 443) are allowed. On Linux, if you change to or from such a port later,
  apply it with `sudo fileparcel service install --start` rather than a plain restart.
- Run admin commands with `sudo`, for example `sudo fileparcel status` (or as the service account:
  `sudo -u fileparcel fileparcel status`): the admin connection only accepts root and the service account.
  A command run with `sudo` while the server is stopped (a restore, key and certificate commands,
  `config edit`) gives the files it wrote back to the service account, and `sudo fileparcel doctor --fix`
  repairs ownership that was changed by hand.

### No service

`./install.sh --service none` installs and sets up the files but registers nothing. Start the server
yourself (from your own supervisor, `tmux`, …):

```sh
~/.local/share/fileparcel/bin/fileparcel serve --home ~/.local/share/fileparcel
```

Stop it with Ctrl-C in its terminal, with your supervisor's stop command, or from any terminal with:

```sh
kill $(cat ~/.local/share/fileparcel/run/fileparcel.pid)   # stops the server cleanly
```

(`fileparcel service stop` only works for a registered service.) Wherever this guide says to stop the
service, stop a server you started by hand this way instead.

FileParcel refuses to run as root unless you add `--allow-root`. On Linux systems without systemd the
installer chooses "no service" by itself (see
[Install on Alpine or another system without systemd](#install-on-alpine-or-another-system-without-systemd)).

### Start, stop and restart the service

```sh
fileparcel service status     # is the service registered and running?
fileparcel service start
fileparcel service stop
fileparcel service restart
fileparcel status             # the server's own view: version, addresses, keys, storage
```

To start at boot or stop doing so:

```sh
fileparcel service enable-boot
fileparcel service disable-boot
```

On Linux you can also use systemd directly: `systemctl --user status fileparcel` for a user service,
`sudo systemctl status fileparcel` for a system service.

---

## Notes for your operating system

### Install on Debian or Ubuntu

It works out of the box. If `ufw` is active, other machines cannot connect until you add the rules the
installer prints ([ufw](#ufw-debian-ubuntu-raspberry-pi-os)). Desktop installs usually run Avahi, which
FileParcel uses to announce `fileparcel.local`; on servers without Avahi, FileParcel uses its own
responder.

### Install on a Raspberry Pi

- Use the **64-bit** Raspberry Pi OS on a Pi 3, 4 or 5, or the 32-bit one on a Pi 2, 3 or 4. The
  installer picks the right program by itself.
- A Pi 4 and older have no hardware AES, so FileParcel automatically encrypts with ChaCha20-Poly1305,
  which is much faster there.
- If you store many files, put the installation directory on an SSD or USB disk rather than the SD card.
  A disk mounted under `/mnt` belongs to root, so first create the folder and give it to yourself, then
  install into it:

  ```sh
  sudo mkdir -p /mnt/ssd/fileparcel && sudo chown "$USER": /mnt/ssd/fileparcel
  ./install.sh --dir /mnt/ssd/fileparcel
  ```

- Keep backups on another disk or machine (the `backup.copy_to` setting, see the
  [user manual](FILEPARCEL.md#backups-and-restore)).
- A Pi Zero or Pi 1 (ARMv6) needs FileParcel built from source. `install.sh` does that by itself when it
  finds the source code (the zip's `src/` folder) and Go 1.26 or newer. It needs internet access and
  takes a while on such a small Pi. To get Go, run this in the unpacked zip, then `./install.sh`:

  ```sh
  sh src/scripts/get-go.sh 1.27.1
  ```

### Install on Fedora, RHEL, Rocky or AlmaLinux

`firewalld` is active by default: run the commands the installer prints
([firewalld](#firewalld-fedora-rhel)).

**SELinux.** A user installation in your home folder works as it is. A system installation in the default
directory `/opt/fileparcel` gets the right labels by itself. If you copied or moved files into it by hand
and the service no longer starts, give them their labels back:

```sh
sudo restorecon -Rv /opt/fileparcel
```

A system installation in **another** directory (here `/srv/fileparcel`) needs one more step, or systemd
may not be allowed to run the program: mark its `bin/` folder as holding programs, then relabel the
directory (`semanage` is in the `policycoreutils-python-utils` package):

```sh
sudo semanage fcontext -a -t bin_t '/srv/fileparcel/bin(/.*)?'
sudo restorecon -Rv /srv/fileparcel
```

**`sudo: fileparcel: command not found`.** On RHEL, Rocky and AlmaLinux, `sudo` only searches
`/usr/sbin` and `/usr/bin`, not `/usr/local/bin` where a system installation links the command. Use the
full path there, for example `sudo /usr/local/bin/fileparcel status`.

### Install on Arch Linux or Manjaro

Install `avahi` and `nss-mdns` if other machines should resolve `.local` names. FileParcel falls back to
its own mDNS responder when Avahi is not running.

### Install on Alpine or another system without systemd

Without systemd the installer uses `--service none`. The same happens where `systemctl` exists but
systemd is not running (WSL without systemd, most containers); asking for `--service user` or `system`
there is an error.

Start FileParcel from OpenRC, runit or s6 with:

```sh
/path/to/installation/bin/fileparcel serve --home /path/to/installation
```

It logs to `<installation directory>/logs` and to standard error. If your supervisor restarts the program
whenever it exits (runit, s6, OpenRC's `supervise-daemon` with respawn), set `FILEPARCEL_SUPERVISED=1`
in its environment: a restart request then exits with code 75 instead of restarting in place. Do not set
it when nothing restarts the process, or a restart request would stop the server.

### Install on a Mac

- Run `./install.sh` in Terminal. The installer removes the download quarantine flag from the program (it
  is not notarised; Apple-silicon programs are ad-hoc signed).
- A user installation lives in `~/Library/Application Support/FileParcel`. Do not choose a folder in
  `~/Documents`, `~/Desktop` or `~/Downloads`: macOS guards them with privacy prompts that a background
  service cannot answer.
- `fileparcel.local` is announced through the Mac's own Bonjour.
- If the application firewall is on, allow incoming connections when asked, or run the command the
  installer prints ([macOS application firewall](#macos-application-firewall)).
- A user installation runs only while you are logged in. For a Mac that serves files from boot, install
  with `sudo ./install.sh`.

### Install on Windows

FileParcel does not run on Windows directly. Either:

- use **Docker Desktop** ([Docker](#run-fileparcel-in-docker); use the `ports:` section of the compose
  file), or
- install the Linux version inside **WSL 2**. For the automatic service, WSL must run systemd: add
  `systemd=true` to the `[boot]` section of `/etc/wsl.conf`, then run `wsl --shutdown` in Windows.
  Without that, the installer installs without a service. Other devices reach FileParcel in WSL only if
  you forward the port from Windows or run Tailscale inside WSL.

---

## Run FileParcel in Docker

The image is small and locked down: just the FileParcel program on a minimal base, with no shell, running
as user and group `65532`. Everything it stores is in the `/data` volume. It uses ports 8443 (HTTPS) and
8080 (HTTP redirect) and has a built-in health check.

### Start it with Docker Compose

`docker-compose.yml` is at the top of the release zip (it builds the image from `src/`). Run these
commands next to it, on Linux:

```sh
mkdir -p fileparcel-data && sudo chown 65532:65532 fileparcel-data   # the container runs as uid 65532
mkdir -m 700 secrets
openssl rand -base64 18 > secrets/fp_admin_password.txt              # the admin password
chmod 644 secrets/fp_admin_password.txt                              # readable by uid 65532
docker compose up -d --build
docker compose logs fileparcel                                       # the addresses and the CA fingerprint
```

Then open `https://<this machine>:8443/`, sign in as `admin` with the password from
`secrets/fp_admin_password.txt`, and change it (Settings → Security). (When the container gets no
password file, as with the plain `docker run` below, FileParcel generates a password and writes it to the
log once.)

What the compose file sets up:

- **Host networking** (`network_mode: host`), so FileParcel sees the real addresses of your devices (the
  access policy needs them) and can announce `fileparcel.local`.
- **Your data** in `./fileparcel-data` (mounted as `/data`). Back it up like any installation directory.
- **The admin account** `admin` (`FILEPARCEL_ADMIN_USER`) with the password from the secret file
  (`FILEPARCEL_ADMIN_PASSWORD_FILE`) and, if you add the line, an e-mail address (`FILEPARCEL_ADMIN_EMAIL`).
  They are used only on the very first start, when the container creates the installation
  (`fileparcel serve --init-if-missing`).
- A read-only container with all capabilities dropped, `no-new-privileges`, `restart: unless-stopped`, and
  40 seconds to shut down cleanly (`stop_grace_period`).
- Optional lines you can uncomment: the host's D-Bus socket (announce `fileparcel.local` through the
  host's Avahi) and the host's `tailscaled.sock` (fetch `*.ts.net` certificates; allow uid 65532 with
  `sudo tailscale set --operator=…`).
- Server settings from `fileparcel.toml` can be set as environment variables, for example
  `FILEPARCEL_SERVER_HTTPS_PORT: "9443"` ([all of them](FILEPARCEL.md#environment-variables)).

### Use Docker Desktop on a Mac or Windows

Docker Desktop has no host networking. In `docker-compose.yml`, delete the `network_mode: host` line and
uncomment the `ports:` section. FileParcel then sees every connection as coming from Docker's gateway, so
let private networks in:

```sh
docker compose exec fileparcel fileparcel network mode private
```

### Start it with plain Docker

The build context is the source tree (`src` in the release zip). Create the data folder for the
container's user first, as in the Compose steps; otherwise Docker creates it as root and FileParcel
cannot write to it:

```sh
mkdir -p fileparcel-data && sudo chown 65532:65532 fileparcel-data   # the container runs as uid 65532
docker build -t fileparcel src
docker run -d --name fileparcel --network host \
  -v "$PWD/fileparcel-data:/data" \
  -e FILEPARCEL_ADMIN_USER=admin \
  --read-only --tmpfs /tmp --cap-drop ALL --security-opt no-new-privileges:true \
  --stop-timeout 40 --restart unless-stopped fileparcel
docker logs fileparcel                  # the generated admin password, the addresses, the CA fingerprint
```

To build images for several processors at once (in a git checkout, use `.` instead of `src`):

```sh
docker buildx build --platform linux/amd64,linux/arm64,linux/arm/v7 -t fileparcel src
```

### Run admin commands in the container

Every `fileparcel` command works inside the container:

```sh
docker compose exec fileparcel fileparcel status
docker compose exec fileparcel fileparcel ca fingerprint
docker compose exec fileparcel fileparcel user create bob --generate-password
```

In a container there is no service, no command link and no installer: `fileparcel install`,
`uninstall`, `upgrade` and `service` are not used. Tailscale Funnel and Serve are not supported in a
container in this version.

---

## Open the firewall

FileParcel checks every connection against its own [access policy](#choose-who-may-connect), but a host
firewall usually blocks the ports before FileParcel ever sees them. The installer and `fileparcel doctor`
print the **exact** commands for your machine, your networks and your ports. Use those; the examples here
assume the LAN `192.168.1.0/24`, Tailscale and the default ports.

Only open FileParcel to the internet on purpose: never forward its ports on your router unless you really
mean to (for share links on the internet, [Tailscale Funnel](#put-share-links-on-the-internet-tailscale-funnel)
needs no open port at all).

### ufw (Debian, Ubuntu, Raspberry Pi OS)

```sh
sudo ufw allow from 192.168.1.0/24 to any port 8443,8080 proto tcp   # your LAN
sudo ufw allow in on tailscale0 to any port 8443 proto tcp           # Tailscale
sudo ufw allow in on wg0 to any port 8443 proto tcp                  # a WireGuard tunnel
sudo ufw status numbered                                             # check the rules
```

### firewalld (Fedora, RHEL)

```sh
sudo firewall-cmd --permanent --add-rich-rule='rule family="ipv4" source address="192.168.1.0/24" port port="8443" protocol="tcp" accept'
sudo firewall-cmd --permanent --add-rich-rule='rule family="ipv4" source address="192.168.1.0/24" port port="8080" protocol="tcp" accept'
zone=$(firewall-cmd --get-zone-of-interface=tailscale0 2>/dev/null) || zone=$(firewall-cmd --get-default-zone); sudo firewall-cmd --permanent --zone="$zone" --add-port=8443/tcp
sudo firewall-cmd --reload
```

The third line opens the port in the zone the Tailscale interface belongs to. Often it belongs to none
(NetworkManager leaves `tailscale0` alone); firewalld then handles its traffic in the default zone, and
the line opens the port there.

### nftables

```sh
sudo nft insert rule inet filter input ip saddr 192.168.1.0/24 tcp dport '{ 8443, 8080 }' accept
sudo nft insert rule inet filter input iifname "tailscale0" tcp dport 8443 accept
```

`insert` puts the rules at the start of the chain (`add` would put them after a drop or reject rule, where
they never match). Adjust the table and chain names (`inet filter input`) to your rule set. To keep the
rules after a reboot, add them to `/etc/nftables.conf` before any drop or reject rule of the input chain.

### macOS application firewall

Allow FileParcel when macOS asks, or run (for a user installation):

```sh
sudo /usr/libexec/ApplicationFirewall/socketfilterfw --add "$HOME/Library/Application Support/FileParcel/bin/fileparcel"
sudo /usr/libexec/ApplicationFirewall/socketfilterfw --unblockapp "$HOME/Library/Application Support/FileParcel/bin/fileparcel"
```

### pf

pf is off on macOS unless you (or a tool) turned it on, and FileParcel does not print pf rules. If you
run pf, add a rule like this to your rule set before any rule that blocks incoming traffic, then reload
it:

```
pass in quick proto tcp from 192.168.1.0/24 to any port { 8443 8080 }
```

```sh
sudo pfctl -f /etc/pf.conf
```

### The mDNS port

UDP port 5353 is only needed when FileParcel runs its **own** mDNS responder (Linux without Avahi). With
Avahi, and on a Mac, the system handles mDNS. The installer adds the rule to its list when it is needed,
for example `sudo ufw allow from 192.168.1.0/24 to any port 5353 proto udp` or
`sudo firewall-cmd --permanent --add-service=mdns`.

### VPNs and the firewall

The printed rules open the port on the VPNs your devices come in through (Tailscale, Headscale,
WireGuard, ZeroTier, …) by their interface names. Outgoing-only VPNs such as NordVPN or Mullvad get no
rule ([why](#over-a-vpn)). Tailscale Funnel and Serve need no rule at all: their traffic reaches
FileParcel through Tailscale on the same machine.

---

## Trust FileParcel's certificate on your devices

FileParcel always uses HTTPS. Unless you set up a publicly trusted certificate (see
[Skip this step](#skip-this-step-with-a-publicly-trusted-certificate)), its certificate comes from a
**local certificate authority (CA)** that the installer created for your server. Browsers warn about it
until you tell each device to trust that CA. You do this once per device.

Trusting it is safe: the CA can only vouch for local names (`.local`, `localhost`, `.ts.net`, your
machine's name and the names you had set before the CA was created), private addresses and your own
network's IPv6 range, so it can never be used to fake a public web site. Its private key is encrypted.

It is more than cosmetic: **passkeys, and installing FileParcel as an app on your phone or computer
(with its offline start page), only work with a trusted certificate**. Browsers never remember an
"accept the risk" exception for them.

### Get the certificate and check its fingerprint

On each device, open `https://<server>:8443/trust` (the address the installer printed). The first time,
the browser warns about the certificate: accept it on this page only. The page shows the fingerprint,
download buttons and instructions for the device you are using. The downloads are:

| Address | File | For |
|---|---|---|
| `https://<server>:8443/trust/ca.crt` | `fileparcel-ca.crt` | Windows, Mac, Android, Firefox |
| `https://<server>:8443/trust/ca.pem` | `fileparcel-ca.pem` | Linux |
| `https://<server>:8443/trust/ca.mobileconfig` | `fileparcel-ca.mobileconfig` | iPhone and iPad (a Mac can use it too) |

(The file names start with your server name; `fileparcel` is the default.)

**Always compare the fingerprint** your device shows with the one on the server:

```sh
fileparcel ca fingerprint
```

On the server the certificate is also in the installation directory, as `certs/ca/ca.crt`. You can save
it in any format, and print these instructions in the terminal:

```sh
fileparcel ca export --format der -o fileparcel-ca.crt   # or --format pem, --format mobileconfig
fileparcel ca trust-help --os ios                        # ios, android, macos, windows, linux, firefox
```

### Trust it on Windows

1. Download `https://<server>:8443/trust/ca.crt`.
2. Double-click it → **Install Certificate** → **Local Machine** → *Place all certificates in the
   following store* → **Trusted Root Certification Authorities** → Finish.

Or, in a Command Prompt or PowerShell opened as Administrator, in the folder of the download:

```powershell
certutil -addstore -f Root fileparcel-ca.crt
```

### Trust it on a Mac

1. Download `https://<server>:8443/trust/ca.crt`.
2. Double-click it; Keychain Access opens. Add it to the **System** keychain.
3. Double-click *FileParcel Local CA* → **Trust** → *When using this certificate*: **Always Trust**.
   Close the window and confirm with your password.

Or in Terminal, in the folder of the download:

```sh
sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain fileparcel-ca.crt
```

### Trust it on an iPhone or iPad

1. Open `https://<server>:8443/trust` in **Safari** (other browsers cannot install profiles), tap
   **Download profile** and then **Allow**.
2. Settings → General → **VPN & Device Management** → the *FileParcel CA* profile → **Install**.
3. Settings → General → About → **Certificate Trust Settings** → turn on full trust for the FileParcel
   Local CA. Without this step the certificate is **not** trusted.

### Trust it on Android

1. Download `https://<server>:8443/trust/ca.crt` (or scan the QR code on the `/trust` page).
2. Settings → Security & privacy → More security settings → Encryption & credentials → **Install a
   certificate** → **CA certificate** → *Install anyway*, and pick the downloaded file. Menu names vary
   by phone maker; search Settings for "CA certificate".
3. Chrome uses it right away. Firefox for Android needs one more step: Settings → About Firefox → tap the
   logo five times → Secret settings → *Use third party CA certificates*.

### Trust it on Linux

Download the certificate and check its fingerprint:

```sh
curl -fsSLk https://<server>:8443/trust/ca.pem -o fileparcel-ca.crt
openssl x509 -noout -fingerprint -sha256 -in fileparcel-ca.crt
```

Add it to the system (used by curl and most programs). On Debian, Ubuntu and Raspberry Pi OS:

```sh
sudo cp fileparcel-ca.crt /usr/local/share/ca-certificates/fileparcel-ca.crt
sudo update-ca-certificates
```

On Fedora and RHEL:

```sh
sudo cp fileparcel-ca.crt /etc/pki/ca-trust/source/anchors/ && sudo update-ca-trust
```

On Arch and other systems with p11-kit:

```sh
sudo trust anchor --store fileparcel-ca.crt
```

Chrome, Chromium and Brave on Linux keep their own list (the `certutil` command comes with the
`libnss3-tools` package on Debian and Ubuntu). Start the browser once first, so that the list exists, then:

```sh
certutil -d sql:$HOME/.pki/nssdb -A -t "C,," -n "FileParcel Local CA" -i fileparcel-ca.crt
```

Chromium installed as a snap (the default on Ubuntu) keeps its list elsewhere; use
`-d sql:$HOME/snap/chromium/current/.pki/nssdb` in the command instead.

### Trust it in Firefox

Firefox keeps its own list on every system:

1. Download `https://<server>:8443/trust/ca.crt`.
2. Settings → Privacy & Security → Certificates → **View Certificates** → **Authorities** → **Import…** →
   pick the file → tick *Trust this CA to identify websites* → OK.

On Windows and macOS you can instead let Firefox use the system's list: open `about:config` and set
`security.enterprise_roots.enabled` to `true`.

### Skip this step with a publicly trusted certificate

Devices trust these without any setup:

- **A Tailscale certificate** for your machine's `*.ts.net` name. Turn on *HTTPS certificates* in the
  Tailscale admin console (DNS page), let FileParcel use Tailscale
  (`sudo tailscale set --operator=$USER`), then run `fileparcel cert tailscale enable`. Headscale cannot
  issue these.
- **Let's Encrypt** (or another ACME CA) for a domain of your own: `fileparcel cert acme enable`.
- **Your own certificate**: `fileparcel cert upload --cert fullchain.pem --key privkey.pem`.

Details are in the user manual under [Certificates and TLS](FILEPARCEL.md#certificates-and-tls).

---

## Sign in for the first time

1. **Sign in.** Open the recommended address from the installer's summary and sign in as `admin` with
   the printed password. If the installer generated it, you are asked to choose a new one right away (at
   least 12 characters by default); until you do, only your own settings work.
2. **Set up two-factor authentication.** Administrators must have it (the setting `auth.require_2fa`,
   default `admins`, which also covers custom roles with server permissions). Scan the QR code with an
   authenticator app (Aegis, 2FAS, Google Authenticator, 1Password, Bitwarden, …), type the code, and
   **save the 10 recovery codes** somewhere safe. If your device supports passkeys, add one too (needs a
   [trusted certificate](#trust-fileparcels-certificate-on-your-devices)). You find all of this later
   under Settings → Security.
3. **Keep the backup identity safe.** If you did not save it from the installer's summary, download it
   now: Admin → Backups → **Export identity…**. Without it, backups cannot be restored on another
   machine.
4. **Sealed master key only:** keep the recovery key the installer printed. It is the only way in if you
   forget the passphrase. (No longer have it? `fileparcel keys recovery-key` makes a new one and shows it
   once.)
5. **Check who may connect.** Admin → Network & VPN shows the addresses, the network interfaces and the
   access policy. Add networks that should be allowed ([Choose who may connect](#choose-who-may-connect)).
6. **Invite people.** Admin → Invites → **New invitation** creates a link people use to make their own
   account (you can also e-mail it, if e-mail is set up). Or add an account yourself: Admin → Users →
   **New user**. On the command line:

   ```sh
   fileparcel invite create --expires 7d --qr                          # a link for one person, with a QR code
   fileparcel user create alice --generate-password                    # an account, with a password shown once
   fileparcel user create bob --email bob@example.com --generate-password
   ```

7. **Create groups** for shared team folders. Every group gets a team folder, `/Team/<group>`. Admin →
   Groups → **New group**, or:

   ```sh
   fileparcel group create Family
   fileparcel group add-member Family alice bob
   fileparcel group add-member Family alice --manager                  # managers can also share the folder
   ```

8. **Create roles** if the built-in ones (Owner, Admin, Member, Guest) are not enough — for example a
   helpdesk that may reset passwords, or contractors who see one folder. Admin → Roles → **New role**,
   or:

   ```sh
   fileparcel role create helpdesk --from member --add users.manage,users.credentials --description "Resets passwords"
   fileparcel user set-role bob helpdesk
   fileparcel role create contractors --base guest                     # no files of their own
   fileparcel group create Design                                      # a team folder, /Team/Design
   fileparcel access grant /Team/Design --role contractors --level view
   ```

   `fileparcel role permissions` lists every permission. The user manual explains roles in
   [Roles and permissions](FILEPARCEL.md#roles-and-permissions).
9. **Run the doctor** once. It checks the whole installation and says what is left to do (firewall, start
   at boot, backups, …):

   ```sh
   fileparcel doctor
   ```

Scheduled, encrypted backups are on from the start: every night at 03:00 a small one without the file
contents, and every Sunday at 04:00 a full one. They are kept in the installation directory, so keep a
copy on another disk too: see [Backups and restore](FILEPARCEL.md#backups-and-restore).

---

## Reach FileParcel from other devices

### On your home network

Every device on your LAN or Wi-Fi can use the server's IP address, for example
`https://192.168.1.20:8443/`. This always works. Show every address, with QR codes for phones:

```sh
fileparcel network urls --qr
```

FileParcel also announces **`https://fileparcel.local:8443/`** on your network (mDNS, also called
Bonjour), so you do not have to remember the IP address. It uses Avahi on Linux when it runs, Bonjour on
a Mac, and otherwise its own responder (then UDP port 5353 must be open,
[see above](#the-mdns-port)).

- `.local` names work on macOS, iPhone and iPad, Windows 10 and 11, Linux desktops with `nss-mdns`, and
  Android 12 or newer in most browsers. Older Android versions and some apps do not resolve them: use the
  IP address or scan the QR code.
- `.local` names do not cross routed VPNs (Tailscale, WireGuard, NetBird, Nebula, OpenVPN): use the VPN
  address or the MagicDNS name there.
- If another device on the network already uses `fileparcel.local`, FileParcel switches to
  `fileparcel-2.local` by itself.

To check or change the name:

```sh
fileparcel network mdns status
fileparcel network mdns name files        # announce files.local instead
fileparcel network mdns disable
```

How the name is published, what happens on a name collision and the other mDNS modes:
[.local names and mDNS](FILEPARCEL.md#local-names-and-mdns) in the user manual.

### Choose who may connect

FileParcel listens on every network interface, but only talks to devices its **access policy** allows.
Anyone else is disconnected before the HTTPS connection even starts.

| Mode | Who may connect |
|---|---|
| `allowlist` (default) | This machine, plus the networks in the allow list. The installer fills it with your LAN and Wi-Fi networks and the ranges of the VPNs your devices come in through. |
| `private` | This machine and every private and VPN address range (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `100.64.0.0/10`, `fc00::/7`, …), plus the allow list. |
| `any` | Every address. Only for servers you deliberately put on the internet. |

The deny list always wins, and the server itself (`127.0.0.1`, `::1`) is always allowed, so the command
line always works.

```sh
fileparcel network                          # addresses, VPNs and the policy at a glance
fileparcel network allow add 10.8.0.0/24    # let a network in
fileparcel network deny add 192.168.1.66    # block one device
fileparcel network mode private
```

A change that would lock out the device you are using is refused unless you confirm it (`--force`). From
the server itself you can always repair the policy on the command line. The full rules, including reverse
proxies and the strict host check, are under
[Network, VPNs and the access policy](FILEPARCEL.md#network-vpns-and-the-access-policy) in the user manual.

### Over a VPN

FileParcel recognises VPNs and decides, for each one, whether other devices can reach the server through
it. VPNs your devices come in through get their addresses listed, put into the certificate, added to the
allow list at installation, and a firewall rule in the installer's summary. VPNs that only carry this
machine's *outgoing* traffic get none of that: nobody connects *in* through them, and allowing their
range would let strangers on the VPN provider's network in.

| Kind | VPNs | Allowed at installation |
|---|---|---|
| **Devices reach this server** | Tailscale, Headscale, ZeroTier, NetBird, Nebula, Netmaker, innernet, Husarnet, NordVPN Meshnet | yes |
| **A tunnel of unknown kind** (treated the same) | WireGuard, OpenVPN, IPsec, tinc, SoftEther, other TUN/TAP devices | its subnet |
| **Outgoing only** | NordVPN, Mullvad, Proton VPN, Cloudflare WARP, Cisco Secure Client, GlobalProtect, Twingate, the Firezone client, and any tunnel that carries your internet traffic | no |
| **Public overlay** | Yggdrasil | no (allowing it asks first) |

See what FileParcel found, and let a VPN in:

```sh
fileparcel network vpn list                # the VPNs, their ranges and whether they may connect
fileparcel network vpn allow tailscale     # let the devices of a VPN connect
fileparcel network vpn remove wg0          # stop letting them in
fileparcel network interfaces              # every interface and how it was classified
```

Admin → Network & VPN shows the same, with a button per VPN. Every interface name and address range
FileParcel looks for, and what each kind means, is listed under
[Access over a VPN](FILEPARCEL.md#access-over-a-vpn) in the user manual.

#### Tailscale

Works out of the box. The installer allows the Tailscale ranges (`100.64.0.0/10` and
`fd7a:115c:a1e0::/48`). Your devices use the server's Tailscale address, or its MagicDNS name
(`https://<machine>.<tailnet>.ts.net:8443/`), which is also in the local certificate. Three extras:

- A **publicly trusted certificate** for the MagicDNS name, so devices need no CA:
  [Skip this step](#skip-this-step-with-a-publicly-trusted-certificate).
- An address **without a port** for your tailnet: [Tailscale Serve](#give-your-tailnet-an-address-without-a-port-tailscale-serve).
- **Share links on the internet**: [Tailscale Funnel](#put-share-links-on-the-internet-tailscale-funnel).

The range `100.64.0.0/10` is shared with NetBird, NordVPN Meshnet, Cloudflare WARP and some internet
providers. If your server has such an address from another source, narrow the allow list to your own
devices.

#### Headscale

Treated like Tailscale and labelled with its control server. With Headscale's default address prefixes
the Tailscale ranges are allowed. With **custom prefixes**, nothing is guessed: add yours (the `prefixes`
in Headscale's `config.yaml`):

```sh
fileparcel network allow add 100.100.0.0/16
```

Headscale cannot issue `ts.net` certificates and has no Funnel. Its MagicDNS names live under your own
`base_domain`. The local certificate covers that name only if the machine was already on Headscale when
FileParcel was installed; otherwise use the IP address, or create a new CA with `fileparcel ca regenerate`
(every device must then trust the new one).

#### WireGuard

The tunnel's subnet is allowed at installation; connect to the server's tunnel address. A tunnel with a
single-address (`/32`) setup has no subnet to allow, so add your tunnel network yourself:

```sh
fileparcel network allow add 10.8.0.0/24
```

If your VPN has a DNS name for the server, add it with
`fileparcel config set network.extra_hosts files.vpn.example`. A name outside `.local` and `.ts.net`
added after installation needs a new CA (`fileparcel ca regenerate`) before the certificate can include
it.

#### ZeroTier

Its subnet is allowed at installation. ZeroTier works like one big LAN, so `.local` names can work across
it too:

```sh
fileparcel config set mdns.zerotier true
```

#### NetBird

Its subnet is allowed at installation. NetBird uses `100.64.0.0/10` addresses like Tailscale.

#### Nebula, Netmaker, innernet, Husarnet, tinc, NordVPN Meshnet, OpenVPN and IPsec

Their subnets are allowed at installation (Husarnet: `fc94::/16`). NordVPN counts as outgoing only, except
**Meshnet**: while NordVPN carries a Meshnet address, that address is offered. OpenVPN and IPsec tunnels
count as outgoing only while they carry your internet traffic.

#### When FileParcel gets a VPN wrong

Detection goes by product names, address ranges and routes, so a tunnel with an unusual name can land in
the wrong group. Correct it:

```sh
fileparcel network vpn role wg0 mesh       # devices can reach this server through wg0
fileparcel network vpn role tun3 egress    # outgoing only
fileparcel network vpn role wg0 auto       # back to automatic detection
```

Or use the ⋮ menu of the interface on Admin → Network & VPN. The certificate is reissued by itself when
the server's addresses change; devices that trust the CA notice nothing.

### Give your tailnet an address without a port (Tailscale Serve)

Tailscale Serve gives every device in your tailnet `https://<machine>.<tailnet>.ts.net/`: no port
number, a certificate every browser trusts, the whole web app. Only your tailnet can use it, and the
access policy still applies to each device's real address.

What you need: Tailscale running on the server, **MagicDNS** and **HTTPS certificates** turned on in the
Tailscale admin console (DNS page), and permission for FileParcel to configure Tailscale:

```sh
sudo tailscale set --operator=$USER
```

For a system installation, name the account FileParcel runs as instead of `$USER`: `fileparcel` on
Linux, `_fileparcel` on a Mac. Tailscale has only one operator per machine.

Then turn it on:

```sh
fileparcel network tailscale-serve enable              # tailnet port 443
fileparcel network tailscale-serve enable --port 4443  # or another port
fileparcel network tailscale-serve status              # the address and every check, with how to fix it
fileparcel network tailscale-serve disable             # turn it off
```

Or use the card *Tailnet address without port (Tailscale Serve)* on Admin → Network & VPN.

### Put share links on the internet (Tailscale Funnel)

Tailscale Funnel publishes FileParcel at `https://<machine>.<tailnet>.ts.net/` on the **whole
internet**, without opening a port on your router and without a firewall rule. Tailscale provides a
certificate every browser trusts, and your home address stays hidden. **It is off until you turn it on.**

#### Choose what the internet can reach

| Mode | What people on the internet reach |
|---|---|
| **Off** (default) | Nothing. |
| **Share links only** (recommended; `--mode shares`) | The share links and file requests you create, and the files their pages load. Every other address — the sign-in page, the API, the admin pages — answers "not found", and nobody can sign in there. |
| **Full app, sign-in required** (`--mode app`) | The whole web app with its sign-in page, except setup, unlocking, the certificate page and — unless you allow it — the admin pages. Only accounts with two-factor authentication can sign in over this address. |

In *Full app* mode, people without two-factor authentication (for example a new account you just
created) cannot sign in over the internet address. The sign-in page says so. They sign in once at the
address they use at home or over your VPN, and set up an authenticator app under **Settings → Security**;
after that the internet address works for them too. Someone you send a personal invitation link to (one
use, the default) can accept it over the internet address and is taken straight to setting up an
authenticator app. A shared link with several uses creates the account, but its first sign-in has to
happen at home or over your VPN.

Share links stay secret links: anyone who has one can open it. Use passwords, expiry dates and download
limits for sensitive files. Visitors from the internet are rate-limited, and the access policy's deny
list applies to their real addresses.

#### What Funnel needs

1. Tailscale signed in to **Tailscale's own control server** (`tailscale status`). Headscale has no
   Funnel; there, a reverse proxy with a publicly trusted certificate is the alternative
   ([Behind a reverse proxy](FILEPARCEL.md#network-vpns-and-the-access-policy)).
2. **MagicDNS** and **HTTPS certificates** turned on for your tailnet (Tailscale admin console → DNS).
3. **Funnel allowed for this machine** in the tailnet policy file (admin console → Access controls):

   ```json
   "nodeAttrs": [
     {"target": ["autogroup:member"], "attr": ["funnel"]}
   ]
   ```

4. Permission for FileParcel to configure Tailscale: `sudo tailscale set --operator=$USER` (for a
   system installation, the account FileParcel runs as: `fileparcel` on Linux, `_fileparcel` on a Mac).
   Not needed when FileParcel runs as root.
5. Shields-up off (`sudo tailscale set --shields-up=false`), FileParcel not running in a container, and
   client certificates (`mtls.mode`) not set to `required` — unless you publish share links only and
   `mtls.exempt_shares` is on (the default).

`fileparcel network funnel status` checks each of these and tells you how to fix what is missing.

#### Turn it on

```sh
fileparcel network funnel status                          # the checks
fileparcel network funnel enable                          # share links only, on public port 443
fileparcel network funnel enable --mode app --port 10000  # the whole app, on port 10000
```

Or Admin → Network & VPN → *Internet access (Tailscale Funnel)*: pick the mode and save. FileParcel asks
before anything becomes reachable from the internet.

- **Ports:** 443 (the first time), 8443 or 10000 — whichever your tailnet policy allows, but never the
  port FileParcel itself uses. With the default FileParcel port 8443, pick 443 or 10000.
- The public name can take **up to 10 minutes** to work on the internet.
- While Funnel is on, new share links use the Funnel address, so their QR codes work anywhere.
- To have Serve and Funnel together, give them different ports: Serve on 443 and Funnel on 10000.

#### Turn it off

```sh
fileparcel network funnel disable
```

FileParcel removes its entry from Tailscale, and nothing is reachable from the internet through it any
more. Share links keep working on your other addresses. Uninstalling FileParcel removes its Funnel and
Serve entries too.

#### Do not use `tailscale funnel` yourself

Never publish FileParcel with the `tailscale funnel` or `tailscale serve` commands (for example
`tailscale funnel https+insecure://localhost:8443`): every visitor would look like the server itself and
slip past the access policy and the rate limits. FileParcel refuses such requests and `fileparcel doctor`
reports the entry. Remove just that entry on the machine that runs it — `tailscale funnel status` shows its
port and path:

```sh
tailscale serve --yes --https=<port> --set-path=<path> off
```

(Without `--set-path`, this removes everything on that port, FileParcel's own entry included.) Then use
`fileparcel network funnel enable` instead.

More about Funnel — the security details, passkeys on the Tailscale address and every check — is in the
user manual under
[Share links on the internet](FILEPARCEL.md#share-links-on-the-internet-tailscale-funnel).

---

## Upgrade to a new version

Upgrades keep all your files, accounts and settings. There are two ways to run one, [with the new release's
installer](#upgrade-from-a-new-release-zip) or [with the fileparcel command](#upgrade-with-the-fileparcel-command);
both do exactly the same.

### Before you upgrade

An upgrade is one command, but a few minutes of preparation make it safe to go back if you need to:

1. **Read the release notes** of the new version on the
   [Releases page](https://github.com/kpdirectmail/fileparcel/releases). They list what changes, anything to
   check before upgrading, and changes that scripts using the `fileparcel` command or the API may notice.
2. **Check the download** ([how](#check-the-download)).
3. **Make a full backup** and make sure you have the backup identity (from the installer's summary). The
   automatic pre-upgrade backup holds the database, settings, keys and certificates but not your files:

   ```sh
   fileparcel backup create --wait
   ```

4. **See the plan** with `fileparcel upgrade --dry-run fileparcel-v2.zip` (or let `./install.sh` show it)
   and fix anything it says blocks the upgrade.
5. **Run `fileparcel doctor`** before and after the upgrade: it lists what needs attention.

Settings keep their values across an upgrade; the release notes say whether a new feature is on from the
start. An older release is not installed over a newer one: to go back, [roll back by hand](#roll-back-by-hand)
with the pre-upgrade backup.

### Upgrade from a new release zip

Download and [check](#check-the-download) the new release, unpack it, and run its installer:

```sh
unzip fileparcel-v2.zip
cd fileparcel-v2
./install.sh
```

The installer asks for the installation directory (press Enter for the default), finds the installation
there, shows the upgrade plan and asks before it starts. `-y` skips the questions and uses the default
directory; so does a run without a terminal (from a script), which has nobody to ask. For an installation
in another directory, name it:

```sh
./install.sh --dir /mnt/ssd/fileparcel
```

For a system installation, run it with `sudo`.

### Upgrade with the fileparcel command

```sh
fileparcel upgrade ~/Downloads/fileparcel-v2.zip
```

Add `--dry-run` to see the plan first. It asks before it starts; without a terminal (from a script or a
cron job) it goes ahead without asking, as with `-y`. For a system installation: `sudo fileparcel upgrade …`.

### What happens during an upgrade

1. The new program is checked against the release's `SHA256SUMS`.
2. A **pre-upgrade backup** is made: the database, the settings, the keys and the certificates (not the
   files themselves, which an upgrade never touches). It stays in `<installation directory>/backups`
   until you delete it, noted "before the upgrade to v2". (`--skip-backup` leaves it out.)
3. The service is stopped.
4. The current program is kept as `bin/fileparcel.prev`, and the new one is put in place.
5. The service is started; the database is updated for the new version as it starts.
6. The installer checks `https://127.0.0.1:<port>/healthz` for up to 30 seconds.
7. **If the new version does not come up, the previous program is put back and started again
   automatically.**
8. `VERSION`, `docs/` and `uninstall.sh` are refreshed.

Good to know:

- Running the upgrade again with the release you already have changes nothing (and keeps
  `bin/fileparcel.prev` for a rollback).
- `--dry-run` shows the plan even while a server you started by hand is running, and says what blocks the
  real upgrade.
- You can also upgrade to a single program file instead of a zip, such as `bin/fileparcel-linux-amd64` of
  an unpacked release. It is checked against the release's `SHA256SUMS` (`--force` accepts one without),
  and `uninstall.sh` and `docs/` are refreshed only from that release, never from other files that happen
  to lie next to the program.
- An upgrade also repairs a missing service registration or command link.
- An **older** release is refused ("v1 is older than the installed v2: …"), because it may not be able to
  open the updated database. `--force` installs it anyway; restoring a backup made with that version is
  the safer way back.
- The upgrade refuses to run while a server you started by hand (`fileparcel serve`) uses the
  installation: stop it first ([how](#no-service)). Without a service, restart the server yourself
  afterwards.
- With a sealed master key, the upgraded server starts **locked**: unlock it at `/unlock` or with
  `fileparcel keys unlock`.
- Reload browser tabs that were open during the upgrade.

### Roll back by hand

If you notice a problem later:

1. **If the new version already updated the database, restore the pre-upgrade backup first, while the
   new program is still installed:**

   ```sh
   fileparcel service stop                 # or stop the server you started by hand
   fileparcel backup list                  # find the backup noted "before the upgrade to …"
   fileparcel backup restore <backup-id> -y
   ```

2. Put the previous program back, remove the `VERSION` file (it still names the newer release, so
   `fileparcel doctor` and `fileparcel status` would report the wrong version), and start it. Use your
   installation directory:

   ```sh
   cp ~/.local/share/fileparcel/bin/fileparcel.prev ~/.local/share/fileparcel/bin/fileparcel
   rm ~/.local/share/fileparcel/VERSION
   fileparcel service start
   ```

Once the problem is fixed, upgrade again the usual way.

Everything done after the upgrade (new files, links, accounts) is not in that backup; download what you
need first.

The pre-upgrade backup has the old version's database layout: the installed program makes it before the
new one is put in place. The older program can also restore a backup over a database that a newer version
already updated, when you give it the backup file and the identity:
`fileparcel backup restore <file.fpbak> --identity-file ~/backup-identity.txt -y`.

### Upgrade a Docker installation

Make a backup first, then build and start the new version:

```sh
docker compose exec fileparcel fileparcel backup create --wait
```

With a **release zip**: stop the old container (`docker compose down` in the old folder), unpack the new
release, move `fileparcel-data/` and `secrets/` from the old folder into the new one, and start it there:

```sh
docker compose up -d --build
```

With a **git checkout**: pull the new version, then run `docker compose build --pull && docker compose up -d`.

---

## Move FileParcel

### Move it to another folder or disk on the same machine

1. Remove the service but keep the data:

   ```sh
   ~/.local/share/fileparcel/uninstall.sh --keep-data
   ```

2. Move the directory. A disk mounted under `/mnt` belongs to root, so move it with `sudo` and then give
   the files back to yourself:

   ```sh
   sudo mv ~/.local/share/fileparcel /mnt/ssd/fileparcel
   sudo chown -R "$USER": /mnt/ssd/fileparcel
   ```

   For a system installation, leave out the `chown` line (`mv` keeps the files' owners), for example
   `sudo mv /opt/fileparcel /srv/fileparcel`.

3. Run the installer of your release (or a newer one) on the new place. It finds the installation,
   registers the service and the command link again, and keeps all data. It does not remember how you
   installed the first time, so **give it the same options again**: `sudo` for a system installation,
   and `--service none`, `--no-boot`, `--symlink PATH` or `--no-symlink` if you used them:

   ```sh
   cd fileparcel-v1
   ./install.sh --dir /mnt/ssd/fileparcel
   ```

### Move it to a new machine

Use a full backup: it carries your files, accounts, settings, keys and the certificate authority, so
devices that trusted the old server trust the new one too.

**On the old machine:**

1. Make sure you have the **backup identity** (from the installer's summary, or Admin → Backups →
   **Export identity…**). No copy at hand? You can also create a new one on the command line; the file
   it writes contains the previous identities too, and the next backup uses the new one:

   ```sh
   (umask 077; fileparcel backup identity generate -y > ~/fileparcel-backup-identity.txt)
   ```

   (`umask 077` keeps the file readable only by you: it holds secret keys.)

2. Keep people from changing things while you move, and turn off Tailscale Funnel and Serve if you use
   them:

   ```sh
   fileparcel maintenance on --message "Moving to a new server"
   fileparcel network funnel disable
   fileparcel network tailscale-serve disable
   ```

3. Make a full backup and copy it straight to a USB disk (or any folder you can copy from):

   ```sh
   fileparcel backup create -o /media/usb/
   ```

4. Stop the old server: `fileparcel service stop`, or stop the server you started by hand
   ([how](#no-service)). Uninstall it once the new one works.

**On the new machine:**

5. [Install FileParcel](#install-in-three-commands) as usual, then stop it:

   ```sh
   ./install.sh -y
   fileparcel service stop
   ```

6. Copy the backup and the identity file to the new machine (or plug in the USB disk), restore the
   backup, and start the server:

   ```sh
   fileparcel backup restore /media/usb/fp-….fpbak --identity-file ~/fileparcel-backup-identity.txt -y
   fileparcel service start
   ```

   Add `--dry-run` first if you only want to check that the backup can be restored.
7. Let people back in, and check everything:

   ```sh
   fileparcel maintenance off
   fileparcel doctor
   ```

After the move:

- **Sign in with the old server's accounts.** The restore brings back every account with its password and
  two-factor sign-in, so the admin password the new installer printed no longer works. The same goes for
  the backup identity: the new installer's one was replaced by the old server's, so keep the identity
  file from step 1, not the one the new installer printed.
- The old machine's settings come back with the backup, including its ports and server name. Change them
  with `fileparcel config set server.https_port 9443` (then `fileparcel service restart`) if the new
  machine needs other ones. If the old server used a port below 1024 (a system installation), apply it
  with `sudo fileparcel service install --start` instead of a restart; a user installation cannot use
  such a port, so choose another one with `fileparcel config set server.https_port`.
- The allow list comes from the old machine too. If the new machine is on another network, add it:
  `fileparcel network allow add 192.168.2.0/24`.
- The server certificate is reissued for the new machine's addresses by itself.
- Turn Tailscale Funnel or Serve on again on the new machine if you use them.
- The restore keeps the new installation's previous state in `pre-restore-<date>/` inside the
  installation directory. Delete it once everything works.
- Open the firewall on the new machine ([Open the firewall](#open-the-firewall)).

The user manual explains backups and restores in detail: [Backups and restore](FILEPARCEL.md#backups-and-restore).

---

## Uninstall FileParcel

Run the uninstaller that was copied into the installation directory (the one in any release zip works
too):

```sh
~/.local/share/fileparcel/uninstall.sh
```

It shows its plan and asks before it removes anything. `fileparcel uninstall` does the same.

### Keep your data (the default)

Without options, the uninstaller removes the service and the `fileparcel` command link, and stops a server
you started by hand. **The installation directory stays**, with all files, keys, backups and logs. Running
`install.sh --dir <that directory>` later brings everything back; give it the options you installed with
(`sudo`, `--service none`, `--no-boot`, `--symlink` or `--no-symlink`), because it does not remember them.

Your encrypted files can only be read together with `keys/master.key` from the same directory, so keep
them together (or keep a backup and its identity).

### Delete everything (`--purge`)

```sh
~/.local/share/fileparcel/uninstall.sh --purge
```

This overwrites the master key and the certificate keys with random bytes (also the copies a restore
keeps in `pre-restore-<date>/`) and deletes the whole installation directory. You must type the directory's
name to confirm. **No backup is made unless you ask
for one:** without it, your stored files are gone for good. (On SSDs and copy-on-write file systems such
as btrfs, ZFS and APFS, overwriting cannot guarantee that the old key bytes are physically gone; the files
are encrypted, and full-disk encryption covers the rest.)

### Make a final backup first

```sh
~/.local/share/fileparcel/uninstall.sh --final-backup --backup-to ~/fileparcel-final --purge
```

`--backup-to` copies the final full backup to a folder outside the installation directory and checks the
copy. If that fails, the uninstaller stops before removing anything. `--final-backup` together with
`--purge` requires `--backup-to`, because a backup left inside the directory would be deleted with it.
Keep the backup identity with the backup, or it cannot be restored.

### All uninstall options

| Option | What it does |
|---|---|
| `--dir DIR` | The installation to remove. Otherwise the uninstaller uses its own location when it lies in an installation, or looks at `$FILEPARCEL_HOME`, the `fileparcel` command link and the default locations (including `$XDG_DATA_HOME/fileparcel`); if it finds more than one installation, it lists them and stops. |
| `--keep-data` | Remove the service and the command link, and stop a server you started by hand (`fileparcel serve`); keep the directory (the default). A FileParcel process it cannot identify is named in the plan: stop it yourself. |
| `--purge` | Also destroy the keys and delete the whole installation directory (asks you to type its name, unless `-y`). Refuses to start while a FileParcel process it cannot identify uses the directory. |
| `--final-backup` | Make a full backup before removing anything. With the service running, the server makes it and the uninstaller waits (Ctrl-C stops waiting; the backup continues). Without `--backup-to` it stays in `backups/` of the installation. |
| `--backup-to DIR` | Copy the final backup to DIR, outside the installation (created if missing; implies `--final-backup`). The uninstaller checks the copy and stops before removing anything if it fails. Required when `--final-backup` is combined with `--purge`. |
| `--remove-user` | Also delete the system account a system installation created (`fileparcel`, or `_fileparcel` on a Mac). |
| `--dry-run` | Show the plan without changing anything. |
| `-y`, `--yes`, `--non-interactive` | Do not ask. |
| `-h`, `--help` | Show the help. |

Examples:

```sh
./uninstall.sh --dry-run                                  # only show the plan
sudo /opt/fileparcel/uninstall.sh -y --purge --remove-user  # a system installation, completely
fileparcel uninstall --dry-run                            # the same plan, through the fileparcel command
```

If the FileParcel program is missing or broken, `uninstall.sh` still removes the service, the command
link and (with `--purge`) the keys and the directory. Steps that need root are printed as `sudo` commands.

### What is left behind

The uninstaller removes the service (stopped, disabled and unregistered), lingering (only if the installer
turned it on and no other user service needs it), the command link (only if it points into this
installation), FileParcel's Tailscale Funnel and Serve entries, with `--purge` the installation directory,
and with `--remove-user` the system account. It does **not** touch:

- **firewall rules** you added — the uninstaller prints the commands to remove them, for example
  `sudo ufw delete allow from 192.168.1.0/24 to any port 8443,8080 proto tcp`. They are made from the ports
  and networks of the installation; if you changed a port since (or restored a backup from another
  machine), check which rules are left with `sudo ufw status numbered` or `sudo firewall-cmd --list-all`;
- **the certificate authority on your devices** ([remove it](#remove-the-certificate-from-your-devices));
- **backup copies** outside the installation directory: the final backup, and the `backup.copy_to` folder;
- a **systemd drop-in** you created with `sudo systemctl edit fileparcel` (for example for
  `backup.copy_to`). Remove it with:

  ```sh
  sudo rm -r /etc/systemd/system/fileparcel.service.d && sudo systemctl daemon-reload
  ```

- the **Tailscale operator** permission you gave with `tailscale set --operator`.

### Remove the certificate from your devices

Once FileParcel is gone, remove its CA ("FileParcel Local CA") from the devices that trusted it:

- **Windows:** run `certlm.msc` → Trusted Root Certification Authorities → Certificates → *FileParcel
  Local CA (…)* → Delete.
- **Mac:** Keychain Access → *System* keychain → Certificates → *FileParcel Local CA (…)* → Delete.
- **iPhone and iPad:** Settings → General → VPN & Device Management → the FileParcel profile → Remove
  Profile.
- **Android:** Settings → Security & privacy → More security settings → Encryption & credentials →
  Trusted credentials → *User* → FileParcel Local CA → Remove. (Menu names vary by phone maker.)
- **Firefox:** Settings → Privacy & Security → Certificates → View Certificates → Authorities → the
  FileParcel entry → Delete or Distrust.
- **Linux**, depending on how you added it:

  ```sh
  sudo rm /usr/local/share/ca-certificates/fileparcel-ca.crt && sudo update-ca-certificates --fresh   # Debian, Ubuntu
  sudo rm /etc/pki/ca-trust/source/anchors/fileparcel-ca.crt && sudo update-ca-trust                  # Fedora, RHEL
  sudo trust anchor --remove fileparcel-ca.crt                                                        # Arch, p11-kit
  certutil -d sql:$HOME/.pki/nssdb -D -n "FileParcel Local CA"                                        # Chrome's own list
  ```

  (For the Chromium snap, use `-d sql:$HOME/snap/chromium/current/.pki/nssdb` in the last command.)

### Uninstall a Docker installation

In the folder with `docker-compose.yml`:

```sh
docker compose down --rmi all
```

This stops and removes the container and the image it built. Your data stays in `fileparcel-data/`: keep
it (starting the container again brings everything back), or delete it together with `secrets/`
(`sudo rm -r fileparcel-data secrets`, because the files belong to uid 65532).

---

## The installation directory

Everything FileParcel stores lives in one directory. Its permissions are tight (the modes on the right;
`keys/` is 0700 and `master.key` 0600): other users on the machine cannot read it, and the server creates
its files with `umask 077`.

```
<installation directory>/                                                                             0750
├── fileparcel.toml       basic settings: ports, name, logging (marks the directory as FileParcel's)  0640
├── VERSION               the installed release, for example "v1 3f9c2a1b7d4e 2026-10-01"
├── uninstall.sh          the uninstaller
├── docs/                 this guide, the user manual and the other documents                         0750
├── bin/fileparcel        the program (the fileparcel command links here)                             0755
├── bin/fileparcel.prev   the previous version, kept for a rollback after an upgrade
├── data/                                                                                             0700
│   ├── fileparcel.db     the database (+ -wal, -shm): accounts, folders, file names, shares,
│   │                     settings, audit log
│   └── blobs/            the encrypted file contents and thumbnails, under random names
├── keys/master.key       the master key (plain or sealed); keep it with the data                     0700/0600
├── certs/                ca/ (local CA and client-certificate CA), server/ (the server's             0700
│                         certificate), acme/, tailscale/, custom/; the CA keys and an uploaded
│                         certificate's key are encrypted, the server certificate's key is not
│                         (it is needed to show the unlock page), nor are ACME and Tailscale keys
├── backups/              encrypted backups (*.fpbak)                                                 0700
├── logs/                 fileparcel.log and its rotated copies, audit.jsonl, launchd logs            0750
├── tmp/                  uploads in progress, zips being built, restore scratch space                0700
├── run/                  admin.sock, fileparcel.lock, fileparcel.pid                                 0700
├── service/              installed.json (what the installer set up); a user service's unit file      0750
└── pre-restore-<date>/   the previous state after a restore (delete it when no longer needed)
```

A system installation differs in one place: the directory itself belongs to `root:fileparcel` with mode
`1770` ([System service](#system-service)).

Outside this directory there are only: the `fileparcel` command link (`~/.local/bin/fileparcel` or
`/usr/local/bin/fileparcel`), the service registration (a systemd link or unit file, or a launchd plist),
the system account of a system installation, and backup copies you set up.

**How commands find the installation:** `fileparcel` uses `--home DIR` if you give it, otherwise
`$FILEPARCEL_HOME`, otherwise the installation the program lives in (the folder above `bin/` that holds
`fileparcel.toml`; the command link leads there). That is why `fileparcel status` just works on the
server, and why `fileparcel --home /path/to/dir status` reaches an installation somewhere else.

---

## Fix installation problems

Start with these two commands on the server; they find most problems and say how to fix them:

```sh
fileparcel status
fileparcel doctor          # add --fix to repair the safe things (permissions, stale files, lingering)
```

### The installer says a port is in use

Another program uses the port. The installer suggests the next free port when you accept the defaults.
To choose one yourself:

```sh
./install.sh --port 9443 --http-port 9080
```

On an existing installation, change the port and restart (then update your firewall rules):

```sh
fileparcel config set server.https_port 9443
fileparcel service restart
```

On Linux, ports below 1024 need a system installation (the installer says "ports below 1024 need a system
install (root)").

### The browser warns that the connection is not private

- The device does not trust FileParcel's CA yet: see
  [Trust FileParcel's certificate on your devices](#trust-fileparcels-certificate-on-your-devices).
- It does, but the warning is about the **name**: you are using a name or address the certificate does
  not contain. A `.local` name or a private IP address can be added at any time; the certificate is
  reissued a few seconds later. Add it, then check the result:

  ```sh
  fileparcel cert sans add nas.local 10.8.0.1
  fileparcel cert status
  ```

  Any other DNS name (for example `files.home.arpa`) is outside what the CA may vouch for: `cert sans add`
  stores it, but `cert status` lists it as "Not covered" until you create a new CA with
  `fileparcel ca regenerate`, after which every device must trust the new CA.

### Other devices cannot connect (timeout, "connection refused" or "reset")

1. Is the server running and on which port? `fileparcel status`
2. **The firewall** is the most common cause: `fileparcel doctor` prints the missing rule
   ([Open the firewall](#open-the-firewall)). ufw blocks everything by default.
3. **The access policy**: is the device's network allowed? Check with `fileparcel network policy`, add it
   with `fileparcel network allow add <network>`. Refused devices show up in `fileparcel logs` as
   "connection refused by the access policy" (at most one line every ten seconds).
4. Use the IP address instead of the `.local` name (some devices do not resolve `.local`).
5. Over a VPN: if Admin → Network & VPN lists your VPN as *outgoing only* although your devices connect
   through it, fix its role: `fileparcel network vpn role <interface> mesh`, then
   `fileparcel network vpn allow <interface>`.

### `fileparcel: command not found`

The installer links the command as `~/.local/bin/fileparcel`, and warns in its summary when that folder is
not on your `PATH`.

- On Debian, Ubuntu and Raspberry Pi OS, `~/.profile` adds `~/.local/bin` to the `PATH` at login, but only
  if the folder already existed then. Log out and back in, or load it into the current shell:

  ```sh
  . ~/.profile
  ```

- On a Mac, and on other systems, add the folder to your `PATH` yourself, for example with
  `echo 'export PATH="$HOME/.local/bin:$PATH"' >> ~/.zprofile` (zsh; `~/.profile` for other shells), then
  open a new terminal.
- Meanwhile the full path always works: `~/.local/bin/fileparcel status`.

For a system installation the command is `/usr/local/bin/fileparcel`; see also
[sudo: fileparcel: command not found](#install-on-fedora-rhel-rocky-or-almalinux) on RHEL.

### `fileparcel.local` does not resolve

Check `fileparcel network mdns status`. On Linux devices install `nss-mdns` (`libnss-mdns`); on Android
use the IP address or the QR code; over Tailscale or WireGuard use the MagicDNS name or the tunnel address
(mDNS does not cross those). If another device uses the name already, FileParcel uses `fileparcel-2.local`.

### The service does not start

1. Look at the service and the log:

   ```sh
   fileparcel service status
   fileparcel logs -n 100
   journalctl --user -u fileparcel -n 50      # a Linux user service
   sudo journalctl -u fileparcel -n 50        # a Linux system service
   ```

   On a Mac the service log is `<installation directory>/logs/launchd.err.log`.
2. "address already in use": see [the installer says a port is in use](#the-installer-says-a-port-is-in-use).
3. After moving a system installation to or from a port below 1024, rewrite the unit:
   `sudo fileparcel service install --start`.
4. Wrong file ownership after copying files by hand (system installation): `sudo fileparcel doctor --fix`.
5. If the log says another FileParcel process is using the installation, a server you started by hand is
   still running. Stop it ([how](#no-service)), then `fileparcel service start`.

### It stops when I log out, or does not start at boot (Linux user service)

Lingering is off. Turn it on (this is what start at boot does), and check:

```sh
fileparcel service enable-boot
loginctl show-user $USER -p Linger
```

On a Mac, a user installation (LaunchAgent) only runs while you are logged in: reinstall with `sudo` for
a LaunchDaemon that starts at boot.

### `systemctl --user` says "Failed to connect to bus"

You are in a session without your own systemd manager (after `su`, or in some SSH setups). Log in
directly as that user, or run `export XDG_RUNTIME_DIR=/run/user/$(id -u)` first. "System has not been
booted with systemd" means systemd is not running at all (WSL without `systemd=true`, a container):
turn it on, or install with `--service none`.

### The server is locked, or pages show an unlock screen

The master key is sealed with a passphrase (`--sealed`, or `fileparcel keys seal` later), and the server
restarted. Unlock it with the passphrase at `https://<server>:8443/unlock`, or on the server:

```sh
fileparcel keys unlock
```

If you forgot the passphrase, enter the recovery key (`FPRK-…`) in the same place. If you have lost both,
the data cannot be recovered. To stop sealing (the server then starts unlocked), run `fileparcel keys unseal`.

### The installation stopped half-way

The summary with the password and the backup identity was still printed: save them. Fix the reported
problem and run the installer again on the same directory; it finishes the installation.

### The upgrade was rolled back

The new version did not start or did not answer in time, so the installer put the previous one back.
Look at `fileparcel logs -n 100` to see why. A common cause is a setting in
`fileparcel.toml` that the new version refuses (the log names it, for example `config: server.public_url: …`);
fix it with `fileparcel config edit`, then run the upgrade again. The release notes of the new version list
such changes ([Before you upgrade](#before-you-upgrade)).

### I forgot the admin password

On the server (the local command line needs no password):

```sh
fileparcel user reset-password admin --generate-password
```

### Tailscale certificates, Serve or Funnel do not work

Run `fileparcel network funnel status --refresh` (or `fileparcel network tailscale-serve status --refresh`):
it lists every requirement and how to fix it. A Tailscale certificate that cannot be fetched ("access
denied") almost always means the operator permission is missing. The usual fixes are `sudo tailscale set --operator=$USER`,
turning on MagicDNS and HTTPS certificates in the Tailscale admin console, and allowing Funnel in the
tailnet policy. Headscale has neither `ts.net` certificates nor Funnel.

### Asking for help

Open an issue on [GitHub](https://github.com/kpdirectmail/fileparcel/issues/new/choose) and include the
output of `fileparcel version` and `fileparcel doctor`, and the relevant lines of `fileparcel logs` (they
contain no passwords or keys, but they do contain names and addresses: remove the ones you do not want to
publish). Report security problems privately, as described in
[SECURITY.md](SECURITY.md#reporting-a-vulnerability).

---

## More documentation

- [User manual](FILEPARCEL.md) — using and running FileParcel: files, sharing, roles, the admin pages,
  the network, certificates, encryption, backups, every setting and a troubleshooting FAQ.
- [The fileparcel command](COMMANDS.md) — managing FileParcel from a terminal, with recipes and the
  reference of every command and flag.
- [Security](SECURITY.md) — the threat model and a hardening checklist.
- [Encryption](ENCRYPTION.md) — how files, keys and backups are encrypted.
- [README](../README.md) — what FileParcel is, in one page.
