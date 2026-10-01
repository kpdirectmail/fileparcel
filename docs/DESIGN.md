# FileParcel — Architecture & Implementation Design

> This is the **binding contract** for everyone working on FileParcel's code. Where code and this document disagree,
> fix the code (or raise the issue with the maintainers when the document is wrong). Section numbers are referenced by
> `docs/DEVELOPMENT.md`. Parts of it (the build stages and units of §16) record how the first version was built.

## 0. Project facts & confirmed decisions

| Topic | Decision |
|---|---|
| Name / command | FileParcel / `fileparcel` |
| Language | Go (toolchain 1.27.1 at `~/sdk/go1.27.1`, `GOTOOLCHAIN=local`), `go.mod` says `go 1.26.0`, `CGO_ENABLED=0` everywhere |
| Module path | `fileparcel` (plain). Imports look like `fileparcel/internal/core`. |
| License | Apache-2.0 |
| Targets | linux/amd64, linux/arm64, linux/arm (GOARM=7), darwin/amd64, darwin/arm64; Docker; systemd (user+system), launchd (agent+daemon) |
| Install dir | Self-contained: *everything* (binary, config, DB, blobs, keys, certs, backups, logs, tmp, socket) lives under one directory chosen at install time. A developer's own installation in the checkout lives in `server/` (gitignored). |
| Defaults | systemd **user** service, HTTPS 8443, HTTP redirect 8080, start-on-boot (linger), admin username `admin` (generated password, must change at first login), master key **plain** (auto-unlock) |
| Frontend | No build step. Vanilla ES modules + hand-written CSS; embedded with `go:embed`; zero npm; strict CSP + Trusted Types |
| Git | `core.hooksPath .githooks`; post-commit builds `releases/fileparcel-vN.zip` + tag `vN`; `releases/`, `server/` and the Docker quick start's `fileparcel-data/` and `secrets/` gitignored |

Host facts the tests must cope with: avahi-daemon may or may not run (D-Bus; `avahi-utils` is not required), a firewall may drop
off-box traffic, unprivileged ports start at 1024, and a Tailscale node may be present but must never be changed by a test (tests
point `FILEPARCEL_TAILSCALE_SOCKET` at a missing socket or a fake tailscaled). The UI tests use Playwright's Chromium, falling back to
`/usr/bin/brave-browser` (or the browser named by `FP_UI_BROWSER`).

---

## 1. Key technical decisions

| Topic | Decision | Reason |
|---|---|---|
| Router | `go-chi/chi/v5` | tiny, stdlib handlers, middleware groups |
| DB | `modernc.org/sqlite` (pure Go), WAL, **1 writer conn + N reader conns** | no cgo; single writer avoids SQLITE_BUSY |
| Upload protocol | **custom parted protocol** (§8) | tusd is huge and doesn't map onto encrypted segments |
| ACME | `caddyserver/certmagic` + `libdns/cloudflare` + `libdns/rfc2136` | proven renewal; DNS-01 |
| mDNS | Linux+Avahi → **Avahi D-Bus** (godbus); macOS → **`dns-sd -P`** child; else **pion/mdns/v2** builtin | coexist with system responders |
| QR | `boombuler/barcode/qr` matrix + in-house SVG/terminal renderer (`internal/qr`) | no stale deps |
| Config | bootstrap **TOML** (`go-toml/v2`) + runtime settings in SQLite | comments, strict types |
| CSRF | `http.CrossOriginProtection` + per-session `X-FP-CSRF` token | defense in depth |
| Blob cipher | AES-256-GCM; **ChaCha20-Poly1305 auto** on CPUs without AES (e.g. Raspberry Pi 4) | speed everywhere |
| Backups | tar → zstd → **age** (X25519 recipient default; passphrase mode optional) | scheduled backups need only a public key |
| Admin transport | CLI speaks the **same REST API** over the Unix socket; **in-process router** when server is down; `--server URL --token` remote | "everything from CLI" by construction |
| Install logic | Go (`fileparcel install/uninstall/service`); `install.sh`/`uninstall.sh` are thin POSIX sh wrappers | testable, same on Linux/macOS (bash 3.2) |
| IDs | `<prefix>_<26-char lowercase Crockford base32 of UUIDv7>`; blob IDs = 32 lowercase hex (128-bit random) | readable, time-ordered, non-enumerable |
| Admin & user files | Admins **cannot** browse others' files unless `auth.admin_can_access_files=true` | least privilege |

---

## 2. Repository layout

```
fileparcel/
├── .gitignore  .gitattributes  .dockerignore
├── .githooks/post-commit            # release trigger (§15)
├── install.sh  uninstall.sh         # POSIX sh wrappers (repo root AND release-zip root)
├── README.md  LICENSE  NOTICE  Makefile  Dockerfile  docker-compose.yml
├── go.mod  go.sum
├── cmd/fileparcel/main.go           # os.Exit(cli.Execute())
├── internal/
│   ├── buildinfo/   Version/Commit/Date via -ldflags; Info struct
│   ├── home/        install-dir resolution, layout paths, perms, flock
│   ├── config/      bootstrap TOML load/save/env overrides/validation
│   ├── core/        domain types (json tags = API schema), service interfaces, errors, Principal, Page[T]
│   ├── ids/         typed IDs, random tokens (base62), constant-time helpers
│   ├── db/          open pools, pragmas, Tx/Read helpers, migration runner; migrations/0001–0004 (§6)
│   ├── events/      in-process pub/sub bus
│   ├── crypt/       AEAD helpers, HKDF, argon2id PHC hash/verify, secure random, common-password list
│   ├── app/         Deps struct (imports core + ratelimit ONLY), Mode
│   ├── wire/        Build(): constructs all concrete services (imports everything)
│   ├── keys/        master key file (plain/sealed), keyring, DEK wrap, field enc, rotation
│   ├── blobstore/   encrypted segmented blob format, reader/writer/parted, verify, GC
│   ├── audit/       HMAC-chained audit log, query, verify, export, prune
│   ├── auth/        passwords, sessions, lockout, TOTP, recovery, WebAuthn, PATs, step-up
│   ├── users/       users, groups, memberships, invites, quotas, spaces bootstrap
│   ├── files/       node tree, perms, trash, versions, FTS search, walk, stars, grants
│   ├── ziputil/     streaming zip/tar writer, compression policy, name sanitation
│   ├── thumbs/      image thumbnails (bounded decode) → encrypted blobs
│   ├── uploads/     batches, parts, finalize, small-file path, zip-on-upload job
│   ├── shares/      public links, file requests, access cookies, access log
│   ├── backup/      create/verify/restore/retention/schedule (age+zstd+tar)
│   ├── jobs/        job registry, runner, cron-lite scheduler, maintenance jobs
│   ├── certs/       local CA (+client CA), leaf, SNI dispatch, certmagic, tailscale, custom, p12, mobileconfig
│   ├── netinfo/     interfaces, VPN classification and roles, URLs, VPN list, exposures, allowlist matcher, tailscale status
│   ├── tslocal/     the one tailscaled client: LocalAPI (status, prefs, serve config with ETag, cert pair) + CLI fallback
│   ├── tsingress/   Tailscale Funnel/Serve: funnel.* settings, checks, reconcile of FileParcel's serve entries, marker, probe
│   ├── mdns/        publisher backends: avahi(dbus) | dnssd(macOS) | builtin(pion) | off
│   ├── qr/          matrix → SVG / data-URI / terminal half-blocks
│   ├── settings/    catalog registry (Register/Def), DB store, bootstrap bridge, validation
│   ├── ratelimit/   keyed token buckets (x/time/rate) with LRU eviction
│   ├── notify/      optional SMTP mailer + text templates
│   ├── server/      listeners (allowlist, TLS-sniff mux, redirect, admin socket), http.Server, lifecycle, sd_notify, restart
│   ├── svc/         systemd (user/system) + launchd (agent/daemon) generation & control, installer logic
│   ├── cli/         cobra commands, client transport (socket | in-process | remote), output (table/json); help.go (groups,
│   │                topics, suggestions), legacy.go (old names), flags.go, complete.go (shell completion), cmd_role.go,
│   │                cmd_access.go, cmd_network_tailscale.go, cmd_whoami.go (§12.6); clikit/ (progress, retry, hashing, Markdown)
│   └── web/
│       ├── router.go        # builds root router; calls every Mount (frozen after foundation)
│       ├── httpx/           JSON, errors, decode, cursors, content-disposition
│       ├── mw/              middleware (headers/CSP, CSRF, auth, roles, elevation, limits, host, sealed gate, logging)
│       ├── static/          embedded asset server (hash prefix, zstd/gzip precompression, ETag)
│       ├── pages/           HTML shells via html/template; /sw.js, manifest, theme.css, well-known, health
│       ├── authapi/ meapi/ usersapi/ filesapi/ uploadapi/ sharesapi/
│       ├── securityapi/     certs, client certs, keys, /system/unlock|status, /trust/*
│       ├── settingsapi/     settings catalog, network, mdns, qr
│       └── opsapi/          backups, jobs, events (SSE), system, dashboard, audit
├── web/                             # Go package `webassets`
│   ├── embed.go                     # //go:embed all:static all:templates  → var FS embed.FS
│   ├── templates/*.html
│   └── static/
│       ├── css/  tokens.css base.css layout.css components.css utilities.css pages/*.css
│       ├── js/   app.js routes.js nav.js core/* components/* upload/* preview/* pages/* public/*
│       ├── icons/sprite.svg  icons/logo.svg  icons/app-192.png  icons/app-512.png  icons/app-apple-180.png  icons/app-maskable-512.png
│       ├── manifest.webmanifest
│       └── sw.js
├── scripts/  release.sh build.sh dev.sh env.sh get-go.sh
├── docs/     FILEPARCEL.md (user manual) INSTALL.md (installation guide) COMMANDS.md (CLI guide + generated reference)
│             DESIGN.md SECURITY.md ENCRYPTION.md DEVELOPMENT.md THIRD_PARTY.md
├── tests/    e2e/{e2e.sh,lib.sh}  ui/{requirements.txt,conftest.py,test_*.py}
├── server/   (gitignored — a developer's own installation, if any)
└── releases/ (gitignored — fileparcel-vN.zip)
```

**Import rules (enforced in review):**
- `core` imports only stdlib + `home`, `config`, `db`, `events`, `buildinfo`.
- Service packages (`keys blobstore audit auth users files ziputil thumbs uploads shares backup jobs certs netinfo tsingress mdns qr settings ratelimit notify`)
  import `core`, `db`, `crypt`, `ids`, `events`, `settings` (for `Register`), `config`, `home`, `buildinfo`, `logx`, stdlib + third-party —
  **never** `web/...`, `app`, `wire`, `cli`, `server`, or another service package's concrete type (use `core` interfaces passed to `New`).
  Exceptions: `uploads` may import `ziputil`; `files` may import `ziputil` and `thumbs`; `auth` and `shares` receive
  `*ratelimit.Registry`; `backup` may import `keys` (`keys.Open`) and `blobstore` (`blobstore.New`), only to open a restored
  temporary home for deep verification (`internal/backup/stores.go`); `jobs/cron` is a leaf parser importable by anyone who
  validates cron settings (`backup`); `qr`, `names` and `tslocal` (the tailscaled LocalAPI/CLI client of `netinfo`,
  `certs`, `tsingress` and the CLI) are leaf utilities importable by anyone.
- `web/*` packages import `app`, `core`, `web/httpx`, `web/mw`, `web/pages` (for `pages.Render`), `qr`, `ids`, `settings` (Register only),
  and `shares` for the names of the public share cookies only (`shares.IsPublicCookie` in `mw.IngressGate`,
  `shares.VisitorCookiePrefix` in `sharesapi`).
- `app` imports only `core` and `ratelimit`.
- Only `wire`, `cli`, `server`, `svc`, `cmd` may import "everything".

---

## 3. Install directory (self-contained)

```
<HOME>/                                  0750 (system installs: root:<service group> 01770, §14.4)
├── fileparcel.toml       # bootstrap config AND the home marker        0640
├── VERSION               # "v7 abc1234 2026-09-19"
├── bin/fileparcel        # binary; PATH symlink points here            0755
├── bin/fileparcel.prev   # previous binary for rollback
├── uninstall.sh  docs/   # copied at install
├── data/                                                                 0700
│   ├── fileparcel.db (+ -wal, -shm)
│   └── blobs/ab/cd/<32hex>          # encrypted blobs, 2-level fan-out
├── keys/master.key       # plain or sealed MK (JSON)             dir 0700 / file 0600
├── certs/                                                                0700
│   ├── ca/{ca.crt, ca.key.enc, client-ca.crt, client-ca.key.enc}
│   ├── server/{leaf.crt, leaf.key}  # leaf key NOT MK-encrypted (needed to serve /unlock while sealed)
│   ├── acme/ (certmagic FileStorage)  tailscale/  custom/{cert.pem,key.pem.enc}
├── backups/*.fpbak                                                       0700
├── logs/fileparcel.log (+ .1..N)  logs/launchd.{out,err}.log            0750
├── tmp/uploads/  tmp/zip/  tmp/restore/  tmp/verify/                     0700
├── run/{admin.sock, fileparcel.lock, fileparcel.pid, clean-shutdown, restore.json}   0700
│   run/{ts-funnel.sock, ts-serve.sock}   # ingress listeners while Tailscale Funnel/Serve is on (§10.6), 0600
└── service/{installed.json, fileparcel.service (systemd user unit only)}   # system unit and launchd plist live outside HOME (§14.4, §14.5)
    service/tailscale.json   # marker of FileParcel's Tailscale serve entries (§10.6), 0600, removed when none remain
```

**Home resolution** — `home.Resolve(flag string) (*Home, error)`: `--home` flag > `$FILEPARCEL_HOME` > `dir(EvalSymlinks(os.Executable()))`
or its parent, whichever contains `fileparcel.toml`. Otherwise error: `no FileParcel home found; run "fileparcel init --home DIR"`.
`home.Home` exposes absolute paths for every entry above (`h.Config()`, `h.DB()`, `h.BlobsDir()`, `h.KeysFile()`, `h.CertsDir()`,
`h.BackupsDir()`, `h.LogsDir()`, `h.TmpDir(sub)`, `h.RunDir()`, `h.Socket()`, `h.LockFile()`, `h.ServiceDir()`, `h.BinDir()`),
`h.EnsureLayout()` (create dirs with the modes above), and `h.Lock() (unlock func(), err error)` (flock on `run/fileparcel.lock`,
held by `serve` for its lifetime and by offline CLI mode). Under that lock, before any job runs, the backup package removes the
scratch data an interrupted backup, restore or deep verification left in `tmp/` (`tmp/restore/restore-*`, `tmp/verify/verify-*`,
`tmp/snapshot-bak_*.db*`, `tmp/members-*.ndjson`; nothing else there).

The process sets `umask 077` at start and refuses to run as root unless `--allow-root` is given (Docker runs as uid 65532).
Admin commands may run as root (`sudo fileparcel …`, e.g. on a system install): when one works in-process on a HOME that belongs
to another account — a system install's service account (§14.4), otherwise HOME's owner — it gives what it wrote back to that
account before it releases the home lock (`svc.SecureSystemHome`/`svc.ChownTree`: the tree but `bin/` and `uninstall.sh`,
symlinks never followed), so the server can still read a restore's `data/`, `keys/`, `certs/` and `fileparcel.toml`, new keys and
certificates, blobs, backups and logs; `config edit` keeps the file's owner, and `doctor` reports entries that account does not
own (`--fix`, as root, gives them back).
Paths outside HOME are only: explicit backup copy destination, the PATH symlink, service registration files
(systemd user unit is *linked* from `<HOME>/service`, launchd plist copied).


---

## 4. Go dependencies (final)

| Module | Use |
|---|---|
| github.com/go-chi/chi/v5 v5.3.2 | router |
| modernc.org/sqlite v1.59.0 | pure-Go SQLite with FTS5 (trigram tokenizer) |
| golang.org/x/crypto v0.57.0 | argon2id, chacha20poly1305 |
| golang.org/x/sys v0.48.0 | flock, SO_PEERCRED/LOCAL_PEERCRED, mlock, statfs, fallocate, `cpu` feature detection |
| golang.org/x/term | no-echo passphrase prompts |
| golang.org/x/time v0.16.0 | `rate` token buckets |
| golang.org/x/net | ipv4/ipv6 PacketConn (pion) |
| golang.org/x/text | `unicode/norm` NFC, `cases` casefold |
| golang.org/x/image | webp/bmp decode + `draw.CatmullRom` for thumbnails |
| github.com/spf13/cobra v1.10.2 | CLI |
| github.com/pelletier/go-toml/v2 v2.4.3 | bootstrap config |
| github.com/pquerna/otp v1.5.0 | TOTP |
| github.com/boombuler/barcode v1.1.0 | QR matrix |
| github.com/go-webauthn/webauthn v0.18.1 | passkeys |
| filippo.io/age v1.3.2 | backup encryption |
| github.com/klauspost/compress v1.20.0 | zstd (backups, static assets), fast flate for zip |
| software.sslmate.com/src/go-pkcs12 v0.7.3 | client-cert .p12 export |
| github.com/caddyserver/certmagic v0.25.4 | ACME lifecycle |
| github.com/libdns/cloudflare v0.2.2, github.com/libdns/rfc2136 v1.0.1 | DNS-01 providers |
| github.com/pion/mdns/v2 v2.2.1 | builtin mDNS/DNS-SD responder |
| github.com/godbus/dbus/v5 v5.2.2 | Avahi publishing on Linux |

Stdlib features relied on: `os.Root` (traversal-proof FS), `crypto/hkdf`, `crypto/sha3` not needed, `http.CrossOriginProtection`,
`http.Server.HTTP2` config, TLS X25519MLKEM768 (default), `testing/synctest`, `sync.WaitGroup.Go`, `time/tzdata` (embed for distroless).
Dev-only tools (never dependencies): staticcheck, govulncheck via `go run …@latest`.

---

## 5. Architecture & package contracts

### 5.1 `internal/core` (written completely in foundation, then frozen — changes only via the integrator)

json tags on core structs **are the API schema** (snake_case). The frontend and the CLI read `internal/core/*.go` as the spec.
Timestamps in JSON are RFC 3339 strings (`time.Time`); in the DB they are INTEGER Unix milliseconds UTC.

```go
package core

// ---------- env / identity / errors ----------
type Clock interface{ Now() time.Time }

type Env struct {
    Home *home.Home; Config *config.Config; DB *db.DB; Log *slog.Logger
    Clock Clock; Bus *events.Bus; Build buildinfo.Info
    Keys Keys; Settings Settings; Audit Audit // filled progressively by wire.Build
}

type Role string // "owner","admin","member","guest","system"(socket / in-process CLI); the built-in (base) role
type AuthVia string // "session","token","socket","share","offline"
type Principal struct {
    UserID, Username string; Role Role; Via AuthVia
    RoleID, RoleName string  // the role ("owner"…"guest", custom "rol_…", "system"; "" = unknown) and its display name ("Finance")
    Caps CapSet              // role capabilities (EffectiveRoleCaps) recorded by SetCaps; read through RoleCaps (scopes apply in Can)
    SessionID, TokenID string; Scopes []string
    AuthLevel int            // 1 = password ok, MFA pending; 2 = full
    EnrollRequired bool      // 2FA policy requires enrollment first
    ElevatedUntil time.Time  // step-up window
    ClientCertSerial string
    IP netip.Addr; UserAgent, RequestID string
    MustChangePassword bool  // full session, users.must_change_password set: only /me* until changed (§9.3)
}
func (p *Principal) IsAdmin() bool            // owner, admin or system: a built-in full administrator (a custom role never is)
func (p *Principal) Elevated(now time.Time) bool // system always true
func (p *Principal) SetCaps(c CapSet)         // the principal's builder (auth, mw --as, files principalFor) records the role's capabilities
func (p *Principal) RoleCaps() CapSet         // ignores token scopes: nil → 0; owner/admin/system → AllCaps; after SetCaps → Caps;
                                              // a "rol_…" RoleID without SetCaps → 0 (fail closed); else BuiltinCaps(Role, false)
func (p *Principal) Can(c Capability) bool    // unknown c → false; system → true; a server capability needs the admin scope on
                                              // API tokens; then RoleCaps().Has(c). AuthLevel is left to the route guards
func (p *Principal) CanAny(cs ...Capability) bool
func (p *Principal) Staff() bool              // owner/admin/system, or the role holds a server capability; ignores token scopes
                                              // (2FA policy "admins", minting the admin scope, elevated tokens)
func (p *Principal) ServerAccess() bool       // IsSystem() || (Staff() && HasScope("admin")): Me.Staff, the SSE admin topics
func WithPrincipal(ctx context.Context, p *Principal) context.Context
func PrincipalFrom(ctx context.Context) *Principal
func SystemPrincipal(via AuthVia) *Principal  // RoleID "system", RoleName "System", SetCaps(AllCaps)
type ReqMeta struct{ IP netip.Addr; UserAgent, RequestID string; Ingress string /* "", "funnel" or "serve" (httpx.Meta) */ }

type Error struct{ Code string; Status int; Message, Field string; Err error } // implements error, Unwrap, Is (by Code)
var ( ErrNotFound /*404 not_found*/; ErrForbidden /*403 forbidden*/; ErrUnauthorized /*401 unauthorized*/
      ErrConflict /*409 conflict*/; ErrInvalid /*422 invalid*/; ErrRateLimited /*429 rate_limited*/; ErrTooLarge /*413 too_large*/
      ErrQuota /*507 quota_exceeded*/; ErrKeysLocked /*503 keys_locked*/
      ErrMFARequired /*401 mfa_required*/; ErrElevationRequired /*403 elevation_required*/
      ErrEnrollRequired /*403 mfa_enroll_required*/; ErrPrecondition /*412 precondition_failed*/
      ErrNotImplemented /*501 not_implemented*/; ErrUnavailable /*503 unavailable*/
      ErrPasswordChangeRequired /*403 password_change_required*/; ErrCSRF /*403 csrf_invalid*/ )
func Invalid(field, msg string) error        // 422 with Field
func NotFoundf(format string, a ...any) error
func Wrap(base *Error, msg string, err error) error

type PageReq struct{ Cursor string; Limit int; Sort string; Desc bool }
type Page[T any] struct{ Items []T `json:"items"`; NextCursor string `json:"next_cursor,omitempty"` }

// ---------- settings ----------
type Settings interface {
    Raw(key string) (json.RawMessage, error)
    Int(key string) int64; Bool(key string) bool; String(key string) string
    Strings(key string) []string; Duration(key string) time.Duration
    Secret(key string) (string, error)        // decrypts a secret setting
    Set(ctx context.Context, by *Principal, changes map[string]json.RawMessage) (*SettingsResult, error) // validates, audits, publishes
    Reset(ctx context.Context, by *Principal, key string) error
    Catalog(ctx context.Context) ([]SettingView, error) // secrets masked (is_set only)
}

// ---------- keys ----------
type KeyState string // "uninitialized","locked","unlocked"
type CipherID uint8   // 1 AES-256-GCM, 2 ChaCha20-Poly1305
type Keys interface {
    State() KeyState
    Unlock(ctx context.Context, passphrase []byte) error      // also accepts a recovery key string
    Lock(ctx context.Context) error                           // sealed mode only
    Status(ctx context.Context) (*KeyStatus, error)
    NewDEK(blobID []byte) (dek, wrapped []byte, kekID string, err error)
    UnwrapDEK(blobID []byte, kekID string, wrapped []byte) ([]byte, error)
    SealField(aad string, plaintext []byte) (string, error)   // "v1:<kekid>:<b64url(nonce||ct)>"
    OpenField(aad string, sealed string) ([]byte, error)
    MAC(purpose string, data ...[]byte) []byte                 // HMAC-SHA256 with HKDF(macKEK, "fp-mac|"+purpose)
    Seal(ctx context.Context, newPass []byte) error            // plain → sealed
    Unseal(ctx context.Context, pass []byte) error             // sealed → plain
    ChangePassphrase(ctx context.Context, oldPass, newPass []byte) error
    RotateKEK(ctx context.Context, purpose string, progress func(done, total int64)) error // purpose: blob|field
    RotateMaster(ctx context.Context) error
    ExportRecovery(ctx context.Context) (string, error)        // returns a new recovery key (shown once)
    Cipher() CipherID                                          // cipher for new blobs (auto-selected)
}

// ---------- blobs ----------
type BlobInfo struct{ ID string `json:"id"`; Size int64 `json:"size"`; StoredSize int64 `json:"stored_size"`; ContentHash string `json:"content_hash"`; Cipher CipherID `json:"cipher"`; CreatedAt time.Time `json:"created_at"` }
type BlobStore interface {
    Create(ctx context.Context) (BlobWriter, error)                              // streaming, unknown size
    CreateParted(ctx context.Context, size int64) (PartedBlob, error)           // part size is fixed: PartSize (8 MiB)
    OpenParted(ctx context.Context, blobID string) (PartedBlob, error)          // resume
    Open(ctx context.Context, blobID string) (BlobReader, error)
    Stat(ctx context.Context, blobID string) (*BlobInfo, error)
    Delete(ctx context.Context, blobID string) error                            // marks deleting + removes file + row
    Verify(ctx context.Context, blobID string) error                            // decrypts every segment
    GC(ctx context.Context, minAge time.Duration) (removed int, freed int64, err error) // unreferenced + stale staging
    Reencrypt(ctx context.Context, blobID string) (newID string, err error)
}
const PartSize = 8 << 20
type BlobWriter interface{ io.Writer; Commit(ctx context.Context) (*BlobInfo, error); Abort() error }
type PartedBlob interface {
    ID() string; Size() int64; PartCount() int
    WritePart(ctx context.Context, n int, r io.Reader, wantSHA256 []byte) (gotSHA256 []byte, err error) // idempotent per part
    Commit(ctx context.Context, partDigests [][]byte) (*BlobInfo, error)
    Abort() error
}
type BlobReader interface{ io.ReadSeekCloser; io.ReaderAt; Size() int64; ID() string }

// ---------- roles and permissions (roles.go; the model and its rules: §6a) ----------
type Capability string // one permission a role grants; the string is the stable API/DB name
const ( CapShareLinks = "shares.links"; CapShareRequests = "shares.requests"; CapUsersLookup = "users.lookup"
        CapTokensCreate = "tokens.create"; CapUsersView = "users.view"; CapUsersManage = "users.manage"
        CapUsersCredentials = "users.credentials"; CapInvitesManage = "invites.manage"; CapGroupsManage = "groups.manage"
        CapSharesManage = "shares.manage"; CapSettingsManage = "settings.manage"; CapNetworkManage = "network.manage"
        CapCertsManage = "certs.manage"; CapBackupsRun = "backups.run"; CapSystemView = "system.view"
        CapSystemManage = "system.manage"; CapAuditView = "audit.view" ) // typed Capability; catalog = bit = UI order; append-only
type CapabilityInfo struct{ Name Capability; Group, Label, Description string; Server, HighImpact bool; Warning string; Implies []Capability }
type CapabilityGroup struct{ ID, Label string }                  // sharing, people, content, server, monitoring
type CapabilityCatalog struct{ Items []CapabilityInfo; Groups []CapabilityGroup } // GET /admin/capabilities
var Capabilities []CapabilityInfo; var CapabilityGroups []CapabilityGroup // the catalog (never modified; Catalog() copies)
func Catalog() CapabilityCatalog
func (c Capability) Valid() bool; Info() (CapabilityInfo, bool); Server() bool; Label() string // Label: the name when unknown
type CapSet uint64                                    // bit i = Capabilities[i], in memory only: the DB and JSON use names
var UserCaps, ServerCaps, AllCaps, MemberCaps CapSet  // built in init (panics on a duplicate or > 64 entries)
func NewCapSet(cs ...Capability) CapSet               // unknown names ignored
func (s CapSet) Has(c Capability) bool; With(cs ...Capability) CapSet; Without(cs ...Capability) CapSet
func (s CapSet) SubsetOf(o CapSet) bool; Minus(o CapSet) CapSet; Server() CapSet /* s & ServerCaps */; Closure() CapSet /* + Implies, transitively */
func (s CapSet) List() []Capability; Names() []string; String() string // catalog order, never nil; String joins with ", "
func (s CapSet) MarshalJSON() ([]byte, error)         // ["shares.links", …]; 0 → []
func (s *CapSet) UnmarshalJSON(b []byte) error        // names; unknown ones ignored (a newer server knows more); null/[] → 0
func ParseCaps(names []Capability) (CapSet, error)    // API/CLI input: 422 permissions `unknown permission "x"`; no closure
func DecodeStoredCaps(jsonText string) CapSet         // roles.permissions: unknown names ignored, bad JSON → 0; no closure
func EncodeCaps(s CapSet) string                      // for roles.permissions; "[]" when empty
func IsCustomRoleID(id string) bool                   // the "rol_" prefix (existence is not checked)
func BuiltinCaps(r Role, guestsShare bool) CapSet     // owner/admin/system → AllCaps; member → MemberCaps; guest → shares.links +
                                                      // shares.requests only with sharing.allow_guests_share; else 0
func EffectiveRoleCaps(base Role, roleID string, stored CapSet, guestsShare bool) CapSet // the only formula: admin bases → AllCaps;
                                                      // custom roleID → stored.Closure() (guestsShare never applies); else BuiltinCaps
func BuiltinRoleName(r Role) string                   // "Owner", "Admin", "Member", "Guest", "System"
func BuiltinRoles(guestsShare bool) []RoleDef         // owner, admin, member, guest (counts and Editable/Assignable left zero)
type RoleDef struct{ ID, Name, Description string; Builtin bool; Base Role; Permissions CapSet; Delegable bool
    CreatedAt, UpdatedAt *time.Time; CreatedBy, UpdatedBy string               // custom roles
    Staff bool; UserCount, GroupCount, GrantCount int; Editable, Assignable bool } // derived; Editable/Assignable for the caller
type RoleDefInput struct{ Name, Description string; Base Role; CopyFrom string; Permissions *[]Capability; Delegable bool } // POST /admin/roles
type RoleDefUpdate struct{ Name, Description *string; Permissions *[]Capability  // PATCH /admin/roles/{id}: Permissions replaces,
    AddPermissions, RemovePermissions []Capability; Delegable *bool }             // or Add/Remove — never both (422 permissions)
type RoleRef struct{ ID, Name, Description, MemberRole string }  // public view: GET /roles, via_roles (MemberRole there)
type RoleGroup struct{ RoleID, RoleName, GroupID, GroupName, SpaceID, MemberRole string; AddedAt time.Time; AddedBy string } // role_groups row
type RoleGroupInput struct{ MemberRole string }                  // PUT /admin/roles/{id}/groups/{groupId}; "" = member
type AccessGroup struct{ GroupID, Name, SpaceID, Role string; Direct bool; DirectRole string; ViaRoles []RoleRef } // effective membership
type SubjectGrantQuery struct{ SubjectType, SubjectID string; Expand bool } // GET /admin/grants; Expand (user): + their groups and role
type SubjectGrants struct{ Items []Grant; Hidden int }          // Hidden = grants on items whose names the caller may not see
type UserAccess struct{ User UserRef; Role RoleDef; Permissions CapSet; Staff, FilesOverride, PersonalSpace bool
    Groups []AccessGroup; Grants []Grant; HiddenGrants, AdminTokens int; Manageable bool } // GET /admin/users/{id}/access

// ---------- escalation rules (escalation.go, added by the roles backend; §6a) ----------
type EscalationError struct{ Reason string; Missing []Capability } // cause of a refusal (logged, never sent); denied attempts are audited from it
func Covers(by *Principal, caps CapSet) bool                          // by.IsAdmin() || caps.Server() ⊆ by.RoleCaps().Server()
func CheckManage(by *Principal, target *User, need Capability) error  // acting on another account (need = users.manage | users.credentials)
type AssignCheck struct{ To *RoleDef; Target *User }                  // Target nil for new accounts and invites
func CheckAssign(by *Principal, c AssignCheck) error                  // giving a role: create, change, invite, accept
func AsEscalation(err error) *EscalationError                         // the EscalationError in err's chain, or nil (for the denied audit entry)
func NeedPermission(c Capability) error                               // 403 `this needs the “<Label>” permission` (the text of mw.RequireCap)
func RoleDelegable(roleID string, customFlag bool) bool               // member/guest always, owner/admin/system never, custom: roles.delegable
// refusals are core.Wrap(ErrForbidden, <message of §6a>, &EscalationError{…})

// ---------- password-protected zip (zip.go; §8.1) ----------
const ( ZipEncAES256 = "aes256" /* WinZip AE-2 */; ZipEncZipCrypto = "zipcrypto" /* weak; compatibility */ ) // "" = not protected
type Secret string // write-only (passwords in request bodies): JSON as a plain string; every fmt verb and slog print "[redacted]"
func (s Secret) Format(f fmt.State, verb rune); LogValue() slog.Value; Reveal() string
func (in BatchInput) LogValue() slog.Value // folder_id, mode, zip_name, conflict, uploader, files (count), zip_encryption, zip_password_set

// ---------- Tailscale Funnel / Serve (ingress.go; §10.6) ----------
const ( IngressFunnel = "funnel"; IngressServe = "serve" )        // IngressInfo.Kind, IngressEntry.Kind, ReqMeta.Ingress
const ( FunnelOff = "off"; FunnelShares = "shares"; FunnelApp = "app" ) // funnel.mode; Serve uses off|app
const ( IngressStateOff = "off"; IngressStateActive = "active"; IngressStateStopped = "stopped" /* server not running */
        IngressStateDrift = "drift" /* tailscaled lost the owned entry */; IngressStateConflict = "conflict" /* a foreign entry holds the port */
        IngressStatePaused = "paused" /* enabled on another node */; IngressStateUnavailable = "unavailable"; IngressStateError = "error" )
type IngressCheck struct{ ID, Label, Status /* ok|warn|fail|skip */, Message, Hint, FixURL string }
type IngressEntry struct{ Kind, Mode string; Port int; HostPort, URL, Backend, State, Message string
    AppliedAt, LastRequestAt, LastPublicRequestAt, ProbedAt *time.Time; Checks []IngressCheck }
type ForeignServe struct{ HostPort, Mount, Target string; Funnel, Foreground bool; Service string; Bypass bool } // not FileParcel's
type IngressStatus struct{ Available bool; Reason, Transport string; Funnel, Serve IngressEntry; FunnelPorts []int
    AllowAdmin, Require2FA bool; Foreign []ForeignServe; Tailscale *TailscaleInfo } // GET /admin/network/tailscale, the write routes
type FunnelInput struct{ Mode string; Port int; AllowAdmin, Require2FA *bool; Confirm string } // PUT /admin/network/funnel; Port 0 = keep
type ServeInput struct{ Enabled bool; Port int }                 // PUT /admin/network/serve
type IngressInfo struct{ Kind string; ClientIP netip.Addr; Public bool; Host, TSUser string } // set per request by the ingress listener
func WithIngress(ctx context.Context, in *IngressInfo) context.Context
func IngressFrom(ctx context.Context) *IngressInfo               // nil for a direct connection
func IPLimitKey(ip netip.Addr, internet bool) string             // rate-limit key: IPv6 over Funnel → "<prefix>/64", else the unmapped address
type IngressPolicy struct{ Mode, DNSName string; Port int; AllowAdmin, Require2FA bool } // what an open ingress listener enforces

// ---------- VPNs (vpn.go; §10.1) ----------
const ( IfYggdrasil = "yggdrasil"; IfHusarnet = "husarnet"; IfExitVPN = "exitvpn"; IfWARP = "warp"; IfFirezone = "firezone"
        IfTwingate = "twingate"; IfCorpVPN = "corpvpn"; IfNetmaker = "netmaker"; IfInnernet = "innernet"; IfTinc = "tinc"
        IfOpenVPN = "openvpn"; IfIPsec = "ipsec"; IfSoftEther = "softether" ) // NetInterface.Kind additions
const ( VPNRoleMesh = "mesh"; VPNRoleUnknown = "unknown"; VPNRoleAccess = "access"; VPNRoleEgress = "egress"
        VPNRoleOverlay = "overlay"; VPNRoleLocal = "local"; VPNRoleNone = "none" ) // NetInterface.Role, VPNInfo.Role, network.iface_roles
const ( VPNRoleSourceAuto = "auto"; VPNRoleSourceOverride = "override" ) // role_source: classification | network.iface_roles
type VPNInfo struct{ ID, Kind, Label, Provider, Role, RoleSource string; Interfaces, Ranges []string
    Allowed string /* yes|partly|no */; CanAllow, NeedsForce, Recommended bool; Note, Warning string } // NetworkOverview.VPNs
type Exposure struct{ ID, Severity /* info|warn|fail */, Message, Hint string } // a way around the access policy (doctor, Network page)

// ---------- bus payloads of roles, ingress and VPNs (events.go) ----------
type AuthzChangedEvent struct{ UserIDs []string; RoleID, Reason string } // "authz.changed", published by users after commit
const ( AuthzRoleAssigned = "role_assigned"; AuthzRoleUpdated = "role_updated"; AuthzRoleDeleted = "role_deleted"
        AuthzRoleGroups = "role_groups"; AuthzRoleDetails = "role_details" ) // Reason
```

The remaining interfaces (`Users`, `Auth`, `Files`, `Uploads`, `Shares`, `Audit`, `Jobs`, `Backups`, `Certs`, `Network`, `MDNS`, `Notify`,
`Ingress`) are specified in §5.1b below. All model structs (User, Session, Group, Space, Node, FileVersion, Grant, UploadBatch, UploadFileState,
Share, ShareAccess, Invite, APIToken, Passkey, ClientCert, Backup, BackupConfig, Job, AuditEntry, AuditRecord, SettingView,
SettingsResult, NetInterface, AccessURL, AccessPolicy, CertStatus, KeyStatus, MDNSStatus, TailscaleInfo, MFAStatus, Usage,
FolderStats, WalkEntry, plus every *Input/*Query/*Update type) are defined by foundation in `internal/core/models.go` with json tags.

**Feature contracts.** The roles, zip, ingress and VPN types above and the field additions below were added in one step before the feature work
and are frozen like the rest of `core` (the only later file is `escalation.go`). JSON names are the snake_case of the
field names (`Require2FA` → `require_2fa`, `VPNs` → `vpns`); `IngressInfo`, `IngressPolicy` and `SubjectGrantQuery` are
never serialized. The JSON (names, order, `omitempty`) is pinned by golden files in
`internal/core/testdata/contract/` (`TestContractJSON` marshals one representative value of every type the web UI and
the CLI exchange; `TestContractJSONDecodes` decodes each file back with unknown fields refused): changing one is a
contract change (`go test ./internal/core -run TestContractJSON -update-contract` rewrites them).
- `User` + `role_id` (never empty; `role` stays the base), `role_name`, `permissions` (EffectiveRoleCaps, with
  `sharing.allow_guests_share`) and `RoleDelegable` (`json:"-"`, for CheckManage); `NewUser`, `InviteInput` + `role_id`
  (a built-in word or `rol_…`; `role` must then be empty or its base); `UserUpdate.RoleID *string` (an admin field;
  `role` without `role_id` gives that built-in role and removes a custom one); `UserQuery.RoleID` (a built-in word
  matches plain holders only). `Invite` + `role_id`, `role_name` ("Deleted role" once the custom role is gone).
- `Group` + `role_count`, `roles` (GetGroup), `via` (MyGroups: `direct`|`role`, `direct` when both); `member_count` and
  `my_role` become effective. `GroupMember.role` becomes effective (manager wins) + `direct`, `direct_role`,
  `via_roles` (RoleRef with `member_role`).
- Grants: `SubjectRole = "role"` (a custom role: everyone holding it) and `GrantManager = "manager"` (PermManage);
  `Grant` + `node_name`, `node_path`, `node_kind`, `space_kind`, `space_name`, `caller_perm` (filled by
  `Files.SubjectGrants` only).
- Zip: `UploadBatch.zip_encryption` (never the password), `Node.zip_encryption` (the current version; derived),
  `FileVersion.zip_encryption`, `FileMeta.ZipEncryption` (`json:"-"`: set by the `upload.zip` job only, never from a
  request body), `BatchInput.zip_encryption` and `BatchInput.zip_password` (`Secret`, write-only).
- `Me.staff` (`ServerAccess()`; false at AuthLevel 1). `SettingView.managed`: the route that owns the key (e.g. `PUT
  /api/v1/admin/network/funnel`); PATCH/DELETE `/admin/settings` refuse it with 409.
- Network: `NetInterface` + `role` (`VPNRole*`), `role_source`, `provider`, `detail`, `default_route`;
  `URLKindFunnel = "funnel"`, `URLKindTailscaleServe = "tailscale_serve"`; `TailscaleInfo` + `version`, `node_id`,
  `userspace`, `shields_up`, `can_configure`, `funnel_capable`, `funnel_ports`, `key_expiry`, `kind_guessed`;
  `NetworkOverview` + `ingress` (the cached `IngressStatus`; omitted while no ingress service is wired), `vpns` and
  `exposures` (always arrays).
- `Services.Ingress` (hooks.go) and `app.Deps.Ingress` (nil until the Funnel/Serve service is wired; every user
  nil-checks it). `ids.PrefixRole = "rol"`.

### 5.1b Remaining service interfaces

```go
// ---------- users ----------
// Authorization is by permission (§6a): users.manage (create, admin fields, status, unlock, delete), users.credentials
// (passwords, 2FA and sessions of others; moving files on delete), invites.manage, groups.manage (group_ids on accounts
// and invites need it too) — Principal.Can — plus the escalation rules CheckManage (acting on another account) and
// CheckAssign (giving a role). Nobody changes their own role; a delegate (not a built-in admin) not their own quota or
// must_change_password either. Roles CRUD is for built-in owners/admins only. Members, MyGroups, GroupIDsOf and GroupsOf
// are effective: direct plus through a role (role_groups).
type Users interface {
    Get(ctx context.Context, id string) (*User, error)
    GetByUsername(ctx context.Context, username string) (*User, error)
    List(ctx context.Context, q UserQuery) (Page[User], error)
    Count(ctx context.Context) (int, error)
    Create(ctx context.Context, by *Principal, in NewUser) (*User, error) // + personal space (not for guests)
    Bootstrap(ctx context.Context, in NewUser) (*User, error)             // first owner; fails if any user exists
    Update(ctx context.Context, by *Principal, id string, in UserUpdate) (*User, error)
    SetPasswordHash(ctx context.Context, by *Principal, id, phc string, mustChange bool) error
    SetStatus(ctx context.Context, by *Principal, id, status string) error
    Delete(ctx context.Context, by *Principal, id, transferTo string) error
    RecordLoginFailure(ctx context.Context, id string) (lockedUntil *time.Time, err error)
    RecordLoginSuccess(ctx context.Context, id string, meta ReqMeta) error
    Unlock(ctx context.Context, by *Principal, id string) error
    Lookup(ctx context.Context, p *Principal, q string) ([]UserRef, error)
    ListGroups(ctx context.Context, q PageReq) (Page[Group], error)
    GetGroup(ctx context.Context, id string) (*Group, error)
    CreateGroup(ctx context.Context, by *Principal, in GroupInput) (*Group, error)   // + group space ("Team folder")
    UpdateGroup(ctx context.Context, by *Principal, id string, in GroupInput) (*Group, error)
    DeleteGroup(ctx context.Context, by *Principal, id string) error
    Members(ctx context.Context, groupID string) ([]GroupMember, error)
    SetMember(ctx context.Context, by *Principal, groupID, userID, role string) error
    RemoveMember(ctx context.Context, by *Principal, groupID, userID string) error
    GroupIDsOf(ctx context.Context, userID string) ([]string, error)
    MyGroups(ctx context.Context, p *Principal) ([]Group, error)
    CreateInvite(ctx context.Context, by *Principal, in InviteInput) (*Invite, string, error) // returns token — URL is /invite/<token> (ListInvites shows it again while the invite is active)
    ListInvites(ctx context.Context, by *Principal, q PageReq) (Page[Invite], error) // URL only where by may see it (§6a)
    RevokeInvite(ctx context.Context, by *Principal, id string) error
    LookupInvite(ctx context.Context, token string) (*Invite, error)
    AcceptInvite(ctx context.Context, token string, in AcceptInvite, phc string, meta ReqMeta) (*User, error)
    // roles (§6a):
    ListRoles(ctx context.Context, by *Principal) ([]RoleDef, error)          // built-ins (owner, admin, member, guest), then custom by name
    GetRole(ctx context.Context, by *Principal, id string) (*RoleDef, error)  // built-in word or rol_…; by nil → no Editable/Assignable
    CreateRole(ctx context.Context, by *Principal, in RoleDefInput) (*RoleDef, error)
    UpdateRole(ctx context.Context, by *Principal, id string, in RoleDefUpdate) (*RoleDef, error) // built-ins → 422
    DeleteRole(ctx context.Context, by *Principal, id, reassignTo string) error // holders move to reassignTo (409 when missing)
    LookupRoles(ctx context.Context, p *Principal) ([]RoleRef, error)         // GET /roles: custom roles (users.lookup or users.view)
    RoleGroups(ctx context.Context, roleID string) ([]RoleGroup, error)
    SetRoleGroup(ctx context.Context, by *Principal, roleID, groupID, memberRole string) (*RoleGroup, error) // custom roles only
    RemoveRoleGroup(ctx context.Context, by *Principal, roleID, groupID string) error
    GroupsOf(ctx context.Context, userID string) ([]AccessGroup, error)       // effective memberships with their sources
}

// ---------- auth ----------
type Auth interface {
    HashPassword(pw string) (string, error)
    VerifyPassword(phc, pw string) (ok bool, needsRehash bool)
    CheckPasswordPolicy(pw string, u *User) error
    Login(ctx context.Context, in LoginInput, meta ReqMeta) (*LoginResult, error)
    VerifyTOTP(ctx context.Context, p *Principal, code string) (*LoginResult, error)
    VerifyRecovery(ctx context.Context, p *Principal, code string) (*LoginResult, error)
    PasskeyLoginBegin(ctx context.Context, username string) (opts json.RawMessage, flowID string, err error)
    PasskeyLoginFinish(ctx context.Context, flowID string, resp []byte, remember bool, p *Principal, meta ReqMeta) (*LoginResult, error)
    Authenticate(r *http.Request) (*Principal, error)     // cookie or Bearer; (nil,nil) = anonymous
    Logout(ctx context.Context, p *Principal) error
    Elevate(ctx context.Context, p *Principal, in ElevateInput) error
    CSRFToken(p *Principal) string
    CheckCSRF(p *Principal, token string) bool
    ChangePassword(ctx context.Context, p *Principal, current, next string) error // revokes other sessions
    AdminSetPassword(ctx context.Context, by *Principal, userID, pw string, mustChange bool) error
    ListSessions(ctx context.Context, userID string) ([]Session, error)
    RevokeSession(ctx context.Context, by *Principal, userID, sessionID string) error
    RevokeAllSessions(ctx context.Context, by *Principal, userID, exceptID string) error
    TOTPBegin(ctx context.Context, p *Principal) (*TOTPEnrollment, error)   // secret, otpauth URI, QR SVG data URI
    TOTPConfirm(ctx context.Context, p *Principal, code string) (recovery []string, err error) // codes only when none are left unused
    TOTPDisable(ctx context.Context, by *Principal, userID string) error
    RegenerateRecovery(ctx context.Context, p *Principal) ([]string, error)
    PasskeyRegisterBegin(ctx context.Context, p *Principal) (json.RawMessage, string, error)
    PasskeyRegisterFinish(ctx context.Context, p *Principal, flowID string, resp []byte, name string) (*Passkey, error)
    ListPasskeys(ctx context.Context, userID string) ([]Passkey, error)
    RenamePasskey(ctx context.Context, p *Principal, id, name string) error
    DeletePasskey(ctx context.Context, p *Principal, id string) error
    CreateToken(ctx context.Context, p *Principal, in TokenInput) (*APIToken, string, error)
    ListTokens(ctx context.Context, userID string) ([]APIToken, error)
    RevokeToken(ctx context.Context, p *Principal, id string) error
    MFAStatus(ctx context.Context, userID string) (*MFAStatus, error)
    ResetMFA(ctx context.Context, by *Principal, userID string) error
    SessionCookie(token string, exp time.Time) *http.Cookie
    Setup(ctx context.Context, setupToken string, in NewUser, meta ReqMeta) (*LoginResult, error) // first-run web setup
    SetupToken(ctx context.Context) (string, error)  // creates/returns one-time setup token when no users exist (printed in logs)
    RotateSession(ctx context.Context, p *Principal) (*LoginResult, error) // new session token after Elevate/ChangePassword; (nil,nil) for non-sessions
    RPID() string                                    // effective WebAuthn RP ID (reported by GET /auth/state)
}

// ---------- files ----------
type Perm int // PermNone < PermView < PermEdit < PermManage < PermOwner
type ConflictPolicy string // "rename","replace","skip","fail"
type Files interface {
    Spaces(ctx context.Context, p *Principal) ([]Space, error)
    Get(ctx context.Context, p *Principal, id string) (*Node, error)
    Authorize(ctx context.Context, p *Principal, id string, need Perm) (*Node, error)
    List(ctx context.Context, p *Principal, folderID string, q ListQuery) (Page[Node], error)
    Breadcrumbs(ctx context.Context, p *Principal, id string) ([]Node, error)
    Mkdir(ctx context.Context, p *Principal, parentID, name string) (*Node, error)
    MkdirAll(ctx context.Context, p *Principal, parentID, relPath string) (*Node, error)
    CommitFile(ctx context.Context, p *Principal, parentID, relPath string, b *BlobInfo, m FileMeta, c ConflictPolicy) (*Node, error)
    Rename(ctx context.Context, p *Principal, id, name string) (*Node, error)
    Move(ctx context.Context, p *Principal, ids []string, dest string, c ConflictPolicy) ([]Node, error)
    Copy(ctx context.Context, p *Principal, ids []string, dest string, c ConflictPolicy) ([]Node, error) // shares blobs, instant
    Trash(ctx context.Context, p *Principal, ids []string) error
    Restore(ctx context.Context, p *Principal, ids []string) ([]Node, error)
    Purge(ctx context.Context, p *Principal, ids []string) error
    ListTrash(ctx context.Context, p *Principal, q ListQuery) (Page[Node], error)
    EmptyTrash(ctx context.Context, p *Principal) error
    Open(ctx context.Context, p *Principal, id, versionID string) (*Node, BlobReader, error)
    Thumbnail(ctx context.Context, p *Principal, id string) (BlobReader, error)
    Walk(ctx context.Context, p *Principal, rootIDs []string, fn func(WalkEntry) error) error // keyset-paged DFS
    Search(ctx context.Context, p *Principal, q SearchQuery) (Page[Node], error)
    Recent(ctx context.Context, p *Principal, limit int) ([]Node, error)
    Star(ctx context.Context, p *Principal, id string, on bool) error
    Starred(ctx context.Context, p *Principal, q ListQuery) (Page[Node], error)
    Versions(ctx context.Context, p *Principal, id string) ([]FileVersion, error)
    RestoreVersion(ctx context.Context, p *Principal, id, versionID string) (*Node, error)
    Grants(ctx context.Context, p *Principal, id string) ([]Grant, error)
    SetGrant(ctx context.Context, p *Principal, id string, in GrantInput) (*Grant, error)
    RemoveGrant(ctx context.Context, p *Principal, id, grantID string) error
    SharedWithMe(ctx context.Context, p *Principal, q ListQuery) (Page[Node], error)
    Stats(ctx context.Context, p *Principal, id string) (*FolderStats, error)
    Usage(ctx context.Context, userID string) (*Usage, error)
    CreateArchiveTicket(ctx context.Context, p *Principal, shareID string, in ArchiveInput) (ticket string, err error)
    ConsumeArchiveTicket(ctx context.Context, ticket string) (*ArchiveTicket, error)
    WriteArchive(ctx context.Context, t *ArchiveTicket, w io.Writer) error   // streams zip or tar
    // system-level (no principal) helpers used by shares/uploads/jobs:
    GetSys(ctx context.Context, id string) (*Node, error)
    IsWithin(ctx context.Context, ancestorID, id string) (bool, error)
    ListSys(ctx context.Context, folderID string, q ListQuery) (Page[Node], error)
    OpenSys(ctx context.Context, id string) (*Node, BlobReader, error)
    SysPrincipalFor(ctx context.Context, userID string) (*Principal, error) // acts as that user (public share ops)
    // live grants to one subject (GET /admin/grants; the route authorizes). Names are filled only where p may see
    // them, the rest are counted in Hidden.
    SubjectGrants(ctx context.Context, p *Principal, q SubjectGrantQuery) (*SubjectGrants, error)
}

// ---------- uploads ----------
type UploadActor struct{ P *Principal; ShareID, Uploader string }
type Uploads interface {
    CreateBatch(ctx context.Context, a UploadActor, in BatchInput) (*UploadBatch, error)
    AddFiles(ctx context.Context, a UploadActor, batchID string, in []UploadFileInput) ([]UploadFileState, error)
    PutPart(ctx context.Context, a UploadActor, uploadID string, n int, body io.Reader, size int64, sha []byte) error
    PutSmall(ctx context.Context, a UploadActor, batchID, clientRef string, body io.Reader, size int64, sha []byte) (*UploadFileState, error)
    Status(ctx context.Context, a UploadActor, uploadID string) (*UploadFileState, error)
    CompleteFile(ctx context.Context, a UploadActor, uploadID string) (*UploadFileState, error)
    CompleteBatch(ctx context.Context, a UploadActor, batchID string) (*UploadBatch, error)
    GetBatch(ctx context.Context, a UploadActor, batchID string) (*UploadBatch, error)
    AbortBatch(ctx context.Context, a UploadActor, batchID string) error
    AbortFile(ctx context.Context, a UploadActor, uploadID string) error
    ExpireStale(ctx context.Context) (int, error)
}

// ---------- shares ----------
type Shares interface {
    Create(ctx context.Context, p *Principal, in ShareInput) (*Share, string, error) // token returned; URL = /s/<token>
    List(ctx context.Context, p *Principal, q ShareQuery) (Page[Share], error)
    ListAll(ctx context.Context, q ShareQuery) (Page[Share], error) // admin
    Get(ctx context.Context, p *Principal, id string) (*Share, error)
    Update(ctx context.Context, p *Principal, id string, in ShareUpdate) (*Share, error)
    Revoke(ctx context.Context, p *Principal, id string) error
    AccessLog(ctx context.Context, p *Principal, id string, q PageReq) (Page[ShareAccess], error)
    Resolve(ctx context.Context, token string) (*Share, *Node, error)     // validates active/expiry/limits
    CheckPassword(ctx context.Context, s *Share, pw string, meta ReqMeta) error
    AccessCookie(s *Share) (*http.Cookie, error)
    HasAccess(r *http.Request, s *Share) bool                              // password cookie valid (or no password)
    CountDownload(ctx context.Context, s *Share) error                     // atomic; ErrForbidden when exhausted
    RecordAccess(ctx context.Context, s *Share, a ShareAccess)
}

// ---------- audit ----------
type Audit interface {
    Record(ctx context.Context, e AuditEntry)          // never fails the caller; fills actor/ip/request from ctx Principal
    RecordTx(ctx context.Context, tx *sql.Tx, e AuditEntry) error
    Query(ctx context.Context, q AuditQuery) (Page[AuditRecord], error)
    Verify(ctx context.Context) (*AuditVerify, error)
    Export(ctx context.Context, q AuditQuery, format string, w io.Writer) error // csv|jsonl
    Prune(ctx context.Context, before time.Time) (int, error)
}

// ---------- jobs ----------
type JobFunc func(ctx context.Context, j JobHandle) error
type JobHandle interface{ ID() string; Params(v any) error; Progress(done, total int64, note string); SetResult(v any) }
type JobOptions struct{ Exclusive string; MaxConcurrent int; Timeout time.Duration; Hidden bool }
type Jobs interface {
    Register(kind string, fn JobFunc, o JobOptions)
    Enqueue(ctx context.Context, kind string, params any, by *Principal) (string, error)
    Get(ctx context.Context, id string) (*Job, error)
    List(ctx context.Context, q JobQuery) (Page[Job], error)
    Cancel(ctx context.Context, id string) error
    Schedule(name, cron, kind string, params any) error
    Unschedule(name string)
    Schedules(ctx context.Context) ([]JobSchedule, error)
    Start(ctx context.Context) error
    Stop(ctx context.Context) error
}

// ---------- backups ----------
type Backups interface {
    Create(ctx context.Context, by *Principal, in BackupInput) (jobID string, err error)
    CreateSync(ctx context.Context, by *Principal, in BackupInput) (*Backup, error) // used by pre-upgrade/final backups & CLI offline
    List(ctx context.Context, q PageReq) (Page[Backup], error)
    Get(ctx context.Context, id string) (*Backup, error)
    Delete(ctx context.Context, by *Principal, id string) error
    Verify(ctx context.Context, by *Principal, id string, deep bool) (jobID string, err error)
    Download(ctx context.Context, id string) (io.ReadCloser, int64, string, error)
    Import(ctx context.Context, by *Principal, r io.Reader) (*Backup, error)
    ScheduleRestore(ctx context.Context, by *Principal, id string, c RestoreCreds) error // writes run/restore.json, then restart
    RestoreOffline(ctx context.Context, file string, c RestoreCreds, o RestoreOpts) error
    Prune(ctx context.Context) (int, error)
    Config(ctx context.Context) (*BackupConfig, error)
    SetConfig(ctx context.Context, by *Principal, c BackupConfig) error
    GenerateIdentity(ctx context.Context, by *Principal) (recipient, identity string, err error)
}

// ---------- certs ----------
type Certs interface {
    TLSConfig() *tls.Config
    Status(ctx context.Context) (*CertStatus, error)
    CAExport(format string) (data []byte, contentType, filename string, err error) // pem|der|mobileconfig
    Fingerprint() string                                      // SHA-256 of CA cert DER, hex with colons
    RenewLocal(ctx context.Context, force bool) error
    RegenerateCA(ctx context.Context, by *Principal, constrained bool) error
    SetCustom(ctx context.Context, by *Principal, certPEM, keyPEM []byte) error
    ClearCustom(ctx context.Context, by *Principal) error
    ApplyACME(ctx context.Context) error
    FetchTailscale(ctx context.Context) error
    HTTPChallenge(next http.Handler) http.Handler
    PubliclyTrusted(serverName string) bool
    IssueClient(ctx context.Context, by *Principal, in ClientCertInput) (*ClientCert, []byte, error) // p12 bytes
    ListClient(ctx context.Context, q PageReq, userID string) (Page[ClientCert], error)
    RevokeClient(ctx context.Context, by *Principal, id, reason string) error
    CheckClient(ctx context.Context, cs *tls.ConnectionState) (*ClientCert, error)
    Init(ctx context.Context) error            // create CA/client CA/leaf if missing (used by `init`)
    Start(ctx context.Context) error
}

// ---------- network / mdns / notify ----------
type Network interface {
    Interfaces(ctx context.Context) ([]NetInterface, error)
    URLs(ctx context.Context) ([]AccessURL, error)
    Allowed(ip netip.Addr) bool                 // lock-free hot path (atomic.Pointer)
    Policy() AccessPolicy
    SetPolicy(ctx context.Context, by *Principal, p AccessPolicy, current netip.Addr, force bool) ([]string, error) // warnings
    CheckPolicy(p AccessPolicy, ip netip.Addr) (bool, error) // validate p and evaluate it for ip without applying (lockout guard)
    Hostnames() []string                        // SAN names (mdns name.local, hostname, MagicDNS, extra)
    IPs() []netip.Addr                          // SAN IPs
    Tailscale(ctx context.Context) (*TailscaleInfo, error)
    IsLocal(ip netip.Addr) bool                 // an address of any local interface (lock-free snapshot)
    Start(ctx context.Context) error
}
type MDNS interface {
    Status() MDNSStatus
    Name() string                               // effective FQDN e.g. "fileparcel.local"
    Republish(ctx context.Context) error
    Start(ctx context.Context) error
    Stop() error
}
type Notify interface {
    Enabled() bool
    Send(ctx context.Context, to []string, tmpl string, data any) error
    Test(ctx context.Context, to string) error
}

// ---------- ingress (Tailscale Funnel / Serve, package tsingress; §10.6) ----------
type Ingress interface {
    Status(ctx context.Context, refresh bool) (*IngressStatus, error)
    SetFunnel(ctx context.Context, by *Principal, in FunnelInput) (*IngressStatus, error) // weakening sign-in: by.IsAdmin() only
    SetServe(ctx context.Context, by *Principal, in ServeInput) (*IngressStatus, error)
    Reapply(ctx context.Context, by *Principal) (*IngressStatus, error)       // rewrites the owned entries (fixes drift)
    RemoveAll(ctx context.Context, by *Principal, reason string) error        // e.g. uninstall
    Start(ctx context.Context) error                                          // subscribe + load; writes nothing
    Attach(l IngressListeners)                                                // server.Run after listening: first reconcile (async)
    Detach(ctx context.Context)                                               // server shutdown: suspend TCP-backend entries
    // lock-free hot path:
    Policy(kind string) IngressPolicy
    CheckProbe(kind, nonce string) bool
    Note(kind string, public, conflict bool)
    PublicBaseURL() string                                                    // "" unless Funnel shares|app is active
    InternetLinks() bool
    AccessURLs() []AccessURL
}
type IngressListeners interface {                                             // implemented by package server
    Open(kind, network, address string, peerUIDs []int) error
    Close(kind string)
}
```

### 5.2 Deps and wiring

```go
package app
type Mode int // ModeNetwork, ModeSocket(unused), ModeOffline
type Deps struct {
    *core.Env
    Mode Mode
    Auth core.Auth; Users core.Users; Files core.Files; Uploads core.Uploads; Shares core.Shares
    Blobs core.BlobStore; Jobs core.Jobs; Backups core.Backups; Certs core.Certs
    Network core.Network; MDNS core.MDNS; Notify core.Notify; Limiter *ratelimit.Registry
    Ingress core.Ingress // Tailscale Funnel/Serve; nil until wired, every user nil-checks it
}
```

`wire.Build(ctx, h *home.Home, mode app.Mode) (*app.Deps, func(), error)` — construction order and **fixed constructor signatures**:

```
config.Load(h) → log (slog; file+stderr) → db.Open(h.DB()) + db.Migrate → events.New() → env
keys.Open(env)                                   → env.Keys      (state locked/unlocked; never blocks)
settings.New(env)                                → env.Settings
audit.New(env)                                   → env.Audit
jobs.New(env)             ratelimit.New(env)
blobstore.New(env)
users.New(env)            auth.New(env, users, limiter)
files.New(env, blobs, jobs)
uploads.New(env, files, blobs, jobs)
shares.New(env, files, limiter)
netinfo.New(env)          certs.New(env, net)          mdns.New(env, net)
tsingress.New(env, net)                          → Services.Ingress, Deps.Ingress (every mode; §10.6)
backup.New(env, blobs, jobs)                     notify.New(env)
```
All constructors return `(*Service, error)` where `*Service` implements the core interface (`var _ core.X = (*Service)(nil)`).
`wire.Start(ctx, d)` calls `Start` on net → certs → Ingress (subscribe and load only, no write; a failure is logged) → mdns → jobs
(Offline mode: skips Ingress, mdns and jobs; certs only loads). A running server calls `Ingress.Attach(listeners)` once its listeners
are up (the first reconcile) and `Ingress.Detach` before it drains (§9.1, §10.6).

### 5.3 HTTP mounting rules

Each API package exposes `func Mount(api chi.Router, d *app.Deps)` (the `/api/v1` sub-router, already wrapped with the API middleware chain) and,
where needed, `func MountRoot(r chi.Router, d *app.Deps)` (root router). `internal/web/router.go` (foundation-owned, frozen) calls all of them.
**Modules never call `r.Route()` or `r.Mount()`**; they use `r.Group(func(r chi.Router){ r.Use(...); r.Get("/full/path", h) })`.

| Package (unit) | Owned paths under `/api/v1` | Root paths |
|---|---|---|
| authapi (B) | `/auth/*` | |
| meapi (B) | `/me`, `/me/*` except `/me/client-certs*` | |
| usersapi (C) | `/admin/users*`, `/admin/invites*`, `/admin/groups*`, `/admin/roles*`, `/admin/capabilities`, `/groups`, `/users/lookup`, `/roles`, `/activity` | |
| filesapi (D) | `/spaces`, `/nodes*`, `/trash*`, `/search`, `/recent`, `/starred`, `/shared-with-me`, `/archives*`, `/admin/grants` | |
| uploadapi (E) | `/upload-batches*`, `/uploads*` | |
| sharesapi (E) | `/shares*`, `/admin/shares` | `/s/{token}` and `/s/{token}/*` |
| securityapi (F) | `/admin/certs*`, `/admin/client-certs*`, `/admin/keys*`, `/me/client-certs*`, `/system/unlock`, `/system/status` | `/trust/ca.crt`, `/trust/ca.pem`, `/trust/ca.mobileconfig` |
| settingsapi (G) | `/admin/settings*`, `/admin/network*` (incl. `/admin/network/tailscale*`, `/admin/network/funnel`, `/admin/network/serve`), `/admin/mdns*`, `/network/urls`, `/qr.svg` | |
| opsapi (H) | `/admin/backups*`, `/admin/jobs*`, `/admin/system*`, `/admin/dashboard`, `/admin/audit*`, `/jobs/{id}`, `/events` | |
| pages, static (I) | | `/`, SPA routes, `/login`, `/invite/{t}`, `/setup`, `/unlock`, `/trust`, `/static/{hash}/*`, `/sw.js`, `/manifest.webmanifest`, `/theme.css`, `/robots.txt`, `/favicon.ico`, `/.well-known/security.txt`, `/healthz`, `/readyz` |

**mw helpers** (signatures written by foundation; hardened by unit I):
`mw.Principal(r) *core.Principal`, `mw.RequireAuth`, `mw.RequireFull` (MFA done & not EnrollRequired, except allow-listed `/me/*` enrollment routes),
`mw.RequireRole(roles ...core.Role)`, `mw.RequireAdmin`, `mw.RequireElevated`, `mw.RequireScope(s string)`,
`mw.RateLimit(bucket string, key func(*http.Request) string)`, `mw.MaxBody(n int64)`, `mw.NoStore`, `mw.SocketOnly`, `mw.ClientIP(r) netip.Addr`.
`mw.RequireCap(caps ...core.Capability)` = `RequireFull` + `Principal.CanAny(caps...)` (owners, admins and the system
principal always pass; API tokens need the `admin` scope for server permissions). It answers 403 `forbidden` with
`token lacks scope "admin"` when the account holds one of `caps` but the token lacks the scope (the CLI's hint keys on
"admin"), else `this needs the “<Label>” permission` (the label of the first cap); constructing it without a capability or
with an unknown one panics. `mw.RequireAdmin` stays for the admin-only surfaces of §6a.

**httpx**: `httpx.JSON(w, status, v)`, `httpx.Error(w, r, err)` (maps `*core.Error` → `{"error":{"code","message","field","request_id"}}`;
unknown errors → 500 `internal` with message "internal error" and the error logged), `httpx.Decode[T any](r *http.Request, max int64) (T, error)`
(DisallowUnknownFields; 422 on bad JSON), `httpx.PageReq(r) core.PageReq`, `httpx.EncodeCursor(v any) string` / `DecodeCursor(s string, v any) error`
(opaque base64url JSON), `httpx.Attachment(w, name string, inline bool)` (RFC 6266 `filename*=UTF-8''…` + ASCII fallback, `%`/`?` replaced there so no browser decodes it),
`httpx.Created(w, v)`, `httpx.NoContent(w)`, `httpx.Meta(r) core.ReqMeta`.

**events topics** (`events.Bus`): `settings.changed{keys}`, `network.changed`, `certs.changed`, `keys.state`, `mdns.changed`,
`job.progress{job,user}`, `job.done{job,user}`, `upload.batch_done{batch,user}`, `share.accessed{share,user}`, `backup.finished{backup}`,
`system.restart` (asks the running server to restart; never delivered over SSE), and
`authz.changed{user_ids,role_id,reason}` (`core.AuthzChangedEvent`; the permissions of the listed accounts or of every
holder of `role_id` changed: `role_assigned`, `role_updated` (its permissions), `role_deleted`, `role_groups`, and
`role_details` when only a role's name, description or `delegable` flag changed; published by `users` after
commit) and `ingress.changed` (nil; the Funnel/Serve status changed; published by `tsingress`). Who receives which topic
over SSE (`GET /events`) is decided per permission in `opsapi/sse.go` (§6a): `ingress.changed` needs `network.manage`, and
an `authz.changed` addressed to the stream's own principal is delivered and then closes the stream (except
`role_groups` and `role_details`), so the client reconnects with its new permissions.
`Bus.Publish(events.Event{Topic string; UserID string; Data any})`, `Bus.Subscribe(topics ...string) (<-chan events.Event, func())`,
non-blocking with bounded buffer (256) and drop-oldest.

**Settings registration**: each owning package declares its keys in its own `settings.go`:
```go
func init() {
    settings.Register(settings.Def{Key: "storage.trash_days", Section: "storage", Order: 40, Type: settings.TypeInt,
        Default: 30, Min: 0, Max: 3650, Restart: false, Secret: false, Enum: nil,
        Label: "Trash retention (days)", Description: "…", Validate: nil})
}
```
Types: `TypeBool, TypeInt, TypeString, TypeStrings, TypeDuration (string "15m"), TypeEnum, TypeCIDRs, TypeSecret, TypeCron, TypeColor, TypeEmail, TypeURL`.
There is no central catalog file. `Def.Managed` names the route that owns a key (the Funnel/Serve keys of §11.2); the
store copies it into `SettingView.managed`, `Settings.Set` from services is unaffected, and PATCH/DELETE `/admin/settings`
refuse the key with 409.

**Feature extension hooks.** Files that several features (roles, zip passwords, Funnel/VPNs, CLI) touch have one hook per feature, each in the feature's own file,
so no feature edits another's code:
- **Page boot and `/me`** (`internal/web/pages`): `pages.Features(d, p) map[string]bool` (`features.go`; `p` nil on
  anonymous pages) is the feature map of the page boot *and* of `GET /me` (the client merges both, `/me` winning). It
  composes `baseFeatures` (`features.go`: the original flags, and the permission-derived `links`, `requests`, `directory`,
  `tokens`), `zipFeatures` (`features_zip.go`: `zip_legacy_encryption`), `ingressFeatures` (`features_ingress.go`:
  `internet_links`, `funnel_2fa`) and `maintenanceFeatures` (`features_maintenance.go`: `maintenance`, whether maintenance
  mode is on — the banner with *Turn off* for administrators and *Operate the server*, and the notice on the sign-in
  page). The boot also carries `limits` (`bootLimits`, `features_zip.go`: numeric form limits
  such as `zip_password_min`; always an object; boot only, not `/me`) and `ingress` (`"funnel"`/`"serve"` from
  `core.IngressFrom`; omitted on a direct connection); `PageData.PublicOnly` comes from `publicOnly(d, r)`
  (`features_ingress.go`; every page `NewPageData` builds, the share and error pages included). The feature files read
  settings through `boolSetting`, `intSetting` and `enumSetting` (`pages.go`: the default when a key is not registered).
  `web/static/js/core/dom.js boot()` copies `limits` (`{}` when absent) and `ingress` (`''`).
- **Settings routes** (`internal/web/settingsapi`, `hooks.go`): PATCH and DELETE `/admin/settings` call
  `checkKeys` → `runKeyChecks(views, keys, capGuard, managedGuard)` before `checkElevation`, then the lockout guard and the
  passkey guard. `runKeyChecks` applies each check to every known key before the next check (unknown keys are left to
  the store's 422), so the order is: permission for every key (`capGuard`, `caps.go`: 403, `field` = the key) → managed
  for every key (`managedGuard`, `managed.go`: 409) → step-up → lockout → passkeys. A request that also touches a key the
  caller may not change is therefore refused with 403 even when another of its keys is managed. `listable`
  (`capVisible`, `caps.go`) filters `GET /admin/settings`; `extraWarnings` (`ingressWarnings`, `managed.go`) is appended
  to the PATCH warnings; `Mount` ends with `mountTailscale` (`tailscale.go`: the routes of §9.4 under
  `/admin/network/tailscale*`, `/admin/network/funnel`, `/admin/network/serve`).
- **Doctor** (`internal/web/opsapi`): `runDoctor` adds `checkIngress(ctx, d, now)` (`doctor_network.go`: the Funnel,
  Serve and VPN checks) right after `checkFirewall`.

---

## 6. SQLite schema (`internal/db/migrations/`)

Conventions: `*_at` = INTEGER Unix ms UTC; IDs TEXT with prefixes; JSON columns TEXT; sensitive columns field-encrypted (`_enc`, §7.5).
Pragmas at open: `journal_mode=WAL`, `synchronous=NORMAL`, `foreign_keys=ON`, `busy_timeout=10000`, `temp_store=MEMORY`,
`cache_size=-65536`, `mmap_size=268435456`, `wal_autocheckpoint=1000`. Writer pool: `SetMaxOpenConns(1)`, `_txlock=immediate`.
Reader pool: N=min(8, GOMAXPROCS) conns with `PRAGMA query_only=ON`.
A write transaction lowers `busy_timeout` to 250 ms on the connection it holds and retries in `db.Tx` for up to 10 s, so a
cross-process lock cannot pin the single writer past the caller's deadline; `Writer()` statements (VACUUM, `wal_checkpoint(TRUNCATE)`,
`PRAGMA optimize`) keep the 10 s wait.
Migration runner: embedded `migrations/NNNN_name.sql`, table `schema_migrations(version INTEGER PRIMARY KEY, name TEXT, applied_at INTEGER)`,
each migration in one transaction, refuses to open a DB whose version is newer than the binary knows.

**Migration numbering.** The migrations are `0001_init`, `0002_roles`, `0003_zip_password` and `0004_fts_name_key`.
- **No gaps:** after sorting, the embedded versions must be exactly `1..N`; otherwise `db.Migrations()` fails with
  `db: missing migration NNNN (migrations must be numbered without gaps)` and the binary refuses to start, rather than
  leave a database without a migration. A file name that is not `NNNN_name.sql` (four digits) or a duplicate version fails the
  same way.
- **Set-based apply:** `db.Migrate` runs every embedded migration whose version is not recorded in `schema_migrations`,
  in ascending order, each in its own transaction together with its row. It does not skip everything up to the highest
  recorded version, so a migration numbered below one that is already applied still runs.
- **Name check:** a recorded version whose name differs from the embedded migration's name means the database was
  migrated by a build that numbered its migrations differently; `Migrate` fails with
  `db: migration NNNN is "<recorded>" in the database but "<embedded>" in this binary` before running anything, so the
  database is left untouched. A recorded row without a name counts as applied.
- `ErrSchemaTooNew` still compares the highest recorded version with the highest embedded one.
- Only the integrator adds migrations (docs/DEVELOPMENT.md §7), with the next free number; a shipped migration is never
  edited or renumbered.

The listing below is `0001_init` (with the search index as `0004` rebuilds it); the later migrations apply on top.

```sql
CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT NOT NULL) WITHOUT ROWID;
-- install_id, created_at, mk_id, mk_check, setup_token_hash, audit_anchor_seq, audit_anchor_hash

CREATE TABLE users (
  id TEXT PRIMARY KEY, username TEXT NOT NULL COLLATE NOCASE UNIQUE,
  display_name TEXT NOT NULL DEFAULT '', email TEXT COLLATE NOCASE UNIQUE,
  role TEXT NOT NULL CHECK (role IN ('owner','admin','member','guest')),
  status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active','disabled')),
  password_hash TEXT, password_changed_at INTEGER, must_change_password INTEGER NOT NULL DEFAULT 0,
  webauthn_handle BLOB NOT NULL UNIQUE, quota_bytes INTEGER,
  failed_logins INTEGER NOT NULL DEFAULT 0, lock_level INTEGER NOT NULL DEFAULT 0, locked_until INTEGER,
  last_login_at INTEGER, last_login_ip TEXT, prefs TEXT NOT NULL DEFAULT '{}',
  created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL, created_by TEXT);

CREATE TABLE sessions (
  id TEXT PRIMARY KEY, token_hash BLOB NOT NULL UNIQUE,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  auth_level INTEGER NOT NULL, mfa_method TEXT, csrf_secret BLOB NOT NULL, remember INTEGER NOT NULL DEFAULT 0,
  created_at INTEGER NOT NULL, last_seen_at INTEGER NOT NULL, idle_expires_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL, elevated_until INTEGER, ip TEXT, user_agent TEXT,
  client_cert_serial TEXT, revoked_at INTEGER);
CREATE INDEX sessions_user ON sessions(user_id);
CREATE INDEX sessions_exp ON sessions(expires_at);

CREATE TABLE totp_secrets (user_id TEXT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
  secret_enc TEXT NOT NULL, confirmed_at INTEGER, last_step INTEGER NOT NULL DEFAULT 0,
  created_at INTEGER NOT NULL) WITHOUT ROWID;
CREATE TABLE recovery_codes (id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  code_mac BLOB NOT NULL, used_at INTEGER, created_at INTEGER NOT NULL);
CREATE INDEX recovery_user ON recovery_codes(user_id);
CREATE TABLE webauthn_credentials (id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  credential_id BLOB NOT NULL UNIQUE, name TEXT NOT NULL DEFAULT 'Passkey',
  credential_enc TEXT NOT NULL,                 -- webauthn.Credential JSON, field-encrypted
  aaguid BLOB, sign_count INTEGER NOT NULL DEFAULT 0,
  backup_eligible INTEGER NOT NULL DEFAULT 0, backup_state INTEGER NOT NULL DEFAULT 0,
  rp_id TEXT NOT NULL, created_at INTEGER NOT NULL, last_used_at INTEGER);
CREATE INDEX webauthn_user ON webauthn_credentials(user_id);
CREATE TABLE api_tokens (id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE, name TEXT NOT NULL,
  token_hash BLOB NOT NULL UNIQUE, scopes TEXT NOT NULL, created_at INTEGER NOT NULL,
  expires_at INTEGER, last_used_at INTEGER, last_used_ip TEXT, revoked_at INTEGER);
CREATE TABLE client_certs (id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE, name TEXT NOT NULL,
  serial TEXT NOT NULL UNIQUE, fingerprint_sha256 TEXT NOT NULL UNIQUE,
  not_before INTEGER NOT NULL, not_after INTEGER NOT NULL, issued_by TEXT, issued_at INTEGER NOT NULL,
  revoked_at INTEGER, revoke_reason TEXT, last_seen_at INTEGER);

CREATE TABLE groups (id TEXT PRIMARY KEY, name TEXT NOT NULL COLLATE NOCASE UNIQUE,
  description TEXT NOT NULL DEFAULT '', created_at INTEGER NOT NULL, created_by TEXT);
  -- name also unique by casefold(NFC) like node names (checked by users; NOCASE folds ASCII only)
CREATE TABLE group_members (
  group_id TEXT NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  role TEXT NOT NULL CHECK (role IN ('member','manager')), added_at INTEGER NOT NULL,
  PRIMARY KEY (group_id, user_id)) WITHOUT ROWID;
CREATE INDEX group_members_user ON group_members(user_id);
CREATE TABLE invites (id TEXT PRIMARY KEY, token_hash BLOB NOT NULL UNIQUE, token_enc TEXT NOT NULL,
  email TEXT, role TEXT NOT NULL CHECK (role IN ('admin','member','guest')),
  group_ids TEXT NOT NULL DEFAULT '[]', quota_bytes INTEGER,
  max_uses INTEGER NOT NULL DEFAULT 1, uses INTEGER NOT NULL DEFAULT 0, expires_at INTEGER NOT NULL,
  note TEXT, created_by TEXT REFERENCES users(id) ON DELETE SET NULL,
  created_at INTEGER NOT NULL, revoked_at INTEGER);
  -- a creator's active invites are revoked (audited) when it loses admin rights: demotion to member/guest,
  -- disable, delete (before SET NULL, which would make them look like the system principal's)

CREATE TABLE spaces (id TEXT PRIMARY KEY, kind TEXT NOT NULL CHECK (kind IN ('user','group')),
  owner_user_id TEXT REFERENCES users(id) ON DELETE CASCADE,
  group_id TEXT REFERENCES groups(id) ON DELETE CASCADE,
  name TEXT NOT NULL, quota_bytes INTEGER, used_bytes INTEGER NOT NULL DEFAULT 0, created_at INTEGER NOT NULL,
  CHECK ((kind='user' AND owner_user_id IS NOT NULL AND group_id IS NULL)
      OR (kind='group' AND group_id IS NOT NULL AND owner_user_id IS NULL)));
CREATE UNIQUE INDEX spaces_user ON spaces(owner_user_id) WHERE kind='user';
CREATE UNIQUE INDEX spaces_group ON spaces(group_id) WHERE kind='group';

CREATE TABLE keyring (id TEXT PRIMARY KEY,
  purpose TEXT NOT NULL CHECK (purpose IN ('blob','field','mac')),
  mk_id TEXT NOT NULL, wrapped BLOB NOT NULL,            -- nonce||ct, AES-256-GCM under MK, AAD "fp-kek|<id>|<purpose>"
  state TEXT NOT NULL CHECK (state IN ('active','retired')),
  created_at INTEGER NOT NULL, retired_at INTEGER);
CREATE UNIQUE INDEX keyring_active ON keyring(purpose) WHERE state='active';

CREATE TABLE blobs (id TEXT PRIMARY KEY,
  state TEXT NOT NULL CHECK (state IN ('staging','ready','deleting')),
  size INTEGER NOT NULL, stored_size INTEGER, cipher INTEGER NOT NULL, seg_log2 INTEGER NOT NULL DEFAULT 16,
  kek_id TEXT NOT NULL REFERENCES keyring(id), wrapped_dek BLOB NOT NULL,
  content_hash TEXT, parts_done INTEGER NOT NULL DEFAULT 0,
  created_at INTEGER NOT NULL, verified_at INTEGER);
CREATE INDEX blobs_kek ON blobs(kek_id);
CREATE INDEX blobs_state ON blobs(state, created_at);

-- nodes has an explicit INTEGER PRIMARY KEY (rid) so FTS5 external-content rowids survive VACUUM / VACUUM INTO.
CREATE TABLE nodes (rid INTEGER PRIMARY KEY, id TEXT NOT NULL UNIQUE,
  space_id TEXT NOT NULL REFERENCES spaces(id) ON DELETE CASCADE,
  parent_id TEXT REFERENCES nodes(id) ON DELETE CASCADE,
  kind TEXT NOT NULL CHECK (kind IN ('folder','file')),
  name TEXT NOT NULL, name_key TEXT NOT NULL,           -- NFC; casefold(NFC)
  size INTEGER NOT NULL DEFAULT 0, mime TEXT, version_id TEXT,  -- no FK (cycle); code-maintained
  content_hash TEXT, client_mtime INTEGER,
  created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL,
  created_by TEXT REFERENCES users(id) ON DELETE SET NULL,
  updated_by TEXT REFERENCES users(id) ON DELETE SET NULL,
  trashed_at INTEGER, trashed_by TEXT, trash_root INTEGER NOT NULL DEFAULT 0,
  thumb_blob_id TEXT REFERENCES blobs(id) ON DELETE SET NULL);
CREATE UNIQUE INDEX nodes_root ON nodes(space_id) WHERE parent_id IS NULL;
CREATE UNIQUE INDEX nodes_live_name ON nodes(parent_id, name_key) WHERE trashed_at IS NULL;
CREATE INDEX nodes_children ON nodes(parent_id, kind, name_key);
CREATE INDEX nodes_trash ON nodes(space_id, trash_root, trashed_at) WHERE trashed_at IS NOT NULL;
CREATE INDEX nodes_recent ON nodes(space_id, updated_at);
-- The index covers name_key (0004_fts_name_key.sql; 0001 indexed name), so search folds case exactly like
-- name uniqueness ("STRASSE" finds "Straße.txt"). Every UPDATE that renames a node sets name_key.
CREATE VIRTUAL TABLE nodes_fts USING fts5(name_key, content='nodes', content_rowid='rid', tokenize='trigram');
CREATE TRIGGER nodes_fts_ai AFTER INSERT ON nodes BEGIN
  INSERT INTO nodes_fts(rowid, name_key) VALUES (new.rid, new.name_key); END;
CREATE TRIGGER nodes_fts_ad AFTER DELETE ON nodes BEGIN
  INSERT INTO nodes_fts(nodes_fts, rowid, name_key) VALUES ('delete', old.rid, old.name_key); END;
CREATE TRIGGER nodes_fts_au AFTER UPDATE OF name_key ON nodes BEGIN
  INSERT INTO nodes_fts(nodes_fts, rowid, name_key) VALUES ('delete', old.rid, old.name_key);
  INSERT INTO nodes_fts(rowid, name_key) VALUES (new.rid, new.name_key); END;
-- search: the query is folded like name_key (names.Key); trigram MATCH when the folded query has >= 3 chars,
-- LIKE on name_key for shorter ones.

CREATE TABLE file_versions (id TEXT PRIMARY KEY,
  node_id TEXT NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,
  blob_id TEXT NOT NULL REFERENCES blobs(id), size INTEGER NOT NULL, content_hash TEXT,
  created_at INTEGER NOT NULL, created_by TEXT REFERENCES users(id) ON DELETE SET NULL);
CREATE INDEX versions_node ON file_versions(node_id, created_at DESC);
CREATE INDEX versions_blob ON file_versions(blob_id);

CREATE TABLE node_grants (id TEXT PRIMARY KEY,
  node_id TEXT NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,
  subject_type TEXT NOT NULL CHECK (subject_type IN ('user','group')), subject_id TEXT NOT NULL,
  role TEXT NOT NULL CHECK (role IN ('viewer','editor')), created_by TEXT,
  created_at INTEGER NOT NULL, expires_at INTEGER,
  UNIQUE (node_id, subject_type, subject_id));
CREATE INDEX grants_subject ON node_grants(subject_type, subject_id);
CREATE TABLE stars (user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  node_id TEXT NOT NULL REFERENCES nodes(id) ON DELETE CASCADE, created_at INTEGER NOT NULL,
  PRIMARY KEY (user_id, node_id)) WITHOUT ROWID;

CREATE TABLE shares (id TEXT PRIMARY KEY, kind TEXT NOT NULL CHECK (kind IN ('link','request')),
  node_id TEXT NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,
  created_by TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  token_hash BLOB NOT NULL UNIQUE, token_enc TEXT NOT NULL, title TEXT, message TEXT,
  password_hash TEXT, password_version INTEGER NOT NULL DEFAULT 0,
  allow_download INTEGER NOT NULL DEFAULT 1, allow_preview INTEGER NOT NULL DEFAULT 1,
  allow_upload INTEGER NOT NULL DEFAULT 0, require_uploader_name INTEGER NOT NULL DEFAULT 0,
  upload_max_file_bytes INTEGER, upload_quota_bytes INTEGER, upload_used_bytes INTEGER NOT NULL DEFAULT 0,
  max_downloads INTEGER, download_count INTEGER NOT NULL DEFAULT 0, expires_at INTEGER,
  notify_owner INTEGER NOT NULL DEFAULT 0, disabled_at INTEGER,
  created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL, last_access_at INTEGER);
CREATE INDEX shares_node ON shares(node_id);
CREATE INDEX shares_owner ON shares(created_by, created_at);
CREATE TABLE share_access_log (id INTEGER PRIMARY KEY,
  share_id TEXT NOT NULL REFERENCES shares(id) ON DELETE CASCADE, at INTEGER NOT NULL,
  action TEXT NOT NULL CHECK (action IN ('view','preview','download','zip','upload','password_ok','password_fail','blocked')),
  node_id TEXT, bytes INTEGER, ip TEXT, user_agent TEXT, uploader TEXT);
CREATE INDEX share_access_share ON share_access_log(share_id, at);

CREATE TABLE upload_batches (id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,  -- quota owner (share owner for requests)
  share_id TEXT REFERENCES shares(id) ON DELETE CASCADE, uploader TEXT, actor_session TEXT,
  folder_id TEXT NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,
  mode TEXT NOT NULL CHECK (mode IN ('files','zip')), zip_name TEXT,
  conflict TEXT NOT NULL CHECK (conflict IN ('rename','replace','skip','fail')),
  declared_files INTEGER NOT NULL DEFAULT 0, declared_bytes INTEGER NOT NULL DEFAULT 0,
  reserved_bytes INTEGER NOT NULL DEFAULT 0,
  state TEXT NOT NULL CHECK (state IN ('open','finalizing','done','aborted','failed','expired')),
  job_id TEXT, result_node_id TEXT, error TEXT,
  created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL, expires_at INTEGER NOT NULL);
CREATE INDEX upload_batches_state ON upload_batches(state, expires_at);
CREATE TABLE upload_files (id TEXT PRIMARY KEY,
  batch_id TEXT NOT NULL REFERENCES upload_batches(id) ON DELETE CASCADE,
  client_ref TEXT NOT NULL, rel_path TEXT NOT NULL,
  kind TEXT NOT NULL DEFAULT 'file' CHECK (kind IN ('file','dir')),
  size INTEGER NOT NULL, client_mtime INTEGER, mime TEXT,
  blob_id TEXT REFERENCES blobs(id) ON DELETE SET NULL,
  part_count INTEGER NOT NULL DEFAULT 0, parts_done INTEGER NOT NULL DEFAULT 0,
  state TEXT NOT NULL CHECK (state IN ('pending','uploading','uploaded','committed','skipped','failed','aborted')),
  node_id TEXT, error TEXT, created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL,
  UNIQUE (batch_id, client_ref));
CREATE TABLE upload_parts (upload_id TEXT NOT NULL REFERENCES upload_files(id) ON DELETE CASCADE,
  n INTEGER NOT NULL, size INTEGER NOT NULL, sha256 BLOB NOT NULL, received_at INTEGER NOT NULL,
  PRIMARY KEY (upload_id, n)) WITHOUT ROWID;

CREATE TABLE archive_tickets (id_hash BLOB PRIMARY KEY,
  user_id TEXT REFERENCES users(id) ON DELETE CASCADE, share_id TEXT REFERENCES shares(id) ON DELETE CASCADE,
  node_ids TEXT NOT NULL, format TEXT NOT NULL CHECK (format IN ('zip','tar')), name TEXT NOT NULL,
  created_at INTEGER NOT NULL, expires_at INTEGER NOT NULL, used_at INTEGER) WITHOUT ROWID;

CREATE TABLE settings (key TEXT PRIMARY KEY, value TEXT NOT NULL,   -- JSON value; secrets stored as JSON string "v1:…" (sealed)
  updated_at INTEGER NOT NULL, updated_by TEXT) WITHOUT ROWID;

CREATE TABLE audit_log (seq INTEGER PRIMARY KEY AUTOINCREMENT, id TEXT NOT NULL UNIQUE, at INTEGER NOT NULL,
  actor_id TEXT, actor_name TEXT, actor_via TEXT, ip TEXT, user_agent TEXT, request_id TEXT,
  action TEXT NOT NULL, outcome TEXT NOT NULL CHECK (outcome IN ('success','failure','denied')),
  target_type TEXT, target_id TEXT, target_name TEXT, details TEXT NOT NULL DEFAULT '{}',
  prev_hash BLOB NOT NULL, hash BLOB NOT NULL);  -- hash = MAC("audit", prev_hash || canonical(row))
CREATE INDEX audit_at ON audit_log(at);
CREATE INDEX audit_actor ON audit_log(actor_id, at);
CREATE INDEX audit_action ON audit_log(action, at);
CREATE INDEX audit_target ON audit_log(target_type, target_id);

CREATE TABLE jobs (id TEXT PRIMARY KEY, kind TEXT NOT NULL,
  state TEXT NOT NULL CHECK (state IN ('queued','running','succeeded','failed','canceled')),
  params TEXT NOT NULL DEFAULT '{}', result TEXT, error TEXT,
  progress_done INTEGER NOT NULL DEFAULT 0, progress_total INTEGER NOT NULL DEFAULT 0, note TEXT,
  created_by TEXT, schedule TEXT, attempts INTEGER NOT NULL DEFAULT 0,
  created_at INTEGER NOT NULL, started_at INTEGER, finished_at INTEGER);
CREATE INDEX jobs_state ON jobs(state, created_at);
CREATE INDEX jobs_kind ON jobs(kind, created_at);
CREATE TABLE schedules (name TEXT PRIMARY KEY, cron TEXT NOT NULL, kind TEXT NOT NULL,
  params TEXT NOT NULL DEFAULT '{}', enabled INTEGER NOT NULL DEFAULT 1,
  last_run_at INTEGER, next_run_at INTEGER, last_job_id TEXT) WITHOUT ROWID;

CREATE TABLE backups (id TEXT PRIMARY KEY,
  scope TEXT NOT NULL CHECK (scope IN ('full','metadata')),
  state TEXT NOT NULL CHECK (state IN ('running','ready','failed')),
  file_name TEXT NOT NULL, size INTEGER, sha256 TEXT,
  encryption TEXT NOT NULL CHECK (encryption IN ('x25519','passphrase')), recipients TEXT,
  blob_count INTEGER, blob_bytes INTEGER, db_size INTEGER, app_version TEXT, schema_version INTEGER,
  note TEXT, trigger TEXT NOT NULL CHECK (trigger IN ('manual','schedule','pre-upgrade','final','import')),
  job_id TEXT, created_by TEXT, created_at INTEGER NOT NULL, finished_at INTEGER,
  verified_at INTEGER, verify_ok INTEGER, error TEXT, copied_to TEXT);
CREATE INDEX backups_created ON backups(created_at);
```

**(0002)** `0002_roles.sql`: custom roles, role grants, role → group memberships and the `manager` grant level (§6a).
`users.role` keeps the built-in base; `users.role_id` names the custom role (NULL = the built-in role in `users.role`, so
the effective role id is `COALESCE(users.role_id, users.role)`). The triggers are defence in depth: the services validate
first and answer 422/409.

```sql
-- 0002_roles: custom roles ("classes"), role grants, role → group memberships
-- and the manager grant level (DESIGN §6a). users.role keeps the built-in base
-- role; users.role_id names an optional custom role (NULL = the built-in role
-- named by users.role). Applied in one transaction with foreign_keys=ON.

CREATE TABLE roles (
  id TEXT PRIMARY KEY CHECK (length(id) = 30 AND substr(id, 1, 4) = 'rol_'),
  name TEXT NOT NULL COLLATE NOCASE UNIQUE,
  description TEXT NOT NULL DEFAULT '',
  base TEXT NOT NULL CHECK (base IN ('member','guest')),
  permissions TEXT NOT NULL DEFAULT '[]',          -- JSON array of capability names (core.Capabilities)
  delegable INTEGER NOT NULL DEFAULT 0 CHECK (delegable IN (0, 1)),
  created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL,
  created_by TEXT REFERENCES users(id) ON DELETE SET NULL,
  updated_by TEXT REFERENCES users(id) ON DELETE SET NULL);

-- A base change would create or delete personal spaces for every holder.
CREATE TRIGGER roles_identity_fixed BEFORE UPDATE OF id, base ON roles
WHEN NEW.id IS NOT OLD.id OR NEW.base IS NOT OLD.base
BEGIN SELECT RAISE(ABORT, 'roles: id and base cannot be changed'); END;

-- No ON DELETE action: a role that is still assigned cannot be deleted
-- (falling back to the base could give its holders more rights).
ALTER TABLE users ADD COLUMN role_id TEXT REFERENCES roles(id);
CREATE INDEX users_role_id ON users(role_id) WHERE role_id IS NOT NULL;

CREATE TRIGGER users_role_id_ins BEFORE INSERT ON users
WHEN NEW.role_id IS NOT NULL AND NEW.role IS NOT (SELECT r.base FROM roles r WHERE r.id = NEW.role_id)
BEGIN SELECT RAISE(ABORT, 'users.role must equal the base of users.role_id'); END;
CREATE TRIGGER users_role_id_upd BEFORE UPDATE OF role, role_id ON users
WHEN NEW.role_id IS NOT NULL AND NEW.role IS NOT (SELECT r.base FROM roles r WHERE r.id = NEW.role_id)
BEGIN SELECT RAISE(ABORT, 'users.role must equal the base of users.role_id'); END;

-- Not a foreign key: used/revoked invites keep the id of a deleted role for the
-- record. AcceptInvite re-resolves it and refuses when it is gone; DeleteRole
-- revokes the open invites of the role.
ALTER TABLE invites ADD COLUMN role_id TEXT;
CREATE INDEX invites_role_id ON invites(role_id) WHERE role_id IS NOT NULL;
CREATE TRIGGER invites_role_id_ins BEFORE INSERT ON invites
WHEN NEW.role_id IS NOT NULL AND NEW.role IS NOT (SELECT r.base FROM roles r WHERE r.id = NEW.role_id)
BEGIN SELECT RAISE(ABORT, 'invites.role must equal the base of invites.role_id'); END;
CREATE TRIGGER invites_role_id_upd BEFORE UPDATE OF role, role_id ON invites
WHEN NEW.role_id IS NOT NULL AND NEW.role IS NOT (SELECT r.base FROM roles r WHERE r.id = NEW.role_id)
BEGIN SELECT RAISE(ABORT, 'invites.role must equal the base of invites.role_id'); END;

-- node_grants: subject 'role' and level 'manager'. SQLite cannot alter a
-- CHECK; nothing references node_grants, so it is rebuilt with every row and id.
CREATE TABLE node_grants_v2 (id TEXT PRIMARY KEY,
  node_id TEXT NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,
  subject_type TEXT NOT NULL CHECK (subject_type IN ('user','group','role')), subject_id TEXT NOT NULL,
  role TEXT NOT NULL CHECK (role IN ('viewer','editor','manager')), created_by TEXT,
  created_at INTEGER NOT NULL, expires_at INTEGER,
  UNIQUE (node_id, subject_type, subject_id));
INSERT INTO node_grants_v2 (id, node_id, subject_type, subject_id, role, created_by, created_at, expires_at)
  SELECT id, node_id, subject_type, subject_id, role, created_by, created_at, expires_at FROM node_grants;
DROP TABLE node_grants;
ALTER TABLE node_grants_v2 RENAME TO node_grants;
CREATE INDEX grants_subject ON node_grants(subject_type, subject_id);

-- Grants naming a deleted role go with it (DeleteRole also deletes them explicitly, to count them).
CREATE TRIGGER roles_delete_grants AFTER DELETE ON roles
BEGIN DELETE FROM node_grants WHERE subject_type = 'role' AND subject_id = OLD.id; END;

-- Role → group memberships: every holder of the role counts as a member (or
-- manager) of the group. Direct memberships (group_members) stay independent.
CREATE TABLE role_groups (
  role_id TEXT NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
  group_id TEXT NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
  member_role TEXT NOT NULL DEFAULT 'member' CHECK (member_role IN ('member','manager')),
  added_at INTEGER NOT NULL,
  added_by TEXT REFERENCES users(id) ON DELETE SET NULL,
  PRIMARY KEY (role_id, group_id)) WITHOUT ROWID;
CREATE INDEX role_groups_group ON role_groups(group_id);

-- Every membership, direct or through the role. A user may appear twice for one
-- group; readers that need one answer rank with
-- MAX(CASE role WHEN 'manager' THEN 2 ELSE 1 END) — never MAX(role): as
-- strings 'member' > 'manager'.
CREATE VIEW effective_group_members (group_id, user_id, role, source, via_role_id) AS
  SELECT m.group_id, m.user_id, m.role, 'direct', NULL FROM group_members m
  UNION ALL
  SELECT rg.group_id, u.id, rg.member_role, 'role', rg.role_id
  FROM role_groups rg JOIN users u ON u.role_id = rg.role_id;
```

**(0003)** `0003_zip_password.sql`: password-protected zip on upload (§8.1). Existing rows read as NULL (not protected).

```sql
-- 0003_zip_password.sql: password-protected zip-on-upload (DESIGN §8.1, §7.5).
-- upload_batches.zip_encryption: NULL = not protected.
-- upload_batches.zip_password_enc: Keys.SealField value, AAD
--   "upload_batches.zip_password_enc|<id>"; set to NULL as soon as the batch
--   leaves open/finalizing. Never selected by the batch API.
-- file_versions.zip_encryption: protection of that version's bytes; set only
--   by the upload.zip job (through Files.CommitFile), copied by copy/restore.
ALTER TABLE upload_batches ADD COLUMN zip_encryption TEXT
  CHECK (zip_encryption IS NULL OR zip_encryption IN ('aes256','zipcrypto'));
ALTER TABLE upload_batches ADD COLUMN zip_password_enc TEXT;
ALTER TABLE file_versions ADD COLUMN zip_encryption TEXT
  CHECK (zip_encryption IS NULL OR zip_encryption IN ('aes256','zipcrypto'));
```

**(0004)** `0004_fts_name_key.sql`: the search index over `nodes.name_key` shown in the listing above (0001 indexed `name`).

```sql
-- 0004_fts_name_key: the search index covers nodes.name_key (DESIGN §6) instead of nodes.name.
-- The trigram tokenizer folds case one code point at a time, so over the raw name "STRASSE" did not
-- find "Straße.txt" although the two names are equal in a folder. name_key is the full case fold
-- (names.Key); search folds the query the same way, for the index and for short LIKE queries alike.

DROP TRIGGER nodes_fts_ai;
DROP TRIGGER nodes_fts_ad;
DROP TRIGGER nodes_fts_au;
DROP TABLE nodes_fts;

CREATE VIRTUAL TABLE nodes_fts USING fts5(name_key, content='nodes', content_rowid='rid', tokenize='trigram');
CREATE TRIGGER nodes_fts_ai AFTER INSERT ON nodes BEGIN
  INSERT INTO nodes_fts(rowid, name_key) VALUES (new.rid, new.name_key); END;
CREATE TRIGGER nodes_fts_ad AFTER DELETE ON nodes BEGIN
  INSERT INTO nodes_fts(nodes_fts, rowid, name_key) VALUES ('delete', old.rid, old.name_key); END;
CREATE TRIGGER nodes_fts_au AFTER UPDATE OF name_key ON nodes BEGIN
  INSERT INTO nodes_fts(nodes_fts, rowid, name_key) VALUES ('delete', old.rid, old.name_key);
  INSERT INTO nodes_fts(rowid, name_key) VALUES (new.rid, new.name_key); END;
-- search: trigram MATCH on the folded query when it has >= 3 characters; LIKE on name_key otherwise.

INSERT INTO nodes_fts(nodes_fts) VALUES ('rebuild');
```

**Permission model** (implemented in `files`):
- Personal space (`kind=user`): owner → PermOwner on everything in it. Guests — and custom roles based on guest — have
  **no** personal space.
- Group space ("Team folder", `kind=group`): group `manager` → PermManage, group `member` → PermEdit. Membership is direct
  (`group_members`) or through the account's custom role (`role_groups`); `effective_group_members` is both, and the
  higher of the two roles wins.
- `node_grants` on a node apply to that node and all descendants (ancestor walk via recursive CTE, cached per request):
  `viewer` → PermView, `editor` → PermEdit, `manager` → PermManage. Grant subject may be a user, a group or a custom
  role (every account holding it; built-in roles are not grant subjects — use a group). Expired grants ignored.
- Admin/owner roles get **no** content access unless `auth.admin_can_access_files=true` (then PermManage everywhere, audited).
  The override is for the built-in owner and admin roles only; custom roles never get it.
- PermView: list/download/preview; PermEdit: upload/mkdir/rename/move-within/trash/restore; PermManage: grants + shares; PermOwner: purge/transfer.
  Restoring an item whose parent is in the trash puts it into the space root, which needs PermEdit there (403 otherwise).
- Creating a share link on a node requires PermManage (owner always qualifies), `sharing.links_enabled` and the
  `shares.links` permission of the creator's role (a file request: `sharing.requests_enabled` and `shares.requests`; §6a).
- Every denial returns 404 for nodes the principal cannot see at all (no existence leak) and 403 when visible but insufficient.

**Name rules**: NFC-normalized; 1–255 bytes UTF-8; no `/`, `\`, NUL, control chars, bidi embedding/override/isolate chars
(U+202A–U+202E, U+2066–U+2069; LRM/RLM/ALM are allowed); not `.`/`..`; no leading/trailing spaces;
trailing dots stripped for Windows-safety warning (allowed). Uniqueness is case-insensitive (`name_key` = casefold(NFC(name))).
Conflict policy `rename` produces `name (1).ext`, `name (2).ext`, …. When the ` (n)` does not fit in 255 bytes the base name is
shortened first, then the extension; at least the first rune of the name and something of the extension always survive, and the
result is trimmed, so the no-leading/trailing-spaces rule holds for conflict renames too (only reachable with an absurdly long
extension).

---

## 6a. Roles and permissions

Every account has exactly one **role**. The built-in roles `owner`, `admin`, `member` and `guest` keep their meaning;
administrators can add **custom roles** ("classes" in the owner's words; table `roles`, ids `rol_…`) that give accounts
a chosen set of **permissions** — to open parts of the Admin area (*server permissions*) or to shape an ordinary
account (*user permissions*) — and access to folders and groups. Code: `internal/core/roles.go` (catalog, `CapSet`, the
built-in sets), `internal/core/escalation.go` (§6a.4), `internal/users/roles.go` (roles, role → group memberships),
`mw.RequireCap` (route guards, §5.3), `internal/auth/caps.go` (the principal's permissions).

### 6a.1 Model

- **Custom role**: name, description, **base** (`member` = has "My files", `guest` = no personal space), permissions
  and `delegable`. The base is fixed (changing it would create or delete personal spaces for every holder; duplicate
  the role with `copy_from` instead). A custom role is never admin-based: every `IsAdmin()` / `role == 'admin'` check
  (Go, SQL, JS) treats its holders as members or guests, so a check the roles code missed fails closed; server power
  comes only from permissions.
- **Names in storage and API**: `users.role` keeps the built-in base (its CHECK is unchanged) and `users.role_id` names
  the custom role (NULL = the built-in role in `users.role`; triggers keep `users.role = roles.base`). In the API
  `role` is always the base and `role_id` the role the account has (`owner|admin|member|guest|rol_…`, never empty).
  Sending `role` without `role_id` gives that built-in role and removes a custom role (what clients from before custom roles mean).
- **Staff**: a built-in owner or admin, or an account whose role holds a server permission (`Principal.Staff`). On an
  API token the server permissions count only with the `admin` scope (`Principal.ServerAccess`, which is `Me.Staff`
  and subscribes the event stream to the server topics). **Delegate**: a staff account that is not a built-in owner
  or admin. **Delegable role**: one that delegates may give and whose holders they may manage — built-in Member and
  Guest always, Owner and Admin never, a custom role when an administrator sets `delegable` (default off: custom
  roles carry folders and groups, so handing one out is an administrator's decision).
- **Role access**: node grants to a custom role (`node_grants.subject_type = 'role'`) and role → group memberships
  (`role_groups`, `member` or `manager`: every holder counts as a member of the group and of its team folder,
  including people who get the role later). The grant level `manager` (every subject type) gives PermManage on that
  subtree — re-sharing, links, grants; in a team folder also purging and moving out, as for group managers; in a
  personal space those stay with the owner (PermOwner). `effective_group_members` lists direct and role memberships
  (a reader lets `manager` win when a user is in a group both ways) and is what every access query reads. Built-in
  roles are neither grant subjects nor group members (use a group).
- **Permissions and node permissions**: permissions decide *what kind* of action is allowed, node permissions (§6)
  *which items*: a share link needs `shares.links` **and** PermManage on the node.
- **Freshness**: the role and its permissions are resolved on every request from the SQL row that authenticates the
  session or token (`Principal.SetCaps(EffectiveRoleCaps(…))`; `mw.actAs` and `Files.SysPrincipalFor` build the same,
  pinned by `TestPrincipalCapsConsistent`), and `files` reads `users.role_id` inside each operation. A role change, a
  role edit that adds server permissions and a role deletion close the holders' step-up windows. After commit the
  users service publishes `authz.changed` (§5.3; §6a.3 says who receives it): the streams of the accounts concerned
  close and the web app reloads `/me`. API tokens are never revoked by a role change; they lose on their next request
  whatever the new role does not allow.
- **Feature flags and boot** (`pages.Features`, the page boot and `GET /me` alike): `links` and `requests` are the
  server switch and `shares.links` / `shares.requests`; `directory` is `users.lookup` or `users.view`; `tokens` is
  `tokens.create`; all four are off for anonymous visitors and before the second factor. The boot user carries
  `role_id`, `role_name`, `permissions`, `staff` and `space_id` — none of them before the second factor.
- **Limits**: a role name is 1–64 characters after trimming, has no control, text-direction or other invisible
  format characters (Unicode Cf such as a zero-width space, word joiner, BOM or soft hyphen: `names.IsHiddenFormat`;
  the joiners ZWNJ/ZWJ and the marks LRM/RLM/ALM stay allowed), does not start with `rol_`, is not `owner`, `admin`,
  `administrator`, `member`, `guest`, `system`, `everyone`, `all` or `none`, and is unique ignoring case and those
  joiners and marks (`names.LabelKey`; group names are compared the same way and refuse the same characters, and
  display names refuse them too); a description has at most 500 characters; at most
  200 custom roles and 500 group memberships per role. Unknown permission names are refused in input (422
  `permissions`) and ignored when stored ones are read.

### 6a.2 Permission catalog

The order is the bit order of `core.CapSet` and the order of the UI; it is **append-only** (never renumber or reuse a
bit — the database and the API store names). Implied permissions are added when a role is saved and when it is read.
Labels, descriptions and the warnings of the high-impact permissions live in `core.Capabilities` (`GET
/admin/capabilities`; the role editor shows the warnings before saving). Server permissions need the `admin` scope on
API tokens.

| # | Name | Group | Kind | Implies | High impact | Label |
|---|---|---|---|---|---|---|
| 0 | `shares.links` | sharing | user | | | Create share links |
| 1 | `shares.requests` | sharing | user | | | Create file requests |
| 2 | `users.lookup` | sharing | user | | | Find people and roles |
| 3 | `tokens.create` | sharing | user | | | Create API tokens |
| 4 | `users.view` | people | server | | | View people |
| 5 | `users.manage` | people | server | `users.view` | ✓ | Manage accounts |
| 6 | `users.credentials` | people | server | `users.view` | ✓ | Reset sign-in |
| 7 | `invites.manage` | people | server | `users.view` | | Invite people |
| 8 | `groups.manage` | people | server | `users.view` | ✓ | Manage groups |
| 9 | `shares.manage` | content | server | | | Manage everyone's links |
| 10 | `settings.manage` | server | server | | ✓ | General settings |
| 11 | `network.manage` | server | server | | ✓ | Network & VPN |
| 12 | `certs.manage` | server | server | | ✓ | Certificates |
| 13 | `backups.run` | server | server | | | Run backups |
| 14 | `system.view` | monitoring | server | | | Server status |
| 15 | `system.manage` | monitoring | server | `system.view` | ✓ | Operate the server |
| 16 | `audit.view` | monitoring | server | | | Audit and server logs |

Groups (UI sections): `sharing` "Sharing & account", `people` "People", `content` "Content", `server` "Server",
`monitoring` "Monitoring".

Sets (`EffectiveRoleCaps`, the only formula): owners, admins and the system principal hold every permission — one
added later too — plus the admin-only surfaces of §6a.3; Member holds `shares.links`, `shares.requests`,
`users.lookup` and `tokens.create` (`MemberCaps`); Guest holds nothing, plus `shares.links` and `shares.requests`
while `sharing.allow_guests_share` is on; a custom role holds its stored permissions with the implied ones, and the
guest setting never applies to it. A new role without `permissions` and `copy_from` starts with Member's four (base
`member`) or with nothing (base `guest`); `copy_from` starts from another role's permissions (owner or admin: all of
them, on base `member`).

### 6a.3 Admin-only surfaces, settings, jobs and events

Never in a custom role — built-in owners and admins only (`mw.RequireAdmin`, or the service):
- creating, editing and deleting roles (whoever edits roles can grant anything), always with step-up;
- the settings sections `auth`, `ratelimit`, `audit`, `email`, `backup`, `keys` and `server` (except the keys
  `log.*` and `runtime.*`), any section not mapped below, and `POST /admin/settings/email/test`;
- `/admin/keys*`, `PUT`/`DELETE /admin/certs/custom`, and backup download, restore, delete, import, configuration
  and identity (a backup holds everything; a restore brings back a database in which the delegate may have been an
  administrator);
- opening everyone's files (`auth.admin_can_access_files`) and seeing other people's link URLs;
- acting on owner accounts (owners only) and admin accounts (owners and admins), and giving the owner or admin role.

**Settings** (`internal/web/settingsapi/caps.go`): keys starting with `maintenance.`, `log.` or `runtime.` need
`system.manage`; otherwise the section decides: `general`, `storage`, `sharing` → `settings.manage`; `network`, `mdns`,
`funnel` → `network.manage`; `tls`, `acme`, `tailscale`, `mtls` → `certs.manage`; every other section is admin-only
(`TestSettingsSectionsHaveCap` fails for a registered section that is not listed). `GET /admin/settings` lists only the
keys the caller may change; `PATCH` and `DELETE` answer 403 with `field` = the key (`only administrators can change
<key>` or `changing <key> needs the “<Label>” permission`), checked for all keys of the request before the
managed-key check, step-up and the lockout guard (§11.2). Step-up for the sensitive sections applies whoever asks.

**Jobs**: `backup.*` kinds need `backups.run`, every other kind `system.manage` (run and cancel); a job's creator and
holders of `system.view` can read it. **Dashboard**: `recent_audit` only with `audit.view`, `last_backup` only with
`backups.run`.

**Events** (`internal/web/opsapi/sse.go`): `keys.state` to everyone; `upload.*` and `share.accessed` to the user they
concern; `job.*` to the job's creator and to `system.view`; `settings.changed` to any of `settings.manage`,
`network.manage`, `certs.manage`, `system.manage`; `network.changed`, `mdns.changed` and `ingress.changed` to
`network.manage`; `certs.changed` to `certs.manage`; `backup.finished` to `backups.run`; `system.restart` to nobody.
`authz.changed` goes to the accounts it names (by user id, or by role id to its holders) — their stream closes right
after it, except for `role_groups` and `role_details` (a new name, description or `delegable` flag changes nothing the
holders may do: the web app refreshes the role's name without telling them their access changed) — and to holders of
`users.view`, who stay connected; a recipient without `users.view` sees only their own id in `user_ids`.

### 6a.4 Escalation rules

Written once, in `internal/core/escalation.go`, and called by the users, auth and web packages inside their write
transactions against fresh rows. A refusal is 403 `forbidden` whose cause is a `core.EscalationError`.

`Covers(by, caps)`: `by` is a built-in owner or admin (or the system principal), or the server permissions of `caps` are
a subset of those of `by`'s role. User permissions are ignored on purpose (a Helpdesk without `shares.links` may still
create ordinary members), and so are token scopes (the action itself is gated by `Can`).

`CheckManage(by, target, need)` decides whether `by` may act on another account; `need` is `users.manage` (profile,
quota, `must_change_password`, disable/enable, unlock, delete) or `users.credentials` (password, 2FA reset, sessions,
passkeys, authenticators and tokens of others). Self-service (own profile, password, sessions, tokens) is allowed
before it is called.

| Order | Condition | Result |
|---|---|---|
| 1 | no principal | 401 |
| 2 | the system principal | ok |
| 3 | `!by.Can(need)` | 403 `this needs the “<Label>” permission` |
| 4 | the target is an owner, `by` is not | 403 `administrators cannot modify owner accounts` (`users.manage`) or `only an owner can manage the credentials of an owner` (`users.credentials`) |
| 5 | `by` is a built-in owner or admin | ok |
| 6 | the target is `by` | 403 `ask an administrator to change this on your own account` |
| 7 | the target is an admin | 403 `only administrators can manage administrator accounts` |
| 8 | the target holds a custom role that is not delegable | 403 `accounts with the role “<name>” can only be managed by an administrator` |
| 9 | the target has server permissions `by` lacks | 403 `this account has server permissions you do not have (<names>)` |
| 10 | otherwise | ok |

`CheckAssign(by, {To, Target})` decides whether `by` may give the role `To` — on create, role change, invitation and
acceptance; `Target` is the existing account (nil for new accounts and invitations). A self role change is refused
before (`you cannot change your own role`), and the route guard requires `users.manage` (accounts) or
`invites.manage` (invitations).

| Order | Condition | Result |
|---|---|---|
| 1 | the system principal | ok |
| 2 | `To` is owner, `by` is not an owner | 403 `only owners can grant the owner role` |
| 3 | `Target` is an owner, `by` is not | 403 `administrators cannot modify owner accounts` |
| 4 | `by` is a built-in owner or admin | ok |
| 5 | `To` is admin | 403 `only administrators can grant the admin role` |
| 6 | `To` is a custom role that is not delegable | 403 `administrators have not allowed account managers to give the role “<name>”` |
| 7 | `!Covers(by, To.Permissions)` | 403 `you can only give roles whose server permissions you have yourself (missing: <names>)` |
| 8 | `Target` is set and `CheckManage(by, Target, users.manage)` fails | that error |
| 9 | otherwise | ok |

Other rules:
- **Roles**: built-in owners and admins with the admin scope and step-up; built-in roles cannot be changed or deleted
  (422 `id`). Deleting a role with holders needs `reassign_to` (member, guest or another custom role; 409 otherwise —
  there is no implicit fallback, since the base could allow more than the role did); personal spaces follow a base
  change (a holder with personal files blocks a move to a guest-based role: 409 naming up to 10 of them); the role's
  open invitations are revoked and its grants and group memberships removed.
- **Groups**: `group_ids` on new accounts and invitations need `groups.manage` (403 field `group_ids`), and a
  `quota_bytes` on an invitation needs `users.manage` like a quota on an account (403 field `quota_bytes`); role → group
  memberships need `groups.manage` (a group manager can already add any account to any group). **Role grants** need
  PermManage on the node, like group grants: sharing one's own content with a role is not an escalation.
- **Staff invitations** (the admin role, or a custom role with a server permission): step-up, single use (422
  `max_uses`), at most 7 days (422 `expires_at`). Accepting an invitation whose custom role is gone, or whose base no
  longer matches, is the uniform 404 of an invalid invitation.
- **Invitations are checked again when accepted** (`users.inviteCheck`; `GET /auth/invite/{token}` answers the same
  404): a custom role that has a server permission needs a single-use invitation valid for at most 7 days from its
  creation, whenever the permission was added; and an invitation created by an account manager (not a built-in
  owner/admin or the system principal) needs its creator to be active and to pass today what `CreateInvite` demanded —
  `invites.manage`, `CheckAssign` for the role (delegable, server permissions covered), `groups.manage` for initial
  groups, `users.manage` for a quota. A link therefore never creates an account its creator could not invite now. The
  changes that can invalidate open invitations — a role edit of permissions or `delegable`, an account's role change,
  the deletion of a role whose holders move — also revoke them in the same transaction (`invite.revoke` with
  `reason` `staff_limits` or `creator_cannot_give` and `created_by`), so Admin → Invites shows them revoked.
  Built-in admin invitations were limited when they were created; those created before the limit keep working.
- **Invitation links** (`GET /admin/invites`): the `url` is shown to built-in admins, to the invitation's creator, and
  to callers who pass `CheckAssign` for its role and — when it adds people to groups — hold `groups.manage`; the link of
  a staff invitation also needs step-up. Other rows are listed without the link, so they can still be revoked.
  Invitations are revoked when their creator loses `invites.manage` (a role change, a role edit or the deletion of
  their role), as when an administrator is demoted.
- **Deleting with `transfer_to`** by a non-admin also needs `users.credentials` (403 `moving another person's files
  needs the “Reset sign-in” permission`) and `CheckManage(by, destination, users.manage)`; the destination may not be
  the delegate's own account (403 `you cannot move another person's files to your own account; ask an administrator`,
  audited as denied, instead of step 6's message about changing one's own account).
- **Own account**: a delegate never changes their own role, quota or `must_change_password` (step 6); profile,
  password, sessions and tokens stay self-service (`/me*`).
- **Tokens** (§9.3): the token's account needs `tokens.create`; the admin scope needs a staff account.
- **2FA**: `auth.require_2fa = admins` covers every staff account, and the doctor's `admin_2fa` check lists staff
  accounts without a second factor.
- **Denied attempts are audited**: a refusal by these rules from step 4 on (and by the `transfer_to` rule) records the
  attempted action (`user.create`, `user.update`, `user.delete`, `user.disable`, `user.enable`, `user.unlock`,
  `user.password_reset`, `user.mfa_reset`, `session.revoke`, `token.create`, `invite.create`) with `outcome: denied`
  and the details `{"reason", "missing"}`, after the transaction rolled back (§9.6). Guard refusals (`mw.RequireCap`,
  step 3) are not audited: the web app never offers them.

### 6a.5 Where it is enforced

- **Routes**: every `/api/v1/admin/*` route declares its guard in §9.4 — `Cap(…)` for a permission, Adm for the
  admin-only surfaces. `internal/wire/routecaps_test.go` lists every route with its guard (an undeclared admin route
  fails `TestEveryAdminRouteDeclared`) and proves each one on the real middleware chain for every built-in role, for a
  custom role holding exactly the listed permission, and for a role holding all 17 on the admin-only routes
  (`TestAdminRouteGuards`): built-in roles answer exactly as before custom roles existed.
- **Services** check again and decide which accounts, roles and items: the users service (`requireCap` plus §6a.4),
  auth (credentials of others, tokens), files (node permissions, role grants and the manager level), shares
  (`shares.links`, `shares.requests`, `shares.manage`), certificates (`certs.manage`), the settings API per key and
  the event stream per topic.
- **The web app** only hides what the caller cannot use (`me.staff`, `user.permissions`, the feature flags); the
  server is the authority.

---

## 7. Encryption (at rest)

### 7.1 Key hierarchy
```
passphrase ──argon2id──► (sealed mode only) wraps
MK  (32 B master key, keys/master.key)
 ├── KEK[blob]   (keyring row, wrapped by MK)  ──► wraps one DEK per blob
 ├── KEK[field]  (keyring row, wrapped by MK)  ──► seals sensitive DB columns, CA keys, custom cert key
 └── KEK[mac]    (keyring row, wrapped by MK)  ──► HKDF subkeys for HMACs (recovery codes, audit chain, share cookies, tickets)
DEK (32 B random per blob, wrapped by KEK[blob]; stored only in DB → deleting the row crypto-shreds the blob)
```
All wrapping uses AES-256-GCM with a random 96-bit nonce; stored as `nonce || ciphertext||tag`.

### 7.2 `keys/master.key` (JSON, 0600)
```json
{"v":1,"mk_id":"mk_…","mode":"plain","key":"<base64 32B>"}
{"v":1,"mk_id":"mk_…","mode":"sealed",
 "kdf":{"alg":"argon2id","t":3,"m_kib":131072,"p":4,"salt":"<b64 16B>"},
 "nonce":"<b64>","ct":"<b64 MK sealed with KDF key, AAD 'fp-mk|<mk_id>'>",
 "recovery":{"nonce":"<b64>","ct":"<b64 MK sealed with SHA-256(recovery key)>"},
 "escrow":{"pass":{"nonce":"<b64>","ct":"<b64 KDF key sealed with MK, AAD 'fp-mk-escrow|pass|<mk_id>'>"},
           "recovery":{"nonce":"<b64>","ct":"<b64 SHA-256(recovery key) sealed with MK, AAD 'fp-mk-escrow|recovery|<mk_id>'>"}}}
```
- **`escrow`** (optional, both modes): copies of the *unlock secrets* — the argon2id-derived passphrase key (sealed mode only) and the
  recovery hash `SHA-256(RK)` (whenever a `recovery` slot exists) — each sealed **under the MK itself** with AES-256-GCM and the AAD
  above. Opening them needs the MK, but they outlive it: whoever held an MK together with the key file that carried it keeps both
  secrets, and a master rotation does not change them, so they open every later key file too — until the passphrase is changed
  (fresh salt) and a new recovery key is exported. They exist so that
  `RotateMaster` can re-seal MK2 under the unchanged passphrase and keep the exported recovery key valid however the server was
  unlocked (passphrase or recovery key, before or after a restart) — see §7.6. Key files without `escrow` stay valid; a damaged or
  stale entry is ignored rather than blocking an unlock, and a seal/unseal/passphrase change rewrites a consistent set
  (`unseal` drops `escrow.pass` and keeps `escrow.recovery`).
- `meta.mk_check = HMAC-SHA256(MK, "fp-mk-check|" + mk_id)` detects a wrong/foreign key file (refuse to start with a clear error).
- MK bytes are kept in an mlock'ed buffer when possible (the parsed key file kept in memory never holds a plain key); never logged;
  zeroed on Lock. Best effort: short-lived copies (AES key schedules, the JSON of a plain key file being written) pass through
  ordinary Go memory.
- **Plain mode** (the default): unlocked at start. **Sealed mode**: server starts `locked` — only `/unlock`, `/trust*`, `/healthz`,
  `/readyz`, `/static/*`, `/api/v1/system/{status,unlock}` work; everything else → 503 `keys_locked` (pages redirect to `/unlock`).
  Unlock via web (rate-limited 5/min/IP; allowed from networks per `keys.web_unlock` = `lan|any|off`; `lan` = the private ranges of §10.3
  plus the global IPv6 subnets (/64 or longer) of the server's own up LAN/Wi-Fi/VPN interfaces in a role devices come in through —
  `local`, `mesh`, `unknown` (§10.1), never an outgoing, access or overlay VPN's — except next to a public IPv4 address)
  or `fileparcel keys unlock` (socket).
  Unlock accepts the passphrase or the recovery key (`FPRK-XXXX-…`, 256-bit, Crockford base32 groups).
- Master key file writes are atomic (`.tmp` + fsync + rename + dir fsync).

### 7.3 Blob file format (`data/blobs/ab/cd/<32hex>`)
```
Header (32 bytes):
  0..3   magic "FPB1"
  4      format version = 1
  5      cipher id (1 = AES-256-GCM, 2 = ChaCha20-Poly1305)
  6      seg_log2 = 16  (S = 65536 plaintext bytes per segment)
  7      flags = 0
  8..23  blob id (16 raw bytes)
  24..31 reserved (zero)
Segment i (i = 0 … N-1), N = max(1, ceil(P / S)):
  nonce (12 random bytes) || ciphertext (len_i bytes) || tag (16 bytes)       overhead O = 28
  len_i = S for i < N-1;  len_{N-1} = P - (N-1)·S   (0 for an empty blob)
  AAD_i = header[0:32] || uint64be(i) || byte(final ? 1 : 0)
Stored offset of segment i = 32 + i·(S + O);   stored size = 32 + P + N·O
```
- **Random nonces per segment** (not counters) so that re-uploading a part re-encrypts safely; the DEK is unique per blob, so the
  number of encryptions under one key stays far below GCM's random-nonce bound. Do not "optimize" this into a counter.
- The final flag in the AAD detects truncation/extension; the index detects reordering; the header (with blob id) in the AAD
  detects blob swapping. Any auth failure → `ErrCorrupt` (never return unauthenticated plaintext).
- **Random access**: plaintext offset `o` → segment `o >> 16`, inner offset `o & 0xFFFF`. `BlobReader` implements `ReadAt` and `Seek`
  (so `http.ServeContent` handles Range/If-Range/multi-range); it caches the last decrypted segment. Plaintext size P comes from the DB
  and is cross-checked against the file size on open.
- `Create()` (streaming writer, unknown size): buffers one segment, writes segments as they fill, marks the last one final on `Commit`,
  fsyncs file + directory, inserts/updates the `blobs` row (`state=ready`). Staging files are written directly at the final path with
  `state=staging` in the DB; `Abort` deletes both. GC removes `staging` blobs older than 48 h and files without rows.
- **Parted blobs** (uploads): `PartSize = 8 MiB = 128 segments`. Size P is declared up front, the file is preallocated
  (`fallocate`/`Truncate` to stored size), and part n covers segments `[128n, 128n+127]` — written with `WriteAt` at their fixed stored
  offsets, streaming (one segment of buffering), while computing SHA-256 of the part plaintext. The part is recorded as done only after
  the digest matches `wantSHA256`; on mismatch the part's bytes are simply rewritten by the retry. `Commit(partDigests)` requires all
  parts, then sets `content_hash`.
- **content_hash** = `"fp1:" + hex(SHA-256(concat(SHA-256(chunk_k))))` over 8 MiB plaintext chunks (the same for parted and streamed
  blobs; an empty blob hashes the empty concatenation). The upload client computes the same per-part digests.
- The storage directory is accessed through `os.Root` (Go 1.24+) opened on `data/blobs`; blob paths are derived only from validated
  32-hex IDs; user-supplied names never touch the filesystem.

### 7.4 DEK wrapping
`wrapped_dek = AES-256-GCM(KEK[blob], nonce, DEK, AAD = "fp-dek|" + blobID)`; `blobs.kek_id` names the KEK.

### 7.5 Field encryption
`SealField(aad, pt)` → `"v1:<kek_id>:" + base64url(nonce || ct)` under KEK[field]. AAD strings (binding the value to its row):

| Column | AAD |
|---|---|
| totp_secrets.secret_enc | `totp_secrets.secret_enc\|<user_id>` |
| webauthn_credentials.credential_enc | `webauthn_credentials.credential_enc\|<id>` |
| invites.token_enc | `invites.token_enc\|<id>` |
| shares.token_enc | `shares.token_enc\|<id>` |
| upload_batches.zip_password_enc | `upload_batches.zip_password_enc\|<id>` (the password of a protected zip upload, §8.1) |
| settings.value (secret keys) | `settings.value\|<key>` |
| certs/ca/ca.key.enc, client-ca.key.enc | `file\|certs/ca/<name>` |
| certs/custom/key.pem.enc | `file\|certs/custom/key.pem` |

Tokens (session, PAT, invite, share, archive ticket, setup) are ≥128-bit random, so DB lookups use `SHA-256(token)` (`token_hash`).
Recovery codes (low entropy) are stored as `MAC("recovery", user_id, normalized_code)`.

### 7.6 Rotation
- `RotateKEK("blob")`: create new active KEK, retire old, re-wrap every DEK in batches of 500 rows per transaction (DB-only, fast;
  resumable because each row names its kek_id). `RotateKEK("field")`: same, re-sealing every column in §7.5 (files re-sealed too).
  Retired KEKs stay in the keyring until nothing references them **and** they have been retired for at least 15 minutes, so
  `keys status` still lists them right after a rotation (`keys verify` reports those still referenced; `keys rotate` deletes the rest).
- The `mac` KEK is not rotated separately (it would invalidate recovery codes and the audit chain); it changes only with a master rotation
  that re-wraps it (value unchanged).
- `RotateMaster()`: generate MK2; write `keys/master.key.next` (same mode — the passphrase and the recovery key are **unchanged** and
  are not asked for again: MK2 is re-sealed under the passphrase-derived key and the recovery hash taken from the `escrow` object of §7.2
  or from the unlock in progress); in one DB transaction re-wrap all keyring rows under MK2 and update `meta.mk_id/mk_check`; then
  atomically rename `.next` → `master.key`. Because the unlock secrets stay, a master rotation alone does not lock out someone who
  holds an older key file and its MK (§7.2 `escrow`); after a suspected key-file leak the passphrase must be changed and a new
  recovery key exported as well (and the blob/field KEKs rotated if the database may have leaked too: MK2 re-wraps them unchanged).
  Exception, for a key file that carries no `escrow` (hand-written or from an older build): when the server was unlocked with the
  *recovery key*, the passphrase-derived key is unknown and the rotation fails with `ErrPrecondition` (set a new passphrase first);
  an unknown recovery hash invalidates the old recovery key (export a new one; `Status` then reports `recovery_configured=false`).
  Startup recovery: if `.next` exists, it wins (and is renamed over `master.key`) when its `mk_id` equals `meta.mk_id` — that is,
  when the keyring transaction committed; otherwise it is removed. `mk_check` cannot decide this: computing it needs the MK, which a
  sealed `.next` does not yield without the passphrase.
- Optional **data re-encryption** job (`keys.reencrypt`): per blob decrypt → re-encrypt with fresh DEK into a new blob id → swap
  references (`file_versions.blob_id`, `nodes.thumb_blob_id`) in one tx → delete the old blob. It pauses (progress note *"waiting for
  a running backup"*) while a full backup holds the blobs — from before its database snapshot until the last blob is copied — since
  deleting an old blob the snapshot lists would leave the archive without that file; each blob, from the copy to the deletion of
  the old one, runs under that hold.
- **Mutual exclusion with a running backup.** `backup.create` snapshots the database and copies `keys/` and `certs/` under a read
  hold on the key material; while it holds it, `RotateMaster()` and `RotateKEK("field")` fail fast with `ErrConflict` (409,
  *"a backup is copying the key material right now; start the rotation again when it has finished"*). The hold is released as soon
  as the last `certs/` member is written, so the long blob phase of a full backup never blocks a rotation, and `RotateKEK("blob")`
  is never blocked (it touches no on-disk key material). `RotateMaster()` and `RotateKEK("field")` also exclude each other: the
  second one fails fast with `ErrConflict` (*"another key rotation is changing the key material right now; start this one again
  when it has finished"*). Conversely, if a rotation slips through anyway, the backup aborts with
  `ErrConflict` instead of writing an archive whose database and key files disagree: the writer re-reads `meta.mk_id` and the active
  field-KEK id after the key and certificate members and compares them against the snapshot, the archive header carries `mk_id`, and
  every verify, restore and import rejects an archive whose `keys/master.key` names a different master key than its header.

### 7.7 Cipher selection
`storage.cipher` = `auto|aes-gcm|chacha20-poly1305`. `auto` picks AES-256-GCM only on the architectures for which Go ships AES and
GHASH assembly, and only when the CPU has the instructions: AES+PCLMUL (amd64), AES+PMULL (arm64), POWER8 or later (ppc64/ppc64le)
and s390x's message-security assist; otherwise ChaCha20-Poly1305 (e.g. Raspberry Pi 4, and 386, where Go's AES is a table-driven
pure-Go implementation). Readers always honour the header's cipher byte.

### 7.8 What is and isn't encrypted at rest
Encrypted: all file contents, thumbnails, backup archives, TOTP secrets, passkey credentials, share/invite tokens, secret settings,
CA/custom private keys, and the password of a password-protected zip upload while its batch is open or finalizing (sealed, then set
to NULL when the batch ends, §8.1). **Not** encrypted (metadata needed for queries): file/folder names, sizes, timestamps, user
names/emails, audit log, the TLS leaf key, and which file versions are password-protected zips (`file_versions.zip_encryption`).
This is documented in `docs/ENCRYPTION.md` and `docs/SECURITY.md`; full-disk encryption (LUKS/FileVault) is recommended for metadata
confidentiality.

A password-protected zip carries two independent layers: the zip's own encryption under the uploader's password (§8.2), which the
recipient needs after downloading, and FileParcel's at-rest encryption of its blob, which is the same as for any other file.
FileParcel keeps no way to open the first layer once the batch has ended.

---

## 8. Uploads & downloads

### 8.1 Upload protocol
1. **Create batch** — `POST /api/v1/upload-batches`
   ```json
   {"folder_id":"nod_…","mode":"files|zip","zip_name":"Photos.zip","conflict":"rename|replace|skip|fail",
    "zip_encryption":"aes256|zipcrypto","zip_password":"…",
    "files":[{"client_ref":"f1","rel_path":"Trip/day1/a.jpg","size":123456,"mtime":1726700000000,"kind":"file"},
             {"client_ref":"d1","rel_path":"Trip/empty","size":0,"kind":"dir"}]}
   ```
   `zip_encryption`/`zip_password` are optional and mode=zip only (see *Password-protected zips* below).
   Server checks PermEdit on the folder, validates every path segment (§6 name rules; rejects `..`, absolute paths, >64 depth,
   >4096 bytes), reserves quota (`declared_bytes`), and (mode=files) creates missing folders lazily at commit time.
   Taken names are looked up at declaration (`uploads/preflight.go`, resolving paths as `CommitFile` will, numbered folders
   included), so a policy that does not store the new file finds out before any byte is sent: mode=files `skip` declares such a
   file `skipped` (nothing reserved; the client sends nothing), `fail` refuses the declaration (409, "“a/b.txt” already
   exists in this folder"); mode=zip `fail` on a taken `zip_name` and `replace` onto a folder of that name are 409, and `skip`
   declares every file `skipped` — completing such a batch marks it `done` without a job or a .zip (no `result_node_id`), even if
   the name was freed meanwhile. The same applies to `POST …/files`. The node commit still applies the policy, for names taken
   after the declaration.
   A mode=zip batch is stored as one file, so it reserves the bound of its .zip (the data plus the zip format's overhead) and
   that bound must fit `storage.max_file_gb` and the request's `upload_max_file_bytes` (413 on `files` otherwise).
   Declared sizes are bounded so they cannot disable the checks they feed: a `files[].size` above `uploads.MaxDeclaredFileBytes`
   (2^43 bytes, 8 TiB — the 2^20 parts of 8 MiB the part routes accept) is 413, a batch whose declared sizes would overflow
   `int64` is 422 on `files[i].size`, and the space-quota, file-request-quota and free-disk guards refuse a negative amount
   instead of treating it as "nothing to check". Response:
   ```json
   {"id":"upb_…","state":"open","part_size":8388608,"parallel":4,"small_max":8388608,"expires_at":"…",
    "files":[{"id":"upf_…","client_ref":"f1","part_count":1,"parts_done":[],"state":"pending"}]}
   ```
   More files may be added with `POST /api/v1/upload-batches/{id}/files` (same item shape) — the client streams large selections in
   chunks of 1000 entries.
2. **Upload data**
   - Large files (size > `small_max`): `PUT /api/v1/uploads/{upf}/parts/{n}` (n from 0), raw body of exactly the part's length,
     header `X-FP-SHA256: <hex>` of the part plaintext. 204 on success. Idempotent: re-sending a done part with the same digest → 204;
     with a different digest → 409. Up to `parallel` parts in flight per client (across files).
     The wrong length, a bad part number or a malformed digest are rejected from the headers alone, before the body is read, so a
     non-browser client should send `Expect: 100-continue`: it then gets the 422 (e.g. `part 2 must be exactly 12345 bytes (got
     8388608)`) instead of a TCP reset while it is still writing megabytes that the server has already stopped reading. The browser
     client slices exactly and cannot set the header, so it never needs it.
   - Small files (≤ 8 MiB, incl. 0-byte): `PUT /api/v1/upload-batches/{upb}/small?ref=<client_ref>` raw body + `X-FP-SHA256`.
     For mode=files this commits the node immediately and returns the file state (with `node_id`). Re-sending the same
     content is idempotent, except for a file whose node commit failed for good: that answers the failure (409), as
     `…/complete` does. The body is read without holding the file's lock, so a slow sender never delays an abort.
3. **Resume** — `GET /api/v1/uploads/{upf}` → `{"parts_done":[0,1,5], "state":"uploading", …}`. After a page reload the user must
   re-select the files (browsers can't persist `File` handles); the client matches by `rel_path`+`size`+`mtime`
   (then `rel_path`+`size`). Files picked without their folder, or a folder re-picked from inside, match by file
   name+`size`+`mtime` only where that is unambiguous; a picked file is attached to one item at most.
4. **Complete** — `POST /api/v1/uploads/{upf}/complete` (all parts present → blob commit → node commit for mode=files; a gap is
   409 "the upload is incomplete: have 2 of 3 parts (missing: 1)"). Conflict `replace` with byte-identical content (the same
   content hash and zip protection as the current version) adds no version: `Files.CommitFile` returns the node unchanged, the
   upload is committed to it and the blob it sent is deleted, so re-sending a file never charges a second copy.
   `POST /api/v1/upload-batches/{upb}/complete` → for mode=files commits the nodes of files a transient failure left `uploaded`,
   verifies all files committed/skipped/failed and releases leftover reservation; for **mode=zip** it checks the .zip against
   `storage.max_file_gb`, the space quota and free disk once more (a refusal keeps the batch open), enqueues job `upload.zip` and
   returns `{"state":"finalizing","job_id":"job_…"}`. The job streams every staged blob (sorted by rel_path, directories included
   as entries) through `ziputil` into a new blob (`blobstore.Create`), commits a single node `<zip_name>` in the folder (conflict
   policy applies), deletes the staged blobs, publishes
   `upload.batch_done` and `job.done`. Progress is visible through SSE `/api/v1/events` and `GET /api/v1/jobs/{id}`.
   A zip job cut short by a shutdown or crash leaves the batch finalizing with its staged data; `maintenance.uploads` enqueues it
   again (for up to `storage.upload_expiry_hours`). Only an explicit job cancel or a zip error fails the batch and deletes the data.
5. **Abort** — `DELETE /api/v1/upload-batches/{upb}` or `DELETE /api/v1/uploads/{upf}` → staged blobs removed, reservation released
   (409 once the batch is finalizing).
6. **Expiry** — batches not completed within `storage.upload_expiry_hours` (48) are expired by the `maintenance.uploads` job.
7. **Limits** — `storage.max_file_gb` (0 = unlimited), user/space quota, disk free-space check (refuse if it would leave < 1 GiB or
   < 2% free; zip mode needs 2× space temporarily), request body limits (`MaxBody(part length + 0)`), per-user concurrent batch cap (20;
   `409 conflict` "too many unfinished uploads (at most 20); cancel the ones you no longer need … or wait until they expire, 48 hours
   after they started" — not 429, which clients retry by themselves). A quota refusal names the sizes (`humanBytes`) and, when open
   batches hold part of the space, how much: "… (unfinished uploads hold 858.3 MiB until they finish, are cancelled or expire)".
8. **File requests** (public upload links): the same endpoints under `/s/{token}/api/…` with `UploadActor{ShareID, Uploader}`;
   the share owner is the quota owner; `upload_max_file_bytes` and `upload_quota_bytes` enforced; uploads land in the share's folder
   (conflict=rename); `require_uploader_name` adds an `uploader` field; the owner may be notified (`notify_owner`).
   A folder **link** with `allow_upload` takes the same uploads; its share page puts them in the folder being viewed
   (`rel_path` below the share's folder). Visitors see a share's contents only when downloads or previews are allowed, and
   for a link without `allow_upload` — never for a request, nor for an upload-only link (a drop box).

**Password-protected zips** (`internal/uploads/zippassword.go`). A mode=zip batch may carry `zip_password` (write-only) and
`zip_encryption` (`aes256`, the default when only a password is sent, or `zipcrypto`); the job then encrypts every file entry of the
.zip (§8.2). The batch answers (`POST`, `GET /upload-batches/{id}`, `upload.batch_done`) carry `zip_encryption`, never the password.
- **Validation** (`zipProtection`, when the batch is created; later setting changes do not affect open batches), each refusal 422
  `invalid` on the field that is set, with a message that never contains the value: a file request (`/s/{token}/api/…`: the owner
  could not open the result) → "password-protected .zip files are not available for file requests"; mode=files → "a .zip password
  needs mode zip"; an unknown method → `zip_encryption`; `zipcrypto` while `storage.zip_legacy_encryption` is false →
  `zip_encryption` "ZipCrypto is turned off on this server; use AES-256"; then the password rules of `checkZipPassword`: printable
  ASCII only (unzip programs encode other characters differently), `storage.zip_password_min` (12; 8–64) to 99 bytes
  (`ziputil.MaxPasswordLen`: 7-Zip refuses longer WinZip AES passwords and then reports a wrong password; one limit for both
  methods), no leading or trailing space, at least 4 different characters (case-folded), and not on the common-password list
  (`crypt.IsCommonPassword`, shared with account passwords).
- **Sealed at once**: `Keys.SealField("upload_batches.zip_password_enc|<batch id>", pw)` (§7.5; 503 `keys_locked` while locked),
  inserted in the same transaction as the batch row. `batchCols` never reads the column; only `openZipPassword` does. Job params stay
  `{"batch_id"}`; the password is never in job params, results, errors or notes, audit details, events, logs (`core.Secret` and
  `BatchInput.LogValue` redact it for `fmt` and `slog`), API answers or URLs.
- **Complete** opens it first (fail fast, the batch stays `open`): 412 `precondition_failed` "the password of this upload is no longer
  available; upload the files again", 500 `corrupt` "the password of this upload could not be decrypted", 503 `keys_locked`. An enqueue
  error puts the batch back to `open` with the value kept, so it can be completed again.
- **The job** opens it right before it builds the .zip (`ziputil.Options{Encryption, Password}`; every file through `AddFileAt` with a
  context-aware `ReaderAt`, so a cancel stops inside a long entry) and records `FileMeta.ZipEncryption` on the new file version —
  unless the batch had no file entries (a .zip of empty folders is not protected and gets no badge). Its result adds `"encryption"`.
  Locked keys postpone instead of failing: the job fails without touching the batch (still finalizing, with its data and the sealed
  value) and `maintenance.uploads` runs it again.
- **Wiped** by the statement that moves the batch out of `open`/`finalizing`: `done` (the zip job; mode=files batches too,
  defensively), `failBatch` (a zip error; a batch stuck past its retries), `abort` (DELETE, expiry); `maintenance.uploads` also sets
  every value left on a row outside `open`/`finalizing` to NULL before the 7-day purge, and deleted rows (cascades, purge) take it
  along. Lifetime: up to `storage.upload_expiry_hours` while the batch is open; while it is finalizing, until it ends — a job
  interrupted by a shutdown, a crash or locked keys is run again by the hourly `maintenance.uploads` for up to
  `storage.upload_expiry_hours` after finalizing began (then the batch fails), and a job cancelled by hand fails the batch at the next
  hourly run. KEK rotation re-seals the column (§7.6; its compare-and-swap never brings back a value wiped meanwhile); a backup taken
  while a batch is in flight holds the sealed value.
- **Recorded per version**: `file_versions.zip_encryption` (`aes256`|`zipcrypto`|NULL), set only by the zip job through `CommitFile`
  (`FileMeta.ZipEncryption` is `json:"-"`; other values are 422), exposed as `Node.zip_encryption` (the current version; every
  listing, search, recent, starred, trash, SSE node events, the public share API) and `FileVersion.zip_encryption`. Replace, copy
  (also of folders, `copyChildren`) and copy-replace keep it; restoring a version takes that version's value. Audit: `file.upload`
  (and the copy-replace and restore entries) and the failure entry of a zip batch name `zip_encryption`.

**Browser client** (`web/static/js/upload/*`): two pickers — "Upload files" (`<input type=file multiple>`) and "Upload folder"
(`<input type=file webkitdirectory>`; hidden when unsupported, e.g. iOS) — plus a full-window drop zone that accepts mixed files and
folders via `DataTransferItem.webkitGetAsEntry()`, looping `readEntries()` until empty and preserving empty directories. A
pre-upload dialog offers destination, **"Bundle into a single .zip"** + name, **"Protect the .zip with a password"** (§13.6), and
conflict policy. A Web Worker (`hash-worker.js`)
computes per-part SHA-256 with `crypto.subtle.digest` (reads `file.slice()` per part). 4 parts in flight overall, exponential
backoff (1s→30s, 6 tries), pause/resume/cancel per file and globally, speed + ETA, `navigator.wakeLock` while uploading, and a
`beforeunload` warning. A 429 on a data request (the per-IP `api` or `share` rate limit, which a folder of many small files
reaches — each is one request) is not charged to the file: the whole engine waits for `Retry-After` (1 s without one) and then
spaces its requests out (a gap of 25 ms, doubled by every further 429 up to 1 s, 2 % shorter after every success). The
upload panel also lists the user's unfinished batches this browser has no record of (`GET /upload-batches`: another device,
cleared site data, a killed CLI upload) with a Discard button, since each holds its reservation and one of the 20 slots until
it expires: on page load those idle (`updated_at`) for an hour, after a batch could not be declared (quota, batch cap) all.

### 8.2 Downloads & previews
- `GET /api/v1/nodes/{id}/content[?version=ver_…][&inline=1]` → `http.ServeContent` over `BlobReader` (Range, multi-range,
  If-Range, If-None-Match; `ETag: "<version_id>"`; `Last-Modified`). Default is `Content-Disposition: attachment`.
- A `version` other than the current one is always `Content-Type: application/octet-stream` +
  `Content-Disposition: attachment` with the full sandbox CSP, whatever `inline=1` asks and whatever `nodes.mime` says:
  `nodes.mime` describes the current version only, and `file_versions` records no type of its own, so an older version must not
  inherit an inline type the current one happens to have. The `ETag` is still the requested version id. For the same reason,
  restoring a version (`POST /nodes/{id}/versions/{vid}/restore`) detects the type of its content again (`names.DetectMIME`).
- `inline=1` is honoured **only** for the inline allow-list: `image/{png,jpeg,gif,webp,avif,bmp}`, `video/{mp4,webm,ogg,quicktime}`,
  `audio/*`, `application/pdf`, and `text/*` + common code/markup types which are served as `text/plain; charset=utf-8`.
  Everything else (notably `text/html`, `image/svg+xml`, XML, JS) is always an attachment with `Content-Type: application/octet-stream`.
- Content responses always carry: `X-Content-Type-Options: nosniff`, `Cross-Origin-Resource-Policy: same-origin`,
  `Cache-Control: private, no-cache`, and `Content-Security-Policy: default-src 'none'; img-src 'self' data:; media-src 'self';
  style-src 'unsafe-inline'; sandbox` — except `application/pdf` inline, which omits `sandbox` (Chrome's PDF viewer breaks under it)
  but keeps `default-src 'none'; object-src 'self'; frame-ancestors 'self'`.
- MIME: detected at upload from extension (`mime.TypeByExtension` + built-in table) and `http.DetectContentType` of the first 512 bytes;
  stored in `nodes.mime`; the sniffed type wins if the extension claims a dangerous inline type.
- `GET /api/v1/nodes/{id}/thumb` → JPEG (or PNG when alpha) ≤ 320 px, generated asynchronously (`thumbs.generate` job) for images
  ≤ 50 MP (checked via `image.DecodeConfig` before decoding) and stored as encrypted blobs (`nodes.thumb_blob_id`); 404 when absent.
  The 256 MiB decode budget charges what each decoder really allocates (`thumbs.decodeCost`), read from headers `DecodeConfig` skips,
  not the colour model it reports: **JPEG** 1 (gray), 3 (YCbCr), 7 (RGB/Adobe: planes + RGBA copy) or 8 (CMYK/YCbCrK) bytes per pixel
  of the MCU-rounded frame, plus 4 per component for a **progressive** frame (`image/jpeg` keeps one `int32` coefficient per pixel and
  component for the whole image: 5/15/19/24); **PNG** its colour model, except gray with a `tRNS` chunk (decoded as NRGBA 4 or NRGBA64 8)
  and ×1.5 for Adam7 (the passes sit next to the full image); **WebP** 3 (a plain lossy frame), 7 (lossless or VP8X: colour-indexed
  pixels are unpacked next to the NRGBA result) or 8 (with alpha, itself a lossless image); GIF and BMP their colour model. Headers
  that cannot be followed are charged the worst case. An image over budget gets no thumbnail (404, the same outcome as any other
  unsupported image): e.g. a progressive JPEG above roughly 17 MP, CMYK JPEG or 16-bit transparent-gray PNG above 33 MP, lossless
  WebP above 38 MP. The scaler's temporary (≤ ~72 MB for `draw.CatmullRom`) is a fixed per-job overhead on top.
- **Archives**: `POST /api/v1/archives {"node_ids":[…],"format":"zip|tar","name":"…"}` → `{"ticket":"…","url":"/api/v1/archives/<ticket>"}`
  (single-use, 60 s, bound to the user or share; stored hashed). `GET /api/v1/archives/{ticket}` streams (no Content-Length) so a
  plain browser navigation downloads it with native progress. `ziputil`:
  - walks via `Files.Walk` (keyset-paged, bounded memory), writes directory entries for empty folders;
  - **Store** for already-compressed types (jpg/jpeg/png/gif/webp/avif/heic/mp4/mov/mkv/webm/mp3/aac/ogg/flac/zip/7z/rar/gz/bz2/xz/zst/
    docx/xlsx/pptx/odt/epub/apk/jar/pdf), **Deflate** (klauspost flate, level 5 via `RegisterCompressor`) otherwise;
    `storage.zip_compression` = `auto|store|deflate`;
  - sets `UncompressedSize64` up front so zip64 extras are emitted when needed; UTF-8 flag; `Modified` from `client_mtime`/`updated_at`;
  - sanitizes names (no `..`, no leading `/`, backslashes → `_`), de-duplicates colliding names with ` (n)`;
  - honours context cancellation (client disconnect stops the walk).
  - tar format (`archive/tar`, PAX headers) for macOS Archive Utility users.
  - **password protection** (zip-on-upload only, §8.1; folder downloads never encrypt): `Options.Encryption` = `aes256` (WinZip
    AE-2: per entry a fresh 16-byte salt, PBKDF2-HMAC-SHA1 × 1000 → AES-256 key, HMAC key and a 2-byte verifier; AES-256-CTR with the
    WinZip little-endian counter from 1; HMAC-SHA1-80 over the ciphertext; method 99, extra `0x9901` naming the inner method, CRC 0)
    or `zipcrypto` (traditional PKWARE, 12-byte header whose check byte is the CRC's high byte; weak) plus `Password` (printable ASCII,
    ≤ `MaxPasswordLen` 99, 7-Zip's limit for WinZip AES; `New` refuses tar, a method without a password or the reverse, and an
    unknown method — no error names the password). Every **file** entry is encrypted, compressed first; directory entries stay
    plain, and names, sizes, times and the entry count stay readable (a limit of the format). Entries go through
    `archive/zip.Writer.CreateRaw` with a **complete local header and no data descriptor** (the layout streaming readers need), so
    every header value is known first: they are added
    with `AddFileAt(name, mod, size, io.ReaderAt)` (`AddFile` on an encrypting Writer is `ErrReaderAtRequired`). Entries up to 4 MiB
    are read into memory once; a larger one is read twice only when its header needs a value of the data (the ZipCrypto CRC, the
    Deflate length) — AES with inner Store streams in one pass. The second pass re-checks the plaintext CRC and the compressed length
    and CRC (`ErrSourceChanged` on a difference). Deflate falls back to Store when it does not shrink the entry. A size of exactly
    `0xFFFFFFFF` sets flag 3 with every value filled in (Go writes no local zip64 extra for it). The plaintext buffers are cleared after
    every entry and released, with the password, by `Close`. Without encryption `AddFileAt` writes exactly what `AddFile` writes.

---

## 9. HTTP surface

### 9.1 Middleware stack (order)
Listener level (package `server`), before any HTTP parsing:
1. **Allowlist** check of the remote address (IPv4-mapped IPv6 unmapped) → close immediately if denied (no TLS handshake).
2. **Protocol sniff** on the HTTPS port: first byte `0x16` → TLS; otherwise plain HTTP → 308 redirect to `https://<host>:<port><uri>`.
   The optional HTTP port (8080) serves ACME HTTP-01 challenges and 308 redirects only.
A TLS request carrying `Tailscale-Funnel-Request` gets **403** with the removal command (`tailscale serve --yes --https=<port>
off`, then `fileparcel network funnel enable`) and counts in `httpx.ProxySignals.FunnelToMain`: tailscaled strips that header from
client input, so it can only come from a hand-made `tailscale funnel` pointed at FileParcel's own port (on this machine or another
tailnet node), which would make every visitor look like one address. The **admin socket** refuses (403, error log ≤ 1/min) requests
carrying `X-Forwarded-For`, `X-Forwarded-Host`, `Forwarded`, `Via` or any `Tailscale-*` header (`tailscale serve
unix:<HOME>/run/admin.sock` would hand every visitor the system principal); the CLI's `X-FP-As` stays allowed.
**Ingress listeners** (Tailscale Funnel/Serve, §10.6; `server/ingress.go`): opened and closed by the Ingress service through
`core.IngressListeners` (`Attach` right after the listeners above are up; `Detach`, bounded to 5 s, before the drain, then they drain
with the other servers), one per kind — with the TCP backend plus the kind's previous 127.0.0.1 port while tailscaled may still
route to it (the server's manager also has `OpenAt`/`CloseAt`, which tsingress type-asserts) — : `run/ts-{funnel,serve}.sock` (0600; a stale file is replaced, a live one is an error; the path
must fit `sun_path`, no short alias) or `127.0.0.1:<port>` (a busy port is an error). Only peers with uid 0, the owner of tailscaled's
socket or the server's own uid are accepted at Accept (Unix: `SO_PEERCRED`/`LOCAL_PEERCRED`; TCP on Linux: the peer socket's row in
`/proc/net/tcp{,6}`; elsewhere accepted with a one-time warning). They serve plain HTTP/1.1 (TLS ended in tailscaled; no redirect, no
mTLS gate, not in the connection tracker) through `server.ingressHandler`, which trusts tailscaled's headers only there:
`X-Forwarded-For` must be one line with one address (no port or zone; not loopback, unspecified or multicast) → else 400;
policy `off` → 404; `X-Forwarded-Host` (the client's Host — tailscaled routes by SNI) lowercased without a trailing dot must be the
MagicDNS name and a port, if any, the kind's port → else 421, and becomes the request's Host (`name` or `name:port`);
`Tailscale-Funnel-Request` on the serve listener → 403 (Funnel was turned on for the tailnet-only port; noted as a conflict), on the
funnel listener it marks the request public; `GET /.well-known/fileparcel-ingress-probe/<nonce>` of a running self-probe → 204.
Then `RemoteAddr` becomes the client's address, the context gets `core.IngressInfo`, and `X-Forwarded-*`, `Forwarded`, `X-Real-Ip`,
`Via`, every `Tailscale-*` header and `X-FP-As` are removed.
**Server limits** (`http.Server`): `ReadHeaderTimeout` 10 s, `IdleTimeout` 120 s, `MaxHeaderBytes` 64 KiB, and a rolling 30 s read
deadline on every request that carries a body — armed before the handler (so a request refused without reading its body is not parked
in net/http's body drain) and extended by each read, so a stalled (slowloris) sender is torn down while a slow but steady upload is
not. Bodyless requests keep no read deadline: one would cancel their context and break long downloads and event streams.
Root router (`web/router.go`):
3. `RequestID` (X-Request-ID, 16 random bytes b62) → 4. `Recover` (500; a panic after the response started aborts the
connection/stream instead of ending a truncated body cleanly) → 5. `ClientIP` (X-Forwarded-For only from `server.trusted_proxies`;
an ingress request's client is `IngressInfo.ClientIP`, trusted proxies not consulted; a forwarded request from an unconfigured proxy on
this machine — loopback or an own address — or carrying `Tailscale-User-Login` counts in `httpx.ProxySignals.LocalProxy`)
→ 6. `AccessLog` (slog; no query strings for `/s/` and `/invite/`, credential path segments replaced by `…` — `httpx.LogPath`,
which the error and panic log lines use too; logged from a defer, so a panicking request is still one line; `ingress=funnel|serve`
and, for Serve, `ts_user`)
→ 7. `ProxiedPolicy` (a client address taken from a trusted proxy's X-Forwarded-For, i.e. not the peer checked at step 1,
must pass the access policy §10.3 too, else 403 `forbidden`; ingress requests pass — step 10 is their policy) → 8. `HostCheck` (when
`network.strict_host`, Host must be a known name/IP, IPs configured in `network.extra_hosts`/`tls.extra_sans`/`server.public_url`
included; ingress requests pass, their Host was checked by the listener) → 9. `SecurityHeaders` (HSTS for an ingress request by the
rule of §9.2 for the MagicDNS name)
→ 10. `IngressGate` (requests of the ingress listeners only, §10.6: policy `off` → the uniform 404; path hygiene — `path.Clean`
must not change the path (trailing `/` aside), no `\`, no `%2f` in the raw path → 404; Funnel: the deny list only on the client
address, Serve: the full access policy → 403 + `Connection: close`; Funnel rate limits `funnel` (per client, IPv6 per /64) and
`funnel_global` → 429; `mtls.mode=required` → 403 unless `mtls.exempt_shares` and an exempt path; Funnel `shares` mode: only
`/s/{token}[/…]` (any method) and GET/HEAD of `/static/{hash}/…`, `/theme.css`, `/favicon.ico`, `/robots.txt`,
`/manifest.webmanifest`, everything else the uniform 404 (the 404 page, or the API's `not_found` "no such API endpoint" under
`/api/`), and the request loses `Authorization`, `X-FP-CSRF` and every cookie but the public share cookies
(`shares.IsPublicCookie`); Funnel `app` mode: `/setup`, `/unlock`, `/trust[/…]`, `/api/v1/auth/setup`, `/api/v1/system/unlock`,
`/share-target` and — unless `funnel.allow_admin` — `/admin[/…]`, `/api/v1/admin[/…]` → 403 (page or JSON); Funnel while the keys
are locked → 503, never the `/unlock` redirect; in-flight caps 256 per kind and, for Funnel, 64 per client (waiting ≤ 5 s) → 503
`Retry-After: 5`; `X-Robots-Tag: noindex, nofollow` on every Funnel response)
→ 11. `SealedGate` (keys locked → 503 for API paths, the share JSON routes `/s/{token}/api…` included, and unsafe methods /
redirect to `/unlock` for pages, except allow-listed paths)
→ 12. `Maintenance` (while `maintenance.enabled`: 503 with the operator's message, except the paths §20 (known gap 1) keeps reachable;
owners, admins, holders of `system.manage` and in-process callers pass)
→ 13. pages/static/share-root routes.
`/api/v1` group: 14. `MaxBody(1 MiB)` default (upload/import routes override) → 15. `RateLimit("api", perIP)`
→ 16. `Authenticate` (session cookie or `Authorization: Bearer fpt_…`; any other `Authorization` header — e.g. a reverse proxy's
outer Basic gate — is ignored; socket requests carry the system principal; over Funnel, with `funnel.require_2fa`, a principal whose
account has no second factor is enroll-only)
→ 17. `CSRF` for unsafe methods on cookie-authenticated requests: `http.CrossOriginProtection` **and** `X-FP-CSRF` token must match
`Auth.CSRFToken(p)` (a bad token → 403 `csrf_invalid`, a cross-origin block → 403 `forbidden`); Bearer/socket are exempt
→ 18. per-route `RequireAuth` / `RequireFull` / `RequireAdmin` / `RequireCap` (§5.3, §6a) / `RequireElevated` / `RequireScope`.
Rate-limit keys (`mw.PerIP`) are the client address, except over Funnel, where they are `core.IPLimitKey(ip, true)` (an IPv6 client
counts per /64).

### 9.2 Security headers
- App/page HTML: `Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data: blob:;
  media-src 'self' blob:; font-src 'self'; connect-src 'self'; worker-src 'self'; manifest-src 'self'; frame-src 'self';
  object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'; require-trusted-types-for 'script'; trusted-types fp`
  (`fp` is the app's single Trusted Types policy; it only implements `createScriptURL` for same-origin `/static/<hash>/…` and `/sw.js` URLs — needed for `new Worker()` and `serviceWorker.register()`; it never implements `createHTML`/`createScript`)
- All responses: `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer`, `X-Frame-Options: DENY`,
  `Cross-Origin-Opener-Policy: same-origin`, `Cross-Origin-Resource-Policy: same-origin`,
  `Permissions-Policy: camera=(), microphone=(), geolocation=(), payment=(), usb=()` (+ `clipboard-write=(self)`).
- `Strict-Transport-Security: max-age=31536000` only when `tls.hsts=on`, or `auto` and the served certificate is publicly trusted
  (ACME/tailscale/custom chaining to a public root).
- API & HTML: `Cache-Control: no-store`. Static hashed assets: `public, max-age=31536000, immutable`.

### 9.3 Sessions, CSRF, tokens
- Cookie `__Host-fp_session` = 32 random bytes (base62); `Secure; HttpOnly; SameSite=Lax; Path=/`; DB stores SHA-256.
  Idle timeout `auth.session_idle_min` (720), absolute `auth.session_max_days` (30; "remember me" → absolute, else browser session cookie
  with 24 h absolute). Token rotated on login completion (MFA), elevation, and password change. `last_seen_at` writes throttled to 1/min.
- CSRF token = `base64url(HMAC-SHA256(session.csrf_secret, session.id))`, delivered in `GET /api/v1/me` and the page boot JSON;
  sent as `X-FP-CSRF`. A new sign-in is a new session, so a tab still holding the old token gets 403 `csrf_invalid`: the web client
  re-reads the token from `GET /me` and retries once (the same account only; another account reloads the page).
- PATs: `fpt_<tokenid-suffix>_<secret>`; scopes `files:read files:write shares admin`; Bearer only; never CSRF-checked; cannot elevate
  (admin-scope tokens act as elevated only when created with `--elevated`, which requires step-up at creation and max 30 days; an
  expiry at most 5 min past that — a browser clock running ahead — is clamped to 30 days). The `admin` scope is for accounts
  with server permissions — owners, admins and every account whose role holds a server permission (§6a) — and minting it
  for anyone else is 422 (`scopes`: `the admin scope needs an account with server permissions`); a token uses the server
  permissions of its account only with that scope (403 `token lacks scope "admin"`), while user permissions such as
  `shares.links` need none, and an `--elevated` token counts as elevated only while its account is staff; like a session's
  step-up window, its elevation ends (the `elevated` pseudo-scope is removed; the token keeps working with its scopes) when
  server permissions are added to its account's role or the account gets another role, so new power is never usable
  through a step-up taken before it (`users.dropTokenElevationTx`). The token's
  account must hold `tokens.create` (403 `the role of <username> does not allow API tokens`, also for tokens made for
  others and over the admin socket); a role change never revokes tokens, which lose on their next request whatever the
  new role does not allow. A token may mint tokens only with a subset
  of its scopes, never `--elevated`, and never outliving itself (no expiry → the creator's expiry; a later one → 422); it may
  revoke itself and tokens no wider than itself (403 otherwise), and cannot list or revoke browser sessions (`/me/sessions*`).
  File operations need `files:read` up to PermView and `files:write` above it, except: starring needs `files:write`; listing grants
  and creating a share link (PermManage; plus the `shares` scope) need `files:read`; a share that accepts uploads needs `files:write`,
  and so does turning uploads on with `PATCH /shares/{id} {allow_upload: true}` (403 `token lacks scope "files:write"`).
- Step-up ("elevation", `auth.stepup_min`=10): required for: user role changes/deletes, creating an account with a staff
  role (owner, admin, or a custom role with a server permission), creating, editing and deleting roles, password resets
  for others, MFA reset, key operations, certificate/CA changes, network policy, turning Tailscale Funnel or Serve on or
  off, changing or re-applying them (`PUT /admin/network/funnel`, `PUT /admin/network/serve`,
  `POST /admin/network/tailscale/reapply`), backup restore/delete/download, settings in sections
  `auth|network|tls|acme|tailscale|funnel|mtls|keys|backup|server|mdns|email` (`server.name`/`mdns.name` name the certificate and the default passkey
  domain; the `email` relay receives the stored `smtp.password`; `tailscale` and `funnel` decide what tailscaled serves),
  disabling own 2FA, adding a second factor (authenticator app, passkey — both satisfy step-up, and a passkey signs in on its own,
  so a hijacked session must not add its own; users who still have to enroll elevate with the password), changing one's own
  e-mail address (where the security alerts go; the previous address gets an `email_changed` alert — on `PATCH /me/profile`
  and on `PATCH /admin/users/{own id}` alike, which every role with *Manage accounts* reaches), creating admin-scoped
  tokens, creating staff invitations (the admin role, or a custom role with a server permission; they are also single-use
  and expire within 7 days) and reading the links of staff invitations (`GET /admin/invites` leaves
  the `url` of staff invitations out otherwise). Elevate with password, TOTP, or passkey. The step-up rule does not depend
  on who asks: a delegate with the right permission (§6a) steps up exactly like an administrator.
- Lockout: `auth.lockout_threshold` (10) consecutive failures → lock for `auth.lockout_base_min` (15) × 2^(lock_level) (max 24 h);
  plus per-IP rate limit `ratelimit.login_per_min` (10; like the share and unlock limits it also caps a remote IPv6 client's
  whole /64 — not on-link, ULA or link-local — at 8× the per-address allowance, `mw.RateLimit`). Starting a passkey ceremony
  (`POST /auth/passkey/begin`) and reading an invitation (`GET /auth/invite/{token}`) check no credential and have the bucket
  `login_start` at 4× that allowance (`ratelimit.LoginStartFactor`, also with its /64 aggregate): the sign-in page starts a
  ceremony on every load for passkey autofill, and reloading it must not use up the allowance of real attempts, while the
  bounded table of pending ceremonies stays protected. Responses are uniform (`invalid credentials`) and timing-equalized (dummy hash).
  Failed step-ups and wrong current passwords count too; a successful sign-in, step-up or current-password check resets the
  counter. While locked, a signed-in user's step-up and password change get 409 `conflict` naming the lock (checked before any
  credential), not a wrong-password answer.
- 2FA policy `auth.require_2fa` = `off|admins|all` (default `admins`; `admins` covers owners, admins and every account whose
  role holds a server permission, §6a): users in scope without 2FA get `EnrollRequired` → only `/me*`,
  `/auth/logout`, and enrollment routes work until they enroll (403 `mfa_enroll_required`; minus `POST /me/tokens` and
  `POST /me/client-certs`). Their API tokens are refused on every `F` route — a token cannot enroll.
- `users.must_change_password` (generated or admin-set passwords, `--must-change`): a full session of that user gets
  `MustChangePassword` → the same routes as `EnrollRequired` work (so `POST /me/password`), everything else is 403
  `password_change_required` until the password is changed. Tokens are not gated (an admin reset revokes them).

### 9.4 Route table (`/api/v1` unless noted; A=auth required, F=full (MFA done), Adm=admin, E=elevated)

**Cap(x)** = `mw.RequireCap(x)`: F plus the permission `x` of §6a; **Cap(x|y)** admits either. Owners, admins and the system
principal always pass; API tokens need the `admin` scope for server permissions (§5.3). **Adm** = `mw.RequireAdmin`
(built-in owners and admins) stays on the admin-only surfaces (§6a). A guard names the permission of the route; the
service still applies its own rules (escalation, PermManage on nodes, the owner rule).

**authapi (B)** — `GET /auth/state` (public: instance name, setup_needed, passkeys enabled, rp_id, keys state, login message, password_min) ·
`POST /auth/login {username,password,remember}` → `{user}` or `{mfa_required:true, methods:[…]}` · `POST /auth/totp {code}` ·
`POST /auth/recovery {code}` · `POST /auth/passkey/begin {username?}` · `POST /auth/passkey/finish {flow_id, credential, remember?}` ·
`POST /auth/logout` (A) · `POST /auth/elevate {password|totp|passkey}` (A) · `POST /auth/setup {setup_token, username, password, email}`
(only when no users) · `GET /auth/invite/{token}` · `POST /auth/invite/{token}/accept {username, password, display_name, email}`.

**meapi (B)** (A; F unless noted) — `GET /me` (A: user, csrf, mfa, prefs, features, space ids, groups; at AuthLevel 1 the user
object is reduced to id/username/display_name/must_change_password/mfa_enabled and prefs is empty; `staff`, the user's
`role_id`/`role_name`/`permissions`, and the whole `pages.Features` map, §5.3) · `PATCH /me/profile` (E when the e-mail changes) ·
`POST /me/password` · `GET /me/sessions` · `DELETE /me/sessions/{id}` · `POST /me/sessions/revoke-others` · `GET /me/mfa` (A) ·
`POST /me/totp/begin` (E) · `POST /me/totp/confirm` (E) · `DELETE /me/totp` (E) · `POST /me/recovery-codes` (E) ·
`GET /me/passkeys` · `POST /me/passkeys/begin` (E) · `POST /me/passkeys/finish` (E) · `PATCH /me/passkeys/{id}` · `DELETE /me/passkeys/{id}` (E) ·
`GET /me/tokens` · `POST /me/tokens` · `DELETE /me/tokens/{id}` · `GET /me/usage`. The enrollment routes admit `EnrollRequired`
sessions (which elevate with the password). Password, 2FA, passkey and session management refuse API tokens.
`PATCH/DELETE /me/passkeys/{id}` and `DELETE /me/tokens/{id}` act on the caller's own credentials only, administrators included
(other users': `/admin/users/{id}/reset-mfa|password`, or the admin socket).

**usersapi (C)** — Cap(users.view): `GET /admin/users` (`?role=` filters the base, `?role_id=<word|rol_…>` the role) ·
`GET /admin/users/{id}` · `GET /admin/users/{id}/access` (`UserAccess`: the effective-access preview; API tokens also need `files:read`) ·
`GET /admin/groups` · `GET /admin/groups/{id}` · `GET /admin/groups/{id}/members`. Cap(users.manage): `POST /admin/users`
(E when the role is staff; `group_ids` also need groups.manage) · `PATCH /admin/users/{id}` (E on a role change; on one's own account the rules of `PATCH /me/profile`:
E when the e-mail changes, the previous address alerted, e-mail and display name refused for API tokens) ·
`DELETE /admin/users/{id}` (E) · `POST /admin/users/{id}/unlock` · `POST /admin/users/{id}/disable|enable`.
Cap(users.credentials): `POST /admin/users/{id}/password` (E) · `POST /admin/users/{id}/reset-mfa` (E) ·
`GET/DELETE /admin/users/{id}/sessions`. Cap(invites.manage): `GET/POST /admin/invites` (POST of a staff invite: E; GET
leaves out the `url` of invites the caller could not have created, §6a) · `DELETE /admin/invites/{id}`. Cap(groups.manage): `POST /admin/groups` · `PATCH/DELETE /admin/groups/{id}` ·
`PUT /admin/groups/{id}/members/{userId} {role}` · `DELETE /admin/groups/{id}/members/{userId}`. Users, invites and
`PATCH /admin/users/{id}` accept `role_id` next to `role` (§5.1); the escalation rules answer 403 (§6a).
Roles: Cap(users.view) `GET /admin/roles` (`{"items":[RoleDef]}`: owner, admin, member, guest, then custom roles
by name) · `GET /admin/roles/{id}` (built-in words work) · `GET /admin/roles/{id}/groups` (`{"items":[RoleGroup]}`) ·
`GET /admin/capabilities` (`CapabilityCatalog`); Adm, E: `POST /admin/roles` (`RoleDefInput` → 201 `RoleDef`) ·
`PATCH /admin/roles/{id}` (`RoleDefUpdate`; built-in roles 422) · `DELETE /admin/roles/{id}?reassign_to=` (204; 409
`reassign_to` while the role has holders and none is chosen, or when holders would lose personal files; 422 for a
built-in role or a bad `reassign_to`); Cap(groups.manage):
`PUT /admin/roles/{id}/groups/{groupId} {member_role}` (`RoleGroup`; custom roles only) ·
`DELETE /admin/roles/{id}/groups/{groupId}`. (F) `GET /groups` (mine; effective) ·
`GET /users/lookup?q=` (for share/grant pickers; min 2 chars; returns id, username, display_name; needs users.lookup or
users.view, else 403 `your role cannot search the user directory`) · `GET /roles` (custom roles as `RoleRef`, for the
same pickers and with the same check) · `GET /activity` (own events;
`?action=&outcome=&since=&until=&target_type=&target_id=`).

**filesapi (D)** (F) — `GET /spaces` · `GET /nodes/{id}` · `GET /nodes/{id}/children?cursor&limit&sort=name|size|updated|kind&desc` ·
`GET /nodes/{id}/breadcrumbs` · `POST /nodes/{id}/folders {name}` · `PATCH /nodes/{id} {name}` · `POST /nodes/move {ids,dest,conflict}` ·
`POST /nodes/copy {ids,dest,conflict}` · `POST /nodes/trash {ids}` · `GET /nodes/{id}/content` · `GET /nodes/{id}/thumb` ·
`GET /nodes/{id}/stats` · `GET /nodes/{id}/versions` · `POST /nodes/{id}/versions/{vid}/restore` · `GET/POST /nodes/{id}/grants` ·
`DELETE /nodes/{id}/grants/{gid}` · `PUT/DELETE /nodes/{id}/star` · `GET /trash` · `POST /trash/restore {ids}` · `POST /trash/purge {ids}` ·
`DELETE /trash` · `GET /search?q=&space=&kind=` · `GET /recent` · `GET /starred` · `GET /shared-with-me` · `POST /archives` ·
`GET /archives/{ticket}` (ticket is the credential; no auth middleware requirement beyond ticket validity).
`POST /nodes/{id}/grants {subject_type: user|group|role, subject_id, role: viewer|editor|manager, expires_at?}` needs PermManage
on the node, for role subjects too. It creates the subject's grant or replaces its level and expiry (no `expires_at` = no
expiry; the share dialog sends the current expiry when an existing subject is added again). A grant to oneself is 422
`subject_id`; a grant to a group or role that includes the caller may not outlast the caller's own access of that level when
that access comes from grants alone (not from the space or the admin override): 422 `expires_at` "your own access to … ends
on …" — otherwise the holder of an expiring manager grant could re-grant their own role or group without an expiry. Node and version payloads carry `zip_encryption` on protected zips (§8.1).
Cap(users.view): `GET /admin/grants?subject_type=user|group|role&subject_id=[&expand=1]` (`SubjectGrants`: at most 1000
live grants with `node_*`, `space_*` and the caller's `caller_perm`; names the caller may not see are only counted in
`hidden`; API tokens also need `files:read`; 422 malformed, 404 unknown subject).

**uploadapi (E-unit)** (F) — `POST /upload-batches` · `GET /upload-batches` (the caller's own unfinished batches, open or
finalizing, newest first, without files: `{"items": [...]}`) · `GET /upload-batches/{id}` · `POST /upload-batches/{id}/files` ·
`PUT /upload-batches/{id}/small?ref=` · `POST /upload-batches/{id}/complete` · `DELETE /upload-batches/{id}` · `GET /uploads/{id}` ·
`PUT /uploads/{id}/parts/{n}` · `POST /uploads/{id}/complete` · `DELETE /uploads/{id}`.
Password-protected zips (§8.1): `POST /upload-batches` accepts `zip_encryption` (`aes256`|`zipcrypto`; empty with a
password = `aes256`) and the write-only `zip_password` in mode `zip` (422 `invalid` on `zip_password`/`zip_encryption`,
503 `keys_locked`); the batch answers carry `zip_encryption`, never the password; `POST /upload-batches/{id}/complete` may
answer 412 `precondition_failed` or 500 `corrupt` when the stored password cannot be opened (the batch stays open).

**sharesapi (E-unit)** — (F) `GET/POST /shares` (creating a link needs `shares.links`, a file request `shares.requests`; §6) ·
`GET/PATCH/DELETE /shares/{id}` · `GET /shares/{id}/log` · `GET /shares/{id}/qr.svg` ·
A file request never shows the folder's files: `allow_download` or `allow_preview` true, or `allow_upload` false, on a request is
422 on that field (create and PATCH), and `Resolve` treats a stored request as upload-only whatever its flags. Titles, messages and
uploader names refuse control and text-direction characters (`names.IsBidiControl`). A share whose creator lost what `Resolve`
needs on the node (view for a link, edit for a file request) resolves as not found and is `unavailable` in the owner and admin
lists; an upload to a link whose creator can no longer write is refused as "this share does not accept uploads". ·
Cap(shares.manage) `GET /admin/shares`. **Public root** (no session; CrossOriginProtection on unsafe methods; `ratelimit.share_per_min`):
`GET /s/{token}` (HTML via `pages.Render(w, r, "share", data)`) · `GET /s/{token}/api` (share info + root listing) ·
`GET /s/{token}/api/list?node=` · `POST /s/{token}/api/password {password}` (sets share access cookie) ·
`GET /s/{token}/dl/{nodeId}[?inline=1]` · `GET /s/{token}/thumb/{nodeId}` · `POST /s/{token}/api/archive {node_ids,format}` →
ticket URL `/s/{token}/zip/{ticket}` · requests/uploads: `POST /s/{token}/api/upload-batches`, `PUT /s/{token}/api/upload-batches/{id}/small`,
`PUT /s/{token}/api/uploads/{id}/parts/{n}`, `GET /s/{token}/api/uploads/{id}`, `POST /s/{token}/api/uploads/{id}/complete`,
`POST /s/{token}/api/upload-batches/{id}/complete`; the batch/upload flow also needs
`GET /s/{token}/api/upload-batches/{id}`, `POST /s/{token}/api/upload-batches/{id}/files`,
`DELETE /s/{token}/api/upload-batches/{id}` and `DELETE /s/{token}/api/uploads/{id}`, mirroring uploadapi.
File requests never produce password-protected zips: `POST /s/{token}/api/upload-batches` answers 422 when `zip_encryption`
or `zip_password` is present.
Invalid/expired/disabled tokens → the same generic 404 page (no oracle).
Share access cookie: `__Host-fp_s_<last 8 characters of share id>` = `base64url(exp || MAC("share", share_id, password_version, exp))`, 12 h
(the last 8 characters are the random part of the UUIDv7-based id; the leading ones are the `shr_` prefix and the
timestamp, which would collide between shares created close together). Shares that accept uploads also set a visitor
cookie `__Host-fp_uv_<last 8 characters of share id>` = random 16-byte id (base64url), 31 d, issued by the share page and
its info route `GET /s/{token}/api` only: it binds the upload batches a browser opens to that browser (sharesapi/upload.go).

**securityapi (F-unit)** — Cap(certs.manage): `GET /admin/certs` (and every other `/admin/certs*` answer: `core.CertStatus` plus
`uncovered_names`, the configured names the local CA's constraints do not cover, so the leaf does not carry them) ·
`POST /admin/certs/renew` · `POST /admin/certs/ca/regenerate` (E) ·
`POST /admin/certs/acme/apply` (E) · `POST /admin/certs/tailscale/fetch` ·
`GET/POST /admin/client-certs` (POST: E; returns p12 once) · `DELETE /admin/client-certs/{id}` (both: an owner's certificates
only by an owner — the owner rule, 403 for admins) · `GET /admin/client-certs/download?ticket=` (below).
(Adm) `PUT /admin/certs/custom` (E) · `DELETE /admin/certs/custom` (E) · `GET /admin/keys` ·
`POST /admin/keys/{lock,seal,unseal,passphrase,rotate,recovery}` (E) · (F) `GET/POST /me/client-certs` (POST only if `mtls.self_service`, and never with an API token — issuing a client
certificate is credential management, like the `/me` password/TOTP/passkey routes) ·
`DELETE /me/client-certs/{id}` (revoke your own) · `GET /admin/client-certs/download?ticket=` and `GET /me/client-certs/download?ticket=`
(single-use .p12 link from the issue response, 10 min, bound to the issuer) ·
public: `GET /system/status` (`{"state":"locked|unlocked","setup_needed":bool,"web_unlock":"allowed|off|network"}`; `web_unlock`
only while locked: what `POST /system/unlock` would answer this client, so `/unlock` shows the CLI command instead of a form
it would refuse) · `POST /system/unlock {passphrase}` (only when locked;
`ratelimit.unlock_per_min`; network per `keys.web_unlock`) · root `GET /trust/ca.crt|ca.pem|ca.mobileconfig`.

**settingsapi (G)** — Cap(settings.manage|network.manage|certs.manage|system.manage) plus a per-key permission (§6a):
`GET /admin/settings` (catalog with values, defaults, `restart`, `overridden_by_env`, `managed`, secrets masked; only the
keys the caller may change) ·
`PATCH /admin/settings[?force=1] {key:value,…}` (E for sensitive sections) → `{applied, restart_required, warnings}` (`warnings`: accepted
values that will not take full effect, e.g. a `tls.extra_sans`/`network.extra_hosts` name the local CA may not sign, or a
`server.https_port`/`http_port` onto the port of an active Funnel or Serve entry) ·
`DELETE /admin/settings/{key}[?force=1]` (reset; `?force=1` confirms a change the lockout guard or the passkey guard refuses with 409).
PATCH and DELETE check every key in the order of §5.3: 403 `field`=key (`only administrators can change <key>` or
`changing <key> needs the “<Label>” permission`) → 409 `conflict` `field`=key for a managed key (the `funnel.*` keys
except `funnel.backend` and `funnel.backend_port`; the Funnel/Serve routes below change them) → E → lockout → passkeys.
(Adm) `POST /admin/settings/email/test {to}` (sends the notify test message with the stored SMTP settings; 204, 422 bad address,
503 carrying the SMTP error).
Cap(network.manage): `GET /admin/network` (interfaces with `role`, `role_source`, `provider`, `detail`, `default_route`; URLs,
policy, tailscale, `ingress` (cached `IngressStatus`), `vpns`, `exposures`) · `PUT /admin/network/policy {mode,allow,deny,force}` (E; lockout guard) ·
`GET /admin/mdns` · `POST /admin/mdns/republish`.
Tailscale Funnel/Serve (§10.6), Cap(network.manage): `GET /admin/network/tailscale[?refresh=1]` (→ `IngressStatus`;
`refresh` re-reads tailscaled and re-runs the self-probe) · `PUT /admin/network/funnel {mode, port?, allow_admin?, require_2fa?, confirm?}` (E) ·
`PUT /admin/network/serve {enabled, port?}` (E) · `POST /admin/network/tailscale/reapply` (E; rewrites the entries
FileParcel owns) — each answers `IngressStatus`. `confirm: "public"` is required (else 422 `confirm`) for off→shares|app,
shares→app, `allow_admin` false→true and `require_2fa` true→false; weakening sign-in over Funnel (the last two) is for
built-in owners and admins only: 403 `only an owner or administrator can weaken sign-in over the public Funnel address`
(audited `network.funnel`, outcome denied). Other errors: 422 `invalid` (`mode`, `port`, `allow_admin`), 412
`precondition_failed` (`field` = the failing check id, message = check message + hint), 409 `conflict` (`field:"port"`,
names the foreign target), 503 `unavailable` (tailscaled unreachable). With the server stopped the CLI reaches the same
handlers in-process and gets state `stopped`.
(F) `GET /network/urls` · `GET /qr.svg?data=<≤512 chars>`.

**opsapi (H)** — Cap(backups.run): `GET/POST /admin/backups` · `GET /admin/backups/{id}` · `POST /admin/backups/{id}/verify` ·
`GET /admin/backups/config`. (Adm, E) `DELETE /admin/backups/{id}` ·
`GET /admin/backups/{id}/download` · `POST /admin/backups/import` (streaming body up to 1 TiB) · `POST /admin/backups/{id}/restore` ·
`PUT /admin/backups/config` · `POST /admin/backups/identity` (returns identity once) ·
`POST /admin/backups/identity/export` (returns the stored identity again).
Cap(system.view): `GET /admin/jobs` · `GET /admin/jobs/{id}` · `GET /admin/jobs/kinds` ·
`GET /admin/jobs/schedules` · `GET /admin/system` (+ `stats_unavailable` when a figure could not be read, `maintenance`
while maintenance mode is on) ·
`GET /admin/system/doctor` · `GET /admin/dashboard` (+ `extra.stats_unavailable` / `extra.backup_unavailable`, and a warning when the
database or the backup list could not be read, instead of showing zeros or "no backup" as health; the recent audit entries
only with audit.view, the last backup only with backups.run).
Cap(system.manage|backups.run): `POST /admin/jobs/run {kind}` · `POST /admin/jobs/{id}/cancel` (the handler then needs the
permission of the job's kind: `backup.*` → backups.run, every other kind → system.manage).
Cap(system.manage): `POST /admin/system/restart` (E).
Cap(audit.view): `GET /admin/system/logs?n=` (+ `missing`, `file_logging`: an empty tail is told apart from
log.file = false) · `GET /admin/audit` · `GET /admin/audit/verify` ·
`GET /admin/audit/export?format=csv|jsonl`. (F) `GET /jobs/{id}` (own jobs; any job with system.view) · `GET /events` (SSE; per-user
filtering; a principal with `ServerAccess()` also gets the admin topics, each only with its permission (§5.3, §6a.3); heartbeat every 25 s).

**pages/static (I)** — root: `/` → redirect `/files` (or `/login`, `/setup`, `/unlock`); SPA shell for `/files*`, `/shared`, `/links`,
`/requests`, `/starred`, `/recent`, `/trash`, `/activity`, `/search`, `/settings*`, `/admin*`; public pages `/login`, `/invite/{token}`,
`/setup`, `/unlock`, `/trust`; `/static/{hash}/*`; `/sw.js`; `/manifest.webmanifest`; `/theme.css`; `/favicon.ico`; `/robots.txt`
(`Disallow: /`); `/.well-known/security.txt`; `/healthz` (liveness, always 200 "ok"); `/readyz` (200 when DB ok and keys unlocked);
`POST /share-target` (PWA Web Share Target §13.7; redirects to `/files?upload=1` when the service worker did not intercept it).

The mounted table is pinned by `TestRouterMatchesDesign` in `internal/wire`: it walks `web.NewRouter` with `chi.Walk` and
fails both on a route listed here but not mounted and on a route mounted but not listed here.

### 9.5 Error format & pagination
Errors: `{"error":{"code":"not_found","message":"Folder not found","field":"name","request_id":"…"}}` with codes from §5.1.
Lists: `?cursor=&limit=` (default 100, max 500) → `{"items":[…],"next_cursor":"…"}`.

### 9.6 Audit actions (dotted names; `outcome` success|failure|denied)
`auth.login`, `auth.logout`, `auth.mfa`, `auth.lockout`, `auth.elevate`, `auth.setup`, `user.create`, `user.update`, `user.delete`,
`user.disable`, `user.enable`, `user.unlock`, `user.password_change`, `user.password_reset`, `user.mfa_reset`, `mfa.totp_enable`,
`mfa.totp_disable`, `mfa.recovery_regenerate`, `passkey.add`, `passkey.remove`, `token.create`, `token.revoke`, `session.revoke`,
`invite.create`, `invite.revoke`, `invite.accept`, `group.create`, `group.update`, `group.delete`, `group.member_set`, `group.member_remove`,
`group.role_set`, `group.role_remove`, `role.create`, `role.update`, `role.delete`,
`file.upload`, `file.download`, `file.rename`, `file.move`, `file.copy`, `file.trash`, `file.restore`, `file.purge`, `file.version_restore`,
`folder.create`, `grant.set`, `grant.remove`, `archive.download`, `share.create`, `share.update`, `share.revoke`, `share.password_fail`,
`request.upload`, `settings.change`, `network.policy`, `network.funnel`, `network.serve`, `cert.renew`, `cert.custom_set`, `cert.custom_clear`, `cert.acme`, `cert.tailscale`,
`ca.regenerate`, `client_cert.issue`, `client_cert.revoke`, `keys.unlock`, `keys.lock`, `keys.seal`, `keys.unseal`, `keys.passphrase`,
`keys.rotate`, `keys.recovery_export`, `backup.create`, `backup.verify`, `backup.delete`, `backup.download`, `backup.import`,
`backup.restore`, `system.start`, `system.stop`, `system.restart`, `admin.file_access`, `job.run`, `audit.reseal`.

Two of them are not one-entry-per-request: `file.purge` of a large trashed tree is recorded once per delete transaction, each entry
carrying its own figures and `"partial": true` until the last one, so an interrupted purge leaves nothing unrecorded (the *validation*
of the request stays all-or-nothing). `admin.file_access` covers every read, purge or cross-space move that only
`auth.admin_can_access_files` allows — including a search restricted to another user's space (`GET /search?space=`, one entry for
its root; search across all locations never uses the override) — and one node can get a second entry within the same call when a
later step needs a higher permission than the one already recorded (a purge over several transactions is still one call). Public share requests act as the link's creator (`Via share`) and write no
`admin.file_access`: for a link an admin created through the override, that access is audited once when the link is created
(`share.create` needs `PermManage`), and the visits are in the share access log.

`audit.reseal` is written by the audit log itself (actor `system`, outcome failure) when an unlock seals rows that were
written while the keys were unavailable but not by the sealing process (an earlier run, an offline command, or a writer
without the keys): its details name them (`from_seq`, `to_seq`, `sealed`, `unverified`, `unverified_seqs`), since an
unsealed row proves nothing about its origin (ENCRYPTION.md §8).

**Details never contain passwords** (account, share, zip or backup passwords and passphrases): `settings.change` masks
secret values, and a password-protected zip (§8.1) shows up only as `zip_encryption` (`aes256`|`zipcrypto`) in
`file.upload` and in the failure entry of a zip batch.

Actions of roles and Funnel/Serve, and their details:
- **Roles** (§6a): `role.create` (target type `role`; `{name, base, permissions, delegable, copy_from}`), `role.update`
  (`{name:{from,to}?, description:true?, permissions:{added,removed}?, delegable:{from,to}?, users}`), `role.delete`
  (`{name, base, reassigned_to, reassigned_to_name, users_moved, user_ids (≤ 1000, then "truncated": true),
  invites_revoked, grants_removed, groups_removed}`); `group.role_set` (target type `group`; `{role_id, role_name,
  member_role, previous}`, only when something changed) and `group.role_remove`. `user.create`, `user.update`,
  `invite.create` and `invite.accept` also carry the role (`"role_id": {"from","to","name"}` when it changes);
  `grant.set`/`grant.remove` may name `subject_type: "role"` and `role: "manager"`. A refusal by the escalation rules
  is recorded under the attempted action (`user.create`, `user.update`, `user.delete`, `user.disable`, `user.enable`,
  `user.unlock`, `user.password_reset`, `user.mfa_reset`, `session.revoke`, `token.create`, `invite.create`) with
  outcome `denied` and `{"reason", "missing"}`; a plain permission refusal by a route guard (`mw.RequireCap`) is not audited.
- **Tailscale Funnel/Serve** (§10.6): `network.funnel` `{mode, previous_mode, port, previous_port, allow_admin, require_2fa,
  backend, url, reason}` with outcome success, failure (`error`) or denied (`check`, or `rbac` for a weakening by someone
  who is not a built-in owner/admin); `network.serve` `{enabled, port, previous_port, backend, url, reason}`. Changes
  FileParcel makes by itself are recorded as the system actor with a `reason` (`renamed`, `funnel_flag_removed`,
  `uninstall`, `suspend_failed`, `port_clash_removed`). Failed `auth.login` entries gain the reasons
  `funnel_requires_2fa` and `funnel_user_limited`.

### 9.7 Job kinds
`upload.zip`, `thumbs.generate`, `backup.create`, `backup.verify`, `backup.prune`, `keys.rotate_kek`, `keys.reencrypt`,
`maintenance.sessions` (hourly: purge expired sessions/tickets/flows), `maintenance.uploads` (hourly: expire batches, re-run
interrupted zip jobs), `maintenance.trash` (daily: purge trash older than `storage.trash_days`), `maintenance.blob_gc` (daily),
`maintenance.audit_prune` (daily),
`maintenance.db_optimize` (daily: `PRAGMA optimize`, `wal_checkpoint(TRUNCATE)`; the result carries `checkpoint_truncated`, and a
checkpoint SQLite reported as busy is recorded as a note on the job instead of being reported as a clean run; it also prunes finished
job rows and `share_access_log` rows older than `sharing.access_log_days`), `certs.renew_check`
(every 12 h), `maintenance.versions` (daily: keep `storage.versions_keep`).

Job params and results never carry secrets (`GET /jobs/{id}` returns them): `upload.zip` keeps `{"batch_id"}` for a
password-protected zip too — the password stays sealed on the batch row (§8.1) — and its result adds `"encryption"`. The
`upload.zip` result is `{"node_id", "name", "size", "files", "encryption"}`: `name` is the name the .zip was stored under
(conflict `rename` may have numbered it), `node_id` and `name` are absent when conflict `skip` kept an existing file.

Cron specs are rejected when they parse but can never match a date (`0 3 30 2 *`, `0 0 31 4 *`): `cron.Parse`, and therefore
`jobs.Schedule`, `PATCH /admin/settings` and `fileparcel config set backup.schedule_*`, answer 422 rather than storing a schedule
that never runs. Rows stored by older versions are reported by the doctor check `jobs.schedules` (enabled, but no next run).

`GET /admin/jobs` hides the routine runs of the noisy kinds (`maintenance.sessions`, `maintenance.uploads`, `certs.renew_check`,
`thumbs.generate`), but never hides one that **failed** or that somebody started by hand — otherwise the dashboard and the doctor
count failures the list cannot show.

---

## 10. Network, VPNs, TLS & mDNS

### 10.1 Interface classification (`netinfo`)
Enumerate `net.Interfaces()` every 30 s (and on demand); publish `network.changed` when the offered address set, an interface
role, the MagicDNS name, the system `.local` name or `network.extra_hosts` change. Each interface gets a **kind** (what it is)
and a **role** (what it is good for):

| Role | Meaning | URLs, SANs | mDNS | Install allowlist, `network vpn allow` | Firewall hints |
|---|---|---|---|---|---|
| `mesh` | devices of that private network can connect to this machine | yes | – | recommended | by interface |
| `unknown` | a tunnel without a product signal | yes | – | yes | by interface |
| `local` | LAN / Wi-Fi | yes | yes | its subnets | by source subnet |
| `access` | zero-trust or corporate **client**: this machine reaches published resources, nobody comes in through it | no | – | refused (explained) | no |
| `egress` | exit/privacy VPN or internet uplink | no | – | refused (explained) | no |
| `overlay` | public overlay: anyone on it may connect (Yggdrasil) | no | – | only after a confirmation, with a warning | no |
| `none` | loopback, container, bridge-enslaved TAP | no | – | no | no |

**Signals.** Name, addresses and flags from the OS; on Linux `DEVTYPE=` of `/sys/class/net/<if>/uevent` (`wireguard`,
`ovpn-dco`, `ovpn`, `bridge`, `wlan`, …), `…/tun_flags` (a TUN/TAP device) and the `…/master` link (bridge/bond port); the node's
IPs and control server from tailscaled (§10.6 `tslocal`); weak signals from host probes, each cached — an installed binary
(PATH and the product's usual place, 5 min), a running process (`/proc/*/comm`, macOS `ps`, 60 s), tinc networks
(`/etc/tinc/<net>/tinc.conf` `Interface =` or the net name, 5 min) and innernet networks (`/etc/innernet[-server]/<name>.conf`,
5 min). Excluding roles (`access`, `egress`, `overlay`) need a **strong** signal: an exact product name, a product address range,
the Linux `DEVTYPE`, or the effective default route. Weak signals only refine a label, or confirm a generic name (`sdwan0` with the
`twingate` binary). Mistakes lean safe: a wrong exclusion offers fewer addresses and `network.iface_roles` fixes it.

**Classification** (`classify.go`, names lowercased, first match wins):

| # | Kind | Rule | Role |
|---|---|---|---|
| 1 | `loopback` | `FlagLoopback` | none |
| 2 | `container` | `docker*`, `br-*`, `veth*`, `virbr*`, `cni*`, `flannel*`, `cali*`, `lxc*`, `lxd*`, `vmnet*`, `vboxnet*`, `podman*`, `vnet*`, `macvtap*`; a TUN/TAP that is a bridge port (a VM's TAP) | none |
| 3 | `tailscale` / `headscale` | `tailscale*`; an address in `fd7a:115c:a1e0::/48` or one of tailscaled's node IPs; darwin `utun*` with 100.64.0.0/10 only while those IPs are unknown **and** Tailscale is installed (NetBird, WARP and Firezone use that range on macOS too). `headscale` when the control URL is not Tailscale's (prefs unreadable: a MagicDNS name outside `.ts.net`/`.tailscale.net` guesses it, `kind_guessed`) | mesh |
| 4 | `yggdrasil` | `ygg*`, a node address in `200::/8`, a TUN with an address in `200::/7` (a LAN interface with a `300::/64` subnet a Yggdrasil router advertises stays `lan`) | overlay |
| 5 | `husarnet` | `hnet*`, an address in `fc94::/16` | mesh |
| 6 | `exitvpn` | `nordlynx` with a 100.64.0.0/10 Meshnet address ("NordVPN Meshnet": mesh, and **only** those addresses are offered), else `nordlynx`/`nordtun` "NordVPN"; `*-mullvad` "Mullvad VPN"; `proton0`, `pvpnksintrf*`, `ipv6leakintrf*` (kill-switch dummies) "Proton VPN" | mesh / egress |
| 7 | `warp` | `cloudflarewarp` "Cloudflare WARP" | egress |
| 8 | `firezone` | `tun-firezone` (client) → access; `wg-firezone` (0.x server) → unknown | access / unknown |
| 9 | `twingate` | `sdwan0` with the `twingate` binary (without it: row 20) | access |
| 10 | `corpvpn` | `cscotun*` "Cisco Secure Client", `gpd*` "GlobalProtect" | access |
| 11 | `netmaker` | `netmaker`, `nm-*` with `DEVTYPE=wireguard` (NetworkManager's `nm-bridge` stays `lan`) | mesh |
| 12 | `innernet` | an innernet network name | mesh |
| 13 | `tinc` | `tinc*`, a tinc network's interface | unknown |
| 14 | `zerotier` | `zt*`; darwin `feth*` with `zerotier-cli` | mesh |
| 15 | `netbird` | `wt*`, `nb-*`, `netbird*` | mesh |
| 16 | `nebula` | `nebula*` | mesh |
| 17 | `wireguard` | `wg*`, `DEVTYPE=wireguard` (any name) | unknown |
| 18 | `openvpn` | `ovpn*`, `as0t*`, `DEVTYPE=ovpn-dco`/`ovpn`; `tun*`/`tap*` while an `openvpn` process runs (label only) | unknown |
| 19 | `ipsec`, `softether` | `ipsec*`, `xfrm*`, `vti*`, `ip_vti*`; `vpn_*` with the `vpnclient` binary | unknown |
| 20 | `vpn` | `tun*`, `tap*`, `ppp*`, other `utun*`, any Linux TUN/TAP (`edge0`, `sdwan0` without Twingate) | unknown |
| 21 | `wifi` | Linux `…/wireless` or `…/phy80211`, or `wl*` (darwin `en0` is reported as `lan`) | local |
| 22 | `lan` | everything else | local |

**Default-route rule.** A *generic* tunnel (kinds `wireguard`, `openvpn`, `ipsec`, `softether`, `tinc`, `vpn`) that carries the
effective default route is an exit VPN or an uplink → role `egress` (`ppp*` labelled "PPP internet uplink"). Product mesh VPNs keep
their role (a Tailscale exit node in table 52, ZeroTier global routes, a NetBird exit node: their peers still reach this machine);
every VPN that carries it shows `default_route` and the detail "carries the default route". The routing tables are read only while an
up VPN interface exists, cached 60 s or until the interface set changes; a failed read knows no default route (nothing becomes
egress); a cancelled caller gets the last answer and is never recorded, and a refresh whose caller was cancelled keeps the last
snapshot (no `network.changed`, no leaf reissue from a partial read). **Linux** (`routes_linux.go`): `syscall.NetlinkRIB` dumps of `RTM_GETRULE` and `RTM_GETROUTE` per family, parsed by hand
(`routes.go`, portable, tested on captured dumps): the default-route tables are `main` (254) plus the tables of *general* rules —
no source or destination prefix, no tos, no `iif`/`oif`, no `l3mdev`, no uid range, no `ipproto`/`sport`/`dport`, action lookup
(`fwmark`/`not fwmark` rules count: wg-quick's 51820, Mullvad, Tailscale's 52; a split tunnel's `to <prefix> lookup 100` does not),
`local` (255) never; the table is `FRA_TABLE`/`RTA_TABLE` when present (ids above 255); only unicast routes without a source
prefix; a default is a `/0` or both def1 halves (`0.0.0.0/1` + `128.0.0.0/1`, `::/1` + `8000::/1`) on one interface in one table;
the interfaces are `RTA_OIF` and every `RTA_MULTIPATH` nexthop (routes that only name a nexthop object are ignored); at most
200 000 messages. A reply table reached by `from <ip>`/`iif` does not count (VPN servers and multi-homed hosts are not egress).
**darwin** (`routes_darwin.go`): `x/net/route` RIB dump; routes flagged `RTF_IFSCOPE` are ignored (macOS keeps a scoped default
per interface). Elsewhere: none.

**Override** `network.iface_roles` (section `network`, step-up, `network.manage`): entries `"<interface>=<role>"`, role one of the
seven above; the name must be usable in a sysfs path (no `/`, spaces, `=`, control characters; ≤ 64 bytes); ≤ 64 entries; later
entries for the same name win; invalid entries → 422 on write (an invalid stored value is logged and ignored). Applied after
classification: `role_source` becomes `override`, the kind stays. It changes URLs, SANs, the VPN list, the fingerprint (so mDNS
republishes), firewall hints and mDNS interfaces. CLI `network vpn role <iface> <role|auto>`; UI: the role menu of each interface
row (§13.8).

`NetInterface{name, kind, label, up, addrs[], mtu, is_vpn (rows 3–20), role, role_source (auto|override), provider? (nordvpn,
mullvad, proton, cloudflare, firezone, twingate, cisco, paloalto), detail? ("carries the default route", "NordVPN Meshnet",
"kill-switch interface"), default_route?}`. `netinfo.RoleOf(ni)` gives a value without a role (older servers, fakes) its kind's role.

### 10.2 Access URLs
For every address of an **offered** interface — up and role `local`, `mesh` or `unknown`; on a NordVPN Meshnet interface only its
100.64.0.0/10 addresses; never link-local — `https://<ip>:<port>/` (IPv6 in brackets), local interfaces before VPNs, IPv4 before
IPv6. Plus names: `https://<mdns-name>.local:<port>/` (when mDNS publishing is active), `https://<hostname>.local:<port>/` (when the
system responder publishes it), the MagicDNS FQDN (unless the Tailscale interface was set to a role that is not offered),
`server.public_url`, `tls.extra_sans` DNS names, and while they are active the Tailscale Serve address (`tailscale_serve`,
recommended) and the Funnel `app` address (`funnel`) from `Ingress.AccessURLs()` (§10.6). `AccessURL{url, kind, interface, label,
trusted (cert covers it and is publicly trusted), recommended}`. The same offered addresses are the leaf's IP SANs
(`Network.IPs()`), so an exit VPN coming and going no longer reissues the leaf. Shown in the admin UI,
`fileparcel network urls [--qr]`, and the installer summary (with terminal QR codes).

### 10.3 Access policy (allowlist)
`network.access_mode`:
- `private`: loopback, 10/8, 172.16/12, 192.168/16, 169.254/16, 100.64/10, fc00::/7, fe80::/10, ::1/128, plus
  `network.allow_cidrs` (e.g. a LAN's global IPv6 prefix).
- `allowlist` (default at install): loopback + `network.allow_cidrs`. `init` pre-fills it with `netinfo.DefaultAllowlist`: the
  private (RFC 1918/CGNAT/ULA) subnets of up local interfaces and their global IPv6 prefixes (left out, with a note, next to a public
  IPv4 address: a cloud VM's provider network holds other tenants, not the operator's devices), and the ranges of the `mesh` and
  `unknown` VPNs of the VPN list below — never an `egress`, `access` or `overlay` VPN's. VPNs without a range (host-only addresses,
  custom Headscale prefixes) become notes.
- `any`: all addresses (public exposure; UI shows a warning banner).
`network.deny_cidrs` always wins. Loopback is always allowed (so the local CLI and recovery always work).
Enforced in `server` at `Accept()` via `Network.Allowed()` (lock-free `atomic.Pointer` to a compiled matcher). Denials are logged
(rate-limited) but not audited individually. Behind `server.trusted_proxies` the listener only sees the proxy (a same-host proxy is
loopback, always allowed), so the client address resolved from X-Forwarded-For is also checked per request (`mw.ProxiedPolicy`,
§9.1 step 7: 403, in the access log); the proxy's own address is still checked at `Accept()`.
A policy change also reaches connections that are already open (HTTP/2 and keep-alive connections, event streams): the HTTPS
server re-checks the TCP peer when it takes a connection over and before every request, and sweeps its open connections every 2 s;
a connection whose peer is no longer allowed is closed (TCP reset), which ends its event streams and downloads.
**Lockout guard**: `SetPolicy` computes whether the requesting client IP would still be allowed; if not → 409 `conflict` unless `force=true`.

**VPN list** (`netinfo.BuildVPNs(ifaces, tailscale, policy)`, `NetworkOverview.vpns`, `network vpn list`): one `VPNInfo{id, kind,
label, provider?, role, role_source, interfaces[], ranges[], allowed (yes|partly|no), can_allow, needs_force, recommended, note?,
warning?}` per detected VPN — up VPN interfaces with a usable address, plus other interfaces an administrator gave a VPN role. One
entry per product (`tailscale`, `headscale`, `zerotier`, `netbird`, `husarnet`, `yggdrasil`, `warp`, `twingate`; branded exit and
corporate VPNs by provider: `nordvpn`, `mullvad`, `proton`, `cisco`, `paloalto`, `firezone`) unless its interfaces' roles differ,
else one per interface (id = interface name, label "WireGuard (wg0)"); VPNs devices come in through first.

| VPN | ranges | note / warning |
|---|---|---|
| Tailscale | 100.64.0.0/10, fd7a:115c:a1e0::/48 | warning "shared with NetBird, NordVPN Meshnet, Cloudflare WARP and ISP carrier-grade NAT" |
| Headscale | the Tailscale ranges that hold the node's IPs; none guessed for custom prefixes | note "custom Headscale prefixes: add them with `fileparcel network allow add <prefix>` …"; label names the control server ("Headscale (hs.example.org)", "Headscale (self-hosted control server?)" when guessed) |
| NordVPN Meshnet | 100.64.0.0/10 | – |
| Husarnet | fc94::/16 | note "every Husarnet device you allowed in your Husarnet dashboard" |
| Yggdrasil (overlay) | 200::/7 | warning "public overlay: anyone on the Yggdrasil network", `needs_force` |
| other mesh/unknown | the interface subnets | host-only addresses (/32, /128) → note "add its network with `fileparcel network allow add CIDR`" |
| egress, access, none | none, `can_allow` false | WARP: "peer-to-peer in a Zero Trust org uses 100.96.0.0/12; set the role to mesh if you use it"; Firezone client: "on a Firezone Gateway, allow the Firezone client address range manually" |

`allowed` is the matcher's `covers` over the ranges (without ranges: the interface subnets): `yes` when mode `any` or an allow
(or private) prefix contains the range and no deny prefix overlaps it; `partly` when a deny prefix overlaps an allowed range or an
allow prefix only overlaps it; `no` otherwise (also when a deny prefix contains it). `can_allow`: ranges and role
`mesh`/`unknown`/`local`/`overlay`; `recommended` (part of the install allowlist): ranges and role `mesh`/`unknown`.

**Exposures** (`NetworkOverview.exposures`, doctor `network.exposure.*`): ways around the access policy on this machine. netinfo
(`Service.Exposures`, cached 60 s, each probe ≤ 2 s): `tailscale.userspace` (warn; tailscaled without a TUN device dials tailnet
connections to `127.0.0.1`, which is always allowed — hint: a TUN device, or Tailscale Serve, which keeps the tailnet address),
`tailscale.shields_up` (info; tailnet devices cannot connect), `cloudflared` — while a `cloudflared` process runs or its service is
registered, its `config.yml` (`~/.cloudflared`, `/etc/cloudflared`, `/usr/local/etc/cloudflared`, and on Linux the `--config` file
of each running cloudflared; ≤ 256 KiB, line scan of `service:` and the legacy `url:`) and, on Linux, `--url` of its command line are
matched as http(s) URLs whose port is the HTTPS port (default 80/443 by scheme) and whose host is this machine — localhost,
loopback, one of its addresses (`IsLocal`: a LAN URL copied into the config) or its names (`Hostnames`, the `.local` name): warn
"Cloudflare Tunnel forwards <hostnames> to FileParcel: visitors appear as this machine"; no configuration that could be read (a token
tunnel, or a `--config` file this account cannot open) → info; nothing when `server.trusted_proxies` covers loopback (the visitors'
addresses are then seen and checked). The request path adds `tailscale.bypass` (fail) and
`proxy.local_unconfigured` (warn) from `httpx.ProxyExposures` (§10.6).

### 10.4 TLS
- **Local CA** (created at `init`): ECDSA P-256, 10 years, CN `FileParcel Local CA (<name> <install_id[:8]>)`, `BasicConstraints CA:true,
  pathlen 0`, KeyUsage certSign|crlSign, EKU serverAuth (constrained or not: no code-signing/S-MIME with a leaked key). **Name
  constraints** (critical) by default: permitted DNS `.local`, `local`, `localhost`,
  `.ts.net`, the machine hostname, the `Network.Hostnames()` present at creation (a Headscale MagicDNS name, `network.extra_hosts`),
  `tls.extra_sans` domains and the `public_url` host — except a name that is itself a public suffix
  (a TLD such as a host called `dev`, `*.com`; `home.arpa` excepted), which would permit the whole suffix and is left uncovered
  instead (a CA created with one gets a startup warning to regenerate); permitted IP ranges = private ranges from §10.3 +
  the host's global IPv6 /64s at creation; permitted rfc822Name `.invalid` (no e-mail addresses). `ca regenerate --unconstrained`
  drops constraints (warned). Key sealed at `certs/ca/ca.key.enc`.
- **Leaf**: ECDSA P-256, validity `tls.leaf_days` (default 397, max 825 = Apple's limit for user-trusted CAs), SANs = `Network.Hostnames()` + `Network.IPs()` + `localhost` +
  127.0.0.1 + ::1; EKU serverAuth; auto-renew when less than `min(30 days, a third of the certificate's own validity)` is left — so
  the promise also holds at the short end of `tls.leaf_days` (7 days) instead of putting the leaf into permanent renewal — or when the
  SAN set changes (`network.changed`, `mdns.changed`, `settings.changed{tls.extra_sans}`; while the keys are locked the change is
  remembered and applied on `keys.state` unlocked), or when the leaf's validity span no longer
  matches `tls.leaf_days` (`settings.changed{tls.leaf_days}`, renewal reason `validity_changed`; skipped when `NotAfter` was clamped to
  the CA's own expiry, so the check converges). The assembled SAN set is capped at 128 DNS names and 128 IP addresses, in collection
  order (`localhost`, this machine's own names, then `tls.extra_sans`), so an overlong list can never push the server's own names out;
  names the CA's constraints do not permit, and any excess, are dropped, logged, and reported as `uncovered_names` (§9.4). It is **presented with the local CA** (`certs/server/leaf.crt` itself stays leaf-only), so a
  client pinning the CA fingerprint (`fileparcel --fingerprint`) receives the certificate it pinned; verifiers that use a trust store
  ignore the extra self-signed root. The key/certificate pair is replaced crash-safely: the new key is staged as
  `certs/server/leaf.key.next`, the `leaf.crt` rename is the commit point, then the staged key replaces `leaf.key`; at load a
  `leaf.crt` that matches only `leaf.key.next` uses it, and the next reissue completes (or discards) the staged key first.
- **Client CA** (mTLS): separate ECDSA CA (`client-ca.crt/.key.enc`, EKU clientAuth, no name constraints — any constraint makes
  crypto/x509 reject the host-less SAN URI); client certs (EKU clientAuth, CN=username, SAN URI
  `fileparcel:user:<id>`) exported as PKCS#12 holding only the key and the certificate — never the client CA, which Android and
  Windows would install as a trusted root (`Modern2023` encoder; `--legacy` → `LegacyDES` for old Android/macOS; password 6–128
  characters, BMP only). Admins may not issue or revoke an owner's client certificates (owners and the system principal may). `mtls.mode`:
  `off|optional|required`; `required` → `tls.RequireAnyClientCert` + `CheckClient` (revocation via DB) except `/s/*`, `/trust*`,
  `/healthz` when `mtls.exempt_shares` (implemented by `VerifyConnection` + per-request check since TLS can't vary by path: in
  `required` mode the TLS layer requests certs (`RequestClientCert`) and the HTTP middleware rejects requests lacking a valid one;
  `/api/*` gets the JSON error, everything else a `text/plain` 403 that says how to install the client certificate). Without the
  exemption the local health check (§14.2/§14.7; it has no client certificate) counts the TLS `certificate_required` alert of a
  server whose certificate it verified against the local CA as up.
- **Tailscale**: `tailscale.cert_enabled` → fetch via LocalAPI `GET /localapi/v0/cert/<fqdn>?type=pair` (or `tailscale cert` CLI;
  the same socket and CLI candidates as detection in §10.1, incl. darwin's `/var/run/tailscaled.socket`, the Homebrew and app-bundle CLIs) into
  `certs/tailscale/`, renew when < 14 days or when it no longer covers the current MagicDNS name / `tailscale.domain` (checked on
  `network.changed` too, so a node or tailnet rename is picked up). Status reports the certificate and `tailscale_error` only while
  the setting is on (turning it off also clears the error). Headscale doesn't issue ts.net certs → the local CA covers the MagicDNS name if it existed at CA creation;
  otherwise it is reported in `uncovered_names` and needs `ca regenerate` (doctor `tailscale.name_uncovered`, warning on the Network
  page's Tailscale card). Failing fetches and the Funnel/Serve checks add the Headscale hint when the control server is not Tailscale's;
  availability is decided by the node's capabilities (`https`, CertDomains), never by the control URL.
- **ACME** (`acme.*`): certmagic with `FileStorage{Path: certs/acme}`, CA staging/production/custom URL, challenges `dns` (Cloudflare
  API token or RFC 2136 TSIG) or `http`/`tls-alpn` (needs public reachability on 80/443 — documented).
- **Custom**: upload PEM chain + key (key sealed); validated (key matches, not expired, chain order).
- **SNI dispatch** (`GetCertificate`): exact/wildcard match against ACME domains → certmagic; ts.net FQDN with tailscale cert → that;
  custom cert names → custom; otherwise the local leaf. `GetConfigForClient` applies `tls.min_version` (1.2 default; 1.3 option),
  modern AEAD suites only, ALPN `h2`,`http/1.1` (+`acme-tls/1` when needed).
- `/trust` page + `/trust/ca.*` + `fileparcel ca trust-help --os …`: step-by-step for iOS (profile + Certificate Trust Settings),
  Android (Settings → Security → Install certificate → CA), macOS (Keychain → Always Trust), Windows (certutil / Trusted Root), Linux
  (`/usr/local/share/ca-certificates` + `update-ca-certificates`; Fedora `trust anchor`), Firefox (enterprise roots or manual import).
  The page shows the SHA-256 fingerprint for out-of-band verification.

### 10.5 mDNS / `.local`
Name `mdns.name` (default = `server.name` = `fileparcel`) → `fileparcel.local`; DNS-SD service `_https._tcp` instance
`"FileParcel on <hostname>"`, TXT `path=/`, `fp=1`, port = https_port. `mdns.mode` = `auto|avahi|dnssd|builtin|off`:
- **avahi** (Linux; `auto` picks it when the system bus has `org.freedesktop.Avahi`): two entry groups — `AddAddress(iface=-1,
  proto=-1, flags=NO_REVERSE, "fileparcel.local", ip)` per IPv4 (and global/ULA IPv6) of the selected interfaces in one, `AddService(…, host
  "fileparcel.local")` in the other — each committed separately, so a `COLLISION` can be attributed. Watch `StateChanged`: a collision
  of the address group (or a synchronous `CollisionError` from `AddAddress`) → retry with `fileparcel-2.local`, … (publish
  `mdns.changed` so the leaf is reissued); a collision of the service group (or from `AddService`) renames only the DNS-SD instance to
  `"FileParcel on <host> (2)"` and keeps `fileparcel.local` — the instance name is identical for every FileParcel on one machine, so it
  says nothing about the host name. Published only once every committed group is ESTABLISHED. Re-publish on `network.changed`. This
  coexists with avahi-daemon (never bind 5353 ourselves).
- **dnssd** (macOS; `auto` picks it on darwin): supervised child `dns-sd -P "FileParcel on <host>" _https._tcp local <port>
  fileparcel.local <lan-ip> path=/` (restart with backoff; killed on stop; kept in FileParcel's process group so launchd reaps it if
  FileParcel dies without stopping it). dns-sd registers the service without `NoAutoRename`, so mDNSResponder renames a clashing
  instance by itself; the conflict dns-sd reports is the Unique host record's ("Got a reply for record fileparcel.local: Name in use,
  please choose another", exit status 255), which renames the host. A "reply for service" conflict renames only the instance (keep
  `fileparcel.local`). A conflict line naming neither is first treated as a service-instance collision; only a publication whose
  instance already carries a ` (n)` suffix then renames the host — renaming the host moves the access URL, the leaf SANs and the
  WebAuthn RP ID.
- **builtin** (`auto` fallback): pion/mdns/v2 server conn with `WithLocalNames("fileparcel.local")`, `WithLocalAddress`, `WithService`,
  `WithInterfaces(<the selected interfaces>)`; UDP 5353 via `net.ListenConfig` with SO_REUSEADDR|SO_REUSEPORT; probe the
  host name and the service instance first: a host conflict (an answer with an address not ours) renames `<name>-2.local`, an instance
  conflict (another responder answering the same instance with a different port/target, e.g. a second FileParcel on this machine)
  renames only the instance. While `auto` runs it (Linux without Avahi), Avahi is looked for again every 30 s and the publication moves
  to Avahi when it appears (Avahi absent at boot or restarting), so two responders never share 5353 for long.
- **Interfaces** (`mdns.selectInterfaces`): `mdns.interfaces` = `lan` (default) selects every up interface of role `local`
  (§10.1: LAN and Wi-Fi, or one set to `local` with `network.iface_roles`; never an exit VPN such as `nordlynx` or an unknown
  tunnel, which early builds announced on while it classified them `lan`), plus ZeroTier when `mdns.zerotier`; named interfaces are added
  whatever their role (a container interface only when set to `local`). A role change changes the `network.changed` fingerprint,
  so the publication follows.
- mDNS never crosses L3 VPNs (Tailscale/WireGuard/NetBird): use MagicDNS or IPs there. ZeroTier (L2) can opt in (`mdns.zerotier`).
- `MDNSStatus{mode, backend, name, configured (differs from name while a collision rename is in effect), state
  (publishing|published|collision|error|off), error, interfaces[]}`.

### 10.6 Tailscale Serve and Funnel
Package `tsingress` (service, implements `core.Ingress`; wired in every mode, attached only by a running server) publishes FileParcel
on the node's MagicDNS name through tailscaled: **Serve** = tailnet HTTPS without a port (`funnel.serve`, `funnel.serve_port`,
default 443), **Funnel** = the same on the internet (`funnel.mode` `off|shares|app`, `funnel.port` 443/8443/10000). tailscaled
terminates TLS with its own `*.ts.net` certificate and reverse-proxies HTTP/1.1 to a **dedicated ingress listener per kind**
(§9.1), never to the main listener; the request pipeline is §9.1 (`ingressHandler`, `IngressGate`), sign-in and shares §9.3/§9.4.
```
internet ─TLS─► Funnel relay ─► tailscaled :443 ──HTTP/1.1──► run/ts-funnel.sock ─► ingressHandler(funnel) ─► router (+ IngressGate)
tailnet  ─TLS─► tailscaled :443 (Serve) ───────HTTP/1.1──► run/ts-serve.sock  ─► ingressHandler(serve)  ─► router (+ IngressGate)
LAN/VPN  ─TLS─► FileParcel :8443 (allowlist at Accept, own certificates) ─► httpsRoot (refuses Tailscale-Funnel-Request) ─► router
tsingress: desired state (settings + marker) ─► tslocal: GET/POST /localapi/v0/serve-config (Etag/If-Match) ─► tailscaled
```

| | Funnel `shares` | Funnel `app` | Serve |
|---|---|---|---|
| Reaches it | the internet and tailnet devices opening that port | same | tailnet devices |
| Reachable | `/s/{token}[/…]` (any method); GET/HEAD of `/static/{hash}/…`, `/theme.css`, `/favicon.ico`, `/robots.txt`, `/manifest.webmanifest`; the rest the uniform 404 | the app minus setup, unlock, `/trust`, `/share-target` and (unless `funnel.allow_admin`) `/admin`, `/api/v1/admin` | the whole app |
| Access policy | deny list on the real client IP | deny list | the full policy on the real tailnet IP |
| Sign-in | impossible (credentials stripped; public share cookies kept) | only accounts with TOTP or a passkey while `funnel.require_2fa` (default on). Every failed password sign-in gets the same 401, which explains the rule and where to set up a second factor, so it reveals nothing about the password. The exception is the sign-in right after accepting a single-use invitation (`LoginInput.AfterInvite`, never from JSON, audited `after_invite`): the personal link proves the person, while a shared multi-use link does not. Sessions and tokens of accounts without a second factor are `EnrollRequired`, and `MFAStatus.FunnelRequired` reports the requirement for the caller's own account | normal |
| Ports | {443, 8443, 10000} ∩ the node's `funnel-ports` capability − FileParcel's own ports − Serve's port | same | 1–65535 − own ports − Funnel's port |

**`tslocal`** (leaf utility, the one tailscaled client of `netinfo`, `certs`, `tsingress`, the CLI and the installer): LocalAPI over
the Unix socket (Linux `/var/run/tailscale/tailscaled.sock`, `/run/tailscale/…`; darwin `/var/run/tailscaled.socket` too) with Host
`local-tailscaled.sock`, never `Origin`/`Referer`; the CLI (`tailscale`, the app bundle on macOS) only when no socket exists.
`FILEPARCEL_TAILSCALE_SOCKET` pins one socket and disables the CLI fallback; **inside `go test` `Default()` has no socket and no CLI**,
so a test can never reach the real tailscaled. The serve config is a surgical merge: only FileParcel's own entries change;
`Foreground`, `Services`, unknown keys and foreign entries are written back byte for byte; every POST carries `If-Match` (an empty
one would overwrite unconditionally — refused without sending), 412 → re-read and retry (3). POST errors map to 412 checks
(`backend` for "must be root/operator" 401s, `tailscale.operator` for "serve config denied" 403s, `tailscale.shields_up`,
`tailscale.config_locked`, `tailscale.running`), 409 `port` (listener already exists) or 503. CLI transport: `tailscale funnel|serve
--bg --yes --https=<port> --set-path=/ <target>`, removal always `tailscale serve --yes --https=<port> --set-path=/ off` (the funnel
command runs its port check even for `off`); Funnel on 8443/10000 through the CLI needs 443 in `funnel-ports` (`tailscale.cli_port`).

**Owned entries and conflicts.** FileParcel owns the entries whose proxy is `unix:<HOME>/run/ts-{funnel,serve}.sock` or one listed
in this home's marker (a second install has another HOME and sees them as foreign), and during a reconcile the TCP-backend targets
(`http://127.0.0.1:<funnel.backend_port>` / `<+1>`) of the kinds it publishes — only then: a hand-made entry for another program on
such a port stays foreign, and a kind whose port a foreign entry already forwards to is not applied (`backend` error). The marker
names the home that wrote it: a copied home (`cp -a`) ignores a marker whose home still exists, so it never takes over, re-points or
removes the live install's entries (they are foreign there: `conflict`); a moved home (the named home has no `fileparcel.toml` any
more) adopts it, and a listed socket of another home counts only while that home is gone. A desired `(host:port)` conflicts (409 `conflict` naming the target, state `conflict`) with a `Foreground`
session on that port or HostPort, a `TCP[port]` that is not plain HTTPS (`HTTP`, `TCPForward`, `TerminateTLS`), or any foreign mount
of that HostPort. Serve hardening: `AllowFunnel` on FileParcel's Serve entry is removed (audited `funnel_flag_removed`), and the
serve listener refuses Funnel requests. Foreign entries are listed (`IngressStatus.foreign`); `bypass` marks those that target the
main port in any form (bare port, `host:port`, `http(s)://`, `https+insecure://`, `tcp://`; localhost, loopback or an own address)
or the admin socket (also through a symlink), including Foreground and Services entries.

**Backend** (`funnel.backend` `auto|unix|tcp`, `funnel.backend_port`): `unix` = the 0600 sockets in the 0700 `run/`; `tcp` =
`127.0.0.1:<port>` (Funnel) and `<port+1>` (Serve), port 0 = pick 18443/18444 or a random free pair at first use and store it;
`auto` = unix on Linux/BSD, falling back to tcp (warn check `backend.tcp`) when tailscaled refuses Unix targets for this user
(`ErrUnixForbidden`: they need root or a sudo-capable operator) or the path does not fit `sun_path`; tcp on macOS. Peer uids: 0,
the owner of tailscaled's socket, the server's own uid (§9.1). A foreign `unix:`/path entry makes tailscaled demand root for every
change: state `error` — remove that entry or point it at a TCP target, then Re-apply (the server always writes as its own user, a
`sudo` CLI goes through it and the offline CLI never adds entries, so `sudo fileparcel … reapply` cannot help).

**Marker** `<HOME>/service/tailscale.json` (0600, atomic; removed when empty): the home that wrote it, node ID, DNS name, backend, `state`
(`pending` = enabled while the server was stopped, `applied`, `suspended` = TCP entries removed on a clean stop) and the entries.
It is not in the database (a restore brings only the settings), and is read by `Attach`, uninstall and the offline doctor.

**Reconcile** (serialized; `SetFunnel`/`SetServe`/`Reapply`, `Attach`, `settings.changed{funnel.*, server.*_port}`,
`network.changed` with a new DNS name or node; **never on a timer** — a manual `tailscale serve reset` is drift, not fought): status
and prefs → node binding (`funnel.node` ≠ this node's StableNodeID → `paused`) → checks → not attached (server stopped): removals
only, the marker records `pending`, state `stopped` → backend → switch the policy of kinds no longer wanted off **first** (the uniform 404
even if the removal fails) and close their Unix sockets (tailscaled answers 502) → open the wanted ones (the policy snapshot is
published before a listener opens) → merge and POST with the ETag loop → marker `applied` → `ingress.changed` → self-probe. A
127.0.0.1 port stays bound until tailscaled no longer routes to it (the write that removed FileParcel's entry, or a read without it):
any local program could take a free port and serve its own pages at the public address. A move of backend or port opens the new
listener next to the old one (`OpenAt`, one previous listener per kind) and releases the old port after the write; a failed removal
keeps the port bound (status `error` with `backend.tcp`) and is retried (5 s doubling to 5 min); a start while tailscaled is down
binds such a port from the marker. Mode, `allow_admin` and `require_2fa`
are FileParcel-side policy and never touch tailscaled. User calls apply first and store the settings after (all managed keys in one
`Settings.Set`; a failed store reverts tailscaled); a failing check answers 412 with `field` = the check ID and changes nothing.
Automatic reconciles are conservative: a failing capability or MagicDNS check leaves the entry as it is (state `unavailable`) —
only an entry that would take FileParcel's own port is removed (`port_clash_removed`); tailscaled unreachable or not Running keeps
the listeners open and retries (5 s doubling to 5 min) because tailscaled keeps its serve config across its own restarts; an entry
missing from tailscaled is re-added only for a `pending`/`suspended` marker — `applied` but missing, or wanted without a marker (a
restored backup, a new install), is `drift` ("Re-apply to publish"); FileParcel never publishes without a marker. A DNS rename moves
the entries (`renamed`). **Detach** (shutdown, ≤ 5 s, returns within its context: it cancels a running change — every reconcile's tailscaled I/O runs
under a context the detach cancels — and waits for the change lock only within its context): TCP backend → the marker's 127.0.0.1
entries and those of the open 127.0.0.1 listeners removed, marker `suspended` (another local program could squat the port while
FileParcel is down; after a crash they remain — the doctor warns about `backend.tcp`); Unix backend → nothing (502 while down).

**Checks** (`IngressCheck{id, label, status ok|warn|fail|skip, message?, hint?, fix_url?}` per entry): `container` (Funnel/Serve are
unavailable inside Docker/Podman), `tailscale.running`, `tailscale.control` (informational), `tailscale.magicdns`, `tailscale.https`
(capability + CertDomains), `tailscale.funnel_attr` (Funnel: the `funnel` node attribute; fix_url from `query-feature` on
`?refresh=1` or after a failed enable, cached 10 min, else `https://tailscale.com/s/no-funnel`; admin-console links only for
Tailscale's control server; https-only, ≤ 512 characters, never fetched by the server), `tailscale.funnel_port`,
`tailscale.cli_port`, `tailscale.shields_up` (fail for Funnel, warn for Serve), `tailscale.operator` (Linux: root, the socket's
owner or the operator; darwin: the write decides), `tailscale.config_locked` (after tailscaled refused: `--config`),
`tailscale.key_expiry` (warn < 14 days), `port.fileparcel` (422), `mtls` (`mtls.mode=required` only with Funnel `shares` +
`exempt_shares`), and in the status `port.free`, `port.shadow` (Linux: another program listening on that port on the Tailscale
address), `node`, `backend`, `backend.tcp` (also for a kind no longer wanted whose 127.0.0.1 entry could not be removed),
`reachable`, `passkeys` (warn on Funnel `app` and Serve: a passkey works only on its RP ID and FileParcel's allowed origins, so
passkey-only accounts cannot sign in at the ts.net address unless `auth.webauthn_rp_id` covers the MagicDNS name and the address is an
allowed origin; folded into the doctor's Funnel row). `available` = not in a container ∧ running ∧ MagicDNS ∧ HTTPS.
**States**: `off`, `active`, `stopped`, `drift`, `conflict`, `paused`, `unavailable`, `error`; an active Funnel shows the last
request and the last public request (`Tailscale-Funnel-Request` seen) and, during its first 10 minutes without one, "Public DNS can
take up to 10 minutes". Status reads tailscaled at most every 30 s (`?refresh=1` forces it).

**Self-probe**: 5 s after an apply, on `?refresh=1` (waited for ≤ 15 s) and every 10 min while it fails: TLS to the first local IPv4
Tailscale address with SNI = the MagicDNS name, `GET /.well-known/fileparcel-ingress-probe/<nonce>` (32-byte token, 2 min,
constant-time compare) → 204 ok; x509 error then 204 unverified → warn "certificate not trusted yet"; 502 → warn naming the backend
(tailscaled cannot reach it: another user, a sandbox — try `funnel.backend=tcp`); skipped without a local Tailscale address. It runs
over the tailnet: it cannot prove public DNS or the Funnel relay.

**Share links and URLs**: `shares.linkFor` = `server.public_url`, else `Ingress.PublicBaseURL()` while Funnel `shares`/`app` is active,
else relative; `features.internet_links` then tells the share dialog. `netinfo.URLs` adds `Ingress.AccessURLs()` (§10.2).
**Hand-made proxies** (§9.1): a `Tailscale-Funnel-Request` on the main listener is refused (`httpx.ProxySignals.FunnelToMain`), the
admin socket refuses proxied requests, and a forwarded request from an unconfigured local or tailnet proxy counts in
`ProxySignals.LocalProxy`; `httpx.ProxyExposures` turns foreign bypass entries and the signals of the last 24 h into the exposures
`tailscale.bypass` (fail) and `proxy.local_unconfigured` (warn). The signals count only from where such a proxy can be (anyone can
send the headers): `FunnelToMain` from a loopback, own or Tailscale (100.64.0.0/10, fd7a:115c:a1e0::/48) peer, `LocalProxy` from
loopback or an own address, or from a Tailscale peer with `Tailscale-User-Login`; a forged header only refuses itself. Their hint
removes just that entry (`tailscale serve --yes --https=<port> --set-path=<its path> off`), never every handler of the port.

**RBAC and audit**: reading needs `network.manage`, changing it `network.manage` + step-up; turning `require_2fa` off or
`allow_admin` on needs a built-in owner or administrator too (403, audited `denied`, reason `rbac`) and `confirm:"public"` like every
widening — and so does entering `app` mode while they are stored that way (they stay stored while Funnel is off or `shares`, where
they have no effect; the rule compares the effective exposure: admin pages over Funnel = `app` ∧ `allow_admin`, password-only sign-in
= `app` ∧ ¬`require_2fa`). Audit `network.funnel` / `network.serve` (§9.6); automatic changes carry the system actor and a `reason` (`renamed`,
`funnel_flag_removed`, `port_clash_removed`, `uninstall`, `suspend_failed`). **Uninstall** removes FileParcel's entries first
(`tsingress.RemoveMarked`; a failure prints the `tailscale serve … off` commands, with `sudo` after `ErrUnixForbidden`). **Offline**:
the CLI's enable while the server is stopped stores the desired state and marker `pending` ("Saved. FileParcel publishes it on
Tailscale when the server starts."); `tsingress.OfflineFindings` gives the local doctor `network.funnel`, `network.serve`,
`network.funnel_bypass` and `tailscale.key_expiry` from the marker and a read-only tailscaled.
Doctor (server): `network.funnel`, `network.serve` (off: no row; active shares ok; active app warn, and warn when `allow_admin` and
a staff account lacks 2FA; stopped info; drift/conflict/paused/error/unavailable while wanted warn with the hint; `backend.tcp`
folded in), `network.funnel_bypass` (fail), `network.proxy_unconfigured` (warn), `tailscale.key_expiry`, and the VPN rows of §10.3:
`network.exit_vpn` (info: the outgoing VPNs), `network.exit_vpn_allowed` (warn: an allow entry that is exactly an outgoing VPN's
network, with the `fileparcel network allow remove` command), `network.overlay` (warn: an allow entry overlapping 200::/7 that is shorter than a /64 — a single address or a
node's own /64, as the hint recommends, does not warn — or mode
`any` while an overlay is up), `network.exposure.<id>`, `tailscale.name_uncovered`. No firewall rule is needed for Funnel or Serve
(the traffic arrives through tailscaled), and the firewall hints open the `mesh`/`unknown` interfaces by their real names.

---

## 11. Settings catalog & propagation

### 11.1 Bootstrap `fileparcel.toml` (home marker)
Environment overrides: `FILEPARCEL_<SECTION>_<KEY>` (e.g. `FILEPARCEL_SERVER_HTTPS_PORT=9443`); the UI shows "overridden by env".
```toml
install_id = "…"               # generated at init (random 16 bytes hex)
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
file = true
max_size_mb = 50
max_files = 5
[admin_socket]
enabled = true
[runtime]
gomemlimit_mb = 0              # 0 = auto (min(1 GiB, 25% RAM))
```
`config.Load(h)` → `*config.Config` (typed struct with the fields above, `Save()` atomic rewrite preserving the comment header,
`Validate()`), `config.Default(installID)`. `server.public_url` is empty or an http(s) origin (`config.CheckPublicURL`, applied
by `Validate()` and by the catalog field): no user name or password (it would travel in every share and invitation link), no
path other than `/` (the web app is served from the root of its host), no query or fragment, a port only in 1–65535.

### 11.2 Runtime settings (DB), registered by owning packages (`R` = restart required)

| Section | Keys (default) | Owner unit |
|---|---|---|
| general | `ui.instance_name`("FileParcel"), `ui.accent_color`("#2b7ad6"), `ui.default_theme`(system: light/dark/system), `ui.login_message`(""), `ui.default_view`(list: list/grid), `maintenance.enabled`(false), `maintenance.message`("") | I (pages); maintenance.* : web/mw |
| network | `network.access_mode`(allowlist), `network.allow_cidrs`([]), `network.deny_cidrs`([]), `network.strict_host`(false), `network.extra_hosts`([]), `network.iface_roles`([]: `"<ifname>=<role>"`, role `mesh`/`unknown`/`access`/`egress`/`overlay`/`local`/`none`, ≤ 64 entries, later entries win) | G |
| mdns | `mdns.mode`(auto), `mdns.name`("" = server.name), `mdns.interfaces`(lan), `mdns.zerotier`(false) | G |
| tls | `tls.extra_sans`([]), `tls.hsts`(auto: auto/on/off), `tls.min_version`("1.2"), `tls.leaf_days`(397) | F |
| acme | `acme.enabled`(false), `acme.email`, `acme.domains`([]), `acme.ca`(staging: staging/production/<url>), `acme.challenge`(dns: dns/http/tls-alpn), `acme.dns_provider`(cloudflare: cloudflare/rfc2136), `acme.dns_credentials`(secret JSON) | F |
| tailscale | `tailscale.cert_enabled`(false), `tailscale.domain`("" = auto) | F |
| funnel | managed (changed through `PUT /admin/network/funnel` / `serve`, 409 on `PATCH`/`DELETE /admin/settings`): `funnel.mode`(off: off/shares/app), `funnel.port`(443: 443/8443/10000), `funnel.allow_admin`(false; app mode with `require_2fa` only), `funnel.require_2fa`(true), `funnel.serve`(false), `funnel.serve_port`(443: 1–65535), `funnel.node`(""; the StableNodeID of the node Funnel/Serve were enabled on); ordinary: `funnel.backend`(auto: auto/unix/tcp), `funnel.backend_port`(0 = chosen at first use; else 1024–65534) | tsingress |
| mtls | `mtls.mode`(off: off/optional/required), `mtls.exempt_shares`(true), `mtls.self_service`(false) | F |
| auth | `auth.password_min`(12), `auth.require_2fa`(admins: off/admins/all), `auth.passkeys`(true), `auth.webauthn_rp_id`("" = `<mdns name>.local`), `auth.webauthn_origins`([] = derived), `auth.session_idle_min`(720), `auth.session_max_days`(30), `auth.lockout_threshold`(10), `auth.lockout_base_min`(15), `auth.stepup_min`(10), `auth.admin_can_access_files`(false) | B |
| ratelimit | `ratelimit.login_per_min`(10), `ratelimit.api_rps`(50), `ratelimit.api_burst`(200), `ratelimit.share_per_min`(120), `ratelimit.unlock_per_min`(5), `ratelimit.funnel_per_min`(1200: per client over Funnel, an IPv6 client per /64; 1–100000), `ratelimit.funnel_global_per_min`(12000: all Funnel requests together; 1–1000000) | B (ratelimit pkg) |
| storage | `storage.default_quota_gb`(0 = unlimited), `storage.max_file_gb`(0), `storage.upload_parallel`(4), `storage.upload_expiry_hours`(48), `storage.trash_days`(30), `storage.versions_keep`(10), `storage.cipher`(auto), `storage.zip_compression`(auto), `storage.thumbnails`(true), `storage.fsync`(true), `storage.zip_password_min`(12: 8–64), `storage.zip_legacy_encryption`(true: ZipCrypto may be chosen) | A (cipher, fsync), D (trash, versions, zip_compression, thumbnails, quota, max_file), E (upload_*, zip_password_min, zip_legacy_encryption) |
| sharing | `sharing.links_enabled`(true), `sharing.require_password`(false), `sharing.max_expiry_days`(0 = no max), `sharing.default_expiry_days`(7), `sharing.requests_enabled`(true), `sharing.allow_guests_share`(false), `sharing.access_log_days`(365; 0 = keep while the link exists) | E |
| keys | `keys.web_unlock`(lan: lan/any/off) | A |
| backup | `backup.enabled`(true), `backup.schedule_meta`("0 3 * * *"), `backup.schedule_full`("0 4 * * 0"), `backup.keep_last`(7), `backup.keep_daily`(7), `backup.keep_weekly`(4), `backup.keep_monthly`(6), `backup.encryption`(x25519: x25519/passphrase), `backup.recipients`([]), `backup.identity`(secret), `backup.passphrase`(secret), `backup.copy_to`("") | H |
| email | `smtp.host`, `smtp.port`(587), `smtp.tls`(starttls: starttls/tls/none), `smtp.username`, `smtp.password`(secret), `smtp.from`, `notify.events`(["share.upload","security"]) | C |
| audit | `audit.retention_days`(365), `audit.mirror_jsonl`(false) | C |
| server (bootstrap bridge) | `server.https_port` R, `server.http_port` R, `server.bind` R, `server.name` (live for mDNS and the leaf's new name; R otherwise — until the restart the leaf keeps the running name's `.local` too), `server.public_url` R, `server.trusted_proxies`, `log.level` (live), `runtime.gomemlimit_mb`(0 = auto) R | G |

The catalog is pinned by `TestSettingsCatalogMatchesDesign` in `internal/wire`: every key of this table must be registered
with the default and `R` flag given here, and no package may register anything else.

The section `funnel` sorts right after `tailscale` (`settings.SectionOrder`); `funnel` and `tailscale` are sensitive
sections (step-up, §9.3). Which permission changes which section or key is the table of §6a (`settingsapi/caps.go`):
`storage.zip_*` need `settings.manage`, `funnel.*` and `network.iface_roles` `network.manage`, `tailscale.*` `certs.manage`,
and `ratelimit.*` stay admin-only. Roles change four descriptions: `auth.require_2fa` — "admins" covers owners, admins and
every role with a server permission; `sharing.allow_guests_share` — applies to the built-in Guest role only (custom roles
use their own permissions); `auth.admin_can_access_files` — owners and admins only, never custom roles;
`server.public_url` — scheme, host and port only.

Every list setting is bounded by the registry itself: at most 1024 entries of at most 8192 bytes each (the same per-string bound
applies to plain string settings). `tls.extra_sans` and `acme.domains` additionally accept at most 64 entries — an oversized
certificate breaks every TLS handshake ("excessive message size") and would lock the server out of HTTPS. `acme.domains` refuses IP
literals, a numeric last label and `.local`/`.localhost` names; `acme.dns_credentials` must fit one provider's shape (Cloudflare
`api_token` [+ `zone_token`], RFC 2136 `server` + `key_name` + `key` [+ `key_alg`], non-empty strings; which provider is
`acme.dns_provider`, checked when ACME is applied); `acme.email` ≤ 254 bytes with a local part ≤ 64.

### 11.3 Flow
1. `PATCH /api/v1/admin/settings {"key": value, …}` → catalog validation (type, enum, range, custom `Validate`); bootstrap-bridge keys are
   written by an atomic TOML rewrite of the file as it is on disk (edits made while the server runs are kept, not reverted).
2. One transaction writes the rows + one audit entry per key (secret values masked), then publishes `settings.changed{keys}`.
3. Response `{"applied":[…],"restart_required":[…],"warnings":[…]}` (`warnings` omitted when empty); the UI shows a "Restart now" banner (`POST /admin/system/restart` → process exits
   with code 75 → systemd/launchd restart it; when no supervisor is detected — no systemd/launchd markers and no
   `FILEPARCEL_SUPERVISED=1`, see `server.Supervised` — the process re-execs itself in place).
4. The CLI's `config set` uses the same endpoint over the socket (applies live); in offline mode the same handler runs in-process and
   takes effect at next start.
5. `settings.Store` caches values in memory (atomic snapshot), reloaded on `settings.changed`.

---

## 12. CLI command tree (cobra)

**Global flags**: `--home DIR`, `--json`, `-y/--yes`, `--no-color`, `--offline` (force in-process), `--server URL --token PAT|--token-file F
[--ca-file F|--fingerprint SHA256]` (remote; the token defaults to `$FILEPARCEL_TOKEN`, and a `--token` argument is visible in
the process list), `--as USER` (socket/offline only; acts as that user for `files`/`share`/`request`/`token` commands, whose
default is the first owner, and for `access` commands, which have the system's rights without it), `--passphrase-stdin` /
`--passphrase-file F` (the master-key passphrase, so an offline command can open a sealed home without a TTY; commands that bind
their own flag of that name — `init`, `install`, `serve`, `backup restore`, `keys unlock|seal|unseal|passphrase`, `backup config
set` — shadow it and keep their own meaning). An invalid `--server`, `--token`, `--token-file` or `--as` is a usage error (exit
2); `--server` must be `https://` (plain `http://` only for a loopback host: the API is never served over plain HTTP, §9.1, and
the token would travel in cleartext), and the remote client follows no redirect to another host or down to `http`. With both
`--ca-file` and `--fingerprint`, the pinned certificate must be on the chain verified against the CA file.

**Transport** (`cli.Connect()`): try the socket (`run/admin.sock`, peer-cred checked by the server: same uid or root). If nothing
listens and the home lock is free → build `wire.Build(ModeOffline)` and use an in-process `http.RoundTripper` over the same router
(`io.Pipe` streaming; system principal; prompts for the passphrase if sealed); run as root on a HOME that belongs to another
account, it gives what it wrote back to that account before releasing the lock (§3). If the lock is held but the socket is dead →
error with a `fileparcel doctor` hint. `--offline` does not apply to `status`, `doctor` and `healthcheck`, which always inspect the home locally;
`status` and `doctor` say so when the admin socket answers. All commands print tables by default and JSON with `--json`.

The tree, grouped as `fileparcel --help` shows it (main flags only; `fileparcel <command> --help` and the generated reference in
docs/COMMANDS.md have all of them):

```
fileparcel                          root help: the 7 groups, common tasks, help topics
Getting started
├─ status [--json] | open [--qr] [--no-browser] | doctor [--fix] | help [command|topic]
Files & sharing
├─ files  ls [path] [-l] [--sort name|size|updated|kind] | tree [path] | info <path> | search <query> [--in P] [--kind file|folder]
│         | versions <path> [--restore ver_…] | mkdir <path>... [-p] | mv <src>... <dest> | cp <src>... <dest> | rm <path>... [--purge]
│         | trash [--empty] | restore <path|id|name>... | get <remote> [local] [--zip|--tar] [-o F] [-f] [--version ver_…]
│         | put <local>... <remote-folder> [-p] [--conflict rename|replace|skip|fail] [--parallel N]
│               [--zip NAME [--zip-password|--zip-password-stdin|--zip-password-file F|--zip-generate-password]
│                [--zip-encryption aes256|zipcrypto]]
│         (paths are "/My files/…" or "/Team/<group>/…"; also node ids, "nod_…[/sub/path]")
├─ share  list [--inactive] [--all-users [--user U]] | create <path> [--expires 7d|DATE|never] [--password|--password-stdin|
│         --password-file F] [--max-downloads N] [--no-download] [--no-preview] [--upload [--notify]] [--title --message] [--qr]
│         | show <id> [--qr] | edit <id> [...] | enable <id> | disable <id> | delete <id> | log <id>
├─ request list [--inactive] [--all-users [--user U]] | create <folder> [--title --message --expires --max-size --quota
│         --require-name --password… --notify --qr] | show <id> | close <id> | reopen <id> | delete <id> | log <id>
People & access
├─ user   create <user> [--role R --email --display-name --group G... --quota SIZE
│         --generate-password|--password-stdin|--password-file F --must-change] | list [--role R --status S -q TEXT]
│         | show <user> | edit <user> [--role --email --display-name --quota --must-change] | disable <user> | enable <user>
│         | delete <user> [--transfer-to U] | set-role <user> <role> | set-quota <user> <size|unlimited|default>
│         | reset-password <user> [--generate-password|--password-stdin|--password-file F] [--must-change] | reset-2fa <user>
│         | unlock <user> | sessions <user> | revoke-sessions <user>
├─ invite create [--role R --group G... --expires 7d|DATE --uses N --quota --email E --send --note --qr] | list [--inactive]
│         | revoke <id>
├─ group  list | show <group> | create <name> [--description] | edit <group> [--name --description] | rename <group> <new-name>
│         | delete <group> | members <group> | add-member <group> <user>... [--manager] | remove-member <group> <user>...
├─ role   list | show <role> | permissions | members <role> | create <name> [--from R] [--base member|guest]
│         [--add P... --remove P... | --set P,…] [--description] [--delegable|--no-delegable] | edit <role> [--name --description
│         --add --remove --set --delegable|--no-delegable] | delete <role> [--reassign-to R] | add-group <role> <group> [--manager]
│         | remove-group <role> <group>
├─ access list <path> [--direct] | grant <path> (--user U|--group G|--role R)... [--level view|edit|manage]
│         [--expires 30d|DATE|never] | revoke <path> ((--user U|--group G|--role R)... | gnt_…) | check <user> <path>
├─ token  create <name> [--user U --scopes files:read,files:write,shares,admin --elevated --expires 30d|DATE|never]
│         | list [--user U] [--inactive] | revoke <id>
├─ whoami
Server & network
├─ config list [--section S] [--all] | get <key> | set <key> [value] [--force] | unset <key> [--force] | path | edit
│         | test-email --to ADDRESS
├─ network [status] | urls [--qr] | interfaces | policy | mode private|allowlist|any [--force]
│         | allow list | allow add|remove <cidr|ip>... [--force] | deny list | deny add|remove <cidr|ip>... [--force]
│         | vpn [list] | vpn allow|remove <vpn|interface> [--force]
│         | vpn role <interface> <mesh|unknown|access|egress|overlay|local|none|auto>
│         | funnel [status [--refresh]] | funnel enable [--mode shares|app] [--port 443|8443|10000] [--allow-admin|--no-allow-admin]
│         [--require-2fa|--no-require-2fa] | funnel disable | funnel reapply
│         | tailscale-serve [status [--refresh]] | tailscale-serve enable [--port N] | tailscale-serve disable | tailscale-serve reapply
│         | mdns status | mdns enable|disable | mdns name <label> [--force] | mdns mode auto|avahi|dnssd|builtin|off | mdns republish
├─ logs [-f] [-n 200]
Security
├─ audit  list [--since --until --user --action --outcome --target --limit -f] | verify | export [--format csv|jsonl] [-o F] [-f]
├─ ca     show [--pem] | fingerprint | export [--format pem|der|mobileconfig] [-o F] [-f] | regenerate [--unconstrained]
│         | trust-help [--os ios|android|macos|windows|linux|firefox]
├─ cert   status | renew [--force] | sans [list] | sans add|remove <name|ip>... | upload --cert F --key F | clear-custom
│         | acme enable --email E --domain D... --challenge dns|http|tls-alpn --dns-provider cloudflare|rfc2136
│         [--credentials-stdin|--credentials-file F] [--production] | acme disable | tailscale enable|disable|fetch
├─ client-cert issue <user> [--name --expires 365d -o F.p12 -f --password-stdin|--password-file F --legacy] | list [--user]
│         [--inactive] | revoke <id|serial> [--reason]
├─ keys   status | unlock [--passphrase-stdin|--passphrase-file F] | lock | seal | unseal | passphrase | recovery-key | verify
│         | rotate (--kek [--purpose blob|field] | --master | --data) [--wait|--no-wait]
Backups & maintenance
├─ backup create [--scope full|metadata] [--note] [-o PATH|- [-f]] [--wait|--no-wait] | list | show <backup>
│         | verify <backup> [--deep] [--wait|--no-wait] | delete <backup> | export <backup> <path> [-f] | import <file>
│         | restore <backup> [--identity-file F|--identity-stdin|--passphrase-stdin|--passphrase-file F] [--metadata-only]
│         [--dry-run] [-y] | schedule show | schedule set --meta CRON --full CRON | schedule disable|enable | prune
│         | config show | config set --keep-last N ... | identity show | identity generate
├─ maintenance [status] | on [--message TEXT] | off     (settings `maintenance.enabled` / `maintenance.message`, registered by
│                        `web/mw` and enforced by the `Maintenance` gate in the root chain §9.1)
├─ jobs   list [--kind --state --limit] | show <job> [--wait] | cancel <job> | run <kind> [--wait|--no-wait]
├─ db     check [--quick] | vacuum | migrate | stats
├─ gc     [--dry-run] [--min-age 2d]
Install & service
├─ install --dir --port --http-port --name --service user|system|none --boot|--no-boot --symlink PATH|--no-symlink
│          --admin USER --generate-password|--admin-password-stdin|--admin-password-file F --admin-email E --sealed
│          --access MODE --allow CIDR... --upgrade --force --dry-run -y          (called by install.sh; interactive by default)
├─ init  --home DIR [--port 8443] [--http-port 8080] [--name fileparcel] [--admin USER]
│        [--admin-password-stdin|--admin-password-file F|--generate-password] [--admin-email E]
│        [--sealed --passphrase-stdin|--passphrase-file F] [--access private|allowlist|any] [--allow CIDR]...
├─ service install [--user|--system] [--boot|--no-boot] [--start] | uninstall | start [--wait|--no-wait] | stop
│          | restart [--wait|--no-wait] | status | enable-boot | disable-boot | print
├─ upgrade <release.zip|binary> [--dry-run] [--force] [--skip-backup]   # verify SHA256SUMS, pre-upgrade backup, swap bin,
│                                                                          restart, health check, rollback on failure
├─ uninstall [--keep-data|--purge] [--final-backup [--backup-to DIR]] [--remove-user] [--dry-run] [-y]
├─ serve [--foreground] [--dev] [--passphrase-file F] [--init-if-missing] [--allow-root]
├─ healthcheck [--timeout 5s] [--port N] | version [--json] | completion bash|zsh|fish|powershell
└─ docs --markdown [-o F]      (hidden; generates the command reference used by docs/COMMANDS.md)
Help topics: fileparcel help connect | flags | paths | values | permissions | scripting | renamed
```

`--non-interactive` stays on `init`, `install`, `uninstall` and `upgrade` (install.sh and uninstall.sh pass it) but is hidden
from help; `-y` means the same.

### 12.1 Conventions

- **Verbs.** `list` (alias `ls`), `show` (one object), `create` (an object that gets an id), `edit` (several attributes),
  `set-X` (one attribute: `set-role`, `set-quota`), `delete` (alias `rm`; permanent), `add`/`remove` (entries of a list: allow
  lists, SANs, group members), `enable`/`disable` (reversible on/off), `revoke` (credentials or access held by someone else:
  tokens, invitations, client certificates, access grants), `status` (state of a subsystem). Domain verbs stay where they are
  the term of art (`issue`, `renew`, `rotate`, `seal`, `unlock`, `verify`, `prune`, `import`, `export`, `generate`, `grant`).
  `files` keeps its Unix names (`ls`, `mkdir`, `mv`, `cp`, `rm`); there `rm` moves to the trash (`--purge` deletes).
- **Placeholders** in `Use`: lowercase in angle brackets, optional in `[ ]`, repeatable with `...`: `<user>` (username or
  `usr_…`), `<group>`, `<role>`, `<path>`, `<folder>`, `<id>`, `<backup>` (`bak_…` or a file), `<job>`, `<key>` (setting),
  `<cidr|ip>`, `<vpn|interface>`, `<name>` (only for things being created). Shell completion keys off these names (§12.5).
- **Texts.** `Short`: sentence case, imperative, no trailing period, ≤ 64 characters. `Long`: what it does and when to use it,
  then defaults, side effects and what it needs, wrapped at 80 columns; two shared sentences are constants in help.go
  (`elevationNote`, or `elevationNoteFor` when only some uses need step-up, and `confirmNote`). Examples: 2–4 lines (5 for
  `install` and `files put`), each a canonical invocation of the command or a descendant, with the sample data `alice`, `bob`,
  `carol`, `Design`, `Marketing` and full-length ids. `TestEveryCommandDocumented` enforces all of it.
- **Flags.** `-o, --output FILE` (`-` = stdout where it makes sense); `-f, --force` only for "overwrite the output file"
  (`--force` without shorthand overrides a safety check); a risky action asks, and the global `-y` answers; `--wait`/`--no-wait`
  on every command that can return before its job finishes, with the default in the help; `--inactive` includes revoked,
  expired, used or closed items; `--all-users` (+ `--user U`) lists every user's items; durations take `30m`, `12h`, `7d`,
  `2w`, `1d12h` and print as `2d`; `--expires` takes a duration, a date (end of that day) or `never` where things may last
  forever (`parseExpiry`); sizes `500M`, `10G`; lists by repeating the flag; `--x`/`--no-x` for on/off. The helpers are in
  flags.go (`durationVar`, `addOutputFlag`, `addForceFlag`, `addWaitFlags`, `addSecretFlags`, `addInactiveFlag`,
  `addAllUsersFlags`, `parseExpiry`).
- **Secrets** never go on argv: `--X` (a switch that asks on the terminal, annotated `fp:secret-prompt`), `--X-stdin` (first
  line of standard input), `--X-file F` (first line of a file), and a generate switch where a generated secret makes sense.
  The documented exception is the global `--token` (the help recommends `$FILEPARCEL_TOKEN` or `--token-file`). The root's
  `PersistentPreRunE` (`checkInvocation`; no command sets its own) refuses a word typed right after a secret-prompt switch
  without echoing it, and allows only one flag per invocation to read standard input (`config set <secret-key>` without a
  value counts).
- **Output and exit codes** (unchanged contract): tables and results on stdout; prompts, warnings, progress and notes on
  stderr; `--json` = one JSON document (JSON lines with `--follow`), lists are `[]`, never `null`; exit `0` ok, `1` error
  (also "aborted" and a question without a terminal), `2` usage or invalid input, `75` restart requested. `--json` errors are
  `{"error":{"code","message","field"?,"hint"?}}` with `code:"usage"` for exit 2.

### 12.2 Help groups and topics

`fileparcel --help` lists the top-level commands in seven cobra groups — Getting started (`doctor help open status`), Files &
sharing (`files request share`), People & access (`access group invite role token user whoami`), Server & network (`config logs
network`), Security (`audit ca cert client-cert keys`), Backups & maintenance (`backup db gc jobs maintenance`), Install &
service (`completion healthcheck init install serve service uninstall upgrade version`) — plus the common tasks of the root
`Long` and the help topics. Group ids are assigned centrally (`topLevelGroup` in help.go, never in constructors;
`TestRootHelpGroups` fails on a visible command without a group). The big groups have sections the same way (`subGroups`):
`files` (Browse / Upload and download / Organize), `user` (Accounts / Role and storage / Sign-in and security), `network`
(Addresses / Who may connect / Remote access / Local name) and `backup` (Backups / Copy archives / Automatic backups).

The usage template (`usageTemplate`) prints a group's own use line only when running it bare does something (annotation
`fp:bare`: `network`, `network vpn|funnel|tailscale-serve`, `maintenance`, `cert sans`, `backup config|schedule|identity`,
which show their state), one line for the root's 13 global flags on every subcommand page (`fileparcel help flags` has them all; flags inherited from a non-root parent such as
`maintenance --message` are printed in full), and the help topics. Help topics are root children without `Run`:
`fileparcel help <topic>` and `fileparcel <topic>` print their text — `connect`, `flags`, `paths`, `values`, `permissions`,
`scripting`, and `renamed`, which is generated from the legacy registry (§12.4). Their names collide with no command or alias
(test). `fileparcel docs --markdown` (clikit) lists the same groups in its contents and ends with a "Help topics" section.

### 12.3 Errors and suggestions

- **Unknown words.** Every group is a `groupCmd`; an unknown subcommand is a usage error (exit 2) with suggestions by
  optimal-string-alignment distance ≤ 2 plus prefix matches (`fileparcel user lsit` → `did you mean "fileparcel user list"?`).
  At the root, task words that are not commands point at the command that does it (`taskHints`: `upload` → `files put`,
  `passwd` → `user reset-password`, `funnel` → `network funnel`, `headscale` → `network vpn`, `grant` → `access`). Suggestions
  never run anything; prefix matching stays off.
- **Flags** (`flagError`): an unknown flag suggests the closest flag of the command, synonyms (`role create --allow` → `--add`),
  and the sibling command that has it (`share show --inactive` → `share list`); a secret typed into `--password=VALUE`
  or into a `-stdin` switch (`--password-stdin=VALUE`) is redacted. `--X=false` turns an option off like `--no-X` on every
  on/off pair (`onOff`).
- **Arguments** (`argsError`, wrapped around every `Args`): `needs <user>` with the usage line and the first example; a path
  with spaces split into several arguments gets a quoting hint; cobra's flag-group texts become `use only one of --boot and
  --no-boot` (`friendlyCobraError`).
- **Server errors** (`explainErrorFor`, applied once to the whole tree): not found → `list them with "fileparcel user list"`
  (the group's `fp:list` annotation); a remote 403 → what the token's account, role or scopes lack (`see "fileparcel whoami" or
  "fileparcel role show <role>"`); a 403 with `--as` → drop `--as`, plus `access check` for a command on a path (else `whoami`);
  a 422 on a setting key → `config get KEY --json`; a 409 on `create` → it already exists; a managed Funnel setting →
  `network funnel` (`network tailscale-serve` for `funnel.serve*`; nothing when the server's message names the command), a
  setting an environment variable sets → where to change it (no `--force` hint); a disk-space refusal (`quota` code, "free
  disk space") → free space on the server, not a quota. Connection errors name what to do (no home, not a home, a socket owned
  by another system account).

### 12.4 Legacy names

Every invocation that worked before the command tidy-up keeps working (`TestLegacyInvocations` runs the 178 command paths of
the tree before it, every alias and the argument sets scripts use). The registry is `internal/cli/legacy.go`; renames go through it, nowhere
else:

| Kind | Old | New |
|---|---|---|
| command (hidden copy, same constructor) | `mdns …`, `restore …`, `keys export-recovery` | `network mdns …`, `backup restore …`, `keys recovery-key` |
| leaf command (old name kept as an alias) | `user add`, `user passwd`, `user quota`, `share revoke` | `user create`, `user reset-password`, `user set-quota`, `share delete` |
| flag (pflag normalization) | `--generate` (user create, reset-password), `--out` (backup create, client-cert issue), `--all` (share/request list), `--all` (token/invite/client-cert list), `--identity` (backup restore) | `--generate-password`, `--output`, `--all-users`, `--inactive`, `--identity-file` |
| hidden compatibility flag | `request close ID --reopen`, `token create --name NAME`, `cert sans --add/--remove X`, `client-cert issue --days N` | `request reopen ID`, `token create NAME`, `cert sans add/remove X`, `--expires Nd` |

A legacy copy is built by the same constructor, so it has the same guards, confirmations and elevation (hidden is not
weaker); on a terminal (never with `--json`) it prints a one-line note with the new name. Old names are absent from help,
the generated reference and completion; `fileparcel help renamed` lists them all. Two behaviour changes are deliberate: the
bug fix `fileparcel service <typo>` → exit 2 (was 0), and the secret-prompt guard (§12.1) — a word right after
`--password` or `--zip-password` is refused, so `share create --password PATH` and `request create --password PATH`
(which prompted before) must now put the path first. `TestDocsUseCanonicalCommands` (tests/docs) fails when README.md, docs/*.md
(code only, outside generated blocks and the lists of old names), the web scripts, Go string literals or the install files
use an old name (`cli.LegacyNames()`).

### 12.5 Shell completion

`fileparcel completion bash|zsh|fish|powershell` prints cobra's script. Beyond command and flag names, `complete.go` completes
the words of enum flags (`enumFlags`: `--conflict`, `--format`, `--scope`, `--level`, `--mode`, `--base`, `--zip-encryption`,
`--port` of `network funnel enable`, …), fixed argument words (`user set-quota … unlimited|default`, `network vpn role …`), and,
from a running server, user, group and role names, permissions (comma lists too), setting keys, sections and values, VPN ids,
interfaces, the ids of links, file requests, tokens, invitations, backups, jobs, client certificates and access grants, and
remote paths (the entries of the folder the typed path is in; folders end in `/` and get no trailing space). Arguments are
completed by the placeholders of the `Use` line (`argSource`), acting like the command would (file commands as the first owner
over the socket, `access check` as the checked user). `completeFrom` connects only over the admin socket or with `--server`,
never offline (no home lock, no passphrase prompt), gives up after 1.5 s and completes nothing on any error; setting keys,
permissions and the built-in roles fall back to the catalogs compiled into the program. No flag that carries a secret has a
completion function (test).

### 12.6 Files of `internal/cli`

`root.go` (tree, globals, `run`, `printError`), `help.go` (groups, sections, template, topics, `finishTree`, error texts,
suggestions), `legacy.go` (§12.4), `flags.go` (§12.1 helpers, `checkInvocation`), `complete.go` (§12.5), `client.go`
(transports), `output.go` (tables, KV, prompts, secrets), `cmd_common.go` (resolvers for users, groups and roles, the role
catalog, list helpers, `explainErrorFor`), one `cmd_*.go` per group (`cmd_role.go`, `cmd_access.go`,
`cmd_network_tailscale.go` for `network vpn|funnel|tailscale-serve`, `cmd_whoami.go`, …), the lifecycle commands (`init.go`,
`install.go`, `serve.go`, `service.go`, `status.go`, `doctor.go` + `doctor_ingress.go` and `doctor_ingress_wire.go` (the
Funnel/Serve rows of a stopped server, from `tsingress.OfflineFindings`), `upgrade.go`, `uninstall.go`, …) and
`clikit/` (progress bars, retries, content hashing, the Markdown reference). DEVELOPMENT.md "Adding a command" is the
checklist for a new command.

---

## 13. Frontend

### 13.1 Principles
No build step, zero npm. ES modules + modern CSS (`@layer`, nesting, `light-dark()`, container queries, `:has()`).
- `// @ts-check` + JSDoc types in every module.
- The server hashes embedded assets at startup and serves them under `/static/<buildhash>/…` with immutable caching; relative imports
  inherit the prefix — no import map or inline script needed. `<link rel="modulepreload">` for the shell modules; lazy `import()` per page.
- **No `innerHTML`, `outerHTML`, `insertAdjacentHTML`, `document.write`, `eval`, `new Function`, inline event handlers or inline styles**
  (enforced by CSP `require-trusted-types-for 'script'; trusted-types fp`
  (`fp` is the app's single Trusted Types policy; it only implements `createScriptURL` for same-origin `/static/<hash>/…` and `/sw.js` URLs — needed for `new Worker()` and `serviceWorker.register()`; it never implements `createHTML`/`createScript`)). All DOM via the `h()` helper and `textContent`.
- Boot data: `<script type="application/json" id="fp-boot">` (html/template-escaped JSON: csrf, user, instance name, asset base,
  features, keys state). Dynamic styling via classes or `el.style.setProperty()` (CSSOM is allowed).
- QR codes: server-side SVG (`/api/v1/qr.svg?data=…` or data URIs embedded in API responses), displayed via `<img>`.
- Blob URLs only for client-generated downloads (e.g. recovery-codes `.txt`).

### 13.2 Route map
| Public (server template + one module) | App shell (SPA, History API) |
|---|---|
| `/login` (password → TOTP/recovery step; passkey button + `mediation:'conditional'` autofill) | `/files`, `/files/:nodeId` (personal & team folders), `/shared`, `/links`, `/requests`, `/starred`, `/recent`, `/trash`, `/activity`, `/search?q=` |
| `/invite/:token` | `/settings/profile`, `/settings/security`, `/settings/sessions`, `/settings/tokens`, `/settings/appearance`, `/settings/devices` |
| `/setup` (setup token from terminal/logs) | `/admin` (dashboard), `/admin/users`, `/admin/users/:id`, `/admin/invites`, `/admin/groups`, `/admin/groups/:id`, `/admin/roles`, `/admin/roles/:id` |
| `/unlock`, `/trust` | `/admin/settings` (→ the first section the account may change), `/admin/settings/:section`, `/admin/network`, `/admin/certificates`, `/admin/encryption`, `/admin/backups`, `/admin/audit`, `/admin/jobs`, `/admin/system` |
| `/s/:token` (share viewer, file-request drop zone) | |

Admin routes name who may open them (`routes.js`; the app shell's route guard renders the "not allowed" page for everyone
else, without calling the API; the server authorizes every request on its own, §6a):

| Guard | Routes |
|---|---|
| `staff: true` (any server permission; owners and admins) | `/admin` — the dashboard with `system.view`, else "Your admin areas" (a card per admin page the role opens, no API call) |
| `perm: 'users.view'` | `/admin/users`, `/admin/users/:id`, `/admin/groups`, `/admin/groups/:id`, `/admin/roles`, `/admin/roles/:id` |
| `perm: 'invites.manage'` | `/admin/invites` |
| `perm: ['settings.manage', 'network.manage', 'certs.manage', 'system.manage']` (any of) | `/admin/settings`, `/admin/settings/:section` (the section list is what `GET /admin/settings` returns) |
| `perm: 'network.manage'` | `/admin/network` |
| `perm: 'certs.manage'` | `/admin/certificates` |
| `perm: 'backups.run'` | `/admin/backups` |
| `perm: 'audit.view'` | `/admin/audit` |
| `perm: 'system.view'` | `/admin/jobs`, `/admin/system` |
| `admin: true` (built-in owners and admins only) | `/admin/encryption` |

`internal/web/static/perms_test.go` pins every permission name the UI checks (`perm:`, `can('…')`, `canAny([…])`) and the
labels of `core/perms.js` to `core.Capabilities`; `tests/docs/roles_docs_test.go` pins this table to `routes.js`.

### 13.3 JS contracts (foundation writes `core/*`, `routes.js`, `nav.js` and minimal working components; J1 polishes)
```js
// core/dom.js
h(tag, {class, attrs, dataset, on:{click}, style:{prop:val}, text, ref}, ...children) → Element
svg(tag, attrs, ...children); icon(name, {size, label}) → SVGElement  // <svg><use href="<asset>/icons/sprite.svg#name">
clear(el); qs(sel, root); qsa(sel, root); boot() → parsed #fp-boot JSON; asset(path) → `${boot.asset_base}/${path}`

// core/api.js
class ApiError extends Error { status; code; field; requestId }
api.get(path, {query, signal}); api.post/put/patch/del(path, body, opts); api.raw(path, init) → Response
// adds X-FP-CSRF + JSON; 401 → location to /login?next=; 403 elevation_required → promptElevation() then retry once;
// 403 mfa_enroll_required → navigate('/settings/security?enroll=1');
// 403 password_change_required → navigate('/settings/security?must_change=1'); 503 keys_locked → /unlock;
// 403 csrf_invalid → refreshCsrf() (GET /me) then retry once, even with {handle: false}

// core/router.js
start(routes, outlet); navigate(path, {replace}); link(href) → click handler; current() → {path, params, query}
// core/store.js
signal(v) / computed(fn) / effect(fn); session (signal of /me); jobs (SSE-fed store); events.on(topic, fn)
// core/format.js  bytes(n), date(ts), relTime(ts), duration(ms), pct(a,b)
// core/keys.js    shortcut registry (Ctrl/Cmd+K palette, ?, g f, g s …)

// page modules (pages/**.js)
export const title = 'Users';
export async function mount(root, ctx /* {params, query, me, signal: AbortSignal} */) { …; return () => { /* cleanup */ }; }

// components (components/*.js) — public API contract
button({label, icon, variant:'primary'|'secondary'|'ghost'|'danger', size:'sm'|'md', onClick, disabled, type, title})
iconButton({icon, label, onClick, variant})
field({label, name, type, value, help, required, autocomplete, placeholder, min, max}) → {el, input, setError(msg), value()}
select({label, name, options:[{value,label}], value, onChange}) → {el, input}
toggle({label, checked, help, onChange}) → {el, input}
form({fields, submitLabel, onSubmit: async (values)=>{}, cancel}) → {el, reset()}   // maps ApiError.field → field errors
dialog({title, body, actions, size:'sm'|'md'|'lg', onClose}) → {el, open(), close()}
confirm({title, message, danger, confirmLabel}) → Promise<boolean>
prompt({title, label, value, confirmLabel}) → Promise<string|null>
promptElevation() → Promise<boolean>
toast.show({message, kind:'info'|'success'|'warning'|'error', action:{label,onClick}, timeout})
menu({anchor, items:[{label, icon, onClick, danger, disabled, divider}]})
contextMenu(el, itemsFn)                // right-click; long-press (500 ms) on touch
sheet({title, content}) → {open(), close()}   // mobile bottom sheet
tabs({items:[{id,label}], active, onChange}); table({columns, rows, onSort, selectable, empty, rowKey, onRowClick})
virtualList({rowHeight, count, render, overscan}); pageHeader({title, subtitle, actions, breadcrumbs})
card({title, body, actions}); statTile({label, value, hint, icon}); badge({text, kind}); emptyState({icon, title, text, action})
copyField({value, label}); qrImage({src, alt}); progress({value, max, label}); skeleton(n); spinner()
settingsForm({section, keys, onSaved(res, changes)}) → element  // auto-generated from GET /admin/settings catalog (§5.3);
                                      // renders restart_required and warnings from the PATCH answer itself
```

### 13.4 Design system
`@layer reset, tokens, base, layout, components, pages, utilities`. Tokens (`--fp-*`): semantic colours via `light-dark()` —
`bg`, `surface`, `surface-2`, `border`, `text`, `text-muted`, `primary` (brand blue `oklch(0.58 0.16 255)` = `#2b7ad6`, the `ui.accent_color` default; overridable via generated
`/theme.css` from `ui.accent_color`), `accent-kraft` (warm parcel highlight), `success`, `warning`, `danger`, `info`, `focus-ring`;
text on the primary/danger fills (`on-primary`, `on-danger`): white on the light-mode defaults, near-black on the lightened
dark-mode fills (≥ 4.5:1, hovers included); a custom accent's on-primary is picked by contrast;
4 px spacing scale `--fp-space-1…10`; radii 6/10/14/999; shadows 1–3; fluid type (`clamp`) 12–32 px; `system-ui` font stack (no webfonts);
motion 120/200 ms honouring `prefers-reduced-motion`; z-index scale; density `[data-density=compact]`; theme `[data-theme=light|dark]` or system.
Icons: one SVG sprite (~70 icons, Lucide-derived, ISC — recorded in `docs/THIRD_PARTY.md`). App icons (192, 512, Apple 180 and maskable 512 PNG) are
committed under `web/static/icons/`, rendered from `icons/logo.svg`; if the logo changes, re-render them from `logo.svg` with any SVG
rasteriser and commit them (there is no generator in the repository).

### 13.5 Navigation & responsiveness
- **Desktop ≥ 1024 px**: collapsible left sidebar — *Workspace* (My files, Team folders…, Shared with me, Starred, Recent), *Sharing*
  (My links, File requests), Trash, Activity, *Admin* group (Dashboard, Users, Groups, Roles, Invites, Settings, Network & VPN,
  Certificates, Encryption, Backups, Audit log, Jobs, System); footer: storage meter, lock/cert status dot, version. Top bar: search
  (Ctrl/Cmd+K command palette), **Upload split button** (Files / Folder / New folder / New file request), jobs indicator, help,
  avatar menu (its title shows the role name).
- **Permission-driven navigation** (rbac, §6a): `core/store.js` answers `isAdmin()` (built-in owner/admin: the administrator-only
  areas), `can(perm)` / `canAny(perms)` (the role's `permissions` from `/me`, falling back to the boot data; owners and admins pass
  every check), `isStaff()` (`me.staff`: at least one usable server permission) and `hasSpace()` (a personal space; roles based on
  Guest have none). Every navigation surface — sidebar, rail, the *More* sheet, the command palette and `g a` — shows exactly the
  admin items whose route guard (§13.2) passes; the *Admin* group appears as soon as one item is visible, so a delegate sees only
  their own areas. *My files*, *Trash* and the initial Upload button need `hasSpace()`. The jobs indicator links to Admin → Jobs with
  `system.view`, the certificate status dot polls `/admin/certs` only with `certs.manage`. SSE `authz.changed` (an administrator
  changed this account's role, a role or a role's groups) re-reads `/me`, rebuilds the navigation, re-runs the route guard (the
  "not allowed" page replaces a page that is no longer allowed, and the reverse), drops the cached role lists and — when the event
  names this account or its role, and its reason is not `role_details` (only the role's name, description or `delegable` flag
  changed) — refreshes team folders and toasts "Your access was changed by an administrator."
- **Roles pages**: Admin → Roles lists built-in and custom roles (filters, search, New role / Duplicate / Delete for administrators);
  the role page has the tabs Permissions (a switch per catalog permission, implied ones included automatically, a sticky save bar
  with a confirmation that lists what is added — high-impact ones with their warning — and removed, and whom it affects), People,
  and for custom roles Folders (role grants) and Groups (role → group memberships). Pages with unsaved changes ask before leaving.
- **The other admin pages follow the role, control by control** (the server decides; the UI only leaves out what would
  fail): Users filters by role (`?role_id=`), shows role badges and offers New user and the row actions only with
  `users.manage`, for the accounts the role may manage (§6a `CheckManage`); role pickers list the built-in and custom roles,
  those the caller may not give disabled with the reason, and send `role_id`. The user page adds the **Access card** (server
  permissions; groups and team folders with their source, direct or through a role; items shared with the account, and how
  many more are hidden) and shows profile, role and quota read-only without `users.manage` or for an account the role may not
  manage; password, two-factor and session controls need `users.credentials`. Invites: role picker; roles with server access
  are limited to one use and 7 days, and ask for step-up; rows whose link the caller may not see say so. Groups: Roles column;
  the group page marks memberships that come from a role (they are changed on the role) and lists the **Roles in this group**;
  every change needs `groups.manage`. Settings lists the sections `GET /admin/settings` returns (a known section outside the role
  renders the "not allowed" page); System shows the log with `audit.view` and Restart with `system.manage`; Backups keeps
  download, restore, delete, import, the schedule and the keys for administrators; Jobs offers Run and Cancel per kind
  (`backup.*` → `backups.run`, else `system.manage`); Certificates keeps the custom certificate for administrators. A button
  that opens another admin page (the health checks' fix links, the dashboard's tiles and warnings, the notes of the settings
  sections, the Tailscale certificate on the Network page) is shown only when that page's route guard passes (`pathAllowed`).
- **Sharing and account pages**: the Share dialog offers custom roles as subjects (`GET /roles`, when `features.directory`;
  shield avatar, "Role · everyone with this role") and the levels Can view / Can edit / Can manage. Settings → API tokens needs
  `tokens.create` to create tokens and offers the admin scope to staff; Profile names the role and opens **What can I do?**
  (the role's permissions as chips). The invitation page says "You will join as <role>".
- **Tablet 640–1023 px**: icon rail + slide-over drawer.
- **Mobile < 640 px**: top app bar (back, title/breadcrumb, overflow); **bottom tab bar**: Files, Shared, centre **Upload FAB**, Links,
  More (sheet with the rest); file actions via long-press or ⋮ → bottom sheet; multi-select mode with a sticky bottom selection bar;
  touch targets ≥ 44 px; text fields ≥ 16 px on touch screens (iOS zooms into smaller ones on focus); `env(safe-area-inset-*)`
  (the sidebar rail widens by the left inset in landscape); no horizontal overflow at 320 px.
- **File view**: virtualized list & grid (thumbnails), sort, keyboard nav (arrows, Enter, Del, F2, Ctrl+A), shift/ctrl multi-select,
  drag-to-move (desktop), inline rename, preview overlay (image with zoom, video/audio with seeking, PDF iframe, text/code), details panel
  (info, versions, sharing, activity).

### 13.6 Upload UX
Split button & drop overlay (§8.1). Pre-upload dialog (destination, bundle-as-zip toggle + name, conflict policy with "apply to all").
Queue panel: floating card (desktop) / full sheet (mobile) with per-file and overall progress, speed, ETA, pause/resume/cancel/retry.
After reload: a "resume" card listing unfinished batches asking to re-select files.

**Password protection** (`upload/protect.js`, wired by `upload/manager.js`): with "Bundle into a single .zip" on and at least
one file, the switch **Protect the .zip with a password** shows the block:
- an encryption choice of two cards, **AES-256** (Recommended) and **ZipCrypto** — only while `features.zip_legacy_encryption`
  (boot) allows ZipCrypto; choosing it shows a warning; the choice is never remembered;
- **Password** and **Confirm password** (show/hide each; `autocomplete=new-password` plus the password managers' "ignore" hints, so
  the FileParcel sign-in is neither offered nor overwritten), a strength meter, the client-side rules of §8.1 with
  `limits.zip_password_min` (the common-password list is the server's); Enter in the first field moves to the second; no
  `maxlength` (a browser would silently cut a longer paste, and the .zip would be encrypted with a password nobody saved): a value
  over 99 characters is refused at once with "Use at most 99 characters.";
- **Generate a strong password** (20 characters of 61, ≈ 118 bits, longer when the minimum asks for it): it fills both fields and a
  read-only copyable field, and the upload waits until **I've saved this password** is ticked (the copy button ticks it);
- a note that FileParcel does not keep the password and that names inside the .zip stay visible, and a collapsed *Which apps can
  open it?* for the chosen method.

The password lives only in those inputs (cleared when the dialog closes, however it closes) and in the body of
`POST /upload-batches`: the engine drops its copy as soon as that body is built, never writes it to web storage (the resume record
keeps `zipEncryption` only; resuming needs no password) and never declares a protected batch again without the dialog. When the
server refuses the password or the method (422 on `zip_password`/`zip_encryption`), nothing exists on the server yet: the batch is
dropped from the queue without an "Upload failed" toast and the dialog **re-opens** with every choice kept and the server's message
under the field; a refused ZipCrypto (boot data older than the setting) leaves AES-256 selected, and later dialogs of the page no
longer offer ZipCrypto; a refused length ("… at least N characters long", `storage.zip_password_min` raised since the page loaded)
makes N the minimum of the re-opened dialog and of later ones on the page (help text, checks, generator). The queue shows a lock and "(encrypting)" while the job runs, the success toast says "(password-protected)"
when the job really encrypted something.

Phones (< 640 px, bottom sheet with a scrolling body): every control full width, 44 px targets (cards, show/hide, copy, the tick,
`<summary>`, switches), fields ≥ 16 px on touch screens (`--fp-input-min`, so iOS does not zoom). No page sets `interactive-widget`,
so the on-screen keyboard overlays the fixed sheet and `dvh` does not change. The upload dialog uses the keyboard handling every
bottom sheet has (`components/dialog.js` `keyboardInset()`): while the dialog is open on a coarse pointer it computes, on
`visualViewport` `resize`/`scroll` and on focus changes, the loss `innerHeight − visualViewport.height − visualViewport.offsetTop`.
That loss only counts as a keyboard while a text field of the sheet has the focus, the page is not zoomed (`scale` < 1.05) and it is
at least 200 px: browser toolbars (Safari's and Brave's bottom bar, the floating bar of iOS 26) and pinch zoom also shorten the
visual viewport, and taking them for a keyboard lifted every sheet and squeezed its body to a sliver on iPhones. A keyboard sets
`--fp-kb` (the sheet is lifted by it), `--fp-vvh` (it fits into 92 % of the visible height) and `data-kb` (compact head, actions
side by side); otherwise the sheet stays at the bottom with its normal `max-height: 92dvh`. A field focused while the keyboard
opens is scrolled into view once the viewport has settled.

Badges: a labelled lock after the name in the file list and grid (`zipProtectionLabel`: "Password-protected .zip (AES-256)" or
"(ZipCrypto, weak)", also in the row's accessible name), "Protection: Password · AES-256" (or "Password · ZipCrypto (weak)") in the
details panel and a lock on protected versions; the public share page shows the lock (file and folder links) and, for a link to one
protected .zip, "This .zip is password-protected. Ask {owner} for the password."; the link dialog of such a file explains that the
.zip has its own password, to be sent separately, and that "Require a password" is a different lock.

### 13.7 PWA
`manifest.webmanifest`: `display: standalone` (no `window-controls-overlay`: the shell has no title-bar layout), theme colours, icons,
shortcuts (Upload, Shared), `share_target` (files only; POST multipart to `/share-target`, handled by the service worker which stores
the files in IndexedDB-free memory hand-off and opens the upload dialog — read before the first page mounts, so a guest's redirect to
`/shared` keeps it; a share without files, a link or text, says that only files can be shared).
`/sw.js` (served from root with `Cache-Control: no-cache`, build hash templated in): cache-first for `/static/<hash>/*`, network-first
app shell with offline fallback page; never caches `/api`, `/s/`, content downloads. PWA install and SW require a trusted certificate —
explained on `/settings/devices`.

### 13.8 Network page: remote access
`/admin/network` (`pages/admin/network.js`) shows two full-width cards after "Access addresses", built by
`pages/admin/network-remote.js` from `NetworkOverview.ingress` (the cached `IngressStatus`, §10.6) and redrawn when the page reloads
on `ingress.changed`, `network.changed` or `mdns.changed`:
- **Internet access (Tailscale Funnel)** (`#funnel`, the target of the doctor's links): a state badge (Off, Active, Stopped, Needs
  attention for drift/conflict/error, Unavailable, Paused); while active the internet address as copy field and a QR button. The mode
  as choice cards: Off; Share links only (badge "Recommended"); Full app, sign-in required (with the two-factor warning). Without a
  usable Tailscale the reason and the alternatives (Tailscale's control server, or a reverse proxy with ACME and
  `server.trusted_proxies`) replace the choice. `<details>` **Advanced**: the public port (443/8443/10000; a port the tailnet policy
  does not allow, FileParcel's own port and Serve's port are disabled with the reason); "Allow administration over Funnel" and
  "Require two-factor sign-in over Funnel" (full app only; administration needs two-factor sign-in; turning two-factor off or
  administration on is disabled, with the title "Only an owner or administrator can change this", for accounts that are not a
  built-in owner or administrator — the server refuses it with 403 anyway); the `funnel.backend`/`funnel.backend_port`
  settings form, saved on its own. The checklist shows failing and warning checks (label, message, hint, and a "How to fix" button
  for an `https://` `fix_url` of at most 512 characters, `target=_blank rel="noopener noreferrer"`) and folds the others ("13 of 14
  checks passed"). Buttons: Test again (`GET …/tailscale?refresh=1`), Re-apply (drift, conflict, error), Save. Footer: last public
  request or "No public request yet — public DNS can take up to 10 minutes.", the limits of the reachability test, "No router or
  firewall change is needed", and the serve entries of other programs (folded; those that reach FileParcel directly are flagged).
- **Saving Funnel:** widening (off → shares|app, shares → app) first asks "Publish on the internet?" (danger styling, button
  "Publish", what becomes public at which address); weakening (two-factor off, administration on) asks for the typed word `public`;
  the `PUT` then carries `confirm:"public"`; step-up comes from `core/api.js`. Turning Funnel off asks a plain confirmation. A 412
  highlights the check row named by `field` and scrolls to it; 409/422 on `port` marks the port field, 422 on `allow_admin` the
  switch; other errors appear as an alert in the card; a cancelled step-up shows nothing.
- **Tailnet address without port (Tailscale Serve)** (`#serve`): a switch, the tailnet port (1–65535), the address while active, the
  checks and the same buttons; turning it on asks a plain confirmation (no typed word).
- **Warnings on top:** Funnel in `app` mode and active (the whole app is on the internet; whether administration is allowed there),
  and every `exposures[]` entry, most severe first (`fail` → danger, `warn` → warning, `info` → info; titled by id, e.g.
  `tailscale.bypass` "Tailscale forwards to FileParcel directly", with the removal command in the hint).
- **Interfaces by role** (§10.1): "VPNs that reach this server" (mesh, unknown), "Local networks", "Public overlay" (with its
  warning), "Outgoing-only VPNs" (egress, access; folded, "Other devices cannot reach this server through these, so they are not
  offered as addresses or allowed networks.") and "Other" (folded; also a mesh/unknown interface without a usable address, such
  as macOS's link-local-only utun0–utun3, which `vpns[]` leaves out too). Rows show the label, the provider when the label does not name
  it, the detail ("carries the default route"), an "Override" badge, the VPN's policy state (Allowed / Partly allowed / Not allowed)
  and note, and a role menu (not for loopback): "Devices can reach this server through it" (→ mesh), "Outgoing only" (→ egress),
  "Automatic" (entry removed); it reads `GET /admin/settings?section=network` and `PATCH`es `network.iface_roles` (step-up).
  The policy editor's quick-add buttons are the local subnets by the installer's rule (`DefaultAllowlist`: no link-local
  ranges, no public IPv4 subnet and no global IPv6 prefix of an interface with a public IPv4 address, host addresses stay host
  addresses), one button per `vpns[]` entry with `can_allow` and `allowed ≠ yes`
  (all its ranges; an overlay asks first; hidden in "Private networks" mode when the private ranges cover them) and the client
  address; the VPNs' warnings and the notes of VPNs without a range follow in small print. The Tailscale card names a guessed
  Headscale and, for a MagicDNS name outside `.ts.net`, asks `GET /admin/certs` (silently skipped without `certs.manage`) whether the
  local certificate covers it. The dashboard's Network tile counts up interfaces of role mesh/unknown with a usable address as VPNs.
- **Elsewhere:** `components/settings-form.js` shows managed keys (`SettingView.managed`) read-only with a "Managed on the Network page"
  badge and a link to `#funnel` or `#serve`, and never sends them; the share dialog's "link created" step adds "Anyone with this link
  can open it from the internet (Tailscale Funnel)." (icon `globe`) while `features.internet_links` is on (`/me` first, the boot data
  otherwise); the login page adds the two-factor notice over Funnel `app` (boot `ingress` + `features.funnel_2fa`).
- **Phones (< 640 px):** the cards stack, a mode's "Recommended" badge moves under its name, a fix link under its check, and the
  buttons share the row; no horizontal overflow at 320 px and 44 px touch targets with Advanced open (`tests/ui/test_mobile.py`).

---

## 14. Install, uninstall, services, Docker

### 14.1 `install.sh` (POSIX sh, repo root and release-zip root)
1. Parse flags (pass-through to `fileparcel install`): `--dir --port --http-port --name --service user|system|none --boot|--no-boot
   --admin --admin-password-file|--admin-password-stdin|--generate-password --admin-email --sealed --passphrase-file --access --allow CIDR
   --symlink PATH|--no-symlink --from-source --binary PATH -y|--non-interactive --upgrade --dry-run -h|--help`.
2. Detect OS/arch: `uname -s` → linux/darwin; `uname -m` → x86_64→amd64, aarch64/arm64→arm64, armv7l/armv6l→arm. Else build from source or fail clearly.
3. Pick binary: `$SCRIPT_DIR/bin/fileparcel-$os-$arch`, verify against `$SCRIPT_DIR/SHA256SUMS` (`sha256sum` or `shasum -a 256`).
   If absent (e.g. running from a git checkout) and `go` ≥ 1.26 is available (PATH or `~/sdk/go*/bin`) → `go build -trimpath
   -ldflags "-s -w -X fileparcel/internal/buildinfo.Version=…"` into a temp dir. `--from-source` forces building.
4. macOS: `xattr -dr com.apple.quarantine` on the chosen binary.
5. `exec "$BIN" install "$@"` (all prompts happen in Go via x/term; `-y` accepts defaults).

### 14.2 `fileparcel install` (Go, idempotent)
1. Defaults: dir — Linux root `/opt/fileparcel`, Linux user `~/.local/share/fileparcel`, macOS root `/usr/local/fileparcel`, macOS user
   `~/Library/Application Support/FileParcel` (not `~/Documents` — TCC prompts for launchd jobs); service — root → system, user → user,
   none on Linux without `systemctl` or where systemd is not the running init (no `/run/systemd/system`, sd_booted; an explicit
   user/system kind is then an error); ports 8443/8080 (free-port check; suggests next free); boot — yes; admin — `admin`, generated password (shown once, `must_change`);
   access — allowlist with detected LAN/VPN subnets. All inputs the initialisation checks (server name as a DNS label, the owner
   password by the default password policy, the e-mail) are checked before the plan, so `--dry-run` is a reliable preview; a note
   about a replaced default port stays only when that port is used; `boot` is recorded false without a service; `--dry-run --service
   system` as a normal user prints root's plan with the note that it needs `sudo`; `--access any` is explained in the plan, warned
   about in the summary, and its firewall hint opens the ports to any source only (no redundant per-network rules).
2. If `<dir>/fileparcel.toml` exists → **upgrade**: metadata backup (trigger `pre-upgrade`), stop service, `bin/fileparcel` →
   `bin/fileparcel.prev`, atomic copy of the new binary, run migrations via start, health-check `https://127.0.0.1:<port>/healthz`
   (pinned to the local CA) for 30 s; on failure (the start itself failing, an unhealthy server, or Ctrl-C during the check) restore
   `.prev` and restart. `VERSION`, `docs/` and `uninstall.sh` are refreshed only after the health check passes, so a rolled-back upgrade
   leaves them describing the binary that is actually in `bin/`. A home without `installed.json` (made with `init`), or whose record
   is marked incomplete (`uninstall --keep-data`, an install that failed after step 3) or names another directory (a moved home), is
   repaired: service account and ownership (system installs), symlink and service registration are set up from the install options
   (the symlink checked as in step 4 before anything changes; `--no-start` registers without starting). The same release again
   (identical bytes, or the same version and commit per `VERSION`; never `dev`) is "already installed": no backup, no swap, so
   `bin/fileparcel.prev` keeps the previous version. An older release (vN < installed vM) is refused unless `--force` (the database
   may already carry a schema it refuses) and then warned about. `--dry-run` turns the refusals "a server started by hand uses the
   home" and "older release" into `Blocked:` notes of the printed plan.
3. Fresh: create layout (§3 modes), copy binary + `uninstall.sh` + `docs/` + `VERSION`, run `init` logic in-process (MK, DB, keyring,
   CA, client CA, leaf, settings defaults, network policy, owner account, backup identity). When a later step fails, the summary with
   the credentials shown once is still printed and `installed.json` is written marked incomplete; a service account created before a
   failed `init` step is removed again. `uninstall.sh` and `docs/` (also on upgrade) come from `--source`, `$FILEPARCEL_INSTALL_SOURCE`
   (install.sh), the extracted release zip, or the unpacked release around the binary whose `SHA256SUMS` lists the binary and
   `uninstall.sh` with matching hashes (files owned by root, the caller or the binary's owner) — never from any other directory next
   to the binary.
4. Symlink: root → `/usr/local/bin/fileparcel`; user → `~/.local/bin/fileparcel` (create dir). Never replace a foreign file/link
   without `--force`; warn if the dir is not on PATH.
5. Service via `svc` (§14.3–14.5); record everything in `service/installed.json` (`kind`, unit path, `linger_enabled_by_us`, symlink,
   created user, version, installed_at, the firewall hint inputs).
6. Firewall hints: detect ufw (`/etc/ufw/ufw.conf ENABLED=yes`), firewalld (`firewall-cmd --state`), nftables, macOS socketfilterfw;
   print exact commands, e.g. `sudo ufw allow from 192.168.1.0/24 to any port 8443,8080 proto tcp` and
   `sudo ufw allow in on tailscale0 to any port 8443 proto tcp` (UDP 5353 only for the builtin mDNS responder).
7. Summary: URLs per interface with terminal QR code, CA fingerprint, `/trust` URL, admin username + generated password (once),
   Tailscale operator hint when relevant, next steps.

### 14.3 systemd user unit (`<HOME>/service/fileparcel.service` → `systemctl --user link` + `daemon-reload` + `enable` (boot) + `start`; `loginctl enable-linger $USER` when boot)
```ini
[Unit]
Description=FileParcel file sharing server
Documentation=file://<HOME>/docs/FILEPARCEL.md
After=network-online.target
Wants=network-online.target
[Service]
Type=notify
NotifyAccess=main
ExecStart="<HOME>/bin/fileparcel" serve --home "<HOME>"
Restart=always
RestartSec=2
TimeoutStopSec=40
WatchdogSec=60
UMask=0077
NoNewPrivileges=yes
LimitNOFILE=65536
[Install]
WantedBy=default.target
```
Set `XDG_RUNTIME_DIR=/run/user/$UID` (and `DBUS_SESSION_BUS_ADDRESS`) when invoked without a login session.
The user manager makes the `link` itself, in the configuration directory of its own environment: the registration is looked for
there (from `systemctl --user show -p UnitPath`; `~/.config/systemd/user` when it cannot be asked), never under the CLI's
`$XDG_CONFIG_HOME`.
Boot off (`--no-boot`, `disable-boot`) runs `systemctl --user disable` and then `link` again: `disable` removes every symlink to the
unit file, the `link` registration included.
No `TimeoutStartSec`: while `serve` applies a scheduled restore and opens/migrates the database (before `READY=1`) it keeps
extending the default start timeout with `EXTEND_TIMEOUT_USEC` and a `STATUS=` line (`server.ExtendStartTimeout`), so a
large restore is not killed half-way; the rest of the start up to `READY=1` keeps the default bound.
`TimeoutStopSec=40` bounds the stop: `serve` drains HTTP for up to 30 s while the job runner stops in parallel (jobs still running
after 25 s are cancelled), then closes the services, and only then writes `run/clean-shutdown` and removes the PID file — a stop
killed half-way is reported as unclean at the next start.

### 14.4 systemd system unit (root install) adds
`User=fileparcel Group=fileparcel`, `AmbientCapabilities=CAP_NET_BIND_SERVICE` + `CapabilityBoundingSet=CAP_NET_BIND_SERVICE` (only if a
port < 1024 when the unit is rendered — `service install` renders it for the ports in fileparcel.toml, upgrades for those in
`installed.json` — so moving to or from such a port needs `sudo fileparcel service install --start`, not just a restart), `ProtectSystem=strict`, `ReadWritePaths=<HOME>`, `ProtectHome=read-only` (or `no` if HOME is under /home), `PrivateTmp=yes`,
`PrivateDevices=yes`, `ProtectKernelTunables=yes`, `ProtectKernelModules=yes`, `ProtectKernelLogs=yes`, `ProtectControlGroups=yes`,
`RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK`, `RestrictNamespaces=yes`, `LockPersonality=yes`,
`MemoryDenyWriteExecute=yes`, `SystemCallArchitectures=native`, `SystemCallFilter=@system-service`, `WantedBy=multi-user.target`.
Creates `useradd --system --home-dir <HOME> --shell /usr/sbin/nologin fileparcel` (or `adduser -S` on Alpine). HOME itself is
`root:fileparcel` 01770, `bin/` (0755) and `uninstall.sh` are root-owned, the rest is owned by fileparcel (also for the launchd
daemon): root runs `bin/fileparcel` and `uninstall.sh`, and the sticky bit keeps the service account — which must write in HOME
(`fileparcel.toml`, restores) — from renaming or replacing them; `EnsureLayout` leaves that HOME mode alone and upgrades re-apply it.
Root gives the tree to the account (install, `service install --system`) through directory descriptors — `openat` with `O_NOFOLLOW`
and `fchown` on the opened file, never a path resolved again — because the account can swap entries for symlinks meanwhile; symlinks,
special files and files with several hard links the account does not already own are left alone.
`installed.json` belongs to that account too (rewritten by root on upgrade or `uninstall --keep-data`, it is given back to it).
The system unit/plist runs only as `fileparcel`/`_fileparcel` whatever `installed.json` (writable by that account) says, and
`--remove-user` deletes no other account. The unit file is copied to `/etc/systemd/system/fileparcel.service`. The server can write only
below HOME (`ProtectSystem=strict`, `PrivateTmp`): a `backup.copy_to` outside HOME needs a drop-in (`systemctl edit fileparcel`:
`[Service]` `ReadWritePaths=<dir>`, the directory writable by fileparcel; drop-ins survive the installer's rewrites of the unit), and
the uninstaller copies the final backup itself.

### 14.5 launchd
Agent `~/Library/LaunchAgents/com.fileparcel.server.plist` (copied; launchd ignores symlinked plists) or daemon
`/Library/LaunchDaemons/com.fileparcel.server.plist` with `UserName=_fileparcel` (role account via `dscl`, free UID in 400–499).
Keys: `Label`, `ProgramArguments [bin, serve, --home, HOME]`, `EnvironmentVariables{FILEPARCEL_HOME}`, `RunAtLoad`=boot choice,
`KeepAlive{SuccessfulExit=false}`, `Umask 63`, `SoftResourceLimits{NumberOfFiles 65536}`, `StandardOutPath/StandardErrorPath
<HOME>/logs/launchd.{out,err}.log`, `WorkingDirectory HOME`, `ExitTimeOut 40` (the 30 s drain, like `TimeoutStopSec`),
`ProcessType Background`. Control: `launchctl bootstrap|bootout|kickstart -k gui/$UID/com.fileparcel.server` (daemon: `system/…`);
every bootstrap is preceded by a best-effort `launchctl enable` (clears a disabled override of older versions). `SuccessfulExit`
implies `RunAtLoad`, so the job runs whenever the plist is loaded: the boot switch is where the plist lives — in
LaunchAgents/LaunchDaemons (loaded at login/boot) with boot on, else in `~/Library/Application Support/com.fileparcel.server/`
(daemon: `/Library/Application Support/com.fileparcel.server/`, root-owned, outside HOME), which launchd never loads by itself
(`bootstrap` takes any path). `enable-boot`/`disable-boot` move the plist and never run `launchctl disable`, which would survive and
make a later `start` fail. `install` without `--start` re-loads a job that was already running and otherwise loads nothing without
boot.

### 14.6 `uninstall.sh` / `fileparcel uninstall`
`uninstall.sh` locates HOME (`--dir`, else its own directory when it contains `fileparcel.toml`, else `$FILEPARCEL_HOME`, the
`fileparcel` symlink target and the default install locations including `$XDG_DATA_HOME/fileparcel` — several installations found are
listed and it stops: `--dir` chooses) and runs `"$HOME/bin/fileparcel" uninstall "$@"`; fallback when the binary is missing:
stop/disable the service with systemctl/launchctl (only a unit/plist whose `--home` is exactly HOME) and remove the symlink manually.
The service registration and the symlink name HOME as the installer was given it; when `installed.json` records another path to the
same directory (a symlinked component such as `/opt` → `/var/opt`, while `uninstall.sh` and a run through the symlink see the physical
path), that recorded path is used to recognise them (`svc.RegisteredHome`; also by `upgrade` and `fileparcel service`), the files
through HOME. `fileparcel uninstall`: confirm (unless `-y`); a server started by hand (`run/fileparcel.pid` names a live
`fileparcel` process holding the home lock, not the service) is stopped with SIGTERM like the shell fallback does, a process
holding the lock that cannot be identified is named in the plan and the summary (and refuses `--purge` before anything changes;
`--purge` takes the home lock right after the servers are stopped, before the linger, the symlink and the keys change); optional final backup
(`--final-backup`, `--backup-to DIR` outside HOME — which `--final-backup` combined with `--purge` requires, since a backup left in HOME
would be deleted with it; `--purge` alone makes no backup: the server makes the backup, the uninstaller copies it into DIR
— created if missing — and verifies it; any failure stops before anything is removed); stop + disable + unlink the service (`bootout`
for launchd), refusing without changes when the recorded service cannot be managed by this user; disable linger only if the
installer enabled it and no other user units remain enabled; remove the symlink only if it points into HOME; `--keep-data` (default)
leaves HOME without the service and marks `installed.json` incomplete, so the next `install` on HOME registers the service and symlink
again; `--purge` overwrites every file under `keys/` and `certs/` — and their copies in `pre-restore-*/` and crashed restore/verify
staging — with random bytes (SSD caveat printed) then removes HOME behind guards (marker present; HOME not `/`, `$HOME`, `/usr`,
`/etc`, `/var`, `/opt` itself, the per-user shared directories such as `~/.local/share`, `~/Library/Application Support` and the
`$XDG_*_HOME` directories, etc.; the same list refuses them as an install directory); `--remove-user` deletes the system account; prints firewall rules to remove (including the
open-to-everyone rule of access mode `any`, recorded in `installed.json`).

### 14.7 Docker
```dockerfile
# syntax=docker/dockerfile:1
FROM --platform=$BUILDPLATFORM golang:1.27.1 AS build
ARG TARGETOS TARGETARCH VERSION=dev COMMIT=unknown
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -trimpath \
    -ldflags "-s -w -X fileparcel/internal/buildinfo.Version=$VERSION -X fileparcel/internal/buildinfo.Commit=$COMMIT" \
    -o /out/fileparcel ./cmd/fileparcel
FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/fileparcel /usr/local/bin/fileparcel
ENV FILEPARCEL_HOME=/data
VOLUME /data
EXPOSE 8443 8080
USER 65532:65532
HEALTHCHECK CMD ["/usr/local/bin/fileparcel","healthcheck"]
ENTRYPOINT ["/usr/local/bin/fileparcel"]
CMD ["serve","--init-if-missing"]
```
`--init-if-missing` uses `FILEPARCEL_ADMIN_USER`, `FILEPARCEL_ADMIN_PASSWORD_FILE` (else generates a password and logs it once).
`docker-compose.yml`: `network_mode: host` (mDNS + real client IPs; Docker Desktop users switch to `ports:`), env as above,
`./fileparcel-data:/data` (chown 65532 first), optional `/var/run/dbus/system_bus_socket` (Avahi) and
`/var/run/tailscale/tailscaled.sock` (LocalAPI certs) mounts, `secrets: [fp_admin_password]`, `read_only: true`, `cap_drop: [ALL]`,
`security_opt: ["no-new-privileges:true"]`, `restart: unless-stopped`, `stop_grace_period: 40s`.

---

## 15. Release hook (vN zips)

`git config core.hooksPath .githooks` (documented in DEVELOPMENT.md; `make hooks` sets it). `.githooks/post-commit`:
```sh
#!/bin/sh
[ -n "$FILEPARCEL_NO_RELEASE" ] && exit 0
[ -n "$FILEPARCEL_RELEASING" ] && exit 0
gd=$(git rev-parse --git-dir)
{ [ -d "$gd/rebase-merge" ] || [ -d "$gd/rebase-apply" ] || [ -f "$gd/CHERRY_PICK_HEAD" ]; } && exit 0
FILEPARCEL_RELEASING=1 exec sh "$(git rev-parse --show-toplevel)/scripts/release.sh" --from-hook
```
`scripts/release.sh`:
1. **N**: HEAD already tagged `v[0-9]+` → reuse (idempotent rebuild). Amend (`git reflog -1 --format=%gs` starts with `commit (amend)`)
   and `HEAD@{1}` carried `vK` → reuse K (`git tag -f`, delete the old zip). Otherwise N = 1 + max existing `v[0-9]+` tag (0 if none).
   First commit → **v1**; numbers never go backwards.
2. Lock with `mkdir releases/.lock` (portable) + trap cleanup.
3. `git archive HEAD | tar -x -C releases/.stage/fileparcel-vN/src` — builds exactly the committed tree. A commit that contains a
   FileParcel home or secret (`server/`, `fileparcel-data/`, `secrets/`, `fileparcel.toml`, any `keys/master.key`) is refused.
4. `scripts/build.sh` cross-compiles in parallel from `src/`: linux/amd64, linux/arm64, linux/arm (GOARM=7), darwin/amd64, darwin/arm64 with
   `CGO_ENABLED=0 GOTOOLCHAIN=local go build -trimpath -buildvcs=false -ldflags "-s -w -X fileparcel/internal/buildinfo.Version=vN
   -X …Commit=<sha12> -X …Date=<commit ISO date>"`. Uses `scripts/env.sh` to find Go (PATH, or `~/sdk/go*/bin` when the PATH one is missing or older than 1.26). No usable Go → warn, exit 0.
5. Stage: `README.md LICENSE NOTICE VERSION SHA256SUMS install.sh uninstall.sh docker-compose.yml docs/ bin/fileparcel-<os>-<arch> src/`
   (the top-level `docker-compose.yml` builds from `context: src` and tags the image vN; no top-level Dockerfile);
   mtimes set to the commit time; `zip -r -X -q releases/fileparcel-vN.zip fileparcel-vN` (exec bits preserved);
   `releases/fileparcel-vN.zip.sha256`.
6. `git tag -a vN -m "FileParcel vN" HEAD`. Log to `releases/.logs/vN.log`; clean the stage.
7. `RELEASE_KEEP=N` prunes older zips (default keep all). `FILEPARCEL_RELEASE_ASYNC=1` backgrounds the build.

---

## 16. Work breakdown (parallel units with strict directory ownership)

Stage 0 **Foundation** (blocking): Go toolchain + git + go.mod with all deps (`internal/depsguard` blank imports until
integration, where the integrator deletes it and runs `go mod tidy`);
complete `buildinfo home config ids crypt events db(+0001) core app web/httpx web/router.go wire cmd/fileparcel cli/root.go cli/client.go`
and `web/embed.go`, `web/templates/app.html`, `web/static/js/{app,routes,nav}.js`, `web/static/js/core/*`, minimal working
`web/static/js/components/*`, `web/static/css/*` baseline; stubs for every other package with final signatures
(`New(...)` + methods returning `core.ErrNotImplemented`; API packages with empty `Mount`); `mw` with working signatures; minimal
`audit` (plain insert), `ratelimit` (allow-all), `settings` (Register/Def + in-memory store); `docs/DEVELOPMENT.md` (ownership table,
rules). Gate: `go build ./... && go vet ./... && go test ./internal/{db,crypt,home,config,ids}/...`.

Stage 1 **Units** — nobody edits `core`, `db` (except adding their own `_test.go`), `app`, `wire`, `web/router.go`, `web/httpx`, `go.mod`/`go.sum`,
`cmd/`. Needed shared changes go into the unit's final report ("REQUESTS").

| Unit | Owns (exclusive) |
|---|---|
| A Crypto & storage | `internal/keys`, `internal/blobstore` |
| B Auth | `internal/auth`, `internal/ratelimit`, `internal/web/authapi`, `internal/web/meapi` |
| C Users & audit | `internal/users`, `internal/audit`, `internal/notify`, `internal/web/usersapi` |
| D Files | `internal/files`, `internal/ziputil`, `internal/thumbs`, `internal/web/filesapi` |
| E Uploads & shares | `internal/uploads`, `internal/shares`, `internal/web/uploadapi`, `internal/web/sharesapi` |
| F TLS & server | `internal/certs`, `internal/server`, `internal/web/securityapi` |
| G Network & settings | `internal/netinfo`, `internal/mdns`, `internal/qr`, `internal/settings`, `internal/web/settingsapi` |
| H Ops | `internal/jobs`, `internal/backup`, `internal/web/opsapi` |
| I Platform & CLI | `internal/web/mw`, `internal/web/static`, `internal/web/pages`, `internal/cli` (incl. root.go/client.go after hand-off), `internal/svc` |
| J1 Frontend core & files | `web/static/css/**` (except `css/pages/{settings,admin,auth,share}.css`), `web/static/js/{app.js,routes.js,nav.js}`, `js/core/**`, `js/components/**`, `js/upload/**`, `js/preview/**`, `js/pages/{files,shared,links,requests,starred,recent,trash,activity,search}.js`, `web/templates/app.html`, `web/static/manifest.webmanifest`, `web/static/sw.js`, `web/static/icons/**` |
| J2 Frontend admin & public | `web/static/js/pages/settings/**`, `web/static/js/pages/admin/**`, `web/static/js/public/**`, `web/static/css/pages/{settings,admin,auth,share}.css`, `web/templates/{login,invite,setup,unlock,trust,share,error}.html` |
| K Packaging & docs | `install.sh`, `uninstall.sh`, `scripts/**`, `.githooks/**`, `Dockerfile`, `docker-compose.yml`, `.dockerignore`, `Makefile`, `README.md`, `LICENSE`, `NOTICE`, `docs/{FILEPARCEL,INSTALL,COMMANDS,SECURITY,ENCRYPTION,THIRD_PARTY}.md`, `docs/images/**`, `tests/e2e/**`, `tests/smoke/**` |

Unit rules: keep your packages compiling (`go build ./...` must pass before you finish); test only your packages
(`go test -race ./internal/<pkg>/...`); fakes live in `_test.go`; emit audit actions from §9.6; register your settings (§11.2);
never commit; never edit files you don't own.

Stage 2 **Integration** → Stage 3 **Verification** (E2E, UI, security) → Stage 4 **Install on the maintainer's machine** → Stage 5 **Docs + v1 commit**.

---

## 17. Test & verification plan
- **blobstore**: sizes {0, 1, 65535, 65536, 65537, 8 MiB±1, 3×8 MiB+5, random ≤ 64 MiB}; `FuzzReadAt`; every segment boundary via
  `ServeContent` Range incl. multi-range; tamper (bit flip per segment, truncation, extension, segment swap, blob swap, header edit, wrong DEK)
  → error; parallel out-of-order parts with retries; ChaCha path; allocation benchmark.
- **keys**: plain/sealed round-trip; wrong passphrase; recovery-key unlock; KEK rotation over 10k DEKs; master rotation crash recovery
  (`.next` present); field AAD binding (row swap fails); locked state blocks.
- **auth**: PHC encode/verify/rehash; idle/absolute expiry (fake clock/synctest); lockout backoff; RFC 6238 vectors, ±1 step skew, replay of
  same step rejected; recovery single-use; PAT scopes; CSRF (cross-site POST blocked, missing token blocked, Bearer exempt).
- **files**: name-validation table (NFC/NFD, case conflicts, 255-byte limit); move-into-descendant rejected; permission matrix (owner/group
  manager/member/editor grant/viewer grant/guest/stranger/admin-without-access); trash name conflicts; FTS substring search; Walk ordering.
- **ziputil**: empty dirs; unicode; duplicates; store/deflate; zip64 with 4.5 GB synthetic zero reader parsed back; cancellation.
- **uploads**: out-of-order parts, idempotent retry, digest mismatch, conflicting re-send (409), quota reservation/release, expiry, small path,
  zip-on-upload readable with paths preserved, file-request limits.
- **shares**: expiry, disabled, max_downloads under concurrency, password rate limit, cookie bound to password_version.
- **certs**: CA name constraints; leaf verifies for `fileparcel.local`, IPs, ts.net name; SAN-change reissue; p12 round-trip; SNI dispatch;
  mobileconfig parses.
- **netinfo**: classification table over fake interface lists; IPv4-mapped normalization in the matcher.
- **mdns**: builtin responder on loopback answers A and PTR/SRV; Avahi test gated by `FILEPARCEL_TEST_AVAHI=1`.
- **backup**: create → verify → restore into temp home; row and blob equality; wrong identity fails; GFS selection table.
- **settings**: validation, secret masking, events, TOML round-trip.
- **svc**: golden files for units and plists.
- **Integration** (httptest + real TLS): login+TOTP flow; upload (parts→complete) → download + Range (206 bytes equal) → seek; folder zip via
  `archive/zip.Reader`; share anonymous download; member → admin route 403; **route-protection sweep** (`chi.Walk`: every non-public route
  401 anonymously, cross-site POST 403); **header sweep**; static caching & compression negotiation.
- **E2E** (`tests/e2e/e2e.sh`, curl + python3 stdlib): temp home, free port, `--resolve fileparcel.local:PORT:127.0.0.1 --cacert ca.crt`;
  login + CSRF; enroll TOTP and re-login; 50 MB parallel-part upload + sha256 + Range slices vs `dd`; folder upload with nested/empty dirs;
  zip-on-upload; zip download `unzip -t`; share link (password, max-downloads); CLI `config set` via socket reflected in API; backup
  create/verify; `keys rotate --kek`; seal → restart → 503 → unlock → download OK; HTTP→HTTPS 308 (both ports); `evil.html`/`evil.svg`
  served as attachment; TLS 1.1 rejected (`openssl s_client -tls1_1`).
- **Playwright** (`tests/ui`, venv in scratch/`tests/ui/.venv`): Chromium (fallback `executable_path=/usr/bin/brave-browser`), args
  `--host-resolver-rules=MAP fileparcel.local 127.0.0.1` + `--ignore-certificate-errors-spki-list=<b64 sha256 SPKI>`; viewports 1440×900,
  Pixel 7, iPhone 14; light+dark; flows: login, TOTP enroll (QR visible), virtual passkey (CDP WebAuthn), create folder, `set_input_files`
  for files & a directory, upload completes, image/video preview, share dialog QR, share page in fresh context, every admin page renders,
  mobile bottom nav/sheet/long-press. Fail on console errors, CSP/Trusted-Types violations, horizontal overflow, tap targets < 40 px.
  Screenshots → `tests/ui/screenshots/` (gitignored; the handful committed for README.md live in `docs/images/`).
- **Live smoke** (`tests/smoke/run_all.sh`, bash + python3 stdlib; `make smoke`): a fresh `init`ed home on 18443/18080, then 11 phases
  (auth, users, files, shares, admin, pages, the CLI over the admin socket, sealed, rest, destructive, maintenance) driven over real
  HTTPS, with a local SMTP sink for e-mail; `coverage.py` then reports mounted-route coverage from the access log (§20.1). Overrides:
  `FP_SMOKE_DIR` (needs ≥ 1.5 GiB free), `FP_PORT`/`FP_HTTP_PORT`, `FP_HOST` (the suite pins `tls.extra_sans` and `auth.webauthn_rp_id`
  to it, so an mDNS collision rename cannot break the run) and `FP_KEEP_SERVER=1`. The exit status is 0 only when every phase passed.
- **Security checklist**: authz on every handler; IDOR on node/share/job/batch IDs; CSRF; traversal (zip names, share paths, upload
  rel_path); stored XSS (filenames as text, content headers); session fixation; token entropy + constant-time compare; rate limits;
  secrets never logged; allowlist before TLS; socket peer-cred; file modes; argon2 params + semaphore; parameterized SQL only;
  govulncheck clean; zero Trusted Types violations.
- **Feature contracts**: `internal/core/contract_test.go` pins the JSON of every roles/zip/ingress/VPN API type against the golden files in
  `internal/core/testdata/contract/` (and decodes each back with unknown fields refused); `internal/db/migrate_numbering_test.go`
  covers the migration numbering of §6 (no gaps, set-based apply, the name check, an upgrade from a database that carries only 0001);
  `internal/web/mw/requirecap_test.go` checks that `RequireCap` answers like `RequireAdmin` for the built-in roles;
  `tests/docs/contract_docs_test.go` keeps this document in step with the code (every audit action in §9.6, every
  event topic in §5.3, every migration in §6, every `Cap(…)` of §9.4 a real permission).
- **Feature integration** (where the packages meet): `internal/wire/features_integration_test.go` drives one real server with a fake
  tailscaled — a custom role with `network.manage` runs Funnel but cannot weaken its sign-in (403, audited `denied`/`rbac`),
  a delegate without it gets 403 on `funnel.mode` before an administrator's 409 (managed), `ingress.changed` follows the
  permission and a role edit closes the holder's event stream, a guest-based role with an editor grant uploads a
  protected zip whose public link shows `zip_encryption` over Funnel while no session reaches `/api/v1/me` or any roles route
  there, and the doctor names staff without 2FA while administration over Funnel is allowed — plus the upgrade of a database
  that carries only 0001 (§20 gap 11 for the unreleased numbering); `tests/ui/test_feature_integration.py` checks the same from the browser
  (a `netops` delegate's Admin area and locked Funnel switches, a Contractors upload with the lock badge, 320 px light
  and dark).

The feature subsections here and in §18 belong to the later work packages (A roles backend, B roles web UI, C zip
password, D Tailscale Funnel/Serve and VPNs, E command line), not to the units of §16.

### Roles and permissions (A/B)

<!-- packages A (backend) and B (web UI): tests of roles and permissions -->

Backend (package A; §6a):
- **core**: `roles_test.go` (catalog invariants and golden order, `CapSet`, `ParseCaps`, `EffectiveRoleCaps`, the
  `Principal.Can` matrix incl. tokens and literals without `SetCaps`); `escalation_test.go` (`Covers`, the
  `CheckManage`/`CheckAssign` tables for owner, admin, a Helpdesk, an Auditor and the system principal against every
  kind of target, with the exact texts and the `EscalationError` cause).
- **db**: `TestMigration0002` (constraints, triggers, cascades, the view, and `EXPLAIN QUERY PLAN` without table
  scans).
- **auth**: session and token principals carry the role and its permissions and follow a role edit on the next
  request; 2FA for staff roles; `CreateToken` per role (tokens.create, the admin scope, elevated tokens); the
  credential routes for delegates with their denied audit entries.
- **users**: roles CRUD (name rules, limits, `copy_from`, the closure, deleting with `reassign_to` and personal
  files), `role_id` on create, update, invite and accept, the Helpdesk delegation matrix with the exact texts and
  denied audit entries, role → group memberships and effective members with their sources, invitation links per
  caller, and `authz.changed` for every change.
- **files**: role grants at all three levels, the manager level in team folders and personal spaces, access through a
  role's groups, live role changes, and `SubjectGrants` (visibility, `hidden`, `caller_perm`, paths, the 1000-row cap).
- **shares, certs, settingsapi, opsapi, mw**: link and request creation per permission, `shares.manage`, client
  certificates per `certs.manage`, settings per key, jobs per kind, the dashboard parts, the SSE delivery matrix and
  `authz.changed` closing the affected streams, the doctor's staff 2FA check, `RequireCap`, `actAs` and maintenance
  for `system.manage`.
- **usersapi, filesapi, meapi, pages**: every roles route (JSON shapes, errors, step-up, delegates), the access
  preview, `GET /admin/grants`, `GET /roles`, invitation links end to end; `/me` and the page boot agree on the role,
  the permissions, `staff` and the feature flags, and name no role before the second factor.
- **wire**: `routecaps_test.go` (`TestEveryAdminRouteDeclared`, `TestAdminRouteGuards`, `TestPrincipalCapsConsistent`,
  `TestSettingsSectionsHaveCap`), the roles routes in `designRoutes`, and end-to-end runs with the real services
  (`delegation_test.go`, `role_access_test.go`, `roles_api_test.go`).
- **Smoke** (`t02_users.py`): create a role, give it to a new account, sign in as the holder (a staff role enrols a
  second factor first) and reach exactly its admin areas, role → group, a role grant, the access preview and
  `/admin/grants`, delete with `reassign_to`, and the audit entries.

Web UI (package B; §13.2, §13.5):
- **`internal/web/static/perms_test.go`**: every permission name the UI checks (`perm:` of `routes.js`, `can('…')` and
  `canAny([…])` in `routes.js`, `nav.js`, `app.js` and the pages) is a `core.Capabilities` name; `core/perms.js` labels
  all 17 with the catalog labels in catalog order and lists exactly the server permissions and `core.MemberCaps`; the
  built-in role descriptions of `pages/admin/common.js` are `core.BuiltinRoles`'; every `core.Act*` audit action has a
  label on the admin pages, the role-related ones also on the Activity page.
- **`tests/docs/roles_docs_test.go`**: the manual's permission table is the catalog (order, labels, descriptions,
  implied permissions, warnings), its built-in roles table matches `core.BuiltinRoles`, its `role create|edit`
  examples name real permissions, and the texts the manual quotes still exist in the web app and the server; the route
  guard table of §13.2 matches `routes.js`.
- **Playwright** (`tests/ui/test_roles.py`, set-up through the API in `tests/ui/helpers_roles.py`, which the feature
  integration tests reuse): an administrator creates a role on Admin → Roles (step-up), turns on *Manage accounts*
  (*View people* follows), saves and gives it to a new account; a Helpdesk delegate sees Dashboard ("Your admin
  areas", no API call), Users, Groups and Roles only, the "not allowed" page elsewhere without a request, an
  administrator's account read-only with the reason, and only the roles it may give in New user; a role that is a
  member of a group opens the team folder for upload, and the group's page and the role filter of Admin → Users show
  it; a folder shared with a role at *Can manage* can be shared on by its holder; the Access card on desktop and on a
  phone; a live demotion (event stream open) hides the Admin group and shows the toast within 5 s; an invites-only
  delegate gets an admin invitation without its link, and an administrator gets the link of a staff role's invitation
  only through "Show link" (step-up); `/admin/roles`, every tab of a role and the New role sheet at 320 × 640 on both
  phones, light and dark (no overflow, 44 px targets, the save bar above the tab bar, saving works). `test_mobile.py`
  checks `/admin/roles` at 320 px and for 44 px targets.

### Password-protected zips (C)

<!-- package C: tests of password-protected zips -->

- **ziputil** (`encrypt_test.go`, `interop_test.go`, `zip64_test.go`; the independent reader `ziputiltest` has its own 0x9901
  parsing, counter loop and ZipCrypto keys): known-answer vectors (AE-2 entry data with an injected salt, the PBKDF2 key split, the
  little-endian counter at blocks 1, 2 and 2³²+5; ZipCrypto), fixed wrong passwords that collide with the verifier or the check
  byte (→ MAC or CRC failure), round trips of both methods (Store fallback, the UTF-8 flag rule, empty files, times), complete local
  headers, tampering, 1000 distinct salts, a source that changes or is short/long between the passes, pass counts per case, the
  `0xFFFFFFFF` descriptor edge, `New` validation, `AddFileAt` = `AddFile` without encryption, cleared buffers, archives made by
  7-Zip read back, and interop: `7z x` / `unzip -P` **extract and the bytes are compared** (skipped when the tool is absent;
  `7z t` alone passes a wrong keystream for Store entries), a wrong password fails. A 4.5 GiB AES entry checks zip64 through a
  verifying sink (skipped with `-short`; `FP_TEST_BIG=1` also extracts it with 7-Zip).
- **uploads** (`zippassword_test.go`, `realblob_test.go`): every validation rule and `zipProtection` step; the sealed value is
  `v1:`… and opens only with its batch's AAD, and a marker password appears nowhere else (database file and WAL, jobs, audit, events,
  logs, API JSON, `fmt` verbs); the job's .zip reads back with the password (both methods, parted and empty files, UTF-8 names),
  the version is recorded, params stay `{"batch_id"}`; the value is NULL after done, abort, expiry, job failure, cancel, the stuck
  bound and the sweep, and kept across an enqueue error and a re-run; `complete` fails fast (412/500/503, batch open); locked keys
  postpone the job; a batch of folders only is not protected; a cancel stops inside a 20 MiB entry; unprotected jobs are
  byte-identical to before; the real blob store and keyring.
- **files, db, keys, crypt, web**: `zip_encryption` round trips (listings, search, versions, walk, trash, copy of a file and of a
  folder, copy-replace, restore; 422 for other values), the migration's CHECK constraints, KEK rotation re-seals the column and never
  resurrects a value wiped meanwhile, the shared common-password list, 422 on `/s/{token}/api/upload-batches` with either field, the
  boot hints `features.zip_legacy_encryption` and `limits.zip_password_min`.
- **e2e** `t_zip_on_upload_password`: ZipCrypto (`unzip -P`, a wrong password fails) and AES-256 (header checked with python3,
  `7z` extract and compare) through the API; no password in the job or the batch answers.
- **Playwright** `tests/ui/test_zip_password.py`: the dialog's rules, Enter, the generator and its tick, an AES-256 upload whose
  download is checked with `struct` (method 99, flag 1, `0x9901` AE-2) and extracted with 7-Zip byte for byte; ZipCrypto (warning,
  headers, 7-Zip and unzip extraction) and its removal by the setting; nothing in web storage, cookies or IndexedDB, before and after;
  a server refusal re-opens the dialog with its choices; a refused ZipCrypto leaves AES-256 only; the phone sheet at 320 px (no
  overflow, 44 px targets, 16 px fields, lifted by a simulated keyboard, light and dark, Pixel 7 and iPhone 14); the link dialog note
  and the public page's lock and "Ask … for the password".

### Tailscale Funnel, Serve and VPNs (D)

<!-- package D: tests of Tailscale Funnel/Serve and VPN detection -->

- **Safety**: no test reaches the real tailscaled — `tslocal.Default()` has no socket and no CLI under `go test`; tests that need a
  daemon set `FILEPARCEL_TAILSCALE_SOCKET` to a fake (`tslocal/tslocaltest`, Python `tests/ui/fake_tailscaled.py`); the Playwright
  session server, `tests/e2e/e2e.sh` and `tests/smoke` point it at a missing `<work>/no-tailscaled.sock`.
- **tslocal**: status/prefs/`CapMap`/`funnel-ports` parsing, `null` config, byte-for-byte round trip of unknown keys, `Services`,
  `Foreground` and untouched entries, `SetEntry`/`RemoveEntry`/`Conflict` matrices, `If-Match` always sent (empty ETag → nothing
  posted), error mapping, no `Origin`/`Referer`, golden CLI argv (removal `serve … off` for both kinds), timeouts and output limits.
- **tsingress**: the exact config written for off → shares into a foreign config, shares → app without a write, port moves, listener
  closed before the POST, conflict matrix → 409, Serve's foreign `AllowFunnel` removed and audited, bypass matrix, every 412 check,
  the 422 rules, the RBAC weakening cases (a `network.manage` delegate → 403 `denied`), node mismatch, rename, ETag retry, Unix → TCP
  fallback and `funnel.backend_port` persisted, marker states (Start writes nothing; offline enable → `pending` and no POST; Attach
  applies `pending`/`suspended`; missing entries → `drift`; Detach), port clash removal, apply-then-store, probe results and nonces.
- **server / mw / auth / shares / pages / httpx**: ingress header trust (XFF/XFH matrices, probe, policy off), `/proc/net/tcp{,6}`
  parser and peer-uid checks incl. real `SO_PEERCRED`, Attach/Detach around listen and drain, admin-socket and main-listener
  refusals; `IngressGate` shares/app path matrices with byte-equal 404s, cookie stripping, deny list vs full policy, `/64` rate-limit
  keys, in-flight caps, mTLS, sealed, strict host, HSTS; Funnel login without 2FA → uniform 401, no lockout, `auth_funnel_user`;
  `funnel_share_pw`; `internet_links`, `funnel_2fa`, `PublicOnly`; ProxySignals.
- **settingsapi / opsapi**: the four routes and guards, managed keys → 409, `funnel`/`tailscale` sensitive, the overview's
  `ingress`/`vpns`/`exposures`, the Funnel lockout guard (deny list only), the port-clash warning; the doctor's Funnel rows, VPN rows
  (`doctor_vpn_test.go`) and firewall hints by role.
- **netinfo**: every row of the classification table and its negatives (`nm-bridge`, `nm-mynet` without DEVTYPE, `wg0` with and
  without a default route, a default only in a `from`-rule table, Tailscale as an exit node still mesh, nordlynx Meshnet, a darwin
  `utun` with WARP's range, `sdwan0` without Twingate, `tun0` with 200::1, `ppp0` + default, a bridge-port TAP); rtnetlink parsing
  of **dumps captured on the development machine** (`testdata/netlink/*.bin`: its rules 5210–5270 and Tailscale's table 52) and of
  synthetic messages (`FRA_TABLE` > 255, `FRA_SRC`, `FRA_IIFNAME`, uid range, `RTA_TABLE`, `RTA_MULTIPATH`, def1 halves, nexthop
  objects, errors, the message limit); darwin `RTF_IFSCOPE`; the route cache; `network.iface_roles` (validation, URLs, SANs,
  fingerprint, MagicDNS); `offered`/`offeredAddr`, `ipRank` by role; `BuildVPNs`, `DefaultAllowlist`, `covers`; exposures
  (cloudflared config fixtures, command lines, token tunnels, trusted loopback).
- **mdns** selects by role; **svc** installer uninstall step and firewall input by role; **provision** role-aware allowlist.
- **wire**: `funnel_integration_test.go` — a real server against a fake tailscaled: enable → config with `If-Match`; a share over
  the funnel socket with the visitor's address in the log; the admin cookie → 404; deny list → 403; `app` without 2FA → 401 without
  a lockout; the Funnel header on the main listener → 403; disable → socket gone, config restored.
- **Playwright**: `test_funnel.py` (checklist and fix link, enable with "Publish" and step-up, the share dialog's internet notice,
  "Last public request", a file request over the socket, disable restoring the foreign entry, bypass alert + doctor fail),
  `test_vpn.py` (the interfaces by role, the role menu with step-up, the VPN quick-add buttons, the dashboard chip, 320 px light and
  dark against a fixed overview), `test_mobile.py` (the Funnel card with Advanced open at 320 px). Manual only, on the owner's
  machine: `tailscale serve status --json` before/after `fileparcel network funnel enable -y`, a share link opened on a phone off
  Wi-Fi, `/login` not found over Funnel, `network funnel status` Reachable, disable → `{}`.

### Command line (E)

<!-- package E: tests of the command line -->

The command line (§12), tested in `internal/cli` against the fake API of `fakeapi_test.go`, whose role, grant, zip and
Funnel/VPN routes are built from the contract goldens, and in `tests/docs`:
- **Tree and help** (`cli_tidy_test.go`, `cmd_tree_test.go`): `TestEveryCommandDocumented` (Short, Long, 2–5 examples that
  resolve to the command or a descendant without a legacy name, `Use` placeholders), `TestRootHelpGroups`, `TestSubGroups`,
  `TestHelpTopics`, `TestCompactGlobalFlags`, `TestDesignCommandPaths`, `TestExamplesUseRealPermissions`.
- **Old names**: `TestLegacyInvocations` (every command path and alias of the tree before the tidy-up, and the argument sets
  scripts use, land on the canonical command with the canonical flags), `TestLegacyHidden`, `TestLegacyNoticeOnlyOnTTY`.
- **Errors**: suggestions for words and flags, task words, friendly argument errors, not-found and 403 hints, the
  secret-prompt guard (a secret typed after a prompt switch is refused and never echoed), one reader of standard input.
- **Commands**: every command's requests and output against the fake, including roles (`TestRole*`: `--from`, permission
  names checked before any request, `--reassign-to`), access (`TestAccess*`: levels, identity, inherited grants, `check`
  reasons), zip passwords (`TestZipPasswordFlags`: only `POST /upload-batches` carries the password), Funnel/Serve/VPN
  (`TestFunnel*`, `TestVPN*`, `TestTailscaleServeNotServe`) and `TestWhoami*`.
- **Completion** (`TestCompletion*`): static words, server sources over the admin socket and remotely, never offline (no lock,
  no prompt), the 1.5 s bound, no completion function on a secret flag, every `Use` placeholder known to `argSource`.
- **Docs** (`tests/docs/cli_docs_test.go`): `TestCLIReferenceUpToDate` (the generated reference in COMMANDS.md equals the
  program's, and the manual carries none), `TestDocsUseCanonicalCommands` (no old command or flag name in README.md, docs/*.md code, the web scripts, Go
  string literals or the install files), `TestLegacyUseDetection`; clikit's `TestMarkdownHelpTopics` and
  `TestMarkdownGroupedContents`.
- **Smoke** phase 7 (`tests/smoke/t07_cli.sh`) runs the CLI over the admin socket of a live server: the legacy names next to
  the canonical ones, suggestions, `whoami`, completion of user names, roles, access, the VPN list, Funnel status (Tailscale
  absent), a zip upload with a generated password, and a custom role from creation to deletion. e2e restores its backup with
  `backup restore --dry-run`.

---

## 18. Risks & gotchas
1. **WebAuthn RP ID** must be a domain (never an IP); browsers refuse WebAuthn on certificate errors → passkeys work once the CA is
   trusted or on a ts.net name with a Tailscale cert. Default RP ID `fileparcel.local`; changing it orphans passkeys (UI warns; while accounts have no second factor but a passkey,
   the settings API refuses turning `auth.passkeys` off or moving the RP ID — `auth.webauthn_rp_id`, or `mdns.name`/`server.name` while
   it is empty — with 409 unless `?force=1`). The passkey
   UI hides when `location.hostname` isn't the RP ID or a subdomain. Server side, the accepted origins (`auth.webauthn_origins`, empty =
   derived) are the RP ID, `server.public_url` and the other names this server is configured to serve under the RP ID (`network.extra_hosts`,
   `tls.extra_sans`, `acme.domains`), at the HTTPS port and at 443; wildcards, IP literals and names outside the RP ID are skipped.
   TOTP always works.
2. **User services & boot**: without linger the service stops at logout / doesn't start at boot. `systemctl --user` needs `XDG_RUNTIME_DIR`.
3. **mDNS coexistence**: never bind a second responder when Avahi is present; use D-Bus with `NO_REVERSE`. mDNS doesn't cross L3 VPNs.
   Android `.local` support varies → every URL is also shown by IP + QR. macOS: `dns-sd` avoids the Local Network privacy prompt.
4. **Trusting the local CA**: iOS needs profile install **and** the Certificate Trust Settings toggle; Apple requires ≤ 825-day leaves +
   SAN + EKU; Firefox has its own store; HSTS stays off for untrusted certs (auto); SW/PWA need a trusted cert.
5. **ACME**: home servers rarely have public reachability → DNS-01 or `tailscale cert`. LE staging first. ts.net names appear in public
   CT logs. `tailscale cert` needs operator permission and HTTPS enabled for the tailnet. Headscale has no ts.net certs.
6. **Firewall**: ufw on this host drops inbound; nothing is reachable off-box until the user adds rules (installer + `doctor` print them).
7. **Ports**: non-root can't bind < 1024 → URLs carry `:8443`.
8. **SQLite single writer**: one writer conn, `BEGIN IMMEDIATE`, short transactions, never blob I/O inside a write transaction, throttled
   `last_seen_at`, keyset pagination, periodic `wal_checkpoint(TRUNCATE)`.
9. **Big zips**: streaming only (no Content-Length/resume). macOS Archive Utility has trouble with some streamed zip64 → offer tar;
   zip-on-upload temporarily doubles disk use (pre-checked).
10. **Browser folder APIs**: no single picker for mixed files+folders → two buttons + drag&drop; `readEntries` batches; iOS can't pick folders.
11. **Nonce safety**: random per-segment nonces (retries rewrite segments) — keep them random.
12. **Raspberry Pi 4 has no AES instructions** → ChaCha auto; argon2 memory bounded by a 256 MiB process-wide budget
    (4 × 64 MiB password hashes, or 1 × 128 MiB master-key KDF + 2 × 64 MiB — every derivation reserves its own `m`).
    The FIFO queue behind it is bounded for the anonymous request paths (sign-in, share passwords): a check that would be the
    33rd waiter (8 × the 4 slots) fails at once with 503 "busy" instead of queueing, and a waiter whose request is cancelled
    leaves the queue; neither counts as a failed attempt.
    The same applies to every GOARCH for which Go ships no AES/GHASH assembly (386 among them): `auto` must not pick AES there,
    or it selects a table-driven pure-Go AES (§7.7).
13. **Sealed mode + boot**: the service boots locked until someone unlocks it (documented).
14. **HTTP/2 upload throughput**: enlarge per-stream/conn receive windows (`http.HTTP2Config`).
15. **Cookies aren't port-isolated**: other HTTPS services on the same host could receive our cookie (documented; low risk).
16. **IPv4-mapped IPv6** must be `Unmap()`ed before allowlist checks. **CGNAT overlap**: 100.64/10 is shared by Tailscale/NetBird/ISP CGNAT.
17. **Unix socket path limit** (108 Linux / 104 macOS): fall back to a relative path after `chdir` or a Linux abstract socket.
18. **macOS**: Gatekeeper quarantine stripped by install.sh; darwin/arm64 binaries are ad-hoc signed by the Go linker; LaunchAgents run only
    after login — boot-time start needs the LaunchDaemon (root install).
19. **Docker**: mDNS and real client IPs need `network_mode: host` (Linux). Distroless has no tailscale CLI → mount the LocalAPI socket.
20. **Thumbnails**: `image.DecodeConfig` ≤ 50 MP before decode; bounded worker pool; timeouts. The pixel budget is per *decoder*,
    not per pixel count: the colour model `DecodeConfig` reports under-counts several decoders (a progressive JPEG costs about five
    times a baseline one, a CMYK JPEG, a gray PNG with `tRNS`, an Adam7 PNG or an alpha WebP up to four times its model), so the
    headers decide the budget (§8.2) and the worst case is charged when they cannot be read.
21. **Backup memory**: neither creating nor reading an archive may hold per-member state — the manifest's member list is spilled to
    (and streamed from) a temp file on both sides, the reader folds it into rolling hashes instead of a map, and the manifest's own
    size is bounded by what the archive actually contains. `maxMembers` is 5 M.
22. **go:embed** ignores `.`/`_` files unless `all:` prefix is used (we use `all:`); avoid dotfiles in assets anyway.
23. **Release zips** are ~60–80 MB each; `RELEASE_KEEP` prunes.

<!-- feature subsections: use bullets, not numbers ("§18.N" in code comments means item N of the list above). -->

### Roles and permissions (A/B)

<!-- packages A (backend) and B (web UI): risks of roles and permissions -->

Backend (package A; §6a):
- **A missed check fails closed, not open**: custom roles are never admin-based, so an `IsAdmin()` check written before roles still
  refuses their holders. The opposite risk is a permission the web app offers while a service still refuses it; the
  services are tested per permission.
- **Every new admin route and settings section needs its permission**: `TestEveryAdminRouteDeclared` fails for an
  `/api/v1/admin/*` route missing from `routecaps_test.go`, `TestSettingsSectionsHaveCap` for a section missing from
  `settingsapi/caps.go` (unlisted sections are admin-only).
- **The catalog is append-only**: bits exist only in memory and names in the database, so removing a permission
  silently drops it from every stored role (unknown names are ignored) and reusing a name gives old roles a new power.
- **Open event streams keep their principal**: a change that publishes no `authz.changed` (e.g. toggling
  `sharing.allow_guests_share`) reaches an open stream only at its next reconnect (at most 30 minutes); no topic
  depends on it.
- **Staff invitation limits are checked when the invitation is created**: a multi-use invitation for a role that later
  gains a server permission stays usable until it expires or is revoked (the list shows it).
- **Role names and descriptions are visible** to everyone who may search the directory (`GET /roles`): they must hold
  no secrets.
- **API tokens and grant names**: `GET /admin/grants` and the access preview name items, so a token needs `files:read`
  besides the `admin` scope (an admin-only token gets 403 there).

Web UI (package B; §13.5):
- **The web app only leaves out what would fail**: route guards, the navigation and the controls read the role's
  permissions from `/me`, but the server decides every request. A button shown by mistake answers 403; one hidden by
  mistake is a usability bug, not a hole. For owners and admins `can()` is always true, so a permission a newer server
  adds never hides an administrator's page.
- **A server without roles**: the web app detects it by a `/me` without `role_id` (`rolesSupported()`): role pickers
  offer the built-in roles and the Access card, the group page's roles and the roles API calls are left out. A server
  that sent `/me` without `role_id` by mistake would lose those parts of the UI, not rights.
- **Delegates' own account**: the user page shows their own account read-only with a pointer to Settings (the server
  refuses a delegate's own role, quota and password rule); a mistake in the client-side mirror of the escalation rules
  (`mayManageAccount`) only shows or hides controls.

### Password-protected zips (C)

<!-- package C: risks of password-protected zips -->

- **The format limits the protection.** AE-2 derives its key with PBKDF2-HMAC-SHA1 × 1000 (tens of millions of guesses per second
  on a GPU), so a short password falls quickly: 12 characters minimum, the common-password list and the generator are the
  mitigations. ZipCrypto falls to a known-plaintext attack (`bkcrack`, ~12 known bytes — exactly what Store keeps for PNG, JPEG,
  PDF, DOCX…): opt-in per upload, warned, never the default, switchable off (`storage.zip_legacy_encryption`). Names, folder
  structure, sizes (and so compressibility), times and the entry count stay visible.
- **Per-entry authentication.** The AE-2 MAC covers one entry's ciphertext: entries can be renamed, dropped, reordered or moved
  between archives with the same password without a reader noticing.
- **Readers.** AES zips do not open in Windows File Explorer or macOS Archive Utility; ZipCrypto does. The reader table of
  FILEPARCEL.md and the manual QA list of DEVELOPMENT.md must be kept current.
- **Test trap.** A wrong (big-endian) CTR counter still passes `7z t` for Store entries (AE-2 has no CRC, the MAC covers the
  ciphertext): interop tests extract and compare bytes. Go's `cipher.NewCTR` must never be used for WinZip AES.
- **Not end-to-end.** The server holds the password while it builds the .zip (it has the plaintext files anyway); Go strings
  cannot be zeroed, so it lives briefly in request decoding, the batch creation and the job, like an account password. The sealed
  copy can be in a backup taken while its batch was in flight.
- **Keyboard on phones.** Every bottom sheet lifts itself above the on-screen keyboard from `visualViewport` (§13.6); the keyboard
  is inferred (a focused text field and a loss of at least 200 px), because browsers expose no keyboard height. Tested with a
  simulated viewport in Chromium and WebKit; real keyboards stay on the manual list of DEVELOPMENT §10.

### Tailscale Funnel, Serve and VPNs (D)

<!-- package D: risks of Tailscale Funnel/Serve and VPN detection -->

- **A hand-made Funnel to the main port** (`tailscale funnel https+insecure://localhost:8443`, or a Funnel on another node pointed at
  this server) would make every visitor one address that the allowlist admits: the main listener refuses `Tailscale-Funnel-Request`
  (tailscaled strips it from client input), the doctor fails on such entries, and `tailscale serve unix:<admin.sock>` gets 403 from the
  admin socket. Unconfigured local proxies (nginx, cloudflared, `tailscale serve localhost:8443`) are detected, not blocked:
  applying the policy to their forwarded addresses would break existing setups.
- **Userspace Tailscale** (no TUN) dials tailnet connections from 127.0.0.1: every peer bypasses the access policy; reported as the
  exposure `tailscale.userspace` (Serve keeps the real address).
- **TCP backend**: while FileParcel is stopped another local program could listen on 127.0.0.1:<backend port> and receive the Funnel
  traffic; entries are removed on every clean stop, but remain after a crash (doctor warns while the TCP backend is used). The Unix
  backend has no such window (0700 `run/`).
- **tailscaled checks the whole posted config**: while any `unix:`/path entry exists (FileParcel's own included), every change needs
  root or a sudo-capable operator — other tools editing the serve config on this machine are affected; there is one operator per
  machine.
- **Funnel limits**: ports 443/8443/10000 only, non-configurable bandwidth limits, public DNS can take up to 10 minutes, the
  self-probe goes over the tailnet (cannot prove public DNS). `ts.net` is on the Public Suffix List: every node of the tailnet is
  same-site with FileParcel (`__Host-` cookies and the CSRF checks already cover it). Headscale has no Funnel relays or ts.net
  certificates (juanfont/headscale#1921): unavailable there, decided by capabilities.
- **Classification mistakes**: an exit VPN classified as a mesh would put its addresses into URLs, SANs and (at install) the allow
  list; an interface classified as outgoing loses its URLs. Strong signals only for the excluding roles, `network.iface_roles` fixes
  either way, and allow lists are never rewritten (the doctor points out outgoing-VPN networks in existing ones). The default-route
  rule applies to generic tunnels only; 100.64.0.0/10 is still shared by Tailscale, NetBird, NordVPN Meshnet, WARP and CGNAT.
- **Probes**: the routing tables, `/proc` and a few configuration files are read (bounded, cached); on hosts where netlink is
  denied nothing becomes egress by its default route.

### Command line (E)

<!-- package E: risks of the command line -->

- **Old names are an interface.** Scripts in the wild call `user add`, `mdns`, `restore`, `--generate`…: a rename goes through
  `legacy.go`, and no entry is ever removed. A legacy copy must come from the same constructor, or its confirmations,
  elevation and validation drift apart from the canonical command's.
- **No command sets `PersistentPreRun(E)`.** cobra runs only the nearest one, so the root's `checkInvocation` (the
  secret-prompt guard, the one-stdin rule, `--token-file`) would be skipped silently; `TestNoCommandPersistentPreRun` fails on it.
- **Help text is documentation.** A changed Short, Long or Example changes the generated reference in COMMANDS.md;
  `TestCLIReferenceUpToDate` fails until `scripts/gen-cli-docs.sh` has run.
- **Completion runs on every Tab.** It must never take the home lock or ask for a passphrase (offline mode) and must give up
  quickly: every server source goes through `completeFrom`, and a flag that carries a secret never gets a completion function.
- **Older servers.** The CLI keeps working against a server without custom roles, grants or Funnel: built-in role words
  resolve without a request, the permission catalog falls back to the compiled one, and a missing route answers "…(upgrade
  it)". Removing those fallbacks breaks mixed versions (a new CLI with `--server` against an old server).
- **Rights of the admin socket.** Without `--as`, `access` commands act with the socket's full rights (the system principal):
  a grant made that way is audited with the system actor; `--as USER` narrows to that user's rights.

## 19. Resolved questions
License Apache-2.0 · module path `fileparcel` · admin user `admin` · plain key mode is the default · linux/arm (GOARM=7) included ·
the person installing runs the sudo steps (firewall rules; optional `tailscale set --operator=<user>`) after install.

## 20. Known gaps (integration)
Recorded here so they are not mistaken for finished work.

1. ~~**Maintenance mode is CLI-only.**~~ **Closed** (live smoke test): `web/mw/maintenance.go` registers
   `maintenance.enabled` and `maintenance.message` in the `general` section and adds the `Maintenance` gate to the root
   chain (§9.1, after `SealedGate`). While it is on, API requests (the share JSON routes included) get `503 unavailable` with `Retry-After` and the
   operator's message, page navigations get the 503 notice (`pages.MaintenanceNotice`, the generic error page — `mw`
   cannot import `pages`, so `web/router.go` passes the handler in), and `/healthz`, `/readyz`, the static assets, the
   sign-in/unlock/trust pages, `/api/v1/auth/*` (except `/api/v1/auth/invite/*`: accepting an invitation creates an account,
   and the `/invite/{token}` page is closed too), `/api/v1/me*`, `/api/v1/system/*`, `/api/v1/admin/*`, the admin SPA and
   `/settings/*` stay reachable (the last one is the visitor's own account UI, backed only by `/api/v1/me*`, and it is
   where the SPA sends an administrator who still has to enrol a second factor). Administrators (resolved by the gate itself, since it runs before `Authenticate`) and trusted
   in-process callers (admin socket, offline CLI — how it is switched off again) pass everywhere. Covered by
   `internal/web/mw/maintenance_test.go`. While it is on, the people who keep working see it: a banner on every page of
   the web app (`features.maintenance`, with *Turn off* for *Operate the server*), a warning in the doctor
   (`GET /admin/system/doctor`: the dashboard's health list and `fileparcel doctor`), a line in `fileparcel status`
   (`GET /admin/system` `maintenance`), and a notice on the sign-in page.
2. **ACME has never run against a real CA.** Only the configuration, the DNS providers and the challenge routing are
   covered by tests.
3. **The dnssd (macOS) mDNS backend has only been tested with a fake `dns-sd`**, and the Tailscale integration only
   against a fake LocalAPI socket and a fake CLI.
4. **mTLS "required" is not bound to the session user**: any valid, unrevoked client certificate of an active user is
   accepted, and nothing writes `sessions.client_cert_serial`.
5. **The sd_notify `STATUS=` line is not refreshed** when the keys go from locked to unlocked.
6. **Invitation e-mails need `server.public_url`** (or an access URL from the network service) to build an absolute link;
   without one (or when the mail queue refuses the message) the e-mail is skipped: the invitation is still created, and
   the create response's `invite.email_error` says why, which the admin UI and the CLI show as a warning next to the link.

7. **Roles:** an open event stream keeps the permissions of the request that opened it for changes that
   publish no `authz.changed` (e.g. `sharing.allow_guests_share`) until it reconnects (at most
   `sseMaxLifetime`, 30 min).
8. **Tailscale Funnel/Serve** has only run against a fake tailscaled (`tslocaltest`, `fake_tailscaled.py`);
   the real-tailnet check is manual (DEVELOPMENT §10). A deny-list change does not end a Funnel event stream
   that is already open (IngressGate checks each request; the connection tracker of §10.3 cannot see the
   ingress listeners, whose peer is tailscaled). Over Funnel `app` without `funnel.allow_admin`, a staff
   account's event stream still carries the server topics its permissions receive (notifications only; no
   `/api/v1/admin/*` route is reachable). Every active share link is reachable in `shares` mode (no per-link
   flag), Funnel inside Docker reports `unavailable`, and the darwin route/process probes of `netinfo` are
   unit-tested but have never run on a Mac.
9. **Protected zips:** real phone keyboards (the sheets' keyboard handling is tested with a simulated
   viewport) and third-party unzip tools are the manual list of DEVELOPMENT §10.
10. **Zip uploads are audited with the channel `share`:** the `upload.zip` job writes the file through
    `Files.SysPrincipalFor` (Via share), so its `file.upload` entry says `share` whatever channel created the
    batch (the actor is right).
11. **No renumber fix-up for the review's migration numbering:** a database that recorded
    `(2, 'fts_name_key')` (a development build that was never released; released databases before the roles migration carry only 0001) is refused
    with `db: migration 0002 is "fts_name_key" in the database but "roles" in this binary` before anything
    runs (`internal/wire` `TestV4UpgradeDatabases`).
12. **Going back to an older release:** a binary built before a migration cannot open the migrated database, and
    one whose restore opens the database first stops with `ErrSchemaTooNew`; the newer binary restores the
    pre-upgrade backup without migrating it, then the binaries are swapped (INSTALL.md "Roll back by hand").
    Checked by hand on a real home (init, data, `fileparcel upgrade` with the delegated backup, start, restore,
    start of the older binary); not an automated test.
13. **CLI paths:** `/Team/<group>` resolves the groups the acting user belongs to and also a team folder
    shared with them as a whole; a folder shared from deeper inside a team folder is reached by its id.

### 20.1 Live smoke test (what has actually been exercised against a running server)

A full run of `tests/smoke/run_all.sh` against a fresh `init`ed home (HTTPS 18443, HTTP 18080) covers 226 of the 233 mounted routes and every
group of §9.4: the auth flows (password, CSRF, TOTP enrol + re-login, recovery codes, elevation, PATs and scopes,
lockout and the per-IP rate limits), users/groups/invites, the whole file tree (mkdir/rename/move/copy/trash/restore/
purge/search/recent/star/versions/grants), both upload paths (small and multipart with `X-FP-SHA256`, resume,
idempotent re-send, zip-mode batches through the `upload.zip` job), downloads with Range/HEAD/`If-None-Match`,
thumbnails, zip and tar archives, shares (passwords, `max_downloads`, expiry, the public pages, file requests
including a multipart upload through `/s/{token}/api/…`), the admin surfaces (certs, client certs and their one-time
`.p12` links, keys, settings, network policy incl. the lockout guard from a non-loopback address, mDNS, jobs,
doctor, dashboard, audit + chain verification, SSE), `/trust/ca.*`, sealed mode (seal → restart → locked 503 →
`/unlock` → unlock → `keys lock` → CLI unlock → unseal), maintenance mode, the CLI over the admin socket, and a
real backup → change → restore → verify cycle plus backup import, identity rotation, `system/restart` and CA
regeneration. E-mail is covered end to end against a local SMTP sink (the test message and an invitation both
arrive). It also drives custom roles, role grants and role group memberships, access checks, the VPN list,
Funnel/Serve status and password-protected zip uploads through the CLI (phase 7). Of the seven routes missing from that
count, `/healthz`, `/readyz`, `/favicon.ico` and `/static/{hash}/*` are kept out of the access log the coverage is
measured from by `mw/accesslog.go` and asserted directly; the other three — `PUT /admin/network/funnel`,
`PUT /admin/network/serve` and `POST /admin/network/tailscale/reapply` — need a tailscaled, which the smoke run never
reaches (it points `FILEPARCEL_TAILSCALE_SOCKET` at a missing socket), and are driven against a fake one by
`internal/wire` (`TestFunnelEndToEnd`, `TestV4CrossFeature`) and `tests/ui/test_funnel.py`.

Still untested against the real world: gaps 2–6 above — ACME against a real CA, the macOS `dns-sd`
backend, Tailscale (the smoke run never reaches a tailscaled, so `POST /admin/certs/tailscale/fetch` answers
412 `precondition_failed` with the reason, which is the correct behaviour there; Funnel and Serve: gap 8),
mTLS binding, `sd_notify` and absolute invitation links. Passkeys are covered only as far as the ceremony
endpoints go (options, flow ids, no account-existence oracle, clean errors on a bad flow): a successful
registration needs a real authenticator.
