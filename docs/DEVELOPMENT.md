# FileParcel — Development Guide

This guide is for contributors: how to set up, build and test FileParcel, the rules the code follows, and
how to send a change. Start with [CONTRIBUTING.md](../CONTRIBUTING.md) for how to report bugs and open a pull
request. The binding architecture is [`docs/DESIGN.md`](DESIGN.md); section numbers (§) below
refer to it. Where this guide and DESIGN.md disagree, DESIGN.md wins — report the conflict.

---

## 1. Setup

FileParcel is pure Go (no cgo, no npm). Toolchain: **Go 1.27.1** in `~/sdk/go1.27.1`, `GOTOOLCHAIN=local`.

```sh
git clone https://github.com/kpdirectmail/fileparcel && cd fileparcel
scripts/get-go.sh 1.27.1          # once: downloads go1.27.1 for this OS/arch into ~/sdk (SHA-256 verified)
. scripts/env.sh                  # every shell: puts ~/sdk/go*/bin (newest first) on PATH if `go` is missing
                                  # or older than 1.26, exports GOTOOLCHAIN=local
```

`scripts/get-go.sh -n VERSION` prints the URL and the expected SHA-256 without downloading.

The module path is `fileparcel` (imports look like `fileparcel/internal/core`). `go.mod` says `go 1.26.0`.
Release builds use `CGO_ENABLED=0`; `go test -race` works with the default settings.

## 2. Build, test, run

```sh
go build ./...                                   # must always pass
go vet ./...
go test ./internal/<yourpkg>/...                 # the packages you changed (fast)
go test -race ./internal/<yourpkg>/...           # before you send the change
go run ./cmd/fileparcel version                  # smoke test of the CLI
go mod tidy                                      # only after changing dependencies (keep to DESIGN §4)
```

Before you send a change (must stay green): `go build ./... && go vet ./... && go test ./...` and
`go run ./cmd/fileparcel version`. Never leave a `_test.go` that references APIs that don't exist yet.

Release checks (maintainers; all of it must pass before a release):

```sh
gofmt -l ./internal ./cmd ./tests                # must print nothing (tests/ holds Go packages too)
go build ./... && go vet ./... && go test -race ./...
go run honnef.co/go/tools/cmd/staticcheck@latest ./...     # skip only style findings, with //lint:ignore <check> <reason>
go run golang.org/x/vuln/cmd/govulncheck@latest ./...
for t in linux/amd64 linux/arm64 linux/arm darwin/amd64 darwin/arm64; do   # GOARM=7 for linux/arm
    CGO_ENABLED=0 GOOS=${t%/*} GOARCH=${t#*/} go build -o /dev/null ./cmd/fileparcel
done
sh scripts/gen-cli-docs.sh --check               # the reference in docs/COMMANDS.md matches the cobra tree
sh scripts/gen-settings-docs.sh --check          # the settings reference in docs/FILEPARCEL.md matches the registry
sh scripts/check-third-party.sh                  # THIRD_PARTY.md + the FILEPARCEL.md "Packages used" table
sh tests/e2e/e2e.sh                              # DESIGN §17 end-to-end run against a fresh build
sh tests/ui/run.sh                               # DESIGN §17 Playwright UI suite (tests/ui/.venv, ~4 min)
FP_SMOKE_DIR=/var/tmp/fp-smoke bash tests/smoke/run_all.sh   # DESIGN §20.1 11-phase live run (1.5 GiB, ~15 min)
```

Unit tests do not prove a server works. `tests/smoke/run_all.sh` (`make smoke`) is that run, automated: it
`init`s a throw-away home on a spare port pair, `serve`s it, and exercises every §9.4 group against it — auth
and the second factor, the file tree, both upload paths, downloads with Range, shares and file requests, the
admin surfaces, sealed mode, maintenance mode, the CLI over the admin socket, and a backup/restore cycle —
then prints mounted-route coverage from the access log. It defaults to ports 18443/18080 and the host name
`fileparcel.local`; override with `FP_PORT`, `FP_HTTP_PORT` and `FP_HOST`, keep the server up afterwards with
`FP_KEEP_SERVER=1`, and point `FP_SMOKE_DIR` at a file system with at least 1.5 GiB free. §20.1 records what
the last such run covered and what it did not.

The design contract is pinned by tests in `internal/wire`, which fail on drift in **either** direction
(documented but missing, or implemented but undocumented):
`TestRouterMatchesDesign` (§9.4 route table vs `chi.Walk` over `web.NewRouter`),
`TestJobKindsMatchDesign` (§9.7 job kinds and schedules) and
`TestSettingsCatalogMatchesDesign` (§11.2 settings, their defaults and their restart flags).
When a change to the contract is intended, change DESIGN.md and the test together.

### Integrity checks and fts5

Run `PRAGMA quick_check` / `integrity_check` only through `db.DB.IntegrityCheck`, which opens its own
short-lived connection. Since SQLite 3.44 those pragmas call each virtual table's `xIntegrity`, and fts5
answers it from a structure record cached on that connection — a path with no `xBegin`, so nothing refreshes
it. A pooled reader that has served a `/search` request therefore keeps walking a structure the writer has
since merged away and reports "fts5: corruption found reading blob N from table nodes_fts" on a perfectly
intact database. `GET /admin/system/doctor` did exactly that under normal load (and told the operator to
restore from backup) until it was moved onto the helper. `internal/db/fts_quickcheck_test.go` pins it; the
same invariant is why `fileparcel db check` must not query `nodes_fts` before running its pragma.

**Never run tests or experiments against `server/`**: it is gitignored and may hold your own (live)
installation. Use a throw-away home under your temp directory, on ports of its own, that never touches the
machine's tailscaled and does not announce `fileparcel.local` next to a real installation:

```sh
H=$(mktemp -d)/home
go run ./cmd/fileparcel init --home "$H" --port 18443 --http-port 0 -y
FILEPARCEL_HOME=$H go run ./cmd/fileparcel --offline config set mdns.mode off
FILEPARCEL_HOME=$H FILEPARCEL_TAILSCALE_SOCKET=/nonexistent go run ./cmd/fileparcel serve
```

In Go tests, build a home with `home.New(t.TempDir())`, `h.EnsureLayout()` and
`config.Default(config.NewInstallID()).SaveTo(h.Config())`, then `wire.Build(ctx, h, app.ModeOffline)` for a
fully wired `*app.Deps` (see `internal/wire/wire_test.go` and `internal/cli/client_test.go`).

## 3. Rules

1. **Releases are cut by the maintainers.** With `git config core.hooksPath .githooks` every commit builds
   `releases/fileparcel-vN.zip` and tags `vN` (§15), so work on a branch and leave the hooks off in your
   clone. Tests and scripts never use `sudo`.
2. **The shared contracts** — `internal/core`, `internal/db` and its migrations, `internal/app`,
   `internal/wire`, `internal/web/router.go`, `internal/web/httpx`, `go.mod`, `go.sum`, `cmd/` — are used
   by every package (§5 below says where things live). Change them deliberately, together with DESIGN.md and
   the tests that pin them, and say so when you send the change (§8).
3. **Keep the build green**: `go build ./...` must pass; don't leave other packages broken.
4. **HTTP modules never call `r.Route()` or `r.Mount()`.** They register routes inside
   `api.Group(func(r chi.Router) { r.Use(...); r.Get("/path", h) })` from their `Mount` / `MountRoot`.
5. **Frontend: no `innerHTML`, `outerHTML`, `insertAdjacentHTML`, `document.write`, `eval`, `new Function`,
   inline event handlers or inline styles.** CSP enforces `require-trusted-types-for 'script'; trusted-types fp` (the single `fp` policy only creates same-origin script URLs for Web Workers and the service worker).
   Build DOM with `h()` and `textContent` (§13.1).
6. Only parameterized SQL. Never log secrets (passwords, tokens, keys, share passwords, TOTP secrets).
7. Fakes/test doubles live in `_test.go` files of the package that uses them (or a `…test` package such as
   `internal/uploads/uploadtest` when several packages share them).
8. Emit the audit actions of §9.6 (constants `core.Act*`) and register your settings (§11.2) in your
   package's `settings.go`.

## 4. Import rules (§2, enforced in review)

| Package | May import |
|---|---|
| `core` | stdlib + `home`, `config`, `db`, `events`, `buildinfo` |
| service packages (`keys blobstore audit auth users files ziputil thumbs uploads shares backup jobs certs netinfo tsingress mdns qr settings ratelimit notify`) | `core`, `db`, `crypt`, `ids`, `events`, `settings` (for `Register`), `config`, `home`, `buildinfo`, `logx`, stdlib, third-party. **Never** `web/...`, `app`, `wire`, `cli`, `server`, or another service's concrete type (use the `core` interfaces you receive in `New`). |
| exceptions | `uploads` → `ziputil`; `files` → `ziputil`, `thumbs`; `auth`/`shares` receive `*ratelimit.Registry`; `backup` → `keys` (`keys.Open`) and `blobstore` (`blobstore.New`), only to open a restored temporary home for deep verification (`internal/backup/stores.go`); `jobs/cron` is a leaf parser importable by anyone who validates cron settings (`backup`); `qr`, `names` and `tslocal` (the tailscaled client) are leaf utilities importable by anyone |
| `web/*` | `app`, `core`, `web/httpx`, `web/mw`, `web/pages` (for `pages.Render`), `web/static`, `qr`, `names`, `ids`, `events` (to publish), `settings` (Register only). `web/pages` and `web/static` also import `fileparcel/web` (package `webassets`, the embedded FS). Never `ratelimit` — use the `mw.Bucket*` names. |
| `app` | `core`, `ratelimit` only |
| `wire`, `cli`, `server`, `svc`, `cmd` | everything |

`internal/depsguard` existed during the build stage: behind the build tag `depsguard` it blank-imported every
dependency of §4 so `go mod tidy` would keep them while packages were stubs. It was removed at integration and
`go mod tidy` kept every module, so each one is now imported for real. `go.uber.org/zap` is a direct dependency
of exactly one file, `internal/certs/zaplog.go`, which routes certmagic's zap records into the FileParcel log.

## 5. Where things live

| Area | Packages and files |
|---|---|
| Foundation and wiring | `internal/{buildinfo,home,config,core,ids,db,events,crypt,logx,app,wire}`, `internal/web/router.go`, `internal/web/httpx`, `cmd/`, `go.mod`, `go.sum` |
| Keys and blob storage | `internal/keys`, `internal/blobstore` |
| Sign-in | `internal/auth`, `internal/ratelimit`, `internal/web/authapi`, `internal/web/meapi` |
| Users, audit and notifications | `internal/users`, `internal/audit`, `internal/notify`, `internal/web/usersapi` |
| Files | `internal/files`, `internal/ziputil`, `internal/names`, `internal/thumbs`, `internal/web/filesapi` |
| Uploads and shares | `internal/uploads`, `internal/shares`, `internal/web/uploadapi`, `internal/web/sharesapi` |
| TLS and the server | `internal/certs`, `internal/server`, `internal/web/securityapi` |
| Network and settings | `internal/netinfo`, `internal/mdns`, `internal/tsingress`, `internal/tslocal`, `internal/qr`, `internal/settings`, `internal/web/settingsapi` |
| Jobs and backups | `internal/jobs`, `internal/backup`, `internal/web/opsapi` |
| Platform and CLI | `internal/web/mw`, `internal/web/static`, `internal/web/pages`, `internal/cli`, `internal/svc` |
| Web app: core and files | `web/static/css/**` (except `css/pages/{settings,admin,auth,share}.css`), `web/static/js/{app.js,routes.js,nav.js}`, `js/core/**`, `js/components/**`, `js/upload/**`, `js/preview/**`, `js/pages/{files,shared,links,requests,starred,recent,trash,activity,search}.js`, `web/templates/app.html`, `web/static/manifest.webmanifest`, `web/static/sw.js`, `web/static/icons/**` |
| Web app: admin and public pages | `web/static/js/pages/settings/**`, `web/static/js/pages/admin/**`, `web/static/js/public/**`, `web/static/css/pages/{settings,admin,auth,share}.css`, `web/templates/{login,invite,setup,unlock,trust,share,error}.html` |
| Packaging and docs | `install.sh`, `uninstall.sh`, `scripts/**`, `.githooks/**`, `Dockerfile`, `docker-compose.yml`, `.dockerignore`, `Makefile`, `README.md`, `LICENSE`, `NOTICE`, `docs/**`, `tests/e2e/**`, `tests/smoke/**` |

`web/embed.go` (package `webassets`, `//go:embed all:static all:templates`) is shared and frozen.

## 6. The contract in brief

Read `internal/core` first — it *is* the API documentation (json tags = HTTP schema).

- **Services** implement one `core` interface. Constructors are fixed (§5.2), e.g.
  `files.New(env *core.Env, blobs core.BlobStore, jobs core.Jobs) (*Service, error)`, and every package asserts
  `var _ core.Files = (*Service)(nil)`. `wire.Build` constructs them in order; `wire.Start` starts
  network → certs → mdns → jobs (offline mode: network only).
- **Optional hooks** (`core/hooks.go`) — wire checks every service for them, so you never need to edit wire:
  - `Bind(*core.Services) error` — late binding to collaborators your constructor lacks (e.g. shares → Notify).
    Store references only; don't call other services from Bind.
  - `RegisterJobs(core.Jobs) error` — register job kinds and schedules (`core.Job*` kind constants), called after Bind.
  - `io.Closer` — closed in reverse construction order by the cleanup func.
  - `Jobs.Stop` and `MDNS.Stop` are called by cleanup even if `Start` never ran: make them safe.
- **Errors**: return `*core.Error` values (`core.ErrNotFound`, `core.Invalid(field, msg)`, `core.NotFoundf`,
  `core.Wrap(core.ErrConflict, "msg", cause)`, `core.Errorf`). `errors.Is` matches by code. Handlers call
  `httpx.Error(w, r, err)`; anything that is not a `*core.Error` becomes 500 `internal` (logged, not leaked).
  Authentication failures of stored data (blob segments, wrapped keys, sealed fields, backups) are `core.ErrCorrupt`.
- **Request/response bodies** that are not a single model live in `internal/core/api.go` (`core.Me`,
  `core.AuthState`, `core.CodeInput`, `core.PasswordChangeInput`, `core.NameInput`, `core.MoveInput`,
  `core.NodeIDsInput`, `core.ArchiveTicketResponse`, `core.PublicShareInfo`, `core.SystemStatus`,
  `core.NetworkOverview`, `core.SystemInfo`, `core.Dashboard`, …). Use them; don't invent parallel shapes.
  `PATCH /me/profile` decodes `core.ProfileUpdate` (never `UserUpdate`: role/quota are admin-only).
- **Names & paths**: validate with `names.Clean(name)` → `(nfc, key, err)` (key = `nodes.name_key`),
  `names.SplitRelPath(relPath)` for upload paths, `names.Numbered(name, n, isDir)` for `rename` conflicts.
- **Pagination**: `httpx.PageReq(r)` → `core.PageReq`; return `core.NewPage(items, httpx.EncodeCursor(key))`.
- **Time**: use `env.Now()` / `env.Clock`, store `db.Ms(t)`, read `db.FromMs`, nullable via `db.NullMs(*time.Time)` /
  `db.FromNullMs`.
- **DB**: writes via `env.DB.Tx(ctx, func(tx *sql.Tx) error {...})` (BEGIN IMMEDIATE, retried on BUSY — fn may run
  more than once; no side effects outside the tx; no nested Tx; no file I/O inside). Reads via `env.DB.Read`,
  `Query`, `QueryRow` (read-only pool). `db.IsUnique(err)`, `db.IsForeignKey(err)`, `db.IsNoRows(err)`.
- **IDs & tokens**: `ids.New(ids.PrefixNode)`, `ids.NewBlobID()`, `ids.Token(32)`, store `ids.HashToken(tok)`,
  compare with `ids.Equal`.
- **Crypto**: `crypt.HashPassword` / `crypt.VerifyPassword` (argon2id, semaphore-bounded), `crypt.NewAEAD`,
  `crypt.Seal/Open`, `crypt.HKDF`, `crypt.HMAC` (length-framed), `crypt.RandomBytes`, `crypt.Zero`.
- **Events**: `env.Bus.Publish(events.Event{Topic: events.TopicJobDone, UserID: uid, Data: core.JobEvent{...}})`;
  subscribe with `env.Bus.Subscribe("job.*")`. Non-blocking, 256-event buffer, drop-oldest.
- **Settings**: declare keys in your package's `settings.go`:
  ```go
  func init() {
      settings.Register(settings.Def{Key: "storage.trash_days", Section: "storage", Order: 40,
          Type: settings.TypeInt, Default: 30, Min: 0, Max: 3650, Label: "Trash retention (days)"})
  }
  ```
  Read with `env.Settings.Int("storage.trash_days")` etc. Bootstrap keys (`server.*`, `log.level`) use
  `Bootstrap: true` and live in `fileparcel.toml` (`config.Config.Get/Set/Save`).
- **Audit**: `env.Audit.Record(ctx, core.AuditEntry{Action: core.ActFileRename, TargetType: "node", TargetID: id})`
  (actor/IP/request id come from the ctx principal) or `RecordTx` inside your transaction. Rows are persisted
  immediately in every key state (see the key-state rule on `core.Audit`).
- **Keys lifecycle**: `init`/`install`/`serve --init-if-missing` call `env.Keys.Init(ctx, sealed, passphrase)`
  (creates master key + keyring, returns the one-time recovery key in sealed mode), then `Certs.Init(ctx)`.
- **Certs lifecycle**: `certs.New` loads everything from disk (no network, no goroutines); offline mode never
  calls `Certs.Start` (see `core.Certs`).
- **Restart / restore**: request a restart by publishing `events.Event{Topic: events.TopicSystemRestart}` (server
  exits 75). `serve` calls `backup.ApplyPendingRestore(ctx, h, log)` under the home lock before `wire.Build`,
  extending systemd's start timeout meanwhile (`server.ExtendStartTimeout`) until `server.Run` sends `READY=1`.

### HTTP modules

```go
// Package filesapi ...
func Mount(api chi.Router, d *app.Deps) {           // api is mounted at /api/v1: use relative paths
    api.Group(func(r chi.Router) {
        r.Use(mw.RequireFull)
        r.Get("/spaces", func(w http.ResponseWriter, r *http.Request) {
            spaces, err := d.Files.Spaces(r.Context(), mw.Principal(r))
            if err != nil { httpx.Error(w, r, err); return }
            httpx.JSON(w, http.StatusOK, spaces)
        })
    })
}
```

- The `/api/v1` chain already applies `MaxBody(1 MiB)` → `RateLimit("api", per IP)` → `Authenticate` → `CSRF`.
  Raise the body limit per route with `mw.MaxBody(n)` (an inner MaxBody replaces the outer one).
  Socket/offline principals are never rate limited.
- Guards: `mw.RequireAuth`, `mw.RequireFull`, `mw.RequireAdmin`, `mw.RequireRole(...)`, `mw.RequireElevated`,
  `mw.RequireScope(core.ScopeFilesWrite)`, `mw.SocketOnly`, `mw.NoStore`,
  `mw.RateLimit(mw.BucketLogin|BucketShare|BucketUnlock|BucketAPI, mw.PerIP|mw.PerUser)`.
  Accessors: `mw.Principal(r)`, `mw.ClientIP(r)`, `mw.Deps(r)`, `httpx.Meta(r)`.
- **A vs F** (DESIGN §9.4): `RequireAuth` admits AuthLevel-1 (second factor pending) principals only on
  `/auth/*`, `GET /me` and `GET /me/mfa`. Everything else uses `RequireFull`, which also admits users with a
  pending 2FA *enrollment* to `/me*` and `/auth/logout` (not `POST /me/tokens`, `POST /me/client-certs`). So the
  "(A)" enrollment routes (`/me/totp/*`, `/me/passkeys/begin|finish`) use `RequireFull`.
- Decode bodies with `httpx.Decode[T](r, max)` (unknown fields → 422). User content (downloads, previews,
  thumbnails, share downloads) goes through `httpx.ServeBlob(w, r, name, mime, mod, etag, inline, rs)` which applies
  the §8.2 allow-list/CSP/CORP/cache rules and Range; `httpx.ContentHeaders` for streamed bodies (archives);
  `httpx.Attachment(w, name, inline)` for the disposition alone.
- **HEAD** requests reach GET handlers (`middleware.GetHead` in the router). Skip side effects on HEAD
  (share download counters, access log, single-use archive tickets, download audit).
- Root-level pages use `pages.Render(w, r, "share", data)` (DESIGN §9.4) or `pages.RenderTitled(w, r, page, title, data)`;
  `data` becomes `boot.data` in the page; `pages.NotFound(w, r)` is the generic 404 page.
- Static assets are served under `static.AssetBase()` (`/static/<hash>`). In `sw.js` and
  `manifest.webmanifest` the placeholders `__FP_ASSET_BASE__` and `__FP_ASSET_HASH__` are replaced at serve time.
- Trusted in-process callers (admin socket, offline CLI) arrive with a principal already in the request context;
  they may send `X-FP-As: <username>` to act as a user.

### CLI

Commands live in `internal/cli` (DESIGN §12). Global flags are in `cli.G`. Talk to the server with
`WithClient(cmd, func(ctx, c *Client) error { … })` (or `withUserClient` for commands that act on a user's own
files, shares or tokens), then `c.Do(ctx, "GET", api("/admin/users"), nil, &page)`, `listAll[T]` for paged lists
and `c.Stream(...)` for raw bodies. API errors come back as `*core.Error` (with `Status`).

#### Adding a command

1. **Constructor and registration.** A top-level command lives in its own file with
   `func init() { Register(newXCmd) }`; a subcommand is added by its parent's constructor (`cmd.AddCommand`). A
   command group is a `groupCmd(use, short, long, example, aliases...)`, which rejects unknown words with
   suggestions. Constructors keep no state outside the flags they bind (`NewRootCmd` builds a fresh tree for
   every test).
2. **`Use` placeholders** (DESIGN §12.1): lowercase in angle brackets, optional in `[ ]`, repeatable with `...`
   — `<user>`, `<group>`, `<role>`, `<path>`, `<folder>`, `<id>`, `<backup>`, `<job>`, `<key>`, `<name>` (only for
   something being created). Never `<username>` or `<old-name>`. Shell completion picks the argument's source
   from the placeholder (`argSource` in complete.go): use the usual names, or add yours there.
3. **Texts.** `Short`: sentence case, imperative, no trailing period, at most 64 characters. `Long`: what it does
   and when to use it, then defaults, side effects and what it needs, wrapped at 80 columns; end with
   `elevationNote` (or `elevationNoteFor("…")`) when it needs step-up remotely and `confirmNote` when it asks
   first, and with `filesPathNote` on file, share and request commands. `Example`: 2–4 lines, each indented by two
   spaces and a canonical `fileparcel …` invocation of the command itself, with the sample data `alice`, `bob`,
   `carol`, `Design`, `Marketing`, `"/My files/…"` and full-length ids (`shr_01j9zq3x4k6m8p0r2t4v6x8z0b`).
4. **Groups and sections.** Add a new top-level name to `topLevelGroup` in help.go, and a new child of `files`,
   `user`, `network` or `backup` to its section in `subGroups`. Constructors never set `GroupID`. An object group
   calls `setListHint(cmd, "fileparcel x list")` so a not-found error says where to look; a group that does
   something when run bare sets the `fp:bare` annotation.
5. **Flags.** Use the helpers of flags.go: `addOutputFlag` (`-o/--output`), `addForceFlag` (`-f/--force`, only
   for overwriting the output file), `addWaitFlags`, `durationVar`, `addInactiveFlag`, `addAllUsersFlags`,
   `parseExpiry`. Secrets never go on argv: `addSecretFlags` registers `--x` (a switch that asks on the terminal,
   annotated `fp:secret-prompt`), `--x-stdin`, `--x-file` and optionally a generate switch. A flag with a fixed set
   of words gets an entry in `enumFlags` (complete.go). No command sets `PersistentPreRun(E)`: the root's
   `checkInvocation` must run for every command.
6. **Renames go through `legacy.go`** — a hidden copy for a renamed command, a flag mapping for a renamed flag,
   the old name as an alias for a renamed leaf — never by deleting the old spelling. `fileparcel help renamed` and
   `TestLegacyInvocations` pick the entry up.
7. **Output.** `Print(cmd, v, human)`: the object with `--json` (lists as `[]`, never `null`), tables and `KV`
   blocks otherwise; notes and warnings with `Infof`/`Warnf` on stderr. `UsageError(…)` exits 2.
8. **Test and document.** Test against the fake API (`newFakeAPI`, `socketHome` for the admin socket), then run
   `go test ./internal/cli/... ./tests/docs` — `TestEveryCommandDocumented` checks the texts and examples,
   `TestCLIReferenceUpToDate` the reference — and regenerate the reference in docs/COMMANDS.md with
   `sh scripts/gen-cli-docs.sh` (`--check` only compares).

## 7. Adding a database migration

Schema changes affect every installation: agree on them with the maintainers first (§8).

1. Add `internal/db/migrations/NNNN_short_name.sql` with the next 4-digit number. The numbers must run 1..N
   without gaps (otherwise `db.Migrations()` fails and the binary refuses to start); `db.Migrate` applies every
   version the database has not recorded and refuses one recorded under another name (DESIGN §6 "Migration
   numbering"). Never edit or renumber a migration that has shipped (0001 is frozen once released).
2. The file runs in **one transaction** together with its `schema_migrations` row. Don't use statements that
   can't run in a transaction (`VACUUM`, `PRAGMA journal_mode`), and don't toggle `foreign_keys`.
3. Keep `nodes_fts` in sync: it indexes `nodes.name_key` (0004); if you touch that column, the triggers
   `nodes_fts_ai/ad/au` must still hold, and every rename must set `name_key` along with `name`.
4. Add a test in `internal/db` that migrates a fresh DB and exercises the change. A binary refuses to open a DB
   whose version is newer than its own (`db.ErrSchemaTooNew`).

## 8. Sending a change

Changes arrive as pull requests on [GitHub](https://github.com/kpdirectmail/fileparcel/pulls), from a branch of
your fork ([CONTRIBUTING.md](../CONTRIBUTING.md)). Describe what changed and why, and list the checks of §2 you ran (at least the ones that touch your change;
`go test ./tests/docs` whenever a help text or a document changed). Name every deviation from DESIGN.md with
its reason, or change DESIGN.md in the same change. Changes to the shared contracts of §3 rule 2 and new
database migrations (§7) need the maintainers' agreement first; say what is unfinished.

## 9. Frontend notes (§13)

No build step: vanilla ES modules and hand-written CSS embedded with `go:embed`. Every module starts with
`// @ts-check`. Boot data is read from `<script type="application/json" id="fp-boot">` (fields: `asset_base`,
`instance`, `csrf`, `user`, `keys_state`, `features`, `rp_id`, `version`, `ui`, `page`, `data`). Send `X-FP-CSRF`
on unsafe API calls. Page templates receive `.Title .Page .Instance .Asset .Theme .Lang .Boot` and may use the
`asset` template func; partials go in `web/templates/_*.html` or `web/templates/partials/*.html`.

## 10. Manual checks before a release

### Protected zip compatibility

The automated tests extract every password-protected .zip with 7-Zip and Info-ZIP `unzip` and compare the
bytes (`internal/ziputil`, `tests/e2e`, `tests/ui/test_zip_password.py`). What only a person can check, on
real devices, before each release — record the results, and update the reader table in FILEPARCEL.md
("Password-protecting the .zip") and DESIGN §18 when one changes:

1. Through the web app, upload the same three files (a text file, a JPEG and a PDF, one of them with an accent
   in its name, e.g. `Café.txt`) twice as a bundled .zip: once with AES-256, once with ZipCrypto.
2. **Windows 11 File Explorer**: the ZipCrypto .zip asks for the password and extracts; the AES-256 one
   fails (write down the message).
3. **macOS Archive Utility** (double-click): ZipCrypto asks for the password and extracts; AES-256 fails with
   "Unable to expand".
4. **Keka** (or The Unarchiver) on macOS and **7-Zip** on Windows: both .zips open; a wrong password is refused.
5. **iOS Files** and **Files by Google** (Android): record whether each .zip opens (the manual calls them not
   reliable and recommends a zip app).
6. **Phone keyboard** (iPhone with Safari and an Android phone with Chrome): open the upload dialog, turn on
   *Bundle into a single .zip* and *Protect the .zip with a password*, tap into *Password*: the sheet rises
   above the keyboard and the field stays visible, the page does not zoom in, the keyboard's *next* key moves
   to *Confirm password* and *done* submits, and a generated password can be copied.

### Tailscale Funnel on a real tailnet

The automated tests only ever talk to a fake tailscaled (`internal/tslocal/tslocaltest`,
`tests/ui/fake_tailscaled.py`); no test, fixture or script may run `tailscale serve` or `tailscale funnel`
against a real daemon (its operator is often the person running the tests). Before a release that touches
Funnel or Serve, the owner checks on a machine of their own, whose tailnet policy allows Funnel:

1. Note `tailscale serve status --json`, then run `fileparcel network funnel enable -y`: the status gains
   FileParcel's entry next to what was there.
2. Create a share link and open it on a phone off Wi-Fi (public DNS may need about 10 minutes).
3. `https://<machine>.<tailnet>.ts.net/login` answers "not found" (share links only).
4. `fileparcel network funnel status` shows *Reachable* ok.
5. `fileparcel network funnel disable`: `tailscale serve status --json` is back to what step 1 noted.
