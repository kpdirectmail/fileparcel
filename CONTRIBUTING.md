# Contributing to FileParcel

Thanks for your interest in FileParcel. Bug reports, ideas, documentation fixes and code are all welcome.
This page says how to report a problem and how to send a change; the details of the code base are in the
[Development guide](docs/DEVELOPMENT.md) and the [Design](docs/DESIGN.md) document.

FileParcel is a volunteer project: answers and reviews are best effort and may take a while.

## Report a bug

1. Run `fileparcel doctor` on the server. It checks the installation and often says what is wrong
   (`fileparcel doctor --fix` repairs the safe things). Also look through the
   [troubleshooting FAQ](docs/FILEPARCEL.md#troubleshooting-and-faq),
   [Fix installation problems](docs/INSTALL.md#fix-installation-problems) and the
   [existing issues](https://github.com/kpdirectmail/fileparcel/issues).
2. [Open a bug report](https://github.com/kpdirectmail/fileparcel/issues/new/choose). The form asks for:
   - the output of `fileparcel version`,
   - the operating system and processor of the server, and how FileParcel is installed (user service,
     system service, Docker, …),
   - the browser and device, if the problem is in the web app,
   - the steps to reproduce it, what you expected and what happened instead,
   - the output of `fileparcel doctor` and the relevant lines of `fileparcel logs -n 100`.
3. **Issues are public.** Before you paste output, remove passwords, tokens, share links, backup identities
   and recovery keys, and replace host names, user names and IP addresses you do not want to publish with
   placeholders. The log never contains passwords or keys, but it does contain names and addresses.

## Report a security problem

Do **not** open a public issue. Report it privately through
[GitHub's private vulnerability reporting](https://github.com/kpdirectmail/fileparcel/security/advisories/new).
[SECURITY.md](docs/SECURITY.md#reporting-a-vulnerability) says what to include and what to expect.

## Request a feature

[Open a feature request](https://github.com/kpdirectmail/fileparcel/issues/new/choose) and describe the
problem you want solved, not only the solution. FileParcel tries to stay one small program that is private
by default and easy to run at home or in a small office, so some ideas will not fit; for anything larger
than a small fix, please open an issue and agree on the approach before writing the code.

## Build FileParcel

You need `git`, a POSIX shell and Go 1.26 or newer. No C compiler, Node.js or database server is needed.

```sh
git clone https://github.com/kpdirectmail/fileparcel
cd fileparcel
scripts/get-go.sh 1.27.1    # optional: installs Go 1.27.1 into ~/sdk, checksum-verified
. scripts/env.sh            # in every shell: puts that Go on PATH and sets GOTOOLCHAIN=local
make build                  # bin/fileparcel for this machine
make dev                    # a dev server on https://127.0.0.1:18443 with a scratch home
```

`make help` lists every target. Never test against a real installation: `make dev`, the test suites and
the examples in the [Development guide](docs/DEVELOPMENT.md#2-build-test-run) all use a throw-away home on
ports of their own.

## Test your change

| Command | What it runs | Needs |
|---|---|---|
| `make test` | `go test ./...`: unit and integration tests, plus `tests/docs` (links and anchors in the docs, canonical command names, the generated references) | Go |
| `make lint` | `gofmt -s` check, `go vet`, `staticcheck`, and `shellcheck` when installed | Go, internet for `staticcheck` |
| `make e2e` | an end-to-end run against a freshly built server over HTTPS | `curl`, `python3`, `openssl`, `unzip`, `tar` |
| `make ui` | the Playwright tests of the web app (creates `tests/ui/.venv` on first use) | `python3` with `venv`, internet for the first run |
| `make smoke` | the live smoke run of every API group (about 15 minutes, 1.5 GiB free disk) | `bash`, `python3` |

At least `make test` must pass for every change; run `make e2e` and `make ui` when you touch the server or
the web app. If you changed a command's help text or a setting, regenerate the references and commit the
result:

```sh
sh scripts/gen-cli-docs.sh          # the command reference in docs/COMMANDS.md
sh scripts/gen-settings-docs.sh     # the settings reference in docs/FILEPARCEL.md
```

## Style

- **Go**: formatted with `gofmt -s`, checked with `go vet` and `staticcheck`. Follow the package layout,
  import rules and conventions of the [Development guide](docs/DEVELOPMENT.md#3-rules): parameterized SQL
  only, never log secrets, errors as `*core.Error`, fakes in `_test.go` files.
- **Web app**: plain ES modules and hand-written CSS, no build step and no npm. Every module starts with
  `// @ts-check`; build the DOM with `h()` and `textContent`, never `innerHTML`, inline handlers or inline
  styles (the Content Security Policy enforces this).
- **Shell scripts**: POSIX `sh` (they must run with dash and macOS bash 3.2), clean under `shellcheck`.
- **Commands**: the help texts follow the rules in
  [Adding a command](docs/DEVELOPMENT.md#adding-a-command); renamed commands keep their old names working.
- **Docs**: plain, short sentences for people who are not experts; every relative link and `#anchor` must
  resolve (`go test ./tests/docs` checks them). Example data uses made-up names (`alice`, `bob`, `Design`)
  and documentation addresses (`192.168.1.20`, `example.com`), never real ones.
- Keep tests, screenshots and logs free of real names, host names, IP addresses and secrets.

## Send a change

1. Fork the repository and create a branch for your change. Do not enable the release hook
   (`make hooks`) in your clone: releases are made by the maintainers.
2. Keep the change focused: one fix or feature per pull request, with its tests and documentation.
3. Changes to the shared contracts (`internal/core`, the database migrations, `internal/wire`, the router,
   `go.mod`), new dependencies and database schema changes need agreement in an issue first; see
   [Sending a change](docs/DEVELOPMENT.md#8-sending-a-change).
4. Open a pull request. The template asks what changed and why, and which checks you ran.

A `Signed-off-by` line is **not** required, and there is no contributor license agreement. By sending a
contribution you agree that it is licensed under the project's [Apache License 2.0](LICENSE), as section 5
of that license describes.
