<!-- Thanks for contributing! Please read CONTRIBUTING.md first. Security fixes: report the problem privately
     first (https://github.com/kpdirectmail/fileparcel/security/advisories/new) instead of opening a public PR. -->

## What and why

<!-- What does this change, and why? Link the issue it fixes, e.g. "Fixes #123". -->

## How it was tested

<!-- Tick what you ran. At least the Go checks; "go test ./tests/docs" whenever a help text or a document changed. -->

- [ ] `gofmt -l ./internal ./cmd ./tests` prints nothing
- [ ] `go build ./... && go vet ./... && go test ./...` (or `make test`)
- [ ] `go test -race` for the packages I changed
- [ ] `make e2e`
- [ ] `make ui` (web app changes)
- [ ] Tried it by hand on a scratch server (`make dev`)

## Checklist

- [ ] Docs updated (README, docs/*.md), and `sh scripts/gen-cli-docs.sh` / `sh scripts/gen-settings-docs.sh` run if
      a command's help or a setting changed
- [ ] No change to the shared contracts (DEVELOPMENT.md §3 rule 2), the database schema or DESIGN.md — or it is
      explained below
- [ ] No passwords, keys, personal names, host names or IP addresses in code, tests, logs or screenshots

## Notes for the reviewer

<!-- Deviations from DESIGN.md, anything unfinished, things you are unsure about. -->
