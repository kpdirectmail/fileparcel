# FileParcel - developer shortcuts. Every target is a thin wrapper around the
# scripts in scripts/ or a plain go command; nothing here is needed to build
# FileParcel (scripts/build.sh does that). Works with GNU make and BSD make.
#
#   make build      binary for this machine          -> bin/fileparcel
#   make cross      all release targets in parallel  -> dist/fileparcel-<os>-<arch>
#   make test       go test ./...                     (make test-race: with -race)
#   make vet        go vet ./...
#   make lint       gofmt check + go vet + staticcheck + shellcheck (when installed)
#   make vuln       govulncheck ./...
#   make release    build releases/fileparcel-vN.zip for HEAD (normally done by the hook)
#   make dev        run a dev server on https://127.0.0.1:18443 (scripts/dev.sh)
#   make hooks      enable the release hook (git config core.hooksPath .githooks)
#   make e2e        end-to-end test against a fresh build (tests/e2e/e2e.sh)
#   make ui         Playwright UI tests (tests/ui; creates tests/ui/.venv)
#   make smoke      11-phase live smoke harness (tests/smoke/run_all.sh, ~15 min)
#   make docker     docker build -t fileparcel:dev .
#   make clean      remove bin/ and dist/

SHELL = /bin/sh
# Every recipe line runs in a fresh shell; this finds Go (PATH or ~/sdk/go*/bin)
# and pins GOTOOLCHAIN=local.
GOENV = . ./scripts/env.sh &&
PKG = ./...
STATICCHECK = honnef.co/go/tools/cmd/staticcheck@latest
GOVULNCHECK = golang.org/x/vuln/cmd/govulncheck@latest

.PHONY: all help build cross test test-race vet fmt lint vuln release dev hooks e2e ui smoke docker clean

all: build

help:
	@sed -n '4,18s/^# \{0,1\}//p' Makefile

build:
	sh scripts/build.sh -o bin host

cross:
	sh scripts/build.sh -o dist all

test:
	$(GOENV) go test $(PKG)

test-race:
	$(GOENV) go test -race $(PKG)

vet:
	$(GOENV) go vet $(PKG)

fmt:
	$(GOENV) gofmt -s -w cmd internal web

lint: vet
	@$(GOENV) out=$$(gofmt -s -l cmd internal web); \
	if [ -n "$$out" ]; then echo "gofmt -s would change:"; echo "$$out"; exit 1; fi
	$(GOENV) go run $(STATICCHECK) $(PKG)
	@if command -v shellcheck >/dev/null 2>&1; then \
		shellcheck -s sh install.sh uninstall.sh scripts/*.sh .githooks/post-commit tests/e2e/*.sh; \
		shellcheck -s bash tests/smoke/*.sh; \
	else echo "shellcheck not installed; skipping the shell script lint"; fi

vuln:
	$(GOENV) go run $(GOVULNCHECK) $(PKG)

release:
	sh scripts/release.sh

dev:
	sh scripts/dev.sh

hooks:
	git config core.hooksPath .githooks
	@echo "Release hook enabled: every commit builds releases/fileparcel-vN.zip and tags vN."
	@echo "Skip it for one commit with FILEPARCEL_NO_RELEASE=1 git commit ..."

e2e:
	sh tests/e2e/e2e.sh

ui:
	sh tests/ui/run.sh

# run_all.sh is bash, not sh, and aborts below ~1.5 GiB free in FP_SMOKE_DIR.
smoke:
	FP_SMOKE_DIR=$${FP_SMOKE_DIR:-$${TMPDIR:-/tmp}/fileparcel-smoke} bash tests/smoke/run_all.sh

docker:
	docker build -t fileparcel:dev .

clean:
	rm -rf bin dist
