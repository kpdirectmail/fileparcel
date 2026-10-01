# syntax=docker/dockerfile:1
# FileParcel container image (DESIGN §14.7): a static, CGO-free binary on
# distroless, running as uid 65532 with everything in the /data volume.
# The build context is the source tree: the repository, or src/ of a release
# zip (whose top-level docker-compose.yml builds from src/).
#
#   docker build -t fileparcel .
#   docker build -t fileparcel --build-arg VERSION=v1 --build-arg COMMIT=$(git rev-parse --short=12 HEAD) .
#   docker buildx build --platform linux/amd64,linux/arm64,linux/arm/v7 -t fileparcel .
#
# See docker-compose.yml and docs/INSTALL.md ("Run FileParcel in Docker") for running it.

FROM --platform=$BUILDPLATFORM golang:1.27.1 AS build
ARG TARGETOS TARGETARCH TARGETVARIANT VERSION=dev COMMIT=unknown DATE=
WORKDIR /src
ENV GOTOOLCHAIN=local
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod go mod download
COPY . .
RUN --mount=type=cache,target=/go/pkg/mod --mount=type=cache,target=/root/.cache/go-build \
    set -eu; \
    if [ "$TARGETARCH" = arm ]; then GOARM="${TARGETVARIANT#v}"; export GOARM; fi; \
    [ -n "$DATE" ] || DATE=$(date -u +%Y-%m-%dT%H:%M:%SZ); \
    CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -trimpath -buildvcs=false \
      -ldflags "-s -w -X fileparcel/internal/buildinfo.Version=$VERSION -X fileparcel/internal/buildinfo.Commit=$COMMIT -X fileparcel/internal/buildinfo.Date=$DATE" \
      -o /out/fileparcel ./cmd/fileparcel; \
    mkdir -p /out/data

FROM gcr.io/distroless/static-debian12:nonroot
LABEL org.opencontainers.image.title="FileParcel" \
      org.opencontainers.image.description="Self-hosted, encrypted file sharing" \
      org.opencontainers.image.licenses="Apache-2.0"
COPY --from=build /out/fileparcel /usr/local/bin/fileparcel
# An empty /data owned by the runtime user, so a fresh named volume is writable.
COPY --from=build --chown=65532:65532 --chmod=0750 /out/data /data
ENV FILEPARCEL_HOME=/data
VOLUME /data
EXPOSE 8443 8080
USER 65532:65532
HEALTHCHECK --interval=30s --timeout=10s --start-period=60s --retries=3 \
    CMD ["/usr/local/bin/fileparcel","healthcheck"]
ENTRYPOINT ["/usr/local/bin/fileparcel"]
CMD ["serve","--init-if-missing"]
