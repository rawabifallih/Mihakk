#!/usr/bin/env bash
# Run the Go toolchain inside Docker so Go never has to be installed on the host.
#
#   scripts/go.sh test ./...
#   scripts/go.sh build ./cmd/mihakk
#   scripts/go.sh vet ./...
#
# The container runs with --network none: the engine's unit tests are hermetic
# and must never reach the network. Loopback still works, so httptest servers
# inside the container are fine.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
GO_IMAGE="${MIHAKK_GO_IMAGE:-golang:1.25-alpine}"
NETWORK="${MIHAKK_GO_NETWORK:-none}"

mkdir -p "${REPO_ROOT}/.gocache/build" "${REPO_ROOT}/.gocache/mod"

exec docker run --rm \
  -v "${REPO_ROOT}:/src" \
  -v "${REPO_ROOT}/.gocache:/gocache" \
  -w /src/engine \
  -e GOCACHE=/gocache/build \
  -e GOMODCACHE=/gocache/mod \
  -e GOFLAGS="${GOFLAGS:-}" \
  --network "${NETWORK}" \
  "${GO_IMAGE}" go "$@"
