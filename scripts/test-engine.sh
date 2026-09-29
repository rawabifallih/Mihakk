#!/usr/bin/env bash
# Full engine check: formatting, vet, unit tests, and the race detector.
# Everything runs inside Docker with --network none, so the engine's tests can
# never reach a real target.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ALPINE_IMAGE="${MIHAKK_GO_IMAGE:-golang:1.25-alpine}"
# The race detector needs cgo, which the Debian-based image provides out of the box.
RACE_IMAGE="${MIHAKK_GO_RACE_IMAGE:-golang:1.25}"

mkdir -p "${REPO_ROOT}/.gocache/build" "${REPO_ROOT}/.gocache/mod"

run_go() {
  local image="$1"; shift
  docker run --rm \
    -v "${REPO_ROOT}:/src" \
    -v "${REPO_ROOT}/.gocache:/gocache" \
    -w /src/engine \
    -e GOCACHE=/gocache/build \
    -e GOMODCACHE=/gocache/mod \
    -e CGO_ENABLED="${CGO_ENABLED:-0}" \
    --network none \
    "${image}" "$@"
}

echo "==> gofmt"
unformatted="$(run_go "${ALPINE_IMAGE}" gofmt -l .)"
if [[ -n "${unformatted}" ]]; then
  echo "not gofmt-clean:" >&2
  echo "${unformatted}" >&2
  exit 1
fi

echo "==> go vet"
run_go "${ALPINE_IMAGE}" go vet ./...

echo "==> go test"
run_go "${ALPINE_IMAGE}" go test -count=1 "$@" ./...

echo "==> go test -race"
CGO_ENABLED=1 run_go "${RACE_IMAGE}" go test -race -count=1 ./...

echo "==> go build"
run_go "${ALPINE_IMAGE}" go build -o /dev/null ./cmd/mihakk

echo "all engine checks passed"
