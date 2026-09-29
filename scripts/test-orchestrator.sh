#!/usr/bin/env bash
# Run the orchestrator's tests inside its own image, with --network none.
#
# Dependencies are installed into the image at build time, so the tests need
# no network. Running with --network none proves it, and also proves the
# orchestrator's only outbound path is the engine client -- which the tests
# replace with an in-process fake.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# The test target, not the deployed one: since phase 8a the runtime image carries
# neither pytest nor the test tree, and that is checked below rather than assumed.
IMAGE="${MIHAKK_ORCHESTRATOR_TEST_IMAGE:-mihakk-orchestrator-test:dev}"
RUNTIME_IMAGE="${MIHAKK_ORCHESTRATOR_IMAGE:-mihakk-orchestrator:dev}"

echo "==> building the orchestrator images (runtime and test)"
docker build -q --target test -t "${IMAGE}" -f "${REPO_ROOT}/orchestrator/Dockerfile" \
  "${REPO_ROOT}" >/dev/null
docker build -q --target runtime -t "${RUNTIME_IMAGE}" \
  -f "${REPO_ROOT}/orchestrator/Dockerfile" "${REPO_ROOT}" >/dev/null

# The deployed image is the service and nothing else. Each probe asks for one
# thing and must be refused for that reason: an image that failed to start at all
# would also "lack pytest", so the positive control comes first.
echo "==> the runtime image carries no test tooling"
docker run --rm --network none "${RUNTIME_IMAGE}" \
  python3 -c "import app.main, fastapi, httpx" >/dev/null 2>&1 \
  || { echo "the runtime image cannot import the service itself" >&2; exit 1; }
if docker run --rm --network none "${RUNTIME_IMAGE}" python3 -c "import pytest" >/dev/null 2>&1; then
  echo "the runtime image carries pytest" >&2
  exit 1
fi
if docker run --rm --network none "${RUNTIME_IMAGE}" test -e /srv/tests; then
  echo "the runtime image carries the test tree" >&2
  exit 1
fi
if docker run --rm --network none "${RUNTIME_IMAGE}" test -e /srv/requirements-dev.txt; then
  echo "the runtime image carries the development requirements" >&2
  exit 1
fi
echo "runtime image: service imports, no pytest, no tests/, no dev requirements"

echo "==> orchestrator tests"
# Two read-only mounts, both for the same reason: these tests must use the shared
# artefacts, not copies of them.
#   schemas/ holds the golden aggregate document, asserted from the Go side too.
#   scripts/ holds the HTML tree checker the live integration run uses, so the
#            page is judged here by exactly the code that judges it there.
#   dashboard/ holds the pages this process serves, asserted here for what they
#            must not contain.
exec docker run --rm \
  -v "${REPO_ROOT}/orchestrator:/srv" \
  -v "${REPO_ROOT}/schemas:/schemas:ro" \
  -v "${REPO_ROOT}/scripts:/checks:ro" \
  -v "${REPO_ROOT}/dashboard:/dashboard:ro" \
  -w /srv \
  --network none \
  "${IMAGE}" python3 -m pytest tests -q "$@"
