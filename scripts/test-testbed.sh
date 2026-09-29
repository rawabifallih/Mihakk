#!/usr/bin/env bash
# Run the testbed's own tests inside Docker, with --network none.
#
# The testbed uses the standard library only, so it needs no package installs
# and no network at any point. Running with --network none proves that: the
# tests bind a server on loopback inside the container and nothing reaches out.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
IMAGE="${MIHAKK_PYTHON_IMAGE:-python:3.11-alpine}"

echo "==> testbed application tests"
docker run --rm \
  -v "${REPO_ROOT}/testbed:/app" \
  -w /app \
  --network none \
  "${IMAGE}" python3 -m unittest "$@" test_app

# The static half of the isolation check is a pure function of the resolved
# compose config, so it is unit-tested here against synthetic configurations.
# The runtime half is exercised by verify-testbed-isolation.sh.
echo
echo "==> testbed isolation check tests"
docker run --rm \
  -v "${REPO_ROOT}/scripts:/checks" \
  -w /checks \
  --network none \
  "${IMAGE}" python3 -m unittest "$@" test_isolation_checks

# Strict readers for docker/compose output: every unreadable input must be an
# error rather than an empty result, or a check passes on no evidence.
echo
echo "==> unreadable-output handling"
docker run --rm \
  -v "${REPO_ROOT}/scripts:/checks" \
  -w /checks \
  --network none \
  "${IMAGE}" python3 -m unittest "$@" test_container_ports test_check_networks test_check_listeners

# The live integration script reads values that arrived over HTTP and derives a
# throwaway compose project from the real one. Both readers are pure functions of
# their input, so they are unit-tested here -- including the hostile inputs,
# which is the half that matters: a response carrying shell metacharacters must
# be text, and an unreadable response must never read as a pass.
echo
echo "==> run-report and derived-project readers"
docker run --rm \
  -v "${REPO_ROOT}/scripts:/checks" \
  -v "${REPO_ROOT}/dashboard:/dashboard:ro" \
  -w /checks \
  --network none \
  "${IMAGE}" python3 -m unittest "$@" test_read_run_report

# The dashboard is the first component that needs JavaScript, so the report's
# "no script at all" defence does not carry over to it. This is what replaces it,
# and it runs here rather than only in the browser test: it costs a second, so it
# can guard every commit, while the browser costs minutes.
echo
echo "==> dashboard source: no data becomes markup"
docker run --rm \
  -v "${REPO_ROOT}/scripts:/checks" \
  -v "${REPO_ROOT}/dashboard:/dashboard:ro" \
  -w /checks \
  --network none \
  "${IMAGE}" python3 check_dashboard_js.py /dashboard

echo
echo "all testbed checks passed"
