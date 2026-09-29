#!/usr/bin/env bash
# End-to-end scenarios for verify-testbed-isolation.sh.
#
# The static half of the check is unit-tested in test_isolation_checks.py.
# These are the cases that can only be settled by running real containers:
# what the check does about a port published by a *different* service, about a
# port bound by the testbed on some other number, and about a testbed
# container that already existed before the check ran.
#
# Each scenario builds its own compose file under a separate project name, so
# nothing here touches a real stack.
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VERIFY="${REPO_ROOT}/scripts/verify-testbed-isolation.sh"
WORK="$(mktemp -d)"
PROJECT="mihakk-scenario"
CONTAINER="mihakk-scenario-testbed"
IMAGE="mihakk-testbed:dev"

PASS=0
FAIL=0

ok()   { printf '  \033[32mPASS\033[0m  %s\n' "$1"; PASS=$((PASS + 1)); }
bad()  { printf '  \033[31mFAIL\033[0m  %s\n' "$1"; FAIL=$((FAIL + 1)); }
note() { printf '        %s\n' "$1"; }

compose_for() { echo "${WORK}/$1.yml"; }
dc() { docker compose -f "$(compose_for "$1")" "${@:2}"; }

teardown() {
  local variant="$1"
  dc "${variant}" down --remove-orphans --volumes >/dev/null 2>&1 || true
}

cleanup() {
  for variant in isolated sidecar-8000 testbed-odd-port; do
    [[ -f "$(compose_for "${variant}")" ]] && teardown "${variant}"
  done
  rm -rf "${WORK}"
}
trap cleanup EXIT

run_verify() {
  local variant="$1"
  MIHAKK_COMPOSE_FILE="$(compose_for "${variant}")" \
  MIHAKK_TESTBED_CONTAINER="${CONTAINER}" \
    "${VERIFY}" >"${WORK}/out.txt" 2>&1
  return $?
}

# --- compose variants -------------------------------------------------------

write_isolated() {
  cat >"$(compose_for isolated)" <<YAML
name: ${PROJECT}
services:
  testbed:
    build:
      context: ${REPO_ROOT}/testbed
    image: ${IMAGE}
    container_name: ${CONTAINER}
    networks: [scenario-internal]
networks:
  scenario-internal:
    name: ${PROJECT}-internal
    internal: true
YAML
}

# Another service publishes host port 8000 while the testbed publishes nothing.
write_sidecar_8000() {
  cat >"$(compose_for sidecar-8000)" <<YAML
name: ${PROJECT}
services:
  testbed:
    build:
      context: ${REPO_ROOT}/testbed
    image: ${IMAGE}
    container_name: ${CONTAINER}
    networks: [scenario-internal]
  dashboard:
    image: ${IMAGE}
    container_name: ${PROJECT}-dashboard
    command: ["python3", "-u", "app.py"]
    ports:
      - "8000:8000"
    networks: [scenario-public]
networks:
  scenario-internal:
    name: ${PROJECT}-internal
    internal: true
  scenario-public:
    name: ${PROJECT}-public
YAML
}

# The testbed binds a host port that is not 8000.
write_testbed_odd_port() {
  cat >"$(compose_for testbed-odd-port)" <<YAML
name: ${PROJECT}
services:
  testbed:
    build:
      context: ${REPO_ROOT}/testbed
    image: ${IMAGE}
    container_name: ${CONTAINER}
    ports:
      - "19999:8000"
    networks: [scenario-public]
networks:
  scenario-public:
    name: ${PROJECT}-public
YAML
}

# docker inspect prints a blank line to stdout for a missing container before
# it exits non-zero, so the raw substitution is "\nabsent" rather than
# "absent". Strip whitespace and decide on emptiness instead.
container_id() {
  docker inspect -f '{{.Id}}' "${CONTAINER}" 2>/dev/null | tr -d '[:space:]'
}

container_state() {
  local status
  status="$(docker inspect -f '{{.State.Status}}' "${CONTAINER}" 2>/dev/null | tr -d '[:space:]')"
  [[ -z "${status}" ]] && status="absent"
  printf '%s' "${status}"
}

echo "building the testbed image once"
write_isolated
dc isolated build testbed >/dev/null 2>&1 || {
  echo "could not build the testbed image" >&2
  exit 1
}

# --- Scenario 1 -------------------------------------------------------------
echo
echo "== 1. another service publishes host port 8000; the testbed does not =="
write_sidecar_8000
teardown sidecar-8000
dc sidecar-8000 up -d dashboard >/dev/null 2>&1
if [[ "$(docker inspect -f '{{.State.Running}}' "${PROJECT}-dashboard" 2>/dev/null)" != "true" ]]; then
  note "could not publish host port 8000 (something else may be using it)"
  bad "scenario 1 could not be set up"
else
  note "dashboard is publishing host port 8000"
  if run_verify sidecar-8000; then
    ok "isolation check passes: another service's published port is not the testbed's problem"
  else
    bad "isolation check failed although only the dashboard published a port"
    sed -n '1,40p' "${WORK}/out.txt"
  fi
fi
teardown sidecar-8000

# --- Scenario 2 -------------------------------------------------------------
echo
echo "== 2. the testbed binds host port 19999 (not its own 8000) =="
write_testbed_odd_port
teardown testbed-odd-port
if run_verify testbed-odd-port; then
  bad "isolation check passed although the testbed published host port 19999"
else
  if grep -q "19999" "${WORK}/out.txt"; then
    ok "isolation check rejects a testbed host binding on any port, naming 19999"
  else
    bad "check failed, but never mentioned the offending port 19999"
    sed -n '1,40p' "${WORK}/out.txt"
  fi
fi
teardown testbed-odd-port

# --- Scenario 3 -------------------------------------------------------------
echo
echo "== 3. a testbed container that already exists but is stopped =="
write_isolated
teardown isolated
dc isolated up -d testbed >/dev/null 2>&1
dc isolated stop testbed >/dev/null 2>&1
BEFORE_ID="$(container_id)"
BEFORE_STATE="$(container_state)"
note "before: state=${BEFORE_STATE} id=${BEFORE_ID:0:12}"

if [[ "${BEFORE_STATE}" != "exited" ]]; then
  bad "could not set up a stopped testbed container (state=${BEFORE_STATE})"
else
  run_verify isolated
  RC=$?
  AFTER_ID="$(container_id)"
  AFTER_STATE="$(container_state)"
  note "after:  state=${AFTER_STATE} id=${AFTER_ID:0:12} (verify exit ${RC})"

  if [[ -z "${AFTER_ID}" ]]; then
    bad "the pre-existing container was deleted by the check"
  elif [[ "${AFTER_ID}" != "${BEFORE_ID}" ]]; then
    bad "the pre-existing container was replaced (id changed)"
  elif [[ "${AFTER_STATE}" != "exited" ]]; then
    bad "the pre-existing container was left in state ${AFTER_STATE}, not stopped"
  elif [[ ${RC} -ne 0 ]]; then
    bad "the check itself failed on an isolated config (exit ${RC})"
    sed -n '1,40p' "${WORK}/out.txt"
  else
    ok "a pre-existing stopped container survives, keeps its identity, and is left stopped"
  fi
fi
teardown isolated

# --- Scenario 4 -------------------------------------------------------------
echo
echo "== 4. a testbed container that is already running =="
write_isolated
teardown isolated
dc isolated up -d testbed >/dev/null 2>&1
BEFORE_ID="$(container_id)"
note "before: state=$(container_state) id=${BEFORE_ID:0:12}"

run_verify isolated
RC=$?
AFTER_ID="$(container_id)"
AFTER_STATE="$(container_state)"
note "after:  state=${AFTER_STATE} id=${AFTER_ID:0:12} (verify exit ${RC})"

if [[ "${AFTER_STATE}" != "running" ]]; then
  bad "a testbed that was already running was left in state ${AFTER_STATE}"
elif [[ "${AFTER_ID}" != "${BEFORE_ID}" ]]; then
  bad "the running container was replaced (id changed)"
elif [[ ${RC} -ne 0 ]]; then
  bad "the check itself failed on an isolated config (exit ${RC})"
else
  ok "a running container is left running, with its identity intact"
fi
teardown isolated

# --- Scenario 5 -------------------------------------------------------------
echo
echo "== 5. no container beforehand: the check cleans up after itself =="
write_isolated
teardown isolated
if [[ "$(container_state)" != "absent" ]]; then
  bad "could not reach a clean starting state"
else
  run_verify isolated
  RC=$?
  AFTER_STATE="$(container_state)"
  note "after:  state=${AFTER_STATE} (verify exit ${RC})"
  if [[ "${AFTER_STATE}" != "absent" ]]; then
    bad "the check left behind a container it created (state=${AFTER_STATE})"
  elif [[ ${RC} -ne 0 ]]; then
    bad "the check itself failed on an isolated config (exit ${RC})"
  else
    ok "a container the check created is removed again"
  fi
fi
teardown isolated

echo
echo "================================"
printf 'passed: %d   failed: %d\n' "${PASS}" "${FAIL}"
[[ ${FAIL} -gt 0 ]] && exit 1
echo "all isolation scenarios behaved correctly"
