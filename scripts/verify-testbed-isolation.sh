#!/usr/bin/env bash
# Verify that the local testbed is actually isolated.
#
# The acceptance criterion is that isolation is *checked*, not merely asserted
# in a comment, so every claim here is tested against the running system.
#
# Scope: the static checks constrain the `testbed` service alone. Other
# services are left alone on purpose -- the dashboard and the orchestrator API
# will need a published port and a non-internal network in later phases, and a
# check that forbade those everywhere would end up switched off. The static
# analysis itself lives in check_testbed_isolation.py and is unit-tested by
# test_isolation_checks.py.
#
#   static  1. the testbed publishes no ports to the host
#   static  2. EVERY network the testbed attaches to is internal (not merely
#              one of them: a second, non-internal interface would restore
#              egress)
#   runtime 3. the testbed container has no host port binding on ANY port,
#              checked against both the live binding table and the requested
#              port bindings.
#
#              There is deliberately no "connect to localhost:8000 and expect
#              failure" check. It proved nothing: a refused connection does
#              not show the testbed is unpublished, and a successful one does
#              not show the testbed answered it -- another service may publish
#              that port perfectly legitimately. Asking Docker what the
#              testbed container itself binds is the question that matters.
#   runtime 4. the container has no default route (checked in the kernel's
#              routing table, so no packets are sent anywhere)
#   runtime 5. an outbound TCP connect fails. The target is 192.0.2.1 from
#              TEST-NET-1 (RFC 5737), reserved for documentation and never
#              routed on the public internet: no real service is contacted.
#   runtime 6. positive control -- the testbed IS reachable by service name
#              from inside the network, so checks 3-5 cannot pass merely
#              because nothing is running.
#
# Exits non-zero if any check fails.
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# Overridable so test-isolation-scenarios.sh can run this against variant
# compose files under a separate project name, without touching a real stack.
COMPOSE_FILE="${MIHAKK_COMPOSE_FILE:-${REPO_ROOT}/deploy/docker-compose.yml}"
COMPOSE=(docker compose -f "${COMPOSE_FILE}")
# Optional second file, merged on top: deploy/compose.target.yml, when the engine
# has joined an operator's network. Its external network is inspected below and
# counts as internal only if Docker says so.
if [[ -n "${MIHAKK_COMPOSE_OVERLAY:-}" ]]; then
  COMPOSE+=(-f "${MIHAKK_COMPOSE_OVERLAY}")
fi

# The compose file requires a control token to resolve. The value is
# irrelevant here -- nothing is started with it by these checks -- but the
# variable must be set for `compose config` to succeed.
export MIHAKK_CONTROL_TOKEN="${MIHAKK_CONTROL_TOKEN:-isolation-check-placeholder}"
# The compose file now requires the dashboard token as well, for the same
# interpolation reason. This script starts no orchestrator, so the value is
# never used as a credential.
export MIHAKK_DASHBOARD_TOKEN="${MIHAKK_DASHBOARD_TOKEN:-dashboard-placeholder}"
SERVICE="${MIHAKK_TESTBED_SERVICE:-testbed}"
CONTAINER="${MIHAKK_TESTBED_CONTAINER:-mihakk-testbed}"

PASS=0
FAIL=0
UNVERIFIED=0
KEEP_UP="${MIHAKK_KEEP_UP:-0}"
INITIAL_STATE="absent"

ok()   { printf '  \033[32mPASS\033[0m        %s\n' "$1"; PASS=$((PASS + 1)); }
bad()  { printf '  \033[31mFAIL\033[0m        %s\n' "$1"; FAIL=$((FAIL + 1)); }
info() { printf '              %s\n' "$1"; }

# A check whose evidence could not be gathered is NOT a passing check.
# Reporting it separately keeps the distinction visible -- "this is wrong" and
# "I could not tell" are different things to act on -- but both are failures
# of the run: isolation is only verified when it has actually been observed.
unverified() { printf '  \033[33mUNVERIFIED\033[0m  %s\n' "$1"; UNVERIFIED=$((UNVERIFIED + 1)); }

TMP_ERR="$(mktemp)"

# The testbed container can be in one of three states before this runs, and
# each needs different treatment afterwards. Collapsing "stopped" into "absent"
# would delete a container the operator created and merely had stopped.
testbed_state() {
  local running
  running="$(docker inspect -f '{{.State.Running}}' "${CONTAINER}" 2>/dev/null | tr -d '[:space:]')"
  if [[ -z "${running}" ]]; then
    # No such container. docker inspect also prints a blank line here, so
    # emptiness is the reliable signal rather than the exit code alone.
    echo absent
  elif [[ "${running}" == "true" ]]; then
    echo running
  else
    echo stopped
  fi
}

# Put things back exactly as they were. `compose down` would stop every other
# service in the project -- an orchestrator or dashboard that was already
# running before the check started -- which is not this script's business.
# The probe container is disposed of by `compose run --rm`, and the network is
# left in place because it is shared and cheap to keep.
cleanup() {
  rm -f "${TMP_ERR}"
  if [[ "${KEEP_UP}" == "1" ]]; then
    return
  fi
  case "${INITIAL_STATE:-absent}" in
    running)
      : # It was running before this script; leave it running.
      ;;
    stopped)
      # It existed and was stopped. Stop it again, but keep the container:
      # removing it would destroy something this script did not create.
      "${COMPOSE[@]}" stop "${SERVICE}" >/dev/null 2>&1 || true
      ;;
    absent)
      "${COMPOSE[@]}" stop "${SERVICE}" >/dev/null 2>&1 || true
      "${COMPOSE[@]}" rm -f "${SERVICE}" >/dev/null 2>&1 || true
      ;;
  esac
}
trap cleanup EXIT

echo "== static checks on the resolved compose config =="

if ! CONFIG_JSON="$("${COMPOSE[@]}" config --format json 2>"${TMP_ERR}")"; then
  unverified "docker compose config failed: $(tr '\n' ' ' <"${TMP_ERR}" | cut -c1-200)"
  echo
  printf 'passed: %d   failed: %d   unverified: %d\n' "${PASS}" "${FAIL}" "${UNVERIFIED}"
  echo "TESTBED ISOLATION NOT VERIFIED"
  exit 1
fi

# 1 + 2: analyse the *resolved* config rather than grepping the file, so an
# override or an extended service cannot slip a published port past the check.
# The analysis is delegated to check_testbed_isolation.py, which is unit-tested
# against synthetic configs by test_isolation_checks.py.
# No service argument: every service that must be isolated is checked, which
# from phase 5 means the engine's control API as well as the testbed.
# An external network's isolation is not in the config: it is whatever the
# operator created. Each one is inspected, and only those Docker reports internal
# are vouched for; any other stays a problem the checker reports.
VERIFIED_ARGS=()
EXTERNAL_NETWORKS="$(printf '%s' "${CONFIG_JSON}" | python3 -c '
import json, sys
config = json.load(sys.stdin)
for key, body in (config.get("networks") or {}).items():
    if isinstance(body, dict) and body.get("external"):
        print(body.get("name") or key)
' 2>/dev/null)"
for network in ${EXTERNAL_NETWORKS}; do
  INSPECTED="$(docker network inspect "${network}" 2>/dev/null)"
  INSPECT_RC=$?
  VERDICT="$(python3 "${REPO_ROOT}/scripts/check_networks.py" "${INSPECT_RC}" "${INSPECTED}" "${network}")"
  case $? in
    0) VERIFIED_ARGS+=(--verified-internal "${network}"); info "${VERDICT}" ;;
    1) info "${VERDICT}" ;;
    *) unverified "external network ${network}: ${VERDICT}" ;;
  esac
done

# ${arr[@]+...}: bash 3.2 treats an empty array as unset under set -u.
STATIC_RESULT="$(printf '%s' "${CONFIG_JSON}" | python3 "${REPO_ROOT}/scripts/check_testbed_isolation.py" \
  ${VERIFIED_ARGS[@]+"${VERIFIED_ARGS[@]}"} 2>"${TMP_ERR}")"
STATIC_RC=$?

# Exit 2 means the checker could not interpret the config at all. Treating
# that as "no problems found" is the fail-open bug this whole file guards
# against, so it is reported as unverified instead.
if [[ ${STATIC_RC} -eq 2 ]]; then
  unverified "compose config could not be analysed: $(printf '%s' "${STATIC_RESULT}" | python3 -c 'import json,sys
try: print(json.load(sys.stdin).get("error","unknown"))
except Exception: print("unreadable checker output")' 2>/dev/null)"
elif [[ ${STATIC_RC} -ne 0 && ${STATIC_RC} -ne 1 ]]; then
  unverified "the compose checker exited ${STATIC_RC}: $(tr '\n' ' ' <"${TMP_ERR}" | cut -c1-200)"
else
  # Parse once, strictly. If the report cannot be read, nothing about it may
  # be reported as passing.
  STATIC_LINES="$(printf '%s' "${STATIC_RESULT}" | python3 -c '
import json, sys
data = json.load(sys.stdin)
if not isinstance(data, dict) or "problems" not in data or "notes" not in data:
    raise SystemExit("unexpected report shape")
for note in data["notes"]:
    print("NOTE|" + note)
for problem in data["problems"]:
    print("PROBLEM|" + problem)
print("END|")
' 2>/dev/null)"

  if [[ -z "${STATIC_LINES}" ]] || ! grep -q '^END|' <<<"${STATIC_LINES}"; then
    unverified "the compose checker's report could not be read; port and network declarations are unverified"
  else
    STATIC_PROBLEMS=0
    while IFS= read -r line; do
      case "${line}" in
        NOTE\|*)    info "${line#NOTE|}" ;;
        PROBLEM\|*) bad "${line#PROBLEM|}"; STATIC_PROBLEMS=$((STATIC_PROBLEMS + 1)) ;;
      esac
    done <<<"${STATIC_LINES}"

    if [[ ${STATIC_PROBLEMS} -eq 0 ]]; then
      ok "no service that must be isolated publishes a port to the host"
      ok "every network they attach to is internal"
    fi
  fi
fi

echo
echo "== bringing the testbed up =="
INITIAL_STATE="$(testbed_state)"
case "${INITIAL_STATE}" in
  running)
    info "testbed was already running; it will be left running"
    ;;
  stopped)
    info "testbed container exists but is stopped; it will be started and stopped again"
    # `start`, not `up`: up may recreate the container, which would replace
    # something the operator created rather than preserving it.
    if ! "${COMPOSE[@]}" start "${SERVICE}" >/dev/null 2>&1; then
      bad "could not start the existing testbed container"
      exit 1
    fi
    ;;
  absent)
    info "no testbed container; one will be created and removed afterwards"
    if ! "${COMPOSE[@]}" up -d --build "${SERVICE}" >/dev/null 2>&1; then
      bad "could not start the testbed"
      "${COMPOSE[@]}" up -d --build "${SERVICE}" 2>&1 | tail -20
      exit 1
    fi
    ;;
esac

# Wait for the healthcheck rather than sleeping a guessed interval.
#
# Every branch above starts the container, so this wait expiring is not a
# variation to carry on through: it means readiness was never established. The
# expiry used to be swallowed, and the checks ran against a container that might
# still be starting -- so the in-container probe could fail for want of a ready
# app and report it as an isolation failure. That is a check drawing a verdict
# from evidence it does not have, which is the one thing this script is built not
# to do; under a loaded Docker daemon the thirty seconds are not generous.
#
# UNVERIFIED, not FAIL: nothing here says isolation is broken, only that it could
# not be examined.
for _ in $(seq 1 30); do
  STATE="$(docker inspect -f '{{.State.Health.Status}}' "${CONTAINER}" 2>/dev/null || echo unknown)"
  [[ "${STATE}" == "healthy" ]] && break
  sleep 1
done
info "container health: ${STATE:-unknown}"

if [[ "${STATE:-unknown}" != "healthy" ]]; then
  unverified "the testbed never became healthy (last state: ${STATE:-unknown}); the checks below would be examining a container that is not ready, so they were not run"
  echo
  echo "================================"
  printf 'passed: %d   failed: %d   unverified: %d\n' "${PASS}" "${FAIL}" "${UNVERIFIED}"
  echo "TESTBED ISOLATION NOT VERIFIED (the testbed never became ready)"
  exit 1
fi

echo
echo "== runtime checks =="

# 3: the testbed container must bind no host port at all -- any port, not
# just the one it serves on. Both sources are consulted: NetworkSettings.Ports
# is what is live, HostConfig.PortBindings is what was asked for, and they can
# disagree (Docker silently ignores `ports:` on an internal network, so the
# request is visible only in the latter).
# Capture both tables. A failed inspect leaves the variable empty, which the
# strict reader rejects rather than reading as "no bindings".
check_container_ports() {
  local container="$1" label="$2"

  if [[ "$(docker inspect -f '{{.State.Status}}' "${container}" 2>/dev/null | tr -d '[:space:]')" == "" ]]; then
    info "${label}: no container present, port bindings not applicable"
    return 0
  fi

  local live requested report summary
  live="$(docker inspect -f '{{json .NetworkSettings.Ports}}' "${container}" 2>/dev/null)"
  requested="$(docker inspect -f '{{json .HostConfig.PortBindings}}' "${container}" 2>/dev/null)"

  report="$(python3 "${REPO_ROOT}/scripts/check_container_ports.py" "${live}" "${requested}" 2>"${TMP_ERR}")"
  if [[ $? -ne 0 ]]; then
    local reason
    reason="$(printf '%s' "${report}" | python3 -c '
import json, sys
try: print(json.load(sys.stdin).get("error", "unknown"))
except Exception: print("unreadable output")' 2>/dev/null)"
    [[ -z "${reason}" ]] && reason="$(tr '\n' ' ' <"${TMP_ERR}" | cut -c1-200)"
    unverified "${label}: port bindings could not be read: ${reason}"
    return 0
  fi

  summary="$(printf '%s' "${report}" | python3 -c '
import json, sys
data = json.load(sys.stdin)
if not isinstance(data, dict) or "bound" not in data or "exposed" not in data:
    raise SystemExit("unexpected report shape")
print("|".join(["; ".join(data["bound"]), ",".join(data["exposed"])]))
' 2>/dev/null)"

  if [[ -z "${summary}" ]]; then
    unverified "${label}: the port report could not be read; port bindings are unverified"
    return 0
  fi
  local bound="${summary%%|*}" exposed="${summary#*|}"
  if [[ -z "${bound}" ]]; then
    ok "${label} binds no host port on any port (exposed, unpublished: ${exposed})"
  else
    bad "${label} binds host ports: ${bound}"
  fi
}

LIVE_PORTS="$(docker inspect -f '{{json .NetworkSettings.Ports}}' "${CONTAINER}" 2>/dev/null)"
REQUESTED_PORTS="$(docker inspect -f '{{json .HostConfig.PortBindings}}' "${CONTAINER}" 2>/dev/null)"

PORT_REPORT="$(python3 "${REPO_ROOT}/scripts/check_container_ports.py" "${LIVE_PORTS}" "${REQUESTED_PORTS}" 2>"${TMP_ERR}")"
PORT_RC=$?

if [[ ${PORT_RC} -ne 0 ]]; then
  PORT_ERROR="$(printf '%s' "${PORT_REPORT}" | python3 -c '
import json, sys
try: print(json.load(sys.stdin).get("error", "unknown"))
except Exception: print("unreadable output")' 2>/dev/null)"
  [[ -z "${PORT_ERROR}" ]] && PORT_ERROR="$(tr '\n' ' ' <"${TMP_ERR}" | cut -c1-200)"
  unverified "port bindings could not be read: ${PORT_ERROR}"
else
  PORT_SUMMARY="$(printf '%s' "${PORT_REPORT}" | python3 -c '
import json, sys
data = json.load(sys.stdin)
if not isinstance(data, dict) or "bound" not in data or "exposed" not in data:
    raise SystemExit("unexpected report shape")
print("|".join(["; ".join(data["bound"]), ",".join(data["exposed"])]))
' 2>/dev/null)"

  if [[ -z "${PORT_SUMMARY}" ]]; then
    unverified "the port report could not be read; port bindings are unverified"
  else
    BOUND_LIST="${PORT_SUMMARY%%|*}"
    EXPOSED_LIST="${PORT_SUMMARY#*|}"
    if [[ -z "${BOUND_LIST}" ]]; then
      ok "testbed container binds no host port on any port (exposed, unpublished: ${EXPOSED_LIST})"
    else
      bad "testbed container binds host ports: ${BOUND_LIST}"
    fi
  fi
fi

# The engine's control API is a second way to reach the engine, so its port
# gets the same treatment. It is checked only when a container exists: the
# compose file grows across phases, and failing on a service that has not been
# started would be noise rather than a finding.
check_container_ports "${MIHAKK_ENGINE_CONTAINER:-mihakk-engine}" "engine control API container"

# 4, 5, 6: run the in-container probe on the same internal network.
echo
echo "== in-container probe (no default route, no egress, reachable by name) =="
PROBE_OUT="$("${COMPOSE[@]}" run --rm --no-TTY "${SERVICE}" python3 /app/isolation_probe.py 2>"${TMP_ERR}")"
PROBE_RC=$?

# The probe exits non-zero when a check fails, which is a normal result, so
# the report is read rather than discarded on a non-zero exit. What it is read
# by is check_probe_report.py, which refuses three things this script used to
# accept: output it cannot parse, a report missing any of the three required
# checks (any non-empty `checks` mapping was enough), and a report whose
# content contradicts the exit code (the code was never consulted at all).
PROBE_LINES="$(printf '%s' "${PROBE_OUT}" | python3 "${REPO_ROOT}/scripts/check_probe_report.py" "${PROBE_RC}" 2>/dev/null)"

if [[ -z "${PROBE_LINES}" ]]; then
  unverified "the in-container probe produced no readable result (exit ${PROBE_RC}): $(tr '\n' ' ' <"${TMP_ERR}" | cut -c1-160)"
elif grep -q '^invalid|' <<<"${PROBE_LINES}"; then
  unverified "$(grep -m1 '^invalid|' <<<"${PROBE_LINES}" | cut -d'|' -f2-)"
elif ! grep -q '^end|' <<<"${PROBE_LINES}"; then
  unverified "the probe report was truncated before it finished"
else
  while IFS= read -r line; do
    STATUS="${line%%|*}"
    DETAIL="${line#*|}"
    case "${STATUS}" in
      pass)       ok "${DETAIL}" ;;
      fail)       bad "${DETAIL}" ;;
      unverified) unverified "${DETAIL}" ;;
    esac
  done <<<"${PROBE_LINES}"
fi

echo
echo "================================"
printf 'passed: %d   failed: %d   unverified: %d\n' "${PASS}" "${FAIL}" "${UNVERIFIED}"
if [[ ${FAIL} -gt 0 ]]; then
  echo "TESTBED IS NOT PROPERLY ISOLATED"
  exit 1
fi
if [[ ${UNVERIFIED} -gt 0 ]]; then
  # Nothing was observed to be wrong, but something could not be observed at
  # all. That is not a pass.
  echo "TESTBED ISOLATION NOT VERIFIED (${UNVERIFIED} check(s) could not be evaluated)"
  exit 1
fi
if [[ ${PASS} -eq 0 ]]; then
  echo "TESTBED ISOLATION NOT VERIFIED (no checks ran)"
  exit 1
fi
echo "testbed isolation verified"
