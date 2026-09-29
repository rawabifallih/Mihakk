#!/usr/bin/env bash
# Does the live integration test leave a neighbouring stack alone?
#
# An earlier version of test-integration-orchestrator.sh brought the shared
# `mihakk` project up and ran `down -v --remove-orphans` in its exit trap: it
# would stop whatever the operator had running and delete the project's named
# volumes -- the engine's stored sessions, cases and audit log, and the
# orchestrator's SQLite. The fix needs a test that fails if it is ever undone.
#
# The first attempt at that test made the same mistake it was testing for: it
# planted a decoy under the REAL pinned names (mihakk_engine-data,
# mihakk-testbed) and then deleted them on the strength of believing it had
# created them. One wrong inventory and it would have destroyed the very data at
# issue.
#
# So nothing here is named after the real project. Instead the test builds a
# REPRESENTATIVE stack in a namespace of its own -- a compose file derived from
# the committed one with every pinned name rewritten into
# mihakk-decoy-<pid>-<ts> -- brings it up, and points the live test at that same
# file through MIHAKK_COMPOSE_FILE. That keeps the test meaningful: a live script
# that reverted to "use the project the file names, then down -v" would now
# destroy the representative stack, because the representative stack is what the
# file names. Surviving is evidence again, instead of being out of range.
#
# Every name is claimed before use through claim_name.py, which fails CLOSED: an
# inventory that errors, or answers about a different name, refuses the name
# rather than assuming it is free. Only names claimed successfully are ever
# removed.
#
# Checked on both paths, because cleanup runs on both:
#   1. after the live test SUCCEEDS,
#   2. after it is INTERRUPTED mid-run, which is when a trap that reaches too far
#      does its damage.
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# Overridable so this test can be tested: pointing it at a deliberately
# defective live script must make the checks below FAIL. Now that the stack at
# risk is the representative one, that proof can be run without endangering
# anything real.
LIVE_TEST="${MIHAKK_LIVE_TEST:-${REPO_ROOT}/scripts/test-integration-orchestrator.sh}"
CLAIM="${REPO_ROOT}/scripts/claim_name.py"
REAL_COMPOSE="${REPO_ROOT}/deploy/docker-compose.yml"
WORK="$(mktemp -d)"

# A namespace of our own. Nothing in the real project's namespace is touched.
NS="mihakk-decoy-$$-$(date +%s)"
DECOY_PROJECT="${NS}"
DECOY_VOLUME="${NS}_engine-data"
DECOY_CONTAINER="${NS}-testbed"
MARKER="sessions/decoy/cases.jsonl"
MARKER_TEXT="pre-existing engine data that must survive the test run"

export MIHAKK_CONTROL_TOKEN="${MIHAKK_CONTROL_TOKEN:-$(head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n')}"
# The orchestrator refuses to serve anything without this, so a real one is
# generated per run rather than a placeholder.
export MIHAKK_DASHBOARD_TOKEN="${MIHAKK_DASHBOARD_TOKEN:-$(head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n')}"

PASS=0
FAIL=0
ok()   { printf '  \033[32mPASS\033[0m  %s\n' "$1"; PASS=$((PASS + 1)); }
bad()  { printf '  \033[31mFAIL\033[0m  %s\n' "$1"; FAIL=$((FAIL + 1)); }
note() { printf '        %s\n' "$1"; }

# Only names this run claimed successfully may be removed.
CLAIMED_VOLUME=0
STACK_UP=0

cleanup() {
  local rc=$?
  trap - EXIT INT TERM
  if [[ "${STACK_UP}" == "1" ]]; then
    docker compose -f "${WORK}/representative.json" down -v >/dev/null 2>&1 || true
  fi
  if [[ "${CLAIMED_VOLUME}" == "1" ]]; then
    docker volume rm -f "${DECOY_VOLUME}" >/dev/null 2>&1 || true
  fi
  rm -rf "${WORK}"
  exit "${rc}"
}
trap cleanup EXIT INT TERM

# claim <name> <kind>: 0 free, non-zero refused. Never assumes.
claim() {
  local name="$1" kind="$2" output rc explanation verdict
  case "${kind}" in
    volume)    output="$(docker volume ls -q --filter "name=^${name}$" 2>/dev/null)"; rc=$? ;;
    container) output="$(docker ps -a --filter "name=^${name}$" --format '{{.Names}}' 2>/dev/null)"; rc=$? ;;
    network)   output="$(docker network ls --filter "name=^${name}$" --format '{{.Name}}' 2>/dev/null)"; rc=$? ;;
    *)         bad "claim: unknown kind ${kind}"; return 1 ;;
  esac
  explanation="$(python3 "${CLAIM}" "${name}" "${rc}" "${output}" 2>&1)"
  verdict=$?
  if [[ ${verdict} -ne 0 ]]; then
    note "${explanation}"
  fi
  return ${verdict}
}

# --- 0. the guard itself ----------------------------------------------------
# The claim step is what authorises every later removal, so it is checked before
# anything is created. Both failure modes must refuse.
echo "== 0. the name guard refuses rather than assumes =="

GUARD_NAME="${NS}-guardcheck"

# (a) a resource that already exists under the chosen name.
# This one is deliberately created by this run, under this run's unique prefix,
# so removing it afterwards is unambiguous.
if docker volume create "${GUARD_NAME}" >/dev/null 2>&1; then
  if claim "${GUARD_NAME}" volume; then
    bad "the guard called an existing name free"
  else
    ok "an existing resource under the chosen name is refused, not written over"
  fi
  if docker volume inspect "${GUARD_NAME}" >/dev/null 2>&1; then
    ok "the refused resource is still there: refusing did not delete it"
  else
    bad "the refused resource was deleted"
  fi
  docker volume rm -f "${GUARD_NAME}" >/dev/null 2>&1
else
  bad "could not create the guard-check volume"
fi

# (b) an inventory that cannot be read. A stub docker earlier in PATH fails the
# listing, the same trick scripts/test-unverified-paths.sh uses.
mkdir -p "${WORK}/stub"
cat >"${WORK}/stub/docker" <<'STUB'
#!/usr/bin/env bash
# Fails exactly the inventory call, passes nothing else through: this stub is
# only ever consulted for the claim step below.
if [[ "${1:-}" == "volume" && "${2:-}" == "ls" ]]; then
  echo "cannot connect to the Docker daemon" >&2
  exit 1
fi
exit 1
STUB
chmod +x "${WORK}/stub/docker"

STUB_OUTPUT="$(PATH="${WORK}/stub:${PATH}" docker volume ls -q --filter "name=^${GUARD_NAME}$" 2>/dev/null)"
STUB_RC=$?
python3 "${CLAIM}" "${GUARD_NAME}" "${STUB_RC}" "${STUB_OUTPUT}" >/dev/null 2>&1
GUARD_VERDICT=$?
if [[ "${GUARD_VERDICT}" == "2" ]]; then
  ok "an inventory that cannot be read is UNKNOWN, so the name is refused (fails closed)"
else
  bad "a failed inventory produced verdict ${GUARD_VERDICT}; it must be 2 (unknown)"
fi

# --- 1. build the representative stack --------------------------------------
echo
echo "== 1. a representative stack, in a namespace of its own =="

if ! docker compose -f "${REAL_COMPOSE}" config --format json >"${WORK}/resolved.json" 2>"${WORK}/resolve.err"; then
  bad "the committed compose file could not be resolved"
  sed 's/^/        /' "${WORK}/resolve.err"
  exit 1
fi

# A free port, so the representative orchestrator cannot collide with a real one.
REP_PORT="$(python3 -c '
import socket
s = socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1]); s.close()
')"

# Rewrite every pinned name into this run's namespace. The representative stack
# is therefore a faithful copy of the real layout -- same services, same pinned
# style -- that shares no name with it.
if ! python3 - "${WORK}/resolved.json" "${NS}" "${REP_PORT}" >"${WORK}/representative.json" <<'PY'
import json, sys

config = json.load(open(sys.argv[1]))
ns, port = sys.argv[2], sys.argv[3]

config["name"] = ns
for service, body in (config.get("services") or {}).items():
    body["container_name"] = f"{ns}-{service}"
for network, body in (config.get("networks") or {}).items():
    if isinstance(body, dict):
        body["name"] = f"{ns}-{network}"
for volume, body in (config.get("volumes") or {}).items():
    if isinstance(body, dict):
        body["name"] = f"{ns}_{volume}"

orch = (config.get("services") or {}).get("orchestrator")
if orch and orch.get("ports"):
    first = orch["ports"][0]
    orch["ports"] = [{"mode": first.get("mode", "ingress"), "target": first["target"],
                      "published": str(port), "protocol": first.get("protocol", "tcp"),
                      "host_ip": "127.0.0.1"}]

json.dump(config, sys.stdout, indent=2)
PY
then
  bad "could not build the representative compose file"
  exit 1
fi
note "namespace ${NS}, orchestrator on port ${REP_PORT}"

# Claim every name the representative stack will use.
for claimed in "${DECOY_VOLUME}:volume" "${DECOY_CONTAINER}:container"; do
  if ! claim "${claimed%%:*}" "${claimed##*:}"; then
    bad "refusing to build the representative stack: ${claimed%%:*} is not free"
    exit 1
  fi
done
ok "every representative name was claimed through the fail-closed guard"

# The volume that stands in for real engine data. Declared by the representative
# compose file, so `down -v` on that project would remove it -- which is exactly
# the damage being watched for.
if ! docker volume create "${DECOY_VOLUME}" >/dev/null 2>&1; then
  bad "could not create the representative volume"
  exit 1
fi
CLAIMED_VOLUME=1

if ! docker run --rm -v "${DECOY_VOLUME}:/data" alpine:3.21 \
      sh -c "mkdir -p /data/sessions/decoy && printf '%s' '${MARKER_TEXT}' > /data/${MARKER}" \
      >/dev/null 2>&1; then
  bad "could not write the marker into the representative volume"
  exit 1
fi

read_marker() {
  docker run --rm -v "${DECOY_VOLUME}:/data" alpine:3.21 \
    sh -c "cat /data/${MARKER} 2>/dev/null" 2>/dev/null
}

if [[ "$(read_marker)" != "${MARKER_TEXT}" ]]; then
  bad "the marker did not read back after being written"
  exit 1
fi

# One service of the representative stack running, standing in for a stack the
# operator left up. Compose uses the project name the file pins.
STACK_UP=1
if ! docker compose -f "${WORK}/representative.json" up -d --build testbed \
      >"${WORK}/rep-up.log" 2>&1; then
  bad "the representative stack did not come up"
  tail -10 "${WORK}/rep-up.log" | sed 's/^/        /'
  exit 1
fi

REP_ID_BEFORE="$(docker inspect -f '{{.Id}}' "${DECOY_CONTAINER}" 2>/dev/null)"
if [[ -z "${REP_ID_BEFORE}" ]]; then
  bad "the representative container is not there after bringing it up"
  exit 1
fi
ok "the representative stack is up: project ${DECOY_PROJECT}, container ${REP_ID_BEFORE:0:12}"
note "a live script that used the project its compose file names would destroy this"

# --- assertions -------------------------------------------------------------
assert_representative_intact() {
  local after_what="$1" id state marker

  id="$(docker inspect -f '{{.Id}}' "${DECOY_CONTAINER}" 2>/dev/null)"
  state="$(docker inspect -f '{{.State.Running}}' "${DECOY_CONTAINER}" 2>/dev/null)"

  if [[ -z "${id}" ]]; then
    bad "${after_what}: the representative container was removed"
  elif [[ "${id}" != "${REP_ID_BEFORE}" ]]; then
    bad "${after_what}: the representative container was replaced (${REP_ID_BEFORE:0:12} -> ${id:0:12})"
  elif [[ "${state}" != "true" ]]; then
    bad "${after_what}: the representative container was stopped"
  else
    ok "${after_what}: the neighbouring container is still running, same id"
  fi

  if ! docker volume inspect "${DECOY_VOLUME}" >/dev/null 2>&1; then
    bad "${after_what}: the neighbouring volume was deleted"
    return
  fi
  marker="$(read_marker)"
  if [[ "${marker}" == "${MARKER_TEXT}" ]]; then
    ok "${after_what}: the neighbouring volume still holds its data, unchanged"
  else
    bad "${after_what}: the volume's data changed or vanished (read: '${marker}')"
  fi
}

# --- 2. after a successful run ----------------------------------------------
echo
echo "== 2. the live test runs to completion against the representative file =="
if MIHAKK_COMPOSE_FILE="${WORK}/representative.json" \
   "${LIVE_TEST}" >"${WORK}/live.log" 2>&1; then
  ok "the live integration test passed"
else
  bad "the live integration test did not pass"
  tail -20 "${WORK}/live.log" | sed 's/^/        /'
fi
assert_representative_intact "after a successful run"

# --- 3. after an interrupted run --------------------------------------------
echo
echo "== 3. the live test is interrupted mid-run =="
MIHAKK_COMPOSE_FILE="${WORK}/representative.json" \
  "${LIVE_TEST}" >"${WORK}/live-abort.log" 2>&1 &
LIVE_PID=$!

STARTED=0
for _ in $(seq 1 240); do
  if docker ps -a --filter "name=mihakk-live-" --format '{{.Names}}' 2>/dev/null | grep -q .; then
    STARTED=1
    break
  fi
  kill -0 "${LIVE_PID}" 2>/dev/null || break
  sleep 1
done

if [[ "${STARTED}" != "1" ]]; then
  bad "the live test never brought its own containers up, so the interruption proves nothing"
  wait "${LIVE_PID}" 2>/dev/null
else
  note "its containers are up; sending SIGTERM"
  kill -TERM "${LIVE_PID}" 2>/dev/null
  wait "${LIVE_PID}" 2>/dev/null
  ok "the interrupted run exited"
  assert_representative_intact "after an interrupted run"

  LEFTOVER="$(docker ps -aq --filter "name=mihakk-live-" 2>/dev/null | wc -l | tr -d ' ')"
  if [[ "${LEFTOVER}" == "0" ]]; then
    ok "the interrupted run removed its own containers"
  else
    bad "the interrupted run left ${LEFTOVER} of its own container(s) behind"
  fi
  LEFTOVER_VOL="$(docker volume ls -q --filter "name=mihakk-live-" 2>/dev/null | wc -l | tr -d ' ')"
  if [[ "${LEFTOVER_VOL}" == "0" ]]; then
    ok "the interrupted run removed its own volumes"
  else
    bad "the interrupted run left ${LEFTOVER_VOL} of its own volume(s) behind"
  fi
fi

echo
echo "================================"
printf 'passed: %d   failed: %d\n' "${PASS}" "${FAIL}"
if [[ "${FAIL}" -eq 0 ]]; then
  echo "the live test isolates its own project and leaves a neighbouring stack alone"
  exit 0
fi
echo "the live test reaches outside its own project"
exit 1
