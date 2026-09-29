#!/usr/bin/env bash
# Phase 8a, live: the stack reaches an operator's application without owning it.
#
# An operator's application is stood up here as the operator would have it: its
# OWN compose project, its own network (with a local service it depends on), its
# own volume with data in it, and in-memory state that a restart would lose. The
# operator -- this script, acting as them -- creates an internal network and
# attaches the application to it. Mihakk is then started, used, failed,
# interrupted and stopped through scripts/stack.sh, and after every one of those
# the application is compared with how it was before Mihakk existed.
#
#   A1  the engine has no TCP listener off loopback (read from /proc, not probed)
#   A2  from the operator's network, no port on the engine answers -- all 65535
#   A3  the engine does not route between its networks: forwarding is off in its
#       namespace, and a route through it goes nowhere in either direction
#   A4  the six isolation checks pass with the target overlay applied
#   A5  the application, its data, its networks and its neighbours are unchanged
#       after up, down, a failing run, an interrupt, and an engine crash; and it
#       keeps reaching its own network's service throughout
#   A6  stack.sh refuses a real non-internal network and a missing one, and
#       creates neither
#   A7  a session authorised for the application reaches it over the socket and
#       the target network; one aimed at a neighbour it is not authorised for
#       sends that neighbour nothing
#   +   the control socket is 0660 in group 10010, and a process outside the
#       group is refused; every network the engine is on is internal; `down`
#       keeps Mihakk's volumes
#
# Each of A1, A3 and A5 is also shown to FAIL when what it guards is broken, so a
# pass means something. Every name used here is claimed first through
# scripts/claim_name.py, and only claimed names are removed.
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CLAIM="${REPO_ROOT}/scripts/claim_name.py"
STACK="${REPO_ROOT}/scripts/stack.sh"
WORK="$(mktemp -d /tmp/mihakk-stack.XXXXXX)"

NS="mkstk-$$-$(date +%s)"
TARGET_NET="${NS}-target"          # the operator's shared internal network
OWNER_NET="${NS}-owner-net"        # the application's own network
PLAIN_NET="${NS}-plain"            # a non-internal network, for A6
MISSING_NET="${NS}-missing"        # never created
OWNER_VOLUME="${NS}-owner-data"
OWNER_PROJECT="${NS}-owner"
APP="${NS}-owner-app"
PEER="${NS}-owner-peer"
BYSTANDER="${NS}-bystander"
ENGINE="${NS}-engine"
TESTBED="${NS}-testbed"
PROBE_IMAGE="python:3.11-alpine"

export MIHAKK_SECRETS_FILE="${WORK}/secrets/secrets.env"
export MIHAKK_COMPOSE_FILE="${WORK}/stack.json"
export MIHAKK_PORT
MIHAKK_PORT="$(python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1]); s.close()')"

PASS=0
FAIL=0
UNVERIFIED=0
ok()         { printf '  \033[32mPASS\033[0m        %s\n' "$1"; PASS=$((PASS + 1)); }
bad()        { printf '  \033[31mFAIL\033[0m        %s\n' "$1"; FAIL=$((FAIL + 1)); }
unverified() { printf '  \033[33mUNVERIFIED\033[0m  %s\n' "$1"; UNVERIFIED=$((UNVERIFIED + 1)); }
note()       { printf '              %s\n' "$1"; }

CLAIMED=()          # "kind:name" this run may remove
STACK_TOUCHED=0
OWNER_UP=0

cleanup() {
  local rc=$?
  trap - EXIT INT TERM
  if [[ "${STACK_TOUCHED}" == "1" ]]; then
    # The stack under test is this run's own project (namespaced, never the one
    # the real file names), so -v is safe here and only here.
    if [[ "${NS}" == mihakk || -z "${NS}" ]]; then
      echo "refusing to tear down a project named '${NS}'" >&2
    else
      MIHAKK_CONTROL_TOKEN=x MIHAKK_DASHBOARD_TOKEN=x \
        docker compose -f "${MIHAKK_COMPOSE_FILE}" down -v >/dev/null 2>&1 || true
    fi
  fi
  if [[ "${OWNER_UP}" == "1" ]]; then
    docker compose -f "${WORK}/owner.json" down >/dev/null 2>&1 || true
  fi
  docker rm -f "${NS}-probe-a" "${NS}-probe-b" "${NS}-router" "${NS}-sens" >/dev/null 2>&1 || true
  local entry
  for entry in ${CLAIMED[@]+"${CLAIMED[@]}"}; do
    case "${entry}" in
      network:*) docker network rm "${entry#network:}" >/dev/null 2>&1 || true ;;
      volume:*)  docker volume rm -f "${entry#volume:}" >/dev/null 2>&1 || true ;;
    esac
  done
  rm -rf "${WORK}"
  exit "${rc}"
}
trap cleanup EXIT INT TERM

claim() {  # kind name -> 0 only when the name is free
  local kind="$1" name="$2" output rc
  case "${kind}" in
    volume)    output="$(docker volume ls -q --filter "name=^${name}$" 2>/dev/null)"; rc=$? ;;
    network)   output="$(docker network ls --filter "name=^${name}$" --format '{{.Name}}' 2>/dev/null)"; rc=$? ;;
    container) output="$(docker ps -a --filter "name=^${name}$" --format '{{.Names}}' 2>/dev/null)"; rc=$? ;;
  esac
  python3 "${CLAIM}" "${name}" "${rc}" "${output}" >/dev/null 2>&1
}

# docker exec a python one-liner in a container; prints its stdout.
pyexec() { local c="$1"; shift; docker exec "${c}" python3 -c "$@" 2>/dev/null; }

# Talk to the orchestrator with the dashboard token, which travels by environment
# from the secrets file to this helper and is never in this shell.
api() {  # METHOD PATH OUTFILE [BODYFILE] -> prints the status code
  python3 "${REPO_ROOT}/scripts/secrets_file.py" run "${MIHAKK_SECRETS_FILE}" -- \
    python3 "${REPO_ROOT}/scripts/test_stack_api.py" "$1" \
      "http://127.0.0.1:${MIHAKK_PORT}$2" "$3" "${4:-}" "${ENGINE}"
}

# ---------------------------------------------------------------------------
echo "== 0. names, secrets, and the stack under test =="
for entry in "network:${TARGET_NET}" "network:${OWNER_NET}" "network:${PLAIN_NET}" \
             "network:${MISSING_NET}" "volume:${OWNER_VOLUME}" "container:${APP}" \
             "container:${PEER}" "container:${BYSTANDER}" "container:${ENGINE}"; do
  if ! claim "${entry%%:*}" "${entry#*:}"; then
    unverified "the name ${entry#*:} is not free (or could not be checked); refusing to start"
    exit 1
  fi
done
ok "every name this run uses was claimed through the fail-closed guard"

if ! "${REPO_ROOT}/scripts/init-secrets.sh" "${MIHAKK_SECRETS_FILE}" >"${WORK}/init.log" 2>&1; then
  bad "init-secrets.sh failed"; sed 's/^/              /' "${WORK}/init.log"; exit 1
fi
ok "secrets created by init-secrets.sh, outside the repository"

# The committed compose file, uninterpolated, moved into this run's namespace:
# stack.sh drives it unchanged, and the ${...} references are resolved from the
# secrets file and MIHAKK_PORT exactly as for a real stack.
if ! docker compose -f "${REPO_ROOT}/deploy/docker-compose.yml" config --no-interpolate \
      --format json >"${WORK}/resolved.json" 2>"${WORK}/resolve.err" \
   || ! python3 "${REPO_ROOT}/scripts/namespaced_compose.py" "${WORK}/resolved.json" "${NS}" \
      >"${MIHAKK_COMPOSE_FILE}" 2>>"${WORK}/resolve.err"; then
  bad "the committed compose file could not be namespaced"; sed 's/^/              /' "${WORK}/resolve.err"; exit 1
fi
ok "the committed compose file, namespaced as ${NS}, on port ${MIHAKK_PORT}"

# ---------------------------------------------------------------------------
echo
echo "== 1. the operator's application, in a project of its own =="
mkdir -p "${WORK}/owner/peer"
echo "peer-reachable" >"${WORK}/owner/peer/ok.txt"
cat >"${WORK}/owner/app.py" <<'PY'
# The operator's application. It keeps state in memory that a restart would lose
# (boot_id, the request counter) and reads data from its volume. Mihakk never
# writes to it; fuzzing only reads.
import json, os, secrets
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
BOOT = secrets.token_hex(8)
COUNT = {"n": 0}
RECORDS = open("/data/records.json").read()
class H(BaseHTTPRequestHandler):
    def _send(self, code, body):
        raw = json.dumps(body).encode()
        self.send_response(code); self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw))); self.end_headers(); self.wfile.write(raw)
    def do_GET(self):
        if self.path == "/_state":
            return self._send(200, {"boot_id": BOOT, "requests": COUNT["n"]})
        COUNT["n"] += 1
        if self.path.startswith("/api/items"):
            return self._send(200, {"items": json.loads(RECORDS)})
        return self._send(404, {"error": "not found"})
    do_POST = do_GET
    def log_message(self, *a): pass
ThreadingHTTPServer(("0.0.0.0", 8000), H).serve_forever()
PY
cat >"${WORK}/owner.json" <<JSON
{
  "name": "${OWNER_PROJECT}",
  "services": {
    "app": {
      "image": "${PROBE_IMAGE}", "container_name": "${APP}",
      "command": ["python3", "-u", "/srv/app.py"],
      "volumes": ["${OWNER_VOLUME}:/data:ro", "${WORK}/owner:/srv:ro"],
      "networks": ["owner-net"]
    },
    "peer": {
      "image": "${PROBE_IMAGE}", "container_name": "${PEER}",
      "command": ["python3", "-m", "http.server", "8080", "-d", "/srv/peer"],
      "volumes": ["${WORK}/owner:/srv:ro"],
      "networks": ["owner-net"]
    },
    "bystander": {
      "image": "${PROBE_IMAGE}", "container_name": "${BYSTANDER}",
      "command": ["python3", "-u", "/srv/app.py"],
      "volumes": ["${OWNER_VOLUME}:/data:ro", "${WORK}/owner:/srv:ro"],
      "networks": ["target"]
    }
  },
  "networks": {
    "owner-net": {"name": "${OWNER_NET}"},
    "target": {"name": "${TARGET_NET}", "external": true}
  },
  "volumes": {"${OWNER_VOLUME}": {"name": "${OWNER_VOLUME}", "external": true}}
}
JSON

# The operator creates the shared network, internal, and the application's data.
docker network create --internal "${TARGET_NET}" >/dev/null && CLAIMED+=("network:${TARGET_NET}")
docker volume create "${OWNER_VOLUME}" >/dev/null && CLAIMED+=("volume:${OWNER_VOLUME}")
docker run --rm -v "${OWNER_VOLUME}:/data" "${PROBE_IMAGE}" \
  sh -c 'printf "[\"alpha\", \"beta\", \"gamma\"]" > /data/records.json' >/dev/null 2>&1
OWNER_UP=1
if ! docker compose -f "${WORK}/owner.json" up -d >"${WORK}/owner-up.log" 2>&1; then
  bad "the operator's project did not come up"; sed 's/^/              /' "${WORK}/owner-up.log"; exit 1
fi
CLAIMED+=("network:${OWNER_NET}")
for _ in $(seq 1 30); do
  pyexec "${APP}" "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/_state', timeout=2)" && break
  sleep 1
done
ok "the application runs in project ${OWNER_PROJECT}, on its own network, with its own data"

# Its own network, with a service it depends on. Reached by name, locally, never
# the internet.
reaches_own_network() {
  local got
  got="$(pyexec "${APP}" "import urllib.request; print(urllib.request.urlopen('http://peer:8080/ok.txt', timeout=5).read().decode().strip())")"
  [[ "${got}" == "peer-reachable" ]]
}

# Everything about the application that Mihakk must not change, as one text blob.
snapshot() {
  local c
  for c in "${APP}" "${PEER}" "${BYSTANDER}"; do
    docker inspect -f "${c}: id={{.Id}} started={{.State.StartedAt}} restarts={{.RestartCount}} status={{.State.Status}}" "${c}" 2>&1
  done
  printf 'app memory: %s\n' "$(pyexec "${APP}" "import urllib.request; print(urllib.request.urlopen('http://127.0.0.1:8000/_state', timeout=5).read().decode())" | python3 -c 'import json,sys; print(json.load(sys.stdin)["boot_id"])' 2>&1)"
  printf 'app networks: %s\n' "$(docker inspect -f '{{range $k, $v := .NetworkSettings.Networks}}{{$k}} {{end}}' "${APP}" 2>&1)"
  printf 'volume: %s\n' "$(docker run --rm -v "${OWNER_VOLUME}:/d:ro" "${PROBE_IMAGE}" sh -c 'cd /d && find . -type f | sort | xargs sha256sum' 2>&1 | shasum -a 256)"
  local n
  for n in "${OWNER_NET}" "${TARGET_NET}"; do
    docker network inspect -f "${n}: id={{.Id}} created={{.Created}} internal={{.Internal}}" "${n}" 2>&1
  done
  # The target network's members, minus the one container Mihakk is allowed to
  # add. Anything else appearing or vanishing is a change to the operator's side.
  printf 'target members: %s\n' "$(docker network inspect -f '{{range .Containers}}{{.Name}} {{end}}' "${TARGET_NET}" 2>&1 |
    tr ' ' '\n' | grep -v "^${ENGINE}$" | grep -v '^$' | sort | tr '\n' ' ')"
}

same_as_baseline() {  # label
  local now="${WORK}/snap-$(date +%s%N 2>/dev/null || date +%s)-$RANDOM"
  snapshot >"${now}"
  if cmp -s "${WORK}/baseline" "${now}"; then
    ok "$1: the application, its data, networks and neighbours are unchanged"
  else
    bad "$1: the operator's side changed"
    diff "${WORK}/baseline" "${now}" | sed 's/^/              /'
  fi
  if reaches_own_network; then
    ok "$1: the application still reaches its own network's service"
  else
    bad "$1: the application can no longer reach its own network's service"
  fi
}

if reaches_own_network; then
  ok "before joining anything, the application reaches its own network's service"
else
  bad "the application cannot reach its own service even before Mihakk; nothing below would mean anything"
  exit 1
fi

# The operator attaches the application to the shared network. This is their
# act, not Mihakk's: nothing in scripts/stack.sh connects anything.
docker network connect "${TARGET_NET}" "${APP}"
snapshot >"${WORK}/baseline"
if reaches_own_network; then
  ok "after joining the internal network, the application still reaches its own network"
else
  bad "joining the internal network cut the application off from its own network"
fi

# ---------------------------------------------------------------------------
echo
echo "== A6. stack.sh refuses what it cannot vouch for, and creates nothing =="
docker network create "${PLAIN_NET}" >/dev/null && CLAIMED+=("network:${PLAIN_NET}")
project_containers() {
  docker ps -aq --filter "label=com.docker.compose.project=${NS}" 2>/dev/null | wc -l | tr -d ' '
}
if "${STACK}" up --target-network "${PLAIN_NET}" >"${WORK}/a6.log" 2>&1; then
  bad "a real non-internal network was accepted"; STACK_TOUCHED=1
elif [[ "$(project_containers)" != "0" ]]; then
  bad "refused, but containers were created anyway"; STACK_TOUCHED=1
elif grep -q "NOT internal" "${WORK}/a6.log"; then
  ok "a real non-internal network is refused before anything starts"
else
  bad "refused for another reason: $(tail -1 "${WORK}/a6.log")"
fi
if "${STACK}" up --target-network "${MISSING_NET}" >"${WORK}/a6b.log" 2>&1; then
  bad "a network that does not exist was accepted"; STACK_TOUCHED=1
elif docker network inspect "${MISSING_NET}" >/dev/null 2>&1; then
  bad "stack.sh created the missing network"; CLAIMED+=("network:${MISSING_NET}")
else
  ok "a missing network is refused, and not created"
fi
same_as_baseline "after the refusals"

# ---------------------------------------------------------------------------
echo
echo "== up, with the engine joining the operator's internal network =="
STACK_TOUCHED=1
if ! "${STACK}" up --target-network "${TARGET_NET}" >"${WORK}/up.log" 2>&1; then
  bad "stack.sh up failed"; tail -25 "${WORK}/up.log" | sed 's/^/              /'; exit 1
fi
ok "stack.sh up --target-network ${TARGET_NET}"
same_as_baseline "after up"

echo
echo "== every network the engine is on is internal (inspected independently) =="
ENGINE_NETS="$(docker inspect -f '{{range $k, $v := .NetworkSettings.Networks}}{{$k}} {{end}}' "${ENGINE}" 2>/dev/null)"
# shellcheck disable=SC2086
NETS_OUT="$(docker network inspect ${ENGINE_NETS} 2>/dev/null)"; NETS_RC=$?
# shellcheck disable=SC2086
VERDICT="$(python3 "${REPO_ROOT}/scripts/check_networks.py" "${NETS_RC}" "${NETS_OUT}" ${ENGINE_NETS})"
case $? in
  0) ok "the engine is on: ${ENGINE_NETS}-- each an internal bridge network" ;;
  1) bad "the engine is on a network that is not internal: ${VERDICT}" ;;
  *) unverified "the engine's networks could not be verified: ${VERDICT}" ;;
esac
case " ${ENGINE_NETS} " in
  *" ${TARGET_NET} "*) ok "the engine joined the operator's network" ;;
  *)                   bad "the engine is not on ${TARGET_NET}; the rest would test nothing" ;;
esac
if docker inspect -f '{{range $k, $v := .NetworkSettings.Networks}}{{$k}} {{end}}' "${TESTBED}" 2>/dev/null | grep -q "${TARGET_NET}"; then
  bad "the testbed is on the operator's network"
else
  ok "the testbed is not on the operator's network"
fi
ORCH_NETS="$(docker inspect -f '{{range $k, $v := .NetworkSettings.Networks}}{{$k}} {{end}}' "${NS}-orchestrator" 2>/dev/null)"
case "${ORCH_NETS}" in
  *internal*|*"${TARGET_NET}"*) bad "the orchestrator is on ${ORCH_NETS}" ;;
  *) ok "the orchestrator is on its public network only (${ORCH_NETS% })" ;;
esac

echo
echo "== the control socket =="
SOCK="$(docker exec "${ENGINE}" stat -c '%A %u %g' /run/mihakk/control.sock 2>/dev/null)"
if [[ "${SOCK}" == "srw-rw---- 10003 10010" ]]; then
  ok "the socket is srw-rw----, owned by the engine, group 10010"
else
  bad "the socket is '${SOCK:-unreadable}'"
fi
DIR="$(docker exec "${ENGINE}" stat -c '%a %g' /run/mihakk 2>/dev/null)"
[[ "${DIR}" == "2770 10010" ]] && ok "its directory is 2770, group 10010" || bad "its directory is '${DIR:-unreadable}'"
SOCK_VOLUME="${NS}_control-socket"
connect_as() {  # user:group -> prints CONNECTED or the error class
  docker run --rm --network none --user "$1" -v "${SOCK_VOLUME}:/run/mihakk:ro" "${PROBE_IMAGE}" \
    python3 -c "
import socket
s = socket.socket(socket.AF_UNIX)
try:
    s.connect('/run/mihakk/control.sock'); print('CONNECTED')
except Exception as e:
    print(type(e).__name__)" 2>/dev/null
}
OUTSIDER="$(connect_as 12345:12345)"
MEMBER="$(connect_as 12345:10010)"
if [[ "${MEMBER}" != "CONNECTED" ]]; then
  unverified "a group-10010 process could not connect (${MEMBER:-no output}), so the refusal below proves nothing"
elif [[ "${OUTSIDER}" == "PermissionError" ]]; then
  ok "a process outside group 10010 is refused (PermissionError); a member connects"
else
  bad "a process outside group 10010 got: ${OUTSIDER:-no output}"
fi

# ---------------------------------------------------------------------------
echo
echo "== A1. no TCP listener off loopback in the engine =="
listeners_of() { docker exec "$1" cat /proc/net/tcp /proc/net/tcp6 2>/dev/null; }
L_OUT="$(listeners_of "${ENGINE}" | python3 "${REPO_ROOT}/scripts/check_listeners.py")"
case $? in
  0) ok "every listening socket in the engine is on loopback"
     printf '%s\n' "${L_OUT}" | sed 's/^/              /' ;;
  1) bad "the engine listens off loopback"; printf '%s\n' "${L_OUT}" | sed 's/^/              /' ;;
  *) unverified "the engine's listeners could not be read: ${L_OUT}" ;;
esac

# Sensitivity: the same check on an engine started the pre-8a way must fail.
docker run -d --name "${NS}-sens" --network none -e MIHAKK_CONTROL_TOKEN=sensitivity-check \
  --sysctl net.ipv4.ip_forward=1 mihakk-engine:dev serve -addr 0.0.0.0:8900 -data /tmp >/dev/null 2>&1
sleep 2
python3 "${REPO_ROOT}/scripts/check_listeners.py" <<<"$(listeners_of "${NS}-sens")" >/dev/null
[[ $? -eq 1 ]] && ok "sensitivity: an engine on -addr 0.0.0.0:8900 is caught by the same check" \
               || bad "sensitivity: the listener check did not catch -addr 0.0.0.0:8900"

echo
echo "== A2. from the operator's network, no port on the engine answers =="
ENGINE_TARGET_IP="$(docker inspect -f "{{(index .NetworkSettings.Networks \"${TARGET_NET}\").IPAddress}}" "${ENGINE}" 2>/dev/null)"
APP_TARGET_IP="$(docker inspect -f "{{(index .NetworkSettings.Networks \"${TARGET_NET}\").IPAddress}}" "${APP}" 2>/dev/null)"
cat >"${WORK}/scan.py" <<'PY'
import asyncio, sys
host, control_host, control_port = sys.argv[1], sys.argv[2], int(sys.argv[3])
async def probe(h, p, sem):
    async with sem:
        try:
            _, w = await asyncio.wait_for(asyncio.open_connection(h, p), 1.0)
            w.close(); return p
        except Exception:
            return None
async def main():
    sem = asyncio.Semaphore(400)
    # Positive control first: the scanner can see an open port on this network.
    control = await probe(control_host, control_port, sem)
    found = [p for p in await asyncio.gather(*(probe(host, p, sem) for p in range(1, 65536))) if p]
    print("control=%s open=%s" % ("open" if control else "closed", ",".join(map(str, found)) or "none"))
asyncio.run(main())
PY
SCAN="$(docker run --rm --network "${TARGET_NET}" -v "${WORK}/scan.py:/scan.py:ro" "${PROBE_IMAGE}" \
  python3 /scan.py "${ENGINE_TARGET_IP}" "${APP_TARGET_IP}" 8000 2>&1)"
case "${SCAN}" in
  "control=open open=none") ok "all 65535 TCP ports on the engine (${ENGINE_TARGET_IP}) are closed; the scanner sees the application's port" ;;
  control=closed*)          unverified "the scanner could not see the application's open port, so its silence proves nothing (${SCAN})" ;;
  *)                        bad "ports answer on the engine from the operator's network: ${SCAN}" ;;
esac

echo
echo "== A3. the engine does not route between its networks =="
FWD="$(docker exec "${ENGINE}" cat /proc/sys/net/ipv4/ip_forward /proc/sys/net/ipv6/conf/all/forwarding 2>/dev/null | tr '\n' ' ')"
[[ "${FWD}" == "0 0 " ]] && ok "forwarding is off in the engine (ipv4 0, ipv6 0)" || bad "forwarding in the engine: '${FWD}'"
SENS_FWD="$(docker exec "${NS}-sens" cat /proc/sys/net/ipv4/ip_forward 2>/dev/null)"
[[ "${SENS_FWD}" == "1" ]] && ok "sensitivity: the same read reports 1 on an engine started with forwarding on" \
                           || bad "sensitivity: forwarding on read as '${SENS_FWD}'"
docker rm -f "${NS}-sens" >/dev/null 2>&1

INTERNAL_NET="${NS}-mihakk-internal"
ENGINE_INTERNAL_IP="$(docker inspect -f "{{(index .NetworkSettings.Networks \"${INTERNAL_NET}\").IPAddress}}" "${ENGINE}" 2>/dev/null)"
TARGET_SUBNET="$(docker network inspect -f '{{range .IPAM.Config}}{{.Subnet}}{{end}}' "${TARGET_NET}")"
INTERNAL_SUBNET="$(docker network inspect -f '{{range .IPAM.Config}}{{.Subnet}}{{end}}' "${INTERNAL_NET}")"

# Two probes that may add routes (NET_ADMIN), one on each side of the engine, each
# routing the other side's subnet through it. B listens; A tries to reach it.
route_through() {  # router-on-A-side router-on-B-side netA netB subnetA subnetB label
  docker run -d --name "${NS}-probe-b" --network "$4" --cap-add NET_ADMIN "${PROBE_IMAGE}" \
    sh -c "ip route add $5 via $2 && python3 -c \"
import socket
s = socket.socket(); s.bind(('0.0.0.0', 9999)); s.listen()
while True: s.accept()[0].close()\"" >/dev/null
  sleep 1
  local b_ip
  b_ip="$(docker inspect -f "{{(index .NetworkSettings.Networks \"$4\").IPAddress}}" "${NS}-probe-b")"
  docker run --rm --name "${NS}-probe-a" --network "$3" --cap-add NET_ADMIN "${PROBE_IMAGE}" \
    sh -c "ip route add $6 via $1 && python3 -c \"
import socket
s = socket.socket(); s.settimeout(3)
try:
    s.connect(('${b_ip}', 9999)); print('REACHED')
except Exception as e:
    print('BLOCKED ' + type(e).__name__)\"" 2>&1
  docker rm -f "${NS}-probe-b" >/dev/null 2>&1
}
R1="$(route_through "${ENGINE_TARGET_IP}" "${ENGINE_INTERNAL_IP}" "${TARGET_NET}" "${INTERNAL_NET}" \
      "${TARGET_SUBNET}" "${INTERNAL_SUBNET}")"
case "${R1}" in
  BLOCKED*) ok "operator's network -> testbed's network, routed through the engine: ${R1}" ;;
  *)        bad "a route through the engine reached the testbed's network: ${R1}" ;;
esac
R2="$(route_through "${ENGINE_INTERNAL_IP}" "${ENGINE_TARGET_IP}" "${INTERNAL_NET}" "${TARGET_NET}" \
      "${INTERNAL_SUBNET}" "${TARGET_SUBNET}")"
case "${R2}" in
  BLOCKED*) ok "testbed's network -> operator's network, routed through the engine: ${R2}" ;;
  *)        bad "a route through the engine reached the operator's network: ${R2}" ;;
esac

# Positive control for the method: the same probes DO get through a router that
# forwards, on two plain networks where nothing else stops them. Without this,
# "BLOCKED" could just mean the probe never worked.
CTRL_A="${NS}-ctrl-a"; CTRL_B="${NS}-ctrl-b"
if claim network "${CTRL_A}" && claim network "${CTRL_B}"; then
  docker network create "${CTRL_A}" >/dev/null && CLAIMED+=("network:${CTRL_A}")
  docker network create "${CTRL_B}" >/dev/null && CLAIMED+=("network:${CTRL_B}")
  docker run -d --name "${NS}-router" --network "${CTRL_A}" --sysctl net.ipv4.ip_forward=1 \
    "${PROBE_IMAGE}" sleep 120 >/dev/null
  docker network connect "${CTRL_B}" "${NS}-router"
  RA="$(docker inspect -f "{{(index .NetworkSettings.Networks \"${CTRL_A}\").IPAddress}}" "${NS}-router")"
  RB="$(docker inspect -f "{{(index .NetworkSettings.Networks \"${CTRL_B}\").IPAddress}}" "${NS}-router")"
  SA="$(docker network inspect -f '{{range .IPAM.Config}}{{.Subnet}}{{end}}' "${CTRL_A}")"
  SB="$(docker network inspect -f '{{range .IPAM.Config}}{{.Subnet}}{{end}}' "${CTRL_B}")"
  R3="$(route_through "${RA}" "${RB}" "${CTRL_A}" "${CTRL_B}" "${SA}" "${SB}")"
  docker rm -f "${NS}-router" >/dev/null 2>&1
  case "${R3}" in
    REACHED) ok "positive control: the same probes cross a forwarding router on plain networks" ;;
    *)       unverified "positive control failed (${R3}); the BLOCKED results above are unproven" ;;
  esac
else
  unverified "could not claim names for the positive-control networks"
fi

# And directly, without any added route: neither side can reach the other.
T2A="$(pyexec "${TESTBED}" "
import socket; s = socket.socket(); s.settimeout(3)
try:
    s.connect(('${APP_TARGET_IP}', 8000)); print('REACHED')
except Exception as e: print('BLOCKED ' + type(e).__name__)")"
A2T_IP="$(docker inspect -f "{{(index .NetworkSettings.Networks \"${INTERNAL_NET}\").IPAddress}}" "${TESTBED}" 2>/dev/null)"
A2T="$(pyexec "${APP}" "
import socket; s = socket.socket(); s.settimeout(3)
try:
    s.connect(('${A2T_IP}', 8000)); print('REACHED')
except Exception as e: print('BLOCKED ' + type(e).__name__)")"
[[ "${T2A}" == BLOCKED* ]] && ok "the testbed cannot reach the application (${T2A})" || bad "the testbed reached the application: ${T2A}"
[[ "${A2T}" == BLOCKED* ]] && ok "the application cannot reach the testbed (${A2T})" || bad "the application reached the testbed: ${A2T}"

# ---------------------------------------------------------------------------
echo
echo "== A4. the six isolation checks, with the target overlay applied =="
MIHAKK_COMPOSE_OVERLAY="${REPO_ROOT}/deploy/compose.target.yml" MIHAKK_TARGET_NETWORK="${TARGET_NET}" \
MIHAKK_TESTBED_CONTAINER="${TESTBED}" MIHAKK_ENGINE_CONTAINER="${ENGINE}" \
  "${REPO_ROOT}/scripts/verify-testbed-isolation.sh" >"${WORK}/a4.log" 2>&1
A4_RC=$?
A4_TALLY="$(grep -E '^passed:' "${WORK}/a4.log")"
if [[ ${A4_RC} -eq 0 ]]; then
  ok "verify-testbed-isolation.sh with the overlay: ${A4_TALLY}"
else
  bad "verify-testbed-isolation.sh with the overlay failed (${A4_TALLY:-no tally})"
  sed 's/^/              /' "${WORK}/a4.log"
fi
# Without the runtime inspection the external network cannot be vouched for.
MIHAKK_TARGET_NETWORK="${TARGET_NET}" MIHAKK_CONTROL_TOKEN=x MIHAKK_DASHBOARD_TOKEN=x \
  docker compose -f "${MIHAKK_COMPOSE_FILE}" -f "${REPO_ROOT}/deploy/compose.target.yml" \
  config --format json 2>/dev/null | python3 "${REPO_ROOT}/scripts/check_testbed_isolation.py" >"${WORK}/a4b.log"
[[ $? -eq 1 ]] && grep -q "must be inspected" "${WORK}/a4b.log" \
  && ok "sensitivity: without inspecting it, the external network is a problem, not a pass" \
  || bad "sensitivity: the static check accepted an uninspected external network"

# ---------------------------------------------------------------------------
echo
echo "== A7. sessions over the socket and the operator's network =="
for _ in $(seq 1 30); do
  [[ "$(api GET /healthz "${WORK}/h.json")" == "200" ]] && break; sleep 1
done
write_session() {  # file host allowed-ip digest operator
  cat >"$1" <<JSON
{
  "config_version": "1",
  "scope": {
    "targets": [{"scheme": "http", "host": "$2", "port": 8000,
                 "path_prefixes": ["/api"], "methods": ["GET"],
                 "allowed_addresses": ["$3/32"]}],
    "max_redirects": 2
  },
  "limits": {"requests_per_second": 100, "burst": 20, "max_total_requests": 60,
             "max_concurrency": 2, "max_session_duration": "2m",
             "request_timeout": "5s", "max_response_bytes": 1048576},
  "authorization": {"operator": "$5",
                    "statement": "I am authorised to test the targets listed in this scope.",
                    "acked_at": "$(date -u +%Y-%m-%dT%H:%M:%SZ)", "scope_digest": "$4"}
}
JSON
}
digest_of() {
  docker run --rm --network none -v "${WORK}:/work:ro" mihakk-engine:dev scope-check -config "/work/$1" 2>&1 |
    grep -o 'the configured scope is sha256:[0-9a-f]*' | awk '{print $NF}'
}
start_session() {  # session-id config-file host -> prints the start status code
  python3 - "$2" "$1" "$3" >"${WORK}/$1-body.json" <<'PY'
import json, sys
config = json.load(open(sys.argv[1]))
json.dump({"session_id": sys.argv[2], "config": config, "seed": "6d6968616b6b2d70686173652d352d35",
           "max_cases": 40,
           "corpus": {"corpus_version": "1", "samples": [
               {"id": "items", "method": "GET",
                "url": "http://%s:8000/api/items?page=1" % sys.argv[3],
                "headers": {"Accept": ["application/json"]}}]}}, sys.stdout)
PY
  api POST "/v1/sessions/$1/start" "${WORK}/$1-start.json" "${WORK}/$1-body.json"
}
wait_session() {  # session-id -> prints the final status
  local status=""
  for _ in $(seq 1 120); do
    api GET "/v1/sessions/$1" "${WORK}/$1-view.json" >/dev/null
    status="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1])).get("status",""))' "${WORK}/$1-view.json" 2>/dev/null)"
    [[ "${status}" != "running" && -n "${status}" ]] && break
    sleep 1
  done
  printf '%s' "${status}"
}
app_requests() {
  pyexec "$1" "import json, urllib.request; print(json.load(urllib.request.urlopen('http://127.0.0.1:8000/_state', timeout=5))['requests'])"
}

APP_BEFORE="$(app_requests "${APP}")"
write_session "${WORK}/s-app.json" "${APP}" "${APP_TARGET_IP}" "sha256:$(printf '0%.0s' $(seq 1 64))" stack-test
write_session "${WORK}/s-app.json" "${APP}" "${APP_TARGET_IP}" "$(digest_of s-app.json)" stack-test
CODE="$(start_session app-1 "${WORK}/s-app.json" "${APP}")"
STATUS="$(wait_session app-1)"
APP_AFTER="$(app_requests "${APP}")"
if [[ "${CODE}" == "202" && "${STATUS}" == "completed" ]]; then
  ok "an authorised session against the application completed (start ${CODE}, status ${STATUS})"
else
  bad "the authorised session: start ${CODE}, status ${STATUS:-unknown}"
  head -c 400 "${WORK}/app-1-start.json" | sed 's/^/              /'; echo
fi
if [[ -n "${APP_BEFORE}" && -n "${APP_AFTER}" && "${APP_AFTER}" -gt "${APP_BEFORE}" ]]; then
  ok "the application received $((APP_AFTER - APP_BEFORE)) requests from the engine over the target network"
else
  bad "the application's request count did not move (${APP_BEFORE:-?} -> ${APP_AFTER:-?})"
fi
REPORT="$(api GET /v1/sessions/app-1/report "${WORK}/app-1-report.json")"
[[ "${REPORT}" == "200" ]] && ok "its report is served" || bad "its report: ${REPORT}"

# A neighbour on the same network, named as the host, with only the application's
# address authorised: the engine resolves the name, the address is not the pinned
# one, and nothing may be sent to it.
BYSTANDER_BEFORE="$(app_requests "${BYSTANDER}")"
write_session "${WORK}/s-by.json" "${BYSTANDER}" "${APP_TARGET_IP}" "sha256:$(printf '0%.0s' $(seq 1 64))" stack-test
write_session "${WORK}/s-by.json" "${BYSTANDER}" "${APP_TARGET_IP}" "$(digest_of s-by.json)" stack-test
CODE="$(start_session by-1 "${WORK}/s-by.json" "${BYSTANDER}")"
STATUS=""
[[ "${CODE}" == "202" ]] && STATUS="$(wait_session by-1)"
BYSTANDER_AFTER="$(app_requests "${BYSTANDER}")"
if [[ -n "${BYSTANDER_BEFORE}" && "${BYSTANDER_BEFORE}" == "${BYSTANDER_AFTER}" ]]; then
  ok "the unauthorised neighbour received nothing (start ${CODE}, status ${STATUS:-refused at start})"
else
  bad "the unauthorised neighbour's count moved: ${BYSTANDER_BEFORE:-?} -> ${BYSTANDER_AFTER:-?}"
fi
# The engine's own account, not a word search: its append-only audit log, which
# records every case the safety layer refused, with the reason. Progress now
# reports those cases too; the audit remains the independent evidence for why.
refusals_in_audit() {  # session-id -> "<not_sent count> <disallowed-address count>"
  docker exec "${ENGINE}" cat /data/audit.jsonl 2>/dev/null | python3 -c '
import json, sys
session = sys.argv[1]
sent_refused = disallowed = 0
for line in sys.stdin:
    try:
        event = json.loads(line)
    except ValueError:
        continue
    if event.get("session_id") != session or event.get("outcome") != "not_sent":
        continue
    sent_refused += 1
    if "resolved to no authorised address" in (event.get("reason") or ""):
        disallowed += 1
print(sent_refused, disallowed)' "$1"
}
read -r BY_NOT_SENT BY_DISALLOWED <<<"$(refusals_in_audit by-1)"
read -r APP_NOT_SENT _ <<<"$(refusals_in_audit app-1)"
if [[ -z "${BY_NOT_SENT}" || -z "${APP_NOT_SENT}" ]]; then
  unverified "the engine's audit log could not be read"
elif [[ "${BY_DISALLOWED}" -ge 1 && "${BY_DISALLOWED}" == "${BY_NOT_SENT}" && "${APP_NOT_SENT}" -eq 0 ]]; then
  ok "the engine's audit log records ${BY_DISALLOWED} request(s) not sent to the neighbour, each because its address is not authorised; none for the authorised session"
else
  bad "audit: neighbour not_sent=${BY_NOT_SENT} (address refusals ${BY_DISALLOWED}), authorised session not_sent=${APP_NOT_SENT}"
fi
# Every surface an operator reads keeps attempts, answers and refusals apart:
# the session view (from stored progress), and the JSON and HTML reports (from
# the engine record). Cases and HTTP requests are extracted separately too.
delivery_of() {
  api GET "/v1/sessions/$1" "${WORK}/$1-dview.json" >/dev/null
  api GET "/v1/sessions/$1/report" "${WORK}/$1-drep.json" >/dev/null
  api GET "/v1/sessions/$1/report?format=html" "${WORK}/$1-drep.html" >/dev/null
  python3 - "${WORK}/$1-dview.json" "${WORK}/$1-drep.json" "${WORK}/$1-drep.html" <<'PY'
import json, sys
from html.parser import HTMLParser
class Find(HTMLParser):
    verdict = "absent"
    responses = "absent"
    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if a.get("id") == "delivery":
            self.verdict = a.get("data-delivery") or "none"
            self.responses = a.get("data-responses") or "none"
def get(path, *keys):
    try:
        value = json.load(open(path))
        for k in keys:
            value = value[k]
        return value
    except Exception:
        return "unreadable"
page = Find(); page.feed(open(sys.argv[3]).read())
print(get(sys.argv[1], "delivery", "verdict"), get(sys.argv[1], "delivery", "responses"),
      get(sys.argv[2], "delivery", "verdict"), get(sys.argv[2], "delivery", "responses"),
      page.verdict, page.responses,
      get(sys.argv[2], "delivery", "cases", "attempted"),
      get(sys.argv[2], "delivery", "cases", "refused"),
      get(sys.argv[2], "delivery", "baseline", "attempted"),
      get(sys.argv[2], "delivery", "baseline", "refused"),
      get(sys.argv[2], "delivery", "http_requests", "answered"),
      get(sys.argv[2], "delivery", "http_requests", "unanswered"),
      get(sys.argv[2], "delivery", "http_requests", "refused"))
PY
}
read -r BV BVR BJ BJR BH BHR BCA BCR BBA BBR BHA BHU BHF <<<"$(delivery_of by-1)"
if [[ "${BV} ${BVR} ${BJ} ${BJR} ${BH} ${BHR}" == \
      "none_attempted not_applicable none_attempted not_applicable none_attempted not_applicable" \
      && "${BCA}" == "0" && "${BBA}" == "0" && "${BHA}" == "0" && "${BHU}" == "0" \
      && "${BCR}" =~ ^[0-9]+$ && "${BBR}" =~ ^[0-9]+$ && "${BHF}" =~ ^[0-9]+$ \
      && "${BCR}" -gt 0 && "${BBR}" -gt 0 && "${BHF}" -gt 0 ]]; then
  ok "the neighbour is 'nothing attempted' everywhere: ${BCR} cases, ${BBR} baseline and ${BHF} HTTP connects refused"
else
  bad "the neighbour: view ${BV}/${BVR}, json ${BJ}/${BJR}, html ${BH}/${BHR}; cases ${BCA}/${BCR}, baseline ${BBA}/${BBR}, HTTP ${BHA}/${BHU}/${BHF}"
fi
read -r AV AVR AJ AJR AH AHR ACA ACR ABA ABR AHA AHU AHF <<<"$(delivery_of app-1)"
if [[ "${AV} ${AVR} ${AJ} ${AJR} ${AH} ${AHR}" == \
      "none_refused all_answered none_refused all_answered none_refused all_answered" \
      && "${ACR}" == "0" && "${ABR}" == "0" && "${AHU}" == "0" && "${AHF}" == "0" ]]; then
  ok "the application is 'attempted, answered' everywhere, with cases and HTTP requests kept apart (${ACA}+${ABA} cases/baseline; ${AHA} HTTP)"
else
  bad "the application: view ${AV}/${AVR}, json ${AJ}/${AJR}, html ${AH}/${AHR}; cases ${ACA}/${ACR}, baseline ${ABA}/${ABR}, HTTP ${AHA}/${AHU}/${AHF}"
fi
# A response was observed for exactly as many HTTP requests as this no-redirect
# application counted. This is deliberately the HTTP count, not the case count.
if [[ "${AHA}" == "$((APP_AFTER - APP_BEFORE))" ]]; then
  ok "the engine's answered HTTP count (${AHA}) is exactly what the application received"
else
  bad "the engine says ${AHA} HTTP requests got responses; the application counted $((APP_AFTER - APP_BEFORE))"
fi

same_as_baseline "after the sessions"

# ---------------------------------------------------------------------------
echo
echo "== A5. failure, interruption and a crash leave the application alone =="

# (a) A test harness that fails, with the usual trap bringing the stack down.
( trap '"${STACK}" down >/dev/null 2>&1' EXIT
  "${STACK}" up --target-network "${TARGET_NET}" >/dev/null 2>&1
  exit 1 ) ; FAILED_RC=$?
[[ ${FAILED_RC} -ne 0 ]] && note "the simulated failing run exited ${FAILED_RC}"
same_as_baseline "after a failing run and its trap"

# (b) Interrupted mid-up. stack.sh must undo nothing on its own.
"${STACK}" up --target-network "${TARGET_NET}" >"${WORK}/int.log" 2>&1 &
UP_PID=$!
sleep 4
kill -INT "${UP_PID}" 2>/dev/null; kill -TERM "${UP_PID}" 2>/dev/null
wait "${UP_PID}" 2>/dev/null
same_as_baseline "after SIGINT/SIGTERM during up"
"${STACK}" down >/dev/null 2>&1
same_as_baseline "after down following the interrupt"

# (c) Up again, a session running, and the engine killed under it.
"${STACK}" up --target-network "${TARGET_NET}" >"${WORK}/up2.log" 2>&1 || { bad "second up failed"; tail -5 "${WORK}/up2.log"; }
start_session app-crash "${WORK}/s-app.json" "${APP}" >/dev/null
sleep 1
docker kill "${ENGINE}" >/dev/null 2>&1
same_as_baseline "after the engine was killed mid-session"

# ---------------------------------------------------------------------------
echo
echo "== down =="
if "${STACK}" down >"${WORK}/down.log" 2>&1; then ok "stack.sh down"; else bad "stack.sh down failed"; fi
same_as_baseline "after the final down"
if docker network inspect -f '{{range .Containers}}{{.Name}} {{end}}' "${TARGET_NET}" | grep -q "${ENGINE}"; then
  bad "the engine is still on the operator's network"
else
  ok "the engine has left the operator's network, which is still there"
fi
KEPT=0
for v in engine-data orchestrator-data control-socket; do
  docker volume inspect "${NS}_${v}" >/dev/null 2>&1 && KEPT=$((KEPT + 1))
done
[[ ${KEPT} -eq 3 ]] && ok "down kept Mihakk's three volumes" || bad "down kept ${KEPT} of Mihakk's three volumes"

# ---------------------------------------------------------------------------
echo
echo "== sensitivity: the comparison does see a change to the operator's side =="
cp "${WORK}/baseline" "${WORK}/baseline.real"
docker restart "${APP}" >/dev/null 2>&1
snapshot >"${WORK}/after-restart"
if cmp -s "${WORK}/baseline" "${WORK}/after-restart"; then
  bad "a restart of the application went unnoticed"
else
  ok "a restart of the application is detected ($(diff "${WORK}/baseline" "${WORK}/after-restart" | grep -c '^>') line(s) differ)"
fi
snapshot >"${WORK}/baseline"
docker network disconnect "${TARGET_NET}" "${APP}" >/dev/null 2>&1
snapshot >"${WORK}/after-disconnect"
cmp -s "${WORK}/baseline" "${WORK}/after-disconnect" \
  && bad "disconnecting the application went unnoticed" \
  || ok "disconnecting the application from the shared network is detected"
docker network connect "${TARGET_NET}" "${APP}" >/dev/null 2>&1
snapshot >"${WORK}/baseline"
docker run --rm -v "${OWNER_VOLUME}:/data" "${PROBE_IMAGE}" sh -c 'echo changed >> /data/records.json' >/dev/null 2>&1
snapshot >"${WORK}/after-write"
cmp -s "${WORK}/baseline" "${WORK}/after-write" \
  && bad "a write to the application's data went unnoticed" \
  || ok "a write to the application's data is detected"

echo
echo "================================"
printf 'passed: %d   failed: %d   unverified: %d\n' "${PASS}" "${FAIL}" "${UNVERIFIED}"
if [[ ${FAIL} -eq 0 && ${UNVERIFIED} -eq 0 ]]; then
  echo "the stack reached the operator's application without owning any of it"
  exit 0
fi
exit 1
