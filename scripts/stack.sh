#!/usr/bin/env bash
# Start, stop and inspect the Mihakk stack.
#
#   scripts/stack.sh up [--target-network NAME]
#   scripts/stack.sh down
#   scripts/stack.sh status
#
# The tokens come from the secrets file (scripts/init-secrets.sh creates it),
# read by scripts/secrets_file.py and handed to docker compose through the
# environment. The file is never sourced and nothing in it is executed. This
# script never prints either token, and never prints `docker compose config`,
# whose output would contain them.
#
# --target-network NAME lets the engine reach an application the operator runs in
# their own compose project. The operator creates the network and attaches their
# application to it; this script does neither. It refuses, before anything
# starts, a network that does not exist, that is not a local bridge network
# Docker reports as internal, that could not be inspected, or whose name is one
# of Docker's or Mihakk's own. After `up` it reads every network the engine is on
# and takes the stack back down if any of them is not internal.
#
# What `down` does and does not do:
#   - stops and removes this project's containers and its own networks;
#   - never -v: the engine's sessions and the orchestrator's database survive;
#   - never --remove-orphans, never anything outside this project: the operator's
#     application, its data and its networks are not this script's to touch, and
#     the target network is left exactly where it was, minus the engine.
#
# Environment:
#   MIHAKK_SECRETS_FILE  the secrets file (default ${XDG_CONFIG_HOME:-~/.config}/mihakk/secrets.env)
#   MIHAKK_PORT          the orchestrator's loopback port (default 8100)
#   MIHAKK_COMPOSE_FILE  the compose file (default deploy/docker-compose.yml); the
#                        tests point this at a stack of their own
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SECRETS="${MIHAKK_SECRETS_FILE:-${XDG_CONFIG_HOME:-${HOME}/.config}/mihakk/secrets.env}"
COMPOSE_FILE="${MIHAKK_COMPOSE_FILE:-${REPO_ROOT}/deploy/docker-compose.yml}"
TARGET_OVERLAY="${REPO_ROOT}/deploy/compose.target.yml"
SECRETS_PY="${REPO_ROOT}/scripts/secrets_file.py"
NETWORKS_PY="${REPO_ROOT}/scripts/check_networks.py"

# Names that are never an operator's target network: Docker's own, and the ones
# this stack manages. The project's networks are added from the compose file.
RESERVED_NETWORKS="bridge host none mihakk-internal mihakk-public"

say()  { printf '%s\n' "$*"; }
fail() { printf 'stack: %s\n' "$*" >&2; exit 1; }

usage() {
  sed -n '2,6p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//' >&2
  exit 2
}

# Interrupted, nothing is undone behind the operator's back: whatever compose had
# started stays as it is, and `down` is the way to stop it. In particular an
# interrupt never reaches for a volume, an orphan or another project.
on_signal() {
  trap - INT TERM
  printf '\nstack: interrupted; nothing was removed. Run scripts/stack.sh down to stop what started.\n' >&2
  exit 130
}
trap on_signal INT TERM

# Commands that only read the compose file or remove this project's containers
# need the tokens to be SET for interpolation, not to be right. They get
# placeholders, so `down` and `status` work even if the secrets file is gone.
with_placeholders() {
  MIHAKK_CONTROL_TOKEN="placeholder-unused-by-${1}" \
  MIHAKK_DASHBOARD_TOKEN="placeholder-unused-by-${1}" \
  MIHAKK_TARGET_NETWORK="${MIHAKK_TARGET_NETWORK:-placeholder-unused}" \
    "${@:2}"
}

# The project's name and its own network names, read without interpolation so no
# token is involved. Printed as lines: "project NAME" then "network NAME".
project_facts() {
  docker compose -f "${COMPOSE_FILE}" config --no-interpolate --format json 2>/dev/null |
    python3 -c '
import json, sys
try:
    config = json.load(sys.stdin)
except Exception:
    sys.exit(2)
name = config.get("name")
if not isinstance(name, str) or not name:
    sys.exit(2)
print("project " + name)
for key, body in (config.get("networks") or {}).items():
    if isinstance(body, dict) and body.get("external"):
        continue
    real = (body or {}).get("name") if isinstance(body, dict) else None
    print("network " + (real or name + "_" + key))
'
}

check_port() {
  local port="${MIHAKK_PORT:-8100}"
  if ! [[ "${port}" =~ ^[0-9]{4,5}$ ]] || (( 10#${port} < 1024 || 10#${port} > 65535 )); then
    fail "MIHAKK_PORT must be a number from 1024 to 65535"
  fi
}

# Every network the engine is attached to, as Docker has it, must be internal.
# Prints the verdict lines; returns check_networks.py's exit code.
verify_engine_networks() {
  local project="$1" id names out rc
  id="$(docker ps -q --filter "label=com.docker.compose.project=${project}" \
          --filter "label=com.docker.compose.service=engine" 2>/dev/null | head -1)"
  if [[ -z "${id}" ]]; then
    say "  no running engine container found for project ${project}"
    return 2
  fi
  names="$(docker inspect -f '{{json .NetworkSettings.Networks}}' "${id}" 2>/dev/null |
    python3 -c '
import json, sys
try:
    networks = json.load(sys.stdin)
except Exception:
    sys.exit(2)
if not isinstance(networks, dict) or not networks:
    sys.exit(2)
print("\n".join(sorted(networks)))
')" || { say "  the engine's networks could not be read"; return 2; }

  # Word splitting is safe here: check_networks.py refuses any name Docker would
  # not create, and Docker's names contain no whitespace.
  # shellcheck disable=SC2086
  out="$(docker network inspect ${names} 2>/dev/null)"; rc=$?
  # shellcheck disable=SC2086
  python3 "${NETWORKS_PY}" "${rc}" "${out}" ${names} | sed 's/^/  /'
  return "${PIPESTATUS[0]}"
}

cmd_up() {
  local target="" facts project network verdict rc
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --target-network)
        [[ $# -ge 2 ]] || usage
        target="$2"; shift 2 ;;
      *) usage ;;
    esac
  done

  check_port

  # The file is validated before anything starts, so a bad file is a refusal
  # with a line number rather than a half-started stack.
  python3 "${SECRETS_PY}" check "${SECRETS}" >/dev/null || exit 1

  facts="$(project_facts)" || fail "the compose file ${COMPOSE_FILE} could not be read"
  project="$(printf '%s\n' "${facts}" | sed -n 's/^project //p')"

  local files=(-f "${COMPOSE_FILE}")
  if [[ -n "${target}" ]]; then
    say "== the target network =="
    for network in ${RESERVED_NETWORKS} $(printf '%s\n' "${facts}" | sed -n 's/^network //p'); do
      [[ "${target}" == "${network}" ]] && fail "refusing ${target}: it is not an operator's network"
    done

    # Read the network Docker really has. `external: true` in the overlay says
    # who owns it; only this says whether it is isolated. Unreadable is refused.
    local inspected
    inspected="$(docker network inspect "${target}" 2>/dev/null)"; rc=$?
    verdict="$(python3 "${NETWORKS_PY}" "${rc}" "${inspected}" "${target}")"
    case $? in
      0) say "  ${verdict}" ;;
      1) fail "refusing ${target}: ${verdict}. Create an internal network (docker network create --internal NAME) and attach the application to it" ;;
      *) fail "refusing ${target}: it could not be verified (${verdict}); nothing was started" ;;
    esac
    files+=(-f "${TARGET_OVERLAY}")
    export MIHAKK_TARGET_NETWORK="${target}"
  fi

  say "== starting project ${project} =="
  # The tokens are added to docker compose's environment by secrets_file.py,
  # which executes compose directly: they are never in this shell's variables.
  python3 "${SECRETS_PY}" run "${SECRETS}" -- \
    docker compose "${files[@]}" up -d --build --wait --wait-timeout 180
  rc=$?
  if [[ ${rc} -ne 0 ]]; then
    fail "docker compose up exited ${rc}; run scripts/stack.sh status, then scripts/stack.sh down"
  fi

  say "== every network the engine is on =="
  verify_engine_networks "${project}"
  rc=$?
  if [[ ${rc} -ne 0 ]]; then
    say "the engine is on a network that is not verifiably internal; taking the stack down"
    with_placeholders down docker compose -f "${COMPOSE_FILE}" down >/dev/null 2>&1
    exit 1
  fi

  say
  say "Mihakk is up: http://127.0.0.1:${MIHAKK_PORT:-8100}/"
  say "Log in with the dashboard token: scripts/show-dashboard-token.sh (in a terminal)."
}

cmd_down() {
  [[ $# -eq 0 ]] || usage
  # This project only, and neither -v nor --remove-orphans. The target overlay is
  # not needed: the engine is this project's container, and removing it is what
  # detaches it from the operator's network. The network itself is external, so
  # compose would not remove it either way.
  with_placeholders down docker compose -f "${COMPOSE_FILE}" down
}

cmd_status() {
  [[ $# -eq 0 ]] || usage
  local facts project
  with_placeholders status docker compose -f "${COMPOSE_FILE}" ps
  facts="$(project_facts)" || fail "the compose file ${COMPOSE_FILE} could not be read"
  project="$(printf '%s\n' "${facts}" | sed -n 's/^project //p')"
  say
  say "networks the engine is on:"
  verify_engine_networks "${project}"
}

[[ $# -ge 1 ]] || usage
command="$1"; shift
case "${command}" in
  up)     cmd_up "$@" ;;
  down)   cmd_down "$@" ;;
  status) cmd_status "$@" ;;
  *)      usage ;;
esac
