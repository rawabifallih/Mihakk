#!/usr/bin/env bash
# The whole stack, live: orchestrator -> engine -> testbed, over real sockets.
#
# Everything else that exercises this path replaces part of it. The Go tests
# drive the control API in-process; the orchestrator's tests replace the engine
# with an httpx.MockTransport, which does not just skip the deployment but skips
# the HTTP layer itself -- no socket, no chunked encoding, no NDJSON framing.
#
# So this checks the seam, not the logic on either side of it:
#   - a run started through the orchestrator's HTTP API reaches the engine;
#   - the NDJSON event stream survives a real connection;
#   - what lands in SQLite is what the engine actually reported;
#   - completeness is proved from the stored rows, not asserted.
#
# Three rules this script exists to obey, each of them learned the hard way:
#
#   1. It runs in a THROWAWAY compose project of its own, derived from the real
#      compose file by scripts/isolated_compose.py. An earlier version brought
#      the shared `mihakk` project up and ran `down -v --remove-orphans` on exit,
#      which would stop a person's running stack and delete the engine's stored
#      sessions and the orchestrator's SQLite along with it. A -p flag alone is
#      not enough, because the real file pins container and network names.
#
#   2. It never proves "not published" by failing to connect to a fixed host
#      port -- another process may hold that port, and a refused connection is
#      not evidence about this container. It inspects each container's own port
#      bindings, requested and live, for any port number, through the strict
#      reader in scripts/check_container_ports.py. If the bindings cannot be
#      read the result is UNVERIFIED and a non-zero exit, never a pass.
#
#   3. It never executes data that came off an HTTP response. Verdicts come from
#      scripts/read_run_report.py as tab-separated lines that are read, not
#      sourced. The version that sourced KEY=value lines would have run
#      $(...) inside a server's reply.
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# The committed stack by default. Overridable so the scenario test can point this
# at a representative stack of its own: the project this script must not touch
# then belongs to the test, which is what makes "it left the other project alone"
# a claim that can actually fail.
REAL_COMPOSE="${MIHAKK_COMPOSE_FILE:-${REPO_ROOT}/deploy/docker-compose.yml}"
WORK="$(mktemp -d)"

# A project of our own. Never the one the compose file names for itself, which is
# read from the resolved config below rather than assumed.
PROJECT="mihakk-live-$$-$(date +%s)"
SHARED_PROJECT=""

SESSION="live-$(date +%s)"
SEED="6d6968616b6b2d70686173652d352d35"

# A real token for a real run: generated per run, never committed, and only ever
# travelling over the internal Docker network.
export MIHAKK_CONTROL_TOKEN="${MIHAKK_CONTROL_TOKEN:-$(head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n')}"
# The orchestrator refuses to serve anything without this, so a real one is
# generated per run rather than a placeholder.
export MIHAKK_DASHBOARD_TOKEN="${MIHAKK_DASHBOARD_TOKEN:-$(head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n')}"

# Every request to the orchestrator carries this, by the bearer path a script
# is meant to use: the same secret the browser's login takes, checked the same
# way, and needing no CSRF token because a bearer header is never ambient.
# Defined here so it exists before the first use.
AUTH=(-H "Authorization: Bearer ${MIHAKK_DASHBOARD_TOKEN}")

PASS=0
FAIL=0
UNVERIFIED=0
ok()         { printf '  \033[32mPASS\033[0m        %s\n' "$1"; PASS=$((PASS + 1)); }
bad()        { printf '  \033[31mFAIL\033[0m        %s\n' "$1"; FAIL=$((FAIL + 1)); }
unverified() { printf '  \033[33mUNVERIFIED\033[0m  %s\n' "$1"; UNVERIFIED=$((UNVERIFIED + 1)); }
note()       { printf '              %s\n' "$1"; }

STACK_UP=0

# Cleanup removes this script's own project and nothing else. `down -v` is safe
# here only because the project is private to this run and holds no data anyone
# else put there; it would not be safe against the shared project.
#
# Trapped on INT and TERM as well as EXIT: without those, an interrupted run
# leaves its containers and volumes behind.
cleanup() {
  local rc=$?
  trap - EXIT INT TERM
  if [[ "${STACK_UP}" == "1" ]]; then
    if [[ -n "${SHARED_PROJECT}" && "${PROJECT}" == "${SHARED_PROJECT}" ]]; then
      printf 'refusing to tear down %s: it is the project the compose file names\n' \
        "${SHARED_PROJECT}" >&2
    else
      docker compose -p "${PROJECT}" -f "${WORK}/compose.json" down -v >/dev/null 2>&1 || true
    fi
  fi
  rm -rf "${WORK}"
  exit "${rc}"
}
trap cleanup EXIT INT TERM

# --- derive a throwaway project from the real compose file ------------------
echo "== deriving a throwaway compose project =="

# A free host port, so a stack already listening on 8100 is left alone.
ORCH_PORT="$(python3 -c '
import socket
s = socket.socket()
s.bind(("127.0.0.1", 0))
print(s.getsockname()[1])
s.close()
')"
if [[ -z "${ORCH_PORT}" ]]; then
  unverified "could not find a free host port for the orchestrator"
  exit 1
fi
ORCH="http://127.0.0.1:${ORCH_PORT}"

if ! docker compose -f "${REAL_COMPOSE}" config --format json >"${WORK}/resolved.json" 2>"${WORK}/resolve.err"; then
  bad "the real compose file could not be resolved"
  sed 's/^/              /' "${WORK}/resolve.err"
  exit 1
fi

# The project the file names for itself: the one this script must never act on.
SHARED_PROJECT="$(python3 -c '
import json, sys
try:
    print(json.load(open(sys.argv[1])).get("name") or "")
except Exception:
    print("")
' "${WORK}/resolved.json")"
if [[ -z "${SHARED_PROJECT}" ]]; then
  unverified "the compose file names no project, so there is nothing to protect it by name"
  exit 1
fi

if [[ "${PROJECT}" == "${SHARED_PROJECT}" ]]; then
  bad "the throwaway project name collides with the project the compose file names"
  exit 1
fi

if ! python3 "${REPO_ROOT}/scripts/isolated_compose.py" \
      "${WORK}/resolved.json" orchestrator 127.0.0.1 "${ORCH_PORT}" \
      >"${WORK}/compose.json" 2>"${WORK}/derive.err"; then
  bad "the throwaway project could not be derived from the compose file"
  sed 's/^/              /' "${WORK}/derive.err"
  exit 1
fi
ok "derived a throwaway project (${PROJECT}) from $(basename "${REAL_COMPOSE}")"
note "the '${SHARED_PROJECT}' project the file names is not touched; orchestrator on port ${ORCH_PORT}"

COMPOSE=(docker compose -p "${PROJECT}" -f "${WORK}/compose.json")

# --- bring it up -----------------------------------------------------------
echo
echo "== bringing up the stack =="
STACK_UP=1
if ! "${COMPOSE[@]}" up -d --build >"${WORK}/compose.log" 2>&1; then
  bad "the stack did not come up"
  tail -20 "${WORK}/compose.log" | sed 's/^/              /'
  exit 1
fi

READY=0
for _ in $(seq 1 60); do
  if curl -sS "${AUTH[@]}" -m 2 "${ORCH}/healthz" >/dev/null 2>&1; then READY=1; break; fi
  sleep 1
done
if [[ "${READY}" != "1" ]]; then
  bad "the orchestrator never answered on ${ORCH}"
  "${COMPOSE[@]}" logs --tail 30 orchestrator 2>&1 | sed 's/^/              /'
  exit 1
fi
ok "the orchestrator answers on its published loopback port"

# --- the isolated services publish nothing ---------------------------------
# Inspected per container, for any port, requested and live. Not probed.
container_id() {
  local service="$1" id
  id="$("${COMPOSE[@]}" ps -q "${service}" 2>/dev/null | head -1 | tr -d '[:space:]')"
  printf '%s' "${id}"
}

check_no_host_ports() {
  local service="$1" id live requested report summary rc

  id="$(container_id "${service}")"
  if [[ -z "${id}" ]]; then
    unverified "${service}: no container found, so its port bindings were not checked"
    return
  fi

  if ! live="$(docker inspect -f '{{json .NetworkSettings.Ports}}' "${id}" 2>&1)"; then
    unverified "${service}: docker inspect failed for live bindings: ${live}"
    return
  fi
  if ! requested="$(docker inspect -f '{{json .HostConfig.PortBindings}}' "${id}" 2>&1)"; then
    unverified "${service}: docker inspect failed for requested bindings: ${requested}"
    return
  fi

  # The strict reader: any unreadable input is exit 2, never an empty table.
  report="$(python3 "${REPO_ROOT}/scripts/check_container_ports.py" "${live}" "${requested}" 2>&1)"
  rc=$?
  if [[ ${rc} -ne 0 ]]; then
    unverified "${service}: port bindings could not be read, so isolation is unverified: ${report}"
    return
  fi

  # The decision is made in python and returned as an exit status; the summary
  # is only ever printed, never executed.
  summary="$(python3 - "${report}" <<'PY'
import json, sys
try:
    data = json.loads(sys.argv[1])
except (ValueError, json.JSONDecodeError) as exc:
    print("the port report is not valid JSON (%s)" % exc)
    sys.exit(2)
bound = data.get("bound")
exposed = data.get("exposed")
if not isinstance(bound, list) or not isinstance(exposed, list):
    print("the port report has no bound/exposed lists")
    sys.exit(2)
if bound:
    print("host ports bound: " + "; ".join(str(b) for b in bound))
    sys.exit(1)
print("exposed but unpublished: " + (", ".join(str(e) for e in exposed) or "none"))
sys.exit(0)
PY
)"
  rc=$?
  case "${rc}" in
    0) ok "${service} binds no host port (${summary})" ;;
    1) bad "${service} publishes a port to the host (${summary})" ;;
    *) unverified "${service}: the port report could not be judged (${summary})" ;;
  esac
}

echo
echo "== the isolated services publish nothing =="
check_no_host_ports engine
check_no_host_ports testbed

TESTBED_ID="$(container_id testbed)"
TESTBED_IP="$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' \
  "${TESTBED_ID}" 2>/dev/null | tr -d '[:space:]')"
if [[ -z "${TESTBED_IP}" ]]; then
  unverified "could not determine the testbed's address"
  exit 1
fi
note "testbed is at ${TESTBED_IP}"

# --- the session config ----------------------------------------------------
# Same shape the CLI takes. The scope authorises the testbed's single address,
# and the acknowledgement is bound to the scope digest, so the digest is asked
# for rather than guessed.
write_config() {
  cat >"${WORK}/session.json" <<JSON
{
  "config_version": "1",
  "scope": {
    "targets": [
      {
        "scheme": "http", "host": "testbed", "port": 8000,
        "path_prefixes": ["/api"],
        "methods": ["GET", "POST"],
        "allowed_addresses": ["${TESTBED_IP}/32"]
      }
    ],
    "max_redirects": 2
  },
  "limits": {
    "requests_per_second": 200,
    "burst": 50,
    "max_total_requests": 400,
    "max_concurrency": 4,
    "max_session_duration": "3m",
    "request_timeout": "10s",
    "max_response_bytes": 1048576
  },
  "authorization": {
    "operator": "live-integration-script",
    "statement": "I am authorised to test the targets listed in this scope.",
    "acked_at": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
    "scope_digest": "$1"
  }
}
JSON
}

write_config "sha256:0000000000000000000000000000000000000000000000000000000000000000"
SCOPE_OUTPUT="$(docker run --rm -v "${WORK}:/work" mihakk-engine:dev \
  scope-check -config /work/session.json 2>&1)"
DIGEST="$(printf '%s\n' "${SCOPE_OUTPUT}" |
  grep -o 'the configured scope is sha256:[0-9a-f]*' | awk '{print $NF}')"
if [[ -z "${DIGEST}" ]]; then
  if [[ "${SCOPE_OUTPUT}" == *"acked_at is in the future"* ]]; then
    python3 - "${WORK}/session.json" "${REPO_ROOT}/scripts" <<'PY'
import json, sys
sys.path.insert(0, sys.argv[2])
from local_api_transport import clock_diagnostic
with open(sys.argv[1]) as source:
    acked_at = json.load(source)["authorization"]["acked_at"]
print(clock_diagnostic(acked_at))
PY
  fi
  unverified "could not obtain the scope digest"
  exit 1
fi
write_config "${DIGEST}"
note "scope digest ${DIGEST:0:20}..."

# --- start the run through the orchestrator --------------------------------
echo
echo "== starting a run through the orchestrator =="
if ! python3 - "${WORK}/session.json" "${SESSION}" "${SEED}" \
      "${REPO_ROOT}/testbed/corpus.json" >"${WORK}/start_body.json" <<'PY'
import json, pathlib, sys
config = json.loads(pathlib.Path(sys.argv[1]).read_text())
corpus = json.loads(pathlib.Path(sys.argv[4]).read_text())
json.dump({
    "session_id": sys.argv[2],
    "config": config,
    "corpus": corpus,
    "seed": sys.argv[3],
    "max_cases": 120,
}, sys.stdout)
PY
then
  bad "could not build the start request"
  exit 1
fi

curl -sS "${AUTH[@]}" -m 60 -X POST -H 'Content-Type: application/json' \
  --data-binary "@${WORK}/start_body.json" \
  "${ORCH}/v1/sessions/${SESSION}/start" >"${WORK}/start.json" 2>"${WORK}/start.err"

if ! python3 -c '
import json, sys
try:
    body = json.load(open(sys.argv[1]))
except Exception as exc:
    print("unreadable: %s" % exc)
    sys.exit(2)
sys.exit(0 if body.get("status") == "running" else 1)
' "${WORK}/start.json"; then
  bad "the orchestrator did not start the run"
  head -c 400 "${WORK}/start.json" | sed 's/^/              /'
  exit 1
fi
ok "the run started: the start request crossed the wire and the engine accepted it"

# --- wait for it to settle -------------------------------------------------
echo
echo "== following the stream =="
for _ in $(seq 1 180); do
  curl -sS "${AUTH[@]}" -m 10 "${ORCH}/v1/sessions/${SESSION}" >"${WORK}/session_view.json" 2>/dev/null
  if ! python3 -c '
import json, sys
try:
    status = json.load(open(sys.argv[1])).get("status")
except Exception:
    sys.exit(0)
sys.exit(0 if status == "running" or not status else 1)
' "${WORK}/session_view.json"; then
    break
  fi
  sleep 1
done

curl -sS "${AUTH[@]}" -m 30 "${ORCH}/v1/sessions/${SESSION}/findings" >"${WORK}/findings.json" 2>/dev/null
curl -sS "${AUTH[@]}" -m 30 "${ORCH}/v1/sessions/${SESSION}/events?limit=5000" >"${WORK}/events.json" 2>/dev/null

# --- judge the run ---------------------------------------------------------
# read_run_report.py parses the responses and prints one verdict per line. The
# lines are READ here, never sourced: a reason string carrying $(...) is text.
echo
echo "== what crossed the wire =="
python3 "${REPO_ROOT}/scripts/read_run_report.py" \
  "${WORK}/session_view.json" "${WORK}/findings.json" "${WORK}/events.json" \
  >"${WORK}/verdicts.tsv" 2>"${WORK}/verdicts.err"
REPORT_RC=$?

if [[ ! -s "${WORK}/verdicts.tsv" ]]; then
  unverified "the run report produced no verdicts (exit ${REPORT_RC})"
  sed 's/^/              /' "${WORK}/verdicts.err" 2>/dev/null
else
  while IFS="$(printf '\t')" read -r verdict message; do
    case "${verdict}" in
      PASS)       ok "${message}" ;;
      FAIL)       bad "${message}" ;;
      UNVERIFIED) unverified "${message}" ;;
      *)          unverified "unrecognised verdict line: ${verdict} ${message}" ;;
    esac
  done <"${WORK}/verdicts.tsv"
fi

# --- the report, end to end ------------------------------------------------
# Go produces the aggregate, Python consumes it, and this is where the two meet
# over a real socket. Every check below runs against this run's genuine findings
# rather than a fixture, and the readers it uses are the same ones the unit tests
# cover, so a failure here is about the seam and not about the checking.
echo
echo "== the report crosses the language boundary =="

curl -sS "${AUTH[@]}" -m 30 "${ORCH}/v1/sessions/${SESSION}/report" >"${WORK}/report.json" 2>/dev/null
curl -sS "${AUTH[@]}" -m 30 -D "${WORK}/report.headers" \
  "${ORCH}/v1/sessions/${SESSION}/report?format=html" >"${WORK}/report.html" 2>/dev/null

python3 "${REPO_ROOT}/scripts/check_report_conservation.py" \
  "${WORK}/report.json" "${WORK}/findings.json" >"${WORK}/report_verdicts.tsv" 2>&1
REPORT_RC=$?

if [[ ! -s "${WORK}/report_verdicts.tsv" ]]; then
  unverified "the report check produced no verdicts (exit ${REPORT_RC})"
else
  while IFS="$(printf '\t')" read -r verdict message; do
    case "${verdict}" in
      PASS)       ok "${message}" ;;
      FAIL)       bad "${message}" ;;
      UNVERIFIED) unverified "${message}" ;;
      *)          unverified "unrecognised verdict: ${verdict} ${message}" ;;
    esac
  done <"${WORK}/report_verdicts.tsv"
fi

# The HTML is judged by parsing it, not by searching its text: the report is
# required to keep hostile payloads visible as escaped text, so a search for
# "javascript:" would reject the correct answer.
HTML_OUT="$(python3 "${REPO_ROOT}/scripts/check_report_html.py" "${WORK}/report.html" 2>&1)"
HTML_RC=$?
case "${HTML_RC}" in
  0) ok "the HTML report has no executable context" ;;
  1) bad "the HTML report has an executable context"
     printf '%s\n' "${HTML_OUT}" | grep '^FAIL' | sed 's/^/              /' ;;
  *) unverified "the HTML report could not be judged: ${HTML_OUT}" ;;
esac

# The policy must be on the served response, not only in the meta fallback.
check_header() {
  local name="$1" expected="$2" line
  line="$(grep -i "^${name}:" "${WORK}/report.headers" 2>/dev/null | tail -1 | tr -d '\r')"
  if [[ -z "${line}" ]]; then
    bad "the served report carries no ${name} header"
    return
  fi
  case "${line}" in
    *"${expected}"*) ok "${name} is set on the served response" ;;
    *)               bad "${name} is '${line}', expected to contain '${expected}'" ;;
  esac
}
check_header "content-type" "text/html; charset=utf-8"
check_header "x-content-type-options" "nosniff"
check_header "referrer-policy" "no-referrer"
check_header "content-security-policy" "default-src 'none'"

# Derived from the stored files, so two fetches agree byte for byte.
curl -sS "${AUTH[@]}" -m 30 "${ORCH}/v1/sessions/${SESSION}/report" >"${WORK}/report2.json" 2>/dev/null
if cmp -s "${WORK}/report.json" "${WORK}/report2.json"; then
  ok "two fetches of the report are byte-identical"
else
  bad "two fetches of the report differ, so it is not a pure function of what is stored"
fi

# --- phase 8b: a dropped stream, restart, and overlapping live runs ----------
echo
echo "== live resilience: two overlapping runs and a mid-run restart =="

# Slow the request budget, not the testbed. This leaves enough time to observe
# both sessions mid-flight and restart the orchestrator while the engine keeps
# running. The scope digest does not change when only limits change.
python3 - "${WORK}/start_body.json" "${WORK}" <<'PY'
import json, pathlib, sys
body = json.loads(pathlib.Path(sys.argv[1]).read_text())
for suffix in ("a", "b"):
    run = json.loads(json.dumps(body))
    run["session_id"] = f"{body['session_id']}-resilience-{suffix}"
    run["max_cases"] = 80
    run["config"]["limits"].update({
        "requests_per_second": 2, "burst": 1, "max_concurrency": 1,
    })
    pathlib.Path(sys.argv[2], f"resilience-{suffix}.json").write_text(json.dumps(run))
PY

for suffix in a b; do
  id="${SESSION}-resilience-${suffix}"
  curl -sS "${AUTH[@]}" -m 60 -X POST -H 'Content-Type: application/json' \
    --data-binary "@${WORK}/resilience-${suffix}.json" \
    "${ORCH}/v1/sessions/${id}/start" >"${WORK}/resilience-${suffix}-start.json" 2>"${WORK}/resilience-${suffix}-start.err"
  if python3 -c 'import json,sys; b=json.load(open(sys.argv[1])); sys.exit(0 if b.get("status")=="running" else 1)' \
      "${WORK}/resilience-${suffix}-start.json"; then
    ok "resilience session ${suffix} was accepted by the live engine"
  else
    bad "resilience session ${suffix} did not start"
    sed 's/^/              /' "${WORK}/resilience-${suffix}-start.err"
    exit 1
  fi
done

OVERLAP=0
for _ in $(seq 1 20); do
  for suffix in a b; do
    id="${SESSION}-resilience-${suffix}"
    curl -sS "${AUTH[@]}" -m 5 "${ORCH}/v1/sessions/${id}" >"${WORK}/resilience-${suffix}-before.json" 2>/dev/null
    curl -sS "${AUTH[@]}" -m 5 "${ORCH}/v1/sessions/${id}/events?limit=5000" >"${WORK}/resilience-${suffix}-events-before.json" 2>/dev/null
  done
  if python3 - "${WORK}" <<'PY'
import json, pathlib, sys
root = pathlib.Path(sys.argv[1])
try:
    for suffix in ("a", "b"):
        view = json.loads((root / f"resilience-{suffix}-before.json").read_text())
        events = json.loads((root / f"resilience-{suffix}-events-before.json").read_text())
        assert view["status"] == "running"
        assert any(e.get("seq", 0) > 0 for e in events["events"])
except (AssertionError, OSError, ValueError, KeyError, TypeError):
    sys.exit(1)
PY
  then OVERLAP=1; break; fi
  sleep 1
done
if [[ "${OVERLAP}" != "1" ]]; then
  bad "both sessions were not observed running with stored events at the same time"
  exit 1
fi
ok "two sessions overlapped while both were storing real engine events"

if "${COMPOSE[@]}" exec -T orchestrator python - "${SESSION}-resilience-a" \
    <"${REPO_ROOT}/scripts/probe_live_stream.py" >"${WORK}/stream-probe.log" 2>&1; then
  ok "a deliberately closed NDJSON connection resumed at the next seq over a fresh socket"
  note "$(tail -1 "${WORK}/stream-probe.log")"
else
  bad "the real NDJSON stream did not resume after a deliberate close"
  sed 's/^/              /' "${WORK}/stream-probe.log"
  exit 1
fi

# Do not let a fast run turn the restart into a test of already-finished data.
for suffix in a b; do
  id="${SESSION}-resilience-${suffix}"
  curl -sS "${AUTH[@]}" -m 5 "${ORCH}/v1/sessions/${id}" >"${WORK}/resilience-${suffix}-at-restart.json" 2>/dev/null
done
if ! python3 - "${WORK}" <<'PY'
import json, pathlib, sys
root = pathlib.Path(sys.argv[1])
try:
    assert all(json.loads((root / f"resilience-{s}-at-restart.json").read_text())["status"]
               == "running" for s in ("a", "b"))
except (AssertionError, OSError, ValueError, KeyError, TypeError):
    sys.exit(1)
PY
then
  unverified "one of the runs finished before the restart; recovery was not exercised"
  exit 1
fi

ORCH_ID="$(container_id orchestrator)"
STARTED_BEFORE="$(docker inspect -f '{{.State.StartedAt}}' "${ORCH_ID}" 2>/dev/null)"
if [[ -z "${STARTED_BEFORE}" ]] || ! "${COMPOSE[@]}" restart orchestrator >"${WORK}/restart.log" 2>&1; then
  unverified "could not establish that the orchestrator restarted"
  exit 1
fi
STARTED_AFTER="$(docker inspect -f '{{.State.StartedAt}}' "${ORCH_ID}" 2>/dev/null)"
if [[ -z "${STARTED_AFTER}" || "${STARTED_AFTER}" == "${STARTED_BEFORE}" ]]; then
  bad "the orchestrator's StartedAt did not change"
  exit 1
fi
ok "the orchestrator container restarted while the engine sessions existed"

READY=0
for _ in $(seq 1 30); do
  if curl -sS "${AUTH[@]}" -m 2 "${ORCH}/healthz" >/dev/null 2>&1; then
    READY=1
    break
  fi
  sleep 1
done
if [[ "${READY}" != "1" ]]; then
  bad "the restarted orchestrator never became ready"
  exit 1
fi

"${COMPOSE[@]}" logs --no-color orchestrator >"${WORK}/orchestrator-restart.log" 2>&1
if python3 - "${WORK}" "${SESSION}" <<'PY'
import json, pathlib, re, sys
root, base = pathlib.Path(sys.argv[1]), sys.argv[2]
log = (root / "orchestrator-restart.log").read_text()
for suffix in ("a", "b"):
    events = json.loads((root / f"resilience-{suffix}-events-before.json").read_text())["events"]
    observed = max(e["seq"] for e in events if e.get("seq", 0) > 0)
    pattern = rf"resuming session {re.escape(base)}-resilience-{suffix} from seq (\d+) after a restart"
    matches = [int(n) for n in re.findall(pattern, log)]
    assert matches and max(matches) >= observed > 0, (suffix, observed, matches)
PY
then
  ok "both restarted followers resumed from positive, previously stored sequence numbers"
else
  bad "the restarted service did not log a resume point for both active sessions"
  tail -40 "${WORK}/orchestrator-restart.log" | sed 's/^/              /'
  exit 1
fi

SETTLED=0
for _ in $(seq 1 180); do
  for suffix in a b; do
    id="${SESSION}-resilience-${suffix}"
    curl -sS "${AUTH[@]}" -m 5 "${ORCH}/v1/sessions/${id}" >"${WORK}/resilience-${suffix}-view.json" 2>/dev/null
  done
  if python3 - "${WORK}" <<'PY'
import json, pathlib, sys
root = pathlib.Path(sys.argv[1])
try:
    statuses = [json.loads((root / f"resilience-{s}-view.json").read_text())["status"]
                for s in ("a", "b")]
except (OSError, ValueError, KeyError, TypeError):
    sys.exit(1)
sys.exit(0 if all(status != "running" for status in statuses) else 1)
PY
  then SETTLED=1; break; fi
  sleep 1
done
if [[ "${SETTLED}" != "1" ]]; then
  bad "both runs did not settle after the orchestrator restart"
  exit 1
fi

for suffix in a b; do
  id="${SESSION}-resilience-${suffix}"
  curl -sS "${AUTH[@]}" -m 30 "${ORCH}/v1/sessions/${id}/findings" >"${WORK}/resilience-${suffix}-findings.json" 2>/dev/null
  curl -sS "${AUTH[@]}" -m 30 "${ORCH}/v1/sessions/${id}/events?limit=5000" >"${WORK}/resilience-${suffix}-events.json" 2>/dev/null
  if python3 "${REPO_ROOT}/scripts/read_run_report.py" \
      "${WORK}/resilience-${suffix}-view.json" \
      "${WORK}/resilience-${suffix}-findings.json" \
      "${WORK}/resilience-${suffix}-events.json" \
      >"${WORK}/resilience-${suffix}-verdicts.tsv" 2>&1; then
    ok "session ${suffix} completed with a contiguous, complete stored stream after restart"
  else
    bad "session ${suffix} was incomplete after restart"
    sed 's/^/              /' "${WORK}/resilience-${suffix}-verdicts.tsv"
  fi
done

# --- the testbed came through it -------------------------------------------
echo
echo "== the testbed came through it =="
if [[ "$(docker inspect -f '{{.State.Running}}' "${TESTBED_ID}" 2>/dev/null)" == "true" ]]; then
  ok "the testbed survived the run"
else
  bad "the testbed is no longer running"
fi

echo
echo "================================"
printf 'passed: %d   failed: %d   unverified: %d\n' "${PASS}" "${FAIL}" "${UNVERIFIED}"
if [[ "${FAIL}" -eq 0 && "${UNVERIFIED}" -eq 0 ]]; then
  echo "the orchestrator, the engine and the testbed worked together over real sockets"
  exit 0
fi
if [[ "${UNVERIFIED}" -gt 0 && "${FAIL}" -eq 0 ]]; then
  echo "the live path could not be fully verified; treat it as unproven, not as working"
  exit 1
fi
echo "the live path is broken"
exit 1
