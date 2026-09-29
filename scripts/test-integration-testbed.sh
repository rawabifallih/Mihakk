#!/usr/bin/env bash
# End-to-end run of the engine against the real testbed.
#
# The Go tests exercise the same logic against loopback servers that mimic the
# planted behaviours. This runs the actual engine binary against the actual
# testbed container, over the isolated Docker network, and checks the whole
# path: baseline, run, detection, stored cases, audit log, reproduce.
#
# Everything happens inside the internal network. The engine container is
# attached to it, the testbed publishes nothing to the host, and the scope
# authorises exactly one address: the testbed container's own IP.
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
COMPOSE=(docker compose -f "${REPO_ROOT}/deploy/docker-compose.yml")
NETWORK="mihakk-internal"
GO_IMAGE="${MIHAKK_GO_IMAGE:-golang:1.25-alpine}"
WORK="$(mktemp -d)"
DATA="${WORK}/data"

# docker compose interpolates the whole file before it selects a service, and
# the engine service declares ${MIHAKK_CONTROL_TOKEN:?...}. Without a value even
# `up testbed` fails, though this script never starts the engine service. The
# placeholder therefore resolves the file and authenticates nothing.
export MIHAKK_CONTROL_TOKEN="${MIHAKK_CONTROL_TOKEN:-integration-placeholder}"
# The compose file now requires the dashboard token as well, for the same
# interpolation reason. This script starts no orchestrator, so the value is
# never used as a credential.
export MIHAKK_DASHBOARD_TOKEN="${MIHAKK_DASHBOARD_TOKEN:-dashboard-placeholder}"

# A fixed seed, so the run is the same one every time.
SEED="6d6968616b6b2d70686173652d34"
MUTATIONS_PER_TARGET=24

PASS=0
FAIL=0
ok()   { printf '  \033[32mPASS\033[0m  %s\n' "$1"; PASS=$((PASS + 1)); }
bad()  { printf '  \033[31mFAIL\033[0m  %s\n' "$1"; FAIL=$((FAIL + 1)); }
note() { printf '        %s\n' "$1"; }

STARTED_TESTBED=0
cleanup() {
  if [[ "${STARTED_TESTBED}" == "1" ]]; then
    "${COMPOSE[@]}" stop testbed >/dev/null 2>&1 || true
    "${COMPOSE[@]}" rm -f testbed >/dev/null 2>&1 || true
  fi
  rm -rf "${WORK}"
}
trap cleanup EXIT

mkdir -p "${DATA}" "${REPO_ROOT}/.gocache/build" "${REPO_ROOT}/.gocache/mod"

# Run the engine inside a container attached to the testbed's internal
# network. That network has no route out, so this also demonstrates the engine
# working with no internet access at all.
engine() {
  docker run --rm \
    --network "${NETWORK}" \
    -v "${REPO_ROOT}:/src" \
    -v "${REPO_ROOT}/.gocache:/gocache" \
    -v "${WORK}:/work" \
    -w /src/engine \
    -e GOCACHE=/gocache/build \
    -e GOMODCACHE=/gocache/mod \
    "${GO_IMAGE}" go run ./cmd/mihakk "$@"
}

echo "== starting the testbed =="
if [[ "$(docker inspect -f '{{.State.Running}}' mihakk-testbed 2>/dev/null | tr -d '[:space:]')" != "true" ]]; then
  STARTED_TESTBED=1
  # Keeping compose's own diagnosis: "could not start the testbed" on its own
  # sent a reader looking at the Docker daemon when the actual cause was a
  # missing variable.
  if ! "${COMPOSE[@]}" up -d --build testbed >"${WORK}/compose.log" 2>&1; then
    bad "could not start the testbed"
    tail -5 "${WORK}/compose.log" | sed 's/^/        /'
    exit 1
  fi
fi
for _ in $(seq 1 30); do
  [[ "$(docker inspect -f '{{.State.Health.Status}}' mihakk-testbed 2>/dev/null)" == "healthy" ]] && break
  sleep 1
done

TESTBED_IP="$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' mihakk-testbed 2>/dev/null | tr -d '[:space:]')"
if [[ -z "${TESTBED_IP}" ]]; then
  bad "could not determine the testbed's address"
  exit 1
fi
note "testbed is at ${TESTBED_IP} on ${NETWORK}"

# The scope authorises the testbed's single address, not its subnet.
write_config() {
  local digest="$1"
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
    "max_total_requests": 600,
    "max_concurrency": 4,
    "max_session_duration": "3m",
    "request_timeout": "10s",
    "max_response_bytes": 1048576
  },
  "authorization": {
    "operator": "integration-script",
    "statement": "I am authorised to test the targets listed in this scope.",
    "acked_at": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
    "scope_digest": "${digest}"
  }
}
JSON
}

# The acknowledgement is bound to the scope digest, so the engine is asked
# what the digest is rather than it being guessed.
write_config "sha256:0000000000000000000000000000000000000000000000000000000000000000"
DIGEST="$(engine scope-check -config /work/session.json 2>&1 |
  grep -o 'the configured scope is sha256:[0-9a-f]*' | awk '{print $NF}')"
if [[ -z "${DIGEST}" ]]; then
  bad "could not obtain the scope digest"
  engine scope-check -config /work/session.json 2>&1 | tail -5
  exit 1
fi
write_config "${DIGEST}"

if engine scope-check -config /work/session.json >/dev/null 2>&1; then
  ok "the session config is accepted (authorisation bound to ${DIGEST:0:20}...)"
else
  bad "the session config was refused"
  engine scope-check -config /work/session.json 2>&1 | tail -5
  exit 1
fi

echo
echo "== running against the testbed =="
RUN_OUT="${WORK}/run.txt"
engine run \
  -config /work/session.json \
  -corpus /src/testbed/corpus.json \
  -data /work/data \
  -seed "${SEED}" \
  -session-id integration \
  -mutations-per-target "${MUTATIONS_PER_TARGET}" \
  -quiet >"${RUN_OUT}" 2>&1
RUN_RC=$?

if [[ ${RUN_RC} -ne 0 ]]; then
  bad "the run failed (exit ${RUN_RC})"
  tail -20 "${RUN_OUT}"
  exit 1
fi
sed -n '1,12p' "${RUN_OUT}" | sed 's/^/        /'

CASES="${DATA}/sessions/integration/cases.jsonl"
if [[ ! -s "${CASES}" ]]; then
  bad "the run saved no cases"
  tail -20 "${RUN_OUT}"
  exit 1
fi

# --- What was detected -----------------------------------------------------
echo
echo "== detection =="
SUMMARY="$(python3 - "${CASES}" <<'PY'
import json, sys, collections, pathlib

by_type = collections.Counter()
by_path = collections.defaultdict(set)
stable_hits = 0
missing_recipe = 0
overclaims = 0

for line in pathlib.Path(sys.argv[1]).read_text().splitlines():
    if not line.strip():
        continue
    case = json.loads(line)
    url = case["request_summary"]["url"]
    for ind in case["indicators"]:
        by_type[ind["type"]] += 1
        by_path[url.split("?")[0]].add(ind["type"])
        if not ind.get("reason"):
            overclaims += 1
        if "confidence" in ind:
            overclaims += 1
    if "/api/items" in url:
        stable_hits += 1
    rep = case.get("reproduction", {})
    if not all(rep.get(k) for k in ("engine_version", "master_seed", "corpus_digest", "config_digest")):
        missing_recipe += 1
    if case.get("status") != "indicator_needs_verification":
        overclaims += 1

print(json.dumps({
    "by_type": dict(by_type),
    "stable_hits": stable_hits,
    "missing_recipe": missing_recipe,
    "overclaims": overclaims,
    "paths": {p: sorted(t) for p, t in by_path.items()},
}))
PY
)"
note "$(printf '%s' "${SUMMARY}" | python3 -c 'import json,sys; d=json.load(sys.stdin); print("indicators:", d["by_type"])')"

field() { printf '%s' "${SUMMARY}" | python3 -c "import json,sys; print(json.load(sys.stdin)$1)"; }

if [[ "$(field '["by_type"].get("http_5xx", 0)')" -gt 0 ]]; then
  ok "the planted 5xx was detected"
else
  bad "the planted 5xx was not detected"
fi

if [[ "$(field '["by_type"].get("latency_anomaly", 0)')" -gt 0 ]]; then
  ok "the planted slow path was detected"
else
  bad "the planted slow path was not detected"
fi

if [[ "$(field '["stable_hits"]')" -eq 0 ]]; then
  ok "the stable path produced no indicator"
else
  bad "the stable path produced $(field '["stable_hits"]') indicator(s)"
  field '["paths"]'
fi

if [[ "$(field '["missing_recipe"]')" -eq 0 ]]; then
  ok "every saved case carries a full regeneration recipe"
else
  bad "$(field '["missing_recipe"]') case(s) cannot be regenerated"
fi

if [[ "$(field '["overclaims"]')" -eq 0 ]]; then
  ok "every case is recorded as an indicator needing verification, with a reason and no confidence"
else
  bad "$(field '["overclaims"]') case(s) overclaim or lack a reason"
fi

# --- Audit -----------------------------------------------------------------
echo
echo "== audit log =="
AUDIT="${DATA}/audit.jsonl"
if [[ -s "${AUDIT}" ]]; then
  AUDIT_CHECK="$(python3 - "${AUDIT}" <<'PY'
import json, sys, pathlib
events = [json.loads(l) for l in pathlib.Path(sys.argv[1]).read_text().splitlines() if l.strip()]
types = {e["type"] for e in events}
started = next((e for e in events if e["type"] == "session_started"), None)
problems = []
for required in ("session_started", "session_stopped"):
    if required not in types:
        problems.append(f"no {required} event")
if started:
    for field in ("operator", "statement", "authorisation_acked_at", "scope_digest", "limits", "targets", "seed"):
        if not started.get(field):
            problems.append(f"session_started has no {field}")
print(json.dumps({"events": len(events), "problems": problems}))
PY
)"
  if [[ "$(printf '%s' "${AUDIT_CHECK}" | python3 -c 'import json,sys; print(len(json.load(sys.stdin)["problems"]))')" -eq 0 ]]; then
    ok "the audit log records who, when, on what authority, against what, under which limits"
    note "$(printf '%s' "${AUDIT_CHECK}" | python3 -c 'import json,sys; print(json.load(sys.stdin)["events"], "events")')"
  else
    bad "the audit log is incomplete"
    printf '%s' "${AUDIT_CHECK}" | python3 -c 'import json,sys; [print("       ", p) for p in json.load(sys.stdin)["problems"]]'
  fi
else
  bad "no audit log was written"
fi

# --- Reproduce -------------------------------------------------------------
echo
echo "== reproduce =="
CASE_ID="$(python3 - "${CASES}" <<'PY'
import json, sys, pathlib
for line in pathlib.Path(sys.argv[1]).read_text().splitlines():
    if not line.strip():
        continue
    case = json.loads(line)
    if any(i["type"] == "http_5xx" for i in case["indicators"]):
        print(case["case_id"])
        break
PY
)"
if [[ -z "${CASE_ID}" ]]; then
  bad "no 5xx case to reproduce"
else
  note "reproducing ${CASE_ID}"
  REPRO="${WORK}/repro.json"
  engine reproduce "${CASE_ID}" \
    -config /work/session.json \
    -corpus /src/testbed/corpus.json \
    -data /work/data -json >"${REPRO}" 2>"${WORK}/repro.err"
  REPRO_RC=$?

  if [[ ${REPRO_RC} -ne 0 ]]; then
    bad "reproduce failed (exit ${REPRO_RC})"
    tail -10 "${WORK}/repro.err"
  else
    REPRO_CHECK="$(python3 - "${REPRO}" <<'PY'
import json, sys, pathlib
r = json.loads(pathlib.Path(sys.argv[1]).read_text())
problems = []
if not r.get("authorization_revalidated"):
    problems.append("authorisation was not re-validated")
if not r.get("scope_digest"):
    problems.append("no scope digest recorded")
if r.get("fidelity") not in ("exact", "drifted"):
    problems.append(f"unexpected fidelity {r.get('fidelity')!r}")
if "indicator_reappeared" not in r:
    problems.append("no answer about the indicator")
note = (r.get("comparison_note") or "").lower()
if not note:
    problems.append("no comparison note")
for claim in ("vulnerability confirmed", "is a confirmed vulnerability", "exploitable"):
    if claim in note:
        problems.append(f"the note overclaims: {claim}")
print(json.dumps({
    "problems": problems,
    "fidelity": r.get("fidelity"),
    "reappeared": r.get("indicator_reappeared"),
    "note": r.get("comparison_note"),
}))
PY
)"
    if [[ "$(printf '%s' "${REPRO_CHECK}" | python3 -c 'import json,sys; print(len(json.load(sys.stdin)["problems"]))')" -eq 0 ]]; then
      ok "reproduce re-validated authorisation and scope, and answered without overclaiming"
      note "fidelity=$(printf '%s' "${REPRO_CHECK}" | python3 -c 'import json,sys; print(json.load(sys.stdin)["fidelity"])') reappeared=$(printf '%s' "${REPRO_CHECK}" | python3 -c 'import json,sys; print(json.load(sys.stdin)["reappeared"])')"
      note "$(printf '%s' "${REPRO_CHECK}" | python3 -c 'import json,sys; print(json.load(sys.stdin)["note"][:150])')"
    else
      bad "the reproduce result is not acceptable"
      printf '%s' "${REPRO_CHECK}" | python3 -c 'import json,sys; [print("       ", p) for p in json.load(sys.stdin)["problems"]]'
    fi
  fi
fi

# --- The target must still be alive ----------------------------------------
echo
echo "== the testbed survived =="
if [[ "$(docker inspect -f '{{.State.Running}}' mihakk-testbed 2>/dev/null | tr -d '[:space:]')" == "true" ]]; then
  ok "the testbed container is still running after the run"
else
  bad "the testbed container died during the run"
fi

echo
echo "================================"
printf 'passed: %d   failed: %d\n' "${PASS}" "${FAIL}"
[[ ${FAIL} -gt 0 ]] && exit 1
echo "the engine detected both planted behaviours on the real testbed, left the stable path alone, and reproduced a case"
