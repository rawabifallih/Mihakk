#!/usr/bin/env bash
# The dashboard, in a real browser.
#
# This is the only test in the project that needs a browser, and the only one that
# pulls an image beyond the base ones. It is kept in a script of its own, outside
# the fast suites, for that reason: scripts/check_dashboard_js.py asserts the same
# property against the source in about a second, so the guard that runs on every
# commit is that one and this is the confirmation against a real DOM.
#
# What only a browser can answer: did anything execute, did the hostile payload
# survive as text, did the Content-Security-Policy actually arrive, and is the
# target's own output visually and structurally separated from the judgement.
#
# Everything runs in a throwaway compose project, as the live integration test
# does, so an operator's own stack is untouched.
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORK="$(mktemp -d)"
PROJECT="mihakk-browser-$$-$(date +%s)"

# The Playwright base ships the browsers but not the Python package, so a thin
# image is built on top of it once and cached. Only the first run needs the
# network; this is the one test in the project that does.
BROWSER_BASE="${MIHAKK_BROWSER_BASE:-mcr.microsoft.com/playwright/python:v1.49.0-noble}"
BROWSER_IMAGE="${MIHAKK_BROWSER_IMAGE:-mihakk-browser-test:dev}"

export MIHAKK_CONTROL_TOKEN="${MIHAKK_CONTROL_TOKEN:-$(head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n')}"
export MIHAKK_DASHBOARD_TOKEN="${MIHAKK_DASHBOARD_TOKEN:-$(head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n')}"

PASS=0
FAIL=0
ok()   { printf '  \033[32mPASS\033[0m  %s\n' "$1"; PASS=$((PASS + 1)); }
bad()  { printf '  \033[31mFAIL\033[0m  %s\n' "$1"; FAIL=$((FAIL + 1)); }
note() { printf '        %s\n' "$1"; }

NETWORK="${PROJECT}-net"
CREATED_NETWORK=0
ORCH_CONTAINER="${PROJECT}-orchestrator"
CREATED_ORCH=0

cleanup() {
  local rc=$?
  trap - EXIT INT TERM
  [[ "${CREATED_ORCH}" == "1" ]] && docker rm -f "${ORCH_CONTAINER}" >/dev/null 2>&1
  [[ "${CREATED_NETWORK}" == "1" ]] && docker network rm "${NETWORK}" >/dev/null 2>&1
  rm -rf "${WORK}"
  exit "${rc}"
}
trap cleanup EXIT INT TERM

echo "== building the browser image (cached after the first run) =="
if ! docker build -q -t "${BROWSER_IMAGE}" \
     --build-arg "BASE=${BROWSER_BASE}" \
     -f "${REPO_ROOT}/scripts/browser-test.Dockerfile" \
     "${REPO_ROOT}/scripts" >/dev/null; then
  bad "the browser image did not build"
  exit 1
fi

echo
echo "== building the orchestrator image =="
if ! docker build -q -t mihakk-orchestrator:dev \
     -f "${REPO_ROOT}/orchestrator/Dockerfile" "${REPO_ROOT}" >/dev/null; then
  bad "the orchestrator image did not build"
  exit 1
fi

# A stub engine, so this test is about the dashboard and not about a real run. It
# serves one session whose every rendered field carries a hostile payload.
cat >"${WORK}/stub_engine.py" <<'STUB'
"""A stand-in engine that serves one session full of hostile content."""
import json
from http.server import BaseHTTPRequestHandler, HTTPServer

PAYLOAD = (
    "<script>window.__pwned = 1;</script>"
    "\"><img src=x onerror=\"window.__pwned=1\">"
    "</textarea></pre><script>window.__pwned=1</script>"
    "<iframe src=\"//evil.invalid\"></iframe>"
    "<a href=\"javascript:window.__pwned=1\">click</a>"
    "javascript:window.__pwned=1"
    "{{7*7}} ${7*7}"
    "vulnerability detected — exploited successfully"
)

def group(gid, indicator_type, cases):
    return {
        "group_id": "sha256:" + gid * 64,
        "signature": {"indicator_type": indicator_type, "target": PAYLOAD,
                      "method": "GET", "path": "/api/" + PAYLOAD,
                      "status_code": 500 if indicator_type == "http_5xx" else None},
        "occurrences": len(cases),
        "mutators": ["truncate", "null-byte"],
        "case_ids": cases,
        "representative": {
            "case_id": cases[0], "case_index": 1, "reason": PAYLOAD,
            "reproduction": {"engine_version": "0.7.0-stub", "master_seed": "ab",
                             "case_index": 1,
                             "corpus_digest": "sha256:" + "b" * 64,
                             "config_digest": "sha256:" + "c" * 64,
                             "target": PAYLOAD},
            "request_summary": {"method": "GET",
                                "url": "http://testbed:8000/api/items?q=" + PAYLOAD,
                                "redacted": True, "body_preview": PAYLOAD},
            "response_summary": {"status_code": 500, "latency_ms": 12.5,
                                 "body_bytes": 40, "truncated": False,
                                 "error": PAYLOAD},
        },
        "first_observed_at": "2026-01-01T00:00:01Z",
        "last_observed_at": "2026-01-01T00:00:02Z",
    }

GROUPS = [group("d", "http_5xx", ["hostile-000001", "hostile-000002"]),
          group("e", "latency_anomaly", ["hostile-000003"])]

AGGREGATE = {
    "aggregate_version": "1",
    "session": {"session_id": "hostile", "engine_version": "0.7.0-stub",
                "started_at": "2026-01-01T00:00:00Z", "status": "completed",
                "operator": PAYLOAD, "corpus_digest": "sha256:" + "b" * 64,
                "config_digest": "sha256:" + "c" * 64, "planned_cases": 10,
                "executed_cases": 10, "saved_cases": 3, "refused_cases": 0,
                # Redirect hops: 13 cases and baseline requests, 25 HTTP requests.
                "accounting": {"cases_attempted": 10, "cases_answered": 10,
                               "baseline_attempted": 3,
                               "baseline_refused": 0, "baseline_answered": 3,
                               "http_answered": 25, "http_unanswered": 0,
                               "http_refused": 0}},
    "scope": {"recorded": True, "consistent": True,
              "digest": "sha256:" + "a" * 64,
              "recomputed_digest": "sha256:" + "a" * 64, "max_redirects": 2,
              "targets": [{"scheme": "http", "host": PAYLOAD, "port": 8000,
                           "path_prefixes": ["/api/" + PAYLOAD],
                           "methods": ["GET"]}],
              "targets_summary": ["http://testbed:8000"],
              "withheld": ["allowed_addresses"]},
    "completeness": {"engine_status": "completed", "saved_cases_stated": 3,
                     "cases_in_store": 3, "unsaved_cases": 0,
                     "audit_failures": 0, "consistent": True},
    "totals": {"cases": 3, "indicator_instances": 3, "groups": 2},
    "groups": GROUPS,
    "note": "Results are indicators that need verification, not confirmed vulnerabilities.",
}

# Three sessions besides "hostile", each for one claim the dashboard must not make.
def variant(session_id, executed, refused, accounting):
    doc = json.loads(json.dumps(AGGREGATE))
    doc["session"].update(session_id=session_id, operator="browser-test",
                          executed_cases=executed, saved_cases=0, refused_cases=refused,
                          accounting=accounting)
    doc["completeness"].update(saved_cases_stated=0, cases_in_store=0)
    doc["totals"] = {"cases": 0, "indicator_instances": 0, "groups": 0}
    doc["groups"] = []
    return doc

# Refused in full: completed, stored nothing, attempted nothing.
REFUSED = variant("refused-all", 0, 10, {
    "cases_attempted": 0, "cases_answered": 0,
    "baseline_attempted": 0, "baseline_refused": 3,
    "baseline_answered": 0, "http_answered": 0, "http_unanswered": 0, "http_refused": 13})
# The target refused the connection: every request attempted, none answered.
NO_ANSWER = variant("no-answer", 10, 0, {
    "cases_attempted": 10, "cases_answered": 0,
    "baseline_attempted": 3, "baseline_refused": 0,
    "baseline_answered": 0, "http_answered": 0, "http_unanswered": 13, "http_refused": 0})
# Recorded before the counts existed: accounting null, never zero.
LEGACY = variant("legacy", 10, 0, None)
AGGREGATES = {"hostile": AGGREGATE, "refused-all": REFUSED,
              "no-answer": NO_ANSWER, "legacy": LEGACY}


class Handler(BaseHTTPRequestHandler):
    def _send(self, code, body):
        raw = json.dumps(body).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def do_GET(self):
        if self.path == "/healthz":
            return self._send(200, {"status": "ok"})
        if self.path.endswith("/aggregate"):
            run = self.path.split("/")[3] if self.path.count("/") >= 4 else ""
            return self._send(200, AGGREGATES.get(run, AGGREGATE))
        if "/events" in self.path:
            self.send_response(200)
            self.send_header("Content-Type", "application/x-ndjson")
            self.end_headers()
            return
        return self._send(404, {"error": "not_found"})

    def do_POST(self):
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length) if length else b"{}"
        try:
            parsed = json.loads(body or b"{}")
        except Exception:
            parsed = {}
        ack = ((parsed.get("config") or {}).get("authorization") or {})
        if ack.get("operator") == "not-authorised":
            # The engine's refusal, in the shape the real one uses. The dashboard
            # must show this as it arrived rather than rewording it.
            return self._send(403, {
                "error": "authorization_required",
                "detail": "mihakk: the authorisation acknowledgement is not valid "
                          "for this scope",
            })
        return self._send(202, {"session_id": "hostile",
                                "engine_version": "0.7.0-stub",
                                "scope_digest": "sha256:" + "a" * 64,
                                "corpus_digest": "sha256:" + "b" * 64,
                                "config_digest": "sha256:" + "c" * 64,
                                "planned_cases": 10})

    def do_DELETE(self):
        return self._send(202, {"stopping": True})

    def log_message(self, *args):
        pass


HTTPServer(("0.0.0.0", 8900), Handler).serve_forever()
STUB

# Seed the orchestrator's database with the session the stub describes, so the
# dashboard has something to list without a real run.
cat >"${WORK}/seed.py" <<'SEED'
import sys
sys.path.insert(0, "/srv")
from app import db as store

database = store.Database("/data/mihakk.db")
database.create_session("hostile", "2026-01-01T00:00:00Z")
database.append_event("hostile", {"seq": 1, "type": "started", "session_id": "hostile",
                                  "at": "2026-01-01T00:00:00Z",
                                  "progress": {"requests_used": 0, "elapsed_ms": 0}})
database.append_event("hostile", {"seq": 2, "type": "progress", "session_id": "hostile",
                                  "at": "2026-01-01T00:00:01Z",
                                  "progress": {"requests_used": 9, "elapsed_ms": 1000,
                                               "executed": 2, "refused": 0, "answered": 2,
                                               "attempted": 2,
                                               "baseline_attempted": 3, "baseline_refused": 0,
                                               "baseline_answered": 3, "http_answered": 9,
                                               "http_unanswered": 0, "http_refused": 0}})
database.append_event("hostile", {"seq": 3, "type": "progress", "session_id": "hostile",
                                  "at": "2026-01-01T00:00:02Z",
                                  "progress": {"requests_used": 25, "elapsed_ms": 2500,
                                               "executed": 10, "refused": 0, "answered": 10,
                                               "attempted": 10,
                                               "baseline_attempted": 3, "baseline_refused": 0,
                                               "baseline_answered": 3, "http_answered": 25,
                                               "http_unanswered": 0, "http_refused": 0}})
database.append_event("hostile", {"seq": 4, "type": "done", "session_id": "hostile",
                                  "at": "2026-01-01T00:00:03Z",
                                  "done": {"status": "completed", "total_seq": 4}})
database.update_session("hostile", total_seq=4, engine_status="completed",
                        status=store.COMPLETED, ended_at="2026-01-01T00:00:03Z")
database.refresh_completeness("hostile")

# Created earlier than "hostile", so the list keeps "hostile" first.
def seed(session_id, created, progresses):
    database.create_session(session_id, created)
    kinds = [("started", None)] + [("progress", p) for p in progresses] + [("done", None)]
    for seq, (kind, payload) in enumerate(kinds, start=1):
        e = {"seq": seq, "type": kind, "session_id": session_id, "at": created}
        if kind == "progress":
            e["progress"] = payload
        if kind == "done":
            e["done"] = {"status": "completed", "total_seq": len(kinds)}
        database.append_event(session_id, e)
    database.update_session(session_id, total_seq=len(kinds), engine_status="completed",
                            status=store.COMPLETED, ended_at=created)
    database.refresh_completeness(session_id)

def counts(used, ms, ex, rf, an, ba, br, bn, ha, hu, hr):
    return {"requests_used": used, "elapsed_ms": ms, "executed": ex, "refused": rf,
            "attempted": ex, "answered": an,
            "baseline_attempted": ba, "baseline_refused": br,
            "baseline_answered": bn, "http_answered": ha, "http_unanswered": hu,
            "http_refused": hr}

seed("refused-all", "2025-12-31T00:00:00Z", [
    counts(3, 400, 0, 0, 0, 0, 3, 0, 0, 0, 3), counts(13, 900, 0, 10, 0, 0, 3, 0, 0, 0, 13)])
seed("no-answer", "2025-12-30T00:00:00Z", [
    counts(3, 400, 0, 0, 0, 3, 0, 0, 0, 3, 0), counts(13, 900, 10, 0, 0, 3, 0, 0, 0, 13, 0)])
# An engine from before the counts: progress without them.
seed("legacy", "2025-12-29T00:00:00Z", [
    {"requests_used": 5, "elapsed_ms": 400, "executed": 2, "refused": 0},
    {"requests_used": 13, "elapsed_ms": 900, "executed": 10, "refused": 0}])
database.close()
print("seeded")
SEED

# Configurations the browser test uploads: one the stub accepts and one whose
# acknowledgement it refuses.
cat >"${WORK}/config-good.json" <<'CFG'
{
  "config_version": "1",
  "scope": {
    "targets": [{"scheme": "http", "host": "testbed", "port": 8000,
                 "path_prefixes": ["/api"], "methods": ["GET"],
                 "allowed_addresses": ["172.19.0.2/32"]}],
    "max_redirects": 2
  },
  "limits": {"requests_per_second": 50, "burst": 10, "max_total_requests": 100,
             "max_concurrency": 2, "max_session_duration": "1m",
             "request_timeout": "5s", "max_response_bytes": 1048576},
  "authorization": {"operator": "browser-test",
                    "statement": "I am authorised to test the targets listed in this scope.",
                    "acked_at": "2026-01-01T00:00:00Z",
                    "scope_digest": "sha256:0000000000000000000000000000000000000000000000000000000000000000"}
}
CFG

sed 's/"browser-test"/"not-authorised"/' "${WORK}/config-good.json" \
  >"${WORK}/config-refused.json"

cat >"${WORK}/corpus.json" <<'CORPUS'
{"corpus_version": "1",
 "samples": [{"id": "items", "method": "GET",
              "url": "http://testbed:8000/api/items?page=1",
              "headers": {"Authorization": ["Bearer super-secret-value-do-not-show"]}}]}
CORPUS

echo
echo "== starting a throwaway orchestrator with a stub engine =="
docker network create "${NETWORK}" >/dev/null 2>&1 && CREATED_NETWORK=1

if ! docker run -d --name "${ORCH_CONTAINER}" \
      --network "${NETWORK}" \
      -v "${WORK}:/work" \
      -e MIHAKK_CONTROL_TOKEN="${MIHAKK_CONTROL_TOKEN}" \
      -e MIHAKK_DASHBOARD_TOKEN="${MIHAKK_DASHBOARD_TOKEN}" \
      -e MIHAKK_ENGINE_URL="http://127.0.0.1:8900" \
      -e MIHAKK_DB="/data/mihakk.db" \
      -e MIHAKK_ALLOWED_HOSTS="${ORCH_CONTAINER}:8100,127.0.0.1:8100,localhost:8100" \
      --user root \
      mihakk-orchestrator:dev \
      sh -c 'mkdir -p /data && python3 /work/seed.py \
             && (python3 /work/stub_engine.py &) \
             && exec uvicorn app.main:app --host 0.0.0.0 --port 8100' \
      >/dev/null 2>&1; then
  bad "the orchestrator container did not start"
  exit 1
fi
CREATED_ORCH=1

READY=0
for _ in $(seq 1 60); do
  if docker run --rm --network "${NETWORK}" "${BROWSER_IMAGE}" \
       python3 -c "
import sys, urllib.request
try:
    urllib.request.urlopen('http://${ORCH_CONTAINER}:8100/healthz', timeout=2)
except Exception:
    sys.exit(1)
" >/dev/null 2>&1; then
    READY=1
    break
  fi
  sleep 1
done

if [[ "${READY}" != "1" ]]; then
  bad "the orchestrator never became reachable"
  docker logs "${ORCH_CONTAINER}" 2>&1 | tail -20 | sed 's/^/        /'
  exit 1
fi
ok "the orchestrator is up with a stub engine and a seeded session"

echo
echo "== the dashboard in Chromium =="
docker run --rm \
  --network "${NETWORK}" \
  -v "${REPO_ROOT}/scripts:/checks:ro" \
  -v "${WORK}:/uploads:ro" \
  -e MIHAKK_DASHBOARD_URL="http://${ORCH_CONTAINER}:8100" \
  -e MIHAKK_UPLOADS="/uploads" \
  -e MIHAKK_DASHBOARD_TOKEN="${MIHAKK_DASHBOARD_TOKEN}" \
  -e MIHAKK_CONTROL_TOKEN="${MIHAKK_CONTROL_TOKEN}" \
  -w /checks \
  "${BROWSER_IMAGE}" python3 dashboard_browser_test.py
BROWSER_RC=$?

if [[ "${BROWSER_RC}" -eq 0 ]]; then
  ok "every browser check passed"
else
  bad "the browser checks failed (exit ${BROWSER_RC})"
fi

echo
echo "================================"
printf 'passed: %d   failed: %d\n' "${PASS}" "${FAIL}"
if [[ "${FAIL}" -eq 0 ]]; then
  echo "the dashboard renders hostile content as text and executes none of it"
  exit 0
fi
echo "the dashboard is not safe to serve"
exit 1
