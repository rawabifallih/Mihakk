#!/usr/bin/env bash
# Does the runner keep a failing suite's evidence?
#
# Twice a single check failed inside a Docker suite and the cause could not be
# investigated, because the command that ran the suites piped each through `tail`:
# by the time the failure was visible, the name of the failing check and its reason
# had been thrown away. The runner exists to stop that, so the runner needs a test
# that fails if it ever starts summarising again.
#
# Simulated failures, not real suites: the question is what the runner does with a
# non-zero exit and the output that came with it, and a stub answers that in
# milliseconds without Docker.
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RUNNER="${REPO_ROOT}/scripts/test-all.sh"
WORK="$(mktemp -d)"

PASS=0
FAIL=0
ok()   { printf '  \033[32mPASS\033[0m  %s\n' "$1"; PASS=$((PASS + 1)); }
bad()  { printf '  \033[31mFAIL\033[0m  %s\n' "$1"; FAIL=$((FAIL + 1)); }
note() { printf '        %s\n' "$1"; }

cleanup() { rm -rf "${WORK}"; }
trap cleanup EXIT INT TERM

# A stub suite that fails the way a real one does: several passing checks, one
# failing check with a name and a reason, and a tally at the end. The detail sits
# in the MIDDLE of the output, which is exactly what a tail would keep and a head
# would lose.
CHECK_NAME="the testbed container was replaced"
CHECK_REASON="before=993974bd2845 after=d458a3ce3232"

cat >"${WORK}/failing-suite.sh" <<STUB
#!/usr/bin/env bash
echo "== 1. a check that passes =="
echo "  PASS  something fine"
echo "== 2. the check that matters =="
echo "  FAIL  ${CHECK_NAME}"
echo "        ${CHECK_REASON}"
echo "== 3. more checks after it =="
for i in \$(seq 1 40); do echo "  PASS  filler check \$i"; done
echo "================================"
echo "passed: 41   failed: 1"
echo "the suite reports a problem"
exit 1
STUB
chmod +x "${WORK}/failing-suite.sh"

cat >"${WORK}/passing-suite.sh" <<'STUB'
#!/usr/bin/env bash
echo "  PASS  all well"
echo "passed: 1   failed: 0"
exit 0
STUB
chmod +x "${WORK}/passing-suite.sh"

echo "== a failing suite: its evidence must survive =="

OUT="$(MIHAKK_TEST_SUITES="ok-one=${WORK}/passing-suite.sh
broken=${WORK}/failing-suite.sh
ok-two=${WORK}/passing-suite.sh" \
       MIHAKK_TEST_LOGS="${WORK}/logs" \
       "${RUNNER}" 2>&1)"
RC=$?

if [[ ${RC} -ne 0 ]]; then
  ok "the runner exits non-zero when a suite fails (exit ${RC})"
else
  bad "the runner exited 0 despite a failing suite"
fi

if grep -qF "${CHECK_NAME}" <<<"${OUT}"; then
  ok "the failing check's name survives"
else
  bad "the failing check's name was lost"
fi

if grep -qF "${CHECK_REASON}" <<<"${OUT}"; then
  ok "the failing check's reason survives"
else
  bad "the failing check's reason was lost — this is the failure mode being guarded"
fi

# The detail is mid-output, so a tail would have kept the tally and dropped it.
if grep -q "FULL OUTPUT: broken" <<<"${OUT}"; then
  ok "the failing suite's output is printed in full, and labelled"
else
  bad "the runner did not print the failing suite's full output"
fi

if grep -q "filler check 40" <<<"${OUT}" && grep -q "filler check 1$" <<<"${OUT}"; then
  ok "output from both ends of the suite is present, so nothing was truncated"
else
  bad "the output was truncated"
fi

if grep -q "failing suite(s): broken" <<<"${OUT}"; then
  ok "the summary names which suite failed"
else
  bad "the summary does not name the failing suite"
fi

if grep -q "ok-one" <<<"${OUT}" && grep -q "ok-two" <<<"${OUT}"; then
  ok "the suites that passed are reported too"
else
  bad "passing suites are missing from the report"
fi

# Every suite's exit code is recorded, not only the failing one's.
for name in ok-one broken ok-two; do
  if [[ ! -f "${WORK}/logs/${name}.exit" ]]; then
    bad "no exit code was recorded for ${name}"
    break
  fi
done
if [[ -f "${WORK}/logs/broken.exit" && "$(cat "${WORK}/logs/broken.exit")" == "1" ]]; then
  ok "each suite's exit code is kept on disk"
else
  bad "the failing suite's exit code was not recorded"
fi

if [[ -s "${WORK}/logs/broken.log" ]] && grep -qF "${CHECK_REASON}" "${WORK}/logs/broken.log"; then
  ok "each suite's full output is kept on disk for later reading"
else
  bad "the suite log on disk is missing or incomplete"
fi

# A later suite must still run: stopping at the first failure would hide the rest.
if grep -q "ok-two" <<<"${OUT}"; then
  ok "a suite after the failing one still runs"
else
  bad "the runner stopped at the first failure"
fi

echo
echo "== everything passing: the runner says so and exits 0 =="

CLEAN_OUT="$(MIHAKK_TEST_SUITES="a=${WORK}/passing-suite.sh
b=${WORK}/passing-suite.sh" \
             MIHAKK_TEST_LOGS="${WORK}/logs-clean" \
             "${RUNNER}" 2>&1)"
CLEAN_RC=$?

if [[ ${CLEAN_RC} -eq 0 ]]; then
  ok "the runner exits 0 when every suite passes"
else
  bad "the runner exited ${CLEAN_RC} with nothing failing"
  printf '%s\n' "${CLEAN_OUT}" | sed 's/^/        /'
fi

if grep -q "every suite passed" <<<"${CLEAN_OUT}"; then
  ok "it says plainly that everything passed"
else
  bad "no success line"
fi

if ! grep -q "FULL OUTPUT" <<<"${CLEAN_OUT}"; then
  ok "it does not dump output when there is nothing to investigate"
else
  bad "it printed full output for a passing run"
fi

echo
echo "== a suite that reads stdin must not swallow the suite list =="

# The runner reads its suite list from stdin, so a suite that reads stdin too used
# to consume the remaining entries: the run ended after the first such suite and
# reported success for the handful it had managed. It cost six skipped suites
# before it was noticed.
cat >"${WORK}/greedy-suite.sh" <<'STUB'
#!/usr/bin/env bash
cat >/dev/null            # drain whatever is on stdin
echo "  PASS  drained stdin"
exit 0
STUB
chmod +x "${WORK}/greedy-suite.sh"

GREEDY_OUT="$(MIHAKK_TEST_SUITES="first=${WORK}/greedy-suite.sh
second=${WORK}/passing-suite.sh
third=${WORK}/passing-suite.sh" \
              MIHAKK_TEST_LOGS="${WORK}/logs-greedy" \
              "${RUNNER}" 2>&1)"
GREEDY_RC=$?

if [[ ${GREEDY_RC} -eq 0 ]]; then
  ok "the run with a stdin-reading suite finished cleanly"
else
  bad "the run failed unexpectedly (exit ${GREEDY_RC})"
fi

RAN=0
for name in first second third; do
  [[ -f "${WORK}/logs-greedy/${name}.exit" ]] && RAN=$((RAN + 1))
done
if [[ ${RAN} -eq 3 ]]; then
  ok "every suite after the stdin-reading one still ran (${RAN}/3)"
else
  bad "only ${RAN}/3 suites ran: a suite swallowed the list"
fi

if grep -q "suites passed: 3" <<<"${GREEDY_OUT}"; then
  ok "the summary counts all three"
else
  bad "the summary does not account for all three suites"
  printf '%s\n' "${GREEDY_OUT}" | tail -6 | sed 's/^/        /'
fi

echo
echo "== a suite that produces nothing but fails =="

cat >"${WORK}/silent-suite.sh" <<'STUB'
#!/usr/bin/env bash
exit 3
STUB
chmod +x "${WORK}/silent-suite.sh"

SILENT_OUT="$(MIHAKK_TEST_SUITES="silent=${WORK}/silent-suite.sh" \
              MIHAKK_TEST_LOGS="${WORK}/logs-silent" \
              "${RUNNER}" 2>&1)"
SILENT_RC=$?
if [[ ${SILENT_RC} -ne 0 ]] && grep -q "exit 3" <<<"${SILENT_OUT}"; then
  ok "a suite that fails silently still reports its exit code"
else
  bad "a silent failure was not reported with its exit code"
fi

echo
echo "== a suite that prints a token =="

# The runner keeps logs in full and prints a failing suite's log in full, which is
# exactly why a token printed by any suite has to be caught -- and caught without
# the catching itself repeating the value. The token is this check's own; the
# runner is told it through the environment, the way it tells the suites.
LEAK_TOKEN="$(head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n')"
cat >"${WORK}/leaky-suite.sh" <<'STUB'
#!/usr/bin/env bash
echo "  PASS  something unrelated"
echo "debug: logging in with ${MIHAKK_DASHBOARD_TOKEN}"
exit 0
STUB
chmod +x "${WORK}/leaky-suite.sh"

LEAK_OUT="$(MIHAKK_DASHBOARD_TOKEN="${LEAK_TOKEN}" \
            MIHAKK_TEST_SUITES="leaky=${WORK}/leaky-suite.sh" \
            MIHAKK_TEST_LOGS="${WORK}/logs-leaky" \
            "${RUNNER}" 2>&1)"
LEAK_RC=$?
if [[ ${LEAK_RC} -ne 0 ]] && grep -q "leaky.log:2: MIHAKK_DASHBOARD_TOKEN" <<<"${LEAK_OUT}"; then
  ok "a token in a suite's output fails the run, located by file and line"
else
  bad "a token in a suite's output went unreported (exit ${LEAK_RC})"
fi
if grep -qF "${LEAK_TOKEN}" <<<"${LEAK_OUT}"; then
  bad "the runner's own output repeats the token it found"
else
  ok "the runner reports the leak without repeating the value"
fi
if grep -qF "${LEAK_TOKEN}" "${WORK}/logs-leaky/leaky.log" 2>/dev/null; then
  bad "the kept log still holds the token"
elif grep -q "REDACTED:MIHAKK_DASHBOARD_TOKEN" "${WORK}/logs-leaky/leaky.log" 2>/dev/null; then
  ok "the kept log is redacted, and says where the value was"
else
  bad "the kept log is missing or was not redacted"
fi

echo
echo "================================"
printf 'passed: %d   failed: %d\n' "${PASS}" "${FAIL}"
if [[ ${FAIL} -eq 0 ]]; then
  echo "the runner keeps a failing suite's evidence"
  exit 0
fi
echo "the runner loses evidence"
exit 1
