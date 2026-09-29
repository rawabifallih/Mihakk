#!/usr/bin/env bash
# Run the test suites, keeping every one's output and exit code.
#
# This exists because of a specific way evidence was lost, twice. Running the
# suites from one ad-hoc command and piping each through `tail` meant that when a
# single check failed, the name of that check and its reason had already been
# discarded by the time the failure was visible -- so two Docker failures went
# uninvestigated and had to be recorded as undetermined.
#
# So: each suite writes its full output to a file, the summary reports every exit
# code, and a failure prints the failing suite's output IN FULL rather than its
# tail. Nothing is summarised on the path where the detail is what matters.
#
# The slow Docker suites are opt-in, because most runs do not want twenty minutes:
#
#   scripts/test-all.sh            the fast suites (five)
#   scripts/test-all.sh --all      those plus the live Docker ones
#   scripts/test-all.sh --browser  those plus the browser test
#
# MIHAKK_TEST_SUITES overrides the list, as "name=command" entries separated by
# newlines. That is how the runner's own failure handling is tested.
#
# Every suite gets the same pair of tokens for the run (generated here unless
# already set), and when the suites are done every kept log and every file git
# tracks is searched for them. A hit fails the run, is reported by file, line and
# which token -- never by value -- and is redacted in the kept log, because a log
# kept as evidence should not keep the secret along with it.
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LOG_DIR="${MIHAKK_TEST_LOGS:-$(mktemp -d)}"
KEEP_LOGS="${MIHAKK_KEEP_LOGS:-0}"

mkdir -p "${LOG_DIR}"

WITH_DOCKER=0
WITH_BROWSER=0
for arg in "$@"; do
  case "${arg}" in
    --all)     WITH_DOCKER=1 ;;
    --browser) WITH_DOCKER=1; WITH_BROWSER=1 ;;
    --help|-h)
      sed -n '2,25p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
      exit 0 ;;
    *)
      printf 'unknown option: %s\n' "${arg}" >&2
      exit 2 ;;
  esac
done

# name=command, one per line. Order matters: the fast ones first, so a broken
# build is reported in seconds rather than after the Docker suites.
default_suites() {
  cat <<'SUITES'
engine=./scripts/test-engine.sh
orchestrator=./scripts/test-orchestrator.sh
testbed=./scripts/test-testbed.sh
secrets=./scripts/test-secrets.sh
loopback-api=python3 ./scripts/test-loopback-api.py
SUITES
  if [[ "${WITH_DOCKER}" == "1" ]]; then
    cat <<'SUITES'
isolation=./scripts/verify-testbed-isolation.sh
unverified-paths=./scripts/test-unverified-paths.sh
isolation-scenarios=./scripts/test-isolation-scenarios.sh
integration-testbed=./scripts/test-integration-testbed.sh
live-orchestrator=./scripts/test-integration-orchestrator.sh
live-faults=python3 ./scripts/test_live_faults.py
operations-quickstart=python3 ./scripts/test-operations-quickstart.py
orchestrator-scenarios=./scripts/test-orchestrator-scenarios.sh
stack=./scripts/test-stack.sh
SUITES
  fi
  if [[ "${WITH_BROWSER}" == "1" ]]; then
    echo "dashboard-browser=./scripts/test-dashboard-browser.sh"
  fi
}

SUITES="${MIHAKK_TEST_SUITES:-$(default_suites)}"

# One pair for the whole run, so that what the suites were given is known here and
# can be searched for afterwards. Suites that generate their own when unset now
# use these instead.
new_token() { head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n'; }
export MIHAKK_CONTROL_TOKEN="${MIHAKK_CONTROL_TOKEN:-$(new_token)}"
export MIHAKK_DASHBOARD_TOKEN="${MIHAKK_DASHBOARD_TOKEN:-$(new_token)}"

PASSED=0
FAILED=0
FAILED_NAMES=()

printf 'logs: %s\n\n' "${LOG_DIR}"

while IFS= read -r entry; do
  [[ -z "${entry}" ]] && continue
  name="${entry%%=*}"
  command="${entry#*=}"
  log="${LOG_DIR}/${name}.log"

  printf '== %s ==\n' "${name}"
  started="$(date +%s)"
  # Output goes to the file, whole. The terminal gets a one-line result; the file
  # is what a failure is read from.
  #
  # stdin comes from /dev/null because this loop reads the suite list from ITS
  # stdin: a suite that reads stdin swallows the remaining entries, and the run
  # ends early looking like a success. It did -- only the first Docker suite ran
  # and the runner reported four passes out of nine.
  ( cd "${REPO_ROOT}" && eval "${command}" ) </dev/null >"${log}" 2>&1
  rc=$?
  elapsed=$(( $(date +%s) - started ))

  printf '%s\n' "${rc}" >"${LOG_DIR}/${name}.exit"

  if [[ ${rc} -eq 0 ]]; then
    PASSED=$((PASSED + 1))
    printf '  \033[32mPASS\033[0m  %s (exit 0, %ds)\n\n' "${name}" "${elapsed}"
  else
    FAILED=$((FAILED + 1))
    FAILED_NAMES+=("${name}")
    printf '  \033[31mFAIL\033[0m  %s (exit %d, %ds)\n\n' "${name}" "${rc}" "${elapsed}"
  fi
done <<<"${SUITES}"

# --- did a token end up anywhere it should not be? ---------------------------
printf '== secret scan ==\n'
SCAN_OUT="$(python3 "${REPO_ROOT}/scripts/scan_secrets.py" scan "${LOG_DIR}"/*.log 2>&1)"
SCAN_RC=$?
TRACKED_OUT="$(python3 "${REPO_ROOT}/scripts/scan_secrets.py" scan-tracked "${REPO_ROOT}" 2>&1)"
TRACKED_RC=$?
printf '%s\n' "${SCAN_OUT}" "${TRACKED_OUT}" | sed 's/^/  /'
if [[ ${SCAN_RC} -eq 1 ]]; then
  python3 "${REPO_ROOT}/scripts/scan_secrets.py" redact "${LOG_DIR}"/*.log | sed 's/^/  /'
fi
if [[ ${SCAN_RC} -ne 0 || ${TRACKED_RC} -ne 0 ]]; then
  FAILED=$((FAILED + 1))
  FAILED_NAMES+=("secret-scan")
  printf '  \033[31mFAIL\033[0m  secret-scan (logs exit %d, tracked files exit %d)\n\n' \
    "${SCAN_RC}" "${TRACKED_RC}"
  # The pseudo-suite has no log of its own; the verdict above is its output.
  printf '%s\n%s\n' "${SCAN_OUT}" "${TRACKED_OUT}" >"${LOG_DIR}/secret-scan.log"
  printf '%s\n' 1 >"${LOG_DIR}/secret-scan.exit"
else
  printf '  \033[32mPASS\033[0m  secret-scan\n\n'
fi

echo "================================"
printf 'suites passed: %d   failed: %d\n' "${PASSED}" "${FAILED}"

if [[ ${FAILED} -gt 0 ]]; then
  for name in "${FAILED_NAMES[@]}"; do
    echo
    echo "================================================================"
    printf 'FULL OUTPUT: %s (exit %s)\n' "${name}" "$(cat "${LOG_DIR}/${name}.exit")"
    echo "================================================================"
    # In full. The tail is what lost the evidence the last two times.
    cat "${LOG_DIR}/${name}.log"
  done
  echo
  printf 'failing suite(s): %s\n' "${FAILED_NAMES[*]}"
  printf 'logs kept at: %s\n' "${LOG_DIR}"
  exit 1
fi

if [[ "${KEEP_LOGS}" != "1" && -z "${MIHAKK_TEST_LOGS:-}" ]]; then
  rm -rf "${LOG_DIR}"
else
  printf 'logs kept at: %s\n' "${LOG_DIR}"
fi
echo "every suite passed"
