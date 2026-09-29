#!/usr/bin/env bash
# The secrets path end to end, without Docker: the scripts an operator runs.
#
#   - init-secrets.sh creates a private file, prints neither token, never
#     overwrites, and refuses a path inside a git working tree;
#   - show-dashboard-token.sh gives nothing to a redirected stdout;
#   - stack.sh reads the file with the strict parser and never executes it: a
#     file carrying shell metacharacters is refused before docker is ever run,
#     nothing in it runs, and no token appears in what it prints;
#   - stack.sh refuses a target network it cannot verify as internal, before
#     anything starts;
#   - git tracks nothing shaped like a secrets file, and the guard that says so
#     does fail when one is tracked.
#
# docker is replaced on PATH by a stub that records every call. The stack is never
# started here -- that is test-stack.sh -- so every refusal is also checked to
# have happened before `compose up`, not after it.
#
# Runs on the host because the scripts under test are bash and run on the host;
# the parser's unit tests run here too, under the host's own python3, which is the
# interpreter stack.sh will use.
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORK="$(mktemp -d /tmp/mihakk-secrets.XXXXXX)"
REAL_DOCKER="$(command -v docker || true)"

PASS=0
FAIL=0
ok()   { printf '  \033[32mPASS\033[0m  %s\n' "$1"; PASS=$((PASS + 1)); }
bad()  { printf '  \033[31mFAIL\033[0m  %s\n' "$1"; FAIL=$((FAIL + 1)); }
note() { printf '        %s\n' "$1"; }

cleanup() { rm -rf "${WORK}"; }
trap cleanup EXIT INT TERM

# --- the parser and the network reader, under the host's python ------------
echo "== unit tests under the host's python3 ($(python3 -c 'import sys; print(sys.version.split()[0])')) =="
if (cd "${REPO_ROOT}/scripts" && python3 -m unittest test_secrets_file test_check_networks \
      >"${WORK}/unit.log" 2>&1); then
  ok "secrets_file and check_networks: $(grep -Eo 'Ran [0-9]+ tests' "${WORK}/unit.log")"
else
  bad "the unit tests failed under the host's python3"
  sed 's/^/        /' "${WORK}/unit.log"
fi

# The stub records each call, and answers only what a test set up for it.
mkdir -p "${WORK}/bin"
cat >"${WORK}/bin/docker" <<'STUB'
#!/usr/bin/env bash
printf '%s\n' "$*" >>"${STUB_LOG}"
case "$*" in
  "network inspect "*)
    [[ -n "${STUB_INSPECT_RC:-}" ]] || exit 1
    printf '%s' "${STUB_INSPECT_OUT:-}"
    exit "${STUB_INSPECT_RC}" ;;
  compose*"config --no-interpolate"*)
    exec "${REAL_DOCKER}" "$@" ;;
esac
exit 0
STUB
chmod +x "${WORK}/bin/docker"
export STUB_LOG="${WORK}/docker-calls.log" REAL_DOCKER

stub_called_up() { grep -q " up " "${STUB_LOG}" 2>/dev/null; }

# --- init-secrets.sh --------------------------------------------------------
echo
echo "== init-secrets.sh =="
SECRETS="${WORK}/config/mihakk/secrets.env"
INIT_OUT="$("${REPO_ROOT}/scripts/init-secrets.sh" "${SECRETS}" 2>&1)"
INIT_RC=$?
if [[ ${INIT_RC} -eq 0 && -f "${SECRETS}" ]]; then
  ok "it creates the file"
else
  bad "it did not create the file (exit ${INIT_RC})"
  note "${INIT_OUT}"
fi

MODE="$(python3 -c 'import os,stat,sys; print(oct(stat.S_IMODE(os.stat(sys.argv[1]).st_mode)))' "${SECRETS}" 2>/dev/null)"
[[ "${MODE}" == "0o600" ]] && ok "the file is 0600" || bad "the file is ${MODE:-missing}, not 0600"

# Compared inside python, so neither value passes through this shell's output.
LEAKED="$(printf '%s' "${INIT_OUT}" | python3 -c '
import sys
sys.path.insert(0, sys.argv[2])
import secrets_file
tokens = secrets_file.read(sys.argv[1])
out = sys.stdin.read()
print(sum(value in out for value in tokens.values()))
' "${SECRETS}" "${REPO_ROOT}/scripts")"
[[ "${LEAKED}" == "0" ]] && ok "it prints neither token" || bad "it printed ${LEAKED:-?} token(s)"

BEFORE="$(shasum -a 256 "${SECRETS}")"
if "${REPO_ROOT}/scripts/init-secrets.sh" "${SECRETS}" >/dev/null 2>&1; then
  bad "a second run over an existing file succeeded"
else
  [[ "$(shasum -a 256 "${SECRETS}")" == "${BEFORE}" ]] \
    && ok "a second run refuses and leaves the existing file unchanged" \
    || bad "a second run changed the existing file"
fi

INSIDE="${REPO_ROOT}/mihakk-test-secrets-$$.env"
if "${REPO_ROOT}/scripts/init-secrets.sh" "${INSIDE}" >/dev/null 2>&1 || [[ -e "${INSIDE}" ]]; then
  bad "a path inside the repository was accepted"
  rm -f "${INSIDE}"
else
  ok "a path inside the repository is refused and nothing is created"
fi

# --- show-dashboard-token.sh ------------------------------------------------
echo
echo "== show-dashboard-token.sh =="
SHOW_OUT="$(MIHAKK_SECRETS_FILE="${SECRETS}" "${REPO_ROOT}/scripts/show-dashboard-token.sh" 2>&1)"
SHOW_RC=$?
SHOWN="$(printf '%s' "${SHOW_OUT}" | python3 -c '
import sys
sys.path.insert(0, sys.argv[2])
import secrets_file
print(sum(v in sys.stdin.read() for v in secrets_file.read(sys.argv[1]).values()))
' "${SECRETS}" "${REPO_ROOT}/scripts")"
if [[ ${SHOW_RC} -ne 0 && "${SHOWN}" == "0" ]]; then
  ok "with stdout captured it refuses and prints no token"
else
  bad "with stdout captured it exited ${SHOW_RC} and printed ${SHOWN:-?} token(s)"
fi

# --- stack.sh never executes the file ---------------------------------------
echo
echo "== stack.sh reads the secrets file, never runs it =="
MARKER="${WORK}/pwned"
GOODDASH="$(python3 -c 'import secrets; print(secrets.token_hex(32))')"
n=0
while IFS= read -r hostile; do
  n=$((n + 1))
  f="${WORK}/hostile-${n}.env"
  printf '%s\nMIHAKK_DASHBOARD_TOKEN=%s\n' "${hostile}" "${GOODDASH}" >"${f}"
  chmod 600 "${f}"
  : >"${STUB_LOG}"
  out="$(PATH="${WORK}/bin:${PATH}" MIHAKK_SECRETS_FILE="${f}" \
         "${REPO_ROOT}/scripts/stack.sh" up 2>&1)"
  rc=$?
  if [[ ${rc} -eq 0 ]]; then
    bad "hostile file ${n} was accepted"
  elif [[ -e "${MARKER}" ]]; then
    bad "hostile file ${n}: something in it RAN"
    rm -f "${MARKER}"
  elif stub_called_up; then
    bad "hostile file ${n}: docker compose up was reached"
  elif grep -qF "${GOODDASH}" <<<"${out}"; then
    bad "hostile file ${n}: the refusal printed the other token"
  else
    ok "refused, nothing ran, no token printed: $(printf '%s' "${hostile}" | cut -c1-48)"
  fi
done <<HOSTILE
MIHAKK_CONTROL_TOKEN=\$(touch ${MARKER})
MIHAKK_CONTROL_TOKEN=\`touch ${MARKER}\`
MIHAKK_CONTROL_TOKEN=$(printf 'a%.0s' $(seq 1 64)); touch ${MARKER}
export MIHAKK_CONTROL_TOKEN=$(printf 'a%.0s' $(seq 1 64))
MIHAKK_CONTROL_TOKEN="\$(touch ${MARKER})"
touch ${MARKER}
PATH=${WORK}/bin
HOSTILE

# Group-readable, and a symlink: refused as files, whatever they contain.
cp "${SECRETS}" "${WORK}/loose.env"; chmod 640 "${WORK}/loose.env"
ln -s "${SECRETS}" "${WORK}/link.env"
for f in loose link; do
  : >"${STUB_LOG}"
  if PATH="${WORK}/bin:${PATH}" MIHAKK_SECRETS_FILE="${WORK}/${f}.env" \
       "${REPO_ROOT}/scripts/stack.sh" up >/dev/null 2>&1 || stub_called_up; then
    bad "a ${f} secrets file was used"
  else
    ok "a ${f} secrets file is refused before compose runs"
  fi
done

# The port is interpolated into the host allowlist, so it is checked as a number.
: >"${STUB_LOG}"
if PATH="${WORK}/bin:${PATH}" MIHAKK_SECRETS_FILE="${SECRETS}" MIHAKK_PORT='8100,evil.example:80' \
     "${REPO_ROOT}/scripts/stack.sh" up >/dev/null 2>&1 || stub_called_up; then
  bad "a MIHAKK_PORT carrying a second host was accepted"
else
  ok "MIHAKK_PORT must be a plain port number"
fi

# --- stack.sh refuses a target network it cannot vouch for ------------------
echo
echo "== stack.sh --target-network: refused unless Docker says internal =="
net_json() {  # name internal driver
  printf '[{"Name":"%s","Id":"%064d","Internal":%s,"Driver":"%s","Scope":"local"}]' "$1" 0 "$2" "$3"
}
refuse_case() {  # label network inspect-rc inspect-out
  : >"${STUB_LOG}"
  local out rc
  out="$(PATH="${WORK}/bin:${PATH}" MIHAKK_SECRETS_FILE="${SECRETS}" \
         STUB_INSPECT_RC="$3" STUB_INSPECT_OUT="$4" \
         "${REPO_ROOT}/scripts/stack.sh" up --target-network "$2" 2>&1)"
  rc=$?
  if [[ ${rc} -ne 0 ]] && ! stub_called_up; then
    ok "$1"
  else
    bad "$1 (exit ${rc}, compose up reached: $(stub_called_up && echo yes || echo no))"
    note "$(printf '%s' "${out}" | tail -3)"
  fi
}
refuse_case "a network that does not exist is refused, and not created" \
  owner-missing 1 ""
refuse_case "a network that cannot be inspected is refused as unverified" \
  owner-shared 0 "not json"
refuse_case "a network that is not internal is refused, not warned about" \
  owner-shared 0 "$(net_json owner-shared false bridge)"
refuse_case "a non-bridge network is refused even if internal" \
  owner-shared 0 "$(net_json owner-shared true macvlan)"
for reserved in bridge host none mihakk-internal mihakk-public; do
  refuse_case "the reserved name '${reserved}' is refused" "${reserved}" 0 \
    "$(net_json "${reserved}" true bridge)"
done
refuse_case "a name docker would not create is refused" '$(touch '"${MARKER}"')' 0 "[]"
[[ -e "${MARKER}" ]] && bad "a network name was executed" || ok "no network name was executed"

if grep -Eq "network (create|rm|connect|disconnect)" "${STUB_LOG}" 2>/dev/null; then
  bad "stack.sh tried to create, remove or reconnect a network"
else
  ok "stack.sh never created, removed or reconnected a network in any of these"
fi

# --- nothing secrets-shaped is tracked --------------------------------------
echo
echo "== git tracks no secrets file =="
if python3 "${REPO_ROOT}/scripts/check_no_tracked_secrets.py" "${REPO_ROOT}" >"${WORK}/tracked.log" 2>&1; then
  ok "$(cat "${WORK}/tracked.log")"
else
  bad "$(cat "${WORK}/tracked.log")"
fi

# And the guard fails when it should: a throwaway clone with a .env forced in.
if git clone -q "${REPO_ROOT}" "${WORK}/clone" 2>/dev/null; then
  printf 'MIHAKK_CONTROL_TOKEN=x\n' >"${WORK}/clone/deploy/.env"
  git -C "${WORK}/clone" add -f deploy/.env
  if python3 "${REPO_ROOT}/scripts/check_no_tracked_secrets.py" "${WORK}/clone" >"${WORK}/clone.log" 2>&1; then
    bad "a force-added .env went unnoticed"
  elif grep -q "deploy/.env" "${WORK}/clone.log"; then
    ok "a force-added deploy/.env is caught and named"
  else
    bad "the guard failed for another reason: $(cat "${WORK}/clone.log")"
  fi
else
  bad "could not clone the repository to test the guard"
fi

echo
echo "================================"
printf 'passed: %d   failed: %d\n' "${PASS}" "${FAIL}"
[[ ${FAIL} -eq 0 ]] || exit 1
echo "the secrets path is data, never code"
