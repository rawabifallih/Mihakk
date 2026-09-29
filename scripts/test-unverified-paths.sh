#!/usr/bin/env bash
# Negative tests for the paths where verify-testbed-isolation.sh cannot gather
# its evidence.
#
# The rule under test: if a check's input cannot be read -- the command failed,
# the output is malformed, it is a bare null, or its shape is not what was
# expected -- the run must report UNVERIFIED and exit non-zero. It must never
# report PASS, and it must never print "testbed isolation verified".
#
# Corrupting the input is done with a stub `docker` placed ahead of the real
# one on PATH. It intercepts only the calls whose output feeds a verdict and
# forwards everything else, so the rest of the run is genuine.
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VERIFY="${REPO_ROOT}/scripts/verify-testbed-isolation.sh"
REAL_DOCKER="$(command -v docker)"
WORK="$(mktemp -d)"

PASS=0
FAIL=0

ok()   { printf '  \033[32mPASS\033[0m  %s\n' "$1"; PASS=$((PASS + 1)); }
bad()  { printf '  \033[31mFAIL\033[0m  %s\n' "$1"; FAIL=$((FAIL + 1)); }
note() { printf '        %s\n' "$1"; }

cleanup() {
  "${REAL_DOCKER}" compose -f "${REPO_ROOT}/deploy/docker-compose.yml" down >/dev/null 2>&1 || true
  rm -rf "${WORK}"
}
trap cleanup EXIT

if [[ -z "${REAL_DOCKER}" ]]; then
  echo "docker not found" >&2
  exit 1
fi

mkdir -p "${WORK}/bin"
cat >"${WORK}/bin/docker" <<'STUB'
#!/usr/bin/env bash
# Stub docker: corrupts one specific call, forwards everything else.
case "${MIHAKK_STUB_TARGET}" in
  ports)
    if [[ "$1" == "inspect" ]]; then
      for arg in "$@"; do
        case "${arg}" in
          *NetworkSettings.Ports*|*HostConfig.PortBindings*)
            case "${MIHAKK_STUB_MODE}" in
              fail)       exit 1 ;;
              empty)      exit 0 ;;
              malformed)  printf '{not json\n'; exit 0 ;;
              null)       printf 'null\n'; exit 0 ;;
              wrongshape) printf '["unexpected","list"]\n'; exit 0 ;;
              badbinding) printf '{"8000/tcp": "0.0.0.0:8000"}\n'; exit 0 ;;
            esac
            ;;
        esac
      done
    fi
    ;;
  health)
    # The container never reports healthy, as under a loaded daemon.
    if [[ "$1" == "inspect" ]]; then
      for arg in "$@"; do
        case "${arg}" in
          *State.Health.Status*)
            case "${MIHAKK_STUB_MODE}" in
              starting) printf 'starting\n'; exit 0 ;;
              unhealthy) printf 'unhealthy\n'; exit 0 ;;
              fail)      exit 1 ;;
            esac
            ;;
        esac
      done
    fi
    ;;
  config)
    if [[ "$1" == "compose" ]]; then
      for arg in "$@"; do
        if [[ "${arg}" == "config" ]]; then
          case "${MIHAKK_STUB_MODE}" in
            fail)      exit 1 ;;
            malformed) printf '{not json\n'; exit 0 ;;
            null)      printf 'null\n'; exit 0 ;;
            noservices) printf '{"networks":{}}\n'; exit 0 ;;
          esac
        fi
      done
    fi
    ;;
  probe)
    if [[ "$1" == "compose" ]]; then
      for arg in "$@"; do
        if [[ "${arg}" == "run" ]]; then
          case "${MIHAKK_STUB_MODE}" in
            fail)      exit 1 ;;
            malformed) printf 'not json at all\n'; exit 0 ;;
            nochecks)  printf '{"all_passed": true}\n'; exit 0 ;;
            badstatus) printf '{"checks":{"x":{"status":"maybe","detail":"?"}}}\n'; exit 0 ;;
            onecheck)
              # One passing check and nothing else: the default-route and
              # egress checks simply did not happen.
              printf '{"checks":{"no_default_route":{"status":"pass","detail":"only check present"}}}\n'
              exit 0 ;;
            twochecks)
              printf '{"checks":{"no_default_route":{"status":"pass","detail":"d"},"external_connect_refused":{"status":"pass","detail":"d"}}}\n'
              exit 0 ;;
            allpass_badrc)
              # A complete, entirely passing report -- with an exit code that
              # says otherwise.
              printf '{"checks":{"no_default_route":{"status":"pass","detail":"d"},"external_connect_refused":{"status":"pass","detail":"d"},"testbed_reachable_by_service_name":{"status":"pass","detail":"d"}}}\n'
              exit 3 ;;
          esac
        fi
      done
    fi
    ;;
esac
exec "${MIHAKK_REAL_DOCKER}" "$@"
STUB
chmod +x "${WORK}/bin/docker"

# One scenario: run the verifier with a corrupted input and assert the verdict.
expect_unverified() {
  local target="$1" mode="$2" label="$3"
  local out rc

  out="$(MIHAKK_STUB_TARGET="${target}" \
         MIHAKK_STUB_MODE="${mode}" \
         MIHAKK_REAL_DOCKER="${REAL_DOCKER}" \
         PATH="${WORK}/bin:${PATH}" \
         "${VERIFY}" 2>&1)"
  rc=$?

  local problems=()
  [[ ${rc} -eq 0 ]] && problems+=("exited 0")
  grep -q "UNVERIFIED" <<<"${out}" || problems+=("never printed UNVERIFIED")
  grep -q "testbed isolation verified" <<<"${out}" && problems+=("claimed isolation was verified")

  if [[ ${#problems[@]} -eq 0 ]]; then
    ok "${label}: exits ${rc}, reports UNVERIFIED"
  else
    bad "${label}: $(IFS='; '; echo "${problems[*]}")"
    sed -n '1,25p' <<<"${out}"
  fi
}

echo "== compose config cannot be read =="
for mode in fail malformed null noservices; do
  expect_unverified config "${mode}" "compose config ${mode}"
done

echo
echo "== port bindings cannot be read =="
note "starting the testbed once so these runs reuse it"
"${REAL_DOCKER}" compose -f "${REPO_ROOT}/deploy/docker-compose.yml" up -d --build testbed >/dev/null 2>&1
for mode in fail empty malformed null wrongshape badbinding; do
  expect_unverified ports "${mode}" "docker inspect ports ${mode}"
done

echo
echo "== the in-container probe cannot be read =="
for mode in fail malformed nochecks badstatus; do
  expect_unverified probe "${mode}" "probe ${mode}"
done

echo
echo "== the probe report is incomplete, or disagrees with its exit code =="
expect_unverified probe onecheck      "probe reports only one passing check"
expect_unverified probe twochecks     "probe omits one required check"
expect_unverified probe allpass_badrc "probe reports all checks passing but exits 3"

echo
echo "== the testbed never becomes ready =="
note "a bounded wait whose expiry used to be swallowed: the checks then ran against"
note "a container that was not ready, so a probe could fail for want of a started"
note "app and be reported as an isolation failure"
for mode in starting unhealthy fail; do
  expect_unverified health "${mode}" "health never healthy (${mode})"
done

echo
echo "== control: with nothing corrupted, the check still passes =="
CONTROL_OUT="$("${VERIFY}" 2>&1)"
CONTROL_RC=$?
if [[ ${CONTROL_RC} -eq 0 ]] && grep -q "testbed isolation verified" <<<"${CONTROL_OUT}"; then
  ok "an uncorrupted run still verifies (so the stubs, not the script, caused the failures above)"
else
  bad "the uncorrupted run did not verify (exit ${CONTROL_RC})"
  sed -n '1,25p' <<<"${CONTROL_OUT}"
fi

echo
echo "================================"
printf 'passed: %d   failed: %d\n' "${PASS}" "${FAIL}"
[[ ${FAIL} -gt 0 ]] && exit 1
echo "every unreadable input is reported as unverified, never as a pass"
