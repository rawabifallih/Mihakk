#!/usr/bin/env bash
# Show the dashboard login token -- to a terminal, and only to a terminal.
#
# With stdout redirected (a log file, a pipe, a test runner that keeps output),
# this refuses and prints nothing: the point of keeping the token out of every
# script's output would be lost the first time a run was logged. It is a guard
# against capturing the token by accident, not against someone set on it.
#
# The file is read by scripts/secrets_file.py, never sourced.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SECRETS="${MIHAKK_SECRETS_FILE:-${XDG_CONFIG_HOME:-${HOME}/.config}/mihakk/secrets.env}"

exec python3 "${REPO_ROOT}/scripts/secrets_file.py" show-dashboard "${SECRETS}"
