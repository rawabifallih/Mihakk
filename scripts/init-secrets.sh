#!/usr/bin/env bash
# Create the operator's secrets file: the control token and the dashboard token.
#
#   scripts/init-secrets.sh [PATH]
#
# PATH defaults to $MIHAKK_SECRETS_FILE, then ${XDG_CONFIG_HOME:-~/.config}/mihakk/secrets.env.
#
# What it will not do:
#   - print either token. Test runs keep their output in full, so a token printed
#     here would sit in a log file. To see the dashboard token, run
#     scripts/show-dashboard-token.sh in a terminal.
#   - overwrite an existing file, or create one inside a git working tree.
#   - write anything that is later executed: scripts/stack.sh reads the file with
#     a strict parser (scripts/secrets_file.py), never with `source`.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DEFAULT="${XDG_CONFIG_HOME:-${HOME}/.config}/mihakk/secrets.env"
SECRETS="${1:-${MIHAKK_SECRETS_FILE:-${DEFAULT}}}"

python3 "${REPO_ROOT}/scripts/secrets_file.py" generate "${SECRETS}"

cat <<EOF

Next:
  scripts/stack.sh up                        start the stack
  scripts/show-dashboard-token.sh            show the login token (in a terminal only)

Keep ${SECRETS} out of every repository and backup you share.
EOF
if [[ "${SECRETS}" != "${DEFAULT}" ]]; then
  echo "It is not at the default path, so export MIHAKK_SECRETS_FILE=${SECRETS} for the scripts."
fi
