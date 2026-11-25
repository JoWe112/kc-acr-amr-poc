#!/usr/bin/env bash
#
# run-e2e.sh — runs all end-to-end tests against the running docker-compose stack.
#
#   scripts/e2e_test.py          password, X.509 (both CAs + unmapped), SSO, step-up, essential acr
#   scripts/e2e_passkey_test.py  passkey register/login/step-up with a software authenticator
#
# Runs inside a throw-away Python container (host network) so the `cryptography`
# package needed by the passkey test does not have to be installed on the host.

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PYTHON_IMAGE="${PYTHON_IMAGE:-python:3.13-alpine}"

docker run --rm --network host \
  -e KC_ADMIN_USER -e KC_ADMIN_PASSWORD \
  -v "${ROOT_DIR}/scripts:/work/scripts:ro" \
  -v "${ROOT_DIR}/certs:/work/certs:ro" \
  -w /work \
  "${PYTHON_IMAGE}" \
  sh -c 'pip install -q --disable-pip-version-check --root-user-action=ignore "cryptography>=44,<47" \
         && python3 -I scripts/e2e_test.py && echo && python3 -I scripts/e2e_passkey_test.py'
