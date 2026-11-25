#!/usr/bin/env bash
#
# validate-bruno.sh — runs the Bruno collection with the official Bruno CLI against the
# running stack, so the .bru files, scripts and tests are validated by Bruno itself.
#
# Login requests 02-04 only build the authorize URL (a real login needs a browser), so
# for 05-07 an authorization code is obtained by scripts/e2e_test.py --issue-code and
# injected as `authCode`/`codeVerifier`. Each login method is exercised once.
#
# BRU_SANDBOX=safe (default, same as the Bruno desktop app's Safe Mode) or developer.

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BRU_CLI_VERSION="${BRU_CLI_VERSION:-4.3.0}"
NODE_IMAGE="${NODE_IMAGE:-node:22-alpine}"
API_SECRET="${POC_API_SECRET:-poc-api-secret-change-me}"
BRU_SANDBOX="${BRU_SANDBOX:-safe}"

bru() {
  docker run --rm --network host -v "${ROOT_DIR}:/work" -w /work/bruno -e npm_config_loglevel=error "${NODE_IMAGE}" \
    sh -c "npm i -g -s @usebruno/cli@${BRU_CLI_VERSION} >/dev/null && bru run $* --env local --cacert ../certs/ca-standard.crt --env-var apiClientSecret=${API_SECRET} --sandbox=${BRU_SANDBOX} --bail"
}

echo "### Discovery + login URL builders (01-04)"
bru '"01 Discovery.bru" "02 Login - Standard.bru" "03 Login - Step-up LoA 2.bru" "04 Login - Step-up LoA 3.bru"'

for method in password testuser-standard testuser-high; do
  acr=""
  [[ "${method}" == "testuser-high" ]] && acr="--acr-values loa3"
  echo "### Token exchange / UserInfo / Introspection after login with: ${method} ${acr}"
  # shellcheck disable=SC2086
  json="$(python3 "${ROOT_DIR}/scripts/e2e_test.py" --issue-code "${method}" ${acr})"
  code="$(python3 -c 'import json,sys; print(json.load(sys.stdin)["code"])' <<<"${json}")"
  verifier="$(python3 -c 'import json,sys; print(json.load(sys.stdin)["verifier"])' <<<"${json}")"
  bru "\"05 Token Exchange.bru\" \"06 UserInfo.bru\" \"07 Token Introspection.bru\" --env-var authCode=${code} --env-var codeVerifier=${verifier}"
done
echo "Bruno collection validated (sandbox: ${BRU_SANDBOX})."
