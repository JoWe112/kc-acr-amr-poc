#!/usr/bin/env bash
#
# build-spi.sh — builds the X.509 Issuer LoA SPI JAR and runs its unit tests.
#
# Uses the official Maven image so no local JDK/Maven is required. The host's ~/.m2
# is mounted as cache. Output: spi/target/x509-issuer-loa-authenticator.jar
#
# Usage: scripts/build-spi.sh [extra maven args]   (default goal: verify)

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MAVEN_IMAGE="${MAVEN_IMAGE:-maven:3.9.9-eclipse-temurin-21}"
mkdir -p "${HOME}/.m2"

docker run --rm \
  -u "$(id -u):$(id -g)" \
  -v "${HOME}/.m2:/m2" \
  -v "${ROOT_DIR}/spi:/src" \
  -w /src \
  "${MAVEN_IMAGE}" \
  mvn -B -ntp -Dmaven.repo.local=/m2/repository -Duser.home=/tmp "${@:-verify}"

echo "Built: ${ROOT_DIR}/spi/target/x509-issuer-loa-authenticator.jar"
