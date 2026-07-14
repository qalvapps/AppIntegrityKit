#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
TMP_ROOT="${TMPDIR:-/tmp}/AppIntegrityKitVerify"
PYTHON_VENV="${TMP_ROOT}/python"
PROJECT_DIR="${TMP_ROOT}/project"
DERIVED_DATA="${TMP_ROOT}/DerivedData"

cleanup() {
  rm -rf "${TMP_ROOT}"
}
trap cleanup EXIT

rm -rf "${TMP_ROOT}"
mkdir -p "${PROJECT_DIR}"

swift test \
  --package-path "${ROOT}" \
  --scratch-path "${TMP_ROOT}/swift"

python3 -m venv "${PYTHON_VENV}"
"${PYTHON_VENV}/bin/pip" install --quiet -e "${ROOT}/Server/Python[dev]"
PYTHONDONTWRITEBYTECODE=1 \
  "${PYTHON_VENV}/bin/pytest" \
  -p no:cacheprovider \
  "${ROOT}/Server/Python/tests"

xcodegen generate \
  --spec "${ROOT}/project.yml" \
  --project "${PROJECT_DIR}" \
  --project-root "${ROOT}" \
  --quiet

xcodebuild \
  -project "${PROJECT_DIR}/AppIntegrityKit.xcodeproj" \
  -scheme AppIntegrityKit \
  -destination "generic/platform=iOS" \
  -derivedDataPath "${DERIVED_DATA}" \
  -quiet \
  CODE_SIGNING_ALLOWED=NO \
  build
