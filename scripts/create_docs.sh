#!/usr/bin/env bash
set -euo pipefail

SCHEME="${SCHEME:-AppIntegrityKit}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
BUILD_DIR="${ROOT}/build/docs"
DERIVED_DATA_PATH="${DERIVED_DATA_PATH:-${BUILD_DIR}/DerivedData}"
ARCHIVE_OUT_DIR="${BUILD_DIR}/archive"
STATIC_SITE_DIR="${BUILD_DIR}/site"
PROJECT_DIR="${BUILD_DIR}/project"

rm -rf "${BUILD_DIR}"
mkdir -p "${ARCHIVE_OUT_DIR}" "${STATIC_SITE_DIR}" "${PROJECT_DIR}"

xcodegen generate \
  --spec "${ROOT}/project.yml" \
  --project "${PROJECT_DIR}" \
  --project-root "${ROOT}" \
  --quiet

xcodebuild docbuild \
  -project "${PROJECT_DIR}/AppIntegrityKit.xcodeproj" \
  -scheme "${SCHEME}" \
  -destination "generic/platform=iOS" \
  -derivedDataPath "${DERIVED_DATA_PATH}" \
  -quiet \
  CODE_SIGNING_ALLOWED=NO

DOCC_ARCHIVE="$(find "${DERIVED_DATA_PATH}" -name "${SCHEME}.doccarchive" -type d | head -1)"
cp -R "${DOCC_ARCHIVE}" "${ARCHIVE_OUT_DIR}/${SCHEME}.doccarchive"

xcrun docc process-archive transform-for-static-hosting \
  "${ARCHIVE_OUT_DIR}/${SCHEME}.doccarchive" \
  --output-path "${STATIC_SITE_DIR}" \
  --hosting-base-path "${SCHEME}"
