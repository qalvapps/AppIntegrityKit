#!/usr/bin/env bash
set -euo pipefail

SCHEME="${SCHEME:-AppIntegrityKit}"
CONFIG="${CONFIG:-Release}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
BUILD_DIR="${ROOT}/build"
DERIVED_DATA_PATH="${DERIVED_DATA_PATH:-${BUILD_DIR}/DerivedData}"
OUT_DIR="${BUILD_DIR}/out"
PROJECT_DIR="${BUILD_DIR}/project"
IOS_ARCHIVE="${BUILD_DIR}/ios_devices.xcarchive"
SIM_ARCHIVE="${BUILD_DIR}/ios_simulator.xcarchive"

rm -rf "${BUILD_DIR}"
mkdir -p "${OUT_DIR}" "${PROJECT_DIR}"

xcodegen generate \
  --spec "${ROOT}/project.yml" \
  --project "${PROJECT_DIR}" \
  --project-root "${ROOT}" \
  --quiet

xcodebuild archive \
  -project "${PROJECT_DIR}/AppIntegrityKit.xcodeproj" \
  -scheme "${SCHEME}" \
  -configuration "${CONFIG}" \
  -sdk iphoneos \
  -destination "generic/platform=iOS" \
  -archivePath "${IOS_ARCHIVE}" \
  -derivedDataPath "${DERIVED_DATA_PATH}" \
  -quiet \
  SKIP_INSTALL=NO BUILD_LIBRARY_FOR_DISTRIBUTION=YES CODE_SIGNING_ALLOWED=NO

xcodebuild archive \
  -project "${PROJECT_DIR}/AppIntegrityKit.xcodeproj" \
  -scheme "${SCHEME}" \
  -configuration "${CONFIG}" \
  -sdk iphonesimulator \
  -destination "generic/platform=iOS Simulator" \
  -archivePath "${SIM_ARCHIVE}" \
  -derivedDataPath "${DERIVED_DATA_PATH}" \
  -quiet \
  SKIP_INSTALL=NO BUILD_LIBRARY_FOR_DISTRIBUTION=YES CODE_SIGNING_ALLOWED=NO

xcodebuild -create-xcframework \
  -framework "${IOS_ARCHIVE}/Products/Library/Frameworks/${SCHEME}.framework" \
  -framework "${SIM_ARCHIVE}/Products/Library/Frameworks/${SCHEME}.framework" \
  -output "${OUT_DIR}/${SCHEME}.xcframework"
