#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CRATE_DIR="${ROOT_DIR}/rust/cache-core"

if ! command -v cargo >/dev/null 2>&1; then
  echo "cargo not found in PATH"
  exit 1
fi

BUILD_MODE="${BUILD_MODE:-release}"

if [[ "${BUILD_MODE}" == "release" ]]; then
  cargo build --manifest-path "${CRATE_DIR}/Cargo.toml" --release
else
  cargo build --manifest-path "${CRATE_DIR}/Cargo.toml"
fi

echo "built rust cache core (${BUILD_MODE}) at ${CRATE_DIR}/target"
