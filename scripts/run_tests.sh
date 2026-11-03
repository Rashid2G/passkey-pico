#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BUILD_DIR="${REPO_ROOT}/build/host_tests"

echo "=== [pico-passkey] Running Native Host Unit & Integration Tests ==="

# 1. Configure CMake for host tests
echo ">> Configuring CMake in ${BUILD_DIR}..."
cmake -B "${BUILD_DIR}" \
      -G Ninja \
      -DPICO_PASSKEY_HOST_TESTS=ON \
      -DCMAKE_BUILD_TYPE=Debug \
      "${REPO_ROOT}"

# 2. Build all test targets
echo ">> Building all host test targets..."
cmake --build "${BUILD_DIR}"

# 3. Run ctest with full verbose output and failure logging
echo ">> Executing ctest suite..."
ctest --test-dir "${BUILD_DIR}" --output-on-failure -V "$@"

echo "=== All tests completed successfully! ==="
