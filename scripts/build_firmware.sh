#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SDK_DIR="${REPO_ROOT}/.sdk/pico-sdk"
TOOLCHAIN_BIN="${REPO_ROOT}/.sdk/arm-gnu-toolchain/bin"
BUILD_DIR="${REPO_ROOT}/build/firmware"
UF2_TARGET="${BUILD_DIR}/pico_passkey.uf2"
ELF_TARGET="${BUILD_DIR}/pico_passkey.elf"

echo "=== [pico-passkey] Firmware Build ==="

# 1. Bootstrap SDK and toolchain if missing
if [[ ! -d "${SDK_DIR}" || ! -f "${SDK_DIR}/pico_sdk_init.cmake" ]]; then
    echo ">> Pico SDK not found at ${SDK_DIR}. Running bootstrap_sdk.sh..."
    "${REPO_ROOT}/scripts/bootstrap_sdk.sh"
fi

# Ensure local toolchain is on PATH if system toolchain is not found
if ! command -v arm-none-eabi-gcc >/dev/null 2>&1; then
    if [[ -d "${TOOLCHAIN_BIN}" ]]; then
        echo ">> Adding local toolchain to PATH: ${TOOLCHAIN_BIN}"
        export PATH="${TOOLCHAIN_BIN}:${PATH}"
    else
        echo "Error: arm-none-eabi-gcc not found on system and local toolchain missing." >&2
        echo "Please run ./scripts/bootstrap_sdk.sh to install the toolchain." >&2
        exit 1
    fi
fi

if [[ -z "${PICO_SDK_PATH:-}" ]]; then
    export PICO_SDK_PATH="${SDK_DIR}"
fi

# 2. Configure CMake in build/firmware
echo ">> Configuring CMake in ${BUILD_DIR}..."
cmake -B "${BUILD_DIR}" \
      -G Ninja \
      -DPICO_PASSKEY_HOST_TESTS=OFF \
      -DCMAKE_BUILD_TYPE=Release \
      "${REPO_ROOT}"

# 3. Build firmware target
echo ">> Building pico_passkey firmware..."
cmake --build "${BUILD_DIR}" --target pico_passkey

# 4. Check outputs & report binary size
if [[ ! -f "${UF2_TARGET}" ]]; then
    echo "Error: Expected UF2 file not found at ${UF2_TARGET}" >&2
    exit 1
fi

SIZE_TOOL="$(command -v arm-none-eabi-size || true)"
if [[ -z "${SIZE_TOOL}" && -x "${TOOLCHAIN_BIN}/arm-none-eabi-size" ]]; then
    SIZE_TOOL="${TOOLCHAIN_BIN}/arm-none-eabi-size"
fi

echo ""
echo "=== Firmware Build Summary ==="
if [[ -n "${SIZE_TOOL}" && -f "${ELF_TARGET}" ]]; then
    echo ">> Firmware Binary Section Sizes (arm-none-eabi-size):"
    "${SIZE_TOOL}" -B "${ELF_TARGET}"
    echo ""
fi

echo "UF2 Firmware image ready: ${UF2_TARGET}"
echo "File size: $(stat -c %s "${UF2_TARGET}" 2>/dev/null || wc -c < "${UF2_TARGET}") bytes"
echo "To flash your Pico, run: ./scripts/flash_pico.sh"
