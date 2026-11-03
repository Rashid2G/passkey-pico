#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SDK_ROOT="${REPO_ROOT}/.sdk"
PICO_SDK_DIR="${SDK_ROOT}/pico-sdk"
TOOLCHAIN_DIR="${SDK_ROOT}/arm-gnu-toolchain"
PICO_SDK_TAG="${PICO_SDK_TAG:-2.1.1}"
ARM_GCC_VER="13.3.rel1"

mkdir -p "${SDK_ROOT}"

echo "[1/2] Checking Raspberry Pi Pico SDK (${PICO_SDK_TAG})..."
if [[ ! -f "${PICO_SDK_DIR}/pico_sdk_init.cmake" ]]; then
    echo "  Cloning pico-sdk ${PICO_SDK_TAG}..."
    rm -rf "${PICO_SDK_DIR}"
    git clone --depth 1 --branch "${PICO_SDK_TAG}" \
        https://github.com/raspberrypi/pico-sdk.git "${PICO_SDK_DIR}"
    echo "  Initializing required submodules (tinyusb, mbedtls)..."
    git -C "${PICO_SDK_DIR}" submodule update --init --depth 1 \
        lib/tinyusb lib/mbedtls
else
    echo "  Found pico-sdk at ${PICO_SDK_DIR}"
fi

echo "[2/2] Checking ARM GNU Toolchain (arm-none-eabi-gcc)..."
if command -v arm-none-eabi-gcc >/dev/null 2>&1; then
    echo "  Using system arm-none-eabi-gcc: $(command -v arm-none-eabi-gcc)"
elif [[ -x "${TOOLCHAIN_DIR}/bin/arm-none-eabi-gcc" ]]; then
    echo "  Found local toolchain at ${TOOLCHAIN_DIR}/bin/arm-none-eabi-gcc"
else
    ARCH="$(uname -m)"
    if [[ "${ARCH}" != "x86_64" && "${ARCH}" != "aarch64" ]]; then
        echo "Unsupported host architecture for automatic toolchain download: ${ARCH}" >&2
        exit 1
    fi
    ARCHIVE_NAME="arm-gnu-toolchain-${ARM_GCC_VER}-${ARCH}-arm-none-eabi.tar.xz"
    DOWNLOAD_URL="https://developer.arm.com/-/media/Files/downloads/gnu/${ARM_GCC_VER}/binrel/${ARCHIVE_NAME}"
    echo "  Downloading ${ARCHIVE_NAME}..."
    curl -fL --retry 3 -o "${SDK_ROOT}/${ARCHIVE_NAME}" "${DOWNLOAD_URL}"
    echo "  Extracting toolchain..."
    mkdir -p "${TOOLCHAIN_DIR}"
    tar -xJf "${SDK_ROOT}/${ARCHIVE_NAME}" -C "${TOOLCHAIN_DIR}" --strip-components=1
    rm -f "${SDK_ROOT}/${ARCHIVE_NAME}"
    echo "  Installed ${TOOLCHAIN_DIR}/bin/arm-none-eabi-gcc"
fi

echo "SDK bootstrap complete."
