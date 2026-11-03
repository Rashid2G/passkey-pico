#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BUILD_DIR="${REPO_ROOT}/build/firmware"
UF2_FILE="${BUILD_DIR}/pico_passkey.uf2"

echo "=== [pico-passkey] Flashing RP2040 Firmware ==="

# 1. Ensure firmware binary is built
if [[ ! -f "${UF2_FILE}" ]]; then
    echo ">> UF2 image not found at ${UF2_FILE}. Triggering build..."
    "${REPO_ROOT}/scripts/build_firmware.sh"
fi

if [[ ! -f "${UF2_FILE}" ]]; then
    echo "Error: Failed to find or build ${UF2_FILE}" >&2
    exit 1
fi

# 2. Detect mounted RP2040 BOOTSEL volume
CURRENT_USER="${USER:-$(id -un)}"
MOUNT_CANDIDATES=(
    "/run/media/${CURRENT_USER}/RPI-RP2"
    "/media/${CURRENT_USER}/RPI-RP2"
    "/run/media/RPI-RP2"
    "/media/RPI-RP2"
    "/Volumes/RPI-RP2"
)

DETECTED_MOUNT=""
for candidate in "${MOUNT_CANDIDATES[@]}"; do
    if [[ -d "${candidate}" && -w "${candidate}" ]]; then
        DETECTED_MOUNT="${candidate}"
        break
    fi
done

# If not found in standard paths, inspect lsblk
if [[ -z "${DETECTED_MOUNT}" ]] && command -v lsblk >/dev/null 2>&1; then
    LSBLK_MOUNT="$(lsblk -o LABEL,MOUNTPOINT 2>/dev/null | awk '$1 == "RPI-RP2" && $2 != "" {print $2; exit}')"
    if [[ -n "${LSBLK_MOUNT}" && -d "${LSBLK_MOUNT}" && -w "${LSBLK_MOUNT}" ]]; then
        DETECTED_MOUNT="${LSBLK_MOUNT}"
    fi
fi

# 3. Flash via mount copy or picotool fallback
if [[ -n "${DETECTED_MOUNT}" ]]; then
    echo ">> Detected mounted RP2040 BOOTSEL volume at: ${DETECTED_MOUNT}"
    echo ">> Copying ${UF2_FILE} -> ${DETECTED_MOUNT}/"
    cp "${UF2_FILE}" "${DETECTED_MOUNT}/"
    echo ">> Syncing filesystem..."
    sync
    echo ">> Flashing initiated! The RP2040 will automatically reboot into pico-passkey."
    exit 0
fi

# Fallback: Check if picotool is available
if command -v picotool >/dev/null 2>&1; then
    echo ">> BOOTSEL mountpoint not found. Attempting to flash via picotool..."
    if picotool info >/dev/null 2>&1; then
        echo ">> Device detected via picotool. Loading firmware and rebooting..."
        picotool load -fx "${UF2_FILE}"
        echo ">> Flashed successfully with picotool!"
        exit 0
    else
        echo ">> picotool could not find an accessible RP2040 device."
    fi
fi

# 4. If neither worked, provide clear manual instructions
echo ""
echo "======================================================================"
echo "Error: No RP2040 BOOTSEL volume or picotool device detected."
echo "======================================================================"
echo "To flash pico-passkey onto your Raspberry Pi Pico:"
echo "  1. Unplug your Raspberry Pi Pico from the USB cable."
echo "  2. Press and hold down the white 'BOOTSEL' button on the board."
echo "  3. While holding the button, plug the USB cable back into your PC."
echo "  4. Release the 'BOOTSEL' button."
echo "  5. The Pico will enumerate as a mass storage device named 'RPI-RP2'."
echo "  6. Re-run this script:"
echo "       ./scripts/flash_pico.sh"
echo "     Or manually copy the UF2 file:"
echo "       cp \"${UF2_FILE}\" /run/media/${CURRENT_USER}/RPI-RP2/"
echo "======================================================================"
exit 1
