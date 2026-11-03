# Build, Flash & Debugging Guide: Pico Passkey

This guide provides complete instructions for setting up the build environment, compiling firmware and native host tests, flashing the Raspberry Pi Pico via BOOTSEL and SWD, debugging with GDB and OpenOCD, and configuring Linux `udev` rules.

---

## 1. Prerequisites & Dependencies

### Host System Requirements
Pico Passkey supports building on **Linux (Ubuntu, Debian, Fedora, Arch)**, **macOS**, and **Windows (WSL2)**.

### Required Host Packages
| Package | Purpose | Debian/Ubuntu | Arch Linux | Fedora |
|---|---|---|---|---|
| `cmake` (>= 3.16) | Build configuration | `sudo apt install cmake` | `sudo pacman -S cmake` | `sudo dnf install cmake` |
| `ninja-build` | Fast parallel build system | `sudo apt install ninja-build` | `sudo pacman -S ninja` | `sudo dnf install ninja-build` |
| `gcc` / `clang` | Host compiler for test suites | `sudo apt install build-essential` | `sudo pacman -S base-devel` | `sudo dnf install gcc gcc-c++` |
| `libmbedtls-dev` | Host crypto library for native tests | `sudo apt install libmbedtls-dev` | `sudo pacman -S mbedtls` | `sudo dnf install mbedtls-devel` |
| `curl`, `tar`, `git` | SDK download & management | `sudo apt install curl tar git` | `sudo pacman -S curl tar git` | `sudo dnf install curl tar git` |

### ARM Cross-Compiler Toolchain
- **Required**: `arm-none-eabi-gcc` (version 10.3 or newer, 13.3+ recommended).
- If `arm-none-eabi-gcc` is not installed on your system, the included bootstrap script (`scripts/bootstrap_sdk.sh`) **automatically downloads and installs** the official Arm GNU Toolchain 13.3.rel1 into `.sdk/arm-gnu-toolchain/`.

---

## 2. SDK & Toolchain Bootstrap

The repository includes a self-contained bootstrap script that provisions the Raspberry Pi Pico SDK (`pico-sdk` tag `2.1.1`) along with the required submodules (`tinyusb` and `mbedtls`):

```bash
# Run SDK bootstrap
./scripts/bootstrap_sdk.sh
```

### What `bootstrap_sdk.sh` Performs:
1. Creates the local `.sdk/` directory (ignored by `.gitignore`).
2. Clones `https://github.com/raspberrypi/pico-sdk.git` at release tag `2.1.1`.
3. Checks out and initializes the required SDK submodules (`lib/tinyusb` and `lib/mbedtls`).
4. Checks whether `arm-none-eabi-gcc` exists on your system `$PATH`. If not found, downloads the precompiled Arm GNU Toolchain archive for your host architecture (`x86_64` or `aarch64`) from Arm Developer, extracts it to `.sdk/arm-gnu-toolchain/`, and verifies the binary.

---

## 3. Building the RP2040 Firmware

### Quick Build (Recommended)
Use the automated build script:
```bash
./scripts/build_firmware.sh
```

This script:
1. Checks for `.sdk/pico-sdk` and runs `bootstrap_sdk.sh` if missing.
2. Configures CMake in `build/firmware/` with Ninja and `-DPICO_PASSKEY_HOST_TESTS=OFF`.
3. Compiles the firmware and produces `build/firmware/pico_passkey.uf2` and `build/firmware/pico_passkey.elf`.
4. Executes `arm-none-eabi-size` on the resulting binary to display flash and RAM consumption.

### Manual CMake Configuration
To manually configure and build the firmware:
```bash
# 1. Set SDK path (if not using local .sdk directory)
export PICO_SDK_PATH="${PWD}/.sdk/pico-sdk"

# 2. Configure build with Ninja
cmake -B build/firmware \
      -G Ninja \
      -DPICO_PASSKEY_HOST_TESTS=OFF \
      -DCMAKE_BUILD_TYPE=Release

# 3. Compile target
cmake --build build/firmware --target pico_passkey
```

### Build Artifacts
Upon a successful build, the following files are produced in `build/firmware/`:
- `pico_passkey.uf2`: Drag-and-drop firmware image for the RP2040 USB bootloader.
- `pico_passkey.elf`: Executable and Linkable Format binary for SWD debugging.
- `pico_passkey.bin`: Raw binary image.
- `pico_passkey.hex`: Intel HEX file format.
- `pico_passkey.map`: Linker memory map.

---

## 4. Flashing the Firmware

### Method 1: Automated Flashing Script (`scripts/flash_pico.sh`)
```bash
./scripts/flash_pico.sh
```
1. Unplug the Pico from USB.
2. Press and hold the white **BOOTSEL** button on the Pico board.
3. Plug the Pico into your computer via USB while holding the button.
4. Release the **BOOTSEL** button. The board mounts as a USB mass storage drive labeled `RPI-RP2`.
5. Run `./scripts/flash_pico.sh`. The script detects the mounted volume (via `/run/media/$USER/RPI-RP2`, `/media/$USER/RPI-RP2`, or `lsblk`), copies `pico_passkey.uf2`, calls `sync`, and the Pico automatically reboots into FIDO2 authenticator mode.

### Method 2: Manual Drag-and-Drop
After entering BOOTSEL mode, copy the UF2 file directly:
```bash
cp build/firmware/pico_passkey.uf2 /run/media/$USER/RPI-RP2/
sync
```

### Method 3: Flashing via `picotool`
If you have `picotool` installed:
```bash
# Flash UF2 and reboot RP2040 into application mode
picotool load -fx build/firmware/pico_passkey.uf2
```

### Method 4: SWD (Serial Wire Debug) Flashing
You can flash the Pico without pressing BOOTSEL using a Raspberry Pi Debug Probe or a second Pico running `picoprobe`:
```bash
openocd -f interface/cmsis-dap.cfg \
        -f target/rp2040.cfg \
        -c "adapter speed 5000" \
        -c "program build/firmware/pico_passkey.elf verify reset exit"
```

---

## 5. SWD Hardware Debugging with GDB

### Hardware Setup
Connect the Raspberry Pi Debug Probe (or `picoprobe`) to the RP2040 3-pin SWD header:
- **DEBUG PROBE SWCLK** -> **RP2040 SWCLK** (Pin 2 on SWD header)
- **DEBUG PROBE SWDIO** -> **RP2040 SWDIO** (Pin 1 on SWD header)
- **DEBUG PROBE GND**   -> **RP2040 GND**   (Pin 3 on SWD header)

### 1. Launch OpenOCD Server
In a dedicated terminal:
```bash
openocd -f interface/cmsis-dap.cfg -f target/rp2040.cfg -s tcl
```
OpenOCD opens a GDB server listening on `localhost:3333`.

### 2. Connect with GDB
In another terminal:
```bash
# Use local ARM toolchain GDB or system gdb-multiarch
./.sdk/arm-gnu-toolchain/bin/arm-none-eabi-gdb build/firmware/pico_passkey.elf \
    -ex "target extended-remote :3333" \
    -ex "monitor reset init" \
    -ex "load" \
    -ex "b pk_ctap2_process_message" \
    -ex "b pk_storage_save_credential" \
    -ex "continue"
```

### Useful GDB Commands for Pico Passkey
- `monitor reset init`: Resets and halts the RP2040 dual Cortex-M0+ cores.
- `print *storage`: Inspects active A/B state, generation counter, and monotonic sign counter.
- `print *pin`: Inspects ephemeral PIN token permissions, timeout timestamps, and boot retry counters.
- `x/32xb 0x101e0000`: Dumps the raw active state sector in QSPI flash memory (`0x10000000 + 0x1E0000`).

---

## 6. Linux udev Rules Configuration

### Why udev Configuration is Required
On modern Linux distributions, USB HID raw character devices (`/dev/hidraw*`) are restricted to `root` by default. Without a udev rule:
- Web browsers (Google Chrome, Chromium, Mozilla Firefox, Brave, Microsoft Edge) cannot open `/dev/hidraw*`.
- WebAuthn calls (`navigator.credentials.create()` and `navigator.credentials.get()`) fail with `NotAllowedError: The operation either timed out or was not allowed`.

### Rule Definition (`udev/70-pico-passkey.rules`)
```udev
KERNEL=="hidraw*", SUBSYSTEM=="hidraw", ATTRS{idVendor}=="2e8a", ATTRS{idProduct}=="f1d0", TAG+="uaccess", GROUP="plugdev", MODE="0660"
```
- `ATTRS{idVendor}=="2e8a"`: Raspberry Pi Foundation USB Vendor ID.
- `ATTRS{idProduct}=="f1d0"`: Pico Passkey USB Product ID.
- `TAG+="uaccess"`: Grants access to the actively logged-in seat user via systemd `logind`.
- `GROUP="plugdev", MODE="0660"`: Fallback for distributions utilizing the traditional `plugdev` group.

### Installation Instructions
```bash
# 1. Copy the udev rule to system directory
sudo cp udev/70-pico-passkey.rules /etc/udev/rules.d/

# 2. Reload udev rule database and trigger hotplug events
sudo udevadm control --reload-rules
sudo udevadm trigger

# 3. Ensure your current user is in the plugdev group (if applicable)
sudo usermod -a -G plugdev "$USER"
```

### Verifying Device Node Permissions
Plug the Pico Passkey into USB and verify the device node:
```bash
ls -l /dev/hidraw*
```
Expected output:
```
crw-rw----+ 1 root plugdev 243, 0 Nov  3 17:00 /dev/hidraw0
```
Notice the `+` character at the end of permissions indicating an active POSIX ACL granted to your desktop user account via `uaccess`. You can verify ACL details with:
```bash
getfacl /dev/hidraw0
```
User permissions will display:
```
# file: dev/hidraw0
# owner: root
# group: plugdev
user::rw-
user:youruser:rw-
group::rw-
mask::rw-
other::---
```
