# Pico Passkey — Detailed Reference & Technical Guide

This document contains the detailed technical overview, repository structure, feature specifications, build and flashing steps, and operational references for the Pico Passkey project.

---

## Security Warning

> **Note**: This project is intended for educational, experimental, and development use. The Raspberry Pi Pico (RP2040) does not contain a hardware secure element (SE) or cryptographic enclave. All keys and state are stored in external NOR flash. While credentials are protected against origin spoofing and cryptographic attacks in software, physical possession of the device allows flash extraction. Do not rely on this hardware to protect high-value or production accounts. For a comprehensive threat model and hardware limitations analysis, see [SECURITY_LIMITATIONS.md](SECURITY_LIMITATIONS.md).

---

## Full Feature Breakdown

### FIDO2 / WebAuthn & CTAP Specifications
- **FIDO CTAP 2.1 & 2.0 Compliance**: Full implementation of `authenticatorMakeCredential`, `authenticatorGetAssertion`, `authenticatorGetNextAssertion`, `authenticatorGetInfo`, `authenticatorClientPIN`, and `authenticatorReset`.
- **Legacy CTAP1 / U2F Backward Compatibility**: Interoperates with legacy U2F services via raw APDU handling (`U2F_REGISTER`, `U2F_AUTHENTICATE`, `U2F_VERSION`).
- **Resident Passkeys (Discoverable Credentials)**: Stores up to 64 resident passkeys in flash memory, enabling username-less logins on platforms such as Google, GitHub, Microsoft, and Passkeys.io.
- **Unlimited Non-Resident Credentials**: Uses stateless 64-byte HMAC-SHA-256 sealed credential handles with deterministic P-256 keypair derivation via HKDF-SHA-256, allowing unlimited registered services with zero flash memory overhead.
- **`hmac-secret` Extension (WebAuthn PRF)**: Supports symmetric key derivation for client-side encryption, disk encryption tokens, and offline database unlocking (e.g., KeePassXC).
- **Cryptographic Origin Isolation**: Binds credential derivation and lookup to relying party domain hashes (`rp_id_hash`), preventing cross-origin spoofing and phishing.

### Cryptography & PIN Protection
- **Curve & Algorithms**: NIST P-256 (secp256r1) with ECDSA SHA-256 (`ES256`, COSE algorithm `-7`), ECDH key agreement (`ECDH-ES+HKDF-256`, COSE algorithm `-25`), HMAC-SHA-256, and AES-256-CBC.
- **FIDO2 PIN Protocol v1**: Ephemeral P-256 ECDH key exchange with AES-256-CBC token encryption, persistent retry tracking (maximum 8 attempts), and session throttling (maximum 3 attempts per power cycle).

### Flash Storage & Reliability
- **Wear-Leveled Flash Engine**: Custom flash journal using A/B ping-pong sectors for persistent configuration, an append-only monotonic signature counter log, and wear leveling across 28 flash sectors (112 slots).
- **Power-Loss Resilient**: Atomic journal transitions guarantee state consistency even if power is removed mid-write.

### Testing & HAL
- **Hardware Abstraction Layer (HAL)**: Fully abstracted interface (`platform.h`) decoupling protocol logic from RP2040 hardware, allowing unit and integration testing natively on Linux/macOS without physical hardware.

---

## Repository Directory Layout

```
pico-passkey/
├── CMakeLists.txt              # Top-level build configuration (Firmware & Host Tests)
├── pico_sdk_import.cmake       # Pico SDK import loader and toolchain binder
├── README.md                   # Project summary and introduction
├── include/
│   └── passkey/
│       ├── cbor.h              # Streaming zero-allocation CBOR encoder & decoder
│       ├── config.h            # Firmware constants, USB VID/PID, AAGUID, memory map
│       ├── crypto.h            # P-256, SHA-256, HMAC, HKDF, AES-256, DER crypto API
│       ├── ctap2.h             # CTAP2.1 & CTAP1 command processing and state machine
│       ├── ctaphid.h           # CTAPHID framing, reassembly, channel arbitration, timeouts
│       ├── pin.h               # CTAP2 PIN protocol v1, retry tracking, pinUvAuthToken
│       ├── platform.h          # Hardware Abstraction Layer (HAL) interface contract
│       ├── status.h            # Internal error codes & official FIDO status constants
│       ├── storage.h           # A/B journaled state, wear-leveling & monotonic counter log
│       └── usb_hid.h           # USB HID report descriptor & endpoint queues
├── src/                        # RP2040 firmware & core protocol implementation
├── tests/
│   ├── mock_platform.h         # Mock HAL state, deterministic clock, fault injection hooks
│   ├── mock_platform.c         # Simulated flash memory, PRNG, and virtual user presence
│   ├── test_crypto.c           # Cryptographic unit tests (NIST & RFC test vectors)
│   ├── test_storage.c          # Flash crash-recovery, wear-leveling, and counter tests
│   ├── test_ctaphid.c          # Framing, reassembly, sequence check, and timeout tests
│   ├── test_ctap2.c            # MakeCredential, GetAssertion, and PIN protocol tests
│   └── test_webauthn_e2e.c     # End-to-end simulated WebAuthn browser transaction tests
├── scripts/
│   ├── bootstrap_sdk.sh        # Automatically downloads Pico SDK and ARM GCC toolchain
│   ├── build_firmware.sh       # Compiles RP2040 firmware into pico_passkey.uf2
│   ├── flash_pico.sh           # Auto-detects BOOTSEL volume or picotool to flash Pico
│   └── run_tests.sh            # Builds and executes all native host unit/integration tests
├── udev/
│   └── 70-pico-passkey.rules   # Linux udev rules granting non-root browser access
└── docs/
    ├── ARCHITECTURE.md         # System design, state machines, and flash layout
    ├── BUILD_AND_FLASH.md      # Toolchain setup, CMake options, flashing, and SWD debug
    ├── DETAILS.md              # This detailed reference document
    ├── FIDO2_CAPABILITIES.md   # Command matrix, algorithms, options, PIN protocol details
    ├── SECURITY_LIMITATIONS.md # Security analysis & RP2040 hardware limits
    └── TESTING.md              # Test suite documentation, fault injection, browser verification
```

---

## Detailed Build & Flashing Instructions

### 1. Prerequisites (Debian/Ubuntu)
```bash
sudo apt update
sudo apt install -y cmake ninja-build build-essential libmbedtls-dev git curl tar
```
*(Arch Linux: `sudo pacman -S cmake ninja base-devel mbedtls git curl tar`)*

### 2. Bootstrap SDK & Toolchain
The bootstrap script provisions the Raspberry Pi Pico SDK (`pico-sdk` tag `2.1.1`) along with submodules (`tinyusb`, `mbedtls`) and downloads the Arm GNU Toolchain if `arm-none-eabi-gcc` is not installed on your system:
```bash
./scripts/bootstrap_sdk.sh
```

### 3. Build the Firmware
Compile the firmware and generate `pico_passkey.uf2`:
```bash
./scripts/build_firmware.sh
```

### 4. Flash to Raspberry Pi Pico
1. Unplug the Pico from USB.
2. Hold down the white **BOOTSEL** button on the Pico board.
3. Plug the Pico into your computer via USB while holding the button.
4. Release the **BOOTSEL** button (the board will mount as a USB mass storage drive named `RPI-RP2`).
5. Run the flashing script:
   ```bash
   ./scripts/flash_pico.sh
   ```
The Pico will flash and immediately reboot into FIDO2 security key mode.

### 5. Linux udev Configuration
Web browsers require permission to communicate with raw USB HID endpoints (`/dev/hidraw*`). To install the udev rule without needing `sudo` every time:
```bash
sudo cp udev/70-pico-passkey.rules /etc/udev/rules.d/
sudo udevadm control --reload-rules
sudo udevadm trigger
sudo usermod -a -G plugdev "$USER"
```

---

## User Interaction & Visual Indicators

| Action | LED Status | Required User Action |
|---|---|---|
| **User Presence (UP)** | Fast blinking | **Press the white BOOTSEL button** on the Pico board to approve the authentication request. |
| **Device Identification (Wink)** | Slow pulsing pattern | Visual feedback requested by the OS or browser. No action needed. |
| **Factory Reset Window** | Active during first 10 seconds of power-on | Re-plug the Pico, initiate a reset via browser or host tool, and press the button within 10 seconds. |

---

## Running Native Host Tests

You can execute the entire unit, integration, and WebAuthn end-to-end test suite directly on your host machine without physical hardware:
```bash
./scripts/run_tests.sh
```

---

## Deeper Documentation Links

For further technical details, see the dedicated guides:

- [ARCHITECTURE.md](ARCHITECTURE.md) — System layering, CTAPHID reassembly, sequence diagrams, and flash layout.
- [BUILD_AND_FLASH.md](BUILD_AND_FLASH.md) — Advanced CMake flags, manual compilation, SWD debugging via GDB/OpenOCD, and troubleshooting.
- [FIDO2_CAPABILITIES.md](FIDO2_CAPABILITIES.md) — Complete CTAP2.1 command matrix, COSE algorithm parameters, and PIN protocol specification.
- [SECURITY_LIMITATIONS.md](SECURITY_LIMITATIONS.md) — Cryptographic architecture vs RP2040 unencrypted flash hardware limitations.
- [TESTING.md](TESTING.md) — Test cases, mock HAL architecture, fault injection, and live browser testing instructions.
