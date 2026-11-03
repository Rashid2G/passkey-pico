# Pico Passkey: FIDO2 / WebAuthn Authenticator on Raspberry Pi Pico

**Pico Passkey** is a standards-compliant, open-source **FIDO2 / CTAP2.1 / WebAuthn hardware security key and passkey authenticator** running on the dual-core ARM Cortex-M0+ Raspberry Pi Pico (RP2040).

It transforms an inexpensive ($4) Raspberry Pi Pico board into a standalone USB security key capable of passwordless passkey authentication, multi-factor authentication (2FA), and CTAP2 client PIN protection across modern web browsers (Chromium, Google Chrome, Mozilla Firefox, Microsoft Edge, and Safari).

---

## Key Features

- **Full FIDO CTAP 2.1 & 2.0 Compliance**: Supports `authenticatorMakeCredential`, `authenticatorGetAssertion`, `authenticatorGetNextAssertion`, `authenticatorGetInfo`, `authenticatorClientPIN`, and `authenticatorReset`.
- **Legacy CTAP1 / U2F Backward Compatibility**: Interoperates with legacy U2F services via raw APDU handling (`U2F_REGISTER`, `U2F_AUTHENTICATE`, `U2F_VERSION`).
- **Resident Passkeys (Discoverable Credentials)**: Stores up to **64 resident passkeys** in flash memory, enabling username-less passwordless logins on sites like Google, GitHub, Microsoft, and Passkeys.io.
- **Unlimited Non-Resident Credentials**: Employs stateless 64-byte HMAC-SHA-256 sealed credential handles and deterministic P-256 keypair derivation via HKDF-SHA-256, allowing unlimited registered services with zero flash memory usage.
- **Wear-Leveled Flash Engine**: Custom flash journal manager utilizing A/B ping-pong sectors for persistent configuration, an append-only monotonic signature counter log, and wear leveling across 28 flash sectors (112 slots).
- **FIDO2 PIN Protocol v1**: Implements CTAP2 PIN authentication with ephemeral P-256 ECDH key agreement, AES-256-CBC encryption, persistent retry decrements (max 8), and boot session throttling (max 3).
- **Cryptographic Origin Isolation**: Strictly binds credential derivation and lookup to relying party domain hashes (`rp_id_hash`), guaranteeing protection against phishing and cross-origin spoofing.
- **`hmac-secret` Extension (WebAuthn PRF)**: Supports symmetric key derivation for client-side encryption, disk encryption tokens, and offline database unlocking (e.g. KeePassXC).
- **100% Host Testable**: Complete Hardware Abstraction Layer ([`platform.h`](include/passkey/platform.h)) enables full unit and integration testing natively on Linux without physical hardware.

---

## Directory Layout

```
pico-passkey/
├── CMakeLists.txt              # Top-level build configuration (Firmware & Host Tests)
├── pico_sdk_import.cmake       # Pico SDK import loader and toolchain binder
├── README.md                   # This overview & quickstart guide
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
    ├── ARCHITECTURE.md         # Detailed system design, Mermaid diagrams, flash layout
    ├── BUILD_AND_FLASH.md      # Toolchain setup, CMake options, flashing, and SWD debug
    ├── FIDO2_CAPABILITIES.md   # Command matrix, algorithms, options, PIN protocol details
    ├── SECURITY_LIMITATIONS.md # Engineering security analysis & RP2040 hardware limits
    └── TESTING.md              # Test suite documentation, fault injection, browser verification
```

---

## Quickstart Guide

### 1. Prerequisites (Debian/Ubuntu)
```bash
sudo apt update
sudo apt install -y cmake ninja-build build-essential libmbedtls-dev git curl tar
```
*(On Arch Linux: `sudo pacman -S cmake ninja base-devel mbedtls git curl tar`)*

### 2. Bootstrap SDK & Toolchain
The bootstrap script provisions the Raspberry Pi Pico SDK (`pico-sdk` tag `2.1.1`) with required submodules (`tinyusb`, `mbedtls`) and downloads the Arm GNU Toolchain if `arm-none-eabi-gcc` is not present on your system:
```bash
./scripts/bootstrap_sdk.sh
```

### 3. Build the Firmware
Compile the firmware binary and generate `pico_passkey.uf2`:
```bash
./scripts/build_firmware.sh
```

### 4. Flash to Raspberry Pi Pico
1. Unplug the Pico from USB.
2. Hold down the white **BOOTSEL** button on the Pico board.
3. Plug the Pico into your computer via USB while holding the button.
4. Release the **BOOTSEL** button (the board will mount as a USB drive named `RPI-RP2`).
5. Run the flashing script:
   ```bash
   ./scripts/flash_pico.sh
   ```
The Pico will flash and immediately reboot into FIDO2 security key mode.

### 5. Install Linux udev Rules
To allow web browsers to access the raw USB HID device without `sudo`:
```bash
sudo cp udev/70-pico-passkey.rules /etc/udev/rules.d/
sudo udevadm control --reload-rules
sudo udevadm trigger
sudo usermod -a -G plugdev "$USER"
```

---

## Running Native Host Tests

Execute all native unit, integration, and end-to-end test suites directly on your development machine:
```bash
./scripts/run_tests.sh
```

---

## User Interaction & Visual Indicators

| Action | User Prompt / LED Status | Required Action |
|---|---|---|
| **User Presence (UP)** | On-board LED blinks rapidly | **Press the white BOOTSEL button** on the Pico board to approve the WebAuthn request. |
| **Device Identification (Wink)** | Distinctive slow pulsing pattern | Visual feedback when requested by the OS or browser. |
| **Factory Reset Window** | Active only during first 10s of power-on | Re-plug Pico, issue reset in browser, and press button within 10 seconds. |

---

## Detailed Documentation

For in-depth technical documentation, refer to the following guides:

- **[Architecture & Design (`docs/ARCHITECTURE.md`)](docs/ARCHITECTURE.md)**: Layered architecture, CTAPHID reassembly state machine, MakeCredential/GetAssertion sequence diagrams, NOR flash memory layout, wear leveling, and module specifications.
- **[Build, Flash & Debugging (`docs/BUILD_AND_FLASH.md`)](docs/BUILD_AND_FLASH.md)**: Prerequisites, CMake options, UF2 flashing via BOOTSEL and `picotool`, SWD hardware debugging with OpenOCD and GDB, and udev setup.
- **[FIDO2 Capabilities (`docs/FIDO2_CAPABILITIES.md`)](docs/FIDO2_CAPABILITIES.md)**: Supported CTAP2.1/CTAP1 commands, COSE algorithms (`ES256`, `ECDH-ES+HKDF-256`), options (`rk`, `clientPin`, `credMgmt`), extensions (`hmac-secret`), and PIN protocol v1.
- **[Security Analysis & Limitations (`docs/SECURITY_LIMITATIONS.md`)](docs/SECURITY_LIMITATIONS.md)**: Transparent engineering analysis of implemented cryptographic properties vs. RP2040 external unencrypted QSPI flash hardware limitations and threat mitigations.
- **[Testing & Browser Verification (`docs/TESTING.md`)](docs/TESTING.md)**: Test suites (`test_crypto`, `test_storage`, `test_ctaphid`, `test_ctap2`, `test_webauthn_e2e`), fault-injection crash recovery, and live testing on `webauthn.io` and `passkeys.io` with Chrome and Firefox.

---

## License

This project is licensed under the Apache License 2.0.
