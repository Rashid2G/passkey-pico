# Pico Passkey

A FIDO2 / WebAuthn passkey authenticator running on the Raspberry Pi Pico (RP2040).

Plug the Pico in via USB, and it acts as a standalone hardware security key for passwordless passkey logins and two-factor authentication across Chromium, Chrome, Firefox, Safari, and Edge.

> **Important:** This is an open-source, educational DIY project. The RP2040 does not have a secure element, meaning cryptographic keys are stored in external flash memory. It is great for learning how FIDO2/WebAuthn works under the hood, but **do not use it to protect sensitive, real-world accounts**. Read [docs/SECURITY_LIMITATIONS.md](docs/SECURITY_LIMITATIONS.md) for details.

---

## What It Supports

- **WebAuthn & CTAP 2.1**: Works with passkey logins on GitHub, Google, Microsoft, Passkeys.io, and legacy U2F services.
- **Resident & Non-Resident Keys**: Up to 64 resident credentials (usernameless logins) stored in wear-leveled flash, plus unlimited stateless non-resident keys.
- **User Presence**: The onboard LED flashes when an authentication request arrives; press the white **BOOTSEL** button to confirm.
- **PIN Protection**: Supports FIDO2 client PINs with retry limits.
- **Host Test Suite**: Includes a full mock platform so you can compile and run unit and integration tests on Linux without physical hardware.

---

## Quickstart

```bash
# 1. Download SDK and ARM toolchain
./scripts/bootstrap_sdk.sh

# 2. Build the firmware
./scripts/build_firmware.sh

# 3. Flash to Pico (hold BOOTSEL while plugging into USB, then run)
./scripts/flash_pico.sh
```

On Linux, install the udev rule once so browsers can access the key without root:
```bash
sudo cp udev/70-pico-passkey.rules /etc/udev/rules.d/ && sudo udevadm trigger
```

---

## Documentation

Full details, architecture, and guides are located in the [docs/](docs/) folder:

- **[Detailed Reference (`docs/DETAILS.md`)](docs/DETAILS.md)** — Complete feature breakdown, repository layout, detailed setup, and operational tables.
- **[Build & Flashing Guide (`docs/BUILD_AND_FLASH.md`)](docs/BUILD_AND_FLASH.md)** — Toolchain requirements, CMake options, UF2 flashing, and SWD debugging with GDB.
- **[Architecture & Design (`docs/ARCHITECTURE.md`)](docs/ARCHITECTURE.md)** — State machines, CTAPHID reassembly, sequence diagrams, and flash layout.
- **[FIDO2 Capabilities (`docs/FIDO2_CAPABILITIES.md`)](docs/FIDO2_CAPABILITIES.md)** — Supported CTAP commands, COSE algorithms, options, and PIN protocol.
- **[Security Analysis (`docs/SECURITY_LIMITATIONS.md`)](docs/SECURITY_LIMITATIONS.md)** — Hardware limits of the RP2040 and threat modeling.
- **[Testing Guide (`docs/TESTING.md`)](docs/TESTING.md)** — Native host test suite, fault injection, and live browser testing.

---

## License

Apache License 2.0. See [LICENSE](LICENSE) or source headers for terms.
