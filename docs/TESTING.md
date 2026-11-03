# Testing & Verification Guide: Pico Passkey

This guide documents the automated native test suites, fault-injection and crash-recovery tests, and step-by-step procedures for verifying the authenticator against real web browsers (Google Chrome, Chromium, Mozilla Firefox) on live WebAuthn relying parties.

---

## 1. Automated Native Host Test Suite

Pico Passkey is designed with a strict Hardware Abstraction Layer ([`platform.h`](../include/passkey/platform.h)). By compiling with `-DPICO_PASSKEY_HOST_TESTS=ON`, the entire cryptographic, storage, PIN, CTAP2, and CTAPHID codebase is compiled natively on the development machine and linked against [`tests/mock_platform.c`](../tests/mock_platform.c) and host `mbedcrypto`.

This provides:
- **Zero RP2040 Silicon Required**: Full test execution on CI/CD Linux runners.
- **Microsecond Execution Times**: Complete test suites run in under 2 seconds.
- **Memory Safety & Sanitizers**: Compatible with AddressSanitizer (`-fsanitize=address`) and Valgrind.
- **Deterministic Time & Fault Injection**: Exact control over monotonic time and flash write failures.

### Running All Host Tests
```bash
./scripts/run_tests.sh
```

Or execute `ctest` directly with custom filters:
```bash
cmake -B build/host_tests -G Ninja -DPICO_PASSKEY_HOST_TESTS=ON
cmake --build build/host_tests
ctest --test-dir build/host_tests --output-on-failure -V
```

---

## 2. Test Suites Overview

### 2.1 Cryptographic Core Tests (`test_crypto`)
Target: `tests/test_crypto.c`
- **SHA-256 & Multi-Buffer SHA-256**: Validated against NIST CAVP vectors and concatenation boundary tests.
- **HMAC-SHA-256**: Validated against RFC 4231 test vectors (empty key, short key, key > 64 bytes).
- **HKDF-SHA-256**: RFC 5869 Extract-and-Expand validation across varying salt and info parameters.
- **AES-256-CBC Zero-IV**: CTAP2 PIN Protocol v1 encryption and decryption with exact 16-byte block alignment checks.
- **P-256 Keypair Generation**: Validates public points lie on NIST SECP256R1 curve equation $y^2 = x^3 - 3x + b \pmod p$.
- **Deterministic Keypair Derivation**: Verifies that identical `(master_secret, rp_id_hash, cred_random)` inputs produce identical keypairs, and distinct `rp_id_hash` values yield cryptographically isolated keys.
- **ECDSA P-256 ASN.1 DER Signatures**: Validates standard `ECDSA-Sig-Value` ASN.1 DER parsing and verifies low-$S$ scalar normalization ($S \le n/2$).
- **ECDH Shared Secret Derivation**: Validates shared coordinate derivation $Z_x$ and subsequent SHA-256 digest against CTAP2 test vectors.
- **Non-Resident Credential ID Sealing**: Verifies that altering even a single bit of a 64-byte sealed credential handle causes HMAC verification failure.
- **Constant-Time Comparison**: Tests `pk_crypto_consttime_eq` across identical buffers, single-bit flips, and mismatching prefixes.
- **Secret Zeroization**: Confirms that volatile memory wiping clears sensitive cryptographic buffers.

### 2.2 Persistent Storage & Wear-Leveling Tests (`test_storage`)
Target: `tests/test_storage.c`
- **Flash Initialization & Mount**: Tests formatting virgin flash (filled with `0xFF`) and restoring pre-existing valid sectors.
- **A/B State Journaling**: Evaluates atomic state transitions between Sector 0 and Sector 1 with CRC32 verification and generational rollover.
- **Monotonic Signature Counter Log**: Tests append-only logging across pages without sector erasures. Verifies rollover from Counter Sector A to Sector B and ensures counter values never decrement across simulated restarts.
- **Resident Credential Storage**: Tests storing up to 64 resident credentials across the 28 wear-leveled sectors.
- **Wear-Leveling Candidate Selection**: Verifies the allocator chooses sectors with the lowest erase counts (`erase_count`).
- **Atomic Credential Update & Tombstoning**: Validates that updating an existing `(rp_id_hash, user_id)` commits the new slot (`0xFE -> 0xFC`) before tombstoning the old slot (`0xFC -> 0x00`).
- **Factory Reset**: Validates complete erasure of credential sectors, re-generation of root keys, and reset of monotonic counters.

### 2.3 CTAPHID Transport Protocol Tests (`test_ctaphid`)
Target: `tests/test_ctaphid.c`
- **Channel Allocation**: Evaluates broadcast `CID` (`0xFFFFFFFF`) handling, dynamic 32-bit CID assignment, and channel reuse.
- **Frame Segmentation & Reassembly**:
  - Single packet transaction (BCNT $\le 57$ bytes).
  - Multi-packet transaction across INIT frame and multiple CONT frames (up to 7,609 bytes).
- **Sequence Number Enforcement**: Simulates dropped or out-of-order CONT frames; verifies `CTAPHID_ERR_INVALID_SEQ` response.
- **Transaction Timeout (500 ms)**: Simulates transmission stalls by advancing mock monotonic clock; verifies incomplete frames are dropped with `CTAPHID_ERR_TIMEOUT`.
- **Channel Arbitration & Locking**: Verifies that while one channel holds an active transaction or `CTAPHID_CMD_LOCK`, packets on other channels receive `CTAPHID_ERR_CHANNEL_BUSY`.
- **Keepalive Transmissions**: Verifies that while user presence is pending, CTAPHID emits periodic `0xBB` keepalive frames with `0x02` (`UPNEEDED`) every 100 ms.
- **Diagnostics**: Tests `CTAPHID_CMD_PING` reflection and `CTAPHID_CMD_WINK` dispatch.

### 2.4 CTAP2 Protocol Core Tests (`test_ctap2`)
Target: `tests/test_ctap2.c`
- **`authenticatorGetInfo`**: Asserts complete CBOR payload structure, including supported versions (`FIDO_2_0`, `FIDO_2_1`), options (`rk: true`, `up: true`, `clientPin`), AAGUID, and algorithms.
- **`authenticatorMakeCredential`**:
  - Non-resident credential generation: returns sealed 64-byte credential ID.
  - Resident credential generation: stores metadata, user ID, and private key in flash pool.
  - Validates `authData` flag layout (UP=1, UV=0, AT=1, ED=0).
- **`authenticatorGetAssertion`**:
  - Non-resident assertion: unseals `credentialId`, regenerates keypair, increments counter, signs `authData || clientDataHash`.
  - Resident assertion: locates credential by `rp_id_hash`, returns user handle and valid signature.
- **`authenticatorGetNextAssertion`**: Validates pagination when multiple credentials exist for the same RP ID, and tests 30-second session expiration.
- **PIN Protocol v1 & Subcommands**:
  - Querying retries (`0x01`).
  - Key agreement negotiation (`0x02`).
  - Setting new PIN (`0x03`) with UTF-8 length validation.
  - Changing PIN (`0x04`).
  - Generating ephemeral `pinUvAuthToken` (`0x05` / `0x09`).
  - Scoped permission bitmask enforcement (`PK_PIN_PERM_MC`, `PK_PIN_PERM_GA`).
- **Throttling & Lockout**:
  - Verifies persistent retry counter decrements on invalid PIN attempts.
  - Verifies `CTAP2_ERR_PIN_BLOCKED` when retries reach 0.
  - Verifies `CTAP2_ERR_PIN_AUTH_BLOCKED` after 3 consecutive boot session failures.
- **Factory Reset Enforcement**: Asserts that `authenticatorReset` is rejected if called $> 10$ seconds after boot.

### 2.5 End-to-End WebAuthn Simulator (`test_webauthn_e2e`)
Target: `tests/test_webauthn_e2e.c`
- Simulates complete browser transactions by feeding raw 64-byte USB HID report streams into the authenticator stack:
  1. Virtual browser issues WebAuthn Registration (`MakeCredential`) for `webauthn.io`.
  2. Mock user presses button (UP confirmed).
  3. Browser extracts public key and attestation signature.
  4. Virtual browser issues WebAuthn Authentication (`GetAssertion`).
  5. Authenticator signs challenge and increments monotonic counter.
  6. Test verifies signature against registered public key.
  7. Tests passkey flow (resident key registration followed by username-less authentication).

---

## 3. Fault Injection & Power-Loss Recovery Testing

Reliability under sudden power disconnects is essential for USB security keys. Pico Passkey uses [`mock_platform.h`](../tests/mock_platform.h) hooks to simulate catastrophic hardware failures:

```c
typedef struct {
    ...
    /* Fault injection hooks for storage recovery testing */
    bool          fail_after_pages;
    uint32_t      pages_remaining_before_fail;
} pk_mock_platform_state_t;
```

### Automated Failure Scenarios Tested:
1. **Power Cut During A/B State Sector Erase**:
   - The inactive state sector is erased, but power fails before new data is written.
   - On reboot, `pk_storage_init` detects the corrupted/erased sector, falls back to the valid counterpart sector, and restores full device state without data loss.
2. **Power Cut During State Commit**:
   - New state is partially programmed, causing a CRC32 mismatch.
   - On reboot, `pk_storage_init` discards the corrupted generation and loads the prior valid generation.
3. **Power Cut During Resident Credential Write**:
   - Power fails while a credential slot is in `PK_CRED_SLOT_COMMITTING` (`0xFE`) state.
   - On reboot, the storage engine detects the incomplete write, marks the uncommitted slot as `PK_CRED_SLOT_TOMBSTONE` (`0x00`), and preserves the pre-existing active credential slot.
4. **Counter Page Corruption**:
   - Power cut during an append-only counter write.
   - On reboot, the counter log parser detects the trailing corrupted page, falls back to the last verified page entry, and continues uninterrupted.

---

## 4. Live Browser WebAuthn Verification Procedures

Once the firmware is flashed to a physical Raspberry Pi Pico, verify compliance using standard desktop browsers.

### 4.1 Prerequisites Check
1. Connect Pico Passkey to a USB port.
2. Confirm the Linux udev rule is installed:
   ```bash
   ls -l /dev/hidraw*
   ```
   Ensure your user account has read/write permissions (`+` POSIX ACL or `plugdev` group).
3. Confirm kernel device detection:
   ```bash
   dmesg | tail -n 20
   ```
   Look for: `Raspberry Pi Foundation Pico Passkey FIDO2 Security Key ... hidraw0`.

---

### 4.2 Chromium / Google Chrome Verification

#### Test A: `webauthn.io` (Standard 2FA & Discoverable Passkeys)
1. Navigate to **[https://webauthn.io](https://webauthn.io)** in Google Chrome or Chromium.
2. **Registration (MakeCredential)**:
   - Enter a username (e.g., `testuser`).
   - Under **Attachment**, select `Cross-Platform`.
   - Under **Discoverable Credential**, select `Preferred` or `Required` (tests Resident Passkey mode).
   - Under **Attestation Type**, select `Direct` or `None`.
   - Click **Register**.
   - The browser prompts: *"Set up your security key"*.
   - The on-board Pico LED will begin blinking.
   - **Press the white BOOTSEL button** on the Pico board.
   - WebAuthn displays: *"Registration Successful"*.
3. **Authentication (GetAssertion)**:
   - Click **Authenticate**.
   - The browser prompts: *"Touch your security key"*.
   - **Press the BOOTSEL button**.
   - WebAuthn displays: *"Authentication Successful"*.

#### Test B: `passkeys.io` (High-Level Passkey Experience)
1. Open **[https://passkeys.io](https://passkeys.io)**.
2. Enter an email address and click **Continue**.
3. When prompted to create a Passkey, select **Security Key**.
4. Touch the Pico BOOTSEL button to confirm user presence.
5. Sign out, click **Sign in with a Passkey**, and touch the Pico button again to complete instant passwordless login.

#### Browser Diagnostic Console: `chrome://device-log`
To inspect raw USB CTAP communications in Chromium:
1. Open a tab to `chrome://device-log`.
2. Set **Log level** to `Debug`.
3. Check the **FIDO** and **USB** event checkboxes.
4. Attempt a WebAuthn transaction. You will see real-time HID packet negotiations, channel allocations, and CTAP error codes if any occur.

#### Managing Credentials in Chrome: `chrome://settings/securityKeys`
1. Navigate to `chrome://settings/securityKeys`.
2. Select **Manage PIN** to set or change your Pico Passkey client PIN.
3. Select **Sign-in data** to view and delete stored discoverable credentials (resident passkeys) using the CTAP2 Credential Management protocol.
4. Select **Reset security key** (must be performed within 10 seconds of plugging in the Pico).

---

### 4.3 Mozilla Firefox Verification

#### Verification Steps
1. In Firefox, open **[https://webauthn.io](https://webauthn.io)**.
2. Ensure CTAP2 support is enabled in `about:config`:
   - `security.webauth.webauthn`: `true`
   - `security.webauth.ctap2`: `true`
3. Enter a username and click **Register**.
4. Firefox displays the native OS security key prompt: *"Please touch your security key"*.
5. Press the Pico BOOTSEL button.
6. Verify successful registration and authentication.

#### Terminal Debugging with Firefox WebAuthn Logger
To capture detailed low-level WebAuthn logs from Firefox:
```bash
MOZ_LOG="webauthn:5" firefox https://webauthn.io
```
Every CTAP2 request, CBOR payload, and USB response will be printed to stdout.

---

### 4.4 USB Packet Capture with Wireshark

To inspect the raw 64-byte USB HID report packets on Linux:
1. Load the Linux USB monitoring kernel module:
   ```bash
   sudo modprobe usbmon
   ```
2. Launch Wireshark as root or with capture capabilities:
   ```bash
   sudo wireshark
   ```
3. Capture on the interface `usbmonX` corresponding to the USB bus where the Pico is plugged in (find bus number via `lsusb`).
4. Filter by USB device address or FIDO HID report size:
   ```
   usb.data_len == 64
   ```
5. Observe the 64-byte packet streams:
   - Initial packets starting with channel ID and command byte (`0x90` for CBOR).
   - Periodic keepalive packets (`0xBB 0x02` for User Presence pending).
   - Continuation packets with incrementing sequence bytes (`0x00`, `0x01`, `0x02`...).
