# Security Analysis & Hardware Limitations: Pico Passkey

This document provides a transparent engineering analysis of the security properties implemented in **Pico Passkey**, the threat model addressed, the inherent hardware limitations of the Raspberry Pi Pico (RP2040) platform, and recommended mitigations.

---

## 1. Threat Model & Security Objectives

| Threat Actor | Vector | Security Objective | Addressed? |
|---|---|---|---|
| **Remote Web Attacker** | Phishing, MITM, DNS spoofing, credential stuffing | Bind credentials to Relying Party ID; prevent credential reuse on phishing domains | **YES (Complete)** |
| **Local Host Malware** | Malicious processes issuing unauthorized WebAuthn requests | Require physical user presence (button press); enforce 10s boot reset window | **YES (Complete)** |
| **PIN Brute-Forcer** | Automated software guessing client PIN over USB | Persistent retry counter (8 max) + boot session counter (3 max) | **YES (Complete)** |
| **Flash Cloner (Software)** | Dumping state through USB protocols | CTAP2 specification prohibits private key extraction; no debug interface over USB | **YES (Complete)** |
| **Physical Hardware Attacker** | Desoldering external QSPI flash, bus sniffing, chip probing | Protect secrets against physical laboratory extraction | **NO (Hardware Limitation)** |

---

## 2. Implemented Firmware Security Properties

### 2.1 Cryptographic Credential Isolation per Relying Party (RP ID)
Pico Passkey strictly enforces origin isolation across all credentials:
- **Non-Resident Credentials**: The private key scalar $d$ is derived via HKDF-SHA-256 where the salt is `rp_id_hash`:
  $$d = \text{HKDF-SHA-256}(\text{IKM}=\text{master\_secret}, \text{Salt}=\text{SHA-256}(\text{rpId}), \text{Info}=\text{"PK-P256-KEY-DERIV"} \parallel \text{cred\_random})$$
  Even if a malicious site captures a credential ID issued for `login.gov`, presenting that credential ID under `attacker.com` results in a completely different scalar and invalid signature.
- **Resident Credentials**: Stored resident credential records explicitly store `rp_id_hash`. Credential lookups during `authenticatorGetAssertion` match `rp_id_hash` via strict binary equality.

### 2.2 Tamper-Evident HMAC-Sealed Non-Resident Credentials
Non-resident credentials are not stored in flash. Instead, the 64-byte `credentialId` returned to the browser contains:
- Bytes 0..31: Per-credential random 32-byte nonce (`cred_random`).
- Bytes 32..63: 32-byte HMAC tag:
  $$\text{Tag} = \text{HMAC-SHA-256}(\text{cred\_mac\_key}, \text{"PK-NRCRED-V1"} \parallel \text{rp\_id\_hash} \parallel \text{cred\_random})$$
When the host presents a non-resident credential ID during authentication, the authenticator recalculates the expected HMAC tag over `cred_mac_key`, the active `rp_id_hash`, and the unsealed `cred_random`. If any byte is altered, or if the credential was issued for another origin, validation fails immediately with `CTAP2_ERR_INVALID_CREDENTIAL`.

### 2.3 Constant-Time Cryptographic Comparisons
All MAC checks, PIN hash verifications, and auth token validations are performed using constant-time comparisons (`pk_crypto_consttime_eq`):
```c
bool pk_crypto_consttime_eq(const uint8_t *a, const uint8_t *b, size_t len) {
    uint8_t diff = 0;
    for (size_t i = 0; i < len; i++) {
        diff |= (a[i] ^ b[i]);
    }
    return diff == 0;
}
```
This prevents timing side-channel attacks from leaking secret bytes through network latency or high-precision USB host timers.

### 2.4 Explicit Memory Zeroization
To protect sensitive cryptographic secrets in RAM (ephemeral ECDH private keys, unencrypted PIN buffers, derived shared secrets, and `pinToken`), Pico Passkey utilizes `pk_crypto_zeroize()`:
- Employs volatile pointers or `mbedtls_platform_zeroize()` to guarantee the compiler will not eliminate buffer clears via Dead Store Elimination (DSE).
- Scrubbing is performed immediately upon completion of every cryptographic operation or sub-command failure.

### 2.5 Dual-Tier PIN Retry Throttling
To protect against automated PIN dictionary and brute-force attacks:
1. **Persistent Retries (A/B Flash Journal)**:
   - Initialized to 8 attempts.
   - **Crucial Security Measure**: The persistent counter is decremented and committed to flash **prior** to evaluating candidate PIN validity. If an attacker abruptly cuts power during verification, the attempt is already consumed.
   - Reaching 0 permanently blocks PIN operations (`CTAP2_ERR_PIN_BLOCKED`). Only a complete factory reset (`authenticatorReset`) can unlock the device, which irrevocably wipes all resident credentials and master secrets.
2. **Boot Session Retries (RAM)**:
   - Capped at 3 consecutive failed attempts within a single power cycle.
   - Prevents an automated script from exhausting all 8 persistent attempts in a few seconds. After 3 failures, PIN operations are rejected with `CTAP2_ERR_PIN_AUTH_BLOCKED` until the physical USB device is power-cycled.

### 2.6 Strict 10-Second Boot Window for Factory Reset
The CTAP2 specification mandates protection against unauthorized device wipes:
- `authenticatorReset` (subcommand `0x07`) is **strictly rejected** with `CTAP2_ERR_NOT_ALLOWED` if more than **10,000 milliseconds** (`PK_RESET_WINDOW_MS`) have elapsed since microcontroller boot.
- Within the 10-second window, the reset command still requires **physical button confirmation** via `pk_platform_request_user_presence`.
- This guarantees background malware on a host computer cannot silently wipe or reinitialize an authenticator during normal desktop operation.

### 2.7 Append-Only Monotonic Signature Counter
The global monotonic counter (`signCount`) increments on every assertion:
- Prevents cloned security keys and protects against replay attacks.
- Implemented as an append-only log across dedicated flash sectors to eliminate sector wear while preserving rollback protection across reboots.

---

## 3. Hardware Security Limitations of the RP2040

While the firmware implements state-of-the-art cryptographic safeguards against remote and local software attacks, the **Raspberry Pi Pico (RP2040) has fundamental hardware architecture limitations** that prospective users and system architects must understand.

```
RP2040 Physical Attack Surface
+--------------------------------------------------------------------+
|  Raspberry Pi Pico PCB                                             |
|                                                                    |
|  +------------------+     Plaintext QSPI Bus      +-------------+  |
|  |  RP2040 MCU      | <=========================> | External    |  |
|  |                  |    Traces exposed on PCB    | NOR Flash   |  |
|  | - No Internal    |                             | (W25Q16)    |  |
|  |   Flash          |                             |             |  |
|  | - No Hardware    |                             | Contains:   |  |
|  |   Secure Element |                             | - Master    |  |
|  | - No Bus Crypt   |                             |   Secret    |  |
|  +------------------+                             | - Resident  |  |
|                                                   |   Keys      |  |
|                                                   +-------------+  |
+--------------------------------------------------------------------+
                                                           ^
                                                           |
                      Attacker with SOIC-8 Clip / SPI Programmer
                      dumps entire flash memory in 5 seconds
```

### 3.1 External Unencrypted QSPI Flash
- **No On-Chip Non-Volatile Memory**: The RP2040 microcontroller contains 264 KiB of SRAM and 16 KiB of internal boot ROM, but **zero internal flash memory**.
- **External Flash Storage**: All firmware code, configuration data, and persistent cryptographic secrets reside on an external SPI/QSPI NOR flash chip (Winbond W25Q16 or equivalent).
- **Plaintext Bus**: The RP2040 does **not** feature hardware on-the-fly flash decryption (unlike the RP2350 or ESP32-S3). All flash communication travels over exposed PCB traces in plaintext.
- **Physical Extraction Risk**: Anyone with temporary physical possession of the Pico can attach a $5 SOIC-8 test clip or desolder the 8-pin flash chip and read the entire 2 MiB flash dump using an inexpensive programmer (such as a CH341A, Raspberry Pi, or `flashrom`) in seconds.

### 3.2 Absence of a Hardware Secure Element
- Commercial authenticators (YubiKey, SoloKeys, Nitrokey) utilize certified Secure Elements (e.g., NXP, Infineon, STMicroelectronics) rated at **Common Criteria EAL 5+ or 6+**.
- Secure Elements feature:
  - Active physical shielding layers and tamper sensors (detecting decapsulation, UV light, laser fault injection).
  - Internal hardware cryptographic engines with Differential Power Analysis (DPA) and Correlation Power Analysis (CPA) countermeasures.
  - Glitch detection (voltage and clock monitors).
  - True on-chip read-out protection (ROP) and internal non-volatile memory that cannot be probed via external pins.
- The RP2040 has **none** of these physical tamper protections.

### 3.3 Side-Channel Vulnerabilities
- The dual ARM Cortex-M0+ cores run standard software implementations of P-256 scalar point multiplication and AES-256.
- Without hardware-accelerated constant-current power regulation or side-channel masking, the device is theoretically susceptible to Simple Power Analysis (SPA) or Electromagnetic (EM) side-channel probing if an attacker monitors board decoupling capacitors during cryptographic operations.

---

## 4. Threat Impact & Mitigations

### 4.1 Flash Dump Exposure Analysis

| Device State | What is Exposed in Flash Dump? | Attacker Capabilities |
|---|---|---|
| **Without Client PIN** | `master_secret`, `cred_mac_key`, all resident credential private keys, monotonic counter. | **Total Compromise**: Attacker can clone all resident passkeys and derive all non-resident private keys. |
| **With Strong Client PIN Configured** | `pin_salt`, `pin_hash_verifier`, `master_secret` (if not PIN-encrypted), resident private keys. | **Partial / High Risk**: Attacker has offline access to `pin_hash_verifier`. They can perform high-speed offline dictionary attacks (millions of guesses/sec on a GPU) against the PIN. |

### 4.2 Engineering Mitigations & Recommendations

1. **Mandatory Client PIN with High Entropy**:
   - Always configure a strong client PIN of at least 8 to 12 alphanumeric characters.
   - Do not use 4-digit PINs (`1234`), as an attacker with a flash dump can crack a 4-digit PIN offline in less than one second.
2. **Intended Deployment Scenarios**:
   - **Recommended For**:
     - Developers learning FIDO2, CTAP2, WebAuthn, and embedded USB architectures.
     - Automated WebAuthn integration testing and CI/CD pipelines.
     - Everyday personal 2FA where the primary threat is remote phishing and physical theft by sophisticated state-sponsored laboratories is not in the threat profile.
   - **NOT Recommended For**:
     - High-assurance corporate access or high-value cryptocurrency storage where physical device loss or confiscation is a primary threat model.
3. **Future Hardware Evolution**:
   - **Raspberry Pi RP2350 Upgrade**: The newer RP2350 microcontroller introduces ARM TrustZone, OTP anti-rollback flags, hardware SHA-256, and hardware on-the-fly external flash encryption (AES-XIP). Porting Pico Passkey to RP2350 substantially closes the physical flash dump vector.
   - **External Secure Element (I2C Companion)**: Connecting an ATECC608A or NXP SE050 chip via I2C to hold the root `master_secret` and handle ECDSA signing within a physical secure element.
