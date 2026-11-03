#ifndef PICO_PASSKEY_PIN_H
#define PICO_PASSKEY_PIN_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "passkey/config.h"
#include "passkey/crypto.h"
#include "passkey/platform.h"
#include "passkey/status.h"
#include "passkey/storage.h"

/* CTAP2 authenticatorClientPIN (0x06) Subcommands (§6.5.5) */
#define PK_PIN_SUBCMD_GET_RETRIES                 0x01U
#define PK_PIN_SUBCMD_GET_KEY_AGREEMENT           0x02U
#define PK_PIN_SUBCMD_SET_PIN                     0x03U
#define PK_PIN_SUBCMD_CHANGE_PIN                  0x04U
#define PK_PIN_SUBCMD_GET_PIN_TOKEN               0x05U
#define PK_PIN_SUBCMD_GET_PIN_UV_TOKEN_USING_UV   0x06U
#define PK_PIN_SUBCMD_GET_UV_RETRIES              0x07U
#define PK_PIN_SUBCMD_GET_PIN_UV_TOKEN_USING_PIN  0x09U

/* CTAP2.1 pinUvAuthToken Permission Bits (§6.5.5.7) */
#define PK_PIN_PERM_MC   0x01U /* MakeCredential */
#define PK_PIN_PERM_GA   0x02U /* GetAssertion */
#define PK_PIN_PERM_CM   0x04U /* CredentialManagement */
#define PK_PIN_PERM_BE   0x08U /* BioEnrollment */
#define PK_PIN_PERM_LBW  0x10U /* LargeBlobWrite */
#define PK_PIN_PERM_ACFG 0x20U /* AuthenticatorConfig */
#define PK_PIN_PERM_DEFAULT (PK_PIN_PERM_MC | PK_PIN_PERM_GA)

typedef struct {
    const pk_platform_t *platform;
    pk_crypto_ctx_t     *crypto;
    pk_storage_ctx_t    *storage;
    /* Ephemeral 32-byte pinUvAuthToken generated on boot and rotated as required */
    uint8_t              pin_token[PK_PIN_TOKEN_LEN];
    bool                 token_active;
    uint64_t             token_issued_ms;
    uint8_t              token_permissions;
    bool                 token_has_rp_id;
    uint8_t              token_rp_id_hash[32];
    /* Per-boot retry counter (blocks PIN auth until power cycle after 3 failures) */
    uint8_t              boot_retries_remaining;
} pk_pin_ctx_t;

/* Initialize PIN subsystem, generate ephemeral pinUvAuthToken, set boot retries */
pk_err_t pk_pin_init(
    pk_pin_ctx_t *pin,
    const pk_platform_t *platform,
    pk_crypto_ctx_t *crypto,
    pk_storage_ctx_t *storage
);

/* Reset ephemeral PIN state (called on factory reset) */
pk_err_t pk_pin_reset(pk_pin_ctx_t *pin);

/* Validate UTF-8 PIN policy per CTAP2 §6.5.1:
 *   - Minimum 4 UTF-8 codepoints (and >= 4 bytes)
 *   - Maximum 63 bytes
 *   - No NUL bytes inside the PIN length
 */
bool pk_pin_validate_policy(const uint8_t *pin_utf8, size_t pin_len);

/* Process CTAP2 authenticatorClientPIN (0x06) CBOR request payload and encode
 * the CBOR response payload (excluding the 1-byte status prefix).
 * Returns CTAP2_OK (0x00) or an official CTAP2_ERR_* status byte.
 */
uint8_t pk_pin_handle_command(
    pk_pin_ctx_t *pin,
    const uint8_t *cbor_req,
    size_t cbor_req_len,
    uint8_t *cbor_resp,
    size_t max_resp_len,
    size_t *out_resp_len
);

/* Verify `pinUvAuthParam` (LEFT(HMAC-SHA-256(pinToken, data), 16)) for
 * MakeCredential, GetAssertion, or CredentialManagement requests.
 * Also checks token expiration, `required_perm` bitmask, and optional `rp_id_hash` binding.
 * Returns CTAP2_OK (0x00) on success, or CTAP2_ERR_PIN_AUTH_INVALID / CTAP2_ERR_PIN_TOKEN_EXPIRED.
 */
uint8_t pk_pin_verify_auth_param(
    pk_pin_ctx_t *pin,
    uint8_t pin_protocol,
    const uint8_t *data,
    size_t data_len,
    const uint8_t *pin_auth,
    size_t pin_auth_len,
    uint8_t required_perm,
    const uint8_t *rp_id_hash_opt
);

/* Returns true if a PIN is currently configured in persistent storage */
bool pk_pin_is_set(const pk_pin_ctx_t *pin);

/* Returns remaining persistent PIN retries */
uint8_t pk_pin_get_retries(const pk_pin_ctx_t *pin);

/* Returns true if PIN authentication is blocked for the current boot session */
bool pk_pin_is_boot_blocked(const pk_pin_ctx_t *pin);

#endif /* PICO_PASSKEY_PIN_H */
