#ifndef PICO_PASSKEY_CTAP2_H
#define PICO_PASSKEY_CTAP2_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "passkey/config.h"
#include "passkey/crypto.h"
#include "passkey/pin.h"
#include "passkey/platform.h"
#include "passkey/status.h"
#include "passkey/storage.h"

/* CTAP2 Authenticator Command Bytes (§6) */
#define CTAP2_CMD_MAKE_CREDENTIAL       0x01U
#define CTAP2_CMD_GET_ASSERTION         0x02U
#define CTAP2_CMD_GET_INFO              0x04U
#define CTAP2_CMD_CLIENT_PIN            0x06U
#define CTAP2_CMD_RESET                 0x07U
#define CTAP2_CMD_GET_NEXT_ASSERTION    0x08U
#define CTAP2_CMD_CREDENTIAL_MGMT       0x0AU
#define CTAP2_CMD_SELECTION             0x0BU
#define CTAP2_CMD_CREDENTIAL_MGMT_PRE   0x41U

/* Authenticator Data Flags (§6.1) */
#define CTAP2_AUTH_DATA_FLAG_UP         0x01U /* Bit 0: User Present */
#define CTAP2_AUTH_DATA_FLAG_UV         0x04U /* Bit 2: User Verified */
#define CTAP2_AUTH_DATA_FLAG_AT         0x40U /* Bit 6: Attested Credential Data */
#define CTAP2_AUTH_DATA_FLAG_ED         0x80U /* Bit 7: Extension Data Included */

/* Cached multi-assertion session state for authenticatorGetNextAssertion (0x08) */
typedef struct {
    bool               active;
    uint64_t           created_ms;
    uint8_t            rp_id_hash[32];
    uint8_t            client_data_hash[32];
    uint8_t            flags;
    bool               hmac_secret_requested;
    uint8_t            hmac_shared_secret[32];
    uint8_t            hmac_salts[64];
    size_t             hmac_salts_len;
    size_t             total_creds;
    size_t             next_index;
    pk_resident_cred_t creds[8];
} pk_assertion_session_t;

/* Cached enumeration state for authenticatorCredentialManagement (0x0A / 0x41) */
typedef struct {
    bool     rp_enum_active;
    uint64_t rp_enum_created_ms;
    size_t   total_rps;
    size_t   next_rp_index;

    bool     cred_enum_active;
    uint64_t cred_enum_created_ms;
    uint8_t  cred_enum_rp_id_hash[32];
    size_t   total_creds;
    size_t   next_cred_index;
} pk_cred_mgmt_session_t;

typedef struct {
    const pk_platform_t    *platform;
    pk_crypto_ctx_t        *crypto;
    pk_storage_ctx_t       *storage;
    pk_pin_ctx_t           *pin;
    pk_keepalive_cb_t       keepalive_cb;
    void                   *keepalive_ctx;
    pk_assertion_session_t  assertion_session;
    pk_cred_mgmt_session_t  cred_mgmt_session;
} pk_ctap2_ctx_t;

/* Initialize CTAP2 protocol engine */
pk_err_t pk_ctap2_init(
    pk_ctap2_ctx_t *ctap,
    const pk_platform_t *platform,
    pk_crypto_ctx_t *crypto,
    pk_storage_ctx_t *storage,
    pk_pin_ctx_t *pin
);

/* Register optional keepalive callback invoked while awaiting user presence */
void pk_ctap2_set_keepalive_callback(
    pk_ctap2_ctx_t *ctap,
    pk_keepalive_cb_t cb,
    void *user_ctx
);

/* Process a raw CTAP2 CBOR command message (`req[0]` is command byte,
 * `req[1..req_len-1]` is CBOR parameter map).
 * Writes status byte at `resp[0]` and optional CBOR response at `resp[1..]`.
 * Always sets `*out_resp_len >= 1`.
 */
void pk_ctap2_process_message(
    pk_ctap2_ctx_t *ctap,
    const uint8_t *req,
    size_t req_len,
    uint8_t *resp,
    size_t max_resp_len,
    size_t *out_resp_len
);

/* Process a Legacy U2F / CTAP1 raw APDU (for CTAPHID_MSG backward compatibility) */
void pk_ctap1_process_apdu(
    pk_ctap2_ctx_t *ctap,
    const uint8_t *apdu,
    size_t apdu_len,
    uint8_t *resp,
    size_t max_resp_len,
    size_t *out_resp_len
);

#endif /* PICO_PASSKEY_CTAP2_H */
