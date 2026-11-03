#ifndef PICO_PASSKEY_STORAGE_H
#define PICO_PASSKEY_STORAGE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "passkey/config.h"
#include "passkey/crypto.h"
#include "passkey/platform.h"
#include "passkey/status.h"

#define PK_STORAGE_STATE_MAGIC   0x32534B50UL /* "PKS2" */
#define PK_STORAGE_CRED_MAGIC    0x31434B50UL /* "PKC1" */
#define PK_STORAGE_CNT_MAGIC     0x314E4B50UL /* "PKN1" */
#define PK_STORAGE_VERSION       1U

#define PK_CRED_SLOT_EMPTY       0xFFU
#define PK_CRED_SLOT_COMMITTING  0xFEU
#define PK_CRED_SLOT_ACTIVE      0xFCU
#define PK_CRED_SLOT_TOMBSTONE   0x00U

/* Device persistent state stored in A/B journaled sectors 0 & 1 */
typedef struct {
    uint8_t master_secret[32];    /* Root secret for deterministic key derivation */
    uint8_t cred_mac_key[32];     /* HMAC key for sealing non-resident credential IDs */
    uint8_t attestation_seed[32]; /* Seed for batch attestation keypair */
    bool    pin_set;              /* True if user has configured a PIN */
    uint8_t pin_retries;          /* Remaining persistent PIN attempts (max 8) */
    uint8_t pin_salt[16];         /* Salt for PIN hash protection */
    uint8_t pin_hash_Verifier[32];/* HMAC-SHA-256(pin_salt, LEFT(SHA-256(PIN), 16)) */
    uint8_t pin_raw_hash16[16];   /* Masked LEFT(SHA-256(PIN), 16) for clientPin verification */
    uint32_t base_sign_counter;   /* Base counter snapshotted at last state commit */
} pk_device_state_t;

/* Resident (discoverable) credential record */
typedef struct {
    bool     active;
    uint16_t slot_index;
    uint32_t write_seq;           /* Monotonic creation sequence (for newest-first ordering) */
    uint32_t erase_count;         /* Per-sector erase wear counter */
    uint32_t use_count;           /* Credential sign counter snapshot */
    uint8_t  cred_Provide_up_uv_flags;
    uint8_t  cred_id[PK_CRED_ID_RESIDENT_LEN];
    uint8_t  cred_random[32];
    uint8_t  priv_key[PK_P256_PRIVKEY_LEN];
    pk_p256_pubkey_t pub_key;
    uint8_t  rp_id_hash[32];
    char     rp_id[PK_RP_ID_MAX_LEN];
    uint8_t  user_id[PK_USER_ID_MAX_LEN];
    uint8_t  user_id_len;
    char     user_name[PK_USER_NAME_MAX_LEN];
    char     user_display_name[PK_USER_DISPLAY_MAX_LEN];
    bool     hmac_secret_enabled;
} pk_resident_cred_t;

typedef struct {
    const pk_platform_t *platform;
    pk_crypto_ctx_t     *crypto;
    bool                 initialized;
    pk_device_state_t    state;
    uint32_t             state_generation;
    uint8_t              active_state_sector;
    uint32_t             sign_counter;
    uint8_t              active_counter_sector;
    uint16_t             counter_slot_idx;
    uint32_t             next_cred_seq;
    uint32_t             sector_erase_counts[PK_STORAGE_CRED_SECTOR_COUNT];
} pk_storage_ctx_t;

/* Initialize storage subsystem: mounts or formats flash, recovers incomplete
 * writes, loads highest valid A/B state generation, and reconstructs the
 * monotonic signature counter from the append-only counter log.
 */
pk_err_t pk_storage_init(
    pk_storage_ctx_t *storage,
    const pk_platform_t *platform,
    pk_crypto_ctx_t *crypto
);

/* Perform a factory reset (CTAP2 authenticatorReset): regenerates all device
 * root secrets, clears PIN state, resets signature counter, and erases all
 * resident credentials.
 */
pk_err_t pk_storage_factory_reset(pk_storage_ctx_t *storage);

/* Persist updated device state (e.g., PIN set/change/retry decrement) via
 * atomic A/B sector journaling with CRC32 verification.
 */
pk_err_t pk_storage_save_state(pk_storage_ctx_t *storage);

/* Increment and persist the global monotonic signature counter using the
 * append-only flash page log (avoids erasing a sector on every assertion).
 */
pk_err_t pk_storage_next_sign_counter(pk_storage_ctx_t *storage, uint32_t *out_counter);

/* Store a resident credential. If a resident credential with the same
 * (rp_id_hash, user_id) already exists, it is atomically superseded (new slot
 * committed before old slot is tombstoned). Uses wear-leveling across sectors.
 */
pk_err_t pk_storage_save_credential(
    pk_storage_ctx_t *storage,
    const pk_resident_cred_t *cred
);

/* Find all resident credentials matching `rp_id_hash`, sorted from newest
 * (`write_seq` descending) to oldest.
 */
pk_err_t pk_storage_find_by_rp(
    pk_storage_ctx_t *storage,
    const uint8_t rp_id_hash[32],
    pk_resident_cred_t *out_creds,
    size_t max_creds,
    size_t *out_count
);

/* Find a specific resident credential by `rp_id_hash` and `cred_id` */
pk_err_t pk_storage_find_by_id(
    pk_storage_ctx_t *storage,
    const uint8_t rp_id_hash[32],
    const uint8_t *cred_id,
    size_t cred_id_len,
    pk_resident_cred_t *out_cred
);

/* Delete a resident credential by `cred_id` (marks slot as tombstone) */
pk_err_t pk_storage_delete_by_id(
    pk_storage_ctx_t *storage,
    const uint8_t *cred_id,
    size_t cred_id_len
);

/* Query credential management metadata (total active resident credentials and
 * remaining free capacity, plus distinct RP count).
 */
pk_err_t pk_storage_get_stats(
    pk_storage_ctx_t *storage,
    size_t *out_active_creds,
    size_t *out_free_creds,
    size_t *out_rp_count
);

/* Enumerate distinct Relying Parties that have resident credentials stored */
typedef struct {
    uint8_t rp_id_hash[32];
    char    rp_id[PK_RP_ID_MAX_LEN];
} pk_rp_summary_t;

pk_err_t pk_storage_list_rps(
    pk_storage_ctx_t *storage,
    pk_rp_summary_t *out_rps,
    size_t max_rps,
    size_t *out_count
);

#endif /* PICO_PASSKEY_STORAGE_H */
