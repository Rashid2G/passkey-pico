#include "passkey/pin.h"
#include "passkey/cbor.h"
#include "passkey/crypto.h"
#include "passkey/storage.h"
#include "passkey/config.h"
#include "passkey/status.h"
#include <string.h>

/* Helper to decrypt and validate new PIN padding and policy.
 * Returns true if valid, false if decryption failed or policy violated.
 */
static bool extract_and_validate_new_pin(
    const uint8_t *shared_secret,
    const uint8_t *new_pin_enc,
    uint8_t out_padded_pin[PK_PIN_PADDED_LEN],
    size_t *out_pin_len
) {
    if (pk_crypto_aes256_cbc_decrypt_zero_iv(shared_secret, new_pin_enc, PK_PIN_PADDED_LEN, out_padded_pin) != PK_OK) {
        return false;
    }

    size_t pin_len = 0;
    while (pin_len < PK_PIN_PADDED_LEN && out_padded_pin[pin_len] != 0x00U) {
        pin_len++;
    }

    /* Must have trailing 0x00 padding and fit within length bounds */
    if (pin_len == PK_PIN_PADDED_LEN || pin_len < PK_PIN_MIN_LEN || pin_len > PK_PIN_MAX_LEN) {
        return false;
    }

    /* All bytes after the first 0x00 must be 0x00 */
    for (size_t k = pin_len; k < PK_PIN_PADDED_LEN; ++k) {
        if (out_padded_pin[k] != 0x00U) {
            return false;
        }
    }

    if (!pk_pin_validate_policy(out_padded_pin, pin_len)) {
        return false;
    }

    *out_pin_len = pin_len;
    return true;
}

/* Helper to decrypt pinHashEnc (16 bytes) and verify against persistent state */
static bool verify_pin_hash_enc(
    pk_pin_ctx_t *pin,
    const uint8_t *shared_secret,
    const uint8_t *pin_hash_enc
) {
    uint8_t decrypted_pin_hash[16];
    if (pk_crypto_aes256_cbc_decrypt_zero_iv(shared_secret, pin_hash_enc, 16, decrypted_pin_hash) != PK_OK) {
        return false;
    }

    uint8_t expected_verifier[PK_SHA256_LEN];
    if (pk_crypto_hmac_sha256(
            pin->storage->state.pin_salt, sizeof(pin->storage->state.pin_salt),
            decrypted_pin_hash, sizeof(decrypted_pin_hash),
            expected_verifier) != PK_OK) {
        pk_crypto_zeroize(decrypted_pin_hash, sizeof(decrypted_pin_hash));
        return false;
    }

    bool match = pk_crypto_consttime_eq(decrypted_pin_hash, pin->storage->state.pin_raw_hash16, 16) &&
                 pk_crypto_consttime_eq(expected_verifier, pin->storage->state.pin_hash_Verifier, 32);

    pk_crypto_zeroize(decrypted_pin_hash, sizeof(decrypted_pin_hash));
    pk_crypto_zeroize(expected_verifier, sizeof(expected_verifier));
    return match;
}

/* Helper to handle PIN authentication mismatch */
static uint8_t handle_pin_auth_mismatch(pk_pin_ctx_t *pin, uint8_t *shared_secret)
{
    pin->crypto->pin_ecdh_valid = false;
    pk_crypto_zeroize(pin->crypto->pin_ecdh_priv, sizeof(pin->crypto->pin_ecdh_priv));
    pin->token_active = false;
    if (shared_secret != NULL) {
        pk_crypto_zeroize(shared_secret, 32);
    }
    if (pin->storage->state.pin_retries == 0) {
        return CTAP2_ERR_PIN_BLOCKED;
    }
    if (pin->boot_retries_remaining == 0) {
        return CTAP2_ERR_PIN_AUTH_BLOCKED;
    }
    return CTAP2_ERR_PIN_INVALID;
}

pk_err_t pk_pin_init(
    pk_pin_ctx_t *pin,
    const pk_platform_t *platform,
    pk_crypto_ctx_t *crypto,
    pk_storage_ctx_t *storage
) {
    if (pin == NULL || platform == NULL || crypto == NULL || storage == NULL) {
        return PK_ERR_INVALID_ARG;
    }

    pin->platform = platform;
    pin->crypto = crypto;
    pin->storage = storage;
    pin->boot_retries_remaining = PK_PIN_BOOT_RETRIES;
    pin->token_active = false;
    pin->token_issued_ms = 0;
    pin->token_permissions = 0;
    pin->token_has_rp_id = false;
    memset(pin->token_rp_id_hash, 0, sizeof(pin->token_rp_id_hash));

    pk_err_t err = pk_crypto_random(crypto, pin->pin_token, sizeof(pin->pin_token));
    if (err != PK_OK) {
        return err;
    }

    return PK_OK;
}

pk_err_t pk_pin_reset(pk_pin_ctx_t *pin)
{
    if (pin == NULL || pin->crypto == NULL) {
        return PK_ERR_INVALID_ARG;
    }

    pin->token_active = false;
    pin->token_issued_ms = 0;
    pin->token_permissions = 0;
    pin->token_has_rp_id = false;
    memset(pin->token_rp_id_hash, 0, sizeof(pin->token_rp_id_hash));
    pin->boot_retries_remaining = PK_PIN_BOOT_RETRIES;

    pk_err_t err = pk_crypto_random(pin->crypto, pin->pin_token, sizeof(pin->pin_token));
    if (err != PK_OK) {
        return err;
    }

    return pk_crypto_regenerate_pin_keyagreement(pin->crypto);
}

bool pk_pin_validate_policy(const uint8_t *pin_utf8, size_t pin_len)
{
    if (pin_utf8 == NULL || pin_len < PK_PIN_MIN_LEN || pin_len > PK_PIN_MAX_LEN) {
        return false;
    }

    /* Check for embedded NUL bytes */
    for (size_t k = 0; k < pin_len; ++k) {
        if (pin_utf8[k] == 0x00U) {
            return false;
        }
    }

    size_t codepoints = 0;
    size_t i = 0;

    while (i < pin_len) {
        uint8_t b0 = pin_utf8[i];

        if (b0 <= 0x7FU) {
            /* 1-byte ASCII (0x01..0x7F) */
            codepoints++;
            i++;
        } else if ((b0 & 0xE0U) == 0xC0U) {
            /* 2-byte sequence: 110xxxxx 10xxxxxx */
            if (b0 < 0xC2U || (i + 1) >= pin_len) {
                return false;
            }
            uint8_t b1 = pin_utf8[i + 1];
            if ((b1 & 0xC0U) != 0x80U) {
                return false;
            }
            codepoints++;
            i += 2;
        } else if ((b0 & 0xF0U) == 0xE0U) {
            /* 3-byte sequence: 1110xxxx 10xxxxxx 10xxxxxx */
            if ((i + 2) >= pin_len) {
                return false;
            }
            uint8_t b1 = pin_utf8[i + 1];
            uint8_t b2 = pin_utf8[i + 2];
            if ((b1 & 0xC0U) != 0x80U || (b2 & 0xC0U) != 0x80U) {
                return false;
            }
            /* Overlong encoding check for 0xE0 */
            if (b0 == 0xE0U && b1 < 0xA0U) {
                return false;
            }
            /* UTF-16 surrogate halves (0xD800..0xDFFF) are invalid */
            if (b0 == 0xEDU && b1 > 0x9FU) {
                return false;
            }
            codepoints++;
            i += 3;
        } else if ((b0 & 0xF8U) == 0xF0U) {
            /* 4-byte sequence: 11110xxx 10xxxxxx 10xxxxxx 10xxxxxx */
            if (b0 > 0xF4U || (i + 3) >= pin_len) {
                return false;
            }
            uint8_t b1 = pin_utf8[i + 1];
            uint8_t b2 = pin_utf8[i + 2];
            uint8_t b3 = pin_utf8[i + 3];
            if ((b1 & 0xC0U) != 0x80U || (b2 & 0xC0U) != 0x80U || (b3 & 0xC0U) != 0x80U) {
                return false;
            }
            /* Overlong encoding check for 0xF0 */
            if (b0 == 0xF0U && b1 < 0x90U) {
                return false;
            }
            /* Codepoint limit check (U+10FFFF) for 0xF4 */
            if (b0 == 0xF4U && b1 > 0x8FU) {
                return false;
            }
            codepoints++;
            i += 4;
        } else {
            /* Invalid leading byte or naked continuation byte */
            return false;
        }
    }

    return codepoints >= PK_PIN_MIN_LEN;
}

uint8_t pk_pin_handle_command(
    pk_pin_ctx_t *pin,
    const uint8_t *cbor_req,
    size_t cbor_req_len,
    uint8_t *cbor_resp,
    size_t max_resp_len,
    size_t *out_resp_len
) {
    if (pin == NULL || cbor_resp == NULL || out_resp_len == NULL) {
        return CTAP1_ERR_INVALID_PARAMETER;
    }
    *out_resp_len = 0;

    if (pin->platform == NULL || pin->crypto == NULL || pin->storage == NULL) {
        return CTAP2_ERR_PROCESSING;
    }

    if (cbor_req == NULL || cbor_req_len == 0) {
        return CTAP2_ERR_INVALID_CBOR;
    }

    pk_cbor_reader_t r;
    pk_cbor_reader_init(&r, cbor_req, cbor_req_len);

    uint8_t major = 0;
    if (pk_cbor_peek_major(&r, &major) != PK_OK) {
        return CTAP2_ERR_INVALID_CBOR;
    }
    if (major != PK_CBOR_MAJOR_MAP) {
        return CTAP2_ERR_CBOR_UNEXPECTED_TYPE;
    }

    size_t map_count = 0;
    if (pk_cbor_decode_map_header(&r, &map_count) != PK_OK) {
        return CTAP2_ERR_INVALID_CBOR;
    }

    uint64_t pin_protocol = 0;
    bool has_pin_protocol = false;
    uint64_t subcmd = 0;
    bool has_subcmd = false;
    pk_p256_pubkey_t peer_key;
    memset(&peer_key, 0, sizeof(peer_key));
    bool has_key_agreement = false;
    const uint8_t *pin_auth = NULL;
    size_t pin_auth_len = 0;
    const uint8_t *new_pin_enc = NULL;
    size_t new_pin_enc_len = 0;
    const uint8_t *pin_hash_enc = NULL;
    size_t pin_hash_enc_len = 0;
    uint64_t permissions = 0;
    bool has_permissions = false;
    const char *rp_id = NULL;
    size_t rp_id_len = 0;

    for (size_t i = 0; i < map_count; ++i) {
        uint64_t key = 0;
        if (pk_cbor_decode_uint(&r, &key) != PK_OK) {
            return CTAP2_ERR_INVALID_CBOR;
        }
        switch (key) {
            case 0x01:
                if (pk_cbor_decode_uint(&r, &pin_protocol) != PK_OK) {
                    return CTAP2_ERR_INVALID_CBOR;
                }
                has_pin_protocol = true;
                break;
            case 0x02:
                if (pk_cbor_decode_uint(&r, &subcmd) != PK_OK) {
                    return CTAP2_ERR_INVALID_CBOR;
                }
                has_subcmd = true;
                break;
            case 0x03:
                if (pk_cbor_decode_cose_p256_pubkey(&r, &peer_key) != PK_OK) {
                    return CTAP2_ERR_INVALID_CBOR;
                }
                has_key_agreement = true;
                break;
            case 0x04:
                if (pk_cbor_decode_bstr(&r, &pin_auth, &pin_auth_len) != PK_OK) {
                    return CTAP2_ERR_INVALID_CBOR;
                }
                break;
            case 0x05:
                if (pk_cbor_decode_bstr(&r, &new_pin_enc, &new_pin_enc_len) != PK_OK) {
                    return CTAP2_ERR_INVALID_CBOR;
                }
                break;
            case 0x06:
                if (pk_cbor_decode_bstr(&r, &pin_hash_enc, &pin_hash_enc_len) != PK_OK) {
                    return CTAP2_ERR_INVALID_CBOR;
                }
                break;
            case 0x09:
                if (pk_cbor_decode_uint(&r, &permissions) != PK_OK) {
                    return CTAP2_ERR_INVALID_CBOR;
                }
                has_permissions = true;
                break;
            case 0x0A:
                if (pk_cbor_decode_tstr(&r, &rp_id, &rp_id_len) != PK_OK) {
                    return CTAP2_ERR_INVALID_CBOR;
                }
                break;
            default:
                if (pk_cbor_skip_item(&r) != PK_OK) {
                    return CTAP2_ERR_INVALID_CBOR;
                }
                break;
        }
    }

    if (!has_subcmd) {
        return CTAP2_ERR_MISSING_PARAMETER;
    }

    if (has_pin_protocol && pin_protocol != 1) {
        return CTAP1_ERR_INVALID_PARAMETER;
    }

    if (subcmd != PK_PIN_SUBCMD_GET_RETRIES && subcmd != PK_PIN_SUBCMD_GET_UV_RETRIES) {
        if (!has_pin_protocol) {
            return CTAP2_ERR_MISSING_PARAMETER;
        }
    }

    switch (subcmd) {
        case PK_PIN_SUBCMD_GET_RETRIES: {
            uint8_t retries = pin->storage->state.pin_retries;
            bool power_cycle_state = (pin->boot_retries_remaining == 0 && retries > 0);

            pk_cbor_writer_t w;
            pk_cbor_writer_init(&w, cbor_resp, max_resp_len);

            if (power_cycle_state) {
                if (pk_cbor_encode_map_header(&w, 2) != PK_OK ||
                    pk_cbor_encode_uint(&w, 3) != PK_OK ||
                    pk_cbor_encode_uint(&w, retries) != PK_OK ||
                    pk_cbor_encode_uint(&w, 4) != PK_OK ||
                    pk_cbor_encode_bool(&w, true) != PK_OK) {
                    return CTAP2_ERR_PROCESSING;
                }
            } else {
                if (pk_cbor_encode_map_header(&w, 1) != PK_OK ||
                    pk_cbor_encode_uint(&w, 3) != PK_OK ||
                    pk_cbor_encode_uint(&w, retries) != PK_OK) {
                    return CTAP2_ERR_PROCESSING;
                }
            }

            *out_resp_len = w.offset;
            return CTAP2_OK;
        }

        case PK_PIN_SUBCMD_GET_UV_RETRIES: {
            pk_cbor_writer_t w;
            pk_cbor_writer_init(&w, cbor_resp, max_resp_len);
            if (pk_cbor_encode_map_header(&w, 1) != PK_OK ||
                pk_cbor_encode_uint(&w, 5) != PK_OK ||
                pk_cbor_encode_uint(&w, 0) != PK_OK) {
                return CTAP2_ERR_PROCESSING;
            }
            *out_resp_len = w.offset;
            return CTAP2_OK;
        }

        case PK_PIN_SUBCMD_GET_KEY_AGREEMENT: {
            if (!pin->crypto->pin_ecdh_valid) {
                if (pk_crypto_regenerate_pin_keyagreement(pin->crypto) != PK_OK) {
                    return CTAP2_ERR_PROCESSING;
                }
            }

            pk_cbor_writer_t w;
            pk_cbor_writer_init(&w, cbor_resp, max_resp_len);
            if (pk_cbor_encode_map_header(&w, 1) != PK_OK ||
                pk_cbor_encode_uint(&w, 1) != PK_OK ||
                pk_cbor_encode_cose_p256_pubkey(&w, &pin->crypto->pin_ecdh_pub, true) != PK_OK) {
                return CTAP2_ERR_PROCESSING;
            }
            *out_resp_len = w.offset;
            return CTAP2_OK;
        }

        case PK_PIN_SUBCMD_SET_PIN: {
            if (!has_key_agreement || new_pin_enc == NULL || pin_auth == NULL) {
                return CTAP2_ERR_MISSING_PARAMETER;
            }
            if (new_pin_enc_len != PK_PIN_PADDED_LEN || pin_auth_len != 16) {
                return CTAP1_ERR_INVALID_PARAMETER;
            }
            if (pin->storage->state.pin_set) {
                return CTAP2_ERR_NOT_ALLOWED;
            }

            if (!pin->crypto->pin_ecdh_valid) {
                if (pk_crypto_regenerate_pin_keyagreement(pin->crypto) != PK_OK) {
                    return CTAP2_ERR_PROCESSING;
                }
            }

            uint8_t shared_secret[32];
            if (pk_crypto_p256_ecdh_shared_secret_sha256(
                    pin->crypto, pin->crypto->pin_ecdh_priv, &peer_key, shared_secret) != PK_OK) {
                pin->crypto->pin_ecdh_valid = false;
                pk_crypto_zeroize(pin->crypto->pin_ecdh_priv, sizeof(pin->crypto->pin_ecdh_priv));
                return CTAP2_ERR_PIN_AUTH_INVALID;
            }

            uint8_t hmac[PK_SHA256_LEN];
            if (pk_crypto_hmac_sha256(shared_secret, sizeof(shared_secret), new_pin_enc, new_pin_enc_len, hmac) != PK_OK ||
                !pk_crypto_consttime_eq(hmac, pin_auth, 16)) {
                pk_crypto_zeroize(hmac, sizeof(hmac));
                pin->crypto->pin_ecdh_valid = false;
                pk_crypto_zeroize(pin->crypto->pin_ecdh_priv, sizeof(pin->crypto->pin_ecdh_priv));
                pk_crypto_zeroize(shared_secret, sizeof(shared_secret));
                return CTAP2_ERR_PIN_AUTH_INVALID;
            }
            pk_crypto_zeroize(hmac, sizeof(hmac));

            uint8_t padded_pin[PK_PIN_PADDED_LEN];
            size_t pin_len = 0;
            if (!extract_and_validate_new_pin(shared_secret, new_pin_enc, padded_pin, &pin_len)) {
                pk_crypto_zeroize(padded_pin, sizeof(padded_pin));
                pk_crypto_zeroize(shared_secret, sizeof(shared_secret));
                return CTAP2_ERR_PIN_POLICY_VIOLATION;
            }
            pk_crypto_zeroize(shared_secret, sizeof(shared_secret));

            uint8_t full_hash[PK_SHA256_LEN];
            if (pk_crypto_sha256(padded_pin, pin_len, full_hash) != PK_OK) {
                pk_crypto_zeroize(padded_pin, sizeof(padded_pin));
                return CTAP2_ERR_PROCESSING;
            }
            pk_crypto_zeroize(padded_pin, sizeof(padded_pin));

            memcpy(pin->storage->state.pin_raw_hash16, full_hash, 16);
            pk_crypto_zeroize(full_hash, sizeof(full_hash));

            if (pk_crypto_random(pin->crypto, pin->storage->state.pin_salt, sizeof(pin->storage->state.pin_salt)) != PK_OK) {
                return CTAP2_ERR_PROCESSING;
            }

            if (pk_crypto_hmac_sha256(
                    pin->storage->state.pin_salt, sizeof(pin->storage->state.pin_salt),
                    pin->storage->state.pin_raw_hash16, sizeof(pin->storage->state.pin_raw_hash16),
                    pin->storage->state.pin_hash_Verifier) != PK_OK) {
                return CTAP2_ERR_PROCESSING;
            }

            pin->storage->state.pin_set = true;
            pin->storage->state.pin_retries = PK_PIN_MAX_RETRIES;
            pin->boot_retries_remaining = PK_PIN_BOOT_RETRIES;

            if (pk_storage_save_state(pin->storage) != PK_OK) {
                return CTAP2_ERR_PROCESSING;
            }

            /* Rotate ECDH keyAgreement keypair after setPIN per CTAP2 §6.5.5.4 */
            pin->crypto->pin_ecdh_valid = false;
            pk_crypto_zeroize(pin->crypto->pin_ecdh_priv, sizeof(pin->crypto->pin_ecdh_priv));

            *out_resp_len = 0;
            return CTAP2_OK;
        }

        case PK_PIN_SUBCMD_CHANGE_PIN: {
            if (!has_key_agreement || new_pin_enc == NULL || pin_hash_enc == NULL || pin_auth == NULL) {
                return CTAP2_ERR_MISSING_PARAMETER;
            }
            if (new_pin_enc_len != PK_PIN_PADDED_LEN || pin_hash_enc_len != 16 || pin_auth_len != 16) {
                return CTAP1_ERR_INVALID_PARAMETER;
            }
            if (!pin->storage->state.pin_set) {
                return CTAP2_ERR_PIN_NOT_SET;
            }
            if (pin->storage->state.pin_retries == 0) {
                return CTAP2_ERR_PIN_BLOCKED;
            }
            if (pin->boot_retries_remaining == 0) {
                return CTAP2_ERR_PIN_AUTH_BLOCKED;
            }

            if (!pin->crypto->pin_ecdh_valid) {
                if (pk_crypto_regenerate_pin_keyagreement(pin->crypto) != PK_OK) {
                    return CTAP2_ERR_PROCESSING;
                }
            }

            uint8_t shared_secret[32];
            if (pk_crypto_p256_ecdh_shared_secret_sha256(
                    pin->crypto, pin->crypto->pin_ecdh_priv, &peer_key, shared_secret) != PK_OK) {
                pin->crypto->pin_ecdh_valid = false;
                pk_crypto_zeroize(pin->crypto->pin_ecdh_priv, sizeof(pin->crypto->pin_ecdh_priv));
                return CTAP2_ERR_PIN_AUTH_INVALID;
            }

            uint8_t concat[PK_PIN_PADDED_LEN + 16];
            memcpy(concat, new_pin_enc, PK_PIN_PADDED_LEN);
            memcpy(concat + PK_PIN_PADDED_LEN, pin_hash_enc, 16);
            uint8_t hmac[PK_SHA256_LEN];
            pk_err_t hmac_err = pk_crypto_hmac_sha256(shared_secret, sizeof(shared_secret), concat, sizeof(concat), hmac);
            pk_crypto_zeroize(concat, sizeof(concat));

            if (hmac_err != PK_OK || !pk_crypto_consttime_eq(hmac, pin_auth, 16)) {
                pk_crypto_zeroize(hmac, sizeof(hmac));
                pin->crypto->pin_ecdh_valid = false;
                pk_crypto_zeroize(pin->crypto->pin_ecdh_priv, sizeof(pin->crypto->pin_ecdh_priv));
                pk_crypto_zeroize(shared_secret, sizeof(shared_secret));
                return CTAP2_ERR_PIN_AUTH_INVALID;
            }
            pk_crypto_zeroize(hmac, sizeof(hmac));

            /* Anti-bruteforce: Decrement retry counters and save BEFORE checking old PIN hash */
            if (pin->storage->state.pin_retries > 0) {
                pin->storage->state.pin_retries--;
            }
            if (pin->boot_retries_remaining > 0) {
                pin->boot_retries_remaining--;
            }
            if (pk_storage_save_state(pin->storage) != PK_OK) {
                pk_crypto_zeroize(shared_secret, sizeof(shared_secret));
                return CTAP2_ERR_PROCESSING;
            }

            if (!verify_pin_hash_enc(pin, shared_secret, pin_hash_enc)) {
                return handle_pin_auth_mismatch(pin, shared_secret);
            }

            /* Old PIN verified successfully! Decrypt and validate new PIN */
            uint8_t padded_new_pin[PK_PIN_PADDED_LEN];
            size_t new_pin_len = 0;
            if (!extract_and_validate_new_pin(shared_secret, new_pin_enc, padded_new_pin, &new_pin_len)) {
                pk_crypto_zeroize(padded_new_pin, sizeof(padded_new_pin));
                pk_crypto_zeroize(shared_secret, sizeof(shared_secret));
                /* Policy failed: restore retries per CTAP2 spec since old PIN was correct */
                pin->storage->state.pin_retries = PK_PIN_MAX_RETRIES;
                pin->boot_retries_remaining = PK_PIN_BOOT_RETRIES;
                pk_storage_save_state(pin->storage);
                return CTAP2_ERR_PIN_POLICY_VIOLATION;
            }
            pk_crypto_zeroize(shared_secret, sizeof(shared_secret));

            uint8_t new_full_hash[PK_SHA256_LEN];
            if (pk_crypto_sha256(padded_new_pin, new_pin_len, new_full_hash) != PK_OK) {
                pk_crypto_zeroize(padded_new_pin, sizeof(padded_new_pin));
                return CTAP2_ERR_PROCESSING;
            }
            pk_crypto_zeroize(padded_new_pin, sizeof(padded_new_pin));

            memcpy(pin->storage->state.pin_raw_hash16, new_full_hash, 16);
            pk_crypto_zeroize(new_full_hash, sizeof(new_full_hash));

            if (pk_crypto_random(pin->crypto, pin->storage->state.pin_salt, sizeof(pin->storage->state.pin_salt)) != PK_OK) {
                return CTAP2_ERR_PROCESSING;
            }

            if (pk_crypto_hmac_sha256(
                    pin->storage->state.pin_salt, sizeof(pin->storage->state.pin_salt),
                    pin->storage->state.pin_raw_hash16, sizeof(pin->storage->state.pin_raw_hash16),
                    pin->storage->state.pin_hash_Verifier) != PK_OK) {
                return CTAP2_ERR_PROCESSING;
            }

            pin->storage->state.pin_retries = PK_PIN_MAX_RETRIES;
            pin->boot_retries_remaining = PK_PIN_BOOT_RETRIES;

            /* Rotate pin_token and invalidate active token session */
            pk_crypto_random(pin->crypto, pin->pin_token, sizeof(pin->pin_token));
            pin->token_active = false;
            pin->token_issued_ms = 0;
            pin->token_permissions = 0;
            pin->token_has_rp_id = false;
            memset(pin->token_rp_id_hash, 0, sizeof(pin->token_rp_id_hash));

            if (pk_storage_save_state(pin->storage) != PK_OK) {
                return CTAP2_ERR_PROCESSING;
            }

            /* Rotate ECDH keyAgreement keypair after changePIN per CTAP2 §6.5.5.5 */
            pin->crypto->pin_ecdh_valid = false;
            pk_crypto_zeroize(pin->crypto->pin_ecdh_priv, sizeof(pin->crypto->pin_ecdh_priv));

            *out_resp_len = 0;
            return CTAP2_OK;
        }

        case PK_PIN_SUBCMD_GET_PIN_TOKEN:
        case PK_PIN_SUBCMD_GET_PIN_UV_TOKEN_USING_PIN: {
            if (pin_auth != NULL || pin_auth_len > 0) {
                return CTAP1_ERR_INVALID_PARAMETER;
            }
            if (!has_key_agreement || pin_hash_enc == NULL) {
                return CTAP2_ERR_MISSING_PARAMETER;
            }
            if (pin_hash_enc_len != 16) {
                return CTAP1_ERR_INVALID_PARAMETER;
            }
            if (subcmd == PK_PIN_SUBCMD_GET_PIN_UV_TOKEN_USING_PIN) {
                if (!has_permissions) {
                    return CTAP2_ERR_MISSING_PARAMETER;
                }
                /* Validate permissions against supported bits: MC, GA, CM */
                if (permissions == 0 || (permissions & ~(PK_PIN_PERM_MC | PK_PIN_PERM_GA | PK_PIN_PERM_CM)) != 0) {
                    return CTAP2_ERR_UNAUTHORIZED_PERMISSION;
                }
            }

            if (!pin->storage->state.pin_set) {
                return CTAP2_ERR_PIN_NOT_SET;
            }
            if (pin->storage->state.pin_retries == 0) {
                return CTAP2_ERR_PIN_BLOCKED;
            }
            if (pin->boot_retries_remaining == 0) {
                return CTAP2_ERR_PIN_AUTH_BLOCKED;
            }

            if (!pin->crypto->pin_ecdh_valid) {
                if (pk_crypto_regenerate_pin_keyagreement(pin->crypto) != PK_OK) {
                    return CTAP2_ERR_PROCESSING;
                }
            }

            uint8_t shared_secret[32];
            if (pk_crypto_p256_ecdh_shared_secret_sha256(
                    pin->crypto, pin->crypto->pin_ecdh_priv, &peer_key, shared_secret) != PK_OK) {
                pin->crypto->pin_ecdh_valid = false;
                pk_crypto_zeroize(pin->crypto->pin_ecdh_priv, sizeof(pin->crypto->pin_ecdh_priv));
                return CTAP2_ERR_PIN_AUTH_INVALID;
            }

            /* Anti-bruteforce: Decrement retry counters and commit to flash BEFORE verifying PIN hash */
            if (pin->storage->state.pin_retries > 0) {
                pin->storage->state.pin_retries--;
            }
            if (pin->boot_retries_remaining > 0) {
                pin->boot_retries_remaining--;
            }
            if (pk_storage_save_state(pin->storage) != PK_OK) {
                pk_crypto_zeroize(shared_secret, sizeof(shared_secret));
                return CTAP2_ERR_PROCESSING;
            }

            if (!verify_pin_hash_enc(pin, shared_secret, pin_hash_enc)) {
                return handle_pin_auth_mismatch(pin, shared_secret);
            }

            /* Success: Restore full retries */
            pin->boot_retries_remaining = PK_PIN_BOOT_RETRIES;
            if (pin->storage->state.pin_retries != PK_PIN_MAX_RETRIES) {
                pin->storage->state.pin_retries = PK_PIN_MAX_RETRIES;
                if (pk_storage_save_state(pin->storage) != PK_OK) {
                    pk_crypto_zeroize(shared_secret, sizeof(shared_secret));
                    return CTAP2_ERR_PROCESSING;
                }
            }

            /* Generate fresh ephemeral pinToken and activate token session */
            if (pk_crypto_random(pin->crypto, pin->pin_token, sizeof(pin->pin_token)) != PK_OK) {
                pk_crypto_zeroize(shared_secret, sizeof(shared_secret));
                return CTAP2_ERR_PROCESSING;
            }
            pin->token_active = true;
            pin->token_issued_ms = pin->platform->now_ms(pin->platform->ctx);

            if (subcmd == PK_PIN_SUBCMD_GET_PIN_UV_TOKEN_USING_PIN) {
                pin->token_permissions = (uint8_t)permissions;
                if (rp_id != NULL && rp_id_len > 0) {
                    if (pk_crypto_sha256((const uint8_t *)rp_id, rp_id_len, pin->token_rp_id_hash) != PK_OK) {
                        pk_crypto_zeroize(shared_secret, sizeof(shared_secret));
                        return CTAP2_ERR_PROCESSING;
                    }
                    pin->token_has_rp_id = true;
                } else {
                    pin->token_has_rp_id = false;
                    memset(pin->token_rp_id_hash, 0, sizeof(pin->token_rp_id_hash));
                }
            } else {
                /* Legacy getPinToken grants MC | GA | CM permissions */
                pin->token_permissions = PK_PIN_PERM_MC | PK_PIN_PERM_GA | PK_PIN_PERM_CM;
                pin->token_has_rp_id = false;
                memset(pin->token_rp_id_hash, 0, sizeof(pin->token_rp_id_hash));
            }

            uint8_t encrypted_token[32];
            if (pk_crypto_aes256_cbc_encrypt_zero_iv(
                    shared_secret, pin->pin_token, sizeof(pin->pin_token), encrypted_token) != PK_OK) {
                pk_crypto_zeroize(shared_secret, sizeof(shared_secret));
                return CTAP2_ERR_PROCESSING;
            }
            pk_crypto_zeroize(shared_secret, sizeof(shared_secret));

            /* Keep pin_ecdh valid so client can reuse key agreement for hmac-secret in the same ceremony */

            pk_cbor_writer_t w;
            pk_cbor_writer_init(&w, cbor_resp, max_resp_len);
            if (pk_cbor_encode_map_header(&w, 1) != PK_OK ||
                pk_cbor_encode_uint(&w, 2) != PK_OK ||
                pk_cbor_encode_bstr(&w, encrypted_token, sizeof(encrypted_token)) != PK_OK) {
                pk_crypto_zeroize(encrypted_token, sizeof(encrypted_token));
                return CTAP2_ERR_PROCESSING;
            }
            pk_crypto_zeroize(encrypted_token, sizeof(encrypted_token));

            *out_resp_len = w.offset;
            return CTAP2_OK;
        }

        default:
            return CTAP2_ERR_INVALID_SUBCOMMAND;
    }
}

uint8_t pk_pin_verify_auth_param(
    pk_pin_ctx_t *pin,
    uint8_t pin_protocol,
    const uint8_t *data,
    size_t data_len,
    const uint8_t *pin_auth,
    size_t pin_auth_len,
    uint8_t required_perm,
    const uint8_t *rp_id_hash_opt
) {
    if (pin == NULL || pin->platform == NULL) {
        return CTAP1_ERR_INVALID_PARAMETER;
    }
    if (data_len > 0 && data == NULL) {
        return CTAP1_ERR_INVALID_PARAMETER;
    }
    if (pin_protocol != 1) {
        return CTAP1_ERR_INVALID_PARAMETER;
    }
    if (pin_auth == NULL || pin_auth_len != 16) {
        return CTAP1_ERR_INVALID_PARAMETER;
    }
    if (!pin->token_active) {
        return CTAP2_ERR_PIN_AUTH_INVALID;
    }

    uint64_t now = pin->platform->now_ms(pin->platform->ctx);
    if (now < pin->token_issued_ms || (now - pin->token_issued_ms) > PK_PIN_TOKEN_TIMEOUT_MS) {
        pin->token_active = false;
        return CTAP2_ERR_PIN_TOKEN_EXPIRED;
    }

    uint8_t mac[PK_SHA256_LEN];
    if (pk_crypto_hmac_sha256(pin->pin_token, sizeof(pin->pin_token), data, data_len, mac) != PK_OK) {
        return CTAP2_ERR_PROCESSING;
    }
    bool mac_ok = pk_crypto_consttime_eq(mac, pin_auth, 16);
    pk_crypto_zeroize(mac, sizeof(mac));
    if (!mac_ok) {
        return CTAP2_ERR_PIN_AUTH_INVALID;
    }

    if ((pin->token_permissions & required_perm) != required_perm) {
        if ((required_perm & PK_PIN_PERM_CM) != 0 && (pin->token_permissions & PK_PIN_PERM_CM) == 0) {
            return CTAP2_ERR_UNAUTHORIZED_PERMISSION;
        }
        return CTAP2_ERR_PIN_AUTH_INVALID;
    }

    if (rp_id_hash_opt != NULL && pin->token_has_rp_id) {
        if (!pk_crypto_consttime_eq(pin->token_rp_id_hash, rp_id_hash_opt, 32)) {
            return CTAP2_ERR_PIN_AUTH_INVALID;
        }
    }

    return CTAP2_OK;
}

bool pk_pin_is_set(const pk_pin_ctx_t *pin)
{
    if (pin == NULL || pin->storage == NULL) {
        return false;
    }
    return pin->storage->state.pin_set;
}

uint8_t pk_pin_get_retries(const pk_pin_ctx_t *pin)
{
    if (pin == NULL || pin->storage == NULL) {
        return 0;
    }
    return pin->storage->state.pin_retries;
}

bool pk_pin_is_boot_blocked(const pk_pin_ctx_t *pin)
{
    if (pin == NULL) {
        return false;
    }
    return pin->boot_retries_remaining == 0;
}
