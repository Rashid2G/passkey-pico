#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "mock_platform.h"
#include "passkey/config.h"
#include "passkey/status.h"
#include "passkey/cbor.h"
#include "passkey/crypto.h"
#include "passkey/storage.h"
#include "passkey/pin.h"
#include "passkey/ctap2.h"

#define TEST_ASSERT(cond) do { \
    if (!(cond)) { \
        fprintf(stderr, "ASSERTION FAILED at %s:%d: %s\n", __FILE__, __LINE__, #cond); \
        exit(1); \
    } \
} while (0)

static pk_mock_platform_state_t mock;
static pk_platform_t platform;
static pk_crypto_ctx_t crypto;
static pk_storage_ctx_t storage;
static pk_pin_ctx_t pin;
static pk_ctap2_ctx_t ctap2;

static void setup_env(void) {
    pk_mock_platform_init(&mock, &platform);
    TEST_ASSERT(pk_crypto_init(&crypto, &platform) == PK_OK);
    TEST_ASSERT(pk_storage_init(&storage, &platform, &crypto) == PK_OK);
    TEST_ASSERT(pk_pin_init(&pin, &platform, &crypto, &storage) == PK_OK);
    TEST_ASSERT(pk_ctap2_init(&ctap2, &platform, &crypto, &storage, &pin) == PK_OK);
}

/* Helper to get current PIN retries */
static uint8_t ctap_get_retries(void) {
    uint8_t req[32];
    req[0] = CTAP2_CMD_CLIENT_PIN;
    pk_cbor_writer_t w;
    pk_cbor_writer_init(&w, req + 1, sizeof(req) - 1);
    pk_cbor_encode_map_header(&w, 2);
    pk_cbor_encode_uint(&w, 1);
    pk_cbor_encode_uint(&w, 1);
    pk_cbor_encode_uint(&w, 2);
    pk_cbor_encode_uint(&w, PK_PIN_SUBCMD_GET_RETRIES);
    size_t req_len = 1 + w.offset;

    uint8_t resp[64];
    size_t resp_len = 0;
    pk_ctap2_process_message(&ctap2, req, req_len, resp, sizeof(resp), &resp_len);
    TEST_ASSERT(resp_len > 1 && resp[0] == CTAP2_OK);

    pk_cbor_reader_t r;
    pk_cbor_reader_init(&r, resp + 1, resp_len - 1);
    size_t map_cnt = 0;
    TEST_ASSERT(pk_cbor_decode_map_header(&r, &map_cnt) == PK_OK);
    uint64_t retries = 0;
    for (size_t i = 0; i < map_cnt; i++) {
        uint64_t k = 0;
        TEST_ASSERT(pk_cbor_decode_uint(&r, &k) == PK_OK);
        if (k == 3) {
            TEST_ASSERT(pk_cbor_decode_uint(&r, &retries) == PK_OK);
        } else {
            TEST_ASSERT(pk_cbor_skip_item(&r) == PK_OK);
        }
    }
    return (uint8_t)retries;
}

/* Helper to get authenticator keyAgreement public key */
static void ctap_get_key_agreement(pk_p256_pubkey_t *out_pub) {
    uint8_t req[32];
    req[0] = CTAP2_CMD_CLIENT_PIN;
    pk_cbor_writer_t w;
    pk_cbor_writer_init(&w, req + 1, sizeof(req) - 1);
    pk_cbor_encode_map_header(&w, 2);
    pk_cbor_encode_uint(&w, 1);
    pk_cbor_encode_uint(&w, 1);
    pk_cbor_encode_uint(&w, 2);
    pk_cbor_encode_uint(&w, PK_PIN_SUBCMD_GET_KEY_AGREEMENT);
    size_t req_len = 1 + w.offset;

    uint8_t resp[256];
    size_t resp_len = 0;
    pk_ctap2_process_message(&ctap2, req, req_len, resp, sizeof(resp), &resp_len);
    TEST_ASSERT(resp_len > 1 && resp[0] == CTAP2_OK);

    pk_cbor_reader_t r;
    pk_cbor_reader_init(&r, resp + 1, resp_len - 1);
    size_t map_cnt = 0;
    TEST_ASSERT(pk_cbor_decode_map_header(&r, &map_cnt) == PK_OK);
    bool found_key = false;
    for (size_t i = 0; i < map_cnt; i++) {
        uint64_t k = 0;
        TEST_ASSERT(pk_cbor_decode_uint(&r, &k) == PK_OK);
        if (k == 1) { // keyAgreement
            TEST_ASSERT(pk_cbor_decode_cose_p256_pubkey(&r, out_pub) == PK_OK);
            found_key = true;
        } else {
            TEST_ASSERT(pk_cbor_skip_item(&r) == PK_OK);
        }
    }
    TEST_ASSERT(found_key);
}

/* Helper to set a new PIN */
static void ctap_set_pin(const char *pin_str) {
    pk_p256_pubkey_t auth_pub;
    ctap_get_key_agreement(&auth_pub);

    uint8_t plat_priv[PK_P256_PRIVKEY_LEN];
    pk_p256_pubkey_t plat_pub;
    TEST_ASSERT(pk_crypto_p256_keygen(&crypto, plat_priv, &plat_pub) == PK_OK);

    uint8_t shared_secret[32];
    TEST_ASSERT(pk_crypto_p256_ecdh_shared_secret_sha256(&crypto, plat_priv, &auth_pub, shared_secret) == PK_OK);

    uint8_t new_pin_padded[64];
    memset(new_pin_padded, 0, 64);
    size_t pin_len = strlen(pin_str);
    memcpy(new_pin_padded, pin_str, pin_len);

    uint8_t new_pin_enc[64];
    TEST_ASSERT(pk_crypto_aes256_cbc_encrypt_zero_iv(shared_secret, new_pin_padded, 64, new_pin_enc) == PK_OK);

    uint8_t hmac[32];
    TEST_ASSERT(pk_crypto_hmac_sha256(shared_secret, 32, new_pin_enc, 64, hmac) == PK_OK);
    uint8_t pin_auth[16];
    memcpy(pin_auth, hmac, 16);

    uint8_t req[256];
    req[0] = CTAP2_CMD_CLIENT_PIN;
    pk_cbor_writer_t w;
    pk_cbor_writer_init(&w, req + 1, sizeof(req) - 1);
    pk_cbor_encode_map_header(&w, 5);
    pk_cbor_encode_uint(&w, 1);
    pk_cbor_encode_uint(&w, 1);
    pk_cbor_encode_uint(&w, 2);
    pk_cbor_encode_uint(&w, PK_PIN_SUBCMD_SET_PIN);
    pk_cbor_encode_uint(&w, 3);
    TEST_ASSERT(pk_cbor_encode_cose_p256_pubkey(&w, &plat_pub, true) == PK_OK);
    pk_cbor_encode_uint(&w, 4);
    pk_cbor_encode_bstr(&w, pin_auth, 16);
    pk_cbor_encode_uint(&w, 5);
    pk_cbor_encode_bstr(&w, new_pin_enc, 64);
    size_t req_len = 1 + w.offset;

    uint8_t resp[64];
    size_t resp_len = 0;
    pk_ctap2_process_message(&ctap2, req, req_len, resp, sizeof(resp), &resp_len);
    TEST_ASSERT(resp_len >= 1 && resp[0] == CTAP2_OK);
}

/* Helper to get PIN token using Subcommand 0x05 */
static uint8_t ctap_get_pin_token(const char *pin_str, uint8_t *out_token_32) {
    pk_p256_pubkey_t auth_pub;
    ctap_get_key_agreement(&auth_pub);

    uint8_t plat_priv[PK_P256_PRIVKEY_LEN];
    pk_p256_pubkey_t plat_pub;
    TEST_ASSERT(pk_crypto_p256_keygen(&crypto, plat_priv, &plat_pub) == PK_OK);

    uint8_t shared_secret[32];
    TEST_ASSERT(pk_crypto_p256_ecdh_shared_secret_sha256(&crypto, plat_priv, &auth_pub, shared_secret) == PK_OK);

    uint8_t full_hash[32];
    TEST_ASSERT(pk_crypto_sha256((const uint8_t *)pin_str, strlen(pin_str), full_hash) == PK_OK);

    uint8_t pin_hash_enc[16];
    TEST_ASSERT(pk_crypto_aes256_cbc_encrypt_zero_iv(shared_secret, full_hash, 16, pin_hash_enc) == PK_OK);

    uint8_t req[256];
    req[0] = CTAP2_CMD_CLIENT_PIN;
    pk_cbor_writer_t w;
    pk_cbor_writer_init(&w, req + 1, sizeof(req) - 1);
    pk_cbor_encode_map_header(&w, 4);
    pk_cbor_encode_uint(&w, 1);
    pk_cbor_encode_uint(&w, 1);
    pk_cbor_encode_uint(&w, 2);
    pk_cbor_encode_uint(&w, PK_PIN_SUBCMD_GET_PIN_TOKEN);
    pk_cbor_encode_uint(&w, 3);
    TEST_ASSERT(pk_cbor_encode_cose_p256_pubkey(&w, &plat_pub, true) == PK_OK);
    pk_cbor_encode_uint(&w, 6);
    pk_cbor_encode_bstr(&w, pin_hash_enc, 16);
    size_t req_len = 1 + w.offset;

    uint8_t resp[256];
    size_t resp_len = 0;
    pk_ctap2_process_message(&ctap2, req, req_len, resp, sizeof(resp), &resp_len);
    if (resp[0] != CTAP2_OK) {
        return resp[0];
    }

    if (out_token_32 != NULL) {
        pk_cbor_reader_t r;
        pk_cbor_reader_init(&r, resp + 1, resp_len - 1);
        size_t map_cnt = 0;
        TEST_ASSERT(pk_cbor_decode_map_header(&r, &map_cnt) == PK_OK);
        bool found_token = false;
        for (size_t i = 0; i < map_cnt; i++) {
            uint64_t k = 0;
            TEST_ASSERT(pk_cbor_decode_uint(&r, &k) == PK_OK);
            if (k == 2) {
                const uint8_t *enc_token = NULL;
                size_t enc_token_len = 0;
                TEST_ASSERT(pk_cbor_decode_bstr(&r, &enc_token, &enc_token_len) == PK_OK);
                TEST_ASSERT(enc_token_len == 32);
                TEST_ASSERT(pk_crypto_aes256_cbc_decrypt_zero_iv(shared_secret, enc_token, 32, out_token_32) == PK_OK);
                found_token = true;
            } else {
                TEST_ASSERT(pk_cbor_skip_item(&r) == PK_OK);
            }
        }
        TEST_ASSERT(found_token);
    }
    return CTAP2_OK;
}

/* Helper to get PIN/UV token using Subcommand 0x09 */
static uint8_t ctap_get_pin_uv_token(const char *pin_str, uint8_t permissions, uint8_t *out_token_32) {
    pk_p256_pubkey_t auth_pub;
    ctap_get_key_agreement(&auth_pub);

    uint8_t plat_priv[PK_P256_PRIVKEY_LEN];
    pk_p256_pubkey_t plat_pub;
    TEST_ASSERT(pk_crypto_p256_keygen(&crypto, plat_priv, &plat_pub) == PK_OK);

    uint8_t shared_secret[32];
    TEST_ASSERT(pk_crypto_p256_ecdh_shared_secret_sha256(&crypto, plat_priv, &auth_pub, shared_secret) == PK_OK);

    uint8_t full_hash[32];
    TEST_ASSERT(pk_crypto_sha256((const uint8_t *)pin_str, strlen(pin_str), full_hash) == PK_OK);

    uint8_t pin_hash_enc[16];
    TEST_ASSERT(pk_crypto_aes256_cbc_encrypt_zero_iv(shared_secret, full_hash, 16, pin_hash_enc) == PK_OK);

    uint8_t req[256];
    req[0] = CTAP2_CMD_CLIENT_PIN;
    pk_cbor_writer_t w;
    pk_cbor_writer_init(&w, req + 1, sizeof(req) - 1);
    pk_cbor_encode_map_header(&w, 5);
    pk_cbor_encode_uint(&w, 1);
    pk_cbor_encode_uint(&w, 1);
    pk_cbor_encode_uint(&w, 2);
    pk_cbor_encode_uint(&w, PK_PIN_SUBCMD_GET_PIN_UV_TOKEN_USING_PIN);
    pk_cbor_encode_uint(&w, 3);
    TEST_ASSERT(pk_cbor_encode_cose_p256_pubkey(&w, &plat_pub, true) == PK_OK);
    pk_cbor_encode_uint(&w, 6);
    pk_cbor_encode_bstr(&w, pin_hash_enc, 16);
    pk_cbor_encode_uint(&w, 9);
    pk_cbor_encode_uint(&w, permissions);
    size_t req_len = 1 + w.offset;

    uint8_t resp[256];
    size_t resp_len = 0;
    pk_ctap2_process_message(&ctap2, req, req_len, resp, sizeof(resp), &resp_len);
    if (resp[0] != CTAP2_OK) {
        return resp[0];
    }

    if (out_token_32 != NULL) {
        pk_cbor_reader_t r;
        pk_cbor_reader_init(&r, resp + 1, resp_len - 1);
        size_t map_cnt = 0;
        TEST_ASSERT(pk_cbor_decode_map_header(&r, &map_cnt) == PK_OK);
        bool found_token = false;
        for (size_t i = 0; i < map_cnt; i++) {
            uint64_t k = 0;
            TEST_ASSERT(pk_cbor_decode_uint(&r, &k) == PK_OK);
            if (k == 2) {
                const uint8_t *enc_token = NULL;
                size_t enc_token_len = 0;
                TEST_ASSERT(pk_cbor_decode_bstr(&r, &enc_token, &enc_token_len) == PK_OK);
                TEST_ASSERT(enc_token_len == 32);
                TEST_ASSERT(pk_crypto_aes256_cbc_decrypt_zero_iv(shared_secret, enc_token, 32, out_token_32) == PK_OK);
                found_token = true;
            } else {
                TEST_ASSERT(pk_cbor_skip_item(&r) == PK_OK);
            }
        }
        TEST_ASSERT(found_token);
    }
    return CTAP2_OK;
}

/* Helper to change PIN */
static void ctap_change_pin(const char *old_pin_str, const char *new_pin_str) {
    pk_p256_pubkey_t auth_pub;
    ctap_get_key_agreement(&auth_pub);

    uint8_t plat_priv[PK_P256_PRIVKEY_LEN];
    pk_p256_pubkey_t plat_pub;
    TEST_ASSERT(pk_crypto_p256_keygen(&crypto, plat_priv, &plat_pub) == PK_OK);

    uint8_t shared_secret[32];
    TEST_ASSERT(pk_crypto_p256_ecdh_shared_secret_sha256(&crypto, plat_priv, &auth_pub, shared_secret) == PK_OK);

    uint8_t old_hash[32];
    TEST_ASSERT(pk_crypto_sha256((const uint8_t *)old_pin_str, strlen(old_pin_str), old_hash) == PK_OK);
    uint8_t pin_hash_enc[16];
    TEST_ASSERT(pk_crypto_aes256_cbc_encrypt_zero_iv(shared_secret, old_hash, 16, pin_hash_enc) == PK_OK);

    uint8_t new_pin_padded[64];
    memset(new_pin_padded, 0, 64);
    memcpy(new_pin_padded, new_pin_str, strlen(new_pin_str));
    uint8_t new_pin_enc[64];
    TEST_ASSERT(pk_crypto_aes256_cbc_encrypt_zero_iv(shared_secret, new_pin_padded, 64, new_pin_enc) == PK_OK);

    uint8_t to_mac[80];
    memcpy(to_mac, new_pin_enc, 64);
    memcpy(to_mac + 64, pin_hash_enc, 16);
    uint8_t hmac[32];
    TEST_ASSERT(pk_crypto_hmac_sha256(shared_secret, 32, to_mac, 80, hmac) == PK_OK);
    uint8_t pin_auth[16];
    memcpy(pin_auth, hmac, 16);

    uint8_t req[256];
    req[0] = CTAP2_CMD_CLIENT_PIN;
    pk_cbor_writer_t w;
    pk_cbor_writer_init(&w, req + 1, sizeof(req) - 1);
    pk_cbor_encode_map_header(&w, 6);
    pk_cbor_encode_uint(&w, 1);
    pk_cbor_encode_uint(&w, 1);
    pk_cbor_encode_uint(&w, 2);
    pk_cbor_encode_uint(&w, PK_PIN_SUBCMD_CHANGE_PIN);
    pk_cbor_encode_uint(&w, 3);
    TEST_ASSERT(pk_cbor_encode_cose_p256_pubkey(&w, &plat_pub, true) == PK_OK);
    pk_cbor_encode_uint(&w, 4);
    pk_cbor_encode_bstr(&w, pin_auth, 16);
    pk_cbor_encode_uint(&w, 5);
    pk_cbor_encode_bstr(&w, new_pin_enc, 64);
    pk_cbor_encode_uint(&w, 6);
    pk_cbor_encode_bstr(&w, pin_hash_enc, 16);
    size_t req_len = 1 + w.offset;

    uint8_t resp[64];
    size_t resp_len = 0;
    pk_ctap2_process_message(&ctap2, req, req_len, resp, sizeof(resp), &resp_len);
    TEST_ASSERT(resp_len >= 1 && resp[0] == CTAP2_OK);
}

/* Test 1: authenticatorGetInfo (0x04) */
static void test_authenticator_get_info(void) {
    printf("Running test_authenticator_get_info...\n");
    uint8_t req[1] = { CTAP2_CMD_GET_INFO };
    uint8_t resp[PK_CTAP2_MAX_MSG_SIZE];
    size_t resp_len = 0;

    pk_ctap2_process_message(&ctap2, req, 1, resp, sizeof(resp), &resp_len);
    TEST_ASSERT(resp_len > 1);
    TEST_ASSERT(resp[0] == CTAP2_OK);

    pk_cbor_reader_t r;
    pk_cbor_reader_init(&r, resp + 1, resp_len - 1);
    size_t map_entries = 0;
    TEST_ASSERT(pk_cbor_decode_map_header(&r, &map_entries) == PK_OK);

    bool found_u2f_v2 = false;
    bool found_fido_2_0 = false;
    bool found_fido_2_1 = false;
    bool found_aaguid = false;
    bool found_options = false;
    bool opt_rk = false, opt_up = false, opt_client_pin = false;
    bool found_max_msg_size = false;
    uint64_t max_msg_size = 0;
    bool found_pin_protocols = false;
    bool found_pin_protocol_1 = false;

    for (size_t i = 0; i < map_entries; i++) {
        uint64_t key = 0;
        TEST_ASSERT(pk_cbor_decode_uint(&r, &key) == PK_OK);
        if (key == 1) { // versions
            size_t count = 0;
            TEST_ASSERT(pk_cbor_decode_array_header(&r, &count) == PK_OK);
            TEST_ASSERT(count == 4);
            for (size_t j = 0; j < count; j++) {
                const char *str = NULL;
                size_t len = 0;
                TEST_ASSERT(pk_cbor_decode_tstr(&r, &str, &len) == PK_OK);
                if (len == 6 && memcmp(str, "U2F_V2", 6) == 0) found_u2f_v2 = true;
                if (len == 8 && memcmp(str, "FIDO_2_0", 8) == 0) found_fido_2_0 = true;
                if (len == 8 && memcmp(str, "FIDO_2_1", 8) == 0) found_fido_2_1 = true;
            }
        } else if (key == 2) { // extensions
            size_t count = 0;
            TEST_ASSERT(pk_cbor_decode_array_header(&r, &count) == PK_OK);
            TEST_ASSERT(count == 2);
            bool found_cp = false, found_hmac = false;
            for (size_t j = 0; j < count; j++) {
                const char *str = NULL;
                size_t len = 0;
                TEST_ASSERT(pk_cbor_decode_tstr(&r, &str, &len) == PK_OK);
                if (len == 11 && memcmp(str, "credProtect", 11) == 0) found_cp = true;
                if (len == 11 && memcmp(str, "hmac-secret", 11) == 0) found_hmac = true;
            }
            TEST_ASSERT(found_cp && found_hmac);
        } else if (key == 3) { // aaguid
            const uint8_t *b = NULL;
            size_t len = 0;
            TEST_ASSERT(pk_cbor_decode_bstr(&r, &b, &len) == PK_OK);
            TEST_ASSERT(len == 16);
            found_aaguid = true;
        } else if (key == 4) { // options
            size_t opt_cnt = 0;
            TEST_ASSERT(pk_cbor_decode_map_header(&r, &opt_cnt) == PK_OK);
            for (size_t j = 0; j < opt_cnt; j++) {
                const char *opt_name = NULL;
                size_t opt_len = 0;
                TEST_ASSERT(pk_cbor_decode_tstr(&r, &opt_name, &opt_len) == PK_OK);
                bool val = false;
                TEST_ASSERT(pk_cbor_decode_bool(&r, &val) == PK_OK);
                if (opt_len == 2 && memcmp(opt_name, "rk", 2) == 0) opt_rk = val;
                if (opt_len == 2 && memcmp(opt_name, "up", 2) == 0) opt_up = val;
                if (opt_len == 9 && memcmp(opt_name, "clientPin", 9) == 0) opt_client_pin = val;
            }
            found_options = true;
        } else if (key == 5) { // maxMsgSize
            TEST_ASSERT(pk_cbor_decode_uint(&r, &max_msg_size) == PK_OK);
            found_max_msg_size = true;
        } else if (key == 6) { // pinUvAuthProtocols
            size_t p_cnt = 0;
            TEST_ASSERT(pk_cbor_decode_array_header(&r, &p_cnt) == PK_OK);
            TEST_ASSERT(p_cnt >= 1);
            for (size_t j = 0; j < p_cnt; j++) {
                uint64_t proto = 0;
                TEST_ASSERT(pk_cbor_decode_uint(&r, &proto) == PK_OK);
                if (proto == 1) found_pin_protocol_1 = true;
            }
            found_pin_protocols = true;
        } else {
            TEST_ASSERT(pk_cbor_skip_item(&r) == PK_OK);
        }
    }

    TEST_ASSERT(found_u2f_v2 && found_fido_2_0 && found_fido_2_1);
    TEST_ASSERT(found_aaguid);
    TEST_ASSERT(found_options && opt_rk && opt_up && !opt_client_pin);
    TEST_ASSERT(found_max_msg_size && max_msg_size == PK_CTAP2_MAX_MSG_SIZE);
    TEST_ASSERT(found_pin_protocols && found_pin_protocol_1);

    printf("  [PASS] authenticatorGetInfo decoded and verified\n");
}

/* Test 2: authenticatorClientPIN (0x06) Full Lifecycle */
static void test_client_pin_lifecycle(void) {
    printf("Running test_client_pin_lifecycle...\n");

    // 1. Initial state: PIN is not set
    TEST_ASSERT(!pk_pin_is_set(&pin));
    TEST_ASSERT(ctap_get_retries() == PK_PIN_MAX_RETRIES);

    // 2. Set initial PIN to "123456"
    ctap_set_pin("123456");
    TEST_ASSERT(pk_pin_is_set(&pin));

    // Verify authenticatorGetInfo now reports clientPin = true
    uint8_t req[1] = { CTAP2_CMD_GET_INFO };
    uint8_t resp[PK_CTAP2_MAX_MSG_SIZE];
    size_t resp_len = 0;
    pk_ctap2_process_message(&ctap2, req, 1, resp, sizeof(resp), &resp_len);
    TEST_ASSERT(resp_len > 1 && resp[0] == CTAP2_OK);
    pk_cbor_reader_t r;
    pk_cbor_reader_init(&r, resp + 1, resp_len - 1);
    size_t map_entries = 0;
    TEST_ASSERT(pk_cbor_decode_map_header(&r, &map_entries) == PK_OK);
    bool opt_client_pin = false;
    for (size_t i = 0; i < map_entries; i++) {
        uint64_t key = 0;
        TEST_ASSERT(pk_cbor_decode_uint(&r, &key) == PK_OK);
        if (key == 4) { // options
            size_t opt_cnt = 0;
            TEST_ASSERT(pk_cbor_decode_map_header(&r, &opt_cnt) == PK_OK);
            for (size_t j = 0; j < opt_cnt; j++) {
                const char *opt_name = NULL;
                size_t opt_len = 0;
                TEST_ASSERT(pk_cbor_decode_tstr(&r, &opt_name, &opt_len) == PK_OK);
                bool val = false;
                TEST_ASSERT(pk_cbor_decode_bool(&r, &val) == PK_OK);
                if (opt_len == 9 && memcmp(opt_name, "clientPin", 9) == 0) opt_client_pin = val;
            }
        } else {
            TEST_ASSERT(pk_cbor_skip_item(&r) == PK_OK);
        }
    }
    TEST_ASSERT(opt_client_pin == true);

    // 3. Test wrong PIN attempts decrementing retries
    uint8_t pin_token[32];
    uint8_t status = ctap_get_pin_token("000000", pin_token);
    TEST_ASSERT(status == CTAP2_ERR_PIN_INVALID);
    TEST_ASSERT(ctap_get_retries() == 7);

    status = ctap_get_pin_token("111111", pin_token);
    TEST_ASSERT(status == CTAP2_ERR_PIN_INVALID);
    TEST_ASSERT(ctap_get_retries() == 6);

    // 4. Test correct PIN succeeds and resets retries to 8
    status = ctap_get_pin_token("123456", pin_token);
    TEST_ASSERT(status == CTAP2_OK);
    TEST_ASSERT(ctap_get_retries() == PK_PIN_MAX_RETRIES);

    // 5. Change PIN from "123456" to "654321"
    ctap_change_pin("123456", "654321");

    // 6. Verify old PIN fails and new PIN succeeds
    status = ctap_get_pin_token("123456", pin_token);
    TEST_ASSERT(status == CTAP2_ERR_PIN_INVALID);
    status = ctap_get_pin_token("654321", pin_token);
    TEST_ASSERT(status == CTAP2_OK);

    // 7. Test getPinUvAuthTokenUsingPin (Subcommand 0x09)
    uint8_t pin_uv_token[32];
    uint8_t perms = PK_PIN_PERM_MC | PK_PIN_PERM_GA | PK_PIN_PERM_CM;
    status = ctap_get_pin_uv_token("654321", perms, pin_uv_token);
    TEST_ASSERT(status == CTAP2_OK);
    TEST_ASSERT(pk_crypto_consttime_eq(pin_uv_token, pin.pin_token, 32));

    printf("  [PASS] authenticatorClientPIN lifecycle complete\n");
}

/* Helper to make a resident credential using MakeCredential (0x01) */
static void make_test_credential(const uint8_t *pin_token_32, const char *rp_id, const char *user_id_str, uint8_t out_cred_id[64]) {
    uint8_t cdh[32];
    memset(cdh, 0x55, 32);

    uint8_t full_mac[32];
    uint8_t pin_auth[16];
    TEST_ASSERT(pk_crypto_hmac_sha256(pin_token_32, 32, cdh, 32, full_mac) == PK_OK);
    memcpy(pin_auth, full_mac, 16);

    uint8_t req[512];
    req[0] = CTAP2_CMD_MAKE_CREDENTIAL;
    pk_cbor_writer_t w;
    pk_cbor_writer_init(&w, req + 1, sizeof(req) - 1);
    pk_cbor_encode_map_header(&w, 7);

    // 0x01: clientDataHash
    pk_cbor_encode_uint(&w, 1);
    pk_cbor_encode_bstr(&w, cdh, 32);

    // 0x02: rp
    pk_cbor_encode_uint(&w, 2);
    pk_cbor_encode_map_header(&w, 2);
    pk_cbor_encode_tstr_c(&w, "id");
    pk_cbor_encode_tstr_c(&w, rp_id);
    pk_cbor_encode_tstr_c(&w, "name");
    pk_cbor_encode_tstr_c(&w, "Example Corp");

    // 0x03: user
    pk_cbor_encode_uint(&w, 3);
    pk_cbor_encode_map_header(&w, 3);
    pk_cbor_encode_tstr_c(&w, "id");
    pk_cbor_encode_bstr(&w, (const uint8_t *)user_id_str, strlen(user_id_str));
    pk_cbor_encode_tstr_c(&w, "name");
    pk_cbor_encode_tstr_c(&w, user_id_str);
    pk_cbor_encode_tstr_c(&w, "displayName");
    pk_cbor_encode_tstr_c(&w, "User Display Name");

    // 0x04: pubKeyCredParams
    pk_cbor_encode_uint(&w, 4);
    pk_cbor_encode_array_header(&w, 1);
    pk_cbor_encode_map_header(&w, 2);
    pk_cbor_encode_tstr_c(&w, "type");
    pk_cbor_encode_tstr_c(&w, "public-key");
    pk_cbor_encode_tstr_c(&w, "alg");
    pk_cbor_encode_int(&w, PK_COSE_ALG_ES256);

    // 0x07: options
    pk_cbor_encode_uint(&w, 7);
    pk_cbor_encode_map_header(&w, 2);
    pk_cbor_encode_tstr_c(&w, "rk");
    pk_cbor_encode_bool(&w, true);
    pk_cbor_encode_tstr_c(&w, "up");
    pk_cbor_encode_bool(&w, true);

    // 0x08: pinUvAuthParam
    pk_cbor_encode_uint(&w, 8);
    pk_cbor_encode_bstr(&w, pin_auth, 16);

    // 0x09: pinUvAuthProtocol
    pk_cbor_encode_uint(&w, 9);
    pk_cbor_encode_uint(&w, 1);

    size_t req_len = 1 + w.offset;
    uint8_t resp[1024];
    size_t resp_len = 0;
    pk_ctap2_process_message(&ctap2, req, req_len, resp, sizeof(resp), &resp_len);
    if (resp_len < 1 || resp[0] != CTAP2_OK) {
        fprintf(stderr, "MakeCredential failed with status: 0x%02X (%s)\n", resp[0], pk_ctap_status_str(resp[0]));
    }
    TEST_ASSERT(resp_len > 1 && resp[0] == CTAP2_OK);

    // Extract authData to get cred_id
    pk_cbor_reader_t r;
    pk_cbor_reader_init(&r, resp + 1, resp_len - 1);
    size_t map_cnt = 0;
    TEST_ASSERT(pk_cbor_decode_map_header(&r, &map_cnt) == PK_OK);
    const uint8_t *auth_data = NULL;
    size_t auth_data_len = 0;
    for (size_t i = 0; i < map_cnt; i++) {
        uint64_t k = 0;
        TEST_ASSERT(pk_cbor_decode_uint(&r, &k) == PK_OK);
        if (k == 2) {
            TEST_ASSERT(pk_cbor_decode_bstr(&r, &auth_data, &auth_data_len) == PK_OK);
        } else {
            TEST_ASSERT(pk_cbor_skip_item(&r) == PK_OK);
        }
    }
    TEST_ASSERT(auth_data != NULL && auth_data_len >= 119);
    uint16_t id_len = ((uint16_t)auth_data[53] << 8) | auth_data[54];
    TEST_ASSERT(id_len == 64);
    memcpy(out_cred_id, &auth_data[55], 64);
}

/* Test 3: authenticatorCredentialManagement (0x0A) with Multi-RP and Multi-Credential enumeration */
static void test_credential_management(void) {
    printf("Running test_credential_management...\n");

    // Obtain pinUvAuthToken with PK_PIN_PERM_CM | PK_PIN_PERM_MC | PK_PIN_PERM_GA
    uint8_t pin_token[32];
    uint8_t perms = PK_PIN_PERM_CM | PK_PIN_PERM_MC | PK_PIN_PERM_GA;
    uint8_t status = ctap_get_pin_uv_token("654321", perms, pin_token);
    TEST_ASSERT(status == CTAP2_OK);

    // 1. getCredsMetadata (0x01)
    uint8_t full_mac[32];
    uint8_t pin_auth[16];
    const uint8_t subcmd1 = 0x01;
    TEST_ASSERT(pk_crypto_hmac_sha256(pin_token, 32, &subcmd1, 1, full_mac) == PK_OK);
    memcpy(pin_auth, full_mac, 16);

    uint8_t req[512];
    req[0] = CTAP2_CMD_CREDENTIAL_MGMT;
    pk_cbor_writer_t w;
    pk_cbor_writer_init(&w, req + 1, sizeof(req) - 1);
    pk_cbor_encode_map_header(&w, 3);
    pk_cbor_encode_uint(&w, 1); // subCommand
    pk_cbor_encode_uint(&w, 1);
    pk_cbor_encode_uint(&w, 3); // pinUvAuthProtocol
    pk_cbor_encode_uint(&w, 1);
    pk_cbor_encode_uint(&w, 4); // pinUvAuthParam
    pk_cbor_encode_bstr(&w, pin_auth, 16);
    size_t req_len = 1 + w.offset;

    uint8_t resp[512];
    size_t resp_len = 0;
    pk_ctap2_process_message(&ctap2, req, req_len, resp, sizeof(resp), &resp_len);
    TEST_ASSERT(resp_len > 1 && resp[0] == CTAP2_OK);

    pk_cbor_reader_t r;
    pk_cbor_reader_init(&r, resp + 1, resp_len - 1);
    size_t map_cnt = 0;
    TEST_ASSERT(pk_cbor_decode_map_header(&r, &map_cnt) == PK_OK);
    uint64_t initial_creds_count = 0;
    for (size_t i = 0; i < map_cnt; i++) {
        uint64_t k = 0;
        TEST_ASSERT(pk_cbor_decode_uint(&r, &k) == PK_OK);
        if (k == 1) {
            TEST_ASSERT(pk_cbor_decode_uint(&r, &initial_creds_count) == PK_OK);
        } else {
            TEST_ASSERT(pk_cbor_skip_item(&r) == PK_OK);
        }
    }

    // 2. Register 3 credentials: 2 on "example.com" and 1 on "second.org"
    uint8_t cred_id1[64];
    uint8_t cred_id2[64];
    uint8_t cred_id3[64];
    make_test_credential(pin_token, "example.com", "user_cm_test_1", cred_id1);
    make_test_credential(pin_token, "example.com", "user_cm_test_2", cred_id2);
    make_test_credential(pin_token, "second.org", "user_cm_test_3", cred_id3);

    // 3. enumerateRPsBegin (0x02)
    const uint8_t subcmd2 = 0x02;
    TEST_ASSERT(pk_crypto_hmac_sha256(pin_token, 32, &subcmd2, 1, full_mac) == PK_OK);
    memcpy(pin_auth, full_mac, 16);

    req[0] = CTAP2_CMD_CREDENTIAL_MGMT;
    pk_cbor_writer_init(&w, req + 1, sizeof(req) - 1);
    pk_cbor_encode_map_header(&w, 3);
    pk_cbor_encode_uint(&w, 1);
    pk_cbor_encode_uint(&w, 2);
    pk_cbor_encode_uint(&w, 3);
    pk_cbor_encode_uint(&w, 1);
    pk_cbor_encode_uint(&w, 4);
    pk_cbor_encode_bstr(&w, pin_auth, 16);
    req_len = 1 + w.offset;

    pk_ctap2_process_message(&ctap2, req, req_len, resp, sizeof(resp), &resp_len);
    TEST_ASSERT(resp_len > 1 && resp[0] == CTAP2_OK);

    pk_cbor_reader_init(&r, resp + 1, resp_len - 1);
    TEST_ASSERT(pk_cbor_decode_map_header(&r, &map_cnt) == PK_OK);
    uint8_t enumerated_rp_hash[32];
    bool found_rp_hash = false;
    uint64_t total_rps = 0;
    for (size_t i = 0; i < map_cnt; i++) {
        uint64_t k = 0;
        TEST_ASSERT(pk_cbor_decode_uint(&r, &k) == PK_OK);
        if (k == 4) { // rpIdHash
            const uint8_t *h = NULL;
            size_t h_len = 0;
            TEST_ASSERT(pk_cbor_decode_bstr(&r, &h, &h_len) == PK_OK);
            TEST_ASSERT(h_len == 32);
            memcpy(enumerated_rp_hash, h, 32);
            found_rp_hash = true;
        } else if (k == 5) { // totalRPs
            TEST_ASSERT(pk_cbor_decode_uint(&r, &total_rps) == PK_OK);
        } else {
            TEST_ASSERT(pk_cbor_skip_item(&r) == PK_OK);
        }
    }
    TEST_ASSERT(found_rp_hash && total_rps == 2);

    // 4. enumerateRPsGetNextRP (0x03)
    const uint8_t subcmd3 = 0x03;
    TEST_ASSERT(pk_crypto_hmac_sha256(pin_token, 32, &subcmd3, 1, full_mac) == PK_OK);
    memcpy(pin_auth, full_mac, 16);

    req[0] = CTAP2_CMD_CREDENTIAL_MGMT;
    pk_cbor_writer_init(&w, req + 1, sizeof(req) - 1);
    pk_cbor_encode_map_header(&w, 3);
    pk_cbor_encode_uint(&w, 1);
    pk_cbor_encode_uint(&w, 3);
    pk_cbor_encode_uint(&w, 3);
    pk_cbor_encode_uint(&w, 1);
    pk_cbor_encode_uint(&w, 4);
    pk_cbor_encode_bstr(&w, pin_auth, 16);
    req_len = 1 + w.offset;

    pk_ctap2_process_message(&ctap2, req, req_len, resp, sizeof(resp), &resp_len);
    TEST_ASSERT(resp_len > 1 && resp[0] == CTAP2_OK);

    // Second enumerateRPsGetNextRP must return CTAP2_ERR_NO_CREDENTIALS (all 2 RPs returned)
    pk_ctap2_process_message(&ctap2, req, req_len, resp, sizeof(resp), &resp_len);
    TEST_ASSERT(resp_len >= 1 && resp[0] == CTAP2_ERR_NO_CREDENTIALS);

    // 5. enumerateCredentialsBegin (0x04) for "example.com"
    uint8_t example_rp_hash[32];
    TEST_ASSERT(pk_crypto_sha256((const uint8_t *)"example.com", 11, example_rp_hash) == PK_OK);

    uint8_t params_buf[128];
    pk_cbor_writer_t pw;
    pk_cbor_writer_init(&pw, params_buf, sizeof(params_buf));
    pk_cbor_encode_map_header(&pw, 1);
    pk_cbor_encode_uint(&pw, 1);
    pk_cbor_encode_bstr(&pw, example_rp_hash, 32);
    size_t params_len = pw.offset;

    uint8_t to_mac[140];
    to_mac[0] = 0x04;
    memcpy(to_mac + 1, params_buf, params_len);
    TEST_ASSERT(pk_crypto_hmac_sha256(pin_token, 32, to_mac, 1 + params_len, full_mac) == PK_OK);
    memcpy(pin_auth, full_mac, 16);

    req[0] = CTAP2_CMD_CREDENTIAL_MGMT;
    pk_cbor_writer_init(&w, req + 1, sizeof(req) - 1);
    pk_cbor_encode_map_header(&w, 4);
    pk_cbor_encode_uint(&w, 1);
    pk_cbor_encode_uint(&w, 4);
    pk_cbor_encode_uint(&w, 2);
    pk_cbor_encode_raw(&w, params_buf, params_len);
    pk_cbor_encode_uint(&w, 3);
    pk_cbor_encode_uint(&w, 1);
    pk_cbor_encode_uint(&w, 4);
    pk_cbor_encode_bstr(&w, pin_auth, 16);
    req_len = 1 + w.offset;

    pk_ctap2_process_message(&ctap2, req, req_len, resp, sizeof(resp), &resp_len);
    TEST_ASSERT(resp_len > 1 && resp[0] == CTAP2_OK);

    pk_cbor_reader_init(&r, resp + 1, resp_len - 1);
    TEST_ASSERT(pk_cbor_decode_map_header(&r, &map_cnt) == PK_OK);
    uint64_t total_creds = 0;
    for (size_t i = 0; i < map_cnt; i++) {
        uint64_t k = 0;
        TEST_ASSERT(pk_cbor_decode_uint(&r, &k) == PK_OK);
        if (k == 9) { // totalCredentials
            TEST_ASSERT(pk_cbor_decode_uint(&r, &total_creds) == PK_OK);
        } else {
            TEST_ASSERT(pk_cbor_skip_item(&r) == PK_OK);
        }
    }
    TEST_ASSERT(total_creds == 2);

    // 6. enumerateCredentialsGetNextCredential (0x05)
    const uint8_t subcmd5 = 0x05;
    TEST_ASSERT(pk_crypto_hmac_sha256(pin_token, 32, &subcmd5, 1, full_mac) == PK_OK);
    memcpy(pin_auth, full_mac, 16);

    req[0] = CTAP2_CMD_CREDENTIAL_MGMT;
    pk_cbor_writer_init(&w, req + 1, sizeof(req) - 1);
    pk_cbor_encode_map_header(&w, 3);
    pk_cbor_encode_uint(&w, 1);
    pk_cbor_encode_uint(&w, 5);
    pk_cbor_encode_uint(&w, 3);
    pk_cbor_encode_uint(&w, 1);
    pk_cbor_encode_uint(&w, 4);
    pk_cbor_encode_bstr(&w, pin_auth, 16);
    req_len = 1 + w.offset;

    pk_ctap2_process_message(&ctap2, req, req_len, resp, sizeof(resp), &resp_len);
    TEST_ASSERT(resp_len > 1 && resp[0] == CTAP2_OK);

    // Second enumerateCredentialsGetNextCredential must return CTAP2_ERR_NO_CREDENTIALS
    pk_ctap2_process_message(&ctap2, req, req_len, resp, sizeof(resp), &resp_len);
    TEST_ASSERT(resp_len >= 1 && resp[0] == CTAP2_ERR_NO_CREDENTIALS);

    // 7. Delete all 3 test credentials
    const uint8_t *creds_to_del[3] = { cred_id1, cred_id2, cred_id3 };
    for (int c = 0; c < 3; c++) {
        pk_cbor_writer_init(&pw, params_buf, sizeof(params_buf));
        pk_cbor_encode_map_header(&pw, 1);
        pk_cbor_encode_uint(&pw, 2);
        pk_cbor_encode_map_header(&pw, 2);
        pk_cbor_encode_tstr_c(&pw, "id");
        pk_cbor_encode_bstr(&pw, creds_to_del[c], 64);
        pk_cbor_encode_tstr_c(&pw, "type");
        pk_cbor_encode_tstr_c(&pw, "public-key");
        params_len = pw.offset;

        to_mac[0] = 0x06;
        memcpy(to_mac + 1, params_buf, params_len);
        TEST_ASSERT(pk_crypto_hmac_sha256(pin_token, 32, to_mac, 1 + params_len, full_mac) == PK_OK);
        memcpy(pin_auth, full_mac, 16);

        req[0] = CTAP2_CMD_CREDENTIAL_MGMT;
        pk_cbor_writer_init(&w, req + 1, sizeof(req) - 1);
        pk_cbor_encode_map_header(&w, 4);
        pk_cbor_encode_uint(&w, 1);
        pk_cbor_encode_uint(&w, 6);
        pk_cbor_encode_uint(&w, 2);
        pk_cbor_encode_raw(&w, params_buf, params_len);
        pk_cbor_encode_uint(&w, 3);
        pk_cbor_encode_uint(&w, 1);
        pk_cbor_encode_uint(&w, 4);
        pk_cbor_encode_bstr(&w, pin_auth, 16);
        req_len = 1 + w.offset;

        pk_ctap2_process_message(&ctap2, req, req_len, resp, sizeof(resp), &resp_len);
        TEST_ASSERT(resp_len >= 1 && resp[0] == CTAP2_OK);
    }

    // Verify credential count decreased back to initial
    TEST_ASSERT(pk_crypto_hmac_sha256(pin_token, 32, &subcmd1, 1, full_mac) == PK_OK);
    memcpy(pin_auth, full_mac, 16);
    req[0] = CTAP2_CMD_CREDENTIAL_MGMT;
    pk_cbor_writer_init(&w, req + 1, sizeof(req) - 1);
    pk_cbor_encode_map_header(&w, 3);
    pk_cbor_encode_uint(&w, 1);
    pk_cbor_encode_uint(&w, 1);
    pk_cbor_encode_uint(&w, 3);
    pk_cbor_encode_uint(&w, 1);
    pk_cbor_encode_uint(&w, 4);
    pk_cbor_encode_bstr(&w, pin_auth, 16);
    req_len = 1 + w.offset;

    pk_ctap2_process_message(&ctap2, req, req_len, resp, sizeof(resp), &resp_len);
    TEST_ASSERT(resp_len > 1 && resp[0] == CTAP2_OK);

    pk_cbor_reader_init(&r, resp + 1, resp_len - 1);
    TEST_ASSERT(pk_cbor_decode_map_header(&r, &map_cnt) == PK_OK);
    uint64_t final_creds_count = 0;
    for (size_t i = 0; i < map_cnt; i++) {
        uint64_t k = 0;
        TEST_ASSERT(pk_cbor_decode_uint(&r, &k) == PK_OK);
        if (k == 1) {
            TEST_ASSERT(pk_cbor_decode_uint(&r, &final_creds_count) == PK_OK);
        } else {
            TEST_ASSERT(pk_cbor_skip_item(&r) == PK_OK);
        }
    }
    TEST_ASSERT(final_creds_count == initial_creds_count);

    printf("  [PASS] authenticatorCredentialManagement subcommands verified\n");
}

/* Test 4: authenticatorReset (0x07) */
static void test_authenticator_reset(void) {
    printf("Running test_authenticator_reset...\n");

    // Success within 10s of boot (mock.now_ms <= 10000)
    mock.now_ms = 5000;
    uint8_t req[1] = { CTAP2_CMD_RESET };
    uint8_t resp[64];
    size_t resp_len = 0;

    pk_ctap2_process_message(&ctap2, req, 1, resp, sizeof(resp), &resp_len);
    TEST_ASSERT(resp_len >= 1 && resp[0] == CTAP2_OK);
    TEST_ASSERT(!pk_pin_is_set(&pin));

    // Rejection after 10s of boot (mock.now_ms > 10000)
    mock.now_ms = 10001;
    pk_ctap2_process_message(&ctap2, req, 1, resp, sizeof(resp), &resp_len);
    TEST_ASSERT(resp_len >= 1 && resp[0] == CTAP2_ERR_NOT_ALLOWED);

    printf("  [PASS] authenticatorReset within 10s and rejection after 10s\n");
}

/* Test 5: credProtect extension in MakeCredential */
static void test_make_credential_cred_protect(void) {
    printf("Running test_make_credential_cred_protect...\n");
    setup_env();

    uint8_t cdh[32];
    memset(cdh, 0x88, 32);

    // 1. Invalid credProtect value: 0 -> CTAP2_ERR_INVALID_CBOR
    uint8_t req[512];
    req[0] = CTAP2_CMD_MAKE_CREDENTIAL;
    pk_cbor_writer_t w;
    pk_cbor_writer_init(&w, req + 1, sizeof(req) - 1);
    pk_cbor_encode_map_header(&w, 5);
    pk_cbor_encode_uint(&w, 1);
    pk_cbor_encode_bstr(&w, cdh, 32);
    pk_cbor_encode_uint(&w, 2);
    pk_cbor_encode_map_header(&w, 1);
    pk_cbor_encode_tstr_c(&w, "id");
    pk_cbor_encode_tstr_c(&w, "test.example.com");
    pk_cbor_encode_uint(&w, 3);
    pk_cbor_encode_map_header(&w, 1);
    pk_cbor_encode_tstr_c(&w, "id");
    pk_cbor_encode_bstr(&w, (const uint8_t *)"uid1", 4);
    pk_cbor_encode_uint(&w, 4);
    pk_cbor_encode_array_header(&w, 1);
    pk_cbor_encode_map_header(&w, 2);
    pk_cbor_encode_tstr_c(&w, "type");
    pk_cbor_encode_tstr_c(&w, "public-key");
    pk_cbor_encode_tstr_c(&w, "alg");
    pk_cbor_encode_int(&w, PK_COSE_ALG_ES256);
    pk_cbor_encode_uint(&w, 6); // extensions
    pk_cbor_encode_map_header(&w, 1);
    pk_cbor_encode_tstr_c(&w, "credProtect");
    pk_cbor_encode_uint(&w, 0); // invalid
    size_t req_len = 1 + w.offset;

    uint8_t resp[1024];
    size_t resp_len = 0;
    pk_ctap2_process_message(&ctap2, req, req_len, resp, sizeof(resp), &resp_len);
    TEST_ASSERT(resp_len >= 1 && resp[0] == CTAP2_ERR_INVALID_CBOR);

    // 2. Invalid credProtect value: 4 -> CTAP2_ERR_INVALID_CBOR
    pk_cbor_writer_init(&w, req + 1, sizeof(req) - 1);
    pk_cbor_encode_map_header(&w, 5);
    pk_cbor_encode_uint(&w, 1);
    pk_cbor_encode_bstr(&w, cdh, 32);
    pk_cbor_encode_uint(&w, 2);
    pk_cbor_encode_map_header(&w, 1);
    pk_cbor_encode_tstr_c(&w, "id");
    pk_cbor_encode_tstr_c(&w, "test.example.com");
    pk_cbor_encode_uint(&w, 3);
    pk_cbor_encode_map_header(&w, 1);
    pk_cbor_encode_tstr_c(&w, "id");
    pk_cbor_encode_bstr(&w, (const uint8_t *)"uid1", 4);
    pk_cbor_encode_uint(&w, 4);
    pk_cbor_encode_array_header(&w, 1);
    pk_cbor_encode_map_header(&w, 2);
    pk_cbor_encode_tstr_c(&w, "type");
    pk_cbor_encode_tstr_c(&w, "public-key");
    pk_cbor_encode_tstr_c(&w, "alg");
    pk_cbor_encode_int(&w, PK_COSE_ALG_ES256);
    pk_cbor_encode_uint(&w, 6); // extensions
    pk_cbor_encode_map_header(&w, 1);
    pk_cbor_encode_tstr_c(&w, "credProtect");
    pk_cbor_encode_uint(&w, 4); // invalid
    req_len = 1 + w.offset;

    pk_ctap2_process_message(&ctap2, req, req_len, resp, sizeof(resp), &resp_len);
    TEST_ASSERT(resp_len >= 1 && resp[0] == CTAP2_ERR_INVALID_CBOR);

    // 3. Valid credProtect: 2 and hmac-secret: true -> verify ED flag and canonical order
    pk_cbor_writer_init(&w, req + 1, sizeof(req) - 1);
    pk_cbor_encode_map_header(&w, 5);
    pk_cbor_encode_uint(&w, 1);
    pk_cbor_encode_bstr(&w, cdh, 32);
    pk_cbor_encode_uint(&w, 2);
    pk_cbor_encode_map_header(&w, 1);
    pk_cbor_encode_tstr_c(&w, "id");
    pk_cbor_encode_tstr_c(&w, "test.example.com");
    pk_cbor_encode_uint(&w, 3);
    pk_cbor_encode_map_header(&w, 1);
    pk_cbor_encode_tstr_c(&w, "id");
    pk_cbor_encode_bstr(&w, (const uint8_t *)"uid1", 4);
    pk_cbor_encode_uint(&w, 4);
    pk_cbor_encode_array_header(&w, 1);
    pk_cbor_encode_map_header(&w, 2);
    pk_cbor_encode_tstr_c(&w, "type");
    pk_cbor_encode_tstr_c(&w, "public-key");
    pk_cbor_encode_tstr_c(&w, "alg");
    pk_cbor_encode_int(&w, PK_COSE_ALG_ES256);
    pk_cbor_encode_uint(&w, 6); // extensions
    pk_cbor_encode_map_header(&w, 2);
    pk_cbor_encode_tstr_c(&w, "credProtect");
    pk_cbor_encode_uint(&w, 2);
    pk_cbor_encode_tstr_c(&w, "hmac-secret");
    pk_cbor_encode_bool(&w, true);
    req_len = 1 + w.offset;

    pk_ctap2_process_message(&ctap2, req, req_len, resp, sizeof(resp), &resp_len);
    TEST_ASSERT(resp_len >= 1 && resp[0] == CTAP2_OK);

    pk_cbor_reader_t r;
    pk_cbor_reader_init(&r, resp + 1, resp_len - 1);
    size_t map_cnt = 0;
    TEST_ASSERT(pk_cbor_decode_map_header(&r, &map_cnt) == PK_OK);
    const uint8_t *auth_data = NULL;
    size_t auth_data_len = 0;
    for (size_t i = 0; i < map_cnt; i++) {
        uint64_t k = 0;
        TEST_ASSERT(pk_cbor_decode_uint(&r, &k) == PK_OK);
        if (k == 2) {
            TEST_ASSERT(pk_cbor_decode_bstr(&r, &auth_data, &auth_data_len) == PK_OK);
        } else {
            TEST_ASSERT(pk_cbor_skip_item(&r) == PK_OK);
        }
    }
    TEST_ASSERT(auth_data != NULL && auth_data_len > 119);
    // ED flag (0x80) must be set
    TEST_ASSERT((auth_data[32] & CTAP2_AUTH_DATA_FLAG_ED) != 0);

    // Skip attested credential data: 16B aaguid + 2B cred_id_len + 64B cred_id + COSE key
    pk_cbor_reader_t cose_r;
    pk_cbor_reader_init(&cose_r, &auth_data[119], auth_data_len - 119);
    pk_p256_pubkey_t dummy_pub;
    TEST_ASSERT(pk_cbor_decode_cose_p256_pubkey(&cose_r, &dummy_pub) == PK_OK);

    // After COSE key comes the extension CBOR map
    size_t ext_offset = 119 + cose_r.offset;
    pk_cbor_reader_t ext_r;
    pk_cbor_reader_init(&ext_r, &auth_data[ext_offset], auth_data_len - ext_offset);
    size_t ext_count = 0;
    TEST_ASSERT(pk_cbor_decode_map_header(&ext_r, &ext_count) == PK_OK);
    TEST_ASSERT(ext_count == 2);

    // 1st key must be credProtect
    const char *k1_str = NULL;
    size_t k1_len = 0;
    TEST_ASSERT(pk_cbor_decode_tstr(&ext_r, &k1_str, &k1_len) == PK_OK);
    TEST_ASSERT(k1_len == 11 && memcmp(k1_str, "credProtect", 11) == 0);
    uint64_t cp_read = 0;
    TEST_ASSERT(pk_cbor_decode_uint(&ext_r, &cp_read) == PK_OK);
    TEST_ASSERT(cp_read == 2);

    // 2nd key must be hmac-secret
    const char *k2_str = NULL;
    size_t k2_len = 0;
    TEST_ASSERT(pk_cbor_decode_tstr(&ext_r, &k2_str, &k2_len) == PK_OK);
    TEST_ASSERT(k2_len == 11 && memcmp(k2_str, "hmac-secret", 11) == 0);
    bool hs_read = false;
    TEST_ASSERT(pk_cbor_decode_bool(&ext_r, &hs_read) == PK_OK);
    TEST_ASSERT(hs_read == true);

    printf("  [PASS] credProtect extension handling verified\n");
}

/* Test 6: hmac-secret GetAssertion extension round-trip */
static void test_hmac_secret_roundtrip(void) {
    printf("Running test_hmac_secret_roundtrip...\n");
    setup_env();

    // 1. Set PIN and obtain pinUvAuthToken
    ctap_set_pin("123456");
    uint8_t pin_token[32];
    uint8_t perms = PK_PIN_PERM_MC | PK_PIN_PERM_GA;
    TEST_ASSERT(ctap_get_pin_uv_token("123456", perms, pin_token) == CTAP2_OK);

    // 2. MakeCredential with hmac-secret: true
    uint8_t cdh[32];
    memset(cdh, 0x77, 32);

    uint8_t full_mac[32];
    uint8_t pin_auth[16];
    TEST_ASSERT(pk_crypto_hmac_sha256(pin_token, 32, cdh, 32, full_mac) == PK_OK);
    memcpy(pin_auth, full_mac, 16);

    uint8_t req[1024];
    req[0] = CTAP2_CMD_MAKE_CREDENTIAL;
    pk_cbor_writer_t w;
    pk_cbor_writer_init(&w, req + 1, sizeof(req) - 1);
    pk_cbor_encode_map_header(&w, 8);
    pk_cbor_encode_uint(&w, 1);
    pk_cbor_encode_bstr(&w, cdh, 32);
    pk_cbor_encode_uint(&w, 2);
    pk_cbor_encode_map_header(&w, 1);
    pk_cbor_encode_tstr_c(&w, "id");
    pk_cbor_encode_tstr_c(&w, "hmac.example.com");
    pk_cbor_encode_uint(&w, 3);
    pk_cbor_encode_map_header(&w, 2);
    pk_cbor_encode_tstr_c(&w, "id");
    pk_cbor_encode_bstr(&w, (const uint8_t *)"uid_hmac", 8);
    pk_cbor_encode_tstr_c(&w, "name");
    pk_cbor_encode_tstr_c(&w, "hmac_user");
    pk_cbor_encode_uint(&w, 4);
    pk_cbor_encode_array_header(&w, 1);
    pk_cbor_encode_map_header(&w, 2);
    pk_cbor_encode_tstr_c(&w, "type");
    pk_cbor_encode_tstr_c(&w, "public-key");
    pk_cbor_encode_tstr_c(&w, "alg");
    pk_cbor_encode_int(&w, PK_COSE_ALG_ES256);
    pk_cbor_encode_uint(&w, 6); // extensions
    pk_cbor_encode_map_header(&w, 1);
    pk_cbor_encode_tstr_c(&w, "hmac-secret");
    pk_cbor_encode_bool(&w, true);
    pk_cbor_encode_uint(&w, 7); // options
    pk_cbor_encode_map_header(&w, 2);
    pk_cbor_encode_tstr_c(&w, "rk");
    pk_cbor_encode_bool(&w, true);
    pk_cbor_encode_tstr_c(&w, "up");
    pk_cbor_encode_bool(&w, true);
    pk_cbor_encode_uint(&w, 8);
    pk_cbor_encode_bstr(&w, pin_auth, 16);
    pk_cbor_encode_uint(&w, 9);
    pk_cbor_encode_uint(&w, 1);

    size_t req_len = 1 + w.offset;
    uint8_t resp[1024];
    size_t resp_len = 0;
    pk_ctap2_process_message(&ctap2, req, req_len, resp, sizeof(resp), &resp_len);
    TEST_ASSERT(resp_len > 1 && resp[0] == CTAP2_OK);

    // Extract credential ID
    pk_cbor_reader_t r;
    pk_cbor_reader_init(&r, resp + 1, resp_len - 1);
    size_t map_cnt = 0;
    TEST_ASSERT(pk_cbor_decode_map_header(&r, &map_cnt) == PK_OK);
    const uint8_t *auth_data = NULL;
    size_t auth_data_len = 0;
    for (size_t i = 0; i < map_cnt; i++) {
        uint64_t k = 0;
        TEST_ASSERT(pk_cbor_decode_uint(&r, &k) == PK_OK);
        if (k == 2) {
            TEST_ASSERT(pk_cbor_decode_bstr(&r, &auth_data, &auth_data_len) == PK_OK);
        } else {
            TEST_ASSERT(pk_cbor_skip_item(&r) == PK_OK);
        }
    }
    TEST_ASSERT(auth_data != NULL && auth_data_len >= 119);
    uint16_t cred_id_len = ((uint16_t)auth_data[53] << 8) | auth_data[54];
    TEST_ASSERT(cred_id_len == 64);
    uint8_t cred_id[64];
    memcpy(cred_id, &auth_data[55], 64);

    // 3. Perform GetAssertion with hmac-secret extension
    pk_p256_pubkey_t auth_pub;
    ctap_get_key_agreement(&auth_pub);
    uint8_t plat_priv[PK_P256_PRIVKEY_LEN];
    pk_p256_pubkey_t plat_pub;
    TEST_ASSERT(pk_crypto_p256_keygen(&crypto, plat_priv, &plat_pub) == PK_OK);
    uint8_t shared_secret[32];
    TEST_ASSERT(pk_crypto_p256_ecdh_shared_secret_sha256(&crypto, plat_priv, &auth_pub, shared_secret) == PK_OK);

    uint8_t salt1[32];
    memset(salt1, 0x5A, 32);
    uint8_t enc_salt[32];
    TEST_ASSERT(pk_crypto_aes256_cbc_encrypt_zero_iv(shared_secret, salt1, 32, enc_salt) == PK_OK);
    uint8_t salt_auth_full[32];
    TEST_ASSERT(pk_crypto_hmac_sha256(shared_secret, 32, enc_salt, 32, salt_auth_full) == PK_OK);
    uint8_t salt_auth[16];
    memcpy(salt_auth, salt_auth_full, 16);

    uint8_t get_cdh[32];
    memset(get_cdh, 0x99, 32);
    TEST_ASSERT(pk_crypto_hmac_sha256(pin_token, 32, get_cdh, 32, full_mac) == PK_OK);
    memcpy(pin_auth, full_mac, 16);

    req[0] = CTAP2_CMD_GET_ASSERTION;
    pk_cbor_writer_init(&w, req + 1, sizeof(req) - 1);
    pk_cbor_encode_map_header(&w, 6);
    pk_cbor_encode_uint(&w, 1);
    pk_cbor_encode_tstr_c(&w, "hmac.example.com");
    pk_cbor_encode_uint(&w, 2);
    pk_cbor_encode_bstr(&w, get_cdh, 32);
    pk_cbor_encode_uint(&w, 3);
    pk_cbor_encode_array_header(&w, 1);
    pk_cbor_encode_map_header(&w, 2);
    pk_cbor_encode_tstr_c(&w, "type");
    pk_cbor_encode_tstr_c(&w, "public-key");
    pk_cbor_encode_tstr_c(&w, "id");
    pk_cbor_encode_bstr(&w, cred_id, 64);
    pk_cbor_encode_uint(&w, 4);
    pk_cbor_encode_map_header(&w, 1);
    pk_cbor_encode_tstr_c(&w, "hmac-secret");
    pk_cbor_encode_map_header(&w, 3);
    pk_cbor_encode_uint(&w, 1);
    TEST_ASSERT(pk_cbor_encode_cose_p256_pubkey(&w, &plat_pub, true) == PK_OK);
    pk_cbor_encode_uint(&w, 2);
    pk_cbor_encode_bstr(&w, enc_salt, 32);
    pk_cbor_encode_uint(&w, 3);
    pk_cbor_encode_bstr(&w, salt_auth, 16);
    pk_cbor_encode_uint(&w, 6);
    pk_cbor_encode_bstr(&w, pin_auth, 16);
    pk_cbor_encode_uint(&w, 7);
    pk_cbor_encode_uint(&w, 1);

    req_len = 1 + w.offset;
    pk_ctap2_process_message(&ctap2, req, req_len, resp, sizeof(resp), &resp_len);
    TEST_ASSERT(resp_len > 1 && resp[0] == CTAP2_OK);

    pk_cbor_reader_init(&r, resp + 1, resp_len - 1);
    TEST_ASSERT(pk_cbor_decode_map_header(&r, &map_cnt) == PK_OK);
    auth_data = NULL;
    auth_data_len = 0;
    for (size_t i = 0; i < map_cnt; i++) {
        uint64_t k = 0;
        TEST_ASSERT(pk_cbor_decode_uint(&r, &k) == PK_OK);
        if (k == 2) {
            TEST_ASSERT(pk_cbor_decode_bstr(&r, &auth_data, &auth_data_len) == PK_OK);
        } else {
            TEST_ASSERT(pk_cbor_skip_item(&r) == PK_OK);
        }
    }
    TEST_ASSERT(auth_data != NULL && auth_data_len > 37);
    TEST_ASSERT((auth_data[32] & CTAP2_AUTH_DATA_FLAG_ED) != 0);

    // Extension map at offset 37
    pk_cbor_reader_t ext_r;
    pk_cbor_reader_init(&ext_r, &auth_data[37], auth_data_len - 37);
    size_t ext_cnt = 0;
    TEST_ASSERT(pk_cbor_decode_map_header(&ext_r, &ext_cnt) == PK_OK);
    TEST_ASSERT(ext_cnt == 1);
    const char *ext_name = NULL;
    size_t ext_name_len = 0;
    TEST_ASSERT(pk_cbor_decode_tstr(&ext_r, &ext_name, &ext_name_len) == PK_OK);
    TEST_ASSERT(ext_name_len == 11 && memcmp(ext_name, "hmac-secret", 11) == 0);
    const uint8_t *enc_hmac_output = NULL;
    size_t enc_hmac_output_len = 0;
    TEST_ASSERT(pk_cbor_decode_bstr(&ext_r, &enc_hmac_output, &enc_hmac_output_len) == PK_OK);
    TEST_ASSERT(enc_hmac_output_len == 32);

    // Decrypt hmac-secret output
    uint8_t dec_secret1[32];
    TEST_ASSERT(pk_crypto_aes256_cbc_decrypt_zero_iv(shared_secret, enc_hmac_output, 32, dec_secret1) == PK_OK);

    // Calling GetAssertion again with identical salt must produce identical decrypted secret
    pk_ctap2_process_message(&ctap2, req, req_len, resp, sizeof(resp), &resp_len);
    TEST_ASSERT(resp_len > 1 && resp[0] == CTAP2_OK);
    pk_cbor_reader_init(&r, resp + 1, resp_len - 1);
    TEST_ASSERT(pk_cbor_decode_map_header(&r, &map_cnt) == PK_OK);
    for (size_t i = 0; i < map_cnt; i++) {
        uint64_t k = 0;
        TEST_ASSERT(pk_cbor_decode_uint(&r, &k) == PK_OK);
        if (k == 2) {
            TEST_ASSERT(pk_cbor_decode_bstr(&r, &auth_data, &auth_data_len) == PK_OK);
        } else {
            TEST_ASSERT(pk_cbor_skip_item(&r) == PK_OK);
        }
    }
    pk_cbor_reader_init(&ext_r, &auth_data[37], auth_data_len - 37);
    TEST_ASSERT(pk_cbor_decode_map_header(&ext_r, &ext_cnt) == PK_OK);
    TEST_ASSERT(pk_cbor_decode_tstr(&ext_r, &ext_name, &ext_name_len) == PK_OK);
    TEST_ASSERT(pk_cbor_decode_bstr(&ext_r, &enc_hmac_output, &enc_hmac_output_len) == PK_OK);
    uint8_t dec_secret2[32];
    TEST_ASSERT(pk_crypto_aes256_cbc_decrypt_zero_iv(shared_secret, enc_hmac_output, 32, dec_secret2) == PK_OK);
    TEST_ASSERT(memcmp(dec_secret1, dec_secret2, 32) == 0);

    printf("  [PASS] hmac-secret roundtrip and deterministic derivation verified\n");
}

/* Test 7: credProtect level 3 UV enforcement in GetAssertion */
static void test_cred_protect_levels(void) {
    printf("Running test_cred_protect_levels...\n");
    setup_env();

    ctap_set_pin("123456");
    uint8_t pin_token[32];
    uint8_t perms = PK_PIN_PERM_MC | PK_PIN_PERM_GA;
    TEST_ASSERT(ctap_get_pin_uv_token("123456", perms, pin_token) == CTAP2_OK);

    // MakeCredential with credProtect = 3 (userVerificationRequired)
    uint8_t cdh[32];
    memset(cdh, 0x66, 32);

    uint8_t full_mac[32];
    uint8_t pin_auth[16];
    TEST_ASSERT(pk_crypto_hmac_sha256(pin_token, 32, cdh, 32, full_mac) == PK_OK);
    memcpy(pin_auth, full_mac, 16);

    uint8_t req[1024];
    req[0] = CTAP2_CMD_MAKE_CREDENTIAL;
    pk_cbor_writer_t w;
    pk_cbor_writer_init(&w, req + 1, sizeof(req) - 1);
    pk_cbor_encode_map_header(&w, 8);
    pk_cbor_encode_uint(&w, 1);
    pk_cbor_encode_bstr(&w, cdh, 32);
    pk_cbor_encode_uint(&w, 2);
    pk_cbor_encode_map_header(&w, 1);
    pk_cbor_encode_tstr_c(&w, "id");
    pk_cbor_encode_tstr_c(&w, "cp3.example.com");
    pk_cbor_encode_uint(&w, 3);
    pk_cbor_encode_map_header(&w, 2);
    pk_cbor_encode_tstr_c(&w, "id");
    pk_cbor_encode_bstr(&w, (const uint8_t *)"uid_cp3", 7);
    pk_cbor_encode_tstr_c(&w, "name");
    pk_cbor_encode_tstr_c(&w, "cp3_user");
    pk_cbor_encode_uint(&w, 4);
    pk_cbor_encode_array_header(&w, 1);
    pk_cbor_encode_map_header(&w, 2);
    pk_cbor_encode_tstr_c(&w, "type");
    pk_cbor_encode_tstr_c(&w, "public-key");
    pk_cbor_encode_tstr_c(&w, "alg");
    pk_cbor_encode_int(&w, PK_COSE_ALG_ES256);
    pk_cbor_encode_uint(&w, 6); // extensions
    pk_cbor_encode_map_header(&w, 1);
    pk_cbor_encode_tstr_c(&w, "credProtect");
    pk_cbor_encode_uint(&w, 3); // level 3: userVerificationRequired
    pk_cbor_encode_uint(&w, 7); // options
    pk_cbor_encode_map_header(&w, 2);
    pk_cbor_encode_tstr_c(&w, "rk");
    pk_cbor_encode_bool(&w, true);
    pk_cbor_encode_tstr_c(&w, "up");
    pk_cbor_encode_bool(&w, true);
    pk_cbor_encode_uint(&w, 8);
    pk_cbor_encode_bstr(&w, pin_auth, 16);
    pk_cbor_encode_uint(&w, 9);
    pk_cbor_encode_uint(&w, 1);

    size_t req_len = 1 + w.offset;
    uint8_t resp[1024];
    size_t resp_len = 0;
    pk_ctap2_process_message(&ctap2, req, req_len, resp, sizeof(resp), &resp_len);
    TEST_ASSERT(resp_len > 1 && resp[0] == CTAP2_OK);

    // Extract cred_id
    pk_cbor_reader_t r;
    pk_cbor_reader_init(&r, resp + 1, resp_len - 1);
    size_t map_cnt = 0;
    TEST_ASSERT(pk_cbor_decode_map_header(&r, &map_cnt) == PK_OK);
    const uint8_t *auth_data = NULL;
    size_t auth_data_len = 0;
    for (size_t i = 0; i < map_cnt; i++) {
        uint64_t k = 0;
        TEST_ASSERT(pk_cbor_decode_uint(&r, &k) == PK_OK);
        if (k == 2) {
            TEST_ASSERT(pk_cbor_decode_bstr(&r, &auth_data, &auth_data_len) == PK_OK);
        } else {
            TEST_ASSERT(pk_cbor_skip_item(&r) == PK_OK);
        }
    }
    TEST_ASSERT(auth_data != NULL && auth_data_len >= 119);
    uint16_t cred_id_len = ((uint16_t)auth_data[53] << 8) | auth_data[54];
    TEST_ASSERT(cred_id_len == 64);
    uint8_t cred_id[64];
    memcpy(cred_id, &auth_data[55], 64);

    // Call GetAssertion WITHOUT pinUvAuthParam -> MUST fail with CTAP2_ERR_PIN_REQUIRED or CTAP2_ERR_OPERATION_DENIED
    uint8_t get_cdh[32];
    memset(get_cdh, 0x55, 32);
    req[0] = CTAP2_CMD_GET_ASSERTION;
    pk_cbor_writer_init(&w, req + 1, sizeof(req) - 1);
    pk_cbor_encode_map_header(&w, 3);
    pk_cbor_encode_uint(&w, 1);
    pk_cbor_encode_tstr_c(&w, "cp3.example.com");
    pk_cbor_encode_uint(&w, 2);
    pk_cbor_encode_bstr(&w, get_cdh, 32);
    pk_cbor_encode_uint(&w, 3);
    pk_cbor_encode_array_header(&w, 1);
    pk_cbor_encode_map_header(&w, 2);
    pk_cbor_encode_tstr_c(&w, "type");
    pk_cbor_encode_tstr_c(&w, "public-key");
    pk_cbor_encode_tstr_c(&w, "id");
    pk_cbor_encode_bstr(&w, cred_id, 64);
    req_len = 1 + w.offset;

    pk_ctap2_process_message(&ctap2, req, req_len, resp, sizeof(resp), &resp_len);
    TEST_ASSERT(resp_len >= 1 && (resp[0] == CTAP2_ERR_PIN_REQUIRED || resp[0] == CTAP2_ERR_OPERATION_DENIED));

    // Call GetAssertion WITH valid pinUvAuthParam -> MUST succeed
    TEST_ASSERT(pk_crypto_hmac_sha256(pin_token, 32, get_cdh, 32, full_mac) == PK_OK);
    memcpy(pin_auth, full_mac, 16);

    pk_cbor_writer_init(&w, req + 1, sizeof(req) - 1);
    pk_cbor_encode_map_header(&w, 5);
    pk_cbor_encode_uint(&w, 1);
    pk_cbor_encode_tstr_c(&w, "cp3.example.com");
    pk_cbor_encode_uint(&w, 2);
    pk_cbor_encode_bstr(&w, get_cdh, 32);
    pk_cbor_encode_uint(&w, 3);
    pk_cbor_encode_array_header(&w, 1);
    pk_cbor_encode_map_header(&w, 2);
    pk_cbor_encode_tstr_c(&w, "type");
    pk_cbor_encode_tstr_c(&w, "public-key");
    pk_cbor_encode_tstr_c(&w, "id");
    pk_cbor_encode_bstr(&w, cred_id, 64);
    pk_cbor_encode_uint(&w, 6);
    pk_cbor_encode_bstr(&w, pin_auth, 16);
    pk_cbor_encode_uint(&w, 7);
    pk_cbor_encode_uint(&w, 1);
    req_len = 1 + w.offset;

    pk_ctap2_process_message(&ctap2, req, req_len, resp, sizeof(resp), &resp_len);
    TEST_ASSERT(resp_len >= 1 && resp[0] == CTAP2_OK);

    printf("  [PASS] credProtect level 3 UV enforcement verified\n");
}

int main(void) {
    printf("=== Starting CTAP2 Unit & Integration Tests ===\n");
    setup_env();

    test_authenticator_get_info();
    test_client_pin_lifecycle();
    test_credential_management();
    test_make_credential_cred_protect();
    test_hmac_secret_roundtrip();
    test_cred_protect_levels();
    test_authenticator_reset();

    printf("=== All CTAP2 Tests Passed Successfully! ===\n");
    return 0;
}
