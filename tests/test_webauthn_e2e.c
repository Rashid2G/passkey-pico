#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>

#include "mock_platform.h"
#include "passkey/config.h"
#include "passkey/status.h"
#include "passkey/cbor.h"
#include "passkey/crypto.h"
#include "passkey/storage.h"
#include "passkey/pin.h"
#include "passkey/ctap2.h"
#include "passkey/ctaphid.h"

#define TEST_ASSERT(cond) do { \
    if (!(cond)) { \
        fprintf(stderr, "ASSERTION FAILED at %s:%d: %s\n", __FILE__, __LINE__, #cond); \
        exit(1); \
    } \
} while (0)

#define MAX_CAPTURED_PACKETS 128

typedef struct {
    uint8_t packets[MAX_CAPTURED_PACKETS][PK_HID_PACKET_SIZE];
    size_t count;
} tx_capture_t;

static pk_mock_platform_state_t mock;
static pk_platform_t platform;
static pk_crypto_ctx_t crypto;
static pk_storage_ctx_t storage;
static pk_pin_ctx_t pin;
static pk_ctap2_ctx_t ctap2;
static pk_ctaphid_ctx_t ctaphid;
static tx_capture_t tx_cap;

static void hid_tx_cb(void *tx_ctx, const uint8_t packet[PK_HID_PACKET_SIZE]) {
    tx_capture_t *cap = (tx_capture_t *)tx_ctx;
    if (cap->count < MAX_CAPTURED_PACKETS) {
        memcpy(cap->packets[cap->count], packet, PK_HID_PACKET_SIZE);
        cap->count++;
    }
}

static inline void encode_u32_be(uint8_t *dst, uint32_t val) {
    dst[0] = (uint8_t)(val >> 24);
    dst[1] = (uint8_t)(val >> 16);
    dst[2] = (uint8_t)(val >> 8);
    dst[3] = (uint8_t)(val);
}

static inline uint32_t decode_u32_be(const uint8_t *src) {
    return ((uint32_t)src[0] << 24) |
           ((uint32_t)src[1] << 16) |
           ((uint32_t)src[2] << 8)  |
           ((uint32_t)src[3]);
}

static inline uint16_t decode_u16_be(const uint8_t *src) {
    return (uint16_t)(((uint16_t)src[0] << 8) | (uint16_t)src[1]);
}

static void setup_full_stack(void) {
    memset(&tx_cap, 0, sizeof(tx_cap));
    pk_mock_platform_init(&mock, &platform);
    TEST_ASSERT(pk_crypto_init(&crypto, &platform) == PK_OK);
    TEST_ASSERT(pk_storage_init(&storage, &platform, &crypto) == PK_OK);
    TEST_ASSERT(pk_pin_init(&pin, &platform, &crypto, &storage) == PK_OK);
    TEST_ASSERT(pk_ctap2_init(&ctap2, &platform, &crypto, &storage, &pin) == PK_OK);
    TEST_ASSERT(pk_ctaphid_init(&ctaphid, &platform, &ctap2, hid_tx_cb, &tx_cap) == PK_OK);
}

static void ctaphid_send_payload(pk_ctaphid_ctx_t *hid, uint32_t cid, uint8_t cmd, const uint8_t *payload, size_t len) {
    uint8_t pkt[PK_HID_PACKET_SIZE];
    memset(pkt, 0, sizeof(pkt));

    encode_u32_be(&pkt[0], cid);
    pkt[4] = cmd | CTAPHID_TYPE_INIT;
    pkt[5] = (uint8_t)(len >> 8);
    pkt[6] = (uint8_t)(len & 0xFF);

    size_t init_chunk = (len > 57) ? 57 : len;
    if (payload && init_chunk > 0) {
        memcpy(&pkt[7], payload, init_chunk);
    }
    pk_ctaphid_rx_packet(hid, pkt);

    size_t offset = init_chunk;
    uint8_t seq = 0;
    while (offset < len) {
        memset(pkt, 0, sizeof(pkt));
        encode_u32_be(&pkt[0], cid);
        pkt[4] = seq++ & 0x7FU;
        size_t cont_chunk = len - offset;
        if (cont_chunk > 59) cont_chunk = 59;
        memcpy(&pkt[5], payload + offset, cont_chunk);
        offset += cont_chunk;
        pk_ctaphid_rx_packet(hid, pkt);
    }
}

static int ctaphid_reassemble_response(
    const tx_capture_t *cap,
    uint32_t *out_cid,
    uint8_t *out_cmd,
    uint8_t *out_payload,
    size_t max_payload_len,
    size_t *out_payload_len
) {
    if (!cap || cap->count == 0) return -1;

    // Scan for first packet with INIT bit set
    size_t start_idx = 0;
    while (start_idx < cap->count && (cap->packets[start_idx][4] & CTAPHID_TYPE_INIT) == 0) {
        start_idx++;
    }
    if (start_idx >= cap->count) return -1;

    const uint8_t *first = cap->packets[start_idx];
    *out_cid = decode_u32_be(&first[0]);
    *out_cmd = first[4];
    uint16_t total_len = decode_u16_be(&first[5]);
    *out_payload_len = total_len;

    if (total_len > max_payload_len) return -2;

    size_t copied = 0;
    size_t init_chunk = (total_len > 57) ? 57 : total_len;
    memcpy(out_payload, &first[7], init_chunk);
    copied += init_chunk;

    uint8_t expected_seq = 0;
    for (size_t p = start_idx + 1; p < cap->count && copied < total_len; p++) {
        const uint8_t *cont = cap->packets[p];
        uint32_t cont_cid = decode_u32_be(&cont[0]);
        if (cont_cid != *out_cid) continue;
        uint8_t seq = cont[4];
        if (seq != expected_seq++) return -5;

        size_t remaining = total_len - copied;
        size_t cont_chunk = (remaining > 59) ? 59 : remaining;
        memcpy(out_payload + copied, &cont[5], cont_chunk);
        copied += cont_chunk;
    }

    return (copied == total_len) ? 0 : -3;
}

static uint32_t ctaphid_allocate_channel(pk_ctaphid_ctx_t *hid, tx_capture_t *cap) {
    memset(cap, 0, sizeof(*cap));
    uint8_t nonce[8] = { 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88 };
    ctaphid_send_payload(hid, CTAPHID_BROADCAST_CID, CTAPHID_CMD_INIT, nonce, 8);
    TEST_ASSERT(cap->count >= 1);
    uint32_t r_cid = 0;
    uint8_t r_cmd = 0;
    uint8_t r_payload[64];
    size_t r_len = 0;
    TEST_ASSERT(ctaphid_reassemble_response(cap, &r_cid, &r_cmd, r_payload, sizeof(r_payload), &r_len) == 0);
    TEST_ASSERT(r_len == 17);
    TEST_ASSERT(memcmp(r_payload, nonce, 8) == 0);
    uint32_t assigned_cid = decode_u32_be(&r_payload[8]);
    TEST_ASSERT(assigned_cid != 0 && assigned_cid != CTAPHID_BROADCAST_CID);
    return assigned_cid;
}

static uint8_t ctaphid_call_cbor(
    pk_ctaphid_ctx_t *hid,
    tx_capture_t *cap,
    uint32_t cid,
    const uint8_t *req,
    size_t req_len,
    uint8_t *out_resp,
    size_t max_resp_len,
    size_t *out_resp_len
) {
    memset(cap, 0, sizeof(*cap));
    ctaphid_send_payload(hid, cid, CTAPHID_CMD_CBOR, req, req_len);

    uint32_t r_cid = 0;
    uint8_t r_cmd = 0;
    uint8_t r_payload[PK_CTAP2_MAX_MSG_SIZE];
    size_t r_len = 0;
    int err = ctaphid_reassemble_response(cap, &r_cid, &r_cmd, r_payload, sizeof(r_payload), &r_len);
    TEST_ASSERT(err == 0);
    TEST_ASSERT(r_cid == cid);
    TEST_ASSERT((r_cmd & ~CTAPHID_TYPE_INIT) == (CTAPHID_CMD_CBOR & ~CTAPHID_TYPE_INIT));
    TEST_ASSERT(r_len >= 1);

    uint8_t status = r_payload[0];
    if (out_resp != NULL && r_len > 1) {
        size_t cbor_len = r_len - 1;
        if (cbor_len > max_resp_len) cbor_len = max_resp_len;
        memcpy(out_resp, r_payload + 1, cbor_len);
        if (out_resp_len) *out_resp_len = cbor_len;
    } else if (out_resp_len) {
        *out_resp_len = 0;
    }
    return status;
}

static bool extract_pubkey_from_cert(const uint8_t *cert_der, size_t cert_len, pk_p256_pubkey_t *out_pub) {
    const uint8_t needle[4] = { 0x03, 0x42, 0x00, 0x04 };
    for (size_t i = 0; i + 4 + 64 <= cert_len; i++) {
        if (memcmp(cert_der + i, needle, 4) == 0) {
            memcpy(out_pub->x, cert_der + i + 4, 32);
            memcpy(out_pub->y, cert_der + i + 36, 32);
            return true;
        }
    }
    return false;
}

/* Helper to configure a PIN and get a token over CTAPHID */
static void setup_pin_and_get_token(
    pk_ctaphid_ctx_t *hid,
    tx_capture_t *cap,
    uint32_t cid,
    const char *pin_str,
    uint8_t out_token_32[32]
) {
    // 1. getKeyAgreement
    uint8_t req[512];
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
    uint8_t status = ctaphid_call_cbor(hid, cap, cid, req, req_len, resp, sizeof(resp), &resp_len);
    TEST_ASSERT(status == CTAP2_OK);

    pk_cbor_reader_t r;
    pk_cbor_reader_init(&r, resp, resp_len);
    size_t map_cnt = 0;
    TEST_ASSERT(pk_cbor_decode_map_header(&r, &map_cnt) == PK_OK);
    pk_p256_pubkey_t auth_pub;
    bool found_key = false;
    for (size_t i = 0; i < map_cnt; i++) {
        uint64_t k = 0;
        TEST_ASSERT(pk_cbor_decode_uint(&r, &k) == PK_OK);
        if (k == 1) {
            TEST_ASSERT(pk_cbor_decode_cose_p256_pubkey(&r, &auth_pub) == PK_OK);
            found_key = true;
        } else {
            TEST_ASSERT(pk_cbor_skip_item(&r) == PK_OK);
        }
    }
    TEST_ASSERT(found_key);

    // 2. Platform ECDH
    uint8_t plat_priv[PK_P256_PRIVKEY_LEN];
    pk_p256_pubkey_t plat_pub;
    TEST_ASSERT(pk_crypto_p256_keygen(&crypto, plat_priv, &plat_pub) == PK_OK);

    uint8_t shared_secret[32];
    TEST_ASSERT(pk_crypto_p256_ecdh_shared_secret_sha256(&crypto, plat_priv, &auth_pub, shared_secret) == PK_OK);

    // 3. Set PIN
    uint8_t new_pin_padded[64];
    memset(new_pin_padded, 0, 64);
    memcpy(new_pin_padded, pin_str, strlen(pin_str));

    uint8_t new_pin_enc[64];
    TEST_ASSERT(pk_crypto_aes256_cbc_encrypt_zero_iv(shared_secret, new_pin_padded, 64, new_pin_enc) == PK_OK);

    uint8_t hmac[32];
    TEST_ASSERT(pk_crypto_hmac_sha256(shared_secret, 32, new_pin_enc, 64, hmac) == PK_OK);
    uint8_t pin_auth[16];
    memcpy(pin_auth, hmac, 16);

    req[0] = CTAP2_CMD_CLIENT_PIN;
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
    req_len = 1 + w.offset;

    status = ctaphid_call_cbor(hid, cap, cid, req, req_len, resp, sizeof(resp), &resp_len);
    TEST_ASSERT(status == CTAP2_OK);

    // 4. Get PIN Token
    // Fetch fresh keyAgreement after setPIN per CTAP2 §6.5.5.4
    req[0] = CTAP2_CMD_CLIENT_PIN;
    pk_cbor_writer_init(&w, req + 1, sizeof(req) - 1);
    pk_cbor_encode_map_header(&w, 2);
    pk_cbor_encode_uint(&w, 1);
    pk_cbor_encode_uint(&w, 1);
    pk_cbor_encode_uint(&w, 2);
    pk_cbor_encode_uint(&w, PK_PIN_SUBCMD_GET_KEY_AGREEMENT);
    req_len = 1 + w.offset;

    status = ctaphid_call_cbor(hid, cap, cid, req, req_len, resp, sizeof(resp), &resp_len);
    TEST_ASSERT(status == CTAP2_OK);

    pk_cbor_reader_init(&r, resp, resp_len);
    TEST_ASSERT(pk_cbor_decode_map_header(&r, &map_cnt) == PK_OK);
    found_key = false;
    for (size_t i = 0; i < map_cnt; i++) {
        uint64_t k = 0;
        TEST_ASSERT(pk_cbor_decode_uint(&r, &k) == PK_OK);
        if (k == 1) {
            TEST_ASSERT(pk_cbor_decode_cose_p256_pubkey(&r, &auth_pub) == PK_OK);
            found_key = true;
        } else {
            TEST_ASSERT(pk_cbor_skip_item(&r) == PK_OK);
        }
    }
    TEST_ASSERT(found_key);

    TEST_ASSERT(pk_crypto_p256_keygen(&crypto, plat_priv, &plat_pub) == PK_OK);
    TEST_ASSERT(pk_crypto_p256_ecdh_shared_secret_sha256(&crypto, plat_priv, &auth_pub, shared_secret) == PK_OK);

    uint8_t full_hash[32];
    TEST_ASSERT(pk_crypto_sha256((const uint8_t *)pin_str, strlen(pin_str), full_hash) == PK_OK);
    uint8_t pin_hash_enc[16];
    TEST_ASSERT(pk_crypto_aes256_cbc_encrypt_zero_iv(shared_secret, full_hash, 16, pin_hash_enc) == PK_OK);

    req[0] = CTAP2_CMD_CLIENT_PIN;
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
    req_len = 1 + w.offset;

    status = ctaphid_call_cbor(hid, cap, cid, req, req_len, resp, sizeof(resp), &resp_len);
    TEST_ASSERT(status == CTAP2_OK);

    pk_cbor_reader_init(&r, resp, resp_len);
    TEST_ASSERT(pk_cbor_decode_map_header(&r, &map_cnt) == PK_OK);
    bool found_token = false;
    for (size_t i = 0; i < map_cnt; i++) {
        uint64_t k = 0;
        TEST_ASSERT(pk_cbor_decode_uint(&r, &k) == PK_OK);
        if (k == 2) {
            const uint8_t *enc_tok = NULL;
            size_t enc_tok_len = 0;
            TEST_ASSERT(pk_cbor_decode_bstr(&r, &enc_tok, &enc_tok_len) == PK_OK);
            TEST_ASSERT(enc_tok_len == 32);
            TEST_ASSERT(pk_crypto_aes256_cbc_decrypt_zero_iv(shared_secret, enc_tok, 32, out_token_32) == PK_OK);
            found_token = true;
        } else {
            TEST_ASSERT(pk_cbor_skip_item(&r) == PK_OK);
        }
    }
    TEST_ASSERT(found_token);
}

/* Scenario 1: Non-resident (rk: false) WebAuthn registration & authentication */
static void test_scenario_1_non_resident(void) {
    printf("Running Scenario 1: Non-resident WebAuthn registration & authentication...\n");
    setup_full_stack();

    uint32_t cid = ctaphid_allocate_channel(&ctaphid, &tx_cap);

    // 1. MakeCredential (rk: false, rp.id = "example.com")
    uint8_t cdh_reg[32];
    memset(cdh_reg, 0x11, 32);

    uint8_t req[512];
    req[0] = CTAP2_CMD_MAKE_CREDENTIAL;
    pk_cbor_writer_t w;
    pk_cbor_writer_init(&w, req + 1, sizeof(req) - 1);
    pk_cbor_encode_map_header(&w, 5);

    // 0x01: clientDataHash
    pk_cbor_encode_uint(&w, 1);
    pk_cbor_encode_bstr(&w, cdh_reg, 32);

    // 0x02: rp
    pk_cbor_encode_uint(&w, 2);
    pk_cbor_encode_map_header(&w, 2);
    pk_cbor_encode_tstr_c(&w, "id");
    pk_cbor_encode_tstr_c(&w, "example.com");
    pk_cbor_encode_tstr_c(&w, "name");
    pk_cbor_encode_tstr_c(&w, "Example Non-Resident RP");

    // 0x03: user
    pk_cbor_encode_uint(&w, 3);
    pk_cbor_encode_map_header(&w, 3);
    pk_cbor_encode_tstr_c(&w, "id");
    pk_cbor_encode_bstr(&w, (const uint8_t *)"usr_nr_1", 8);
    pk_cbor_encode_tstr_c(&w, "name");
    pk_cbor_encode_tstr_c(&w, "alice");
    pk_cbor_encode_tstr_c(&w, "displayName");
    pk_cbor_encode_tstr_c(&w, "Alice Non-Resident");

    // 0x04: pubKeyCredParams
    pk_cbor_encode_uint(&w, 4);
    pk_cbor_encode_array_header(&w, 1);
    pk_cbor_encode_map_header(&w, 2);
    pk_cbor_encode_tstr_c(&w, "type");
    pk_cbor_encode_tstr_c(&w, "public-key");
    pk_cbor_encode_tstr_c(&w, "alg");
    pk_cbor_encode_int(&w, PK_COSE_ALG_ES256);

    // 0x07: options { "rk": false, "up": true }
    pk_cbor_encode_uint(&w, 7);
    pk_cbor_encode_map_header(&w, 2);
    pk_cbor_encode_tstr_c(&w, "rk");
    pk_cbor_encode_bool(&w, false);
    pk_cbor_encode_tstr_c(&w, "up");
    pk_cbor_encode_bool(&w, true);

    size_t req_len = 1 + w.offset;
    uint8_t resp[1024];
    size_t resp_len = 0;
    uint8_t status = ctaphid_call_cbor(&ctaphid, &tx_cap, cid, req, req_len, resp, sizeof(resp), &resp_len);
    TEST_ASSERT(status == CTAP2_OK);

    // Parse MakeCredential response: map { 1: fmt ("packed"), 2: authData, 3: attStmt }
    pk_cbor_reader_t r;
    pk_cbor_reader_init(&r, resp, resp_len);
    size_t map_cnt = 0;
    TEST_ASSERT(pk_cbor_decode_map_header(&r, &map_cnt) == PK_OK);

    const uint8_t *auth_data = NULL;
    size_t auth_data_len = 0;
    const uint8_t *att_sig = NULL;
    size_t att_sig_len = 0;
    const uint8_t *att_cert = NULL;
    size_t att_cert_len = 0;

    for (size_t i = 0; i < map_cnt; i++) {
        uint64_t k = 0;
        TEST_ASSERT(pk_cbor_decode_uint(&r, &k) == PK_OK);
        if (k == 2) { // authData
            TEST_ASSERT(pk_cbor_decode_bstr(&r, &auth_data, &auth_data_len) == PK_OK);
        } else if (k == 3) { // attStmt
            size_t stmt_cnt = 0;
            TEST_ASSERT(pk_cbor_decode_map_header(&r, &stmt_cnt) == PK_OK);
            for (size_t j = 0; j < stmt_cnt; j++) {
                const char *stmt_key = NULL;
                size_t sk_len = 0;
                TEST_ASSERT(pk_cbor_decode_tstr(&r, &stmt_key, &sk_len) == PK_OK);
                if (sk_len == 3 && memcmp(stmt_key, "sig", 3) == 0) {
                    TEST_ASSERT(pk_cbor_decode_bstr(&r, &att_sig, &att_sig_len) == PK_OK);
                } else if (sk_len == 3 && memcmp(stmt_key, "x5c", 3) == 0) {
                    size_t x5c_cnt = 0;
                    TEST_ASSERT(pk_cbor_decode_array_header(&r, &x5c_cnt) == PK_OK);
                    TEST_ASSERT(x5c_cnt >= 1);
                    TEST_ASSERT(pk_cbor_decode_bstr(&r, &att_cert, &att_cert_len) == PK_OK);
                    for (size_t extra = 1; extra < x5c_cnt; extra++) {
                        TEST_ASSERT(pk_cbor_skip_item(&r) == PK_OK);
                    }
                } else {
                    TEST_ASSERT(pk_cbor_skip_item(&r) == PK_OK);
                }
            }
        } else {
            TEST_ASSERT(pk_cbor_skip_item(&r) == PK_OK);
        }
    }

    TEST_ASSERT(auth_data != NULL && auth_data_len >= 119);
    TEST_ASSERT(att_sig != NULL && att_sig_len > 0);
    TEST_ASSERT(att_cert != NULL && att_cert_len > 0);

    // Verify authData RP ID hash equals SHA-256("example.com")
    uint8_t expected_rp_hash[32];
    TEST_ASSERT(pk_crypto_sha256((const uint8_t *)"example.com", 11, expected_rp_hash) == PK_OK);
    TEST_ASSERT(memcmp(auth_data, expected_rp_hash, 32) == 0);

    // Verify UP and AT flags are set (byte 32)
    uint8_t flags = auth_data[32];
    TEST_ASSERT((flags & CTAP2_AUTH_DATA_FLAG_UP) != 0);
    TEST_ASSERT((flags & CTAP2_AUTH_DATA_FLAG_AT) != 0);

    // Verify signature over authData || clientDataHash with attestation certificate public key (x5c)
    pk_p256_pubkey_t att_pub;
    TEST_ASSERT(extract_pubkey_from_cert(att_cert, att_cert_len, &att_pub));

    uint8_t sig_hash[32];
    TEST_ASSERT(pk_crypto_sha256_two(auth_data, auth_data_len, cdh_reg, 32, sig_hash) == PK_OK);
    TEST_ASSERT(pk_crypto_p256_verify_der(&att_pub, sig_hash, att_sig, att_sig_len) == PK_OK);

    // Extract the 64-byte credentialId and COSE ES256 public key from authData
    uint16_t cred_id_len = ((uint16_t)auth_data[53] << 8) | auth_data[54];
    TEST_ASSERT(cred_id_len == 64);
    uint8_t cred_id[64];
    memcpy(cred_id, &auth_data[55], 64);

    pk_p256_pubkey_t cred_pub;
    pk_cbor_reader_t cose_r;
    pk_cbor_reader_init(&cose_r, &auth_data[119], auth_data_len - 119);
    TEST_ASSERT(pk_cbor_decode_cose_p256_pubkey(&cose_r, &cred_pub) == PK_OK);

    // 2. Perform authenticatorGetAssertion with allowList: [{"type": "public-key", "id": credentialId}]
    uint8_t cdh_auth1[32];
    memset(cdh_auth1, 0x22, 32);

    req[0] = CTAP2_CMD_GET_ASSERTION;
    pk_cbor_writer_init(&w, req + 1, sizeof(req) - 1);
    pk_cbor_encode_map_header(&w, 3);

    // 0x01: rpId
    pk_cbor_encode_uint(&w, 1);
    pk_cbor_encode_tstr_c(&w, "example.com");

    // 0x02: clientDataHash
    pk_cbor_encode_uint(&w, 2);
    pk_cbor_encode_bstr(&w, cdh_auth1, 32);

    // 0x03: allowList
    pk_cbor_encode_uint(&w, 3);
    pk_cbor_encode_array_header(&w, 1);
    pk_cbor_encode_map_header(&w, 2);
    pk_cbor_encode_tstr_c(&w, "type");
    pk_cbor_encode_tstr_c(&w, "public-key");
    pk_cbor_encode_tstr_c(&w, "id");
    pk_cbor_encode_bstr(&w, cred_id, 64);

    req_len = 1 + w.offset;
    status = ctaphid_call_cbor(&ctaphid, &tx_cap, cid, req, req_len, resp, sizeof(resp), &resp_len);
    TEST_ASSERT(status == CTAP2_OK);

    // Parse GetAssertion response: map { 1: credential, 2: authData, 3: signature }
    pk_cbor_reader_init(&r, resp, resp_len);
    TEST_ASSERT(pk_cbor_decode_map_header(&r, &map_cnt) == PK_OK);

    const uint8_t *assert_auth_data = NULL;
    size_t assert_auth_data_len = 0;
    const uint8_t *assert_sig = NULL;
    size_t assert_sig_len = 0;

    for (size_t i = 0; i < map_cnt; i++) {
        uint64_t k = 0;
        TEST_ASSERT(pk_cbor_decode_uint(&r, &k) == PK_OK);
        if (k == 2) {
            TEST_ASSERT(pk_cbor_decode_bstr(&r, &assert_auth_data, &assert_auth_data_len) == PK_OK);
        } else if (k == 3) {
            TEST_ASSERT(pk_cbor_decode_bstr(&r, &assert_sig, &assert_sig_len) == PK_OK);
        } else {
            TEST_ASSERT(pk_cbor_skip_item(&r) == PK_OK);
        }
    }

    TEST_ASSERT(assert_auth_data != NULL && assert_auth_data_len == 37);
    TEST_ASSERT(assert_sig != NULL && assert_sig_len > 0);

    // Verify assertion signature over authData || clientDataHash using pk_crypto_p256_verify_der
    uint8_t assert_hash[32];
    TEST_ASSERT(pk_crypto_sha256_two(assert_auth_data, assert_auth_data_len, cdh_auth1, 32, assert_hash) == PK_OK);
    TEST_ASSERT(pk_crypto_p256_verify_der(&cred_pub, assert_hash, assert_sig, assert_sig_len) == PK_OK);

    uint32_t counter1 = decode_u32_be(&assert_auth_data[33]);

    // 3. Verify signature counter strictly increments across assertions
    uint8_t cdh_auth2[32];
    memset(cdh_auth2, 0x33, 32);

    req[0] = CTAP2_CMD_GET_ASSERTION;
    pk_cbor_writer_init(&w, req + 1, sizeof(req) - 1);
    pk_cbor_encode_map_header(&w, 3);
    pk_cbor_encode_uint(&w, 1);
    pk_cbor_encode_tstr_c(&w, "example.com");
    pk_cbor_encode_uint(&w, 2);
    pk_cbor_encode_bstr(&w, cdh_auth2, 32);
    pk_cbor_encode_uint(&w, 3);
    pk_cbor_encode_array_header(&w, 1);
    pk_cbor_encode_map_header(&w, 2);
    pk_cbor_encode_tstr_c(&w, "type");
    pk_cbor_encode_tstr_c(&w, "public-key");
    pk_cbor_encode_tstr_c(&w, "id");
    pk_cbor_encode_bstr(&w, cred_id, 64);

    req_len = 1 + w.offset;
    status = ctaphid_call_cbor(&ctaphid, &tx_cap, cid, req, req_len, resp, sizeof(resp), &resp_len);
    TEST_ASSERT(status == CTAP2_OK);

    pk_cbor_reader_init(&r, resp, resp_len);
    TEST_ASSERT(pk_cbor_decode_map_header(&r, &map_cnt) == PK_OK);
    assert_auth_data = NULL;
    assert_sig = NULL;
    for (size_t i = 0; i < map_cnt; i++) {
        uint64_t k = 0;
        TEST_ASSERT(pk_cbor_decode_uint(&r, &k) == PK_OK);
        if (k == 2) {
            TEST_ASSERT(pk_cbor_decode_bstr(&r, &assert_auth_data, &assert_auth_data_len) == PK_OK);
        } else if (k == 3) {
            TEST_ASSERT(pk_cbor_decode_bstr(&r, &assert_sig, &assert_sig_len) == PK_OK);
        } else {
            TEST_ASSERT(pk_cbor_skip_item(&r) == PK_OK);
        }
    }
    TEST_ASSERT(assert_auth_data != NULL && assert_auth_data_len == 37);
    uint32_t counter2 = decode_u32_be(&assert_auth_data[33]);
    TEST_ASSERT(counter2 > counter1);

    // Verify 2nd assertion signature
    TEST_ASSERT(pk_crypto_sha256_two(assert_auth_data, assert_auth_data_len, cdh_auth2, 32, assert_hash) == PK_OK);
    TEST_ASSERT(pk_crypto_p256_verify_der(&cred_pub, assert_hash, assert_sig, assert_sig_len) == PK_OK);

    printf("  [PASS] Scenario 1 non-resident registration, attestation, and assertion verified\n");
}

/* Scenario 2: Resident / Discoverable Passkey (rk: true) with PIN and power cycle */
static void test_scenario_2_resident_power_cycle(void) {
    printf("Running Scenario 2: Resident Passkey with PIN across power cycle...\n");
    setup_full_stack();

    uint32_t cid = ctaphid_allocate_channel(&ctaphid, &tx_cap);

    // 1. Configure PIN and get token
    uint8_t pin_token[32];
    setup_pin_and_get_token(&ctaphid, &tx_cap, cid, "pass1234", pin_token);

    // 2. MakeCredential with rk: true and pinUvAuthParam (uv: true)
    uint8_t cdh_reg[32];
    memset(cdh_reg, 0x44, 32);

    uint8_t hmac_auth[32];
    uint8_t pin_auth[16];
    TEST_ASSERT(pk_crypto_hmac_sha256(pin_token, 32, cdh_reg, 32, hmac_auth) == PK_OK);
    memcpy(pin_auth, hmac_auth, 16);

    uint8_t user_id[4] = { 0x41, 0x42, 0x43, 0x44 };

    uint8_t req[512];
    req[0] = CTAP2_CMD_MAKE_CREDENTIAL;
    pk_cbor_writer_t w;
    pk_cbor_writer_init(&w, req + 1, sizeof(req) - 1);
    pk_cbor_encode_map_header(&w, 7);

    // 0x01: clientDataHash
    pk_cbor_encode_uint(&w, 1);
    pk_cbor_encode_bstr(&w, cdh_reg, 32);

    // 0x02: rp
    pk_cbor_encode_uint(&w, 2);
    pk_cbor_encode_map_header(&w, 2);
    pk_cbor_encode_tstr_c(&w, "id");
    pk_cbor_encode_tstr_c(&w, "login.example.com");
    pk_cbor_encode_tstr_c(&w, "name");
    pk_cbor_encode_tstr_c(&w, "Login Example");

    // 0x03: user
    pk_cbor_encode_uint(&w, 3);
    pk_cbor_encode_map_header(&w, 3);
    pk_cbor_encode_tstr_c(&w, "id");
    pk_cbor_encode_bstr(&w, user_id, sizeof(user_id));
    pk_cbor_encode_tstr_c(&w, "name");
    pk_cbor_encode_tstr_c(&w, "alice");
    pk_cbor_encode_tstr_c(&w, "displayName");
    pk_cbor_encode_tstr_c(&w, "Alice Smith");

    // 0x04: pubKeyCredParams
    pk_cbor_encode_uint(&w, 4);
    pk_cbor_encode_array_header(&w, 1);
    pk_cbor_encode_map_header(&w, 2);
    pk_cbor_encode_tstr_c(&w, "type");
    pk_cbor_encode_tstr_c(&w, "public-key");
    pk_cbor_encode_tstr_c(&w, "alg");
    pk_cbor_encode_int(&w, PK_COSE_ALG_ES256);

    // 0x07: options { "rk": true, "up": true }
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
    uint8_t status = ctaphid_call_cbor(&ctaphid, &tx_cap, cid, req, req_len, resp, sizeof(resp), &resp_len);
    TEST_ASSERT(status == CTAP2_OK);

    // Extract credential public key from authData
    pk_cbor_reader_t r;
    pk_cbor_reader_init(&r, resp, resp_len);
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
    pk_p256_pubkey_t resident_pub;
    pk_cbor_reader_t cose_r;
    pk_cbor_reader_init(&cose_r, &auth_data[119], auth_data_len - 119);
    TEST_ASSERT(pk_cbor_decode_cose_p256_pubkey(&cose_r, &resident_pub) == PK_OK);

    // 3. Simulate power cycle (re-initializing storage, pin, ctap2, ctaphid on the same flash image)
    memset(&tx_cap, 0, sizeof(tx_cap));
    TEST_ASSERT(pk_crypto_init(&crypto, &platform) == PK_OK);
    TEST_ASSERT(pk_storage_init(&storage, &platform, &crypto) == PK_OK);
    TEST_ASSERT(pk_pin_init(&pin, &platform, &crypto, &storage) == PK_OK);
    TEST_ASSERT(pk_ctap2_init(&ctap2, &platform, &crypto, &storage, &pin) == PK_OK);
    TEST_ASSERT(pk_ctaphid_init(&ctaphid, &platform, &ctap2, hid_tx_cb, &tx_cap) == PK_OK);

    // Allocate fresh channel after reboot
    cid = ctaphid_allocate_channel(&ctaphid, &tx_cap);

    // 4. Passwordless authentication (authenticatorGetAssertion with empty allowList)
    uint8_t cdh_auth[32];
    memset(cdh_auth, 0x66, 32);

    req[0] = CTAP2_CMD_GET_ASSERTION;
    pk_cbor_writer_init(&w, req + 1, sizeof(req) - 1);
    pk_cbor_encode_map_header(&w, 2);
    pk_cbor_encode_uint(&w, 1);
    pk_cbor_encode_tstr_c(&w, "login.example.com");
    pk_cbor_encode_uint(&w, 2);
    pk_cbor_encode_bstr(&w, cdh_auth, 32);

    req_len = 1 + w.offset;
    status = ctaphid_call_cbor(&ctaphid, &tx_cap, cid, req, req_len, resp, sizeof(resp), &resp_len);
    TEST_ASSERT(status == CTAP2_OK);

    // Decode and verify user handle and signature
    pk_cbor_reader_init(&r, resp, resp_len);
    TEST_ASSERT(pk_cbor_decode_map_header(&r, &map_cnt) == PK_OK);

    const uint8_t *assert_auth_data = NULL;
    size_t assert_auth_data_len = 0;
    const uint8_t *assert_sig = NULL;
    size_t assert_sig_len = 0;
    bool found_user = false;
    bool verified_user_id = false;
    bool verified_user_name = false;
    bool verified_display_name = false;

    for (size_t i = 0; i < map_cnt; i++) {
        uint64_t k = 0;
        TEST_ASSERT(pk_cbor_decode_uint(&r, &k) == PK_OK);
        if (k == 2) {
            TEST_ASSERT(pk_cbor_decode_bstr(&r, &assert_auth_data, &assert_auth_data_len) == PK_OK);
        } else if (k == 3) {
            TEST_ASSERT(pk_cbor_decode_bstr(&r, &assert_sig, &assert_sig_len) == PK_OK);
        } else if (k == 4) { // user
            found_user = true;
            size_t u_cnt = 0;
            TEST_ASSERT(pk_cbor_decode_map_header(&r, &u_cnt) == PK_OK);
            for (size_t u = 0; u < u_cnt; u++) {
                const char *u_key = NULL;
                size_t uk_len = 0;
                TEST_ASSERT(pk_cbor_decode_tstr(&r, &u_key, &uk_len) == PK_OK);
                if (uk_len == 2 && memcmp(u_key, "id", 2) == 0) {
                    const uint8_t *uid = NULL;
                    size_t uid_len = 0;
                    TEST_ASSERT(pk_cbor_decode_bstr(&r, &uid, &uid_len) == PK_OK);
                    TEST_ASSERT(uid_len == 4 && memcmp(uid, user_id, 4) == 0);
                    verified_user_id = true;
                } else if (uk_len == 4 && memcmp(u_key, "name", 4) == 0) {
                    const char *uname = NULL;
                    size_t un_len = 0;
                    TEST_ASSERT(pk_cbor_decode_tstr(&r, &uname, &un_len) == PK_OK);
                    TEST_ASSERT(un_len == 5 && memcmp(uname, "alice", 5) == 0);
                    verified_user_name = true;
                } else if (uk_len == 11 && memcmp(u_key, "displayName", 11) == 0) {
                    const char *udn = NULL;
                    size_t udn_len = 0;
                    TEST_ASSERT(pk_cbor_decode_tstr(&r, &udn, &udn_len) == PK_OK);
                    TEST_ASSERT(udn_len == 11 && memcmp(udn, "Alice Smith", 11) == 0);
                    verified_display_name = true;
                } else {
                    TEST_ASSERT(pk_cbor_skip_item(&r) == PK_OK);
                }
            }
        } else {
            TEST_ASSERT(pk_cbor_skip_item(&r) == PK_OK);
        }
    }

    TEST_ASSERT(found_user && verified_user_id && verified_user_name && verified_display_name);
    TEST_ASSERT(assert_auth_data != NULL && assert_auth_data_len == 37);
    TEST_ASSERT(assert_sig != NULL && assert_sig_len > 0);

    // Cryptographic signature verification with resident_pub
    uint8_t assert_hash[32];
    TEST_ASSERT(pk_crypto_sha256_two(assert_auth_data, assert_auth_data_len, cdh_auth, 32, assert_hash) == PK_OK);
    TEST_ASSERT(pk_crypto_p256_verify_der(&resident_pub, assert_hash, assert_sig, assert_sig_len) == PK_OK);

    printf("  [PASS] Scenario 2 resident passkey verified across simulated power cycle\n");
}

/* Scenario 3: Multi-account resident credentials on the same RP */
static void test_scenario_3_multi_account(void) {
    printf("Running Scenario 3: Multi-account resident credentials on the same RP...\n");
    setup_full_stack();

    uint32_t cid = ctaphid_allocate_channel(&ctaphid, &tx_cap);

    // Register credential 1: alice@example.com
    uint8_t cdh1[32];
    memset(cdh1, 0x71, 32);

    uint8_t req[512];
    req[0] = CTAP2_CMD_MAKE_CREDENTIAL;
    pk_cbor_writer_t w;
    pk_cbor_writer_init(&w, req + 1, sizeof(req) - 1);
    pk_cbor_encode_map_header(&w, 5);
    pk_cbor_encode_uint(&w, 1);
    pk_cbor_encode_bstr(&w, cdh1, 32);
    pk_cbor_encode_uint(&w, 2);
    pk_cbor_encode_map_header(&w, 2);
    pk_cbor_encode_tstr_c(&w, "id");
    pk_cbor_encode_tstr_c(&w, "accounts.example.com");
    pk_cbor_encode_tstr_c(&w, "name");
    pk_cbor_encode_tstr_c(&w, "Accounts Service");
    pk_cbor_encode_uint(&w, 3);
    pk_cbor_encode_map_header(&w, 3);
    pk_cbor_encode_tstr_c(&w, "id");
    pk_cbor_encode_bstr(&w, (const uint8_t *)"alice_uid", 9);
    pk_cbor_encode_tstr_c(&w, "name");
    pk_cbor_encode_tstr_c(&w, "alice@example.com");
    pk_cbor_encode_tstr_c(&w, "displayName");
    pk_cbor_encode_tstr_c(&w, "Alice Cooper");
    pk_cbor_encode_uint(&w, 4);
    pk_cbor_encode_array_header(&w, 1);
    pk_cbor_encode_map_header(&w, 2);
    pk_cbor_encode_tstr_c(&w, "type");
    pk_cbor_encode_tstr_c(&w, "public-key");
    pk_cbor_encode_tstr_c(&w, "alg");
    pk_cbor_encode_int(&w, PK_COSE_ALG_ES256);
    pk_cbor_encode_uint(&w, 7);
    pk_cbor_encode_map_header(&w, 2);
    pk_cbor_encode_tstr_c(&w, "rk");
    pk_cbor_encode_bool(&w, true);
    pk_cbor_encode_tstr_c(&w, "up");
    pk_cbor_encode_bool(&w, true);

    size_t req_len = 1 + w.offset;
    uint8_t resp[1024];
    size_t resp_len = 0;
    uint8_t status = ctaphid_call_cbor(&ctaphid, &tx_cap, cid, req, req_len, resp, sizeof(resp), &resp_len);
    TEST_ASSERT(status == CTAP2_OK);

    // Extract Alice's public key
    pk_cbor_reader_t r;
    pk_cbor_reader_init(&r, resp, resp_len);
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
    pk_p256_pubkey_t alice_pub;
    pk_cbor_reader_t cose_r;
    pk_cbor_reader_init(&cose_r, &auth_data[119], auth_data_len - 119);
    TEST_ASSERT(pk_cbor_decode_cose_p256_pubkey(&cose_r, &alice_pub) == PK_OK);

    // Advance clock and register credential 2: bob@example.com
    pk_mock_platform_advance_time(&mock, 100);

    uint8_t cdh2[32];
    memset(cdh2, 0x72, 32);

    req[0] = CTAP2_CMD_MAKE_CREDENTIAL;
    pk_cbor_writer_init(&w, req + 1, sizeof(req) - 1);
    pk_cbor_encode_map_header(&w, 5);
    pk_cbor_encode_uint(&w, 1);
    pk_cbor_encode_bstr(&w, cdh2, 32);
    pk_cbor_encode_uint(&w, 2);
    pk_cbor_encode_map_header(&w, 2);
    pk_cbor_encode_tstr_c(&w, "id");
    pk_cbor_encode_tstr_c(&w, "accounts.example.com");
    pk_cbor_encode_tstr_c(&w, "name");
    pk_cbor_encode_tstr_c(&w, "Accounts Service");
    pk_cbor_encode_uint(&w, 3);
    pk_cbor_encode_map_header(&w, 3);
    pk_cbor_encode_tstr_c(&w, "id");
    pk_cbor_encode_bstr(&w, (const uint8_t *)"bob_uid", 7);
    pk_cbor_encode_tstr_c(&w, "name");
    pk_cbor_encode_tstr_c(&w, "bob@example.com");
    pk_cbor_encode_tstr_c(&w, "displayName");
    pk_cbor_encode_tstr_c(&w, "Bob Builder");
    pk_cbor_encode_uint(&w, 4);
    pk_cbor_encode_array_header(&w, 1);
    pk_cbor_encode_map_header(&w, 2);
    pk_cbor_encode_tstr_c(&w, "type");
    pk_cbor_encode_tstr_c(&w, "public-key");
    pk_cbor_encode_tstr_c(&w, "alg");
    pk_cbor_encode_int(&w, PK_COSE_ALG_ES256);
    pk_cbor_encode_uint(&w, 7);
    pk_cbor_encode_map_header(&w, 2);
    pk_cbor_encode_tstr_c(&w, "rk");
    pk_cbor_encode_bool(&w, true);
    pk_cbor_encode_tstr_c(&w, "up");
    pk_cbor_encode_bool(&w, true);

    req_len = 1 + w.offset;
    status = ctaphid_call_cbor(&ctaphid, &tx_cap, cid, req, req_len, resp, sizeof(resp), &resp_len);
    TEST_ASSERT(status == CTAP2_OK);

    // Extract Bob's public key
    pk_cbor_reader_init(&r, resp, resp_len);
    TEST_ASSERT(pk_cbor_decode_map_header(&r, &map_cnt) == PK_OK);
    auth_data = NULL;
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
    pk_p256_pubkey_t bob_pub;
    pk_cbor_reader_init(&cose_r, &auth_data[119], auth_data_len - 119);
    TEST_ASSERT(pk_cbor_decode_cose_p256_pubkey(&cose_r, &bob_pub) == PK_OK);

    // Call authenticatorGetAssertion with empty allowList
    uint8_t cdh_multi[32];
    memset(cdh_multi, 0x88, 32);

    req[0] = CTAP2_CMD_GET_ASSERTION;
    pk_cbor_writer_init(&w, req + 1, sizeof(req) - 1);
    pk_cbor_encode_map_header(&w, 2);
    pk_cbor_encode_uint(&w, 1);
    pk_cbor_encode_tstr_c(&w, "accounts.example.com");
    pk_cbor_encode_uint(&w, 2);
    pk_cbor_encode_bstr(&w, cdh_multi, 32);

    req_len = 1 + w.offset;
    status = ctaphid_call_cbor(&ctaphid, &tx_cap, cid, req, req_len, resp, sizeof(resp), &resp_len);
    TEST_ASSERT(status == CTAP2_OK);

    // Decode first assertion: must have numberOfCredentials == 2
    pk_cbor_reader_init(&r, resp, resp_len);
    TEST_ASSERT(pk_cbor_decode_map_header(&r, &map_cnt) == PK_OK);

    const uint8_t *auth1 = NULL;
    size_t auth1_len = 0;
    const uint8_t *sig1 = NULL;
    size_t sig1_len = 0;
    uint64_t num_creds = 0;
    char user1_name[64] = {0};

    for (size_t i = 0; i < map_cnt; i++) {
        uint64_t k = 0;
        TEST_ASSERT(pk_cbor_decode_uint(&r, &k) == PK_OK);
        if (k == 2) {
            TEST_ASSERT(pk_cbor_decode_bstr(&r, &auth1, &auth1_len) == PK_OK);
        } else if (k == 3) {
            TEST_ASSERT(pk_cbor_decode_bstr(&r, &sig1, &sig1_len) == PK_OK);
        } else if (k == 4) { // user
            size_t u_cnt = 0;
            TEST_ASSERT(pk_cbor_decode_map_header(&r, &u_cnt) == PK_OK);
            for (size_t u = 0; u < u_cnt; u++) {
                const char *uk = NULL;
                size_t uk_len = 0;
                TEST_ASSERT(pk_cbor_decode_tstr(&r, &uk, &uk_len) == PK_OK);
                if (uk_len == 4 && memcmp(uk, "name", 4) == 0) {
                    const char *un = NULL;
                    size_t un_len = 0;
                    TEST_ASSERT(pk_cbor_decode_tstr(&r, &un, &un_len) == PK_OK);
                    if (un_len < sizeof(user1_name)) {
                        memcpy(user1_name, un, un_len);
                    }
                } else {
                    TEST_ASSERT(pk_cbor_skip_item(&r) == PK_OK);
                }
            }
        } else if (k == 5) { // numberOfCredentials
            TEST_ASSERT(pk_cbor_decode_uint(&r, &num_creds) == PK_OK);
        } else {
            TEST_ASSERT(pk_cbor_skip_item(&r) == PK_OK);
        }
    }
    TEST_ASSERT(num_creds >= 2);
    TEST_ASSERT(auth1 != NULL && sig1 != NULL);

    // Verify first assertion signature with the corresponding public key
    uint8_t hash1[32];
    TEST_ASSERT(pk_crypto_sha256_two(auth1, auth1_len, cdh_multi, 32, hash1) == PK_OK);
    if (strcmp(user1_name, "bob@example.com") == 0) {
        TEST_ASSERT(pk_crypto_p256_verify_der(&bob_pub, hash1, sig1, sig1_len) == PK_OK);
    } else {
        TEST_ASSERT(pk_crypto_p256_verify_der(&alice_pub, hash1, sig1, sig1_len) == PK_OK);
    }

    // Call authenticatorGetNextAssertion (0x08)
    req[0] = CTAP2_CMD_GET_NEXT_ASSERTION;
    status = ctaphid_call_cbor(&ctaphid, &tx_cap, cid, req, 1, resp, sizeof(resp), &resp_len);
    TEST_ASSERT(status == CTAP2_OK);

    pk_cbor_reader_init(&r, resp, resp_len);
    TEST_ASSERT(pk_cbor_decode_map_header(&r, &map_cnt) == PK_OK);

    const uint8_t *auth2 = NULL;
    size_t auth2_len = 0;
    const uint8_t *sig2 = NULL;
    size_t sig2_len = 0;
    char user2_name[64] = {0};

    for (size_t i = 0; i < map_cnt; i++) {
        uint64_t k = 0;
        TEST_ASSERT(pk_cbor_decode_uint(&r, &k) == PK_OK);
        if (k == 2) {
            TEST_ASSERT(pk_cbor_decode_bstr(&r, &auth2, &auth2_len) == PK_OK);
        } else if (k == 3) {
            TEST_ASSERT(pk_cbor_decode_bstr(&r, &sig2, &sig2_len) == PK_OK);
        } else if (k == 4) {
            size_t u_cnt = 0;
            TEST_ASSERT(pk_cbor_decode_map_header(&r, &u_cnt) == PK_OK);
            for (size_t u = 0; u < u_cnt; u++) {
                const char *uk = NULL;
                size_t uk_len = 0;
                TEST_ASSERT(pk_cbor_decode_tstr(&r, &uk, &uk_len) == PK_OK);
                if (uk_len == 4 && memcmp(uk, "name", 4) == 0) {
                    const char *un = NULL;
                    size_t un_len = 0;
                    TEST_ASSERT(pk_cbor_decode_tstr(&r, &un, &un_len) == PK_OK);
                    if (un_len < sizeof(user2_name)) {
                        memcpy(user2_name, un, un_len);
                    }
                } else {
                    TEST_ASSERT(pk_cbor_skip_item(&r) == PK_OK);
                }
            }
        } else {
            TEST_ASSERT(pk_cbor_skip_item(&r) == PK_OK);
        }
    }
    TEST_ASSERT(auth2 != NULL && sig2 != NULL);
    TEST_ASSERT(strcmp(user1_name, user2_name) != 0);

    // Verify second assertion signature
    uint8_t hash2[32];
    TEST_ASSERT(pk_crypto_sha256_two(auth2, auth2_len, cdh_multi, 32, hash2) == PK_OK);
    if (strcmp(user2_name, "bob@example.com") == 0) {
        TEST_ASSERT(pk_crypto_p256_verify_der(&bob_pub, hash2, sig2, sig2_len) == PK_OK);
    } else {
        TEST_ASSERT(pk_crypto_p256_verify_der(&alice_pub, hash2, sig2, sig2_len) == PK_OK);
    }

    // Calling GetNextAssertion again when no more credentials exist should return CTAP2_ERR_NOT_ALLOWED (0x30)
    status = ctaphid_call_cbor(&ctaphid, &tx_cap, cid, req, 1, resp, sizeof(resp), &resp_len);
    TEST_ASSERT(status == CTAP2_ERR_NOT_ALLOWED);

    printf("  [PASS] Scenario 3 multi-account GetAssertion and GetNextAssertion verified\n");
}

/* Scenario 4: Relying Party isolation check */
static void test_scenario_4_rp_isolation(void) {
    printf("Running Scenario 4: Relying Party isolation check...\n");
    setup_full_stack();

    uint32_t cid = ctaphid_allocate_channel(&ctaphid, &tx_cap);

    // Register credential for example.com
    uint8_t cdh[32];
    memset(cdh, 0x91, 32);

    uint8_t req[512];
    req[0] = CTAP2_CMD_MAKE_CREDENTIAL;
    pk_cbor_writer_t w;
    pk_cbor_writer_init(&w, req + 1, sizeof(req) - 1);
    pk_cbor_encode_map_header(&w, 4);
    pk_cbor_encode_uint(&w, 1);
    pk_cbor_encode_bstr(&w, cdh, 32);
    pk_cbor_encode_uint(&w, 2);
    pk_cbor_encode_map_header(&w, 2);
    pk_cbor_encode_tstr_c(&w, "id");
    pk_cbor_encode_tstr_c(&w, "example.com");
    pk_cbor_encode_tstr_c(&w, "name");
    pk_cbor_encode_tstr_c(&w, "Example Legitimate RP");
    pk_cbor_encode_uint(&w, 3);
    pk_cbor_encode_map_header(&w, 2);
    pk_cbor_encode_tstr_c(&w, "id");
    pk_cbor_encode_bstr(&w, (const uint8_t *)"user_iso", 8);
    pk_cbor_encode_tstr_c(&w, "name");
    pk_cbor_encode_tstr_c(&w, "user_iso");
    pk_cbor_encode_uint(&w, 4);
    pk_cbor_encode_array_header(&w, 1);
    pk_cbor_encode_map_header(&w, 2);
    pk_cbor_encode_tstr_c(&w, "type");
    pk_cbor_encode_tstr_c(&w, "public-key");
    pk_cbor_encode_tstr_c(&w, "alg");
    pk_cbor_encode_int(&w, PK_COSE_ALG_ES256);

    size_t req_len = 1 + w.offset;
    uint8_t resp[1024];
    size_t resp_len = 0;
    uint8_t status = ctaphid_call_cbor(&ctaphid, &tx_cap, cid, req, req_len, resp, sizeof(resp), &resp_len);
    TEST_ASSERT(status == CTAP2_OK);

    // Extract cred_id
    pk_cbor_reader_t r;
    pk_cbor_reader_init(&r, resp, resp_len);
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
    uint8_t example_cred_id[64];
    memcpy(example_cred_id, &auth_data[55], 64);

    // 1. Verify credential presented to "evil.example.com" is rejected with CTAP2_ERR_NO_CREDENTIALS (0x2E)
    req[0] = CTAP2_CMD_GET_ASSERTION;
    pk_cbor_writer_init(&w, req + 1, sizeof(req) - 1);
    pk_cbor_encode_map_header(&w, 3);
    pk_cbor_encode_uint(&w, 1);
    pk_cbor_encode_tstr_c(&w, "evil.example.com");
    pk_cbor_encode_uint(&w, 2);
    pk_cbor_encode_bstr(&w, cdh, 32);
    pk_cbor_encode_uint(&w, 3);
    pk_cbor_encode_array_header(&w, 1);
    pk_cbor_encode_map_header(&w, 2);
    pk_cbor_encode_tstr_c(&w, "type");
    pk_cbor_encode_tstr_c(&w, "public-key");
    pk_cbor_encode_tstr_c(&w, "id");
    pk_cbor_encode_bstr(&w, example_cred_id, 64);

    req_len = 1 + w.offset;
    status = ctaphid_call_cbor(&ctaphid, &tx_cap, cid, req, req_len, resp, sizeof(resp), &resp_len);
    TEST_ASSERT(status == CTAP2_ERR_NO_CREDENTIALS);

    // 2. Verify excludeList prevents duplicate registration (CTAP2_ERR_CREDENTIAL_EXCLUDED = 0x19)
    req[0] = CTAP2_CMD_MAKE_CREDENTIAL;
    pk_cbor_writer_init(&w, req + 1, sizeof(req) - 1);
    pk_cbor_encode_map_header(&w, 5);
    pk_cbor_encode_uint(&w, 1);
    pk_cbor_encode_bstr(&w, cdh, 32);
    pk_cbor_encode_uint(&w, 2);
    pk_cbor_encode_map_header(&w, 2);
    pk_cbor_encode_tstr_c(&w, "id");
    pk_cbor_encode_tstr_c(&w, "example.com");
    pk_cbor_encode_tstr_c(&w, "name");
    pk_cbor_encode_tstr_c(&w, "Example Corp");
    pk_cbor_encode_uint(&w, 3);
    pk_cbor_encode_map_header(&w, 2);
    pk_cbor_encode_tstr_c(&w, "id");
    pk_cbor_encode_bstr(&w, (const uint8_t *)"user2", 5);
    pk_cbor_encode_tstr_c(&w, "name");
    pk_cbor_encode_tstr_c(&w, "user2");
    pk_cbor_encode_uint(&w, 4);
    pk_cbor_encode_array_header(&w, 1);
    pk_cbor_encode_map_header(&w, 2);
    pk_cbor_encode_tstr_c(&w, "type");
    pk_cbor_encode_tstr_c(&w, "public-key");
    pk_cbor_encode_tstr_c(&w, "alg");
    pk_cbor_encode_int(&w, PK_COSE_ALG_ES256);
    pk_cbor_encode_uint(&w, 5); // excludeList
    pk_cbor_encode_array_header(&w, 1);
    pk_cbor_encode_map_header(&w, 2);
    pk_cbor_encode_tstr_c(&w, "type");
    pk_cbor_encode_tstr_c(&w, "public-key");
    pk_cbor_encode_tstr_c(&w, "id");
    pk_cbor_encode_bstr(&w, example_cred_id, 64);

    req_len = 1 + w.offset;
    status = ctaphid_call_cbor(&ctaphid, &tx_cap, cid, req, req_len, resp, sizeof(resp), &resp_len);
    TEST_ASSERT(status == CTAP2_ERR_CREDENTIAL_EXCLUDED);

    printf("  [PASS] Scenario 4 RP isolation and excludeList rejection verified\n");
}

/* Scenario 5: Chromium & Firefox U2F / CTAP1 fallback and UP timeout / cancel */
static void test_scenario_5_u2f_fallback_and_up_errors(void) {
    printf("Running Scenario 5: U2F / CTAP1 fallback and User Presence error handling...\n");
    setup_full_stack();

    uint32_t cid = ctaphid_allocate_channel(&ctaphid, &tx_cap);

    // 1. Chromium & Firefox U2F fallback (CTAPHID_CMD_MSG with U2F_VERSION APDU 00 03 00 00 00 00 00)
    const uint8_t u2f_ver_apdu[7] = { 0x00, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00 };
    memset(&tx_cap, 0, sizeof(tx_cap));
    ctaphid_send_payload(&ctaphid, cid, CTAPHID_CMD_MSG, u2f_ver_apdu, sizeof(u2f_ver_apdu));

    uint32_t r_cid = 0;
    uint8_t r_cmd = 0;
    uint8_t r_payload[64];
    size_t r_len = 0;
    TEST_ASSERT(ctaphid_reassemble_response(&tx_cap, &r_cid, &r_cmd, r_payload, sizeof(r_payload), &r_len) == 0);
    TEST_ASSERT(r_cid == cid);
    TEST_ASSERT((r_cmd & ~CTAPHID_TYPE_INIT) == (CTAPHID_CMD_MSG & ~CTAPHID_TYPE_INIT));

    // Expected response: "U2F_V2" followed by SW 0x9000 (8 bytes total)
    TEST_ASSERT(r_len == 8);
    TEST_ASSERT(memcmp(r_payload, "U2F_V2\x90\x00", 8) == 0);

    // 2. User Presence timeout handling (CTAP2_ERR_USER_ACTION_TIMEOUT = 0x2F)
    mock.next_up_result = PK_UP_TIMEOUT;

    uint8_t cdh[32];
    memset(cdh, 0xAA, 32);

    uint8_t req[512];
    req[0] = CTAP2_CMD_MAKE_CREDENTIAL;
    pk_cbor_writer_t w;
    pk_cbor_writer_init(&w, req + 1, sizeof(req) - 1);
    pk_cbor_encode_map_header(&w, 4);
    pk_cbor_encode_uint(&w, 1);
    pk_cbor_encode_bstr(&w, cdh, 32);
    pk_cbor_encode_uint(&w, 2);
    pk_cbor_encode_map_header(&w, 2);
    pk_cbor_encode_tstr_c(&w, "id");
    pk_cbor_encode_tstr_c(&w, "example.com");
    pk_cbor_encode_tstr_c(&w, "name");
    pk_cbor_encode_tstr_c(&w, "Example");
    pk_cbor_encode_uint(&w, 3);
    pk_cbor_encode_map_header(&w, 2);
    pk_cbor_encode_tstr_c(&w, "id");
    pk_cbor_encode_bstr(&w, (const uint8_t *)"uid", 3);
    pk_cbor_encode_tstr_c(&w, "name");
    pk_cbor_encode_tstr_c(&w, "uid");
    pk_cbor_encode_uint(&w, 4);
    pk_cbor_encode_array_header(&w, 1);
    pk_cbor_encode_map_header(&w, 2);
    pk_cbor_encode_tstr_c(&w, "type");
    pk_cbor_encode_tstr_c(&w, "public-key");
    pk_cbor_encode_tstr_c(&w, "alg");
    pk_cbor_encode_int(&w, PK_COSE_ALG_ES256);

    size_t req_len = 1 + w.offset;
    uint8_t resp[256];
    size_t resp_len = 0;
    uint8_t status = ctaphid_call_cbor(&ctaphid, &tx_cap, cid, req, req_len, resp, sizeof(resp), &resp_len);
    TEST_ASSERT(status == CTAP2_ERR_USER_ACTION_TIMEOUT);

    // 3. User Presence cancel handling (CTAP2_ERR_KEEPALIVE_CANCEL = 0x2D)
    mock.next_up_result = PK_UP_CANCELLED;
    status = ctaphid_call_cbor(&ctaphid, &tx_cap, cid, req, req_len, resp, sizeof(resp), &resp_len);
    TEST_ASSERT(status == CTAP2_ERR_KEEPALIVE_CANCEL);

    // Reset UP result to confirmed
    mock.next_up_result = PK_UP_CONFIRMED;

    printf("  [PASS] Scenario 5 U2F fallback, UP timeout, and UP cancel verified\n");
}

int main(void) {
    printf("=== Starting WebAuthn End-to-End Tests ===\n");

    test_scenario_1_non_resident();
    test_scenario_2_resident_power_cycle();
    test_scenario_3_multi_account();
    test_scenario_4_rp_isolation();
    test_scenario_5_u2f_fallback_and_up_errors();

    printf("=== All WebAuthn E2E Tests Passed Successfully! ===\n");
    return 0;
}
