#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include "passkey/crypto.h"
#include "passkey/cbor.h"
#include "passkey/status.h"
#include "passkey/config.h"
#include "mock_platform.h"

#define TEST_PASS_MSG(test_name) printf("  [PASS] %s\n", (test_name))
#define TEST_ASSERT(cond, msg) do { \
    if (!(cond)) { \
        fprintf(stderr, "  [FAIL] %s:%d: %s (%s)\n", __FILE__, __LINE__, msg, #cond); \
        return 1; \
    } \
} while (0)

/* 1. Test SHA-256 against NIST test vector ("abc") and two-buffer variation */
static int test_sha256(void)
{
    /* NIST SHA-256 test vector for "abc" */
    static const uint8_t nist_input[] = "abc";
    static const uint8_t nist_expected[PK_SHA256_LEN] = {
        0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea,
        0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23,
        0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c,
        0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad
    };

    uint8_t hash[PK_SHA256_LEN];
    pk_err_t err = pk_crypto_sha256(nist_input, 3, hash);
    TEST_ASSERT(err == PK_OK, "pk_crypto_sha256 failed");
    TEST_ASSERT(memcmp(hash, nist_expected, PK_SHA256_LEN) == 0, "SHA-256 digest does not match NIST vector");

    /* Test pk_crypto_sha256_two with split buffers ("a" + "bc") */
    uint8_t hash_two[PK_SHA256_LEN];
    err = pk_crypto_sha256_two((const uint8_t *)"a", 1, (const uint8_t *)"bc", 2, hash_two);
    TEST_ASSERT(err == PK_OK, "pk_crypto_sha256_two failed");
    TEST_ASSERT(memcmp(hash_two, nist_expected, PK_SHA256_LEN) == 0, "SHA-256 two-buffer digest mismatch");

    TEST_PASS_MSG("SHA-256 (NIST vector and two-buffer)");
    return 0;
}

/* 2. Test HMAC-SHA-256 against RFC 4231 and HKDF-SHA-256 against RFC 5869 */
static int test_hmac_and_hkdf(void)
{
    /* RFC 4231 Test Case 1:
     * Key = 20 bytes of 0x0b
     * Data = "Hi There" (8 bytes)
     */
    uint8_t key1[20];
    memset(key1, 0x0b, sizeof(key1));
    static const uint8_t data1[] = "Hi There";
    static const uint8_t expected_hmac1[PK_SHA256_LEN] = {
        0xb0, 0x34, 0x4c, 0x61, 0xd8, 0xdb, 0x38, 0x53,
        0x5c, 0xa8, 0xaf, 0xce, 0xaf, 0x0b, 0xf1, 0x2b,
        0x88, 0x1d, 0xc2, 0x00, 0xc9, 0x83, 0x3d, 0xa7,
        0x26, 0xe9, 0x37, 0x6c, 0x2e, 0x32, 0xcf, 0xf7
    };

    uint8_t mac1[PK_SHA256_LEN];
    pk_err_t err = pk_crypto_hmac_sha256(key1, sizeof(key1), data1, 8, mac1);
    TEST_ASSERT(err == PK_OK, "pk_crypto_hmac_sha256 case 1 failed");
    TEST_ASSERT(memcmp(mac1, expected_hmac1, PK_SHA256_LEN) == 0, "HMAC RFC 4231 Case 1 mismatch");

    /* RFC 4231 Test Case 2:
     * Key = "Jefe" (4 bytes)
     * Data = "what do ya want for nothing?" (28 bytes)
     */
    static const uint8_t key2[] = "Jefe";
    static const uint8_t data2[] = "what do ya want for nothing?";
    static const uint8_t expected_hmac2[PK_SHA256_LEN] = {
        0x5b, 0xdc, 0xc1, 0x46, 0xbf, 0x60, 0x75, 0x4e,
        0x6a, 0x04, 0x24, 0x26, 0x08, 0x95, 0x75, 0xc7,
        0x5a, 0x00, 0x3f, 0x08, 0x9d, 0x27, 0x39, 0x83,
        0x9d, 0xec, 0x58, 0xb9, 0x64, 0xec, 0x38, 0x43
    };

    uint8_t mac2[PK_SHA256_LEN];
    err = pk_crypto_hmac_sha256(key2, 4, data2, 28, mac2);
    TEST_ASSERT(err == PK_OK, "pk_crypto_hmac_sha256 case 2 failed");
    TEST_ASSERT(memcmp(mac2, expected_hmac2, PK_SHA256_LEN) == 0, "HMAC RFC 4231 Case 2 mismatch");

    /* RFC 5869 Test Case 1 (HKDF-SHA-256):
     * IKM  = 22 bytes of 0x0b
     * salt = 13 bytes: 0x00, 0x01, ..., 0x0c
     * info = 10 bytes: 0xf0, 0xf1, ..., 0xf9
     * L    = 42 bytes
     */
    uint8_t ikm[22];
    memset(ikm, 0x0b, sizeof(ikm));
    static const uint8_t salt[13] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c
    };
    static const uint8_t info[10] = {
        0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7,
        0xf8, 0xf9
    };
    static const uint8_t expected_okm[42] = {
        0x3c, 0xb2, 0x5f, 0x25, 0xfa, 0xac, 0xd5, 0x7a,
        0x90, 0x43, 0x4f, 0x64, 0xd0, 0x36, 0x2f, 0x2a,
        0x2d, 0x2d, 0x0a, 0x90, 0xcf, 0x1a, 0x5a, 0x4c,
        0x5d, 0xb0, 0x2d, 0x56, 0xec, 0xc4, 0xc5, 0xbf,
        0x34, 0x00, 0x72, 0x08, 0xd5, 0xb8, 0x87, 0x18,
        0x58, 0x65
    };

    uint8_t okm[42];
    err = pk_crypto_hkdf_sha256(salt, sizeof(salt), ikm, sizeof(ikm), info, sizeof(info), okm, 42);
    TEST_ASSERT(err == PK_OK, "pk_crypto_hkdf_sha256 failed");
    TEST_ASSERT(memcmp(okm, expected_okm, 42) == 0, "HKDF RFC 5869 Case 1 mismatch");

    TEST_PASS_MSG("HMAC-SHA-256 (RFC 4231) and HKDF-SHA-256 (RFC 5869)");
    return 0;
}

/* 3. Test AES-256-CBC encrypt & decrypt round-trip with zero IV and verify rejection of non-16-byte-multiples */
static int test_aes256_cbc(void)
{
    uint8_t key[32];
    for (size_t i = 0; i < sizeof(key); ++i) {
        key[i] = (uint8_t)(i * 7 + 1);
    }

    uint8_t plaintext[48];
    for (size_t i = 0; i < sizeof(plaintext); ++i) {
        plaintext[i] = (uint8_t)(0xAA ^ (uint8_t)i);
    }

    uint8_t ciphertext[48];
    uint8_t decrypted[48];

    /* Valid round-trip (48 bytes = 3 * 16) */
    pk_err_t err = pk_crypto_aes256_cbc_encrypt_zero_iv(key, plaintext, 48, ciphertext);
    TEST_ASSERT(err == PK_OK, "AES encrypt 48 bytes failed");
    TEST_ASSERT(memcmp(plaintext, ciphertext, 48) != 0, "Ciphertext should differ from plaintext");

    err = pk_crypto_aes256_cbc_decrypt_zero_iv(key, ciphertext, 48, decrypted);
    TEST_ASSERT(err == PK_OK, "AES decrypt 48 bytes failed");
    TEST_ASSERT(memcmp(plaintext, decrypted, 48) == 0, "AES decrypted text does not match plaintext");

    /* Round-trip with 16 bytes (1 block) */
    err = pk_crypto_aes256_cbc_encrypt_zero_iv(key, plaintext, 16, ciphertext);
    TEST_ASSERT(err == PK_OK, "AES encrypt 16 bytes failed");
    err = pk_crypto_aes256_cbc_decrypt_zero_iv(key, ciphertext, 16, decrypted);
    TEST_ASSERT(err == PK_OK, "AES decrypt 16 bytes failed");
    TEST_ASSERT(memcmp(plaintext, decrypted, 16) == 0, "AES 16-byte round-trip mismatch");

    /* Non-16-byte-multiple length rejection */
    err = pk_crypto_aes256_cbc_encrypt_zero_iv(key, plaintext, 0, ciphertext);
    TEST_ASSERT(err != PK_OK, "AES encrypt len=0 should be rejected");

    err = pk_crypto_aes256_cbc_encrypt_zero_iv(key, plaintext, 15, ciphertext);
    TEST_ASSERT(err != PK_OK, "AES encrypt len=15 should be rejected");

    err = pk_crypto_aes256_cbc_encrypt_zero_iv(key, plaintext, 17, ciphertext);
    TEST_ASSERT(err != PK_OK, "AES encrypt len=17 should be rejected");

    err = pk_crypto_aes256_cbc_encrypt_zero_iv(key, plaintext, 31, ciphertext);
    TEST_ASSERT(err != PK_OK, "AES encrypt len=31 should be rejected");

    err = pk_crypto_aes256_cbc_decrypt_zero_iv(key, ciphertext, 0, decrypted);
    TEST_ASSERT(err != PK_OK, "AES decrypt len=0 should be rejected");

    err = pk_crypto_aes256_cbc_decrypt_zero_iv(key, ciphertext, 15, decrypted);
    TEST_ASSERT(err != PK_OK, "AES decrypt len=15 should be rejected");

    err = pk_crypto_aes256_cbc_decrypt_zero_iv(key, ciphertext, 17, decrypted);
    TEST_ASSERT(err != PK_OK, "AES decrypt len=17 should be rejected");

    TEST_PASS_MSG("AES-256-CBC round-trip and non-16-byte rejection");
    return 0;
}

/* 4. Test P-256 keygen, deterministic derivation, ECDSA DER sign/verify, tampering detection */
static int test_p256_and_ecdsa(pk_crypto_ctx_t *ctx)
{
    uint8_t priv[PK_P256_PRIVKEY_LEN];
    pk_p256_pubkey_t pub;

    /* Key generation */
    pk_err_t err = pk_crypto_p256_keygen(ctx, priv, &pub);
    TEST_ASSERT(err == PK_OK, "pk_crypto_p256_keygen failed");

    /* Verify public key matches private key scalar */
    pk_p256_pubkey_t pub_from_priv;
    err = pk_crypto_p256_pubkey_from_priv(priv, &pub_from_priv);
    TEST_ASSERT(err == PK_OK, "pk_crypto_p256_pubkey_from_priv failed");
    TEST_ASSERT(memcmp(&pub, &pub_from_priv, sizeof(pk_p256_pubkey_t)) == 0,
                "Pubkey from private scalar mismatch");

    /* Deterministic credential key derivation */
    uint8_t master_secret[32];
    uint8_t rp_id_hash[32];
    uint8_t cred_random[32];
    memset(master_secret, 0x11, sizeof(master_secret));
    memset(rp_id_hash, 0x22, sizeof(rp_id_hash));
    memset(cred_random, 0x33, sizeof(cred_random));

    uint8_t det_priv1[PK_P256_PRIVKEY_LEN];
    pk_p256_pubkey_t det_pub1;
    err = pk_crypto_derive_credential_keypair(master_secret, rp_id_hash, cred_random, det_priv1, &det_pub1);
    TEST_ASSERT(err == PK_OK, "Deterministic key derivation 1 failed");

    /* Identical inputs produce identical keypair */
    uint8_t det_priv2[PK_P256_PRIVKEY_LEN];
    pk_p256_pubkey_t det_pub2;
    err = pk_crypto_derive_credential_keypair(master_secret, rp_id_hash, cred_random, det_priv2, &det_pub2);
    TEST_ASSERT(err == PK_OK, "Deterministic key derivation 2 failed");
    TEST_ASSERT(memcmp(det_priv1, det_priv2, 32) == 0, "Deterministic private keys should be identical");
    TEST_ASSERT(memcmp(&det_pub1, &det_pub2, sizeof(pk_p256_pubkey_t)) == 0, "Deterministic pubkeys should be identical");

    /* Different rp_id_hash produces distinct keypair */
    uint8_t diff_rp_id_hash[32];
    memcpy(diff_rp_id_hash, rp_id_hash, 32);
    diff_rp_id_hash[0] ^= 0xFF;
    uint8_t det_priv3[PK_P256_PRIVKEY_LEN];
    pk_p256_pubkey_t det_pub3;
    err = pk_crypto_derive_credential_keypair(master_secret, diff_rp_id_hash, cred_random, det_priv3, &det_pub3);
    TEST_ASSERT(err == PK_OK, "Deterministic key derivation with diff rp_id_hash failed");
    TEST_ASSERT(memcmp(det_priv1, det_priv3, 32) != 0, "Keys for distinct RP IDs must differ");

    /* Different cred_random produces distinct keypair */
    uint8_t diff_cred_random[32];
    memcpy(diff_cred_random, cred_random, 32);
    diff_cred_random[0] ^= 0xFF;
    uint8_t det_priv4[PK_P256_PRIVKEY_LEN];
    pk_p256_pubkey_t det_pub4;
    err = pk_crypto_derive_credential_keypair(master_secret, rp_id_hash, diff_cred_random, det_priv4, &det_pub4);
    TEST_ASSERT(err == PK_OK, "Deterministic key derivation with diff cred_random failed");
    TEST_ASSERT(memcmp(det_priv1, det_priv4, 32) != 0, "Keys for distinct cred_random must differ");

    /* ECDSA DER signing and verification */
    static const uint8_t test_msg[] = "FIDO2 WebAuthn Assertion Signature Test";
    uint8_t hash[PK_SHA256_LEN];
    pk_crypto_sha256(test_msg, strlen((const char *)test_msg), hash);

    uint8_t sig[PK_ECDSA_MAX_DER_SIG_LEN];
    size_t sig_len = 0;
    err = pk_crypto_p256_sign_der(ctx, det_priv1, hash, sig, &sig_len);
    TEST_ASSERT(err == PK_OK, "ECDSA sign DER failed");
    TEST_ASSERT(sig_len > 0 && sig_len <= PK_ECDSA_MAX_DER_SIG_LEN, "Invalid DER signature length");
    TEST_ASSERT(sig[0] == 0x30, "DER signature must start with ASN.1 SEQUENCE 0x30");

    /* Verification with corresponding public key */
    err = pk_crypto_p256_verify_der(&det_pub1, hash, sig, sig_len);
    TEST_ASSERT(err == PK_OK, "ECDSA verify DER failed with authentic signature");

    /* Verification failure on tampered message digest */
    uint8_t tampered_hash[PK_SHA256_LEN];
    memcpy(tampered_hash, hash, PK_SHA256_LEN);
    tampered_hash[0] ^= 0x01;
    err = pk_crypto_p256_verify_der(&det_pub1, tampered_hash, sig, sig_len);
    TEST_ASSERT(err != PK_OK, "ECDSA verify must fail on tampered message hash");

    /* Verification failure on tampered signature */
    uint8_t tampered_sig[PK_ECDSA_MAX_DER_SIG_LEN];
    memcpy(tampered_sig, sig, sig_len);
    tampered_sig[sig_len - 1] ^= 0x01;
    err = pk_crypto_p256_verify_der(&det_pub1, hash, tampered_sig, sig_len);
    TEST_ASSERT(err != PK_OK, "ECDSA verify must fail on tampered signature");

    /* Verification failure with wrong public key */
    err = pk_crypto_p256_verify_der(&det_pub3, hash, sig, sig_len);
    TEST_ASSERT(err != PK_OK, "ECDSA verify must fail with mismatched public key");

    TEST_PASS_MSG("P-256 Keygen, deterministic derivation, ECDSA sign/verify, tamper detection");
    return 0;
}

/* 5. Test Low-S normalization in ECDSA signatures (RFC 6979 / BIP-62 / FIDO2) */
static int test_low_s_normalization(pk_crypto_ctx_t *ctx)
{
    /* Half-order n/2 for secp256r1 */
    static const uint8_t secp256r1_half_order[32] = {
        0x7F, 0xFF, 0xFF, 0xFF, 0x80, 0x00, 0x00, 0x00,
        0x7F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xDE, 0x73, 0x7D, 0x56, 0xD3, 0x8B, 0xCE, 0x42,
        0x79, 0xDC, 0xB5, 0x61, 0x7E, 0x31, 0x92, 0xA8
    };

    uint8_t priv[PK_P256_PRIVKEY_LEN];
    pk_p256_pubkey_t pub;
    pk_err_t err = pk_crypto_p256_keygen(ctx, priv, &pub);
    TEST_ASSERT(err == PK_OK, "Keygen failed");

    /* Generate multiple signatures and verify 100% of them satisfy s <= n/2 */
    for (int i = 0; i < 32; ++i) {
        uint8_t msg[32];
        memset(msg, (uint8_t)(i * 11 + 3), sizeof(msg));
        uint8_t sig[PK_ECDSA_MAX_DER_SIG_LEN];
        size_t sig_len = 0;
        err = pk_crypto_p256_sign_der(ctx, priv, msg, sig, &sig_len);
        TEST_ASSERT(err == PK_OK, "Signing failed");

        TEST_ASSERT(sig[0] == 0x30, "Sig must start with 0x30");
        TEST_ASSERT(sig[2] == 0x02, "r tag must be 0x02");
        size_t r_len = sig[3];
        size_t s_tag_pos = 4 + r_len;
        TEST_ASSERT(s_tag_pos < sig_len, "s tag offset out of range");
        TEST_ASSERT(sig[s_tag_pos] == 0x02, "s tag must be 0x02");
        size_t s_len = sig[s_tag_pos + 1];
        const uint8_t *s_val = &sig[s_tag_pos + 2];
        if (s_len == 33 && s_val[0] == 0x00) {
            s_val++;
            s_len--;
        }
        TEST_ASSERT(s_len <= 32, "s length invalid");

        uint8_t s_32[32];
        memset(s_32, 0, sizeof(s_32));
        memcpy(&s_32[32 - s_len], s_val, s_len);

        TEST_ASSERT(memcmp(s_32, secp256r1_half_order, 32) <= 0,
                    "ECDSA signature s must be <= n/2 (low-S normalization check)");
        TEST_ASSERT(pk_crypto_p256_verify_der(&pub, msg, sig, sig_len) == PK_OK,
                    "Normalized signature must verify cleanly");
    }

    TEST_PASS_MSG("Low-S normalization (s <= n/2 enforced across all signatures)");
    return 0;
}

/* 6. Test fail-closed behavior on hardware RNG fault */
static int test_rng_failure_mode(pk_crypto_ctx_t *ctx, pk_mock_platform_state_t *mock)
{
    mock->rng_failure = true;
    uint8_t priv[PK_P256_PRIVKEY_LEN];
    pk_p256_pubkey_t pub;
    pk_err_t err = pk_crypto_p256_keygen(ctx, priv, &pub);
    TEST_ASSERT(err != PK_OK, "pk_crypto_p256_keygen must fail when hardware RNG fails");

    uint8_t hash[PK_SHA256_LEN] = { 0x42 };
    uint8_t sig[PK_ECDSA_MAX_DER_SIG_LEN];
    size_t sig_len = 0;
    err = pk_crypto_p256_sign_der(ctx, priv, hash, sig, &sig_len);
    TEST_ASSERT(err != PK_OK, "pk_crypto_p256_sign_der must fail when hardware RNG fails");

    mock->rng_failure = false;
    TEST_PASS_MSG("Hardware RNG failure closed behavior (safe fail on RNG fault)");
    return 0;
}

/* 7. Test ECDH P-256 shared secret computation between Alice and Bob */
static int test_ecdh_shared_secret(pk_crypto_ctx_t *ctx)
{
    uint8_t priv_alice[PK_P256_PRIVKEY_LEN];
    pk_p256_pubkey_t pub_alice;
    uint8_t priv_bob[PK_P256_PRIVKEY_LEN];
    pk_p256_pubkey_t pub_bob;

    pk_err_t err = pk_crypto_p256_keygen(ctx, priv_alice, &pub_alice);
    TEST_ASSERT(err == PK_OK, "Alice keygen failed");
    err = pk_crypto_p256_keygen(ctx, priv_bob, &pub_bob);
    TEST_ASSERT(err == PK_OK, "Bob keygen failed");

    uint8_t secret_alice[PK_SHA256_LEN];
    uint8_t secret_bob[PK_SHA256_LEN];

    /* Alice computes shared secret using Alice's priv and Bob's pub */
    err = pk_crypto_p256_ecdh_shared_secret_sha256(ctx, priv_alice, &pub_bob, secret_alice);
    TEST_ASSERT(err == PK_OK, "Alice ECDH computation failed");

    /* Bob computes shared secret using Bob's priv and Alice's pub */
    err = pk_crypto_p256_ecdh_shared_secret_sha256(ctx, priv_bob, &pub_alice, secret_bob);
    TEST_ASSERT(err == PK_OK, "Bob ECDH computation failed");

    TEST_ASSERT(memcmp(secret_alice, secret_bob, PK_SHA256_LEN) == 0,
                "ECDH SHA-256(Z) shared secret must be identical on both sides");

    TEST_PASS_MSG("ECDH P-256 shared secret (Alice & Bob agreement)");
    return 0;
}

/* 8. Test non-resident credential ID sealing and unsealing */
static int test_seal_unseal_credential(pk_crypto_ctx_t *ctx)
{
    uint8_t cred_mac_key[32];
    uint8_t rp_id_hash[32];
    memset(cred_mac_key, 0x44, sizeof(cred_mac_key));
    memset(rp_id_hash, 0x55, sizeof(rp_id_hash));

    uint8_t cred_id[PK_CRED_ID_NONRESIDENT_LEN];
    uint8_t cred_random[32];

    pk_err_t err = pk_crypto_seal_nonresident_cred_id(ctx, cred_mac_key, rp_id_hash, cred_id, cred_random);
    TEST_ASSERT(err == PK_OK, "pk_crypto_seal_nonresident_cred_id failed");
    TEST_ASSERT(memcmp(cred_id, cred_random, 32) == 0, "First 32 bytes of cred_id must be cred_random");

    /* Valid unseal */
    uint8_t unsealed_random[32];
    err = pk_crypto_unseal_nonresident_cred_id(cred_mac_key, rp_id_hash, cred_id, unsealed_random);
    TEST_ASSERT(err == PK_OK, "pk_crypto_unseal_nonresident_cred_id failed");
    TEST_ASSERT(memcmp(unsealed_random, cred_random, 32) == 0, "Unsealed cred_random mismatch");

    /* Wrong rp_id_hash fails with PK_ERR_AUTH_FAILED */
    uint8_t wrong_rp[32];
    memcpy(wrong_rp, rp_id_hash, 32);
    wrong_rp[0] ^= 0x01;
    err = pk_crypto_unseal_nonresident_cred_id(cred_mac_key, wrong_rp, cred_id, unsealed_random);
    TEST_ASSERT(err == PK_ERR_AUTH_FAILED, "Unseal with wrong rp_id_hash must return PK_ERR_AUTH_FAILED");

    /* Wrong cred_mac_key fails with PK_ERR_AUTH_FAILED */
    uint8_t wrong_key[32];
    memcpy(wrong_key, cred_mac_key, 32);
    wrong_key[0] ^= 0x01;
    err = pk_crypto_unseal_nonresident_cred_id(wrong_key, rp_id_hash, cred_id, unsealed_random);
    TEST_ASSERT(err == PK_ERR_AUTH_FAILED, "Unseal with wrong MAC key must return PK_ERR_AUTH_FAILED");

    /* Flipped bit in random part (byte 0) fails with PK_ERR_AUTH_FAILED */
    uint8_t tampered_id[PK_CRED_ID_NONRESIDENT_LEN];
    memcpy(tampered_id, cred_id, PK_CRED_ID_NONRESIDENT_LEN);
    tampered_id[0] ^= 0x01;
    err = pk_crypto_unseal_nonresident_cred_id(cred_mac_key, rp_id_hash, tampered_id, unsealed_random);
    TEST_ASSERT(err == PK_ERR_AUTH_FAILED, "Unseal with tampered random portion must return PK_ERR_AUTH_FAILED");

    /* Flipped bit in MAC part (byte 40) fails with PK_ERR_AUTH_FAILED */
    memcpy(tampered_id, cred_id, PK_CRED_ID_NONRESIDENT_LEN);
    tampered_id[40] ^= 0x01;
    err = pk_crypto_unseal_nonresident_cred_id(cred_mac_key, rp_id_hash, tampered_id, unsealed_random);
    TEST_ASSERT(err == PK_ERR_AUTH_FAILED, "Unseal with tampered MAC portion must return PK_ERR_AUTH_FAILED");

    TEST_PASS_MSG("Non-resident credential ID seal/unseal and tamper rejection");
    return 0;
}

/* 9. Test attestation certificate generation */
static int test_attestation_cert(pk_crypto_ctx_t *ctx)
{
    uint8_t attestation_seed[32];
    memset(attestation_seed, 0x88, sizeof(attestation_seed));

    uint8_t attest_priv[PK_P256_PRIVKEY_LEN];
    uint8_t cert_der[1024];
    size_t cert_len = 0;

    pk_err_t err = pk_crypto_build_attestation_cert_der(
        ctx,
        attestation_seed,
        attest_priv,
        cert_der,
        sizeof(cert_der),
        &cert_len
    );
    TEST_ASSERT(err == PK_OK, "pk_crypto_build_attestation_cert_der failed");
    TEST_ASSERT(cert_len > 0, "Attestation certificate length must be > 0");
    TEST_ASSERT(cert_der[0] == 0x30, "DER certificate must begin with ASN.1 SEQUENCE (0x30)");

    /* Verify deterministic private key derivation from seed */
    uint8_t attest_priv2[PK_P256_PRIVKEY_LEN];
    uint8_t cert_der2[1024];
    size_t cert_len2 = 0;
    err = pk_crypto_build_attestation_cert_der(
        ctx,
        attestation_seed,
        attest_priv2,
        cert_der2,
        sizeof(cert_der2),
        &cert_len2
    );
    TEST_ASSERT(err == PK_OK, "Second attestation cert generation failed");
    TEST_ASSERT(cert_len2 > 0 && cert_der2[0] == 0x30, "Second DER certificate must also start with 0x30");
    TEST_ASSERT(memcmp(attest_priv, attest_priv2, 32) == 0, "Attestation private keys should be identical for same seed");

    TEST_PASS_MSG("Attestation certificate generation (valid DER starting with 0x30)");
    return 0;
}

/* 10. Test CBOR canonical encoder/decoder for COSE P-256 public key */
static int test_cbor_cose_pubkey(pk_crypto_ctx_t *ctx)
{
    uint8_t priv[PK_P256_PRIVKEY_LEN];
    pk_p256_pubkey_t original_pub;
    pk_err_t err = pk_crypto_p256_keygen(ctx, priv, &original_pub);
    TEST_ASSERT(err == PK_OK, "Keygen failed");

    /* Round-trip with for_ecdh = false (alg = -7 ES256) */
    uint8_t cbor_buf[256];
    pk_cbor_writer_t w;
    pk_cbor_writer_init(&w, cbor_buf, sizeof(cbor_buf));

    err = pk_cbor_encode_cose_p256_pubkey(&w, &original_pub, false);
    TEST_ASSERT(err == PK_OK, "pk_cbor_encode_cose_p256_pubkey failed (ES256)");
    TEST_ASSERT(w.offset > 0, "Encoded CBOR buffer length must be > 0");

    pk_cbor_reader_t r;
    pk_cbor_reader_init(&r, cbor_buf, w.offset);
    pk_p256_pubkey_t decoded_pub;
    err = pk_cbor_decode_cose_p256_pubkey(&r, &decoded_pub);
    TEST_ASSERT(err == PK_OK, "pk_cbor_decode_cose_p256_pubkey failed (ES256)");
    TEST_ASSERT(memcmp(original_pub.x, decoded_pub.x, 32) == 0, "Decoded pubkey X mismatch");
    TEST_ASSERT(memcmp(original_pub.y, decoded_pub.y, 32) == 0, "Decoded pubkey Y mismatch");

    /* Round-trip with for_ecdh = true (alg = -25 ECDH-ES+HKDF-256) */
    pk_cbor_writer_init(&w, cbor_buf, sizeof(cbor_buf));
    err = pk_cbor_encode_cose_p256_pubkey(&w, &original_pub, true);
    TEST_ASSERT(err == PK_OK, "pk_cbor_encode_cose_p256_pubkey failed (ECDH)");

    pk_cbor_reader_init(&r, cbor_buf, w.offset);
    memset(&decoded_pub, 0, sizeof(decoded_pub));
    err = pk_cbor_decode_cose_p256_pubkey(&r, &decoded_pub);
    TEST_ASSERT(err == PK_OK, "pk_cbor_decode_cose_p256_pubkey failed (ECDH)");
    TEST_ASSERT(memcmp(original_pub.x, decoded_pub.x, 32) == 0, "Decoded ECDH pubkey X mismatch");
    TEST_ASSERT(memcmp(original_pub.y, decoded_pub.y, 32) == 0, "Decoded ECDH pubkey Y mismatch");

    TEST_PASS_MSG("CBOR COSE P-256 pubkey canonical encode/decode round-trip");
    return 0;
}

/* 11. Test utility functions: zeroize, consttime_eq, crc32 */
static int test_crypto_utilities(void)
{
    /* Zeroize */
    uint8_t secret[32];
    memset(secret, 0xEE, sizeof(secret));
    pk_crypto_zeroize(secret, sizeof(secret));
    for (size_t i = 0; i < sizeof(secret); ++i) {
        TEST_ASSERT(secret[i] == 0, "pk_crypto_zeroize should clear bytes to zero");
    }

    /* Constant-time equality */
    uint8_t a[16] = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16 };
    uint8_t b[16] = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16 };
    TEST_ASSERT(pk_crypto_consttime_eq(a, b, 16) == true, "Equal buffers should return true");

    b[15] = 17;
    TEST_ASSERT(pk_crypto_consttime_eq(a, b, 16) == false, "Unequal buffers should return false");

    /* IEEE 802.3 CRC32 check vector: "123456789" -> 0xCBF43926 */
    static const uint8_t crc_check_data[] = "123456789";
    uint32_t crc = pk_crc32(crc_check_data, 9);
    TEST_ASSERT(crc == 0xCBF43926UL, "pk_crc32 standard test vector mismatch");

    TEST_PASS_MSG("Crypto utilities (zeroize, consttime_eq, crc32)");
    return 0;
}

int main(void)
{
    printf("=== Running crypto unit tests ===\n");

    pk_mock_platform_state_t mock;
    pk_platform_t platform;
    pk_mock_platform_init(&mock, &platform);

    pk_crypto_ctx_t crypto;
    pk_err_t err = pk_crypto_init(&crypto, &platform);
    if (err != PK_OK) {
        fprintf(stderr, "pk_crypto_init failed: %d\n", (int)err);
        return 1;
    }

    if (test_sha256() != 0) return 1;
    if (test_hmac_and_hkdf() != 0) return 1;
    if (test_aes256_cbc() != 0) return 1;
    if (test_p256_and_ecdsa(&crypto) != 0) return 1;
    if (test_low_s_normalization(&crypto) != 0) return 1;
    if (test_rng_failure_mode(&crypto, &mock) != 0) return 1;
    if (test_ecdh_shared_secret(&crypto) != 0) return 1;
    if (test_seal_unseal_credential(&crypto) != 0) return 1;
    if (test_attestation_cert(&crypto) != 0) return 1;
    if (test_cbor_cose_pubkey(&crypto) != 0) return 1;
    if (test_crypto_utilities() != 0) return 1;

    printf("\n[PASS] All crypto unit tests passed successfully!\n");
    return 0;
}
