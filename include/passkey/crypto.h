#ifndef PICO_PASSKEY_CRYPTO_H
#define PICO_PASSKEY_CRYPTO_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "passkey/config.h"
#include "passkey/platform.h"
#include "passkey/status.h"

#define PK_SHA256_LEN            32U
#define PK_P256_PRIVKEY_LEN      32U
#define PK_P256_PUBKEY_COORD_LEN 32U
#define PK_ECDSA_MAX_DER_SIG_LEN 72U
#define PK_AES_BLOCK_LEN         16U

typedef struct {
    uint8_t x[PK_P256_PUBKEY_COORD_LEN];
    uint8_t y[PK_P256_PUBKEY_COORD_LEN];
} pk_p256_pubkey_t;

typedef struct {
    const pk_platform_t *platform;
    bool initialized;
    /* Ephemeral authenticator ECDH keyAgreement keypair for CTAP2 clientPin (§6.5.5) */
    uint8_t pin_ecdh_priv[PK_P256_PRIVKEY_LEN];
    pk_p256_pubkey_t pin_ecdh_pub;
    bool pin_ecdh_valid;
} pk_crypto_ctx_t;

/* Initialize cryptographic engine and generate initial PIN ECDH keyAgreement pair */
pk_err_t pk_crypto_init(pk_crypto_ctx_t *ctx, const pk_platform_t *platform);

/* Securely wipe memory (prevents compiler dead-store elimination) */
void pk_crypto_zeroize(void *buf, size_t len);

/* Constant-time byte comparison: returns true iff a[0..len-1] == b[0..len-1] */
bool pk_crypto_consttime_eq(const uint8_t *a, const uint8_t *b, size_t len);

/* Fill buffer with cryptographically secure random bytes */
pk_err_t pk_crypto_random(pk_crypto_ctx_t *ctx, uint8_t *out, size_t len);

/* Compute SHA-256 digest */
pk_err_t pk_crypto_sha256(const uint8_t *data, size_t len, uint8_t out_hash[PK_SHA256_LEN]);

/* Compute SHA-256 over two concatenated buffers (data1 || data2) */
pk_err_t pk_crypto_sha256_two(
    const uint8_t *data1, size_t len1,
    const uint8_t *data2, size_t len2,
    uint8_t out_hash[PK_SHA256_LEN]
);

/* Compute HMAC-SHA-256 */
pk_err_t pk_crypto_hmac_sha256(
    const uint8_t *key, size_t key_len,
    const uint8_t *data, size_t data_len,
    uint8_t out_mac[PK_SHA256_LEN]
);

/* HKDF-SHA-256 (RFC 5869) extract-and-expand */
pk_err_t pk_crypto_hkdf_sha256(
    const uint8_t *salt, size_t salt_len,
    const uint8_t *ikm, size_t ikm_len,
    const uint8_t *info, size_t info_len,
    uint8_t *okm, size_t okm_len
);

/* AES-256-CBC with zero IV and no padding (len must be a non-zero multiple of 16,
 * as required by FIDO CTAP2 PIN Protocol v1 §6.5.4)
 */
pk_err_t pk_crypto_aes256_cbc_encrypt_zero_iv(
    const uint8_t key[32],
    const uint8_t *in,
    size_t len,
    uint8_t *out
);

pk_err_t pk_crypto_aes256_cbc_decrypt_zero_iv(
    const uint8_t key[32],
    const uint8_t *in,
    size_t len,
    uint8_t *out
);

/* Generate random SECP256R1 (P-256) keypair */
pk_err_t pk_crypto_p256_keygen(
    pk_crypto_ctx_t *ctx,
    uint8_t out_priv[PK_P256_PRIVKEY_LEN],
    pk_p256_pubkey_t *out_pub
);

/* Deterministic P-256 key derivation from master secret, RP ID hash (32 bytes),
 * and credential random nonce (32 bytes). Uses HKDF-SHA-256 with counter retry
 * until scalar is in [1, n-1], then computes public point Q = d * G.
 */
pk_err_t pk_crypto_derive_credential_keypair(
    const uint8_t master_secret[32],
    const uint8_t rp_id_hash[32],
    const uint8_t cred_random[32],
    uint8_t out_priv[PK_P256_PRIVKEY_LEN],
    pk_p256_pubkey_t *out_pub
);

/* Compute public key Q = d * G from a 32-byte P-256 private scalar */
pk_err_t pk_crypto_p256_pubkey_from_priv(
    const uint8_t priv[PK_P256_PRIVKEY_LEN],
    pk_p256_pubkey_t *out_pub
);

/* Sign a 32-byte SHA-256 digest with a P-256 private key, outputting ASN.1 DER
 * signature (`ECDSA-Sig-Value`) as required by WebAuthn / COSE ES256 (-7).
 */
pk_err_t pk_crypto_p256_sign_der(
    pk_crypto_ctx_t *ctx,
    const uint8_t priv[PK_P256_PRIVKEY_LEN],
    const uint8_t hash[PK_SHA256_LEN],
    uint8_t out_der_sig[PK_ECDSA_MAX_DER_SIG_LEN],
    size_t *out_der_sig_len
);

/* Verify an ASN.1 DER ECDSA P-256 signature against a 32-byte SHA-256 digest */
pk_err_t pk_crypto_p256_verify_der(
    const pk_p256_pubkey_t *pub,
    const uint8_t hash[PK_SHA256_LEN],
    const uint8_t *der_sig,
    size_t der_sig_len
);

/* Compute ECDH shared secret Z (32-byte X coordinate of shared point) on P-256,
 * then hash with SHA-256 (`SHA-256(Z)`) per CTAP2 PIN Protocol v1 §6.5.4.
 */
pk_err_t pk_crypto_p256_ecdh_shared_secret_sha256(
    pk_crypto_ctx_t *ctx,
    const uint8_t priv[PK_P256_PRIVKEY_LEN],
    const pk_p256_pubkey_t *peer_pub,
    uint8_t out_shared_secret[PK_SHA256_LEN]
);

/* Regenerate the authenticator's ephemeral PIN ECDH keyAgreement keypair */
pk_err_t pk_crypto_regenerate_pin_keyagreement(pk_crypto_ctx_t *ctx);

/* Seal/Unseal a non-resident credential ID (64 bytes):
 *   bytes  0..31: cred_random (32-byte random per-credential nonce)
 *   bytes 32..63: HMAC-SHA-256(cred_mac_key, "PK-NRCRED-V1" || rp_id_hash || cred_random)
 */
pk_err_t pk_crypto_seal_nonresident_cred_id(
    pk_crypto_ctx_t *ctx,
    const uint8_t cred_mac_key[32],
    const uint8_t rp_id_hash[32],
    uint8_t out_cred_id[PK_CRED_ID_NONRESIDENT_LEN],
    uint8_t out_cred_random[32]
);

pk_err_t pk_crypto_unseal_nonresident_cred_id(
    const uint8_t cred_mac_key[32],
    const uint8_t rp_id_hash[32],
    const uint8_t cred_id[PK_CRED_ID_NONRESIDENT_LEN],
    uint8_t out_cred_random[32]
);

/* Obtain self-signed batch attestation certificate (DER) and matching P-256 private key
 * derived deterministically from the device attestation seed so no hardcoded private key
 * is stored in source code.
 */
pk_err_t pk_crypto_build_attestation_cert_der(
    pk_crypto_ctx_t *ctx,
    const uint8_t attestation_seed[32],
    uint8_t out_priv[PK_P256_PRIVKEY_LEN],
    uint8_t *out_cert_der,
    size_t max_cert_len,
    size_t *out_cert_len
);

/* Standard IEEE 802.3 CRC32 for storage integrity verification */
uint32_t pk_crc32(const uint8_t *data, size_t len);

#endif /* PICO_PASSKEY_CRYPTO_H */
