#include "passkey/crypto.h"
#include <string.h>

#define MBEDTLS_ALLOW_PRIVATE_ACCESS
#include <mbedtls/version.h>
#include <mbedtls/sha256.h>
#include <mbedtls/aes.h>
#include <mbedtls/ecp.h>
#include <mbedtls/ecdsa.h>
#include <mbedtls/bignum.h>
#include <mbedtls/error.h>

#if MBEDTLS_VERSION_MAJOR >= 3
#define pk_mbedtls_sha256(in, len, out, is224) mbedtls_sha256(in, len, out, is224)
#define pk_mbedtls_sha256_starts(ctx, is224)   mbedtls_sha256_starts(ctx, is224)
#define pk_mbedtls_sha256_update(ctx, in, len) mbedtls_sha256_update(ctx, in, len)
#define pk_mbedtls_sha256_finish(ctx, out)     mbedtls_sha256_finish(ctx, out)
#else
#define pk_mbedtls_sha256(in, len, out, is224) mbedtls_sha256_ret(in, len, out, is224)
#define pk_mbedtls_sha256_starts(ctx, is224)   mbedtls_sha256_starts_ret(ctx, is224)
#define pk_mbedtls_sha256_update(ctx, in, len) mbedtls_sha256_update_ret(ctx, in, len)
#define pk_mbedtls_sha256_finish(ctx, out)     mbedtls_sha256_finish_ret(ctx, out)
#endif

/* -------------------------------------------------------------------------
 * Memory Zeroization and Constant-Time Comparison
 * ------------------------------------------------------------------------- */

void pk_crypto_zeroize(void *buf, size_t len)
{
    if (buf == NULL || len == 0) {
        return;
    }
    volatile uint8_t *p = (volatile uint8_t *)buf;
    while (len--) {
        *p++ = 0;
    }
}

bool pk_crypto_consttime_eq(const uint8_t *a, const uint8_t *b, size_t len)
{
    if (len == 0) {
        return true;
    }
    if (a == NULL || b == NULL) {
        return false;
    }
    volatile uint8_t diff = 0;
    for (size_t i = 0; i < len; ++i) {
        diff |= (uint8_t)(a[i] ^ b[i]);
    }
    return (diff == 0);
}

/* -------------------------------------------------------------------------
 * Random Number Generation
 * ------------------------------------------------------------------------- */

pk_err_t pk_crypto_random(pk_crypto_ctx_t *ctx, uint8_t *out, size_t len)
{
    if (len == 0) {
        return PK_OK;
    }
    if (ctx == NULL || ctx->platform == NULL ||
        ctx->platform->get_random_bytes == NULL || out == NULL) {
        return PK_ERR_INVALID_ARG;
    }
    return ctx->platform->get_random_bytes(ctx->platform->ctx, out, len);
}

static int pk_mbedtls_f_rng(void *p_rng, unsigned char *output, size_t len)
{
    if (len == 0) {
        return 0;
    }
    if (output == NULL) {
        return -1;
    }
    if (p_rng != NULL) {
        pk_crypto_ctx_t *ctx = (pk_crypto_ctx_t *)p_rng;
        if (ctx->platform != NULL && ctx->platform->get_random_bytes != NULL) {
            pk_err_t err = ctx->platform->get_random_bytes(ctx->platform->ctx, output, len);
            if (err == PK_OK) {
                return 0;
            }
        }
        /* Fail closed: Never fall back to predictable pseudo-randomness for cryptographic keys */
        return MBEDTLS_ERR_ECP_RANDOM_FAILED;
    }

    /* Fallback PRNG ONLY for internal non-critical coordinate blinding when ctx is explicitly NULL */
    static uint64_t s_prng_state = 0x853C49E6748FEA9BULL;
    for (size_t i = 0; i < len; ++i) {
        s_prng_state ^= s_prng_state << 13;
        s_prng_state ^= s_prng_state >> 7;
        s_prng_state ^= s_prng_state << 17;
        output[i] = (unsigned char)(s_prng_state & 0xFFU);
    }
    return 0;
}

/* -------------------------------------------------------------------------
 * SHA-256 Hashing
 * ------------------------------------------------------------------------- */

pk_err_t pk_crypto_sha256(const uint8_t *data, size_t len, uint8_t out_hash[PK_SHA256_LEN])
{
    if ((len > 0 && data == NULL) || out_hash == NULL) {
        return PK_ERR_INVALID_ARG;
    }

    mbedtls_sha256_context sha;
    mbedtls_sha256_init(&sha);

    int ret = pk_mbedtls_sha256_starts(&sha, 0);
    if (ret == 0 && len > 0) {
        ret = pk_mbedtls_sha256_update(&sha, data, len);
    }
    if (ret == 0) {
        ret = pk_mbedtls_sha256_finish(&sha, out_hash);
    }

    mbedtls_sha256_free(&sha);
    return (ret == 0) ? PK_OK : PK_ERR_CRYPTO;
}

pk_err_t pk_crypto_sha256_two(
    const uint8_t *data1, size_t len1,
    const uint8_t *data2, size_t len2,
    uint8_t out_hash[PK_SHA256_LEN]
)
{
    if ((len1 > 0 && data1 == NULL) || (len2 > 0 && data2 == NULL) || out_hash == NULL) {
        return PK_ERR_INVALID_ARG;
    }

    mbedtls_sha256_context sha;
    mbedtls_sha256_init(&sha);

    int ret = pk_mbedtls_sha256_starts(&sha, 0);
    if (ret == 0 && len1 > 0) {
        ret = pk_mbedtls_sha256_update(&sha, data1, len1);
    }
    if (ret == 0 && len2 > 0) {
        ret = pk_mbedtls_sha256_update(&sha, data2, len2);
    }
    if (ret == 0) {
        ret = pk_mbedtls_sha256_finish(&sha, out_hash);
    }

    mbedtls_sha256_free(&sha);
    return (ret == 0) ? PK_OK : PK_ERR_CRYPTO;
}

/* -------------------------------------------------------------------------
 * RFC 2104 HMAC-SHA-256
 * ------------------------------------------------------------------------- */

typedef struct {
    mbedtls_sha256_context sha;
    uint8_t opad[64];
} pk_hmac_sha256_ctx_t;

static pk_err_t pk_hmac_sha256_init_ctx(
    pk_hmac_sha256_ctx_t *hctx,
    const uint8_t *key,
    size_t key_len
)
{
    if (hctx == NULL || (key_len > 0 && key == NULL)) {
        return PK_ERR_INVALID_ARG;
    }

    uint8_t k0[64];
    memset(k0, 0, sizeof(k0));

    if (key_len > 64) {
        pk_err_t err = pk_crypto_sha256(key, key_len, k0);
        if (err != PK_OK) {
            return err;
        }
    } else if (key_len > 0) {
        memcpy(k0, key, key_len);
    }

    uint8_t ipad[64];
    for (size_t i = 0; i < 64; ++i) {
        ipad[i] = (uint8_t)(k0[i] ^ 0x36U);
        hctx->opad[i] = (uint8_t)(k0[i] ^ 0x5CU);
    }
    pk_crypto_zeroize(k0, sizeof(k0));

    mbedtls_sha256_init(&hctx->sha);
    int ret = pk_mbedtls_sha256_starts(&hctx->sha, 0);
    if (ret == 0) {
        ret = pk_mbedtls_sha256_update(&hctx->sha, ipad, 64);
    }
    pk_crypto_zeroize(ipad, sizeof(ipad));

    return (ret == 0) ? PK_OK : PK_ERR_CRYPTO;
}

static pk_err_t pk_hmac_sha256_update_ctx(
    pk_hmac_sha256_ctx_t *hctx,
    const uint8_t *data,
    size_t len
)
{
    if (hctx == NULL || (len > 0 && data == NULL)) {
        return PK_ERR_INVALID_ARG;
    }
    if (len == 0) {
        return PK_OK;
    }
    int ret = pk_mbedtls_sha256_update(&hctx->sha, data, len);
    return (ret == 0) ? PK_OK : PK_ERR_CRYPTO;
}

static pk_err_t pk_hmac_sha256_finish_ctx(
    pk_hmac_sha256_ctx_t *hctx,
    uint8_t out_mac[PK_SHA256_LEN]
)
{
    if (hctx == NULL || out_mac == NULL) {
        return PK_ERR_INVALID_ARG;
    }

    uint8_t inner_hash[PK_SHA256_LEN];
    int ret = pk_mbedtls_sha256_finish(&hctx->sha, inner_hash);
    mbedtls_sha256_free(&hctx->sha);

    if (ret == 0) {
        mbedtls_sha256_init(&hctx->sha);
        ret = pk_mbedtls_sha256_starts(&hctx->sha, 0);
        if (ret == 0) {
            ret = pk_mbedtls_sha256_update(&hctx->sha, hctx->opad, 64);
        }
        if (ret == 0) {
            ret = pk_mbedtls_sha256_update(&hctx->sha, inner_hash, PK_SHA256_LEN);
        }
        if (ret == 0) {
            ret = pk_mbedtls_sha256_finish(&hctx->sha, out_mac);
        }
        mbedtls_sha256_free(&hctx->sha);
    }

    pk_crypto_zeroize(inner_hash, sizeof(inner_hash));
    pk_crypto_zeroize(hctx->opad, sizeof(hctx->opad));
    return (ret == 0) ? PK_OK : PK_ERR_CRYPTO;
}

pk_err_t pk_crypto_hmac_sha256(
    const uint8_t *key, size_t key_len,
    const uint8_t *data, size_t data_len,
    uint8_t out_mac[PK_SHA256_LEN]
)
{
    if ((key_len > 0 && key == NULL) || (data_len > 0 && data == NULL) || out_mac == NULL) {
        return PK_ERR_INVALID_ARG;
    }

    pk_hmac_sha256_ctx_t hmac;
    pk_err_t err = pk_hmac_sha256_init_ctx(&hmac, key, key_len);
    if (err != PK_OK) {
        return err;
    }
    if (data_len > 0) {
        err = pk_hmac_sha256_update_ctx(&hmac, data, data_len);
        if (err != PK_OK) {
            mbedtls_sha256_free(&hmac.sha);
            pk_crypto_zeroize(hmac.opad, sizeof(hmac.opad));
            return err;
        }
    }
    return pk_hmac_sha256_finish_ctx(&hmac, out_mac);
}

/* -------------------------------------------------------------------------
 * RFC 5869 HKDF-SHA-256
 * ------------------------------------------------------------------------- */

pk_err_t pk_crypto_hkdf_sha256(
    const uint8_t *salt, size_t salt_len,
    const uint8_t *ikm, size_t ikm_len,
    const uint8_t *info, size_t info_len,
    uint8_t *okm, size_t okm_len
)
{
    if ((ikm_len > 0 && ikm == NULL) ||
        (salt_len > 0 && salt == NULL) ||
        (info_len > 0 && info == NULL) ||
        (okm_len > 0 && okm == NULL) ||
        okm_len > (255U * PK_SHA256_LEN)) {
        return PK_ERR_INVALID_ARG;
    }
    if (okm_len == 0) {
        return PK_OK;
    }

    /* Step 1: HKDF-Extract */
    uint8_t prk[PK_SHA256_LEN];
    uint8_t default_salt[PK_SHA256_LEN];
    const uint8_t *actual_salt = salt;
    size_t actual_salt_len = salt_len;
    if (salt == NULL || salt_len == 0) {
        memset(default_salt, 0, sizeof(default_salt));
        actual_salt = default_salt;
        actual_salt_len = sizeof(default_salt);
    }

    pk_err_t err = pk_crypto_hmac_sha256(actual_salt, actual_salt_len, ikm, ikm_len, prk);
    if (actual_salt == default_salt) {
        pk_crypto_zeroize(default_salt, sizeof(default_salt));
    }
    if (err != PK_OK) {
        return err;
    }

    /* Step 2: HKDF-Expand */
    uint8_t t[PK_SHA256_LEN];
    size_t n = (okm_len + PK_SHA256_LEN - 1U) / PK_SHA256_LEN;
    size_t okm_pos = 0;
    size_t rem = okm_len;

    for (size_t i = 1; i <= n; ++i) {
        pk_hmac_sha256_ctx_t hmac;
        err = pk_hmac_sha256_init_ctx(&hmac, prk, sizeof(prk));
        if (err != PK_OK) {
            break;
        }

        if (i > 1) {
            err = pk_hmac_sha256_update_ctx(&hmac, t, sizeof(t));
            if (err != PK_OK) {
                mbedtls_sha256_free(&hmac.sha);
                pk_crypto_zeroize(hmac.opad, sizeof(hmac.opad));
                break;
            }
        }

        if (info != NULL && info_len > 0) {
            err = pk_hmac_sha256_update_ctx(&hmac, info, info_len);
            if (err != PK_OK) {
                mbedtls_sha256_free(&hmac.sha);
                pk_crypto_zeroize(hmac.opad, sizeof(hmac.opad));
                break;
            }
        }

        uint8_t c = (uint8_t)i;
        err = pk_hmac_sha256_update_ctx(&hmac, &c, 1);
        if (err != PK_OK) {
            mbedtls_sha256_free(&hmac.sha);
            pk_crypto_zeroize(hmac.opad, sizeof(hmac.opad));
            break;
        }

        err = pk_hmac_sha256_finish_ctx(&hmac, t);
        if (err != PK_OK) {
            break;
        }

        size_t to_copy = (rem < PK_SHA256_LEN) ? rem : PK_SHA256_LEN;
        memcpy(okm + okm_pos, t, to_copy);
        okm_pos += to_copy;
        rem -= to_copy;
    }

    pk_crypto_zeroize(t, sizeof(t));
    pk_crypto_zeroize(prk, sizeof(prk));
    return err;
}

/* -------------------------------------------------------------------------
 * AES-256-CBC Zero-IV
 * ------------------------------------------------------------------------- */

pk_err_t pk_crypto_aes256_cbc_encrypt_zero_iv(
    const uint8_t key[32],
    const uint8_t *in,
    size_t len,
    uint8_t *out
)
{
    if (key == NULL || in == NULL || out == NULL || len == 0 || (len % PK_AES_BLOCK_LEN) != 0) {
        return PK_ERR_INVALID_ARG;
    }

    uint8_t iv[PK_AES_BLOCK_LEN];
    memset(iv, 0, sizeof(iv));

    mbedtls_aes_context aes;
    mbedtls_aes_init(&aes);

    int ret = mbedtls_aes_setkey_enc(&aes, key, 256);
    if (ret == 0) {
        ret = mbedtls_aes_crypt_cbc(&aes, MBEDTLS_AES_ENCRYPT, len, iv, in, out);
    }

    mbedtls_aes_free(&aes);
    pk_crypto_zeroize(iv, sizeof(iv));

    return (ret == 0) ? PK_OK : PK_ERR_CRYPTO;
}

pk_err_t pk_crypto_aes256_cbc_decrypt_zero_iv(
    const uint8_t key[32],
    const uint8_t *in,
    size_t len,
    uint8_t *out
)
{
    if (key == NULL || in == NULL || out == NULL || len == 0 || (len % PK_AES_BLOCK_LEN) != 0) {
        return PK_ERR_INVALID_ARG;
    }

    uint8_t iv[PK_AES_BLOCK_LEN];
    memset(iv, 0, sizeof(iv));

    mbedtls_aes_context aes;
    mbedtls_aes_init(&aes);

    int ret = mbedtls_aes_setkey_dec(&aes, key, 256);
    if (ret == 0) {
        ret = mbedtls_aes_crypt_cbc(&aes, MBEDTLS_AES_DECRYPT, len, iv, in, out);
    }

    mbedtls_aes_free(&aes);
    pk_crypto_zeroize(iv, sizeof(iv));

    return (ret == 0) ? PK_OK : PK_ERR_CRYPTO;
}

/* -------------------------------------------------------------------------
 * Elliptic Curve Cryptography: SECP256R1 (NIST P-256)
 * ------------------------------------------------------------------------- */

pk_err_t pk_crypto_p256_keygen(
    pk_crypto_ctx_t *ctx,
    uint8_t out_priv[PK_P256_PRIVKEY_LEN],
    pk_p256_pubkey_t *out_pub
)
{
    if (ctx == NULL || out_priv == NULL || out_pub == NULL) {
        return PK_ERR_INVALID_ARG;
    }

    mbedtls_ecp_group grp;
    mbedtls_mpi d;
    mbedtls_ecp_point Q;

    mbedtls_ecp_group_init(&grp);
    mbedtls_mpi_init(&d);\
    mbedtls_ecp_point_init(&Q);

    int ret = mbedtls_ecp_group_load(&grp, MBEDTLS_ECP_DP_SECP256R1);
    if (ret == 0) {
        ret = mbedtls_ecp_gen_keypair(&grp, &d, &Q, pk_mbedtls_f_rng, ctx);
    }
    if (ret == 0) {
        ret = mbedtls_mpi_write_binary(&d, out_priv, PK_P256_PRIVKEY_LEN);
    }
    if (ret == 0) {
        ret = mbedtls_mpi_write_binary(&Q.X, out_pub->x, PK_P256_PUBKEY_COORD_LEN);
    }
    if (ret == 0) {
        ret = mbedtls_mpi_write_binary(&Q.Y, out_pub->y, PK_P256_PUBKEY_COORD_LEN);
    }

    mbedtls_ecp_point_free(&Q);
    mbedtls_mpi_free(&d);
    mbedtls_ecp_group_free(&grp);

    if (ret != 0) {
        pk_crypto_zeroize(out_priv, PK_P256_PRIVKEY_LEN);
        pk_crypto_zeroize(out_pub, sizeof(*out_pub));
        return PK_ERR_CRYPTO;
    }

    return PK_OK;
}

pk_err_t pk_crypto_p256_pubkey_from_priv(
    const uint8_t priv[PK_P256_PRIVKEY_LEN],
    pk_p256_pubkey_t *out_pub
)
{
    if (priv == NULL || out_pub == NULL) {
        return PK_ERR_INVALID_ARG;
    }

    mbedtls_ecp_group grp;
    mbedtls_mpi d;
    mbedtls_ecp_point Q;

    mbedtls_ecp_group_init(&grp);
    mbedtls_mpi_init(&d);
    mbedtls_ecp_point_init(&Q);

    int ret = mbedtls_ecp_group_load(&grp, MBEDTLS_ECP_DP_SECP256R1);
    if (ret == 0) {
        ret = mbedtls_mpi_read_binary(&d, priv, PK_P256_PRIVKEY_LEN);
    }
    if (ret == 0) {
        ret = mbedtls_ecp_check_privkey(&grp, &d);
    }
    if (ret == 0) {
        ret = mbedtls_ecp_mul(&grp, &Q, &d, &grp.G, pk_mbedtls_f_rng, NULL);
    }
    if (ret == 0) {
        ret = mbedtls_mpi_write_binary(&Q.X, out_pub->x, PK_P256_PUBKEY_COORD_LEN);
    }
    if (ret == 0) {
        ret = mbedtls_mpi_write_binary(&Q.Y, out_pub->y, PK_P256_PUBKEY_COORD_LEN);
    }

    mbedtls_ecp_point_free(&Q);
    mbedtls_mpi_free(&d);
    mbedtls_ecp_group_free(&grp);

    if (ret != 0) {
        pk_crypto_zeroize(out_pub, sizeof(*out_pub));
        return PK_ERR_CRYPTO;
    }

    return PK_OK;
}

pk_err_t pk_crypto_derive_credential_keypair(
    const uint8_t master_secret[32],
    const uint8_t rp_id_hash[32],
    const uint8_t cred_random[32],
    uint8_t out_priv[PK_P256_PRIVKEY_LEN],
    pk_p256_pubkey_t *out_pub
)
{
    if (master_secret == NULL || rp_id_hash == NULL ||
        cred_random == NULL || out_priv == NULL || out_pub == NULL) {
        return PK_ERR_INVALID_ARG;
    }

    mbedtls_ecp_group grp;
    mbedtls_mpi d;
    mbedtls_ecp_group_init(&grp);
    mbedtls_mpi_init(&d);

    int ret = mbedtls_ecp_group_load(&grp, MBEDTLS_ECP_DP_SECP256R1);
    if (ret != 0) {
        mbedtls_mpi_free(&d);
        mbedtls_ecp_group_free(&grp);
        return PK_ERR_CRYPTO;
    }

    /* info_buf: "PK-CRED" (7 bytes) || cred_random (32 bytes) || counter_byte (1 byte) = 40 bytes */
    uint8_t info_buf[40];
    memcpy(info_buf, "PK-CRED", 7);
    memcpy(info_buf + 7, cred_random, 32);

    bool found = false;
    for (uint32_t counter = 0; counter < 256; ++counter) {
        info_buf[39] = (uint8_t)counter;
        pk_err_t err = pk_crypto_hkdf_sha256(
            rp_id_hash, 32,
            master_secret, 32,
            info_buf, sizeof(info_buf),
            out_priv, PK_P256_PRIVKEY_LEN
        );
        if (err != PK_OK) {
            break;
        }

        if (mbedtls_mpi_read_binary(&d, out_priv, PK_P256_PRIVKEY_LEN) == 0 &&
            mbedtls_ecp_check_privkey(&grp, &d) == 0) {
            found = true;
            break;
        }
    }

    pk_crypto_zeroize(info_buf, sizeof(info_buf));
    mbedtls_mpi_free(&d);
    mbedtls_ecp_group_free(&grp);

    if (!found) {
        pk_crypto_zeroize(out_priv, PK_P256_PRIVKEY_LEN);
        return PK_ERR_CRYPTO;
    }

    return pk_crypto_p256_pubkey_from_priv(out_priv, out_pub);
}

/* Helper to write an unsigned 32-byte integer in strict canonical ASN.1 DER */
static size_t pk_asn1_write_der_integer(const uint8_t raw[32], uint8_t *out)
{
    size_t start = 0;
    while (start < 32 && raw[start] == 0) {
        start++;
    }
    if (start == 32) {
        out[0] = 0x02;
        out[1] = 0x01;
        out[2] = 0x00;
        return 3;
    }

    size_t val_len = 32 - start;
    bool need_zero = ((raw[start] & 0x80U) != 0);
    size_t int_len = val_len + (need_zero ? 1U : 0U);

    out[0] = 0x02;
    out[1] = (uint8_t)int_len;
    size_t pos = 2;
    if (need_zero) {
        out[pos++] = 0x00;
    }
    memcpy(&out[pos], &raw[start], val_len);
    return 2U + int_len;
}

pk_err_t pk_crypto_p256_sign_der(
    pk_crypto_ctx_t *ctx,
    const uint8_t priv[PK_P256_PRIVKEY_LEN],
    const uint8_t hash[PK_SHA256_LEN],
    uint8_t out_der_sig[PK_ECDSA_MAX_DER_SIG_LEN],
    size_t *out_der_sig_len
)
{
    if (ctx == NULL || priv == NULL || hash == NULL ||
        out_der_sig == NULL || out_der_sig_len == NULL) {
        return PK_ERR_INVALID_ARG;
    }

    mbedtls_ecp_group grp;
    mbedtls_mpi d, r, s;

    mbedtls_ecp_group_init(&grp);
    mbedtls_mpi_init(&d);
    mbedtls_mpi_init(&r);
    mbedtls_mpi_init(&s);

    int ret = mbedtls_ecp_group_load(&grp, MBEDTLS_ECP_DP_SECP256R1);
    if (ret == 0) {
        ret = mbedtls_mpi_read_binary(&d, priv, PK_P256_PRIVKEY_LEN);
    }
    if (ret == 0) {
        ret = mbedtls_ecdsa_sign(&grp, &r, &s, &d, hash, PK_SHA256_LEN, pk_mbedtls_f_rng, ctx);
    }

    /* Enforce low-S normalization per BIP-62 / RFC 6979 / FIDO CTAP2: s <= N/2 */
    if (ret == 0) {
        mbedtls_mpi half_n;
        mbedtls_mpi_init(&half_n);
        if (mbedtls_mpi_copy(&half_n, &grp.N) == 0 &&
            mbedtls_mpi_shift_r(&half_n, 1) == 0) {
            if (mbedtls_mpi_cmp_mpi(&s, &half_n) > 0) {
                (void)mbedtls_mpi_sub_mpi(&s, &grp.N, &s);
            }
        }
        mbedtls_mpi_free(&half_n);
    }

    uint8_t r_raw[32], s_raw[32];
    if (ret == 0) {
        ret = mbedtls_mpi_write_binary(&r, r_raw, sizeof(r_raw));
    }
    if (ret == 0) {
        ret = mbedtls_mpi_write_binary(&s, s_raw, sizeof(s_raw));
    }

    /* Zeroize private scalar d as required */
    mbedtls_mpi_free(&d);
    mbedtls_mpi_free(&r);
    mbedtls_mpi_free(&s);
    mbedtls_ecp_group_free(&grp);

    if (ret != 0) {
        pk_crypto_zeroize(r_raw, sizeof(r_raw));
        pk_crypto_zeroize(s_raw, sizeof(s_raw));
        return PK_ERR_CRYPTO;
    }

    uint8_t r_der[35];
    uint8_t s_der[35];
    size_t r_der_len = pk_asn1_write_der_integer(r_raw, r_der);
    size_t s_der_len = pk_asn1_write_der_integer(s_raw, s_der);
    pk_crypto_zeroize(r_raw, sizeof(r_raw));
    pk_crypto_zeroize(s_raw, sizeof(s_raw));

    size_t seq_len = r_der_len + s_der_len;
    if (2U + seq_len > PK_ECDSA_MAX_DER_SIG_LEN) {
        return PK_ERR_CRYPTO;
    }

    out_der_sig[0] = 0x30;
    out_der_sig[1] = (uint8_t)seq_len;
    memcpy(out_der_sig + 2, r_der, r_der_len);
    memcpy(out_der_sig + 2 + r_der_len, s_der, s_der_len);
    *out_der_sig_len = 2U + seq_len;

    return PK_OK;
}

pk_err_t pk_crypto_p256_verify_der(
    const pk_p256_pubkey_t *pub,
    const uint8_t hash[PK_SHA256_LEN],
    const uint8_t *der_sig,
    size_t der_sig_len
)
{
    if (pub == NULL || hash == NULL || der_sig == NULL) {
        return PK_ERR_INVALID_ARG;
    }
    if (der_sig_len < 8 || der_sig_len > PK_ECDSA_MAX_DER_SIG_LEN) {
        return PK_ERR_CRYPTO;
    }

    /* SEQUENCE header */
    if (der_sig[0] != 0x30 || der_sig[1] != (der_sig_len - 2)) {
        return PK_ERR_CRYPTO;
    }

    size_t pos = 2;

    /* Parse INTEGER r */
    if (pos >= der_sig_len || der_sig[pos++] != 0x02) {
        return PK_ERR_CRYPTO;
    }
    if (pos >= der_sig_len) {
        return PK_ERR_CRYPTO;
    }
    size_t r_len = der_sig[pos++];
    if (r_len == 0 || pos + r_len > der_sig_len) {
        return PK_ERR_CRYPTO;
    }
    const uint8_t *r_bytes = &der_sig[pos];
    pos += r_len;

    /* Parse INTEGER s */
    if (pos >= der_sig_len || der_sig[pos++] != 0x02) {
        return PK_ERR_CRYPTO;
    }
    if (pos >= der_sig_len) {
        return PK_ERR_CRYPTO;
    }
    size_t s_len = der_sig[pos++];
    if (s_len == 0 || pos + s_len != der_sig_len) {
        return PK_ERR_CRYPTO;
    }
    const uint8_t *s_bytes = &der_sig[pos];

    /* Canonical DER checks for non-negative minimal integers */
    if ((r_bytes[0] & 0x80U) != 0 || (s_bytes[0] & 0x80U) != 0) {
        return PK_ERR_CRYPTO;
    }
    if (r_len > 1 && r_bytes[0] == 0x00 && (r_bytes[1] & 0x80U) == 0) {
        return PK_ERR_CRYPTO;
    }
    if (s_len > 1 && s_bytes[0] == 0x00 && (s_bytes[1] & 0x80U) == 0) {
        return PK_ERR_CRYPTO;
    }

    mbedtls_ecp_group grp;
    mbedtls_ecp_point Q;
    mbedtls_mpi r, s;

    mbedtls_ecp_group_init(&grp);
    mbedtls_ecp_point_init(&Q);
    mbedtls_mpi_init(&r);
    mbedtls_mpi_init(&s);

    int ret = mbedtls_ecp_group_load(&grp, MBEDTLS_ECP_DP_SECP256R1);
    if (ret == 0) {
        ret = mbedtls_mpi_read_binary(&Q.X, pub->x, PK_P256_PUBKEY_COORD_LEN);
    }
    if (ret == 0) {
        ret = mbedtls_mpi_read_binary(&Q.Y, pub->y, PK_P256_PUBKEY_COORD_LEN);
    }
    if (ret == 0) {
        ret = mbedtls_mpi_lset(&Q.Z, 1);
    }
    if (ret == 0) {
        ret = mbedtls_ecp_check_pubkey(&grp, &Q);
    }
    if (ret == 0) {
        ret = mbedtls_mpi_read_binary(&r, r_bytes, r_len);
    }
    if (ret == 0) {
        ret = mbedtls_mpi_read_binary(&s, s_bytes, s_len);
    }
    if (ret == 0) {
        ret = mbedtls_ecdsa_verify(&grp, hash, PK_SHA256_LEN, &Q, &r, &s);
    }

    mbedtls_mpi_free(&s);
    mbedtls_mpi_free(&r);
    mbedtls_ecp_point_free(&Q);
    mbedtls_ecp_group_free(&grp);

    if (ret == 0) {
        return PK_OK;
    }
    if (ret == MBEDTLS_ERR_ECP_VERIFY_FAILED) {
        return PK_ERR_AUTH_FAILED;
    }
    return PK_ERR_CRYPTO;
}

pk_err_t pk_crypto_p256_ecdh_shared_secret_sha256(
    pk_crypto_ctx_t *ctx,
    const uint8_t priv[PK_P256_PRIVKEY_LEN],
    const pk_p256_pubkey_t *peer_pub,
    uint8_t out_shared_secret[PK_SHA256_LEN]
)
{
    if (ctx == NULL || priv == NULL || peer_pub == NULL || out_shared_secret == NULL) {
        return PK_ERR_INVALID_ARG;
    }

    mbedtls_ecp_group grp;
    mbedtls_mpi d;
    mbedtls_ecp_point Q_peer, P;
    uint8_t z[PK_SHA256_LEN];

    mbedtls_ecp_group_init(&grp);
    mbedtls_mpi_init(&d);
    mbedtls_ecp_point_init(&Q_peer);
    mbedtls_ecp_point_init(&P);

    int ret = mbedtls_ecp_group_load(&grp, MBEDTLS_ECP_DP_SECP256R1);
    if (ret == 0) {
        ret = mbedtls_mpi_read_binary(&Q_peer.X, peer_pub->x, PK_P256_PUBKEY_COORD_LEN);
    }
    if (ret == 0) {
        ret = mbedtls_mpi_read_binary(&Q_peer.Y, peer_pub->y, PK_P256_PUBKEY_COORD_LEN);
    }
    if (ret == 0) {
        ret = mbedtls_mpi_lset(&Q_peer.Z, 1);
    }
    if (ret == 0) {
        ret = mbedtls_ecp_check_pubkey(&grp, &Q_peer);
    }
    if (ret == 0) {
        ret = mbedtls_mpi_read_binary(&d, priv, PK_P256_PRIVKEY_LEN);
    }
    if (ret == 0) {
        ret = mbedtls_ecp_check_privkey(&grp, &d);
    }
    if (ret == 0) {
        ret = mbedtls_ecp_mul(&grp, &P, &d, &Q_peer, pk_mbedtls_f_rng, ctx);
    }
    if (ret == 0) {
        ret = mbedtls_mpi_write_binary(&P.X, z, sizeof(z));
    }

    mbedtls_ecp_point_free(&P);
    mbedtls_ecp_point_free(&Q_peer);
    mbedtls_mpi_free(&d);
    mbedtls_ecp_group_free(&grp);

    pk_err_t err = PK_ERR_CRYPTO;
    if (ret == 0) {
        err = pk_crypto_sha256(z, sizeof(z), out_shared_secret);
    }
    pk_crypto_zeroize(z, sizeof(z));

    return (ret == 0 && err == PK_OK) ? PK_OK : PK_ERR_CRYPTO;
}

pk_err_t pk_crypto_regenerate_pin_keyagreement(pk_crypto_ctx_t *ctx)
{
    if (ctx == NULL || ctx->platform == NULL) {
        return PK_ERR_INVALID_ARG;
    }

    ctx->pin_ecdh_valid = false;
    pk_crypto_zeroize(ctx->pin_ecdh_priv, sizeof(ctx->pin_ecdh_priv));
    pk_crypto_zeroize(&ctx->pin_ecdh_pub, sizeof(ctx->pin_ecdh_pub));

    pk_err_t err = pk_crypto_p256_keygen(ctx, ctx->pin_ecdh_priv, &ctx->pin_ecdh_pub);
    if (err == PK_OK) {
        ctx->pin_ecdh_valid = true;
    }
    return err;
}

pk_err_t pk_crypto_init(pk_crypto_ctx_t *ctx, const pk_platform_t *platform)
{
    if (ctx == NULL || platform == NULL || platform->get_random_bytes == NULL) {
        return PK_ERR_INVALID_ARG;
    }
    pk_crypto_zeroize(ctx, sizeof(*ctx));
    ctx->platform = platform;
    ctx->initialized = true;
    return pk_crypto_regenerate_pin_keyagreement(ctx);
}

/* -------------------------------------------------------------------------
 * Non-Resident Credential ID Sealing & Unsealing
 * ------------------------------------------------------------------------- */

pk_err_t pk_crypto_seal_nonresident_cred_id(
    pk_crypto_ctx_t *ctx,
    const uint8_t cred_mac_key[32],
    const uint8_t rp_id_hash[32],
    uint8_t out_cred_id[PK_CRED_ID_NONRESIDENT_LEN],
    uint8_t out_cred_random[32]
)
{
    if (ctx == NULL || cred_mac_key == NULL || rp_id_hash == NULL || out_cred_id == NULL) {
        return PK_ERR_INVALID_ARG;
    }

    pk_err_t err = pk_crypto_random(ctx, out_cred_id, 32);
    if (err != PK_OK) {
        return err;
    }
    if (out_cred_random != NULL) {
        memcpy(out_cred_random, out_cred_id, 32);
    }

    uint8_t msg[12 + 32 + 32];
    memcpy(msg, "PK-NRCRED-V1", 12);
    memcpy(msg + 12, rp_id_hash, 32);
    memcpy(msg + 44, out_cred_id, 32);

    err = pk_crypto_hmac_sha256(cred_mac_key, 32, msg, sizeof(msg), out_cred_id + 32);
    pk_crypto_zeroize(msg, sizeof(msg));

    return err;
}

pk_err_t pk_crypto_unseal_nonresident_cred_id(
    const uint8_t cred_mac_key[32],
    const uint8_t rp_id_hash[32],
    const uint8_t cred_id[PK_CRED_ID_NONRESIDENT_LEN],
    uint8_t out_cred_random[32]
)
{
    if (cred_mac_key == NULL || rp_id_hash == NULL ||
        cred_id == NULL || out_cred_random == NULL) {
        return PK_ERR_INVALID_ARG;
    }

    uint8_t msg[12 + 32 + 32];
    memcpy(msg, "PK-NRCRED-V1", 12);
    memcpy(msg + 12, rp_id_hash, 32);
    memcpy(msg + 44, cred_id, 32);

    uint8_t expected_mac[32];
    pk_err_t err = pk_crypto_hmac_sha256(cred_mac_key, 32, msg, sizeof(msg), expected_mac);
    pk_crypto_zeroize(msg, sizeof(msg));
    if (err != PK_OK) {
        return err;
    }

    if (!pk_crypto_consttime_eq(expected_mac, cred_id + 32, 32)) {
        pk_crypto_zeroize(expected_mac, sizeof(expected_mac));
        return PK_ERR_AUTH_FAILED;
    }

    pk_crypto_zeroize(expected_mac, sizeof(expected_mac));
    memcpy(out_cred_random, cred_id, 32);
    return PK_OK;
}

/* -------------------------------------------------------------------------
 * X.509 v3 Self-Signed Batch Attestation Certificate
 * ------------------------------------------------------------------------- */

/* Pre-assembled TBSCertificate template with 0-filled pubkey placeholder (320 bytes) */
static const uint8_t s_tbs_template[320] = {
    /* 0..3: SEQUENCE header */
    0x30, 0x82, 0x01, 0x3C,
    /* 4..8: version [0] EXPLICIT INTEGER 2 */
    0xA0, 0x03, 0x02, 0x01, 0x02,
    /* 9..11: serialNumber INTEGER 1 */
    0x02, 0x01, 0x01,
    /* 12..23: signature AlgorithmIdentifier: ecdsa-with-SHA256 (1.2.840.10045.4.3.2) */
    0x30, 0x0A, 0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x02,
    /* 24..102: issuer (79 bytes) */
    0x30, 0x4D,
    /* C=US (13 bytes) */
    0x31, 0x0B, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x06, 0x13, 0x02, 'U', 'S',
    /* O=Pico Passkey (23 bytes) */
    0x31, 0x15, 0x30, 0x13, 0x06, 0x03, 0x55, 0x04, 0x0A, 0x13, 0x0C,
    'P', 'i', 'c', 'o', ' ', 'P', 'a', 's', 's', 'k', 'e', 'y',
    /* CN=Pico Passkey FIDO2 Attestation (41 bytes) */
    0x31, 0x27, 0x30, 0x25, 0x06, 0x03, 0x55, 0x04, 0x03, 0x13, 0x1E,
    'P', 'i', 'c', 'o', ' ', 'P', 'a', 's', 's', 'k', 'e', 'y', ' ',
    'F', 'I', 'D', 'O', '2', ' ', 'A', 't', 't', 'e', 's', 't', 'a', 't', 'i', 'o', 'n',
    /* 103..134: validity (32 bytes) */
    0x30, 0x1E,
    /* notBefore: 20250101000000Z (15 bytes) */
    0x17, 0x0D, '2', '5', '0', '1', '0', '1', '0', '0', '0', '0', '0', '0', 'Z',
    /* notAfter: 20491231235959Z (15 bytes) */
    0x17, 0x0D, '4', '9', '1', '2', '3', '1', '2', '3', '5', '9', '5', '9', 'Z',
    /* 135..213: subject (identical to issuer, 79 bytes) */
    0x30, 0x4D,
    0x31, 0x0B, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x06, 0x13, 0x02, 'U', 'S',
    0x31, 0x15, 0x30, 0x13, 0x06, 0x03, 0x55, 0x04, 0x0A, 0x13, 0x0C,
    'P', 'i', 'c', 'o', ' ', 'P', 'a', 's', 's', 'k', 'e', 'y',
    0x31, 0x27, 0x30, 0x25, 0x06, 0x03, 0x55, 0x04, 0x03, 0x13, 0x1E,
    'P', 'i', 'c', 'o', ' ', 'P', 'a', 's', 's', 'k', 'e', 'y', ' ',
    'F', 'I', 'D', 'O', '2', ' ', 'A', 't', 't', 'e', 's', 't', 'a', 't', 'i', 'o', 'n',
    /* 214..304: SubjectPublicKeyInfo (91 bytes) */
    0x30, 0x59,
    /* AlgorithmIdentifier: id-ecPublicKey (1.2.840.10045.2.1), prime256v1 (1.2.840.10045.3.1.7) (21 bytes) */
    0x30, 0x13,
    0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01,
    0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07,
    /* subjectPublicKey BIT STRING (68 bytes): tag 0x03, len 0x42, pad 0x00, 0x04, pub.x (32), pub.y (32) */
    0x03, 0x42, 0x00, 0x04,
    /* 241..272: pub.x (placeholder 32 bytes) */
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    /* 273..304: pub.y (placeholder 32 bytes) */
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    /* 305..319: extensions [3] (15 bytes): BasicConstraints CA:FALSE */
    0xA3, 0x0D,
    0x30, 0x0B,
    0x30, 0x09,
    0x06, 0x03, 0x55, 0x1D, 0x13,
    0x04, 0x02, 0x30, 0x00
};

/* Deterministic pseudorandom generator for reproducible batch attestation certificate signing */
typedef struct {
    uint8_t key[32];
    uint32_t counter;
} pk_det_rng_state_t;

static pk_err_t pk_det_get_random_bytes(void *user_ctx, uint8_t *buf, size_t len)
{
    pk_det_rng_state_t *st = (pk_det_rng_state_t *)user_ctx;
    while (len > 0) {
        uint8_t block[32];
        uint8_t ctr_buf[4];
        ctr_buf[0] = (uint8_t)(st->counter >> 24);
        ctr_buf[1] = (uint8_t)(st->counter >> 16);
        ctr_buf[2] = (uint8_t)(st->counter >> 8);
        ctr_buf[3] = (uint8_t)(st->counter);
        st->counter++;
        pk_crypto_hmac_sha256(st->key, 32, ctr_buf, 4, block);
        size_t to_copy = (len < 32) ? len : 32;
        memcpy(buf, block, to_copy);
        buf += to_copy;
        len -= to_copy;
    }
    return PK_OK;
}

static bool s_attest_cache_valid = false;
static uint8_t s_attest_cached_seed[32];
static uint8_t s_attest_cached_priv[PK_P256_PRIVKEY_LEN];
static uint8_t s_attest_cached_cert[512];
static size_t s_attest_cached_cert_len = 0;

pk_err_t pk_crypto_build_attestation_cert_der(
    pk_crypto_ctx_t *ctx,
    const uint8_t attestation_seed[32],
    uint8_t out_priv[PK_P256_PRIVKEY_LEN],
    uint8_t *out_cert_der,
    size_t max_cert_len,
    size_t *out_cert_len
)
{
    (void)ctx;
    if (attestation_seed == NULL || out_priv == NULL ||
        out_cert_der == NULL || out_cert_len == NULL) {
        return PK_ERR_INVALID_ARG;
    }

    if (s_attest_cache_valid &&
        pk_crypto_consttime_eq(s_attest_cached_seed, attestation_seed, 32)) {
        if (max_cert_len < s_attest_cached_cert_len) {
            return PK_ERR_BUFFER_TOO_SMALL;
        }
        memcpy(out_priv, s_attest_cached_priv, PK_P256_PRIVKEY_LEN);
        memcpy(out_cert_der, s_attest_cached_cert, s_attest_cached_cert_len);
        *out_cert_len = s_attest_cached_cert_len;
        return PK_OK;
    }

    pk_p256_pubkey_t pub;
    pk_err_t err = pk_crypto_derive_credential_keypair(
        attestation_seed,
        (const uint8_t *)"PICO-PASSKEY-BATCH-ATTEST-SALT!!",
        (const uint8_t *)"PICO-PASSKEY-BATCH-ATTEST-NONCE!",
        out_priv,
        &pub
    );
    if (err != PK_OK) {
        return err;
    }

    uint8_t tbs[sizeof(s_tbs_template)];
    memcpy(tbs, s_tbs_template, sizeof(s_tbs_template));
    memcpy(&tbs[241], pub.x, 32);
    memcpy(&tbs[273], pub.y, 32);

    uint8_t tbs_hash[PK_SHA256_LEN];
    err = pk_crypto_sha256(tbs, sizeof(tbs), tbs_hash);
    if (err != PK_OK) {
        pk_crypto_zeroize(tbs, sizeof(tbs));
        pk_crypto_zeroize(out_priv, PK_P256_PRIVKEY_LEN);
        return err;
    }

    /* Use deterministic RNG seeded by attestation_seed so cert is 100% reproducible */
    pk_det_rng_state_t det_rng;
    memcpy(det_rng.key, attestation_seed, 32);
    det_rng.counter = 1;

    pk_platform_t det_platform;
    memset(&det_platform, 0, sizeof(det_platform));
    det_platform.ctx = &det_rng;
    det_platform.get_random_bytes = pk_det_get_random_bytes;

    pk_crypto_ctx_t det_ctx;
    memset(&det_ctx, 0, sizeof(det_ctx));
    det_ctx.platform = &det_platform;
    det_ctx.initialized = true;

    uint8_t der_sig[PK_ECDSA_MAX_DER_SIG_LEN];
    size_t der_sig_len = 0;
    err = pk_crypto_p256_sign_der(&det_ctx, out_priv, tbs_hash, der_sig, &der_sig_len);
    pk_crypto_zeroize(&det_rng, sizeof(det_rng));
    pk_crypto_zeroize(tbs_hash, sizeof(tbs_hash));
    if (err != PK_OK) {
        pk_crypto_zeroize(tbs, sizeof(tbs));
        pk_crypto_zeroize(out_priv, PK_P256_PRIVKEY_LEN);
        return err;
    }

    static const uint8_t s_sig_alg[12] = {
        0x30, 0x0A, 0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x02
    };

    size_t sig_val_len = 1U + der_sig_len;
    size_t sig_bitstring_total = 2U + sig_val_len;
    size_t cert_content_len = sizeof(tbs) + sizeof(s_sig_alg) + sig_bitstring_total;
    size_t total_cert_len = 4U + cert_content_len;

    if (max_cert_len < total_cert_len) {
        pk_crypto_zeroize(tbs, sizeof(tbs));
        pk_crypto_zeroize(der_sig, sizeof(der_sig));
        pk_crypto_zeroize(out_priv, PK_P256_PRIVKEY_LEN);
        return PK_ERR_BUFFER_TOO_SMALL;
    }

    out_cert_der[0] = 0x30;
    out_cert_der[1] = 0x82;
    out_cert_der[2] = (uint8_t)((cert_content_len >> 8) & 0xFFU);
    out_cert_der[3] = (uint8_t)(cert_content_len & 0xFFU);

    size_t pos = 4;
    memcpy(out_cert_der + pos, tbs, sizeof(tbs));
    pos += sizeof(tbs);

    memcpy(out_cert_der + pos, s_sig_alg, sizeof(s_sig_alg));
    pos += sizeof(s_sig_alg);

    out_cert_der[pos++] = 0x03;
    out_cert_der[pos++] = (uint8_t)sig_val_len;
    out_cert_der[pos++] = 0x00;
    memcpy(out_cert_der + pos, der_sig, der_sig_len);
    pos += der_sig_len;

    *out_cert_len = pos;

    if (pos <= sizeof(s_attest_cached_cert)) {
        memcpy(s_attest_cached_seed, attestation_seed, 32);
        memcpy(s_attest_cached_priv, out_priv, PK_P256_PRIVKEY_LEN);
        memcpy(s_attest_cached_cert, out_cert_der, pos);
        s_attest_cached_cert_len = pos;
        s_attest_cache_valid = true;
    }

    pk_crypto_zeroize(tbs, sizeof(tbs));
    pk_crypto_zeroize(der_sig, sizeof(der_sig));

    return PK_OK;
}

/* -------------------------------------------------------------------------
 * Standard IEEE 802.3 CRC-32 (0xEDB88320)
 * ------------------------------------------------------------------------- */

uint32_t pk_crc32(const uint8_t *data, size_t len)
{
    if (data == NULL || len == 0) {
        return 0;
    }
    uint32_t crc = 0xFFFFFFFFU;
    for (size_t i = 0; i < len; ++i) {
        crc ^= (uint32_t)data[i];
        for (int b = 0; b < 8; ++b) {
            crc = (crc >> 1) ^ (0xEDB88320U & (0U - (crc & 1U)));
        }
    }
    return crc ^ 0xFFFFFFFFU;
}
