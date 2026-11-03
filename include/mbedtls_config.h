#ifndef PICO_PASSKEY_MBEDTLS_CONFIG_H
#define PICO_PASSKEY_MBEDTLS_CONFIG_H

/* Embedded Mbed TLS 2.28 Configuration for RP2040 FIDO2 Security Key */
#define MBEDTLS_NO_PLATFORM_ENTROPY
#define MBEDTLS_ENTROPY_HARDWARE_ALT

/* System & Bignum Support */
#define MBEDTLS_HAVE_ASM
#define MBEDTLS_PLATFORM_C
#define MBEDTLS_BIGNUM_C
#define MBEDTLS_OID_C
#define MBEDTLS_ASN1_PARSE_C
#define MBEDTLS_ASN1_WRITE_C

/* Elliptic Curve Cryptography: NIST P-256 (secp256r1) */
#define MBEDTLS_ECP_C
#define MBEDTLS_ECP_DP_SECP256R1_ENABLED
#define MBEDTLS_ECP_NIST_OPTIM
#define MBEDTLS_ECDSA_C
#define MBEDTLS_ECDH_C
#define MBEDTLS_ECDH_LEGACY_CONTEXT

/* Hashing, MAC, and Key Derivation */
#define MBEDTLS_MD_C
#define MBEDTLS_SHA256_C
#define MBEDTLS_HKDF_C

/* Symmetric Encryption: AES-256-CBC for CTAP2 PIN Protocol v1 */
#define MBEDTLS_AES_C
#define MBEDTLS_CIPHER_C
#define MBEDTLS_CIPHER_MODE_CBC
#define MBEDTLS_AES_ROM_TABLES

/* Deterministic / CSPRNG support */
#define MBEDTLS_ENTROPY_C
#define MBEDTLS_CTR_DRBG_C

#include "mbedtls/check_config.h"

#endif /* PICO_PASSKEY_MBEDTLS_CONFIG_H */
