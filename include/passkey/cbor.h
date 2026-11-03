#ifndef PICO_PASSKEY_CBOR_H
#define PICO_PASSKEY_CBOR_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "passkey/crypto.h"
#include "passkey/status.h"

/* RFC 8949 CBOR Major Types */
#define PK_CBOR_MAJOR_UINT   0U
#define PK_CBOR_MAJOR_NINT   1U
#define PK_CBOR_MAJOR_BSTR   2U
#define PK_CBOR_MAJOR_TSTR   3U
#define PK_CBOR_MAJOR_ARRAY  4U
#define PK_CBOR_MAJOR_MAP    5U
#define PK_CBOR_MAJOR_TAG    6U
#define PK_CBOR_MAJOR_SIMPLE 7U

/* COSE Algorithm & Key Constants */
#define PK_COSE_ALG_ES256    (-7)
#define PK_COSE_ALG_ECDH_ES_HKDF_256 (-25)
#define PK_COSE_KTY_EC2      2
#define PK_COSE_CRV_P256     1

/* Zero-allocation CBOR Encoder */
typedef struct {
    uint8_t *buf;
    size_t capacity;
    size_t offset;
    pk_err_t err;
} pk_cbor_writer_t;

void pk_cbor_writer_init(pk_cbor_writer_t *w, uint8_t *buf, size_t capacity);
pk_err_t pk_cbor_encode_uint(pk_cbor_writer_t *w, uint64_t val);
pk_err_t pk_cbor_encode_nint(pk_cbor_writer_t *w, int64_t negative_val);
pk_err_t pk_cbor_encode_int(pk_cbor_writer_t *w, int64_t val);
pk_err_t pk_cbor_encode_bstr(pk_cbor_writer_t *w, const uint8_t *data, size_t len);
pk_err_t pk_cbor_encode_tstr(pk_cbor_writer_t *w, const char *str, size_t len);
pk_err_t pk_cbor_encode_tstr_c(pk_cbor_writer_t *w, const char *cstr);
pk_err_t pk_cbor_encode_bool(pk_cbor_writer_t *w, bool val);
pk_err_t pk_cbor_encode_array_header(pk_cbor_writer_t *w, size_t count);
pk_err_t pk_cbor_encode_map_header(pk_cbor_writer_t *w, size_t count);
pk_err_t pk_cbor_encode_raw(pk_cbor_writer_t *w, const uint8_t *raw, size_t len);

/* Encode COSE_Key for an ES256 (EC2 P-256) public key in CTAP2 canonical CBOR order:
 *   { 1: 2, 3: -7, -1: 1, -2: x (32B), -3: y (32B) }
 * If `for_ecdh` is true, encodes alg (key 3) as -25 (ECDH-ES+HKDF-256) per CTAP2 §6.5.5.
 */
pk_err_t pk_cbor_encode_cose_p256_pubkey(
    pk_cbor_writer_t *w,
    const pk_p256_pubkey_t *pub,
    bool for_ecdh
);

/* Zero-allocation CBOR Decoder */
typedef struct {
    const uint8_t *buf;
    size_t len;
    size_t offset;
} pk_cbor_reader_t;

void pk_cbor_reader_init(pk_cbor_reader_t *r, const uint8_t *buf, size_t len);
size_t pk_cbor_reader_remaining(const pk_cbor_reader_t *r);
pk_err_t pk_cbor_peek_major(const pk_cbor_reader_t *r, uint8_t *out_major);
pk_err_t pk_cbor_decode_uint(pk_cbor_reader_t *r, uint64_t *out_val);
pk_err_t pk_cbor_decode_int(pk_cbor_reader_t *r, int64_t *out_val);
pk_err_t pk_cbor_decode_bstr(pk_cbor_reader_t *r, const uint8_t **out_ptr, size_t *out_len);
pk_err_t pk_cbor_decode_tstr(pk_cbor_reader_t *r, const char **out_ptr, size_t *out_len);
pk_err_t pk_cbor_decode_bool(pk_cbor_reader_t *r, bool *out_val);
pk_err_t pk_cbor_decode_array_header(pk_cbor_reader_t *r, size_t *out_count);
pk_err_t pk_cbor_decode_map_header(pk_cbor_reader_t *r, size_t *out_count);
pk_err_t pk_cbor_skip_item(pk_cbor_reader_t *r);

/* Decode a COSE_Key EC2 P-256 public key map into `out_pub` */
pk_err_t pk_cbor_decode_cose_p256_pubkey(pk_cbor_reader_t *r, pk_p256_pubkey_t *out_pub);

#endif /* PICO_PASSKEY_CBOR_H */
