#include "passkey/cbor.h"
#include <string.h>

#define PK_CBOR_MAX_SKIP_DEPTH 8U

void pk_cbor_writer_init(pk_cbor_writer_t *w, uint8_t *buf, size_t capacity) {
    if (w == NULL) {
        return;
    }
    w->buf = buf;
    w->capacity = capacity;
    w->offset = 0;
    if (buf == NULL && capacity > 0) {
        w->err = PK_ERR_INVALID_ARG;
    } else {
        w->err = PK_OK;
    }
}

static size_t cbor_header_len(uint64_t val) {
    if (val <= 23ULL) {
        return 1;
    } else if (val <= 0xFFULL) {
        return 2;
    } else if (val <= 0xFFFFULL) {
        return 3;
    } else if (val <= 0xFFFFFFFFULL) {
        return 5;
    } else {
        return 9;
    }
}

static pk_err_t encode_header(pk_cbor_writer_t *w, uint8_t major, uint64_t val) {
    size_t needed = cbor_header_len(val);
    if (w->capacity < w->offset || (w->capacity - w->offset) < needed) {
        w->err = PK_ERR_BUFFER_TOO_SMALL;
        return PK_ERR_BUFFER_TOO_SMALL;
    }

    uint8_t *p = &w->buf[w->offset];
    uint8_t m = (uint8_t)(major << 5);

    if (val <= 23ULL) {
        p[0] = (uint8_t)(m | (uint8_t)val);
    } else if (val <= 0xFFULL) {
        p[0] = (uint8_t)(m | 24U);
        p[1] = (uint8_t)val;
    } else if (val <= 0xFFFFULL) {
        p[0] = (uint8_t)(m | 25U);
        p[1] = (uint8_t)((val >> 8) & 0xFFU);
        p[2] = (uint8_t)(val & 0xFFU);
    } else if (val <= 0xFFFFFFFFULL) {
        p[0] = (uint8_t)(m | 26U);
        p[1] = (uint8_t)((val >> 24) & 0xFFU);
        p[2] = (uint8_t)((val >> 16) & 0xFFU);
        p[3] = (uint8_t)((val >> 8) & 0xFFU);
        p[4] = (uint8_t)(val & 0xFFU);
    } else {
        p[0] = (uint8_t)(m | 27U);
        p[1] = (uint8_t)((val >> 56) & 0xFFU);
        p[2] = (uint8_t)((val >> 48) & 0xFFU);
        p[3] = (uint8_t)((val >> 40) & 0xFFU);
        p[4] = (uint8_t)((val >> 32) & 0xFFU);
        p[5] = (uint8_t)((val >> 24) & 0xFFU);
        p[6] = (uint8_t)((val >> 16) & 0xFFU);
        p[7] = (uint8_t)((val >> 8) & 0xFFU);
        p[8] = (uint8_t)(val & 0xFFU);
    }

    w->offset += needed;
    return PK_OK;
}

pk_err_t pk_cbor_encode_uint(pk_cbor_writer_t *w, uint64_t val) {
    if (w == NULL) {
        return PK_ERR_INVALID_ARG;
    }
    if (w->err != PK_OK) {
        return w->err;
    }
    return encode_header(w, PK_CBOR_MAJOR_UINT, val);
}

pk_err_t pk_cbor_encode_nint(pk_cbor_writer_t *w, int64_t negative_val) {
    if (w == NULL) {
        return PK_ERR_INVALID_ARG;
    }
    if (w->err != PK_OK) {
        return w->err;
    }
    if (negative_val >= 0) {
        w->err = PK_ERR_INVALID_ARG;
        return PK_ERR_INVALID_ARG;
    }
    uint64_t n = (uint64_t)(-(negative_val + 1));
    return encode_header(w, PK_CBOR_MAJOR_NINT, n);
}

pk_err_t pk_cbor_encode_int(pk_cbor_writer_t *w, int64_t val) {
    if (w == NULL) {
        return PK_ERR_INVALID_ARG;
    }
    if (w->err != PK_OK) {
        return w->err;
    }
    if (val >= 0) {
        return encode_header(w, PK_CBOR_MAJOR_UINT, (uint64_t)val);
    } else {
        uint64_t n = (uint64_t)(-(val + 1));
        return encode_header(w, PK_CBOR_MAJOR_NINT, n);
    }
}

pk_err_t pk_cbor_encode_bstr(pk_cbor_writer_t *w, const uint8_t *data, size_t len) {
    if (w == NULL || (data == NULL && len > 0)) {
        if (w != NULL) {
            w->err = PK_ERR_INVALID_ARG;
        }
        return PK_ERR_INVALID_ARG;
    }
    if (w->err != PK_OK) {
        return w->err;
    }
    size_t hlen = cbor_header_len(len);
    if (w->capacity < w->offset || (w->capacity - w->offset) < (hlen + len)) {
        w->err = PK_ERR_BUFFER_TOO_SMALL;
        return PK_ERR_BUFFER_TOO_SMALL;
    }
    encode_header(w, PK_CBOR_MAJOR_BSTR, (uint64_t)len);
    if (len > 0) {
        memcpy(&w->buf[w->offset], data, len);
        w->offset += len;
    }
    return PK_OK;
}

pk_err_t pk_cbor_encode_tstr(pk_cbor_writer_t *w, const char *str, size_t len) {
    if (w == NULL || (str == NULL && len > 0)) {
        if (w != NULL) {
            w->err = PK_ERR_INVALID_ARG;
        }
        return PK_ERR_INVALID_ARG;
    }
    if (w->err != PK_OK) {
        return w->err;
    }
    size_t hlen = cbor_header_len(len);
    if (w->capacity < w->offset || (w->capacity - w->offset) < (hlen + len)) {
        w->err = PK_ERR_BUFFER_TOO_SMALL;
        return PK_ERR_BUFFER_TOO_SMALL;
    }
    encode_header(w, PK_CBOR_MAJOR_TSTR, (uint64_t)len);
    if (len > 0) {
        memcpy(&w->buf[w->offset], str, len);
        w->offset += len;
    }
    return PK_OK;
}

pk_err_t pk_cbor_encode_tstr_c(pk_cbor_writer_t *w, const char *cstr) {
    if (w == NULL || cstr == NULL) {
        if (w != NULL) {
            w->err = PK_ERR_INVALID_ARG;
        }
        return PK_ERR_INVALID_ARG;
    }
    if (w->err != PK_OK) {
        return w->err;
    }
    return pk_cbor_encode_tstr(w, cstr, strlen(cstr));
}

pk_err_t pk_cbor_encode_bool(pk_cbor_writer_t *w, bool val) {
    if (w == NULL) {
        return PK_ERR_INVALID_ARG;
    }
    if (w->err != PK_OK) {
        return w->err;
    }
    if (w->capacity < w->offset || (w->capacity - w->offset) < 1) {
        w->err = PK_ERR_BUFFER_TOO_SMALL;
        return PK_ERR_BUFFER_TOO_SMALL;
    }
    w->buf[w->offset++] = val ? 0xF5U : 0xF4U;
    return PK_OK;
}

pk_err_t pk_cbor_encode_array_header(pk_cbor_writer_t *w, size_t count) {
    if (w == NULL) {
        return PK_ERR_INVALID_ARG;
    }
    if (w->err != PK_OK) {
        return w->err;
    }
    return encode_header(w, PK_CBOR_MAJOR_ARRAY, (uint64_t)count);
}

pk_err_t pk_cbor_encode_map_header(pk_cbor_writer_t *w, size_t count) {
    if (w == NULL) {
        return PK_ERR_INVALID_ARG;
    }
    if (w->err != PK_OK) {
        return w->err;
    }
    return encode_header(w, PK_CBOR_MAJOR_MAP, (uint64_t)count);
}

pk_err_t pk_cbor_encode_raw(pk_cbor_writer_t *w, const uint8_t *raw, size_t len) {
    if (w == NULL || (raw == NULL && len > 0)) {
        if (w != NULL) {
            w->err = PK_ERR_INVALID_ARG;
        }
        return PK_ERR_INVALID_ARG;
    }
    if (w->err != PK_OK) {
        return w->err;
    }
    if (w->capacity < w->offset || (w->capacity - w->offset) < len) {
        w->err = PK_ERR_BUFFER_TOO_SMALL;
        return PK_ERR_BUFFER_TOO_SMALL;
    }
    if (len > 0) {
        memcpy(&w->buf[w->offset], raw, len);
        w->offset += len;
    }
    return PK_OK;
}

pk_err_t pk_cbor_encode_cose_p256_pubkey(
    pk_cbor_writer_t *w,
    const pk_p256_pubkey_t *pub,
    bool for_ecdh
) {
    if (w == NULL || pub == NULL) {
        if (w != NULL) {
            w->err = PK_ERR_INVALID_ARG;
        }
        return PK_ERR_INVALID_ARG;
    }
    if (w->err != PK_OK) {
        return w->err;
    }

    pk_err_t err;

    err = pk_cbor_encode_map_header(w, 5);
    if (err != PK_OK) return err;

    /* Key 1: kty -> 2 (EC2) */
    err = pk_cbor_encode_uint(w, 1);
    if (err != PK_OK) return err;
    err = pk_cbor_encode_uint(w, PK_COSE_KTY_EC2);
    if (err != PK_OK) return err;

    /* Key 3: alg -> -25 (ECDH-ES+HKDF-256) or -7 (ES256) */
    err = pk_cbor_encode_uint(w, 3);
    if (err != PK_OK) return err;
    err = pk_cbor_encode_int(w, for_ecdh ? PK_COSE_ALG_ECDH_ES_HKDF_256 : PK_COSE_ALG_ES256);
    if (err != PK_OK) return err;

    /* Key -1: crv -> 1 (P-256) */
    err = pk_cbor_encode_int(w, -1);
    if (err != PK_OK) return err;
    err = pk_cbor_encode_uint(w, PK_COSE_CRV_P256);
    if (err != PK_OK) return err;

    /* Key -2: x coordinate (32-byte bstr) */
    err = pk_cbor_encode_int(w, -2);
    if (err != PK_OK) return err;
    err = pk_cbor_encode_bstr(w, pub->x, PK_P256_PUBKEY_COORD_LEN);
    if (err != PK_OK) return err;

    /* Key -3: y coordinate (32-byte bstr) */
    err = pk_cbor_encode_int(w, -3);
    if (err != PK_OK) return err;
    err = pk_cbor_encode_bstr(w, pub->y, PK_P256_PUBKEY_COORD_LEN);
    if (err != PK_OK) return err;

    return PK_OK;
}

void pk_cbor_reader_init(pk_cbor_reader_t *r, const uint8_t *buf, size_t len) {
    if (r == NULL) {
        return;
    }
    r->buf = buf;
    r->len = len;
    r->offset = 0;
}

size_t pk_cbor_reader_remaining(const pk_cbor_reader_t *r) {
    if (r == NULL || r->offset >= r->len) {
        return 0;
    }
    return r->len - r->offset;
}

pk_err_t pk_cbor_peek_major(const pk_cbor_reader_t *r, uint8_t *out_major) {
    if (r == NULL || out_major == NULL) {
        return PK_ERR_INVALID_ARG;
    }
    if (r->offset >= r->len) {
        return PK_ERR_BUFFER_TOO_SMALL;
    }
    *out_major = (uint8_t)(r->buf[r->offset] >> 5);
    return PK_OK;
}

static pk_err_t decode_header(
    pk_cbor_reader_t *r,
    uint8_t *out_major,
    uint64_t *out_val
) {
    if (r == NULL || out_major == NULL || out_val == NULL) {
        return PK_ERR_INVALID_ARG;
    }
    if (r->offset >= r->len) {
        return PK_ERR_BUFFER_TOO_SMALL;
    }

    uint8_t initial_byte = r->buf[r->offset];
    uint8_t major = (uint8_t)(initial_byte >> 5);
    uint8_t info = (uint8_t)(initial_byte & 0x1FU);

    uint64_t val = 0;
    size_t header_len = 1;

    if (info <= 23U) {
        val = info;
    } else if (info == 24U) {
        header_len = 2;
        if (r->len - r->offset < header_len) {
            return PK_ERR_BUFFER_TOO_SMALL;
        }
        val = r->buf[r->offset + 1];
    } else if (info == 25U) {
        header_len = 3;
        if (r->len - r->offset < header_len) {
            return PK_ERR_BUFFER_TOO_SMALL;
        }
        val = ((uint64_t)r->buf[r->offset + 1] << 8) |
              ((uint64_t)r->buf[r->offset + 2]);
    } else if (info == 26U) {
        header_len = 5;
        if (r->len - r->offset < header_len) {
            return PK_ERR_BUFFER_TOO_SMALL;
        }
        val = ((uint64_t)r->buf[r->offset + 1] << 24) |
              ((uint64_t)r->buf[r->offset + 2] << 16) |
              ((uint64_t)r->buf[r->offset + 3] << 8)  |
              ((uint64_t)r->buf[r->offset + 4]);
    } else if (info == 27U) {
        header_len = 9;
        if (r->len - r->offset < header_len) {
            return PK_ERR_BUFFER_TOO_SMALL;
        }
        val = ((uint64_t)r->buf[r->offset + 1] << 56) |
              ((uint64_t)r->buf[r->offset + 2] << 48) |
              ((uint64_t)r->buf[r->offset + 3] << 40) |
              ((uint64_t)r->buf[r->offset + 4] << 32) |
              ((uint64_t)r->buf[r->offset + 5] << 24) |
              ((uint64_t)r->buf[r->offset + 6] << 16) |
              ((uint64_t)r->buf[r->offset + 7] << 8)  |
              ((uint64_t)r->buf[r->offset + 8]);
    } else {
        return PK_ERR_CORRUPT;
    }

    *out_major = major;
    *out_val = val;
    r->offset += header_len;
    return PK_OK;
}

pk_err_t pk_cbor_decode_uint(pk_cbor_reader_t *r, uint64_t *out_val) {
    if (r == NULL || out_val == NULL) {
        return PK_ERR_INVALID_ARG;
    }
    size_t saved_offset = r->offset;
    uint8_t major;
    uint64_t val;
    pk_err_t err = decode_header(r, &major, &val);
    if (err != PK_OK) {
        return err;
    }
    if (major != PK_CBOR_MAJOR_UINT) {
        r->offset = saved_offset;
        return PK_ERR_CORRUPT;
    }
    *out_val = val;
    return PK_OK;
}

pk_err_t pk_cbor_decode_int(pk_cbor_reader_t *r, int64_t *out_val) {
    if (r == NULL || out_val == NULL) {
        return PK_ERR_INVALID_ARG;
    }
    size_t saved_offset = r->offset;
    uint8_t major;
    uint64_t val;
    pk_err_t err = decode_header(r, &major, &val);
    if (err != PK_OK) {
        return err;
    }
    if (major == PK_CBOR_MAJOR_UINT) {
        if (val > (uint64_t)INT64_MAX) {
            r->offset = saved_offset;
            return PK_ERR_OVERFLOW;
        }
        *out_val = (int64_t)val;
        return PK_OK;
    } else if (major == PK_CBOR_MAJOR_NINT) {
        if (val > (uint64_t)INT64_MAX) {
            r->offset = saved_offset;
            return PK_ERR_OVERFLOW;
        }
        *out_val = -1 - (int64_t)val;
        return PK_OK;
    } else {
        r->offset = saved_offset;
        return PK_ERR_CORRUPT;
    }
}

pk_err_t pk_cbor_decode_bstr(pk_cbor_reader_t *r, const uint8_t **out_ptr, size_t *out_len) {
    if (r == NULL || out_ptr == NULL || out_len == NULL) {
        return PK_ERR_INVALID_ARG;
    }
    size_t saved_offset = r->offset;
    uint8_t major;
    uint64_t val;
    pk_err_t err = decode_header(r, &major, &val);
    if (err != PK_OK) {
        return err;
    }
    if (major != PK_CBOR_MAJOR_BSTR) {
        r->offset = saved_offset;
        return PK_ERR_CORRUPT;
    }
    if (val > (uint64_t)(r->len - r->offset)) {
        r->offset = saved_offset;
        return PK_ERR_BUFFER_TOO_SMALL;
    }
    *out_ptr = &r->buf[r->offset];
    *out_len = (size_t)val;
    r->offset += (size_t)val;
    return PK_OK;
}

pk_err_t pk_cbor_decode_tstr(pk_cbor_reader_t *r, const char **out_ptr, size_t *out_len) {
    if (r == NULL || out_ptr == NULL || out_len == NULL) {
        return PK_ERR_INVALID_ARG;
    }
    size_t saved_offset = r->offset;
    uint8_t major;
    uint64_t val;
    pk_err_t err = decode_header(r, &major, &val);
    if (err != PK_OK) {
        return err;
    }
    if (major != PK_CBOR_MAJOR_TSTR) {
        r->offset = saved_offset;
        return PK_ERR_CORRUPT;
    }
    if (val > (uint64_t)(r->len - r->offset)) {
        r->offset = saved_offset;
        return PK_ERR_BUFFER_TOO_SMALL;
    }
    *out_ptr = (const char *)&r->buf[r->offset];
    *out_len = (size_t)val;
    r->offset += (size_t)val;
    return PK_OK;
}

pk_err_t pk_cbor_decode_bool(pk_cbor_reader_t *r, bool *out_val) {
    if (r == NULL || out_val == NULL) {
        return PK_ERR_INVALID_ARG;
    }
    if (r->offset >= r->len) {
        return PK_ERR_BUFFER_TOO_SMALL;
    }
    uint8_t b = r->buf[r->offset];
    if (b == 0xF4U) {
        *out_val = false;
        r->offset += 1;
        return PK_OK;
    } else if (b == 0xF5U) {
        *out_val = true;
        r->offset += 1;
        return PK_OK;
    } else if (b == 0xF8U) {
        if (r->len - r->offset < 2) {
            return PK_ERR_BUFFER_TOO_SMALL;
        }
        uint8_t simple = r->buf[r->offset + 1];
        if (simple == 20U) {
            *out_val = false;
            r->offset += 2;
            return PK_OK;
        } else if (simple == 21U) {
            *out_val = true;
            r->offset += 2;
            return PK_OK;
        }
    }
    return PK_ERR_CORRUPT;
}

pk_err_t pk_cbor_decode_array_header(pk_cbor_reader_t *r, size_t *out_count) {
    if (r == NULL || out_count == NULL) {
        return PK_ERR_INVALID_ARG;
    }
    size_t saved_offset = r->offset;
    uint8_t major;
    uint64_t val;
    pk_err_t err = decode_header(r, &major, &val);
    if (err != PK_OK) {
        return err;
    }
    if (major != PK_CBOR_MAJOR_ARRAY) {
        r->offset = saved_offset;
        return PK_ERR_CORRUPT;
    }
    /* An array cannot contain more elements than remaining buffer bytes */
    if (val > (uint64_t)(r->len - r->offset)) {
        r->offset = saved_offset;
        return PK_ERR_CORRUPT;
    }
#if SIZE_MAX < UINT64_MAX
    if (val > (uint64_t)SIZE_MAX) {
        r->offset = saved_offset;
        return PK_ERR_OVERFLOW;
    }
#endif
    *out_count = (size_t)val;
    return PK_OK;
}

pk_err_t pk_cbor_decode_map_header(pk_cbor_reader_t *r, size_t *out_count) {
    if (r == NULL || out_count == NULL) {
        return PK_ERR_INVALID_ARG;
    }
    size_t saved_offset = r->offset;
    uint8_t major;
    uint64_t val;
    pk_err_t err = decode_header(r, &major, &val);
    if (err != PK_OK) {
        return err;
    }
    if (major != PK_CBOR_MAJOR_MAP) {
        r->offset = saved_offset;
        return PK_ERR_CORRUPT;
    }
    /* Each map entry has at least 1 key byte and 1 value byte (2 bytes per entry) */
    if (val > (uint64_t)((r->len - r->offset) / 2)) {
        r->offset = saved_offset;
        return PK_ERR_CORRUPT;
    }
#if SIZE_MAX < UINT64_MAX
    if (val > (uint64_t)SIZE_MAX) {
        r->offset = saved_offset;
        return PK_ERR_OVERFLOW;
    }
#endif
    *out_count = (size_t)val;
    return PK_OK;
}

static pk_err_t skip_item_internal(pk_cbor_reader_t *r, unsigned int depth) {
    if (depth > PK_CBOR_MAX_SKIP_DEPTH) {
        return PK_ERR_OVERFLOW;
    }
    if (r == NULL) {
        return PK_ERR_INVALID_ARG;
    }
    if (r->offset >= r->len) {
        return PK_ERR_BUFFER_TOO_SMALL;
    }

    uint8_t initial_byte = r->buf[r->offset];
    uint8_t major = (uint8_t)(initial_byte >> 5);
    uint8_t info = (uint8_t)(initial_byte & 0x1FU);

    if (major == PK_CBOR_MAJOR_SIMPLE) {
        size_t len = 1;
        if (info <= 23U) {
            len = 1;
        } else if (info == 24U) {
            len = 2;
        } else if (info == 25U) {
            len = 3;
        } else if (info == 26U) {
            len = 5;
        } else if (info == 27U) {
            len = 9;
        } else {
            /* Reject info == 31 (indefinite-length / "break") and undefined simple values */
            return PK_ERR_CORRUPT;
        }
        if (r->len - r->offset < len) {
            return PK_ERR_BUFFER_TOO_SMALL;
        }
        r->offset += len;
        return PK_OK;
    }

    uint64_t val = 0;
    pk_err_t err = decode_header(r, &major, &val);
    if (err != PK_OK) {
        return err;
    }

    switch (major) {
    case PK_CBOR_MAJOR_UINT:
    case PK_CBOR_MAJOR_NINT:
        return PK_OK;

    case PK_CBOR_MAJOR_BSTR:
    case PK_CBOR_MAJOR_TSTR:
        if (val > (uint64_t)(r->len - r->offset)) {
            return PK_ERR_BUFFER_TOO_SMALL;
        }
        r->offset += (size_t)val;
        return PK_OK;

    case PK_CBOR_MAJOR_ARRAY:
        if (val > (uint64_t)(r->len - r->offset)) {
            return PK_ERR_CORRUPT;
        }
        for (uint64_t i = 0; i < val; i++) {
            err = skip_item_internal(r, depth + 1);
            if (err != PK_OK) {
                return err;
            }
        }
        return PK_OK;

    case PK_CBOR_MAJOR_MAP:
        if (val > (uint64_t)((r->len - r->offset) / 2)) {
            return PK_ERR_CORRUPT;
        }
        for (uint64_t i = 0; i < val; i++) {
            err = skip_item_internal(r, depth + 1);
            if (err != PK_OK) {
                return err;
            }
            err = skip_item_internal(r, depth + 1);
            if (err != PK_OK) {
                return err;
            }
        }
        return PK_OK;

    case PK_CBOR_MAJOR_TAG:
        return skip_item_internal(r, depth + 1);

    default:
        return PK_ERR_CORRUPT;
    }
}

pk_err_t pk_cbor_skip_item(pk_cbor_reader_t *r) {
    if (r == NULL) {
        return PK_ERR_INVALID_ARG;
    }
    size_t saved = r->offset;
    pk_err_t err = skip_item_internal(r, 0);
    if (err != PK_OK) {
        r->offset = saved;
    }
    return err;
}

pk_err_t pk_cbor_decode_cose_p256_pubkey(pk_cbor_reader_t *r, pk_p256_pubkey_t *out_pub) {
    if (r == NULL || out_pub == NULL) {
        return PK_ERR_INVALID_ARG;
    }

    size_t saved_offset = r->offset;
    size_t map_count = 0;
    pk_err_t err = pk_cbor_decode_map_header(r, &map_count);
    if (err != PK_OK) {
        r->offset = saved_offset;
        return err;
    }

    bool found_kty = false;
    bool found_crv = false;
    bool found_x = false;
    bool found_y = false;

    for (size_t i = 0; i < map_count; i++) {
        uint8_t key_major = 0;
        err = pk_cbor_peek_major(r, &key_major);
        if (err != PK_OK) {
            r->offset = saved_offset;
            return err;
        }

        if (key_major == PK_CBOR_MAJOR_UINT || key_major == PK_CBOR_MAJOR_NINT) {
            int64_t key = 0;
            err = pk_cbor_decode_int(r, &key);
            if (err != PK_OK) {
                r->offset = saved_offset;
                return err;
            }

            if (key == 1) {
                /* kty: must be 2 (EC2) */
                int64_t kty = 0;
                err = pk_cbor_decode_int(r, &kty);
                if (err != PK_OK) {
                    r->offset = saved_offset;
                    return err;
                }
                if (kty != PK_COSE_KTY_EC2) {
                    r->offset = saved_offset;
                    return PK_ERR_CORRUPT;
                }
                found_kty = true;
            } else if (key == -1) {
                /* crv: must be 1 (P-256) */
                int64_t crv = 0;
                err = pk_cbor_decode_int(r, &crv);
                if (err != PK_OK) {
                    r->offset = saved_offset;
                    return err;
                }
                if (crv != PK_COSE_CRV_P256) {
                    r->offset = saved_offset;
                    return PK_ERR_CORRUPT;
                }
                found_crv = true;
            } else if (key == -2) {
                /* x coordinate: 32-byte bstr */
                const uint8_t *x_ptr = NULL;
                size_t x_len = 0;
                err = pk_cbor_decode_bstr(r, &x_ptr, &x_len);
                if (err != PK_OK) {
                    r->offset = saved_offset;
                    return err;
                }
                if (x_len != PK_P256_PUBKEY_COORD_LEN) {
                    r->offset = saved_offset;
                    return PK_ERR_CORRUPT;
                }
                memcpy(out_pub->x, x_ptr, PK_P256_PUBKEY_COORD_LEN);
                found_x = true;
            } else if (key == -3) {
                /* y coordinate: 32-byte bstr */
                const uint8_t *y_ptr = NULL;
                size_t y_len = 0;
                err = pk_cbor_decode_bstr(r, &y_ptr, &y_len);
                if (err != PK_OK) {
                    r->offset = saved_offset;
                    return err;
                }
                if (y_len != PK_P256_PUBKEY_COORD_LEN) {
                    r->offset = saved_offset;
                    return PK_ERR_CORRUPT;
                }
                memcpy(out_pub->y, y_ptr, PK_P256_PUBKEY_COORD_LEN);
                found_y = true;
            } else {
                /* Unknown integer key (e.g. alg = 3, etc.): skip value */
                err = pk_cbor_skip_item(r);
                if (err != PK_OK) {
                    r->offset = saved_offset;
                    return err;
                }
            }
        } else {
            /* Non-integer key: skip key and value */
            err = pk_cbor_skip_item(r);
            if (err != PK_OK) {
                r->offset = saved_offset;
                return err;
            }
            err = pk_cbor_skip_item(r);
            if (err != PK_OK) {
                r->offset = saved_offset;
                return err;
            }
        }
    }

    if (!found_kty || !found_crv || !found_x || !found_y) {
        r->offset = saved_offset;
        return PK_ERR_CORRUPT;
    }

    return PK_OK;
}
